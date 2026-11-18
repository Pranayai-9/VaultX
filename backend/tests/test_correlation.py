"""
VaultX Phase 2 - Unit Tests for Threat Intelligence & Correlation Engines
BECPL (Bharat Electronics Components Pvt. Ltd.), Pune

Runnable via standard library unittest OR pytest:
  python -m unittest backend/tests/test_correlation.py -v
  pytest backend/tests/test_correlation.py -v
"""

from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure repository root is importable
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.threat_intel.threat_intel_feeds import (
    REDIS_KEY_CISA_KEV,
    REDIS_KEY_IP_BLOCKLIST,
    REDIS_KEY_JA3_BLOCKLIST,
    ThreatIntelFeedManager,
)
from backend.threat_intel.vulnerability_engine import (
    REDIS_STREAM_VULNERABILITIES,
    VulnerabilityEngine,
)
from backend.threat_intel.exploitation_correlator import (
    ExploitationCorrelator,
    ExploitationStage,
    REDIS_STREAM_EXPLOITATION,
)
from backend.threat_intel.supply_chain_monitor import (
    REDIS_STREAM_SUPPLY_CHAIN,
    SupplyChainMonitor,
)
from backend.correlation.correlation_engine import (
    CorrelationEngine,
    REDIS_STREAM_INCIDENTS,
)
from backend.correlation.infrastructure_graph import InfrastructureGraph
from backend.correlation.blast_radius_analyzer import (
    BlastRadiusAnalyzer,
    OT_SAFETY_NOTE,
    REDIS_STREAM_BLAST_RADIUS,
)
from backend.correlation.risk_assessor import (
    INFRASTRUCTURE_SECTIONS,
    REDIS_HASH_RISK_SECTIONS,
    RiskAssessor,
    SectionRiskLevel,
)
from backend.correlation.ai_investigation_assistant import (
    AI_DISCLAIMER,
    AIInvestigationAssistant,
)


class FakeRedis:
    """Minimal synchronous in-memory Redis double for hashes, keys, and streams."""

    def __init__(self) -> None:
        self.hashes: Dict[str, Dict[str, str]] = {}
        self.kv: Dict[str, str] = {}
        self.streams: Dict[str, List[Dict[str, Any]]] = {}

    def hset(self, key: str, mapping: Dict[str, str]) -> int:
        bucket = self.hashes.setdefault(key, {})
        bucket.update(mapping)
        return len(mapping)

    def hget(self, key: str, field_name: str) -> Any:
        return self.hashes.get(key, {}).get(field_name)

    def set(self, key: str, value: str) -> bool:
        self.kv[key] = value
        return True

    def get(self, key: str) -> Any:
        return self.kv.get(key)

    def xadd(self, stream: str, fields: Dict[str, Any]) -> str:
        entries = self.streams.setdefault(stream, [])
        entry_id = f"{len(entries) + 1}-0"
        entries.append({"id": entry_id, "fields": dict(fields)})
        return entry_id


class FakeDB:
    """Minimal synchronous DB double capturing executed SQL statements."""

    def __init__(self) -> None:
        self.executed: List[Tuple[str, Any]] = []

    def execute(self, sql: str, params: Any = None) -> None:
        self.executed.append((sql.strip(), params))


class TestThreatIntelAndCorrelation(unittest.TestCase):
    """End-to-end unit test suite for VaultX Phase 2 Threat Intel & Correlation."""

    # ------------------------------------------------------------------
    # 1. Correlation Engine: All 10 Rules + Deduplication
    # ------------------------------------------------------------------
    def test_correlation_engine(self) -> None:
        redis = FakeRedis()
        db = FakeDB()
        engine = CorrelationEngine(db_client=db, redis_client=redis)
        t0 = datetime(2026, 11, 18, 10, 0, 0, tzinfo=timezone.utc)

        # RULE-CORP-001: Lateral Movement Campaign (>= 3 distinct targets in < 10 min)
        res = []
        for idx, dst in enumerate(["CORP-FS-01", "CORP-DC-01", "CORP-BACKUP-01"]):
            res = engine.ingest_event(
                "detections:anomaly",
                {
                    "event_id": f"ev-corp1-{idx}",
                    "timestamp": (t0 + timedelta(minutes=idx * 2)).isoformat(),
                    "source_asset_id": "CORP-WS-004",
                    "destination_asset_id": dst,
                    "source_vlan": 10,
                    "destination_vlan": 10,
                },
            )
        corp1 = [i for i in res if i.rule_id == "RULE-CORP-001"]
        self.assertEqual(len(corp1), 1)
        self.assertEqual(corp1[0].severity, "high")
        self.assertIn("T1021", corp1[0].mitre_techniques)
        self.assertRegex(corp1[0].incident_reference, r"^INC-2026-\d{3}$")

        # Verify deduplication: re-ingesting same lateral movement updates existing incident
        inc_count_before = len(engine.incidents)
        dup_res = engine.ingest_event(
            "detections:anomaly",
            {
                "event_id": "ev-corp1-dup",
                "timestamp": (t0 + timedelta(minutes=7)).isoformat(),
                "source_asset_id": "CORP-WS-004",
                "destination_asset_id": "CORP-DC-01",
                "source_vlan": 10,
                "destination_vlan": 10,
            },
        )
        corp1_dup = [i for i in dup_res if i.rule_id == "RULE-CORP-001"]
        self.assertEqual(len(corp1_dup), 1)
        self.assertEqual(corp1_dup[0].incident_id, corp1[0].incident_id)
        self.assertEqual(len(engine.incidents), inc_count_before)
        self.assertIn("ev-corp1-dup", corp1_dup[0].evidence)

        # RULE-CORP-002: Credential Compromise + Movement
        t2 = t0 + timedelta(hours=2)
        engine.ingest_event(
            "detections:identity",
            {
                "event_id": "ev-corp2-auth",
                "timestamp": t2.isoformat(),
                "event_type": "identity_anomaly",
                "anomaly_type": "off_hours",
                "identity": "rajesh.sharma",
                "source_asset_id": "CORP-WS-002",
                "source_vlan": 10,
            },
        )
        res2 = engine.ingest_event(
            "detections:anomaly",
            {
                "event_id": "ev-corp2-net",
                "timestamp": (t2 + timedelta(minutes=12)).isoformat(),
                "event_type": "network_anomaly",
                "anomaly_type": "new_destination",
                "identity": "rajesh.sharma",
                "source_asset_id": "CORP-WS-002",
                "destination_asset_id": "CORP-ERP-01",
                "source_vlan": 10,
            },
        )
        self.assertTrue(any(i.rule_id == "RULE-CORP-002" and i.severity == "high" for i in res2))

        # RULE-CORP-003: LOTL Execution Chain
        t3 = t0 + timedelta(hours=4)
        engine.ingest_event(
            "detections:lotl",
            {
                "event_id": "ev-corp3-lotl",
                "timestamp": t3.isoformat(),
                "event_type": "lotl_indicator",
                "source_asset_id": "CORP-WS-003",
                "process_name": "powershell.exe",
            },
        )
        res3 = engine.ingest_event(
            "detections:anomaly",
            {
                "event_id": "ev-corp3-ext",
                "timestamp": (t3 + timedelta(minutes=5)).isoformat(),
                "source_asset_id": "CORP-WS-003",
                "destination_ip": "198.51.100.5",
                "is_external": True,
            },
        )
        corp3 = [i for i in res3 if i.rule_id == "RULE-CORP-003"]
        self.assertEqual(len(corp3), 1)
        self.assertEqual(set(corp3[0].mitre_techniques), {"T1059", "T1041"})

        # RULE-ENG-001: Firmware Exfiltration Attempt (CRITICAL)
        t4 = t0 + timedelta(hours=6)
        engine.ingest_event(
            "detections:anomaly",
            {
                "event_id": "ev-eng1-repo",
                "timestamp": t4.isoformat(),
                "source_asset_id": "ENG-WS-002",
                "destination_asset_id": "ENG-GITSVR-01",
                "destination_vlan": 20,
                "destination_port": 3000,
            },
        )
        res4 = engine.ingest_event(
            "detections:encrypted_traffic",
            {
                "event_id": "ev-eng1-tls",
                "timestamp": (t4 + timedelta(minutes=4)).isoformat(),
                "source_asset_id": "ENG-WS-002",
                "event_type": "encrypted_traffic_anomaly",
                "destination_ip": "203.0.113.99",
            },
        )
        self.assertTrue(any(i.rule_id == "RULE-ENG-001" and i.severity == "critical" for i in res4))

        # RULE-VENDOR-001: Vendor Compromise Chain (within 60 min in sequence)
        t5 = t0 + timedelta(hours=8)
        engine.ingest_event(
            "detections:supply_chain",
            {
                "event_id": "ev-vend1-auth",
                "timestamp": t5.isoformat(),
                "vendor_id": "VEND-005",
                "identity": "vendor_hexacore_dev",
                "indicator_type": "vendor_auth_anomaly",
                "source_asset_id": "DMZ-BASTION-01",
            },
        )
        engine.ingest_event(
            "detections:supply_chain",
            {
                "event_id": "ev-vend1-res",
                "timestamp": (t5 + timedelta(minutes=15)).isoformat(),
                "vendor_id": "VEND-005",
                "identity": "vendor_hexacore_dev",
                "indicator_type": "unexpected_resource_access",
                "source_asset_id": "DMZ-BASTION-01",
                "destination_asset_id": "ENG-WS-002",
            },
        )
        res5 = engine.ingest_event(
            "detections:supply_chain",
            {
                "event_id": "ev-vend1-vlan",
                "timestamp": (t5 + timedelta(minutes=35)).isoformat(),
                "vendor_id": "VEND-005",
                "identity": "vendor_hexacore_dev",
                "indicator_type": "cross_vlan_access",
                "source_asset_id": "DMZ-BASTION-01",
                "destination_asset_id": "CORP-FS-01",
                "source_vlan": 50,
                "destination_vlan": 10,
            },
        )
        self.assertTrue(any(i.rule_id == "RULE-VENDOR-001" and i.severity == "high" for i in res5))

        # RULE-VENDOR-002: Service Account Misuse
        t6 = t0 + timedelta(hours=10)
        engine.ingest_event(
            "detections:supply_chain",
            {
                "event_id": "ev-vend2-svc",
                "timestamp": t6.isoformat(),
                "identity": "svc_erp_integration",
                "indicator_type": "service_account_anomaly",
                "source_asset_id": "CORP-ERP-01",
            },
        )
        engine.ingest_event(
            "detections:supply_chain",
            {
                "event_id": "ev-vend2-api",
                "timestamp": (t6 + timedelta(minutes=3)).isoformat(),
                "identity": "svc_erp_integration",
                "indicator_type": "unusual_api_activity",
                "source_asset_id": "CORP-ERP-01",
            },
        )
        res6 = engine.ingest_event(
            "detections:anomaly",
            {
                "event_id": "ev-vend2-ext",
                "timestamp": (t6 + timedelta(minutes=6)).isoformat(),
                "identity": "svc_erp_integration",
                "source_asset_id": "CORP-ERP-01",
                "destination_ip": "185.220.101.10",
                "is_external": True,
            },
        )
        self.assertTrue(any(i.rule_id == "RULE-VENDOR-002" and i.severity == "high" for i in res6))

        # RULE-OT-001: Unauthorized OT Access (CRITICAL + OT_SAFETY_FLAG=True)
        t7 = t0 + timedelta(hours=12)
        res7 = engine.ingest_event(
            "detections:signature",
            {
                "event_id": "ev-ot1-modbus",
                "timestamp": t7.isoformat(),
                "source_asset_id": "CORP-WS-004",
                "destination_asset_id": "OT-PLC-SMTA-01",
                "source_vlan": 10,
                "destination_vlan": 30,
                "protocol": "Modbus",
                "destination_port": 502,
                "modbus_function_code": 6,
            },
        )
        ot1 = [i for i in res7 if i.rule_id == "RULE-OT-001"]
        self.assertEqual(len(ot1), 1)
        self.assertEqual(ot1[0].severity, "critical")
        self.assertTrue(ot1[0].ot_safety_flag)

        # RULE-OT-002: IT-to-OT Communication (also triggered for unapproved VLAN 10 -> 30)
        ot2 = [i for i in res7 if i.rule_id == "RULE-OT-002"]
        self.assertEqual(len(ot2), 1)
        self.assertEqual(ot2[0].severity, "high")

        # RULE-EXFIL-001: Data Exfiltration
        t8 = datetime(2026, 11, 19, 2, 30, 0, tzinfo=timezone.utc)  # unusual hour (02:30 UTC)
        res8 = engine.ingest_event(
            "detections:encrypted_traffic",
            {
                "event_id": "ev-exfil1",
                "timestamp": t8.isoformat(),
                "source_asset_id": "ENG-GITSVR-01",
                "destination_ip": "185.220.101.45",
                "upload_ratio": 0.92,
                "bytes_out": 250_000_000,
                "asset_criticality": "critical",
            },
        )
        self.assertTrue(any(i.rule_id == "RULE-EXFIL-001" and i.severity == "high" for i in res8))

        # RULE-SCAN-001: Recon + Vuln Scan (MEDIUM non-KEV, HIGH if KEV)
        t9 = t8 + timedelta(hours=2)
        engine.ingest_event(
            "detections:signature",
            {
                "event_id": "ev-scan-1",
                "timestamp": t9.isoformat(),
                "event_type": "port_scan_pattern",
                "source_asset_id": "CORP-WS-002",
                "destination_asset_id": "ENG-WS-002",
                "distinct_ports_scanned": 50,
            },
        )
        res9_med = engine.ingest_event(
            "intel:exploitation",
            {
                "event_id": "ev-vuln-nonkev",
                "timestamp": (t9 + timedelta(minutes=2)).isoformat(),
                "asset_id": "ENG-WS-002",
                "cve_id": "CVE-2016-10009",
                "is_kev": False,
            },
        )
        self.assertTrue(any(i.rule_id == "RULE-SCAN-001" and i.severity == "medium" for i in res9_med))

        # KEV escalation on CORP-WS-004 (CVE-2020-0796)
        t10 = t9 + timedelta(hours=2)
        engine.ingest_event(
            "detections:signature",
            {
                "event_id": "ev-scan-2",
                "timestamp": t10.isoformat(),
                "event_type": "port_scan_pattern",
                "source_asset_id": "CORP-WS-002",
                "destination_asset_id": "CORP-WS-004",
                "distinct_ports_scanned": 40,
            },
        )
        res10_kev = engine.ingest_event(
            "intel:exploitation",
            {
                "event_id": "ev-vuln-kev",
                "timestamp": (t10 + timedelta(minutes=1)).isoformat(),
                "asset_id": "CORP-WS-004",
                "cve_id": "CVE-2020-0796",
                "is_kev": True,
            },
        )
        self.assertTrue(any(i.rule_id == "RULE-SCAN-001" and i.severity == "high" for i in res10_kev))

        # Verify Redis stream publishing & DB persistence were invoked
        self.assertGreaterEqual(len(redis.streams.get(REDIS_STREAM_INCIDENTS, [])), 10)
        self.assertGreaterEqual(len(db.executed), 10)

    # ------------------------------------------------------------------
    # 2. Infrastructure Graph & Blast Radius Analyzer
    # ------------------------------------------------------------------
    def test_blast_radius(self) -> None:
        redis = FakeRedis()
        db = FakeDB()
        graph = InfrastructureGraph(redis_client=redis)

        # Verify NetworkX JSON export
        nx_json = graph.to_networkx_json()
        self.assertTrue(nx_json["directed"])
        self.assertGreater(len(nx_json["nodes"]), 50)
        self.assertGreater(len(nx_json["links"]), 50)

        # Shortest path & connected_assets on BECPL OT/Engineering topology
        path = graph.shortest_path("OT-HMI-SMTA-01", "OT-PLC-SMTA-01")
        self.assertEqual(path, ["OT-HMI-SMTA-01", "OT-PLC-SMTA-01"])

        two_hop = graph.connected_assets("OT-PLC-SMTA-01", hops=2)
        self.assertIn("OT-HMI-SMTA-01", two_hop)
        self.assertIn("OT-SCADA-GW01", two_hop)

        # Anomalous observed edge not in approved communication_matrix.json
        graph.ingest_observed_flows(
            [
                {
                    "source_asset_id": "CORP-WS-004",
                    "destination_asset_id": "OT-PLC-SMTA-01",
                    "protocol": "Modbus",
                    "dst_port": 502,
                    "frequency": 4,
                }
            ]
        )
        anoms = graph.anomalous_edges()
        self.assertTrue(
            any(a["source"] == "CORP-WS-004" and a["destination"] == "OT-PLC-SMTA-01" for a in anoms)
        )

        # Vendor reachability query
        graph.add_vendor_link("VEND-ID-CODEBRIDGE", "DMZ-BASTION-01", protocol="SSH", port=22)
        graph.add_edge("DMZ-BASTION-01", "ENG-GITSVR-01", protocol="SSH", port=22, is_approved=True)
        vendor_reachable = graph.vendor_connected_assets("VEND-ID-CODEBRIDGE")
        self.assertIn("DMZ-BASTION-01", vendor_reachable)
        self.assertIn("ENG-GITSVR-01", vendor_reachable)

        # BlastRadiusAnalyzer with OT PLC asset + 24h observed flow
        analyzer = BlastRadiusAnalyzer(graph=graph, db_client=db, redis_client=redis)
        br = analyzer.analyze(
            incident_id="inc-ot-test-001",
            affected_assets=["OT-PLC-SMTA-01"],
            recent_flows_24h=[
                {
                    "source_asset_id": "CORP-WS-004",
                    "destination_asset_id": "OT-PLC-SMTA-01",
                    "identity": "compromised_operator",
                }
            ],
        )
        self.assertTrue(br.ot_impact_detected)
        self.assertTrue(any(OT_SAFETY_NOTE in note for note in br.safety_notes))
        direct_plc = br.directly_affected_assets[0]
        self.assertEqual(direct_plc["safety_note"], OT_SAFETY_NOTE)
        self.assertIn("production_impact", direct_plc)
        self.assertIn("isolation_difficulty", direct_plc)

        potential_ids = {a["asset_id"] for a in br.potentially_affected_assets}
        self.assertIn("OT-HMI-SMTA-01", potential_ids)
        self.assertIn("CORP-WS-004", potential_ids)
        self.assertIn("Manufacturing OT", br.related_zones)
        self.assertEqual(len(redis.streams.get(REDIS_STREAM_BLAST_RADIUS, [])), 1)
        self.assertEqual(len(db.executed), 1)

    # ------------------------------------------------------------------
    # 3. Section-Level Risk Assessor
    # ------------------------------------------------------------------
    def test_risk_assessor(self) -> None:
        redis = FakeRedis()
        db = FakeDB()
        assessor = RiskAssessor(db_client=db, redis_client=redis)

        incidents = [
            {
                "incident_id": "inc-1",
                "incident_reference": "INC-2026-001",
                "rule_id": "RULE-OT-001",
                "severity": "critical",
                "status": "open",
                "affected_assets": ["OT-PLC-SMTA-01"],
                "affected_zones": ["Manufacturing OT"],
                "ot_safety_flag": True,
            },
            {
                "incident_id": "inc-2",
                "incident_reference": "INC-2026-002",
                "rule_id": "RULE-CORP-001",
                "severity": "high",
                "status": "open",
                "affected_assets": ["CORP-WS-004", "CORP-DC-01"],
                "affected_zones": ["Corporate IT"],
                "ot_safety_flag": False,
            },
        ]
        vulnerabilities = [
            {"asset_id": "ENG-WS-002", "cve_id": "CVE-2016-10009", "risk_score": 13.5, "is_kev": False},
            {"asset_id": "CORP-WS-004", "cve_id": "CVE-2020-0796", "risk_score": 15.0, "is_kev": True},
        ]
        anomalies_24h = [
            {"asset_id": "ENG-WS-002", "network_zone": "Engineering & Firmware"},
            {"asset_id": "ENG-WS-002", "network_zone": "Engineering & Firmware"},
        ]
        comm_anomalies = [
            {"source": "VEND-ID-CODEBRIDGE", "destination": "ENG-WS-002"}
        ]

        results = assessor.assess_all_sections(
            incidents=incidents,
            vulnerabilities=vulnerabilities,
            anomalies_24h=anomalies_24h,
            communication_anomalies=comm_anomalies,
        )

        self.assertEqual(set(results.keys()), set(INFRASTRUCTURE_SECTIONS))
        self.assertEqual(results["Manufacturing OT"].risk_level, SectionRiskLevel.CRITICAL)
        self.assertEqual(results["Corporate IT"].risk_level, SectionRiskLevel.THREATENED)
        self.assertEqual(results["Corporate IT"].critical_asset_count_in_incidents, 1)
        self.assertEqual(results["Engineering/Firmware"].risk_level, SectionRiskLevel.ELEVATED)
        self.assertEqual(results["Third-Party"].risk_level, SectionRiskLevel.ELEVATED)
        self.assertEqual(results["Warehouse/Logistics"].risk_level, SectionRiskLevel.SECURE)
        self.assertEqual(results["Cloud"].risk_level, SectionRiskLevel.SECURE)
        self.assertTrue(len(results["Manufacturing OT"].recommended_actions) >= 1)

        # Redis hash 'risk:sections' populated for all 6 sections
        self.assertEqual(len(redis.hashes.get(REDIS_HASH_RISK_SECTIONS, {})), 6)
        # PostgreSQL security_events history written (6 sections)
        self.assertEqual(len(db.executed), 6)

    # ------------------------------------------------------------------
    # 4. Vulnerability Engine, Feeds & Exploitation Correlator Ladder
    # ------------------------------------------------------------------
    def test_vulnerability_engine(self) -> None:
        redis = FakeRedis()
        db = FakeDB()
        feeds = ThreatIntelFeedManager(redis_client=redis)

        # Verify ThreatIntelFeedManager lookups & Redis hashes
        self.assertIsNotNone(feeds.check_ip("185.220.101.10"))
        self.assertIsNone(feeds.check_ip("10.10.10.5"))
        self.assertIsNotNone(feeds.check_ja3("72a589da586844d7f0818ce684948eea"))
        kev_match = feeds.check_cve("CVE-2020-0796")
        self.assertIsNotNone(kev_match)
        self.assertTrue(kev_match.details.get("is_kev"))
        self.assertEqual(len(feeds.get_kev_catalog()), 20)
        self.assertIn(REDIS_KEY_IP_BLOCKLIST, redis.hashes)
        self.assertIn(REDIS_KEY_JA3_BLOCKLIST, redis.hashes)
        self.assertIn(REDIS_KEY_CISA_KEV, redis.hashes)

        # Run VulnerabilityEngine scan across assets + 4 Phase 1 vulnerable assets
        vuln_engine = VulnerabilityEngine(
            feed_manager=feeds, db_client=db, redis_client=redis
        )
        findings = vuln_engine.scan_all_assets(publish=True)
        matched_pairs = {(f.asset_id, f.cve_id): f for f in findings}

        self.assertIn(("CORP-WS-004", "CVE-2020-0796"), matched_pairs)
        self.assertIn(("ENG-WS-002", "CVE-2016-10009"), matched_pairs)
        self.assertIn(("MES-SERVER", "CVE-2018-1000656"), matched_pairs)
        self.assertIn(("FIRMWARE-STORAGE", "CVE-2019-9511"), matched_pairs)

        # Verify Risk Score formula: CVSS * criticality_multiplier * exposure_multiplier
        # CORP-WS-004: CVSS 10.0 * high (1.5) * internal-only (1.0) = 15.0
        smbghost = matched_pairs[("CORP-WS-004", "CVE-2020-0796")]
        self.assertAlmostEqual(smbghost.risk_score, 15.0)
        self.assertTrue(smbghost.is_kev)

        # MES-SERVER: CVSS 7.5 * critical (2.0) * cross-vlan-accessible (1.2) = 18.0
        mes_flask = matched_pairs[("MES-SERVER", "CVE-2018-1000656")]
        self.assertAlmostEqual(mes_flask.risk_score, 18.0)

        self.assertGreaterEqual(len(redis.streams.get(REDIS_STREAM_VULNERABILITIES, [])), 4)

        # Test ExploitationCorrelator classification ladder
        correlator = ExploitationCorrelator(db_client=db, redis_client=redis)

        # Stage 1: VULNERABILITY_EXPOSED (CVE match, no attack indicators)
        f1 = correlator.process_event("intel:vulnerabilities", smbghost.to_dict())[0]
        self.assertEqual(f1.stage, ExploitationStage.VULNERABILITY_EXPOSED)

        # Stage 2: ATTACK_ATTEMPT_DETECTED (Suricata exploit alert on port 445 + CVE match)
        f2 = correlator.process_event(
            "detections:signature",
            {
                "event_id": "suricata-smb-01",
                "destination_asset_id": "CORP-WS-004",
                "destination_port": 445,
                "detection_source": "suricata",
                "signature": "ET EXPLOIT Possible CVE-2020-0796 SMBGhost Attempt",
            },
        )[0]
        self.assertEqual(f2.stage, ExploitationStage.ATTACK_ATTEMPT_DETECTED)

        # Stage 3: POTENTIAL_EXPLOITATION (network exploit + anomaly + endpoint indicators)
        correlator.process_event(
            "detections:anomaly",
            {
                "event_id": "anom-smb-01",
                "destination_asset_id": "CORP-WS-004",
                "destination_port": 445,
                "anomaly_type": "unusual_smb_burst",
            },
        )
        f3 = correlator.process_event(
            "detections:lotl",
            {
                "event_id": "endpoint-proc-01",
                "asset_id": "CORP-WS-004",
                "event_type": "process_create",
                "process_name": "cmd.exe",
            },
        )[0]
        self.assertEqual(f3.stage, ExploitationStage.POTENTIAL_EXPLOITATION)
        # Must NEVER auto-escalate to CONFIRMED_COMPROMISE
        self.assertNotEqual(f3.stage, ExploitationStage.CONFIRMED_COMPROMISE)
        self.assertIn("Do not automatically label", f3.advisory_note)

        # Stage 4: CONFIRMED_COMPROMISE via manual analyst escalation ONLY
        f4 = correlator.confirm_compromise(
            asset_id="CORP-WS-004",
            cve_id="CVE-2020-0796",
            analyst_id="sec_analyst_pune_01",
            notes="Verified shellcode payload in memory dump",
        )
        self.assertEqual(f4.stage, ExploitationStage.CONFIRMED_COMPROMISE)
        self.assertEqual(f4.confirmed_by_analyst, "sec_analyst_pune_01")
        self.assertGreaterEqual(len(redis.streams.get(REDIS_STREAM_EXPLOITATION, [])), 4)

    # ------------------------------------------------------------------
    # 5. Supply Chain Monitor
    # ------------------------------------------------------------------
    def test_supply_chain_monitor(self) -> None:
        redis = FakeRedis()
        monitor = SupplyChainMonitor(redis_client=redis)

        # A. Off-hours vendor auth from unexpected IP with failed MFA
        auth_inds = monitor.check_vendor_authentication(
            {
                "event_id": "auth-v-01",
                "vendor_id": "VEND-005",
                "identity": "vendor_hexacore_dev",
                "source_ip": "185.220.101.45",
                "timestamp": "2026-11-18T02:15:00+00:00",
                "mfa_used": False,
                "mfa_failed": True,
            }
        )
        self.assertEqual(len(auth_inds), 1)
        self.assertEqual(auth_inds[0].indicator_type, "vendor_auth_anomaly")
        self.assertEqual(auth_inds[0].severity, "high")

        # B + F + I. Unexpected resource access crossing into OT VLAN 30 critical PLC
        res_inds = monitor.check_resource_access(
            {
                "event_id": "flow-v-01",
                "vendor_id": "VEND-005",
                "identity": "vendor_hexacore_dev",
                "source_asset_id": "DMZ-BASTION-01",
                "destination_asset_id": "OT-PLC-SMTA-01",
                "destination_port": 502,
                "destination_vlan": 30,
            }
        )
        types = {i.indicator_type for i in res_inds}
        self.assertIn("unexpected_resource_access", types)
        self.assertIn("unexpected_cross_it_ot_boundary", types)
        self.assertIn("suspicious_vendor_critical_infra_access", types)

        # C. Service account misuse (svc_erp_integration)
        svc_inds = monitor.check_service_account_misuse(
            {
                "event_id": "svc-01",
                "identity": "svc_erp_integration",
                "operation": "dump_all_payroll_db",
                "interactive_shell": True,
            }
        )
        self.assertEqual(len(svc_inds), 1)
        self.assertEqual(svc_inds[0].indicator_type, "service_account_anomaly")

        # D. Unusual API activity (> 2x normal rate)
        api_inds = monitor.check_api_activity(
            {
                "event_id": "api-01",
                "vendor_id": "VEND-003",
                "identity": "vendor_bluedart_api",
                "observed_rpm": 180,  # baseline is 60 -> 3x
            }
        )
        self.assertEqual(len(api_inds), 1)
        self.assertEqual(api_inds[0].indicator_type, "unusual_api_activity")

        # E. Abnormal shared storage access
        storage_inds = monitor.check_shared_storage_access(
            {
                "event_id": "file-01",
                "vendor_id": "VEND-005",
                "identity": "vendor_hexacore_dev",
                "file_path": "/finance/payroll_2026.xlsx",
            }
        )
        self.assertEqual(len(storage_inds), 1)
        self.assertEqual(storage_inds[0].indicator_type, "abnormal_shared_storage_access")

        # G. Unusual encrypted outbound from vendor-accessed asset
        out_inds = monitor.check_encrypted_outbound(
            {
                "event_id": "tls-01",
                "source_asset_id": "OT-PLC-SMTA-01",
                "destination_ip": "198.51.100.5",
                "bytes_out": 200_000_000,
                "is_encrypted": True,
            }
        )
        self.assertEqual(len(out_inds), 1)
        self.assertEqual(out_inds[0].indicator_type, "unusual_encrypted_outbound")

        # Maintenance window suppression test
        win_start = datetime(2026, 11, 21, 18, 0, 0, tzinfo=timezone.utc)
        win_end = datetime(2026, 11, 21, 22, 0, 0, tzinfo=timezone.utc)
        monitor.add_maintenance_window(
            vendor_id="VEND-002",
            start=win_start,
            end=win_end,
            allowed_assets=["OT-PLC-SMTA-01"],
        )
        maint_inds = monitor.check_resource_access(
            {
                "event_id": "flow-maint-01",
                "vendor_id": "VEND-002",
                "identity": "vendor_yamaha_smt",
                "destination_asset_id": "OT-PLC-SMTA-01",
                "destination_port": 443,
                "destination_vlan": 30,
                "timestamp": "2026-11-21T19:00:00+00:00",
            }
        )
        ot_maint = [i for i in maint_inds if i.indicator_type == "unexpected_cross_it_ot_boundary"]
        self.assertEqual(len(ot_maint), 1)
        self.assertTrue(ot_maint[0].suppressed)

        self.assertGreater(len(redis.streams.get(REDIS_STREAM_SUPPLY_CHAIN, [])), 0)

    # ------------------------------------------------------------------
    # 6. AI Investigation Assistant (9 Mandatory Fields, No Autonomous Action)
    # ------------------------------------------------------------------
    def test_ai_investigation_assistant(self) -> None:
        db = FakeDB()
        assistant = AIInvestigationAssistant(db_client=db, enable_llm_hook=False)

        incident = {
            "incident_id": "inc-inv-001",
            "incident_reference": "INC-2026-009",
            "rule_id": "RULE-OT-001",
            "title": "Unauthorized Modbus Write to OT-PLC-SMTA-01",
            "description": "Unauthorized Modbus FC6 write from CORP-WS-004 to OT-PLC-SMTA-01.",
            "severity": "critical",
            "affected_assets": ["CORP-WS-004", "OT-PLC-SMTA-01"],
            "affected_zones": ["Corporate IT", "Manufacturing OT"],
            "mitre_techniques": ["T0855"],
            "first_seen": "2026-11-18T12:00:00+00:00",
            "ot_safety_flag": True,
        }
        events = [
            {
                "event_id": "ev-ot-100",
                "timestamp": "2026-11-18T12:00:00+00:00",
                "event_type": "alert",
                "detection_source": "suricata",
                "severity": "critical",
                "source_asset_id": "CORP-WS-004",
                "destination_asset_id": "OT-PLC-SMTA-01",
                "identity": "ops_user_04",
                "principal_type": "HUMAN_USER",
                "signature": "Modbus Write Single Register FC6 from Corporate VLAN",
            }
        ]

        summary = assistant.investigate(incident=incident, related_events=events, persist=True)
        data = summary.to_dict()

        # Verify all 9 mandatory fields are present and grounded in ev-ot-100
        for field_name in (
            "what_happened",
            "where",
            "first_indicator",
            "affected_assets",
            "involved_identities",
            "related_events",
            "potential_impact",
            "investigation_recommendations",
            "containment_options",
        ):
            self.assertIn(field_name, data)
            self.assertTrue(data[field_name], f"Expected non-empty field: {field_name}")

        self.assertIn("ev-ot-100", data["what_happened"])
        self.assertEqual(data["first_indicator"]["event_id"], "ev-ot-100")
        self.assertFalse(summary.autonomous_action_taken)
        self.assertTrue(data["potential_impact"]["ot_safety_flag"])
        self.assertTrue(
            any(opt["action_category"] == "OT_BOUNDARY_RESTRICTION" for opt in data["containment_options"])
        )
        self.assertEqual(len(db.executed), 1)
        self.assertIn("AI-assisted analysis", AI_DISCLAIMER)


if __name__ == "__main__":
    unittest.main()
