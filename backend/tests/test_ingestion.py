"""
VaultX NIDS - Phase 2 Ingestion & Processing Unit Test Suite
Bharat Electronics Components Pvt. Ltd. (BECPL), Pune

Covers:
  - Normaliser: Zeek conn.log, Suricata alert, Sysmon XML, auditd line, VPN, Cloud, API GW, errors
  - Enricher: IP-to-asset lookup hit & miss, identity lookup & UNKNOWN_IDENTITY fallback,
              cross-VLAN & critical asset risk flags
  - Dedup cache: duplicate detection, TTL expiry (mock Redis), per-minute stats
  - Flow aggregator: bidirectional stats, FIN/RST and timeout closure, Redis emission
  - Feature extractor: CIC-IDS2017 + BECPL + encrypted traffic features, vector shape & value ranges
  - Parallel processor: selective inference routing & ML queue backpressure
  - Checkpoint manager & Sensor health monitor
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# Ensure repository root is importable
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.ingestion.checkpoint_manager import CheckpointManager
from backend.ingestion.dedup_cache import DedupCache
from backend.ingestion.enricher import AssetIdentityEnricher
from backend.ingestion.event_schema import (
    DetectionSource,
    EncryptionMetadata,
    EventType,
    PrincipalType,
    Severity,
    StandardSecurityEvent,
)
from backend.ingestion.models import EnrichedSecurityEvent, FlowRecord, ProcessingPriority, RiskFlag
from backend.ingestion.normaliser import (
    ApiGwNormaliser,
    AuditdNormaliser,
    CloudNormaliser,
    EventNormaliser,
    NormalisationError,
    SuricataNormaliser,
    SysmonNormaliser,
    VPNNormaliser,
    ZeekNormaliser,
)
from backend.ingestion.sensor_health_monitor import SensorHealthMonitor
from backend.processing.feature_extractor import NUMERIC_FEATURE_NAMES, FeatureExtractor
from backend.processing.flow_aggregator import FlowAggregator
from backend.processing.parallel_processor import ParallelEventProcessor


# ---------------------------------------------------------------------------
# In-memory Async Mock Redis with TTL support
# ---------------------------------------------------------------------------

class FakeClock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def advance(self, seconds: float) -> None:
        self.now += seconds


class MockRedis:
    """Lightweight async Redis mock supporting GET, SETEX, HSET/HGETALL, XADD, ZADD."""

    def __init__(self, clock: Optional[FakeClock] = None) -> None:
        self._clock = clock or FakeClock()
        self._kv: Dict[str, tuple[str, Optional[float]]] = {}
        self._hashes: Dict[str, Dict[str, Any]] = {}
        self._streams: Dict[str, List[tuple[str, Dict[str, Any]]]] = {}
        self._zsets: Dict[str, Dict[str, float]] = {}

    async def get(self, key: str) -> Optional[str]:
        item = self._kv.get(key)
        if item is None:
            return None
        val, exp = item
        if exp is not None and self._clock.now >= exp:
            del self._kv[key]
            return None
        return val

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        self._kv[key] = (value, self._clock.now + ttl)
        return True

    async def hincrby(self, name: str, key: str, amount: int = 1) -> int:
        bucket = self._hashes.setdefault(name, {})
        bucket[key] = int(bucket.get(key, 0)) + amount
        return bucket[key]

    async def hset(self, name: str, key: str, value: str) -> int:
        bucket = self._hashes.setdefault(name, {})
        bucket[key] = value
        return 1

    async def hgetall(self, name: str) -> Dict[str, Any]:
        return dict(self._hashes.get(name, {}))

    async def xadd(self, stream: str, fields: Dict[str, Any]) -> str:
        entries = self._streams.setdefault(stream, [])
        msg_id = f"{int(self._clock.now * 1000)}-{len(entries)}"
        entries.append((msg_id, fields))
        return msg_id

    async def xlen(self, stream: str) -> int:
        return len(self._streams.get(stream, []))

    async def zadd(self, name: str, mapping: Dict[str, float]) -> int:
        zset = self._zsets.setdefault(name, {})
        zset.update(mapping)
        return len(mapping)

    async def zremrangebyscore(self, name: str, min_score: Any, max_score: float) -> int:
        zset = self._zsets.get(name, {})
        to_remove = [k for k, v in zset.items() if v <= max_score]
        for k in to_remove:
            del zset[k]
        return len(to_remove)


class _MockDBConn:
    def __init__(self, assets: Dict[str, Dict[str, Any]], identities: Dict[str, Dict[str, Any]]) -> None:
        self._assets = assets
        self._identities = identities
        self.executed: List[tuple[str, tuple]] = []

    async def fetchrow(self, query: str, *args: Any) -> Optional[Dict[str, Any]]:
        if "FROM becpl_nids.assets" in query:
            return self._assets.get(args[0])
        if "FROM becpl_nids.identities" in query:
            return self._identities.get(args[0])
        return None

    async def fetch(self, query: str, *args: Any) -> List[Dict[str, Any]]:
        return []

    async def execute(self, query: str, *args: Any) -> str:
        self.executed.append((query, args))
        return "INSERT 0 1"


class _MockDBPoolCtx:
    def __init__(self, conn: _MockDBConn) -> None:
        self._conn = conn

    async def __aenter__(self) -> _MockDBConn:
        return self._conn

    async def __aexit__(self, *args: Any) -> None:
        return None


class MockDBPool:
    def __init__(
        self,
        assets: Optional[Dict[str, Dict[str, Any]]] = None,
        identities: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self.conn = _MockDBConn(assets or {}, identities or {})

    def acquire(self) -> _MockDBPoolCtx:
        return _MockDBPoolCtx(self.conn)


# ---------------------------------------------------------------------------
# 1. Normaliser Tests
# ---------------------------------------------------------------------------

class TestNormaliser:
    def test_zeek_conn_log_json(self) -> None:
        raw = {
            "ts": 1731900000.5,
            "uid": "C1a2B3c4D5e6F7",
            "id.orig_h": "10.10.10.25",
            "id.orig_p": 54321,
            "id.resp_h": "10.10.30.10",
            "id.resp_p": 502,
            "proto": "tcp",
            "service": "modbus",
            "duration": 1.25,
            "orig_bytes": 1200,
            "resp_bytes": 3400,
            "orig_pkts": 10,
            "resp_pkts": 12,
            "conn_state": "SF",
            "history": "ShADadFf",
        }
        ev = EventNormaliser().normalise(raw, sensor_id="SENSOR-OT-01")
        assert ev.detection_source == DetectionSource.ZEEK
        assert ev.event_type == EventType.NETWORK_FLOW
        assert ev.source_ip == "10.10.10.25"
        assert ev.destination_ip == "10.10.30.10"
        assert ev.source_port == 54321
        assert ev.destination_port == 502
        assert ev.protocol == "TCP"
        assert ev.connection_duration == 1250
        assert ev.bytes_transferred == 4600
        assert ev.packets_transferred == 22
        assert ev.event_provenance is not None
        assert ev.event_provenance.source_system == "zeek"
        assert ev.event_provenance.raw_log_reference == "C1a2B3c4D5e6F7"

    def test_zeek_conn_log_tsv(self) -> None:
        tsv = (
            "1731900000.0\tCxyz123\t10.10.20.15\t49152\t10.10.20.5\t443\t"
            "tcp\tssl\t2.5\t512\t2048\tSF\tT\tT\t0\tShADadFf\t6\t800\t8\t2400"
        )
        ev = ZeekNormaliser().normalise(tsv, sensor_id="SENSOR-ENG-01")
        assert ev.source_ip == "10.10.20.15"
        assert ev.destination_port == 443
        assert ev.bytes_transferred == 2560
        assert ev.event_provenance is not None
        assert ev.event_provenance.collection_method == "SPAN"

    def test_suricata_alert(self) -> None:
        raw = {
            "timestamp": "2026-11-18T05:10:00.123456+0000",
            "flow_id": 99887766,
            "in_iface": "eth1",
            "event_type": "alert",
            "src_ip": "10.10.50.12",
            "src_port": 44120,
            "dest_ip": "10.10.30.11",
            "dest_port": 502,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "signature_id": 9000001,
                "rev": 2,
                "signature": "BECPL OT Unauthorized Modbus Write Coil",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1,
            },
        }
        ev = EventNormaliser().normalise(raw, sensor_id="SENSOR-OT-01")
        assert ev.detection_source == DetectionSource.SURICATA
        assert ev.event_type == EventType.ALERT
        assert ev.severity == Severity.CRITICAL
        assert ev.source_ip == "10.10.50.12"
        assert ev.destination_ip == "10.10.30.11"
        assert ev.destination_port == 502
        assert ev.evidence["signature_id"] == 9000001
        assert ev.event_provenance is not None
        assert ev.event_provenance.source_system == "suricata"

    def test_sysmon_xml(self) -> None:
        xml_event = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Sysmon" />
            <EventID>3</EventID>
            <TimeCreated SystemTime="2026-11-18T05:15:30.000Z" />
            <Computer>CORP-WS-014</Computer>
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
          </System>
          <EventData>
            <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
            <Data Name="User">BECPL\\r.kulkarni</Data>
            <Data Name="Protocol">tcp</Data>
            <Data Name="SourceIp">10.10.10.14</Data>
            <Data Name="SourcePort">51234</Data>
            <Data Name="DestinationIp">10.10.20.5</Data>
            <Data Name="DestinationPort">22</Data>
            <Data Name="ProcessId">4242</Data>
          </EventData>
        </Event>
        """
        ev = EventNormaliser().normalise(xml_event)
        assert ev.detection_source == DetectionSource.SYSMON
        assert ev.sensor_id == "CORP-WS-014"
        assert ev.event_type == EventType.NETWORK_FLOW
        assert ev.source_ip == "10.10.10.14"
        assert ev.destination_ip == "10.10.20.5"
        assert ev.destination_port == 22
        assert ev.evidence["principal_name"] == "BECPL\\r.kulkarni"
        assert ev.event_provenance is not None
        assert ev.event_provenance.source_system == "sysmon"

    def test_auditd_line(self) -> None:
        line = (
            'type=USER_AUTH msg=audit(1731900100.456:789): pid=2101 uid=0 auid=1001 '
            'ses=42 msg=\'op=PAM:authentication acct="admin_ot" exe="/usr/sbin/sshd" '
            'hostname=? addr=10.10.70.5 terminal=ssh res=failed\''
        )
        ev = EventNormaliser().normalise(line, sensor_id="OT-HIST-01")
        assert ev.detection_source == DetectionSource.AUDITD
        assert ev.event_type == EventType.AUTH_EVENT
        assert ev.severity == Severity.MEDIUM
        assert ev.source_ip == "10.10.70.5"
        assert ev.evidence["principal_name"] == "admin_ot"
        assert ev.evidence["audit_serial"] == "789"
        assert ev.event_provenance is not None
        assert ev.event_provenance.source_system == "auditd"

    def test_vpn_cloud_apigw_normalisers(self) -> None:
        vpn_ev = VPNNormaliser().normalise({
            "source": "vpn",
            "timestamp": "2026-11-18T05:20:00Z",
            "vpn_user": "vendor_maint_01",
            "remote_ip": "103.21.58.10",
            "gateway_ip": "10.10.50.2",
            "status": "success",
        })
        assert vpn_ev.event_type == EventType.AUTH_EVENT
        assert vpn_ev.evidence["principal_name"] == "vendor_maint_01"

        cloud_ev = CloudNormaliser().normalise({
            "eventTime": "2026-11-18T05:21:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "sourceIPAddress": "10.10.60.10",
            "userIdentity": {"userName": "svc_erp_sync"},
        })
        assert cloud_ev.evidence["principal_name"] == "svc_erp_sync"

        apigw_ev = ApiGwNormaliser().normalise({
            "source": "api_gw",
            "timestamp": "2026-11-18T05:22:00Z",
            "request_id": "req-001",
            "http_method": "POST",
            "path": "/api/v1/shipment",
            "status_code": 403,
            "client_ip": "10.10.40.22",
        })
        assert apigw_ev.event_type == EventType.HTTP_EVENT
        assert apigw_ev.severity == Severity.MEDIUM

    def test_normalisation_error_on_empty_input(self) -> None:
        with pytest.raises(NormalisationError):
            EventNormaliser().normalise({})
        with pytest.raises(NormalisationError):
            EventNormaliser().normalise("")


# ---------------------------------------------------------------------------
# 2. Enricher Tests
# ---------------------------------------------------------------------------

class TestEnricher:
    @pytest.mark.asyncio
    async def test_ip_to_asset_hit_cross_vlan_and_critical_flags(self) -> None:
        redis = MockRedis()
        db_pool = MockDBPool(
            assets={
                "10.10.10.25": {
                    "asset_id": "CORP-WS-025",
                    "hostname": "corp-ws-025.becpl.local",
                    "ip_str": "10.10.10.25",
                    "vlan_id": 10,
                    "zone_name": "Corporate_IT",
                    "zone_type": "corporate",
                    "device_type": "workstation",
                    "criticality": "medium",
                    "owner_department": "Finance",
                    "identity_classification": "HUMAN_USER",
                },
                "10.10.30.10": {
                    "asset_id": "OT-SMT-PLC01",
                    "hostname": "smt-plc-01.ot.becpl",
                    "ip_str": "10.10.30.10",
                    "vlan_id": 30,
                    "zone_name": "OT",
                    "zone_type": "ot",
                    "device_type": "plc",
                    "criticality": "critical",
                    "owner_department": "Manufacturing",
                    "identity_classification": "INDUSTRIAL_DEVICE",
                },
            }
        )
        enricher = AssetIdentityEnricher(redis_client=redis, db_pool=db_pool, cache_ttl_seconds=60)
        event = StandardSecurityEvent(
            sensor_id="SENSOR-OT-01",
            source_ip="10.10.10.25",
            destination_ip="10.10.30.10",
            source_port=51100,
            destination_port=502,
            protocol="TCP",
            event_type=EventType.NETWORK_FLOW,
            detection_source=DetectionSource.ZEEK,
        )

        enriched = await enricher.enrich(event)
        assert enriched.source_asset_id == "CORP-WS-025"
        assert enriched.destination_asset_id == "OT-SMT-PLC01"
        assert enriched.source_zone == "Corporate_IT"
        assert enriched.destination_zone == "OT"
        assert enriched.source_criticality == "medium"
        assert enriched.destination_criticality == "critical"
        assert enriched.is_cross_vlan is True
        assert enriched.involves_critical_asset is True
        assert RiskFlag.CROSS_VLAN.value in enriched.risk_flags
        assert RiskFlag.CRITICAL_ASSET_INVOLVED.value in enriched.risk_flags
        assert RiskFlag.OT_DESTINATION.value in enriched.risk_flags
        assert enriched.processing_priority == ProcessingPriority.HIGH_PRIORITY
        # Network flow without explicit auth identity MUST remain UNKNOWN_IDENTITY
        assert enriched.principal_type == PrincipalType.UNKNOWN_IDENTITY
        assert enriched.identity_id is None

        # Verify second lookup hits Redis cache (asset cached)
        cached_val = await redis.get(f"{AssetIdentityEnricher.ASSET_CACHE_PREFIX}10.10.30.10")
        assert cached_val is not None
        assert "OT-SMT-PLC01" in cached_val

    @pytest.mark.asyncio
    async def test_ip_to_asset_miss_and_identity_fallback(self) -> None:
        redis = MockRedis()
        known_uid = str(uuid.uuid4())
        db_pool = MockDBPool(
            assets={},
            identities={
                "r.sharma": {
                    "identity_id": known_uid,
                    "principal_name": "r.sharma",
                    "principal_type": "HUMAN_USER",
                }
            },
        )
        enricher = AssetIdentityEnricher(redis_client=redis, db_pool=db_pool)

        # Internal unknown IP + unknown auth user -> asset miss & UNKNOWN_IDENTITY
        ev_miss = StandardSecurityEvent(
            sensor_id="SENSOR-CORP-01",
            source_ip="10.10.10.199",
            destination_ip="8.8.8.8",
            event_type=EventType.AUTH_EVENT,
            evidence={"principal_name": "ghost_user"},
        )
        enriched_miss = await enricher.enrich(ev_miss)
        assert enriched_miss.source_asset_id is None
        assert enriched_miss.destination_zone == "External"
        assert RiskFlag.EXTERNAL_DESTINATION.value in enriched_miss.risk_flags
        assert enriched_miss.principal_type == PrincipalType.UNKNOWN_IDENTITY
        assert enriched_miss.identity_id is None

        # Auth event with known principal_name -> resolves identity_id & principal_type
        ev_auth = StandardSecurityEvent(
            sensor_id="SENSOR-CORP-01",
            source_ip="10.10.10.199",
            destination_ip="10.10.10.5",
            event_type=EventType.AUTH_EVENT,
            evidence={"principal_name": "r.sharma"},
        )
        enriched_auth = await enricher.enrich(ev_auth)
        assert str(enriched_auth.identity_id) == known_uid
        assert enriched_auth.principal_type == PrincipalType.HUMAN_USER


# ---------------------------------------------------------------------------
# 3. Dedup Cache Tests
# ---------------------------------------------------------------------------

class TestDedupCache:
    @pytest.mark.asyncio
    async def test_duplicate_detection_and_ttl_expiry(self) -> None:
        clock = FakeClock(start=1_731_900_000.0)
        redis = MockRedis(clock=clock)
        cache = DedupCache(redis_client=redis, ttl_seconds=300)

        ts = datetime(2026, 11, 18, 5, 30, 12, tzinfo=timezone.utc)

        # First sight -> NOT duplicate
        is_dup_1, hash_1 = await cache.check_and_record(
            timestamp=ts,
            src_ip="10.10.10.10",
            dst_ip="10.10.20.20",
            src_port=50000,
            dst_port=443,
            event_type="network_flow",
        )
        assert is_dup_1 is False
        assert len(hash_1) == 64  # SHA-256 hex

        # Immediate repeat in same minute bucket -> DUPLICATE
        is_dup_2, hash_2 = await cache.check_and_record(
            timestamp=ts + timedelta(seconds=10),
            src_ip="10.10.10.10",
            dst_ip="10.10.20.20",
            src_port=50000,
            dst_port=443,
            event_type="network_flow",
        )
        assert is_dup_2 is True
        assert hash_2 == hash_1
        assert cache.duplicates_filtered_total == 1
        assert cache.duplicates_per_minute() == 1

        # Advance mock Redis clock past 300s TTL -> expires, treated as NEW again
        clock.advance(301.0)
        is_dup_3 = await cache.is_duplicate(
            timestamp=ts,
            src_ip="10.10.10.10",
            dst_ip="10.10.20.20",
            src_port=50000,
            dst_port=443,
            event_type="network_flow",
        )
        assert is_dup_3 is False


# ---------------------------------------------------------------------------
# 4. Flow Aggregator Tests
# ---------------------------------------------------------------------------

class TestFlowAggregator:
    @pytest.mark.asyncio
    async def test_bidirectional_flow_and_fin_completion(self) -> None:
        redis = MockRedis()
        aggregator = FlowAggregator(redis_client=redis, flow_timeout_seconds=60)
        t0 = datetime(2026, 11, 18, 6, 0, 0, tzinfo=timezone.utc)

        # Forward packet (initiator -> responder)
        e1 = EnrichedSecurityEvent(
            sensor_id="SENSOR-CORP-01",
            timestamp=t0,
            source_ip="10.10.10.12",
            destination_ip="10.10.20.5",
            source_port=52000,
            destination_port=443,
            protocol="TCP",
            bytes_transferred=500,
            packets_transferred=2,
            source_vlan=10,
            destination_vlan=20,
            source_zone="Corporate_IT",
            destination_zone="Engineering",
            source_criticality="medium",
            destination_criticality="high",
            is_cross_vlan=True,
            evidence={"tcp_flags": "SYN,ACK"},
        )
        assert await aggregator.add_event(e1) is None
        assert aggregator.active_flow_count == 1

        # Reverse packet (responder -> initiator) on same bidirectional 5-tuple
        e2 = EnrichedSecurityEvent(
            sensor_id="SENSOR-CORP-01",
            timestamp=t0 + timedelta(seconds=2),
            source_ip="10.10.20.5",
            destination_ip="10.10.10.12",
            source_port=443,
            destination_port=52000,
            protocol="TCP",
            bytes_transferred=2000,
            packets_transferred=4,
            evidence={"tcp_flags": "PSH,ACK"},
        )
        assert await aggregator.add_event(e2) is None
        assert aggregator.active_flow_count == 1

        # Forward FIN packet closes flow
        e3 = EnrichedSecurityEvent(
            sensor_id="SENSOR-CORP-01",
            timestamp=t0 + timedelta(seconds=5),
            source_ip="10.10.10.12",
            destination_ip="10.10.20.5",
            source_port=52000,
            destination_port=443,
            protocol="TCP",
            bytes_transferred=500,
            packets_transferred=1,
            evidence={"tcp_flags": "FIN,ACK"},
        )
        completed = await aggregator.add_event(e3)
        assert completed is not None
        assert aggregator.active_flow_count == 0
        assert completed.close_reason == "FIN"
        assert completed.src_ip == "10.10.10.12"
        assert completed.dst_ip == "10.10.20.5"
        assert completed.initiating_direction == "forward"
        assert completed.fwd_bytes == 1000
        assert completed.bwd_bytes == 2000
        assert completed.fwd_packets == 3
        assert completed.bwd_packets == 4
        assert completed.total_bytes == 3000
        assert completed.duration_ms == pytest.approx(5000.0)
        assert completed.upload_download_ratio == pytest.approx(0.5)
        assert completed.down_up_ratio == pytest.approx(2.0)
        assert completed.is_cross_vlan is True
        assert await redis.xlen("flows:completed") == 1

    @pytest.mark.asyncio
    async def test_timeout_flow_expiration(self) -> None:
        redis = MockRedis()
        aggregator = FlowAggregator(redis_client=redis, flow_timeout_seconds=60)
        t0 = datetime(2026, 11, 18, 6, 0, 0, tzinfo=timezone.utc)

        ev = StandardSecurityEvent(
            sensor_id="SENSOR-OT-01",
            timestamp=t0,
            source_ip="10.10.30.2",
            destination_ip="10.10.30.10",
            source_port=40001,
            destination_port=502,
            protocol="TCP",
            bytes_transferred=256,
            packets_transferred=2,
        )
        await aggregator.add_event(ev)
        assert aggregator.active_flow_count == 1

        # Not expired at +30s
        assert await aggregator.expire_timed_out_flows(now=t0 + timedelta(seconds=30)) == []
        # Expired at +61s
        expired = await aggregator.expire_timed_out_flows(now=t0 + timedelta(seconds=61))
        assert len(expired) == 1
        assert expired[0].close_reason == "timeout"
        assert aggregator.active_flow_count == 0


# ---------------------------------------------------------------------------
# 5. Feature Extractor Tests
# ---------------------------------------------------------------------------

class TestFeatureExtractor:
    def test_feature_vector_shape_and_ranges_with_tls(self) -> None:
        t0 = datetime(2026, 11, 18, 7, 0, 0, tzinfo=timezone.utc)
        flow = FlowRecord(
            src_ip="10.10.50.10",
            dst_ip="10.10.30.10",
            src_port=54000,
            dst_port=443,
            protocol="TCP",
            start_time=t0,
            end_time=t0 + timedelta(seconds=10),
            duration_ms=10_000.0,
            fwd_packets=20,
            bwd_packets=30,
            fwd_bytes=4000,
            bwd_bytes=12000,
            total_packets=50,
            total_bytes=16000,
            flow_bytes_per_sec=1600.0,
            flow_packets_per_sec=5.0,
            fwd_iat_mean=0.5,
            bwd_iat_mean=0.33,
            inter_packet_interval_mean=0.2,
            inter_packet_interval_std=0.05,
            psh_flag_count=8,
            ack_flag_count=45,
            pkt_len_mean=320.0,
            pkt_len_std=45.2,
            source_vlan=50,
            dest_vlan=30,
            source_criticality="high",
            dest_criticality="critical",
            is_cross_vlan=True,
            is_vendor_connection=True,
            is_ot_destination=True,
            is_external_dest=False,
            tls_version="TLSv1.3",
            sni="hmi.ot.becpl.internal",
            cert_issuer_known=True,
            ja3_hash="771,4865-4866,0-23,29,0",
            ja3s_hash="771,4865,43",
        )

        extractor = FeatureExtractor()
        feats = extractor.extract(flow)

        # Verify CIC-IDS2017 fields
        for key in (
            "duration", "protocol_num", "fwd_packets", "bwd_packets",
            "fwd_bytes", "bwd_bytes", "flow_bytes_per_sec", "flow_packets_per_sec",
            "fwd_iat_mean", "bwd_iat_mean", "psh_flag_count", "ack_flag_count",
            "down_up_ratio", "pkt_len_mean", "pkt_len_std",
        ):
            assert key in feats
            assert feats[key] >= 0

        # Verify BECPL fields
        assert feats["protocol_num"] == 6
        assert feats["source_vlan"] == 50
        assert feats["dest_vlan"] == 30
        assert feats["is_cross_vlan"] == 1
        assert feats["source_criticality_score"] == 3.0
        assert feats["dest_criticality_score"] == 4.0
        assert feats["is_vendor_connection"] == 1
        assert feats["is_ot_destination"] == 1
        assert feats["is_external_dest"] == 0

        # Verify always-available encrypted features
        assert feats["flow_duration_sec"] == pytest.approx(10.0)
        assert feats["bytes_up"] == 4000
        assert feats["bytes_down"] == 12000
        assert feats["ratio_up_down"] == pytest.approx(4000 / 12000, rel=1e-4)
        assert feats["num_packets"] == 50

        # Verify TLS metadata features
        assert feats["tls_version_num"] == pytest.approx(1.3)
        assert feats["has_sni"] == 1
        assert feats["cert_issuer_known"] == 1
        assert feats["ja3_hash"] == "771,4865-4866,0-23,29,0"

        # Verify numeric vector shape
        names, vec = extractor.extract_vector(flow)
        assert len(names) == len(NUMERIC_FEATURE_NAMES)
        assert len(vec) == len(NUMERIC_FEATURE_NAMES)
        assert all(isinstance(v, float) for v in vec)
        assert all(v >= 0.0 for v in vec)

    def test_feature_extractor_without_tls(self) -> None:
        t0 = datetime(2026, 11, 18, 7, 0, 0, tzinfo=timezone.utc)
        flow = FlowRecord(
            src_ip="10.10.10.5",
            dst_ip="10.10.10.1",
            src_port=53000,
            dst_port=53,
            protocol="UDP",
            start_time=t0,
            end_time=t0 + timedelta(milliseconds=100),
            duration_ms=100.0,
            fwd_packets=1,
            bwd_packets=1,
            fwd_bytes=64,
            bwd_bytes=128,
        )
        feats = FeatureExtractor().extract(flow)
        assert feats["protocol_num"] == 17
        assert "tls_version_num" not in feats
        assert "flow_duration_sec" in feats
        assert feats["num_packets"] == 2


# ---------------------------------------------------------------------------
# 6. Parallel Processor, Checkpoint Manager & Sensor Health Monitor Tests
# ---------------------------------------------------------------------------

class TestPipelineComponents:
    @pytest.mark.asyncio
    async def test_parallel_processor_selective_inference_and_backpressure(self) -> None:
        redis = MockRedis()
        agg = FlowAggregator(redis_client=redis)
        proc = ParallelEventProcessor(
            flow_aggregator=agg,
            redis_client=redis,
            worker_count=2,
            ml_queue_backpressure_threshold=2,
        )

        normal_ev = EnrichedSecurityEvent(
            sensor_id="SENSOR-CORP-01",
            source_ip="10.10.10.5",
            destination_ip="10.10.10.6",
            source_port=50000,
            destination_port=80,
            protocol="TCP",
            source_zone="Corporate_IT",
            destination_zone="Corporate_IT",
        )
        suspicious_ev = EnrichedSecurityEvent(
            sensor_id="SENSOR-CORP-01",
            source_ip="10.10.10.5",
            destination_ip="10.10.20.6",
            source_port=50001,
            destination_port=80,
            protocol="TCP",
            is_cross_vlan=True,
            risk_flags=[RiskFlag.CROSS_VLAN.value],
        )
        high_prio_ev = EnrichedSecurityEvent(
            sensor_id="SENSOR-OT-01",
            source_ip="10.10.50.5",
            destination_ip="10.10.30.10",
            source_port=50002,
            destination_port=502,
            protocol="TCP",
            involves_critical_asset=True,
            risk_flags=[RiskFlag.OT_DESTINATION.value, RiskFlag.CRITICAL_ASSET_INVOLVED.value],
        )

        out_normal = await proc.process_event(normal_ev)
        assert out_normal.routing_tier == "lightweight"

        out_high = await proc.process_event(high_prio_ev)
        assert out_high.routing_tier == "immediate_ml"

        # Fill ML queue up to threshold (2), then 3rd suspicious event triggers backpressure
        assert (await proc.process_event(suspicious_ev)).routing_tier == "ml_queue"
        assert (await proc.process_event(suspicious_ev)).routing_tier == "ml_queue"
        assert (await proc.process_event(suspicious_ev)).routing_tier == "statistical_only_backpressure"
        assert proc.ml_backpressure_active is True

    @pytest.mark.asyncio
    async def test_sensor_offline_alert(self) -> None:
        redis = MockRedis()
        mon = SensorHealthMonitor(redis_client=redis, offline_threshold_seconds=300)
        t0 = datetime(2026, 11, 18, 8, 0, 0, tzinfo=timezone.utc)

        await mon.record_heartbeat("SENSOR-OT-01", events_per_min=450.0, timestamp=t0)
        alerts_ok = await mon.check_sensors(now=t0 + timedelta(seconds=120))
        assert alerts_ok == []

        alerts_offline = await mon.check_sensors(now=t0 + timedelta(seconds=360))
        assert len(alerts_offline) == 1
        assert alerts_offline[0].alert_type == "SENSOR_OFFLINE"
        assert "SENSOR-OT-01" in mon.get_offline_sensors()
        assert await redis.xlen("alerts:operational") == 1

    @pytest.mark.asyncio
    async def test_checkpoint_manager_recovery_and_flush(self) -> None:
        redis = MockRedis()
        db_pool = MockDBPool()
        cm = CheckpointManager(redis_client=redis, db_pool=db_pool)

        await cm.update_checkpoint("events:raw", "1731900000000-5")
        assert cm.is_already_processed("events:raw", "1731900000000-4") is True
        assert cm.is_already_processed("events:raw", "1731900000000-6") is False

        flushed = await cm.flush_now()
        assert flushed == 1
        assert len(db_pool.conn.executed) == 1
