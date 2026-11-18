"""
VaultX Phase 2 - Central Threat Correlation & Systemic Analysis Engine
BECPL (Bharat Electronics Components Pvt. Ltd.), Pune

Consumes from ALL 8 detection & intelligence Redis streams:
  1. detections:signature
  2. detections:ml
  3. detections:anomaly
  4. detections:encrypted_traffic
  5. detections:lotl
  6. detections:identity
  7. detections:supply_chain
  8. intel:exploitation

Maintains a sliding event buffer per asset per zone (30-minute default window,
60-minute retention for multi-stage vendor compromise chains).

Implements all 10 BECPL correlation rules:
  - RULE-CORP-001   : Lateral Movement Campaign (>= 3 distinct targets < 10 min, HIGH, T1021)
  - RULE-CORP-002   : Credential Compromise + Movement (identity_anomaly + network_anomaly < 30 min, HIGH)
  - RULE-CORP-003   : LOTL Execution Chain (lotl_indicator + external conn < 15 min, HIGH, T1059+T1041)
  - RULE-ENG-001    : Firmware Exfiltration Attempt (VLAN 20 port 3000 + encrypted_traffic_anomaly, CRITICAL)
  - RULE-VENDOR-001 : Vendor Compromise Chain (vendor_auth_anomaly + unexpected_resource_access + cross_vlan_access in sequence < 60 min, HIGH)
  - RULE-VENDOR-002 : Service Account Misuse (service_account_anomaly + unusual_api_activity + external_connection, HIGH)
  - RULE-OT-001     : Unauthorized OT Access (Modbus from non-approved source + write FC6/FC8/FC16, CRITICAL, OT_SAFETY_FLAG=True)
  - RULE-OT-002     : IT-to-OT Communication (VLAN 10/20 -> VLAN 30 not on approved allowlist, HIGH)
  - RULE-EXFIL-001  : Data Exfiltration (encrypted_traffic_anomaly high_upload_ratio + large_volume + critical_asset + unusual_time, HIGH)
  - RULE-SCAN-001   : Reconnaissance and Vulnerability Scan (port_scan_pattern + CVE match, MEDIUM; HIGH if KEV CVE)

Handles incident deduplication, INC-YYYY-NNN reference generation, PostgreSQL persistence,
and publishing to Redis stream 'incidents:active'.
"""

from __future__ import annotations

import inspect
import ipaddress
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("vaultx.correlation.engine")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COMM_MATRIX_PATH = REPO_ROOT / "infra" / "topology" / "communication_matrix.json"
DEFAULT_ASSETS_PATH = REPO_ROOT / "infra" / "topology" / "assets.json"

CORRELATION_STREAMS: Tuple[str, ...] = (
    "detections:signature",
    "detections:ml",
    "detections:anomaly",
    "detections:encrypted_traffic",
    "detections:lotl",
    "detections:identity",
    "detections:supply_chain",
    "intel:exploitation",
)

REDIS_STREAM_INCIDENTS = "incidents:active"

MODBUS_WRITE_FUNCTION_CODES: Set[int] = {5, 6, 8, 15, 16}
MODBUS_CRITICAL_WRITE_FCS: Set[int] = {6, 8, 16}

VLAN_ZONE_MAP: Dict[int, str] = {
    10: "Corporate IT",
    20: "Engineering & Firmware",
    30: "Manufacturing OT",
    40: "Warehouse & Logistics",
    50: "DMZ & Vendor Access",
    60: "Cloud & External Integrations",
    70: "Security Management",
}


@dataclass
class IncidentRecord:
    """Correlated security incident written to PostgreSQL and 'incidents:active'."""

    incident_id: str
    incident_reference: str
    rule_id: str
    title: str
    description: str
    severity: str  # critical | high | medium | low
    status: str = "open"
    affected_assets: List[str] = field(default_factory=list)
    affected_zones: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactic: str = ""
    attack_scenario: str = ""
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    evidence: List[str] = field(default_factory=list)  # list of related event_ids
    evidence_details: List[Dict[str, Any]] = field(default_factory=list)
    ot_safety_flag: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _is_external_ip(ip_str: Optional[str]) -> bool:
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except ValueError:
        return False


def _infer_vlan_from_ip(ip_str: Optional[str]) -> Optional[int]:
    if not ip_str:
        return None
    parts = ip_str.strip().split(".")
    if len(parts) == 4 and parts[0] == "10" and parts[1] == "10":
        try:
            vlan = int(parts[2])
            if vlan in VLAN_ZONE_MAP:
                return vlan
        except ValueError:
            pass
    if len(parts) == 4 and parts[0] == "172" and parts[1] == "20":
        try:
            vlan = int(parts[2])
            if vlan in VLAN_ZONE_MAP:
                return vlan
        except ValueError:
            pass
    return None


def _parse_ts(ts: Any) -> datetime:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, str):
        try:
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


class CorrelationEngine:
    """
    Central multi-stream threat correlation engine implementing all 10 BECPL
    systemic correlation rules, sliding time windows, and incident deduplication.
    """

    def __init__(
        self,
        db_client: Any = None,
        redis_client: Any = None,
        assets_path: Optional[Path | str] = None,
        comm_matrix_path: Optional[Path | str] = None,
        window_minutes: int = 30,
        max_retention_minutes: int = 60,
    ) -> None:
        self.db_client = db_client
        self.redis_client = redis_client
        self.window = timedelta(minutes=window_minutes)
        self.max_retention = timedelta(minutes=max(max_retention_minutes, window_minutes))

        # Sliding event buffer keyed by (zone, asset_id)
        self._buffer: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        # Global recent events list for cross-asset/vendor/service-account sequences
        self._global_events: List[Dict[str, Any]] = []

        # Open & historical incidents keyed by incident_id
        self.incidents: Dict[str, IncidentRecord] = {}
        self._incident_seq: int = 0

        # Static topology metadata for allowlists & asset criticality
        self.assets: Dict[str, Dict[str, Any]] = {}
        self.approved_it_ot_pairs: Set[Tuple[str, str]] = set()
        self.approved_modbus_sources: Set[str] = {
            "OT-SCADA-GW01",
            "OT-SCADA-01",
            "OT-HMI-SMTA-01",
            "OT-HMI-SMTB-01",
            "OT-HMI-THT-01",
            "OT-HMI-01",
            "OT-ENV-SENS-01",
        }
        self._load_topology(
            Path(assets_path) if assets_path else DEFAULT_ASSETS_PATH,
            Path(comm_matrix_path) if comm_matrix_path else DEFAULT_COMM_MATRIX_PATH,
        )

    def _load_topology(self, assets_path: Path, comm_matrix_path: Path) -> None:
        if assets_path.exists():
            try:
                for asset in json.loads(assets_path.read_text(encoding="utf-8")):
                    aid = asset.get("asset_id")
                    if aid:
                        self.assets[aid] = asset
            except Exception as exc:
                logger.warning("Could not load assets.json: %s", exc)

        if comm_matrix_path.exists():
            try:
                for rule in json.loads(comm_matrix_path.read_text(encoding="utf-8")):
                    action = str(rule.get("action", "")).upper()
                    if action not in ("ALLOW", "RESTRICT"):
                        continue
                    src = str(rule.get("source", ""))
                    dst = str(rule.get("destination", ""))
                    if src and dst:
                        self.approved_it_ot_pairs.add((src, dst))
                        if str(rule.get("protocol", "")).lower() == "modbus" or rule.get("port") == 502:
                            self.approved_modbus_sources.add(src)
            except Exception as exc:
                logger.warning("Could not load communication_matrix.json: %s", exc)

    # ------------------------------------------------------------------
    # Event Buffering & Pruning
    # ------------------------------------------------------------------
    def _normalize_event(self, stream: str, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        ev = dict(raw_event)
        ev["_stream"] = stream
        ev["_ts"] = _parse_ts(ev.get("timestamp"))
        if not ev.get("event_id"):
            ev["event_id"] = str(uuid.uuid4())
        else:
            ev["event_id"] = str(ev["event_id"])

        src_asset = ev.get("source_asset_id") or ev.get("source_asset") or ev.get("asset_id")
        dst_asset = ev.get("destination_asset_id") or ev.get("destination_asset") or ev.get("target_asset_id")
        ev["source_asset_id"] = src_asset
        ev["destination_asset_id"] = dst_asset

        src_vlan = ev.get("source_vlan")
        if src_vlan is None and src_asset and src_asset in self.assets:
            src_vlan = self.assets[src_asset].get("vlan")
        if src_vlan is None:
            src_vlan = _infer_vlan_from_ip(ev.get("source_ip"))
        ev["source_vlan"] = src_vlan

        dst_vlan = ev.get("destination_vlan")
        if dst_vlan is None and dst_asset and dst_asset in self.assets:
            dst_vlan = self.assets[dst_asset].get("vlan")
        if dst_vlan is None:
            dst_vlan = _infer_vlan_from_ip(ev.get("destination_ip"))
        if dst_vlan is None and isinstance(dst_asset, str) and dst_asset.upper().startswith("OT-"):
            dst_vlan = 30
        ev["destination_vlan"] = dst_vlan

        zone = (
            ev.get("network_zone")
            or VLAN_ZONE_MAP.get(src_vlan)
            or VLAN_ZONE_MAP.get(dst_vlan)
            or "Unknown"
        )
        ev["network_zone"] = zone
        return ev

    def _prune_buffers(self, now: datetime) -> None:
        cutoff = now - self.max_retention
        self._global_events = [e for e in self._global_events if e["_ts"] >= cutoff]
        for key in list(self._buffer.keys()):
            kept = [e for e in self._buffer[key] if e["_ts"] >= cutoff]
            if kept:
                self._buffer[key] = kept
            else:
                del self._buffer[key]

    def _record_event(self, ev: Dict[str, Any]) -> None:
        now = ev["_ts"]
        self._prune_buffers(now)
        self._global_events.append(ev)

        zone = ev.get("network_zone", "Unknown")
        primary_asset = ev.get("source_asset_id") or ev.get("destination_asset_id") or "GLOBAL"
        self._buffer.setdefault((zone, str(primary_asset)), []).append(ev)

    def _events_within(
        self, reference_ts: datetime, minutes: int
    ) -> List[Dict[str, Any]]:
        start = reference_ts - timedelta(minutes=minutes)
        return [e for e in self._global_events if start <= e["_ts"] <= reference_ts]

    # ------------------------------------------------------------------
    # Public Ingestion Entrypoint
    # ------------------------------------------------------------------
    def ingest_event(self, stream: str, event: Dict[str, Any]) -> List[IncidentRecord]:
        """
        Ingest a single detection/intelligence event from any of the 8 streams,
        buffer it, evaluate all 10 correlation rules, and return any created or
        updated IncidentRecords.
        """
        ev = self._normalize_event(stream, event)
        self._record_event(ev)

        triggered: List[IncidentRecord] = []
        rule_checks = (
            self._check_rule_corp_001,
            self._check_rule_corp_002,
            self._check_rule_corp_003,
            self._check_rule_eng_001,
            self._check_rule_vendor_001,
            self._check_rule_vendor_002,
            self._check_rule_ot_001,
            self._check_rule_ot_002,
            self._check_rule_exfil_001,
            self._check_rule_scan_001,
        )

        for check in rule_checks:
            match = check(ev)
            if match is not None:
                incident = self._upsert_incident(match)
                triggered.append(incident)

        return triggered

    # ------------------------------------------------------------------
    # Correlation Rules (10 Rules)
    # ------------------------------------------------------------------

    # RULE-CORP-001: Lateral Movement Campaign
    def _check_rule_corp_001(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        src = ev.get("source_asset_id")
        if not src:
            return None
        recent = self._events_within(ev["_ts"], minutes=10)
        same_src = [
            e
            for e in recent
            if e.get("source_asset_id") == src
            and e.get("destination_asset_id")
            and e.get("destination_asset_id") != src
        ]
        distinct_targets = sorted({str(e["destination_asset_id"]) for e in same_src})
        if len(distinct_targets) < 3:
            return None

        return {
            "rule_id": "RULE-CORP-001",
            "title": f"Lateral Movement Campaign from {src}",
            "description": (
                f"Source asset {src} connected to {len(distinct_targets)} distinct internal targets "
                f"({', '.join(distinct_targets)}) within 10 minutes."
            ),
            "severity": "high",
            "attack_scenario": "SCN-003_lateral_movement",
            "mitre_tactic": "Lateral Movement",
            "mitre_techniques": ["T1021"],
            "affected_assets": sorted({str(src), *distinct_targets}),
            "events": same_src,
            "ot_safety_flag": any(t.upper().startswith("OT-") for t in distinct_targets),
        }

    # RULE-CORP-002: Credential Compromise + Movement
    def _check_rule_corp_002(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        recent = self._events_within(ev["_ts"], minutes=30)
        identity_anoms = [
            e
            for e in recent
            if (
                e.get("event_type") == "identity_anomaly"
                or e.get("_stream") == "detections:identity"
                or e.get("indicator_type") in ("off_hours", "impossible_travel", "identity_anomaly")
            )
            and (
                e.get("anomaly_type") in ("off_hours", "impossible_travel")
                or e.get("indicator_type") in ("off_hours", "impossible_travel")
                or e.get("off_hours")
                or e.get("impossible_travel")
            )
        ]
        net_anoms = [
            e
            for e in recent
            if (
                e.get("event_type") == "network_anomaly"
                or e.get("_stream") == "detections:anomaly"
                or e.get("indicator_type") == "new_destination"
            )
            and (
                e.get("anomaly_type") == "new_destination"
                or e.get("indicator_type") == "new_destination"
                or e.get("new_destination")
            )
        ]
        if not identity_anoms or not net_anoms:
            return None

        # Correlate by shared asset or shared identity
        for id_ev in identity_anoms:
            for net_ev in net_anoms:
                same_asset = (
                    id_ev.get("source_asset_id")
                    and id_ev.get("source_asset_id") == net_ev.get("source_asset_id")
                )
                same_identity = (
                    id_ev.get("identity")
                    and id_ev.get("identity") == net_ev.get("identity")
                ) or (
                    id_ev.get("principal_name")
                    and id_ev.get("principal_name") == net_ev.get("principal_name")
                )
                if same_asset or same_identity:
                    assets = sorted(
                        {
                            str(a)
                            for a in (
                                id_ev.get("source_asset_id"),
                                net_ev.get("source_asset_id"),
                                net_ev.get("destination_asset_id"),
                            )
                            if a
                        }
                    )
                    return {
                        "rule_id": "RULE-CORP-002",
                        "title": "Credential Compromise Followed by Unusual Network Movement",
                        "description": (
                            "Identity anomaly (off-hours or impossible travel) correlated with "
                            "a new network destination within 30 minutes."
                        ),
                        "severity": "high",
                        "attack_scenario": "credential_compromise_movement",
                        "mitre_tactic": "Credential Access / Lateral Movement",
                        "mitre_techniques": ["T1078", "T1021"],
                        "affected_assets": assets,
                        "events": [id_ev, net_ev],
                        "ot_safety_flag": False,
                    }
        return None

    # RULE-CORP-003: LOTL Execution Chain
    def _check_rule_corp_003(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        host = ev.get("source_asset_id")
        if not host:
            return None
        recent = self._events_within(ev["_ts"], minutes=15)
        lotl_events = [
            e
            for e in recent
            if e.get("source_asset_id") == host
            and (
                e.get("_stream") == "detections:lotl"
                or e.get("event_type") == "lotl_indicator"
                or e.get("indicator_type") == "lotl_indicator"
            )
        ]
        ext_conns = [
            e
            for e in recent
            if e.get("source_asset_id") == host
            and (
                e.get("is_external")
                or e.get("event_type") == "network_connection_to_external"
                or _is_external_ip(e.get("destination_ip"))
            )
        ]
        if not lotl_events or not ext_conns:
            return None

        return {
            "rule_id": "RULE-CORP-003",
            "title": f"Living-off-the-Land (LOTL) Execution Chain on {host}",
            "description": (
                f"LOTL tool/script execution indicator on {host} correlated with external "
                f"network egress within 15 minutes."
            ),
            "severity": "high",
            "attack_scenario": "SCN-004_lotl",
            "mitre_tactic": "Execution / Exfiltration",
            "mitre_techniques": ["T1059", "T1041"],
            "affected_assets": [str(host)],
            "events": lotl_events + ext_conns,
            "ot_safety_flag": False,
        }

    # RULE-ENG-001: Firmware Exfiltration Attempt
    def _check_rule_eng_001(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        src = ev.get("source_asset_id")
        if not src:
            return None
        recent = self._events_within(ev["_ts"], minutes=30)
        fw_access = [
            e
            for e in recent
            if e.get("source_asset_id") == src
            and (
                (e.get("destination_vlan") == 20 and int(e.get("destination_port") or e.get("dst_port") or 0) == 3000)
                or e.get("firmware_repo_access") is True
                or (
                    str(e.get("destination_asset_id", "")).upper() in ("ENG-GITSVR-01", "ENG-GIT-01", "FIRMWARE-STORAGE")
                    and int(e.get("destination_port") or e.get("dst_port") or 0) == 3000
                )
            )
        ]
        enc_anoms = [
            e
            for e in recent
            if e.get("source_asset_id") == src
            and (
                e.get("_stream") == "detections:encrypted_traffic"
                or e.get("event_type") == "encrypted_traffic_anomaly"
                or e.get("indicator_type") == "encrypted_traffic_anomaly"
            )
        ]
        if not fw_access or not enc_anoms:
            return None

        assets = sorted(
            {
                str(a)
                for a in [src] + [e.get("destination_asset_id") for e in fw_access]
                if a
            }
        )
        return {
            "rule_id": "RULE-ENG-001",
            "title": f"Critical Firmware Exfiltration Attempt from {src}",
            "description": (
                f"Asset {src} accessed the Engineering firmware repository (VLAN 20, port 3000) "
                f"and subsequently exhibited encrypted traffic anomalies indicating firmware IP theft."
            ),
            "severity": "critical",
            "attack_scenario": "firmware_ip_exfiltration",
            "mitre_tactic": "Exfiltration",
            "mitre_techniques": ["T1048"],
            "affected_assets": assets,
            "events": fw_access + enc_anoms,
            "ot_safety_flag": False,
        }

    # RULE-VENDOR-001: Vendor Compromise Chain (Phase 1 Scenario 1)
    def _check_rule_vendor_001(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        recent = self._events_within(ev["_ts"], minutes=60)
        vendor_key = ev.get("vendor_id") or ev.get("identity") or ev.get("source_asset_id")
        if not vendor_key:
            return None

        def _matches_actor(e: Dict[str, Any]) -> bool:
            return vendor_key in (
                e.get("vendor_id"),
                e.get("identity"),
                e.get("principal_name"),
                e.get("source_asset_id"),
            )

        actor_events = [e for e in recent if _matches_actor(e)]
        auth_anoms = [
            e
            for e in actor_events
            if e.get("indicator_type") == "vendor_auth_anomaly"
            or e.get("event_type") == "vendor_auth_anomaly"
        ]
        res_anoms = [
            e
            for e in actor_events
            if e.get("indicator_type") == "unexpected_resource_access"
            or e.get("event_type") == "unexpected_resource_access"
        ]
        cross_vlan = [
            e
            for e in actor_events
            if e.get("indicator_type") in ("cross_vlan_access", "unexpected_cross_it_ot_boundary")
            or e.get("event_type") == "cross_vlan_access"
            or e.get("cross_vlan_access") is True
            or (
                e.get("source_vlan") is not None
                and e.get("destination_vlan") is not None
                and e.get("source_vlan") != e.get("destination_vlan")
                and e.get("policy_violation") is True
            )
        ]
        if not (auth_anoms and res_anoms and cross_vlan):
            return None

        # Verify sequence order: auth <= resource <= cross_vlan within 60 min
        t_auth = min(e["_ts"] for e in auth_anoms)
        res_after = [e for e in res_anoms if e["_ts"] >= t_auth]
        if not res_after:
            return None
        t_res = min(e["_ts"] for e in res_after)
        cross_after = [e for e in cross_vlan if e["_ts"] >= t_res]
        if not cross_after:
            return None

        chain_events = [auth_anoms[0], res_after[0], cross_after[0]]
        assets = sorted(
            {
                str(a)
                for e in chain_events
                for a in (e.get("source_asset_id"), e.get("destination_asset_id"))
                if a
            }
        )
        return {
            "rule_id": "RULE-VENDOR-001",
            "title": f"Vendor Compromise Chain Detected ({vendor_key})",
            "description": (
                f"Sequential vendor compromise indicators for {vendor_key} within 60 minutes: "
                "vendor authentication anomaly -> unexpected resource access -> cross-VLAN access."
            ),
            "severity": "high",
            "attack_scenario": "SCN-001_vendor_compromise",
            "mitre_tactic": "Initial Access / Lateral Movement",
            "mitre_techniques": ["T1199"],
            "affected_assets": assets or [str(vendor_key)],
            "events": chain_events,
            "ot_safety_flag": any(e.get("destination_vlan") == 30 for e in chain_events),
        }

    # RULE-VENDOR-002: Service Account Misuse (Phase 1 Scenario 2)
    def _check_rule_vendor_002(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        recent = self._events_within(ev["_ts"], minutes=30)
        actor = ev.get("identity") or ev.get("principal_name") or ev.get("source_asset_id")
        if not actor:
            return None

        def _same_svc(e: Dict[str, Any]) -> bool:
            return actor in (
                e.get("identity"),
                e.get("principal_name"),
                e.get("source_asset_id"),
            )

        svc_events = [e for e in recent if _same_svc(e)]
        svc_anoms = [
            e
            for e in svc_events
            if e.get("indicator_type") == "service_account_anomaly"
            or e.get("event_type") == "service_account_anomaly"
        ]
        api_anoms = [
            e
            for e in svc_events
            if e.get("indicator_type") == "unusual_api_activity"
            or e.get("event_type") == "unusual_api_activity"
        ]
        ext_conns = [
            e
            for e in svc_events
            if e.get("event_type") == "external_connection"
            or e.get("indicator_type") == "external_connection"
            or e.get("is_external") is True
            or _is_external_ip(e.get("destination_ip"))
        ]
        if not (svc_anoms and api_anoms and ext_conns):
            return None

        chain = [svc_anoms[0], api_anoms[0], ext_conns[0]]
        assets = sorted(
            {
                str(a)
                for e in chain
                for a in (e.get("source_asset_id"), e.get("destination_asset_id"))
                if a
            }
        )
        return {
            "rule_id": "RULE-VENDOR-002",
            "title": f"Service Account Misuse Chain ({actor})",
            "description": (
                f"Service account {actor} exhibited anomalous operations, unusual API call volume, "
                "and outbound external connectivity."
            ),
            "severity": "high",
            "attack_scenario": "SCN-002_service_misuse",
            "mitre_tactic": "Persistence / Exfiltration",
            "mitre_techniques": ["T1078.002"],
            "affected_assets": assets or [str(actor)],
            "events": chain,
            "ot_safety_flag": False,
        }

    # RULE-OT-001: Unauthorized OT Access (Phase 1 Scenario 6)
    def _check_rule_ot_001(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        protocol = str(ev.get("protocol", "")).lower()
        dst_port = ev.get("destination_port") or ev.get("dst_port")
        is_modbus = protocol == "modbus" or (dst_port is not None and int(dst_port) == 502)
        if not is_modbus:
            return None

        fc = ev.get("modbus_function_code") or ev.get("function_code")
        try:
            fc_int = int(fc) if fc is not None else None
        except (TypeError, ValueError):
            fc_int = None

        is_write_op = fc_int in MODBUS_CRITICAL_WRITE_FCS or bool(ev.get("is_modbus_write", False))
        if not is_write_op:
            return None

        src_asset = str(ev.get("source_asset_id") or "")
        src_vlan = ev.get("source_vlan")
        is_approved_source = (
            src_vlan == 30 and src_asset in self.approved_modbus_sources
        ) or (src_asset in self.approved_modbus_sources and ev.get("approved_engineering") is True)

        if is_approved_source:
            return None

        dst_asset = str(ev.get("destination_asset_id") or "OT-PLC-UNKNOWN")
        assets = sorted({a for a in (src_asset, dst_asset) if a})
        return {
            "rule_id": "RULE-OT-001",
            "title": f"CRITICAL: Unauthorized Modbus Write (FC{fc_int}) to {dst_asset}",
            "description": (
                f"Unauthorized Modbus write operation (FC{fc_int}) targeting OT asset {dst_asset} "
                f"from non-approved source {src_asset or ev.get('source_ip')} (VLAN {src_vlan}). "
                "OT safety flag raised — mandatory human review required before containment."
            ),
            "severity": "critical",
            "attack_scenario": "SCN-006_ot_anomaly",
            "mitre_tactic": "Impair Process Control (ICS)",
            "mitre_techniques": ["T0855"],
            "affected_assets": assets,
            "events": [ev],
            "ot_safety_flag": True,
        }

    # RULE-OT-002: IT-to-OT Communication
    def _check_rule_ot_002(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        src_vlan = ev.get("source_vlan")
        dst_vlan = ev.get("destination_vlan")
        if src_vlan not in (10, 20) or dst_vlan != 30:
            return None

        src_asset = str(ev.get("source_asset_id") or "")
        dst_asset = str(ev.get("destination_asset_id") or "")
        if (src_asset, dst_asset) in self.approved_it_ot_pairs and not ev.get("firewall_violation"):
            return None

        assets = sorted({a for a in (src_asset, dst_asset) if a})
        return {
            "rule_id": "RULE-OT-002",
            "title": f"Unapproved IT-to-OT Communication (VLAN {src_vlan} -> VLAN 30)",
            "description": (
                f"Unapproved connection from {src_asset or ev.get('source_ip')} (VLAN {src_vlan}) "
                f"to OT asset {dst_asset or ev.get('destination_ip')} (VLAN 30) violating IT/OT segmentation policy."
            ),
            "severity": "high",
            "attack_scenario": "it_to_ot_segmentation_violation",
            "mitre_tactic": "Lateral Movement (ICS)",
            "mitre_techniques": ["T0886"],
            "affected_assets": assets,
            "events": [ev],
            "ot_safety_flag": True,
        }

    # RULE-EXFIL-001: Data Exfiltration (Phase 1 Scenario 5)
    def _check_rule_exfil_001(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        is_enc_anom = (
            ev.get("_stream") == "detections:encrypted_traffic"
            or ev.get("event_type") == "encrypted_traffic_anomaly"
            or ev.get("indicator_type") == "encrypted_traffic_anomaly"
        )
        if not is_enc_anom:
            return None

        upload_ratio = float(ev.get("upload_ratio", 0.0))
        high_upload = bool(ev.get("high_upload_ratio")) or upload_ratio >= 0.75

        bytes_out = int(ev.get("bytes_out") or ev.get("bytes_transferred") or 0)
        large_volume = bool(ev.get("large_volume")) or bytes_out >= 50_000_000

        src_asset = str(ev.get("source_asset_id") or "")
        asset_crit = str(
            ev.get("asset_criticality")
            or self.assets.get(src_asset, {}).get("criticality", "medium")
        ).lower()
        is_critical_asset = bool(ev.get("critical_asset")) or asset_crit == "critical"

        hour = ev["_ts"].hour
        unusual_time = bool(ev.get("unusual_time")) or (hour < 7 or hour >= 21)

        if not (high_upload and large_volume and is_critical_asset and unusual_time):
            return None

        return {
            "rule_id": "RULE-EXFIL-001",
            "title": f"Encrypted Data Exfiltration Suspected from Critical Asset {src_asset}",
            "description": (
                f"Critical asset {src_asset} exhibited high upload ratio ({upload_ratio:.2f}) and "
                f"large encrypted transfer ({bytes_out} bytes) during unusual hours (hour {hour:02d})."
            ),
            "severity": "high",
            "attack_scenario": "SCN-005_encrypted_exfil",
            "mitre_tactic": "Exfiltration",
            "mitre_techniques": ["T1048.002"],
            "affected_assets": [src_asset] if src_asset else [],
            "events": [ev],
            "ot_safety_flag": src_asset.upper().startswith("OT-"),
        }

    # RULE-SCAN-001: Reconnaissance and Vulnerability Scan (Phase 1 Scenario 7)
    def _check_rule_scan_001(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        recent = self._events_within(ev["_ts"], minutes=30)
        scan_events = [
            e
            for e in recent
            if e.get("event_type") == "port_scan_pattern"
            or e.get("indicator_type") == "port_scan_pattern"
            or int(e.get("distinct_ports_scanned", 0)) >= 10
        ]
        # Also detect raw multi-port scan across buffered flows targeting same destination
        dst = ev.get("destination_asset_id")
        if not scan_events and dst:
            target_flows = [
                e
                for e in recent
                if e.get("destination_asset_id") == dst
                and (e.get("destination_port") or e.get("dst_port")) is not None
            ]
            distinct_ports = {
                int(e.get("destination_port") or e.get("dst_port")) for e in target_flows
            }
            if len(distinct_ports) >= 10:
                scan_events = target_flows

        vuln_events = [
            e
            for e in recent
            if (
                e.get("_stream") in ("intel:exploitation", "intel:vulnerabilities")
                or e.get("cve_id")
                or e.get("cve_matched")
            )
        ]
        if not scan_events or not vuln_events:
            return None

        # Correlate scan target with vulnerable asset
        for scan_ev in scan_events:
            target = scan_ev.get("destination_asset_id")
            for vuln_ev in vuln_events:
                vuln_asset = vuln_ev.get("asset_id") or vuln_ev.get("destination_asset_id")
                if target and vuln_asset and target == vuln_asset:
                    is_kev = bool(vuln_ev.get("is_kev", False))
                    severity = "high" if is_kev else "medium"
                    cve_id = vuln_ev.get("cve_id", "UNKNOWN-CVE")
                    assets = sorted(
                        {
                            str(a)
                            for a in (scan_ev.get("source_asset_id"), target)
                            if a
                        }
                    )
                    return {
                        "rule_id": "RULE-SCAN-001",
                        "title": f"Reconnaissance Scan Targeting Vulnerable Asset {target} ({cve_id})",
                        "description": (
                            f"Port scan activity against {target} correlated with known vulnerability "
                            f"{cve_id} ({'CISA KEV - escalated to HIGH' if is_kev else 'non-KEV'})."
                        ),
                        "severity": severity,
                        "attack_scenario": "SCN-007_vuln_scan",
                        "mitre_tactic": "Discovery",
                        "mitre_techniques": ["T1046"],
                        "affected_assets": assets,
                        "events": [scan_ev, vuln_ev],
                        "ot_safety_flag": str(target).upper().startswith("OT-"),
                    }
        return None

    # ------------------------------------------------------------------
    # Incident Deduplication, Creation & Emission
    # ------------------------------------------------------------------
    def _next_incident_reference(self, ts: datetime) -> str:
        self._incident_seq += 1
        return f"INC-{ts.year}-{self._incident_seq:03d}"

    def _find_matching_open_incident(
        self, affected_assets: List[str], mitre_techniques: List[str], rule_id: str
    ) -> Optional[IncidentRecord]:
        """
        Deduplication check: match an OPEN incident with overlapping/same affected assets
        and matching MITRE technique (or same rule_id).
        """
        target_assets = set(affected_assets)
        target_mitre = set(mitre_techniques)
        for inc in self.incidents.values():
            if inc.status != "open":
                continue
            inc_assets = set(inc.affected_assets)
            inc_mitre = set(inc.mitre_techniques)
            if inc_assets == target_assets and (
                (target_mitre and bool(inc_mitre & target_mitre)) or inc.rule_id == rule_id
            ):
                return inc
        return None

    def _upsert_incident(self, match: Dict[str, Any]) -> IncidentRecord:
        events = match.get("events", [])
        event_ids = [str(e["event_id"]) for e in events if e.get("event_id")]
        timestamps = [e["_ts"] for e in events if isinstance(e.get("_ts"), datetime)]
        first_ts = min(timestamps) if timestamps else datetime.now(timezone.utc)
        last_ts = max(timestamps) if timestamps else first_ts

        affected_assets = match.get("affected_assets", [])
        mitre_techniques = match.get("mitre_techniques", [])
        affected_zones = sorted(
            {
                str(e.get("network_zone"))
                for e in events
                if e.get("network_zone") and e.get("network_zone") != "Unknown"
            }
            | {
                VLAN_ZONE_MAP[self.assets[a]["vlan"]]
                for a in affected_assets
                if a in self.assets and self.assets[a].get("vlan") in VLAN_ZONE_MAP
            }
        )

        existing = self._find_matching_open_incident(
            affected_assets, mitre_techniques, match["rule_id"]
        )
        if existing is not None:
            for eid in event_ids:
                if eid not in existing.evidence:
                    existing.evidence.append(eid)
            for ev in events:
                if ev["event_id"] not in {d.get("event_id") for d in existing.evidence_details}:
                    existing.evidence_details.append(self._serialize_event_summary(ev))
            existing.last_seen = max(existing.last_seen, last_ts.isoformat())
            for zone in affected_zones:
                if zone not in existing.affected_zones:
                    existing.affected_zones.append(zone)
            if match.get("ot_safety_flag"):
                existing.ot_safety_flag = True
            self._emit_incident_sync(existing, is_update=True)
            return existing

        incident = IncidentRecord(
            incident_id=str(uuid.uuid4()),
            incident_reference=self._next_incident_reference(first_ts),
            rule_id=match["rule_id"],
            title=match["title"],
            description=match["description"],
            severity=match["severity"],
            status="open",
            affected_assets=affected_assets,
            affected_zones=affected_zones,
            mitre_techniques=mitre_techniques,
            mitre_tactic=match.get("mitre_tactic", ""),
            attack_scenario=match.get("attack_scenario", ""),
            first_seen=first_ts.isoformat(),
            last_seen=last_ts.isoformat(),
            evidence=list(dict.fromkeys(event_ids)),
            evidence_details=[self._serialize_event_summary(e) for e in events],
            ot_safety_flag=bool(match.get("ot_safety_flag", False)),
        )
        self.incidents[incident.incident_id] = incident
        self._emit_incident_sync(incident, is_update=False)
        return incident

    @staticmethod
    def _serialize_event_summary(ev: Dict[str, Any]) -> Dict[str, Any]:
        return {
            k: v
            for k, v in ev.items()
            if not k.startswith("_")
        }

    def list_open_incidents(self) -> List[IncidentRecord]:
        return [inc for inc in self.incidents.values() if inc.status == "open"]

    # ------------------------------------------------------------------
    # Persistence & Redis Publishing
    # ------------------------------------------------------------------
    def _emit_incident_sync(self, incident: IncidentRecord, is_update: bool) -> None:
        self._publish_redis_sync(incident, is_update=is_update)
        self._persist_incident_sync(incident, is_update=is_update)

    def _publish_redis_sync(self, incident: IncidentRecord, is_update: bool) -> None:
        if self.redis_client is None:
            return
        xadd = getattr(self.redis_client, "xadd", None)
        if xadd is None or inspect.iscoroutinefunction(xadd):
            return
        try:
            xadd(
                REDIS_STREAM_INCIDENTS,
                {
                    "incident_id": incident.incident_id,
                    "incident_reference": incident.incident_reference,
                    "rule_id": incident.rule_id,
                    "severity": incident.severity,
                    "action": "updated" if is_update else "created",
                    "ot_safety_flag": str(incident.ot_safety_flag).lower(),
                    "payload": json.dumps(incident.to_dict()),
                },
            )
        except Exception as exc:
            logger.error("Failed publishing incident to Redis: %s", exc)

    async def publish_incident(self, incident: IncidentRecord, is_update: bool = False) -> None:
        if self.redis_client is None:
            return
        res = self.redis_client.xadd(
            REDIS_STREAM_INCIDENTS,
            {
                "incident_id": incident.incident_id,
                "incident_reference": incident.incident_reference,
                "rule_id": incident.rule_id,
                "severity": incident.severity,
                "action": "updated" if is_update else "created",
                "ot_safety_flag": str(incident.ot_safety_flag).lower(),
                "payload": json.dumps(incident.to_dict()),
            },
        )
        if inspect.isawaitable(res):
            await res

    def _persist_incident_sync(self, incident: IncidentRecord, is_update: bool) -> None:
        if self.db_client is None:
            return
        execute = getattr(self.db_client, "execute", None)
        if execute is None or inspect.iscoroutinefunction(execute):
            return
        try:
            if is_update:
                execute(
                    """
                    UPDATE becpl_nids.incidents
                    SET last_seen = %s, evidence = %s::jsonb, ot_safety_flag = %s
                    WHERE incident_id = %s
                    """,
                    (
                        incident.last_seen,
                        json.dumps(incident.evidence),
                        incident.ot_safety_flag,
                        incident.incident_id,
                    ),
                )
            else:
                execute(
                    """
                    INSERT INTO becpl_nids.incidents (
                        incident_id, incident_reference, rule_id, title, description,
                        severity, status, attack_scenario, mitre_tactic, mitre_technique,
                        mitre_techniques, affected_assets, affected_zones,
                        first_seen, last_seen, evidence, ot_safety_flag
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s
                    )
                    """,
                    (
                        incident.incident_id,
                        incident.incident_reference,
                        incident.rule_id,
                        incident.title,
                        incident.description,
                        incident.severity,
                        incident.status,
                        incident.attack_scenario,
                        incident.mitre_tactic,
                        ",".join(incident.mitre_techniques),
                        incident.mitre_techniques,
                        incident.affected_assets,
                        incident.affected_zones,
                        incident.first_seen,
                        incident.last_seen,
                        json.dumps(incident.evidence),
                        incident.ot_safety_flag,
                    ),
                )
        except Exception as exc:
            logger.error("Failed persisting incident %s: %s", incident.incident_reference, exc)

    async def persist_incident(self, incident: IncidentRecord) -> None:
        """Async upsert of IncidentRecord into PostgreSQL incidents table."""
        if self.db_client is None:
            return
        res = self.db_client.execute(
            """
            INSERT INTO becpl_nids.incidents (
                incident_id, incident_reference, rule_id, title, description,
                severity, status, attack_scenario, mitre_tactic, mitre_technique,
                mitre_techniques, affected_assets, affected_zones,
                first_seen, last_seen, evidence, ot_safety_flag
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb, $17
            )
            ON CONFLICT (incident_id) DO UPDATE SET
                last_seen = EXCLUDED.last_seen,
                evidence = EXCLUDED.evidence,
                ot_safety_flag = EXCLUDED.ot_safety_flag
            """,
            incident.incident_id,
            incident.incident_reference,
            incident.rule_id,
            incident.title,
            incident.description,
            incident.severity,
            incident.status,
            incident.attack_scenario,
            incident.mitre_tactic,
            ",".join(incident.mitre_techniques),
            incident.mitre_techniques,
            incident.affected_assets,
            incident.affected_zones,
            incident.first_seen,
            incident.last_seen,
            json.dumps(incident.evidence),
            incident.ot_safety_flag,
        )
        if inspect.isawaitable(res):
            await res
