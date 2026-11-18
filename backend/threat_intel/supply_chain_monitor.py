"""
VaultX Phase 2 - Third-Party Trust & Supply Chain Security Monitor
BECPL (Bharat Electronics Components Pvt. Ltd.), Pune

Loads third-party trust inventory from PostgreSQL `vendors` + `communication_rules`
(with BECPL default vendor profiles & communication_matrix.json fallback).

Detection capabilities (each produces a VendorAnomalyIndicator as evidence, NOT a standalone alert):
  A. Suspicious vendor authentication (unexpected IP, off-hours, failed MFA)
  B. Unexpected resource access (asset not in permitted_destinations or unapproved port)
  C. Service account misuse (svc_erp_integration doing unexpected operations)
  D. Unusual API activity (> 2x normal API call rate from vendor identity)
  E. Abnormal shared storage access (vendor reading/writing unexpected files)
  F. Unexpected cross IT/OT boundary (vendor connection reaching OT VLAN 30)
  G. Unusual encrypted outbound (large encrypted transfer from vendor-accessed asset)
  H. Cross-system lateral movement (vendor identity seen on multiple internal assets)
  I. Suspicious vendor-originated critical infra access

Publishes indicators to Redis stream 'detections:supply_chain'.
"""

from __future__ import annotations

import inspect
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("vaultx.threat_intel.supply_chain_monitor")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COMM_MATRIX_PATH = REPO_ROOT / "infra" / "topology" / "communication_matrix.json"
REDIS_STREAM_SUPPLY_CHAIN = "detections:supply_chain"

CRITICAL_INFRA_ASSETS: Set[str] = {
    "CORP-DC-01",
    "CORP-DC-02",
    "CORP-BACKUP-01",
    "ENG-GITSVR-01",
    "ENG-GIT-01",
    "ENG-OTA-STG01",
    "OT-SCADA-GW01",
    "OT-SCADA-01",
    "OT-PLC-SMTA-01",
    "OT-PLC-SMTB-01",
    "OT-SMT-PLC01",
    "SEC-VAULT-01",
    "SEC-DB-01",
}


@dataclass
class VendorProfile:
    """Third-party trust boundary definition for a vendor or external partner."""

    vendor_id: str
    vendor_name: str
    vendor_type: str
    approved_identities: List[str] = field(default_factory=list)
    approved_source_ips: List[str] = field(default_factory=list)
    permitted_destinations: List[str] = field(default_factory=list)
    permitted_ports: List[int] = field(default_factory=list)
    allowed_vlans: List[int] = field(default_factory=list)
    authorised_time_windows: List[Tuple[int, int]] = field(
        default_factory=lambda: [(8, 20)]
    )  # list of (start_hour_24, end_hour_24)
    mfa_required: bool = True
    expected_patterns: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VendorAnomalyIndicator:
    """Supply chain evidence indicator (fed to correlation engine, not standalone incident)."""

    indicator_id: str
    vendor_id: str
    indicator_type: str
    evidence: Dict[str, Any]
    severity: str
    suppress_if_approved_maintenance: bool = False
    suppressed: bool = False
    identity: Optional[str] = None
    source_asset_id: Optional[str] = None
    destination_asset_id: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _default_becpl_vendor_profiles() -> List[VendorProfile]:
    """Seed vendor trust profiles aligned with BECPL database/schema/05_seed_data.sql."""
    return [
        VendorProfile(
            vendor_id="VEND-001",
            vendor_name="Shenzhen Precision Microelectronics Co.",
            vendor_type="component_supplier",
            approved_identities=["vendor_sz_micro", "svc_edi_supplier"],
            approved_source_ips=["203.0.113.10", "10.10.50.10"],
            permitted_destinations=["CLOUD-GW-01", "DMZ-VEND-PORTAL"],
            permitted_ports=[443],
            allowed_vlans=[50, 60],
            authorised_time_windows=[(8, 20)],
            mfa_required=True,
            expected_patterns={
                "baseline_api_rpm": 20.0,
                "permitted_storage_paths": ["/edi/inbound", "/datasheets"],
                "max_outbound_bytes": 25_000_000,
                "permitted_service_operations": ["read_po", "sync_datasheet"],
            },
        ),
        VendorProfile(
            vendor_id="VEND-002",
            vendor_name="Yamaha SMT Machine Automation Services",
            vendor_type="maintenance_vendor",
            approved_identities=["vendor_yamaha_smt", "VEND-ID-SIEMENS"],
            approved_source_ips=["198.51.100.22", "10.10.50.101"],
            permitted_destinations=["DMZ-BASTION-01", "DMZ-JUMP-01", "OT-SCADA-GW01"],
            permitted_ports=[22, 443, 3389],
            allowed_vlans=[50],  # VLAN 30 only during approved maintenance
            authorised_time_windows=[(9, 18)],
            mfa_required=True,
            expected_patterns={
                "baseline_api_rpm": 10.0,
                "permitted_storage_paths": ["/diagnostics/smt"],
                "max_outbound_bytes": 50_000_000,
                "ot_access_requires_maintenance": True,
            },
        ),
        VendorProfile(
            vendor_id="VEND-003",
            vendor_name="BlueDart Express Ltd - Pune Logistics Gateway",
            vendor_type="logistics",
            approved_identities=["vendor_bluedart_api", "svc_erp_integration"],
            approved_source_ips=["198.51.100.33", "10.10.60.10"],
            permitted_destinations=["WH-SRV-01", "CORP-ERP-01", "CLOUD-GW-01"],
            permitted_ports=[443, 8443],
            allowed_vlans=[40, 60],
            authorised_time_windows=[(6, 22)],
            mfa_required=True,
            expected_patterns={
                "baseline_api_rpm": 60.0,
                "permitted_storage_paths": ["/manifests", "/shipping_labels"],
                "max_outbound_bytes": 30_000_000,
                "permitted_service_operations": [
                    "sync_manifest",
                    "push_tracking",
                    "query_dispatch",
                ],
            },
        ),
        VendorProfile(
            vendor_id="VEND-004",
            vendor_name="CloudOps Pune Consultancy Services",
            vendor_type="cloud",
            approved_identities=["vendor_cloudops", "VEND-ID-NETSOLVE"],
            approved_source_ips=["203.0.113.44", "10.10.50.103"],
            permitted_destinations=["CLOUD-GW-01", "DMZ-BASTION-01"],
            permitted_ports=[22, 443],
            allowed_vlans=[50, 60],
            authorised_time_windows=[(9, 19)],
            mfa_required=True,
            expected_patterns={
                "baseline_api_rpm": 30.0,
                "permitted_storage_paths": ["/backups/metadata"],
                "max_outbound_bytes": 100_000_000,
            },
        ),
        VendorProfile(
            vendor_id="VEND-005",
            vendor_name="HexaCore Embedded Firmware Labs",
            vendor_type="dev_service",
            approved_identities=["vendor_hexacore_dev", "VEND-ID-CODEBRIDGE"],
            approved_source_ips=["203.0.113.55", "10.10.50.102"],
            permitted_destinations=["DMZ-BASTION-01", "ENG-GITSVR-01", "ENG-GIT-01"],
            permitted_ports=[22, 443],
            allowed_vlans=[20, 50],
            authorised_time_windows=[(9, 20)],
            mfa_required=True,
            expected_patterns={
                "baseline_api_rpm": 40.0,
                "permitted_storage_paths": ["/repos/stm32-sensor"],
                "max_outbound_bytes": 40_000_000,
            },
        ),
    ]


class SupplyChainMonitor:
    """
    Evaluates third-party vendor authentication, resource access, service account usage,
    API rates, storage access, IT/OT boundary crossings, encrypted outbound volume,
    lateral movement, and critical infrastructure access.
    """

    def __init__(
        self,
        db_client: Any = None,
        redis_client: Any = None,
        comm_matrix_path: Optional[Path | str] = None,
        vendors: Optional[List[VendorProfile]] = None,
    ) -> None:
        self.db_client = db_client
        self.redis_client = redis_client
        self.comm_matrix_path = (
            Path(comm_matrix_path) if comm_matrix_path else DEFAULT_COMM_MATRIX_PATH
        )

        self.vendors: Dict[str, VendorProfile] = {}
        self.identity_to_vendor: Dict[str, str] = {}
        # Approved maintenance windows: vendor_id -> list of {start: datetime, end: datetime, allowed_assets: [...]}
        self.maintenance_windows: Dict[str, List[Dict[str, Any]]] = {}
        # Track unique internal assets accessed per vendor identity for lateral movement detection (H)
        self._identity_asset_history: Dict[str, Set[str]] = {}
        # Track assets recently accessed by vendors for outbound encrypted transfer check (G)
        self._vendor_accessed_assets: Dict[str, str] = {}  # asset_id -> vendor_id
        # History of emitted indicators
        self.indicators: List[VendorAnomalyIndicator] = []

        for profile in (vendors if vendors is not None else _default_becpl_vendor_profiles()):
            self.register_vendor(profile)
        self._enrich_from_comm_matrix()

    def register_vendor(self, profile: VendorProfile) -> None:
        self.vendors[profile.vendor_id] = profile
        for ident in profile.approved_identities:
            self.identity_to_vendor[ident.lower()] = profile.vendor_id

    def _enrich_from_comm_matrix(self) -> None:
        """Augment vendor permitted destinations/ports from infra/topology/communication_matrix.json."""
        if not self.comm_matrix_path.exists():
            return
        try:
            rules = json.loads(self.comm_matrix_path.read_text(encoding="utf-8"))
        except Exception:
            return
        for rule in rules:
            if str(rule.get("action", "")).upper() != "ALLOW":
                continue
            src = str(rule.get("source", ""))
            dst = str(rule.get("destination", ""))
            port = rule.get("port")
            vendor_id = self.identity_to_vendor.get(src.lower())
            if vendor_id and vendor_id in self.vendors:
                prof = self.vendors[vendor_id]
                if dst and dst not in prof.permitted_destinations:
                    prof.permitted_destinations.append(dst)
                if isinstance(port, int) and port not in prof.permitted_ports:
                    prof.permitted_ports.append(port)

    async def load_from_db(self) -> int:
        """Load vendors and communication_rules from PostgreSQL if DB client is configured."""
        if self.db_client is None or not hasattr(self.db_client, "fetch"):
            return len(self.vendors)
        rows = await self.db_client.fetch(
            "SELECT vendor_id, vendor_name, vendor_type, allowed_vlans, mfa_required "
            "FROM becpl_nids.vendors WHERE is_active = TRUE"
        )
        for row in rows:
            vid = f"VEND-{int(row['vendor_id']):03d}" if isinstance(row["vendor_id"], int) else str(row["vendor_id"])
            if vid not in self.vendors:
                self.register_vendor(
                    VendorProfile(
                        vendor_id=vid,
                        vendor_name=row["vendor_name"],
                        vendor_type=row.get("vendor_type", "other"),
                        allowed_vlans=list(row.get("allowed_vlans") or []),
                        mfa_required=bool(row.get("mfa_required", True)),
                    )
                )
        return len(self.vendors)

    def resolve_vendor(
        self, vendor_id: Optional[str] = None, identity: Optional[str] = None
    ) -> Optional[VendorProfile]:
        if vendor_id and vendor_id in self.vendors:
            return self.vendors[vendor_id]
        if identity:
            mapped = self.identity_to_vendor.get(identity.lower())
            if mapped:
                return self.vendors.get(mapped)
        return None

    # ------------------------------------------------------------------
    # Maintenance Window Suppression
    # ------------------------------------------------------------------
    def add_maintenance_window(
        self,
        vendor_id: str,
        start: datetime,
        end: datetime,
        allowed_assets: Optional[List[str]] = None,
    ) -> None:
        self.maintenance_windows.setdefault(vendor_id, []).append(
            {
                "start": start,
                "end": end,
                "allowed_assets": set(allowed_assets or []),
            }
        )

    def is_in_approved_maintenance(
        self, vendor_id: str, ts: datetime, destination_asset: Optional[str] = None
    ) -> bool:
        for win in self.maintenance_windows.get(vendor_id, []):
            if win["start"] <= ts <= win["end"]:
                allowed = win["allowed_assets"]
                if not allowed or (destination_asset and destination_asset in allowed):
                    return True
        return False

    @staticmethod
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

    def _emit_indicator(
        self,
        vendor_id: str,
        indicator_type: str,
        evidence: Dict[str, Any],
        severity: str,
        ts: datetime,
        suppress_if_approved_maintenance: bool = False,
        identity: Optional[str] = None,
        source_asset_id: Optional[str] = None,
        destination_asset_id: Optional[str] = None,
    ) -> VendorAnomalyIndicator:
        suppressed = (
            suppress_if_approved_maintenance
            and self.is_in_approved_maintenance(vendor_id, ts, destination_asset_id)
        )
        indicator = VendorAnomalyIndicator(
            indicator_id=str(uuid.uuid4()),
            vendor_id=vendor_id,
            indicator_type=indicator_type,
            evidence=evidence,
            severity=severity,
            suppress_if_approved_maintenance=suppress_if_approved_maintenance,
            suppressed=suppressed,
            identity=identity,
            source_asset_id=source_asset_id,
            destination_asset_id=destination_asset_id,
            timestamp=ts.isoformat(),
        )
        self.indicators.append(indicator)
        if not suppressed:
            self._publish_redis_sync(indicator)
        return indicator

    # ------------------------------------------------------------------
    # Detection Capabilities A - I
    # ------------------------------------------------------------------

    # A. Suspicious vendor authentication
    def check_vendor_authentication(
        self, event: Dict[str, Any]
    ) -> List[VendorAnomalyIndicator]:
        """Detect unexpected IP, off-hours auth, or failed/missing MFA for vendor logins."""
        profile = self.resolve_vendor(event.get("vendor_id"), event.get("identity") or event.get("principal_name"))
        if not profile:
            return []

        ts = self._parse_ts(event.get("timestamp"))
        identity = event.get("identity") or event.get("principal_name")
        src_ip = str(event.get("source_ip", ""))
        mfa_used = event.get("mfa_used")
        mfa_failed = bool(event.get("mfa_failed", False))
        reasons: List[str] = []

        if src_ip and profile.approved_source_ips and src_ip not in profile.approved_source_ips:
            reasons.append(f"unexpected_source_ip:{src_ip}")

        hour = ts.hour
        in_hours = any(start <= hour < end for start, end in profile.authorised_time_windows)
        if not in_hours:
            reasons.append(f"off_hours_auth:hour_{hour:02d}")

        if mfa_failed or (profile.mfa_required and mfa_used is False):
            reasons.append("failed_or_missing_mfa")

        if not reasons:
            return []

        severity = "high" if ("failed_or_missing_mfa" in reasons or len(reasons) >= 2) else "medium"
        ind = self._emit_indicator(
            vendor_id=profile.vendor_id,
            indicator_type="vendor_auth_anomaly",
            evidence={
                "check": "A_suspicious_vendor_auth",
                "reasons": reasons,
                "source_ip": src_ip,
                "auth_hour": hour,
                "authorised_windows": profile.authorised_time_windows,
                "mfa_used": mfa_used,
                "mfa_failed": mfa_failed,
                "event_id": event.get("event_id"),
            },
            severity=severity,
            ts=ts,
            suppress_if_approved_maintenance=("off_hours_auth" in " ".join(reasons) and len(reasons) == 1),
            identity=identity,
            source_asset_id=event.get("source_asset_id"),
            destination_asset_id=event.get("target_asset_id") or event.get("destination_asset_id"),
        )
        return [ind]

    # B, F, H, I. Network/Resource Access Checks
    def check_resource_access(
        self, event: Dict[str, Any]
    ) -> List[VendorAnomalyIndicator]:
        """
        Evaluate vendor resource access for:
        - B. Unexpected resource access (asset not in permitted_destinations or unapproved port)
        - F. Unexpected cross IT/OT boundary (connection reaching VLAN 30)
        - H. Cross-system lateral movement (vendor identity accessing multiple internal assets)
        - I. Suspicious vendor-originated critical infra access
        """
        profile = self.resolve_vendor(event.get("vendor_id"), event.get("identity") or event.get("principal_name"))
        if not profile:
            return []

        ts = self._parse_ts(event.get("timestamp"))
        identity = event.get("identity") or event.get("principal_name") or profile.vendor_id
        src_asset = event.get("source_asset_id") or event.get("source_asset")
        dst_asset = str(event.get("destination_asset_id") or event.get("destination_asset") or "")
        dst_port = event.get("destination_port") or event.get("dst_port")
        dst_vlan = event.get("destination_vlan")

        # Track vendor-touched assets for encrypted outbound correlation (G) and lateral movement (H)
        if dst_asset:
            self._vendor_accessed_assets[dst_asset] = profile.vendor_id
            seen_assets = self._identity_asset_history.setdefault(identity.lower(), set())
            seen_assets.add(dst_asset)

        emitted: List[VendorAnomalyIndicator] = []

        # B. Unexpected resource access
        unapproved_asset = bool(dst_asset and dst_asset not in profile.permitted_destinations)
        unapproved_port = bool(
            dst_port is not None
            and profile.permitted_ports
            and int(dst_port) not in profile.permitted_ports
        )
        if unapproved_asset or unapproved_port:
            emitted.append(
                self._emit_indicator(
                    vendor_id=profile.vendor_id,
                    indicator_type="unexpected_resource_access",
                    evidence={
                        "check": "B_unexpected_resource_access",
                        "destination_asset": dst_asset,
                        "destination_port": dst_port,
                        "permitted_destinations": profile.permitted_destinations,
                        "permitted_ports": profile.permitted_ports,
                        "unapproved_asset": unapproved_asset,
                        "unapproved_port": unapproved_port,
                        "event_id": event.get("event_id"),
                    },
                    severity="high" if unapproved_asset else "medium",
                    ts=ts,
                    suppress_if_approved_maintenance=True,
                    identity=identity,
                    source_asset_id=src_asset,
                    destination_asset_id=dst_asset,
                )
            )

        # F. Unexpected cross IT/OT boundary (VLAN 30)
        is_ot_target = dst_vlan == 30 or dst_asset.upper().startswith("OT-")
        if is_ot_target and 30 not in profile.allowed_vlans:
            emitted.append(
                self._emit_indicator(
                    vendor_id=profile.vendor_id,
                    indicator_type="unexpected_cross_it_ot_boundary",
                    evidence={
                        "check": "F_unexpected_cross_it_ot_boundary",
                        "destination_asset": dst_asset,
                        "destination_vlan": 30,
                        "allowed_vlans": profile.allowed_vlans,
                        "event_id": event.get("event_id"),
                    },
                    severity="critical",
                    ts=ts,
                    suppress_if_approved_maintenance=bool(
                        profile.expected_patterns.get("ot_access_requires_maintenance", False)
                    ),
                    identity=identity,
                    source_asset_id=src_asset,
                    destination_asset_id=dst_asset,
                )
            )

        # H. Cross-system lateral movement (>= 3 distinct internal assets accessed by vendor identity)
        seen_assets = self._identity_asset_history.get(identity.lower(), set())
        unapproved_seen = [a for a in seen_assets if a not in profile.permitted_destinations]
        if len(seen_assets) >= 3 and len(unapproved_seen) >= 1:
            emitted.append(
                self._emit_indicator(
                    vendor_id=profile.vendor_id,
                    indicator_type="cross_system_lateral_movement",
                    evidence={
                        "check": "H_cross_system_lateral_movement",
                        "identity": identity,
                        "assets_accessed": sorted(seen_assets),
                        "unapproved_assets": sorted(unapproved_seen),
                        "event_id": event.get("event_id"),
                    },
                    severity="high",
                    ts=ts,
                    suppress_if_approved_maintenance=False,
                    identity=identity,
                    source_asset_id=src_asset,
                    destination_asset_id=dst_asset,
                )
            )

        # I. Suspicious vendor-originated critical infra access
        if dst_asset in CRITICAL_INFRA_ASSETS and dst_asset not in profile.permitted_destinations:
            emitted.append(
                self._emit_indicator(
                    vendor_id=profile.vendor_id,
                    indicator_type="suspicious_vendor_critical_infra_access",
                    evidence={
                        "check": "I_suspicious_vendor_critical_infra_access",
                        "destination_asset": dst_asset,
                        "event_id": event.get("event_id"),
                    },
                    severity="critical",
                    ts=ts,
                    suppress_if_approved_maintenance=False,
                    identity=identity,
                    source_asset_id=src_asset,
                    destination_asset_id=dst_asset,
                )
            )

        return emitted

    # C. Service account misuse
    def check_service_account_misuse(
        self, event: Dict[str, Any]
    ) -> List[VendorAnomalyIndicator]:
        """Detect unexpected operations by service accounts such as svc_erp_integration."""
        identity = str(event.get("identity") or event.get("principal_name") or "")
        profile = self.resolve_vendor(event.get("vendor_id"), identity)
        if not profile and not identity.lower().startswith("svc_"):
            return []

        ts = self._parse_ts(event.get("timestamp"))
        vendor_id = profile.vendor_id if profile else "VEND-SVC-UNKNOWN"
        permitted_ops = set(
            (profile.expected_patterns if profile else {}).get(
                "permitted_service_operations",
                ["sync_manifest", "push_tracking", "query_dispatch"],
            )
        )
        operation = str(event.get("operation", "")).lower()
        is_interactive = bool(event.get("interactive_shell", False))
        unexpected_op = bool(operation and operation not in permitted_ops)

        if not unexpected_op and not is_interactive:
            return []

        ind = self._emit_indicator(
            vendor_id=vendor_id,
            indicator_type="service_account_anomaly",
            evidence={
                "check": "C_service_account_misuse",
                "identity": identity,
                "operation": operation,
                "permitted_operations": sorted(permitted_ops),
                "interactive_shell": is_interactive,
                "event_id": event.get("event_id"),
            },
            severity="high",
            ts=ts,
            suppress_if_approved_maintenance=False,
            identity=identity,
            source_asset_id=event.get("source_asset_id"),
            destination_asset_id=event.get("destination_asset_id"),
        )
        return [ind]

    # D. Unusual API activity (> 2x normal API call rate)
    def check_api_activity(
        self, event: Dict[str, Any]
    ) -> List[VendorAnomalyIndicator]:
        """Detect API call rate exceeding 2x the vendor identity's normal baseline."""
        profile = self.resolve_vendor(event.get("vendor_id"), event.get("identity") or event.get("principal_name"))
        if not profile:
            return []

        ts = self._parse_ts(event.get("timestamp"))
        baseline_rpm = float(
            event.get("baseline_rpm")
            or profile.expected_patterns.get("baseline_api_rpm", 30.0)
        )
        observed_rpm = float(event.get("observed_rpm") or event.get("api_calls_per_minute", 0.0))

        if baseline_rpm <= 0 or observed_rpm <= 2.0 * baseline_rpm:
            return []

        ratio = round(observed_rpm / baseline_rpm, 2)
        ind = self._emit_indicator(
            vendor_id=profile.vendor_id,
            indicator_type="unusual_api_activity",
            evidence={
                "check": "D_unusual_api_activity",
                "observed_rpm": observed_rpm,
                "baseline_rpm": baseline_rpm,
                "rate_multiplier": ratio,
                "endpoint": event.get("api_endpoint"),
                "event_id": event.get("event_id"),
            },
            severity="high" if ratio >= 4.0 else "medium",
            ts=ts,
            suppress_if_approved_maintenance=True,
            identity=event.get("identity") or event.get("principal_name"),
            source_asset_id=event.get("source_asset_id"),
            destination_asset_id=event.get("destination_asset_id"),
        )
        return [ind]

    # E. Abnormal shared storage access
    def check_shared_storage_access(
        self, event: Dict[str, Any]
    ) -> List[VendorAnomalyIndicator]:
        """Detect vendor reading/writing unexpected files or paths on shared storage."""
        profile = self.resolve_vendor(event.get("vendor_id"), event.get("identity") or event.get("principal_name"))
        if not profile:
            return []

        ts = self._parse_ts(event.get("timestamp"))
        file_path = str(event.get("file_path") or event.get("target_file") or "")
        permitted_paths = profile.expected_patterns.get("permitted_storage_paths", [])
        if not file_path:
            return []

        allowed = any(file_path.startswith(prefix) for prefix in permitted_paths)
        if allowed:
            return []

        ind = self._emit_indicator(
            vendor_id=profile.vendor_id,
            indicator_type="abnormal_shared_storage_access",
            evidence={
                "check": "E_abnormal_shared_storage_access",
                "file_path": file_path,
                "action": event.get("file_action", "read"),
                "permitted_paths": permitted_paths,
                "event_id": event.get("event_id"),
            },
            severity="high",
            ts=ts,
            suppress_if_approved_maintenance=False,
            identity=event.get("identity") or event.get("principal_name"),
            source_asset_id=event.get("source_asset_id"),
            destination_asset_id=event.get("destination_asset_id"),
        )
        return [ind]

    # G. Unusual encrypted outbound from vendor-accessed asset
    def check_encrypted_outbound(
        self, event: Dict[str, Any]
    ) -> List[VendorAnomalyIndicator]:
        """Detect large encrypted outbound transfer from a vendor-accessed asset."""
        src_asset = str(event.get("source_asset_id") or event.get("source_asset") or "")
        vendor_id = event.get("vendor_id") or self._vendor_accessed_assets.get(src_asset)
        profile = self.resolve_vendor(vendor_id, event.get("identity") or event.get("principal_name"))
        if not profile:
            return []

        ts = self._parse_ts(event.get("timestamp"))
        bytes_out = int(event.get("bytes_out") or event.get("bytes_transferred") or 0)
        is_encrypted = bool(event.get("is_encrypted", True))
        threshold = int(profile.expected_patterns.get("max_outbound_bytes", 50_000_000))

        if not is_encrypted or bytes_out <= threshold:
            return []

        ind = self._emit_indicator(
            vendor_id=profile.vendor_id,
            indicator_type="unusual_encrypted_outbound",
            evidence={
                "check": "G_unusual_encrypted_outbound",
                "source_asset": src_asset,
                "destination_ip": event.get("destination_ip"),
                "bytes_out": bytes_out,
                "threshold_bytes": threshold,
                "sni": event.get("sni"),
                "event_id": event.get("event_id"),
            },
            severity="high",
            ts=ts,
            suppress_if_approved_maintenance=False,
            identity=event.get("identity") or event.get("principal_name"),
            source_asset_id=src_asset,
            destination_asset_id=event.get("destination_asset_id"),
        )
        return [ind]

    def evaluate_event(self, event: Dict[str, Any]) -> List[VendorAnomalyIndicator]:
        """Unified dispatcher routing an event through all applicable supply chain checks."""
        etype = str(event.get("event_type", "")).lower()
        results: List[VendorAnomalyIndicator] = []
        if etype in ("auth_event", "vendor_auth", "login"):
            results.extend(self.check_vendor_authentication(event))
        if etype in ("network_flow", "resource_access", "connection"):
            results.extend(self.check_resource_access(event))
        if etype in ("service_operation", "service_account"):
            results.extend(self.check_service_account_misuse(event))
        if etype in ("api_activity", "http_event"):
            results.extend(self.check_api_activity(event))
        if etype in ("file_access", "storage_access"):
            results.extend(self.check_shared_storage_access(event))
        if etype in ("tls_event", "encrypted_outbound"):
            results.extend(self.check_encrypted_outbound(event))
        return results

    # ------------------------------------------------------------------
    # Redis Publishing
    # ------------------------------------------------------------------
    def _publish_redis_sync(self, indicator: VendorAnomalyIndicator) -> None:
        if self.redis_client is None:
            return
        xadd = getattr(self.redis_client, "xadd", None)
        if xadd is None or inspect.iscoroutinefunction(xadd):
            return
        try:
            xadd(
                REDIS_STREAM_SUPPLY_CHAIN,
                {
                    "payload": json.dumps(indicator.to_dict()),
                    "vendor_id": indicator.vendor_id,
                    "indicator_type": indicator.indicator_type,
                    "severity": indicator.severity,
                },
            )
        except Exception as exc:
            logger.error("Failed publishing supply chain indicator to Redis: %s", exc)

    async def publish_indicator(self, indicator: VendorAnomalyIndicator) -> None:
        """Async publish to Redis stream 'detections:supply_chain'."""
        if self.redis_client is None or indicator.suppressed:
            return
        result = self.redis_client.xadd(
            REDIS_STREAM_SUPPLY_CHAIN,
            {
                "payload": json.dumps(indicator.to_dict()),
                "vendor_id": indicator.vendor_id,
                "indicator_type": indicator.indicator_type,
                "severity": indicator.severity,
            },
        )
        if inspect.isawaitable(result):
            await result
