"""
test_containment.py — Unit Tests for VaultX Phase 2 Containment & Response Engine.

Compatible with both ``pytest`` and ``python -m unittest``.

Coverage
--------
* ``test_policy_engine``        : MODE 1-4 behaviour, hardcoded MODE 3 default,
                                  OT safety override (VLAN 30 & ot_safety_flag),
                                  immutable OT_ALWAYS_HUMAN_APPROVAL, all 10
                                  mandatory ActionProposal fields, RBAC mode lock.
* ``test_approval_engine``      : RBAC roles, two-person rule for CRITICAL OT,
                                  simulated MFA validation, 4-hour action expiry,
                                  emergency break-glass with elevated audit & admin
                                  alerting, reversible action policies.
* ``test_enforcement_adapters`` : FirewallAdapter, EndpointQuarantineAdapter,
                                  IdentityAdapter, VPNAdapter, OTBoundaryAdapter
                                  (including mandatory OT safety docstring),
                                  ContainmentActionExecutor workflow & timeout.
* ``test_model_pipeline``       : LABEL_VERIFICATION rejecting ML-only labels,
                                  DATA_QUALITY >20% missing filter, DEDUPLICATION,
                                  SENSITIVE_DATA_REDACTION, offline training,
                                  evaluation, and SECURITY_MANAGER promotion gate.
"""

from __future__ import annotations

import hashlib
import tempfile
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from backend.containment.action_executor import (
    ActionExecutionTimeoutError,
    ContainmentActionExecutor,
)
from backend.containment.approval_engine import (
    ActionExpiredError,
    ApprovalEngine,
    AuthenticationError,
    AuthorizationError,
    IdentityRecord,
    InvalidBreakGlassError,
    REVERSE_ACTION_MAP,
    get_reverse_action,
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
    ContainmentAction,
    EndpointQuarantineAdapter,
    EnforcementAdapter,
    ExecutionResult,
    FirewallAdapter,
    IdentityAdapter,
    OTBoundaryAdapter,
    RollbackResult,
    VPNAdapter,
)
from backend.containment.model_pipeline import ModelImprovementPipeline
from backend.containment.policy_engine import (
    ActionProposal,
    AffectedAsset,
    ContainmentPolicyEngine,
    DisabledModeError,
    UnauthorizedModeChangeError,
)
from backend.containment.simulated_firewall import SimulatedFirewallManager


# ---------------------------------------------------------------------------
# Helpers & Test Doubles
# ---------------------------------------------------------------------------


class _FakeRedis:
    """Minimal in-memory Redis stream stub capturing xadd() calls."""

    def __init__(self) -> None:
        self.streams: dict[str, list[dict[str, Any]]] = {}

    def xadd(self, stream: str, fields: dict[str, Any]) -> str:
        self.streams.setdefault(stream, []).append(fields)
        return f"{len(self.streams[stream])}-0"


class _SlowHangingAdapter(EnforcementAdapter):
    """Adapter double that sleeps longer than timeout to verify timeout handling."""

    adapter_name = "SlowHangingAdapter"

    def __init__(self, delay_seconds: float = 0.5) -> None:
        self._delay = delay_seconds

    def execute(self, action: ContainmentAction) -> ExecutionResult:
        time.sleep(self._delay)
        return ExecutionResult(
            action_id=action.action_id,
            adapter_name=self.adapter_name,
            success=True,
            status=ActionStatus.COMPLETED,
            message="completed slowly",
        )

    def rollback(self, action_id: uuid.UUID) -> RollbackResult:
        return RollbackResult(
            action_id=action_id,
            adapter_name=self.adapter_name,
            success=True,
            status=ActionStatus.ROLLED_BACK,
            message="rolled back",
        )

    def status(self, action_id: uuid.UUID) -> ActionStatus:
        return ActionStatus.PENDING


def _make_corp_workstation(criticality: str = "medium") -> AffectedAsset:
    return AffectedAsset(
        asset_id="CORP-WS-101",
        hostname="fin-ws-pune-01",
        vlan_id=10,
        criticality=criticality,
        device_type="workstation",
        ip_address="10.10.10.101",
    )


def _make_ot_plc() -> AffectedAsset:
    return AffectedAsset(
        asset_id="OT-SMT-PLC01",
        hostname="plc-smt-line1",
        vlan_id=30,
        criticality="critical",
        device_type="plc",
        ip_address="10.10.30.20",
    )


def _seed_identities() -> dict[str, IdentityRecord]:
    return {
        "analyst@becpl.in": IdentityRecord(
            identity_id=uuid.uuid4(),
            principal_name="analyst@becpl.in",
            role=Role.ANALYST,
            is_active=True,
        ),
        "operator@becpl.in": IdentityRecord(
            identity_id=uuid.uuid4(),
            principal_name="operator@becpl.in",
            role=Role.OPERATOR,
            is_active=True,
        ),
        "approver1@becpl.in": IdentityRecord(
            identity_id=uuid.uuid4(),
            principal_name="approver1@becpl.in",
            role=Role.APPROVER,
            is_active=True,
        ),
        "approver2@becpl.in": IdentityRecord(
            identity_id=uuid.uuid4(),
            principal_name="approver2@becpl.in",
            role=Role.APPROVER,
            is_active=True,
        ),
        "ciso@becpl.in": IdentityRecord(
            identity_id=uuid.uuid4(),
            principal_name="ciso@becpl.in",
            role=Role.SECURITY_MANAGER,
            is_active=True,
        ),
        "admin@becpl.in": IdentityRecord(
            identity_id=uuid.uuid4(),
            principal_name="admin@becpl.in",
            role=Role.ADMIN,
            is_active=True,
        ),
    }


# ---------------------------------------------------------------------------
# 1. Policy Engine Tests
# ---------------------------------------------------------------------------


class TestPolicyEngine(unittest.TestCase):
    def test_default_mode_is_mode3_and_creates_pending_action(self) -> None:
        engine = ContainmentPolicyEngine()
        self.assertEqual(engine.current_mode, ContainmentMode.HUMAN_APPROVAL_REQUIRED)
        self.assertTrue(OT_ALWAYS_HUMAN_APPROVAL)

        incident_id = uuid.uuid4()
        asset = _make_corp_workstation("medium")
        proposal = engine.propose_action(
            incident_id=incident_id,
            affected_asset=asset,
            action_category=ActionCategory.ENDPOINT_QUARANTINE,
            reason_for_isolation="Suspicious SMB lateral movement from finance workstation",
            supporting_evidence=["evt-1001", "evt-1002"],
            parameters={"quarantine_vlan": 999},
            initiated_by="operator@becpl.in",
        )

        # Verify MODE 3 creates pending action with no approver yet
        self.assertEqual(proposal.execution_status, ActionStatus.PENDING.value)
        self.assertIsNone(proposal.approver_identity)
        self.assertIsNotNone(proposal.isolation_policy_id)

        # Verify all 10 mandatory ActionProposal fields
        proposal_dict = proposal.to_dict()
        for field_name in ActionProposal.MANDATORY_FIELDS:
            self.assertIn(field_name, proposal_dict)
        self.assertEqual(proposal_dict["incident_id"], str(incident_id))
        self.assertEqual(proposal_dict["affected_asset"]["asset_id"], "CORP-WS-101")
        self.assertEqual(proposal_dict["affected_asset"]["hostname"], "fin-ws-pune-01")
        self.assertEqual(proposal_dict["affected_asset"]["vlan_id"], 10)
        self.assertEqual(proposal_dict["affected_asset"]["criticality"], "medium")
        self.assertEqual(proposal_dict["affected_network_segment"], "Corporate IT")
        self.assertEqual(proposal_dict["supporting_evidence"], ["evt-1001", "evt-1002"])
        self.assertEqual(
            proposal_dict["proposed_action"]["action_type"],
            ActionCategory.ENDPOINT_QUARANTINE.value,
        )
        self.assertTrue(len(proposal_dict["expected_operational_impact"]) > 20)
        self.assertEqual(proposal_dict["required_permissions"], Role.APPROVER.value)

    def test_disabled_mode_raises_error_and_monitor_mode_recommends_only(self) -> None:
        engine = ContainmentPolicyEngine()

        # Non-ADMIN cannot change mode
        with self.assertRaises(UnauthorizedModeChangeError):
            engine.set_mode(ContainmentMode.DISABLED, Role.APPROVER, "approver1@becpl.in")

        # MODE 1: DISABLED raises DisabledModeError
        engine.set_mode(ContainmentMode.DISABLED, Role.ADMIN, "admin@becpl.in", reason="maintenance")
        with self.assertRaises(DisabledModeError):
            engine.propose_action(
                incident_id=uuid.uuid4(),
                affected_asset=_make_corp_workstation(),
                action_category=ActionCategory.NETWORK_CONTAINMENT,
                reason_for_isolation="C2 beacon detected",
                supporting_evidence=["evt-2001"],
                parameters={"src_ip": "10.10.10.101", "dst_ip": "198.51.100.22", "port": 443},
            )

        # MODE 2: MONITOR_ONLY logs status='recommended'
        engine.set_mode(ContainmentMode.MONITOR_ONLY, Role.ADMIN, "admin@becpl.in")
        proposal = engine.propose_action(
            incident_id=uuid.uuid4(),
            affected_asset=_make_corp_workstation(),
            action_category=ActionCategory.NETWORK_CONTAINMENT,
            reason_for_isolation="C2 beacon detected",
            supporting_evidence=["evt-2002"],
            parameters={"src_ip": "10.10.10.101", "dst_ip": "198.51.100.22", "port": 443},
        )
        self.assertEqual(proposal.execution_status, ActionStatus.RECOMMENDED.value)

    def test_ot_safety_override_blocks_automation_even_in_mode4(self) -> None:
        config = ContainmentConfig()
        # Immutable safety invariant cannot be turned off programmatically
        with self.assertRaises(SafetyInvariantViolationError):
            config.ot_always_human_approval = False

        engine = ContainmentPolicyEngine(config=config)
        engine.set_mode(ContainmentMode.PRE_APPROVED_AUTOMATION, Role.ADMIN, "admin@becpl.in")

        # 1. Pre-approved non-OT corporate template auto-approves in MODE 4
        corp_proposal = engine.propose_action(
            incident_id=uuid.uuid4(),
            affected_asset=_make_corp_workstation("low"),
            action_category=ActionCategory.NETWORK_CONTAINMENT,
            reason_for_isolation="Known C2 IP block",
            supporting_evidence=["evt-3001"],
            parameters={"src_ip": "10.10.10.101", "dst_ip": "203.0.113.50", "port": 443},
            template_id="TPL-BLOCK-KNOWN-C2-IT",
        )
        self.assertEqual(corp_proposal.execution_status, ActionStatus.APPROVED.value)
        self.assertFalse(corp_proposal.ot_safety_override_applied)

        # 2. VLAN 30 OT PLC ALWAYS forced to pending (human approval) even in MODE 4
        ot_proposal = engine.propose_action(
            incident_id=uuid.uuid4(),
            affected_asset=_make_ot_plc(),
            action_category=ActionCategory.OT_BOUNDARY_RESTRICTION,
            reason_for_isolation="Unauthorized Modbus TCP/502 write to SMT Line 1 PLC",
            supporting_evidence=["evt-3002"],
            parameters={"ot_target_ip": "10.10.30.20"},
            template_id="TPL-BLOCK-KNOWN-C2-IT",
        )
        self.assertEqual(ot_proposal.execution_status, ActionStatus.PENDING.value)
        self.assertTrue(ot_proposal.ot_safety_override_applied)
        self.assertTrue(ot_proposal.two_person_rule_required)
        self.assertIn("two-person rule", ot_proposal.required_permissions)

        # 3. Non-VLAN-30 asset carrying ot_safety_flag=True ALSO forced to pending in MODE 4
        flagged_eng_asset = AffectedAsset(
            asset_id="ENG-FLASHER-01",
            hostname="firmware-flasher.eng.becpl.local",
            vlan_id=20,
            criticality="medium",
            device_type="workstation",
            ip_address="10.10.20.40",
            ot_safety_flag=True,
        )
        flagged_proposal = engine.propose_action(
            incident_id=uuid.uuid4(),
            affected_asset=flagged_eng_asset,
            action_category=ActionCategory.NETWORK_CONTAINMENT,
            reason_for_isolation="Anomalous flashing traffic",
            supporting_evidence=["evt-3003"],
            template_id="TPL-BLOCK-KNOWN-C2-IT",
        )
        self.assertEqual(flagged_proposal.execution_status, ActionStatus.PENDING.value)
        self.assertTrue(flagged_proposal.ot_safety_override_applied)


# ---------------------------------------------------------------------------
# 2. Approval Engine Tests
# ---------------------------------------------------------------------------


class TestApprovalEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.break_glass_secret = "BECPL-EMERGENCY-2026-CODE"
        bg_hash = hashlib.sha256(self.break_glass_secret.encode("utf-8")).hexdigest()
        self.config = ContainmentConfig(break_glass_hash=bg_hash)
        self.policy_engine = ContainmentPolicyEngine(config=self.config)
        self.redis = _FakeRedis()
        self.approval_engine = ApprovalEngine(
            policy_engine=self.policy_engine,
            redis_client=self.redis,
            config=self.config,
            identities=_seed_identities(),
        )

    def test_role_based_approval_and_mfa_simulation(self) -> None:
        proposal = self.policy_engine.propose_action(
            incident_id=uuid.uuid4(),
            affected_asset=_make_corp_workstation("medium"),
            action_category=ActionCategory.ENDPOINT_QUARANTINE,
            reason_for_isolation="Ransomware precursor behaviour",
            supporting_evidence=["evt-4001"],
        )

        # Invalid MFA token (doesn't start with '1' or wrong length) rejected
        with self.assertRaises(AuthenticationError):
            self.approval_engine.approve_action(
                action_id=proposal.action_id,
                approver_identity="approver1@becpl.in",
                approver_role=Role.APPROVER,
                mfa_token="299999",
            )
        with self.assertRaises(AuthenticationError):
            self.approval_engine.approve_action(
                action_id=proposal.action_id,
                approver_identity="approver1@becpl.in",
                approver_role=Role.APPROVER,
                mfa_token="12345",
            )

        # ANALYST and OPERATOR cannot approve
        with self.assertRaises(AuthorizationError):
            self.approval_engine.approve_action(
                action_id=proposal.action_id,
                approver_identity="analyst@becpl.in",
                approver_role=Role.ANALYST,
                mfa_token="123456",
            )
        with self.assertRaises(AuthorizationError):
            self.approval_engine.approve_action(
                action_id=proposal.action_id,
                approver_identity="operator@becpl.in",
                approver_role=Role.OPERATOR,
                mfa_token="123456",
            )

        # APPROVER succeeds on tier-1 non-critical action with valid simulated MFA '1xxxxx'
        res = self.approval_engine.approve_action(
            action_id=proposal.action_id,
            approver_identity="approver1@becpl.in",
            approver_role=Role.APPROVER,
            mfa_token="104829",
        )
        self.assertTrue(res.approved)
        self.assertEqual(res.status, ActionStatus.APPROVED.value)
        self.assertEqual(res.approval_method, ApprovalMethod.MFA_TOKEN.value)
        self.assertIsNotNone(res.reverse_action)

        # APPROVER is blocked on THIRD_PARTY_CONTAINMENT (requires SECURITY_MANAGER)
        vendor_prop = self.policy_engine.propose_action(
            incident_id=uuid.uuid4(),
            affected_asset=AffectedAsset(
                asset_id="DMZ-JUMP-01",
                hostname="bastion.dmz.becpl.local",
                vlan_id=50,
                criticality="high",
                device_type="server",
            ),
            action_category=ActionCategory.THIRD_PARTY_CONTAINMENT,
            reason_for_isolation="Compromised vendor VPN session outside window",
            supporting_evidence=["evt-4002"],
            parameters={"session_id": "vpn-sess-01", "vendor_name": "Yamaha SMT"},
        )
        with self.assertRaises(AuthorizationError):
            self.approval_engine.approve_action(
                action_id=vendor_prop.action_id,
                approver_identity="approver1@becpl.in",
                approver_role=Role.APPROVER,
                mfa_token="111111",
            )

        mgr_res = self.approval_engine.approve_action(
            action_id=vendor_prop.action_id,
            approver_identity="ciso@becpl.in",
            approver_role=Role.SECURITY_MANAGER,
            mfa_token="199999",
            approval_method=ApprovalMethod.MANAGER_APPROVAL,
        )
        self.assertTrue(mgr_res.approved)
        self.assertEqual(mgr_res.status, ActionStatus.APPROVED.value)

    def test_two_person_rule_for_critical_ot_containment(self) -> None:
        ot_prop = self.policy_engine.propose_action(
            incident_id=uuid.uuid4(),
            affected_asset=_make_ot_plc(),
            action_category=ActionCategory.OT_BOUNDARY_RESTRICTION,
            reason_for_isolation="Rogue Modbus write attempt to SMT Line 1 PLC",
            supporting_evidence=["evt-5001"],
        )

        # 1st approval by SECURITY_MANAGER -> still pending (awaiting second approver)
        first = self.approval_engine.approve_action(
            action_id=ot_prop.action_id,
            approver_identity="ciso@becpl.in",
            approver_role=Role.SECURITY_MANAGER,
            mfa_token="100001",
        )
        self.assertFalse(first.approved)
        self.assertTrue(first.awaiting_second_approver)
        self.assertEqual(first.status, ActionStatus.PENDING.value)

        # Same identity cannot sign twice
        with self.assertRaises(AuthorizationError):
            self.approval_engine.approve_action(
                action_id=ot_prop.action_id,
                approver_identity="ciso@becpl.in",
                approver_role=Role.SECURITY_MANAGER,
                mfa_token="100002",
            )

        # 2nd distinct APPROVER completes two-person approval
        second = self.approval_engine.approve_action(
            action_id=ot_prop.action_id,
            approver_identity="approver1@becpl.in",
            approver_role=Role.APPROVER,
            mfa_token="100003",
        )
        self.assertTrue(second.approved)
        self.assertFalse(second.awaiting_second_approver)
        self.assertEqual(second.status, ActionStatus.APPROVED.value)
        self.assertEqual(second.approved_by, "ciso@becpl.in")
        self.assertEqual(second.second_approver, "approver1@becpl.in")

    def test_action_expiry_after_4_hours_and_break_glass(self) -> None:
        t0 = datetime(2026, 11, 18, 6, 0, 0, tzinfo=timezone.utc)
        proposal = self.policy_engine.propose_action(
            incident_id=uuid.uuid4(),
            affected_asset=_make_corp_workstation("medium"),
            action_category=ActionCategory.NETWORK_CONTAINMENT,
            reason_for_isolation="Suspicious outbound exfil",
            supporting_evidence=["evt-6001"],
            parameters={"src_ip": "10.10.10.101", "dst_ip": "198.51.100.99", "port": 443},
        )
        self.approval_engine.approve_action(
            action_id=proposal.action_id,
            approver_identity="approver1@becpl.in",
            approver_role=Role.APPROVER,
            mfa_token="123456",
            now=t0,
        )

        # Not expired at +3h59m
        self.assertFalse(
            self.approval_engine.is_action_expired(proposal, now=t0 + timedelta(hours=3, minutes=59))
        )
        # Expired at +4h01m
        expired_ids = self.approval_engine.check_and_expire_actions(
            now=t0 + timedelta(hours=4, minutes=1)
        )
        self.assertIn(proposal.action_id, expired_ids)
        self.assertEqual(proposal.execution_status, ActionStatus.EXPIRED.value)

        # Break-glass emergency override
        bg_prop = self.policy_engine.propose_action(
            incident_id=uuid.uuid4(),
            affected_asset=_make_ot_plc(),
            action_category=ActionCategory.OT_BOUNDARY_RESTRICTION,
            reason_for_isolation="Active PLC sabotage in progress",
            supporting_evidence=["evt-6002"],
        )
        with self.assertRaises(InvalidBreakGlassError):
            self.approval_engine.break_glass_approve(
                action_id=bg_prop.action_id,
                actor_identity="admin@becpl.in",
                break_glass_code="WRONG-CODE",
                reason="Emergency",
            )

        bg_res = self.approval_engine.break_glass_approve(
            action_id=bg_prop.action_id,
            actor_identity="admin@becpl.in",
            break_glass_code=self.break_glass_secret,
            reason="Active OT ransomware emergency",
        )
        self.assertTrue(bg_res.approved)
        self.assertTrue(bg_res.break_glass_used)
        self.assertEqual(bg_res.approval_method, ApprovalMethod.BREAK_GLASS.value)
        self.assertEqual(len(self.approval_engine.get_admin_alerts()), 1)
        self.assertIn("containment:alerts", self.redis.streams)

        # Every action category has a defined reverse action
        for category in ActionCategory:
            self.assertIn(category, REVERSE_ACTION_MAP)
            self.assertTrue(get_reverse_action(category).reverse_action_type)


# ---------------------------------------------------------------------------
# 3. Enforcement Adapters & Action Executor Tests
# ---------------------------------------------------------------------------


class TestEnforcementAdaptersAndExecutor(unittest.TestCase):
    def test_firewall_adapter_rule_creation_and_rollback(self) -> None:
        fw_mgr = SimulatedFirewallManager()
        adapter = FirewallAdapter(firewall_manager=fw_mgr)

        # Direct helper test
        rule = adapter.add_block_rule("10.10.10.101", "198.51.100.5", 443)
        self.assertTrue(fw_mgr.check_rule_exists("10.10.10.101", "198.51.100.5", "TCP", 443, "BLOCK"))
        self.assertEqual(len(adapter.list_active_rules()), 1)
        self.assertTrue(adapter.remove_rule(rule.rule_id))
        self.assertEqual(len(adapter.list_active_rules()), 0)

        # Adapter execute() + rollback()
        action = ContainmentAction(
            action_id=uuid.uuid4(),
            incident_id=uuid.uuid4(),
            action_category=ActionCategory.NETWORK_CONTAINMENT,
            target_ip="10.10.10.101",
            parameters={"src_ip": "10.10.10.101", "dst_ip": "10.10.30.20", "port": 502},
            approved_by="ciso@becpl.in",
        )
        exec_res = adapter.execute(action)
        self.assertTrue(exec_res.success)
        self.assertEqual(adapter.status(action.action_id), ActionStatus.COMPLETED)
        self.assertTrue(fw_mgr.check_rule_exists("10.10.10.101", "10.10.30.20", "TCP", 502, "BLOCK"))

        rb_res = adapter.rollback(action.action_id)
        self.assertTrue(rb_res.success)
        self.assertEqual(adapter.status(action.action_id), ActionStatus.ROLLED_BACK)
        self.assertFalse(fw_mgr.check_rule_exists("10.10.10.101", "10.10.30.20", "TCP", 502, "BLOCK"))

    def test_identity_quarantine_vpn_and_ot_boundary_adapters(self) -> None:
        # 1. IdentityAdapter
        identity_id = uuid.uuid4()
        id_adapter = IdentityAdapter(
            identity_store={
                str(identity_id): {
                    "identity_id": str(identity_id),
                    "principal_name": "yamaha_field_eng",
                    "is_active": True,
                }
            }
        )
        id_action = ContainmentAction(
            action_id=uuid.uuid4(),
            incident_id=uuid.uuid4(),
            action_category=ActionCategory.IDENTITY_CONTAINMENT,
            target_identity_id=identity_id,
            target_principal="yamaha_field_eng",
            approved_by="ciso@becpl.in",
        )
        id_res = id_adapter.execute(id_action)
        self.assertTrue(id_res.success)
        self.assertFalse(id_adapter.get_identity_state(str(identity_id))["is_active"])
        self.assertEqual(len(id_adapter.get_revocation_audit()), 1)

        id_rb = id_adapter.rollback(id_action.action_id)
        self.assertTrue(id_rb.success)
        self.assertTrue(id_adapter.get_identity_state(str(identity_id))["is_active"])

        # 2. EndpointQuarantineAdapter preserves VLAN 70 management access
        q_adapter = EndpointQuarantineAdapter()
        q_action = ContainmentAction(
            action_id=uuid.uuid4(),
            incident_id=uuid.uuid4(),
            action_category=ActionCategory.ENDPOINT_QUARANTINE,
            target_asset_id="CORP-WS-101",
            approved_by="approver1@becpl.in",
        )
        q_res = q_adapter.execute(q_action)
        self.assertTrue(q_res.success)
        q_rec = q_adapter.get_quarantine_record(q_action.action_id)
        self.assertIsNotNone(q_rec)
        self.assertTrue(q_rec.management_access_preserved)
        self.assertEqual(q_rec.allowed_management_cidr, "10.10.70.0/24")
        self.assertTrue(q_adapter.rollback(q_action.action_id).success)
        self.assertFalse(q_rec.active)

        # 3. VPNAdapter
        vpn_adapter = VPNAdapter()
        vpn_action = ContainmentAction(
            action_id=uuid.uuid4(),
            incident_id=uuid.uuid4(),
            action_category=ActionCategory.THIRD_PARTY_CONTAINMENT,
            target_ip="10.10.50.10",
            parameters={"session_id": "wg-yamaha-01", "vendor_name": "Yamaha SMT"},
            approved_by="ciso@becpl.in",
        )
        self.assertTrue(vpn_adapter.execute(vpn_action).success)
        self.assertEqual(vpn_adapter.get_session("wg-yamaha-01")["session_status"], "suspended")
        self.assertTrue(vpn_adapter.rollback(vpn_action.action_id).success)
        self.assertEqual(vpn_adapter.get_session("wg-yamaha-01")["session_status"], "restored")

        # 4. OTBoundaryAdapter docstring safety note + Modbus 502 rules
        self.assertIn("qualified OT/ICS engineer", OTBoundaryAdapter.__doc__ or "")
        self.assertIn("Automated enforcement is NOT safe for production OT", OTBoundaryAdapter.__doc__ or "")
        ot_adapter = OTBoundaryAdapter()
        ot_action = ContainmentAction(
            action_id=uuid.uuid4(),
            incident_id=uuid.uuid4(),
            action_category=ActionCategory.OT_BOUNDARY_RESTRICTION,
            target_asset_id="OT-SMT-PLC01",
            target_ip="10.10.30.20",
            parameters={"ot_target_ip": "10.10.30.20"},
            approved_by="ciso@becpl.in",
        )
        ot_res = ot_adapter.execute(ot_action)
        self.assertTrue(ot_res.success)
        self.assertTrue(
            ot_adapter.firewall_manager.check_rule_exists("10.10.30.10", "10.10.30.20", "TCP", 502, "ALLOW")
        )
        self.assertTrue(
            ot_adapter.firewall_manager.check_rule_exists("10.10.10.0/24", "10.10.30.20", "TCP", 502, "BLOCK")
        )
        self.assertTrue(ot_adapter.rollback(ot_action.action_id).success)
        self.assertEqual(len(ot_adapter.firewall_manager.list_active_rules()), 0)

    def test_action_executor_workflow_and_timeout(self) -> None:
        policy_engine = ContainmentPolicyEngine()
        redis = _FakeRedis()
        approval_engine = ApprovalEngine(
            policy_engine=policy_engine,
            redis_client=redis,
            identities=_seed_identities(),
        )
        correlation_updates: list[tuple[uuid.UUID, str]] = []
        executor = ContainmentActionExecutor(
            policy_engine=policy_engine,
            approval_engine=approval_engine,
            redis_client=redis,
            correlation_notifier=lambda inc_id, st, _d: correlation_updates.append((inc_id, st)),
        )

        incident_id = uuid.uuid4()
        proposal = policy_engine.propose_action(
            incident_id=incident_id,
            affected_asset=_make_corp_workstation("medium"),
            action_category=ActionCategory.NETWORK_CONTAINMENT,
            reason_for_isolation="Malicious outbound scan",
            supporting_evidence=["evt-7001"],
            parameters={"src_ip": "10.10.10.101", "dst_ip": "198.51.100.77", "port": 8443},
        )
        approval_engine.approve_action(
            action_id=proposal.action_id,
            approver_identity="approver1@becpl.in",
            approver_role=Role.APPROVER,
            mfa_token="123456",
        )

        exec_res = executor.execute_action(proposal.action_id)
        self.assertTrue(exec_res.success)
        self.assertEqual(proposal.execution_status, ActionStatus.COMPLETED.value)
        self.assertIn("containment:executed", redis.streams)
        self.assertEqual(correlation_updates[-1], (incident_id, "contained"))

        # Rollback via executor
        rb_res = executor.rollback_action(proposal.action_id, actor_identity="ciso@becpl.in", reason="False positive")
        self.assertTrue(rb_res.success)
        self.assertEqual(proposal.execution_status, ActionStatus.ROLLED_BACK.value)
        self.assertEqual(correlation_updates[-1], (incident_id, "investigating"))

        # Timeout test
        slow_executor = ContainmentActionExecutor(
            policy_engine=policy_engine,
            approval_engine=approval_engine,
            adapters={ActionCategory.NETWORK_CONTAINMENT: _SlowHangingAdapter(delay_seconds=0.4)},
            redis_client=redis,
        )
        slow_prop = policy_engine.propose_action(
            incident_id=uuid.uuid4(),
            affected_asset=_make_corp_workstation("medium"),
            action_category=ActionCategory.NETWORK_CONTAINMENT,
            reason_for_isolation="Timeout simulation",
            supporting_evidence=["evt-7002"],
            parameters={"src_ip": "10.10.10.101", "dst_ip": "198.51.100.88", "port": 443},
        )
        approval_engine.approve_action(
            action_id=slow_prop.action_id,
            approver_identity="approver1@becpl.in",
            approver_role=Role.APPROVER,
            mfa_token="123456",
        )
        with self.assertRaises(ActionExecutionTimeoutError):
            slow_executor.execute_action(slow_prop.action_id, timeout_seconds=0.05)
        self.assertEqual(slow_prop.execution_status, ActionStatus.FAILED.value)
        self.assertEqual(len(slow_executor.get_alerts()), 1)


# ---------------------------------------------------------------------------
# 4. Model Improvement Pipeline Tests
# ---------------------------------------------------------------------------


class TestModelPipeline(unittest.TestCase):
    def test_label_verification_rejects_ml_only_labels(self) -> None:
        pipeline = ModelImprovementPipeline()
        analyst_uuid = str(uuid.uuid4())
        records = [
            # Valid analyst-confirmed label
            {
                "event_id": "evt-a1",
                "features": {"duration": 100.0},
                "label": "LATERAL_MOVEMENT",
                "label_source": "analyst_feedback",
                "analyst_id": analyst_uuid,
            },
            # Valid scenario ground truth label
            {
                "event_id": "evt-s1",
                "features": {"duration": 200.0},
                "label": "OT_ANOMALY",
                "label_source": "scenario_ground_truth",
            },
            # REJECTED: ML model prediction only
            {
                "event_id": "evt-ml1",
                "features": {"duration": 300.0},
                "label": "ENCRYPTED_EXFIL",
                "label_source": "ml_prediction",
            },
            # REJECTED: Auto-label without human verification
            {
                "event_id": "evt-auto1",
                "features": {"duration": 400.0},
                "label": "LOTL",
                "label_source": "auto_label",
            },
            # REJECTED: Missing analyst_id on analyst_feedback
            {
                "event_id": "evt-no-analyst",
                "features": {"duration": 500.0},
                "label": "BENIGN",
                "label_source": "analyst_feedback",
            },
        ]

        verified, report = pipeline.verify_labels(records)
        self.assertEqual(report.total_records, 5)
        self.assertEqual(report.verified_count, 2)
        self.assertEqual(report.rejected_count, 3)
        verified_ids = {r["event_id"] for r in verified}
        self.assertEqual(verified_ids, {"evt-a1", "evt-s1"})

    def test_data_quality_dedup_redaction_and_promotion_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = ModelImprovementPipeline(artifact_dir=Path(tmpdir))

            # 1. Data quality filter (> 20% missing rejected)
            fv_good = {
                "event_id": "evt-q1",
                "features": {f"f{i}": float(i) for i in range(10)},
            }
            # 2 of 10 missing == 20% (accepted: threshold is strictly > 20%)
            fv_borderline = {
                "event_id": "evt-q2",
                "features": {f"f{i}": (None if i < 2 else float(i)) for i in range(10)},
            }
            # 3 of 10 missing == 30% (> 20% -> rejected)
            fv_bad = {
                "event_id": "evt-q3",
                "features": {f"f{i}": (None if i < 3 else float(i)) for i in range(10)},
            }
            accepted, dq_report = pipeline.run_data_quality_filter([fv_good, fv_borderline, fv_bad])
            self.assertEqual(dq_report.accepted_count, 2)
            self.assertEqual(dq_report.rejected_count, 1)
            self.assertEqual(dq_report.rejection_reasons[0]["event_id"], "evt-q3")

            # 2. Deduplication by event hash
            unique, removed = pipeline.deduplicate_vectors([fv_good, dict(fv_good)])
            self.assertEqual(len(unique), 1)
            self.assertEqual(removed, 1)

            # 3. Sensitive data redaction
            dirty = [
                {
                    "event_id": "evt-sec1",
                    "password": "SuperSecretPassword123",
                    "api_key": "sk-live-9999999",
                    "features": {
                        "duration": 50.0,
                        "auth_note": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaaaaa.bbbbbbb rajesh@becpl.in",
                    },
                }
            ]
            cleaned = pipeline.redact_sensitive_data(dirty)
            self.assertNotIn("password", cleaned[0])
            self.assertNotIn("api_key", cleaned[0])
            self.assertNotIn("rajesh@becpl.in", cleaned[0]["features"]["auth_note"])
            self.assertIn("[REDACTED_", cleaned[0]["features"]["auth_note"])

            # 4. Versioned dataset -> offline train -> evaluate -> SECURITY_MANAGER promotion
            analyst_id = str(uuid.uuid4())
            training_events = []
            for i in range(16):
                is_attack = i % 2 == 1
                training_events.append(
                    {
                        "event_id": f"evt-train-{i}",
                        "connection_duration_ms": 5000 if is_attack else 120,
                        "orig_bytes": 90000 if is_attack else 400,
                        "resp_bytes": 500 if is_attack else 800,
                        "orig_packets": 100 if is_attack else 5,
                        "resp_packets": 10 if is_attack else 5,
                        "protocol": "TCP",
                        "source_vlan": 10,
                        "dest_vlan": 30 if is_attack else 10,
                        "label": "OT_ANOMALY" if is_attack else "BENIGN",
                        "label_source": "analyst_feedback",
                        "analyst_id": analyst_id,
                    }
                )
            vectors = pipeline.extract_features(pipeline.normalise_events(training_events))
            verified, _ = pipeline.verify_labels(vectors)
            manifest = pipeline.create_versioned_training_dataset(verified, version=1)
            self.assertEqual(manifest.object_prefix, "datasets/training/v1")

            candidate = pipeline.train_offline_model(verified, dataset_version=manifest.version)
            eval_report = pipeline.evaluate_model(candidate["model_id"])
            self.assertGreaterEqual(eval_report.accuracy, 0.0)
            self.assertEqual(eval_report.holdout_samples, 4)

            # Non-SECURITY_MANAGER cannot promote
            with self.assertRaises(AuthorizationError):
                pipeline.approve_and_promote_model(
                    model_id=candidate["model_id"],
                    approver_identity="approver1@becpl.in",
                    approver_role=Role.APPROVER,
                    mfa_token="123456",
                )

            # SECURITY_MANAGER with valid MFA promotes for controlled restart deployment
            deployment = pipeline.approve_and_promote_model(
                model_id=candidate["model_id"],
                approver_identity="ciso@becpl.in",
                approver_role=Role.SECURITY_MANAGER,
                mfa_token="123456",
            )
            self.assertTrue(deployment["load_on_next_restart"])
            self.assertTrue((Path(tmpdir) / "active_model_deployment.json").exists())


if __name__ == "__main__":
    unittest.main()
