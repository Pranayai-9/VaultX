"""
policy_engine.py — Policy-Based Containment Engine for VaultX Phase 2.

The most critical safety component in VaultX. Governs whether and how
containment proposals are created, enforces BECPL's four containment modes,
matches assets against PostgreSQL ``isolation_policies``, and strictly enforces
the immutable OT Safety Override for Manufacturing VLAN 30 and OT-flagged assets.

Containment Modes
-----------------
MODE 1 (DISABLED):
    Detects and records threats only; containment functions raise
    ``DisabledModeError``.
MODE 2 (MONITOR_ONLY):
    Prepares isolation recommendations and logs them to ``response_actions``
    with ``status='recommended'``; does NOT execute.
MODE 3 (HUMAN_APPROVAL_REQUIRED) — HARDCODED DEFAULT:
    Creates a pending containment action in ``response_actions`` with
    ``status='pending'``; execution is blocked until approved by an
    authorised human approver.
MODE 4 (PRE_APPROVED_AUTOMATION):
    Only auto-approves narrowly pre-scoped, pre-tested, pre-approved action
    templates on non-OT, non-critical assets; all other actions fall back to
    human approval (``status='pending'``).

OT Safety Override
------------------
Regardless of the active mode (even MODE 4), ANY containment action targeting
an asset in VLAN 30 (OT) or with ``ot_safety_flag=True`` ALWAYS requires human
approval (MODE 3 minimum).
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.containment.containment_config import (
    ActionCategory,
    ActionStatus,
    ApprovalMethod,
    ContainmentConfig,
    ContainmentMode,
    DB_SCHEMA,
    DEFAULT_MODE_ENUM,
    OT_ALWAYS_HUMAN_APPROVAL,
    OT_DEVICE_TYPES,
    OT_VLAN_ID,
    PRE_APPROVED_ACTION_TEMPLATES,
    QUARANTINE_VLAN_ID,
    Role,
    SafetyInvariantViolationError,
    VLAN_NAMES,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class DisabledModeError(RuntimeError):
    """Raised when containment is invoked while the engine is in MODE 1 (DISABLED)."""


class UnauthorizedModeChangeError(PermissionError):
    """Raised when a non-ADMIN principal attempts to change the containment mode."""


class PolicyLookupError(LookupError):
    """Raised when a required isolation policy cannot be resolved."""


class ProposalValidationError(ValueError):
    """Raised when an ActionProposal is missing any of the 10 mandatory fields."""


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class AffectedAsset:
    """Target asset metadata embedded inside an ActionProposal."""

    asset_id: str
    hostname: str
    vlan_id: int
    criticality: str  # critical | high | medium | low
    vlan_name: str = ""
    device_type: str = "workstation"
    ip_address: str | None = None
    ot_safety_flag: bool = False

    def __post_init__(self) -> None:
        self.criticality = self.criticality.strip().lower()
        if not self.vlan_name:
            self.vlan_name = VLAN_NAMES.get(self.vlan_id, f"VLAN-{self.vlan_id}")
        if self.vlan_id == OT_VLAN_ID or self.device_type.lower() in OT_DEVICE_TYPES:
            self.ot_safety_flag = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "vlan_id": self.vlan_id,
            "vlan_name": self.vlan_name,
            "criticality": self.criticality,
            "device_type": self.device_type,
            "ip_address": self.ip_address,
            "ot_safety_flag": self.ot_safety_flag,
        }


@dataclass
class IsolationPolicy:
    """Mirrors a row from ``becpl_nids.isolation_policies``."""

    policy_id: uuid.UUID
    policy_name: str
    target_asset_type: str | None
    target_criticality: str | None
    isolation_method: str
    quarantine_vlan: int | None
    requires_human_approval: bool
    approval_required_role: str
    production_safety_check: bool
    safety_check_command: str | None = None
    max_isolation_duration_hours: int = 24
    auto_restore: bool = False
    rollback_procedure: str = ""
    notify_on_isolation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": str(self.policy_id),
            "policy_name": self.policy_name,
            "target_asset_type": self.target_asset_type,
            "target_criticality": self.target_criticality,
            "isolation_method": self.isolation_method,
            "quarantine_vlan": self.quarantine_vlan,
            "requires_human_approval": self.requires_human_approval,
            "approval_required_role": self.approval_required_role,
            "production_safety_check": self.production_safety_check,
            "safety_check_command": self.safety_check_command,
            "max_isolation_duration_hours": self.max_isolation_duration_hours,
            "auto_restore": self.auto_restore,
            "rollback_procedure": self.rollback_procedure,
            "notify_on_isolation": self.notify_on_isolation,
        }


@dataclass
class ActionProposal:
    """
    Structured containment action proposal containing all 10 mandatory fields
    required by BECPL governance and persisted to ``becpl_nids.response_actions``.

    Mandatory Fields
    ----------------
    1. incident_id
    2. affected_asset (asset_id + hostname + VLAN + criticality)
    3. affected_network_segment (VLAN name)
    4. reason_for_isolation (evidence summary)
    5. supporting_evidence (list of event_ids)
    6. proposed_action (action_type + parameters)
    7. expected_operational_impact (human-readable impact statement)
    8. required_permissions (role required to approve)
    9. approver_identity (populated when approved; None while pending)
    10. execution_status (recommended/pending/approved/executing/completed/failed/rolled_back/expired)
    """

    # 10 Mandatory Fields
    incident_id: uuid.UUID
    affected_asset: AffectedAsset
    affected_network_segment: str
    reason_for_isolation: str
    supporting_evidence: list[str]
    proposed_action: dict[str, Any]
    expected_operational_impact: str
    required_permissions: str
    approver_identity: str | None = None
    execution_status: str = ActionStatus.PENDING.value

    # Supplementary Governance & DB Linkage Fields
    action_id: uuid.UUID = field(default_factory=uuid.uuid4)
    action_category: ActionCategory = ActionCategory.NETWORK_CONTAINMENT
    isolation_policy_id: uuid.UUID | None = None
    isolation_policy_name: str | None = None
    initiated_by: str = "vaultx-policy-engine"
    target_identity_id: uuid.UUID | None = None
    target_ip: str | None = None
    approval_method: str | None = None
    approval_timestamp: datetime | None = None
    second_approver: str | None = None
    break_glass_used: bool = False
    ot_safety_override_applied: bool = False
    two_person_rule_required: bool = False
    containment_mode: ContainmentMode = DEFAULT_MODE_ENUM
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    executed_at: datetime | None = None
    completed_at: datetime | None = None
    rollback_at: datetime | None = None
    notes: str | None = None

    MANDATORY_FIELDS = (
        "incident_id",
        "affected_asset",
        "affected_network_segment",
        "reason_for_isolation",
        "supporting_evidence",
        "proposed_action",
        "expected_operational_impact",
        "required_permissions",
        "approver_identity",
        "execution_status",
    )

    def validate_mandatory_fields(self) -> None:
        """Verify all 10 mandatory fields exist and non-nullable fields are populated."""
        if not self.incident_id:
            raise ProposalValidationError("Mandatory field 'incident_id' is required.")
        if not isinstance(self.affected_asset, AffectedAsset):
            raise ProposalValidationError("Mandatory field 'affected_asset' must be an AffectedAsset.")
        if not (self.affected_asset.asset_id and self.affected_asset.hostname and self.affected_asset.criticality):
            raise ProposalValidationError(
                "'affected_asset' must include asset_id, hostname, VLAN, and criticality."
            )
        if not self.affected_network_segment:
            raise ProposalValidationError("Mandatory field 'affected_network_segment' is required.")
        if not self.reason_for_isolation or not self.reason_for_isolation.strip():
            raise ProposalValidationError("Mandatory field 'reason_for_isolation' is required.")
        if not isinstance(self.supporting_evidence, list) or len(self.supporting_evidence) == 0:
            raise ProposalValidationError(
                "Mandatory field 'supporting_evidence' must be a non-empty list of event_ids."
            )
        if not isinstance(self.proposed_action, dict) or "action_type" not in self.proposed_action:
            raise ProposalValidationError(
                "Mandatory field 'proposed_action' must include 'action_type' and parameters."
            )
        if not self.expected_operational_impact or not self.expected_operational_impact.strip():
            raise ProposalValidationError("Mandatory field 'expected_operational_impact' is required.")
        if not self.required_permissions or not self.required_permissions.strip():
            raise ProposalValidationError("Mandatory field 'required_permissions' is required.")
        if not self.execution_status:
            raise ProposalValidationError("Mandatory field 'execution_status' is required.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": str(self.action_id),
            # 10 mandatory fields
            "incident_id": str(self.incident_id),
            "affected_asset": self.affected_asset.to_dict(),
            "affected_network_segment": self.affected_network_segment,
            "reason_for_isolation": self.reason_for_isolation,
            "supporting_evidence": list(self.supporting_evidence),
            "proposed_action": dict(self.proposed_action),
            "expected_operational_impact": self.expected_operational_impact,
            "required_permissions": self.required_permissions,
            "approver_identity": self.approver_identity,
            "execution_status": self.execution_status,
            # Extended metadata
            "action_category": self.action_category.value,
            "isolation_policy_id": str(self.isolation_policy_id) if self.isolation_policy_id else None,
            "isolation_policy_name": self.isolation_policy_name,
            "initiated_by": self.initiated_by,
            "target_identity_id": str(self.target_identity_id) if self.target_identity_id else None,
            "target_ip": self.target_ip,
            "approval_method": self.approval_method,
            "approval_timestamp": self.approval_timestamp.isoformat() if self.approval_timestamp else None,
            "second_approver": self.second_approver,
            "break_glass_used": self.break_glass_used,
            "ot_safety_override_applied": self.ot_safety_override_applied,
            "two_person_rule_required": self.two_person_rule_required,
            "containment_mode": self.containment_mode.name,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "rollback_at": self.rollback_at.isoformat() if self.rollback_at else None,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Phase 1 DB Action Type Compatibility Mapping
# ---------------------------------------------------------------------------

CATEGORY_TO_LEGACY_ACTION_TYPE: dict[ActionCategory, str] = {
    ActionCategory.ENDPOINT_QUARANTINE: "quarantine",
    ActionCategory.IDENTITY_CONTAINMENT: "disable_account",
    ActionCategory.NETWORK_CONTAINMENT: "firewall_rule",
    ActionCategory.THIRD_PARTY_CONTAINMENT: "session_revoke",
    ActionCategory.OT_BOUNDARY_RESTRICTION: "acl_update",
}


# ---------------------------------------------------------------------------
# Default Seed Isolation Policies (fallback when DB is offline)
# ---------------------------------------------------------------------------


def _default_seed_policies() -> list[IsolationPolicy]:
    return [
        IsolationPolicy(
            policy_id=uuid.UUID("11111111-1111-1111-1111-111111111101"),
            policy_name="IT Workstation Rapid Quarantine",
            target_asset_type="workstation",
            target_criticality="medium",
            isolation_method="vlan_quarantine",
            quarantine_vlan=QUARANTINE_VLAN_ID,
            requires_human_approval=True,
            approval_required_role=Role.APPROVER.value,
            production_safety_check=False,
            max_isolation_duration_hours=24,
            auto_restore=True,
            rollback_procedure=(
                "Switch port return to original VLAN 10 tag via SNMP/REST API "
                "and flush DHCP lease"
            ),
            notify_on_isolation=["secops@becpl.in", "helpdesk@becpl.in"],
        ),
        IsolationPolicy(
            policy_id=uuid.UUID("11111111-1111-1111-1111-111111111102"),
            policy_name="Manufacturing OT Asset Controlled Isolation",
            target_asset_type="plc",
            target_criticality="critical",
            isolation_method="acl_block",
            quarantine_vlan=None,
            requires_human_approval=True,
            approval_required_role=f"{Role.SECURITY_MANAGER.value} + {Role.APPROVER.value}",
            production_safety_check=True,
            safety_check_command="/opt/vaultx/scripts/verify_plant_safety_interlock.sh --asset-id %ASSET_ID%",
            max_isolation_duration_hours=8,
            auto_restore=False,
            rollback_procedure=(
                "Clear dynamic ACL rule from core switch 10.10.30.1 and verify "
                "PLC heartbeat with SCADA supervisor"
            ),
            notify_on_isolation=[
                "plant-safety@becpl.in",
                "secops@becpl.in",
                "gm-manufacturing@becpl.in",
            ],
        ),
        IsolationPolicy(
            policy_id=uuid.UUID("11111111-1111-1111-1111-111111111103"),
            policy_name="Vendor Session Kill and Bastion ACL Block",
            target_asset_type="server",
            target_criticality="high",
            isolation_method="firewall_block",
            quarantine_vlan=None,
            requires_human_approval=True,
            approval_required_role=Role.SECURITY_MANAGER.value,
            production_safety_check=False,
            max_isolation_duration_hours=12,
            auto_restore=False,
            rollback_procedure=(
                "Revoke vendor VPN/Teleport session token and drop stateful "
                "connection tracking table on DMZ firewall"
            ),
            notify_on_isolation=["secops@becpl.in", "vendor-governance@becpl.in"],
        ),
        IsolationPolicy(
            policy_id=uuid.UUID("11111111-1111-1111-1111-111111111104"),
            policy_name="Compromised Account Token Revocation",
            target_asset_type=None,
            target_criticality="high",
            isolation_method="acl_block",
            quarantine_vlan=None,
            requires_human_approval=True,
            approval_required_role=Role.APPROVER.value,
            production_safety_check=False,
            max_isolation_duration_hours=48,
            auto_restore=False,
            rollback_procedure=(
                "Re-enable LDAP/AD identity after verified password reset and "
                "MFA re-enrollment"
            ),
            notify_on_isolation=["secops@becpl.in", "hr-compliance@becpl.in"],
        ),
    ]


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------


class ContainmentPolicyEngine:
    """
    Policy-based containment engine governing all BECPL isolation proposals.

    * Hardcoded default mode: ``ContainmentMode.HUMAN_APPROVAL_REQUIRED`` (MODE 3).
    * Mode changes require ``Role.ADMIN``.
    * OT Safety Override is permanently active (``OT_ALWAYS_HUMAN_APPROVAL = True``).
    * Persists proposals to ``becpl_nids.response_actions`` (PostgreSQL when
      connected, plus an in-memory store for inspection and testing).
    """

    def __init__(
        self,
        db_conn: Any | None = None,
        config: ContainmentConfig | None = None,
        policies: list[IsolationPolicy] | None = None,
    ) -> None:
        self._db_conn = db_conn
        self._config = config or ContainmentConfig()
        # Hardcoded default MODE 3 regardless of untrusted external defaults
        self._mode: ContainmentMode = DEFAULT_MODE_ENUM
        self._policies: list[IsolationPolicy] = (
            list(policies) if policies is not None else _default_seed_policies()
        )
        self._proposals: dict[uuid.UUID, ActionProposal] = {}
        self._mode_audit_history: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Mode Management
    # ------------------------------------------------------------------

    @property
    def current_mode(self) -> ContainmentMode:
        return self._mode

    @property
    def config(self) -> ContainmentConfig:
        return self._config

    def set_mode(
        self,
        new_mode: ContainmentMode | str | int,
        actor_role: Role | str,
        actor_identity: str,
        reason: str = "",
    ) -> ContainmentMode:
        """
        Change the containment engine operating mode.
        Strictly restricted to ``Role.ADMIN``.
        """
        role_enum = actor_role if isinstance(actor_role, Role) else Role(str(actor_role).upper())
        if role_enum != Role.ADMIN:
            raise UnauthorizedModeChangeError(
                f"Role {role_enum.value!r} is not authorised to change containment mode. "
                f"Only {Role.ADMIN.value} may reconfigure containment mode."
            )

        resolved_mode = ContainmentMode.from_name(new_mode)
        previous_mode = self._mode
        self._mode = resolved_mode

        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor_identity,
            "actor_role": role_enum.value,
            "previous_mode": previous_mode.name,
            "new_mode": resolved_mode.name,
            "reason": reason,
        }
        self._mode_audit_history.append(audit_entry)
        self._write_mode_change_audit(audit_entry)
        logger.warning(
            "Containment mode changed by %s (%s): %s -> %s (reason=%s)",
            actor_identity,
            role_enum.value,
            previous_mode.name,
            resolved_mode.name,
            reason,
        )
        return self._mode

    # ------------------------------------------------------------------
    # OT Safety & RBAC Determination Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_ot_asset(asset: AffectedAsset) -> bool:
        """
        Return True if the asset belongs to Manufacturing OT (VLAN 30), has
        ``ot_safety_flag=True``, or is an industrial device type.
        """
        return (
            asset.vlan_id == OT_VLAN_ID
            or bool(asset.ot_safety_flag)
            or asset.device_type.strip().lower() in OT_DEVICE_TYPES
            or asset.vlan_name.strip().upper() in {"OT", "MANUFACTURING OT"}
        )

    def determine_required_permissions(
        self,
        asset: AffectedAsset,
        action_category: ActionCategory,
    ) -> tuple[str, bool]:
        """
        Determine the required approver role(s) and whether the two-person rule
        applies for this (asset, action_category) combination.

        Returns
        -------
        (required_permissions_label, two_person_rule_required)
        """
        is_ot = self.is_ot_asset(asset)
        is_critical = asset.criticality == "critical"

        # Two-person rule for CRITICAL OT asset containment
        if is_critical and (is_ot or action_category == ActionCategory.OT_BOUNDARY_RESTRICTION):
            if self._config.two_person_rule_ot:
                return (
                    f"{Role.SECURITY_MANAGER.value} + {Role.APPROVER.value} (two-person rule)",
                    True,
                )

        # Security Manager required for third-party, OT boundary, or any CRITICAL asset
        if (
            action_category in (
                ActionCategory.THIRD_PARTY_CONTAINMENT,
                ActionCategory.OT_BOUNDARY_RESTRICTION,
            )
            or is_critical
            or is_ot
        ):
            return (Role.SECURITY_MANAGER.value, False)

        # Tier-1 actions on non-critical assets may be approved by APPROVER
        return (Role.APPROVER.value, False)

    # ------------------------------------------------------------------
    # Policy Lookup
    # ------------------------------------------------------------------

    def lookup_isolation_policy(
        self,
        asset: AffectedAsset,
        action_category: ActionCategory,
    ) -> IsolationPolicy | None:
        """
        Look up the best-matching isolation policy from PostgreSQL
        ``becpl_nids.isolation_policies`` (falling back to the loaded policy
        catalog when offline).
        """
        policies = self._fetch_policies_from_db() or self._policies
        if not policies:
            return None

        desired_method = {
            ActionCategory.ENDPOINT_QUARANTINE: "vlan_quarantine",
            ActionCategory.IDENTITY_CONTAINMENT: "acl_block",
            ActionCategory.NETWORK_CONTAINMENT: "firewall_block",
            ActionCategory.THIRD_PARTY_CONTAINMENT: "firewall_block",
            ActionCategory.OT_BOUNDARY_RESTRICTION: "acl_block",
        }.get(action_category, "firewall_block")

        is_ot = self.is_ot_asset(asset)
        best_policy: IsolationPolicy | None = None
        best_score = -1

        for policy in policies:
            score = 0
            if is_ot and policy.production_safety_check:
                score += 50
            if policy.target_asset_type and policy.target_asset_type.lower() == asset.device_type.lower():
                score += 30
            if policy.target_criticality and policy.target_criticality.lower() == asset.criticality.lower():
                score += 20
            if policy.isolation_method == desired_method:
                score += 15
            if action_category == ActionCategory.THIRD_PARTY_CONTAINMENT and "vendor" in policy.policy_name.lower():
                score += 40
            if action_category == ActionCategory.IDENTITY_CONTAINMENT and "account" in policy.policy_name.lower():
                score += 40

            if score > best_score:
                best_score = score
                best_policy = policy

        return best_policy

    # ------------------------------------------------------------------
    # Operational Impact Generator
    # ------------------------------------------------------------------

    def _build_operational_impact(
        self,
        asset: AffectedAsset,
        action_category: ActionCategory,
        parameters: dict[str, Any],
    ) -> str:
        is_ot = self.is_ot_asset(asset)
        if action_category == ActionCategory.ENDPOINT_QUARANTINE:
            impact = (
                f"Endpoint {asset.hostname} ({asset.asset_id}) on VLAN {asset.vlan_id} "
                f"({asset.vlan_name}) will be moved to Quarantine VLAN {QUARANTINE_VLAN_ID}. "
                f"User/workload network traffic will be blocked while management access to "
                f"VLAN 70 (Security Management) is preserved."
            )
        elif action_category == ActionCategory.IDENTITY_CONTAINMENT:
            principal = parameters.get("principal_name") or parameters.get("target_identity_id") or "target identity"
            impact = (
                f"Identity '{principal}' will be disabled in LDAP/AD and active sessions "
                f"revoked. User/service will be unable to authenticate until re-enabled."
            )
        elif action_category == ActionCategory.NETWORK_CONTAINMENT:
            src_ip = parameters.get("src_ip", asset.ip_address or "unknown")
            dst_ip = parameters.get("dst_ip", "ANY")
            port = parameters.get("port", "ANY")
            impact = (
                f"Network traffic from {src_ip} to {dst_ip} (port {port}) will be blocked "
                f"via simulated firewall ACL. Dependent sessions on this path will terminate."
            )
        elif action_category == ActionCategory.THIRD_PARTY_CONTAINMENT:
            vendor = parameters.get("vendor_name") or parameters.get("session_id") or "vendor VPN session"
            impact = (
                f"Third-party vendor remote VPN session ({vendor}) will be immediately "
                f"suspended. Scheduled remote vendor maintenance will pause until reinstated."
            )
        elif action_category == ActionCategory.OT_BOUNDARY_RESTRICTION:
            impact = (
                f"IT-to-OT boundary traffic targeting {asset.hostname} ({asset.asset_id}) "
                f"on VLAN {asset.vlan_id} ({asset.vlan_name}) will be restricted to the "
                f"approved Modbus TCP/502 allowlist. Non-approved engineering/IT sessions "
                f"will be dropped; local PLC safety interlocks remain untouched."
            )
        else:
            impact = f"Containment action {action_category.value} will restrict {asset.hostname}."

        if is_ot:
            impact += (
                " [OT SAFETY NOTICE: Target is in Manufacturing OT / carries ot_safety_flag; "
                "human approval and OT/ICS safety verification are mandatory prior to execution.]"
            )
        return impact

    # ------------------------------------------------------------------
    # Template Check for MODE 4 (PRE_APPROVED_AUTOMATION)
    # ------------------------------------------------------------------

    def _matches_pre_approved_template(
        self,
        asset: AffectedAsset,
        action_category: ActionCategory,
        template_id: str | None,
    ) -> bool:
        """
        Check whether the proposed action matches a narrowly pre-scoped,
        pre-tested, pre-approved automation template.
        OT assets are NEVER eligible.
        """
        if self.is_ot_asset(asset):
            return False
        if not template_id or template_id not in PRE_APPROVED_ACTION_TEMPLATES:
            return False

        tpl = PRE_APPROVED_ACTION_TEMPLATES[template_id]
        if not tpl.get("pre_tested", False):
            return False
        if tpl["action_category"] != action_category.value:
            return False
        if asset.vlan_id not in tpl["allowed_vlans"]:
            return False
        if asset.criticality not in tpl["allowed_criticalities"]:
            return False
        return True

    # ------------------------------------------------------------------
    # Core Proposal Entrypoint
    # ------------------------------------------------------------------

    def propose_action(
        self,
        incident_id: uuid.UUID | str,
        affected_asset: AffectedAsset,
        action_category: ActionCategory | str,
        reason_for_isolation: str,
        supporting_evidence: list[str],
        parameters: dict[str, Any] | None = None,
        initiated_by: str = "vaultx-policy-engine",
        target_identity_id: uuid.UUID | str | None = None,
        template_id: str | None = None,
        expected_operational_impact: str | None = None,
        notes: str | None = None,
    ) -> ActionProposal:
        """
        Evaluate containment policy, enforce mode & OT safety override, build a
        fully populated 10-field ``ActionProposal``, and persist it to
        ``becpl_nids.response_actions``.

        Raises
        ------
        DisabledModeError
            If the containment engine is currently in MODE 1 (DISABLED).
        ProposalValidationError
            If required evidence or proposal fields are missing.
        """
        if not OT_ALWAYS_HUMAN_APPROVAL or not self._config.ot_always_human_approval:
            raise SafetyInvariantViolationError("OT_ALWAYS_HUMAN_APPROVAL invariant violated.")

        # MODE 1: DISABLED — detect & record only, containment raises DisabledModeError
        if self._mode == ContainmentMode.DISABLED:
            raise DisabledModeError(
                "Containment engine is in MODE 1 (DISABLED). "
                "Threats are detected and recorded only; containment actions are blocked."
            )

        inc_uuid = (
            incident_id if isinstance(incident_id, uuid.UUID) else uuid.UUID(str(incident_id))
        )
        cat_enum = (
            action_category
            if isinstance(action_category, ActionCategory)
            else ActionCategory(str(action_category).upper())
        )
        identity_uuid: uuid.UUID | None = None
        if target_identity_id is not None:
            identity_uuid = (
                target_identity_id
                if isinstance(target_identity_id, uuid.UUID)
                else uuid.UUID(str(target_identity_id))
            )

        action_params = dict(parameters or {})
        if template_id:
            action_params["template_id"] = template_id

        # Resolve matching isolation policy
        policy = self.lookup_isolation_policy(affected_asset, cat_enum)

        # OT safety override check
        is_ot = self.is_ot_asset(affected_asset)
        ot_override_applied = False

        # RBAC required permissions + two-person rule check
        required_perms, two_person_required = self.determine_required_permissions(
            affected_asset, cat_enum
        )

        # Operational impact statement
        impact_statement = expected_operational_impact or self._build_operational_impact(
            affected_asset, cat_enum, action_params
        )

        # Determine initial execution status based on mode + OT safety override
        now = datetime.now(timezone.utc)
        approver_identity: str | None = None
        approval_method: str | None = None
        approval_timestamp: datetime | None = None
        expires_at: datetime | None = None

        if self._mode == ContainmentMode.MONITOR_ONLY:
            # MODE 2: log recommendation only, never execute
            exec_status = ActionStatus.RECOMMENDED.value
        elif self._mode == ContainmentMode.HUMAN_APPROVAL_REQUIRED:
            # MODE 3 (default): pending human approval
            exec_status = ActionStatus.PENDING.value
            if is_ot:
                ot_override_applied = True
        elif self._mode == ContainmentMode.PRE_APPROVED_AUTOMATION:
            # MODE 4: OT SAFETY OVERRIDE always forces MODE 3 minimum for OT assets
            if is_ot:
                ot_override_applied = True
                exec_status = ActionStatus.PENDING.value
                logger.warning(
                    "OT SAFETY OVERRIDE: Asset %s (VLAN %s, ot_safety_flag=%s) forced to "
                    "HUMAN_APPROVAL_REQUIRED despite active MODE 4 (PRE_APPROVED_AUTOMATION).",
                    affected_asset.asset_id,
                    affected_asset.vlan_id,
                    affected_asset.ot_safety_flag,
                )
            elif self._matches_pre_approved_template(affected_asset, cat_enum, template_id):
                exec_status = ActionStatus.APPROVED.value
                approver_identity = f"auto_policy:{template_id}"
                approval_method = ApprovalMethod.AUTO_POLICY.value
                approval_timestamp = now
                expires_at = now + timedelta(hours=self._config.approval_expiry_hours)
            else:
                # Any non-pre-approved action falls back to human approval
                exec_status = ActionStatus.PENDING.value
        else:
            exec_status = ActionStatus.PENDING.value

        proposed_action_payload = {
            "action_type": cat_enum.value,
            "legacy_action_type": CATEGORY_TO_LEGACY_ACTION_TYPE[cat_enum],
            "parameters": action_params,
        }

        proposal = ActionProposal(
            incident_id=inc_uuid,
            affected_asset=affected_asset,
            affected_network_segment=affected_asset.vlan_name,
            reason_for_isolation=reason_for_isolation,
            supporting_evidence=list(supporting_evidence),
            proposed_action=proposed_action_payload,
            expected_operational_impact=impact_statement,
            required_permissions=required_perms,
            approver_identity=approver_identity,
            execution_status=exec_status,
            action_category=cat_enum,
            isolation_policy_id=policy.policy_id if policy else None,
            isolation_policy_name=policy.policy_name if policy else None,
            initiated_by=initiated_by,
            target_identity_id=identity_uuid,
            target_ip=action_params.get("src_ip") or affected_asset.ip_address,
            approval_method=approval_method,
            approval_timestamp=approval_timestamp,
            ot_safety_override_applied=ot_override_applied,
            two_person_rule_required=two_person_required,
            containment_mode=self._mode,
            created_at=now,
            expires_at=expires_at,
            notes=notes,
        )

        # Validate all 10 mandatory fields before persisting
        proposal.validate_mandatory_fields()

        # Store in memory & persist to PostgreSQL response_actions
        self._proposals[proposal.action_id] = proposal
        self._persist_proposal(proposal)

        logger.info(
            "ActionProposal created: action_id=%s category=%s asset=%s status=%s mode=%s ot_override=%s",
            proposal.action_id,
            cat_enum.value,
            affected_asset.asset_id,
            proposal.execution_status,
            self._mode.name,
            ot_override_applied,
        )
        return proposal

    # ------------------------------------------------------------------
    # Retrieval Helpers
    # ------------------------------------------------------------------

    def get_proposal(self, action_id: uuid.UUID | str) -> ActionProposal | None:
        target_id = action_id if isinstance(action_id, uuid.UUID) else uuid.UUID(str(action_id))
        return self._proposals.get(target_id)

    def list_proposals(self, status: str | None = None) -> list[ActionProposal]:
        items = list(self._proposals.values())
        if status:
            items = [p for p in items if p.execution_status == status]
        return items

    def register_proposal(self, proposal: ActionProposal) -> None:
        """Register an existing proposal into the in-memory store."""
        self._proposals[proposal.action_id] = proposal

    # ------------------------------------------------------------------
    # PostgreSQL Persistence Helpers
    # ------------------------------------------------------------------

    def _fetch_policies_from_db(self) -> list[IsolationPolicy]:
        if self._db_conn is None:
            return []
        sql = f"""
            SELECT policy_id, policy_name, target_asset_type, target_criticality,
                   isolation_method, quarantine_vlan, requires_human_approval,
                   approval_required_role, production_safety_check, safety_check_command,
                   max_isolation_duration_hours, auto_restore, rollback_procedure,
                   notify_on_isolation
              FROM {DB_SCHEMA}.isolation_policies
        """
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(sql)
                rows = cur.fetchall()
            policies: list[IsolationPolicy] = []
            for row in rows:
                policies.append(
                    IsolationPolicy(
                        policy_id=uuid.UUID(str(row[0])),
                        policy_name=row[1],
                        target_asset_type=row[2],
                        target_criticality=row[3],
                        isolation_method=row[4],
                        quarantine_vlan=row[5],
                        requires_human_approval=bool(row[6]),
                        approval_required_role=row[7] or Role.APPROVER.value,
                        production_safety_check=bool(row[8]),
                        safety_check_command=row[9],
                        max_isolation_duration_hours=row[10] or 24,
                        auto_restore=bool(row[11]),
                        rollback_procedure=row[12] or "",
                        notify_on_isolation=list(row[13] or []),
                    )
                )
            return policies
        except Exception as exc:
            logger.warning("Could not fetch isolation_policies from PostgreSQL: %s", exc)
            return []

    def _persist_proposal(self, proposal: ActionProposal) -> None:
        if self._db_conn is None:
            return
        sql = f"""
            INSERT INTO {DB_SCHEMA}.response_actions (
                action_id, incident_id, action_type, target_asset_id,
                target_identity_id, target_ip, isolation_policy_id,
                initiated_by, approved_by, approval_method, approval_timestamp,
                status, execution_detail, notes, break_glass_used, second_approver,
                action_proposal, expires_at, ot_safety_override, created_at
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s::jsonb, %s, %s, %s,
                %s::jsonb, %s, %s, %s
            )
            ON CONFLICT (action_id) DO UPDATE SET
                status = EXCLUDED.status,
                approved_by = EXCLUDED.approved_by,
                approval_method = EXCLUDED.approval_method,
                approval_timestamp = EXCLUDED.approval_timestamp,
                action_proposal = EXCLUDED.action_proposal,
                expires_at = EXCLUDED.expires_at
        """
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(
                    sql,
                    (
                        str(proposal.action_id),
                        str(proposal.incident_id),
                        proposal.action_category.value,
                        proposal.affected_asset.asset_id,
                        str(proposal.target_identity_id) if proposal.target_identity_id else None,
                        proposal.target_ip,
                        str(proposal.isolation_policy_id) if proposal.isolation_policy_id else None,
                        proposal.initiated_by,
                        proposal.approver_identity,
                        proposal.approval_method,
                        proposal.approval_timestamp,
                        proposal.execution_status,
                        json.dumps({"proposed_action": proposal.proposed_action}, default=str),
                        proposal.notes or proposal.reason_for_isolation,
                        proposal.break_glass_used,
                        proposal.second_approver,
                        json.dumps(proposal.to_dict(), default=str),
                        proposal.expires_at,
                        proposal.ot_safety_override_applied,
                        proposal.created_at,
                    ),
                )
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to persist ActionProposal %s to PostgreSQL: %s", proposal.action_id, exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass

    def _write_mode_change_audit(self, entry: dict[str, Any]) -> None:
        if self._db_conn is None:
            return
        sql = f"""
            INSERT INTO {DB_SCHEMA}.audit_log (
                actor, actor_type, action, target_table, target_id,
                old_value, new_value, outcome
            ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s)
        """
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(
                    sql,
                    (
                        entry["actor"],
                        "human_operator",
                        "CONTAINMENT_MODE_CHANGED",
                        "containment_config",
                        "global_mode",
                        json.dumps({"mode": entry["previous_mode"]}),
                        json.dumps({"mode": entry["new_mode"], "reason": entry["reason"]}),
                        "success",
                    ),
                )
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to write containment mode audit log: %s", exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass
