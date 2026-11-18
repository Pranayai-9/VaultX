"""
approval_engine.py — Human-in-the-Loop Approval & Authentication Engine for
VaultX Phase 2.

Enforces role-based access control (RBAC), simulated MFA verification,
two-person approval for CRITICAL OT containment, 4-hour approval expiry,
reversible action policy mapping, emergency break-glass override with elevated
audit trail & admin alerting, and tamper-evident audit logging.

RBAC Policy
-----------
* ``ANALYST``          : Read-only; cannot propose or approve.
* ``OPERATOR``         : Can propose containment actions; cannot approve.
* ``APPROVER``         : Can approve tier-1 actions (``ENDPOINT_QUARANTINE``,
                         ``IDENTITY_CONTAINMENT``, ``NETWORK_CONTAINMENT``)
                         for non-critical assets.
* ``SECURITY_MANAGER`` : Required for ``THIRD_PARTY_CONTAINMENT``,
                         ``OT_BOUNDARY_RESTRICTION``, and any action on
                         ``CRITICAL`` assets; can approve any action.
* ``ADMIN``            : Can modify system configuration and invoke emergency
                         break-glass with valid ``BREAK_GLASS_HASH`` code.

Two-Person Rule
---------------
Any containment action targeting a ``CRITICAL`` OT asset requires TWO distinct
authenticated approvers: a ``SECURITY_MANAGER`` AND a second ``APPROVER``
(or second ``SECURITY_MANAGER``).
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from backend.containment.containment_config import (
    ActionCategory,
    ActionStatus,
    ApprovalMethod,
    ContainmentConfig,
    DB_SCHEMA,
    OT_VLAN_ID,
    REDIS_STREAM_CONTAINMENT_ALERTS,
    Role,
)
from backend.containment.policy_engine import ActionProposal, ContainmentPolicyEngine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AuthorizationError(PermissionError):
    """Raised when an actor lacks RBAC permission for the requested action."""


class AuthenticationError(PermissionError):
    """Raised when approver identity lookup or MFA token validation fails."""


class ActionNotFoundError(LookupError):
    """Raised when a target response action cannot be found."""


class ActionExpiredError(RuntimeError):
    """Raised when an approved action has exceeded the 4-hour execution window."""


class InvalidBreakGlassError(PermissionError):
    """Raised when an invalid or unconfigured break-glass code is supplied."""


class InvalidStateTransitionError(ValueError):
    """Raised when an approval/rejection is attempted on an incompatible status."""


# ---------------------------------------------------------------------------
# Reversible Policy Registry (Every Action Category Has a Defined Reverse Action)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReverseActionSpec:
    """Defines the exact reverse/rollback policy for a containment action category."""

    action_category: ActionCategory
    reverse_action_type: str
    adapter_method: str
    description: str
    requires_safety_verification: bool = False


REVERSE_ACTION_MAP: dict[ActionCategory, ReverseActionSpec] = {
    ActionCategory.ENDPOINT_QUARANTINE: ReverseActionSpec(
        action_category=ActionCategory.ENDPOINT_QUARANTINE,
        reverse_action_type="RESTORE_ENDPOINT_VLAN",
        adapter_method="EndpointQuarantineAdapter.rollback",
        description=(
            "Remove endpoint from Quarantine VLAN 999, close quarantine_records entry, "
            "and restore original production VLAN assignment."
        ),
    ),
    ActionCategory.IDENTITY_CONTAINMENT: ReverseActionSpec(
        action_category=ActionCategory.IDENTITY_CONTAINMENT,
        reverse_action_type="REENABLE_IDENTITY",
        adapter_method="IdentityAdapter.rollback",
        description=(
            "Set identities.is_active = TRUE in PostgreSQL / LDAP after credential reset "
            "and log restoration to audit_log."
        ),
    ),
    ActionCategory.NETWORK_CONTAINMENT: ReverseActionSpec(
        action_category=ActionCategory.NETWORK_CONTAINMENT,
        reverse_action_type="REMOVE_FIREWALL_BLOCK_RULE",
        adapter_method="FirewallAdapter.rollback",
        description=(
            "Deactivate the simulated firewall block rule (active = FALSE, "
            "rolled_back_at = NOW()) and restore normal routing."
        ),
    ),
    ActionCategory.THIRD_PARTY_CONTAINMENT: ReverseActionSpec(
        action_category=ActionCategory.THIRD_PARTY_CONTAINMENT,
        reverse_action_type="RESTORE_VENDOR_VPN_ACCESS",
        adapter_method="VPNAdapter.rollback",
        description=(
            "Lift vendor VPN peer suspension in vendor_sessions after vendor "
            "re-verification and MFA re-authentication."
        ),
    ),
    ActionCategory.OT_BOUNDARY_RESTRICTION: ReverseActionSpec(
        action_category=ActionCategory.OT_BOUNDARY_RESTRICTION,
        reverse_action_type="RESTORE_OT_BOUNDARY_POLICY",
        adapter_method="OTBoundaryAdapter.rollback",
        description=(
            "Remove temporary Modbus TCP/502 emergency restriction rules from "
            "simulated_firewall_rules after OT/ICS engineer safety verification."
        ),
        requires_safety_verification=True,
    ),
}


def get_reverse_action(action_category: ActionCategory | str) -> ReverseActionSpec:
    """Return the defined reverse action specification for any containment category."""
    cat = (
        action_category
        if isinstance(action_category, ActionCategory)
        else ActionCategory(str(action_category).upper())
    )
    return REVERSE_ACTION_MAP[cat]


# ---------------------------------------------------------------------------
# Identity Record & Result Models
# ---------------------------------------------------------------------------


@dataclass
class IdentityRecord:
    """Minimal representation of a row in ``becpl_nids.identities``."""

    identity_id: uuid.UUID
    principal_name: str
    role: Role
    is_active: bool = True
    mfa_enrolled: bool = True
    email: str | None = None
    department: str | None = None


@dataclass
class ApprovalResult:
    """Outcome of an approval, partial two-person approval, rejection, or break-glass call."""

    action_id: uuid.UUID
    status: str
    approved: bool
    awaiting_second_approver: bool = False
    approved_by: str | None = None
    second_approver: str | None = None
    approval_method: str | None = None
    approval_timestamp: datetime | None = None
    expires_at: datetime | None = None
    break_glass_used: bool = False
    reverse_action: ReverseActionSpec | None = None
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": str(self.action_id),
            "status": self.status,
            "approved": self.approved,
            "awaiting_second_approver": self.awaiting_second_approver,
            "approved_by": self.approved_by,
            "second_approver": self.second_approver,
            "approval_method": self.approval_method,
            "approval_timestamp": (
                self.approval_timestamp.isoformat() if self.approval_timestamp else None
            ),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "break_glass_used": self.break_glass_used,
            "reverse_action": (
                self.reverse_action.reverse_action_type if self.reverse_action else None
            ),
            "message": self.message,
        }


# ---------------------------------------------------------------------------
# RBAC Constants
# ---------------------------------------------------------------------------

TIER1_APPROVER_CATEGORIES: frozenset[ActionCategory] = frozenset(
    {
        ActionCategory.ENDPOINT_QUARANTINE,
        ActionCategory.IDENTITY_CONTAINMENT,
        ActionCategory.NETWORK_CONTAINMENT,
    }
)

SECURITY_MANAGER_ONLY_CATEGORIES: frozenset[ActionCategory] = frozenset(
    {
        ActionCategory.THIRD_PARTY_CONTAINMENT,
        ActionCategory.OT_BOUNDARY_RESTRICTION,
    }
)

MFA_SIMULATION_PATTERN = re.compile(r"^1\d{5}$")


# ---------------------------------------------------------------------------
# Approval Engine
# ---------------------------------------------------------------------------


class ApprovalEngine:
    """
    Human-in-the-loop approval and authentication engine for VaultX containment.

    Parameters
    ----------
    policy_engine : ContainmentPolicyEngine
        Source of proposals to inspect and update.
    db_conn : optional DB-API 2.0 connection
        PostgreSQL connection for ``identities``, ``response_actions``, and ``audit_log``.
    redis_client : optional Redis client
        Used to publish emergency break-glass alerts to ``containment:alerts``.
    config : ContainmentConfig | None
        Runtime safety configuration (4h expiry, break-glass hash, two-person rule).
    identities : dict[str, IdentityRecord] | None
        Optional in-memory identity directory keyed by ``principal_name`` (used
        when PostgreSQL is offline or during unit testing).
    admin_alert_callback : callable | None
        Optional callback invoked with alert payload dict when break-glass fires.
    """

    def __init__(
        self,
        policy_engine: ContainmentPolicyEngine,
        db_conn: Any | None = None,
        redis_client: Any | None = None,
        config: ContainmentConfig | None = None,
        identities: dict[str, IdentityRecord] | None = None,
        admin_alert_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._policy_engine = policy_engine
        self._db_conn = db_conn
        self._redis = redis_client
        self._config = config or policy_engine.config
        self._identities: dict[str, IdentityRecord] = dict(identities or {})
        self._admin_alert_callback = admin_alert_callback
        self._audit_records: list[dict[str, Any]] = []
        self._admin_alerts: list[dict[str, Any]] = []
        # Track two-person rule partial approvals: action_id -> list of (principal, role)
        self._partial_approvals: dict[uuid.UUID, list[tuple[str, Role]]] = {}

    # ------------------------------------------------------------------
    # Identity Registry Helpers
    # ------------------------------------------------------------------

    def register_identity(self, record: IdentityRecord) -> None:
        """Register an identity in the local directory (for tests / lab mode)."""
        self._identities[record.principal_name] = record

    def _lookup_identity(self, principal_name: str) -> IdentityRecord:
        """
        Look up an approver identity in PostgreSQL ``becpl_nids.identities``
        (falling back to the registered in-memory identity store).
        """
        if self._db_conn is not None:
            sql = f"""
                SELECT identity_id, principal_name, is_active, mfa_enrolled,
                       email, department, is_privileged
                  FROM {DB_SCHEMA}.identities
                 WHERE principal_name = %s
                 LIMIT 1
            """
            try:
                with self._db_conn.cursor() as cur:
                    cur.execute(sql, (principal_name,))
                    row = cur.fetchone()
                if row is not None:
                    # Prefer role from in-memory map if supplied; otherwise infer from privilege
                    local = self._identities.get(principal_name)
                    inferred_role = (
                        local.role
                        if local
                        else (Role.SECURITY_MANAGER if row[6] else Role.APPROVER)
                    )
                    return IdentityRecord(
                        identity_id=uuid.UUID(str(row[0])),
                        principal_name=row[1],
                        role=inferred_role,
                        is_active=bool(row[2]),
                        mfa_enrolled=bool(row[3]),
                        email=row[4],
                        department=row[5],
                    )
            except Exception as exc:
                logger.warning("Identity DB lookup failed for %s: %s", principal_name, exc)

        record = self._identities.get(principal_name)
        if record is None:
            raise AuthenticationError(
                f"Approver identity {principal_name!r} not found in identities table."
            )
        return record

    # ------------------------------------------------------------------
    # MFA Simulation Validation
    # ------------------------------------------------------------------

    @staticmethod
    def validate_mfa_token(mfa_token: str | None) -> bool:
        """
        Validate simulated 6-digit MFA token.
        In VaultX simulation mode, any 6-digit numeric code starting with '1'
        (e.g. ``123456``) is accepted as valid MFA.
        """
        if not mfa_token or not isinstance(mfa_token, str):
            return False
        return bool(MFA_SIMULATION_PATTERN.match(mfa_token.strip()))

    # ------------------------------------------------------------------
    # RBAC Enforcement Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def can_propose(role: Role | str) -> bool:
        """Return True if the role is permitted to propose containment actions."""
        r = role if isinstance(role, Role) else Role(str(role).upper())
        return r in {Role.OPERATOR, Role.APPROVER, Role.SECURITY_MANAGER, Role.ADMIN}

    def _is_critical_ot_action(self, proposal: ActionProposal) -> bool:
        is_ot = (
            proposal.affected_asset.vlan_id == OT_VLAN_ID
            or proposal.affected_asset.ot_safety_flag
            or proposal.action_category == ActionCategory.OT_BOUNDARY_RESTRICTION
        )
        return is_ot and proposal.affected_asset.criticality == "critical"

    def _validate_approver_rbac(
        self,
        proposal: ActionProposal,
        approver_role: Role,
        is_second_approver_slot: bool = False,
    ) -> None:
        """
        Verify whether ``approver_role`` has authority to approve ``proposal``.
        Raises ``AuthorizationError`` on violation.
        """
        if approver_role in (Role.ANALYST, Role.OPERATOR):
            raise AuthorizationError(
                f"Role {approver_role.value} is not authorised to approve containment actions."
            )

        if approver_role == Role.ADMIN:
            raise AuthorizationError(
                "ADMIN role manages system configuration; standard containment approval "
                "requires APPROVER or SECURITY_MANAGER (use break_glass_approve for emergencies)."
            )

        if approver_role == Role.SECURITY_MANAGER:
            # SECURITY_MANAGER can approve any action category & criticality
            return

        # Approver role checks
        if approver_role == Role.APPROVER:
            # For two-person CRITICAL OT rule, APPROVER is permitted as the second approver
            if self._is_critical_ot_action(proposal) and self._config.two_person_rule_ot:
                if is_second_approver_slot:
                    return
                # Allow APPROVER to sign first only if SECURITY_MANAGER still signs second
                return

            if proposal.action_category in SECURITY_MANAGER_ONLY_CATEGORIES:
                raise AuthorizationError(
                    f"Action category {proposal.action_category.value} requires "
                    f"{Role.SECURITY_MANAGER.value} approval; {Role.APPROVER.value} is insufficient."
                )

            if proposal.affected_asset.criticality == "critical":
                raise AuthorizationError(
                    f"Asset {proposal.affected_asset.asset_id} has CRITICAL criticality; "
                    f"requires {Role.SECURITY_MANAGER.value} approval."
                )

            if proposal.action_category not in TIER1_APPROVER_CATEGORIES:
                raise AuthorizationError(
                    f"APPROVER cannot approve {proposal.action_category.value}."
                )
            return

        raise AuthorizationError(f"Unhandled role {approver_role!r}.")

    # ------------------------------------------------------------------
    # Action Expiry Management (4-hour window)
    # ------------------------------------------------------------------

    def is_action_expired(
        self,
        proposal: ActionProposal,
        now: datetime | None = None,
    ) -> bool:
        """
        Check whether an approved action has passed its expiry deadline
        (4 hours after approval).
        """
        if proposal.execution_status == ActionStatus.EXPIRED.value:
            return True
        if proposal.execution_status != ActionStatus.APPROVED.value:
            return False

        current = now or datetime.now(timezone.utc)
        if proposal.expires_at is not None:
            return current >= proposal.expires_at
        if proposal.approval_timestamp is not None:
            deadline = proposal.approval_timestamp + timedelta(
                hours=self._config.approval_expiry_hours
            )
            return current >= deadline
        return False

    def expire_if_needed(
        self,
        proposal: ActionProposal,
        now: datetime | None = None,
    ) -> bool:
        """
        If ``proposal`` is approved and past its 4-hour window, transition it to
        ``status='expired'``, persist to DB, and write an audit log entry.
        """
        if not self.is_action_expired(proposal, now=now):
            return False
        if proposal.execution_status != ActionStatus.EXPIRED.value:
            old_status = proposal.execution_status
            proposal.execution_status = ActionStatus.EXPIRED.value
            self._persist_approval_update(proposal)
            self.write_audit_log(
                actor="vaultx-approval-engine",
                actor_type="system",
                action="CONTAINMENT_ACTION_EXPIRED",
                target_table="response_actions",
                target_id=str(proposal.action_id),
                old_value={"status": old_status},
                new_value={
                    "status": ActionStatus.EXPIRED.value,
                    "expiry_hours": self._config.approval_expiry_hours,
                },
                outcome="success",
            )
            logger.warning("Containment action %s expired after %dh.", proposal.action_id, self._config.approval_expiry_hours)
        return True

    def check_and_expire_actions(self, now: datetime | None = None) -> list[uuid.UUID]:
        """Scan all tracked actions and expire any approved actions older than 4 hours."""
        expired_ids: list[uuid.UUID] = []
        for proposal in self._policy_engine.list_proposals(status=ActionStatus.APPROVED.value):
            if self.expire_if_needed(proposal, now=now):
                expired_ids.append(proposal.action_id)
        return expired_ids

    # ------------------------------------------------------------------
    # Standard Human-in-the-Loop Approval
    # ------------------------------------------------------------------

    def approve_action(
        self,
        action_id: uuid.UUID | str,
        approver_identity: str,
        approver_role: Role | str,
        mfa_token: str,
        approval_method: ApprovalMethod | str = ApprovalMethod.MFA_TOKEN,
        notes: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalResult:
        """
        Authenticate and authorise a human approver to approve a pending
        containment action.

        Enforces:
        1. Approver exists & is active in ``identities`` table.
        2. Valid simulated 6-digit MFA token starting with ``'1'``.
        3. RBAC check (APPROVER vs SECURITY_MANAGER).
        4. Two-person rule for CRITICAL OT assets (requires both a
           ``SECURITY_MANAGER`` and a second distinct ``APPROVER`` / manager).
        5. Writes approval record to ``response_actions`` and ``audit_log``.
        """
        target_id = action_id if isinstance(action_id, uuid.UUID) else uuid.UUID(str(action_id))
        proposal = self._policy_engine.get_proposal(target_id)
        if proposal is None:
            raise ActionNotFoundError(f"Containment action {target_id} not found.")

        if proposal.execution_status != ActionStatus.PENDING.value:
            raise InvalidStateTransitionError(
                f"Cannot approve action {target_id} in status {proposal.execution_status!r}. "
                f"Only 'pending' actions may be approved."
            )

        role_enum = (
            approver_role if isinstance(approver_role, Role) else Role(str(approver_role).upper())
        )
        method_enum = (
            approval_method
            if isinstance(approval_method, ApprovalMethod)
            else ApprovalMethod(str(approval_method).lower())
        )

        # 1. Authenticate approver in identities table
        identity = self._lookup_identity(approver_identity)
        if not identity.is_active:
            self.write_audit_log(
                actor=approver_identity,
                actor_type="human_operator",
                action="CONTAINMENT_APPROVAL_DENIED",
                target_table="response_actions",
                target_id=str(target_id),
                new_value={"reason": "identity_inactive"},
                outcome="failure",
                failure_reason="Approver identity is disabled",
            )
            raise AuthenticationError(f"Approver identity {approver_identity!r} is not active.")

        # 2. Validate MFA token
        if not self.validate_mfa_token(mfa_token):
            self.write_audit_log(
                actor=approver_identity,
                actor_type="human_operator",
                action="CONTAINMENT_MFA_FAILED",
                target_table="response_actions",
                target_id=str(target_id),
                new_value={"approver": approver_identity, "role": role_enum.value},
                outcome="failure",
                failure_reason="Invalid simulated MFA token",
            )
            raise AuthenticationError(
                "Invalid MFA token. Simulated MFA requires a 6-digit numeric token starting with '1'."
            )

        # 3. RBAC validation
        existing_sigs = self._partial_approvals.get(target_id, [])
        try:
            self._validate_approver_rbac(
                proposal,
                role_enum,
                is_second_approver_slot=len(existing_sigs) > 0,
            )
        except AuthorizationError as exc:
            self.write_audit_log(
                actor=approver_identity,
                actor_type="human_operator",
                action="CONTAINMENT_APPROVAL_UNAUTHORIZED",
                target_table="response_actions",
                target_id=str(target_id),
                new_value={"role": role_enum.value, "required": proposal.required_permissions},
                outcome="failure",
                failure_reason=str(exc),
            )
            raise

        timestamp = now or datetime.now(timezone.utc)
        reverse_spec = get_reverse_action(proposal.action_category)

        # 4. Two-person rule check for CRITICAL OT containment
        requires_two_person = (
            proposal.two_person_rule_required
            or (self._is_critical_ot_action(proposal) and self._config.two_person_rule_ot)
        )

        if requires_two_person:
            # Ensure distinct identities for two-person rule
            if any(p == approver_identity for p, _ in existing_sigs):
                raise AuthorizationError(
                    f"Two-person rule violation: {approver_identity!r} already provided "
                    f"the first approval for {target_id}. A distinct second approver is required."
                )

            updated_sigs = existing_sigs + [(approver_identity, role_enum)]
            self._partial_approvals[target_id] = updated_sigs

            roles_present = [r for _, r in updated_sigs]
            has_security_manager = Role.SECURITY_MANAGER in roles_present
            has_two_people = len(updated_sigs) >= 2

            if not (has_two_people and has_security_manager):
                # Record first signature, remain pending until second distinct approver signs
                proposal.approver_identity = updated_sigs[0][0]
                if len(updated_sigs) >= 2:
                    proposal.second_approver = updated_sigs[1][0]
                self._persist_approval_update(proposal)
                self.write_audit_log(
                    actor=approver_identity,
                    actor_type="human_operator",
                    action="CONTAINMENT_TWO_PERSON_PARTIAL_APPROVAL",
                    target_table="response_actions",
                    target_id=str(target_id),
                    old_value={"status": ActionStatus.PENDING.value},
                    new_value={
                        "status": ActionStatus.PENDING.value,
                        "signers": [(p, r.value) for p, r in updated_sigs],
                        "approval_method": method_enum.value,
                    },
                    outcome="partial",
                )
                needed = (
                    Role.APPROVER.value
                    if has_security_manager
                    else Role.SECURITY_MANAGER.value
                )
                return ApprovalResult(
                    action_id=target_id,
                    status=ActionStatus.PENDING.value,
                    approved=False,
                    awaiting_second_approver=True,
                    approved_by=proposal.approver_identity,
                    second_approver=proposal.second_approver,
                    approval_method=method_enum.value,
                    approval_timestamp=timestamp,
                    reverse_action=reverse_spec,
                    message=(
                        f"First approval recorded by {approver_identity} ({role_enum.value}). "
                        f"Two-person rule for CRITICAL OT requires a second distinct {needed}."
                    ),
                )

            # Both distinct approvers (including a SECURITY_MANAGER) have signed!
            proposal.approver_identity = updated_sigs[0][0]
            proposal.second_approver = updated_sigs[1][0]
        else:
            proposal.approver_identity = approver_identity

        # Finalize approval
        proposal.execution_status = ActionStatus.APPROVED.value
        proposal.approval_method = method_enum.value
        proposal.approval_timestamp = timestamp
        proposal.expires_at = timestamp + timedelta(hours=self._config.approval_expiry_hours)
        if notes:
            proposal.notes = f"{proposal.notes} | {notes}" if proposal.notes else notes

        self._persist_approval_update(proposal)
        self.write_audit_log(
            actor=approver_identity,
            actor_type="human_operator",
            action="CONTAINMENT_ACTION_APPROVED",
            target_table="response_actions",
            target_id=str(target_id),
            old_value={"status": ActionStatus.PENDING.value},
            new_value={
                "status": ActionStatus.APPROVED.value,
                "approved_by": proposal.approver_identity,
                "second_approver": proposal.second_approver,
                "approval_method": method_enum.value,
                "expires_at": proposal.expires_at.isoformat(),
                "reverse_action": reverse_spec.reverse_action_type,
            },
            outcome="success",
        )

        logger.info(
            "Action %s APPROVED by %s (second=%s, method=%s, expires=%s)",
            target_id,
            proposal.approver_identity,
            proposal.second_approver,
            method_enum.value,
            proposal.expires_at.isoformat(),
        )
        return ApprovalResult(
            action_id=target_id,
            status=ActionStatus.APPROVED.value,
            approved=True,
            awaiting_second_approver=False,
            approved_by=proposal.approver_identity,
            second_approver=proposal.second_approver,
            approval_method=method_enum.value,
            approval_timestamp=timestamp,
            expires_at=proposal.expires_at,
            reverse_action=reverse_spec,
            message=f"Containment action {target_id} approved and ready for execution.",
        )

    # ------------------------------------------------------------------
    # Rejection Workflow
    # ------------------------------------------------------------------

    def reject_action(
        self,
        action_id: uuid.UUID | str,
        actor_identity: str,
        actor_role: Role | str,
        reason: str,
    ) -> ApprovalResult:
        """Reject a pending containment proposal and write an audit log entry."""
        target_id = action_id if isinstance(action_id, uuid.UUID) else uuid.UUID(str(action_id))
        proposal = self._policy_engine.get_proposal(target_id)
        if proposal is None:
            raise ActionNotFoundError(f"Containment action {target_id} not found.")

        role_enum = actor_role if isinstance(actor_role, Role) else Role(str(actor_role).upper())
        if role_enum == Role.ANALYST:
            raise AuthorizationError("ANALYST role is read-only and cannot reject actions.")

        if proposal.execution_status not in (
            ActionStatus.PENDING.value,
            ActionStatus.RECOMMENDED.value,
        ):
            raise InvalidStateTransitionError(
                f"Cannot reject action {target_id} in status {proposal.execution_status!r}."
            )

        old_status = proposal.execution_status
        proposal.execution_status = ActionStatus.REJECTED.value
        proposal.notes = f"Rejected by {actor_identity}: {reason}"
        self._partial_approvals.pop(target_id, None)
        self._persist_approval_update(proposal)

        self.write_audit_log(
            actor=actor_identity,
            actor_type="human_operator",
            action="CONTAINMENT_ACTION_REJECTED",
            target_table="response_actions",
            target_id=str(target_id),
            old_value={"status": old_status},
            new_value={"status": ActionStatus.REJECTED.value, "reason": reason},
            outcome="success",
        )
        return ApprovalResult(
            action_id=target_id,
            status=ActionStatus.REJECTED.value,
            approved=False,
            message=f"Containment action {target_id} rejected by {actor_identity}: {reason}",
        )

    # ------------------------------------------------------------------
    # Emergency Override (Break-Glass)
    # ------------------------------------------------------------------

    def break_glass_approve(
        self,
        action_id: uuid.UUID | str,
        actor_identity: str,
        break_glass_code: str,
        reason: str,
        executor_callback: Callable[[uuid.UUID], Any] | None = None,
        now: datetime | None = None,
    ) -> ApprovalResult:
        """
        Emergency break-glass override:
        1. Validates ``break_glass_code`` against SHA-256 ``BREAK_GLASS_HASH`` env var.
        2. Marks action ``approved`` with ``approval_method='break_glass'`` and
           ``break_glass_used=True``.
        3. Writes an ELEVATED audit trail entry.
        4. Alerts all system admins (via Redis stream + callback + admin alerts log).
        5. If ``executor_callback`` is provided, triggers immediate execution.
        """
        target_id = action_id if isinstance(action_id, uuid.UUID) else uuid.UUID(str(action_id))
        proposal = self._policy_engine.get_proposal(target_id)
        if proposal is None:
            raise ActionNotFoundError(f"Containment action {target_id} not found.")

        if not self._config.verify_break_glass_code(break_glass_code):
            self.write_audit_log(
                actor=actor_identity,
                actor_type="human_operator",
                action="CONTAINMENT_BREAK_GLASS_FAILED",
                target_table="response_actions",
                target_id=str(target_id),
                new_value={"severity": "CRITICAL", "reason": reason},
                outcome="failure",
                failure_reason="Invalid break-glass emergency code",
            )
            raise InvalidBreakGlassError(
                "Break-glass emergency code verification failed against BREAK_GLASS_HASH."
            )

        timestamp = now or datetime.now(timezone.utc)
        old_status = proposal.execution_status
        proposal.approver_identity = actor_identity
        proposal.approval_method = ApprovalMethod.BREAK_GLASS.value
        proposal.approval_timestamp = timestamp
        proposal.expires_at = timestamp + timedelta(hours=self._config.approval_expiry_hours)
        proposal.break_glass_used = True
        proposal.execution_status = ActionStatus.APPROVED.value
        proposal.notes = f"[BREAK-GLASS OVERRIDE by {actor_identity}] {reason}"

        self._persist_approval_update(proposal)

        # Elevated audit trail
        self.write_audit_log(
            actor=actor_identity,
            actor_type="human_operator",
            action="CONTAINMENT_BREAK_GLASS_OVERRIDE",
            target_table="response_actions",
            target_id=str(target_id),
            old_value={"status": old_status},
            new_value={
                "audit_level": "ELEVATED_CRITICAL",
                "status": ActionStatus.APPROVED.value,
                "approval_method": ApprovalMethod.BREAK_GLASS.value,
                "break_glass_used": True,
                "reason": reason,
                "asset_id": proposal.affected_asset.asset_id,
                "vlan_id": proposal.affected_asset.vlan_id,
                "action_category": proposal.action_category.value,
            },
            outcome="success",
        )

        # Alert all admins
        admin_alert = {
            "alert_type": "BREAK_GLASS_EMERGENCY_OVERRIDE",
            "severity": "critical",
            "timestamp": timestamp.isoformat(),
            "action_id": str(target_id),
            "incident_id": str(proposal.incident_id),
            "actor": actor_identity,
            "target_asset_id": proposal.affected_asset.asset_id,
            "target_vlan": proposal.affected_asset.vlan_id,
            "action_category": proposal.action_category.value,
            "reason": reason,
            "recipients": ["ALL_ADMINS", "CISO", "secops@becpl.in", "plant-safety@becpl.in"],
        }
        self._notify_all_admins(admin_alert)

        if executor_callback is not None:
            executor_callback(target_id)

        reverse_spec = get_reverse_action(proposal.action_category)
        return ApprovalResult(
            action_id=target_id,
            status=proposal.execution_status,
            approved=True,
            approved_by=actor_identity,
            approval_method=ApprovalMethod.BREAK_GLASS.value,
            approval_timestamp=timestamp,
            expires_at=proposal.expires_at,
            break_glass_used=True,
            reverse_action=reverse_spec,
            message=(
                f"BREAK-GLASS override accepted for action {target_id} by {actor_identity}. "
                f"Elevated audit logged and all admins alerted."
            ),
        )

    # ------------------------------------------------------------------
    # Audit Logging & Admin Alerting
    # ------------------------------------------------------------------

    def write_audit_log(
        self,
        actor: str,
        actor_type: str,
        action: str,
        target_table: str,
        target_id: str,
        old_value: dict[str, Any] | None = None,
        new_value: dict[str, Any] | None = None,
        outcome: str = "success",
        failure_reason: str | None = None,
    ) -> dict[str, Any]:
        """Write an audit record to memory and ``becpl_nids.audit_log``."""
        record = {
            "audit_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "actor_type": actor_type,
            "action": action,
            "target_table": target_table,
            "target_id": target_id,
            "old_value": old_value,
            "new_value": new_value,
            "outcome": outcome,
            "failure_reason": failure_reason,
        }
        self._audit_records.append(record)

        if self._db_conn is not None:
            sql = f"""
                INSERT INTO {DB_SCHEMA}.audit_log (
                    actor, actor_type, action, target_table, target_id,
                    old_value, new_value, outcome, failure_reason
                ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s)
            """
            try:
                with self._db_conn.cursor() as cur:
                    cur.execute(
                        sql,
                        (
                            actor,
                            actor_type,
                            action,
                            target_table,
                            target_id,
                            json.dumps(old_value, default=str) if old_value is not None else None,
                            json.dumps(new_value, default=str) if new_value is not None else None,
                            outcome,
                            failure_reason,
                        ),
                    )
                self._db_conn.commit()
            except Exception as exc:
                logger.warning("Failed to persist audit_log record: %s", exc)
                try:
                    self._db_conn.rollback()
                except Exception:
                    pass
        return record

    def get_audit_logs(self) -> list[dict[str, Any]]:
        return list(self._audit_records)

    def get_admin_alerts(self) -> list[dict[str, Any]]:
        return list(self._admin_alerts)

    def _notify_all_admins(self, alert_payload: dict[str, Any]) -> None:
        self._admin_alerts.append(alert_payload)
        logger.critical("ADMIN ALERT [%s]: %s", alert_payload["alert_type"], json.dumps(alert_payload))
        if self._redis is not None:
            try:
                self._redis.xadd(
                    REDIS_STREAM_CONTAINMENT_ALERTS,
                    {"payload": json.dumps(alert_payload, default=str)},
                )
            except Exception as exc:
                logger.warning("Failed to publish admin alert to Redis: %s", exc)
        if self._admin_alert_callback is not None:
            try:
                self._admin_alert_callback(alert_payload)
            except Exception as exc:
                logger.warning("Admin alert callback raised an error: %s", exc)

    def _persist_approval_update(self, proposal: ActionProposal) -> None:
        if self._db_conn is None:
            return
        sql = f"""
            UPDATE {DB_SCHEMA}.response_actions
               SET approved_by = %s,
                   second_approver = %s,
                   approval_method = %s,
                   approval_timestamp = %s,
                   status = %s,
                   break_glass_used = %s,
                   expires_at = %s,
                   notes = %s,
                   action_proposal = %s::jsonb
             WHERE action_id = %s
        """
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(
                    sql,
                    (
                        proposal.approver_identity,
                        proposal.second_approver,
                        proposal.approval_method,
                        proposal.approval_timestamp,
                        proposal.execution_status,
                        proposal.break_glass_used,
                        proposal.expires_at,
                        proposal.notes,
                        json.dumps(proposal.to_dict(), default=str),
                        str(proposal.action_id),
                    ),
                )
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to update response_actions for %s: %s", proposal.action_id, exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass
