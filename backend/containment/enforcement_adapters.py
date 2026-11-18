"""
enforcement_adapters.py — Simulated Enforcement Adapters for VaultX Phase 2.

Implements the ``EnforcementAdapter`` abstraction for lab-safe simulation of
BECPL network, endpoint, identity, vendor VPN, and OT boundary containment.

Adapters
--------
1. ``FirewallAdapter``           — Simulated OPNsense / FortiGate ACLs
                                   (writes to ``becpl_nids.simulated_firewall_rules``).
2. ``EndpointQuarantineAdapter`` — Simulated VLAN 999 quarantine with VLAN 70
                                   security management access preserved
                                   (writes to ``becpl_nids.quarantine_records``).
3. ``IdentityAdapter``           — Simulated OpenLDAP / Active Directory disable
                                   (updates ``becpl_nids.identities.is_active = FALSE``
                                   and writes revocation to ``becpl_nids.audit_log``).
4. ``VPNAdapter``                — Simulated WireGuard vendor VPN peer suspension
                                   (updates ``becpl_nids.vendor_sessions``).
5. ``OTBoundaryAdapter``         — Simulated IT-to-OT boundary restriction with
                                   strict Modbus TCP/502 allowlist rules
                                   (writes to ``becpl_nids.simulated_firewall_rules``).
"""

from __future__ import annotations

import json
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.containment.containment_config import (
    ActionCategory,
    ActionStatus,
    DB_SCHEMA,
    QUARANTINE_VLAN_ID,
    SECURITY_VLAN_ID,
    VLAN_MAP,
)
from backend.containment.simulated_firewall import FirewallRule, SimulatedFirewallManager

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Adapter Data Models
# ---------------------------------------------------------------------------


@dataclass
class ContainmentAction:
    """Normalized execution payload passed into an ``EnforcementAdapter``."""

    action_id: uuid.UUID
    incident_id: uuid.UUID
    action_category: ActionCategory
    target_asset_id: str | None = None
    target_identity_id: uuid.UUID | None = None
    target_principal: str | None = None
    target_ip: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    initiated_by: str = "system"
    approved_by: str | None = None
    expires_at: datetime | None = None


@dataclass
class ExecutionResult:
    """Structured result returned by ``EnforcementAdapter.execute()``."""

    action_id: uuid.UUID
    adapter_name: str
    success: bool
    status: ActionStatus
    message: str
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": str(self.action_id),
            "adapter_name": self.adapter_name,
            "success": self.success,
            "status": self.status.value,
            "message": self.message,
            "executed_at": self.executed_at.isoformat(),
            "details": self.details,
            "error": self.error,
        }


@dataclass
class RollbackResult:
    """Structured result returned by ``EnforcementAdapter.rollback()``."""

    action_id: uuid.UUID
    adapter_name: str
    success: bool
    status: ActionStatus
    message: str
    rolled_back_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": str(self.action_id),
            "adapter_name": self.adapter_name,
            "success": self.success,
            "status": self.status.value,
            "message": self.message,
            "rolled_back_at": self.rolled_back_at.isoformat(),
            "details": self.details,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Abstract Base Interface
# ---------------------------------------------------------------------------


class EnforcementAdapter(ABC):
    """Abstract base interface implemented by all VaultX containment adapters."""

    adapter_name: str = "BaseEnforcementAdapter"

    @abstractmethod
    def execute(self, action: ContainmentAction) -> ExecutionResult:
        """Apply the simulated enforcement action."""

    @abstractmethod
    def rollback(self, action_id: uuid.UUID) -> RollbackResult:
        """Reverse a previously executed enforcement action."""

    @abstractmethod
    def status(self, action_id: uuid.UUID) -> ActionStatus:
        """Return the current enforcement ``ActionStatus`` for ``action_id``."""


# ---------------------------------------------------------------------------
# 1. FirewallAdapter (Simulated OPNsense / FortiGate)
# ---------------------------------------------------------------------------


class FirewallAdapter(EnforcementAdapter):
    """
    Simulated OPNsense / FortiGate perimeter & inter-VLAN firewall adapter.

    Writes ACL rules to PostgreSQL ``becpl_nids.simulated_firewall_rules`` via
    ``SimulatedFirewallManager``.

    In production: would invoke the FortiGate REST API
    (``/api/v2/cmdb/firewall/policy``) or OPNsense Firewall Filter API.
    """

    adapter_name = "FirewallAdapter"

    def __init__(
        self,
        firewall_manager: SimulatedFirewallManager | None = None,
        db_conn: Any | None = None,
    ) -> None:
        self._fw = firewall_manager or SimulatedFirewallManager(db_conn=db_conn)
        # action_id -> list of firewall rule_ids created for that action
        self._action_rules: dict[uuid.UUID, list[uuid.UUID]] = {}
        self._action_status: dict[uuid.UUID, ActionStatus] = {}

    @property
    def firewall_manager(self) -> SimulatedFirewallManager:
        return self._fw

    def add_block_rule(
        self,
        src_ip: str,
        dst_ip: str,
        port: int | str | None = "ANY",
        protocol: str = "TCP",
        created_by: str = "vaultx-firewall-adapter",
        incident_id: uuid.UUID | None = None,
        expires_at: datetime | None = None,
    ) -> FirewallRule:
        """Simulate adding a BLOCK ACL rule on OPNsense/FortiGate."""
        res = self._fw.add_rule(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            port_range=port,
            action="BLOCK",
            created_by=created_by,
            incident_id=incident_id,
            expires_at=expires_at,
        )
        assert res.rule is not None
        return res.rule

    def remove_rule(
        self,
        rule_id: uuid.UUID | str,
        removed_by: str = "vaultx-firewall-adapter",
    ) -> bool:
        """Simulate removing/deactivating a firewall rule."""
        res = self._fw.remove_rule(rule_id=rule_id, removed_by=removed_by)
        return res.success

    def list_active_rules(self) -> list[FirewallRule]:
        """List all currently active simulated firewall rules."""
        return self._fw.list_active_rules()

    def execute(self, action: ContainmentAction) -> ExecutionResult:
        params = action.parameters
        src_ip = params.get("src_ip") or action.target_ip
        dst_ip = params.get("dst_ip", "ANY")
        port = params.get("port", params.get("port_range", "ANY"))
        protocol = params.get("protocol", "TCP")
        rule_action = params.get("firewall_action", "BLOCK")

        if not src_ip:
            self._action_status[action.action_id] = ActionStatus.FAILED
            return ExecutionResult(
                action_id=action.action_id,
                adapter_name=self.adapter_name,
                success=False,
                status=ActionStatus.FAILED,
                message="FirewallAdapter requires 'src_ip' or 'target_ip'.",
                error="missing_src_ip",
            )

        res = self._fw.add_rule(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            port_range=port,
            action=rule_action,
            created_by=action.approved_by or action.initiated_by,
            incident_id=action.incident_id,
            expires_at=action.expires_at,
            notes=f"VaultX containment action {action.action_id}",
        )
        assert res.rule is not None
        self._action_rules[action.action_id] = [res.rule.rule_id]
        self._action_status[action.action_id] = ActionStatus.COMPLETED

        return ExecutionResult(
            action_id=action.action_id,
            adapter_name=self.adapter_name,
            success=True,
            status=ActionStatus.COMPLETED,
            message=res.message,
            details={"rule_id": str(res.rule.rule_id), "rule": res.rule.to_dict()},
        )

    def rollback(self, action_id: uuid.UUID) -> RollbackResult:
        rule_ids = self._action_rules.get(action_id, [])
        if not rule_ids:
            return RollbackResult(
                action_id=action_id,
                adapter_name=self.adapter_name,
                success=False,
                status=ActionStatus.FAILED,
                message=f"No firewall rules recorded for action {action_id}.",
                error="action_not_found",
            )

        removed: list[str] = []
        for rid in rule_ids:
            res = self._fw.remove_rule(rid, removed_by="vaultx-rollback", reason=f"Rollback {action_id}")
            if res.success:
                removed.append(str(rid))

        self._action_status[action_id] = ActionStatus.ROLLED_BACK
        return RollbackResult(
            action_id=action_id,
            adapter_name=self.adapter_name,
            success=len(removed) == len(rule_ids),
            status=ActionStatus.ROLLED_BACK,
            message=f"Rolled back {len(removed)} simulated firewall rule(s) for action {action_id}.",
            details={"removed_rule_ids": removed},
        )

    def status(self, action_id: uuid.UUID) -> ActionStatus:
        return self._action_status.get(action_id, ActionStatus.PENDING)


# ---------------------------------------------------------------------------
# 2. EndpointQuarantineAdapter (Simulated Docker Network / VLAN 999 Quarantine)
# ---------------------------------------------------------------------------


@dataclass
class QuarantineRecord:
    """Represents a row in ``becpl_nids.quarantine_records``."""

    record_id: uuid.UUID
    action_id: uuid.UUID
    asset_id: str
    incident_id: uuid.UUID
    quarantine_start: datetime
    quarantine_end: datetime | None = None
    quarantine_vlan: int = QUARANTINE_VLAN_ID
    management_access_preserved: bool = True
    allowed_management_cidr: str = VLAN_MAP[SECURITY_VLAN_ID]["cidr"]
    created_by: str = "system"
    active: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": str(self.record_id),
            "action_id": str(self.action_id),
            "asset_id": self.asset_id,
            "incident_id": str(self.incident_id),
            "quarantine_start": self.quarantine_start.isoformat(),
            "quarantine_end": self.quarantine_end.isoformat() if self.quarantine_end else None,
            "quarantine_vlan": self.quarantine_vlan,
            "management_access_preserved": self.management_access_preserved,
            "allowed_management_cidr": self.allowed_management_cidr,
            "created_by": self.created_by,
            "active": self.active,
        }


class EndpointQuarantineAdapter(EnforcementAdapter):
    """
    Simulated endpoint quarantine adapter.

    Writes quarantine state to PostgreSQL ``becpl_nids.quarantine_records`` and
    simulates moving the asset to Quarantine VLAN 999 (Docker network policy in
    the lab environment).

    ALWAYS preserves the management access path so the quarantined host remains
    reachable from VLAN 70 (Security Management, ``10.10.70.0/24``) for forensic
    collection and remediation.
    """

    adapter_name = "EndpointQuarantineAdapter"

    def __init__(self, db_conn: Any | None = None) -> None:
        self._db_conn = db_conn
        self._records: dict[uuid.UUID, QuarantineRecord] = {}
        self._action_status: dict[uuid.UUID, ActionStatus] = {}

    def get_quarantine_record(self, action_id: uuid.UUID) -> QuarantineRecord | None:
        return self._records.get(action_id)

    def execute(self, action: ContainmentAction) -> ExecutionResult:
        asset_id = action.target_asset_id or action.parameters.get("asset_id")
        if not asset_id:
            self._action_status[action.action_id] = ActionStatus.FAILED
            return ExecutionResult(
                action_id=action.action_id,
                adapter_name=self.adapter_name,
                success=False,
                status=ActionStatus.FAILED,
                message="EndpointQuarantineAdapter requires 'target_asset_id'.",
                error="missing_asset_id",
            )

        now = datetime.now(timezone.utc)
        quarantine_vlan = int(action.parameters.get("quarantine_vlan", QUARANTINE_VLAN_ID))
        # Management path to VLAN 70 is always preserved
        record = QuarantineRecord(
            record_id=uuid.uuid4(),
            action_id=action.action_id,
            asset_id=asset_id,
            incident_id=action.incident_id,
            quarantine_start=now,
            quarantine_vlan=quarantine_vlan,
            management_access_preserved=True,
            allowed_management_cidr=VLAN_MAP[SECURITY_VLAN_ID]["cidr"],
            created_by=action.approved_by or action.initiated_by,
            active=True,
        )
        self._records[action.action_id] = record
        self._persist_quarantine_start(record)
        self._action_status[action.action_id] = ActionStatus.COMPLETED

        msg = (
            f"Simulated endpoint quarantine applied to {asset_id}: moved to VLAN {quarantine_vlan} "
            f"(Docker quarantine network policy); management path to VLAN {SECURITY_VLAN_ID} "
            f"({record.allowed_management_cidr}) preserved."
        )
        logger.info(msg)
        return ExecutionResult(
            action_id=action.action_id,
            adapter_name=self.adapter_name,
            success=True,
            status=ActionStatus.COMPLETED,
            message=msg,
            details=record.to_dict(),
        )

    def rollback(self, action_id: uuid.UUID) -> RollbackResult:
        record = self._records.get(action_id)
        if record is None:
            return RollbackResult(
                action_id=action_id,
                adapter_name=self.adapter_name,
                success=False,
                status=ActionStatus.FAILED,
                message=f"No quarantine record found for action {action_id}.",
                error="record_not_found",
            )

        now = datetime.now(timezone.utc)
        record.quarantine_end = now
        record.active = False
        self._persist_quarantine_end(record)
        self._action_status[action_id] = ActionStatus.ROLLED_BACK

        msg = f"Quarantine lifted for asset {record.asset_id}; original VLAN restored."
        logger.info(msg)
        return RollbackResult(
            action_id=action_id,
            adapter_name=self.adapter_name,
            success=True,
            status=ActionStatus.ROLLED_BACK,
            message=msg,
            details=record.to_dict(),
        )

    def status(self, action_id: uuid.UUID) -> ActionStatus:
        return self._action_status.get(action_id, ActionStatus.PENDING)

    def _persist_quarantine_start(self, record: QuarantineRecord) -> None:
        if self._db_conn is None:
            return
        sql = f"""
            INSERT INTO {DB_SCHEMA}.quarantine_records (
                record_id, asset_id, incident_id, quarantine_start,
                quarantine_end, management_access_preserved, created_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(
                    sql,
                    (
                        str(record.record_id),
                        record.asset_id,
                        str(record.incident_id),
                        record.quarantine_start,
                        record.quarantine_end,
                        record.management_access_preserved,
                        record.created_by,
                    ),
                )
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to persist quarantine_record %s: %s", record.record_id, exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass

    def _persist_quarantine_end(self, record: QuarantineRecord) -> None:
        if self._db_conn is None:
            return
        sql = f"""
            UPDATE {DB_SCHEMA}.quarantine_records
               SET quarantine_end = %s
             WHERE record_id = %s
        """
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(sql, (record.quarantine_end, str(record.record_id)))
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to update quarantine_record %s: %s", record.record_id, exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 3. IdentityAdapter (Simulated OpenLDAP / Active Directory)
# ---------------------------------------------------------------------------


class IdentityAdapter(EnforcementAdapter):
    """
    Simulated OpenLDAP / Active Directory identity containment adapter.

    Disables the target identity in PostgreSQL ``becpl_nids.identities``
    (``is_active = FALSE``) and logs session revocation to ``becpl_nids.audit_log``.

    In production: would invoke the LDAP / Microsoft Graph / AD DS API to
    disable the account and revoke Kerberos TGTs / OAuth refresh tokens.
    """

    adapter_name = "IdentityAdapter"

    def __init__(
        self,
        db_conn: Any | None = None,
        identity_store: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._db_conn = db_conn
        # Keyed by str(identity_id) or principal_name
        self._identity_store: dict[str, dict[str, Any]] = identity_store if identity_store is not None else {}
        self._action_targets: dict[uuid.UUID, str] = {}
        self._action_status: dict[uuid.UUID, ActionStatus] = {}
        self._revocation_audit: list[dict[str, Any]] = []

    def get_identity_state(self, key: str) -> dict[str, Any] | None:
        return self._identity_store.get(key)

    def get_revocation_audit(self) -> list[dict[str, Any]]:
        return list(self._revocation_audit)

    def execute(self, action: ContainmentAction) -> ExecutionResult:
        identity_key = (
            str(action.target_identity_id)
            if action.target_identity_id
            else (action.target_principal or action.parameters.get("principal_name"))
        )
        if not identity_key:
            self._action_status[action.action_id] = ActionStatus.FAILED
            return ExecutionResult(
                action_id=action.action_id,
                adapter_name=self.adapter_name,
                success=False,
                status=ActionStatus.FAILED,
                message="IdentityAdapter requires 'target_identity_id' or 'principal_name'.",
                error="missing_identity",
            )

        now = datetime.now(timezone.utc)
        entry = self._identity_store.setdefault(
            identity_key,
            {
                "identity_id": str(action.target_identity_id) if action.target_identity_id else identity_key,
                "principal_name": action.target_principal or action.parameters.get("principal_name", identity_key),
                "is_active": True,
            },
        )
        previous_active = entry.get("is_active", True)
        entry["is_active"] = False
        entry["disabled_at"] = now.isoformat()
        entry["sessions_revoked_at"] = now.isoformat()

        self._update_identity_db(action.target_identity_id, entry["principal_name"], is_active=False)

        audit_entry = {
            "timestamp": now.isoformat(),
            "action_id": str(action.action_id),
            "actor": action.approved_by or action.initiated_by,
            "action": "IDENTITY_DISABLED_AND_SESSIONS_REVOKED",
            "target_identity": identity_key,
            "principal_name": entry["principal_name"],
            "old_value": {"is_active": previous_active},
            "new_value": {"is_active": False, "sessions_revoked": True},
        }
        self._revocation_audit.append(audit_entry)
        self._persist_audit(audit_entry)

        self._action_targets[action.action_id] = identity_key
        self._action_status[action.action_id] = ActionStatus.COMPLETED

        msg = (
            f"Simulated LDAP/AD containment executed: identity '{entry['principal_name']}' "
            f"disabled (is_active=False) and active sessions revoked."
        )
        logger.info(msg)
        return ExecutionResult(
            action_id=action.action_id,
            adapter_name=self.adapter_name,
            success=True,
            status=ActionStatus.COMPLETED,
            message=msg,
            details=audit_entry,
        )

    def rollback(self, action_id: uuid.UUID) -> RollbackResult:
        identity_key = self._action_targets.get(action_id)
        if not identity_key or identity_key not in self._identity_store:
            return RollbackResult(
                action_id=action_id,
                adapter_name=self.adapter_name,
                success=False,
                status=ActionStatus.FAILED,
                message=f"No disabled identity tracked for action {action_id}.",
                error="action_not_found",
            )

        now = datetime.now(timezone.utc)
        entry = self._identity_store[identity_key]
        entry["is_active"] = True
        entry["restored_at"] = now.isoformat()

        identity_uuid = None
        try:
            identity_uuid = uuid.UUID(str(entry.get("identity_id")))
        except ValueError:
            pass
        self._update_identity_db(identity_uuid, entry["principal_name"], is_active=True)

        audit_entry = {
            "timestamp": now.isoformat(),
            "action_id": str(action_id),
            "actor": "vaultx-rollback",
            "action": "IDENTITY_REENABLED",
            "target_identity": identity_key,
            "principal_name": entry["principal_name"],
            "old_value": {"is_active": False},
            "new_value": {"is_active": True},
        }
        self._revocation_audit.append(audit_entry)
        self._persist_audit(audit_entry)

        self._action_status[action_id] = ActionStatus.ROLLED_BACK
        return RollbackResult(
            action_id=action_id,
            adapter_name=self.adapter_name,
            success=True,
            status=ActionStatus.ROLLED_BACK,
            message=f"Identity '{entry['principal_name']}' re-enabled (is_active=True).",
            details=audit_entry,
        )

    def status(self, action_id: uuid.UUID) -> ActionStatus:
        return self._action_status.get(action_id, ActionStatus.PENDING)

    def _update_identity_db(
        self,
        identity_id: uuid.UUID | None,
        principal_name: str,
        is_active: bool,
    ) -> None:
        if self._db_conn is None:
            return
        try:
            with self._db_conn.cursor() as cur:
                if identity_id is not None:
                    cur.execute(
                        f"UPDATE {DB_SCHEMA}.identities SET is_active = %s WHERE identity_id = %s",
                        (is_active, str(identity_id)),
                    )
                else:
                    cur.execute(
                        f"UPDATE {DB_SCHEMA}.identities SET is_active = %s WHERE principal_name = %s",
                        (is_active, principal_name),
                    )
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to update identities table for %s: %s", principal_name, exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass

    def _persist_audit(self, entry: dict[str, Any]) -> None:
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
                        entry["action"],
                        "identities",
                        entry["target_identity"],
                        json.dumps(entry["old_value"]),
                        json.dumps(entry["new_value"]),
                        "success",
                    ),
                )
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to write identity audit log: %s", exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 4. VPNAdapter (Simulated WireGuard Vendor Session Suspension)
# ---------------------------------------------------------------------------


class VPNAdapter(EnforcementAdapter):
    """
    Simulated WireGuard vendor VPN containment adapter.

    Records VPN session suspension in PostgreSQL ``becpl_nids.vendor_sessions``.

    In production: would invoke the WireGuard control plane API (or
    OPNsense WireGuard peer API) to remove the vendor peer public key and
    drop active tunnel handshakes.
    """

    adapter_name = "VPNAdapter"

    def __init__(
        self,
        db_conn: Any | None = None,
        sessions: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._db_conn = db_conn
        self._sessions: dict[str, dict[str, Any]] = sessions if sessions is not None else {}
        self._action_sessions: dict[uuid.UUID, str] = {}
        self._action_status: dict[uuid.UUID, ActionStatus] = {}

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        return self._sessions.get(session_id)

    def execute(self, action: ContainmentAction) -> ExecutionResult:
        session_id = str(action.parameters.get("session_id") or uuid.uuid4())
        vendor_name = action.parameters.get("vendor_name", "unknown_vendor")
        vendor_id = action.parameters.get("vendor_id")
        peer_ip = action.parameters.get("peer_ip") or action.target_ip

        now = datetime.now(timezone.utc)
        session = self._sessions.setdefault(
            session_id,
            {
                "session_id": session_id,
                "vendor_id": vendor_id,
                "vendor_name": vendor_name,
                "peer_ip": peer_ip,
                "session_status": "active",
            },
        )
        session["session_status"] = "suspended"
        session["suspended_at"] = now.isoformat()
        session["suspended_by"] = action.approved_by or action.initiated_by
        session["incident_id"] = str(action.incident_id)

        self._persist_vpn_session(session, status="suspended", ended_at=now)
        self._action_sessions[action.action_id] = session_id
        self._action_status[action.action_id] = ActionStatus.COMPLETED

        msg = (
            f"Simulated WireGuard VPN peer suspended: session={session_id} "
            f"vendor='{vendor_name}' peer_ip={peer_ip}."
        )
        logger.info(msg)
        return ExecutionResult(
            action_id=action.action_id,
            adapter_name=self.adapter_name,
            success=True,
            status=ActionStatus.COMPLETED,
            message=msg,
            details=dict(session),
        )

    def rollback(self, action_id: uuid.UUID) -> RollbackResult:
        session_id = self._action_sessions.get(action_id)
        if not session_id or session_id not in self._sessions:
            return RollbackResult(
                action_id=action_id,
                adapter_name=self.adapter_name,
                success=False,
                status=ActionStatus.FAILED,
                message=f"No suspended vendor VPN session found for action {action_id}.",
                error="session_not_found",
            )

        now = datetime.now(timezone.utc)
        session = self._sessions[session_id]
        session["session_status"] = "restored"
        session["restored_at"] = now.isoformat()

        self._persist_vpn_session(session, status="restored", ended_at=None)
        self._action_status[action_id] = ActionStatus.ROLLED_BACK

        msg = f"Vendor VPN suspension lifted for session {session_id} ({session['vendor_name']})."
        logger.info(msg)
        return RollbackResult(
            action_id=action_id,
            adapter_name=self.adapter_name,
            success=True,
            status=ActionStatus.ROLLED_BACK,
            message=msg,
            details=dict(session),
        )

    def status(self, action_id: uuid.UUID) -> ActionStatus:
        return self._action_status.get(action_id, ActionStatus.PENDING)

    def _persist_vpn_session(
        self,
        session: dict[str, Any],
        status: str,
        ended_at: datetime | None,
    ) -> None:
        if self._db_conn is None:
            return
        sql = f"""
            INSERT INTO {DB_SCHEMA}.vendor_sessions (
                session_id, vendor_id, vendor_name, source_ip,
                session_status, ended_at, suspension_reason
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (session_id) DO UPDATE SET
                session_status = EXCLUDED.session_status,
                ended_at = EXCLUDED.ended_at,
                suspension_reason = EXCLUDED.suspension_reason
        """
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(
                    sql,
                    (
                        session["session_id"],
                        session.get("vendor_id"),
                        session.get("vendor_name"),
                        session.get("peer_ip"),
                        status,
                        ended_at,
                        f"VaultX containment action (incident={session.get('incident_id')})",
                    ),
                )
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to persist vendor_sessions update: %s", exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 5. OTBoundaryAdapter (Simulated IT-to-OT Boundary Enforcement)
# ---------------------------------------------------------------------------


class OTBoundaryAdapter(EnforcementAdapter):
    """
    This adapter simulates OT boundary enforcement. In production deployment, any modification to rules affecting industrial controllers, PLCs, or safety systems must be reviewed by a qualified OT/ICS engineer. Automated enforcement is NOT safe for production OT environments without validated safety interlock assessment.

    Writes strict Modbus TCP/502 allowlist and IT-to-OT deny rules to
    PostgreSQL ``becpl_nids.simulated_firewall_rules`` via
    ``SimulatedFirewallManager``.
    """

    adapter_name = "OTBoundaryAdapter"
    MODBUS_PORT = "502"

    def __init__(
        self,
        firewall_manager: SimulatedFirewallManager | None = None,
        db_conn: Any | None = None,
    ) -> None:
        self._fw = firewall_manager or SimulatedFirewallManager(db_conn=db_conn)
        self._action_rules: dict[uuid.UUID, list[uuid.UUID]] = {}
        self._action_status: dict[uuid.UUID, ActionStatus] = {}

    @property
    def firewall_manager(self) -> SimulatedFirewallManager:
        return self._fw

    def execute(self, action: ContainmentAction) -> ExecutionResult:
        params = action.parameters
        ot_target_ip = params.get("ot_target_ip") or action.target_ip or "10.10.30.0/24"
        allowed_sources: list[str] = list(
            params.get("approved_modbus_sources", ["10.10.30.10", "10.10.20.15"])
        )
        blocked_source = params.get("blocked_src_ip", "10.10.10.0/24")
        actor = action.approved_by or action.initiated_by

        created_rules: list[FirewallRule] = []
        # 1. Strict ALLOW rules for approved SCADA / Engineering Modbus TCP/502 sources
        for allowed_src in allowed_sources:
            res = self._fw.add_rule(
                src_ip=allowed_src,
                dst_ip=ot_target_ip,
                protocol="TCP",
                port_range=self.MODBUS_PORT,
                action="ALLOW",
                created_by=actor,
                incident_id=action.incident_id,
                expires_at=action.expires_at,
                notes=f"OT Boundary Modbus/502 strict allowlist (action={action.action_id})",
            )
            assert res.rule is not None
            created_rules.append(res.rule)

        # 2. Explicit BLOCK rule for unauthorized IT/external traffic to OT Modbus TCP/502
        block_res = self._fw.add_rule(
            src_ip=blocked_source,
            dst_ip=ot_target_ip,
            protocol="TCP",
            port_range=self.MODBUS_PORT,
            action="BLOCK",
            created_by=actor,
            incident_id=action.incident_id,
            expires_at=action.expires_at,
            notes=f"OT Boundary IT-to-OT Modbus/502 restriction (action={action.action_id})",
        )
        assert block_res.rule is not None
        created_rules.append(block_res.rule)

        self._action_rules[action.action_id] = [r.rule_id for r in created_rules]
        self._action_status[action.action_id] = ActionStatus.COMPLETED

        msg = (
            f"Simulated OT boundary restriction applied for {ot_target_ip} on Modbus TCP/502: "
            f"{len(allowed_sources)} allowlist rule(s) + IT-to-OT block rule from {blocked_source}."
        )
        logger.warning(msg)
        return ExecutionResult(
            action_id=action.action_id,
            adapter_name=self.adapter_name,
            success=True,
            status=ActionStatus.COMPLETED,
            message=msg,
            details={
                "modbus_port": self.MODBUS_PORT,
                "rule_ids": [str(r.rule_id) for r in created_rules],
                "rules": [r.to_dict() for r in created_rules],
            },
        )

    def rollback(self, action_id: uuid.UUID) -> RollbackResult:
        rule_ids = self._action_rules.get(action_id, [])
        if not rule_ids:
            return RollbackResult(
                action_id=action_id,
                adapter_name=self.adapter_name,
                success=False,
                status=ActionStatus.FAILED,
                message=f"No OT boundary rules recorded for action {action_id}.",
                error="action_not_found",
            )

        removed: list[str] = []
        for rid in rule_ids:
            res = self._fw.remove_rule(rid, removed_by="vaultx-ot-rollback", reason=f"Rollback {action_id}")
            if res.success:
                removed.append(str(rid))

        self._action_status[action_id] = ActionStatus.ROLLED_BACK
        return RollbackResult(
            action_id=action_id,
            adapter_name=self.adapter_name,
            success=len(removed) == len(rule_ids),
            status=ActionStatus.ROLLED_BACK,
            message=f"Rolled back {len(removed)} simulated OT boundary rule(s) for action {action_id}.",
            details={"removed_rule_ids": removed},
        )

    def status(self, action_id: uuid.UUID) -> ActionStatus:
        return self._action_status.get(action_id, ActionStatus.PENDING)


# ---------------------------------------------------------------------------
# Adapter Registry / Factory
# ---------------------------------------------------------------------------


def build_default_adapters(
    db_conn: Any | None = None,
    firewall_manager: SimulatedFirewallManager | None = None,
) -> dict[ActionCategory, EnforcementAdapter]:
    """Construct the default map of ActionCategory -> EnforcementAdapter."""
    fw_mgr = firewall_manager or SimulatedFirewallManager(db_conn=db_conn)
    return {
        ActionCategory.ENDPOINT_QUARANTINE: EndpointQuarantineAdapter(db_conn=db_conn),
        ActionCategory.IDENTITY_CONTAINMENT: IdentityAdapter(db_conn=db_conn),
        ActionCategory.NETWORK_CONTAINMENT: FirewallAdapter(firewall_manager=fw_mgr, db_conn=db_conn),
        ActionCategory.THIRD_PARTY_CONTAINMENT: VPNAdapter(db_conn=db_conn),
        ActionCategory.OT_BOUNDARY_RESTRICTION: OTBoundaryAdapter(firewall_manager=fw_mgr, db_conn=db_conn),
    }
