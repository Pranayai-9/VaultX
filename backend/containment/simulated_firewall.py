"""
simulated_firewall.py — Simulated Firewall State Manager for VaultX Phase 2.

Provides a lab-safe, PostgreSQL-backed + in-memory firewall ACL manager that
simulates OPNsense / FortiGate rule enforcement without mutating host iptables
or production industrial network switches.

Responsibilities
----------------
* Maintain active firewall rules in memory and mirror to PostgreSQL
  ``becpl_nids.simulated_firewall_rules``.
* Expose ``add_rule()``, ``remove_rule()``, ``list_active_rules()``, and
  ``check_rule_exists()``.
* Validate IP/CIDR addresses, protocols, ports, and actions (``BLOCK`` / ``ALLOW``).
* Record structured simulated firewall audit log entries (in memory and
  ``becpl_nids.audit_log`` when a DB connection is available).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from backend.containment.containment_config import DB_SCHEMA

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class FirewallRule:
    """Represents a single simulated firewall rule."""

    rule_id: uuid.UUID
    src_ip: str
    dst_ip: str
    protocol: str
    port_range: str
    action: str  # "BLOCK" or "ALLOW"
    active: bool = True
    created_by: str = "system"
    incident_id: uuid.UUID | None = None
    expires_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    rolled_back_at: datetime | None = None
    notes: str | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        current = now or datetime.now(timezone.utc)
        return current >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": str(self.rule_id),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "port_range": self.port_range,
            "action": self.action,
            "active": self.active,
            "created_by": self.created_by,
            "incident_id": str(self.incident_id) if self.incident_id else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat(),
            "rolled_back_at": self.rolled_back_at.isoformat() if self.rolled_back_at else None,
            "notes": self.notes,
        }


@dataclass
class FirewallAuditEntry:
    """Audit log entry emitted for every simulated firewall operation."""

    entry_id: uuid.UUID
    timestamp: datetime
    actor: str
    operation: str  # "ADD_RULE" | "REMOVE_RULE" | "CHECK_RULE" | "EXPIRE_RULE"
    rule_id: uuid.UUID | None
    outcome: str  # "success" | "failure"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": str(self.entry_id),
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "operation": self.operation,
            "rule_id": str(self.rule_id) if self.rule_id else None,
            "outcome": self.outcome,
            "details": self.details,
        }


@dataclass
class FirewallOperationResult:
    """Structured result returned by simulated firewall mutations."""

    success: bool
    rule_id: uuid.UUID | None
    message: str
    simulated_device: str = "OPNsense-FortiGate-Sim-BECPL-FW01"
    rule: FirewallRule | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "rule_id": str(self.rule_id) if self.rule_id else None,
            "message": self.message,
            "simulated_device": self.simulated_device,
            "rule": self.rule.to_dict() if self.rule else None,
            "timestamp": self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# Validation Helpers
# ---------------------------------------------------------------------------


def _validate_ip_or_cidr(value: str) -> str:
    """Validate an IPv4/IPv6 address, CIDR block, or 'ANY'."""
    cleaned = value.strip()
    if cleaned.upper() == "ANY":
        return "ANY"
    try:
        ipaddress.ip_network(cleaned, strict=False)
        return cleaned
    except ValueError as exc:
        raise ValueError(f"Invalid IP address or CIDR specification: {value!r}") from exc


def _normalise_port_range(port: int | str | None) -> str:
    if port is None:
        return "ANY"
    port_str = str(port).strip().upper()
    if port_str in ("", "ANY", "*"):
        return "ANY"
    if "-" in port_str:
        parts = port_str.split("-", 1)
        start, end = int(parts[0]), int(parts[1])
        if not (1 <= start <= end <= 65535):
            raise ValueError(f"Invalid port range: {port!r}")
        return f"{start}-{end}"
    port_num = int(port_str)
    if not (1 <= port_num <= 65535):
        raise ValueError(f"Invalid port number: {port!r}")
    return str(port_num)


# ---------------------------------------------------------------------------
# Simulated Firewall State Manager
# ---------------------------------------------------------------------------


class SimulatedFirewallManager:
    """
    Manages in-memory and PostgreSQL-backed simulated firewall rules.

    Parameters
    ----------
    db_conn : optional DB-API 2.0 connection (e.g. ``psycopg2`` connection)
        When provided, all rule additions, removals, and audit entries are
        persisted to ``becpl_nids.simulated_firewall_rules`` and
        ``becpl_nids.audit_log``. When ``None``, operates purely in memory
        (ideal for unit tests and offline lab runs).
    device_name : str
        Identifier for the simulated firewall appliance in logs/responses.
    """

    VALID_ACTIONS = frozenset({"BLOCK", "ALLOW"})
    VALID_PROTOCOLS = frozenset({"TCP", "UDP", "ICMP", "ANY", "MODBUS"})

    def __init__(
        self,
        db_conn: Any | None = None,
        device_name: str = "OPNsense-FortiGate-Sim-BECPL-FW01",
    ) -> None:
        self._db_conn = db_conn
        self._device_name = device_name
        self._rules: dict[uuid.UUID, FirewallRule] = {}
        self._audit_log: list[FirewallAuditEntry] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_rule(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str = "TCP",
        port_range: int | str | None = "ANY",
        action: str = "BLOCK",
        created_by: str = "system",
        incident_id: uuid.UUID | str | None = None,
        expires_at: datetime | None = None,
        notes: str | None = None,
    ) -> FirewallOperationResult:
        """
        Validate, apply (simulate), and persist a new firewall rule.

        Returns a ``FirewallOperationResult`` containing the created rule.
        """
        norm_src = _validate_ip_or_cidr(src_ip)
        norm_dst = _validate_ip_or_cidr(dst_ip)
        norm_proto = protocol.strip().upper()
        if norm_proto not in self.VALID_PROTOCOLS:
            raise ValueError(
                f"Unsupported protocol {protocol!r}. Allowed: {sorted(self.VALID_PROTOCOLS)}"
            )
        norm_port = _normalise_port_range(port_range)
        norm_action = action.strip().upper()
        if norm_action not in self.VALID_ACTIONS:
            raise ValueError(
                f"Unsupported firewall action {action!r}. Allowed: {sorted(self.VALID_ACTIONS)}"
            )

        inc_uuid: uuid.UUID | None = None
        if incident_id is not None:
            inc_uuid = (
                incident_id if isinstance(incident_id, uuid.UUID) else uuid.UUID(str(incident_id))
            )

        rule = FirewallRule(
            rule_id=uuid.uuid4(),
            src_ip=norm_src,
            dst_ip=norm_dst,
            protocol=norm_proto,
            port_range=norm_port,
            action=norm_action,
            active=True,
            created_by=created_by,
            incident_id=inc_uuid,
            expires_at=expires_at,
            created_at=datetime.now(timezone.utc),
            notes=notes,
        )

        self._rules[rule.rule_id] = rule
        self._persist_add_rule(rule)
        self._record_audit(
            actor=created_by,
            operation="ADD_RULE",
            rule_id=rule.rule_id,
            outcome="success",
            details=rule.to_dict(),
        )

        msg = (
            f"[{self._device_name}] Simulated {norm_action} rule applied: "
            f"{norm_src} -> {norm_dst} ({norm_proto}/{norm_port}) [rule_id={rule.rule_id}]"
        )
        logger.info(msg)
        return FirewallOperationResult(
            success=True,
            rule_id=rule.rule_id,
            message=msg,
            simulated_device=self._device_name,
            rule=rule,
        )

    def remove_rule(
        self,
        rule_id: uuid.UUID | str,
        removed_by: str = "system",
        reason: str | None = None,
    ) -> FirewallOperationResult:
        """
        Deactivate / roll back a simulated firewall rule by ``rule_id``.
        """
        target_id = rule_id if isinstance(rule_id, uuid.UUID) else uuid.UUID(str(rule_id))
        rule = self._rules.get(target_id)
        if rule is None:
            msg = f"Firewall rule {target_id} not found."
            self._record_audit(
                actor=removed_by,
                operation="REMOVE_RULE",
                rule_id=target_id,
                outcome="failure",
                details={"reason": msg},
            )
            return FirewallOperationResult(
                success=False,
                rule_id=target_id,
                message=msg,
                simulated_device=self._device_name,
            )

        now = datetime.now(timezone.utc)
        rule.active = False
        rule.rolled_back_at = now
        self._persist_remove_rule(rule)
        self._record_audit(
            actor=removed_by,
            operation="REMOVE_RULE",
            rule_id=rule.rule_id,
            outcome="success",
            details={"reason": reason or "manual_rollback", "rule": rule.to_dict()},
        )

        msg = (
            f"[{self._device_name}] Simulated rule removed: "
            f"{rule.src_ip} -> {rule.dst_ip} ({rule.protocol}/{rule.port_range}) "
            f"[rule_id={rule.rule_id}]"
        )
        logger.info(msg)
        return FirewallOperationResult(
            success=True,
            rule_id=rule.rule_id,
            message=msg,
            simulated_device=self._device_name,
            rule=rule,
        )

    def list_active_rules(
        self,
        include_expired: bool = False,
        now: datetime | None = None,
    ) -> list[FirewallRule]:
        """Return all currently active simulated firewall rules."""
        current = now or datetime.now(timezone.utc)
        active: list[FirewallRule] = []
        for rule in self._rules.values():
            if not rule.active:
                continue
            if not include_expired and rule.is_expired(current):
                continue
            active.append(rule)
        return active

    def check_rule_exists(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str | None = None,
        port_range: int | str | None = None,
        action: str | None = None,
    ) -> bool:
        """
        Check whether an active, non-expired rule matching the given criteria
        currently exists in the simulated firewall.
        """
        norm_src = _validate_ip_or_cidr(src_ip)
        norm_dst = _validate_ip_or_cidr(dst_ip)
        norm_proto = protocol.strip().upper() if protocol else None
        norm_port = _normalise_port_range(port_range) if port_range is not None else None
        norm_action = action.strip().upper() if action else None

        for rule in self.list_active_rules():
            if rule.src_ip != norm_src or rule.dst_ip != norm_dst:
                continue
            if norm_proto and rule.protocol != norm_proto:
                continue
            if norm_port and rule.port_range != norm_port:
                continue
            if norm_action and rule.action != norm_action:
                continue
            return True
        return False

    def get_rule(self, rule_id: uuid.UUID | str) -> FirewallRule | None:
        target_id = rule_id if isinstance(rule_id, uuid.UUID) else uuid.UUID(str(rule_id))
        return self._rules.get(target_id)

    def get_audit_log(self) -> list[FirewallAuditEntry]:
        """Return a copy of all simulated firewall audit log entries."""
        return list(self._audit_log)

    # ------------------------------------------------------------------
    # PostgreSQL Persistence Helpers
    # ------------------------------------------------------------------

    def _persist_add_rule(self, rule: FirewallRule) -> None:
        if self._db_conn is None:
            return
        sql = f"""
            INSERT INTO {DB_SCHEMA}.simulated_firewall_rules (
                rule_id, src_ip, dst_ip, protocol, port_range,
                action, active, created_by, incident_id, expires_at, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (rule_id) DO NOTHING
        """
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(
                    sql,
                    (
                        str(rule.rule_id),
                        rule.src_ip,
                        rule.dst_ip,
                        rule.protocol,
                        rule.port_range,
                        rule.action,
                        rule.active,
                        rule.created_by,
                        str(rule.incident_id) if rule.incident_id else None,
                        rule.expires_at,
                        rule.created_at,
                    ),
                )
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to persist firewall rule %s to PostgreSQL: %s", rule.rule_id, exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass

    def _persist_remove_rule(self, rule: FirewallRule) -> None:
        if self._db_conn is None:
            return
        sql = f"""
            UPDATE {DB_SCHEMA}.simulated_firewall_rules
               SET active = FALSE, rolled_back_at = %s
             WHERE rule_id = %s
        """
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(sql, (rule.rolled_back_at, str(rule.rule_id)))
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to update firewall rule %s in PostgreSQL: %s", rule.rule_id, exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass

    def _record_audit(
        self,
        actor: str,
        operation: str,
        rule_id: uuid.UUID | None,
        outcome: str,
        details: dict[str, Any],
    ) -> None:
        entry = FirewallAuditEntry(
            entry_id=uuid.uuid4(),
            timestamp=datetime.now(timezone.utc),
            actor=actor,
            operation=operation,
            rule_id=rule_id,
            outcome=outcome,
            details=details,
        )
        self._audit_log.append(entry)

        if self._db_conn is None:
            return
        sql = f"""
            INSERT INTO {DB_SCHEMA}.audit_log (
                actor, actor_type, action, target_table, target_id,
                new_value, outcome
            ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s)
        """
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(
                    sql,
                    (
                        actor,
                        "system" if actor == "system" else "human_operator",
                        f"SIMULATED_FIREWALL_{operation}",
                        "simulated_firewall_rules",
                        str(rule_id) if rule_id else None,
                        json.dumps(details, default=str),
                        outcome,
                    ),
                )
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to persist firewall audit log to PostgreSQL: %s", exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass
