"""
VaultX - Third-Party Vendor Session Tracker
BECPL Manufacturing-Aware Hybrid NIDS - Phase 2

Specialized tracker for all `THIRD_PARTY_IDENTITY` sessions enforcing BECPL's
Vendor Access Policy (`docs/vendor_access_policy.md` & `becpl_nids.vendors`):
  * Default maximum session duration: 4 hours (configurable per vendor).
  * Approved access scope enforcement (allowed assets/resources/VLANs).
  * Concurrent session limit enforcement per vendor.
  * Tracks: vendor_id, vendor_name, approved_access_scope, session_start,
    session_end, resources_accessed, bytes_transferred, policy_violations.
  * Persists sessions to PostgreSQL `becpl_nids.vendor_sessions`.
  * Publishes policy violation alerts to Redis stream `detections:identity`.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

try:
    import psycopg2
except ImportError:  # pragma: no cover
    psycopg2 = None  # type: ignore[assignment]

from backend.behavioural.behaviour_config import (
    IDENTITY_DETECTION_STREAM,
    VENDOR_DEFAULT_MAX_CONCURRENT_SESSIONS,
    VENDOR_SESSION_MAX_HOURS,
)

logger = logging.getLogger(__name__)


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass
class VendorPolicy:
    """Enforceable vendor access policy derived from `becpl_nids.vendors`."""

    vendor_id: int
    vendor_name: str
    approved_access_scope: str
    approved_resources: Set[str] = field(default_factory=set)
    allowed_vlans: Set[int] = field(default_factory=set)
    max_session_duration_hours: float = VENDOR_SESSION_MAX_HOURS
    max_concurrent_sessions: int = VENDOR_DEFAULT_MAX_CONCURRENT_SESSIONS
    mfa_required: bool = True

    def is_resource_approved(self, resource: str) -> bool:
        if not self.approved_resources:
            return True
        res_lower = resource.lower()
        for allowed in self.approved_resources:
            a_lower = allowed.lower()
            if a_lower.endswith("*"):
                if res_lower.startswith(a_lower[:-1]):
                    return True
            elif res_lower == a_lower:
                return True
        return False


@dataclass
class VendorSessionRecord:
    """Active or completed third-party vendor session record."""

    session_id: str
    vendor_id: int
    vendor_name: str
    identity_id: str
    source_ip: str
    approved_access_scope: str
    session_start: datetime
    session_end: Optional[datetime] = None
    resources_accessed: List[str] = field(default_factory=list)
    bytes_transferred: int = 0
    policy_violations: List[str] = field(default_factory=list)

    @property
    def duration_minutes(self) -> int:
        end = _ensure_utc(self.session_end or datetime.now(timezone.utc))
        start = _ensure_utc(self.session_start)
        return max(0, int((end - start).total_seconds() // 60))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "vendor_id": self.vendor_id,
            "vendor_name": self.vendor_name,
            "identity_id": self.identity_id,
            "source_ip": self.source_ip,
            "approved_access_scope": self.approved_access_scope,
            "session_start": _ensure_utc(self.session_start).isoformat(),
            "session_end": (
                _ensure_utc(self.session_end).isoformat() if self.session_end else None
            ),
            "duration_minutes": self.duration_minutes,
            "resources_accessed": list(self.resources_accessed),
            "bytes_transferred": self.bytes_transferred,
            "policy_violations": list(self.policy_violations),
        }


@dataclass
class VendorViolationAlert:
    """Alert raised on a vendor policy violation."""

    alert_id: str
    timestamp: datetime
    session_id: str
    vendor_id: int
    vendor_name: str
    identity_id: str
    violation_type: str
    severity: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": _ensure_utc(self.timestamp).isoformat(),
            "session_id": self.session_id,
            "vendor_id": self.vendor_id,
            "vendor_name": self.vendor_name,
            "identity_id": self.identity_id,
            "violation_type": self.violation_type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
        }


class VendorSessionTracker:
    """
    Tracks THIRD_PARTY_IDENTITY sessions, checks duration (<= 4h), resource scope,
    and concurrent session limits, persists records to `becpl_nids.vendor_sessions`,
    and publishes violations to Redis stream `detections:identity`.
    """

    def __init__(
        self,
        policies: Optional[Dict[int, VendorPolicy]] = None,
        pg_dsn: Optional[str] = None,
        redis_client: Optional[Any] = None,
    ) -> None:
        self._policies: Dict[int, VendorPolicy] = dict(policies or {})
        self._pg_dsn = pg_dsn
        self._redis = redis_client
        self._active_sessions: Dict[str, VendorSessionRecord] = {}

    def register_policy(self, policy: VendorPolicy) -> None:
        self._policies[policy.vendor_id] = policy

    # ------------------------------------------------------------------
    # Lifecycle & Enforcement
    # ------------------------------------------------------------------

    def start_session(
        self,
        vendor_id: int,
        identity_id: str,
        source_ip: str,
        session_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        identity_category: str = "THIRD_PARTY_IDENTITY",
        publish: bool = True,
    ) -> tuple[VendorSessionRecord, List[VendorViolationAlert]]:
        """Register a new vendor session and enforce concurrent session limits."""
        if identity_category.upper() != "THIRD_PARTY_IDENTITY":
            raise ValueError(
                f"VendorSessionTracker only tracks THIRD_PARTY_IDENTITY (got {identity_category})"
            )

        policy = self._policies.get(vendor_id)
        vendor_name = policy.vendor_name if policy else f"Vendor-{vendor_id}"
        scope = policy.approved_access_scope if policy else "unspecified"
        ts = _ensure_utc(start_time or datetime.now(timezone.utc))
        sid = session_id or str(uuid.uuid4())

        record = VendorSessionRecord(
            session_id=sid,
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            identity_id=identity_id,
            source_ip=source_ip,
            approved_access_scope=scope,
            session_start=ts,
        )
        self._active_sessions[sid] = record

        alerts: List[VendorViolationAlert] = []
        max_concurrent = (
            policy.max_concurrent_sessions
            if policy
            else VENDOR_DEFAULT_MAX_CONCURRENT_SESSIONS
        )
        vendor_active = self.get_active_sessions_for_vendor(vendor_id)
        if len(vendor_active) > max_concurrent:
            v_code = f"concurrent_session_limit_exceeded:{len(vendor_active)}/{max_concurrent}"
            record.policy_violations.append(v_code)
            alert = VendorViolationAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=ts,
                session_id=sid,
                vendor_id=vendor_id,
                vendor_name=vendor_name,
                identity_id=identity_id,
                violation_type="vendor_concurrent_sessions_exceeded",
                severity="HIGH",
                description=(
                    f"Vendor '{vendor_name}' has {len(vendor_active)} concurrent "
                    f"sessions (policy limit: {max_concurrent})"
                ),
                evidence={
                    "active_session_ids": [s.session_id for s in vendor_active],
                    "max_concurrent_sessions": max_concurrent,
                },
            )
            alerts.append(alert)
            if publish and self._redis is not None:
                self._publish_alert(alert)

        return record, alerts

    def record_activity(
        self,
        session_id: str,
        resource: Optional[str] = None,
        bytes_transferred: int = 0,
        timestamp: Optional[datetime] = None,
        vlan_id: Optional[int] = None,
        publish: bool = True,
    ) -> List[VendorViolationAlert]:
        """
        Update resources accessed and bytes transferred on an active vendor
        session; raise alerts for scope violations or duration > 4 hours.
        """
        record = self._active_sessions.get(session_id)
        if record is None:
            raise KeyError(f"Unknown active vendor session: {session_id}")

        ts = _ensure_utc(timestamp or datetime.now(timezone.utc))
        policy = self._policies.get(record.vendor_id)
        max_hours = (
            policy.max_session_duration_hours if policy else VENDOR_SESSION_MAX_HOURS
        )

        record.bytes_transferred += max(0, int(bytes_transferred))
        if resource and resource not in record.resources_accessed:
            record.resources_accessed.append(resource)

        alerts: List[VendorViolationAlert] = []

        # 1. Check session duration > max_hours (default 4 hours)
        elapsed_hours = max(0.0, (ts - record.session_start).total_seconds() / 3600.0)
        if elapsed_hours > max_hours:
            v_code = f"session_duration_exceeded:{elapsed_hours:.2f}h>{max_hours:.1f}h"
            if not any(v.startswith("session_duration_exceeded") for v in record.policy_violations):
                record.policy_violations.append(v_code)
            alert = VendorViolationAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=ts,
                session_id=session_id,
                vendor_id=record.vendor_id,
                vendor_name=record.vendor_name,
                identity_id=record.identity_id,
                violation_type="vendor_session_duration_exceeded",
                severity="HIGH",
                description=(
                    f"Vendor '{record.vendor_name}' session {session_id} exceeded "
                    f"{max_hours:.1f}-hour limit ({elapsed_hours:.2f} hours)"
                ),
                evidence={
                    "elapsed_hours": round(elapsed_hours, 2),
                    "max_session_duration_hours": max_hours,
                },
            )
            alerts.append(alert)

        # 2. Check resource accessed outside approved scope
        if resource and policy is not None and not policy.is_resource_approved(resource):
            v_code = f"out_of_scope_resource:{resource}"
            if v_code not in record.policy_violations:
                record.policy_violations.append(v_code)
            alert = VendorViolationAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=ts,
                session_id=session_id,
                vendor_id=record.vendor_id,
                vendor_name=record.vendor_name,
                identity_id=record.identity_id,
                violation_type="vendor_scope_violation",
                severity="CRITICAL",
                description=(
                    f"Vendor '{record.vendor_name}' accessed resource '{resource}' "
                    f"outside approved scope ({policy.approved_access_scope})"
                ),
                evidence={
                    "resource": resource,
                    "approved_resources": sorted(policy.approved_resources),
                    "approved_access_scope": policy.approved_access_scope,
                },
            )
            alerts.append(alert)

        # 3. Check disallowed VLAN access if vlan_id provided
        if (
            vlan_id is not None
            and policy is not None
            and policy.allowed_vlans
            and vlan_id not in policy.allowed_vlans
        ):
            v_code = f"disallowed_vlan:{vlan_id}"
            if v_code not in record.policy_violations:
                record.policy_violations.append(v_code)
            alert = VendorViolationAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=ts,
                session_id=session_id,
                vendor_id=record.vendor_id,
                vendor_name=record.vendor_name,
                identity_id=record.identity_id,
                violation_type="vendor_vlan_scope_violation",
                severity="CRITICAL",
                description=(
                    f"Vendor '{record.vendor_name}' accessed disallowed VLAN {vlan_id} "
                    f"(allowed VLANs: {sorted(policy.allowed_vlans)})"
                ),
                evidence={
                    "vlan_id": vlan_id,
                    "allowed_vlans": sorted(policy.allowed_vlans),
                },
            )
            alerts.append(alert)

        if publish and self._redis is not None:
            for alert in alerts:
                self._publish_alert(alert)

        return alerts

    def end_session(
        self,
        session_id: str,
        end_time: Optional[datetime] = None,
        persist: bool = True,
        publish: bool = True,
    ) -> tuple[VendorSessionRecord, List[VendorViolationAlert]]:
        """Close a vendor session, perform final duration check, and write to PG."""
        record = self._active_sessions.get(session_id)
        if record is None:
            raise KeyError(f"Unknown active vendor session: {session_id}")

        ts = _ensure_utc(end_time or datetime.now(timezone.utc))
        alerts = self.record_activity(
            session_id=session_id,
            timestamp=ts,
            publish=publish,
        )
        record.session_end = ts
        del self._active_sessions[session_id]

        if persist and self._pg_dsn and psycopg2 is not None:
            self._persist_session_pg(record)

        return record, alerts

    def get_active_sessions_for_vendor(self, vendor_id: int) -> List[VendorSessionRecord]:
        return [
            s for s in self._active_sessions.values() if s.vendor_id == vendor_id
        ]

    # ------------------------------------------------------------------
    # Persistence & Publishing
    # ------------------------------------------------------------------

    def _persist_session_pg(self, record: VendorSessionRecord) -> None:
        try:
            identity_uuid = None
            try:
                uuid.UUID(record.identity_id)
                identity_uuid = record.identity_id
            except ValueError:
                identity_uuid = None

            session_uuid = record.session_id
            try:
                uuid.UUID(session_uuid)
            except ValueError:
                session_uuid = str(uuid.uuid4())

            with psycopg2.connect(self._pg_dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO becpl_nids.vendor_sessions (
                            session_id, vendor_id, identity_id, source_ip,
                            session_start, session_end, duration_minutes,
                            resources_accessed, bytes_transferred, policy_violations
                        )
                        VALUES (
                            %s::uuid, %s, %s::uuid, %s::inet,
                            %s, %s, %s,
                            %s, %s, %s
                        )
                        ON CONFLICT (session_id) DO UPDATE SET
                            session_end = EXCLUDED.session_end,
                            duration_minutes = EXCLUDED.duration_minutes,
                            resources_accessed = EXCLUDED.resources_accessed,
                            bytes_transferred = EXCLUDED.bytes_transferred,
                            policy_violations = EXCLUDED.policy_violations
                        """,
                        (
                            session_uuid,
                            record.vendor_id,
                            identity_uuid,
                            record.source_ip,
                            record.session_start,
                            record.session_end,
                            record.duration_minutes,
                            record.resources_accessed,
                            record.bytes_transferred,
                            record.policy_violations,
                        ),
                    )
                conn.commit()
        except Exception as exc:
            logger.error(
                "Failed writing vendor_session %s to PostgreSQL: %s",
                record.session_id,
                exc,
            )

    def _publish_alert(self, alert: VendorViolationAlert) -> None:
        self._redis.xadd(
            IDENTITY_DETECTION_STREAM,
            {
                "anomaly_id": alert.alert_id,
                "anomaly_type": alert.violation_type,
                "principal_id": alert.identity_id,
                "vendor_id": str(alert.vendor_id),
                "severity": alert.severity,
                "payload": json.dumps(alert.to_dict()),
            },
        )
