"""
VaultX - Active Session Tracker
BECPL Manufacturing-Aware Hybrid NIDS - Phase 2

Maintains active user, service, agent, and vendor sessions in Redis hash
`sessions:active` ({session_id: JSON session_data}).

Capabilities:
  * Updates sessions on auth events and correlated network flows from the same source IP.
  * Detects session anomalies:
      - Human session duration > 8 hours -> warning
      - Multiple simultaneous sessions for same human identity from different IPs -> suspicious
      - Human session continuing after business hours (outside 07:00-22:00 IST) -> observation
  * Supports the containment engine via `active_sessions_for_identity(identity_id)`
    and `revoke_session(session_id)` for rapid session revocation.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from backend.behavioural.behaviour_config import (
    ACTIVE_SESSIONS_REDIS_KEY,
    HUMAN_BUSINESS_HOUR_END_IST,
    HUMAN_BUSINESS_HOUR_START_IST,
    HUMAN_SESSION_MAX_HOURS,
    IDENTITY_DETECTION_STREAM,
)

logger = logging.getLogger(__name__)

IST = timezone(timedelta(hours=5, minutes=30))


@dataclass
class ActiveSession:
    """Representation of an active session stored in Redis `sessions:active`."""

    session_id: str
    principal_id: str
    identity_type: str
    source_ip: str
    target_resource: str
    start_time: datetime
    last_activity: datetime
    auth_method: str
    is_revoked: bool = False

    @property
    def duration_hours(self) -> float:
        delta = self.last_activity - self.start_time
        return max(0.0, delta.total_seconds() / 3600.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "principal_id": self.principal_id,
            "identity_type": self.identity_type,
            "source_ip": self.source_ip,
            "target_resource": self.target_resource,
            "start_time": _ensure_utc(self.start_time).isoformat(),
            "last_activity": _ensure_utc(self.last_activity).isoformat(),
            "auth_method": self.auth_method,
            "is_revoked": self.is_revoked,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActiveSession":
        return cls(
            session_id=data["session_id"],
            principal_id=data["principal_id"],
            identity_type=data["identity_type"],
            source_ip=data["source_ip"],
            target_resource=data.get("target_resource", ""),
            start_time=datetime.fromisoformat(data["start_time"]),
            last_activity=datetime.fromisoformat(data["last_activity"]),
            auth_method=data.get("auth_method", "unknown"),
            is_revoked=bool(data.get("is_revoked", False)),
        )


@dataclass
class SessionAnomaly:
    """Session anomaly finding."""

    anomaly_id: str
    timestamp: datetime
    session_id: str
    principal_id: str
    identity_type: str
    anomaly_type: str
    classification: str  # warning | suspicious | observation
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "timestamp": _ensure_utc(self.timestamp).isoformat(),
            "session_id": self.session_id,
            "principal_id": self.principal_id,
            "identity_type": self.identity_type,
            "anomaly_type": self.anomaly_type,
            "classification": self.classification,
            "description": self.description,
            "evidence": self.evidence,
        }


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class SessionTracker:
    """
    Tracks active sessions in Redis hash `sessions:active` (with an in-memory
    fallback store when no Redis client is provided).
    """

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        human_max_hours: float = HUMAN_SESSION_MAX_HOURS,
    ) -> None:
        self._redis = redis_client
        self._human_max_hours = human_max_hours
        self._memory_store: Dict[str, ActiveSession] = {}

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def register_or_update_auth_session(
        self,
        session_id: str,
        principal_id: str,
        identity_type: str,
        source_ip: str,
        target_resource: str,
        auth_method: str,
        timestamp: Optional[datetime] = None,
        publish: bool = True,
    ) -> Tuple_SessionResult:
        """Create or refresh a session on an auth event and evaluate anomalies."""
        now = _ensure_utc(timestamp or datetime.now(timezone.utc))
        existing = self.get_session(session_id)

        if existing is not None:
            existing.last_activity = max(existing.last_activity, now)
            if target_resource:
                existing.target_resource = target_resource
            session = existing
        else:
            session = ActiveSession(
                session_id=session_id,
                principal_id=principal_id,
                identity_type=identity_type.upper(),
                source_ip=source_ip,
                target_resource=target_resource,
                start_time=now,
                last_activity=now,
                auth_method=auth_method,
            )

        self._save_session(session)
        anomalies = self.detect_session_anomalies(session, now=now)
        if publish and self._redis is not None:
            for a in anomalies:
                self._publish_anomaly(a)
        return session, anomalies

    def update_from_network_flow(
        self,
        source_ip: str,
        timestamp: Optional[datetime] = None,
        target_resource: Optional[str] = None,
        publish: bool = True,
    ) -> List[SessionAnomaly]:
        """Update `last_activity` for active sessions matching `source_ip`."""
        now = _ensure_utc(timestamp or datetime.now(timezone.utc))
        all_anomalies: List[SessionAnomaly] = []

        for session in self.list_active_sessions():
            if session.source_ip == source_ip and not session.is_revoked:
                session.last_activity = max(session.last_activity, now)
                if target_resource:
                    session.target_resource = target_resource
                self._save_session(session)
                anomalies = self.detect_session_anomalies(session, now=now)
                if publish and self._redis is not None:
                    for a in anomalies:
                        self._publish_anomaly(a)
                all_anomalies.extend(anomalies)
        return all_anomalies

    def end_session(self, session_id: str) -> bool:
        """Remove a session from `sessions:active` on normal logout/expiry."""
        removed = False
        if self._redis is not None:
            removed = bool(self._redis.hdel(ACTIVE_SESSIONS_REDIS_KEY, session_id))
        if session_id in self._memory_store:
            del self._memory_store[session_id]
            removed = True
        return removed

    # ------------------------------------------------------------------
    # Containment support
    # ------------------------------------------------------------------

    def active_sessions_for_identity(self, identity_id: str) -> List[ActiveSession]:
        """
        Return all active, non-revoked sessions belonging to `identity_id`.
        Used by the containment engine to revoke active sessions during isolation.
        """
        return [
            s
            for s in self.list_active_sessions()
            if s.principal_id == identity_id and not s.is_revoked
        ]

    def revoke_session(self, session_id: str) -> bool:
        """Mark session revoked and remove it from `sessions:active`."""
        return self.end_session(session_id)

    def revoke_sessions_for_identity(self, identity_id: str) -> List[str]:
        """Revoke all active sessions for `identity_id`; returns revoked session IDs."""
        revoked_ids: List[str] = []
        for s in self.active_sessions_for_identity(identity_id):
            if self.revoke_session(s.session_id):
                revoked_ids.append(s.session_id)
        return revoked_ids

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def detect_session_anomalies(
        self, session: ActiveSession, now: Optional[datetime] = None
    ) -> List[SessionAnomaly]:
        """Evaluate the 3 session anomaly checks for HUMAN_USER sessions."""
        ts = _ensure_utc(now or session.last_activity)
        anomalies: List[SessionAnomaly] = []

        if session.identity_type != "HUMAN_USER":
            return anomalies

        # 1. Session duration > 8 hours -> warning
        duration_h = max(0.0, (ts - session.start_time).total_seconds() / 3600.0)
        if duration_h > self._human_max_hours:
            anomalies.append(
                SessionAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    timestamp=ts,
                    session_id=session.session_id,
                    principal_id=session.principal_id,
                    identity_type=session.identity_type,
                    anomaly_type="long_human_session",
                    classification="warning",
                    description=(
                        f"Human session {session.session_id} for {session.principal_id} "
                        f"exceeds {self._human_max_hours:.0f} hours ({duration_h:.2f}h)"
                    ),
                    evidence={
                        "duration_hours": round(duration_h, 2),
                        "max_hours": self._human_max_hours,
                    },
                )
            )

        # 2. Multiple simultaneous sessions from same human identity from different IPs -> suspicious
        peer_sessions = self.active_sessions_for_identity(session.principal_id)
        distinct_ips = sorted({s.source_ip for s in peer_sessions})
        if len(distinct_ips) > 1:
            anomalies.append(
                SessionAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    timestamp=ts,
                    session_id=session.session_id,
                    principal_id=session.principal_id,
                    identity_type=session.identity_type,
                    anomaly_type="concurrent_human_sessions_different_ips",
                    classification="suspicious",
                    description=(
                        f"Human identity {session.principal_id} has simultaneous "
                        f"active sessions from multiple IPs: {', '.join(distinct_ips)}"
                    ),
                    evidence={
                        "distinct_ips": distinct_ips,
                        "active_session_ids": [s.session_id for s in peer_sessions],
                    },
                )
            )

        # 3. Session continuing after business hours (outside 07:00-22:00 IST) -> observation
        hour_ist = ts.astimezone(IST).hour
        if not (HUMAN_BUSINESS_HOUR_START_IST <= hour_ist < HUMAN_BUSINESS_HOUR_END_IST):
            anomalies.append(
                SessionAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    timestamp=ts,
                    session_id=session.session_id,
                    principal_id=session.principal_id,
                    identity_type=session.identity_type,
                    anomaly_type="after_hours_human_session",
                    classification="observation",
                    description=(
                        f"Human session {session.session_id} for {session.principal_id} "
                        f"continuing after business hours ({hour_ist:02d}:00 IST)"
                    ),
                    evidence={"hour_ist": hour_ist},
                )
            )

        return anomalies

    # ------------------------------------------------------------------
    # Storage helpers
    # ------------------------------------------------------------------

    def get_session(self, session_id: str) -> Optional[ActiveSession]:
        if self._redis is not None:
            raw = self._redis.hget(ACTIVE_SESSIONS_REDIS_KEY, session_id)
            if raw:
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                return ActiveSession.from_dict(json.loads(raw))
            return None
        return self._memory_store.get(session_id)

    def list_active_sessions(self) -> List[ActiveSession]:
        if self._redis is not None:
            raw_map = self._redis.hgetall(ACTIVE_SESSIONS_REDIS_KEY) or {}
            sessions: List[ActiveSession] = []
            for _k, v in raw_map.items():
                if isinstance(v, bytes):
                    v = v.decode("utf-8")
                try:
                    sessions.append(ActiveSession.from_dict(json.loads(v)))
                except Exception as exc:
                    logger.warning("Corrupt session entry in Redis: %s", exc)
            return sessions
        return list(self._memory_store.values())

    def _save_session(self, session: ActiveSession) -> None:
        if self._redis is not None:
            self._redis.hset(
                ACTIVE_SESSIONS_REDIS_KEY,
                session.session_id,
                json.dumps(session.to_dict()),
            )
        else:
            self._memory_store[session.session_id] = session

    def _publish_anomaly(self, anomaly: SessionAnomaly) -> None:
        severity_map = {
            "suspicious": "HIGH",
            "warning": "MEDIUM",
            "observation": "LOW",
        }
        self._redis.xadd(
            IDENTITY_DETECTION_STREAM,
            {
                "anomaly_id": anomaly.anomaly_id,
                "anomaly_type": anomaly.anomaly_type,
                "principal_id": anomaly.principal_id,
                "severity": severity_map.get(anomaly.classification, "LOW"),
                "payload": json.dumps(anomaly.to_dict()),
            },
        )


Tuple_SessionResult = tuple  # (ActiveSession, List[SessionAnomaly])
