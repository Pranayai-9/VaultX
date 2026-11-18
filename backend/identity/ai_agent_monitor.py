"""
VaultX - AI Agent & Automation Workload Observability Monitor
BECPL Manufacturing-Aware Hybrid NIDS - Phase 2

Cannot determine if traffic is AI-generated from packets alone. This module
correlates API telemetry, auth logs, and workload identity — not network packet
analysis.

Responsibilities:
  * Tracks identities classified as `AI_AGENT` or `AUTOMATION_WORKLOAD`.
  * Enforces approved operational boundaries per workload:
      - Approved API endpoints (from vendor_records / vendors policy)
      - Approved resource types
      - Approved time windows (hours in IST)
      - Approved source IPs / CIDR networks
      - Approved tool invocations (when exposed by agent telemetry)
  * Produces evidence-based anomaly records (never standalone auto-alerts) and
    publishes them to Redis stream `detections:identity`.
  * Maintains live agent activity summaries in Redis hash
    `agent:activity:{identity_id}`.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, List, Optional, Set

try:
    import psycopg2
except ImportError:  # pragma: no cover
    psycopg2 = None  # type: ignore[assignment]

from backend.behavioural.behaviour_config import (
    AGENT_ACTIVITY_REDIS_PREFIX,
    AI_AGENT_RATE_MULTIPLIER_THRESHOLD,
    IDENTITY_DETECTION_STREAM,
)

logger = logging.getLogger(__name__)

IST = timezone(timedelta(hours=5, minutes=30))
TRACKED_AGENT_CATEGORIES = frozenset({"AI_AGENT", "AUTOMATION_WORKLOAD"})


@dataclass
class AgentOperationalBoundary:
    """Approved operational scope for an AI_AGENT or AUTOMATION_WORKLOAD."""

    identity_id: str
    agent_name: str
    identity_category: str = "AI_AGENT"
    approved_api_endpoints: Set[str] = field(default_factory=set)
    approved_resource_types: Set[str] = field(default_factory=set)
    approved_hours_ist: Set[int] = field(default_factory=lambda: set(range(0, 24)))
    approved_source_networks: List[str] = field(default_factory=list)  # IPs or CIDRs
    approved_tools: Set[str] = field(default_factory=set)
    normal_calls_per_minute: float = 10.0

    def is_source_ip_approved(self, ip_str: str) -> bool:
        if not self.approved_source_networks:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        for entry in self.approved_source_networks:
            try:
                if "/" in entry:
                    if ip_obj in ipaddress.ip_network(entry, strict=False):
                        return True
                elif ip_obj == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        return False

    def is_endpoint_approved(self, endpoint: str) -> bool:
        if not self.approved_api_endpoints:
            return True
        for allowed in self.approved_api_endpoints:
            if allowed.endswith("*"):
                if endpoint.startswith(allowed[:-1]):
                    return True
            elif endpoint == allowed:
                return True
        return False


@dataclass
class AgentActivityEvent:
    """Single API / tool / auth telemetry event for an AI agent or automation workload."""

    identity_id: str
    identity_category: str
    timestamp: datetime
    source_ip: str
    api_endpoint: Optional[str] = None
    resource_type: Optional[str] = None
    target_resource: Optional[str] = None
    tool_name: Optional[str] = None
    status_code: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentAnomaly:
    """Evidence-based agent boundary deviation published to `detections:identity`."""

    anomaly_id: str
    timestamp: datetime
    identity_id: str
    agent_name: str
    identity_category: str
    anomaly_type: str
    severity: str
    score: float
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    is_evidence_only: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "timestamp": self.timestamp.isoformat(),
            "identity_id": self.identity_id,
            "agent_name": self.agent_name,
            "identity_category": self.identity_category,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "score": round(self.score, 4),
            "description": self.description,
            "evidence": self.evidence,
            "is_evidence_only": self.is_evidence_only,
        }


class AIAgentMonitor:
    """
    Cannot determine if traffic is AI-generated from packets alone. This module
    correlates API telemetry, auth logs, and workload identity — not network
    packet analysis.
    """

    def __init__(
        self,
        boundaries: Optional[Dict[str, AgentOperationalBoundary]] = None,
        redis_client: Optional[Any] = None,
        pg_dsn: Optional[str] = None,
        rate_multiplier_threshold: float = AI_AGENT_RATE_MULTIPLIER_THRESHOLD,
    ) -> None:
        self._boundaries: Dict[str, AgentOperationalBoundary] = dict(boundaries or {})
        self._redis = redis_client
        self._pg_dsn = pg_dsn
        self._rate_multiplier = rate_multiplier_threshold
        self._call_timestamps: Dict[str, Deque[datetime]] = defaultdict(deque)
        self._activity_counters: Dict[str, Dict[str, Any]] = {}

    def register_boundary(self, boundary: AgentOperationalBoundary) -> None:
        """Register or update approved operational boundaries for an AI/automation identity."""
        self._boundaries[boundary.identity_id] = boundary

    def evaluate_activity(
        self,
        event: AgentActivityEvent,
        publish: bool = True,
        persist: bool = False,
    ) -> List[AgentAnomaly]:
        """
        Evaluate a single agent API/auth/tool telemetry event against approved
        boundaries, update Redis summary `agent:activity:{identity_id}`, and
        publish any evidence-based anomalies to `detections:identity`.
        """
        if event.identity_category.upper() not in TRACKED_AGENT_CATEGORIES:
            return []

        boundary = self._boundaries.get(event.identity_id)
        ts = (
            event.timestamp
            if event.timestamp.tzinfo
            else event.timestamp.replace(tzinfo=timezone.utc)
        )
        agent_name = boundary.agent_name if boundary else event.identity_id

        # Track 1-minute sliding call rate
        window = self._call_timestamps[event.identity_id]
        window.append(ts)
        cutoff = ts - timedelta(minutes=1)
        while window and window[0] < cutoff:
            window.popleft()
        current_rpm = float(len(window))

        anomalies: List[AgentAnomaly] = []

        if boundary is not None:
            # 1. API endpoint outside approved list
            if event.api_endpoint and not boundary.is_endpoint_approved(
                event.api_endpoint
            ):
                anomalies.append(
                    AgentAnomaly(
                        anomaly_id=str(uuid.uuid4()),
                        timestamp=ts,
                        identity_id=event.identity_id,
                        agent_name=agent_name,
                        identity_category=event.identity_category,
                        anomaly_type="agent_unapproved_api_endpoint",
                        severity="MEDIUM",
                        score=0.70,
                        description=(
                            f"Agent '{agent_name}' called unapproved API endpoint "
                            f"'{event.api_endpoint}'"
                        ),
                        evidence={
                            "api_endpoint": event.api_endpoint,
                            "approved_endpoints": sorted(boundary.approved_api_endpoints),
                            "source_ip": event.source_ip,
                        },
                    )
                )

            # 2. Unusually high API call frequency (> 3x normal rate)
            rate_limit = boundary.normal_calls_per_minute * self._rate_multiplier
            if boundary.normal_calls_per_minute > 0 and current_rpm > rate_limit:
                anomalies.append(
                    AgentAnomaly(
                        anomaly_id=str(uuid.uuid4()),
                        timestamp=ts,
                        identity_id=event.identity_id,
                        agent_name=agent_name,
                        identity_category=event.identity_category,
                        anomaly_type="agent_high_api_frequency",
                        severity="MEDIUM",
                        score=0.65,
                        description=(
                            f"Agent '{agent_name}' API call rate {current_rpm:.1f}/min "
                            f"exceeds {self._rate_multiplier:.1f}x normal "
                            f"({boundary.normal_calls_per_minute:.1f}/min)"
                        ),
                        evidence={
                            "current_rpm": current_rpm,
                            "normal_rpm": boundary.normal_calls_per_minute,
                            "threshold_rpm": rate_limit,
                        },
                    )
                )

            # 3. Resource access outside approved scope
            if (
                event.resource_type
                and boundary.approved_resource_types
                and event.resource_type not in boundary.approved_resource_types
            ):
                anomalies.append(
                    AgentAnomaly(
                        anomaly_id=str(uuid.uuid4()),
                        timestamp=ts,
                        identity_id=event.identity_id,
                        agent_name=agent_name,
                        identity_category=event.identity_category,
                        anomaly_type="agent_out_of_scope_resource",
                        severity="HIGH",
                        score=0.80,
                        description=(
                            f"Agent '{agent_name}' accessed out-of-scope resource "
                            f"type '{event.resource_type}'"
                        ),
                        evidence={
                            "resource_type": event.resource_type,
                            "target_resource": event.target_resource,
                            "approved_resource_types": sorted(
                                boundary.approved_resource_types
                            ),
                        },
                    )
                )

            # 4. Unexpected source IP
            if event.source_ip and not boundary.is_source_ip_approved(event.source_ip):
                anomalies.append(
                    AgentAnomaly(
                        anomaly_id=str(uuid.uuid4()),
                        timestamp=ts,
                        identity_id=event.identity_id,
                        agent_name=agent_name,
                        identity_category=event.identity_category,
                        anomaly_type="agent_unexpected_source_ip",
                        severity="HIGH",
                        score=0.80,
                        description=(
                            f"Agent '{agent_name}' authenticated/called from "
                            f"unapproved source IP {event.source_ip}"
                        ),
                        evidence={
                            "source_ip": event.source_ip,
                            "approved_source_networks": boundary.approved_source_networks,
                        },
                    )
                )

            # 5. Approved time window check
            hour_ist = ts.astimezone(IST).hour
            if boundary.approved_hours_ist and hour_ist not in boundary.approved_hours_ist:
                anomalies.append(
                    AgentAnomaly(
                        anomaly_id=str(uuid.uuid4()),
                        timestamp=ts,
                        identity_id=event.identity_id,
                        agent_name=agent_name,
                        identity_category=event.identity_category,
                        anomaly_type="agent_outside_approved_window",
                        severity="LOW",
                        score=0.50,
                        description=(
                            f"Agent '{agent_name}' active at {hour_ist:02d}:00 IST "
                            f"outside approved operating window"
                        ),
                        evidence={
                            "hour_ist": hour_ist,
                            "approved_hours_ist": sorted(boundary.approved_hours_ist),
                        },
                    )
                )

            # 6. Unusual tool invocation in agent telemetry
            if (
                event.tool_name
                and boundary.approved_tools
                and event.tool_name not in boundary.approved_tools
            ):
                anomalies.append(
                    AgentAnomaly(
                        anomaly_id=str(uuid.uuid4()),
                        timestamp=ts,
                        identity_id=event.identity_id,
                        agent_name=agent_name,
                        identity_category=event.identity_category,
                        anomaly_type="agent_unusual_tool_invocation",
                        severity="HIGH",
                        score=0.85,
                        description=(
                            f"Agent '{agent_name}' invoked unapproved tool "
                            f"'{event.tool_name}'"
                        ),
                        evidence={
                            "tool_name": event.tool_name,
                            "approved_tools": sorted(boundary.approved_tools),
                        },
                    )
                )

        # Update Redis summary `agent:activity:{identity_id}`
        self._update_activity_summary(event, ts, current_rpm, len(anomalies))

        if persist and self._pg_dsn and psycopg2 is not None:
            self._persist_activity_pg(event, ts, anomalies)

        if publish and self._redis is not None:
            for anomaly in anomalies:
                self._publish_anomaly(anomaly)

        return anomalies

    def get_activity_summary(self, identity_id: str) -> Dict[str, Any]:
        """Return current activity summary from Redis hash `agent:activity:{identity_id}`."""
        if self._redis is not None:
            key = f"{AGENT_ACTIVITY_REDIS_PREFIX}{identity_id}"
            raw = self._redis.hgetall(key)
            if raw:
                return {
                    (k.decode("utf-8") if isinstance(k, bytes) else str(k)): (
                        v.decode("utf-8") if isinstance(v, bytes) else v
                    )
                    for k, v in raw.items()
                }
        return dict(self._activity_counters.get(identity_id, {}))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _update_activity_summary(
        self,
        event: AgentActivityEvent,
        ts: datetime,
        current_rpm: float,
        anomaly_count: int,
    ) -> None:
        summary = self._activity_counters.setdefault(
            event.identity_id,
            {
                "identity_id": event.identity_id,
                "identity_category": event.identity_category,
                "total_calls": 0,
                "anomaly_count": 0,
                "last_seen": "",
                "last_source_ip": "",
                "last_endpoint": "",
                "last_tool": "",
                "current_rpm": 0.0,
            },
        )
        summary["total_calls"] = int(summary["total_calls"]) + 1
        summary["anomaly_count"] = int(summary["anomaly_count"]) + anomaly_count
        summary["last_seen"] = ts.isoformat()
        summary["last_source_ip"] = event.source_ip
        summary["last_endpoint"] = event.api_endpoint or ""
        summary["last_tool"] = event.tool_name or ""
        summary["current_rpm"] = round(current_rpm, 2)

        if self._redis is not None:
            key = f"{AGENT_ACTIVITY_REDIS_PREFIX}{event.identity_id}"
            mapping = {k: str(v) for k, v in summary.items()}
            self._redis.hset(key, mapping=mapping)

    def _publish_anomaly(self, anomaly: AgentAnomaly) -> None:
        self._redis.xadd(
            IDENTITY_DETECTION_STREAM,
            {
                "anomaly_id": anomaly.anomaly_id,
                "anomaly_type": anomaly.anomaly_type,
                "principal_id": anomaly.identity_id,
                "severity": anomaly.severity,
                "score": str(anomaly.score),
                "payload": json.dumps(anomaly.to_dict()),
            },
        )

    def _persist_activity_pg(
        self,
        event: AgentActivityEvent,
        ts: datetime,
        anomalies: List[AgentAnomaly],
    ) -> None:
        try:
            identity_uuid = None
            try:
                uuid.UUID(event.identity_id)
                identity_uuid = event.identity_id
            except ValueError:
                identity_uuid = None

            with psycopg2.connect(self._pg_dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO becpl_nids.agent_activities (
                            activity_id, identity_id, identity_category, timestamp,
                            source_ip, api_endpoint, resource_type, target_resource,
                            tool_name, status_code, anomaly_flags, metadata
                        )
                        VALUES (
                            %s::uuid, %s::uuid, %s, %s,
                            %s::inet, %s, %s, %s,
                            %s, %s, %s, %s::jsonb
                        )
                        """,
                        (
                            str(uuid.uuid4()),
                            identity_uuid,
                            event.identity_category,
                            ts,
                            event.source_ip,
                            event.api_endpoint,
                            event.resource_type,
                            event.target_resource,
                            event.tool_name,
                            event.status_code,
                            [a.anomaly_type for a in anomalies],
                            json.dumps(event.metadata),
                        ),
                    )
                conn.commit()
        except Exception as exc:
            logger.error("Failed persisting agent activity to PG: %s", exc)
