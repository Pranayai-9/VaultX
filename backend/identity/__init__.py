"""
VaultX Identity Intelligence Package (Phase 2).

Provides human/non-human identity authentication intelligence, AI agent &
automation workload boundary monitoring, active session tracking for
containment, and third-party vendor session compliance enforcement.
"""

from backend.identity.ai_agent_monitor import (
    AgentActivityEvent,
    AgentAnomaly,
    AgentOperationalBoundary,
    AIAgentMonitor,
)
from backend.identity.identity_engine import (
    AuthEventRecord,
    IdentityAnomaly,
    IdentityEngine,
    fingerprint_token,
)
from backend.identity.session_tracker import (
    ActiveSession,
    SessionAnomaly,
    SessionTracker,
)
from backend.identity.vendor_session_tracker import (
    VendorPolicy,
    VendorSessionRecord,
    VendorSessionTracker,
    VendorViolationAlert,
)

__all__ = [
    "AIAgentMonitor",
    "AgentActivityEvent",
    "AgentAnomaly",
    "AgentOperationalBoundary",
    "ActiveSession",
    "AuthEventRecord",
    "IdentityAnomaly",
    "IdentityEngine",
    "SessionAnomaly",
    "SessionTracker",
    "VendorPolicy",
    "VendorSessionRecord",
    "VendorSessionTracker",
    "VendorViolationAlert",
    "fingerprint_token",
]
