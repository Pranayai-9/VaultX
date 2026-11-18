"""
VaultX - Behavioural Intelligence Engine Configuration
BECPL Manufacturing-Aware Hybrid NIDS - Phase 2

Centralized, tuneable configuration constants for the behavioural baseline,
deviation detection, LOTL detection, identity intelligence, and session
tracking subsystems.
"""

from typing import Dict, List

# ---------------------------------------------------------------------------
# Supported entity types (11 canonical manufacturing/enterprise entity classes)
# ---------------------------------------------------------------------------
SUPPORTED_ENTITY_TYPES: List[str] = [
    "engineering_workstation",
    "corporate_workstation",
    "industrial_controller",
    "hmi",
    "mes_server",
    "erp_system",
    "warehouse_system",
    "vendor_connection",
    "service_account",
    "automation_agent",
    "ai_agent",
]

# ---------------------------------------------------------------------------
# Baseline computation schedule & storage
# ---------------------------------------------------------------------------
BASELINE_RECOMPUTE_INTERVAL_HOURS: int = 6
BASELINE_LOOKBACK_DAYS: int = 7
BASELINE_MIN_SAMPLES: int = 100
BASELINE_REDIS_TTL_SECONDS: int = 7 * 3600  # 7 hours

# ---------------------------------------------------------------------------
# Deviation detection thresholds & false positive reduction
# ---------------------------------------------------------------------------
DEVIATION_ALERT_THRESHOLD_LOW: float = 0.5
DEVIATION_ALERT_THRESHOLD_MEDIUM: float = 0.7
DEVIATION_ALERT_THRESHOLD_HIGH: float = 0.85

DEVIATION_MIN_SIGNALS_LOW: int = 2
DEVIATION_MIN_SIGNALS_MEDIUM: int = 3
DEVIATION_MIN_SIGNALS_HIGH: int = 4

MAINTENANCE_WINDOW_SCORE_REDUCTION: float = 0.5

# Per-signal weights for combined weighted sum (clamped to [0.0, 1.0]).
# Can be overridden by backend.detection.detection_config.DEVIATION_SIGNAL_WEIGHTS
# when that module is present.
SIGNAL_WEIGHTS: Dict[str, float] = {
    "new_destination": 0.90,
    "unusual_port": 0.80,
    "time_anomaly": 0.80,
    "volume_anomaly": 0.90,
    "frequency_anomaly": 0.85,
    "new_peer": 0.85,
    "cross_vlan_unexpected": 1.00,
}

# Criticality -> score mapping for destination and peer deviations
CRITICALITY_SCORES: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.3,
    "unknown": 0.6,
}

# ---------------------------------------------------------------------------
# LOTL detection
# ---------------------------------------------------------------------------
LOTL_ENDPOINT_STREAM: str = "events:endpoint"
LOTL_DETECTION_STREAM: str = "detections:lotl"
LOTL_NETWORK_CORRELATION_WINDOW_MINUTES: int = 15

# ---------------------------------------------------------------------------
# Identity & session tracking
# ---------------------------------------------------------------------------
RAW_EVENTS_STREAM: str = "events:raw"
IDENTITY_DETECTION_STREAM: str = "detections:identity"

BRUTE_FORCE_FAILURE_THRESHOLD: int = 5
BRUTE_FORCE_WINDOW_MINUTES: int = 5
IMPOSSIBLE_TRAVEL_WINDOW_HOURS: int = 1
IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH: float = 800.0

HUMAN_BUSINESS_HOUR_START_IST: int = 7   # 07:00 IST
HUMAN_BUSINESS_HOUR_END_IST: int = 22    # 22:00 IST (10 PM)

HUMAN_SESSION_MAX_HOURS: float = 8.0
VENDOR_SESSION_MAX_HOURS: float = 4.0
VENDOR_DEFAULT_MAX_CONCURRENT_SESSIONS: int = 2

AI_AGENT_RATE_MULTIPLIER_THRESHOLD: float = 3.0

# ---------------------------------------------------------------------------
# Redis keys
# ---------------------------------------------------------------------------
BASELINE_ASSET_REDIS_PREFIX: str = "baseline:asset:"
BASELINE_IDENTITY_REDIS_PREFIX: str = "baseline:identity:"
ACTIVE_SESSIONS_REDIS_KEY: str = "sessions:active"
AGENT_ACTIVITY_REDIS_PREFIX: str = "agent:activity:"

# ---------------------------------------------------------------------------
# BECPL 7-VLAN topology reference
# ---------------------------------------------------------------------------
VLAN_MAP: Dict[int, Dict[str, str]] = {
    10: {"name": "Corporate IT", "cidr": "10.10.10.0/24"},
    20: {"name": "Engineering", "cidr": "10.10.20.0/24"},
    30: {"name": "OT", "cidr": "10.10.30.0/24"},
    40: {"name": "Warehouse", "cidr": "10.10.40.0/24"},
    50: {"name": "DMZ", "cidr": "10.10.50.0/24"},
    60: {"name": "Cloud", "cidr": "10.10.60.0/24"},
    70: {"name": "Security", "cidr": "10.10.70.0/24"},
}

ENGINEERING_VLAN_ID: int = 20
OT_VLAN_ID: int = 30

# Approved engineering asset prefixes / types eligible for OT firmware deployments
APPROVED_ENGINEERING_ENTITY_TYPES: List[str] = [
    "engineering_workstation",
]
