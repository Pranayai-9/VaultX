"""
detection_config.py — Configuration constants for the VaultX Detection Engine.

BECPL (Bharat Electronics Components Pvt. Ltd.), Pune — Manufacturing-Aware Hybrid NIDS.
Centralizes all tuneable detection thresholds, Redis stream names, label sets,
feature schema definitions, and model governance gates. Values can be overridden
via environment variables in production deployments.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

MODEL_DIR: str = os.environ.get(
    "VAULTX_MODEL_DIR",
    str(Path(__file__).resolve().parents[1] / "models"),
)

DEFAULT_DATASET_PATH: str = os.environ.get(
    "VAULTX_DEFAULT_DATASET",
    str(
        Path(__file__).resolve().parents[2]
        / "datasets"
        / "processed"
        / "becpl_synthetic_traffic_50k.csv"
    ),
)

# ---------------------------------------------------------------------------
# ML Classifier Thresholds
# ---------------------------------------------------------------------------

# Predictions with max probability < ML_CONFIDENCE_THRESHOLD are classified as
# UNCERTAIN rather than attack, preventing low-confidence false alerts.
ML_CONFIDENCE_THRESHOLD: float = float(
    os.environ.get("VAULTX_ML_CONFIDENCE_THRESHOLD", "0.65")
)

# ---------------------------------------------------------------------------
# Isolation Forest / Anomaly Detection
# ---------------------------------------------------------------------------

# Expected contamination fraction for Isolation Forest trained on BENIGN traffic.
ANOMALY_CONTAMINATION: float = float(
    os.environ.get("VAULTX_ANOMALY_CONTAMINATION", "0.1")
)

# Rolling window (seconds) for per-asset and per-zone anomaly rate tracking.
ANOMALY_RATE_WINDOW_SECONDS: int = int(
    os.environ.get("VAULTX_ANOMALY_RATE_WINDOW", "3600")
)

# Anomaly rate threshold above which an investigation suggestion is raised.
ANOMALY_INVESTIGATION_RATE_THRESHOLD: float = float(
    os.environ.get("VAULTX_ANOMALY_INVESTIGATION_THRESHOLD", "0.25")
)

# Minimum observations in a window before generating an investigation suggestion.
ANOMALY_INVESTIGATION_MIN_SAMPLES: int = int(
    os.environ.get("VAULTX_ANOMALY_MIN_SAMPLES", "10")
)

# ---------------------------------------------------------------------------
# Signature Engine
# ---------------------------------------------------------------------------

# Identical alerts within this window (seconds) are deduplicated.
SIGNATURE_DEDUP_WINDOW_SECONDS: int = int(
    os.environ.get("VAULTX_SIGNATURE_DEDUP_WINDOW", "60")
)

# Alerts/min from the same source IP that constitutes an alert storm.
ALERT_STORM_THRESHOLD: int = int(
    os.environ.get("VAULTX_ALERT_STORM_THRESHOLD", "100")
)

# Suricata severity (1=highest .. 4=lowest) to BECPL severity strings.
SURICATA_SEVERITY_MAP: Dict[int, str] = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}

# ---------------------------------------------------------------------------
# Encrypted Traffic Analyzer
# ---------------------------------------------------------------------------

# Upload fraction (bytes_up / (bytes_up + bytes_down)) threshold for external flows.
ENCRYPTED_TRAFFIC_UPLOAD_RATIO_THRESHOLD: float = float(
    os.environ.get("VAULTX_UPLOAD_RATIO_THRESHOLD", "0.8")
)

# Flow duration threshold (hours) for connections to previously unseen external IPs.
ENCRYPTED_TRAFFIC_DURATION_THRESHOLD_HOURS: float = float(
    os.environ.get("VAULTX_DURATION_THRESHOLD_HOURS", "2.0")
)

# Autocorrelation threshold for C2 periodic beacon detection.
BEACON_INTERVAL_CORRELATION_THRESHOLD: float = float(
    os.environ.get("VAULTX_BEACON_CORR_THRESHOLD", "0.7")
)

# Minimum distinct signals required before publishing an encrypted traffic finding.
ENCRYPTED_TRAFFIC_MIN_SIGNALS: int = int(
    os.environ.get("VAULTX_ETA_MIN_SIGNALS", "2")
)

# Large outbound transfer threshold (bytes) from critical assets (default 50 MB).
CRITICAL_ASSET_VOLUME_THRESHOLD_BYTES: int = int(
    os.environ.get("VAULTX_CRITICAL_VOLUME_BYTES", str(50 * 1024 * 1024))
)

# Unusual outbound connection hours (inclusive, 24h clock: 03:00-05:59 -> 3..5).
UNUSUAL_HOURS_START: int = int(os.environ.get("VAULTX_UNUSUAL_HOURS_START", "3"))
UNUSUAL_HOURS_END: int = int(os.environ.get("VAULTX_UNUSUAL_HOURS_END", "5"))

# Rolling window (days) for per-asset JA3 novelty tracking.
JA3_HISTORY_DAYS: int = int(os.environ.get("VAULTX_JA3_HISTORY_DAYS", "30"))

# Short certificate validity threshold (days).
SHORT_CERT_VALIDITY_DAYS: int = int(os.environ.get("VAULTX_SHORT_CERT_DAYS", "30"))

# ---------------------------------------------------------------------------
# Redis Stream Names
# ---------------------------------------------------------------------------

REDIS_STREAM_RAW_EVENTS: str = "events:raw"
REDIS_STREAM_SIGNATURE_DETECTIONS: str = "detections:signature"
REDIS_STREAM_ML_DETECTIONS: str = "detections:ml"
REDIS_STREAM_ANOMALY_DETECTIONS: str = "detections:anomaly"
REDIS_STREAM_ENCRYPTED_TRAFFIC: str = "detections:encrypted_traffic"

# ---------------------------------------------------------------------------
# BECPL Labels & Feature Schema
# ---------------------------------------------------------------------------

ATTACK_LABELS: List[str] = [
    "VENDOR_COMPROMISE",
    "SERVICE_MISUSE",
    "LATERAL_MOVEMENT",
    "LOTL",
    "ENCRYPTED_EXFIL",
    "OT_ANOMALY",
    "VULNERABILITY_SCAN",
]

ALL_LABELS: List[str] = ["BENIGN"] + ATTACK_LABELS
UNCERTAIN_LABEL: str = "UNCERTAIN"

# Numeric and categorical feature columns aligned with becpl_synthetic_traffic_50k.csv
NUMERIC_FEATURE_COLUMNS: List[str] = [
    "source_port",
    "destination_port",
    "connection_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "packets_transferred",
    "bytes_transferred",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "source_vlan",
    "destination_vlan",
]

CATEGORICAL_FEATURE_COLUMNS: List[str] = [
    "protocol",
    "identity_classification",
]

FEATURE_COLUMNS: List[str] = NUMERIC_FEATURE_COLUMNS + CATEGORICAL_FEATURE_COLUMNS

PROTOCOL_ENCODING: Dict[str, int] = {
    "TCP": 0,
    "UDP": 1,
    "ICMP": 2,
    "MODBUS": 3,
    "S7COMM": 4,
    "HTTP": 5,
    "HTTPS": 6,
    "TLS": 7,
    "DNS": 8,
    "OTHER": 9,
}

IDENTITY_ENCODING: Dict[str, int] = {
    "HUMAN_USER": 0,
    "SERVICE_ACCOUNT": 1,
    "AUTOMATION_WORKLOAD": 2,
    "AI_AGENT": 3,
    "INDUSTRIAL_DEVICE": 4,
    "THIRD_PARTY_IDENTITY": 5,
    "UNKNOWN_IDENTITY": 6,
}

# BECPL 7-VLAN mapping
BECPL_VLANS: Dict[int, str] = {
    10: "Corporate IT",
    20: "Engineering",
    30: "OT",
    40: "Warehouse",
    50: "DMZ",
    60: "Cloud",
    70: "Security",
}

# ---------------------------------------------------------------------------
# Model Governance & Lifecycle
# ---------------------------------------------------------------------------

MODEL_STATE_CANDIDATE: str = "candidate"
MODEL_STATE_VALIDATED: str = "validated"
MODEL_STATE_APPROVED: str = "approved"
MODEL_STATE_DEPLOYED: str = "deployed"
MODEL_STATE_RETIRED: str = "retired"

MODEL_LIFECYCLE_STATES: List[str] = [
    MODEL_STATE_CANDIDATE,
    MODEL_STATE_VALIDATED,
    MODEL_STATE_APPROVED,
    MODEL_STATE_DEPLOYED,
    MODEL_STATE_RETIRED,
]

# Minimum evaluation thresholds required before a candidate can be validated/approved.
MODEL_MIN_MACRO_F1: float = float(os.environ.get("VAULTX_MODEL_MIN_MACRO_F1", "0.80"))
MODEL_MIN_WEIGHTED_F1: float = float(os.environ.get("VAULTX_MODEL_MIN_WEIGHTED_F1", "0.85"))
MODEL_MAX_FPR: float = float(os.environ.get("VAULTX_MODEL_MAX_FPR", "0.05"))

# ---------------------------------------------------------------------------
# Feature Store Quality Gate
# ---------------------------------------------------------------------------

FEATURE_STORE_MAX_MISSING_RATIO: float = float(
    os.environ.get("VAULTX_FS_MAX_MISSING_RATIO", "0.20")
)
FEATURE_SCHEMA_VERSION: str = "1.0.0"

# ---------------------------------------------------------------------------
# Behavioural Deviation Signal Weights (shared reference)
# ---------------------------------------------------------------------------

DEVIATION_SIGNAL_WEIGHTS: Dict[str, float] = {
    "new_destination": 0.20,
    "unusual_port": 0.12,
    "time_anomaly": 0.14,
    "volume_anomaly": 0.16,
    "frequency_anomaly": 0.12,
    "new_peer": 0.14,
    "cross_vlan_unexpected": 0.12,
}
