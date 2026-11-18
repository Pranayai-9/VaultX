"""
model_pipeline.py — Continuous Log & Model Improvement Pipeline for VaultX Phase 2.

Governance Notice
-----------------
This pipeline is strictly **MANUAL or SCHEDULED — NEVER AUTOMATIC** on live
detection streams. In particular:
* ``LABEL_VERIFICATION`` accepts **ONLY** analyst-confirmed labels from
  ``becpl_nids.analyst_feedback`` and explicitly tagged scenario ground-truth
  labels. Labels derived solely from ML model predictions are strictly
  REJECTED to prevent self-reinforcing confirmation bias and concept drift.
* ``HUMAN_APPROVAL`` requires ``SECURITY_MANAGER`` authorisation (with MFA)
  before a candidate model can be promoted in ``becpl_nids.ml_models``.
* ``CONTROLLED_DEPLOYMENT`` writes a versioned deployment pointer loaded by
  ``ml_classifier.py`` on its next controlled restart.

Full Lifecycle Stages
---------------------
1.  DATA_COLLECTION             — Read from ``security_events``, ``auth_events``, ``endpoint_events``
2.  NORMALISATION               — Normalise raw event records into unified schema
3.  SECURE_STORAGE              — Persist validated vectors to ``becpl_nids.feature_vectors``
4.  DATA_QUALITY                — Filter out feature vectors with > 20% missing values & log reasons
5.  DEDUPLICATION               — Deduplicate feature vectors by deterministic SHA-256 event hash
6.  SENSITIVE_DATA_REDACTION    — Strip raw tokens, passwords, API keys, JWTs, and PII
7.  FEATURE_EXTRACTION          — Apply ``feature_extractor.py`` on validated events
8.  LABEL_VERIFICATION          — Accept ONLY analyst_feedback + scenario labels; reject ML-only labels
9.  TRAINING_DATASET_VERSIONING — Save versioned datasets to MinIO (``datasets/training/v{N}/``)
10. OFFLINE_MODEL_TRAINING      — Trigger offline ``model_trainer.py`` (manual / scheduled)
11. MODEL_EVALUATION            — Evaluate on holdout set and generate evaluation report
12. HUMAN_APPROVAL              — Require ``SECURITY_MANAGER`` approval + MFA before promotion
13. MODEL_REGISTRY              — Update ``becpl_nids.ml_models`` and mark model ``approved``
14. CONTROLLED_DEPLOYMENT       — Write deployment manifest for ``ml_classifier.py`` next restart

CLI Usage
---------
    python -m backend.containment.model_pipeline --stage data_quality
    python -m backend.containment.model_pipeline --stage feature_extraction
    python -m backend.containment.model_pipeline --stage train --dataset-version 1
    python -m backend.containment.model_pipeline --stage evaluate --model-id <uuid>
    python -m backend.containment.model_pipeline --stage promote --model-id <uuid> --approver ciso@becpl.in --role SECURITY_MANAGER --mfa-token 123456
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import logging
import math
import os
import re
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.containment.approval_engine import ApprovalEngine, AuthenticationError, AuthorizationError
from backend.containment.containment_config import (
    DB_SCHEMA,
    MINIO_BUCKET,
    MINIO_TRAINING_DATASET_PREFIX,
    MODEL_PIPELINE_MAX_MISSING_RATIO,
    OT_VLAN_ID,
    Role,
)

logger = logging.getLogger(__name__)

# Optional runtime dependencies (graceful fallback for offline/unit-test environments)
try:
    import joblib
except ImportError:
    joblib = None  # type: ignore[assignment]

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
    )
    from sklearn.model_selection import train_test_split
except ImportError:
    np = None  # type: ignore[assignment]
    RandomForestClassifier = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Constants & Sensitive Data Redaction Patterns
# ---------------------------------------------------------------------------

ALLOWED_LABEL_SOURCES: frozenset[str] = frozenset(
    {"analyst_feedback", "scenario_label", "scenario_ground_truth"}
)

REJECTED_ML_ONLY_LABEL_SOURCES: frozenset[str] = frozenset(
    {"ml_prediction", "model_prediction", "auto_label", "model_output", "classifier", "unverified"}
)

VALID_BECPL_LABELS: frozenset[str] = frozenset(
    {
        "BENIGN",
        "VENDOR_COMPROMISE",
        "SERVICE_MISUSE",
        "LATERAL_MOVEMENT",
        "LOTL",
        "ENCRYPTED_EXFIL",
        "OT_ANOMALY",
        "VULNERABILITY_SCAN",
    }
)

SENSITIVE_KEY_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth_header",
    "authorization",
    "cookie",
    "session_key",
    "private_key",
    "credential",
    "ssn",
    "aadhaar",
    "pan_number",
    "phone",
    "email",
    "raw_payload",
)

SENSITIVE_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("BEARER_TOKEN", re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("EMAIL_PII", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("PHONE_PII", re.compile(r"\+?\d{1,3}[-.\s]?\d{3,5}[-.\s]?\d{4,6}")),
    ("PAN_PII", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),
    ("AADHAAR_PII", re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")),
)

STANDARD_FEATURE_COLUMNS: tuple[str, ...] = (
    "duration",
    "protocol_num",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "down_up_ratio",
    "source_vlan",
    "dest_vlan",
    "is_cross_vlan",
    "source_criticality_score",
    "dest_criticality_score",
    "is_vendor_connection",
    "is_ot_destination",
    "is_external_dest",
)

PROTOCOL_NUM_MAP: dict[str, int] = {
    "TCP": 6,
    "UDP": 17,
    "ICMP": 1,
    "MODBUS": 6,
}

CRITICALITY_SCORE_MAP: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
}


# ---------------------------------------------------------------------------
# Result Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class DataQualityReport:
    """Summary of Stage 4 (DATA_QUALITY) filtering."""

    total_records: int
    accepted_count: int
    rejected_count: int
    max_missing_ratio: float
    rejection_reasons: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class LabelVerificationReport:
    """Summary of Stage 8 (LABEL_VERIFICATION) gate."""

    total_records: int
    verified_count: int
    rejected_count: int
    accepted_sources: dict[str, int] = field(default_factory=dict)
    rejection_reasons: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class DatasetVersionManifest:
    """Manifest persisted alongside each versioned training dataset in MinIO."""

    version: int
    object_prefix: str
    dataset_path: str
    record_count: int
    feature_columns: list[str]
    label_distribution: dict[str, int]
    sha256_checksum: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "object_prefix": self.object_prefix,
            "dataset_path": self.dataset_path,
            "record_count": self.record_count,
            "feature_columns": self.feature_columns,
            "label_distribution": self.label_distribution,
            "sha256_checksum": self.sha256_checksum,
            "created_at": self.created_at,
        }


@dataclass
class ModelEvaluationReport:
    """Holdout evaluation metrics produced by Stage 11 (MODEL_EVALUATION)."""

    model_id: uuid.UUID
    model_name: str
    model_version: str
    dataset_version: int
    accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    holdout_samples: int
    confusion_matrix: list[list[int]]
    per_class_metrics: dict[str, Any]
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": str(self.model_id),
            "model_name": self.model_name,
            "model_version": self.model_version,
            "dataset_version": self.dataset_version,
            "accuracy": round(self.accuracy, 4),
            "precision_macro": round(self.precision_macro, 4),
            "recall_macro": round(self.recall_macro, 4),
            "f1_macro": round(self.f1_macro, 4),
            "holdout_samples": self.holdout_samples,
            "confusion_matrix": self.confusion_matrix,
            "per_class_metrics": self.per_class_metrics,
            "evaluated_at": self.evaluated_at,
        }


# ---------------------------------------------------------------------------
# Model Improvement Pipeline (13-Step + Controlled Deployment Lifecycle)
# ---------------------------------------------------------------------------


class ModelImprovementPipeline:
    """
    Manual / scheduled continuous log and model improvement lifecycle manager.

    Never auto-trains or auto-promotes on live predictions.
    """

    def __init__(
        self,
        db_conn: Any | None = None,
        minio_client: Any | None = None,
        artifact_dir: str | Path | None = None,
        max_missing_ratio: float = MODEL_PIPELINE_MAX_MISSING_RATIO,
    ) -> None:
        self._db_conn = db_conn
        self._minio = minio_client
        self._artifact_dir = Path(
            artifact_dir or os.environ.get("VAULTX_MODEL_DIR", "backend/models")
        )
        self._max_missing_ratio = max_missing_ratio
        self._dataset_version_counter = 0
        self._registry: dict[uuid.UUID, dict[str, Any]] = {}
        self._stored_feature_vectors: list[dict[str, Any]] = []
        self._audit_log: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Step 1: DATA_COLLECTION
    # ------------------------------------------------------------------

    def collect_data(
        self,
        since: datetime | None = None,
        limit: int = 10000,
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Stage 1 — DATA_COLLECTION:
        Reads recent records from PostgreSQL ``security_events``,
        ``auth_events``, and ``endpoint_events``.
        """
        collected: dict[str, list[dict[str, Any]]] = {
            "security_events": [],
            "auth_events": [],
            "endpoint_events": [],
        }
        if self._db_conn is None:
            logger.info("DATA_COLLECTION: no DB connection supplied; returning empty collection.")
            return collected

        tables = [
            ("security_events", "event_id"),
            ("auth_events", "auth_id"),
            ("endpoint_events", "endpoint_event_id"),
        ]
        for table, _pk in tables:
            try:
                with self._db_conn.cursor() as cur:
                    if since is not None:
                        cur.execute(
                            f"SELECT * FROM {DB_SCHEMA}.{table} WHERE timestamp >= %s ORDER BY timestamp DESC LIMIT %s",
                            (since, limit),
                        )
                    else:
                        cur.execute(
                            f"SELECT * FROM {DB_SCHEMA}.{table} ORDER BY timestamp DESC LIMIT %s",
                            (limit,),
                        )
                    cols = [desc[0] for desc in cur.description]
                    collected[table] = [dict(zip(cols, row)) for row in cur.fetchall()]
            except Exception as exc:
                logger.warning("DATA_COLLECTION failed for %s: %s", table, exc)
        return collected

    # ------------------------------------------------------------------
    # Step 2: NORMALISATION
    # ------------------------------------------------------------------

    def normalise_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Stage 2 — NORMALISATION:
        Normalises heterogeneous events (security, auth, endpoint) into a
        consistent dictionary schema ready for feature extraction.
        """
        normalised: list[dict[str, Any]] = []
        for raw in events:
            event_id = str(
                raw.get("event_id")
                or raw.get("auth_id")
                or raw.get("endpoint_event_id")
                or uuid.uuid4()
            )
            proto = str(raw.get("protocol", "TCP")).upper()
            normalised.append(
                {
                    "event_id": event_id,
                    "timestamp": str(raw.get("timestamp") or datetime.now(timezone.utc).isoformat()),
                    "source_ip": str(raw.get("source_ip") or raw.get("src_ip") or ""),
                    "destination_ip": str(raw.get("destination_ip") or raw.get("dst_ip") or ""),
                    "source_port": raw.get("source_port", raw.get("src_port")),
                    "destination_port": raw.get("destination_port", raw.get("dst_port")),
                    "protocol": proto,
                    "connection_duration_ms": raw.get("connection_duration_ms", raw.get("duration_ms", 0)),
                    "bytes_transferred": raw.get("bytes_transferred", 0),
                    "packets_transferred": raw.get("packets_transferred", 0),
                    "orig_bytes": raw.get("orig_bytes", raw.get("fwd_bytes")),
                    "resp_bytes": raw.get("resp_bytes", raw.get("bwd_bytes")),
                    "orig_packets": raw.get("orig_packets", raw.get("fwd_packets")),
                    "resp_packets": raw.get("resp_packets", raw.get("bwd_packets")),
                    "source_vlan": raw.get("source_vlan"),
                    "dest_vlan": raw.get("dest_vlan"),
                    "source_criticality": raw.get("source_criticality", "medium"),
                    "dest_criticality": raw.get("dest_criticality", "medium"),
                    "is_vendor_connection": raw.get("is_vendor_connection", False),
                    "event_type": raw.get("event_type", "network_flow"),
                    "label": raw.get("label"),
                    "label_source": raw.get("label_source"),
                    "analyst_id": raw.get("analyst_id"),
                    "metadata": raw.get("metadata", {}),
                }
            )
        return normalised

    # ------------------------------------------------------------------
    # Step 3: SECURE_STORAGE
    # ------------------------------------------------------------------

    def store_feature_vectors(self, feature_vectors: list[dict[str, Any]]) -> int:
        """
        Stage 3 — SECURE_STORAGE:
        Persists redacted, deduplicated feature vectors to PostgreSQL
        ``becpl_nids.feature_vectors`` (and in-memory buffer).
        """
        stored = 0
        for vec in feature_vectors:
            self._stored_feature_vectors.append(dict(vec))
            if self._db_conn is not None:
                sql = f"""
                    INSERT INTO {DB_SCHEMA}.feature_vectors (
                        vector_id, event_id, event_hash, features, label, label_source, created_at
                    ) VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s)
                    ON CONFLICT (event_hash) DO NOTHING
                """
                try:
                    with self._db_conn.cursor() as cur:
                        cur.execute(
                            sql,
                            (
                                str(uuid.uuid4()),
                                str(vec.get("event_id")) if vec.get("event_id") else None,
                                vec.get("event_hash") or self._compute_event_hash(vec),
                                json.dumps(vec.get("features", vec), default=str),
                                vec.get("label"),
                                vec.get("label_source"),
                                datetime.now(timezone.utc),
                            ),
                        )
                    self._db_conn.commit()
                except Exception as exc:
                    logger.warning("SECURE_STORAGE failed for vector: %s", exc)
                    try:
                        self._db_conn.rollback()
                    except Exception:
                        pass
            stored += 1
        return stored

    # ------------------------------------------------------------------
    # Step 4: DATA_QUALITY (> 20% missing value gate)
    # ------------------------------------------------------------------

    @staticmethod
    def _is_missing(value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, str) and value.strip() == "":
            return True
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return True
        return False

    def run_data_quality_filter(
        self,
        feature_vectors: list[dict[str, Any]],
        expected_features: tuple[str, ...] | list[str] | None = None,
    ) -> tuple[list[dict[str, Any]], DataQualityReport]:
        """
        Stage 4 — DATA_QUALITY:
        Filters out any feature vector with strictly more than
        ``self._max_missing_ratio`` (default 20%) missing values and logs
        explicit rejection reasons.
        """
        accepted: list[dict[str, Any]] = []
        rejection_reasons: list[dict[str, Any]] = []

        for idx, record in enumerate(feature_vectors):
            features = record.get("features") if isinstance(record.get("features"), dict) else record
            keys = list(expected_features) if expected_features else [
                k for k in features.keys()
                if k not in {"event_id", "event_hash", "label", "label_source", "analyst_id", "metadata"}
            ]
            if not keys:
                reason = "empty_feature_vector"
                rejection_reasons.append(
                    {"index": idx, "event_id": record.get("event_id"), "reason": reason, "missing_ratio": 1.0}
                )
                logger.warning("DATA_QUALITY rejected record %s: %s", record.get("event_id"), reason)
                continue

            missing_keys = [k for k in keys if k not in features or self._is_missing(features[k])]
            missing_ratio = len(missing_keys) / len(keys)

            if missing_ratio > self._max_missing_ratio:
                reason = (
                    f"missing_value_ratio={missing_ratio:.2%} exceeds "
                    f"threshold={self._max_missing_ratio:.2%} (missing: {missing_keys})"
                )
                rejection_reasons.append(
                    {
                        "index": idx,
                        "event_id": record.get("event_id"),
                        "missing_ratio": round(missing_ratio, 4),
                        "missing_keys": missing_keys,
                        "reason": reason,
                    }
                )
                logger.warning("DATA_QUALITY rejected record %s: %s", record.get("event_id"), reason)
                continue

            accepted.append(record)

        report = DataQualityReport(
            total_records=len(feature_vectors),
            accepted_count=len(accepted),
            rejected_count=len(rejection_reasons),
            max_missing_ratio=self._max_missing_ratio,
            rejection_reasons=rejection_reasons,
        )
        return accepted, report

    # ------------------------------------------------------------------
    # Step 5: DEDUPLICATION (by event hash)
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_event_hash(record: dict[str, Any]) -> str:
        """Compute deterministic SHA-256 hash over event identity + features."""
        if record.get("event_hash"):
            return str(record["event_hash"])
        features = record.get("features") if isinstance(record.get("features"), dict) else record
        canonical = json.dumps(
            {
                "event_id": record.get("event_id"),
                "features": {
                    k: v
                    for k, v in sorted(features.items())
                    if k not in {"event_hash", "created_at"}
                },
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def deduplicate_vectors(
        self,
        feature_vectors: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Stage 5 — DEDUPLICATION:
        Removes duplicate feature vectors by SHA-256 event hash.
        Returns ``(unique_vectors, duplicates_removed_count)``.
        """
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        removed = 0

        for record in feature_vectors:
            ev_hash = self._compute_event_hash(record)
            if ev_hash in seen:
                removed += 1
                continue
            seen.add(ev_hash)
            copy = dict(record)
            copy["event_hash"] = ev_hash
            unique.append(copy)

        return unique, removed

    # ------------------------------------------------------------------
    # Step 6: SENSITIVE_DATA_REDACTION
    # ------------------------------------------------------------------

    def redact_sensitive_data(
        self,
        feature_vectors: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Stage 6 — SENSITIVE_DATA_REDACTION:
        Recursively removes raw tokens, passwords, API keys, JWTs, and PII
        from feature vectors before training storage.
        """
        return [self._redact_obj(record) for record in feature_vectors]

    def _redact_obj(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            cleaned: dict[str, Any] = {}
            for key, val in obj.items():
                key_lower = str(key).lower()
                if any(sub in key_lower for sub in SENSITIVE_KEY_SUBSTRINGS):
                    # Drop sensitive field completely from training vector
                    continue
                cleaned[key] = self._redact_obj(val)
            return cleaned
        if isinstance(obj, list):
            return [self._redact_obj(item) for item in obj]
        if isinstance(obj, str):
            redacted = obj
            for tag, pattern in SENSITIVE_VALUE_PATTERNS:
                redacted = pattern.sub(f"[REDACTED_{tag}]", redacted)
            return redacted
        return obj

    # ------------------------------------------------------------------
    # Step 7: FEATURE_EXTRACTION (integrates backend/processing/feature_extractor.py)
    # ------------------------------------------------------------------

    def extract_features(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Stage 7 — FEATURE_EXTRACTION:
        Applies ``backend.processing.feature_extractor`` when available, falling
        back to a CIC-IDS2017 + BECPL compatible feature extractor so the
        pipeline runs reliably in all environments.
        """
        external_extractor = None
        try:
            from backend.processing import feature_extractor as ext_mod  # type: ignore[import-not-found]
            if hasattr(ext_mod, "FeatureExtractor"):
                external_extractor = ext_mod.FeatureExtractor()
        except Exception:
            external_extractor = None

        vectors: list[dict[str, Any]] = []
        for event in events:
            extracted: dict[str, Any] | None = None
            if external_extractor is not None and hasattr(external_extractor, "extract"):
                try:
                    out = external_extractor.extract(event)
                    if isinstance(out, dict):
                        extracted = out
                except Exception as exc:
                    logger.debug("External feature_extractor fallback triggered: %s", exc)

            if extracted is None:
                extracted = self._fallback_extract_features(event)

            record: dict[str, Any] = {
                "event_id": event.get("event_id", str(uuid.uuid4())),
                "features": extracted,
            }
            if "label" in event:
                record["label"] = event["label"]
            if "label_source" in event:
                record["label_source"] = event["label_source"]
            if "analyst_id" in event:
                record["analyst_id"] = event["analyst_id"]
            record["event_hash"] = self._compute_event_hash(record)
            vectors.append(record)
        return vectors

    @staticmethod
    def _fallback_extract_features(event: dict[str, Any]) -> dict[str, Any]:
        """Built-in CIC-IDS2017 + BECPL feature extractor."""
        duration_ms = float(event.get("connection_duration_ms") or event.get("duration") or 0.0)
        duration_s = max(duration_ms / 1000.0, 0.001)
        fwd_bytes = float(event.get("orig_bytes") or event.get("fwd_bytes") or event.get("bytes_transferred") or 0.0)
        bwd_bytes = float(event.get("resp_bytes") or event.get("bwd_bytes") or 0.0)
        fwd_pkts = float(event.get("orig_packets") or event.get("fwd_packets") or event.get("packets_transferred") or 0.0)
        bwd_pkts = float(event.get("resp_packets") or event.get("bwd_packets") or 0.0)

        proto = str(event.get("protocol", "TCP")).upper()
        src_vlan = event.get("source_vlan")
        dst_vlan = event.get("dest_vlan")
        dst_ip = str(event.get("destination_ip") or event.get("dst_ip") or "")

        is_external = 0
        if dst_ip and not dst_ip.startswith(("10.", "192.168.", "172.16.")):
            is_external = 1

        return {
            "duration": duration_ms,
            "protocol_num": PROTOCOL_NUM_MAP.get(proto, 0),
            "fwd_packets": fwd_pkts,
            "bwd_packets": bwd_pkts,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "flow_bytes_per_sec": (fwd_bytes + bwd_bytes) / duration_s,
            "flow_packets_per_sec": (fwd_pkts + bwd_pkts) / duration_s,
            "down_up_ratio": bwd_bytes / max(fwd_bytes, 1.0),
            "source_vlan": src_vlan if src_vlan is not None else 0,
            "dest_vlan": dst_vlan if dst_vlan is not None else 0,
            "is_cross_vlan": int(src_vlan is not None and dst_vlan is not None and src_vlan != dst_vlan),
            "source_criticality_score": CRITICALITY_SCORE_MAP.get(
                str(event.get("source_criticality", "medium")).lower(), 0.5
            ),
            "dest_criticality_score": CRITICALITY_SCORE_MAP.get(
                str(event.get("dest_criticality", "medium")).lower(), 0.5
            ),
            "is_vendor_connection": int(bool(event.get("is_vendor_connection", False))),
            "is_ot_destination": int(dst_vlan == OT_VLAN_ID),
            "is_external_dest": is_external,
        }

    # ------------------------------------------------------------------
    # Step 8: LABEL_VERIFICATION (STRICT — NO ML-ONLY AUTO-LABELLING!)
    # ------------------------------------------------------------------

    def fetch_analyst_feedback(self) -> dict[str, dict[str, Any]]:
        """
        Load analyst-confirmed labels from ``becpl_nids.analyst_feedback``.
        Returns mapping ``event_id -> feedback_row``.
        """
        if self._db_conn is None:
            return {}
        sql = f"""
            SELECT event_id, original_prediction, analyst_label, analyst_id,
                   feedback_timestamp, notes
              FROM {DB_SCHEMA}.analyst_feedback
             WHERE analyst_label IS NOT NULL
               AND analyst_id IS NOT NULL
        """
        feedback_map: dict[str, dict[str, Any]] = {}
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(sql)
                for row in cur.fetchall():
                    feedback_map[str(row[0])] = {
                        "event_id": str(row[0]),
                        "original_prediction": row[1],
                        "analyst_label": row[2],
                        "analyst_id": str(row[3]),
                        "feedback_timestamp": row[4],
                        "notes": row[5],
                    }
        except Exception as exc:
            logger.warning("Could not read analyst_feedback table: %s", exc)
        return feedback_map

    def verify_labels(
        self,
        records: list[dict[str, Any]],
        analyst_feedback_map: dict[str, dict[str, Any]] | None = None,
    ) -> tuple[list[dict[str, Any]], LabelVerificationReport]:
        """
        Stage 8 — LABEL_VERIFICATION:
        Enforces strict ground-truth governance:
        * Accepts ONLY records whose label is confirmed by a human analyst
          (``analyst_feedback`` table or ``label_source == 'analyst_feedback'``
          with non-empty ``analyst_id``) OR an explicit scenario ground-truth
          label (``label_source in {'scenario_label', 'scenario_ground_truth'}``).
        * Strictly REJECTS any record labelled only by an ML model prediction
          (``ml_prediction``, ``model_prediction``, ``auto_label``, missing
          ``label_source``, or analyst_feedback missing ``analyst_id``).
        """
        fb_map = analyst_feedback_map if analyst_feedback_map is not None else self.fetch_analyst_feedback()
        verified: list[dict[str, Any]] = []
        rejection_reasons: list[dict[str, Any]] = []
        accepted_sources: dict[str, int] = {}

        for idx, record in enumerate(records):
            event_id = str(record.get("event_id") or "")
            label_source = str(record.get("label_source") or "").strip().lower()
            label = record.get("label")
            analyst_id = record.get("analyst_id")

            # Check if DB / supplied analyst_feedback confirms this event_id
            if event_id and event_id in fb_map:
                fb = fb_map[event_id]
                label = fb.get("analyst_label")
                analyst_id = fb.get("analyst_id")
                label_source = "analyst_feedback"

            # Reject ML-only or unknown label sources
            if label_source in REJECTED_ML_ONLY_LABEL_SOURCES or label_source not in ALLOWED_LABEL_SOURCES:
                reason = (
                    f"Rejected unverified/ML-only label_source={label_source!r}. "
                    f"Only analyst_feedback or scenario_ground_truth labels are permitted."
                )
                rejection_reasons.append({"index": idx, "event_id": event_id, "reason": reason})
                continue

            if label_source == "analyst_feedback" and not analyst_id:
                reason = "analyst_feedback label missing confirming analyst_id."
                rejection_reasons.append({"index": idx, "event_id": event_id, "reason": reason})
                continue

            if not label or str(label).strip().upper() not in VALID_BECPL_LABELS:
                reason = f"Invalid or missing BECPL label {label!r}."
                rejection_reasons.append({"index": idx, "event_id": event_id, "reason": reason})
                continue

            clean_record = dict(record)
            clean_record["label"] = str(label).strip().upper()
            clean_record["label_source"] = label_source
            if analyst_id:
                clean_record["analyst_id"] = str(analyst_id)
            verified.append(clean_record)
            accepted_sources[label_source] = accepted_sources.get(label_source, 0) + 1

        report = LabelVerificationReport(
            total_records=len(records),
            verified_count=len(verified),
            rejected_count=len(rejection_reasons),
            accepted_sources=accepted_sources,
            rejection_reasons=rejection_reasons,
        )
        return verified, report

    # ------------------------------------------------------------------
    # Step 9: TRAINING_DATASET_VERSIONING (MinIO datasets/training/v{N}/)
    # ------------------------------------------------------------------

    def create_versioned_training_dataset(
        self,
        verified_records: list[dict[str, Any]],
        version: int | None = None,
    ) -> DatasetVersionManifest:
        """
        Stage 9 — TRAINING_DATASET_VERSIONING:
        Creates a versioned training dataset under ``datasets/training/v{N}/``
        in MinIO (with local artifact directory persistence fallback).
        """
        if not verified_records:
            raise ValueError("Cannot create versioned training dataset from empty verified records.")

        if version is None:
            self._dataset_version_counter += 1
            version = self._dataset_version_counter
        else:
            self._dataset_version_counter = max(self._dataset_version_counter, version)

        prefix = f"{MINIO_TRAINING_DATASET_PREFIX}/v{version}"
        dataset_object = f"{prefix}/training_dataset.jsonl"
        manifest_object = f"{prefix}/manifest.json"

        lines = [json.dumps(rec, sort_keys=True, default=str) for rec in verified_records]
        payload_bytes = ("\n".join(lines) + "\n").encode("utf-8")
        checksum = hashlib.sha256(payload_bytes).hexdigest()

        label_dist: dict[str, int] = {}
        feature_cols: set[str] = set()
        for rec in verified_records:
            lbl = str(rec["label"])
            label_dist[lbl] = label_dist.get(lbl, 0) + 1
            feats = rec.get("features") if isinstance(rec.get("features"), dict) else {}
            feature_cols.update(feats.keys())

        manifest = DatasetVersionManifest(
            version=version,
            object_prefix=prefix,
            dataset_path=dataset_object,
            record_count=len(verified_records),
            feature_columns=sorted(feature_cols),
            label_distribution=label_dist,
            sha256_checksum=checksum,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        manifest_bytes = json.dumps(manifest.to_dict(), indent=2).encode("utf-8")

        # Upload to MinIO when available
        if self._minio is not None:
            try:
                self._minio.put_object(
                    MINIO_BUCKET,
                    dataset_object,
                    io.BytesIO(payload_bytes),
                    length=len(payload_bytes),
                    content_type="application/x-ndjson",
                )
                self._minio.put_object(
                    MINIO_BUCKET,
                    manifest_object,
                    io.BytesIO(manifest_bytes),
                    length=len(manifest_bytes),
                    content_type="application/json",
                )
            except Exception as exc:
                logger.warning("MinIO upload failed (falling back to local storage): %s", exc)

        # Always persist locally for reproducibility / offline CLI execution
        local_dir = self._artifact_dir / prefix
        local_dir.mkdir(parents=True, exist_ok=True)
        (local_dir / "training_dataset.jsonl").write_bytes(payload_bytes)
        (local_dir / "manifest.json").write_bytes(manifest_bytes)

        logger.info(
            "TRAINING_DATASET_VERSIONING: saved v%d (%d records) to %s",
            version,
            len(verified_records),
            prefix,
        )
        return manifest

    # ------------------------------------------------------------------
    # Step 10: OFFLINE_MODEL_TRAINING
    # ------------------------------------------------------------------

    def train_offline_model(
        self,
        verified_records: list[dict[str, Any]],
        model_name: str = "VaultX-BECPL-Classifier",
        model_version: str | None = None,
        dataset_version: int = 1,
        feature_columns: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Stage 10 — OFFLINE_MODEL_TRAINING:
        Triggers ``backend.detection.model_trainer`` if available, or trains an
        offline RandomForest classifier on verified labelled records, splitting
        out a holdout test set for Stage 11 evaluation.
        """
        if RandomForestClassifier is None or np is None:
            raise RuntimeError("scikit-learn and numpy are required for offline model training.")
        if len(verified_records) < 4:
            raise ValueError("At least 4 verified labelled records are required for training.")

        cols = feature_columns or list(STANDARD_FEATURE_COLUMNS)
        X_rows: list[list[float]] = []
        y_rows: list[str] = []
        for rec in verified_records:
            feats = rec.get("features") if isinstance(rec.get("features"), dict) else rec
            X_rows.append([float(feats.get(c, 0.0) or 0.0) for c in cols])
            y_rows.append(str(rec["label"]))

        X = np.array(X_rows, dtype=float)
        y = np.array(y_rows)

        # Holdout split (stratify when possible)
        unique_labels, counts = np.unique(y, return_counts=True)
        stratify = y if len(unique_labels) > 1 and int(counts.min()) >= 2 else None
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=stratify
        )

        clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            class_weight="balanced",
            random_state=42,
        )
        clf.fit(X_train, y_train)

        model_id = uuid.uuid4()
        version_str = model_version or f"v2.{dataset_version}.0"
        model_dir = self._artifact_dir / "candidates" / str(model_id)
        model_dir.mkdir(parents=True, exist_ok=True)
        model_path = model_dir / "model.joblib"
        if joblib is not None:
            joblib.dump({"model": clf, "feature_columns": cols}, model_path)

        candidate = {
            "model_id": model_id,
            "model_name": model_name,
            "model_version": version_str,
            "model_type": "classification",
            "dataset_version": dataset_version,
            "feature_columns": cols,
            "model_artifact_path": str(model_path),
            "lifecycle_state": "candidate",
            "is_active": False,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "_clf": clf,
            "_holdout": (X_test, y_test),
        }
        self._registry[model_id] = candidate
        logger.info("OFFLINE_MODEL_TRAINING completed: model_id=%s version=%s", model_id, version_str)
        return candidate

    # ------------------------------------------------------------------
    # Step 11: MODEL_EVALUATION
    # ------------------------------------------------------------------

    def evaluate_model(self, model_id: uuid.UUID | str) -> ModelEvaluationReport:
        """
        Stage 11 — MODEL_EVALUATION:
        Evaluates a trained candidate model on its holdout test set and
        generates a structured evaluation report.
        """
        mid = model_id if isinstance(model_id, uuid.UUID) else uuid.UUID(str(model_id))
        candidate = self._registry.get(mid)
        if candidate is None:
            raise LookupError(f"Candidate model {mid} not found in pipeline registry.")

        clf = candidate["_clf"]
        X_test, y_test = candidate["_holdout"]
        y_pred = clf.predict(X_test)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
        rec = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
        f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
        cm = confusion_matrix(y_test, y_pred).tolist()
        per_class = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

        report = ModelEvaluationReport(
            model_id=mid,
            model_name=candidate["model_name"],
            model_version=candidate["model_version"],
            dataset_version=candidate["dataset_version"],
            accuracy=acc,
            precision_macro=prec,
            recall_macro=rec,
            f1_macro=f1,
            holdout_samples=int(len(y_test)),
            confusion_matrix=cm,
            per_class_metrics=per_class,
        )
        candidate["evaluation_report"] = report.to_dict()
        candidate["lifecycle_state"] = "validated"

        # Save evaluation report JSON alongside candidate artifact
        report_path = Path(candidate["model_artifact_path"]).parent / "evaluation_report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

        logger.info(
            "MODEL_EVALUATION completed: model_id=%s accuracy=%.4f f1_macro=%.4f",
            mid,
            acc,
            f1,
        )
        return report

    # ------------------------------------------------------------------
    # Steps 12, 13, 14: HUMAN_APPROVAL -> MODEL_REGISTRY -> CONTROLLED_DEPLOYMENT
    # ------------------------------------------------------------------

    def approve_and_promote_model(
        self,
        model_id: uuid.UUID | str,
        approver_identity: str,
        approver_role: Role | str,
        mfa_token: str,
        notes: str = "",
    ) -> dict[str, Any]:
        """
        Stages 12, 13, 14 — HUMAN_APPROVAL, MODEL_REGISTRY, CONTROLLED_DEPLOYMENT:
        * Enforces ``Role.SECURITY_MANAGER`` + valid simulated MFA token.
        * Updates ``becpl_nids.ml_models`` setting the candidate as ``approved``.
        * Writes a controlled deployment pointer file read by ``ml_classifier.py``
          on its next controlled restart (never silently hot-swaps).
        """
        role_enum = (
            approver_role if isinstance(approver_role, Role) else Role(str(approver_role).upper())
        )
        if role_enum != Role.SECURITY_MANAGER:
            raise AuthorizationError(
                f"Model promotion requires {Role.SECURITY_MANAGER.value} approval; "
                f"role {role_enum.value!r} is not authorised."
            )

        if not ApprovalEngine.validate_mfa_token(mfa_token):
            raise AuthenticationError(
                "Invalid MFA token for model promotion approval "
                "(simulated MFA requires a 6-digit code starting with '1')."
            )

        mid = model_id if isinstance(model_id, uuid.UUID) else uuid.UUID(str(model_id))
        candidate = self._registry.get(mid)
        if candidate is None:
            raise LookupError(f"Model {mid} not found in pipeline registry.")

        now = datetime.now(timezone.utc)
        candidate["lifecycle_state"] = "approved"
        candidate["approved_by"] = approver_identity
        candidate["approved_at"] = now.isoformat()
        candidate["approval_notes"] = notes

        # Stage 13: Update ml_models table in PostgreSQL
        self._persist_model_registry(candidate)

        # Stage 14: Controlled Deployment manifest (loaded by ml_classifier.py on next restart)
        deployment_manifest = {
            "model_id": str(mid),
            "model_name": candidate["model_name"],
            "model_version": candidate["model_version"],
            "artifact_path": candidate["model_artifact_path"],
            "approved_by": approver_identity,
            "approved_at": now.isoformat(),
            "deployment_mode": "CONTROLLED_RESTART",
            "load_on_next_restart": True,
        }
        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        pointer_path = self._artifact_dir / "active_model_deployment.json"
        pointer_path.write_text(json.dumps(deployment_manifest, indent=2), encoding="utf-8")

        self._audit_log.append(
            {
                "timestamp": now.isoformat(),
                "actor": approver_identity,
                "role": role_enum.value,
                "action": "ML_MODEL_PROMOTED_FOR_CONTROLLED_DEPLOYMENT",
                "model_id": str(mid),
                "model_version": candidate["model_version"],
            }
        )
        logger.info(
            "MODEL_REGISTRY + CONTROLLED_DEPLOYMENT: model %s (%s) approved by %s; "
            "deployment manifest written to %s",
            mid,
            candidate["model_version"],
            approver_identity,
            pointer_path,
        )
        return deployment_manifest

    def _persist_model_registry(self, candidate: dict[str, Any]) -> None:
        if self._db_conn is None:
            return
        sql = f"""
            INSERT INTO {DB_SCHEMA}.ml_models (
                model_id, model_name, model_version, model_type,
                training_dataset, training_date, feature_set,
                performance_metrics, is_active, lifecycle_state,
                approved_by, approved_at, notes
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s, %s,
                %s::jsonb, %s, %s,
                %s, %s, %s
            )
            ON CONFLICT (model_id) DO UPDATE SET
                performance_metrics = EXCLUDED.performance_metrics,
                lifecycle_state = EXCLUDED.lifecycle_state,
                approved_by = EXCLUDED.approved_by,
                approved_at = EXCLUDED.approved_at,
                notes = EXCLUDED.notes
        """
        try:
            with self._db_conn.cursor() as cur:
                cur.execute(
                    sql,
                    (
                        str(candidate["model_id"]),
                        candidate["model_name"],
                        candidate["model_version"],
                        candidate["model_type"],
                        f"{MINIO_TRAINING_DATASET_PREFIX}/v{candidate['dataset_version']}/",
                        datetime.now(timezone.utc).date(),
                        candidate["feature_columns"],
                        json.dumps(candidate.get("evaluation_report", {}), default=str),
                        False,  # Becomes active on next controlled restart of ml_classifier.py
                        "approved",
                        candidate.get("approved_by"),
                        candidate.get("approved_at"),
                        candidate.get("approval_notes", ""),
                    ),
                )
            self._db_conn.commit()
        except Exception as exc:
            logger.warning("Failed to update ml_models registry in PostgreSQL: %s", exc)
            try:
                self._db_conn.rollback()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m backend.containment.model_pipeline",
        description="VaultX Continuous Log & Model Improvement Pipeline (Manual/Scheduled).",
    )
    parser.add_argument(
        "--stage",
        required=True,
        choices=["data_quality", "feature_extraction", "train", "evaluate", "promote"],
        help="Pipeline stage to execute.",
    )
    parser.add_argument("--input-file", type=str, default=None, help="Optional JSONL input file.")
    parser.add_argument("--output-dir", type=str, default=None, help="Artifact output directory.")
    parser.add_argument("--dataset-version", type=int, default=1, help="Training dataset version.")
    parser.add_argument("--model-id", type=str, default=None, help="Candidate model UUID.")
    parser.add_argument("--approver", type=str, default=None, help="Approver identity (promote stage).")
    parser.add_argument("--role", type=str, default=Role.SECURITY_MANAGER.value, help="Approver role.")
    parser.add_argument("--mfa-token", type=str, default=None, help="Simulated 6-digit MFA token.")
    parser.add_argument("--notes", type=str, default="", help="Optional promotion notes.")
    return parser


def _load_jsonl(path: str | None) -> list[dict[str, Any]]:
    if not path:
        return []
    records: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = build_cli_parser()
    args = parser.parse_args(argv)
    pipeline = ModelImprovementPipeline(artifact_dir=args.output_dir)

    records = _load_jsonl(args.input_file)

    if args.stage == "data_quality":
        redacted = pipeline.redact_sensitive_data(records)
        deduped, removed = pipeline.deduplicate_vectors(redacted)
        accepted, report = pipeline.run_data_quality_filter(deduped)
        print(
            json.dumps(
                {
                    "stage": "data_quality",
                    "duplicates_removed": removed,
                    "accepted": report.accepted_count,
                    "rejected": report.rejected_count,
                    "rejection_reasons": report.rejection_reasons,
                },
                indent=2,
            )
        )
        return 0

    if args.stage == "feature_extraction":
        normalised = pipeline.normalise_events(records)
        vectors = pipeline.extract_features(normalised)
        redacted = pipeline.redact_sensitive_data(vectors)
        deduped, removed = pipeline.deduplicate_vectors(redacted)
        accepted, report = pipeline.run_data_quality_filter(deduped)
        stored = pipeline.store_feature_vectors(accepted)
        print(
            json.dumps(
                {
                    "stage": "feature_extraction",
                    "extracted": len(vectors),
                    "duplicates_removed": removed,
                    "stored": stored,
                    "rejected": report.rejected_count,
                },
                indent=2,
            )
        )
        return 0

    if args.stage == "train":
        verified, label_report = pipeline.verify_labels(records)
        if not verified:
            print(
                json.dumps(
                    {
                        "stage": "train",
                        "error": "No verified labels available after LABEL_VERIFICATION gate.",
                        "rejected": label_report.rejected_count,
                    },
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1
        manifest = pipeline.create_versioned_training_dataset(verified, version=args.dataset_version)
        candidate = pipeline.train_offline_model(verified, dataset_version=manifest.version)
        eval_report = pipeline.evaluate_model(candidate["model_id"])
        print(
            json.dumps(
                {
                    "stage": "train",
                    "dataset": manifest.to_dict(),
                    "model_id": str(candidate["model_id"]),
                    "evaluation": eval_report.to_dict(),
                },
                indent=2,
            )
        )
        return 0

    if args.stage == "evaluate":
        if not args.model_id:
            parser.error("--model-id is required for --stage evaluate")
        eval_report = pipeline.evaluate_model(args.model_id)
        print(json.dumps(eval_report.to_dict(), indent=2))
        return 0

    if args.stage == "promote":
        if not (args.model_id and args.approver and args.mfa_token):
            parser.error("--model-id, --approver, and --mfa-token are required for --stage promote")
        deployment = pipeline.approve_and_promote_model(
            model_id=args.model_id,
            approver_identity=args.approver,
            approver_role=args.role,
            mfa_token=args.mfa_token,
            notes=args.notes,
        )
        print(json.dumps(deployment, indent=2))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
