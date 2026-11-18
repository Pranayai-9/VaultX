"""
feature_store.py — Feature Store for VaultX ML Detection Pipeline.

BECPL (Bharat Electronics Components Pvt. Ltd.), Pune — Manufacturing-Aware Hybrid NIDS.

Responsibilities
----------------
* Persists extracted feature vectors (from ``backend/processing/feature_extractor.py``)
  to PostgreSQL table ``becpl_nids.feature_vectors`` (DDL created idempotently).
* Associates every stored feature vector with its originating ``event_id``.
* Provides offline training retrieval:
  ``get_features_for_training(start_date, end_date, include_labels=True)``.
* Tracks feature schema versions and column mappings across model versions
  (``becpl_nids.feature_schema_versions``).
* Enforces data quality gate: rejects feature vectors with ``> 20%`` missing values,
  logs the rejection, and skips persistence.
"""

from __future__ import annotations

import json
import logging
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import pandas as pd

try:
    import sqlalchemy as sa
except ImportError:  # pragma: no cover
    sa = None  # type: ignore[assignment]

try:
    from backend.detection.detection_config import (
        FEATURE_COLUMNS,
        FEATURE_SCHEMA_VERSION,
        FEATURE_STORE_MAX_MISSING_RATIO,
    )
except ImportError:
    from detection_config import (  # type: ignore[no-redef]
        FEATURE_COLUMNS,
        FEATURE_SCHEMA_VERSION,
        FEATURE_STORE_MAX_MISSING_RATIO,
    )

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PostgreSQL Table DDL
# ---------------------------------------------------------------------------

FEATURE_STORE_DDL = """
CREATE SCHEMA IF NOT EXISTS becpl_nids;

CREATE TABLE IF NOT EXISTS becpl_nids.feature_schema_versions (
    schema_version   VARCHAR(50) PRIMARY KEY,
    feature_columns  TEXT[] NOT NULL,
    column_mapping   JSONB DEFAULT '{}'::jsonb,
    description      TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS becpl_nids.feature_vectors (
    vector_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id         VARCHAR(100) NOT NULL,
    schema_version   VARCHAR(50) NOT NULL,
    feature_data     JSONB NOT NULL,
    missing_ratio    DECIMAL(5,4) NOT NULL,
    label            VARCHAR(100),
    binary_label     INTEGER,
    event_timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feature_vectors_event_id
    ON becpl_nids.feature_vectors (event_id);
CREATE INDEX IF NOT EXISTS idx_feature_vectors_ts
    ON becpl_nids.feature_vectors (event_timestamp DESC);
"""


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class StoredFeatureRecord:
    vector_id: str
    event_id: str
    schema_version: str
    feature_data: Dict[str, Any]
    missing_ratio: float
    event_timestamp: datetime
    label: Optional[str] = None
    binary_label: Optional[int] = None


# ---------------------------------------------------------------------------
# Feature Store Service
# ---------------------------------------------------------------------------


class FeatureStore:
    """
    PostgreSQL-backed feature store with schema versioning and >20% missing-value quality gate.

    Falls back cleanly to in-memory storage when ``db_session_factory`` is ``None``
    (e.g. during unit tests or offline prototyping).
    """

    def __init__(
        self,
        db_session_factory: Optional[Callable[[], Any]] = None,
        schema_version: str = FEATURE_SCHEMA_VERSION,
        expected_features: Optional[List[str]] = None,
        max_missing_ratio: float = FEATURE_STORE_MAX_MISSING_RATIO,
    ) -> None:
        self._db_factory = db_session_factory
        self.schema_version = schema_version
        self.expected_features: List[str] = list(expected_features or FEATURE_COLUMNS)
        self.max_missing_ratio = float(max_missing_ratio)

        # In-memory mirrors / fallback storage
        self._schemas: Dict[str, Dict[str, Any]] = {
            self.schema_version: {
                "schema_version": self.schema_version,
                "feature_columns": list(self.expected_features),
                "column_mapping": {},
                "description": "BECPL Phase 2 baseline 15-feature schema",
            }
        }
        self._records: List[StoredFeatureRecord] = []
        self._rejected_count: int = 0

    def ensure_tables(self) -> bool:
        """Create ``becpl_nids.feature_vectors`` and ``feature_schema_versions`` if absent."""
        if self._db_factory is None or sa is None:
            return False
        session = None
        try:
            session = self._db_factory()
            for stmt in FEATURE_STORE_DDL.strip().split(";"):
                cleaned = stmt.strip()
                if cleaned:
                    session.execute(sa.text(cleaned))
            session.commit()
            return True
        except Exception as exc:
            logger.error("Failed to create feature_store tables: %s", exc)
            if session is not None:
                try:
                    session.rollback()
                except Exception:
                    pass
            return False
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass

    @staticmethod
    def _is_missing(value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, str) and value.strip() == "":
            return True
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return True
        return False

    def compute_missing_ratio(
        self,
        feature_vector: Dict[str, Any],
        schema_version: Optional[str] = None,
    ) -> float:
        """Compute fraction of expected schema features that are missing or NaN/Inf."""
        ver = schema_version or self.schema_version
        schema = self._schemas.get(ver)
        cols = schema["feature_columns"] if schema else self.expected_features
        if not cols:
            return 0.0
        missing = sum(1 for col in cols if col not in feature_vector or self._is_missing(feature_vector[col]))
        return missing / len(cols)

    def register_schema_version(
        self,
        schema_version: str,
        feature_columns: List[str],
        column_mapping: Optional[Dict[str, str]] = None,
        description: str = "",
    ) -> Dict[str, Any]:
        """Register a feature schema version and mapping from prior feature names."""
        entry = {
            "schema_version": schema_version,
            "feature_columns": list(feature_columns),
            "column_mapping": dict(column_mapping or {}),
            "description": description,
        }
        self._schemas[schema_version] = entry

        if self._db_factory is not None and sa is not None:
            session = None
            try:
                session = self._db_factory()
                session.execute(
                    sa.text(
                        """
                        INSERT INTO becpl_nids.feature_schema_versions (
                            schema_version, feature_columns, column_mapping, description
                        ) VALUES (
                            :schema_version, :feature_columns, CAST(:column_mapping AS JSONB), :description
                        )
                        ON CONFLICT (schema_version) DO UPDATE
                        SET feature_columns = EXCLUDED.feature_columns,
                            column_mapping = EXCLUDED.column_mapping,
                            description = EXCLUDED.description
                        """
                    ),
                    {
                        "schema_version": schema_version,
                        "feature_columns": list(feature_columns),
                        "column_mapping": json.dumps(entry["column_mapping"]),
                        "description": description,
                    },
                )
                session.commit()
            except Exception as exc:
                logger.error("Failed to persist schema version %s: %s", schema_version, exc)
                if session is not None:
                    try:
                        session.rollback()
                    except Exception:
                        pass
            finally:
                if session is not None:
                    try:
                        session.close()
                    except Exception:
                        pass

        return entry

    def get_schema_mapping(self, schema_version: str) -> Dict[str, str]:
        """Return recorded feature name mapping for a schema version."""
        schema = self._schemas.get(schema_version)
        return dict(schema.get("column_mapping", {})) if schema else {}

    def save_feature_vector(
        self,
        event_id: str,
        feature_vector: Dict[str, Any],
        label: Optional[str] = None,
        binary_label: Optional[int] = None,
        event_timestamp: Optional[datetime] = None,
        schema_version: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate and persist a feature vector associated with ``event_id``.

        Rejects vectors with > ``max_missing_ratio`` (default 20%) missing values,
        logs a warning, and skips persistence.

        Returns ``(accepted: bool, vector_id_or_none)``.
        """
        ver = schema_version or self.schema_version
        missing_ratio = self.compute_missing_ratio(feature_vector, schema_version=ver)

        if missing_ratio > self.max_missing_ratio:
            self._rejected_count += 1
            logger.warning(
                "Rejecting feature vector for event_id=%s: missing_ratio=%.2f%% exceeds limit %.2f%%",
                event_id,
                missing_ratio * 100.0,
                self.max_missing_ratio * 100.0,
            )
            return False, None

        ts = event_timestamp or datetime.now(tz=timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        if binary_label is None and label is not None:
            binary_label = 0 if str(label).upper() == "BENIGN" else 1

        vector_id = str(uuid.uuid4())
        # Sanitize NaN/Inf values before JSON serialization
        clean_features = {
            k: (None if self._is_missing(v) else v)
            for k, v in feature_vector.items()
        }

        rec = StoredFeatureRecord(
            vector_id=vector_id,
            event_id=str(event_id),
            schema_version=ver,
            feature_data=clean_features,
            missing_ratio=round(missing_ratio, 4),
            event_timestamp=ts,
            label=label,
            binary_label=binary_label,
        )
        self._records.append(rec)

        if self._db_factory is not None and sa is not None:
            session = None
            try:
                session = self._db_factory()
                session.execute(
                    sa.text(
                        """
                        INSERT INTO becpl_nids.feature_vectors (
                            vector_id, event_id, schema_version, feature_data,
                            missing_ratio, label, binary_label, event_timestamp
                        ) VALUES (
                            CAST(:vector_id AS UUID), :event_id, :schema_version,
                            CAST(:feature_data AS JSONB), :missing_ratio,
                            :label, :binary_label, :event_timestamp
                        )
                        """
                    ),
                    {
                        "vector_id": rec.vector_id,
                        "event_id": rec.event_id,
                        "schema_version": rec.schema_version,
                        "feature_data": json.dumps(rec.feature_data),
                        "missing_ratio": rec.missing_ratio,
                        "label": rec.label,
                        "binary_label": rec.binary_label,
                        "event_timestamp": rec.event_timestamp,
                    },
                )
                session.commit()
            except Exception as exc:
                logger.error("Failed to save feature vector for event %s: %s", event_id, exc)
                if session is not None:
                    try:
                        session.rollback()
                    except Exception:
                        pass
            finally:
                if session is not None:
                    try:
                        session.close()
                    except Exception:
                        pass

        return True, vector_id

    def get_features_for_training(
        self,
        start_date: datetime,
        end_date: datetime,
        include_labels: bool = True,
        target_schema_version: Optional[str] = None,
    ) -> pd.DataFrame:
        """
        Retrieve feature vectors between ``start_date`` and ``end_date`` as a DataFrame
        suitable for ``model_trainer.py``.
        """
        if start_date.tzinfo is None:
            start_date = start_date.replace(tzinfo=timezone.utc)
        if end_date.tzinfo is None:
            end_date = end_date.replace(tzinfo=timezone.utc)

        rows: List[Dict[str, Any]] = []

        if self._db_factory is not None and sa is not None:
            session = None
            try:
                session = self._db_factory()
                query = sa.text(
                    """
                    SELECT event_id, schema_version, feature_data, label, binary_label, event_timestamp
                    FROM becpl_nids.feature_vectors
                    WHERE event_timestamp >= :start_date
                      AND event_timestamp <= :end_date
                    ORDER BY event_timestamp ASC
                    """
                )
                result = session.execute(query, {"start_date": start_date, "end_date": end_date})
                for r in result.fetchall():
                    feat = r[2] if isinstance(r[2], dict) else json.loads(r[2])
                    row = dict(feat)
                    row["event_id"] = r[0]
                    row["schema_version"] = r[1]
                    row["timestamp"] = r[5].isoformat() if hasattr(r[5], "isoformat") else str(r[5])
                    if include_labels:
                        row["label"] = r[3]
                        row["binary_label"] = r[4]
                    rows.append(row)
            except Exception as exc:
                logger.error("DB query failed in get_features_for_training: %s", exc)
            finally:
                if session is not None:
                    try:
                        session.close()
                    except Exception:
                        pass
        else:
            for rec in self._records:
                if start_date <= rec.event_timestamp <= end_date:
                    row = dict(rec.feature_data)
                    row["event_id"] = rec.event_id
                    row["schema_version"] = rec.schema_version
                    row["timestamp"] = rec.event_timestamp.isoformat()
                    if include_labels:
                        row["label"] = rec.label
                        row["binary_label"] = rec.binary_label
                    rows.append(row)

        df = pd.DataFrame(rows)
        if not df.empty and target_schema_version and target_schema_version in self._schemas:
            mapping = self._schemas[target_schema_version].get("column_mapping") or {}
            if mapping:
                df = df.rename(columns=mapping)
        return df

    @property
    def rejected_count(self) -> int:
        """Number of feature vectors rejected by the >20% missing-value quality gate."""
        return self._rejected_count
