"""
anomaly_detector.py — Unsupervised Isolation Forest Anomaly Detector for VaultX.

BECPL (Bharat Electronics Components Pvt. Ltd.), Pune — Manufacturing-Aware Hybrid NIDS.

Design Principles
-----------------
* Operates on the **BENIGN-baseline feature space** (trained exclusively on confirmed normal traffic).
* Detects unknown attack patterns absent from supervised training data and subtle behavioural drift.
* **CRITICAL POLICY**: An anomaly score alone NEVER creates a standalone security alert.
  Anomaly outputs are published as *evidence* to Redis stream ``detections:anomaly`` for
  combination with signature, ML, behavioural, and threat-intel signals in the correlation engine.
* Tracks rolling anomaly rates per asset, per network zone, and per time window.
  Elevated anomaly rates generate **investigation suggestions** (NOT auto-alerts).
* Provides per-flow feature explainability comparing observed values against the BENIGN baseline.
"""

from __future__ import annotations

import json
import logging
import pickle
import time
import uuid
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np

try:
    from backend.detection.detection_config import (
        ANOMALY_CONTAMINATION,
        ANOMALY_INVESTIGATION_MIN_SAMPLES,
        ANOMALY_INVESTIGATION_RATE_THRESHOLD,
        ANOMALY_RATE_WINDOW_SECONDS,
        FEATURE_COLUMNS,
        IDENTITY_ENCODING,
        MODEL_DIR,
        PROTOCOL_ENCODING,
        REDIS_STREAM_ANOMALY_DETECTIONS,
    )
except ImportError:
    from detection_config import (  # type: ignore[no-redef]
        ANOMALY_CONTAMINATION,
        ANOMALY_INVESTIGATION_MIN_SAMPLES,
        ANOMALY_INVESTIGATION_RATE_THRESHOLD,
        ANOMALY_RATE_WINDOW_SECONDS,
        FEATURE_COLUMNS,
        IDENTITY_ENCODING,
        MODEL_DIR,
        PROTOCOL_ENCODING,
        REDIS_STREAM_ANOMALY_DETECTIONS,
    )

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class AnomalyResult:
    """Structured anomaly scoring result emitted as correlation evidence (never a standalone alert)."""

    event_id: str
    anomaly_score: float              # Normalized 0.0 (normal) .. 1.0 (highly anomalous)
    contamination_score: float        # Raw IsolationForest decision_function score (<0 => anomalous)
    is_anomaly: bool
    creates_alert: bool = False       # Invariant: anomaly score alone NEVER creates an alert
    asset_id: Optional[str] = None
    zone: Optional[str] = None
    anomalous_features: List[Dict[str, Any]] = field(default_factory=list)
    investigation_suggestion: Optional[Dict[str, Any]] = None
    model_version: str = "1"
    timestamp: str = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())
    published: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Sliding-Window Rate Tracker
# ---------------------------------------------------------------------------


class _WindowRateTracker:
    """Tracks (timestamp, is_anomaly) events per key over a sliding window."""

    def __init__(self, window_seconds: int = ANOMALY_RATE_WINDOW_SECONDS) -> None:
        self.window_seconds = window_seconds
        self._records: Dict[str, deque[Tuple[float, bool]]] = defaultdict(deque)

    def record(self, key: str, is_anomaly: bool, now: Optional[float] = None) -> Tuple[float, int]:
        ts = time.monotonic() if now is None else now
        dq = self._records[key]
        dq.append((ts, is_anomaly))
        self._evict(dq, ts)
        total = len(dq)
        anomalies = sum(1 for _, flag in dq if flag)
        rate = anomalies / total if total > 0 else 0.0
        return rate, total

    def get_rate(self, key: str, now: Optional[float] = None) -> Tuple[float, int]:
        ts = time.monotonic() if now is None else now
        dq = self._records.get(key)
        if not dq:
            return 0.0, 0
        self._evict(dq, ts)
        total = len(dq)
        anomalies = sum(1 for _, flag in dq if flag)
        return (anomalies / total if total > 0 else 0.0), total

    def _evict(self, dq: deque[Tuple[float, bool]], now: float) -> None:
        while dq and (now - dq[0][0]) > self.window_seconds:
            dq.popleft()


# ---------------------------------------------------------------------------
# Unsupervised Isolation Forest Detector
# ---------------------------------------------------------------------------


class AnomalyDetector:
    """
    Unsupervised Isolation Forest anomaly detector operating on BENIGN baseline space.

    Parameters
    ----------
    model_path:
        Path to ``isolation_forest_v{version}.pkl``.
    scaler_path:
        Path to ``feature_scaler_v{version}.pkl``.
    redis_client:
        Optional Redis client to publish evidence to ``detections:anomaly``.
    window_seconds:
        Rolling window duration for per-asset / per-zone anomaly rates.
    investigation_rate_threshold:
        Fraction of anomalous flows in window that triggers an investigation suggestion.
    investigation_min_samples:
        Minimum samples in window before raising an investigation suggestion.
    """

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        scaler_path: Optional[Union[str, Path]] = None,
        redis_client: Any = None,
        window_seconds: int = ANOMALY_RATE_WINDOW_SECONDS,
        investigation_rate_threshold: float = ANOMALY_INVESTIGATION_RATE_THRESHOLD,
        investigation_min_samples: int = ANOMALY_INVESTIGATION_MIN_SAMPLES,
        model_object: Any = None,
        scaler_object: Any = None,
        feature_columns: Optional[List[str]] = None,
        model_version: str = "1",
    ) -> None:
        self._model_dir = Path(MODEL_DIR)
        self.model_version = str(model_version)
        self.model_path = (
            Path(model_path)
            if model_path is not None
            else self._model_dir / f"isolation_forest_v{self.model_version}.pkl"
        )
        self.scaler_path = (
            Path(scaler_path)
            if scaler_path is not None
            else self._model_dir / f"feature_scaler_v{self.model_version}.pkl"
        )
        self._redis = redis_client
        self.investigation_rate_threshold = float(investigation_rate_threshold)
        self.investigation_min_samples = int(investigation_min_samples)

        self.model: Any = None
        self.scaler: Any = None
        self.feature_columns: List[str] = list(feature_columns or FEATURE_COLUMNS)
        self.baseline_mean: Dict[str, float] = {}
        self.baseline_std: Dict[str, float] = {}
        self.protocol_encoding: Dict[str, int] = dict(PROTOCOL_ENCODING)
        self.identity_encoding: Dict[str, int] = dict(IDENTITY_ENCODING)
        self.numeric_medians: Dict[str, float] = {}
        self.contamination: float = ANOMALY_CONTAMINATION

        self._asset_tracker = _WindowRateTracker(window_seconds=window_seconds)
        self._zone_tracker = _WindowRateTracker(window_seconds=window_seconds)
        self._global_tracker = _WindowRateTracker(window_seconds=window_seconds)

        if model_object is not None:
            self._attach_model(model_object)
        else:
            self._load_model()

        if scaler_object is not None:
            self._attach_scaler(scaler_object)
        else:
            self._load_scaler()

    def _attach_model(self, obj: Any) -> None:
        if isinstance(obj, dict) and "model" in obj:
            self.model = obj["model"]
            self.model_version = str(obj.get("version", self.model_version))
            self.feature_columns = list(obj.get("feature_columns", self.feature_columns))
            self.contamination = float(obj.get("contamination", self.contamination))
            prep = obj.get("preprocessing") or {}
            self.protocol_encoding = dict(prep.get("protocol_encoding", self.protocol_encoding))
            self.identity_encoding = dict(prep.get("identity_encoding", self.identity_encoding))
            self.numeric_medians = dict(prep.get("numeric_medians", {}))
        else:
            self.model = obj

    def _attach_scaler(self, obj: Any) -> None:
        if isinstance(obj, dict) and "standard_scaler" in obj:
            self.scaler = obj["standard_scaler"]
            self.baseline_mean = dict(obj.get("baseline_mean", {}))
            self.baseline_std = dict(obj.get("baseline_std", {}))
            if "feature_columns" in obj:
                self.feature_columns = list(obj["feature_columns"])
        else:
            self.scaler = obj
            if hasattr(self.scaler, "mean_") and hasattr(self.scaler, "scale_"):
                self.baseline_mean = {
                    col: float(m) for col, m in zip(self.feature_columns, self.scaler.mean_)
                }
                self.baseline_std = {
                    col: float(s) for col, s in zip(self.feature_columns, self.scaler.scale_)
                }

    def _load_model(self) -> None:
        if not self.model_path.exists():
            logger.warning("Isolation Forest artifact %s not found", self.model_path)
            return
        with open(self.model_path, "rb") as f:
            self._attach_model(pickle.load(f))
        logger.info("Loaded AnomalyDetector v%s from %s", self.model_version, self.model_path)

    def _load_scaler(self) -> None:
        if not self.scaler_path.exists():
            logger.warning("Feature scaler artifact %s not found", self.scaler_path)
            return
        with open(self.scaler_path, "rb") as f:
            self._attach_scaler(pickle.load(f))

    def _vectorize(
        self,
        feature_input: Union[Dict[str, Any], Sequence[float], np.ndarray],
    ) -> Tuple[np.ndarray, np.ndarray, Dict[str, float]]:
        """Return (raw_vec, scaled_vec, named_raw_features)."""
        if isinstance(feature_input, dict):
            vals: List[float] = []
            named: Dict[str, float] = {}
            for col in self.feature_columns:
                raw_val = feature_input.get(col)
                if col == "protocol":
                    if isinstance(raw_val, (int, float)) and not np.isnan(raw_val):
                        v = float(raw_val)
                    else:
                        v = float(
                            self.protocol_encoding.get(
                                str(raw_val or "TCP").strip().upper(),
                                self.protocol_encoding.get("OTHER", 9),
                            )
                        )
                elif col == "identity_classification":
                    if isinstance(raw_val, (int, float)) and not np.isnan(raw_val):
                        v = float(raw_val)
                    else:
                        v = float(
                            self.identity_encoding.get(
                                str(raw_val or "UNKNOWN_IDENTITY").strip().upper(),
                                self.identity_encoding.get("UNKNOWN_IDENTITY", 6),
                            )
                        )
                else:
                    if raw_val is None:
                        v = float(self.numeric_medians.get(col, 0.0))
                    else:
                        try:
                            v = float(raw_val)
                            if np.isnan(v) or np.isinf(v):
                                v = float(self.numeric_medians.get(col, 0.0))
                        except (TypeError, ValueError):
                            v = float(self.numeric_medians.get(col, 0.0))
                vals.append(v)
                named[col] = v
            raw_arr = np.array([vals], dtype=float)
        else:
            raw_arr = np.asarray(feature_input, dtype=float)
            if raw_arr.ndim == 1:
                raw_arr = raw_arr.reshape(1, -1)
            raw_arr = np.nan_to_num(raw_arr, nan=0.0, posinf=0.0, neginf=0.0)
            named = {
                col: float(raw_arr[0, idx]) if idx < raw_arr.shape[1] else 0.0
                for idx, col in enumerate(self.feature_columns)
            }

        scaled_arr = self.scaler.transform(raw_arr) if self.scaler is not None else raw_arr.copy()
        return raw_arr, scaled_arr, named

    def explain_anomaly(
        self,
        raw_features: Dict[str, float],
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Identify features most anomalous relative to the BENIGN baseline mean and std.
        Returns top-K features ranked by absolute z-score deviation.
        """
        deviations: List[Dict[str, Any]] = []
        for col in self.feature_columns:
            obs = float(raw_features.get(col, 0.0))
            mean = float(self.baseline_mean.get(col, 0.0))
            std = float(self.baseline_std.get(col, 1.0))
            safe_std = std if std > 1e-9 else 1.0
            z_score = (obs - mean) / safe_std
            deviations.append(
                {
                    "feature": col,
                    "observed_value": round(obs, 6),
                    "baseline_mean": round(mean, 6),
                    "baseline_std": round(std, 6),
                    "z_score": round(float(z_score), 4),
                    "direction": "above_baseline" if z_score >= 0 else "below_baseline",
                }
            )
        deviations.sort(key=lambda item: abs(item["z_score"]), reverse=True)
        return deviations[:top_k]

    def score(
        self,
        feature_input: Union[Dict[str, Any], Sequence[float], np.ndarray],
        event_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        zone: Optional[str] = None,
        publish: bool = True,
        now: Optional[float] = None,
    ) -> AnomalyResult:
        """
        Score a flow against the BENIGN-baseline Isolation Forest.

        NOTE: Never creates an alert on its own (`creates_alert` is always False).
        Publishes anomaly evidence to ``detections:anomaly`` for correlation.
        """
        if self.model is None:
            raise RuntimeError("Isolation Forest model is not loaded. Run offline training first.")

        ev_id = event_id or (
            str(feature_input.get("event_id") or feature_input.get("flow_id"))
            if isinstance(feature_input, dict)
            and (feature_input.get("event_id") or feature_input.get("flow_id"))
            else str(uuid.uuid4())
        )

        _raw_arr, scaled_arr, named_raw = self._vectorize(feature_input)
        decision = float(self.model.decision_function(scaled_arr)[0])
        pred_flag = int(self.model.predict(scaled_arr)[0])  # -1 = anomaly, 1 = normal
        is_anomaly = pred_flag == -1

        # Map decision_function (roughly [-0.5, 0.5], <0 anomalous) to [0.0, 1.0] via sigmoid
        normalized_score = float(1.0 / (1.0 + np.exp(5.0 * decision)))

        # Track rolling anomaly rates per asset, per zone, and globally
        self._global_tracker.record("global", is_anomaly, now=now)
        suggestion: Optional[Dict[str, Any]] = None

        if asset_id:
            asset_rate, asset_samples = self._asset_tracker.record(asset_id, is_anomaly, now=now)
            if (
                asset_samples >= self.investigation_min_samples
                and asset_rate >= self.investigation_rate_threshold
            ):
                suggestion = {
                    "type": "investigation_suggestion",
                    "scope": "asset",
                    "target": asset_id,
                    "anomaly_rate": round(asset_rate, 4),
                    "sample_count": asset_samples,
                    "message": (
                        f"Elevated anomaly rate ({asset_rate:.1%} over {asset_samples} flows) "
                        f"on asset {asset_id}; recommend analyst review and correlation check."
                    ),
                    "auto_alert": False,
                }

        if zone:
            zone_rate, zone_samples = self._zone_tracker.record(zone, is_anomaly, now=now)
            if (
                suggestion is None
                and zone_samples >= self.investigation_min_samples
                and zone_rate >= self.investigation_rate_threshold
            ):
                suggestion = {
                    "type": "investigation_suggestion",
                    "scope": "zone",
                    "target": zone,
                    "anomaly_rate": round(zone_rate, 4),
                    "sample_count": zone_samples,
                    "message": (
                        f"Elevated anomaly rate ({zone_rate:.1%} over {zone_samples} flows) "
                        f"in zone {zone}; recommend analyst review and correlation check."
                    ),
                    "auto_alert": False,
                }

        anomalous_features = self.explain_anomaly(named_raw, top_k=5) if is_anomaly else []

        result = AnomalyResult(
            event_id=ev_id,
            anomaly_score=round(normalized_score, 6),
            contamination_score=round(decision, 6),
            is_anomaly=is_anomaly,
            creates_alert=False,
            asset_id=asset_id,
            zone=zone,
            anomalous_features=anomalous_features,
            investigation_suggestion=suggestion,
            model_version=self.model_version,
        )

        if publish:
            result.published = self._publish_anomaly(result)

        return result

    def _publish_anomaly(self, result: AnomalyResult) -> bool:
        """Publish anomaly evidence (not alert) to Redis stream ``detections:anomaly``."""
        if self._redis is None:
            return False
        try:
            payload = {
                "event_id": result.event_id,
                "anomaly_score": str(result.anomaly_score),
                "contamination_score": str(result.contamination_score),
                "is_anomaly": "true" if result.is_anomaly else "false",
                "creates_alert": "false",
                "asset_id": result.asset_id or "",
                "zone": result.zone or "",
                "anomalous_features": json.dumps(result.anomalous_features),
                "investigation_suggestion": json.dumps(result.investigation_suggestion or {}),
                "model_version": result.model_version,
                "timestamp": result.timestamp,
            }
            self._redis.xadd(REDIS_STREAM_ANOMALY_DETECTIONS, payload)
            return True
        except Exception as exc:
            logger.error("Failed to publish anomaly score to Redis: %s", exc)
            return False

    def get_asset_anomaly_rate(self, asset_id: str, now: Optional[float] = None) -> Dict[str, Any]:
        rate, count = self._asset_tracker.get_rate(asset_id, now=now)
        return {"asset_id": asset_id, "anomaly_rate": round(rate, 4), "sample_count": count}

    def get_zone_anomaly_rate(self, zone: str, now: Optional[float] = None) -> Dict[str, Any]:
        rate, count = self._zone_tracker.get_rate(zone, now=now)
        return {"zone": zone, "anomaly_rate": round(rate, 4), "sample_count": count}

    def get_global_anomaly_rate(self, now: Optional[float] = None) -> Dict[str, Any]:
        rate, count = self._global_tracker.get_rate("global", now=now)
        return {"anomaly_rate": round(rate, 4), "sample_count": count}
