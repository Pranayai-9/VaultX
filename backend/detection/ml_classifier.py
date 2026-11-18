"""
ml_classifier.py — Supervised Random Forest Classifier for VaultX Detection Engine.

BECPL (Bharat Electronics Components Pvt. Ltd.), Pune — Manufacturing-Aware Hybrid NIDS.

Capabilities
------------
* Loads trained Random Forest artifact from ``backend/models/rf_classifier_v{version}.pkl``
  (optionally trains offline artifact if missing and explicitly allowed).
* Accepts feature vectors produced by ``backend/processing/feature_extractor.py`` (dict or array).
* Multi-class prediction across all 8 BECPL classes:
  ``BENIGN``, ``VENDOR_COMPROMISE``, ``SERVICE_MISUSE``, ``LATERAL_MOVEMENT``,
  ``LOTL``, ``ENCRYPTED_EXFIL``, ``OT_ANOMALY``, ``VULNERABILITY_SCAN``.
* Outputs ``binary_label`` (0 = benign/uncertain, 1 = attack).
* Confidence calibration: probability estimates checked against ``ML_CONFIDENCE_THRESHOLD``
  (default 0.65). Predictions below threshold are classified as ``UNCERTAIN`` rather than attack.
* Explainability: returns top-5 contributing features using SHAP TreeExplainer
  (with deterministic feature-importance fallback if SHAP is unavailable).
* Publishes detections with ``confidence >= threshold`` and ``predicted_class != BENIGN``
  to Redis stream ``detections:ml``.
* Tracks analyst false-positive corrections in PostgreSQL (``becpl_nids.ml_feedback``)
  for future offline retraining cycles.
"""

from __future__ import annotations

import json
import logging
import pickle
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np

try:
    import shap

    SHAP_AVAILABLE = True
except ImportError:  # pragma: no cover
    SHAP_AVAILABLE = False

try:
    import sqlalchemy as sa
except ImportError:  # pragma: no cover
    sa = None  # type: ignore[assignment]

try:
    from backend.detection.detection_config import (
        ALL_LABELS,
        DEFAULT_DATASET_PATH,
        FEATURE_COLUMNS,
        IDENTITY_ENCODING,
        ML_CONFIDENCE_THRESHOLD,
        MODEL_DIR,
        PROTOCOL_ENCODING,
        REDIS_STREAM_ML_DETECTIONS,
        UNCERTAIN_LABEL,
    )
except ImportError:
    from detection_config import (  # type: ignore[no-redef]
        ALL_LABELS,
        DEFAULT_DATASET_PATH,
        FEATURE_COLUMNS,
        IDENTITY_ENCODING,
        ML_CONFIDENCE_THRESHOLD,
        MODEL_DIR,
        PROTOCOL_ENCODING,
        REDIS_STREAM_ML_DETECTIONS,
        UNCERTAIN_LABEL,
    )

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prediction & Feedback Data Models
# ---------------------------------------------------------------------------


@dataclass
class MLPrediction:
    """Structured prediction returned by ``MLClassifier``."""

    event_id: str
    predicted_class: str
    raw_predicted_class: str
    confidence_score: float
    binary_label: int  # 0 = benign or uncertain, 1 = confirmed-confidence attack
    is_uncertain: bool
    top_features: List[Dict[str, Any]]
    class_probabilities: Dict[str, float]
    model_version: str
    timestamp: str = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())
    published: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalystFeedback:
    """Analyst correction / false-positive label stored for future retraining."""

    feedback_id: str
    event_id: str
    predicted_class: str
    corrected_class: str
    analyst_id: str
    is_false_positive: bool
    notes: str = ""
    model_version: str = "1"
    feature_vector: Dict[str, Any] = field(default_factory=dict)
    recorded_at: str = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# PostgreSQL DDL for Analyst Feedback
# ---------------------------------------------------------------------------

ML_FEEDBACK_DDL = """
CREATE TABLE IF NOT EXISTS becpl_nids.ml_feedback (
    feedback_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id           VARCHAR(100) NOT NULL,
    model_version      VARCHAR(50) NOT NULL,
    predicted_class    VARCHAR(100) NOT NULL,
    corrected_class    VARCHAR(100) NOT NULL,
    is_false_positive  BOOLEAN NOT NULL,
    analyst_id         VARCHAR(100) NOT NULL,
    notes              TEXT,
    feature_vector     JSONB,
    recorded_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


# ---------------------------------------------------------------------------
# Supervised ML Classifier
# ---------------------------------------------------------------------------


class MLClassifier:
    """
    Supervised Random Forest NIDS classifier with confidence gating and SHAP explainability.

    Parameters
    ----------
    model_path:
        Path to ``rf_classifier_v{version}.pkl``. Defaults to ``backend/models/rf_classifier_v1.pkl``.
    shap_explainer_path:
        Optional path to ``shap_explainer_v{version}.pkl``.
    confidence_threshold:
        Minimum probability threshold (default 0.65). Below this -> ``UNCERTAIN``.
    redis_client:
        Optional Redis client to publish detections to ``detections:ml``.
    db_session_factory:
        Optional SQLAlchemy session factory for storing analyst false-positive feedback.
    auto_train_if_missing:
        If True and ``model_path`` does not exist, invokes ``ModelTrainer`` to generate v1.
    model_object:
        Optional pre-loaded sklearn model (convenient for dependency injection / testing).
    """

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        shap_explainer_path: Optional[Union[str, Path]] = None,
        confidence_threshold: float = ML_CONFIDENCE_THRESHOLD,
        redis_client: Any = None,
        db_session_factory: Optional[Callable[[], Any]] = None,
        auto_train_if_missing: bool = False,
        model_object: Any = None,
        feature_columns: Optional[List[str]] = None,
        model_version: str = "1",
    ) -> None:
        self.confidence_threshold = float(confidence_threshold)
        self._redis = redis_client
        self._db_factory = db_session_factory
        self._model_dir = Path(MODEL_DIR)
        self.model_path = (
            Path(model_path)
            if model_path is not None
            else self._model_dir / f"rf_classifier_v{model_version}.pkl"
        )
        self.shap_explainer_path = (
            Path(shap_explainer_path)
            if shap_explainer_path is not None
            else self._model_dir / f"shap_explainer_v{model_version}.pkl"
        )

        self.model: Any = None
        self.rf_scaler: Any = None
        self.shap_explainer: Any = None
        self.feature_columns: List[str] = list(feature_columns or FEATURE_COLUMNS)
        self.classes_: List[str] = list(ALL_LABELS)
        self.protocol_encoding: Dict[str, int] = dict(PROTOCOL_ENCODING)
        self.identity_encoding: Dict[str, int] = dict(IDENTITY_ENCODING)
        self.numeric_medians: Dict[str, float] = {}
        self.model_version: str = str(model_version)
        self._feedback_buffer: List[AnalystFeedback] = []

        if model_object is not None:
            self._attach_model_object(model_object)
        else:
            self._load_artifacts(auto_train_if_missing=auto_train_if_missing)

    def _attach_model_object(self, obj: Any) -> None:
        if isinstance(obj, dict) and "model" in obj:
            self.model = obj["model"]
            self.model_version = str(obj.get("version", self.model_version))
            self.feature_columns = list(obj.get("feature_columns", self.feature_columns))
            self.rf_scaler = obj.get("rf_scaler")
            prep = obj.get("preprocessing") or {}
            self.protocol_encoding = dict(prep.get("protocol_encoding", self.protocol_encoding))
            self.identity_encoding = dict(prep.get("identity_encoding", self.identity_encoding))
            self.numeric_medians = dict(prep.get("numeric_medians", {}))
            if hasattr(self.model, "classes_"):
                self.classes_ = [str(c) for c in self.model.classes_]
            elif "classes" in obj:
                self.classes_ = [str(c) for c in obj["classes"]]
        else:
            self.model = obj
            if hasattr(self.model, "classes_"):
                self.classes_ = [str(c) for c in self.model.classes_]

    def _load_artifacts(self, auto_train_if_missing: bool = False) -> None:
        if not self.model_path.exists():
            if auto_train_if_missing:
                logger.warning(
                    "Model artifact %s not found; triggering offline trainer", self.model_path
                )
                try:
                    from backend.detection.model_trainer import ModelTrainer
                except ImportError:
                    from model_trainer import ModelTrainer  # type: ignore[no-redef]
                trainer = ModelTrainer(model_dir=self.model_path.parent)
                trainer.train(dataset_path=DEFAULT_DATASET_PATH, version=self.model_version)
            else:
                logger.warning(
                    "Model artifact %s not found; classifier initialized without loaded weights",
                    self.model_path,
                )
                return

        with open(self.model_path, "rb") as f:
            bundle = pickle.load(f)
        self._attach_model_object(bundle)
        logger.info("Loaded MLClassifier v%s from %s", self.model_version, self.model_path)

        # Load SHAP explainer if available
        if self.shap_explainer_path.exists():
            try:
                with open(self.shap_explainer_path, "rb") as f:
                    shap_obj = pickle.load(f)
                self.shap_explainer = (
                    shap_obj["explainer"] if isinstance(shap_obj, dict) else shap_obj
                )
            except Exception as exc:
                logger.warning("Failed to load SHAP explainer %s: %s", self.shap_explainer_path, exc)

        if self.shap_explainer is None and SHAP_AVAILABLE and self.model is not None:
            try:
                self.shap_explainer = shap.TreeExplainer(self.model)
            except Exception:
                self.shap_explainer = None

    def vectorize_features(
        self,
        feature_input: Union[Dict[str, Any], Sequence[float], np.ndarray],
    ) -> Tuple[np.ndarray, Dict[str, float]]:
        """
        Convert feature_extractor dict or numeric sequence into a (1, n_features) numpy array
        matching ``self.feature_columns``.
        """
        if isinstance(feature_input, dict):
            values: List[float] = []
            named: Dict[str, float] = {}
            for col in self.feature_columns:
                raw_val = feature_input.get(col)
                if col == "protocol":
                    if isinstance(raw_val, (int, float)) and not np.isnan(raw_val):
                        val = float(raw_val)
                    else:
                        proto_str = str(raw_val or "TCP").strip().upper()
                        val = float(self.protocol_encoding.get(proto_str, self.protocol_encoding.get("OTHER", 9)))
                elif col == "identity_classification":
                    if isinstance(raw_val, (int, float)) and not np.isnan(raw_val):
                        val = float(raw_val)
                    else:
                        id_str = str(raw_val or "UNKNOWN_IDENTITY").strip().upper()
                        val = float(
                            self.identity_encoding.get(
                                id_str, self.identity_encoding.get("UNKNOWN_IDENTITY", 6)
                            )
                        )
                else:
                    if raw_val is None or (isinstance(raw_val, float) and (np.isnan(raw_val) or np.isinf(raw_val))):
                        val = float(self.numeric_medians.get(col, 0.0))
                    else:
                        try:
                            val = float(raw_val)
                            if np.isnan(val) or np.isinf(val):
                                val = float(self.numeric_medians.get(col, 0.0))
                        except (TypeError, ValueError):
                            val = float(self.numeric_medians.get(col, 0.0))
                values.append(val)
                named[col] = val
            arr = np.array([values], dtype=float)
        else:
            arr = np.asarray(feature_input, dtype=float)
            if arr.ndim == 1:
                arr = arr.reshape(1, -1)
            arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
            named = {
                col: float(arr[0, idx]) if idx < arr.shape[1] else 0.0
                for idx, col in enumerate(self.feature_columns)
            }

        if self.rf_scaler is not None:
            arr = self.rf_scaler.transform(arr)

        return arr, named

    def _compute_top_features(
        self,
        X_vec: np.ndarray,
        named_features: Dict[str, float],
        class_idx: int,
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """Compute top-K SHAP contributing features for the predicted class."""
        shap_contribs: Optional[np.ndarray] = None

        if self.shap_explainer is not None:
            try:
                raw_shap = self.shap_explainer.shap_values(X_vec)
                if isinstance(raw_shap, list):
                    # Older SHAP format: list of (n_samples, n_features) per class
                    shap_contribs = np.asarray(raw_shap[class_idx])[0]
                else:
                    arr = np.asarray(raw_shap)
                    if arr.ndim == 3:
                        # Newer SHAP format: (n_samples, n_features, n_classes)
                        shap_contribs = arr[0, :, class_idx]
                    elif arr.ndim == 2:
                        shap_contribs = arr[0]
            except Exception as exc:
                logger.debug("SHAP computation fallback triggered: %s", exc)

        if shap_contribs is None:
            # Deterministic fallback using RF feature_importances_
            importances = getattr(self.model, "feature_importances_", None)
            if importances is not None and len(importances) == len(self.feature_columns):
                shap_contribs = np.asarray(importances, dtype=float)
            else:
                shap_contribs = np.zeros(len(self.feature_columns), dtype=float)

        ranked_indices = np.argsort(np.abs(shap_contribs))[::-1][:top_k]
        top_list: List[Dict[str, Any]] = []
        for idx in ranked_indices:
            if idx < len(self.feature_columns):
                fname = self.feature_columns[int(idx)]
                top_list.append(
                    {
                        "feature": fname,
                        "shap_value": round(float(shap_contribs[int(idx)]), 6),
                        "feature_value": round(float(named_features.get(fname, 0.0)), 6),
                    }
                )
        return top_list

    def predict(
        self,
        feature_input: Union[Dict[str, Any], Sequence[float], np.ndarray],
        event_id: Optional[str] = None,
        publish: bool = True,
    ) -> MLPrediction:
        """
        Classify a single feature vector with confidence gating and SHAP explainability.
        """
        if self.model is None:
            raise RuntimeError("MLClassifier model is not loaded. Run offline training first.")

        ev_id = event_id or (
            str(feature_input.get("event_id") or feature_input.get("flow_id"))
            if isinstance(feature_input, dict)
            and (feature_input.get("event_id") or feature_input.get("flow_id"))
            else str(uuid.uuid4())
        )

        X_vec, named_features = self.vectorize_features(feature_input)
        probs = self.model.predict_proba(X_vec)[0]
        classes = [str(c) for c in getattr(self.model, "classes_", self.classes_)]

        best_idx = int(np.argmax(probs))
        raw_class = classes[best_idx]
        confidence = float(probs[best_idx])

        # Confidence calibration gate
        if confidence < self.confidence_threshold:
            predicted_class = UNCERTAIN_LABEL
            is_uncertain = True
            binary_label = 0
        else:
            predicted_class = raw_class
            is_uncertain = False
            binary_label = 0 if predicted_class == "BENIGN" else 1

        top_features = self._compute_top_features(X_vec, named_features, best_idx, top_k=5)
        prob_map = {cls_name: round(float(p), 6) for cls_name, p in zip(classes, probs)}

        prediction = MLPrediction(
            event_id=ev_id,
            predicted_class=predicted_class,
            raw_predicted_class=raw_class,
            confidence_score=round(confidence, 6),
            binary_label=binary_label,
            is_uncertain=is_uncertain,
            top_features=top_features,
            class_probabilities=prob_map,
            model_version=self.model_version,
        )

        # Publish high-confidence non-BENIGN detections to detections:ml
        if (
            publish
            and not prediction.is_uncertain
            and prediction.confidence_score >= self.confidence_threshold
            and prediction.predicted_class != "BENIGN"
        ):
            prediction.published = self._publish_detection(prediction)

        return prediction

    def _publish_detection(self, prediction: MLPrediction) -> bool:
        """Publish confirmed-confidence attack predictions to Redis ``detections:ml``."""
        if self._redis is None:
            return False
        try:
            payload = {
                "event_id": prediction.event_id,
                "predicted_class": prediction.predicted_class,
                "confidence_score": str(prediction.confidence_score),
                "binary_label": str(prediction.binary_label),
                "top_features": json.dumps(prediction.top_features),
                "class_probabilities": json.dumps(prediction.class_probabilities),
                "model_version": prediction.model_version,
                "timestamp": prediction.timestamp,
            }
            self._redis.xadd(REDIS_STREAM_ML_DETECTIONS, payload)
            return True
        except Exception as exc:
            logger.error("Failed to publish ML detection to Redis: %s", exc)
            return False

    def record_analyst_feedback(
        self,
        event_id: str,
        predicted_class: str,
        corrected_class: str,
        analyst_id: str,
        notes: str = "",
        feature_vector: Optional[Dict[str, Any]] = None,
    ) -> AnalystFeedback:
        """
        Record analyst correction (e.g., marking an attack prediction as BENIGN false positive)
        in PostgreSQL ``becpl_nids.ml_feedback`` for future offline retraining.
        """
        is_fp = predicted_class != "BENIGN" and corrected_class == "BENIGN"
        fb = AnalystFeedback(
            feedback_id=str(uuid.uuid4()),
            event_id=event_id,
            predicted_class=predicted_class,
            corrected_class=corrected_class,
            analyst_id=analyst_id,
            is_false_positive=is_fp,
            notes=notes,
            model_version=self.model_version,
            feature_vector=feature_vector or {},
        )
        self._feedback_buffer.append(fb)

        if self._db_factory is not None and sa is not None:
            session = None
            try:
                session = self._db_factory()
                session.execute(sa.text(ML_FEEDBACK_DDL))
                session.execute(
                    sa.text(
                        """
                        INSERT INTO becpl_nids.ml_feedback (
                            feedback_id, event_id, model_version,
                            predicted_class, corrected_class, is_false_positive,
                            analyst_id, notes, feature_vector
                        ) VALUES (
                            CAST(:feedback_id AS UUID), :event_id, :model_version,
                            :predicted_class, :corrected_class, :is_false_positive,
                            :analyst_id, :notes, CAST(:feature_vector AS JSONB)
                        )
                        """
                    ),
                    {
                        "feedback_id": fb.feedback_id,
                        "event_id": fb.event_id,
                        "model_version": fb.model_version,
                        "predicted_class": fb.predicted_class,
                        "corrected_class": fb.corrected_class,
                        "is_false_positive": fb.is_false_positive,
                        "analyst_id": fb.analyst_id,
                        "notes": fb.notes,
                        "feature_vector": json.dumps(fb.feature_vector),
                    },
                )
                session.commit()
            except Exception as exc:
                logger.error("Failed to persist analyst feedback: %s", exc)
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

        return fb

    def get_false_positive_summary(self) -> Dict[str, Any]:
        """Return summary statistics of in-memory analyst false-positive feedback."""
        total = len(self._feedback_buffer)
        fps = [f for f in self._feedback_buffer if f.is_false_positive]
        by_class: Dict[str, int] = {}
        for f in fps:
            by_class[f.predicted_class] = by_class.get(f.predicted_class, 0) + 1
        return {
            "total_feedback": total,
            "false_positives": len(fps),
            "false_positive_by_predicted_class": by_class,
        }
