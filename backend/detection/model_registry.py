"""
model_registry.py — Model Version Registry and Controlled Deployment for VaultX.

BECPL (Bharat Electronics Components Pvt. Ltd.), Pune — Manufacturing-Aware Hybrid NIDS.

Governance Model
----------------
* Tracks all trained model versions in PostgreSQL ``becpl_nids.ml_models``
  (with local JSON manifest fallback for offline / unit-test execution).
* Strict lifecycle progression:
  ``candidate`` -> ``validated`` -> ``approved`` -> ``deployed`` -> ``retired``
* A candidate model can ONLY be marked ``approved`` when BOTH conditions hold:
  1. Evaluation metrics satisfy quality thresholds (macro F1, weighted F1, max FPR).
  2. Explicit human approval is recorded in ``becpl_nids.response_actions``.
* Supports controlled promotion (``promote_model``), holdout comparison against
  the currently deployed model (``compare_models``), versioned loading with automatic
  fallback (``load_model``), and instant rollback (``rollback_model``).
* Logs EVERY lifecycle transition to ``becpl_nids.audit_log``.
"""

from __future__ import annotations

import json
import logging
import pickle
import uuid
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import numpy as np

try:
    import sqlalchemy as sa
except ImportError:  # pragma: no cover
    sa = None  # type: ignore[assignment]

try:
    from sklearn.metrics import f1_score
except ImportError:  # pragma: no cover
    f1_score = None  # type: ignore[assignment]

try:
    from backend.detection.detection_config import (
        MODEL_DIR,
        MODEL_LIFECYCLE_STATES,
        MODEL_MAX_FPR,
        MODEL_MIN_MACRO_F1,
        MODEL_MIN_WEIGHTED_F1,
        MODEL_STATE_APPROVED,
        MODEL_STATE_CANDIDATE,
        MODEL_STATE_DEPLOYED,
        MODEL_STATE_RETIRED,
        MODEL_STATE_VALIDATED,
    )
except ImportError:
    from detection_config import (  # type: ignore[no-redef]
        MODEL_DIR,
        MODEL_LIFECYCLE_STATES,
        MODEL_MAX_FPR,
        MODEL_MIN_MACRO_F1,
        MODEL_MIN_WEIGHTED_F1,
        MODEL_STATE_APPROVED,
        MODEL_STATE_CANDIDATE,
        MODEL_STATE_DEPLOYED,
        MODEL_STATE_RETIRED,
        MODEL_STATE_VALIDATED,
    )

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class ModelRecord:
    """Metadata record for a registered model version."""

    version_id: str
    model_name: str
    model_type: str
    state: str = MODEL_STATE_CANDIDATE
    training_dataset: str = ""
    training_date: str = field(default_factory=lambda: date.today().isoformat())
    metrics: Dict[str, Any] = field(default_factory=dict)
    artifact_paths: Dict[str, str] = field(default_factory=dict)
    approved_by: Optional[str] = None
    approval_action_id: Optional[str] = None
    approved_at: Optional[str] = None
    deployed_at: Optional[str] = None
    retired_at: Optional[str] = None
    is_active: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LoadedModelBundle:
    """Loaded inference artifacts for a model version."""

    version_id: str
    rf_bundle: Any
    isolation_forest_bundle: Any = None
    scaler_bundle: Any = None
    shap_bundle: Any = None
    fallback_used: bool = False
    requested_version: Optional[str] = None


# ---------------------------------------------------------------------------
# Model Registry Service
# ---------------------------------------------------------------------------


class ModelRegistry:
    """
    Manages model lifecycle, human-gated approval, deployment, comparison, and rollback.

    Parameters
    ----------
    model_dir:
        Directory containing serialized model artifacts and ``evaluation_report_v*.json``.
    db_session_factory:
        Optional SQLAlchemy session factory connected to ``becpl_nids``.
    manifest_path:
        Optional path to local JSON registry manifest (defaults to ``<model_dir>/registry.json``).
    min_macro_f1:
        Minimum RF macro F1 required for validation/approval.
    min_weighted_f1:
        Minimum RF weighted F1 required for validation/approval.
    max_fpr:
        Maximum acceptable RF false positive rate on benign traffic.
    """

    def __init__(
        self,
        model_dir: Union[str, Path] = MODEL_DIR,
        db_session_factory: Optional[Callable[[], Any]] = None,
        manifest_path: Optional[Union[str, Path]] = None,
        min_macro_f1: float = MODEL_MIN_MACRO_F1,
        min_weighted_f1: float = MODEL_MIN_WEIGHTED_F1,
        max_fpr: float = MODEL_MAX_FPR,
    ) -> None:
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self._db_factory = db_session_factory
        self.manifest_path = (
            Path(manifest_path) if manifest_path is not None else self.model_dir / "registry.json"
        )
        self.min_macro_f1 = float(min_macro_f1)
        self.min_weighted_f1 = float(min_weighted_f1)
        self.max_fpr = float(max_fpr)

        self._models: Dict[str, ModelRecord] = {}
        self._deployment_history: List[str] = []
        self._audit_events: List[Dict[str, Any]] = []
        self._approval_actions: Dict[str, Dict[str, Any]] = {}

        self._load_manifest()

    # ------------------------------------------------------------------
    # Manifest persistence (offline / local state)
    # ------------------------------------------------------------------

    def _load_manifest(self) -> None:
        if not self.manifest_path.exists():
            return
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for ver, rec_dict in (data.get("models") or {}).items():
                self._models[ver] = ModelRecord(**rec_dict)
            self._deployment_history = list(data.get("deployment_history") or [])
        except Exception as exc:
            logger.warning("Failed to load local registry manifest %s: %s", self.manifest_path, exc)

    def _save_manifest(self) -> None:
        try:
            payload = {
                "updated_at": datetime.now(tz=timezone.utc).isoformat(),
                "deployment_history": self._deployment_history,
                "models": {ver: rec.to_dict() for ver, rec in self._models.items()},
            }
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as exc:
            logger.warning("Failed to save local registry manifest: %s", exc)

    # ------------------------------------------------------------------
    # Audit & DB Helpers
    # ------------------------------------------------------------------

    def _log_audit(
        self,
        actor: str,
        action: str,
        target_id: str,
        old_value: Optional[Dict[str, Any]] = None,
        new_value: Optional[Dict[str, Any]] = None,
        outcome: str = "success",
        failure_reason: Optional[str] = None,
    ) -> None:
        entry = {
            "audit_id": str(uuid.uuid4()),
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "actor": actor,
            "actor_type": "human_operator" if actor not in ("system", "model_registry") else "system",
            "action": action,
            "target_table": "ml_models",
            "target_id": target_id,
            "old_value": old_value,
            "new_value": new_value,
            "outcome": outcome,
            "failure_reason": failure_reason,
        }
        self._audit_events.append(entry)

        if self._db_factory is None or sa is None:
            return
        session = None
        try:
            session = self._db_factory()
            session.execute(
                sa.text(
                    """
                    INSERT INTO becpl_nids.audit_log (
                        actor, actor_type, action, target_table, target_id,
                        old_value, new_value, outcome, failure_reason
                    ) VALUES (
                        :actor, :actor_type, :action, 'ml_models', :target_id,
                        CAST(:old_value AS JSONB), CAST(:new_value AS JSONB),
                        :outcome, :failure_reason
                    )
                    """
                ),
                {
                    "actor": entry["actor"],
                    "actor_type": entry["actor_type"],
                    "action": entry["action"],
                    "target_id": entry["target_id"],
                    "old_value": json.dumps(old_value) if old_value is not None else None,
                    "new_value": json.dumps(new_value) if new_value is not None else None,
                    "outcome": outcome,
                    "failure_reason": failure_reason,
                },
            )
            session.commit()
        except Exception as exc:
            logger.error("Failed to write model transition to audit_log: %s", exc)
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

    def _record_human_approval_in_db(
        self,
        version_id: str,
        approver_id: str,
        approval_method: str = "manager_approval",
        notes: str = "",
    ) -> str:
        """Record human model approval in PostgreSQL ``becpl_nids.response_actions``."""
        action_id = str(uuid.uuid4())
        now_iso = datetime.now(tz=timezone.utc).isoformat()
        self._approval_actions[action_id] = {
            "action_id": action_id,
            "version_id": version_id,
            "approver_id": approver_id,
            "approval_method": approval_method,
            "approval_timestamp": now_iso,
            "status": "approved",
            "notes": notes,
        }

        if self._db_factory is None or sa is None:
            return action_id

        session = None
        try:
            session = self._db_factory()
            session.execute(
                sa.text(
                    """
                    INSERT INTO becpl_nids.response_actions (
                        action_id, action_type, initiated_by, approved_by,
                        approval_method, approval_timestamp, status,
                        execution_detail, notes
                    ) VALUES (
                        CAST(:action_id AS UUID), 'notify', :initiated_by, :approved_by,
                        :approval_method, NOW(), 'approved',
                        CAST(:detail AS JSONB), :notes
                    )
                    """
                ),
                {
                    "action_id": action_id,
                    "initiated_by": approver_id,
                    "approved_by": approver_id,
                    "approval_method": approval_method,
                    "detail": json.dumps(
                        {"governance_action": "model_approval", "model_version": version_id}
                    ),
                    "notes": notes or f"Human approval for VaultX ML model v{version_id}",
                },
            )
            session.commit()
        except Exception as exc:
            logger.error("Failed to record human approval in response_actions: %s", exc)
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
        return action_id

    def _sync_model_to_db(self, rec: ModelRecord) -> None:
        if self._db_factory is None or sa is None:
            return
        session = None
        try:
            session = self._db_factory()
            session.execute(
                sa.text(
                    """
                    INSERT INTO becpl_nids.ml_models (
                        model_name, model_version, model_type, training_dataset,
                        training_date, performance_metrics, threshold_config,
                        is_active, deployed_at, retired_at, notes
                    ) VALUES (
                        :model_name, :model_version, :model_type, :training_dataset,
                        CAST(:training_date AS DATE), CAST(:metrics AS JSONB),
                        CAST(:threshold_config AS JSONB), :is_active,
                        :deployed_at, :retired_at, :notes
                    )
                    """
                ),
                {
                    "model_name": rec.model_name,
                    "model_version": rec.version_id,
                    "model_type": rec.model_type,
                    "training_dataset": rec.training_dataset,
                    "training_date": rec.training_date,
                    "metrics": json.dumps(rec.metrics),
                    "threshold_config": json.dumps(
                        {
                            "lifecycle_state": rec.state,
                            "approved_by": rec.approved_by,
                            "approval_action_id": rec.approval_action_id,
                        }
                    ),
                    "is_active": rec.is_active,
                    "deployed_at": rec.deployed_at,
                    "retired_at": rec.retired_at,
                    "notes": rec.notes,
                },
            )
            session.commit()
        except Exception as exc:
            logger.error("Failed to sync model v%s to ml_models: %s", rec.version_id, exc)
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

    # ------------------------------------------------------------------
    # Lifecycle Operations
    # ------------------------------------------------------------------

    def register_model(
        self,
        version_id: str,
        metrics: Optional[Dict[str, Any]] = None,
        model_name: str = "vaultx_rf_classifier",
        model_type: str = "classification",
        training_dataset: str = "becpl_synthetic_traffic_50k.csv",
        artifact_paths: Optional[Dict[str, str]] = None,
        actor: str = "system",
        notes: str = "",
    ) -> ModelRecord:
        """Register a newly trained model version in ``candidate`` state."""
        version_id = str(version_id)
        if metrics is None:
            report_file = self.model_dir / f"evaluation_report_v{version_id}.json"
            if report_file.exists():
                with open(report_file, "r", encoding="utf-8") as f:
                    metrics = json.load(f)
            else:
                metrics = {}

        default_artifacts = {
            "rf_classifier": str(self.model_dir / f"rf_classifier_v{version_id}.pkl"),
            "isolation_forest": str(self.model_dir / f"isolation_forest_v{version_id}.pkl"),
            "feature_scaler": str(self.model_dir / f"feature_scaler_v{version_id}.pkl"),
            "shap_explainer": str(self.model_dir / f"shap_explainer_v{version_id}.pkl"),
            "evaluation_report": str(self.model_dir / f"evaluation_report_v{version_id}.json"),
        }
        if artifact_paths:
            default_artifacts.update(artifact_paths)

        record = ModelRecord(
            version_id=version_id,
            model_name=model_name,
            model_type=model_type,
            state=MODEL_STATE_CANDIDATE,
            training_dataset=training_dataset,
            metrics=metrics,
            artifact_paths=default_artifacts,
            is_active=False,
            notes=notes,
        )
        self._models[version_id] = record
        self._save_manifest()
        self._sync_model_to_db(record)
        self._log_audit(
            actor=actor,
            action="model_registered",
            target_id=version_id,
            new_value={"state": MODEL_STATE_CANDIDATE, "model_name": model_name},
        )
        return record

    def _extract_rf_metrics(self, metrics: Dict[str, Any]) -> Tuple[float, float, float]:
        rf = metrics.get("rf_classifier", metrics)
        macro_f1 = float(rf.get("macro_f1", 0.0))
        weighted_f1 = float(rf.get("weighted_f1", 0.0))
        fpr = float(rf.get("false_positive_rate", 1.0))
        return macro_f1, weighted_f1, fpr

    def check_metric_thresholds(self, version_id: str) -> Tuple[bool, List[str]]:
        """Verify whether a model's evaluation metrics satisfy BECPL deployment gates."""
        rec = self._models.get(str(version_id))
        if rec is None:
            return False, [f"Model version {version_id} not registered"]

        macro_f1, weighted_f1, fpr = self._extract_rf_metrics(rec.metrics)
        reasons: List[str] = []
        if macro_f1 < self.min_macro_f1:
            reasons.append(f"macro_f1 {macro_f1:.4f} < threshold {self.min_macro_f1:.4f}")
        if weighted_f1 < self.min_weighted_f1:
            reasons.append(f"weighted_f1 {weighted_f1:.4f} < threshold {self.min_weighted_f1:.4f}")
        if fpr > self.max_fpr:
            reasons.append(f"false_positive_rate {fpr:.4f} > max {self.max_fpr:.4f}")
        return len(reasons) == 0, reasons

    def validate_model(self, version_id: str, actor: str = "system") -> Tuple[bool, List[str]]:
        """Transition a ``candidate`` model to ``validated`` if evaluation metrics pass thresholds."""
        version_id = str(version_id)
        rec = self._models.get(version_id)
        if rec is None:
            raise KeyError(f"Model version '{version_id}' is not registered")

        passed, reasons = self.check_metric_thresholds(version_id)
        if not passed:
            self._log_audit(
                actor=actor,
                action="model_validation_failed",
                target_id=version_id,
                old_value={"state": rec.state},
                new_value={"state": rec.state, "reasons": reasons},
                outcome="failure",
                failure_reason="; ".join(reasons),
            )
            return False, reasons

        old_state = rec.state
        rec.state = MODEL_STATE_VALIDATED
        self._save_manifest()
        self._log_audit(
            actor=actor,
            action="model_validated",
            target_id=version_id,
            old_value={"state": old_state},
            new_value={"state": rec.state},
        )
        return True, []

    def approve_model(
        self,
        version_id: str,
        approver_id: str,
        approval_method: str = "manager_approval",
        notes: str = "",
    ) -> ModelRecord:
        """
        Mark a model as ``approved`` ONLY if evaluation metrics pass thresholds AND
        an explicit human approver ID is provided. Approval is persisted to ``response_actions``.
        """
        version_id = str(version_id)
        if not approver_id or not str(approver_id).strip():
            raise ValueError("Explicit human approver_id is required to approve a model")

        rec = self._models.get(version_id)
        if rec is None:
            raise KeyError(f"Model version '{version_id}' is not registered")

        passed, reasons = self.check_metric_thresholds(version_id)
        if not passed:
            self._log_audit(
                actor=approver_id,
                action="model_approval_rejected",
                target_id=version_id,
                old_value={"state": rec.state},
                outcome="failure",
                failure_reason="; ".join(reasons),
            )
            raise ValueError(
                f"Cannot approve model v{version_id}: evaluation thresholds not met ({'; '.join(reasons)})"
            )

        # Ensure validated step occurred
        if rec.state == MODEL_STATE_CANDIDATE:
            rec.state = MODEL_STATE_VALIDATED

        action_id = self._record_human_approval_in_db(
            version_id=version_id,
            approver_id=approver_id,
            approval_method=approval_method,
            notes=notes,
        )
        old_state = rec.state
        rec.state = MODEL_STATE_APPROVED
        rec.approved_by = approver_id
        rec.approval_action_id = action_id
        rec.approved_at = datetime.now(tz=timezone.utc).isoformat()
        self._save_manifest()
        self._log_audit(
            actor=approver_id,
            action="model_approved",
            target_id=version_id,
            old_value={"state": old_state},
            new_value={
                "state": rec.state,
                "approved_by": approver_id,
                "approval_action_id": action_id,
            },
        )
        return rec

    def promote_model(
        self,
        version_id: str,
        approver_id: str,
        approval_method: str = "manager_approval",
        notes: str = "",
    ) -> ModelRecord:
        """
        Approve (if validated/candidate and thresholds met) and deploy ``version_id`` as active.
        Retires the previously deployed model version and records full audit trail.
        """
        version_id = str(version_id)
        rec = self._models.get(version_id)
        if rec is None:
            raise KeyError(f"Model version '{version_id}' is not registered")

        if rec.state != MODEL_STATE_APPROVED:
            self.approve_model(
                version_id=version_id,
                approver_id=approver_id,
                approval_method=approval_method,
                notes=notes,
            )

        # Retire current active model (if any and different)
        current_active = self.get_active_model()
        if current_active is not None and current_active.version_id != version_id:
            prev_state = current_active.state
            current_active.state = MODEL_STATE_RETIRED
            current_active.is_active = False
            current_active.retired_at = datetime.now(tz=timezone.utc).isoformat()
            self._log_audit(
                actor=approver_id,
                action="model_retired",
                target_id=current_active.version_id,
                old_value={"state": prev_state, "is_active": True},
                new_value={"state": MODEL_STATE_RETIRED, "is_active": False},
            )

        old_state = rec.state
        rec.state = MODEL_STATE_DEPLOYED
        rec.is_active = True
        rec.deployed_at = datetime.now(tz=timezone.utc).isoformat()
        if not self._deployment_history or self._deployment_history[-1] != version_id:
            self._deployment_history.append(version_id)

        self._save_manifest()
        self._sync_model_to_db(rec)
        self._log_audit(
            actor=approver_id,
            action="model_deployed",
            target_id=version_id,
            old_value={"state": old_state, "is_active": False},
            new_value={"state": MODEL_STATE_DEPLOYED, "is_active": True},
        )
        return rec

    def rollback_model(
        self,
        actor: str = "system",
        reason: str = "Manual or automated rollback to previous stable version",
    ) -> ModelRecord:
        """Roll back the active model to the immediately preceding deployed version."""
        current = self.get_active_model()
        if len(self._deployment_history) < 2:
            raise RuntimeError("No previous deployed model version available for rollback")

        current_ver = current.version_id if current else self._deployment_history[-1]
        # Find the latest version in history different from current_ver
        previous_ver: Optional[str] = None
        for ver in reversed(self._deployment_history[:-1]):
            if ver != current_ver and ver in self._models:
                previous_ver = ver
                break

        if previous_ver is None:
            raise RuntimeError("No valid previous model record found for rollback")

        if current is not None:
            current.state = MODEL_STATE_RETIRED
            current.is_active = False
            current.retired_at = datetime.now(tz=timezone.utc).isoformat()

        target = self._models[previous_ver]
        prev_state = target.state
        target.state = MODEL_STATE_DEPLOYED
        target.is_active = True
        target.deployed_at = datetime.now(tz=timezone.utc).isoformat()
        self._deployment_history.append(previous_ver)

        self._save_manifest()
        self._log_audit(
            actor=actor,
            action="model_rollback",
            target_id=previous_ver,
            old_value={"active_version": current_ver, "target_prev_state": prev_state},
            new_value={"active_version": previous_ver, "state": MODEL_STATE_DEPLOYED, "reason": reason},
        )
        return target

    # ------------------------------------------------------------------
    # Querying, Loading, and Comparison
    # ------------------------------------------------------------------

    def get_active_model(self) -> Optional[ModelRecord]:
        """Return the currently deployed/active ``ModelRecord``, or None if none deployed."""
        for rec in self._models.values():
            if rec.is_active and rec.state == MODEL_STATE_DEPLOYED:
                return rec
        return None

    def list_models(self) -> List[ModelRecord]:
        """Return all registered model records."""
        return list(self._models.values())

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        """Return in-memory audit trail of all lifecycle transitions."""
        return list(self._audit_events)

    def _load_version_files(self, version_id: str) -> LoadedModelBundle:
        rec = self._models.get(version_id)
        rf_path = Path(
            (rec.artifact_paths.get("rf_classifier") if rec else None)
            or (self.model_dir / f"rf_classifier_v{version_id}.pkl")
        )
        if not rf_path.exists():
            raise FileNotFoundError(f"RF artifact not found for version {version_id}: {rf_path}")

        with open(rf_path, "rb") as f:
            rf_bundle = pickle.load(f)

        def _maybe_load(key: str, default_name: str) -> Any:
            p = Path((rec.artifact_paths.get(key) if rec else None) or (self.model_dir / default_name))
            if p.exists():
                with open(p, "rb") as fh:
                    return pickle.load(fh)
            return None

        return LoadedModelBundle(
            version_id=version_id,
            rf_bundle=rf_bundle,
            isolation_forest_bundle=_maybe_load("isolation_forest", f"isolation_forest_v{version_id}.pkl"),
            scaler_bundle=_maybe_load("feature_scaler", f"feature_scaler_v{version_id}.pkl"),
            shap_bundle=_maybe_load("shap_explainer", f"shap_explainer_v{version_id}.pkl"),
            fallback_used=False,
            requested_version=version_id,
        )

    def load_model(self, version: Optional[str] = None) -> LoadedModelBundle:
        """
        Load model artifacts for ``version`` (or currently active version if omitted).
        If loading the requested version fails, automatically falls back to the previous
        deployed version and logs the fallback to ``audit_log``.
        """
        target_ver = str(version) if version is not None else None
        if target_ver is None:
            active = self.get_active_model()
            if active is not None:
                target_ver = active.version_id
            else:
                target_ver = "1"

        try:
            return self._load_version_files(target_ver)
        except Exception as primary_exc:
            logger.error("Failed to load model v%s: %s; attempting fallback", target_ver, primary_exc)
            # Search deployment history in reverse for a loadable previous version
            candidates = [v for v in reversed(self._deployment_history) if v != target_ver]
            for fallback_ver in candidates:
                try:
                    bundle = self._load_version_files(fallback_ver)
                    bundle.fallback_used = True
                    bundle.requested_version = target_ver
                    self._log_audit(
                        actor="model_registry",
                        action="model_load_fallback",
                        target_id=fallback_ver,
                        old_value={"requested_version": target_ver},
                        new_value={"loaded_version": fallback_ver},
                        outcome="partial",
                        failure_reason=str(primary_exc),
                    )
                    return bundle
                except Exception:
                    continue
            raise RuntimeError(
                f"Failed to load model v{target_ver} and no fallback version succeeded: {primary_exc}"
            ) from primary_exc

    def compare_models(
        self,
        candidate_version: str,
        deployed_version: Optional[str] = None,
        X_holdout: Optional[np.ndarray] = None,
        y_holdout: Optional[np.ndarray] = None,
    ) -> Dict[str, Any]:
        """
        Compare a candidate model against the currently deployed model using either a
        provided holdout test set (``X_holdout``, ``y_holdout``) or their recorded evaluation reports.
        """
        candidate_version = str(candidate_version)
        cand_rec = self._models.get(candidate_version)
        if cand_rec is None:
            raise KeyError(f"Candidate model v{candidate_version} not registered")

        if deployed_version is None:
            active = self.get_active_model()
            deployed_version = active.version_id if active else None

        dep_rec = self._models.get(str(deployed_version)) if deployed_version else None

        if X_holdout is not None and y_holdout is not None and f1_score is not None:
            cand_bundle = self._load_version_files(candidate_version)
            cand_clf = cand_bundle.rf_bundle["model"] if isinstance(cand_bundle.rf_bundle, dict) else cand_bundle.rf_bundle
            cand_pred = cand_clf.predict(X_holdout)
            cand_macro = float(f1_score(y_holdout, cand_pred, average="macro", zero_division=0))
            cand_weighted = float(f1_score(y_holdout, cand_pred, average="weighted", zero_division=0))
            benign_mask = np.asarray(y_holdout) == "BENIGN"
            cand_fpr = float(np.mean(cand_pred[benign_mask] != "BENIGN")) if np.any(benign_mask) else 0.0

            if dep_rec is not None:
                dep_bundle = self._load_version_files(dep_rec.version_id)
                dep_clf = dep_bundle.rf_bundle["model"] if isinstance(dep_bundle.rf_bundle, dict) else dep_bundle.rf_bundle
                dep_pred = dep_clf.predict(X_holdout)
                dep_macro = float(f1_score(y_holdout, dep_pred, average="macro", zero_division=0))
                dep_weighted = float(f1_score(y_holdout, dep_pred, average="weighted", zero_division=0))
                dep_fpr = float(np.mean(dep_pred[benign_mask] != "BENIGN")) if np.any(benign_mask) else 0.0
            else:
                dep_macro, dep_weighted, dep_fpr = 0.0, 0.0, 1.0
            eval_source = "holdout_dataset"
        else:
            cand_macro, cand_weighted, cand_fpr = self._extract_rf_metrics(cand_rec.metrics)
            if dep_rec is not None:
                dep_macro, dep_weighted, dep_fpr = self._extract_rf_metrics(dep_rec.metrics)
            else:
                dep_macro, dep_weighted, dep_fpr = 0.0, 0.0, 1.0
            eval_source = "evaluation_reports"

        thresholds_ok, failed_reasons = self.check_metric_thresholds(candidate_version)
        delta_macro = round(cand_macro - dep_macro, 4)
        delta_weighted = round(cand_weighted - dep_weighted, 4)
        delta_fpr = round(cand_fpr - dep_fpr, 6)

        recommend = thresholds_ok and (
            dep_rec is None or (cand_macro >= dep_macro and cand_fpr <= self.max_fpr)
        )

        return {
            "evaluation_source": eval_source,
            "candidate_version": candidate_version,
            "deployed_version": dep_rec.version_id if dep_rec else None,
            "candidate_metrics": {
                "macro_f1": round(cand_macro, 4),
                "weighted_f1": round(cand_weighted, 4),
                "false_positive_rate": round(cand_fpr, 6),
            },
            "deployed_metrics": {
                "macro_f1": round(dep_macro, 4),
                "weighted_f1": round(dep_weighted, 4),
                "false_positive_rate": round(dep_fpr, 6),
            }
            if dep_rec
            else None,
            "delta": {
                "macro_f1": delta_macro,
                "weighted_f1": delta_weighted,
                "false_positive_rate": delta_fpr,
            },
            "thresholds_passed": thresholds_ok,
            "failed_reasons": failed_reasons,
            "recommend_promotion": recommend,
        }
