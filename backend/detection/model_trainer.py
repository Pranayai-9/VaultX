"""
model_trainer.py — Offline ML Model Training Pipeline for VaultX.

BECPL (Bharat Electronics Components Pvt. Ltd.), Pune — Manufacturing-Aware Hybrid NIDS.

IMPORTANT
---------
This module is an **OFFLINE** training pipeline. It is executed manually via CLI
or orchestrated by ``train_models.sh`` / the Model Registry service — NEVER called
synchronously on the live event stream.

Pipeline steps
--------------
1. Load training data from ``datasets/processed/becpl_synthetic_traffic_50k.csv``
   plus optional additional validated datasets (e.g. CIC-IDS2017 CSVs in ``datasets/raw/``).
2. Handle missing/infinite values (median imputation for numeric, mode for categorical).
3. Encode categorical features (``protocol`` -> int, ``identity_classification`` -> int).
4. Stratified train/test split (80/20) stratified by ``label``.
5. Apply SMOTE class-imbalance resampling on the **training set only** (never test set).
6. Feature scaling: ``StandardScaler`` fitted on BENIGN training traffic for Isolation Forest;
   optional ``MinMaxScaler`` for Random Forest.
7. Train Random Forest (``n_estimators=200, max_depth=15, class_weight='balanced', random_state=42``).
8. Train Isolation Forest (``contamination=0.1, n_estimators=200``) on **BENIGN samples only**.
9. Evaluate both models (per-class precision/recall/F1/FPR, macro/weighted F1, confusion matrix,
   1000-sample inference latency, IF attack detection rate and benign FPR).
10. Save versioned artefacts to ``backend/models/``:
    - ``rf_classifier_v{version}.pkl``
    - ``isolation_forest_v{version}.pkl``
    - ``feature_scaler_v{version}.pkl``
    - ``shap_explainer_v{version}.pkl``
    - ``evaluation_report_v{version}.json``
11. Register the candidate model in PostgreSQL ``becpl_nids.ml_models`` (when DB available).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pickle
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.metrics import (
        confusion_matrix,
        f1_score,
        precision_recall_fscore_support,
    )
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import MinMaxScaler, StandardScaler

    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover
    SKLEARN_AVAILABLE = False

try:
    from imblearn.over_sampling import SMOTE

    IMBLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover
    IMBLEARN_AVAILABLE = False

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
        ANOMALY_CONTAMINATION,
        CATEGORICAL_FEATURE_COLUMNS,
        DEFAULT_DATASET_PATH,
        FEATURE_COLUMNS,
        IDENTITY_ENCODING,
        ML_CONFIDENCE_THRESHOLD,
        MODEL_DIR,
        NUMERIC_FEATURE_COLUMNS,
        PROTOCOL_ENCODING,
    )
except ImportError:
    from detection_config import (  # type: ignore[no-redef]
        ALL_LABELS,
        ANOMALY_CONTAMINATION,
        CATEGORICAL_FEATURE_COLUMNS,
        DEFAULT_DATASET_PATH,
        FEATURE_COLUMNS,
        IDENTITY_ENCODING,
        ML_CONFIDENCE_THRESHOLD,
        MODEL_DIR,
        NUMERIC_FEATURE_COLUMNS,
        PROTOCOL_ENCODING,
    )

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CIC-IDS2017 Harmonization Helpers
# ---------------------------------------------------------------------------

CIC_IDS2017_COLUMN_MAP: Dict[str, str] = {
    "Flow ID": "flow_id",
    "Timestamp": "timestamp",
    "Source IP": "source_ip",
    "Destination IP": "destination_ip",
    "Source Port": "source_port",
    "Destination Port": "destination_port",
    "Protocol": "protocol",
    "Flow Duration": "connection_duration",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Backward Packets": "total_bwd_packets",
    "Total Length of Fwd Packets": "total_fwd_bytes",
    "Total Length of Bwd Packets": "total_bwd_bytes",
    "Flow Bytes/s": "flow_bytes_per_sec",
    "Flow Packets/s": "flow_packets_per_sec",
    "Label": "label",
}

CIC_PROTO_NUM_MAP: Dict[str, str] = {
    "6": "TCP",
    "17": "UDP",
    "1": "ICMP",
    "6.0": "TCP",
    "17.0": "UDP",
    "1.0": "ICMP",
}

CIC_LABEL_MAP: Dict[str, str] = {
    "BENIGN": "BENIGN",
    "PORTSCAN": "VULNERABILITY_SCAN",
    "DOS HULK": "SERVICE_MISUSE",
    "DOS GOLDENEYE": "SERVICE_MISUSE",
    "DOS SLOWLORIS": "SERVICE_MISUSE",
    "DOS SLOWHTTPTEST": "SERVICE_MISUSE",
    "DDOS": "SERVICE_MISUSE",
    "FTP-PATATOR": "VENDOR_COMPROMISE",
    "SSH-PATATOR": "VENDOR_COMPROMISE",
    "BOT": "ENCRYPTED_EXFIL",
    "INFILTRATION": "LATERAL_MOVEMENT",
    "WEB ATTACK - BRUTE FORCE": "VENDOR_COMPROMISE",
    "WEB ATTACK - XSS": "SERVICE_MISUSE",
    "WEB ATTACK - SQL INJECTION": "SERVICE_MISUSE",
    "HEARTBLEED": "ENCRYPTED_EXFIL",
}


def harmonize_cic_ids2017(df: pd.DataFrame) -> pd.DataFrame:
    """
    Harmonize a CIC-IDS2017 CSV DataFrame into the BECPL standard schema
    per ``datasets/metadata/feature_harmonisation.json``.
    """
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    df = df.rename(columns={k: v for k, v in CIC_IDS2017_COLUMN_MAP.items() if k in df.columns})

    # Convert CIC microseconds duration to seconds if values look like microseconds
    if "connection_duration" in df.columns:
        dur = pd.to_numeric(df["connection_duration"], errors="coerce")
        if dur.median() > 10000:
            df["connection_duration"] = dur / 1_000_000.0
        else:
            df["connection_duration"] = dur

    # Derived totals
    if "packets_transferred" not in df.columns:
        fwd_p = pd.to_numeric(df.get("total_fwd_packets", 0), errors="coerce").fillna(0)
        bwd_p = pd.to_numeric(df.get("total_bwd_packets", 0), errors="coerce").fillna(0)
        df["packets_transferred"] = fwd_p + bwd_p
    if "bytes_transferred" not in df.columns:
        fwd_b = pd.to_numeric(df.get("total_fwd_bytes", 0), errors="coerce").fillna(0)
        bwd_b = pd.to_numeric(df.get("total_bwd_bytes", 0), errors="coerce").fillna(0)
        df["bytes_transferred"] = fwd_b + bwd_b

    # Protocol numeric code -> string
    if "protocol" in df.columns:
        df["protocol"] = (
            df["protocol"]
            .astype(str)
            .str.strip()
            .str.upper()
            .replace(CIC_PROTO_NUM_MAP)
        )
    else:
        df["protocol"] = "TCP"

    # Defaults for BECPL-specific context columns
    if "source_vlan" not in df.columns:
        df["source_vlan"] = 50  # DMZ / External benchmark default
    if "destination_vlan" not in df.columns:
        df["destination_vlan"] = 10  # Corporate IT default
    if "identity_classification" not in df.columns:
        df["identity_classification"] = "UNKNOWN_IDENTITY"

    # Normalize label names
    if "label" in df.columns:
        df["label"] = (
            df["label"]
            .astype(str)
            .str.strip()
            .str.upper()
            .map(lambda lbl: CIC_LABEL_MAP.get(lbl, lbl if lbl in ALL_LABELS else "SERVICE_MISUSE"))
        )
        df["binary_label"] = (df["label"] != "BENIGN").astype(int)

    return df


# ---------------------------------------------------------------------------
# Preprocessing Pipeline
# ---------------------------------------------------------------------------


def load_datasets(
    primary_path: str | Path,
    extra_paths: Optional[List[str | Path]] = None,
) -> pd.DataFrame:
    """Load primary BECPL CSV and optional CIC-IDS2017 CSVs into one DataFrame."""
    primary_path = Path(primary_path)
    if not primary_path.exists():
        raise FileNotFoundError(f"Primary dataset not found: {primary_path}")

    frames: List[pd.DataFrame] = [pd.read_csv(primary_path)]
    logger.info("Loaded primary dataset %s (%d rows)", primary_path.name, len(frames[0]))

    for extra in extra_paths or []:
        ep = Path(extra)
        if not ep.exists():
            logger.warning("Skipping missing extra dataset: %s", ep)
            continue
        raw_df = pd.read_csv(ep)
        # Detect CIC-IDS2017 headers
        stripped_cols = {str(c).strip() for c in raw_df.columns}
        if "Flow Duration" in stripped_cols or "Destination Port" in stripped_cols:
            raw_df = harmonize_cic_ids2017(raw_df)
        frames.append(raw_df)
        logger.info("Loaded extra dataset %s (%d rows)", ep.name, len(raw_df))

    combined = pd.concat(frames, ignore_index=True)
    return combined


def preprocess_dataframe(
    df: pd.DataFrame,
    numeric_cols: List[str] = NUMERIC_FEATURE_COLUMNS,
    categorical_cols: List[str] = CATEGORICAL_FEATURE_COLUMNS,
) -> Tuple[pd.DataFrame, pd.Series, Dict[str, Any]]:
    """
    Preprocess raw BECPL traffic DataFrame:
    1. Ensure all feature columns exist.
    2. Replace inf/-inf with NaN.
    3. Median imputation for numeric columns; mode imputation for categorical columns.
    4. Encode ``protocol`` and ``identity_classification`` to deterministic integers.

    Returns ``(X, y, preprocessing_metadata)``.
    """
    work = df.copy()

    if "label" not in work.columns:
        raise ValueError("Dataset must contain a 'label' column")

    # Clean labels
    work["label"] = work["label"].astype(str).str.strip().str.upper()

    # Ensure required numeric columns exist
    numeric_medians: Dict[str, float] = {}
    for col in numeric_cols:
        if col not in work.columns:
            work[col] = np.nan
        work[col] = pd.to_numeric(work[col], errors="coerce")
        work[col] = work[col].replace([np.inf, -np.inf], np.nan)
        med = float(work[col].median()) if work[col].notna().any() else 0.0
        numeric_medians[col] = med
        work[col] = work[col].fillna(med)

    # Categorical imputation (mode) + encoding
    categorical_modes: Dict[str, str] = {}
    protocol_map = dict(PROTOCOL_ENCODING)
    identity_map = dict(IDENTITY_ENCODING)

    for col in categorical_cols:
        if col not in work.columns:
            work[col] = np.nan
        series = work[col].astype("object")
        mode_vals = series.dropna().mode()
        mode_val = str(mode_vals.iloc[0]) if len(mode_vals) > 0 else ("TCP" if col == "protocol" else "UNKNOWN_IDENTITY")
        categorical_modes[col] = mode_val
        cleaned = series.fillna(mode_val).astype(str).str.strip().str.upper()

        if col == "protocol":
            next_idx = max(protocol_map.values(), default=-1) + 1
            for val in cleaned.unique():
                if val not in protocol_map:
                    protocol_map[val] = next_idx
                    next_idx += 1
            work[col] = cleaned.map(protocol_map).astype(int)
        elif col == "identity_classification":
            next_idx = max(identity_map.values(), default=-1) + 1
            for val in cleaned.unique():
                if val not in identity_map:
                    identity_map[val] = next_idx
                    next_idx += 1
            work[col] = cleaned.map(identity_map).astype(int)

    feature_cols = list(numeric_cols) + list(categorical_cols)
    X = work[feature_cols].astype(float)
    y = work["label"].astype(str)

    metadata = {
        "feature_columns": feature_cols,
        "numeric_columns": list(numeric_cols),
        "categorical_columns": list(categorical_cols),
        "numeric_medians": numeric_medians,
        "categorical_modes": categorical_modes,
        "protocol_encoding": protocol_map,
        "identity_encoding": identity_map,
    }
    return X, y, metadata


# ---------------------------------------------------------------------------
# Trainer Class
# ---------------------------------------------------------------------------


class ModelTrainer:
    """
    Offline training pipeline producing versioned Random Forest, Isolation Forest,
    Feature Scaler, SHAP TreeExplainer, and JSON evaluation report.
    """

    def __init__(
        self,
        model_dir: str | Path = MODEL_DIR,
        db_session_factory: Optional[Callable[[], Any]] = None,
        scale_rf: bool = False,
        use_smote: bool = True,
        random_state: int = 42,
    ) -> None:
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self._db_factory = db_session_factory
        self.scale_rf = scale_rf
        self.use_smote = use_smote
        self.random_state = random_state

    def train(
        self,
        dataset_path: str | Path = DEFAULT_DATASET_PATH,
        version: str = "1",
        extra_datasets: Optional[List[str | Path]] = None,
        register_in_db: bool = True,
    ) -> Dict[str, Any]:
        """Execute full offline training, evaluation, and artifact persistence."""
        if not SKLEARN_AVAILABLE:
            raise RuntimeError(
                "scikit-learn is required for training. "
                "Install with: pip install scikit-learn imbalanced-learn shap pandas numpy"
            )

        dataset_path = Path(dataset_path)
        logger.info("Starting offline training run v%s on %s", version, dataset_path)

        # 1. Load & preprocess
        df = load_datasets(dataset_path, extra_paths=extra_datasets)
        X, y, prep_meta = preprocess_dataframe(df)
        feature_cols = prep_meta["feature_columns"]

        # 2. Stratified 80/20 train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=0.20,
            stratify=y,
            random_state=self.random_state,
        )
        raw_train_count = int(len(X_train))
        test_count = int(len(X_test))
        logger.info("Stratified split: train=%d, test=%d", raw_train_count, test_count)

        # 3. Feature scaling
        # StandardScaler fitted on BENIGN training samples for Isolation Forest baseline
        benign_train_mask = y_train == "BENIGN"
        X_train_benign = X_train.loc[benign_train_mask]
        if len(X_train_benign) == 0:
            raise ValueError("Training set contains no BENIGN samples for Isolation Forest baseline")

        if_scaler = StandardScaler()
        X_train_benign_scaled = if_scaler.fit_transform(X_train_benign.values)
        X_test_if_scaled = if_scaler.transform(X_test.values)

        rf_scaler: Optional[MinMaxScaler] = None
        X_train_rf_vals = X_train.values
        X_test_rf_vals = X_test.values
        if self.scale_rf:
            rf_scaler = MinMaxScaler()
            X_train_rf_vals = rf_scaler.fit_transform(X_train_rf_vals)
            X_test_rf_vals = rf_scaler.transform(X_test_rf_vals)

        # 4. SMOTE on training set ONLY (never on test set)
        smote_applied = False
        X_train_resampled = X_train_rf_vals
        y_train_resampled = y_train.values
        if self.use_smote and IMBLEARN_AVAILABLE:
            min_class_count = int(pd.Series(y_train).value_counts().min())
            if min_class_count >= 2:
                k_neighbors = min(5, min_class_count - 1)
                smote = SMOTE(random_state=self.random_state, k_neighbors=k_neighbors)
                X_train_resampled, y_train_resampled = smote.fit_resample(
                    X_train_rf_vals, y_train.values
                )
                smote_applied = True
                logger.info(
                    "SMOTE applied on training set: %d -> %d samples",
                    raw_train_count,
                    len(X_train_resampled),
                )
            else:
                logger.warning("Skipping SMOTE: smallest class has < 2 samples")
        elif self.use_smote:
            logger.warning("imbalanced-learn not installed; training RF without SMOTE")

        # 5. Train Random Forest Classifier
        rf_params = {
            "n_estimators": 200,
            "max_depth": 15,
            "class_weight": "balanced",
            "random_state": self.random_state,
            "n_jobs": -1,
        }
        rf_clf = RandomForestClassifier(**rf_params)
        rf_clf.fit(X_train_resampled, y_train_resampled)
        logger.info("Random Forest trained (%d classes)", len(rf_clf.classes_))

        # 6. Train Isolation Forest on BENIGN training samples ONLY
        if_params = {
            "contamination": ANOMALY_CONTAMINATION,
            "n_estimators": 200,
            "random_state": self.random_state,
            "n_jobs": -1,
        }
        iso_forest = IsolationForest(**if_params)
        iso_forest.fit(X_train_benign_scaled)
        logger.info(
            "Isolation Forest trained on %d BENIGN samples (contamination=%.2f)",
            len(X_train_benign_scaled),
            ANOMALY_CONTAMINATION,
        )

        # 7. Evaluate Random Forest on untouched holdout test set
        rf_eval = self._evaluate_rf(rf_clf, X_test_rf_vals, y_test.values)

        # 8. Evaluate Isolation Forest on holdout test set
        if_eval = self._evaluate_isolation_forest(iso_forest, X_test_if_scaled, y_test.values)

        # 9. Build SHAP TreeExplainer
        shap_explainer = None
        if SHAP_AVAILABLE:
            try:
                shap_explainer = shap.TreeExplainer(rf_clf)
                logger.info("SHAP TreeExplainer initialized")
            except Exception as exc:
                logger.warning("Failed to initialize SHAP TreeExplainer: %s", exc)

        # 10. Save versioned artifacts
        rf_path = self.model_dir / f"rf_classifier_v{version}.pkl"
        if_path = self.model_dir / f"isolation_forest_v{version}.pkl"
        scaler_path = self.model_dir / f"feature_scaler_v{version}.pkl"
        shap_path = self.model_dir / f"shap_explainer_v{version}.pkl"
        report_path = self.model_dir / f"evaluation_report_v{version}.json"

        rf_bundle = {
            "model": rf_clf,
            "version": str(version),
            "feature_columns": feature_cols,
            "classes": [str(c) for c in rf_clf.classes_],
            "preprocessing": prep_meta,
            "rf_scaler": rf_scaler,
            "confidence_threshold": ML_CONFIDENCE_THRESHOLD,
            "trained_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        with open(rf_path, "wb") as f:
            pickle.dump(rf_bundle, f, protocol=pickle.HIGHEST_PROTOCOL)

        if_bundle = {
            "model": iso_forest,
            "version": str(version),
            "feature_columns": feature_cols,
            "contamination": ANOMALY_CONTAMINATION,
            "preprocessing": prep_meta,
            "trained_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        with open(if_path, "wb") as f:
            pickle.dump(if_bundle, f, protocol=pickle.HIGHEST_PROTOCOL)

        scaler_bundle = {
            "standard_scaler": if_scaler,
            "rf_scaler": rf_scaler,
            "feature_columns": feature_cols,
            "baseline_mean": dict(zip(feature_cols, [float(m) for m in if_scaler.mean_])),
            "baseline_std": dict(zip(feature_cols, [float(s) for s in if_scaler.scale_])),
            "version": str(version),
        }
        with open(scaler_path, "wb") as f:
            pickle.dump(scaler_bundle, f, protocol=pickle.HIGHEST_PROTOCOL)

        if shap_explainer is not None:
            with open(shap_path, "wb") as f:
                pickle.dump(
                    {
                        "explainer": shap_explainer,
                        "feature_columns": feature_cols,
                        "classes": [str(c) for c in rf_clf.classes_],
                        "version": str(version),
                    },
                    f,
                    protocol=pickle.HIGHEST_PROTOCOL,
                )

        # 11. Build and save evaluation report JSON
        report: Dict[str, Any] = {
            "model_version": str(version),
            "training_date": date.today().isoformat(),
            "training_dataset": dataset_path.name,
            "additional_datasets": [Path(p).name for p in (extra_datasets or [])],
            "train_samples": raw_train_count,
            "train_samples_after_smote": int(len(X_train_resampled)),
            "smote_applied": smote_applied,
            "test_samples": test_count,
            "feature_columns": feature_cols,
            "rf_classifier": rf_eval,
            "isolation_forest": if_eval,
            "artifacts": {
                "rf_classifier": rf_path.name,
                "isolation_forest": if_path.name,
                "feature_scaler": scaler_path.name,
                "shap_explainer": shap_path.name if shap_explainer is not None else None,
            },
            "limitations": [
                "Dataset represents simulated BECPL traffic, not real-world production data",
                "Model should be retrained with real sensor data before production deployment",
            ],
        }
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        logger.info("Saved evaluation report to %s", report_path)

        # 12. Update PostgreSQL ml_models registry if DB session factory available
        if register_in_db and self._db_factory is not None:
            self._register_in_db(version, dataset_path.name, feature_cols, rf_params, if_params, report)

        return report

    def _evaluate_rf(
        self,
        rf_clf: Any,
        X_test: np.ndarray,
        y_test: np.ndarray,
    ) -> Dict[str, Any]:
        classes = [str(c) for c in rf_clf.classes_]
        y_pred = rf_clf.predict(X_test)

        # Measure inference latency for 1000 samples
        n_bench = min(1000, len(X_test))
        X_bench = X_test[:n_bench]
        t0 = time.perf_counter()
        _ = rf_clf.predict_proba(X_bench)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latency_per_1000_ms = round(elapsed_ms * (1000.0 / max(n_bench, 1)), 3)

        prec, rec, f1, supp = precision_recall_fscore_support(
            y_test, y_pred, labels=classes, zero_division=0
        )
        cm = confusion_matrix(y_test, y_pred, labels=classes)

        per_class_metrics: Dict[str, Dict[str, Any]] = {}
        total_samples = int(cm.sum())
        for idx, cls_name in enumerate(classes):
            tp = int(cm[idx, idx])
            fp = int(cm[:, idx].sum() - tp)
            fn = int(cm[idx, :].sum() - tp)
            tn = int(total_samples - tp - fp - fn)
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            per_class_metrics[cls_name] = {
                "precision": round(float(prec[idx]), 4),
                "recall": round(float(rec[idx]), 4),
                "f1": round(float(f1[idx]), 4),
                "false_positive_rate": round(fpr, 6),
                "support": int(supp[idx]),
            }

        macro_f1 = round(float(f1_score(y_test, y_pred, average="macro", zero_division=0)), 4)
        weighted_f1 = round(float(f1_score(y_test, y_pred, average="weighted", zero_division=0)), 4)

        # Overall false positive rate: BENIGN samples incorrectly predicted as attack
        benign_mask = y_test == "BENIGN"
        if np.any(benign_mask):
            overall_fpr = round(float(np.mean(y_pred[benign_mask] != "BENIGN")), 6)
        else:
            overall_fpr = 0.0

        return {
            "per_class_metrics": per_class_metrics,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "false_positive_rate": overall_fpr,
            "confusion_matrix": {
                "labels": classes,
                "matrix": cm.tolist(),
            },
            "inference_time_ms_per_1000_samples": latency_per_1000_ms,
        }

    def _evaluate_isolation_forest(
        self,
        iso_forest: Any,
        X_test_scaled: np.ndarray,
        y_test: np.ndarray,
    ) -> Dict[str, Any]:
        # IsolationForest.predict returns -1 for anomaly, 1 for normal
        preds = iso_forest.predict(X_test_scaled)
        is_anomaly = preds == -1

        attack_mask = y_test != "BENIGN"
        benign_mask = y_test == "BENIGN"

        attack_det_rate = (
            round(float(np.mean(is_anomaly[attack_mask])), 4) if np.any(attack_mask) else 0.0
        )
        benign_fpr = (
            round(float(np.mean(is_anomaly[benign_mask])), 4) if np.any(benign_mask) else 0.0
        )

        return {
            "contamination": ANOMALY_CONTAMINATION,
            "anomaly_detection_rate_on_attacks": attack_det_rate,
            "false_positive_rate_on_benign": benign_fpr,
        }

    def _register_in_db(
        self,
        version: str,
        dataset_name: str,
        feature_cols: List[str],
        rf_params: Dict[str, Any],
        if_params: Dict[str, Any],
        report: Dict[str, Any],
    ) -> None:
        if sa is None or self._db_factory is None:
            return
        session = None
        try:
            session = self._db_factory()
            for model_name, model_type, hyperparams, metrics in [
                (
                    "vaultx_rf_classifier",
                    "classification",
                    rf_params,
                    report["rf_classifier"],
                ),
                (
                    "vaultx_isolation_forest",
                    "anomaly_detection",
                    if_params,
                    report["isolation_forest"],
                ),
            ]:
                session.execute(
                    sa.text(
                        """
                        INSERT INTO becpl_nids.ml_models (
                            model_name, model_version, model_type, training_dataset,
                            training_date, feature_set, hyperparameters,
                            performance_metrics, threshold_config, is_active, notes
                        ) VALUES (
                            :model_name, :model_version, :model_type, :training_dataset,
                            :training_date, :feature_set, CAST(:hyperparameters AS JSONB),
                            CAST(:performance_metrics AS JSONB), CAST(:threshold_config AS JSONB),
                            FALSE, :notes
                        )
                        """
                    ),
                    {
                        "model_name": model_name,
                        "model_version": str(version),
                        "model_type": model_type,
                        "training_dataset": dataset_name,
                        "training_date": date.today(),
                        "feature_set": feature_cols,
                        "hyperparameters": json.dumps(hyperparams),
                        "performance_metrics": json.dumps(metrics),
                        "threshold_config": json.dumps(
                            {
                                "ml_confidence_threshold": ML_CONFIDENCE_THRESHOLD,
                                "lifecycle_state": "candidate",
                            }
                        ),
                        "notes": "Trained offline by model_trainer.py; awaiting validation and human approval.",
                    },
                )
            session.commit()
            logger.info("Registered model version v%s in becpl_nids.ml_models", version)
        except Exception as exc:
            logger.error("Failed to update ml_models registry in PostgreSQL: %s", exc)
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


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VaultX Offline ML Model Trainer (Random Forest + Isolation Forest)"
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default=DEFAULT_DATASET_PATH,
        help="Path to primary BECPL synthetic/labelled traffic CSV.",
    )
    parser.add_argument(
        "--extra-datasets",
        type=str,
        nargs="*",
        default=[],
        help="Optional additional CSV datasets (e.g. CIC-IDS2017 format in datasets/raw/).",
    )
    parser.add_argument(
        "--version",
        type=str,
        default="1",
        help="Model version identifier (e.g. 1, 2, 1.1).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=MODEL_DIR,
        help="Output directory for serialized models and evaluation report.",
    )
    parser.add_argument(
        "--scale-rf",
        action="store_true",
        help="Apply MinMaxScaler to Random Forest features (optional).",
    )
    parser.add_argument(
        "--no-smote",
        action="store_true",
        help="Disable SMOTE resampling on the training split.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    args = _build_arg_parser().parse_args(argv)
    trainer = ModelTrainer(
        model_dir=args.output_dir,
        scale_rf=args.scale_rf,
        use_smote=not args.no_smote,
    )
    report = trainer.train(
        dataset_path=args.dataset,
        version=args.version,
        extra_datasets=args.extra_datasets,
        register_in_db=False,
    )
    rf = report["rf_classifier"]
    iso = report["isolation_forest"]
    print(
        json.dumps(
            {
                "status": "completed",
                "model_version": report["model_version"],
                "train_samples": report["train_samples"],
                "test_samples": report["test_samples"],
                "rf_macro_f1": rf["macro_f1"],
                "rf_weighted_f1": rf["weighted_f1"],
                "rf_false_positive_rate": rf["false_positive_rate"],
                "rf_inference_ms_per_1000": rf["inference_time_ms_per_1000_samples"],
                "if_attack_detection_rate": iso["anomaly_detection_rate_on_attacks"],
                "if_benign_fpr": iso["false_positive_rate_on_benign"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
