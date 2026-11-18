"""
VaultX Detection Engine Package
BECPL (Bharat Electronics Components Pvt. Ltd.), Pune — Manufacturing-Aware Hybrid NIDS.

Modules:
- detection_config: Centralized configuration constants and thresholds.
- signature_engine: Suricata EVE JSON signature alert consumer and enricher.
- ml_classifier: Supervised Random Forest classifier with confidence calibration & SHAP.
- anomaly_detector: Unsupervised Isolation Forest baseline deviation scorer.
- encrypted_traffic_analyzer: Metadata-only TLS/HTTPS/QUIC intelligence and C2 beacon detector.
- model_trainer: Offline training, SMOTE balancing, evaluation, and artifact generation pipeline.
- model_registry: Controlled model lifecycle (candidate -> validated -> approved -> deployed -> retired).
- feature_store: PostgreSQL feature vector persistence, schema versioning, and quality gating.
"""

from __future__ import annotations

__all__ = [
    "detection_config",
    "signature_engine",
    "ml_classifier",
    "anomaly_detector",
    "encrypted_traffic_analyzer",
    "model_trainer",
    "model_registry",
    "feature_store",
]
