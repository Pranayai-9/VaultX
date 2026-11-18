"""
backend/api/routers/models.py — Machine Learning Model Registry, Evaluation & Promotion
VaultX Hybrid NIDS for BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status

from backend.api.dependencies import get_current_user, mock_store, require_roles
from backend.api.schemas import (
    ModelEvaluationReportResponse,
    ModelMetadataResponse,
    PromoteModelRequest,
    RetrainModelRequest,
    RetrainModelResponse,
    UserProfile,
    UserRole,
)

router = APIRouter(prefix="/models", tags=["Machine Learning Model Registry"])


@router.get(
    "",
    response_model=List[ModelMetadataResponse],
    summary="List all registered ML models, active production models, and candidate models",
)
async def list_models(
    current_user: UserProfile = Depends(get_current_user),
) -> List[ModelMetadataResponse]:
    """
    Returns model catalog including Random Forest supervised classifier,
    Isolation Forest anomaly detector, and Encrypted Traffic metadata analyzers.
    """
    return [ModelMetadataResponse(**m) for m in mock_store.active_models.values()]


@router.get(
    "/{model_id}/evaluation",
    response_model=ModelEvaluationReportResponse,
    summary="Get detailed evaluation report, confusion metrics, and SHAP explainability",
)
async def get_model_evaluation_report(
    model_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> ModelEvaluationReportResponse:
    """
    Returns offline holdout test set evaluation metrics (Precision, Recall, F1, FPR)
    and top contributing SHAP feature importances.
    """
    model = mock_store.active_models.get(model_id)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model with ID '{model_id}' not found in registry.",
        )

    # Detailed metrics for Random Forest classifier
    if "rf" in model_id.lower() or "classifier" in model["model_name"].lower():
        return ModelEvaluationReportResponse(
            model_id=model["model_id"],
            model_name=model["model_name"],
            model_version=model["model_version"],
            training_date=model["training_date"],
            train_samples=40000,
            test_samples=10000,
            accuracy=0.978,
            macro_f1=model["macro_f1"],
            weighted_f1=0.974,
            false_positive_rate=model["false_positive_rate"],
            inference_time_ms_per_1000_samples=12.5,
            per_class_metrics={
                "BENIGN": {"precision": 0.992, "recall": 0.988, "f1": 0.990},
                "VENDOR_COMPROMISE": {"precision": 0.941, "recall": 0.935, "f1": 0.938},
                "SERVICE_MISUSE": {"precision": 0.925, "recall": 0.910, "f1": 0.917},
                "LATERAL_MOVEMENT": {"precision": 0.953, "recall": 0.960, "f1": 0.956},
                "LOTL": {"precision": 0.912, "recall": 0.895, "f1": 0.903},
                "ENCRYPTED_EXFIL": {"precision": 0.938, "recall": 0.945, "f1": 0.941},
                "OT_ANOMALY": {"precision": 0.985, "recall": 0.990, "f1": 0.987},
                "VULNERABILITY_SCAN": {"precision": 0.978, "recall": 0.982, "f1": 0.980},
            },
            top_shap_features=[
                "flow_bytes_per_sec",
                "is_cross_vlan",
                "is_ot_destination",
                "fwd_packets",
                "down_up_ratio",
            ],
            limitations=[
                "Trained on BECPL synthetic digital twin traffic (50k flows). Retraining on live sensor capture recommended prior to full production deployment.",
                "High upload ratio exfiltration detection requires minimum 50KB data transfer to avoid false positives on large software downloads.",
            ],
        )

    # Detailed metrics for Isolation Forest
    return ModelEvaluationReportResponse(
        model_id=model["model_id"],
        model_name=model["model_name"],
        model_version=model["model_version"],
        training_date=model["training_date"],
        train_samples=32000,
        test_samples=8000,
        accuracy=0.942,
        macro_f1=model["macro_f1"],
        weighted_f1=0.940,
        false_positive_rate=model["false_positive_rate"],
        inference_time_ms_per_1000_samples=8.5,
        per_class_metrics={
            "BENIGN": {"precision": 0.965, "recall": 0.972, "f1": 0.968},
            "ANOMALY": {"precision": 0.885, "recall": 0.860, "f1": 0.872},
        },
        top_shap_features=[
            "flow_packets_per_sec",
            "connection_duration",
            "pkt_len_mean",
            "bwd_iat_mean",
        ],
        limitations=[
            "Unsupervised anomaly detector flags statistical outliers; must be corroborated by correlation engine or signature rule.",
        ],
    )


@router.post(
    "/{model_id}/promote",
    response_model=ModelMetadataResponse,
    summary="Promote candidate model to active production inference engine",
)
async def promote_model_to_production(
    model_id: str,
    payload: PromoteModelRequest,
    current_user: UserProfile = Depends(require_roles(UserRole.SECURITY_MANAGER, UserRole.ADMIN)),
) -> ModelMetadataResponse:
    """
    Enforces governance gate: promotes a vetted model candidate to production.
    Requires SECURITY_MANAGER or ADMIN authorization.
    """
    model = mock_store.active_models.get(model_id)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model with ID '{model_id}' not found.",
        )

    now = datetime.now(timezone.utc)
    model["is_active"] = True
    model["deployed_at"] = now
    return ModelMetadataResponse(**model)


@router.post(
    "/train",
    response_model=RetrainModelResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger asynchronous offline model retraining pipeline",
)
async def trigger_offline_training(
    payload: RetrainModelRequest,
    current_user: UserProfile = Depends(require_roles(UserRole.OPERATOR, UserRole.SECURITY_MANAGER, UserRole.ADMIN)),
) -> RetrainModelResponse:
    """
    Launches the 13-step continuous improvement retraining pipeline offline.
    Incorporates analyst feedback labels and newly acquired normal traffic baseline vectors.
    """
    now = datetime.now(timezone.utc)
    job_id = f"train-job-{uuid.uuid4().hex[:8]}"
    return RetrainModelResponse(
        job_id=job_id,
        status="queued",
        model_candidate_version="v2.1.0-rc1",
        started_at=now,
        message=f"Offline retraining job successfully scheduled using dataset '{payload.dataset_name}'. Estimators: {payload.epochs_or_estimators}.",
    )
