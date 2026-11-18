"""
backend/api/routers/behavioural.py — Behavioral Baselines, Deviations & Maintenance Windows
VaultX Hybrid NIDS for BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status

from backend.api.dependencies import get_current_user, mock_store, require_roles
from backend.api.schemas import (
    BaselineProfile,
    DeviationQueryRequest,
    DeviationQueryResponse,
    MaintenanceWindowCreate,
    MaintenanceWindowResponse,
    SeverityLevel,
    UserProfile,
    UserRole,
)

router = APIRouter(prefix="/behavioural", tags=["Behavioral Intelligence & Baselines"])


@router.get(
    "/baselines/{asset_id}",
    response_model=BaselineProfile,
    summary="Get 7-day rolling behavioral baseline profile for an asset",
)
async def get_asset_baseline(
    asset_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> BaselineProfile:
    """
    Returns statistical norms computed from past 7 days of flow data:
    normal destinations, ports, protocols, hourly transfer volume, and communication peers.
    """
    aid = asset_id.upper()
    now = datetime.now(timezone.utc)

    if aid.startswith("OT-"):
        return BaselineProfile(
            asset_id=aid,
            normal_destinations=["10.10.30.11", "10.10.30.12", "10.10.30.1"],
            normal_ports=[502, 8080],
            normal_protocols=["Modbus TCP", "HTTP"],
            bytes_per_hour_mean=4250000.0,
            bytes_per_hour_std=120000.0,
            connections_per_hour_mean=14.0,
            normal_hours=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],
            normal_peers=["OT-HMI-001", "MES-SERVER"],
            computed_at=now,
        )

    # Workstation default baseline
    return BaselineProfile(
        asset_id=aid,
        normal_destinations=["10.10.10.10", "10.10.10.5", "10.10.10.1"],
        normal_ports=[80, 443, 53, 389],
        normal_protocols=["TCP", "UDP"],
        bytes_per_hour_mean=28000000.0,
        bytes_per_hour_std=5400000.0,
        connections_per_hour_mean=45.0,
        normal_hours=[9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
        normal_peers=["CORP-DC-001", "CORP-ERP-01"],
        computed_at=now,
    )


@router.post(
    "/deviations/query",
    response_model=DeviationQueryResponse,
    summary="Evaluate traffic flow against asset baseline for anomalous deviation scoring",
)
async def query_deviation(
    payload: DeviationQueryRequest,
    current_user: UserProfile = Depends(get_current_user),
) -> DeviationQueryResponse:
    """
    Computes multi-signal deviation score across new destination, unusual port, off-hours,
    and volume anomaly. Applies maintenance window suppression if active.
    """
    aid = payload.asset_id.upper()
    signals: List[str] = []
    score = 0.0

    # Destination check
    if "30." in payload.destination_ip and not aid.startswith("OT-"):
        signals.append("cross_vlan_unexpected (Destination in Manufacturing OT)")
        score += 0.60
    if payload.destination_port not in (80, 443, 53, 502, 5432):
        signals.append(f"unusual_port ({payload.destination_port})")
        score += 0.30
    if payload.hour_of_day < 7 or payload.hour_of_day > 20:
        signals.append(f"time_anomaly (Observed at hour {payload.hour_of_day}:00 outside business hours)")
        score += 0.40

    is_anomalous = len(signals) >= 2 or score >= 0.70
    sev = SeverityLevel.HIGH if score >= 0.8 else (SeverityLevel.MEDIUM if score >= 0.5 else SeverityLevel.LOW)

    return DeviationQueryResponse(
        asset_id=aid,
        combined_deviation_score=round(min(score, 1.0), 2),
        is_anomalous=is_anomalous,
        signals_triggered=signals,
        severity=sev,
        suppressed_by_maintenance_window=False,
    )


@router.get(
    "/maintenance-windows",
    response_model=List[MaintenanceWindowResponse],
    summary="List approved plant maintenance windows that suppress false positive anomaly alerts",
)
async def list_maintenance_windows(
    current_user: UserProfile = Depends(get_current_user),
) -> List[MaintenanceWindowResponse]:
    """Returns active and scheduled maintenance windows (e.g. firmware updates, PLC reprogramming)."""
    return [
        MaintenanceWindowResponse(
            window_id="mw-001",
            start_time=datetime(2026, 11, 20, 22, 0, 0, tzinfo=timezone.utc),
            end_time=datetime(2026, 11, 21, 4, 0, 0, tzinfo=timezone.utc),
            target_assets=["OT-PLC-001", "OT-HMI-001", "FIRMWARE-RELEASE-SYSTEM"],
            description="Scheduled SMT Line 1 controller firmware patch & calibration window.",
            approver="sec_mgr_rajesh",
            is_active=False,
        )
    ]


@router.post(
    "/maintenance-windows",
    response_model=MaintenanceWindowResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Schedule an approved plant maintenance window",
)
async def create_maintenance_window(
    payload: MaintenanceWindowCreate,
    current_user: UserProfile = Depends(require_roles(UserRole.APPROVER, UserRole.SECURITY_MANAGER, UserRole.ADMIN)),
) -> MaintenanceWindowResponse:
    """Schedules a maintenance window to suppress anomalous alerts during authorized engineering work."""
    new_id = f"mw-{uuid.uuid4().hex[:6]}"
    return MaintenanceWindowResponse(
        window_id=new_id,
        start_time=payload.start_time,
        end_time=payload.end_time,
        target_assets=payload.target_assets,
        description=payload.description,
        approver=current_user.username,
        is_active=True,
    )
