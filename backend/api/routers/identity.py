"""
backend/api/routers/identity.py — 7-Way Multi-Source Identity Registry & Session Compliance
VaultX Hybrid NIDS for BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.api.dependencies import get_current_user, mock_store
from backend.api.schemas import (
    ActiveSessionResponse,
    AgentTelemetryResponse,
    IdentityProfileResponse,
    IdentityRecord,
    PrincipalType,
    UserProfile,
    VendorComplianceResponse,
)

router = APIRouter(prefix="/identity", tags=["Identity Intelligence & Sessions"])


@router.get(
    "/registry",
    response_model=List[IdentityRecord],
    summary="List all tracked principals across the 7 identity classifications",
)
async def list_identities(
    principal_type: Optional[PrincipalType] = Query(None, description="Filter by identity type"),
    department: Optional[str] = Query(None, description="Filter by department"),
    current_user: UserProfile = Depends(get_current_user),
) -> List[IdentityRecord]:
    """
    Returns the complete BECPL identity catalog classifying principals into:
    HUMAN_USER, SERVICE_ACCOUNT, AUTOMATION_WORKLOAD, AI_AGENT, INDUSTRIAL_DEVICE,
    THIRD_PARTY_IDENTITY, or UNKNOWN_IDENTITY.
    """
    results: List[IdentityRecord] = []
    for item in mock_store.identities.values():
        if principal_type and item["principal_type"] != principal_type:
            continue
        if department and department.lower() not in (item.get("department") or "").lower():
            continue
        results.append(IdentityRecord(**item))
    return results


@router.get(
    "/sessions/active",
    response_model=List[ActiveSessionResponse],
    summary="List active authenticated sessions across VPN, SSH, Web, and Kerberos",
)
async def list_active_sessions(
    current_user: UserProfile = Depends(get_current_user),
) -> List[ActiveSessionResponse]:
    """
    Returns real-time session table tracking duration, target resources, and anomalies
    (such as session duration > 8 hours, off-hours access, or impossible travel).
    """
    now = datetime.now(timezone.utc)
    sessions = [
        ActiveSessionResponse(
            session_id="sess-001",
            principal_name="rahul.sharma",
            principal_type=PrincipalType.HUMAN_USER,
            source_ip="10.10.20.30",
            target_resource="gitea-server.becpl.internal:3000",
            auth_method="kerberos_sso",
            session_start=now,
            last_activity=now,
            duration_minutes=45,
            is_anomalous=False,
            anomaly_reasons=[],
        ),
        ActiveSessionResponse(
            session_id="sess-002",
            principal_name="vendor_schneider",
            principal_type=PrincipalType.THIRD_PARTY_IDENTITY,
            source_ip="172.20.50.10",
            target_resource="corp-erp-db.becpl.internal:5432",
            auth_method="wireguard_vpn_cert",
            session_start=now,
            last_activity=now,
            duration_minutes=250,  # > 240 mins (4 hours policy limit)
            is_anomalous=True,
            anomaly_reasons=["Session duration 250m exceeds 4-hour vendor policy limit", "Accessing unapproved Corporate ERP DB zone"],
        ),
        ActiveSessionResponse(
            session_id="sess-003",
            principal_name="ai_defect_inspector",
            principal_type=PrincipalType.AI_AGENT,
            source_ip="10.10.20.31",
            target_resource="mes-server.becpl.internal:8080/api/v1/quality",
            auth_method="api_key_bearer",
            session_start=now,
            last_activity=now,
            duration_minutes=120,
            is_anomalous=False,
            anomaly_reasons=[],
        ),
    ]
    return sessions


@router.get(
    "/profiles/{identity_id}",
    response_model=IdentityProfileResponse,
    summary="Get detailed behavioral profile, authorized zones, and baseline for an identity",
)
async def get_identity_profile(
    identity_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> IdentityProfileResponse:
    """Returns behavioral baseline parameters and authorized zone boundaries for a specific identity."""
    target = mock_store.identities.get(identity_id)
    if not target:
        for i in mock_store.identities.values():
            if i["principal_name"].lower() == identity_id.lower():
                target = i
                break

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity '{identity_id}' not found.",
        )

    now = datetime.now(timezone.utc)
    return IdentityProfileResponse(
        identity=IdentityRecord(**target),
        active_sessions=[],
        normal_working_hours="09:00 - 18:30 IST (Mon-Sat)",
        authorized_zones=["Engineering & Firmware", "Corporate IT"] if target["principal_type"] == PrincipalType.HUMAN_USER else ["Manufacturing OT"],
        recent_anomalies=[
            {"timestamp": now, "type": "Off-hours login attempt", "source_ip": "198.51.100.42"}
        ] if target["risk_score"] > 50 else [],
    )


@router.get(
    "/agents/telemetry",
    response_model=List[AgentTelemetryResponse],
    summary="Monitor AI agents and automation workloads operational telemetry",
)
async def get_ai_agent_telemetry(
    current_user: UserProfile = Depends(get_current_user),
) -> List[AgentTelemetryResponse]:
    """
    Provides observability into autonomous AI agents and automated scripts interacting
    with BECPL APIs, detecting API call burst rate anomalies and scope transgressions.
    """
    return [
        AgentTelemetryResponse(
            agent_id="agent-01",
            agent_name="ai_defect_inspector",
            classification=PrincipalType.AI_AGENT,
            model_or_runtime="YOLOv8-Embedded-Vision / Python 3.11",
            authorized_endpoints=[
                "/api/v1/quality/inspect",
                "/api/v1/quality/telemetry",
                "/api/v1/mes/batch-status",
            ],
            current_calls_per_minute=22.4,
            baseline_calls_per_minute=20.0,
            last_invoked_tool="trigger_camera_strobe",
            compliance_status="compliant",
            notes="Vision AI agent inspecting surface-mount component placement on SMT Line 1.",
        ),
        AgentTelemetryResponse(
            agent_id="agent-02",
            agent_name="bot_erp_sync",
            classification=PrincipalType.AUTOMATION_WORKLOAD,
            model_or_runtime="Celery Worker / Python 3.11",
            authorized_endpoints=[
                "/api/v1/erp/inventory",
                "/api/v1/wms/stock-levels",
            ],
            current_calls_per_minute=5.0,
            baseline_calls_per_minute=5.0,
            last_invoked_tool="sync_wms_ledger",
            compliance_status="compliant",
            notes="Automated backend sync between Warehouse WMS and Corporate Odoo ERP.",
        ),
    ]


@router.get(
    "/vendor/compliance",
    response_model=List[VendorComplianceResponse],
    summary="Get vendor access policy compliance report (4-hour limits, MFA adherence)",
)
async def get_vendor_compliance(
    current_user: UserProfile = Depends(get_current_user),
) -> List[VendorComplianceResponse]:
    """
    Audits third-party vendor access against BECPL Vendor Remote Access Policy:
    Flags sessions exceeding 4 hours, missing MFA, or unauthorized cross-VLAN traversals.
    """
    return [
        VendorComplianceResponse(
            vendor_id="VEND-SCHNEIDER",
            vendor_name="Schneider Electric India (Industrial Maintenance)",
            active_sessions_count=1,
            max_session_hours_allowed=4,
            exceeded_duration_sessions=["sess-002"],
            unauthorized_zone_attempts=1,
            mfa_compliance_pct=100.0,
            overall_compliance_status="policy_violation",
        ),
        VendorComplianceResponse(
            vendor_id="VEND-BLUEDART",
            vendor_name="Blue Dart Express (Logistics API Integration)",
            active_sessions_count=0,
            max_session_hours_allowed=4,
            exceeded_duration_sessions=[],
            unauthorized_zone_attempts=0,
            mfa_compliance_pct=100.0,
            overall_compliance_status="compliant",
        ),
        VendorComplianceResponse(
            vendor_id="VEND-AWS-SUPPORT",
            vendor_name="AWS Cloud Managed Services",
            active_sessions_count=0,
            max_session_hours_allowed=4,
            exceeded_duration_sessions=[],
            unauthorized_zone_attempts=0,
            mfa_compliance_pct=100.0,
            overall_compliance_status="compliant",
        ),
    ]
