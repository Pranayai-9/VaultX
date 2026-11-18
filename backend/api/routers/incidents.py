"""
backend/api/routers/incidents.py — Incident Management, Timeline, Blast Radius & AI Investigation
VaultX Hybrid NIDS for BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.api.dependencies import get_current_user, get_db_pool, mock_store, require_roles
from backend.api.schemas import (
    AIInvestigationSummary,
    BlastRadiusEdge,
    BlastRadiusGraph,
    BlastRadiusNode,
    IncidentCreate,
    IncidentResponse,
    IncidentStatus,
    IncidentTimelineItem,
    IncidentUpdateStatus,
    SeverityLevel,
    UserProfile,
    UserRole,
)

router = APIRouter(prefix="/incidents", tags=["Incidents & Forensics"])


@router.get(
    "",
    response_model=List[IncidentResponse],
    summary="List security incidents with filtering by severity, status, and VLAN zone",
)
async def list_incidents(
    severity: Optional[SeverityLevel] = Query(None, description="Filter by severity level"),
    status: Optional[IncidentStatus] = Query(None, description="Filter by incident status"),
    zone: Optional[str] = Query(None, description="Filter by affected zone name or keyword"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: UserProfile = Depends(get_current_user),
) -> List[IncidentResponse]:
    """
    Returns paginated list of security incidents detected across BECPL networks.
    Permitted for all authenticated roles (ANALYST, OPERATOR, APPROVER, SECURITY_MANAGER, ADMIN).
    """
    results: List[IncidentResponse] = []
    
    for inc_data in mock_store.incidents.values():
        if severity and inc_data.get("severity") != severity:
            continue
        if status and inc_data.get("status") != status:
            continue
        if zone:
            zones = inc_data.get("affected_zones", [])
            if not any(zone.lower() in z.lower() for z in zones):
                continue
        results.append(IncidentResponse(**inc_data))

    # Sort newest first
    results.sort(key=lambda x: x.created_at, reverse=True)
    return results[offset : offset + limit]


@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create or ingest a correlated incident record",
)
async def create_incident(
    payload: IncidentCreate,
    current_user: UserProfile = Depends(require_roles(UserRole.OPERATOR, UserRole.SECURITY_MANAGER, UserRole.ADMIN)),
) -> IncidentResponse:
    """
    Manually creates or records a security incident. Requires OPERATOR, SECURITY_MANAGER, or ADMIN role.
    """
    now = datetime.now(timezone.utc)
    new_id = str(uuid.uuid4())
    ref_num = len(mock_store.incidents) + 1
    incident_ref = f"INC-2026-{ref_num:03d}"

    incident_dict = {
        "incident_id": new_id,
        "incident_reference": incident_ref,
        "title": payload.title,
        "description": payload.description,
        "severity": payload.severity,
        "status": IncidentStatus.OPEN,
        "attack_scenario": payload.attack_scenario or "Custom Operator Incident",
        "mitre_tactic": payload.mitre_tactic,
        "mitre_technique": payload.mitre_technique,
        "affected_assets": payload.affected_assets,
        "affected_zones": payload.affected_zones,
        "ioc_list": payload.ioc_list,
        "detected_at": now,
        "created_at": now,
        "updated_at": now,
        "assigned_to": current_user.username,
        "timeline": [
            {
                "timestamp": now,
                "actor": current_user.username,
                "action": "Incident Created",
                "notes": f"Created via REST API by {current_user.full_name or current_user.username}",
            }
        ],
        "investigation_summary": None,
    }

    mock_store.incidents[new_id] = incident_dict
    return IncidentResponse(**incident_dict)


@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
    summary="Get full incident details by ID or incident reference",
)
async def get_incident(
    incident_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> IncidentResponse:
    """
    Retrieves complete incident record including evidence IOCs, affected assets, and timeline.
    Accepts either UUID or reference string (e.g. INC-2026-001).
    """
    # Lookup by ID or reference
    for item in mock_store.incidents.values():
        if item["incident_id"] == incident_id or item["incident_reference"] == incident_id:
            return IncidentResponse(**item)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Incident with ID or Reference '{incident_id}' not found.",
    )


@router.patch(
    "/{incident_id}/status",
    response_model=IncidentResponse,
    summary="Update incident lifecycle status (e.g. investigating, contained, resolved, closed)",
)
async def update_incident_status(
    incident_id: str,
    payload: IncidentUpdateStatus,
    current_user: UserProfile = Depends(require_roles(UserRole.OPERATOR, UserRole.SECURITY_MANAGER, UserRole.ADMIN)),
) -> IncidentResponse:
    """
    Transitions incident status and records audit event in timeline. Requires OPERATOR, SECURITY_MANAGER, or ADMIN.
    """
    target: Optional[Dict[str, Any]] = None
    for item in mock_store.incidents.values():
        if item["incident_id"] == incident_id or item["incident_reference"] == incident_id:
            target = item
            break

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )

    now = datetime.now(timezone.utc)
    old_status = target["status"]
    target["status"] = payload.status
    target["updated_at"] = now

    if payload.status == IncidentStatus.CONTAINED:
        target["contained_at"] = now
    elif payload.status == IncidentStatus.RESOLVED:
        target["resolved_at"] = now
    elif payload.status == IncidentStatus.CLOSED:
        target["closed_at"] = now

    timeline_note = f"Status changed from {old_status} to {payload.status.value}"
    if payload.notes:
        timeline_note += f": {payload.notes}"
    if payload.false_positive_reason:
        timeline_note += f" (FP Reason: {payload.false_positive_reason})"

    target["timeline"].append({
        "timestamp": now,
        "actor": current_user.username,
        "action": "Status Update",
        "notes": timeline_note,
    })

    return IncidentResponse(**target)


@router.get(
    "/{incident_id}/timeline",
    response_model=List[IncidentTimelineItem],
    summary="Get chronological timeline of forensic events and analyst actions",
)
async def get_incident_timeline(
    incident_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> List[IncidentTimelineItem]:
    """
    Returns time-ordered sequence of sensor alerts, correlation notices, and containment actions for an incident.
    """
    for item in mock_store.incidents.values():
        if item["incident_id"] == incident_id or item["incident_reference"] == incident_id:
            return [IncidentTimelineItem(**entry) for entry in item.get("timeline", [])]

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Incident '{incident_id}' not found.",
    )


@router.get(
    "/{incident_id}/blast-radius",
    response_model=BlastRadiusGraph,
    summary="Compute and return blast radius dependency graph and lateral exposure paths",
)
async def get_incident_blast_radius(
    incident_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> BlastRadiusGraph:
    """
    Constructs the directed risk graph mapping compromised nodes, lateral communication peers,
    and cross-VLAN exposure. Specifically alerts if OT boundaries (VLAN 30) are threatened.
    """
    target: Optional[Dict[str, Any]] = None
    for item in mock_store.incidents.values():
        if item["incident_id"] == incident_id or item["incident_reference"] == incident_id:
            target = item
            break

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )

    # Dynamic graph generation based on incident scenario
    ref = target.get("incident_reference", "")
    if "006" in ref or "OT" in target.get("title", ""):
        # OT scenario blast radius
        nodes = [
            BlastRadiusNode(id="ENG-WS-002", label="Firmware Dev Workstation", type="workstation", vlan_id=20, zone_name="Engineering & Firmware", criticality="high", compromised=True, risk_score=92.0),
            BlastRadiusNode(id="OT-PLC-001", label="SMT Line 1 OpenPLC Runtime", type="plc", vlan_id=30, zone_name="Manufacturing OT", criticality="critical", compromised=False, risk_score=85.0),
            BlastRadiusNode(id="OT-HMI-001", label="Line 1 Node-RED Operator HMI", type="hmi", vlan_id=30, zone_name="Manufacturing OT", criticality="critical", compromised=False, risk_score=78.0),
            BlastRadiusNode(id="MES-SERVER", label="Shopfloor MES Server", type="server", vlan_id=30, zone_name="Manufacturing OT", criticality="high", compromised=False, risk_score=64.0),
        ]
        edges = [
            BlastRadiusEdge(source="ENG-WS-002", target="OT-PLC-001", protocol="Modbus TCP", port=502, traffic_direction="outbound", observed_bytes=1420, suspicious=True),
            BlastRadiusEdge(source="OT-PLC-001", target="OT-HMI-001", protocol="Modbus TCP", port=502, traffic_direction="bidirectional", observed_bytes=84000, suspicious=False),
            BlastRadiusEdge(source="OT-HMI-001", target="MES-SERVER", protocol="HTTP", port=8080, traffic_direction="bidirectional", observed_bytes=42000, suspicious=False),
        ]
        return BlastRadiusGraph(
            incident_id=target["incident_id"],
            root_cause_asset="ENG-WS-002",
            total_nodes_at_risk=4,
            ot_boundary_threatened=True,
            critical_assets_exposed=["OT-PLC-001", "OT-HMI-001"],
            nodes=nodes,
            edges=edges,
        )

    # Default blast radius graph for IT/DMZ incidents
    nodes = [
        BlastRadiusNode(id="DMZ-VPN-GW", label="WireGuard VPN Gateway", type="gateway", vlan_id=50, zone_name="DMZ & Vendor Access", criticality="high", compromised=True, risk_score=88.0),
        BlastRadiusNode(id="CORP-ERP-DB", label="PostgreSQL ERP Database", type="server", vlan_id=10, zone_name="Corporate IT", criticality="critical", compromised=False, risk_score=76.0),
        BlastRadiusNode(id="CORP-WS-004", label="Finance Workstation (Vulnerable)", type="workstation", vlan_id=10, zone_name="Corporate IT", criticality="medium", compromised=False, risk_score=65.0),
    ]
    edges = [
        BlastRadiusEdge(source="DMZ-VPN-GW", target="CORP-ERP-DB", protocol="TCP", port=5432, traffic_direction="outbound", observed_bytes=12800, suspicious=True),
        BlastRadiusEdge(source="DMZ-VPN-GW", target="CORP-WS-004", protocol="SMB", port=445, traffic_direction="outbound", observed_bytes=3400, suspicious=True),
    ]
    return BlastRadiusGraph(
        incident_id=target["incident_id"],
        root_cause_asset="DMZ-VPN-GW",
        total_nodes_at_risk=3,
        ot_boundary_threatened=False,
        critical_assets_exposed=["CORP-ERP-DB"],
        nodes=nodes,
        edges=edges,
    )


@router.get(
    "/{incident_id}/investigation",
    response_model=AIInvestigationSummary,
    summary="Get context-aware AI investigation assistant narrative and root-cause synthesis",
)
async def get_incident_investigation(
    incident_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> AIInvestigationSummary:
    """
    Returns LLM/rule-synthesized incident investigation briefing including root-cause hypothesis,
    MITRE ATT&CK mapping, and safety impact assessment for manufacturing MSME operations.
    """
    target: Optional[Dict[str, Any]] = None
    for item in mock_store.incidents.values():
        if item["incident_id"] == incident_id or item["incident_reference"] == incident_id:
            target = item
            break

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )

    summary = target.get("investigation_summary")
    if not summary:
        now = datetime.now(timezone.utc)
        summary = {
            "incident_id": target["incident_id"],
            "narrative": f"Investigation in progress for incident {target['incident_reference']}. Multi-source telemetry gathered from VLAN sensors.",
            "attack_vector": target.get("attack_scenario", "Unknown"),
            "mitre_tactics": [target.get("mitre_tactic", "Execution")],
            "mitre_techniques": [target.get("mitre_technique", "T1059")],
            "confidence_score": 0.85,
            "root_cause_hypothesis": "Suspicious anomaly detected by hybrid ML & signature correlation.",
            "recommended_containment_actions": ["Review host audit logs", "Monitor peer traffic"],
            "potential_business_impact": "Operational disruption or unauthorized data access",
            "ot_safety_evaluation": "Standard precautions apply. Verify safety before isolating endpoints.",
            "generated_at": now,
        }

    return AIInvestigationSummary(**summary)
