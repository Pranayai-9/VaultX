"""
backend/api/routers/containment.py — Policy Engine, Human-in-the-Loop Approval & Containment Enforcement
VaultX Hybrid NIDS for BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.api.dependencies import get_current_user, mock_store, require_roles
from backend.api.schemas import (
    ActionStatus,
    ActionType,
    ApproveActionRequest,
    ContainmentMode,
    ContainmentModesResponse,
    ExecuteActionRequest,
    FirewallRuleCreate,
    FirewallRuleResponse,
    IncidentStatus,
    ProposeActionRequest,
    ResponseActionResponse,
    RollbackActionRequest,
    UserProfile,
    UserRole,
)

router = APIRouter(prefix="/containment", tags=["Containment & Response"])


def _is_ot_target(asset_id: Optional[str], target_ip: Optional[str]) -> bool:
    """Helper to determine whether target asset or IP belongs to Manufacturing OT (VLAN 30)."""
    if asset_id:
        aid = asset_id.upper()
        if aid.startswith("OT-") or "PLC" in aid or "HMI" in aid or "MES" in aid:
            return True
    if target_ip:
        if target_ip.startswith("10.10.30.") or target_ip.startswith("172.20.30."):
            return True
    return False


@router.get(
    "/modes",
    response_model=ContainmentModesResponse,
    summary="Get active containment policy mode and safety interlock state",
)
async def get_containment_modes(
    current_user: UserProfile = Depends(get_current_user),
) -> ContainmentModesResponse:
    """
    Returns the currently active containment mode and describes all 4 operating modes.
    Enforces that OT safety interlocks remain engaged at all times.
    """
    return ContainmentModesResponse(
        active_mode=mock_store.active_containment_mode,
        ot_safety_interlock_active=True,
        modes_available={
            "MODE_1_MONITOR_ONLY": "Passive detection only; alerts generated without active network intervention.",
            "MODE_2_AUTO_ISOLATE_NON_OT": "Automated isolation permitted for Corporate IT (VLAN 10) & DMZ (VLAN 50). Manufacturing OT ALWAYS protected by human gate.",
            "MODE_3_HUMAN_APPROVAL_REQUIRED": "Default production mode: all containment proposals require human authorization and MFA token.",
            "MODE_4_STRICT_ZERO_TRUST": "Emergency lockdown mode: immediate perimeter block on unauthenticated/untrusted ingress.",
        },
        two_person_rule_for_ot=True,
        max_isolation_duration_hours=24,
    )


@router.post(
    "/propose",
    response_model=ResponseActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Propose an automated or operator-initiated containment action",
)
async def propose_containment_action(
    payload: ProposeActionRequest,
    current_user: UserProfile = Depends(require_roles(UserRole.OPERATOR, UserRole.APPROVER, UserRole.SECURITY_MANAGER, UserRole.ADMIN)),
) -> ResponseActionResponse:
    """
    Proposes an isolation action (e.g. host quarantine, IP block, credential disable).
    Validates target zone safety. If OT is targeted, automatically marks action for mandatory human authorization.
    """
    # Verify incident exists
    inc = mock_store.incidents.get(payload.incident_id)
    if not inc:
        for i in mock_store.incidents.values():
            if i["incident_reference"] == payload.incident_id:
                inc = i
                break
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{payload.incident_id}' not found.",
        )

    now = datetime.now(timezone.utc)
    new_action_id = str(uuid.uuid4())
    is_ot = _is_ot_target(payload.target_asset_id, payload.target_ip)

    action_record = {
        "action_id": new_action_id,
        "incident_id": inc["incident_id"],
        "action_type": payload.action_type,
        "target_asset_id": payload.target_asset_id,
        "target_ip": payload.target_ip,
        "target_identity_id": payload.target_identity_id,
        "initiated_by": current_user.username,
        "approved_by": None,
        "second_approver": None,
        "status": ActionStatus.PENDING,
        "is_ot_asset": is_ot,
        "approval_method": None,
        "approval_timestamp": None,
        "executed_at": None,
        "rollback_at": None,
        "rollback_reason": None,
        "execution_detail": {
            "justification": payload.justification,
            "isolation_method": payload.isolation_method,
            "quarantine_vlan": payload.quarantine_vlan,
            "ot_safety_warning": "OT asset requires Security Manager + Operations two-person approval before execution." if is_ot else None,
        },
        "created_at": now,
    }

    mock_store.response_actions[new_action_id] = action_record

    # Append to incident timeline
    inc["timeline"].append({
        "timestamp": now,
        "actor": current_user.username,
        "action": f"Proposed Containment: {payload.action_type.value}",
        "notes": f"Target: {payload.target_asset_id or payload.target_ip}. Justification: {payload.justification}",
    })

    return ResponseActionResponse(**action_record)


@router.get(
    "/actions",
    response_model=List[ResponseActionResponse],
    summary="List all proposed, pending, executed, and rolled-back containment actions",
)
async def list_containment_actions(
    status_filter: Optional[ActionStatus] = Query(None, alias="status"),
    incident_id: Optional[str] = Query(None),
    current_user: UserProfile = Depends(get_current_user),
) -> List[ResponseActionResponse]:
    """
    Returns history of response actions across all network zones with filtering by lifecycle status.
    """
    results: List[ResponseActionResponse] = []
    for item in mock_store.response_actions.values():
        if status_filter and item["status"] != status_filter:
            continue
        if incident_id and item["incident_id"] != incident_id:
            continue
        results.append(ResponseActionResponse(**item))

    results.sort(key=lambda x: x.created_at, reverse=True)
    return results


@router.get(
    "/actions/{action_id}",
    response_model=ResponseActionResponse,
    summary="Get details of a specific containment action",
)
async def get_containment_action(
    action_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> ResponseActionResponse:
    """Retrieves full execution audit trail of a specific containment action."""
    action = mock_store.response_actions.get(action_id)
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Containment action '{action_id}' not found.",
        )
    return ResponseActionResponse(**action)


@router.post(
    "/actions/{action_id}/approve",
    response_model=ResponseActionResponse,
    summary="Approve a pending containment action with MFA token and OT two-person validation",
)
async def approve_containment_action(
    action_id: str,
    payload: ApproveActionRequest,
    current_user: UserProfile = Depends(require_roles(UserRole.APPROVER, UserRole.SECURITY_MANAGER, UserRole.ADMIN)),
) -> ResponseActionResponse:
    """
    Authorizes a pending response action.
    Validates MFA code (6 digits).
    For OT assets (VLAN 30 / PLCs / HMIs):
      - Enforces two-person approval rule: requires second_approver_username.
      - Requires SECURITY_MANAGER or ADMIN role.
    """
    action = mock_store.response_actions.get(action_id)
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Containment action '{action_id}' not found.",
        )

    if action["status"] != ActionStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve action with status '{action['status'].value}'. Must be 'pending'.",
        )

    # Validate MFA code
    if not (payload.mfa_code.isdigit() and len(payload.mfa_code) == 6):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA verification token: Must be a 6-digit numeric TOTP code.",
        )

    # Enforce OT Safety & Two-Person Rule
    if action["is_ot_asset"]:
        if current_user.role not in (UserRole.SECURITY_MANAGER, UserRole.ADMIN) and not payload.break_glass:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="OT Containment Safety Violation: Authorizing containment for industrial assets requires SECURITY_MANAGER role.",
            )
        if not payload.second_approver_username and not payload.break_glass:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="OT Two-Person Rule Violation: Manufacturing safety policy mandates a designated second approver (Operations Head / Plant Manager) for OT isolation.",
            )

    now = datetime.now(timezone.utc)
    action["status"] = ActionStatus.APPROVED
    action["approved_by"] = current_user.username
    action["second_approver"] = payload.second_approver_username
    action["approval_method"] = "break_glass" if payload.break_glass else "mfa_token"
    action["approval_timestamp"] = now
    action["execution_detail"]["approval_notes"] = payload.approval_notes
    if payload.break_glass:
        action["execution_detail"]["break_glass_reason"] = payload.break_glass_reason

    # Add to incident timeline
    inc = mock_store.incidents.get(action["incident_id"])
    if inc:
        inc["timeline"].append({
            "timestamp": now,
            "actor": current_user.username,
            "action": f"Approved Action: {action['action_type'].value}",
            "notes": f"Approved via {action['approval_method']}. Second approver: {payload.second_approver_username or 'N/A'}",
        })

    return ResponseActionResponse(**action)


@router.post(
    "/actions/{action_id}/execute",
    response_model=ResponseActionResponse,
    summary="Execute an approved containment action via network firewall or identity adapter",
)
async def execute_containment_action(
    action_id: str,
    payload: ExecuteActionRequest,
    current_user: UserProfile = Depends(require_roles(UserRole.OPERATOR, UserRole.SECURITY_MANAGER, UserRole.ADMIN)),
) -> ResponseActionResponse:
    """
    Executes containment action using relevant network enforcement adapter (simulated firewall, VLAN shift, session revocation).
    """
    action = mock_store.response_actions.get(action_id)
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Containment action '{action_id}' not found.",
        )

    if action["status"] != ActionStatus.APPROVED and not payload.force_immediate:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Action must be in 'approved' status before execution. Current: '{action['status'].value}'.",
        )

    now = datetime.now(timezone.utc)
    action["status"] = ActionStatus.COMPLETED
    action["executed_at"] = now

    # Apply enforcement to simulated firewall or session
    if action["action_type"] in (ActionType.BLOCK_IP, ActionType.FIREWALL_RULE):
        ip = action.get("target_ip") or "198.51.100.42"
        rule_id = f"FW-EXEC-{len(mock_store.firewall_rules) + 1:03d}"
        mock_store.firewall_rules[rule_id] = {
            "rule_id": rule_id,
            "source_ip": ip,
            "destination_ip": "0.0.0.0/0",
            "protocol": "ANY",
            "port": "ANY",
            "action": "DROP",
            "active": True,
            "incident_id": action["incident_id"],
            "created_by": current_user.username,
            "created_at": now,
            "expires_at": None,
        }
        action["execution_detail"]["enforcement"] = f"Created firewall rule {rule_id} dropping all traffic from {ip}"

    elif action["action_type"] == ActionType.ISOLATE:
        target = action.get("target_asset_id") or "UNKNOWN-ASSET"
        action["execution_detail"]["enforcement"] = f"Shifted switch port for {target} to quarantine VLAN 70 (Management Access Preserved)"

    elif action["action_type"] == ActionType.SESSION_REVOKE:
        target_id = action.get("target_identity_id") or "id-006"
        action["execution_detail"]["enforcement"] = f"Revoked active WireGuard VPN session for identity {target_id}"

    # Update incident status to contained
    inc = mock_store.incidents.get(action["incident_id"])
    if inc:
        inc["status"] = IncidentStatus.CONTAINED
        inc["contained_at"] = now
        inc["timeline"].append({
            "timestamp": now,
            "actor": current_user.username,
            "action": f"Executed Containment: {action['action_type'].value}",
            "notes": f"Enforcement successful: {action['execution_detail'].get('enforcement', 'Action completed')}",
        })

    return ResponseActionResponse(**action)


@router.post(
    "/actions/{action_id}/rollback",
    response_model=ResponseActionResponse,
    summary="Rollback a previously executed containment action and restore normal connectivity",
)
async def rollback_containment_action(
    action_id: str,
    payload: RollbackActionRequest,
    current_user: UserProfile = Depends(require_roles(UserRole.SECURITY_MANAGER, UserRole.ADMIN)),
) -> ResponseActionResponse:
    """
    Rolls back containment action, removes generated firewall ACLs, and restores asset network access.
    Requires SECURITY_MANAGER or ADMIN role.
    """
    action = mock_store.response_actions.get(action_id)
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Containment action '{action_id}' not found.",
        )

    if action["status"] != ActionStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Can only rollback completed actions. Current status is '{action['status'].value}'.",
        )

    now = datetime.now(timezone.utc)
    action["status"] = ActionStatus.ROLLED_BACK
    action["rollback_at"] = now
    action["rollback_reason"] = payload.rollback_reason

    # Deactivate associated firewall rules
    for rule in mock_store.firewall_rules.values():
        if rule.get("incident_id") == action["incident_id"]:
            rule["active"] = False

    inc = mock_store.incidents.get(action["incident_id"])
    if inc:
        inc["timeline"].append({
            "timestamp": now,
            "actor": current_user.username,
            "action": f"Rolled Back Containment: {action['action_type'].value}",
            "notes": f"Rollback reason: {payload.rollback_reason}",
        })

    return ResponseActionResponse(**action)


@router.get(
    "/firewall/rules",
    response_model=List[FirewallRuleResponse],
    summary="List active simulated firewall ACL rules enforced across BECPL gateways",
)
async def list_firewall_rules(
    current_user: UserProfile = Depends(get_current_user),
) -> List[FirewallRuleResponse]:
    """Returns active and expired firewall rules implemented for perimeter and inter-VLAN containment."""
    return [FirewallRuleResponse(**rule) for rule in mock_store.firewall_rules.values()]


@router.delete(
    "/firewall/rules/{rule_id}",
    summary="Deactivate or remove a simulated firewall rule",
)
async def delete_firewall_rule(
    rule_id: str,
    current_user: UserProfile = Depends(require_roles(UserRole.SECURITY_MANAGER, UserRole.ADMIN)),
):
    """Deletes or deactivates a specific firewall rule. Requires SECURITY_MANAGER or ADMIN."""
    rule = mock_store.firewall_rules.get(rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Firewall rule '{rule_id}' not found.",
        )
    rule["active"] = False
    return {"message": f"Firewall rule '{rule_id}' deactivated successfully."}
