"""
backend/api/dependencies.py — Dependency Injection & Security Context
VaultX Hybrid NIDS for BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Set

from fastapi import Depends, Header, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.api.schemas import (
    ActionStatus,
    ActionType,
    ContainmentMode,
    IncidentStatus,
    PrincipalType,
    SeverityLevel,
    UserProfile,
    UserRole,
)

logger = logging.getLogger("vaultx.dependencies")

# Security Bearer scheme
bearer_scheme = HTTPBearer(auto_error=False)

# Simulation mode flag
SIMULATION_MODE: bool = os.environ.get("VAULTX_SIMULATION_MODE", "true").lower() in ("1", "true", "yes")

# Known API keys and Token mapping for BECPL Security Operations
TOKEN_ROLE_MAP: Dict[str, Dict[str, Any]] = {
    "vaultx-admin-key": {"username": "admin", "role": UserRole.ADMIN, "department": "Security Ops", "full_name": "System Administrator"},
    "admin-token": {"username": "admin", "role": UserRole.ADMIN, "department": "Security Ops", "full_name": "System Administrator"},
    "vaultx-manager-key": {"username": "sec_mgr_rajesh", "role": UserRole.SECURITY_MANAGER, "department": "Cybersecurity", "full_name": "Rajesh Kumar (Security Manager)"},
    "manager-token": {"username": "sec_mgr_rajesh", "role": UserRole.SECURITY_MANAGER, "department": "Cybersecurity", "full_name": "Rajesh Kumar (Security Manager)"},
    "vaultx-approver-key": {"username": "approver_anita", "role": UserRole.APPROVER, "department": "Operations Management", "full_name": "Anita Deshmukh (Plant Ops Head)"},
    "approver-token": {"username": "approver_anita", "role": UserRole.APPROVER, "department": "Operations Management", "full_name": "Anita Deshmukh (Plant Ops Head)"},
    "vaultx-operator-key": {"username": "operator_vikram", "role": UserRole.OPERATOR, "department": "SOC Operations", "full_name": "Vikram Shinde (SOC Lead)"},
    "operator-token": {"username": "operator_vikram", "role": UserRole.OPERATOR, "department": "SOC Operations", "full_name": "Vikram Shinde (SOC Lead)"},
    "vaultx-analyst-key": {"username": "analyst_pooja", "role": UserRole.ANALYST, "department": "SOC Operations", "full_name": "Pooja Patil (Security Analyst)"},
    "analyst-token": {"username": "analyst_pooja", "role": UserRole.ANALYST, "department": "SOC Operations", "full_name": "Pooja Patil (Security Analyst)"},
}


# ---------------------------------------------------------------------------
# In-Memory Mock Store for Simulation and Standalone Executions
# ---------------------------------------------------------------------------

class MockDataStore:
    """
    High-fidelity in-memory state for BECPL NIDS when PostgreSQL/Redis are offline.
    Pre-populates Phase 1 and Phase 2 assets, incidents, models, threat intel, and firewall ACLs.
    """
    def __init__(self):
        self.incidents: Dict[str, Dict[str, Any]] = {}
        self.response_actions: Dict[str, Dict[str, Any]] = {}
        self.firewall_rules: Dict[str, Dict[str, Any]] = {}
        self.vulnerabilities: Dict[str, Dict[str, Any]] = {}
        self.kev_catalog: List[Dict[str, Any]] = []
        self.ip_blocklist: List[Dict[str, Any]] = []
        self.ja3_signatures: Dict[str, Dict[str, Any]] = {}
        self.identities: Dict[str, Dict[str, Any]] = {}
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.active_models: Dict[str, Dict[str, Any]] = {}
        self.maintenance_windows: Dict[str, Dict[str, Any]] = {}
        self.active_containment_mode: ContainmentMode = ContainmentMode.MODE_3_HUMAN_APPROVAL_REQUIRED
        self._seed_default_data()

    def _seed_default_data(self):
        now = datetime.now(timezone.utc)
        
        # 1. Incidents corresponding to Phase 1 Scenarios
        incidents_seed = [
            {
                "incident_id": "c1a10001-0000-0000-0000-000000000001",
                "incident_reference": "INC-2026-001",
                "title": "Vendor Remote Access Scope Creep & Unauthorized IT Traversal",
                "description": "Third-party vendor identity (vendor_schneider) logged in via VPN gateway (VLAN 50) outside authorized hours and initiated port scan toward Corporate ERP database.",
                "severity": SeverityLevel.HIGH,
                "status": IncidentStatus.OPEN,
                "attack_scenario": "Vendor Compromise & Scope Creep",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "T1199",
                "affected_assets": ["DMZ-VPN-GW", "CORP-ERP-DB", "CORP-WS-004"],
                "affected_zones": ["DMZ & Vendor Access", "Corporate IT"],
                "ioc_list": {"source_ip": "172.20.50.10", "suspicious_ip": "198.51.100.42", "vendor_id": "VEND-SCHNEIDER"},
                "detected_at": now,
                "created_at": now,
                "updated_at": now,
                "timeline": [
                    {"timestamp": now, "actor": "Zeek-Sensor-VLAN50", "action": "Anomaly Detected: VPN session initiated at 02:15 IST", "notes": "Expected window 09:00-18:00 IST"},
                    {"timestamp": now, "actor": "Suricata-Sensor-VLAN10", "action": "Alert triggered: Cross-VLAN scan to port 5432", "notes": "Rule BECPL-SUR-004"}
                ],
                "investigation_summary": {
                    "incident_id": "c1a10001-0000-0000-0000-000000000001",
                    "narrative": "A credential belonging to external maintenance vendor Schneider Electric was used from a previously unseen IP to access the DMZ WireGuard VPN. Following authentication, lateral reconnaissance targeted the PostgreSQL database holding ERP records.",
                    "attack_vector": "Third-party supply chain credential abuse",
                    "mitre_tactics": ["Initial Access", "Discovery", "Lateral Movement"],
                    "mitre_techniques": ["T1199 (Trusted Relationship)", "T1046 (Network Service Discovery)"],
                    "confidence_score": 0.94,
                    "root_cause_hypothesis": "Compromised vendor laptop credentials leaked on dark web",
                    "recommended_containment_actions": ["Revoke vendor session", "Block source IP on Edge Firewall", "Enforce MFA re-enrollment"],
                    "potential_business_impact": "Potential exfiltration of bill-of-materials and manufacturing component pricing",
                    "ot_safety_evaluation": "OT zone currently untouched. Strict isolation of VLAN 50 will NOT affect shopfloor PLCs.",
                    "generated_at": now
                }
            },
            {
                "incident_id": "c1a10002-0000-0000-0000-000000000002",
                "incident_reference": "INC-2026-002",
                "title": "Service Account Kerberoasting & ERP Database Access",
                "description": "svc_backup account requested multiple Kerberos TGS tickets with RC4 encryption; subsequent query burst executed on ERP Postgres server.",
                "severity": SeverityLevel.HIGH,
                "status": IncidentStatus.INVESTIGATING,
                "attack_scenario": "Service Credential Abuse",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1558.003",
                "affected_assets": ["CORP-DC-001", "CORP-ERP-DB", "CORP-BACKUP-01"],
                "affected_zones": ["Corporate IT"],
                "ioc_list": {"service_account": "svc_backup", "source_ip": "10.10.10.20"},
                "detected_at": now,
                "created_at": now,
                "updated_at": now,
                "timeline": [{"timestamp": now, "actor": "Identity-Engine", "action": "Kerberoast ticket request burst", "notes": "SPN: postgres/db-postgres.becpl.internal"}],
                "investigation_summary": {
                    "incident_id": "c1a10002-0000-0000-0000-000000000002",
                    "narrative": "Internal backup service account observed requesting ticket granting service tokens with legacy weak encryption, pointing to ticket extraction attempts.",
                    "attack_vector": "Internal credential harvesting",
                    "mitre_tactics": ["Credential Access"],
                    "mitre_techniques": ["T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)"],
                    "confidence_score": 0.88,
                    "root_cause_hypothesis": "Weak service account password vulnerable to offline cracking",
                    "recommended_containment_actions": ["Rotate svc_backup password", "Enforce AES-256 Kerberos encryption", "Isolate backup server temporarily"],
                    "potential_business_impact": "Unauthorized access to financial ERP database",
                    "ot_safety_evaluation": "Completely confined to Corporate IT. Zero OT impact.",
                    "generated_at": now
                }
            },
            {
                "incident_id": "c1a10006-0000-0000-0000-000000000006",
                "incident_reference": "INC-2026-006",
                "title": "Unauthorized Modbus TCP Write Command to SMT Line 1 PLC",
                "description": "Workstation in Engineering segment (ENG-WS-002) sent Modbus Function Code 16 (Preset Multiple Registers) to OpenPLC runtime in Manufacturing OT VLAN outside maintenance window.",
                "severity": SeverityLevel.CRITICAL,
                "status": IncidentStatus.OPEN,
                "attack_scenario": "OT Anomaly & Modbus Tampering",
                "mitre_tactic": "Impair Process Control",
                "mitre_technique": "T0855",
                "affected_assets": ["ENG-WS-002", "OT-PLC-001", "OT-HMI-001"],
                "affected_zones": ["Engineering & Firmware", "Manufacturing OT"],
                "ioc_list": {"source_ip": "10.10.20.31", "dest_ip": "10.10.30.10", "protocol": "Modbus TCP", "function_code": 16},
                "detected_at": now,
                "created_at": now,
                "updated_at": now,
                "timeline": [
                    {"timestamp": now, "actor": "Zeek-Sensor-VLAN30", "action": "Zeek Notice: Modbus write from non-whitelisted Engineering IP", "notes": "Port 502 FC 16 targeted address 0x1004"},
                    {"timestamp": now, "actor": "OT-Safety-Interlock", "action": "Safety Rule Triggered: OT write during active shift requires manager approval", "notes": "Interlock safety check halted automatic isolation"}
                ],
                "investigation_summary": {
                    "incident_id": "c1a10006-0000-0000-0000-000000000006",
                    "narrative": "A suspicious Modbus TCP Function 16 packet was sent from an engineering computer directly to the SMT assembly line programmable logic controller. The packet attempted to alter holding register values governing conveyor belt speed.",
                    "attack_vector": "Engineering workstation pivot into industrial control network",
                    "mitre_tactics": ["Inhibit Response Function", "Impair Process Control"],
                    "mitre_techniques": ["T0855 (Unauthorized Command Message)", "T0836 (Modify Parameter)"],
                    "confidence_score": 0.98,
                    "root_cause_hypothesis": "Engineering workstation compromised via malicious firmware development dependency",
                    "recommended_containment_actions": ["Isolate ENG-WS-002 immediately", "Verify PLC holding register state via manual HMI audit", "Require 2-person approval for OT boundary ACL block"],
                    "potential_business_impact": "Physical component defect on PCB line, equipment jamming, or human safety risk on assembly floor",
                    "ot_safety_evaluation": "CRITICAL OT SAFETY WARNING: Do NOT drop active PLC connection abruptly without human operator confirmation on shopfloor to prevent emergency line trip.",
                    "generated_at": now
                }
            }
        ]
        for inc in incidents_seed:
            self.incidents[inc["incident_id"]] = inc

        # 2. Pre-seeded Response Actions
        action_seed = {
            "action_id": "d2b20001-0000-0000-0000-000000000001",
            "incident_id": "c1a10001-0000-0000-0000-000000000001",
            "action_type": ActionType.BLOCK_IP,
            "target_asset_id": "DMZ-VPN-GW",
            "target_ip": "198.51.100.42",
            "target_identity_id": None,
            "initiated_by": "operator_vikram",
            "approved_by": "sec_mgr_rajesh",
            "second_approver": None,
            "status": ActionStatus.COMPLETED,
            "is_ot_asset": False,
            "approval_method": "mfa_token",
            "approval_timestamp": now,
            "executed_at": now,
            "rollback_at": None,
            "rollback_reason": None,
            "execution_detail": {"adapter": "EdgeFirewallAdapter", "rule_id": "FW-AUTO-001", "result": "IP 198.51.100.42 blocked on DMZ interface"},
            "created_at": now
        }
        self.response_actions[action_seed["action_id"]] = action_seed

        # 3. Simulated Firewall Rules
        fw_seed = {
            "FW-AUTO-001": {
                "rule_id": "FW-AUTO-001",
                "source_ip": "198.51.100.42",
                "destination_ip": "0.0.0.0/0",
                "protocol": "ANY",
                "port": "ANY",
                "action": "DROP",
                "active": True,
                "incident_id": "c1a10001-0000-0000-0000-000000000001",
                "created_by": "sec_mgr_rajesh",
                "created_at": now,
                "expires_at": None
            }
        }
        self.firewall_rules.update(fw_seed)

        # 4. Known Vulnerabilities from Phase 1/Phase 2 spec
        vulns_seed = {
            "CVE-2020-0796": {
                "cve_id": "CVE-2020-0796",
                "cvss_score": 10.0,
                "severity": SeverityLevel.CRITICAL,
                "description": "SMBv3 Compression Remote Code Execution Vulnerability (SMBGhost)",
                "affected_assets": ["CORP-WS-004"],
                "in_cisa_kev": True,
                "exploit_available": True,
                "patch_available": True,
                "recommended_mitigation": "Disable SMBv3 compression; apply Microsoft March 2020 Security Update."
            },
            "CVE-2016-10009": {
                "cve_id": "CVE-2016-10009",
                "cvss_score": 7.5,
                "severity": SeverityLevel.HIGH,
                "description": "OpenSSH ssh-agent arbitrary library loading vulnerability",
                "affected_assets": ["ENG-WS-002"],
                "in_cisa_kev": False,
                "exploit_available": True,
                "patch_available": True,
                "recommended_mitigation": "Upgrade OpenSSH to version 7.4 or later; disable agent forwarding."
            },
            "CVE-2018-1000656": {
                "cve_id": "CVE-2018-1000656",
                "cvss_score": 7.5,
                "severity": SeverityLevel.HIGH,
                "description": "Flask / Jinja2 template injection leading to arbitrary command execution",
                "affected_assets": ["MES-SERVER"],
                "in_cisa_kev": False,
                "exploit_available": True,
                "patch_available": True,
                "recommended_mitigation": "Upgrade Flask to >= 1.0.3 and sanitize template inputs."
            },
            "CVE-2019-9511": {
                "cve_id": "CVE-2019-9511",
                "cvss_score": 7.5,
                "severity": SeverityLevel.HIGH,
                "description": "HTTP/2 Data Drip resource exhaustion in nginx web server",
                "affected_assets": ["FIRMWARE-STORAGE"],
                "in_cisa_kev": False,
                "exploit_available": True,
                "patch_available": True,
                "recommended_mitigation": "Upgrade nginx to >= 1.16.1; limit HTTP/2 stream count."
            }
        }
        self.vulnerabilities.update(vulns_seed)

        # 5. CISA KEV Items
        self.kev_catalog = [
            {
                "cve_id": "CVE-2020-0796",
                "vendor_project": "Microsoft",
                "product": "Windows & Windows Server",
                "vulnerability_name": "Microsoft Windows SMBv3 Remote Code Execution Vulnerability",
                "date_added": "2021-11-03",
                "short_description": "A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests.",
                "required_action": "Apply updates per vendor instructions.",
                "due_date": "2022-05-03",
                "known_ransomware_campaign_use": "Known"
            },
            {
                "cve_id": "CVE-2021-44228",
                "vendor_project": "Apache",
                "product": "Log4j",
                "vulnerability_name": "Apache Log4j2 JNDI Remote Code Execution Vulnerability",
                "date_added": "2021-12-10",
                "short_description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                "required_action": "Apply updates per vendor instructions.",
                "due_date": "2021-12-24",
                "known_ransomware_campaign_use": "Known"
            }
        ]

        # 6. IP Blocklist
        self.ip_blocklist = [
            {"ip_address": "198.51.100.42", "category": "c2", "source_feed": "CISA KEV / AlienVault OTX", "confidence": 0.95, "added_at": now},
            {"ip_address": "203.0.113.88", "category": "tor_exit", "source_feed": "TorProject Directory", "confidence": 0.99, "added_at": now},
            {"ip_address": "185.220.101.5", "category": "scanner", "source_feed": "Shadowserver Industrial Scanner Feed", "confidence": 0.90, "added_at": now}
        ]

        # 7. JA3 Fingerprints
        self.ja3_signatures = {
            "6734f37431670b3ab4292b8f60f29984": {
                "matched_threat": True,
                "threat_name": "Cobalt Strike HTTPS Beacon",
                "malware_family": "CobaltStrike",
                "confidence": 0.98,
                "first_seen_in_network": False,
                "is_whitelisted": False
            },
            "b32309a26951912be7dba376398abc3b": {
                "matched_threat": False,
                "threat_name": None,
                "malware_family": None,
                "confidence": 0.0,
                "first_seen_in_network": True,
                "is_whitelisted": True
            }
        }

        # 8. Model Registry Seed
        self.active_models = {
            "model-rf-001": {
                "model_id": "model-rf-001",
                "model_name": "VaultX Random Forest Multi-Class Classifier",
                "model_version": "v1.2.0",
                "model_type": "classification",
                "training_dataset": "becpl_synthetic_traffic_50k.csv",
                "training_date": "2026-11-18",
                "is_active": True,
                "macro_f1": 0.962,
                "false_positive_rate": 0.014,
                "inference_latency_ms": 1.25,
                "deployed_at": now
            },
            "model-if-001": {
                "model_id": "model-if-001",
                "model_name": "VaultX Isolation Forest Anomaly Detector",
                "model_version": "v1.0.1",
                "model_type": "anomaly_detection",
                "training_dataset": "becpl_synthetic_traffic_50k.csv (Benign Baseline)",
                "training_date": "2026-11-18",
                "is_active": True,
                "macro_f1": 0.915,
                "false_positive_rate": 0.028,
                "inference_latency_ms": 0.85,
                "deployed_at": now
            }
        }

        # 9. Identities Seed
        identities_seed = [
            {"identity_id": "id-001", "principal_name": "rahul.sharma", "principal_type": PrincipalType.HUMAN_USER, "department": "Firmware Engineering", "assigned_assets": ["ENG-WS-001"], "risk_score": 15.0, "mfa_enforced": True, "is_active": True},
            {"identity_id": "id-002", "principal_name": "svc_backup", "principal_type": PrincipalType.SERVICE_ACCOUNT, "department": "IT Operations", "assigned_assets": ["CORP-BACKUP-01", "CORP-ERP-DB"], "risk_score": 68.0, "mfa_enforced": False, "is_active": True},
            {"identity_id": "id-003", "principal_name": "bot_erp_sync", "principal_type": PrincipalType.AUTOMATION_WORKLOAD, "department": "Supply Chain", "assigned_assets": ["CORP-ERP-01"], "risk_score": 10.0, "mfa_enforced": False, "is_active": True},
            {"identity_id": "id-004", "principal_name": "ai_defect_inspector", "principal_type": PrincipalType.AI_AGENT, "department": "Quality Assurance", "assigned_assets": ["ENG-WS-002", "MES-SERVER"], "risk_score": 25.0, "mfa_enforced": True, "is_active": True},
            {"identity_id": "id-005", "principal_name": "openplc_smt_line1", "principal_type": PrincipalType.INDUSTRIAL_DEVICE, "department": "Manufacturing", "assigned_assets": ["OT-PLC-001"], "risk_score": 45.0, "mfa_enforced": False, "is_active": True},
            {"identity_id": "id-006", "principal_name": "vendor_schneider", "principal_type": PrincipalType.THIRD_PARTY_IDENTITY, "department": "Contractor Maintenance", "assigned_assets": ["DMZ-VPN-GW"], "risk_score": 78.0, "mfa_enforced": True, "is_active": True},
            {"identity_id": "id-007", "principal_name": "unknown_dhcp_device", "principal_type": PrincipalType.UNKNOWN_IDENTITY, "department": "Unassigned", "assigned_assets": [], "risk_score": 85.0, "mfa_enforced": False, "is_active": True},
        ]
        for item in identities_seed:
            self.identities[item["identity_id"]] = item


# Global Singleton Mock DataStore
mock_store = MockDataStore()


# ---------------------------------------------------------------------------
# Auth Dependency Functions
# ---------------------------------------------------------------------------

async def get_current_user(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    auth_header: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme)
) -> UserProfile:
    """
    Validates API Key or Bearer Token and resolves authenticated UserProfile.
    In testing/simulation mode without credentials, defaults to ADMIN.
    """
    token_candidate: Optional[str] = None
    
    if x_api_key:
        token_candidate = x_api_key.strip()
    elif auth_header and auth_header.credentials:
        token_candidate = auth_header.credentials.strip()

    if token_candidate:
        user_meta = TOKEN_ROLE_MAP.get(token_candidate)
        if user_meta:
            return UserProfile(
                username=user_meta["username"],
                role=user_meta["role"],
                department=user_meta["department"],
                full_name=user_meta.get("full_name")
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid API Key or Bearer token: '{token_candidate}'"
            )

    # If in simulation/dev mode and no token provided, return default OPERATOR
    if SIMULATION_MODE:
        return UserProfile(
            username="dev_operator",
            role=UserRole.OPERATOR,
            department="SOC Operations (Simulation Mode)",
            full_name="Simulation Operator"
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing authentication credentials. Provide X-API-Key or Bearer token."
    )


def require_roles(*allowed_roles: UserRole):
    """
    Role-Based Access Control (RBAC) dependency factory.
    Admins are always authorized.
    """
    async def role_checker(current_user: UserProfile = Depends(get_current_user)) -> UserProfile:
        if current_user.role == UserRole.ADMIN:
            return current_user
        if current_user.role in allowed_roles:
            return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access forbidden: User '{current_user.username}' with role '{current_user.role.value}' does not have required permissions ({[r.value for r in allowed_roles]})."
        )
    return role_checker


# ---------------------------------------------------------------------------
# Database & Redis Connection Dependencies
# ---------------------------------------------------------------------------

async def get_db_pool(request: Request) -> Any:
    """
    Returns PostgreSQL asyncpg pool if connected, or mock store fallback.
    """
    if hasattr(request.app.state, "db_pool") and request.app.state.db_pool is not None:
        return request.app.state.db_pool
    return mock_store


async def get_redis_client(request: Request) -> Any:
    """
    Returns Redis connection client if connected, or mock store fallback.
    """
    if hasattr(request.app.state, "redis_client") and request.app.state.redis_client is not None:
        return request.app.state.redis_client
    return mock_store
