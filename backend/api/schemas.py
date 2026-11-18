"""
backend/api/schemas.py — Pydantic Data Models & Request/Response Schemas
VaultX Hybrid NIDS for BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class UserRole(str, Enum):
    ANALYST = "ANALYST"
    OPERATOR = "OPERATOR"
    APPROVER = "APPROVER"
    SECURITY_MANAGER = "SECURITY_MANAGER"
    ADMIN = "ADMIN"


class PrincipalType(str, Enum):
    HUMAN_USER = "HUMAN_USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    AUTOMATION_WORKLOAD = "AUTOMATION_WORKLOAD"
    AI_AGENT = "AI_AGENT"
    INDUSTRIAL_DEVICE = "INDUSTRIAL_DEVICE"
    THIRD_PARTY_IDENTITY = "THIRD_PARTY_IDENTITY"
    UNKNOWN_IDENTITY = "UNKNOWN_IDENTITY"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class ContainmentMode(str, Enum):
    MODE_1_MONITOR_ONLY = "MODE_1_MONITOR_ONLY"
    MODE_2_AUTO_ISOLATE_NON_OT = "MODE_2_AUTO_ISOLATE_NON_OT"
    MODE_3_HUMAN_APPROVAL_REQUIRED = "MODE_3_HUMAN_APPROVAL_REQUIRED"
    MODE_4_STRICT_ZERO_TRUST = "MODE_4_STRICT_ZERO_TRUST"


class ActionType(str, Enum):
    ISOLATE = "isolate"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    PATCH = "patch"
    RESTORE = "restore"
    QUARANTINE = "quarantine"
    FIREWALL_RULE = "firewall_rule"
    ACL_UPDATE = "acl_update"
    PASSWORD_RESET = "password_reset"
    SESSION_REVOKE = "session_revoke"
    SERVICE_STOP = "service_stop"
    EVIDENCE_COLLECT = "evidence_collect"
    ESCALATE = "escalate"
    NOTIFY = "notify"


class ActionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class NetworkZoneName(str, Enum):
    CORPORATE = "Corporate IT"
    ENGINEERING = "Engineering & Firmware"
    OT = "Manufacturing OT"
    WAREHOUSE = "Warehouse & Logistics"
    DMZ = "DMZ & Vendor Access"
    CLOUD = "Cloud & External Integrations"
    SECURITY = "Security Management"


# ---------------------------------------------------------------------------
# Auth & User Schemas
# ---------------------------------------------------------------------------

class UserProfile(BaseModel):
    username: str
    role: UserRole
    department: str
    is_active: bool = True
    full_name: Optional[str] = None
    email: Optional[str] = None


# ---------------------------------------------------------------------------
# Health & Status Schemas
# ---------------------------------------------------------------------------

class DatabaseStatus(BaseModel):
    connected: bool
    latency_ms: float
    pool_size: int
    active_connections: int
    pending_migrations: int = 0
    version: str = "PostgreSQL 15.4"


class RedisStatus(BaseModel):
    connected: bool
    latency_ms: float
    used_memory_human: str = "12.4M"
    connected_clients: int = 4
    total_streams: int = 6


class SensorHealth(BaseModel):
    sensor_id: str
    hostname: str
    vlan_id: int
    zone_name: str
    sensor_type: str  # zeek, suricata, sysmon
    status: str  # online, degraded, offline
    events_per_sec: float
    drop_rate_pct: float
    last_heartbeat: datetime


class QueueDepth(BaseModel):
    stream_name: str
    queue_length: int
    consumer_groups: int
    unacknowledged_events: int
    stream_lag_ms: float


class PipelineMetrics(BaseModel):
    events_ingested_total: int
    events_per_second: float
    dedup_ratio: float
    normalization_latency_ms: float
    enrichment_latency_ms: float
    active_backpressure: bool
    backpressure_threshold: int = 5000


class SystemHealthResponse(BaseModel):
    status: str  # healthy, degraded, unhealthy
    timestamp: datetime
    uptime_seconds: float
    database: DatabaseStatus
    redis: RedisStatus
    pipeline: PipelineMetrics
    sensors_online: int
    sensors_total: int
    system_version: str = "VaultX Phase 2 v2.0.0"


# ---------------------------------------------------------------------------
# Incident Schemas
# ---------------------------------------------------------------------------

class IncidentTimelineItem(BaseModel):
    timestamp: datetime
    actor: str
    action: str
    notes: Optional[str] = None


class BlastRadiusNode(BaseModel):
    id: str  # asset_id or ip
    label: str
    type: str  # workstation, server, plc, hmi, cloud, vendor
    vlan_id: int
    zone_name: str
    criticality: str
    compromised: bool
    risk_score: float


class BlastRadiusEdge(BaseModel):
    source: str
    target: str
    protocol: str
    port: Optional[int] = None
    traffic_direction: str = "bidirectional"
    observed_bytes: int = 0
    suspicious: bool = False


class BlastRadiusGraph(BaseModel):
    incident_id: str
    root_cause_asset: str
    total_nodes_at_risk: int
    ot_boundary_threatened: bool
    critical_assets_exposed: List[str]
    nodes: List[BlastRadiusNode]
    edges: List[BlastRadiusEdge]


class AIInvestigationSummary(BaseModel):
    incident_id: str
    narrative: str
    attack_vector: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    confidence_score: float
    root_cause_hypothesis: str
    recommended_containment_actions: List[str]
    potential_business_impact: str
    ot_safety_evaluation: str
    generated_at: datetime


class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: SeverityLevel
    attack_scenario: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    affected_assets: List[str] = Field(default_factory=list)
    affected_zones: List[str] = Field(default_factory=list)
    ioc_list: Dict[str, Any] = Field(default_factory=dict)


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdateStatus(BaseModel):
    status: IncidentStatus
    notes: Optional[str] = None
    false_positive_reason: Optional[str] = None


class IncidentResponse(IncidentBase):
    incident_id: str
    incident_reference: str
    status: IncidentStatus
    detected_at: datetime
    contained_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    timeline: List[IncidentTimelineItem] = Field(default_factory=list)
    investigation_summary: Optional[AIInvestigationSummary] = None
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Containment Schemas
# ---------------------------------------------------------------------------

class ContainmentModesResponse(BaseModel):
    active_mode: ContainmentMode
    ot_safety_interlock_active: bool = True
    modes_available: Dict[str, str]
    two_person_rule_for_ot: bool = True
    max_isolation_duration_hours: int = 24


class ProposeActionRequest(BaseModel):
    incident_id: str
    action_type: ActionType
    target_asset_id: Optional[str] = None
    target_ip: Optional[str] = None
    target_identity_id: Optional[str] = None
    justification: str
    isolation_method: Optional[str] = "firewall_block"
    quarantine_vlan: Optional[int] = 70


class ApproveActionRequest(BaseModel):
    mfa_code: str = Field(..., description="6-digit TOTP / MFA verification code")
    approval_notes: Optional[str] = None
    second_approver_username: Optional[str] = Field(
        None, description="Required for OT assets under two-person rule"
    )
    break_glass: bool = False
    break_glass_reason: Optional[str] = None


class ExecuteActionRequest(BaseModel):
    force_immediate: bool = False


class RollbackActionRequest(BaseModel):
    rollback_reason: str


class ResponseActionResponse(BaseModel):
    action_id: str
    incident_id: str
    action_type: ActionType
    target_asset_id: Optional[str] = None
    target_ip: Optional[str] = None
    target_identity_id: Optional[str] = None
    initiated_by: str
    approved_by: Optional[str] = None
    second_approver: Optional[str] = None
    status: ActionStatus
    is_ot_asset: bool
    approval_method: Optional[str] = None
    approval_timestamp: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    rollback_at: Optional[datetime] = None
    rollback_reason: Optional[str] = None
    execution_detail: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class FirewallRuleResponse(BaseModel):
    rule_id: str
    source_ip: str
    destination_ip: str
    protocol: str
    port: Optional[str] = "ANY"
    action: str  # DROP, REJECT, ALLOW
    active: bool
    incident_id: Optional[str] = None
    created_by: str
    created_at: datetime
    expires_at: Optional[datetime] = None


class FirewallRuleCreate(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str = "TCP"
    port: Optional[str] = "ANY"
    action: str = "DROP"
    justification: str
    incident_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Threat Intel Schemas
# ---------------------------------------------------------------------------

class VulnerabilityRecord(BaseModel):
    cve_id: str
    cvss_score: float
    severity: SeverityLevel
    description: str
    affected_assets: List[str]
    in_cisa_kev: bool
    exploit_available: bool
    patch_available: bool
    recommended_mitigation: str


class KEVRecord(BaseModel):
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_campaign_use: str


class AssetExposureResponse(BaseModel):
    asset_id: str
    hostname: str
    ip_address: str
    vlan_id: int
    zone_name: str
    criticality: str
    exposure_rating: str  # critical, high, medium, low
    vulnerabilities: List[VulnerabilityRecord]
    open_ports: List[int]
    active_threat_indicators: int


class BlocklistEntry(BaseModel):
    ip_address: str
    category: str  # c2, tor, scanner, brute_force
    source_feed: str
    confidence: float
    added_at: datetime


class JA3CheckRequest(BaseModel):
    ja3_hash: str
    ja3s_hash: Optional[str] = None
    sni: Optional[str] = None
    asset_id: Optional[str] = None


class JA3CheckResponse(BaseModel):
    ja3_hash: str
    matched_threat: bool
    threat_name: Optional[str] = None
    malware_family: Optional[str] = None
    confidence: float
    first_seen_in_network: bool
    is_whitelisted: bool


# ---------------------------------------------------------------------------
# Identity Schemas
# ---------------------------------------------------------------------------

class IdentityRecord(BaseModel):
    identity_id: str
    principal_name: str
    principal_type: PrincipalType
    department: Optional[str] = None
    assigned_assets: List[str] = Field(default_factory=list)
    risk_score: float
    mfa_enforced: bool
    is_active: bool
    last_authenticated: Optional[datetime] = None


class ActiveSessionResponse(BaseModel):
    session_id: str
    principal_name: str
    principal_type: PrincipalType
    source_ip: str
    target_resource: str
    auth_method: str
    session_start: datetime
    last_activity: datetime
    duration_minutes: int
    is_anomalous: bool
    anomaly_reasons: List[str] = Field(default_factory=list)


class IdentityProfileResponse(BaseModel):
    identity: IdentityRecord
    active_sessions: List[ActiveSessionResponse]
    normal_working_hours: str
    authorized_zones: List[str]
    recent_anomalies: List[Dict[str, Any]] = Field(default_factory=list)


class AgentTelemetryResponse(BaseModel):
    agent_id: str
    agent_name: str
    classification: PrincipalType
    model_or_runtime: str
    authorized_endpoints: List[str]
    current_calls_per_minute: float
    baseline_calls_per_minute: float
    last_invoked_tool: Optional[str] = None
    compliance_status: str  # compliant, anomaly_detected, out_of_bounds
    notes: str


class VendorComplianceResponse(BaseModel):
    vendor_id: str
    vendor_name: str
    active_sessions_count: int
    max_session_hours_allowed: int = 4
    exceeded_duration_sessions: List[str] = Field(default_factory=list)
    unauthorized_zone_attempts: int = 0
    mfa_compliance_pct: float
    overall_compliance_status: str  # compliant, review_required, policy_violation


# ---------------------------------------------------------------------------
# Risk Schemas
# ---------------------------------------------------------------------------

class ZoneRiskScore(BaseModel):
    vlan_id: int
    zone_name: str
    risk_score: float  # 0.0 - 100.0
    threat_level: str  # LOW, MODERATE, HIGH, CRITICAL
    active_incidents_count: int
    vulnerable_assets_count: int
    unauthorized_cross_vlan_attempts: int
    last_assessment_time: datetime


class AssetCriticalityEntry(BaseModel):
    asset_id: str
    hostname: str
    vlan_id: int
    zone_name: str
    device_type: str
    criticality: str  # critical, high, medium, low
    business_impact: str
    safety_impact_if_compromised: str


class OperationalRecommendation(BaseModel):
    priority: int
    category: str
    recommendation: str
    target_zone: str
    rationale: str
    estimated_remediation_effort: str


class OTSafetyStatus(BaseModel):
    interlocks_engaged: bool
    active_ot_isolation_actions: int
    production_line_safety_clearance: bool
    modbus_watchdog_active: bool
    safety_override_requires_2_approvers: bool = True
    last_safety_audit: datetime


# ---------------------------------------------------------------------------
# Model Registry Schemas
# ---------------------------------------------------------------------------

class ModelMetadataResponse(BaseModel):
    model_id: str
    model_name: str
    model_version: str
    model_type: str
    training_dataset: str
    training_date: str
    is_active: bool
    macro_f1: float
    false_positive_rate: float
    inference_latency_ms: float
    deployed_at: Optional[datetime] = None


class ModelEvaluationReportResponse(BaseModel):
    model_id: str
    model_name: str
    model_version: str
    training_date: str
    train_samples: int
    test_samples: int
    accuracy: float
    macro_f1: float
    weighted_f1: float
    false_positive_rate: float
    inference_time_ms_per_1000_samples: float
    per_class_metrics: Dict[str, Dict[str, float]]
    top_shap_features: List[str]
    limitations: List[str]


class PromoteModelRequest(BaseModel):
    manager_approval_notes: str
    confirm_test_evaluation: bool = True


class RetrainModelRequest(BaseModel):
    dataset_name: Optional[str] = "becpl_synthetic_traffic_50k.csv"
    epochs_or_estimators: Optional[int] = 200
    include_analyst_feedback: bool = True


class RetrainModelResponse(BaseModel):
    job_id: str
    status: str  # queued, training, completed, failed
    model_candidate_version: str
    started_at: datetime
    message: str


# ---------------------------------------------------------------------------
# Ingestion & Detection Schemas
# ---------------------------------------------------------------------------

class IngestionStatusResponse(BaseModel):
    is_running: bool
    active_streams: List[str]
    events_ingested_total: int
    batch_size: int
    backpressure_active: bool
    last_checkpoint_timestamp: datetime


class StreamLagEntry(BaseModel):
    stream_name: str
    consumer_group: str
    last_delivered_id: str
    lag_count: int
    oldest_unprocessed_age_sec: float


class IngestionControlRequest(BaseModel):
    action: str  # pause, resume, reset_checkpoints, flush_buffer


class InferenceRequest(BaseModel):
    flow_features: Dict[str, Any]
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None


class InferenceResponse(BaseModel):
    predicted_label: str
    is_attack: bool
    confidence_score: float
    model_version: str
    top_contributing_features: List[str]
    anomaly_score: float
    uncertain_flag: bool


class FeatureVectorTestRequest(BaseModel):
    vectors: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Behavioural Schemas
# ---------------------------------------------------------------------------

class BaselineProfile(BaseModel):
    asset_id: str
    normal_destinations: List[str]
    normal_ports: List[int]
    normal_protocols: List[str]
    bytes_per_hour_mean: float
    bytes_per_hour_std: float
    connections_per_hour_mean: float
    normal_hours: List[int]
    normal_peers: List[str]
    computed_at: datetime


class DeviationQueryRequest(BaseModel):
    asset_id: str
    destination_ip: str
    destination_port: int
    protocol: str
    bytes_transferred: int
    hour_of_day: int


class DeviationQueryResponse(BaseModel):
    asset_id: str
    combined_deviation_score: float
    is_anomalous: bool
    signals_triggered: List[str]
    severity: SeverityLevel
    suppressed_by_maintenance_window: bool


class MaintenanceWindowCreate(BaseModel):
    start_time: datetime
    end_time: datetime
    target_assets: List[str]
    description: str
    approver: str


class MaintenanceWindowResponse(BaseModel):
    window_id: str
    start_time: datetime
    end_time: datetime
    target_assets: List[str]
    description: str
    approver: str
    is_active: bool
