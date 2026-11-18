// VaultX Phase 3 — TypeScript Domain Models matching backend/api/schemas.py

export type UserRole =
  | 'ANALYST'
  | 'OPERATOR'
  | 'APPROVER'
  | 'SECURITY_MANAGER'
  | 'ADMIN';

export type PrincipalType =
  | 'HUMAN_USER'
  | 'SERVICE_ACCOUNT'
  | 'AUTOMATION_WORKLOAD'
  | 'AI_AGENT'
  | 'INDUSTRIAL_DEVICE'
  | 'THIRD_PARTY_IDENTITY'
  | 'UNKNOWN_IDENTITY';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export type IncidentStatus =
  | 'open'
  | 'investigating'
  | 'contained'
  | 'resolved'
  | 'closed'
  | 'false_positive';

export type ContainmentMode =
  | 'MODE_1_DISABLED'
  | 'MODE_2_MONITOR_ONLY'
  | 'MODE_3_HUMAN_APPROVAL_REQUIRED'
  | 'MODE_4_PREAPPROVED_AUTOMATION';

export type ActionType =
  | 'isolate'
  | 'block_ip'
  | 'disable_account'
  | 'patch'
  | 'restore'
  | 'quarantine'
  | 'firewall_rule'
  | 'acl_update'
  | 'password_reset'
  | 'session_revoke'
  | 'service_stop'
  | 'evidence_collect'
  | 'escalate'
  | 'notify';

export type ActionStatus =
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'executing'
  | 'completed'
  | 'failed'
  | 'rolled_back';

export type ZoneHealthStatus = 'healthy' | 'warning' | 'elevated' | 'critical' | 'offline';

export interface UserProfile {
  username: string;
  role: UserRole;
  department: string;
  is_active: boolean;
  full_name: string;
  email: string;
  api_key?: string;
}

// Command Centre Overview
export interface CommandCentreOverview {
  networkStatus: 'PROTECTED' | 'ELEVATED' | 'UNDER_ATTACK';
  healthScore: number;
  activeIncidents: number;
  criticalCves: number;
  sensorsActive: number;
  sensorsTotal: number;
  ingestionLagMs: number;
  activeFlows: number;
  throughputGbps: number;
  encryptedTrafficPct: number;
  internalTrafficPct: number;
  externalTrafficPct: number;
  trafficByOrigin: {
    human: number;
    automated: number;
    aiAgent: number;
    industrial: number;
  };
  threatSummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unresolved: number;
    resolved: number;
  };
}

export interface SystemAnalysisEntry {
  id: string;
  timestamp: string;
  zone: string;
  severity: SeverityLevel;
  summary: string;
  evidenceRef: string;
  confidence: number;
}

// Infrastructure 7-VLAN Topology
export interface ModbusRegister {
  address: string;
  name: string;
  value: string;
  unit: string;
  baseline: string;
  status: 'normal' | 'warning' | 'tampered';
}

export interface VlanAssetNode {
  asset_id: string;
  hostname: string;
  ip_address: string;
  device_type: string;
  criticality: 'critical' | 'high' | 'medium' | 'low';
  status: ZoneHealthStatus;
  os_or_firmware: string;
  active_alerts: number;
}

export interface VlanZoneDetail {
  vlan_id: number;
  name: string;
  shortName: string;
  subnet: string;
  gateway: string;
  status: ZoneHealthStatus;
  risk_score: number;
  active_incidents: number;
  asset_count: number;
  throughput_mbps: number;
  sensor_id: string;
  isolation_enabled: boolean;
  description: string;
  assets: VlanAssetNode[];
  telemetry: {
    label: string;
    value: string;
    status?: 'ok' | 'warn' | 'crit' | 'info';
  }[];
  modbusRegisters?: ModbusRegister[];
  firmwareIntegrity?: {
    repo: string;
    branch: string;
    artifact: string;
    sha256: string;
    verified: boolean;
    lastPush: string;
  }[];
  blockedCrossVlanCount: number;
}

// Network Monitoring
export interface NetworkFlow {
  flow_id: string;
  timestamp: string;
  source_ip: string;
  source_asset: string;
  source_zone: string;
  dest_ip: string;
  dest_asset: string;
  dest_zone: string;
  protocol: string;
  port: number;
  direction: 'Inbound' | 'Outbound' | 'Lateral';
  identity: string;
  identity_type: PrincipalType;
  bytes_sent: number;
  bytes_recv: number;
  pps: number;
  encrypted: boolean;
  tls_version?: string;
  ja3_hash?: string;
  detection_status: 'clean' | 'suspicious' | 'malicious' | 'blocked';
  rule_match?: string;
}

// Threat Intelligence
export interface KEVRecord {
  cve_id: string;
  vendor_project: string;
  product: string;
  vulnerability_name: string;
  date_added: string;
  short_description: string;
  required_action: string;
  due_date: string;
  known_ransomware_campaign_use: string;
  affected_becpl_assets: string[];
}

export interface BlocklistEntry {
  ip_address: string;
  category: 'c2' | 'tor' | 'scanner' | 'brute_force' | 'exfil_vps';
  source_feed: string;
  confidence: number;
  hits_24h: number;
  asn: string;
  country: string;
  added_at: string;
}

export interface JA3Fingerprint {
  ja3_hash: string;
  threat_name: string;
  malware_family: string;
  confidence: number;
  matched_flows: number;
  last_seen: string;
  status: 'blocked' | 'alerting' | 'monitoring';
}

export type ExploitationStage =
  | 'EXPOSED'
  | 'ATTACK_ATTEMPT'
  | 'POTENTIAL_EXPLOITATION'
  | 'CONFIRMED_COMPROMISE';

export interface ExploitationLadderItem {
  id: string;
  cve_id: string;
  asset_id: string;
  zone: string;
  stage: ExploitationStage;
  evidence: string;
  updated_at: string;
  incident_ref?: string;
}

// Third-Party Trust / Supply Chain
export interface VendorRecord {
  vendor_id: string;
  vendor_name: string;
  service_scope: string;
  trust_tier: 'Critical OT' | 'Firmware R&D' | 'Network Ops' | 'Logistics API' | 'Cloud Infra';
  allowed_zones: string[];
  active_sessions_count: number;
  max_session_hours: number;
  mfa_compliance_pct: number;
  unauthorized_zone_attempts: number;
  risk_score: number;
  compliance_status: 'compliant' | 'review_required' | 'policy_violation';
  last_audit: string;
}

export interface VendorSession {
  session_id: string;
  vendor_name: string;
  principal_name: string;
  source_ip: string;
  source_geo: string;
  entry_node: string;
  target_resource: string;
  started_at: string;
  remaining_seconds: number;
  max_seconds: number;
  mfa_verified: boolean;
  is_anomalous: boolean;
  anomaly_reasons: string[];
}

// Vulnerability Management
export interface VulnerabilityRecord {
  cve_id: string;
  title: string;
  cvss_score: number;
  severity: SeverityLevel;
  software: string;
  version: string;
  description: string;
  affected_assets: {
    asset_id: string;
    hostname: string;
    ip: string;
    zone: string;
    criticality: 'critical' | 'high' | 'medium' | 'low';
    exposure: 'internet_dmz' | 'cross_vlan' | 'internal_only' | 'ot_isolated';
    priority_risk_score: number;
  }[];
  in_cisa_kev: boolean;
  exploit_available: boolean;
  patch_available: boolean;
  is_test_target?: boolean;
  recommended_mitigation: string;
}

// Incident Investigation
export interface IncidentTimelineItem {
  timestamp: string;
  actor: string;
  action: string;
  notes?: string;
  stage?: string;
}

export interface BlastRadiusNode {
  id: string;
  label: string;
  type: string;
  vlan_id: number;
  zone_name: string;
  criticality: 'critical' | 'high' | 'medium' | 'low';
  hop_level: 0 | 1 | 2;
  compromised: boolean;
  risk_score: number;
}

export interface BlastRadiusEdge {
  source: string;
  target: string;
  protocol: string;
  port?: number;
  suspicious: boolean;
  bytes_label: string;
}

export interface AIInvestigationSummary {
  incident_id: string;
  narrative: string;
  attack_vector: string;
  mitre_tactics: string[];
  mitre_techniques: string[];
  confidence_score: number;
  root_cause_hypothesis: string;
  recommended_containment_actions: string[];
  potential_business_impact: string;
  ot_safety_evaluation: string;
  generated_at: string;
}

export interface IncidentEvidenceLog {
  id: string;
  timestamp: string;
  sensor: string;
  protocol: string;
  src: string;
  dst: string;
  signature: string;
  severity: SeverityLevel;
  raw: string;
}

export interface IncidentRecord {
  incident_id: string;
  incident_reference: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  status: IncidentStatus;
  attack_scenario: string;
  mitre_tactic: string;
  mitre_technique: string;
  affected_assets: string[];
  affected_zones: string[];
  detected_at: string;
  assigned_to: string;
  ot_safety_flag: boolean;
  timeline: IncidentTimelineItem[];
  blast_radius: {
    root_cause_asset: string;
    total_nodes_at_risk: number;
    ot_boundary_threatened: boolean;
    nodes: BlastRadiusNode[];
    edges: BlastRadiusEdge[];
  };
  evidence_logs: IncidentEvidenceLog[];
  investigation_summary: AIInvestigationSummary;
}

// Containment & Active Defence
export interface ContainmentAction {
  action_id: string;
  incident_id: string;
  incident_reference: string;
  action_type: ActionType;
  target_asset_id: string;
  target_ip: string;
  target_zone: string;
  reason: string;
  operational_impact: string;
  required_role: UserRole;
  initiated_by: string;
  approved_by?: string;
  second_approver?: string;
  status: ActionStatus;
  is_ot_asset: boolean;
  approval_method?: string;
  created_at: string;
  executed_at?: string;
  rollback_at?: string;
  rollback_reason?: string;
}

export interface FirewallRule {
  rule_id: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  port: string;
  action: 'DROP' | 'REJECT' | 'QUARANTINE' | 'RATE_LIMIT';
  zone: string;
  active: boolean;
  incident_id: string;
  created_by: string;
  created_at: string;
  expires_at: string;
}

// Security History & Audit
export interface SecurityEventLog {
  event_id: string;
  timestamp: string;
  zone: string;
  asset_id: string;
  identity: string;
  event_type: string;
  severity: SeverityLevel;
  message: string;
  source_engine: 'Zeek' | 'Suricata' | 'ML-RF' | 'Behavioural' | 'Containment' | 'IAM';
}

export interface AuditLogEntry {
  seq: number;
  audit_id: string;
  timestamp: string;
  actor: string;
  role: UserRole;
  action: string;
  target: string;
  outcome: 'SUCCESS' | 'DENIED' | 'OVERRIDE';
  prev_hash: string;
  entry_hash: string;
}

// Model Intelligence
export interface ModelMetadata {
  model_id: string;
  model_name: string;
  model_version: string;
  model_type: string;
  role: 'Classifier' | 'Anomaly Detector' | 'Preprocessor' | 'Explainability' | 'Candidate';
  training_dataset: string;
  training_date: string;
  status: 'deployed' | 'candidate' | 'archived';
  macro_f1: number;
  accuracy: number;
  false_positive_rate: number;
  inference_latency_ms: number;
  drift_score: number;
  samples_evaluated: number;
}

export interface ShapFeatureImportance {
  feature: string;
  importance: number;
  direction: 'attack' | 'benign';
  description: string;
}

// System Health
export interface SensorHealth {
  sensor_id: string;
  hostname: string;
  vlan_id: number;
  zone_name: string;
  engines: string[];
  status: 'online' | 'degraded' | 'offline';
  events_per_sec: number;
  drop_rate_pct: number;
  cpu_pct: number;
  memory_pct: number;
  zeek_status: 'active' | 'warning' | 'down';
  suricata_status: 'active' | 'warning' | 'down';
  last_heartbeat: string;
}

export interface QueueDepthMetric {
  stream_name: string;
  queue_length: number;
  consumer_groups: number;
  unacknowledged: number;
  lag_ms: number;
}

// Administration & Policies
export interface MaintenanceWindow {
  window_id: string;
  title: string;
  start_time: string;
  end_time: string;
  target_zones: string[];
  target_assets: string[];
  approver: string;
  suppress_alerts: boolean;
  status: 'active' | 'scheduled' | 'completed';
}

export interface DataRetentionRule {
  id: string;
  data_class: string;
  hot_days: number;
  warm_days: number;
  cold_archive_days: number;
  compliance_tag: string;
  encryption: string;
}

// Multi-Agent Operational Demo
export interface ValidationScenario {
  scenario_id: string;
  name: string;
  category: 'Supply Chain' | 'Identity' | 'Lateral Movement' | 'LotL' | 'Exfiltration' | 'OT / ICS' | 'Recon' | 'AI Agent' | 'Firmware' | 'Stress Test';
  severity: SeverityLevel;
  target_zone: string;
  source_asset: string;
  target_asset: string;
  ot_safety_lock: boolean;
  expected_eps: number;
  mitre: string[];
  description: string;
  agent_steps: {
    agent: 'sensors' | 'normalizer' | 'detection' | 'correlation' | 'containment' | 'coordinator';
    action: string;
    detail: string;
    latency_ms: number;
  }[];
}
