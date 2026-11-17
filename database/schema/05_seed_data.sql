-- VaultX NIDS - Seed Data for BECPL (Bharat Electronics Components Pvt. Ltd., Pune)
-- Schema: becpl_nids

SET search_path TO becpl_nids;

-- ===========================================================================
-- 1. Network Zones (7 VLANs as per Network Architecture)
-- ===========================================================================
INSERT INTO network_zones (
  zone_name, vlan_id, cidr_range, gateway_ip, dns_server,
  dhcp_range_start, dhcp_range_end, zone_type, criticality, description, inter_vlan_allow
) VALUES
  ('Corporate IT', 10, '10.10.10.0/24', '10.10.10.1', '10.10.70.5',
   '10.10.10.100', '10.10.10.250', 'corporate', 'medium',
   'Workstations for HR, Finance, Executive, Sales, and ERP desktop clients',
   ARRAY['50', '60', '70']),

  ('Engineering & Firmware', 20, '10.10.20.0/24', '10.10.20.1', '10.10.70.5',
   '10.10.20.100', '10.10.20.200', 'engineering', 'high',
   'PCB design workstations, Git servers, firmware flashing rigs, build servers',
   ARRAY['30', '50', '60', '70']),

  ('Manufacturing OT', 30, '10.10.30.0/24', '10.10.30.1', '10.10.70.5',
   NULL, NULL, 'ot', 'critical',
   'Pick-and-place SMT machines, reflow ovens, AOI visual inspection, PLCs, HMIs',
   ARRAY['20', '70']),

  ('Warehouse & Logistics', 40, '10.10.40.0/24', '10.10.40.1', '10.10.70.5',
   '10.10.40.100', '10.10.40.200', 'warehouse', 'medium',
   'Barcode scanners, inventory terminal PCs, dispatch printers, automated scales',
   ARRAY['10', '50', '70']),

  ('DMZ & Vendor Access', 50, '10.10.50.0/24', '10.10.50.1', '10.10.70.5',
   NULL, NULL, 'dmz', 'high',
   'Vendor jump host, VPN termination endpoint, reverse proxy, external relays',
   ARRAY['10', '20', '30', '70']),

  ('Cloud & External Integrations', 60, '10.10.60.0/24', '10.10.60.1', '10.10.70.5',
   NULL, NULL, 'cloud', 'high',
   'AWS India Direct Connect/IPsec gateway, logistics API connectors (DTDC/BlueDart), cloud ERP sync',
   ARRAY['10', '40', '70']),

  ('Security Management', 70, '10.10.70.0/24', '10.10.70.1', '10.10.70.5',
   NULL, NULL, 'security', 'critical',
   'VaultX NIDS sensors, PostgreSQL, Redis, SIEM collector, DNS, NTP, monitoring relays',
   ARRAY['10', '20', '30', '40', '50', '60'])
ON CONFLICT (vlan_id) DO UPDATE SET
  zone_name = EXCLUDED.zone_name,
  cidr_range = EXCLUDED.cidr_range,
  gateway_ip = EXCLUDED.gateway_ip,
  dns_server = EXCLUDED.dns_server,
  criticality = EXCLUDED.criticality,
  description = EXCLUDED.description;

-- ===========================================================================
-- 2. Vendors
-- ===========================================================================
INSERT INTO vendors (
  vendor_id, vendor_name, vendor_type, contact_email, contact_phone,
  country, approved_access_scope, allowed_vlans, mfa_required,
  max_session_duration_hours, requires_vpn, is_active, notes
) VALUES
  (1, 'Shenzhen Precision Microelectronics Co.', 'component_supplier',
   'support@sz-precisionmicro.cn', '+86-755-8839001', 'China',
   'Component datasheet portal sync and EDI purchase reconciliation',
   ARRAY[60], true, 2, true, true,
   'Raw component supplier; API only, no interactive terminal access'),

  (2, 'Yamaha SMT Machine Automation Services', 'maintenance_vendor',
   'service.in@yamaha-motor.com', '+91-20-66778800', 'India',
   'Remote diagnostic telemetry and periodic firmware updates on SMT line 1 & 2',
   ARRAY[30, 50], true, 4, true, true,
   'Requires engineering supervision before remote maintenance sessions'),

  (3, 'BlueDart Express Ltd - Pune Logistics Gateway', 'logistics',
   'edi-support@bluedart.com', '+91-20-27123456', 'India',
   'Automated shipping manifest API sync and tracking webhook integration',
   ARRAY[40, 60], true, 4, false, true,
   'B2B API authentication using rotating HMAC tokens and TLS client certs'),

  (4, 'CloudOps Pune Consultancy Services', 'cloud',
   'secops@cloudops-pune.in', '+91-20-41009988', 'India',
   'AWS India cloud migration support and backup replication monitoring',
   ARRAY[60, 70], true, 4, true, true,
   'Privileged cloud architecture consultants with quarterly review cadence'),

  (5, 'HexaCore Embedded Firmware Labs', 'dev_service',
   'contractor-sec@hexacore.io', '+91-80-49991200', 'India',
   'Contract firmware development for custom STM32/ESP32 automotive sensor modules',
   ARRAY[20, 50], true, 4, true, true,
   'Git repository access via DMZ jump host only; direct internet checkout restricted')
ON CONFLICT (vendor_id) DO UPDATE SET
  vendor_name = EXCLUDED.vendor_name,
  approved_access_scope = EXCLUDED.approved_access_scope,
  allowed_vlans = EXCLUDED.allowed_vlans;

-- ===========================================================================
-- 3. Core Assets (Representative Sample across all 7 VLANs)
-- ===========================================================================
INSERT INTO assets (
  asset_id, hostname, ip_address, mac_address, vlan_id, zone_id,
  device_type, os_name, os_version, firmware_version, primary_application,
  owner_department, criticality, identity_classification, vulnerability_exposure,
  communication_peers, last_patched, is_active, notes
) VALUES
  -- VLAN 10 (Corporate IT)
  ('CORP-DC-01', 'dc01.corp.becpl.local', '10.10.10.10', '00:50:56:A1:00:10', 10, 1,
   'server', 'Windows Server', '2022 Standard', NULL, 'Active Directory Domain Controller / DNS',
   'IT Operations', 'critical', 'SERVICE_ACCOUNT', 'low',
   ARRAY['CORP-ERP-01', 'SEC-VAULT-01'], '2026-10-15', true, 'Primary domain controller'),

  ('CORP-ERP-01', 'erp.corp.becpl.local', '10.10.10.15', '00:50:56:A1:00:15', 10, 1,
   'server', 'Ubuntu Linux', '22.04 LTS', NULL, 'PostgreSQL ERP & Inventory System',
   'Finance & Operations', 'critical', 'SERVICE_ACCOUNT', 'medium',
   ARRAY['CORP-DC-01', 'CORP-WS-101', 'WH-SRV-01'], '2026-09-30', true, 'Central business ERP'),

  ('CORP-WS-101', 'fin-ws-pune-01', '10.10.10.101', '00:50:56:A1:01:01', 10, 1,
   'workstation', 'Windows 11 Pro', '23H2', NULL, 'Accounting & SAP Business One Client',
   'Finance', 'medium', 'HUMAN_USER', 'medium',
   ARRAY['CORP-ERP-01', 'CORP-DC-01'], '2026-10-18', true, 'Finance Lead Workstation'),

  -- VLAN 20 (Engineering & Firmware)
  ('ENG-GIT-01', 'git.eng.becpl.local', '10.10.20.10', '00:50:56:A2:00:10', 20, 2,
   'server', 'Ubuntu Linux', '24.04 LTS', NULL, 'GitLab CE Firmware Repository',
   'R&D Firmware', 'critical', 'SERVICE_ACCOUNT', 'low',
   ARRAY['ENG-BUILD-01', 'ENG-WS-201'], '2026-10-25', true, 'Houses proprietary schematic & firmware'),

  ('ENG-BUILD-01', 'builder01.eng.becpl.local', '10.10.20.15', '00:50:56:A2:00:15', 20, 2,
   'server', 'Debian Linux', '12 Bookworm', NULL, 'CI/CD Yocto & ARM GCC Cross-Compiler',
   'R&D Firmware', 'high', 'AUTOMATION_WORKLOAD', 'low',
   ARRAY['ENG-GIT-01', 'OT-FLASHER-01'], '2026-10-20', true, 'Automated firmware compilation runner'),

  ('ENG-WS-201', 'pcb-cad-ws-01', '10.10.20.101', '00:50:56:A2:01:01', 20, 2,
   'workstation', 'Windows 11 Pro', '23H2', NULL, 'Altium Designer / KiCad Schematic Design',
   'Engineering', 'high', 'HUMAN_USER', 'medium',
   ARRAY['ENG-GIT-01'], '2026-10-10', true, 'Lead PCB layout engineer workstation'),

  -- VLAN 30 (Manufacturing OT)
  ('OT-SMT-PLC01', 'plc-smt-line1', '10.10.30.20', '00:0E:8C:30:00:20', 30, 3,
   'plc', 'Siemens Simatic', 'S7-1500', 'V2.9.2', 'SMT Component Placement Controller',
   'Manufacturing Plant', 'critical', 'INDUSTRIAL_DEVICE', 'high',
   ARRAY['OT-HMI-01', 'OT-SCADA-01'], '2026-03-12', true, 'Legacy industrial firmware, requires production isolation'),

  ('OT-HMI-01', 'hmi-line1-panel', '10.10.30.25', '00:0E:8C:30:00:25', 30, 3,
   'hmi', 'Windows 10 IoT Enterprise', '21H2', 'v4.1.0', 'Line 1 Production Monitoring Touchpanel',
   'Manufacturing Plant', 'critical', 'INDUSTRIAL_DEVICE', 'high',
   ARRAY['OT-SMT-PLC01', 'OT-SCADA-01'], '2026-04-10', true, 'Touchscreen HMI on factory floor'),

  ('OT-SCADA-01', 'scada-gateway.ot.becpl.local', '10.10.30.10', '00:0E:8C:30:00:10', 30, 3,
   'gateway', 'Debian Linux', '11 Bullseye', 'v2.4.1', 'Ignition SCADA OT Gateway & Historian',
   'Operations Technology', 'critical', 'SERVICE_ACCOUNT', 'medium',
   ARRAY['OT-SMT-PLC01', 'OT-HMI-01', 'ENG-BUILD-01'], '2026-08-15', true, 'Bridge between factory floor and engineering telemetry'),

  -- VLAN 40 (Warehouse & Logistics)
  ('WH-SRV-01', 'wh-manager.corp.becpl.local', '10.10.40.10', '00:50:56:A4:00:10', 40, 4,
   'server', 'Ubuntu Linux', '22.04 LTS', NULL, 'Warehouse Barcode Dispatch & Packing Dispatcher',
   'Logistics', 'high', 'SERVICE_ACCOUNT', 'low',
   ARRAY['CORP-ERP-01', 'WH-SCAN-01'], '2026-10-01', true, 'Warehouse management host'),

  ('WH-SCAN-01', 'handheld-zebra-01', '10.10.40.101', '00:23:68:40:01:01', 40, 4,
   'scanner', 'Android Enterprise', '13', 'ZBR-v4.2', 'Packaging Barcode Scanner Terminal',
   'Logistics', 'medium', 'HUMAN_USER', 'low',
   ARRAY['WH-SRV-01'], '2026-10-05', true, 'Wireless barcode gun in shipping dock'),

  -- VLAN 50 (DMZ & Vendor Access)
  ('DMZ-JUMP-01', 'bastion.dmz.becpl.local', '10.10.50.10', '00:50:56:A5:00:10', 50, 5,
   'server', 'Rocky Linux', '9.4', NULL, 'Guacamole / Teleport Vendor Access Jump Host',
   'IT Security', 'critical', 'SERVICE_ACCOUNT', 'low',
   ARRAY['OT-SCADA-01', 'ENG-GIT-01'], '2026-11-01', true, 'MFA-enforced bastion for vendor maintenance'),

  -- VLAN 60 (Cloud & External Integrations)
  ('CLOUD-GW-01', 'aws-vpn-gw.cloud.becpl.local', '10.10.60.10', '00:50:56:A6:00:10', 60, 6,
   'gateway', 'Alpine Linux', '3.19', 'IPsec-Strongswan', 'AWS Mumbai Hybrid Direct Tunnel',
   'Infrastructure', 'critical', 'SERVICE_ACCOUNT', 'low',
   ARRAY['CORP-ERP-01'], '2026-10-28', true, 'Secure IPsec tunnel gateway to AWS ap-south-1'),

  -- VLAN 70 (Security Management)
  ('SEC-VAULT-01', 'vaultx-core.sec.becpl.local', '10.10.70.10', '00:50:56:A7:00:10', 70, 7,
   'server', 'Ubuntu Linux', '24.04 LTS', NULL, 'VaultX NIDS Core Ingestion & Analytics Engine',
   'IT Security', 'critical', 'SERVICE_ACCOUNT', 'none',
   ARRAY['SEC-DB-01', 'SEC-SENSOR-01'], '2026-11-10', true, 'VaultX primary processing engine'),

  ('SEC-DB-01', 'postgres-ts.sec.becpl.local', '10.10.70.20', '00:50:56:A7:00:20', 70, 7,
   'server', 'PostgreSQL 15 on Ubuntu', '22.04 LTS', NULL, 'Security Data Foundation Master DB',
   'IT Security', 'critical', 'SERVICE_ACCOUNT', 'none',
   ARRAY['SEC-VAULT-01'], '2026-11-10', true, 'Stores security events, flows, identities, audits'),

  ('SEC-SENSOR-01', 'nids-probe-pune.sec.becpl.local', '10.10.70.30', '00:50:56:A7:00:30', 70, 7,
   'sensor', 'Debian Linux', '12 Bookworm', 'Zeek-6.0/Suri-7.0', 'SPAN/Mirror Port Collector Probe',
   'IT Security', 'critical', 'SERVICE_ACCOUNT', 'none',
   ARRAY['SEC-VAULT-01'], '2026-11-12', true, 'Network passive tap capturing VLAN 10-50 traffic')
ON CONFLICT (asset_id) DO UPDATE SET
  hostname = EXCLUDED.hostname,
  ip_address = EXCLUDED.ip_address,
  primary_application = EXCLUDED.primary_application,
  criticality = EXCLUDED.criticality,
  identity_classification = EXCLUDED.identity_classification;

-- ===========================================================================
-- 4. Identities
-- ===========================================================================
INSERT INTO identities (
  principal_name, principal_type, department, email, associated_asset_id,
  authentication_methods, is_active, is_privileged, vendor_id, mfa_enrolled
) VALUES
  ('rajesh.patil@becpl.in', 'HUMAN_USER', 'IT Operations', 'rajesh.patil@becpl.in',
   'CORP-WS-101', ARRAY['password', 'mfa'], true, true, NULL, true),

  ('amit.shinde@becpl.in', 'HUMAN_USER', 'Engineering', 'amit.shinde@becpl.in',
   'ENG-WS-201', ARRAY['password', 'certificate'], true, false, NULL, true),

  ('svc_vaultx_ingest', 'SERVICE_ACCOUNT', 'IT Security', 'secops@becpl.in',
   'SEC-VAULT-01', ARRAY['api_key', 'certificate'], true, true, NULL, false),

  ('svc_ignition_scada', 'SERVICE_ACCOUNT', 'Operations Technology', 'ot-admins@becpl.in',
   'OT-SCADA-01', ARRAY['certificate'], true, true, NULL, false),

  ('yamaha_field_eng', 'THIRD_PARTY_IDENTITY', 'Field Maintenance', 'service.in@yamaha-motor.com',
   'DMZ-JUMP-01', ARRAY['password', 'mfa'], true, false, 2, true),

  ('ot_line1_smt_plc', 'INDUSTRIAL_DEVICE', 'Manufacturing', NULL,
   'OT-SMT-PLC01', ARRAY['certificate'], true, false, NULL, false),

  ('gitlab_ci_runner', 'AUTOMATION_WORKLOAD', 'R&D Firmware', 'ci@becpl.in',
   'ENG-BUILD-01', ARRAY['api_key'], true, false, NULL, false)
ON CONFLICT DO NOTHING;

-- ===========================================================================
-- 5. Isolation Policies
-- ===========================================================================
INSERT INTO isolation_policies (
  policy_name, target_asset_type, target_criticality, isolation_method,
  quarantine_vlan, requires_human_approval, approval_required_role,
  production_safety_check, safety_check_command, max_isolation_duration_hours,
  auto_restore, rollback_procedure, notify_on_isolation
) VALUES
  ('IT Workstation Rapid Quarantine', 'workstation', 'medium', 'vlan_quarantine',
   999, false, 'Security Analyst Tier 1',
   false, NULL, 24, true,
   'Switch port return to original VLAN 10 tag via SNMP/REST API and flush DHCP lease',
   ARRAY['secops@becpl.in', 'helpdesk@becpl.in']),

  ('Manufacturing OT Asset Controlled Isolation', 'plc', 'critical', 'acl_block',
   NULL, true, 'Plant Operations Head + CISO',
   true, '/opt/vaultx/scripts/verify_plant_safety_interlock.sh --asset-id %ASSET_ID%', 8, false,
   'Clear dynamic ACL rule from core switch 10.10.30.1 and verify PLC heartbeat with SCADA supervisor',
   ARRAY['plant-safety@becpl.in', 'secops@becpl.in', 'gm-manufacturing@becpl.in']),

  ('Vendor Session Kill and Bastion ACL Block', 'server', 'high', 'firewall_block',
   NULL, false, 'Security Incident Handler',
   false, NULL, 12, false,
   'Revoke Teleport SSH session token and drop stateful connection tracking table on DMZ firewall',
   ARRAY['secops@becpl.in', 'vendor-governance@becpl.in']),

  ('Compromised Account Token Revocation', NULL, 'high', 'vlan_quarantine',
   NULL, false, 'Security Analyst Tier 2',
   false, NULL, 48, false,
   'Invalidate Active Directory Kerberos ticket-granting tickets (TGT) and force password reset flag',
   ARRAY['secops@becpl.in', 'hr-compliance@becpl.in']);

-- ===========================================================================
-- 6. ML Model Metadata Placeholders
-- ===========================================================================
INSERT INTO ml_models (
  model_name, model_version, model_type, training_dataset,
  training_date, feature_set, hyperparameters, performance_metrics,
  threshold_config, is_active, deployed_at, notes
) VALUES
  ('VaultX OT Protocol Anomaly Autoencoder', 'v1.4.0', 'anomaly_detection',
   'BECPL_OT_BASELINE_2026_Q3.pcap.parquet', '2026-09-15',
   ARRAY['flow_duration_ms', 'orig_bytes', 'resp_bytes', 'packet_rate', 'modbus_function_code', 'inter_packet_time_variance'],
   '{"latent_dim": 8, "learning_rate": 0.001, "batch_size": 64, "epochs": 50}'::jsonb,
   '{"reconstruction_error_mean": 0.012, "precision": 0.984, "recall": 0.961, "f1_score": 0.972, "auc_roc": 0.991}'::jsonb,
   '{"low": 0.025, "medium": 0.050, "high": 0.085, "critical": 0.150}'::jsonb,
   true, '2026-10-01 00:00:00+05:30',
   'Trained on 3 months of baseline SMT line Modbus TCP & S7Comm telemetry'),

  ('Lateral Movement Random Forest Classifier', 'v2.1.2', 'classification',
   'CICIDS2017_BECPL_HYBRID_COMBINED.parquet', '2026-08-20',
   ARRAY['src_dst_vlan_cross', 'kerberos_ticket_type', 'smb_named_pipe_count', 'failed_auth_window_count', 'non_standard_port_flag'],
   '{"n_estimators": 200, "max_depth": 12, "criterion": "gini", "class_weight": "balanced"}'::jsonb,
   '{"accuracy": 0.993, "precision": 0.978, "recall": 0.985, "f1_score": 0.981}'::jsonb,
   '{"alert_threshold": 0.82, "high_confidence_quarantine": 0.95}'::jsonb,
   true, '2026-09-01 00:00:00+05:30',
   'Identifies credential dumping, Pass-the-Hash, and PsExec cross-VLAN propagation');

-- ===========================================================================
-- 7. Detection Rules (Sigma & Suricata Mappings)
-- ===========================================================================
INSERT INTO detection_rules (
  rule_id, rule_name, rule_type, source_system, rule_content,
  mapped_attack_scenario, mitre_tactic, mitre_technique, severity,
  confidence_level, is_active, version
) VALUES
  ('RULE-SMT-MODBUS-WRITE', 'Unauthorized Modbus Write to SMT PLC from Non-Engineering Zone',
   'snort', 'suricata',
   'alert tcp !10.10.20.0/24 any -> 10.10.30.20 502 (msg:"VAULTX SMT PLC Write attempt outside Engineering VLAN"; content:"|00 00 00 00|"; sid:2026001; rev:1;)',
   'ot_sabotage_lateral_movement', 'Lateral Movement', 'T1021.002', 'critical',
   0.98, true, '1.0'),

  ('RULE-IT-OT-DIRECT-SMB', 'Direct SMB File Sharing Connection Attempt into OT VLAN 30',
   'sigma', 'zeek_notice',
   'selection: destination.zone: "VLAN_30" and destination.port: [445, 139] and not source.ip: "10.10.70.0/24"',
   'lateral_movement_ransomware', 'Lateral Movement', 'T1021.002', 'high',
   0.95, true, '1.2'),

  ('RULE-BRUTE-FORCE-RDP-BASTION', 'Multiple RDP Authentication Failures against DMZ Jump Host',
   'custom_ml', 'auth_events',
   'count(failure) > 5 within 60s per source_ip -> DMZ-JUMP-01',
   'external_credential_access', 'Credential Access', 'T1110.001', 'high',
   0.92, true, '2.0'),

  ('RULE-EXFILTRATION-S3-ANOMALY', 'Abnormal Volume Outbound Transfer to External S3 Endpoint',
   'custom_ml', 'network_flows',
   'bytes_transferred > 500MB and dst_port == 443 and not dst_ip in aws_approved_endpoints',
   'intellectual_property_theft', 'Exfiltration', 'T1048.003', 'critical',
   0.94, true, '1.1');

-- ===========================================================================
-- 8. Communication Matrix Rules
-- ===========================================================================
INSERT INTO communication_rules (
  rule_id, source_asset_id, source_vlan, destination_asset_id, destination_vlan,
  protocol, port, action, condition_text, justification, monitoring_type, alert_on_violation
) VALUES
  ('CMR-001', 'CORP-WS-101', 10, 'CORP-ERP-01', 10,
   'TCP', 5432, 'ALLOW', 'Standard working hours 08:00 - 19:00 IST',
   'Finance workstation querying accounting ERP PostgreSQL database', 'passive', false),

  ('CMR-002', 'ENG-WS-201', 20, 'ENG-GIT-01', 20,
   'TCP', 22, 'ALLOW', 'SSH key authentication with ED25519',
   'PCB Engineers pushing firmware source and schematic files', 'passive', false),

  ('CMR-003', 'ENG-BUILD-01', 20, 'OT-SCADA-01', 30,
   'TCP', 8088, 'ALLOW', 'Controlled deployment pipeline; requires pre-release tag',
   'Publishing validated firmware binary images to factory OT SCADA repository', 'active', true),

  ('CMR-004', NULL, 10, NULL, 30,
   'ANY', NULL, 'DENY', 'Strict IT to OT firewall isolation',
   'Airgap boundary: Direct Corporate IT traffic into Manufacturing OT is prohibited', 'active', true),

  ('CMR-005', 'DMZ-JUMP-01', 50, 'OT-SCADA-01', 30,
   'TCP', 443, 'RESTRICT', 'Vendor maintenance window only + active MFA approval',
   'Supervised Yamaha remote engineering maintenance of SMT production lines', 'active', true);
