-- VaultX NIDS - Core Reference Tables
-- BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
-- Schema: becpl_nids

-- Enable useful PostgreSQL extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- trigram indexes for text search
-- TimescaleDB (optional, comment out if not installed):
-- CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE SCHEMA IF NOT EXISTS becpl_nids;
SET search_path TO becpl_nids;

-- ---------------------------------------------------------------------------
-- Network Zones / VLANs
-- ---------------------------------------------------------------------------
CREATE TABLE network_zones (
  zone_id       SERIAL PRIMARY KEY,
  zone_name     VARCHAR(100) NOT NULL,
  vlan_id       INTEGER UNIQUE,
  cidr_range    CIDR,
  gateway_ip    INET,
  dns_server    INET,
  dhcp_range_start INET,
  dhcp_range_end   INET,
  zone_type     VARCHAR(50) CHECK (zone_type IN (
                  'corporate', 'engineering', 'ot', 'warehouse',
                  'dmz', 'cloud', 'security')),
  criticality   VARCHAR(20) CHECK (criticality IN ('critical','high','medium','low')),
  description   TEXT,
  inter_vlan_allow TEXT[],  -- list of vlan_ids this zone may communicate with
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Asset Inventory
-- ---------------------------------------------------------------------------
CREATE TABLE assets (
  asset_id               VARCHAR(50) PRIMARY KEY,
  hostname               VARCHAR(255),
  ip_address             INET,
  mac_address            MACADDR,
  vlan_id                INTEGER REFERENCES network_zones(vlan_id),
  zone_id                INTEGER REFERENCES network_zones(zone_id),
  device_type            VARCHAR(50) CHECK (device_type IN (
                           'workstation','server','switch','firewall','router',
                           'plc','hmi','sensor','gateway','printer','scanner',
                           'vm','container','access_point','ip_camera','ups',
                           'storage','iot_device','other')),
  os_name                VARCHAR(100),
  os_version             VARCHAR(50),
  firmware_version       VARCHAR(50),
  primary_application    VARCHAR(100),
  owner_department       VARCHAR(100),
  criticality            VARCHAR(20) CHECK (criticality IN ('critical','high','medium','low')),
  identity_classification VARCHAR(50) CHECK (identity_classification IN (
                           'HUMAN_USER','SERVICE_ACCOUNT','AUTOMATION_WORKLOAD',
                           'AI_AGENT','INDUSTRIAL_DEVICE','THIRD_PARTY_IDENTITY',
                           'UNKNOWN_IDENTITY')),
  vulnerability_exposure VARCHAR(20) CHECK (vulnerability_exposure IN ('high','medium','low','none')),
  communication_peers    TEXT[],   -- peer asset_ids this device talks to
  last_patched           DATE,
  is_active              BOOLEAN DEFAULT TRUE,
  notes                  TEXT,
  created_at             TIMESTAMPTZ DEFAULT NOW(),
  updated_at             TIMESTAMPTZ DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Identity / User Records
-- ---------------------------------------------------------------------------
CREATE TABLE identities (
  identity_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_name         VARCHAR(255) NOT NULL,
  principal_type         VARCHAR(50) NOT NULL CHECK (principal_type IN (
                           'HUMAN_USER','SERVICE_ACCOUNT','AUTOMATION_WORKLOAD',
                           'AI_AGENT','INDUSTRIAL_DEVICE','THIRD_PARTY_IDENTITY',
                           'UNKNOWN_IDENTITY')),
  department             VARCHAR(100),
  email                  VARCHAR(255),
  associated_asset_id    VARCHAR(50) REFERENCES assets(asset_id),
  authentication_methods TEXT[],   -- password, mfa, certificate, api_key
  is_active              BOOLEAN DEFAULT TRUE,
  is_privileged          BOOLEAN DEFAULT FALSE,
  vendor_id              INTEGER,  -- FK to vendors added after vendors table
  mfa_enrolled           BOOLEAN DEFAULT FALSE,
  last_login             TIMESTAMPTZ,
  created_at             TIMESTAMPTZ DEFAULT NOW(),
  updated_at             TIMESTAMPTZ DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Vendor Records
-- ---------------------------------------------------------------------------
CREATE TABLE vendors (
  vendor_id                  SERIAL PRIMARY KEY,
  vendor_name                VARCHAR(255) NOT NULL,
  vendor_type                VARCHAR(100) CHECK (vendor_type IN (
                               'component_supplier','maintenance_vendor',
                               'logistics','cloud','dev_service','other')),
  contact_email              VARCHAR(255),
  contact_phone              VARCHAR(50),
  country                    VARCHAR(100),
  approved_access_scope      TEXT,
  allowed_vlans              INTEGER[],  -- VLANs this vendor may access
  mfa_required               BOOLEAN DEFAULT TRUE,
  max_session_duration_hours INTEGER DEFAULT 4,
  requires_vpn               BOOLEAN DEFAULT TRUE,
  is_active                  BOOLEAN DEFAULT TRUE,
  last_access_review         DATE,
  next_access_review         DATE,
  notes                      TEXT,
  created_at                 TIMESTAMPTZ DEFAULT NOW()
);

-- Add FK from identities to vendors (now that vendors exists)
ALTER TABLE identities
  ADD CONSTRAINT fk_identities_vendor
  FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id);

-- ---------------------------------------------------------------------------
-- Communication Rules / Policy
-- ---------------------------------------------------------------------------
CREATE TABLE communication_rules (
  rule_id              VARCHAR(20) PRIMARY KEY,
  source_asset_id      VARCHAR(50) REFERENCES assets(asset_id),
  source_vlan          INTEGER REFERENCES network_zones(vlan_id),
  destination_asset_id VARCHAR(50) REFERENCES assets(asset_id),
  destination_vlan     INTEGER REFERENCES network_zones(vlan_id),
  protocol             VARCHAR(20),
  port                 INTEGER,
  port_range_end       INTEGER,  -- for port ranges
  action               VARCHAR(10) CHECK (action IN ('ALLOW','DENY','RESTRICT')),
  condition_text       TEXT,
  justification        TEXT,
  monitoring_type      VARCHAR(20) CHECK (monitoring_type IN ('passive','active','none')),
  alert_on_violation   BOOLEAN DEFAULT TRUE,
  time_restriction     VARCHAR(100),  -- e.g. 'business_hours_only', 'anytime'
  created_at           TIMESTAMPTZ DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Vulnerability Inventory
-- ---------------------------------------------------------------------------
CREATE TABLE vulnerabilities (
  vuln_id            VARCHAR(20) PRIMARY KEY,
  cve_id             VARCHAR(20),
  asset_id           VARCHAR(50) REFERENCES assets(asset_id),
  cvss_score         DECIMAL(3,1),
  cvss_vector        VARCHAR(100),
  severity           VARCHAR(20) CHECK (severity IN ('critical','high','medium','low','informational')),
  description        TEXT,
  affected_component VARCHAR(255),
  patch_available    BOOLEAN,
  patch_applied      BOOLEAN DEFAULT FALSE,
  workaround_applied BOOLEAN DEFAULT FALSE,
  workaround_notes   TEXT,
  discovered_at      TIMESTAMPTZ DEFAULT NOW(),
  remediated_at      TIMESTAMPTZ,
  assigned_to        VARCHAR(100),
  risk_accepted      BOOLEAN DEFAULT FALSE,
  risk_accepted_by   VARCHAR(100),
  risk_accepted_at   TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- Isolation Policies
-- ---------------------------------------------------------------------------
CREATE TABLE isolation_policies (
  policy_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_name              VARCHAR(255) NOT NULL,
  target_asset_type        VARCHAR(50),
  target_criticality       VARCHAR(20),
  isolation_method         VARCHAR(50) CHECK (isolation_method IN (
                             'vlan_quarantine','firewall_block','port_disable',
                             'acl_block','null_route')),
  quarantine_vlan          INTEGER,
  requires_human_approval  BOOLEAN DEFAULT TRUE,
  approval_required_role   VARCHAR(50),
  production_safety_check  BOOLEAN DEFAULT FALSE,  -- mandatory for OT assets
  safety_check_command     TEXT,
  max_isolation_duration_hours INTEGER,
  auto_restore             BOOLEAN DEFAULT FALSE,
  rollback_procedure       TEXT,
  notify_on_isolation      TEXT[],  -- list of roles/contacts to notify
  created_at               TIMESTAMPTZ DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- ML Model Metadata
-- ---------------------------------------------------------------------------
CREATE TABLE ml_models (
  model_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  model_name          VARCHAR(255) NOT NULL,
  model_version       VARCHAR(50),
  model_type          VARCHAR(100) CHECK (model_type IN (
                        'classification','anomaly_detection','clustering',
                        'regression','rule_based','ensemble')),
  training_dataset    VARCHAR(255),
  training_date       DATE,
  feature_set         TEXT[],
  hyperparameters     JSONB,
  performance_metrics JSONB,  -- precision, recall, f1, auc, etc.
  threshold_config    JSONB,  -- per-severity confidence thresholds
  is_active           BOOLEAN DEFAULT FALSE,
  deployed_at         TIMESTAMPTZ,
  retired_at          TIMESTAMPTZ,
  notes               TEXT,
  created_at          TIMESTAMPTZ DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Detection Rules
-- ---------------------------------------------------------------------------
CREATE TABLE detection_rules (
  rule_id          VARCHAR(50) PRIMARY KEY,
  rule_name        VARCHAR(255) NOT NULL,
  rule_type        VARCHAR(50),  -- sigma, snort, suricata, custom_ml, zeek_notice
  source_system    VARCHAR(50),
  rule_content     TEXT,
  mapped_attack_scenario VARCHAR(100),
  mitre_tactic     VARCHAR(100),
  mitre_technique  VARCHAR(50),
  severity         VARCHAR(20),
  confidence_level DECIMAL(3,2),
  is_active        BOOLEAN DEFAULT TRUE,
  version          VARCHAR(20),
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Triggers to auto-update updated_at
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION becpl_nids.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_network_zones_updated_at
  BEFORE UPDATE ON network_zones
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_assets_updated_at
  BEFORE UPDATE ON assets
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_identities_updated_at
  BEFORE UPDATE ON identities
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();
