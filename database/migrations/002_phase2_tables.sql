-- VaultX NIDS - Phase 2 Database Migration
-- BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
-- Schema: becpl_nids
-- Run as: psql -U nids_user -d becpl_nids -f 002_phase2_tables.sql

SET search_path TO becpl_nids, public;

-- ===========================================================================
-- 1. Asset Behavioural Baselines
-- ===========================================================================
CREATE TABLE IF NOT EXISTS becpl_nids.asset_baselines (
  baseline_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id      VARCHAR(50) REFERENCES becpl_nids.assets(asset_id),
  computed_at   TIMESTAMPTZ NOT NULL,
  baseline_json JSONB NOT NULL,
  sample_count  INTEGER,
  is_active     BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_asset_baselines_asset_active
  ON becpl_nids.asset_baselines (asset_id, is_active, computed_at DESC);

-- ===========================================================================
-- 2. Identity Behavioural Baselines
-- ===========================================================================
CREATE TABLE IF NOT EXISTS becpl_nids.identity_baselines (
  baseline_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id   UUID REFERENCES becpl_nids.identities(identity_id),
  computed_at   TIMESTAMPTZ NOT NULL,
  baseline_json JSONB NOT NULL,
  sample_count  INTEGER,
  is_active     BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_identity_baselines_identity_active
  ON becpl_nids.identity_baselines (identity_id, is_active, computed_at DESC);

-- ===========================================================================
-- 3. Third-Party Vendor Sessions
-- ===========================================================================
CREATE TABLE IF NOT EXISTS becpl_nids.vendor_sessions (
  session_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vendor_id          INTEGER REFERENCES becpl_nids.vendors(vendor_id),
  identity_id        UUID,
  source_ip          INET,
  session_start      TIMESTAMPTZ,
  session_end        TIMESTAMPTZ,
  duration_minutes   INTEGER,
  resources_accessed TEXT[],
  bytes_transferred  BIGINT,
  policy_violations  TEXT[],
  created_at         TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vendor_sessions_vendor_start
  ON becpl_nids.vendor_sessions (vendor_id, session_start DESC);
CREATE INDEX IF NOT EXISTS idx_vendor_sessions_identity
  ON becpl_nids.vendor_sessions (identity_id);

-- ===========================================================================
-- 4. ML Feature Vectors (Feature Store)
-- ===========================================================================
CREATE TABLE IF NOT EXISTS becpl_nids.feature_vectors (
  vector_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  flow_id             UUID,
  asset_id            VARCHAR(50) REFERENCES becpl_nids.assets(asset_id),
  identity_id         UUID,
  window_start        TIMESTAMPTZ NOT NULL,
  window_end          TIMESTAMPTZ NOT NULL,
  feature_schema_ver  VARCHAR(20) NOT NULL DEFAULT 'v1',
  features            JSONB NOT NULL,
  label               VARCHAR(50),
  anomaly_score       DECIMAL(5,4),
  model_version       VARCHAR(50),
  created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feature_vectors_asset_window
  ON becpl_nids.feature_vectors (asset_id, window_start DESC);
CREATE INDEX IF NOT EXISTS idx_feature_vectors_label
  ON becpl_nids.feature_vectors (label) WHERE label IS NOT NULL;

-- ===========================================================================
-- 5. Threat Intelligence (IP Blocklist, Bad JA3 Hashes, CISA KEV Correlation)
-- ===========================================================================
CREATE TABLE IF NOT EXISTS becpl_nids.threat_intel (
  intel_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  indicator_type  VARCHAR(30) NOT NULL CHECK (indicator_type IN (
                    'ip', 'cidr', 'domain', 'ja3', 'ja3s', 'file_hash', 'cve_kev', 'url')),
  indicator_value VARCHAR(255) NOT NULL,
  source_feed     VARCHAR(100) NOT NULL,  -- e.g. 'cisa_kev', 'abuse_ch', 'feodo', 'internal'
  threat_category VARCHAR(100),           -- e.g. 'c2', 'botnet', 'ransomware', 'scanner', 'kev'
  severity        VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
  confidence      DECIMAL(4,3) CHECK (confidence BETWEEN 0 AND 1),
  cve_id          VARCHAR(30),
  kev_due_date    DATE,
  description     TEXT,
  metadata        JSONB,
  first_seen      TIMESTAMPTZ DEFAULT NOW(),
  last_seen       TIMESTAMPTZ DEFAULT NOW(),
  expires_at      TIMESTAMPTZ,
  is_active       BOOLEAN DEFAULT TRUE,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (indicator_type, indicator_value, source_feed)
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_lookup
  ON becpl_nids.threat_intel (indicator_type, indicator_value) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_threat_intel_cve
  ON becpl_nids.threat_intel (cve_id) WHERE cve_id IS NOT NULL;

-- ===========================================================================
-- 6. AI Agent & Automation Workload Activities
-- ===========================================================================
CREATE TABLE IF NOT EXISTS becpl_nids.agent_activities (
  activity_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id       UUID REFERENCES becpl_nids.identities(identity_id),
  identity_category VARCHAR(50) CHECK (identity_category IN ('AI_AGENT', 'AUTOMATION_WORKLOAD')),
  timestamp         TIMESTAMPTZ NOT NULL,
  source_ip         INET,
  api_endpoint      VARCHAR(255),
  resource_type     VARCHAR(100),
  target_resource   VARCHAR(255),
  tool_name         VARCHAR(150),
  status_code       INTEGER,
  anomaly_flags     TEXT[],
  metadata          JSONB,
  created_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_activities_identity_ts
  ON becpl_nids.agent_activities (identity_id, timestamp DESC);

-- ===========================================================================
-- 7. Approved Maintenance Windows (OT & Engineering Operations)
-- ===========================================================================
CREATE TABLE IF NOT EXISTS becpl_nids.maintenance_windows (
  window_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id           VARCHAR(50) REFERENCES becpl_nids.assets(asset_id),
  vlan_id            INTEGER REFERENCES becpl_nids.network_zones(vlan_id),
  start_datetime     TIMESTAMPTZ NOT NULL,
  end_datetime       TIMESTAMPTZ NOT NULL,
  description        TEXT NOT NULL,
  change_ticket_id   VARCHAR(100),
  approved_by        VARCHAR(150),
  approved_identities TEXT[],
  is_approved        BOOLEAN DEFAULT TRUE,
  created_at         TIMESTAMPTZ DEFAULT NOW(),
  CHECK (end_datetime > start_datetime)
);

CREATE INDEX IF NOT EXISTS idx_maintenance_windows_active
  ON becpl_nids.maintenance_windows (asset_id, start_datetime, end_datetime)
  WHERE is_approved = TRUE;
CREATE INDEX IF NOT EXISTS idx_maintenance_windows_vlan
  ON becpl_nids.maintenance_windows (vlan_id, start_datetime, end_datetime)
  WHERE is_approved = TRUE;

-- ===========================================================================
-- 8. Asset Software Inventory (for Phase 2 Vulnerability / CVE Correlation)
-- ===========================================================================
CREATE TABLE IF NOT EXISTS becpl_nids.software_inventory (
  inventory_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id       VARCHAR(50) NOT NULL REFERENCES becpl_nids.assets(asset_id),
  software_name  VARCHAR(255) NOT NULL,
  version        VARCHAR(100),
  cpe_string     VARCHAR(255),
  service_port   INTEGER,
  source         VARCHAR(50) DEFAULT 'asset_registry',  -- asset_registry | discovery | agent
  discovered_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at     TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (asset_id, software_name, version)
);

CREATE INDEX IF NOT EXISTS idx_software_inventory_asset
  ON becpl_nids.software_inventory (asset_id);
CREATE INDEX IF NOT EXISTS idx_software_inventory_cpe
  ON becpl_nids.software_inventory (cpe_string) WHERE cpe_string IS NOT NULL;
