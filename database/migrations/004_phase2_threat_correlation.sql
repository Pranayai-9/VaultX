-- VaultX NIDS - Phase 2 Threat Intelligence & Correlation Tables Migration
-- BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
-- Schema: becpl_nids
-- Safe, idempotent migration extending Phase 1 schema for Phase 2 engines.

SET search_path TO becpl_nids;

-- ---------------------------------------------------------------------------
-- 1. Asset Software Inventory (for CVE & CPE Vulnerability Correlation)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS software_inventory (
  inventory_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id        VARCHAR(50) NOT NULL,
  software_name   VARCHAR(255) NOT NULL,
  version         VARCHAR(100) NOT NULL,
  cpe_string      VARCHAR(255),
  service_port    INTEGER,
  source          VARCHAR(50) DEFAULT 'asset_registry', -- asset_registry, discovery, agent, manual
  discovered_at   TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (asset_id, software_name, version)
);

CREATE INDEX IF NOT EXISTS idx_software_inventory_asset
  ON software_inventory (asset_id);
CREATE INDEX IF NOT EXISTS idx_software_inventory_cpe
  ON software_inventory (cpe_string);

-- ---------------------------------------------------------------------------
-- 2. Offline Threat Intelligence Store (CVE subset, KEV, IP/JA3 feeds)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_intel (
  intel_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  indicator_type  VARCHAR(30) NOT NULL CHECK (indicator_type IN (
                    'cve', 'cisa_kev', 'ip_blocklist', 'ja3_blocklist', 'domain', 'hash')),
  indicator_value VARCHAR(255) NOT NULL,
  source          VARCHAR(100) NOT NULL,
  severity        VARCHAR(20) CHECK (severity IN ('critical','high','medium','low','informational')),
  metadata        JSONB DEFAULT '{}'::jsonb,
  is_simulated    BOOLEAN DEFAULT FALSE,
  added_at        TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (indicator_type, indicator_value)
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_type_val
  ON threat_intel (indicator_type, indicator_value);

-- ---------------------------------------------------------------------------
-- 3. Extend vulnerabilities table with risk scoring & KEV flags
-- ---------------------------------------------------------------------------
ALTER TABLE vulnerabilities
  ADD COLUMN IF NOT EXISTS risk_score DECIMAL(5,2),
  ADD COLUMN IF NOT EXISTS criticality_multiplier DECIMAL(3,2),
  ADD COLUMN IF NOT EXISTS exposure_multiplier DECIMAL(3,2),
  ADD COLUMN IF NOT EXISTS is_kev BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS cpe_matched VARCHAR(255),
  ADD COLUMN IF NOT EXISTS affected_port INTEGER;

-- ---------------------------------------------------------------------------
-- 4. Extend incidents table for Phase 2 Correlation, Blast Radius & AI Investigation
-- ---------------------------------------------------------------------------
ALTER TABLE incidents
  ADD COLUMN IF NOT EXISTS rule_id VARCHAR(50),
  ADD COLUMN IF NOT EXISTS mitre_techniques TEXT[],
  ADD COLUMN IF NOT EXISTS evidence JSONB DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS ot_safety_flag BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS blast_radius_json JSONB,
  ADD COLUMN IF NOT EXISTS investigation_summary JSONB,
  ADD COLUMN IF NOT EXISTS investigation_narrative TEXT;

CREATE INDEX IF NOT EXISTS idx_incidents_status_severity
  ON incidents (status, severity);
CREATE INDEX IF NOT EXISTS idx_incidents_ot_safety
  ON incidents (ot_safety_flag) WHERE ot_safety_flag = TRUE;

-- ---------------------------------------------------------------------------
-- 5. Extend security_events.event_type constraint for Phase 2 event types
--    (exploitation_indicator, risk_assessment, supply_chain_indicator)
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  constraint_name TEXT;
BEGIN
  SELECT c.conname INTO constraint_name
  FROM pg_constraint c
  JOIN pg_class t ON c.conrelid = t.oid
  JOIN pg_namespace n ON t.relnamespace = n.oid
  WHERE n.nspname = 'becpl_nids'
    AND t.relname = 'security_events'
    AND c.contype = 'c'
    AND pg_get_constraintdef(c.oid) LIKE '%event_type%';

  IF constraint_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE becpl_nids.security_events DROP CONSTRAINT %I', constraint_name);
  END IF;

  ALTER TABLE becpl_nids.security_events
    ADD CONSTRAINT security_events_event_type_check
    CHECK (event_type IN (
      'network_flow','alert','auth_event','endpoint_event',
      'dns_event','http_event','tls_event','sensor_health',
      'policy_violation','manual','exploitation_indicator',
      'risk_assessment','supply_chain_indicator'
    ));
END $$;
