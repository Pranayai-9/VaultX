-- =============================================================================
-- VaultX Phase 2 Migration 003: Containment, Response & Model Improvement
-- BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
-- Schema: becpl_nids
-- =============================================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS becpl_nids;
SET search_path TO becpl_nids;

-- ---------------------------------------------------------------------------
-- 1. Simulated Firewall Rules (OPNsense / FortiGate & OT Boundary Simulation)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS becpl_nids.simulated_firewall_rules (
  rule_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  src_ip         VARCHAR(64) NOT NULL,
  dst_ip         VARCHAR(64) NOT NULL,
  protocol       VARCHAR(20) NOT NULL DEFAULT 'TCP'
                   CHECK (protocol IN ('TCP', 'UDP', 'ICMP', 'ANY', 'MODBUS')),
  port_range     VARCHAR(32) NOT NULL DEFAULT 'ANY',
  action         VARCHAR(10) NOT NULL CHECK (action IN ('BLOCK', 'ALLOW')),
  active         BOOLEAN NOT NULL DEFAULT TRUE,
  created_by     VARCHAR(100) NOT NULL,
  incident_id    UUID REFERENCES becpl_nids.incidents(incident_id),
  expires_at     TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  rolled_back_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sim_fw_rules_active
  ON becpl_nids.simulated_firewall_rules (active, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_sim_fw_rules_incident
  ON becpl_nids.simulated_firewall_rules (incident_id);

CREATE INDEX IF NOT EXISTS idx_sim_fw_rules_src_dst
  ON becpl_nids.simulated_firewall_rules (src_ip, dst_ip);

-- ---------------------------------------------------------------------------
-- 2. Endpoint Quarantine Records (VLAN 999 with VLAN 70 Management Preserved)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS becpl_nids.quarantine_records (
  record_id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id                    VARCHAR(50) NOT NULL REFERENCES becpl_nids.assets(asset_id),
  incident_id                 UUID REFERENCES becpl_nids.incidents(incident_id),
  quarantine_start            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  quarantine_end              TIMESTAMPTZ,
  management_access_preserved BOOLEAN NOT NULL DEFAULT TRUE,
  created_by                  VARCHAR(100) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_quarantine_records_asset
  ON becpl_nids.quarantine_records (asset_id, quarantine_start DESC);

CREATE INDEX IF NOT EXISTS idx_quarantine_records_incident
  ON becpl_nids.quarantine_records (incident_id);

-- ---------------------------------------------------------------------------
-- 3. Analyst Feedback Table (Human-Verified Ground Truth for ML Pipeline)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS becpl_nids.analyst_feedback (
  feedback_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id            UUID,
  original_prediction VARCHAR(50),
  analyst_label       VARCHAR(50),  -- confirmed correct label
  analyst_id          UUID,
  feedback_timestamp  TIMESTAMPTZ DEFAULT NOW(),
  notes               TEXT
);

CREATE INDEX IF NOT EXISTS idx_analyst_feedback_event
  ON becpl_nids.analyst_feedback (event_id);

CREATE INDEX IF NOT EXISTS idx_analyst_feedback_timestamp
  ON becpl_nids.analyst_feedback (feedback_timestamp DESC);

-- ---------------------------------------------------------------------------
-- 4. Vendor VPN Sessions (Supporting VPNAdapter if not created earlier)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS becpl_nids.vendor_sessions (
  session_id        VARCHAR(100) PRIMARY KEY,
  vendor_id         INTEGER REFERENCES becpl_nids.vendors(vendor_id),
  vendor_name       VARCHAR(255),
  identity_id       UUID REFERENCES becpl_nids.identities(identity_id),
  source_ip         INET,
  started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at          TIMESTAMPTZ,
  session_status    VARCHAR(30) NOT NULL DEFAULT 'active'
                      CHECK (session_status IN ('active', 'closed', 'suspended', 'revoked', 'restored')),
  suspension_reason TEXT
);

-- ---------------------------------------------------------------------------
-- 5. Feature Vectors Table (Supporting ModelImprovementPipeline SECURE_STORAGE)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS becpl_nids.feature_vectors (
  vector_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id     UUID,
  event_hash   VARCHAR(64) UNIQUE NOT NULL,
  features     JSONB NOT NULL,
  label        VARCHAR(50),
  label_source VARCHAR(50),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feature_vectors_label_source
  ON becpl_nids.feature_vectors (label_source, created_at DESC);

-- ---------------------------------------------------------------------------
-- 6. Extend incidents table with investigation & blast-radius fields
-- ---------------------------------------------------------------------------
ALTER TABLE becpl_nids.incidents
  ADD COLUMN IF NOT EXISTS investigation_summary   JSONB,
  ADD COLUMN IF NOT EXISTS investigation_narrative TEXT,
  ADD COLUMN IF NOT EXISTS blast_radius_json       JSONB;

-- ---------------------------------------------------------------------------
-- 7. Extend response_actions table with break-glass, two-person, & proposal fields
-- ---------------------------------------------------------------------------
ALTER TABLE becpl_nids.response_actions
  ADD COLUMN IF NOT EXISTS break_glass_used   BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS second_approver    VARCHAR(100),
  ADD COLUMN IF NOT EXISTS action_proposal    JSONB,
  ADD COLUMN IF NOT EXISTS expires_at         TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS ot_safety_override BOOLEAN DEFAULT FALSE;

-- Update status CHECK constraint to include Phase 2 'recommended' and 'expired' states
ALTER TABLE becpl_nids.response_actions
  DROP CONSTRAINT IF EXISTS response_actions_status_check;

ALTER TABLE becpl_nids.response_actions
  ADD CONSTRAINT response_actions_status_check
  CHECK (status IN (
    'recommended', 'pending', 'approved', 'rejected',
    'executing', 'completed', 'failed', 'rolled_back', 'expired'
  ));

-- Update action_type CHECK constraint to allow Phase 2 canonical containment categories
ALTER TABLE becpl_nids.response_actions
  DROP CONSTRAINT IF EXISTS response_actions_action_type_check;

ALTER TABLE becpl_nids.response_actions
  ADD CONSTRAINT response_actions_action_type_check
  CHECK (action_type IN (
    'isolate', 'block_ip', 'disable_account', 'patch',
    'restore', 'quarantine', 'firewall_rule', 'acl_update',
    'password_reset', 'session_revoke', 'service_stop',
    'evidence_collect', 'escalate', 'notify',
    'ENDPOINT_QUARANTINE', 'IDENTITY_CONTAINMENT',
    'NETWORK_CONTAINMENT', 'THIRD_PARTY_CONTAINMENT',
    'OT_BOUNDARY_RESTRICTION'
  ));

CREATE INDEX IF NOT EXISTS idx_response_actions_status_expires
  ON becpl_nids.response_actions (status, expires_at);

-- ---------------------------------------------------------------------------
-- 8. Extend ml_models table with controlled promotion lifecycle columns
-- ---------------------------------------------------------------------------
ALTER TABLE becpl_nids.ml_models
  ADD COLUMN IF NOT EXISTS lifecycle_state VARCHAR(30) DEFAULT 'candidate'
    CHECK (lifecycle_state IN ('candidate', 'validated', 'approved', 'deployed', 'retired')),
  ADD COLUMN IF NOT EXISTS approved_by     VARCHAR(100),
  ADD COLUMN IF NOT EXISTS approved_at     TIMESTAMPTZ;

COMMIT;
