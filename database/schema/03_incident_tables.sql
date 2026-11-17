-- VaultX NIDS - Incident & Response Tables
-- BECPL (Bharat Electronics Components Pvt. Ltd.), Pune

SET search_path TO becpl_nids;

-- ---------------------------------------------------------------------------
-- Security Incidents
-- ---------------------------------------------------------------------------
CREATE TABLE incidents (
  incident_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_reference VARCHAR(20) UNIQUE,  -- e.g. INC-2026-001
  title              VARCHAR(255) NOT NULL,
  description        TEXT,
  severity           VARCHAR(20) CHECK (severity IN ('critical','high','medium','low','informational')),
  status             VARCHAR(30) DEFAULT 'open' CHECK (status IN (
                       'open','investigating','contained','resolved','closed','false_positive')),
  attack_scenario    VARCHAR(100),   -- lateral_movement, ransomware, insider_threat, etc.
  mitre_tactic       VARCHAR(100),
  mitre_technique    VARCHAR(50),
  affected_assets    TEXT[],         -- array of asset_ids
  affected_zones     TEXT[],         -- array of zone names
  ioc_list           JSONB,          -- indicators of compromise: IPs, hashes, domains
  first_seen         TIMESTAMPTZ,
  last_seen          TIMESTAMPTZ,
  detected_at        TIMESTAMPTZ DEFAULT NOW(),
  contained_at       TIMESTAMPTZ,
  resolved_at        TIMESTAMPTZ,
  closed_at          TIMESTAMPTZ,
  assigned_to        VARCHAR(100),
  escalated_to       VARCHAR(100),
  false_positive_reason TEXT,
  timeline           JSONB,          -- array of {ts, actor, action, notes}
  lessons_learned    TEXT,
  created_at         TIMESTAMPTZ DEFAULT NOW(),
  updated_at         TIMESTAMPTZ DEFAULT NOW()
);

CREATE TRIGGER trg_incidents_updated_at
  BEFORE UPDATE ON incidents
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ---------------------------------------------------------------------------
-- Response Actions (human-authorised, logged for compliance)
-- ---------------------------------------------------------------------------
CREATE TABLE response_actions (
  action_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id          UUID REFERENCES incidents(incident_id),
  action_type          VARCHAR(50) CHECK (action_type IN (
                         'isolate','block_ip','disable_account','patch',
                         'restore','quarantine','firewall_rule','acl_update',
                         'password_reset','session_revoke','service_stop',
                         'evidence_collect','escalate','notify')),
  target_asset_id      VARCHAR(50),
  target_identity_id   UUID,
  target_ip            INET,
  isolation_policy_id  UUID REFERENCES isolation_policies(policy_id),
  initiated_by         VARCHAR(100) NOT NULL,  -- human operator
  approved_by          VARCHAR(100),
  approval_method      VARCHAR(50) CHECK (approval_method IN (
                         'mfa_token','manager_approval','break_glass',
                         'auto_policy','self_service')),
  approval_timestamp   TIMESTAMPTZ,
  status               VARCHAR(30) DEFAULT 'pending' CHECK (status IN (
                         'pending','approved','rejected','executing',
                         'completed','failed','rolled_back')),
  execution_detail     JSONB,         -- result details, error messages
  executed_at          TIMESTAMPTZ,
  completed_at         TIMESTAMPTZ,
  rollback_at          TIMESTAMPTZ,
  rollback_reason      TEXT,
  rollback_by          VARCHAR(100),
  notes                TEXT,
  created_at           TIMESTAMPTZ DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- System Audit Log (tamper-evident; partitioned)
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
  audit_id      UUID DEFAULT gen_random_uuid(),
  timestamp     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor         VARCHAR(100) NOT NULL,
  actor_type    VARCHAR(50) CHECK (actor_type IN (
                  'human_operator','service_account','automation','system','unknown')),
  action        VARCHAR(100) NOT NULL,
  target_table  VARCHAR(100),
  target_id     VARCHAR(100),
  old_value     JSONB,
  new_value     JSONB,
  ip_address    INET,
  session_id    VARCHAR(100),
  request_id    UUID,
  outcome       VARCHAR(20) CHECK (outcome IN ('success','failure','partial')),
  failure_reason TEXT,
  PRIMARY KEY (audit_id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE TABLE audit_log_2026_10 PARTITION OF audit_log FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE audit_log_2026_11 PARTITION OF audit_log FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE audit_log_2026_12 PARTITION OF audit_log FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE audit_log_2027_01 PARTITION OF audit_log FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE audit_log_2027_02 PARTITION OF audit_log FOR VALUES FROM ('2027-02-01') TO ('2027-03-01');
CREATE TABLE audit_log_2027_03 PARTITION OF audit_log FOR VALUES FROM ('2027-03-01') TO ('2027-04-01');

-- ---------------------------------------------------------------------------
-- Data Retention Policies
-- ---------------------------------------------------------------------------
CREATE TABLE retention_policies (
  policy_id             SERIAL PRIMARY KEY,
  data_type             VARCHAR(50) UNIQUE NOT NULL,
  table_name            VARCHAR(100),
  online_retention_days INTEGER NOT NULL,
  archive_retention_days INTEGER,
  archive_to            VARCHAR(50) CHECK (archive_to IN ('minio','s3','local','none')),
  archive_format        VARCHAR(20) DEFAULT 'parquet',  -- parquet, csv, json
  compression           VARCHAR(20) DEFAULT 'gzip',
  is_active             BOOLEAN DEFAULT TRUE,
  notes                 TEXT
);

INSERT INTO retention_policies
  (data_type, table_name, online_retention_days, archive_retention_days, archive_to, notes)
VALUES
  ('security_events', 'security_events', 90,  365, 'minio', 'Primary security events — CERT-In 90-day minimum'),
  ('network_flows',   'network_flows',   30,  180, 'minio', 'Network flow records'),
  ('auth_events',     'auth_events',     90,  365, 'minio', 'Authentication events'),
  ('endpoint_events', 'endpoint_events', 30,  90,  'minio', 'Endpoint telemetry'),
  ('pcap_captures',   NULL,              7,   30,  'minio', 'Raw PCAP — strictly bounded due to size'),
  ('audit_log',       'audit_log',       180, 730, 'minio', 'System audit log — 2-year retention'),
  ('sensor_health',   'sensor_health',   14,  90,  'minio', 'Sensor health metrics'),
  ('incidents',       'incidents',       365, 1825,'minio', 'Incident records — 5-year retention'),
  ('response_actions','response_actions',365, 1825,'minio', 'Response actions — 5-year retention');

-- ---------------------------------------------------------------------------
-- Alert Rules / Correlation Rules metadata
-- ---------------------------------------------------------------------------
CREATE TABLE alert_rules (
  alert_rule_id    VARCHAR(50) PRIMARY KEY,
  rule_name        VARCHAR(255) NOT NULL,
  rule_category    VARCHAR(100),  -- brute_force, lateral_movement, data_exfil, ot_anomaly, etc.
  description      TEXT,
  logic_type       VARCHAR(50),   -- threshold, sequence, ml_score, sigma, snort
  logic_definition JSONB,         -- rule parameters / sigma rule body
  severity         VARCHAR(20),
  confidence_min   DECIMAL(3,2),
  cooldown_seconds INTEGER DEFAULT 300,
  is_active        BOOLEAN DEFAULT TRUE,
  linked_model_id  UUID REFERENCES ml_models(model_id),
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TRIGGER trg_alert_rules_updated_at
  BEFORE UPDATE ON alert_rules
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();
