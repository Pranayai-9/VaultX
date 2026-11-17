-- VaultX NIDS - Time-Series Event Tables
-- BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
-- Uses native PostgreSQL declarative partitioning by month (no TimescaleDB required)

SET search_path TO becpl_nids;

-- ---------------------------------------------------------------------------
-- Main Security Events Table (partitioned by month on timestamp)
-- ---------------------------------------------------------------------------
CREATE TABLE security_events (
  event_id                UUID DEFAULT gen_random_uuid(),
  timestamp               TIMESTAMPTZ NOT NULL,
  sensor_id               VARCHAR(50),
  source_ip               INET,
  destination_ip          INET,
  source_port             INTEGER,
  destination_port        INTEGER,
  protocol                VARCHAR(20),
  network_zone            VARCHAR(50),
  source_asset_id         VARCHAR(50),
  destination_asset_id    VARCHAR(50),
  identity_id             UUID,
  principal_type          VARCHAR(50),
  application             VARCHAR(100),
  flow_id                 UUID,
  connection_duration_ms  BIGINT,
  bytes_transferred       BIGINT,
  packets_transferred     INTEGER,
  encryption_metadata     JSONB,  -- {tls_version, cipher_suite, sni, cert_issuer}
  event_type              VARCHAR(50) CHECK (event_type IN (
                            'network_flow','alert','auth_event','endpoint_event',
                            'dns_event','http_event','tls_event','sensor_health',
                            'policy_violation','manual')),
  detection_source        VARCHAR(50) CHECK (detection_source IN (
                            'zeek','suricata','sysmon','auditd','windows_event',
                            'netflow','snmp','manual','synthetic')),
  severity                VARCHAR(20) CHECK (severity IN (
                            'critical','high','medium','low','informational')),
  confidence              DECIMAL(5,4) CHECK (confidence BETWEEN 0 AND 1),
  evidence                JSONB,  -- raw evidence payload, rule matches, etc.
  processing_status       VARCHAR(20) DEFAULT 'pending' CHECK (processing_status IN (
                            'pending','validated','enriched','alerted','archived','error')),
  -- Provenance / lineage
  event_provenance        JSONB,  -- {source_system, collection_method, raw_log_ref, pipeline_version}
  model_version           VARCHAR(50),
  detection_rule_version  VARCHAR(50),
  -- Incident linkage
  incident_id             UUID,
  response_action_id      UUID,
  -- Internal
  created_at              TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (event_id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Monthly partitions (extend forward as needed)
CREATE TABLE security_events_2026_10 PARTITION OF security_events
  FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE security_events_2026_11 PARTITION OF security_events
  FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE security_events_2026_12 PARTITION OF security_events
  FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE security_events_2027_01 PARTITION OF security_events
  FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE security_events_2027_02 PARTITION OF security_events
  FOR VALUES FROM ('2027-02-01') TO ('2027-03-01');
CREATE TABLE security_events_2027_03 PARTITION OF security_events
  FOR VALUES FROM ('2027-03-01') TO ('2027-04-01');

-- ---------------------------------------------------------------------------
-- Network Flow Records (Zeek conn.log / NetFlow)
-- ---------------------------------------------------------------------------
CREATE TABLE network_flows (
  flow_id              UUID DEFAULT gen_random_uuid(),
  timestamp            TIMESTAMPTZ NOT NULL,
  sensor_id            VARCHAR(50),
  src_ip               INET,
  dst_ip               INET,
  src_port             INTEGER,
  dst_port             INTEGER,
  protocol             VARCHAR(20),
  duration_ms          BIGINT,
  orig_bytes           BIGINT,
  resp_bytes           BIGINT,
  orig_packets         INTEGER,
  resp_packets         INTEGER,
  conn_state           VARCHAR(10),   -- Zeek connection state codes
  missed_bytes         BIGINT,
  history              VARCHAR(50),   -- Zeek history field
  source_asset_id      VARCHAR(50),
  destination_asset_id VARCHAR(50),
  source_zone          VARCHAR(50),
  destination_zone     VARCHAR(50),
  -- Application layer metadata
  tls_version          VARCHAR(20),
  tls_cipher           VARCHAR(100),
  tls_server_name      VARCHAR(255),
  tls_cert_subject     VARCHAR(255),
  dns_query            VARCHAR(255),
  dns_answer           TEXT[],
  dns_rcode            INTEGER,
  http_method          VARCHAR(10),
  http_host            VARCHAR(255),
  http_uri             TEXT,
  http_status          INTEGER,
  http_user_agent      TEXT,
  http_response_body_len BIGINT,
  -- Detection output
  detection_flags      TEXT[],        -- rule/model detection tags
  suricata_alert_id    VARCHAR(100),
  zeek_uid             VARCHAR(50),
  created_at           TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (flow_id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE TABLE network_flows_2026_10 PARTITION OF network_flows FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE network_flows_2026_11 PARTITION OF network_flows FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE network_flows_2026_12 PARTITION OF network_flows FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE network_flows_2027_01 PARTITION OF network_flows FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE network_flows_2027_02 PARTITION OF network_flows FOR VALUES FROM ('2027-02-01') TO ('2027-03-01');
CREATE TABLE network_flows_2027_03 PARTITION OF network_flows FOR VALUES FROM ('2027-03-01') TO ('2027-04-01');

-- ---------------------------------------------------------------------------
-- Authentication Events
-- ---------------------------------------------------------------------------
CREATE TABLE auth_events (
  auth_id          UUID DEFAULT gen_random_uuid(),
  timestamp        TIMESTAMPTZ NOT NULL,
  identity_id      UUID,
  principal_name   VARCHAR(255),
  principal_type   VARCHAR(50),
  auth_method      VARCHAR(50),   -- password, mfa_totp, certificate, api_key, sso, kerberos
  source_ip        INET,
  source_asset_id  VARCHAR(50),
  target_system    VARCHAR(100),
  target_asset_id  VARCHAR(50),
  success          BOOLEAN,
  failure_reason   VARCHAR(100),
  mfa_used         BOOLEAN,
  mfa_method       VARCHAR(50),
  session_id       VARCHAR(100),
  session_duration_s INTEGER,
  privilege_escalation BOOLEAN DEFAULT FALSE,
  event_provenance JSONB,
  raw_event        JSONB,
  PRIMARY KEY (auth_id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE TABLE auth_events_2026_10 PARTITION OF auth_events FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE auth_events_2026_11 PARTITION OF auth_events FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE auth_events_2026_12 PARTITION OF auth_events FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE auth_events_2027_01 PARTITION OF auth_events FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE auth_events_2027_02 PARTITION OF auth_events FOR VALUES FROM ('2027-02-01') TO ('2027-03-01');

-- ---------------------------------------------------------------------------
-- Endpoint Events (Sysmon / auditd / Windows Event Log)
-- ---------------------------------------------------------------------------
CREATE TABLE endpoint_events (
  endpoint_event_id  UUID DEFAULT gen_random_uuid(),
  timestamp          TIMESTAMPTZ NOT NULL,
  asset_id           VARCHAR(50),
  hostname           VARCHAR(255),
  event_type         VARCHAR(50) CHECK (event_type IN (
                       'process_create','process_terminate','network_connect',
                       'file_create','file_delete','file_modify','registry_modify',
                       'registry_create','driver_load','image_load',
                       'pipe_created','pipe_connected','wmi_event',
                       'dns_query','raw_access_read','scheduled_task',
                       'user_logon','user_logoff','privilege_use',
                       'kernel_module_load','cron_job','shell_exec')),
  process_name       VARCHAR(255),
  process_id         INTEGER,
  process_guid       UUID,
  parent_process_name VARCHAR(255),
  parent_process_id  INTEGER,
  parent_process_guid UUID,
  command_line       TEXT,
  current_directory  TEXT,
  user_name          VARCHAR(100),
  user_domain        VARCHAR(100),
  image_hash         VARCHAR(64),   -- SHA-256
  image_hash_algorithm VARCHAR(20) DEFAULT 'SHA256',
  signed             BOOLEAN,
  signature          VARCHAR(255),
  target_file        TEXT,
  target_object      TEXT,         -- registry key / pipe name
  network_dest_ip    INET,
  network_dest_port  INTEGER,
  network_protocol   VARCHAR(20),
  initiated          BOOLEAN,      -- whether connection was initiated by this process
  detection_flags    TEXT[],
  event_id_raw       INTEGER,      -- raw Windows/Sysmon event ID
  raw_event          JSONB,
  PRIMARY KEY (endpoint_event_id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE TABLE endpoint_events_2026_10 PARTITION OF endpoint_events FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE endpoint_events_2026_11 PARTITION OF endpoint_events FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE endpoint_events_2026_12 PARTITION OF endpoint_events FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE endpoint_events_2027_01 PARTITION OF endpoint_events FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE endpoint_events_2027_02 PARTITION OF endpoint_events FOR VALUES FROM ('2027-02-01') TO ('2027-03-01');

-- ---------------------------------------------------------------------------
-- Sensor Health / Telemetry
-- ---------------------------------------------------------------------------
CREATE TABLE sensor_health (
  health_id           UUID DEFAULT gen_random_uuid(),
  timestamp           TIMESTAMPTZ NOT NULL,
  sensor_id           VARCHAR(50),
  sensor_host         VARCHAR(255),
  monitored_vlan      INTEGER,
  events_per_second   DECIMAL(10,2),
  packet_drop_rate    DECIMAL(5,4),  -- 0.0000 – 1.0000
  cpu_percent         DECIMAL(5,2),
  memory_percent      DECIMAL(5,2),
  disk_free_gb        DECIMAL(10,2),
  network_rx_mbps     DECIMAL(10,2),
  network_tx_mbps     DECIMAL(10,2),
  zeek_status         VARCHAR(20) CHECK (zeek_status IN ('running','stopped','error','unknown')),
  suricata_status     VARCHAR(20) CHECK (suricata_status IN ('running','stopped','error','unknown')),
  redis_lag_ms        INTEGER,
  postgres_lag_ms     INTEGER,
  queue_depth         INTEGER,
  status              VARCHAR(20) CHECK (status IN ('healthy','degraded','critical','offline')),
  alert_sent          BOOLEAN DEFAULT FALSE,
  PRIMARY KEY (health_id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE TABLE sensor_health_2026_10 PARTITION OF sensor_health FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE sensor_health_2026_11 PARTITION OF sensor_health FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE sensor_health_2026_12 PARTITION OF sensor_health FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE sensor_health_2027_01 PARTITION OF sensor_health FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE sensor_health_2027_02 PARTITION OF sensor_health FOR VALUES FROM ('2027-02-01') TO ('2027-03-01');
