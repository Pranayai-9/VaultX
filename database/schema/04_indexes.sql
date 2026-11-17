-- VaultX NIDS - Performance Indexes
-- BECPL (Bharat Electronics Components Pvt. Ltd.), Pune
-- Strategy: B-Tree for equality/range, BRIN for append-only time-series, GIN for JSONB/arrays

SET search_path TO becpl_nids;

-- ===========================================================================
-- security_events indexes
-- ===========================================================================

-- BRIN on timestamp (very efficient for append-only partitioned tables)
CREATE INDEX idx_se_timestamp_brin ON security_events USING BRIN (timestamp)
  WITH (pages_per_range = 128);

-- B-Tree on timestamp for exact range queries
CREATE INDEX idx_se_timestamp ON security_events (timestamp DESC);

-- Network address lookups
CREATE INDEX idx_se_source_ip       ON security_events (source_ip);
CREATE INDEX idx_se_destination_ip  ON security_events (destination_ip);

-- Asset lookups
CREATE INDEX idx_se_source_asset    ON security_events (source_asset_id) WHERE source_asset_id IS NOT NULL;
CREATE INDEX idx_se_dest_asset      ON security_events (destination_asset_id) WHERE destination_asset_id IS NOT NULL;

-- Alerting / triage
CREATE INDEX idx_se_severity        ON security_events (severity, timestamp DESC);
CREATE INDEX idx_se_processing_status ON security_events (processing_status) WHERE processing_status = 'pending';

-- Incident correlation
CREATE INDEX idx_se_incident_id     ON security_events (incident_id) WHERE incident_id IS NOT NULL;

-- Identity correlation
CREATE INDEX idx_se_identity_id     ON security_events (identity_id) WHERE identity_id IS NOT NULL;

-- Detection source / event type
CREATE INDEX idx_se_event_type      ON security_events (event_type, timestamp DESC);
CREATE INDEX idx_se_detection_source ON security_events (detection_source);

-- GIN on JSONB evidence for full-document search
CREATE INDEX idx_se_evidence_gin    ON security_events USING GIN (evidence);
CREATE INDEX idx_se_provenance_gin  ON security_events USING GIN (event_provenance);

-- ===========================================================================
-- network_flows indexes
-- ===========================================================================

-- BRIN on timestamp
CREATE INDEX idx_nf_timestamp_brin  ON network_flows USING BRIN (timestamp)
  WITH (pages_per_range = 128);

CREATE INDEX idx_nf_timestamp       ON network_flows (timestamp DESC);

-- IP lookups
CREATE INDEX idx_nf_src_ip          ON network_flows (src_ip);
CREATE INDEX idx_nf_dst_ip          ON network_flows (dst_ip);

-- Zone-to-zone queries (key for OT/IT segmentation analytics)
CREATE INDEX idx_nf_zone_pair       ON network_flows (source_zone, destination_zone, timestamp DESC);

-- Asset lookups
CREATE INDEX idx_nf_source_asset    ON network_flows (source_asset_id) WHERE source_asset_id IS NOT NULL;
CREATE INDEX idx_nf_dest_asset      ON network_flows (destination_asset_id) WHERE destination_asset_id IS NOT NULL;

-- Protocol / port analytics
CREATE INDEX idx_nf_protocol_port   ON network_flows (protocol, dst_port);

-- Zeek UID for cross-log correlation
CREATE INDEX idx_nf_zeek_uid        ON network_flows (zeek_uid) WHERE zeek_uid IS NOT NULL;

-- ===========================================================================
-- auth_events indexes
-- ===========================================================================

-- BRIN on timestamp
CREATE INDEX idx_ae_timestamp_brin  ON auth_events USING BRIN (timestamp)
  WITH (pages_per_range = 128);

CREATE INDEX idx_ae_timestamp       ON auth_events (timestamp DESC);

-- Principal lookups
CREATE INDEX idx_ae_principal_name  ON auth_events (principal_name, timestamp DESC);
CREATE INDEX idx_ae_identity_id     ON auth_events (identity_id) WHERE identity_id IS NOT NULL;

-- Success/failure filtering (brute force detection)
CREATE INDEX idx_ae_success         ON auth_events (success, timestamp DESC);
CREATE INDEX idx_ae_failure         ON auth_events (source_ip, success, timestamp DESC)
  WHERE success = FALSE;

-- Source IP correlation
CREATE INDEX idx_ae_source_ip       ON auth_events (source_ip);

-- ===========================================================================
-- endpoint_events indexes
-- ===========================================================================

-- BRIN on timestamp
CREATE INDEX idx_ee_timestamp_brin  ON endpoint_events USING BRIN (timestamp)
  WITH (pages_per_range = 128);

CREATE INDEX idx_ee_timestamp       ON endpoint_events (timestamp DESC);

-- Asset / host lookups
CREATE INDEX idx_ee_asset_id        ON endpoint_events (asset_id, timestamp DESC);

-- Event type filtering
CREATE INDEX idx_ee_event_type      ON endpoint_events (event_type, timestamp DESC);

-- Process hunting
CREATE INDEX idx_ee_process_name    ON endpoint_events (process_name) WHERE process_name IS NOT NULL;
CREATE INDEX idx_ee_image_hash      ON endpoint_events (image_hash) WHERE image_hash IS NOT NULL;

-- Detection flags (GIN for array containment)
CREATE INDEX idx_ee_detection_flags_gin ON endpoint_events USING GIN (detection_flags);

-- GIN on raw event JSONB
CREATE INDEX idx_ee_raw_event_gin   ON endpoint_events USING GIN (raw_event);

-- ===========================================================================
-- sensor_health indexes
-- ===========================================================================

CREATE INDEX idx_sh_timestamp_brin  ON sensor_health USING BRIN (timestamp)
  WITH (pages_per_range = 128);

CREATE INDEX idx_sh_sensor_id       ON sensor_health (sensor_id, timestamp DESC);
CREATE INDEX idx_sh_status          ON sensor_health (status) WHERE status IN ('degraded','critical','offline');

-- ===========================================================================
-- incidents indexes
-- ===========================================================================

CREATE INDEX idx_inc_severity       ON incidents (severity, detected_at DESC);
CREATE INDEX idx_inc_status         ON incidents (status) WHERE status IN ('open','investigating','contained');
CREATE INDEX idx_inc_reference      ON incidents (incident_reference);
CREATE INDEX idx_inc_assigned_to    ON incidents (assigned_to) WHERE assigned_to IS NOT NULL;
CREATE INDEX idx_inc_ioc_gin        ON incidents USING GIN (ioc_list);
CREATE INDEX idx_inc_affected_assets_gin ON incidents USING GIN (affected_assets);

-- ===========================================================================
-- response_actions indexes
-- ===========================================================================

CREATE INDEX idx_ra_incident_id     ON response_actions (incident_id);
CREATE INDEX idx_ra_status          ON response_actions (status) WHERE status IN ('pending','executing');
CREATE INDEX idx_ra_target_asset    ON response_actions (target_asset_id) WHERE target_asset_id IS NOT NULL;

-- ===========================================================================
-- audit_log indexes
-- ===========================================================================

CREATE INDEX idx_al_timestamp_brin  ON audit_log USING BRIN (timestamp)
  WITH (pages_per_range = 128);

CREATE INDEX idx_al_actor           ON audit_log (actor, timestamp DESC);
CREATE INDEX idx_al_action          ON audit_log (action, timestamp DESC);
CREATE INDEX idx_al_target          ON audit_log (target_table, target_id);

-- ===========================================================================
-- Core reference table indexes
-- ===========================================================================

CREATE INDEX idx_assets_ip          ON assets (ip_address);
CREATE INDEX idx_assets_mac         ON assets (mac_address);
CREATE INDEX idx_assets_vlan        ON assets (vlan_id);
CREATE INDEX idx_assets_criticality ON assets (criticality) WHERE is_active = TRUE;

CREATE INDEX idx_identities_principal ON identities (principal_name);
CREATE INDEX idx_identities_type    ON identities (principal_type) WHERE is_active = TRUE;

CREATE INDEX idx_vulns_asset        ON vulnerabilities (asset_id);
CREATE INDEX idx_vulns_severity     ON vulnerabilities (severity) WHERE patch_applied = FALSE;
CREATE INDEX idx_vulns_cve          ON vulnerabilities (cve_id) WHERE cve_id IS NOT NULL;
