##############################################################################
# local.zeek — Zeek Site-Local Configuration for VaultX BECPL Sensor Nodes
# Bharat Electronics Components Pvt. Ltd. — Manufacturing-Aware Hybrid NIDS
# Deploy to: /opt/zeek/share/zeek/site/local.zeek
##############################################################################

##############################################################################
# 1. Standard Framework Loading
##############################################################################

# Connection logging (foundation for all correlation)
@load base/protocols/conn

# DNS monitoring — critical for detecting C2 and data exfiltration over DNS
@load base/protocols/dns

# HTTP monitoring — ERP, WMS, internal web apps, vendor portal
@load base/protocols/http

# SSL/TLS monitoring — certificate anomalies, unusual cipher suites
@load base/protocols/ssl
@load base/files/x509

# File analysis framework — detects malware downloads, firmware tampering
@load base/frameworks/files

# Notice framework — structured alerting (Zeek notices vs. Suricata alerts)
@load base/frameworks/notice

# Intel framework — IOC feed ingestion (placeholder; feeds loaded separately)
@load base/frameworks/intel

# Signature framework — lightweight pattern matching within Zeek
@load base/frameworks/signatures

# Software detection — tracks observed application versions
@load policy/frameworks/software/version-changes
@load policy/frameworks/software/vulnerable

##############################################################################
# 2. Additional Protocol Analyzers
##############################################################################

# SMTP — monitors email traffic on corporate VLAN
@load base/protocols/smtp

# FTP — legacy file transfers in warehouse / engineering segments
@load base/protocols/ftp

# SSH — administrative access monitoring
@load base/protocols/ssh

# DHCP — tracks IP assignments; feeds the IP-to-identity mapping
@load base/protocols/dhcp

# SNMP — network device monitoring traffic
# @load base/protocols/snmp   # enable if SNMP is in scope

# MySQL / PostgreSQL — database query monitoring (ERP segment)
# @load policy/protocols/mysql   # enable when analyzer is available

##############################################################################
# 3. Detection Policy Scripts
##############################################################################

# Scan detection (horizontal and vertical port scans)
@load policy/misc/scan

# Detect clear-text passwords in protocols like FTP, HTTP Basic Auth
@load policy/protocols/ftp/detect-bruteforcing
@load policy/protocols/ssh/detect-bruteforcing

# Track SSH authentication — ties into lateral movement detection
@load policy/protocols/ssh/geo-data
@load policy/protocols/ssh/interesting-hostnames

# SSL certificate anomaly detection
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/expiring-certs
@load policy/protocols/ssl/weak-keys

# File extraction (hashes only by default; full extract on request)
@load policy/frameworks/files/hash-all-files
@load policy/frameworks/files/extract-all-files

# Notice suppression — throttle repeated notices for same src
@load policy/frameworks/notice/community-id

##############################################################################
# 4. JSON Log Output Format
##############################################################################

# Output ALL logs as JSON — required for EVE-JSON pipeline compatibility
# and for the sensor_agent.py Redis publisher
redef LogAscii::use_json = T;

# Timestamps in ISO 8601 format for consistent parsing across the pipeline
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# Include all fields (don't strip empty values) for complete event context
redef LogAscii::empty_field = "null";

# Use gzip compression for rotated logs (reduces disk usage ~70% on sensors)
redef Log::default_rotation_postprocessor_cmd = "gzip";

##############################################################################
# 5. Log Retention Settings
##############################################################################

# Active log directory (before rotation)
redef Log::default_logdir = "/var/log/zeek/logs";

# Rotation interval: every 60 minutes (matches zeekctl LogRotationInterval)
redef Log::default_rotation_interval = 1hr;

# Log expiry handled by zeekctl LogExpireInterval = 90 (days)
# Sensor keeps 90 days locally; central NIDS server retains indefinitely.

##############################################################################
# 6. Network Definition (BECPL VLAN Subnets)
##############################################################################

# HOME_NET equivalent — all BECPL internal networks
redef Site::local_nets = {
    172.20.10.0/24,   # VLAN 10 Corporate IT
    172.20.20.0/24,   # VLAN 20 Engineering & Firmware
    172.20.30.0/24,   # VLAN 30 OT / Manufacturing
    172.20.40.0/24,   # VLAN 40 Warehouse & Logistics
    172.20.50.0/24,   # VLAN 50 DMZ & Vendor Access
    172.20.70.0/24,   # VLAN 70 Security Management
};

# Private subnets that are NOT BECPL internal (e.g. cloud VPCs)
# redef Site::private_nets += { 10.0.0.0/8, 192.168.0.0/16 };

##############################################################################
# 7. Intel Framework Configuration (Placeholder — feeds loaded separately)
##############################################################################

# Intel feed file locations (populated by threat-intel pipeline)
# redef Intel::read_files += {
#     "/opt/zeek/intel/ip_blocklist.txt",
#     "/opt/zeek/intel/domain_blocklist.txt",
# };

##############################################################################
# 8. Custom BECPL Scripts
##############################################################################

# Asset identity enrichment — correlates IPs to asset registry identities
@load site/becpl_identity_enrichment

# OT network monitoring — Modbus TCP detection and anomaly notices
@load site/becpl_ot_monitor

# Lateral movement detection — multi-host connection rate tracking
@load site/becpl_lateral_movement

##############################################################################
# 9. Misc Tuning
##############################################################################

# Extend connection timeout for OT protocols (Modbus sessions can be long)
redef tcp_session_timer = 300 secs;
redef udp_session_timer = 120 secs;

# Increase state table size for high-throughput segments
redef table_expire_interval = 10 secs;

# Suppress reporting of internal→internal connections for well-known services
# (reduce noise; conn.log still records everything)
redef Notice::policy += {
    [$pred(n: Notice::Info) = {
        return n$note == SSH::Password_Guessing &&
               n$src in Site::local_nets;
    },
    $action = Notice::ACTION_LOG]
};

##############################################################################
# End of local.zeek
##############################################################################
