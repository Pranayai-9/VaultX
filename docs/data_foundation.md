# Data Foundation & Architecture Specification — VaultX

> **Document Version:** 1.0  
> **Target Audience:** Security Data Engineers, Database Administrators, Backend Developers  
> **Schema Namespace:** `becpl_nids` (PostgreSQL 15+)

---

## 1. Overview of the Data Architecture

The VaultX Data Foundation serves as the central operational repository for all network security telemetry, asset inventories, identity mappings, detection alerts, and audit logs. The architecture harmonizes high-throughput streaming event ingestion with analytical relational queries, enforcing strict tenant separation, auditability, and data retention lifecycles.

```
+--------------------------------------------------------------------------------------------------+
|                                    DATA FOUNDATION ARCHITECTURE                                  |
|                                                                                                  |
|   +-------------------+    +--------------------+    +--------------------+                      |
|   | Passive Zeek Node |    |   Suricata Node    |    |  Sysmon / auditd   |                      |
|   +---------+---------+    +---------+----------+    +---------+----------+                      |
|             |                        |                         |                                 |
|             +------------------------+-------------------------+                                 |
|                                      |                                                           |
|                                      v                                                           |
|                       +------------------------------+                                           |
|                       |  Redis Streams Transport     |                                           |
|                       |  (Decoupled Ingestion Bus)   |                                           |
|                       |  `events:raw`, `events:sim`  |                                           |
|                       +--------------+---------------+                                           |
|                                      |                                                           |
|                                      v                                                           |
|                       +------------------------------+                                           |
|                       | Log Ingestion Service        |                                           |
|                       | (Enrichment, Schema Check)   |                                           |
|                       +--------------+---------------+                                           |
|                                      |                                                           |
|             +------------------------+------------------------+                                  |
|             |                                                 |                                  |
|             v                                                 v                                  |
|   +------------------------------------+    +------------------------------------+               |
|   | PostgreSQL 15 Relational Core      |    | MinIO S3 Object Storage            |               |
|   | Schema: `becpl_nids`               |    | - `vaultx-pcaps` (Triggered PCAPs) |               |
|   | - 01 Core Reference Tables         |    | - `vaultx-models` (ML Artifacts)   |               |
|   | - 02 Time-Series (Monthly Partns)  |    | - `vaultx-datasets` (Raw Datasets) |               |
|   | - 03 Incidents & Audit Logs        |    | - `vaultx-archives` (Cold JSONL)   |               |
|   | - 04 Optimized B-Tree/BRIN/GIN     |    +------------------------------------+               |
|   +------------------------------------+                                                         |
+--------------------------------------------------------------------------------------------------+
```

---

## 2. Database Schema Overview

The database layer is modularized into 5 SQL files located in `database/schema/`:

| File | Purpose | Key Tables Created | Partitioning Strategy |
|---|---|---|---|
| `01_core_tables.sql` | Reference master data: network segments, assets, identities, vendors, policies | `network_zones`, `assets`, `identities`, `vendors`, `communication_rules`, `vulnerabilities`, `isolation_policies`, `ml_models` | Standard relational tables with primary keys, unique constraints, and foreign key relations |
| `02_time_series_tables.sql` | High-frequency append-only security telemetry and flow observations | `security_events`, `network_flows`, `auth_events`, `endpoint_events`, `sensor_health` | **Declarative Monthly Range Partitioning** on `timestamp` |
| `03_incident_tables.sql` | Operational triage, human-in-the-loop responses, and system compliance logs | `incidents`, `response_actions`, `audit_log`, `retention_policies` | `audit_log` is partitioned monthly; `incidents` and `response_actions` are relational |
| `04_indexes.sql` | Storage engine indexing and query optimization | Trigram indexes (`pg_trgm`), BRIN indexes on timestamps, GIN indexes on JSONB | Optimized for rapid time-window filtering and JSON payload traversal |
| `05_seed_data.sql` | Initial bootstrap configuration | Seed rows for all 7 network zones, isolation safety policies, and retention policies | Idempotent baseline inserts |

---

## 3. Standard Security Event Schema

All events ingested into `becpl_nids.security_events` conform to a standardized schema, ensuring uniform analytical structure regardless of whether the event originated from Zeek, Suricata, Sysmon, or an industrial sensor client.

### 3.1 Field Specification

| Field Name | Data Type | Nullable | Description | Example / Allowed Values |
|---|---|:---:|---|---|
| `event_id` | `UUID` | No | Globally unique identifier generated per event | `gen_random_uuid()` |
| `timestamp` | `TIMESTAMPTZ` | No | UTC timestamp when event occurred (Partition Key) | `2026-11-17 14:32:05.123+00` |
| `sensor_id` | `VARCHAR(50)` | Yes | Identifier of sensor node that captured traffic | `SENSOR-OT-01`, `SENSOR-CORP-01` |
| `source_ip` | `INET` | Yes | Source IPv4 or IPv6 address | `10.10.30.12` |
| `destination_ip` | `INET` | Yes | Destination IPv4 or IPv6 address | `10.10.30.10` |
| `source_port` | `INTEGER` | Yes | Source TCP/UDP port number | `49152` |
| `destination_port` | `INTEGER` | Yes | Destination TCP/UDP port number | `502` |
| `protocol` | `VARCHAR(20)` | Yes | Transport or application protocol | `TCP`, `UDP`, `Modbus`, `HTTP`, `TLS` |
| `network_zone` | `VARCHAR(50)` | Yes | Monitored network zone name | `corporate`, `engineering`, `ot`, `dmz` |
| `source_asset_id` | `VARCHAR(50)` | Yes | Enriched asset identifier for source | `ENG-WS-001`, `OT-PLC-001` |
| `destination_asset_id`| `VARCHAR(50)` | Yes | Enriched asset identifier for destination | `OT-MES-001`, `CORP-ERP-001` |
| `identity_id` | `UUID` | Yes | Foreign key to `becpl_nids.identities` | Correlated user or service identity |
| `principal_type` | `VARCHAR(50)` | Yes | Evaluated identity classification | `HUMAN_USER`, `SERVICE_ACCOUNT`, `INDUSTRIAL_DEVICE` |
| `application` | `VARCHAR(100)`| Yes | Application or daemon name | `pymodbus`, `odoo`, `sshd`, `nginx` |
| `flow_id` | `UUID` | Yes | Flow correlation identifier linking bidirectional packets | `3fa85f64-5717-4562-b3fc-2c963f66afa6` |
| `connection_duration_ms`| `BIGINT` | Yes | Total duration of flow in milliseconds | `4520` |
| `bytes_transferred` | `BIGINT` | Yes | Total bytes exchanged across connection | `1048576` |
| `packets_transferred`| `INTEGER` | Yes | Total packet count in connection | `142` |
| `encryption_metadata`| `JSONB` | Yes | TLS handshake and cipher telemetry | See Section 3.2 |
| `event_type` | `VARCHAR(50)` | No | Classification of telemetry record | `network_flow`, `alert`, `auth_event`, `policy_violation` |
| `detection_source` | `VARCHAR(50)` | No | Originating detector tool | `zeek`, `suricata`, `sysmon`, `auditd`, `synthetic` |
| `severity` | `VARCHAR(20)` | Yes | Risk severity rating | `critical`, `high`, `medium`, `low`, `informational` |
| `confidence` | `DECIMAL(5,4)`| Yes | Detector or ML model confidence score (0.0 to 1.0) | `0.9850` |
| `evidence` | `JSONB` | Yes | Raw detector payload, matched rules, signatures | See Section 3.2 |
| `processing_status` | `VARCHAR(20)` | No | Pipeline ingestion state | `pending`, `validated`, `enriched`, `alerted`, `archived` |
| `event_provenance` | `JSONB` | Yes | Audit lineage of data collection | See Section 3.2 |
| `model_version` | `VARCHAR(50)` | Yes | Identifier of ML model if evaluated | `v1.2-randomforest-xiiotid` |
| `detection_rule_version`| `VARCHAR(50)`| Yes | Version tag of Suricata / Zeek rule set | `becpl-ruleset-v2026.11` |
| `incident_id` | `UUID` | Yes | Link to `becpl_nids.incidents` if part of active case | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` |
| `response_action_id` | `UUID` | Yes | Link to `becpl_nids.response_actions` | Response record triggered by this event |

### 3.2 Detailed JSONB Sub-Objects

#### `encryption_metadata` (JSONB)
Captures unencrypted metadata from the cryptographic handshake:
```json
{
  "tls_version": "TLSv1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "sni": "update.vendor-firmware.internal",
  "cert_issuer": "CN=BECPL Internal Root CA",
  "cert_subject": "CN=update.vendor-firmware.internal",
  "ja3_fingerprint": "6734f37431670e3ab4292b8f60f29984",
  "ja3s_fingerprint": "eb1d9433e6ced5637314972a842cf5e7"
}
```

#### `evidence` (JSONB)
Stores diagnostic evidence for analysts:
```json
{
  "signature_id": 2026001,
  "signature_message": "BECPL-POLICY: Unauthorized Modbus write from non-engineering subnet",
  "modbus": {
    "function_code": 16,
    "function_name": "WRITE_MULTIPLE_REGISTERS",
    "target_register": 40001,
    "value_count": 2
  },
  "raw_packet_reference": "pcap_20261117_143205_sec01.pcap"
}
```

#### `event_provenance` (JSONB)
Tracks data lineage from sensor capture to database insert:
```json
{
  "source_system": "SENSOR-OT-01",
  "collection_method": "af-packet-zeek",
  "ingestion_agent": "vaultx-log-ingestion-v1.0",
  "raw_log_ref": "/var/log/zeek/conn.2026-11-17-14:00:00.log.gz:line:4812",
  "pipeline_latency_ms": 48
}
```

---

## 4. Partitioning & Indexing Strategy

### 4.1 Native Monthly Range Partitioning
Time-series tables (`security_events`, `network_flows`, `auth_events`, `endpoint_events`, `sensor_health`, `audit_log`) use PostgreSQL declarative partitioning:

```sql
CREATE TABLE security_events (
  event_id    UUID DEFAULT gen_random_uuid(),
  timestamp   TIMESTAMPTZ NOT NULL,
  -- ... other fields ...
  PRIMARY KEY (event_id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE TABLE security_events_2026_11 PARTITION OF security_events
  FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
```

**Operational Advantages:**
- **Partition Pruning:** Queries specifying `WHERE timestamp >= '2026-11-15' AND timestamp < '2026-11-18'` immediately bypass all partitions outside November 2026.
- **Zero-Cost Retention Purging:** Dropping aged data is executed as `DROP TABLE becpl_nids.security_events_2026_08`, releasing disk space instantly with zero table-locking or vacuum overhead.

### 4.2 Index Optimization Matrix
- **BRIN (Block Range Index):** Applied to `timestamp` columns across all partitioned tables. BRIN indexes occupy less than 1% of the space of B-tree indexes on append-only time-series data.
- **B-Tree Indexes:** Applied to foreign keys and lookup targets: `source_ip`, `destination_ip`, `source_asset_id`, `severity`, and `incident_id`.
- **GIN (Generalized Inverted Index):** Applied to `evidence` and `raw_event` JSONB columns using `jsonb_path_ops`, allowing rapid indexing of deep JSON queries.
- **Trigram (`pg_trgm`):** Applied to asset hostnames and command-line fields for substring pattern matching.

---

## 5. Retention Policies & Tiered Lifecycle

Configured in `becpl_nids.retention_policies`:

| Data Category | Hot Online Retention (PostgreSQL) | Warm Archive Retention (MinIO S3) | Storage Format (Archive) | Permanent Action |
|---|:---:|:---:|---|---|
| `security_events` | 90 Days | 365 Days | Compressed Parquet / JSONL | Purge from MinIO |
| `network_flows` | 30 Days | 180 Days | Compressed Parquet | Purge from MinIO |
| `auth_events` | 90 Days | 365 Days | Compressed Parquet | Purge from MinIO |
| `endpoint_events` | 30 Days | 90 Days | Compressed JSONL | Purge from MinIO |
| `pcap_captures` | 7 Days (Local buffer) | 30 Days (Triggered only) | Standard PCAP.gz | Purge from MinIO |
| `audit_log` | 180 Days | 730 Days (2 Years) | Gzip JSONL with SHA-256 hash | Regulatory Archive |
| `sensor_health` | 14 Days | 90 Days | Compressed Parquet | Purge from MinIO |

---

## 6. Redis Streams Bus Specification

Redis Streams acts as an asynchronous, backpressure-tolerant ingestion buffer between passive sensor agents and the database ingestion worker.

### 6.1 Stream Keys & Topics

| Stream Name | Producer | Consumer | Payload Contents | Max Length Policy |
|---|---|---|---|---|
| `events:raw` | Sensor Agents (Zeek/Suricata) | `log_ingestion_service` | Un-enriched, validated detector output | `MAXLEN ~ 100000` |
| `events:endpoint` | Sysmon / auditd Collectors | `log_ingestion_service` | Endpoint process and command-line records | `MAXLEN ~ 50000` |
| `events:third_party` | VPN & Cloud Audit Simulator | `log_ingestion_service` | Authentications, API gateway accesses | `MAXLEN ~ 50000` |
| `events:simulation` | Attack / Normal Traffic Gens | `log_ingestion_service` | Synthetic lab evaluation events | `MAXLEN ~ 100000` |
| `events:processed` | `log_ingestion_service` | Phase 2 ML Engine | Fully enriched security events | `MAXLEN ~ 100000` |
| `sensor:health` | Sensor Agents | Monitoring Daemon | CPU, memory, packet drop rate | `MAXLEN ~ 10000` |

### 6.2 Consumer Groups & Backpressure Management
- Ingestion workers operate under a named Redis consumer group (`cg_vaultx_ingest`).
- Messages are consumed using `XREADGROUP GROUP cg_vaultx_ingest worker_1 COUNT 100 BLOCK 2000 STREAMS events:raw >`.
- Successful database inserts trigger `XACK events:raw cg_vaultx_ingest <message_id>`.
- If PostgreSQL slows during maintenance, Redis absorbs telemetry spikes up to 100,000 events without dropping frames on sensor nodes.

---

## 7. MinIO Object Storage Architecture

MinIO provides S3-compatible, on-premises object storage partitioned into 4 distinct buckets:

```
MinIO Object Storage Cluster (Port 9000 / 9001)
├── vaultx-pcaps/          # Incident-triggered 15-minute rolling packet captures
│   └── 2026/11/INC-001_sensor-ot-01_capture.pcap.gz
├── vaultx-models/         # Versioned ML detection model artifacts & weight vectors
│   ├── v1.0-baseline-randomforest.joblib
│   └── manifests/v1.0-sha256.json
├── vaultx-datasets/       # Curated benchmark datasets for offline retraining
│   ├── raw/ (XIIOTID, ToN_IoT, HAI, CSE-CIC-IDS2018)
│   └── processed/ (Harmonized, balanced train/test splits)
└── vaultx-archives/       # Cold exports of expired PostgreSQL partitions
    └── 2026-10/security_events_2026_10.parquet.gz
```

---

## 8. Security Controls, RBAC & Backup Procedures

### 8.1 Role-Based Access Control (RBAC) in PostgreSQL
Four dedicated database roles enforce least-privilege separation:
1. `vaultx_admin`: Full DDL and schema management privileges; restricted to DBAs.
2. `vaultx_ingest`: `INSERT` and `SELECT` rights on time-series tables; used exclusively by `log_ingestion_service.py`.
3. `vaultx_analyst`: `SELECT` privileges across all telemetry, `INSERT`/`UPDATE` on `incidents` and `response_actions`.
4. `vaultx_readonly`: Read-only access for reporting and audit reviewers.

### 8.2 Cryptographic Protection
- **In Transit:** TLS 1.3 enforced for all database connections (`sslmode=require`), HTTPS for MinIO, and TLS encryption for Redis Streams over VLAN 70.
- **At Rest:** PostgreSQL tablespace encryption or host-level LUKS/dm-crypt encryption; MinIO server-side encryption enabled (`SSE-S3`).

### 8.3 Backup & Disaster Recovery Policy
- **Hot Database Backup:** Continuous PostgreSQL Write-Ahead Log (WAL) archiving combined with daily automated `pg_dump` of the `becpl_nids` schema to an isolated offsite NAS.
- **Target Metrics for BECPL:**
  - **Recovery Point Objective (RPO):** Maximum 15 minutes of event loss.
  - **Recovery Time Objective (RTO):** Full database restore within 2 hours.
