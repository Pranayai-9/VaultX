# VaultX Deployment & Operations Guide

> **Document Version:** 1.0  
> **Applies To:** Phase 1 Digital Twin, Database Cluster & Sensor Telemetry Pipeline  
> **Target System:** Bharat Electronics Components Pvt. Ltd. (BECPL) Environment

---

## 1. System Prerequisites

Before deploying the VaultX environment, verify that the host system satisfies the following dependencies:

| Component | Minimum Version | Verification Command | Notes |
|---|---|---|---|
| **Operating System** | Linux (Ubuntu 22.04 LTS / Debian 12) or Windows 11 with WSL2 | `uname -a` | Linux kernel 5.15+ recommended |
| **Docker Engine** | 24.0.0+ | `docker --version` | Ensure Docker daemon has at least 12 GB RAM assigned in WSL2/Desktop |
| **Docker Compose** | v2.20.0+ | `docker compose version` | Must support Compose specification `include:` directive |
| **Python** | 3.11.0+ | `python3 --version` | Required for running local ingestion scripts, sensors, and CLI tools |
| **Git** | 2.34.0+ | `git --version` | For repository management |
| **Network Ports** | Available ports: 3000, 1880, 5020, 8070, 8080, 9000, 9001 | `netstat -ano` (Win) / `ss -tulpn` (Linux) | Ensure local development ports do not conflict |

---

## 2. Repository Setup & Environment Configuration

### 2.1 Clone Repository
```bash
git clone https://github.com/becpl/vaultx.git
cd vaultx
```

### 2.2 Configure Environment Variables
Copy the template configuration file:
```bash
# On Linux / macOS / WSL
cp docker/.env.example docker/.env

# On Windows PowerShell
Copy-Item docker\.env.example docker\.env
```

Review and adjust credentials in `docker/.env` as necessary for your deployment:

```dotenv
# =============================================================================
# VaultX Environment Configuration
# =============================================================================

# Security Database (PostgreSQL 15)
SEC_DB_NAME=vaultx
SEC_DB_USER=vaultx_user
SEC_DB_PASSWORD=vaultx_db_2024
SEC_DB_PORT=5432

# Redis Streams Event Transport
REDIS_PORT=6379

# MinIO S3 Object Storage
MINIO_ROOT_USER=minio
MINIO_ROOT_PASSWORD=minio123
MINIO_SEC_PORT=9000
MINIO_SEC_CONSOLE_PORT=9001

# Core Service External Port Mappings
NIDS_PORT=8070
GITEA_PORT=3000
JENKINS_PORT=8080
NODERED_PORT=1880
OPENPLC_MODBUS_PORT=502
MODBUS_PORT=5020
MES_PORT=5010
WMS_PORT=5030
```

---

## 3. Step-by-Step Deployment Procedure

### Step 1: Initialize Docker Networks
VaultX defines 7 dedicated isolated Docker bridge networks simulating the 7 enterprise and manufacturing VLANs. When running docker compose, they are created automatically:
- `net_corporate` (172.20.10.0/24) — VLAN 10 Corporate IT
- `net_engineering` (172.20.20.0/24) — VLAN 20 Engineering & Firmware
- `net_ot` (172.20.30.0/24) — VLAN 30 Manufacturing OT
- `net_warehouse` (172.20.40.0/24) — VLAN 40 Warehouse & Logistics
- `net_dmz` (172.20.50.0/24) — VLAN 50 DMZ & Vendor Access
- `net_cloud` (172.20.60.0/24) — VLAN 60 Cloud & External Integrations
- `net_security` (172.20.70.0/24) — VLAN 70 Security Management

### Step 2: Start the Security & Data Foundation Stack
Start the core storage and messaging tier (PostgreSQL, Redis Streams, MinIO):

```bash
docker compose -f docker/compose/security.yml up -d
```

Verify that the security services are healthy:
```bash
docker compose -f docker/compose/security.yml ps
```

You should see `vaultx-security-db`, `vaultx-redis-streams`, and `vaultx-minio-storage` running in state `Up`.

### Step 3: Execute Database Schema Migrations
Initialize the `becpl_nids` schema, core reference tables, time-series partitions, and indexes:

```bash
# Execute schemas sequentially into security-db
docker exec -i vaultx-security-db psql -U vaultx_user -d vaultx < database/schema/01_core_tables.sql
docker exec -i vaultx-security-db psql -U vaultx_user -d vaultx < database/schema/02_time_series_tables.sql
docker exec -i vaultx-security-db psql -U vaultx_user -d vaultx < database/schema/03_incident_tables.sql
docker exec -i vaultx-security-db psql -U vaultx_user -d vaultx < database/schema/04_indexes.sql
```

Verify schema installation:
```bash
docker exec -it vaultx-security-db psql -U vaultx_user -d vaultx -c "\dn"
docker exec -it vaultx-security-db psql -U vaultx_user -d vaultx -c "SELECT table_name FROM information_schema.tables WHERE table_schema='becpl_nids';"
```

### Step 4: Start Full Manufacturing Simulation Services
Launch the complete digital twin environment across all remaining segments:

```bash
docker compose -f docker/docker-compose.yml up -d
```

This brings up:
- Corporate IT: ERP Server, LDAP Directory, File Server, Internal DNS
- Engineering: Gitea Git repository, Jenkins CI, Firmware Storage
- Manufacturing OT: OpenPLC runtime, Node-RED HMI, MES API Server, Modbus TCP simulator, synthetic industrial sensors
- Warehouse: WMS server, Inventory DB, Barcode terminal simulator, Supplier API
- DMZ: WireGuard VPN gateway, Reverse proxy, Edge boundary simulator
- Cloud: Simulated S3 cloud storage, external integration mock endpoints

---

## 4. Service Verification Checklist & Access URLs

Once all containers are running, verify service accessibility using a browser or `curl`:

| Subsystem | Service Name | Internal IP | External URL / Port | Default Credentials | Verification Status |
|---|---|---|---|---|:---:|
| **Security** | VaultX NIDS Central API | 172.20.70.10 | [http://localhost:8070/health](http://localhost:8070/health) | N/A (Token in Phase 2) | [ ] |
| **Security** | MinIO Object Storage Console | 172.20.70.13 | [http://localhost:9001](http://localhost:9001) | `minio` / `minio123` | [ ] |
| **Security** | Redis Streams | 172.20.70.12 | Port 6379 | No auth (Internal VLAN 70) | [ ] |
| **Engineering** | Gitea Git Repository | 172.20.20.10 | [http://localhost:3000](http://localhost:3000) | Setup wizard on 1st run | [ ] |
| **Engineering** | Jenkins Build CI | 172.20.20.11 | [http://localhost:8080](http://localhost:8080) | Initial admin token in logs | [ ] |
| **OT** | Node-RED Industrial HMI | 172.20.30.11 | [http://localhost:1880](http://localhost:1880) | Anonymous (Lab mode) | [ ] |
| **OT** | OpenPLC Modbus TCP | 172.20.30.10 | Port 502 / Port 5020 | Modbus unit ID: 1 | [ ] |
| **OT** | MES Simulator API | 172.20.30.12 | [http://localhost:5010/status](http://localhost:5010/status) | N/A | [ ] |
| **Warehouse** | WMS Simulator API | 172.20.40.10 | [http://localhost:5030/inventory](http://localhost:5030/inventory) | N/A | [ ] |

---

## 5. Starting Telemetry Collection & Traffic Generation

### 5.1 Start Ingestion Service (Local Development Mode)
Install Python dependencies and start the ingestion service daemon:
```bash
cd backend/ingestion
pip install -r requirements.txt
python log_ingestion_service.py
```
The service will subscribe to Redis stream `events:raw`, parse inbound Zeek/Suricata payloads, enrich them against the `assets` table, and insert them into PostgreSQL `becpl_nids.security_events`.

### 5.2 Start Background Legitimate Traffic Simulator
To generate normal background manufacturing and corporate flows:
```bash
python telemetry/traffic_simulation/normal_traffic_gen.py --rate 10
```

### 5.3 Trigger Controlled Attack Scenario (Validation Test)
To simulate MITRE-mapped attack techniques (e.g., Scenario 1: Compromised Vendor VPN pivot into OT):
```bash
python telemetry/traffic_simulation/attack_scenario_gen.py --scenario 1
```

Confirm that alerts appear in the database:
```bash
docker exec -it vaultx-security-db psql -U vaultx_user -d vaultx -c "SELECT timestamp, event_type, source_ip, destination_ip, severity, detection_source FROM becpl_nids.security_events ORDER BY timestamp DESC LIMIT 10;"
```

---

## 6. Maintenance & Troubleshooting FAQ

### 6.1 Container Port Conflicts
**Symptom:** `Error starting userland proxy: listen tcp4 0.0.0.0:8080: bind: address already in use`  
**Resolution:** Jenkins, NIDS Central, or local web servers might clash. Open `docker/.env` and override the host port mapping (e.g. `JENKINS_PORT=8088`).

### 6.2 Redis Streams Lag or Memory Expiry
**Symptom:** Sensor agents report Redis connection failures or stream message dropping.  
**Resolution:** By default, Redis Streams in VaultX uses `MAXLEN ~ 100000` to prevent unconstrained memory growth. Ensure the `log_ingestion_service.py` is actively consuming and acknowledging messages using consumer groups.

### 6.3 TimescaleDB / Declarative Partition Pruning
**Symptom:** Event queries slow down after multiple weeks of continuous traffic generation.  
**Resolution:** Verify queries include explicit `timestamp` predicates (`WHERE timestamp >= NOW() - INTERVAL '7 days'`). This allows the PostgreSQL planner to eliminate non-relevant monthly partitions from disk scanning.
