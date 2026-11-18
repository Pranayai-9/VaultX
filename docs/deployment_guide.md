# VaultX Full-Platform Deployment & Operations Guide

> **Document Version:** 3.0 (Full Platform — Phases 1, 2 & 3)  
> **Applies To:** 7-VLAN Digital Twin, PostgreSQL/Redis Data Foundation, Central Security Backend API, Real-Time WebSockets, React Industrial SOC Command Dashboard & 10-Scenario Validation Suite  
> **Target System:** Bharat Electronics Components Pvt. Ltd. (BECPL), Bhosari MIDC, Pune, Maharashtra  

---

## 1. System Prerequisites

Verify that the host machine meets all hardware and software requirements before starting the VaultX platform:

| Component | Minimum Version | Verification Command | Notes |
|---|---|---|---|
| **Operating System** | Windows 11 (PowerShell 5.1+/7+ & WSL2) or Linux (Ubuntu 22.04 LTS / Debian 12) | `uname -a` / `$PSVersionTable` | Linux kernel 5.15+ recommended for passive sensors |
| **Python** | 3.11+ (verified through 3.15) | `python --version` | Required for FastAPI backend, ML engines, ingestion, and validation suite |
| **Node.js & pnpm** | Node.js 20+ and pnpm 9+ | `node --version; pnpm --version` | Required for React 19 + TypeScript SOC Command Dashboard (`frontend/`) |
| **Docker Engine** | 24.0.0+ | `docker --version` | Assign ≥ 12 GB RAM for full 7-VLAN digital twin |
| **Docker Compose** | v2.20.0+ | `docker compose version` | Must support Compose `include:` directive |
| **Git** | 2.34.0+ | `git --version` | Repository & worktree management |
| **Network Ports** | `5173`, `8000`, `3000`, `1880`, `5010`, `5020`, `5030`, `5432`, `6379`, `8080`, `9000`, `9001` | `netstat -ano` (Win) / `ss -tulpn` (Linux) | `5173` (SOC UI) and `8000` (Backend API + WS) are required for local dev |

---

## 2. Repository Setup & Environment Configuration

### 2.1 Clone Repository
```powershell
git clone https://github.com/becpl/vaultx.git
cd vaultx
```

### 2.2 Infrastructure Environment Variables (`docker/.env`)
Copy or verify `docker/.env`:
```powershell
# Windows PowerShell
if (-not (Test-Path docker\.env)) { Copy-Item docker\.env.example docker\.env }
```

Key infrastructure settings in `docker/.env`:
```dotenv
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

# Digital Twin External Port Mappings
NIDS_PORT=8070
GITEA_PORT=3000
JENKINS_PORT=8080
NODERED_PORT=1880
OPENPLC_MODBUS_PORT=502
MODBUS_PORT=5020
MES_PORT=5010
WMS_PORT=5030
```

### 2.3 Backend & Frontend Runtime Variables
- **Backend (`backend/main.py`):**
  - `VAULTX_ENABLE_LIVE_DB=false` *(default)*: Launches immediately using VaultX's high-fidelity in-memory BECPL digital-twin state—ideal for rapid SOC UI demos and CI testing without Docker.
  - `VAULTX_ENABLE_LIVE_DB=true`: Connects via `asyncpg` and `redis.asyncio` to live PostgreSQL (`POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`) and Redis (`REDIS_HOST`, `REDIS_PORT`).
- **Frontend (`frontend/.env.local`, optional):**
  - `VITE_API_BASE_URL=http://localhost:8000/api/v1` *(default)*
  - `VITE_WS_URL=ws://localhost:8000/ws` *(default)*

---

## 3. Step-by-Step Full-Platform Deployment

### Step 1: Start the Security & Data Foundation Stack (Docker)
Launch PostgreSQL 15, Redis Streams, and MinIO S3 on the isolated VLAN 70 management bridge (`net_security`, `172.20.70.0/24`):

```powershell
docker compose -f docker/compose/security.yml up -d
docker compose -f docker/compose/security.yml ps
```

Confirm `vaultx-security-db`, `vaultx-redis-streams`, and `vaultx-minio-storage` report status `Up`.

### Step 2: Apply All Phase 1 Schemas & Phase 2–3 Database Migrations
Execute the base schemas followed by all Phase 2 migrations sequentially:

```powershell
# Phase 1 Core Schemas, Monthly Time-Series Partitions, Incidents, Indexes & Seed Data
Get-Content database/schema/01_core_tables.sql | docker exec -i vaultx-security-db psql -U vaultx_user -d vaultx
Get-Content database/schema/02_time_series_tables.sql | docker exec -i vaultx-security-db psql -U vaultx_user -d vaultx
Get-Content database/schema/03_incident_tables.sql | docker exec -i vaultx-security-db psql -U vaultx_user -d vaultx
Get-Content database/schema/04_indexes.sql | docker exec -i vaultx-security-db psql -U vaultx_user -d vaultx
Get-Content database/schema/05_seed_data.sql | docker exec -i vaultx-security-db psql -U vaultx_user -d vaultx

# Phase 2 Behavioural, Containment, Threat Intel & Correlation Migrations
Get-Content database/migrations/002_phase2_tables.sql | docker exec -i vaultx-security-db psql -U vaultx_user -d vaultx
Get-Content database/migrations/003_phase2_containment.sql | docker exec -i vaultx-security-db psql -U vaultx_user -d vaultx
Get-Content database/migrations/004_phase2_threat_correlation.sql | docker exec -i vaultx-security-db psql -U vaultx_user -d vaultx
```

Verify table registration inside `becpl_nids`:
```powershell
docker exec -it vaultx-security-db psql -U vaultx_user -d vaultx -c "SELECT table_name FROM information_schema.tables WHERE table_schema='becpl_nids' ORDER BY table_name;"
```

### Step 3: Start the 7-VLAN Manufacturing Digital Twin
```powershell
docker compose -f docker/docker-compose.yml up -d
```

This creates all 7 isolated Docker bridge networks (`172.20.10.0/24` through `172.20.70.0/24`) and launches Corporate IT (ERP, LDAP, DNS), Engineering (Gitea, Jenkins, Firmware Storage), Manufacturing OT (OpenPLC Modbus TCP, Node-RED HMI, MES API, Industrial Sensors), Warehouse (WMS, Supplier API), DMZ (WireGuard VPN, Bastion), and Cloud mock services.

### Step 4: Start the VaultX Central Security Backend API & Ingestion Workers
Install Python dependencies and start the central FastAPI server (`port 8000`):

```powershell
# Install Python dependencies
pip install -r backend/ingestion/requirements.txt

# Option A: Fast Digital-Twin Fallback Mode (no live DB required)
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Option B: Live PostgreSQL + Redis Streams Mode
$env:VAULTX_ENABLE_LIVE_DB="true"
$env:POSTGRES_HOST="localhost"
$env:POSTGRES_USER="vaultx_user"
$env:POSTGRES_PASSWORD="vaultx_db_2024"
$env:POSTGRES_DB="vaultx"
$env:REDIS_HOST="localhost"
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

To run the asynchronous Redis Streams event ingestion pipeline alongside the API in Live Mode (separate terminal):
```powershell
python -m backend.ingestion.pipeline
```

### Step 5: Launch the Industrial SOC Command Dashboard (`frontend/`)
Start the React 19 + TypeScript + Tailwind CSS frontend using `pnpm`:

```powershell
cd frontend
pnpm install
pnpm dev
```

The Vite development server starts on **[http://localhost:5173](http://localhost:5173)** and connects automatically to the FastAPI backend (`http://localhost:8000/api/v1`) and live WebSocket telemetry stream (`ws://localhost:8000/ws`). If the backend is offline, the frontend seamlessly falls back to its built-in BECPL simulation provider (`frontend/src/services/mockData.ts`) so all 13 SOC views remain interactive.

To create and preview an optimised production bundle:
```powershell
cd frontend
pnpm run build
pnpm preview
```

---

## 4. Real-Time WebSockets & Live SOC Streaming

VaultX streams real-time security alerts, incident state transitions, containment proposals, sensor heartbeats, and interactive scenario animations to the SOC Command Dashboard via WebSockets (`frontend/src/services/websocket.ts`):

- **Endpoint:** `ws://localhost:8000/ws` (or `wss://<host>/ws` behind TLS reverse proxy in production)
- **Event Channels Streamed:**
  - `incident.created` / `incident.updated` — Live correlation incidents (`INC-2026-001`–`INC-2026-007`)
  - `detection.alert` — Real-time Suricata, Random Forest, Isolation Forest, LOTL, and IIoT loophole alerts
  - `containment.proposal` / `containment.executed` / `containment.rolled_back` — HITL MFA and Two-Person OT approval updates
  - `sensor.health` — 6-sensor telemetry heartbeats, packet drop rates, and Redis backpressure status
  - `scenario.telemetry` — Live animated event frames for the Multi-Agent Workflow Operational Demo (`/agent-demo`)
- **Resilience:** Implements exponential-backoff auto-reconnection and automatic simulation-mode fallback when no live backend socket is reachable.

---

## 5. Service Verification Checklist, URLs & RBAC Credentials

### 5.1 Platform Endpoints

| Subsystem | Service Name | Local URL / Port | Credentials / Auth | Verify |
|---|---|---|---|:---:|
| **Phase 3 SOC UI** | Industrial SOC Command Dashboard (13 Views) | [http://localhost:5173](http://localhost:5173) | Built-in role switcher | [ ] |
| **Phase 2–3 API** | VaultX Central Backend (Swagger / OpenAPI 3.1) | [http://localhost:8000/docs](http://localhost:8000/docs) | `X-API-Key` / `Bearer` token | [ ] |
| **Phase 2–3 API** | Backend Readiness & Health | [http://localhost:8000/healthz](http://localhost:8000/healthz) | Public readiness probe | [ ] |
| **Observability** | Prometheus Metrics Exporter | [http://localhost:8000/metrics](http://localhost:8000/metrics) | OpenMetrics scrape | [ ] |
| **Real-Time Bus** | WebSocket Telemetry Stream | `ws://localhost:8000/ws` | Connected by SOC UI | [ ] |
| **Security Tier** | MinIO S3 Console | [http://localhost:9001](http://localhost:9001) | `minio` / `minio123` | [ ] |
| **Security Tier** | Redis Streams | `localhost:6379` | VLAN 70 internal | [ ] |
| **Engineering** | Gitea Firmware Git / Jenkins CI | `:3000` / `:8080` | Lab setup wizard / container log | [ ] |
| **Manufacturing OT** | Node-RED HMI / OpenPLC Modbus / MES API | `:1880` / `:5020` / `:5010/status` | Modbus Unit ID `1` | [ ] |
| **Warehouse** | WMS Simulator API | [http://localhost:5030/inventory](http://localhost:5030/inventory) | Lab mode | [ ] |

### 5.2 Development RBAC API Keys (`X-API-Key` Header)

| Role | API Key | Bearer Token | Capabilities |
|---|---|---|---|
| `ANALYST` | `vaultx-analyst-key` | `analyst-token` | Read-only SOC inspection |
| `OPERATOR` | `vaultx-operator-key` | `operator-token` | Create/update incidents, propose containment, trigger inference |
| `APPROVER` | `vaultx-approver-key` | `approver-token` | Approve IT containment (with 6-digit MFA `1xxxxx`), secondary OT approver |
| `SECURITY_MANAGER` | `vaultx-manager-key` | `manager-token` | Primary OT containment approval (Two-Person Rule), rollback, ML model promotion |
| `ADMIN` | `vaultx-admin-key` | `admin-token` | Full platform administration |

---

## 6. Running Traffic Simulation, Tests, Model Training & Validation

### 6.1 Synthetic Traffic & Attack Scenario Injection
```powershell
# Generate legitimate BECPL background traffic
python telemetry/traffic_simulation/normal_traffic_gen.py --rate 10

# Trigger a controlled MITRE-mapped attack scenario (1 through 7)
python telemetry/traffic_simulation/attack_scenario_gen.py --scenario 1
```

### 6.2 Offline ML Model Training (Anti-Poisoning Pipeline)
```powershell
# Retrain Random Forest, Isolation Forest, Feature Scaler & SHAP Explainer offline
.\backend\detection\train_models.ps1

# Or invoke the 14-stage continuous improvement pipeline CLI directly
python -m backend.containment.model_pipeline --stage data_quality
python -m backend.containment.model_pipeline --stage train --dataset-version 1
```

### 6.3 Running Unit Tests & the 10-Scenario Phase 3 Validation Suite
```powershell
# 1. Run full backend unit & integration tests (API, detection, behavioural, containment, correlation, loopholes)
python -m pytest backend/tests/ -v

# 2. Run the 10-Scenario End-to-End Validation & Burst Stress Suite (exports backend/validation/validation_results.json)
python -m backend.validation.run_all_tests

# 3. Verify 100% pass rate via pytest
python -m pytest backend/tests/test_e2e_validation.py -v

# 4. Verify Frontend TypeScript & Vite production build
cd frontend; pnpm run build; cd ..
```

---

## 7. Maintenance & Troubleshooting FAQ

### 7.1 Container or Local Port Conflicts
- **Symptom:** `bind: address already in use` on port `8000`, `8080`, or `5173`.
- **Resolution:** Override Docker port mappings in `docker/.env` (e.g., `JENKINS_PORT=8088`), or pass `--port 8001` to `uvicorn` and `--port 5174` to `pnpm dev`.

### 7.2 WebSocket Connection Refused in SOC Dashboard
- **Symptom:** Dashboard header shows `Simulation Fallback` instead of `Live Connected`.
- **Resolution:** Ensure `uvicorn backend.main:app --host 0.0.0.0 --port 8000` is running and accessible, verify `VITE_API_BASE_URL` and `VITE_WS_URL` match the backend port, and check browser DevTools console for CORS or proxy issues.

### 7.3 OT Containment Approval Returns `403 Forbidden` or `422 Unprocessable Content`
- **Symptom:** Approving containment on VLAN 30 assets (`OT-PLC-001`, `OT-HMI-001`, `OT-MES01`) is blocked.
- **Resolution:** This is an **intentional safety invariant** (`OT_ALWAYS_HUMAN_APPROVAL = True`). Ensure the primary approver authenticates with `SECURITY_MANAGER` credentials (`vaultx-manager-key`), supplies a valid 6-digit MFA code (`1xxxxx`), and includes a distinct `second_approver_username` (Plant Operations Head) to satisfy the Two-Person Rule.

### 7.4 Redis Streams Backpressure Alerts
- **Symptom:** `BackpressureAlert` emitted to `alerts:operational` or ML queue degrades to statistical-only mode.
- **Resolution:** Redis Streams caps memory at `MAXLEN ~ 100000`; `BACKPRESSURE_THRESHOLD = 10,000` and `ML_QUEUE_BACKPRESSURE_THRESHOLD = 500` protect pipeline stability. Scale `WORKER_COUNT` in `backend/ingestion/config.py` or verify `backend/ingestion/pipeline.py` consumers are actively executing `XACK`.

### 7.5 PostgreSQL Partition Pruning Performance
- **Symptom:** Event history queries slow down over multi-week retention windows.
- **Resolution:** Always filter `becpl_nids.security_events` and `network_flows` with explicit `timestamp` bounds (`WHERE timestamp >= NOW() - INTERVAL '7 days'`) so PostgreSQL prunes non-matching monthly partitions using BRIN indexes.
