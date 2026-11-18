# VaultX Central Security Backend API Documentation
**Manufacturing-Aware Hybrid NIDS for Bharat Electronics Components Pvt. Ltd. (BECPL), Pune**

> **Version:** 2.0.0 (Phase 2 Deliverable)  
> **Target Enterprise:** Bharat Electronics Components Pvt. Ltd. (Bhosari MIDC, Pune, Maharashtra)  
> **Base URL:** `http://10.10.70.5:8000/api/v1` (Production Security VLAN 70) / `http://localhost:8000/api/v1` (Digital Twin)  
> **Interactive Documentation:** Swagger UI: `/docs` | ReDoc: `/redoc` | OpenAPI 3.1.0 Spec: `/openapi.json`  

---

## 1. Architectural Overview & Authentication

VaultX Phase 2 exposes a modular, asynchronous REST API running on **FastAPI** and **Python 3.15**, orchestrating the event ingestion pipeline, hybrid detection engines (Random Forest + Isolation Forest + Suricata), 7-way identity registry, cross-VLAN correlation, and policy-driven OT containment.

### 1.1 Authentication Schemes
The API supports two authentication mechanisms across all private endpoints:
1. **API Key Header:** `X-API-Key: <api_key>`
2. **HTTP Bearer Token:** `Authorization: Bearer <token>`

Every request is audited with a request-scoped correlation identifier (`X-Correlation-ID`) and response latency header (`X-Response-Time-Ms`).

### 1.2 Five-Tier Role-Based Access Control (RBAC)
User permissions are strictly scoped to operational personas at BECPL:

| Role | Key Tokens / Identifiers | Typical Department | Permitted Capabilities |
|---|---|---|---|
| **ANALYST** | `vaultx-analyst-key`, `analyst-token` | SOC Operations | Read-only inspection of incidents, blast radius graphs, AI investigation summaries, threat intel, risk scores, baselines, and model evaluations. |
| **OPERATOR** | `vaultx-operator-key`, `operator-token` | SOC Operations | All ANALYST permissions + create incidents, update incident lifecycle statuses, propose containment actions, trigger on-demand inference, test feature vectors, schedule retraining jobs. |
| **APPROVER** | `vaultx-approver-key`, `approver-token` | Operations Management / Plant Ops | All OPERATOR permissions + authorize non-OT containment actions with 6-digit MFA token; act as secondary approver for OT containment; approve maintenance windows. |
| **SECURITY_MANAGER** | `vaultx-manager-key`, `manager-token` | Cybersecurity Leadership | All APPROVER permissions + authorize OT containment actions (under Two-Person Rule), execute emergency containment, rollback containment actions, promote ML candidate models to production. |
| **ADMIN** | `vaultx-admin-key`, `admin-token` | System Administration | Unrestricted root access; pipeline stream configuration; database maintenance and user provisioning. |

---

## 2. Role Permissions Matrix

| Endpoint | Method | Path | Minimum Role Required |
|---|:---:|---|---|
| **Health Check** | `GET` | `/health` | `ANALYST` |
| **Sensor Telemetry** | `GET` | `/health/sensors` | `ANALYST` |
| **Pipeline Lag** | `GET` | `/health/pipeline` | `OPERATOR` |
| **Prometheus Exporter** | `GET` | `/metrics` | *Public / Scraper* |
| **List Incidents** | `GET` | `/incidents` | `ANALYST` |
| **Create Incident** | `POST` | `/incidents` | `OPERATOR` |
| **Get Incident Detail** | `GET` | `/incidents/{id}` | `ANALYST` |
| **Update Incident Status** | `PATCH` | `/incidents/{id}/status` | `OPERATOR` |
| **Incident Timeline** | `GET` | `/incidents/{id}/timeline` | `ANALYST` |
| **Incident Blast Radius** | `GET` | `/incidents/{id}/blast-radius` | `ANALYST` |
| **AI Investigation** | `GET` | `/incidents/{id}/investigation` | `ANALYST` |
| **Containment Modes** | `GET` | `/containment/modes` | `ANALYST` |
| **Propose Containment** | `POST` | `/containment/propose` | `OPERATOR` |
| **List Actions** | `GET` | `/containment/actions` | `ANALYST` |
| **Approve Action (IT)** | `POST` | `/containment/actions/{id}/approve` | `APPROVER` |
| **Approve Action (OT)** | `POST` | `/containment/actions/{id}/approve` | `SECURITY_MANAGER` (+ 2nd Approver) |
| **Execute Action** | `POST` | `/containment/actions/{id}/execute` | `OPERATOR` |
| **Rollback Action** | `POST` | `/containment/actions/{id}/rollback` | `SECURITY_MANAGER` |
| **List Firewall Rules** | `GET` | `/containment/firewall/rules` | `ANALYST` |
| **Delete Firewall Rule** | `DELETE` | `/containment/firewall/rules/{rule_id}` | `SECURITY_MANAGER` |
| **Vulnerabilities Catalog** | `GET` | `/threat-intel/vulnerabilities` | `ANALYST` |
| **CVE Detail** | `GET` | `/threat-intel/vulnerabilities/{cve_id}` | `ANALYST` |
| **CISA KEV Catalog** | `GET` | `/threat-intel/kev` | `ANALYST` |
| **Asset Exposure** | `GET` | `/threat-intel/assets/{asset_id}/exposure` | `ANALYST` |
| **Threat IP Blocklist** | `GET` | `/threat-intel/blocklist` | `ANALYST` |
| **JA3 Fingerprint Check** | `POST` | `/threat-intel/check-ja3` | `ANALYST` |
| **Identity Registry** | `GET` | `/identity/registry` | `ANALYST` |
| **Active Sessions** | `GET` | `/identity/sessions/active` | `ANALYST` |
| **Identity Profile** | `GET` | `/identity/profiles/{identity_id}` | `ANALYST` |
| **AI Agent Telemetry** | `GET` | `/identity/agents/telemetry` | `ANALYST` |
| **Vendor Compliance** | `GET` | `/identity/vendor/compliance` | `ANALYST` |
| **Zone Risk Scores** | `GET` | `/risk/zones` | `ANALYST` |
| **Criticality Matrix** | `GET` | `/risk/assets/criticality` | `ANALYST` |
| **Risk Recommendations** | `GET` | `/risk/recommendations` | `ANALYST` |
| **OT Safety Status** | `GET` | `/risk/ot-safety` | `ANALYST` |
| **Model Registry** | `GET` | `/models` | `ANALYST` |
| **Evaluation Report** | `GET` | `/models/{model_id}/evaluation` | `ANALYST` |
| **Promote Model** | `POST` | `/models/{model_id}/promote` | `SECURITY_MANAGER` |
| **Trigger Retraining** | `POST` | `/models/train` | `OPERATOR` |
| **Ingestion Status** | `GET` | `/ingestion/status` | `ANALYST` |
| **Stream Lag** | `GET` | `/ingestion/lag` | `ANALYST` |
| **Ingestion Control** | `POST` | `/ingestion/control` | `OPERATOR` |
| **Real-time Inference** | `POST` | `/detection/inference` | `ANALYST` |
| **Test Feature Vectors** | `POST` | `/detection/test-features` | `OPERATOR` |
| **Asset Baseline** | `GET` | `/behavioural/baselines/{asset_id}` | `ANALYST` |
| **Deviation Query** | `POST` | `/behavioural/deviations/query` | `ANALYST` |
| **Maintenance Windows** | `GET` | `/behavioural/maintenance-windows` | `ANALYST` |
| **Schedule Window** | `POST` | `/behavioural/maintenance-windows` | `APPROVER` |

---

## 3. Endpoints Detail

### 3.1 Health & Distributed Sensor Telemetry

#### `GET /api/v1/health`
Returns consolidated system health across PostgreSQL, Redis Streams, and ingestion pipeline.
- **Headers:** `X-API-Key: vaultx-analyst-key`
- **Response `200 OK`:**
  ```json
  {
    "status": "healthy",
    "timestamp": "2026-11-18T05:30:00Z",
    "uptime_seconds": 14250.2,
    "database": {
      "connected": true,
      "latency_ms": 1.45,
      "pool_size": 10,
      "active_connections": 3,
      "pending_migrations": 0,
      "version": "PostgreSQL 15.4 (TimescaleDB / becpl_nids)"
    },
    "redis": {
      "connected": true,
      "latency_ms": 0.82,
      "used_memory_human": "14.8M",
      "connected_clients": 6,
      "total_streams": 6
    },
    "pipeline": {
      "events_ingested_total": 142850,
      "events_per_second": 245.8,
      "dedup_ratio": 0.18,
      "normalization_latency_ms": 0.65,
      "enrichment_latency_ms": 0.42,
      "active_backpressure": false,
      "backpressure_threshold": 5000
    },
    "sensors_online": 7,
    "sensors_total": 7,
    "system_version": "VaultX Phase 2 v2.0.0 (BECPL Bhosari MIDC)"
  }
  ```

#### `GET /api/v1/health/sensors`
Returns heartbeats, throughput, and packet drop percentages from passive sensors across VLAN 10 through 70.
- **Response `200 OK`:** Array of `SensorHealth` objects.

#### `GET /metrics`
Exposes Prometheus text formatted scrape metrics for Grafana dashboard integration:
- `vaultx_uptime_seconds` (gauge)
- `vaultx_events_ingested_total` (counter)
- `vaultx_queue_depth{stream="..."}` (gauge)
- `vaultx_sensors_online{status="..."}` (gauge)
- `vaultx_active_incidents{severity="..."}` (gauge)

---

### 3.2 Security Incidents & Blast Radius Forensics

#### `GET /api/v1/incidents`
Lists security incidents with query filters.
- **Query Parameters:**
  * `severity` (`critical`, `high`, `medium`, `low`)
  * `status` (`open`, `investigating`, `contained`, `resolved`, `closed`)
  * `zone` (e.g. `Manufacturing OT`, `Corporate IT`)
  * `limit` (default: 50)
  * `offset` (default: 0)

#### `GET /api/v1/incidents/{incident_id}/blast-radius`
Generates directed graph of compromised nodes, lateral hops, and exposed assets.
- **Response `200 OK`:**
  ```json
  {
    "incident_id": "c1a10006-0000-0000-0000-000000000006",
    "root_cause_asset": "ENG-WS-002",
    "total_nodes_at_risk": 4,
    "ot_boundary_threatened": true,
    "critical_assets_exposed": ["OT-PLC-001", "OT-HMI-001"],
    "nodes": [
      {
        "id": "ENG-WS-002",
        "label": "Firmware Dev Workstation",
        "type": "workstation",
        "vlan_id": 20,
        "zone_name": "Engineering & Firmware",
        "criticality": "high",
        "compromised": true,
        "risk_score": 92.0
      },
      {
        "id": "OT-PLC-001",
        "label": "SMT Line 1 OpenPLC Runtime",
        "type": "plc",
        "vlan_id": 30,
        "zone_name": "Manufacturing OT",
        "criticality": "critical",
        "compromised": false,
        "risk_score": 85.0
      }
    ],
    "edges": [
      {
        "source": "ENG-WS-002",
        "target": "OT-PLC-001",
        "protocol": "Modbus TCP",
        "port": 502,
        "traffic_direction": "outbound",
        "observed_bytes": 1420,
        "suspicious": true
      }
    ]
  }
  ```

#### `GET /api/v1/incidents/{incident_id}/investigation`
Returns AI-synthesized narrative briefing, root-cause hypothesis, and OT safety evaluation.

---

### 3.3 OT-Safe Containment & Approval Workflow

#### `GET /api/v1/containment/modes`
Inspects active containment operating mode:
- `MODE_1_MONITOR_ONLY`: Passive monitoring only.
- `MODE_2_AUTO_ISOLATE_NON_OT`: Auto-isolation for Corporate IT and DMZ. OT assets protected by mandatory human gate.
- `MODE_3_HUMAN_APPROVAL_REQUIRED`: Default production mode; requires MFA authorization for all containment.
- `MODE_4_STRICT_ZERO_TRUST`: Emergency perimeter lockdown.

#### `POST /api/v1/containment/propose`
Proposes an isolation action (e.g. host quarantine, firewall IP block, account disable).
- **Request Body:**
  ```json
  {
    "incident_id": "INC-2026-006",
    "action_type": "isolate",
    "target_asset_id": "OT-PLC-001",
    "target_ip": "10.10.30.10",
    "justification": "Modbus write tampering detected on assembly line controller",
    "isolation_method": "vlan_quarantine",
    "quarantine_vlan": 70
  }
  ```

#### `POST /api/v1/containment/actions/{action_id}/approve`
Authorizes an action using a 6-digit TOTP token.
- **For OT Assets (VLAN 30):**
  * Requires `SECURITY_MANAGER` role.
  * Enforces **Two-Person Rule**: requires `second_approver_username`.
- **Request Body:**
  ```json
  {
    "mfa_code": "849201",
    "second_approver_username": "anita_deshmukh_plant_ops",
    "approval_notes": "Concurred with Plant Operations Head. Secondary SMT line ready.",
    "break_glass": false
  }
  ```

#### `POST /api/v1/containment/actions/{action_id}/execute`
Deploys firewall ACL rules or shifts switch port to quarantine VLAN.

#### `POST /api/v1/containment/actions/{action_id}/rollback`
Reverses enforcement action and restores normal connectivity. Requires `SECURITY_MANAGER` or `ADMIN`.

---

### 3.4 Threat Intelligence & Vulnerability Management

#### `GET /api/v1/threat-intel/vulnerabilities`
Searches vulnerability catalog. Specifically correlates BECPL's target vulnerable assets:
- `CORP-WS-004` → `CVE-2020-0796` (SMBGhost, CVSS 10.0, CISA KEV)
- `ENG-WS-002` → `CVE-2016-10009` (OpenSSH agent arbitrary library execution)
- `MES-SERVER` → `CVE-2018-1000656` (Flask Jinja2 template injection)
- `FIRMWARE-STORAGE` → `CVE-2019-9511` (nginx HTTP/2 Data Drip DoS)

#### `POST /api/v1/threat-intel/check-ja3`
Checks TLS client handshake hash against known threat actor signatures (e.g. Cobalt Strike, Sliver).
- **Request Body:**
  ```json
  {
    "ja3_hash": "6734f37431670b3ab4292b8f60f29984"
  }
  ```
- **Response `200 OK`:**
  ```json
  {
    "ja3_hash": "6734f37431670b3ab4292b8f60f29984",
    "matched_threat": true,
    "threat_name": "Cobalt Strike HTTPS Beacon",
    "malware_family": "CobaltStrike",
    "confidence": 0.98,
    "first_seen_in_network": false,
    "is_whitelisted": false
  }
  ```

---

### 3.5 7-Way Multi-Source Identity & Session Compliance

#### `GET /api/v1/identity/registry`
Returns principals across the 7 classifications:
1. `HUMAN_USER` (Employees, engineers, operators)
2. `SERVICE_ACCOUNT` (Database backups, Active Directory sync)
3. `AUTOMATION_WORKLOAD` (Celery background workers, CI/CD runners)
4. `AI_AGENT` (Visual defect inspection models, autonomous agents)
5. `INDUSTRIAL_DEVICE` (PLCs, RTUs, smart energy meters)
6. `THIRD_PARTY_IDENTITY` (Maintenance vendors, logistics APIs)
7. `UNKNOWN_IDENTITY` (Unclassified rogue/DHCP devices)

#### `GET /api/v1/identity/vendor/compliance`
Audits vendor remote access against BECPL policy (4-hour session limit, MFA enforcement, zone scope).

---

### 3.6 Dynamic Risk Assessment & OT Safety

#### `GET /api/v1/risk/zones`
Section-level risk scores across all 6 manufacturing zones:
- `Corporate IT` (VLAN 10)
- `Engineering & Firmware` (VLAN 20)
- `Manufacturing OT` (VLAN 30)
- `Warehouse & Logistics` (VLAN 40)
- `DMZ & Vendor Access` (VLAN 50)
- `Cloud & External Integrations` (VLAN 60)

#### `GET /api/v1/risk/ot-safety`
Verifies that industrial interlocks prevent automated disconnections on active manufacturing lines.

---

### 3.7 Machine Learning Model Registry & Governance

#### `GET /api/v1/models`
Lists registered ML models (Random Forest classifier `v1.2.0`, Isolation Forest anomaly detector `v1.0.1`).

#### `GET /api/v1/models/{model_id}/evaluation`
Returns holdout test set performance metrics (Macro F1, FPR, latency) and top contributing SHAP features.

#### `POST /api/v1/models/{model_id}/promote`
Promotes candidate model to active production inference engine. Requires `SECURITY_MANAGER` role.

#### `POST /api/v1/models/train`
Triggers the 13-step continuous retraining pipeline offline using updated baseline and analyst feedback.

---

## 4. End-to-End Critical Workflows (Curl Examples)

### Workflow 1: Incident Triage & Blast Radius Query
Query active incidents and inspect lateral exposure into OT:
```bash
# 1. Fetch open incidents in OT or Engineering
curl -X GET "http://localhost:8000/api/v1/incidents?status=open" \
  -H "X-API-Key: vaultx-analyst-key"

# 2. Inspect blast radius for SMT Line incident
curl -X GET "http://localhost:8000/api/v1/incidents/INC-2026-006/blast-radius" \
  -H "X-API-Key: vaultx-analyst-key"
```

---

### Workflow 2: Proposing a Containment Action
SOC Operator proposes network isolation of a suspicious firmware engineering workstation:
```bash
curl -X POST "http://localhost:8000/api/v1/containment/propose" \
  -H "X-API-Key: vaultx-operator-key" \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-2026-006",
    "action_type": "isolate",
    "target_asset_id": "ENG-WS-002",
    "target_ip": "10.10.20.31",
    "justification": "Unauthorized Modbus write command initiated toward SMT Line 1 PLC",
    "isolation_method": "vlan_quarantine",
    "quarantine_vlan": 70
  }'
```

---

### Workflow 3: Approving Containment with 6-Digit MFA & OT Two-Person Rule
Security Manager authorizes OT boundary isolation in coordination with Plant Operations Head:
```bash
curl -X POST "http://localhost:8000/api/v1/containment/actions/<ACTION_ID>/approve" \
  -H "X-API-Key: vaultx-manager-key" \
  -H "Content-Type: application/json" \
  -d '{
    "mfa_code": "938210",
    "second_approver_username": "anita_deshmukh_plant_ops",
    "approval_notes": "Concurred with Plant Operations Head. Secondary SMT line ready.",
    "break_glass": false
  }'
```

---

### Workflow 4: Inspecting OT Safety Status & Active Interlocks
Verify that shopfloor production line interlocks are active and unviolated:
```bash
curl -X GET "http://localhost:8000/api/v1/risk/ot-safety" \
  -H "X-API-Key: vaultx-analyst-key"
```

---

### Workflow 5: Real-Time Machine Learning Inference on Flow Feature Vector
Run on-demand multi-class prediction with SHAP explainability:
```bash
curl -X POST "http://localhost:8000/api/v1/detection/inference" \
  -H "X-API-Key: vaultx-analyst-key" \
  -H "Content-Type: application/json" \
  -d '{
    "flow_features": {
      "protocol": "Modbus TCP",
      "flow_bytes_per_sec": 1420.0,
      "total_fwd_packets": 12,
      "total_bwd_packets": 8
    },
    "source_ip": "10.10.20.31",
    "destination_ip": "10.10.30.10"
  }'
```

---

## 5. Error Codes & HTTP Response Schemas

| Status Code | Error Classification | Description |
|---|---|---|
| `200 OK` | Success | Request succeeded. Response body contains requested resource. |
| `201 Created` | Resource Created | Resource created (e.g. incident created, containment action proposed). |
| `202 Accepted` | Async Job Accepted | Asynchronous job scheduled (e.g. offline model retraining). |
| `400 Bad Request` | Validation Error | Malformed parameters or invalid MFA verification format (must be 6 digits). |
| `401 Unauthorized` | Missing / Invalid Auth | Missing or invalid API key or Bearer token. |
| `403 Forbidden` | RBAC Access Denied | Authenticated identity lacks required role permissions for the endpoint. |
| `404 Not Found` | Resource Not Found | Target incident, action, model, or CVE does not exist in local datastore. |
| `422 Unprocessable` | Safety Policy Violation | OT Two-Person Rule violation (missing required secondary approver). |
| `500 Internal Error` | Server Exception | Unhandled internal exception; includes `correlation_id` in response JSON. |

### Standard Error Response Body
```json
{
  "error": "HTTPException",
  "status_code": 403,
  "message": "Access forbidden: User 'analyst_pooja' with role 'ANALYST' does not have required permissions (['APPROVER', 'SECURITY_MANAGER', 'ADMIN']).",
  "correlation_id": "4d5e6f7a-8b9c-0d1e-2f3a-4b5c6d7e8f9a"
}
```
