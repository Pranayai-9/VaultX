# Architectural Security Principles — VaultX

> **Document Version:** 1.0  
> **Status:** Ratified Architecture Baseline  
> **Applicability:** VaultX NIDS Core Design for Bharat Electronics Components Pvt. Ltd. (BECPL)

---

## Executive Summary

Designing an intrusion detection and cyber defence architecture for a mid-tier Indian electronics manufacturing MSME presents unique constraints that invalidate standard enterprise IT security assumptions:
- **Zero Production Interruption Tolerance:** Manufacturing lines (SMT pick-and-place, AOI testing, reflow ovens) operate on tight delivery schedules under automotive Tier-2 contracts. An unwarranted automated network disconnect can cause thermal damage, defective PCB batches, and substantial financial penalties.
- **Resource Constraints:** The entire IT and plant operations team comprises 3–4 personnel. Complex, cloud-heavy SIEMs requiring dedicated 24/7 SOC staffing are unsustainable.
- **Hybrid Protocol Spectrum:** Environments blend commodity IT protocols (HTTP, TLS, SMB, LDAP) with deterministic industrial automation protocols (Modbus TCP, OPC-UA) and proprietary vendor engineering channels.

To address these real-world challenges, VaultX is founded on **five core architectural principles**:

```
+---------------------------------------------------------------------------------------+
|                         VAULTX CORE ARCHITECTURAL PRINCIPLES                          |
|                                                                                       |
|   1. DISTRIBUTED PASSIVE SENSORS       2. MULTI-SOURCE IDENTITY CLASSIFICATION        |
|      No central packet routing;           Packets alone lie; correlate endpoint +     |
|      passive TAPs + Redis Streams         auth logs to classify 7 identity types      |
|                                                                                       |
|   3. BOUNDED TIERED RETENTION          4. OFFLINE RETRAINING PIPELINE                 |
|      Zero raw PCAP bloat;                 No online auto-poisoning; deterministic,    |
|      incident-triggered PCAP captures     cryptographically signed model releases     |
|                                                                                       |
|   5. POLICY-DRIVEN OT ISOLATION                                                       |
|      Mandatory Human-in-the-Loop for OT assets; automated quarantine for IT only     |
+---------------------------------------------------------------------------------------+
```

---

## Principle 1: Distributed Passive Sensors

### 1.1 The Anti-Pattern: Centralized Inline Packet Routing
A common architectural flaw in legacy intrusion systems is routing all enterprise and industrial traffic through a centralized inline inspection appliance or firewall. In a manufacturing MSME, this creates severe failure modes:
1. **Single Point of Failure (SPOF):** If the central appliance crashes or undergoes reboot cycles during firmware updates, entire production lines halt.
2. **Deterministic Latency Invalidation:** Industrial protocols like Modbus TCP and real-time Ethernet require predictable round-trip times (<10 ms). Any inline queuing or deep packet inspection introduces jitter, triggering PLC watchdog timeouts and emergency halts.
3. **Bandwidth Saturation:** Aggregating inter-VLAN and intra-VLAN camera, engineering CAD/CAM, and factory traffic over a single central server exceeds standard 1 Gbps backbones.

### 1.2 The VaultX Solution: Distributed Passive Taps & SPAN Ports
VaultX places dedicated, lightweight passive sensor nodes at the edge of each network segment (VLAN 10 Corporate IT, VLAN 20 Engineering, VLAN 30 OT, VLAN 40 Warehouse, VLAN 50 DMZ).

```
   Physical Network Link (e.g., SMT Switch to MES)
   =======================[ Copper TAP ]=======================> Normal Flow
                                |
                                | (Receive-Only Optical/Copper Split)
                                v
                     +--------------------+
                     | Passive Sensor Node|
                     | - Interface in     |
                     |   promiscuous mode |
                     | - No IP bound      |
                     | - Zeek + Suricata  |
                     +---------+----------+
                               |
                               | Filtered JSON Security Events (Over VLAN 70)
                               v
                     +--------------------+
                     | Redis Streams Bus  |
                     +--------------------+
```

- **Zero Inline Footprint:** Sensor capture interfaces operate strictly in promiscuous mode with **no IP address bound**, making them invisible on the monitored link and physically incapable of injecting packets into industrial buses.
- **Local Protocol Parsing:** Sensors run Zeek (for connection state tracking, protocol decoding, and asset enrichment) and Suricata (for signature-based threat detection).
- **Asynchronous Event Transport:** Pre-filtered security notices and flow records are transmitted as lightweight JSON objects over a separate, dedicated out-of-band management network (VLAN 70) to a central **Redis Streams** instance.
- **Architectural Trade-offs:**
  - *Trade-off:* Passive sensors cannot directly drop a malicious packet mid-flight (unlike an IPS).
  - *Justification:* In industrial manufacturing, false-positive drops are exponentially more expensive than detection-triggered quarantine. Defense is achieved by notifying the isolation engine rather than disrupting the wire inline.

---

## Principle 2: Identity Classification Beyond Network Packets

### 2.1 The Network Packet Fallacy
Network packets reveal IP addresses, MAC addresses, ports, and protocols. However, in modern enterprise and manufacturing environments:
- DHCP and dynamic container allocation cause IP reassignment.
- NAT boundaries and internal reverse proxies mask true originator endpoints.
- Stolen service credentials or compromised vendor VPN tunnels appear as legitimate source IPs.
- Network traffic alone cannot answer: *Is this connection initiated by a human engineer, an automated CI/CD pipeline, an AI script, or an industrial PLC?*

### 2.2 Multi-Source Telemetry Correlation
VaultX fuses three independent telemetry streams to establish authentic workload identity:
1. **Network Flows & Protocol Decoding:** Zeek connection metadata, TLS SNI, HTTP headers, Modbus function codes.
2. **Endpoint Process Telemetry:** Sysmon (Windows) and auditd (Linux) event logs tracking parent-child process lineages, executing binaries, and command-line arguments.
3. **Authentication & Directory Logs:** Active Directory / OpenLDAP authentication events, WireGuard/OpenVPN connection logs, and service account token usage.

```
       Network Sensor               Endpoint Collector           Authentication Gateway
       (Zeek / Suricata)             (Sysmon / auditd)               (LDAP / VPN Logs)
              |                              |                               |
       [ IP / Port / SNI ]          [ PID / Executable / CLI ]      [ User Principal / MFA ]
              |                              |                               |
              +------------------------------+-------------------------------+
                                             |
                                             v
                           +------------------------------------+
                           |    Identity Correlation Engine     |
                           |    (VaultX Ingestion & ML Core)    |
                           +-----------------+------------------+
                                             |
                                             v
                                 Assigned Identity Record
                               (One of 7 Validated Classes)
```

### 2.3 The 7 Identity Classifications & Evidence Criteria

| Identity Classification | Definition & Scope | Primary Telemetry Sources | Required Evidence Threshold |
|---|---|---|---|
| `HUMAN_USER` | Interactive human operator using desktop/laptop workstations | Sysmon Event ID 1 (explorer.exe parent), LDAP successful login, interactive keystroke/session tokens | Active session in directory service + endpoint interactive shell / GUI parent process. |
| `SERVICE_ACCOUNT` | Non-human credentials executing daemon processes (e.g., ERP-to-DB sync) | Static account names (`svc_*`), background systemd services, Windows services (services.exe parent) | Fixed source IP/host, non-interactive login type, predictable cron/timer cadence. |
| `AUTOMATION_WORKLOAD` | Automated scripts, CI/CD pipelines (Jenkins, Gitea actions), scheduled tasks | Jenkins job runners, container orchestration tags, python/curl execution with specific user-agents | Endpoint process genealogy tracing to scheduler or CI daemon + temporary build tokens. |
| `AI_AGENT` | Autonomous local LLM agents or analytical reasoning models executing queries | Designated API tokens, custom HTTP header `X-VaultX-Agent-ID`, process command-line flags | Cryptographic agent token + approved agent host IP binding in `assets` registry. |
| `INDUSTRIAL_DEVICE` | Embedded OT controllers, PLCs, HMIs, and smart sensors on shopfloor | Modbus TCP, EtherNet/IP, proprietary serial-over-IP, hardware MAC OUI matching industrial vendors | Hardware MAC registered in OT asset table, communication restricted to industrial protocols (port 502/44818). |
| `THIRD_PARTY_IDENTITY` | External maintenance contractors, logistics partners (DTDC/BlueDart), cloud vendors | DMZ VPN gateway logs, vendor tenant certificates, reverse proxy authenticated headers | WireGuard/OpenVPN authenticated identity with active vendor contract reference in `vendors` table. |
| `UNKNOWN_IDENTITY` | Any workload failing to meet evidence thresholds for the above 6 classes | Unregistered IP/MAC, anomalous process execution without directory corroboration | Default fallback classification; triggers immediate high-priority alert and scrutiny. |

---

## Principle 3: Bounded, Configurable Data Retention

### 3.1 The Storage Economics of Manufacturing MSMEs
At a 1 Gbps continuous network link, raw packet capture (PCAP) consumes approximately:
$$\text{Storage Rate} \approx 100 \text{ MB/s} \approx 6 \text{ GB/minute} \approx 8.64 \text{ TB/day}$$
Storing full PCAPs indefinitely is financially ruinous for an MSME and provides negligible analytical return after 72 hours.

### 3.2 The Tiered Retention Model

```
   Raw Wire Packets
         |
   [ Ring Buffer: 15-min RAM/NVMe ] ----(High Severity Alert Fired)----> [ MinIO: vaultx-pcaps ]
         |                                                               (Retained 30 Days)
   (Metadata Extraction)
         v
   PostgreSQL / TimescaleDB (Hot Tier)
   - `security_events`: 90 Days Online
   - `network_flows`: 30 Days Online
   - `auth_events`: 90 Days Online
         |
         +----(Monthly Archive Job)----> MinIO / S3 (Cold Compressed Tier)
                                         - Parquet / JSONL Gzip: 180 to 365 Days
                                         - System Audit Log: 730 Days (Statutory)
                                               |
                                         (Expiry Job)
                                               v
                                            [ PURGE ]
```

- **Incident-Triggered PCAP Preservation:** Sensor nodes maintain a rolling 15-minute raw circular buffer in memory or local NVMe scratch space. Full PCAPs are **never** committed to persistent storage unless an anomaly or high-severity detection rule triggers an evidence freeze. When triggered, only the corresponding 15-minute window is tagged, compressed, and uploaded to the MinIO `vaultx-pcaps` bucket.
- **Partition Pruning:** Time-series tables in PostgreSQL use native monthly declarative partitioning. Purging data older than the retention boundary executes as an atomic `DROP TABLE becpl_nids.security_events_YYYY_MM`, avoiding disk fragmentation and eliminating multi-hour `DELETE` query overhead.

---

## Principle 4: Offline Model Retraining

### 4.1 The Perils of Online Auto-Retraining
Academic literature frequently proposes "online continuous learning" for NIDS, where machine learning models update their internal weights in real-time based on incoming network flows. In an industrial MSME, this introduces critical vulnerabilities:
1. **Adversarial Poisoning:** An attacker can slowly introduce low-and-slow reconnaissance flows over several weeks, tricking an adaptive model into classifying malicious reconnaissance as normal baseline behavior.
2. **False Label Propagation:** Operational anomalies (such as an unannounced weekend firmware flashing batch) will be ingested as either false positives or contaminated training labels.
3. **Non-Deterministic Production State:** If two sensors or cluster instances update weights independently, detection behavior becomes unreproducible and unexplainable during incident triage.

### 4.2 The VaultX Retraining Pipeline

```
  +---------------------------------------------------------------------------------+
  |                       OFFLINE MODEL RETRAINING PIPELINE                         |
  |                                                                                 |
  |  [ Validated Security Events ] + [ Curated Lab Scenarios ] + [ Benchmark Datasets ]
  |                                |                                                |
  |                                v                                                |
  |                  [ Data Hygiene & Deduplication ]                               |
  |                  - Anonymize IP/MAC                                             |
  |                  - Temporal split (prevent leakage)                             |
  |                  - Class balancing (SMOTE / Focal Loss)                         |
  |                                |                                                |
  |                                v                                                |
  |                  [ Offline Model Training Cluster ]                             |
  |                  - Random Forest / XGBoost / Autoencoder                        |
  |                  - Cross-dataset validation (HAI, X-IIoTID)                     |
  |                                |                                                |
  |                                v                                                |
  |                  [ Strict Acceptance Gate ]                                     |
  |                  - FAR < 0.1% per 24h                                           |
  |                  - Recall on OT Scenarios >= 98%                                |
  |                                |                                                |
  |                                v                                                |
  |                  [ Cryptographic Signing & Release ]                            |
  |                  - SHA-256 model manifest                                       |
  |                  - Deployment to MinIO `vaultx-models`                          |
  |                                |                                                |
  |  ==============================|==============================================  |
  |                                v                                                |
  |  [ Real-Time NIDS Detection Engine ] <--- Read-Only Inference Weights           |
  |  (Deterministic, zero weight mutation during live production operation)        |
  +---------------------------------------------------------------------------------+
```

- **Separation of Concerns:** The real-time detection engine in `nids-central` executes inference only using immutable, read-only model files loaded at startup.
- **Audited Releases:** Retraining occurs out-of-band on a quarterly schedule or post-incident review. New candidate models must pass automated regression testing against a "golden evaluation dataset" before receiving cryptographic sign-off from the security lead.

---

## Principle 5: Policy-Driven OT Isolation (Safety First)

### 5.1 IT vs. OT Isolation Realities
The traditional IT security reflex—*automatically isolate any host exhibiting signs of compromise*—is potentially catastrophic in manufacturing:

| Domain | Target Asset | Automated Disconnect Consequence | Acceptable Response |
|---|---|---|---|
| **Corporate IT** | Employee Laptop (`CORP-WS-002`) | User cannot access email; minor productivity delay | **Immediate Automated Isolation:** Revoke 802.1X port or drop IP at firewall switch port. |
| **Engineering** | Firmware Dev Machine | Developer session killed; uncommitted git code temporarily unavailable | **Automated Isolation with Admin Notice:** Block cross-VLAN routes to Gitea/Jenkins. |
| **Manufacturing OT** | PLC controlling SMT Solder Reflow Oven | Temperature monitoring lost; heating elements overheat; fire hazard; scrap of ₹25 Lakhs in boards; worker physical risk | **NEVER AUTOMATE ISOLATION.** Alert operator, engage safety interlocks, require human OT engineer authorization. |

### 5.2 Mandatory Human-in-the-Loop (HITL) Workflow
VaultX classifies assets into strict isolation tiers in the `isolation_policies` table:

```
               [ High-Confidence Anomaly Detected on Asset ]
                                    |
                    Is asset located in VLAN 30 (OT)
                     or marked as INDUSTRIAL_DEVICE?
                                    |
                   +----------------+----------------+
                   |                                 |
                 YES                                 NO (Corporate / DMZ)
                   |                                 |
                   v                                 v
     +---------------------------+     +---------------------------+
     |   OT SAFETY INTERLOCK     |     |   AUTOMATED QUARANTINE    |
     | - Alert Plant Operations  |     | - Firewall drop rule      |
     | - Switch to Local Control |     | - Active session revoked  |
     | - Dual Human Sign-off Req |     | - Audit entry recorded    |
     | - Max 15-min review timer |     +---------------------------+
     +-------------+-------------+
                   |
     [ Plant Engineer Sign-Off? ]
            /             \
          YES              NO
          /                 \
         v                   v
  [ Controlled Safe Stop ]  [ Suppress Alert / False Positive Log ]
```

- **Zero Autonomous PLC Disconnects:** VaultX will never autonomously issue a network drop, switch port shutdown, or firewall blackhole against an OT device without human verification.
- **Boundary Containment Alternative:** When an OT asset is suspected of compromise, the isolation engine automatically severs **upstream boundary paths** (e.g. blocking the IT-to-OT DMZ bridge or terminating the vendor VPN gateway) while preserving local shopfloor Modbus/HMI communication, ensuring the physical machine continues running under local supervisory control.
- **Audit Trails:** Every isolation action (automated or human-authorized) requires dual entry logging in `becpl_nids.response_actions` and `becpl_nids.audit_log`, capturing operator identity, justification, and approval timestamp.
