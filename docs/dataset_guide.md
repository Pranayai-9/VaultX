# Multi-Dataset Strategy & Harmonisation Guide — VaultX

> **Document Version:** 1.0  
> **Target Audience:** ML Engineers, Security Researchers, Data Scientists  
> **Scope:** Offline Model Training, Benchmark Acquisition & Evaluation for BECPL

---

## 1. Executive Summary & Strategy

Modern electronics manufacturing plants do not operate as pure enterprise IT networks, nor do they operate as isolated legacy SCADA islands. They are **hybrid cyber-physical ecosystems** integrating commodity operating systems, cloud-connected ERP/WMS supply chain systems, and real-time industrial controllers.

No single publicly available academic dataset captures this heterogeneous reality. To build robust, generalized intrusion detection models in VaultX Phase 2, we implement a **Multi-Dataset Strategy** combining six curated academic benchmarks with domain-specific synthetic telemetry generated from the **BECPL Digital Twin simulation**.

```
+--------------------------------------------------------------------------------------------------+
|                                    MULTI-DATASET COVERAGE MATRIX                                 |
|                                                                                                  |
|   Enterprise IT & Perimeter Threats       IIoT & Smart Edge Devices      Physical ICS / Control  |
|   +-------------------------------+       +-------------------------+    +--------------------+  |
|   | CSE-CIC-IDS2018               |       | X-IIoTID                |    | HAI 22.04 / 23.05  |  |
|   | CIC-IDS2017                   |       | ToN_IoT                 |    | (Hardware-in-the-  |  |
|   | UNSW-NB15                     |       |                         |    |  Loop ICS Testbed) |  |
|   +---------------+---------------+       +------------+------------+    +---------+----------+  |
|                   |                                    |                           |             |
|                   +------------------------------------+---------------------------+             |
|                                                        |                                         |
|                                                        v                                         |
|                                      +------------------------------------+                      |
|                                      | Harmonisation & Normalization Pipeline                    |
|                                      +-----------------+------------------+                      |
|                                                        |                                         |
|                                                        +<==== [ BECPL Manufacturing Simulation ] |
|                                                        |      (Indian MSME Workflows, Modbus,    |
|                                                        |       Supplier APIs, Tier-2 OT Flows)   |
|                                                        v                                         |
|                                      +------------------------------------+                      |
|                                      | Balanced, Leakage-Free ML Datasets |                      |
|                                      +------------------------------------+                      |
+--------------------------------------------------------------------------------------------------+
```

---

## 2. Overview of the 6 Benchmark Datasets

| Dataset Identifier | Full Name & Source | Target Domain | Primary Attack Vectors Covered | Size / Records | License | Relevance to BECPL |
|---|---|---|---|---|---|---|
| **X-IIoTID** | *X-IIoTID: A New Dataset for Industrial IoT* (Univ. of New South Wales) | Industrial IoT & Smart Factory Edge | Modbus attacks, command injection, MITM, DoS, ransomware, discovery, MQTT exploitation | ~820,000 records (~1.2 GB) | Creative Commons Attribution (CC BY 4.0) | High relevance for IoT sensor assemblies and embedded modules on VLAN 30 |
| **ToN_IoT** | *Telemetry and Network datasets for IoT* (UNSW Canberra Cyber) | Industrial IoT, Fog & Cloud Systems | Scanning, password cracking, DoS/DDoS, XSS, backdoors, injection | ~22 million records (~5.5 GB CSV) | Academic / Research Use | Validates telemetry from edge gateways, Linux controllers, and cloud telemetry |
| **CSE-CIC-IDS2018** | *Communications Security Establishment & CIC* (Univ. of New Brunswick) | Enterprise IT Infrastructure | Brute force (SSH/FTP), DoS/DDoS, Heartbleed, Web attacks, Botnet, Infiltration | ~16 million flows (~14 GB) | Open Academic Access | Models corporate IT (VLAN 10) attacks, credential abuse, and perimeter compromises |
| **HAI 22.04 / 23.05**| *Hardware-in-the-Loop Augmented ICS* (Affiliated Institute of ETRI, Korea) | Critical Infrastructure & Physical Control Lines | Physical process anomalies, sensor spoofing, actuator disruption, multi-stage control loops | ~1.5 million rows per test suite | CC BY-NC-SA 4.0 | Direct analog for SMT Pick-and-Place, reflow oven thermal control, and PLC monitoring |
| **CIC-IDS2017** | *Canadian Institute for Cybersecurity* (Univ. of New Brunswick) | Enterprise Network Flows | PortScan, Botnet, Infiltration, Web Attacks, DoS/DDoS | ~2.8 million flows (~3.1 GB) | Open Academic Access | Baseline validation for classic lateral movement and external port reconnaissance |
| **UNSW-NB15** | *UNSW Cyber Testbed Flow Dataset* | Mixed Hybrid Network Flows | Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms | ~2.5 million records (~100 MB) | CC BY 4.0 | Evaluates generalized low-level TCP/IP anomaly detection and flow classification |

---

## 3. The Critical Limitation of Public Academic Datasets

> [!IMPORTANT]
> **Core Architecture Observation:**  
> **None of these publicly available datasets represents the complete, authentic network behavior of an Indian electronics manufacturing MSME.**

### 3.1 What Public Benchmarks Lack
1. **Indian Business Operational Rhythms:**
   - Public datasets are generated in academic testbeds in Canada, Australia, or South Korea under rigid Western office hours or continuous synthetic loop cycles.
   - They fail to capture Indian manufacturing shift patterns (e.g., General Shift 09:00–18:00 vs. Night Production Shift 20:00–06:00), local holiday schedules, and intermittent power-cycling behavior.
2. **Indian Logistics & Supply Chain Integrations:**
   - Electronics MSMEs in Pune interact daily with Indian logistics APIs (DTDC, BlueDart, Delhivery), domestic component distributors, and Government e-Invoicing / GSTN portals. Public datasets do not contain these specific API payload structures or HTTP traffic profiles.
3. **Brownfield SMT & Industrial Protocol Hybridization:**
   - Datasets like CIC-IDS2018 contain zero industrial protocol flows (no Modbus, no Siemens S7comm).
   - Datasets like HAI contain physical time-series measurements but lack correlating corporate IT and DMZ perimeter traffic.
4. **Lean IT Operational Artifacts:**
   - Academic testbeds feature clean, modern enterprise software. Real MSMEs feature legacy machines, shared jump boxes, unpatched Windows 7/10 inspection workstations, and legitimate script-driven file sharing that would trigger false alarms in academic models.

### 3.2 How the BECPL Digital Twin Simulation Bridges This Gap
The VaultX Phase 1 digital twin explicitly addresses these limitations by synthesizing:
- Modbus TCP traffic between simulated PLCs, Node-RED HMIs, and MES servers on VLAN 30.
- RESTful supply chain traffic simulating domestic distributor API exchanges on VLAN 40/50.
- Realistic background noise generated by `normal_traffic_gen.py`, reflecting actual shopfloor operating cadences.
- Labeled multi-stage attack scenarios (`scenarios/`) mapped to real threat actor behaviors targeting Indian manufacturing plants.

---

## 4. Data Harmonisation & Feature Engineering

Because each dataset uses divergent column conventions (e.g. Zeek `id.orig_h` vs CIC `Src IP` vs X-IIoTID `Source_IP`), VaultX defines a **Canonical Harmonisation Schema**.

### 4.1 Canonical Feature Mapping

| Harmonized Feature Name | Zeek Field | CIC-IDS2018 Field | X-IIoTID Field | Data Type | Description |
|---|---|---|---|---|---|
| `flow_duration_ms` | `duration` (×1000) | `Flow Duration` (÷1000)| `Duration` | `Float` | Connection lifetime in ms |
| `orig_bytes` | `orig_bytes` | `TotLen Fwd Pkts` | `SrcBytes` | `Integer` | Outbound payload bytes |
| `resp_bytes` | `resp_bytes` | `TotLen Bwd Pkts` | `DstBytes` | `Integer` | Inbound payload bytes |
| `orig_pkts` | `orig_pkts` | `Total Fwd Packets`| `SrcPkts` | `Integer` | Outbound packet count |
| `resp_pkts` | `resp_pkts` | `Total Backward Packets`| `DstPkts` | `Integer` | Inbound packet count |
| `orig_ip_bytes` | `orig_ip_bytes` | `Fwd Header Length`| `SrcHeaderBytes` | `Integer` | Outbound IP header overhead |
| `conn_state` | `conn_state` | *Derived from flags*| *Derived from flags*| `Categorical`| TCP handshake state (SF, S0, REJ) |
| `proto` | `proto` | `Protocol` | `Protocol` | `Categorical`| TCP, UDP, ICMP |
| `service` | `service` | *Derived from Dst Port*| `Service` | `Categorical`| Modbus, HTTP, SSH, DNS |

### 4.2 Data Hygiene & Address Space Alignment
- **IP/MAC Re-mapping:** When training hybrid models, public dataset IP ranges are synthetically re-mapped into the BECPL network scheme (`10.10.x.x` and `172.20.x.x`) to preserve consistent subnet distance and zone crossing features.
- **Normalization:** Numerical flow features undergo robust scaling (`RobustScaler`) or logarithmic transformation ($\log(x+1)$) to prevent high-volume burst flows from skewing model weight calculations.

---

## 5. Class Imbalance Handling Strategy

In industrial networks, malicious traffic accounts for less than **0.01%** of aggregate packets, creating extreme class imbalance that leads naive classifiers to achieve deceptively high 99.9% accuracy while exhibiting 0% attack recall.

```
+---------------------------------------------------------------------------------+
|                       CLASS IMBALANCE MITIGATION STRATEGY                       |
|                                                                                 |
|   Raw Telemetry: [ Normal Flows > 99.9% ] =======> [ Rare Attacks < 0.1% ]      |
|                                |                               |                |
|                                v                               v                |
|               [ Stratified Down-Sampling ]            [ SMOTE / ADASYN ]        |
|               - Retain representative normal          - Synthesize minority     |
|                 profiles across all VLANs               attack samples in       |
|                                |                        feature space           |
|                                +---------------+---------------+                |
|                                                |                                |
|                                                v                                |
|                              [ Balanced Training Batch ]                        |
|                              (Target: 80% Normal / 20% Attack)                  |
|                                                |                                |
|                                                v                                |
|                              [ Cost-Sensitive Loss Function ]                   |
|                              - Focal Loss ($\gamma = 2.0$)                      |
|                              - Class Weighted Cross-Entropy                     |
|                                ($\text{weight}_{\text{attack}} = 20.0$)         |
+---------------------------------------------------------------------------------+
```

1. **Synthetic Minority Over-sampling (SMOTE & ADASYN):** Applied strictly to the training fold of tabular feature representations for rare attacks (e.g. Modbus function code tampering, lateral RDP pivoting).
2. **Cost-Sensitive Learning / Focal Loss:**
   $$\mathcal{L}_{\text{focal}} = -\alpha_t (1 - p_t)^\gamma \log(p_t)$$
   Down-weights well-classified normal examples, focusing gradient descent updates on ambiguous, hard-to-classify attack vectors.
3. **Precision-Recall Threshold Tuning:** Operational decision thresholds are calibrated based on **Precision-Recall (PR) curves** rather than ROC curves, targeting a false positive rate $<0.1\%$ per 24-hour cycle.

---

## 6. Train/Test Split Protocols & Leakage Prevention

Data leakage is the most prevalent flaw in intrusion detection literature, causing models to achieve artificial 99% laboratory accuracy but fail completely in production.

VaultX enforces three mandatory isolation rules for all model training:
1. **Strict Temporal Splitting:**
   - Data is ordered chronologically. Training is performed on time interval $[T_0, T_1]$, validation on $[T_1, T_2]$, and final evaluation on $[T_2, T_3]$.
   - *Never use random K-fold shuffling across time-series data*, as future packets leak into past flows.
2. **Host / Device Separation:**
   - Training sets and test sets must not share identical IP/MAC combinations for synthetic attack injection. Models must learn general behavioral patterns (e.g., rapid fan-out port scanning), not memorize that `10.10.10.32` is an attacker.
3. **No Target Leakage in Feature Engineering:**
   - Min/max scaling parameters, imputation statistics, and SMOTE distributions must be fit **exclusively** on the training fold and applied transformations out-of-sample to validation and test folds.

---

## 7. Model Evaluation Strategy

Models deployed in VaultX Phase 2 are evaluated on a **two-tier matrix**:

### Tier 1: Per-Dataset In-Domain Metrics
- **Metrics Computed:** Macro Precision, Macro Recall, F1-Score, False Alarm Rate (FAR) per hour, Balanced Accuracy.
- **Minimum Acceptance Gate:**
  - Overall Attack Recall $\ge 96.0\%$
  - OT / Modbus Specific Attack Recall $\ge 99.0\%$
  - False Alarm Rate $< 0.1\%$ per 24 hours of normal background traffic

### Tier 2: Cross-Dataset Generalization Testing
Models trained on one dataset must be tested on another without weight updates to confirm architectural robustness:
- *Test A:* Train on CSE-CIC-IDS2018 (Enterprise) $\longrightarrow$ Test on ToN_IoT (Edge).
- *Test B:* Train on X-IIoTID (IIoT) $\longrightarrow$ Test on BECPL OT Digital Twin.
- *Test C:* Train on BECPL Baseline $\longrightarrow$ Test on HAI 22.04 Physical Anomalies.
