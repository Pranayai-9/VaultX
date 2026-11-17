# Comprehensive Benchmark Dataset Documentation
## VaultX Hybrid NIDS — Bharat Electronics Components Pvt. Ltd. (BECPL)

This document provides exhaustive technical documentation for the six primary reference datasets evaluated within the VaultX research framework:
1. **CIC-IDS2017**
2. **CSE-CIC-IDS2018**
3. **ToN_IoT**
4. **X-IIoTID**
5. **HAI 22.04**
6. **UNSW-NB15**

---

## 1. CIC-IDS2017 (Canadian Institute for Cybersecurity)

### 1.1 Citation & Provenance
- **Full Citation:** Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP 2018), pp. 108–116.
- **DOI:** `10.5220/0006639801080116`
- **License:** Open Access for academic research (Attribution required).
- **Download URL:** `https://www.unb.ca/cic/datasets/ids-2017.html`

### 1.2 Format, Size & Scope
- **File Format:** CSV (Pre-extracted flow features via CICFlowMeter) and Raw PCAP.
- **Size:** ~3.1 GB compressed (CSV flows), ~51 GB (raw PCAP).
- **Duration / Date:** 5 continuous days (Monday 3 July 2017 to Friday 7 July 2017).
- **Total Records:** 2,830,743 labeled network flows across 8 CSV files.

### 1.3 Key Features & Available Telemetry
Extracted with **CICFlowMeter** (83 features per flow):
- `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Total Length of Fwd Packets`, `Total Length of Bwd Packets`
- `Fwd Packet Length Max/Min/Mean/Std`, `Bwd Packet Length Max/Min/Mean/Std`
- `Flow Bytes/s`, `Flow Packets/s`, `Flow IAT Mean/Std/Max/Min`
- TCP Flags: `FIN`, `SYN`, `RST`, `PSH`, `ACK`, `URG`, `CWE`, `ECE`
- Down/Up Ratio, Average Packet Size, Subflow Fwd/Bwd Bytes
- Packet Inter-Arrival Times (IAT), Active/Idle Min/Mean/Max.

### 1.4 Attack Types Included
- **Brute Force:** FTP-Patator, SSH-Patator.
- **DoS / DDoS:** DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest, DDoS LOIC.
- **Web Attacks:** SQL Injection, Cross-Site Scripting (XSS), Web Brute Force.
- **Infiltration & Botnet:** Dropbox download + Metasploit payload, Ares Botnet C2.
- **Port Scans:** Nmap TCP SYN sweep, service scan.

### 1.5 Class Distribution & Imbalance
- **Benign:** 2,273,097 flows (~80.3%)
- **Malicious:** 557,646 flows (~19.7%)
- Significant intraday imbalance: e.g., Friday morning DDoS consists of 128,027 attack flows vs 97,718 benign, whereas SQL Injection comprises only 21 flows across the entire week.

### 1.6 Known Limitations & Caveats
- **TCP Inter-Arrival Time Calculation Flaws:** In the original CICFlowMeter extraction, negative flow duration values and infinite flow rates (`Flow Bytes/s = Inf`) exist due to integer overflow in microsecond counters.
- **Synthetic Background Traffic:** Generated using automated human-profile agents that lack real manufacturing protocol dynamics (no Modbus, S7, or industrial telemetry).
- **Repetitive Attack Tool Signatures:** LOIC and Hulk floods repeat identical packet sizes and byte distributions.

### 1.7 Harmonisation to BECPL Standard Schema
- Maps directly to VaultX Flow Schema:
  - `Source IP`, `Destination IP`, `Source Port`, `Destination Port`, `Protocol`
  - `Flow Duration` $\rightarrow$ `connection_duration`
  - `Total Fwd Packets + Total Backward Packets` $\rightarrow$ `packets_transferred`
  - `Total Length of Fwd Packets + Total Length of Bwd Packets` $\rightarrow$ `bytes_transferred`
- Unmapped: High-order statistical variance features (compressed into summary embeddings in VaultX).

### 1.8 Relevance to Manufacturing MSMEs
Provides valuable multi-vector benchmark data for corporate-facing perimeter attacks (e.g., SCN-003 brute force, SCN-007 port scanning, web application probes against vendor portals).

### 1.9 Train/Test Leakage Risks & Mitigation
- **Leakage Risk:** Random train/test split leaks identical flow IP addresses and timestamp correlations between train and test sets, yielding artificially inflated F1-scores (>99.5%).
- **Mitigation:** Use strict **Day-based Splitting** (e.g., Train on Monday–Wednesday, Test on Thursday–Friday) or GroupKFold based on Source IP prefixes.

---

## 2. CSE-CIC-IDS2018 (AWS & CIC)

### 2.1 Citation & Provenance
- **Full Citation:** Canadian Institute for Cybersecurity & Communications Security Establishment (2018). *CSE-CIC-IDS2018 on AWS*. University of New Brunswick & Amazon Web Services.
- **DOI / Registry:** AWS Open Data Registry `arn:aws:s3:::cse-cic-ids2018`
- **License:** Creative Commons Attribution 4.0 International (CC-BY 4.0).
- **Download URL:** `https://registry.opendata.aws/cse-cic-ids2018/`

### 2.2 Format, Size & Scope
- **File Format:** CSV (CICFlowMeter-V3) and AWS VPC Flow Logs / raw PCAPs.
- **Size:** ~16.4 GB (10 CSV files), ~450 GB (raw PCAP).
- **Duration / Date:** 10 days of capture in February–March 2018.
- **Total Records:** 16,233,002 network flows.

### 2.3 Key Features & Available Telemetry
80 extracted statistical flow features:
- `Dst Port`, `Protocol`, `Flow Duration`, `Tot Fwd Pkts`, `Tot Bwd Pkts`
- `Fwd Pkt Len Max/Min/Mean/Std`, `Bwd Pkt Len Max/Min/Mean/Std`
- `Flow Byts/s`, `Flow Pkts/s`, `Fwd/Bwd IAT Mean/Std/Max/Min`
- Flag counts (`Fwd PSH Flags`, `Bwd PSH Flags`, `Fwd URG Flags`, `FIN`, `SYN`, `RST`, `ACK`)
- `Init Fwd Win Byts`, `Init Bwd Win Byts`, `Fwd Seg Size Min`, `Active/Idle` states.

### 2.4 Attack Types Included
- **Botnets:** Zeus and Ares botnets.
- **DoS / DDoS:** LOIC HTTP, LOIC UDP, HOIC, Slowloris, SlowHTTPTest.
- **Brute Force:** Web Brute Force, XSS, SQL Injection.
- **Infiltration:** Dropbox compromise followed by internal reconnaissance and privilege escalation.

### 2.5 Class Distribution & Imbalance
- **Benign:** ~13,484,708 flows (~83.1%)
- **Malicious:** ~2,748,294 flows (~16.9%)
- Extreme sub-class disparity: SQL Injection has 87 rows; DDoS-LOIC has >576,000 rows.

### 2.6 Known Limitations & Caveats
- Significant volume of missing values (`NaN`) and string literals in numeric columns in February 28 / March 1 CSVs.
- Class label inconsistencies across different daily CSVs (e.g., `DDoS attacks-LOIC-HTTP` vs `DDoS-LOIC-HTTP`).

### 2.7 Harmonisation to BECPL Standard Schema
- Directly maps to standard flow identifiers.
- Enrichable with BECPL identity classifications (`AUTOMATION_WORKLOAD` for botnets, `THIRD_PARTY_IDENTITY` for web brute force).

### 2.8 Relevance to Manufacturing MSMEs
Models multi-stage cloud and external integration breaches, relevant to BECPL's AWS VPC integration and VLAN 60 cloud services.

### 2.9 Train/Test Leakage Risks & Mitigation
- **Leakage Risk:** Temporal autocorrelation across consecutive flow captures from the same victim VM.
- **Mitigation:** Split strictly by target machine subnet and date; remove IP address features prior to feeding deep learning models to prevent memorizing victim IP addresses.

---

## 3. ToN_IoT (UNSW Canberra Cyber)

### 3.1 Citation & Provenance
- **Full Citation:** Al-Zewairi, M., et al. / Moustafa, N. (2020). *A new distributed architecture for evaluating AI-based security systems at the big data in IoT*. IEEE Access, Vol. 8, pp. 11090–11105.
- **DOI:** `10.1109/ACCESS.2020.3015488`
- **License:** Academic Use License (UNSW Canberra Cyber).
- **Download URL:** `https://cloudstor.aarnet.edu.au/plus/s/ds5vHzRPJyRAigB`

### 3.2 Format, Size & Scope
- **File Format:** CSV (Zeek network connection logs) + Operating System logs (Linux / Windows) + IoT telemetry logs (MQTT, Modbus, HTTP).
- **Size:** ~1.4 GB (Network CSV subset), ~42 GB full package.
- **Duration / Date:** Captured across heterogeneous IoT/IIoT testbeds in 2019.
- **Total Records:** 22,339,021 network flow entries.

### 3.3 Key Features & Available Telemetry
Directly parsed from **Zeek (Bro)** conn.log and telemetry:
- `ts`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `proto`, `service`
- `duration`, `src_bytes`, `dst_bytes`, `conn_state`, `missed_bytes`
- `src_pkts`, `src_ip_bytes`, `dst_pkts`, `dst_ip_bytes`
- `dns_query`, `dns_qclass`, `dns_qtype`, `dns_rcode`
- `http_trans_depth`, `http_method`, `http_uri`, `http_version`, `http_user_agent`
- Multi-class labels: `label` (binary 0/1) and `type` (attack taxonomy).

### 3.4 Attack Types Included
- **Scanning:** Port scanning, vulnerability scanning.
- **DoS / DDoS:** HTTP floods, SYN floods.
- **Ransomware & Backdoors:** IoT ransomware, C2 callbacks.
- **Data Injection:** MQTT broker injections, fake sensor values.
- **XSS & Password Brute Force:** Brute force against industrial IoT gateways.

### 3.5 Class Distribution & Imbalance
- Network subset (Train/Test standard split):
  - **Benign:** ~300,000 flows (~65%)
  - **Attack:** ~161,043 flows (~35%)
  - High coverage of scanning (20,000+ rows) and DoS attacks.

### 3.6 Known Limitations & Caveats
- IP addressing uses private range `192.168.1.0/24` flat topology; lacks enterprise multi-VLAN segmentation.
- Zeek feature extraction has missing values denoted as `-` (standard Zeek null symbol) which must be replaced before numerical processing.

### 3.7 Harmonisation to BECPL Standard Schema
- **Direct 1:1 match with VaultX Zeek ingestion pipeline.**
  - `src_ip` $\rightarrow$ `source_ip`
  - `dst_ip` $\rightarrow$ `destination_ip`
  - `src_port` $\rightarrow$ `source_port`
  - `dst_port` $\rightarrow$ `destination_port`
  - `proto` $\rightarrow$ `protocol`
  - `duration` $\rightarrow$ `connection_duration`
  - `src_bytes + dst_bytes` $\rightarrow$ `bytes_transferred`
  - `src_pkts + dst_pkts` $\rightarrow$ `packets_transferred`

### 3.8 Relevance to Manufacturing MSMEs
**Extremely high.** Provides real Zeek connection logs and IoT/MQTT telemetry identical to VaultX's sensor architecture. Directly supports SCN-004 (LotL/Backdoor) and SCN-007 (Scanning).

### 3.9 Train/Test Leakage Risks & Mitigation
- Standard release includes a pre-partitioned train/test set with identical target IPs. VaultX applies stratification on `type` while ensuring time-ordered chronological splitting.

---

## 4. X-IIoTID (Industrial IoT Intrusion Dataset)

### 4.1 Citation & Provenance
- **Full Citation:** Al-Hawawreh, M., Sitnikova, E., & Aboutorab, N. (2021). *X-IIoTID: A Connectivity-Agnostic and Device-Agnostic Intrusion Dataset for Industrial Internet of Things*. IEEE Access, Vol. 10, pp. 3134–3155.
- **DOI:** `10.1109/ACCESS.2021.3134375`
- **License:** IEEE Dataport Open Access.
- **Download URL:** `https://ieee-dataport.org/documents/x-iiotid-connectivity-and-agnostic-intrusion-dataset-industrial-internet-things`

### 4.2 Format, Size & Scope
- **File Format:** CSV.
- **Size:** ~850 MB.
- **Duration / Date:** Multi-stage testbed execution in 2021.
- **Total Records:** 820,834 instances with 68 features.

### 4.3 Key Features & Available Telemetry
Features divided into Network, Device, and System domains:
- Network: `IP_src`, `IP_dst`, `Port_src`, `Port_dst`, `Protocol`, `Duration`, `Bytes_in`, `Bytes_out`
- Protocol Specific: Modbus function codes, MQTT message types, CoAP headers, OPC-UA node identifiers.
- System Activity: Process memory usage, file read/write operations on edge gateway.
- Classifications: `class1` (Normal/Attack), `class2` (Attack Category: Weaponization, Recon, Exploitation, Lateral, Exfil, Tampering), `class3` (Specific sub-attack).

### 4.4 Attack Types Included
- **Industrial Protocol Tampering:** Modbus register manipulation, unauthorized coil writes.
- **Reconnaissance:** Modbus device enumeration, TCP/UDP scanning.
- **Command & Control:** MQTT broker hijack, reverse shells.
- **Ransomware / Encryption:** ICS edge locker payloads.
- **MitM & Replay:** Modbus command spoofing.

### 4.5 Class Distribution & Imbalance
- **Benign:** 375,412 instances (~45.7%)
- **Attack:** 445,422 instances (~54.3%)
- Well-balanced primary classes, with specialized sub-attack scarcity (e.g., Modbus memory dump: 1,420 rows).

### 4.6 Known Limitations & Caveats
- Feature names contain mixed uppercase and lowercase conventions (`IP_src`, `bytes_in`, `Scr_bytes`).
- Non-network features (edge host metrics) are concatenated into network flow rows, requiring separate filtering for pure NIDS pipelines.

### 4.7 Harmonisation to BECPL Standard Schema
- Highly compatible with VaultX Industrial Telemetry Engine:
  - `IP_src` $\rightarrow$ `source_ip`
  - `IP_dst` $\rightarrow$ `destination_ip`
  - Modbus parameters map directly to `protocol_details` in SCN-001 and SCN-006.

### 4.8 Relevance to Manufacturing MSMEs
**Premier industrial reference dataset.** Specifically mirrors BECPL SMT Line A/B Modbus communication patterns, setpoint modifications, and industrial command tampering.

### 4.9 Train/Test Leakage Risks & Mitigation
- Avoid shuffling without grouping by sequence window. Industrial control state machines exhibit continuous autocorrelation; train on normal operational cycles, evaluate on novel attack injection phases.

---

## 5. HAI 22.04 (Hardware-in-the-Loop Augmented ICS Dataset)

### 5.1 Citation & Provenance
- **Full Citation:** Shin, H. K., Lee, W., Yun, J. H., & Kim, H. C. (2022). *HAI 22.04: Hardware-in-the-loop Augmented ICS Security Dataset*. Electronics and Telecommunications Research Institute (ETRI), South Korea.
- **DOI / GitHub:** `https://github.com/icsdataset/hai`
- **License:** Creative Commons Attribution 4.0 International (CC-BY 4.0).
- **Download URL:** `https://github.com/icsdataset/hai/releases/tag/22.04`

### 5.2 Format, Size & Scope
- **File Format:** CSV (Time-series analog and digital sensor telemetry).
- **Size:** ~1.2 GB compressed.
- **Duration / Date:** 100+ hours of continuous operational runs in 2021–2022.
- **Total Records:** Over 2,000,000 time-series observations sampled at 1-second intervals.

### 5.3 Key Features & Available Telemetry
86 physical process variables across 4 industrial testbed loops (Boiler, Turbine, Water Treatment, Smart Grid):
- Pressures, temperatures, flow rates, rotational speeds, valve positions, motor drive frequencies.
- Discrete PLC state signals (interlock trip, run status, setpoints).
- Binary and Multi-attack labels (`attack`, `attack_P1`, `attack_P2`, `attack_P3`, `attack_P4`).

### 5.4 Attack Types Included
- Physical process setpoint manipulation (analogous to SCN-006 conveyor speed tampering).
- Stealthy false data injection (FDI) attacks bypassing standard threshold alarms.
- Actuator manipulation (abrupt valve closing, pump shutdown).
- Complex multi-point coordinated sabotage attacks.

### 5.5 Class Distribution & Imbalance
- **Benign:** >95% of total run time (normal operating conditions).
- **Attack:** <5% (subtle anomalies lasting between 2 minutes and 25 minutes per attack cycle).
- Highly realistic class imbalance representing true manufacturing operating reality.

### 5.6 Known Limitations & Caveats
- HAI captures **physical sensor/actuator signals** rather than network packets (PCAP/flow).
- Requires pairing with a network layer to correlate packet arrivals with physical process parameter changes.

### 5.7 Harmonisation to BECPL Standard Schema
- Used within VaultX's **OT Physical Anomaly Correlator**:
  - `timestamp` $\rightarrow$ `timestamp`
  - Process variables (e.g., `P1_B4002`, `P1_FT01`) map to BECPL SMT oven temperatures and motor speed registers (`40001`–`40005`).

### 5.8 Relevance to Manufacturing MSMEs
Crucial for validating the safety-critical constraints of SCN-006. Enables testing of physics-aware anomaly detection algorithms that detect sabotage even when network packets appear syntactically valid.

### 5.9 Train/Test Leakage Risks & Mitigation
- Train strictly on pure benign operational datasets (`hai-train1.csv`, `hai-train2.csv`). Evaluate exclusively on unseen test partitions (`hai-test1.csv`, `hai-test2.csv`). Zero overlap in time intervals.

---

## 6. UNSW-NB15 (Australian Centre for Cyber Security)

### 6.1 Citation & Provenance
- **Full Citation:** Moustafa, N., & Slay, J. (2015). *UNSW-NB15: a comprehensive dataset for network intrusion detection systems (UNSW-NB15 dataset)*. 2015 Military Communications and Information Systems Conference (MilCIS), Canberra, pp. 1–6.
- **DOI:** `10.1109/MilCIS.2015.7348942`
- **License:** Academic and Research Use (ACCS / UNSW).
- **Download URL:** `https://research.unsw.edu.au/projects/unsw-nb15-dataset`

### 6.2 Format, Size & Scope
- **File Format:** CSV (Argus / Bro-IDS features) + Raw PCAP.
- **Size:** ~550 MB (CSV feature files), ~100 GB (raw PCAP).
- **Duration / Date:** 16-hour and 15-hour capture periods on 22 Jan 2015 and 17 Feb 2015.
- **Total Records:** 2,540,044 records (full set); standard subset contains 257,673 records.

### 6.3 Key Features & Available Telemetry
49 features spanning flow, content, time, and additional generated attributes:
- Basic: `srcip`, `sport`, `dstip`, `dsport`, `proto`, `state`, `dur`, `sbytes`, `dbytes`, `sttl`, `dttl`
- Content: `swin`, `dwin`, `stcpb`, `dtcpb`, `smeansz`, `dmeansz`, `trans_depth`, `res_bdy_len`
- Time: `sjit`, `djit`, `stime`, `ltime`, `sintpkt`, `dintpkt`, `tcprtt`, `synack`, `ackdat`
- Service & Category: `service` (http, ftp, smtp, ssh, dns, etc.), `attack_cat`, `label`.

### 6.4 Attack Types Included
- **Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms.**

### 6.5 Class Distribution & Imbalance
- Standard Partitioned Set:
  - **Training Set (175,341 rows):** Benign: 56,000 (31.9%), Attack: 119,341 (68.1%)
  - **Testing Set (82,332 rows):** Benign: 37,000 (44.9%), Attack: 45,332 (55.1%)
- Sub-category distribution is heavily skewed (Exploits and Generic dominate; Worms < 174 instances).

### 6.6 Known Limitations & Caveats
- The standard training/testing split provided by UNSW has an **inverted class balance** (more attacks than benign in train set), which can lead to inflated false positive rates in real-world deployments if unadjusted.
- Flow features contain synthetic artifacts generated by the IXIA PerfectStorm tool.

### 6.7 Harmonisation to BECPL Standard Schema
- Maps directly to VaultX Flow Schema:
  - `srcip` $\rightarrow$ `source_ip`
  - `dstip` $\rightarrow$ `destination_ip`
  - `sport` $\rightarrow$ `source_port`
  - `dsport` $\rightarrow$ `destination_port`
  - `proto` $\rightarrow$ `protocol`
  - `dur` $\rightarrow$ `connection_duration`
  - `sbytes + dbytes` $\rightarrow$ `bytes_transferred`
  - `spkts + dpkts` $\rightarrow$ `packets_transferred`

### 6.8 Relevance to Manufacturing MSMEs
Strong benchmark for evaluating modern exploit payloads (CVE exploitation in SCN-007), shellcode execution, and reconnaissance sweeps against enterprise workstations.

### 6.9 Train/Test Leakage Risks & Mitigation
- **Feature Leakage:** Features like `ct_srv_src` and `ct_dst_src_ltm` encode session counts within a sliding window that can leak class state across train/test boundaries if the test set is sampled randomly from the stream.
- **Mitigation:** Strict time-based splitting and independent normalization of sliding-window aggregations.
