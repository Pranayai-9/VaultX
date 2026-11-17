# VaultX Dataset Acquisition & Preparation Guide
**Project:** VaultX — Manufacturing-Aware Hybrid NIDS  
**Target Enterprise:** Bharat Electronics Components Pvt. Ltd. (BECPL), Pune, Maharashtra  
**Document Classification:** Internal Technical Documentation  

---

## 1. Executive Disclaimer & Operational Context

> [!IMPORTANT]
> **Essential Context & Limitation Disclaimer:**  
> **None of these public datasets represents complete network behaviour of Indian electronics manufacturing MSMEs. Additional labelled traffic is generated from the BECPL manufacturing simulation.**
>
> Public benchmark datasets originate from university testbeds (UNSW, UNB) or generic chemical/water process setups (HAI). Indian electronics MSMEs operate with distinct constraints: mixed legacy Windows 7/10 machines, high reliance on third-party maintenance vendors over unsegmented VPNs, hybrid Modbus TCP over Wi-Fi/Ethernet converters, and specific ERP-to-MES batch reporting rhythms. The datasets below provide foundational baselines, while the synthetic simulation modules (`normal_traffic_gen.py` and `attack_scenario_gen.py`) furnish the target domain ground truth.

---

## 2. Dataset Storage Architecture

All ingested and preprocessed datasets follow a strict file system hierarchy to ensure reproducible pipelines:

```
VaultX/
├── datasets/
│   ├── raw/                      # Untouched source downloads (read-only)
│   │   ├── xiiotid/              # CSV / PCAP files from X-IIoTID repository
│   │   ├── ton_iot/              # Network & OS telemetry CSVs from UNSW
│   │   ├── cse_cic_ids2018/      # Daily AWS S3 flow CSVs & pcaps
│   │   ├── hai_22_04/            # Hardware-in-the-Loop time-series CSVs
│   │   ├── cic_ids2017/          # MachineLearningCSV flow datasets
│   │   └── unsw_nb15/            # Pre-split CSVs & 100GB pcap dumps
│   ├── processed/                # Normalized, sanitized Parquet / SQLite files
│   │   ├── normalized_flows.parquet
│   │   ├── modbus_baseline.parquet
│   │   └── combined_train_test/
│   └── simulation/               # Artifacts emitted by BECPL simulation scripts
│       ├── becpl_normal_baseline.jsonl
│       └── becpl_scenarios_1_to_7.jsonl
```

---

## 3. Dataset Download & Acquisition Specifications

### 3.1 X-IIoTID (Multi-Tier Industrial IoT Intrusion Dataset)
* **Primary URL:** [https://github.com/Alhawawreh/X-IIoTID](https://github.com/Alhawawreh/X-IIoTID)
* **Registration Requirements:** None (Direct Git clone or Zenodo archive download).
* **Expected Formats & Sizes:**
  * Cleaned CSV feature tables: ~1.2 GB
  * Raw packet captures (PCAP): ~42 GB
* **Acquisition Steps:**
  ```bash
  git clone https://github.com/Alhawawreh/X-IIoTID.git datasets/raw/xiiotid/
  # Or download the full CSV package from Zenodo:
  curl -L -o datasets/raw/xiiotid/X-IIoTID.csv https://zenodo.org/record/5047823/files/X-IIoTID.csv?download=1
  ```

### 3.2 ToN_IoT (Heterogeneous IoT & Network Telemetry)
* **Primary URL:** [UNSW Canberra Research Data Repository](https://research.unsw.edu.au/projects/toniot-datasets)
* **Registration Requirements:** Free academic registration form on UNSW repository.
* **Expected Formats & Sizes:**
  * Processed Zeek/Bro log CSVs: ~4.5 GB
  * Operating System telemetry (Linux & Windows): ~2.8 GB
  * Raw PCAP files: ~110 GB
* **Target Subsets for VaultX:**
  * `Train_Test_datasets/Train_Test_Network_dataset/`
  * `Processed_datasets/Processed_Linux_datasets/`
  * `Processed_datasets/Processed_Windows_datasets/`

### 3.3 CSE-CIC-IDS2018
* **Primary URL:** [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2018.html)
* **Registration Requirements:** Direct download from AWS Open Data Registry (`s3://cse-cic-ids2018/`).
* **Expected Formats & Sizes:**
  * 10 Daily CSV Flow Tables: ~7.2 GB (compressed)
  * Raw PCAP payload dumps: ~440 GB
* **Acquisition Command:**
  ```bash
  aws s3 sync --no-sign-request s3://cse-cic-ids2018/ProcessedTrafficDataStore/ datasets/raw/cse_cic_ids2018/
  ```

### 3.4 HAI 22.04 (Hardware-in-the-Loop Augmented ICS Dataset)
* **Primary URL:** [https://github.com/icsdataset/hai](https://github.com/icsdataset/hai)
* **Registration Requirements:** None (Open GitHub / Kaggle mirror).
* **Expected Formats & Sizes:**
  * CSV files (`hai-train1.csv`, `hai-train2.csv`, `hai-test1.csv`): ~850 MB total.
* **Acquisition Steps:**
  ```bash
  git clone https://github.com/icsdataset/hai.git datasets/raw/hai_22_04/
  ```

### 3.5 CIC-IDS2017
* **Primary URL:** [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)
* **Registration Requirements:** None.
* **Expected Formats & Sizes:**
  * `GeneratedLabelledFlows.zip` (CSV): ~2.4 GB.

### 3.6 UNSW-NB15
* **Primary URL:** [UNSW-NB15 Resource Center](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
* **Registration Requirements:** None.
* **Expected Formats & Sizes:**
  * Official Train/Test split CSVs (`UNSW_NB15_training-set.csv`, `UNSW_NB15_testing-set.csv`): ~120 MB.

---

## 4. Dataset Preparation & Preprocessing Pipeline

To prepare these heterogeneous datasets for the VaultX hybrid model pipeline, execute the four-stage transformation:

### Stage 1: Schema Normalization & Column Alignment
Map heterogeneous field names to the canonical VaultX telemetry schema:
* `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`, `duration`, `bytes_in`, `bytes_out`, `packets_in`, `packets_out`, `flag_cross_vlan`, `identity_classification`, `label`.

### Stage 2: Deduplication & Quality Filtering
1. **Remove Duplicate Rows:** Especially prevalent in CIC-IDS2017 due to multi-collector overlap.
2. **Handle Infinite and NaN Values:** Replace `Flow Bytes/s` overflow values with column 99.9th percentile values.
3. **Cleanse Private IP Artifacts:** In CSE-CIC-IDS2018, ensure source IP subnets do not collide with BECPL's assigned 172.20.0.0/16 architecture during joint training.

### Stage 3: Train / Validation / Test Partitioning
* **Temporal Partitioning:** Where timestamps are available (e.g. ToN_IoT, CSE-CIC-IDS2018), partition chronologically rather than randomly to prevent data leakage across sliding time windows.
* **Class-Preserving Stratified Split:** When chronological splitting is not feasible, use Stratified 5-Fold Cross-Validation preserving rare attack classes (e.g., Modbus parameter modification, Heartbleed).

### Stage 4: Integration with BECPL Simulation Data
Blend public datasets with simulated telemetry at a calibrated ratio:
* 70% public industrial/enterprise flow baseline (volume and diversity).
* 30% BECPL simulation records (domain-specific VLAN layouts, OT registers, identity classes, and vendor access patterns).

---

## 5. Acknowledgement of Limitations & Mitigations

| Dataset Limitation | Real-World Impact | VaultX Mitigation Strategy |
| :--- | :--- | :--- |
| **Extreme Class Imbalance** | Benign flows outnumber attack vectors 99:1; ML models can collapse to naive majority-class predictors. | Apply SMOTE / focal loss during offline training; use rule-based Suricata and deterministic Zeek notices as high-confidence guardrails. |
| **Domain Mismatch in OT** | HAI covers chemical water plants, not electronics assembly line pick-and-place PLCs. | Leverage HAI solely for continuous variable drift algorithms; use `becpl_ot_monitor.zeek` for discrete Modbus FC 0x05/0x10 command enforcement. |
| **Absence of Identity Context** | Public datasets evaluate IPs only; unable to discern whether an IP belongs to a third-party vendor, machine service account, or human employee. | Run `becpl_identity_enrichment.zeek` to inject `identity_classification` tags into connection flows before feeding the ML inference engine. |
| **Time Period & Tool Decay** | Attack tools in 2017/2018 datasets (e.g. LOIC, Patator) exhibit distinct TCP signature artifacts absent in modern Living-off-the-Land (LOTL) attacks. | Use `attack_scenario_gen.py` to inject contemporary LOTL (PowerShell, certutil, mshta) and TLSv1.3 encrypted C2 patterns into the training corpus. |

---
*Maintained by the VaultX Telemetry & Sensor Engineering Team (BECPL SOC).*
