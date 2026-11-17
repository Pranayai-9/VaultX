# VaultX Dataset Management & Benchmark Repository
## Bharat Electronics Components Pvt. Ltd. (BECPL), Pune, Maharashtra

---

## 1. Directory Structure

```text
datasets/
├── README.md                           <- Master dataset governance & retrieval guide
├── raw/                                <- Pristine, unmodified source datasets (gitignored / external)
├── processed/                          <- Harmonised feature vectors, parquet/csv partitions & benchmarks
│   └── becpl_synthetic_traffic_50k.csv <- BECPL manufacturing-tailored synthetic dataset (~50,000 records)
├── metadata/                           <- Schema definitions, mapping matrices & academic documentation
│   ├── dataset_documentation.md        <- Deep-dive documentation for all 6 reference datasets
│   └── feature_harmonisation.json      <- JSON mapping schema to unified BECPL NIDS standard
└── scripts/                            <- Processing, synthesis, and validation tooling
    ├── requirements.txt                <- Python dependencies (pandas, numpy, scikit-learn, redis)
    ├── dataset_validator.py            <- Rigorous dataset validator & leakage checker
    └── generate_becpl_traffic.py       <- High-fidelity synthetic traffic generator (50k records)
```

---

## 2. Research Dataset Disclaimer & Indian MSME Context

> [!IMPORTANT]
> **DISCLAIMER REGARDING ACADEMIC & PUBLIC BENCHMARK DATASETS:**
> The public datasets referenced in this repository (e.g., CIC-IDS2017, CSE-CIC-IDS2018, ToN_IoT, X-IIoTID, HAI 22.04, UNSW-NB15) originate from controlled university testbeds, simulated enterprise labs in North America, Australia, or South Korea.
> 
> **Key Realities for Indian Manufacturing MSMEs like BECPL:**
> 1. **Traffic Profile Divergence:** Academic datasets typically model generic corporate IT web-browsing, video streaming, and broad volumetric DDoS floods. In contrast, an Indian electronics manufacturing MSME network features high-frequency deterministic telemetry (Modbus/TCP, MQTT, S7Comm, OPC-UA), sporadic ERP batch updates, tight vendor VPN tunnels, and virtually zero consumer internet browsing from the plant floor.
> 2. **Infrastructure Asymmetry:** Public datasets assume modern high-bandwidth architectures. Indian MSMEs frequently operate with asymmetrical uplinks (e.g., 100 Mbps MPLS primary with dynamic failover), older unmanaged switches in peripheral areas, legacy Windows workstations running EOL operating systems due to proprietary CAD toolchain dependencies, and air-gapped or semi-isolated OT segments.
> 3. **Role of Public Datasets:** Consequently, the public datasets are utilized for **baseline feature engineering, initial model pre-training, and benchmark validation**, whereas the primary detection engines in VaultX are fine-tuned on the tailored **BECPL Synthetic Manufacturing Dataset** (`becpl_synthetic_traffic_50k.csv`).

---

## 3. Dataset Download Instructions

Due to repository size constraints and storage optimization, raw PCAP and multi-gigabyte CSV files are stored on external secure academic mirrors. Follow the instructions below to acquire each benchmark:

### 3.1 CIC-IDS2017 (Canadian Institute for Cybersecurity)
- **URL:** [UNB CIC-IDS2017 Dataset Portal](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Files:** `GeneratedLabelledFlows.zip` (CSV flows) or `PCAPs.zip`
- **Destination:** Place unzipped CSVs into `datasets/raw/cic_ids2017/`

### 3.2 CSE-CIC-IDS2018 (AWS & CIC)
- **URL:** [AWS Open Data Registry – CSE-CIC-IDS2018](https://registry.opendata.aws/cse-cic-ids2018/)
- **Command:** `aws s3 sync --no-sign-request s3://cse-cic-ids2018/ProcessedTrafficData/ datasets/raw/cse_cic_ids2018/`

### 3.3 ToN_IoT (UNSW Canberra Cyber)
- **URL:** [UNSW ToN_IoT Repository](https://cloudstor.aarnet.edu.au/plus/s/ds5vHzRPJyRAigB)
- **Files:** `Network_dataset/` (Network flow CSVs) and `IoT_dataset/` (Telemetry logs)
- **Destination:** `datasets/raw/ton_iot/`

### 3.4 X-IIoTID (Industrial IoT Intrusion Dataset)
- **URL:** [IEEE Dataport – X-IIoTID](https://ieee-dataport.org/documents/x-iiotid-connectivity-and-agnostic-intrusion-dataset-industrial-internet-things)
- **Files:** `X-IIoTID.csv`
- **Destination:** `datasets/raw/x_iiotid/`

### 3.5 HAI 22.04 (Hardware-in-the-Loop Augmented ICS Dataset)
- **URL:** [GitHub – ETRI HAI Dataset](https://github.com/icsdataset/hai)
- **Files:** `hai-22.04.tar.gz`
- **Destination:** `datasets/raw/hai_22_04/`

### 3.6 UNSW-NB15 (Australian Centre for Cyber Security)
- **URL:** [UNSW-NB15 Data Portal](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- **Files:** `UNSW-NB15_1.csv` through `UNSW-NB15_4.csv`
- **Destination:** `datasets/raw/unsw_nb15/`

---

## 4. Academic Citation Requirements

When utilizing or publishing evaluation results derived from these benchmarks alongside VaultX, cite the original works:

1. **CIC-IDS2017:**
   > Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP. DOI: 10.5220/0006639801080116.
2. **CSE-CIC-IDS2018:**
   > Canadian Institute for Cybersecurity & AWS (2018). *Communications Security Establishment & CIC Collaborative Dataset*. University of New Brunswick.
3. **ToN_IoT:**
   > Al-Zewairi, M., et al. / Moustafa, N. (2020). *A new distributed architecture for evaluating AI-based security systems at the big data in IoT*. IEEE Access. DOI: 10.1109/ACCESS.2020.3015488.
4. **X-IIoTID:**
   > Al-Hawawreh, M., Sitnikova, E., & Aboutorab, N. (2021). *X-IIoTID: A Connectivity-Agnostic and Device-Agnostic Intrusion Dataset for Industrial Internet of Things*. IEEE Access. DOI: 10.1109/ACCESS.2021.3134375.
5. **HAI 22.04:**
   > Shin, H. K., et al. (2022). *HAI 22.04: Hardware-in-the-loop Augmented ICS Security Dataset*. ETRI.
6. **UNSW-NB15:**
   > Moustafa, N., & Slay, J. (2015). *UNSW-NB15: a comprehensive dataset for network intrusion detection systems*. IEEE MilCIS. DOI: 10.1109/MilCIS.2015.7348942.
