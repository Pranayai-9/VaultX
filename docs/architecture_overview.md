# Architecture Overview — VaultX Manufacturing-Aware Hybrid NIDS

> **Document version:** 1.0  
> **Classification:** Internal – Restricted  
> **Last updated:** 2026-11-17  
> **Owner:** Infrastructure Architect, VaultX NIDS Project  
> **Audience:** VaultX Project Stakeholders, BECPL IT Team, Security Partner

---

## 1. Executive Summary

**VaultX** is a Manufacturing-Aware Hybrid Network Intrusion Detection System (NIDS) designed specifically for Bharat Electronics Components Pvt. Ltd. (BECPL), a Pune-based MSME electronics manufacturer. The system provides unified visibility and threat detection across BECPL's IT, Engineering, Operational Technology (OT), and Logistics network zones.

VaultX is delivered in three phases over 12 months, progressing from passive visibility and baselining, through active threat detection and alerting, to automated response and regulatory compliance reporting.

**Key Design Principles:**
- **IT/OT Separation Preserved** — All detection is passive in OT zones; no active scanning or response in VLAN 30
- **Zone-Based Trust Architecture** — 7 VLANs with explicit deny-all defaults and minimal explicit allows
- **Hybrid Detection** — Combines signature-based (Suricata rules) and ML-based anomaly detection (behavioural baselines)
- **Indian Manufacturing Context** — Tuned for Modbus, EtherNet/IP, MQTT, and common embedded firmware protocols
- **Minimal Footprint** — NIDS probes are passive; no inline blocking in OT (avoid production impact)

---

## 2. Three-Phase Delivery Architecture

### Phase 1 — Visibility & Baseline (Months 1–3)

**Goal:** Establish full network visibility, discover all assets, and build behavioural baselines.

**Key Deliverables:**
- Passive NIDS probe deployment at all 4 production SPAN points (SP-01 through SP-04)
- VaultX Asset Discovery Engine — auto-populates `assets.json` from passive traffic
- Protocol fingerprinting for OT protocols (Modbus, EtherNet/IP, MQTT, S7comm)
- 90-day baseline capture (traffic volumes, communication peers, protocol patterns per VLAN)
- VaultX Management Console deployment on VLAN 70 (SEC-NIDS-MGR01)
- SIEM integration: Wazuh ingest from all probes

**Infrastructure Added (Phase 1):**
- 4× VaultX Probe appliances (OT-NIDS-PROBE01, WH-NIDS-PROBE01, SEC-PROBE-CORP, SEC-PROBE-ENG)
- 1× VaultX Management Server (SEC-NIDS-MGR01)
- SPAN port configuration on Cisco Catalyst 9300, Cisco IE-3300

---

### Phase 2 — Threat Detection (Months 4–7)

**Goal:** Activate signature + anomaly detection; build alert pipeline.

**Key Deliverables:**
- Suricata IDS ruleset activation (Emerging Threats + custom OT rules)
- ML anomaly detection model training on Phase 1 baseline
- Modbus/DNP3 command validation engine
- Alert routing: Probe → SIEM (Wazuh) → PagerDuty / SMS → IT Manager
- Threat Intelligence integration: MISP feed ingestion (SEC-THREATINTEL01)
- VaultX dashboard: Live topology map with alert overlay
- Identity-aware correlation: map network flows to `identity_classification` from asset registry

**New Detection Capabilities:**
- OT protocol anomaly (unexpected Modbus function codes, coil writes outside business hours)
- Lateral movement detection (inter-VLAN unexpected paths)
- Vendor session anomaly (access outside approved windows, non-standard ports)
- Cloud exfiltration heuristics (large outbound to unexpected destinations via VLAN 60)

---

### Phase 3 — Response & Hardening (Months 8–12)

**Goal:** Automated response playbooks, OT policy enforcement, compliance reporting.

**Key Deliverables:**
- FortiGate integration: automated firewall rule push on confirmed threats (IT zones only)
- OT incident playbook: alert → human review → physical isolation (no automated OT blocking)
- BECPL Cybersecurity Incident Response Plan (IRP) document
- ISO 9001 / IEC 62443 compliance reporting module
- CERT-In 6-hour notification workflow
- Annual red team exercise plan
- VaultX dashboard v2: compliance posture view, trend analytics

---

## 3. Network Architecture Diagram

```mermaid
flowchart TD
    INTERNET["🌐 Internet\n(ISP: Jio Business + ACT Failover)"]
    
    subgraph EXTERNAL["External Ecosystem"]
        AWS["☁️ AWS India\n(ap-south-1)\nERP, S3, CloudTrail"]
        M365["📧 Microsoft 365\nEmail, Teams"]
        GITHUB["🔧 GitHub Enterprise\nFirmware Repos"]
        ZOHO["📊 Zoho CRM"]
        DTDC["🚚 DTDC / BlueDart\nLogistics APIs"]
        SIEMENS["⚙️ Siemens Partner\nOT Maintenance\n(On-site only)"]
        CODEBRIDGE["💻 CodeBridge\nFirmware Dev\n(Remote-Bastion)"]
    end

    INTERNET <-->|"WAN - 100Mbps Jio + 50Mbps ACT"| FG

    subgraph BECPL["BECPL Campus — Bhosari MIDC, Pune"]
        FG["🛡️ FortiGate 100F\nNGFW + Inter-VLAN Router\nBorder Security"]
        CORE["🔀 Cisco Catalyst 9300\nCore Switch\n(VLAN trunk)"]

        FG <-->|"Trunk"| CORE

        subgraph V10["VLAN 10 — Corporate IT (10.10.10.0/24)"]
            DC["AD Domain Controllers\n10.10.10.2/.3"]
            FS["File Server\n10.10.10.4"]
            CORP_WS["Workstations x8\n10.10.10.20-34"]
            BACKUP["Backup Server\n10.10.10.11"]
        end

        subgraph V20["VLAN 20 — Engineering & Firmware (10.10.20.0/24)"]
            BUILD["Jenkins CI/CD\n10.10.20.2"]
            GIT["Git Mirror\n10.10.20.3"]
            OTA["OTA Staging\n10.10.20.4"]
            ENG_WS["Eng Workstations x5\n10.10.20.10-14"]
            ENG_NAS["NAS - Gerber/BOM\n10.10.20.6"]
        end

        subgraph V30["VLAN 30 — Manufacturing OT (10.10.30.0/24) 🔴 ISOLATED"]
            MES["MES Server\n10.10.30.3"]
            SCADA["SCADA Gateway\n10.10.30.2"]
            PLC["PLCs x5\n10.10.30.10-14\nSiemens S7-1200"]
            HMI["HMIs x3\n10.10.30.20-22"]
            AOI["AOI Machines x2\n10.10.30.30-31"]
            ICT["ICT/Burn-in\n10.10.30.40-41"]
            OT_PROBE["VaultX Probe\n10.10.30.60"]
        end

        subgraph V40["VLAN 40 — Warehouse & Logistics (10.10.40.0/24)"]
            WMS["WMS Server\n10.10.40.2"]
            SCANNERS["Barcode Scanners x3\n10.10.40.10-12"]
            RFID["RFID Gateways x2\n10.10.40.20-21"]
            WH_PC["WH Workstations x2\n10.10.40.30-31"]
            WH_PROBE["VaultX Probe\n10.10.40.50"]
        end

        subgraph V50["VLAN 50 — DMZ & Vendor Access (10.10.50.0/24)"]
            BASTION["Bastion Host\n10.10.50.2"]
            VENDOR_PORTAL["Vendor Portal\n10.10.50.3"]
            VPN_GW["VPN Gateway\n10.10.50.10"]
            WAF["FortiWeb WAF\n10.10.50.20"]
        end

        subgraph V60["VLAN 60 — Cloud & External (10.10.60.0/24)"]
            PROXY["Squid Proxy\n10.10.60.2\nSSL Inspection"]
            MAILGW["Email Gateway\n10.10.60.3"]
            AWS_VPN["AWS VPN Term.\n10.10.60.4"]
            M365_GW["M365 Gateway\n10.10.60.10"]
        end

        subgraph V70["VLAN 70 — Security Management (10.10.70.0/24) 🟢 OOB"]
            SIEM["Wazuh SIEM\n10.10.70.2"]
            NIDS_MGR["VaultX NIDS Mgr\n10.10.70.3"]
            NMS["Zabbix NMS\n10.10.70.4"]
            MISP["MISP Threat Intel\n10.10.70.5"]
            JUMPHOST["Admin Jumphost\n10.10.70.11\nMFA Required"]
            PROBES_MGR["NIDS Probes Mgmt\n10.10.70.20-23"]
        end

        CORE <-->|"L2 trunk"| V10
        CORE <-->|"L2 trunk"| V20
        CORE <-->|"Industrial SW\nIE-3300"| V30
        CORE <-->|"L2 trunk"| V40
        CORE <-->|"L2 trunk"| V50
        CORE <-->|"L2 trunk"| V60
        CORE <-->|"OOB mgmt"| V70
    end

    V10 <-->|"HTTPS 443\nEmail relay"| V60
    V20 <-->|"HTTPS 443\nallowlisted"| V60
    V40 <-->|"HTTPS 443\nAPI calls"| V60
    V60 <-->|"TLS 1.3"| AWS
    V60 <-->|"TLS 1.3"| M365
    V60 <-->|"TLS 1.3"| GITHUB
    V60 <-->|"TLS 1.3"| ZOHO
    V60 <-->|"HTTPS API"| DTDC

    V50 <-->|"HTTPS 443"| INTERNET
    CODEBRIDGE <-->|"SSH via VPN\nMFA+4h limit"| V50
    BASTION <-->|"SSH - VLAN20 only"| V20
    BASTION <-->|"RDP - VLAN10 only"| V10

    OTA <-->|"MQTT-TLS 8883\ntime-boxed"| V30

    V70 <-->|"Passive SPAN\nSyslog UDP 514"| V30
    V70 <-->|"SNMP/Syslog"| V10
    V70 <-->|"SNMP/Syslog"| V20
    V70 <-->|"SNMP/Syslog"| V40

    SIEMENS <-->|"On-site only\nPhysical console"| V30

    style V30 fill:#ffdddd,stroke:#cc0000,color:#000
    style V70 fill:#ddffdd,stroke:#006600,color:#000
    style V50 fill:#fff3cd,stroke:#856404,color:#000
    style BECPL fill:#f0f4ff,stroke:#3366cc,color:#000
```

---

## 4. System Context Diagram — BECPL External Relationships

```mermaid
flowchart LR
    subgraph BECPL_CTX["BECPL — Bharat Electronics Components Pvt. Ltd."]
        BECPL_CORE["BECPL IT/OT\nInfrastructure\n(7 VLANs)"]
        VAULTX["VaultX\nHybrid NIDS\nSecurity Overlay"]
    end

    subgraph SUPPLIERS["Component Suppliers"]
        TAIWAN["🇹🇼 Taiwan\n(TSMC ecosystem)\nMCUs, ICs"]
        CHINA["🇨🇳 China\n(Shenzhen OEMs)\nPassives, bare PCBs"]
        INDIA_DIST["🇮🇳 Arrow India\nMouser India\n(Local distributors)"]
    end

    subgraph CUSTOMERS["Customers / OEMs"]
        AUTO_OEM["🚗 Automotive Tier-1\n(Tata, Mahindra supply chain)"]
        CE_OEM["📱 Consumer Electronics\nOEM (NDA)"]
        IOT_CO["🏭 IoT Platform\nCompanies (Pune/BLR)"]
        GOVT["🏛️ DRDO / PSU\n(via distributor)"]
    end

    subgraph LOGISTICS["Logistics Partners"]
        DTDC2["🚚 DTDC Express"]
        BLUEDART2["✈️ BlueDart Express"]
        DHL2["🌍 DHL India\n(International)"]
        JNPT["🚢 JNPT Mumbai\n(Sea freight)"]
    end

    subgraph CLOUD_CTX["Cloud & SaaS"]
        AWS2["☁️ AWS India\nap-south-1\nERP + Storage"]
        M365_2["📧 Microsoft 365\nEmail + Collab"]
        GITHUB2["🔧 GitHub Enterprise\nFirmware source"]
        ZOHO2["📊 Zoho CRM\nSales pipeline"]
    end

    subgraph REGULATORS["Regulatory / Compliance"]
        ISO9001["📋 ISO 9001:2015\n(Certified)"]
        CERTIN["🔒 CERT-In\n(NCIIPC guidelines)"]
        STQC["🏷️ STQC / BIS\n(In progress)"]
        DPDP["📜 DPDP Act 2023\n(Awareness)"]
    end

    subgraph VENDORS_CTX["Service Vendors"]
        SIEMENS2["⚙️ Siemens India\nOT Maintenance"]
        CODEBRIDGE2["💻 CodeBridge\nFirmware Dev"]
        NETSOLVE["🖥️ NetSolve\nIT Infrastructure"]
        VAULTX_PARTNER["🛡️ VaultX\nSecurity Partner"]
    end

    SUPPLIERS --> |"Components\n(import by sea/air)"| BECPL_CORE
    BECPL_CORE --> |"Finished goods\n(PCBs, modules, sensors)"| CUSTOMERS
    BECPL_CORE <--> |"Shipping\n& tracking API"| LOGISTICS
    BECPL_CORE <--> |"ERP, email\n, source control"| CLOUD_CTX
    BECPL_CORE <--> |"Maintenance\n& dev services"| VENDORS_CTX
    VAULTX --> |"Monitors\nall zones"| BECPL_CORE
    VAULTX --> |"Reports to"| CERTIN
    BECPL_CORE --> |"Compliance\nreporting"| REGULATORS
```

---

## 5. Security Architecture Principles

### 5.1 Defense-in-Depth Stack

| Layer | Control |
|---|---|
| **Perimeter** | FortiGate 100F NGFW with IPS, SSL inspection, geo-blocking |
| **Network Segmentation** | 7 VLANs with explicit inter-VLAN firewall policy |
| **OT Isolation** | VLAN 30 default deny-all; physical air-gap for vendor maintenance |
| **Detection** | VaultX hybrid NIDS (signature + ML anomaly) across 4 SPAN points |
| **Identity** | Active Directory + MFA (Duo/Authenticator) rollout; PAM for privileged access |
| **Endpoint** | Windows Defender ATP on IT endpoints; EDR rollout in progress |
| **Cloud** | AWS CloudTrail, IAM least-privilege, S3 bucket policies, GuardDuty |
| **Response** | SIEM alert pipeline → IT Manager → FortiGate automated response (IT only) |
| **Logging** | Centralised on VLAN 70 (Wazuh + OpenSearch); 1-year retention |

### 5.2 Trust Boundaries

```
HIGH TRUST (internal, authenticated)
│  VLAN 70 — Security Management (admin + MFA only)
│  VLAN 20 — Engineering (domain auth, allowlisted internet)
│  VLAN 10 — Corporate IT (domain auth)
│
MEDIUM TRUST (controlled, monitored)
│  VLAN 40 — Warehouse (domain auth, limited scope)
│  VLAN 30 — Manufacturing OT (isolated, no external auth)
│
LOW TRUST (controlled access, session-limited)
│  VLAN 50 — DMZ/Vendor (MFA + bastion + session recording)
│  VLAN 60 — Cloud/External (proxy only, SSL inspected)
│
ZERO TRUST (untrusted)
   Internet / External
```

### 5.3 OT-Specific Security Decisions

| Decision | Rationale |
|---|---|
| **No inline blocking in VLAN 30** | Risk of production disruption (false positives stopping PLCs = manufacturing halt) |
| **Passive SPAN taps only in OT** | No active probes that generate traffic to OT devices |
| **Separate industrial switch (IE-3300)** | Supports OT protocols and power redundancy; isolates from IT switching fabric |
| **On-site-only OT vendor access** | Remote OT access is unacceptably high risk; Siemens engineers must physically attend |
| **Modbus/EtherNet/IP deep inspection** | VaultX probe performs protocol-aware parsing; alerts on function code anomalies |
| **OT asset patching freeze** | PLC firmware only updated during scheduled maintenance windows (quarterly) |

---

## 6. Data Flow Summary

| Flow | Source | Destination | Protocol | Inspection |
|---|---|---|---|---|
| Corporate internet | VLAN 10 | Internet | HTTPS via VLAN 60 proxy | SSL inspection (FortiGate) |
| OT telemetry → SIEM | VLAN 30 | VLAN 70 | Syslog UDP 514 | VaultX probe passively monitors |
| Firmware OTA push | VLAN 20 (OTA server) | VLAN 30 (PLCs) | MQTT-TLS 8883 | Allowlisted flow; VaultX alert if off-schedule |
| Vendor remote session | Internet → VLAN 50 | VLAN 20 or 10 | SSH/RDP via bastion | Full session recording |
| ERP cloud sync | VLAN 10/60 | AWS ap-south-1 | HTTPS + IPSec VPN | CloudTrail + VaultX cloud module |
| Logistics API | VLAN 40/60 | DTDC/BlueDart | HTTPS REST API | Proxy allowlist; API key auth |
| Threat intel updates | VLAN 70 (MISP) | Internet (via proxy) | HTTPS | Allowlisted feeds only |

---

## 7. VaultX Component Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    VLAN 70 — Security Management                 │
│  ┌──────────────────┐   ┌────────────────┐   ┌───────────────┐  │
│  │  VaultX NIDS Mgr  │   │  Wazuh SIEM    │   │  MISP TI Feed │  │
│  │  (SEC-NIDS-MGR01) │◄──│  (SEC-SIEM01)  │◄──│  Aggregator   │  │
│  │  - Probe mgmt     │   │  - Alert mgmt  │   │  (SEC-TI-01)  │  │
│  │  - Topology map   │   │  - Correlation │   └───────────────┘  │
│  │  - Rule engine    │   │  - Dashboard   │                       │
│  └──────────────────┘   └────────────────┘                       │
└─────────────────────────────────────────────────────────────────┘
         ▲                      ▲                    ▲
         │ Probe telemetry      │ Syslog/SNMP        │
    ┌────┴──────┐          ┌────┴──────┐        ┌────┴──────┐
    │  Probe    │          │  Probe    │        │  Probe    │
    │  OT SPAN  │          │  Corp SPAN│        │  WH SPAN  │
    │ (VLAN 30) │          │ (VLAN 10) │        │ (VLAN 40) │
    └───────────┘          └───────────┘        └───────────┘
         │                      │                    │
    [SMT PLCs]            [Corp Workstations]   [WMS/Scanners]
    [HMIs/AOI]            [Servers/Printers]    [RFID Gateways]
```

---

## 8. Compliance Mapping

| Requirement | Framework | VaultX Control |
|---|---|---|
| Continuous network monitoring | NIST CSF DE.CM-1 | NIDS probes + SIEM |
| OT network segmentation | IEC 62443-3-3 SR 5.1 | VLAN 30 isolation + FortiGate policy |
| Audit log integrity | ISO 27001 A.12.4 | Centralised log collection VLAN 70, tamper-evident |
| Incident detection & response | CERT-In 2022 directions | VaultX alert pipeline + IRP (Phase 3) |
| Vendor access controls | ISO 27001 A.15 | Vendor Access Policy (this project) |
| Vulnerability management | NIST CSF ID.RA-1 | OpenVAS (SEC-VULN-SCAN01), quarterly scan |

---

*Document prepared by: VaultX Infrastructure Architect*  
*Review cycle: Quarterly or upon major architecture change*
