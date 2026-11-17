# Organisation Profile — Bharat Electronics Components Pvt. Ltd. (BECPL)

> **Document version:** 1.0  
> **Classification:** Internal – VaultX Project Reference  
> **Last updated:** 2026-11-17  
> **Owner:** Infrastructure Architect, VaultX NIDS Project

---

## 1. Company Overview

| Attribute | Details |
|---|---|
| **Legal Name** | Bharat Electronics Components Pvt. Ltd. |
| **Short Name / Abbreviation** | BECPL |
| **Type** | Private Limited Company |
| **Category** | MSME – Medium Enterprise |
| **Founded** | 2009 |
| **Headquarters** | Plot No. 47-B, Bhosari MIDC, Pune, Maharashtra – 411026 |
| **CIN** | U32300MH2009PTC192847 *(illustrative)* |
| **GSTIN** | 27AABCB1234F1ZK *(illustrative)* |
| **Employee Strength** | ~120 (permanent) + ~15 contract workers |
| **Annual Turnover** | ₹35–60 Crore (FY 2025–26 estimate) |
| **Fiscal Year** | April – March |

---

## 2. Business Profile

BECPL is a mid-tier electronics contract manufacturer specialising in the design, fabrication, and testing of printed circuit boards (PCBs), embedded hardware modules, and industrial IoT sensor assemblies. The company serves as a Tier-2 supplier to several automotive electronics and consumer electronics original equipment manufacturers (OEMs) operating in India.

The company operates a single manufacturing campus in Bhosari MIDC, Pune — a 12,000 sq. ft. climate-controlled facility — housing SMT lines, through-hole assembly, testing chambers, and a bonded warehouse.

BECPL has achieved steady growth on the back of "Make in India" procurement preferences and PLI (Production-Linked Incentive) scheme participation for electronics manufacturing.

---

## 3. Manufacturing Scope

### 3.1 Core Capabilities
- **PCB Fabrication & Assembly** — Multi-layer PCBs (up to 12 layers), SMT + THT hybrid assembly
- **Embedded Module Manufacturing** — ARM Cortex-M/A series SBCs, communication modules (LoRa, NB-IoT, BLE)
- **IoT Sensor Assemblies** — Temperature, humidity, vibration, and current-sensing modules for industrial and automotive use
- **Firmware Integration** — Basic bootloader flashing and OTA firmware staging during production
- **Quality & Testing** — AOI (Automated Optical Inspection), ICT (In-Circuit Testing), functional burn-in testing

### 3.2 Production Lines
| Line | Description | Volume (monthly) |
|---|---|---|
| SMT Line A | High-speed SMT for consumer-grade PCBs | ~8,000 boards |
| SMT Line B | Precision SMT for automotive-grade PCBs | ~3,500 boards |
| THT Assembly | Manual and semi-automated through-hole | ~1,200 boards |
| IoT Sensor Line | Sensor module assembly & calibration | ~2,000 units |
| Embedded Module Line | SBC/comm-module flashing & testing | ~600 units |

---

## 4. Product Lines

| Product Category | Key Products | End-Use Sector |
|---|---|---|
| **PCBs** | 4L/8L automotive control PCBs, LED driver boards, power supply boards | Automotive, Industrial, Consumer |
| **Embedded Modules** | LoRa gateway boards, NB-IoT breakout boards, BLE beacon modules | Smart City, Agriculture, Asset Tracking |
| **IoT Sensors** | Industrial temp/humidity sensors, vibration monitors, smart meter sub-assemblies | Industrial Automation, Utility |
| **Custom Assemblies** | Box-build assemblies for OEM customers | Consumer Electronics OEMs |

---

## 5. Key Customers

| Customer Segment | Representative Clients | Procurement Mode |
|---|---|---|
| **Automotive OEMs** | Tier-1 suppliers to Tata Motors, Mahindra, Maruti (undisclosed sub-tier) | Long-term supply agreements |
| **Consumer Electronics OEMs** | Contract client for a leading FMCG electronics brand (NDA) | Spot + scheduled POs |
| **Industrial IoT Solution Providers** | 2 start-up IoT platform companies (Pune/Bangalore) | Project-based |
| **Government / PSU** | DRDO evaluation batches (through distributor) | Tender-based |

---

## 6. Supply Chain & Key Business Dependencies

### 6.1 Component Suppliers
| Category | Supplier Region | Key Risk |
|---|---|---|
| Semiconductors (MCUs, power ICs) | Taiwan (TSMC ecosystem), China (Shenzhen OEMs) | Geopolitical disruption, USD/INR FX risk |
| Passive components (resistors, capacitors) | China (Yageo, Samsung distributors) | Tariff/duty risk |
| PCB bare boards | China (domestic manufacturers), India (Genus PCB) | Quality variation |
| Local distributors | Arrow India, Mouser (domestic) | Lead time risk |

### 6.2 Logistics Partners
| Partner | Mode | Scope |
|---|---|---|
| **DTDC** | Road, Air | Domestic dispatch (components & FG goods) |
| **BlueDart** | Air Express | Priority shipments, automotive-grade deliveries |
| **DHL India** | International Air | Import of components from Taiwan/China |
| **Mumbai Port (JNPT)** | Sea Freight | Bulk component imports |

### 6.3 Cloud & Digital Infrastructure
| Provider | Service | Region |
|---|---|---|
| **AWS India (Mumbai Region – ap-south-1)** | ERP hosting (SAP B1 on EC2), S3 for document storage, CloudTrail | ap-south-1 |
| **Microsoft 365** | Email, Teams, SharePoint | Global (India data residency) |
| **Zoho CRM** | Sales pipeline, customer management | SaaS (Zoho India servers) |
| **GitHub Enterprise** | Firmware source code repository | Cloud (US), accessed via VPN |

---

## 7. IT Infrastructure Maturity

**Overall Maturity Level: Medium-Low (ML-2 on a 5-point scale)**

| Domain | Maturity | Notes |
|---|---|---|
| Networking | Medium | Managed switches, basic VLAN segmentation (being formalised) |
| Endpoint Management | Low-Medium | Mix of Windows 10/11 PCs; partial MDM (Intune pilot) |
| Identity & Access | Low | On-prem Active Directory, no MFA enforced (MFA under rollout) |
| Patch Management | Low | Irregular patching cycles; some OT equipment unpatched for 2+ years |
| Security Monitoring | Low | No SIEM; firewall logs reviewed ad hoc |
| Backup & DR | Medium | Daily tape backup + AWS S3 replication; no tested DR plan |
| OT/ICS Security | Very Low | OT network is flat; no network-level controls between IT and OT |
| Vendor/Third-party | Low | No formal vendor access policy; VPN credentials shared |
| Incident Response | Very Low | No IRP; no security on-call roster |

---

## 8. IT & Security Team

| Role | Count | Scope |
|---|---|---|
| IT Manager | 1 | Overall IT ops, vendor coordination |
| Network/Systems Admin | 2 | Network, servers, endpoint support |
| IT Support Technician | 1 (part-time) | Helpdesk, printer/peripheral support |
| **Security Personnel** | 0 dedicated | Security tasks absorbed by IT Manager & sys admin |
| **External Security Partner** | 1 (retainer) | Quarterly pen-test, ad hoc incident support |

> **Note:** VaultX NIDS will be managed operationally by the Network/Systems Admin with escalations to the IT Manager. No CISO or dedicated SOC exists.

---

## 9. Compliance Posture

| Standard / Framework | Status | Notes |
|---|---|---|
| **ISO 9001:2015** | Certified | Manufacturing quality management; surveillance audit due Q3 2026 |
| **STQC (BIS IS 13252)** | Awareness only | STQC certification not yet pursued; on roadmap for FY 2026-27 |
| **CERT-In Guidelines (IT Act 2000)** | Partial | No formal incident reporting process; cybersecurity policy in draft |
| **RBI DPDP Act 2023** | Awareness | Limited PII processing; DPDP readiness assessment pending |
| **IEC 62443 (OT Security)** | Not started | Identified as gap in VaultX scoping exercise |
| **NIST CSF 2.0** | Aspirational | Referenced in VaultX project charter |

---

## 10. Key Business Risks (Cyber / Operational)

1. **OT/IT Convergence Risk** — Unprotected OT network; SMT line PLC accessible from same LAN as office PCs.
2. **Supply Chain Cyber Risk** — Firmware delivered via USB from Chinese component vendors; no code signing.
3. **Insider Threat** — Low identity hygiene; shared credentials on production HMIs.
4. **Third-party Remote Access** — Maintenance vendors access OT systems via shared TeamViewer credentials.
5. **Ransomware Exposure** — No EDR on 60% of endpoints; backup restore untested.
6. **Data Exfiltration** — Engineering IP (Gerber files, firmware source) stored on shared drives without DLP.
7. **Cloud Misconfiguration** — AWS S3 buckets with broad IAM policies; CloudTrail enabled but logs unreviewed.

---

## 11. VaultX Project Context

BECPL has commissioned the **VaultX Manufacturing-Aware Hybrid NIDS** project to address the network-layer visibility and threat detection gaps identified above. The project spans three phases:

| Phase | Scope | Timeline |
|---|---|---|
| **Phase 1 – Visibility & Baseline** | Passive sensor deployment, asset discovery, traffic baselining | Month 1–3 |
| **Phase 2 – Threat Detection** | Signature + anomaly detection engine, alert pipeline, SIEM integration | Month 4–7 |
| **Phase 3 – Response & Hardening** | Automated response playbooks, OT policy enforcement, compliance reporting | Month 8–12 |

---

*Document prepared by: VaultX Infrastructure Architect*  
*Review cycle: Quarterly or upon significant infrastructure change*
