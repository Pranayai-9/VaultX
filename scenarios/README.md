# VaultX Attack Scenarios & Threat Simulation Suite
## Bharat Electronics Components Pvt. Ltd. (BECPL), Pune, Maharashtra

---

## 1. Executive Overview

This directory contains the operational and technical definitions of the **seven core attack scenarios** developed for **VaultX**, a Manufacturing-Aware Hybrid Network Intrusion Detection System (NIDS) designed for **Bharat Electronics Components Pvt. Ltd. (BECPL)**. 

BECPL is an electronics manufacturing Micro, Small, and Medium Enterprise (MSME) situated in Bhosari MIDC, Pune, operating Surface Mount Technology (SMT) production lines, through-hole assembly lines, firmware flashing, and IoT sensor manufacturing. Like many Indian manufacturing MSMEs, BECPL operates in a high-threat environment characterized by limited dedicated internal cybersecurity staff (3-4 IT personnel), increasing reliance on external original equipment manufacturer (OEM) vendors for maintenance, cross-VLAN integration between Enterprise Resource Planning (ERP) and Manufacturing Execution Systems (MES), and legacy industrial control assets that cannot host endpoint protection software.

The scenarios documented herein simulate the primary attack vectors, TTPs (Tactics, Techniques, and Procedures), and anomaly patterns observed in targeted cyberattacks against Indian manufacturing and critical supply chain ecosystems.

---

## 2. Threat Landscape: Indian Electronics Manufacturing MSMEs

Indian electronics manufacturing MSMEs face targeted and opportunistic threats driven by geopolitical tensions, intellectual property (IP) theft, industrial espionage, and cybercriminal extortion. Key threat dynamics include:

### 2.1 Threat Actors & Motivations
1. **Ransomware Cartels (e.g., LockBit, BlackCat/ALPHV, Medusa):**
   - **Motivation:** Financial extortion.
   - **Vector:** Double extortion targeting both corporate Windows systems and manufacturing operations (causing production line halts where downtime costs exceed ₹25,00,000 per shift).
   - **Relevance to BECPL:** Adversaries leverage initial access brokers (IABs), compromised vendor VPN credentials, or phishing to gain footholds, followed by Living-off-the-Land (LotL) reconnaissance and multi-VLAN lateral movement.

2. **State-Sponsored APTs & IP Espionage Groups (e.g., Volt Typhoon, APT41, SideCopy):**
   - **Motivation:** Theft of proprietary schematic designs, Gerber files, Bill of Materials (BOM), custom microcontroller firmware (for automotive and defense contracts), and customer lists.
   - **Vector:** Targeted spear-phishing of engineering workstations, supply chain compromise, and low-and-slow encrypted exfiltration using cloud proxies or external VPS infrastructure.

3. **Compromised Supply Chain & Vendor Ecosystems:**
   - **Motivation:** Indirect access into segmented manufacturing networks.
   - **Vector:** Equipment maintenance vendors (e.g., SMT pick-and-place calibrators, reflow oven servicing) accessing internal networks via remote access VPNs without stringent multi-factor authentication (MFA) or session isolation.

4. **Internal Misconfigurations & Service Credential Abuse:**
   - **Motivation:** Opportunistic credential theft or insider sabotage.
   - **Vector:** Over-privileged machine-to-machine (M2M) service tokens (ERP-to-WMS integration accounts) reused by threat actors to exfiltrate inventory manifests or manipulate shipping dispatches.

---

## 3. Summary of Core Attack Scenarios

| Scenario ID | Name | Severity | Primary Segments Involved | Primary MITRE ATT&CK | OT Safety Critical | Human Approval Required |
|:---|:---|:---:|:---|:---|:---:|:---:|
| **SCN-001** | Compromised Third-Party Vendor Access | High | DMZ, Corporate IT, OT | T1078, T1021.004, T1570 | Yes | Yes |
| **SCN-002** | Service Credential Misuse | High | Corporate IT, Cloud/Ext, Warehouse | T1078.004, T1041, T1098 | No | No |
| **SCN-003** | Suspicious Lateral Movement | High | Corporate IT, Engineering, OT | T1021.001, T1018, T1046 | Yes | Yes (if touching OT) |
| **SCN-004** | Living off the Land (LotL) Execution | Critical | Corporate IT | T1059.001, T1140, T1053.005 | No | No |
| **SCN-005** | Encrypted External Exfiltration | Critical | Engineering & Firmware | T1041, T1573.001, T1008 | No | No |
| **SCN-006** | Manufacturing OT Network Anomaly | Critical | Manufacturing OT | T1565.002, T0836, T0855 | Yes | Yes (MANDATORY) |
| **SCN-007** | Vulnerability Exposure & Active Recon | Medium | DMZ, Corporate IT, Engineering | T1595.002, T1046, T1190 | No | No |

---

## 4. Scenario Objectives & Expected Observables

### SCN-001: Compromised Third-Party Vendor Access
- **Objective:** Detect credential abuse and unauthorized cross-segment bridging by an authenticated third-party maintenance vendor.
- **Expected Observables:**
  - Authenticated VPN session originating from an atypical geographic ASN or outside contracted maintenance hours (02:15 IST).
  - SSH / RDP sessions hopping from DMZ Bastion (`DMZ-BASTION01` / `10.10.50.2`) directly into the Manufacturing Execution System (`OT-MES01` / `10.10.30.3`).
  - Unauthorized Modbus TCP (port 502) polling and connection attempts directed at SMT line PLCs (`10.10.30.10` / `172.20.30.12`).
  - Zeek `conn.log` showing policy violations (DMZ-to-OT direct attempts).

### SCN-002: Service Credential Misuse
- **Objective:** Uncover anomalous API usage, token replay, and unauthorized REST endpoint invocation by a trusted service account.
- **Expected Observables:**
  - Token `svc_erp_integration` executing anomalous HTTP POST and DELETE methods on `/shipments/dispatch` and `/suppliers/admin`.
  - Significant burst in outbound HTTP request frequency (from 1 call/5 min baseline to 140 calls/min).
  - Egress flows from the application server towards untrusted external IP addresses.
  - Absence of expected user-agent and header entropy variations.

### SCN-003: Suspicious Lateral Movement
- **Objective:** Identify automated host discovery, credential stuffing, and multi-protocol fan-out scanning across security zones.
- **Expected Observables:**
  - High fan-out ratio from single workstation (`CORP-WS-002` / `10.10.10.21`).
  - RDP (port 3389) connection attempts to 10+ internal endpoints within an 8-minute window.
  - SMB (port 445) session negotiation followed by multiple STATUS_LOGON_FAILURE events (Windows Event ID 4625).
  - Cross-VLAN SSH (port 22) connections into Engineering workstations (`VLAN 20`).

### SCN-004: Living off the Land (LotL)
- **Objective:** Spot evasion-focused tradecraft relying on trusted native Windows administrative binaries (LOLBins).
- **Expected Observables:**
  - Sysmon Event ID 1: `powershell.exe` invoked with `-EncodedCommand`, `-NoProfile`, `-ExecutionPolicy Bypass`.
  - Sysmon Event ID 3 & Zeek `http.log`: `certutil.exe` making outbound HTTP requests with default `certutil` user-agent to download a payload (`msedge_update.bin`).
  - Process execution of `schtasks.exe /create` for persistence.
  - Account creation attempt (`net user /add`).

### SCN-005: Encrypted External Communication (Data Exfiltration)
- **Objective:** Detect exfiltration of proprietary design IP (Gerber files, firmware source) via encrypted TLS without payload decryption.
- **Expected Observables:**
  - Long-duration TLS 1.3 flow (4+ hours) from engineering workstation (`ENG-WS-001` / `10.10.20.10`) to unclassified external IP.
  - High cumulative byte ratio (megabytes to gigabytes outbound vs. minimal inbound acknowledgment).
  - TLS Client Hello metadata showing rare JA3/JA3S fingerprint hash not present in BECPL baseline.
  - Uncategorized or newly registered SNI domain (Dynamic DNS or direct IP).

### SCN-006: Manufacturing OT Network Anomaly
- **Objective:** Catch unauthorized industrial control protocol manipulation and setpoint tampering targeting SMT line PLCs.
- **Expected Observables:**
  - Modbus/TCP traffic originating from unauthorized source IP (`10.10.20.30` or rogue node) targeting PLC (`10.10.30.10`).
  - Modbus Function Code 6 (Write Single Register) or Function Code 16 (Write Multiple Registers) modifying holding register `40003` (Conveyor Speed / Reflow Thermal Zone 2).
  - Modbus Function Code 8 (Diagnostics) scans probing PLC internal state.
  - Industrial safety constraint violation: Automatic isolation inhibited pending human engineering approval.

### SCN-007: Vulnerability Exposure & Active Recon
- **Objective:** Detect external and internal reconnaissance scanning identifying legacy, unpatched manufacturing systems.
- **Expected Observables:**
  - High-rate SYN scan packets across ports 22, 80, 443, 445, 502, 3389, 8080.
  - Characteristic Nmap service version detection probes with aggressive payload signatures.
  - Target responses revealing vulnerable version banners (e.g., Windows 10 1909 SMBGhost CVE-2020-0796, OpenSSH 7.4 CVE-2016-10009, Flask 1.0 CVE-2018-1000656).

---

## 5. Industrial Safety Considerations & Response Protocols

In an operational manufacturing facility like BECPL, **network isolation actions carry direct physical consequences**:
1. Abruptly terminating network connections to a Programmable Logic Controller (PLC) during an active SMT soldering or reflow cycle can cause PCB thermal destruction, component misplacement, solder paste hardening, or mechanical motor lockups.
2. Therefore, VaultX enforces a **Safety-Constrained Response Matrix**:
   - **IT-Only Alerts (e.g., LotL, Corporate Lateral Movement):** Automated quarantine of workstation switch port via 802.1X / FortiGate API is permitted.
   - **OT & Industrial Device Alerts (SCN-001 when touching PLCs, SCN-006):** Automated containment is **strictly prohibited**. VaultX generates high-priority audible and dashboard alerts to the OT On-Duty Engineer and Security Lead. Containment requires explicit two-person authorization ("Four-Eyes Principle") before issuing industrial reset or switch-port disabling commands.

---

## 6. Directory Structure

```text
scenarios/
├── README.md                           <- This master document
├── scenario_definitions.json           <- Machine-readable metadata for all 7 scenarios
├── scenario_01_vendor_compromise.md    <- Deep dive: Vendor Credential Compromise
├── scenario_02_service_credential_misuse.md <- Deep dive: Service Account Misuse
├── scenario_03_lateral_movement.md     <- Deep dive: Internal Lateral Movement
├── scenario_04_lotl.md                 <- Deep dive: Living off the Land Execution
├── scenario_05_encrypted_exfil.md      <- Deep dive: Encrypted Design IP Exfiltration
├── scenario_06_ot_anomaly.md           <- Deep dive: Industrial Protocol Anomaly
├── scenario_07_vulnerability_exposure.md <- Deep dive: Reconnaissance & Vulnerability Scan
└── attack_simulation/
    ├── __init__.py
    ├── base_scenario.py                <- Python generator base class (Redis stream emitter)
    ├── scenario_01.py                  <- Python executable simulation for Scenario 1
    └── scenario_06.py                  <- Python executable simulation for Scenario 6 (OT)
```
