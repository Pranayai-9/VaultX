# Network Topology — Bharat Electronics Components Pvt. Ltd. (BECPL)

> **Document version:** 1.0  
> **Classification:** Internal – Restricted (IT / Security Team only)  
> **Last updated:** 2026-11-17  
> **Owner:** Infrastructure Architect, VaultX NIDS Project

---

## 1. Architecture Overview

BECPL's network is a **single-campus, hybrid architecture** situated at Bhosari MIDC, Pune. The design enforces zone-based segmentation via 7 VLANs served by a **FortiGate 100F next-generation firewall** acting as the core inter-VLAN router and policy enforcer. A **Cisco Catalyst 9300** stacked core switch provides Layer-2 aggregation; access-layer switches serve individual zones.

```
Internet (ISP: Jio Business + ACT Fibernet failover)
         │
  [FortiGate 100F – Border NGFW]
         │
  [Cisco Catalyst 9300 – Core Switch]
    ├── VLAN 10 – Corporate IT
    ├── VLAN 20 – Engineering & Firmware
    ├── VLAN 30 – Manufacturing OT
    ├── VLAN 40 – Warehouse & Logistics
    ├── VLAN 50 – DMZ & Vendor Access
    ├── VLAN 60 – Cloud & External Integrations
    └── VLAN 70 – Security Management (OOB)
```

**Primary WAN:** Jio Business 100 Mbps MPLS/Fiber (static IP block: 103.25.68.0/29)  
**Secondary WAN:** ACT Fibernet 50 Mbps (failover, dynamic IP)  
**Core DNS:** 10.10.70.10 (internal), 8.8.8.8 / 1.1.1.1 (external forwarders)  
**NTP Server:** 10.10.70.11 (syncs to pool.ntp.org)

---

## 2. VLAN Definitions

### 2.1 VLAN 10 — Corporate IT

| Parameter | Value |
|---|---|
| **VLAN ID** | 10 |
| **Name** | Corporate IT |
| **Subnet** | 10.10.10.0/24 |
| **Gateway** | 10.10.10.1 (FortiGate virtual interface) |
| **DNS Server** | 10.10.10.5 (internal AD DNS) |
| **DHCP Range** | 10.10.10.100 – 10.10.10.200 |
| **Static IP Block** | 10.10.10.1 – 10.10.10.99 |
| **Switch** | Cisco Catalyst 2960-X (Wing A) |

**Purpose:** Hosts all corporate office workstations (admin, finance, HR, sales, procurement), the Active Directory domain controllers, file servers, and corporate printers. This is the primary end-user segment.

**Assigned Hosts (Static IPs):**

| IP | Hostname | Device | Role |
|---|---|---|---|
| 10.10.10.1 | FG-VLAN10-GW | FortiGate 100F vif | VLAN Gateway |
| 10.10.10.2 | BECPL-DC01 | Server | AD Domain Controller Primary |
| 10.10.10.3 | BECPL-DC02 | Server | AD Domain Controller Secondary |
| 10.10.10.4 | BECPL-FS01 | Server | File Server (DFS) |
| 10.10.10.5 | BECPL-DNS01 | Server | Internal DNS / DHCP |
| 10.10.10.6 | BECPL-PRINT01 | Printer | Corporate Network Printer |
| 10.10.10.7 | BECPL-PRINT02 | Printer | HR/Finance Printer |
| 10.10.10.10 | BECPL-MGMT01 | Server | IT Management Jump Server |
| 10.10.10.11 | BECPL-BACKUP01 | Server | Backup Server (Veeam) |
| 10.10.10.20 | CORP-WS-001 | Workstation | IT Manager – Workstation |
| 10.10.10.21 | CORP-WS-002 | Workstation | Sys Admin 1 – Workstation |
| 10.10.10.22 | CORP-WS-003 | Workstation | Sys Admin 2 – Workstation |
| 10.10.10.30 | CORP-WS-004 | Workstation | Finance Manager |
| 10.10.10.31 | CORP-WS-005 | Workstation | HR Manager |
| 10.10.10.32 | CORP-WS-006 | Workstation | Procurement Head |
| 10.10.10.33 | CORP-WS-007 | Workstation | Sales Manager |
| 10.10.10.34 | CORP-WS-008 | Workstation | Director/MD Workstation |
| 10.10.10.40 | CORP-VOIP-01 | VoIP Phone | Reception |
| 10.10.10.41 | CORP-VOIP-02 | VoIP Phone | Conference Room |

**Permitted Inter-VLAN Paths:**
- VLAN 10 → VLAN 60 (Cloud/External): HTTPS (443), port 25/587 (email relay)
- VLAN 10 → VLAN 70 (Security Mgmt): HTTPS (443) for SIEM dashboard (read-only, monitored)
- VLAN 10 → VLAN 50 (DMZ): HTTPS (443) to vendor portal only

**Restricted Paths:**
- VLAN 10 → VLAN 30 (OT): **BLOCKED entirely**
- VLAN 10 → VLAN 20 (Engineering): Restricted; file server sync only via approved service account
- VLAN 10 → VLAN 40 (Warehouse): Read-only access to WMS dashboard (port 8443)

**Firewall Rules Summary:**
- Default DENY all outbound except HTTPS/HTTP to internet (via VLAN 60 proxy)
- Allow DNS to 10.10.10.5
- Allow LDAP/Kerberos intra-VLAN to DCs
- Block SMB (445) inter-VLAN

---

### 2.2 VLAN 20 — Engineering & Firmware

| Parameter | Value |
|---|---|
| **VLAN ID** | 20 |
| **Name** | Engineering & Firmware |
| **Subnet** | 10.10.20.0/24 |
| **Gateway** | 10.10.20.1 (FortiGate virtual interface) |
| **DNS Server** | 10.10.20.5 (secondary DNS, forwards to 10.10.10.5) |
| **DHCP Range** | 10.10.20.100 – 10.10.20.180 |
| **Static IP Block** | 10.10.20.1 – 10.10.20.99 |
| **Switch** | Cisco Catalyst 2960-X (R&D Wing) |

**Purpose:** Dedicated to hardware design engineers, firmware developers, and EDA/CAD workstations. Hosts the firmware CI/CD build server, Gerber file repositories, and the OTA staging server used to flash firmware to production units before shipment.

**Assigned Hosts (Static IPs):**

| IP | Hostname | Device | Role |
|---|---|---|---|
| 10.10.20.1 | FG-VLAN20-GW | FortiGate 100F vif | VLAN Gateway |
| 10.10.20.2 | ENG-BUILDSVR01 | Server | Firmware CI/CD Build Server (Jenkins) |
| 10.10.20.3 | ENG-GITSVR01 | Server | Local Git Mirror (GitHub Enterprise proxy cache) |
| 10.10.20.4 | ENG-OTA-STG01 | Server | OTA Firmware Staging Server |
| 10.10.20.5 | ENG-DNS01 | Server | Secondary DNS |
| 10.10.20.6 | ENG-NAS01 | Server | NAS – Gerber / BOM / Design Files |
| 10.10.20.10 | ENG-WS-001 | Workstation | Lead Hardware Engineer |
| 10.10.20.11 | ENG-WS-002 | Workstation | Firmware Developer 1 |
| 10.10.20.12 | ENG-WS-003 | Workstation | Firmware Developer 2 |
| 10.10.20.13 | ENG-WS-004 | Workstation | PCB Layout Designer |
| 10.10.20.14 | ENG-WS-005 | Workstation | Embedded Systems Engineer |
| 10.10.20.20 | ENG-TESTRIG-01 | Server | Hardware Test Rig (automated) |
| 10.10.20.21 | ENG-FLASHER-01 | Embedded | JTAG/USB Flash Station |

**Permitted Inter-VLAN Paths:**
- VLAN 20 → VLAN 60: HTTPS (443) to GitHub Enterprise, NPM/pip registries (allowlisted)
- VLAN 20 → VLAN 30: **Restricted** – OTA staging push to OT VLAN via dedicated service account, port 8883 (MQTT-TLS), time-boxed (production hours only)
- VLAN 20 → VLAN 70: HTTPS (443) for SIEM agent reporting

**Restricted Paths:**
- VLAN 20 → VLAN 10: No lateral access; email via VLAN 60 proxy only
- VLAN 20 → VLAN 50: No access (vendor contacts via VLAN 10 email)

**Firewall Rules Summary:**
- Outbound HTTPS to allowlisted developer resources
- Block USB-over-IP lateral movement paths
- Alert on any connection attempt to VLAN 30 not from ENG-OTA-STG01

---

### 2.3 VLAN 30 — Manufacturing OT

| Parameter | Value |
|---|---|
| **VLAN ID** | 30 |
| **Name** | Manufacturing OT |
| **Subnet** | 10.10.30.0/24 |
| **Gateway** | 10.10.30.1 (FortiGate virtual interface – strict policy) |
| **DNS Server** | 10.10.30.5 (isolated DNS, no internet forwarding) |
| **DHCP Range** | None (all static) |
| **Static IP Block** | 10.10.30.1 – 10.10.30.99 |
| **Switch** | Cisco IE-3300 Industrial Ethernet Switch |

**Purpose:** The most sensitive network segment. Hosts all Operational Technology (OT): PLCs controlling SMT lines, HMIs, AOI systems, pick-and-place machines, reflow ovens, test chambers, and the OT SCADA/MES gateway. **Strictly air-gapped from internet; inter-VLAN access is minimal and tightly controlled.**

**Assigned Hosts (Static IPs):**

| IP | Hostname | Device | Role |
|---|---|---|---|
| 10.10.30.1 | FG-VLAN30-GW | FortiGate 100F vif | VLAN Gateway (strict deny-all default) |
| 10.10.30.2 | OT-SCADA-GW01 | Server/Gateway | SCADA/MES Historian Gateway |
| 10.10.30.3 | OT-MES01 | Server | Manufacturing Execution System (MES) |
| 10.10.30.5 | OT-DNS01 | Server | Isolated OT DNS |
| 10.10.30.10 | OT-PLC-SMTA-01 | PLC | SMT Line A – PLC (Siemens S7-1200) |
| 10.10.30.11 | OT-PLC-SMTB-01 | PLC | SMT Line B – PLC (Siemens S7-1200) |
| 10.10.30.12 | OT-PLC-THT-01 | PLC | THT Assembly Line PLC |
| 10.10.30.13 | OT-PLC-IOT-01 | PLC | IoT Sensor Line PLC |
| 10.10.30.14 | OT-PLC-EMB-01 | PLC | Embedded Module Line PLC |
| 10.10.30.20 | OT-HMI-SMTA-01 | HMI | SMT Line A – Operator HMI (Weintek) |
| 10.10.30.21 | OT-HMI-SMTB-01 | HMI | SMT Line B – Operator HMI |
| 10.10.30.22 | OT-HMI-THT-01 | HMI | THT Line – Operator HMI |
| 10.10.30.30 | OT-AOI-SMTA-01 | Sensor/Machine | AOI Machine – SMT Line A |
| 10.10.30.31 | OT-AOI-SMTB-01 | Sensor/Machine | AOI Machine – SMT Line B |
| 10.10.30.40 | OT-ICT-01 | Sensor/Machine | ICT Test Chamber Controller |
| 10.10.30.41 | OT-BURNIN-01 | Sensor/Machine | Burn-in Test Rack Controller |
| 10.10.30.50 | OT-REFLOW-SMTA | Sensor | Reflow Oven – SMT Line A (temp sensor node) |
| 10.10.30.51 | OT-REFLOW-SMTB | Sensor | Reflow Oven – SMT Line B (temp sensor node) |
| 10.10.30.60 | OT-NIDS-PROBE01 | Sensor | VaultX Passive NIDS Probe – OT SPAN |

**Permitted Inter-VLAN Paths:**
- VLAN 30 → VLAN 70: Syslog (UDP 514), SNMP trap (UDP 162) to SIEM/NMS only (one-way push)
- VLAN 20 (OTA staging server only) → VLAN 30: MQTT-TLS (8883), time-boxed
- VLAN 70 → VLAN 30: ICMP ping only for liveness monitoring (passive probe)

**Restricted Paths:**
- VLAN 30 → Internet: **COMPLETELY BLOCKED**
- VLAN 30 → VLAN 10: **BLOCKED**
- VLAN 30 → VLAN 50: **BLOCKED** (vendor access to OT is physically on-site only)
- VLAN 30 → VLAN 40: **BLOCKED**

**Firewall Rules Summary:**
- Default DENY ALL (outbound and inbound)
- Explicit ALLOW: OT → VLAN 70 syslog/SNMP only
- Explicit ALLOW: ENG-OTA-STG01 → OT MQTT on schedule only
- Alert on ANY unexpected outbound connection

---

### 2.4 VLAN 40 — Warehouse & Logistics

| Parameter | Value |
|---|---|
| **VLAN ID** | 40 |
| **Name** | Warehouse & Logistics |
| **Subnet** | 10.10.40.0/24 |
| **Gateway** | 10.10.40.1 (FortiGate virtual interface) |
| **DNS Server** | 10.10.40.5 |
| **DHCP Range** | 10.10.40.100 – 10.10.40.180 |
| **Static IP Block** | 10.10.40.1 – 10.10.40.99 |
| **Switch** | Cisco Catalyst 2960-L (Warehouse) |

**Purpose:** Hosts warehouse management systems (WMS), barcode scanners, RFID readers, and logistics tracking terminals. Interfaces with DTDC/BlueDart tracking APIs via the cloud VLAN.

**Assigned Hosts (Static IPs):**

| IP | Hostname | Device | Role |
|---|---|---|---|
| 10.10.40.1 | FG-VLAN40-GW | FortiGate 100F vif | VLAN Gateway |
| 10.10.40.2 | WH-WMS-SVR01 | Server | Warehouse Management System Server |
| 10.10.40.5 | WH-DNS01 | Server | Local DNS |
| 10.10.40.10 | WH-SCAN-001 | Scanner | Barcode Scanner Terminal 1 |
| 10.10.40.11 | WH-SCAN-002 | Scanner | Barcode Scanner Terminal 2 |
| 10.10.40.12 | WH-SCAN-003 | Scanner | Barcode Scanner Terminal 3 |
| 10.10.40.20 | WH-RFID-GW01 | Gateway | RFID Reader Gateway (shelf tracking) |
| 10.10.40.21 | WH-RFID-GW02 | Gateway | RFID Reader Gateway (dispatch area) |
| 10.10.40.30 | WH-PC-001 | Workstation | Warehouse Supervisor PC |
| 10.10.40.31 | WH-PC-002 | Workstation | Logistics Coordinator PC |
| 10.10.40.40 | WH-PRINT-001 | Printer | Zebra Label Printer (shipping labels) |
| 10.10.40.50 | WH-NIDS-PROBE01 | Sensor | VaultX Passive NIDS Probe – WH SPAN |

**Permitted Inter-VLAN Paths:**
- VLAN 40 → VLAN 60: HTTPS (443) to DTDC/BlueDart API, Zoho CRM (allowlisted)
- VLAN 40 → VLAN 10: WMS dashboard read-only on 8443 (authenticated)
- VLAN 40 → VLAN 70: Syslog, SNMP trap

**Restricted Paths:**
- VLAN 40 → VLAN 30: **BLOCKED**
- VLAN 40 → VLAN 20: **BLOCKED**

---

### 2.5 VLAN 50 — DMZ & Vendor Access

| Parameter | Value |
|---|---|
| **VLAN ID** | 50 |
| **Name** | DMZ & Vendor Access |
| **Subnet** | 10.10.50.0/24 |
| **Gateway** | 10.10.50.1 (FortiGate virtual interface) |
| **DNS Server** | 10.10.50.5 |
| **DHCP Range** | 10.10.50.100 – 10.10.50.200 (dynamic, for vendor sessions) |
| **Static IP Block** | 10.10.50.1 – 10.10.50.99 |
| **Switch** | Cisco Catalyst 2960-X (DMZ port group) |

**Purpose:** Hosts the vendor remote-access gateway (Privileged Access Workstation/Bastion), vendor portal (self-service ticket & access request), and reverse proxy. All third-party remote access terminates here before proxied access to target systems.

**Assigned Hosts (Static IPs):**

| IP | Hostname | Device | Role |
|---|---|---|---|
| 10.10.50.1 | FG-VLAN50-GW | FortiGate 100F vif | VLAN Gateway |
| 10.10.50.2 | DMZ-BASTION01 | Server | Privileged Access Workstation / Bastion Host |
| 10.10.50.3 | DMZ-VEND-PORTAL | Server | Vendor Self-Service Portal (HTTPS) |
| 10.10.50.4 | DMZ-REVPROXY01 | Server | Nginx Reverse Proxy |
| 10.10.50.5 | DMZ-DNS01 | Server | DMZ DNS |
| 10.10.50.10 | DMZ-VPN-GW01 | Gateway | FortiClient VPN Concentrator (vendor VPN) |
| 10.10.50.20 | DMZ-WAF01 | Server | Web Application Firewall (FortiWeb) |

**Permitted Inter-VLAN Paths:**
- VLAN 50 (Bastion only) → VLAN 10: RDP (3389) for approved vendor IT sessions (MFA required)
- VLAN 50 (Bastion only) → VLAN 20: SSH (22) for firmware vendor sessions only
- Internet → VLAN 50: HTTPS (443) only to DMZ-VEND-PORTAL and DMZ-VPN-GW01

**Restricted Paths:**
- VLAN 50 → VLAN 30: **BLOCKED** (OT vendor access is on-site only)
- VLAN 50 → VLAN 40: **BLOCKED**
- VLAN 50 → VLAN 70: **BLOCKED**

---

### 2.6 VLAN 60 — Cloud & External Integrations

| Parameter | Value |
|---|---|
| **VLAN ID** | 60 |
| **Name** | Cloud & External Integrations |
| **Subnet** | 10.10.60.0/24 |
| **Gateway** | 10.10.60.1 (FortiGate virtual interface) |
| **DNS Server** | 10.10.60.5 |
| **DHCP Range** | 10.10.60.100 – 10.10.60.180 |
| **Static IP Block** | 10.10.60.1 – 10.10.60.99 |
| **Switch** | Dedicated cloud-uplink VLAN on core switch |

**Purpose:** Acts as the controlled egress/ingress point for all cloud and external SaaS integrations. Hosts the proxy server, email gateway, and AWS Direct Connect / VPN termination point. All internet-bound traffic from internal VLANs is routed through this segment's proxy.

**Assigned Hosts (Static IPs):**

| IP | Hostname | Device | Role |
|---|---|---|---|
| 10.10.60.1 | FG-VLAN60-GW | FortiGate 100F vif | VLAN Gateway |
| 10.10.60.2 | CLOUD-PROXY01 | Server | Squid Forward Proxy (SSL inspection) |
| 10.10.60.3 | CLOUD-MAILGW01 | Server | Email Security Gateway (Postfix + Rspamd) |
| 10.10.60.4 | CLOUD-AWSVPN01 | Gateway | AWS Site-to-Site VPN Termination |
| 10.10.60.5 | CLOUD-DNS01 | Server | Cloud-side DNS resolver |
| 10.10.60.10 | CLOUD-M365-GW | Server | Microsoft 365 Integration Proxy |
| 10.10.60.11 | CLOUD-ZOHOGW01 | Server | Zoho CRM API Integration Gateway |

**Permitted Inter-VLAN Paths:**
- All internal VLANs → VLAN 60 (Proxy only): HTTPS (443) for internet egress
- VLAN 60 → Internet: HTTPS to allowlisted cloud destinations (AWS, M365, GitHub, Zoho, DTDC APIs)
- VLAN 60 → VLAN 10: Return traffic for email, file sync

**Restricted Paths:**
- Direct internet access from any internal VLAN (bypassing proxy): **BLOCKED**
- VLAN 60 → VLAN 30: **BLOCKED**
- VLAN 60 → VLAN 70: **BLOCKED** (security management traffic uses OOB)

---

### 2.7 VLAN 70 — Security Management

| Parameter | Value |
|---|---|
| **VLAN ID** | 70 |
| **Name** | Security Management |
| **Subnet** | 10.10.70.0/24 |
| **Gateway** | 10.10.70.1 (FortiGate virtual interface) |
| **DNS Server** | 10.10.70.10 (authoritative for internal zone) |
| **DHCP Range** | None (all static) |
| **Static IP Block** | 10.10.70.1 – 10.10.70.99 |
| **Switch** | Dedicated OOB management VLAN on core switch |

**Purpose:** Out-of-band security management zone. Hosts the VaultX NIDS management console, SIEM (Wazuh/OpenSearch), NMS (Zabbix), threat intelligence feed aggregator, NTP master, and all NIDS probe management. Access restricted to IT admin accounts with MFA.

**Assigned Hosts (Static IPs):**

| IP | Hostname | Device | Role |
|---|---|---|---|
| 10.10.70.1 | FG-VLAN70-GW | FortiGate 100F vif | VLAN Gateway |
| 10.10.70.2 | SEC-SIEM01 | Server | Wazuh SIEM Manager + OpenSearch |
| 10.10.70.3 | SEC-NIDS-MGR01 | Server | VaultX NIDS Management Console |
| 10.10.70.4 | SEC-NMS01 | Server | Zabbix Network Monitoring Server |
| 10.10.70.5 | SEC-THREATINTEL01 | Server | Threat Intel Feed Aggregator (MISP) |
| 10.10.70.6 | SEC-LOGCOL01 | Server | Log Collector / Syslog Aggregator |
| 10.10.70.7 | SEC-VULN-SCAN01 | Server | Vulnerability Scanner (OpenVAS) |
| 10.10.70.10 | SEC-DNS-NTP01 | Server | Master DNS + NTP Server |
| 10.10.70.11 | SEC-JUMPHOST01 | Server | Admin Jump Host (MFA enforced) |
| 10.10.70.20 | SEC-PROBE-OT | Sensor | VaultX NIDS Probe (OT SPAN receiver mgmt) |
| 10.10.70.21 | SEC-PROBE-WH | Sensor | VaultX NIDS Probe (Warehouse SPAN receiver mgmt) |
| 10.10.70.22 | SEC-PROBE-CORP | Sensor | VaultX NIDS Probe (Corporate SPAN receiver mgmt) |
| 10.10.70.23 | SEC-PROBE-ENG | Sensor | VaultX NIDS Probe (Engineering SPAN receiver mgmt) |
| 10.10.70.30 | SEC-PKI-CA01 | Server | Internal PKI / Certificate Authority |

**Permitted Inter-VLAN Paths:**
- VLAN 70 → All VLANs: SNMP read (UDP 161), ICMP, Syslog receive (UDP 514) — monitoring only
- VLAN 70 → VLAN 30: SPAN/tap receive only (passive, no active sessions into OT)
- VLAN 10 (admin workstations, MFA) → VLAN 70: HTTPS (443), SSH (22) via jumphost

**Restricted Paths:**
- VLAN 70 → Internet: **BLOCKED** (threat intel updates via allowlisted proxy in VLAN 60 only)
- Any non-admin VLAN → VLAN 70: **BLOCKED**

---

## 3. Security Monitoring Points

| Monitoring Point | Location | Method | Coverage |
|---|---|---|---|
| **SP-01** | VLAN 10 ↔ Core Switch SPAN | Passive tap | Corporate IT east-west traffic |
| **SP-02** | VLAN 20 ↔ Core Switch SPAN | Passive tap | Engineering east-west + north-south |
| **SP-03** | VLAN 30 ↔ Industrial Switch SPAN | Passive tap | All OT traffic (Modbus, EtherNet/IP) |
| **SP-04** | VLAN 40 ↔ Warehouse Switch SPAN | Passive tap | Warehouse/WMS traffic |
| **SP-05** | WAN ingress/egress (FortiGate) | Active IPS | Internet-facing threat detection |
| **SP-06** | VLAN 50 DMZ | Active + passive | Vendor session monitoring |
| **SP-07** | VLAN 60 Cloud Proxy | Active (DPI) | Cloud egress inspection |
| **SP-08** | Core Switch trunk ports | Passive tap | Inter-VLAN routing visibility |

---

## 4. Remote Administration Paths

| Access Path | Allowed From | Method | Controls |
|---|---|---|---|
| Firewall admin | VLAN 70 jumphost only | HTTPS FortiGate GUI / SSH | MFA + certificate auth |
| Server RDP/SSH | VLAN 70 jumphost → target | RDP via jumphost | AD auth + MFA + session recording |
| OT equipment admin | On-site only (physical console) | Serial / VGA | Physical access log |
| NMS/SIEM access | VLAN 10 admin workstations | HTTPS to VLAN 70 (MFA) | RBAC within Wazuh/Zabbix |
| Cloud AWS console | VLAN 60 proxy + MFA | HTTPS | AWS IAM + hardware MFA |

---

## 5. Vendor Access Summary

| Vendor Type | Access Point | Allowed Segments | Method | Controls |
|---|---|---|---|---|
| OT Maintenance Vendor (Siemens partner) | On-site only | VLAN 30 (physical) | Local console | Escorted; session logged on-site |
| Firmware Dev Service | VLAN 50 bastion | VLAN 20 only | SSH via bastion | MFA + time-limited (4h max) |
| IT Infrastructure Vendor | VLAN 50 bastion | VLAN 10 only | RDP via bastion | MFA + session recording |
| Cloud Vendor (AWS support) | Via AWS Console | AWS only (no on-prem) | AWS IAM + STS | Conditional access; audit via CloudTrail |
| Logistics API (DTDC/BlueDart) | Internet → VLAN 60 proxy | API endpoint only | HTTPS + API key | Rate-limited; logged |

---

*Document prepared by: VaultX Infrastructure Architect*  
*Review cycle: Bi-annual or upon topology change*
