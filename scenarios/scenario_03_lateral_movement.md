# Scenario 03: Suspicious Lateral Movement (SCN-003)

---

## 1. Scenario Overview

| Attribute | Specification |
|:---|:---|
| **Scenario ID** | SCN-003 |
| **Scenario Name** | Suspicious Multi-VLAN Lateral Movement & Port Fan-Out |
| **Severity Level** | **High** |
| **Target Enterprise** | Bharat Electronics Components Pvt. Ltd. (BECPL), Pune |
| **Compromised Host** | `CORP-WS-002` (IP: `10.10.10.21` / SysAdmin Workstation) |
| **Target Hosts** | `BECPL-FS01` (`10.10.10.4`), `BECPL-DC01` (`10.10.10.2`), `ENG-WS-001` (`10.10.20.10`), `ENG-BUILDSVR01` (`10.10.20.2`), `WH-WMS-SVR01` (`10.10.40.2`), `OT-MES01` (`10.10.30.3`) |
| **Affected VLANs** | VLAN 10 (Corp IT), VLAN 20 (Engineering), VLAN 30 (OT), VLAN 40 (Warehouse) |
| **Simulation Duration** | 8 minutes |
| **Total Connections** | 23 network connections across 6 distinct hosts in 3 VLANs |
| **OT Safety Criticality** | **High if targeting OT VLAN; automated containment allowed on IT switchports** |

---

## 2. Threat Context & Attack Vector

An employee workstation in the Corporate IT zone (`CORP-WS-002`) has been compromised via an initial phishing email payload executing an interactive command-and-control agent (Cobalt Strike / Sliver).

Having established execution privileges under the compromised sysadmin account `becpl\pune_admin02`, the adversary initiates automated lateral movement seeking:
1. **Network share reconnaissance** over SMB (port 445).
2. **Interactive desktop hijacking** over RDP (port 3389) across peer workstations and servers.
3. **Cross-boundary pivoting** over SSH (port 22) into Linux-based engineering servers and manufacturing gateways.

```
                  ┌──────────────────────┐
                  │ CORP-WS-002 (Victim) │
                  │     10.10.10.21      │
                  └──────────┬───────────┘
                             │
     ┌───────────────────────┼────────────────────────┐
     ▼ (VLAN 10: SMB/RDP)    ▼ (VLAN 20: SSH/RDP)     ▼ (VLAN 30: Policy Violation)
┌──────────────┐        ┌──────────────┐         ┌──────────────┐
│ BECPL-FS01   │        │ ENG-WS-001   │         │ OT-MES01     │
│ 10.10.10.4   │        │ 10.10.20.10  │         │ 10.10.30.3   │
└──────────────┘        └──────────────┘         └──────────────┘
```

---

## 3. High-Density Attack Timeline (8-Minute Window)

| Relative Time | Event ID | Source Entity | Destination Entity | Protocol / Port | Observation & Status | Classification |
|:---:|:---|:---|:---|:---:|:---|:---:|
| 00:15 | EVT-03-01 | 10.10.10.21:49210 | 10.10.10.4:445 | SMB (TCP 445) | IPC$ connect, Tree Connect to `\\BECPL-FS01\Confidential`. Successful auth. | Malicious |
| 00:45 | EVT-03-02 | 10.10.10.21:49212 | 10.10.10.2:445 | SMB (TCP 445) | Attempted SAMR query on Domain Controller. | Malicious |
| 01:20 | EVT-03-03 | 10.10.10.21:49301 | 10.10.10.30:3389 | RDP (TCP 3389) | SYN scan and connection attempt to Finance PC. STATUS_LOGON_FAILURE. | Malicious |
| 01:50 | EVT-03-04 | 10.10.10.21:49302 | 10.10.10.31:3389 | RDP (TCP 3389) | Connection attempt to HR PC. STATUS_LOGON_FAILURE. | Malicious |
| 02:15 | EVT-03-05 | 10.10.10.21:49303 | 10.10.10.32:3389 | RDP (TCP 3389) | Connection attempt to Procurement PC. Connection timeout. | Malicious |
| 02:40 | EVT-03-06 | 10.10.10.21:49304 | 10.10.10.33:3389 | RDP (TCP 3389) | Connection attempt to Sales PC. STATUS_LOGON_FAILURE. | Malicious |
| 03:10 | EVT-03-07 | 10.10.10.21:49305 | 10.10.10.10:3389 | RDP (TCP 3389) | Connection attempt to IT Jump Server. Auth failed (MFA challenge rejected). | Malicious |
| 03:45 | EVT-03-08 | 10.10.10.21:51101 | 10.10.20.10:22 | SSH (TCP 22) | **Cross-VLAN:** SSH banner exchange with Lead Eng Workstation. Auth rejected. | Malicious |
| 04:10 | EVT-03-09 | 10.10.10.21:51102 | 10.10.20.2:22 | SSH (TCP 22) | **Cross-VLAN:** SSH connection to CI/CD Build Server. Auth rejected. | Malicious |
| 04:35 | EVT-03-10 | 10.10.10.21:51103 | 10.10.20.6:445 | SMB (TCP 445) | **Cross-VLAN:** Attempted access to Engineering NAS (Gerber files). | Malicious |
| 05:00 | EVT-03-11 | 10.10.10.21:52001 | 10.10.40.2:8443 | HTTPS (8443) | **Cross-VLAN:** Attempted access to Warehouse WMS server. | Malicious |
| 05:40 | EVT-03-12 | 10.10.10.21:53001 | 10.10.30.3:22 | SSH (TCP 22) | **Cross-VLAN (CRITICAL VIOLATION):** Attempted SSH into Manufacturing MES. | Malicious |
| 05:41 | EVT-03-13 | 10.10.10.1 | 10.10.70.2 | Syslog (FW) | FortiGate DROP: FW-010-030 Block IT to OT traffic. | Alert |
| 06:15 | EVT-03-14 | 10.10.10.21:49401 | 10.10.10.22:3389 | RDP (TCP 3389) | RDP connection to Sysadmin 2 Workstation. | Malicious |
| 07:00 | EVT-03-15 | 10.10.70.3 | 10.10.10.21 | 802.1X Revoke | VaultX Automated Response: Port security quarantine on switch `Cisco Catalyst 2960X-A Port Gi1/0/21`. | Mitigation |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Technical Description |
|:---|:---|:---|:---|
| **Discovery** | `T1018` | Remote System Discovery | Automated scanning of subnet ranges across VLAN 10 and VLAN 20. |
| **Discovery** | `T1046` | Network Service Discovery | Port probing against ports 22, 445, 3389, and 8443. |
| **Lateral Movement** | `T1021.001` | Remote Services: Remote Desktop Protocol | Rapid sequential RDP connection attempts to Windows endpoints. |
| **Lateral Movement** | `T1021.002` | Remote Services: SMB/Windows Admin Shares | SMB connection attempts to file servers and engineering NAS. |
| **Lateral Movement** | `T1021.004` | Remote Services: SSH | Cross-segment SSH attempts targeting Linux build servers. |
| **Credential Access** | `T1110.001` | Brute Force: Password Guessing | Repeated logon failures across multiple workstation targets. |

---

## 5. Detection Observables & Statistical Signals

### 5.1 Zeek `conn.log` Behavioral Indicators
- **High Outbound Connection Degree (Fan-Out):** Source IP `10.10.10.21` initiates connections to 6 distinct subnets/hosts within 8 minutes. (Standard office workstation baseline: fan-out $\le$ 3 distinct internal targets).
- **Service Asymmetry:** High ratio of SYN packets sent without successful handshake completion (`history` string in Zeek: `S`, `Sr`, or `S_R`).
- **Protocol Churn:** Rapid switching between SMB (445), RDP (3389), and SSH (22).

### 5.2 Windows Security Log Correlation
- Multiple instances of Event ID 4625 (`An account failed to log on`) across different destination computers with status code `0xC000006A` (wrong password) or `0xC0000234` (account locked).

---

## 6. Response Playbook & Containment

1. **IT Zone Isolation (Automated):**
   - Signal Cisco Catalyst 2960X via SNMP/CLI to disable switchport `Gi1/0/21`.
   - Update FortiGate firewall dynamically to inject temporary null-route for `10.10.10.21`.
2. **Credential Invalidation:**
   - Force password reset on `becpl\pune_admin02` in Active Directory (`10.10.10.2`).
3. **Forensic Acquisition:**
   - Trigger memory and triage artifact dump from `CORP-WS-002` to secure forensic share on VLAN 70.
