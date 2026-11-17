# Scenario 01: Compromised Third-Party Vendor Access (SCN-001)

---

## 1. Scenario Overview

| Attribute | Specification |
|:---|:---|
| **Scenario ID** | SCN-001 |
| **Scenario Name** | Compromised Third-Party Vendor Access |
| **Severity Level** | **High / Critical** |
| **Target Enterprise** | Bharat Electronics Components Pvt. Ltd. (BECPL), Pune |
| **Target Facility** | Bhosari MIDC Plant – SMT Assembly Line A/B |
| **Compromised Identity** | `techmaintain_ext_eng` (TechMaintain Solutions Pvt. Ltd.) |
| **Originating Infrastructure**| External VPN Gateway (`DMZ-VPN-GW01` / `10.10.50.10`) |
| **Target Assets** | Bastion Host (`DMZ-BASTION01` / `10.10.50.2`), MES Server (`OT-MES01` / `10.10.30.3`), SMT Line A PLC (`OT-PLC-SMTA-01` / `10.10.30.10`, legacy alias `172.20.30.12`) |
| **Simulation Duration** | 45 minutes |
| **Total Generated Events** | 24 labelled events |
| **OT Safety Criticality** | **High** (requires human supervisor review prior to OT network actions) |

---

## 2. Threat Actor Profile & Threat Model

### 2.1 Threat Actor & Objective
- **Adversary Profile:** Financially motivated cybercrime group or industrial competitor operating via initial access acquired on dark web forums.
- **Compromise Origin:** The external vendor **"TechMaintain Solutions Pvt. Ltd."** (an authorized contractor providing calibration, servicing, and firmware updates for SMT pick-and-place machinery and reflow ovens) suffered an infostealer malware infection on an engineer's laptop.
- **Adversary Objective:** Leverage valid vendor credentials to bypass perimeter controls, pivot through the DMZ jump host into the manufacturing execution tier, and stage backdoor persistence or manipulate PLC logic to sabotage production quality.

### 2.2 Attack Path
```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Adversary (Infostealer)
    participant VPN as DMZ-VPN-GW01 (10.10.50.10)
    participant Bastion as DMZ-BASTION01 (10.10.50.2)
    participant MES as OT-MES01 (10.10.30.3)
    participant PLC as OT-PLC-SMTA-01 (10.10.30.10)
    participant VaultX as VaultX Hybrid NIDS

    Attacker->>VPN: 1. Authenticate with valid creds (02:15 IST, Foreign ASN)
    VPN-->>Attacker: Session Established (Assigned 10.10.50.112)
    Attacker->>Bastion: 2. SSH into Bastion Jump Host
    Note over Bastion,VaultX: Observable: Geo/Time Auth Anomaly
    Attacker->>MES: 3. Cross-VLAN SSH pivot to MES Server (10.10.30.3)
    Note over MES,VaultX: Observable: Unauthorized cross-VLAN SSH flow
    Attacker->>MES: 4. SCP transfer of reconnaissance script (recon_modbus.py)
    Attacker->>PLC: 5. Direct TCP/502 (Modbus) SYN packets & Read Holding Registers
    Note over PLC,VaultX: Violation: Non-whitelisted Modbus source to SMT PLC
    VaultX-->>VaultX: Correlation: Auth Anomaly + Lateral Jump + OT Violation
    VaultX->>VPN: Auto-Response: Terminate VPN tunnel & Revoke token
    Note over VaultX,PLC: OT Safety Lock: PLC port NOT killed; Human alert issued
```

---

## 3. Timeline & Event Breakdown (45-Minute Window)

| Timestamp (T+) | Event ID | Source IP:Port | Destination IP:Port | Protocol / Action | Classification | Description / Observables |
|:---|:---|:---|:---|:---|:---:|:---|
| T+00:00 | EVT-01-01 | 185.220.101.45:49152 | 103.25.68.2:443 | HTTPS / TLS | Malicious | FortiClient SSL-VPN authentication attempt for user `techmaintain_ext_eng`. |
| T+00:02 | EVT-01-02 | 10.10.50.10:443 | 10.10.70.2:514 | Syslog (Auth) | Malicious | VPN auth SUCCESS. Anomaly: Login at 02:15 AM IST (vendor window is 09:00–18:00 IST) from ASN 208323 (Tor Exit / Hosting provider in Europe). Dynamic IP `10.10.50.112` leased. |
| T+02:10 | EVT-01-03 | 10.10.50.112:51224 | 10.10.50.2:22 | SSH (TCP 22) | Malicious | Bastion login attempt via SSH with public key + password. |
| T+02:15 | EVT-01-04 | 10.10.50.2:22 | 10.10.70.2:514 | Syslog (Auth) | Malicious | SSH auth success for `techmaintain_ext_eng` on `DMZ-BASTION01`. |
| T+05:00 | EVT-01-05 | 10.10.50.2:49812 | 10.10.10.5:53 | DNS (UDP 53) | Benign | Internal DNS query for `ot-mes01.becpl.internal`. |
| T+08:20 | EVT-01-06 | 10.10.50.2:53412 | 10.10.30.3:22 | SSH (TCP 22) | Malicious | Direct SSH connection from DMZ Bastion to Manufacturing Execution System (`OT-MES01` / `10.10.30.3`). Violates policy (bastion is restricted from OT subnet). |
| T+08:22 | EVT-01-07 | 10.10.30.3:22 | 10.10.70.2:514 | Syslog (Auth) | Malicious | SSH authentication accepted on `OT-MES01` using cached credentials. |
| T+11:00 | EVT-01-08 | 10.10.30.3:44120 | 10.10.50.2:22 | SCP / SSH | Malicious | Lateral tool transfer: `recon_modbus.py` uploaded to `/tmp/` on MES server. |
| T+15:30 | EVT-01-09 | 10.10.30.3:38901 | 10.10.30.1:icmp | ICMP Echo | Malicious | Ping sweep across OT subnet `10.10.30.0/24`. |
| T+15:31 | EVT-01-10 | 10.10.30.3:38902 | 10.10.30.10:icmp | ICMP Echo | Malicious | Ping response from SMT Line A PLC (`OT-PLC-SMTA-01`). |
| T+15:32 | EVT-01-11 | 10.10.30.3:38903 | 10.10.30.11:icmp | ICMP Echo | Malicious | Ping response from SMT Line B PLC (`OT-PLC-SMTB-01`). |
| T+20:10 | EVT-01-12 | 10.10.30.3:48102 | 10.10.30.10:502 | Modbus/TCP | Malicious | TCP SYN to Modbus port 502 on SMT Line A PLC. |
| T+20:11 | EVT-01-13 | 10.10.30.10:502 | 10.10.30.3:48102 | Modbus/TCP | Malicious | TCP SYN-ACK from PLC (connection established). |
| T+20:12 | EVT-01-14 | 10.10.30.3:48102 | 10.10.30.10:502 | Modbus/TCP | Malicious | Modbus FC3 (Read Holding Registers, Unit ID 1, Addr 40001, Len 10). |
| T+20:13 | EVT-01-15 | 10.10.30.10:502 | 10.10.30.3:48102 | Modbus/TCP | Malicious | Modbus FC3 response with register values (conveyor velocity, nozzle temperature). |
| T+25:00 | EVT-01-16 | 10.10.30.20:51000 | 10.10.30.10:502 | Modbus/TCP | Benign | Legitimate HMI operator polling cycle (`OT-HMI-SMTA-01`). |
| T+28:00 | EVT-01-17 | 10.10.30.3:48110 | 10.10.30.10:502 | Modbus/TCP | Malicious | Modbus FC16 (Write Multiple Registers) attempt targeting motor control registers. |
| T+30:00 | EVT-01-18 | 10.10.70.3 | 10.10.50.10:8443 | FortiOS REST | Mitigation | VaultX automated containment: Terminate SSL-VPN session for `techmaintain_ext_eng`. |
| T+30:01 | EVT-01-19 | 10.10.70.3 | 10.10.10.2:636 | LDAPS | Mitigation | VaultX automated containment: Disable AD account `techmaintain_ext_eng`. |
| T+30:05 | EVT-01-20 | 10.10.70.3 | 10.10.70.2 | Alert | Detection | Correlated High-Severity Security Incident raised: SCN-001 detected. |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Applied Context in BECPL |
|:---|:---|:---|:---|
| **Initial Access** | `T1078.002` | Valid Accounts: Domain Accounts | Stolen credentials of third-party vendor user `techmaintain_ext_eng` used at VPN gateway. |
| **Initial Access** | `T1133` | External Remote Services | FortiClient SSL-VPN portal utilized as entry point into DMZ network. |
| **Lateral Movement** | `T1021.004` | Remote Services: SSH | SSH session initiated from DMZ Bastion across VLAN boundary to `OT-MES01`. |
| **Lateral Movement** | `T1570` | Lateral Tool Transfer | Upload of Python Modbus scanner (`recon_modbus.py`) from Bastion to MES server. |
| **Discovery** | `T1018` | Remote System Discovery | ICMP ping sweep from MES server discovering industrial PLCs on `10.10.30.0/24`. |
| **Discovery** | `T1046` | Network Service Discovery | Port probe against TCP port 502 across PLC subnet. |
| **Inhibit Response / Impair Process** | `T0836` | Modify Parameter (ICS) | Attempted Modbus FC16 write commands targeting PLC conveyor speed registers. |

---

## 5. Detection Hypothesis & Rules

### 5.1 Primary Hypothesis
An adversary using valid vendor credentials will inevitably trigger multi-domain anomalies across:
1. **Identity & Authentication:** Anomaly score high due to atypical login timestamp (outside 09:00–18:00 IST), foreign geolocation / ASN, and absence of prior approved change ticket.
2. **Network Flow & Routing:** A connection initiating from VLAN 50 (DMZ) directly terminating on VLAN 30 (OT) violates firewall rule `FW-053` (DMZ to OT Block).
3. **Protocol & Semantics:** Modbus/TCP traffic originating from any IP other than designated HMIs (`10.10.30.20-22`) or SCADA Gateway (`10.10.30.2`) represents an immediate malicious event.

### 5.2 Zeek Correlation Logic
```zeek
# Pseudo-Zeek signature for SCN-001
event modbus_message(c: connection, headers: ModbusHeaders) {
    if ( c$id$orig_h !in ot_authorized_controllers && c$id$resp_p == 502/tcp ) {
        NOTICE([$note=OT::UnauthorizedModbusSource,
                $msg=fmt("Unauthorized Modbus client %s attempting control of PLC %s", c$id$orig_h, c$id$resp_h),
                $conn=c,
                $sub=fmt("VendorPivotScenario: %s", c$id$orig_h)]);
    }
}
```

---

## 6. Containment, Response & OT Safety Protocol

### 6.1 Automated Containment Actions (IT / DMZ Tier)
- **Step 1:** Issue immediate API call to FortiGate NGFW (`10.10.50.10` / `10.10.70.1`) to revoke the active SSL-VPN session ID.
- **Step 2:** Send LDAP request to Active Directory (`10.10.10.2`) disabling `techmaintain_ext_eng` account.
- **Step 3:** Drop existing TCP states originating from `10.10.50.112` at the core Catalyst 9300 switch.

### 6.2 OT Safety Criticality Exception (MANDATORY HUMAN APPROVAL)
> [!CAUTION]
> **SAFETY HAZARD IN SMT PRODUCTION LINE:**
> If the vendor is actively engaged in scheduled calibration of SMT Line A's pick-and-place nozzle or reflow oven heaters, executing an automated switch-port shutdown or TCP reset to `OT-PLC-SMTA-01` (`10.10.30.10`) may cause:
> 1. Uncontrolled thermal run-off in the 10-zone reflow oven.
> 2. Mechanical collision of the high-speed high-precision mounter head.
> 3. Production scrap costing upwards of ₹8,00,000 per incident.
>
> **Enforced VaultX Policy:**
> - VaultX will **NEVER** issue an automated port disable or TCP reset targeting OT VLAN assets (`10.10.30.0/24`).
> - The containment action on the OT tier requires **Two-Man Rule (Four-Eyes Principle)** verification:
>   - Shift In-Charge (Manufacturing): Confirms line status is mechanically safe to isolate.
>   - Security Lead: Confirms malicious adversary presence and approves physical patch disconnection.
