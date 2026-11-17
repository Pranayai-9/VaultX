# Scenario 06: Manufacturing OT Network Anomaly (SCN-006)

---

## 1. Scenario Overview

| Attribute | Specification |
|:---|:---|
| **Scenario ID** | SCN-006 |
| **Scenario Name** | Manufacturing OT Network Anomaly & Industrial Parameter Manipulation |
| **Severity Level** | **Critical (Life-Safety & Production Integrity Threat)** |
| **Target Enterprise** | Bharat Electronics Components Pvt. Ltd. (BECPL), Pune |
| **Target Facility** | SMT Assembly Line A – Main Floor (`VLAN 30`) |
| **Target Asset** | SMT Line A PLC (`OT-PLC-SMTA-01` / `10.10.30.10`, legacy alias `172.20.30.10`) |
| **Legitimate Controller** | SMT Line A Operator HMI (`OT-HMI-SMTA-01` / `10.10.30.20`, alias `172.20.30.11`) |
| **Rogue / Unauthorized Source**| Engineering Station (`ENG-WS-005` / `10.10.20.30` or `172.20.20.30`) & Unknown IP (`10.10.30.95`) |
| **Protocol Attacked** | Modbus/TCP (Port 502) |
| **Registers Manipulated** | Register `40003` (SMT Conveyor Speed / Motor Drive RPM) |
| **Simulation Duration** | 25 minutes |
| **Total Events** | 28 labelled events |
| **OT Safety Criticality** | **EXTREME: AUTOMATED ISOLATION STRICTLY PROHIBITED** |

---

## 2. Industrial Process Context & Baseline

### 2.1 Physical Manufacturing Process (SMT Line A)
BECPL manufactures multi-layer IoT sensor circuit boards. The SMT Line A involves:
1. **Solder Paste Printer:** Applies solder paste with sub-millimeter precision.
2. **High-Speed Pick-and-Place Machine:** Mounts up to 40,000 components per hour.
3. **Reflow Soldering Oven:** 10-zone thermal profile peaking at 245°C.

The conveyor speed connecting the solder paste printer, pick-and-place head, and reflow oven is regulated by Siemens S7-1200 PLC holding register `40003`. 
- **Nominal conveyor speed setpoint:** `120 cm/min` (represented as integer value `1200` in register `40003`).
- **Critical Failure Limits:**
  - Speed $> 150 \text{ cm/min}$: Misalignment in pick-and-place, tombstoning of passives, PCB jamming inside reflow oven.
  - Speed $< 80 \text{ cm/min}$: Excessive thermal exposure in reflow oven leading to PCB delamination, component burn-out, or fire hazard.

### 2.2 Normal Telemetry Baseline
- **Approved Communication Pair:** HMI (`10.10.30.20`) $\longleftrightarrow$ PLC (`10.10.30.10`).
- **Function Code:** Exclusively **Modbus FC3 (Read Holding Registers)**.
- **Polling Interval:** Exactly every 10 seconds.
- **Register Range Polled:** Addresses `40001` through `40005` (5 registers: Status, Line Health, Conveyor Speed, Zone 1 Temp, Zone 2 Temp).
- **Write Operations:** Manual setpoint modifications require an on-screen confirmation at the physical HMI console; writes over network are never initiated from VLAN 20 or external zones.

---

## 3. Attack Progression Flow

```
[Normal Operation]
OT-HMI-SMTA-01 (10.10.30.20) ─── Modbus FC3 (Read 40001-40005) ───► OT-PLC-SMTA-01 (10.10.30.10)
                                    [Every 10 seconds]

[Anomaly 1: Unauthorized Cross-VLAN Write]
ENG-WS-005 (10.10.20.30) ───────── Modbus FC6 (Write Single Reg) ─► OT-PLC-SMTA-01 (10.10.30.10)
                                    [Register 40003 = 2800 (280 cm/min)]
                                    VIOLATION: Unapproved Source + Write Operation

[Anomaly 2: Industrial Reconnaissance / Probe]
Unknown Node (10.10.30.95) ─────── Modbus FC8 (Diagnostics) ─────► OT-PLC-SMTA-01 (10.10.30.10)
                                    VIOLATION: Sub-function 00 (Echo) & Sub-function 04 (Force Listen)
```

---

## 4. Telemetry Timeline & Labelled Event Sequence

| Relative Time | Event ID | Source Entity | Target Entity | Protocol & Command | Label | Observation & Semantic Detail |
|:---:|:---|:---|:---|:---:|:---:|:---|
| 00:00 | EVT-06-01 | 10.10.30.20:50201 | 10.10.30.10:502 | Modbus FC3 | Benign | Read Reg 40001–40005. Response: [1, 0, 1200, 1850, 2450]. Status OK. |
| 00:10 | EVT-06-02 | 10.10.30.20:50201 | 10.10.30.10:502 | Modbus FC3 | Benign | Read Reg 40001–40005. Response: [1, 0, 1200, 1852, 2451]. Status OK. |
| 00:20 | EVT-06-03 | 10.10.30.20:50201 | 10.10.30.10:502 | Modbus FC3 | Benign | Read Reg 40001–40005. Standard polling cycle. |
| 04:15 | EVT-06-04 | 10.10.20.30:48910 | 10.10.30.10:502 | TCP SYN | Malicious | Unauthorized cross-VLAN TCP handshake initiated from Engineering to PLC. |
| 04:16 | EVT-06-05 | 10.10.30.10:502 | 10.10.20.30:48910 | TCP SYN-ACK | Malicious | Handshake completed. |
| 04:17 | EVT-06-06 | 10.10.20.30:48910 | 10.10.30.10:502 | Modbus FC6 | Malicious | **MALICIOUS WRITE:** Write Single Register `40003` with value `2800` (Conveyor speed accelerated to 280 cm/min). |
| 04:18 | EVT-06-07 | 10.10.30.10:502 | 10.10.20.30:48910 | Modbus FC6 Resp | Malicious | PLC acknowledges write: Register `40003` updated to `2800`. SMT conveyor accelerates abnormally. |
| 04:20 | EVT-06-08 | 10.10.30.20:50201 | 10.10.30.10:502 | Modbus FC3 | Benign | HMI read cycle. Register `40003` returns `2800`. HMI operator alert: High conveyor speed deviation. |
| 08:30 | EVT-06-09 | 10.10.30.95:51240 | 10.10.30.10:502 | Modbus FC8 | Malicious | **ANOMALOUS PROBE:** Unknown host `10.10.30.95` issues Modbus FC8 Diagnostics (Sub-function 0x0004 - Force Listen Only Mode). |
| 08:31 | EVT-06-10 | 10.10.30.10:502 | 10.10.30.95:51240 | Modbus FC8 Resp | Malicious | PLC accepts diagnostic command. Risk of communication freeze. |
| 08:45 | EVT-06-11 | VaultX-Engine | Security-Console | Correlated Alert | Detection | **CRITICAL INDUSTRIAL ALERT (ID: OT-ANOMALY-006):** Unauthorized Modbus FC6 write and FC8 probe detected. |
| 08:46 | EVT-06-12 | VaultX-Engine | Safety-Controller | Safety Interlock | Interlock | **SAFETY INTERLOCK ENGAGED:** Automated network isolation blocked. Human intervention alert dispatched to Plant In-Charge & OT Lead. |

---

## 5. MITRE ATT&CK for ICS Mapping

| Tactic | Technique ID | Technique Name | Industrial Physical Context |
|:---|:---|:---|:---|
| **Impair Process Control** | `T0836` | Modify Parameter | Changing conveyor drive speed setpoint (`40003`) beyond mechanical tolerance. |
| **Impair Process Control** | `T1565.002` | Transmitted Data Manipulation | Injecting unauthorized Modbus Write Single Register (FC6) frames across the network. |
| **Inhibit Response Function**| `T0855` | Unauthorized Command Message | Sending Modbus FC8 Force Listen Only mode to suppress PLC telemetry back to HMI. |
| **Discovery** | `T0846` | Remote System Discovery | Probing industrial subnets for active Modbus listening devices on port 502. |

---

## 6. OT Life-Safety Considerations & Containment Policy

### 6.1 The Safety Dilemma
In an IT context, isolating a compromised endpoint via `shutdown port` is the default best practice. In manufacturing OT:
- If VaultX automatically drops the network port of `OT-PLC-SMTA-01`, the PLC loses its emergency stop (E-STOP) network coordination and HMI monitoring.
- If the conveyor is running at high speed (`2800`), cutting its network could cause a catastrophic mechanical crash in the SMT pick-and-place gantry, spraying surface-mount components, destroying expensive titanium nozzles, and creating potential physical injury to nearby plant floor technicians.

### 6.2 Mandatory Human Authorization Workflow
VaultX implements the following hard-coded safety policy:

```python
def execute_containment(alert: Alert) -> ContainmentStatus:
    if alert.target_asset.network_segment == "VLAN_30_OT" or alert.target_asset.device_type == "plc":
        # SAFETY INHIBIT: Automated port isolation prohibited
        logger.warning("SAFETY LOCK: Automated containment blocked for OT asset %s", alert.target_asset.asset_id)
        dispatch_high_priority_pager(
            role="PLANT_SAFETY_OFFICER",
            message=f"OT Setpoint Tampering on {alert.target_asset.asset_id}. Manual verification required!"
        )
        return ContainmentStatus.PENDING_HUMAN_APPROVAL
    else:
        # IT Zone: Proceed with automated port isolation
        isolate_switch_port(alert.target_asset.switch_port)
        return ContainmentStatus.ISOLATED
```

### 6.3 Plant Operator Action Steps
1. Floor supervisor visually verifies SMT Line A conveyor status and engages physical mechanical emergency stop on the machine panel if physical damage is imminent.
2. OT engineer manually reverts register `40003` via the local, physically connected engineering programming console.
3. Security administrator isolates the rogue source `10.10.20.30` at the engineering switch level, completely away from the manufacturing floor.
