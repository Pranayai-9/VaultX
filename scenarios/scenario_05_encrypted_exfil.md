# Scenario 05: Encrypted External Exfiltration (SCN-005)

---

## 1. Scenario Overview

| Attribute | Specification |
|:---|:---|
| **Scenario ID** | SCN-005 |
| **Scenario Name** | Encrypted External Exfiltration (Design IP Theft) |
| **Severity Level** | **Critical** |
| **Target Enterprise** | Bharat Electronics Components Pvt. Ltd. (BECPL), Pune |
| **Source Asset** | `ENG-WS-001` (`10.10.20.10` / Lead Hardware Engineer Workstation) |
| **Stolen Assets** | Multilayer PCB Gerber files, Bill of Materials (BOM), Automotive MCU source code |
| **Destination** | Rogue External VPS: `185.196.8.121:443` (SNI: `cdn-telemetry-cache.com`) |
| **Simulation Duration** | 4.5 hours (sustained low-and-slow flow) |
| **Encrypted Flow Volume** | ~485 Megabytes outbound |
| **Detection Constraint** | **Zero Payload Decryption** (Flow metadata, TLS handshake, and JA3/JA3S fingerprinting only) |
| **OT Safety Criticality** | **Low** (R&D Engineering network, no production PLC impact) |

---

## 2. Threat Actor Context & Modus Operandi

State-sponsored industrial espionage groups (or competitors seeking to replicate BECPL's defense-grade embedded sensor designs) target the Engineering & Firmware VLAN (`VLAN 20`). Once an implant or insider gains access to `ENG-WS-001`, the adversary compresses proprietary CAD/Gerber designs and initiates an encrypted exfiltration channel over standard HTTPS (TCP 443).

Because BECPL cannot decrypt all developer TLS sessions due to certificate pinning in engineering toolchains (Altium 365, Git, KiCad plugins), the NIDS must identify exfiltration **purely from network flow telemetry and TLS handshake metadata**.

```
    [ENG-WS-001: 10.10.20.10]
 (Gerber Files & Schematic ZIP)
               │
               ▼  TLS 1.3 Handshake (Port 443)
  Client Hello [JA3: 72a589da586844d7f0818ce684948eea]
  SNI: cdn-telemetry-cache.com
  Cert: Self-Signed / Let's Encrypt (Issued < 48 hrs)
               │
               ▼  Long-Lived Flow (4.5 hrs, 485 MB out / 2.1 MB in)
   [Perimeter FortiGate / Zeek]
               │
               ▼
  [VaultX Flow & TLS Anomaly Classifier]
               │
               ▼
 [Alert: High-Confidence Exfiltration]
```

---

## 3. Legitimate Baseline vs. Exfiltration Flow Metadata

| Telemetry Feature | Legitimate Baseline (GitHub / AWS / Altium) | Malicious Exfiltration Channel | Anomaly Signal |
|:---|:---|:---|:---:|
| **Destination IP / ASN** | AS13335 (Cloudflare), AS16509 (Amazon), AS36459 (GitHub) | AS202425 (Bulletproof hosting provider in Seychelles) | **Extreme ASN Risk** |
| **SNI (Server Name Indication)**| `github.com`, `api.altium.com`, `aws.amazon.com` | `cdn-telemetry-cache.com` (Registered 3 days ago) | **Domain Age Anomaly** |
| **TLS Certificate Issuer**| DigiCert, Amazon Trust Services, Let's Encrypt Authority E1 | Self-signed / Newly generated DV certificate | **Certificate Entropy** |
| **JA3 Client Fingerprint**| Standard Chrome / Go-Git / Windows Edge fingerprints | Custom Python `requests` or Golang embedded TLS client | **Rare JA3 in VLAN 20** |
| **Flow Duration** | 2 seconds to 300 seconds (bursty API calls) | 16,200 seconds (4.5 hours continuous stream) | **Duration Outlier** |
| **Byte Asymmetry (Out / In)**| Ratio $\approx 1:5$ to $1:20$ (Downloading libraries/assets) | Ratio $\approx 230:1$ (485 MB uploaded, 2.1 MB downloaded) | **Severe Byte Inversion** |
| **Packet Inter-Arrival Time**| Variable Poisson distribution | Highly regular chunking (16 KB chunks every 500 ms) | **Exfiltration Shaping** |

---

## 4. Timeline of Telemetry & Network Observables

| Relative Time | Channel / Log | Source Entity | Destination Entity | Observable Details | Classification |
|:---:|:---|:---|:---|:---|:---:|
| 00:00 | Zeek `ssl.log` | 10.10.20.10:52110 | 140.82.121.4:443 | SNI: `github.com`. Normal developer git pull. | Benign |
| 00:15 | Zeek `ssl.log` | 10.10.20.10:53402 | 185.196.8.121:443 | Client Hello initiated. SNI: `cdn-telemetry-cache.com`. JA3: `72a589da586844d7f0818ce684948eea`. | Malicious |
| 00:16 | Zeek `x509.log` | 185.196.8.121:443 | 10.10.20.10:53402 | Certificate Subject: `CN=cdn-telemetry-cache.com`. Validity: 90 days. Not in corporate trusted roots. | Malicious |
| 00:30 | Zeek `conn.log` | 10.10.20.10:53402 | 185.196.8.121:443 | Flow running: 900s. Orig_bytes: 45MB. Resp_bytes: 210KB. | Malicious |
| 01:30 | Zeek `conn.log` | 10.10.20.10:53402 | 185.196.8.121:443 | Flow running: 4500s. Orig_bytes: 180MB. Resp_bytes: 840KB. | Malicious |
| 03:00 | Zeek `conn.log` | 10.10.20.10:53402 | 185.196.8.121:443 | Flow running: 9900s. Orig_bytes: 340MB. Resp_bytes: 1.5MB. | Malicious |
| 04:30 | Zeek `conn.log` | 10.10.20.10:53402 | 185.196.8.121:443 | Flow completed: 16200s. Orig_bytes: 485.4MB. Resp_bytes: 2.1MB. Connection state: `SF`. | Malicious |
| 04:31 | VaultX ML Engine | Flow Analytics | Autoencoder anomaly score: 0.962 (Threshold: 0.700). High-confidence exfiltration alert. | Alert |

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Technical Description |
|:---|:---|:---|:---|
| **Exfiltration** | `T1041` | Exfiltration Over C2 Channel | Proprietary engineering IP transmitted over established TLS session. |
| **Command and Control** | `T1573.001` | Encrypted Channel: Symmetric Cryptography | TLS 1.3 session used to encapsulate exfiltration data and prevent inspection. |
| **Command and Control** | `T1008` | Fallback Channels | Utilizing unmonitored direct outbound port 443 path. |
| **Defense Evasion** | `T1036.005` | Masquerading: Match Legitimate Name or Location | Using misleading domain `cdn-telemetry-cache.com` to imitate CDN traffic. |

---

## 6. VaultX Feature Extraction & Detection Algorithm

VaultX calculates the following flow features from Zeek `conn.log` and `ssl.log` every 60 seconds:
1. **Byte Asymmetry Index ($BAI$):**
   $$BAI = \frac{\text{orig\_bytes} - \text{resp\_bytes}}{\text{orig\_bytes} + \text{resp\_bytes}}$$
   *(Normal web traffic: $BAI \in [-0.9, -0.3]$; Exfiltration: $BAI \approx +0.99$)*
2. **Session Persistence Factor ($SPF$):** Duration of active connection exceeding $99.9\text{th}$ percentile of engineering VLAN baseline.
3. **Domain & JA3 Reputation Vector:** Zero-shot threat intelligence lookup on SNI and JA3 client hash.

---

## 7. Containment Strategy

1. **Firewall Drop Rule:**
   - Automatically push dynamic drop filter for `185.196.8.121` on the border FortiGate.
2. **Workstation Isolation:**
   - Issue network isolation order for `ENG-WS-001` (`10.10.20.10`) via switch VLAN reassignment to Remediation VLAN 99.
3. **Forensic Notification:**
   - Alert Head of R&D and Security Lead to review compromised CAD projects and identify leaked intellectual property.
