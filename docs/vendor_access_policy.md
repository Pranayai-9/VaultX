# Vendor Access Policy — Bharat Electronics Components Pvt. Ltd. (BECPL)

> **Document version:** 1.0  
> **Classification:** Internal – Restricted  
> **Last updated:** 2026-11-17  
> **Policy Owner:** IT Manager, BECPL  
> **Reviewed by:** VaultX Infrastructure Architect  
> **Next Review Date:** 2027-02-17 (Quarterly)

---

## 1. Policy Purpose & Scope

This policy governs all remote and on-site access by third-party vendors, contractors, and service providers to BECPL's IT and OT infrastructure. It applies to any person or automated system not employed directly by BECPL that requires network-level access to BECPL systems.

**In-scope:** Remote access via VPN/bastion, on-site vendor access to networked equipment, cloud support sessions, API integrations.  
**Out-of-scope:** Physical building access (covered by Physical Security Policy v1.1), read-only public-facing portals.

---

## 2. Approved Vendor Identities

### 2.1 Vendor Registry

| Vendor ID | Vendor Name | Type | Contact | Approved Since |
|---|---|---|---|---|
| **VEND-001** | Siemens India Ltd. (Authorized Partner) | OT Maintenance | siemens-support@partner.in | 2024-06-01 |
| **VEND-002** | CodeBridge Firmware Services Pvt. Ltd. | Firmware Dev Service | cb-secure@codebridge.in | 2025-01-15 |
| **VEND-003** | NetSolve IT Infrastructure Pvt. Ltd. | IT Infrastructure Vendor | helpdesk@netsolve.co.in | 2024-03-20 |
| **VEND-004** | Amazon Web Services India (TAM) | Cloud Vendor | becpl-tam@aws.amazon.com | 2023-11-01 |
| **VEND-005** | DTDC Express Ltd. | Logistics Provider | api-integration@dtdc.com | 2025-04-01 |
| **VEND-006** | BlueDart Express Ltd. | Logistics Provider | api@bluedart.com | 2025-04-01 |
| **VEND-007** | VaultX Security Partners | NIDS Project Contractor | vaultx@secpartners.in | 2026-11-01 |

---

## 3. Access Scope by Vendor

### 3.1 VEND-001 — Siemens India Ltd. (OT Maintenance)

| Attribute | Detail |
|---|---|
| **Access Type** | On-site physical access only (NO remote access) |
| **Allowed Segments** | VLAN 30 (Manufacturing OT) — specific PLCs and HMIs only |
| **Allowed Systems** | OT-PLC-SMTA-01, OT-PLC-SMTB-01, OT-HMI-SMTA-01, OT-HMI-SMTB-01 |
| **Prohibited Systems** | All VLAN 10, 20, 40, 50, 60, 70 assets |
| **Access Protocol** | Local serial console / laptop with approved offline tools |
| **Network Connectivity** | Zero — engineer's laptop must be air-gapped or on isolated maintenance VLAN |
| **MFA Requirement** | N/A (on-site escort policy applies) |
| **Session Limit** | Maximum 8 hours per maintenance window |
| **Advance Notice** | Minimum 48 hours written notice to IT Manager |

**On-Site Controls:**
- Vendor engineer must be escorted by BECPL Network/Systems Admin at all times
- Vendor laptop must be inspected and approved by IT Manager before connecting to any equipment
- All USB drives must be scanned with BECPL's offline antivirus tool before use
- Paper-based session log maintained (time in, systems accessed, actions taken, time out)
- VaultX NIDS probe on VLAN 30 provides passive recording of all network activity during session

---

### 3.2 VEND-002 — CodeBridge Firmware Services Pvt. Ltd. (Firmware Dev)

| Attribute | Detail |
|---|---|
| **Access Type** | Remote via VLAN 50 bastion host (DMZ-BASTION01) |
| **Allowed Segments** | VLAN 20 (Engineering & Firmware) only |
| **Allowed Systems** | ENG-GITSVR01 (read/push to dedicated firmware branch only), ENG-OTA-STG01 (push only, no console) |
| **Prohibited Systems** | All OT systems, corporate IT, production build infrastructure |
| **Access Protocol** | SSH via bastion (key-based authentication) |
| **MFA Requirement** | Mandatory — TOTP (Authenticator app) + SSH key |
| **Session Limit** | Maximum **4 hours** per session; auto-terminate enforced by bastion |
| **Allowed Hours** | Monday–Friday, 09:00–18:00 IST only |
| **Concurrent Sessions** | Maximum 2 simultaneous sessions per vendor identity |
| **Advance Notice** | 24 hours via vendor portal ticket (VEND-002 account) |

**Controls:**
- Bastion session recording enabled (keystroke + screen video, retained 90 days)
- Git repository access scoped to `firmware/external-dev` branch only; merge to main requires BECPL engineer approval
- No clipboard copy from bastion to external system allowed
- VaultX NIDS alerts on any attempt to reach VLAN 30 from VEND-002 session

---

### 3.3 VEND-003 — NetSolve IT Infrastructure (IT Vendor)

| Attribute | Detail |
|---|---|
| **Access Type** | Remote via VLAN 50 bastion host |
| **Allowed Segments** | VLAN 10 (Corporate IT) only |
| **Allowed Systems** | Servers: BECPL-DC01, BECPL-DC02, BECPL-FS01 (read-only AD audit), BECPL-PRINT01/02 |
| **Prohibited Systems** | VLAN 20 (Engineering), VLAN 30 (OT), VLAN 70 (Security Mgmt) |
| **Access Protocol** | RDP via bastion to specific server IPs |
| **MFA Requirement** | Mandatory — Hardware token (RSA SecurID or FIDO2) + AD credentials |
| **Session Limit** | Maximum **4 hours** per session |
| **Allowed Hours** | Monday–Saturday, 08:00–20:00 IST |
| **Concurrent Sessions** | Maximum 1 per ticket |
| **Advance Notice** | 24 hours via ServiceNow ticket raised by IT Manager |

**Controls:**
- Full RDP session recording; screen captures every 30 seconds
- Change requests must be pre-approved in writing before remote session
- BECPL IT Manager retains right to terminate session at any time
- All privileged commands logged to SIEM in real-time

---

### 3.4 VEND-004 — Amazon Web Services India (Cloud TAM/Support)

| Attribute | Detail |
|---|---|
| **Access Type** | AWS Console only (no on-premises access) |
| **Allowed Segments** | AWS cloud environment (ap-south-1) only |
| **Allowed Systems** | EC2 instances (ERP servers), S3 buckets (approved) — per IAM role |
| **Prohibited Systems** | On-premises VLANs 10, 20, 30, 40, 50, 70 |
| **Access Protocol** | AWS IAM + STS temporary credentials (assume-role with max 4h TTL) |
| **MFA Requirement** | Mandatory — AWS virtual MFA device |
| **Session Limit** | STS token TTL maximum **4 hours** |
| **Allowed Hours** | Business hours IST for scheduled support; emergency 24/7 with BECPL approval |
| **Concurrent Sessions** | Managed via AWS IAM role constraints |

**Controls:**
- AWS CloudTrail logging enabled for all API calls in BECPL account
- TAM access via dedicated IAM role `becpl-tam-support-role` with least-privilege policy
- BECPL IT Manager receives SNS notification on role assumption
- Cross-account access prohibited; TAM cannot access BECPL VPC directly (no VPC peering for support)

---

### 3.5 VEND-005 / VEND-006 — DTDC & BlueDart (Logistics API)

| Attribute | Detail |
|---|---|
| **Access Type** | Outbound API calls only (BECPL → vendor APIs); no inbound access |
| **Allowed Segments** | VLAN 60 (Cloud/External Integrations) — proxy layer only |
| **Access Protocol** | HTTPS (TLS 1.2+) REST API |
| **Authentication** | API key (stored in BECPL's secrets manager) |
| **MFA Requirement** | N/A (service-to-service, API key auth) |
| **Session Type** | Stateless; no persistent sessions |
| **Rate Limiting** | 100 requests/minute enforced at proxy |

**Controls:**
- API keys rotated quarterly
- All API calls logged at VLAN 60 proxy
- Outbound domain allowlist: `api.dtdc.com`, `api.bluedart.com` only
- No inbound callback hooks from logistics vendors (pull model only)

---

### 3.6 VEND-007 — VaultX Security Partners (NIDS Project)

| Attribute | Detail |
|---|---|
| **Access Type** | Remote via VLAN 50 bastion + on-site for probe deployment |
| **Allowed Segments** | VLAN 70 (Security Management) for NIDS console; VLAN 30 on-site for probe maintenance |
| **Allowed Systems** | SEC-NIDS-MGR01, SEC-SIEM01 (read-only), NIDS probes |
| **MFA Requirement** | Mandatory — FIDO2 hardware key |
| **Session Limit** | Maximum **4 hours** remote; unlimited on-site with escort |
| **Allowed Hours** | Monday–Friday, 09:00–19:00 IST |
| **Advance Notice** | 24 hours |

---

## 4. MFA Requirements

| Scenario | MFA Method | Enforcement Point |
|---|---|---|
| Remote access via bastion (all vendors) | TOTP or FIDO2 hardware key | FortiClient VPN + bastion SSH/RDP |
| AWS console access | AWS virtual MFA device | IAM policy condition |
| On-site privileged access (IT systems) | Physical escort (no network MFA) | Physical access log |
| Emergency/break-glass (see §6) | Hardware OTP token (kept in IT Manager's safe) | Manual verification |

**MFA grace period:** Zero tolerance — no session may be established without MFA completion.  
**Shared credentials:** Strictly prohibited. Each vendor engineer requires an individual account.

---

## 5. Session Limits & Technical Controls

| Control | Requirement |
|---|---|
| **Maximum session duration** | 4 hours (auto-terminate) |
| **Idle timeout** | 15 minutes (session killed, re-auth required) |
| **Concurrent sessions per vendor account** | Maximum 2 (default 1) |
| **Session recording** | Mandatory for all bastion sessions (keystroke + video) |
| **Recording retention** | 90 days minimum; 1 year for incident-related recordings |
| **Jump-host isolation** | Bastion cannot reach internet directly; all connections proxied |
| **Clipboard restriction** | Disabled by default on bastion RDP sessions |
| **File transfer** | Allowed only via approved SFTP path; files scanned before inbound |
| **Network segmentation** | Vendor sessions confined to approved destination IPs only (host-based firewall on bastion) |

---

## 6. Audit Logging Requirements

All vendor access must generate audit-grade logs that are:

- **Tamper-evident:** Logs forwarded to VLAN 70 SIEM (SEC-LOGCOL01) in real-time; stored separately from local bastion logs
- **Comprehensive:** Log fields include: Vendor ID, User ID, source IP, destination IP, protocol, port, session start/end, commands executed (for SSH), MFA event, session recording reference ID
- **Retained:** Minimum 1 year (online 90 days, archived 9 months on AWS S3 with Glacier lifecycle)
- **Reviewed:** Weekly review by IT Manager; automated alerts on anomalies (session duration >4h, off-hours access, failed MFA)

**SIEM Alerting Rules for Vendor Access:**
1. Any vendor session exceeding 4 hours → CRITICAL alert to IT Manager
2. Vendor session outside approved hours → HIGH alert
3. Vendor attempting to access non-approved segment → CRITICAL + automatic session termination
4. 3 consecutive MFA failures → account lock + CRITICAL alert
5. Vendor file download >50 MB in a session → HIGH alert for review

---

## 7. Break-Glass Procedures

**Break-glass** applies when emergency vendor access is required outside business hours or for systems not in the standard scope (e.g., production-down scenario).

### Procedure:
1. **Authorisation:** IT Manager (primary) or Director (secondary) must verbally authorise and document in the break-glass log
2. **Credential issuance:** Emergency credentials (time-limited, 2-hour) issued from secure physical vault (IT Manager's office safe)
3. **Supervision:** At least one BECPL staff member must be present (physical or via remote screen-share) throughout the break-glass session
4. **Notification:** BECPL Director and VaultX Security Partner notified within 15 minutes of session start
5. **Post-event review:** Full session recording reviewed within 24 hours; break-glass log entry completed
6. **Credential rotation:** Break-glass credentials rotated immediately after use; new credentials sealed in vault

**Break-glass log location:** `docs/break_glass_log.xlsx` on BECPL-FS01 (access-controlled, IT Manager + Director only)

---

## 8. Vendor Onboarding & Offboarding

### Onboarding Checklist:
- [ ] Signed NDA and IT Security Addendum received
- [ ] Background verification confirmation from vendor (for individuals accessing sensitive systems)
- [ ] Individual vendor accounts created (no shared accounts)
- [ ] MFA device enrolled and tested
- [ ] Vendor briefed on this policy (signature required)
- [ ] Access scope documented in Vendor Registry (§2.1)
- [ ] IT Manager approval email on record

### Offboarding Checklist:
- [ ] All vendor accounts disabled within 24 hours of project completion
- [ ] MFA device de-enrolled
- [ ] Session recordings reviewed for anomalies before archive
- [ ] API keys rotated (for logistics vendors)
- [ ] Vendor portal account deactivated
- [ ] Exit confirmation documented in Vendor Registry

---

## 9. Quarterly Access Reviews

Vendor access is reviewed **quarterly** (February, May, August, November) by the IT Manager with the following process:

1. Pull Vendor Registry and active account list from bastion
2. Confirm each vendor still has a valid business need
3. Review session logs from the previous quarter for policy adherence
4. Update access scope if project requirements have changed
5. Renew or revoke vendor accounts accordingly
6. Document review outcome in `docs/vendor_access_review_YYYY_QN.md`

**Next scheduled review:** 2027-02-17

---

## 10. Policy Violations & Consequences

| Violation | Consequence |
|---|---|
| Access outside approved scope | Immediate session termination; vendor account suspended |
| Shared credentials | Immediate account revocation; contract review |
| Attempting to access OT from remote | Automatic firewall block; CRITICAL alert; contract termination review |
| Data exfiltration attempt | Session termination; legal review; law enforcement notification |
| MFA bypass attempt | Account suspension; IT Manager escalation; possible contract termination |

---

*Policy owner: IT Manager, BECPL*  
*Approval: Managing Director, BECPL*  
*Last reviewed: 2026-11-17*
