# [MISCONFIG-004]: Legacy Authentication Enabled

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-004 |
| **MITRE ATT&CK v18.1** | T1556 – Modify Authentication Process (legacy protocols) |
| **Tactic** | Initial Access / Defense Evasion / Persistence |
| **Platforms** | Microsoft Entra ID / Microsoft 365 (Exchange Online, other basic-auth workloads) |
| **Severity** | High to Critical (depending on exposure) |
| **Technique Status** | ACTIVE (though reduced where legacy auth is fully blocked) |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All tenants where legacy protocols (SMTP AUTH, IMAP, POP, older MAPI/EWS) remain enabled |
| **Patched In** | N/A – requires explicit configuration to disable legacy auth and enforce modern authentication |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** Legacy authentication refers to basic and modernized flows that do not fully support Conditional Access and MFA, including SMTP AUTH, POP, IMAP, older MAPI/EWS, and some older Office clients. When these are left enabled, attackers can authenticate with just usernames and passwords, often bypassing MFA and other advanced controls.
- **Attack Surface:** Internet-exposed Microsoft 365 and Entra ID endpoints that accept legacy protocols; mobile and desktop mail clients; scripts and applications still using basic authentication.
- **Business Impact:** **Bypass of MFA and Conditional Access for accounts with valid credentials.** Attackers can use password spraying and credential stuffing to gain mailbox access, send phishing emails, exfiltrate data, and pivot further into the tenant.
- **Technical Context:** Even when organizations enable MFA for web and modern clients, legacy protocols can remain enabled for compatibility. Features such as BAV2ROPC can obscure underlying basic authentication, and many tenants have not fully removed SMTP AUTH or other legacy endpoints. Sign‑in Logs and unified audit logs provide visibility, but only if actively monitored and acted upon.

### Operational Risk
- **Execution Risk:** High – Commodity tools and scripts can target these endpoints at scale with low sophistication.
- **Stealth:** Medium – Failed attempts are noisy but often not monitored; successful sessions using SMTP AUTH or similar may generate limited telemetry visible to end users.
- **Reversibility:** Configuration can be hardened quickly, but misuse of compromised mailboxes (phishing, fraud, data theft) can have long‑lasting consequences.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | Microsoft 365 / Entra ID recommendations to disable legacy authentication | Legacy protocols undermine MFA and policy-based controls required by CIS. |
| **DISA STIG** | IA and AC controls for network / remote access | STIGs expect strong authentication for remote/cloud services; basic auth without MFA is non‑compliant. |
| **CISA SCuBA** | Identity baseline | SCuBA emphasizes phasing out legacy auth to support strong identity protections. |
| **NIST 800-53** | AC‑17, IA‑2, IA‑11 | Remote access and authentication controls discourage single‑factor basic auth for sensitive resources. |
| **GDPR** | Art. 32 | Continuing to allow weak authentication may be inconsistent with “state of the art” security obligations for personal data. |
| **DORA** | ICT risk management for financial entities | Use of basic auth can be interpreted as insufficient identity assurance for critical financial systems. |
| **NIS2** | Art. 21 | Requires appropriate access control measures; legacy auth is widely regarded as weak and risky. |
| **ISO 27001** | A.5.15, A.8.2, A.8.3 | Strong technical authentication controls should be enforced; basic auth contradicts best practice. |
| **ISO 27005** | Risk scenario: “Legacy protocol used to bypass modern controls” | Legacy endpoints provide direct paths around zero‑trust architectures. |

## 3. TECHNICAL PREREQUISITES
- **Required Privileges (to MISCONFIGURE):** Global Administrator, Exchange Administrator, or roles capable of changing modern/legacy auth and protocol settings.
- **Required Privileges (to EXPLOIT):** Any username with a valid password where legacy auth is still enabled.
- **Required Access:** Internet connectivity to M365/Entra endpoints supporting legacy protocols.

**Scope:**
- Exchange Online (SMTP AUTH, POP, IMAP, older MAPI/EWS).
- Other SaaS services still accepting basic auth.

## 4. ENVIRONMENTAL RECONNAISSANCE

#### Portal Reconnaissance – Identify Legacy Auth Usage

**Entra Sign-in Logs:**
1. In **Entra admin center**, go to **Entra ID → Monitoring & health → Sign-in logs**.
2. Add the **Client app** filter and select all **Legacy authentication clients**.
3. Review successful sign‑ins over the last 7–30 days.

**What to Look For:**
- Accounts with recurring successful sign‑ins via legacy protocols.
- High‑value users or service accounts using legacy auth.

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1 – Password Spray via Legacy Protocols

**Supported Versions:** All tenants where legacy auth endpoints remain enabled.

#### Step 1: Enumerate Usernames
**Objective:** Build a list of valid usernames using OSINT, enumeration, or previous breaches.

#### Step 2: Conduct Spray Against Legacy Endpoints
**Objective:** Attempt authentication via SMTP AUTH / IMAP / POP using a small set of common passwords.

**Result:**
- Any match grants mailbox‑level or account‑level access without MFA where legacy auth is not blocked.

### METHOD 2 – Bypassing MFA for Accounts Using Legacy Clients

**Objective:** Use discovered valid credentials against legacy endpoints even when MFA is enforced for web sign‑ins.

**What This Means:**
- MFA protecting modern clients does not help if legacy protocols are still allowed.

## 6. TOOLS & COMMANDS REFERENCE

#### Entra Admin Center – Block Legacy Auth with Conditional Access

- Path: **Entra ID → Security → Conditional Access → Policies**.
- Create a policy **“Block legacy authentication”**.
  - Users: **All users** (carefully manage exceptions if truly required).
  - Cloud apps: **All cloud apps**.
  - Conditions → Client apps: select all **Legacy authentication clients**.
  - Grant: **Block access**.

#### Exchange Online – Protocol Configuration (Conceptual)

- Review and disable POP/IMAP/SMTP AUTH per‑mailbox and tenant‑wide, aligning with Microsoft’s current guidance.

## 7. MICROSOFT SENTINEL DETECTION (LEGACY AUTH SIGN-INS)

#### Query 1: Successful Legacy Authentication Sign-ins

**Rule Configuration:**
- **Table:** `SigninLogs`.
- **Severity:** High.
- **Frequency:** 5–15 minutes; look back 1 day.

**KQL Pattern:**
```kusto
SigninLogs
| where TimeGenerated > ago(1d)
| where ClientAppUsed in~ ("IMAP", "POP", "SMTP", "MAPI", "Other clients")
| where ResultType == 0  // success
| project TimeGenerated, UserPrincipalName, ClientAppUsed, IPAddress, AppDisplayName
```

**What This Detects:**
- Successful sign‑ins using legacy protocols, suitable for alerting and follow‑up.

## 8. MICROSOFT DEFENDER FOR CLOUD (IDENTITY & M365)

#### Detection Alerts (Conceptual)
- Alerts or recommendations indicating continued use of basic/legacy authentication.
- Risky sign‑ins or anomalies associated with legacy protocols.

**Mitigation:**
- Follow product guidance to disable legacy authentication and migrate remaining clients.

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Legacy Protocol Use in Audit Logs
```powershell
Connect-ExchangeOnline

Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) \
  -Operations "UserLoggedIn" -ResultSize 500 |
  Where-Object { $_.AuditData -like "*SMTP*" -or $_.AuditData -like "*POP*" -or $_.AuditData -like "*IMAP*" }
```

**What to Look For:**
- Accounts with repeated logons via SMTP/POP/IMAP.

## 10. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL – Block Legacy Authentication
*   **Action 1: Block Legacy Clients via Conditional Access.**
    - As detailed above, create a CA policy that blocks legacy authentication clients for all users.

*   **Action 2: Disable Legacy Protocols in Exchange Online.**
    - For each mailbox, disable POP/IMAP/SMTP AUTH where not required.
    - Update mail clients to use modern authentication.

#### Priority 2: HIGH – Monitor and Phase-Out Exceptions
*   **Action:** Maintain a strict list of exceptions with a clear decommissioning plan and continuous monitoring.

#### Validation Query (Verify Fix)
```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed in~ ("IMAP", "POP", "SMTP", "MAPI", "Other clients")
| summarize Count = count() by ClientAppUsed
```

**What to Look For:**
- Zero or near‑zero successful legacy sign‑ins over time.

## 11. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)
*   Sudden spikes in SMTP AUTH or other legacy‑protocol sign‑ins.
*   Mailboxes sending large volumes of outbound mail unexpectedly.

#### Forensic Artifacts
*   **Sign-in Logs:** ClientAppUsed values indicating legacy auth.
*   **Unified Audit Log:** Detailed protocol and operation data for logons.

#### Response Procedures
1.  **Contain:**
    - Immediately block legacy auth using Conditional Access.
    - Disable affected protocols for compromised accounts.

2.  **Investigate:**
    - Review outbound mail, mailbox rules, and forwarding.
    - Correlate with sign‑in sources and IP addresses.

3.  **Remediate:**
    - Reset passwords and enforce MFA.
    - Migrate or retire any remaining legacy clients.

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | Password Spraying (T1110.003) | Attacker targets legacy auth endpoints. |
| **2** | **Current Step** | **[MISCONFIG-004] Legacy Authentication Enabled** | Legacy protocols permit access without MFA or modern controls. |
| **3** | **Persistence** | Account Manipulation (T1098) | Attacker sets forwarding rules, app passwords, or OAuth grants. |
| **4** | **Lateral Movement** | Use of Compromised Accounts | Attacker sends internal phishing and accesses additional resources. |
| **5** | **Impact** | Data Exfiltration / Fraud | Compromised mailboxes used for data theft or financial fraud. |

## 13. REAL-WORLD EXAMPLES

#### Example 1: BAV2ROPC and Legacy Auth
- **Scenario:** Organizations relying on legacy protocols like SMTP AUTH while assuming MFA blocked attacks.
- **Impact:** Attackers exploited the underlying basic authentication behavior to gain access with passwords only, sending spam and phishing from compromised mailboxes.

#### Example 2: Legacy Mobile Mail Clients
- **Scenario:** Older mobile email apps requiring basic auth left enabled for “business reasons”.
- **Impact:** Attackers leveraged stolen credentials to sync entire mailboxes without MFA, leading to large‑scale data exposure and business email compromise.

---