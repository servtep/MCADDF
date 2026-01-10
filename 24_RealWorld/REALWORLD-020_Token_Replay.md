# [REALWORLD-020]: Token Replay CAE Evasion (Entra ID)

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-020 |
| **MITRE ATT&CK v18.1** | T1550 (Use of Web Session Cookie / Use of Stolen Tokens); related to T1556.009 (Modify Authentication Process: Conditional Access Policies) |
| **Tactic** | Credential Access; Defense Evasion; Persistence |
| **Platforms** | Microsoft Entra ID, Microsoft 365, CAE‑enabled SaaS (Exchange Online, SharePoint Online, Teams, Graph‑based apps) |
| **Severity** | High to Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Entra ID tenants using OAuth 2.0 / OIDC tokens with or without Continuous Access Evaluation (CAE) and Token Protection |
| **Patched In** | Not fully patched; partially mitigated by CAE, Token Protection, strict network enforcement and device binding |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Token replay CAE evasion targets weaknesses in how Entra ID and downstream services evaluate and revoke tokens. In classic cloud attacks, adversaries steal OAuth access, refresh or Primary Refresh Tokens (PRTs) and replay them from attacker‑controlled devices. Continuous Access Evaluation (CAE) and Token Protection aim to reduce the lifetime and replay value of stolen tokens, but misconfiguration, partial deployment, strict‑location bypass, and legacy non‑CAE aware apps create opportunities for attackers to retain access even after administrators believe they have revoked sessions.
- **Attack Surface:** OAuth access and refresh tokens, PRTs on Windows endpoints, browser session cookies, device‑code and auth‑code flows, and any application path that is not fully CAE‑aware or token‑bound.
- **Business Impact:** **Stealthy post‑compromise access even after incident response steps.** Adversaries can continue to use valid tokens to read mail, access files, or call Graph APIs while administrators are revoking sessions or resetting passwords. If CAE is not fully enforced, stolen tokens may remain valid for up to default lifetimes (for example, one hour or longer) or can be refreshed using long‑lived refresh tokens.
- **Technical Context:** Attacks are typically enabled by AiTM phishing, infostealers, or endpoint compromise that expose tokens or session cookies. CAE introduces near real‑time revocation for critical events and strict location enforcement, but only for CAE‑capable clients and resources. Evasion patterns include targeting non‑CAE aware apps, exploiting split‑tunnel or split‑path networking that disables strict location, obtaining non‑bound tokens, or performing activity quickly before CAE triggers.

### Operational Risk

- **Execution Risk:** Medium – Requires ability to steal valid tokens and understand target CAE and Conditional Access configuration.
- **Stealth:** High – Replayed tokens appear as fully authenticated sessions; MFA has already been satisfied and many logs look legitimate.
- **Reversibility:** Medium – Once all refresh tokens are revoked, CAE properly enforced and endpoints cleaned, access can be removed; data accessed during replay is not reversible.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Microsoft 365 / Entra ID CAE and session management | Requires secure configuration of session controls and token lifetimes. |
| **DISA STIG** | Identity and endpoint hardening STIGs | Token protection, secure authentication, and device security. |
| **CISA SCuBA** | Cloud identity protection | Emphasises detection and revocation of token theft and replay incidents. |
| **NIST 800-53** | AC-2, AC-7, AC-12, IA-2 | Session management, account control, and strong authentication. |
| **GDPR** | Art. 32 | Requires appropriate security of processing, including robust session and token protections. |
| **DORA** | Art. 9 | ICT risk management for identity and session controls in financial organisations. |
| **NIS2** | Art. 21 | Includes secure identity and session handling for essential services. |
| **ISO 27001** | A.5.15, A.8.2 | Secure user authentication and protection of access credentials and sessions. |
| **ISO 27005** | Token Theft and Replay | Risk scenario where theft of tokens undermines identity assurance and revocation.

## 3. TECHNICAL PREREQUISITES

- **Required Privileges (attacker):**
  - Ability to steal valid tokens (access, refresh, PRT) via AiTM phishing, malware, or browser/session compromise.
- **Required Access:**
  - Network path to services trusting Entra ID (Microsoft 365, Graph, custom apps).

**Supported Versions:**
- Entra ID tenants with and without CAE and Token Protection enabled.

## 4. ENVIRONMENTAL RECONNAISSANCE

### Assess CAE and Token Protection Posture

- Entra admin portal → Security → Conditional Access → Named locations and session policies.
- Review whether:
  - Continuous Access Evaluation is enabled for supported apps.
  - Token Protection policies are configured.
  - Sign‑in frequency and persistent browser session policies are set appropriately.

### Endpoint Reconnaissance (Token Stores)

- Review browser profiles and token caches on compromised endpoints.
- On Windows, inspect PRT and token caches with dedicated forensic tools; ensure LSA protection and credential guard are enabled for defence.

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Classic Token Replay Against Non‑CAE or Partially Protected Apps

**Supported Versions:** Any Entra tenant with legacy or non‑CAE aware applications.

#### Step 1: Steal Tokens

**Objective:** Obtain a valid token or session cookie.

**Execution Examples:**
- AiTM phishing proxy captures session cookies and OAuth tokens after user completes MFA.
- Infostealer malware exfiltrates browser cookies and PRTs from endpoints lacking Token Protection and LSA hardening.

#### Step 2: Replay Token From Attacker Infrastructure

**Objective:** Use the stolen token to authenticate from a different device or location.

**Execution:**
- Import cookies into attacker browser or use scripts to add stolen Authorization header values into API calls.
- Target services that are not CAE‑capable or where CAE session enforcement is misconfigured.

**Result:**
- Successful access as the victim user without additional MFA prompts, appearing as a normal session.

### METHOD 2 – CAE Evasion by Targeting Non‑Enforced Paths and Split‑Path Networks

**Supported Versions:** Entra tenants where CAE is configured but network paths or apps are not fully CAE‑enforced.

#### Step 1: Identify CAE‑Capable Apps and Policies

**Defensive View:**
- Enumerate CAE enabled applications and evaluate whether strict location enforcement is used or only standard enforcement.

#### Step 2: Target Non‑CAE Apps or Legacy Protocols

**Objective:** Use tokens against services that do not evaluate CAE signals or where Conditional Access is weaker.

**Execution:**
- Replay refresh tokens or PRT‑derived tokens to request access tokens for non‑CAE aware APIs or custom line‑of‑business apps.

#### Step 3: Exploit Split‑Path or Inconsistent Network Enforcement

**Objective:** Bypass strict network conditions that would otherwise revoke or block tokens.

**Execution:**
- Abuse configurations where authentication path and data path differ (for example, VPN or proxy misconfiguration) so that Entra relaxes location‑bound CAE enforcement.

## 6. ATTACK SIMULATION AND VERIFICATION (Atomic Red Team)

- Use Atomic Red Team tests for T1550 (Use of web session cookie) to emulate session token replay and validate CAE, Conditional Access and Identity Protection detections.

## 7. TOOLS AND COMMANDS REFERENCE

- Browser developer tools and scripts for importing cookies and tokens (red team use in lab only).
- Entra ID and Defender for Cloud Apps portals for monitoring token usage.
- PowerShell and Microsoft Graph for revoking tokens and inspecting sessions.

## 8. SPLUNK DETECTION RULES

### Rule: Token Replay or Session Hijack Pattern

```spl
index=o365 OR index=azure sourcetype="o365:management:activity" \
  Operation="UserLoggedIn"
| stats earliest(ClientIP) as first_ip, latest(ClientIP) as last_ip, \
        earliest(City) as first_city, latest(City) as last_city \
        by UserId, SessionId
| where first_ip!=last_ip OR first_city!=last_city
```

- Detects cases where the same session identifier is used from different IPs or locations, consistent with token replay.

## 9. MICROSOFT SENTINEL DETECTION

### Query: Possible Token Replay in Entra ID Sign‑In Logs

```kusto
SigninLogs
| summarize \
    firstTime=min(TimeGenerated), lastTime=max(TimeGenerated), \
    firstIp=arg_min(TimeGenerated, IPAddress).IPAddress, \
    lastIp=arg_max(TimeGenerated, IPAddress).IPAddress \
  by UserPrincipalName, SessionId
| where firstIp != lastIp
```

- Alerts when the same SessionId is used from different IPs, matching token replay or AiTM behaviour.

## 10. WINDOWS EVENT LOG MONITORING

- Focus on endpoint compromise that led to token theft (for example, malware execution, suspicious browser processes) rather than the replay itself, which is cloud‑side.

## 11. SYSMON DETECTION PATTERNS

- Detect infostealers, browser scraping tools and unusual access to browser and token cache directories.

## 12. MICROSOFT DEFENDER FOR CLOUD

- Ensure Identity Protection and CAE are enabled and tuned.
- Configure alerts for anomalous tokens, impossible travel, and suspicious OAuth app behaviour.

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) \
  -Operations 'UserLoggedIn' \
  | Export-Csv '.\\user-logins.csv' -NoTypeInformation
```

- Use for hunting anomalous locations and repeated logins from unusual IPs.

## 14. DEFENSIVE MITIGATIONS

- Enable CAE for all supported Microsoft 365 and custom apps where possible.
- Deploy Token Protection for sign‑in sessions and refresh tokens to bind tokens to devices.
- Use strict location enforcement for high‑risk roles and workloads.
- Harden endpoints with LSA protection, Credential Guard, and up‑to‑date antimalware to reduce token theft.
- Set short sign‑in frequencies and disable long‑lived persistent browser sessions for privileged users.

## 15. DETECTION AND INCIDENT RESPONSE

- When token theft or replay is suspected:
  - Immediately revoke all refresh tokens for affected accounts.
  - Invalidate sessions via Entra ID and, where possible, sign users out of all sessions.
  - Reset passwords and re‑enrol MFA for compromised identities.
  - Isolate and triage endpoints where tokens were likely stolen.

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | Phishing / AiTM | User authenticates through adversary‑in‑the‑middle or compromised host. |
| 2 | Credential Access | Token theft (T1552, T1550) | Access, refresh or PRT tokens stolen. |
| 3 | Current Step | REALWORLD-020 – Token Replay CAE Evasion | Reuse tokens while avoiding or outrunning CAE controls. |
| 4 | Persistence | Long‑lived refresh tokens without Token Protection | Continued access until tokens are revoked or expire. |
| 5 | Impact | Data theft or further lateral movement | Abuse cloud APIs and apps under victim identity. |

## 17. REAL-WORLD EXAMPLES

- Vendor and Microsoft security blogs describing real token theft campaigns, anomalous token detections and the role of CAE.
- Case studies of AiTM phishing and infostealer‑driven token replay against Microsoft 365.

---