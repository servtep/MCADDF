# [MISCONFIG-002]: Disabled MFA Requirements

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-002 |
| **MITRE ATT&CK v18.1** | T1556.006 – Multi-Factor Authentication (Modify Authentication Process) |
| **Tactic** | Defense Evasion / Persistence / Initial Access |
| **Platforms** | Microsoft Entra ID / Microsoft 365 (sign-in policies, Conditional Access, security defaults, MFA registration) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Microsoft Entra ID tenants (security defaults and Conditional Access capable SKUs) |
| **Patched In** | N/A – configuration-dependent; requires hardening rather than vendor patch |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** Disabled MFA requirements arise when security defaults are turned off without equivalent Conditional Access policies, when Conditional Access excludes large user populations or critical accounts from MFA, or when legacy authentication protocols and non-interactive flows bypass MFA controls. This creates large windows where valid but single‑factor credentials are sufficient for full account access.
- **Attack Surface:** All interactive and non‑interactive sign‑in flows to Entra ID and Microsoft 365 workloads, including browser, desktop and mobile clients, legacy protocols (SMTP, IMAP, POP, MAPI, EWS), service principals, and OAuth flows such as ROPC.
- **Business Impact:** **Mass account takeover and persistent access using only passwords.** Adversaries can perform password spraying, credential stuffing, and replay attacks that completely bypass MFA‑based mitigations, then maintain persistence by registering additional factors, app passwords, or modifying policies.
- **Technical Context:** Even if MFA is nominally “enabled”, Conditional Access design flaws (broad exclusions, gaps in policy scope, lack of coverage for non‑interactive sign‑ins) or disabled security defaults allow many sign‑ins to proceed without MFA. Legacy authentication and special flows (such as BAV2ROPC and SMTP AUTH) present additional MFA blind spots when not comprehensively blocked.

### Operational Risk
- **Execution Risk:** High – Exploitation relies on commodity techniques (password spray, credential stuffing) and widely available tools.
- **Stealth:** Medium to High – Failed sprays are noisy in sign‑in logs but rarely monitored systematically; successful logons without MFA look similar to legitimate low‑risk access if not correlated with geography, device, or risk signals.
- **Reversibility:** Partial – Enforcing MFA and blocking legacy authentication can be done quickly, but compromise that occurred while MFA was disabled (data theft, lateral movement, mailbox rules, OAuth grants) may be difficult to fully undo.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Microsoft 365 / Entra ID controls on strong authentication | Benchmarks require MFA for privileged accounts and recommend MFA for all users; disabling MFA violates these controls. |
| **DISA STIG** | Access control and IA family controls | STIGs require multi‑factor authentication for administrative access and remote access wherever technically feasible. |
| **CISA SCuBA** | Identity and access baselines | SCuBA profiles mandate MFA for all privileged accounts and for general user access to cloud services. |
| **NIST 800-53** | AC‑2, AC‑7, AC‑17, IA‑2, IA‑11 | Account management, remote access, and identification/authentication controls explicitly call for multifactor mechanisms for privileged and remote access. |
| **GDPR** | Art. 32 | Controllers and processors must implement appropriate technical measures; MFA is a common expectation for access to personal data in cloud services. |
| **DORA** | Articles on ICT risk management and access control | Financial entities are expected to deploy strong authentication and protect access to critical services and data. |
| **NIS2** | Art. 21 | Requires appropriate measures including multi‑factor authentication for network and information systems of essential and important entities. |
| **ISO 27001** | A.5.15, A.8.2, A.8.3 | Access control and user authentication controls require strong authentication proportional to risk, especially for privileged and remote access. |
| **ISO 27005** | Risk scenario: “Credential theft without secondary factor” | Disabled or weak MFA is a primary risk driver for large-scale credential compromise scenarios. |

## 3. TECHNICAL PREREQUISITES
- **Required Privileges (to MISCONFIGURE):** Global Administrator, Security Administrator, Conditional Access Administrator, or custom roles with permission to manage authentication methods and Conditional Access policies.
- **Required Privileges (to EXPLOIT):** Any account for which MFA is not enforced on the relevant sign‑in paths (standard user, guest, or service account).
- **Required Access:** Ability to send authentication requests to Entra ID endpoints (internet connectivity). For spray attacks, access to tenant identifiers (domain names, user formats) is helpful but often trivial to obtain.

**Supported Versions / Scope:**
- All Entra ID tenants with security defaults disabled or replaced by incomplete Conditional Access policies.
- All Microsoft 365 workloads federated to Entra ID.

- **Tools:**
  - Entra admin center (security defaults, authentication methods, Conditional Access).
  - Sentinel / Log Analytics (to analyze Sign‑in Logs and Audit Logs).
  - PowerShell / CLI for managing policies and searching logs.

## 4. ENVIRONMENTAL RECONNAISSANCE

#### Management Station / Portal Reconnaissance (Configuration)

**Check Security Defaults and Conditional Access:**
- In the **Entra admin center**:
  1. Go to **Entra ID → Overview → Properties**.
  2. At the bottom, open **Manage security defaults**.
  3. Verify whether **Security defaults** are set to **Enabled** or **Disabled**.
- Go to **Entra ID → Security → Conditional Access → Policies** and review:
  - Whether there is at least one policy that **requires MFA for all users** (or all high‑risk sign‑ins).
  - Whether there are broad **exclusions** (for example, “All users” policy but excluding `Guest`, `Directory Synchronization`, `Service` or large security groups).

**What to Look For:**
- Security defaults **Disabled** without a comprehensive Conditional Access design.
- No tenant‑wide MFA requirement, or MFA enforced only for a narrow subset of users or apps.
- Policies limited to particular apps (for example, Exchange Online) leaving gaps for others.

#### Sentinel / KQL Reconnaissance (Sign-in Logs)

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| extend errorCode = toint(Status.errorCode)
| where errorCode == 0  // successful sign-ins
| extend isMfaSatisfied = tostring(AuthenticationDetails[0].authenticationStepResultDetail)
| summarize Count = count() by isMfaSatisfied
```

**What to Look For:**
- A large volume of successful sign‑ins where no MFA step is present or clearly indicated.
- High‑privilege accounts authenticating without MFA.

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1 – Password Spraying Against MFA-Disabled Accounts

**Supported Versions:** All Entra ID tenants with incomplete MFA enforcement.

#### Step 1: Identify Targets Without MFA
**Objective:** Locate accounts that can authenticate without MFA.

**Approach (Defender / Sentinel / Logs):**
- Use Sign‑in Logs to filter successful sign‑ins with no MFA requirement.
- Focus on:
  - Accounts in administrative roles.
  - Service accounts and legacy mailboxes.
  - Guests and B2B accounts.

#### Step 2: Conduct Password Spray
**Objective:** Use low‑and‑slow password spraying to obtain valid credentials.

**Notes:**
- From an attacker standpoint, commonly targeted protocols include web sign‑ins and legacy endpoints when not blocked.
- Detection depends on failed logon monitoring, impossible travel, risk‑based policies, and account lockout thresholds.

#### Step 3: Establish Persistence
**Objective:** Once authenticated, an attacker can:
- Register additional MFA methods under their control (where allowed).
- Create app passwords or OAuth grants that bypass MFA.
- Modify Conditional Access or authentication policies if privileges permit.

### METHOD 2 – Conditional Access Gaps and Exclusions

**Supported Versions:** All tenants using Conditional Access.

#### Step 1: Enumerate Conditional Access Gaps
**Objective:** Identify policy combinations that allow password‑only sign‑ins.

**Portal Steps:**
1. Go to **Entra ID → Security → Conditional Access → Policies**.
2. Review each policy’s **Assignments**:
   - Users/groups.
   - Cloud apps.
   - Conditions (locations, device platforms, client apps).
3. Check **Grant** controls to see whether MFA is required, and for which traffic.

**Common Gaps:**
- Policies that target only a subset of users (for example, only administrators) and leave standard users unprotected.
- Policies that exclude “break‑glass” or service accounts too broadly.
- Policies not applied to non‑interactive sign‑ins.

#### Step 2: Exploit Exclusions
**Objective:** Log in with passwords only by using accounts excluded from MFA policies.

**What This Means:**
- A single compromised excluded account can be used to pivot into the environment with minimal friction and low immediate suspicion.

## 6. TOOLS & COMMANDS REFERENCE

#### Entra Admin Center – Security Defaults & MFA

- **Security Defaults:**
  - Path: **Entra ID → Overview → Properties → Manage security defaults**.
  - Secure baseline: **Enabled** unless fully replaced by Conditional Access.

- **Authentication Methods:**
  - Path: **Entra ID → Protection → Authentication methods**.
  - Ensure modern, phishing‑resistant methods are enabled and legacy/weak ones minimized.

#### Example: Review Conditional Access via KQL
```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "conditional access policy" and Result == "success"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

## 7. MICROSOFT SENTINEL DETECTION (MFA DISABLED / BYPASSED)

#### Query 1: Successful Sign-ins Without MFA
**Rule Configuration:**
- **Table:** `SigninLogs`.
- **Fields:** `UserPrincipalName`, `AuthenticationDetails`, `RiskDetail`, `RiskState`.
- **Severity:** High for privileged accounts; Medium for standard users.
- **Frequency:** Every 5–15 minutes; look back 1–24 hours.

**KQL Pattern:**
```kusto
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0  // success
| extend authDetail = tostring(AuthenticationDetails[0].authenticationStepResultDetail)
| where authDetail == "" or authDetail == "MFA requirement satisfied by claim" or isempty(authDetail)
| project TimeGenerated, UserPrincipalName, IPAddress, ClientAppUsed, RiskDetail, RiskState
```

**What This Detects:**
- Successful sign‑ins where no explicit MFA challenge occurred, including those where policies were not in scope or were silently satisfied.

## 8. MICROSOFT DEFENDER FOR CLOUD (IDENTITY PROTECTION)

#### Detection Alerts (Conceptual)
- “Users without MFA configured” for administrative roles.
- “Sign‑ins from unfamiliar locations or devices without MFA.”
- “Risky sign‑ins that succeeded with single‑factor authentication.”

**Remediation Guidance:**
- Enforce MFA registration for all users, with immediate focus on privileged roles.
- Review risky sign‑ins and force password reset where necessary.

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Security Defaults and Policy Changes
```powershell
Connect-ExchangeOnline

# Search for changes to security settings and Conditional Access/Authentication policies
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) \
  -Operations "Update policy","Update authentication method policy" -ResultSize 500
```

**What to Look For:**
- Recent changes disabling security defaults.
- Changes to authentication method policies.
- Conditional Access changes that relax MFA requirements or add broad exclusions.

## 10. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL – Enforce Tenant-Wide MFA Baseline
*   **Action 1: Enable Security Defaults (For Small Tenants).**
    1. Go to **Entra ID → Overview → Properties → Manage security defaults**.
    2. Set **Security defaults** to **Enabled**.
    3. Ensure all admins and users complete MFA registration.

*   **Action 2: Implement Comprehensive Conditional Access MFA Policies (For Larger Tenants).**
    1. Go to **Entra ID → Security → Conditional Access → Policies**.
    2. Create a policy such as **“Require MFA for All Users”**.
    3. Target **All users**, excluding only tightly-controlled break‑glass accounts.
    4. Target **All cloud apps**.
    5. Under **Grant**, select **Require multi-factor authentication**.
    6. Deploy via ring‑based rollout (pilot group → all users) while monitoring sign‑in impact.

#### Priority 2: HIGH – Block Legacy Authentication
*   **Action: Block Legacy Protocols Using Conditional Access.**
    1. Create a policy **“Block legacy authentication”**.
    2. Under **Conditions → Client apps**, select all **legacy authentication clients**.
    3. Under **Grant**, choose **Block access**.
    4. Phase rollout after auditing legacy usage.

#### Access Control & Policy Hardening
*   **Authentication Methods Governance:**
    - Prefer phishing‑resistant methods (FIDO2, Windows Hello for Business) where possible.
    - Avoid SMS/voice as sole second factors for high‑risk roles.

*   **Risk-Based Policies:**
    - Require MFA for sign‑ins with elevated risk or from unfamiliar locations/devices.

#### Validation Command (Verify Fix)
```kusto
// Sentinel – Percentage of sign-ins requiring MFA (example pattern)
SigninLogs
| where TimeGenerated > ago(7d)
| summarize Total = count(), WithMfa = countif(AuthenticationRequirement == "multiFactorAuthentication")
| extend MfaCoverage = 100.0 * todouble(WithMfa) / todouble(Total)
```

**What to Look For:**
- MFA coverage trending toward 100% for interactive sign‑ins, especially for admin roles.

## 11. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)
*   **Accounts:** Users with sudden spikes in successful sign‑ins without MFA, especially from new locations or devices.
*   **Configuration:** Recent changes disabling security defaults or relaxing Conditional Access / authentication method policies.
*   **Behavior:** Password‑spray‑like patterns (many failures against many users) followed by a small number of successes without MFA.

#### Forensic Artifacts
*   **Sign‑in Logs:** Successful and failed attempts, client apps used, MFA requirements.
*   **Audit Logs / Unified Audit Log:** Policy changes, security defaults toggling, authentication method registrations.

#### Response Procedures
1.  **Contain:**
    - Immediately re‑enable MFA requirements (security defaults or Conditional Access).
    - Block legacy authentication at the tenant level.

2.  **Eradicate:**
    - Reset passwords for affected accounts and invalidate refresh tokens.
    - Remove suspicious MFA methods or app passwords registered during the exposure window.

3.  **Recover:**
    - Review mail forwarding rules, OAuth consent grants, and directory role assignments for compromised accounts.

4.  **Lessons Learned:**
    - Update onboarding standards so new tenants never run without MFA.
    - Formalize Conditional Access design and periodic coverage reviews.

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | Valid Accounts (T1078) | Attacker obtains or guesses valid credentials. |
| **2** | **Current Step** | **[MISCONFIG-002] Disabled MFA Requirements** | Weak or missing MFA enforcement allows full account access with only a password. |
| **3** | **Persistence** | Account Manipulation (T1098) | Attacker registers new MFA methods, app passwords, or OAuth grants. |
| **4** | **Privilege Escalation** | Abuse Elevation Control Mechanism (T1548) | Attacker leverages access to escalate into administrative roles. |
| **5** | **Impact** | Data Exfiltration / Business Email Compromise | Attacker uses accounts to steal data, phish internally, or manipulate payments. |

## 13. REAL-WORLD EXAMPLES

#### Example 1: Password Spray Against Tenants Without MFA
- **Target:** Multiple Microsoft 365 tenants across sectors.
- **Timeline:** 2020–2025 and ongoing.
- **Technique Status:** ACTIVE – frequently seen in incident reports.
- **Impact:** Attackers used commodity password‑spray tools against tenants with no MFA or incomplete Conditional Access, leading to widespread mailbox compromise, internal phishing, and fraud.

#### Example 2: Legacy Authentication Bypass of MFA
- **Target:** Organizations leaving SMTP AUTH and other basic auth protocols enabled.
- **Timeline:** Documented widely as identity attack vector.
- **Technique Status:** ACTIVE – though reduced where legacy auth has been aggressively disabled.
- **Impact:** Even where MFA was enabled for web sign‑in, attackers used legacy protocols and flows to authenticate without MFA, then used the access for spam, phishing, or credential replay.

---