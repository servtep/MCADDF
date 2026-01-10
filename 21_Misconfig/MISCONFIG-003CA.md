# [MISCONFIG-003]: Conditional Access Gaps

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-003 |
| **MITRE ATT&CK v18.1** | T1556.009 – Conditional Access Policies (Modify Authentication Process) |
| **Tactic** | Defense Evasion / Initial Access / Persistence |
| **Platforms** | Microsoft Entra ID (Conditional Access), Microsoft 365 workloads relying on Entra ID |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Entra ID tenants using Conditional Access |
| **Patched In** | N/A – requires secure policy design and ongoing governance |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** Conditional Access (CA) gaps are design or implementation flaws where some sign‑ins are not evaluated by any effective policy, or are evaluated only by weak policies. Examples include over‑specific policies, uncontrolled exclusions, per‑app policies that omit core services, report‑only rules never enforced, and missing coverage for non‑interactive sign‑ins. Attackers exploit these “holes” to bypass MFA, device compliance checks, or other controls even in tenants that appear heavily protected.
- **Attack Surface:** All Entra ID sign‑in flows to Microsoft 365 and Azure resources, particularly:
  - Users or groups excluded from policies (for example, break‑glass, service, guest, and testing accounts).
  - Non‑interactive sign‑ins and legacy protocols.
  - Newly provisioned apps or tenants where CA coverage was not updated.
- **Business Impact:** **Silent bypass of zero‑trust controls and MFA.** Misdesigned CA allows attackers with valid credentials to authenticate with fewer or no security checks, undermining otherwise strong posture and enabling long‑term persistence.
- **Technical Context:** By default, Entra allows sign‑ins unless blocked or constrained by a CA policy. Poorly designed policies (too many narrow rules, lack of a “block‑by‑default” pattern, or unmonitored exclusions) leave large portions of traffic effectively unmanaged. Insights & Reporting often reveals that only a fraction of sign‑ins are under CA evaluation.

### Operational Risk
- **Execution Risk:** High – Exploitation only requires valid credentials and knowledge of which paths are not covered by CA; these are often easy to infer (service accounts, certain apps, legacy protocols).
- **Stealth:** High – Successful sign‑ins via CA gaps look like standard logons in most monitoring systems unless specific coverage analytics exist.
- **Reversibility:** Good for the configuration (policies can be redesigned), but damage from undetected access (data exfiltration, inbox rules, OAuth grants) might be hard to fully reconstruct.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | Conditional Access and MFA configuration controls | Benchmarks expect systematic use of CA to enforce MFA, device compliance, and session controls; gaps violate these expectations. |
| **DISA STIG** | Access enforcement controls | STIGs require robust access enforcement for remote/cloud services; CA gaps represent inconsistent policy enforcement. |
| **CISA SCuBA** | Conditional Access / policy baselines | SCuBA emphasizes consistent policy coverage, including high‑risk sign‑ins and privileged accounts; design gaps are non‑compliant. |
| **NIST 800-53** | AC‑2, AC‑3, AC‑17, AC‑19, AC‑20 | Access control, remote access, and external connections must be governed by consistently applied policies. |
| **GDPR** | Art. 25, Art. 32 | Security by design and by default requires that technical measures (like CA) are applied comprehensively, not partially. |
| **DORA** | ICT risk management and access control articles | Conditional access gaps in financial tenants undermine mandated strong access governance. |
| **NIS2** | Art. 21 | Requires appropriate risk‑based access control measures across essential and important entities’ systems. |
| **ISO 27001** | A.5.15, A.8.2, A.8.3 | Policies and mechanisms must be consistently enforced; partial or uneven CA coverage contradicts these controls. |
| **ISO 27005** | Risk scenario: “Bypass of policy‑based access control” | CA gaps directly instantiate this risk scenario in cloud identity. |

## 3. TECHNICAL PREREQUISITES
- **Required Privileges (to MISCONFIGURE):** Global Administrator, Security Administrator, Conditional Access Administrator, or equivalent custom roles.
- **Required Privileges (to EXPLOIT):** Any account whose sign‑in path is not under effective CA evaluation (user, guest, service principal).
- **Required Access:** Ability to authenticate to Entra ID and reach the targeted workloads.

**Scope:**
- All Entra ID tenants using Conditional Access.
- Sign‑in types: interactive, non‑interactive, legacy, and modern.

## 4. ENVIRONMENTAL RECONNAISSANCE

#### Portal Reconnaissance – Policy Inventory

**Steps:**
1. Go to **Entra ID → Security → Conditional Access → Policies**.
2. Export or list all policies, noting:
   - State: **On**, **Off**, or **Report‑only**.
   - Assignments: **Users/Groups**, **Cloud apps**, **Conditions**.
   - **Grant** controls: MFA, device compliance, block, etc.

**What to Look For:**
- Policies still in **Report‑only** for long periods.
- Policies targeting only small pilot groups with no equivalent tenant‑wide rule.
- Large exclusion lists containing generic groups, guests, or “All service accounts”.

#### Insights & Reporting / KQL

Use Insights & Reporting to estimate coverage, or KQL queries over `SigninLogs` that show which sign‑ins were evaluated by policies and with what result.

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| summarize Total = count(), WithConditionalAccess = countif(isnotempty(ConditionalAccessStatus))
| extend CoveragePercent = 100.0 * todouble(WithConditionalAccess) / todouble(Total)
```

**What to Look For:**
- Coverage percentages significantly below 100%, especially for high‑privilege accounts.

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1 – Bypassing Controls via Excluded Accounts

**Supported Versions:** All Entra tenants using CA with exclusions.

#### Step 1: Enumerate Excluded Accounts
**Objective:** Identify accounts not governed by strong CA policies.

**Portal Steps:**
1. For each critical policy (for example, “Require MFA for all users”):
   - Review **Users → Exclude**.
2. Note any broad or generic exclusions (for example, `All_Admins_Test`, `Service_Accounts`, entire domains).

**What This Means:**
- Any excluded account with sign‑in capability represents a potential bypass for the controls enforced by that policy.

#### Step 2: Authenticate as an Excluded Account
**Objective:** Use acquired credentials for an excluded account to sign in without restrictions enforced by the excluded policy.

**Outcome:**
- Sign‑in proceeds without MFA or device constraints that would otherwise apply.

### METHOD 2 – Exploiting Gaps from Overly Specific Policies

**Supported Versions:** All CA deployments with many granular policies.

#### Step 1: Identify App or Scenario Coverage Gaps
**Objective:** Determine which apps or sign‑in types are not covered by strong CA.

**Portal Steps:**
1. Review each policy’s **Cloud apps or actions** scope.
2. Compare with the organization’s actual application inventory.

**Common Issues:**
- Policies created only for Exchange Online / SharePoint while other critical apps remain unmanaged.
- Non‑interactive sign‑ins or legacy protocols not covered by any blocking policy.

#### Step 2: Target Unprotected Apps
**Objective:** Use valid credentials against apps or flows not covered by CA (for example, a custom line‑of‑business application or API without CA enforcement) to gain access with fewer checks.

## 6. TOOLS & COMMANDS REFERENCE

#### Entra Admin Center – Conditional Access Essentials

- **Policy List:** **Entra ID → Security → Conditional Access → Policies**.
- **Insights & Reporting:** **Conditional Access → Insights and reporting** to view CA evaluation results and coverage.
- **What If Tool:** On a given policy, use **What If** to simulate how sign‑ins would be evaluated.

#### Sentinel / KQL Examples
```kusto
// List recent Conditional Access policy changes
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "conditional access policy" and Result == "success"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

## 7. MICROSOFT SENTINEL DETECTION (CA POLICY CHANGES & GAPS)

#### Query 1: Conditional Access Policy Modified by New Actor

**Purpose:** Detect CA policy modifications performed by identities that have not changed policies recently.

**Rule Configuration:**
- **Table:** `AuditLogs`.
- **Severity:** Medium to High depending on environment.
- **Frequency:** Daily (look back 14 days).

**KQL Pattern (adapted):**
```kusto
let known_actors = (
  AuditLogs
  | where TimeGenerated between(ago(14d)..ago(1d))
  | where OperationName has "conditional access policy" and Result == "success"
  | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
  | summarize by Actor
);
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName has "conditional access policy" and Result == "success"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| where Actor !in (known_actors)
| project TimeGenerated, OperationName, Actor, TargetResources
```

**What This Detects:**
- New administrators (or compromised accounts) modifying CA policies, potentially to introduce gaps or weaken enforcement.

## 8. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts (Conceptual)
- Recommendations indicating weak or missing Conditional Access coverage for privileged roles.
- Findings related to sign‑ins not protected by MFA or risk‑based Conditional Access.

**Mitigation Focus:**
- Enforce baseline CA templates where available.
- Integrate identity risk signals into CA decisions.

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Conditional Access Policy Changes
```powershell
Connect-ExchangeOnline

Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) \
  -Operations "Add conditional access policy","Update conditional access policy","Delete conditional access policy" \
  -ResultSize 500
```

**What to Look For:**
- New or modified CA policies that:
  - Remove MFA requirements.
  - Add large exclusion groups.
  - Narrow the set of protected apps.

## 10. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL – Adopt a “Block-by-Default” CA Strategy
*   **Action 1: Design Baseline Policies That Cover All Sign-ins.**
    1. Create a baseline policy that **blocks all sign‑ins** by default, then explicitly allows defined personas (users, devices, locations) with MFA and device checks.
    2. Ensure there is always at least one emergency break‑glass account, carefully monitored and protected by strong controls.

*   **Action 2: Minimize Exclusions.**
    - Replace broad exclusions with the smallest possible set of service and break‑glass accounts.
    - Document and regularly review all exclusions.

#### Priority 2: HIGH – Simplify and Consolidate Policies
*   **Action:** Reduce the number of overlapping granular policies and move toward a small set of well‑structured “persona‑based” policies (for example, employees, partners, admins, devices).

#### Access Control & Policy Hardening
*   Use **Insights & Reporting** to monitor CA coverage.
*   Conduct periodic reviews of **What If** results for key personas and applications.

#### Validation Command (Verify Fix)
```kusto
// Estimate CA coverage for administrator sign-ins
SigninLogs
| where TimeGenerated > ago(7d)
| where isnotempty(ConditionalAccessStatus)
| summarize Total = count(), Blocked = countif(ConditionalAccessStatus == "failure"), 
            WithControls = countif(ConditionalAccessStatus == "success")
```

**What to Look For:**
- High percentage of sign‑ins for privileged roles evaluated by CA and subject to MFA/device controls.

## 11. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)
*   Sudden CA policy changes not aligned with change management.
*   New exclusions for critical users or groups.
*   Successful sign‑ins from unusual locations or devices that do not trigger expected CA controls.

#### Forensic Artifacts
*   **AuditLogs:** CA policy add/update/delete operations.
*   **SigninLogs:** ConditionalAccessStatus, applied policies, and outcomes.

#### Response Procedures
1.  **Contain:**
    - Temporarily disable suspicious CA policy changes or revert to known‑good baselines.
    - Remove inappropriate exclusions.

2.  **Investigate:**
    - Identify who changed CA policies and from which IP/device.
    - Review all sign‑ins that occurred while weakened policies were active.

3.  **Remediate:**
    - Redesign CA according to best practices (persona‑based, minimal exclusions, baseline MFA).
    - Implement monitoring and alerting for CA changes.

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | Valid Accounts (T1078) | Attacker obtains valid credentials. |
| **2** | **Defense Evasion** | **[MISCONFIG-003] Conditional Access Gaps** | Attacker authenticates through paths not protected by strong CA policies. |
| **3** | **Persistence** | Account Manipulation (T1098) | Attacker registers devices, adds MFA methods, or creates OAuth grants via unprotected flows. |
| **4** | **Privilege Escalation** | Abuse Elevation Control Mechanism (T1548) | Attacker leverages unprotected access to gain additional roles. |
| **5** | **Impact** | Data Exfiltration / Business Email Compromise | Attacker uses the bypassed controls to conduct long‑term malicious activity. |

## 13. REAL-WORLD EXAMPLES

#### Example 1: Policy Overload and Unintended Gaps
- **Scenario:** Tenant with hundreds of CA policies, many highly specific.
- **Issue:** Only the first subset of policies were evaluated for some users; multiple scenarios were left without MFA or device checks.
- **Impact:** Attackers used valid credentials to log in via a combination of apps and locations that fell through the cracks, bypassing intended zero‑trust controls.

#### Example 2: Misused Exclusions for Service Accounts
- **Scenario:** Service accounts excluded from CA to avoid breaking automation.
- **Issue:** These accounts were also usable for interactive sign‑ins.
- **Impact:** Compromise of a single service account credential provided broad access without MFA or device validation, enabling further lateral movement and privilege escalation.

---