# [MISCONFIG-001]: Overly Permissive RBAC

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-001 |
| **MITRE ATT&CK v18.1** | T1548 – Abuse Elevation Control Mechanism (Privilege Escalation) |
| **Tactic** | Privilege Escalation / Defense Evasion |
| **Platforms** | Microsoft Entra ID, Azure RBAC (management groups, subscriptions, resource groups, resources) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Microsoft Entra ID tenants using Azure RBAC (all current SKUs) |
| **Patched In** | N/A – configuration-dependent misconfiguration (no vendor hotfix) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** Overly permissive RBAC occurs when security principals (users, groups, service principals, managed identities, guests, partners) are assigned roles that exceed what is strictly required, often at excessively broad scopes (management group, subscription, or entire tenant). This violates least privilege and enables attackers who compromise any of these identities to perform high-impact actions such as creating new privileged accounts, exfiltrating data, or disabling security controls.
- **Attack Surface:** Microsoft Entra ID directory roles and Azure RBAC (management group, subscription, resource group, and resource scopes), including built‑in and custom roles, Privileged Identity Management (PIM) assignments, and role assignments delegated to external tenants (B2B guests, CSP, Lighthouse).
- **Business Impact:** **Rapid privilege escalation and full cloud takeover.** A single compromised low-trust identity with hidden high-privilege RBAC assignments can lead to tenant-wide data exposure, destructive changes (delete resources, rotate keys, modify policies), or disabling of logging and security controls.
- **Technical Context:** Attacks typically start from a valid but seemingly low-value identity (end user, service principal, guest). By enumerating role assignments and effective permissions, the attacker identifies mis-scoped roles (Owner, User Access Administrator, Contributor, custom roles with wildcard permissions) and abuses them to escalate privileges. Detection is feasible but requires continuous monitoring of RBAC changes, baselining of privileged roles, and rigorous reviews of cross-tenant and application permissions.

### Operational Risk
- **Execution Risk:** High – Misconfigured RBAC often enables irreversible or tenant-wide changes (resource deletion, key rotation, role escalation) once exploited.
- **Stealth:** Medium – All RBAC changes are logged, but most environments lack dedicated analytics. Abuse via existing over-privileged assignments can be subtle, especially when performed through legitimate portals and APIs.
- **Reversibility:** Partial – Role assignments can be corrected, but actions taken under over-privileged identities (data exfiltration, destructive operations, policy changes) may be irreversible without prior backups or versioning.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Microsoft Azure / Entra ID controls on least privilege and privileged access (for example, CIS Azure 1.x sections on RBAC and role assignments) | Overly broad RBAC assignments violate least‑privilege and privileged access management requirements. |
| **DISA STIG** | Access control family (role‑based or attribute‑based access enforcement) | STIG guidance requires strict control and monitoring of privileged roles; over‑privileged assignments breach these principles. |
| **CISA SCuBA** | Identity and Access Management (IAM) configuration baseline | SCuBA requires least‑privilege configuration of cloud roles and systematic review of privileged access. |
| **NIST 800-53** | AC‑2, AC‑3, AC‑5, AC‑6, AC‑17, AC‑19 | Account management and access enforcement controls mandate least privilege, separation of duties, and restriction of remote administrative access. |
| **GDPR** | Art. 25, Art. 32 | Data protection by design and security of processing require limiting access to personal data to what is strictly necessary. |
| **DORA** | Articles on ICT risk management and access control (for example, Art. 9) | Financial entities must ensure strict control of privileged access to critical systems and data. |
| **NIS2** | Art. 21 – Cybersecurity risk-management measures | Requires appropriate access control, including privileged access management, to essential and important entities’ networks and information systems. |
| **ISO 27001** | A.5.15, A.5.18, A.8.2, A.8.3 (and 2013 edition A.9.2.3) | Controls mandate least privilege, privileged access management, and periodic review of user access rights. |
| **ISO 27005** | Risk scenario: “Compromise or misuse of administration interfaces or privileged cloud identities” | Over‑permissive RBAC is a key driver for high‑impact identity and cloud governance risk scenarios. |

## 3. TECHNICAL PREREQUISITES
- **Required Privileges (to EXPLOIT):** Any identity that already has a misconfigured role with high‑impact permissions (for example, Owner, User Access Administrator, Contributor with security permissions, custom roles granting `Microsoft.Authorization/*`, `Microsoft.Resources/*`, or data‑plane actions).
- **Required Privileges (to CREATE/FIX misconfig):** Global Administrator, Privileged Role Administrator, User Access Administrator, or equivalent custom roles with RBAC write permissions.
- **Required Access:** Ability to authenticate to Microsoft Entra ID (interactive or via service principal) and reach Azure management endpoints (portal, Azure CLI, PowerShell, or management APIs).

**Supported Versions / Scope:**
- **Entra ID / Azure:** All current tenants and subscriptions using Azure RBAC.
- **Management scopes:** Tenant root group (if enabled), management groups, subscriptions, resource groups, individual resources.
- **PIM:** Both permanent and eligible role assignments in Microsoft Entra Privileged Identity Management.

- **Tools:**
  - Azure Portal (Microsoft Entra admin center and Azure Resource Manager portal).
  - Azure PowerShell (Az module – for example, `Get-AzRoleAssignment`, `New-AzRoleAssignment`).
  - Azure CLI (for example, `az role assignment list`, `az role assignment create`).

## 4. ENVIRONMENTAL RECONNAISSANCE

#### Management Station / PowerShell Reconnaissance
Use Azure PowerShell to enumerate RBAC assignments and identify over‑privileged identities.

```powershell
# Connect to Azure
Connect-AzAccount

# List all role assignments in the current subscription
Get-AzRoleAssignment |
  Sort-Object RoleDefinitionName, SignInName

# Focus on high-impact roles (Owner, User Access Administrator, Contributor)
Get-AzRoleAssignment |
  Where-Object { $_.RoleDefinitionName -in @("Owner", "User Access Administrator", "Contributor") } |
  Select-Object RoleDefinitionName, Scope, DisplayName, SignInName, ObjectId

# Identify custom roles with authorization or security permissions
Get-AzRoleDefinition |
  Where-Object { $_.Actions -match "Microsoft.Authorization/" -or $_.Actions -match "Microsoft.Security/" } |
  Select-Object Name, Id, @{Name="Actions";Expression={$_.Actions -join ";"}}
```

**What to Look For:**
- Assignments of **Owner** or **User Access Administrator** at:
  - Tenant root group or management-group scope.
  - Subscription scope assigned to generic groups (for example, “All_Employees”, “VPN_Users”) or external users.
- Custom roles whose `Actions` include wildcard or broad patterns (for example, `Microsoft.Authorization/*`, `*/*`).
- Service principals and managed identities holding powerful roles that are not documented or monitored.

**Version Note:** Azure RBAC cmdlets are consistent across current Az module versions, but environments with multiple tenants/subscriptions may require scoping via `-SubscriptionId` or `-Scope` parameters.

#### Linux/Bash / Azure CLI Reconnaissance
```bash
# Log in interactively or with a service principal
az login

# List all role assignments in the current subscription
az role assignment list --all --output table

# Focus on high-impact roles
az role assignment list --all \
  --role "Owner" \
  --output table

# List custom roles and their permissions
az role definition list --custom-role-only true --output jsonc
```

**What to Look For:**
- Principals with `Owner` or `User Access Administrator` at broad scopes.
- Custom roles where `actions` contain `*` or `Microsoft.Authorization/*`.
- External principals (B2B guests, CSP/Lighthouse principals) holding high‑privilege roles.

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1 – Abusing Over-Privileged RBAC via Azure Portal

**Supported Versions:** All current Entra ID / Azure portals.

#### Step 1: Enumerate Your Effective Roles
**Objective:** Determine whether the compromised identity (user or service principal) has hidden high‑privilege RBAC assignments.

**Command (Portal):**
- Sign in to the Azure portal with the compromised identity.
- Navigate to **Microsoft Entra ID → Roles and administrators → My roles**.
- Navigate to **Subscriptions → [Target Subscription] → Access control (IAM) → View my access**.

**Expected Output:**
- List of Entra directory roles and Azure RBAC roles (for example, Owner, Contributor, User Access Administrator) along with their scopes.

**What This Means:**
- Any role with management‑ or subscription‑level scope and broad permissions (especially Owner or User Access Administrator) indicates a strong privilege‑escalation vector.

**OpSec & Evasion:**
- Enumeration through portal is standard admin behavior but still logged in **Sign‑in logs** and **Audit Logs**.
- Use of compromised service principals via scripts may blend into automation noise.

#### Step 2: Elevate Privileges by Creating a Backdoor Principal
**Objective:** Use over‑privileged RBAC permissions to create a new, attacker‑controlled identity with persistent high privileges.

**Version Note:** Details differ slightly depending on whether the identity holds Owner, User Access Administrator, or a custom role.

**Portal Actions:**
1. Navigate to **Microsoft Entra ID → App registrations → New registration** and create a new application (backdoor service principal).
2. Navigate to **Subscriptions → [Target Subscription] → Access control (IAM) → Add → Add role assignment**.
3. Select a high‑privilege role such as **Contributor** or a tailored custom role that still allows sensitive operations (for stealth, avoid obvious roles like Global Administrator where possible).
4. Under **Members**, select the newly created application (service principal).
5. Assign the role at subscription or resource‑group scope.

**Expected Output:**
- New service principal visible under **Access control (IAM) → Role assignments** with the chosen role.

**What This Means:**
- The attacker now owns a separate principal that can perform privileged operations even if the original compromised user account is remediated.

**OpSec & Evasion:**
- Choose less conspicuous role names (for example, a custom role labeled as a business function) and narrower scopes to avoid manual reviews.
- Activity is fully logged in **AuditLogs** and **AzureActivity**, but many tenants lack specific analytics for new high‑privilege assignments.

#### Step 3: Perform High-Impact Actions
**Objective:** Use the newly created or discovered over‑privileged principal to perform impactful operations (data exfiltration, further escalation, or security control tampering).

**Example Operations (Portal):**
- Rotate or export secrets from **Key Vaults**, **App Registrations**, or **Service Principals**.
- Create additional role assignments to other attacker‑controlled identities.
- Modify or delete **Defender for Cloud**, **Sentinel**, or **Conditional Access** configurations if the role has necessary permissions.

**Expected Output:**
- Successful execution of sensitive operations (for example, secret access, new role assignments, policy changes).

**What This Means:**
- A single RBAC misconfiguration often enables full cloud compromise and long‑term persistence.

**Troubleshooting:**
- **Error:** Not authorized to create role assignments.
  - **Cause:** Role lacks `Microsoft.Authorization/roleAssignments/write`.
  - **Fix:** Search for other privileges (for example, the ability to create or modify automation that already runs as a more powerful identity) or chain this misconfig with others (for example, misconfigured managed identity).

### METHOD 2 – Enumerating and Abusing Over-Privileged RBAC via PowerShell / CLI

**Supported Versions:** All current Az PowerShell / Azure CLI releases.

#### Step 1: Enumerate High-Privilege Role Assignments
**Objective:** Programmatically enumerate all role assignments to quickly locate over‑privileged principals and broad scopes.

**PowerShell Command:**
```powershell
Connect-AzAccount

# List high-privilege role assignments (Owner, User Access Administrator, Contributor)
Get-AzRoleAssignment |
  Where-Object { $_.RoleDefinitionName -in @("Owner", "User Access Administrator", "Contributor") } |
  Select-Object RoleDefinitionName, Scope, DisplayName, SignInName, ObjectId
```

**Azure CLI Command:**
```bash
az login

# List all Owner role assignments in the subscription
az role assignment list --role "Owner" --output table
```

**Expected Output:**
- Tabular lists of principals and scopes for high‑privilege roles.

**What This Means:**
- Any unexpected user, group, guest, service principal, or managed identity in these lists is a candidate for abuse.

#### Step 2: Abuse Over-Privileged Role to Escalate
**Objective:** Use an identified over‑privileged assignment to grant additional access.

**PowerShell Command (example – create a new role assignment):**
```powershell
# Example: grant Contributor on a resource group to an attacker-controlled service principal
$spId = "<BackdoorServicePrincipalObjectId>"
$rgName = "<TargetResourceGroupName>"
New-AzRoleAssignment -ObjectId $spId -RoleDefinitionName "Contributor" -ResourceGroupName $rgName
```

**Azure CLI Command (equivalent):**
```bash
az role assignment create \
  --assignee-object-id <BackdoorServicePrincipalObjectId> \
  --role "Contributor" \
  --resource-group <TargetResourceGroupName>
```

**Expected Output:**
- Confirmation of a new role assignment.

**OpSec & Evasion:**
- Execute from trusted administration workstations or automation identities already used for operations to blend with normal activity.
- Avoid blatant role choices (for example, subscription‑level Owner) when stealth is more valuable than maximal rights.

## 6. TOOLS & COMMANDS REFERENCE

#### Azure PowerShell (Az module)

**Minimum Version:** Current Az module supported by the tenant (Az.Accounts / Az.Resources).
**Supported Platforms:** Windows, Linux, macOS.

**Installation (example):**
```powershell
# Install Az module (run as an administrator on the management host)
Install-Module -Name Az -Scope AllUsers -Repository PSGallery -Force

# Import the module
Import-Module Az

# Authenticate
Connect-AzAccount
```

**Usage – Role Assignment Enumeration (example):**
```powershell
# List all role assignments in the current subscription
Get-AzRoleAssignment |
  Select-Object RoleDefinitionName, Scope, DisplayName, SignInName, ObjectId
```

#### Azure CLI

**Supported Platforms:** Windows, Linux, macOS (shell / CI pipelines).

**Usage – Role Assignment Enumeration (example):**
```bash
# Log in interactively
az login

# List role assignments for a subscription
az role assignment list --all --output table
```

## 7. MICROSOFT SENTINEL DETECTION (RBAC CHANGE MONITORING)

#### Query 1: High-Privilege Role Assignment Changes
**Rule Configuration:**
- **Required Table:** `AuditLogs` (Entra ID / Azure AD logs) and/or `AzureActivity`.
- **Required Fields:** `OperationName`, `InitiatedBy`, `TargetResources`, `Result`, `Category` / `ActivityStatus`.
- **Alert Severity:** High.
- **Frequency:** Every 5 minutes (look back 1–24 hours depending on volume).
- **Applies To Versions:** All Entra ID / Azure tenants ingesting audit data into Log Analytics.

**KQL Query (example pattern):**
```kusto
AuditLogs
| where OperationName has_any ("Add member to role", "Add eligible member to role", "Add member to directory role")
| where Result =~ "success"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend Target = tostring(TargetResources[0].displayName)
| extend Role   = tostring(TargetResources[0].modifiedProperties[0].newValue)
| project TimeGenerated, OperationName, Actor, Target, Role, Result
```

**What This Detects:**
- Successful additions of members to Entra directory roles (including privileged roles) that can indirectly grant or manage RBAC permissions.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal → Microsoft Sentinel**.
2. Select the workspace → **Analytics**.
3. Click **+ Create → Scheduled query rule**.
4. On **General**, set:
   - Name: `High-Privilege Role Assignment Changes`.
   - Severity: `High`.
5. On **Set rule logic**:
   - Paste the KQL query above.
   - Run query every: `5 minutes`.
   - Lookup data from last: `1 hour`.
6. On **Incident settings**, enable **Create incidents**.
7. Configure **Automations** if available (for example, notify on-call, trigger playbook).
8. **Review + create** the rule.

## 8. MICROSOFT DEFENDER FOR CLOUD (IDENTITY & RBAC MISCONFIGS)

#### Detection Alerts (Conceptual)
**Example Alerts:**
- “Excessive number of subscription owners detected.”
- “High privileged directory roles assigned to regular users.”
- “Overly permissive custom role definitions.”

**Severity:** Typically High or Medium depending on product classification.
**Description:** Triggered when Defender for Cloud analytics detect:
- Many identities holding Owner or equivalent at subscription / management group scopes.
- Custom roles with broad wildcard permissions assigned to non‑admin accounts.
- Service principals, managed identities, or guests with unexpected high‑privilege roles.

**Manual Configuration Steps (Enable Defender for Cloud for Subscriptions):**
1. In **Azure Portal**, go to **Microsoft Defender for Cloud**.
2. Under **Environment settings**, select your subscription.
3. Under **Defender plans**, enable identity‑related and cloud resource plans as appropriate.
4. Save changes and allow time for assessments to populate.
5. Review **Recommendations** related to RBAC and privileged identities and track remediation status.

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Role and Policy Changes
**PowerShell Example:**
```powershell
# Connect to Exchange Online / Purview
Connect-ExchangeOnline

# Search recent admin role changes in the unified audit log
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) \
  -Operations "Add member to role","Add member to directory role" \
  -ResultSize 500
```

- **Operation:** Changes to directory roles and other admin roles surfaced in the unified audit log.
- **Workload:** AzureActiveDirectory / Microsoft Entra ID.
- **Details:** Review which actor performed the change, which principal was modified, and from which IP/device.

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to the **Microsoft Purview compliance portal**.
2. Go to **Audit**.
3. If needed, click **Turn on auditing** and wait for activation.

**Manual Steps (Search Role Changes):**
1. In **Audit**, open **Search**.
2. Set the **Date range** for investigation.
3. Under **Activities**, select operations related to role membership or directory role changes.
4. Run the search and export results for detailed offline analysis.

## 10. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL – Enforce Least Privilege RBAC Design
*   **Action 1: Remove Broad Owner/User Access Administrator Assignments.**
    **Applies To Versions:** All Entra ID / Azure tenants.
    
    **Manual Steps (Portal – Subscription Scope):**
    1. Go to **Azure Portal → Subscriptions → [Subscription] → Access control (IAM) → Role assignments**.
    2. Filter by role: **Owner** and **User Access Administrator**.
    3. For each non‑essential assignment (especially generic groups, guests, or automation identities), select **Remove**.
    4. Reassign more granular roles (for example, built‑in Reader, Contributor to specific resource groups, or job‑function roles) as appropriate.

*   **Action 2: Use Least-Privileged Built-In or Custom Roles by Task.**
    **Manual Steps (Portal – Entra Roles):**
    1. Go to **Microsoft Entra admin center → Roles and administrators**.
    2. For each administrative task, select the documented least‑privileged role (for example, User Administrator instead of Global Administrator).
    3. Where necessary, create custom roles exposing only specific API permissions required for the function.

#### Priority 2: HIGH – Implement PIM and Just-in-Time Administration
*   **Action: Convert Permanent High-Privilege Assignments to PIM Eligible Roles.**
    **Manual Steps:**
    1. Go to **Entra ID → Privileged Identity Management → Azure AD roles / Azure resources**.
    2. Identify accounts with permanent high‑privilege role assignments.
    3. Convert them to **eligible** assignments with:
       - Approval workflows.
       - Just‑in‑time activation.
       - Mandatory MFA and justification on activation.

#### Access Control & Policy Hardening
*   **Conditional Access:** Require MFA and device / location conditions for all privileged roles.
    **Manual Steps:**
    1. Go to **Entra ID → Security → Conditional Access**.
    2. Create a policy targeting **Privileged roles** or specific admin groups.
    3. Under **Grant**, choose to **Require multi-factor authentication** and other controls (for example, compliant device, hybrid‑joined device where applicable).

*   **RBAC/ABAC:**
    - Restrict RBAC scopes using **management groups**, **resource groups**, and where applicable **Administrative Units**.
    - Avoid assigning roles directly to users; instead, assign to well‑managed groups.

#### Validation Command (Verify Fix)
```powershell
# Confirm there are no unexpected Owner or User Access Administrator assignments
Get-AzRoleAssignment |
  Where-Object { $_.RoleDefinitionName -in @("Owner", "User Access Administrator") } |
  Select-Object RoleDefinitionName, Scope, DisplayName, SignInName
```

**What to Look For:**
- Only formally approved admin groups or break‑glass accounts should appear.
- No guest, CSP, or generic user groups should hold wide‑scope high‑privilege roles.

## 11. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)
*   **Identities:** New or unexpected accounts (users, guests, service principals) assigned Owner, User Access Administrator, or powerful custom roles.
*   **Configuration:** Sudden increase in custom roles or changes to role definitions to include wildcard permissions.
*   **Activity Patterns:** Bursts of role assignment changes, especially followed by resource deletions, key access, or policy modifications.

#### Forensic Artifacts
*   **Cloud Logs:**
    - Microsoft Entra **Audit Logs** – role membership changes, app registrations, PIM activation.
    - **Azure Activity Log** – RBAC changes at subscription/resource scopes.
    - **Sentinel** incidents created from RBAC analytics.
*   **M365 Unified Audit Log:** Admin role changes, directory role membership modifications where unified logging is enabled.

#### Response Procedures
1.  **Contain:**
    - Temporarily disable or block sign‑in for suspected compromised accounts (if feasible).
    - Remove or downgrade suspicious high‑privilege role assignments.

2.  **Collect Evidence:**
    - Export Entra **Audit Logs** and **Azure Activity Logs** for the affected period.
    - Capture Sentinel incidents and related entities (accounts, IPs, service principals).

3.  **Remediate:**
    - Rebuild RBAC following least‑privilege patterns.
    - Remove unneeded custom roles or reduce their permissions.
    - Migrate permanent high‑privilege assignments to PIM.

4.  **Post-Incident Hardening:**
    - Implement continuous RBAC monitoring (Sentinel analytics, Defender for Cloud recommendations).
    - Introduce periodic access reviews for privileged groups and roles.

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | Valid Accounts (T1078) | Attacker obtains credentials for a standard user, guest, or service principal (for example, via phishing or credential stuffing). |
| **2** | **Discovery** | Cloud Resource Enumeration | Attacker enumerates role assignments, subscriptions, and resource groups to locate misconfigured RBAC. |
| **3** | **Current Step** | **[MISCONFIG-001] Overly Permissive RBAC** | Over‑privileged assignments at broad scopes enable immediate high‑impact operations. |
| **4** | **Persistence / Privilege Escalation** | Account Manipulation (T1098) | Attacker creates new privileged principals or grants permanent roles to attacker‑controlled identities. |
| **5** | **Impact / Exfiltration** | Data Destruction (T1485), Exfiltration over Web Services (T1567) | Attacker deletes resources, steals data, or disables security controls using elevated privileges. |

## 13. REAL-WORLD EXAMPLES

#### Example 1: Over-Privileged Built-in Roles and VPN Key Exposure
- **Target:** Large enterprise using Azure with multiple subscriptions and hub‑and‑spoke networking.
- **Timeline:** Public research in 2025 highlighted that certain Azure built‑in roles were over‑privileged and allowed access to VPN keys and configuration.
- **Technique Status:** Misconfigured roles were not fully deprecated; organizations were advised to avoid them or replace them with custom least‑privilege definitions.
- **Impact:** Any identity holding these roles at subscription scope could extract VPN keys and potentially pivot into on‑premises networks.

#### Example 2: Guest and CSP Accounts with Tenant-Wide Owner Rights
- **Target:** Multi‑tenant environment using Microsoft Entra B2B and Cloud Solution Provider (CSP) relationships.
- **Timeline:** Multiple incident reports across 2023–2025.
- **Technique Status:** ACTIVE – still commonly observed in assessments and red‑team engagements.
- **Impact:** Compromise of a single guest or CSP admin account with subscription‑level Owner or User Access Administrator enabled:
  - Creation of new global admins and privileged service principals.
  - Modification of Conditional Access and Defender policies.
  - Rapid full‑tenant compromise with limited visibility until logs were thoroughly reviewed.

---