# REC-CERT-001: ADCS Enumeration via Certify

**SERVTEP ID:** REC-CERT-001  
**Technique Name:** ADCS enumeration via Certify  
**MITRE ATT&CK Mapping:** T1087.002 (Account Discovery - Domain Account)  
**CVE Reference:** N/A  
**Environment:** Windows Active Directory  
**Severity:** Critical  
**Difficulty:** Medium  

---

## Executive Summary

Active Directory Certificate Services (ADCS) is a critical but often misconfigured component of Windows domains. The Certify tool enumerates ADCS infrastructure, certificate templates, and privilege escalation paths. Vulnerable ADCS configurations enable attackers to enroll for certificates impersonating domain accounts, service accounts, or even domain controllers. This reconnaissance technique identifies ADCS exploitation opportunities that lead to full domain compromise.

---

## Objective

Comprehensively enumerate ADCS to:
- Discover certificate authorities and their locations
- Identify vulnerable certificate templates
- Find templates allowing authentication (Domain Controller, admin impersonation)
- Enumerate enrollment permissions and who can request certificates
- Identify templates with overly permissive Subject Alternative Name (SAN)
- Discover certificate renewal and revocation configurations
- Map ADCS to enrollment servers and distribution points
- Identify weak cryptography configurations (MD5, RC4)

---

## Prerequisites

- Network access to Active Directory Certificate Services
- Certify tool (from Certify GitHub repository)
- PowerShell 5.0+
- Windows domain user credentials (optional for some enumeration)
- LDAP connectivity to domain controller (port 389)

---

## Execution Procedures

### Method 1: Certify Tool Installation and Basic Enumeration

**Step 1:** Download and execute Certify
```bash
# Clone Certify repository
git clone https://github.com/ly4k/Certify
cd Certify

# Compile Certify (requires Visual Studio)
msbuild Certify.sln /p:Configuration=Release

# Or download pre-compiled binary
# Usage
.\Certify.exe find /vulnerable
```

**Step 2:** Discover certificate authorities
```bash
# List all CAs in domain
.\Certify.exe find

# Example output:
# Found 2 Certificate Authority(ies):
#   DC01.example.com - example-DC01-CA
#   CA01.example.com - example-CA-01
```

**Step 3:** Enumerate certificate templates
```bash
# List all certificate templates
.\Certify.exe cas

# Get detailed template information
.\Certify.exe template /name:"Web Server"

# List templates by enrollment permissions
.\Certify.exe templates /enrollmentperm
```

### Method 2: Vulnerability Detection in Certificate Templates

**Step 1:** Find vulnerable certificate templates
```bash
# Scan for exploitable templates (ESC1-ESC11 vulnerabilities)
.\Certify.exe find /vulnerable

# Output shows:
# [!] Vulnerable Certificates Template(s) Found!
#   Template Name: "User"
#   Vulnerability: ESC1 - Allows client authentication and overly permissive enrollment
```

**Step 2:** Analyze specific vulnerabilities
```bash
# ESC1: Allows requesting certificate with impersonated SAN
.\Certify.exe find /vulnerable /useronly

# ESC2: Certificate chain validation weakness
.\Certify.exe find /vulnerable /template:"Domain Controller"

# ESC3: Overly permissive CA access
.\Certify.exe find /vulnerable /clientauth

# ESC4: Overly permissive template permissions
.\Certify.exe find /enrollmentperm
```

### Method 3: PowerShell ADCS Enumeration

**Step 1:** Enumerate certificate services via PowerShell
```powershell
# Get all Certificate Authorities
Get-ADObject -Filter "objectClass -eq 'pKIEnrollmentService'" -Properties "*" | 
  Select-Object Name, distinguishedName

# Enumerate LDAP for ADCS configuration
$ldapFilter = "(&(objectClass=pKICertificateTemplate))"
$ldapSearch = New-Object System.DirectoryServices.DirectorySearcher
$ldapSearch.Filter = $ldapFilter

$templates = $ldapSearch.FindAll()
Write-Host "Found $($templates.Count) certificate templates"

foreach ($template in $templates) {
  $props = $template.Properties
  Write-Host "Template: $($props['name'][0])"
  Write-Host "  Display Name: $($props['displayName'][0])"
  Write-Host "  Enhanced Key Usage: $($props['pKIExtendedKeyUsage'])"
}
```

**Step 2:** Analyze template permissions
```powershell
# Get template permissions (who can enroll)
$templates | ForEach-Object {
  $templateName = $_.Properties['name'][0]
  $sd = $_.Properties['ntsecuritydescriptor'][0]
  
  Write-Host "Template: $templateName"
  Write-Host "  Permissions:"
  
  # Parse security descriptor
  $acl = [System.DirectoryServices.ActiveDirectoryAccessRule[]]($sd.Access)
  $acl | ForEach-Object {Write-Host "    - $($_.IdentityReference)"}
}
```

**Step 3:** Identify dangerous template properties
```powershell
# Find templates allowing client authentication
$templates | Where-Object {
  $_.Properties['pKIExtendedKeyUsage'] -contains "1.3.6.1.5.5.7.3.2"  # Client auth OID
} | Select-Object @{N='Name';E={$_.Properties['name'][0]}}, 
  @{N='EnhancedKeyUsage';E={$_.Properties['pKIExtendedKeyUsage']}}

# Find templates with overly permissive SAN (ESC1)
$templates | Where-Object {
  $_.Properties['msPKI-Certificate-Name-Flag'] -eq 1  # Supports SAN
} | Select-Object @{N='Name';E={$_.Properties['name'][0]}}

# Find templates allowing domain controller enrollment
$templates | Where-Object {
  $_.Properties['pKIExtendedKeyUsage'] -contains "1.3.6.1.4.1.311.20.2"  # Domain Controller auth
}
```

### Method 4: ADCS Web Interface Enumeration

**Step 1:** Discover ADCS web interfaces
```bash
# Find Certificate Services web enrollment interfaces
nmap -p 443 --script ssl-cert <ca-server>

# Query directly if accessible
curl -k https://<ca-server>/certsrv

# Check for publicly accessible ADCS
# Common URLs:
# https://ca01.example.com/certsrv
# https://pki.example.com/certsrv
```

**Step 2:** Enumerate templates via web interface
```bash
# Templates are often listed in HTML response
curl -k https://<ca-server>/certsrv/certfnsh.asp | grep -i "certificate" | head -20

# Look for POST parameters revealing template names
curl -k https://<ca-server>/certsrv/certrqxt.asp | grep "TemplateName"
```

### Method 5: Advanced ADCS Exploitation Path Analysis

**Step 1:** Map privilege escalation via ADCS
```bash
# Find Domain Controller templates
.\Certify.exe find /template:"Domain Controller" /vulnerable

# If DC template is enrollable -> can create DC certificate -> DCSync

# Find Domain Admin enrollment templates
.\Certify.exe find /enrollmentperm /clientauth | grep -i "admin"

# If Domain Admin template is enrollable -> can impersonate admin -> DA compromise
```

**Step 2:** Identify certificate chain validation weaknesses
```bash
# Get CA certificate chain
.\Certify.exe cas /verbose

# Check for weak root CA certificates (MD5, SHA1)
# Weak roots = potential for certificate forgery

# Get enrollment servers (may have different permissions than CA)
.\Certify.exe find /enrollmentservers
```

### Method 6: Comprehensive ADCS Audit

**Step 1:** Full enumeration and risk assessment
```powershell
# Comprehensive ADCS audit script
$auditResults = @{
  "CertificateAuthorities" = @()
  "VulnerableTemplates" = @()
  "HighRiskConfigurations" = @()
}

# Get all CAs
$cas = Get-ADObject -Filter "objectClass -eq 'pKIEnrollmentService'" -Properties "*"

$cas | ForEach-Object {
  $auditResults["CertificateAuthorities"] += [PSCustomObject]@{
    Name = $_.Name
    Location = $_.DistinguishedName
    Version = $_.Properties['operatingSystemVersion']
  }
}

# Get templates and check for vulnerabilities
Get-ADObject -Filter "objectClass -eq 'pKICertificateTemplate'" -Properties "*" |
  ForEach-Object {
    $template = $_
    
    # Check for ESC vulnerabilities
    if ($template.Properties['msPKI-Certificate-Name-Flag'] -eq 1) {
      $auditResults["VulnerableTemplates"] += [PSCustomObject]@{
        Name = $template.Properties['name'][0]
        Vulnerability = "ESC1 - Overly Permissive SAN"
        RiskLevel = "Critical"
      }
    }
  }

# Export audit results
$auditResults | ConvertTo-Json -Depth 5 | Out-File adcs_audit.json
```

---

## Technical Deep Dive

### Common ADCS Vulnerabilities (ESC-series)

| Vulnerability | Type | Exploitation |
|---|---|---|
| ESC1 | Template misconfiguration | Enroll for admin/DC certificate |
| ESC2 | Intermediate CA misconfiguration | CA-signed certificate forgery |
| ESC3 | Registration authority misconfiguration | Bypass template restrictions |
| ESC4 | Overly permissive ACLs | Modify template, enable privilege escalation |
| ESC8 | NTLM relay to ADCS | Force authentication to ADCS, intercept |
| ESC11 | Filters improperly evaluated | Bypass template restrictions |

### Certificate Template Dangerous Properties

| Property | Risk | Exploitation |
|---|---|---|
| Client Authentication OID | High | Can authenticate as anyone |
| Domain Controller OID | Critical | Can impersonate DC → DCSync |
| Overly Permissive SAN | High | Can enroll for other identities |
| Allow Administrator Access | Critical | Can modify template settings |
| Publish to AD | Medium | Template availability to attackers |

---

## Detection Strategies (Blue Team)

### ADCS Activity Monitoring

1. **Certificate Enrollment Auditing**
   - Event ID 4887: Certificate Services received certificate request
   - Event ID 4888: Certificate Services approved certificate request
   - Alert on unusual template requests (DC templates, admin templates)

2. **Certify Tool Detection**
   - Monitor for Certify.exe execution
   - Alert on ADCS enumeration queries
   - Track Lightweight Directory Access Protocol (LDAP) queries to certificate templates

3. **Azure AD Activity Logging**
   ```kusto
   AuditLogs
   | where ActivityDisplayName contains "Certificate"
   | summarize by InitiatedBy, ActivityDisplayName, bin(TimeGenerated, 1h)
   ```

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Stealthy Enumeration**
   - Use PowerShell (less suspicious than specialized tools)
   - Query templates during normal hours
   - Avoid tools with known signatures (Certify)

2. **Certificate Enrollment Stealth**
   - Request certificates from legitimate-appearing templates
   - Avoid Domain Controller templates if possible
   - Use enrolled certificates sparingly

### Defensive Measures

1. **ADCS Hardening**
   - Disable vulnerable templates
   - Restrict enrollment permissions
   - Require manager approval for sensitive templates
   - Disable unused ADCS web interfaces

2. **Monitoring**
   - Enable Certificate Services logging
   - Alert on unusual template requests
   - Monitor for Certify and similar enumeration tools

---

## Mitigation Strategies

1. **Immediate Actions**
   - Audit certificate templates for ESC vulnerabilities
   - Disable Domain Controller and Admin templates
   - Review and restrict enrollment permissions

2. **Detection & Response**
   - Enable ADCS event logging
   - Monitor for abnormal certificate requests
   - Alert on template modification attempts

3. **Long-term Security**
   - Implement certificate template hardening
   - Regular ADCS security audits
   - Use managed identities instead of certificate-based auth
   - Enforce strong cryptography (disable MD5, SHA1)

---

## References & Further Reading

- [Certify GitHub Repository](https://github.com/ly4k/Certify)
- [Specterops - Certified Pre-Owned ADCS Attacks](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [ADCS Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview)
- [MITRE ATT&CK Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1548/)

---

## Related SERVTEP Techniques

- **PE-ELEVATE-001**: AD CS Certificate Services Abuse
- **PE-ELEVATE-002**: Alternative Subject Alternative Names (SANs)
- **PE-EXPLOIT-001**: PrintNightmare (often combined with ADCS)

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| ADCS discovery | 1-2 minutes | Easy |
| Template enumeration | 2-5 minutes | Easy |
| Vulnerability analysis | 5-10 minutes | Medium |
| Full audit | 15-30 minutes | Medium |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
