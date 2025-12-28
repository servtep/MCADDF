# REC-CLOUD-006: Azure Service Principal Enumeration

**SERVTEP ID:** REC-CLOUD-006  
**Technique Name:** Azure service principal enumeration  
**MITRE ATT&CK Mapping:** T1087.004 (Account Discovery - Cloud Account)  
**CVE Reference:** N/A  
**Environment:** Entra ID  
**Severity:** Critical  
**Difficulty:** Easy  

---

## Executive Summary

Service principals in Entra ID represent applications and services with access to Azure and Microsoft 365 resources. Attackers enumerate service principals to identify privileged accounts, overly-permissioned applications, and potential lateral movement paths. Unlike regular user accounts, service principals often have elevated permissions, persistence mechanisms, and weak credential management. Service principal enumeration is critical for privilege escalation and persistence planning.

---

## Objective

Comprehensively enumerate service principals to:
- Discover all registered applications and service principals
- Identify service principals with Directory.ReadWrite.All or similar admin scopes
- Map service principal role assignments and resource access
- Find service principals with certificate credentials (persistent access)
- Identify overly-permissioned service principals
- Discover managed identities and their assignments
- Map OAuth consent grants to service principals
- Identify service principal owners (potential modification paths)

---

## Prerequisites

- Entra ID credentials (any user can enumerate service principals)
- Azure CLI or PowerShell with Az.Accounts module
- Graph API access (delegated or application permissions)
- Optional: Service principal with Application.Read.All permissions

---

## Execution Procedures

### Method 1: PowerShell Service Principal Enumeration

**Step 1:** Basic service principal discovery
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.Read.All"

# Get all service principals
$servicePrincipals = Get-MgServicePrincipal -All -Property "id,displayName,appId,servicePrincipalType"

# Export all service principals
$servicePrincipals | Export-Csv service_principals.csv -NoTypeInformation

# Count by type
$servicePrincipals | Group-Object servicePrincipalType | 
  ForEach-Object {Write-Host "$($_.Name): $($_.Count) principals"}
```

**Step 2:** Identify privileged service principals
```powershell
# Get service principals with Directory.ReadWrite.All permission
$dangerousSPs = @()

$servicePrincipals | ForEach-Object {
  $spId = $_.id
  
  # Get role assignments
  $roleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId
  
  # Check for dangerous roles (Directory admin, Global admin equivalent)
  $roleAssignments | ForEach-Object {
    if ($_.appRoleId -eq "19dbc75e-c2d2-464f-a147-3ba239039ba2") {  # Directory.ReadWrite.All
      $dangerousSPs += [PSCustomObject]@{
        Name = $_.displayName
        AppId = $_.appId
        RoleId = $_.appRoleId
      }
    }
  }
}

# Export dangerous service principals
$dangerousSPs | Export-Csv dangerous_sps.csv
```

**Step 3:** Find service principals with certificate credentials
```powershell
# Get service principals with key credentials (certificates)
$servicePrincipals | Where-Object {$_.keyCredentials -ne $null} |
  Select-Object displayName, appId | 
  Export-Csv sps_with_certs.csv

# Detailed certificate enumeration
$servicePrincipals | ForEach-Object {
  $sp = $_
  if ($sp.keyCredentials) {
    Write-Host "Service Principal: $($sp.displayName)"
    $sp.keyCredentials | ForEach-Object {
      Write-Host "  Certificate: $($_.displayName)"
      Write-Host "    Key Usage: $($_.keyUsage)"
      Write-Host "    Start Date: $($_.startDateTime)"
      Write-Host "    End Date: $($_.endDateTime)"
    }
  }
}
```

**Step 4:** Enumerate managed identities
```powershell
# Get system-assigned managed identities (via VMs/App Services)
Get-MgVirtualMachine -All | Where-Object {$_.identity.type -contains "SystemAssigned"} |
  ForEach-Object {
    Write-Host "VM with managed identity: $($_.displayName)"
    Write-Host "  Principal ID: $($_.identity.principalId)"
  }

# Get user-assigned managed identities
$managedIdentities = Get-MgServicePrincipal -Filter "servicePrincipalType eq 'ManagedIdentity'" -All

$managedIdentities | Select-Object displayName, appId | 
  Export-Csv managed_identities.csv
```

### Method 2: Graph API Service Principal Queries

**Step 1:** Advanced filtering for privileged service principals
```powershell
# Find service principals with app roles assigned (likely privileged)
$servicePrincipals | ForEach-Object {
  $spId = $_.id
  $roleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId
  
  if ($roleAssignments.count -gt 0) {
    Write-Host "$($_.displayName): $($roleAssignments.count) roles"
    $roleAssignments | ForEach-Object {
      Write-Host "  Role ID: $($_.appRoleId)"
    }
  }
}

# Find service principals created recently (potential backdoors)
$cutoffDate = (Get-Date).AddDays(-30)
$recentSPs = Get-MgServicePrincipal -Filter "createdDateTime gt $cutoffDate" -All

Write-Host "Service Principals created in last 30 days: $($recentSPs.count)"
```

**Step 2:** Service principal owner enumeration
```powershell
# Get owners of service principals (who can modify permissions/credentials)
$servicePrincipals | ForEach-Object {
  $spId = $_.id
  $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $spId
  
  if ($owners.count -gt 0) {
    Write-Host "Service Principal: $($_.displayName)"
    $owners | ForEach-Object {Write-Host "  Owner: $($_.displayName)"}
  }
}
```

### Method 3: Azure CLI Service Principal Enumeration

**Step 1:** List and analyze service principals
```bash
# Get all service principals in Azure AD
az ad sp list --output table

# Get detailed service principal information
az ad sp list --query "[].{Name:displayName, AppID:appId, Type:servicePrincipalType}" -o table

# Find service principals with dangerous permissions
az ad sp list --query "[?contains(oauth2Permissions, 'admin')].{Name:displayName, Permissions:oauth2Permissions}"
```

**Step 2:** Service principal permission analysis
```bash
# Get OAuth2 permissions for service principal
az ad sp show --id <service-principal-id> --query "oauth2Permissions"

# Get all role assignments for service principal
az role assignment list --assignee <principal-id> --output table
```

### Method 4: Comprehensive Service Principal Audit

**Step 1:** Full enumeration with classification
```powershell
# Comprehensive service principal inventory
$inventory = @()

Get-MgServicePrincipal -All | ForEach-Object {
  $sp = $_
  $spId = $_.id
  
  # Get role assignments
  $roles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId
  
  # Get owners
  $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $spId
  
  # Get credentials
  $hasPassword = $sp.passwordCredentials.count -gt 0
  $hasCert = $sp.keyCredentials.count -gt 0
  
  # Risk classification
  $risk = if ($roles.count -gt 5) {"High"} else {"Medium"}
  
  $inventory += [PSCustomObject]@{
    Name = $sp.displayName
    AppId = $sp.appId
    Type = $sp.servicePrincipalType
    RoleCount = $roles.count
    OwnerCount = $owners.count
    HasPassword = $hasPassword
    HasCertificate = $hasCert
    RiskLevel = $risk
  }
}

# Export comprehensive inventory
$inventory | Export-Csv service_principal_inventory.csv -NoTypeInformation

# Sort by risk
$inventory | Where-Object {$_.RiskLevel -eq "High"} | 
  Select-Object Name, AppId, RoleCount | 
  Export-Csv high_risk_sps.csv
```

**Step 2:** Identify overly-permissioned service principals
```powershell
# Service principals with Directory-wide admin roles
$adminSPs = @()

$servicePrincipals | ForEach-Object {
  $spId = $_.id
  $roles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId
  
  # Check for admin role IDs
  $adminRoles = @(
    "62e90394-69f5-4237-9190-012177145e10",  # Directory.ReadWrite.All
    "19dbc75e-c2d2-464f-a147-3ba239039ba2",  # Directory.Read.All (but still admin)
    "9e3f62cf-ca93-4989-b6ce-5f6e88d0a312"   # AppRoleAssignment.ReadWrite.All
  )
  
  $roles | Where-Object {$_.appRoleId -in $adminRoles} | 
    ForEach-Object {
      $adminSPs += [PSCustomObject]@{
        Name = $_.displayName
        AppId = $_.appId
        AdminRole = $_.appRoleId
      }
    }
}

Write-Host "Service Principals with admin roles: $($adminSPs.count)"
$adminSPs | Export-Csv admin_service_principals.csv
```

### Method 5: Service Principal Lateral Movement Discovery

**Step 1:** Identify service principals that can be impersonated
```powershell
# Find service principals that user has permissions to modify
$userPerms = Get-MgContext

$servicePrincipals | ForEach-Object {
  $spId = $_.id
  
  # Check if current user can modify this SP (Get-MgServicePrincipal ownership)
  $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $spId
  
  $isOwner = $owners | Where-Object {$_.id -eq $userPerms.Account.ObjectId}
  
  if ($isOwner) {
    Write-Host "[MODIFIABLE] Service Principal: $($_.displayName)"
  }
}
```

**Step 2:** Find service principals with cross-subscription access
```powershell
# Service principals with Azure subscription access
$servicePrincipals | ForEach-Object {
  $spId = $_.id
  $roles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId
  
  # Check for Azure management roles
  $roles | Where-Object {$_.resourceDisplayName -eq "Azure Service Management API"} |
    ForEach-Object {Write-Host "$($_.displayName) has Azure management access"}
}
```

---

## Technical Deep Dive

### Service Principal Types

| Type | Purpose | Risk |
|------|---------|------|
| Application | Registered app with Azure access | High |
| ManagedIdentity | VM/App Service identity | Medium |
| Legacy | Legacy service accounts | Low |
| SocialIdp | Social identity provider | Low |

### Dangerous Roles for Service Principals

| Role | ID | Impact |
|------|----|----|
| Directory.ReadWrite.All | 19dbc75e... | Full AD modification |
| Mail.ReadWrite.All | 024d8b74... | All mailbox access |
| Files.ReadWrite.All | dfabfca6... | All file access |
| AppRoleAssignment.ReadWrite.All | 9e3f62cf... | Privilege escalation |

---

## Detection Strategies (Blue Team)

### Service Principal Monitoring

1. **Suspicious Creation**
   - Alert on new service principal creation
   - Monitor for rapid role assignment
   - Track certificate/secret creation

2. **Privilege Escalation Indicators**
   - Service principal gaining admin roles
   - Sudden permission scope increases
   - Unexpected role assignment patterns

3. **Azure Activity Logging**
   ```kusto
   AuditLogs
   | where ActivityDisplayName contains "Update service principal"
   | summarize by UserPrincipalName, ActivityDisplayName, bin(TimeGenerated, 1h)
   ```

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Stealthy Enumeration**
   - Use delegated permissions (less suspicious)
   - Avoid Application.ReadWrite.All scope
   - Query during normal business hours

2. **Service Principal Abuse**
   - Create new SP with minimal logging
   - Assign roles during high-activity periods
   - Use legitimate automation SP names

### Defensive Measures

1. **Access Controls**
   - Limit who can enumerate service principals
   - Restrict Application.Read.All permissions
   - Require approval for new applications

2. **Monitoring**
   - Alert on Application.Read.All scope requests
   - Monitor service principal role changes
   - Track new certificate credentials

---

## Mitigation Strategies

1. **Immediate Actions**
   - Audit service principals with Directory admin roles
   - Review certificate-based service principals
   - Disable unused service principals

2. **Detection & Response**
   - Enable audit logging for service principal changes
   - Alert on high-privilege role assignments
   - Monitor certificate credential creation

3. **Long-term Security**
   - Implement workload identity federation
   - Use managed identities instead of SPNs
   - Regular service principal access reviews
   - Limit Application.ReadWrite.All permissions

---

## References & Further Reading

- [Service Principal Object in Azure AD](https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
- [Application Permissions Reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Azure AD Role IDs](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference)

---

## Related SERVTEP Techniques

- **REC-CLOUD-001**: BloodHound (privilege analysis)
- **REC-CLOUD-004**: AADInternals (service principal enumeration)
- **PE-ACCTMGMT-001**: App Registration Privileges Escalation
- **PE-VALID-011**: Managed Identity MSI Escalation

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| Basic enumeration | 1-2 minutes | Easy |
| Privilege discovery | 2-5 minutes | Easy |
| Certificate analysis | 3-5 minutes | Medium |
| Full audit | 10-20 minutes | Medium |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
