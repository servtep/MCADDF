# REC-M365-001: Microsoft Graph API Enumeration

**SERVTEP ID:** REC-M365-001  
**Technique Name:** Microsoft Graph API enumeration  
**MITRE ATT&CK Mapping:** T1087.004 (Account Discovery - Cloud Account)  
**CVE Reference:** N/A  
**Environment:** Microsoft 365  
**Severity:** Critical  
**Difficulty:** Medium  

---

## Executive Summary

Microsoft Graph API is the primary interface for accessing data across Microsoft 365 services (Exchange, Teams, SharePoint, OneDrive). Attackers enumerate the Graph API to discover users, groups, applications, team structures, and mailbox configurations. Unlike PowerShell or Azure CLI, Graph API queries are difficult to distinguish from legitimate application activity, making them ideal for stealthy reconnaissance. With appropriate permissions (delegated or application), attackers can map entire M365 environments, identify privileged accounts, and discover sensitive data locations.

---

## Objective

Comprehensively enumerate Microsoft 365 infrastructure via Graph API to:
- Discover all users, groups, and distribution lists
- Map Teams and channels structure
- Enumerate SharePoint sites and document libraries
- Identify mailbox permissions and delegates
- Find application permissions and consent grants
- Discover Azure AD joined devices
- Map organizational hierarchy and reporting relationships
- Identify service accounts and app registrations with sensitive permissions

---

## Prerequisites

- Microsoft 365 subscription with user or application account
- Graph API permissions (delegated or application scopes)
- Python with requests library OR PowerShell with Microsoft.Graph module
- OAuth 2.0 or credential-based authentication
- Internet connectivity to graph.microsoft.com

---

## Execution Procedures

### Method 1: PowerShell Microsoft.Graph Module

**Step 1:** Install and authenticate
```powershell
# Install Microsoft.Graph module
Install-Module -Name Microsoft.Graph -Force

# Import modules for specific workloads
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Mail
Import-Module Microsoft.Graph.Teams

# Authenticate to Microsoft Graph
Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All", "Mail.Read"

# Verify authentication
Get-MgContext
```

**Step 2:** Enumerate all users
```powershell
# Get all users in tenant
$users = Get-MgUser -All -Property "id,displayName,mail,userPrincipalName,accountEnabled,userType"

# Export users to CSV
$users | Select-Object displayName, mail, userPrincipalName, accountEnabled, userType | 
  Export-Csv m365_users.csv -NoTypeInformation

# Find external users (B2B)
$externalUsers = $users | Where-Object {$_.userType -eq "Guest"}
Write-Host "External Users: $($externalUsers.count)"

# Find service accounts
$serviceAccounts = $users | Where-Object {$_.displayName -like "*service*" -or $_.displayName -like "*svc*"}
```

**Step 3:** Enumerate groups and memberships
```powershell
# Get all groups
$groups = Get-MgGroup -All -Property "id,displayName,mail,groupTypes,securityEnabled"

# Get group members for sensitive groups
$domainAdmins = Get-MgGroup -Filter "displayName eq 'Domain Admins'" -Property "id" | 
  ForEach-Object { Get-MgGroupMember -GroupId $_.id }

# Map group hierarchy (nested groups)
function Get-GroupMembers-Recursive {
  param($groupId, $depth = 0)
  
  $members = Get-MgGroupMember -GroupId $groupId
  foreach ($member in $members) {
    Write-Host ("  " * $depth) + $member.DisplayName
    
    # If member is a group, recurse
    if ($member.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.group") {
      Get-GroupMembers-Recursive -groupId $member.id -depth ($depth + 1)
    }
  }
}

# Get all distribution lists
$distributionLists = Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')" -All
```

**Step 4:** Enumerate applications and service principals
```powershell
# Get all service principals
$servicePrincipals = Get-MgServicePrincipal -All -Property "id,displayName,appId,servicePrincipalType"

# Find service principals with Directory.ReadWrite.All permission
$dangerousSPs = $servicePrincipals | Where-Object {
  $spId = $_.id
  $appRoles = Get-MgServicePrincipal -ServicePrincipalId $spId -ExpandProperty appRoleAssignments
  $appRoles.appRoleAssignments | Where-Object {$_.appRoleId -eq "19dbc75e-c2d2-464f-a147-3ba239039ba2"}
}

# Export service principals to CSV
$servicePrincipals | Select-Object displayName, appId, servicePrincipalType | 
  Export-Csv service_principals.csv
```

### Method 2: Python-Based Graph API Enumeration

**Step 1:** Install required libraries and authenticate
```bash
# Install Microsoft Graph SDK
pip install msgraph-core azure-identity

# Set up authentication
export TENANT_ID="your-tenant-id"
export CLIENT_ID="your-app-id"
export CLIENT_SECRET="your-client-secret"
```

**Step 2:** User and group enumeration script
```python
from azure.identity import ClientCredentialFlow
from msgraph.core import GraphClient

# Authenticate
credentials = ClientCredentialFlow(
    client_id="client-id",
    client_secret="client-secret",
    tenant_id="tenant-id"
)

client = GraphClient(credential=credentials)

# Get all users
users_response = client.get("/users?$select=id,displayName,mail,userPrincipalName")
users = users_response.json()['value']

print(f"Total users: {len(users)}")
for user in users:
    print(f"  - {user['displayName']} ({user['mail']})")

# Export to JSON
import json
with open('m365_users.json', 'w') as f:
    json.dump(users, f, indent=2)

# Get all groups
groups_response = client.get("/groups?$select=id,displayName,mail,groupTypes")
groups = groups_response.json()['value']

print(f"\nTotal groups: {len(groups)}")

# Get members for each group
for group in groups:
    members_response = client.get(f"/groups/{group['id']}/members")
    members = members_response.json()['value']
    print(f"  {group['displayName']}: {len(members)} members")
```

**Step 3:** Mailbox and Teams enumeration
```python
# Get all mailboxes (requires Mail.Read scope)
mailboxes_response = client.get("/me/mailFolders?$select=id,displayName")
mailboxes = mailboxes_response.json()['value']

# Get all Teams
teams_response = client.get("/teams?$select=id,displayName,isArchived")
teams = teams_response.json()['value']

print(f"Teams in tenant: {len(teams)}")

# Get channels for each team
for team in teams:
    channels_response = client.get(f"/teams/{team['id']}/channels")
    channels = channels_response.json()['value']
    print(f"  {team['displayName']}: {len(channels)} channels")

# Get members of each team
for team in teams:
    members_response = client.get(f"/teams/{team['id']}/members")
    members = members_response.json()['value']
    print(f"    Members: {len(members)}")
```

### Method 3: Graph Explorer (GUI-Based Enumeration)

**Step 1:** Access Graph Explorer
```
1. Navigate to https://developer.microsoft.com/en-us/graph/graph-explorer
2. Sign in with M365 credentials
3. Grant required permissions
```

**Step 2:** Run enumeration queries
```
Common Graph API endpoints for reconnaissance:

# Get all users
GET /users?$select=id,displayName,mail,userPrincipalName,accountEnabled

# Get all groups
GET /groups?$select=id,displayName,mail,groupTypes,securityEnabled

# Get service principals
GET /servicePrincipals?$select=id,displayName,appId,appDisplayName

# Get all teams
GET /teams?$select=id,displayName,isArchived

# Get devices
GET /devices?$select=id,displayName,deviceVersion,isCompliant

# Get applications
GET /applications?$select=id,appId,displayName,requiredResourceAccess
```

### Method 4: Advanced Graph Queries with Filtering

**Step 1:** Targeted user enumeration
```powershell
# Find admin accounts
Get-MgUser -Filter "assignedLicenses/any(c:true)" -All | 
  Where-Object {Get-MgUserMemberOf -UserId $_.id | 
    Where-Object {$_.displayName -like "*admin*"}}

# Find accounts with no activity (potential service accounts)
Get-MgUser -Filter "signInActivity/lastSignInDateTime lt 2024-01-01" -All

# Find external accounts
Get-MgUser -Filter "mail eq null" -All

# Find users with specific email domains
Get-MgUser -Filter "mail endswith '@guest.example.com'" -All
```

**Step 2:** Application permission discovery
```powershell
# Get OAuth2 permission grants (consent grants)
$grants = Get-MgOauth2PermissionGrant -All

$grants | Select-Object clientId, consentType, principalId, scope | 
  Export-Csv oauth_grants.csv

# Find applications with Graph API admin scopes
$spId = (Get-MgServicePrincipal -Filter "appDisplayName eq 'Microsoft Graph'").id

$grants | Where-Object {$_.resourceId -eq $spId} | 
  ForEach-Object {
    $scope = $_.scope
    if ($scope -contains "Directory.ReadWrite.All" -or 
        $scope -contains "Mail.ReadWrite.All") {
      Write-Host "[HIGH RISK] Application with admin scope: $($_.clientId)"
    }
  }
```

**Step 3:** Device and compliance enumeration
```powershell
# Get all devices
Get-MgDevice -All | Select-Object displayName, isCompliant, deviceVersion

# Find non-compliant devices (potential vulnerabilities)
Get-MgDevice -Filter "isCompliant eq false" -All

# Get device owner information
Get-MgDevice -Filter "isCompliant eq false" -All | ForEach-Object {
  $deviceId = $_.id
  $owner = Get-MgDeviceRegisteredOwner -DeviceId $deviceId
  Write-Host "Device: $($_.displayName) - Owner: $($owner.displayName)"
}
```

### Method 5: Organizational Structure Mapping

**Step 1:** Map reporting relationships
```powershell
# Get manager for all users (shows organizational hierarchy)
$users | ForEach-Object {
  $manager = Get-MgUserManager -UserId $_.id
  Write-Host "$($_.displayName) reports to $($manager.displayName)"
} | Export-Csv org_hierarchy.csv
```

**Step 2:** Department and office location enumeration
```powershell
# Get users by department
$users | Where-Object {$_.department -ne $null} | 
  Group-Object department | 
  ForEach-Object {Write-Host "$($_.Name): $($_.Count) users"}

# Get users by office location
$users | Where-Object {$_.officeLocation -ne $null} | 
  Group-Object officeLocation | 
  ForEach-Object {Write-Host "$($_.Name): $($_.Count) users"}
```

### Method 6: Comprehensive Export and Analysis

**Step 1:** Export complete M365 environment
```powershell
# Create comprehensive inventory
$inventory = @{
  "Users" = @(Get-MgUser -All)
  "Groups" = @(Get-MgGroup -All)
  "ServicePrincipals" = @(Get-MgServicePrincipal -All)
  "Applications" = @(Get-MgApplication -All)
  "Teams" = @(Get-MgTeam -All)
  "Devices" = @(Get-MgDevice -All)
}

# Export to JSON
$inventory | ConvertTo-Json -Depth 5 | Out-File m365_environment.json

# Export by category
foreach ($category in $inventory.Keys) {
  $inventory[$category] | Export-Csv "${category}.csv" -NoTypeInformation
}
```

**Step 2:** Identify high-value targets
```powershell
# Users with mailbox forwarding enabled
Get-MgUser -All | ForEach-Object {
  $mailbox = Get-MgUserMailboxSettings -UserId $_.id
  if ($mailbox.forwardingAddress -ne $null) {
    Write-Host "[FORWARD] $($_.displayName) -> $($mailbox.forwardingAddress)"
  }
}

# Groups with high member count
Get-MgGroup -All | ForEach-Object {
  $memberCount = (Get-MgGroupMember -GroupId $_.id | Measure-Object).Count
  if ($memberCount -gt 100) {
    Write-Host "[HIGH MEMBERS] $($_.displayName): $memberCount members"
  }
}

# Recently created accounts (potential backdoors)
$cutoff = (Get-Date).AddDays(-30)
Get-MgUser -Filter "createdDateTime gt $cutoff" -All
```

---

## Technical Deep Dive

### Graph API Authentication Methods

**Delegated Permissions (on behalf of user):**
- User login required
- Limited to user's accessible data
- Requires interactive authentication

**Application Permissions (app-only):**
- No user interaction
- Tenant-wide access
- Service principal authentication
- Higher privilege potential

### Key Graph API Endpoints for Reconnaissance

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `/users` | User enumeration | High |
| `/groups` | Group discovery | High |
| `/servicePrincipals` | Service principal mapping | Critical |
| `/applications` | Application inventory | Critical |
| `/teams` | Team structure | Medium |
| `/devices` | Device enumeration | Medium |
| `/me/memberOf` | User group membership | Medium |
| `/oauth2PermissionGrants` | Consent grant mapping | Critical |

---

## Detection Strategies (Blue Team)

### Graph API Query Monitoring

1. **Microsoft Sentinel Rules**
   ```kusto
   AADServicePrincipalSignInLogs
   | where AppId contains "graph"
   | summarize SignInCount = count() by AppId, UserPrincipalName, bin(TimeGenerated, 5m)
   | where SignInCount > 50
   ```

2. **Azure Activity Logging**
   - Monitor Microsoft.Graph API calls
   - Alert on bulk user/group queries
   - Track permission consent grants

3. **Behavioral Indicators**
   - Service principal accessing User.Read.All scope
   - Graph API queries from non-standard clients
   - Bulk enumeration patterns (high query frequency)

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Stealthy Querying**
   - Use delegated permissions (harder to flag)
   - Space API calls across time
   - Mix reconnaissance queries with legitimate application data access

2. **Credential Management**
   - Use service principal with minimal permissions
   - Avoid dedicated reconnaissance tools
   - Use legitimate automation accounts

### Defensive Measures

1. **Permission Limiting**
   - Don't grant User.Read.All to unnecessary apps
   - Regularly audit OAuth consent grants
   - Disable legacy authentication

2. **Monitoring**
   - Alert on unusual Graph API access patterns
   - Monitor service principal behavior
   - Track bulk query operations

---

## Mitigation Strategies

1. **Immediate Actions**
   - Audit and revoke unnecessary OAuth consent grants
   - Review service principal permissions
   - Disable unused applications

2. **Detection & Response**
   - Enable Azure AD Sign-in Logs
   - Monitor Graph API usage
   - Alert on bulk enumeration

3. **Long-term Security**
   - Implement app governance policies
   - Use Conditional Access for API access
   - Regular permission audits

---

## References & Further Reading

- [Microsoft Graph API Overview](https://learn.microsoft.com/en-us/graph/overview)
- [Graph API Permissions Reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Azure AD OAuth2 Permissions](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent)
- [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)

---

## Related SERVTEP Techniques

- **REC-M365-002**: Cross-tenant service discovery
- **REC-CLOUD-001**: BloodHound (privilege path analysis)
- **REC-CLOUD-004**: AADInternals (Entra ID reconnaissance)
- **IA-PHISH-002**: Consent grant OAuth attacks

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| Authentication | 1-2 minutes | Easy |
| User enumeration | 2-5 minutes | Easy |
| Group/team discovery | 2-5 minutes | Easy |
| Application mapping | 3-5 minutes | Medium |
| Full reconnaissance | 10-20 minutes | Medium |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
