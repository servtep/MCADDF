# REC-M365-002: Cross-Tenant Service Discovery

**SERVTEP ID:** REC-M365-002  
**Technique Name:** Cross-tenant service discovery  
**MITRE ATT&CK Mapping:** T1580 (Cloud Service Discovery)  
**CVE Reference:** N/A  
**Environment:** Microsoft 365  
**Severity:** High  
**Difficulty:** Hard  

---

## Executive Summary

Cross-tenant service discovery involves enumerating and identifying Microsoft 365 services, shared resources, and integration points accessible across organizational boundaries. Organizations often share Teams, SharePoint sites, or participate in federated sharing with external partners. Attackers exploit these trust relationships to discover shared resources, identify organizational connections, and pivot to external tenant infrastructure. This technique reveals which organizations your target partners with and what services they expose externally.

---

## Objective

Discover and enumerate cross-tenant M365 services to:
- Map external resource sharing relationships
- Identify federated Teams and channels
- Find shared SharePoint sites with external access
- Discover Azure AD B2B collaboration relationships
- Map organizational partnerships and integrations
- Identify exposed Teams channels and files
- Enumerate delegated access and shared mailboxes
- Discover graph connector integrations (external data sources)

---

## Prerequisites

- Access to target M365 organization (user account or guest access)
- Cross-tenant authentication capability
- B2B collaboration enabled in target organization
- Teams, SharePoint, or Exchange with shared resources
- Optional: Multiple M365 tenant credentials for testing

---

## Execution Procedures

### Method 1: Teams Cross-Tenant Service Discovery

**Step 1:** Enumerate shared Teams and channels
```powershell
# Get all Teams accessible to current user
Get-MgTeam -All | Select-Object displayName, isArchived, visibility

# Find shared Teams (external members present)
Get-MgTeam -All | ForEach-Object {
  $teamId = $_.id
  $members = Get-MgTeamMember -TeamId $teamId
  
  # Check for external members (userType = Guest)
  $externalMembers = $members | Where-Object {
    $_.AdditionalProperties["userType"] -eq "Guest"
  }
  
  if ($externalMembers.count -gt 0) {
    Write-Host "[SHARED] $($_.displayName): $($externalMembers.count) external members"
  }
}

# Enumerate channels in shared Teams
Get-MgTeam -All | ForEach-Object {
  $teamId = $_.id
  $channels = Get-MgTeamChannel -TeamId $teamId
  Write-Host "Team: $($_.displayName) - Channels: $($channels.count)"
}
```

**Step 2:** Access shared channel content
```powershell
# Get shared channels (cross-tenant channels)
Get-MgTeamChannelSharedWithTeam -TeamId $teamId | 
  Select-Object displayName, id, tenantId

# Find messages in shared channels (if permissions allow)
Get-MgTeamChannelMessage -TeamId $teamId -ChannelId $channelId | 
  Select-Object from, createdDateTime, body | 
  Sort-Object createdDateTime -Descending | 
  Head -20
```

### Method 2: SharePoint Cross-Tenant Sharing Discovery

**Step 1:** Enumerate shared SharePoint sites
```powershell
# Get all SharePoint sites accessible to current user
Get-MgSite -All | Select-Object displayName, webUrl, id

# Find sites with external sharing enabled
Get-MgSite -All | ForEach-Object {
  $siteId = $_.id
  $sharing = Get-MgSiteSharingInformation -SiteId $siteId
  
  if ($sharing.sharingCapabilities -eq "ExternalUserSharingCapable") {
    Write-Host "[EXTERNAL SHARING] $($_.displayName)"
  }
}

# Get external users with SharePoint access
Get-MgSite -All | ForEach-Object {
  $siteId = $_.id
  $permissions = Get-MgSitePermission -SiteId $siteId
  
  $externalPerms = $permissions | Where-Object {
    $_.grantedToIdentities.user.displayName -like "*guest*" -or
    $_.grantedToIdentities.user.mail -like "*#ext#*"
  }
  
  if ($externalPerms.count -gt 0) {
    Write-Host "$($_.displayName): $($externalPerms.count) external permissions"
  }
}
```

**Step 2:** Discover shared document libraries
```powershell
# Get lists and libraries within sites
Get-MgSite -All | ForEach-Object {
  $siteId = $_.id
  $lists = Get-MgSiteList -SiteId $siteId
  
  foreach ($list in $lists) {
    $items = Get-MgListItem -SiteId $siteId -ListId $list.id
    Write-Host "List: $($list.displayName) - Items: $($items.count)"
  }
}

# Find document libraries with open permissions
Get-MgSite -All | ForEach-Object {
  $siteId = $_.id
  $drives = Get-MgSiteDrive -SiteId $siteId
  
  foreach ($drive in $drives) {
    $items = Get-MgDriveItem -DriveId $drive.id
    Write-Host "Drive: $($drive.name) - Items: $($items.count)"
  }
}
```

### Method 3: Azure AD B2B Collaboration Mapping

**Step 1:** Enumerate B2B users and invitations
```powershell
# Get all B2B guest users in tenant
Get-MgUser -Filter "userType eq 'Guest'" -All | 
  Select-Object displayName, mail, createdDateTime | 
  Export-Csv b2b_guests.csv

# Map which organizations B2B users come from (by email domain)
$guests = Get-MgUser -Filter "userType eq 'Guest'" -All

$guests | ForEach-Object {
  $email = $_.mail
  $domain = $email.Split('@')[1]
  Write-Host "Guest from $domain : $($_.displayName)"
} | Group-Object domain | 
  ForEach-Object {Write-Host "  $($_.Name): $($_.Count) users"}

# Get B2B invitation status
Get-MgInvitation -All | Select-Object invitedUserEmailAddress, status, createdDateTime
```

**Step 2:** Map B2B user access and permissions
```powershell
# Get groups that contain B2B users
$guests = Get-MgUser -Filter "userType eq 'Guest'" -All

foreach ($guest in $guests) {
  $groupMembership = Get-MgUserMemberOf -UserId $guest.id
  Write-Host "$($guest.displayName):"
  $groupMembership | ForEach-Object {Write-Host "  - $($_.displayName)"}
}
```

### Method 4: Cross-Tenant Delegated Access Discovery

**Step 1:** Find delegated mailbox access (shared mailboxes)
```powershell
# Get shared mailboxes (full access delegates)
Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited | 
  ForEach-Object {
    $mailbox = $_
    $delegates = Get-MailboxPermission -Identity $mailbox.Identity | 
      Where-Object {$_.IsInherited -eq $false -and $_.AccessRights -contains "FullAccess"}
    
    Write-Host "Shared Mailbox: $($mailbox.DisplayName)"
    $delegates | ForEach-Object {Write-Host "  Delegate: $($_.User)"}
  }

# Get mailbox forwarding rules (potential data exfiltration)
Get-Mailbox -ResultSize Unlimited | Where-Object {$_.ForwardingAddress -ne $null} |
  Select-Object DisplayName, ForwardingAddress
```

**Step 2:** Find delegated folder permissions
```powershell
# Get mailbox folder delegates
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
  $mailbox = $_
  Get-MailboxFolderPermission -Identity "$($mailbox.Identity):\Calendar" -ErrorAction SilentlyContinue |
    Where-Object {$_.User -like "*guest*" -or $_.User -like "*#ext#*"} |
    ForEach-Object {Write-Host "External calendar access: $($mailbox.DisplayName)"}
}
```

### Method 5: Teams Shared Channels and Federation Discovery

**Step 1:** Enumerate Teams federation relationships
```powershell
# Get Teams Direct Routing configuration (indicates external federation)
Get-CsTeamsCallingPolicy -Identity * | Select-Object Identity, AllowMeetNow

# Find Teams with external meeting accessibility
Get-MgTeam -All | ForEach-Object {
  $teamId = $_.id
  $settings = Get-MgTeamTeamMessagingSettings -TeamId $teamId
  
  if ($settings.AllowGiphy -or $settings.AllowStickersAndMemes) {
    Write-Host "[EXTERNAL CAPABLE] $($_.displayName)"
  }
}

# Get Teams connected to shared channels
Get-MgTeamSharedChannel -TeamId $teamId | 
  Select-Object displayName, id, sharedChannelTenantId
```

**Step 2:** Discover guest access permissions
```powershell
# Get guest user policies
Get-CsTeamsGuestCallingPolicy | Select-Object Identity, AllowPrivateCalling

# Find Teams with guest messaging enabled
Get-MgTeam -All | ForEach-Object {
  $teamId = $_.id
  $settings = Get-MgTeamMessagingSettings -TeamId $teamId
  
  if ($settings.AllowUserEditMessage -and $settings.AllowUserDeleteMessage) {
    Write-Host "Guests can edit/delete messages: $($_.displayName)"
  }
}
```

### Method 6: Graph Connectors and External Data Source Discovery

**Step 1:** Find Microsoft Search connectors
```powershell
# Get external connections (graph connectors integrating external data)
Get-MgExternalConnection -All | 
  Select-Object displayName, id, configuration

# Get external connection items (indexed data from external sources)
Get-MgExternalConnectionItem -ExternalConnectionId $connId | 
  Select-Object displayName, id, externalItemId
```

**Step 2:** Enumerate external content sources
```powershell
# Discover what external systems are integrated
Get-MgExternalConnection -All | ForEach-Object {
  Write-Host "External Connection: $($_.displayName)"
  Write-Host "  Config: $($_.configuration.connectorId)"
}
```

### Method 7: Cross-Tenant Collaboration Inventory

**Step 1:** Create comprehensive cross-tenant map
```powershell
# Export complete external sharing configuration
$crossTenantMap = @{
  "B2B_Guests" = @(Get-MgUser -Filter "userType eq 'Guest'" -All)
  "Shared_Teams" = @()
  "Shared_SharePoint" = @()
  "Delegated_Mailboxes" = @()
  "External_Connections" = @(Get-MgExternalConnection -All)
}

# Add shared Teams details
Get-MgTeam -All | ForEach-Object {
  $teamId = $_.id
  $members = Get-MgTeamMember -TeamId $teamId
  $externalMembers = $members | Where-Object {
    $_.AdditionalProperties["userType"] -eq "Guest"
  }
  
  if ($externalMembers.count -gt 0) {
    $crossTenantMap["Shared_Teams"] += @{
      "Team" = $_.displayName
      "External_Members" = $externalMembers.count
    }
  }
}

# Export cross-tenant map to JSON
$crossTenantMap | ConvertTo-Json -Depth 5 | Out-File cross_tenant_map.json
```

---

## Technical Deep Dive

### Cross-Tenant Trust Models

**1. B2B Collaboration**
- Organizations explicitly add guest users
- Controlled via Conditional Access and sharing policies
- Discoverable via guest user enumeration

**2. Teams Shared Channels**
- Channel members from multiple tenants
- New Teams feature (more secure than external access)
- Access logged separately from external access

**3. Delegated Access**
- Shared mailboxes, delegates, forwarding rules
- Resource forest model (less common)
- Often misconfigured with overly broad permissions

**4. Federation**
- Entra ID federation (pre-configured trust)
- Teams Direct Routing (PSTN integration)
- Organizational relationships

---

## Detection Strategies (Blue Team)

### Cross-Tenant Activity Monitoring

1. **B2B User Auditing**
   - Monitor guest user creation/deletion
   - Track guest access to sensitive resources
   - Alert on external user group membership

2. **Sharing Policy Enforcement**
   - Disable external sharing by default
   - Restrict guest access to specific groups
   - Require approval for external sharing

3. **Azure AD Conditional Access**
   - Block guest access except from approved domains
   - Require MFA for B2B users
   - Restrict to compliant devices

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Discovery Without Detection**
   - Use existing guest access credentials
   - Query from within shared Teams/sites (harder to track)
   - Use legitimate tools (Teams client, SharePoint UI)

2. **Data Exfiltration**
   - Download shared files during "normal" hours
   - Use shared mailbox access to forward sensitive emails
   - Export Teams chat history if permissions allow

### Defensive Measures

1. **External User Management**
   - Regular audit of guest users
   - Remove unnecessary external access
   - Enforce guest access review quarterly

2. **Resource Protection**
   - Sensitivity labels on shared resources
   - Data loss prevention (DLP) policies
   - Audit external access logs

---

## Mitigation Strategies

1. **Immediate Actions**
   - Audit B2B guest users and their access
   - Review shared mailboxes and delegates
   - Check Teams external member access

2. **Detection & Response**
   - Enable audit logging for sharing events
   - Alert on unusual external access patterns
   - Monitor Teams external meeting activity

3. **Long-term Security**
   - Implement Zero Trust for external collaboration
   - Use Conditional Access for B2B users
   - Regular external access reviews
   - Classify data and restrict sharing

---

## References & Further Reading

- [Microsoft 365 Guest Access Security](https://learn.microsoft.com/en-us/microsoft-365/solutions/collaborate-with-people-outside-your-organization)
- [Teams Shared Channels](https://learn.microsoft.com/en-us/microsoftteams/shared-channels)
- [B2B Collaboration Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/best-practices)
- [Microsoft 365 Audit Logging](https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-log-search)

---

## Related SERVTEP Techniques

- **REC-M365-001**: Microsoft Graph API enumeration
- **REC-CLOUD-001**: BloodHound (privilege path analysis)
- **IA-PHISH-002**: Consent grant OAuth attacks
- **PERSIST-EMAIL-001**: Mail Forwarding Rules

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| B2B user enumeration | 2-5 minutes | Easy |
| Teams discovery | 3-10 minutes | Medium |
| SharePoint mapping | 5-15 minutes | Medium |
| Delegated access | 5-10 minutes | Medium |
| Full assessment | 15-40 minutes | Hard |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
