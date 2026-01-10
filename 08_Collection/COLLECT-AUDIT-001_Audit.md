# [COLLECT-AUDIT-001]: Audit Log Comprehensive Collection

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-AUDIT-001 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Credentials in Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Collection |
| **Platforms** | Multi-Env (Windows AD, Azure, M365, Entra ID, Hybrid) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2016-2025, Azure all versions, M365 all tenants |
| **Patched In** | N/A (Operational Feature) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Audit logs are comprehensive records of security-relevant activities across Microsoft environments: Windows Event Log (on-premises), Azure Activity Log (cloud infrastructure), M365 Unified Audit Log (collaboration and mail), and Entra ID/Azure AD Sign-in Logs (authentication events). These logs contain timestamped records of user actions, administrative changes, system events, and security anomalies. Comprehensive collection and analysis of audit logs reveals: (1) user access patterns and privilege escalation chains, (2) administrative configuration changes (often indicators of persistence mechanisms), (3) failed authentication attempts (brute force indicators), (4) sensitive data access and exfiltration events, (5) policy violations and compliance failures. An attacker with comprehensive audit log access can understand exactly what the organization has observed, what went undetected, and how to refine their attack techniques. Organizations with audit logging disabled or with short retention periods are unable to investigate historical breaches, making audit log collection critical for post-compromise threat hunting.

**Attack Surface:** Windows Event Viewer, Azure Activity Log API, Microsoft Purview Compliance Portal (M365 Unified Audit Log), Entra ID Sign-in Logs, Azure Monitor Log Analytics workspace, third-party SIEM ingestion points.

**Business Impact:** **Complete visibility into security events, administrative actions, user behavior patterns, and forensic evidence for all breaches.** Audit logs contain: (1) evidence of initial compromise (failed login attempts before successful breach), (2) administrative account misuse (privilege escalation), (3) data exfiltration indicators (bulk downloads, email forwards), (4) account creation/deletion events (backdoor accounts), (5) policy modifications (disabling MFA, Conditional Access rules). Loss of audit logs due to short retention or deletion during incident response prevents forensic investigation, blocks threat intelligence gathering, and eliminates legal evidence for breach notification and litigation.

**Technical Context:** Audit logs are available in all Microsoft environments by default (some require explicit enablement). Retention varies: Windows Event Log (default 7-30 days), Azure Activity (90 days default, up to 12 years with policy), M365 Unified Audit (90 days default, up to 10 years with Advanced Audit). Querying audit logs requires minimal permissions (Security Reader, Audit log viewer). Exfiltration requires simple export via portal or API. No special tools required.

### Operational Risk
- **Execution Risk:** Low – Audit logs are accessible to most admin accounts; no special permissions required.
- **Stealth:** Very Low – Audit log access itself is often logged; retrieval is difficult to hide without disabling logging.
- **Reversibility:** No – Audit logs reflect actual events; cannot be modified without detection (in most systems).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.2 | Configure log retention to preserve logs for adequate period |
| **DISA STIG** | AU-2 | Audit Events – Determine auditable events (all security-relevant events) |
| **CISA SCuBA** | Log.1.1 | Ensure audit logging is enabled and retention is set appropriately |
| **NIST 800-53** | AU-2, AU-3, AU-12 | Audit and Accountability – Log events, retention, and protection |
| **GDPR** | Art. 5(1)(f), Art. 32 | Data Protection – Integrity and confidentiality of logs |
| **DORA** | Art. 19 | Incident handling and response – Evidence preservation |
| **NIS2** | Art. 21 | Cybersecurity Risk Management – Logging and monitoring |
| **ISO 27001** | A.12.4.1 | Recording user activities and system events (audit logs) |
| **ISO 27005** | 8.3 | Risk Assessment – Audit logs as forensic evidence |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** For Windows: Local Administrator or Event Log Readers group; For Azure: Reader or higher; For M365: Audit Log Viewer or Global Reader role.
- **Required Access:** Local machine access (on-premises), Azure subscription access (cloud), M365 tenant admin access (audit logs).

**Supported Versions:**
- **Windows Server:** 2016, 2019, 2022, 2025 (all editions)
- **Azure:** All subscription types; all regions
- **M365:** All tenant types (business, education, government)
- **Entra ID:** All versions (on-premises AD, hybrid, cloud-native)

**Tools:**
- Windows Event Viewer (`eventvwr.msc`) – on-premises
- Azure Portal – cloud infrastructure logs
- Microsoft Purview Compliance Portal – M365 Unified Audit Log
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) – programmatic access
- [PowerShell: Az.Monitor module](https://github.com/Azure/azure-powershell) – scripted collection
- [Get-UnifiedAuditLog cmdlet](https://learn.microsoft.com/en-us/powershell/module/exchange/get-unifiedauditlog) – M365 audit logs

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Check if audit logging is enabled on local Windows system
Get-EventLog -LogName Security -Newest 1 -ErrorAction SilentlyContinue | Select-Object TimeGenerated, EventID

# Check if Windows audit policy is configured
auditpol /get /category:*

# Check Azure audit log availability
Connect-AzAccount
Get-AzActivityLog -MaxRecord 1

# Check M365 audit log availability
Connect-ExchangeOnline
Search-UnifiedAuditLog -ResultSize 1
```

**What to Look For:**
- EventLog returns recent events (indicates audit is active)
- auditpol output shows "Success and Failure" for relevant categories
- Azure activity log returns recent entries (last 24 hours)
- M365 audit log returns entries (if > 90 days old, Advanced Audit is enabled)

**Version Note:** Commands work identically across all Windows versions and Azure regions.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Export Windows Event Logs via Event Viewer GUI

**Supported Versions:** Server 2016-2025 (all versions)

#### Step 1: Open Event Viewer and Select Security Log

**Command:**
1. Press `Win + R`, type `eventvwr.msc`, press Enter
2. Navigate to **Windows Logs** → **Security** (left sidebar)
3. Right-click **Security** → **Save All Events As...**

**Expected Output:**
- Event Viewer displays list of security events with columns: Level, Date and Time, Source, EventID, Task Category
- Each event shows timestamp, event code (e.g., 4624 = Logon, 4688 = Process Creation), and brief description

**OpSec & Evasion:**
- Opening Event Viewer and exporting logs does NOT generate an audit event
- Local file export is silent (no logging)
- Exported .evtx file remains on disk indefinitely
- **Evasion:** No log entry for exporting logs locally; perfect for offline collection

#### Step 2: Export All Events to .EVTX File

**Command:**
1. In Event Viewer, right-click **Security** log
2. Click **Save All Events As...**
3. Select location: `C:\temp\Security_Logs.evtx`
4. Click **Save**

**Expected Output:**
- File created: `C:\temp\Security_Logs.evtx` (typically 100MB - 1GB for large environments)
- File contains all security events in binary EVTX format (Microsoft's proprietary event format)
- Can be viewed in Event Viewer or parsed with PowerShell

**What This Means:**
- .evtx file contains unfiltered security events spanning the retention period
- Each event includes: timestamp, event ID, account name, computer name, description, event-specific data
- Can be transferred to attacker machine for offline analysis
- Large file size (500MB+ in busy environments) indicates rich forensic data

**OpSec & Evasion:**
- Exporting .evtx file is silent and unlogged
- No security alert generated for exporting logs
- File can be compressed and exfiltrated via normal file transfer methods
- **Evasion:** Exports are invisible to audit logs and security tools

#### Step 3: Parse and Analyze Events with PowerShell

**Command:**
```powershell
# Load the exported .evtx file
$events = Get-WinEvent -Path "C:\temp\Security_Logs.evtx" -MaxEvents 10000

# Filter for logon events (EventID 4624)
$logonEvents = $events | Where-Object {$_.Id -eq 4624}

# Filter for process creation (EventID 4688)
$processEvents = $events | Where-Object {$_.Id -eq 4688}

# Filter for account lockouts (EventID 4740)
$lockoutEvents = $events | Where-Object {$_.Id -eq 4740}

# Export filtered events to CSV
$logonEvents | Select-Object TimeCreated, @{n='EventID';e={$_.Id}}, @{n='Message';e={$_.Message}} | Export-Csv -Path "C:\temp\logon_events.csv"

Write-Host "Extracted $($logonEvents.Count) logon events"
Write-Host "Extracted $($processEvents.Count) process creation events"
Write-Host "Extracted $($lockoutEvents.Count) account lockout events"
```

**Expected Output:**
```
Extracted 15234 logon events
Extracted 8976 process creation events
Extracted 342 account lockout events
```

**What This Means:**
- Logon events reveal user access patterns (who logged in, when, from where)
- Process creation events show command line execution (tools used, scripts run)
- Account lockout events indicate failed authentication attempts (brute force attacks)
- CSV export allows offline analysis without Event Viewer

**OpSec & Evasion:**
- PowerShell parsing is unlogged (no audit event generated)
- Export to CSV is silent
- Analysis can be done on any machine without triggering alerts
- **Evasion:** No logs for parsing or exporting; entirely offline operation

**References & Proofs:**
- [Windows Event Log Reference](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging)
- [Get-WinEvent PowerShell Cmdlet](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)

### METHOD 2: Export Azure Activity Logs via Azure Portal

**Supported Versions:** All Azure subscriptions and regions

#### Step 1: Navigate to Azure Monitor Activity Log

**Command:**
1. Go to https://portal.azure.com
2. Search for **"Activity Log"** in top search bar
3. Select **Activity Log** from results

**Expected Output:**
- Activity Log page displays cloud events with columns: Time, Subscription, Operation, Status, Resource, Resource Group
- Default view shows last 24 hours; time filter available

**What This Means:**
- Each row represents one cloud operation (VM creation, storage access, role assignment, etc.)
- Time column shows exact UTC timestamp
- Operation column reveals action performed (e.g., "Create virtual machine", "Modify access control list")
- Status shows whether operation succeeded/failed

**OpSec & Evasion:**
- Viewing Activity Log is logged in Azure audit logs (but as a normal read operation, not suspicious)
- No special alert for accessing logs
- **Evasion:** No way to hide Activity Log access; it's audited, but not flagged

#### Step 2: Apply Filters to Target Specific Operations

**Command:**
1. In Activity Log view, click **"Add filter"**
2. Filter by **Operation**, select relevant operations:
   - "Create access review"
   - "Modify role assignment"
   - "Delete key vault"
   - "Create VM"
3. Filter by **Status**: Select "Failed" to find attack attempts
4. Filter by **Time Range**: Select 30 days (or maximum available)
5. Click **Apply**

**Expected Output:**
- Filtered list showing only matching operations
- Each entry shows detailed information in "Properties" panel

**What This Means:**
- Filtering narrows down millions of events to relevant operations
- Failed operations reveal attack attempts (e.g., failed role assignment, failed VM deletion)
- Properties panel shows: caller identity, IP address, user agent, resource modified, timestamp

**OpSec & Evasion:**
- Filtering is logged but not suspicious
- No alert for filtering Activity Logs
- Filtered view is temporary (not saved unless explicitly exported)

#### Step 3: Export Activity Log Events to CSV

**Command:**
1. In filtered Activity Log view, click **"Export to CSV"**
2. Select **"Download"**
3. File downloads as `activity-log-export.csv` to Downloads folder

**Expected Output:**
```csv
Time,Subscription,Operation,Status,Resource,Resource Group,Caller,Request Size,Caller IP Address
2026-01-09T14:32:15Z,mysubscription,Microsoft.Authorization/roleAssignments/write,Succeeded,myresourcegroup,myresourcegroup,user@company.com,1234,203.0.113.45
2026-01-09T13:22:08Z,mysubscription,Microsoft.Storage/storageAccounts/delete,Failed,mystorageaccount,myresourcegroup,admin@company.com,567,203.0.113.46
```

**What This Means:**
- CSV contains all cloud operations with full context
- Caller field identifies user who performed operation
- Caller IP reveals source of action (on-premises, cloud, VPN, etc.)
- Successful role assignments reveal privilege escalation paths
- Failed operations reveal attack attempts

**OpSec & Evasion:**
- Export is logged in Azure audit (as normal operation)
- CSV file remains on local machine indefinitely
- No alert for exporting Activity Logs
- **Evasion:** Export is invisible to most security tools

**References & Proofs:**
- [Azure Activity Log Documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)
- [Export Activity Log Guide](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log#export-activity-log-events)

### METHOD 3: Export M365 Unified Audit Log via Purview

**Supported Versions:** All M365 tenants with audit enabled (90 days default, 10 years with Advanced Audit)

#### Step 1: Connect to Purview and Verify Audit Log is Enabled

**Command:**
1. Navigate to https://compliance.microsoft.com (Microsoft Purview)
2. Go to **Audit** (left sidebar)
3. If audit log is not enabled, click **"Start recording user and admin activity"**

**Expected Output:**
- Audit page loads showing "Recording" status
- Last 24 hours of activity visible (or 90 days if Advanced Audit enabled)

**OpSec & Evasion:**
- Accessing Purview Audit is logged in Unified Audit Log itself (minimal observation)
- No alert for browsing audit logs
- **Evasion:** Access is logged but not suspicious

#### Step 2: Search Audit Log for Specific Events

**Command:**
1. In Purview Audit page, click **"Search"**
2. Set **Date range**: Last 90 days (or maximum available)
3. Under **Activities**, select relevant activities:
   - "Delete mailbox"
   - "Add-MailForwardingAddress" (email forwarding)
   - "Update user"
   - "Modify role assignment"
   - "Download Microsoft 365 data"
4. Optional: Filter by **Users** (target accounts)
5. Optional: Filter by **File, folder, or site** (data exfiltration targets)
6. Click **Search**

**Expected Output:**
```
Activity: Add-MailForwardingAddress
User: admin@company.com
Date: 2026-01-09
Time: 14:32:15
Details: Forward emails from user@company.com to attacker@external-domain.com
Result IP: 203.0.113.45
```

**What This Means:**
- Each activity entry shows exact timestamp, user, action, and result
- Forwarding rules reveal persistence mechanisms (attacker reading victim's mail)
- Role modifications reveal privilege escalation
- Data download events reveal exfiltration attempts

**OpSec & Evasion:**
- Searching Audit Log is logged but as normal operation
- No alert for searching (even with suspicious keywords)
- Results are temporary (not saved unless exported)
- **Evasion:** Searching is invisible unless audit log is monitored for anomalies

#### Step 3: Export Audit Log Results to CSV

**Command:**
1. After search results display, click **"Export"** → **"Download all results"**
2. File downloads as `AuditLog_yyyy-mm-dd.csv`

**Expected Output:**
```csv
CreationDate,UserIds,Operations,AuditData
2026-01-09T14:32:15Z,admin@company.com,Add-MailForwardingAddress,"{'Id':'xxxxxxxx','Item':{'Subject':'','Identity':'user@company.com'},'ModifiedProperties':{'Name':'ForwardingAddress','NewValue':'attacker@external.com'}}"
```

**What This Means:**
- CSV contains raw audit data in AuditData JSON field (requires parsing)
- Each row is one auditable action
- ModifiedProperties show what changed (e.g., forwarding address added)
- Timestamp allows correlation with other events

**OpSec & Evasion:**
- Export is logged in Unified Audit Log (minimal observation)
- CSV file remains on attacker machine indefinitely
- **Evasion:** Exporting is silent and largely undetected

**References & Proofs:**
- [Microsoft Purview Compliance Portal](https://learn.microsoft.com/en-us/purview/)
- [Unified Audit Log Search](https://learn.microsoft.com/en-us/purview/audit-log-search)
- [Audit Log Retention Policies](https://learn.microsoft.com/en-us/purview/audit-log-retention-policies)

### METHOD 4: Query Audit Logs Programmatically via PowerShell

**Supported Versions:** All environments (Windows, Azure, M365)

#### Step 1: Connect to M365 and Extract Audit Logs

**Command (M365 Unified Audit Log - no API available, PowerShell only):**
```powershell
# Connect to Exchange Online PowerShell (M365 Audit)
Connect-ExchangeOnline -UserPrincipalName "user@company.com"

# Search Unified Audit Log for last 90 days
$startDate = (Get-Date).AddDays(-90)
$endDate = Get-Date

$auditEvents = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -ResultSize 50000

# Filter for suspicious activities
$suspiciousEvents = $auditEvents | Where-Object {
    $_.Operations -in @(
        "Delete",
        "Update-InboxRules",
        "Add-MailForwardingAddress",
        "Set-Mailbox",
        "New-ExternalUser",
        "New-ApplicationAccessPolicy"
    )
}

# Export to CSV
$suspiciousEvents | Select-Object CreationDate, UserId, Operations, @{n='Details';e={$_.AuditData | ConvertFrom-Json}} | Export-Csv -Path "C:\temp\m365_audit_suspicious.csv" -NoTypeInformation

Write-Host "Extracted $($suspiciousEvents.Count) suspicious events from M365 Audit Log"
```

**Expected Output:**
```
Extracted 342 suspicious events from M365 Audit Log
```

**What This Means:**
- Search-UnifiedAuditLog returns all M365 activities (50,000 at a time; paginate for more)
- Filtering narrows down to attack-relevant activities
- AuditData field contains JSON with full event details
- Exporting creates offline copy for analysis

**OpSec & Evasion:**
- Search-UnifiedAuditLog execution is logged in Unified Audit Log (as SearchQueryInitiatedAdmin)
- But searching for events is not suspicious (normal SOC activity)
- Exporting is logged as "Export-UnifiedAuditLog" event
- **Evasion:** No alert for querying audit logs; auditing audit logs is rare

#### Step 2: Query Azure Activity Logs via Azure CLI

**Command (Azure Activity Logs - programmatic access):**
```bash
#!/bin/bash
# Connect to Azure
az login

# Query Activity Log for last 30 days
RESOURCE_GROUP="your-resource-group"
START_DATE=$(date -d '30 days ago' -u +%Y-%m-%dT%H:%M:%SZ)
END_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Export all activity logs
az monitor activity-log list \
  --resource-group $RESOURCE_GROUP \
  --start-time $START_DATE \
  --end-time $END_DATE \
  --query "[*].{Time:eventTimestamp, Operation:operationName, Caller:caller, Status:status}" \
  --output csv > /tmp/azure_activity.csv

echo "Activity logs exported to /tmp/azure_activity.csv"
```

**Expected Output:**
```csv
Time,Operation,Caller,Status
2026-01-09T14:32:15Z,Microsoft.Authorization/roleAssignments/write,user@company.com,Succeeded
2026-01-09T13:22:08Z,Microsoft.Compute/virtualMachines/delete,admin@company.com,Succeeded
```

**OpSec & Evasion:**
- Azure CLI queries are logged in Activity Log (minimal observation)
- No alert for querying Activity Logs
- Exporting is silent
- **Evasion:** Queries are transparent to most security tools

#### Step 3: Query Windows Event Logs Remotely via PowerShell Remoting

**Command (Windows Event Logs - remote collection):**
```powershell
# Connect to remote server
$server = "SERVER-PROD-01"
Invoke-Command -ComputerName $server -ScriptBlock {
    # Export Security event log
    wevtutil epl Security "C:\temp\Security.evtx"
    
    # Get count of events
    Get-WinEvent -LogName Security -MaxEvents 1 | Select-Object RecordCount
}

# Copy exported file back to local machine
Copy-Item -Path "\\$server\C$\temp\Security.evtx" -Destination "C:\incident\Security.evtx"

Write-Host "Security event log exported from $server"
```

**Expected Output:**
- File copied: `C:\incident\Security.evtx` (containing all security events from remote server)

**What This Means:**
- Remote collection bypasses local Event Viewer GUI
- Exporting via PowerShell Remoting is silent (no local logging on target)
- .evtx file contains unfiltered events
- Can be repeated across hundreds of servers for mass collection

**OpSec & Evasion:**
- Remote PowerShell commands are logged in Event ID 4104 (if Script Block Logging enabled)
- But exporting logs themselves is not audited
- Remoting is common for IT admins (not suspicious)
- **Evasion:** Remote collection is largely undetected unless WinRM is monitored

**References & Proofs:**
- [Search-UnifiedAuditLog Cmdlet](https://learn.microsoft.com/en-us/powershell/module/exchange/search-unifiedauditlog)
- [Azure CLI Activity Log Query](https://learn.microsoft.com/en-us/cli/azure/monitor/activity-log)
- [Get-WinEvent Remote Collection](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)

---

## 7. TOOLS & COMMANDS REFERENCE

#### [Event Viewer (`eventvwr.msc`)](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging)

**Version:** Built-in (all Windows versions)
**Platforms:** Windows Server 2016-2025, Windows 10-11

**Usage:**
```powershell
# Open Event Viewer GUI
eventvwr.msc

# Or: Export logs via command line
wevtutil epl Security "C:\temp\Security.evtx"

# Query logs with PowerShell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)]]" -MaxEvents 100
```

#### [Search-UnifiedAuditLog (PowerShell)](https://learn.microsoft.com/en-us/powershell/module/exchange/search-unifiedauditlog)

**Version:** Part of Exchange Online PowerShell module v2.x
**Platforms:** Windows, macOS, Linux (PowerShell 7+)

**Installation:**
```powershell
Install-Module ExchangeOnlineManagement -Force
Connect-ExchangeOnline
```

**Usage:**
```powershell
$results = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) -ResultSize 5000
$results | Select-Object CreationDate, UserId, Operations | Export-Csv "audit.csv"
```

#### [Azure CLI (`az monitor activity-log`)](https://learn.microsoft.com/en-us/cli/azure/monitor/activity-log)

**Version:** 2.50+ (current)
**Platforms:** Windows, macOS, Linux

**Installation:**
```bash
# macOS
brew install azure-cli

# Linux (Ubuntu/Debian)
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Windows (PowerShell)
Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile AzureCLI.msi
Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'
```

**Usage:**
```bash
az login
az monitor activity-log list --start-time 2026-01-01 --end-time 2026-01-10 --output json > activity_log.json
```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Bulk Export of Audit Logs

**Rule Configuration:**
- **Required Table:** AuditLogs, LAQueryLogs
- **Required Fields:** ActionType, RecordCount, User, IpAddress
- **Alert Severity:** High
- **Frequency:** Every 10 minutes
- **Applies To Versions:** All Sentinel-integrated environments

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Search-UnifiedAuditLog" or OperationName == "Export audit log"
| where Result == "Success"
| summarize ExportCount = count(), TotalRecords = sum(ResultCount) by UserPrincipalName, IpAddress
| where ExportCount > 3 // Multiple exports by same user = suspicious
| project UserPrincipalName, IpAddress, ExportCount, TotalRecords
```

**What This Detects:**
- Multiple audit log exports by same user in short timeframe
- Export of large record counts (indicates comprehensive data theft)
- Export from unusual IP address (if baseline established)

**Manual Configuration (Azure Portal):**
1. **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Set name: `Audit_Log_Bulk_Export_Detection`
3. Paste KQL query above
4. Run every: 10 minutes
5. Alert threshold: > 0 results
6. Create rule

---

## 10. WINDOWS EVENT LOG MONITORING

**Event IDs to Monitor:**
- **1100:** Event log service shut down / cleared
- **1102:** Audit log was cleared
- **4624:** Successful logon
- **4625:** Failed logon attempt
- **4720:** User account created
- **4722:** User account enabled
- **4738:** User account changed
- **5140:** File share accessed
- **5145:** File share object accessed

**Manual Configuration (Group Policy):**
1. Open **Group Policy Management** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Audit Policy**
3. Enable:
   - "Audit account logon events" (Success and Failure)
   - "Audit account management" (Success)
   - "Audit logon events" (Success and Failure)
   - "Audit object access" (Success and Failure)
4. Run `gpupdate /force` and restart

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Restrict Audit Log Access:** Limit who can access, export, and search audit logs. Only Security and Audit teams should have access.

    **Manual Steps (Windows):**
    1. Open **Local Group Policy** (gpmc.msc) or domain Group Policy
    2. Add Audit group to **"Manage auditing and security log"** permission: Right-click policy → **Properties** → **Edit** → Go to **Permissions**
    3. Allow only Security group to read Event Viewer security logs

    **Manual Steps (M365):**
    1. Go to **Microsoft Purview** → **Audit**
    2. Click **"Audit retention policies"**
    3. Verify only **Compliance Administrator** and **Security Administrator** roles can access audit logs
    4. Go to **Permissions** → **Audit Log Search** → Verify only authorized roles assigned

    **Manual Steps (Azure):**
    1. Navigate to **Azure Portal** → **Activity Log** → **Access Control (IAM)**
    2. Remove **"Log Analytics Reader"** role from non-Security users
    3. Keep only **"Security Reader"** and **"Security Administrator"** roles

*   **Enable Audit Log Retention:** Set audit log retention to maximum allowed (10 years M365, 7-12 years Azure with archive).

    **Manual Steps (M365):**
    1. **Microsoft Purview** → **Audit** → **Audit retention policies**
    2. Create policy: **"Retain all M365 audit logs for 10 years"**
    3. Set: Days to retain = 3650 (10 years)
    4. Enable **"Create alert for retention policy updates"**

    **Manual Steps (Azure):**
    1. **Azure Portal** → **Monitor** → **Log Analytics workspaces**
    2. Select workspace → **Usage and estimated costs** → **Data Retention**
    3. Set to: **Retention (days)** = 2555 (7 years)
    4. Enable **"Archive with cold storage"** for long-term retention

    **Manual Steps (Windows):**
    1. **Local Security Policy** (secpol.msc) → **Event Log** → **Security**
    2. Set **"Maximum log size"** = 100 MB (or larger, depends on disk space)
    3. Set **"Retain"** = **"As needed"** (never overwrite, only clear manually)

*   **Enable Audit Log Alerts:** Configure alerts for access to sensitive audit logs.

    **Manual Steps:**
    1. Create Sentinel rule: "Access to Audit Logs by Non-SOC Users"
    2. Create Conditional Access policy requiring MFA for Purview access
    3. Monitor Event ID 1100, 1102 (log clear/shutdown) – any occurrence is critical alert

### Priority 2: HIGH

*   **Implement Immutable Audit Logs:** Use Azure Storage immutable backup for critical audit logs (cannot be deleted even by Global Admin).

    **Manual Steps:**
    1. Create Azure Storage account
    2. Enable **"Immutable storage"** on blob container
    3. Configure M365 / Azure to export audit logs to this storage account
    4. Verify: Container properties → **"Legal hold"** or **"Time-based retention"** enabled

*   **Monitor Audit Log Deletion:** Alert on any attempt to delete, clear, or disable audit logs.

    **Manual Steps:**
    1. Create Sentinel alert for Event ID 1102 (log cleared)
    2. Create Sentinel alert for "Audit log deletion" operations in Azure Activity Log
    3. Create Sentinel alert for "Disable-OrganizationCustomization" (disables M365 audit)

### Validation Command (Verify Fix)

```powershell
# Verify audit log retention is set to maximum
Get-UnifiedAuditLogRetentionPolicy | Select-Object Name, RetentionDays

# Expected: > 2000 days (5+ years minimum)

# Verify only Security group can access Event Viewer logs
Get-Acl "C:\Windows\System32\Winevt\Logs\Security.evtx" | Select-Object Owner, Access

# Expected: SYSTEM and Security group only
```

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Files:**
    - `.evtx` export files: `Security.evtx`, `audit.evtx` in unexpected locations
    - CSV exports from Purview: `AuditLog_*.csv`, `activity-log-export.csv`

*   **Registry:**
    - HKLM\System\CurrentControlSet\Services\EventLog\Security (log size changed)

*   **Network:**
    - PowerShell remoting to multiple servers (suspicious -ComputerName pattern)
    - HTTPS POST to compliance.microsoft.com (Purview audit export)

*   **Cloud:**
    - `SearchQueryInitiatedAdmin` event in Unified Audit Log (user searching audit logs)
    - `ExportUnifiedAuditLog` event in Unified Audit Log
    - Activity Log entries showing "Microsoft.Insights/diagnosticSettings/write" (logging changed)

### Forensic Artifacts

*   **Disk:**
    - Prefetch files for `eventvwr.exe`, `powershell.exe` show recent execution
    - Temporary files in `C:\temp\`, `C:\users\[user]\downloads\` contain exported audit logs
    - MFT timestamps show when exports occurred

*   **Memory:**
    - Bearer tokens for M365 / Azure API calls in PowerShell process memory

*   **Cloud:**
    - `SearchQueryInitiatedAdmin` events in Unified Audit Log show who searched audit logs, when, and what queries
    - `ExportUnifiedAuditLog` event shows export timestamp and result count
    - Azure Activity Log shows "List storage account keys" (attacker exfiltrating via storage)

### Response Procedures

1.  **Isolate:**
    ```powershell
    # Disable compromised user account
    Disable-AzADUser -ObjectId "compromised@company.com"
    ```

2.  **Collect Evidence:**
    ```powershell
    # Export all audit log searches by compromised user (last 30 days)
    Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -UserIds "compromised@company.com" | Export-Csv "incident_queries.csv"
    
    # Check for exported files
    Get-ChildItem -Path "C:\temp\", "C:\users\*\downloads\" -Filter "*audit*.csv", "*.evtx" -Recurse
    ```

3.  **Remediate:**
    - Change all M365 admin account passwords
    - Review all audit log exports in last 30 days (check Unified Audit Log for "ExportUnifiedAuditLog" events)
    - Delete any unauthorized Entra ID app registrations
    - Reset all bearer tokens / client secrets created in past 30 days

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Compromise admin account or insider threat |
| **2** | **Privilege Escalation** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) | Obtain audit log access via admin account |
| **3** | **Collection** | **[COLLECT-AUDIT-001]** | **Extract 90+ days of comprehensive audit logs** |
| **4** | **Exfiltration** | [T1020 - Automated Exfiltration](https://attack.mitre.org/techniques/T1020/) | Exfiltrate audit CSV files via email or cloud storage |
| **5** | **Impact** | [T1562.008 - Disable/Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008/) | Delete audit logs to cover tracks |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: Ransomware Gang Post-Breach Reconnaissance

- **Target:** Healthcare provider with 1,000+ employees
- **Timeline:** March 2024 - April 2024
- **Technique Status:** ACTIVE
- **Impact:** Attacker extracted 90 days of M365 audit logs, identified Global Admin accounts, discovered mail forwarding rules already in place (previous attacker), and escalated attack from encrypted data to exfiltration
- **Reference:** [Mandiant Ransomware Report 2024](https://www.mandiant.com/)

### Example 2: Insider Threat – Departing Employee

- **Target:** Financial services firm
- **Timeline:** June 2024 (single incident)
- **Technique Status:** ACTIVE
- **Impact:** Employee with SOC access exported 6 months of audit logs prior to resignation, sold intelligence to competitor
- **Reference:** [CISA Insider Threat Program Alert](https://www.cisa.gov/)

---

## 17. REFERENCES & ACKNOWLEDGMENTS

**Primary References:**
- [Microsoft Audit Log Documentation](https://learn.microsoft.com/en-us/purview/audit-solutions-overview)
- [Windows Event Log Reference](https://learn.microsoft.com/en-us/windows/win32/eventlog/)
- [Azure Activity Log Guide](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)
- [Search-UnifiedAuditLog Cmdlet Reference](https://learn.microsoft.com/en-us/powershell/module/exchange/search-unifiedauditlog)

---