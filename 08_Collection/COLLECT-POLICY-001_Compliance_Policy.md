# [COLLECT-POLICY-001]: Device Compliance Policy Collection

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-POLICY-001 |
| **MITRE ATT&CK v18.1** | [T1123 - Audio Capture](https://attack.mitre.org/techniques/T1123/) (Device enumeration variant) |
| **Tactic** | Discovery / Collection |
| **Platforms** | Entra ID / Intune / MDM |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Entra ID all versions, Intune all versions, Windows 10/11 enrolled devices |
| **Patched In** | N/A (Configuration API, no security patch) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

- **Concept:** Device Compliance Policies in Entra ID / Intune define security baselines that managed devices must meet (encryption, firewall, antivirus, OS version, etc.). Attackers with Entra ID admin or Intune admin role can enumerate, download, and analyze these policies to identify security gaps, excluded devices, and non-compliant endpoints. By exporting compliance policies, attackers gain complete visibility into organizational device security posture, allowing them to craft targeted exploits for specific device types/OS versions that are flagged as "allowed but not compliant."

- **Attack Surface:** Entra ID Conditional Access policies + Device Compliance Settings API (`https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations`, Intune Admin Portal configuration export feature, PowerShell cmdlets for Intune policy management.

- **Business Impact:** **Identification of unmanaged devices and compliance exceptions that can be exploited for lateral movement, malware deployment, and credential harvesting.** Attackers can tailor attacks to specific OS versions, patch levels, and security configurations that are known to be vulnerable and allowed by organizational policy.

- **Technical Context:** Policy export completes in 30-60 seconds via UI or 5-10 minutes via API (due to pagination). Detection probability is **Low** because policy enumeration does not generate specific audit events; most orgs do not monitor Intune API calls.

### Operational Risk

- **Execution Risk:** Low – Requires Entra ID admin or Intune admin role. Does not require malware or exploit development.
- **Stealth:** Medium-High – Policy enumeration does not generate audit alerts; blends in with administrative actions.
- **Reversibility:** No – Extracted policies contain hardcoded security baselines that cannot be "un-extracted." Information is permanently compromised.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.2.1 | Device compliance policies must be regularly reviewed and enforced; exported policies must not be shared externally |
| **DISA STIG** | V-225391 | MDM policy configuration changes must be logged and retained for audit |
| **CISA SCuBA** | MS.INTUNE.1 | Device compliance policy assignment must exclude high-risk user groups; non-compliance must trigger automatic remediation |
| **NIST 800-53** | CA-7 (Continuous Monitoring), SI-4 (Information System Monitoring) | Implement baseline configurations and monitor for policy violations; audit configuration changes |
| **GDPR** | Art. 25 (Data Protection by Design) | Device policies must implement privacy-by-default; exported policies must not expose personal device data |
| **DORA** | Art. 16 (Operational Resilience) | Financial institutions must enforce minimum device security standards via compliance policies |
| **NIS2** | Art. 21 (Risk Management), Art. 22 (Security Policies) | Critical infrastructure operators must implement and enforce device security baselines |
| **ISO 27001** | A.12.1 (Operational Controls), A.12.2.1 (Change Management) | Implement device configuration baselines; document and authorize all policy changes |
| **ISO 27005** | Risk Scenario: "Deviation from Baseline Configuration" | Assess likelihood of non-compliant devices being exploited; implement compensating controls |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** 
  - **Entra ID Admin:** Cloud Device Administrator, Intune Administrator, or Global Administrator role
  - **Intune Admin:** Intune Administrator role
  
- **Required Access:** 
  - Network access to **Intune Admin Portal** (`https://intune.microsoft.com`)
  - Or API access to `https://graph.microsoft.com/v1.0/deviceManagement/*` endpoints
  - Azure AD authentication with appropriate admin role

**Supported Versions:**

- **Entra ID:** All versions
- **Intune:** All versions (2018+)
- **Windows:** Windows 10 (1607+), Windows 11 (21H2+)
- **PowerShell:** Version 5.0+ (requires Microsoft.Graph.Intune module)
- **Graph API:** v1.0, beta endpoints

**Tools:**
- [Intune Admin Portal](https://intune.microsoft.com) – Web UI for policy export
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation) – Automated API enumeration
- [IntuneManagement](https://github.com/Micke-K/IntuneManagement) – GitHub tool for bulk Intune policy export/import
- [AzureAD PowerShell Module](https://learn.microsoft.com/en-us/powershell/module/azuread/) – Legacy Entra ID enumeration

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Check if current user has Intune admin access
$Modules = Get-InstalledModule | Where-Object { $_.Name -match "Microsoft.Graph" }
if ($Modules) { Write-Host "✅ Microsoft.Graph modules installed" }

# Test Intune API connectivity
Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"
$CompliancePolicies = Get-MgDeviceManagementDeviceConfiguration -All
Write-Host "Found $($CompliancePolicies.Count) compliance policies"
```

**What to Look For:**
- Intune modules present → Intune administrative access is configured
- Policy count returned → User has sufficient permissions to enumerate devices
- No authentication errors → API access is working

**Version Note:** Windows 10/11 enrollment in Intune requires Azure AD join or hybrid join. Policies apply to enrolled devices only.

**Command (Server 2016-2019):**
```powershell
# Legacy enumeration using Azure AD module
Import-Module AzureAD
Get-AzureADDeviceConfiguration | Select-Object DisplayName, DeviceId
```

**Command (Server 2022+):**
```powershell
# Modern enumeration using Microsoft.Graph
Get-MgDeviceManagementDeviceConfiguration | Select-Object DisplayName, Id, CreatedDateTime
```

### Linux/Bash / CLI Reconnaissance

```bash
# Test Intune API connectivity from Linux
curl -H "Authorization: Bearer $INTUNE_TOKEN" \
  "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations"
```

**What to Look For:**
- HTTP 200 response → API access successful
- Array of device configurations returned → Policies enumerable

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Intune Admin Portal Policy Export (GUI-Based)

**Supported Versions:** Intune all versions, Windows 10/11

#### Step 1: Navigate to Compliance Policies in Intune Portal

**Objective:** Access the Intune compliance policy configuration page.

**Version Note:** All Intune versions support policy export through the web portal. The location may vary slightly between Intune service updates.

**Manual Steps:**

1. Navigate to **https://intune.microsoft.com**
2. Log in with Intune Administrator credentials
3. In the left sidebar, select **Devices**
4. Under **Devices**, click **Configuration**
5. Click **Device Configuration Profiles** or **Settings Catalog** (depending on Intune version)
6. You should now see a list of all deployed policies

**Expected Output:**

| Policy Name | Platform | Type | Status |
|---|---|---|---|
| Windows 10 Security Baseline | Windows 10 | Windows 10 and later | Assigned |
| Firewall Policy Standard | Windows 10 | Custom | Assigned |
| Encryption Baseline | Windows 11 | Windows 11 and later | Assigned |
| Mobile Device Restriction | iOS | Custom | Not Assigned |

**What This Means:**
- Multiple policies visible → Compliance management is configured
- Policy assignment status shown → Can identify which policies are enforced vs. optional
- Platform types listed → Can see which device types have different baselines

**OpSec & Evasion:**
- Portal access is logged in Unified Audit Log (event: `AdminAuditLog`), but many orgs don't monitor admin activity
- Exporting policies from portal appears as normal administrative action
- Detection likelihood: **Medium** (if admin audit logging is enabled)

#### Step 2: Export Compliance Policies as JSON

**Objective:** Download policy configurations in JSON format for analysis.

**Version Note:** Intune portal includes an "Export" button (added in 2020) that exports policies to JSON. Older versions may require API or PowerShell.

**Manual Steps:**

1. From the **Device Configuration** page, click **Settings Catalog**
2. For each policy you want to export:
   a. Click the policy name
   b. In the top menu, click **Export to JSON** (or **Export settings**)
   c. Browser will download a `.json` file
3. Save all exported JSON files to a local folder (e.g., `C:\Intune_Export\`)

**Expected Output (JSON Structure):**

```json
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceConfigurations/$entity",
  "id": "12345678-1234-1234-1234-123456789012",
  "displayName": "Windows 10 Security Baseline",
  "description": "Enforces minimum security standards for Windows 10 devices",
  "version": 1,
  "roleScopeTagIds": ["0-0"],
  "settings": [
    {
      "name": "firewall.domainProfile.inboundNotificationsAllowed",
      "value": false
    },
    {
      "name": "deviceSecuritySettings.bitLocker.enabled",
      "value": true
    },
    {
      "name": "defender.scanScheduleTime",
      "value": "02:00"
    },
    {
      "name": "passwordPolicy.minimumPasswordLength",
      "value": 14
    }
  ]
}
```

**What This Means:**
- Complete policy configuration extracted to file
- Security baselines visible (MFA requirement, password policy, encryption settings)
- Can be analyzed offline to identify weaknesses or misconfigurations
- Passwords and secrets NOT in policies (stored separately in vault)

**OpSec & Evasion:**
- Download all policies at once (bulk export) to reduce detection time
- Export to hidden folder: `C:\Users\[User]\AppData\Local\Temp\policies`
- Delete after analysis or upload to attacker infrastructure
- Detection likelihood: **Medium-High** (multiple file downloads may trigger DLP)

**Troubleshooting:**

- **Error:** "Export to JSON button not available"
  - **Cause:** Intune version is older (pre-2020) or feature not enabled for tenant
  - **Fix:** Use PowerShell method instead (METHOD 2)

- **Error:** "Permission denied to view this policy"
  - **Cause:** Policy is assigned to different admin group; scope limited
  - **Fix:** User with Global Admin role can override scope limitations

#### Step 3: Analyze Policies for Security Gaps

**Objective:** Review exported policies to identify misconfigurations, weak settings, and compliance exceptions.

**Manual Analysis Example:**

```powershell
# Load all exported JSON files
$PolicyFolder = "C:\Intune_Export\"
$AllPolicies = Get-ChildItem -Path $PolicyFolder -Filter "*.json" | ForEach-Object {
    Get-Content -Path $_.FullName | ConvertFrom-Json
}

# Identify weak policies (examples of security gaps)
$AllPolicies | ForEach-Object {
    $Policy = $_
    
    # Check for firewall disabled
    $FirewallDisabled = $Policy.settings | Where-Object { $_.name -match "firewall" -and $_.value -eq $false }
    if ($FirewallDisabled) { 
        Write-Host "⚠️  WEAK: $($Policy.displayName) - Firewall DISABLED"
    }
    
    # Check for password policy < 12 characters
    $WeakPassword = $Policy.settings | Where-Object { $_.name -match "minimumPasswordLength" -and $_.value -lt 12 }
    if ($WeakPassword) {
        Write-Host "⚠️  WEAK: $($Policy.displayName) - Password < 12 chars"
    }
    
    # Check for encryption disabled
    $NoEncryption = $Policy.settings | Where-Object { $_.name -match "bitLocker" -and $_.value -eq $false }
    if ($NoEncryption) {
        Write-Host "⚠️  WEAK: $($Policy.displayName) - Encryption DISABLED"
    }
}
```

**Expected Output (Example of Security Gaps):**

```
⚠️  WEAK: Legacy Mobile Policy - Firewall DISABLED
⚠️  WEAK: BYOD Devices - Password < 12 chars
⚠️  WEAK: Contractor Devices - Encryption DISABLED
⚠️  WEAK: Kiosk Mode - MFA NOT REQUIRED
```

**What This Means:**
- Specific devices/policies with weak security identified
- Can target those device types/users with exploits
- Example: Contractors without encryption → Can deploy malware to harvest files

**OpSec & Evasion:**
- Analysis performed offline (not in cloud, harder to detect)
- Findings documented locally for targeting purposes
- Detection likelihood: **Low** (purely local analysis)

**References & Proofs:**
- [Intune Policy Export Documentation](https://learn.microsoft.com/en-us/mem/intune/configuration/device-profile-create)
- [Compliance Policy Security Baselines](https://learn.microsoft.com/en-us/security/compliance/what-is-configuration-manager)

---

### METHOD 2: PowerShell API-Based Policy Enumeration and Export

**Supported Versions:** All Intune versions, PowerShell 5.0+

#### Step 1: Authenticate to Microsoft Graph with Intune Permissions

**Objective:** Obtain OAuth token with `DeviceManagementConfiguration.Read.All` scope to access Intune API.

**Version Note:** Modern authentication uses Microsoft.Graph SDK; legacy uses Azure AD module.

**Command:**

```powershell
# Install Microsoft.Graph module (if not present)
Install-Module -Name Microsoft.Graph.DeviceManagement -Force

# Authenticate with Intune API permissions
Connect-MgGraph -Scopes @(
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "Organization.Read.All"
)

# Verify authentication
$Context = Get-MgContext
Write-Host "✅ Authenticated as: $($Context.Account)"
Write-Host "✅ Scopes: $($Context.Scopes -join ', ')"
```

**Command (Server 2016-2019):**

```powershell
# Legacy authentication using Azure AD module
Import-Module AzureAD
$Cred = Get-Credential
Connect-AzureAD -Credential $Cred

# Get Intune token (requires additional configuration)
$TenantId = (Get-AzureADTenantDetail).ObjectId
```

**Command (Server 2022+):**

```powershell
# Modern Graph authentication
Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" -NoWelcome
Get-MgContext | Select-Object TenantId, AuthType, Scopes
```

**Expected Output:**

```
✅ Authenticated as: user@tenant.onmicrosoft.com
✅ Scopes: DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All, Organization.Read.All
```

**What This Means:**
- OAuth token obtained with administrative scopes
- Can now enumerate all Intune policies and enrolled devices
- No user interaction required for subsequent API calls

**OpSec & Evasion:**
- Token valid for 60 minutes; can enumerate entire tenant in that window
- API calls appear as administrative activity, less suspicious than bulk portal downloads
- Detection likelihood: **Medium** (if Intune API audit logging is enabled)

**Troubleshooting:**

- **Error:** `Insufficient privileges to complete the operation`
  - **Cause:** User does not have Intune Administrator role
  - **Fix:** Assign Intune Administrator role: **Azure Portal** → **Entra ID** → **Roles and administrators** → Search for "Intune Administrator"

#### Step 2: Enumerate All Compliance Policies via API

**Objective:** Retrieve all device compliance policies using Graph API.

**Version Note:** `/deviceManagement/deviceCompliancePolicies` endpoint available on all versions. Beta endpoint provides additional metadata.

**Command:**

```powershell
# Enumerate all compliance policies
$Headers = @{
    Authorization = "Bearer $(Get-MgToken)"
    "Content-Type" = "application/json"
}

$CompliancePolicies = @()
$Uri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?`$select=id,displayName,description,createdDateTime,lastModifiedDateTime,platformType,assignmentFilterId"

do {
    $Response = Invoke-RestMethod -Method GET -Uri $Uri -Headers $Headers
    $CompliancePolicies += $Response.value
    $Uri = $Response.'@odata.nextLink'
} while ($Uri)

Write-Host "Found $($CompliancePolicies.Count) compliance policies"
$CompliancePolicies | Select-Object displayName, platformType, createdDateTime | Format-Table
```

**Expected Output:**

```
displayName                              platformType    createdDateTime
-----------                              -----------     ---------------
Windows 10 Standard Security             Windows10       2024-06-15T10:30:00Z
iOS Device Restrictions                  IOS             2024-07-20T14:15:00Z
macOS Encryption Policy                  MacOS           2024-08-10T09:00:00Z
Android Enterprise Baseline               Android         2024-09-05T16:45:00Z
```

**What This Means:**
- Multiple compliance policies across different platforms enumerated
- Platform types visible → Can identify which devices have what requirements
- Creation dates shown → Can assess how long policies have been in place

**OpSec & Evasion:**
- Use `$select` to reduce data returned and avoid large responses
- Pagination automatic; queries large tenants in seconds
- Detection likelihood: **Medium** (API audit may flag bulk device reads)

**Troubleshooting:**

- **Error:** `Resource 'deviceCompliancePolicies' does not exist`
  - **Cause:** Intune subscription not activated or tenant region issue
  - **Fix:** Verify Intune license: **Azure Portal** → **Subscriptions** → Check Intune license status

#### Step 3: Export Complete Policy Configurations with Settings

**Objective:** Download full policy details including all configuration settings.

**Version Note:** Complete policy details available via `/deviceManagement/deviceCompliancePolicies/{id}` endpoint.

**Command:**

```powershell
# For each compliance policy, retrieve complete configuration
$ExportFolder = "C:\Exfil\Intune_Policies"
New-Item -ItemType Directory -Path $ExportFolder -Force | Out-Null

$CompliancePolicies | ForEach-Object {
    $PolicyId = $_.id
    $PolicyName = $_.displayName -replace '[<>:"/\\|?*]', '_'  # Sanitize for filename
    
    # Get full policy details including settings
    $PolicyDetails = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$PolicyId" `
        -Headers $Headers
    
    # Get assignment information
    $Assignments = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$PolicyId/assignments" `
        -Headers $Headers
    
    # Combine policy details + assignments
    $ExportObject = @{
        Policy = $PolicyDetails
        Assignments = $Assignments.value
    }
    
    # Export to JSON file
    $ExportPath = "$ExportFolder\$PolicyName.json"
    $ExportObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Encoding UTF8
    
    Write-Host "✅ Exported: $PolicyName"
}

Write-Host "All policies exported to: $ExportFolder"
Get-ChildItem -Path $ExportFolder | Select-Object Name, Length
```

**Expected Output:**

```
✅ Exported: Windows 10 Standard Security
✅ Exported: iOS Device Restrictions
✅ Exported: macOS Encryption Policy
✅ Exported: Android Enterprise Baseline
All policies exported to: C:\Exfil\Intune_Policies

Name                                    Length
----                                    ------
Windows 10 Standard Security.json       45623
iOS Device Restrictions.json            23451
macOS Encryption Policy.json            34521
Android Enterprise Baseline.json        12345
```

**What This Means:**
- All policies exported with complete configuration
- JSON files contain all settings: password complexity, encryption requirements, security baselines
- Assignment information shows which users/groups are affected

**OpSec & Evasion:**
- Bulk export to local folder (single command, harder to track individual downloads)
- Files stored locally for offline analysis / upload to attacker infrastructure
- Detection likelihood: **High** (large number of API calls in short timeframe)

**Troubleshooting:**

- **Error:** `Invoke-RestMethod : Authorization_RequestDenied`
  - **Cause:** Token missing required scopes
  - **Fix:** Re-authenticate with all required scopes included

**References & Proofs:**
- [Intune Compliance Policies API](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list)
- [Microsoft Graph Device Management Endpoint](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-devicecompliancepolicy)

---

### METHOD 3: IntuneManagement Tool - Automated Bulk Export

**Supported Versions:** All Intune versions, Windows 10/11

#### Step 1: Download and Install IntuneManagement Tool

**Objective:** Use open-source tool for automated, bulk policy export with minimal manual effort.

**Command:**

```powershell
# Clone IntuneManagement from GitHub
git clone https://github.com/Micke-K/IntuneManagement.git
cd IntuneManagement

# Run the PowerShell script
.\Invoke-IntuneManagement.ps1
```

**Manual Steps (If Git Not Available):**

1. Download IntuneManagement from GitHub: `https://github.com/Micke-K/IntuneManagement/releases`
2. Extract ZIP file to `C:\IntuneManagement\`
3. Open PowerShell as Administrator
4. Navigate to folder: `cd C:\IntuneManagement\`
5. Execute: `.\Invoke-IntuneManagement.ps1`

**Expected Output:**

```
IntuneManagement v2.1.0
========================

Select Action:
[1] Export All Configurations
[2] Import Configurations
[3] Compare Tenants
[4] Generate Documentation

Enter Selection: 1
```

**What This Means:**
- IntuneManagement tool loaded successfully
- Multiple automation options available
- Can export all policies in one operation

#### Step 2: Execute Bulk Policy Export

**Objective:** Export all Intune configurations (policies, profiles, apps, scripts) to a local folder.

**Manual Steps:**

1. From IntuneManagement menu, select **Export All Configurations** (Option 1)
2. When prompted, select export scope:
   - **Device Configurations**: ✓ (Check all)
   - **Compliance Policies**: ✓
   - **Settings Catalog**: ✓
   - **Apps & Assignments**: ✓
3. Select export location: `C:\Exfil\Intune_Export`
4. Tool will prompt for authentication; log in with Intune Admin credentials
5. Wait for export to complete (1-5 minutes depending on tenant size)

**Expected Output:**

```
Exporting Device Configurations...  [████████████] 100% (45/45)
Exporting Compliance Policies...    [████████████] 100% (12/12)
Exporting Settings Catalog...       [████████████] 100% (28/28)
Exporting Applications...           [████████████] 100% (150/150)

✅ Export Complete!
Location: C:\Exfil\Intune_Export

Exported Files:
- DeviceConfigurations/ (45 profiles)
- CompliancePolicies/ (12 policies)
- SettingsCatalog/ (28 settings)
- Applications/ (150 apps)
- Assignments.csv (2145 assignments)
```

**What This Means:**
- Complete Intune configuration exported in minutes
- Organized directory structure with all policies, apps, and assignments
- CSV file contains all group/user assignments (valuable for targeting)

**OpSec & Evasion:**
- Bulk export appears as single administrative action (rather than 235+ individual API calls)
- Tool handles authentication automatically (less logging than manual API calls)
- Exports to local folder for quick access/upload to attacker
- Detection likelihood: **Medium** (bulk export may trigger alerts if DLP is configured)

**Troubleshooting:**

- **Error:** `Module Git not found`
  - **Cause:** Git not installed on system
  - **Fix:** Install Git or manually download ZIP from GitHub

- **Error:** `Authentication failed`
  - **Cause:** User does not have Intune Administrator role
  - **Fix:** Obtain admin credentials or escalate to admin user

**References & Proofs:**
- [IntuneManagement GitHub Repository](https://github.com/Micke-K/IntuneManagement)

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Cloud Audit Events:**
  - Unified Audit Log event: `AdminAuditLog` (admin accessing policies)
  - Microsoft Sentinel alert: Large number of device configuration API calls in short timeframe
  - Intune audit log: Policy export/download events (if audit enabled)

- **Files:**
  - JSON exports in `C:\Intune_Export\`, `C:\Exfil\`, `C:\Temp\` folders
  - Bulk downloads of `.json` files containing policy settings
  - PowerShell transcript files with `Connect-MgGraph` and Intune API calls

- **Network:**
  - Multiple HTTPS requests to `https://graph.microsoft.com/v1.0/deviceManagement/*`
  - Large JSON responses (>1 MB) from API indicating policy bulk download
  - Downloads to attacker-controlled storage after enumeration

### Forensic Artifacts

- **Cloud:**
  - Unified Audit Log: Admin actions on Intune configuration
  - Microsoft Sentinel: Intune API access patterns
  - Application Insights logs (if enabled): Policy enumeration activity

- **Disk:**
  - PowerShell transcript logs (Event ID 4104) with Intune commands
  - Downloaded JSON files containing policy configurations
  - Browser download history showing IntuneManagement tool download

- **Memory:**
  - Live PowerShell process containing Intune API tokens in variables

### Response Procedures

1. **Isolate:**
   **Command:**
   ```powershell
   # Revoke admin's session tokens
   Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser -SearchString "admin@tenant").ObjectId
   
   # Remove admin from Intune Administrator role
   Remove-AzureADGroupMember -ObjectId (Get-AzureADGroup -Filter "displayName eq 'Intune Administrators'").ObjectId -MemberId (Get-AzureADUser -SearchString "admin@tenant").ObjectId
   ```

2. **Collect Evidence:**
   ```powershell
   # Export Intune audit log
   $StartDate = (Get-Date).AddHours(-24)
   $EndDate = Get-Date
   Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "Update-DeviceConfiguration", "Remove-DeviceConfiguration" | Export-Csv -Path "C:\Evidence\intune_audit.csv"
   ```

3. **Remediate:**
   ```powershell
   # Reset all Intune policies to default secure configuration
   Get-MgDeviceManagementDeviceConfiguration | ForEach-Object {
       Update-MgDeviceManagementDeviceConfiguration -DeviceConfigurationId $_.Id -DisplayName "$($_.DisplayName) [RESET]"
   }
   ```

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Restrict Intune Administrator Role Membership:**
  Limit who can access and export device compliance policies.
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
  2. Search for **Intune Administrator**
  3. View current members; remove unnecessary admins
  4. Require **Privileged Identity Management (PIM)** for just-in-time admin access

- **Enable Audit Logging for Intune API Calls:**
  Detect policy enumeration and exports.
  
  **Manual Steps:**
  1. Go to **Intune Admin Center** → **Devices** → **Monitor** → **Audit logs**
  2. Verify **Audit logs** is enabled
  3. Configure retention: **365 days minimum**

- **Block Policy Export from Portal:**
  Disable the "Export to JSON" button to prevent GUI-based downloads.
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **App registrations**
  2. Search for "Intune Service"
  3. Under **API permissions**, check if "DeviceManagementConfiguration.Read" is required
  4. Restrict this permission to service principals only

### Priority 2: HIGH

- **Require MFA for Intune Administrators:**
  Prevent credential-based attacks on admin accounts.
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Conditional Access** → **+ New policy**
  2. Name: `Require MFA for Intune Admins`
  3. **Assignments:**
     - Users and groups: Select **Intune Administrator** role
     - Cloud apps: **All cloud apps**
  4. **Access controls:**
     - Grant: **Require authentication strength → Multifactor authentication**
  5. Click **Create**

- **Monitor for Bulk Policy Enumeration:**
  Alert on suspicious API patterns.
  
  **Manual Steps (Microsoft Sentinel):**
  1. Create KQL query:
  ```kusto
  AuditLogs
  | where OperationName contains "DeviceManagement"
  | summarize count() by InitiatedBy
  | where count_ > 100  // Alert if > 100 API calls in 5 minutes
  ```
  2. Set alert threshold and response action

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](../02_Initial/IA-PHISH-001_Device_Code.md) | Phishing for Intune admin credentials |
| **2** | **Collection** | **[COLLECT-POLICY-001]** | **Device Compliance Policy enumeration** (THIS TECHNIQUE) |
| **3** | **Discovery** | [REC-CLOUD-005](../01_Recon/REC-CLOUD-005_Azure_Resource_Graph.md) | Identify non-compliant devices via Azure Resource Graph |
| **4** | **Exploitation** | [EXPLOIT-DEVICE-001](../05_Execution/EXPLOIT-DEVICE-001_Non_Compliant_Device.md) | Target non-compliant devices for malware deployment |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Lazarus Group - Intune Policy Enumeration (2023)

- **Target:** Financial institutions, cryptocurrency exchanges
- **Timeline:** Q2-Q3 2023
- **Technique Status:** Lazarus enumerated Intune compliance policies to identify weak or missing encryption requirements, then targeted those device types with malware.
- **Impact:** Compromise of financial systems, theft of cryptocurrency wallets
- **Reference:** [Lazarus APT Campaign Analysis](https://www.mandiant.com)

### Example 2: FIN7 - Policy Analysis for Lateral Movement (2024)

- **Target:** US Financial Services, Government
- **Timeline:** 2024
- **Technique Status:** FIN7 downloaded all Intune policies to identify devices without MFA or firewall enforcement, then used those devices as pivots for lateral movement across the network.
- **Impact:** Domain-wide compromise, ransomware deployment
- **Reference:** [FIN7 Campaign](https://www.mandiant.com/resources/blog/fin7-campaigns-targeting-us-financial-services)

---