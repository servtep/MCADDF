# [CA-UNSC-002]: /etc/sssd/sssd.conf Harvesting

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-002 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Linux / Unix |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The SSSD configuration file (`/etc/sssd/sssd.conf`) contains the domain join configuration. Historically, it sometimes stored the Bind Account password in cleartext (`ldap_default_authtok`). If permissions are weak, local users can read this password.
- **Attack Surface:** File permissions.
- **Business Impact:** **Service Account Compromise**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Read access to file.
- **Vulnerable Config:** `chmod 644` on `sssd.conf` containing `ldap_default_authtok`.
- **Tools:** `cat`, `grep`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Permissions & Content**
```bash
grep -i "authtok" /etc/sssd/sssd.conf
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Audit
| Source | Event ID | Filter Logic |
|---|---|---|
| **Auditd** | `open` | Unauthorized read of sssd.conf. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Permissions:** `chmod 600 /etc/sssd/sssd.conf`.
*   **Config:** Use Kerberos keytabs for bind authentication instead of cleartext passwords.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-004]
> **Next Logical Step:** [LAT-AD-001]
