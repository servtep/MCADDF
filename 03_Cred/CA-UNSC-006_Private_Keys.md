# [CA-UNSC-006]: Private Keys Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-006 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Private Keys (T1552.004)](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows / Linux / M365 |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Attackers search file systems and code repositories for unencrypted private keys (`.pem`, `.ppk`, `.pfx`). In cloud environments, this extends to searching for SSH keys inadvertently stored in cloud storage or accessible via metadata services.
- **Attack Surface:** Local file systems (`~/.ssh`), File Shares, and DevOps repos.
- **Business Impact:** **Identity Cloning**. Possession of a private key often grants password-less access to servers (SSH) or allows signing malicious code/tokens.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Access.
- **Tools:**
    - [TruffleHog](https://github.com/trufflesecurity/trufflehog)
    - [Snaffler](https://github.com/SnaffCon/Snaffler)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Local Discovery (Linux/Windows)**
```bash
grep -r "BEGIN RSA PRIVATE KEY" /home/ 2>/dev/null
findstr /s /i "BEGIN RSA PRIVATE KEY" C:\Users\*.pem
```

**Step 2: Network Discovery (Snaffler)**
Scan file shares for key files.
```powershell
Snaffler.exe -s -d target.local -o results.txt
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Auditd** | `open` | Rapid access to multiple hidden files (`.ssh/*`, `.aws/*`). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Storage:** Enforce the use of Hardware Security Modules (HSM) or FIDO2 keys (YubiKey) where private keys never leave the hardware.
*   **Scanning:** Implement pre-commit hooks (git-secrets) to prevent committing keys to repos.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-004]
> **Next Logical Step:** [LAT-SSH-001]
