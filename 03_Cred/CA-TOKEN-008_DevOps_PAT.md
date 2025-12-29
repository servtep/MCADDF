# [CA-TOKEN-008]: Azure DevOps PAT Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-008 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure DevOps |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Personal Access Tokens (PATs) are used to authenticate to Azure DevOps. They are often cached in plain text or base64 in the user's home directory (e.g., `.azure/azureProfile.json` or `.git-credentials`).
- **Attack Surface:** User Workstation Filesystem.
- **Business Impact:** **Source Code Compromise**. Access to repos, pipelines, and potentially production deployment triggers.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Access.
- **Tools:**
    - `cat` / `grep`
    - [Snaffler](https://github.com/SnaffCon/Snaffler)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Discovery**
Check common locations.
```bash
# Windows
type %USERPROFILE%\.azure\azureProfile.json
type %USERPROFILE%\.git-credentials

# Linux
cat ~/.azure/azureProfile.json
```

**Step 2: Abuse**
Use the PAT to authenticate.
```bash
echo $PAT | az devops login
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 ADO Auditing
| Source | Event | Filter Logic |
|---|---|---|
| **Auditing** | `PAT Usage` | PAT usage from an IP different than the creator's IP. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Policy:** Enforce short-lived PATs.
*   **Conditional Access:** Apply CAPs to Azure DevOps (e.g., restrict access to compliant devices), rendering stolen PATs useless on attacker machines.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-004]
> **Next Logical Step:** [CA-UNSC-016]
