# [CA-TOKEN-006]: Service Principal Certificate Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-006 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Service Principals (App Registrations) can authenticate using X.509 certificates. If an attacker gains access to the `.pfx` or `.pem` file (via DevOps pipelines, file shares, or compromised developer machines), they can authenticate as the Service Principal indefinitely. Unlike passwords, certificates often have long expiration times (1-2 years).
- **Attack Surface:** Certificate Files.
- **Business Impact:** **Service Impersonation**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Read access to certificate file.
- **Tools:**
    - Azure CLI

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Authenticate**
```bash
az login --service-principal -u <AppID> -p <CertFile.pem> --tenant <TenantID>
```

**Step 2: Enumerate Permissions**
```bash
az ad sp show --id <AppID> --query "appRoles"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `ServicePrincipal` | Authentication using a certificate from an IP not associated with the application's known infrastructure. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Workload Identity:** Use **Workload Identity Federation** (OIDC) to eliminate the need for managing certificates for cloud-to-cloud scenarios (GitHub Actions, AWS, GCP).
*   **Key Vault:** Store certificates in Key Vault and use Managed Identities to access them, rather than keeping files on disk.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-UNSC-006]
> **Next Logical Step:** [LAT-CLOUD-001]
