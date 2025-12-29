# [CA-UNSC-010]: Service Principal Secrets Harvesting

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-010 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Private Keys (T1552.004)](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Application Registrations (Service Principals) use Certificates or Client Secrets for authentication. Unlike user passwords, these are often hardcoded in DevOps pipelines, local config files (`appsettings.json`), or inadvertently committed to Git.
- **Attack Surface:** Source Code, CI/CD Logs, and Local Configs.
- **Business Impact:** **Service Impersonation**. Allows the attacker to act as the application, often with broad Graph API permissions (e.g., `User.ReadWrite.All`).

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Read Access to code/configs.
- **Tools:**
    - [TruffleHog](https://github.com/trufflesecurity/trufflehog)
    - Manual Grep

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Discovery**
Search for Client Secret patterns (32-40 char Base64 strings).
```bash
grep -r "ClientSecret" .
```

**Step 2: Validation**
Test the secret against Entra ID.
```bash
az login --service-principal -u <AppID> -p <Secret> --tenant <TenantID>
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **SignInLogs** | ServicePrincipal | Sign-in from anomalous IP using the compromised AppID. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Rotation:** Rotate the compromised secret immediately in the Azure Portal.
*   **Managed Identity:** Replace Service Principals with **Managed Identities** wherever possible (eliminates credentials entirely).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-004]
> **Next Logical Step:** [EXFIL-CLOUD-001]
