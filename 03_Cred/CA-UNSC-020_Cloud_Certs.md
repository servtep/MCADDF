# [CA-UNSC-020]: Multi-Cloud Federation Certs Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-020 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Private Keys (T1552.004)](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Cross-Cloud (AWS/GCP <-> Azure) |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Organizations often use "Workload Identity Federation" (OIDC) to allow AWS or GCP workloads to access Azure resources without secrets. However, if the trust is configured using **X.509 Certificates** (Self-Signed) stored on the AWS/GCP instance instead of OIDC, stealing that certificate allows an attacker to authenticate as the Azure Service Principal from anywhere.
- **Attack Surface:** AWS EC2 / GCP Compute Instances.
- **Business Impact:** **Cross-Cloud Pivot**. Compromising AWS leads to Azure compromise.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Root on the source cloud VM.
- **Tools:**
    - `cat` / `ssh`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Discovery**
Look for `.pem` files used by Azure CLI/SDK scripts on the AWS box.
```bash
find / -name "*.pem" 2>/dev/null
```

**Step 2: Authentication**
Login to Azure using the stolen cert.
```bash
az login --service-principal -u <AppID> -p <PathToPEM> --tenant <TenantID>
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | ServicePrincipal | Sign-in using Certificate from an IP address that does not belong to the expected AWS/GCP range. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **OIDC:** Deprecate certificate-based federation for cloud workloads. Use **Workload Identity Federation** (OIDC) which relies on the cloud provider's ephemeral tokens, eliminating the need to manage/store certificates.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-003] (AWS Compromise)
> **Next Logical Step:** [LAT-CLOUD-001] (Azure Entry)
