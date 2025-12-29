# [CA-TOKEN-018]: Cloud-to-Cloud Token Compromise

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-018 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Cross-Cloud (AWS <-> Azure) |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** With Workload Identity Federation, AWS workloads use their own metadata service (IMDS) to get a signed JWT (`sts:GetCallerIdentity` or similar) and exchange it for an Azure Token. If an attacker compromises the AWS workload (SSRF/RCE), they can perform this exchange manually to access Azure resources.
- **Attack Surface:** AWS Metadata Service.
- **Business Impact:** **Cross-Cloud Pivot**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** RCE on AWS EC2.
- **Tools:** `curl`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Get AWS Identity Token**
(Depends on AWS IMDS version).

**Step 2: Exchange for Azure Token**
```bash
# This is the "subject" token for the Azure exchange
AZURE_TOKEN=$(curl -X POST ...)
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `FederatedCredential` | Sign-in where the issuer is `aws.amazon.com`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Subject Validation:** When configuring the Trust in Azure, strictly validate the `sub` claim (Subject) to ensure only the *specific* AWS Role/Instance Profile can authenticate, not *any* workload in the AWS account.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-003]
> **Next Logical Step:** [LAT-CLOUD-001]
