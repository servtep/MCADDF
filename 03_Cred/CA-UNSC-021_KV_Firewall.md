# [CA-UNSC-021]: Key Vault Firewall Bypass

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-021 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Container API (T1552.007)](https://attack.mitre.org/techniques/T1552/007/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure Key Vault has a firewall to restrict access to specific IPs/VNETs. However, the setting **"Allow Trusted Microsoft Services"** allows any Azure resource (e.g., App Service, Cloud Shell) to bypass this firewall if it authenticates with a trusted identity. An attacker who compromises *any* Azure resource in the tenant (even one not explicitly whitelisted) can potentially pivot through this exception if RBAC/Access Policies are loose.
- **Attack Surface:** Key Vault Network Rules.
- **Business Impact:** **Perimeter Bypass**. Accessing a "Private" Key Vault from the public internet (via Azure Cloud Shell or a compromised App Service).

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Contributor on Key Vault (to enable bypass) or Control of a Trusted Service.
- **Tools:**
    - Azure Portal / CLI

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Configuration**
```bash
az keyvault network-rule show --name "TargetKV"
# Look for "bypass": "AzureServices"
```

**Step 2: Pivot**
If direct access is blocked (403 Forbidden), spin up an Azure Cloud Shell or Function App in the same tenant and attempt to access the vault from there.
```powershell
# From Cloud Shell (Trusted Service)
Get-AzKeyVaultSecret -VaultName "TargetKV"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Activity Logs
| Source | Event | Filter Logic |
|---|---|---|
| **KeyVault** | `SecretGet` | Successful access where `CallerIPAddress` belongs to Microsoft IP ranges, but the identity is suspicious. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Disable Bypass:** Set "Allow Trusted Microsoft Services" to **No** if strict isolation is required.
*   **RBAC:** Rely primarily on Identity (RBAC) rather than Network Rules for security. Network rules are a secondary layer.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [CA-UNSC-007]
