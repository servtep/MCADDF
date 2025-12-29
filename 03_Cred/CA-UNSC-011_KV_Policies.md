# [CA-UNSC-011]: Key Vault Access Policies Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-011 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Container API (T1552.007)](https://attack.mitre.org/techniques/T1552/007/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Legacy "Access Policies" in Key Vault grant broad permissions (e.g., "All Secrets") to a Principal. Unlike RBAC, you cannot scope this to individual secrets. If an attacker adds themselves to an Access Policy (requires `Microsoft.KeyVault/vaults/accessPolicies/write`), they gain access to EVERYTHING in that vault.
- **Attack Surface:** Key Vault Access Policies.
- **Business Impact:** **Privilege Escalation**. Gaining access to secrets they shouldn't see.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Contributor on the Key Vault resource.
- **Tools:**
    - Azure CLI / Portal

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Modify Policy**
Grant yourself full access.
```powershell
Set-AzKeyVaultAccessPolicy -VaultName "TargetKV" -UserPrincipalName attacker@target.com -PermissionsToSecrets get,list,set,delete
```

**Step 2: Harvest**
(See CA-UNSC-007)

## 5. DETECTION (Blue Team Operations)

#### 5.1 Activity Logs
| Source | Operation | Filter Logic |
|---|---|---|
| **ActivityLog** | `UpdateAccessPolicy` | Alert on any modification to Access Policies. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Switch to RBAC:** Change the Key Vault permission model to "Azure Role-Based Access Control" (RBAC). This disables Access Policies entirely and forces granular IAM.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [CA-UNSC-007]
