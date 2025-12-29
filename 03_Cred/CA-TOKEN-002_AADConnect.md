# [CA-TOKEN-002]: Azure AD Connect Credential Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-002 |
| **MITRE ATT&CK v18.1** | [Credentials from Password Stores (T1555)](https://attack.mitre.org/techniques/T1555/) |
| **Tactic** | Credential Access |
| **Platforms** | Hybrid AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure AD Connect stores the credentials for the `MSOL_` account (used to replicate to Azure) and the `ADSync` account (used to read from AD) in a LocalDB database encrypted with DPAPI. An attacker with Local Admin rights can extract these credentials. The `MSOL_` account has powerful "Directory Synchronization" rights in the cloud.
- **Attack Surface:** ADSync Database (`(localdb)\.\ADSync`).
- **Business Impact:** **Cloud Takeover**. The `MSOL_` account can be used to set the "ImmutableID" of users, facilitating a Golden SAML attack (Source Anchor modification).

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Local Admin on AADC Server.
- **Tools:**
    - [AADInternals](https://github.com/Gerenios/AADInternals)
    - [AdSyncDecrypt](https://github.com/AdSyncDecrypt)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extract Credentials**
```powershell
# AADInternals
Get-AADIntSyncCredentials -Extract
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Sync Service` | Sign-ins by the Sync Account from unexpected IPs (not the AADC server). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Access Control:** Restrict Local Admin access to the AADC server strictly.
*   **Rotation:** Rotate the AADC service account credentials regularly.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-001]
> **Next Logical Step:** [LAT-CLOUD-002]
