# [CA-UNSC-019]: Federation Server Certificate Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-019 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Private Keys (T1552.004)](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Hybrid AD / ADFS |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Active Directory Federation Services (ADFS) uses a Token Signing Certificate to sign SAML tokens. If an attacker extracts the private key of this certificate from the ADFS server, they can forge SAML tokens for ANY user (Golden SAML) to access federated applications (including M365/Entra ID) without touching AD or ADFS again.
- **Attack Surface:** ADFS Server Database or Local Store.
- **Business Impact:** **Cloud Takeover (Golden SAML)**. Bypass MFA and gain Global Admin in Entra ID.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Local Admin on ADFS Server.
- **Tools:**
    - [ADFSDump](https://github.com/fireeye/ADFSDump)
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Export Key (ADFSDump)**
```cmd
ADFSDump.exe
```
*Output: Base64 encoded Private Key and Configuration details.*

**Step 2: Forge Token (Golden SAML)**
Use the key to sign a SAML assertion for the Administrator.
```bash
# Using shuriken or ADFSpoof
python3 adfs-spoof.py -b <Base64Key> -s <Issuer> ...
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Federated User` | Authentication using SAML where the token was issued *outside* the known ADFS IP range (impossible travel, but specific to token issuance). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **HSM:** Store the Token Signing Key in a **Hardware Security Module** (HSM). This prevents extraction of the private key, making Golden SAML impossible.
*   **Monitor:** Alert on any access to the ADFS service account's personal certificate store.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-001]
> **Next Logical Step:** [LAT-CLOUD-002] (Golden SAML)
