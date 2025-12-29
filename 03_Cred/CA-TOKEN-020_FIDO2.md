# [CA-TOKEN-020]: FIDO2 Resident Credential Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-020 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows / YubiKey |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** FIDO2 keys (like YubiKey) can store "Resident Keys" (Discoverable Credentials). While the private key is non-exportable, older firmware or side-channel attacks might allow cloning. More commonly, if an attacker has physical access and the PIN, they can use the key to authenticate.
- **Attack Surface:** Physical Security Key.
- **Business Impact:** **MFA Bypass**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Physical Access + PIN.
- **Tools:** `ykman`, `fido2-token`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Enumeration**
Check for resident keys.
```bash
ykman fido credentials list
```

**Step 2: Abuse**
Use the key to sign into Azure Portal (if PIN is known/sniffed).

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `FIDO2` | Sign-in from unexpected location. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Bio:** Enforce Biometric FIDO2 keys (e.g., YubiKey Bio) to prevent PIN-only theft usage.
*   **Attestation:** Use Intune to validate the FIDO2 key model/serial if possible (limited support currently).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHYSICAL-001]
> **Next Logical Step:** [LAT-CLOUD-001]
