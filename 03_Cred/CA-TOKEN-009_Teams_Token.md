# [CA-TOKEN-009]: Teams Token Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-009 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint / M365 |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The Microsoft Teams desktop client stores authentication tokens (Skype token, Access token) in LevelDB/SQLite databases on disk. Historically these were plaintext; newer versions encrypt them with DPAPI. An attacker with local access can decrypt them to read chat history or send messages.
- **Attack Surface:** `%AppData%\Microsoft\Teams\` or `%LocalAppData%\Packages\MSTeams_...\`.
- **Business Impact:** **Internal Communication Compromise**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Access.
- **Tools:**
    - [TeamsTokenDumper](https://github.com/Author/Tool) (Hypothetical/Custom)
    - [Keytar](https://github.com/keytar)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Locate Cookie File**
```powershell
$Path = "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Default\Network\Cookies"
```

**Step 2: Decrypt (Custom Tool)**
Decrypt the `encrypted_value` column using the DPAPI key stored in `Local State`.

**Step 3: Abuse**
Use the `skypeToken` to query the chat API.
```bash
curl -H "Authentication: skype_token=$TOKEN" https://messenger.teams.microsoft.com/...
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Endpoint Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4663 | Access to Teams `Cookies` or `Local State` file by non-Teams processes. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **EDR:** Monitor access to the Teams data directory.
*   **Policy:** Shorten session lifetimes to minimize the window of opportunity for stolen tokens.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-VALID-001]
> **Next Logical Step:** [EXFIL-M365-001]
