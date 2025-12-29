# [CA-STORE-004]: Browser Saved Credentials Harvesting

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-STORE-004 |
| **MITRE ATT&CK v18.1** | [Credentials from Password Stores: Credentials from Web Browsers (T1555.003)](https://attack.mitre.org/techniques/T1555/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Modern browsers (Chrome, Edge) encrypt saved passwords using the user's DPAPI keys. Attackers execute tools in the user's context to decrypt the SQLite databases (`Login Data`) where these are stored.
- **Attack Surface:** `AppData` directory files.
- **Business Impact:** **SaaS Compromise**. Access to M365, AWS, Salesforce, and other cloud portals.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Access.
- **Tools:**
    - [LaZagne](https://github.com/AlessandroZ/LaZagne)
    - [SharpChrome](https://github.com/GhostPack/SharpDPAPI)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extraction**
Run SharpChrome to dump passwords.
```powershell
.\SharpChrome.exe cookies
.\SharpChrome.exe logins
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4663 | Access to `Login Data` or `Cookies` file by non-browser process. |

#### 5.2 Sentinel (KQL)
```kusto
FileReadEvents
| where FileName in ("Login Data", "Cookies")
| where ProcessName !in ("chrome.exe", "msedge.exe")
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **GPO:** Set "Enable saving passwords to the password manager" to **Disabled** for Edge/Chrome.
*   **Endpoint DLP:** Block read access to browser profile folders by unknown binaries.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005]
> **Next Logical Step:** [REC-M365-001]
