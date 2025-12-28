# [CA-DUMP-009]: Mapped Drive Credential Exposure

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-009 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Registry (T1552.002)](https://attack.mitre.org/techniques/T1552/002/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Users often map network drives with specific credentials (different from their logon user) for accessing legacy shares or NAS devices. These credentials can be stored in the Registry (`HKCU\Network`) or Credential Manager.
- **Attack Surface:** `HKCU\Network` and `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`.
- **Business Impact:** **Lateral Movement**. Capture of plaintext passwords for shared resources.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Access (Interactive or Remote Execution).
- **Vulnerable Config:** Users manually checking "Connect using different credentials".
- **Tools:**
    - `reg query`
    - PowerShell

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Enumeration**
Check for mapped drives in the registry.
```powershell
Get-ItemProperty -Path "HKCU:\Network\*" | Select-Object RemotePath, UserName, ProviderName
```

**Step 2: Retrieval**
If credentials are not null, they might be stored in the Windows Credential Manager linked to the `RemotePath`.
```cmd
cmdkey /list
```
*Note: Directly extracting the password requires `Mimikatz` (dpapi module) to unprotect the blob found in Cred Manager.*

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4663 | Access to `HKCU\Network` keys. |

#### 5.2 Sentinel (KQL)
```kusto
// Rare, usually looking for process behavior
ProcessCreationEvents
| where ProcessCommandLine has "reg" and ProcessCommandLine has "HKCU\\Network"
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Policy:** Enforce Drive Mapping via GPO using **Item-Level Targeting** with the logged-on user's context, rather than hardcoded credentials.
*   **Credential Guard:** Helps protect the DPAPI Master Key used to encrypt these entries.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005]
> **Next Logical Step:** [LAT-SMB-001] (Accessing the share)
