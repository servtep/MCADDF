# [CA-UNSC-004]: NTFRS SYSVOL Replication Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-004 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Group Policy Preferences (T1552.006)](https://attack.mitre.org/techniques/T1552/006/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Older domains used NTFRS (File Replication Service) for SYSVOL replication. When migrated to DFSR (Distributed File System Replication), the old NTFRS folder structure is sometimes left behind in a "Deleted" state but still accessible. This legacy folder often contains old GPP XML files with passwords that were "deleted" from the live SYSVOL but persist in the backup.
- **Attack Surface:** Hidden/Legacy SYSVOL folders.
- **Business Impact:** **Credential Recovery**. Recovering passwords thought to be deleted.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Any Domain User.
- **Vulnerable Config:** Domains migrated from NTFRS to DFSR without full cleanup.
- **Tools:**
    - `dir /s /a` (Manual exploration)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check for Legacy Folders**
Look for `SYSVOL_DFSR` or `SYSVOL` (old) folders on Domain Controllers.
```cmd
dir \\DC01\C$\Windows\SYSVOL\domain\policies /s /b | findstr "Groups.xml"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 5140 | Access to non-standard SYSVOL paths. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Cleanup:** Ensure the NTFRS to DFSR migration process is completed with the `ELIMINATED` state, which removes the legacy folders.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-UNSC-003]
> **Next Logical Step:** [LAT-AD-001]
