# [CA-UNSC-003]: SYSVOL GPP Credential Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-003 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Group Policy Preferences (T1552.006)](https://attack.mitre.org/techniques/T1552/006/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Group Policy Preferences (GPP) previously allowed admins to set local user passwords via GPO. These passwords were encrypted with a static AES key published by Microsoft (MS14-025). Attackers scan the `SYSVOL` share for `Groups.xml`, extract the `cpassword` attribute, and decrypt it instantly.
- **Attack Surface:** SYSVOL Share (`\\domain\SYSVOL`).
- **Business Impact:** **Local Admin / Domain Admin**. If the GPO sets the local admin password, attackers gain admin on every machine the GPO applies to.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Any Domain User.
- **Vulnerable Config:** Legacy GPOs created before KB2962486 (2014) that have not been deleted.
- **Tools:**
    - [Get-GPPPassword (PowerSploit)](https://github.com/PowerShellMafia/PowerSploit)
    - `gpp-decrypt`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Scan SYSVOL**
```powershell
findstr /S /I "cpassword" \\target.local\sysvol\*.xml
```

**Step 2: Automated (PowerView)**
```powershell
Get-GPPPassword
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 5140 | Access to `Groups.xml`, `Services.xml`, `ScheduledTasks.xml` in SYSVOL. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Cleanup:** Run a script to search for and DELETE all `Groups.xml` files containing `cpassword` in SYSVOL.
*   **LAPS:** Replace GPP password management with LAPS.

## 7. ATTACK CHAIN
> **Preceding Technique:** [REC-AD-003]
> **Next Logical Step:** [LAT-AD-001]
