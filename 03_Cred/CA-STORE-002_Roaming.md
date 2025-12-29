# [CA-STORE-002]: Credential Roaming Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-STORE-002 |
| **MITRE ATT&CK v18.1** | [Credentials from Password Stores (T1555)](https://attack.mitre.org/techniques/T1555/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** A legacy feature in Windows ("Credential Roaming") syncs user certificates and credentials to AD LDAP attributes (`msPKI-CredentialRoamingTokens`). Attackers can perform LDAP queries to retrieve these encrypted blobs. If they crack the user's password (or have the DAPI Master Key), they can decrypt these tokens, which often contain valid PFX files.
- **Attack Surface:** AD User Attributes (LDAP).
- **Business Impact:** **Certificate Theft**. Extraction of user certificates for persistence or authentication.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Authenticated User (Read access to own attributes or others depending on ACL).
- **Vulnerable Config:** Credential Roaming enabled (GPO).
- **Tools:**
    - [PowerView](https://github.com/PowerShellMafia/PowerSploit)
    - [Dirkjanm's Roaming Tools](https://github.com/dirkjanm/roaming)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Enumeration**
Check for the presence of roaming tokens.
```powershell
Get-DomainUser -Properties msPKI-CredentialRoamingTokens
```

**Step 2: Extraction & Decryption**
Extract the blob and decrypt (requires user password/hash).
```bash
# Using Python tool (dirkjanm)
python3 roaming_pki.py -u user -p password -d target.local
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4662 | Access to attribute `msPKI-CredentialRoamingTokens`. |

#### 5.2 Sentinel (KQL)
```kusto
SecurityEvent
| where EventID == 4662
| where Properties has "msPKI-CredentialRoamingTokens"
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **GPO:** Disable "Credential Roaming" in Group Policy.
    `User Configuration > Windows Settings > Security Settings > Public Key Policies > Certificate Services Client - Credential Roaming` (Set to "Not Configured" or "Disabled").
*   **Cleanup:** Clear the `msPKI-CredentialRoamingTokens` attribute for all users to remove stale data.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-VALID-001]
> **Next Logical Step:** [CA-KERB-009] (PKINIT with stolen cert)
