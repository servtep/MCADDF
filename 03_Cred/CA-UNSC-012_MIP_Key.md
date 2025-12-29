# [CA-UNSC-012]: MIP Master Key Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-012 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | M365 / Purview |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Microsoft Information Protection (MIP) / Azure Information Protection (AIP) uses a Tenant Key (SLC) to encrypt protected documents. If an attacker gains `Information Protection Administrator` rights or compromises the Key Vault holding the "Customer Managed Key" (BYOK), they can decrypt ALL sensitive documents in the organization.
- **Attack Surface:** Purview / AIP Super User Group.
- **Business Impact:** **Total IP Theft**. Ability to read "Confidential" labeled documents.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Global Admin or Information Protection Admin.
- **Tools:**
    - [AIPService PowerShell](https://learn.microsoft.com/en-us/powershell/module/aipservice/)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Super User**
Add yourself to the AIP Super User feature (bypasses all label restrictions).
```powershell
Add-AipServiceSuperUser -EmailAddress attacker@target.com
```

**Step 2: Decrypt**
Use the `Unprotect-RMSFile` cmdlet to bulk decrypt files found on shares.
```powershell
Unprotect-RMSFile -Path "C:\Confidential\*.docx"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Audit Logs
| Source | Event | Filter Logic |
|---|---|---|
| **UnifiedAuditLog** | `Add-AipServiceSuperUser` | Critical alert. This should never happen outside scheduled maintenance. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Monitoring:** Create a high-priority alert for ANY changes to the AIP Super User list.
*   **Role Separation:** Ensure only a dedicated break-glass account holds the Info Protection Admin role.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [EXFIL-M365-001]
