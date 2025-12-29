# [CA-TOKEN-004]: Graph API Token Theft (Device Code Phishing)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-004 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | M365 / Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Attackers initiate an OAuth "Device Code Flow" for a legitimate application (like Microsoft Graph PowerShell). They present the victim with a code (`ABC-123`) to enter at `microsoft.com/devicelogin`. Once the victim authenticates, the attacker receives a Refresh Token (PRT) and Access Token on their CLI, bypassing the need for the victim's password.
- **Attack Surface:** User Interaction (Phishing).
- **Business Impact:** **Session Hijacking**. Access to user data without knowing their password.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** None (Public Client Flow).
- **Tools:**
    - [TokenTactics](https://github.com/rvrsh3ll/TokenTactics)
    - [GraphRunner](https://github.com/dafthack/GraphRunner)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Generate Code**
```powershell
Get-AzureToken -Client Graph
```
*Output: "To sign in, use a web browser to open the page... and enter the code..."*

**Step 2: Phish**
Send the code to the victim via email/Teams.

**Step 3: Receive Token**
Once validated, the tool outputs the JWT.
```powershell
Connect-MgGraph -AccessToken $Token
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Device Code` | `AuthenticationProtocol` is "DeviceCode". Alert if originating IP is different from the user's usual location. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Conditional Access:** Block "Device Code Flow" for users who do not need it, or require the device to be Managed/Compliant.
*   **User Training:** Train users never to enter codes they didn't request.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005]
> **Next Logical Step:** [EXFIL-M365-001]
