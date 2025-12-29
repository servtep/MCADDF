# [CA-TOKEN-021]: Entra SSO Credential Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-021 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows / Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** On non-Entra joined devices (e.g., personal laptops accessing corporate resources), Entra ID may drop a persistent cookie (`ESTSAUTHPERSISTENT`) or use the "Windows Accounts" Chrome extension to maintain SSO. Attackers can export these specific cookies to gain long-term access.
- **Attack Surface:** Browser Cookies.
- **Business Impact:** **Long-Term Session Hijacking**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Access.
- **Tools:**
    - [Cookie Editor]
    - [Roadtx]

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Export Cookie**
Look for `ESTSAUTHPERSISTENT`.

**Step 2: Exchange**
Use Roadtx to exchange the cookie for an Access Token.
```bash
roadtx gettokens --cookie "ESTSAUTHPERSISTENT=..."
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Browser` | Sign-in with `KeepMeSignedIn` (KMSI) flag from new IP. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **KMSI:** Disable "Stay signed in" (KMSI) in Company Branding settings.
*   **Session Lifetime:** Reduce persistent browser session lifetime.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005]
> **Next Logical Step:** [EXFIL-M365-001]
