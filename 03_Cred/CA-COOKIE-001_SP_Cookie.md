# [CA-COOKIE-001]: SharePoint Online Cookie Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-COOKIE-001 |
| **MITRE ATT&CK v18.1** | [Steal Web Session Cookie (T1539)](https://attack.mitre.org/techniques/T1539/) |
| **Tactic** | Credential Access |
| **Platforms** | M365 / SharePoint |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** SharePoint Online relies heavily on two cookies for authentication: `rtFa` (Root Federation) and `FedAuth`. If an attacker can steal these cookies (via XSS, Malware, or AiTM Phishing), they can access the user's entire SharePoint and OneDrive environment without triggering MFA.
- **Attack Surface:** Browser Cookies.
- **Business Impact:** **Data Theft**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Access (to steal cookie).
- **Tools:**
    - [Cookie Editor](https://github.com/Cookie-Editor/Cookie-Editor)
    - [Evilginx2](https://github.com/kgretzky/evilginx2)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Theft (AiTM)**
Setup Evilginx2 to capture `FedAuth` and `rtFa` cookies during a phishing session.

**Step 2: Injection**
Inject the cookies into a fresh browser session (using Cookie Editor extension).

**Step 3: Access**
Navigate to `https://target.sharepoint.com`.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `SharePoint` | Sign-in where the `SessionId` remains the same but the `IPAddress` changes significantly (Token Replay). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Idle Session Timeout:** Configure aggressive idle session timeouts for SharePoint Online to invalidate cookies sooner.
*   **Conditional Access:** Enforce "App Enforced Restrictions" to block downloads if the device is unmanaged, limiting the impact of a stolen cookie.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005]
> **Next Logical Step:** [EXFIL-M365-001]
