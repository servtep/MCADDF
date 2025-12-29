# [CA-TOKEN-005]: OAuth Access Token Interception (Illicit Consent)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-005 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Attackers register a multi-tenant Azure App and trick a user into "Consenting" to permissions (e.g., `Mail.Read`). Once consented, the attacker receives an Authorization Code which they exchange for an Access Token. This grants persistent access to the user's data without needing their credentials ever again.
- **Attack Surface:** User Consent Prompt.
- **Business Impact:** **Persistent Data Access**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User ability to consent to apps.
- **Tools:**
    - [365-Stealer](https://github.com/AlteredSecurity/365-Stealer)
    - [O365-Attack-Toolkit](https://github.com/mdsecactivebreach/o365-attack-toolkit)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Setup**
Host the malicious app and phishing page.

**Step 2: Phish**
Send link: `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=ATTACKER_APP...`

**Step 3: Harvest**
Upon user consent, the app receives the `code`, swaps it for a `token`, and exfiltrates data.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `Consent to application` | User consenting to a new, unverified multi-tenant application. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Admin Consent:** Configure "User Consent Settings" to **"Do not allow user consent"**. Require Admin approval for all third-party apps.
*   **Verified Publishers:** Only allow consent for Verified Publishers.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005]
> **Next Logical Step:** [EXFIL-M365-001]
