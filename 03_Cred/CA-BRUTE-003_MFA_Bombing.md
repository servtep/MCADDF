# [CA-BRUTE-003]: MFA Bombing/Fatigue Attacks

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-BRUTE-003 |
| **MITRE ATT&CK v18.1** | [Multi-Factor Authentication Request Generation (T1621)](https://attack.mitre.org/techniques/T1621/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID / M365 |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** After compromising a username and password (via Spraying or Phishing), the attacker is blocked by MFA. To bypass this, they repeatedly trigger MFA push notifications to the user's mobile device (often late at night). The goal is to annoy or confuse the user into hitting "Approve" just to stop the notifications.
- **Attack Surface:** Microsoft Authenticator / Duo / Okta.
- **Business Impact:** **MFA Bypass**. Gaining full access despite MFA protection.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Valid Credentials (User+Pass).
- **Tools:**
    - [MFAFatigue](https://github.com/MFAFatigue)
    - [MFASweep](https://github.com/dafthack/MFASweep)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Loop Requests**
Script a loop to hit the login endpoint every 10-20 seconds.
```bash
while true; do
  curl -X POST https://login.microsoftonline.com/... -d "grant_type=password&..."
  sleep 15
done
```

**Step 2: Social Engineering (Optional)**
Call or message the user claiming to be IT Support: "We are running maintenance, please approve the prompt to sync your account."

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `MFA Denied` | Multiple `50074` (MFA required) or `50076` (MFA failed) events followed immediately by a `Success` (50074 -> 0). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Number Matching:** Enforce **MFA Number Matching** in Microsoft Authenticator. The user must type a code displayed on the login screen into their phone, making blind approval impossible.
*   **Limits:** Configure limits on MFA requests per minute to block the "bombing" behavior.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-BRUTE-001]
> **Next Logical Step:** [EXFIL-M365-001]
