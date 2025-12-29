# [CA-COOKIE-002]: Authenticator App Session Hijacking

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-COOKIE-002 |
| **MITRE ATT&CK v18.1** | [Steal Web Session Cookie (T1539)](https://attack.mitre.org/techniques/T1539/) |
| **Tactic** | Credential Access |
| **Platforms** | Android / iOS |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** If an attacker compromises a mobile device (via malware or physical access), they can extract the SQLite database used by the Microsoft Authenticator app. This database contains the "CloudAP" tokens (PRT equivalent for mobile) or session cookies that allow the app to perform Passwordless Sign-in.
- **Attack Surface:** Mobile Device Storage (`/data/data/com.azure.authenticator`).
- **Business Impact:** **MFA Bypass**. Cloning the MFA token generator.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Root / Jailbreak on Mobile Device.
- **Tools:**
    - `adb`
    - [sqlite3]

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extraction (Android)**
```bash
adb shell
su
cp /data/data/com.azure.authenticator/databases/Authenticator.db /sdcard/
```

**Step 2: Analysis**
Open the DB and look for tokens/seeds.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Mobile App` | Simultaneous logins from the same DeviceID but vastly different locations (Cloned device). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Intune:** Enforce Jailbreak/Root detection. Block access if the device is compromised.
*   **App Protection Policies:** Use MAM to encrypt app data, making the SQLite DB unreadable even to Root users (requires specific key from KeyStore).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005]
> **Next Logical Step:** [LAT-CLOUD-001]
