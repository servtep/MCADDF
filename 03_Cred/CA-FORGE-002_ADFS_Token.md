# [CA-FORGE-002]: ADFS Token Forging

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-FORGE-002 |
| **MITRE ATT&CK v18.1** | [Forge Web Credentials: SAML Tokens (T1606.002)](https://attack.mitre.org/techniques/T1606/002/) |
| **Tactic** | Credential Access / Persistence |
| **Platforms** | Hybrid AD (ADFS) |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Unlike "Golden SAML" which focuses on cross-tenant/cloud dominance, general ADFS token forging allows an attacker with the **Token Signing Key** to generate SAML assertions for *any* application relying on that ADFS server (internal HR portals, VPNs, custom apps). The attacker does not need to compromise the target application directly; they simply forge a token claiming to be a valid user with arbitrary claims (e.g., `Group: Administrators`).
- **Attack Surface:** ADFS Signing Keys (Encrypted in AD DKM).
- **Business Impact:** **Application Impersonation**. Bypassing authentication for all federated apps.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Domain Admin or ADFS Service Account compromise (to decrypt DKM).
- **Tools:**
    - [ADFSDump](https://github.com/fireeye/ADFSDump)
    - [ADFSpoof](https://github.com/mandiant/ADFSpoof)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extract DKM & Keys**
Run `ADFSDump` on the ADFS server to pull the Encrypted PFX and decrypt it using the DKM key from Active Directory.
```cmd
ADFSDump.exe
```

**Step 2: Forge Assertion**
Create a token for a specific Relying Party Trust (RPT).
```bash
python3 adfspoof.py -b <Base64Key> -s "https://internal-app.corp/sso" --upn "admin@corp.local" --claims "Group=Admins"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 ADFS Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 299/500 | Correlate application logins with ADFS issuance logs. If an app accepts a token but ADFS has no record of issuing it, it's a forgery. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **HSM:** Move Token Signing Keys to a **Hardware Security Module** (HSM) to prevent private key extraction.
*   **Rotation:** If a compromise is suspected, rotate the Token Signing Certificate immediately (invalidates all existing forged tokens).

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-UNSC-019]
> **Next Logical Step:** [LAT-CLOUD-002]
