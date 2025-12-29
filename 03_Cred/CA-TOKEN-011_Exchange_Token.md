# [CA-TOKEN-011]: Exchange Online OAuth Token Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-011 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Authentication Certificates (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Exchange Online / M365 |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Attackers leverage stolen Entra ID tokens (specifically Refresh Tokens or Access Tokens with `Mail.ReadWrite` scope) to access Exchange Online mailboxes via Graph API or EWS. Unlike traditional credential theft, this bypasses MFA and often allows programmatic email search and exfiltration without triggering interactive sign-in alerts.
- **Attack Surface:** OAuth Token Endpoint.
- **Business Impact:** **BEC & Data Exfiltration**. Reading CEO emails, injecting malicious inbox rules, or sending internal phishing emails.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Access Token with Exchange scopes (user or app).
- **Tools:**
    - [TokenTactics](https://github.com/rvrsh3ll/TokenTactics)
    - [GraphRunner](https://github.com/dafthack/GraphRunner)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Refresh Token Exchange**
If possessing a Refresh Token (RT), exchange it for an Exchange Online Access Token.
```powershell
RefreshTo-ExchangeToken -domain target.com -RefreshToken $RT
```

**Step 2: Access Mailbox**
Use the token to list messages.
```bash
curl -H "Authorization: Bearer $ExToken" https://outlook.office.com/api/v2.0/me/messages
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Exchange Online` | Sign-in using "Exchange Web Services" or "Microsoft Graph" from an uncommon IP. |
| **OfficeActivity** | `MailItemsAccessed` | Bulk access to mail items (requires Audit Premium). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Continuous Access Evaluation (CAE):** Enable CAE for Exchange Online. This revokes the token near-instantly if critical events (password change, IP change) occur.
*   **Legacy Auth:** Block Legacy Authentication (EWS/IMAP/POP3) which is easier to abuse.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-TOKEN-004] (Device Code Phishing)
> **Next Logical Step:** [EXFIL-M365-001]
