# [REALWORLD-018]: OAuth Provider Impersonation

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-018 |
| **MITRE ATT&CK v18.1** | T1484.002 (Domain or Tenant Policy: Trust Modification); related to T1550 (Use of Web Session Cookie / Token Replay) |
| **Tactic** | Initial Access; Credential Access; Persistence; Defense Evasion |
| **Platforms** | Cross-Cloud (Entra ID, Okta, Google Workspace, AWS IAM Identity Center, SaaS using OAuth 2.0 / OIDC) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All major IdPs and SaaS platforms that support OAuth 2.0 / OIDC, including Entra ID and multi-tenant apps |
| **Patched In** | No single patch; mitigated through OAuth consent governance, verified publishers, Conditional Access, and tenant hardening |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** OAuth provider impersonation abuses the trust model of OAuth 2.0 and OpenID Connect. Instead of directly compromising user credentials, adversaries register malicious applications or IdP integrations that mimic legitimate providers, or abuse multi-tenant OAuth apps, to obtain tokens that appear to originate from trusted sources. When a victim grants consent or when a tenant misconfigures trust, the attacker can impersonate users and access APIs such as Microsoft Graph, Google APIs, or custom SaaS scopes.
- **Attack Surface:** Entra ID multi‑tenant apps, OAuth consent pages, external IdP connections, device code and auth code flows, and any SaaS platform where adding an OAuth IdP or app is permitted to admins or end users.
- **Business Impact:** **Stealthy, long‑lived access to cloud data and APIs.** Attackers can read and modify mailboxes, files, CRM data, cloud resources, and even manage identity settings without further MFA prompts. Because access is granted via OAuth grants, password resets often do not remove the backdoor.
- **Technical Context:** Attacks frequently involve phishing that drives the victim to a genuine OAuth consent page or an AiTM proxy. In other variants, threat actors such as Scattered Spider target IdP admins, then register apps or IdPs that impersonate trusted providers. Detection focuses on OAuth app inventory, unusual scopes, new service principals, and anomalous token usage, rather than endpoint‑centric telemetry.

### Operational Risk

- **Execution Risk:** Medium – Configuration and social engineering heavy; low malware footprint.
- **Stealth:** High – Uses legitimate OAuth flows and normal sign‑in pages, often bypassing traditional signature‑based defenses.
- **Reversibility:** Medium – OAuth grants and rogue apps can be revoked, but follow‑on actions (data exfiltration, secondary persistence) may be irreversible.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Microsoft 365 / Entra ID controls for app consent and enterprise apps | Improper OAuth governance violates secure configuration requirements. |
| **DISA STIG** | Application Security and Identity controls | Ensure external IdPs and OAuth clients are vetted, approved, and monitored. |
| **CISA SCuBA** | Cloud identity & SaaS baselines | Emphasises granular control of OAuth apps and third‑party access to federal tenants. |
| **NIST 800-53** | AC-3, AC-6, IA-2, IA-5 | Access enforcement, least privilege, and strong authentication extended to application‑to‑API trust. |
| **GDPR** | Art. 5, 25, 32 | Controller must maintain control of data sharing with processors and sub‑processors; risky OAuth consents breach data minimisation and security of processing. |
| **DORA** | Art. 9, 11 | Governance over ICT third‑party risk including API‑based and OAuth access to financial data. |
| **NIS2** | Art. 21 | Requires managing supply‑chain and third‑party access risks, including OAuth‑based integrations. |
| **ISO 27001** | A.5.19, A.5.23, A.8.23 | Managing information security in use of cloud services and third‑party components. |
| **ISO 27005** | SaaS OAuth Backdoor | Risk scenario where unvetted OAuth apps or IdP impersonation leads to data breach.

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:**
  - To execute the attack at scale: ability to register apps or configure external IdPs (Global Admin, Cloud App Admin, Okta App Admin, etc.).
  - For consent‑phishing: any user capable of granting delegated permissions within tenant policy.
- **Required Access:**
  - Ability to deliver phishing links or malicious login flows to targets.
  - Access to developer portals or admin centers to register apps.

**Supported Versions:**
- Major IdPs and SaaS supporting OAuth 2.0 / OIDC, including Entra ID, Okta, Google, and custom IdPs.

- **Tools:**
  - OAuth device‑code and auth‑code phishing kits / AiTM proxies.
  - Logpoint, Elastic or Sentinel for detecting anomalous token use.
  - Vendor‑specific tools for reviewing OAuth apps (Entra portal, Google Admin, Okta System Logs).

## 4. ENVIRONMENTAL RECONNAISSANCE

### Entra ID / PowerShell Reconnaissance

```powershell
# List OAuth service principals and their permissions
Connect-MgGraph -Scopes 'Application.Read.All','Directory.Read.All'
Get-MgServicePrincipal -All | Select-Object AppId, DisplayName, PublisherName

# List OAuth consent grants
Get-MgOauth2PermissionGrant -All |
  Select-Object ClientId, ResourceId, Scope, ConsentType
```

**What to Look For:**
- Newly created multi‑tenant apps with broad scopes like Mail.ReadWrite, Files.Read.All or offline_access.
- Apps without verified publishers but with high‑privilege scopes.

### Entra ID Portal Reconnaissance

- Azure portal → Entra ID → Enterprise applications:
  - Filter by Application type equals Multi‑tenant.
  - Sort by Created date to identify recent additions.
  - Inspect permissions and consent type (admin vs user).

### Okta / SaaS Reconnaissance

- Okta Admin console → Applications → Applications:
  - Identify recently added OAuth apps and sign‑on methods.
  - Cross‑check with security team change records.

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Malicious Multi‑Tenant OAuth App in Entra ID

**Supported Versions:** All Entra ID tenants allowing user or admin consent to multi‑tenant apps.

#### Step 1: Register Malicious App

**Objective:** Create a multi‑tenant OAuth app controlled by the attacker.

**Portal Steps:**
1. Azure portal → Entra ID → App registrations → New registration.
2. Set supported account types to multiple organisations.
3. Configure redirect URI to attacker‑controlled domain.
4. Add API permissions such as Microsoft Graph Mail.ReadWrite, Files.Read.All, Directory.Read.All, offline_access.

#### Step 2: Launch Consent Phishing

**Objective:** Trick users into granting the app permissions.

**Execution:**
- Craft a URL targeting the official Microsoft consent endpoint with the attacker app_id and scopes.
- Send phishing emails or messages convincing the user to click the link.

**Result:**
- Once the user authenticates and approves, Entra ID issues OAuth tokens and creates persistent consent grants.

### METHOD 2 – OAuth Provider Impersonation via Inbound IdP

**Supported Versions:** IdPs and SaaS platforms that allow configuring external OAuth providers.

#### Step 1: Add Attacker‑Controlled OAuth Provider

**Objective:** Configure a connection that appears to be a trusted provider (for example, corporate IdP or Microsoft) but is actually controlled by the attacker.

**Execution:**
- In target SaaS or IdP admin console, add a new OAuth/OIDC IdP.
- Use attacker‑controlled issuer URLs and JWKS endpoints but label the connection as a familiar provider.

#### Step 2: Abuse Subject / Email Mapping

**Objective:** Map accounts from attacker IdP to privileged accounts in the target tenant.

**Execution:**
- Configure claims mapping so that sub or email from attacker IdP equals the target account identifiers.
- Enable Just‑in‑Time provisioning or automatic account linking.

**Result:**
- Any login via the attacker IdP yields tokens treated as if they originate from the real provider, impersonating target users.

## 6. ATTACK SIMULATION AND VERIFICATION (Atomic Red Team)

- Use Atomic Red Team tests for T1550 and T1136/T1098 to emulate OAuth misuse, then validate detections on token replay and new app registration.

**Generic Command:**
```powershell
Invoke-AtomicTest T1550 -TestNumbers 1
```

## 7. TOOLS AND COMMANDS REFERENCE

- Entra ID App registrations portal and Graph PowerShell.
- Okta developer console and System Logs.
- OAuth debugging tools such as jwt.ms or jwt.io for token inspection (defensive use only).

## 8. SPLUNK DETECTION RULES

### Rule: Suspicious New OAuth App With High‑Privilege Scopes

```spl
index=azure OR index=o365 sourcetype="o365:management:activity" \
  Operation="Add service principal" OR Operation="Update application"
| search ModifiedProperties.scope="*Mail.ReadWrite*" OR ModifiedProperties.scope="*Directory.Read.All*" \
  OR ModifiedProperties.scope="*offline_access*"
| stats latest(TimeGenerated) as last_time by UserId, Workload, Operation, ModifiedProperties
```

## 9. MICROSOFT SENTINEL DETECTION

### Query: Entra ID Risky OAuth App or Consent

```kusto
AuditLogs
| where OperationName in ('Add service principal','Consent to application','Grant consent to application')
| extend scopes = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue)
| where scopes has_any ('Mail.ReadWrite','Files.Read.All','Directory.Read.All')
```

## 10. WINDOWS EVENT LOG MONITORING

Primarily cloud‑based; Windows logs play a secondary role for local token theft and browser compromise, covered in other modules.

## 11. SYSMON DETECTION PATTERNS

Use generic browser and process monitoring patterns for AiTM proxies and token theft infrastructure running on attacker footholds.

## 12. MICROSOFT DEFENDER FOR CLOUD

- Enable Defender for Cloud Apps / Defender for Cloud App governance for OAuth apps.
- Turn on alerts for risky OAuth apps and suspicious consent grants.

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) \
  -Operations 'Consent to application','Add service principal' \
  | Export-Csv '.\\oauth-consents.csv' -NoTypeInformation
```

## 14. DEFENSIVE MITIGATIONS

- Restrict user consent to verified publishers and low‑risk scopes only.
- Require admin approval for any app requesting high‑risk permissions.
- Periodically review and remove unused or risky OAuth apps and consents.

## 15. DETECTION AND INCIDENT RESPONSE

- Identify all tokens and consents associated with the rogue app.
- Revoke OAuth grants, disable the app, and rotate any keys or secrets.
- Hunt for data exfiltration and secondary persistence (for example, new app secrets, added roles).

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | OAuth consent phishing | User is tricked into granting permissions. |
| 2 | Credential Access | Token theft / reuse | Adversary harvests and reuses OAuth tokens. |
| 3 | Current Step | REALWORLD-018 – OAuth Provider Impersonation | Attacker app or IdP impersonates trusted provider. |
| 4 | Persistence | OAuth backdoor | Rogue app or IdP remains until removed. |
| 5 | Impact | Data theft and account takeover | Wide API access used for exfiltration or further escalation. |

## 17. REAL-WORLD EXAMPLES

- Vendor advisories on OAuth consent phishing in Entra ID.
- Incident reports where malicious OAuth apps and impersonated providers were used to access Microsoft 365 mailboxes and files.

---