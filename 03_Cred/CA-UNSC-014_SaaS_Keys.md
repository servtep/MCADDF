# [CA-UNSC-014]: SaaS API Key Exposure

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-014 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | M365 / Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Organizations use third-party SaaS tools (Salesforce, ServiceNow, Slack) integrated with Entra ID. Often, developers hardcode "integration tokens" or "webhooks" in scripts or internal wikis (SharePoint, Confluence).
- **Attack Surface:** SharePoint Online, Teams Chat History, OneNote.
- **Business Impact:** **Third-Party Compromise**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Standard User (Read Access to SharePoint/Teams).
- **Tools:**
    - [GraphRunner](https://github.com/dafthack/GraphRunner)
    - [TruffleHog](https://github.com/trufflesecurity/trufflehog)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Scan M365 (GraphRunner)**
Search across all accessible SharePoint sites and Teams channels.
```powershell
Invoke-GraphRunner -Search "xoxb-" # Slack Bot Token
Invoke-GraphRunner -Search "glpat-" # GitLab Token
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Purview
| Source | Event | Filter Logic |
|---|---|---|
| **DLP** | `SensitiveInfoType` | Trigger on detection of API Key patterns in SharePoint/OneDrive. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **DLP Policies:** Implement Microsoft Purview DLP policies to block the storage/sharing of API key patterns (Regex) in SharePoint/Teams.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005]
> **Next Logical Step:** [LAT-SAAS-001]
