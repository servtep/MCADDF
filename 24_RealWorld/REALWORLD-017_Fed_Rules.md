# [REALWORLD-017]: Inbound Federation Rule Creation

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-017 |
| **MITRE ATT&CK v18.1** | T1556 (Modify Authentication Process); T1484.002 (Domain or Tenant Policy: Trust Modification) |
| **Tactic** | Credential Access; Persistence; Defense Evasion; Initial Access |
| **Platforms** | Cross-Cloud (Microsoft Entra ID, Okta, other SAML/OIDC IdPs, AD FS, AWS IAM Identity Center) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Microsoft Entra ID (all current); Okta (all current); AD FS 2016-2022; major enterprise IdPs that support inbound federation |
| **Patched In** | Not fully patched; mitigated via hardened configuration, least privilege and monitoring rather than a single patch |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Inbound federation rule creation abuses trust relationships between identity providers to create a rogue or backdoored identity provider, domain, or cross-tenant trust. Instead of attacking passwords directly, the adversary modifies how authentication is performed so that tokens issued by an attacker-controlled IdP or signing key are accepted as legitimate for any user. This aligns with MITRE T1556 (Modify Authentication Process) and T1484.002 (Trust Modification), where cloud or hybrid identity trust settings are altered to bypass normal controls.
- **Attack Surface:** Microsoft Entra ID federated domains and external IdPs, Okta inbound federation, AD FS trusts, cross-tenant access and synchronization policies, and any SaaS IdP that can accept SAML/OIDC assertions from external identity providers.
- **Business Impact:** **Complete identity compromise and long‑term persistence.** An attacker with a malicious inbound federation can impersonate any user (including highly privileged admins), bypass MFA when the IdP is trusted to assert MFA, and silently regain access even after passwords are reset or local sessions are revoked.
- **Technical Context:** Attacks are configuration‑driven and often low‑noise, performed via admin portals, PowerShell, or API. They frequently follow helpdesk or cloud admin account takeover. Detection depends on detailed auditing of federation settings, domain authentication type, signing certificates, and cross‑tenant policies rather than traditional endpoint telemetry.

### Operational Risk

- **Execution Risk:** Medium – The changes are reversible at configuration level but may be complex to fully unwind across multiple IdPs and tenants.
- **Stealth:** High – Changes are made via legitimate admin channels and may be indistinguishable from normal configuration work if not tightly monitored.
- **Reversibility:** Partially reversible – Trust configurations and certificates can be removed; however, attacker‑issued tokens may have been used to perform further destructive or stealthy actions that persist.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Microsoft 365 / Entra ID 1.1, 1.2 | Secure configuration of identity providers, strong admin controls and logging over federation and domain settings. |
| **DISA STIG** | APP3520 / IDPS‑related controls | Ensure SSO and federation configurations are documented, approved, and monitored; restrict who may modify identity trust. |
| **CISA SCuBA** | Entra ID Identity and Access Baseline | Requires strong governance and monitoring for federated domains, external IdPs, and cross‑tenant access. |
| **NIST 800-53** | AC-2, AC-3, AC-5, IA-2, IA-4 | Account management, access enforcement, separation of duties, and strong authentication for identity management systems. |
| **GDPR** | Art. 24, 25, 32 | Controllers must implement appropriate technical and organisational measures; weak identity trust exposes personal data across tenants. |
| **DORA** | Art. 9, 11 | ICT risk management and security of network and information systems, including identity and access services across financial infrastructures. |
| **NIS2** | Art. 21 | Cybersecurity risk management and incident handling, including secure identity federation for essential and important entities. |
| **ISO 27001** | A.5.15, A.5.18, A.8.2, A.8.3 | Access control, privileged access restriction, secure authentication, and protection of information in applications. |
| **ISO 27005** | Identity System Compromise | Risk scenario where compromise of IdP trust enables full tenant takeover and cross‑tenant abuse.

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:**
  - Microsoft Entra ID Global Administrator or equivalent custom role able to manage domains, identity providers, and cross‑tenant access.
  - Okta Super Administrator or administrator with rights to manage Identity Providers and inbound federation.
  - AD FS Farm Administrator when modifying on‑premises federation trusts.
- **Required Access:**
  - Network access to IdP admin portals or management APIs (Azure portal, Entra admin center, Okta Admin, etc.).
  - Ability to authenticate as a high‑privilege admin or compromise the channel that performs federation changes (for example, helpdesk workflows).

**Supported Versions:**
- **Entra ID / Azure AD:** All supported tenants that allow federated domains, external IdPs, or cross‑tenant access and synchronization.
- **AD FS:** Windows Server 2016, 2019, 2022.
- **Okta:** All current cloud service versions supporting inbound federation.

- **Tools:**
  - AADInternals (PowerShell module) – backdooring federated domains and inspecting federation settings: https://github.com/Gerenios/AADInternals
  - Microsoft Graph PowerShell SDK – administration of domains, identity providers, and cross‑tenant policies: https://learn.microsoft.com/entra/identity-platform/graph-powershell
  - Azure CLI with Microsoft Graph or Entra extensions – scripting enumeration and changes.
  - Okta APIs and Terraform providers – managing Identity Providers and federation settings.

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance (Entra ID)

Baseline objective: identify existing federated domains and external IdPs that could be abused or have been altered.

```powershell
# List Entra ID domains and their authentication type
Connect-MgGraph -Scopes 'Domain.Read.All'
Get-MgDomain | Select-Object Id, AuthenticationType, IsVerified
```

**What to Look For:**
- Domains with `AuthenticationType` set to `Federated` rather than `Managed`.
- Unusual or unexpected domains (for example, recently added vanity domains that are not in CMDB).
- Any domain that appears verified but is not in official inventory.

**Version Note:** Graph commands are consistent across Entra ID tenants; the key differences are consented scopes and whether legacy AzureAD modules are still in use.

```powershell
# Retrieve full federation settings via AADInternals
Import-Module AADInternals
Connect-AADIntAzureAD
Get-AADIntTenantFederationSettings
```

**What to Look For:**
- Unexpected token‑signing certificates.
- Secondary token‑signing certificates that were not deployed by the identity team.
- Suspicious issuer URIs or endpoints pointing to attacker‑controlled infrastructure.

#### Cross‑Tenant Access and Synchronization Recon

```powershell
# List cross-tenant access settings (B2B / direct connect / sync)
Connect-MgGraph -Scopes 'Policy.Read.All'
Get-MgPolicyCrossTenantAccessPolicy | Select-Object Default, DisplayName

Get-MgPolicyCrossTenantAccessPolicyPartner | Select-Object TenantId, InboundAccess, OutboundAccess
```

**What to Look For:**
- New partner tenants with inbound access configured that are not documented.
- Partners for which inbound user synchronization is enabled without a business justification.

### Linux/Bash / CLI Reconnaissance

```bash
# Enumerate Entra ID domains via Microsoft Graph using Azure CLI
az login --tenant <tenant-id>
az rest \
  --method GET \
  --url https://graph.microsoft.com/v1.0/domains \
  --headers 'ConsistencyLevel=eventual' \
  --query 'value[].{id:id, authType:authenticationType, isVerified:isVerified}'
```

**What to Look For:**
- Same indicators as in PowerShell: federated domains, unexpected issuers, and recently added domains.

For Okta:

```bash
# List Okta Identity Providers (IdPs)
OKTA_ORG_URL='https://yourorg.okta.com'
API_TOKEN='<api-token>'

curl -s -H "Authorization: SSWS $API_TOKEN" \
  "$OKTA_ORG_URL/api/v1/idps" | jq '.[].{name:name, type:type, id:id, status:status}'
```

**What to Look For:**
- New or disabled‑then‑re‑enabled Identity Providers.
- IdPs configured for inbound federation that are not documented (for example, another Okta org or external SAML IdP).
- Auto‑link or Just‑in‑Time (JIT) account settings that permit automatic account creation or linking.

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Backdooring an Existing Entra Federated Domain (AADInternals)

**Supported Versions:** Entra ID with federated domains, AD FS 2016‑2022.

#### Step 1: Enumerate and Export Current Federation Settings

**Objective:** Obtain the current domain federation configuration for backup and later comparison.

**Command:**
```powershell
Import-Module AADInternals
Connect-AADIntAzureAD

# Export current federation settings to JSON
Get-AADIntTenantFederationSettings | Out-File -FilePath '.\\federation-backup.json'
```

**Expected Output:**
- JSON or PowerShell object data describing each federated domain, issuer URI, endpoints, token‑signing certificates and identifiers.

**What This Means:**
- Confirms which domains are federated and which signing certificates are currently trusted by Entra ID.

**OpSec & Evasion:**
- Attackers typically perform this step shortly after compromising a Global Admin, blending it with other admin reconnaissance.

#### Step 2: Add a Rogue Secondary Token‑Signing Certificate

**Objective:** Introduce an attacker‑controlled certificate so that tokens signed with it are accepted as valid SAML assertions for any user in the tenant.

**Command:**
```powershell
# Create or import attacker-controlled certificate
$certPath = '.\\attacker-signing.pfx'
$certPassword = Read-Host -AsSecureString 'Cert password'

$backdoorParams = @{
  DomainName = 'victim-domain.tld'
  PfxFile    = $certPath
  Password   = $certPassword
}

ConvertTo-AADIntBackdoor @backdoorParams
```

**Expected Output:**
- AADInternals confirms that a secondary token‑signing certificate has been added for the selected federated domain.

**What This Means:**
- The attacker now controls a certificate that can be used to issue SAML tokens trusted by Entra ID for that domain.

**OpSec & Evasion:**
- This change may generate minimal log noise and appear as a routine federation update unless dedicated detections are in place.

**Troubleshooting:**
- If the command fails because the domain is not federated, attackers may first convert a managed domain to a federated one using Entra or MSOnline PowerShell.

#### Step 3: Issue Forged Tokens and Access Tenant Resources

**Objective:** Use the rogue certificate to generate SAML tokens for arbitrary users and exchange them for access tokens.

**Command:**
- Attack tools or custom scripts sign SAML assertions for target UPNs and post them to the relevant SSO endpoint (for example, Active Directory Federation Services or a custom IdP endpoint) to obtain OAuth access tokens for Microsoft 365 or Azure resources.

**Expected Output:**
- Valid access tokens for Graph, Exchange Online, SharePoint Online, or other service principals configured to trust the federated domain.

**What This Means:**
- The attacker can impersonate any user, including Global Admins, via normal SSO flows.

**References and Proofs:**
- Tenable Federated Domains List and secondary token‑signing backdoor case study.
- AADInternals documentation and talks on federated domain backdoors.
- MITRE ATT&CK T1556.007 and T1484.002 guidance on hybrid identity and trust modification.

### METHOD 2 – Creating a Rogue Inbound Federation in Okta (Inbound SAML/OIDC IdP)

**Supported Versions:** Okta Identity Cloud with Inbound Federation enabled.

#### Step 1: Compromise a Super Admin Account

**Objective:** Obtain credentials and MFA approval to a highly privileged Okta Super Admin or equivalent.

**Execution:**
- Social‑engineering of helpdesk to reset MFA.
- SIM‑swapping or MFA fatigue targeted at existing admins.

#### Step 2: Add a Malicious Source IdP (Inbound Federation)

**Objective:** Configure an attacker‑controlled IdP as an inbound federation source into the victim Okta tenant.

**Manual Portal Steps:**
1. Log into the Okta Admin console as Super Admin.
2. Navigate to `Security` → `Identity Providers`.
3. Select `Add Identity Provider` and choose `SAML 2.0` or `OIDC`.
4. Provide attacker‑controlled IdP metadata (issuer, SSO URL, certificate, and claims).
5. Enable Just‑In‑Time account provisioning or automatic account linking for targeted apps.

**What This Means:**
- Successful authentication at the attacker‑controlled IdP is now accepted as a valid login into applications protected by the victim Okta tenant.

#### Step 3: Abuse Username Mapping and Auto‑Linking

**Objective:** Manipulate the username or subject claim so that attacker identities map to real user accounts in the target tenant.

**Execution:**
- Configure the inbound IdP profile mapping so that the username attribute is set to a target user UPN or email.
- Enable automatic account linking based on this attribute.

**Result:**
- When the attacker signs into their own IdP account, Okta maps it to an existing privileged user in the target tenant and grants SSO access.

**References and Proofs:**
- Okta and vendor write‑ups on cross‑tenant impersonation and inbound federation abuse.
- MITRE ATT&CK T1484.002 examples where adversaries add federated IdPs and manipulate trust.

## 6. ATTACK SIMULATION AND VERIFICATION (Atomic Red Team)

### Atomic Red Team

- **Atomic Test ID:** T1484.002 – Domain or Tenant Trust Modification.
- **Test Name:** Modify federation settings on a domain.
- **Description:** Simulates an adversary changing domain authentication from managed to federated or altering trust settings for detection validation.
- **Supported Versions:** Windows Server AD / Entra hybrid identity environments.

**Command:**
```powershell
Invoke-AtomicTest T1484.002 -TestNumbers 1
```

**Cleanup Command:**
```powershell
Invoke-AtomicTest T1484.002 -TestNumbers 1 -Cleanup
```

**Reference:**
- Atomic Red Team library entry for T1484.002.

## 7. TOOLS AND COMMANDS REFERENCE

### AADInternals

- **Repository:** https://github.com/Gerenios/AADInternals
- **Purpose:** Research and attack tooling for Entra ID, including federation backdoors, token operations, and hybrid identity abuse.

**Installation (PowerShell):**
```powershell
Install-Module AADInternals -Scope CurrentUser
Import-Module AADInternals
```

**Example Usage:**
```powershell
Connect-AADIntAzureAD
Get-AADIntTenantFederationSettings
```

### Microsoft Graph PowerShell SDK

- **Purpose:** Administration of domains, identity providers, and cross‑tenant access policies via Graph.

**Installation:**
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Import-Module Microsoft.Graph
```

**Example Usage:**
```powershell
Connect-MgGraph -Scopes 'Domain.Read.All','Policy.Read.All'
Get-MgDomain
Get-MgPolicyCrossTenantAccessPolicyPartner
```

## 8. SPLUNK DETECTION RULES

### Rule 1: Suspicious Federation or Domain Trust Changes

**Rule Configuration:**
- **Required Index:** azure, o365, or custom index for Entra audit logs.
- **Required Sourcetype:** o365:management:activity or azure:monitor:aad.
- **Required Fields:** Operation, Workload, UserId, ModifiedProperties.
- **Alert Threshold:** Any event; treat as high‑severity.

**SPL Query:**
```spl
index=azure OR index=o365 sourcetype IN("o365:management:activity","azure:monitor:aad")
| search Operation IN("Set federation settings on domain","Set domain authentication","Add partner to cross-tenant access setting","Update partner cross-tenant access setting")
| stats latest(TimeGenerated) as last_time, values(ModifiedProperties) as modified by UserId, Operation, Workload
```

**What This Detects:**
- Administrative operations that change how domains authenticate or modify cross‑tenant access.
- Potential addition of a rogue federated IdP or partner tenant.

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Entra ID Federated Domain or Cross‑Tenant Trust Modification

**Rule Configuration:**
- **Required Table:** AuditLogs.
- **Required Fields:** OperationName, InitiatedBy, TargetResources, ModifiedProperties.
- **Alert Severity:** High.
- **Frequency:** Every 5 minutes; look back 24 hours.

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    'Set federation settings on domain',
    'Set domain authentication',
    'Add partner to cross-tenant access setting',
    'Update partner cross-tenant access setting',
    'Create partner cross-tenant synchronization'
  )
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, ModifiedProperties
```

**What This Detects:**
- Direct manipulation of domain federation and cross‑tenant trust configuration that may indicate a new backdoor IdP or domain.

## 10. WINDOWS EVENT LOG MONITORING

Even though this is a cloud‑centric technique, on‑premises AD FS servers and hybrid identity components leave artifacts in Windows event logs.

**Example Event IDs:**
- AD FS Admin log events for trust creation and certificate updates.
- Security events for logons to AD FS administration consoles.

**Manual Configuration Steps (Group Policy):**
1. Enable advanced auditing for object access and account management on AD FS servers.
2. Forward AD FS and Security logs to a central SIEM.

## 11. SYSMON DETECTION PATTERNS

Use Sysmon on AD FS and hybrid identity servers to track unexpected process execution (for example, PowerShell scripts altering federation configuration) and modifications to configuration files.

- Configure ProcessCreate and FileCreate rules for AD FS binaries and configuration paths.

## 12. MICROSOFT DEFENDER FOR CLOUD

Defender for Cloud and Defender for Cloud Apps can raise alerts for suspicious OAuth app activity, anomalous sign‑ins, and risky tenant configuration changes.

- Ensure Defender for Cloud plans covering Entra ID and Microsoft 365 are enabled.
- Enable anomaly detection for identity and access operations.

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

Use the Unified Audit Log to review Azure AD and Microsoft 365 operations affecting domains and federation.

**Example PowerShell:**
```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) \
  -Operations 'Set federation settings on domain','Set domain authentication' \
  | Export-Csv -Path '.\\federation-audit.csv' -NoTypeInformation
```

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- Restrict who can manage domains, identity providers, and cross‑tenant access (dedicated Tier‑0 admin accounts only).
- Enforce strong MFA and just‑in‑time elevation for these roles.
- Require formal change management for any trust or federation modifications.

### Priority 2: HIGH

- Regularly export and review federated domain configuration, including token‑signing certificates and issuer URIs.
- Disable or remove unused federated domains and external IdPs.

### Access Control and Policy Hardening

- Use Conditional Access to restrict where and how Global Admins and identity admins can sign in (for example, privileged access workstations only).
- Block legacy or non‑modern authentication methods that bypass Conditional Access.

## 15. DETECTION AND INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- Newly added federated domains or external IdPs that are not in design documentation.
- Secondary token‑signing certificates added to existing trusts.
- Cross‑tenant access partners configured with unexpected inbound synchronization.

### Forensic Artifacts

- Entra AuditLogs for domain and federation operations.
- Okta system logs for IdP additions and JIT mappings.
- AD FS admin logs and configuration backups.

### Response Procedures

1. Immediately revoke or disable suspicious federation configurations and cross‑tenant partners.
2. Rotate all federation and token‑signing certificates under legitimate control.
3. Perform full incident response to identify actions performed using attacker‑issued tokens and remove any additional persistence (for example, OAuth apps, access keys, role assignments).

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | Phishing or helpdesk social engineering | Compromise a cloud admin account with privileges over federation. |
| 2 | Privilege Escalation | Account Manipulation (T1098) | Grant additional roles or elevate privileges on the compromised identity. |
| 3 | Current Step | REALWORLD-017 – Inbound Federation Rule Creation | Create or modify trust to allow attacker‑controlled IdP or signing key. |
| 4 | Persistence | OAuth / SAML Backdoor | Use the rogue trust as a long‑term backdoor into the tenant. |
| 5 | Impact | Data exfiltration or ransomware | Abuse backdoor access to exfiltrate data or deploy ransomware. |

## 17. REAL-WORLD EXAMPLES

- Incident response and threat intelligence reports describing abuse of federated domains and inbound federation across Okta, Entra ID, and other IdPs.
- MITRE ATT&CK case studies where adversaries modified domain or tenant trust (for example, APT29 and SolarWinds, Scattered Spider adding federated IdPs).

---