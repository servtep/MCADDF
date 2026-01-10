# [REALWORLD-019]: Scattered Spider IdP TTP (Federated IdP and Additional Cloud Credentials)

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-019 |
| **MITRE ATT&CK v18.1** | T1098.003 (Account Manipulation: Additional Cloud Roles); T1484.002 (Domain or Tenant Policy: Trust Modification); T1556.007 (Modify Authentication Process: Hybrid Identity) |
| **Tactic** | Initial Access; Privilege Escalation; Persistence; Defense Evasion; Credential Access |
| **Platforms** | Cross‑Cloud (Entra ID, Okta, AWS, GCP, SaaS IdPs) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Modern IdPs and cloud providers targeted by Scattered Spider / UNC3944 / Octo Tempest (Entra ID, Okta, AWS IAM, GCP IAM, major SaaS) |
| **Patched In** | Not applicable; mitigated by identity governance, strong helpdesk and MFA processes, and hardened federation controls |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** This module captures real‑world identity‑centric TTPs used by Scattered Spider (also tracked as UNC3944, Octo Tempest, Roasted 0ktapus, STORM‑0875). The group is known for social‑engineering helpdesks, bypassing MFA, and then abusing IdPs such as Okta and Entra ID to add rogue federated identity providers, enable inbound federation, and grant themselves additional cloud roles and credentials. Once inside, they manipulate identity trust and authorization to gain tenant‑wide control, mirroring a full Active Directory compromise in the cloud.
- **Attack Surface:** Helpdesk and support workflows, self‑service password reset, MFA enrollment and reset procedures, IdP admin portals, Entra ID and Okta federation and inbound IdP configuration, and cloud IAM role assignment interfaces across AWS, Azure, and GCP.
- **Business Impact:** **Rapid full‑tenant takeover and high‑impact extortion.** Scattered Spider has demonstrated the ability to move from a single helpdesk call to control of IdPs, cloud accounts, and virtualisation platforms (for example, ESXi) in hours, often culminating in data theft and ransomware. Identity infrastructure becomes the pivot point for controlling entire estates.
- **Technical Context:** The group heavily favours built‑in cloud and IdP capabilities over custom malware: SaaS admin portals, Graph and AWS APIs, federated IdPs, and IAM roles. Tradecraft focuses on account manipulation (assigning Global Admin, root‑level roles, adding FIDO/MFA devices), inbound federation and auto‑linking, and deleting or weakening Conditional Access and security controls.

### Operational Risk

- **Execution Risk:** Low for the attacker once an initial privileged identity is obtained; all further steps use legitimate features.
- **Stealth:** Medium to High – Activity blends with admin operations but often concentrated in short, intense windows. Without focused detections, many operations look like urgent troubleshooting.
- **Reversibility:** Partially reversible – Roles, MFA devices and IdPs can be removed, but compromised data, secrets, and downstream persistence in cloud workloads may persist.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS controls for Entra ID, Okta, AWS IAM | Hardening admin roles, MFA, and federation aligns with CIS identity baselines. |
| **DISA STIG** | Identity and Access Management STIGs | Mandate strong controls for privileged identities and SSO systems. |
| **CISA SCuBA** | Identity, SaaS, and cloud baselines | Directly addresses identity‑centric threats such as UNC3944 / Scattered Spider. |
| **NIST 800-53** | AC-2, AC-5, AC-6, IA-2, IR-4 | Account management, separation of duties, least privilege, strong auth, and incident response. |
| **GDPR** | Art. 32 | Security of processing; IdP compromise routinely leads to mass personal data exposure. |
| **DORA** | Art. 9, 10 | Operational resilience for identity infrastructure in financial services. |
| **NIS2** | Art. 21 | Cyber risk management including modern identity‑centric threats. |
| **ISO 27001** | A.5.15, A.5.16, A.8.2, A.8.3 | Access control, identity management, and secure authentication. |
| **ISO 27005** | Identity Provider Takeover | Risk scenario: adversary takes control of IdP and cloud IAM to orchestrate full‑stack compromise.

## 3. TECHNICAL PREREQUISITES

- **Required Privileges (for attacker):**
  - Initial foothold: Valid credentials for user with SSPR or helpdesk identity proofing that can be abused.
  - Objective: Admin‑level access in IdP (Okta Super Admin, Entra Global Admin) and high‑privilege cloud IAM roles.
- **Required Access:**
  - Ability to contact helpdesk or support channels and convincingly impersonate users.
  - Network access to IdP admin portals and cloud consoles.

**Supported Versions:**
- Modern cloud and SaaS platforms where Scattered Spider has been active: Okta, Entra ID, AWS IAM, vSphere, and major SaaS applications.

## 4. ENVIRONMENTAL RECONNAISSANCE

### Identity Posture and Admin Surface

Key defensive reconnaissance (Blue Team) to evaluate risk exposure to Scattered Spider‑style operations:

- Enumerate all helpdesk workflows that can reset passwords, MFA factors or phone numbers.
- Map which roles can:
  - Add or modify federated IdPs or inbound federation.
  - Grant Global Admin or equivalent roles.
  - Approve risky OAuth apps and grants.

Example Entra ID role enumeration:

```powershell
Connect-MgGraph -Scopes 'Directory.Read.All','RoleManagement.Read.All'
Get-MgRoleManagementDirectoryRoleDefinition |
  Where-Object {$_.DisplayName -like '*Admin*'} |
  Select-Object DisplayName, Id
```

### Okta / Entra Federation and Inbound IdP Recon

- Okta System Logs: search for events related to adding or updating Identity Providers, MFA authenticators, and admin roles.
- Entra AuditLogs: look for operations modifying Conditional Access, cross‑tenant access settings, and domain federation.

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Helpdesk‑Driven Account Takeover and MFA Reset

**Supported Versions:** Any organisation with helpdesk‑mediated MFA or password reset.

#### Step 1: Collect Target Identity Data

**Objective:** Gather enough information to pass helpdesk identity verification.

**Execution:**
- Use infostealer data, LinkedIn, OSINT, and prior breaches to obtain usernames, email, phone numbers, and partial personal data.

#### Step 2: Social‑Engineer Helpdesk

**Objective:** Convince support to reset MFA and/or password for high‑value accounts.

**Execution:**
- Call support claiming loss of phone or new device setup.
- Answer security questions using harvested data.
- Request MFA reset or SSPR phone number change.

### METHOD 2 – Adding Federated IdP and Automatic Account Linking (Okta / Entra ID)

**Supported Versions:** Okta inbound federation; Entra cross‑tenant access and external IdPs.

#### Step 1: Obtain IdP Admin Rights

**Objective:** Get Super Admin in Okta or Global Admin in Entra ID.

**Execution:**
- Continue from Method 1 or leverage SIM‑swapping and MFA fatigue attacks to land on privileged accounts.

#### Step 2: Add Attacker‑Controlled IdP

**Objective:** Configure a new SAML or OIDC IdP pointing to attacker infrastructure.

**Portal Steps (generic):**
1. Log into IdP admin console as administrator.
2. Navigate to Identity Providers or federation settings.
3. Add new IdP with attacker‑controlled endpoints and certificate.
4. Configure username mappings to match existing user identifiers.
5. Enable Just‑in‑Time provisioning or automatic account linking.

**Result:**
- Logins via the attacker IdP are treated as legitimate and mapped to victim users.

#### Step 3: Assign Additional Cloud Roles (T1098.003)

**Objective:** Grant persistent high‑privilege roles to attacker‑controlled or compromised accounts.

Example Entra ID role assignment (legitimate cmdlet, attacker misuse):

```powershell
Connect-MgGraph -Scopes 'RoleManagement.ReadWrite.Directory'
$role = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Global Administrator'"
New-MgRoleManagementDirectoryRoleAssignment -PrincipalId <attacker-object-id> -RoleDefinitionId $role.Id -DirectoryScopeId '/'
```

**Result:**
- Attacker account now holds Global Admin, enabling full control and further manipulation.

## 6. ATTACK SIMULATION AND VERIFICATION (Atomic Red Team)

- Use Atomic Red Team tests for T1098.003 (Additional Cloud Roles) and T1484.002 (Trust Modification) to emulate role assignment and trust changes, then verify SIEM detections.

## 7. TOOLS AND COMMANDS REFERENCE

- Cloud provider CLIs and SDKs (Azure, AWS, GCP) for IAM role management.
- Entra ID and Okta admin portals.
- Identity‑security platforms (for example, CSPM/CIEM) to baseline admin and helpdesk capabilities.

## 8. SPLUNK DETECTION RULES

### Rule: Sudden Assignment of High‑Privilege Cloud Roles

```spl
index=azure sourcetype="azure:monitor:aad" \
  Operation="Add member to role" OR Operation="Add directory role member"
| search TargetResources.roleName IN("Global Administrator","Privileged Role Administrator","User Access Administrator")
| stats values(TargetResources) as targets, values(InitiatedBy) as actors by Operation, TimeGenerated
```

## 9. MICROSOFT SENTINEL DETECTION

### Query: Entra ID High‑Privilege Role Assignment and Federation Changes

```kusto
AuditLogs
| where OperationName in (
    'Add member to role',
    'Add directory role member',
    'Add identity provider',
    'Set federation settings on domain',
    'Set domain authentication'
  )
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, ModifiedProperties
```

## 10. WINDOWS EVENT LOG MONITORING

- Monitor domain controllers, ADFS and key servers for unusual admin logons associated with cloud identity tools and reverse SSH/RMM used by Scattered Spider.

## 11. SYSMON DETECTION PATTERNS

- Detect installation and use of remote access tools and off‑the‑shelf utilities (RMM, remote shells) used by the group.

## 12. MICROSOFT DEFENDER FOR CLOUD

- Enable identity‑based alerts and advanced detections for Entra ID risky users, impossible travel, and suspicious sign‑ins.

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

- Use audit searches focused on operations adding roles, identity providers, and modifying Conditional Access.

## 14. DEFENSIVE MITIGATIONS

- Harden helpdesk and SSPR: require strong out‑of‑band identity verification, block phone‑only verification for privileged roles, and record calls for QA.
- Implement phishing‑resistant MFA for admin and helpdesk identities.
- Restrict who can create or modify IdPs, inbound federation, and cross‑tenant access.
- Enforce Privileged Identity Management (PIM) and just‑in‑time elevation across IdPs and cloud IAM.

## 15. DETECTION AND INCIDENT RESPONSE

- Treat any signs of Scattered Spider‑like activity as a major incident.
- Immediately lock down IdP admin accounts, rotate MFA devices, and revoke sessions.
- Review all federated IdPs, inbound federation rules, and high‑privilege role assignments for tampering.

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | Social engineering, SIM swapping | Obtain initial account access. |
| 2 | Privilege Escalation | T1098.003 Additional Cloud Roles | Elevate permissions to IdP and cloud admin. |
| 3 | Current Step | REALWORLD-019 – Scattered Spider IdP TTP | Abuse IdP federation and IAM to maintain access. |
| 4 | Persistence | Federation backdoors, added MFA devices | Long‑term tenant access. |
| 5 | Impact | Data theft, ESXi compromise, ransomware | Monetise access through extortion. |

## 17. REAL-WORLD EXAMPLES

- Public reporting on MGM Resorts, Caesars and other Scattered Spider incidents showing inbound federation abuse, role escalation and identity‑centric operations.
- MITRE ATT&CK group entry for G1015 (Scattered Spider) and case C0027, describing IAM and federation abuse.

---