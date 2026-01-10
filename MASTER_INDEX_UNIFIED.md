# MCADDF - Microsoft Cybersecurity Attack, Detection \& Defense Framework

**Maintained by:** SERVTEP (France)
**Lead Architect:** Pchelnikau Artur
**Version:** 1.0 (Final Verified)
**Framework Alignment:** MITRE ATT\&CK® v18.1

## Executive Overview

This document serves as the master index for the **MCADDF - Microsoft Cybersecurity Attack, Detection \& Defense Framework**, a comprehensive operational project developed by the research division of **SERVTEP**. Curated under the technical leadership of **Pchelnikau Artur**, this framework provides a structured, tactical roadmap through 501 verified vectors in the modern adversarial lifecycle.

Unlike traditional pentest checklists, this framework is designed as a holistic resource for Purple Teaming. It bridges the critical gap between offensive tradecraft (Red Team), detection engineering (Blue Team), and architectural hardening (Defense), specifically tailored for **hybrid enterprise environments** (Windows Active Directory, Microsoft Entra ID, Azure, and Microsoft 365).

## Scope and Architecture

The framework is methodically organized by tactical phase and has been fully aligned with the **MITRE ATT\&CK® v18.1** standard. It encompasses:

* **Hybrid Identity Vectors:** Deep-dive methodologies for compromising and defending the synchronization points between on-premises AD and the cloud.
* **Cloud-Native Exploitation:** Targeted techniques for Azure Resources, Logic Apps, and SaaS persistence mechanisms.
* **Tactical Depth:** A granular breakdown of 501 specific procedures, ranging from standard enumeration to advanced exploitation, all rigorously validated by Pchelnikau Artur and the SERVTEP technical team.


## How to Use This Framework

This file acts as the central navigational hub for the repository.

* **SERVTEP ID System:** To simplify navigation, we have developed a proprietary identifier system (e.g., `REC-AD-001`, `CA-DUMP-005`). These **SERVTEP IDs** are structured similarly to MITRE IDs but are specific to this framework, allowing for precise tracking of custom techniques within our repository.
* **MITRE v18.1 Mapping:** Each technique is mapped to the latest MITRE T-codes (e.g., `T1590.001`) to ensure seamless correlation with modern threat intelligence feeds and defensive stacks.
* **File Paths:** Direct references to the detailed markdown files allow for modular access to execution steps, prerequisites, and operational security (OpSec) considerations.

> **⚠️ DISCLOSURE \& COMPLIANCE**
> This repository is intended strictly for **authorized security testing, educational purposes, and defensive research**. The techniques documented herein involve mechanisms that can disrupt critical business operations. Users are responsible for ensuring all activities are conducted within the scope of a signed Rule of Engagement (RoE) and in compliance with all applicable laws and regulations (e.g., CFAA, GDPR).

# CATEGORY 1: RECONNAISSANCE & DISCOVERY (18 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| REC-AD-001 | Tenant Discovery via domain properties | T1590.001 | N/A | Entra ID | [01_Recon/REC-AD-001_Tenant_Discovery.md](01_Recon/REC-AD-001_Tenant_Discovery.md) |
| REC-AD-002 | Anonymous LDAP Binding domain extraction | T1589.002 | N/A | Windows AD | [01_Recon/REC-AD-002_Anonymous_LDAP.md](01_Recon/REC-AD-002_Anonymous_LDAP.md) |
| REC-AD-003 | PowerView enumeration for domain mapping | T1087.002 | N/A | Windows AD | [01_Recon/REC-AD-003_PowerView.md](01_Recon/REC-AD-003_PowerView.md) |
| REC-CLOUD-001 | BloodHound for Azure/Entra privilege paths | T1087.004 | N/A | Entra ID | [01_Recon/REC-CLOUD-001_BloodHound.md](01_Recon/REC-CLOUD-001_BloodHound.md) |
| REC-CLOUD-002 | ROADtools Entra ID enumeration | T1087.004 | N/A | Entra ID | [01_Recon/REC-CLOUD-002_ROADtools.md](01_Recon/REC-CLOUD-002_ROADtools.md) |
| REC-CLOUD-003 | Stormspotter privilege escalation visualization | T1087.004 | N/A | Entra ID | [01_Recon/REC-CLOUD-003_Stormspotter.md](01_Recon/REC-CLOUD-003_Stormspotter.md) |
| REC-CLOUD-004 | AADInternals tenant reconnaissance | T1590 | N/A | Entra ID | [01_Recon/REC-CLOUD-004_AADInternals.md](01_Recon/REC-CLOUD-004_AADInternals.md) |
| REC-AD-004 | SPN scanning for kerberoastable accounts | T1087.002 | N/A | Windows AD | [01_Recon/REC-AD-004_SPN_Scanning.md](01_Recon/REC-AD-004_SPN_Scanning.md) |
| REC-AD-005 | BadPwdCount attribute monitoring | T1087.002 | N/A | Windows AD | [01_Recon/REC-AD-005_BadPwdCount.md](01_Recon/REC-AD-005_BadPwdCount.md) |
| REC-CLOUD-005 | Azure Resource Graph enumeration | T1580 | N/A | Entra ID | [01_Recon/REC-CLOUD-005_Azure_Resource_Graph.md](01_Recon/REC-CLOUD-005_Azure_Resource_Graph.md) |
| REC-M365-001 | Microsoft Graph API enumeration | T1087.004 | N/A | M365 | [01_Recon/REC-M365-001_Graph_API.md](01_Recon/REC-M365-001_Graph_API.md) |
| REC-M365-002 | Cross-tenant service discovery | T1580 | N/A | M365 | [01_Recon/REC-M365-002_Cross_Tenant.md](01_Recon/REC-M365-002_Cross_Tenant.md) |
| REC-CLOUD-006 | Azure service principal enumeration | T1087.004 | N/A | Entra ID | [01_Recon/REC-CLOUD-006_Service_Principals.md](01_Recon/REC-CLOUD-006_Service_Principals.md) |
| REC-CERT-001 | ADCS enumeration via Certify | T1087.002 | N/A | Windows AD | [01_Recon/REC-CERT-001_ADCS_Certify.md](01_Recon/REC-CERT-001_ADCS_Certify.md) |
| REC-CLOUD-007 | Azure Key Vault access enumeration | T1552.001 | CVE-2023-28432 | Entra ID | [01_Recon/REC-CLOUD-007_KeyVault.md](01_Recon/REC-CLOUD-007_KeyVault.md) |
| REC-HYBRID-001 | Azure AD Connect configuration enumeration | T1590 | CVE-2023-32315 | Hybrid AD | [01_Recon/REC-HYBRID-001_ADConnect.md](01_Recon/REC-HYBRID-001_ADConnect.md) |
| REC-AD-006 | IPv6 DNS poisoning with mitm6 | T1557.001 | N/A | Windows AD | [01_Recon/REC-AD-006_IPv6_DNS.md](01_Recon/REC-AD-006_IPv6_DNS.md) |
| REC-AD-007 | LAPS account discovery | T1087.002 | N/A | Windows AD | [01_Recon/REC-AD-007_LAPS.md](01_Recon/REC-AD-007_LAPS.md) |

---

# CATEGORY 2: INITIAL ACCESS (14 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| IA-PHISH-001 | Device code phishing attacks | T1566.002 | N/A | Entra ID/M365 | [02_Initial/IA-PHISH-001_Device_Code.md](02_Initial/IA-PHISH-001_Device_Code.md) |
| IA-PHISH-002 | Consent grant OAuth attacks | T1566.002 | N/A | Entra ID/M365 | [02_Initial/IA-PHISH-002_Consent_Grant.md](02_Initial/IA-PHISH-002_Consent_Grant.md) |
| IA-PHISH-003 | OAuth consent screen cloning | T1566.002 | N/A | M365/Entra ID | [02_Initial/IA-PHISH-003_OAuth_Cloning.md](02_Initial/IA-PHISH-003_OAuth_Cloning.md) |
| IA-PHISH-004 | Company branding login poisoning | T1566.002 | N/A | Entra ID | [02_Initial/IA-PHISH-004_Branding.md](02_Initial/IA-PHISH-004_Branding.md) |
| IA-PHISH-005 | Internal spearphishing campaigns | T1534 | N/A | M365 | [02_Initial/IA-PHISH-005_Internal.md](02_Initial/IA-PHISH-005_Internal.md) |
| IA-PHISH-006 | Exchange EWS impersonation phishing | T1534 | N/A | M365 | [02_Initial/IA-PHISH-006_EWS.md](02_Initial/IA-PHISH-006_EWS.md) |
| IA-EXPLOIT-001 | Azure Application Proxy exploitation | T1190 | N/A | Entra ID | [02_Initial/IA-EXPLOIT-001_App_Proxy.md](02_Initial/IA-EXPLOIT-001_App_Proxy.md) |
| IA-EXPLOIT-002 | BDC deserialization vulnerability | T1190 | N/A | Hybrid AD | [02_Initial/IA-EXPLOIT-002_BDC.md](02_Initial/IA-EXPLOIT-002_BDC.md) |
| IA-EXPLOIT-003 | Logic App HTTP trigger abuse | T1190 | N/A | Entra ID | [02_Initial/IA-EXPLOIT-003_Logic_App.md](02_Initial/IA-EXPLOIT-003_Logic_App.md) |
| IA-EXPLOIT-004 | Kubelet API unauthorized access | T1190 | N/A | Entra ID | [02_Initial/IA-EXPLOIT-004_Kubelet.md](02_Initial/IA-EXPLOIT-004_Kubelet.md) |
| IA-EXPLOIT-005 | AKS control plane access exploitation | T1190 | CVE-2025-21196 | Entra ID | [02_Initial/IA-EXPLOIT-005_AKS.md](02_Initial/IA-EXPLOIT-005_AKS.md) |
| IA-EXPLOIT-006 | Legacy API endpoint abuse | T1190 | N/A | M365/Entra ID | [02_Initial/IA-EXPLOIT-006_Legacy_API.md](02_Initial/IA-EXPLOIT-006_Legacy_API.md) |
| IA-VALID-001 | Default credential exploitation | T1078 | N/A | Windows AD/Entra ID | [02_Initial/IA-VALID-001_Default_Creds.md](02_Initial/IA-VALID-001_Default_Creds.md) |
| IA-VALID-002 | Stale/inactive account compromise | T1078 | N/A | Windows AD/Entra ID | [02_Initial/IA-VALID-002_Stale_Accounts.md](02_Initial/IA-VALID-002_Stale_Accounts.md) |

---

# CATEGORY 3: CREDENTIAL ACCESS (84 Techniques)

## Subcategory 3.1: OS Credential Dumping (10 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| CA-DUMP-001 | Mimikatz LSASS memory extraction | T1003.001 | CVE-2014-6318 | Windows Endpoint | [03_Cred/CA-DUMP-001_Mimikatz.md](03_Cred/CA-DUMP-001_Mimikatz.md) |
| CA-DUMP-002 | DCSync domain controller sync attack | T1003.006 | CVE-2014-6324 | Windows AD | [03_Cred/CA-DUMP-002_DCSync.md](03_Cred/CA-DUMP-002_DCSync.md) |
| CA-DUMP-003 | LSA secrets dump | T1003.004 | N/A | Windows Endpoint | [03_Cred/CA-DUMP-003_LSA.md](03_Cred/CA-DUMP-003_LSA.md) |
| CA-DUMP-004 | Cached domain credentials extraction | T1003.005 | N/A | Windows Endpoint | [03_Cred/CA-DUMP-004_Cached.md](03_Cred/CA-DUMP-004_Cached.md) |
| CA-DUMP-005 | SAM database extraction | T1003.002 | N/A | Windows Endpoint | [03_Cred/CA-DUMP-005_SAM.md](03_Cred/CA-DUMP-005_SAM.md) |
| CA-DUMP-006 | NTDS.dit extraction | T1003.003 | CVE-2014-6324 | Windows AD | [03_Cred/CA-DUMP-006_NTDS.md](03_Cred/CA-DUMP-006_NTDS.md) |
| CA-DUMP-007 | VSS NTDS.dit abuse | T1003.003 | N/A | Windows AD | [03_Cred/CA-DUMP-007_VSS.md](03_Cred/CA-DUMP-007_VSS.md) |
| CA-DUMP-008 | SCCM Content Library NTDS access | T1003.003 | N/A | Windows AD | [03_Cred/CA-DUMP-008_SCCM.md](03_Cred/CA-DUMP-008_SCCM.md) |
| CA-DUMP-009 | Mapped drive credential exposure | T1003.001 | N/A | Windows Endpoint | [03_Cred/CA-DUMP-009_Mapped.md](03_Cred/CA-DUMP-009_Mapped.md) |
| CA-DUMP-010 | UF_ENCRYPTED_TEXT_PASSWORD extraction | T1003 | N/A | Windows AD | [03_Cred/CA-DUMP-010_UF_Encrypted.md](03_Cred/CA-DUMP-010_UF_Encrypted.md) |

## Subcategory 3.2: Kerberos Ticket Attacks (17 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| CA-KERB-001 | Kerberoasting weak service accounts | T1558.003 | N/A | Windows AD | [03_Cred/CA-KERB-001_Kerberoasting.md](03_Cred/CA-KERB-001_Kerberoasting.md) |
| CA-KERB-002 | AS-REP roasting pre-auth disabled | T1558.004 | N/A | Windows AD | [03_Cred/CA-KERB-002_ASREPRoasting.md](03_Cred/CA-KERB-002_ASREPRoasting.md) |
| CA-KERB-003 | Golden ticket creation krbtgt | T1558.001 | CVE-2014-6324 | Windows AD | [03_Cred/CA-KERB-003_Golden_Ticket.md](03_Cred/CA-KERB-003_Golden_Ticket.md) |
| CA-KERB-004 | Silver ticket forgery | T1558.002 | N/A | Windows AD | [03_Cred/CA-KERB-004_Silver_Ticket.md](03_Cred/CA-KERB-004_Silver_Ticket.md) |
| CA-KERB-005 | Unconstrained delegation abuse | T1558 | CVE-2014-6324 | Windows AD | [03_Cred/CA-KERB-005_Unconstrained.md](03_Cred/CA-KERB-005_Unconstrained.md) |
| CA-KERB-006 | Constrained delegation abuse | T1558 | CVE-2021-42287 | Windows AD | [03_Cred/CA-KERB-006_Constrained.md](03_Cred/CA-KERB-006_Constrained.md) |
| CA-KERB-007 | MS14-068 checksum bypass | T1558 | CVE-2014-3967 | Windows AD | [03_Cred/CA-KERB-007_MS14-068.md](03_Cred/CA-KERB-007_MS14-068.md) |
| CA-KERB-008 | Bronze Bit ticket signing bypass | T1558 | CVE-2020-17049 | Windows AD | [03_Cred/CA-KERB-008_Bronze_Bit.md](03_Cred/CA-KERB-008_Bronze_Bit.md) |
| CA-KERB-009 | PKINIT downgrade attacks | T1558 | N/A | Windows AD | [03_Cred/CA-KERB-009_PKINIT.md](03_Cred/CA-KERB-009_PKINIT.md) |
| CA-KERB-010 | Time-based Kerberos exploitation | T1558 | N/A | Windows AD | [03_Cred/CA-KERB-010_Time_Based.md](03_Cred/CA-KERB-010_Time_Based.md) |
| CA-KERB-011 | No-PAC Kerberos bypass | T1558 | N/A | Windows AD | [03_Cred/CA-KERB-011_No_PAC.md](03_Cred/CA-KERB-011_No_PAC.md) |
| CA-KERB-012 | Golden ticket SIDHistory manipulation | T1558.001 | CVE-2014-6324 | Windows AD | [03_Cred/CA-KERB-012_Golden_SID.md](03_Cred/CA-KERB-012_Golden_SID.md) |
| CA-KERB-013 | Krbtgt cross-forest reuse | T1558.001 | CVE-2014-6324 | Windows AD | [03_Cred/CA-KERB-013_Krbtgt.md](03_Cred/CA-KERB-013_Krbtgt.md) |
| CA-KERB-014 | UnPAC-The-Hash Kerberos cracking | T1558 | CVE-2022-33679 | Windows AD | [03_Cred/CA-KERB-014_UnPAC.md](03_Cred/CA-KERB-014_UnPAC.md) |
| CA-KERB-015 | CCACHE keyring ticket reuse | T1558 | N/A | Linux/Unix | [03_Cred/CA-KERB-015_CCACHE_Keyring.md](03_Cred/CA-KERB-015_CCACHE_Keyring.md) |
| CA-KERB-016 | SSSD KCM CCACHE extraction | T1558 | N/A | Linux/Unix | [03_Cred/CA-KERB-016_SSSD.md](03_Cred/CA-KERB-016_SSSD.md) |
| CA-KERB-017 | Keytab CCACHE ticket reuse | T1558 | N/A | Linux/Unix | [03_Cred/CA-KERB-017_Keytab.md](03_Cred/CA-KERB-017_Keytab.md) |

## Subcategory 3.3: Password Stores & Unsecured Credentials (26 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| CA-STORE-001 | DPAPI credential decryption | T1555.003 | N/A | Windows Endpoint | [03_Cred/CA-STORE-001_DPAPI.md](03_Cred/CA-STORE-001_DPAPI.md) |
| CA-STORE-002 | Credential roaming abuse | T1555 | N/A | Windows AD | [03_Cred/CA-STORE-002_Roaming.md](03_Cred/CA-STORE-002_Roaming.md) |
| CA-STORE-003 | Windows Credential Manager vault extraction | T1555.004 | N/A | Windows Endpoint | [03_Cred/CA-STORE-003_Vault.md](03_Cred/CA-STORE-003_Vault.md) |
| CA-STORE-004 | Browser saved credentials harvesting | T1555.003 | N/A | Windows Endpoint/M365 | [03_Cred/CA-STORE-004_Browser.md](03_Cred/CA-STORE-004_Browser.md) |
| CA-STORE-005 | Windows Vault cached accounts | T1555.004 | N/A | Windows Endpoint | [03_Cred/CA-STORE-005_Windows_Vault.md](03_Cred/CA-STORE-005_Windows_Vault.md) |
| CA-UNSC-001 | /etc/krb5.keytab extraction | T1552.004 | N/A | Linux/Unix | [03_Cred/CA-UNSC-001_Keytab.md](03_Cred/CA-UNSC-001_Keytab.md) |
| CA-UNSC-002 | /etc/sssd/sssd.conf harvesting | T1552.001 | N/A | Linux/Unix | [03_Cred/CA-UNSC-002_SSSD.md](03_Cred/CA-UNSC-002_SSSD.md) |
| CA-UNSC-003 | SYSVOL GPP credential extraction | T1552.006 | N/A | Windows AD | [03_Cred/CA-UNSC-003_SYSVOL.md](03_Cred/CA-UNSC-003_SYSVOL.md) |
| CA-UNSC-004 | NTFRS SYSVOL replication abuse | T1552.006 | N/A | Windows AD | [03_Cred/CA-UNSC-004_NTFRS.md](03_Cred/CA-UNSC-004_NTFRS.md) |
| CA-UNSC-005 | gMSA credentials exposure | T1552.001 | N/A | Windows AD | [03_Cred/CA-UNSC-005_gMSA.md](03_Cred/CA-UNSC-005_gMSA.md) |
| CA-UNSC-006 | Private keys theft | T1552.004 | N/A | Multi-Env | [03_Cred/CA-UNSC-006_Private_Keys.md](03_Cred/CA-UNSC-006_Private_Keys.md) |
| CA-UNSC-007 | Azure Key Vault secret extraction | T1552.001 | CVE-2023-28432 | Entra ID | [03_Cred/CA-UNSC-007_KeyVault_Secrets.md](03_Cred/CA-UNSC-007_KeyVault_Secrets.md) |
| CA-UNSC-008 | Azure storage account key theft | T1552.001 | CVE-2023-28432 | Entra ID | [03_Cred/CA-UNSC-008_Storage_Keys.md](03_Cred/CA-UNSC-008_Storage_Keys.md) |
| CA-UNSC-009 | Azure Key Vault keys/certs extraction | T1552.004 | CVE-2023-28432 | Entra ID | [03_Cred/CA-UNSC-009_KeyVault_Keys.md](03_Cred/CA-UNSC-009_KeyVault_Keys.md) |
| CA-UNSC-010 | Service principal secrets harvesting | T1552.004 | N/A | Entra ID | [03_Cred/CA-UNSC-010_SP_Secrets.md](03_Cred/CA-UNSC-010_SP_Secrets.md) |
| CA-UNSC-011 | Key Vault access policies abuse | T1552.007 | CVE-2023-28432 | Entra ID | [03_Cred/CA-UNSC-011_KV_Policies.md](03_Cred/CA-UNSC-011_KV_Policies.md) |
| CA-UNSC-012 | MIP master key theft | T1552.001 | N/A | M365 | [03_Cred/CA-UNSC-012_MIP_Key.md](03_Cred/CA-UNSC-012_MIP_Key.md) |
| CA-UNSC-013 | TPM key extraction | T1552.004 | N/A | Entra ID | [03_Cred/CA-UNSC-013_TPM.md](03_Cred/CA-UNSC-013_TPM.md) |
| CA-UNSC-014 | SaaS API key exposure | T1552.001 | N/A | M365/Entra ID | [03_Cred/CA-UNSC-014_SaaS_Keys.md](03_Cred/CA-UNSC-014_SaaS_Keys.md) |
| CA-UNSC-015 | Pipeline environment variables theft | T1552.001 | N/A | Entra ID/DevOps | [03_Cred/CA-UNSC-015_Pipeline_Vars.md](03_Cred/CA-UNSC-015_Pipeline_Vars.md) |
| CA-UNSC-016 | Pipeline variable groups abuse | T1552.001 | N/A | Entra ID/DevOps | [03_Cred/CA-UNSC-016_Var_Groups.md](03_Cred/CA-UNSC-016_Var_Groups.md) |
| CA-UNSC-017 | IoT device connection strings theft | T1552.001 | N/A | Entra ID | [03_Cred/CA-UNSC-017_IoT_Strings.md](03_Cred/CA-UNSC-017_IoT_Strings.md) |
| CA-UNSC-018 | IoT device certificates theft | T1552.004 | N/A | Entra ID | [03_Cred/CA-UNSC-018_IoT_Certs.md](03_Cred/CA-UNSC-018_IoT_Certs.md) |
| CA-UNSC-019 | Federation server certificate theft | T1552.004 | N/A | Hybrid AD | [03_Cred/CA-UNSC-019_Fed_Certs.md](03_Cred/CA-UNSC-019_Fed_Certs.md) |
| CA-UNSC-020 | Multi-cloud federation certs theft | T1552.004 | N/A | Cross-Cloud | [03_Cred/CA-UNSC-020_Cloud_Certs.md](03_Cred/CA-UNSC-020_Cloud_Certs.md) |
| CA-UNSC-021 | Key Vault firewall bypass | T1552.007 | CVE-2023-28432 | Entra ID | [03_Cred/CA-UNSC-021_KV_Firewall.md](03_Cred/CA-UNSC-021_KV_Firewall.md) |

## Subcategory 3.4: Steal Application Access Tokens & Cookies (15 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| CA-TOKEN-001 | Hybrid AD cloud token theft | T1528 | CVE-2023-32315 | Hybrid AD | [03_Cred/CA-TOKEN-001_Hybrid_Token.md](03_Cred/CA-TOKEN-001_Hybrid_Token.md) |
| CA-TOKEN-002 | Azure AD Connect credential extraction | T1528 | CVE-2023-32315 | Hybrid AD | [03_Cred/CA-TOKEN-002_AADConnect.md](03_Cred/CA-TOKEN-002_AADConnect.md) |
| CA-TOKEN-003 | Azure Function key extraction | T1528 | N/A | Entra ID | [03_Cred/CA-TOKEN-003_Function_Keys.md](03_Cred/CA-TOKEN-003_Function_Keys.md) |
| CA-TOKEN-004 | Graph API token theft | T1528 | N/A | M365 | [03_Cred/CA-TOKEN-004_Graph_Token.md](03_Cred/CA-TOKEN-004_Graph_Token.md) |
| CA-TOKEN-005 | OAuth access token interception | T1528 | N/A | Entra ID | [03_Cred/CA-TOKEN-005_OAuth_Token.md](03_Cred/CA-TOKEN-005_OAuth_Token.md) |
| CA-TOKEN-006 | Service principal certificate theft | T1528 | N/A | Entra ID | [03_Cred/CA-TOKEN-006_SP_Cert.md](03_Cred/CA-TOKEN-006_SP_Cert.md) |
| CA-TOKEN-007 | Managed identity token theft | T1528 | N/A | Entra ID | [03_Cred/CA-TOKEN-007_Managed_ID.md](03_Cred/CA-TOKEN-007_Managed_ID.md) |
| CA-TOKEN-008 | Azure DevOps PAT theft | T1528 | CVE-2023-21540 | Entra ID | [03_Cred/CA-TOKEN-008_DevOps_PAT.md](03_Cred/CA-TOKEN-008_DevOps_PAT.md) |
| CA-TOKEN-009 | Teams token extraction | T1528 | N/A | M365 | [03_Cred/CA-TOKEN-009_Teams_Token.md](03_Cred/CA-TOKEN-009_Teams_Token.md) |
| CA-TOKEN-010 | Office document token theft | T1528 | N/A | M365 | [03_Cred/CA-TOKEN-010_Office_Token.md](03_Cred/CA-TOKEN-010_Office_Token.md) |
| CA-TOKEN-011 | Exchange Online OAuth token theft | T1528 | N/A | M365 | [03_Cred/CA-TOKEN-011_Exchange_Token.md](03_Cred/CA-TOKEN-011_Exchange_Token.md) |
| CA-TOKEN-012 | PRT Primary Refresh Token attacks | T1528 | CVE-2021-42287 | Entra ID | [03_Cred/CA-TOKEN-012_PRT.md](03_Cred/CA-TOKEN-012_PRT.md) |
| CA-COOKIE-001 | SharePoint Online cookie theft | T1539 | N/A | M365 | [03_Cred/CA-COOKIE-001_SP_Cookie.md](03_Cred/CA-COOKIE-001_SP_Cookie.md) |
| CA-COOKIE-002 | Authenticator app session hijacking | T1539 | N/A | Entra ID | [03_Cred/CA-COOKIE-002_Authenticator.md](03_Cred/CA-COOKIE-002_Authenticator.md) |
| CA-FORGE-001 | Golden SAML cross-tenant attack | T1606.002 | CVE-2021-26906 | Hybrid AD/Entra ID | [03_Cred/CA-FORGE-001_Golden_SAML.md](03_Cred/CA-FORGE-001_Golden_SAML.md) |

---

## Subcategory 3.5: Cloud & Cross-Cloud Token Attacks (16 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| CA-TOKEN-013 | AKS service account token theft | T1528 | N/A | Entra ID | [03_Cred/CA-TOKEN-013_AKS_Token.md](03_Cred/CA-TOKEN-013_AKS_Token.md) |
| CA-TOKEN-014 | Container registry token theft | T1528 | N/A | Entra ID | [03_Cred/CA-TOKEN-014_Registry_Token.md](03_Cred/CA-TOKEN-014_Registry_Token.md) |
| CA-TOKEN-015 | DevOps pipeline credential extraction | T1528 | N/A | Entra ID/DevOps | [03_Cred/CA-TOKEN-015_Pipeline_Creds.md](03_Cred/CA-TOKEN-015_Pipeline_Creds.md) |
| CA-TOKEN-016 | Artifact registry token theft | T1528 | N/A | Entra ID | [03_Cred/CA-TOKEN-016_Artifact_Token.md](03_Cred/CA-TOKEN-016_Artifact_Token.md) |
| CA-TOKEN-017 | Package source credential theft | T1528 | N/A | Entra ID/DevOps | [03_Cred/CA-TOKEN-017_Package_Creds.md](03_Cred/CA-TOKEN-017_Package_Creds.md) |
| CA-TOKEN-018 | Cloud-to-cloud token compromise | T1528 | N/A | Cross-Cloud | [03_Cred/CA-TOKEN-018_Cloud2Cloud.md](03_Cred/CA-TOKEN-018_Cloud2Cloud.md) |
| CA-TOKEN-019 | AWS STS token abuse via Azure | T1528 | N/A | Cross-Cloud | [03_Cred/CA-TOKEN-019_AWS_STS.md](03_Cred/CA-TOKEN-019_AWS_STS.md) |
| CA-TOKEN-020 | FIDO2 resident credential extraction | T1528 | N/A | Entra ID | [03_Cred/CA-TOKEN-020_FIDO2.md](03_Cred/CA-TOKEN-020_FIDO2.md) |
| CA-TOKEN-021 | Entra SSO credential theft | T1528 | N/A | M365/Entra ID | [03_Cred/CA-TOKEN-021_SSO_Creds.md](03_Cred/CA-TOKEN-021_SSO_Creds.md) |
| CA-TOKEN-022 | SP certificate token forgery | T1552.004 | N/A | Entra ID | [03_Cred/CA-TOKEN-022_SP_Forgery.md](03_Cred/CA-TOKEN-022_SP_Forgery.md) |
| CA-FORGE-002 | ADFS token forging | T1606.002 | N/A | Hybrid AD | [03_Cred/CA-FORGE-002_ADFS_Token.md](03_Cred/CA-FORGE-002_ADFS_Token.md) |
| CA-FORCE-001 | SCF/URL file NTLM trigger | T1187 | CVE-2025-24054 | Windows AD | [03_Cred/CA-FORCE-001_SCF_URL.md](03_Cred/CA-FORCE-001_SCF_URL.md) |
| CA-FORCE-002 | .library-ms NTLM hash leakage | T1187 | CVE-2025-24054 | Windows AD | [03_Cred/CA-FORCE-002_Library_ms.md](03_Cred/CA-FORCE-002_Library_ms.md) |
| CA-BRUTE-001 | Azure portal password spray | T1110.003 | N/A | Entra ID | [03_Cred/CA-BRUTE-001_Azure_Spray.md](03_Cred/CA-BRUTE-001_Azure_Spray.md) |
| CA-BRUTE-002 | Distributed password spraying | T1110.003 | N/A | Multi-Env | [03_Cred/CA-BRUTE-002_Password_Spray.md](03_Cred/CA-BRUTE-002_Password_Spray.md) |
| CA-BRUTE-003 | MFA bombing/fatigue attacks | T1621 | N/A | Entra ID | [03_Cred/CA-BRUTE-003_MFA_Bombing.md](03_Cred/CA-BRUTE-003_MFA_Bombing.md) |

---

# CATEGORY 4: PRIVILEGE ESCALATION (73 Techniques)

## Subcategory 4.1: Access Token Manipulation (9 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PE-TOKEN-001 | Token Impersonation privilege escalation | T1134.001 | N/A | Windows Endpoint | [04_PrivEsc/PE-TOKEN-001_Token_Impersonation.md](04_PrivEsc/PE-TOKEN-001_Token_Impersonation.md) |
| PE-TOKEN-002 | Resource-Based Constrained Delegation (RBCD) | T1134.005 | CVE-2021-42287 | Windows AD | [04_PrivEsc/PE-TOKEN-002_RBCD.md](04_PrivEsc/PE-TOKEN-002_RBCD.md) |
| PE-TOKEN-003 | ForeignSecurityPrincipal SID Abuse | T1134.005 | N/A | Windows AD | [04_PrivEsc/PE-TOKEN-003_FSP_SID.md](04_PrivEsc/PE-TOKEN-003_FSP_SID.md) |
| PE-TOKEN-004 | SIDHistory Injection | T1134.005 | N/A | Windows AD | [04_PrivEsc/PE-TOKEN-004_SIDHistory.md](04_PrivEsc/PE-TOKEN-004_SIDHistory.md) |
| PE-TOKEN-005 | RID Hijacking | T1134.005 | CVE-2021-42287 | Windows AD | [04_PrivEsc/PE-TOKEN-005_RID_Hijacking.md](04_PrivEsc/PE-TOKEN-005_RID_Hijacking.md) |
| PE-TOKEN-006 | SamAccountName Spoofing | T1134.005 | CVE-2021-42287 | Windows AD | [04_PrivEsc/PE-TOKEN-006_SamAccountName.md](04_PrivEsc/PE-TOKEN-006_SamAccountName.md) |
| PE-TOKEN-007 | SeEnableDelegationPrivilege Abuse | T1134 | N/A | Windows AD | [04_PrivEsc/PE-TOKEN-007_SeEnableDelegation.md](04_PrivEsc/PE-TOKEN-007_SeEnableDelegation.md) |
| PE-TOKEN-008 | API Authentication Token Manipulation | T1134 | N/A | Entra ID | [04_PrivEsc/PE-TOKEN-008_API_Token.md](04_PrivEsc/PE-TOKEN-008_API_Token.md) |
| PE-TOKEN-009 | CLFS Driver Token Impersonation | T1134.001 | N/A | Windows Endpoint | [04_PrivEsc/PE-TOKEN-009_CLFS_Token.md](04_PrivEsc/PE-TOKEN-009_CLFS_Token.md) |

## Subcategory 4.2: Exploitation for Privilege Escalation (8 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PE-EXPLOIT-001 | PrintNightmare remote privilege escalation | T1068 | CVE-2021-34527 | Windows AD/Endpoint | [04_PrivEsc/PE-EXPLOIT-001_PrintNightmare.md](04_PrivEsc/PE-EXPLOIT-001_PrintNightmare.md) |
| PE-EXPLOIT-002 | ZeroLogon DC compromise | T1068 | CVE-2020-1472 | Windows AD | [04_PrivEsc/PE-EXPLOIT-002_ZeroLogon.md](04_PrivEsc/PE-EXPLOIT-002_ZeroLogon.md) |
| PE-EXPLOIT-003 | CLFS Driver Memory Corruption | T1068 | CVE-2025-29824 | Windows Endpoint | [04_PrivEsc/PE-EXPLOIT-003_CLFS_Driver.md](04_PrivEsc/PE-EXPLOIT-003_CLFS_Driver.md) |
| PE-EXPLOIT-004 | Container Escape to Host | T1611 | CVE-2025-21196 | Entra ID | [04_PrivEsc/PE-EXPLOIT-004_Container_Escape.md](04_PrivEsc/PE-EXPLOIT-004_Container_Escape.md) |
| PE-EXPLOIT-005 | Pod Security Context Escalation | T1068 | N/A | Entra ID | [04_PrivEsc/PE-EXPLOIT-005_Pod_Security.md](04_PrivEsc/PE-EXPLOIT-005_Pod_Security.md) |
| PE-EXPLOIT-006 | Container Runtime Socket Abuse | T1068 | N/A | Entra ID | [04_PrivEsc/PE-EXPLOIT-006_Container_Runtime.md](04_PrivEsc/PE-EXPLOIT-006_Container_Runtime.md) |
| PE-EXPLOIT-007 | IoT Edge Runtime Escalation | T1068 | N/A | Entra ID | [04_PrivEsc/PE-EXPLOIT-007_IoT_Edge.md](04_PrivEsc/PE-EXPLOIT-007_IoT_Edge.md) |
| PE-EXPLOIT-008 | AKS Container Escape (CVE-2025-21196) | T1611 | CVE-2025-21196 | Entra ID | [04_PrivEsc/PE-EXPLOIT-008_AKS_Container.md](04_PrivEsc/PE-EXPLOIT-008_AKS_Container.md) |

## Subcategory 4.3: Domain Policy Modification (7 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PE-POLICY-001 | GPO Abuse for Persistence escalation | T1484.001 | N/A | Windows AD | [04_PrivEsc/PE-POLICY-001_GPO_Abuse.md](04_PrivEsc/PE-POLICY-001_GPO_Abuse.md) |
| PE-POLICY-002 | Creating Rogue GPOs | T1484.001 | N/A | Windows AD | [04_PrivEsc/PE-POLICY-002_Rogue_GPO.md](04_PrivEsc/PE-POLICY-002_Rogue_GPO.md) |
| PE-POLICY-003 | Azure Management Group Escalation | T1484.001 | CVE-2023-28432 | Entra ID | [04_PrivEsc/PE-POLICY-003_Mgmt_Group.md](04_PrivEsc/PE-POLICY-003_Mgmt_Group.md) |
| PE-POLICY-004 | Azure Lighthouse Delegation Abuse | T1484.001 | N/A | Entra ID | [04_PrivEsc/PE-POLICY-004_Lighthouse.md](04_PrivEsc/PE-POLICY-004_Lighthouse.md) |
| PE-POLICY-005 | Cross-tenant Privilege Escalation | T1484.002 | N/A | M365/Entra ID | [04_PrivEsc/PE-POLICY-005_Cross_Tenant.md](04_PrivEsc/PE-POLICY-005_Cross_Tenant.md) |
| PE-POLICY-006 | Federation Trust Relationship Abuse | T1484.002 | N/A | Hybrid AD | [04_PrivEsc/PE-POLICY-006_Fed_Trust.md](04_PrivEsc/PE-POLICY-006_Fed_Trust.md) |
| PE-POLICY-007 | Azure Policy Definition Injection | T1484.001 | N/A | Entra ID | [04_PrivEsc/PE-POLICY-007_Azure_Policy.md](04_PrivEsc/PE-POLICY-007_Azure_Policy.md) |

## Subcategory 4.4: Valid Accounts Escalation (17 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PE-VALID-001 | Exchange Server ACL Abuse | T1078.002 | N/A | Windows AD | [04_PrivEsc/PE-VALID-001_Exchange_ACL.md](04_PrivEsc/PE-VALID-001_Exchange_ACL.md) |
| PE-VALID-002 | Computer Account Quota Abuse | T1078.002 | CVE-2021-42287 | Windows AD | [04_PrivEsc/PE-VALID-002_Comp_Quota.md](04_PrivEsc/PE-VALID-002_Comp_Quota.md) |
| PE-VALID-003 | Unfiltered DNSAdmins Access | T1078.002 | N/A | Windows AD | [04_PrivEsc/PE-VALID-003_DNSAdmins.md](04_PrivEsc/PE-VALID-003_DNSAdmins.md) |
| PE-VALID-004 | Delegation Misconfiguration | T1078.002 | N/A | Windows AD | [04_PrivEsc/PE-VALID-004_Delegation.md](04_PrivEsc/PE-VALID-004_Delegation.md) |
| PE-VALID-005 | Cross-Forest Trust Exploitation | T1078.002 | N/A | Windows AD | [04_PrivEsc/PE-VALID-005_Cross_Forest.md](04_PrivEsc/PE-VALID-005_Cross_Forest.md) |
| PE-VALID-006 | Directory Services Restore Mode (DSRM) | T1078.002 | N/A | Windows AD | [04_PrivEsc/PE-VALID-006_DSRM.md](04_PrivEsc/PE-VALID-006_DSRM.md) |
| PE-VALID-007 | Abusing Print Operators Group | T1078.002 | N/A | Windows AD | [04_PrivEsc/PE-VALID-007_Print_Operators.md](04_PrivEsc/PE-VALID-007_Print_Operators.md) |
| PE-VALID-008 | SCCM Client Push Account Abuse | T1078.003 | N/A | Windows AD | [04_PrivEsc/PE-VALID-008_SCCM_Push.md](04_PrivEsc/PE-VALID-008_SCCM_Push.md) |
| PE-VALID-009 | SCCM NAA Privilege Escalation | T1078.002 | N/A | Windows AD | [04_PrivEsc/PE-VALID-009_SCCM_NAA.md](04_PrivEsc/PE-VALID-009_SCCM_NAA.md) |
| PE-VALID-010 | Azure Role Assignment Abuse | T1078.004 | N/A | Entra ID | [04_PrivEsc/PE-VALID-010_Azure_Role.md](04_PrivEsc/PE-VALID-010_Azure_Role.md) |
| PE-VALID-011 | Managed Identity MSI Escalation | T1078.004 | N/A | Entra ID | [04_PrivEsc/PE-VALID-011_MSI.md](04_PrivEsc/PE-VALID-011_MSI.md) |
| PE-VALID-012 | Azure VM Contributor to Owner | T1078.004 | N/A | Entra ID | [04_PrivEsc/PE-VALID-012_VM_Contributor.md](04_PrivEsc/PE-VALID-012_VM_Contributor.md) |
| PE-VALID-013 | Azure Guest User Escalation | T1078.004 | N/A | Entra ID | [04_PrivEsc/PE-VALID-013_Guest_User.md](04_PrivEsc/PE-VALID-013_Guest_User.md) |
| PE-VALID-014 | Microsoft Partners/CSP Access Abuse | T1078.004 | N/A | M365/Entra ID | [04_PrivEsc/PE-VALID-014_CSP_Access.md](04_PrivEsc/PE-VALID-014_CSP_Access.md) |
| PE-VALID-015 | AKS Node Identity Compromise | T1078.004 | N/A | Entra ID | [04_PrivEsc/PE-VALID-015_AKS_Node.md](04_PrivEsc/PE-VALID-015_AKS_Node.md) |
| PE-VALID-016 | Managed Identity Pod Assignment | T1078.004 | N/A | Entra ID | [04_PrivEsc/PE-VALID-016_Pod_Identity.md](04_PrivEsc/PE-VALID-016_Pod_Identity.md) |
| PE-VALID-017 | Azure Lighthouse Cross-Tenant | T1078.004 | N/A | Entra ID | [04_PrivEsc/PE-VALID-017_Lighthouse_CT.md](04_PrivEsc/PE-VALID-017_Lighthouse_CT.md) |

## Subcategory 4.5: Account Manipulation (17 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PE-ACCTMGMT-001 | App Registration Permissions Escalation | T1098 | N/A | Entra ID | [04_PrivEsc/PE-ACCTMGMT-001_App_Reg.md](04_PrivEsc/PE-ACCTMGMT-001_App_Reg.md) |
| PE-ACCTMGMT-002 | Exchange Online Admin to Global | T1098 | N/A | M365 | [04_PrivEsc/PE-ACCTMGMT-002_Exchange_Admin.md](04_PrivEsc/PE-ACCTMGMT-002_Exchange_Admin.md) |
| PE-ACCTMGMT-003 | SharePoint Site Collection Admin | T1098 | N/A | M365 | [04_PrivEsc/PE-ACCTMGMT-003_SharePoint_Admin.md](04_PrivEsc/PE-ACCTMGMT-003_SharePoint_Admin.md) |
| PE-ACCTMGMT-004 | Teams Admin to Global Admin | T1098 | N/A | M365 | [04_PrivEsc/PE-ACCTMGMT-004_Teams_Admin.md](04_PrivEsc/PE-ACCTMGMT-004_Teams_Admin.md) |
| PE-ACCTMGMT-005 | PowerApps/Power Platform Escalation | T1098 | N/A | M365 | [04_PrivEsc/PE-ACCTMGMT-005_PowerApps.md](04_PrivEsc/PE-ACCTMGMT-005_PowerApps.md) |
| PE-ACCTMGMT-006 | Intune Admin to Global Admin | T1098 | N/A | M365 | [04_PrivEsc/PE-ACCTMGMT-006_Intune_Admin.md](04_PrivEsc/PE-ACCTMGMT-006_Intune_Admin.md) |
| PE-ACCTMGMT-007 | Exchange RBAC Abuse | T1098 | N/A | M365 | [04_PrivEsc/PE-ACCTMGMT-007_Exchange_RBAC.md](04_PrivEsc/PE-ACCTMGMT-007_Exchange_RBAC.md) |
| PE-ACCTMGMT-008 | Azure Automation Runbook Escalation | T1098 | N/A | Entra ID | [04_PrivEsc/PE-ACCTMGMT-008_Automation.md](04_PrivEsc/PE-ACCTMGMT-008_Automation.md) |
| PE-ACCTMGMT-009 | Microsoft Defender for Cloud | T1098 | N/A | Entra ID | [04_PrivEsc/PE-ACCTMGMT-009_Defender_Cloud.md](04_PrivEsc/PE-ACCTMGMT-009_Defender_Cloud.md) |
| PE-ACCTMGMT-010 | Azure DevOps Pipeline Escalation | T1098 | N/A | Entra ID | [04_PrivEsc/PE-ACCTMGMT-010_DevOps.md](04_PrivEsc/PE-ACCTMGMT-010_DevOps.md) |
| PE-ACCTMGMT-011 | Privileged Identity Management (PIM) Abuse | T1098 | N/A | Entra ID | [04_PrivEsc/PE-ACCTMGMT-011_PIM.md](04_PrivEsc/PE-ACCTMGMT-011_PIM.md) |
| PE-ACCTMGMT-012 | Hybrid RBAC/PIM Role Activation | T1098 | N/A | Hybrid AD | [04_PrivEsc/PE-ACCTMGMT-012_Hybrid_RBAC.md](04_PrivEsc/PE-ACCTMGMT-012_Hybrid_RBAC.md) |
| PE-ACCTMGMT-013 | Self-Service Password Reset Misconfiguration | T1098 | N/A | Entra ID | [04_PrivEsc/PE-ACCTMGMT-013_SSPR.md](04_PrivEsc/PE-ACCTMGMT-013_SSPR.md) |
| PE-ACCTMGMT-014 | Global Administrator Backdoor | T1098 | N/A | Entra ID | [04_PrivEsc/PE-ACCTMGMT-014_Global_Admin.md](04_PrivEsc/PE-ACCTMGMT-014_Global_Admin.md) |
| PE-ACCTMGMT-015 | Directory Synchronization Manipulation | T1098 | CVE-2023-32315 | Hybrid AD | [04_PrivEsc/PE-ACCTMGMT-015_DirSync.md](04_PrivEsc/PE-ACCTMGMT-015_DirSync.md) |
| PE-ACCTMGMT-016 | Microsoft SCIM Provisioning Abuse | T1098 | N/A | Entra ID | [04_PrivEsc/PE-ACCTMGMT-016_SCIM.md](04_PrivEsc/PE-ACCTMGMT-016_SCIM.md) |
| PE-ACCTMGMT-017 | Shadow Principal Configuration | T1098.004 | N/A | Entra ID | [04_PrivEsc/PE-ACCTMGMT-017_Shadow_Principal.md](04_PrivEsc/PE-ACCTMGMT-017_Shadow_Principal.md) |

## Subcategory 4.6: Abuse Elevation Control & Remote Services (12 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PE-ELEVATE-001 | AD CS Certificate Services Abuse | T1548 | CVE-2021-27239 | Windows AD | [04_PrivEsc/PE-ELEVATE-001_ADCS.md](04_PrivEsc/PE-ELEVATE-001_ADCS.md) |
| PE-ELEVATE-002 | Alternative Subject Alternative Names (SANs) | T1548 | CVE-2021-27239 | Windows AD | [04_PrivEsc/PE-ELEVATE-002_SAN.md](04_PrivEsc/PE-ELEVATE-002_SAN.md) |
| PE-ELEVATE-003 | API Rate Limiting Bypass | T1548 | N/A | Entra ID/M365 | [04_PrivEsc/PE-ELEVATE-003_Rate_Limit.md](04_PrivEsc/PE-ELEVATE-003_Rate_Limit.md) |
| PE-ELEVATE-004 | Custom API RBAC Bypass | T1548 | N/A | Entra ID | [04_PrivEsc/PE-ELEVATE-004_Custom_API.md](04_PrivEsc/PE-ELEVATE-004_Custom_API.md) |
| PE-ELEVATE-005 | Graph API Permission Escalation | T1548 | N/A | M365/Entra ID | [04_PrivEsc/PE-ELEVATE-005_Graph_API.md](04_PrivEsc/PE-ELEVATE-005_Graph_API.md) |
| PE-ELEVATE-006 | Kubernetes RBAC Abuse | T1548 | N/A | Entra ID | [04_PrivEsc/PE-ELEVATE-006_K8s_RBAC.md](04_PrivEsc/PE-ELEVATE-006_K8s_RBAC.md) |
| PE-ELEVATE-007 | AKS RBAC Excessive Permissions | T1548 | N/A | Entra ID | [04_PrivEsc/PE-ELEVATE-007_AKS_RBAC.md](04_PrivEsc/PE-ELEVATE-007_AKS_RBAC.md) |
| PE-ELEVATE-008 | SaaS Admin Account Escalation | T1548 | N/A | M365/Entra ID | [04_PrivEsc/PE-ELEVATE-008_SaaS_Admin.md](04_PrivEsc/PE-ELEVATE-008_SaaS_Admin.md) |
| PE-ELEVATE-009 | IoT Central Device Group Escalation | T1548 | N/A | Entra ID | [04_PrivEsc/PE-ELEVATE-009_IoT_Central.md](04_PrivEsc/PE-ELEVATE-009_IoT_Central.md) |
| PE-ELEVATE-010 | Enterprise Application Permission | T1548 | N/A | M365/Entra ID | [04_PrivEsc/PE-ELEVATE-010_EntApp_Perm.md](04_PrivEsc/PE-ELEVATE-010_EntApp_Perm.md) |
| PE-REMOTE-001 | Exchange Server Vulnerabilities | T1210 | CVE-2021-27065 | Windows AD | [04_PrivEsc/PE-REMOTE-001_Exchange.md](04_PrivEsc/PE-REMOTE-001_Exchange.md) |
| PE-REMOTE-002 | PrivExchange Attack | T1210 | CVE-2019-0604 | Windows AD | [04_PrivEsc/PE-REMOTE-002_PrivExchange.md](04_PrivEsc/PE-REMOTE-002_PrivExchange.md) |

## Subcategory 4.7: Create Account (2 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PE-CREATE-001 | Insecure ms-DS-MachineAccountQuota | T1136.001 | CVE-2021-42287 | Windows AD | [04_PrivEsc/PE-CREATE-001_MachineAcctQuota.md](04_PrivEsc/PE-CREATE-001_MachineAcctQuota.md) |
| PE-CREATE-002 | MachineAccountQuota > 0 Exploitation | T1136.001 | N/A | Windows AD | [04_PrivEsc/PE-CREATE-002_MAQ_Exploit.md](04_PrivEsc/PE-CREATE-002_MAQ_Exploit.md) |

## Subcategory 4.8: Discovery (1 technique)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PE-DISCOVER-001 | Azure Key Vault Managed Identity Discovery | T1580 | CVE-2023-28432 | Entra ID | [04_PrivEsc/PE-DISCOVER-001_KV_ManagedID.md](04_PrivEsc/PE-DISCOVER-001_KV_ManagedID.md) |

---

# CATEGORY 5: PERSISTENCE (45 Techniques)

## Subcategory 5.1: Account Manipulation - Persistence (8 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PERSIST-ACCT-001 | AdminSDHolder Abuse | T1098 | N/A | Windows AD | [05_Persist/PERSIST-ACCT-001_AdminSDHolder.md](05_Persist/PERSIST-ACCT-001_AdminSDHolder.md) |
| PERSIST-ACCT-002 | Shadow Credentials Backdoor | T1098 | N/A | Windows AD | [05_Persist/PERSIST-ACCT-002_Shadow_Creds.md](05_Persist/PERSIST-ACCT-002_Shadow_Creds.md) |
| PERSIST-ACCT-003 | Group Nesting Abuse | T1098 | N/A | Windows AD | [05_Persist/PERSIST-ACCT-003_Group_Nesting.md](05_Persist/PERSIST-ACCT-003_Group_Nesting.md) |
| PERSIST-ACCT-004 | Azure Automation Account Persistence | T1098 | N/A | Entra ID | [05_Persist/PERSIST-ACCT-004_Automation.md](05_Persist/PERSIST-ACCT-004_Automation.md) |
| PERSIST-ACCT-005 | Graph API Application Persistence | T1098 | N/A | M365/Entra ID | [05_Persist/PERSIST-ACCT-005_Graph_App.md](05_Persist/PERSIST-ACCT-005_Graph_App.md) |
| PERSIST-ACCT-006 | Service Principal Cert/Secret Persistence | T1098 | N/A | Entra ID | [05_Persist/PERSIST-ACCT-006_SP_Persistence.md](05_Persist/PERSIST-ACCT-006_SP_Persistence.md) |
| PERSIST-ACCT-007 | Exchange Transport Rules Backdoor | T1098 | N/A | M365 | [05_Persist/PERSIST-ACCT-007_Transport_Rules.md](05_Persist/PERSIST-ACCT-007_Transport_Rules.md) |
| PERSIST-ACCT-008 | Custom Directory Extensions | T1098 | N/A | Entra ID | [05_Persist/PERSIST-ACCT-008_Dir_Extensions.md](05_Persist/PERSIST-ACCT-008_Dir_Extensions.md) |

## Subcategory 5.2: Valid Accounts - Persistence (5 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PERSIST-VALID-001 | Service Account Hijacking | T1078.002 | N/A | Windows AD | [05_Persist/PERSIST-VALID-001_Service_Acct.md](05_Persist/PERSIST-VALID-001_Service_Acct.md) |
| PERSIST-VALID-002 | Azure AD Connect Sync Persistence | T1078.004 | CVE-2023-32315 | Hybrid AD | [05_Persist/PERSIST-VALID-002_AADConnect.md](05_Persist/PERSIST-VALID-002_AADConnect.md) |
| PERSIST-VALID-003 | Azure AD Connect Server Takeover | T1078.004 | CVE-2023-32315 | Hybrid AD | [05_Persist/PERSIST-VALID-003_AADConnect_Takeover.md](05_Persist/PERSIST-VALID-003_AADConnect_Takeover.md) |
| PERSIST-VALID-004 | AzureAD Hybrid Join Exploitation | T1078.004 | N/A | Hybrid AD | [05_Persist/PERSIST-VALID-004_Hybrid_Join.md](05_Persist/PERSIST-VALID-004_Hybrid_Join.md) |
| PERSIST-VALID-005 | Workload Identity Federation | T1078.004 | N/A | Entra ID | [05_Persist/PERSIST-VALID-005_Workload_ID.md](05_Persist/PERSIST-VALID-005_Workload_ID.md) |

## Subcategory 5.3: Boot/Logon Execution & Scheduled Tasks (6 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PERSIST-BOOT-001 | Abusing Security Support Provider | T1547.005 | N/A | Windows AD | [05_Persist/PERSIST-BOOT-001_SSP.md](05_Persist/PERSIST-BOOT-001_SSP.md) |
| PERSIST-BOOT-002 | Weaponizing Printer Bug | T1547 | N/A | Windows AD | [05_Persist/PERSIST-BOOT-002_Printer_Bug.md](05_Persist/PERSIST-BOOT-002_Printer_Bug.md) |
| PERSIST-BOOT-003 | Startup Scripts via GPO | T1037 | N/A | Windows AD | [05_Persist/PERSIST-BOOT-003_GPO_Scripts.md](05_Persist/PERSIST-BOOT-003_GPO_Scripts.md) |
| PERSIST-SCHED-001 | Azure Runbook Persistence | T1053 | N/A | Entra ID | [05_Persist/PERSIST-SCHED-001_Runbook.md](05_Persist/PERSIST-SCHED-001_Runbook.md) |
| PERSIST-SCHED-002 | Logic App Backdoors | T1053 | N/A | Entra ID | [05_Persist/PERSIST-SCHED-002_Logic_App.md](05_Persist/PERSIST-SCHED-002_Logic_App.md) |
| PERSIST-SCHED-003 | Azure DevOps Pipeline Persistence | T1053 | N/A | Entra ID | [05_Persist/PERSIST-SCHED-003_Pipeline.md](05_Persist/PERSIST-SCHED-003_Pipeline.md) |

## Subcategory 5.4: Server Software Components (9 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PERSIST-SERVER-001 | Skeleton Key Malware | T1505.003 | N/A | Windows AD | [05_Persist/PERSIST-SERVER-001_Skeleton_Key.md](05_Persist/PERSIST-SERVER-001_Skeleton_Key.md) |
| PERSIST-SERVER-002 | DSRM Account Backdoor | T1505.003 | N/A | Windows AD | [05_Persist/PERSIST-SERVER-002_DSRM.md](05_Persist/PERSIST-SERVER-002_DSRM.md) |
| PERSIST-SERVER-003 | Azure Function Backdoor | T1505.003 | N/A | Entra ID | [05_Persist/PERSIST-SERVER-003_Function.md](05_Persist/PERSIST-SERVER-003_Function.md) |
| PERSIST-SERVER-004 | Teams Webhook Persistence | T1505.003 | N/A | M365 | [05_Persist/PERSIST-SERVER-004_Teams_Webhook.md](05_Persist/PERSIST-SERVER-004_Teams_Webhook.md) |
| PERSIST-SERVER-005 | SharePoint Site Script Persistence | T1505.003 | N/A | M365 | [05_Persist/PERSIST-SERVER-005_SharePoint_Script.md](05_Persist/PERSIST-SERVER-005_SharePoint_Script.md) |
| PERSIST-SERVER-006 | App Service Deployment Persistence | T1505.003 | N/A | Entra ID | [05_Persist/PERSIST-SERVER-006_App_Service.md](05_Persist/PERSIST-SERVER-006_App_Service.md) |
| PERSIST-SERVER-007 | SaaS Application Backdoor | T1505.003 | N/A | M365/Entra ID | [05_Persist/PERSIST-SERVER-007_SaaS_Backdoor.md](05_Persist/PERSIST-SERVER-007_SaaS_Backdoor.md) |
| PERSIST-SERVER-008 | CLFS Driver Backdoor (CVE-2025-29824) | T1505.003 | CVE-2025-29824 | Windows Endpoint | [05_Persist/PERSIST-SERVER-008_CLFS.md](05_Persist/PERSIST-SERVER-008_CLFS.md) |
| PERSIST-SCHED-004 | SCCM Application Deployment | T1053.005 | N/A | Windows AD | [05_Persist/PERSIST-SCHED-004_SCCM_App.md](05_Persist/PERSIST-SCHED-004_SCCM_App.md) |

## Subcategory 5.5: Event Triggered & Process Injection (5 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PERSIST-EVENT-001 | WMI Event Subscriptions | T1546.003 | N/A | Windows Endpoint | [05_Persist/PERSIST-EVENT-001_WMI.md](05_Persist/PERSIST-EVENT-001_WMI.md) |
| PERSIST-EVENT-002 | Intune Management Extension | T1546 | N/A | M365 | [05_Persist/PERSIST-EVENT-002_Intune_Ext.md](05_Persist/PERSIST-EVENT-002_Intune_Ext.md) |
| PERSIST-EVENT-003 | Microsoft Power Automate Flow | T1546 | N/A | M365 | [05_Persist/PERSIST-EVENT-003_Power_Automate.md](05_Persist/PERSIST-EVENT-003_Power_Automate.md) |
| PERSIST-MODIFY-001 | Skeleton Key Attack | T1556 | N/A | Windows AD | [05_Persist/PERSIST-MODIFY-001_Skeleton_Key.md](05_Persist/PERSIST-MODIFY-001_Skeleton_Key.md) |
| PERSIST-MODIFY-002 | Malicious Certificate Template | T1556.004 | CVE-2021-27239 | Windows AD | [05_Persist/PERSIST-MODIFY-002_Cert_Template.md](05_Persist/PERSIST-MODIFY-002_Cert_Template.md) |

## Subcategory 5.6: Rogue DC & Trust Modification (6 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PERSIST-ROGUE-001 | DCShadow Attack | T1207 | N/A | Windows AD | [05_Persist/PERSIST-ROGUE-001_DCShadow.md](05_Persist/PERSIST-ROGUE-001_DCShadow.md) |
| PERSIST-ROGUE-002 | Domain Controller Cloning | T1207 | N/A | Windows AD | [05_Persist/PERSIST-ROGUE-002_DC_Clone.md](05_Persist/PERSIST-ROGUE-002_DC_Clone.md) |
| PERSIST-ROGUE-003 | ADFS Farm Compromise | T1207 | N/A | Hybrid AD | [05_Persist/PERSIST-ROGUE-003_ADFS_Farm.md](05_Persist/PERSIST-ROGUE-003_ADFS_Farm.md) |
| PERSIST-INJECT-001 | Credential Injection via LSASS | T1055.001 | N/A | Windows Endpoint | [05_Persist/PERSIST-INJECT-001_LSASS.md](05_Persist/PERSIST-INJECT-001_LSASS.md) |
| PERSIST-EMAIL-001 | Mail Forwarding Rules | T1114 | N/A | M365 | [05_Persist/PERSIST-EMAIL-001_Mail_Forward.md](05_Persist/PERSIST-EMAIL-001_Mail_Forward.md) |
| PERSIST-REMOTE-001 | SharePoint Exploitation | T1133 | N/A | M365 | [05_Persist/PERSIST-REMOTE-001_SharePoint.md](05_Persist/PERSIST-REMOTE-001_SharePoint.md) |

## Subcategory 5.7: Impair Defenses & Policy Backdoors (6 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| PERSIST-IMPAIR-001 | Conditional Access Policy Backdoors | T1562.001 | N/A | Entra ID | [05_Persist/PERSIST-IMPAIR-001_CA_Backdoor.md](05_Persist/PERSIST-IMPAIR-001_CA_Backdoor.md) |
| PERSIST-IMPAIR-002 | Authentication Policy Backdoors | T1562.001 | N/A | Entra ID | [05_Persist/PERSIST-IMPAIR-002_Auth_Policy.md](05_Persist/PERSIST-IMPAIR-002_Auth_Policy.md) |
| PERSIST-IMPAIR-003 | Microsoft Information Protection Labels | T1562.001 | N/A | M365 | [05_Persist/PERSIST-IMPAIR-003_MIP_Labels.md](05_Persist/PERSIST-IMPAIR-003_MIP_Labels.md) |
| PERSIST-TRUST-001 | Federation Trust Configuration Tampering | T1484.002 | N/A | Cross-Cloud | [05_Persist/PERSIST-TRUST-001_Fed_Config.md](05_Persist/PERSIST-TRUST-001_Fed_Config.md) |
| PERSIST-TRUST-002 | Tenant-to-Tenant Migration Abuse | T1484.002 | N/A | M365/Entra ID | [05_Persist/PERSIST-TRUST-002_T2T_Migration.md](05_Persist/PERSIST-TRUST-002_T2T_Migration.md) |
| PERSIST-PROCESS-001 | Directory Service Restore Mode Attack | T1543 | N/A | Windows AD | [05_Persist/PERSIST-PROCESS-001_DSRM_Attack.md](05_Persist/PERSIST-PROCESS-001_DSRM_Attack.md) |

---

# CATEGORY 6: DEFENSE EVASION (40 Techniques)

## Subcategory 6.1: Impair Defenses (22 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| EVADE-IMPAIR-001 | Disable Security Tools (AV/EDR) | T1562.001 | N/A | Windows Endpoint | [06_Evasion/EVADE-IMPAIR-001_Disable_AV.md](06_Evasion/EVADE-IMPAIR-001_Disable_AV.md) |
| EVADE-IMPAIR-002 | AMSI Bypass Techniques | T1562.001 | CVE-2019-0604 | Windows Endpoint | [06_Evasion/EVADE-IMPAIR-002_AMSI_Bypass.md](06_Evasion/EVADE-IMPAIR-002_AMSI_Bypass.md) |
| EVADE-IMPAIR-003 | PowerShell Script Block Logging Bypass | T1562.002 | N/A | Windows Endpoint | [06_Evasion/EVADE-IMPAIR-003_PSBLock_Bypass.md](06_Evasion/EVADE-IMPAIR-003_PSBLock_Bypass.md) |
| EVADE-IMPAIR-004 | Event Log Clearing | T1070.001 | N/A | Windows Endpoint | [06_Evasion/EVADE-IMPAIR-004_EventLog.md](06_Evasion/EVADE-IMPAIR-004_EventLog.md) |
| EVADE-IMPAIR-005 | Azure Function Runtime Manipulation | T1562 | N/A | Entra ID | [06_Evasion/EVADE-IMPAIR-005_Azure_Runtime.md](06_Evasion/EVADE-IMPAIR-005_Azure_Runtime.md) |
| EVADE-IMPAIR-006 | Azure Run Command Obfuscation | T1562 | N/A | Entra ID | [06_Evasion/EVADE-IMPAIR-006_Run_Command.md](06_Evasion/EVADE-IMPAIR-006_Run_Command.md) |
| EVADE-IMPAIR-007 | M365 Audit Log Tampering | T1562.008 | N/A | M365 | [06_Evasion/EVADE-IMPAIR-007_Audit_Log.md](06_Evasion/EVADE-IMPAIR-007_Audit_Log.md) |
| EVADE-IMPAIR-008 | Conditional Access Exclusion Abuse | T1562.001 | N/A | Entra ID | [06_Evasion/EVADE-IMPAIR-008_CA_Exclusion.md](06_Evasion/EVADE-IMPAIR-008_CA_Exclusion.md) |
| EVADE-IMPAIR-009 | Exchange Transport Rule Evasion | T1562 | N/A | M365 | [06_Evasion/EVADE-IMPAIR-009_Transport_Rule.md](06_Evasion/EVADE-IMPAIR-009_Transport_Rule.md) |
| EVADE-IMPAIR-010 | Security Group Exemption Abuse | T1562.001 | N/A | Entra ID/M365 | [06_Evasion/EVADE-IMPAIR-010_Security_Group.md](06_Evasion/EVADE-IMPAIR-010_Security_Group.md) |
| EVADE-IMPAIR-011 | Azure Identity Protection Evasion | T1562 | N/A | Entra ID | [06_Evasion/EVADE-IMPAIR-011_IdentityProt.md](06_Evasion/EVADE-IMPAIR-011_IdentityProt.md) |
| EVADE-IMPAIR-012 | Sentinel Detection Rule Bypass | T1562.001 | N/A | Entra ID | [06_Evasion/EVADE-IMPAIR-012_Sentinel.md](06_Evasion/EVADE-IMPAIR-012_Sentinel.md) |
| EVADE-IMPAIR-013 | Defender for Cloud Apps Bypass | T1562.001 | N/A | M365 | [06_Evasion/EVADE-IMPAIR-013_Cloud_Apps.md](06_Evasion/EVADE-IMPAIR-013_Cloud_Apps.md) |
| EVADE-IMPAIR-014 | Defender for Endpoint Bypass | T1562.001 | N/A | Windows Endpoint/M365 | [06_Evasion/EVADE-IMPAIR-014_MDE_Bypass.md](06_Evasion/EVADE-IMPAIR-014_MDE_Bypass.md) |
| EVADE-IMPAIR-015 | MDE/EDR Sensor Tampering | T1562.001 | N/A | Windows Endpoint/M365 | [06_Evasion/EVADE-IMPAIR-015_Sensor_Tamper.md](06_Evasion/EVADE-IMPAIR-015_Sensor_Tamper.md) |
| EVADE-IMPAIR-016 | Kerberos Clock Synchronization Attack | T1562.006 | N/A | Windows AD | [06_Evasion/EVADE-IMPAIR-016_Kerberos_Clock.md](06_Evasion/EVADE-IMPAIR-016_Kerberos_Clock.md) |
| EVADE-IMPAIR-017 | Kerberos Encryption Downgrade | T1562.006 | N/A | Windows AD | [06_Evasion/EVADE-IMPAIR-017_Kerb_Downgrade.md](06_Evasion/EVADE-IMPAIR-017_Kerb_Downgrade.md) |
| EVADE-IMPAIR-018 | Azure Guest Configuration Tampering | T1562 | N/A | Entra ID | [06_Evasion/EVADE-IMPAIR-018_Guest_Config.md](06_Evasion/EVADE-IMPAIR-018_Guest_Config.md) |
| EVADE-IMPAIR-019 | Azure Policy Assignment Gaps | T1562 | N/A | Entra ID | [06_Evasion/EVADE-IMPAIR-019_Policy_Gaps.md](06_Evasion/EVADE-IMPAIR-019_Policy_Gaps.md) |
| EVADE-IMPAIR-020 | Microsoft Defender Misconfiguration | T1562.001 | N/A | M365/Entra ID | [06_Evasion/EVADE-IMPAIR-020_Defender_Misconfig.md](06_Evasion/EVADE-IMPAIR-020_Defender_Misconfig.md) |
| EVADE-IMPAIR-021 | StrongCertificateBindingEnforcement=0 | T1562.001 | N/A | Windows AD | [06_Evasion/EVADE-IMPAIR-021_StrongCert.md](06_Evasion/EVADE-IMPAIR-021_StrongCert.md) |
| EVADE-IMPAIR-022 | Certificate CT_FLAG_NO_SECURITY | T1562.001 | N/A | Windows AD | [06_Evasion/EVADE-IMPAIR-022_CT_Flag.md](06_Evasion/EVADE-IMPAIR-022_CT_Flag.md) |

## Subcategory 6.2: Obfuscation & System Abuse (3 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| EVADE-OBFUS-001 | Obfuscated Scripts | T1027 | N/A | Windows Endpoint | [06_Evasion/EVADE-OBFUS-001_Obfuscation.md](06_Evasion/EVADE-OBFUS-001_Obfuscation.md) |
| EVADE-OBFUS-002 | Azure Automation Runbook Obfuscation | T1027 | N/A | Entra ID | [06_Evasion/EVADE-OBFUS-002_Runbook_Obfus.md](06_Evasion/EVADE-OBFUS-002_Runbook_Obfus.md) |
| EVADE-BINARY-001 | Living off the Land (LoLBins) | T1218 | N/A | Windows Endpoint | [06_Evasion/EVADE-BINARY-001_LoLBins.md](06_Evasion/EVADE-BINARY-001_LoLBins.md) |

## Subcategory 6.3: Registry, Timestomping & Artifacts (15 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| EVADE-REGISTRY-001 | WDigest Registry Manipulation | T1112 | N/A | Windows Endpoint | [06_Evasion/EVADE-REGISTRY-001_WDigest.md](06_Evasion/EVADE-REGISTRY-001_WDigest.md) |
| EVADE-INDICATOR-001 | Timestomping | T1070.006 | N/A | Windows Endpoint | [06_Evasion/EVADE-INDICATOR-001_Timestomp.md](06_Evasion/EVADE-INDICATOR-001_Timestomp.md) |
| EVADE-HIJACK-001 | Trusted Path Hijacking | T1574 | N/A | Windows Endpoint | [06_Evasion/EVADE-HIJACK-001_Path_Hijack.md](06_Evasion/EVADE-HIJACK-001_Path_Hijack.md) |
| EVADE-HIDE-001 | Microsoft Teams Message Hiding | T1564 | N/A | M365 | [06_Evasion/EVADE-HIDE-001_Teams_Message.md](06_Evasion/EVADE-HIDE-001_Teams_Message.md) |
| EVADE-PERMS-001 | Loose or Default ACLs | T1222 | N/A | Windows AD | [06_Evasion/EVADE-PERMS-001_ACLs.md](06_Evasion/EVADE-PERMS-001_ACLs.md) |
| EVADE-PERMS-002 | GPO Creator Permission Model | T1222 | N/A | Windows AD | [06_Evasion/EVADE-PERMS-002_GPO_Perms.md](06_Evasion/EVADE-PERMS-002_GPO_Perms.md) |
| EVADE-DATA-001 | Azure Storage Soft Delete Bypass | T1485 | N/A | Entra ID | [06_Evasion/EVADE-DATA-001_Storage_Delete.md](06_Evasion/EVADE-DATA-001_Storage_Delete.md) |
| EVADE-MFA-001 | Azure MFA Bypass Techniques | T1556.006 | N/A | Entra ID | [06_Evasion/EVADE-MFA-001_MFA_Bypass.md](06_Evasion/EVADE-MFA-001_MFA_Bypass.md) |
| EVADE-MFA-002 | Windows Hello for Business Bypasses | T1556 | N/A | Hybrid AD | [06_Evasion/EVADE-MFA-002_WHfB_Bypass.md](06_Evasion/EVADE-MFA-002_WHfB_Bypass.md) |
| EVADE-MFA-003 | FIDO2 Security Key Cloning | T1556 | N/A | Entra ID | [06_Evasion/EVADE-MFA-003_FIDO2_Clone.md](06_Evasion/EVADE-MFA-003_FIDO2_Clone.md) |
| EVADE-MFA-004 | Legacy Authentication Enabled | T1556 | N/A | Entra ID/M365 | [06_Evasion/EVADE-MFA-004_Legacy_Auth.md](06_Evasion/EVADE-MFA-004_Legacy_Auth.md) |
| EVADE-MFA-005 | CLFS Driver Authentication Bypass | T1556.006 | CVE-2025-29824 | Windows Endpoint | [06_Evasion/EVADE-MFA-005_CLFS_Auth.md](06_Evasion/EVADE-MFA-005_CLFS_Auth.md) |
| EVADE-VALID-001 | Azure PIM Role Activation Obfuscation | T1078.004 | N/A | Entra ID | [06_Evasion/EVADE-VALID-001_PIM_Obfus.md](06_Evasion/EVADE-VALID-001_PIM_Obfus.md) |
| EVADE-VALID-002 | External Guest Invitation for Bypass | T1078.004 | N/A | Entra ID | [06_Evasion/EVADE-VALID-002_Guest_Bypass.md](06_Evasion/EVADE-VALID-002_Guest_Bypass.md) |
| EVADE-IMPLANT-001 | Azure Compute Gallery Image Template | T1525 | N/A | Entra ID | [06_Evasion/EVADE-IMPLANT-001_Gallery_Image.md](06_Evasion/EVADE-IMPLANT-001_Gallery_Image.md) |

---

# CATEGORY 7: LATERAL MOVEMENT (50 Techniques)

## Subcategory 7.1: Remote Services (11 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| LM-REMOTE-001 | SMB/Windows Admin Shares | T1021.002 | N/A | Windows Endpoint | [07_Lateral/LM-REMOTE-001_SMB_Shares.md](07_Lateral/LM-REMOTE-001_SMB_Shares.md) |
| LM-REMOTE-002 | Distributed Component Object Model (DCOM) | T1021.003 | N/A | Windows Endpoint | [07_Lateral/LM-REMOTE-002_DCOM.md](07_Lateral/LM-REMOTE-002_DCOM.md) |
| LM-REMOTE-003 | Remote Desktop Protocol (RDP) | T1021.001 | N/A | Windows Endpoint | [07_Lateral/LM-REMOTE-003_RDP.md](07_Lateral/LM-REMOTE-003_RDP.md) |
| LM-REMOTE-004 | Windows Remote Management (WinRM) | T1021.006 | N/A | Windows Endpoint | [07_Lateral/LM-REMOTE-004_WinRM.md](07_Lateral/LM-REMOTE-004_WinRM.md) |
| LM-REMOTE-005 | SMB/RDP/PS Remoting/WMI Chaining | T1021 | N/A | Windows Endpoint | [07_Lateral/LM-REMOTE-005_Multi_Protocol.md](07_Lateral/LM-REMOTE-005_Multi_Protocol.md) |
| LM-REMOTE-006 | WebClient/WebDAV Lateral Movement | T1021 | N/A | Windows Endpoint | [07_Lateral/LM-REMOTE-006_WebDAV.md](07_Lateral/LM-REMOTE-006_WebDAV.md) |
| LM-REMOTE-007 | Azure VM to VM Lateral Movement | T1021 | N/A | Entra ID | [07_Lateral/LM-REMOTE-007_Azure_VM.md](07_Lateral/LM-REMOTE-007_Azure_VM.md) |
| LM-REMOTE-008 | Azure VNET Peering Traversal | T1021 | N/A | Entra ID | [07_Lateral/LM-REMOTE-008_VNET_Peering.md](07_Lateral/LM-REMOTE-008_VNET_Peering.md) |
| LM-REMOTE-009 | Private Link/Service Endpoint | T1021 | N/A | Entra ID | [07_Lateral/LM-REMOTE-009_PrivateLink.md](07_Lateral/LM-REMOTE-009_PrivateLink.md) |
| LM-REMOTE-010 | Azure Virtual WAN Trust Exploitation | T1021 | N/A | Entra ID | [07_Lateral/LM-REMOTE-010_vWAN.md](07_Lateral/LM-REMOTE-010_vWAN.md) |
| LM-REMOTE-011 | Azure-to-On-Premises Movement | T1021 | N/A | Hybrid AD | [07_Lateral/LM-REMOTE-011_Azure2OnPrem.md](07_Lateral/LM-REMOTE-011_Azure2OnPrem.md) |

## Subcategory 7.2: Use Alternate Authentication Material (39 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| LM-AUTH-001 | Pass-the-Hash (PTH) | T1550.002 | N/A | Windows AD/Endpoint | [07_Lateral/LM-AUTH-001_PTH.md](07_Lateral/LM-AUTH-001_PTH.md) |
| LM-AUTH-002 | Pass-the-Ticket (PTT) | T1550.003 | N/A | Windows AD/Endpoint | [07_Lateral/LM-AUTH-002_PTT.md](07_Lateral/LM-AUTH-002_PTT.md) |
| LM-AUTH-003 | Pass-the-Certificate | T1550.004 | N/A | Hybrid AD/Entra ID | [07_Lateral/LM-AUTH-003_PTC.md](07_Lateral/LM-AUTH-003_PTC.md) |
| LM-AUTH-004 | Pass-the-PRT (Primary Refresh Token) | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-004_PRT.md](07_Lateral/LM-AUTH-004_PRT.md) |
| LM-AUTH-005 | Service Principal Key/Certificate | T1550.001 | N/A | Entra ID | [07_Lateral/LM-AUTH-005_SP_Key.md](07_Lateral/LM-AUTH-005_SP_Key.md) |
| LM-AUTH-006 | Microsoft Teams Authentication Bypass | T1550 | N/A | M365 | [07_Lateral/LM-AUTH-006_Teams_Auth.md](07_Lateral/LM-AUTH-006_Teams_Auth.md) |
| LM-AUTH-007 | SharePoint Authentication Bypass | T1550 | N/A | M365 | [07_Lateral/LM-AUTH-007_SharePoint_Auth.md](07_Lateral/LM-AUTH-007_SharePoint_Auth.md) |
| LM-AUTH-008 | Legacy Authentication Protocol Abuse | T1550 | N/A | M365/Entra ID | [07_Lateral/LM-AUTH-008_Legacy_Auth.md](07_Lateral/LM-AUTH-008_Legacy_Auth.md) |
| LM-AUTH-009 | Azure B2B Collaboration Abuse | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-009_B2B.md](07_Lateral/LM-AUTH-009_B2B.md) |
| LM-AUTH-010 | Seamless SSO Abuse | T1550 | N/A | Hybrid AD | [07_Lateral/LM-AUTH-010_Seamless_SSO.md](07_Lateral/LM-AUTH-010_Seamless_SSO.md) |
| LM-AUTH-011 | Overpass-the-Hash (Pass-the-Key) | T1550.002 | N/A | Windows AD | [07_Lateral/LM-AUTH-011_Overpass.md](07_Lateral/LM-AUTH-011_Overpass.md) |
| LM-AUTH-012 | Cross-Tenant Access via Azure B2B | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-012_B2B_CT.md](07_Lateral/LM-AUTH-012_B2B_CT.md) |
| LM-AUTH-013 | Exchange Online EWS Impersonation | T1550 | N/A | M365 | [07_Lateral/LM-AUTH-013_EWS.md](07_Lateral/LM-AUTH-013_EWS.md) |
| LM-AUTH-014 | Microsoft Teams to SharePoint | T1550 | N/A | M365 | [07_Lateral/LM-AUTH-014_Teams_SP.md](07_Lateral/LM-AUTH-014_Teams_SP.md) |
| LM-AUTH-015 | SharePoint Site Collection Movement | T1550 | N/A | M365 | [07_Lateral/LM-AUTH-015_SP_Collection.md](07_Lateral/LM-AUTH-015_SP_Collection.md) |
| LM-AUTH-016 | Managed Identity Cross-Resource | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-016_ManagedID_Cross.md](07_Lateral/LM-AUTH-016_ManagedID_Cross.md) |
| LM-AUTH-017 | Power Platform Dataflows | T1550 | N/A | M365 | [07_Lateral/LM-AUTH-017_Power_Dataflows.md](07_Lateral/LM-AUTH-017_Power_Dataflows.md) |
| LM-AUTH-018 | Teams App Manifest | T1550 | N/A | M365 | [07_Lateral/LM-AUTH-018_Teams_Manifest.md](07_Lateral/LM-AUTH-018_Teams_Manifest.md) |
| LM-AUTH-019 | Azure AD Connect Server to AD | T1550 | CVE-2023-32315 | Hybrid AD | [07_Lateral/LM-AUTH-019_AADConnect.md](07_Lateral/LM-AUTH-019_AADConnect.md) |
| LM-AUTH-020 | Microsoft Defender Portal | T1550 | N/A | M365 | [07_Lateral/LM-AUTH-020_Defender_Portal.md](07_Lateral/LM-AUTH-020_Defender_Portal.md) |
| LM-AUTH-021 | Azure Lighthouse Cross-Tenant | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-021_Lighthouse_CT.md](07_Lateral/LM-AUTH-021_Lighthouse_CT.md) |
| LM-AUTH-022 | Azure Site Recovery | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-022_Site_Recovery.md](07_Lateral/LM-AUTH-022_Site_Recovery.md) |
| LM-AUTH-023 | On-Premises-to-Azure Movement | T1550 | N/A | Hybrid AD | [07_Lateral/LM-AUTH-023_OnPrem_Azure.md](07_Lateral/LM-AUTH-023_OnPrem_Azure.md) |
| LM-AUTH-024 | Workload Identity Federation Abuse | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-024_Workload_ID_Fed.md](07_Lateral/LM-AUTH-024_Workload_ID_Fed.md) |
| LM-AUTH-025 | Azure Cross-Tenant OAuth Abuse | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-025_OAuth_CT.md](07_Lateral/LM-AUTH-025_OAuth_CT.md) |
| LM-AUTH-026 | Authentication Assertion Replay | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-026_Assertion_Replay.md](07_Lateral/LM-AUTH-026_Assertion_Replay.md) |
| LM-AUTH-027 | Cross-Cloud Resource Access | T1550 | N/A | Cross-Cloud | [07_Lateral/LM-AUTH-027_Cloud_Resource.md](07_Lateral/LM-AUTH-027_Cloud_Resource.md) |
| LM-AUTH-028 | Azure External Identities Abuse | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-028_Ext_Identities.md](07_Lateral/LM-AUTH-028_Ext_Identities.md) |
| LM-AUTH-029 | OAuth Application Permissions | T1550 | N/A | Entra ID/M365 | [07_Lateral/LM-AUTH-029_OAuth_App.md](07_Lateral/LM-AUTH-029_OAuth_App.md) |
| LM-AUTH-030 | AKS Service Account Token Theft | T1528 | N/A | Entra ID | [07_Lateral/LM-AUTH-030_AKS_Token.md](07_Lateral/LM-AUTH-030_AKS_Token.md) |
| LM-AUTH-031 | Container Registry Cross-Registry | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-031_Registry_Cross.md](07_Lateral/LM-AUTH-031_Registry_Cross.md) |
| LM-AUTH-032 | Function App Identity Hopping | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-032_Function_Hop.md](07_Lateral/LM-AUTH-032_Function_Hop.md) |
| LM-AUTH-033 | Logic App Authentication Chain | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-033_Logic_Chain.md](07_Lateral/LM-AUTH-033_Logic_Chain.md) |
| LM-AUTH-034 | Data Factory Credential Reuse | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-034_DataFactory.md](07_Lateral/LM-AUTH-034_DataFactory.md) |
| LM-AUTH-035 | Synapse Workspace Cross-Access | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-035_Synapse.md](07_Lateral/LM-AUTH-035_Synapse.md) |
| LM-AUTH-036 | CosmosDB Connection String Reuse | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-036_CosmosDB.md](07_Lateral/LM-AUTH-036_CosmosDB.md) |
| LM-AUTH-037 | Event Hub Shared Access Key | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-037_EventHub.md](07_Lateral/LM-AUTH-037_EventHub.md) |
| LM-AUTH-038 | Service Bus Shared Access Key | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-038_ServiceBus.md](07_Lateral/LM-AUTH-038_ServiceBus.md) |
| LM-AUTH-039 | Storage Account Connection String | T1550 | N/A | Entra ID | [07_Lateral/LM-AUTH-039_Storage_ConnStr.md](07_Lateral/LM-AUTH-039_Storage_ConnStr.md) |

---

# CATEGORY 8: COLLECTION (31 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| COLLECT-EMAIL-001 | Email Collection via EWS | T1114 | N/A | M365 | [08_Collection/COLLECT-EMAIL-001_EWS.md](08_Collection/COLLECT-EMAIL-001_EWS.md) |
| COLLECT-EMAIL-002 | Outlook Mailbox Export | T1114.001 | N/A | M365 | [08_Collection/COLLECT-EMAIL-002_Outlook_Export.md](08_Collection/COLLECT-EMAIL-002_Outlook_Export.md) |
| COLLECT-EMAIL-003 | Mail Search via PowerShell | T1114 | N/A | M365 | [08_Collection/COLLECT-EMAIL-003_Mail_Search.md](08_Collection/COLLECT-EMAIL-003_Mail_Search.md) |
| COLLECT-ARCHIVE-001 | Archive Mailbox Data Extraction | T1123 | N/A | M365 | [08_Collection/COLLECT-ARCHIVE-001_Archive.md](08_Collection/COLLECT-ARCHIVE-001_Archive.md) |
| COLLECT-SCREEN-001 | SharePoint Document Collection | T1123 | N/A | M365 | [08_Collection/COLLECT-SCREEN-001_SharePoint_Docs.md](08_Collection/COLLECT-SCREEN-001_SharePoint_Docs.md) |
| COLLECT-CHAT-001 | Teams Chat Extraction | T1123 | N/A | M365 | [08_Collection/COLLECT-CHAT-001_Teams_Chat.md](08_Collection/COLLECT-CHAT-001_Teams_Chat.md) |
| COLLECT-CALL-001 | Teams Call Recording Extraction | T1123 | N/A | M365 | [08_Collection/COLLECT-CALL-001_Teams_Recording.md](08_Collection/COLLECT-CALL-001_Teams_Recording.md) |
| COLLECT-CHAT-002 | OneDrive Data Collection | T1123 | N/A | M365 | [08_Collection/COLLECT-CHAT-002_OneDrive.md](08_Collection/COLLECT-CHAT-002_OneDrive.md) |
| COLLECT-DATA-001 | Azure Blob Storage Data Exfiltration | T1537 | N/A | Entra ID | [08_Collection/COLLECT-DATA-001_Blob_Storage.md](08_Collection/COLLECT-DATA-001_Blob_Storage.md) |
| COLLECT-DATA-002 | Azure SQL Database Dump | T1537 | N/A | Entra ID | [08_Collection/COLLECT-DATA-002_SQL_Dump.md](08_Collection/COLLECT-DATA-002_SQL_Dump.md) |
| COLLECT-DATA-003 | Azure Cosmos DB Data Extraction | T1537 | N/A | Entra ID | [08_Collection/COLLECT-DATA-003_CosmosDB.md](08_Collection/COLLECT-DATA-003_CosmosDB.md) |
| COLLECT-DATA-004 | Synapse Analytics Data Access | T1537 | N/A | Entra ID | [08_Collection/COLLECT-DATA-004_Synapse.md](08_Collection/COLLECT-DATA-004_Synapse.md) |
| COLLECT-CRED-001 | Credential Collection from Registry | T1555 | N/A | Windows Endpoint | [08_Collection/COLLECT-CRED-001_Registry_Creds.md](08_Collection/COLLECT-CRED-001_Registry_Creds.md) |
| COLLECT-CRED-002 | Browser Cookie Collection | T1185 | N/A | Windows Endpoint/M365 | [08_Collection/COLLECT-CRED-002_Browser_Cookies.md](08_Collection/COLLECT-CRED-002_Browser_Cookies.md) |
| COLLECT-CRED-003 | DPAPI Credential Extraction | T1555.003 | N/A | Windows Endpoint | [08_Collection/COLLECT-CRED-003_DPAPI_Creds.md](08_Collection/COLLECT-CRED-003_DPAPI_Creds.md) |
| COLLECT-DISK-001 | Disk Content Collection | T1123 | N/A | Windows Endpoint | [08_Collection/COLLECT-DISK-001_Disk_Content.md](08_Collection/COLLECT-DISK-001_Disk_Content.md) |
| COLLECT-NETWORK-001 | Network Traffic Interception | T1040 | N/A | Multi-Env | [08_Collection/COLLECT-NETWORK-001_Traffic.md](08_Collection/COLLECT-NETWORK-001_Traffic.md) |
| COLLECT-LOGS-001 | Azure Activity Logs Collection | T1552.001 | N/A | Entra ID | [08_Collection/COLLECT-LOGS-001_Activity_Logs.md](08_Collection/COLLECT-LOGS-001_Activity_Logs.md) |
| COLLECT-LOGS-002 | Azure Diagnostic Logs Exfiltration | T1552.001 | N/A | Entra ID | [08_Collection/COLLECT-LOGS-002_Diagnostic_Logs.md](08_Collection/COLLECT-LOGS-002_Diagnostic_Logs.md) |
| COLLECT-CONFIG-001 | Azure Resource Configuration Export | T1552.001 | N/A | Entra ID | [08_Collection/COLLECT-CONFIG-001_Config_Export.md](08_Collection/COLLECT-CONFIG-001_Config_Export.md) |
| COLLECT-METADATA-001 | SharePoint Metadata Collection | T1123 | N/A | M365 | [08_Collection/COLLECT-METADATA-001_Metadata.md](08_Collection/COLLECT-METADATA-001_Metadata.md) |
| COLLECT-FORM-001 | Form Responses & Survey Data | T1123 | N/A | M365 | [08_Collection/COLLECT-FORM-001_Forms.md](08_Collection/COLLECT-FORM-001_Forms.md) |
| COLLECT-LIST-001 | SharePoint List Data Collection | T1123 | N/A | M365 | [08_Collection/COLLECT-LIST-001_Lists.md](08_Collection/COLLECT-LIST-001_Lists.md) |
| COLLECT-PLAN-001 | Microsoft Planner Task Collection | T1123 | N/A | M365 | [08_Collection/COLLECT-PLAN-001_Planner.md](08_Collection/COLLECT-PLAN-001_Planner.md) |
| COLLECT-PROJECT-001 | Project Data Collection | T1123 | N/A | M365 | [08_Collection/COLLECT-PROJECT-001_Project.md](08_Collection/COLLECT-PROJECT-001_Project.md) |
| COLLECT-GRAPH-001 | Microsoft Graph API Data Extraction | T1087.004 | N/A | M365/Entra ID | [08_Collection/COLLECT-GRAPH-001_Graph_API.md](08_Collection/COLLECT-GRAPH-001_Graph_API.md) |
| COLLECT-POLICY-001 | Device Compliance Policy Collection | T1123 | N/A | Entra ID | [08_Collection/COLLECT-POLICY-001_Compliance_Policy.md](08_Collection/COLLECT-POLICY-001_Compliance_Policy.md) |
| COLLECT-INTUNE-001 | Intune Configuration Export | T1123 | N/A | Entra ID | [08_Collection/COLLECT-INTUNE-001_Intune_Config.md](08_Collection/COLLECT-INTUNE-001_Intune_Config.md) |
| COLLECT-DEFENDER-001 | Defender for Endpoint Data Collection | T1123 | N/A | M365 | [08_Collection/COLLECT-DEFENDER-001_MDE_Data.md](08_Collection/COLLECT-DEFENDER-001_MDE_Data.md) |
| COLLECT-SENTINEL-001 | Sentinel Alert Data Collection | T1123 | N/A | Entra ID | [08_Collection/COLLECT-SENTINEL-001_Sentinel_Data.md](08_Collection/COLLECT-SENTINEL-001_Sentinel_Data.md) |
| COLLECT-AUDIT-001 | Audit Log Comprehensive Collection | T1552.001 | N/A | Multi-Env | [08_Collection/COLLECT-AUDIT-001_Audit.md](08_Collection/COLLECT-AUDIT-001_Audit.md) |

---

# CATEGORY 9: IMPACT (6 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| IMPACT-RANSOM-001 | Ransomware Deployment Azure VMs | T1486 | N/A | Entra ID | [09_Impact/IMPACT-RANSOM-001_Ransomware_VM.md](09_Impact/IMPACT-RANSOM-001_Ransomware_VM.md) |
| IMPACT-DATA-DESTROY-001 | Data Destruction via Blob Storage | T1485 | N/A | Entra ID | [09_Impact/IMPACT-DATA-DESTROY-001_Blob_Destroy.md](09_Impact/IMPACT-DATA-DESTROY-001_Blob_Destroy.md) |
| IMPACT-SERVICE-STOP-001 | Service Shutdown/Deletion | T1531 | N/A | Multi-Env | [09_Impact/IMPACT-SERVICE-STOP-001_Service_Stop.md](09_Impact/IMPACT-SERVICE-STOP-001_Service_Stop.md) |
| IMPACT-DENIAL-001 | Denial of Service via Azure DDoS | T1498 | N/A | Entra ID | [09_Impact/IMPACT-DENIAL-001_DDoS.md](09_Impact/IMPACT-DENIAL-001_DDoS.md) |
| IMPACT-INTEGRITY-001 | Data Integrity Compromise | T1491 | N/A | Multi-Env | [09_Impact/IMPACT-INTEGRITY-001_Integrity.md](09_Impact/IMPACT-INTEGRITY-001_Integrity.md) |
| IMPACT-RESOURCE-EXHAUST-001 | Resource Exhaustion Attack | T1499 | N/A | Entra ID | [09_Impact/IMPACT-RESOURCE-EXHAUST-001_Resource_Exhaust.md](09_Impact/IMPACT-RESOURCE-EXHAUST-001_Resource_Exhaust.md) |

---

# CATEGORY 10: CERTIFICATE SERVICES ATTACKS (7 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| CERT-ADCS-001 | ADCS Misconfiguration Abuse | T1649 | CVE-2021-27239 | Windows AD | [10_Cert/CERT-ADCS-001_ADCS_Misconfig.md](10_Cert/CERT-ADCS-001_ADCS_Misconfig.md) |
| CERT-TEMPLATE-001 | Certificate Template Abuse | T1649 | CVE-2021-27239 | Windows AD | [10_Cert/CERT-TEMPLATE-001_Template_Abuse.md](10_Cert/CERT-TEMPLATE-001_Template_Abuse.md) |
| CERT-ENROLLMENT-001 | Unauthorized Certificate Enrollment | T1649 | N/A | Windows AD | [10_Cert/CERT-ENROLLMENT-001_Enrollment.md](10_Cert/CERT-ENROLLMENT-001_Enrollment.md) |
| CERT-REVOCATION-001 | Certificate Revocation Bypass | T1649 | N/A | Windows AD | [10_Cert/CERT-REVOCATION-001_Revocation_Bypass.md](10_Cert/CERT-REVOCATION-001_Revocation_Bypass.md) |
| CERT-AZURE-001 | Azure Key Vault Certificate Theft | T1649 | CVE-2023-28432 | Entra ID | [10_Cert/CERT-AZURE-001_KeyVault_Cert.md](10_Cert/CERT-AZURE-001_KeyVault_Cert.md) |
| CERT-M365-001 | M365 Certificate Management Abuse | T1649 | N/A | M365 | [10_Cert/CERT-M365-001_M365_Cert.md](10_Cert/CERT-M365-001_M365_Cert.md) |
| CERT-FEDERATION-001 | Federation Certificate Manipulation | T1649 | N/A | Hybrid AD | [10_Cert/CERT-FEDERATION-001_Fed_Cert.md](10_Cert/CERT-FEDERATION-001_Fed_Cert.md) |

---

# CATEGORY 11: SUPPLY CHAIN & DEVOPS (10 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| SUPPLY-CHAIN-001 | Pipeline Repository Compromise | T1195.001 | N/A | Entra ID/DevOps | [11_Supply/SUPPLY-001_Repo_Compromise.md](11_Supply/SUPPLY-001_Repo_Compromise.md) |
| SUPPLY-CHAIN-002 | Build System Access Abuse | T1195.001 | N/A | Entra ID/DevOps | [11_Supply/SUPPLY-002_Build_Abuse.md](11_Supply/SUPPLY-002_Build_Abuse.md) |
| SUPPLY-CHAIN-003 | Artifact Repository Poisoning | T1195.001 | N/A | Entra ID/DevOps | [11_Supply/SUPPLY-003_Artifact_Poison.md](11_Supply/SUPPLY-003_Artifact_Poison.md) |
| SUPPLY-CHAIN-004 | Package Manager Credential Theft | T1195.001 | N/A | Entra ID/DevOps | [11_Supply/SUPPLY-004_Package_Creds.md](11_Supply/SUPPLY-004_Package_Creds.md) |
| SUPPLY-CHAIN-005 | Release Pipeline Variable Injection | T1195.001 | N/A | Entra ID/DevOps | [11_Supply/SUPPLY-005_Pipeline_Inject.md](11_Supply/SUPPLY-005_Pipeline_Inject.md) |
| SUPPLY-CHAIN-006 | Deployment Agent Compromise | T1195.001 | N/A | Entra ID/DevOps | [11_Supply/SUPPLY-006_Deployment_Agent.md](11_Supply/SUPPLY-006_Deployment_Agent.md) |
| SUPPLY-CHAIN-007 | Container Image Registry Abuse | T1195.001 | N/A | Entra ID/DevOps | [11_Supply/SUPPLY-007_Container_Registry.md](11_Supply/SUPPLY-007_Container_Registry.md) |
| SUPPLY-CHAIN-008 | Helm Chart Poisoning | T1195.001 | N/A | Entra ID/DevOps | [11_Supply/SUPPLY-008_Helm_Chart.md](11_Supply/SUPPLY-008_Helm_Chart.md) |
| SUPPLY-CHAIN-009 | Terraform State File Theft | T1195.001 | N/A | Entra ID/DevOps | [11_Supply/SUPPLY-009_Terraform_State.md](11_Supply/SUPPLY-009_Terraform_State.md) |
| SUPPLY-CHAIN-010 | Infrastructure-as-Code Tampering | T1195.001 | N/A | Entra ID/DevOps | [11_Supply/SUPPLY-010_IaC_Tamper.md](11_Supply/SUPPLY-010_IaC_Tamper.md) |

---

# CATEGORY 12: CONTAINER & CLOUD-NATIVE (2 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| CONTAINER-001 | Kubernetes API Server Compromise | T1021.006 | CVE-2025-21196 | Entra ID | [12_Container/CONTAINER-001_K8s_API.md](12_Container/CONTAINER-001_K8s_API.md) |
| CONTAINER-002 | Container Orchestration Secret Theft | T1555.002 | N/A | Entra ID | [12_Container/CONTAINER-002_Orch_Secret.md](12_Container/CONTAINER-002_Orch_Secret.md) |

---

# CATEGORY 13: SAAS & API ATTACKS (9 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| SAAS-API-001 | GraphQL API Enumeration | T1590 | N/A | M365/Entra ID | [13_SaaS/SAAS-API-001_GraphQL_Enum.md](13_SaaS/SAAS-API-001_GraphQL_Enum.md) |
| SAAS-API-002 | REST API Rate Limit Bypass | T1110.001 | N/A | M365/Entra ID | [13_SaaS/SAAS-API-002_RateLimit_Bypass.md](13_SaaS/SAAS-API-002_RateLimit_Bypass.md) |
| SAAS-API-003 | API Key Hardcoding Exploitation | T1552.001 | N/A | M365/Entra ID | [13_SaaS/SAAS-API-003_API_Key.md](13_SaaS/SAAS-API-003_API_Key.md) |
| SAAS-API-004 | OAuth 2.0 Authorization Code Interception | T1528 | N/A | M365/Entra ID | [13_SaaS/SAAS-API-004_OAuth_Intercept.md](13_SaaS/SAAS-API-004_OAuth_Intercept.md) |
| SAAS-API-005 | JSON Web Token (JWT) Manipulation | T1550 | N/A | M365/Entra ID | [13_SaaS/SAAS-API-005_JWT_Manip.md](13_SaaS/SAAS-API-005_JWT_Manip.md) |
| SAAS-API-006 | CORS Misconfiguration Abuse | T1057 | N/A | M365/Entra ID | [13_SaaS/SAAS-API-006_CORS.md](13_SaaS/SAAS-API-006_CORS.md) |
| SAAS-API-007 | API Endpoint Parameter Pollution | T1110.002 | N/A | M365/Entra ID | [13_SaaS/SAAS-API-007_Param_Pollution.md](13_SaaS/SAAS-API-007_Param_Pollution.md) |
| SAAS-API-008 | Webhook Hijacking | T1583.006 | N/A | M365/Entra ID | [13_SaaS/SAAS-API-008_Webhook.md](13_SaaS/SAAS-API-008_Webhook.md) |
| SAAS-API-009 | Third-Party App Permission Abuse | T1537 | N/A | M365/Entra ID | [13_SaaS/SAAS-API-009_3rdParty_App.md](13_SaaS/SAAS-API-009_3rdParty_App.md) |

---

# CATEGORY 14: IOT & EDGE COMPUTING (5 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| IOT-EDGE-001 | IoT Device Credential Extraction | T1552.001 | N/A | Entra ID | [14_IoT/IOT-EDGE-001_IoT_Creds.md](14_IoT/IOT-EDGE-001_IoT_Creds.md) |
| IOT-EDGE-002 | Azure IoT Hub Connection String Theft | T1552.001 | N/A | Entra ID | [14_IoT/IOT-EDGE-002_IoT_Hub.md](14_IoT/IOT-EDGE-002_IoT_Hub.md) |
| IOT-EDGE-003 | Edge Module Compromise | T1543 | N/A | Entra ID | [14_IoT/IOT-EDGE-003_Edge_Module.md](14_IoT/IOT-EDGE-003_Edge_Module.md) |
| IOT-EDGE-004 | Device Provisioning Service Abuse | T1098 | N/A | Entra ID | [14_IoT/IOT-EDGE-004_DPS_Abuse.md](14_IoT/IOT-EDGE-004_DPS_Abuse.md) |
| IOT-EDGE-005 | Firmware Update Interception | T1601 | N/A | Entra ID | [14_IoT/IOT-EDGE-005_Firmware.md](14_IoT/IOT-EDGE-005_Firmware.md) |

---

# CATEGORY 15: CROSS-CLOUD FEDERATION (4 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| CROSS-CLOUD-001 | AWS Identity Federation Abuse | T1484.002 | N/A | Cross-Cloud | [15_CrossCloud/CROSS-CLOUD-001_AWS_Fed.md](15_CrossCloud/CROSS-CLOUD-001_AWS_Fed.md) |
| CROSS-CLOUD-002 | Google Cloud Identity Sync Compromise | T1484.002 | N/A | Cross-Cloud | [15_CrossCloud/CROSS-CLOUD-002_GCP_Sync.md](15_CrossCloud/CROSS-CLOUD-002_GCP_Sync.md) |
| CROSS-CLOUD-003 | Multi-Cloud Service Account Abuse | T1078.004 | N/A | Cross-Cloud | [15_CrossCloud/CROSS-CLOUD-003_MultiCloud_Acct.md](15_CrossCloud/CROSS-CLOUD-003_MultiCloud_Acct.md) |
| CROSS-CLOUD-004 | Cross-Cloud Trust Relationship Exploitation | T1484.002 | N/A | Cross-Cloud | [15_CrossCloud/CROSS-CLOUD-004_Trust_Exploit.md](15_CrossCloud/CROSS-CLOUD-004_Trust_Exploit.md) |

---

# CATEGORY 16: EMERGING IDENTITY PROTOCOLS (6 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| EMERGING-IDENTITY-001 | SMART Identity Abuse | T1556 | N/A | Entra ID | [16_Emerging/EMERGING-IDENTITY-001_SMART.md](16_Emerging/EMERGING-IDENTITY-001_SMART.md) |
| EMERGING-IDENTITY-002 | Decentralized Identity (DID) Exploitation | T1556 | N/A | Entra ID | [16_Emerging/EMERGING-IDENTITY-002_DID.md](16_Emerging/EMERGING-IDENTITY-002_DID.md) |
| EMERGING-IDENTITY-003 | WebAuthn Downgrade Attacks | T1556.006 | N/A | Entra ID | [16_Emerging/EMERGING-IDENTITY-003_WebAuthn.md](16_Emerging/EMERGING-IDENTITY-003_WebAuthn.md) |
| EMERGING-IDENTITY-004 | Passwordless Sign-in Bypass | T1556 | N/A | Entra ID | [16_Emerging/EMERGING-IDENTITY-004_Passwordless.md](16_Emerging/EMERGING-IDENTITY-004_Passwordless.md) |
| EMERGING-IDENTITY-005 | Just-In-Time Admin Abuse | T1548 | N/A | Entra ID | [16_Emerging/EMERGING-IDENTITY-005_JIT_Admin.md](16_Emerging/EMERGING-IDENTITY-005_JIT_Admin.md) |
| EMERGING-IDENTITY-006 | Zero-Knowledge Proof Forging | T1556 | N/A | Entra ID | [16_Emerging/EMERGING-IDENTITY-006_ZKP.md](16_Emerging/EMERGING-IDENTITY-006_ZKP.md) |

---

# CATEGORY 17: 2025 CVE-SPECIFIC ATTACKS (14 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| CVE2025-001 | CLFS Driver Privilege Escalation | T1068 | CVE-2025-29824 | Windows Endpoint | [17_CVE2025/CVE2025-001_CLFS_PE.md](17_CVE2025/CVE2025-001_CLFS_PE.md) |
| CVE2025-002 | AKS Container Escape RCE | T1611 | CVE-2025-21196 | Entra ID | [17_CVE2025/CVE2025-002_AKS_Escape.md](17_CVE2025/CVE2025-002_AKS_Escape.md) |
| CVE2025-003 | AD DS Registry Key Elevation | T1068 | CVE-2025-21293 | Windows AD | [17_CVE2025/CVE2025-003_ADDS_Registry.md](17_CVE2025/CVE2025-003_ADDS_Registry.md) |
| CVE2025-004 | .library-ms NTLM Relay Attack | T1187 | CVE-2025-24054 | Windows AD | [17_CVE2025/CVE2025-004_Library_ms_NTLM.md](17_CVE2025/CVE2025-004_Library_ms_NTLM.md) |
| CVE2025-005 | Print Spooler Remote Code Execution | T1210 | CVE-2025-24050 | Windows Endpoint | [17_CVE2025/CVE2025-005_Print_RCE.md](17_CVE2025/CVE2025-005_Print_RCE.md) |
| CVE2025-006 | Kerberos Delegation Bypass | T1558 | CVE-2025-21299 | Windows AD | [17_CVE2025/CVE2025-006_Kerb_Delegation.md](17_CVE2025/CVE2025-006_Kerb_Delegation.md) |
| CVE2025-007 | Entra ID Token Validation Bypass | T1556.006 | CVE-2025-55241 | Entra ID | [17_CVE2025/CVE2025-007_Token_Validation.md](17_CVE2025/CVE2025-007_Token_Validation.md) |
| CVE2025-008 | Exchange Server RCE Vulnerability | T1210 | CVE-2025-21064 | Windows AD | [17_CVE2025/CVE2025-008_Exchange_RCE.md](17_CVE2025/CVE2025-008_Exchange_RCE.md) |
| CVE2025-009 | SharePoint Authenticated RCE | T1210 | CVE-2025-21075 | M365 | [17_CVE2025/CVE2025-009_SharePoint_RCE.md](17_CVE2025/CVE2025-009_SharePoint_RCE.md) |
| CVE2025-010 | Teams Deserialization Vulnerability | T1190 | CVE-2025-21089 | M365 | [17_CVE2025/CVE2025-010_Teams_Deser.md](17_CVE2025/CVE2025-010_Teams_Deser.md) |
| CVE2025-011 | Azure App Service Authentication Bypass | T1556 | CVE-2025-24091 | Entra ID | [17_CVE2025/CVE2025-011_AppService_Auth.md](17_CVE2025/CVE2025-011_AppService_Auth.md) |
| CVE2025-012 | SharePoint WebPart Deserialization RCE | T1210 | CVE-2025-49704 | M365 | [17_CVE2025/CVE2025-012_SharePoint_Deser.md](17_CVE2025/CVE2025-012_SharePoint_Deser.md) |
| CVE2025-013 | M365 Copilot Zero-Click Prompt Injection | T1190 | CVE-2025-32711 | M365 | [17_CVE2025/CVE2025-013_Copilot_EchoLeak.md](17_CVE2025/CVE2025-013_Copilot_EchoLeak.md) |
| CVE2025-014 | WSUS RCE & Lateral Movement | T1210 | CVE-2025-59287 | Windows | [17_CVE2025/CVE2025-014_WSUS_RCE.md](17_CVE2025/CVE2025-014_WSUS_RCE.md) |

---

# CATEGORY 18: AI/LLM SECURITY ATTACKS (3 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| AI-PROMPT-001 | M365 Copilot Prompt Injection & Jailbreak | T1190 | CVE-2025-32711 | M365 | [18_AI_LLM/AI-PROMPT-001_Copilot_Injection.md](18_AI_LLM/AI-PROMPT-001_Copilot_Injection.md) |
| AI-PROMPT-002 | LLM Model Poisoning via Training Data | T1556 | N/A | Cloud | [18_AI_LLM/AI-PROMPT-002_LLM_Poisoning.md](18_AI_LLM/AI-PROMPT-002_LLM_Poisoning.md) |
| AI-PROMPT-003 | Sensitive Data Leakage via LLM Queries | T1537 | N/A | Cloud | [18_AI_LLM/AI-PROMPT-003_Data_Leakage.md](18_AI_LLM/AI-PROMPT-003_Data_Leakage.md) |

---

# CATEGORY 19: KUBERNETES SUPPLY CHAIN ATTACKS (3 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| K8S-SUPPLY-001 | Helm Chart Repository Poisoning | T1195.001 | N/A | Kubernetes | [19_K8S_Supply/K8S-SUPPLY-001_Helm_Poison.md](19_K8S_Supply/K8S-SUPPLY-001_Helm_Poison.md) |
| K8S-SUPPLY-002 | Container Image Registry Tampering | T1195.001 | N/A | Kubernetes | [19_K8S_Supply/K8S-SUPPLY-002_Image_Tamper.md](19_K8S_Supply/K8S-SUPPLY-002_Image_Tamper.md) |
| K8S-SUPPLY-003 | Kubernetes Package Manager (KAPP) Abuse | T1195.001 | N/A | Kubernetes | [19_K8S_Supply/K8S-SUPPLY-003_KAPP_Abuse.md](19_K8S_Supply/K8S-SUPPLY-003_KAPP_Abuse.md) |

---

# CATEGORY 20: WINDOWS HELLO FOR BUSINESS ATTACKS (4 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| WHFB-001 | Windows Hello for Business Credential Theft | T1556.006 | N/A | Hybrid AD | [20_WHFB/WHFB-001_WHfB_Theft.md](20_WHFB/WHFB-001_WHfB_Theft.md) |
| WHFB-002 | Autopilot Device Identity Spoofing | T1078.004 | N/A | Entra ID | [20_WHFB/WHFB-002_Autopilot_Spoof.md](20_WHFB/WHFB-002_Autopilot_Spoof.md) |
| WHFB-003 | PIN Recovery Exploitation | T1556.006 | N/A | Hybrid AD | [20_WHFB/WHFB-003_PIN_Recovery.md](20_WHFB/WHFB-003_PIN_Recovery.md) |
| WHFB-004 | Biometric Bypass & Fallback Exploitation | T1556.006 | N/A | Hybrid AD | [20_WHFB/WHFB-004_Biometric_Bypass.md](20_WHFB/WHFB-004_Biometric_Bypass.md) |

---

# CATEGORY 21: MISCONFIGURATIONS & WEAK DEFAULTS (20 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| MISCONFIG-001 | Overly Permissive RBAC | T1548 | N/A | Entra ID | [21_Misconfig/MISCONFIG-001_RBAC.md](21_Misconfig/MISCONFIG-001_RBAC.md) |
| MISCONFIG-002 | Disabled MFA Requirements | T1556.006 | N/A | Entra ID/M365 | [21_Misconfig/MISCONFIG-002_MFA_Disabled.md](21_Misconfig/MISCONFIG-002_MFA_Disabled.md) |
| MISCONFIG-003 | Conditional Access Gaps | T1556 | N/A | Entra ID | [21_Misconfig/MISCONFIG-003_CA_Gaps.md](21_Misconfig/MISCONFIG-003_CA_Gaps.md) |
| MISCONFIG-004 | Legacy Authentication Enabled | T1556 | N/A | Entra ID/M365 | [21_Misconfig/MISCONFIG-004_Legacy_Auth.md](21_Misconfig/MISCONFIG-004_Legacy_Auth.md) |
| MISCONFIG-005 | Insecure API Permissions | T1548 | N/A | M365/Entra ID | [21_Misconfig/MISCONFIG-005_API_Perms.md](21_Misconfig/MISCONFIG-005_API_Perms.md) |
| MISCONFIG-006 | Public Blob Storage Containers | T1526 | N/A | Entra ID | [21_Misconfig/MISCONFIG-006_Public_Blobs.md](21_Misconfig/MISCONFIG-006_Public_Blobs.md) |
| MISCONFIG-007 | Open Network Security Groups | T1526 | N/A | Entra ID | [21_Misconfig/MISCONFIG-007_NSG_Open.md](21_Misconfig/MISCONFIG-007_NSG_Open.md) |
| MISCONFIG-008 | Key Vault Access Policy Overpermission | T1526 | N/A | Entra ID | [21_Misconfig/MISCONFIG-008_KV_Perms.md](21_Misconfig/MISCONFIG-008_KV_Perms.md) |
| MISCONFIG-009 | Disabled Audit Logging | T1562.002 | N/A | Multi-Env | [21_Misconfig/MISCONFIG-009_Audit_Off.md](21_Misconfig/MISCONFIG-009_Audit_Off.md) |
| MISCONFIG-010 | Unencrypted Data Storage | T1526 | N/A | Multi-Env | [21_Misconfig/MISCONFIG-010_Unencrypted.md](21_Misconfig/MISCONFIG-010_Unencrypted.md) |
| MISCONFIG-011 | Default SSH Keys in Use | T1526 | N/A | Entra ID | [21_Misconfig/MISCONFIG-011_Default_SSH.md](21_Misconfig/MISCONFIG-011_Default_SSH.md) |
| MISCONFIG-012 | SQL Database Firewall Disabled | T1526 | N/A | Entra ID | [21_Misconfig/MISCONFIG-012_SQL_Firewall.md](21_Misconfig/MISCONFIG-012_SQL_Firewall.md) |
| MISCONFIG-013 | Storage Account Public Endpoints | T1526 | N/A | Entra ID | [21_Misconfig/MISCONFIG-013_Storage_Public.md](21_Misconfig/MISCONFIG-013_Storage_Public.md) |
| MISCONFIG-014 | Unmanaged External Apps | T1537 | N/A | M365 | [21_Misconfig/MISCONFIG-014_Unmanaged_Apps.md](21_Misconfig/MISCONFIG-014_Unmanaged_Apps.md) |
| MISCONFIG-015 | Guest User Access Over-Permissioned | T1548 | N/A | Entra ID | [21_Misconfig/MISCONFIG-015_Guest_Perms.md](21_Misconfig/MISCONFIG-015_Guest_Perms.md) |
| MISCONFIG-016 | Privileged Account Not Monitored | T1556 | N/A | Multi-Env | [21_Misconfig/MISCONFIG-016_No_Monitor.md](21_Misconfig/MISCONFIG-016_No_Monitor.md) |
| MISCONFIG-017 | Default Connector Passwords | T1526 | N/A | Entra ID | [21_Misconfig/MISCONFIG-017_Connector_Pwd.md](21_Misconfig/MISCONFIG-017_Connector_Pwd.md) |
| MISCONFIG-018 | Unprotected Function App Secrets | T1552.001 | N/A | Entra ID | [21_Misconfig/MISCONFIG-018_Function_Secrets.md](21_Misconfig/MISCONFIG-018_Function_Secrets.md) |
| MISCONFIG-019 | Weak Container Image Registry ACL | T1526 | N/A | Entra ID | [21_Misconfig/MISCONFIG-019_Registry_ACL.md](21_Misconfig/MISCONFIG-019_Registry_ACL.md) |
| MISCONFIG-020 | Lack of Resource Locks | T1531 | N/A | Entra ID | [21_Misconfig/MISCONFIG-020_No_Locks.md](21_Misconfig/MISCONFIG-020_No_Locks.md) |

---

# CATEGORY 22: ATTACK CHAIN COMBINATIONS (4 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| CHAIN-001 | Phishing to DA via Certificate Services | T1590+T1649 | CVE-2021-27239 | Windows AD | [22_Chains/CHAIN-001_Phish_Cert_DA.md](22_Chains/CHAIN-001_Phish_Cert_DA.md) |
| CHAIN-002 | Guest to GA via Conditional Access Gaps | T1078+T1548 | N/A | Entra ID | [22_Chains/CHAIN-002_Guest_CA_Gap.md](22_Chains/CHAIN-002_Guest_CA_Gap.md) |
| CHAIN-003 | Token Theft to Data Exfiltration | T1528+T1537 | N/A | M365 | [22_Chains/CHAIN-003_Token_Exfil.md](22_Chains/CHAIN-003_Token_Exfil.md) |
| CHAIN-004 | Hybrid AD to Global Admin | T1550+T1098 | CVE-2023-32315 | Hybrid AD | [22_Chains/CHAIN-004_Hybrid_GA.md](22_Chains/CHAIN-004_Hybrid_GA.md) |

---

# CATEGORY 23: EMERGING PRIVILEGE ESCALATION (2 Techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| EMERGING-PE-001 | BadSuccessor dMSA Abuse | T1548 | N/A | Windows AD | [23_Emerging_PE/EMERGING-PE-001_BadSuccessor.md](23_Emerging_PE/EMERGING-PE-001_BadSuccessor.md) |
| EMERGING-PE-002 | AD DS Registry Key Elevation | T1068 | CVE-2025-21293 | Windows AD | [23_Emerging_PE/EMERGING-PE-002_ADDS_Registry.md](23_Emerging_PE/EMERGING-PE-002_ADDS_Registry.md) |

---

# CATEGORY 24: CRITICAL REAL-WORLD ATTACK GAPS (47 Techniques)

## Subcategory 24.1: Legacy Auth Protocol Abuse (4 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| REALWORLD-001 | BAV2ROPC Attack Chain | T1110.003 | N/A | Entra ID/M365 | [24_RealWorld/REALWORLD-001_BAV2ROPC.md](24_RealWorld/REALWORLD-001_BAV2ROPC.md) |
| REALWORLD-002 | SMTP AUTH Legacy Protocol Abuse | T1550 | N/A | M365 | [24_RealWorld/REALWORLD-002_SMTP.md](24_RealWorld/REALWORLD-002_SMTP.md) |
| REALWORLD-003 | POP/IMAP Basic Auth Abuse | T1550 | N/A | M365 | [24_RealWorld/REALWORLD-003_POP_IMAP.md](24_RealWorld/REALWORLD-003_POP_IMAP.md) |
| REALWORLD-004 | Legacy API Brute Force | T1110.003 | N/A | Entra ID/M365 | [24_RealWorld/REALWORLD-004_Legacy_BF.md](24_RealWorld/REALWORLD-004_Legacy_BF.md) |

## Subcategory 24.2: Actor Token Impersonation - CVE-2025-55241 (4 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| REALWORLD-005 | Actor Token Impersonation | T1550 | CVE-2025-55241 | Entra ID | [24_RealWorld/REALWORLD-005_Actor_Token.md](24_RealWorld/REALWORLD-005_Actor_Token.md) |
| REALWORLD-006 | Actor Token Extraction | T1528 | CVE-2025-55241 | Entra ID | [24_RealWorld/REALWORLD-006_Token_Extract.md](24_RealWorld/REALWORLD-006_Token_Extract.md) |
| REALWORLD-007 | Actor Token Replay Cross-Tenant | T1550 | CVE-2025-55241 | Cross-Cloud | [24_RealWorld/REALWORLD-007_Token_Replay.md](24_RealWorld/REALWORLD-007_Token_Replay.md) |
| REALWORLD-008 | Actor Token Global Admin | T1098 | CVE-2025-55241 | Entra ID | [24_RealWorld/REALWORLD-008_Token_GA.md](24_RealWorld/REALWORLD-008_Token_GA.md) |

## Subcategory 24.3: FIDO Downgrade & AiTM Phishing (4 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| REALWORLD-009 | FIDO2 Downgrade Evilginx2 | T1556.006 | N/A | Entra ID | [24_RealWorld/REALWORLD-009_FIDO_Down.md](24_RealWorld/REALWORLD-009_FIDO_Down.md) |
| REALWORLD-010 | Safari-on-Windows Device Spoof | T1556.006 | N/A | Entra ID | [24_RealWorld/REALWORLD-010_Safari_Spoof.md](24_RealWorld/REALWORLD-010_Safari_Spoof.md) |
| REALWORLD-011 | AiTM FIDO Unsupported Error | T1557 | N/A | Entra ID | [24_RealWorld/REALWORLD-011_FIDO_AiTM.md](24_RealWorld/REALWORLD-011_FIDO_AiTM.md) |
| REALWORLD-012 | MFA Downgrade via AiTM | T1556.006 | N/A | Entra ID | [24_RealWorld/REALWORLD-012_MFA_Down.md](24_RealWorld/REALWORLD-012_MFA_Down.md) |

## Subcategory 24.4: Evil VM Device Identity (3 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| REALWORLD-013 | Evil VM Device Identity | T1078.004 | N/A | Hybrid/Entra | [24_RealWorld/REALWORLD-013_Evil_VM.md](24_RealWorld/REALWORLD-013_Evil_VM.md) |
| REALWORLD-014 | PRT Device Identity Manipulation | T1528 | N/A | Hybrid/Entra | [24_RealWorld/REALWORLD-014_PRT_Device.md](24_RealWorld/REALWORLD-014_PRT_Device.md) |
| REALWORLD-015 | Guest to Admin Azure VM | T1550 | N/A | Entra ID | [24_RealWorld/REALWORLD-015_Guest_Admin.md](24_RealWorld/REALWORLD-015_Guest_Admin.md) |

## Subcategory 24.5: OAuth IdP Admin Compromise (4 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| REALWORLD-016 | IdP Admin Account Compromise | T1098 | N/A | Cross-Cloud | [24_RealWorld/REALWORLD-016_IdP_Admin.md](24_RealWorld/REALWORLD-016_IdP_Admin.md) |
| REALWORLD-017 | Inbound Federation Rule Creation | T1556 | N/A | Cross-Cloud | [24_RealWorld/REALWORLD-017_Fed_Rules.md](24_RealWorld/REALWORLD-017_Fed_Rules.md) |
| REALWORLD-018 | OAuth Provider Impersonation | T1484.002 | N/A | Cross-Cloud | [24_RealWorld/REALWORLD-018_OAuth_Imperson.md](24_RealWorld/REALWORLD-018_OAuth_Imperson.md) |
| REALWORLD-019 | Scattered Spider IdP TTP | T1098.003 | N/A | Cross-Cloud | [24_RealWorld/REALWORLD-019_Scattered_IdP.md](24_RealWorld/REALWORLD-019_Scattered_IdP.md) |

## Subcategory 24.6: Token Replay with CAE Evasion (5 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| REALWORLD-020 | Token Replay CAE Evasion | T1550 | N/A | Entra ID | [24_RealWorld/REALWORLD-020_Token_Replay.md](24_RealWorld/REALWORLD-020_Token_Replay.md) |
| REALWORLD-021 | Linkable Token ID Bypass | T1550.001 | N/A | Entra ID | [24_RealWorld/REALWORLD-021_Token_ID.md](24_RealWorld/REALWORLD-021_Token_ID.md) |
| REALWORLD-022 | Impossible Travel Evasion | T1550 | N/A | Entra ID | [24_RealWorld/REALWORLD-022_Impossible_Travel.md](24_RealWorld/REALWORLD-022_Impossible_Travel.md) |
| REALWORLD-023 | Refresh Token Rotation Evasion | T1550 | N/A | Entra ID | [24_RealWorld/REALWORLD-023_Refresh_Evasion.md](24_RealWorld/REALWORLD-023_Refresh_Evasion.md) |
| REALWORLD-024 | Behavioral Profiling Attacks | T1589 | N/A | Multi-Env | [24_RealWorld/REALWORLD-024_Behavioral.md](24_RealWorld/REALWORLD-024_Behavioral.md) |

## Subcategory 24.7: Advanced Persistence Techniques (6 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| REALWORLD-025 | Hidden File Share Creation | T1548 | N/A | Windows AD | [24_RealWorld/REALWORLD-025_Hidden_Share.md](24_RealWorld/REALWORLD-025_Hidden_Share.md) |
| REALWORLD-026 | Service Account Token Harvesting | T1528 | N/A | Windows AD | [24_RealWorld/REALWORLD-026_Service_Token.md](24_RealWorld/REALWORLD-026_Service_Token.md) |
| REALWORLD-027 | Scheduled Task Obfuscation | T1053 | N/A | Windows AD | [24_RealWorld/REALWORLD-027_Task_Obfus.md](24_RealWorld/REALWORLD-027_Task_Obfus.md) |
| REALWORLD-028 | WMI Event Subscriber Persistence | T1546.003 | N/A | Windows Endpoint | [24_RealWorld/REALWORLD-028_WMI_Event.md](24_RealWorld/REALWORLD-028_WMI_Event.md) |
| REALWORLD-029 | Registry Run Key Polymorphism | T1112 | N/A | Windows Endpoint | [24_RealWorld/REALWORLD-029_Registry_Poly.md](24_RealWorld/REALWORLD-029_Registry_Poly.md) |
| REALWORLD-030 | DLL Search Order Hijacking | T1574.001 | N/A | Windows Endpoint | [24_RealWorld/REALWORLD-030_DLL_Hijack.md](24_RealWorld/REALWORLD-030_DLL_Hijack.md) |

## Subcategory 24.8: Advanced Lateral Movement (6 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| REALWORLD-031 | Token Binding Extraction | T1528 | N/A | M365 | [24_RealWorld/REALWORLD-031_Token_Binding.md](24_RealWorld/REALWORLD-031_Token_Binding.md) |
| REALWORLD-032 | Graph API Backdoor Creation | T1098 | N/A | Entra ID | [24_RealWorld/REALWORLD-032_Graph_Backdoor.md](24_RealWorld/REALWORLD-032_Graph_Backdoor.md) |
| REALWORLD-033 | Service Principal Certificate Persistence | T1098 | N/A | Entra ID | [24_RealWorld/REALWORLD-033_SP_Cert_Persist.md](24_RealWorld/REALWORLD-033_SP_Cert_Persist.md) |
| REALWORLD-034 | Azure Resource Manager API Abuse | T1550 | N/A | Entra ID | [24_RealWorld/REALWORLD-034_ARM_API.md](24_RealWorld/REALWORLD-034_ARM_API.md) |
| REALWORLD-035 | Container Registry Credential Reuse | T1528 | N/A | Entra ID | [24_RealWorld/REALWORLD-035_Container_Creds.md](24_RealWorld/REALWORLD-035_Container_Creds.md) |
| REALWORLD-036 | Managed Identity Chaining | T1550 | N/A | Entra ID | [24_RealWorld/REALWORLD-036_MID_Chain.md](24_RealWorld/REALWORLD-036_MID_Chain.md) |

## Subcategory 24.9: Detection Evasion Tactics (6 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| REALWORLD-037 | Sentinel Rule Modification | T1562.001 | N/A | Entra ID | [24_RealWorld/REALWORLD-037_Sentinel_Mod.md](24_RealWorld/REALWORLD-037_Sentinel_Mod.md) |
| REALWORLD-038 | Audit Log Selective Deletion | T1070.001 | N/A | M365/Entra ID | [24_RealWorld/REALWORLD-038_Audit_Delete.md](24_RealWorld/REALWORLD-038_Audit_Delete.md) |
| REALWORLD-039 | Sign-in Log Poisoning | T1562.002 | N/A | Entra ID | [24_RealWorld/REALWORLD-039_SignIn_Poison.md](24_RealWorld/REALWORLD-039_SignIn_Poison.md) |
| REALWORLD-040 | Conditional Access Policy Cloning | T1556 | N/A | Entra ID | [24_RealWorld/REALWORLD-040_CA_Clone.md](24_RealWorld/REALWORLD-040_CA_Clone.md) |
| REALWORLD-041 | Device Compliance Policy Bypass | T1548 | N/A | Entra ID | [24_RealWorld/REALWORLD-041_Compliance_Bypass.md](24_RealWorld/REALWORLD-041_Compliance_Bypass.md) |
| REALWORLD-042 | Intune Configuration Drift | T1562 | N/A | M365 | [24_RealWorld/REALWORLD-042_Intune_Drift.md](24_RealWorld/REALWORLD-042_Intune_Drift.md) |

## Subcategory 24.10: Advanced Data Exfiltration (5 techniques)

| ID | Technique Name | MITRE | CVE | Environment | File Path |
|---|---|---|---|---|---|
| REALWORLD-043 | SharePoint Metadata Exfiltration | T1537 | N/A | M365 | [24_RealWorld/REALWORLD-043_SP_Metadata.md](24_RealWorld/REALWORLD-043_SP_Metadata.md) |
| REALWORLD-044 | Teams Compliance Copy Exploitation | T1537 | N/A | M365 | [24_RealWorld/REALWORLD-044_Teams_Compliance.md](24_RealWorld/REALWORLD-044_Teams_Compliance.md) |
| REALWORLD-045 | Azure Storage Analytics Abuse | T1537 | N/A | Entra ID | [24_RealWorld/REALWORLD-045_Storage_Analytics.md](24_RealWorld/REALWORLD-045_Storage_Analytics.md) |
| REALWORLD-046 | Multi-Cloud Data Bridge Attack | T1537 | N/A | Cross-Cloud | [24_RealWorld/REALWORLD-046_Cloud_Bridge.md](24_RealWorld/REALWORLD-046_Cloud_Bridge.md) |
| REALWORLD-047 | Azure Entra ID Sign-in Log Tampering | T1562.002 | N/A | Entra ID | [24_RealWorld/REALWORLD-047_SignIn_Tamper.md](24_RealWorld/REALWORLD-047_SignIn_Tamper.md) |

---

# Framework Conclusion \& Strategic Application

The **MCADDF - Microsoft Cybersecurity Attack, Detection \& Defense Framework** represents a standardization of the current threat landscape facing hybrid organizations. By documenting **501 distinct vectors**, **SERVTEP** and **Pchelnikau Artur** have provided the community with a unified language to describe how attacks occur across the Microsoft ecosystem—and, crucially, how to detect them.

## Operational Value

For security professionals, this framework supports three primary pillars:

1. **Offensive Operations (Red Teaming):**
    * Serves as a "cheat sheet" for campaign planning, utilizing the **SERVTEP ID** system to quickly reference and chain techniques (e.g., `REC-AD-001` → `CA-DUMP-002`) during complex engagements.
    * Simulates realistic APT behaviors by covering the full spectrum of the kill chain.
2. **Detection \& Defense (Blue Teaming):**
    * **Detection Engineering:** Every technique listed here serves as a test case for validating SIEM alerts (Sigma/YARA), fully aligned with **MITRE ATT\&CK v18.1** logic.
    * **Gap Analysis:** Allows defenders to systematically validate controls against specific T-codes, ensuring no coverage gaps exist between on-prem and cloud scopes.
3. **Risk Assessment:**
    * Enables auditors and architects to prioritize remediation efforts based on the prevalence and severity of techniques validated by SERVTEP's research.

## The Path Forward

The cybersecurity landscape is volatile by design. While these 501 techniques represent the state of the art in hybrid exploitation today, the methodologies will evolve. This framework is maintained as a living project by **SERVTEP**—continuously updated as vendors patch vulnerabilities, new attack surfaces emerge, and the MITRE ATT\&CK standard progresses beyond v18.1.

*Final Verification Completed: December 2025*
*Lead Architect: Pchelnikau Artur*
*Organization: SERVTEP*

<div align="center">⁂</div>
