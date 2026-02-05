<meta name="google-site-verification" content="XIFMHaVyGqaNw9xaHfnGFqV9HR1o5U9bFhOIp9aEWxA" />


# MCADDF - Microsoft Cybersecurity Attack, Detection & Defense Framework

[![Maintenance](https://img.shields.io/badge/Maintained%20by-SERVTEP-blue)](https://servtep.com)
[![License](https://img.shields.io/badge/License-MIT%20%2F%20Apache-green)](./LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v18.1-red)](https://attack.mitre.org/)
[![Status](https://img.shields.io/badge/Status-Active-success)]()

**The definitive operational blueprint for Hybrid Identity and Cloud Security.**

Built and Maintained with ❤️ in France by **[SERVTEP](https://servtep.com)** | Lead Architect: **[Pchelnikau Artur](https://www.linkedin.com/in/artur-pchelnikau/)**

---

## 📖 Overview

The **Microsoft Cybersecurity Attack, Detection & Defense Framework** is a holistic repository designed to bridge the critical gap between traditional on-premises security and modern cloud-native defense.

Unlike standard checklists, this framework maps the entire adversarial lifecycle across the **Hybrid Microsoft Ecosystem**—from **Active Directory** to **Entra ID (Azure AD)**, **Azure Resources**, and **Microsoft 365**. It provides a unified language for Red and Blue Teams to simulate, detect, and mitigate advanced threats.

### 🚀 [ACCESS THE MASTER INDEX](./MASTER_INDEX_UNIFIED.md)
> Click above to browse the complete catalog of 501+ verified techniques.

---

## 🤝 Expert Consulting Services

**Transform your Microsoft security across on-premises, cloud, and hybrid environments**

### Who I Am
**Artur Pchelnikau** — CISO | IT Project Manager | Microsoft Security Architect | Penetration Tester | OSINT Expert  
**18+ years** architecting & implementing secure Microsoft infrastructure at enterprise scale

### What I Do
Comprehensive cybersecurity consulting & program management for **Active Directory | Azure | Entra ID | M365 | Hybrid Security**

| Environment | Services |
|---|---|
| **On-Premises** | AD hardening, tiering, FSMO, forest security, Windows Server hardening |
| **Cloud (Azure)** | Entra ID, Zero Trust, Conditional Access (RBAC/ABAC/PBAC/ReBAC), governance |
| **Hybrid** | Identity sync, cross-tenant, on-prem to cloud migration, seamless security |
| **Microsoft 365** | Exchange, Teams, SharePoint, OneDrive, DLP, compliance policies |
| **Threat Defense** | SIEM (Sentinel), EDR/NDR, SOC optimization, incident response, threat hunting |
| **Advanced** | AI automation, security orchestration, attack simulation, compliance frameworks |

### Delivery & Project Management
📊 **Program Leadership:** Large-scale infrastructure transformation, compliance initiatives, strategic roadmaps  
📋 **Project Execution:** Security implementation, migration planning, risk management, resource coordination  
⏱️ **Methodology:** Agile & waterfall delivery, stakeholder alignment, phased rollout, continuous improvement  
✅ **Success Metrics:** Timeline adherence, budget optimization, quality assurance, business alignment  

### Red Team Capabilities
🔴 **Penetration Testing:** Infrastructure assessment, vulnerability discovery, exploitation chains  
🔴 **OSINT & Reconnaissance:** Deep reconnaissance, attack surface mapping, threat intelligence  
🔴 **Security Testing:** Microsoft environment red teaming, attack simulation using MCADDF scenarios  
🔴 **Purple Team Exercises:** Bridge offensive & defensive operations, validate detection capabilities  

### Core Competencies
🔐 **Identity & Access:** IAM, RBAC, ABAC, PBAC, ReBAC, Conditional Access  
🛡️ **Security Architecture:** Zero Trust, defense-in-depth, risk-based design  
📊 **Compliance & Hardening:** NIST 800-53, CIS Benchmarks, ISO 27001, STIG  
🚨 **Threat Intelligence:** 500+ attack scenarios (MCADDF creator), detection engineering  
⚙️ **Automation & AI:** Intelligent threat response, security workflows, SOAR integration  
🎯 **Red Team Expertise:** Penetration testing, OSINT, attack simulation, vulnerability assessment  
📈 **Project Leadership:** Enterprise transformation, program delivery, strategic execution  

### Ready to Strengthen Your Microsoft Security?
**[Schedule a consultation →](https://www.linkedin.com/in/artur-pchelnikau/)**

---

## 🛡️ Core Philosophy

Modern enterprises do not operate in silos; they operate in hybrid states. Attackers pivot seamlessly between on-prem domain controllers and cloud tenants. This framework is built to reflect that reality.

### Key Features
*   **Hybrid-Native Focus:** Deeply analyzes the synchronization points (e.g., Azure AD Connect or Microsoft Entra Connect) where most modern breaches occur.
*   **The SERVTEP ID System:** Utilizes a proprietary navigation system for precise referencing and tracking.
*   **MITRE ATT&CK® v18.1 Aligned:** Every technique is mapped to the latest T-codes, ensuring compatibility with standard threat intelligence feeds.
*   **Purple Team Ready:** Each entry is designed to support both **Offensive Execution** (Red) and **Defensive Detection** (Blue).

---

## 🏗️ Defense Scope

This framework goes beyond simple remediation. Every technique analyzes defense across four critical architectural layers:

| Layer | Scope of Analysis |
| :--- | :--- |
| **Identity & Access** | **RBAC/ABAC** models, **Conditional Access** policies, **PIM** (Privileged Identity Management), and **Tiered Admin** models. |
| **Network Security** | **NSG** (Network Security Groups), **Azure Firewall**, **Private Links**, and **Segmentation** strategies. |
| **Data Governance** | **Azure Purview** labeling, **DLP** (Data Loss Prevention) policies, and **Information Protection** controls. |
| **Monitoring** | **Microsoft Sentinel** (KQL), **Splunk** (SPL), **Sysmon** (XML), and **Unified Audit Logs**. |

---

## 🧩 The SERVTEP ID System

To simplify navigation across 500+ techniques, we have developed a proprietary logical identifier system. This allows practitioners to instantly recognize the **Tactic**, **Target Technology**, and **Specific Vector** just by reading the ID.

### ID Format Structure
The ID follows the syntax: `[TACTIC]-[TECHNOLOGY]-[INDEX]`

> **Example:** `REC-AD-001`
> *   **REC**: Tactic Category (**Reconnaissance**)
> *   **AD**: Target Technology (**Active Directory**)
> *   **001**: Unique Identifier

### Technology Identifiers (Middle Code)
These codes define the specific environment or technology stack targeted by the technique.

| Code | Target Environment | Scope & Examples |
| :--- | :--- | :--- |
| **AD** | Active Directory (On-Prem) | Domain Controllers, LDAP, Kerberos, DNS, GPO, LAPS |
| **CLOUD** | Azure & Entra ID | App Registrations, Service Principals, Key Vaults, Azure Resources |
| **M365** | Microsoft 365 SaaS | Exchange Online, SharePoint, Teams, Graph API, OneDrive |
| **HYBRID** | Sync Architecture | Azure AD Connect, Microsoft Entra Connect, PHS, PTA, Federation (ADFS), Seamless SSO |
| **PHISH** | Social Engineering | OAuth Consent Grants, Device Code Phishing, Branding Spoofing |
| **EXPLOIT**| Vulnerability Exploitation | CVEs, Deserialization, Logic Apps, Unpatched Services |
| **CERT** | Certificate Services | ADCS (Active Directory Certificate Services), ESC1-ESC16, CA Misconfigs |
| **CONTAINER**| Cloud Native | Azure Kubernetes Service (AKS), Kubelet API, Docker, Pod Escape |
| **SQL** | Database Services | Azure SQL, MSSQL, Data Exfiltration, SQL Injection |
| **ENDO** | Endpoint / OS | Windows 10/11, Server OS, Local Security Authority (LSA) |

---

## 📂 Framework Taxonomy

The repository is organized into 9 primary tactical categories, fully aligned with the Cyber Kill Chain and MITRE ATT&CK.

| Category Code | Name | Description & Sub-Categories |
| :--- | :--- | :--- |
| **REC** | **Reconnaissance** | **Discovery of tenants, domains, and privileges.**<br>• `REC-AD` (LDAP Analysis, BloodHound)<br>• `REC-CLOUD` (Tenant Enum, ROADtools)<br>• `REC-CERT` (ADCS Enum) |
| **IA** | **Initial Access** | **Gaining the first foothold.**<br>• `IA-PHISH` (Device Code, Consent Grant)<br>• `IA-EXPLOIT` (Public Facing Exploits)<br>• `IA-VALID` (Password Spraying) |
| **CA** | **Credential Access** | **Stealing keys to the kingdom.**<br>• `CA-DUMP` (LSASS, DCSync)<br>• `CA-KERB` (Kerberoasting, AS-REP Roasting)<br>• `CA-TOKEN` (PRT Theft, Primary Refresh Token) |
| **PE** | **Privilege Escalation** | **Elevating rights from User to Admin.**<br>• `PE-AD` (ACL Abuse, AdminSDHolder)<br>• `PE-CLOUD` (Role Escalation, PIM Abuse)<br>• `PE-CERT` (ADCS ESC Techniques) |
| **DE** | **Defense Evasion** | **Hiding from SIEM and EDR.**<br>• `DE-LOG` (Event Log Clearing)<br>• `DE-TOKEN` (Impersonation, Token Manipulation)<br>• `DE-AMSI` (AMSI/ETW Bypassing) |
| **LM** | **Lateral Movement** | **Pivoting across the hybrid boundary.**<br>• `LM-AD` (Pass-the-Hash/Ticket)<br>• `LM-HYBRID` (Cloud Pivoting, Hybrid Join)<br>• `LM-CLOUD` (Admin Tier Hopping) |
| **PERS** | **Persistence** | **Maintaining long-term access.**<br>• `PERS-AD` (Golden Ticket, Skeleton Key)<br>• `PERS-CLOUD` (Service Principals, Automation Accounts)<br>• `PERS-HYBRID` (Golden SAML) |
| **EX** | **Exfiltration** | **Stealing the data.**<br>• `EX-M365` (SharePoint/OneDrive Collection)<br>• `EX-SQL` (Database Dump)<br>• `EX-AUTO` (Power Automate Exfiltration) |
| **IMP** | **Impact** | **Destruction and disruption.**<br>• `IMP-RANSOM` (Encryption)<br>• `IMP-DOS` (Denial of Service)<br>• `IMP-DESTROY` (Resource Deletion) |

---

## 💡 How to Use This Framework

### For Red Teams
Use this repository as a comprehensive "cheat sheet" for campaign planning. The **SERVTEP IDs** allow you to chain techniques logically (e.g., `REC-AD-001` → `CA-DUMP-002` → `LM-HYBRID-003`) to simulate realistic APT behaviors.

### For Blue Teams & Detection Engineers
Use the framework for **Gap Analysis**. Select a technique ID (e.g., `IA-PHISH-002`), simulate it, and verify if your SIEM/EDR triggers the expected alert.

### For Architects & CISOs
Utilize the index to audit your environment's exposure. Prioritize remediation based on the "Technique Severity" and prevalence noted in the documentation.

---

## 🤝 Contributing

This is a living framework. As the Microsoft ecosystem evolves, so do the threats. We welcome contributions from the community to keep this repository at the cutting edge.

1.  Fork the repository.
2.  Create a branch for your technique or update.
3.  Submit a Pull Request with a detailed description.

---

## ⚠️ Disclaimer

> **EDUCATIONAL AND DEFENSIVE USE ONLY**
>
> The contents of this repository are for **authorized security testing, educational purposes, and defensive research**. The techniques listed involve mechanisms that can disrupt critical business operations or bypass security controls.
>
> **[SERVTEP](https://servtep.com)** and **[Pchelnikau Artur](https://www.linkedin.com/in/artur-pchelnikau/)** accept no liability for any damage caused by the misuse of this information. Users are responsible for ensuring all activities are conducted within the scope of a signed Rule of Engagement (RoE) and in compliance with all applicable local, federal, and international laws.

---

## 📜 License

This project is licensed under the terms of the [LICENSE](./LICENSE) file.

---

<p align="center">
  Built with ❤️ in France by <strong>SERVTEP</strong>
</p>
