# [MISCONFIG-010]: Unencrypted Data Storage

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-010 |
| **MITRE ATT&CK v18.1** | [T1530 – Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/) |
| **Tactic** | Collection / Impact |
| **Platforms** | Multi-Env (Azure Storage, Azure Files, Azure Disks, Azure SQL, Windows Servers, SaaS) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure regions and SKUs; Windows Server 2016–2025; Azure SQL Database/Managed Instance; Azure Storage accounts |
| **Patched In** | N/A (mitigated via encryption-at-rest features and policy) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** Unencrypted data at rest exposes sensitive information to offline compromise through stolen disks, snapshots, unmanaged backups, misconfigured cloud storage, or privileged infrastructure access. In Azure and hybrid environments this includes storage accounts with encryption disabled, SQL databases with Transparent Data Encryption (TDE) off, file shares and on-prem volumes without BitLocker, and cloud snapshots or exports stored in plaintext. An attacker who gains hypervisor, storage, or backup access can harvest entire datasets without touching the live workload.
- **Attack Surface:** Azure Storage (Blob, File, Queue, Table), Azure Disks and snapshots, Azure SQL (IaaS and PaaS), on-prem Windows volumes, backup repositories, exports to non-encrypted locations, and test/dev copies of production data.
- **Business Impact:** **High likelihood of large-scale data breach and regulatory sanction.** Offline theft of unencrypted data can include credentials, PII, PHI, financial records, and intellectual property. Because attacks may occur at the storage or backup layer, they can bypass many application-layer controls, dramatically increasing breach scope and notification costs.
- **Technical Context:** Modern Azure services encrypt new data at rest by default, but legacy resources and specific features (older storage accounts, SQL instances with TDE toggled off, unattached or legacy managed disks, third-party backups) still present risk. Misconfigurations often persist for years. Adversaries exploit this by stealing snapshots, copying unmanaged VHDs, or exfiltrating unencrypted database files.

### Operational Risk
- **Execution Risk:** Medium/High – enabling encryption after the fact can incur downtime or performance impact if not planned, but leaving data unencrypted leaves catastrophic exposure.
- **Stealth:** High – attackers accessing snapshots, backup files, or exported VHDs may not touch production workloads, leaving minimal live telemetry.
- **Reversibility:** Low – once unencrypted data is exfiltrated there is no technical rollback.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | Azure Foundations DP-4 / related storage & SQL controls | Require encryption at rest for storage accounts, disks, and SQL data. |
| **DISA STIG** | SRG-APP-000429-DB / OS disk encryption families | Enforce database and host disk encryption for sensitive data. |
| **CISA SCuBA** | Data Protection DP controls | Encryption of cloud data at rest and in backup repositories. |
| **NIST 800-53** | SC-12, SC-28 | Cryptographic protection and protection of information at rest. |
| **GDPR** | Art. 32 | Encryption of personal data as an appropriate technical control. |
| **DORA** | Art. 9 | Protection and prevention measures for critical financial data, including encryption. |
| **NIS2** | Art. 21 | Measures for data security and access control in essential/important entities. |
| **ISO 27001** | A.8.24, A.8.25 | Use of cryptography and protection of data at rest in storage and backups. |
| **ISO 27005** | Risk Scenario | Compromise of unencrypted production, backup, or snapshot data.

## 3. TECHNICAL PREREQUISITES
- **Required Privileges:**
  - Subscription Owner / Contributor or Storage/SQL specific roles to change encryption settings.
  - Local or domain administrative rights to enable BitLocker or volume encryption on-prem.
- **Required Access:**
  - Azure Portal / PowerShell / CLI access.
  - Access to virtualization or backup platforms for on-prem workloads.

**Supported Versions:**
- Azure Storage: all GA regions and account types, with some legacy accounts allowing encryption to be toggled.
- Azure SQL Database / Managed Instance: all supported versions.
- Windows Server: 2016, 2019, 2022, 2025 with BitLocker.

## 4. ENVIRONMENTAL RECONNAISSANCE

### Azure Storage & SQL Recon (PowerShell)

```powershell
# List storage accounts without infrastructure encryption
Get-AzStorageAccount | Select-Object ResourceGroupName,StorageAccountName,
  EnableHttpsTrafficOnly,SupportsHttpsTrafficOnly,EnableHierarchicalNamespace, 
  Encryption

# Azure SQL TDE status
Get-AzSqlDatabase | Select-Object ServerName,DatabaseName,TransparentDataEncryptionState
```

**What to Look For:**
- Storage accounts where encryption is disabled or limited to subset of services.
- SQL databases where `TransparentDataEncryptionState` is `Disabled`.

### Disk & Snapshot Recon

```powershell
Get-AzDisk | Select-Object Name,Encryption,DiskState
Get-AzSnapshot | Select-Object Name,Encryption
```

**What to Look For:**
- Disks and snapshots without encryption or using weaker legacy options.

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Exploit Unencrypted Azure Storage and Disks

**Supported Versions:** All Azure subscriptions.

#### Step 1: Copy Unencrypted Blob or File Content
**Objective:** Demonstrate how an attacker with storage key or SAS token can bulk exfiltrate unencrypted data.

**Command (Azure CLI):**
```bash
# List blobs in a container
az storage blob list \
  --account-name <storageAccount> \
  --container-name <container> \
  --auth-mode key -o table

# Download an entire container
az storage blob download-batch \
  --account-name <storageAccount> \
  --source <container> \
  --destination ./loot \
  --auth-mode key
```

**Expected Output:**
- Local copy of all objects; contents readable in plaintext.

**OpSec & Evasion:**
- If logging is weak, only storage access logs and some network traces exist. Attackers may target storage accounts without diagnostic logging or Defender for Storage enabled.

#### Step 2: Export or Mount Unencrypted VHDs
**Objective:** Mount or copy managed disks or snapshots that are not encrypted.

**Command (PowerShell):**
```powershell
# Export URI of a snapshot (if allowed)
Grant-AzSnapshotAccess -ResourceGroupName <rg> -SnapshotName <snap> -DurationInSecond 3600 -Access Read
```

**Expected Output:**
- Time-limited SAS URL that can be downloaded and mounted offline.

### METHOD 2 – Exploit Unencrypted Azure SQL

**Supported Versions:** Azure SQL Database / Managed Instance.

#### Step 1: Identify Databases with TDE Disabled

```powershell
Get-AzSqlDatabase | Where-Object { $_.TransparentDataEncryptionState -eq "Disabled" } |
  Select-Object ServerName,DatabaseName
```

#### Step 2: Export Plaintext Bacpac or Backup
**Objective:** Export entire unencrypted database for offline analysis.

**Outline:**
- Use `SqlPackage` or Azure Portal export to BACPAC.
- Store export in a storage account (which itself may be unencrypted) and download.

**OpSec & Evasion:**
- If exports and storage are unencrypted, contents are fully exposed to any attacker who gains access to the export location.

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

There is no specific Atomic Red Team test dedicated solely to unencrypted-at-rest misconfiguration. Use storage exfiltration tests for T1530 (Data from Cloud Storage Object) to simulate data theft once misconfiguration is present.

## 7. TOOLS & COMMANDS REFERENCE

### Azure CLI

```bash
# Check encryption config for a storage account
az storage account show -n <account> -g <rg> --query "encryption"

# Check SQL TDE
az sql db tde show -g <rg> -s <server> -n <db>
```

### PowerShell Modules
- Az.Storage
- Az.Sql
- Az.Compute

## 8. SPLUNK DETECTION RULES

### Rule 1: Access to Storage Accounts with Encryption Disabled

**SPL Idea:**
- Correlate cloud configuration inventory (e.g. from CSPM or Azure Inventory index) listing unencrypted storage or SQL with high-volume data access events from those resources.

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: SQL Databases with TDE Disabled
```kusto
AzureDiagnostics
| where ResourceType == "DATABASES"
| where Category == "SQLSecurityAuditEvents" or Category == "SQLInsights"
| summarize any_prop = any(Properties_s) by Resource
```

Supplement with Azure Resource Graph queries:
```kusto
resources
| where type == "microsoft.sql/servers/databases"
| extend tde = properties.encryption
| where tde != "Enabled" and tde != "True"
```

## 10. WINDOWS EVENT LOG MONITORING

For on-prem volumes, ensure BitLocker and file server auditing events are collected:
- BitLocker status (event IDs under `Microsoft-Windows-BitLocker/BitLocker Management`).
- File access events on sensitive shares.

## 11. SYSMON DETECTION PATTERNS

Use Sysmon to track:
- Large file copy operations from sensitive volumes.
- Mounting of VHD/VHDX images exported from servers.

## 12. MICROSOFT DEFENDER FOR CLOUD

Key recommendations:
- Storage accounts should have infrastructure encryption enabled.
- SQL databases should have Transparent Data Encryption enabled.
- Disks and snapshots should be encrypted with platform or customer-managed keys.

Review and remediate all High/Medium recommendations under Data Protection.

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

For M365 workloads, ensure:
- Unified Audit Log is enabled.
- Data exports (for example, SharePoint exports, eDiscovery exports) are stored in encrypted locations.

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL
- Enforce encryption at rest for all new resources via Azure Policy (DP-4):
  - Storage accounts must have encryption enabled.
  - SQL databases must have TDE enabled.
  - Disks and snapshots must be encrypted.

- Migrate legacy resources:
  - Enable TDE on legacy SQL databases.
  - Enable encryption on older storage accounts and file services.
  - Convert unmanaged disks to managed, then enable encryption.

### Priority 2: HIGH
- Use customer-managed keys (CMK) and Key Vault for highly sensitive workloads.
- Enforce HTTPS-only access to storage and SQL endpoints.

### Validation Command (Verify Fix)
```powershell
Get-AzStorageAccount | Select-Object StorageAccountName,Encryption
Get-AzSqlDatabase | Select-Object ServerName,DatabaseName,TransparentDataEncryptionState
Get-AzDisk | Select-Object Name,Encryption
```

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)
- Unusual export or download of large storage containers from accounts identified as unencrypted.
- Export of SQL databases without TDE to external storage.

### Forensic Artifacts
- Storage access logs and diagnostics.
- SQL audit logs.
- Backup system logs showing export or restore of unencrypted images.

### Response Procedures
1. Identify unencrypted data sources and classify sensitivity.
2. Contain by restricting access keys, SAS tokens, and IP ranges.
3. Enable encryption at rest and rotate keys.
4. Conduct breach assessment if exfiltration is suspected; notify per GDPR/NIS2 as necessary.

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | Compromise of subscription or storage keys | Attacker gains keys or privileged role. |
| 2 | Discovery | Cloud Storage Discovery (T1530, T1526) | Attacker enumerates storage and databases. |
| 3 | Current Step | **MISCONFIG-010 – Unencrypted Data Storage** | Attacker targets unencrypted assets, snapshots, or exports. |
| 4 | Collection | Bulk export of data | Offline harvesting, decryption not required. |
| 5 | Exfiltration & Impact | Data breach, extortion | Regulatory reporting and brand damage. |

## 17. REAL-WORLD EXAMPLES

### Example 1: Public Cloud Storage Breaches
- Numerous incidents where misconfigured cloud storage (S3, Azure Blob) was left public and unencrypted, exposing millions of records (credit cards, PII, medical data).

### Example 2: Unencrypted SQL Backups
- Organizations have suffered breaches when attackers gained access to backup shares or exported BACPAC files that were stored unencrypted, allowing offline credential and data extraction.

---