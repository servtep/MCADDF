# [MISCONFIG-006]: Public Blob Storage Containers

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-006 |
| **MITRE ATT&CK v18.1** | [Cloud Service Discovery (T1526)](https://attack.mitre.org/techniques/T1526/) |
| **Tactic** | Discovery / Initial Access / Collection |
| **Platforms** | Azure Storage (Blob), Entra ID, Azure Resource Manager |
| **Severity** | High (Critical if sensitive data is stored) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure Storage accounts created via Azure Resource Manager with Blob service (all regions) |
| **Patched In** | N/A – design allows public access; mitigated via configuration (`AllowBlobPublicAccess`, container ACLs, private endpoints, and policy). |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure Blob containers can be configured for anonymous read access at the storage‑account level (`AllowBlobPublicAccess`) and at the container level (`Public access level`: `Blob` or `Container`). When these settings are misconfigured, containers that hold internal or sensitive data become readable by anyone on the internet without authentication. Attackers routinely scan for publicly accessible containers in Azure (similar to S3 bucket hunting) and perform automated data harvesting.
- **Attack Surface:** Azure Storage accounts with Blob service where:
  - Storage account **allows** blob public access.
  - One or more containers have public access level set to **Blob** or **Container** instead of `Private`.
- **Business Impact:** **Silent data leakage at scale.** Public containers may expose source code, configuration files, datasets, PII, secrets (config files with connection strings), and backups. This can lead to regulatory non‑compliance, IP loss, and enable follow‑on attacks (credential stuffing, lateral movement).
- **Technical Context:** For Resource Manager‑based storage accounts, anonymous access is disabled by default, but admins can still enable `AllowBlobPublicAccess` or create older accounts where it is implicitly enabled. At the container level, setting `Public access level` to `Blob` or `Container` allows unauthenticated reads; the account‑level setting acts as a master switch that can override container settings. Microsoft strongly recommends disabling public access unless absolutely necessary and using SAS, CDN, or other controlled distribution methods instead.

### Operational Risk
- **Execution Risk:** Medium – Toggling public access is low‑risk operationally but can break legacy applications that rely on anonymous reads.
- **Stealth:** Very High – Anonymous access leaves minimal authentication traces; only Storage analytics/Diagnostics and Defender for Storage telemetry indicate activity.
- **Reversibility:** High for configuration (can disable public access), **Low for data** already exfiltrated; once public, data may be scraped and mirrored.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Azure Foundations** | AZURE 3.x – Storage Encryption & Access | Requires restricting anonymous/public access to storage accounts and containers. |
| **DISA STIG** | APP3550 / SRG-APP-000231 | Protects data at rest from unauthorized access; prohibits unauthenticated access to sensitive data stores. |
| **CISA SCuBA** | Storage Hardening | Guidance to prevent anonymous/public data exposure in cloud object stores. |
| **NIST 800‑53 Rev5** | AC‑3, SC‑7, SC‑28 | Access enforcement, boundary protection, and protection of information at rest – public blobs violate least privilege and boundary controls. |
| **GDPR** | Art. 25, Art. 32 | Data protection by design/default; public exposure of PII via blobs is a clear violation of appropriate technical measures. |
| **DORA** | Art. 9 | ICT risk management – cloud data stores must be appropriately segmented and access‑controlled. |
| **NIS2** | Art. 21 | Requires robust technical and organizational measures to manage cyber risk, including secure configuration of storage. |
| **ISO 27001:2022** | A.8.12, A.8.24 | Data leakage prevention and protection of information stored in cloud services. |
| **ISO 27005** | "Public Cloud Data Bucket Exposure" | Classic risk scenario: misconfigured public storage exposing regulated or sensitive data. |

---

## 3. TECHNICAL PREREQUISITES
- **Required Privileges (Misconfig Creation):**
  - Azure RBAC roles with write access to storage accounts and blob containers, e.g. **Storage Account Contributor**, **Owner**, or custom roles with `Microsoft.Storage/storageAccounts/write` and `Microsoft.Storage/storageAccounts/blobServices/containers/write`.
- **Required Access (Attacker):**
  - Any internet access to the blob endpoint `https://<account>.blob.core.windows.net`.
  - Knowledge or enumeration of account and container names.

**Supported Versions:**
- **Azure Storage Accounts:** Resource Manager‑based general‑purpose v2 (GPv2) and BlobStorage accounts with Blob service.
- **Clients:** Any HTTP(S) client (browser, `curl`, SDKs). No authentication required if container is public.

- **Tools:**
  - Azure Portal and Storage Explorer.
  - `az` CLI (`az storage account`, `az storage container`).
  - 3rd‑party scanners (Orca, custom scripts) for public blob enumeration.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

#### Management Station / PowerShell Reconnaissance

```powershell
# List storage accounts and the AllowBlobPublicAccess flag
Connect-AzAccount
$subs = Get-AzSubscription

foreach ($sub in $subs) {
  Set-AzContext -SubscriptionId $sub.Id | Out-Null
  Get-AzStorageAccount | Select-Object @{n='Subscription';e={$sub.Name}},
                                 ResourceGroupName, StorageAccountName, AllowBlobPublicAccess
}
```

**What to Look For:**
- Storage accounts where `AllowBlobPublicAccess` is `$true` or `$null` (older accounts where public access is permitted by default).

**Enumerate Container Public Access Levels:**
```powershell
$rg = "<ResourceGroup>"
$sa = "<StorageAccountName>"

$ctx = (Get-AzStorageAccount -ResourceGroupName $rg -Name $sa).Context
Get-AzStorageContainer -Context $ctx | Select-Object Name, PublicAccess
```

**What to Look For:**
- Containers with `PublicAccess` set to `Blob` or `Container` instead of `Off`/`Private`. These are anonymously readable if account‑level setting allows it.

#### Azure CLI / Bash Reconnaissance

```bash
# List storage accounts with AllowBlobPublicAccess
az storage account list --query "[].{name:name, resourceGroup:resourceGroup, allowBlobPublicAccess:allowBlobPublicAccess}" -o table

# For a given account, list containers and access levels
ACCOUNT="<storage-account>"
RG="<resource-group>"

az storage container list \
  --account-name $ACCOUNT \
  --auth-mode login \
  --query "[].{name:name, publicAccess:properties.publicAccess}" -o table
```

**What to Look For:**
- Any container with `publicAccess` != `None` in a storage account that is not intentionally internet‑facing.

#### External Reconnaissance (Attacker View)

```bash
# Anonymous listing attempt (only works if container public access = Container)
ACCOUNT="victimstorage"
CONTAINER="backups"

curl -s "https://${ACCOUNT}.blob.core.windows.net/${CONTAINER}?restype=container&comp=list"

# Anonymous blob download (works if Blob or Container level access)
BLOB="sensitive-config.json"
curl -O "https://${ACCOUNT}.blob.core.windows.net/${CONTAINER}/${BLOB}"
```

**What to Look For:**
- HTTP 200 responses listing blobs or returning blob content without authentication.

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Exploiting a Public Blob Container for Data Exfiltration

**Supported Versions:** All Azure storage accounts that allow public access and have containers configured with `Blob` or `Container` access level.

#### Step 1: Discover Public Containers
**Objective:** Enumerate containers and identify those with public access.

**Command (External, Unauthenticated):**
```bash
# Assume attacker has guessed or discovered account and container names
curl -s "https://victimstorage.blob.core.windows.net/public?restype=container&comp=list" | xmllint --format -
```

**Expected Output:** XML document listing blobs within the `public` container if `PublicAccess` is `Container`. For `Blob` level, listing may fail but direct blob URLs still work.

**What This Means:**
- Any listed blob is readable anonymously; attackers can iterate through names and download files.

**OpSec & Evasion:**
- Requests come from arbitrary IPs; unless Defender for Storage and diagnostics are enabled, detection is difficult.

#### Step 2: Mass Download Blobs
**Objective:** Exfiltrate all accessible content.

```bash
ACCOUNT="victimstorage"
CONTAINER="public"

# Simple enumeration using a wordlist
for name in $(cat wordlist.txt); do
  url="https://${ACCOUNT}.blob.core.windows.net/${CONTAINER}/${name}"
  if curl -s --head "$url" | grep -q "200"; then
    echo "[+] Found: $url" | tee -a found_blobs.txt
    curl -s "$url" -o "downloaded_${name}"
  fi
done
```

**Expected Output:** Files written locally; HTTP 200 responses from blob service.

**What This Means:**
- Attacker now has offline copies of all discovered blobs; further analysis can reveal secrets, PII, or internal IP addressing.

**Troubleshooting:**
- **Error:** `404 The specified container does not exist` – container name incorrect or access disabled.
- **Error:** `PublicAccess is disabled` – account owner has disabled anonymous access at account level despite container setting.

**References & Proofs:**
- Microsoft – *Remediate anonymous read access to blob data*.
- Orca – risk description for Azure public blob containers.

### METHOD 2 – Creating a Public Container via Misconfiguration

**Supported Versions:** Resource Manager‑based storage accounts with `AllowBlobPublicAccess` permitted.

#### Step 1: Enable Blob Public Access at the Account Level
**Objective:** Accidentally or intentionally configure storage account to allow container‑level public access.

**Command (Azure CLI):**
```bash
ACCOUNT="corpdata"
RG="rg-storage"

az storage account update \
  --name $ACCOUNT \
  --resource-group $RG \
  --allow-blob-public-access true
```

#### Step 2: Create a Public Container
```bash
az storage container create \
  --name public \
  --account-name $ACCOUNT \
  --auth-mode login \
  --public-access blob
```

**Expected Output:** Container `public` created; blobs uploaded into this container are now anonymously readable.

**OpSec & Evasion:**
- Activity appears in Azure Activity Logs as configuration changes to the storage account and container properties.

**Troubleshooting:**
- If a built‑in policy `Storage account public access should be disallowed` is enforced, creation/update may fail with policy violation.

**References:**
- Microsoft – configuration guidance and `AllowBlobPublicAccess` property.
- Defender for Cloud recommendations – “Storage account public access should be disallowed”.

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

There is no storage‑specific Atomic Red Team test for Azure public blob misconfiguration, but T1530 (*Data from Cloud Storage Object*) and T1526 (*Cloud Service Discovery*) tests cover similar patterns in S3.

#### Atomic Pattern (Conceptual)
- **Atomic Test ID:** T1530 – Data from Cloud Storage Object.
- **Test Name:** Enumerate and download objects from a public cloud bucket.
- **Description:** Demonstrates the risk of misconfigured public object stores by creating a bucket, setting public ACLs, and downloading data anonymously.

**Adaptation to Azure:**
- Use the method 2 commands above to create a public container.
- Use `curl` or `az storage blob download` without authentication to download data.

**Cleanup Command:**
```bash
az storage container delete --name public --account-name $ACCOUNT --auth-mode login
```

**Reference:** Atomic Red Team T1530 and Microsoft documentation on anonymous blob access.

---

## 7. TOOLS & COMMANDS REFERENCE

#### Azure PowerShell (Az.Storage)

**Installation:**
```powershell
Install-Module Az.Storage -Scope CurrentUser
Import-Module Az.Storage
```

**Usage (Check AllowBlobPublicAccess):**
```powershell
Get-AzStorageAccount | Select-Object StorageAccountName, AllowBlobPublicAccess
```

#### Azure CLI

**Installation:** Cross‑platform CLI for Azure.

**Usage:**
```bash
az storage account list --query "[].{name:name, allowBlobPublicAccess:allowBlobPublicAccess}" -o table
```

#### Script (One-Liner – Find Public Containers Across Subscriptions)
```powershell
Connect-AzAccount
$subs = Get-AzSubscription

$results = foreach ($sub in $subs) {
  Set-AzContext -SubscriptionId $sub.Id | Out-Null
  Get-AzStorageAccount | ForEach-Object {
    $ctx = $_.Context
    Get-AzStorageContainer -Context $ctx | Where-Object { $_.PublicAccess -ne "Off" } |
      Select-Object @{n='Subscription';e={$sub.Name}},
                    @{n='StorageAccount';e={$_.CloudStorageAccount.StorageAccountName}},
                    Name, PublicAccess
  }
}
$results | Format-Table -AutoSize
```

---

## 8. SPLUNK DETECTION RULES

#### Rule 1: Storage Account or Container Public Access Enabled
**Rule Configuration:**
- **Required Index:** `azure:monitor:storage` or Azure Activity log index.
- **Required Sourcetype:** `azure:activity`.
- **Required Fields:** `operationName`, `properties`, `resourceId`, `resultType`.
- **Alert Threshold:** Any change that sets `allowBlobPublicAccess` to `true` or container `publicAccess` != `None`.

**SPL Query:**
```spl
index=azure_activity (operationName="Microsoft.Storage/storageAccounts/write" OR \
                      operationName="Microsoft.Storage/storageAccounts/blobServices/containers/write")
| eval props = spath(_raw, "properties")
| eval allowBlobPublicAccess = spath(props, "properties.allowBlobPublicAccess"),
       publicAccess = spath(props, "properties.publicAccess")
| search allowBlobPublicAccess="true" OR publicAccess!="None" AND publicAccess!="" 
| stats latest(_time) AS lastChange BY resourceId, allowBlobPublicAccess, publicAccess
```

**What This Detects:**
- Configuration changes enabling storage account public access or changing container ACLs to public.

**Manual Configuration Steps:**
- Save as alert `Azure Blob Public Access Enabled` with severity High and notify storage/security teams.

**Source:** Microsoft Defender for Cloud data security recommendations and community detection examples.

#### False Positive Analysis
- **Legitimate Activity:** Public static website hosting or CDN origins intentionally using public containers.
- **Tuning:** Maintain an allow‑list of storage accounts explicitly approved for public access and exclude them in SPL (`NOT resourceId IN (...)`).

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: New or Modified Public Blob Containers
**Rule Configuration:**
- **Required Table:** `AzureActivity`.
- **Required Fields:** `OperationNameValue`, `ResourceProviderValue`, `Properties`, `ResourceId`.
- **Alert Severity:** High.
- **Frequency:** Every 15 minutes.

**KQL Query:**
```kusto
AzureActivity
| where ResourceProviderValue == "MICROSOFT.STORAGE" 
| where OperationNameValue in ("MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
                               "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE")
| extend props = parse_json(Properties)
| extend allowBlobPublicAccess = tostring(props.responseBody.properties.allowBlobPublicAccess),
         publicAccess = tostring(props.responseBody.properties.publicAccess)
| where allowBlobPublicAccess =~ "true" or publicAccess !~ "None" and publicAccess != ""
| project TimeGenerated, OperationNameValue, ResourceId, allowBlobPublicAccess, publicAccess, Caller
```

**What This Detects:**
- Any write operation that enables account‑level public access or sets a container ACL to public.

**Manual Configuration Steps:**
- Create a Sentinel scheduled query rule `Public Blob Access Enabled` using this KQL and assign to cloud security team.

**Source:** Microsoft Defender for Cloud recommendation “Storage account public access should be disallowed” and its associated policy.

---

## 10. WINDOWS EVENT LOG MONITORING

Not directly applicable; this misconfiguration occurs in Azure control plane. Windows event logs are only relevant insofar as they capture admin tooling used locally.

Suggested minimal monitoring:
- Enable process creation logging (4688) and PowerShell Script Block logging on admin workstations to detect scripts that manage storage accounts in bulk.

---

## 11. SYSMON DETECTION PATTERNS

Optional; focus on detecting heavy use of storage‑management tooling from non‑admin systems.

```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="contains">az.exe</Image>
      <CommandLine condition="contains">storage account update</CommandLine>
      <CommandLine condition="contains">allow-blob-public-access</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts
**Alert Name:** Storage account allows public blob access / Anomalous access to a storage account from the internet.
- **Severity:** High.
- **Description:**
  - Configuration or activity indicative of public exposure of storage containers, or anomalous access patterns from untrusted IP addresses.
- **Applies To:** Storage accounts onboarded to Defender for Storage.

**Manual Configuration Steps (Enable Defender for Storage):**
1. Azure Portal → **Microsoft Defender for Cloud → Environment settings**.
2. Select subscription → under **Defender plans**, enable **Defender for Storage**.
3. Review recommendations such as **"Storage account public access should be disallowed"**.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

Azure Storage access isn’t logged via the M365 unified audit log, but you can use:
- **Azure Monitor / Diagnostics**: Blob read/write metrics and logs.
- **Defender for Cloud / Storage**: Security alerts and anomaly detections.

For M365 workloads that *use* Blob as a backing store (e.g., certain services), correlate:
- Application logs indicating writes to Azure Blob with downstream exposure.

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Disable Public Access at the Storage Account Level**
  - **Action:** Set `AllowBlobPublicAccess` to `false` on all storage accounts unless explicitly justified.

  **Manual Steps (Portal):**
  1. Storage account → **Configuration** → **Blob public access** → set to **Disabled**.
  2. Save the change.

  **Manual Steps (PowerShell):**
  ```powershell
  Get-AzStorageAccount | ForEach-Object {
    if ($_.AllowBlobPublicAccess -ne $false) {
      Set-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $_.StorageAccountName `
        -AllowBlobPublicAccess $false
    }
  }
  ```

* **Enforce Policy: Disallow Public Blob Access**
  - Assign the built‑in policy **"Storage account public access should be disallowed"** to all subscriptions, with exceptions only where required.

#### Priority 2: HIGH

* **Set All Containers to Private**
  - Enumerate containers and set `PublicAccess` to `Off` for any that do not need to be public.

  ```powershell
  $ctx = (Get-AzStorageAccount -ResourceGroupName $rg -Name $sa).Context
  Get-AzStorageContainer -Context $ctx | Where-Object { $_.PublicAccess -ne "Off" } |
    ForEach-Object {
      Set-AzStorageContainerAcl -Context $ctx -Name $_.Name -PublicAccess Off
    }
  ```

* **Use SAS, CDN, or Private Endpoints Instead of Public Containers**
  - For content distribution, use **time‑bound SAS tokens** and Azure CDN or Static Websites with tightly controlled origins.

#### Access Control & Policy Hardening

* **Network Controls:**
  - Restrict storage accounts to **private endpoints** and disallow public network access where feasible.

* **RBAC:**
  - Limit who can modify storage account configuration and container ACLs (e.g., dedicated storage administrators).

#### Validation Command (Verify Fix)
```powershell
Connect-AzAccount
Get-AzSubscription | ForEach-Object {
  Set-AzContext -SubscriptionId $_.Id | Out-Null
  Get-AzStorageAccount | ForEach-Object {
    $sa = $_
    if ($sa.AllowBlobPublicAccess -ne $false) {
      Write-Output "[!] Public access still allowed on $($sa.StorageAccountName)"
    }
    $ctx = $sa.Context
    Get-AzStorageContainer -Context $ctx | Where-Object { $_.PublicAccess -ne "Off" } |
      ForEach-Object {
        Write-Output "[!] Container $($_.Name) on $($sa.StorageAccountName) is $($_.PublicAccess)"
      }
  }
}
```

**Expected Output (If Secure):**
- No warnings printed; all `AllowBlobPublicAccess` are `False` and all containers show `Off`.

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)
* **Network:**
  - Sudden spike in anonymous blob reads from unusual IP ranges.
* **Data:**
  - Discovery that proprietary or PII‑containing data is available via direct HTTPS URLs with no auth.

#### Forensic Artifacts
* **Cloud:**
  - Storage analytics / diagnostic logs: `AuthenticationType = Anonymous`, `RequestStatus = Success`.
  - Defender for Storage alerts on anomalous or malicious IP access.

#### Response Procedures
1. **Isolate:**
   - Immediately set storage account `AllowBlobPublicAccess` to `false` and set affected containers to `Private`.
2. **Collect Evidence:**
   - Export access logs and Defender alerts for IR analysis.
3. **Remediate:**
   - Rotate any secrets or keys found to be exposed in blobs.
   - Notify data protection officer if regulated data was exposed (GDPR/DORA/NIS2 implications).

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Discovery** | REC-CLOUD-005 – Azure Resource Graph enumeration | Attacker discovers storage accounts and containers. |
| **2** | **Discovery** | T1526 – Cloud Service Discovery | Enumerates cloud storage services and configuration. |
| **3** | **Current Step** | **MISCONFIG-006 – Public Blob Storage Containers** | Misconfiguration exposes blob data to the internet. |
| **4** | **Collection** | T1530 – Data from Cloud Storage Object | Attacker downloads exposed blobs. |
| **5** | **Impact** | DATA-EXFIL-XXX – Data disclosure | Breach of confidentiality; regulatory reporting triggered. |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: Public Cloud Storage Bucket Exposures (Cross‑Cloud Pattern)
- **Target:** Multiple organizations across sectors.
- **Timeline:** 2019–ongoing (S3, Azure Blob, GCS).
- **Technique Status:** Numerous incidents where misconfigured public object stores leaked backups, customer data, and credentials; pattern is identical for Azure Blob when public access is enabled.
- **Impact:** Large‑scale PII exposure, regulatory fines, and reputational damage.

#### Example 2: Misconfigured Azure Blob Containers Detected by CSPM Tools
- **Target:** Azure tenants scanned by CSPM / CNAPP tools.
- **Timeline:** Continuous as part of cloud security posture assessments.
- **Technique Status:** Tools such as Orca Security and Defender for Cloud routinely flag public containers as high‑severity misconfigurations.
- **Impact:** Early detection often prevents breach; where ignored, attackers can harvest source code, logs, and secrets from public blobs.

---