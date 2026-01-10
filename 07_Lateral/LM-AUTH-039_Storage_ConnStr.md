# [LM-AUTH-039]: Storage Account Connection String

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-039 |
| **Technique Name** | Storage Account Connection String |
| **File Path** | 07_Lateral/LM-AUTH-039_Storage_ConnStr.md |
| **MITRE ATT&CK v18.1** | T1550 – Use Alternate Authentication Material |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, Azure Storage (Blob/Queue/File/Table/Data Lake), Azure workloads using Shared Key/connection strings |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure Storage accounts using Shared Key or account‑level SAS via connection strings (all current SKUs) |
| **Patched In** | N/A – design/usage risk; mitigated through Entra ID, scoped SAS, network controls, and secret hygiene |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:**
  This technique abuses **Azure Storage account connection strings** that embed the **account name and Shared Key** (or account‑level SAS) to obtain full access to storage resources and pivot laterally into other workloads that trust these accounts. A standard Shared Key connection string, such as `DefaultEndpointsProtocol=https;AccountName=storagesample;AccountKey=<account-key>`, provides the authorization information required to perform any operation permitted by the key, including enumerate containers, exfiltrate data, overwrite blobs, and generate new SAS tokens.[7][10][13][14] If an attacker discovers such a connection string in source code, configuration files, CI/CD variables, logs, or on a compromised VM/Function/App Service, they can impersonate trusted services, poison data, and trigger downstream compute resources (Functions, Logic Apps, Data Factory, Synapse) that react to storage events, achieving lateral movement across the Azure estate.[5][8][14][17]

- **Attack Surface:**
  Azure **Storage account access keys and connection strings**, any workloads using Shared Key authorization (applications, scripts, containers, Functions, Logic Apps, Data Factory, Synapse, AKS, IoT), and secondary components that process data from those storage accounts (analytics, backups, model training, etc.).[7][10][13][14]

- **Business Impact:**
  **Full compromise of one or more storage accounts**, leading to **data exfiltration, tampering, ransomware‑style destruction, and downstream service compromise**. Attackers can overwrite Function code, inject malicious content, or alter configuration files stored in blob/file shares, leading to privilege escalation and lateral movement into higher‑privileged identities or critical workloads.[5][8][14][17]

- **Technical Context:**
  Exploitation is low‑effort once a connection string is obtained. Tools and SDKs natively support Shared Key authentication. Activity appears as **legitimate Azure Storage operations** over HTTPS unless carefully correlated with unusual clients, IPs, or operation patterns. Risks are amplified when **long‑lived account SAS tokens** or broad account keys are used instead of scoped, short‑lived SAS or Entra ID‑based auth.[7][10][11][14]

### Operational Risk

- **Execution Risk:** Critical – account keys essentially act as **master keys**; compromise equates to complete control over the storage account and any dependent workflows.
- **Stealth:** High – operations are indistinguishable from normal client actions if performed via SDKs over HTTPS and from typical IP ranges, unless advanced analytics or baselining is in place.[8][14]
- **Reversibility:** Low/Partial – keys and SAS tokens can be rotated or revoked, but data copied or processed by downstream services and any triggered workflows cannot be fully undone.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 1.4 – 3.x, 4.x | Secure management of access keys, encryption at rest, network restrictions, and use of managed identities. |
| **DISA STIG** | SRG‑APP‑000148 / APP3510 (conceptual) | Application authentication and key management requirements for external services. |
| **CISA SCuBA** | SCB‑AZ‑STOR‑1, SCB‑AZ‑IA‑1 | Secure storage configuration and identity‑based access instead of Shared Keys where possible. |
| **NIST 800‑53** | AC‑3, AC‑6, IA‑5, SC‑12, SC‑28 | Access enforcement, least privilege, authentication management, cryptographic key management, and protection of data at rest. |
| **GDPR** | Art. 32 | Security of processing – unauthorized access to personal data in storage accounts. |
| **DORA** | Art. 9, 11 | ICT security and resilience; dependency on cloud storage as critical supporting service. |
| **NIS2** | Art. 21 | Technical and organizational measures to secure network and information systems, including cloud storage. |
| **ISO 27001** | A.9.2.3, A.10.1, A.12.4 | Management of privileged access, cryptographic controls, and logging/monitoring of access to sensitive data stores. |
| **ISO 27005** | Risk Scenario | "Compromise of cloud storage keys/connection strings leading to data breach and cross‑service compromise." |

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Using a Stolen Storage Account Connection String (Shared Key)

**Supported Versions:** All Azure Storage accounts where **Shared Key authorization** is enabled (default) and connection strings are configured.[7][10][13]

#### Step 1: Discover Storage Connection Strings in Code and Configuration

**Objective:** Search for Azure Storage connection strings in compromised repos, hosts, CI/CD logs, or configuration files.

**Typical Patterns:**

```text
DefaultEndpointsProtocol=https;AccountName=<name>;AccountKey=<key>;
DefaultEndpointsProtocol=https;AccountName=storagesample;AccountKey=<account-key>;EndpointSuffix=core.windows.net
```

**Command (Linux host or source tree):**

```bash
# Look for typical connection string markers
grep -R "DefaultEndpointsProtocol=https;AccountName=" . -n 2>/dev/null
grep -R "AccountKey=" . -n 2>/dev/null
```

**Expected Output:**

- Lines in source or config that reveal full connection strings or separate `AccountName` + `AccountKey` values.

**What This Means:**

- Each such string effectively **authorizes requests against the storage account** with the rights of the corresponding key; if this is a primary or secondary account key, it usually grants full read/write/delete permissions.[7][10][13][14]

**OpSec & Evasion:**

- Prefer harvesting from **local files, environment variables, and CI logs** instead of calling management APIs directly.
- Avoid mass scanning on production hosts that could trigger EDR alerts.

**Troubleshooting:**

- **Issue:** Only partial strings found (for example, `AccountKey` missing).
  - **Fix:** Identify Key Vault references or app settings that resolve at runtime.

**References & Proofs:**

- Microsoft Learn – "Configure Azure Storage connection strings" and warning about storing account keys in clear text.[7][10][13]

---

#### Step 2: Validate and Use the Connection String for Data Access

**Objective:** Confirm the connection string works and enumerate containers/blobs.

**Command (Azure CLI using connection string):**

```bash
export AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=<account-key>;EndpointSuffix=core.windows.net"

# List containers
az storage container list --output table

# List blobs in a candidate container
az storage blob list -c critical-data --output table
```

**Expected Output:**

- Successful listing of containers and blobs, confirming that the connection string is valid and has at least read permissions.

**What This Means:**

- The attacker now has **direct, programmatic access** to storage data. If the key has full rights, they can read, write, delete and generate SAS tokens, enabling both **collection and interference** with operational workloads.[4][7][10][14]

**OpSec & Evasion:**

- Limit enumeration to specific containers or paths that are likely to be relevant (for example, `functions`, `artifacts`, `config`, `logs`).
- Use SDKs from a **host that is already expected to access the account**, to avoid anomalous client fingerprints.

**Troubleshooting:**

- **Error:** `AuthorizationFailure`.
  - **Cause:** Key rotated or connection string truncated.
  - **Fix:** Search for updated keys, or pivot via another compromised principal with `listkeys` permissions.[7][10]

**References & Proofs:**

- Microsoft Learn – Storage connection string usage and Shared Key authentication model.[7][10][13]

---

#### Step 3: Lateral Movement via Triggered Compute and Data Poisoning

**Objective:** Use access gained through the connection string to compromise **downstream compute (Functions, Logic Apps, Data Factory, Synapse)** or data flows.

**Techniques:**

- **Overwrite Function App files** in the associated storage account (if using classic Functions storage model), leading to execution of attacker‑controlled code and possible exfiltration of managed identity tokens.[8][14][17]
- **Upload crafted blobs** to containers monitored by Event Grid/Functions/Logic Apps to trigger workflows under higher‑privileged identities.

**Command (example – overwrite function code blob):**

```bash
# Upload a malicious function file to the functions container
az storage blob upload \
  --container-name azure-webjobs-hosts \
  --file ./malicious_function.json \
  --name functions/myfunc/function.json
```

**Expected Output:**

- Successful upload with status indicating overwrite of existing blob.

**What This Means:**

- The next time the Function host synchronizes from storage, it may **load and execute attacker‑controlled configuration or code**, enabling elevation and lateral movement through the Function’s managed identity.[8][14][17]

**OpSec & Evasion:**

- Preserve **naming patterns and basic structure** of existing code/config to avoid immediate operational failure that would trigger rapid investigation.

**Troubleshooting:**

- **Issue:** Function fails and rolls back or raises errors.
  - **Fix:** Gradually modify behavior (for example, exfiltrate tokens and then proxy original logic) instead of replacing everything at once.

**References & Proofs:**

- Public research on using Azure Storage Shared Key and SAS credentials to overwrite Function code and exfiltrate managed identities for lateral movement.[5][8][14][17]

---

### METHOD 2 – Using an Account‑Level SAS Embedded in a Connection String

**Supported Versions:** All storage accounts with **account‑level SAS** enabled.

#### Step 1: Extract and Analyze SAS‑Based Connection String

**Objective:** Identify connection strings where the credentials are an **account‑level SAS** rather than a Shared Key.

**Example Format:**

```text
BlobEndpoint=https://myaccount.blob.core.windows.net/;
SharedAccessSignature=sv=2023-01-03&ss=b&srt=co&sp=racwdl&se=2099-12-31T23:59:59Z&sig=<signature>
```

**Command:**

```bash
grep -R "SharedAccessSignature=" . -n 2>/dev/null
```

**Expected Output:**

- One or more connection strings including `SharedAccessSignature=` with long, complex query strings.[7]

**What This Means:**

- The SAS often grants **multi‑service, multi‑resource, long‑lived permissions** equivalent to the account key, particularly if `ss` includes multiple services and `sp` includes `rwdlacup` (read/write/delete/list/add/create/update/process).[7][11][14]

**OpSec & Evasion:**

- Maintain **existing expiry (`se`)** to avoid suspicious regeneration; rely on long‑lived tokens where misconfigured.

**Troubleshooting:**

- **Issue:** Some operations denied.
  - **Cause:** SAS missing specific permissions (for example, no `d` for delete).
  - **Fix:** Use allowed operations to further compromise environment (for example, copy data elsewhere even if delete not allowed).[11][14]

**References & Proofs:**

- Microsoft Learn – using SAS in connection strings and implications of SAS permissions.[7][10][13]
- Security research highlighting risk of long‑lived, over‑permissive SAS tokens.[11][14]

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL – Eliminate or Minimize Shared Key/Account SAS Usage

**Action 1:** Migrate applications from **Shared Key / account‑level SAS connection strings** to **Entra ID‑based, passwordless authentication** (for example, `DefaultAzureCredential`).

**Manual Steps (Portal + Code):**

1. In Azure Portal, open **Storage account → Security + networking → Access keys** and review usage.
2. Enable **Entra ID authorization** for applicable services (Blob, Queue, etc.) and assign **role‑based access** (for example, `Storage Blob Data Reader/Contributor`) to managed identities or service principals.
3. Update application code to replace connection strings with `BlobServiceClient(new Uri("https://myaccount.blob.core.windows.net"), new DefaultAzureCredential())` or equivalent.[7][10][13]
4. After successful migration, gradually **rotate keys** and **disable Shared Key authorization** where supported, or ensure keys are only used in tightly controlled backend components.

---

**Action 2:** Restrict and Monitor SAS Usage

**Manual Steps:**

1. Enforce **service‑level SAS** scoped to specific containers/blobs, with minimal permissions and short expiry.
2. Avoid **account SAS** except in tightly controlled automation scenarios.
3. Use **Stored Access Policies** to centrally manage and revoke SAS where possible.

**Manual Steps (Policy / Governance):**

- Implement Azure Policy to **audit or deny deployments** that embed storage connection strings or SAS tokens in ARM templates, App Service settings, or Function app settings.

---

### Priority 2: HIGH – Secure Storage, Rotation, and Network Boundaries

**Action:** Store any remaining keys/SAS tokens in **Key Vault**, rotate frequently, and enforce **network controls**.

**Steps:**

1. Move all remaining `AccountKey`/SAS values into Key Vault; disallow storage in plain‑text config or code.[7][10][13][14]
2. Configure **private endpoints**, disable public network access where possible, and enforce **trusted services** and **Firewalls** to reduce impact if a key is leaked.[8][14]
3. Implement **continuous scanning** (DevSecOps) to detect connection strings and SAS tokens in repos.

**Validation Command (Verify Fix):**

```bash
rg "AccountKey=" . -g"*.config" -g"*.json" -g"*.ps1" -g"*.yml"
rg "SharedAccessSignature=" .
```

**Expected Output (If Secure):**

- No direct `AccountKey` or `SharedAccessSignature` values in code/config; references should point to Key Vault or identity‑based flows.

**What to Look For:**

- Any remaining secrets should be triaged, rotated and removed.

---

### Access Control & Policy Hardening

- Use **RBAC** to strictly limit who can list storage keys or create SAS tokens.
- Apply **Conditional Access** to admin and DevOps accounts with these rights.
- Implement **Just‑In‑Time access** and approval workflows for `listkeys` and SAS creation where feasible.

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Cloud:**
  - Sudden spikes in read/write/delete operations from unusual IPs, tenants or user agents.[8][14]
  - Unexpected `Microsoft.Storage/storageAccounts/listkeys/action` and SAS creation operations in Activity Logs.[17]
- **Data:**
  - Unexplained modifications to Function code blobs, configuration containers, or critical data containers.

### Forensic Artifacts

- **Azure Activity Logs:**
  - `listKeys`, `regenerateKey`, `setServiceProperties`, `putContainer` or SAS generation operations from atypical identities.[7][10][17]
- **Storage Logs (if enabled):**
  - Access patterns (IP, user agent, operations) outside normal baselines; unusual LIST and READ operations across many containers.
- **Application Logs:**
  - Function/Logic App invocation logs that correspond to attacker‑initiated blob uploads.

### Response Procedures

1. **Containment – Rotate Keys and Revoke SAS**
   - Immediately **regenerate storage account keys** and re‑deploy dependent apps with updated credentials.
   - Revoke or expire suspected SAS tokens; where possible, remove account‑level SAS and replace with scoped tokens.

2. **Evidence Collection**
   - Export Activity Logs and Storage logs for the suspected time window.
   - Snapshot critical containers for offline analysis before further changes.

3. **Eradication and Hardening**
   - Migrate from Shared Key to **Entra ID‑based auth**; enforce Azure Policy to prevent regression.
   - Implement DevSecOps checks (pre‑commit hooks, pipeline scanners) to detect secrets.

4. **Recovery and Monitoring**
   - Restore corrupted data from backups where required.
   - Deploy or tune **Sentinel analytics** to alert on abnormal key operations and data access patterns.

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | IA‑EXPLOIT‑003 – Logic App HTTP trigger abuse | Gain initial foothold by abusing exposed HTTP endpoints tied to storage workflows. |
| **2** | **Privilege Escalation** | PE‑ELEVATE‑005 – Graph API Permission Escalation | Escalate to roles that can manage storage accounts or list keys. |
| **3** | **Current Step** | **LM‑AUTH‑039 – Storage Account Connection String** | Use stolen connection strings to fully compromise storage accounts and their data. |
| **4** | **Persistence** | PERSIST‑SERVER‑003 – Azure Function Backdoor | Maintain persistence by overwriting function code/configuration in associated storage. |
| **5** | **Impact** | COLLECT‑DATA‑001 – Azure Blob Storage Data Exfiltration | Exfiltrate sensitive data and use it for further attacks or extortion. |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Long‑Lived SAS Token Exposure Leading to Storage Takeover

- **Target:** Azure Blob Storage used as backend for web and mobile applications.
- **Timeline:** 2024–2025 – documented cases where over‑permissive, long‑lived SAS tokens were exposed in public repos or front‑end code, enabling complete storage takeover.[11][14]
- **Technique Status:** Active – widespread misuse of SAS and Shared Key authorization continues despite Microsoft guidance favoring Entra ID and least‑privilege SAS.[7][10][13][14]
- **Impact:** Attackers gained read/write/delete access to blobs, modified application assets, and in some scenarios accessed configuration and secret files stored in the same account, enabling broader compromise and lateral movement to other Azure services.[8][11][14]
- **Reference:** Public research and Microsoft security case studies on Azure Storage SAS misuse and storage account compromise.[5][8][11][14][17]

### Example 2: Storage‑Backed Function App Lateral Movement

- **Target:** Azure Function Apps using storage accounts for code and triggers.
- **Timeline:** 2023–2024 – security research highlighted that access to the related storage account using Shared Key or SAS allowed overwriting function files and exfiltrating managed identity tokens, which were then used to move laterally to virtual machines and other PaaS resources.[8][14][17]
- **Technique Status:** Active – pattern remains viable wherever Functions and other compute services depend on storage accounts protected by Shared Key or broad SAS.
- **Impact:** Full compromise of Function Apps, theft of tokens for higher‑privileged identities, and subsequent access to crown‑jewel systems and data.
- **Reference:** Security research on Azure Storage Shared Key/Function abuse and lateral movement via managed identity token theft and storage‑triggered workflows.[5][8][14][17]

---