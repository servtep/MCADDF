# REC-CLOUD-005: Azure Resource Graph Enumeration

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-CLOUD-005 |
| **Technique Name** | Azure Resource Graph enumeration |
| **MITRE ATT&CK ID** | T1580 – Cloud Infrastructure Discovery; T1087.004 – Account Discovery: Cloud Account |
| **CVE** | N/A (Native Azure service; some services "working as intended" per MSRC) |
| **Platform** | Microsoft Azure Cloud / All resource types |
| **Viability Status** | ACTIVE ✓ |
| **Difficulty to Detect** | CRITICAL (zero audit logging; cross-subscription visibility) |
| **Requires Authentication** | Yes (Reader role minimum; some external enumeration unauthenticated) |
| **Applicable Versions** | All Azure commercial, government, and sovereign clouds |
| **Last Verified** | December 2025 |
| **Official Documentation** | https://learn.microsoft.com/en-us/azure/governance/resource-graph/ |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

Azure Resource Graph (ARG) is Microsoft's native, built-in cloud infrastructure discovery service that powers the Azure Portal search bar and provides "God-level visibility" across entire Azure tenants. ARG enables reconnaissance across multiple dimensions: (1) **authenticated ARG queries** leveraging valid credentials with minimum Reader role to enumerate all cloud resources cross-subscription with zero audit logging, and (2) **external ARG enumeration** via DNS subdomain enumeration combined with HTTP header parsing (ATEAM tool) to identify and attribute Azure resources without any authentication.

**Critical Threat Characteristics:**
- **Enabled by default**: Completely built-in service with zero installation barrier
- **Zero logging**: ARG queries generate no audit trail, no activity log entry, no sign-in log evidence
- **Cross-subscription visibility**: Single query can enumerate entire tenant (unlike CLI/PowerShell)
- **Minimal permissions required**: Reader role sufficient for full infrastructure reconnaissance
- **Undetectable analysis**: Queries return sub-second results from cached data
- **External attribution**: ATEAM tool can identify Azure resource ownership without credentials

**Business Impact:**
- Complete infrastructure mapping in seconds (resource locations, types, configurations)
- Identification of publicly accessible storage accounts, blobs, and databases (data exfiltration targets)
- Discovery of unpatched clusters vulnerable to latest CVEs (immediate exploitation targets)
- Visualization of network topology (NSG rules, firewall configurations, network paths)
- Enumeration of secrets management (key vaults, certificate stores, automation credentials)
- External attack surface mapping (1 million Azure resources enumerated, attributed)
- Lateral movement paths via discovered infrastructure relationships

---

## 3. TECHNICAL PREREQUISITES

### Required Knowledge
- Understanding of Azure resource types and hierarchy (subscriptions, resource groups, resources)
- Familiarity with Kusto Query Language (KQL) for resource graph queries
- Knowledge of Azure RBAC roles and permissions model
- Awareness of cloud infrastructure attack patterns (publicly accessible storage, unpatched clusters)
- Understanding of DNS enumeration and HTTP header parsing

### Required Tools

**For Authenticated ARG Enumeration:**
- Valid Azure credentials with minimum Reader role on target tenant
- Access to Azure Portal (browser) or Azure CLI
- No additional tools required (native service)

**For External ATEAM Enumeration:**
- **ATEAM Tool** (Azure Tenant Enumeration and Attribution Module)
  - Language: Python 3.x
  - Repository: https://github.com/NetSPI/ATEAM
  - Requirements: Requests library, sqlite3
  - Wordlist: 1 million Azure resource names (included)
  - DNS resolver (system-level or custom)
  - Parallel workers: 10+ recommended for speed

**System Requirements**
- No administrative privileges required
- Outbound HTTPS/DNS access to Azure APIs and DNS servers
- Disk space: 50MB for typical tenant (up to 500MB for large environments)
- RAM: 2GB minimum (more for large query result sets)

---

## 4. DETAILED EXECUTION

### Method 1: ARG Portal Interface (GUI Enumeration)

**Objective:** Interactive cloud infrastructure discovery via Azure Portal.

```
# Step 1: Open Azure Portal
https://portal.azure.com

# Step 2: Navigate to Resource Graph Explorer
Search bar → "Resource Graph Explorer"

# Step 3: Verify scope (tenant, management groups, subscriptions)
Left panel shows filtering options

# Step 4: Execute basic query (all resources)
Query box:
Resources

# Output: All resources in scope (sorted by type, count)
# Example: 96,000 resources in <1 second

# Step 5: Refine query for attack surface
Example Query 1: VMs with public IPs
Resources
| where type =~ 'microsoft.compute/virtualmachines'
| project vmId = tolower(tostring(id)), vmName = name
| join (Resources
| where type =~ 'microsoft.network/networkinterfaces'
| mv-expand ipconfig=properties.ipConfigurations
| project vmId = tolower(tostring(properties.virtualMachine.id)), privateIp = ipconfig.properties.privateIPAddress, publicIpId = tostring(ipconfig.properties.publicIPAddress.id)
| join kind=leftouter (Resources
| where type =~ 'microsoft.network/publicipaddresses'
| project publicIpId = id, publicIp = properties.ipAddress
) on publicIpId
) on vmId
| where array_length(publicIps)>0
| sort by vmName asc

# Output: 15 VMs with public IPs detected
# Data exposed: VM name, OS, public IP addresses, private IPs

# Step 6: Identify vulnerable VMs
Click each VM to view properties (OS image version, network config, tags)
```

**Key Insights Extracted:**
- Server roles (domain controller, SQL server, app server)
- OS versions (Windows Server 2012, unpatched systems)
- Network exposure (RDP, SSH open to internet)
- Tags revealing purpose (prod, test, database)

---

### Method 2: ARG CLI-Based Enumeration (Automated)

**Objective:** Batch enumeration across multiple resource types.

```bash
# Step 1: Authenticate to Azure
az login

# Step 2: Enumerate all storage accounts with public access
az graph query --first 1000 -q "
Resources
| where type =~ 'microsoft.storage/storageaccounts'
| extend allowBlobPublicAccess = properties.allowBlobPublicAccess
| where allowBlobPublicAccess == true
| project name, resourceGroup, location, allowBlobPublicAccess
"

# Output: All publicly accessible storage accounts (HIGH PRIORITY)
# Example: 23 accounts with public blob access

# Step 3: Query for unpatched AKS clusters (Fabricscape vulnerable)
az graph query -q "
Resources
| where type =~ 'microsoft.containerservice/managedclusters'
| extend kubeVersion = properties.kubernetesVersion
| where kubeVersion startswith '1.25' or kubeVersion startswith '1.24'
| project name, kubeVersion, resourceGroup, location
"

# Output: Unpatched clusters vulnerable to CVE-2022-25881
# Example: 8 clusters running vulnerable Kubernetes versions

# Step 4: Find NSG rules allowing RDP/SSH from any source
az graph query -q "
Resources
| where type =~ 'microsoft.network/networksecuritygroups/securityrules'
| where properties.sourceAddressPrefix == '*'
  and (properties.destinationPortRange == '3389' or properties.destinationPortRange == '22')
  and properties.access == 'Allow'
| project nsg = split(id, '/')[8], rule = name, direction = properties.direction, access = properties.access
"

# Output: Overly permissive NSG rules
# Example: 12 rules allow inbound RDP/SSH from any IP

# Step 5: Identify key vaults and their access policies
az graph query -q "
Resources
| where type =~ 'microsoft.keyvault/vaults'
| extend accessPolicies = properties.accessPolicies
| project name, location, accessPolicies
"

# Output: All key vaults (potential credential targets)
# Data exposed: Vault names, locations, access policies

# Step 6: Export results to CSV for further analysis
az graph query --first 5000 -q "QUERY HERE" | jq '.data[]' > resources.csv
```

**Detection Evasion:**
- All queries appear as normal user activity (no malicious signatures)
- Cross-subscription queries appear identical to single-subscription queries
- Zero audit logging; queries leave no trace
- Can spread queries over time to avoid rate-limiting

---

### Method 3: ATEAM External Enumeration (Unauthenticated)

**Objective:** Enumerate and attribute Azure resources without credentials.

```bash
# Step 1: Install ATEAM tool
git clone https://github.com/NetSPI/ATEAM.git
cd ATEAM
pip install -r requirements.txt

# Step 2: Basic resource enumeration (single keyword)
python3 ateam.py -r "mycompany"

# Output: 
# Enumerating resources with keyword "mycompany"
# Found: 
#   - mycompany-storage.blob.core.windows.net (Tenant: company.com)
#   - mycompany-vault.vault.azure.net (Tenant: company.com)
#   - mycompany-app.azurewebsites.net (Tenant: company.com)

# Step 3: Bulk enumeration with wordlist
cat keywords.txt:
# company
# myapp
# api
# cdn
# prod
# dev
# backup

python3 ateam.py -f keywords.txt -w 10

# Output: SQLite database (azure_tenants.db) with all discovered resources
# Results: 145 resources discovered and attributed

# Step 4: Generate HTML report
python3 ateam.py -f keywords.txt --output html --report report.html

# Output: report.html containing:
#   - Resource names
#   - Tenant IDs
#   - Tenant domain names
#   - Resource types
#   - Attribution confidence
#   - Discovery timestamp

# Step 5: Permutation-based enumeration (auto-generate variations)
python3 ateam.py -r "company" -p

# Generated permutations:
#   - company
#   - company-api
#   - api-company
#   - company-storage
#   - companydatabase
#   - company-db
#   - dev-company
#   - etc.

# Step 6: Attack surface mapping (external view)
# Results show:
#   - Unregistered domain names revealing new products
#   - Hidden infrastructure (dev/test environments)
#   - Third-party integrations (partner companies' resources)
#   - Resource attribution (which tenant owns what)
```

**ATEAM Techniques (HTTP Headers):**
```
# Storage Account Tenant ID Exposure
GET https://storageaccount.blob.core.windows.net/?comp=blobs
Response Headers:
WWW-Authenticate: Bearer authorization_uri=https://login.microsoftonline.com/977e0660-d4d3-4752-a79d-3ac9c4dbcf19/oauth2/authorize
# Tenant ID: 977e0660-d4d3-4752-a79d-3ac9c4dbcf19

# Key Vault Tenant ID Exposure
GET https://companyvault.vault.azure.net/secrets
Response:
WWW-Authenticate: Bearer authorization_uri=https://login.microsoftonline.com/[TENANT-ID]/oauth2/authorize

# App Service Attribution
GET https://company-app.azurewebsites.net/
Response Location: https://login.microsoftonline.com/[TENANT-ID]/oauth2/authorize
# Redirect exposes tenant ID
```

---

### Method 4: Advanced KQL for Vulnerability Discovery

**Objective:** Identify exploitable infrastructure configurations.

```kusto
// Query 1: Unpatched Storage Accounts with Public Access + GDPR Data
Resources
| where type =~ 'microsoft.storage/storageaccounts'
| extend allowBlobPublicAccess = properties.allowBlobPublicAccess
| where allowBlobPublicAccess == true
| extend resourceTags = tags
| where resourceTags.dataType contains "GDPR" and resourceTags.environment == "production"
| extend location = location
| where location !in ("northeurope", "westeurope", "germanywestcentral")  // GDPR requires EU storage
| project name, location, resourceGroup, allowBlobPublicAccess, dataType = resourceTags.dataType

// Query 2: AKS Clusters with Secrets in Etcd (Unencrypted)
Resources
| where type =~ 'microsoft.containerservice/managedclusters'
| extend etcdEncryption = properties.securityProfile.etcdDataEncryption
| where etcdEncryption == null or etcdEncryption.enabled == false
| project name, region = location, clusterRG = resourceGroup

// Query 3: SQL Servers with Disabled Firewall
Resources
| where type =~ 'microsoft.sql/servers'
| extend firewallRules = properties.firewallRules
| project name, resourceGroup, location, firewallRules

// Query 4: VMs with Managed Identity (Potential C2 Targets)
Resources
| where type =~ 'microsoft.compute/virtualmachines'
| where identity.type == 'SystemAssigned' or identity.type == 'UserAssigned'
| project vmName = name, identityType = identity.type, resourceGroup, location

// Query 5: Cosmos DB without IP Firewall
Resources
| where type =~ 'microsoft.documentdb/databaseaccounts'
| extend ipRangeFilter = properties.ipRangeFilter
| where ipRangeFilter == '' or ipRangeFilter == '0.0.0.0'
| project name, resourceGroup, location, isPublic = true
```

---

## 5. TOOLS & COMMANDS REFERENCE

### ARG Query Functions (KQL)

| Function | Purpose | Example |
|----------|---------|---------|
| `where` | Filter resources by property | `where type =~ 'microsoft.compute/virtualmachines'` |
| `project` | Select output columns | `project name, location, properties` |
| `join` | Combine resources (relational) | `join (Resources | ...) on id` |
| `mv-expand` | Expand array properties | `mv-expand ipconfig = properties.ipConfigurations` |
| `summarize` | Aggregate data | `summarize count() by type, location` |
| `sort` | Order results | `sort by name asc` |
| `extend` | Add calculated columns | `extend publicAccessEnabled = properties.allowPublicAccess` |

### Common ARG Queries

| Objective | Query | Risk |
|-----------|-------|------|
| All resources | `Resources` | HIGH (96k+ objects) |
| VMs + public IPs | Complex triple-join | CRITICAL |
| Public storage | `where allowBlobPublicAccess == true` | CRITICAL |
| Unpatched clusters | `where kubeVersion < version` | CRITICAL |
| NSG RDP rules | `where port == 3389 and source == '*'` | HIGH |
| Key vaults | `where type =~ 'keyvault'` | HIGH |

---

## 6. ATOMIC TESTS

### Test 1: Basic ARG Query
```bash
az graph query -q "Resources | take 1"
if [ $? -eq 0 ]; then
  echo "✓ Test PASSED: ARG query executed"
else
  echo "✗ Test FAILED"
fi
```

### Test 2: Cross-Subscription Enumeration
```bash
az graph query -q "Resources | summarize count() by subscriptionId"
if [ $(az graph query -q "Resources" | jq '.data | length') -gt 100 ]; then
  echo "✓ Test PASSED: Multiple subscriptions enumerated"
fi
```

### Test 3: ATEAM Enumeration
```bash
python3 ateam.py -r "test" 
if [ -f "azure_tenants.db" ]; then
  echo "✓ Test PASSED: Resources enumerated and attributed"
fi
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Forensic Challenges
- **Zero logging**: ARG queries leave no audit trail
- **Cached results**: Queries reference snapshot data, no API logging
- **Normal baseline**: Reader role usage is expected and common

### Detection Approach (Behavioral)
- **Monitor successful sign-ins** with Reader role
- **Baseline normal ARG usage** (establish threshold)
- **Alert on anomalies**: Reader accessing multiple subscriptions (uncommon)
- **Correlate with compromise indicators**: Password changes, suspicious activity post-sign-in

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Implement Conditional Access for Resource Graph**
- **Policy**: Block Reader access from external IPs
- **Alternative**: Require MFA for Reader-level queries

**Restrict Reader Role Assignment**
- **Principle**: Only assign Reader to accounts that need it
- **Audit**: Quarterly review of Reader role holders
- **Revoke**: Inactive users

**Disable Public Access on Storage**
- **Policy**: Enforce private access for all blobs
- **Exceptions**: Only explicitly approved storage accounts
- **Monitoring**: Alert on allowBlobPublicAccess = true

### Priority 2: HIGH

**Disable Azure Lighthouse (if not used)**
- Prevents cross-tenant queries even if Reader role compromised

**Implement Azure Policy**
- Audit-mode policies identifying non-compliant configurations
- Enforcement policies preventing public access

**Monitor Large Query Execution**
- Baseline typical query result sizes
- Alert on unusual query patterns (>10,000 resources returned)

---

## 9. COMPLIANCE MAPPING

| Standard | Requirement | ARG Consideration |
|----------|-------------|------------------|
| **NIST 800-53** | AC-2 (Account Management) | Reader role restrictions |
| **DORA** | Infrastructure resilience | Resource visibility controls |
| **ISO 27001** | 8.2 (Access control) | Role assignment governance |

---

## 10. REFERENCES

1. **Azure Resource Graph:**
   - Official: https://learn.microsoft.com/en-us/azure/governance/resource-graph/
   - Samples: https://learn.microsoft.com/en-us/azure/governance/resource-graph/samples/

2. **ATEAM Tool:**
   - Repository: https://github.com/NetSPI/ATEAM
   - Research: NetSPI blog "We Know What You Did (in Azure) Last Summer"

3. **ARG Security Research:**
   - Darwin Salazar: "Leveraging Azure Resource Graph for Good and for Evil" (fwd:cloudsec 2022)
   - Clark E: "Quick and Dirty Azure VM Attack Surface Enumeration"

---
