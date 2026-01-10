# [LM-REMOTE-008]: Azure VNET Peering Traversal

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-REMOTE-008 |
| **MITRE ATT&CK v18.1** | [T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID / Azure |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure subscription types; VNETs with peering enabled |
| **Patched In** | N/A (Technique remains active; requires architectural redesign) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure VNET (Virtual Network) Peering Traversal exploits the fact that peered virtual networks become part of the same routing domain with full unrestricted traffic flow by default. Many organizations implement hub-and-spoke architectures with peered networks but fail to deploy additional security controls (NSGs, Azure Firewall, User-Defined Routes) between peered networks. Once an attacker compromises a VM in one peered VNET (e.g., "Development"), they can seamlessly access VMs in other peered VNETs (e.g., "Production", "Shared Services") using internal IP addresses. This is fundamentally different from on-premises environments where multiple physical networks require explicit routing configuration. VNET peering makes network traversal trivial—the attacker doesn't need to exploit routing misconfigurations; the connectivity is intentionally built-in.

**Attack Surface:**
- **VNET Peering Links (RFC1918 IP ranges):** Direct connectivity between peered address spaces
- **Azure Firewall:** If deployed, inspects east-west traffic; if missing, full traversal allowed
- **Network Security Groups (NSGs):** Per-NIC or per-subnet filtering; often omitted between peered networks
- **User-Defined Routes (UDRs):** Route table configurations; may bypass firewall if misconfigured
- **Service Endpoints / Private Endpoints:** Access to Azure PaaS services (Storage, SQL, Key Vault) from peered networks

**Business Impact:** **Enables breach escalation from development environment to production.** Development networks often have weaker security controls (fewer admins, less monitoring, lower sensitivity data). If a development VM is compromised and peered to production, the attacker can immediately access production databases, application servers, and sensitive data. Typical impact includes data breach of production systems, ransomware deployment across all peered networks, and infrastructure destruction.

**Technical Context:** VNET peering traversal is instantaneous—once a VM is compromised, lateral movement to other VNETs occurs in seconds. Detection is challenging because peering traffic is internal to Azure (not crossing organization boundaries) and appears as normal VM-to-VM communication. The primary defense is architectural: enforce zero-trust network segmentation even between peered networks. Many organizations skip this step because peering is perceived as "trusted internal traffic."

### Operational Risk

- **Execution Risk:** Very Low – Simply requires network connectivity; no exploitation needed
- **Stealth:** High – Internal traffic blends with legitimate cross-VNET communication
- **Reversibility:** No – Once peered networks are accessed, resources are compromised until manually recovered

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 6.3, 6.5 | Network Segmentation, VPC/VNET Configuration |
| **DISA STIG** | SRG-APP-000516 | Application Communication Security via Network |
| **CISA SCuBA** | SC.L1-3.3.6, SC.L1-3.13.8 | Network Isolation and Segmentation, Interconnection Traffic |
| **NIST 800-53** | AC-3, AC-4, SI-4 | Access Enforcement, Information Flow Enforcement, System Monitoring |
| **GDPR** | Art. 32 | Security of Processing - Network segmentation and isolation |
| **DORA** | Art. 10 | Incident Handling (Cross-system incidents via network bridges) |
| **NIS2** | Art. 21 | Cyber Risk Management - Network monitoring and segregation |
| **ISO 27001** | A.13.1.1, A.13.2.1 | Network Architecture, Network Access Control |
| **ISO 27005** | § 4.4.1, § 5.4.2 | Risk Analysis – Network isolation failure, Risk Treatment options |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Valid credentials on initial VNET VM (any privilege level)
- **Required Access:** VNET peering must be established and `Allow Virtual Network Access` enabled; traffic must not be filtered by NSG/Firewall

**Supported Versions:**
- **Azure Subscriptions:** All types (EA, PAYG, CSP, Government Cloud, etc.)
- **VNETs:** All regions; IPv4 and IPv6 peering
- **Other Requirements:** Target resources (VMs, databases, storage) must be reachable via RFC1918 IP addresses on peered VNET

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (v2.40.0+)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/) (Az module v9.0+)
- [Impacket](https://github.com/fortra/impacket) (for RDP/SSH lateral movement across VNETs)
- [Nmap](https://nmap.org/) (for port scanning across peered networks)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound) (for Azure RBAC visualization; can show trust relationships)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Connect to Azure subscription
Connect-AzAccount

# Enumerate all VNETs in subscription
Get-AzVirtualNetwork | Select-Object Name, ResourceGroupName, AddressSpace

# Check peering relationships
$vnet = Get-AzVirtualNetwork -Name "DevelopmentVNET" -ResourceGroupName "RG1"
$vnet | Get-AzVirtualNetworkPeering | Select-Object Name, PeeringState, AllowVirtualNetworkAccess

# Enumerate VMs in peered VNETs
Get-AzVM -ResourceGroupName "ProductionRG" | Select-Object Name, @{N="VNET";E={($_.NetworkProfile.NetworkInterfaces[0].Id -split "/" | select -Last 1)}}

# Check NSG rules between peered networks
$nsg = Get-AzNetworkSecurityGroup -ResourceGroupName "ProductionRG" -Name "Prod-NSG"
$nsg | Get-AzNetworkSecurityRuleConfig | Select-Object Name, SourceAddressPrefix, DestinationPortRange, Access
```

**What to Look For:**
- Multiple VNETs with `PeeringState = Connected` → Trust relationships exist
- `AllowVirtualNetworkAccess = True` on both sides → Full peering enabled
- NSG rules allow traffic from development CIDR to production CIDR → Likely misconfigured or overly permissive
- No Azure Firewall or UDRs between peers → No additional security controls

**Version Note:** Behavior consistent across all Azure subscription types and regions

### Linux/Bash / CLI Reconnaissance

```bash
# Login to Azure
az login

# List all VNETs and their peering status
az network vnet list --query "[].{Name:name, ResourceGroup:resourceGroup, AddressSpace:addressSpace}" -o table

# Check specific peering relationship
az network vnet peering list --resource-group "RG1" --vnet-name "DevelopmentVNET" --query "[].{Name:name, PeeringState:peeringState, AllowVirtualNetworkAccess:allowVirtualNetworkAccess}" -o table

# Enumerate VMs and their subnets in peered VNETs
az vm list --resource-group "ProductionRG" --query "[].{Name:name, Subnet:networkProfile.networkInterfaces[0].id}" -o table

# Check network interfaces and their private IPs
az network nic list --resource-group "ProductionRG" --query "[].{Name:name, PrivateIP:ipConfigurations[0].privateIpAddress, Subnet:ipConfigurations[0].subnet.id}" -o table

# List NSG rules for production NSG
az network nsg rule list --resource-group "ProductionRG" --nsg-name "Prod-NSG" --query "[].{Name:name, SourcePrefix:sourceAddressPrefix, DestPort:destinationPortRange, Access:access}" -o table
```

**What to Look For:**
- VNET address spaces that don't overlap but are peered
- Peering states showing "Connected" on both sides
- NSG rules showing permissive access between VNET address spaces
- No rules explicitly denying development → production traffic

---

## 4. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: Direct RDP/SSH Traversal Across Peered VNETs

**Supported Versions:** All Azure VM editions

#### Step 1: Identify Target VMs in Peered VNETs

**Objective:** Enumerate VMs accessible via peering and determine which are reachable

**Command:**
```powershell
# From compromised VM in Development VNET (10.0.0.0/16)
# Enumerate production VNET (10.1.0.0/16) resources

# Perform network scanning across peering link
$productionSubnet = "10.1.1.0/24"  # Production Subnet
$ports = 3389, 22, 5985  # RDP, SSH, WinRM

# Scan for accessible hosts
for ($i = 1; $i -le 254; $i++) {
    $ip = "10.1.1.$i"
    $result = Test-NetConnection -ComputerName $ip -Port 3389 -WarningAction SilentlyContinue
    if ($result.TcpTestSucceeded) {
        Write-Host "RDP accessible on $ip"
    }
}

# Alternative: Use PowerShell remoting across peering
$ips = @("10.1.1.5", "10.1.2.10", "10.1.3.15")
foreach ($ip in $ips) {
    $session = New-PSSession -ComputerName $ip -Credential (Get-Credential) -ErrorAction SilentlyContinue
    if ($session) {
        Write-Host "PowerShell Remoting successful on $ip"
    }
}
```

**Expected Output:**
```
RDP accessible on 10.1.1.5
RDP accessible on 10.1.1.10
RDP accessible on 10.1.1.15
PowerShell Remoting successful on 10.1.2.10
```

**What This Means:**
- Multiple hosts in production VNET are reachable from development VNET
- VNET peering allows unrestricted traffic flow
- RDP/WinRM ports are open (no NSG blocking)
- Lateral movement targets identified

**OpSec & Evasion:**
- Network scanning creates traffic visible in NSG flow logs (if enabled)
- PowerShell remoting appears as legitimate admin activity
- Detection likelihood: Medium (depends on monitoring VNET peering traffic)

**References & Proofs:**
- [Azure VNET Peering - Microsoft Learn](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview)
- [Network Security Groups - Microsoft Learn](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)

#### Step 2: Compromise Production VM via RDP/SSH

**Objective:** Establish remote access session on production VM from development VM

**Command:**
```powershell
# Connect to production VM via RDP (from compromised development VM)
# Using credentials from development network (often reused across environments)

$cred = Get-Credential
mstsc.exe /v:10.1.1.5 /admin /u:contoso\administrator /p:$cred.Password

# Alternative: PowerShell Remoting across peering
$session = New-PSSession -ComputerName 10.1.1.5 -Credential $cred
Enter-PSSession $session

# Execute commands on production VM
whoami  # Verify access
Get-Service | Where-Object Status -eq "Running"  # Enumerate services
Get-ChildItem "C:\Program Files\SQL Server\" -Recurse  # Look for databases
```

**Expected Output:**
```
[10.1.1.5]: PS C:\Users\Administrator\Documents>
CONTOSO\Administrator
```

**What This Means:**
- Successfully authenticated to production VM via VNET peering
- Attacker now has interactive access to production infrastructure
- Commands execute with same privilege level as compromised account
- Production environment is fully accessible

**OpSec & Evasion:**
- RDP connection creates Event ID 4624 logon on production DC
- PowerShell Remoting shows as legitimate remote session
- Credentials reused across environments appear normal
- Detection likelihood: Low-Medium (if monitoring for cross-VNET logons)

**Troubleshooting:**
- **Error:** "Cannot connect to 10.1.1.5"
  - **Cause:** NSG rule blocks RDP from development subnet
  - **Fix:** Check NSG inbound rules: `Get-AzNetworkSecurityRuleConfig -NSG $nsg | Where DestinationPort -like "*3389*"`

- **Error:** "Access Denied" when using credentials
  - **Cause:** Credentials don't have access to production VM
  - **Fix:** Use credentials of production admin account (if obtained from credential spray/dumping)

---

### METHOD 2: Azure Resource Access via Peering (Storage, SQL, Key Vault)

**Supported Versions:** All Azure subscription types

#### Step 1: Enumerate Azure Resources in Peered VNET

**Objective:** Identify PaaS resources accessible from compromised VM via peering

**Command:**
```powershell
# From compromised development VM, enumerate production Azure resources

# List storage accounts in production resource group
Get-AzStorageAccount -ResourceGroupName "ProductionRG" | Select-Object StorageAccountName, Location, Kind

# List SQL databases
Get-AzSqlServer -ResourceGroupName "ProductionRG" | Select-Object ServerName, Location, FullyQualifiedDomainName

# List Key Vaults
Get-AzKeyVault -ResourceGroupName "ProductionRG" | Select-Object VaultName, Location

# Check if VM has managed identity with permissions to these resources
$vmIdentity = (Get-AzVM -Name "ProdVM1" -ResourceGroupName "ProductionRG").Identity
if ($vmIdentity) {
    Get-AzRoleAssignment -ObjectId $vmIdentity.PrincipalId | Select-Object RoleDefinitionName, Scope
}
```

**Expected Output:**
```
StorageAccountName: prodstorage2024
Location: eastus
Kind: StorageV2

ServerName: prodsqlserver01
FullyQualifiedDomainName: prodsqlserver01.database.windows.net

VaultName: prod-keyvault-01
Location: eastus

RoleDefinitionName: Reader
Scope: /subscriptions/.../resourceGroups/ProductionRG
```

**What This Means:**
- Storage, SQL, and Key Vault resources are accessible via peering
- Managed identity has broad permissions (Reader role)
- Can retrieve secrets from Key Vault if permissions allow
- Database access is possible via internal IP addresses

**OpSec & Evasion:**
- Resource enumeration creates minimal audit logs
- Access attempts may be logged but appear normal if using valid credentials
- Detection likelihood: Medium (depends on RBAC auditing)

#### Step 2: Access SQL Database Across Peering

**Objective:** Connect to SQL database in production VNET using internal IP

**Command:**
```powershell
# Connect to SQL Server in production using internal VNET address
$sqlServer = "prodsqlserver01.database.windows.net"
$database = "ProductionDB"
$credential = Get-Credential  # Production SQL admin credentials (if obtained)

# Create SQL connection
$connectionString = "Server=$sqlServer;Database=$database;User ID=$($credential.UserName);Password=$($credential.Password);"

# Execute SQL query
$sqlConnection = New-Object System.Data.SqlClient.SqlConnection
$sqlConnection.ConnectionString = $connectionString
$sqlConnection.Open()

$sqlCommand = $sqlConnection.CreateCommand()
$sqlCommand.CommandText = "SELECT * FROM sys.databases"
$result = $sqlCommand.ExecuteReader()
while ($result.Read()) {
    Write-Host $result[0]
}
$sqlConnection.Close()
```

**Expected Output:**
```
master
tempdb
model
msdb
ProductionDB
SensitiveDataDB
CustomerDatabase
```

**What This Means:**
- Authenticated successfully to production SQL database
- Can enumerate databases and tables
- Can execute queries or dump data
- Full database access achieved

**OpSec & Evasion:**
- SQL connection logs show authentication attempts (may trigger alerts)
- Data exfiltration creates data transfer logs
- Detection likelihood: High (if SQL auditing enabled)

---

### METHOD 3: Azure Firewall Bypass via Subnet Routes

**Supported Versions:** Azure VNETs with Azure Firewall or UDRs

#### Step 1: Identify Firewall Configuration

**Objective:** Determine if Azure Firewall is deployed and check its bypass methods

**Command:**
```powershell
# Check if Azure Firewall is deployed in hub VNET
Get-AzFirewall -ResourceGroupName "NetworkRG" | Select-Object Name, ProvisioningState, Location

# Check User-Defined Routes (UDRs) for bypass
$routeTable = Get-AzRouteTable -ResourceGroupName "ProductionRG" -Name "Prod-Routes"
$routeTable | Get-AzRouteConfig | Select-Object Name, AddressPrefix, NextHopType, NextHopIpAddress

# Identify Azure Firewall private IP address
$firewall = Get-AzFirewall -ResourceGroupName "NetworkRG" -Name "HubFirewall"
$firewall.IpConfigurations | Select-Object Name, PrivateIpAddress
```

**Expected Output:**
```
Name: HubFirewall
ProvisioningState: Succeeded

Name: Default-Route
AddressPrefix: 0.0.0.0/0
NextHopType: VirtualAppliance
NextHopIpAddress: 10.200.1.4

Name: ToProduction
AddressPrefix: 10.1.0.0/16
NextHopType: VirtualAppliance
NextHopIpAddress: 10.200.1.4
```

**What This Means:**
- Azure Firewall is deployed and routing is configured
- Most traffic goes through firewall for inspection
- Some routes may bypass firewall if configured incorrectly

**OpSec & Evasion:**
- Firewall rules may block suspicious traffic
- Custom rules may allow certain traffic paths
- Detection likelihood: Depends on firewall rule design

#### Step 2: Exploit Firewall Bypass (If Misconfigured)

**Objective:** Route traffic to bypass firewall inspection

**Command:**
```powershell
# Check if Direct-Peering route bypasses firewall
# (Some organizations set NextHopType: "VNetLocal" for peered subnets, which bypasses firewall)

# From compromised VM, attempt direct routing to peered subnet
$targetVM = "10.1.1.5"
$hops = Test-NetConnection -ComputerName $targetVM -TraceRoute -WarningAction SilentlyContinue

# Analyze route
$hops.TraceRoute | ForEach-Object {
    Write-Host "$($_): $(if ($_ -eq '10.200.1.4') { 'FIREWALL' } else { 'DIRECT' })"
}

# If direct route is available, traffic bypasses firewall
# Attempt to access production resources directly
$session = New-PSSession -ComputerName $targetVM -Credential (Get-Credential)
```

**Expected Output (If Firewall Bypass Exists):**
```
10.0.0.1: SOURCE
10.1.1.5: DIRECT (No firewall hop)
```

**What This Means:**
- Traffic routed directly to production without firewall inspection
- Firewall rules do not apply to this traffic path
- Malicious traffic (exfiltration, C2 communication) can flow without detection
- Lateral movement is unobstructed

---

## 5. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team

- **Atomic Test ID:** T1021.002 (Network traversal via peering), T1021.001 (RDP across VNET)
- **Test Names:** 
  - "Lateral Movement via VNET Peering"
  - "RDP Across Peered Networks"
  
- **Supported Versions:** All

- **Command:**
```powershell
# VNET peering traversal test
Invoke-AtomicTest T1021.001 -TestNumbers 2  # RDP lateral movement

# Custom test for peering traversal
# (If custom Atomic test exists)
```

**Reference:** [Atomic Red Team - T1021](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021/T1021.md)

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: VNET Peering Traversal Detection

**Rule Configuration:**
- **Required Table:** AzureNetworkAnalytics_CL (NSG Flow Logs)
- **Required Fields:** SrcIP_s, DestIP_s, DestPort_d, Protocol_s, AllowedInFlows_d, Direction_s
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All (requires NSG Flow Logs enabled)

**KQL Query:**
```kusto
AzureNetworkAnalytics_CL
| where AllowedInFlows_d > 0
| where SrcIP_s startswith "10.0." and DestIP_s startswith "10.1."  // Dev to Prod subnets
| where DestPort_d in (3389, 22, 5985, 5986, 1433)  // RDP, SSH, WinRM, SQL ports
| where Protocol_s in ("T", "U")  // TCP, UDP
| summarize ConnectionCount = sum(AllowedInFlows_d) by SrcIP_s, DestIP_s, DestPort_d, bin(TimeGenerated, 5m)
| where ConnectionCount > 5
| project-reorder TimeGenerated, SrcIP_s, DestIP_s, DestPort_d, ConnectionCount
```

**What This Detects:**
- Traffic flowing from development subnet to production subnet
- Multiple connections to administrative ports (RDP, SSH)
- Pattern indicates lateral movement via peering
- Increased connection count suggests reconnaissance or sustained access

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Lateral Movement - VNET Peering Traversal`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL above
   - Run every: `5 minutes`
   - Lookup data from the last: `30 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Entity mapping: SrcIP_s → IP, DestIP_s → IP
6. Click **Create**

#### Query 2: Cross-VNET Resource Access via Managed Identity

**Rule Configuration:**
- **Required Table:** AzureActivity
- **Required Fields:** OperationName, Properties, CallerIpAddress, ResourceGroup
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All

**KQL Query:**
```kusto
AzureActivity
| where OperationName in ("Get secret", "List secrets", "Create or update secret")
| where ResourceGroup startswith "Production"
| where CallerIpAddress startswith "10.0."  // From development VNET
| summarize AccessCount = count() by CallerIpAddress, ResourceGroup, OperationName, bin(TimeGenerated, 10m)
| where AccessCount > 3
```

**What This Detects:**
- Key Vault secret access from development VNET IPs
- Multiple secret retrieval attempts (credential theft)
- Access to production resources from unusual source

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4624 (Successful Logon)**
- **Log Source:** Security (on production VMs)
- **Trigger:** RDP logons from development VNET IP addresses
- **Filter:** IpAddress startswith "10.0." (development subnet) + LogonType=10 (RDP)
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps:**
1. On **Production VMs**, configure audit logging for logons
2. Enable forwarding to central SIEM or Log Analytics Workspace
3. Create alert for logons from development subnet IPs
4. Notify incident response team immediately

**Event ID: 5156 (Windows Filtering Platform - Outbound Connection)**
- **Log Source:** Security
- **Trigger:** Outbound connections to development VNET from production VM
- **Filter:** DestAddress startswith "10.1."
- **Applies To Versions:** Server 2008+

---

## 8. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Implement Azure Firewall Between Peered VNETs:**
  
  **Applies To Versions:** All
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Virtual Networks** → **Firewalls**
  2. Click **+ Create**
  3. Configure:
     - Name: `Hub-Firewall`
     - Region: Central region (hub)
     - Tier: Standard (minimum)
  4. Create subnets:
     - `AzureFirewallSubnet` (10.200.1.0/24)
  5. Deploy firewall
  6. Route all peering traffic through firewall:
     - Create UDRs for each peered VNET
     - Set NextHopType = "VirtualAppliance"
     - Set NextHopIpAddress = Firewall private IP
  7. Apply UDR to subnets in all peered VNETs
  
  **Manual Steps (Azure CLI):**
  ```bash
  # Create Azure Firewall
  az network firewall create --resource-group "NetworkRG" --name "Hub-Firewall" --location "eastus"
  
  # Create firewall rules to restrict development → production traffic
  az network firewall rule-collection-group create --resource-group "NetworkRG" \
    --firewall-name "Hub-Firewall" --name "RestrictDevToProd" --priority 100 \
    --rule-collection-groups "DenyDevToProd"
  ```

* **Implement Network Security Groups Between Peered VNETs:**
  
  **Applies To Versions:** All
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Virtual Networks** → **Network Security Groups**
  2. Create/Edit production NSG
  3. Add inbound rule:
     - Source: Development VNET CIDR (10.0.0.0/16)
     - Destination ports: Deny all, except explicitly allowed (e.g., 443 for HTTPS API only)
     - Action: Deny
     - Priority: 100 (highest)
  4. Add exception rules below (if needed):
     - Allow only specific ports (e.g., 443) from specific IPs (jump box)
  5. Apply NSG to all production subnets
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Create restrictive NSG for production
  $nsgConfig = New-AzNetworkSecurityGroup -Name "Prod-NSG-Restrictive" -ResourceGroupName "ProductionRG" -Location "eastus"
  
  # Deny all traffic from development VNET by default
  $rule = New-AzNetworkSecurityRuleConfig -Name "DenyAllFromDev" -Protocol '*' `
    -SourcePortRange '*' -SourceAddressPrefix "10.0.0.0/16" `
    -DestinationPortRange '*' -DestinationAddressPrefix '*' `
    -Access "Deny" -Priority 100 -Direction "Inbound"
  
  $nsgConfig | Add-AzNetworkSecurityRuleConfig @rule
  $nsgConfig | Set-AzNetworkSecurityGroup
  ```

* **Disable or Restrict VNET Peering if Not Needed:**
  
  **Applies To Versions:** All
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Virtual Networks**
  2. Select development VNET
  3. In left menu, click **Peerings**
  4. For each peering:
     - If not essential, click **Delete**
     - If essential, set:
       - `AllowVirtualNetworkAccess`: OFF (unless traffic flow is required)
       - `AllowForwardedTraffic`: OFF
       - `AllowGatewayTransit`: OFF
       - `UseRemoteGateways`: OFF

#### Priority 2: HIGH

* **Implement Zero-Trust Network Segmentation (Micro-Segmentation):**
  
  **Applies To Versions:** All
  
  **Manual Steps:**
  1. Deploy Azure Firewall in hub VNET
  2. Create spoke VNETs with no direct peering
  3. Route all inter-VNET traffic through firewall
  4. Configure firewall rules:
     - Default: DENY ALL
     - Explicit: ALLOW only required traffic (e.g., Dev → Prod only for API calls on port 443)
  5. Monitor all firewall rules for suspicious patterns
  6. Implement identity-based rules using Azure Firewall Premium (if budget allows)

* **Enable NSG Flow Logs and Azure Network Watcher:**
  
  **Applies To Versions:** All
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Network Watcher**
  2. Select **NSG Flow Logs**
  3. Click **+ Create**
  4. Select all production NSGs
  5. Enable flow logging to storage account
  6. Set retention: **90 days minimum**
  7. Enable **Traffic Analytics** for visualization
  8. Create alerts in Sentinel for unusual inter-VNET traffic

#### Access Control & Policy Hardening

* **Enforce Principle of Least Privilege for Managed Identities:**
  
  **Manual Steps:**
  1. Navigate to **Azure Portal** → **Virtual Machines** → Select VM
  2. Go to **Identity** → **System-assigned** → **Azure role assignments**
  3. Remove default "Contributor" role
  4. Assign only required roles:
     - `Reader` (read-only on VMs in same VNET)
     - `Storage Blob Data Reader` (specific storage account only)
     - Avoid cross-VNET permissions
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Remove broad roles
  $vm = Get-AzVM -Name "DevVM" -ResourceGroupName "DevRG"
  Remove-AzRoleAssignment -ObjectId $vm.Identity.PrincipalId -RoleDefinitionName "Contributor"
  
  # Assign specific role to specific resource
  New-AzRoleAssignment -ObjectId $vm.Identity.PrincipalId `
    -RoleDefinitionName "Reader" `
    -Scope "/subscriptions/$(Get-AzContext).Subscription.Id/resourceGroups/DevRG"
  ```

#### Validation Command (Verify Fix)

```powershell
# Verify NSG rules block development → production traffic
$nsg = Get-AzNetworkSecurityGroup -ResourceGroupName "ProductionRG" -Name "Prod-NSG"
$nsg | Get-AzNetworkSecurityRuleConfig | 
    Where-Object { $_.SourceAddressPrefix -like "*10.0*" -or $_.SourceAddressPrefix -eq "*" } | 
    Select-Object Name, SourceAddressPrefix, DestinationPortRange, Access

# Verify Azure Firewall is deployed
Get-AzFirewall -ResourceGroupName "NetworkRG" | Select-Object Name, ProvisioningState

# Verify UDRs route traffic through firewall
$routeTable = Get-AzRouteTable -ResourceGroupName "ProductionRG" -Name "Prod-Routes"
$routeTable | Get-AzRouteConfig | 
    Where-Object { $_.NextHopType -eq "VirtualAppliance" } | 
    Select-Object Name, AddressPrefix, NextHopIpAddress

# Verify NSG Flow Logs are enabled
Get-AzNetworkWatcherFlowLogStatus -TargetResourceId (Get-AzNetworkSecurityGroup -ResourceGroupName "ProductionRG").Id
```

**Expected Output (If Secure):**
```
Name                    SourcePrefix           DestPort Access
----                    ----                   -------- ------
DenyAllFromDev         10.0.0.0/16            *        Deny

Name             ProvisioningState
----             -----------------
Hub-Firewall     Succeeded

Name                AddressPrefix     NextHopType        NextHopIpAddress
----                -----             -----------        ----------------
DefaultToFirewall   0.0.0.0/0          VirtualAppliance   10.200.1.4
ToProdVNET         10.1.0.0/16        VirtualAppliance   10.200.1.4

Enabled: True
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] Azure App Service Exploitation | Attacker exploits vulnerable web app in development VNET |
| **2** | **Privilege Escalation** | [PRIV-AZURE-001] Managed Identity Token Theft | Extract managed identity token from compromised app |
| **3** | **Current Step** | **[LM-REMOTE-008]** | **Use token/credentials to lateral move across VNET peering to production resources** |
| **4** | **Persistence** | [PERSIST-AZURE-002] Service Principal Backdoor | Create persistent backdoor in production VNET |
| **5** | **Impact** | [IMPACT-CLOUD-002] Database Exfiltration | Access production SQL database via cross-VNET lateral movement; exfiltrate customer data |

---

## 10. REAL-WORLD EXAMPLES

#### Example 1: Capital One Data Breach (Hybrid Cloud Misconfiguration, 2019)

- **Target:** Financial services (AWS multi-VNET setup, misconfigured security groups)
- **Timeline:** March 2019
- **Technique Status:** Attacker compromised single EC2 instance (AWS equivalent of Azure VM) in development environment; misconfigured security group rules allowed unrestricted access to production VPCs; lateral movement to production database resulted in theft of 106 million customer records
- **Attack Chain:**
  1. Exploited SSRF vulnerability in development EC2 instance
  2. Retrieved AWS metadata credentials from instance
  3. Lateral moved to production VPC due to permissive security group rules
  4. Accessed customer data in RDS database
- **Impact:** $80 million settlement; massive reputational damage
- **Reference:** [Capital One Data Breach - CISA](https://www.cisa.gov/news-events/alerts/2019/07/19/capital-one-financial-corp-announces-data-breach)

#### Example 2: Microsoft Exchange Server Compromise → Azure VNET Lateral Movement (2021)

- **Target:** Enterprise customers with hybrid cloud (on-prem Exchange + Azure infrastructure)
- **Timeline:** March 2021 - June 2021
- **Technique Status:** Attackers exploited ProxyLogon vulnerabilities; compromised on-premises Exchange server; used Azure Hybrid Sync Account credentials to access Azure VNETs; traversed VNETs to compromise production cloud resources
- **Attack Chain:**
  1. Exploited ProxyLogon vulnerability in on-premises Exchange
  2. Obtained Azure Hybrid Sync Account credentials
  3. Lateral moved to Azure VNETs using obtained credentials
  4. Accessed multiple peered VNETs without network segmentation
  5. Deployed backdoors in production VNET
- **Impact:** Widespread compromise of hybrid environments; thousands of organizations affected
- **Reference:** [ProxyLogon Analysis - Microsoft Security](https://learn.microsoft.com/en-us/exchange/important-admin-tasks)

---