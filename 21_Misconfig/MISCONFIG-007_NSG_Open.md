# [MISCONFIG-007]: Open Network Security Groups

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-007 |
| **MITRE ATT&CK v18.1** | [Cloud Service Discovery (T1526)](https://attack.mitre.org/techniques/T1526/) |
| **Tactic** | Discovery / Initial Access / Lateral Movement |
| **Platforms** | Azure Virtual Network, Network Security Groups (NSG), Azure IaaS VMs, PaaS services |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure subscriptions using NSGs for traffic filtering (all regions) |
| **Patched In** | N/A – design allows broad rules; mitigated via proper NSG configuration, just‑in‑time access, and Azure Policy/Defender recommendations. |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** Open Network Security Groups (NSGs) are those with inbound rules allowing traffic from `Any` or `0.0.0.0/0` (or `Internet` service tag) to sensitive ports (22/3389/1433/5985/5986, or `*`). Such rules effectively expose VMs and PaaS endpoints directly to the internet, bypassing perimeter controls and enabling scanning, brute‑force attacks, exploitation of unpatched services, and lateral movement. This misconfiguration is one of the most common and impactful in Azure environments.
- **Attack Surface:**
  - NSGs attached to subnets or NICs with inbound rules like: `Source=*`, `SourcePort=*`, `Destination=*`, `DestPort=22/3389/*`, `Access=Allow`.
  - VMs hosting management services (RDP/SSH/WinRM), databases, or internal APIs.
- **Business Impact:** **Direct exposure of internal workloads to the internet**, leading to:
  - Compromise via credential stuffing or remote exploits (RDP/SSH/HTTP vulnerabilities).
  - Lateral movement from an initially compromised VM to other assets in the same VNet or peered VNets.
  - Breach of segmentation between tiers (web/app/db) and potential data exfiltration.
- **Technical Context:** Azure NSGs are stateful firewalls with default rules allowing intra‑VNet traffic and outbound internet access. Misconfigured custom rules with low priority (e.g., 100–200) granting `Allow` from `Any` override the default deny‑all‑inbound rule and significantly expand the attack surface. Defender for Cloud has built‑in recommendations such as “All network ports should be restricted on network security groups associated to your virtual machine” and adaptive network hardening to detect and remediate such exposures.

### Operational Risk
- **Execution Risk:** Medium – Tightening NSGs can break legacy remote access workflows or application connectivity if not planned.
- **Stealth:** Low from attacker perspective (internet scanning is noisy but often ignored); internal lateral movement after compromise can be stealthy.
- **Reversibility:** High – NSG rules can be updated quickly, but systems already compromised through open ports may remain backdoored.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Azure Foundations** | AZURE 6.x – Network Security | Requires restricting NSG rules from allowing `Any`/`0.0.0.0/0` to sensitive ports; implement least‑privilege network access. |
| **DISA STIG** | SRG‑NET‑000193 | Prohibits unrestricted inbound access; mandates firewall rules to restrict to authorized sources. |
| **CISA SCuBA** | Network Segmentation | Guidance for segmenting cloud networks and avoiding flat, internet‑exposed VNets. |
| **NIST 800‑53 Rev5** | SC‑7, AC‑4, AC‑6 | Boundary protection and information flow enforcement; open NSGs violate least privilege and boundary safeguards. |
| **GDPR** | Art. 32 | Appropriate security including network controls; open management ports to the internet endanger personal data. |
| **DORA** | Art. 9 | Requires robust ICT security measures, including secure network configuration for critical financial workloads. |
| **NIS2** | Art. 21 | Technical measures for risk management – includes segmentation and limiting exposure of critical systems. |
| **ISO 27001:2022** | A.8.20, A.8.21 | Security of network services and network segregation. |
| **ISO 27005** | "Publicly Exposed Management Interface" | Risk scenario: remote management exposed to the internet through misconfigured NSGs. |

---

## 3. TECHNICAL PREREQUISITES
- **Required Privileges (Misconfig Creation):**
  - Azure RBAC: **Network Contributor**, **Owner**, or equivalent custom role with `Microsoft.Network/networkSecurityGroups/securityRules/write`.
- **Required Access (Attacker):**
  - Internet reachability to public IPs of VMs / load balancers associated with open NSGs.

**Supported Versions:**
- All Azure NSG implementations for VNets, subnets, and NICs.

- **Tools:**
  - Azure Portal NSG blades.
  - Azure CLI (`az network nsg`, `az network nsg rule`).
  - Azure Network Watcher (IP flow verify, NSG diagnostics).
  - CSPM tools (Defender for Cloud, third‑party) to detect open NSGs.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

#### Management Station / PowerShell Reconnaissance

```powershell
Connect-AzAccount

Get-AzSubscription | ForEach-Object {
  Set-AzContext -SubscriptionId $_.Id | Out-Null
  Get-AzNetworkSecurityGroup | ForEach-Object {
    $nsg = $_
    $nsg.SecurityRules | Where-Object {
      $_.Direction -eq 'Inbound' -and $_.Access -eq 'Allow' -and \
      ($_.SourceAddressPrefix -eq '0.0.0.0/0' -or $_.SourceAddressPrefix -eq 'Internet' -or $_.SourceAddressPrefix -eq '*')
    } | Select-Object @{n='Subscription';e={$_.Id.Split('/')[-5]}},
                       @{n='NSG';e={$nsg.Name}}, Name, Priority,
                       SourceAddressPrefix, DestinationAddressPrefix,
                       DestinationPortRange, Protocol
  }
} | Sort-Object Priority | Format-Table -AutoSize
```

**What to Look For:**
- Inbound rules with:
  - `SourceAddressPrefix` in (`*`, `0.0.0.0/0`, `Internet`).
  - `DestinationPortRange` set to sensitive management ports (`22`, `3389`, `5985`, `5986`) or `*`.
  - High precedence (low priority value, e.g., 100–300) overriding the default deny rule.

#### Azure CLI / Bash Reconnaissance

```bash
az network nsg list --query "[].{name:name, resourceGroup:resourceGroup, securityRules:securityRules}" -o json > nsgs.json

# Quick jq filter for open inbound rules
cat nsgs.json | jq '.[] | {name, resourceGroup, 
  openRules: (.securityRules[] | select(.direction=="Inbound" and .access=="Allow" and 
    (.sourceAddressPrefix=="*" or .sourceAddressPrefix=="0.0.0.0/0" or .sourceAddressPrefix=="Internet")))}'
```

#### Network Watcher – IP Flow Verify
- Use **IP Flow Verify** to simulate traffic from the internet to a VM’s public IP/port and identify which NSG rule allows it.

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Exploiting Open NSGs from the Internet

**Supported Versions:** All Azure VNets/VMs with NSGs exposing management or application ports broadly.

#### Step 1: Scan for Exposed Ports
**Objective:** Identify open NSG‑exposed ports on Azure public IPs.

**Command (Attacker – Nmap):**
```bash
nmap -Pn -p 22,80,443,3389,5985,5986 <public-ip-range>
```

**Expected Output:**
- Open ports corresponding to NSG rules permitting inbound from `Any`.

#### Step 2: Attempt Brute Force or Exploit
**Objective:** Use exposed RDP/SSH/HTTP services for compromise.

**Example:**
- RDP brute force from internet to Windows VM on port 3389.
- SSH brute force on Linux VMs on port 22.

**What This Means:**
- NSG misconfig is effectively equivalent to a misconfigured on‑prem firewall, but often less monitored.

### METHOD 2 – Creating an Open NSG Rule (Misconfiguration)

**Supported Versions:** All Azure environments using NSGs.

#### Step 1: Create Rule Allowing Any/Any from Internet

**Command (Azure CLI):**
```bash
RG="rg-app"
NSG="nsg-web"

az network nsg rule create \
  --resource-group $RG \
  --nsg-name $NSG \
  --name Allow-Any-RDP \
  --priority 100 \
  --access Allow \
  --protocol Tcp \
  --direction Inbound \
  --source-address-prefixes 0.0.0.0/0 \
  --source-port-ranges "*" \
  --destination-port-ranges 3389 \
  --destination-address-prefixes "*"
```

**Expected Output:**
- NSG rule created; any IP on the internet can now reach port 3389 on associated NICs/subnets.

**References & Proofs:**
- Microsoft tutorials on NSG rule creation.
- Defender for Cloud networking recommendations highlighting overly permissive inbound rules.

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

No specific Atomic test exists for Azure NSG misconfiguration, but threat emulation can leverage:
- T1021.001 (Remote Services: RDP) and T1021.004 (SSH) for remote access over exposed ports.
- T1526 (Cloud Service Discovery) tests for enumerating cloud network resources.

Security teams can:
- Use Terraform/ARM to deploy a lab VM and NSG with open ports.
- Run Atomic tests for RDP/SSH abuse against that VM to validate detections.

---

## 7. TOOLS & COMMANDS REFERENCE

#### Azure PowerShell – NSG Management

```powershell
Install-Module Az.Network -Scope CurrentUser
Import-Module Az.Network

Get-AzNetworkSecurityGroup -Name "nsg-web" -ResourceGroupName "rg-app" |
  Select-Object -ExpandProperty SecurityRules
```

#### Azure CLI – NSG Management

```bash
az network nsg rule list --resource-group rg-app --nsg-name nsg-web -o table
```

#### Script (One-Liner – Detect Open NSG Rules)
```powershell
Connect-AzAccount

Get-AzSubscription | ForEach-Object {
  Set-AzContext -SubscriptionId $_.Id | Out-Null
  Get-AzNetworkSecurityGroup | ForEach-Object {
    $nsg = $_
    $nsg.SecurityRules | Where-Object {
      $_.Direction -eq 'Inbound' -and $_.Access -eq 'Allow' -and \
      ($_.SourceAddressPrefix -in @('*','0.0.0.0/0','Internet'))
    } | Select-Object @{n='Subscription';e={$_.Id.Split('/')[-5]}},
                       @{n='NSG';e={$nsg.Name}}, Name, Priority,
                       SourceAddressPrefix, DestinationPortRange
  }
}
```

---

## 8. SPLUNK DETECTION RULES

#### Rule 1: Overly Permissive NSG Inbound Rules Created or Modified
**Rule Configuration:**
- **Required Index:** `azure_activity`.
- **Required Sourcetype:** `azure:activity`.
- **Required Fields:** `operationName`, `properties`, `resourceId`.
- **Alert Threshold:** Any NSG write that introduces or modifies an inbound allow rule from `Any` or `0.0.0.0/0`.

**SPL Query:**
```spl
index=azure_activity ResourceProviderValue="MICROSOFT.NETWORK" \
  operationName="Microsoft.Network/networkSecurityGroups/securityRules/write"
| eval props = spath(_raw, "properties")
| eval ruleProps = spath(props, "properties")
| eval direction = spath(ruleProps, "direction"),
       access = spath(ruleProps, "access"),
       src = spath(ruleProps, "sourceAddressPrefix"),
       src2 = spath(ruleProps, "sourceAddressPrefixes{}"),
       destPort = spath(ruleProps, "destinationPortRange")
| where direction="Inbound" AND access="Allow" AND \
  (src="*" OR src="0.0.0.0/0" OR src="Internet" OR like(src2, "%0.0.0.0/0%"))
| stats latest(_time) AS lastChange BY resourceId, src, destPort
```

**What This Detects:**
- New or modified NSG rules that allow broad inbound from the internet.

**Source:** Microsoft Defender for Cloud networking recommendations and Azure Policy definitions that identify overly permissive NSGs.

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: All Network Ports Should Be Restricted – NSG Rule Monitoring

**Rule Configuration:**
- **Required Table:** `AzureActivity`.
- **Required Fields:** `OperationNameValue`, `ResourceProviderValue`, `Properties`, `ResourceId`.
- **Alert Severity:** High.

**KQL Query:**
```kusto
AzureActivity
| where ResourceProviderValue == "MICROSOFT.NETWORK" 
| where OperationNameValue == "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
| extend props = parse_json(Properties)
| extend rule = parse_json(tostring(props.responseBody.properties))
| extend direction = tostring(rule.direction),
         access = tostring(rule.access),
         src = tostring(rule.sourceAddressPrefix),
         destPort = tostring(rule.destinationPortRange)
| where direction =~ "Inbound" and access =~ "Allow" and 
      (src in ("*","0.0.0.0/0","Internet"))
| project TimeGenerated, ResourceId, direction, access, src, destPort, Caller
```

**What This Detects:**
- Any write operation that creates or updates a broad inbound allow rule.

**Source:** Defender for Cloud networking recommendations – “All network ports should be restricted on network security groups associated to your virtual machine.”

---

## 10. WINDOWS EVENT LOG MONITORING

Windows event logs are not directly involved in NSG evaluation, but:
- Exposed RDP/WinRM endpoints will generate Security events (4624, 4625 for logon successes/failures) reflecting increased brute‑force activity.
- These should be correlated with NSG configuration that allows public access.

---

## 11. SYSMON DETECTION PATTERNS

Sysmon can help detect repeated failed inbound connections at the host and suspicious execution triggered by remote access.

**Example:**
- Monitor for high volume of logon failures coincident with open NSG ports.

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts
**Alert Names (examples):**
- *All network ports should be restricted on network security groups associated to your virtual machine*.
- *Adaptive network hardening recommendations should be applied on internet facing virtual machines*.
- *Management ports of virtual machines should be protected with just-in-time network access control*.

- **Severity:** High.
- **Description:** Identifies NSGs where inbound rules are too permissive, and recommends restricting ports and sources based on observed traffic and threat intelligence.

**Manual Configuration Steps:**
1. Enable Defender for Cloud for subscriptions.
2. Review **Networking** recommendations; remediate NSGs flagged as overly permissive.
3. Enable **Just‑in‑time VM access** for RDP/SSH to close NSG ports by default and open them only on demand.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

Not applicable directly; NSG configuration is logged in Azure Activity logs, not the M365 unified audit log. Use Sentinel/Log Analytics and Defender for Cloud for governance.

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Remove or Restrict Broad Inbound NSG Rules**
  - Replace `Any`/`0.0.0.0/0` with specific source IP ranges (corporate VPN, Bastion subnet, jump hosts).

  ```powershell
  # Example: restrict RDP to Bastion subnet
  $nsg = Get-AzNetworkSecurityGroup -Name "nsg-web" -ResourceGroupName "rg-app"
  $rule = Get-AzNetworkSecurityRuleConfig -Name "Allow-Any-RDP" -NetworkSecurityGroup $nsg
  $rule.SourceAddressPrefix = "10.0.10.0/24"  # Bastion subnet
  Set-AzNetworkSecurityGroup -NetworkSecurityGroup $nsg
  ```

* **Use Azure Bastion and Just‑in‑Time (JIT) for Management Ports**
  - Disable direct RDP/SSH from internet and access VMs via Bastion with JIT NSG rules.

#### Priority 2: HIGH

* **Enforce Azure Policy for NSG Hardening**
  - Assign policies that audit or deny NSG rules allowing `0.0.0.0/0` to management ports.

* **Segmentation and Zero‑Trust Networking**
  - Use multiple subnets/NSGs for web, app, and data tiers with limited east‑west flows.

#### Validation Command (Verify Fix)
```powershell
Connect-AzAccount
Get-AzSubscription | ForEach-Object {
  Set-AzContext -SubscriptionId $_.Id | Out-Null
  Get-AzNetworkSecurityGroup | ForEach-Object {
    $nsg = $_
    $open = $nsg.SecurityRules | Where-Object {
      $_.Direction -eq 'Inbound' -and $_.Access -eq 'Allow' -and \
      ($_.SourceAddressPrefix -in @('*','0.0.0.0/0','Internet'))
    }
    if ($open) {
      Write-Output "[!] Open inbound rules in $($nsg.Name) in subscription $($_.Id.Split('/')[-5])"
    }
  }
}
```

**Expected Output (If Secure):**
- No `[!]` lines; all NSGs have restricted inbound sources.

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)
* **Network:**
  - Unusual inbound traffic from internet IPs to ports previously closed.
* **Host:**
  - Spikes in failed RDP/SSH logons (4625, SSH logs) followed by successful logons from unfamiliar IPs.

#### Forensic Artifacts
* **Cloud:**
  - Azure Activity logs showing creation of permissive NSG rules.
* **Host:**
  - Windows Security logs / Linux auth logs showing brute‑force behavior.

#### Response Procedures
1. **Isolate:**
   - Immediately update NSGs to block external access; consider deallocating or isolating compromised VMs.
2. **Collect Evidence:**
   - Export Azure Activity and NSG diagnostics; collect host logs and memory images for compromised machines.
3. **Remediate:**
   - Reset credentials, rebuild or restore VMs from clean images, implement hardened NSGs and JIT.

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Discovery** | T1526 – Cloud Service Discovery | Attacker enumerates public IPs and NSGs in Azure. |
| **2** | **Initial Access** | T1021 – Remote Services | Exploitation of exposed RDP/SSH services. |
| **3** | **Current Step** | **MISCONFIG-007 – Open Network Security Groups** | Misconfiguration enables direct access to internal workloads. |
| **4** | **Lateral Movement** | T1021/T1021.004 | Pivoting from compromised VMs to others. |
| **5** | **Impact** | DATA-EXFIL-XXX / IMPACT-XXX | Data theft or destructive actions once inside VNet. |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: Brute Force Against Exposed RDP/SSH in Azure
- **Target:** Multiple Azure tenants operating internet‑facing VMs.
- **Timeline:** Continuous – automated scanning campaigns target exposed RDP/SSH on cloud providers.
- **Technique Status:** Misconfigured NSGs remain one of the most common findings in Azure security assessments; attackers routinely exploit them for initial access.

#### Example 2: Misconfigured NSGs and Insecure APIs in Azure (Research Case Study)
- **Target:** Enterprise Azure environment with multiple VNets.
- **Timeline:** 2025 (research summarizing common Azure risks).
- **Technique Status:** White‑hat review found NSGs allowing broad inbound to management ports and internal APIs; exploitation paths included lateral movement and data exfiltration.
- **Impact:** Highlighted need for policy‑driven NSG baselines, adaptive hardening, and JIT.

---